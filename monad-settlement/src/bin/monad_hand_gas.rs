//! monad_hand_gas — 单手牌结算在 Monad 测试网的真实费用实测执行器。
//!
//! 背景：一手牌在 Monad（结算层/L1）上的链上足迹不是一笔"结算合约调用"，
//! 而是四条独立腿（`contracts/monad` 栈的真实交易形状）：
//!
//! | 腿 | 交易 | 触发节奏 |
//! | --- | --- | --- |
//! | 锚定 | `L1Inbox.submitBatch(index, root, throughOp)` | 每批 1 次（batch_size=64 手） |
//! | 聚合 | `L1Inbox.submitAggregate(...)` | 每聚合窗 1 次 |
//! | 买入 | `L1Bridge.depositNative(to)` | 每次买入 1 笔 |
//! | 提现 | `L1Outbox.commitRoot` + `claim` | 每提现窗 1 次 commitRoot + 每领款人 1 笔 claim |
//!
//! **Monad 计费模型（2026-09-27 测试网实测确认）**：按 `gas_limit × price`
//! 收费，不是 `gas_used × price`——自转账（真实 21000 gas）在 limit=100000
//! 时被精确扣 100000 × price。因此本执行器两阶段实测：
//!
//! 1. `eth_estimateGas` 逐腿取**真实执行 gas**（回执 gasUsed 恒等于 limit，
//!    不可用）；
//! 2. 以 `limit = estimate × 1.1`、`gasPrice = baseFee（地板 100 gwei）`
//!    重发，回执账单 = 紧 limit × 实际 price。
//!
//! 负载说明（诚实口径）：批次根/提现叶由本仓**真实编码器**构造
//! （`proof::leaf_hash` = L2 withdrawal_root builder 的逐字节镜像；
//! submitBatch 的根为确定性测试向量）。L1 gas 只取决于交易形状
//! （calldata 宽度 + 触碰的 storage slot），与根的语义内容无关——
//! 换成任何真实一手牌的根，gasUsed 逐 wei 相同。
//!
//! ```text
//! cargo run -p monad-settlement --bin monad_hand_gas -- \
//!   --l1-rpc https://testnet-rpc.monad.xyz --chain-id 10143 \
//!   --key-file /tmp/monad_e2e_key.txt \
//!   --inbox 0x… --outbox 0x… --bridge 0x… \
//!   [--run-id N] [--out /tmp/monad-hand-gas.json]
//! ```

use std::collections::BTreeMap;

use monad_settlement::abi::{
    batch_count_selector, encode_claim, encode_commit_root, encode_deposit_native,
    encode_set_large_payout_threshold, encode_submit_aggregate, encode_submit_batch, ClaimLeaf,
};
use monad_settlement::l1::{hex_addr, L1Rpc};
use monad_settlement::signer::{Credentials, LegacyTx};
use monad_settlement::{keccak::keccak256, proof, SettlementError, MONAD_TESTNET_CHAIN_ID};

/// 原生资产标签（1 = MON）。
const TAG_NATIVE: u8 = 1;
/// 买入腿金额：0.01 MON。
const DEPOSIT_AMOUNT: u128 = 10_000_000_000_000_000;
/// 提现腿金额：0.01 MON（< 大额门槛 → 不走延迟）。
const CLAIM_AMOUNT: u128 = 10_000_000_000_000_000;
/// 大额门槛恢复值：100 MON（运维 tx，令小额 claim 即时）。
const LARGE_THRESHOLD_RESET: u128 = 100_000_000_000_000_000_000;
/// 紧 limit 安全系数（limit 计费模型下这是唯一杠杆，宁小勿大；
/// 估 gas 的语义分支与真实执行一致，1.1x 余量足够）。
const LIMIT_HEADROOM_NUM: u128 = 11;
const LIMIT_HEADROOM_DEN: u128 = 10;

struct Row {
    leg: &'static str,
    method: &'static str,
    tx: [u8; 32],
    success: bool,
    /// eth_estimateGas 的返回值 = 真实执行 gas（cold 视角）。
    est_gas: u128,
    /// 实际发出的 limit（计费 gas）。
    billed_gas: u128,
    effective_gas_price: u128,
    block: u64,
    note: String,
}

fn main() {
    std::process::exit(run(collect_flag_map(std::env::args().skip(1).collect())));
}

fn collect_flag_map(argv: Vec<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut iter = argv.into_iter();
    while let Some(flag) = iter.next() {
        let Some(name) = flag.strip_prefix("--") else {
            die(&format!("unexpected positional arg: {flag}"));
        };
        if name == "help" || name == "h" {
            out.insert(name.to_string(), String::new());
            continue;
        }
        let value = iter
            .next()
            .unwrap_or_else(|| die(&format!("missing value for --{name}")));
        out.insert(name.to_string(), value);
    }
    out
}

fn die(message: &str) -> ! {
    eprintln!("fatal: {message}");
    std::process::exit(2);
}

fn run(args: BTreeMap<String, String>) -> i32 {
    let get = |name: &str| -> Option<String> { args.get(name).cloned() };
    let l1_rpc = get("l1-rpc").unwrap_or_else(|| die("--l1-rpc is required".into()));
    let chain_id: u64 = get("chain-id")
        .and_then(|s| s.parse().ok())
        .unwrap_or(MONAD_TESTNET_CHAIN_ID);
    let key = match (get("key-env"), get("key-file")) {
        (Some(env), _) => Credentials::from_hex(
            &std::env::var(&env).unwrap_or_else(|_| die(&format!("env {env} not set"))),
        ),
        (None, Some(path)) => Credentials::from_hex(
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| die(&format!("key file {path}: {e}")))
                .trim(),
        ),
        _ => die("--key-env or --key-file required"),
    }
    .unwrap_or_else(|e| die(&format!("bad key: {e}")));
    let parse_addr = |name: &str| -> [u8; 20] {
        let s = get(name).unwrap_or_else(|| die(&format!("--{name} is required")));
        let t = s.trim().strip_prefix("0x").unwrap_or(s.trim());
        let mut out = [0u8; 20];
        hex::decode_to_slice(t, &mut out).unwrap_or_else(|e| die(&format!("bad --{name}: {e}")));
        out
    };
    let (inbox, outbox, bridge) = (parse_addr("inbox"), parse_addr("outbox"), parse_addr("bridge"));
    let out_path = get("out");
    // 运行代号：进 seed / checkpoint 高度，保证跨次运行幂等键不撞。
    let run_id: u64 = get("run-id").and_then(|s| s.parse().ok()).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() % 100_000)
            .unwrap_or(0)
    });
    let seed = |tag: &str| keccak256(format!("monad-hand-gas.{tag}.{run_id}").as_bytes());
    let checkpoint_height = 1000 + run_id;

    let rpc = L1Rpc::new(&l1_rpc).unwrap_or_else(|e| die(&format!("rpc: {e}")));

    // ---- 环境快照（公共 RPC 偶发抖动 → 关键读数带重试）----
    let env_chain = retry3("chain_id", || rpc.chain_id()).unwrap_or(0);
    if env_chain != chain_id {
        die(&format!("chain_id {env_chain} != expected {chain_id}"));
    }
    let height = retry3("block_number", || rpc.block_number()).unwrap_or(0);
    let finalized = retry3("finalized", || rpc.finalized_block()).unwrap_or(0);
    let node_gas_price = retry3("gas_price", || rpc.gas_price()).unwrap_or(0);
    let base_fee = latest_base_fee(&rpc).unwrap_or(0);
    let operator = key.address();
    let balance = retry3("balance", || rpc.get_balance(&operator)).unwrap_or(0);
    let bridge_float0 = rpc.get_balance(&bridge).unwrap_or(0);
    let batch_count0 = call_u64(&rpc, &inbox, &batch_count_selector());
    println!("env: chain={env_chain} height={height} finalized={finalized} baseFee={base_fee} wei gasPrice(node)={node_gas_price} wei runId={run_id}");
    println!(
        "operator 0x{} balance {:.6} MON；bridge 0x{} float {:.6} MON；batchCount={batch_count0:?}",
        hex::encode(operator),
        wei_to_mon(balance),
        hex::encode(bridge),
        wei_to_mon(bridge_float0),
    );
    if balance < 50_000_000_000_000_000 {
        die(&format!(
            "operator 余额不足（{balance} wei < 0.05 MON）：先经官方水龙头领水"
        ));
    }
    // gasPrice 策略：块头 baseFee 在 Monad 测试网上可能报 0（费用机制
    // 不同于此处语义），贴 0 会被拒；取 max(块头, 节点建议价) 起步。
    let gas_price = base_fee.max(node_gas_price);

    // ---- 逐腿实测（估 gas → 紧 limit 发送）----
    let mut rows: Vec<Row> = Vec::new();

    // 腿 1：单手独占一批（batch=1 手，through_op=1）——"一手一锚"上界。
    let root_1hand = seed("batch.1-hand");
    let batch_count1 = call_u64(&rpc, &inbox, &batch_count_selector());
    rows.push(measure(
        &rpc, &key, chain_id, inbox, gas_price, "锚定·1手/批", "submitBatch(1hand)",
        encode_submit_batch(batch_count1.unwrap_or(0), root_1hand, 1), 0,
        "index=当前 batchCount（严格连续）；单手一锚为每手费用上界",
    ));

    // 腿 2：64 手一批（batch=64，through_op=64）——生产节奏；calldata 与
    // 腿 1 同宽 → 执行 gas 相同，每手摊销 = gas/64（纯算术）。
    let root_64hand = seed("batch.64-hand");
    let batch_count2 = call_u64(&rpc, &inbox, &batch_count_selector());
    rows.push(measure(
        &rpc, &key, chain_id, inbox, gas_price, "锚定·64手/批", "submitBatch(64hand)",
        encode_submit_batch(batch_count2.unwrap_or(0), root_64hand, 64), 0,
        "与 1手/批 同宽 calldata → 执行 gas 相同；每手摊销 = gas/64",
    ));

    // 腿 3：聚合锚（覆盖本运行上锚的批次）。
    let aggregate_root = seed("aggregate");
    let aggregate_count = call_u64(&rpc, &inbox, &monad_settlement::keccak::selector("aggregateCount()"));
    rows.push(measure(
        &rpc, &key, chain_id, inbox, gas_price, "聚合锚", "submitAggregate",
        encode_submit_aggregate(aggregate_count.unwrap_or(0), aggregate_root, 64, 2), 0,
        "每聚合窗 1 笔，摊入窗内各手",
    ));

    // 腿 4：买入（depositNative 0.01 MON）。
    rows.push(measure(
        &rpc, &key, chain_id, bridge, gas_price, "买入", "depositNative(0.01MON)",
        encode_deposit_native(operator), DEPOSIT_AMOUNT,
        "每玩家每次买入 1 笔；DepositInitiated 事件供 L2 铸 note",
    ));

    // 运维：恢复大额门槛（非手牌费用，单独记录不计入结算腿）。
    rows.push(measure(
        &rpc, &key, chain_id, outbox, gas_price, "运维·非结算腿", "setLargePayoutThreshold",
        encode_set_large_payout_threshold(TAG_NATIVE, LARGE_THRESHOLD_RESET), 0,
        "把 E2E 设的 1wei 门槛恢复 100 MON；令小额 claim 不走延迟",
    ));

    // 腿 5：提现窗上锚（单赢家，叶 = 真实 withdrawal_root builder 构造）。
    let claim_leaf = ClaimLeaf {
        request_id: seed("claim"),
        external_recipient: monad_settlement::abi::word_address(operator),
        asset_tag: TAG_NATIVE,
        amount: u64::try_from(CLAIM_AMOUNT).expect("fits"),
        burned_note_commitment: seed("burn"),
        checkpoint_height,
    };
    let claim_root = proof::leaf_hash(&claim_leaf);
    rows.push(measure(
        &rpc, &key, chain_id, outbox, gas_price, "提现·窗根上锚", "commitRoot(1leaf)",
        encode_commit_root(checkpoint_height, 1, claim_root, true), 0,
        "每提现窗 1 笔；生产中随 checkpoint 原子携带（无独立 tx）",
    ));

    // 腿 6：赢家领款（claim → Bridge payoutNative 0.01 MON 到账）。
    let bridge_float_before_claim = rpc.get_balance(&bridge).unwrap_or(0);
    rows.push(measure(
        &rpc, &key, chain_id, outbox, gas_price, "提现·领款", "claim(0.01MON)",
        encode_claim(&claim_leaf, claim_root, 1, 0, &[]), 0,
        "每领款人 1 笔；含 Merkle 路径校验 + 台账防重放 + 跨合约打款",
    ));
    let paid = bridge_float_before_claim.saturating_sub(rpc.get_balance(&bridge).unwrap_or(0));

    // ---- 汇总 ----
    let mut failed = 0usize;
    println!(
        "\n{:<14} {:>28} {:>10} {:>10} {:>12} {:>12} {:>10}",
        "腿", "交易", "estGas", "计费gas", "账单wei", "账单MON", "block"
    );
    println!("{}", "-".repeat(104));
    for r in &rows {
        if !r.success {
            failed += 1;
        }
        let cost = r.billed_gas * r.effective_gas_price;
        println!(
            "{:<14} {:>28} {:>10} {:>10} {:>12} {:>12.9} {:>10}{}",
            r.leg,
            r.method,
            r.est_gas,
            r.billed_gas,
            cost,
            wei_to_mon(cost),
            r.block,
            if r.success { "" } else { " [FAIL]" },
        );
        if !r.note.is_empty() {
            println!("{:<14}   · {}", "", r.note);
        }
    }

    // 单手口径（锚定腿执行 gas 与批大小无关 → 摊销为纯算术）。
    let anchor = rows.iter().find(|r| r.method.contains("64hand"));
    let aggregate = rows.iter().find(|r| r.leg == "聚合锚");
    let deposit = rows.iter().find(|r| r.leg == "买入");
    let commit = rows.iter().find(|r| r.leg.contains("窗根上锚"));
    let claim = rows.iter().find(|r| r.leg.contains("领款"));
    let mut summary = serde_json::json!({
        "probe": "monad-hand-gas",
        "billing_model": "gas_limit × gas_price（limit=est×1.1 实测；自转账对照实验确认）",
        "network": { "rpc": l1_rpc, "chain_id": env_chain, "height": height,
                     "base_fee_wei": base_fee, "node_gas_price_wei": node_gas_price,
                     "run_id": run_id },
        "stack": { "inbox": hex_addr(&inbox), "outbox": hex_addr(&outbox), "bridge": hex_addr(&bridge) },
        "rows": rows.iter().map(|r| serde_json::json!({
            "leg": r.leg, "method": r.method,
            "tx": format!("0x{}", hex::encode(r.tx)),
            "success": r.success, "est_gas": r.est_gas,
            "billed_gas": r.billed_gas,
            "effective_gas_price_wei": r.effective_gas_price,
            "cost_wei": r.billed_gas * r.effective_gas_price,
            "block": r.block, "note": r.note,
        })).collect::<Vec<_>>(),
        "failed": failed,
    });
    if let (Some(anchor), Some(deposit), Some(claim)) = (anchor, deposit, claim) {
        let gp = if claim.effective_gas_price > 0 { claim.effective_gas_price } else { gas_price };
        // 每手执行 gas 口径（生产含义：区块打包占用）。
        let per_hand_exec = anchor.est_gas / 64
            + aggregate.map_or(0, |a| a.est_gas / (2 * 64)) // 聚合窗摊 2 批×64 手
            + commit.map_or(0, |c| c.est_gas / 64)
            + claim.est_gas;
        // 每手账单口径（limit 计费：limit=est×1.1 的账单摊销）。
        let per_hand_billed = anchor.billed_gas / 64
            + aggregate.map_or(0, |a| a.billed_gas / (2 * 64))
            + commit.map_or(0, |c| c.billed_gas / 64)
            + claim.billed_gas;
        println!("\n单手结算费用（@ {gp} wei/gas，limit=est×1.1）：");
        println!(
            "  锚定 64手/批：执行 {:.0} gas/手，计费 {:.0} gas/手",
            anchor.est_gas / 64,
            anchor.billed_gas / 64,
        );
        if let Some(a) = aggregate {
            println!(
                "  聚合锚摊销：  执行 {:.0} gas/手，计费 {:.0} gas/手",
                a.est_gas / 128,
                a.billed_gas / 128,
            );
        }
        if let Some(c) = commit {
            println!(
                "  提现窗摊销：  执行 {:.0} gas/手，计费 {:.0} gas/手",
                c.est_gas / 64,
                c.billed_gas / 64,
            );
        }
        println!(
            "  赢家 claim：  执行 {:.0} gas/手，计费 {:.0} gas/手",
            claim.est_gas, claim.billed_gas,
        );
        println!(
            "  ≈ 合计 执行 {per_hand_exec} gas/手（打包视角），账单 ≈ {per_hand_billed} gas × {gp} wei = {:.9} MON/手",
            wei_to_mon(per_hand_billed * gp),
        );
        println!(
            "  买入腿另计：执行 {} gas/次，账单 {:.9} MON/次",
            deposit.est_gas,
            wei_to_mon(deposit.billed_gas * gp),
        );
        println!(
            "  claim 到账对账：Bridge 浮存 -{paid} wei（期望 {CLAIM_AMOUNT}）"
        );
        summary["per_hand"] = serde_json::json!({
            "anchor_est_gas": anchor.est_gas, "anchor_est_per_hand_64": anchor.est_gas / 64,
            "anchor_billed_per_hand_64": anchor.billed_gas / 64,
            "aggregate_est_gas": aggregate.map(|a| a.est_gas),
            "aggregate_est_per_hand": aggregate.map(|a| a.est_gas / 128),
            "commit_root_est_gas": commit.map(|c| c.est_gas),
            "claim_est_gas": claim.est_gas,
            "claim_billed_gas": claim.billed_gas,
            "exec_gas_per_hand": per_hand_exec,
            "billed_gas_per_hand": per_hand_billed,
            "gas_price_wei": gp,
            "billed_mon_per_hand": wei_to_mon(per_hand_billed * gp),
            "deposit_est_gas": deposit.est_gas,
            "deposit_billed_mon": wei_to_mon(deposit.billed_gas * gp),
            "claim_paid_wei": paid,
        });
    }

    let json = serde_json::to_string_pretty(&summary).expect("json");
    println!("\nsummary_json {json}");
    if let Some(path) = out_path {
        std::fs::write(&path, &json).unwrap_or_else(|e| die(&format!("write {path}: {e}")));
        println!("summary → {path}");
    }
    i32::from(failed > 0)
}

/// eth_estimateGas（from = operator，cold 视角）→ 真实执行 gas。
fn estimate_gas(rpc: &L1Rpc, from: &[u8; 20], to: &[u8; 20], value: u128, data: &[u8]) -> u128 {
    let params = serde_json::json!([{
        "from": hex_addr(from),
        "to": hex_addr(to),
        "value": format!("0x{value:x}"),
        "data": format!("0x{}", hex::encode(data)),
    }]);
    match rpc.rpc("eth_estimateGas", params) {
        Ok(v) => v
            .as_str()
            .and_then(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0),
        Err(e) => {
            eprintln!("[estimate] 失败（回退宽松 limit）: {e}");
            0
        }
    }
}

/// 发送一笔交易（先估 gas → 紧 limit）→ 等回执 → 抽取账单要素。
fn measure(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    to: [u8; 20],
    gas_price: u128,
    leg: &'static str,
    method: &'static str,
    data: Vec<u8>,
    value: u128,
    note: &str,
) -> Row {
    let est = estimate_gas(rpc, &key.address(), &to, value, &data);
    // limit = est × 1.1（估不到时回退 500k 宽松值并标注）。
    let billed_gas = if est > 0 {
        (est * LIMIT_HEADROOM_NUM + LIMIT_HEADROOM_DEN - 1) / LIMIT_HEADROOM_DEN
    } else {
        500_000
    };
    let outcome = (|| -> Result<([u8; 32], monad_settlement::l1::Receipt), SettlementError> {
        let nonce = rpc.transaction_count(&key.address())?;
        let tx = LegacyTx {
            nonce,
            gas_price,
            gas_limit: billed_gas,
            to: Some(to),
            value,
            data: data.clone(),
        };
        let signed = key.sign_eip155(&tx, chain_id)?;
        let hash = match rpc.send_raw_transaction(&signed.raw) {
            Ok(h) => h,
            // 起步价被拒（base fee 抬升等）→ 用节点建议价 ×1.15 重签一次。
            Err(e) => {
                let retry_price = rpc.gas_price()?.saturating_mul(115) / 100;
                eprintln!("[{leg}] 起步价 {gas_price} 被拒（{e}）→ 重试 @ {retry_price}");
                let tx = LegacyTx {
                    nonce,
                    gas_price: retry_price,
                    gas_limit: billed_gas,
                    to: Some(to),
                    value,
                    data: data.clone(),
                };
                let signed = key.sign_eip155(&tx, chain_id)?;
                rpc.send_raw_transaction(&signed.raw)?
            }
        };
        let receipt = rpc.wait_receipt(&hash, 1_500, 40)?;
        Ok((hash, receipt))
    })();
    match outcome {
        Ok((tx, receipt)) => Row {
            leg,
            method,
            tx,
            success: receipt.success,
            est_gas: est,
            billed_gas,
            effective_gas_price: receipt.effective_gas_price.unwrap_or(gas_price),
            block: receipt.block_number,
            note: note.into(),
        },
        Err(e) => {
            eprintln!("[{leg}] {method} 发送失败: {e}");
            Row {
                leg,
                method,
                tx: [0u8; 32],
                success: false,
                est_gas: est,
                billed_gas,
                effective_gas_price: gas_price,
                block: 0,
                note: format!("发送失败: {e}"),
            }
        }
    }
}

fn call_u64(rpc: &L1Rpc, to: &[u8; 20], data: &[u8]) -> Option<u64> {
    let ret = rpc.call(to, data).ok()?;
    if ret.len() < 32 {
        return None;
    }
    let mut word = [0u8; 8];
    word.copy_from_slice(&ret[24..32]);
    Some(u64::from_be_bytes(word))
}

/// 公共 RPC 偶发抖动的重试包装（3 次，间隔 300ms）。
fn retry3<T>(what: &str, f: impl Fn() -> Result<T, SettlementError>) -> Option<T> {
    for attempt in 0..3 {
        match f() {
            Ok(v) => return Some(v),
            Err(e) => {
                eprintln!("[env:{what}] 第 {} 次失败: {e}", attempt + 1);
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    }
    None
}

/// latest 块头的 baseFeePerGas（不存在 → None）。
fn latest_base_fee(rpc: &L1Rpc) -> Option<u128> {
    let block = rpc
        .rpc("eth_getBlockByNumber", serde_json::json!(["latest", false]))
        .ok()?;
    block
        .get("baseFeePerGas")?
        .as_str()?
        .trim_start_matches("0x")
        .parse()
        .ok()
}

fn wei_to_mon(wei: u128) -> f64 {
    wei as f64 / 1e18
}
