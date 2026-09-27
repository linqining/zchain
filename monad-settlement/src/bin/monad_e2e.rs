//! monad_e2e — 带水测试钥下的 Monad 测试网链上 E2E 验收执行器。
//!
//! 一条命令完成验收记录 §4 的全部 ⛏ 项（docs/test-records/
//! 2026-09-27-monad-testnet-acceptance.md）：
//! 1. 部署 L1Bridge / L1Outbox / L1Inbox（solc 编译字节码）并三向互联；
//! 2. `batchCount()` == 0（eth_call）；
//! 3. 批次根上锚 E2E：submitBatch → 回执 → batchCount == 1 → finalized；
//! 4. 入金 E2E：depositNative → finalized 窗口 → DepositWatcher 捕获
//!    DepositInitiated → deposits 记录落盘（L2 侧铸 note 由 sequencer 按此
//!    提交 DepositV2，deposit_id 幂等）；
//! 5. 提现 claim E2E：Rust builder 树根 → commitRoot → claim（原生 MON 经
//!    Bridge payout 到账，余额对账）；
//! 6. 大额延迟：threshold=1 → 延迟未满 claim 必败 → 期满后再领成功。
//!
//! 无资金时在 P0 闸门即失败退出（fail-fast，不发任何交易）。
//!
//! ```text
//! cargo run -p monad-settlement --bin monad_e2e -- \
//!   --l1-rpc https://testnet-rpc.monad.xyz --chain-id 10143 \
//!   --key-env MONAD_TESTNET_KEY [--bytecode-dir contracts/monad/out/solc]
//! ```

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use monad_settlement::abi::{
    batch_count_selector, encode_claim, encode_commit_root, encode_deposit_native,
    encode_set_address, encode_set_claim_delay_blocks, encode_set_large_payout_threshold, ClaimLeaf,
};
use monad_settlement::anchor::{AnchorState, AnchorSubmitter};
use monad_settlement::l1::L1Rpc;
use monad_settlement::signer::{Credentials, LegacyTx};
use monad_settlement::{DepositWatcher, SettlementError, MONAD_TESTNET_CHAIN_ID};

const TAG_NATIVE: u8 = 1;
/// 大额延迟（Monad 测试网 ≈0.3s 出块 → 30 块 ≈ 10s）。
const CLAIM_DELAY_BLOCKS: u64 = 30;
/// 入金/提现金额（wei）：0.1 / 0.05 / 0.04 MON，够闭环且省 gas。
const DEPOSIT_AMOUNT: u128 = 100_000_000_000_000_000;
const WITHDRAW_AMOUNT: u128 = 50_000_000_000_000_000;
const WITHDRAW_AMOUNT_2: u128 = 40_000_000_000_000_000;

struct Check {
    item: String,
    ok: bool,
    detail: String,
}

fn main() {
    let args = collect_flag_map(std::env::args().skip(1).collect());
    if args.contains_key("help") || args.contains_key("h") {
        eprintln!(
            "monad_e2e — funded-key on-chain E2E acceptance\n\
             --l1-rpc <url> --chain-id 10143 --key-env <ENV>|--key-file <path>\n\
             [--bytecode-dir contracts/monad/out/solc] [--skip-deploy]\n\
             [--inbox 0x --outbox 0x --bridge 0x]（--skip-deploy 时必填）\n\
             [--send-tx-poll-ms N] [--deposits-file path]"
        );
        std::process::exit(0);
    }
    std::process::exit(run(args));
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
        let value = iter.next().unwrap_or_else(|| die(&format!("missing value for --{name}")));
        out.insert(name.to_string(), value);
    }
    out
}

fn die(message: &str) -> ! {
    eprintln!("fatal: {message}");
    std::process::exit(2);
}

fn parse_hex20(s: &str) -> [u8; 20] {
    let trimmed = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let mut out = [0u8; 20];
    hex::decode_to_slice(trimmed, &mut out)
        .unwrap_or_else(|e| die(&format!("bad address {s}: {e}")));
    out
}

fn run(args: BTreeMap<String, String>) -> i32 {
    let get = |name: &str| -> Option<String> { args.get(name).cloned() };
    let parse_u64 = |name: &str, default: u64| -> u64 {
        get(name).map_or(default, |s| {
            s.parse::<u64>().unwrap_or_else(|e| die(&format!("bad --{name}: {e}")))
        })
    };
    let l1_rpc = get("l1-rpc").unwrap_or_default();
    if l1_rpc.is_empty() {
        die("--l1-rpc is required");
    }
    let chain_id = parse_u64("chain-id", MONAD_TESTNET_CHAIN_ID);
    let key = if let Some(env) = get("key-env") {
        let raw = std::env::var(&env).unwrap_or_else(|_| die(&format!("env {env} not set")));
        Credentials::from_hex(&raw).unwrap_or_else(|e| die(&format!("bad key: {e}")))
    } else {
        get("key-file").map(|path| {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| die(&format!("key file {path}: {e}")));
            Credentials::from_hex(raw.trim()).unwrap_or_else(|e| die(&format!("bad key: {e}")))
        })
        .unwrap_or_else(|| die("--key-env or --key-file required"))
    };
    let bytecode_dir = get("bytecode-dir").unwrap_or_else(|| "../contracts/monad/out/solc".into());
    let skip_deploy = args.contains_key("skip-deploy");
    let poll_ms = parse_u64("send-tx-poll-ms", 1_500);

    let mut checks: Vec<Check> = Vec::new();
    let rpc = match L1Rpc::new(&l1_rpc) {
        Ok(r) => r,
        Err(e) => return fail_early(&mut checks, "rpc_connect", e),
    };

    // ---- P0 闸门：链 + 资金（无资金 fail-fast，不发任何交易）----
    if !record(&mut checks, "chain_id", rpc.chain_id().unwrap_or(0) == chain_id, format!("expected {chain_id}")) {
        return summarize(&checks);
    }
    let balance = match rpc.get_balance(&key.address()) {
        Ok(b) => b,
        Err(e) => return fail_early(&mut checks, "balance", e),
    };
    println!(
        "operator key: 0x{} balance {} wei（{}.{:0>3} MON）",
        hex::encode(key.address()),
        balance,
        balance / 1_000_000_000_000_000_000,
        balance % 1_000_000_000_000_000_000 / 1_000_000_000_000_000
    );
    if !record(
        &mut checks,
        "funded_key",
        balance > 100_000_000_000_000_000, // > 0.1 MON
        "需要 > 0.1 MON：全流程（3 部署 + 12 笔交互 + 1 次回退）实测约 0.2 MON gas @112 gwei".into(),
    ) {
        println!(
            "hint: 先经官方水龙头 https://faucet.monad.xyz（人工验证）为 0x{} 领取测试 MON（建议 ≥1 MON）后重跑",
            hex::encode(key.address())
        );
        return summarize(&checks);
    }

    // ---- 1. 部署 + 互联 ----
    let (inbox, outbox, bridge) = if skip_deploy {
        (
            parse_hex20(&get("inbox").unwrap_or_else(|| die("--skip-deploy needs --inbox"))),
            parse_hex20(&get("outbox").unwrap_or_else(|| die("--skip-deploy needs --outbox"))),
            parse_hex20(&get("bridge").unwrap_or_else(|| die("--skip-deploy needs --bridge"))),
        )
    } else {
        match deploy_stack(&rpc, &key, chain_id, &bytecode_dir, poll_ms) {
            Ok(addrs) => addrs,
            Err(e) => return fail_early(&mut checks, "deploy", e),
        }
    };
    println!(
        "stack: inbox=0x{} outbox=0x{} bridge=0x{}",
        hex::encode(inbox),
        hex::encode(outbox),
        hex::encode(bridge)
    );

    // ---- 2. batchCount() == 0 ----
    let count0 = rpc
        .call(&inbox, &batch_count_selector())
        .map(|ret| decode_u64_word(&ret))
        .unwrap_or(None);
    record(
        &mut checks,
        "batch_count_zero",
        count0 == Some(0),
        format!("batchCount() = {count0:?}"),
    );

    // ---- 3. 批次根上锚 E2E ----
    let submitter_rpc = match L1Rpc::new(&l1_rpc) {
        Ok(r) => r,
        Err(e) => return fail_early(&mut checks, "rpc_reconnect", e),
    };
    let mut submitter = match AnchorSubmitter::connect(submitter_rpc, key.clone(), inbox, chain_id) {
        Ok(s) => s,
        Err(e) => return fail_early(&mut checks, "submitter_connect", e),
    };
    let batch_root = keccak_seed(b"zchain-e2e.batch.1");
    let task = monad_settlement::anchor_task(0, batch_root, 64);
    let anchor_ok = (|| -> Result<bool, SettlementError> {
        submitter.submit(&task)?;
        for _ in 0..40 {
            submitter.poll()?;
            if submitter.snapshot().get(&task.key).is_some_and(AnchorState::is_finalized) {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(poll_ms));
        }
        Ok(false)
    })()
    .unwrap_or(false);
    let count1 = rpc
        .call(&inbox, &batch_count_selector())
        .map(|ret| decode_u64_word(&ret))
        .unwrap_or(None);
    record(
        &mut checks,
        "anchor_batch_root",
        anchor_ok && count1 == Some(1),
        format!("finalized={anchor_ok} batchCount()={count1:?}"),
    );

    // ---- 4. 入金 E2E：锁 MON → finalized 窗口 → watcher 捕获 → 记录落盘 ----
    let deposits_file = get("deposits-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("monad-e2e-deposits.jsonl"));
    let deposit_ok = deposit_e2e(
        &rpc, &key, chain_id, bridge, DEPOSIT_AMOUNT, &deposits_file, poll_ms,
    );
    record(
        &mut checks,
        "deposit_watcher",
        deposit_ok.0,
        format!("0.1 MON 锁入 Bridge，DepositInitiated 已捕获 → {}（{}）", deposits_file.display(), deposit_ok.1),
    );

    // ---- 5. 提现 claim E2E（Rust builder 树根 → 链上 claim → 余额对账）----
    let withdraw_ok = withdraw_e2e(
        &rpc, &key, chain_id, outbox, bridge, WITHDRAW_AMOUNT, b"zchain-e2e.withdraw.1", 1, poll_ms,
    );
    record(
        &mut checks,
        "withdrawal_claim",
        withdraw_ok.0,
        format!("amount={WITHDRAW_AMOUNT} bridge_float={} wei：{}", rpc.get_balance(&bridge).unwrap_or(0), withdraw_ok.1),
    );

    // ---- 6. 大额延迟拦截 ----
    let delay_ok = large_delay_check(&rpc, &key, chain_id, outbox, poll_ms);
    record(&mut checks, "large_payout_delay", delay_ok.0, delay_ok.1);

    summarize(&checks)
}

/// 入金 E2E：depositNative → 回执 → 以回执高度为窗起点的 watcher 等捕获。
fn deposit_e2e(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    bridge: [u8; 20],
    amount: u128,
    deposits_file: &PathBuf,
    poll_ms: u64,
) -> (bool, String) {
    let calldata = encode_deposit_native(key.address());
    let tx_hash = match send_tx(rpc, key, chain_id, Some(bridge), amount, calldata, 200_000) {
        Ok(h) => h,
        Err(e) => return (false, format!("depositNative 发送失败: {e}")),
    };
    let receipt = match rpc.wait_receipt(&tx_hash, poll_ms.max(1_000), 40) {
        Ok(r) if r.success => r,
        Ok(r) => return (false, format!("depositNative 回执失败（block {}）", r.block_number)),
        Err(e) => return (false, format!("depositNative 未打包: {e}")),
    };
    // watcher 从回执高度起扫（窗口右端 = finalized，几秒内覆盖回执块）。
    let mut watcher = DepositWatcher::new(
        L1Rpc::new(rpc.url()).unwrap_or_else(|_| unreachable!("same url")),
        bridge,
        receipt.block_number,
    );
    let mut captured = None;
    for _ in 0..40 {
        match watcher.poll_once() {
            Ok(events) => {
                if let Some(ev) = events
                    .into_iter()
                    .find(|ev| ev.token == [0u8; 20] && ev.amount == amount)
                {
                    captured = Some(ev);
                    break;
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(poll_ms.max(1_000)));
    }
    match captured {
        Some(ev) => {
            // 落 deposits 记录（L2 sequencer 据此提交 DepositV2 铸 note）。
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(deposits_file) {
                let _ = writeln!(
                    f,
                    "{{\"nonce\":{},\"token\":\"0x0000000000000000000000000000000000000000\",\"to\":\"0x{}\",\"amount\":\"{}\"}}",
                    ev.nonce,
                    hex::encode(ev.to),
                    ev.amount
                );
            }
            (true, format!("nonce={} amount={}", ev.nonce, ev.amount))
        }
        None => (false, "finalized 窗口内未捕获事件".into()),
    }
}

/// 提现 E2E：单叶窗（root = leaf_hash，证明为空数组）→ commitRoot → claim
/// → recipient 余额增量对账。
fn withdraw_e2e(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    outbox: [u8; 20],
    bridge: [u8; 20],
    amount: u128,
    seed: &[u8],
    checkpoint_height: u64,
    poll_ms: u64,
) -> (bool, String) {
    let leaf = ClaimLeaf {
        request_id: keccak_seed(seed),
        external_recipient: word_address_of(key.address()),
        asset_tag: TAG_NATIVE,
        amount: u64::try_from(amount).expect("amount fits u64"),
        burned_note_commitment: keccak_seed(b"zchain-e2e.burn"),
        checkpoint_height,
    };
    let root = monad_settlement::proof::leaf_hash(&leaf);
    if let Err(e) = send_tx(
        rpc, key, chain_id, Some(outbox), 0,
        encode_commit_root(checkpoint_height, 1, root, true), 200_000,
    )
    .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40))
    .and_then(|r| if r.success { Ok(()) } else { Err(SettlementError::shape("commit", "receipt failed")) })
    {
        return (false, format!("commitRoot 失败: {e}"));
    }
    // 对账口径：Bridge 浮存减少量 = 实付金额（与领款人侧 gas 无关——
    // 领款人若为 operator 自身，其余额增量会被 claim 交易的 gas 污染）。
    let bridge_float_before = rpc.get_balance(&bridge).unwrap_or(0);
    let claim = send_tx(
        rpc, key, chain_id, Some(outbox), 0,
        encode_claim(&leaf, root, 1, 0, &[]), 400_000,
    )
    .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40));
    match claim {
        Ok(receipt) if receipt.success => {
            let paid = bridge_float_before.saturating_sub(rpc.get_balance(&bridge).unwrap_or(0));
            (paid == amount, format!("claim 成功，Bridge 浮存 -{paid} wei（期望 {amount}）"))
        }
        Ok(receipt) => (false, format!("claim 回执失败（block {}）", receipt.block_number)),
        Err(e) => (false, format!("claim 发送失败: {e}")),
    }
}

/// 大额延迟项：threshold=1 → 提交第二提现根 → 延迟未满 claim 必败 →
/// 出块越过 claimDelayBlocks 后 claim 成功。
fn large_delay_check(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    outbox: [u8; 20],
    poll_ms: u64,
) -> (bool, String) {
    // threshold(TAG_NATIVE) = 1 wei → 任意金额都走延迟。
    if let Err(e) = send_tx(rpc, key, chain_id, Some(outbox), 0, encode_set_large_payout_threshold(1, 1), 100_000)
        .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40))
        .and_then(|r| if r.success { Ok(()) } else { Err(SettlementError::shape("threshold", "receipt failed")) })
    {
        return (false, format!("setLargePayoutThreshold 失败: {e}"));
    }
    let leaf = ClaimLeaf {
        request_id: keccak_seed(b"zchain-e2e.withdraw.2"),
        external_recipient: word_address_of(key.address()),
        asset_tag: TAG_NATIVE,
        amount: u64::try_from(WITHDRAW_AMOUNT_2).expect("amount fits u64"),
        burned_note_commitment: keccak_seed(b"zchain-e2e.burn.2"),
        checkpoint_height: 2,
    };
    let root = monad_settlement::proof::leaf_hash(&leaf);
    if let Err(e) = send_tx(rpc, key, chain_id, Some(outbox), 0, encode_commit_root(2, 1, root, true), 200_000)
        .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40))
        .and_then(|r| if r.success { Ok(()) } else { Err(SettlementError::shape("commit", "receipt failed")) })
    {
        return (false, format!("commitRoot(2) 失败: {e}"));
    }
    // 提前领取：必须失败（ClaimTooEarly → status=0）。
    let early = send_tx(rpc, key, chain_id, Some(outbox), 0, encode_claim(&leaf, root, 1, 0, &[]), 400_000)
        .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40));
    let rejected_early = matches!(early, Ok(receipt) if !receipt.success);
    // 轮询至延迟期满后领取成功（30 块 ≈ 10-15s）。
    let mut claimed_after = false;
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(poll_ms.max(1_000)));
        let claim = send_tx(rpc, key, chain_id, Some(outbox), 0, encode_claim(&leaf, root, 1, 0, &[]), 400_000)
            .and_then(|h| rpc.wait_receipt(&h, poll_ms.max(1_000), 40));
        if matches!(claim, Ok(receipt) if receipt.success) {
            claimed_after = true;
            break;
        }
    }
    (
        rejected_early && claimed_after,
        format!("延迟未满被拒={rejected_early}（ClaimTooEarly 预期）；期满后领取成功={claimed_after}"),
    )
}

// ---------------------------------------------------------------------------
// 部署 / 交易工具
// ---------------------------------------------------------------------------

fn deploy_stack(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    bytecode_dir: &str,
    poll_ms: u64,
) -> Result<([u8; 20], [u8; 20], [u8; 20]), SettlementError> {
    let load = |name: &str| -> Result<Vec<u8>, SettlementError> {
        let hex_str = std::fs::read_to_string(format!("{bytecode_dir}/{name}.bin"))
            .map_err(|e| SettlementError::shape("bytecode", format!("{name}: {e}")))?;
        hex::decode(hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim()))
            .map_err(|e| SettlementError::shape("bytecode", e.to_string()))
    };

    let bridge_addr = deploy_one(rpc, key, chain_id, "L1Bridge", load("L1Bridge")?, poll_ms)?;
    let outbox_addr = deploy_one(rpc, key, chain_id, "L1Outbox", load("L1Outbox")?, poll_ms)?;
    let inbox_addr = deploy_one(rpc, key, chain_id, "L1Inbox", load("L1Inbox")?, poll_ms)?;

    // 互联（一次性授权边）+ 延迟参数。
    for (name, to, data) in [
        ("outbox.setInbox", outbox_addr, encode_set_address("setInbox(address)", inbox_addr)),
        ("outbox.setBridge", outbox_addr, encode_set_address("setBridge(address)", bridge_addr)),
        ("inbox.setOutbox", inbox_addr, encode_set_address("setOutbox(address)", outbox_addr)),
        ("bridge.setOutbox", bridge_addr, encode_set_address("setOutbox(address)", outbox_addr)),
        ("outbox.setClaimDelayBlocks", outbox_addr, encode_set_claim_delay_blocks(CLAIM_DELAY_BLOCKS)),
    ] {
        let tx_hash = send_tx(rpc, key, chain_id, Some(to), 0, data, 200_000)?;
        let receipt = rpc.wait_receipt(&tx_hash, poll_ms.max(1_000), 40)?;
        if !receipt.success {
            return Err(SettlementError::shape("wire", format!("{name} failed")));
        }
        println!("[wire] {name} ok");
    }
    Ok((inbox_addr, outbox_addr, bridge_addr))
}

fn deploy_one(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    name: &str,
    code: Vec<u8>,
    poll_ms: u64,
) -> Result<[u8; 20], SettlementError> {
    // 三个合约构造函数同签名 (address initialAuthority_)：solc 字节码尾部
    // 必须拼接 ABI 编码的构造参数（forge script 自动做，手写部署要手动补）。
    let mut code = code;
    code.extend_from_slice(&monad_settlement::abi::word_address(key.address()));
    let tx_hash = send_tx(rpc, key, chain_id, None, 0, code, 2_000_000)?;
    let receipt = rpc.wait_receipt(&tx_hash, poll_ms.max(1_000), 40)?;
    if !receipt.success {
        return Err(SettlementError::shape("deploy", format!("{name} creation reverted")));
    }
    // 地址回查：优先取回执权威 contractAddress，缺失时按 CREATE 公式派生。
    let address = match receipt.contract_address {
        Some(a) => a,
        None => {
            let nonce = rpc.transaction_count(&key.address())? - 1;
            contract_address(&key.address(), nonce)
        }
    };
    let code_at = rpc.get_code(&address)?;
    if code_at.is_empty() {
        return Err(SettlementError::shape("deploy", format!("{name} no code at 0x{}", hex::encode(address))));
    }
    println!("[deploy] {name} = 0x{}（{}B code）", hex::encode(address), code_at.len());
    Ok(address)
}

fn send_tx(
    rpc: &L1Rpc,
    key: &Credentials,
    chain_id: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    gas_limit: u128,
) -> Result<[u8; 32], SettlementError> {
    let nonce = rpc.transaction_count(&key.address())?;
    let gas_price = rpc.gas_price()?.saturating_mul(11) / 10;
    let tx = LegacyTx { nonce, gas_price, gas_limit, to, value, data };
    let signed = key.sign_eip155(&tx, chain_id)?;
    rpc.send_raw_transaction(&signed.raw)
}

/// CREATE 地址派生 = keccak(0xff ‖ sender ‖ rlp(nonce))[12..]。
fn contract_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut buf = Vec::with_capacity(32);
    buf.push(0xff);
    buf.extend_from_slice(sender);
    if nonce == 0 {
        buf.push(0x80); // RLP 空串
    } else if nonce < 0x80 {
        buf.push(nonce as u8); // 单字节内联
    } else {
        let be = nonce.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        let len = be.len() - first;
        buf.push(0x80 + len as u8);
        buf.extend_from_slice(&be[first..]);
    }
    let hash = monad_settlement::keccak::keccak256(&buf);
    hash[12..].try_into().expect("20 of 32")
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

fn word_address_of(addr: [u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&addr);
    w
}

fn keccak_seed(seed: &[u8]) -> [u8; 32] {
    monad_settlement::keccak::keccak256(seed)
}

fn decode_u64_word(ret: &[u8]) -> Option<u64> {
    if ret.len() < 32 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&ret[24..32]);
    Some(u64::from_be_bytes(b))
}

fn record(checks: &mut Vec<Check>, item: &str, ok: bool, detail: String) -> bool {
    println!("[{}] {}: {}", if ok { "PASS" } else { "FAIL" }, item, detail);
    checks.push(Check { item: item.to_string(), ok, detail });
    ok
}

fn fail_early(checks: &mut Vec<Check>, item: &str, e: SettlementError) -> i32 {
    println!("[FAIL] {item}: {e}");
    checks.push(Check { item: item.to_string(), ok: false, detail: e.to_string() });
    summarize(checks)
}

fn summarize(checks: &[Check]) -> i32 {
    let passed = checks.iter().filter(|c| c.ok).count();
    let summary = serde_json::json!({
        "e2e": "monad-testnet-settlement",
        "passed": passed,
        "failed": checks.len() - passed,
        "checks": checks.iter().map(|c| serde_json::json!({
            "item": c.item, "ok": c.ok, "detail": c.detail,
        })).collect::<Vec<_>>(),
    });
    println!("e2e_summary_json {summary}");
    println!("[e2e] {passed}/{} PASS", checks.len());
    (checks.len() - passed) as i32
}
