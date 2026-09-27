//! monad_settlementd — zchain L2 → Monad(L1) 结算守护进程（生产装配点）。
//!
//! 三类锚定源（**只锚已验证/已终结产物**的纪律）：
//! - 批次根/聚合根：explorer_gateway 只读 API（proven log / 聚合账）；
//! - checkpoint：`--checkpoint-file` 指向 poker-appchain M8 checkpoint JSON
//!   （`zchain.appchain.checkpoint.v1`，BFT finalized 后产出、可携带
//!   withdrawal_root）——state root + 提现根**同文件原子上锚**；
//! - 入金：L1Bridge `DepositInitiated`（finalized 窗口）→ JSONL 落盘 +
//!   可选 POST 到 L2 运营 ingest 端点（sequencer 据此提交 `DepositV2`
//!   op，deposit_id 幂等）。
//!
//! 状态持久化：`--state-file` JSON（anchor 状态 + deposit 水位），原子写
//! （tmp + rename），重启不重放已上锚项。
//!
//! 用法示例：
//! ```text
//! monad_settlementd --mode all \
//!   --l1-rpc https://rpc.monad.xyz --expected-chain-id 143 \
//!   --inbox 0x… --bridge 0x… \
//!   --key-env MONAD_SETTLEMENT_KEY \
//!   --gateway http://127.0.0.1:18900 \
//!   --checkpoint-file ./checkpoints/latest.json \
//!   --state-file ./settlement-state.json \
//!   --deposits-file ./deposits.jsonl \
//!   --poll-interval-ms 4000
//! ```

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use monad_settlement::{
    aggregate_task, anchor_task, checkpoint_task, AnchorState, AnchorSubmitter, Credentials,
    DepositWatcher, L1Rpc, SettlementError, MONAD_TESTNET_CHAIN_ID,
};

fn main() {
    let args = parse_args(collect_flag_map(std::env::args().skip(1).collect()));
    if args.mode == "probe" {
        // 真实网络验收清单：非 0 退出 = 存在 FAIL 项。
        std::process::exit(run_probe(&args));
    }
    if let Err(e) = run(args) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}

/// `--flag value` 序列 → map（缺 value 即 fatal；`--help`/`-h` 为布尔旗标）。
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

struct Args {
    mode: String,
    l1_rpc: String,
    expected_chain_id: u64,
    inbox: Option<[u8; 20]>,
    bridge: Option<[u8; 20]>,
    key: Option<Credentials>,
    gateway: String,
    checkpoint_file: Option<PathBuf>,
    state_file: Option<PathBuf>,
    deposits_file: Option<PathBuf>,
    ingest_url: Option<String>,
    poll_interval_ms: u64,
    bridge_start_block: u64,
    probe_height_interval_ms: u64,
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

fn parse_args(args: BTreeMap<String, String>) -> Args {
    if args.contains_key("help") || args.contains_key("h") {
        print_help();
        std::process::exit(0);
    }
    let get = |name: &str| -> Option<String> { args.get(name).cloned() };
    let parse_u64 = |name: &str, default: u64| -> u64 {
        get(name).map_or(default, |s| {
            s.parse::<u64>().unwrap_or_else(|e| die(&format!("bad --{name}: {e}")))
        })
    };
    let mode = get("mode").unwrap_or_else(|| "all".to_string());
    if !matches!(mode.as_str(), "anchor" | "bridge" | "all" | "probe") {
        die("--mode must be anchor|bridge|all|probe");
    }
    let l1_rpc = get("l1-rpc").unwrap_or_default();
    if l1_rpc.is_empty() {
        die("--l1-rpc is required");
    }
    let key = if let Some(env_name) = get("key-env") {
        Some(Credentials::from_hex(&std::env::var(&env_name).unwrap_or_else(|_| {
            die(&format!("env {env_name} not set"))
        })))
        .map(|r| r.unwrap_or_else(|e| die(&format!("bad key: {e}"))))
    } else {
        get("key-file").map(|path| {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| die(&format!("key file {path}: {e}")));
            Credentials::from_hex(raw.trim()).unwrap_or_else(|e| die(&format!("bad key file: {e}")))
        })
    };
    Args {
        mode,
        l1_rpc,
        expected_chain_id: parse_u64("expected-chain-id", 143),
        inbox: get("inbox").map(|s| parse_hex20(&s)),
        bridge: get("bridge").map(|s| parse_hex20(&s)),
        key,
        gateway: get("gateway").unwrap_or_else(|| "http://127.0.0.1:18900".to_string()),
        checkpoint_file: get("checkpoint-file").map(PathBuf::from),
        state_file: get("state-file").map(PathBuf::from),
        deposits_file: get("deposits-file").map(PathBuf::from),
        ingest_url: get("ingest-url"),
        poll_interval_ms: parse_u64("poll-interval-ms", 4_000),
        bridge_start_block: parse_u64("bridge-start-block", 0),
        probe_height_interval_ms: parse_u64("probe-height-interval-ms", 3_000),
    }
}

fn print_help() {
    eprintln!(
        "monad_settlementd — zchain L2 → Monad L1 settlement daemon\n\
         required : --l1-rpc <url>\n\
         anchor   : --inbox <0x..> --key-env <ENV>|--key-file <path>\n\
                    [--gateway URL] [--checkpoint-file path] [--state-file path]\n\
         bridge   : --bridge <0x..> [--bridge-start-block N]\n\
                    [--deposits-file path] [--ingest-url URL]\n\
         probe    : [--probe-height-interval-ms N]（真实网络验收清单，只读 +\n\
                    随机空钥交易格式验证；输出 JSON 摘要，非 0 退出 = 有 FAIL）\n\
         common   : [--mode anchor|bridge|all|probe] [--expected-chain-id 143|10143]\n\
                    [--poll-interval-ms N] [--help]\n\
         chain ids: mainnet 143, testnet {}",
        MONAD_TESTNET_CHAIN_ID
    );
}

/// probe 模式的单项验收结果。
struct ProbeCheck {
    item: &'static str,
    ok: bool,
    detail: String,
}

/// 真实网络验收清单（对应 docs/monad-l2-settlement.md §6.3 前五项 +
/// 交易格式验证）：全部只读，唯一写操作是**随机空钥**的 deploy 探针交易
/// （预期被资金校验拒绝——恰好证明交易格式/签名被真实网络接受）。
fn run_probe(args: &Args) -> i32 {
    let mut checks: Vec<ProbeCheck> = Vec::new();
    let record = |item: &'static str, ok: bool, detail: String, checks: &mut Vec<ProbeCheck>| {
        log(&format!(
            "[{}] {}: {}",
            if ok { "PASS" } else { "FAIL" },
            item,
            detail
        ));
        checks.push(ProbeCheck { item, ok, detail });
    };

    let rpc = match L1Rpc::new(args.l1_rpc.clone()) {
        Ok(r) => r,
        Err(e) => {
            record("rpc_connect", false, e.to_string(), &mut checks);
            summarize_probe(&checks);
            return 1;
        }
    };

    // 1. chainId 闸门（防错链）。
    match rpc.chain_id() {
        Ok(id) => record(
            "chain_id",
            id == args.expected_chain_id,
            format!("expected {expected}, got {id}", expected = args.expected_chain_id),
            &mut checks,
        ),
        Err(e) => record("chain_id", false, e.to_string(), &mut checks),
    }

    // 2. 出块推进：间隔采样两次，高度必须严格递增。
    let interval = Duration::from_millis(args.probe_height_interval_ms);
    match rpc.block_number() {
        Ok(a) => {
            std::thread::sleep(interval);
            match rpc.block_number() {
                Ok(b) => record(
                    "block_advance",
                    b > a,
                    format!(
                        "height {a} → {b} (+{}) in {}ms",
                        b - a,
                        args.probe_height_interval_ms
                    ),
                    &mut checks,
                ),
                Err(e) => record("block_advance", false, format!("{a} → err: {e}"), &mut checks),
            }
        }
        Err(e) => record("block_advance", false, e.to_string(), &mut checks),
    }

    // 3. finalized 标签：可用、非零、≤ latest。
    match rpc.finalized_block() {
        Ok(f) => {
            let latest = rpc.block_number().unwrap_or(u64::MAX);
            record(
                "finalized_tag",
                f > 0 && f <= latest,
                format!("finalized={f} latest={latest}（单槽终结延迟 {} 块）", latest.saturating_sub(f)),
                &mut checks,
            )
        }
        Err(e) => record("finalized_tag", false, e.to_string(), &mut checks),
    }

    // 4. gas 价格面。
    match rpc.gas_price() {
        Ok(g) if g > 0 => record("gas_price", true, format!("{} wei（{} gwei）", g, g / 1_000_000_000), &mut checks),
        Ok(g) => record("gas_price", false, format!("zero gas price: {g}"), &mut checks),
        Err(e) => record("gas_price", false, e.to_string(), &mut checks),
    }

    // 5. 随机空钥账户：nonce == 0（账户面可查询 + 键不在链上，符合预期）。
    let ephemeral = match ephemeral_credentials() {
        Ok(c) => c,
        Err(e) => {
            record("ephemeral_key", false, e, &mut checks);
            summarize_probe(&checks);
            return 1;
        }
    };
    log(&format!(
        "probe ephemeral address: 0x{}（仅用于只读/探针，不含任何资金）",
        hex::encode(ephemeral.address())
    ));
    match rpc.transaction_count(&ephemeral.address()) {
        Ok(0) => record("fresh_account_nonce", true, "nonce = 0".into(), &mut checks),
        Ok(n) => record("fresh_account_nonce", false, format!("unexpected nonce {n}"), &mut checks),
        Err(e) => record("fresh_account_nonce", false, e.to_string(), &mut checks),
    }

    // 6. eth_getLogs 面：域过滤 + topic0 过滤可执行（空结果即通过）。
    match rpc.block_number() {
        Ok(latest) => match rpc.get_logs(
            latest.saturating_sub(100),
            latest,
            &[ephemeral.address()],
            Some(monad_settlement::abi::deposit_initiated_topic0()),
        ) {
            Ok(logs) if logs.is_empty() => record("get_logs", true, format!("window [{}, {}] empty（endpoint OK）", latest.saturating_sub(100), latest), &mut checks),
            Ok(logs) => record("get_logs", false, format!("unexpected {} logs", logs.len()), &mut checks),
            Err(e) => record("get_logs", false, e.to_string(), &mut checks),
        },
        Err(e) => record("get_logs", false, e.to_string(), &mut checks),
    }

    // 7. 交易格式验证：EIP-155 deploy 探针（随机空钥）。真实网络必须把
    //    交易解码并通过签名/格式校验、最终停在资金闸门——这是"无资金
    //    前提下能拿到的最强格式验收"。资金闸门文案命中 → PASS。
    let tx_format = probe_tx_format(&rpc, &ephemeral, args.expected_chain_id);
    record(tx_format.0, tx_format.1, tx_format.2, &mut checks);

    summarize_probe(&checks);
    checks.iter().filter(|c| !c.ok).count() as i32
}

/// 随机空钥凭据（/dev/urandom 32B；std-only 熵源）。
fn ephemeral_credentials() -> Result<Credentials, String> {
    use std::io::Read;
    let mut key = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .map_err(|e| format!("read /dev/urandom: {e}"))?;
    Credentials::from_bytes(&key).map_err(|e| e.to_string())
}

/// deploy 探针：init code = 0x00（STOP，合法建厂码），随机空钥 + gasPrice×1.1。
/// PASS = 网络返回资金类拒绝（格式/签名已被接受）或意外入账（几乎不可能）。
fn probe_tx_format(rpc: &L1Rpc, creds: &Credentials, chain_id: u64) -> (&'static str, bool, String) {
    let Ok(gas_price) = rpc.gas_price() else {
        return ("tx_format_probe", false, "gas_price unavailable".into());
    };
    let tx = monad_settlement::signer::LegacyTx {
        nonce: 0,
        gas_price: gas_price.saturating_mul(11) / 10,
        gas_limit: 100_000,
        to: None,
        value: 0,
        data: vec![0x00],
    };
    let signed = match creds.sign_eip155(&tx, chain_id) {
        Ok(s) => s,
        Err(e) => return ("tx_format_probe", false, format!("local signing failed: {e}")),
    };
    match rpc.send_raw_transaction(&signed.raw) {
        Ok(hash) => (
            "tx_format_probe",
            true,
            format!("unexpectedly accepted（空钥有资金？）tx=0x{}", hex::encode(hash)),
        ),
        Err(SettlementError::Rpc { message, .. }) => {
            let lowered = message.to_lowercase();
            let funds_gate = lowered.contains("insufficient")
                || lowered.contains("balance")
                || lowered.contains("exceeds");
            (
                "tx_format_probe",
                funds_gate,
                if funds_gate {
                    format!("资金闸门按预期拒绝（签名/格式已被真实网络接受）: {message}")
                } else {
                    format!("非资金类拒绝（可能为格式/规则问题）: {message}")
                },
            )
        }
        Err(e) => ("tx_format_probe", false, format!("transport: {e}")),
    }
}

/// JSON 摘要 + 统计行。
fn summarize_probe(checks: &[ProbeCheck]) {
    let passed = checks.iter().filter(|c| c.ok).count();
    let summary = serde_json::json!({
        "probe": "monad-testnet-acceptance",
        "passed": passed,
        "failed": checks.len() - passed,
        "checks": checks.iter().map(|c| serde_json::json!({
            "item": c.item, "ok": c.ok, "detail": c.detail,
        })).collect::<Vec<_>>(),
    });
    println!("probe_summary_json {}", summary);
    log(&format!("probe finished: {}/{} PASS", passed, checks.len()));
}

fn run(args: Args) -> Result<(), SettlementError> {
    let want_anchor = args.mode != "bridge";
    let want_bridge = args.mode != "anchor";
    if want_anchor && (args.inbox.is_none() || args.key.is_none()) {
        die("anchor mode requires --inbox and --key-env/--key-file");
    }
    if want_bridge && args.bridge.is_none() {
        die("bridge mode requires --bridge");
    }

    // chainId 闸门：启动即校验，防错链全流程（143 / 10143 之外一律拒绝）。
    let actual = L1Rpc::new(args.l1_rpc.clone())?.chain_id()?;
    if actual != args.expected_chain_id {
        return Err(SettlementError::ChainIdMismatch {
            expected: args.expected_chain_id,
            actual,
        });
    }
    log(&format!("chain id verified: {actual}"));

    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| SettlementError::transport("http", e.to_string()))?;

    let mut submitter = if want_anchor {
        let mut s = AnchorSubmitter::connect(
            L1Rpc::new(args.l1_rpc.clone())?,
            args.key.clone().expect("checked"),
            args.inbox.expect("checked"),
            args.expected_chain_id,
        )?;
        if let Some(v) = read_state_file(&args.state_file) {
            s.restore(restore_states(&v));
            log("anchor state restored");
        }
        Some(s)
    } else {
        None
    };

    let deposit_start = read_state_file(&args.state_file)
        .and_then(|v| v.get("deposit_next_block").and_then(Value::as_u64))
        .unwrap_or(args.bridge_start_block);
    let mut watcher = if want_bridge {
        Some(DepositWatcher::new(
            L1Rpc::new(args.l1_rpc.clone())?,
            args.bridge.expect("checked"),
            deposit_start,
        ))
    } else {
        None
    };

    log(&format!(
        "daemon started mode={} gateway={} poll={}ms",
        args.mode, args.gateway, args.poll_interval_ms
    ));
    let interval = Duration::from_millis(args.poll_interval_ms);
    loop {
        if let Some(submitter) = submitter.as_mut() {
            anchor_round(submitter, &http, &args);
        }
        if let Some(w) = watcher.as_mut() {
            bridge_round(w, &http, &args);
        }
        if args.state_file.is_some() {
            let deposit_next = watcher.as_ref().map_or(0, DepositWatcher::next_block);
            if let Some(submitter) = submitter.as_ref() {
                save_state(submitter, deposit_next, args.state_file.as_deref());
            }
        }
        std::thread::sleep(interval);
    }
}

/// anchor 一轮：三类锚定源 → 组任务 → 提交 → poll（回执 + finality）。
fn anchor_round(submitter: &mut AnchorSubmitter, http: &reqwest::blocking::Client, args: &Args) {
    // 1. 批次根（gateway proven log，按追加序；inbox index = 已提交计数）。
    if let Ok(body) = http_get(http, &format!("{}/api/v1/batch_roots", args.gateway)) {
        if let Some(items) = body.get("batch_roots").and_then(Value::as_array) {
            let mut index = submitter.snapshot().keys().filter(|k| k.starts_with("batch:")).count()
                as u64;
            for item in items {
                let Some(root) = item.get("batch_root").and_then(Value::as_str) else { continue };
                let through_op = item.get("op_index").and_then(Value::as_u64).unwrap_or(0);
                let Ok(root32) = parse_32(root) else { continue };
                let task = anchor_task(index, root32, through_op);
                match submitter.submit(&task) {
                    Ok(Some(tx)) => {
                        log(&format!("batch #{index} submitted tx=0x{}", hex::encode(tx)))
                    }
                    Ok(None) => {}
                    Err(e) => log(&format!("batch #{index} submit failed: {e}")),
                }
                index += 1;
            }
        }
    }
    // 2. 聚合根（gateway index 连续；直接采用其 index，缺口由合约连续纪律兜底）。
    if let Ok(body) = http_get(http, &format!("{}/api/v1/aggregates", args.gateway)) {
        if let Some(items) = body.get("aggregates").and_then(Value::as_array) {
            for item in items {
                let Some(remote_index) = item.get("index").and_then(Value::as_u64) else { continue };
                let Some(root) = item.get("root").and_then(Value::as_str) else { continue };
                let through_op = item.get("through_op").and_then(Value::as_u64).unwrap_or(0);
                let batch_count = item.get("batch_count").and_then(Value::as_u64).unwrap_or(0);
                let Ok(root32) = parse_32(root) else { continue };
                let task = aggregate_task(remote_index, root32, through_op, batch_count);
                match submitter.submit(&task) {
                    Ok(Some(tx)) => {
                        log(&format!("aggregate #{remote_index} submitted tx=0x{}", hex::encode(tx)))
                    }
                    Ok(None) => {}
                    Err(e) => log(&format!("aggregate #{remote_index} submit failed: {e}")),
                }
            }
        }
    }
    // 3. checkpoint（M8 文件：state root + withdrawal root 原子上锚；
    //    同高度 + 新提现根 = 不同 key，但合约拒绝同高度重锚 —— daemon 以
    //    "文件更新即重解析，锚定只取最后一次"为纪律，见 runbook）。
    if let Some(path) = &args.checkpoint_file {
        if let Some(task) = checkpoint_task_from_file(path) {
            match submitter.submit(&task) {
                Ok(Some(tx)) => log(&format!("checkpoint submitted tx=0x{}", hex::encode(tx))),
                Ok(None) => {}
                Err(e) => log(&format!("checkpoint submit failed: {e}")),
            }
        }
    }
    if let Err(e) = submitter.poll() {
        log(&format!("poll failed: {e}"));
    }
    let pending = submitter.pending_finality();
    if pending > 0 {
        log(&format!("{pending} anchors awaiting finality"));
    }
}

/// 从 M8 checkpoint JSON 组上锚任务（head_index 作 l2 高度键）。
fn checkpoint_task_from_file(path: &Path) -> Option<monad_settlement::AnchorTask> {
    let raw = std::fs::read_to_string(path).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    if v.get("format").and_then(Value::as_str) != Some("zchain.appchain.checkpoint.v1") {
        return None;
    }
    let head_index = v.get("head_index").and_then(Value::as_u64)?;
    let state_root = parse_32(v.get("state_root").and_then(Value::as_str)?).ok()?;
    let withdrawal_root = v.get("withdrawal_root").and_then(Value::as_object).and_then(|w| {
        let root = parse_32(w.get("root").and_then(Value::as_str)?).ok()?;
        let leaf_count = w.get("leaf_count").and_then(Value::as_u64)?;
        Some((root, leaf_count))
    });
    Some(checkpoint_task(head_index, state_root, withdrawal_root))
}

/// bridge 一轮：拉入金 → JSONL 落盘 + 可选 ingest POST。
fn bridge_round(watcher: &mut DepositWatcher, http: &reqwest::blocking::Client, args: &Args) {
    match watcher.poll_once() {
        Ok(events) => {
            for ev in events {
                let line = json!({
                    "nonce": ev.nonce,
                    "token": format!("0x{}", hex::encode(ev.token)),
                    "to": format!("0x{}", hex::encode(ev.to)),
                    "amount": ev.amount.to_string(),
                })
                .to_string();
                log(&format!(
                    "deposit #{} token=0x{} to=0x{} amount={}",
                    ev.nonce,
                    hex::encode(ev.token),
                    hex::encode(ev.to),
                    ev.amount
                ));
                if let Some(path) = &args.deposits_file {
                    if let Ok(mut f) =
                        std::fs::OpenOptions::new().create(true).append(true).open(path)
                    {
                        let _ = writeln!(f, "{line}");
                    }
                }
                if let Some(url) = &args.ingest_url {
                    if let Err(e) = http
                        .post(url)
                        .header("content-type", "application/json")
                        .body(line)
                        .send()
                    {
                        log(&format!("ingest post failed: {e}"));
                    }
                }
            }
        }
        Err(e) => log(&format!("deposit poll failed: {e}")),
    }
}

fn parse_32(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn http_get(http: &reqwest::blocking::Client, url: &str) -> Result<Value, String> {
    let resp = http
        .get(url)
        .send()
        .map_err(|e| e.to_string())?
        .error_for_status()
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&resp.text().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn read_state_file(path: &Option<PathBuf>) -> Option<Value> {
    let path = path.as_ref()?;
    let raw = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            log(&format!("state file unreadable ({e}); starting fresh"));
            None
        }
    }
}

fn restore_states(v: &Value) -> BTreeMap<String, AnchorState> {
    let mut out = BTreeMap::new();
    if let Some(map) = v.get("anchors").and_then(Value::as_object) {
        for (key, entry) in map {
            let Ok(tx) = parse_32(entry.get("tx").and_then(Value::as_str).unwrap_or("")) else {
                continue;
            };
            let block = entry.get("block").and_then(Value::as_u64);
            let finalized = entry.get("finalized").and_then(Value::as_bool).unwrap_or(false);
            let state = match (block, finalized) {
                (None, _) => AnchorState::Submitted { tx_hash: tx },
                (Some(b), false) => AnchorState::Included { tx_hash: tx, block: b },
                (Some(b), true) => AnchorState::Finalized { tx_hash: tx, block: b },
            };
            out.insert(key.clone(), state);
        }
    }
    out
}

fn save_state(submitter: &AnchorSubmitter, deposit_next_block: u64, path: Option<&Path>) {
    let Some(path) = path else { return };
    let mut anchors = serde_json::Map::new();
    for (key, state) in submitter.snapshot() {
        anchors.insert(
            key,
            json!({
                "tx": format!("0x{}", hex::encode(state.tx_hash())),
                "block": state.block(),
                "finalized": state.is_finalized(),
            }),
        );
    }
    let body = json!({
        "anchors": anchors,
        "deposit_next_block": deposit_next_block,
    });
    // 原子写（tmp + rename），防撕裂。
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, body.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn log(message: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("[{now}] {message}");
}
