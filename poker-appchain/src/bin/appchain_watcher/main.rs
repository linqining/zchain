//! M8：appchain watcher——独立审计进程（三者一致性 + 分叉检测）。
//!
//! 定位：**不信任单一来源**。watcher 从 WAL（或任意链导出）独立重算：
//!
//! - (a) 软确认链完整性：逐帧验签 + prev_hash/index 接续 + 全量重放对
//!   每帧 `state_root` 重放对拍（[`Sequencer::replay`]，独立代码路径）；
//! - (b) 结算语义：每条 [`Operation::Settle`] 用**表注册表策略**
//!   （`state().registry`，重放重建）跑 [`validate_settlement`] 纯函数；
//!   策略不可得的记录为 **WARN 项**（诚实边界：watcher 无法凭空知道
//!   桌策略，不算失败）；
//! - (c) proven log 一致性：按冻结契约解析后，逐条用
//!   [`batch_root`]（与 producer 相同的 op 哈希序 = 批次窗口内 Settle
//!   的 `hand_binding` 升序折叠）独立重算并比对 root；watermark ≤ 链头；
//!   op_index 严格递增；
//! - (c2) aggregate log 一致性（v1.2.3，`--aggregate-log` 可选）：index
//!   连续（从 0 起）、through_op 严格递增且 ≤ 链头；逐条从 proven log 取
//!   窗口 `(prev_through, through_op]` 内的批次根，用 [`aggregate_roots`]
//!   独立重算并比对聚合根（不符 → finding `aggregate_mismatch`，exit 1）；
//! - (d) checkpoint（若给）：[`checkpoint::verify_checkpoint`] 全字段
//!   对拍 + 载荷 digest 校验；
//! - (e) 分叉检测（M8-ACC-6 精神）：`--wal-b` 双链喂入，加载后**即时**
//!   首个分歧帧 index（复用 [`compare_chains`]）。
//!
//! 输出：人类可读报告（stdout）+ `--json-out` 结构化 findings；
//! 退出码 **0 = 一致 / 1 = 发现不一致 / 2 = 用法错误**。
//!
//! 用法：
//!
//! ```text
//! appchain_watcher --appchain-wal <p> --sequencer-public <64hex>
//!                  [--proven-log <p>] [--aggregate-log <p>] [--checkpoint <p>]
//!                  [--wal-b <p>] [--follow-interval-secs N] [--json-out <p>]
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use poker_appchain::aggregate::{aggregate_roots, AggregateRecord};
use poker_appchain::checkpoint;
use poker_appchain::keys::SequencerKey;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::batch_root;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::validate_settlement;
use poker_appchain::soft_confirm::genesis_prev_hash;
use poker_appchain::wal;
use poker_appchain::watcher::compare_chains;

const USAGE: &str = "usage: appchain_watcher --appchain-wal <path> --sequencer-public <64hex>\n\
                     [--proven-log <path>] [--aggregate-log <path>] [--checkpoint <path>]\n\
                     [--wal-b <path>] [--follow-interval-secs <N>] [--json-out <path>]";

/// finding 严重级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    /// 不一致（决定退出码 1）。
    Error,
    /// 观察项/诚实边界（不影响退出码）。
    Warn,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
        }
    }
}

/// 一条检查结论。
#[derive(Debug, Clone)]
struct Finding {
    category: &'static str,
    severity: Severity,
    detail: String,
    at_index: Option<u64>,
}

impl Finding {
    fn error(category: &'static str, detail: String, at_index: Option<u64>) -> Self {
        Self {
            category,
            severity: Severity::Error,
            detail,
            at_index,
        }
    }

    fn warn(category: &'static str, detail: String, at_index: Option<u64>) -> Self {
        Self {
            category,
            severity: Severity::Warn,
            detail,
            at_index,
        }
    }
}

/// 一次检查轮的汇总。
#[derive(Debug, Default)]
struct PassOutcome {
    findings: Vec<Finding>,
    frames_checked: usize,
    proven_entries: usize,
    aggregate_entries: usize,
    fork_at: Option<u64>,
}

impl PassOutcome {
    fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    fn warnings(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
            .count()
    }

    fn consistent(&self) -> bool {
        self.errors() == 0
    }
}

/// 命令行参数。
struct Args {
    appchain_wal: PathBuf,
    sequencer_public: [u8; 32],
    proven_log: Option<PathBuf>,
    aggregate_log: Option<PathBuf>,
    checkpoint: Option<PathBuf>,
    wal_b: Option<PathBuf>,
    follow_interval_secs: Option<u64>,
    json_out: Option<PathBuf>,
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// 解析参数；任何用法错误 → Err（退出码 2）。
fn parse_args(iter: impl Iterator<Item = String>) -> Result<Args, String> {
    let argv: Vec<String> = iter.collect();
    let mut appchain_wal = None;
    let mut sequencer_public = None;
    let mut proven_log = None;
    let mut aggregate_log = None;
    let mut checkpoint_path = None;
    let mut wal_b = None;
    let mut follow = None;
    let mut json_out = None;
    let mut i = 0usize;
    while i < argv.len() {
        let arg = argv[i].clone();
        let value_of = || -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("missing value after {arg} (use --help)"))
        };
        match arg.as_str() {
            "--appchain-wal" => {
                appchain_wal = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--sequencer-public" => {
                let v = value_of()?;
                sequencer_public = Some(
                    parse_hex32(&v)
                        .ok_or_else(|| "--sequencer-public expects 64 hex chars".to_string())?,
                );
                i += 1;
            }
            "--proven-log" => {
                proven_log = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--aggregate-log" => {
                aggregate_log = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--checkpoint" => {
                checkpoint_path = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--wal-b" => {
                wal_b = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--follow-interval-secs" => {
                let v = value_of()?;
                follow = Some(v.parse::<u64>().map_err(|_| {
                    format!("--follow-interval-secs expects an integer, got {v:?}")
                })?);
                i += 1;
            }
            "--json-out" => {
                json_out = Some(PathBuf::from(value_of()?));
                i += 1;
            }
            "--help" | "-h" => return Err(USAGE.to_string()),
            other => return Err(format!("unknown argument {other:?} (use --help)")),
        }
        i += 1;
    }
    Ok(Args {
        appchain_wal: appchain_wal.ok_or("--appchain-wal is required")?,
        sequencer_public: sequencer_public.ok_or("--sequencer-public is required")?,
        proven_log,
        aggregate_log,
        checkpoint: checkpoint_path,
        wal_b,
        follow_interval_secs: follow,
        json_out,
    })
}

/// 解析一行 proven log（冻结契约：op_index / batch_root(64hex) / ts_ms）。
fn parse_proven_line(line: &str) -> Option<(u64, [u8; 32], u64)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let op_index = obj.get("op_index")?.as_u64()?;
    let root_hex = obj.get("batch_root")?.as_str()?;
    let ts_ms = obj.get("ts_ms")?.as_u64()?;
    let root: [u8; 32] = hex::decode(root_hex).ok()?.try_into().ok()?;
    Some((op_index, root, ts_ms))
}

/// 读取 proven log（冻结契约；撕裂尾行忽略 + WARN finding）。
/// 纪律与写入方/网关读取方一致：空文件合法，中间行损坏 → error。
fn read_proven_log(path: &Path, out: &mut PassOutcome) -> Option<Vec<(u64, [u8; 32])>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            out.findings.push(Finding::error(
                "proven_log",
                "proven log unreadable".to_string(),
                None,
            ));
            return None;
        }
    };
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            out.findings.push(Finding::error(
                "proven_log",
                "proven log not utf-8".to_string(),
                None,
            ));
            return None;
        }
    };
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop();
    } else {
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                out.findings.push(Finding::warn(
                    "proven_log",
                    format!(
                        "torn final line ignored ({} bytes, no newline)",
                        tail.len()
                    ),
                    None,
                ));
            }
            _ => {}
        }
    }
    let mut entries = Vec::with_capacity(lines.len());
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match parse_proven_line(line) {
            Some((op_index, root, _ts)) => entries.push((op_index, root)),
            None => {
                out.findings.push(Finding::error(
                    "proven_log",
                    format!("line {} violates frozen contract", i + 1),
                    None,
                ));
                return None;
            }
        }
    }
    Some(entries)
}

/// 解析一行 aggregate log（冻结契约：
/// index / through_op / root(64hex) / ts_ms / batch_count）。
fn parse_aggregate_line(line: &str) -> Option<AggregateRecord> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = v.as_object()?;
    let index = obj.get("index")?.as_u64()?;
    let through_op = obj.get("through_op")?.as_u64()?;
    let root_hex = obj.get("root")?.as_str()?;
    let ts_ms = obj.get("ts_ms")?.as_u64()?;
    let batch_count = obj.get("batch_count")?.as_u64()?;
    let root: [u8; 32] = hex::decode(root_hex).ok()?.try_into().ok()?;
    Some(AggregateRecord {
        index,
        through_op,
        root,
        ts_ms,
        batch_count,
    })
}

/// 读取 aggregate log（冻结契约；撕裂尾行忽略 + WARN finding）。
/// 纪律与写入方/网关读取方一致：空文件合法，中间行损坏 → error。
fn read_aggregate_log(path: &Path, out: &mut PassOutcome) -> Option<Vec<AggregateRecord>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            out.findings.push(Finding::error(
                "aggregate_log",
                "aggregate log unreadable".to_string(),
                None,
            ));
            return None;
        }
    };
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => {
            out.findings.push(Finding::error(
                "aggregate_log",
                "aggregate log not utf-8".to_string(),
                None,
            ));
            return None;
        }
    };
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop();
    } else {
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                out.findings.push(Finding::warn(
                    "aggregate_log",
                    format!(
                        "torn final line ignored ({} bytes, no newline)",
                        tail.len()
                    ),
                    None,
                ));
            }
            _ => {}
        }
    }
    let mut entries = Vec::with_capacity(lines.len());
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match parse_aggregate_line(line) {
            Some(rec) => entries.push(rec),
            None => {
                out.findings.push(Finding::error(
                    "aggregate_log",
                    format!("line {} violates frozen contract", i + 1),
                    None,
                ));
                return None;
            }
        }
    }
    Some(entries)
}

/// 一轮完整检查。
fn run_checks(args: &Args) -> PassOutcome {
    let mut out = PassOutcome::default();

    // ===== (a) 软确认链完整性：加载 + 逐帧验签/接续 =====
    let frames = match wal::read_all(&args.appchain_wal) {
        Ok(f) => f,
        Err(e) => {
            out.findings.push(Finding::error(
                "chain_integrity",
                format!("appchain WAL load failed: {e}"),
                None,
            ));
            return out;
        }
    };
    out.frames_checked = frames.len();
    {
        let mut prev = genesis_prev_hash();
        let mut prev_index: Option<u64> = None;
        for f in &frames {
            let res = match prev_index {
                None => {
                    if f.frame.index != 0 || f.frame.prev_hash != genesis_prev_hash() {
                        Err("genesis frame shape broken".to_string())
                    } else {
                        let h = f.hash().unwrap_or([0; 32]);
                        if SequencerKey::verify(&args.sequencer_public, &h, &f.sig) {
                            Ok(())
                        } else {
                            Err("frame signature invalid".to_string())
                        }
                    }
                }
                Some(pi) => f
                    .verify_against(&prev, pi, &args.sequencer_public)
                    .map_err(|e| e.to_string()),
            };
            if let Err(detail) = res {
                out.findings.push(Finding::error(
                    "chain_integrity",
                    detail,
                    Some(f.frame.index),
                ));
                return out; // 链已破：重放类检查无意义（报告注明）
            }
            prev = f.hash().unwrap_or([0; 32]);
            prev_index = Some(f.frame.index);
        }
    }

    // ===== (a') 全量重放：逐帧 state_root 独立重算；给了 proven log 时
    // 顺带恢复证明水位/批次根（checkpoint 的 watermark/batch_roots 对拍
    // 基准 = 重放 + proven log 恢复，二者独立来源交叉验证）。
    let metrics = Arc::new(MetricsRegistry::new());
    let config = SequencerConfig {
        ops_per_min: u32::MAX,
        open_table_per_min: u32::MAX,
        ..SequencerConfig::default()
    };
    let seq = match Sequencer::replay_restoring_proven(
        &args.appchain_wal,
        args.proven_log.as_deref(),
        args.sequencer_public,
        config,
        metrics,
    ) {
        Ok(s) => s,
        Err(e) => {
            out.findings.push(Finding::error(
                "state_replay",
                format!("independent replay failed: {e}"),
                None,
            ));
            return out;
        }
    };

    // ===== (b) 结算语义（表注册表策略）=====
    for f in &frames {
        if let Operation::Settle(record) = &f.frame.op {
            match seq.state().registry.get(record.table_id) {
                Some(policy) => {
                    if let Err(e) = validate_settlement(record, policy) {
                        out.findings.push(Finding::error(
                            "settlement_semantics",
                            format!(
                                "settle at op {} fails table-{} policy check: {e}",
                                f.frame.index, record.table_id
                            ),
                            Some(f.frame.index),
                        ));
                    }
                }
                None => {
                    // 诚实边界：策略不可得（桌未注册/注册表被跳帧等）——
                    // WARN 列出，不算失败。
                    out.findings.push(Finding::warn(
                        "settlement_policy_unavailable",
                        format!(
                            "settle at op {} references table {} with no registered policy",
                            f.frame.index, record.table_id
                        ),
                        Some(f.frame.index),
                    ));
                }
            }
        }
    }

    // ===== (c) proven log 一致性 =====
    let mut proven_entries: Vec<(u64, [u8; 32])> = Vec::new();
    if let Some(plog) = &args.proven_log {
        if let Some(entries) = read_proven_log(plog, &mut out) {
            out.proven_entries = entries.len();
            proven_entries = entries.clone();
            let chain_len = u64::try_from(frames.len()).unwrap_or(u64::MAX);
            let mut prev_op: Option<u64> = None;
            for (op_index, root) in &entries {
                // 顺序：严格递增（写入方只在水位真实推进时追加）
                if let Some(prev) = prev_op {
                    if *op_index <= prev {
                        out.findings.push(Finding::error(
                            "proven_log_order",
                            format!("op_index {op_index} does not advance past {prev}"),
                            Some(*op_index),
                        ));
                        continue;
                    }
                }
                if *op_index > chain_len {
                    out.findings.push(Finding::error(
                        "proven_log_range",
                        format!(
                            "op_index {op_index} beyond chain head ({chain_len} frames)"
                        ),
                        Some(*op_index),
                    ));
                    prev_op = Some(*op_index);
                    continue;
                }
                // 独立重算批次根：窗口 (prev_op, op_index] 内 Settle 的
                // hand_binding，帧序折叠（与 producer 相同的 op 哈希序）
                let start = prev_op.unwrap_or(0);
                let bindings: Vec<[u8; 32]> = frames
                    .iter()
                    .filter(|f| f.frame.index > start && f.frame.index <= *op_index)
                    .filter_map(|f| match &f.frame.op {
                        Operation::Settle(r) => Some(r.hand_binding),
                        _ => None,
                    })
                    .collect();
                match batch_root(&bindings) {
                    Ok(expect) if expect != *root => {
                        out.findings.push(Finding::error(
                            "proven_log_root_mismatch",
                            format!(
                                "batch root at op {} mismatch: log {} != recomputed {} \
                                 ({} bindings in window)",
                                op_index,
                                hex::encode(root),
                                hex::encode(expect),
                                bindings.len()
                            ),
                            Some(*op_index),
                        ));
                    }
                    Err(e) => {
                        out.findings.push(Finding::error(
                            "proven_log_root_mismatch",
                            format!("batch root recompute failed at op {op_index}: {e}"),
                            Some(*op_index),
                        ));
                    }
                    Ok(_) => {}
                }
                prev_op = Some(*op_index);
            }
            // watermark ≤ 链头
            if let Some(&(last, _)) = entries.last() {
                if last > chain_len {
                    out.findings.push(Finding::error(
                        "proven_log_watermark",
                        format!("watermark {last} exceeds chain head {chain_len}"),
                        Some(last),
                    ));
                }
            }
        }
    }

    // ===== (c2) aggregate log 一致性（v1.2.3，--aggregate-log 可选）=====
    // 从 proven log 取窗口内批次根独立重算 aggregate_roots 并与记录比对；
    // 并校验 index 连续、through_op 单调且 ≤ 链头。
    if let Some(apath) = &args.aggregate_log {
        if let Some(aggs) = read_aggregate_log(apath, &mut out) {
            out.aggregate_entries = aggs.len();
            let chain_len = u64::try_from(frames.len()).unwrap_or(u64::MAX);
            if args.proven_log.is_none() {
                // fail-closed：聚合根的独立重算必须以 proven log 的批次根为
                // 基准——缺 proven log 时无法核验，按不一致处置。
                out.findings.push(Finding::error(
                    "aggregate_mismatch",
                    "--aggregate-log requires --proven-log for independent recompute"
                        .to_string(),
                    None,
                ));
            }
            let mut prev_through: u64 = 0;
            for (i, rec) in aggs.iter().enumerate() {
                // index 连续（从 0 起）
                if rec.index != u64::try_from(i).unwrap_or(u64::MAX) {
                    out.findings.push(Finding::error(
                        "aggregate_range",
                        format!(
                            "aggregate index {} breaks consecutive sequence (position {i})",
                            rec.index
                        ),
                        Some(rec.index),
                    ));
                }
                // through_op 单调（严格递增）且 ≤ 链头
                if i > 0 && rec.through_op <= prev_through {
                    out.findings.push(Finding::error(
                        "aggregate_range",
                        format!(
                            "through_op {} does not advance past {prev_through}",
                            rec.through_op
                        ),
                        Some(rec.index),
                    ));
                }
                if rec.through_op > chain_len {
                    out.findings.push(Finding::error(
                        "aggregate_range",
                        format!(
                            "through_op {} beyond chain head ({chain_len} frames)",
                            rec.through_op
                        ),
                        Some(rec.index),
                    ));
                }
                // 独立重算：窗口 (prev_through, through_op] 内的批次根
                let roots: Vec<[u8; 32]> = proven_entries
                    .iter()
                    .filter(|(op, _)| *op > prev_through && *op <= rec.through_op)
                    .map(|(_, r)| *r)
                    .collect();
                if roots.len() as u64 != rec.batch_count || roots.is_empty() {
                    out.findings.push(Finding::error(
                        "aggregate_mismatch",
                        format!(
                            "aggregate {} window ({prev_through}, {}] has {} proven-log \
                             batch roots but record claims batch_count {}",
                            rec.index, rec.through_op, roots.len(), rec.batch_count
                        ),
                        Some(rec.index),
                    ));
                } else {
                    match aggregate_roots(&roots) {
                        Ok(expect) if expect != rec.root => {
                            out.findings.push(Finding::error(
                                "aggregate_mismatch",
                                format!(
                                    "aggregate root at op {} mismatch: log {} != recomputed {} \
                                     ({} batch roots in window)",
                                    rec.through_op,
                                    hex::encode(rec.root),
                                    hex::encode(expect),
                                    roots.len()
                                ),
                                Some(rec.index),
                            ));
                        }
                        Err(e) => {
                            out.findings.push(Finding::error(
                                "aggregate_mismatch",
                                format!("aggregate root recompute failed at {}: {e}", rec.index),
                                Some(rec.index),
                            ));
                        }
                        Ok(_) => {}
                    }
                }
                prev_through = rec.through_op;
            }
        }
    }

    // ===== (d) checkpoint 对拍 =====
    if let Some(ckpt) = &args.checkpoint {
        if let Err(e) = checkpoint::verify_checkpoint(ckpt, &seq) {
            out.findings.push(Finding::error(
                "checkpoint_mismatch",
                format!("checkpoint verification failed: {e}"),
                None,
            ));
        }
    }

    // ===== (e) 分叉检测（M8-ACC-6：加载后即时比对）=====
    if let Some(wal_b) = &args.wal_b {
        match wal::read_all(wal_b) {
            Ok(frames_b) => match compare_chains(&frames, &frames_b) {
                Some(idx) => {
                    out.findings.push(Finding::error(
                        "fork_detected",
                        format!(
                            "chains diverge at frame index {idx} \
                             (chain A {} frames vs chain B {} frames)",
                            frames.len(),
                            frames_b.len()
                        ),
                        Some(idx),
                    ));
                    out.fork_at = Some(idx);
                }
                None => {}
            },
            Err(e) => {
                out.findings.push(Finding::error(
                    "fork_check",
                    format!("chain B WAL load failed: {e}"),
                    None,
                ));
            }
        }
    }

    out
}

fn write_json_out(args: &Args, out: &PassOutcome) {
    if let Some(path) = &args.json_out {
        let findings: Vec<serde_json::Value> = out
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "category": f.category,
                    "severity": f.severity.as_str(),
                    "detail": f.detail,
                    "at_index": f.at_index,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "consistent": out.consistent(),
            "frames_checked": out.frames_checked,
            "proven_entries": out.proven_entries,
            "aggregate_entries": out.aggregate_entries,
            "fork_at": out.fork_at,
            "errors": out.errors(),
            "warnings": out.warnings(),
            "findings": findings,
        });
        if let Ok(json) = serde_json::to_string_pretty(&doc) {
            let _ = std::fs::write(path, json);
        }
    }
}

fn print_report(pass: u64, out: &PassOutcome) {
    println!("== appchain_watcher pass {pass} ==");
    println!(
        "frames_checked={} proven_entries={} aggregate_entries={} fork_at={}",
        out.frames_checked,
        out.proven_entries,
        out.aggregate_entries,
        out.fork_at
            .map(|i| i.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    if out.findings.is_empty() {
        println!("findings: none");
    }
    for f in &out.findings {
        println!(
            "[{}] {} at {:?}: {}",
            f.severity.as_str(),
            f.category,
            f.at_index,
            f.detail
        );
    }
    println!(
        "RESULT: {} (errors={}, warnings={})",
        if out.consistent() {
            "CONSISTENT"
        } else {
            "INCONSISTENT"
        },
        out.errors(),
        out.warnings()
    );
}

fn real_main() -> i32 {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("{msg}");
            eprintln!("{USAGE}");
            return 2;
        }
    };
    match args.follow_interval_secs {
        None => {
            let out = run_checks(&args);
            write_json_out(&args, &out);
            print_report(1, &out);
            if out.consistent() {
                0
            } else {
                1
            }
        }
        Some(secs) => {
            let interval = Duration::from_secs(secs.max(1));
            let mut pass = 0u64;
            loop {
                pass += 1;
                let out = run_checks(&args);
                write_json_out(&args, &out);
                print_report(pass, &out);
                if !out.consistent() {
                    return 1;
                }
                std::thread::sleep(interval);
            }
        }
    }
}

fn main() {
    std::process::exit(real_main());
}
