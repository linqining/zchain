//! `rake_audit export`：WAL → `zchain.rake_audit.v1` 审计 JSON。
//!
//! 导出路径（与 verify 的独立复验路径相对）：用 `Sequencer::replay` 做全量
//! 重放（链验签 + 每帧状态根重验，fail-closed），随后从软确认链读取 Settle
//! 帧。费率参数（rate_bps/cap/treasury_bps）：`SettlementRecord` 只携带
//! `policy_commitment` 不携带策略明文，因此统一从重放后的 LedgerState 桌
//! 注册表（开桌时冻结）按 table_id 查询，并在导出项中标注
//! `"source": "ledger_fee_registry"`。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use poker_appchain::fee::FeePolicy;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::ops::Operation;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};

/// export 子命令参数（main.rs 已完成解析与校验）。
pub struct ExportArgs {
    /// appchain WAL 路径。
    pub wal: std::path::PathBuf,
    /// sequencer ed25519 公钥（重放验签判据）。
    pub public: [u8; 32],
    /// 时间窗下界（含），按帧 `ts_ms` 过滤。
    pub from_ts: u64,
    /// 时间窗上界（含）。
    pub to_ts: u64,
    /// 可选桌过滤。
    pub table_id: Option<u64>,
    /// 输出 JSON 路径。
    pub out: std::path::PathBuf,
}

/// 费率参数快照（导出给 verify 独立重算用）。
struct PolicySnapshot {
    mode: u8,
    rate_bps: u64,
    cap: u64,
    treasury_bps: u64,
    commitment_hex: String,
}

impl PolicySnapshot {
    fn of(policy: &FeePolicy) -> Self {
        let (mode, rate_bps, cap, treasury_bps) = match policy {
            FeePolicy::Zero => (0u8, 0u64, 0u64, 0u64),
            FeePolicy::FixedRake {
                rate_bps,
                cap,
                split,
            } => (1u8, u64::from(*rate_bps), *cap, u64::from(split.treasury_bps)),
            // TE-E0：判别值 2 枚举先行（销毁处置规则在 poker_l1 合约侧，
            // 审计层只透出计价参数，mode=2 与 mode=1 同形）。
            FeePolicy::FixedRakeBurn {
                rate_bps,
                cap,
                split,
            } => (2u8, u64::from(*rate_bps), *cap, u64::from(split.treasury_bps)),
        };
        Self {
            mode,
            rate_bps,
            cap,
            treasury_bps,
            commitment_hex: hex::encode(policy.commitment_bytes()),
        }
    }

    fn to_json(&self, source: &str) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode,
            "rate_bps": self.rate_bps,
            "cap": self.cap,
            "treasury_bps": self.treasury_bps,
            "policy_commitment": self.commitment_hex,
            "source": source,
        })
    }
}

/// 执行导出：重放 → 抽取 → 写 JSON → stdout 摘要（drill 脚本解析
/// `wal_head_hash=` 一行）。
///
/// # Errors
/// 重放失败（验签/断链/状态根分叉）、注册表缺策略或写文件失败——全部视为
/// 输入错误（退出码 2）。
pub fn run(args: &ExportArgs) -> Result<(), String> {
    // 1. 全量重放（内部 verify_chain + 逐帧状态根重验，任何失败即拒绝）。
    let seq = Sequencer::replay(
        &args.wal,
        args.public,
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    )
    .map_err(|e| format!("WAL 重放失败: {e}"))?;
    let head = seq.head_hash().map_err(|e| format!("head hash: {e}"))?;
    let chain = seq.chain();
    let frames_total = chain.len();

    // 2. 遍历链帧，抽取窗口内的 Settle 记录。
    let mut records: Vec<serde_json::Value> = Vec::new();
    let mut policies: BTreeMap<u64, PolicySnapshot> = BTreeMap::new();
    let mut rake_total: u64 = 0;
    let mut first_index: Option<u64> = None;
    let mut last_index: Option<u64> = None;
    for frame in chain {
        if frame.frame.ts_ms < args.from_ts || frame.frame.ts_ms > args.to_ts {
            continue;
        }
        let Operation::Settle(record) = &frame.frame.op else {
            continue;
        };
        if let Some(filter) = args.table_id {
            if record.table_id != filter {
                continue;
            }
        }
        // 记录未携带策略明文（ABI 只有 policy_commitment）→ 从重放后的
        // 桌注册表查询并注明来源。
        let policy = seq
            .state()
            .registry
            .get(record.table_id)
            .ok_or_else(|| format!("桌 {} 在重放后注册表中无策略", record.table_id))?;
        let snap = PolicySnapshot::of(policy);
        policies.entry(record.table_id).or_insert(snap);

        let inputs_sum: u128 = record
            .inputs
            .iter()
            .map(|i| u128::from(i.note.amount))
            .sum();
        let payouts_sum: u128 = record.payouts.iter().map(|o| u128::from(o.amount)).sum();
        let rake_out_sum = u128::from(record.rake.treasury_out.as_ref().map(|o| o.amount).unwrap_or(0))
            + u128::from(record.rake.operator_out.as_ref().map(|o| o.amount).unwrap_or(0));

        let pots: Vec<serde_json::Value> = record
            .plan
            .pots
            .iter()
            .map(|p| {
                serde_json::json!({
                    "pot_index": p.pot_index,
                    "gross_amount": p.gross_amount,
                    "rake": p.rake,
                    "contested": p.is_contested(),
                    "eligible_seats": u64::from(p.eligible_mask.count_ones()),
                })
            })
            .collect();

        rake_total = rake_total
            .checked_add(record.rake.total)
            .ok_or("rake 汇总溢出")?;
        first_index = Some(first_index.unwrap_or(frame.frame.index));
        last_index = Some(frame.frame.index);

        let out_json = |spec: Option<&poker_appchain::note::NoteSpec>| match spec {
            Some(o) => serde_json::json!({
                "owner": hex::encode(o.owner),
                "amount": o.amount,
            }),
            None => serde_json::Value::Null,
        };

        records.push(serde_json::json!({
            "frame_index": frame.frame.index,
            "ts_ms": frame.frame.ts_ms,
            "table_id": record.table_id,
            "hand_binding": hex::encode(record.hand_binding),
            "pots": pots,
            "rake_base": record.plan.rake_base(),
            "rake_total": record.rake.total,
            "policy": policies
                .get(&record.table_id)
                .map(|p| p.to_json("ledger_fee_registry"))
                .expect("inserted above"),
            "treasury_out": out_json(record.rake.treasury_out.as_ref()),
            "operator_out": out_json(record.rake.operator_out.as_ref()),
            "conservation": {
                "inputs_sum": inputs_sum,
                "payouts_sum": payouts_sum,
                "rake_outputs_sum": rake_out_sum,
            },
        }));
    }

    // 3. 头部（含生成清单与汇总 Σrake）。
    let policy_list: Vec<serde_json::Value> = policies
        .iter()
        .map(|(table_id, p)| {
            let mut v = p.to_json("ledger_fee_registry");
            v["table_id"] = serde_json::json!(table_id);
            v
        })
        .collect();
    let doc = serde_json::json!({
        "format": crate::FORMAT_TAG,
        "header": {
            "wal_head_hash": hex::encode(head),
            "chain_frames_total": frames_total,
            "chain_first_index": chain.first().map(|f| f.frame.index),
            "chain_last_index": chain.last().map(|f| f.frame.index),
            "from_ts_ms": args.from_ts,
            "to_ts_ms": args.to_ts,
            "table_id_filter": args.table_id,
            "record_first_frame_index": first_index,
            "record_last_frame_index": last_index,
            "policy_commitments": policy_list,
            "rake_total": rake_total,
        },
        "records": records,
    });

    // 4. 写出（pretty，便于人工核对与脚本 grep）。
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("创建输出目录失败 {}: {e}", parent.display()))?;
        }
    }
    let file = std::fs::File::create(&args.out)
        .map_err(|e| format!("创建输出文件失败 {}: {e}", args.out.display()))?;
    serde_json::to_writer_pretty(file, &doc)
        .map_err(|e| format!("JSON 序列化失败: {e}"))?;

    println!(
        "frames_total={frames_total} settle_records={} rake_total={rake_total} wal_head_hash={}",
        records.len(),
        hex::encode(head),
    );
    println!("out={}", args.out.display());
    Ok(())
}

/// 供测试/脚本复用：读取已导出 JSON（`Path` 版本仅 verify 测试需要）。
#[allow(dead_code)]
pub(crate) fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON 解析失败: {e}"))
}
