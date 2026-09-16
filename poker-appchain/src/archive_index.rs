//! M4/E2：archive 节点级持久化索引。
//!
//! 目标：把 explorer 的检索面从"全量 replay"升级为持久化索引
//! （块/帧/结算/proof 注册表的落盘索引与按时间窗/桌/绑定的查询），
//! 支撑 archive 节点形态。
//!
//! ## 设计（E2 "indexer 持久化"收口：零新依赖）
//!
//! **回放时同步构建、落盘为索引文件、重启直接加载免 replay**：
//!
//! 1. [`build_index`]：对 WAL 做全量语义重放（`Sequencer::replay`：验签 +
//!    逐帧状态根重验，fail-closed），同时扫描 WAL 字节偏移；索引行与
//!    重放链逐帧交叉核对后落盘；
//! 2. [`load_index`]：从索引文件直接装载（校验 format 标签、逐行契约、
//!    行数与头部计数一致、全文件 digest 一致——坏文件一律 `Err`，不回退
//!    到 replay），重建 binding → (frame_index, offset) 与 table_id →
//!    frame 的内存二级索引；
//! 3. 查询：[`ArchiveIndex::settlement_by_binding`] /
//!    [`ArchiveIndex::frames_by_time_window`] / [`ArchiveIndex::frames_by_table`]。
//!
//! ## 索引文件契约（冻结）：`zchain.appchain.archive_index.v1`
//!
//! JSONL，UTF-8，每行一个紧凑 JSON 对象 + `\n`。**第 1 行为头部**，其后
//! 逐帧一行（WAL 帧序），最后 proof 注册表条目行（可选，无注册表时省略）：
//!
//! ```text
//! {"format":"zchain.appchain.archive_index.v1","sequencer_public":"<64hex>",
//!  "chain_head":{"index":<u64>,"hash":"<64hex>","state_root":"<64hex>"},
//!  "frame_count":<u64>,"settlement_count":<u64>,"proof_count":<u64>,
//!  "digest":"<64hex>"}
//! {"kind":"OpenTable","index":<u64>,"ts_ms":<u64>,"state_root":"<64hex>",
//!  "hash":"<64hex>","offset":<u64>}                    // 非结算帧（7 种 kind）
//! {"kind":"Settle","index":<u64>,"ts_ms":<u64>,"state_root":"<64hex>",
//!  "hash":"<64hex>","offset":<u64>,"table_id":<u64>,
//!  "binding_hex":"<64hex>","pot":<u64>,"rake_base":<u64>,"rake_total":<u64>,
//!  "payouts":[{"owner_short":"<8hex…8hex>","amount":<u64>},...]}
//! {"kind":"Proof","index":<op_index>,"binding_hex":"<64hex>","engine":"<str>"}
//! ```
//!
//! - `offset`：该帧记录在 WAL 文件中的字节偏移（长度前缀 `u32 LE` 的起始
//!   位置）——网关 index 模式据此做**定向单帧读取**（配合 `hash` +
//!   sequencer 验签做完整性校验，fail-closed）；
//! - `digest`：`blake2s-256(头部行之后全部原始字节)`——头部行被 digest 覆盖
//!   的内容锚定（chain_head/counts 与行内容任何不一致都会在装载时暴露）；
//! - `owner_short`：owner 33B 压缩公钥 hex 的前 8 + `…` + 后 8 字符（与
//!   网关摘要口径逐字符一致）；
//! - `kind` 枚举（帧）：`OpenTable | CloseTable | Deposit | WithdrawRequest |
//!   Transfer | BuyIn | Settle` + **v2 追加变体**（TE-M5 缺口收口，2026-09-12：
//!   `MigrateNote | SettleV2 | DepositV2 | WithdrawRequestV2 |
//!   RegisterGameToken | IssueGameToken | BurnGameToken | FaucetMint |
//!   BuyGasCredits | BindGasPolicy`——与 `explorer_gateway::api::
//!   op_type_name` 同一拼写）；`Proof` 行独立于帧连续性（不占 frame 序）。
//!
//! **v2 变体行（additive 契约扩展）**：v2 变体帧除公共五字段外携带
//! `v2` 子对象（kind/table_id/binding 或等价幂等键、金额摘要）：
//! ```text
//! {"kind":"SettleV2",...,"v2":{"binding_hex":"<64hex>","table_id":<u64>,
//!  "amount":<u64 pot>,"rake_total":<u64>}}
//! {"kind":"DepositV2",...,"v2":{"key_hex":"<64hex 幂等键>","asset":"real:usdt",
//!  "amount":<u64>}}
//! ```
//! 各 kind 的必填键见 `v2_required_fields`（装载端 fail-closed：缺失即
//! Err，与 build 端产出严格对称）。**格式标签保持 `.v1` 不升版**——裁决
//! 记录：本扩展是对 TE-M5 发现的 pre-existing 缺陷的修复（`--write-index`
//! 对 v2 WAL 此前直接失败，`kind_of` 产出的 v2 kind 名装载端不识别），
//! v2 WAL 从未产出过 `.v1` 索引文件、既有 `.v1` 文件（纯 v1 WAL）逐字节
//! 兼容，语义零变更；按"加法式 + 既有文件不受影响"的 ABI additive 纪律
//! 处理，升版反而作废全部既有索引文件。**结算计数口径**：`settlement_count`
//! / `by_binding` / `by_table` 维持 v1 `Settle` 专属——与网关 replay 数据面
//! （`settlement_frames` 只投影 v1 `Settle`）严格对等，SettleV2 摘要随帧行
//! 可查但不进结算查询账（两模式对等性是既有受测不变量）。
//!
//! 冻结纪律：字段名/顺序无关（JSON 对象），但**既有字段集与语义不得变更**；
//! v2 变体行是纯加法（新 kind + 新 `v2` 子对象），既有 7 种 kind 行零变更。
//! 错误类型：索引文件损坏/契约不符统一 [`AppchainError::Codec`]（String
//! 描述；error.rs 的 stable category 纪律下不为本模块新增变体）。

use std::collections::BTreeMap;
use std::io::{BufReader, Read as _};
use std::path::Path;
use std::sync::Arc;

use crate::error::{AppchainError, AppchainResult};
use crate::keys::blake2s32;
use crate::metrics::MetricsRegistry;
use crate::ops::Operation;
use crate::sequencer::{Sequencer, SequencerConfig};
use crate::soft_confirm::{genesis_prev_hash, SignedFrame};

/// 索引文件格式标签（冻结）。
pub const FORMAT_TAG: &str = "zchain.appchain.archive_index.v1";

/// 索引头部（文件第 1 行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIndexHeader {
    /// sequencer 公钥（装载方必须与 `--sequencer-public` 比对——索引发错
    /// 链的防线在装载入口 fail-closed）。
    pub sequencer_public: [u8; 32],
    /// 链头帧序号（空链 = 0；`chain_head.index`）。
    pub chain_head_index: u64,
    /// 链头帧哈希（空链 = 创世 prev 全零）。
    pub chain_head_hash: [u8; 32],
    /// 链头状态根。
    pub chain_head_state_root: [u8; 32],
    /// 帧行数（不含 Proof 行）。
    pub frame_count: u64,
    /// Settle 帧行数。
    pub settlement_count: u64,
    /// Proof 行数。
    pub proof_count: u64,
    /// 全文件 digest（头部行之后全部原始字节的 blake2s-256）。
    pub digest: [u8; 32],
}

/// Settle 帧摘要（`frames`/`settlements` 端点在 index 模式的数据源）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleSummary {
    /// 桌 ID（从 settle op 提取）。
    pub table_id: u64,
    /// 手绑定（防重放键）。
    pub binding: [u8; 32],
    /// 本手下注额。
    pub pot: u64,
    /// rake 基数（contested 层 gross 之和，B9 口径）。
    pub rake_base: u64,
    /// rake 总额。
    pub rake_total: u64,
    /// 赔付摘要（owner 缩写 + 数额；与网关摘要口径一致）。
    pub payouts: Vec<(String, u64)>,
}

/// 索引帧条目（一帧一行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameEntry {
    /// op 类型名（与网关 `op_type_name` 同一拼写）。
    pub kind: String,
    /// 帧序号。
    pub index: u64,
    /// 帧时刻（毫秒）。
    pub ts_ms: u64,
    /// 帧后状态根。
    pub state_root: [u8; 32],
    /// 帧哈希（blake2s(borsh(frame))；定向读帧完整性校验用）。
    pub hash: [u8; 32],
    /// WAL 字节偏移（记录长度前缀起始）。
    pub offset: u64,
    /// Settle 摘要（kind == "Settle" 时存在）。
    pub settle: Option<SettleSummary>,
    /// v2 变体摘要（kind ∈ v2 变体集时存在；TE-M5 缺口收口，见模块文档）。
    pub v2: Option<V2OpSummary>,
}

/// v2 变体帧的等价键/金额摘要（`v2` 子对象；字段按 kind 子集出现，
/// 必填集见 [`v2_required_fields`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2OpSummary {
    /// SettleV2/BindGasPolicy 的桌 ID。
    pub table_id: Option<u64>,
    /// SettleV2 的手绑定（防重放键；查询账不收录——两模式对等，见模块文档）。
    pub binding: Option<[u8; 32]>,
    /// 等价幂等键（DepositV2.deposit_id / WithdrawRequestV2.request_id /
    /// IssueGameToken.issue_id / BurnGameToken.burn_id / FaucetMint.claim_id
    /// / BuyGasCredits.pay_digest / MigrateNote.migration_nonce）。
    pub key: Option<[u8; 32]>,
    /// GAME/桌 token id（GTS 族 + BindGasPolicy）。
    pub token_id: Option<u32>,
    /// 资产摘要（`AssetId` 规范串，如 `real:usdt`）。
    pub asset: Option<String>,
    /// 金额摘要（面额/毛额/pot；RegisterGameToken/BindGasPolicy 无金额）。
    pub amount: Option<u64>,
    /// SettleV2 的 rake 总额；RegisterGameToken 的供给上限。
    pub secondary_amount: Option<u64>,
}

/// proof 注册表条目的索引投影。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEntry {
    /// 结算 op 序号（= 帧序号）。
    pub index: u64,
    /// 手绑定 hex。
    pub binding: [u8; 32],
    /// 引擎名。
    pub engine: String,
}

/// 已装载的 archive 索引（内存二级索引 + 冻结契约数据）。
#[derive(Debug, Clone)]
pub struct ArchiveIndex {
    header: ArchiveIndexHeader,
    frames: Vec<FrameEntry>,
    proofs: Vec<ProofEntry>,
    /// binding → 帧行下标（装载时重建；binding 在链上唯一）。
    by_binding: BTreeMap<[u8; 32], usize>,
    /// table_id → 帧行下标列表（升序；settle op 提取）。
    by_table: BTreeMap<u64, Vec<usize>>,
}

impl ArchiveIndex {
    /// 头部（chain head / counts / digest）。
    #[must_use]
    pub fn header(&self) -> &ArchiveIndexHeader {
        &self.header
    }

    /// 全部帧条目（WAL 帧序）。
    #[must_use]
    pub fn frames(&self) -> &[FrameEntry] {
        &self.frames
    }

    /// 全部 proof 索引条目。
    #[must_use]
    pub fn proofs(&self) -> &[ProofEntry] {
        &self.proofs
    }

    /// binding → 结算帧（二级索引命中）。
    #[must_use]
    pub fn settlement_by_binding(&self, binding: &[u8; 32]) -> Option<&FrameEntry> {
        self.by_binding.get(binding).map(|&i| &self.frames[i])
    }

    /// 时间窗 `[from_ts, to_ts]`（双闭区间，与 rake_audit export 窗口语义
    /// 一致）内的帧（帧序）。
    #[must_use]
    pub fn frames_by_time_window(&self, from_ts: u64, to_ts: u64) -> Vec<&FrameEntry> {
        self.frames
            .iter()
            .filter(|f| f.ts_ms >= from_ts && f.ts_ms <= to_ts)
            .collect()
    }

    /// 某桌的全部结算帧（帧序；table_id 从 settle op 提取）。
    #[must_use]
    pub fn frames_by_table(&self, table_id: u64) -> Vec<&FrameEntry> {
        self.by_table
            .get(&table_id)
            .map(|idxs| idxs.iter().map(|&i| &self.frames[i]).collect())
            .unwrap_or_default()
    }
}

// ===== 构建 =====

/// 回放构建索引并写文件（E2 indexer：回放时同步构建）。
///
/// 流程：WAL 偏移扫描（帧记录起始字节偏移）→ `Sequencer::replay` 全量语义
/// 重放（验签 + 状态根重验，fail-closed）→ 扫描帧与重放链逐帧全等核对 →
/// 组装契约行 → digest → 落盘。可选挂 proof 注册表（Proof 行）。
///
/// # Errors
/// WAL 损坏/重放失败 → [`AppchainError::WalCorrupted`] 等（重放原样上抛）；
/// 扫描与重放链不一致（不可能，除非实现缺陷）→ `WalCorrupted`；
/// 注册表读取失败/写文件失败 → 对应错误。
pub fn build_index(
    wal: &Path,
    sequencer_public: [u8; 32],
    proof_registry_path: Option<&Path>,
    out: &Path,
) -> AppchainResult<ArchiveIndex> {
    // 1. 偏移扫描（格式与 wal::read_all 一致：u32 LE 长度 || borsh 帧）。
    let scanned = scan_wal_offsets(wal)?;
    // 2. 全量语义重放（链验签 + 逐帧状态根重验；任何损坏 → Err）。
    let config = SequencerConfig {
        ops_per_min: u32::MAX,
        open_table_per_min: u32::MAX,
        // 与生产方（texas 嵌入式 runtime）一致：replay 重跑 BuyIn 的
        // max_seats 准入，未入池 seat 随动态买卖累积后，默认 10 会令
        // 索引构建在 WAL 中途 "table full" 失败。
        max_seats: 1000,
        ..SequencerConfig::default()
    };
    let seq = Sequencer::replay(wal, sequencer_public, config, Arc::new(MetricsRegistry::new()))?;
    let chain = seq.chain();
    if chain.len() != scanned.len() {
        return Err(AppchainError::WalCorrupted("index scan/replay length mismatch"));
    }
    for (i, (_, frame)) in scanned.iter().enumerate() {
        if chain[i] != **frame {
            return Err(AppchainError::WalCorrupted("index scan/replay frame mismatch"));
        }
    }
    // 3. 组装行（帧行 + 可选 Proof 行），digest 覆盖头部之后的全部原始
    //    字节（= 逐行内容 + 每行换行，与装载端切分严格对齐）。
    let head = seq.head_hash()?;
    let head_frame = chain.last();
    let mut lines: Vec<String> = Vec::with_capacity(scanned.len() + 16);
    let mut settlement_count = 0u64;
    for (offset, frame) in &scanned {
        let line = frame_line(frame, *offset)?;
        if matches!(frame.frame.op, Operation::Settle(_)) {
            settlement_count += 1;
        }
        lines.push(line);
    }
    let proofs = match proof_registry_path {
        Some(p) => crate::proof_registry::read_registry(p)?
            .iter()
            .map(|e| {
                let binding = hex::decode(&e.binding_hex)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(AppchainError::WalCorrupted("proof registry bad binding"))?;
                Ok(ProofEntry {
                    index: e.op_index,
                    binding,
                    engine: e.engine.clone(),
                })
            })
            .collect::<AppchainResult<Vec<_>>>()?,
        None => Vec::new(),
    };
    for p in &proofs {
        lines.push(serde_json::json!({
            "kind": "Proof",
            "index": p.index,
            "binding_hex": hex::encode(p.binding),
            "engine": p.engine,
        })
        .to_string());
    }
    let digest = {
        let mut blob = lines.join("\n");
        if !blob.is_empty() {
            blob.push('\n');
        }
        blake2s32(&[blob.as_bytes()])
    };
    let header = ArchiveIndexHeader {
        sequencer_public,
        chain_head_index: head_frame.map_or(0, |f| f.frame.index),
        chain_head_hash: head_frame.map_or(genesis_prev_hash(), |_| head),
        chain_head_state_root: head_frame.map_or([0u8; 32], |f| f.frame.state_root),
        frame_count: u64::try_from(scanned.len()).unwrap_or(u64::MAX),
        settlement_count,
        proof_count: u64::try_from(proofs.len()).unwrap_or(u64::MAX),
        digest,
    };
    // 4. 写文件：头部行在前，其后为 digest 覆盖的原始行字节（逐行 +
    //    换行，与装载端 "digest = 头部行之后全部原始字节" 严格对齐）。
    let mut body = String::new();
    body.push_str(&header_line(&header));
    body.push('\n');
    for l in &lines {
        body.push_str(l);
        body.push('\n');
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AppchainError::Codec(format!("archive index mkdir: {e}")))?;
        }
    }
    std::fs::write(out, body)
        .map_err(|e| AppchainError::Codec(format!("archive index write: {e}")))?;
    Ok(load_index(out)?)
}

/// 头部行（紧凑 JSON；`to_string` 键序为字母序，装载端按名读取）。
fn header_line(h: &ArchiveIndexHeader) -> String {
    serde_json::json!({
        "format": FORMAT_TAG,
        "sequencer_public": hex::encode(h.sequencer_public),
        "chain_head": {
            "index": h.chain_head_index,
            "hash": hex::encode(h.chain_head_hash),
            "state_root": hex::encode(h.chain_head_state_root),
        },
        "frame_count": h.frame_count,
        "settlement_count": h.settlement_count,
        "proof_count": h.proof_count,
        "digest": hex::encode(h.digest),
    })
    .to_string()
}

/// 单帧 → 索引行（Settle 帧附摘要字段；v2 变体帧附 `v2` 等价键/金额摘要）。
fn frame_line(frame: &SignedFrame, offset: u64) -> AppchainResult<String> {
    let kind = kind_of(&frame.frame.op);
    let mut v = serde_json::json!({
        "kind": kind,
        "index": frame.frame.index,
        "ts_ms": frame.frame.ts_ms,
        "state_root": hex::encode(frame.frame.state_root),
        "hash": hex::encode(frame.hash()?),
        "offset": offset,
    });
    if let Operation::Settle(record) = &frame.frame.op {
        let obj = v.as_object_mut().expect("object just built");
        obj.insert("table_id".into(), serde_json::json!(record.table_id));
        obj.insert(
            "binding_hex".into(),
            serde_json::json!(hex::encode(record.hand_binding)),
        );
        obj.insert("pot".into(), serde_json::json!(record.pot));
        obj.insert("rake_base".into(), serde_json::json!(record.plan.rake_base()));
        obj.insert("rake_total".into(), serde_json::json!(record.rake.total));
        obj.insert(
            "payouts".into(),
            serde_json::json!(record
                .payouts
                .iter()
                .map(|p| serde_json::json!({
                    "owner_short": short_owner_hex(&p.owner),
                    "amount": p.amount,
                }))
                .collect::<Vec<_>>()),
        );
    }
    // v2 变体（TE-M5 缺口收口）：`v2` 子对象携带 kind/table_id/binding 或
    // 等价幂等键、金额摘要——必填集与装载端 `v2_required_fields` 严格对称。
    if let Some(summary) = v2_summary_of(&frame.frame.op) {
        let obj = v.as_object_mut().expect("object just built");
        obj.insert("v2".into(), v2_summary_json(&summary));
    }
    Ok(v.to_string())
}

/// v2 变体 → 等价键/金额摘要（`None` = 非 v2 变体）。字段映射见
/// [`V2OpSummary`] 与模块文档。
fn v2_summary_of(op: &Operation) -> Option<V2OpSummary> {
    use crate::asset_id::AssetId;
    let summary = match op {
        Operation::MigrateNote(op) => V2OpSummary {
            key: Some(op.record.migration_nonce),
            amount: Some(op.record.amount),
            asset: Some(match op.record.asset_class {
                crate::note::AssetClass::Real => AssetId::REAL_NATIVE.to_string(),
                crate::note::AssetClass::Play => AssetId::GAME_PLAY.to_string(),
            }),
            token_id: None,
            table_id: None,
            binding: None,
            secondary_amount: None,
        },
        Operation::SettleV2(record) => V2OpSummary {
            binding: Some(record.hand_binding),
            table_id: Some(record.table_id),
            amount: Some(record.pot),
            secondary_amount: Some(record.rake.total),
            key: None,
            token_id: None,
            asset: None,
        },
        Operation::DepositV2(op) => V2OpSummary {
            key: Some(op.deposit_id),
            asset: Some(op.asset_id.to_string()),
            amount: Some(op.amount),
            token_id: None,
            table_id: None,
            binding: None,
            secondary_amount: None,
        },
        Operation::WithdrawRequestV2(op) => V2OpSummary {
            key: Some(op.request_id),
            asset: Some(op.asset_id.to_string()),
            amount: Some(op.gross_amount),
            token_id: None,
            table_id: None,
            binding: None,
            secondary_amount: None,
        },
        Operation::RegisterGameToken(op) => V2OpSummary {
            token_id: Some(op.token_id),
            secondary_amount: Some(op.max_supply),
            key: None,
            amount: None,
            asset: None,
            table_id: None,
            binding: None,
        },
        Operation::IssueGameToken(op) => V2OpSummary {
            key: Some(op.issue_id),
            token_id: Some(op.token_id),
            amount: Some(op.pay_amount),
            table_id: None,
            binding: None,
            asset: None,
            secondary_amount: None,
        },
        Operation::BurnGameToken(op) => V2OpSummary {
            key: Some(op.burn_id),
            token_id: Some(op.token_id),
            amount: Some(op.note.amount),
            table_id: None,
            binding: None,
            asset: None,
            secondary_amount: None,
        },
        Operation::FaucetMint(op) => V2OpSummary {
            key: Some(op.claim_id),
            token_id: Some(op.token_id),
            amount: Some(op.amount),
            table_id: None,
            binding: None,
            asset: None,
            secondary_amount: None,
        },
        Operation::BuyGasCredits(op) => V2OpSummary {
            key: Some(op.pay_digest),
            asset: Some(op.pricing_asset_id.to_string()),
            amount: Some(op.pay_amount),
            token_id: None,
            table_id: None,
            binding: None,
            secondary_amount: None,
        },
        Operation::BindGasPolicy(op) => V2OpSummary {
            table_id: Some(op.table_id),
            token_id: Some(op.token_id),
            key: None,
            binding: None,
            asset: None,
            amount: None,
            secondary_amount: None,
        },
        _ => return None,
    };
    Some(summary)
}

/// `V2OpSummary` → `v2` 子对象（键名冻结，装载端按名读取）。
fn v2_summary_json(summary: &V2OpSummary) -> serde_json::Value {
    let mut v = serde_json::Map::new();
    if let Some(table_id) = summary.table_id {
        v.insert("table_id".into(), serde_json::json!(table_id));
    }
    if let Some(binding) = &summary.binding {
        v.insert("binding_hex".into(), serde_json::json!(hex::encode(binding)));
    }
    if let Some(key) = &summary.key {
        v.insert("key_hex".into(), serde_json::json!(hex::encode(key)));
    }
    if let Some(token_id) = summary.token_id {
        v.insert("token_id".into(), serde_json::json!(token_id));
    }
    if let Some(asset) = &summary.asset {
        v.insert("asset".into(), serde_json::json!(asset));
    }
    if let Some(amount) = summary.amount {
        v.insert("amount".into(), serde_json::json!(amount));
    }
    if let Some(secondary) = summary.secondary_amount {
        v.insert("secondary_amount".into(), serde_json::json!(secondary));
    }
    serde_json::Value::Object(v)
}

/// 各 v2 kind 的 `v2` 子对象**必填键**（装载端契约，与 build 端产出严格
/// 对称；缺失 → `Codec`，fail-closed）。
fn v2_required_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "MigrateNote" => &["key_hex", "amount"],
        "SettleV2" => &["binding_hex", "table_id", "amount", "secondary_amount"],
        "DepositV2" | "WithdrawRequestV2" => &["key_hex", "asset", "amount"],
        "RegisterGameToken" => &["token_id", "secondary_amount"],
        "IssueGameToken" | "BurnGameToken" | "FaucetMint" => {
            &["key_hex", "token_id", "amount"]
        }
        "BuyGasCredits" => &["key_hex", "asset", "amount"],
        "BindGasPolicy" => &["table_id", "token_id"],
        _ => &[],
    }
}

/// op 类型名（与 explorer_gateway::api::op_type_name 同一拼写——双处定义
/// 是刻意的：bin 层不可被 lib 依赖）。
fn kind_of(op: &Operation) -> &'static str {
    match op {
        Operation::OpenTable { .. } => "OpenTable",
        Operation::CloseTable { .. } => "CloseTable",
        Operation::Deposit { .. } => "Deposit",
        Operation::WithdrawRequest { .. } => "WithdrawRequest",
        Operation::Transfer { .. } => "Transfer",
        Operation::BuyIn { .. } => "BuyIn",
        Operation::Settle(_) => "Settle",
        // ABI v2 追加变体（判别值 7/8；additive 纪律见 ops.rs 模块文档）
        Operation::MigrateNote(_) => "MigrateNote",
        Operation::SettleV2(_) => "SettleV2",
        // TE-M2 追加变体（判别值 9/10；additive 纪律见 ops.rs 模块文档——
        // 本 match 对 Operation 穷尽，新变体只能在此追加命名，属冻结文件
        // 旁的最小机械追加）
        Operation::DepositV2(_) => "DepositV2",
        Operation::WithdrawRequestV2(_) => "WithdrawRequestV2",
        // TE-M3 追加变体（判别值 11/12/13；GTS 游戏币——与
        // explorer_gateway::api::op_type_name 同一拼写的最小机械追加，
        // 见 docs/ABI_TE_M3.md）
        Operation::RegisterGameToken(_) => "RegisterGameToken",
        Operation::IssueGameToken(_) => "IssueGameToken",
        Operation::BurnGameToken(_) => "BurnGameToken",
        // TE-M6 追加变体（判别值 14/15/16；Free 模式 gas 服务费——与
        // explorer_gateway::api::op_type_name 同一拼写的最小机械追加，
        // 见 docs/ABI_TE_M6.md）
        Operation::FaucetMint(_) => "FaucetMint",
        Operation::BuyGasCredits(_) => "BuyGasCredits",
        Operation::BindGasPolicy(_) => "BindGasPolicy",
    }
}

/// owner 33B 压缩公钥 → 摘要缩写（前 8 + `…` + 后 8 hex；与网关
/// `short_hex` 逐字符一致）。
#[must_use]
pub fn short_owner_hex(owner: &[u8; 33]) -> String {
    let h = hex::encode(owner);
    format!("{}\u{2026}{}", &h[..8], &h[h.len() - 8..])
}

/// WAL 偏移扫描：逐记录 `(起始字节偏移, 解码帧)`（格式与 `wal::read_all`
/// 一致；损坏 → `WalCorrupted`）。
fn scan_wal_offsets(path: &Path) -> AppchainResult<Vec<(u64, Box<SignedFrame>)>> {
    let file = std::fs::File::open(path)
        .map_err(|_| AppchainError::WalCorrupted("open failed"))?;
    let mut r = BufReader::new(file);
    let mut out = Vec::new();
    let mut pos = 0u64;
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(AppchainError::WalCorrupted("read length")),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(AppchainError::WalCorrupted("frame length insane"));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)
            .map_err(|_| AppchainError::WalCorrupted("truncated frame"))?;
        let frame = borsh::from_slice::<SignedFrame>(&buf)
            .map_err(|_| AppchainError::WalCorrupted("bad frame encoding"))?;
        out.push((pos, Box::new(frame)));
        pos = pos
            .checked_add(4 + len as u64)
            .ok_or(AppchainError::WalCorrupted("offset overflow"))?;
    }
    Ok(out)
}

// ===== 装载 =====

/// 从索引文件装载（重启直接加载免 replay；fail-closed：坏文件一律 `Err`）。
///
/// 校验链：format 标签 → 头部形状（hex/计数）→ **digest 全文件核对** →
/// 逐行契约（kind 已知 / 帧序连续 / Settle 字段齐备 / binding 唯一非零）→
/// 行数与头部计数一致。任何一步失败 → [`AppchainError::Codec`]。
///
/// # Errors
/// 文件不可读 / 非 UTF-8 / 空 / 契约任何一条不符。
pub fn load_index(path: &Path) -> AppchainResult<ArchiveIndex> {
    let bytes = std::fs::read(path)
        .map_err(|e| AppchainError::Codec(format!("archive index open: {e}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::Codec("archive index not utf-8".into()))?;
    let (header_line, rest) = match text.split_once('\n') {
        Some(pair) => pair,
        None => return Err(AppchainError::Codec("archive index: missing header line".into())),
    };
    let header = parse_header(header_line)?;
    // digest：头部行（含其换行）之后的全部原始字节。
    let digest = blake2s32(&[rest.as_bytes()]);
    if digest != header.digest {
        return Err(AppchainError::Codec(
            "archive index: digest mismatch (file tampered or truncated)".into(),
        ));
    }

    let mut frames: Vec<FrameEntry> = Vec::new();
    let mut proofs: Vec<ProofEntry> = Vec::new();
    let mut by_binding: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut by_table: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut expect_index: u64 = 0;
    let mut settlement_count = 0u64;
    for (lineno, line) in rest.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| AppchainError::Codec(format!("archive index line {}: {e}", lineno + 2)))?;
        let kind = str_field(&v, "kind")?;
        if kind == "Proof" {
            let index = u64_field(&v, "index")?;
            let binding = hex32_field(&v, "binding_hex")?;
            let engine = str_field(&v, "engine")?.to_owned();
            proofs.push(ProofEntry { index, binding, engine });
            continue;
        }
        let entry = parse_frame_line(&v, kind, expect_index, lineno + 2)?;
        expect_index = expect_index
            .checked_add(1)
            .ok_or_else(|| AppchainError::Codec("archive index: frame index overflow".into()))?;
        if let Some(s) = &entry.settle {
            settlement_count += 1;
            let row = frames.len();
            if by_binding.insert(s.binding, row).is_some() {
                return Err(AppchainError::Codec(
                    "archive index: duplicate binding".into(),
                ));
            }
            by_table.entry(s.table_id).or_default().push(row);
        }
        frames.push(entry);
    }
    if frames.len() as u64 != header.frame_count
        || settlement_count != header.settlement_count
        || proofs.len() as u64 != header.proof_count
    {
        return Err(AppchainError::Codec(
            "archive index: line counts disagree with header".into(),
        ));
    }
    Ok(ArchiveIndex {
        header,
        frames,
        proofs,
        by_binding,
        by_table,
    })
}

/// 头部行解析 + 契约校验。
fn parse_header(line: &str) -> AppchainResult<ArchiveIndexHeader> {
    let v: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| AppchainError::Codec(format!("archive index header: {e}")))?;
    let format = str_field(&v, "format")?;
    if format != FORMAT_TAG {
        return Err(AppchainError::Codec(format!(
            "archive index: unsupported format {format:?} (expect {FORMAT_TAG:?})"
        )));
    }
    let head = v
        .get("chain_head")
        .ok_or_else(|| AppchainError::Codec("archive index: missing chain_head".into()))?;
    Ok(ArchiveIndexHeader {
        sequencer_public: hex32_field(&v, "sequencer_public")?,
        chain_head_index: u64_field(head, "index")?,
        chain_head_hash: hex32_field(head, "hash")?,
        chain_head_state_root: hex32_field(head, "state_root")?,
        frame_count: u64_field(&v, "frame_count")?,
        settlement_count: u64_field(&v, "settlement_count")?,
        proof_count: u64_field(&v, "proof_count")?,
        digest: hex32_field(&v, "digest")?,
    })
}

/// 帧行解析 + 契约校验（帧序连续 / Settle 字段齐备 / binding 非零）。
fn parse_frame_line(
    v: &serde_json::Value,
    kind: &str,
    expect_index: u64,
    lineno: usize,
) -> AppchainResult<FrameEntry> {
    // v1 七种 kind + v2 追加变体（TE-M5 缺口收口，拼写与 kind_of/
    // op_type_name 一致）。未知 kind 一律拒（fail-closed 不变）。
    let known = matches!(
        kind,
        "OpenTable"
            | "CloseTable"
            | "Deposit"
            | "WithdrawRequest"
            | "Transfer"
            | "BuyIn"
            | "Settle"
            | "MigrateNote"
            | "SettleV2"
            | "DepositV2"
            | "WithdrawRequestV2"
            | "RegisterGameToken"
            | "IssueGameToken"
            | "BurnGameToken"
            | "FaucetMint"
            | "BuyGasCredits"
            | "BindGasPolicy"
    );
    if !known {
        return Err(AppchainError::Codec(format!(
            "archive index line {lineno}: unknown kind {kind:?}"
        )));
    }
    // v2 变体：`v2` 子对象必填键契约（与 build 端 v2_summary_of 严格对称）。
    let v2 = if v2_required_fields(kind).is_empty() && !matches!(kind, "MigrateNote" | "SettleV2" | "DepositV2" | "WithdrawRequestV2" | "RegisterGameToken" | "IssueGameToken" | "BurnGameToken" | "FaucetMint" | "BuyGasCredits" | "BindGasPolicy") {
        None
    } else {
        let obj = v
            .get("v2")
            .and_then(|x| x.as_object())
            .ok_or_else(|| {
                AppchainError::Codec(format!(
                    "archive index line {lineno}: v2 kind {kind:?} requires the v2 summary object"
                ))
            })?;
        for required in v2_required_fields(kind) {
            if !obj.contains_key(*required) {
                return Err(AppchainError::Codec(format!(
                    "archive index line {lineno}: v2 kind {kind:?} requires field {required:?}"
                )));
            }
        }
        Some(V2OpSummary {
            table_id: opt_u64_field(obj, "table_id", lineno)?,
            binding: opt_hex32_field(obj, "binding_hex", lineno)?,
            key: opt_hex32_field(obj, "key_hex", lineno)?,
            token_id: opt_u64_field(obj, "token_id", lineno)?.map(|x| u32::try_from(x).map_err(|_| AppchainError::Codec(format!("archive index line {lineno}: bad token_id")))).transpose()?,
            asset: obj
                .get("asset")
                .and_then(|x| x.as_str())
                .map(str::to_owned),
            amount: opt_u64_field(obj, "amount", lineno)?,
            secondary_amount: opt_u64_field(obj, "secondary_amount", lineno)?,
        })
    };
    let index = u64_field(v, "index")?;
    if index != expect_index {
        return Err(AppchainError::Codec(format!(
            "archive index line {lineno}: frame index {index} breaks continuity (expect {expect_index})"
        )));
    }
    let settle = if kind == "Settle" {
        let binding = hex32_field(v, "binding_hex")?;
        if binding == [0u8; 32] {
            return Err(AppchainError::Codec(format!(
                "archive index line {lineno}: zero binding"
            )));
        }
        let payouts = v
            .get("payouts")
            .and_then(|p| p.as_array())
            .ok_or_else(|| {
                AppchainError::Codec(format!("archive index line {lineno}: missing payouts"))
            })?
            .iter()
            .map(|p| {
                let owner_short = str_field(p, "owner_short")?.to_owned();
                let amount = u64_field(p, "amount")?;
                Ok((owner_short, amount))
            })
            .collect::<AppchainResult<Vec<_>>>()?;
        Some(SettleSummary {
            table_id: u64_field(v, "table_id")?,
            binding,
            pot: u64_field(v, "pot")?,
            rake_base: u64_field(v, "rake_base")?,
            rake_total: u64_field(v, "rake_total")?,
            payouts,
        })
    } else {
        None
    };
    Ok(FrameEntry {
        kind: kind.to_owned(),
        index,
        ts_ms: u64_field(v, "ts_ms")?,
        state_root: hex32_field(v, "state_root")?,
        hash: hex32_field(v, "hash")?,
        offset: u64_field(v, "offset")?,
        settle,
        v2,
    })
}

/// 可选 u64 字段（缺失 → None；存在但类型错 → `Codec`）。
fn opt_u64_field(
    v: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    lineno: usize,
) -> AppchainResult<Option<u64>> {
    match v.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(x) => x
            .as_u64()
            .map(Some)
            .ok_or_else(|| AppchainError::Codec(format!("archive index line {lineno}: bad {name}"))),
    }
}

/// 可选 hex32 字段（缺失 → None；存在但非 32B hex → `Codec`）。
fn opt_hex32_field(
    v: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    lineno: usize,
) -> AppchainResult<Option<[u8; 32]>> {
    match v.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(x) => {
            let text = x.as_str().ok_or_else(|| {
                AppchainError::Codec(format!("archive index line {lineno}: bad {name}"))
            })?;
            let bytes = hex::decode(text)
                .ok()
                .filter(|b| b.len() == 32)
                .ok_or_else(|| {
                    AppchainError::Codec(format!("archive index line {lineno}: bad hex32 {name}"))
                })?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
    }
}

// ===== 字段读取（契约层本地实现）=====

fn str_field<'a>(v: &'a serde_json::Value, name: &str) -> AppchainResult<&'a str> {
    v.get(name)
        .and_then(|x| x.as_str())
        .ok_or_else(|| AppchainError::Codec(format!("archive index: missing {name}")))
}

fn u64_field(v: &serde_json::Value, name: &str) -> AppchainResult<u64> {
    v.get(name)
        .and_then(|x| x.as_u64())
        .ok_or_else(|| AppchainError::Codec(format!("archive index: missing/bad {name}")))
}

fn hex32_field(v: &serde_json::Value, name: &str) -> AppchainResult<[u8; 32]> {
    let s = str_field(v, name)?;
    let bytes = hex::decode(s)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| AppchainError::Codec(format!("archive index: bad hex32 {name}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
