//! v1.5 真实罚没（plan §2-b）：SlashLedger + bond 扣减 + 共识准入联动。
//!
//! # 语义
//!
//! 1. **SlashLedger（append-only）**：罚没事件 `{validator_pubkey, amount,
//!    reason, ts_ms, height, evidence_digest}` 顺序追加，永不改写/删除；
//!    `evidence_digest` 绑定证据（CensorshipProof 的 receipt 域哈希或双签
//!    证据对的内容哈希），防同一证据重复罚没（幂等键）。
//! 2. **apply_slash → bond 扣减**：从 [`ValidatorSet`] 对应 [`ValidatorEntry`]
//!    的 `stake`（bond 余额）扣减，**扣减到 0 为下限**（不足部分不记欠款，
//!    v1.5 简化；SEC2-H2 的欠款记录语义不在此实现）。扣减后 stake == 0 的
//!    validator 置 `ValidatorStatus::Slashed`。
//! 3. **共识准入联动**：`ValidatorStatus::Slashed` 使
//!    [`ValidatorEntry::can_participate_consensus`] 返回 false —— 这是
//!    validator_set 既有 Active 判定的直接复用，bond 归零 validator 即失去
//!    出块资格（`active_count` / `active_validator_pubkeys_sorted` 等全部
//!    准入路径均以该判定为闸）。无需新增状态位。
//! 4. **触发源**：
//!    - `CensorshipProof` 命中 `Censored`（§5.3-4 三态之三）→
//!      [`apply_slash_from_censorship`]；
//!    - 双签证据（vertex equivocation：同 (epoch, round, author) 两枚合法
//!      签名的不同 vertex；commit cert equivocation 同理）→
//!      [`apply_slash_from_double_sign`]。证据哈希 = 两枚冲突载荷哈希的
//!      域分隔拼接哈希。
//!
//! # 与既有模块的关系
//!
//! - `consensus/slashing.rs`（Task 13）是**金额计算与优先级规则**层
//!   （`compute_slash_amount` / SEC2-H2 优先级），本模块是**事件账本 +
//!   bond 余额扣减执行**层。罚没百分比建议经 `slashing::compute_slash_amount`
//!   计算后传入本模块 `apply_slash`。
//! - `ValidatorEntry.stake` 即 bond 余额（genesis 必须为 0，真金白银经
//!   UTXO-backed bond 在运行期质押，见 `build_genesis_validator_set` 注释）。
//!
//! # 边界（如实标注）
//!
//! - **与 poker-appchain BondLedger 的对账**：poker_l1 侧扣减的是本进程
//!   ValidatorSet 的内存 bond 余额（经 system object 持久化路径时可随
//!   ValidatorSet 快照落盘）；appchain 侧 BondLedger 是独立账本。两侧的
//!   对账/单一事实源接线属后续工作 —— v1.5 以本模块事件流（append-only、
//!   含 evidence_digest）为对账凭据，不改变 appchain 任何代码。
//! - **Node 侧触发为主观判定**：`check_censorship` 命中 Censored 时由本节点
//!   对 receipt 签发者本地执行罚没（原型口径）。生产语义需要 QC 背书的
//!   审查证据 + epoch 边界统一结算，避免单节点主观证据直接改写共享状态 ——
//!   接入点在 [`SlashLedger`]：事件先行、结算随后。
//! - **无 re-bond**：v1.5 无恢复/重新质押路径；`Slashed` 状态不可逆
//!   （[ValidatorEntry] 语义沿用）。恢复路径须先定义治理语义，属后续版本。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde::{Deserialize, Serialize};

use crate::consensus::validator_set::{ValidatorEntry, ValidatorSet, ValidatorStatus};
use crate::consensus::{Epoch, Round};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::{BlockHeight, Hash};

/// 罚没原因（v1.5 两类；对应 plan §2-b）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    /// 审查证据成立（CensorshipProof 三态判定为 `Censored`）。
    CensorshipProof,
    /// 双签（vertex / commit cert equivocation）。
    DoubleSign,
}

impl SlashReason {
    /// 稳定的判别字符串（JSONL/日志输出用，格式冻结）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CensorshipProof => "censorship_proof",
            Self::DoubleSign => "double_sign",
        }
    }
}

/// 单条罚没事件（append-only 账本的一行）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashEvent {
    /// 被罚没 validator 的 tagged pubkey。
    pub validator_pubkey: TaggedPubkey,
    /// 本次扣减金额（bond 余额单位；0 扣减（余额已尽）也记录，作停止出块凭据）。
    pub amount: u64,
    /// 罚没原因。
    pub reason: SlashReason,
    /// 事件时间（记账节点本地时钟，毫秒；跨节点不作因果序）。
    pub ts_ms: u64,
    /// 证据触发时的链高提示（0 = 未提供）。
    pub height: BlockHeight,
    /// 证据摘要（幂等键：同一证据不重复罚没）。
    pub evidence_digest: Hash,
}

impl SlashEvent {
    /// 事件自身的域分隔摘要（账本链式校验用）。
    #[must_use]
    pub fn event_digest(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(b"ZCHAIN_SLASH_EVENT_V1");
        h.update(&self.validator_pubkey.to_bytes());
        h.update(&self.amount.to_le_bytes());
        h.update(self.reason.as_str().as_bytes());
        h.update(&self.ts_ms.to_le_bytes());
        h.update(&self.height.to_le_bytes());
        h.update(&self.evidence_digest);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

/// v1.5 默认罚没金额：审查/双签证据成立即全额罚没（与
/// `slashing::DEFAULT_SLASH_PERCENTAGE = 100` 一致；调用方可按治理参数
/// 用 `compute_slash_amount` 计算部分罚没后传入）。
pub const DEFAULT_SLASH_AMOUNT_FULL: u64 = u64::MAX;

/// append-only 罚没账本。
///
/// `events` 只增不减；`applied_evidences` 是 `evidence_digest` 的去重集合
/// （幂等：同一证据对同一 validator 只产生一条事件）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashLedger {
    events: Vec<SlashEvent>,
    applied_evidences: std::collections::BTreeSet<(TaggedPubkey, Hash)>,
}

impl SlashLedger {
    /// 空账本。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 已记录事件数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// 是否无事件。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 全部事件（append-only 只读快照）。
    #[must_use]
    pub fn events(&self) -> &[SlashEvent] {
        &self.events
    }

    /// 某 validator 的全部事件（账本序）。
    #[must_use]
    pub fn events_for(&self, pubkey: &TaggedPubkey) -> Vec<&SlashEvent> {
        self.events
            .iter()
            .filter(|e| &e.validator_pubkey == pubkey)
            .collect()
    }

    /// 某 validator 的累计罚没金额。
    #[must_use]
    pub fn total_slashed(&self, pubkey: &TaggedPubkey) -> u64 {
        self.events
            .iter()
            .filter(|e| &e.validator_pubkey == pubkey)
            .map(|e| e.amount)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// 执行罚没并记账（核心入口）。
    ///
    /// 幂等：`evidence_digest` 与 pubkey 的组合已存在 → 返回 `Ok(None)`，
    /// 不重复扣减。
    ///
    /// 扣减规则：从 `set` 中该 validator 的 `stake` 扣 `amount`（saturating
    /// 到 0 下限），扣后 stake == 0 → 状态置 [`ValidatorStatus::Slashed`]
    /// （即失去出块资格，见模块头准入联动说明）。validator 不在集合中或
    /// 已 Slashed → `Err`（无 bond 可罚/不可重复罚没）。
    pub fn apply_slash(
        &mut self,
        set: &mut ValidatorSet,
        validator_pubkey: &TaggedPubkey,
        amount: u64,
        reason: SlashReason,
        ts_ms: u64,
        height: BlockHeight,
        evidence_digest: Hash,
    ) -> PokerL1Result<Option<SlashEvent>> {
        // 幂等：同一证据同一 validator 只罚一次。
        if !self
            .applied_evidences
            .insert((validator_pubkey.clone(), evidence_digest))
        {
            return Ok(None);
        }
        let entry = set
            .find_validator_mut(validator_pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;
        if entry.status == ValidatorStatus::Slashed {
            return Err(PokerL1Error::Other(format!(
                "slash: validator {:?} 已处于 Slashed 状态（v1.5 无 re-bond，不可重复罚没）",
                validator_pubkey
            )));
        }
        if !entry.can_be_slashed() {
            return Err(PokerL1Error::Other(format!(
                "slash: validator {:?} 状态 {:?} 不可罚没",
                validator_pubkey, entry.status
            )));
        }
        let deducted = entry.stake.min(amount);
        entry.stake -= deducted;
        let halted = entry.stake == 0;
        if halted {
            entry.status = ValidatorStatus::Slashed;
        }
        // stake 变化 → ValidatorSet 承诺哈希必须同步刷新（compute_hash 输入
        // 含 validators 全量字段；不刷新会使 validate_persisted 失败）。
        set.validator_set_hash = set.compute_hash();
        let event = SlashEvent {
            validator_pubkey: validator_pubkey.clone(),
            amount: deducted,
            reason,
            ts_ms,
            height,
            evidence_digest,
        };
        self.events.push(event.clone());
        Ok(Some(event))
    }

    /// CensorshipProof 命中 `Censored` 触发罚没。
    ///
    /// `evidence_digest` = CensorshipProof 证据域摘要
    /// （[`censorship_evidence_digest`]），绑定 (chain_id, tx_hash, seen_at_ms,
    /// 签发者) —— 同一 receipt 证据全网幂等。
    pub fn apply_slash_from_censorship(
        &mut self,
        set: &mut ValidatorSet,
        receipt_validator_pubkey: &TaggedPubkey,
        evidence_digest: Hash,
        amount: u64,
        ts_ms: u64,
        height: BlockHeight,
    ) -> PokerL1Result<Option<SlashEvent>> {
        self.apply_slash(
            set,
            receipt_validator_pubkey,
            amount,
            SlashReason::CensorshipProof,
            ts_ms,
            height,
            evidence_digest,
        )
    }

    /// 双签证据触发罚没。
    ///
    /// `payload_a` / `payload_b` 为同署名者对同一位点（同 (epoch, round,
    /// author) 或同 (epoch, commit_round)）签下的两枚不同载荷的字节编码；
    /// 证据摘要 = 两载荷按序拼接的域分隔哈希（载荷交换不改变摘要：内部
    /// 取序后哈希，见 [`double_sign_evidence_digest`]）。
    pub fn apply_slash_from_double_sign(
        &mut self,
        set: &mut ValidatorSet,
        offender: &TaggedPubkey,
        payload_a: &[u8],
        payload_b: &[u8],
        amount: u64,
        ts_ms: u64,
        height: BlockHeight,
    ) -> PokerL1Result<Option<SlashEvent>> {
        let evidence_digest = double_sign_evidence_digest(payload_a, payload_b);
        self.apply_slash(
            set,
            offender,
            amount,
            SlashReason::DoubleSign,
            ts_ms,
            height,
            evidence_digest,
        )
    }
}

/// CensorshipProof 证据的域分隔摘要（幂等键）。
///
/// `blake2b_256("ZCHAIN_CENSORSHIP_V1" || chain_id || tx_hash || seen_at_ms || pubkey)`
#[must_use]
pub fn censorship_evidence_digest(
    chain_id: crate::ChainId,
    tx_hash: &Hash,
    seen_at_ms: u64,
    validator_pubkey: &TaggedPubkey,
) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(b"ZCHAIN_CENSORSHIP_V1");
    h.update(&chain_id.to_le_bytes());
    h.update(tx_hash);
    h.update(&seen_at_ms.to_le_bytes());
    h.update(&validator_pubkey.to_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 双签证据摘要（载荷序无关：按字节序取序后拼接）。
///
/// `blake2b_256("ZCHAIN_DOUBLE_SIGN_V1" || len(a) || min(a,b) || len(max(a,b)) || max(a,b))`
#[must_use]
pub fn double_sign_evidence_digest(payload_a: &[u8], payload_b: &[u8]) -> Hash {
    let (first, second) = if payload_a <= payload_b {
        (payload_a, payload_b)
    } else {
        (payload_b, payload_a)
    };
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(b"ZCHAIN_DOUBLE_SIGN_V1");
    h.update(&(first.len() as u64).to_le_bytes());
    h.update(first);
    h.update(&(second.len() as u64).to_le_bytes());
    h.update(second);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// vertex 双签判定的最小证据校验（v1.5 原型口径）。
///
/// 真正的 equivocation 侦测（含签名重验）由 `slashing::VertexEquivocationEvidence`
/// 承担；本函数只做位点谓词：同 `(epoch, round, author)` 且载荷哈希不同。
#[must_use]
pub fn is_vertex_double_sign(a: &crate::consensus::DagVertex, b: &crate::consensus::DagVertex) -> bool {
    a.epoch == b.epoch
        && a.round == b.round
        && a.author_pubkey.to_bytes() == b.author_pubkey.to_bytes()
        && a.vertex_hash() != b.vertex_hash()
}

/// （epoch, round）位点元组（双签证据的位点标识）。
#[must_use]
pub const fn vertex_site(epoch: Epoch, round: Round) -> (Epoch, Round) {
    (epoch, round)
}

/// validator 是否仍具备出块资格（只读准入判定；复用 validator_set 既有语义）。
#[must_use]
pub fn can_produce_blocks(set: &ValidatorSet, pubkey: &TaggedPubkey) -> bool {
    set.find_validator(pubkey)
        .is_some_and(ValidatorEntry::can_participate_consensus)
}


// ===== 对账恒等（排期表 §2 bond/slash 行出口判据第三项） =====
//
// # 恒等式
//
// ```text
// effective_bond(v) == initial_bond(v) − Σ ledger.amount(v)   （saturating）
// halted(v) ⇔ effective_bond(v) == 0                            （v1 无 re-bond）
// ```
//
// `apply_slash` 记录的 `amount` 是**实际扣减额**（`min(stake, amount)`），
// 因此上式是精确恒等（不是有损近似）——任何一侧不一致即账本/状态损坏。
//
// # 跨进程锚（与 poker-appchain BondLedger 的对账）
//
// 两仓无依赖边（appchain 侧 BondLedger 是 v1"只记录不执行"的独立账本）。
// 对账凭据 = 本账本的**链式事件摘要**
// [`SlashLedger::reconciliation_digest`]（append-only 事件流折叠根，
// 任一事件篡改/删除/重排必然失配）：poker_l1 侧执行罚没后导出该摘要，
// appchain 侧经 `BondLedger` 的 `SlashRecord`（reason 字段以
// `slash_ledger_digest:<hex>` 约定留痕）锚定同一摘要——两侧摘要相等
// 即"执行侧扣减流 == 记录侧留痕流"。appchain 侧自身的余额恒等式
// （`balance == ΣDeposit − ΣWithdraw`，SlashRecord 不进余额）由其
// `BondLedger::reconcile` 对账。

/// 对账单行（per-validator）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashReconciliationRow {
    /// validator。
    pub validator_pubkey: TaggedPubkey,
    /// 期初 bond（对账基准快照）。
    pub initial_bond: u64,
    /// 账本累计扣减（事件 amount 之和）。
    pub slashed_total: u64,
    /// 当前 bond 余额（ValidatorSet 实时值）。
    pub effective_bond: u64,
    /// 恒等式核对：`initial − slashed == effective` 且 halted ⇔ 余额 0。
    pub consistent: bool,
    /// 该 validator 的事件数。
    pub events: usize,
}

/// 对账报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashReconciliationReport {
    /// 逐 validator 行（pubkey 序）。
    pub rows: Vec<SlashReconciliationRow>,
    /// 全部行一致且无"事件存在但无期初基准"的孤儿。
    pub all_consistent: bool,
    /// 账本链式事件摘要（跨进程对账锚，见模块注释）。
    pub ledger_digest: Hash,
}

impl SlashLedger {
    /// 账本链式事件摘要：`d_i = H("ZCHAIN_SLASH_RECON_V1" ‖ d_{i-1} ‖
    /// event_digest_i)`，`d_0 = 0`。append-only 事件流的折叠根——对账
    /// 两侧各持一份，相等即事件流逐位一致（防篡改/删失/重排）。
    #[must_use]
    pub fn reconciliation_digest(&self) -> Hash {
        let mut acc = [0u8; 32];
        for e in &self.events {
            let mut h = Blake2bVar::new(32).expect("32 <= 64");
            h.update(b"ZCHAIN_SLASH_RECON_V1");
            h.update(&acc);
            h.update(&e.event_digest());
            let mut out = [0u8; 32];
            h.finalize_variable(&mut out).expect("32 <= 64");
            acc = out;
        }
        acc
    }

    /// 对账恒等核算（排期表 §2 bond/slash 出口判据）。
    ///
    /// `initial_bonds`：期初 bond 快照（genesis/注册时刻的 stake 基准），
    /// 覆盖集合 ∪ 事件集合中出现的全部 validator（缺基准的 validator 计
    /// 入 `orphans`，破坏 `all_consistent`——事件无基准无法核对，宁可
    /// 报警不可放行）。
    #[must_use]
    pub fn reconcile(
        &self,
        set: &ValidatorSet,
        initial_bonds: &std::collections::BTreeMap<TaggedPubkey, u64>,
    ) -> SlashReconciliationReport {
        // 参与对账的 validator 全集（集合成员 ∪ 事件主体），pubkey 序。
        let mut keys: std::collections::BTreeSet<TaggedPubkey> =
            initial_bonds.keys().cloned().collect();
        for e in &self.events {
            keys.insert(e.validator_pubkey.clone());
        }
        let mut rows = Vec::with_capacity(keys.len());
        let mut all_consistent = true;
        let mut orphans = 0usize;
        for pk in keys {
            let Some(&initial) = initial_bonds.get(&pk) else {
                orphans += 1;
                all_consistent = false;
                continue;
            };
            let slashed_total = self.total_slashed(&pk);
            let effective = set
                .find_validator(&pk)
                .map(|e| e.stake)
                .unwrap_or(0);
            let halted_status = set
                .find_validator(&pk)
                .is_some_and(|e| e.status == ValidatorStatus::Slashed);
            let mut consistent =
                initial.saturating_sub(slashed_total) == effective;
            // halted ⇔ 余额 0（v1 无 re-bond；部分罚没不得置 Slashed）
            consistent &= halted_status == (effective == 0);
            let events = self.events_for(&pk).len();
            // 无事件的 validator：slashed_total 必为 0（账本与集合独立损坏
            // 才会出现"无事件却有扣减"）
            if events == 0 {
                consistent &= slashed_total == 0;
            }
            all_consistent &= consistent;
            rows.push(SlashReconciliationRow {
                validator_pubkey: pk,
                initial_bond: initial,
                slashed_total,
                effective_bond: effective,
                consistent,
                events,
            });
        }
        if orphans > 0 {
            tracing::warn!(
                orphans,
                "slash reconcile: ledger events reference validators without initial bond baseline"
            );
        }
        SlashReconciliationReport {
            rows,
            all_consistent,
            ledger_digest: self.reconciliation_digest(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::VRF_PUBKEY_SIZE;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_set(count: usize, stake: u64) -> ValidatorSet {
        let validators: Vec<ValidatorEntry> = (0..count)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_tagged_pubkey(0x10 + i as u8),
                    [0x20 + i as u8; VRF_PUBKEY_SIZE],
                    stake,
                    0,
                );
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let genesis = crate::consensus::validator_set::compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    const EVIDENCE: Hash = [0xEEu8; 32];

    #[test]
    fn slash_deducts_stake_and_records_event() {
        let mut set = make_set(5, 1_000);
        let target = set.validators[0].pubkey.clone();
        let mut ledger = SlashLedger::new();

        let event = ledger
            .apply_slash(
                &mut set,
                &target,
                400,
                SlashReason::CensorshipProof,
                1_000,
                10,
                EVIDENCE,
            )
            .expect("罚没应成功")
            .expect("首次证据必须产生事件");
        assert_eq!(event.amount, 400);
        assert_eq!(event.reason, SlashReason::CensorshipProof);
        assert_eq!(event.evidence_digest, EVIDENCE);
        assert_eq!(set.validators[0].stake, 600);
        assert_eq!(set.validators[0].status, ValidatorStatus::Active);
        assert!(can_produce_blocks(&set, &target), "未归零仍可出块");
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.total_slashed(&target), 400);
    }

    #[test]
    fn slash_is_idempotent_per_evidence() {
        let mut set = make_set(5, 1_000);
        let target = set.validators[0].pubkey.clone();
        let mut ledger = SlashLedger::new();
        let cfg = (400, SlashReason::DoubleSign, 1u64, 1u64);
        ledger
            .apply_slash(&mut set, &target, cfg.0, cfg.1, cfg.2, cfg.3, EVIDENCE)
            .unwrap();
        let second = ledger
            .apply_slash(&mut set, &target, cfg.0, cfg.1, cfg.2, cfg.3, EVIDENCE)
            .unwrap();
        assert!(second.is_none(), "同一证据不得重复罚没");
        assert_eq!(set.validators[0].stake, 600, "余额只应扣一次");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn slash_to_zero_halts_block_production() {
        let mut set = make_set(5, 1_000);
        let target = set.validators[0].pubkey.clone();
        let mut ledger = SlashLedger::new();

        // 全额罚没（DEFAULT_SLASH_AMOUNT_FULL 语义：saturate 到 0）
        let event = ledger
            .apply_slash(
                &mut set,
                &target,
                DEFAULT_SLASH_AMOUNT_FULL,
                SlashReason::DoubleSign,
                1,
                1,
                EVIDENCE,
            )
            .unwrap()
            .unwrap();
        assert_eq!(event.amount, 1_000, "扣减以余额为上限（下限 0）");
        assert_eq!(set.validators[0].stake, 0);
        assert_eq!(set.validators[0].status, ValidatorStatus::Slashed);
        assert!(
            !can_produce_blocks(&set, &target),
            "bond 归零 validator 必须失去出块资格"
        );
        assert_eq!(set.active_count(), 4, "active_count 必须排除 Slashed");
        // 已 Slashed 后再次罚没 → Err（不可重复罚没）
        let other_evidence = [0x11u8; 32];
        assert!(ledger
            .apply_slash(&mut set, &target, 100, SlashReason::DoubleSign, 2, 2, other_evidence)
            .is_err());
        assert!(set.validators[0].can_participate_consensus() == false);
    }

    #[test]
    fn slash_rejects_unknown_validator() {
        let mut set = make_set(5, 1_000);
        let outsider = make_tagged_pubkey(0x99);
        let mut ledger = SlashLedger::new();
        let err = ledger
            .apply_slash(&mut set, &outsider, 100, SlashReason::DoubleSign, 1, 1, EVIDENCE)
            .unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
        assert!(ledger.is_empty(), "失败罚没不得留下事件");
    }

    #[test]
    fn censorship_trigger_uses_stable_evidence_digest() {
        let pubkey = make_tagged_pubkey(0x42);
        let d1 = censorship_evidence_digest(crate::DEFAULT_CHAIN_ID, &[7u8; 32], 1234, &pubkey);
        let d2 = censorship_evidence_digest(crate::DEFAULT_CHAIN_ID, &[7u8; 32], 1234, &pubkey);
        assert_eq!(d1, d2, "同证据必须同摘要（幂等键）");
        let d3 = censorship_evidence_digest(crate::DEFAULT_CHAIN_ID, &[7u8; 32], 1235, &pubkey);
        assert_ne!(d1, d3, "seen_at_ms 变化必须改变摘要");
    }

    #[test]
    fn double_sign_trigger_digest_is_order_independent() {
        let a = b"payload-A";
        let b = b"payload-B";
        assert_eq!(
            double_sign_evidence_digest(a, b),
            double_sign_evidence_digest(b, a),
            "载荷交换不得改变证据摘要"
        );
        assert_ne!(
            double_sign_evidence_digest(a, b),
            double_sign_evidence_digest(a, a)
        );
    }

    #[test]
    fn slash_event_digest_is_deterministic() {
        let event = SlashEvent {
            validator_pubkey: make_tagged_pubkey(0x42),
            amount: 100,
            reason: SlashReason::CensorshipProof,
            ts_ms: 5,
            height: 9,
            evidence_digest: EVIDENCE,
        };
        assert_eq!(event.event_digest(), event.event_digest());
        let json = serde_json::to_string(&event).unwrap();
        let back: SlashEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back, "事件 JSON 往返必须一致（对账凭据要求）");
    }

    #[test]
    fn ledger_roundtrip_bcs_like_via_json() {
        let mut set = make_set(5, 500);
        let t0 = set.validators[0].pubkey.clone();
        let t1 = set.validators[1].pubkey.clone();
        let mut ledger = SlashLedger::new();
        ledger
            .apply_slash(&mut set, &t0, 100, SlashReason::CensorshipProof, 1, 1, [1u8; 32])
            .unwrap();
        ledger
            .apply_slash(&mut set, &t1, 200, SlashReason::DoubleSign, 2, 2, [2u8; 32])
            .unwrap();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: SlashLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn vertex_double_sign_predicate() {
        use crate::consensus::DagVertex;
        let mut a = DagVertex {
            epoch: 1,
            round: 3,
            author_pubkey: make_tagged_pubkey(0x42),
            tx_list: vec![],
            parent_hashes: vec![[1u8; 32]],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let mut b = a.clone();
        assert!(
            !is_vertex_double_sign(&a, &b),
            "完全相同 vertex 不是双签"
        );
        b.parent_hashes = vec![[2u8; 32]];
        assert!(is_vertex_double_sign(&a, &b), "同位点不同内容 = 双签证据");
        b.epoch = 2;
        a = b.clone();
        a.epoch = 3;
        assert!(!is_vertex_double_sign(&a, &b), "不同位点不是 vertex 双签");
        // vertex_site：位点元组
        assert_eq!(vertex_site(1, 3), (1, 3));
    }

    #[test]
    fn slash_reason_strings_frozen() {
        assert_eq!(SlashReason::CensorshipProof.as_str(), "censorship_proof");
        assert_eq!(SlashReason::DoubleSign.as_str(), "double_sign");
        // serde snake_case 命名冻结（JSONL 对账格式）
        assert_eq!(
            serde_json::to_string(&SlashReason::CensorshipProof).unwrap(),
            "\"censorship_proof\""
        );
    }

    // ===== 对账恒等 =====

    use super::{SlashLedger as L2, SlashReconciliationRow};
    use std::collections::BTreeMap;

    fn make_baseline(set: &ValidatorSet) -> BTreeMap<TaggedPubkey, u64> {
        set.validators
            .iter()
            .map(|v| (v.pubkey.clone(), v.stake))
            .collect()
    }

    /// 恒等式：部分罚没与全额罚没（饱和扣减）下 initial − Σevents == effective，
    /// halted ⇔ 余额 0；无事件 validator slashed_total == 0。
    #[test]
    fn slash_reconciliation_identity_holds() {
        let mut set = make_set(3, 1_000);
        let baseline = make_baseline(&set);
        let pks: Vec<TaggedPubkey> = set.validators.iter().map(|v| v.pubkey.clone()).collect();
        let mut ledger = SlashLedger::new();
        // 部分罚没 validator 0（300）
        ledger
            .apply_slash(&mut set, &pks[0], 300, SlashReason::CensorshipProof, 1, 10, [1; 32])
            .unwrap()
            .expect("首次罚没必须生效");
        // 全额罚没 validator 1（u64::MAX 建议额 → 饱和扣 1_000 → 归零停出块）
        ledger
            .apply_slash(&mut set, &pks[1], DEFAULT_SLASH_AMOUNT_FULL, SlashReason::DoubleSign, 2, 11, [2; 32])
            .unwrap()
            .expect("全额罚没必须生效");
        // validator 2 无事件
        let report = ledger.reconcile(&set, &baseline);
        assert!(report.all_consistent, "恒等式必须成立: {report:?}");
        assert_eq!(report.rows.len(), 3);
        let row0 = report.rows.iter().find(|r| r.validator_pubkey == pks[0]).unwrap();
        assert_eq!((row0.initial_bond, row0.slashed_total, row0.effective_bond), (1_000, 300, 700));
        assert!(row0.consistent && row0.events == 1);
        let row1 = report.rows.iter().find(|r| r.validator_pubkey == pks[1]).unwrap();
        assert_eq!((row1.slashed_total, row1.effective_bond), (1_000, 0), "饱和扣减记录实际扣减额");
        assert!(row1.consistent);
        let row2 = report.rows.iter().find(|r| r.validator_pubkey == pks[2]).unwrap();
        assert_eq!((row2.slashed_total, row2.effective_bond), (0, 1_000));
        // 归零 validator 失去出块资格（准入联动面）
        assert!(!can_produce_blocks(&set, &pks[1]));
        assert!(can_produce_blocks(&set, &pks[0]));
    }

    /// 恒等式破坏面：期初基准与集合实况矛盾 → consistent=false；
    /// 事件无基准 → all_consistent=false（孤儿 fail-closed）。
    #[test]
    fn slash_reconciliation_detects_inconsistency() {
        let mut set = make_set(2, 1_000);
        let pks: Vec<TaggedPubkey> = set.validators.iter().map(|v| v.pubkey.clone()).collect();
        let mut ledger = SlashLedger::new();
        ledger
            .apply_slash(&mut set, &pks[0], 400, SlashReason::CensorshipProof, 1, 10, [3; 32])
            .unwrap();
        let mut baseline = make_baseline(&set);
        // 基准错记（initial=500 vs 实况 1_000−400=600）
        baseline.insert(pks[0].clone(), 500);
        let report = ledger.reconcile(&set, &baseline);
        assert!(!report.all_consistent);
        let row = report.rows.iter().find(|r| r.validator_pubkey == pks[0]).unwrap();
        assert!(!row.consistent);
        // 孤儿：事件主体无基准
        let mut empty_baseline = BTreeMap::new();
        empty_baseline.insert(pks[1].clone(), 1_000);
        let report2 = ledger.reconcile(&set, &empty_baseline);
        assert!(!report2.all_consistent, "事件无基准必须 fail-closed");
    }

    /// 链式对账摘要：确定性 + 事件敏感（追加必失配）+ 幂等事件不改摘要 +
    /// 空账本为零向量。
    #[test]
    fn slash_ledger_digest_chain_sensitivity() {
        let mut set = make_set(1, 1_000);
        let target = set.validators[0].pubkey.clone();
        let mut ledger = SlashLedger::new();
        assert_eq!(ledger.reconciliation_digest(), [0u8; 32], "空账本摘要 = 零向量");
        ledger
            .apply_slash(&mut set, &target, 100, SlashReason::CensorshipProof, 1, 10, [4; 32])
            .unwrap();
        let d1 = ledger.reconciliation_digest();
        assert_eq!(d1, ledger.reconciliation_digest(), "确定性");
        ledger
            .apply_slash(&mut set, &target, 100, SlashReason::CensorshipProof, 2, 11, [5; 32])
            .unwrap();
        let d2 = ledger.reconciliation_digest();
        assert_ne!(d1, d2, "追加事件必须改变折叠根");
        // 幂等事件（同证据）不改变摘要
        let mut dup = SlashLedger::new();
        let mut set2 = make_set(1, 1_000);
        let target2 = set2.validators[0].pubkey.clone();
        dup.apply_slash(&mut set2, &target2, 100, SlashReason::CensorshipProof, 1, 10, [6; 32])
            .unwrap();
        let before = dup.reconciliation_digest();
        dup.apply_slash(&mut set2, &target2, 100, SlashReason::CensorshipProof, 9, 99, [6; 32])
            .unwrap();
        assert_eq!(before, dup.reconciliation_digest(), "幂等拒记不改摘要");
        let _ = SlashReconciliationRow {
            validator_pubkey: target.clone(),
            initial_bond: 0,
            slashed_total: 0,
            effective_bond: 0,
            consistent: true,
            events: 0,
        };
    }
}
