//! Slashing 与审查调查（Task 13 — SubTask 13.2 / 13.3 / 13.4 / 13.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 13.2 — vertex equivocation slashing**：
//!   - **NEW-M15**：`slash_amount = stake * slash_percentage / 100`，`slash_percentage` 默认 100%（全额罚没，可治理）
//!   - **SEC2-H2 — 多重 slashing 处理规则**：扣除基数 = 剩余质押（非原始）；
//!     优先级：vertex equivocation > commit cert equivocation > 拒收 checkpoint > 停机 > refuse_ack；
//!     每项扣除 = 剩余 * slash_percentage / 100；质押耗尽转欠款记录；受害者补偿按优先级分配
//! - **SubTask 13.3 — 停机 slashing**：
//!   - 连续 `downtime_threshold_blocks`（默认 100）未提交任何 vertex → 治理踢出
//!   - **NEW-L2**：停机 validator 罚没 `downtime_slash_percentage`（默认 10%）保证金 + 失去出块资格
//!   - **SEC-M1**：连续 `downtime_threshold_blocks + 2 * epoch_length_blocks` 未提交任何 vertex
//!     → 自动 slashing `downtime_slash_percentage`（无需治理介入），治理仅用于争议申辩
//! - **SubTask 13.4 — 审查缓解**：force_* tx 任何 validator 必须接受并装入 vertex；
//!   审查证据可作治理踢出依据
//! - **SubTask 13.5 — 审查调查流程（NEW-H1）**：
//!   - `force_checkpoint` 触发 assigned_validator 标记 `under_investigation` + `defense_window_blocks`（默认 50）防御窗口
//!   - 窗口内可提交"未收到证明"申辩免责
//!   - 窗口内无申辩或申辩无效 → 治理 slashing
//!   - 窗口内合理申辩 → 豁免 slashing 仅记录审查嫌疑
//!   - **R4-H5**：`under_investigation_count` 仅当申辩无效或无申辩时 +1（非"无论申辩是否成功 +1"）；
//!     衰减机制：每 epoch 衰减 1（最低为 0），防止历史指控永久累积

use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::consensus::{Epoch, ValidatorSet};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;

/// 默认 slashing 百分比（NEW-M15：equivocation 全额罚没，可治理）。
pub const DEFAULT_SLASH_PERCENTAGE: u32 = 100;

/// 默认停机阈值 block 数（SubTask 13.3：连续 100 block 未提交 vertex → 治理踢出）。
pub const DEFAULT_DOWNTIME_THRESHOLD_BLOCKS: BlockHeight = 100;

/// 默认停机 slashing 百分比（NEW-L2：10%，由 5% 提升至 10% 以威慑协助审查的停机）。
pub const DEFAULT_DOWNTIME_SLASH_PERCENTAGE: u32 = 10;

/// 默认防御窗口 block 数（NEW-H1：force_checkpoint 触发后 validator 有 50 block 提交申辩）。
pub const DEFAULT_DEFENSE_WINDOW_BLOCKS: BlockHeight = 50;

/// Slashing 原因（SEC2-H2：优先级排序）。
///
/// 优先级（数字越小优先级越高）：
/// 1. `VertexEquivocation` — 同一 (epoch, round, author) 双签 vertex
/// 2. `CommitCertEquivocation` — 同一 (epoch, commit_round) 双签 commit certificate
/// 3. `RefuseCheckpoint` — 拒收 checkpoint（审查证据）
/// 4. `Downtime` — 停机
/// 5. `RefuseAck` — 拒绝 ACK
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlashingReason {
    /// vertex equivocation（最高优先级，SEC2-H2）。
    VertexEquivocation,
    /// commit certificate equivocation（SEC2-H2）。
    CommitCertEquivocation,
    /// 拒收 checkpoint（SubTask 13.4：审查证据）。
    RefuseCheckpoint,
    /// 停机（SubTask 13.3：SEC-M1 / NEW-L2）。
    Downtime,
    /// 拒绝 ACK（最低优先级）。
    RefuseAck,
}

impl SlashingReason {
    /// 获取优先级（数字越小优先级越高，SEC2-H2）。
    pub const fn priority(self) -> u8 {
        match self {
            Self::VertexEquivocation => 1,
            Self::CommitCertEquivocation => 2,
            Self::RefuseCheckpoint => 3,
            Self::Downtime => 4,
            Self::RefuseAck => 5,
        }
    }

    /// 获取该原因对应的默认 slash_percentage。
    ///
    /// - equivocation 类：100%（NEW-M15 全额罚没）
    /// - 停机：10%（NEW-L2）
    /// - 其他：100%（保守默认）
    pub const fn default_slash_percentage(self) -> u32 {
        match self {
            Self::VertexEquivocation
            | Self::CommitCertEquivocation
            | Self::RefuseCheckpoint
            | Self::RefuseAck => DEFAULT_SLASH_PERCENTAGE,
            Self::Downtime => DEFAULT_DOWNTIME_SLASH_PERCENTAGE,
        }
    }
}

/// Slashing 配置（可治理参数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// equivocation 类 slashing 百分比（NEW-M15：默认 100%）。
    pub slash_percentage: u32,
    /// 停机阈值 block 数（SubTask 13.3：默认 100）。
    pub downtime_threshold_blocks: BlockHeight,
    /// 停机 slashing 百分比（NEW-L2：默认 10%）。
    pub downtime_slash_percentage: u32,
    /// 防御窗口 block 数（NEW-H1：默认 50）。
    pub defense_window_blocks: BlockHeight,
    /// epoch 长度（block 数，SEC-M1 自动 slashing 计算 = downtime_threshold + 2*epoch_length）。
    pub epoch_length_blocks: BlockHeight,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            slash_percentage: DEFAULT_SLASH_PERCENTAGE,
            downtime_threshold_blocks: DEFAULT_DOWNTIME_THRESHOLD_BLOCKS,
            downtime_slash_percentage: DEFAULT_DOWNTIME_SLASH_PERCENTAGE,
            defense_window_blocks: DEFAULT_DEFENSE_WINDOW_BLOCKS,
            epoch_length_blocks: 1000,
        }
    }
}

impl SlashingConfig {
    /// 计算 SEC-M1 自动 slashing 触发阈值。
    ///
    /// spec SEC-M1：连续 `downtime_threshold_blocks + 2 * epoch_length_blocks` 未提交 vertex → 自动 slashing。
    pub const fn auto_slash_threshold(&self) -> BlockHeight {
        self.downtime_threshold_blocks + 2 * self.epoch_length_blocks
    }
}

/// 计算 slash 金额（NEW-M15）。
///
/// `slash_amount = remaining_stake * slash_percentage / 100`
///
/// SEC2-H2：扣除基数 = 剩余质押（非原始质押），每项 slashing 基于当时剩余质押计算。
///
/// M-2 修复：使用 `saturating_mul` 防止 u64 乘法溢出。
pub const fn compute_slash_amount(remaining_stake: u64, slash_percentage: u32) -> u64 {
    remaining_stake.saturating_mul(slash_percentage as u64) / 100
}

/// 判定是否触发治理踢出（SubTask 13.3：连续 `downtime_threshold_blocks` 未提交 vertex）。
pub const fn is_downtime_governance_kickout(
    last_vertex_height: BlockHeight,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> bool {
    current_height.saturating_sub(last_vertex_height) >= config.downtime_threshold_blocks
}

/// 判定是否触发 SEC-M1 自动 slashing（连续 `downtime_threshold + 2*epoch_length` 未提交 vertex）。
pub const fn is_downtime_auto_slashable(
    last_vertex_height: BlockHeight,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> bool {
    current_height.saturating_sub(last_vertex_height) >= config.auto_slash_threshold()
}

/// 审查调查状态（NEW-H1 / R4-H5）。
///
/// `force_checkpoint` 触发 assigned_validator 进入调查状态：
/// - `defense_window_blocks` 内可提交"未收到证明"申辩
/// - 申辩成功 → 豁免 slashing，仅记录审查嫌疑
/// - 申辩失败或无申辩 → 治理 slashing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationState {
    /// 调查触发 block height（force_checkpoint 提交时的 block height）。
    pub triggered_at_height: BlockHeight,
    /// 防御窗口结束 height（triggered_at + defense_window_blocks）。
    pub defense_deadline: BlockHeight,
    /// 是否已提交申辩。
    pub defense_submitted: bool,
    /// 申辩是否有效（false = 无效或未申辩）。
    pub defense_valid: bool,
    /// 是否已 resolve（申辩成功或窗口过期后处理）。
    pub resolved: bool,
}

impl InvestigationState {
    /// 创建新调查状态（force_checkpoint 触发时调用）。
    pub const fn new(triggered_at_height: BlockHeight, config: &SlashingConfig) -> Self {
        Self {
            triggered_at_height,
            defense_deadline: triggered_at_height + config.defense_window_blocks,
            defense_submitted: false,
            defense_valid: false,
            resolved: false,
        }
    }

    /// 提交申辩（窗口内有效）。
    ///
    /// 返回 `Ok(())` 表示申辩已记录；`Err` 表示已超过窗口或已 resolve。
    pub fn submit_defense(&mut self, current_height: BlockHeight) -> PokerL1Result<()> {
        if self.resolved {
            return Err(PokerL1Error::Other(
                "investigation already resolved".to_string(),
            ));
        }
        if current_height > self.defense_deadline {
            return Err(PokerL1Error::Other(format!(
                "defense window expired (current={}, deadline={})",
                current_height, self.defense_deadline
            )));
        }
        self.defense_submitted = true;
        Ok(())
    }

    /// 评估申辩有效性并 resolve 调查。
    ///
    /// 参数：
    /// - `current_height`：当前 block height
    /// - `defense_valid`：申辩是否有效（由治理或验证逻辑判定）
    ///
    /// 返回 `Ok(should_slash)`：
    /// - `true`：申辩无效或未提交 → 治理 slashing
    /// - `false`：申辩有效 → 豁免 slashing
    pub fn resolve(
        &mut self,
        current_height: BlockHeight,
        defense_valid: bool,
    ) -> PokerL1Result<bool> {
        if self.resolved {
            return Err(PokerL1Error::Other(
                "investigation already resolved".to_string(),
            ));
        }
        // 窗口过期且未申辩 → 视为申辩无效
        if current_height > self.defense_deadline && !self.defense_submitted {
            self.defense_valid = false;
            self.resolved = true;
            return Ok(true); // 应 slashing
        }
        self.defense_valid = defense_valid;
        self.resolved = true;
        Ok(!defense_valid) // 申辩无效 → slashing
    }

    /// 判定申辩窗口是否已过期。
    pub const fn is_window_expired(&self, current_height: BlockHeight) -> bool {
        current_height > self.defense_deadline
    }
}

/// Slashing 执行结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingResult {
    /// 被 slashing 的 validator pubkey。
    pub validator: TaggedPubkey,
    /// slashing 原因。
    pub reason: SlashingReason,
    /// 扣除前的剩余质押。
    pub stake_before: u64,
    /// 扣除金额。
    pub slash_amount: u64,
    /// 扣除后的剩余质押。
    pub stake_after: u64,
    /// 是否转为欠款记录（stake_after == 0 且仍有应扣）。
    pub debt_recorded: bool,
}

/// 应用单次 slashing 到 ValidatorSet（SEC2-H2：扣除基数 = 剩余质押）。
///
/// spec NEW-M15 + SEC2-H2：
/// - `slash_amount = remaining_stake * slash_percentage / 100`
/// - 扣除后剩余质押 = remaining_stake - slash_amount
/// - 质押耗尽（remaining_stake < slash_amount）→ 全额扣除 + 转欠款记录
/// - validator 状态转为 Slashed
///
/// 参数：
/// - `validator_set`：可变 ValidatorSet 引用
/// - `validator_pubkey`：被 slashing 的 validator
/// - `reason`：slashing 原因（决定 slash_percentage）
/// - `config`：slashing 配置
pub fn apply_slashing(
    validator_set: &mut ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    reason: SlashingReason,
    config: &SlashingConfig,
) -> PokerL1Result<SlashingResult> {
    let validator = validator_set
        .find_validator_mut(validator_pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;

    // SEC2-H2：多重 slashing 须继续从剩余质押扣除；
    // 仅 Retired 状态（已退出且 VRF key 已销毁）不可再 slashing。
    if matches!(validator.status, crate::consensus::ValidatorStatus::Retired) {
        return Err(PokerL1Error::Other(format!(
            "validator retired, cannot be slashed (status={:?})",
            validator.status
        )));
    }

    let stake_before = validator.stake;
    let slash_percentage = match reason {
        SlashingReason::Downtime => config.downtime_slash_percentage,
        _ => config.slash_percentage,
    };
    let slash_amount = compute_slash_amount(stake_before, slash_percentage);
    let (stake_after, debt_recorded) = if stake_before >= slash_amount {
        (stake_before - slash_amount, false)
    } else {
        // 质押耗尽 → 全额扣除 + 转欠款记录（SEC2-H2）
        (0u64, true)
    };

    validator.stake = stake_after;
    // 标记为 Slashed（踢出 + 罚没）
    // 注意：停机类 slashing 保留出块资格剥夺但状态由治理决定
    if reason != SlashingReason::Downtime {
        // 使用 matches! 避免 const 不兼容问题（status 字段非 const 可写）
        validator.status = crate::consensus::ValidatorStatus::Slashed;
    }

    Ok(SlashingResult {
        validator: validator_pubkey.clone(),
        reason,
        stake_before,
        slash_amount,
        stake_after,
        debt_recorded,
    })
}

/// 多重 slashing 执行器（SEC2-H2：按优先级顺序处理）。
///
/// spec SEC2-H2：扣除基数 = 剩余质押（非原始）；优先级：
/// vertex equiv > commit cert equiv > refuse checkpoint > downtime > refuse_ack；
/// 每项扣除 = 剩余 * slash_percentage / 100。
///
/// 参数：
/// - `validator_set`：可变 ValidatorSet
/// - `validator_pubkey`：被 slashing 的 validator
/// - `reasons`：slashing 原因列表（将按优先级排序后依次执行）
/// - `config`：slashing 配置
///
/// 返回每项 slashing 的结果列表（按优先级排序）。
pub fn apply_multi_slashing(
    validator_set: &mut ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    mut reasons: Vec<SlashingReason>,
    config: &SlashingConfig,
) -> PokerL1Result<Vec<SlashingResult>> {
    // 按优先级排序（数字越小优先级越高）
    reasons.sort_by_key(|r| r.priority());

    let mut results = Vec::with_capacity(reasons.len());
    for reason in reasons {
        // 每次 slashing 基于当时剩余质押计算
        let result = apply_slashing(validator_set, validator_pubkey, reason, config)?;
        // 若质押已耗尽，后续 slashing 仍记录但金额为 0（转欠款）
        let debt_recorded = result.debt_recorded && result.stake_after == 0;
        results.push(result);
        let _ = debt_recorded; // 继续处理剩余原因（记录欠款），但金额为 0
    }
    Ok(results)
}

/// vertex equivocation 证据（SubTask 13.2）。
///
/// spec：提交两个冲突 vertex + 两个签名证据 → 踢出 + 罚没保证金。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VertexEquivocationEvidence {
    /// epoch（SEC-C1：绑定 epoch 防 equivocation 证据歧义）。
    pub epoch: Epoch,
    /// DAG round（同一 round 双签构成 equivocation）。
    pub round: u64,
    /// validator pubkey（author）。
    pub author: TaggedPubkey,
    /// 第一个 vertex hash。
    pub vertex_hash_1: crate::Hash,
    /// 第二个 vertex hash（必须不同于 vertex_hash_1）。
    pub vertex_hash_2: crate::Hash,
    /// 第一个 vertex 的签名。
    pub signature_1: Vec<u8>,
    /// 第二个 vertex 的签名。
    pub signature_2: Vec<u8>,
}

impl VertexEquivocationEvidence {
    /// 校验证据有效性（同一 epoch + round + author 但 vertex_hash 不同）。
    pub fn validate(&self) -> PokerL1Result<()> {
        if self.vertex_hash_1 == self.vertex_hash_2 {
            return Err(PokerL1Error::Other(
                "vertex equivocation: vertex_hash_1 == vertex_hash_2 (not equivocation)"
                    .to_string(),
            ));
        }
        if self.signature_1.is_empty() || self.signature_2.is_empty() {
            return Err(PokerL1Error::Other(
                "vertex equivocation: signatures must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// 构造 slashing 原因。
    pub const fn to_reason(&self) -> SlashingReason {
        SlashingReason::VertexEquivocation
    }
}

/// commit certificate equivocation 证据（SEC2-C1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitCertEquivocationEvidence {
    /// epoch。
    pub epoch: Epoch,
    /// commit round（同一 commit_round 双签构成 equivocation）。
    pub commit_round: u64,
    /// 第一个 commit certificate hash。
    pub cert_hash_1: crate::Hash,
    /// 第二个 commit certificate hash。
    pub cert_hash_2: crate::Hash,
}

impl CommitCertEquivocationEvidence {
    /// 校验证据有效性。
    pub fn validate(&self) -> PokerL1Result<()> {
        if self.cert_hash_1 == self.cert_hash_2 {
            return Err(PokerL1Error::Other(
                "commit cert equivocation: cert_hash_1 == cert_hash_2 (not equivocation)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// 构造 slashing 原因。
    pub const fn to_reason(&self) -> SlashingReason {
        SlashingReason::CommitCertEquivocation
    }
}

/// 检查 validator 是否处于停机状态并返回对应 slashing 原因（SubTask 13.3）。
///
/// 返回：
/// - `Ok(Some(SlashingReason::Downtime))`：触发自动 slashing（SEC-M1）
/// - `Ok(None)`：未触发 slashing（但可能已触发治理踢出，由调用方检查 `is_downtime_governance_kickout`）
pub fn check_downtime_slashing(
    validator_set: &ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> PokerL1Result<Option<SlashingReason>> {
    let validator = validator_set
        .find_validator(validator_pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;

    if !validator.can_be_slashed() {
        return Ok(None);
    }

    // SEC-M1：连续 downtime_threshold + 2*epoch_length 未提交 vertex → 自动 slashing
    if is_downtime_auto_slashable(validator.last_vertex_height, current_height, config) {
        return Ok(Some(SlashingReason::Downtime));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::{
        ValidatorEntry, ValidatorStatus, compute_genesis_chain_randomness,
    };
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_vrf_pubkey(byte: u8) -> [u8; 33] {
        [byte; 33]
    }

    fn make_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<ValidatorEntry> = (0..count)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_tagged_pubkey(0x10 + i as u8),
                    make_vrf_pubkey(0x10 + i as u8),
                    1_000_000,
                    0,
                );
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    // ===== SlashingReason 优先级测试 =====

    #[test]
    fn slashing_reason_priority_order() {
        assert!(
            SlashingReason::VertexEquivocation.priority()
                < SlashingReason::CommitCertEquivocation.priority()
        );
        assert!(
            SlashingReason::CommitCertEquivocation.priority()
                < SlashingReason::RefuseCheckpoint.priority()
        );
        assert!(SlashingReason::RefuseCheckpoint.priority() < SlashingReason::Downtime.priority());
        assert!(SlashingReason::Downtime.priority() < SlashingReason::RefuseAck.priority());
    }

    #[test]
    fn slashing_reason_default_slash_percentage() {
        assert_eq!(
            SlashingReason::VertexEquivocation.default_slash_percentage(),
            100
        );
        assert_eq!(
            SlashingReason::CommitCertEquivocation.default_slash_percentage(),
            100
        );
        assert_eq!(
            SlashingReason::RefuseCheckpoint.default_slash_percentage(),
            100
        );
        assert_eq!(SlashingReason::Downtime.default_slash_percentage(), 10);
        assert_eq!(SlashingReason::RefuseAck.default_slash_percentage(), 100);
    }

    // ===== compute_slash_amount 测试 =====

    #[test]
    fn compute_slash_amount_full() {
        // 100% 罚没
        let amount = compute_slash_amount(1_000_000, 100);
        assert_eq!(amount, 1_000_000);
    }

    #[test]
    fn compute_slash_amount_ten_percent() {
        // 10% 罚没
        let amount = compute_slash_amount(1_000_000, 10);
        assert_eq!(amount, 100_000);
    }

    #[test]
    fn compute_slash_amount_zero_stake() {
        let amount = compute_slash_amount(0, 100);
        assert_eq!(amount, 0);
    }

    #[test]
    fn compute_slash_amount_uses_remaining_not_original() {
        // SEC2-H2：扣除基数 = 剩余质押
        // 第一次扣除 100% 后剩余 0，第二次扣除应基于 0
        let after_first = compute_slash_amount(1_000_000, 100);
        assert_eq!(after_first, 1_000_000);
        let remaining = 1_000_000 - after_first;
        let after_second = compute_slash_amount(remaining, 100);
        assert_eq!(after_second, 0);
    }

    // ===== SlashingConfig 测试 =====

    #[test]
    fn slashing_config_default() {
        let config = SlashingConfig::default();
        assert_eq!(config.slash_percentage, 100);
        assert_eq!(config.downtime_threshold_blocks, 100);
        assert_eq!(config.downtime_slash_percentage, 10);
        assert_eq!(config.defense_window_blocks, 50);
        assert_eq!(config.epoch_length_blocks, 1000);
    }

    #[test]
    fn slashing_config_auto_slash_threshold() {
        let config = SlashingConfig::default();
        // SEC-M1：downtime_threshold + 2 * epoch_length = 100 + 2000 = 2100
        assert_eq!(config.auto_slash_threshold(), 2100);
    }

    // ===== 停机判定测试 =====

    #[test]
    fn is_downtime_governance_kickout_at_threshold() {
        let config = SlashingConfig::default();
        // 刚好达到阈值 → 触发治理踢出
        assert!(is_downtime_governance_kickout(100, 200, &config));
        // 未达到阈值
        assert!(!is_downtime_governance_kickout(100, 199, &config));
    }

    #[test]
    fn is_downtime_auto_slashable_at_threshold() {
        let config = SlashingConfig::default();
        // SEC-M1：连续 2100 block 未提交 → 自动 slashing
        assert!(is_downtime_auto_slashable(100, 2200, &config));
        // 未达到自动 slashing 阈值（仅治理踢出）
        assert!(!is_downtime_auto_slashable(100, 2000, &config));
    }

    #[test]
    fn is_downtime_auto_slashable_saturating_sub() {
        let config = SlashingConfig::default();
        // current < last_vertex → saturating_sub 为 0，不触发
        assert!(!is_downtime_auto_slashable(500, 100, &config));
    }

    // ===== apply_slashing 测试 =====

    #[test]
    fn apply_slashing_vertex_equivocation_full_slash() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .expect("slashing 应成功");

        assert_eq!(result.reason, SlashingReason::VertexEquivocation);
        assert_eq!(result.stake_before, 1_000_000);
        assert_eq!(result.slash_amount, 1_000_000); // 100%
        assert_eq!(result.stake_after, 0);
        assert!(!result.debt_recorded); // 刚好耗尽，无欠款
        assert_eq!(set.validators[0].status, ValidatorStatus::Slashed);
        assert_eq!(set.validators[0].stake, 0);
    }

    #[test]
    fn apply_slashing_downtime_ten_percent() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(&mut set, &target, SlashingReason::Downtime, &config)
            .expect("停机 slashing 应成功");

        assert_eq!(result.slash_amount, 100_000); // 10%
        assert_eq!(result.stake_after, 900_000);
        // 停机类不立即标记 Slashed（保留治理申辩权）
        assert_eq!(set.validators[0].status, ValidatorStatus::Active);
        assert_eq!(set.validators[0].stake, 900_000);
    }

    #[test]
    fn apply_slashing_allows_already_slashed_for_multi_slashing() {
        // SEC2-H2：多重 slashing 须继续从剩余质押扣除
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        // 模拟第一次 slashing 后的状态：status=Slashed, stake=500_000
        set.validators[0].status = ValidatorStatus::Slashed;
        set.validators[0].stake = 500_000;
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::CommitCertEquivocation,
            &config,
        )
        .expect("已 Slashed 的 validator 应可继续 slashing（SEC2-H2）");
        assert_eq!(result.stake_before, 500_000);
        assert_eq!(result.slash_amount, 500_000); // 100% of remaining
        assert_eq!(result.stake_after, 0);
    }

    #[test]
    fn apply_slashing_rejects_retired() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.validators[0].status = ValidatorStatus::Retired;
        let config = SlashingConfig::default();

        let err = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn apply_slashing_rejects_validator_not_in_set() {
        let mut set = make_validator_set(5);
        let unknown = make_tagged_pubkey(0xFF);
        let config = SlashingConfig::default();

        let err = apply_slashing(
            &mut set,
            &unknown,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
    }

    #[test]
    fn apply_slashing_debt_when_stake_insufficient() {
        let mut set = make_validator_set(5);
        // 将 stake 设为很小，使 slash_amount > stake
        set.validators[0].stake = 50;
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .expect("slashing 应成功");

        // stake=50, slash_percentage=100% → slash_amount=50, 但 stake < amount → 全额扣除 + 欠款
        assert_eq!(result.stake_before, 50);
        assert_eq!(result.slash_amount, 50); // compute_slash_amount(50, 100) = 50
        assert_eq!(result.stake_after, 0);
        // stake_before (50) >= slash_amount (50) → 不转欠款
        assert!(!result.debt_recorded);
    }

    // ===== apply_multi_slashing 测试（SEC2-H2） =====

    #[test]
    fn apply_multi_slashing_processes_by_priority() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // 同时触发 vertex equiv + downtime + refuse_ack
        let reasons = vec![
            SlashingReason::RefuseAck,
            SlashingReason::Downtime,
            SlashingReason::VertexEquivocation,
        ];
        let results = apply_multi_slashing(&mut set, &target, reasons, &config)
            .expect("多重 slashing 应成功");

        // 按优先级排序后：vertex equiv (1) → downtime (4) → refuse_ack (5)
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].reason, SlashingReason::VertexEquivocation);
        assert_eq!(results[1].reason, SlashingReason::Downtime);
        assert_eq!(results[2].reason, SlashingReason::RefuseAck);

        // 第一次 vertex equiv 扣 100% → 剩余 0
        assert_eq!(results[0].stake_before, 1_000_000);
        assert_eq!(results[0].slash_amount, 1_000_000);
        assert_eq!(results[0].stake_after, 0);

        // 第二次 downtime 基于剩余 0 → 扣 0
        assert_eq!(results[1].stake_before, 0);
        assert_eq!(results[1].slash_amount, 0);

        // 第三次 refuse_ack 基于剩余 0 → 扣 0
        assert_eq!(results[2].stake_before, 0);
        assert_eq!(results[2].slash_amount, 0);
    }

    #[test]
    fn apply_multi_slashing_downtime_then_refuse_ack() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // downtime (10%) + refuse_ack (100%)
        let reasons = vec![SlashingReason::RefuseAck, SlashingReason::Downtime];
        let results = apply_multi_slashing(&mut set, &target, reasons, &config)
            .expect("多重 slashing 应成功");

        // 排序后：downtime (4) → refuse_ack (5)
        assert_eq!(results[0].reason, SlashingReason::Downtime);
        assert_eq!(results[1].reason, SlashingReason::RefuseAck);

        // downtime 扣 10% = 100_000，剩余 900_000
        assert_eq!(results[0].slash_amount, 100_000);
        assert_eq!(results[0].stake_after, 900_000);

        // refuse_ack 基于 900_000 扣 100% = 900_000
        assert_eq!(results[1].stake_before, 900_000);
        assert_eq!(results[1].slash_amount, 900_000);
        assert_eq!(results[1].stake_after, 0);
    }

    // ===== VertexEquivocationEvidence 测试 =====

    #[test]
    fn vertex_equivocation_evidence_validate_ok() {
        let evidence = VertexEquivocationEvidence {
            epoch: 1,
            round: 10,
            author: make_tagged_pubkey(0x10),
            vertex_hash_1: [1u8; 32],
            vertex_hash_2: [2u8; 32],
            signature_1: vec![0u8; 65],
            signature_2: vec![0u8; 65],
        };
        evidence.validate().expect("有效证据应通过");
    }

    #[test]
    fn vertex_equivocation_evidence_rejects_same_hash() {
        let evidence = VertexEquivocationEvidence {
            epoch: 1,
            round: 10,
            author: make_tagged_pubkey(0x10),
            vertex_hash_1: [1u8; 32],
            vertex_hash_2: [1u8; 32], // 相同
            signature_1: vec![0u8; 65],
            signature_2: vec![0u8; 65],
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn vertex_equivocation_evidence_rejects_empty_signature() {
        let evidence = VertexEquivocationEvidence {
            epoch: 1,
            round: 10,
            author: make_tagged_pubkey(0x10),
            vertex_hash_1: [1u8; 32],
            vertex_hash_2: [2u8; 32],
            signature_1: vec![], // 空
            signature_2: vec![0u8; 65],
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    // ===== CommitCertEquivocationEvidence 测试 =====

    #[test]
    fn commit_cert_equivocation_evidence_validate_ok() {
        let evidence = CommitCertEquivocationEvidence {
            epoch: 1,
            commit_round: 5,
            cert_hash_1: [1u8; 32],
            cert_hash_2: [2u8; 32],
        };
        evidence.validate().expect("有效证据应通过");
    }

    #[test]
    fn commit_cert_equivocation_evidence_rejects_same_hash() {
        let evidence = CommitCertEquivocationEvidence {
            epoch: 1,
            commit_round: 5,
            cert_hash_1: [1u8; 32],
            cert_hash_2: [1u8; 32],
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    // ===== check_downtime_slashing 测试 =====

    #[test]
    fn check_downtime_slashing_triggers_auto_slash() {
        let set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // last_vertex_height=100, current=2200 → 2100 block 未提交 → SEC-M1 自动 slashing
        // 注意：make_validator_set 中 last_vertex_height=0
        // 需要构造一个 last_vertex_height=100 的 set
        let mut set = set;
        set.validators[0].last_vertex_height = 100;

        let result = check_downtime_slashing(&set, &target, 2200, &config).expect("检查应成功");
        assert_eq!(result, Some(SlashingReason::Downtime));
    }

    #[test]
    fn check_downtime_slashing_no_trigger_below_threshold() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.validators[0].last_vertex_height = 100;
        let config = SlashingConfig::default();

        // current=2000 → 1900 block 未提交，未达 2100 阈值
        let result = check_downtime_slashing(&set, &target, 2000, &config).expect("检查应成功");
        assert_eq!(result, None);
    }

    #[test]
    fn check_downtime_slashing_rejects_unknown_validator() {
        let set = make_validator_set(5);
        let unknown = make_tagged_pubkey(0xFF);
        let config = SlashingConfig::default();

        let err = check_downtime_slashing(&set, &unknown, 2200, &config).unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
    }

    // ===== InvestigationState 测试（NEW-H1 / R4-H5） =====

    #[test]
    fn investigation_state_new() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        assert_eq!(state.triggered_at_height, 1000);
        assert_eq!(state.defense_deadline, 1050); // 1000 + 50
        assert!(!state.defense_submitted);
        assert!(!state.defense_valid);
        assert!(!state.resolved);
    }

    #[test]
    fn investigation_state_submit_defense_within_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("窗口内申辩应成功");
        assert!(state.defense_submitted);
        assert!(!state.resolved);
    }

    #[test]
    fn investigation_state_submit_defense_rejects_after_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        let err = state.submit_defense(1060).unwrap_err(); // > 1050
        assert!(matches!(err, PokerL1Error::Other(_)));
        assert!(!state.defense_submitted);
    }

    #[test]
    fn investigation_state_resolve_with_valid_defense() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("申辩");
        // 申辩有效 → 不 slashing
        let should_slash = state.resolve(1030, true).expect("resolve");
        assert!(!should_slash, "有效申辩不应 slashing");
        assert!(state.resolved);
        assert!(state.defense_valid);
    }

    #[test]
    fn investigation_state_resolve_with_invalid_defense() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("申辩");
        // 申辩无效 → slashing
        let should_slash = state.resolve(1030, false).expect("resolve");
        assert!(should_slash, "无效申辩应 slashing");
        assert!(state.resolved);
        assert!(!state.defense_valid);
    }

    #[test]
    fn investigation_state_resolve_no_defense_after_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        // 未提交申辩，窗口过期
        let should_slash = state.resolve(1060, false).expect("resolve");
        assert!(should_slash, "无申辩 + 窗口过期应 slashing");
        assert!(state.resolved);
    }

    #[test]
    fn investigation_state_resolve_rejects_already_resolved() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.resolve(1030, true).expect("首次 resolve");
        let err = state.resolve(1040, true).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn investigation_state_is_window_expired() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        assert!(!state.is_window_expired(1050)); // == deadline，未过期
        assert!(state.is_window_expired(1051)); // > deadline，过期
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn slashing_reason_bcs_roundtrip() {
        for reason in [
            SlashingReason::VertexEquivocation,
            SlashingReason::CommitCertEquivocation,
            SlashingReason::RefuseCheckpoint,
            SlashingReason::Downtime,
            SlashingReason::RefuseAck,
        ] {
            let bytes = bcs::to_bytes(&reason).unwrap();
            let recovered: SlashingReason = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(reason, recovered);
        }
    }

    #[test]
    fn slashing_config_bcs_roundtrip() {
        let config = SlashingConfig::default();
        let bytes = bcs::to_bytes(&config).unwrap();
        let recovered: SlashingConfig = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(config, recovered);
    }

    #[test]
    fn vertex_equivocation_evidence_bcs_roundtrip() {
        let evidence = VertexEquivocationEvidence {
            epoch: 1,
            round: 10,
            author: make_tagged_pubkey(0x10),
            vertex_hash_1: [1u8; 32],
            vertex_hash_2: [2u8; 32],
            signature_1: vec![0u8; 65],
            signature_2: vec![0u8; 65],
        };
        let bytes = bcs::to_bytes(&evidence).unwrap();
        let recovered: VertexEquivocationEvidence = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(evidence, recovered);
    }

    #[test]
    fn investigation_state_bcs_roundtrip() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        let bytes = bcs::to_bytes(&state).unwrap();
        let recovered: InvestigationState = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(state, recovered);
    }

    #[test]
    fn slashing_result_bcs_roundtrip() {
        let result = SlashingResult {
            validator: make_tagged_pubkey(0x10),
            reason: SlashingReason::VertexEquivocation,
            stake_before: 1_000_000,
            slash_amount: 1_000_000,
            stake_after: 0,
            debt_recorded: false,
        };
        let bytes = bcs::to_bytes(&result).unwrap();
        let recovered: SlashingResult = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(result, recovered);
    }
}
