//! P0-3（plan-appchain §5.2-3）：REAL 结算出证策略——fail-closed 配置面。
//!
//! ## 语义分层（三层门，全部默认收紧）
//!
//! 1. **引擎层**：[`crate::pipeline::ValidationEngine`]（host 签名引擎）对
//!    REAL 结算一律返回 [`AppchainError::RealRequiresStarkProof`]——host
//!    attestation 天然不能给真金出证，与管道配置无关。
//! 2. **管道提交层**（单实例单引擎 → 拒绝路径尽早）：REAL 结算 op 在
//!    [`crate::pipeline::ProofPipeline::submit`] 即做准入——模式放行 +
//!    引擎具备 STARK 出证能力（[`STARK_ENGINE_PREFIX`] 前缀）+
//!    StarkRequired 已钉 verifier key + hand_proof 存在。
//! 3. **批次/水位层**：组批出队前对 REAL op 的 bundle 复查允许集与
//!    attestor 钉扎；违反则 completion 原地保留——该 op **不得标记已证明**、
//!    水位不推进，并计 `real_settlement_rejected_total` 告警指标。
//!
//! ## 模式
//!
//! | [`RealMode`]        | 允许出证 REAL 的引擎                | verifier key |
//! |---------------------|-------------------------------------|--------------|
//! | `Disabled`          | 无（拒绝一切 REAL 出证）            | —            |
//! | `HostAttestation`   | `host-validate-v2`、`texas-air-*`   | 可选         |
//! | `StarkRequired`（默认） | `texas-air-*`（真实 STARK 验证路径） | **必须**     |
//!
//! 默认值 = `StarkRequired` 且未钉 key：**REAL 结算全部拒绝**（fail-closed
//! ——生产必须显式注入固定 attestor 公钥后才放行 REAL 出证）。

use crate::note::AssetClass;
use crate::settlement::SettlementRecord;

/// texas-air STARK 引擎名前缀（`StarkRequired` 允许集判定；真实证明必须
/// 经过该族引擎的 stwo 验证路径）。
pub const STARK_ENGINE_PREFIX: &str = "texas-air-";

/// host attestation 引擎名（`HostAttestation` 模式的最低允许档）。
pub const HOST_ATTESTATION_ENGINE: &str = "host-validate-v2";

/// REAL 结算的证明等级要求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealMode {
    /// 拒绝一切 REAL 结算出证（维护/熔断档）。
    Disabled,
    /// testnet/PLAY/内测语义：允许 host attestation 档出证
    /// （[`HOST_ATTESTATION_ENGINE`]）；STARK 引擎（更强）同样放行。
    HostAttestation,
    /// 生产语义（**默认**）：REAL 出证必须来自 STARK 引擎
    /// （[`STARK_ENGINE_PREFIX`] 前缀），且 attestor 公钥钉扎到配置的
    /// 固定 verifier key。
    StarkRequired,
}

impl RealMode {
    /// 引擎是否在本模式的 REAL 出证允许集内。
    #[must_use]
    pub fn engine_allowed(self, engine: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::HostAttestation => {
                engine == HOST_ATTESTATION_ENGINE || engine.starts_with(STARK_ENGINE_PREFIX)
            }
            Self::StarkRequired => engine.starts_with(STARK_ENGINE_PREFIX),
        }
    }
}

impl Default for RealMode {
    /// 默认 = [`RealMode::StarkRequired`]（fail-closed）。
    fn default() -> Self {
        Self::StarkRequired
    }
}

/// REAL 结算出证策略。
///
/// 默认构造 = `StarkRequired` + 未钉 key：REAL 结算全部拒绝；生产配置用
/// [`RealSettlementPolicy::stark_required`] 注入固定 attestor 公钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealSettlementPolicy {
    /// 证明等级模式（默认 [`RealMode::StarkRequired`]）。
    pub mode: RealMode,
    /// 固定 attestor 公钥（生产注入；`StarkRequired` 下必须 Some，否则
    /// REAL 结算全部拒绝）。
    pub verifier_key: Option<[u8; 32]>,
}

impl Default for RealSettlementPolicy {
    /// 默认 = fail-closed：`StarkRequired` + 未钉 key（REAL 全拒）。
    fn default() -> Self {
        Self {
            mode: RealMode::StarkRequired,
            verifier_key: None,
        }
    }
}

impl RealSettlementPolicy {
    /// 生产配置：`StarkRequired` + 固定 verifier key。
    #[must_use]
    pub fn stark_required(verifier_key: [u8; 32]) -> Self {
        Self {
            mode: RealMode::StarkRequired,
            verifier_key: Some(verifier_key),
        }
    }

    /// testnet/内测配置：`HostAttestation`（不要求钉扎）。
    #[must_use]
    pub fn host_attestation() -> Self {
        Self {
            mode: RealMode::HostAttestation,
            verifier_key: None,
        }
    }

    /// 引擎是否在本策略的 REAL 出证允许集内。
    #[must_use]
    pub fn engine_allowed(&self, engine: &str) -> bool {
        self.mode.engine_allowed(engine)
    }

    /// 出证前提配置是否完备（`StarkRequired` 必须已钉 verifier key）。
    #[must_use]
    pub fn config_complete(&self) -> bool {
        self.mode != RealMode::StarkRequired || self.verifier_key.is_some()
    }

    /// bundle 级 attestor 钉扎检查（`StarkRequired`：必须等于固定
    /// verifier key；未钉 key 时同样不放行——fail-closed）。
    #[must_use]
    pub fn attestor_pinned(&self, attestor_public: &[u8; 32]) -> bool {
        match (self.mode, self.verifier_key) {
            (RealMode::StarkRequired, Some(k)) => k == *attestor_public,
            (RealMode::StarkRequired, None) => false,
            _ => true,
        }
    }
}

/// 结算是否为 REAL 类（单类语义：首个输入的资产类即结算类；空输入返回
/// false——该记录由 `validate_settlement` 的非空检查独立拒绝）。
#[must_use]
pub fn is_real_settlement(record: &SettlementRecord) -> bool {
    crate::settlement::settlement_input_class(record) == Some(AssetClass::Real)
}

/// 提现 provenance：被提现 note 的资产类与其铸出来源 op
/// （`LedgerState.note_origins`——消费后保留，WAL 重放可重建）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalProvenance {
    /// 被提现 note 的资产类（REAL 走 finality 门，PLAY 豁免）。
    pub asset_class: AssetClass,
    /// note 铸出时的帧链 op 序号。
    pub source_op_index: u64,
}

/// finality 证据快照（sequencer 侧导出，供托管账提现申请判定）。
///
/// 连续前缀语义下 `proven_watermark >= op` 等价于「该 op 已证明」；
/// `batch_covered_through = Some(t)`（t ≥ op）表示该 op 所属批次根已被
/// 记录（§5.4 v1 finality 定义）。批次侧用 [`Option`] 而非裸数值：op 0
/// 与「尚无任何批次根」在裸数值下都是 0，会把未证明的 op 0 误放行
///（fail-closed 要求 None 必拒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FinalityEvidence {
    /// 当前 proven 水位（最大连续前缀）。
    pub proven_watermark: u64,
    /// 已记录批次根覆盖到的最大 op（None = 尚无批次根记录）。
    pub batch_covered_through: Option<u64>,
}

impl FinalityEvidence {
    /// op 是否已过 v1 finality 门（水位覆盖 + 批次根覆盖）。
    #[must_use]
    pub fn covers(&self, op_index: u64) -> bool {
        self.proven_watermark >= op_index
            && self.batch_covered_through.is_some_and(|t| t >= op_index)
    }
}
