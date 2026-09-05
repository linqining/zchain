//! 统一错误类型。stable category 纪律：外部输入边界的每个拒绝路径
//! 都有唯一变体（延续 PERFORMANCE_FOLLOWUPS #24⑤ 的错误分类方向）。

use thiserror::Error;

/// poker-appchain 统一错误。
#[derive(Debug, Error)]
pub enum AppchainError {
    /// note 金额溢出或非法（0 面额）。
    #[error("invalid note amount: {0}")]
    InvalidAmount(u64),
    /// 资产类不匹配（REAL/PLAY 混转）。
    #[error("asset class mismatch: {0} vs {1}")]
    AssetClassMismatch(&'static str, &'static str),
    /// nullifier 已存在（双花）。
    #[error("double spend: nullifier already spent")]
    DoubleSpend,
    /// note 不存在或包含证明失败。
    #[error("note not found or inclusion proof invalid")]
    NoteNotFound,
    /// P 层签名缺失或无效。
    #[error("owner signature invalid or missing")]
    BadSignature,
    /// 结算守恒失败：Σ输入 ≠ Σ输出 + 抽取。
    #[error("conservation violated: inputs={inputs} outputs={outputs} rake={rake}")]
    ConservationViolated {
        /// 输入面额总和。
        inputs: u128,
        /// 输出面额总和。
        outputs: u128,
        /// 抽取总额。
        rake: u128,
    },
    /// 费率与 policy_commitment 不一致（少抽/多抽/换策略）。
    #[error("fee policy mismatch: expected rake {expected}, got {got}")]
    FeeMismatch {
        /// 按策略应抽取的数额。
        expected: u128,
        /// witness 声称的抽取数额。
        got: u128,
    },
    /// 策略未注册或已被冻结后篡改。
    #[error("fee policy not registered for table {0}")]
    PolicyNotRegistered(u64),
    /// 结算重放（hand_binding 已结算）。
    #[error("settlement replay: hand binding already settled")]
    SettlementReplay,
    /// 桌未开放或已关闭。
    #[error("table {0} not open")]
    TableNotOpen(u64),
    /// 桌准入拒绝（note 未证明 / 桌满 / 限流）。
    #[error("admission rejected: {0}")]
    AdmissionRejected(&'static str),
    /// 限流触发。
    #[error("rate limited for principal {}", hex::encode(.0))]
    RateLimited([u8; 32]),
    /// 软确认链断裂（prev_hash 不接续 / index 不连续）。
    #[error("soft confirm chain broken at index {0}")]
    ChainBroken(u64),
    /// 软确认帧签名无效。
    #[error("soft confirm frame signature invalid")]
    BadFrameSignature,
    /// WAL 损坏或不可重放。
    #[error("wal corrupted: {0}")]
    WalCorrupted(&'static str),
    /// 出入金对账差异。
    #[error("reconciliation mismatch: issued={issued} reserved={reserved}")]
    ReconciliationMismatch {
        /// 已发行 REAL note 总额。
        issued: u128,
        /// 链上储备 + 浮存。
        reserved: u128,
    },
    /// 提现幂等冲突或重复申请。
    #[error("withdrawal idempotency conflict: {0}")]
    WithdrawalConflict(String),
    /// 编解码失败。
    #[error("codec error: {0}")]
    Codec(String),
    /// watcher 检测到分叉/不一致。
    #[error("fork detected at index {0}")]
    ForkDetected(u64),
    /// 参数越界（bps > 10000 等）。
    #[error("out of range: {0}")]
    OutOfRange(&'static str),
}

/// 带 stable category 的 Result 别名。
pub type AppchainResult<T> = Result<T, AppchainError>;
