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
    /// 资产不匹配（TE-M1：v2 AssetId 粒度——domain 或 token_id 任一不同
    /// 即拒绝；v1 路径继续走 [`AppchainError::AssetClassMismatch`]，其
    /// 语义冻结不动）。
    #[error("asset mismatch: expected {expected}, got {got}")]
    AssetMismatch {
        /// 期望资产（首输入 / 基准资产）。
        expected: crate::asset_id::AssetId,
        /// 实际资产（越界方）。
        got: crate::asset_id::AssetId,
    },
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
    /// REAL 结算在当前引擎/策略下不可出证（P0-3 fail-closed）：host 签名
    /// 引擎天然不能给 REAL 出证；REAL 模式 Disabled / 引擎不在允许集 /
    /// StarkRequired 未配置 verifier key 时同样拒绝（见 `real_policy`）。
    #[error("real settlement requires a STARK proof (real settlement policy forbids this proving path)")]
    RealRequiresStarkProof,
    /// attestation 公钥与固定 verifier key 不一致（StarkRequired 钉扎检查：
    /// 生产注入固定 attestor 公钥，非钉扎签名者的 bundle 一律拒绝）。
    #[error("attestor public key mismatch against pinned verifier key")]
    VerifierKeyMismatch,
    /// 提现未达 finality 门槛（§5.4 配套）：REAL note 的来源 op 未被证明
    /// 水位覆盖，或其所属批次根尚未记录（托管打款侧拒绝）。
    #[error("withdrawal not finalized: source op {op_index} not covered by a proven batch (proven watermark {watermark})")]
    WithdrawalNotFinalized {
        /// 被提现 note 的铸出来源 op 序号。
        op_index: u64,
        /// 当前 proven 水位。
        watermark: u64,
    },
    /// withdrawal root 未 finalized（M7-ACC-5，`withdrawal_root`）：claim 引用
    /// 的根摘要不在 finalized 台账——未知摘要、根尚未 `mark_finalized`、或叶
    /// 的 checkpoint_height 与注册记录不一致（摘要重绑定失败），一律
    /// fail-closed 拒绝。
    #[error("withdrawal root not finalized: digest={digest_hex}")]
    RootNotFinalized {
        /// 被引用的根摘要（hex 编码 32B）。
        digest_hex: String,
    },
    /// 提现已领取（M7-ACC-5 防重放，`withdrawal_root`）：request_id 已在
    /// claim 台账（Vault 必须自检"未领取"，跨实例重载后仍拒绝）。
    #[error("withdrawal already claimed: request_id={request_id_hex}")]
    AlreadyClaimed {
        /// 重复领取的请求 id（hex 编码 32B）。
        request_id_hex: String,
    },
    /// claim 的 Merkle 包含证明无效（`withdrawal_root`）：索引越界、证明
    /// 长度超限或路径校验失败——含叶任一字段被篡改的情形。
    #[error("withdrawal claim merkle proof invalid: {0}")]
    WithdrawalProofInvalid(&'static str),
    /// TE-M3：GTS 游戏币注册表拒绝（稳定类别）：token_id 0 遗留 PLAY 保留
    /// 位、零 issuer、anchor 非 REAL 域已注册 token、同 token_id 重注册
    /// （genesis 冻结，重定价 = 发新 token）、未注册 token 的发行/销毁。
    #[error("game token registry rejected: {0}")]
    GameRegistryRejected(&'static str),
    /// TE-M3：发行价带越界（INV-TE-4 validation 层，双层强制的第 1 层；
    /// 第 2 层 = rate 进 genesis 摘要）。`R ∉ [R_min, R_max]` 一律拒。
    #[error("issuance rate out of band: rate={rate}, min={min}, max={max}")]
    RateOutOfBand {
        /// 被拒比率。
        rate: u64,
        /// 价带下界。
        min: u64,
        /// 价带上界。
        max: u64,
    },
    /// TE-M3：游戏币供给超限（`Σminted + 本次铸造 > max_supply`；0 上限 =
    /// 不限，不触发本错误）。
    #[error("game token supply cap exceeded: token={token_id}, minted={minted}, requested={requested}, cap={cap}")]
    SupplyCapExceeded {
        /// 目标 token。
        token_id: u32,
        /// 已铸总量。
        minted: u128,
        /// 本次申请量。
        requested: u128,
        /// 供给上限。
        cap: u64,
    },
    /// TE-M6：GasPolicy 绑定拒绝（稳定类别）：Paid 模式 token 桌绑定
    /// （TE-D7：双重收费 v1 禁止）、未注册/遗留 PLAY token、计价资产非
    /// REAL 域注册 token、fee/k 结构非法、成本覆盖不足
    /// （`fee_per_hand < min_coverage_k·c_hand`）、已绑定桌重绑
    /// （绑定即冻结）。
    #[error("gas policy rejected: {0}")]
    GasPolicyRejected(&'static str),
    /// TE-M6：gas credit 余额不足（INV-TE-8 消耗前置校验拒绝；计量账
    /// 恒等 `credit = Σpurchased − Σconsumed ≥ 0` 由此保持——扣减从不
    /// 穿透零点，不足整笔拒绝零状态变更）。
    #[error("gas credit insufficient: asset={asset}, balance={balance}, required={required}")]
    GasCreditInsufficient {
        /// 计价资产（GasPolicy 绑定的 pricing_asset_id）。
        asset: crate::asset_id::AssetId,
        /// 当前余额。
        balance: u64,
        /// 本次消耗要求（fee_per_hand）。
        required: u64,
    },
}

/// 带 stable category 的 Result 别名。
pub type AppchainResult<T> = Result<T, AppchainError>;
