//! 统一错误类型。stable category 纪律：钱包边界的每个拒绝路径都有唯一变体
//! （fail-closed：任何"未覆盖语义"都落到显式拒绝，绝不静默放行）。

use thiserror::Error;

/// 会话密钥准入拒绝原因（WALLET-ACC-3/3a：每类负例一个独立变体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRejectReason {
    /// binding 已撤销（撤销粘滞，不可恢复）。
    Revoked,
    /// 当前时间早于 valid_after。
    NotYetValid,
    /// 当前时间 ≥ valid_until（或 binding 状态机判为过期）。
    Expired,
    /// 请求 scope 不在 allowed_scopes 内。
    ScopeNotAllowed,
    /// 桌不在白名单内（或白名单模式下缺桌 ID）。
    TableNotAllowed,
    /// 单笔金额超过 per_tx_limit。
    OverPerTxLimit,
    /// 当日累计超过 daily_limit（binding 状态机判为 exhausted）。
    DailyLimitExhausted,
    /// 请求 chain_id 与授权 chain_id 不一致（换网防重放）。
    ChainMismatch,
    /// 授权不存在。
    UnknownBinding,
    /// 高风险操作（轮换/恢复/提额）不允许只靠会话密钥，必须主 owner 二次授权。
    OwnerRequired,
}

/// poker-wallet 统一错误。
#[derive(Debug, Error)]
pub enum WalletError {
    /// keystore/backup 口令错误或信封损坏（AEAD 认证失败，fail-closed）。
    #[error("keystore authentication failed (wrong passphrase or corrupted envelope)")]
    BadPassword,
    /// 完整性校验失败（字节篡改/索引不一致）。
    #[error("integrity check failed: {0}")]
    Tampered(&'static str),
    /// 备份/keystore 版本超出支持范围（未来版本 fail-closed）。
    #[error("unsupported format version: found {found}, max supported {max_supported}")]
    UnsupportedVersion {
        /// 实际遇到的版本号。
        found: u16,
        /// 本构建支持的最高版本号。
        max_supported: u16,
    },
    /// 未知域标签（M6-ACC-7：`zchain` 之外的 domain 一律拒绝）。
    #[error("unknown domain tag: {0}")]
    UnknownDomainTag(String),
    /// 未知 ABI 版本（M6-ACC-7）。
    #[error("unknown ABI version: {0}")]
    UnknownAbiVersion(u32),
    /// 金额溢出或守恒预检失败（M6-ACC-7）。
    #[error("amount overflow or conservation pre-check failed: {0}")]
    AmountOverflow(&'static str),
    /// 任意 bytes 签名请求被拒绝（无 signBytes 默认能力，WALLET-ACC-3）。
    #[error("raw bytes signing is rejected: structured requests only")]
    RawBytesRejected,
    /// 会话密钥准入拒绝（WALLET-ACC-3/3a）。
    #[error("session key admission rejected: {0:?}")]
    SessionRejected(SessionRejectReason),
    /// 请求已过期。
    #[error("request expired: expiry {expiry} < now {now}")]
    Expired {
        /// 请求过期时间（unix 秒）。
        expiry: u64,
        /// 当前时间（unix 秒）。
        now: u64,
    },
    /// 请求 nonce 重放。
    #[error("nonce replay detected: chain={chain} nonce={nonce}")]
    NonceReplay {
        /// 链 ID。
        chain: String,
        /// 被重放的 nonce。
        nonce: u64,
    },
    /// note 不存在（按承诺/nullifier 查找失败）。
    #[error("note not found: {0}")]
    NoteNotFound(String),
    /// 资产类不匹配（REAL/PLAY 混用，物理分库越界）。
    #[error("asset class mismatch: {0}")]
    AssetClassMismatch(String),
    /// verifier 拒绝（settlement/软确认帧/批次根校验失败，附原因）。
    #[error("verifier rejected: {0}")]
    VerifierRejected(String),
    /// 编解码失败。
    #[error("codec error: {0}")]
    Codec(String),
    /// 参数非法。
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// 密钥材料非法（坏长度/非规范/超出曲线阶）。
    #[error("bad key material: {0}")]
    BadKeyMaterial(&'static str),
    /// 同步检测到重组（checkpoint 哈希不接续）。
    #[error("reorg detected at index {index}")]
    ReorgDetected {
        /// 检测到分叉的帧序号。
        index: u64,
    },
    /// vault adapter 拒绝（能力不足/状态未就绪）。
    #[error("vault adapter rejected: {0}")]
    VaultRejected(&'static str),
    /// IO 失败（CLI 文件读写）。
    #[error("io error: {0}")]
    Io(String),
}

/// 带 stable category 的 Result 别名。
pub type WalletResult<T> = Result<T, WalletError>;
