//! 统一错误类型。覆盖 Phase 1 所有错误场景，便于 validator / RPC 返回精确错误码。
//!
//! 安全路径相关错误（签名 / nonce / chain_id / ObjectID）须包含足够上下文以供审计追溯。

use thiserror::Error;

/// 库统一错误类型。
///
/// 注意：enum 变体的命名字段（如 `tag` / `actual` / `expected` / `tx` / `account` 等）
/// 名称已自描述，且每个变体均有文档注释说明语义，故此处允许字段缺文档。
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum PokerL1Error {
    // ===== 签名相关（Task 5 / SEC-M9 / NEW-L1 / SEC2-L1） =====
    /// tagged pubkey tag 字节未识别。SEC-M9：未知 tag 返回 UnknownScheme，禁止隐式 fallback。
    #[error("unknown signature scheme tag: 0x{tag:02x}")]
    UnknownScheme { tag: u8 },
    /// tagged pubkey 长度不匹配该 tag 的预期。
    #[error("tagged pubkey length {actual} != expected {expected} for tag 0x{tag:02x}")]
    InvalidPubkeyLength { tag: u8, actual: usize, expected: usize },
    /// secp256k1 high-s 签名（BIP-62 / NEW-L1）— 拒绝，不规范化转换。
    #[error("secp256k1 signature s > n/2 (high-s rejected per BIP-62)")]
    InvalidSignatureLowS,
    /// ed25519 签名 R 或 S 非规范化编码（SEC2-L1）。
    #[error("ed25519 signature non-canonical encoding")]
    InvalidSignatureCanonical,
    /// 签名验证失败（恢复的 pubkey 与 tagged pubkey 不匹配，或底层 verify 返回 false）。
    #[error("signature verification failed")]
    InvalidSignature,
    /// 签名字节长度错误。
    #[error("signature length {actual} != expected {expected}")]
    InvalidSignatureLength { actual: usize, expected: usize },
    /// tagged pubkey 与签名 scheme tag 不一致（pubkey 是 secp256k1，sig 却声称 ed25519）。
    #[error("curve tag mismatch: pubkey tag 0x{pub_tag:02x} vs sig tag 0x{sig_tag:02x}")]
    CurveMismatch { pub_tag: u8, sig_tag: u8 },
    /// secp256k1 底层错误（解析失败等）。
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    // ===== 对象模型相关（Task 2 / NEW-L4 / IMPL-SEC-3） =====
    /// ObjectID 已存在（NEW-L4：创建时校验，冲突返回 ObjectIDCollision）。
    #[error("ObjectID collision: {0:?}")]
    ObjectIDCollision(crate::object_model::ObjectID),
    /// ObjectID 不存在（读 / 更新时）。
    #[error("object not found: {0:?}")]
    ObjectNotFound(crate::object_model::ObjectID),
    /// 操作方非对象 owner。
    #[error("not owner of object {0:?}")]
    NotOwner(crate::object_model::ObjectID),
    /// 试图修改 Immutable 对象（结算后冻结）。
    #[error("object is immutable: {0:?}")]
    ObjectImmutable(crate::object_model::ObjectID),
    /// 对象版本号不匹配（optimistic concurrency）。
    #[error("object version mismatch: expected {expected}, got {actual}")]
    ObjectVersionMismatch { expected: u64, actual: u64 },

    // ===== 账户 / 重放保护相关（Task 6 / M10 / NEW-M9 / SEC-H7） =====
    /// chain_id 不匹配（跨链重放）。
    #[error("wrong chain_id: tx={tx}, network={network}")]
    WrongChainId { tx: u64, network: u64 },
    /// account nonce 不匹配。
    #[error("nonce too low: tx={tx}, account={account}")]
    NonceTooLow { tx: u64, account: u64 },
    /// account nonce 跳号（高于当前 +1）。
    #[error("nonce too high: tx={tx}, account={account}")]
    NonceTooHigh { tx: u64, account: u64 },
    /// GameTurn nonce 不匹配（per-game per-player）。
    #[error("gameturn_nonce mismatch: tx={tx}, game={game}")]
    GameTurnNonceMismatch { tx: u64, game: u64 },
    /// 正常 GameTurn tx 设置了 is_fallback=true（SEC-H7：validator 拒绝）。
    #[error("normal GameTurn tx must not set is_fallback=true")]
    InvalidFallbackFlag,
    /// 余额不足支付 gas。
    #[error("insufficient balance: needed={needed}, has={has}")]
    InsufficientBalance { needed: u64, has: u64 },
    /// 实际 gas 消耗超过 tx 声明的预算（VM 执行后校验）。
    #[error("gas used {used} exceeds tx budget {budget}")]
    GasExceedsBudget { used: u64, budget: u64 },

    // ===== 存储相关（Task 4） =====
    /// RocksDB 后端错误。
    #[error("rocksdb error: {0}")]
    Rocksdb(String),
    /// 序列化 / 反序列化错误。
    #[error("serialization error: {0}")]
    Serialization(String),
    /// 区块不存在（按 hash / height 查询）。
    #[error("block not found")]
    BlockNotFound,
    /// DAG vertex 不存在。
    #[error("dag vertex not found")]
    DagVertexNotFound,
    /// 输入超长（syscall / 字段长度限制）。
    #[error("input too long: {actual} > {limit}")]
    InputTooLong { actual: usize, limit: usize },

    // ===== 通用 =====
    /// 其他错误（带字符串上下文）。
    #[error("{0}")]
    Other(String),
}

/// 库统一 Result 别名。
pub type PokerL1Result<T> = Result<T, PokerL1Error>;

impl From<bcs::Error> for PokerL1Error {
    fn from(e: bcs::Error) -> Self {
        Self::Serialization(format!("bcs: {e}"))
    }
}

impl From<serde_json::Error> for PokerL1Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(format!("json: {e}"))
    }
}

impl From<blake2::digest::InvalidLength> for PokerL1Error {
    fn from(e: blake2::digest::InvalidLength) -> Self {
        Self::Serialization(format!("blake2 invalid length: {e}"))
    }
}
