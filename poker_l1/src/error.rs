//! 统一错误类型。覆盖 Phase 1 + Phase 2 所有错误场景，便于 validator / RPC 返回精确错误码。
//!
//! 安全路径相关错误（签名 / nonce / chain_id / ObjectID / 轮转 / assigned_validator）
//! 须包含足够上下文以供审计追溯。

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

    // ===== Phase 2: 路由 / 轮转 / 游戏分配（Task 7 / 8 / 12） =====
    /// tx 通道与路由提示不匹配（SubTask 7.2：GameTurn+CheckpointAnchor 应路由到 assigned_validator）。
    #[error("wrong lane: lane={lane:?}, route={route:?}, expected assigned_validator for GameTurn/CheckpointAnchor")]
    WrongLane {
        /// tx 通道。
        lane: crate::transaction::TxLane,
        /// 路由提示。
        route: crate::transaction::RouteHint,
    },
    /// GameTurn / CheckpointAnchor tx 提交给了非 assigned_validator 的 validator（SubTask 7.5）。
    #[error("not assigned validator for game (game_id={game_id:?}, assigned={assigned:?}, receiver={receiver:?})")]
    NotAssignedValidator {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 链上记录的 assigned_validator pubkey。
        assigned: crate::signature::TaggedPubkey,
        /// 当前接收 tx 的 validator pubkey。
        receiver: crate::signature::TaggedPubkey,
    },
    /// 非当前轮次玩家提交 GameTurn tx（SubTask 7.4：轮转约束）。
    #[error("not your turn (game_id={game_id:?}, current_turn={current_turn:?}, actor={actor:?})")]
    NotYourTurn {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 当前轮次玩家地址。
        current_turn: crate::Address,
        /// 实际提交 tx 的玩家地址。
        actor: crate::Address,
    },
    /// 玩家活跃 Game 数量超限（SubTask 8.7：S8 修复，max_active_games_per_player 默认 10）。
    #[error("too many active games: player={player:?}, active={active}, limit={limit}")]
    TooManyActiveGames {
        /// 玩家地址。
        player: crate::Address,
        /// 当前活跃 Game 数。
        active: u32,
        /// 上限。
        limit: u32,
    },
    /// Game 对象不存在或未激活。
    #[error("game not found or inactive: {0:?}")]
    GameNotFound(crate::object_model::ObjectID),
    /// assigned_validator 未在指定 block 范围内装入 GameTurn tx（SubTask 8.9：NEW-H2 fallback 触发条件）。
    #[error("assigned validator timeout: game_id={game_id:?}, timeout_blocks={timeout_blocks}")]
    AssignedValidatorTimeout {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 超时阈值（block 数）。
        timeout_blocks: u64,
    },
    /// fallback tx 缺少 assigned_validator_timeout_proof（SubTask 8.9：NEW-H2）。
    #[error("fallback tx missing timeout proof")]
    MissingTimeoutProof,
    /// fallback tx 的 timeout_proof 验证失败（SubTask 8.9：多副本见证签名不足 / round 范围不正确）。
    #[error("invalid timeout proof: {0}")]
    InvalidTimeoutProof(String),

    // ===== Phase 2: 时间共识（Task 11） =====
    /// block.height 不等于 prev.height + 1（S10：严格单调递增）。
    #[error("block height not strictly increasing: prev={prev}, got={got}")]
    BlockHeightNotIncreasing { prev: u64, got: u64 },
    /// block.timestamp_ms < prev.timestamp_ms（S10：单调不减）。
    #[error("block timestamp moved backwards: prev={prev}, got={got}")]
    BlockTimestampMovedBackwards { prev: u64, got: u64 },
    /// block.timestamp_ms > prev.timestamp_ms + max_interval_ms（S10：最大间隔约束）。
    #[error("block timestamp interval exceeded: prev={prev}, got={got}, max_interval={max_interval}")]
    BlockTimestampIntervalExceeded {
        prev: u64,
        got: u64,
        max_interval: u64,
    },

    // ===== Phase 2: DAG 共识 / Bullshark（Task 8 / 9） =====
    /// vertex 签名验证失败（SEC-C1：签名对象 = hash(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)）。
    #[error("dag vertex signature verification failed")]
    InvalidVertexSignature,
    /// vertex parent_hashes 数量不足 2/3 validator（spec：vertex 须引用 ≥2/3 validator 的上一轮 vertex hash）。
    #[error("vertex parent count {actual} < required {required} (2/3 of validator set)")]
    InsufficientParents { actual: usize, required: usize },
    /// vertex 大小超限（max_vertex_size 默认 256KB）。
    #[error("vertex size {actual} exceeds max_vertex_size {limit}")]
    VertexTooLarge { actual: usize, limit: usize },
    /// commit certificate 签名数不足 2/3 quorum（SubTask 9.1 / 10.7）。
    #[error("commit certificate signer count {actual} < quorum {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    /// commit certificate 签名验证失败（SubTask 10.7）。
    #[error("commit certificate signature verification failed for signer index {signer_idx}")]
    InvalidCommitCertificateSignature { signer_idx: usize },
    /// commit certificate 的 epoch / prev_commit_hash / state_root 字段与本地不匹配（SEC2-C1）。
    #[error("commit certificate field mismatch: {0}")]
    CommitCertificateMismatch(String),

    // ===== Phase 2: Block 验证器（Task 10） =====
    /// Public 通道 tx 排序不合法（gas/arrival 非单调，SubTask 10.2）。
    #[error("invalid public tx ordering: tx[{idx}] gas_price={tx_price} < prev_price={prev_price}")]
    InvalidTxOrdering {
        /// 出错 tx 的索引。
        idx: usize,
        /// 出错 tx 的 gas price。
        tx_price: u64,
        /// 前一个 tx 的 gas price。
        prev_price: u64,
    },
    /// GameTurn 通道 tx 被错误计费 gas（SubTask 10.4：GameTurn 通道免 gas）。
    #[error("GameTurn tx charged gas: budget={budget}, price={price}")]
    GameTurnGasCharged {
        /// tx 声明的 gas budget。
        budget: u64,
        /// tx 声明的 gas price。
        price: u64,
    },
    /// 状态根不匹配（SubTask 10.5：两通道状态根转移校验）。
    #[error("state root mismatch: expected={expected:?}, got={got:?}")]
    StateRootMismatch {
        /// 期望的状态根。
        expected: crate::Hash,
        /// 实际的状态根。
        got: crate::Hash,
    },
    /// public_tx_root 不匹配（SubTask 10.5）。
    #[error("public_tx_root mismatch: expected={expected:?}, got={got:?}")]
    PublicTxRootMismatch {
        /// 期望的 public_tx_root。
        expected: crate::Hash,
        /// 实际的 public_tx_root。
        got: crate::Hash,
    },
    /// gameturn_tx_root 不匹配（SubTask 10.5）。
    #[error("gameturn_tx_root mismatch: expected={expected:?}, got={got:?}")]
    GameTurnTxRootMismatch {
        /// 期望的 gameturn_tx_root。
        expected: crate::Hash,
        /// 实际的 gameturn_tx_root。
        got: crate::Hash,
    },
    /// game sub-block 的 assigned_validator 签名验证失败（SubTask 10.3）。
    #[error("invalid game sub-block signature: game_id={game_id:?}")]
    InvalidGameSubBlockSignature {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
    },
    /// vertex 内 tx 排序违反 S9 规则（SubTask 10.6：GameTurn 应优先于 ForceSync）。
    #[error("vertex tx ordering violates S9: ForceSync tx at idx {force_idx} before GameTurn tx at idx {turn_idx}")]
    InvalidVertexTxOrdering {
        /// ForceSync tx 的索引。
        force_idx: usize,
        /// GameTurn tx 的索引。
        turn_idx: usize,
    },

    // ===== Phase 2: ValidatorSet / Slashing（Task 13） =====
    /// validator 集规模不足（SEC-C2：主网 |V| < 5 时 OffChain 模式 Game 创建被拒绝）。
    #[error("validator set too small for OffChain: size={size}, required>=5")]
    ValidatorSetTooSmallForOffChain { size: usize },
    /// validator 不在当前 ValidatorSet 中。
    #[error("validator not in set: {0:?}")]
    ValidatorNotInSet(crate::signature::TaggedPubkey),
    /// 同一 (epoch, round, author_pubkey) 出现两个冲突 vertex（equivocation slashing）。
    #[error("vertex equivocation detected: epoch={epoch}, round={round}, author={author:?}")]
    VertexEquivocation {
        epoch: u64,
        round: u64,
        author: crate::signature::TaggedPubkey,
    },
    /// 同一 (epoch, commit_round) 出现两个冲突 commit certificate（commit cert equivocation slashing）。
    #[error("commit certificate equivocation: epoch={epoch}, commit_round={commit_round}")]
    CommitCertEquivocation { epoch: u64, commit_round: u64 },
    /// VRF proof 验证失败（IMPL-SEC-2：ECVRF-secp256k1，97B proof）。
    #[error("vrf proof verification failed")]
    InvalidVrfProof,
    /// VRF input 与链上 epoch 不匹配（SEC2-C2：VRF input = hash(chain_id || epoch || prev_epoch_randomness)）。
    #[error("vrf input mismatch: expected epoch={expected}, got={got}")]
    VrfInputMismatch { expected: u64, got: u64 },
    /// VRF output 与链上 epoch_randomness 不匹配（SEC2-M10）。
    #[error("vrf output mismatch")]
    VrfOutputMismatch,
    /// validator 处于 bonding 期，不可参与共识（NEW-L3）。
    #[error("validator in bonding period: pubkey={0:?}")]
    ValidatorInBonding(crate::signature::TaggedPubkey),
    /// validator 处于 unbonding 期，不可参与共识但可被 slashing（R5-H7）。
    #[error("validator in unbonding period: pubkey={0:?}")]
    ValidatorInUnbonding(crate::signature::TaggedPubkey),
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
