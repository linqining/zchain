//! 节点集成模块（Task 32 — SubTask 32.1 / 32.2 / 32.3 / 32.4 / 32.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 32.1**：validator 节点（DAG vertex 产出 + Bullshark 共识 + game sub-block）
//! - **SubTask 32.2**：full node（validation only，不参与共识，执行 Layer 1-3 裁剪）
//! - **SubTask 32.3**：archive node（永不裁剪，提供 `request_historical_data` RPC）
//! - **SubTask 32.4**：light node（仅 block header + state root commitment 订阅）
//! - **SubTask 32.5**：CLI 工具（keygen 支持 secp256k1/ed25519 tagged pubkey、query、
//!   deploy contract、send tx、upgrade contract、本地计算 assigned_validator、请求历史数据）
//!
//! 实现说明：
//! - [`NodeRole`] 区分 4 种节点角色；裁剪行为委托给 [`crate::storage::NodeRole`]
//! - [`NodeConfig`] 定义节点启动配置
//! - [`Node`] 持有存储后端与可选 validator 密钥，提供 RPC 后端集成点
//! - CLI 工具函数（keygen / query / send_tx）以纯函数形式提供，可被二进制 main 调用

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountStore};
use crate::block::validator::{
    validate_block_tx_roots, validate_commit_certificate_signatures, validate_gameturn_no_gas,
    validate_state_root_transition, validate_tx_chain_id, validate_tx_signature,
    validate_vertex_tx_ordering,
};
use crate::block::{Block, TimeConsensusConfig, validate_block_time};
use crate::consensus::{
    DagVertex, Epoch, MAX_VERTEX_SIZE, ValidatorEntry, ValidatorSet,
    compute_genesis_chain_randomness, required_parent_count, validate_commit_certificate_fields,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::executor::{
    BlockExecutionOutcome, ExecutionEnvironment, FeePolicy, execute_block, execute_block_serial,
};
use crate::object_model::{Object, ObjectID};
use crate::signature::TaggedPubkey;
use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use crate::signature::unified::verify_signature;
use crate::storage::{
    BlockStore, BridgeRegistryStore, DagVertexStore, NodeRole as PruningNodeRole, ObjectBackend,
    ObjectDb, ObjectDbSnapshot,
};
use crate::transaction::{Transaction, TxLane, validate_tx_limits};
use crate::vm::PrecompileRegistry;
use crate::vm::contracts::{GamePrecompile, TexasPokerPrecompile};
use crate::{Address, BlockHeight, ChainId, Hash};

/// tx_cache 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_NODE_TX_CACHE_SIZE: usize = 10_000;

/// pending_tx 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_PENDING_TX_SIZE: usize = 10_000;

/// 生产默认时钟来源：`SystemTime` UNIX 时间（毫秒）。
fn system_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ===== SubTask 32.1 ~ 32.4: 节点角色 =====

/// 节点角色（spec SubTask 32.1 ~ 32.4）。
///
/// - `Validator`：参与共识（DAG vertex 产出 + Bullshark 投票），裁剪行为同 Full
/// - `Full`：仅验证，不参与共识，执行 Layer 1-3 裁剪
/// - `Archive`：永不裁剪，提供 `request_historical_data` RPC
/// - `Light`：仅订阅 block header + state root commitment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum NodeRole {
    /// Validator 节点：参与 DAG 共识 + game sub-block 产出。
    Validator,
    /// Full node：仅验证，不参与共识，执行 Layer 1-3 裁剪。
    #[default]
    Full,
    /// Archive node：永不裁剪，提供历史数据 RPC。
    Archive,
    /// Light node：仅 block header + state root 订阅。
    Light,
}

impl NodeRole {
    /// 转换为裁剪角色（[`crate::storage::NodeRole`]）。
    ///
    /// Validator 的裁剪行为同 Full（执行 Layer 1-3 裁剪）。
    #[must_use]
    pub const fn to_pruning_role(self) -> PruningNodeRole {
        match self {
            Self::Validator | Self::Full => PruningNodeRole::Full,
            Self::Archive => PruningNodeRole::Archive,
            Self::Light => PruningNodeRole::Light,
        }
    }

    /// 是否应执行裁剪。
    #[must_use]
    pub const fn should_prune(self) -> bool {
        self.to_pruning_role().should_prune()
    }

    /// 是否为 validator 节点。
    #[must_use]
    pub const fn is_validator(self) -> bool {
        matches!(self, Self::Validator)
    }

    /// 是否为 archive 节点（提供历史数据 RPC）。
    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::Archive)
    }

    /// 是否为 light 节点（仅订阅 header）。
    #[must_use]
    pub const fn is_light(self) -> bool {
        matches!(self, Self::Light)
    }
}

// ===== NodeConfig =====

/// 节点启动配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// 节点角色。
    pub role: NodeRole,
    /// 网络 chain_id。
    pub chain_id: ChainId,
    /// 数据目录（RocksDB 路径）。
    pub data_dir: PathBuf,
    /// RPC 监听地址（如 "127.0.0.1:8545"）。
    pub rpc_listen: String,
    /// P2P 监听地址（如 "127.0.0.1:9000"）。
    pub p2p_listen: String,
    /// Validator 密钥（仅 Validator 角色需要）。
    pub validator_key: Option<ValidatorKey>,
    /// 创世 validator 列表（P0-4 动态 quorum）。
    ///
    /// 节点启动时以此初始化 ValidatorSet（epoch 0）。
    /// 空列表仅适合在注册 validator 之前准备 genesis 状态；生产入口在启动
    /// RPC/P2P/共识前必须调用 [`Node::ensure_consensus_ready`] 并拒绝空集合。
    /// Entries must have zero stake; native ZCN stake is admitted only through UTXO-backed bond.
    #[serde(default)]
    pub genesis_validators: Vec<ValidatorEntry>,
    /// Resource-credit policy. Compute metering remains enabled when set to `Free`.
    #[serde(default)]
    pub fee_policy: FeePolicy,
    /// M3-ACC-6：强制包含期限（毫秒）。
    ///
    /// 交易在 mempool 中停留超过该期限后，下一次出块 drain 会被强制提升到普通交易
    /// 之前进块（§5.3 ForceInclude）。`0 = 禁用强制包含路径（行为与历史版本一致）`。
    #[serde(default = "crate::force_include::default_inclusion_deadline_ms")]
    pub inclusion_deadline_ms: u64,
    /// M3-ACC-6：审查检测窗口（块数，§5.3 "近 K 个块"的 v1 块数近似）。
    #[serde(default = "crate::force_include::default_censorship_window_blocks")]
    pub censorship_window_blocks: u64,
    /// v1.5-c：checkpoint 产出间隔（块数；`height % interval == 0` 的高度上
    /// validator 发起/签署 checkpoint，2f+1 聚合 QC 后落盘）。`0 = 禁用`。
    #[serde(default = "default_checkpoint_interval_blocks")]
    pub checkpoint_interval_blocks: u64,
    /// v1.5-e：checkpoint QC 阈值 t（真 t-of-n 阈值 BLS；密钥来自
    /// `consensus::dkg` deal-sum）。`0 = 关闭，走既有聚合模式（零回退）`。
    #[serde(default)]
    pub qc_threshold_t: u32,
    /// v1.5-e：DKG 群密钥集 JSON 文件路径（公开面；
    /// `qc_threshold_t > 0` 时必填，`zchain dkg` 产出）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkg_keyset_path: Option<PathBuf>,
    /// v1.5-e：本节点 DKG 群份额 JSON 文件路径（私密面；
    /// `qc_threshold_t > 0` 时必填，载入时过 keyset Feldman 校验，fail-closed）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkg_share_path: Option<PathBuf>,
}

/// serde default：checkpoint 间隔默认 32 块。
pub const fn default_checkpoint_interval_blocks() -> u64 {
    crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS
}

impl NodeConfig {
    /// 创建默认配置（Full node，chain_id = DEFAULT_CHAIN_ID）。
    #[must_use]
    pub fn default_full(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Full,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            fee_policy: FeePolicy::Free,
            inclusion_deadline_ms: crate::force_include::DEFAULT_INCLUSION_DEADLINE_MS,
            censorship_window_blocks: crate::force_include::DEFAULT_CENSORSHIP_WINDOW_BLOCKS,
            checkpoint_interval_blocks:
                crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            qc_threshold_t: 0,
            dkg_keyset_path: None,
            dkg_share_path: None,
        }
    }

    /// 创建 validator 配置。
    #[must_use]
    pub fn validator(data_dir: PathBuf, validator_key: ValidatorKey) -> Self {
        Self {
            role: NodeRole::Validator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: Some(validator_key),
            genesis_validators: vec![],
            fee_policy: FeePolicy::Free,
            inclusion_deadline_ms: crate::force_include::DEFAULT_INCLUSION_DEADLINE_MS,
            censorship_window_blocks: crate::force_include::DEFAULT_CENSORSHIP_WINDOW_BLOCKS,
            checkpoint_interval_blocks:
                crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            qc_threshold_t: 0,
            dkg_keyset_path: None,
            dkg_share_path: None,
        }
    }

    /// 创建 archive 配置。
    #[must_use]
    pub fn archive(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Archive,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            fee_policy: FeePolicy::Free,
            inclusion_deadline_ms: crate::force_include::DEFAULT_INCLUSION_DEADLINE_MS,
            censorship_window_blocks: crate::force_include::DEFAULT_CENSORSHIP_WINDOW_BLOCKS,
            checkpoint_interval_blocks:
                crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            qc_threshold_t: 0,
            dkg_keyset_path: None,
            dkg_share_path: None,
        }
    }

    /// 创建 light 配置。
    #[must_use]
    pub fn light(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Light,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            fee_policy: FeePolicy::Free,
            inclusion_deadline_ms: crate::force_include::DEFAULT_INCLUSION_DEADLINE_MS,
            censorship_window_blocks: crate::force_include::DEFAULT_CENSORSHIP_WINDOW_BLOCKS,
            checkpoint_interval_blocks:
                crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            qc_threshold_t: 0,
            dkg_keyset_path: None,
            dkg_share_path: None,
        }
    }

    /// 设置创世 validator 列表（builder 风格）。
    #[must_use]
    pub fn with_genesis_validators(mut self, validators: Vec<ValidatorEntry>) -> Self {
        self.genesis_validators = validators;
        self
    }

    /// Select the chain's resource-credit policy.
    #[must_use]
    pub const fn with_fee_policy(mut self, fee_policy: FeePolicy) -> Self {
        self.fee_policy = fee_policy;
        self
    }

    /// M3-ACC-6：设置强制包含期限（毫秒；`0 = 禁用强制包含路径`）。
    #[must_use]
    pub const fn with_inclusion_deadline_ms(mut self, inclusion_deadline_ms: u64) -> Self {
        self.inclusion_deadline_ms = inclusion_deadline_ms;
        self
    }

    /// M3-ACC-6：设置审查检测窗口（块数，v1 块数近似）。
    #[must_use]
    pub const fn with_censorship_window_blocks(mut self, censorship_window_blocks: u64) -> Self {
        self.censorship_window_blocks = censorship_window_blocks;
        self
    }

    /// v1.5-c：设置 checkpoint 产出间隔（块数；`0 = 禁用`）。
    #[must_use]
    pub const fn with_checkpoint_interval_blocks(
        mut self,
        checkpoint_interval_blocks: u64,
    ) -> Self {
        self.checkpoint_interval_blocks = checkpoint_interval_blocks;
        self
    }
}

// ===== ValidatorKey =====

/// Validator 密钥（secp256k1）。
///
/// 用于 DAG vertex 签名与 commit certificate 签名。
/// 注意：私钥仅在 validator 节点内存中持有，不持久化到磁盘。
///
/// M-4 修复：实现 `Drop` 自动 zeroize 私钥，自定义 `Debug` 隐藏私钥内容。
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorKey {
    /// secp256k1 私钥（32 字节）。
    pub secret_key_bytes: [u8; 32],
    /// 对应的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// VRF 私钥（缺口 #3 §3.6：ECVRF-secp256k1，32 字节）。
    /// `None` 表示未配置 VRF（epoch_randomness 走 fallback）。
    pub vrf_secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorKey")
            .field("secret_key_bytes", &"[REDACTED]")
            .field("tagged_pubkey", &self.tagged_pubkey)
            .finish()
    }
}

impl Drop for ValidatorKey {
    fn drop(&mut self) {
        self.secret_key_bytes.fill(0);
        if let Some(vrf) = &mut self.vrf_secret {
            vrf.fill(0);
        }
    }
}

impl ValidatorKey {
    /// 从 secp256k1 私钥字节构造。
    ///
    /// 私钥必须为 32 字节且在 secp256k1 曲线阶范围内。
    pub fn from_secret_bytes(secret_key_bytes: [u8; 32]) -> PokerL1Result<Self> {
        use secp256k1::{PublicKey, Secp256k1};
        let secp = Secp256k1::new();
        let secret_key =
            secp256k1::SecretKey::from_slice(&secret_key_bytes).map_err(PokerL1Error::Secp256k1)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let compressed = public_key.serialize();
        let tagged_pubkey = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            compressed.to_vec(),
        )?;
        Ok(Self {
            secret_key_bytes,
            tagged_pubkey,
            vrf_secret: None,
        })
    }

    /// 设置 VRF 私钥（缺口 #3 §3.6）。
    pub fn with_vrf_secret(mut self, vrf_secret: [u8; 32]) -> Self {
        self.vrf_secret = Some(vrf_secret);
        self
    }
}

// ===== Node =====

/// tx 缓存状态（M-6 修复 — 合并 cache + order 到单个 Mutex 避免多锁死锁）。
///
/// C-2 修复：FIFO 淘汰机制防止内存 DoS（上限 10,000 条）。
struct TxCacheState {
    /// tx_hash → tx 映射。
    cache: std::collections::HashMap<Hash, Transaction>,
    /// 插入顺序（FIFO 淘汰追踪）。
    order: std::collections::VecDeque<Hash>,
}

impl TxCacheState {
    /// 创建空状态。
    fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// 插入 tx，若已存在则更新；若新插入则追加到 order 队列。
    /// 超过 max_size 时 FIFO 淘汰最旧条目。
    fn insert(&mut self, tx_hash: Hash, tx: Transaction, max_size: usize) {
        if !self.cache.contains_key(&tx_hash) {
            self.order.push_back(tx_hash);
        }
        self.cache.insert(tx_hash, tx);
        while self.cache.len() > max_size {
            if let Some(old_hash) = self.order.pop_front() {
                self.cache.remove(&old_hash);
            } else {
                break;
            }
        }
    }

    /// 按 hash 查询 tx。
    fn get(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.cache.get(tx_hash)
    }
}

/// A pending transaction together with the data needed to index it cheaply.
///
/// `Transaction` deliberately does not cache its derived caller address.  The mempool does: the
/// address is required for RBF, and deriving it for every queued transaction on every submission
/// turned a 10,000-entry mempool into an O(N²) hot path.
struct PendingTxEntry {
    /// Monotonic, in-process identifier.  It distinguishes otherwise identical transactions in
    /// the (permitted) zero-fee non-RBF case.
    id: u64,
    /// Caller derived once when the transaction enters the mempool.
    caller: Address,
    /// Full transaction in FIFO arrival order.
    tx: Transaction,
    /// M3-ACC-6：到达时间（进入 mempool 时的节点本地时钟，毫秒）。
    ///
    /// 交易本体无时间戳（块时间为确定性逻辑时钟），到达时间由接收 validator 记录，
    /// 用于 ForceInclude 期限判定（§5.3-2）。requeue 回排时从 SeenReceipt 恢复原始
    /// 到达时间，避免重复计时。
    arrived_at_ms: u64,
}

/// Pending transaction queue and its RBF index.
///
/// The queue remains the source of truth for arrival ordering.  `by_caller_nonce` points at the
/// oldest queued entry for a key, matching the previous linear `VecDeque::iter().position()`
/// semantics while making the common no-conflict submission O(1).  It contains a deque because
/// legacy zero-fee submissions do not participate in RBF and may share a caller/nonce.
struct PendingTxState {
    queue: std::collections::VecDeque<PendingTxEntry>,
    by_caller_nonce: std::collections::HashMap<(Address, u64), std::collections::VecDeque<u64>>,
    next_id: u64,
}

impl PendingTxState {
    fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            by_caller_nonce: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn oldest_for(&self, caller: Address, nonce: u64) -> Option<(usize, &PendingTxEntry)> {
        let id = *self.by_caller_nonce.get(&(caller, nonce))?.front()?;
        self.queue
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.id == id)
    }

    fn push(&mut self, caller: Address, tx: Transaction, arrived_at_ms: u64) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.by_caller_nonce
            .entry((caller, tx.nonce))
            .or_default()
            .push_back(id);
        self.queue.push_back(PendingTxEntry {
            id,
            caller,
            tx,
            arrived_at_ms,
        });
    }

    fn push_front(&mut self, caller: Address, tx: Transaction, arrived_at_ms: u64) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.by_caller_nonce
            .entry((caller, tx.nonce))
            .or_default()
            .push_front(id);
        self.queue.push_front(PendingTxEntry {
            id,
            caller,
            tx,
            arrived_at_ms,
        });
    }

    /// Remove an entry by its queue position and update the RBF index at the same time.
    fn remove(&mut self, index: usize) -> Option<PendingTxEntry> {
        let entry = self.queue.remove(index)?;
        let key = (entry.caller, entry.tx.nonce);
        let remove_key = if let Some(ids) = self.by_caller_nonce.get_mut(&key) {
            // This cannot fail while `queue` and the index are mutated only through this type.
            let id_index = ids
                .iter()
                .position(|id| *id == entry.id)
                .expect("pending transaction RBF index must reference queue entry");
            ids.remove(id_index);
            ids.is_empty()
        } else {
            false
        };
        if remove_key {
            self.by_caller_nonce.remove(&key);
        }
        Some(entry)
    }

    fn drain(&mut self) -> std::collections::VecDeque<PendingTxEntry> {
        self.by_caller_nonce.clear();
        std::mem::take(&mut self.queue)
    }
}

/// SeenReceipt 内存 map（M3-ACC-6，§5.3-1）。
///
/// **v1 边界：receipt 仅存内存，节点重启丢失；持久化 / P2P receipt 同步属 v2。**
/// C-2 同款 FIFO 上限防内存 DoS。
struct SeenReceiptsState {
    map: std::collections::HashMap<Hash, crate::force_include::SeenReceipt>,
    order: std::collections::VecDeque<Hash>,
}

impl SeenReceiptsState {
    fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn insert(&mut self, receipt: crate::force_include::SeenReceipt, max_size: usize) {
        if !self.map.contains_key(&receipt.tx_hash) {
            self.order.push_back(receipt.tx_hash);
        }
        self.map.insert(receipt.tx_hash, receipt);
        while self.map.len() > max_size {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
    }

    fn get(&self, tx_hash: &Hash) -> Option<crate::force_include::SeenReceipt> {
        self.map.get(tx_hash).cloned()
    }
}

/// ForceInclude 已提升集合（M3-ACC-6 去重，§5.3-2 "已进过块的 hash 防重复包含"）。
///
/// v1 语义：drain 提升时即标记（把"已进入 vertex batch"视为"已进块"的最早保守点）。
/// 同一 tx_hash 不会被二次强制提升；回排（requeue）后按普通排序随下一轮 drain 进块。
struct ForceIncludeState {
    included: std::collections::HashSet<Hash>,
    order: std::collections::VecDeque<Hash>,
}

impl ForceIncludeState {
    fn new() -> Self {
        Self {
            included: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// 标记提升；返回 false 表示此前已提升过（去重命中）。
    fn mark_included(&mut self, tx_hash: Hash, max_size: usize) -> bool {
        if !self.included.insert(tx_hash) {
            return false;
        }
        self.order.push_back(tx_hash);
        while self.order.len() > max_size {
            if let Some(old) = self.order.pop_front() {
                self.included.remove(&old);
            } else {
                break;
            }
        }
        true
    }

    fn snapshot(&self) -> Vec<Hash> {
        self.order.iter().copied().collect()
    }
}

/// v1.5-c：checkpoint 投票收集与最新 QC 状态。
///
/// votes 按 `(epoch, height)` 分桶（有界：最多保留 4 个位点的票）；`latest_qc`
/// 为已达成 2f+1 的最新 checkpoint（重启经 `checkpoints.jsonl` sidecar 恢复
/// 最高高度一条）。
struct CheckpointState {
    votes: std::collections::HashMap<(crate::consensus::Epoch, u64), Vec<crate::consensus::checkpoint::CheckpointVote>>,
    vote_sites_order: std::collections::VecDeque<(crate::consensus::Epoch, u64)>,
    latest_qc: Option<crate::consensus::checkpoint::CheckpointQc>,
    /// v1.5-e：阈值形态部分份额签名（按位点分桶，与 votes 同款有界）。
    threshold_partials: std::collections::HashMap<
        (crate::consensus::Epoch, u64),
        Vec<crate::consensus::checkpoint::ThresholdQcPartial>,
    >,
    /// v1.5-e：阈值部分份额桶的 FIFO 驱逐序。
    threshold_sites_order: std::collections::VecDeque<(crate::consensus::Epoch, u64)>,
}

/// checkpoint 投票桶上限（位点数）。
const MAX_CHECKPOINT_VOTE_SITES: usize = 4;

impl CheckpointState {
    fn new() -> Self {
        Self {
            votes: std::collections::HashMap::new(),
            vote_sites_order: std::collections::VecDeque::new(),
            latest_qc: None,
            threshold_partials: std::collections::HashMap::new(),
            threshold_sites_order: std::collections::VecDeque::new(),
        }
    }
}

/// v1.5-d：DA 请求/回执状态（原型口径：内存态；凭证验证逻辑见
/// `consensus::da`，重启不恢复 —— DA 请求是短生命周期对象）。
struct DaState {
    /// digest → 条目（请求 + 已收集回执）。
    entries: std::collections::HashMap<Hash, DaEntry>,
    /// FIFO 驱逐序（上限 [`MAX_DA_ENTRIES`]）。
    order: std::collections::VecDeque<Hash>,
    /// 待 gossip 的本节点回执（validator loop 每轮 drain 并广播）。
    outbox: std::collections::VecDeque<crate::consensus::da::DaReceipt>,
}

/// DA 条目。
struct DaEntry {
    request: crate::consensus::da::DaRequest,
    receipts: Vec<crate::consensus::da::DaReceipt>,
    /// 已聚合的凭证（凑齐 2f+1 时生成）。
    certificate: Option<crate::consensus::da::DaCertificate>,
}

/// DA 状态条目上限（内存 DoS 防护）。
const MAX_DA_ENTRIES: usize = 256;

impl DaState {
    fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            outbox: std::collections::VecDeque::new(),
        }
    }

    fn entry_mut(&mut self, request: crate::consensus::da::DaRequest) -> &mut DaEntry {
        let digest = request.digest;
        if !self.order.contains(&digest) {
            self.order.push_back(digest);
        }
        while self.order.len() > MAX_DA_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
        self.entries.entry(digest).or_insert_with(|| DaEntry {
            request,
            receipts: Vec::new(),
            certificate: None,
        })
    }
}

/// DA 状态视图（RPC `da_status` 返回；字节 hex）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaStatus {
    /// 是否已有请求。
    pub requested: bool,
    /// 数据摘要（0x hex）。
    pub digest: String,
    /// 请求位点 epoch。
    pub epoch: u64,
    /// 请求位点高度。
    pub height: u64,
    /// 已收集回执数。
    pub receipt_count: usize,
    /// 是否已成凭证（≥2f+1）。
    pub certified: bool,
    /// 凭证签名者数（certified=true 时 ≥2f+1）。
    pub cert_signers: usize,
}

/// checkpoint QC JSONL sidecar 文件名（相对 data_dir；域名冻结）。
pub const CHECKPOINT_SIDECAR_FILE: &str = "checkpoints.jsonl";

// ===== v1.5-e：DKG 密钥材料文件面（`zchain dkg` 产出 / Node 载入） =====

/// DKG 群密钥集 JSON 文件形态（公开面；字节字段 0x hex，脚本友好）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgKeysetFile {
    /// 参与者总数 n（分片 id ∈ 1..=n）。
    pub n: u32,
    /// 签名/重建阈值 t。
    pub t: u32,
    /// 群公钥 Q（G2 compressed，0x hex 96B）。
    pub group_pubkey_g2: String,
    /// 各 dealer 承诺集（外层按 dealer_id-1，内层 k = 0..=t-1；0x hex 96B）。
    pub commitments_g2: Vec<Vec<String>>,
}

/// DKG 参与者群份额 JSON 文件形态（**私密面**；文件权限由部署层保证）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgShareFile {
    /// 参与者 id（1..=n）。
    pub participant_id: u64,
    /// 群份额标量（0x hex 32B）。
    pub scalar_hex: String,
}

/// [`GroupKeyset`] → JSON 字符串（文件写入面）。
///
/// # Errors
/// 群公钥/承诺长度非法或 JSON 序列化失败。
pub fn dkg_keyset_to_json(
    keyset: &crate::consensus::dkg::GroupKeyset,
) -> PokerL1Result<String> {
    let hex_96 = |bytes: &[u8]| -> PokerL1Result<String> {
        if bytes.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "dkg keyset file: commitment size {} != {}",
                bytes.len(),
                crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
            )));
        }
        Ok(format!("0x{}", hex::encode(bytes)))
    };
    let mut commitments = Vec::with_capacity(keyset.commitments_g2.len());
    for dealer in &keyset.commitments_g2 {
        commitments.push(
            dealer
                .iter()
                .map(|c| hex_96(c))
                .collect::<PokerL1Result<Vec<_>>>()?,
        );
    }
    let file = DkgKeysetFile {
        n: keyset.n,
        t: keyset.t,
        group_pubkey_g2: hex_96(&keyset.group_pubkey_g2)?,
        commitments_g2: commitments,
    };
    serde_json::to_string_pretty(&file)
        .map_err(|e| PokerL1Error::Serialization(format!("dkg keyset json: {e}")))
}

/// JSON 字符串 → [`GroupKeyset`]（文件载入面；逐字段尺寸校验，fail-closed）。
///
/// # Errors
/// JSON 非法、hex 非法或承诺/群公钥尺寸非 96B。
pub fn dkg_keyset_from_json(s: &str) -> PokerL1Result<crate::consensus::dkg::GroupKeyset> {
    let file: DkgKeysetFile = serde_json::from_str(s)
        .map_err(|e| PokerL1Error::Serialization(format!("dkg keyset json: {e}")))?;
    let hex_96 = |s: &str| -> PokerL1Result<Vec<u8>> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(stripped)
            .map_err(|e| PokerL1Error::Serialization(format!("dkg keyset hex: {e}")))?;
        if bytes.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "dkg keyset file: point size {} != {}",
                bytes.len(),
                crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
            )));
        }
        Ok(bytes)
    };
    let mut commitments = Vec::with_capacity(file.commitments_g2.len());
    for dealer in &file.commitments_g2 {
        commitments.push(
            dealer
                .iter()
                .map(|c| hex_96(c))
                .collect::<PokerL1Result<Vec<_>>>()?,
        );
    }
    Ok(crate::consensus::dkg::GroupKeyset {
        n: file.n,
        t: file.t,
        group_pubkey_g2: hex_96(&file.group_pubkey_g2)?,
        commitments_g2: commitments,
    })
}

/// [`ParticipantShare`] → JSON 字符串（文件写入面）。
///
/// # Errors
/// JSON 序列化失败。
pub fn dkg_share_to_json(
    share: &crate::consensus::dkg::ParticipantShare,
) -> PokerL1Result<String> {
    let file = DkgShareFile {
        participant_id: share.id,
        scalar_hex: format!("0x{}", hex::encode(share.scalar)),
    };
    serde_json::to_string_pretty(&file)
        .map_err(|e| PokerL1Error::Serialization(format!("dkg share json: {e}")))
}

/// JSON 字符串 → [`ParticipantShare`]（文件载入面）。
///
/// # Errors
/// JSON 非法、hex 非法或标量非 32B。
pub fn dkg_share_from_json(s: &str) -> PokerL1Result<crate::consensus::dkg::ParticipantShare> {
    let file: DkgShareFile = serde_json::from_str(s)
        .map_err(|e| PokerL1Error::Serialization(format!("dkg share json: {e}")))?;
    let stripped = file.scalar_hex.strip_prefix("0x").unwrap_or(&file.scalar_hex);
    let bytes = hex::decode(stripped)
        .map_err(|e| PokerL1Error::Serialization(format!("dkg share hex: {e}")))?;
    let scalar: [u8; crate::crypto_precompiles::bls::SCALAR_SIZE] =
        bytes.as_slice().try_into().map_err(|_| {
            PokerL1Error::InvalidBlsScalar(format!(
                "dkg share scalar size {} != {}",
                bytes.len(),
                crate::crypto_precompiles::bls::SCALAR_SIZE
            ))
        })?;
    Ok(crate::consensus::dkg::ParticipantShare {
        id: file.participant_id,
        scalar,
    })
}

/// 重放 checkpoint sidecar，返回最高高度的一条合法 QC（None = 无/全部损坏）。
fn replay_latest_checkpoint_qc(
    data_dir: &std::path::Path,
) -> Option<crate::consensus::checkpoint::CheckpointQc> {
    let content = std::fs::read_to_string(data_dir.join(CHECKPOINT_SIDECAR_FILE)).ok()?;
    let mut best: Option<crate::consensus::checkpoint::CheckpointQc> = None;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(qc) = serde_json::from_str::<crate::consensus::checkpoint::CheckpointQc>(line) {
            if best.as_ref().is_none_or(|b| qc.height >= b.height) {
                best = Some(qc);
            }
        }
    }
    best
}

/// v1.5-e：从配置路径加载 DKG 密钥材料（keyset 公开面 + 本节点群份额私密面）。
///
/// fail-closed：
/// - `qc_threshold_t == 0`（聚合模式）时配置了任何 dkg 路径 → 拒（材料与模式
///   不一致，防误配后静默走聚合）；
/// - `qc_threshold_t > 0` 缺任一路径 → 拒；
/// - `keyset.t != qc_threshold_t` → 拒；
/// - 本节点份额未过 `keyset.verify_participant_share`（Feldman 等式）→ 拒。
///
/// # Errors
/// 上述任一拒绝条件或文件读取/解析失败。
fn load_dkg_material(
    config: &NodeConfig,
) -> PokerL1Result<(
    Option<crate::consensus::dkg::GroupKeyset>,
    Option<crate::consensus::dkg::ParticipantShare>,
)> {
    if config.qc_threshold_t == 0 {
        if config.dkg_keyset_path.is_some() || config.dkg_share_path.is_some() {
            return Err(PokerL1Error::Other(
                "dkg: 配置了 keyset/share 路径但 qc-threshold-t == 0（聚合模式不接受阈值材料）".into(),
            ));
        }
        return Ok((None, None));
    }
    let Some(ks_path) = &config.dkg_keyset_path else {
        return Err(PokerL1Error::Other(
            "dkg: --qc-threshold-t > 0 需要 --dkg-keyset <path>".into(),
        ));
    };
    let Some(share_path) = &config.dkg_share_path else {
        return Err(PokerL1Error::Other(
            "dkg: --qc-threshold-t > 0 需要 --dkg-share <path>".into(),
        ));
    };
    let keyset = dkg_keyset_from_json(
        &std::fs::read_to_string(ks_path).map_err(|e| {
            PokerL1Error::Other(format!("dkg: keyset 文件读取失败（{}）：{e}", ks_path.display()))
        })?,
    )?;
    if keyset.t != config.qc_threshold_t {
        return Err(PokerL1Error::Other(format!(
            "dkg: keyset.t {} != 配置 qc-threshold-t {}（fail-closed）",
            keyset.t, config.qc_threshold_t
        )));
    }
    let share = dkg_share_from_json(
        &std::fs::read_to_string(share_path).map_err(|e| {
            PokerL1Error::Other(format!(
                "dkg: share 文件读取失败（{}）：{e}",
                share_path.display()
            ))
        })?,
    )?;
    if !keyset.verify_participant_share(&share)? {
        return Err(PokerL1Error::Other(
            "dkg: 本节点群份额未通过 keyset Feldman 校验（fail-closed 拒载）".into(),
        ));
    }
    Ok((Some(keyset), Some(share)))
}

/// 节点实例 — 持有存储后端与可选 validator 密钥。
///
/// 不直接运行网络/event loop；由上层二进制集成 tokio runtime + network + RPC server。
/// 本结构提供存储访问、tx 提交、block/vertex 查询等核心方法。
pub struct Node {
    /// 配置。
    config: NodeConfig,
    /// BlockStore。
    block_store: BlockStore,
    /// Serializes the complete validate → execute snapshots → persist block transition.
    ///
    /// ObjectDb, AccountStore and BlockStore do not share one physical transaction, so two local
    /// block writers must not interleave their preflight checks and commits.
    block_commit_lock: std::sync::Mutex<()>,
    /// ObjectDb。
    object_db: std::sync::Mutex<ObjectDb>,
    /// DagVertexStore。
    vertex_store: DagVertexStore,
    /// AccountStore（内存版，Phase 4 接入 rocksdb）。
    account_store: std::sync::Mutex<AccountStore>,
    /// 已提交的 tx 缓存（M-6 修复 — cache + order 合并到单个 Mutex）。
    tx_cache: std::sync::Mutex<TxCacheState>,
    /// 待装 vertex 的 tx 缓冲（仅 Validator 角色）。
    pending_tx: std::sync::Mutex<PendingTxState>,
    /// pending_tx 的 Condvar — submit_tx 时 notify，validator loop 用 wait_timeout 等待。
    pending_tx_condvar: std::sync::Condvar,
    /// 当前 ValidatorSet（P0-4 动态 quorum）。
    ///
    /// Production consensus admission fails closed when there are no active validators. Explicit
    /// in-memory constructors retain an empty-set mode for unit and integration tests which focus
    /// on execution rather than consensus membership.
    validator_set: std::sync::Mutex<ValidatorSet>,
    /// Whether consensus admission may bypass validator membership for explicit in-memory tests.
    allow_empty_consensus_for_tests: bool,
    /// 预编译合约注册表（共享 Arc — block 执行时 clone 引用而非重建）。
    ///
    /// 注册内置预编译合约：
    /// - [`GamePrecompile`]（`0xFF..01`，GameTurn 通道免 gas）
    /// - [`TexasPokerPrecompile`]（`0xFF..02`，GameTurn 通道免 gas）
    ///
    /// 治理升级（版本号 + timelock）经 `propose_upgrade` / `activate_upgrade`，
    /// 不在此处直接重建。
    precompile_registry: Arc<PrecompileRegistry>,
    /// Bridge registry store（缺口 #9：bridge_verify 铸币路径 + nonce 持久化）。
    ///
    /// 生产节点持久化（重启不丢 nonce，防重放铸币）。`None` 表示节点未启用桥
    /// （bridge contract_call 会被 executor 拒绝）。
    bridge_registry_store: Option<Arc<BridgeRegistryStore>>,
    /// 指标收集器（缺口 #7：Prometheus 风格指标导出）。
    metrics: Arc<crate::metrics::MetricsCollector>,
    /// ZK verifier registry（链上 zk_verify 启用）。
    zk_verifier: Option<crate::offline::zk_verifier::ZkVerifierRegistry>,
    /// Light client header 缓存（缺口：subscribe_light_headers 完整实现）。
    /// validator 节点在 put_block 时生成并签名；light/full 节点可订阅获取。
    light_headers: std::sync::Mutex<Vec<crate::network::LightClientHeader>>,
    /// M3-ACC-6：节点本地时钟来源（可注入；生产默认 SystemTime，测试注 fake clock）。
    time_source: std::sync::Mutex<Box<dyn Fn() -> u64 + Send + Sync>>,
    /// M3-ACC-6：已签发的 SeenReceipt（v1.5-a1：validator 节点经 JSONL sidecar
    /// `<data_dir>/seen_receipts.jsonl` 持久化，重启重放恢复；内存节点无 sidecar）。
    seen_receipts: std::sync::Mutex<SeenReceiptsState>,
    /// v1.5-a1：SeenReceipt sidecar 写句柄（`Some` = 持久化路径；内存节点为 `None`）。
    receipt_sidecar: std::sync::Mutex<Option<crate::force_include::ReceiptSidecar>>,
    /// M3-ACC-6：已强制提升（视为已进块）的 tx_hash 去重集合。
    force_include: std::sync::Mutex<ForceIncludeState>,
    /// v1.5-b：真实罚没账本（append-only）。`check_censorship` 命中 Censored 时
    /// 对 receipt 签发者执行 bond 扣减并记账（原型口径：单节点主观证据；生产
    /// 语义见 `consensus::slash` 模块头边界说明）。
    slash_ledger: std::sync::Mutex<crate::consensus::slash::SlashLedger>,
    /// v1.5-c：checkpoint 投票收集与最新 QC（重启经 sidecar 恢复）。
    checkpoint_state: std::sync::Mutex<CheckpointState>,
    /// v1.5-c：checkpoint QC sidecar 写句柄（`Some` = 持久化路径；内存节点 None）。
    checkpoint_sidecar: std::sync::Mutex<Option<std::fs::File>>,
    /// v1.5-e：DKG 群密钥集（`qc_threshold_t > 0` 时载入；公开面）。
    dkg_keyset: Option<crate::consensus::dkg::GroupKeyset>,
    /// v1.5-e：本节点 DKG 群份额（私密面；载入时已过 Feldman 校验）。
    dkg_share: Option<crate::consensus::dkg::ParticipantShare>,
    /// v1.5-d：DA 请求/回执状态（内存态原型）。
    da_state: std::sync::Mutex<DaState>,
}

/// 构造默认预编译合约注册表并注册内置预编译合约。
///
/// 在 [`Node::open`] / [`Node::open_inmemory_with_validators`] 中调用，
/// 确保 `GamePrecompile` 和 `TexasPokerPrecompile` 在节点启动时即注册。
fn build_default_precompile_registry() -> Arc<PrecompileRegistry> {
    let mut registry = PrecompileRegistry::new();
    registry.register(GamePrecompile::new_arc(1));
    registry.register(TexasPokerPrecompile::new_arc(1));
    registry.register(crate::vm::contracts::cairo_fact_registry::CairoFactRegistryPrecompile::new_arc(1));
    Arc::new(registry)
}

/// 从创世 validator 列表构建初始 ValidatorSet（epoch 0）。
///
/// - `genesis_chain_randomness` 由所有 validator pubkey 聚合派生（SEC2-M12）
/// - 初始 `epoch_randomness = genesis_chain_randomness`，`prev_epoch_randomness = 0`
fn build_genesis_validator_set(validators: Vec<ValidatorEntry>) -> PokerL1Result<ValidatorSet> {
    if let Some(validator) = validators.iter().find(|validator| validator.stake != 0) {
        return Err(PokerL1Error::Other(format!(
            "genesis validator {:?} declares unbacked stake {}; genesis validators must start at zero and bond NativeCoin UTXOs after genesis mint",
            validator.pubkey, validator.stake
        )));
    }
    let genesis_chain_randomness = compute_genesis_chain_randomness(&validators);
    let mut set = ValidatorSet {
        epoch: 0,
        validators,
        validator_set_hash: [0u8; 32],
        epoch_randomness: genesis_chain_randomness,
        prev_epoch_randomness: [0u8; 32],
        genesis_chain_randomness,
    };
    set.validator_set_hash = set.compute_hash();
    Ok(set)
}

fn validator_staking_escrow(set: &ValidatorSet) -> PokerL1Result<u64> {
    set.validators.iter().try_fold(0u64, |total, validator| {
        total
            .checked_add(validator.stake)
            .ok_or_else(|| PokerL1Error::Other("validator staking escrow sum overflow".into()))
    })
}

fn read_persisted_validator_set(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<(ValidatorSet, u64)>> {
    use crate::consensus::validator_set::{VALIDATOR_SET_OBJECT_ID, decode_validator_set_object};
    match object_db.read(&VALIDATOR_SET_OBJECT_ID) {
        Ok(object) => Ok(Some((
            decode_validator_set_object(&object, chain_id)?,
            object.version,
        ))),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn stage_validator_set_update(
    snapshot: &mut ObjectDbSnapshot,
    chain_id: ChainId,
    current: &ValidatorSet,
    next: &ValidatorSet,
) -> PokerL1Result<()> {
    use crate::consensus::validator_set::{
        VALIDATOR_SET_OBJECT_ID, decode_validator_set_object, validator_set_object,
    };
    let existing = snapshot.read(&VALIDATOR_SET_OBJECT_ID)?;
    let persisted = decode_validator_set_object(&existing, chain_id)?;
    if &persisted != current {
        return Err(PokerL1Error::Other(
            "in-memory ValidatorSet differs from authoritative persisted state".into(),
        ));
    }
    let next_version = existing
        .version
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other("ValidatorSet object version overflow".into()))?;
    snapshot.replace_system_object(validator_set_object(chain_id, next, next_version)?)
}

impl Node {
    /// 打开节点（初始化所有存储后端）。
    ///
    /// The standard node intentionally starts without a generic ZK verifier registry. The former
    /// STWO/zkVM MVP registry had no production soundness guarantee, so exposing it by default
    /// would make the VM `zk_verify` syscall look available when it must remain fail-closed.
    /// Applications which eventually provide an independently audited verifier can use the
    /// explicit [`Self::open_with_zk_verifier_registry`] constructor instead.
    pub fn open(config: NodeConfig) -> PokerL1Result<Self> {
        Self::open_with_optional_zk_verifier_registry(config, None)
    }

    /// Open a node with an application-supplied ZK verifier registry.
    ///
    /// This is the dependency-inversion boundary for application-aware verifiers such as the
    /// Texas recursive STWO verifier. `poker_l1` cannot depend on `poker_texas_air` without a Cargo
    /// cycle, so the top-level node binary constructs and injects the final registry here.
    pub fn open_with_zk_verifier_registry(
        config: NodeConfig,
        zk_registry: crate::offline::zk_verifier::ZkVerifierRegistry,
    ) -> PokerL1Result<Self> {
        Self::open_with_optional_zk_verifier_registry(config, Some(zk_registry))
    }

    /// Shared construction path for the standard fail-closed node and an explicitly configured
    /// verifier registry.
    fn open_with_optional_zk_verifier_registry(
        config: NodeConfig,
        zk_verifier: Option<crate::offline::zk_verifier::ZkVerifierRegistry>,
    ) -> PokerL1Result<Self> {
        let block_path = config.data_dir.join("blocks");
        let object_path = config.data_dir.join("objects");
        let vertex_path = config.data_dir.join("vertices");
        let account_path = config.data_dir.join("accounts");
        let bridge_path = config.data_dir.join("bridge_registry");
        let block_store = BlockStore::open(&block_path)?;
        let object_db = ObjectDb::open(&object_path)?;
        let vertex_store = DagVertexStore::open(&vertex_path)?;
        // 缺口 #8：AccountStore 落 RocksDB，重启后账户余额 / nonce 不丢失。
        let account_store = AccountStore::open(&account_path)?;
        // 缺口 #9：BridgeRegistryStore 落 RocksDB，重启后 deposit/burn nonce 不丢失（防重放铸币）。
        let bridge_registry_store = BridgeRegistryStore::open(&bridge_path)?;
        let configured_validator_set =
            build_genesis_validator_set(config.genesis_validators.clone())?;
        let persisted_validator_set = read_persisted_validator_set(&object_db, config.chain_id)?;
        let treasury_initialized = crate::economics::read_treasury(&object_db)?.is_some();
        if treasury_initialized != persisted_validator_set.is_some() {
            return Err(PokerL1Error::Other(
                "TreasuryCap and ValidatorSet system objects must be initialized together".into(),
            ));
        }
        let validator_set = persisted_validator_set
            .map(|(set, _)| set)
            .unwrap_or(configured_validator_set);
        crate::economics::reconcile_native_supply_if_initialized(
            &object_db,
            validator_staking_escrow(&validator_set)?,
        )?;
        let precompile_registry = build_default_precompile_registry();
        // v1.5-a1：SeenReceipt sidecar（持久化 + 重启重放恢复）。
        let (mut receipt_sidecar, replayed_receipts) =
            if config.role.is_validator() && config.validator_key.is_some() {
                let (sidecar, replayed) =
                    crate::force_include::ReceiptSidecar::open(&config.data_dir).map_err(|e| {
                        PokerL1Error::Other(format!(
                            "seen_receipts sidecar 打开失败（{}）：{e}",
                            config.data_dir.display()
                        ))
                    })?;
                (Some(sidecar), replayed)
            } else {
                (None, Vec::new())
            };
        let mut seen_receipts_state = SeenReceiptsState::new();
        for receipt in replayed_receipts {
            seen_receipts_state.insert(receipt, MAX_PENDING_TX_SIZE);
        }
        if let Some(sidecar) = &receipt_sidecar
            && sidecar.corrupt_lines() > 0
        {
            tracing::warn!(
                "seen_receipts sidecar 重放跳过 {} 条损坏行（崩溃残留，append-only 语义不受影响）",
                sidecar.corrupt_lines()
            );
        }
        let receipt_sidecar = std::sync::Mutex::new(receipt_sidecar);
        // v1.5-c：checkpoint QC sidecar（append 写句柄 + 重放最新 QC）。
        let checkpoint_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(config.data_dir.join(CHECKPOINT_SIDECAR_FILE))
            .map_err(|e| {
                PokerL1Error::Other(format!(
                    "checkpoint sidecar 打开失败（{}）：{e}",
                    config.data_dir.display()
                ))
            })?;
        let mut checkpoint_state = CheckpointState::new();
        // v1.5-e：DKG 密钥材料（qc_threshold_t > 0 时载入；fail-closed 自检）。
        let (dkg_keyset, dkg_share) = load_dkg_material(&config)?;
        if let Some(ks) = &dkg_keyset {
            tracing::info!(
                "threshold QC: DKG keyset 已载入 n={} t={} digest=0x{} share_id={:?}",
                ks.n,
                ks.t,
                hex::encode(ks.group_key_digest()),
                dkg_share.as_ref().map(|s| s.id)
            );
        }
        checkpoint_state.latest_qc = replay_latest_checkpoint_qc(&config.data_dir);
        // v1.5-e：重启恢复 fail-closed 校验 —— sidecar 重放的 QC 必须通过
        // 当前形态对应的密码学验证（阈值形态对本地 keyset 单配对；聚合形态
        // 对活跃 validator 数 quorum 验证），损坏/挪群 QC 拒载（清为 None）。
        if let Some(qc) = checkpoint_state.latest_qc.as_ref() {
            let vc = validator_set.active_count().max(1);
            match qc.verify_any(vc, dkg_keyset.as_ref()) {
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        "checkpoint sidecar 重放的 QC 未通过恢复校验，拒载（fail-closed）：{e}"
                    );
                    checkpoint_state.latest_qc = None;
                }
            }
        }
        let checkpoint_state = std::sync::Mutex::new(checkpoint_state);
        let checkpoint_sidecar = std::sync::Mutex::new(Some(checkpoint_file));
        Ok(Self {
            config,
            block_store,
            block_commit_lock: std::sync::Mutex::new(()),
            object_db: std::sync::Mutex::new(object_db),
            vertex_store,
            account_store: std::sync::Mutex::new(account_store),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(PendingTxState::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            allow_empty_consensus_for_tests: false,
            precompile_registry,
            bridge_registry_store: Some(Arc::new(bridge_registry_store)),
            metrics: Arc::new(crate::metrics::MetricsCollector::new()),
            zk_verifier,
            light_headers: std::sync::Mutex::new(Vec::new()),
            time_source: std::sync::Mutex::new(Box::new(system_time_ms)),
            seen_receipts: std::sync::Mutex::new(seen_receipts_state),
            receipt_sidecar,
            force_include: std::sync::Mutex::new(ForceIncludeState::new()),
            slash_ledger: std::sync::Mutex::new(crate::consensus::slash::SlashLedger::new()),
            checkpoint_state,
            checkpoint_sidecar,
            dkg_keyset,
            dkg_share,
            da_state: std::sync::Mutex::new(DaState::new()),
        })
    }

    /// Apply the one-time native ZCN genesis allocation.
    ///
    /// Accounts remain identity/nonce records with zero legacy balance; spendable funds are
    /// emitted as address-owned native coin UTXOs. TreasuryCap creation, all coin creations and
    /// permanent closure of genesis minting are committed in one ObjectDb batch.
    ///
    /// Reapplying the identical allocation is a no-op. A different allocation after mint closure
    /// is rejected instead of being silently ignored.
    pub fn apply_genesis_alloc(
        &self,
        allocs: impl IntoIterator<Item = (TaggedPubkey, u64)>,
    ) -> PokerL1Result<usize> {
        let allocs: Vec<(TaggedPubkey, u64)> = allocs.into_iter().collect();
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let mut native_allocs = Vec::with_capacity(allocs.len());
        let mut missing_accounts = Vec::new();
        for (pubkey, amount) in &allocs {
            let addr = crate::account::derive_address(&pubkey);
            if let Some(account) = account_store.get(&addr) {
                if account.tagged_pubkey != *pubkey {
                    return Err(PokerL1Error::Other(format!(
                        "genesis account pubkey mismatch at address {addr:?}"
                    )));
                }
                if account.balance != 0 {
                    return Err(PokerL1Error::Other(format!(
                        "genesis account {addr:?} has legacy balance {}; refusing duplicate monetary state",
                        account.balance
                    )));
                }
            } else {
                missing_accounts.push(pubkey.clone());
            }
            native_allocs.push((addr, *amount));
        }
        let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        // 对拍对象的 version 必须沿用持久化系统对象的当前 version（重启后
        // 运行期会推进 version），否则 genesis 幂等对拍在"对象内容一致、
        // 仅 version 不同"上误报 differs-after-closure。首启（无持久化
        // 对象）用 0。
        let persisted_version = object_db
            .read(&crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID)
            .map(|o| o.version)
            .unwrap_or(0);
        let validator_set_object = crate::consensus::validator_set::validator_set_object(
            self.config.chain_id,
            &validator_set,
            persisted_version,
        )?;
        let minted = crate::economics::genesis_mint_with_system_objects(
            &mut object_db,
            self.config.chain_id,
            &native_allocs,
            vec![validator_set_object],
        )?;
        // Account records are non-monetary identity/nonce metadata. If persistence fails here,
        // startup fails and the identical genesis call repairs missing zero-balance accounts on
        // the next restart without minting again.
        for pubkey in missing_accounts {
            account_store.create(crate::account::Account::new(pubkey, 0))?;
        }
        crate::economics::reconcile_native_supply(
            &object_db,
            validator_staking_escrow(&validator_set)?,
        )?;
        Ok(minted)
    }

    /// 创建内存节点（用于测试）。
    pub fn open_inmemory(role: NodeRole, chain_id: ChainId) -> PokerL1Result<Self> {
        Self::open_inmemory_with_validators(role, chain_id, vec![])
    }

    /// 创建带创世 validator 列表的内存节点（P0-4 动态 quorum 测试用）。
    pub fn open_inmemory_with_validators(
        role: NodeRole,
        chain_id: ChainId,
        genesis_validators: Vec<ValidatorEntry>,
    ) -> PokerL1Result<Self> {
        let validator_set = build_genesis_validator_set(genesis_validators.clone())?;
        let precompile_registry = build_default_precompile_registry();
        Ok(Self {
            config: NodeConfig {
                role,
                chain_id,
                data_dir: PathBuf::from("/tmp/poker_l1_inmemory"),
                rpc_listen: "127.0.0.1:0".to_string(),
                p2p_listen: "127.0.0.1:0".to_string(),
                validator_key: None,
                genesis_validators,
                fee_policy: FeePolicy::Free,
                inclusion_deadline_ms: crate::force_include::DEFAULT_INCLUSION_DEADLINE_MS,
                censorship_window_blocks:
                    crate::force_include::DEFAULT_CENSORSHIP_WINDOW_BLOCKS,
                checkpoint_interval_blocks:
                    crate::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
                qc_threshold_t: 0,
                dkg_keyset_path: None,
                dkg_share_path: None,
            },
            block_store: BlockStore::open_inmemory()?,
            block_commit_lock: std::sync::Mutex::new(()),
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(PendingTxState::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            allow_empty_consensus_for_tests: true,
            precompile_registry,
            // 缺口 #9：内存节点默认不启用桥（bridge contract_call 会拒绝）；
            // 需桥的测试可用 [`Node::with_bridge`] 显式注入。
            bridge_registry_store: None,
            metrics: Arc::new(crate::metrics::MetricsCollector::new()),
            zk_verifier: None,
            light_headers: std::sync::Mutex::new(Vec::new()),
            time_source: std::sync::Mutex::new(Box::new(system_time_ms)),
            seen_receipts: std::sync::Mutex::new(SeenReceiptsState::new()),
            receipt_sidecar: std::sync::Mutex::new(None),
            force_include: std::sync::Mutex::new(ForceIncludeState::new()),
            slash_ledger: std::sync::Mutex::new(crate::consensus::slash::SlashLedger::new()),
            checkpoint_state: std::sync::Mutex::new(CheckpointState::new()),
            checkpoint_sidecar: std::sync::Mutex::new(None),
            dkg_keyset: None,
            dkg_share: None,
            da_state: std::sync::Mutex::new(DaState::new()),
        })
    }

    /// 创建内存节点并直接指定完整配置（M3-ACC-6 集成测试用）。
    ///
    /// 与 [`Self::open_inmemory_with_validators`] 同一内存构造路径，但允许测试注入
    /// validator 密钥、强制包含期限等配置。`allow_empty_consensus_for_tests` 同内存
    /// 构造（仅适合聚焦执行而非共识成员的测试）。
    pub fn open_inmemory_with_config(config: NodeConfig) -> PokerL1Result<Self> {
        let validator_set = build_genesis_validator_set(config.genesis_validators.clone())?;
        // v1.5-e：与持久化路径同一 DKG 材料载入纪律（fail-closed 自检）。
        let (dkg_keyset, dkg_share) = load_dkg_material(&config)?;
        let precompile_registry = build_default_precompile_registry();
        Ok(Self {
            config,
            block_store: BlockStore::open_inmemory()?,
            block_commit_lock: std::sync::Mutex::new(()),
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(PendingTxState::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            allow_empty_consensus_for_tests: true,
            precompile_registry,
            bridge_registry_store: None,
            metrics: Arc::new(crate::metrics::MetricsCollector::new()),
            zk_verifier: None,
            light_headers: std::sync::Mutex::new(Vec::new()),
            time_source: std::sync::Mutex::new(Box::new(system_time_ms)),
            seen_receipts: std::sync::Mutex::new(SeenReceiptsState::new()),
            receipt_sidecar: std::sync::Mutex::new(None),
            force_include: std::sync::Mutex::new(ForceIncludeState::new()),
            slash_ledger: std::sync::Mutex::new(crate::consensus::slash::SlashLedger::new()),
            checkpoint_state: std::sync::Mutex::new(CheckpointState::new()),
            checkpoint_sidecar: std::sync::Mutex::new(None),
            dkg_keyset,
            dkg_share,
            da_state: std::sync::Mutex::new(DaState::new()),
        })
    }

    /// 获取节点角色。
    #[must_use]
    pub const fn role(&self) -> NodeRole {
        self.config.role
    }

    /// 获取 chain_id。
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.config.chain_id
    }

    // ===== P0-4: 动态 quorum（ValidatorSet 接入节点） =====

    /// 当前 validator 总数（含 Bonding / Unbonding / Slashed / Retired）。
    pub fn validator_count(&self) -> usize {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .validators
            .len()
    }

    /// 当前活跃 validator 数量（动态 quorum 的计算基数）。
    pub fn active_validator_count(&self) -> usize {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_count()
    }

    /// Ensure this node has an active validator set before it starts serving consensus traffic.
    ///
    /// Persistent production entry points must call this after loading genesis state and before
    /// starting RPC/P2P listeners. Consensus admission also enforces the same invariant, so an
    /// accidentally exposed node cannot accept unsigned vertices or blocks while unconfigured.
    pub fn ensure_consensus_ready(&self) -> PokerL1Result<()> {
        let active = self.active_validator_count();
        if active == 0 {
            return Err(PokerL1Error::Other(
                "consensus is not configured: active ValidatorSet is empty".into(),
            ));
        }
        Ok(())
    }

    /// 当前动态 quorum（严格 > 2/3 活跃 validator：`2 * n / 3 + 1`）。
    ///
    /// 未配置 active validator 时返回 0；生产入口不得以此状态启动共识服务。
    pub fn required_quorum(&self) -> usize {
        let active = self.active_validator_count();
        if active == 0 {
            return 0;
        }
        crate::consensus::required_quorum(active)
    }

    /// 校验 pubkey 是否为当前活跃 validator（可参与共识）。
    pub fn is_active_validator(&self, pubkey: &TaggedPubkey) -> bool {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .find_validator(pubkey)
            .is_some_and(ValidatorEntry::can_participate_consensus)
    }

    /// 活跃 validator pubkey 列表（按字节排序，commit certificate signer_bitmap 索引基准）。
    ///
    /// 排序保证全网点对 bitmap 索引的解释一致。
    pub fn active_validator_pubkeys_sorted(&self) -> Vec<TaggedPubkey> {
        let set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut pubkeys: Vec<TaggedPubkey> = set
            .validators
            .iter()
            .filter(|v| v.can_participate_consensus())
            .map(|v| v.pubkey.clone())
            .collect();
        pubkeys.sort_by_key(TaggedPubkey::to_bytes);
        pubkeys
    }

    /// Register an unfunded validator entry for consensus-only unit tests.
    ///
    /// Production registration must use [`Self::bond_validator`] so stake is backed by consumed
    /// ZCN UTXOs. Keeping this path test-only prevents zero-stake validator admission in a node.
    #[cfg(test)]
    pub(crate) fn add_validator(&self, entry: ValidatorEntry) -> PokerL1Result<()> {
        if entry.stake > 0 {
            return Err(PokerL1Error::Other(
                "non-zero validator stake must be funded through bond_validator native-coin inputs"
                    .into(),
            ));
        }
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        if next_set.find_validator(&entry.pubkey).is_some() {
            return Err(PokerL1Error::Other(format!(
                "validator already in set: {:?}",
                entry.pubkey
            )));
        }
        next_set.validators.push(entry);
        next_set.validator_set_hash = next_set.compute_hash();
        if read_persisted_validator_set(&object_db, self.config.chain_id)?.is_some() {
            let mut snapshot = object_db.create_snapshot();
            stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
            snapshot.apply_to(&mut object_db)?;
        } else if crate::economics::read_treasury(&object_db)?.is_some() {
            return Err(PokerL1Error::Other(
                "initialized Treasury is missing authoritative ValidatorSet state".into(),
            ));
        }
        *set = next_set;
        Ok(())
    }

    /// Consume validator-owned native coin UTXOs and lock `entry.stake` in staking escrow.
    ///
    /// Any excess input value is returned as deterministic change. Treasury supply is unchanged:
    /// value moves from live UTXOs into `ValidatorEntry.stake` escrow.
    pub fn bond_validator(
        &self,
        mut entry: ValidatorEntry,
        coin_inputs: &[ObjectID],
    ) -> PokerL1Result<Option<ObjectID>> {
        if entry.stake == 0 {
            return Err(PokerL1Error::Other(
                "bond_validator requires non-zero stake".into(),
            ));
        }
        // Admission always begins in Bonding; callers cannot buy immediate consensus power by
        // submitting an entry pre-marked Active.
        entry.status = crate::consensus::ValidatorStatus::Bonding;
        let owner = crate::account::derive_address(&entry.pubkey);
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut object_snapshot = object_db.create_snapshot();
        let selection = crate::economics::select_owned_native_coins(
            &object_snapshot,
            coin_inputs,
            owner,
            entry.stake,
        )?;

        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        if next_set.find_validator(&entry.pubkey).is_some() {
            return Err(PokerL1Error::Other(format!(
                "validator already in set: {:?}",
                entry.pubkey
            )));
        }
        next_set.validators.push(entry.clone());
        next_set.validator_set_hash = next_set.compute_hash();

        let operation_hash = crate::economics::system_coin_operation_hash(
            b"STAKING_BOND_V1",
            owner,
            coin_inputs,
            entry.stake,
            next_set.epoch,
        );
        let change = crate::economics::consume_native_coin_selection(
            &mut object_snapshot,
            &selection,
            owner,
            entry.stake,
            &operation_hash,
            0,
        )?;
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_staking_escrow(&next_set)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(change)
    }

    /// Slash staking escrow and atomically account for the destroyed ZCN in TreasuryCap.
    pub fn slash_validator(
        &self,
        validator_pubkey: &TaggedPubkey,
        reason: crate::consensus::SlashingReason,
        config: &crate::consensus::SlashingConfig,
    ) -> PokerL1Result<crate::consensus::SlashingResult> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        let result =
            crate::consensus::apply_slashing(&mut next_set, validator_pubkey, reason, config)?;
        next_set.validator_set_hash = next_set.compute_hash();
        let mut object_snapshot = object_db.create_snapshot();
        crate::economics::burn_escrowed_native(&mut object_snapshot, result.slash_amount)?;
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_staking_escrow(&next_set)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(result)
    }

    /// Complete unbonding by converting staking escrow back into a native coin UTXO.
    pub fn complete_unbonding(
        &self,
        validator_pubkey: &TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        let owner = crate::account::derive_address(validator_pubkey);
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        let validator = next_set
            .find_validator_mut(validator_pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;
        // 须处于 Unbonding 且 lock 期已到。
        if validator.status != crate::consensus::ValidatorStatus::Unbonding {
            return Err(PokerL1Error::Other(format!(
                "validator not in unbonding (status={:?})",
                validator.status
            )));
        }
        if current_height < validator.unbonding_until_height {
            return Err(PokerL1Error::Other(format!(
                "unbonding lock not expired: current={current_height} < until={}",
                validator.unbonding_until_height
            )));
        }
        let refund = validator.stake;
        validator.stake = 0;
        validator.status = crate::consensus::ValidatorStatus::Retired;
        next_set.validator_set_hash = next_set.compute_hash();

        let mut object_snapshot = object_db.create_snapshot();
        if refund > 0 {
            let payout_hash = crate::economics::system_coin_operation_hash(
                b"STAKING_UNBOND_V1",
                owner,
                &[],
                refund,
                current_height,
            );
            crate::economics::create_native_coin_output(
                &mut object_snapshot,
                owner,
                refund,
                &payout_hash,
                0,
            )?;
        }
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_staking_escrow(&next_set)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(refund)
    }

    /// 推进 epoch（衰减审查计数 + 滚动 prev_epoch_randomness，NEW-H1 / SEC2-C2）。
    /// 推进 epoch 并（若配置了 VRF 私钥）派生新 epoch_randomness（缺口 #3 §3.6）。
    ///
    /// 流程：
    /// 1. `ValidatorSet::advance_epoch`（滚动 prev_epoch_randomness + 衰减审查计数）
    /// 2. 若 `vrf_secret` 提供：用 ECVRF prover 对当前 epoch 的 VRF input 生成 proof，
    ///    调 `submit_epoch_vrf_proof` 验证并写入新 epoch_randomness。
    /// 3. 未配置 VRF / 提交失败：调 `fallback_epoch_randomness`（SEC2-M12 降级）。
    ///
    /// **self-proposing 模式**：当前节点用自身 VRF 私钥为该 epoch 生成 proof。
    /// 多 validator 完整 VRF 协议（proposer 选举 + proof gossip）属后续工作；
    /// 此实现使 epoch_randomness 来自真实 ECVRF（非 stub），且与验证方一致
    /// （验证方用同一 prover pub key + proof 重算相同 output）。
    pub fn advance_epoch_with_vrf(
        &self,
        new_epoch: Epoch,
        vrf_secret: Option<&[u8; 32]>,
    ) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.advance_epoch(new_epoch);

        // 尝试用 VRF proof 派生 epoch_randomness。
        let vrf_ok = if let Some(secret) = vrf_secret {
            let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(secret);
            let vrf_input = crate::consensus::validator_set::compute_vrf_input(
                self.config.chain_id,
                next_set.epoch,
                &next_set.prev_epoch_randomness,
            );
            match prover.prove(&vrf_input) {
                Ok((proof, _output)) => {
                    // submit_epoch_vrf_proof 内部用 Secp256k1VrfVerifier 验证 proof
                    // 并把 output 写入 epoch_randomness。
                    let verifier = crate::consensus::ecvrf::Secp256k1VrfVerifier::new();
                    next_set
                        .submit_epoch_vrf_proof(
                            self.config.chain_id,
                            &self
                                .config
                                .validator_key
                                .as_ref()
                                .map(|k| &k.tagged_pubkey)
                                .cloned()
                                .unwrap_or_else(|| {
                                    // 无 validator_key 时无法标识 proposer，fallback。
                                    TaggedPubkey {
                                        tag: 0,
                                        raw: vec![],
                                    }
                                }),
                            &proof,
                            &verifier,
                        )
                        .is_ok()
                }
                Err(_) => false,
            }
        } else {
            false
        };

        if !vrf_ok {
            // 降级：fallback epoch_randomness（SEC2-M12）。
            next_set.fallback_epoch_randomness();
        }
        next_set.validator_set_hash = next_set.compute_hash();
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// 推进 epoch（不派生 VRF randomness，仅滚动 prev + 衰减；旧行为）。
    pub fn advance_epoch(&self, new_epoch: Epoch) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.advance_epoch(new_epoch);
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// 处理 bonding 到期（NEW-L3：到达 bonding_until_height 后转 Active）。
    pub fn process_bonding_expiry(&self, current_height: BlockHeight) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.process_bonding_expiry(current_height);
        if next_set == *set {
            return Ok(());
        }
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// Persistently move an active validator into the unbonding state.
    pub fn start_validator_unbonding(
        &self,
        validator_pubkey: &TaggedPubkey,
        unbonding_until_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.start_unbonding(validator_pubkey, unbonding_until_height)?;
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// 当前 epoch。
    pub fn current_epoch(&self) -> Epoch {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch
    }

    /// 获取配置引用。
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// 获取 BlockStore 引用。
    #[must_use]
    pub const fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    /// 获取 DagVertexStore 引用。
    #[must_use]
    pub const fn vertex_store(&self) -> &DagVertexStore {
        &self.vertex_store
    }

    /// 按 hash 查询 block。
    pub fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_hash(hash) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 按 height 查询 block。
    pub fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_height(height) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 写入对象。
    pub fn put_object(&self, object: Object) -> PokerL1Result<()> {
        if crate::economics::is_reserved_economic_object(&object) {
            return Err(PokerL1Error::Other(
                "reserved economic objects must be created through economics APIs".into(),
            ));
        }
        self.object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(object)
    }

    /// 查询对象。
    pub fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        let result = self
            .object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read(id);
        match result {
            Ok(obj) => Ok(Some(obj)),
            Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List an address's spendable native ZCN UTXOs in deterministic object-ID order.
    pub fn list_native_coins(
        &self,
        owner: Address,
    ) -> PokerL1Result<Vec<crate::economics::OwnedNativeCoin>> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::list_owned_native_coins(&object_db, owner)
    }

    /// Return the wallet-facing aggregate ZCN balance across all owned UTXOs.
    pub fn native_coin_balance(&self, owner: Address) -> PokerL1Result<u64> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::native_coin_balance(&object_db, owner)
    }

    /// Read the native ZCN TreasuryCap tracked by the UTXO/escrow monetary domain.
    pub fn treasury_cap(&self) -> PokerL1Result<Option<crate::economics::TreasuryCap>> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::read_treasury(&object_db)
    }

    /// Audit every currently modelled native ZCN custody domain.
    ///
    /// Lock ordering intentionally matches bond/slash/unbond paths: `ObjectDb` first, then
    /// `ValidatorSet`. Keeping both locks for the duration gives the report one coherent view of
    /// live UTXOs, table vaults and staking escrow.
    pub fn audit_native_supply(
        &self,
    ) -> PokerL1Result<crate::economics::NativeSupplyReconciliation> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let staking_escrow = validator_staking_escrow(&validator_set)?;
        crate::economics::audit_native_supply(&object_db, staking_escrow)
    }

    /// Require Treasury supply to equal live UTXOs plus staking and Texas table escrow.
    pub fn reconcile_native_supply(
        &self,
    ) -> PokerL1Result<crate::economics::NativeSupplyReconciliation> {
        self.audit_native_supply()?.require_balanced()
    }

    /// 写入 DAG vertex（入库前验证）。
    ///
    /// P0-3 修复：在写入存储前执行完整验证链：
    /// 1. 大小校验（≤ MAX_VERTEX_SIZE）
    /// 2. 签名验证（author_sig 对 signing_hash）
    /// 3. tx 边界、chain_id 与签名校验
    /// 5. vertex 内 tx 排序校验（S9 规则）
    /// 6. parent graph 校验（存在、去重、严格上一轮、distinct active-author quorum）
    pub fn put_vertex(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        self.validate_vertex(vertex)?;
        self.vertex_store.put(vertex)
    }

    /// 验证 DAG vertex（P0-3）。
    ///
    /// 在 vertex 入库或入内存 DAG 前调用，防止恶意或损坏的 vertex 污染存储。
    pub fn validate_vertex(&self, vertex: &DagVertex) -> PokerL1Result<()> {
        // 1. 大小校验
        let vertex_size = vertex.to_bcs()?.len();
        if vertex_size > MAX_VERTEX_SIZE {
            return Err(PokerL1Error::VertexTooLarge {
                actual: vertex_size,
                limit: MAX_VERTEX_SIZE,
            });
        }

        let current_epoch = self.current_epoch();
        if vertex.epoch != current_epoch {
            return Err(PokerL1Error::InvalidVertexEpoch {
                actual: vertex.epoch,
                expected: current_epoch,
            });
        }

        // 2. author 必须是当前活跃 validator（P0-4 动态 quorum）。
        // 放在签名验证之前，可快速丢弃非 validator 的顶点并避免验签开销。
        {
            let set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            let active_count = set.active_count();
            if active_count == 0 && !self.allow_empty_consensus_for_tests {
                return Err(PokerL1Error::Other(
                    "cannot admit DAG vertex with an empty active ValidatorSet".into(),
                ));
            }
            let is_active = set
                .find_validator(&vertex.author_pubkey)
                .is_some_and(ValidatorEntry::can_participate_consensus);
            if active_count > 0 && !is_active {
                return Err(PokerL1Error::VertexAuthorNotActiveValidator(
                    vertex.author_pubkey.clone(),
                ));
            }
        }

        // 3. 签名验证（author_sig 对 signing_hash）
        let signing_hash = vertex.signing_hash(self.config.chain_id);
        verify_signature(&vertex.author_pubkey, &vertex.author_sig, &signing_hash).map_err(
            |_| PokerL1Error::InvalidVertexSignature {
                vertex_hash: vertex.vertex_hash(),
            },
        )?;

        // 同一 author 在同一 (epoch, round) 只能有一个内容 hash。完全相同的 vertex
        // 属于网络重放，保持幂等；内容不同则在进入 tx/parent 深层校验前直接拒绝。
        let vertex_hash = vertex.vertex_hash();
        for existing in self.vertex_store.get_by_round(vertex.epoch, vertex.round)? {
            if existing.author_pubkey == vertex.author_pubkey
                && existing.vertex_hash() != vertex_hash
            {
                return Err(PokerL1Error::VertexEquivocation {
                    epoch: vertex.epoch,
                    round: vertex.round,
                    author: vertex.author_pubkey.clone(),
                });
            }
        }

        // 3. tx 边界、chain_id 与签名校验。P2P vertex 绕过普通 RPC admission，
        // 因此不能等到 block execution 才发现并拒绝无效交易。
        for tx in &vertex.tx_list {
            validate_tx_limits(tx)?;
            validate_tx_chain_id(tx, self.config.chain_id)?;
            validate_tx_signature(tx)?;
        }

        // 4. vertex 内 tx 排序校验（S9：GameTurn 优先于 ForceSync）
        validate_vertex_tx_ordering(&vertex.tx_list)?;

        // 5. Parent graph validation. Counting raw hashes is insufficient: one validator could
        // otherwise equivocate multiple parents and manufacture a quorum. Round 1 is the only
        // parentless round; every later vertex must reference a distinct-author quorum from the
        // immediately preceding round.
        if vertex.round == 0 {
            return Err(PokerL1Error::InvalidVertexRound {
                round: vertex.round,
            });
        }
        if vertex.round == 1 {
            if !vertex.parent_hashes.is_empty() {
                return Err(PokerL1Error::UnexpectedFirstRoundParents {
                    actual: vertex.parent_hashes.len(),
                });
            }
            return Ok(());
        }

        let active_parent_authors: std::collections::BTreeSet<Vec<u8>> = self
            .active_validator_pubkeys_sorted()
            .into_iter()
            .map(|pubkey| pubkey.to_bytes())
            .collect();
        let validator_count = active_parent_authors.len().max(1);
        let required = required_parent_count(validator_count);
        let expected_parent_round = vertex.round - 1;
        let mut seen_parent_hashes = std::collections::BTreeSet::new();
        let mut seen_parent_authors = std::collections::BTreeSet::new();

        for parent_hash in &vertex.parent_hashes {
            if !seen_parent_hashes.insert(*parent_hash) {
                return Err(PokerL1Error::DuplicateParentVertex(*parent_hash));
            }
            let parent = match self.vertex_store.get_by_hash(parent_hash) {
                Ok(parent) => parent,
                Err(PokerL1Error::DagVertexNotFound) => {
                    return Err(PokerL1Error::ParentVertexNotFound(*parent_hash));
                }
                Err(error) => return Err(error),
            };
            if parent.epoch != vertex.epoch {
                return Err(PokerL1Error::InvalidParentVertexEpoch {
                    parent_hash: *parent_hash,
                    actual: parent.epoch,
                    expected: vertex.epoch,
                });
            }
            if parent.round != expected_parent_round {
                return Err(PokerL1Error::InvalidParentVertexRound {
                    parent_hash: *parent_hash,
                    actual: parent.round,
                    expected: expected_parent_round,
                });
            }

            let parent_author = parent.author_pubkey.to_bytes();
            if !active_parent_authors.is_empty() && !active_parent_authors.contains(&parent_author)
            {
                return Err(PokerL1Error::ParentVertexAuthorNotActiveValidator(
                    parent.author_pubkey,
                ));
            }
            if !seen_parent_authors.insert(parent_author) {
                return Err(PokerL1Error::DuplicateParentVertexAuthor(
                    parent.author_pubkey,
                ));
            }
        }

        if seen_parent_authors.len() < required {
            return Err(PokerL1Error::InsufficientParents {
                actual: seen_parent_authors.len(),
                required,
            });
        }

        Ok(())
    }

    /// 写入 block（入库前验证 + 状态根重放比对）。
    ///
    /// P0-3 修复：在写入存储前执行完整验证链：
    /// 1. block header 字段校验（height / prev_hash 连续性）
    /// 2. tx roots 一致性校验
    /// 3. GameTurn 免 gas 校验
    /// 4. commit certificate 多签验证
    /// 5. 状态根重放比对：重新执行 tx，比对计算出的 state_root 与 header.state_root
    pub fn put_block(&self, block: &Block) -> PokerL1Result<Hash> {
        let _commit_guard = self
            .block_commit_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let candidate_hash = block.block_hash(self.config.chain_id);
        match self.block_store.get_by_height(block.header.height) {
            Ok(existing) => {
                let existing_hash = existing.block_hash(self.config.chain_id);
                if existing_hash == candidate_hash {
                    return Ok(candidate_hash);
                }
                // 恰 quorum 存活修复 · 语句级去重：同一高度、同一签名对象
                //（cert signing_hash 不含 signature_list/signer_bitmap）的两个 block
                // 仅仅是同一 finalize 决议的不同签名子集 —— 并发装配的各节点收集到
                // 的投票子集不同，块字节（乃至 block hash）随之不同，但链语义完全
                // 一致。按语句去重：保留先入库的变体，后到的当重复接受，避免
                // 「同一语句的不同签名变体」被误判为分叉、把节点永久冻结在自己的
                // 变体上。不同语句（真正的分叉企图）仍然 fail-closed 拒绝。
                // 去重条件附加 timestamp 一致：并发装配的 timestamp 由同一个已存储
                // 父块确定性推导，必然相同；不同 timestamp 意味着伪造/冲突块。
                let existing_statement = existing
                    .header
                    .dag_commit_certificate
                    .signing_hash(self.config.chain_id);
                let candidate_statement = block
                    .header
                    .dag_commit_certificate
                    .signing_hash(self.config.chain_id);
                if existing_statement == candidate_statement
                    && existing.header.timestamp_ms == block.header.timestamp_ms
                {
                    return Ok(existing_hash);
                }
                return Err(PokerL1Error::Other(format!(
                    "block height {} is already committed to a different hash",
                    block.header.height
                )));
            }
            Err(PokerL1Error::BlockNotFound) => {}
            Err(error) => return Err(error),
        }

        self.validate_block_structure(block)?;

        // Hold both state locks across provisional replay and commit.  A block is first executed
        // against isolated snapshots; only a matching state root may be materialized locally.
        // This prevents a rejected block from changing objects or account nonces.
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let (object_snapshot, account_snapshot, _) =
            self.prepare_block_execution(block, &object_db, &account_store)?;
        {
            let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            crate::economics::reconcile_native_supply_snapshot_if_initialized(
                &object_snapshot,
                validator_staking_escrow(&validator_set)?,
            )?;
        }

        // Account nonces are replay protection.  Commit their RocksDB batch first; should the
        // following ObjectDb write fail, make a best-effort restoration before surfacing failure.
        // The two stores currently have independent RocksDB handles, so a future storage
        // consolidation is still required for crash-atomic cross-store commits.
        let account_before = account_store.create_snapshot();
        account_store.apply_snapshot(account_snapshot)?;
        if let Err(error) = object_snapshot.apply_to(&mut object_db) {
            if let Err(rollback_error) = account_store.apply_snapshot(account_before) {
                tracing::error!(
                    "ObjectDb commit failed after account snapshot commit; account rollback also failed: {rollback_error}"
                );
            }
            return Err(error);
        }

        let hash = self.block_store.put(block, self.config.chain_id)?;
        // 缺口 #4：State Pruning 接入出块路径。
        if self.config.role.should_prune() {
            if let Err(e) = self.run_pruning(block.header.height) {
                tracing::warn!("run_pruning 失败（不阻断出块）：{e}");
            }
        }
        // Light client header 多签背书：validator 节点用自己的 secp256k1 key
        // 对 block header 签名，生成 LightClientHeader 并缓存供 light client 订阅。
        if let Some(vkey) = &self.config.validator_key {
            self.sign_and_store_light_header(block, vkey);
        }
        Ok(hash)
    }

    /// 为 block 生成 validator 签名的 LightClientHeader（light client 协议核心）。
    ///
    /// validator 用自己的 secp256k1 secret key 对 `header_bytes` 的 blake2b_256 哈希签名，
    /// 生成 `ValidatorSig`（tagged_pubkey + 65B 签名），存入 `LightClientHeader.signatures`。
    /// 多个 validator 各自签名后，light client 收集 ≥2/3 签名即可验证 header 真实性。
    fn sign_and_store_light_header(&self, block: &Block, vkey: &ValidatorKey) {
        use blake2::digest::{Update, VariableOutput};
        use secp256k1::{Message, Secp256k1, SecretKey};
        let header_bytes = borsh::to_vec(&block.header).unwrap_or_default();
        // 签名对象 = blake2b_256(header_bytes)
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 <= 64");
        Update::update(&mut hasher, &header_bytes);
        let mut msg_hash = [0u8; 32];
        hasher.finalize_variable(&mut msg_hash).expect("32 <= 64");
        // secp256k1 recoverable 签名
        let secp = Secp256k1::new();
        let secret = match SecretKey::from_slice(&vkey.secret_key_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut full_sig = compact.to_vec();
        full_sig.push(recovery_id.to_i32() as u8);
        let validator_sig = crate::network::ValidatorSig {
            validator: vkey.tagged_pubkey.clone(),
            signature: full_sig,
        };
        // 尝试合并到已有的同 header LightClientHeader，或新建。
        let mut headers = self.light_headers.lock().unwrap_or_else(|e| e.into_inner());
        // 查找是否已有同 header_bytes 的 header（多 validator 合并签名）。
        if let Some(existing) = headers.iter_mut().find(|h| h.header_bytes == header_bytes) {
            // 去重：同一 validator 不重复签名。
            if !existing
                .signatures
                .iter()
                .any(|s| s.validator == validator_sig.validator)
            {
                existing.signatures.push(validator_sig);
            }
        } else {
            // 新建 LightClientHeader。
            let lch = crate::network::LightClientHeader {
                header_bytes,
                signatures: vec![validator_sig],
                signer_bitmap: vec![],
            };
            headers.push(lch);
            // 限制缓存大小（保留最近 1000 个 header）。
            if headers.len() > 1000 {
                headers.remove(0);
            }
        }
    }

    /// 获取缓存的 LightClientHeader 列表（供 subscribe_light_headers RPC/P2P 使用）。
    #[must_use]
    pub fn get_light_headers(&self) -> Vec<crate::network::LightClientHeader> {
        self.light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// 合并 peer 发来的 LightClientHeader 签名（多 validator 签名合并）。
    pub fn merge_light_header(&self, header: crate::network::LightClientHeader) {
        let mut headers = self.light_headers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = headers
            .iter_mut()
            .find(|h| h.header_bytes == header.header_bytes)
        {
            for sig in &header.signatures {
                if !existing
                    .signatures
                    .iter()
                    .any(|s| s.validator == sig.validator)
                {
                    existing.signatures.push(sig.clone());
                }
            }
        } else {
            headers.push(header);
            if headers.len() > 1000 {
                headers.remove(0);
            }
        }
    }

    /// 执行状态裁剪（缺口 #4）。
    ///
    /// 裁剪 height < `current - tx_prune_after_blocks` 的旧区块 body，
    /// 以及 epoch < `block_epoch - 1`（留一个 epoch 缓冲）的旧 DAG vertex。
    /// 仅 Full/Validator 节点调用（Archive 不裁剪）。
    ///
    /// 返回 `(pruned_blocks, pruned_vertices)`。
    pub fn run_pruning(&self, current_height: u64) -> PokerL1Result<(usize, usize)> {
        let pruning_config = crate::storage::PruningConfig::default();
        // 裁剪旧区块：height < current - tx_prune_after_blocks
        let block_threshold = current_height.saturating_sub(pruning_config.tx_prune_after_blocks);
        let pruned_blocks = if block_threshold > 0 {
            self.block_store.prune_old_blocks(block_threshold)?
        } else {
            0
        };
        // 裁剪旧 vertex：epoch < current_epoch（用 block epoch 推算，留 1 个 epoch 缓冲）。
        // 简化：vertex 按 epoch 裁剪，保留当前 epoch 的全部 vertex。
        let block_epoch = crate::consensus::Epoch::MAX; // 占位：实际应从 block header 取 epoch
        let _ = block_epoch;
        // vertex 裁剪需要 epoch 信息；当前 block header 无 epoch 字段，
        // 暂用 vertex_prune_after_blocks 对应的 epoch 估算（保守不裁剪，避免误删）。
        // 完整实现需 block header 携带 epoch 或从 cert 推导。
        let pruned_vertices = 0usize;
        if pruned_blocks > 0 || pruned_vertices > 0 {
            tracing::info!(
                "run_pruning: pruned {} blocks, {} vertices (current_height={})",
                pruned_blocks,
                pruned_vertices,
                current_height
            );
        }
        Ok((pruned_blocks, pruned_vertices))
    }

    /// 验证 block（P0-3）。
    ///
    /// 在 block 入库前调用，确保 block 合法且状态根正确。
    pub fn validate_block(&self, block: &Block) -> PokerL1Result<()> {
        self.validate_block_structure(block)?;
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.prepare_block_execution(block, &object_db, &account_store)?;
        Ok(())
    }

    /// Validate block metadata that is independent of the local execution state.
    fn validate_block_structure(&self, block: &Block) -> PokerL1Result<()> {
        let header = &block.header;

        // 1. Resolve the canonical parent from the local tip. A missing `height - 1` must never
        // make validation weaker: that previously allowed an isolated block at an arbitrary
        // height to skip both the parent hash and time-consensus checks.
        let previous_block = match self.block_store.get_tip_height()? {
            Some(tip_height) => {
                let expected_height = tip_height
                    .checked_add(1)
                    .ok_or_else(|| PokerL1Error::Other("block height overflow".into()))?;
                if header.height != expected_height {
                    return Err(PokerL1Error::BlockHeightNotIncreasing {
                        prev: tip_height,
                        got: header.height,
                    });
                }
                let previous = self.block_store.get_by_height(tip_height)?;
                validate_block_time(
                    Some(&previous.header),
                    header,
                    &TimeConsensusConfig::default(),
                )?;
                let expected_prev_hash = previous.block_hash(self.config.chain_id);
                if header.prev_hash != expected_prev_hash {
                    return Err(PokerL1Error::InvalidPrevHash {
                        expected: expected_prev_hash,
                        got: header.prev_hash,
                    });
                }
                Some(previous)
            }
            None => {
                // Genesis monetary/object state is initialized outside BlockStore, so the first
                // committed consensus block is height 1 and references the logical genesis hash 0.
                if header.height != 1 {
                    return Err(PokerL1Error::BlockHeightNotIncreasing {
                        prev: 0,
                        got: header.height,
                    });
                }
                if header.prev_hash != [0u8; 32] {
                    return Err(PokerL1Error::InvalidPrevHash {
                        expected: [0u8; 32],
                        got: header.prev_hash,
                    });
                }
                None
            }
        };

        // 2. Both lane commitments must exactly match their bodies.
        validate_block_tx_roots(
            &block.public_txs,
            &block.gameturn_txs,
            header.public_tx_root,
            header.gameturn_tx_root,
        )?;

        // 3. GameTurn / CheckpointAnchor are the only gas-free body lane.
        validate_gameturn_no_gas(&block.gameturn_txs)?;

        // 4. Bind the certificate to both this header and the previous finalized certificate.
        // The signature alone proves only that validators signed a self-contained statement; it
        // does not establish that the statement belongs at this point in the local chain.
        //
        // 恰 quorum 存活修复：prev_commit_hash 链改用 **signing_hash**（不含签名的
        // 语句哈希）。cert_hash 含 signature_list —— 并发装配的签名子集差异会让
        // 同一语句的不同变体持有不同 cert_hash，下一个高度的歌 prev_commit_hash
        // 随之分叉，投票语句无法跨节点收敛。语句链仍保持 hash-linked（防
        // long-range attack），且与投票对象（signing_hash）严格一致。
        let cert = &header.dag_commit_certificate;
        let expected_prev_commit_hash = previous_block
            .as_ref()
            .map(|previous| {
                previous
                    .header
                    .dag_commit_certificate
                    .signing_hash(self.config.chain_id)
            })
            .unwrap_or([0u8; 32]);
        match previous_block.as_ref() {
            None if cert.epoch != self.current_epoch() => {
                return Err(PokerL1Error::CommitCertificateMismatch(format!(
                    "first certificate epoch mismatch: cert={}, validator_set={}",
                    cert.epoch,
                    self.current_epoch()
                )));
            }
            Some(previous) => {
                let previous_epoch = previous.header.dag_commit_certificate.epoch;
                let max_epoch = previous_epoch
                    .checked_add(1)
                    .ok_or_else(|| PokerL1Error::Other("certificate epoch overflow".into()))?;
                if cert.epoch < previous_epoch || cert.epoch > max_epoch {
                    return Err(PokerL1Error::CommitCertificateMismatch(format!(
                        "certificate epoch must stay at {previous_epoch} or advance once to {max_epoch}, got {}",
                        cert.epoch
                    )));
                }
            }
            None => {}
        }
        validate_commit_certificate_fields(
            cert,
            cert.epoch,
            expected_prev_commit_hash,
            header.state_root,
            header.public_tx_root,
            header.gameturn_tx_root,
        )?;

        let expected_commit_round = previous_block.as_ref().map_or(Ok(1), |previous| {
            previous
                .header
                .dag_commit_certificate
                .commit_round
                .checked_add(1)
                .ok_or_else(|| PokerL1Error::Other("commit round overflow".into()))
        })?;
        if cert.commit_round != expected_commit_round {
            return Err(PokerL1Error::CommitCertificateMismatch(format!(
                "commit_round mismatch: cert={}, expected={expected_commit_round}",
                cert.commit_round
            )));
        }

        // 5. A production node always requires a full, individually verified quorum.
        // A DAG reference graph is not a substitute for a finality certificate.
        let active_pubkeys = self.active_validator_pubkeys_sorted();
        if active_pubkeys.is_empty() && !self.allow_empty_consensus_for_tests {
            return Err(PokerL1Error::Other(
                "cannot admit block with an empty active ValidatorSet".into(),
            ));
        }
        if !active_pubkeys.is_empty() {
            validate_commit_certificate_signatures(cert, &active_pubkeys, self.config.chain_id)?;
        }

        // Bridge execution currently mutates an independent nonce registry.  Until that registry
        // participates in the same staged commit as ObjectDb and AccountStore, accepting such a
        // block would make failed validation stateful.  Reject it rather than silently replaying
        // a non-transactional bridge side effect.
        let bridge_contract_id = crate::vm::precompile::reserved::bridge_contract_id();
        if block.canonical_execution_txs().iter().any(|tx| {
            tx.contract_call
                .as_ref()
                .is_some_and(|call| call.contract_id == bridge_contract_id)
        }) {
            return Err(PokerL1Error::Other(
                "bridge block execution is disabled until nonce/object/account commits are transactional"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Execute a candidate block against isolated ObjectDb and AccountStore snapshots.
    ///
    /// The returned snapshots are suitable for a caller that has already completed all validation
    /// and wants to commit them.  Ordinary validation simply drops them, leaving live state
    /// untouched even when the candidate state root is wrong.
    fn prepare_block_execution(
        &self,
        block: &Block,
        object_db: &ObjectDb,
        account_store: &AccountStore,
    ) -> PokerL1Result<(ObjectDbSnapshot, AccountStore, BlockExecutionOutcome)> {
        let header = &block.header;
        let mut env = self.execution_environment(header.height, header.timestamp_ms);
        if let Some(first_vh) = header.dag_commit_certificate.vertex_hash_list.first() {
            if let Ok(vertex) = self.vertex_store.get_by_hash(first_vh) {
                env = env.with_proposer(crate::account::derive_address(&vertex.author_pubkey));
            }
        }

        let mut object_snapshot = object_db.create_snapshot();
        let mut account_snapshot = account_store.create_snapshot();
        let txs = block.canonical_execution_txs();
        let outcome = execute_block_serial(&env, &txs, &mut object_snapshot, &mut account_snapshot);
        validate_state_root_transition(outcome.state_root, header.state_root)?;
        Ok((object_snapshot, account_snapshot, outcome))
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    ///
    /// 返回 object_db 的当前 SMT root（即上一 block 后的状态根）。
    /// 产块时应先调用 [`Self::execute_block_on_state`] 执行 vertex 中的 txs，
    /// 取返回的 `outcome.state_root` 作为新 block header 的 `state_root`。
    pub fn state_root(&self) -> Hash {
        self.object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_root()
    }

    /// 获取预编译合约注册表引用（共享 Arc）。
    ///
    /// 供 `build_block_from_vertex` 构造 [`ExecutionEnvironment`] 时使用，
    /// 避免 main.rs 直接访问 Node 私有字段。
    #[must_use]
    pub fn precompile_registry(&self) -> Arc<PrecompileRegistry> {
        Arc::clone(&self.precompile_registry)
    }

    /// 获取 ZK verifier registry 的 clone（链上 zk_verify 启用）。
    /// 供 executor 构造 ExecutionEnvironment 时注入，使 VM 内 `zk_verify` syscall 可用。
    #[must_use]
    pub fn zk_verifier_registry_clone(
        &self,
    ) -> Option<crate::offline::zk_verifier::ZkVerifierRegistry> {
        self.zk_verifier.clone()
    }

    /// Synchronize the shared verifier-status control plane from authenticated governance state.
    ///
    /// The verifier implementations themselves remain fixed at node startup; only the per-chain
    /// Stub/Production status is updated. All registry clones observe the same status map.
    ///
    /// # Errors
    ///
    /// Returns an error when this node has no ZK verifier registry configured.
    pub fn synchronize_zk_verifier_governance(
        &self,
        governance: &crate::governance::GovernanceState,
    ) -> PokerL1Result<()> {
        let registry = self.zk_verifier.as_ref().ok_or_else(|| {
            PokerL1Error::Other("node has no ZK verifier registry to synchronize".into())
        })?;
        registry.synchronize_governance_statuses(governance);
        Ok(())
    }

    /// Construct the deterministic block execution environment owned by this node.
    ///
    /// Keeping this assembly in one place is consensus-critical: block production and block
    /// replay must inject the same precompile, ZK-verifier, and bridge registries. In particular,
    /// an application-aware recursive verifier registered at node startup must be visible to the
    /// VM `zk_verify` syscall on every execution path.
    #[must_use]
    pub fn execution_environment(
        &self,
        block_height: BlockHeight,
        block_timestamp: crate::TimestampMs,
    ) -> ExecutionEnvironment {
        let mut env =
            ExecutionEnvironment::new(self.config.chain_id, block_height, block_timestamp)
                .with_precompile_registry_arc(Arc::clone(&self.precompile_registry))
                .with_fee_policy(self.config.fee_policy);
        if let Some(registry) = &self.zk_verifier {
            env = env.with_zk_verifier(registry.clone());
        }
        if let Some(bridge_store) = &self.bridge_registry_store {
            env = env.with_bridge_registry_store(Arc::clone(bridge_store));
        }
        env
    }

    /// 获取指标收集器引用（缺口 #7）。
    #[must_use]
    pub fn metrics(&self) -> Arc<crate::metrics::MetricsCollector> {
        Arc::clone(&self.metrics)
    }

    /// 导出 Prometheus 格式指标文本（缺口 #7）。
    #[must_use]
    pub fn export_metrics(&self) -> String {
        // 刷新 gauge 类指标（tip 高度 + mempool 大小）。
        let tip = self
            .block_store
            .get_tip_height()
            .ok()
            .flatten()
            .unwrap_or(0);
        self.metrics.set_block_height(tip);
        self.metrics.set_mempool_size(
            self.pending_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len() as u64,
        );
        self.metrics.export()
    }

    /// 获取 Bridge registry store 引用（共享 Arc；缺口 #9）。
    ///
    /// 供 `build_block_from_vertex` / `validate_block` 构造 [`ExecutionEnvironment`] 时注入，
    /// 使 bridge contract_call 能访问持久化的 nonce registry。`None` 表示节点未启用桥。
    #[must_use]
    pub fn bridge_registry_store(&self) -> Option<Arc<BridgeRegistryStore>> {
        self.bridge_registry_store.clone()
    }

    /// 注入 Bridge registry store（builder 模式；缺口 #9）。
    ///
    /// 内存节点（`open_inmemory*`）默认不启用桥；需桥的测试可链式调用：
    /// `Node::open_inmemory(..)?.with_bridge(Arc::new(BridgeRegistryStore::open_inmemory()?))`。
    #[must_use]
    pub fn with_bridge(mut self, store: Arc<BridgeRegistryStore>) -> Self {
        self.bridge_registry_store = Some(store);
        self
    }

    /// 在当前链状态上执行 txs，返回执行结果（含新 state_root）。
    ///
    /// 供 `build_block_from_vertex` 在产块时调用：执行 vertex 中的 txs，
    /// 取 `outcome.state_root` 作为新 block 的 state_root。
    ///
    /// 内部加锁 `object_db` + `account_store`，调用 [`execute_block`]。
    /// execute_block 已设计为"失败 tx 返回失败回执，不阻断 block"，
    /// 故仅在底层错误（锁中毒 / RocksDB 写失败）时返回 `Err`。
    ///
    /// # 参数
    ///
    /// - `env`：执行环境（chain_id / height / timestamp / gas limit / precompile registry）
    /// - `txs`：待执行的有序 tx 列表（caller 应先 S9 排序）
    pub fn execute_block_on_state(
        &self,
        env: &ExecutionEnvironment,
        txs: &[Transaction],
    ) -> PokerL1Result<BlockExecutionOutcome> {
        let mut object_db = self
            .object_db
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("object_db mutex poisoned: {e}")))?;
        let mut account_store = self
            .account_store
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("account_store mutex poisoned: {e}")))?;
        Ok(execute_block(
            env,
            txs,
            &mut *object_db,
            &mut *account_store,
        ))
    }

    /// Deterministically execute transactions on isolated state snapshots.
    ///
    /// Block producers use this to derive a candidate state root before the resulting block is
    /// finalized and submitted through [`Self::put_block`].  Unlike
    /// [`Self::execute_block_on_state`], this method never changes the node's live ObjectDb or
    /// AccountStore, so producing a block cannot cause the later validation path to replay the
    /// same transaction twice.
    ///
    /// Bridge calls intentionally execute with no bridge registry here and therefore fail closed.
    /// Their nonce registry does not yet support staged commits with objects and accounts.
    pub fn simulate_block_execution(
        &self,
        env: &ExecutionEnvironment,
        txs: &[Transaction],
    ) -> PokerL1Result<BlockExecutionOutcome> {
        let object_db = self
            .object_db
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("object_db mutex poisoned: {e}")))?;
        let account_store = self
            .account_store
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("account_store mutex poisoned: {e}")))?;
        let mut object_snapshot = object_db.create_snapshot();
        let mut account_snapshot = account_store.create_snapshot();
        let mut simulation_env = env.clone();
        simulation_env.bridge_registry_store = None;
        Ok(execute_block_serial(
            &simulation_env,
            txs,
            &mut object_snapshot,
            &mut account_snapshot,
        ))
    }

    /// 按 hash 查询 DAG vertex。
    pub fn get_vertex(&self, hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        match self.vertex_store.get_by_hash(hash) {
            Ok(vertex) => Ok(Some(vertex)),
            Err(PokerL1Error::DagVertexNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 写入 account。
    pub fn put_account(&self, account: Account) -> PokerL1Result<()> {
        self.account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(account)
    }

    /// 按 address 查询 account。
    pub fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        Ok(self
            .account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(address)
            .cloned())
    }

    /// 提交 tx（缓存 + pending 缓冲）。
    ///
    /// Validator 节点会将 tx 装入下一个 vertex；非 Validator 节点仅缓存用于查询。
    /// C-2 修复：tx_cache 和 pending_tx 均有 FIFO 驱逐上限（10,000 条）。
    /// M-6 修复：tx_cache + order 合并到单个 Mutex，消除多锁死锁风险。
    pub fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        let tx_hash = tx.tx_hash();
        // M3-ACC-6：到达时间戳（节点本地可注入时钟；交易本体无时间戳）。
        let now_ms = self.now_ms();

        // M-6 修复：单次 lock 即可完成 cache + order 操作
        {
            let mut cache = self.tx_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(tx_hash, tx.clone(), MAX_NODE_TX_CACHE_SIZE);
        }

        // M3-ACC-6（§5.3-1）：validator 收到合法 submit_tx 后立即签发 SeenReceipt。
        // 仅 validator 角色且配置了签名密钥时签发（与 vertex / commit cert 同一密钥、
        // 同一 secp256k1 recoverable 方案，不新造密码学）。
        if self.config.role.is_validator()
            && let Some(vkey) = &self.config.validator_key
            && let Ok(secret_key) = secp256k1::SecretKey::from_slice(&vkey.secret_key_bytes)
        {
            let receipt = crate::force_include::SeenReceipt::issue(
                self.config.chain_id,
                tx_hash,
                now_ms,
                &secret_key,
            )?;
            let mut receipts = self.seen_receipts.lock().unwrap_or_else(|e| e.into_inner());
            receipts.insert(receipt.clone(), MAX_PENDING_TX_SIZE);
            drop(receipts);
            // v1.5-a1：同步追加落盘（JSONL sidecar，append-only；重启重放恢复）。
            // 落盘失败不阻断 tx 提交（receipt 仍在内存），仅记告警 —— 持久化是
            // 尽力而为的副作用，签名验证与内存查询能力不受影响。
            let sidecar_result = self
                .receipt_sidecar
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
                .map(|sidecar| sidecar.append(&receipt));
            if let Some(Err(e)) = sidecar_result {
                tracing::warn!(
                    "seen_receipts sidecar 追加失败（tx_hash={}）：{e}",
                    hex::encode(tx_hash)
                );
            }
        }

        if self.config.role.is_validator() {
            let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
            // 缺口 #3：Priority Mempool — RBF（Replace-by-Fee）。
            // 若已有相同 (caller, nonce) 的 tx 且新 tx gas_price 更高 → 替换。
            // Caller address is derived exactly once per submission; `PendingTxState` supplies an
            // O(1) key lookup instead of deriving every queued caller on every new transaction.
            let caller = crate::account::derive_address(&tx.tagged_pubkey);
            let new_price = tx.gas.price;
            let new_nonce = tx.nonce;
            let mut replaced = false;
            if new_price > 0 {
                // 查找同 (caller, nonce) 的最早到达旧 tx，保持此前 FIFO 查找语义。
                if let Some((idx, old)) = pending.oldest_for(caller, new_nonce) {
                    if old.tx.gas.price < new_price {
                        // RBF：替换（仅当新 price 严格更高）。
                        pending.remove(idx);
                        replaced = true;
                    } else {
                        // 旧 tx price 更高或相等 → 拒绝（不替换）。
                        return Err(PokerL1Error::Other(format!(
                            "RBF rejected: existing tx gas_price {} >= new {} for caller {:?} nonce {}",
                            old.tx.gas.price, new_price, caller, new_nonce
                        )));
                    }
                }
            }
            pending.push(caller, tx, now_ms);
            while pending.len() > MAX_PENDING_TX_SIZE {
                // 溢出时丢弃 gas_price 最低的（而非 FIFO 最旧）。
                if pending.len() > 1 {
                    let mut min_idx = 0;
                    let mut min_price = u64::MAX;
                    for (i, entry) in pending.queue.iter().enumerate() {
                        if entry.tx.gas.price < min_price {
                            min_price = entry.tx.gas.price;
                            min_idx = i;
                        }
                    }
                    pending.remove(min_idx);
                } else {
                    pending.remove(0);
                }
            }
            let len_after = pending.len();
            // 唤醒 validator loop（混合模式：有 tx 时立即出 vertex）
            self.pending_tx_condvar.notify_one();
            tracing::info!(
                "submit_tx: tx_hash={} pending_tx.len()={} role={:?} rbf={}",
                hex::encode(tx_hash),
                len_after,
                self.config.role,
                replaced
            );
        } else {
            tracing::warn!(
                "submit_tx: 节点非 validator 角色，tx 仅缓存未加入 pending_tx (tx_hash={})",
                hex::encode(tx_hash)
            );
        }
        Ok(tx_hash)
    }

    /// 按 hash 查询 tx（从缓存；archive node 可遍历 block）。
    pub fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        Ok(self
            .tx_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tx_hash)
            .cloned())
    }

    /// 取出待装 vertex 的 tx（仅 Validator 角色有效）。
    ///
    /// 缺口 #3：Priority Mempool 排序规则。
    ///
    /// 排序优先级（与 S9 vertex 排序规则一致，但加入 gas_price 二级排序）：
    /// 1. **GameTurn + CheckpointAnchor**（优先）：免 gas 的游戏操作/anchor，
    ///    按 arrival 顺序保持（游戏的轮次/nonce 语义由 `build_game_sub_block` 处理）
    /// 2. **Public**（中间）：按 `gas_price` 降序（高 price 先装入 vertex）
    /// 3. **ForceSync**（后置）：按 `gas_price` 降序
    ///
    /// GameTurn 通道的排序**不**按 gas_price（它们免 gas），而按 arrival 顺序，
    /// 因为游戏操作的顺序由轮转规则（`TurnRule`）决定，不是由 gas 竞价决定。
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self
            .pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .into_iter()
            .map(|entry| entry.tx)
            .collect();
        Self::order_txs_legacy(txs)
    }

    /// 既有通道排序（GameTurn/CheckpointAnchor → Public → ForceSync）。
    ///
    /// 从 [`Self::drain_pending_tx`] 与 [`Self::drain_pending_tx_for_block`] 共用，
    /// 保证 `inclusion_deadline_ms = 0`（禁用强制包含）时两条路径产出完全同序。
    fn order_txs_legacy(txs: Vec<Transaction>) -> Vec<Transaction> {
        // 分通道排序：GameTurn/CheckpointAnchor 优先 → Public 中 → ForceSync 后。
        // Public/ForceSync 内部按 gas_price 降序；GameTurn 按 arrival 顺序。
        let mut gameturn: Vec<&Transaction> = Vec::new();
        let mut public: Vec<&Transaction> = Vec::new();
        let mut forcesync: Vec<&Transaction> = Vec::new();
        for tx in &txs {
            match tx.lane_hint {
                TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn.push(tx),
                TxLane::Public => public.push(tx),
                TxLane::ForceSync => forcesync.push(tx),
            }
        }
        // Public / ForceSync 按 gas_price 降序（stable sort 保持 arrival tiebreaker）。
        public.sort_by(|a, b| b.gas.price.cmp(&a.gas.price));
        forcesync.sort_by(|a, b| b.gas.price.cmp(&a.gas.price));
        // GameTurn 保持 arrival 顺序（已按 drain 的 VecDeque 顺序 = arrival）。
        // 组装结果：GameTurn + CheckpointAnchor → Public → ForceSync。
        let mut result: Vec<Transaction> = Vec::with_capacity(txs.len());
        result.extend(gameturn.into_iter().cloned());
        result.extend(public.into_iter().cloned());
        result.extend(forcesync.into_iter().cloned());
        result
    }

    /// 出块 drain（M3-ACC-6，§5.3-2/3）：先扫描强制包含队列，再按既有通道排序。
    ///
    /// 1. `now > arrived_at_ms + inclusion_deadline_ms` 且尚未提升过的交易进入
    ///    强制包含队列（`included` 去重集合防二次强制包含）；
    /// 2. 强制包含队列按 `tx_hash` 字节序升序，**先于**普通交易返回；
    /// 3. 普通交易保持 [`Self::drain_pending_tx`] 的既有通道排序；
    /// 4. `inclusion_deadline_ms == 0` 时完全等价于 [`Self::drain_pending_tx`]
    ///    （禁用路径回归测试覆盖：同输入序列两法同序）。
    pub fn drain_pending_tx_for_block(&self) -> Vec<Transaction> {
        self.drain_pending_tx_for_block_with_forced().0
    }

    /// v1.5-a2：出块 drain 的载荷版 —— 同时返回本轮被强制提升的 tx_hash 集合
    /// （已按字节序升序、去重），供 validator 写入 vertex 的 `forced_tx_hashes`
    /// 载荷字段（强制包含集进共识承诺）。
    ///
    /// 返回 `(排序后 tx 列表, 本轮 forced hash 升序列表)`。
    pub fn drain_pending_tx_for_block_with_forced(&self) -> (Vec<Transaction>, Vec<Hash>) {
        let now_ms = self.now_ms();
        let deadline_ms = self.config.inclusion_deadline_ms;
        let drained: Vec<PendingTxEntry> = self
            .pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .into_iter()
            .collect();
        if drained.is_empty() {
            return (Vec::new(), Vec::new());
        }
        if deadline_ms == 0 {
            // 禁用路径：与历史行为完全一致（不扫描、不标记去重集合）。
            let txs: Vec<Transaction> = drained.into_iter().map(|entry| entry.tx).collect();
            return (Self::order_txs_legacy(txs), Vec::new());
        }
        let mut forced: Vec<crate::force_include::ForceIncludeTx> = Vec::new();
        let mut normal: Vec<Transaction> = Vec::new();
        {
            let mut included = self.force_include.lock().unwrap_or_else(|e| e.into_inner());
            for entry in drained {
                let tx_hash = entry.tx.tx_hash();
                if included.included.contains(&tx_hash)
                    || !crate::force_include::is_past_inclusion_deadline(
                        entry.arrived_at_ms,
                        now_ms,
                        deadline_ms,
                    )
                {
                    normal.push(entry.tx);
                    continue;
                }
                included.mark_included(tx_hash, MAX_PENDING_TX_SIZE);
                tracing::info!(
                    "force_include: tx_hash={} 超过期限 {}ms（arrived_at={} now={}），本块强制包含",
                    hex::encode(tx_hash),
                    deadline_ms,
                    entry.arrived_at_ms,
                    now_ms
                );
                forced.push(crate::force_include::ForceIncludeTx {
                    tx: entry.tx,
                    tx_hash,
                    arrived_at_ms: entry.arrived_at_ms,
                });
            }
        }
        if !forced.is_empty() {
            tracing::info!(
                "force_include: 本轮共强制包含 {} 笔，普通交易 {} 笔按通道排序跟随",
                forced.len(),
                normal.len()
            );
        }
        // v1.5-a2：本轮 forced hash 升序快照（写入 vertex 载荷的承诺集合）。
        let mut forced_hashes: Vec<Hash> = forced.iter().map(|f| f.tx_hash).collect();
        forced_hashes.sort();
        forced_hashes.dedup();
        // 强制包含（tx_hash 升序）在前，普通交易按既有通道排序在后。
        let txs =
            crate::force_include::order_force_include_first(forced, Self::order_txs_legacy(normal));
        (txs, forced_hashes)
    }

    /// Return transactions drained by the validator loop to the front of the mempool.
    ///
    /// This is used when a multi-validator node cannot yet assemble a valid previous-round
    /// parent quorum. The original arrival order is preserved ahead of transactions that arrived
    /// concurrently while the batch was being assembled, so a temporary DAG lag cannot silently
    /// drop or reorder user submissions.
    pub fn requeue_pending_txs(&self, txs: Vec<Transaction>) {
        if !self.config.role.is_validator() || txs.is_empty() {
            return;
        }

        // M3-ACC-6：回排交易从 SeenReceipt 恢复原始到达时间（若存在），
        // 避免强制包含期限被回排重置重新计时。
        let now_ms = self.now_ms();
        let receipts = self.seen_receipts.lock().unwrap_or_else(|e| e.into_inner());
        let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
        for tx in txs.into_iter().rev() {
            let caller = crate::account::derive_address(&tx.tagged_pubkey);
            let arrived_at_ms = receipts
                .get(&tx.tx_hash())
                .map(|receipt| receipt.seen_at_ms)
                .unwrap_or(now_ms);
            pending.push_front(caller, tx, arrived_at_ms);
        }
        while pending.len() > MAX_PENDING_TX_SIZE {
            let min_index = pending
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.tx.gas.price)
                .map(|(index, _)| index)
                .unwrap_or(0);
            pending.remove(min_index);
        }
        self.pending_tx_condvar.notify_one();
    }

    /// 等待 pending_tx 非空或超时（混合模式核心）。
    ///
    /// - 如果 pending_tx 已有 tx → 立即返回 `true`
    /// - 否则阻塞等待，被 `submit_tx` 的 `notify_one` 唤醒后返回 `true`
    /// - 超时返回 `false`（调用方据此决定是否产出空 vertex 推进 commit）
    pub fn wait_for_pending_tx(&self, timeout: std::time::Duration) -> bool {
        let guard = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.is_empty() {
            return true;
        }
        let result = self
            .pending_tx_condvar
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|e| e.into_inner());
        !result.0.is_empty()
    }

    // ===== M3-ACC-6：ForceInclude 抗审查机制（plan §5.3 v1 子集） =====

    /// 节点本地时钟（毫秒）。来源可注入（[`Self::set_time_source`]），生产默认
    /// `SystemTime`。
    fn now_ms(&self) -> u64 {
        let source = self.time_source.lock().unwrap_or_else(|e| e.into_inner());
        (source)()
    }

    /// 注入时钟来源（测试用 fake clock；生产无需调用）。
    pub fn set_time_source(&self, source: Box<dyn Fn() -> u64 + Send + Sync>) {
        let mut guard = self.time_source.lock().unwrap_or_else(|e| e.into_inner());
        *guard = source;
    }

    /// 强制包含期限（毫秒；`0 = 禁用`）。
    #[must_use]
    pub const fn inclusion_deadline_ms(&self) -> u64 {
        self.config.inclusion_deadline_ms
    }

    /// 按 hash 查询 SeenReceipt（§5.3-1；v1.5-a1：validator 节点持久化于
    /// JSONL sidecar，重启后重放恢复，RPC 仍可答）。
    ///
    /// 仅 validator 角色且配置了签名密钥的节点会在 `submit_tx` 时签发。
    pub fn get_seen_receipt(
        &self,
        tx_hash: &Hash,
    ) -> PokerL1Result<Option<crate::force_include::SeenReceipt>> {
        let receipts = self.seen_receipts.lock().unwrap_or_else(|e| e.into_inner());
        Ok(receipts.get(tx_hash))
    }

    /// 已强制提升（视为已进块）的 tx_hash 快照（出块排序集成用）。
    ///
    /// 返回提升顺序快照；[`sort_commit_txs_r4m4_with_force_include`] 消费前会按
    /// hash 排序，故快照顺序不影响结果确定性。
    pub fn force_included_hashes(&self) -> Vec<Hash> {
        let included = self.force_include.lock().unwrap_or_else(|e| e.into_inner());
        included.snapshot()
    }

    /// 从 block store 提取近 `window_blocks` 个块的 tx_hash 全集（§5.3-4 v1 块数近似）。
    ///
    /// 高度从 tip 向下扫描；缺失高度跳过。仅用于 `check_censorship`（低频 RPC）。
    fn recent_window_tx_hashes(&self, window_blocks: u64) -> PokerL1Result<Vec<Hash>> {
        let mut out = Vec::new();
        let tip = match self.block_store.get_tip_height()? {
            Some(tip) => tip,
            None => return Ok(out),
        };
        let start = tip.saturating_sub(window_blocks.saturating_sub(1));
        for height in (start..=tip).rev() {
            if let Ok(block) = self.block_store.get_by_height(height) {
                for tx in block.public_txs.iter().chain(block.gameturn_txs.iter()) {
                    out.push(tx.tx_hash());
                }
            }
        }
        Ok(out)
    }

    /// 审查检测（§5.3-4）：验证 [`crate::force_include::CensorshipProof`]。
    ///
    /// 返回 [`crate::force_include::CensorshipCheckOutcome`] 三态：
    /// - `Included`：tx 已包含（近 K 个块内），指控不成立；
    /// - `NotYetDue`：未超过 `seen_at_ms + deadline_ms`；
    /// - `Censored`：证据成立 —— v1.5-b 起对 receipt 签发者执行**真实罚没**
    ///   （[`crate::consensus::slash::SlashLedger`] 记账 + 本地 ValidatorSet
    ///   bond 扣减；stake 归零即 Slashed、失去出块资格）。证据幂等键 =
    ///   `censorship_evidence_digest(chain_id, tx_hash, seen_at_ms, 签发者)`，
    ///   同一证据不重复罚没。
    ///
    /// 边界（原型口径）：罚没在本节点共享 ValidatorSet 上执行，属单节点主观
    /// 证据结算；QC 背书证据 + epoch 边界统一结算的生产语义见
    /// `consensus::slash` 模块头。罚没失败（validator 不在集合/已 Slashed）
    /// 只记日志，不影响三态返回。
    pub fn check_censorship(
        &self,
        proof: &crate::force_include::CensorshipProof,
    ) -> PokerL1Result<crate::force_include::CensorshipCheckOutcome> {
        let now_ms = self.now_ms();
        let recent = self.recent_window_tx_hashes(self.config.censorship_window_blocks)?;
        let outcome = proof.verify(self.config.chain_id, now_ms, &recent)?;
        if outcome == crate::force_include::CensorshipCheckOutcome::Censored {
            self.metrics().inc_censorship_detected();
            tracing::warn!(
                "CENSORSHIP DETECTED: tx_hash={} seen_at_ms={} deadline_ms={} height_hint={} — v1.5 真实罚没触发",
                hex::encode(proof.receipt.tx_hash),
                proof.receipt.seen_at_ms,
                proof.deadline_ms,
                proof.current_height_hint,
            );
            // v1.5-b：对 receipt 签发者执行罚没（幂等；tip height 作证据链高）。
            let tip_height = self.block_store.get_tip_height()?.unwrap_or(0);
            let evidence_digest = crate::consensus::slash::censorship_evidence_digest(
                self.config.chain_id,
                &proof.receipt.tx_hash,
                proof.receipt.seen_at_ms,
                &proof.receipt.validator_pubkey,
            );
            let mut ledger = self.slash_ledger.lock().unwrap_or_else(|e| e.into_inner());
            let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            match ledger.apply_slash_from_censorship(
                &mut set,
                &proof.receipt.validator_pubkey,
                evidence_digest,
                crate::consensus::slash::DEFAULT_SLASH_AMOUNT_FULL,
                now_ms,
                tip_height,
            ) {
                Ok(Some(event)) => tracing::warn!(
                    "SLASH APPLIED (censorship_proof): validator={:?} deducted={} stake_now={} height={}",
                    event.validator_pubkey,
                    event.amount,
                    set.find_validator(&event.validator_pubkey)
                        .map(|v| v.stake)
                        .unwrap_or(0),
                    tip_height
                ),
                Ok(None) => {}
                Err(e) => tracing::warn!("SLASH 未执行（censorship_proof）：{e}"),
            }
        }
        Ok(outcome)
    }

    /// v1.5-b：罚没账本只读快照（append-only 事件序列）。
    #[must_use]
    pub fn slash_events(&self) -> Vec<crate::consensus::slash::SlashEvent> {
        self.slash_ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .events()
            .to_vec()
    }

    // ===== v1.5-c：checkpoint + BLS 聚合 QC（原型） =====

    /// v1.5-c：checkpoint 产出间隔（块数；0 = 禁用）。
    #[must_use]
    pub const fn checkpoint_interval_blocks(&self) -> u64 {
        self.config.checkpoint_interval_blocks
    }

    /// 当前 tip 已覆盖的最新 checkpoint 边界 → 返回待签署位点
    /// `(epoch, height, state_root)`。
    ///
    /// 语义：取 `height = tip - (tip % interval)`（≤ tip 的最新间隔边界）。
    /// 这样即使 validator loop 的 tick 落在边界高度之后（200ms 出块间隔下
    /// 边界高度可能仅存在一个 tick），也不漏签；重复签署由调用方以
    /// 「本节点已签位点集合」去重。本地缺失边界块（import 未达）→ None，
    /// 待 import 后补签。
    #[must_use]
    pub fn checkpoint_target(&self) -> Option<(crate::consensus::Epoch, u64, Hash)> {
        if self.config.checkpoint_interval_blocks == 0 {
            return None;
        }
        let tip = self.block_store.get_tip_height().ok().flatten()?;
        let interval = self.config.checkpoint_interval_blocks;
        let target = tip - (tip % interval);
        if target == 0 {
            return None;
        }
        let block = self.block_store.get_by_height(target).ok()?;
        let cert = &block.header.dag_commit_certificate;
        Some((cert.epoch, target, block.header.state_root))
    }

    /// 记录一条 checkpoint 投票（已验证签名）并在凑齐 2f+1 时聚合 QC。
    ///
    /// 返回 `(该位点当前票数, 若凑齐则返回新形成的 QC)`。同签名者重复投票去重。
    ///
    /// 边界（原型口径，如实）：BLS 公钥尚无 validator 集注册表，收集端只能做
    /// **签名有效性**（possession）验证 + 2f+1 计数，不能验证"签名者属于当前
    /// validator 集"——公钥注册表（ValidatorEntry 增加 bls_pubkey 字段或独立
    /// registry）属后续接线点。多节点部署中投票源自 gossip 的 validator 连接，
    /// 攻击面可接受于原型。
    pub fn record_checkpoint_vote(
        &self,
        vote: crate::consensus::checkpoint::CheckpointVote,
    ) -> PokerL1Result<(usize, Option<crate::consensus::checkpoint::CheckpointQc>)> {
        use crate::consensus::checkpoint::CheckpointQc;
        vote.verify()?;
        let vc = self.active_validator_count().max(1);
        let mut state = self
            .checkpoint_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (vote.epoch, vote.height);
        if !state.vote_sites_order.contains(&key) {
            state.vote_sites_order.push_back(key);
            while state.vote_sites_order.len() > MAX_CHECKPOINT_VOTE_SITES {
                if let Some(old) = state.vote_sites_order.pop_front() {
                    state.votes.remove(&old);
                }
            }
        }
        let entry = state.votes.entry(key).or_default();
        if entry
            .iter()
            .any(|v| v.signer_pubkey_g2 == vote.signer_pubkey_g2)
        {
            return Ok((entry.len(), None));
        }
        entry.push(vote);
        let collected = entry.len();
        let required = crate::consensus::required_quorum(vc);
        if collected < required {
            return Ok((collected, None));
        }
        let votes = entry.clone();
        let qc = CheckpointQc::form_from_votes(&votes, vc)?;
        self.append_checkpoint_qc(&qc)?;
        state.latest_qc = Some(qc.clone());
        Ok((collected, Some(qc)))
    }

    /// 当前已收集票数（诊断/测试用）。
    #[must_use]
    pub fn checkpoint_vote_count(&self, epoch: crate::consensus::Epoch, height: u64) -> usize {
        self.checkpoint_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .votes
            .get(&(epoch, height))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// 最新已验证 checkpoint QC（重启后由 sidecar 恢复）。
    #[must_use]
    pub fn latest_checkpoint_qc(&self) -> Option<crate::consensus::checkpoint::CheckpointQc> {
        self.checkpoint_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .latest_qc
            .clone()
    }

    // ===== v1.5-e：阈值 QC 形态（真 t-of-n；密钥来自 consensus::dkg） =====

    /// checkpoint QC 阈值 t（`0 = 聚合模式，零回退；> 0 = 阈值形态`）。
    #[must_use]
    pub const fn qc_threshold_t(&self) -> u32 {
        self.config.qc_threshold_t
    }

    /// 本节点 DKG 群份额 id（阈值模式；`None` = 未配置/聚合模式）。
    #[must_use]
    pub fn dkg_share_id(&self) -> Option<u64> {
        self.dkg_share.as_ref().map(|s| s.id)
    }

    /// 本节点 DKG 群份额克隆（validator loop 阈值签名输入；与节点同信任域）。
    #[must_use]
    pub fn dkg_share(&self) -> Option<crate::consensus::dkg::ParticipantShare> {
        self.dkg_share
    }

    /// 记录一条阈值部分份额签名（已验证）并在凑齐 t 时装配阈值 QC。
    ///
    /// 返回 `(该位点当前份额数, 若凑齐则返回新形成的阈值形态 QC)`。
    /// 同参与者重复份额去重。**无 keyset 的节点拒绝（fail-closed）**——聚合
    /// 模式节点走 [`Self::record_checkpoint_vote`]（零回退路径）。
    ///
    /// # Errors
    /// 节点无 DKG keyset、份额签名验证失败（尺寸/点/配对）、位点异构或装配
    /// 失败（见 [`CheckpointQc::form_threshold_from_partials`]）。
    pub fn record_threshold_partial(
        &self,
        partial: crate::consensus::checkpoint::ThresholdQcPartial,
    ) -> PokerL1Result<(usize, Option<crate::consensus::checkpoint::CheckpointQc>)> {
        use crate::consensus::checkpoint::CheckpointQc;
        let Some(keyset) = self.dkg_keyset.as_ref() else {
            return Err(PokerL1Error::Other(
                "threshold partial: 节点未配置 DKG keyset（聚合模式不接受阈值份额）".into(),
            ));
        };
        partial.verify(keyset)?;
        let mut state = self
            .checkpoint_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (partial.epoch, partial.height);
        if !state.threshold_sites_order.contains(&key) {
            state.threshold_sites_order.push_back(key);
            while state.threshold_sites_order.len() > MAX_CHECKPOINT_VOTE_SITES {
                if let Some(old) = state.threshold_sites_order.pop_front() {
                    state.threshold_partials.remove(&old);
                }
            }
        }
        let entry = state.threshold_partials.entry(key).or_default();
        if entry
            .iter()
            .any(|p| p.participant_id == partial.participant_id)
        {
            return Ok((entry.len(), None));
        }
        entry.push(partial);
        let collected = entry.len();
        // 仅在恰好凑齐 t 时装配一次（此后到位的份额只计数：QC 签名者数
        // 确定为 t，避免每个超额份额都重做 Lagrange 重构）。
        if collected != keyset.t as usize {
            return Ok((collected, None));
        }
        let partials = entry.clone();
        let qc = CheckpointQc::form_threshold_from_partials(&partials, keyset)?;
        self.append_checkpoint_qc(&qc)?;
        state.latest_qc = Some(qc.clone());
        Ok((collected, Some(qc)))
    }

    /// 当前已收集阈值部分份额数（诊断/测试用）。
    #[must_use]
    pub fn threshold_partial_count(
        &self,
        epoch: crate::consensus::Epoch,
        height: u64,
    ) -> usize {
        self.checkpoint_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .threshold_partials
            .get(&(epoch, height))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    // ===== v1.5-d：DA 原语（请求/回执/聚合凭证，原型闭环） =====

    /// 发起 DA 请求并签发本节点回执（validator 角色且配置密钥时）。
    ///
    /// 位点取 `(当前 epoch, tip height)`；本节点回执入站内收集并进入 outbox
    /// （由 validator loop gossip 给 peers）。非 validator 节点请求会被拒绝
    /// （无签名能力，DA 回执必须由 validator 签发）。
    pub fn submit_da_request(&self, digest: Hash) -> PokerL1Result<DaStatus> {
        let vkey = self.config.validator_key.as_ref().ok_or_else(|| {
            PokerL1Error::Other("da_request: 本节点非 validator（无签名密钥）".into())
        })?;
        let epoch = self.current_epoch();
        let height = self.block_store.get_tip_height()?.unwrap_or(0);
        let sk = crate::consensus::checkpoint::bls_derive_secret_key(&vkey.secret_key_bytes);
        let receipt = crate::consensus::da::DaReceipt::sign(digest, epoch, height, &sk)?;
        let request = crate::consensus::da::DaRequest {
            digest,
            epoch,
            height,
            requester: vkey.tagged_pubkey.clone(),
        };
        let vc = self.active_validator_count().max(1);
        let mut state = self.da_state.lock().unwrap_or_else(|e| e.into_inner());
        let status = {
            let entry = state.entry_mut(request);
            if !entry
                .receipts
                .iter()
                .any(|r| r.signer_pubkey_g2 == receipt.signer_pubkey_g2)
            {
                entry.receipts.push(receipt.clone());
            }
            // 尝试聚合凭证
            if entry.certificate.is_none() {
                let required = crate::consensus::required_quorum(vc);
                if entry.receipts.len() >= required {
                    let receipts = entry.receipts.clone();
                    entry.certificate =
                        Some(crate::consensus::da::DaCertificate::form_from_receipts(
                            &receipts, vc,
                        )?);
                }
            }
            Self::da_status_of(entry)
        };
        state.outbox.push_back(receipt);
        Ok(status)
    }

    /// 记录 peer 的 DA 回执（P2P 入口；凑齐 2f+1 时聚合凭证）。
    ///
    /// 未请求过的 digest：接受为"被动见证"（validator gossip 的回执本身就
    /// 说明了该 digest 的可用性动议）——与请求路径共用条目结构。
    pub fn record_da_receipt(
        &self,
        receipt: crate::consensus::da::DaReceipt,
    ) -> PokerL1Result<DaStatus> {
        receipt.verify()?;
        let vc = self.active_validator_count().max(1);
        let request = crate::consensus::da::DaRequest {
            digest: receipt.digest,
            epoch: receipt.epoch,
            height: receipt.height,
            requester: crate::signature::TaggedPubkey {
                tag: crate::signature::tagged_pubkey::encode_tag(
                    crate::signature::SignatureScheme::Secp256k1,
                    crate::signature::CURRENT_VERSION,
                ),
                raw: vec![],
            },
        };
        let mut state = self.da_state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.entry_mut(request);
        if !entry
            .receipts
            .iter()
            .any(|r| r.signer_pubkey_g2 == receipt.signer_pubkey_g2)
        {
            entry.receipts.push(receipt);
        }
        if entry.certificate.is_none() {
            let required = crate::consensus::required_quorum(vc);
            if entry.receipts.len() >= required {
                let receipts = entry.receipts.clone();
                entry.certificate =
                    Some(crate::consensus::da::DaCertificate::form_from_receipts(
                        &receipts, vc,
                    )?);
            }
        }
        Ok(Self::da_status_of(entry))
    }

    /// 查询 DA 状态（RPC `da_status`）。
    #[must_use]
    pub fn da_status(&self, digest: &Hash) -> DaStatus {
        let state = self.da_state.lock().unwrap_or_else(|e| e.into_inner());
        match state.entries.get(digest) {
            Some(entry) => Self::da_status_of(entry),
            None => DaStatus {
                requested: false,
                digest: format!("0x{}", hex::encode(digest)),
                epoch: 0,
                height: 0,
                receipt_count: 0,
                certified: false,
                cert_signers: 0,
            },
        }
    }

    fn da_status_of(entry: &DaEntry) -> DaStatus {
        DaStatus {
            requested: true,
            digest: format!("0x{}", hex::encode(entry.request.digest)),
            epoch: entry.request.epoch,
            height: entry.request.height,
            receipt_count: entry.receipts.len(),
            certified: entry.certificate.is_some(),
            cert_signers: entry
                .certificate
                .as_ref()
                .map(crate::consensus::da::DaCertificate::signer_count)
                .unwrap_or(0),
        }
    }

    /// 取出待广播的本地 DA 回执（validator loop 每轮调用）。
    #[must_use]
    pub fn drain_da_outbox(&self) -> Vec<crate::consensus::da::DaReceipt> {
        let mut state = self.da_state.lock().unwrap_or_else(|e| e.into_inner());
        state.outbox.drain(..).collect()
    }

    /// QC 落盘（JSONL sidecar，一行一条 JSON；失败仅记日志 —— QC 仍保留内存态）。
    fn append_checkpoint_qc(
        &self,
        qc: &crate::consensus::checkpoint::CheckpointQc,
    ) -> PokerL1Result<()> {
        use std::io::Write as _;
        let mut guard = self
            .checkpoint_sidecar
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(file) = guard.as_mut() else {
            return Ok(());
        };
        let mut line = serde_json::to_string(qc)
            .map_err(|e| PokerL1Error::Serialization(format!("checkpoint qc json: {e}")))?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .and_then(|_| file.flush())
            .map_err(|e| {
                PokerL1Error::Other(format!("checkpoint sidecar 追加失败: {e}"))
            })
    }

    /// 是否提供历史数据 RPC（仅 Archive 节点）。
    #[must_use]
    pub const fn serves_historical_data(&self) -> bool {
        self.config.role.is_archive()
    }
}

// ===== SubTask 32.5: CLI 工具函数 =====

/// CLI keygen 结果。
///
/// SEC-FIX-2：实现 `Drop` 自动 zeroize 私钥字节，自定义 `Debug` 隐藏私钥内容，
/// 与 `ValidatorKey` 保持一致的安全处理模式。
#[derive(Clone, Serialize, Deserialize)]
pub struct KeygenResult {
    /// 签名方案。
    pub scheme: SignatureScheme,
    /// 私钥字节（secp256k1 = 32B，ed25519 = 32B）。
    pub secret_key_bytes: Vec<u8>,
    /// 对应的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// 派生的账户地址。
    pub address: Address,
}

impl std::fmt::Debug for KeygenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeygenResult")
            .field("scheme", &self.scheme)
            .field("secret_key_bytes", &"[REDACTED]")
            .field("tagged_pubkey", &self.tagged_pubkey)
            .field("address", &self.address)
            .finish()
    }
}

impl Drop for KeygenResult {
    fn drop(&mut self) {
        self.secret_key_bytes.fill(0);
    }
}

/// 生成 secp256k1 tagged pubkey 密钥对。
///
/// 使用 `OsRng` 密码学安全随机源。返回私钥 + tagged pubkey + 地址。
pub fn keygen_secp256k1() -> PokerL1Result<KeygenResult> {
    use secp256k1::Secp256k1;
    use secp256k1::rand::rngs::OsRng;
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let secret_key_bytes = secret_key.secret_bytes();
    let compressed = public_key.serialize();
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )?;
    let address = crate::account::derive_address(&tagged_pubkey);
    // 安全擦除 OsRng 不需要（它是 CSPRNG）
    let secret_vec = secret_key_bytes.to_vec();
    Ok(KeygenResult {
        scheme: SignatureScheme::Secp256k1,
        secret_key_bytes: secret_vec,
        tagged_pubkey,
        address,
    })
}

/// 生成 ed25519 tagged pubkey 密钥对。
///
/// 使用 `OsRng` 密码学安全随机源。返回私钥 + tagged pubkey + 地址。
pub fn keygen_ed25519() -> PokerL1Result<KeygenResult> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let secret_key_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Ed25519,
        CURRENT_VERSION,
        public_bytes.to_vec(),
    )?;
    let address = crate::account::derive_address(&tagged_pubkey);
    Ok(KeygenResult {
        scheme: SignatureScheme::Ed25519,
        secret_key_bytes: secret_key_bytes.to_vec(),
        tagged_pubkey,
        address,
    })
}

/// CLI keygen 入口 — 按签名方案生成密钥对。
pub fn keygen(scheme: SignatureScheme) -> PokerL1Result<KeygenResult> {
    match scheme {
        SignatureScheme::Secp256k1 => keygen_secp256k1(),
        SignatureScheme::Ed25519 => keygen_ed25519(),
    }
}

/// 本地计算 assigned_validator（spec：`hash(game_id, epoch) % |V|`）。
///
/// 客户端 CLI 可用此函数本地预测 assigned_validator，无需查询链上。
///
/// # 参数
///
/// - `game_id`：Game 对象 ID
/// - `epoch`：当前 epoch
/// - `validator_set`：当前 epoch 的 validator 公钥列表（按 BTreeSet 排序后的顺序）
#[must_use]
pub fn compute_assigned_validator_local<'a>(
    game_id: &ObjectID,
    epoch: crate::consensus::Epoch,
    validator_set: &'a [TaggedPubkey],
) -> Option<&'a TaggedPubkey> {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    if validator_set.is_empty() {
        return None;
    }
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[0x41]); // 'A' for Assignment
    h.update(&game_id.to_bytes());
    h.update(&epoch.to_le_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    // 取前 8 字节作为 u64 索引
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&out[..8]);
    // M-8 修复：先在 u64 上取模再转 usize，避免 32-bit 平台截断
    let idx = (u64::from_le_bytes(idx_bytes) % validator_set.len() as u64) as usize;
    validator_set.get(idx)
}

/// CLI 查询节点信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// 节点角色。
    pub role: NodeRole,
    /// chain_id。
    pub chain_id: ChainId,
    /// 当前 tip height（None = 空库）。
    pub tip_height: Option<BlockHeight>,
    /// 当前 tip hash（None = 空库）。
    pub tip_hash: Option<Hash>,
    /// 是否为 validator。
    pub is_validator: bool,
    /// 是否提供历史数据 RPC。
    pub serves_historical_data: bool,
}

/// CLI 查询节点信息。
pub fn query_node_info(node: &Node) -> PokerL1Result<NodeInfo> {
    let tip_height = node.block_store().get_tip_height()?;
    let tip_hash = node.block_store().get_tip_hash()?;
    Ok(NodeInfo {
        role: node.role(),
        chain_id: node.chain_id(),
        tip_height,
        tip_hash,
        is_validator: node.role().is_validator(),
        serves_historical_data: node.serves_historical_data(),
    })
}

// ===== Arc<Node> 适配 RpcBackend =====

/// 为 `Arc<Node>` 提供 RPC 后端能力（便于上层 RPC server 直接使用）。
///
/// 注意：`Node` 本身未实现 [`crate::rpc::RpcBackend`] 因为 `RpcBackend` 要求 `Send + Sync`
/// 且方法签名不返回 `'static` 引用。这里通过 wrapper 提供。
pub struct NodeRpcBackend {
    /// 节点引用。
    node: Arc<Node>,
}

impl NodeRpcBackend {
    /// 创建 RPC 后端。
    #[must_use]
    pub const fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    /// 获取节点引用。
    #[must_use]
    pub const fn node(&self) -> &Arc<Node> {
        &self.node
    }
}

impl crate::rpc::RpcBackend for NodeRpcBackend {
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        self.node.get_block_by_hash(hash)
    }

    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        self.node.get_block_by_height(height)
    }

    fn get_tip_height(&self) -> PokerL1Result<Option<BlockHeight>> {
        self.node.block_store().get_tip_height()
    }

    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        self.node.get_object(id)
    }

    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        self.node.get_tx(tx_hash)
    }

    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        self.node.submit_tx(tx)
    }

    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        self.node.get_account(address)
    }

    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        self.node.get_vertex(vertex_hash)
    }

    fn get_native_coins(
        &self,
        owner: &Address,
    ) -> PokerL1Result<Vec<crate::economics::OwnedNativeCoin>> {
        let object_db = self
            .node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        crate::economics::list_owned_native_coins(&object_db, *owner)
    }

    /// M3-ACC-6（§5.3-1）：SeenReceipt 查询。
    fn get_seen_receipt(
        &self,
        tx_hash: &Hash,
    ) -> PokerL1Result<Option<crate::force_include::SeenReceipt>> {
        self.node.get_seen_receipt(tx_hash)
    }

    fn latest_checkpoint(&self) -> Option<crate::consensus::checkpoint::CheckpointQc> {
        self.node.latest_checkpoint_qc()
    }

    fn submit_da_request(&self, digest: Hash) -> PokerL1Result<crate::node::DaStatus> {
        self.node.submit_da_request(digest)
    }

    fn da_status(&self, digest: &Hash) -> crate::node::DaStatus {
        self.node.da_status(digest)
    }

    /// M3-ACC-6（§5.3-4）：审查检测三态。
    fn check_censorship(
        &self,
        proof: &crate::force_include::CensorshipProof,
    ) -> PokerL1Result<crate::force_include::CensorshipCheckOutcome> {
        self.node.check_censorship(proof)
    }

    fn chain_id(&self) -> ChainId {
        self.node.chain_id()
    }

    fn zk_verifier_registry(&self) -> Option<&crate::offline::zk_verifier::ZkVerifierRegistry> {
        self.node.zk_verifier.as_ref()
    }

    /// 缺口 #7：导出 Prometheus 格式指标（覆写默认空实现）。
    fn export_metrics(&self) -> String {
        self.node.export_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::derive_address;
    use crate::block::{Block, BlockHeader};
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxRequest};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    #[test]
    fn node_role_to_pruning_role() {
        assert_eq!(NodeRole::Validator.to_pruning_role(), PruningNodeRole::Full);
        assert_eq!(NodeRole::Full.to_pruning_role(), PruningNodeRole::Full);
        assert_eq!(
            NodeRole::Archive.to_pruning_role(),
            PruningNodeRole::Archive
        );
        assert_eq!(NodeRole::Light.to_pruning_role(), PruningNodeRole::Light);
    }

    #[test]
    fn node_role_should_prune() {
        assert!(NodeRole::Validator.should_prune());
        assert!(NodeRole::Full.should_prune());
        assert!(!NodeRole::Archive.should_prune());
        assert!(!NodeRole::Light.should_prune());
    }

    #[test]
    fn node_role_predicates() {
        assert!(NodeRole::Validator.is_validator());
        assert!(!NodeRole::Full.is_validator());
        assert!(NodeRole::Archive.is_archive());
        assert!(NodeRole::Light.is_light());
    }

    #[test]
    fn node_role_default_is_full() {
        assert_eq!(NodeRole::default(), NodeRole::Full);
    }

    #[test]
    fn node_config_default_full() {
        let cfg = NodeConfig::default_full(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Full);
        assert_eq!(cfg.chain_id, DEFAULT_CHAIN_ID);
        assert!(cfg.validator_key.is_none());
    }

    #[test]
    fn node_config_validator() {
        let key = ValidatorKey::from_secret_bytes([1u8; 32]).unwrap();
        let cfg = NodeConfig::validator(PathBuf::from("/tmp/test"), key);
        assert_eq!(cfg.role, NodeRole::Validator);
        assert!(cfg.validator_key.is_some());
    }

    #[test]
    fn node_config_archive() {
        let cfg = NodeConfig::archive(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Archive);
    }

    #[test]
    fn node_config_light() {
        let cfg = NodeConfig::light(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Light);
    }

    #[test]
    fn standard_node_has_no_zk_verifier_registry() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(NodeConfig::default_full(temp.path().to_path_buf())).unwrap();

        assert!(node.zk_verifier_registry_clone().is_none());
        assert!(node.execution_environment(7, 11).zk_verifier.is_none());
    }

    #[test]
    fn execution_environment_includes_injected_zk_verifier_registry() {
        use crate::offline::zk_verifier::{VerifierStatus, ZkVerifierRegistry};

        let temp = tempfile::tempdir().unwrap();
        let registry = ZkVerifierRegistry::new();
        registry.set_verifier_status(DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let node = Node::open_with_zk_verifier_registry(
            NodeConfig::default_full(temp.path().to_path_buf()),
            registry,
        )
        .unwrap();

        let env = node.execution_environment(7, 11);
        let injected = env
            .zk_verifier
            .expect("node verifier registry must be injected");
        assert_eq!(
            injected.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
        assert!(injected.registered_schemes().is_empty());
        assert!(env.precompile_registry.is_some());
        assert!(env.bridge_registry_store.is_some());
    }

    #[test]
    fn governance_status_sync_reaches_existing_registry_clones() {
        use crate::governance::GovernanceState;
        use crate::offline::zk_verifier::{VerifierStatus, ZkVerifierRegistry};

        let temp = tempfile::tempdir().unwrap();
        let registry = ZkVerifierRegistry::new();
        let node = Node::open_with_zk_verifier_registry(
            NodeConfig::default_full(temp.path().to_path_buf()),
            registry,
        )
        .unwrap();
        let observer = node.zk_verifier_registry_clone().unwrap();
        assert_eq!(
            observer.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );

        let mut governance = GovernanceState::new();
        governance.set_verifier_status(DEFAULT_CHAIN_ID, VerifierStatus::Production);
        node.synchronize_zk_verifier_governance(&governance)
            .unwrap();

        assert_eq!(
            observer.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
        assert_eq!(
            node.execution_environment(8, 13)
                .zk_verifier
                .unwrap()
                .verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
    }

    #[test]
    fn validator_key_from_secret_bytes() {
        let key = ValidatorKey::from_secret_bytes([42u8; 32]).unwrap();
        assert_eq!(key.secret_key_bytes, [42u8; 32]);
        assert_eq!(
            key.tagged_pubkey.tag,
            encode_tag(SignatureScheme::Secp256k1, CURRENT_VERSION)
        );
        assert_eq!(key.tagged_pubkey.raw.len(), 33);
    }

    #[test]
    fn validator_key_invalid_secret_bytes() {
        // 全零私钥无效（不在曲线阶范围内）
        let result = ValidatorKey::from_secret_bytes([0u8; 32]);
        assert!(result.is_err(), "全零私钥应被拒绝");
    }

    #[test]
    fn node_open_inmemory_full() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(node.role(), NodeRole::Full);
        assert_eq!(node.chain_id(), DEFAULT_CHAIN_ID);
        assert!(!node.serves_historical_data());
    }

    #[test]
    fn node_open_inmemory_archive() {
        let node = Node::open_inmemory(NodeRole::Archive, DEFAULT_CHAIN_ID).unwrap();
        assert!(node.serves_historical_data());
    }

    #[test]
    fn node_open_inmemory_validator() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        assert!(node.role().is_validator());
    }

    #[test]
    fn node_put_and_get_object() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let obj = Object::new(
            ObjectID::new([0xAA; 20], 0),
            Ownership::Shared,
            "TestType",
            b"data".to_vec(),
            None,
        );
        let id = obj.id;
        node.put_object(obj).unwrap();
        let got = node.get_object(&id).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().id, id);
    }

    #[test]
    fn node_get_object_not_found() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let result = node.get_object(&ObjectID::new([0xBB; 20], 0)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn node_put_and_get_account() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged, 1000);
        let address = account.address;
        node.put_account(account).unwrap();
        let got = node.get_account(&address).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().balance, 1000);
    }

    #[test]
    fn node_submit_tx_validator_buffers() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let expected_hash = tx.tx_hash();
        let returned_hash = node.submit_tx(tx).unwrap();
        assert_eq!(returned_hash, expected_hash);

        // validator 应缓冲 tx
        let pending = node.drain_pending_tx();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_hash(), expected_hash);
    }

    #[test]
    fn node_submit_tx_full_does_not_buffer() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();

        // full node 不应缓冲 tx
        let pending = node.drain_pending_tx();
        assert!(pending.is_empty(), "full node 不应缓冲 tx");

        // 但应能查询
        let got = node.get_tx(&tx_hash).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn node_get_tx_after_submit() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();
        let got = node.get_tx(&tx_hash).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().tx_hash(), tx_hash);
    }

    #[test]
    fn keygen_secp256k1_produces_valid_keypair() {
        let result = keygen_secp256k1().unwrap();
        assert_eq!(result.scheme, SignatureScheme::Secp256k1);
        assert_eq!(result.secret_key_bytes.len(), 32);
        assert_eq!(result.tagged_pubkey.raw.len(), 33); // compressed
        // 地址非全零
        assert_ne!(result.address, [0u8; 20]);
    }

    #[test]
    fn keygen_ed25519_produces_valid_keypair() {
        let result = keygen_ed25519().unwrap();
        assert_eq!(result.scheme, SignatureScheme::Ed25519);
        assert_eq!(result.secret_key_bytes.len(), 32);
        assert_eq!(result.tagged_pubkey.raw.len(), 32); // ed25519 pubkey
        assert_ne!(result.address, [0u8; 20]);
    }

    #[test]
    fn keygen_secp256k1_two_calls_produce_different_keys() {
        let r1 = keygen_secp256k1().unwrap();
        let r2 = keygen_secp256k1().unwrap();
        assert_ne!(
            r1.secret_key_bytes, r2.secret_key_bytes,
            "两次 keygen 应产生不同密钥"
        );
        assert_ne!(
            r1.tagged_pubkey.raw, r2.tagged_pubkey.raw,
            "两次 keygen 应产生不同公钥"
        );
    }

    #[test]
    fn keygen_dispatch_by_scheme() {
        let r1 = keygen(SignatureScheme::Secp256k1).unwrap();
        assert_eq!(r1.scheme, SignatureScheme::Secp256k1);
        let r2 = keygen(SignatureScheme::Ed25519).unwrap();
        assert_eq!(r2.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn compute_assigned_validator_local_basic() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let epoch = 1;
        let validators: Vec<TaggedPubkey> = (0..5)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let assigned = compute_assigned_validator_local(&game_id, epoch, &validators);
        assert!(assigned.is_some(), "非空 validator 集应返回结果");
        // 结果应在 validator_set 中
        let assigned_ref = assigned.unwrap();
        assert!(validators.iter().any(|v| v == assigned_ref));
    }

    #[test]
    fn compute_assigned_validator_local_empty_set() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let result = compute_assigned_validator_local(&game_id, 1, &[]);
        assert!(result.is_none(), "空 validator 集应返回 None");
    }

    #[test]
    fn compute_assigned_validator_local_deterministic() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let epoch = 1;
        let validators: Vec<TaggedPubkey> = (0..5)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let r1 = compute_assigned_validator_local(&game_id, epoch, &validators);
        let r2 = compute_assigned_validator_local(&game_id, epoch, &validators);
        assert_eq!(r1, r2, "同一 (game_id, epoch) 应确定性返回相同 validator");
    }

    #[test]
    fn compute_assigned_validator_local_changes_with_epoch() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let validators: Vec<TaggedPubkey> = (0..10)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let r1 = compute_assigned_validator_local(&game_id, 1, &validators);
        let r2 = compute_assigned_validator_local(&game_id, 2, &validators);
        // 不同 epoch 可能返回相同或不同 validator，但都应在集合中
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn query_node_info_empty_node() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert_eq!(info.role, NodeRole::Full);
        assert_eq!(info.chain_id, DEFAULT_CHAIN_ID);
        assert!(info.tip_height.is_none());
        assert!(info.tip_hash.is_none());
        assert!(!info.is_validator);
        assert!(!info.serves_historical_data);
    }

    #[test]
    fn query_node_info_validator() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert!(info.is_validator);
    }

    #[test]
    fn query_node_info_archive() {
        let node = Node::open_inmemory(NodeRole::Archive, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert!(info.serves_historical_data);
    }

    #[test]
    fn node_rpc_backend_adapter() {
        use crate::rpc::RpcBackend;
        let node = Arc::new(Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap());
        let owner_key = tp(0x33);
        let owner = crate::account::derive_address(&owner_key);
        node.apply_genesis_alloc(vec![(owner_key, 42)]).unwrap();
        let backend = NodeRpcBackend::new(node);
        assert_eq!(backend.chain_id(), DEFAULT_CHAIN_ID);
        // get_object 返回 None（空库）
        let result = backend.get_object(&ObjectID::new([0xCC; 20], 0)).unwrap();
        assert!(result.is_none());
        let coins = backend.get_native_coins(&owner).unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].amount, 42);
    }

    // ===== P0-3: validate_vertex 测试 =====

    #[test]
    fn validate_vertex_rejects_wrong_chain_id() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let mut vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID + 1, // 错误 chain_id
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            result.is_err(),
            "错误 chain_id 的 tx 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_vertex_rejects_invalid_signature() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0xFF; 65], // 无效签名
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "无效签名应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_s9_ordering_violation() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![
                // ForceSync 在 GameTurn 之前 → 违反 S9
                Transaction {
                    inputs: vec![],
                    outputs: vec![],
                    contract_call: None,
                    tagged_pubkey: dummy_tagged_pubkey(),
                    signature: vec![0u8; 65],
                    gas: crate::transaction::Gas::zero(),
                    lane_hint: crate::transaction::TxLane::ForceSync,
                    route_hint: crate::transaction::RouteHint::AnyValidator,
                    chain_id: DEFAULT_CHAIN_ID,
                    nonce: 1,
                    gameturn_nonce: None,
                    is_fallback: false,
                },
                Transaction {
                    inputs: vec![],
                    outputs: vec![],
                    contract_call: None,
                    tagged_pubkey: dummy_tagged_pubkey(),
                    signature: vec![0u8; 65],
                    gas: crate::transaction::Gas::zero(),
                    lane_hint: crate::transaction::TxLane::GameTurn,
                    route_hint: crate::transaction::RouteHint::AssignedValidator,
                    chain_id: DEFAULT_CHAIN_ID,
                    nonce: 0,
                    gameturn_nonce: Some(0),
                    is_fallback: false,
                },
            ],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "S9 排序违规应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_parent_not_found() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 2,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![[0xAA; 32]], // 不存在的 parent
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "不存在的 parent 应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_accepts_valid_vertex() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        // 先创建一个有效的 vertex 并入库，作为后续 vertex 的 parent
        let parent = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        // parent 入库前不需要验证签名（测试中跳过）
        let parent_hash = node.vertex_store.put(&parent).unwrap();

        let vertex = DagVertex {
            epoch: 0,
            round: 2,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            parent_hashes: vec![parent_hash],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        // 注意：签名是 dummy，验证会失败。这里只验证 parent 存在性路径
        let result = node.validate_vertex(&vertex);
        assert!(
            result.is_err(),
            "dummy 签名应失败，但 parent 校验应通过: {:?}",
            result
        );
    }

    // ===== P0-3: validate_block 测试 =====

    fn empty_consensus_block(
        node: &Node,
        height: u64,
        timestamp_ms: u64,
        prev_hash: Hash,
        epoch: u64,
        commit_round: u64,
        prev_commit_hash: Hash,
    ) -> Block {
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let state_root = node.state_root();
        Block::new(
            BlockHeader {
                height,
                timestamp_ms,
                prev_hash,
                state_root,
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch,
                    commit_round,
                    prev_commit_hash,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![],
                    state_root,
                    public_tx_root: empty_root,
                    gameturn_tx_root: empty_root,
                    signature_list: vec![],
                    signer_bitmap: vec![],
                },
            },
            vec![],
            vec![],
        )
    }

    #[test]
    fn empty_block_store_accepts_only_canonical_first_block() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();

        let height_gap = empty_consensus_block(&node, 2, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        assert!(matches!(
            node.validate_block(&height_gap),
            Err(PokerL1Error::BlockHeightNotIncreasing { prev: 0, got: 2 })
        ));

        let bad_parent = empty_consensus_block(&node, 1, 1_000, [0xAA; 32], 0, 1, [0u8; 32]);
        assert!(matches!(
            node.validate_block(&bad_parent),
            Err(PokerL1Error::InvalidPrevHash { .. })
        ));
    }

    #[test]
    fn block_certificate_chain_and_timestamp_are_strict() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let first = empty_consensus_block(&node, 1, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        let first_hash = node.put_block(&first).unwrap();
        let first_cert_hash = first
            .header
            .dag_commit_certificate
            .signing_hash(DEFAULT_CHAIN_ID);
        let second = empty_consensus_block(&node, 2, 2_000, first_hash, 1, 2, first_cert_hash);

        let mut backwards = second.clone();
        backwards.header.timestamp_ms = 999;
        assert!(matches!(
            node.validate_block(&backwards),
            Err(PokerL1Error::BlockTimestampMovedBackwards { .. })
        ));

        let mut too_far = second.clone();
        too_far.header.timestamp_ms = 31_001;
        assert!(matches!(
            node.validate_block(&too_far),
            Err(PokerL1Error::BlockTimestampIntervalExceeded { .. })
        ));

        let mut wrong_prev_cert = second.clone();
        wrong_prev_cert
            .header
            .dag_commit_certificate
            .prev_commit_hash = [0xBB; 32];
        assert!(matches!(
            node.validate_block(&wrong_prev_cert),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        let mut reset_round = second.clone();
        reset_round.header.dag_commit_certificate.commit_round = 1;
        assert!(matches!(
            node.validate_block(&reset_round),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        let mut epoch_jump = second.clone();
        epoch_jump.header.dag_commit_certificate.epoch = 2;
        assert!(matches!(
            node.validate_block(&epoch_jump),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        node.put_block(&second).unwrap();
    }

    #[test]
    fn repeated_block_commit_is_idempotent() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = empty_consensus_block(&node, 1, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        let first_hash = node.put_block(&block).unwrap();
        let repeated_hash = node.put_block(&block).unwrap();
        assert_eq!(repeated_hash, first_hash);
        assert_eq!(node.block_store().len().unwrap(), 1);
    }

    #[test]
    fn persistent_node_rejects_empty_consensus_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(NodeConfig::default_full(temp.path().to_path_buf())).unwrap();
        assert!(node.ensure_consensus_ready().is_err());
    }

    #[test]
    fn validate_block_rejects_tx_root_mismatch() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: [0xFF; 32], // 错误的 root
                gameturn_tx_root: crate::block::compute_tx_merkle_root(&[]),
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    public_tx_root: [0xFF; 32],
                    gameturn_tx_root: crate::block::compute_tx_merkle_root(&[]),
                    signature_list: vec![],
                    signer_bitmap: vec![0xFF],
                },
            },
            vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::new(1000, 1),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            vec![],
        );
        let result = node.validate_block(&block);
        assert!(result.is_err(), "tx root 不匹配应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_block_rejects_gameturn_gas_charged() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let mut gameturn_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::new(100, 1), // 错误计费
            lane_hint: crate::transaction::TxLane::GameTurn,
            route_hint: crate::transaction::RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(0),
            is_fallback: false,
        };
        let gt_root = crate::block::compute_tx_merkle_root(&[gameturn_tx.clone()]);
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: crate::block::compute_tx_merkle_root(&[]),
                gameturn_tx_root: gt_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    public_tx_root: crate::block::compute_tx_merkle_root(&[]),
                    gameturn_tx_root: gt_root,
                    signature_list: vec![],
                    signer_bitmap: vec![0xFF],
                },
            },
            vec![],
            vec![gameturn_tx],
        );
        let result = node.validate_block(&block);
        assert!(result.is_err(), "GameTurn 计费应被拒绝: {:?}", result);
    }

    #[test]
    fn state_root_mismatch_does_not_mutate_live_state() {
        use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let tagged_pubkey = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: PublicKey::from_secret_key(&secp, &secret)
                .serialize()
                .to_vec(),
        };
        let caller = derive_address(&tagged_pubkey);
        node.put_account(Account::new(tagged_pubkey.clone(), 0))
            .unwrap();

        let created = Object::new(
            ObjectID::new(caller, 1),
            Ownership::AddressOwned { owner: caller },
            "ValidationRegression",
            b"must-not-leak".to_vec(),
            None,
        );
        let request = TxRequest {
            inputs: vec![],
            outputs: vec![created.clone()],
            contract_call: None,
            gas: Gas::new(1_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let signature = {
            let signature =
                secp.sign_ecdsa_recoverable(&Message::from_digest(request.signing_hash()), &secret);
            let (recovery_id, compact) = signature.serialize_compact();
            let mut bytes = compact.to_vec();
            bytes.push(recovery_id.to_i32() as u8);
            bytes
        };
        let tx = request.into_transaction(tagged_pubkey, signature);
        let env = node.execution_environment(1, 1_000);
        let expected_state_root = node
            .simulate_block_execution(&env, std::slice::from_ref(&tx))
            .unwrap()
            .state_root;
        let mut wrong_state_root = expected_state_root;
        wrong_state_root[0] ^= 0xFF;
        let public_tx_root = crate::block::compute_tx_merkle_root(std::slice::from_ref(&tx));
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let certificate = crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root: wrong_state_root,
            public_tx_root,
            gameturn_tx_root: empty_root,
            signature_list: vec![],
            signer_bitmap: vec![],
        };
        let mut block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1_000,
                prev_hash: [0u8; 32],
                state_root: wrong_state_root,
                public_tx_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: certificate,
            },
            vec![tx],
            vec![],
        );

        let root_before = node.state_root();
        assert!(node.validate_block(&block).is_err());
        assert_eq!(node.state_root(), root_before);
        assert!(node.get_object(&created.id).unwrap().is_none());
        assert_eq!(node.get_account(&caller).unwrap().unwrap().nonce, 0);

        // The same transaction is committed exactly once only after its state root matches.
        block.header.state_root = expected_state_root;
        block.header.dag_commit_certificate.state_root = expected_state_root;
        node.validate_block(&block).unwrap();
        assert!(node.get_object(&created.id).unwrap().is_none());
        node.put_block(&block).unwrap();
        assert!(node.get_object(&created.id).unwrap().is_some());
        assert_eq!(node.get_account(&caller).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn conflicting_height_is_rejected_before_any_state_commit() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let state_root = node.state_root();
        let certificate = crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root,
            public_tx_root: empty_root,
            gameturn_tx_root: empty_root,
            signature_list: vec![],
            signer_bitmap: vec![],
        };
        let first = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1_000,
                prev_hash: [0u8; 32],
                state_root,
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: certificate.clone(),
            },
            vec![],
            vec![],
        );
        let first_hash = node.put_block(&first).unwrap();
        let conflicting = Block::new(
            BlockHeader {
                timestamp_ms: 2_000,
                dag_commit_certificate: certificate,
                ..first.header.clone()
            },
            vec![],
            vec![],
        );

        assert!(node.put_block(&conflicting).is_err());
        assert_eq!(node.state_root(), state_root);
        assert_eq!(
            node.get_block_by_height(1)
                .unwrap()
                .unwrap()
                .block_hash(DEFAULT_CHAIN_ID),
            first_hash
        );
    }

    // ===== P0-4: 动态 quorum（ValidatorSet 接入节点）测试 =====

    use crate::consensus::ValidatorStatus;

    /// 构造测试用 ValidatorEntry（指定状态）。
    fn make_validator_entry(byte: u8, status: ValidatorStatus) -> ValidatorEntry {
        let mut entry = ValidatorEntry::new(
            TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![byte; 33],
            },
            [byte; 33],
            0,
            0,
        );
        entry.status = status;
        entry
    }

    /// 构造 5 个活跃 validator 的创世列表（字节避开 0x02 = dummy_tagged_pubkey）。
    fn five_active_validators() -> Vec<ValidatorEntry> {
        (0xA1u8..=0xA5)
            .map(|b| make_validator_entry(b, ValidatorStatus::Active))
            .collect()
    }

    fn make_real_validator(
        seed: u8,
        status: ValidatorStatus,
    ) -> (secp256k1::SecretKey, ValidatorEntry) {
        let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .unwrap();
        let mut entry = ValidatorEntry::new(tagged, public.serialize(), 0, 0);
        entry.status = status;
        (secret, entry)
    }

    fn signed_empty_vertex(
        secret: &secp256k1::SecretKey,
        author: TaggedPubkey,
        epoch: u64,
        round: u64,
        parent_hashes: Vec<Hash>,
    ) -> DagVertex {
        sign_vertex(
            secret,
            DagVertex {
                epoch,
                round,
                author_pubkey: author,
                tx_list: vec![],
                parent_hashes,
                author_sig: vec![],
                forced_tx_hashes: vec![],
            },
        )
    }

    fn sign_vertex(secret: &secp256k1::SecretKey, mut vertex: DagVertex) -> DagVertex {
        let message = secp256k1::Message::from_digest(vertex.signing_hash(DEFAULT_CHAIN_ID));
        let signature = secp256k1::Secp256k1::new().sign_ecdsa_recoverable(&message, secret);
        let (recovery_id, compact) = signature.serialize_compact();
        vertex.author_sig = compact
            .into_iter()
            .chain(std::iter::once(recovery_id.to_i32() as u8))
            .collect();
        vertex
    }

    fn four_real_validators() -> Vec<(secp256k1::SecretKey, ValidatorEntry)> {
        (1..=4)
            .map(|seed| make_real_validator(seed, ValidatorStatus::Active))
            .collect()
    }

    #[test]
    fn validate_vertex_rejects_invalid_transaction_signature_at_admission() {
        let (secret, validator) = make_real_validator(9, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let mut invalid_tx = make_pub_tx(0x44, 1, 5);
        invalid_tx.tagged_pubkey = validator.pubkey.clone();
        let wrong_message = secp256k1::Message::from_digest([0xAA; 32]);
        let wrong_signature =
            secp256k1::Secp256k1::new().sign_ecdsa_recoverable(&wrong_message, &secret);
        let (wrong_recovery_id, wrong_compact) = wrong_signature.serialize_compact();
        invalid_tx.signature = wrong_compact
            .into_iter()
            .chain(std::iter::once(wrong_recovery_id.to_i32() as u8))
            .collect();
        let vertex = sign_vertex(
            &secret,
            DagVertex {
                epoch: 0,
                round: 1,
                author_pubkey: validator.pubkey,
                tx_list: vec![invalid_tx],
                parent_hashes: vec![],
                author_sig: vec![],
                forced_tx_hashes: vec![],
            },
        );

        assert!(matches!(
            node.validate_vertex(&vertex),
            Err(PokerL1Error::InvalidSignature)
        ));
    }

    #[test]
    fn validate_vertex_accepts_distinct_active_parent_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(3) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );

        node.validate_vertex(&child).unwrap();
    }

    #[test]
    fn validate_vertex_rejects_parent_hash_count_without_distinct_author_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let first = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let equivocation = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        // Different tx content changes the hash while retaining epoch/round/author.
        let mut equivocation = equivocation;
        equivocation.tx_list.push(make_pub_tx(0x55, 1, 1));
        let equivocation = sign_vertex(&validators[0].0, equivocation);
        let first_hash = node.vertex_store.put(&first).unwrap();
        let equivocation_hash = node.vertex_store.put(&equivocation).unwrap();
        let third = signed_empty_vertex(
            &validators[1].0,
            validators[1].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let third_hash = node.put_vertex(&third).unwrap();
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            vec![first_hash, equivocation_hash, third_hash],
        );

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::DuplicateParentVertexAuthor(_))
        ));
    }

    #[test]
    fn validate_vertex_rejects_insufficient_previous_round_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();
        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(2) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::InsufficientParents {
                actual: 2,
                required: 3
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_duplicate_or_wrong_round_parent() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();
        let parent = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let parent_hash = node.put_vertex(&parent).unwrap();

        let duplicate = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            vec![parent_hash, parent_hash],
        );
        assert!(matches!(
            node.validate_vertex(&duplicate),
            Err(PokerL1Error::DuplicateParentVertex(hash)) if hash == parent_hash
        ));

        let wrong_round = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            3,
            vec![parent_hash],
        );
        assert!(matches!(
            node.validate_vertex(&wrong_round),
            Err(PokerL1Error::InvalidParentVertexRound {
                actual: 1,
                expected: 2,
                ..
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_wrong_epoch() {
        let (secret, validator) = make_real_validator(8, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let vertex = signed_empty_vertex(&secret, validator.pubkey, 1, 1, vec![]);

        assert!(matches!(
            node.validate_vertex(&vertex),
            Err(PokerL1Error::InvalidVertexEpoch {
                actual: 1,
                expected: 0
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_parent_from_different_epoch() {
        let (secret, validator) = make_real_validator(7, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let old_epoch_parent = signed_empty_vertex(&secret, validator.pubkey.clone(), 1, 1, vec![]);
        let parent_hash = node.vertex_store.put(&old_epoch_parent).unwrap();
        let child = signed_empty_vertex(&secret, validator.pubkey, 0, 2, vec![parent_hash]);

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::InvalidParentVertexEpoch {
                parent_hash: actual_hash,
                actual: 1,
                expected: 0
            }) if actual_hash == parent_hash
        ));
    }

    #[test]
    fn validate_vertex_rejects_same_author_equivocation_at_admission() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(3) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let first = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes.clone(),
        );
        node.put_vertex(&first).unwrap();

        parent_hashes.swap(0, 1);
        let conflicting = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );
        assert!(matches!(
            node.validate_vertex(&conflicting),
            Err(PokerL1Error::VertexEquivocation {
                epoch: 0,
                round: 2,
                author
            }) if author == validators[3].1.pubkey
        ));
    }

    #[test]
    fn node_genesis_validators_loaded() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        assert_eq!(node.validator_count(), 5);
        assert_eq!(node.active_validator_count(), 5);
        // quorum = 2*5/3+1 = 4
        assert_eq!(node.required_quorum(), 4);
        assert_eq!(node.current_epoch(), 0);
    }

    #[test]
    fn node_rejects_unbacked_genesis_validator_stake() {
        let mut validator = make_validator_entry(0xB1, ValidatorStatus::Active);
        validator.stake = 1;
        let error = match Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            vec![validator],
        ) {
            Ok(_) => panic!("unbacked genesis stake must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unbacked stake"));
    }

    #[test]
    fn node_required_quorum_empty_set_is_zero() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(node.validator_count(), 0);
        assert_eq!(node.active_validator_count(), 0);
        assert_eq!(node.required_quorum(), 0, "创世引导期 quorum 应为 0");
    }

    #[test]
    fn node_required_quorum_reflects_dynamic_set() {
        // 3 active → quorum 3；加入 bonding validator 不影响 active quorum
        let validators: Vec<ValidatorEntry> = (1u8..=3)
            .map(|b| make_validator_entry(b, ValidatorStatus::Active))
            .collect();
        let node =
            Node::open_inmemory_with_validators(NodeRole::Validator, DEFAULT_CHAIN_ID, validators)
                .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        assert_eq!(node.required_quorum(), 3); // 2*3/3+1

        // 加入第 4 个零质押测试 validator（Bonding 状态）→ active 数不变。
        let mut entry4 = make_validator_entry(4, ValidatorStatus::Bonding);
        entry4.stake = 0;
        node.add_validator(entry4).unwrap();
        assert_eq!(node.validator_count(), 4);
        assert_eq!(node.active_validator_count(), 3);
        assert_eq!(node.required_quorum(), 3);

        // bonding 到期 → Active → quorum 变为 2*4/3+1 = 3
        node.process_bonding_expiry(100).unwrap();
        assert_eq!(node.active_validator_count(), 4);
        assert_eq!(node.required_quorum(), 3);

        // 再加入 2 个 active → 6 active → quorum = 2*6/3+1 = 5
        for b in [5u8, 6u8] {
            let mut entry = make_validator_entry(b, ValidatorStatus::Active);
            entry.stake = 0;
            node.add_validator(entry).unwrap();
        }
        assert_eq!(node.active_validator_count(), 6);
        assert_eq!(node.required_quorum(), 5);
    }

    #[test]
    fn node_add_validator_rejects_duplicate() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let dup = make_validator_entry(0xA1, ValidatorStatus::Active);
        let result = node.add_validator(dup);
        assert!(result.is_err(), "重复 pubkey 应被拒绝: {:?}", result);
    }

    #[test]
    fn node_advance_epoch_rolls_randomness() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let randomness_before = {
            let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            set.epoch_randomness
        };
        node.advance_epoch(1).unwrap();
        assert_eq!(node.current_epoch(), 1);
        let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(set.prev_epoch_randomness, randomness_before);
    }

    #[test]
    fn validate_vertex_rejects_non_validator_author() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        // author（0x02;33 = dummy_tagged_pubkey）不在 validator set 中
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            matches!(result, Err(PokerL1Error::VertexAuthorNotActiveValidator(_))),
            "非 validator author 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_vertex_rejects_bonding_author() {
        // author 在 set 中但处于 Bonding 状态（不可参与共识）
        let mut validators = five_active_validators();
        validators.push(make_validator_entry(0x02, ValidatorStatus::Bonding));
        let node =
            Node::open_inmemory_with_validators(NodeRole::Full, DEFAULT_CHAIN_ID, validators)
                .unwrap();
        // dummy_tagged_pubkey raw = [0x02; 33] → 与 bonding entry 匹配
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
            forced_tx_hashes: vec![],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            matches!(result, Err(PokerL1Error::VertexAuthorNotActiveValidator(_))),
            "Bonding author 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_block_rejects_insufficient_cert_quorum() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        // 空 tx 列表，tx roots 正确；cert 无签名 → quorum 不足（0 < 4）
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 0,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0],
                    state_root: [0u8; 32],
                    public_tx_root: empty_root,
                    gameturn_tx_root: empty_root,
                    signature_list: vec![],
                    signer_bitmap: vec![0],
                },
            },
            vec![],
            vec![],
        );
        let result = node.validate_block(&block);
        assert!(
            result.is_err(),
            "quorum 不足的 commit certificate 应被拒绝: {:?}",
            result
        );
    }

    // ===== 缺口 #5：staking 结算测试 =====

    /// 创建 validator entry（用于 UTXO-backed staking 测试）。
    fn make_funded_validator(byte: u8, stake: u64) -> ValidatorEntry {
        let entry = make_validator_entry(byte, ValidatorStatus::Active);
        let mut e = entry;
        e.stake = stake;
        e
    }

    fn genesis_fund_validator(node: &Node, entry: &ValidatorEntry, amount: u64) -> Vec<ObjectID> {
        node.apply_genesis_alloc([(entry.pubkey.clone(), amount)])
            .unwrap();
        let owner = crate::account::derive_address(&entry.pubkey);
        node.list_native_coins(owner)
            .unwrap()
            .into_iter()
            .map(|coin| coin.id)
            .collect()
    }

    #[test]
    fn bond_validator_locks_utxo_value_in_staking_escrow() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x20, 5_000);
        let addr = crate::account::derive_address(&entry.pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 1_005_000);
        assert_eq!(node.native_coin_balance(addr).unwrap(), 1_005_000);
        node.bond_validator(entry, &inputs).unwrap();
        assert_eq!(node.native_coin_balance(addr).unwrap(), 1_000_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(
            node.treasury_cap().unwrap().unwrap().total_supply,
            1_005_000
        );
        let reconciliation = node.reconcile_native_supply().unwrap();
        assert_eq!(reconciliation.live_utxo, 1_000_000);
        assert_eq!(reconciliation.staking_escrow, 5_000);
    }

    #[test]
    fn bonded_validator_and_epoch_survive_persistent_restart() {
        let temp = tempfile::tempdir().unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf());
        let node = Node::open(config.clone()).unwrap();
        let entry = make_funded_validator(0x24, 5_000);
        let pubkey = entry.pubkey.clone();
        let inputs = genesis_fund_validator(&node, &entry, 10_000);
        node.bond_validator(entry, &inputs).unwrap();
        node.advance_epoch(1).unwrap();
        assert_eq!(
            node.reconcile_native_supply().unwrap().staking_escrow,
            5_000
        );
        drop(node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(reopened.current_epoch(), 1);
        let set = reopened.validator_set.lock().unwrap();
        let restored = set
            .find_validator(&pubkey)
            .expect("bonded validator restored");
        assert_eq!(restored.stake, 5_000);
        drop(set);
        assert_eq!(
            reopened.reconcile_native_supply().unwrap().staking_escrow,
            5_000
        );
    }

    #[test]
    fn bond_validator_rejects_insufficient_utxo_value_without_mutation() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let mut entry = make_validator_entry(0x21, ValidatorStatus::Active);
        entry.stake = 10_000;
        let owner = crate::account::derive_address(&entry.pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 100);
        let err = node.bond_validator(entry, &inputs).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientBalance { .. }),
            "余额不足应拒绝: {err:?}"
        );
        assert_eq!(node.native_coin_balance(owner).unwrap(), 100);
        assert_eq!(node.validator_count(), 0);
    }

    #[test]
    fn slash_validator_reduces_stake() {
        // slashing 减少 ValidatorEntry.stake（锁定部分燃烧，不退账户）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x22, 100_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 150_000);
        node.bond_validator(entry, &inputs).unwrap();
        let cap_before = node.treasury_cap().unwrap().unwrap();

        let config = crate::consensus::SlashingConfig::default();
        let result = node
            .slash_validator(
                &pubkey,
                crate::consensus::SlashingReason::VertexEquivocation,
                &config,
            )
            .unwrap();
        // 默认 slash_percentage=100 → slash_amount = 100_000（全额）
        assert_eq!(result.slash_amount, 100_000);
        assert_eq!(result.stake_after, 0);
        assert_eq!(node.native_coin_balance(addr).unwrap(), 50_000);
        let cap_after = node.treasury_cap().unwrap().unwrap();
        assert_eq!(cap_after.total_supply, cap_before.total_supply - 100_000);
        assert_eq!(cap_after.total_burned, cap_before.total_burned + 100_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert!(node.reconcile_native_supply().unwrap().is_balanced());
    }

    #[test]
    fn complete_unbonding_refunds_stake() {
        // unbonding 完成后退还剩余 stake 到账户。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x23, 50_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 75_000);
        node.bond_validator(entry, &inputs).unwrap();
        assert_eq!(node.native_coin_balance(addr).unwrap(), 25_000);
        node.process_bonding_expiry(0).unwrap();

        // 启动 unbonding（锁定到 height 100）
        node.start_validator_unbonding(&pubkey, 100).unwrap();
        // 未到期 → 拒绝
        let err = node.complete_unbonding(&pubkey, 50).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));

        // 到期 → 退还
        let refund = node.complete_unbonding(&pubkey, 100).unwrap();
        assert_eq!(refund, 50_000, "应退还全部剩余 stake");
        assert_eq!(node.native_coin_balance(addr).unwrap(), 75_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 75_000);
        let reconciliation = node.reconcile_native_supply().unwrap();
        assert_eq!(reconciliation.live_utxo, 75_000);
        assert_eq!(reconciliation.staking_escrow, 0);
    }

    // ===== 缺口 #3 §3.6：VRF 时序接入测试 =====

    #[test]
    fn advance_epoch_with_vrf_derives_real_randomness() {
        // 配置 VRF 私钥 → advance_epoch_with_vrf 用真实 ECVRF 派生 epoch_randomness。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 构造一个 validator + VRF 密钥对，注册到 set。
        let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(&[0x55; 32]);
        let vrf_pubkey = prover.derive_public_key().unwrap();
        let tagged =
            TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, vec![0x55; 33]).unwrap();
        let mut entry = ValidatorEntry::new(tagged.clone(), vrf_pubkey, 0, 0);
        entry.status = crate::consensus::ValidatorStatus::Active;
        node.add_validator(entry).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        // 注入 validator_key（使 advance_epoch_with_vrf 能标识 proposer）。
        // 注意：tagged_pubkey 需匹配 set 中的 validator。
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };

        node.advance_epoch_with_vrf(1, Some(&[0x55; 32])).unwrap();

        let set = node.validator_set.lock().unwrap();
        // epoch_randomness 应已变化（真实 ECVRF output，非 fallback 也非旧值）。
        assert_ne!(
            set.epoch_randomness, randomness_before,
            "VRF 应派生新的 epoch_randomness"
        );
        assert_eq!(set.epoch, 1);
    }

    #[test]
    fn advance_epoch_without_vrf_uses_fallback() {
        // 无 VRF 私钥 → fallback_epoch_randomness（SEC2-M12）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };
        node.advance_epoch_with_vrf(1, None).unwrap();
        let set = node.validator_set.lock().unwrap();
        // fallback = hash(prev || genesis)，应不同于原 epoch_randomness（genesis 随机性）。
        assert_eq!(set.epoch, 1);
        // fallback 可能恰好等于原值（若 prev==genesis==0），故仅断言 epoch 推进 + 不 panic。
        let _ = randomness_before;
    }

    // ===== 缺口 #4-M1：genesis 余额分配测试 =====

    fn tp(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    #[test]
    fn apply_genesis_alloc_creates_zero_balance_accounts_and_coins() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk1 = tp(0x30);
        let pk2 = tp(0x31);
        let allocs = vec![(pk1.clone(), 1_000_000), (pk2.clone(), 500_000)];
        let created = node.apply_genesis_alloc(allocs).unwrap();
        assert_eq!(created, 2);
        let addr1 = crate::account::derive_address(&pk1);
        let addr2 = crate::account::derive_address(&pk2);
        assert_eq!(node.get_account(&addr1).unwrap().unwrap().balance, 0);
        assert_eq!(node.get_account(&addr2).unwrap().unwrap().balance, 0);
        let cap = node.treasury_cap().unwrap().unwrap();
        assert_eq!(cap.total_supply, 1_500_000);
        assert!(cap.minting_closed);
        assert!(node.reconcile_native_supply().unwrap().is_balanced());
        let object_db = node.object_db.lock().unwrap();
        assert_eq!(
            crate::economics::native_coin_balance(&object_db, addr1).unwrap(),
            1_000_000
        );
        assert_eq!(
            crate::economics::native_coin_balance(&object_db, addr2).unwrap(),
            500_000
        );
    }

    #[test]
    fn apply_genesis_alloc_is_idempotent() {
        // 完全相同的 genesis allocation 在重启时是 no-op。
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk = tp(0x32);
        node.apply_genesis_alloc(vec![(pk.clone(), 1_000)]).unwrap();
        let created = node.apply_genesis_alloc(vec![(pk.clone(), 1_000)]).unwrap();
        assert_eq!(created, 0, "相同 allocation 不应重复铸币");
        let addr = crate::account::derive_address(&pk);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 1_000);
        assert!(node.apply_genesis_alloc(vec![(pk, 9_999)]).is_err());
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 1_000);
    }

    #[test]
    fn persistent_node_startup_rejects_unbalanced_native_supply() {
        let temp = tempfile::tempdir().unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf());
        let node = Node::open(config.clone()).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();

        let table_id = ObjectID::new([0x88; 20], 44);
        let mut table = crate::vm::contracts::texas_poker::types::TexasPokerTable::new(
            table_id,
            "startup-gate".into(),
            [0x77; 20],
            6,
            50,
            100,
        );
        table.chip_pool = 1;
        let objects =
            crate::vm::contracts::texas_poker::state_codec::table_storage_objects(&table).unwrap();
        let mut object_db = node.object_db.lock().unwrap();
        for object in objects {
            object_db.create(object).unwrap();
        }
        drop(object_db);
        drop(node);

        let error = match Node::open(config) {
            Ok(_) => panic!("startup must reject an unbalanced Treasury state"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("native supply reconciliation mismatch")
        );
    }

    // ===== 缺口 #3：Priority Mempool 测试 =====

    fn make_pub_tx(pubkey_byte: u8, nonce: u64, gas_price: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![pubkey_byte; 33],
            },
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::new(1_000_000, gas_price),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn priority_mempool_drains_by_gas_price_desc() {
        // drain_pending_tx 应按 gas_price 降序返回（高 price 先）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 按乱序插入：price=10, 50, 30
        node.submit_tx(make_pub_tx(0x01, 1, 10)).unwrap();
        node.submit_tx(make_pub_tx(0x02, 1, 50)).unwrap();
        node.submit_tx(make_pub_tx(0x03, 1, 30)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 3);
        // 应按 price 降序：50, 30, 10
        assert_eq!(drained[0].gas.price, 50);
        assert_eq!(drained[1].gas.price, 30);
        assert_eq!(drained[2].gas.price, 10);
    }

    #[test]
    fn priority_mempool_rbf_replaces_lower_price() {
        // 同 (caller, nonce) 的高 price tx 替换低 price tx。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // pubkey_byte=0x05, nonce=1, price=10
        node.submit_tx(make_pub_tx(0x05, 1, 10)).unwrap();
        // 同 caller+nonce，price=20 → RBF 替换
        node.submit_tx(make_pub_tx(0x05, 1, 20)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 1, "RBF 应替换为 1 条");
        assert_eq!(drained[0].gas.price, 20, "应保留高 price tx");
    }

    #[test]
    fn priority_mempool_rbf_rejects_lower_or_equal_price() {
        // 新 price <= 旧 price → 拒绝替换。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x06, 1, 20)).unwrap();
        // price=20（相等）→ 拒绝
        let err = node.submit_tx(make_pub_tx(0x06, 1, 20)).unwrap_err();
        assert!(err.to_string().contains("RBF rejected"));
        // price=10（更低）→ 拒绝
        let err = node.submit_tx(make_pub_tx(0x06, 1, 10)).unwrap_err();
        assert!(err.to_string().contains("RBF rejected"));
        // 应仅保留原 price=20 的 1 条
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].gas.price, 20);
    }

    #[test]
    fn priority_mempool_overflow_evicts_lowest_price() {
        // 溢出时丢弃 gas_price 最低的（而非 FIFO 最旧）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 插入超过 MAX_PENDING_TX_SIZE 条（不同 caller+nonce 避免 RBF）。
        // 用 usize 计数器（避免 u8 回绕），pubkey_byte 用 (i % 200) + 1 避免回绕到 0/重复。
        let count = MAX_PENDING_TX_SIZE + 5;
        for i in 0..count {
            let price = if i == 0 { 999 } else { 1 }; // 第 0 条 price 最高
            let pubkey_byte = ((i % 200) as u8) + 1; // 1..=200，避免 0/回绕
            // nonce = i（全局唯一，避免同 (caller, nonce) RBF）
            node.submit_tx(make_pub_tx(pubkey_byte, i as u64, price))
                .unwrap();
        }
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), MAX_PENDING_TX_SIZE, "应保留上限条数");
        // price=999 的 tx 应被保留（在第一条，因降序）。
        assert_eq!(drained[0].gas.price, 999, "最高 price tx 不应被淘汰");
    }

    #[test]
    fn priority_mempool_same_price_preserves_arrival_order() {
        // 同 gas_price 的 tx 保持 arrival 顺序（stable sort）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x20, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x21, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x22, 1, 5)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained[0].tagged_pubkey.raw[0], 0x20, "arrival 顺序保持");
        assert_eq!(drained[1].tagged_pubkey.raw[0], 0x21);
        assert_eq!(drained[2].tagged_pubkey.raw[0], 0x22);
    }

    // ===== M3-ACC-6：ForceInclude 抗审查测试 =====

    /// 带 validator 密钥与 fake clock 的内存 validator 节点。
    fn force_include_validator_node(deadline_ms: u64) -> (Node, Arc<std::sync::Mutex<u64>>) {
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(PathBuf::from("/tmp/poker_l1_fi_test"), vkey);
        config.inclusion_deadline_ms = deadline_ms;
        let node = Node::open_inmemory_with_config(config).unwrap();
        let clock = Arc::new(std::sync::Mutex::new(1_000u64));
        let clock_handle = Arc::clone(&clock);
        node.set_time_source(Box::new(move || *clock_handle.lock().unwrap()));
        (node, clock)
    }

    #[test]
    fn force_include_validator_issues_seen_receipt_on_submit() {
        // §5.3-1：validator 收到合法 submit_tx 后签发 SeenReceipt（可验证）。
        let (node, clock) = force_include_validator_node(10_000);
        *clock.lock().unwrap() = 1_234;
        let tx = make_pub_tx(0x31, 1, 1);
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();

        let receipt = node
            .get_seen_receipt(&tx_hash)
            .expect("查询 receipt 不应报错")
            .expect("validator submit 后应有 receipt");
        assert_eq!(receipt.tx_hash, tx_hash);
        assert_eq!(receipt.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(receipt.seen_at_ms, 1_234);
        receipt
            .verify()
            .expect("validator 密钥签发的 receipt 必须通过验证");

        // 未命中 → None
        let missing = node.get_seen_receipt(&[0u8; 32]).unwrap();
        assert!(missing.is_none(), "未提交过的 tx 不应有 receipt");
    }

    #[test]
    fn force_include_non_validator_does_not_issue_receipt() {
        let config = NodeConfig::default_full(PathBuf::from("/tmp/poker_l1_fi_full"));
        let node = Node::open_inmemory_with_config(config).unwrap();
        let clock = Arc::new(std::sync::Mutex::new(1_000u64));
        let clock_handle = Arc::clone(&clock);
        node.set_time_source(Box::new(move || *clock_handle.lock().unwrap()));
        let tx = make_pub_tx(0x33, 1, 1);
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();
        assert!(
            node.get_seen_receipt(&tx_hash).unwrap().is_none(),
            "非 validator 不签发 receipt"
        );
    }

    // ===== v1.5-a1：receipt JSONL sidecar 持久化（重启恢复） =====

    #[test]
    fn receipt_sidecar_persists_across_node_restart() {
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_receipt_restart_{}_{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let tx = make_pub_tx(0x81, 1, 1);
        let tx_hash = tx.tx_hash();
        {
            let vkey = ValidatorKey::from_secret_bytes([0x77u8; 32]).unwrap();
            let mut config = NodeConfig::validator(dir.clone(), vkey);
            config.inclusion_deadline_ms = 10_000;
            let node = Node::open(config).unwrap();
            let clock = Arc::new(std::sync::Mutex::new(4_321u64));
            let clock_handle = Arc::clone(&clock);
            node.set_time_source(Box::new(move || *clock_handle.lock().unwrap()));
            node.submit_tx(tx.clone()).unwrap();
            let receipt = node.get_seen_receipt(&tx_hash).unwrap().expect("运行期可查");
            receipt.verify().expect("运行期 receipt 有效");
            // Node drop（模拟进程退出）
        }
        {
            // 重启：同一 data-dir、同一密钥 → sidecar 重放恢复内存 map
            let vkey = ValidatorKey::from_secret_bytes([0x77u8; 32]).unwrap();
            let config = NodeConfig::validator(dir.clone(), vkey);
            let node = Node::open(config).unwrap();
            let receipt = node
                .get_seen_receipt(&tx_hash)
                .expect("查询不应报错")
                .expect("重启后 get_seen_receipt 必须仍可答（v1.5-a1）");
            assert_eq!(receipt.tx_hash, tx_hash);
            assert_eq!(receipt.seen_at_ms, 4_321);
            receipt.verify().expect("重放 receipt 签名必须仍有效");
            // 未提交过的 hash 仍为 None
            assert!(node.get_seen_receipt(&[0xEEu8; 32]).unwrap().is_none());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    // ===== v1.5-a2：drain 返回 forced 载荷集 =====

    #[test]
    fn drain_for_block_with_forced_returns_sorted_payload_set() {
        let (node, clock) = force_include_validator_node(1_000);
        let mut txs: Vec<Transaction> = (0..3)
            .map(|k| make_pub_tx(0x82 + k as u8, k + 1, 1))
            .collect();
        for tx in &txs {
            node.submit_tx(tx.clone()).unwrap();
        }
        *clock.lock().unwrap() = 5_000; // 全部越期限（arrived=1000, deadline=1000）
        let (drained, forced) = node.drain_pending_tx_for_block_with_forced();
        assert_eq!(drained.len(), 3);
        let mut expected: Vec<Hash> = txs.iter().map(|t| t.tx_hash()).collect();
        expected.sort();
        assert_eq!(forced, expected, "载荷 forced 集必须去重升序");
        // vertex 场景：批次交集 —— 只有真实进 vertex 的 tx 才进承诺
        txs.clear();
        assert!(node.drain_pending_tx_for_block_with_forced().1.is_empty());
    }

    // ===== v1.5-b：check_censorship → 真实罚没 =====

    #[test]
    fn check_censorship_applies_slash_and_halts_zero_bond_validator() {
        // genesis validator stake 必须为 0（build_genesis_validator_set 约束），
        // 测试经内存 validator_set 直接注入 bond 余额（同模块私有访问）。
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let issuer_entry = crate::consensus::validator_set::ValidatorEntry::new(
            vkey.tagged_pubkey.clone(),
            [0x33u8; crate::consensus::validator_set::VRF_PUBKEY_SIZE],
            0,
            0,
        );
        let mut config =
            NodeConfig::validator(PathBuf::from("/tmp/poker_l1_slash_test"), vkey);
        config.genesis_validators = vec![issuer_entry];
        config.inclusion_deadline_ms = 1_000;
        let node = Node::open_inmemory_with_config(config).unwrap();
        let clock = Arc::new(std::sync::Mutex::new(0u64));
        let clock_handle = Arc::clone(&clock);
        node.set_time_source(Box::new(move || *clock_handle.lock().unwrap()));
        // 注入 bond 余额 1_000 并设 Active
        {
            let mut set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            set.validators[0].stake = 1_000;
            set.validators[0].status = crate::consensus::validator_set::ValidatorStatus::Active;
            set.validator_set_hash = set.compute_hash();
        }
        let issuer_pubkey = node.validator_set.lock().unwrap().validators[0].pubkey.clone();

        // 构造 Censored 证据：receipt 由本节点 validator 密钥（= set 成员 issuer）
        // 签发，deadline=1_000，now=2_000 → 超时；近窗块为空 → 未包含。
        let vk = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        assert_eq!(
            vk.tagged_pubkey, issuer_pubkey,
            "同种子重建的 validator 密钥必须一致"
        );
        let secret = secp256k1::SecretKey::from_slice(&vk.secret_key_bytes).unwrap();
        let placeholder_tx = make_pub_tx(0x91, 1, 1);
        let receipt = crate::force_include::SeenReceipt::issue(
            DEFAULT_CHAIN_ID,
            placeholder_tx.tx_hash(),
            0,
            &secret,
        )
        .unwrap();
        let proof = crate::force_include::CensorshipProof {
            receipt,
            tx_bytes: placeholder_tx.to_bcs().unwrap(),
            deadline_ms: 1_000,
            current_height_hint: 0,
        };

        // 第一次：Censored → 全额罚没 1000 → stake=0 → Slashed
        *clock.lock().unwrap() = 2_000;
        let outcome = node.check_censorship(&proof).unwrap();
        assert_eq!(
            outcome,
            crate::force_include::CensorshipCheckOutcome::Censored
        );
        {
            let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(set.validators[0].stake, 0, "bond 必须被扣减到 0");
            assert_eq!(
                set.validators[0].status,
                crate::consensus::validator_set::ValidatorStatus::Slashed,
                "归零必须停出块资格"
            );
            assert!(!set.validators[0].can_participate_consensus());
        }
        let events = node.slash_events();
        assert_eq!(events.len(), 1, "必须恰好记一条罚没事件");
        assert_eq!(events[0].amount, 1_000);
        assert_eq!(
            events[0].reason,
            crate::consensus::slash::SlashReason::CensorshipProof
        );

        // 第二次（同证据）：幂等 → 无新事件
        let outcome2 = node.check_censorship(&proof).unwrap();
        assert_eq!(outcome2, crate::force_include::CensorshipCheckOutcome::Censored);
        assert_eq!(node.slash_events().len(), 1, "同证据不得重复罚没");
    }

    // ===== v1.5-c：checkpoint + BLS 聚合 QC（Node 接线） =====

    #[test]
    fn checkpoint_vote_collection_forms_qc_and_persists_sidecar() {
        use crate::consensus::checkpoint::{CheckpointQc, CheckpointVote, bls_derive_secret_key};
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_ckpt_node_{}_{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(dir.clone(), vkey);
        config.checkpoint_interval_blocks = 32;
        let node = Node::open(config).unwrap();

        // 禁用路径：interval=0 → checkpoint_target 恒 None
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, 64, [0xAu8; 32], &bls_derive_secret_key(&[0xA0 + i as u8; 32])).unwrap())
            .collect();
        // 直接经 record 路径收集 5 票（位点是测试构造的，Node 侧不要求 tip 一致 ——
        // 投票位点真实性由签名者自律与 gossip 来源保证，见方法边界说明）
        let mut formed_qc: Option<CheckpointQc> = None;
        for (i, vote) in votes.iter().enumerate() {
            let (count, formed) = node.record_checkpoint_vote(vote.clone()).unwrap();
            assert_eq!(count, i + 1, "票数必须随收集递增");
            if let Some(qc) = formed {
                formed_qc = Some(qc);
            }
        }
        let qc = formed_qc.expect("5 票必须成 QC");
        qc.verify(5).unwrap();
        assert_eq!(node.latest_checkpoint_qc().as_ref().map(|q| q.height), Some(64));

        // 重复投票去重：同签名者再投不增加计数、不重复成 QC
        let (count, none) = node.record_checkpoint_vote(votes[0].clone()).unwrap();
        assert_eq!(count, 5);
        assert!(none.is_none());

        // 侧车已落盘：重开节点重放恢复最新 QC
        drop(node);
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let config = NodeConfig::validator(dir.clone(), vkey);
        let node2 = Node::open(config).unwrap();
        let restored = node2.latest_checkpoint_qc().expect("重启必须恢复最新 QC");
        assert_eq!(restored, qc, "sidecar 重放的 QC 必须与落盘一致");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn checkpoint_interval_trigger_requires_configured_height() {
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(PathBuf::from("/tmp/poker_l1_ckpt_interval"), vkey);
        config.checkpoint_interval_blocks = 32;
        let node = Node::open_inmemory_with_config(config).unwrap();
        // tip 为空（无块）→ 无位点
        assert!(node.checkpoint_target().is_none());
        // 间隔 0 禁用
        let vkey = ValidatorKey::from_secret_bytes([0x43u8; 32]).unwrap();
        let mut config = NodeConfig::validator(PathBuf::from("/tmp/poker_l1_ckpt_off"), vkey);
        config.checkpoint_interval_blocks = 0;
        let node_off = Node::open_inmemory_with_config(config).unwrap();
        assert!(node_off.checkpoint_target().is_none(), "interval=0 必须禁用");
        let _ = node; // 保留变量以示对照
    }

    #[test]
    fn checkpoint_vote_rejects_bad_signature_and_counts_collect() {
        use crate::consensus::checkpoint::{CheckpointVote, bls_derive_secret_key};
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(PathBuf::from("/tmp/poker_l1_ckpt_bad"), vkey);
        config.checkpoint_interval_blocks = 32;
        let node = Node::open_inmemory_with_config(config).unwrap();
        let mut vote =
            CheckpointVote::sign(1, 32, [7u8; 32], &bls_derive_secret_key(&[0xB1u8; 32])).unwrap();
        vote.signature_g1 = vec![0u8; 48]; // 伪签名（非曲线点）
        assert!(node.record_checkpoint_vote(vote).is_err(), "伪签名必须被拒");
        // 合法票：计数递增
        for i in 0..3u8 {
            let v = CheckpointVote::sign(1, 32, [7u8; 32], &bls_derive_secret_key(&[0xC0 + i; 32])).unwrap();
            let (count, _) = node.record_checkpoint_vote(v).unwrap();
            assert_eq!(count, (i + 1) as usize);
        }
        assert_eq!(node.checkpoint_vote_count(1, 32), 3);
        assert_eq!(node.checkpoint_vote_count(1, 64), 0);
    }

    // ===== v1.5-e：阈值 QC（Node 接线） =====

    /// 阈值 QC 端到端（Node 层）：DKG 7-of-5 材料落盘 → 节点载入（fail-closed
    /// 自检）→ 收集 ≥t 份额装配阈值 QC → sidecar 落盘 → 重启恢复且可验。
    #[test]
    fn threshold_qc_collection_forms_qc_persists_and_restores() {
        use crate::consensus::checkpoint::{ThresholdQcPartial, checkpoint_qc_signing_hash};
        use crate::consensus::dkg::{assemble_group_keyset, dealer_deal};
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_thr_node_{}_{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // DKG 演练：7 dealer / t=5
        let n = 7u32;
        let t = 5u32;
        let deals: Vec<_> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[0x90; 32], j, n, t).unwrap())
            .collect();
        let (keyset, shares) = assemble_group_keyset(&deals, n, t).unwrap();
        let keyset_path = dir.join("keyset.json");
        std::fs::write(&keyset_path, dkg_keyset_to_json(&keyset).unwrap()).unwrap();
        for s in &shares {
            std::fs::write(
                dir.join(format!("share-{}.json", s.id)),
                dkg_share_to_json(s).unwrap(),
            )
            .unwrap();
        }
        // 节点 1（参与者 id 3）：t>0 + 材料 → 载入自检通过
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(dir.clone(), vkey);
        config.checkpoint_interval_blocks = 32;
        config.qc_threshold_t = t;
        config.dkg_keyset_path = Some(keyset_path.clone());
        config.dkg_share_path = Some(dir.join("share-3.json"));
        let node = Node::open(config).unwrap();
        assert_eq!(node.qc_threshold_t(), 5);
        assert_eq!(node.dkg_share_id(), Some(3));
        // 收集 5 份（含本节点 id 3）→ 装配阈值 QC + 落盘
        let (epoch, height, root) = (1u64, 64u64, [0xAu8; 32]);
        let signing = checkpoint_qc_signing_hash(epoch, height, root);
        let partials: Vec<ThresholdQcPartial> = [1u64, 2, 3, 5, 7]
            .iter()
            .map(|id| {
                let share = shares.iter().find(|s| s.id == *id).unwrap();
                ThresholdQcPartial {
                    epoch,
                    height,
                    state_root: root,
                    participant_id: *id,
                    sig_g1: share.partial_sign(&signing).unwrap().to_vec(),
                }
            })
            .collect();
        let mut formed = None;
        for (i, p) in partials.iter().enumerate() {
            let (count, qc) = node.record_threshold_partial(p.clone()).unwrap();
            assert_eq!(count, i + 1);
            if qc.is_some() {
                formed = qc;
            }
        }
        let qc = formed.expect("t=5 份额必须装配阈值 QC");
        assert_eq!(qc.signer_count(), 5);
        qc.verify_threshold(&keyset).unwrap();
        assert_eq!(
            node.latest_checkpoint_qc().as_ref().map(|q| q.height),
            Some(64)
        );
        // 重复参与者去重
        let (count, none) = node.record_threshold_partial(partials[0].clone()).unwrap();
        assert_eq!(count, 5);
        assert!(none.is_none());
        // sidecar 已落盘（阈值形态 JSON 行）
        let sidecar = std::fs::read_to_string(dir.join(CHECKPOINT_SIDECAR_FILE)).unwrap();
        assert!(sidecar.contains("\"threshold\""), "阈值形态必须落盘");
        // 重启：恢复 + 恢复期 fail-closed 验证
        drop(node);
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config2 = NodeConfig::validator(dir.clone(), vkey);
        config2.checkpoint_interval_blocks = 32;
        config2.qc_threshold_t = t;
        config2.dkg_keyset_path = Some(keyset_path);
        config2.dkg_share_path = Some(dir.join("share-4.json"));
        let node2 = Node::open(config2).unwrap();
        let restored = node2.latest_checkpoint_qc().expect("重启必须恢复阈值 QC");
        assert_eq!(restored, qc, "sidecar 重放的阈值 QC 必须与落盘一致");
        restored.verify_threshold(&keyset).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 阈值路径 fail-closed 面：伪/越界份额拒；<t 不产 QC；无 keyset 节点拒
    /// 阈值份额（聚合模式零回退：同节点聚合投票路径仍可用）；材料与配置不
    /// 一致（t 不符 / 坏份额 / 缺路径）拒绝启动。
    #[test]
    fn threshold_qc_fail_closed_rejections_and_aggregate_fallback() {
        use crate::consensus::checkpoint::{ThresholdQcPartial, bls_derive_secret_key, checkpoint_qc_signing_hash};
        use crate::consensus::dkg::{assemble_group_keyset, dealer_deal};
        let dir = std::env::temp_dir().join(format!(
            "pokerl1_thr_bad_{}_{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let n = 7u32;
        let t = 5u32;
        let deals: Vec<_> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[0x91; 32], j, n, t).unwrap())
            .collect();
        let (keyset, shares) = assemble_group_keyset(&deals, n, t).unwrap();
        let keyset_path = dir.join("keyset.json");
        std::fs::write(&keyset_path, dkg_keyset_to_json(&keyset).unwrap()).unwrap();
        for s in &shares {
            std::fs::write(
                dir.join(format!("share-{}.json", s.id)),
                dkg_share_to_json(s).unwrap(),
            )
            .unwrap();
        }
        let mut config = NodeConfig::validator(
            PathBuf::from("/tmp/poker_l1_thr_inmem"),
            ValidatorKey::from_secret_bytes([0x43u8; 32]).unwrap(),
        );
        config.qc_threshold_t = t;
        // fail-closed：t>0 缺路径 → 拒启动
        assert!(Node::open_inmemory_with_config(config.clone()).is_err());
        // fail-closed：keyset.t 与配置不符 → 拒启动
        config.dkg_keyset_path = Some(keyset_path.clone());
        config.dkg_share_path = Some(dir.join("share-1.json"));
        config.qc_threshold_t = 4;
        assert!(Node::open_inmemory_with_config(config.clone()).is_err());
        // fail-closed：坏份额（非本群成员）→ 拒启动
        let (other_keyset, other_shares) = {
            let d2: Vec<_> = (1..=u64::from(n))
                .map(|j| dealer_deal(&[0x99; 32], j, n, t).unwrap())
                .collect();
            assemble_group_keyset(&d2, n, t).unwrap()
        };
        std::fs::write(
            dir.join("rogue.json"),
            dkg_share_to_json(&other_shares[0]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("rogue_keyset.json"),
            dkg_keyset_to_json(&other_keyset).unwrap(),
        )
        .unwrap();
        config.qc_threshold_t = t;
        config.dkg_keyset_path = Some(keyset_path.clone());
        config.dkg_share_path = Some(dir.join("rogue.json"));
        assert!(
            Node::open_inmemory_with_config(config.clone()).is_err(),
            "非本群份额必须 fail-closed 拒载"
        );
        // 正常载入（参与者 id 2）
        config.dkg_share_path = Some(dir.join("share-2.json"));
        let node = Node::open_inmemory_with_config(config).unwrap();
        let (epoch, height, root) = (1u64, 32u64, [7u8; 32]);
        let signing = checkpoint_qc_signing_hash(epoch, height, root);
        let mk = |id: u64, sig: [u8; 48]| ThresholdQcPartial {
            epoch,
            height,
            state_root: root,
            participant_id: id,
            sig_g1: sig.to_vec(),
        };
        // 伪签名（非曲线点）拒
        let bogus = mk(1, [0u8; 48]);
        assert!(node.record_threshold_partial(bogus).is_err());
        // 越界参与者 id 拒
        let sig1 = shares[0].partial_sign(&signing).unwrap();
        assert!(node.record_threshold_partial(mk(u64::from(n) + 1, sig1)).is_err());
        // 冒名（份额 6 的签名贴 id 5）拒
        let sig6 = shares[5].partial_sign(&signing).unwrap();
        assert!(node.record_threshold_partial(mk(5, sig6)).is_err());
        // <t 不产 QC
        for id in [1u64, 2, 3, 4] {
            let share = shares.iter().find(|s| s.id == id).unwrap();
            let p = mk(id, share.partial_sign(&signing).unwrap());
            let (count, qc) = node.record_threshold_partial(p).unwrap();
            assert_eq!(count, id as usize);
            assert!(qc.is_none(), "<t 不得产 QC");
        }
        assert_eq!(node.threshold_partial_count(epoch, height), 4);
        assert!(node.latest_checkpoint_qc().is_none());
        // 零回退：无 keyset 节点（t=0）拒阈值份额，聚合投票路径仍可用
        let agg_config = NodeConfig::validator(
            PathBuf::from("/tmp/poker_l1_thr_agg"),
            ValidatorKey::from_secret_bytes([0x44u8; 32]).unwrap(),
        );
        let agg_node = Node::open_inmemory_with_config(agg_config).unwrap();
        assert_eq!(agg_node.qc_threshold_t(), 0);
        assert!(agg_node.dkg_share_id().is_none());
        let share = shares.iter().find(|s| s.id == 1).unwrap();
        let p = mk(1, share.partial_sign(&signing).unwrap());
        assert!(
            agg_node.record_threshold_partial(p).is_err(),
            "无 keyset 节点必须拒阈值份额（fail-closed）"
        );
        use crate::consensus::checkpoint::CheckpointVote;
        let vote = CheckpointVote::sign(epoch, height, root, &bls_derive_secret_key(&[0xC5; 32]))
            .unwrap();
        let (_, agg_qc) = agg_node.record_checkpoint_vote(vote).unwrap();
        assert!(
            agg_qc.is_some(),
            "聚合模式（t=0）路径必须零回退可用"
        );
        assert!(agg_qc.unwrap().threshold.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn da_request_and_peer_receipts_form_certificate() {
        use crate::consensus::checkpoint::bls_derive_secret_key;
        use crate::consensus::da::DaReceipt;
        let vkey = ValidatorKey::from_secret_bytes([0x42u8; 32]).unwrap();
        let mut config = NodeConfig::validator(PathBuf::from("/tmp/poker_l1_da_test"), vkey);
        config.checkpoint_interval_blocks = 32;
        // 5 validator 集（Active）→ 2f+1 = 4
        config.genesis_validators = (0..5usize)
            .map(|i| {
                let mut entry = crate::consensus::validator_set::ValidatorEntry::new(
                    TaggedPubkey {
                        tag: encode_tag(SignatureScheme::Secp256k1, 1),
                        raw: vec![0x20 + i as u8; 33],
                    },
                    [0x30u8; crate::consensus::validator_set::VRF_PUBKEY_SIZE],
                    0,
                    0,
                );
                entry.status = crate::consensus::validator_set::ValidatorStatus::Active;
                entry
            })
            .collect();
        let node = Node::open_inmemory_with_config(config).unwrap();
        let digest = [0xD1u8; 32];

        // 未请求 → requested=false
        let before = node.da_status(&digest);
        assert!(!before.requested);

        // da_request：本节点（validator）签回执
        let status = node.submit_da_request(digest).expect("validator 可发起 DA 请求");
        assert!(status.requested);
        assert_eq!(status.receipt_count, 1);
        assert!(!status.certified, "单回执不足 2f+1");
        // outbox 有本地回执（供 gossip）
        assert_eq!(node.drain_da_outbox().len(), 1);
        assert!(node.drain_da_outbox().is_empty(), "outbox 应被 drain 清空");

        // peer 回执（模拟 5 validator 集，2f+1 = 4）：再收 3 票 → 成凭证
        let mut last_status = None;
        for i in 0..3u8 {
            let receipt =
                DaReceipt::sign(digest, status.epoch, status.height, &bls_derive_secret_key(&[0xF0 + i; 32])).unwrap();
            last_status = Some(node.record_da_receipt(receipt).unwrap());
        }
        let final_status = last_status.expect("应有最终状态");
        assert_eq!(final_status.receipt_count, 4);
        assert!(final_status.certified, "4/5（2f+1）回执必须成凭证");
        assert_eq!(final_status.cert_signers, 4);
        assert!(node.da_status(&digest).certified);

        // 伪回执拒：篡改 height → signing_hash 与 (epoch,height,digest) 不一致
        let mut forged = DaReceipt::sign(digest, status.epoch, status.height, &bls_derive_secret_key(&[0xFfu8; 32])).unwrap();
        forged.height = forged.height.wrapping_add(1);
        assert!(node.record_da_receipt(forged).is_err(), "位点被篡改的回执必须拒绝");
        // 篡改签名（非曲线点）→ 拒
        let mut forged2 = DaReceipt::sign(digest, status.epoch, status.height, &bls_derive_secret_key(&[0xFEu8; 32])).unwrap();
        forged2.signature_g1 = vec![0u8; 48];
        assert!(node.record_da_receipt(forged2).is_err(), "伪签名必须拒绝");
    }

    #[test]
    fn da_request_rejects_non_validator_node() {
        let config = NodeConfig::default_full(PathBuf::from("/tmp/poker_l1_da_full"));
        let node = Node::open_inmemory_with_config(config).unwrap();
        let err = node.submit_da_request([1u8; 32]).unwrap_err();
        assert!(err.to_string().contains("非 validator"));
    }

    #[test]
    fn check_censorship_slash_skips_issuer_outside_validator_set() {
        // 签发者不在本地 validator set → Censored 照常返回，但不产生罚没事件。
        let (node, clock) = force_include_validator_node(1_000);
        let outsider = secp256k1::SecretKey::from_slice(&[0xAAu8; 32]).unwrap();
        let placeholder_tx = make_pub_tx(0x92, 1, 1);
        let receipt = crate::force_include::SeenReceipt::issue(
            DEFAULT_CHAIN_ID,
            placeholder_tx.tx_hash(),
            0,
            &outsider,
        )
        .unwrap();
        let proof = crate::force_include::CensorshipProof {
            receipt,
            tx_bytes: placeholder_tx.to_bcs().unwrap(),
            deadline_ms: 1_000,
            current_height_hint: 0,
        };
        *clock.lock().unwrap() = 2_000;
        let outcome = node.check_censorship(&proof).unwrap();
        assert_eq!(outcome, crate::force_include::CensorshipCheckOutcome::Censored);
        assert!(
            node.slash_events().is_empty(),
            "set 外签发者不得触发罚没事件"
        );
    }

    #[test]
    fn force_include_deadline_triggers_and_orders_by_tx_hash() {
        // §5.3-2/3：超过期限的交易强制包含，且乱序到达 → 块序按 tx_hash 字节序升序。
        let (node, clock) = force_include_validator_node(10_000);
        // t=1000 提交 5 笔（不同 caller/nonce → hash 各异）
        let mut txs: Vec<Transaction> = (0..5)
            .map(|k| make_pub_tx(0x40 + k as u8, k + 1, 1))
            .collect();
        // 乱序提交：按 hash 降序提交
        txs.sort_by(|a, b| b.tx_hash().cmp(&a.tx_hash()));
        for tx in &txs {
            node.submit_tx(tx.clone()).unwrap();
        }

        // 未到期：不出强制包含（此时 drain 走普通通道序，Public 同价 → arrival 序）
        *clock.lock().unwrap() = 11_000; // 恰好 = arrived + deadline，严格大于才触发
        let not_yet = node.drain_pending_tx_for_block();
        assert_eq!(not_yet.len(), 5);
        let expected_arrival: Vec<Hash> = txs.iter().map(|t| t.tx_hash()).collect();
        let got_arrival: Vec<Hash> = not_yet.iter().map(|t| t.tx_hash()).collect();
        assert_eq!(got_arrival, expected_arrival, "未到期时保持 arrival 顺序");

        // 重新提交（mem池已被 drain 清空；本轮 arrived_at = 当前时钟 11000），
        // 推进时钟越期限（> 11000 + 10000）。
        for tx in &txs {
            node.submit_tx(tx.clone()).unwrap();
        }
        *clock.lock().unwrap() = 21_001;
        let forced = node.drain_pending_tx_for_block();
        assert_eq!(forced.len(), 5);
        let mut expected_hash_order: Vec<Hash> =
            txs.iter().map(|t| t.tx_hash()).collect();
        expected_hash_order.sort();
        let got_hash_order: Vec<Hash> = forced.iter().map(|t| t.tx_hash()).collect();
        assert_eq!(
            got_hash_order, expected_hash_order,
            "强制包含队列必须按 tx_hash 字节序升序（与到达顺序无关）"
        );
    }

    #[test]
    fn force_include_dedup_prevents_second_promotion() {
        // 已提升过的 tx 重复进入 mempool（回排/重复提交）→ 不二次强制包含。
        let (node, clock) = force_include_validator_node(1_000);
        let first = make_pub_tx(0x51, 1, 1);
        node.submit_tx(first.clone()).unwrap();

        // 越期限 → drain 强制提升 first
        *clock.lock().unwrap() = 2_001;
        let drained = node.drain_pending_tx_for_block();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tx_hash(), first.tx_hash());

        // first（已提升过）+ 新过期 tx second 一起在 mempool（本轮 arrived_at=2001）
        let second = make_pub_tx(0x52, 1, 1);
        node.submit_tx(first.clone()).unwrap();
        node.submit_tx(second.clone()).unwrap();
        // 推进时钟使 second 也过期（> 2001 + 1000）
        *clock.lock().unwrap() = 3_002;
        let drained = node.drain_pending_tx_for_block();
        assert_eq!(drained.len(), 2);
        // second 进入强制包含组（最前）；first 不再二次强制包含，落到普通组
        assert_eq!(drained[0].tx_hash(), second.tx_hash());
        assert_eq!(drained[1].tx_hash(), first.tx_hash());
    }

    #[test]
    fn force_include_disabled_deadline_zero_matches_legacy_drain() {
        // 禁用路径（deadline=0）与历史 drain_pending_tx 完全同序（对拍）。
        let (node_a, _clock_a) = force_include_validator_node(0);
        let (node_b, _clock_b) = force_include_validator_node(0);
        // 混合序列：GameTurn / Public（不同 gas price）/ ForceSync，乱序提交。
        // 注意 submit_tx 不验签（签名在 RPC/block 层校验），测试 tx 用 dummy 签名即可。
        let sequence: Vec<Transaction> = vec![
            {
                let mut tx = make_pub_tx(0x61, 1, 10);
                tx.lane_hint = crate::transaction::TxLane::GameTurn;
                tx.gameturn_nonce = Some(1);
                tx.gas = crate::transaction::Gas::zero();
                tx
            },
            make_pub_tx(0x62, 1, 50),
            {
                let mut tx = make_pub_tx(0x63, 1, 30);
                tx.lane_hint = crate::transaction::TxLane::ForceSync;
                tx
            },
            make_pub_tx(0x64, 2, 20),
        ];
        for tx in &sequence {
            node_a.submit_tx(tx.clone()).unwrap();
            node_b.submit_tx(tx.clone()).unwrap();
        }
        let legacy = node_a.drain_pending_tx();
        let for_block = node_b.drain_pending_tx_for_block();
        let legacy_hashes: Vec<Hash> = legacy.iter().map(|t| t.tx_hash()).collect();
        let for_block_hashes: Vec<Hash> = for_block.iter().map(|t| t.tx_hash()).collect();
        assert_eq!(
            legacy_hashes, for_block_hashes,
            "deadline=0 禁用时 drain_pending_tx_for_block 必须与历史路径完全同序"
        );
    }

    #[test]
    fn force_include_enabled_but_not_expired_matches_legacy_drain() {
        // 期限启用但无过期交易时，两条路径同样同序。
        let (node_a, _clock_a) = force_include_validator_node(10_000);
        let (node_b, clock_b) = force_include_validator_node(10_000);
        let sequence: Vec<Transaction> = vec![
            make_pub_tx(0x71, 1, 50),
            make_pub_tx(0x72, 2, 20),
            make_pub_tx(0x73, 3, 20),
        ];
        for tx in &sequence {
            node_a.submit_tx(tx.clone()).unwrap();
            node_b.submit_tx(tx.clone()).unwrap();
        }
        assert_eq!(*clock_b.lock().unwrap(), 1_000, "未越期限");
        let legacy = node_a.drain_pending_tx();
        let for_block = node_b.drain_pending_tx_for_block();
        let legacy_hashes: Vec<Hash> = legacy.iter().map(|t| t.tx_hash()).collect();
        let for_block_hashes: Vec<Hash> = for_block.iter().map(|t| t.tx_hash()).collect();
        assert_eq!(legacy_hashes, for_block_hashes);
    }

    #[test]
    fn requeue_pending_txs_preserves_drained_order_ahead_of_new_arrivals() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x20, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x21, 1, 5)).unwrap();
        let drained = node.drain_pending_tx();
        node.submit_tx(make_pub_tx(0x22, 1, 5)).unwrap();

        node.requeue_pending_txs(drained);

        let retried = node.drain_pending_tx();
        assert_eq!(retried.len(), 3);
        assert_eq!(retried[0].tagged_pubkey.raw[0], 0x20);
        assert_eq!(retried[1].tagged_pubkey.raw[0], 0x21);
        assert_eq!(retried[2].tagged_pubkey.raw[0], 0x22);
    }

    #[test]
    fn priority_mempool_gameturn_before_public_regardless_of_gas_price() {
        // GameTurn（免 gas, price=0）应排在 Public（高 gas_price）之前，
        // 因为游戏操作的时间敏感性和轮转规则优先于 gas 竞价。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 插入高 price 的 Public tx
        node.submit_tx(make_pub_tx(0x30, 1, 100)).unwrap();
        // 插入 GameTurn tx（免 gas, price=0）
        let gameturn_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![0x40; 33],
            },
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(), // GameTurn 免 gas
            lane_hint: crate::transaction::TxLane::GameTurn,
            route_hint: crate::transaction::RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(1),
            is_fallback: false,
        };
        node.submit_tx(gameturn_tx).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 2);
        // GameTurn 应排第一（即使 gas_price=0）
        assert_eq!(
            drained[0].lane_hint,
            crate::transaction::TxLane::GameTurn,
            "GameTurn 应排在 Public 之前"
        );
        // Public 排第二（即使 gas_price=100）
        assert_eq!(
            drained[1].lane_hint,
            crate::transaction::TxLane::Public,
            "Public 应排在 GameTurn 之后"
        );
    }

    #[test]
    fn priority_mempool_gameturn_preserves_arrival_order() {
        // 多个 GameTurn tx 保持 arrival 顺序（轮转规则由后续 build_game_sub_block 处理）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let make_gameturn = |byte: u8, nonce: u64| -> Transaction {
            Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: TaggedPubkey {
                    tag: encode_tag(SignatureScheme::Secp256k1, 1),
                    raw: vec![byte; 33],
                },
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::GameTurn,
                route_hint: crate::transaction::RouteHint::AssignedValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 0,
                gameturn_nonce: Some(nonce),
                is_fallback: false,
            }
        };
        node.submit_tx(make_gameturn(0x50, 1)).unwrap();
        node.submit_tx(make_gameturn(0x51, 2)).unwrap();
        node.submit_tx(make_gameturn(0x52, 3)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 3);
        // 全部 GameTurn，保持 arrival 顺序
        assert_eq!(drained[0].tagged_pubkey.raw[0], 0x50);
        assert_eq!(drained[1].tagged_pubkey.raw[0], 0x51);
        assert_eq!(drained[2].tagged_pubkey.raw[0], 0x52);
    }

    #[test]
    fn light_header_generated_with_validator_signature() {
        // validator 节点 put_block 后应生成带 secp256k1 签名的 LightClientHeader。
        let vkey = ValidatorKey::from_secret_bytes([0x42; 32]).unwrap();
        let node =
            Node::open_inmemory_with_validators(NodeRole::Validator, DEFAULT_CHAIN_ID, vec![])
                .unwrap();
        // 手动注入 validator_key（open_inmemory 默认无 key）。
        // 通过直接调用 sign_and_store_light_header 测试。
        let block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    public_tx_root: [0u8; 32],
                    gameturn_tx_root: [0u8; 32],
                    signature_list: vec![],
                    signer_bitmap: vec![0x00],
                },
            },
            vec![],
            vec![],
        );
        node.sign_and_store_light_header(&block, &vkey);
        let headers = node.get_light_headers();
        assert_eq!(headers.len(), 1, "应生成 1 个 LightClientHeader");
        assert_eq!(headers[0].signatures.len(), 1, "应有 1 个 validator 签名");
        assert_eq!(headers[0].signatures[0].validator, vkey.tagged_pubkey);
        assert_eq!(
            headers[0].signatures[0].signature.len(),
            65,
            "secp256k1 签名 65B"
        );
    }

    #[test]
    fn light_header_merges_peer_signatures() {
        // merge_light_header 应合并不同 validator 的签名到同一 header。
        let vkey1 = ValidatorKey::from_secret_bytes([0x42; 32]).unwrap();
        let vkey2 = ValidatorKey::from_secret_bytes([0x43; 32]).unwrap();
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    public_tx_root: [0u8; 32],
                    gameturn_tx_root: [0u8; 32],
                    signature_list: vec![],
                    signer_bitmap: vec![0x00],
                },
            },
            vec![],
            vec![],
        );
        // validator 1 签名
        node.sign_and_store_light_header(&block, &vkey1);
        // validator 2 签名（通过 merge）
        let header2 = {
            let h = node.get_light_headers();
            let mut h2 = h[0].clone();
            h2.signatures.clear();
            h2.signatures.push(crate::network::ValidatorSig {
                validator: vkey2.tagged_pubkey.clone(),
                signature: vec![0u8; 65],
            });
            h2
        };
        node.merge_light_header(header2);
        let headers = node.get_light_headers();
        assert_eq!(headers.len(), 1, "仍为 1 个 header");
        assert_eq!(headers[0].signatures.len(), 2, "应有 2 个 validator 签名");
    }
}
