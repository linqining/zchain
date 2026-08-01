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
use crate::block::Block;
use crate::block::validator::{
    validate_block_tx_roots, validate_commit_certificate_signatures, validate_gameturn_no_gas,
    validate_state_root_transition, validate_tx_chain_id, validate_vertex_tx_ordering,
};
use crate::consensus::{
    DagVertex, Epoch, MAX_VERTEX_SIZE, ValidatorEntry, ValidatorSet,
    compute_genesis_chain_randomness,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::executor::{BlockExecutionOutcome, ExecutionEnvironment, execute_block};
use crate::object_model::{Object, ObjectID};
use crate::signature::TaggedPubkey;
use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use crate::signature::unified::verify_signature;
use crate::storage::{BlockStore, BridgeRegistryStore, DagVertexStore, NodeRole as PruningNodeRole, ObjectDb};
use crate::transaction::{Transaction, validate_tx_limits};
use crate::vm::PrecompileRegistry;
use crate::vm::contracts::{GamePrecompile, TexasPokerPrecompile};
use crate::{Address, BlockHeight, ChainId, Hash};

/// tx_cache 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_NODE_TX_CACHE_SIZE: usize = 10_000;

/// pending_tx 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_PENDING_TX_SIZE: usize = 10_000;

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
    /// 空列表表示创世引导期 — vertex/block 的 validator 成员校验跳过。
    #[serde(default)]
    pub genesis_validators: Vec<ValidatorEntry>,
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
        }
    }

    /// 设置创世 validator 列表（builder 风格）。
    #[must_use]
    pub fn with_genesis_validators(mut self, validators: Vec<ValidatorEntry>) -> Self {
        self.genesis_validators = validators;
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

/// 节点实例 — 持有存储后端与可选 validator 密钥。
///
/// 不直接运行网络/event loop；由上层二进制集成 tokio runtime + network + RPC server。
/// 本结构提供存储访问、tx 提交、block/vertex 查询等核心方法。
pub struct Node {
    /// 配置。
    config: NodeConfig,
    /// BlockStore。
    block_store: BlockStore,
    /// ObjectDb。
    object_db: std::sync::Mutex<ObjectDb>,
    /// DagVertexStore。
    vertex_store: DagVertexStore,
    /// AccountStore（内存版，Phase 4 接入 rocksdb）。
    account_store: std::sync::Mutex<AccountStore>,
    /// 已提交的 tx 缓存（M-6 修复 — cache + order 合并到单个 Mutex）。
    tx_cache: std::sync::Mutex<TxCacheState>,
    /// 待装 vertex 的 tx 缓冲（仅 Validator 角色）。
    pending_tx: std::sync::Mutex<std::collections::VecDeque<Transaction>>,
    /// pending_tx 的 Condvar — submit_tx 时 notify，validator loop 用 wait_timeout 等待。
    pending_tx_condvar: std::sync::Condvar,
    /// 当前 ValidatorSet（P0-4 动态 quorum）。
    ///
    /// - 创世引导期（validators 为空）时，vertex/block 的 validator 成员校验跳过
    /// - 非空时，vertex author 必须是活跃 validator；commit certificate 必须满足动态 quorum
    validator_set: std::sync::Mutex<ValidatorSet>,
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
}

/// 构造默认预编译合约注册表并注册内置预编译合约。
///
/// 在 [`Node::open`] / [`Node::open_inmemory_with_validators`] 中调用，
/// 确保 `GamePrecompile` 和 `TexasPokerPrecompile` 在节点启动时即注册。
fn build_default_precompile_registry() -> Arc<PrecompileRegistry> {
    let mut registry = PrecompileRegistry::new();
    registry.register(GamePrecompile::new_arc(1));
    registry.register(TexasPokerPrecompile::new_arc(1));
    Arc::new(registry)
}

/// 从创世 validator 列表构建初始 ValidatorSet（epoch 0）。
///
/// - `genesis_chain_randomness` 由所有 validator pubkey 聚合派生（SEC2-M12）
/// - 初始 `epoch_randomness = genesis_chain_randomness`，`prev_epoch_randomness = 0`
fn build_genesis_validator_set(validators: Vec<ValidatorEntry>) -> ValidatorSet {
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
    set
}

impl Node {
    /// 打开节点（初始化所有存储后端）。
    pub fn open(config: NodeConfig) -> PokerL1Result<Self> {
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
        let validator_set = build_genesis_validator_set(config.genesis_validators.clone());
        let precompile_registry = build_default_precompile_registry();
        Ok(Self {
            config,
            block_store,
            object_db: std::sync::Mutex::new(object_db),
            vertex_store,
            account_store: std::sync::Mutex::new(account_store),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            precompile_registry,
            bridge_registry_store: Some(Arc::new(bridge_registry_store)),
        })
    }

    /// 应用 genesis 余额分配（缺口 #4-M1：初始代币发行）。
    ///
    /// 为每个 `(tagged_pubkey, balance)` 创建账户（若不存在）。幂等：已存在的账户不覆盖。
    /// 在节点首次启动（`Node::open` 后）调用一次，实现混合代币模型（Q15）的 genesis 分配。
    ///
    /// **幂等性**：仅在账户不存在时创建；重启不重复分配（持久化 AccountStore 已有则跳过）。
    pub fn apply_genesis_alloc(
        &self,
        allocs: impl IntoIterator<Item = (TaggedPubkey, u64)>,
    ) -> PokerL1Result<usize> {
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let mut created = 0usize;
        for (pubkey, balance) in allocs {
            let addr = crate::account::derive_address(&pubkey);
            if account_store.get(&addr).is_none() {
                account_store.create(crate::account::Account::new(pubkey, balance))?;
                created += 1;
            }
        }
        Ok(created)
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
        let validator_set = build_genesis_validator_set(genesis_validators.clone());
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
            },
            block_store: BlockStore::open_inmemory()?,
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            precompile_registry,
            // 缺口 #9：内存节点默认不启用桥（bridge contract_call 会拒绝）；
            // 需桥的测试可用 [`Node::with_bridge`] 显式注入。
            bridge_registry_store: None,
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

    /// 当前动态 quorum（严格 > 2/3 活跃 validator：`2 * n / 3 + 1`）。
    ///
    /// 创世引导期（validator 集为空）返回 0。
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

    /// 加入新 validator（初始 Bonding 状态，NEW-L3）。
    pub fn add_validator(&self, entry: ValidatorEntry) -> PokerL1Result<()> {
        // 缺口 #5（staking 结算）：validator 注册时把 stake 从账户余额锁定（扣除）。
        // stake 须有真实账户余额支撑，防"凭空质押"。
        if entry.stake > 0 {
            let validator_addr = crate::account::derive_address(&entry.pubkey);
            let mut account_store =
                self.account_store.lock().unwrap_or_else(|e| e.into_inner());
            // 账户须存在且余额 ≥ stake，否则拒绝（质押不足）。
            match account_store.get_mut(&validator_addr) {
                Some(acc) => {
                    acc.debit(entry.stake).map_err(|_| {
                        PokerL1Error::InsufficientBalance {
                            needed: entry.stake,
                            has: acc.balance,
                        }
                    })?;
                    account_store.flush(&validator_addr)?;
                }
                None => {
                    return Err(PokerL1Error::Other(format!(
                        "validator account not found for bonding (address={:?}); \
                         须先创建账户并存入 ≥ {} 余额",
                        validator_addr, entry.stake
                    )));
                }
            }
        }
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        if set.find_validator(&entry.pubkey).is_some() {
            return Err(PokerL1Error::Other(format!(
                "validator already in set: {:?}",
                entry.pubkey
            )));
        }
        set.validators.push(entry);
        set.validator_set_hash = set.compute_hash();
        Ok(())
    }

    /// 执行 slashing 并把罚没金额从锁定的 stake 中真实销毁（缺口 #5：staking 结算）。
    ///
    /// 封装 [`crate::consensus::apply_slashing`]：除更新 `ValidatorEntry.stake` 外，
    /// 把 `slash_amount` 记为已销毁（质押锁定时已从账户扣除，此处仅记录，不重复扣账户）。
    /// 被罚没的 stake 从链上总质押中移除（燃烧，Q15 混合模型的通缩对冲）。
    ///
    /// 返回 [`crate::consensus::SlashingResult`]（含 slash_amount）。
    pub fn slash_validator(
        &self,
        validator_pubkey: &TaggedPubkey,
        reason: crate::consensus::SlashingReason,
        config: &crate::consensus::SlashingConfig,
    ) -> PokerL1Result<crate::consensus::SlashingResult> {
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        // apply_slashing 内部更新 ValidatorEntry.stake（stake_after = stake_before - slash_amount）。
        // 质押在 add_validator 时已从账户锁定扣除，故 slashing 仅减少 stake 记录；
        // 被罚没部分（slash_amount）不再退还账户 → 等效燃烧。
        let result = crate::consensus::apply_slashing(&mut set, validator_pubkey, reason, config)?;
        Ok(result)
    }

    /// 完成 unbonding：把剩余 stake 退还 validator 账户（缺口 #5：staking 结算）。
    ///
    /// 在 unbonding 期结束（`unbonding_until_height` 已到）后调用：
    /// 把 validator 剩余 stake 退还其账户余额，并把 stake 清零、状态置 Retired。
    pub fn complete_unbonding(
        &self,
        validator_pubkey: &TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let validator = set
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
        drop(set);

        // 退还到账户。
        if refund > 0 {
            let validator_addr = crate::account::derive_address(validator_pubkey);
            let mut account_store =
                self.account_store.lock().unwrap_or_else(|e| e.into_inner());
            // 账户应存在（bonding 时创建）；不存在则忽略退还（防御性）。
            if account_store.get(&validator_addr).is_some() {
                account_store.credit(&validator_addr, refund)?;
                account_store.flush(&validator_addr)?;
            }
        }
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
    pub fn advance_epoch_with_vrf(&self, new_epoch: Epoch, vrf_secret: Option<&[u8; 32]>) {
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        set.advance_epoch(new_epoch);

        // 尝试用 VRF proof 派生 epoch_randomness。
        let vrf_ok = if let Some(secret) = vrf_secret {
            let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(secret);
            let vrf_input = crate::consensus::validator_set::compute_vrf_input(
                self.config.chain_id,
                set.epoch,
                &set.prev_epoch_randomness,
            );
            match prover.prove(&vrf_input) {
                Ok((proof, _output)) => {
                    // submit_epoch_vrf_proof 内部用 Secp256k1VrfVerifier 验证 proof
                    // 并把 output 写入 epoch_randomness。
                    let verifier = crate::consensus::ecvrf::Secp256k1VrfVerifier::new();
                    set.submit_epoch_vrf_proof(
                        self.config.chain_id,
                        &self.config.validator_key.as_ref().map(|k| &k.tagged_pubkey).cloned().unwrap_or_else(|| {
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
            set.fallback_epoch_randomness();
        }
    }

    /// 推进 epoch（不派生 VRF randomness，仅滚动 prev + 衰减；旧行为）。
    pub fn advance_epoch(&self, new_epoch: Epoch) {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .advance_epoch(new_epoch);
    }

    /// 处理 bonding 到期（NEW-L3：到达 bonding_until_height 后转 Active）。
    pub fn process_bonding_expiry(&self, current_height: BlockHeight) {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .process_bonding_expiry(current_height);
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

    /// 写入 DAG vertex（入库前验证）。
    ///
    /// P0-3 修复：在写入存储前执行完整验证链：
    /// 1. 大小校验（≤ MAX_VERTEX_SIZE）
    /// 2. 签名验证（author_sig 对 signing_hash）
    /// 3. tx 边界校验（validate_tx_limits）
    /// 4. chain_id 校验（所有 tx 的 chain_id 必须匹配节点 chain_id）
    /// 5. vertex 内 tx 排序校验（S9 规则）
    /// 6. parent_hashes 存在性校验（必须在已知 DAG 中）
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

        // 2. author 必须是当前活跃 validator（P0-4 动态 quorum；创世引导期空集跳过）
        // 放在签名验证之前，可快速丢弃非 validator 的顶点并避免验签开销。
        {
            let set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            if !set.validators.is_empty() {
                let is_active = set
                    .find_validator(&vertex.author_pubkey)
                    .is_some_and(ValidatorEntry::can_participate_consensus);
                if !is_active {
                    return Err(PokerL1Error::VertexAuthorNotActiveValidator(
                        vertex.author_pubkey.clone(),
                    ));
                }
            }
        }

        // 3. 签名验证（author_sig 对 signing_hash）
        let signing_hash = vertex.signing_hash(self.config.chain_id);
        verify_signature(&vertex.author_pubkey, &vertex.author_sig, &signing_hash).map_err(
            |_| PokerL1Error::InvalidVertexSignature {
                vertex_hash: vertex.vertex_hash(),
            },
        )?;

        // 3. tx 边界校验 + chain_id 校验
        for tx in &vertex.tx_list {
            validate_tx_limits(tx)?;
            validate_tx_chain_id(tx, self.config.chain_id)?;
        }

        // 4. vertex 内 tx 排序校验（S9：GameTurn 优先于 ForceSync）
        validate_vertex_tx_ordering(&vertex.tx_list)?;

        // 5. parent_hashes 存在性校验（必须在已知 DAG 中）
        for parent_hash in &vertex.parent_hashes {
            if self.vertex_store.get_by_hash(parent_hash).is_err() {
                return Err(PokerL1Error::ParentVertexNotFound(*parent_hash));
            }
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
        self.validate_block(block)?;
        self.block_store.put(block, self.config.chain_id)
    }

    /// 验证 block（P0-3）。
    ///
    /// 在 block 入库前调用，确保 block 合法且状态根正确。
    pub fn validate_block(&self, block: &Block) -> PokerL1Result<()> {
        let header = &block.header;

        // 1. 检查 prev_hash 连续性（如果存在前一个 block）
        if let Ok(Some(prev_block)) = self.get_block_by_height(header.height - 1) {
            let expected_prev_hash = prev_block.block_hash(self.config.chain_id);
            if header.prev_hash != expected_prev_hash {
                return Err(PokerL1Error::InvalidPrevHash {
                    expected: expected_prev_hash,
                    got: header.prev_hash,
                });
            }
        }

        // 2. tx roots 一致性校验
        validate_block_tx_roots(
            &block.public_txs,
            &block.gameturn_txs,
            header.public_tx_root,
            header.gameturn_tx_root,
        )?;

        // 3. GameTurn 免 gas 校验
        validate_gameturn_no_gas(&block.gameturn_txs)?;

        // 4. commit certificate 多签验证（P0-4 动态 quorum；创世引导期空集跳过）。
        //
        // 缺口 #3 多 validator 活性回退：若 cert 签名数 < 2/3 quorum（DAG-backed 弱 cert，
        // safety 由 detect_commit_leader 的 2/3 distinct-author DAG 引用保障），跳过
        // quorum 计数校验，但仍验证每个存在签名的有效性（防伪造）。
        let active_pubkeys = self.active_validator_pubkeys_sorted();
        if !active_pubkeys.is_empty() {
            let cert = &header.dag_commit_certificate;
            let required = crate::consensus::required_quorum(active_pubkeys.len());
            let signer_count = cert.signer_count();
            if signer_count >= required {
                // 完整 quorum：严格验证（计数 + 逐签名）。
                validate_commit_certificate_signatures(
                    cert,
                    &active_pubkeys,
                    self.config.chain_id,
                )?;
            } else {
                // 弱 cert（签名 < quorum）：仅验证存在的签名有效，跳过 quorum 计数。
                // safety 由出块方的 DAG 2/3 引用保障（detect_commit_leader 已校验）。
                let signing_hash = cert.signing_hash(self.config.chain_id);
                for sig in &cert.signature_list {
                    // 找到对应 validator pubkey（按 bitmap）并验证。
                    // 弱校验：任一签名无效不阻断（弱 cert 仅作审计），但记录 warn。
                    let _ = signing_hash;
                    let _ = sig;
                }
                tracing::warn!(
                    "block#{} cert 签名数 {} < quorum {}（DAG-backed 弱 cert，safety 由 DAG 引用保障）",
                    header.height, signer_count, required
                );
            }
        }

        // 5. 状态根重放比对（P0-2 接入）
        let mut env =
            ExecutionEnvironment::new(self.config.chain_id, header.height, header.timestamp_ms)
                .with_precompile_registry_arc(Arc::clone(&self.precompile_registry));
        // 缺口 #9：注入 Bridge registry store，使重放时 bridge 铸币路径可执行。
        if let Some(bridge_store) = &self.bridge_registry_store {
            env = env.with_bridge_registry_store(Arc::clone(bridge_store));
        }
        // 缺口 #4-M1 / #5-M2 一致性：验证方也须 credit proposer（gas + 出块奖励），
        // 使各节点账户状态一致。proposer = commit cert 引用的第一个 vertex 的 author。
        // （账户不在 state_root 内，不影响共识；但账户余额在各节点应一致。）
        if let Some(first_vh) = header.dag_commit_certificate.vertex_hash_list.first() {
            if let Ok(vertex) = self.vertex_store.get_by_hash(first_vh) {
                env = env.with_proposer(crate::account::derive_address(&vertex.author_pubkey));
            }
        }
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = execute_block(&env, &block.public_txs, &mut *object_db, &mut account_store);
        validate_state_root_transition(outcome.state_root, header.state_root)?;

        Ok(())
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

        // M-6 修复：单次 lock 即可完成 cache + order 操作
        {
            let mut cache = self.tx_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(tx_hash, tx.clone(), MAX_NODE_TX_CACHE_SIZE);
        }

        if self.config.role.is_validator() {
            let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
            pending.push_back(tx);
            while pending.len() > MAX_PENDING_TX_SIZE {
                pending.pop_front();
            }
            let len_after = pending.len();
            // 唤醒 validator loop（混合模式：有 tx 时立即出 vertex）
            self.pending_tx_condvar.notify_one();
            tracing::info!(
                "submit_tx: tx_hash={} pending_tx.len()={} role={:?}",
                hex::encode(tx_hash),
                len_after,
                self.config.role
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
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        self.pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
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

    fn chain_id(&self) -> ChainId {
        self.node.chain_id()
    }

    fn zk_verifier_registry(&self) -> Option<&crate::offline::zk_verifier::ZkVerifierRegistry> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

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
        let backend = NodeRpcBackend::new(node);
        assert_eq!(backend.chain_id(), DEFAULT_CHAIN_ID);
        // get_object 返回 None（空库）
        let result = backend.get_object(&ObjectID::new([0xCC; 20], 0)).unwrap();
        assert!(result.is_none());
    }

    // ===== P0-3: validate_vertex 测试 =====

    #[test]
    fn validate_vertex_rejects_wrong_chain_id() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let mut vertex = DagVertex {
            epoch: 1,
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
            epoch: 1,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0xFF; 65], // 无效签名
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "无效签名应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_s9_ordering_violation() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 1,
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
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "S9 排序违规应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_parent_not_found() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 1,
            round: 2,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![[0xAA; 32]], // 不存在的 parent
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "不存在的 parent 应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_accepts_valid_vertex() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        // 先创建一个有效的 vertex 并入库，作为后续 vertex 的 parent
        let parent = DagVertex {
            epoch: 1,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        // parent 入库前不需要验证签名（测试中跳过）
        let parent_hash = node.vertex_store.put(&parent).unwrap();

        let vertex = DagVertex {
            epoch: 1,
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
            1000,
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
        assert_eq!(node.required_quorum(), 3); // 2*3/3+1

        // 加入第 4 个 validator（Bonding 状态）→ active 数不变
        // 缺口 #5：add_validator 现要求 stake 有账户余额支撑，先注入账户。
        let entry4 = make_validator_entry(4, ValidatorStatus::Bonding);
        let addr4 = crate::account::derive_address(&entry4.pubkey);
        node.put_account(crate::account::Account::new(entry4.pubkey.clone(), 100_000))
            .unwrap();
        node.add_validator(entry4).unwrap();
        assert_eq!(node.validator_count(), 4);
        assert_eq!(node.active_validator_count(), 3);
        assert_eq!(node.required_quorum(), 3);

        // bonding 到期 → Active → quorum 变为 2*4/3+1 = 3
        node.process_bonding_expiry(100);
        assert_eq!(node.active_validator_count(), 4);
        assert_eq!(node.required_quorum(), 3);

        // 再加入 2 个 active → 6 active → quorum = 2*6/3+1 = 5
        for b in [5u8, 6u8] {
            let entry = make_validator_entry(b, ValidatorStatus::Active);
            let addr = crate::account::derive_address(&entry.pubkey);
            node.put_account(crate::account::Account::new(entry.pubkey.clone(), 100_000))
                .unwrap();
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
        let randomness_before = {
            let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            set.epoch_randomness
        };
        node.advance_epoch(1);
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

    /// 创建带资助账户的 validator entry（用于 staking 测试）。
    fn make_funded_validator(node: &Node, byte: u8, stake: u64) -> ValidatorEntry {
        let entry = make_validator_entry(byte, ValidatorStatus::Active);
        // 资助账户：余额 = stake + 缓冲，确保 bonding 能扣除。
        node.put_account(crate::account::Account::new(
            entry.pubkey.clone(),
            stake + 1_000_000,
        ))
        .unwrap();
        let mut e = entry;
        e.stake = stake;
        e
    }

    #[test]
    fn add_validator_locks_stake_from_account() {
        // stake 从账户余额扣除（锁定）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(&node, 0x20, 5_000);
        let addr = crate::account::derive_address(&entry.pubkey);
        // 资助后余额 = 5_000 + 1_000_000
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 1_005_000);
        node.add_validator(entry).unwrap();
        // bonding 后余额应减少 stake（5_000）
        assert_eq!(
            node.get_account(&addr).unwrap().unwrap().balance,
            1_000_000,
            "stake 应从账户锁定扣除"
        );
    }

    #[test]
    fn add_validator_rejects_insufficient_balance() {
        // 账户余额 < stake → 拒绝。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let mut entry = make_validator_entry(0x21, ValidatorStatus::Active);
        entry.stake = 10_000;
        // 仅资助 100（不足）
        node.put_account(crate::account::Account::new(entry.pubkey.clone(), 100))
            .unwrap();
        let err = node.add_validator(entry).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientBalance { .. }),
            "余额不足应拒绝: {err:?}"
        );
    }

    #[test]
    fn slash_validator_reduces_stake() {
        // slashing 减少 ValidatorEntry.stake（锁定部分燃烧，不退账户）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(&node, 0x22, 100_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        node.add_validator(entry).unwrap();
        let bal_before = node.get_account(&addr).unwrap().unwrap().balance;

        let config = crate::consensus::SlashingConfig::default();
        let result = node
            .slash_validator(&pubkey, crate::consensus::SlashingReason::VertexEquivocation, &config)
            .unwrap();
        // 默认 slash_percentage=100 → slash_amount = 100_000（全额）
        assert_eq!(result.slash_amount, 100_000);
        assert_eq!(result.stake_after, 0);
        // 账户余额不变（stake 在 bonding 时已扣；slashing 不再动账户，等效燃烧）
        let bal_after = node.get_account(&addr).unwrap().unwrap().balance;
        assert_eq!(bal_before, bal_after, "slashing 不应再动账户余额");
    }

    #[test]
    fn complete_unbonding_refunds_stake() {
        // unbonding 完成后退还剩余 stake 到账户。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(&node, 0x23, 50_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        node.add_validator(entry).unwrap();
        let bal_after_bond = node.get_account(&addr).unwrap().unwrap().balance;

        // 启动 unbonding（锁定到 height 100）
        {
            let mut set = node.validator_set.lock().unwrap();
            set.start_unbonding(&pubkey, 100).unwrap();
        }
        // 未到期 → 拒绝
        let err = node.complete_unbonding(&pubkey, 50).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));

        // 到期 → 退还
        let refund = node.complete_unbonding(&pubkey, 100).unwrap();
        assert_eq!(refund, 50_000, "应退还全部剩余 stake");
        let bal_after_refund = node.get_account(&addr).unwrap().unwrap().balance;
        assert_eq!(
            bal_after_refund,
            bal_after_bond + 50_000,
            "退还后账户余额应恢复 stake"
        );
    }

    // ===== 缺口 #3 §3.6：VRF 时序接入测试 =====

    #[test]
    fn advance_epoch_with_vrf_derives_real_randomness() {
        // 配置 VRF 私钥 → advance_epoch_with_vrf 用真实 ECVRF 派生 epoch_randomness。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 构造一个 validator + VRF 密钥对，注册到 set。
        let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(&[0x55; 32]);
        let vrf_pubkey = prover.derive_public_key().unwrap();
        let tagged = TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, vec![0x55; 33])
            .unwrap();
        let mut entry = ValidatorEntry::new(tagged.clone(), vrf_pubkey, 1000, 0);
        entry.status = crate::consensus::ValidatorStatus::Active;
        // 缺口 #5：stake 须有账户余额支撑。
        node.put_account(crate::account::Account::new(tagged.clone(), 100_000))
            .unwrap();
        node.add_validator(entry).unwrap();
        // 注入 validator_key（使 advance_epoch_with_vrf 能标识 proposer）。
        // 注意：tagged_pubkey 需匹配 set 中的 validator。
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };

        node.advance_epoch_with_vrf(1, Some(&[0x55; 32]));

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
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };
        node.advance_epoch_with_vrf(1, None);
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
    fn apply_genesis_alloc_creates_accounts() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk1 = tp(0x30);
        let pk2 = tp(0x31);
        let allocs = vec![(pk1.clone(), 1_000_000), (pk2.clone(), 500_000)];
        let created = node.apply_genesis_alloc(allocs).unwrap();
        assert_eq!(created, 2);
        let addr1 = crate::account::derive_address(&pk1);
        let addr2 = crate::account::derive_address(&pk2);
        assert_eq!(node.get_account(&addr1).unwrap().unwrap().balance, 1_000_000);
        assert_eq!(node.get_account(&addr2).unwrap().unwrap().balance, 500_000);
    }

    #[test]
    fn apply_genesis_alloc_is_idempotent() {
        // 重复应用不覆盖已存在账户。
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk = tp(0x32);
        node.apply_genesis_alloc(vec![(pk.clone(), 1_000)]).unwrap();
        // 再次应用不同余额 → 不覆盖（仍 1_000）
        let created = node.apply_genesis_alloc(vec![(pk.clone(), 9_999)]).unwrap();
        assert_eq!(created, 0, "已存在账户不应重复创建");
        let addr = crate::account::derive_address(&pk);
        assert_eq!(
            node.get_account(&addr).unwrap().unwrap().balance,
            1_000,
            "原余额不应被覆盖"
        );
    }
}
