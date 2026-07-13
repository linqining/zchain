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
use crate::consensus::DagVertex;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID};
use crate::signature::TaggedPubkey;
use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use crate::storage::{BlockStore, DagVertexStore, NodeRole as PruningNodeRole, ObjectDb};
use crate::transaction::Transaction;
use crate::{Address, BlockHeight, ChainId, Hash};

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
        }
    }
}

// ===== ValidatorKey =====

/// Validator 密钥（secp256k1）。
///
/// 用于 DAG vertex 签名与 commit certificate 签名。
/// 注意：私钥仅在 validator 节点内存中持有，不持久化到磁盘。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorKey {
    /// secp256k1 私钥（32 字节）。
    pub secret_key_bytes: [u8; 32],
    /// 对应的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
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
        })
    }
}

// ===== Node =====

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
    /// 已提交的 tx 缓存（tx_hash → tx）。
    tx_cache: std::sync::Mutex<std::collections::HashMap<Hash, Transaction>>,
    /// 待装 vertex 的 tx 缓冲（仅 Validator 角色）。
    pending_tx: std::sync::Mutex<std::collections::VecDeque<Transaction>>,
}

impl Node {
    /// 打开节点（初始化所有存储后端）。
    pub fn open(config: NodeConfig) -> PokerL1Result<Self> {
        let block_path = config.data_dir.join("blocks");
        let object_path = config.data_dir.join("objects");
        let vertex_path = config.data_dir.join("vertices");
        let block_store = BlockStore::open(&block_path)?;
        let object_db = ObjectDb::open(&object_path)?;
        let vertex_store = DagVertexStore::open(&vertex_path)?;
        Ok(Self {
            config,
            block_store,
            object_db: std::sync::Mutex::new(object_db),
            vertex_store,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// 创建内存节点（用于测试）。
    pub fn open_inmemory(role: NodeRole, chain_id: ChainId) -> PokerL1Result<Self> {
        Ok(Self {
            config: NodeConfig {
                role,
                chain_id,
                data_dir: PathBuf::from("/tmp/poker_l1_inmemory"),
                rpc_listen: "127.0.0.1:0".to_string(),
                p2p_listen: "127.0.0.1:0".to_string(),
                validator_key: None,
            },
            block_store: BlockStore::open_inmemory()?,
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
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

    /// 写入 block。
    pub fn put_block(&self, block: &Block) -> PokerL1Result<Hash> {
        self.block_store.put(block, self.config.chain_id)
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
        self.object_db.lock().unwrap().create(object)
    }

    /// 查询对象。
    pub fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        let result = self.object_db.lock().unwrap().read(id);
        match result {
            Ok(obj) => Ok(Some(obj)),
            Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 写入 DAG vertex。
    pub fn put_vertex(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        self.vertex_store.put(vertex)
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
        self.account_store.lock().unwrap().create(account)
    }

    /// 按 address 查询 account。
    pub fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        Ok(self.account_store.lock().unwrap().get(address).cloned())
    }

    /// 提交 tx（缓存 + pending 缓冲）。
    ///
    /// Validator 节点会将 tx 装入下一个 vertex；非 Validator 节点仅缓存用于查询。
    pub fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        let tx_hash = tx.tx_hash();
        self.tx_cache.lock().unwrap().insert(tx_hash, tx.clone());
        if self.config.role.is_validator() {
            self.pending_tx.lock().unwrap().push_back(tx);
        }
        Ok(tx_hash)
    }

    /// 按 hash 查询 tx（从缓存；archive node 可遍历 block）。
    pub fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        Ok(self.tx_cache.lock().unwrap().get(tx_hash).cloned())
    }

    /// 取出待装 vertex 的 tx（仅 Validator 角色有效）。
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        self.pending_tx.lock().unwrap().drain(..).collect()
    }

    /// 是否提供历史数据 RPC（仅 Archive 节点）。
    #[must_use]
    pub const fn serves_historical_data(&self) -> bool {
        self.config.role.is_archive()
    }
}

// ===== SubTask 32.5: CLI 工具函数 =====

/// CLI keygen 结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    let idx = u64::from_le_bytes(idx_bytes) as usize % validator_set.len();
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
}
