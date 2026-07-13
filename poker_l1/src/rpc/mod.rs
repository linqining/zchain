//! RPC server（Task 31 — SubTask 31.1 / 31.2 / 31.3）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 31.1**：JSON-RPC 方法
//!   - `get_block(hash | height)` / `get_object(id)` / `get_tx(hash)`
//!   - `submit_tx(tx_bytes)` / `get_account(address | pubkey)` / `get_dag_vertex(hash)`
//! - **SubTask 31.2**：WebSocket 订阅事件（block / vertex / tx）
//! - **SubTask 31.3**：crypto verify RPC
//!   - `secp256k1_aggregate_verify(pubkeys, msg_hashes, sigs)`
//!   - `bls_verify(pubkey_g2, signature_g1, msg)`
//!   - `zk_verify(scheme_id, proof, public_io)`
//!
//! 实现说明：
//! - 本模块定义 RPC 请求/响应类型、[`RpcBackend`] trait、[`RpcHandler`] 派发器
//! - 不绑定具体传输层（HTTP / WebSocket）；由上层 node 二进制集成 axum / tungstenite
//! - 纯库代码，可单元测试；集成测试见 `tests/phase6_integration.rs`

use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountStore};
use crate::block::Block;
use crate::consensus::DagVertex;
use crate::crypto_precompiles::native_api::{
    bls_verify as native_bls_verify,
    secp256k1_aggregate_verify as native_secp256k1_aggregate_verify,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID};
use crate::offline::zk_verifier::{SchemeId, ZkPublicIo, ZkVerifierRegistry, ZkVerifyResult};
use crate::signature::TaggedPubkey;
use crate::storage::{BlockStore, DagVertexStore, ObjectDb};
use crate::transaction::Transaction;
use crate::{Address, BlockHeight, ChainId, Hash};

/// JSON-RPC 2.0 请求（spec：https://www.jsonrpc.org/specification）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// 协议版本（固定 "2.0"）。
    pub jsonrpc: String,
    /// 方法名。
    pub method: String,
    /// 参数（位置参数）。
    pub params: serde_json::Value,
    /// 请求 ID（由客户端提供，原样回传）。
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// 协议版本。
    pub jsonrpc: String,
    /// 结果（成功时）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// 错误（失败时）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// 请求 ID（原样回传）。
    pub id: serde_json::Value,
}

/// JSON-RPC 错误对象。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// 错误码（标准 JSON-RPC 错误码或自定义 -32xxx）。
    pub code: i32,
    /// 错误消息。
    pub message: String,
    /// 额外数据（可选）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// 解析错误（-32700）。
    pub const PARSE_ERROR: i32 = -32700;
    /// 无效请求（-32600）。
    pub const INVALID_REQUEST: i32 = -32600;
    /// 方法未找到（-32601）。
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// 无效参数（-32602）。
    pub const INVALID_PARAMS: i32 = -32602;
    /// 内部错误（-32603）。
    pub const INTERNAL_ERROR: i32 = -32603;

    /// 构造错误对象。
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// 构造带额外数据的错误对象。
    pub fn with_data(code: i32, message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

impl JsonRpcResponse {
    /// 成功响应。
    pub fn success(result: serde_json::Value, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// 错误响应。
    pub fn error(err: JsonRpcError, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(err),
            id,
        }
    }
}

// ===== SubTask 31.1: JSON-RPC 方法参数与返回类型 =====

/// `get_block` 参数（按 hash 或 height 查询）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetBlockParams {
    /// 按 block_hash 查询。
    ByHash {
        /// block hash。
        hash: Hash,
    },
    /// 按 height 查询。
    ByHeight {
        /// block height。
        height: BlockHeight,
    },
}

/// `get_object` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetObjectParams {
    /// 对象 ID。
    pub id: ObjectID,
}

/// `get_tx` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTxParams {
    /// tx hash。
    pub tx_hash: Hash,
}

/// `submit_tx` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTxParams {
    /// BCS 编码的 tx 字节。
    pub tx_bytes: Vec<u8>,
}

/// `submit_tx` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTxResult {
    /// 计算出的 tx hash。
    pub tx_hash: Hash,
}

/// `get_account` 参数（按 address 或 tagged pubkey 查询）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAccountParams {
    /// 按 20 字节 address 查询。
    ByAddress {
        /// 账户地址。
        address: Address,
    },
    /// 按 tagged pubkey 查询（库内部派生 address）。
    ByPubkey {
        /// 账户绑定的 tagged pubkey。
        tagged_pubkey: TaggedPubkey,
    },
}

/// `get_dag_vertex` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetDagVertexParams {
    /// vertex hash。
    pub vertex_hash: Hash,
}

// ===== SubTask 31.3: crypto verify RPC 参数与返回类型 =====

/// `secp256k1_aggregate_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1AggregateVerifyParams {
    /// N 个 tagged pubkey。
    pub pubkeys: Vec<TaggedPubkey>,
    /// N 个消息哈希（每个 32 字节）。
    pub msg_hashes: Vec<Hash>,
    /// N 个签名字节。
    pub sigs: Vec<Vec<u8>>,
}

/// `secp256k1_aggregate_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1AggregateVerifyResult {
    /// 全部签名验证通过返回 true，任一失败返回 false。
    pub verified: bool,
}

/// `bls_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsVerifyParams {
    /// 签名者公钥（G2 compressed，96 字节）。
    pub pubkey_g2: Vec<u8>,
    /// 签名（G1 compressed，48 字节）。
    pub signature_g1: Vec<u8>,
    /// 被签名的消息。
    pub msg: Vec<u8>,
}

/// `bls_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsVerifyResult {
    /// 验证结果。
    pub verified: bool,
}

/// `zk_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifyParams {
    /// ZK 证明 scheme_id（1=Hypernova / 2=Groth16 / 3=IPA）。
    pub scheme_id: SchemeId,
    /// proof 字节。
    pub proof: Vec<u8>,
    /// public_io（序列化为 BCS 字节）。
    pub public_io_bytes: Vec<u8>,
    /// max_skip_segments 上限。
    pub max_skip_segments: u32,
    /// max_ack_chain_length 上限。
    pub max_ack_chain_length: u32,
}

/// `zk_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifyRpcResult {
    /// 验证结果。
    pub verified: bool,
    /// 当前 verifier_status（Stub / Production）。
    pub verifier_status: String,
    /// scheme_id。
    pub scheme_id: SchemeId,
}

// ===== SubTask 31.2: WebSocket 订阅 =====

/// WebSocket 订阅事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// 新 block 事件。
    Block,
    /// 新 DAG vertex 事件。
    Vertex,
    /// 新 tx 事件。
    Transaction,
}

/// WebSocket 订阅请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// 订阅的事件类型列表。
    pub event_types: Vec<EventType>,
}

/// WebSocket 订阅响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// 订阅 ID（用于后续取消订阅）。
    pub subscription_id: u64,
}

/// WebSocket 取消订阅请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// 订阅 ID。
    pub subscription_id: u64,
}

/// WebSocket 推送的事件消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMessage {
    /// 订阅 ID。
    pub subscription_id: u64,
    /// 事件类型。
    pub event_type: EventType,
    /// 事件载荷（BCS 字节，客户端按 event_type 反序列化）。
    pub payload: Vec<u8>,
}

// ===== RpcBackend trait =====

/// RPC 后端 trait — 提供存储与状态访问抽象。
///
/// 实现方（节点二进制）组合 BlockStore / ObjectDb / DagVertexStore / AccountStore
/// 实现此 trait，并传给 [`RpcHandler`] 派发请求。
pub trait RpcBackend: Send + Sync {
    /// 按 hash 查询 block。
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>>;
    /// 按 height 查询 block。
    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>>;
    /// 查询对象。
    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>>;
    /// 按 hash 查询 tx（遍历 block 查找；archive node 才支持）。
    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>>;
    /// 提交 tx（验证后放入待装 vertex 缓冲）。
    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash>;
    /// 按 address 查询 account。
    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>>;
    /// 按 hash 查询 DAG vertex。
    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>>;
    /// 当前 chain_id。
    fn chain_id(&self) -> ChainId;
    /// ZK verifier registry（用于 zk_verify RPC）。
    fn zk_verifier_registry(&self) -> Option<&ZkVerifierRegistry>;
}

// ===== RpcHandler =====

/// JSON-RPC 请求派发器。
///
/// 持有 [`RpcBackend`] 引用，将 JSON-RPC 请求派发到后端方法。
/// 方法名匹配 spec SubTask 31.1 / 31.3。
pub struct RpcHandler<'a, B: RpcBackend> {
    /// 后端。
    backend: &'a B,
}

impl<'a, B: RpcBackend> RpcHandler<'a, B> {
    /// 创建 handler。
    pub const fn new(backend: &'a B) -> Self {
        Self { backend }
    }

    /// 处理 JSON-RPC 请求，返回 JSON-RPC 响应。
    pub fn handle(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        // 解析 params 为 serde_json::Value，方法内部再反序列化为具体类型
        let result = match req.method.as_str() {
            "get_block" => self.handle_get_block(&req.params),
            "get_object" => self.handle_get_object(&req.params),
            "get_tx" => self.handle_get_tx(&req.params),
            "submit_tx" => self.handle_submit_tx(&req.params),
            "get_account" => self.handle_get_account(&req.params),
            "get_dag_vertex" => self.handle_get_dag_vertex(&req.params),
            "secp256k1_aggregate_verify" => self.handle_secp256k1_aggregate_verify(&req.params),
            "bls_verify" => self.handle_bls_verify(&req.params),
            "zk_verify" => self.handle_zk_verify(&req.params),
            _ => {
                return JsonRpcResponse::error(
                    JsonRpcError::new(
                        JsonRpcError::METHOD_NOT_FOUND,
                        format!("method not found: {}", req.method),
                    ),
                    req.id.clone(),
                );
            }
        };

        match result {
            Ok(value) => JsonRpcResponse::success(value, req.id.clone()),
            Err(err) => JsonRpcResponse::error(
                JsonRpcError::new(JsonRpcError::INVALID_PARAMS, err),
                req.id.clone(),
            ),
        }
    }

    // ===== SubTask 31.1: JSON-RPC 方法 =====

    fn handle_get_block(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: GetBlockParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let block = match p {
            GetBlockParams::ByHash { hash } => self.backend.get_block_by_hash(&hash),
            GetBlockParams::ByHeight { height } => self.backend.get_block_by_height(height),
        }
        .map_err(|e| e.to_string())?;
        serde_json::to_value(block).map_err(|e| e.to_string())
    }

    fn handle_get_object(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: GetObjectParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let obj = self.backend.get_object(&p.id).map_err(|e| e.to_string())?;
        serde_json::to_value(obj).map_err(|e| e.to_string())
    }

    fn handle_get_tx(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: GetTxParams = serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let tx = self.backend.get_tx(&p.tx_hash).map_err(|e| e.to_string())?;
        serde_json::to_value(tx).map_err(|e| e.to_string())
    }

    fn handle_submit_tx(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: SubmitTxParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        // tx_bytes 边界校验（SubTask 30.6：tx <= 128KB）
        const MAX_TX_SIZE: usize = 128 * 1024;
        if p.tx_bytes.len() > MAX_TX_SIZE {
            return Err(PokerL1Error::TxTooLarge {
                actual: p.tx_bytes.len(),
                limit: MAX_TX_SIZE,
            }
            .to_string());
        }
        let tx = Transaction::from_bcs(&p.tx_bytes).map_err(|e| e.to_string())?;
        let tx_hash = self.backend.submit_tx(tx).map_err(|e| e.to_string())?;
        serde_json::to_value(SubmitTxResult { tx_hash }).map_err(|e| e.to_string())
    }

    fn handle_get_account(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: GetAccountParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let address = match p {
            GetAccountParams::ByAddress { address } => address,
            GetAccountParams::ByPubkey { tagged_pubkey } => {
                crate::account::derive_address(&tagged_pubkey)
            }
        };
        let account = self
            .backend
            .get_account(&address)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(account).map_err(|e| e.to_string())
    }

    fn handle_get_dag_vertex(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let p: GetDagVertexParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let vertex = self
            .backend
            .get_dag_vertex(&p.vertex_hash)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(vertex).map_err(|e| e.to_string())
    }

    // ===== SubTask 31.3: crypto verify RPC =====

    fn handle_secp256k1_aggregate_verify(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let p: Secp256k1AggregateVerifyParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        if p.pubkeys.len() != p.msg_hashes.len() || p.pubkeys.len() != p.sigs.len() {
            return Err("pubkeys / msg_hashes / sigs length mismatch".to_string());
        }
        let msg_refs: Vec<&[u8; 32]> = p.msg_hashes.iter().collect();
        let sig_refs: Vec<&[u8]> = p.sigs.iter().map(|s| s.as_slice()).collect();
        let verified = native_secp256k1_aggregate_verify(&p.pubkeys, &msg_refs, &sig_refs)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(Secp256k1AggregateVerifyResult { verified }).map_err(|e| e.to_string())
    }

    fn handle_bls_verify(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: BlsVerifyParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let verified =
            native_bls_verify(&p.pubkey_g2, &p.signature_g1, &p.msg).map_err(|e| e.to_string())?;
        serde_json::to_value(BlsVerifyResult { verified }).map_err(|e| e.to_string())
    }

    fn handle_zk_verify(&self, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        let p: ZkVerifyParams =
            serde_json::from_value(params.clone()).map_err(|e| e.to_string())?;
        let registry = self
            .backend
            .zk_verifier_registry()
            .ok_or_else(|| "zk verifier registry not available".to_string())?;
        // 反序列化 public_io（ZkPublicIo::from_bytes 内部固定布局）
        let public_io = ZkPublicIo::from_bytes(&p.public_io_bytes)
            .ok_or_else(|| "public_io 反序列化失败：长度不足或格式错误".to_string())?;
        let result: ZkVerifyResult = registry
            .zk_verify(
                self.backend.chain_id(),
                p.scheme_id,
                &p.proof,
                &public_io,
                p.max_skip_segments,
                p.max_ack_chain_length,
            )
            .map_err(|e| e.to_string())?;
        serde_json::to_value(ZkVerifyRpcResult {
            verified: result.verified,
            verifier_status: format!("{:?}", result.verifier_status),
            scheme_id: result.scheme_id,
        })
        .map_err(|e| e.to_string())
    }
}

// ===== MemoryBackend（用于测试） =====

/// 内存后端 — 用于单元测试与集成测试。
///
/// 组合 BlockStore / ObjectDb / DagVertexStore / AccountStore 的内存实例。
pub struct MemoryBackend {
    /// BlockStore。
    block_store: BlockStore,
    /// ObjectDb。
    object_db: std::sync::Mutex<ObjectDb>,
    /// DagVertexStore。
    vertex_store: DagVertexStore,
    /// AccountStore。
    account_store: std::sync::Mutex<AccountStore>,
    /// chain_id。
    chain_id: ChainId,
    /// 已提交的 tx 缓存（tx_hash → tx），用于 get_tx RPC。
    tx_cache: std::sync::Mutex<std::collections::HashMap<Hash, Transaction>>,
    /// 待装 vertex 的 tx 缓冲（submit_tx 写入）。
    pending_tx: std::sync::Mutex<std::collections::VecDeque<Transaction>>,
    /// ZK verifier registry（可选）。
    zk_registry: Option<ZkVerifierRegistry>,
}

impl MemoryBackend {
    /// 创建空内存后端。
    pub fn new(chain_id: ChainId) -> PokerL1Result<Self> {
        Ok(Self {
            block_store: BlockStore::open_inmemory()?,
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            chain_id,
            tx_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            zk_registry: None,
        })
    }

    /// 设置 ZK verifier registry。
    pub fn set_zk_registry(&mut self, registry: ZkVerifierRegistry) {
        self.zk_registry = Some(registry);
    }

    /// 注入 block（测试辅助）。
    pub fn insert_block(&self, block: Block) -> PokerL1Result<Hash> {
        self.block_store.put(&block, self.chain_id)
    }

    /// 注入对象（测试辅助）。
    pub fn insert_object(&self, object: Object) -> PokerL1Result<()> {
        self.object_db.lock().unwrap().create(object)
    }

    /// 注入 DAG vertex（测试辅助）。
    pub fn insert_vertex(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        self.vertex_store.put(vertex)
    }

    /// 注入 account（测试辅助）。
    pub fn insert_account(&self, account: Account) -> PokerL1Result<()> {
        self.account_store.lock().unwrap().create(account)
    }

    /// 取出待装 vertex 的 tx（测试辅助）。
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        self.pending_tx.lock().unwrap().drain(..).collect()
    }
}

impl RpcBackend for MemoryBackend {
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_hash(hash) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_height(height) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        let result = self.object_db.lock().unwrap().read(id);
        match result {
            Ok(obj) => Ok(Some(obj)),
            Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        Ok(self.tx_cache.lock().unwrap().get(tx_hash).cloned())
    }

    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        let tx_hash = tx.tx_hash();
        self.tx_cache.lock().unwrap().insert(tx_hash, tx.clone());
        self.pending_tx.lock().unwrap().push_back(tx);
        Ok(tx_hash)
    }

    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        Ok(self.account_store.lock().unwrap().get(address).cloned())
    }

    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        match self.vertex_store.get_by_hash(vertex_hash) {
            Ok(vertex) => Ok(Some(vertex)),
            Err(PokerL1Error::DagVertexNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn zk_verifier_registry(&self) -> Option<&ZkVerifierRegistry> {
        self.zk_registry.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::Account;
    use crate::block::{Block, BlockHeader};
    use crate::consensus::DagVertex;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, Transaction, TxLane};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    fn dummy_object(id_byte: u8) -> Object {
        Object::new(
            ObjectID::new([id_byte; 20], 0),
            Ownership::Shared,
            "TestType",
            b"test_data".to_vec(),
            None,
        )
    }

    fn dummy_commit_certificate() -> crate::consensus::DagCommitCertificate {
        crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 0,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![],
        }
    }

    fn dummy_block(height: u64) -> Block {
        Block::new(
            BlockHeader {
                height,
                timestamp_ms: height * 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: dummy_commit_certificate(),
            },
            vec![],
            vec![],
        )
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![dummy_object(1)],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn jsonrpc_response_success_serialization() {
        let resp = JsonRpcResponse::success(serde_json::json!({"ok": true}), serde_json::json!(1));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn jsonrpc_response_error_serialization() {
        let resp = JsonRpcResponse::error(
            JsonRpcError::new(JsonRpcError::METHOD_NOT_FOUND, "no method"),
            serde_json::json!(1),
        );
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn get_block_by_height_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let block = dummy_block(10);
        let hash = backend.insert_block(block).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 10}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none(), "get_block 应成功");
        let block_resp: Block = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(block_resp.header.height, 10);
        // hash 一致
        assert_eq!(block_resp.block_hash(DEFAULT_CHAIN_ID), hash);
    }

    #[test]
    fn get_block_by_hash_not_found() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let zero_hash: Hash = [0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"hash": zero_hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.result.is_some(), "not found 应返回 result: null");
        assert!(resp.result.unwrap().is_null());
    }

    #[test]
    fn get_object_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let obj = dummy_object(0xAA);
        let id = obj.id;
        backend.insert_object(obj).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_object".to_string(),
            params: serde_json::json!({"id": id}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let obj_resp: Object = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(obj_resp.id, id);
    }

    #[test]
    fn submit_tx_returns_tx_hash() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tx = dummy_tx();
        let expected_hash = tx.tx_hash();
        let tx_bytes = tx.to_bcs().unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": tx_bytes}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none(), "submit_tx 应成功");
        let result: SubmitTxResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.tx_hash, expected_hash);

        // pending_tx 应有一笔
        let pending = backend.drain_pending_tx();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn submit_tx_too_large_rejected() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        // 构造超大 tx_bytes（128KB + 1）
        let big_bytes = vec![0u8; 128 * 1024 + 1];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": big_bytes}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "超大 tx 应被拒绝");
        assert_eq!(resp.error.unwrap().code, JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn get_account_by_address() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged, 1000);
        let address = account.address;
        backend.insert_account(account).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_account".to_string(),
            params: serde_json::json!({"address": address}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let account_resp: Account = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(account_resp.address, address);
        assert_eq!(account_resp.balance, 1000);
    }

    #[test]
    fn get_account_by_pubkey() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged.clone(), 500);
        backend.insert_account(account).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_account".to_string(),
            params: serde_json::json!({"tagged_pubkey": tagged}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let account_resp: Account = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(account_resp.balance, 500);
    }

    #[test]
    fn get_dag_vertex_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 1,
            round: 5,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let hash = backend.insert_vertex(&vertex).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_dag_vertex".to_string(),
            params: serde_json::json!({"vertex_hash": hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let v_resp: DagVertex = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(v_resp.epoch, 1);
        assert_eq!(v_resp.round, 5);
    }

    #[test]
    fn method_not_found() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "nonexistent_method".to_string(),
            params: serde_json::json!({}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, JsonRpcError::METHOD_NOT_FOUND);
    }

    #[test]
    fn secp256k1_aggregate_verify_length_mismatch() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let msg1: Hash = [0u8; 32];
        let msg2: Hash = [0u8; 32];
        let sig: Vec<u8> = vec![0u8; 65];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "secp256k1_aggregate_verify".to_string(),
            params: serde_json::json!({
                "pubkeys": [dummy_tagged_pubkey()],
                "msg_hashes": [msg1, msg2],
                "sigs": [sig]
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "长度不匹配应返回错误");
    }

    #[test]
    fn bls_verify_invalid_pubkey_length() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let bad_pubkey: Vec<u8> = vec![0u8; 95];
        let sig: Vec<u8> = vec![0u8; 48];
        let msg: Vec<u8> = vec![0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "bls_verify".to_string(),
            params: serde_json::json!({
                "pubkey_g2": bad_pubkey,
                "signature_g1": sig,
                "msg": msg
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "错误 pubkey 长度应返回错误");
    }

    #[test]
    fn zk_verify_no_registry_returns_error() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let proof: Vec<u8> = vec![0u8; 16];
        let public_io: Vec<u8> = vec![0u8; 16];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "zk_verify".to_string(),
            params: serde_json::json!({
                "scheme_id": 1u32,
                "proof": proof,
                "public_io_bytes": public_io,
                "max_skip_segments": 3u32,
                "max_ack_chain_length": 1000u32
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "无 registry 应返回错误");
    }

    #[test]
    fn websocket_event_types_serialize() {
        let types = vec![EventType::Block, EventType::Vertex, EventType::Transaction];
        let s = serde_json::to_string(&types).unwrap();
        assert!(s.contains("Block"));
        assert!(s.contains("Vertex"));
        assert!(s.contains("Transaction"));
        let de: Vec<EventType> = serde_json::from_str(&s).unwrap();
        assert_eq!(de.len(), 3);
    }

    #[test]
    fn subscribe_request_roundtrip() {
        let req = SubscribeRequest {
            event_types: vec![EventType::Block, EventType::Transaction],
        };
        let s = serde_json::to_string(&req).unwrap();
        let de: SubscribeRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(de.event_types.len(), 2);
    }

    #[test]
    fn event_message_roundtrip() {
        let msg = EventMessage {
            subscription_id: 42,
            event_type: EventType::Block,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = serde_json::to_string(&msg).unwrap();
        let de: EventMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(de.subscription_id, 42);
        assert_eq!(de.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn get_tx_returns_none_for_unknown() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let zero_hash: Hash = [0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_tx".to_string(),
            params: serde_json::json!({"tx_hash": zero_hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().is_null());
    }

    #[test]
    fn get_tx_returns_tx_after_submit() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tx = dummy_tx();
        let tx_hash = tx.tx_hash();
        let tx_bytes = tx.to_bcs().unwrap();

        // submit_tx
        let handler = RpcHandler::new(&backend);
        let submit_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": tx_bytes}),
            id: serde_json::json!(1),
        };
        let _ = handler.handle(&submit_req);

        // get_tx
        let get_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_tx".to_string(),
            params: serde_json::json!({"tx_hash": tx_hash}),
            id: serde_json::json!(2),
        };
        let resp = handler.handle(&get_req);
        assert!(resp.error.is_none());
        let tx_resp: Transaction = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(tx_resp.tx_hash(), tx_hash);
    }
}
