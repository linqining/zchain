//! 预编译合约系统（参考以太坊预编译合约设计）。
//!
//! 设计目标：
//! - **模块化**：预编译合约通过 trait 抽象，新增预编译只需实现 trait 并注册
//! - **版本升级**：支持治理门控的预编译合约升级（版本号 + timelock）
//! - **优先级路由**：预编译合约优先于 rBPF 执行，避免 dead-code 问题
//! - **命名空间隔离**：预编译合约使用保留的 ObjectID 命名空间
//!
//! # 架构
//!
//! ```text
//! Precompile (trait)
//!     ├── GamePrecompile (游戏合约)
//!     ├── ... (其他预编译合约)
//!     └── GovernancePrecompile (治理合约，未来扩展)
//!
//! PrecompileRegistry
//!     ├── precompiles: BTreeMap<ObjectID, Arc<dyn Precompile>>
//!     ├── versions: BTreeMap<ObjectID, PrecompileVersion>
//!     └── statuses: BTreeMap<ChainId, PrecompileStatus>
//! ```
//!
//! # 版本升级流程
//!
//! 1. 治理提案提交新预编译版本
//! 2. 90% quorum 投票通过
//! 3. timelock 等待期
//! 4. 激活新版本（旧版本标记为不可调用）

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::{Address, BlockHeight, ChainId, Hash};

/// 预编译合约 trait（统一接口）。
///
/// 所有预编译合约必须实现此 trait，通过 PrecompileRegistry 注册后即可被调用。
pub trait Precompile: Send + Sync {
    /// 预编译合约的唯一标识符（保留的 ObjectID）。
    fn id(&self) -> ObjectID;

    /// 当前版本号。
    fn version(&self) -> u32;

    /// 执行预编译合约调用。
    ///
    /// # 参数
    /// - `caller`：调用者地址
    /// - `caller_pubkey`：调用者公钥
    /// - `method_selector`：方法选择器（32 字节）
    /// - `args`：调用参数（BCS 编码）
    /// - `env`：执行环境
    /// - `object_db`：对象数据库（通过 `ObjectBackend` trait 抽象，支持 `ObjectDb` 和 `ObjectDbSnapshot`）
    ///
    /// # 返回
    /// DispatchResult 包含状态变更信息。
    fn call(
        &self,
        caller: &Address,
        caller_pubkey: &TaggedPubkey,
        method_selector: &[u8; 32],
        args: &[u8],
        env: &ExecutionEnvironment,
        object_db: &mut dyn ObjectBackend,
    ) -> PokerL1Result<DispatchResult>;

    /// 校验方法选择器是否属于此预编译合约。
    ///
    /// 默认实现返回 true（允许任意选择器），子类可覆写以实现更严格的校验。
    fn supports_selector(&self, _selector: &[u8; 32]) -> bool {
        true
    }

    /// 该预编译合约是否免 gas。
    ///
    /// 免 gas 预编译合约（如 [`crate::vm::contracts::GamePrecompile`]）的调用：
    /// - 不消耗 gas、不扣费
    /// - 不推进 account nonce（重放保护由 `gameturn_nonce` + 轮次约束保障）
    /// - 跳过账户 nonce 与 resource-credit 预检
    ///
    /// 反滥用由游戏买入锁仓 + `gameturn_nonce` + 轮次约束（routing.rs）保障。
    ///
    /// 默认 `false`：普通预编译合约（如签名验证、哈希等）仍按 tx gas 策略计费。
    ///
    /// # 安全约束
    ///
    /// executor 在 `execute_tx_inner` 中强制：`gas-free lane`（`TxLane::GameTurn` /
    /// `TxLane::CheckpointAnchor`）必须配 `is_gas_free() == true` 的预编译合约，
    /// 否则直接拒绝执行（防止免费 gas 滥用 DoS）。
    fn is_gas_free(&self) -> bool {
        false
    }
}

/// 预编译合约执行结果。
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// 新创建的对象 ID 列表。
    pub created_objects: Vec<ObjectID>,
    /// 修改的对象 ID 列表。
    pub modified_objects: Vec<ObjectID>,
    /// 读取的对象 ID 列表（并行执行器读写集来源）。
    ///
    /// 并行执行器据此做冲突检测：若两笔 tx 的 read/write 集相交则串行化。
    /// precompile 实现必须把所有通过 `object_db.read(id)` 读到的 id 报告于此，
    /// 否则并行 soundness 会漏掉读-写冲突。未报告读集的 precompile 在调度器中
    /// 默认降级为串行执行（保守策略）。
    pub read_objects: Vec<ObjectID>,
    /// 返回值（BCS 编码）。
    pub return_value: Vec<u8>,
}

impl DispatchResult {
    /// 创建空结果。
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![],
            read_objects: vec![],
            return_value: vec![],
        }
    }

    /// 创建仅修改指定对象的结果。
    #[must_use]
    pub fn modified_only(id: ObjectID) -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![id],
            read_objects: vec![],
            return_value: vec![],
        }
    }

    /// 创建"读并写同一对象"的结果（最常见的 game-only 模式）。
    ///
    /// precompile 通常先读 game 对象、再写回同一对象，故 read == write == {id}。
    #[must_use]
    pub fn read_write_only(id: ObjectID) -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![id],
            read_objects: vec![id],
            return_value: vec![],
        }
    }
}

/// 预编译合约版本信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileVersion {
    /// 当前活跃版本号。
    pub active_version: u32,
    /// 待激活版本（timelock 等待中）。
    pub pending_version: Option<u32>,
    /// 待激活版本的激活高度（timelock 到期高度）。
    pub activation_height: Option<BlockHeight>,
}

/// 预编译合约状态（治理门控）。
///
/// - `Stub`：测试网可用，主网受限
/// - `Production`：完整功能，主网可用
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileStatus {
    /// Stub 状态：测试网可用，主网拒绝某些操作。
    Stub,
    /// Production 状态：完整功能。
    Production,
}

impl PrecompileStatus {
    /// 是否允许主网使用。
    #[must_use]
    pub fn allows_mainnet(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// 预编译合约执行环境。
///
/// 传递给预编译合约的执行上下文。
#[derive(Debug, Clone)]
pub struct ExecutionEnvironment {
    /// 链 ID。
    pub chain_id: ChainId,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: u64,
    /// Transaction-declared object inputs. Funded precompiles must only consume coins from this
    /// signed set; accepting an object ID solely from call arguments would permit relabelling.
    pub tx_inputs: Vec<ObjectID>,
    /// Signed transaction hash used to derive deterministic change and payout object IDs.
    pub tx_hash: Hash,
}

/// 预编译合约注册表（热插拔 + 版本管理）。
///
/// 参考 `ZkVerifierRegistry` 的设计模式，支持：
/// - 热插拔注册/注销预编译合约
/// - 版本升级（治理门控 + timelock）
/// - per-chain_id 状态管理
pub struct PrecompileRegistry {
    /// ObjectID → 预编译合约实例。
    precompiles: BTreeMap<ObjectID, Arc<dyn Precompile>>,
    /// ObjectID → 版本信息。
    versions: BTreeMap<ObjectID, PrecompileVersion>,
    /// ChainId → 预编译状态（治理门控）。
    statuses: BTreeMap<ChainId, PrecompileStatus>,
    /// timelock 等待期（默认 7200 块，约 1 天）。
    timelock_blocks: BlockHeight,
}

impl std::fmt::Debug for PrecompileRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrecompileRegistry")
            .field("precompile_count", &self.precompiles.len())
            .field("versions", &self.versions)
            .field("statuses", &self.statuses)
            .field("timelock_blocks", &self.timelock_blocks)
            .finish()
    }
}

impl PrecompileRegistry {
    /// 创建空注册表（默认 timelock = 7200 块）。
    pub fn new() -> Self {
        Self {
            precompiles: BTreeMap::new(),
            versions: BTreeMap::new(),
            statuses: BTreeMap::new(),
            timelock_blocks: 7200,
        }
    }

    /// 创建带自定义 timelock 的注册表。
    pub fn with_timelock(timelock_blocks: BlockHeight) -> Self {
        Self {
            timelock_blocks,
            precompiles: BTreeMap::new(),
            versions: BTreeMap::new(),
            statuses: BTreeMap::new(),
        }
    }

    /// 注册预编译合约。
    ///
    /// 如果已存在同名预编译，将替换为新版本。
    pub fn register(&mut self, precompile: Arc<dyn Precompile>) {
        let id = precompile.id();
        let version = precompile.version();

        self.precompiles.insert(id, precompile);

        // 更新版本信息
        self.versions
            .entry(id)
            .and_modify(|v| {
                v.active_version = version;
            })
            .or_insert(PrecompileVersion {
                active_version: version,
                pending_version: None,
                activation_height: None,
            });
    }

    /// 注销预编译合约。
    pub fn unregister(&mut self, id: ObjectID) -> Option<Arc<dyn Precompile>> {
        self.versions.remove(&id);
        self.precompiles.remove(&id)
    }

    /// 查询预编译合约。
    pub fn get(&self, id: ObjectID) -> Option<&Arc<dyn Precompile>> {
        self.precompiles.get(&id)
    }

    /// 判断 ObjectID 是否为预编译合约。
    pub fn is_precompile(&self, id: ObjectID) -> bool {
        self.precompiles.contains_key(&id)
    }

    /// 查询某 ObjectID 对应的预编译合约是否免 gas。
    ///
    /// - 已注册的预编译合约：返回其 [`Precompile::is_gas_free`] 属性
    /// - 未注册的 ObjectID：返回 `false`（非预编译合约一律按 tx gas 策略计费）
    ///
    /// executor 在 `execute_tx_inner` 中调用此方法决定 gas/fee/nonce 策略。
    #[must_use]
    pub fn is_gas_free(&self, id: ObjectID) -> bool {
        self.precompiles.get(&id).is_some_and(|p| p.is_gas_free())
    }

    /// 获取所有已注册的预编译合约 ID。
    pub fn registered_ids(&self) -> Vec<ObjectID> {
        self.precompiles.keys().copied().collect()
    }

    /// 设置 per-chain_id 预编译状态（治理门控）。
    pub fn set_status(&mut self, chain_id: ChainId, status: PrecompileStatus) {
        self.statuses.insert(chain_id, status);
    }

    /// 获取 per-chain_id 预编译状态。
    ///
    /// 默认返回 Stub。
    pub fn status(&self, chain_id: ChainId) -> PrecompileStatus {
        *self
            .statuses
            .get(&chain_id)
            .unwrap_or(&PrecompileStatus::Stub)
    }

    /// 提交预编译合约升级提案。
    ///
    /// 触发 timelock 等待期，到期后自动激活新版本。
    pub fn propose_upgrade(
        &mut self,
        id: ObjectID,
        new_version: Arc<dyn Precompile>,
        current_height: BlockHeight,
    ) -> PokerL1Result<()> {
        if new_version.id() != id {
            return Err(PokerL1Error::Other(format!(
                "预编译 ID 不匹配: expected={id:?}, got={:?}",
                new_version.id()
            )));
        }

        let current_version = self
            .versions
            .get(&id)
            .ok_or_else(|| PokerL1Error::Other(format!("预编译未注册: {id:?}")))?;

        if new_version.version() <= current_version.active_version {
            return Err(PokerL1Error::Other(format!(
                "新版本号必须大于当前版本: current={}, new={}",
                current_version.active_version,
                new_version.version()
            )));
        }

        // 注册新版本（暂未激活）
        self.precompiles.insert(id, new_version.clone());

        // 设置 timelock
        let activation_height = current_height + self.timelock_blocks;
        self.versions.insert(
            id,
            PrecompileVersion {
                active_version: current_version.active_version,
                pending_version: Some(new_version.version()),
                activation_height: Some(activation_height),
            },
        );

        Ok(())
    }

    /// 激活待升级的预编译合约（timelock 到期后调用）。
    pub fn activate_upgrade(
        &mut self,
        id: ObjectID,
        current_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let version_info = self
            .versions
            .get_mut(&id)
            .ok_or_else(|| PokerL1Error::Other(format!("预编译未注册: {id:?}")))?;

        let (pending_version, activation_height) =
            match (version_info.pending_version, version_info.activation_height) {
                (Some(v), Some(h)) => (v, h),
                _ => return Err(PokerL1Error::Other(format!("没有待激活的升级: {id:?}"))),
            };

        if current_height < activation_height {
            return Err(PokerL1Error::Other(format!(
                "timelock 未到期: current={}, activation={}",
                current_height, activation_height
            )));
        }

        // 激活新版本
        version_info.active_version = pending_version;
        version_info.pending_version = None;
        version_info.activation_height = None;

        Ok(())
    }

    /// 执行预编译合约调用。
    ///
    /// 步骤：
    /// 1. 查找预编译合约（未注册返回错误）
    /// 2. 检查预编译状态（主网限制）
    /// 3. 检查版本（拒绝调用旧版本）
    /// 4. 调用预编译合约
    pub fn execute(
        &self,
        id: ObjectID,
        caller: &Address,
        caller_pubkey: &TaggedPubkey,
        method_selector: &[u8; 32],
        args: &[u8],
        env: &ExecutionEnvironment,
        object_db: &mut dyn ObjectBackend,
    ) -> PokerL1Result<DispatchResult> {
        let precompile = self
            .precompiles
            .get(&id)
            .ok_or_else(|| PokerL1Error::Other(format!("预编译合约未注册: {id:?}")))?;

        // 检查版本
        let version_info = self.versions.get(&id).unwrap();
        if precompile.version() != version_info.active_version {
            return Err(PokerL1Error::Other(format!(
                "预编译版本不匹配: expected={}, got={}",
                version_info.active_version,
                precompile.version()
            )));
        }

        // 检查方法选择器（可选）
        if !precompile.supports_selector(method_selector) {
            return Err(PokerL1Error::Other(format!(
                "预编译不支持此方法选择器: {:?}",
                method_selector
            )));
        }

        // 调用预编译合约
        precompile.call(caller, caller_pubkey, method_selector, args, env, object_db)
    }
}

/// 预编译合约命名空间保留地址。
///
/// 参考以太坊预编译合约地址（0x01-0x09），使用固定前缀标识预编译合约。
pub mod reserved {
    use crate::Address;
    use crate::object_model::ObjectID;

    /// 预编译合约地址前缀（0xFF 开头，表示系统预留）。
    pub const PRECOMPILE_PREFIX: u8 = 0xFF;

    /// 游戏合约预编译地址。
    pub const GAME_CONTRACT_ADDRESS: Address = [
        PRECOMPILE_PREFIX,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
    ];

    /// 游戏合约预编译 ObjectID。
    #[must_use]
    pub const fn game_contract_id() -> ObjectID {
        ObjectID::new(GAME_CONTRACT_ADDRESS, 0)
    }

    /// Texas Poker 合约预编译地址（0xFF..02）。
    pub const TEXAS_POKER_CONTRACT_ADDRESS: Address = [
        PRECOMPILE_PREFIX,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
    ];

    /// Texas Poker 合约预编译 ObjectID。
    #[must_use]
    pub const fn texas_poker_contract_id() -> ObjectID {
        ObjectID::new(TEXAS_POKER_CONTRACT_ADDRESS, 0)
    }

    /// Bridge 合约预编译地址（0xFF..03，缺口 #9）。
    pub const BRIDGE_CONTRACT_ADDRESS: Address = [
        PRECOMPILE_PREFIX,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
    ];

    /// Bridge 合约预编译 ObjectID（0xFF..03，缺口 #9）。
    #[must_use]
    pub const fn bridge_contract_id() -> ObjectID {
        ObjectID::new(BRIDGE_CONTRACT_ADDRESS, 0)
    }

    /// 原生转账合约预编译地址（0xFF..04，缺口 #4-M1）。
    pub const TRANSFER_CONTRACT_ADDRESS: Address = [
        PRECOMPILE_PREFIX,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x04,
    ];

    /// 原生转账合约预编译 ObjectID（0xFF..04，缺口 #4-M1）。
    #[must_use]
    pub const fn transfer_contract_id() -> ObjectID {
        ObjectID::new(TRANSFER_CONTRACT_ADDRESS, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TaggedPubkey;

    struct TestPrecompile {
        id: ObjectID,
        version: u32,
    }

    impl Precompile for TestPrecompile {
        fn id(&self) -> ObjectID {
            self.id
        }

        fn version(&self) -> u32 {
            self.version
        }

        fn call(
            &self,
            _caller: &Address,
            _caller_pubkey: &TaggedPubkey,
            _method_selector: &[u8; 32],
            _args: &[u8],
            _env: &ExecutionEnvironment,
            _object_db: &mut dyn ObjectBackend,
        ) -> PokerL1Result<DispatchResult> {
            Ok(DispatchResult::empty())
        }
    }

    fn make_test_precompile(id: ObjectID, version: u32) -> Arc<dyn Precompile> {
        Arc::new(TestPrecompile { id, version })
    }

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
            tx_inputs: vec![],
            tx_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_register_and_lookup() {
        let mut registry = PrecompileRegistry::new();
        let id = ObjectID::new([0xFF; 20], 1);
        let precompile = make_test_precompile(id, 1);

        registry.register(precompile);

        assert!(registry.is_precompile(id));
        assert!(registry.get(id).is_some());
        assert!(registry.registered_ids().contains(&id));
    }

    #[test]
    fn test_unregister() {
        let mut registry = PrecompileRegistry::new();
        let id = ObjectID::new([0xFF; 20], 1);
        let precompile = make_test_precompile(id, 1);

        registry.register(precompile);
        assert!(registry.unregister(id).is_some());
        assert!(!registry.is_precompile(id));
    }

    #[test]
    fn test_execute_precompile() {
        let mut registry = PrecompileRegistry::new();
        let id = ObjectID::new([0xFF; 20], 1);
        let precompile = make_test_precompile(id, 1);

        registry.register(precompile);

        let env = make_env();
        let mut db = ObjectDb::open_inmemory().unwrap();
        let result = registry.execute(
            id,
            &[0x00; 20],
            &TaggedPubkey {
                tag: 0,
                raw: vec![0u8; 32],
            },
            &[0u8; 32],
            &[],
            &env,
            &mut db,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_unregistered_precompile() {
        let registry = PrecompileRegistry::new();
        let id = ObjectID::new([0xFF; 20], 1);
        let env = make_env();
        let mut db = ObjectDb::open_inmemory().unwrap();

        let result = registry.execute(
            id,
            &[0x00; 20],
            &TaggedPubkey {
                tag: 0,
                raw: vec![0u8; 32],
            },
            &[0u8; 32],
            &[],
            &env,
            &mut db,
        );

        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_propose_upgrade() {
        let mut registry = PrecompileRegistry::with_timelock(10);
        let id = ObjectID::new([0xFF; 20], 1);

        registry.register(make_test_precompile(id, 1));

        let result = registry.propose_upgrade(id, make_test_precompile(id, 2), 100);
        assert!(result.is_ok());

        let version_info = registry.versions.get(&id).unwrap();
        assert_eq!(version_info.active_version, 1);
        assert_eq!(version_info.pending_version, Some(2));
        assert_eq!(version_info.activation_height, Some(110));
    }

    #[test]
    fn test_propose_upgrade_same_version_rejected() {
        let mut registry = PrecompileRegistry::new();
        let id = ObjectID::new([0xFF; 20], 1);

        registry.register(make_test_precompile(id, 1));

        let result = registry.propose_upgrade(id, make_test_precompile(id, 1), 100);
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_activate_upgrade_before_timelock_rejected() {
        let mut registry = PrecompileRegistry::with_timelock(10);
        let id = ObjectID::new([0xFF; 20], 1);

        registry.register(make_test_precompile(id, 1));
        registry
            .propose_upgrade(id, make_test_precompile(id, 2), 100)
            .unwrap();

        let result = registry.activate_upgrade(id, 105);
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_activate_upgrade_after_timelock() {
        let mut registry = PrecompileRegistry::with_timelock(10);
        let id = ObjectID::new([0xFF; 20], 1);

        registry.register(make_test_precompile(id, 1));
        registry
            .propose_upgrade(id, make_test_precompile(id, 2), 100)
            .unwrap();

        let result = registry.activate_upgrade(id, 110);
        assert!(result.is_ok());

        let version_info = registry.versions.get(&id).unwrap();
        assert_eq!(version_info.active_version, 2);
        assert_eq!(version_info.pending_version, None);
        assert_eq!(version_info.activation_height, None);
    }

    #[test]
    fn test_status_default_is_stub() {
        let registry = PrecompileRegistry::new();
        assert_eq!(registry.status(1), PrecompileStatus::Stub);
    }

    #[test]
    fn test_set_status() {
        let mut registry = PrecompileRegistry::new();
        registry.set_status(1, PrecompileStatus::Production);
        assert_eq!(registry.status(1), PrecompileStatus::Production);
    }

    #[test]
    fn test_reserved_game_contract_id() {
        let id = reserved::game_contract_id();
        assert_eq!(id.creator_address[0], reserved::PRECOMPILE_PREFIX);
    }

    // ===== gas-free 属性测试（预编译合约 Gas 策略重构）=====

    /// 测试用 gas-free 预编译合约（覆写 `is_gas_free() = true`）。
    ///
    /// 与 executor.rs 中的 `GasFreeTestPrecompile` 独立（不同模块，无冲突），
    /// 仅用于验证 `PrecompileRegistry::is_gas_free` 查询方法。
    struct GasFreeTestPrecompile {
        id: ObjectID,
    }

    impl GasFreeTestPrecompile {
        fn new(id: ObjectID) -> Arc<dyn Precompile> {
            Arc::new(Self { id })
        }
    }

    impl Precompile for GasFreeTestPrecompile {
        fn id(&self) -> ObjectID {
            self.id
        }

        fn version(&self) -> u32 {
            1
        }

        fn call(
            &self,
            _caller: &Address,
            _caller_pubkey: &TaggedPubkey,
            _method_selector: &[u8; 32],
            _args: &[u8],
            _env: &ExecutionEnvironment,
            _object_db: &mut dyn ObjectBackend,
        ) -> PokerL1Result<DispatchResult> {
            Ok(DispatchResult::empty())
        }

        fn is_gas_free(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_precompile_is_gas_free_default_false() {
        // 未覆写 is_gas_free() 的 TestPrecompile 应返回 false（默认实现）。
        let precompile = make_test_precompile(ObjectID::new([0xFF; 20], 1), 1);
        assert!(
            !precompile.is_gas_free(),
            "Precompile::is_gas_free() 默认应返回 false"
        );
    }

    #[test]
    fn test_registry_is_gas_free_query() {
        // 验证 PrecompileRegistry::is_gas_free(id) 查询方法：
        // - 已注册的 gas-free precompile → true
        // - 已注册的非 gas-free precompile → false
        // - 未注册的 ObjectID → false
        let mut registry = PrecompileRegistry::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 1);
        let non_gas_free_id = ObjectID::new([0xFD; 20], 2);

        // 注册 gas-free precompile
        registry.register(GasFreeTestPrecompile::new(gas_free_id));
        // 注册普通（非 gas-free）precompile
        registry.register(make_test_precompile(non_gas_free_id, 1));

        // gas-free precompile 查询返回 true
        assert!(
            registry.is_gas_free(gas_free_id),
            "已注册的 gas-free precompile 应返回 true"
        );
        // 普通 precompile 查询返回 false
        assert!(
            !registry.is_gas_free(non_gas_free_id),
            "已注册的非 gas-free precompile 应返回 false"
        );
        // 未注册的 ObjectID 查询返回 false
        assert!(
            !registry.is_gas_free(ObjectID::new([0x00; 20], 999)),
            "未注册的 ObjectID 应返回 false"
        );
    }
}
