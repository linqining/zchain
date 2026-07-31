//! Texas Poker 合约预编译实现（包装 `texas_poker::dispatch` 逻辑）。
//!
//! 将 `texas_poker::dispatch` 路由包装为 `Precompile` trait 实现，
//! 通过 `PrecompileRegistry` 注册后即可被 executor 调用。
//!
//! # ObjectID
//!
//! 固定为 `reserved::texas_poker_contract_id()`（`0xFF..02`）。
//!
//! # 首次调用（create_table）
//!
//! 当 `method_selector == selectors::create_table()` 且 ObjectDb 中无
//! `texas_poker_contract_id()` 对象时，先构造空 `TexasPokerTable`（占位）
//! 写入 ObjectDb，再交给 dispatch::dispatch::create_table 完成字段初始化。
//!
//! # Gas
//!
//! Texas Poker 操作通过 GameTurn 通道提交（spec：GameTurn 通道免 gas），
//! 故 `is_gas_free() = true`。反滥用由 `gameturn_nonce` 重放保护 +
//! 轮次约束 + assigned_validator 路由共同保障。

use std::sync::Arc;

use super::texas_poker::dispatch as tp_dispatch;
use super::texas_poker::dispatch::selectors;
use super::texas_poker::types::TexasPokerTable;
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::vm::contracts::dispatch::DispatchContext;
use crate::vm::precompile::{DispatchResult, ExecutionEnvironment, Precompile, reserved};

/// Texas Poker 合约预编译实现。
///
/// 将 `texas_poker::dispatch` 路由包装为 `Precompile` trait，
/// 通过固定 ObjectID（`reserved::texas_poker_contract_id()`）寻址。
#[derive(Debug, Clone)]
pub struct TexasPokerPrecompile {
    version: u32,
}

impl TexasPokerPrecompile {
    /// 创建 Texas Poker 合约预编译实例。
    #[must_use]
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// 创建 Texas Poker 合约预编译实例（Arc 包装）。
    #[must_use]
    pub fn new_arc(version: u32) -> Arc<dyn Precompile> {
        Arc::new(Self::new(version))
    }
}

impl Precompile for TexasPokerPrecompile {
    fn id(&self) -> ObjectID {
        reserved::texas_poker_contract_id()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn call(
        &self,
        caller: &Address,
        caller_pubkey: &TaggedPubkey,
        method_selector: &[u8; 32],
        args: &[u8],
        env: &ExecutionEnvironment,
        object_db: &mut dyn ObjectBackend,
    ) -> PokerL1Result<DispatchResult> {
        let dispatch_context = DispatchContext {
            caller: *caller,
            caller_pubkey: caller_pubkey.clone(),
            chain_id: env.chain_id,
            block_height: env.block_height,
            block_timestamp: env.block_timestamp,
        };

        let table_id = reserved::texas_poker_contract_id();

        // 读已有 table；不存在则按 create_table 首次调用处理
        let (mut table, is_new) = match object_db.read(&table_id) {
            Ok(obj) => {
                let table: TexasPokerTable = borsh::from_slice(&obj.data).map_err(|e| {
                    PokerL1Error::Serialization(format!("TexasPokerTable borsh: {e}"))
                })?;
                (table, false)
            }
            Err(PokerL1Error::ObjectNotFound(_)) => {
                // 首次调用：仅 create_table 允许在无对象时执行
                if method_selector != &selectors::create_table() {
                    return Err(PokerL1Error::ContractNotFound(table_id));
                }
                // 构造占位空表（dispatch_create_table 会用 args 覆写，含 creator 字段）
                let placeholder = TexasPokerTable::new(
                    table_id,
                    String::new(),
                    crate::vm::contracts::texas_poker::types::EMPTY_PLAYER,
                    2,
                    1,
                    1,
                );
                (placeholder, true)
            }
            Err(e) => return Err(e),
        };

        let result = tp_dispatch::dispatch(&dispatch_context, &mut table, method_selector, args)?;

        // 持久化
        let table_data = borsh::to_vec(&table).map_err(|e| {
            PokerL1Error::Serialization(format!("TexasPokerTable borsh write: {e}"))
        })?;
        if is_new {
            let obj = Object::new(
                table_id,
                Ownership::Shared,
                "TexasPokerTable",
                table_data,
                None,
            );
            object_db.create(obj)?;
        } else {
            object_db.update(&table_id, caller, table_data)?;
        }

        let mut final_result = DispatchResult {
            created_objects: result.created_objects,
            modified_objects: result.modified_objects,
            // 报告读集：仅当读到既有 table（is_new == false）时才存在真实读。
            // 首次 create_table（is_new == true）走 placeholder 分支，无真实读。
            read_objects: if is_new { vec![] } else { vec![table_id] },
            return_value: result.return_value,
        };
        if is_new && !final_result.created_objects.contains(&table_id) {
            final_result.created_objects.push(table_id);
        }

        Ok(final_result)
    }

    fn supports_selector(&self, selector: &[u8; 32]) -> bool {
        selectors::all().contains(selector)
    }

    /// Texas Poker 合约预编译免 gas（GameTurn 通道）。
    ///
    /// 反滥用由以下机制保障：
    /// - `gameturn_nonce` per-game per-player 重放保护
    /// - 轮次约束（routing.rs：`validate_turn_order`）
    /// - assigned_validator 路由（routing.rs：`validate_assigned_validator`）
    fn is_gas_free(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TaggedPubkey;
    use crate::vm::contracts::texas_poker::dispatch::CreateTableArgs;

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    fn make_caller() -> (Address, TaggedPubkey) {
        (
            [0xAA; 20],
            TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
        )
    }

    #[test]
    fn test_texas_poker_precompile_id() {
        let precompile = TexasPokerPrecompile::new(1);
        let expected = reserved::texas_poker_contract_id();
        assert_eq!(precompile.id(), expected);
    }

    #[test]
    fn test_texas_poker_precompile_version() {
        let precompile = TexasPokerPrecompile::new(3);
        assert_eq!(precompile.version(), 3);
    }

    #[test]
    fn test_texas_poker_precompile_supports_known_selector() {
        let precompile = TexasPokerPrecompile::new(1);
        assert!(precompile.supports_selector(&selectors::create_table()));
        assert!(precompile.supports_selector(&selectors::join_table()));
        assert!(precompile.supports_selector(&selectors::fold()));
        assert!(precompile.supports_selector(&selectors::tick()));
    }

    #[test]
    fn test_texas_poker_precompile_rejects_unknown_selector() {
        let precompile = TexasPokerPrecompile::new(1);
        let unknown = [0xFE; 32];
        assert!(!precompile.supports_selector(&unknown));
    }

    #[test]
    fn test_texas_poker_precompile_is_gas_free() {
        let precompile = TexasPokerPrecompile::new(1);
        assert!(precompile.is_gas_free());
    }

    #[test]
    fn test_texas_poker_precompile_create_table_first_call() {
        use crate::storage::object_db::ObjectDb;
        let precompile = TexasPokerPrecompile::new(1);
        let env = make_env();
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        let table_id = reserved::texas_poker_contract_id();

        // 首次调用：create_table（对象不存在）
        let args = CreateTableArgs {
            name: "first_game".into(),
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::create_table(),
                &args_bytes,
                &env,
                &mut object_db,
            )
            .unwrap();

        assert!(result.created_objects.contains(&table_id));
        // 验证对象已写入 ObjectDb
        let obj = object_db.read(&table_id).unwrap();
        let table: TexasPokerTable = borsh::from_slice(&obj.data).unwrap();
        assert_eq!(table.name, "first_game");
        assert_eq!(table.max_players, 6);
        assert_eq!(table.big_blind, 50);
    }

    #[test]
    fn test_texas_poker_precompile_non_create_first_call_rejected() {
        use crate::storage::object_db::ObjectDb;
        let precompile = TexasPokerPrecompile::new(1);
        let env = make_env();
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();

        // 首次调用非 create_table → ContractNotFound
        let result = precompile.call(
            &caller,
            &caller_pk,
            &selectors::start_hand(),
            &[],
            &env,
            &mut object_db,
        );
        assert!(matches!(result, Err(PokerL1Error::ContractNotFound(_))));
    }
}
