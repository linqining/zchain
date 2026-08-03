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
use super::texas_poker::events::{
    TexasPokerEvent, REFUND_TYPE_BET_ONLY, REFUND_TYPE_STACK_AND_BET, REFUND_TYPE_STACK_ONLY,
};
use super::texas_poker::prove_task::L1DispatchOutput;
use super::texas_poker::state_machine::reconcile_table_vault;
use super::texas_poker::types::TexasPokerTable;
use super::texas_poker::TEXAS_POKER_TABLE_OBJECT_TYPE;
use crate::economics::{
    coin_output_nonce, consume_native_coin_selection, create_native_coin_output,
    native_coin_object, select_owned_native_coins, NativeCoinSelection,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::vm::contracts::dispatch::DispatchContext;
use crate::vm::precompile::{reserved, DispatchResult, ExecutionEnvironment, Precompile};
use crate::Address;

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

    fn refund_outputs(return_value: &[u8]) -> PokerL1Result<Vec<(Address, u64)>> {
        let output: L1DispatchOutput = borsh::from_slice(return_value).map_err(|error| {
            PokerL1Error::Serialization(format!("decode Texas dispatch funding output: {error}"))
        })?;
        let mut refunds = Vec::new();
        for event in output.events {
            let TexasPokerEvent::PlayerRefund {
                player,
                amount,
                refund_type,
                ..
            } = event
            else {
                continue;
            };
            match refund_type {
                // STACK refunds leave the TableVault and therefore become wallet-owned UTXOs.
                REFUND_TYPE_STACK_ONLY | REFUND_TYPE_STACK_AND_BET if amount > 0 => {
                    refunds.push((player, amount));
                }
                // BET_ONLY is an in-table rollback: state_machine puts the value back into the
                // seat stack while chip_pool remains unchanged. Creating a UTXO here would pay
                // the same value twice and make the TableVault transition inconsistent.
                REFUND_TYPE_BET_ONLY | REFUND_TYPE_STACK_ONLY | REFUND_TYPE_STACK_AND_BET => {}
                unknown => {
                    return Err(PokerL1Error::Other(format!(
                        "unknown Texas refund type {unknown}"
                    )));
                }
            }
        }
        Ok(refunds)
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

        let pre_locked = reconcile_table_vault(&table)?;
        let required_funding = tp_dispatch::required_funding(method_selector, args)?;
        let selected_coins: Option<NativeCoinSelection> = required_funding
            .map(|required| select_owned_native_coins(object_db, &env.tx_inputs, *caller, required))
            .transpose()?;

        let result = tp_dispatch::dispatch(&dispatch_context, &mut table, method_selector, args)?;
        let refunds = Self::refund_outputs(&result.return_value)?;
        let total_refunds = refunds.iter().try_fold(0u64, |total, (_, amount)| {
            total
                .checked_add(*amount)
                .ok_or_else(|| PokerL1Error::Other("Texas refund sum overflow".into()))
        })?;
        let expected_locked = pre_locked
            .checked_add(required_funding.unwrap_or(0))
            .and_then(|value| value.checked_sub(total_refunds))
            .ok_or_else(|| {
                PokerL1Error::Other("Texas TableVault balance transition overflow".into())
            })?;
        if table.chip_pool != expected_locked {
            return Err(PokerL1Error::Other(format!(
                "Texas TableVault mismatch: pre={pre_locked}, funding={}, refunds={total_refunds}, post={}, expected={expected_locked}",
                required_funding.unwrap_or(0),
                table.chip_pool,
            )));
        }
        reconcile_table_vault(&table)?;

        // Preflight every deterministic output before consuming an input. Normal execution uses
        // WriteCaptureBackend and therefore rolls the complete transaction back on any later
        // error; this preflight also keeps the direct ObjectBackend path fail-before-write.
        let change_output = selected_coins
            .as_ref()
            .and_then(|selection| required_funding.map(|required| (selection, required)))
            .and_then(|(selection, required)| {
                selection
                    .total
                    .checked_sub(required)
                    .filter(|change| *change > 0)
            })
            .map(|change| native_coin_object(*caller, change, coin_output_nonce(&env.tx_hash, 0)))
            .transpose()?;
        if let Some(change) = &change_output {
            if object_db.read(&change.id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(change.id));
            }
        }
        for (index, (player, amount)) in refunds.iter().enumerate() {
            let output_index = u32::try_from(index + 1)
                .map_err(|_| PokerL1Error::Other("too many Texas refund outputs".into()))?;
            let payout = native_coin_object(
                *player,
                *amount,
                coin_output_nonce(&env.tx_hash, output_index),
            )?;
            if object_db.read(&payout.id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(payout.id));
            }
        }

        let mut economic_created = Vec::new();
        if let (Some(selection), Some(required)) = (&selected_coins, required_funding) {
            if let Some(change_id) = consume_native_coin_selection(
                object_db,
                selection,
                *caller,
                required,
                &env.tx_hash,
                0,
            )? {
                economic_created.push(change_id);
            }
        }
        for (index, (player, amount)) in refunds.into_iter().enumerate() {
            let output_index = u32::try_from(index + 1)
                .map_err(|_| PokerL1Error::Other("too many Texas refund outputs".into()))?;
            economic_created.push(create_native_coin_output(
                object_db,
                player,
                amount,
                &env.tx_hash,
                output_index,
            )?);
        }

        // 持久化
        let table_data = borsh::to_vec(&table).map_err(|e| {
            PokerL1Error::Serialization(format!("TexasPokerTable borsh write: {e}"))
        })?;
        if is_new {
            let obj = Object::new(
                table_id,
                Ownership::Shared,
                TEXAS_POKER_TABLE_OBJECT_TYPE,
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
        final_result.created_objects.extend(economic_created);
        final_result
            .read_objects
            .extend(env.tx_inputs.iter().copied());
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
    use blstrs::G1Projective;
    use group::Group;
    use poker_protocol::crypto::ECPoint;

    use crate::economics::{
        coin_output_nonce, decode_native_coin, genesis_mint, list_owned_native_coins,
        native_coin_object, read_treasury,
    };
    use crate::executor::write_capture::WriteCaptureBackend;
    use crate::object_model::Version;
    use crate::signature::TaggedPubkey;
    use crate::vm::contracts::texas_poker::dispatch::{
        AddonArgs, CreateTableArgs, JoinTableArgs, LeaveTableArgs, RebuyArgs,
    };

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
            tx_inputs: vec![],
            tx_hash: [0u8; 32],
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
    fn bet_only_refund_stays_inside_table_vault() {
        let table_id = reserved::texas_poker_contract_id();
        let player = [0x44; 20];
        let output = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
            table_id,
            seat_index: 2,
            player,
            amount: 75,
            refund_type: REFUND_TYPE_BET_ONLY,
        }]);

        let encoded = borsh::to_vec(&output).unwrap();
        assert!(TexasPokerPrecompile::refund_outputs(&encoded)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn stack_refunds_leave_table_vault_but_unknown_types_fail_closed() {
        let table_id = reserved::texas_poker_contract_id();
        let player = [0x55; 20];
        for refund_type in [REFUND_TYPE_STACK_ONLY, REFUND_TYPE_STACK_AND_BET] {
            let output = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
                table_id,
                seat_index: 1,
                player,
                amount: 90,
                refund_type,
            }]);
            let encoded = borsh::to_vec(&output).unwrap();
            assert_eq!(
                TexasPokerPrecompile::refund_outputs(&encoded).unwrap(),
                vec![(player, 90)]
            );
        }

        let unknown = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
            table_id,
            seat_index: 1,
            player,
            amount: 90,
            refund_type: u8::MAX,
        }]);
        let error =
            TexasPokerPrecompile::refund_outputs(&borsh::to_vec(&unknown).unwrap()).unwrap_err();
        assert!(error.to_string().contains("unknown Texas refund type"));
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

    fn create_test_table(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
    ) {
        let args = borsh::to_vec(&CreateTableArgs {
            name: "funded_game".into(),
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
        })
        .unwrap();
        precompile
            .call(
                caller,
                caller_pk,
                &selectors::create_table(),
                &args,
                &make_env(),
                object_db,
            )
            .unwrap();
    }

    fn create_funded_table(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        total_supply: u64,
    ) -> (ObjectDb, ObjectID) {
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut object_db, 1, &[(*caller, total_supply)]).unwrap();
        create_test_table(precompile, caller, caller_pk, &mut object_db);
        let coins = list_owned_native_coins(&object_db, *caller).unwrap();
        assert_eq!(coins.len(), 1);
        (object_db, coins[0].id)
    }

    fn funded_join(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
        input_id: ObjectID,
        buy_in: u64,
        tx_hash: [u8; 32],
    ) -> ObjectID {
        let join_args = borsh::to_vec(&JoinTableArgs {
            player: *caller,
            buy_in,
            pk: ECPoint(G1Projective::identity()),
        })
        .unwrap();
        precompile
            .call(
                caller,
                caller_pk,
                &selectors::join_table(),
                &join_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![input_id],
                    tx_hash,
                    ..make_env()
                },
                object_db,
            )
            .unwrap();
        ObjectID::new(*caller, coin_output_nonce(&tx_hash, 0))
    }

    struct FailTableUpdateBackend<'a> {
        inner: WriteCaptureBackend<'a>,
        table_id: ObjectID,
    }

    impl ObjectBackend for FailTableUpdateBackend<'_> {
        fn create(&mut self, object: Object) -> PokerL1Result<()> {
            self.inner.create(object)
        }

        fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
            self.inner.read(id)
        }

        fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
            self.inner.version_of(id)
        }

        fn update(
            &mut self,
            id: &ObjectID,
            actor: &Address,
            new_data: Vec<u8>,
        ) -> PokerL1Result<()> {
            if id == &self.table_id {
                return Err(PokerL1Error::Other(
                    "injected table persistence failure".into(),
                ));
            }
            self.inner.update(id, actor, new_data)
        }

        fn transfer(
            &mut self,
            id: &ObjectID,
            actor: &Address,
            new_owner: Address,
        ) -> PokerL1Result<()> {
            self.inner.transfer(id, actor, new_owner)
        }

        fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
            self.inner.delete(id)
        }

        fn replace_objects(
            &mut self,
            delete_ids: &[ObjectID],
            create_objects: Vec<Object>,
        ) -> PokerL1Result<()> {
            self.inner.replace_objects(delete_ids, create_objects)
        }

        fn state_root(&self) -> crate::Hash {
            self.inner.state_root()
        }
    }

    #[test]
    fn funded_join_creates_change_and_leave_creates_payout() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        create_test_table(&precompile, &caller, &caller_pk, &mut object_db);

        let input = native_coin_object(caller, 150, 77).unwrap();
        object_db.create(input.clone()).unwrap();
        let join_hash = [0x11; 32];
        let join_env = ExecutionEnvironment {
            tx_inputs: vec![input.id],
            tx_hash: join_hash,
            ..make_env()
        };
        let join_args = borsh::to_vec(&JoinTableArgs {
            player: caller,
            buy_in: 100,
            pk: ECPoint(G1Projective::identity()),
        })
        .unwrap();

        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::join_table(),
                &join_args,
                &join_env,
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&input.id).is_err());
        let change_id = ObjectID::new(caller, coin_output_nonce(&join_hash, 0));
        assert!(result.created_objects.contains(&change_id));
        assert_eq!(
            decode_native_coin(&object_db.read(&change_id).unwrap())
                .unwrap()
                .amount,
            50
        );
        let table_id = reserved::texas_poker_contract_id();
        let table: TexasPokerTable =
            borsh::from_slice(&object_db.read(&table_id).unwrap().data).unwrap();
        assert_eq!(table.chip_pool, 100);
        assert_eq!(table.seats[0].stack, 100);

        let leave_hash = [0x22; 32];
        let leave_env = ExecutionEnvironment {
            tx_hash: leave_hash,
            ..make_env()
        };
        let leave_args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::leave_table(),
                &leave_args,
                &leave_env,
                &mut object_db,
            )
            .unwrap();

        let payout_id = ObjectID::new(caller, coin_output_nonce(&leave_hash, 1));
        assert!(result.created_objects.contains(&payout_id));
        assert_eq!(
            decode_native_coin(&object_db.read(&payout_id).unwrap())
                .unwrap()
                .amount,
            100
        );
        let table: TexasPokerTable =
            borsh::from_slice(&object_db.read(&table_id).unwrap().data).unwrap();
        assert_eq!(table.chip_pool, 0);
        assert!(!table.seats[0].is_occupied());
    }

    #[test]
    fn funded_join_without_coin_input_is_rejected_without_table_mutation() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        create_test_table(&precompile, &caller, &caller_pk, &mut object_db);
        let table_id = reserved::texas_poker_contract_id();
        let table_before = object_db.read(&table_id).unwrap();
        let join_args = borsh::to_vec(&JoinTableArgs {
            player: caller,
            buy_in: 100,
            pk: ECPoint(G1Projective::identity()),
        })
        .unwrap();

        let error = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::join_table(),
                &join_args,
                &make_env(),
                &mut object_db,
            )
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("requires at least one native coin input"));
        assert_eq!(object_db.read(&table_id).unwrap(), table_before);
    }

    #[test]
    fn funded_addon_consumes_input_creates_change_and_updates_all_vaults() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x31; 32],
        );
        let treasury_before = read_treasury(&object_db).unwrap();

        let addon_hash = [0x32; 32];
        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::addon(),
                &addon_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: addon_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&join_change).is_err());
        let addon_change = ObjectID::new(caller, coin_output_nonce(&addon_hash, 0));
        assert!(result.created_objects.contains(&addon_change));
        assert_eq!(
            decode_native_coin(&object_db.read(&addon_change).unwrap())
                .unwrap()
                .amount,
            140
        );
        let table: TexasPokerTable = borsh::from_slice(
            &object_db
                .read(&reserved::texas_poker_contract_id())
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(table.seats[0].stack, 100);
        assert_eq!(table.seats[0].pending_addon, 60);
        assert_eq!(table.chip_pool, 160);
        assert_eq!(table.addon_pool, 60);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
    }

    #[test]
    fn funded_rebuy_consumes_input_creates_change_and_preserves_addon_pool() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x41; 32],
        );
        let treasury_before = read_treasury(&object_db).unwrap();

        let rebuy_hash = [0x42; 32];
        let rebuy_args = borsh::to_vec(&RebuyArgs {
            seat_index: 0,
            amount: 70,
        })
        .unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::rebuy(),
                &rebuy_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: rebuy_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&join_change).is_err());
        let rebuy_change = ObjectID::new(caller, coin_output_nonce(&rebuy_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&rebuy_change).unwrap())
                .unwrap()
                .amount,
            130
        );
        let table: TexasPokerTable = borsh::from_slice(
            &object_db
                .read(&reserved::texas_poker_contract_id())
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(table.seats[0].stack, 170);
        assert_eq!(table.seats[0].pending_addon, 0);
        assert_eq!(table.chip_pool, 170);
        assert_eq!(table.addon_pool, 0);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
    }

    #[test]
    fn leave_after_pending_addon_refunds_stack_and_pending_addon() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x51; 32],
        );
        let addon_hash = [0x52; 32];
        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::addon(),
                &addon_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: addon_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let leave_hash = [0x53; 32];
        let leave_args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::leave_table(),
                &leave_args,
                &ExecutionEnvironment {
                    tx_hash: leave_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let payout_id = ObjectID::new(caller, coin_output_nonce(&leave_hash, 1));
        assert_eq!(
            decode_native_coin(&object_db.read(&payout_id).unwrap())
                .unwrap()
                .amount,
            160
        );
        let addon_change = ObjectID::new(caller, coin_output_nonce(&addon_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&addon_change).unwrap())
                .unwrap()
                .amount,
            140
        );
        let table: TexasPokerTable = borsh::from_slice(
            &object_db
                .read(&reserved::texas_poker_contract_id())
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(table.chip_pool, 0);
        assert_eq!(table.addon_pool, 0);
        assert!(!table.seats[0].is_occupied());
        assert_eq!(
            read_treasury(&object_db).unwrap().unwrap().total_supply,
            300
        );
    }

    #[test]
    fn funded_addon_failure_discards_table_coin_treasury_and_root_changes() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x61; 32],
        );
        let table_id = reserved::texas_poker_contract_id();
        let table_before = object_db.read(&table_id).unwrap();
        let input_before = object_db.read(&join_change).unwrap();
        let treasury_before = read_treasury(&object_db).unwrap();
        let root_before = object_db.state_root();

        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        let error = {
            let mut backend = FailTableUpdateBackend {
                inner: WriteCaptureBackend::new(&object_db),
                table_id,
            };
            precompile
                .call(
                    &caller,
                    &caller_pk,
                    &selectors::addon(),
                    &addon_args,
                    &ExecutionEnvironment {
                        tx_inputs: vec![join_change],
                        tx_hash: [0x62; 32],
                        ..make_env()
                    },
                    &mut backend,
                )
                .unwrap_err()
        };

        assert!(error
            .to_string()
            .contains("injected table persistence failure"));
        assert_eq!(object_db.read(&table_id).unwrap(), table_before);
        assert_eq!(object_db.read(&join_change).unwrap(), input_before);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
        assert_eq!(object_db.state_root(), root_before);
        let discarded_change = ObjectID::new(caller, coin_output_nonce(&[0x62; 32], 0));
        assert!(object_db.read(&discarded_change).is_err());
    }
}
