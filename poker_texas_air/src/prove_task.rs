//! 证明任务（Prove Task）— Post-commit Prover 的数据契约。
//!
//! ## 角色
//!
//! 合约执行层（`poker_l1` dispatch）每次成功执行一个 method 后，产出一个
//! [`ProveTask`]，序列化进 `DispatchResult.return_value`（与 events 一起）。
//! 链下 Orchestrator（[`crate::orchestrator`]）消费任务队列，为每个任务
//! 生成 method proof，并可立即封装为单方法 recursive STWO proof。最终 application-aware
//! verifier 不接收 inner method proof；批量 final aggregate proof 仍未完成。
//!
//! ## 设计原则
//!
//! - **不阻塞执行**：合约层只记录任务，不生成 proof（prove 是重计算，异步做）
//! - **依赖方向保持 air → l1**：本模块只定义数据结构，由 Orchestrator 消费；
//!   合约层填充任务时依赖此结构（通过 `poker_texas_air` crate），但这只在
//!   测试/PoC 场景；生产中合约层用一个等价的纯数据结构，Orchestrator 反序列化
//! - **pre/post table 快照**：Orchestrator 从两个快照算 pre/post state_root，
//!   无需合约层暴露 state_root 计算逻辑
//!
//! ## 与 DispatchResult.return_value 的关系
//!
//! `return_value` = borsh([`DispatchOutput`])，其中 `DispatchOutput` 含
//! `events` + `prove_task`。旧格式（仅 events）通过版本前缀区分。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

// MethodInput remains a transient decoded view. It is no longer persisted in ProveTask.
pub use vm_common::prove_task::MethodInput;

use crate::method_kind::MethodKind;

/// Domain-separated digest of the exact VM dispatch call carried by a task.
///
/// The digest commits to the task-carried dispatch context, selector, and raw
/// Borsh arguments. Method proofs mix it into Fiat-Shamir public inputs so a
/// receipt cannot be detached from the VM call replayed by the host. The digest
/// does not by itself authenticate that the task came from a consensus block.
pub fn dispatch_call_digest(
    context: &poker_l1::vm::contracts::dispatch::DispatchContext,
    selector: &[u8; 32],
    raw_args: &[u8],
) -> crate::error::TexasAirResult<[u8; 32]> {
    let (method_tag, canonical_args) =
        poker_l1::vm::contracts::texas_poker::dispatch::canonical_command_parts(selector, raw_args)
            .map_err(|error| {
                crate::error::TexasAirError::SerializationError(format!(
                    "canonical dispatch command: {error}"
                ))
            })?;
    let encoded = borsh::to_vec(&(context.clone(), method_tag, canonical_args)).map_err(|e| {
        crate::error::TexasAirError::SerializationError(format!("dispatch call context borsh: {e}"))
    })?;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.texas_poker.dispatch_call.v2");
    hasher.update(&encoded);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    Ok(digest)
}

/// 单次 method 调用的证明任务。
///
/// 合约执行成功后产出，Orchestrator 据此生成一个 method proof。
#[derive(Debug, Clone)]
pub struct ProveTask {
    /// 方法种类（选 AIR）。
    pub method_kind: MethodKind,
    /// VM dispatch 记录的完整调用上下文。
    ///
    /// Orchestrator 会据此重放权限和业务逻辑，但不会独立证明该上下文已被交易层或
    /// 共识层认证；生产调用方必须通过外部 block/receipt 锚提供来源保证。
    pub context: poker_l1::vm::contracts::dispatch::DispatchContext,
    /// Canonical Borsh command payload selected by `method_kind`.
    ///
    /// Selector and typed [`MethodInput`] are derived views and are deliberately not stored.
    pub raw_args: Vec<u8>,
    /// 调用前表台快照（算 pre_state_root + 派生 pre 字段）。
    pub pre_table: poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    /// 调用后表台快照（算 post_state_root + 派生 post 字段）。
    pub post_table: poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    /// 表台 ID（公开输入，防跨表台聚合攻击）。
    pub table_id: u64,
    /// 手牌序号（同一 table 内递增）。
    pub hand_id: u32,
    /// 方法调用序号（同一 hand 内递增，Aggregator 据此排序）。
    pub call_seq: u32,
}

impl ProveTask {
    /// 构造新的证明任务。
    #[must_use]
    pub fn new(
        method_kind: MethodKind,
        context: poker_l1::vm::contracts::dispatch::DispatchContext,
        raw_args: Vec<u8>,
        pre_table: poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        post_table: poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        poker_l1::vm::contracts::texas_poker::dispatch::derive_method_input(
            method_kind as u8,
            &raw_args,
        )
        .expect("ProveTask requires a validated canonical command");
        Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        }
    }

    /// Selector deterministically derived from the canonical command tag.
    #[must_use]
    pub fn selector(&self) -> [u8; 32] {
        self.method_kind.selector()
    }

    /// Decode the transient typed input from the only persisted command payload.
    pub fn method_input(&self) -> crate::error::TexasAirResult<MethodInput> {
        poker_l1::vm::contracts::texas_poker::dispatch::derive_method_input(
            self.method_kind as u8,
            &self.raw_args,
        )
        .map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "canonical command input decode failed: {error}"
            ))
        })
    }

    /// Stable bytes committed by method and batch proofs.
    pub fn canonical_command_bytes(&self) -> crate::error::TexasAirResult<Vec<u8>> {
        borsh::to_vec(&(self.method_kind as u8, self.raw_args.clone())).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "canonical command borsh encoding failed: {error}"
            ))
        })
    }
}

impl BorshSerialize for ProveTask {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.method_kind.serialize(writer)?;
        self.context.serialize(writer)?;
        self.raw_args.serialize(writer)?;
        self.pre_table.serialize(writer)?;
        self.post_table.serialize(writer)?;
        self.table_id.serialize(writer)?;
        self.hand_id.serialize(writer)?;
        self.call_seq.serialize(writer)
    }
}

impl BorshDeserialize for ProveTask {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let method_kind = MethodKind::deserialize_reader(reader)?;
        let context =
            poker_l1::vm::contracts::dispatch::DispatchContext::deserialize_reader(reader)?;
        let raw_args = Vec::<u8>::deserialize_reader(reader)?;
        let pre_table =
            poker_l1::vm::contracts::texas_poker::types::TexasPokerTable::deserialize_reader(
                reader,
            )?;
        let post_table =
            poker_l1::vm::contracts::texas_poker::types::TexasPokerTable::deserialize_reader(
                reader,
            )?;
        let table_id = u64::deserialize_reader(reader)?;
        let hand_id = u32::deserialize_reader(reader)?;
        let call_seq = u32::deserialize_reader(reader)?;
        poker_l1::vm::contracts::texas_poker::dispatch::derive_method_input(
            method_kind as u8,
            &raw_args,
        )
        .map_err(|error| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error.to_string())
        })?;
        Ok(Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        })
    }
}

/// dispatch 输出结构（return_value 的新格式）。
///
/// 包含 state_machine 产生的 events + 证明任务。
/// Orchestrator 从链层取回 return_value 后反序列化此结构。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DispatchOutput {
    /// 事件日志（40 种 TexasPokerEvent）。
    pub events: Vec<poker_l1::vm::contracts::texas_poker::events::TexasPokerEvent>,
    /// 证明任务（None 表示此次 dispatch 无需证明，如 tick 无状态变更时）。
    pub prove_task: Option<ProveTask>,
}

impl DispatchOutput {
    /// 仅含 events（无证明任务）的便捷构造。
    #[must_use]
    pub fn events_only(
        events: Vec<poker_l1::vm::contracts::texas_poker::events::TexasPokerEvent>,
    ) -> Self {
        Self {
            events,
            prove_task: None,
        }
    }

    /// 含 events + 证明任务的构造。
    #[must_use]
    pub fn with_task(
        events: Vec<poker_l1::vm::contracts::texas_poker::events::TexasPokerEvent>,
        prove_task: ProveTask,
    ) -> Self {
        Self {
            events,
            prove_task: Some(prove_task),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::vm::contracts::dispatch::DispatchContext;
    use poker_l1::vm::contracts::texas_poker::dispatch::{CreateTableArgs, SeatIndexArgs};

    fn dummy_table(name: &str) -> poker_l1::vm::contracts::texas_poker::types::TexasPokerTable {
        use poker_l1::object_model::ObjectID;
        poker_l1::vm::contracts::texas_poker::types::TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            name.into(),
            [0u8; 20],
            6,
            50,
            100,
        )
    }

    fn dummy_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    #[test]
    fn prove_task_borsh_roundtrip() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 2 }).unwrap(),
            dummy_table("pre"),
            dummy_table("post"),
            42,
            1,
            3,
        );
        let bytes = borsh::to_vec(&task).unwrap();
        let recovered: ProveTask = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.method_kind, MethodKind::Fold);
        assert_eq!(recovered.table_id, 42);
        assert_eq!(recovered.hand_id, 1);
        assert_eq!(recovered.call_seq, 3);
        match recovered.method_input().unwrap() {
            MethodInput::SeatOnly { seat_index } => assert_eq!(seat_index, 2),
            other => panic!("expected SeatOnly, got {other:?}"),
        }
    }

    #[test]
    fn command_views_are_derived_from_the_canonical_payload() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 2 }).unwrap(),
            dummy_table("pre"),
            dummy_table("post"),
            42,
            1,
            3,
        );
        let canonical = borsh::to_vec(&task).unwrap();
        let recovered: ProveTask = borsh::from_slice(&canonical).unwrap();
        assert_eq!(recovered.selector(), MethodKind::Fold.selector());
        assert_eq!(
            recovered.method_input().unwrap(),
            MethodInput::SeatOnly { seat_index: 2 }
        );
        assert_eq!(
            recovered.canonical_command_bytes().unwrap(),
            task.canonical_command_bytes().unwrap()
        );
    }

    #[test]
    fn malformed_canonical_payload_fails_deserialization() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 2 }).unwrap(),
            dummy_table("pre"),
            dummy_table("post"),
            42,
            1,
            3,
        );
        let mut malformed = task;
        malformed.raw_args.clear();
        let bytes = borsh::to_vec(&malformed).unwrap();
        assert!(borsh::from_slice::<ProveTask>(&bytes).is_err());
    }

    #[test]
    fn dispatch_digest_normalizes_legacy_tick_timestamp() {
        use poker_l1::vm::contracts::texas_poker::dispatch::{TickArgs, selectors};

        let context = dummy_context();
        let empty = dispatch_call_digest(&context, &selectors::tick(), &[]).unwrap();
        let legacy = dispatch_call_digest(
            &context,
            &selectors::tick(),
            &borsh::to_vec(&TickArgs {
                now_ms: context.block_timestamp,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(empty, legacy);
    }

    #[test]
    fn dispatch_output_borsh_roundtrip() {
        let out = DispatchOutput::events_only(vec![]);
        let bytes = borsh::to_vec(&out).unwrap();
        let recovered: DispatchOutput = borsh::from_slice(&bytes).unwrap();
        assert!(recovered.events.is_empty());
        assert!(recovered.prove_task.is_none());

        let task = ProveTask::new(
            MethodKind::CreateTable,
            dummy_context(),
            borsh::to_vec(&CreateTableArgs {
                name: "t".into(),
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
            })
            .unwrap(),
            dummy_table("pre"),
            dummy_table("post"),
            1,
            0,
            0,
        );
        let out2 = DispatchOutput::with_task(vec![], task);
        let bytes2 = borsh::to_vec(&out2).unwrap();
        let recovered2: DispatchOutput = borsh::from_slice(&bytes2).unwrap();
        assert!(recovered2.prove_task.is_some());
    }
}
