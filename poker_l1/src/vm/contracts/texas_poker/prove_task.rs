//! L1 证明任务 — dispatch 层产出，Orchestrator（poker_texas_air）消费。
//!
//! ## 角色
//!
//! `dispatch` 主函数执行成功后，构造 [`L1ProveTask`]（含 pre/post table 快照 +
//! method 元数据），与 events 一起封装进 [`L1DispatchOutput`]，borsh 序列化
//! 为 `DispatchResult.return_value`。
//!
//! 链下 Orchestrator 从链层取回 return_value，反序列化为
//! `poker_texas_air::prove_task::DispatchOutput`（两者 borsh 二进制兼容），
//! 据此生成 method proof。
//!
//! ## borsh 兼容性
//!
//! 本模块的类型与 `poker_texas_air::prove_task` 的对应类型字段对齐：
//! - `TexasPokerTable` / `TexasPokerEvent` 都是 poker_l1 类型，两端可见同一类型
//! - `MethodInput` 共享自 `vm-common`
//! - `method_kind: u8` ↔ `poker_texas_air::MethodKind`（`use_discriminant=true`，
//!   单字节 borsh 布局一致）
//!
//! ## 与 poker_texas_air 的关系
//!
//! poker_l1 **不依赖** poker_texas_air（依赖方向是 air → l1）。本模块是 poker_l1
//! 侧的等价定义，通过 borsh 字节流与 Orchestrator 解耦。

use borsh::{BorshDeserialize, BorshSerialize};

// MethodInput 共享自 vm-common（poker_l1 与 poker_texas_air 的 borsh 契约边界）。
pub use vm_common::prove_task::MethodInput;

use super::events::TexasPokerEvent;
use super::types::TexasPokerTable;
use crate::vm::contracts::dispatch::DispatchContext;

/// 单次 method 调用的证明任务（L1 侧定义）。
///
/// borsh 布局与 `poker_texas_air::prove_task::ProveTask` 完全一致。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L1ProveTask {
    /// 方法种类（u8 discriminant，与 poker_texas_air::MethodKind 兼容）。
    pub method_kind: u8,
    /// 方法业务输入（共享自 vm-common）。
    pub method_input: MethodInput,
    /// 执行该调用时经过交易层认证的完整 dispatch 上下文。
    pub context: DispatchContext,
    /// VM 实际路由的原始 selector。
    pub selector: [u8; 32],
    /// VM 实际解码和执行的原始 Borsh 参数。
    pub raw_args: Vec<u8>,
    /// 调用前表台快照。
    pub pre_table: TexasPokerTable,
    /// 调用后表台快照。
    pub post_table: TexasPokerTable,
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 方法调用序号。
    pub call_seq: u32,
}

impl L1ProveTask {
    /// 构造新的证明任务。
    #[must_use]
    pub fn new(
        method_kind: u8,
        method_input: MethodInput,
        context: DispatchContext,
        selector: [u8; 32],
        raw_args: Vec<u8>,
        pre_table: TexasPokerTable,
        post_table: TexasPokerTable,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        Self {
            method_kind,
            method_input,
            context,
            selector,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        }
    }
}

/// dispatch 输出结构（return_value 的格式）。
///
/// borsh 布局与 `poker_texas_air::prove_task::DispatchOutput` 完全一致。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L1DispatchOutput {
    /// 事件日志。
    pub events: Vec<TexasPokerEvent>,
    /// 证明任务（None 表示此次 dispatch 无需证明）。
    pub prove_task: Option<L1ProveTask>,
}

impl L1DispatchOutput {
    /// 仅含 events（无证明任务）的便捷构造。
    #[must_use]
    pub fn events_only(events: Vec<TexasPokerEvent>) -> Self {
        Self {
            events,
            prove_task: None,
        }
    }

    /// 含 events + 证明任务的构造。
    #[must_use]
    pub fn with_task(events: Vec<TexasPokerEvent>, prove_task: L1ProveTask) -> Self {
        Self {
            events,
            prove_task: Some(prove_task),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;

    fn dummy_table(name: &str) -> TexasPokerTable {
        TexasPokerTable::new(
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
                tag: 0x11,
                raw: vec![0xBB; 32],
            },
            chain_id: 7,
            block_height: 11,
            block_timestamp: 13,
        }
    }

    #[test]
    fn l1_prove_task_borsh_roundtrip() {
        let task = L1ProveTask::new(
            6, // MethodKind::Fold = 6
            MethodInput::SeatOnly { seat_index: 2 },
            dummy_context(),
            [0xCC; 32],
            vec![2],
            dummy_table("pre"),
            dummy_table("post"),
            42,
            1,
            3,
        );
        let bytes = borsh::to_vec(&task).unwrap();
        let recovered: L1ProveTask = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.method_kind, 6);
        assert_eq!(recovered.table_id, 42);
        assert_eq!(
            recovered.method_input,
            MethodInput::SeatOnly { seat_index: 2 }
        );
        assert_eq!(recovered.context, dummy_context());
        assert_eq!(recovered.selector, [0xCC; 32]);
        assert_eq!(recovered.raw_args, vec![2]);
    }
}
