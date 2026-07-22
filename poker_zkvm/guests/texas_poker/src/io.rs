//! ZKVM guest 输入/输出格式（Phase 4.4）。
//!
//! # 模型：无状态 ZK 状态转换（Stateless ZK State Transition）
//!
//! Guest 不持有任何持久状态。每次调用接收完整的桌台状态 + 一个方法调用，
//! 执行后返回更新后的桌台状态 + 事件。Host（L1）负责持久化 `ZkvmOutput.table`，
//! 并在下一笔交易时将其作为 `ZkvmInput.table` 重新传入。
//!
//! # 输入格式
//!
//! 由 `guest_sdk::entry::zkvm_entry()` 解析掉 4 字节 LE 长度前缀后，
//! `zkvm_main(input: &[u8])` 收到的 `input` 为 `ZkvmInput` 的 borsh 序列化字节。
//!
//! ```text
//! ZkvmInput {
//!     table:           TexasPokerTable,   // 当前桌台状态（create_table 时可传最小占位）
//!     context:         DispatchContext,    // 调用者 + block 信息
//!     method_selector: [u8; 32],          // blake2b_256(method_name)
//!     args:            Vec<u8>,            // 对应 method 的 *Args borsh 序列化
//! }
//! ```
//!
//! # 输出格式
//!
//! `zkvm_main` 返回 `Ok(Vec<u8>)`，为 `ZkvmOutput` 的 borsh 序列化字节，
//! 由 `commit_output` 写出。失败时返回 `Err(&'static str)` → `panic_msg` 终止。
//!
//! ```text
//! ZkvmOutput {
//!     table:            TexasPokerTable,   // 更新后的桌台状态
//!     events:           Vec<TexasPokerEvent>, // 本次 dispatch 收集的事件
//!     modified_objects: Vec<ObjectID>,      // 被修改的 object ID 列表
//! }
//! ```
//!
//! # 特殊情况
//!
//! - **空输入**：`input.is_empty()` 时返回 `[0x42]`（Phase 1 health check 向后兼容）
//! - **反序列化失败**：返回 `Err("invalid input")` → guest panic
//! - **dispatch 失败**：返回 `Err("dispatch error: ...")` → guest panic

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use super::dispatch::{self, DispatchContext, DispatchError};
use super::events::TexasPokerEvent;
use super::types::{
    DeckState, ObjectID, ReconstructState, RevealAssignment, RevealTokenState, Seat,
    ShuffleState, TableConfig, TexasPokerTable, TimeoutConfig, Timestamps,
};
use super::card::Card;
use super::betting::BettingRound;
use super::side_pot::SidePot;

// ========== 输入/输出结构 ==========

/// ZKVM guest 输入（borsh 序列化传入）。
///
/// 注意：`BorshDeserialize` 为**手动实现**（非 derive），与 `TexasPokerTable` 同理。
/// 派生宏会将 `TexasPokerTable` 字段的 `deserialize_reader` 深度内联到
/// `ZkvmInput::deserialize_reader` 中，触发 RV32I codegen panic。
/// 手动覆盖 `deserialize(buf: &mut &[u8])` 保持每个字段反序列化为独立函数调用。
#[derive(Debug, Clone, BorshSerialize)]
pub struct ZkvmInput {
    /// 当前桌台状态（create_table 时仅 `id` 字段被使用，其余被覆写）。
    pub table: TexasPokerTable,
    /// 调用上下文（caller + block 信息）。
    pub context: DispatchContext,
    /// 方法选择器（`blake2b_256(method_name)`）。
    pub method_selector: [u8; 32],
    /// 方法参数（对应 `*Args` 的 borsh 序列化）。
    pub args: Vec<u8>,
}

impl BorshDeserialize for ZkvmInput {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::io::Error> {
        // 逐字段调用 deserialize。TexasPokerTable::deserialize 已手动覆盖，
        // 会逐字段调用其 22 个字段的 deserialize——全部为独立函数调用（非 #[inline]），
        // 避免 RV32I 上的深度内联 panic。
        Ok(Self {
            table: <TexasPokerTable as BorshDeserialize>::deserialize(buf)?,
            context: <DispatchContext as BorshDeserialize>::deserialize(buf)?,
            method_selector: <[u8; 32] as BorshDeserialize>::deserialize(buf)?,
            args: <Vec<u8> as BorshDeserialize>::deserialize(buf)?,
        })
    }

    fn deserialize_reader<R: borsh::io::Read>(
        reader: &mut R,
    ) -> Result<Self, borsh::io::Error> {
        // 将所有剩余字节读入 Vec，再委托给 deserialize。
        // 这是 ZkvmInput 作为顶层反序列化入口时的路径（entry.rs → zkvm_main →
        // ZkvmInput::try_from_slice → deserialize_reader → read_to_end → deserialize）。
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
        let mut slice: &[u8] = &buf;
        Self::deserialize(&mut slice)
    }
}

/// ZKVM guest 输出（borsh 序列化返回）。
///
/// 注意：`BorshDeserialize` 为**手动实现**（非 derive），与 `ZkvmInput` 同理。
#[derive(Debug, Clone, BorshSerialize)]
pub struct ZkvmOutput {
    /// 更新后的桌台状态。
    pub table: TexasPokerTable,
    /// 本次 dispatch 收集的所有事件（供 host 索引/emit）。
    pub events: Vec<TexasPokerEvent>,
    /// 被修改的 object ID 列表。
    pub modified_objects: Vec<ObjectID>,
}

impl BorshDeserialize for ZkvmOutput {
    fn deserialize(buf: &mut &[u8]) -> Result<Self, borsh::io::Error> {
        Ok(Self {
            table: <TexasPokerTable as BorshDeserialize>::deserialize(buf)?,
            events: <Vec<TexasPokerEvent> as BorshDeserialize>::deserialize(buf)?,
            modified_objects: <Vec<ObjectID> as BorshDeserialize>::deserialize(buf)?,
        })
    }

    fn deserialize_reader<R: borsh::io::Read>(
        reader: &mut R,
    ) -> Result<Self, borsh::io::Error> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
        let mut slice: &[u8] = &buf;
        Self::deserialize(&mut slice)
    }
}

// ========== 错误转字符串 ==========

/// 将 `DispatchError` 转为 `&'static str` 不太可行（含动态 String），
/// 这里用静态分类标签。Guest panic 时 host 看到 `zkvm_panic: guest error`。
///
/// 实际上 `zkvm_main` 返回 `Err(&'static str)` 后 entry.rs 调用 `panic_msg("guest error")`，
/// 所以动态错误详情在 guest 内部用 `format!` 拼接后**只能丢弃**（no_std 无 stderr 打印）。
/// 但为了让 std-test 能断言错误类型，我们用枚举标签而非 String。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkvmErrorKind {
    /// 空 input（不应发生，entry.rs 已过滤）。
    EmptyInput,
    /// 输入 borsh 反序列化失败。
    InvalidInput,
    /// dispatch 返回错误（细分见 `DispatchError`）。
    Dispatch(DispatchError),
    /// 输出 borsh 序列化失败。
    OutputSerialize,
}

impl ZkvmErrorKind {
    /// 转为静态错误消息（供 `zkvm_main` 返回 `Err(&'static str)`）。
    #[must_use]
    pub fn as_static_str(&self) -> &'static str {
        match self {
            Self::EmptyInput => "zkvm: empty input",
            Self::InvalidInput => "zkvm: invalid input (borsh decode failed)",
            Self::Dispatch(_) => "zkvm: dispatch error",
            Self::OutputSerialize => "zkvm: output serialize failed",
        }
    }
}

// ========== zkvm_main 核心逻辑 ==========

/// zkvm_main 核心逻辑（不直接返回 `&'static str`，返回 `ZkvmErrorKind` 便于测试）。
///
/// 入口：
/// - 空 input → `Err(ZkvmErrorKind::EmptyInput)`
/// - 否则 borsh 解码 `ZkvmInput` → dispatch → 序列化 `ZkvmOutput`
///
/// # RV32I sret codegen workaround
///
/// 不使用 `BorshDeserialize::deserialize` 反序列化 `TexasPokerTable` / `ZkvmInput`
/// （返回 `Result<LargeType, Error>` 通过 sret，在 RV32I 上触发
/// `uninitialized read` / `unaligned access`）。
/// 改用 `TexasPokerTable::deserialize_into`（out-param 模式，返回 `Result<(), Error>`
/// 无 sret），并直接内联 `DispatchContext` / `[u8; 32]` / `Vec<u8>` 的反序列化。
pub fn zkvm_main_logic(input: &[u8]) -> Result<Vec<u8>, ZkvmErrorKind> {
    if input.is_empty() {
        return Err(ZkvmErrorKind::EmptyInput);
    }

    let mut buf: &[u8] = input;

    // ===== RV32I sret codegen workaround =====
    //
    // 不能使用 `BorshDeserialize::deserialize` 或 `deserialize_into` 来反序列化
    // `TexasPokerTable`：
    // - `deserialize` 返回 `Result<TexasPokerTable, Error>`（~500 字节 sret）→
    //   sret 指针被设为 NULL → `uninitialized read`
    // - `deserialize_into`（`&mut self` + sret call）→ `self` 指针被 sret
    //   设置覆盖 → `compressed instruction` / `uninitialized read`
    //
    // M6 诊断证明：将 22 个字段直接反序列化为**局部变量**（而非 `self.field`），
    // 然后用结构体字面量构造 `TexasPokerTable`，在 RV32I 上工作正常。
    // 局部变量通过 `sp + offset` 访问（不受 sret 指针影响），而 `self.field`
    // 通过 `self_ptr + offset` 访问（`self_ptr` 可能被 sret 设置覆盖）。
    let id = <ObjectID as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let name = <String as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let max_players = <u8 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let small_blind = <u64 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let big_blind = <u64 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let seats = <Vec<Seat> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let button = <u8 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let pot = <u64 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let side_pots = <Vec<SidePot> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let community_cards = <Vec<Card> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let round_state = <u8 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let betting_round = <Option<BettingRound> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let current_turn = <Option<u8> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let deck_state = <DeckState as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let shuffle_state = <ShuffleState as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    // field 16: reveal_token_state 内联（不调用 <RevealTokenState>::deserialize）
    let reveal_phase = <u8 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let reveal_assignments = <Vec<RevealAssignment> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let reconstruct_state = <ReconstructState as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let timeout_config = <TimeoutConfig as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let timestamps = <Timestamps as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let chip_pool = <u64 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let config = <TableConfig as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let version = <u64 as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;

    // 结构体字面量构造（无 sret — 纯栈写入）
    let mut table = TexasPokerTable {
        id,
        name,
        max_players,
        small_blind,
        big_blind,
        seats,
        button,
        pot,
        side_pots,
        community_cards,
        round_state,
        betting_round,
        current_turn,
        deck_state,
        shuffle_state,
        reveal_token_state: RevealTokenState {
            reveal_phase,
            assignments: reveal_assignments,
        },
        reconstruct_state,
        timeout_config,
        timestamps,
        chip_pool,
        config,
        version,
    };

    // DispatchContext（44 字节）、[u8; 32]、Vec<u8> 均为小类型
    let context = <DispatchContext as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let method_selector = <[u8; 32] as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;
    let args = <Vec<u8> as BorshDeserialize>::deserialize(&mut buf)
        .map_err(|_| ZkvmErrorKind::InvalidInput)?;

    // dispatch — events 作为 out-parameter 传入（避免 sret）
    let mut events: Vec<TexasPokerEvent> = Vec::new();
    dispatch::dispatch(&context, &mut table, &method_selector, &args, &mut events)
        .map_err(|e| ZkvmErrorKind::Dispatch(*e))?;

    let modified_objects = vec![table.id];
    let output = ZkvmOutput {
        table,
        events,
        modified_objects,
    };

    borsh::to_vec(&output).map_err(|_| ZkvmErrorKind::OutputSerialize)
}

// ========== 测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::dispatch::{selectors, CreateTableArgs, DispatchError};
    use super::super::types::Address;

    /// 构造测试用 DispatchContext。
    fn make_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_700_000_000_000,
        }
    }

    /// 构造测试用桌台（最小有效参数）。
    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new([0x42; 32], "test".into(), 6, 25, 50)
    }

    #[test]
    fn zkvm_main_empty_input_returns_empty_input_error() {
        let result = zkvm_main_logic(&[]);
        assert_eq!(result, Err(ZkvmErrorKind::EmptyInput));
    }

    #[test]
    fn zkvm_main_invalid_borsh_returns_invalid_input_error() {
        // 随机垃圾字节，不是合法 borsh
        let garbage = [0xFFu8; 16];
        let result = zkvm_main_logic(&garbage);
        assert_eq!(result, Err(ZkvmErrorKind::InvalidInput));
    }

    #[test]
    fn zkvm_main_unknown_selector_returns_unknown_method_error() {
        let input = ZkvmInput {
            table: make_table(),
            context: make_context(),
            method_selector: [0xFF; 32], // 不匹配任何已知 selector
            args: vec![],
        };
        let input_bytes = borsh::to_vec(&input).unwrap();
        let result = zkvm_main_logic(&input_bytes);
        match result {
            Err(ZkvmErrorKind::Dispatch(DispatchError::UnknownMethod { selector })) => {
                assert_eq!(selector, [0xFF; 32]);
            }
            other => panic!("期望 UnknownMethod 错误，实际: {other:?}"),
        }
    }

    #[test]
    fn zkvm_main_create_table_roundtrip() {
        // 构造 create_table 输入
        let args = CreateTableArgs {
            name: "my_table".into(),
            max_players: 9,
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let input = ZkvmInput {
            table: make_table(), // create_table 仅读 id，其余被覆写
            context: make_context(),
            method_selector: selectors::create_table(),
            args: args_bytes,
        };
        let input_bytes = borsh::to_vec(&input).unwrap();

        // 执行
        let output_bytes = zkvm_main_logic(&input_bytes).expect("create_table 应成功");
        let output: ZkvmOutput =
            BorshDeserialize::try_from_slice(&output_bytes).expect("输出应可反序列化");

        // 验证更新后的桌台
        assert_eq!(output.table.name, "my_table");
        assert_eq!(output.table.max_players, 9);
        assert_eq!(output.table.small_blind, 25);
        assert_eq!(output.table.big_blind, 50);
        assert_eq!(output.table.id, [0x42; 32], "id 应保留自输入");
        assert_eq!(
            output.table.version, 1,
            "create_table 后 version 应为 1（bump_version 调用一次）"
        );
        assert_eq!(output.table.seats.len(), 9);
        assert!(
            output.table.seats.iter().all(|s| s.player == [0u8; 20]),
            "所有座位应为空"
        );

        // 验证事件
        assert!(
            output
                .events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::TableCreated { .. })),
            "应包含 TableCreated 事件"
        );

        // 验证 modified_objects
        assert_eq!(output.modified_objects, vec![[0x42; 32]]);
    }

    #[test]
    fn zkvm_main_create_table_rejects_invalid_max_players() {
        let args = CreateTableArgs {
            name: "bad".into(),
            max_players: 1, // 越界（应 2..=9）
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let input = ZkvmInput {
            table: make_table(),
            context: make_context(),
            method_selector: selectors::create_table(),
            args: args_bytes,
        };
        let input_bytes = borsh::to_vec(&input).unwrap();

        let result = zkvm_main_logic(&input_bytes);
        match result {
            Err(ZkvmErrorKind::Dispatch(DispatchError::Serialization(msg))) => {
                assert!(msg.contains("out of range"), "错误消息: {msg}");
            }
            other => panic!("期望 Serialization 错误，实际: {other:?}"),
        }
    }

    #[test]
    fn zkvm_main_dispatch_context_borsh_roundtrip() {
        let ctx = make_context();
        let bytes = borsh::to_vec(&ctx).unwrap();
        // 20 + 8 + 8 + 8 = 44 字节
        assert_eq!(bytes.len(), 44, "DispatchContext 应为 44 字节");
        let recovered: DispatchContext = BorshDeserialize::try_from_slice(&bytes).unwrap();
        assert_eq!(ctx, recovered);
    }

    #[test]
    fn zkvm_main_zkvm_input_borsh_roundtrip() {
        let args = CreateTableArgs {
            name: "rt".into(),
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let input = ZkvmInput {
            table: make_table(),
            context: make_context(),
            method_selector: selectors::create_table(),
            args: args_bytes,
        };
        let bytes = borsh::to_vec(&input).unwrap();
        let recovered: ZkvmInput = BorshDeserialize::try_from_slice(&bytes).unwrap();
        assert_eq!(recovered.table, input.table);
        assert_eq!(recovered.context, input.context);
        assert_eq!(recovered.method_selector, input.method_selector);
        assert_eq!(recovered.args, input.args);
    }

    #[test]
    fn zkvm_main_zkvm_output_borsh_roundtrip() {
        let output = ZkvmOutput {
            table: make_table(),
            events: vec![TexasPokerEvent::TableCreated {
                table_id: [0x42; 32],
                name: "rt".into(),
            }],
            modified_objects: vec![[0x42; 32]],
        };
        let bytes = borsh::to_vec(&output).unwrap();
        let recovered: ZkvmOutput = BorshDeserialize::try_from_slice(&bytes).unwrap();
        assert_eq!(recovered.table, output.table);
        assert_eq!(recovered.events, output.events);
        assert_eq!(recovered.modified_objects, output.modified_objects);
    }
}
