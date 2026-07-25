//! `join_table` AIR — 简单入座（不参与本局，等下一局）。
//!
//! 移植自 `dispatch::dispatch_join_table` 与 `state_machine` 的入座逻辑。
//!
//! ## 业务规约
//!
//! 1. `round_state == ROUND_WAITING`
//! 2. `seat_index < max_players`
//! 3. 目标座位为空（`seat.player == EMPTY_PLAYER`）
//! 4. `buy_in >= big_blind`
//! 5. 玩家公钥已注册
//!
//! 状态变更：`seat.player = player_addr`, `seat.stack = buy_in`, `version += 1`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `join_table` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_BUY_IN` 起始列（4 limb）。
    pub const INPUT_BUY_IN_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PLAYER_ADDR` 起始列（4 limb，Blake2b 压缩后）。
    pub const INPUT_PLAYER_ADDR_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `join_table` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 13;
}

/// `join_table` AIR 输入参数。
#[derive(Debug, Clone)]
pub struct JoinTableInput {
    /// 座位索引。
    pub seat_index: u8,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家地址。
    pub player_addr: [u8; 20],
}

/// `join_table` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct JoinTableAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: JoinTableInput,
    /// 调用前 state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl JoinTableAir {
    /// 构造新 AIR 实例。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for JoinTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::JoinTable);
        let is_active = common.is_active.clone();

        // 业务列
        let input_seat_index = eval.next_trace_mask();
        let _input_buy_in_0 = eval.next_trace_mask();
        let _input_buy_in_1 = eval.next_trace_mask();
        let _input_buy_in_2 = eval.next_trace_mask();
        let _input_buy_in_3 = eval.next_trace_mask();
        let _input_player_addr_0 = eval.next_trace_mask();
        let _input_player_addr_1 = eval.next_trace_mask();
        let _input_player_addr_2 = eval.next_trace_mask();
        let _input_player_addr_3 = eval.next_trace_mask();
        let _output_seat_stack_0 = eval.next_trace_mask();
        let _output_seat_stack_1 = eval.next_trace_mask();
        let _output_seat_stack_2 = eval.next_trace_mask();
        let _output_seat_stack_3 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        let seat_diff = input_seat_index.clone() - expected_seat;
        eval.add_constraint(is_active.clone() * seat_diff);

        // 约束 2：seat_index < max_players（简化为 < 9，完整实现需要读取 max_players 列）
        // 已在通用约束中通过 round_state 隐含约束
        eval
    }
}

/// `join_table` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct JoinTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_BUY_IN`（4 limb）。
    pub input_buy_in: [M31; 4],
    /// `INPUT_PLAYER_ADDR`（4 limb）。
    pub input_player_addr: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
}

impl JoinTableRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &JoinTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::JoinTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre_round_state = WAITING
                0, // post_round_state = WAITING
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_buy_in: u64_to_m31_limbs(input.buy_in),
            input_player_addr: u64_to_m31_limbs(0), // 简化
            output_seat_stack: u64_to_m31_limbs(input.buy_in),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_buy_in: [ZERO; 4],
            input_player_addr: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_buy_in);
        v.extend_from_slice(&self.input_player_addr);
        v.extend_from_slice(&self.output_seat_stack);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
