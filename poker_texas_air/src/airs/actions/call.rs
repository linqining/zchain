//! `call` AIR — 玩家跟注（匹配当前最高下注）。
//!
//! 移植自 `dispatch::dispatch_call` 与 `state_machine::apply_call`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 玩家未 fold、未 all_in
//! 4. 跟注金额 = `current_bet - seat.bet`（受 stack 限制）
//! 5. 状态变更：
//!    - `seat.stack -= call_amount`
//!    - `seat.bet += call_amount`
//!    - `seat.total_bet += call_amount`
//!    - 若 `seat.stack == 0` 则 `seat.all_in = true`
//!    - `pot += call_amount`, `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 18 个：`INPUT_SEAT_INDEX`, `INPUT_CALL_AMOUNT_BASE[4]`,
//!   `OUTPUT_SEAT_STACK_BASE[4]`, `OUTPUT_SEAT_BET_BASE[4]`,
//!   `OUTPUT_ALL_IN`, `OUTPUT_ACTED`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `call` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CALL_AMOUNT` 起始列（4 limb）。
    pub const INPUT_CALL_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_SEAT_BET` 起始列（4 limb）。
    pub const OUTPUT_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `OUTPUT_ALL_IN` 列（1 = all-in）。
    pub const OUTPUT_ALL_IN: usize = COMMON_NUM_COLUMNS + 13;
    /// `OUTPUT_ACTED` 列（1 = 已行动）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 14;
    /// `call` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 15;
}

/// `call` 输入参数。
#[derive(Debug, Clone)]
pub struct CallInput {
    /// 执行 call 的座位索引。
    pub seat_index: u8,
    /// 跟注金额。
    pub call_amount: u64,
}

/// `call` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CallAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: CallInput,
    /// 调用前 state_root。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root。
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

impl CallAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CallAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Call);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_call_amount_0 = eval.next_trace_mask();
        let _input_call_amount_1 = eval.next_trace_mask();
        let _input_call_amount_2 = eval.next_trace_mask();
        let _input_call_amount_3 = eval.next_trace_mask();
        let _output_seat_stack_0 = eval.next_trace_mask();
        let _output_seat_stack_1 = eval.next_trace_mask();
        let _output_seat_stack_2 = eval.next_trace_mask();
        let _output_seat_stack_3 = eval.next_trace_mask();
        let _output_seat_bet_0 = eval.next_trace_mask();
        let _output_seat_bet_1 = eval.next_trace_mask();
        let _output_seat_bet_2 = eval.next_trace_mask();
        let _output_seat_bet_3 = eval.next_trace_mask();
        let _output_all_in = eval.next_trace_mask();
        let output_acted = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：call_amount 一致性（limb 0）
        let expected_amt_0: E::F = M31::from((self.input.call_amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_call_amount_0 - expected_amt_0));

        // 约束 3：output_acted == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active * (output_acted - one));

        eval
    }
}

/// `call` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct CallRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CALL_AMOUNT`（4 limb）。
    pub input_call_amount: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_BET`（4 limb）。
    pub output_seat_bet: [M31; 4],
    /// `OUTPUT_ALL_IN`。
    pub output_all_in: M31,
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
}

impl CallRow {
    /// 构造 active 行。
    ///
    /// # 参数
    /// - `post_seat_stack`: 调用后座位 stack
    /// - `post_seat_bet`: 调用后座位 bet
    /// - `is_all_in`: 是否 all-in
    #[must_use]
    pub fn active(
        input: &CallInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
        pre_pot: u64,
        post_pot: u64,
        post_seat_stack: u64,
        post_seat_bet: u64,
        is_all_in: bool,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::Call,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                post_round_state,
                pre_pot,
                post_pot,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_call_amount: u64_to_m31_limbs(input.call_amount),
            output_seat_stack: u64_to_m31_limbs(post_seat_stack),
            output_seat_bet: u64_to_m31_limbs(post_seat_bet),
            output_all_in: M31::from(u32::from(is_all_in)),
            output_acted: M31::from(1u32),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_call_amount: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            output_seat_bet: [ZERO; 4],
            output_all_in: ZERO,
            output_acted: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_call_amount);
        v.extend_from_slice(&self.output_seat_stack);
        v.extend_from_slice(&self.output_seat_bet);
        v.push(self.output_all_in);
        v.push(self.output_acted);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
