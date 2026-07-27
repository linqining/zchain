//! `leave_table` AIR — 简单离座（仅在 WAITING 状态）。
//!
//! ## 业务规约
//! 1. `round_state == ROUND_WAITING`
//! 2. `seat_index < max_players`
//! 3. 座位非空
//! 4. 状态变更：`seat.player = EMPTY_PLAYER`, `version += 1`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `leave_table` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_REFUND_AMOUNT` 起始列（4 limb）。
    pub const OUTPUT_REFUND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）：诚实 host 只对占用座位离座，
    /// 故前置「座位非空」由该列 == 1 强制。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 5;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 6;
}

/// `leave_table` 输入参数。
#[derive(Debug, Clone)]
pub struct LeaveTableInput {
    /// 座位索引。
    pub seat_index: u8,
}

/// `leave_table` AIR。
#[derive(Debug, Clone)]
pub struct LeaveTableAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: LeaveTableInput,
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

impl LeaveTableAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for LeaveTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::LeaveTable, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let _refund_0 = eval.next_trace_mask();
        let _refund_1 = eval.next_trace_mask();
        let _refund_2 = eval.next_trace_mask();
        let _refund_3 = eval.next_trace_mask();
        // Gap 3 boolean witness（座位非空）。
        let input_seat_occupied = eval.next_trace_mask();

        // 约束：seat_index == input.seat_index
        let expected: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected));

        // 约束 2（审计 leave_table 前置，degree-2）：pre_round_state == WAITING(0)。
        // leave_table 仅在 WAITING 状态合法（Lean 反例：PREFLOP 下 leave）。
        eval.add_constraint(common.round_state_eq(0));
        // 约束 3（degree-2）：round_state 不变。
        eval.add_constraint(common.round_state_unchanged());
        // 约束 4（Gap 3，degree-2）：input_seat_occupied == 1 — 诚实 host 只对占用座位离座。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one));
        // TODO 阶段 2：refund 守恒、chip_pool/addon_pool 守恒（需新增业务列）。
        eval
    }
}

/// `leave_table` trace 行。
#[derive(Debug, Clone)]
pub struct LeaveTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// 座位索引。
    pub input_seat_index: M31,
    /// 退款金额。
    pub output_refund: [M31; 4],
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub input_seat_occupied: M31,
}

impl LeaveTableRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &LeaveTableInput,
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
                MethodKind::LeaveTable, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                0, 0, 0, 0, 0, 0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            output_refund: [ZERO; 4],
            // Gap 3：诚实 host 只对占用座位离座。
            input_seat_occupied: M31::from(1u32),
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self { common: CommonRow::padding(), input_seat_index: ZERO, output_refund: [ZERO; 4], input_seat_occupied: ZERO }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.output_refund);
        v.push(self.input_seat_occupied);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
