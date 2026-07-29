//! `request_leave_after_hand` AIR — toggle a seat's next-hand leave request.
//!
//! The production host first replays the exact VM dispatch (including caller
//! authorization and raw argument decoding). This AIR then binds the resulting
//! transition row and enforces the local toggle invariant.

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, bool_to_m31, u8_to_m31,
};
use crate::method_kind::MethodKind;

/// Method-specific trace columns.
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// Requested seat.
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS;
    /// `want_leave` before the call.
    pub const INPUT_PRE_WANT_LEAVE: usize = COMMON_NUM_COLUMNS + 1;
    /// `want_leave` after the call.
    pub const OUTPUT_POST_WANT_LEAVE: usize = COMMON_NUM_COLUMNS + 2;
    /// Total trace width.
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 3;
}

/// Public method input reconstructed by the verifier.
#[derive(Debug, Clone)]
pub struct RequestLeaveAfterHandInput {
    /// Requested seat.
    pub seat_index: u8,
    /// Flag before execution.
    pub pre_want_leave: bool,
    /// Flag after execution.
    pub post_want_leave: bool,
}

/// AIR instance.
#[derive(Debug, Clone)]
pub struct RequestLeaveAfterHandAir {
    /// Trace log size.
    pub log_size: u32,
    /// Verifier-reconstructed method input.
    pub input: RequestLeaveAfterHandInput,
    /// Pre-state root projection.
    pub pre_state_root: [M31; 4],
    /// Post-state root projection.
    pub post_state_root: [M31; 4],
    /// Table identifier.
    pub table_id: u64,
    /// Hand identifier.
    pub hand_id: u32,
    /// Call sequence.
    pub call_seq: u32,
    /// Pre-state version.
    pub pre_version: u64,
    /// Post-state version.
    pub post_version: u64,
}

impl RequestLeaveAfterHandAir {
    /// Trace column count.
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for RequestLeaveAfterHandAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write(&mut eval, &statement);
        let is_active = common.is_active.clone();
        let one: E::F = M31::from(1u32).into();

        let seat_index = eval.next_trace_mask();
        let pre_want_leave = eval.next_trace_mask();
        let post_want_leave = eval.next_trace_mask();

        eval.add_constraint(
            is_active.clone()
                * (seat_index - M31::from(u32::from(self.input.seat_index)).into()),
        );
        eval.add_constraint(
            is_active.clone()
                * (pre_want_leave.clone()
                    - M31::from(u32::from(self.input.pre_want_leave)).into()),
        );
        eval.add_constraint(
            is_active.clone()
                * (post_want_leave.clone()
                    - M31::from(u32::from(self.input.post_want_leave)).into()),
        );
        eval.add_constraint(
            is_active.clone() * pre_want_leave.clone() * (pre_want_leave.clone() - one.clone()),
        );
        eval.add_constraint(
            is_active.clone()
                * post_want_leave.clone()
                * (post_want_leave.clone() - one.clone()),
        );
        eval.add_constraint(is_active * (pre_want_leave + post_want_leave - one));

        eval.add_constraint(common.round_state_unchanged());
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }
        eval.add_constraint(common.button_unchanged());
        eval
    }
}

/// Replicated business row.
#[derive(Debug, Clone)]
pub struct RequestLeaveAfterHandRow {
    /// Common columns.
    pub common: CommonRow,
    /// Requested seat.
    pub input_seat_index: M31,
    /// Flag before execution.
    pub input_pre_want_leave: M31,
    /// Flag after execution.
    pub output_post_want_leave: M31,
}

impl RequestLeaveAfterHandRow {
    /// Construct an active row.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn active(
        input: &RequestLeaveAfterHandInput,
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
        pre_button: u8,
        post_button: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::RequestLeaveAfterHand,
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
                pre_button,
                post_button,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_pre_want_leave: bool_to_m31(input.pre_want_leave),
            output_post_want_leave: bool_to_m31(input.post_want_leave),
        }
    }

    /// Construct a padding-compatible row.
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_pre_want_leave: ZERO,
            output_post_want_leave: ZERO,
        }
    }

    /// Serialize in column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut row = self.common.to_vec();
        row.push(self.input_seat_index);
        row.push(self.input_pre_want_leave);
        row.push(self.output_post_want_leave);
        debug_assert_eq!(row.len(), cols::NUM_COLUMNS);
        row
    }
}
