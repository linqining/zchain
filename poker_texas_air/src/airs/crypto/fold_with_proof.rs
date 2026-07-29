//! `fold_with_proof` AIR — mid-round fold plus protocol-layer exit.
//!
//! Full DLEq verification and all deck/pending-list updates are replayed by the
//! trusted host through the public VM dispatch before proving. The current AIR
//! deliberately covers only the same-round `advance_turn` branch; collection,
//! round advancement, and settlement remain fail-closed under P06.

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31};
use crate::method_kind::MethodKind;

/// Method-specific trace columns.
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// Requested seat.
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS;
    /// Folded flag after execution.
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 1;
    /// Witness `pre_round_state^2` for the betting-round vanishing polynomial.
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 2;
    /// Current turn before execution.
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 3;
    /// Current turn after the supported mid-round branch.
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 4;
    /// Total trace width.
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 5;
}

/// Verifier-reconstructed method input.
#[derive(Debug, Clone)]
pub struct FoldWithProofInput {
    /// Folding seat.
    pub seat_index: u8,
    /// Next turn for the supported mid-round branch.
    pub post_current_turn: u8,
}

/// AIR instance.
#[derive(Debug, Clone)]
pub struct FoldWithProofAir {
    /// Trace log size.
    pub log_size: u32,
    /// Verifier-reconstructed method input.
    pub input: FoldWithProofInput,
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

impl FoldWithProofAir {
    /// Trace column count.
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for FoldWithProofAir {
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

        let seat_index = eval.next_trace_mask();
        let folded = eval.next_trace_mask();
        let pre_round_state_q = eval.next_trace_mask();
        let current_turn = eval.next_trace_mask();
        let post_current_turn = eval.next_trace_mask();

        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (seat_index - expected_seat.clone()));
        eval.add_constraint(is_active.clone() * (current_turn - expected_seat));
        eval.add_constraint(is_active.clone() * (folded - M31::from(1u32).into()));

        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(pre_round_state_q));
        for constraint in common.pot_unchanged_4limb() {
            eval.add_constraint(constraint);
        }
        eval.add_constraint(common.button_unchanged());
        eval.add_constraint(
            is_active
                * (post_current_turn
                    - M31::from(u32::from(self.input.post_current_turn)).into()),
        );
        eval
    }
}

/// Replicated business row.
#[derive(Debug, Clone)]
pub struct FoldWithProofRow {
    /// Common columns.
    pub common: CommonRow,
    /// Folding seat.
    pub input_seat_index: M31,
    /// Folded flag after execution.
    pub output_folded: M31,
    /// Betting-round witness.
    pub input_pre_round_state_q: M31,
    /// Current turn before execution.
    pub input_current_turn: M31,
    /// Current turn after execution.
    pub output_current_turn: M31,
}

impl FoldWithProofRow {
    /// Construct an active row.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn active(
        input: &FoldWithProofInput,
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
        let round = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::FoldWithProof,
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
            output_folded: M31::from(1u32),
            input_pre_round_state_q: round * round,
            input_current_turn: u8_to_m31(input.seat_index),
            output_current_turn: u8_to_m31(input.post_current_turn),
        }
    }

    /// Construct a padding-compatible row.
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_folded: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
        }
    }

    /// Serialize in column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut row = self.common.to_vec();
        row.push(self.input_seat_index);
        row.push(self.output_folded);
        row.push(self.input_pre_round_state_q);
        row.push(self.input_current_turn);
        row.push(self.output_current_turn);
        debug_assert_eq!(row.len(), cols::NUM_COLUMNS);
        row
    }
}
