//! Deterministic settlement projection and reset AIR component.

use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::EvalAtRow;

use super::seat_update::COMPOSITION_SEATS;
use super::{
    STAGE_HEADER_NUM_COLUMNS, StageHeaderRow, bind_bool, bind_u64, evaluate_stage_header,
    evaluate_u64_add,
};
use crate::airs::common::{ZERO, compute_add_carries, u64_to_m31_limbs};
use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};

/// Number of columns in the settlement component row.
pub const NUM_COLUMNS: usize = STAGE_HEADER_NUM_COLUMNS
    + 1
    + DIGEST_LIMBS
    + 1
    + 3 * 4
    + COMPOSITION_SEATS * 4
    + COMPOSITION_SEATS * 4
    + COMPOSITION_SEATS * 3
    + 3
    + 1;

/// Settlement algorithm selected by canonical native replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SettlementKind {
    /// No settlement occurred.
    None = 0,
    /// Last-player-standing award without showdown.
    WithoutShowdown = 1,
    /// Canonical side-pot/showdown settlement plan.
    Showdown = 2,
}

/// Canonical fixed-seat settlement and reset projection.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementStagePlan {
    /// Whether settlement/reset occurred.
    pub active: bool,
    /// Settlement algorithm discriminator.
    pub kind: SettlementKind,
    /// Native deterministic plan digest; synthesized canonically for no-showdown.
    pub native_plan_digest: [u8; 32],
    /// Number of showdown runouts; zero for no-showdown.
    pub runout_count: u8,
    /// Pot before rake.
    pub gross_pot: u64,
    /// Rake removed from table custody.
    pub rake: u64,
    /// Sum of all seat awards.
    pub total_awards: u64,
    /// Fixed nine-seat aggregate awards.
    pub awards: [u64; COMPOSITION_SEATS],
    /// Whether reset to the next-hand waiting state was applied.
    pub reset_applied: bool,
}

impl SettlementStagePlan {
    /// Canonical zero payload for a non-terminal dispatch.
    #[must_use]
    pub const fn inactive() -> Self {
        Self {
            active: false,
            kind: SettlementKind::None,
            native_plan_digest: [0; 32],
            runout_count: 0,
            gross_pot: 0,
            rake: 0,
            total_awards: 0,
            awards: [0; COMPOSITION_SEATS],
            reset_applied: false,
        }
    }
}

/// Fixed-width witness row for [`SettlementStagePlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementRow {
    header: StageHeaderRow,
    kind: M31,
    native_plan_digest: [M31; DIGEST_LIMBS],
    runout_count: M31,
    gross_pot: [M31; 4],
    rake: [M31; 4],
    total_awards: [M31; 4],
    awards: [[M31; 4]; COMPOSITION_SEATS],
    accumulators: [[M31; 4]; COMPOSITION_SEATS],
    sum_carries: [[M31; 3]; COMPOSITION_SEATS],
    conservation_carry: [M31; 3],
    reset_applied: M31,
}

impl SettlementRow {
    /// Build the canonical award-sum and conservation witness.
    #[must_use]
    pub fn new(plan: &SettlementStagePlan, link: &super::StageLink) -> Self {
        let mut running = 0u64;
        let mut accumulators = [[ZERO; 4]; COMPOSITION_SEATS];
        let mut sum_carries = [[ZERO; 3]; COMPOSITION_SEATS];
        for index in 0..COMPOSITION_SEATS {
            if let Some(next) = running.checked_add(plan.awards[index]) {
                sum_carries[index] = compute_add_carries(running, plan.awards[index]);
                running = next;
                accumulators[index] = u64_to_m31_limbs(running);
            }
        }
        let conservation_carry = if plan.total_awards.checked_add(plan.rake) == Some(plan.gross_pot)
        {
            compute_add_carries(plan.total_awards, plan.rake)
        } else {
            [ZERO; 3]
        };
        Self {
            header: StageHeaderRow::new(link),
            kind: M31::from(u32::from(plan.kind as u8)),
            native_plan_digest: digest_to_m31_limbs(plan.native_plan_digest),
            runout_count: M31::from(u32::from(plan.runout_count)),
            gross_pot: u64_to_m31_limbs(plan.gross_pot),
            rake: u64_to_m31_limbs(plan.rake),
            total_awards: u64_to_m31_limbs(plan.total_awards),
            awards: plan.awards.map(u64_to_m31_limbs),
            accumulators,
            sum_carries,
            conservation_carry,
            reset_applied: M31::from(u32::from(plan.reset_applied)),
        }
    }

    /// Serialize the row in canonical trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut values = Vec::with_capacity(NUM_COLUMNS);
        self.header.append_to(&mut values);
        values.push(self.kind);
        values.extend_from_slice(&self.native_plan_digest);
        values.push(self.runout_count);
        values.extend_from_slice(&self.gross_pot);
        values.extend_from_slice(&self.rake);
        values.extend_from_slice(&self.total_awards);
        for award in &self.awards {
            values.extend_from_slice(award);
        }
        for accumulator in &self.accumulators {
            values.extend_from_slice(accumulator);
        }
        for carry in &self.sum_carries {
            values.extend_from_slice(carry);
        }
        values.extend_from_slice(&self.conservation_carry);
        values.push(self.reset_applied);
        debug_assert_eq!(values.len(), NUM_COLUMNS);
        values
    }
}

/// Read and constrain one settlement component row.
pub fn evaluate<E: EvalAtRow>(eval: &mut E, plan: &SettlementStagePlan, link: &super::StageLink) {
    evaluate_stage_header(eval, link);
    let kind = eval.next_trace_mask();
    let native_plan_digest: [E::F; DIGEST_LIMBS] = std::array::from_fn(|_| eval.next_trace_mask());
    let runout_count = eval.next_trace_mask();
    let gross_pot: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let rake: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let total_awards: [E::F; 4] = std::array::from_fn(|_| eval.next_trace_mask());
    let awards: [[E::F; 4]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let accumulators: [[E::F; 4]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let sum_carries: [[E::F; 3]; COMPOSITION_SEATS] =
        std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
    let conservation_carry: [E::F; 3] = std::array::from_fn(|_| eval.next_trace_mask());
    let reset_applied = eval.next_trace_mask();

    eval.add_constraint(kind - M31::from(u32::from(plan.kind as u8)).into());
    for (actual, expected) in native_plan_digest
        .iter()
        .zip(digest_to_m31_limbs(plan.native_plan_digest))
    {
        eval.add_constraint(actual.clone() - expected.into());
    }
    eval.add_constraint(runout_count - M31::from(u32::from(plan.runout_count)).into());
    bind_u64(eval, &gross_pot, plan.gross_pot);
    bind_u64(eval, &rake, plan.rake);
    bind_u64(eval, &total_awards, plan.total_awards);
    for (actual, expected) in awards.iter().zip(plan.awards) {
        bind_u64(eval, actual, expected);
    }
    bind_bool(eval, reset_applied, plan.reset_applied);

    let zero: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
    for index in 0..COMPOSITION_SEATS {
        let previous = if index == 0 {
            &zero
        } else {
            &accumulators[index - 1]
        };
        evaluate_u64_add(
            eval,
            previous,
            &awards[index],
            &accumulators[index],
            &sum_carries[index],
        );
    }
    for limb in 0..4 {
        eval.add_constraint(
            accumulators[COMPOSITION_SEATS - 1][limb].clone() - total_awards[limb].clone(),
        );
    }
    evaluate_u64_add(eval, &total_awards, &rake, &gross_pot, &conservation_carry);

    let legal = match plan.kind {
        SettlementKind::None => !plan.active && !plan.reset_applied && plan.runout_count == 0,
        SettlementKind::WithoutShowdown => {
            plan.active && plan.reset_applied && plan.runout_count == 0
        }
        SettlementKind::Showdown => {
            plan.active && plan.reset_applied && matches!(plan.runout_count, 1 | 2)
        }
    };
    let legal: E::F = M31::from(u32::from(legal)).into();
    let one: E::F = M31::from(1u32).into();
    eval.add_constraint(legal - one);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::composition::plan::{StageKind, StageLink};

    #[test]
    fn row_sums_multi_winner_awards() {
        let plan = SettlementStagePlan {
            active: true,
            kind: SettlementKind::Showdown,
            native_plan_digest: [7; 32],
            runout_count: 2,
            gross_pot: 200,
            rake: 10,
            total_awards: 190,
            awards: [95, 0, 0, 0, 95, 0, 0, 0, 0],
            reset_applied: true,
        };
        let link = StageLink {
            active: true,
            stage_kind: StageKind::Settlement,
            stage_index: 3,
            plan_digest: [1; 32],
            input_digest: [2; 32],
            output_digest: [3; 32],
        };
        assert_eq!(SettlementRow::new(&plan, &link).to_vec().len(), NUM_COLUMNS);
    }
}
