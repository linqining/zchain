//! Fixed `CpuV1` composition-polynomial evaluation AIR.
//!
//! The L1 verifier evaluates every `CpuAir` constraint at the transcript-derived OODS point,
//! divides by the CPU trace-domain vanishing polynomial, and folds the quotients with a random
//! coefficient. This module reuses `CpuAir::evaluate` through a nested [`EvalAtRow`] adapter so the
//! recursive verifier cannot drift from the fixed method AIR by maintaining a second handwritten
//! constraint list.
//!
//! This closes only the composition-evaluation subproblem. The sampled values and transcript
//! challenges still need to be linked to canonical Merkle openings and Poseidon252 transcript AIR
//! before recursive verification can be enabled.

use core::array;
use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};

use ark_ff::{One, Zero};
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::fields::FieldExpOps;
use stwo::core::poly::circle::CanonicCoset;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
use crate::stwo_backend::cpu_air::CpuAir;

/// Four M31 columns are used for each sampled QM31 value.
pub const COMP_EVAL_AIR_NUM_COLUMNS: usize = NUM_COLUMNS * SECURE_EXTENSION_DEGREE;

/// Evaluates the fixed `CpuAir` composition claim from all original-trace OODS samples.
#[derive(Debug, Clone)]
pub struct CompositionEvalAir {
    trace_log_size: u32,
    cpu_log_size: u32,
    oods_point: stwo::core::circle::CirclePoint<SecureField>,
    composition_random_coeff: SecureField,
    claimed_composition_eval: SecureField,
}

impl CompositionEvalAir {
    /// Creates a fixed CPU composition evaluator.
    #[must_use]
    pub const fn new(
        trace_log_size: u32,
        cpu_log_size: u32,
        oods_point: stwo::core::circle::CirclePoint<SecureField>,
        composition_random_coeff: SecureField,
        claimed_composition_eval: SecureField,
    ) -> Self {
        Self {
            trace_log_size,
            cpu_log_size,
            oods_point,
            composition_random_coeff,
            claimed_composition_eval,
        }
    }

    /// Returns the recursive trace log size.
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.trace_log_size
    }
}

impl FrameworkEval for CompositionEvalAir {
    fn log_size(&self) -> u32 {
        self.trace_log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.trace_log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let sampled_values = (0..NUM_COLUMNS)
            .map(|_| {
                let limbs = array::from_fn(|_| eval.next_trace_mask());
                RecursiveExpression(E::combine_ef(limbs))
            })
            .collect();

        let denominator_inverse =
            coset_vanishing(CanonicCoset::new(self.cpu_log_size).coset, self.oods_point).inverse();
        let nested = CpuCompositionEvaluator::new(
            sampled_values,
            self.composition_random_coeff,
            denominator_inverse,
        );
        let nested = CpuAir::new(self.cpu_log_size).evaluate(nested);
        eval.add_constraint(nested.finalize().0 - E::EF::from(self.claimed_composition_eval));
        eval
    }
}

/// Local newtype allowing the outer AIR extension expressions to act as `CpuAir` point values.
#[derive(Debug, Clone)]
struct RecursiveExpression<T>(T);

impl<T: Zero> Zero for RecursiveExpression<T> {
    fn zero() -> Self {
        Self(T::zero())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl<T: One> One for RecursiveExpression<T> {
    fn one() -> Self {
        Self(T::one())
    }
}

impl<T: Neg<Output = T>> Neg for RecursiveExpression<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl<T: Add<Output = T>> Add for RecursiveExpression<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl<T: Sub<Output = T>> Sub for RecursiveExpression<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl<T: Mul<Output = T>> Mul for RecursiveExpression<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl<T: AddAssign> AddAssign for RecursiveExpression<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl<T> MulAssign for RecursiveExpression<T>
where
    T: Clone + Mul<Output = T>,
{
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = self.0.clone() * rhs.0;
    }
}

impl<T> AddAssign<BaseField> for RecursiveExpression<T>
where
    T: Add<SecureField, Output = T> + Clone,
{
    fn add_assign(&mut self, rhs: BaseField) {
        self.0 = self.0.clone() + SecureField::from(rhs);
    }
}

impl<T: From<SecureField>> From<BaseField> for RecursiveExpression<T> {
    fn from(value: BaseField) -> Self {
        Self(T::from(SecureField::from(value)))
    }
}

impl<T: From<SecureField>> From<SecureField> for RecursiveExpression<T> {
    fn from(value: SecureField) -> Self {
        Self(T::from(value))
    }
}

impl<T> Add<BaseField> for RecursiveExpression<T>
where
    T: Add<SecureField, Output = T>,
{
    type Output = Self;

    fn add(self, rhs: BaseField) -> Self::Output {
        Self(self.0 + SecureField::from(rhs))
    }
}

impl<T> Mul<BaseField> for RecursiveExpression<T>
where
    T: Mul<BaseField, Output = T>,
{
    type Output = Self;

    fn mul(self, rhs: BaseField) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl<T> Add<SecureField> for RecursiveExpression<T>
where
    T: Add<SecureField, Output = T>,
{
    type Output = Self;

    fn add(self, rhs: SecureField) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl<T> Sub<SecureField> for RecursiveExpression<T>
where
    T: Sub<SecureField, Output = T>,
{
    type Output = Self;

    fn sub(self, rhs: SecureField) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl<T> Mul<SecureField> for RecursiveExpression<T>
where
    T: Mul<SecureField, Output = T>,
{
    type Output = Self;

    fn mul(self, rhs: SecureField) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl<T> FieldExpOps for RecursiveExpression<T>
where
    T: Clone + One + Mul<Output = T>,
{
    fn inverse(&self) -> Self {
        panic!("inverse is not used by the fixed CpuV1 composition evaluator")
    }
}

struct CpuCompositionEvaluator<T> {
    sampled_values: Vec<RecursiveExpression<T>>,
    column_index: usize,
    random_coeff: RecursiveExpression<T>,
    denominator_inverse: RecursiveExpression<T>,
    accumulation: RecursiveExpression<T>,
}

impl<T> CpuCompositionEvaluator<T>
where
    T: Clone + Zero + From<SecureField>,
{
    fn new(
        sampled_values: Vec<RecursiveExpression<T>>,
        random_coeff: SecureField,
        denominator_inverse: SecureField,
    ) -> Self {
        Self {
            sampled_values,
            column_index: 0,
            random_coeff: RecursiveExpression(T::from(random_coeff)),
            denominator_inverse: RecursiveExpression(T::from(denominator_inverse)),
            accumulation: RecursiveExpression(T::zero()),
        }
    }

    fn finalize(self) -> RecursiveExpression<T> {
        assert_eq!(self.column_index, NUM_COLUMNS);
        self.accumulation
    }
}

impl<T> EvalAtRow for CpuCompositionEvaluator<T>
where
    T: Clone
        + Debug
        + Zero
        + One
        + Neg<Output = T>
        + AddAssign
        + Add<T, Output = T>
        + Sub<T, Output = T>
        + Mul<T, Output = T>
        + Add<BaseField, Output = T>
        + Mul<BaseField, Output = T>
        + Add<SecureField, Output = T>
        + Sub<SecureField, Output = T>
        + Mul<SecureField, Output = T>
        + From<SecureField>,
{
    type F = RecursiveExpression<T>;
    type EF = RecursiveExpression<T>;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N] {
        assert_eq!(interaction, stwo_constraint_framework::ORIGINAL_TRACE_IDX);
        assert!(offsets.iter().all(|offset| *offset == 0));
        assert_eq!(N, 1);
        let value = self.sampled_values[self.column_index].clone();
        self.column_index += 1;
        array::from_fn(|_| value.clone())
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        let constraint = Self::EF::from(constraint);
        self.accumulation = RecursiveExpression(
            self.accumulation.0.clone() * self.random_coeff.0.clone()
                + constraint.0 * self.denominator_inverse.0.clone(),
        );
    }

    fn combine_ef(values: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
        values[0].clone()
            + values[1].clone() * SecureField::from_u32_unchecked(0, 1, 0, 0)
            + values[2].clone() * SecureField::from_u32_unchecked(0, 0, 1, 0)
            + values[3].clone() * SecureField::from_u32_unchecked(0, 0, 0, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::air::{Component, Components};
    use stwo::core::circle::CirclePoint;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::{
        assert_constraints_on_trace, FrameworkComponent, TraceLocationAllocator,
    };

    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::trace_native::TraceBuilder;

    fn fixed_cpu_composition_fixture() -> (Vec<Vec<BaseField>>, CompositionEvalAir, SecureField) {
        let cpu_log_size = 10;
        let trace_log_size = 2;
        let mut builder = TraceBuilder::new(cpu_log_size);
        builder.fill_padding_to_full();
        let proof = prove_cpu_trace(&builder.finalize()).unwrap();

        let mut allocator = TraceLocationAllocator::default();
        let component = FrameworkComponent::new(
            &mut allocator,
            CpuAir::new(cpu_log_size),
            SecureField::zero(),
        );
        let components = Components {
            components: vec![&component as &dyn Component],
            n_preprocessed_columns: 0,
        };

        let mut channel = stwo::core::channel::Poseidon252Channel::default();
        use stwo::core::channel::{Channel, MerkleChannel};
        use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
        Poseidon252MerkleChannel::mix_root(&mut channel, proof.0.commitments[0]);
        Poseidon252MerkleChannel::mix_root(&mut channel, proof.0.commitments[1]);
        let random_coeff = channel.draw_secure_felt();
        Poseidon252MerkleChannel::mix_root(&mut channel, proof.0.commitments[2]);
        let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
        let expected = components.eval_composition_polynomial_at_point(
            oods_point,
            &proof.0.sampled_values,
            random_coeff,
            cpu_log_size,
        );

        let samples = &proof.0.sampled_values[1];
        assert_eq!(samples.len(), NUM_COLUMNS);
        let n_rows = 1usize << trace_log_size;
        let mut trace = Vec::with_capacity(COMP_EVAL_AIR_NUM_COLUMNS);
        for column in samples {
            assert_eq!(column.len(), 1);
            for limb in column[0].to_m31_array() {
                trace.push(vec![limb; n_rows]);
            }
        }

        (
            trace,
            CompositionEvalAir::new(
                trace_log_size,
                cpu_log_size,
                oods_point,
                random_coeff,
                expected,
            ),
            expected,
        )
    }

    #[test]
    fn fixed_cpu_composition_air_accepts_real_samples() {
        let (trace, air, _) = fixed_cpu_composition_fixture();
        let trees = TreeVec::new(vec![vec![], trace.iter().collect()]);
        assert_constraints_on_trace(
            &trees,
            air.log_size(),
            |eval| {
                air.evaluate(eval);
            },
            SecureField::zero(),
        );
    }

    #[test]
    #[should_panic(expected = "constraint #0")]
    fn fixed_cpu_composition_air_rejects_wrong_claim() {
        let (trace, air, expected) = fixed_cpu_composition_fixture();
        let bad_air = CompositionEvalAir::new(
            air.trace_log_size,
            air.cpu_log_size,
            air.oods_point,
            air.composition_random_coeff,
            expected + SecureField::from(1u32),
        );
        let trees = TreeVec::new(vec![vec![], trace.iter().collect()]);
        assert_constraints_on_trace(
            &trees,
            bad_air.log_size(),
            |eval| {
                bad_air.evaluate(eval);
            },
            SecureField::zero(),
        );
    }

    #[test]
    #[should_panic(expected = "constraint #0")]
    fn fixed_cpu_composition_air_rejects_tampered_sample() {
        let (mut trace, air, _) = fixed_cpu_composition_fixture();
        trace[crate::stwo_backend::column_layout_v2::IS_PADDING * SECURE_EXTENSION_DEGREE][0] +=
            BaseField::from(1u32);
        let trees = TreeVec::new(vec![vec![], trace.iter().collect()]);
        assert_constraints_on_trace(
            &trees,
            air.log_size(),
            |eval| {
                air.evaluate(eval);
            },
            SecureField::zero(),
        );
    }
}
