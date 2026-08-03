//! Semantic AIR for the fixed `CpuV1` PCS quotient and FRI folding schedule.
//!
//! The quotient component consumes every PCS queried M31 value exactly once from the Merkle leaf
//! packing table and replays Stwo's `fri_answers` as a verifier-fixed affine accumulation. The FRI
//! component consumes every committed FRI leaf coordinate, binds queried inputs to the preceding
//! quotient/fold output, performs the exact fold-step-one butterfly, and checks the degree-zero
//! last layer polynomial required by `PcsConfig::default()`.

use core::array;
use std::collections::HashMap;

use stwo::core::air::{Component, Components};
use stwo::core::circle::Coset;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::quotients::{
    ColumnSampleBatch, PointSample, accumulate_row_quotients,
    build_samples_with_randomness_and_periodicity, quotient_constants,
};
use stwo::core::pcs::{PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::LineDomain;
use stwo::core::queries::Queries;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, ORIGINAL_TRACE_IDX,
    Relation, RelationEntry, TraceLocationAllocator,
};

use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
use crate::stwo_backend::cpu_air::CpuAir;

use super::cpu_transcript_binding_air::secure_field_from_draw_result;
use super::merkle_semantic_air::MERKLE_QUERIED_VALUE_RELATION_ID;
use super::public_inputs::{RecursivePublicInputs, RecursiveVerifierProgram};
use super::replay_witness::{CanonicalVerifierWitness, PoseidonCallSource};

const FRI_QUERY_VALUE_RELATION_ID: u32 = 1_990_310_005;

const QUOTIENT_VALUE_COLUMN: usize = 0;
const QUOTIENT_ACC_BEFORE_START: usize = 1;
const QUOTIENT_ACC_AFTER_START: usize = QUOTIENT_ACC_BEFORE_START + SECURE_EXTENSION_DEGREE;
pub(crate) const PCS_QUOTIENT_AIR_NUM_COLUMNS: usize =
    QUOTIENT_ACC_AFTER_START + SECURE_EXTENSION_DEGREE;
pub(crate) const PCS_QUOTIENT_INTERACTION_COLUMNS: usize = 4;

const Q_PRE_ACTIVE: usize = 0;
const Q_PRE_FIRST: usize = 1;
const Q_PRE_LAST: usize = 2;
const Q_PRE_TREE_INDEX: usize = 3;
const Q_PRE_NODE_INDEX: usize = 4;
const Q_PRE_LEAF_VALUE_INDEX: usize = 5;
const Q_PRE_QUERY_POSITION: usize = 6;
const Q_PRE_COEFF_START: usize = 7;
const Q_PRE_OFFSET_START: usize = Q_PRE_COEFF_START + SECURE_EXTENSION_DEGREE;
const PCS_QUOTIENT_PREPROCESSED_COLUMNS: usize = Q_PRE_OFFSET_START + SECURE_EXTENSION_DEGREE;

const FOLD_LEFT_START: usize = 0;
const FOLD_RIGHT_START: usize = FOLD_LEFT_START + SECURE_EXTENSION_DEGREE;
const FOLD_OUTPUT_START: usize = FOLD_RIGHT_START + SECURE_EXTENSION_DEGREE;
pub(crate) const FRI_FOLD_AIR_NUM_COLUMNS: usize = FOLD_OUTPUT_START + SECURE_EXTENSION_DEGREE;
const N_FRI_FOLD_RELATIONS: usize = 11;
pub(crate) const FRI_FOLD_INTERACTION_COLUMNS: usize =
    N_FRI_FOLD_RELATIONS.div_ceil(2) * SECURE_EXTENSION_DEGREE;

const F_PRE_ACTIVE: usize = 0;
const F_PRE_LAYER_INDEX: usize = 1;
const F_PRE_FIRST_LAYER: usize = 2;
const F_PRE_FINAL_LAYER: usize = 3;
const F_PRE_LEFT_POSITION: usize = 4;
const F_PRE_RIGHT_POSITION: usize = 5;
const F_PRE_FOLDED_POSITION: usize = 6;
const F_PRE_LEFT_QUERY: usize = 7;
const F_PRE_RIGHT_QUERY: usize = 8;
const F_PRE_INVERSE_TWIDDLE: usize = 9;
const F_PRE_ALPHA_START: usize = 10;
const F_PRE_LAST_COEFF_START: usize = F_PRE_ALPHA_START + SECURE_EXTENSION_DEGREE;
const FRI_FOLD_PREPROCESSED_COLUMNS: usize = F_PRE_LAST_COEFF_START + SECURE_EXTENSION_DEGREE;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FriSemanticAirError {
    #[error("FRI semantic AIR only supports the fixed CpuV1 default PCS configuration")]
    InvalidConfig,
    #[error("CpuV1 sampled-value shape is inconsistent")]
    InvalidSampleShape,
    #[error("CpuV1 queried-value metadata is inconsistent")]
    InvalidColumnMetadata,
    #[error("FRI transcript draw schedule is inconsistent")]
    InvalidDrawSchedule,
    #[error("FRI layer schedule is inconsistent")]
    InvalidLayerSchedule,
    #[error("FRI semantic metadata does not fit M31")]
    MetadataOverflow,
    #[error("canonical PCS queried values differ from the fixed quotient schedule")]
    QuotientWitnessMismatch,
    #[error("canonical FRI folds differ from the fixed public schedule")]
    FoldWitnessMismatch,
}

#[derive(Debug, Clone)]
struct QuotientScheduleRow {
    query_index: usize,
    query_position: usize,
    tree_index: usize,
    node_index: usize,
    leaf_value_index: usize,
    coefficient: SecureField,
    offset: SecureField,
    first: bool,
    last: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PcsQuotientPublicWitness {
    pub n_rows: usize,
    pub log_size: u32,
    schedule: Vec<QuotientScheduleRow>,
    columns: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl PcsQuotientPublicWitness {
    pub(crate) fn new(
        public_inputs: &RecursivePublicInputs,
        sampled_values: &[SecureField],
    ) -> Result<Self, FriSemanticAirError> {
        let schedule = quotient_schedule(public_inputs, sampled_values)?;
        if schedule.is_empty() {
            return Err(FriSemanticAirError::InvalidColumnMetadata);
        }
        let n_rows = schedule.len();
        let log_size = padded_log_size(n_rows);
        let mut rows = schedule
            .iter()
            .map(quotient_preprocessed_row)
            .collect::<Result<Vec<_>, _>>()?;
        rows.resize(
            1usize << log_size,
            [BaseField::from(0u32); PCS_QUOTIENT_PREPROCESSED_COLUMNS],
        );
        let (_, columns) = rows_to_preprocessed_columns(&rows, log_size, |column| {
            quotient_preprocessed_id(column, log_size, n_rows)
        });
        Ok(Self {
            n_rows,
            log_size,
            schedule,
            columns,
        })
    }

    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        (
            (0..PCS_QUOTIENT_PREPROCESSED_COLUMNS)
                .map(|column| quotient_preprocessed_id(column, self.log_size, self.n_rows))
                .collect(),
            self.columns.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PcsQuotientWitness {
    pub base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl PcsQuotientWitness {
    pub(crate) fn new(
        canonical: &CanonicalVerifierWitness,
        public: &PcsQuotientPublicWitness,
    ) -> Result<Self, FriSemanticAirError> {
        if canonical.first_layer_query_positions
            != public
                .schedule
                .iter()
                .filter(|row| row.first)
                .map(|row| row.query_position)
                .collect::<Vec<_>>()
            || canonical.first_layer_answers.len() != canonical.first_layer_query_positions.len()
        {
            return Err(FriSemanticAirError::QuotientWitnessMismatch);
        }

        let mut values = HashMap::new();
        for leaf in &canonical.merkle_leaves {
            let PoseidonCallSource::PcsMerkle { tree_index } = leaf.source else {
                continue;
            };
            for (value_index, value) in leaf.values.iter().copied().enumerate() {
                if values
                    .insert((tree_index, leaf.position, value_index), value)
                    .is_some()
                {
                    return Err(FriSemanticAirError::QuotientWitnessMismatch);
                }
            }
        }

        let mut accumulator = SecureField::from(0u32);
        let mut rows = Vec::with_capacity(public.n_rows);
        for schedule in &public.schedule {
            if schedule.first {
                accumulator = SecureField::from(0u32);
            }
            let value = *values
                .get(&(
                    schedule.tree_index,
                    schedule.node_index,
                    schedule.leaf_value_index,
                ))
                .ok_or(FriSemanticAirError::QuotientWitnessMismatch)?;
            let before = accumulator;
            accumulator += SecureField::from(value) * schedule.coefficient + schedule.offset;
            if schedule.last
                && canonical.first_layer_answers.get(schedule.query_index) != Some(&accumulator)
            {
                return Err(FriSemanticAirError::QuotientWitnessMismatch);
            }
            let mut row = [BaseField::from(0u32); PCS_QUOTIENT_AIR_NUM_COLUMNS];
            row[QUOTIENT_VALUE_COLUMN] = value;
            row[QUOTIENT_ACC_BEFORE_START..QUOTIENT_ACC_AFTER_START]
                .copy_from_slice(&before.to_m31_array());
            row[QUOTIENT_ACC_AFTER_START..].copy_from_slice(&accumulator.to_m31_array());
            rows.push(row);
        }
        rows.resize(
            1usize << public.log_size,
            [BaseField::from(0u32); PCS_QUOTIENT_AIR_NUM_COLUMNS],
        );
        Ok(Self {
            base_trace: rows_to_base_columns(&rows, public.log_size),
        })
    }

    pub(crate) fn write_interaction_trace(
        &self,
        public: &PcsQuotientPublicWitness,
        lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let n_vec_rows = 1usize << (public.log_size - LOG_N_LANES);
        let mut logup = LogupTraceGenerator::new(public.log_size);
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let (leaf_numerator, leaf_denominator) = quotient_fraction(
                &self.base_trace,
                &public.columns,
                0,
                vec_row,
                lookup_elements,
            );
            let (answer_numerator, answer_denominator) = quotient_fraction(
                &self.base_trace,
                &public.columns,
                1,
                vec_row,
                lookup_elements,
            );
            column.write_frac(
                vec_row,
                leaf_numerator * answer_denominator + answer_numerator * leaf_denominator,
                leaf_denominator * answer_denominator,
            );
        }
        column.finalize_col();
        logup.finalize_last()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PcsQuotientAir {
    log_size: u32,
    n_rows: usize,
    lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl PcsQuotientAir {
    pub(crate) const fn new(
        log_size: u32,
        n_rows: usize,
        lookup_elements: cairo_air::relations::CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_rows,
            lookup_elements,
        }
    }
}

impl FrameworkEval for PcsQuotientAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let fixed = (0..PCS_QUOTIENT_PREPROCESSED_COLUMNS)
            .map(|column| {
                eval.get_preprocessed_column(quotient_preprocessed_id(
                    column,
                    self.log_size,
                    self.n_rows,
                ))
            })
            .collect::<Vec<_>>();
        let value = eval.next_trace_mask();
        let before: [(E::F, E::F); SECURE_EXTENSION_DEGREE] = array::from_fn(|_| {
            let [current, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
            (current, next)
        });
        let after: [E::F; SECURE_EXTENSION_DEGREE] = array::from_fn(|_| eval.next_trace_mask());
        let active = fixed[Q_PRE_ACTIVE].clone();
        let first = fixed[Q_PRE_FIRST].clone();
        let last = fixed[Q_PRE_LAST].clone();
        for coordinate in 0..SECURE_EXTENSION_DEGREE {
            let expected = before[coordinate].0.clone()
                + value.clone() * fixed[Q_PRE_COEFF_START + coordinate].clone()
                + fixed[Q_PRE_OFFSET_START + coordinate].clone();
            eval.add_constraint(active.clone() * (after[coordinate].clone() - expected));
            eval.add_constraint(first.clone() * before[coordinate].0.clone());
            eval.add_constraint(
                (active.clone() - last.clone())
                    * (before[coordinate].1.clone() - after[coordinate].clone()),
            );
        }
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::from(active),
            &merkle_value_relation_values(
                E::F::from(BaseField::from(1u32)),
                E::F::from(BaseField::from(0u32)),
                fixed[Q_PRE_TREE_INDEX].clone(),
                fixed[Q_PRE_NODE_INDEX].clone(),
                fixed[Q_PRE_LEAF_VALUE_INDEX].clone(),
                value,
            ),
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::from(last),
            &fri_query_relation_values(
                E::F::from(BaseField::from(0u32)),
                fixed[Q_PRE_QUERY_POSITION].clone(),
                &after,
            ),
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Debug, Clone)]
struct FoldScheduleRow {
    layer_index: usize,
    left_position: usize,
    right_position: usize,
    folded_position: usize,
    left_query: bool,
    right_query: bool,
    inverse_twiddle: BaseField,
    alpha: SecureField,
    last_coefficient: SecureField,
    first_layer: bool,
    final_layer: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct FriFoldPublicWitness {
    pub n_rows: usize,
    pub log_size: u32,
    schedule: Vec<FoldScheduleRow>,
    columns: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl FriFoldPublicWitness {
    pub(crate) fn new(
        public_inputs: &RecursivePublicInputs,
        draw_results: &[starknet_ff::FieldElement],
    ) -> Result<Self, FriSemanticAirError> {
        let schedule = fold_schedule(public_inputs, draw_results)?;
        if schedule.is_empty() {
            return Err(FriSemanticAirError::InvalidLayerSchedule);
        }
        let n_rows = schedule.len();
        let log_size = padded_log_size(n_rows);
        let mut rows = schedule
            .iter()
            .map(fold_preprocessed_row)
            .collect::<Result<Vec<_>, _>>()?;
        rows.resize(
            1usize << log_size,
            [BaseField::from(0u32); FRI_FOLD_PREPROCESSED_COLUMNS],
        );
        let (_, columns) = rows_to_preprocessed_columns(&rows, log_size, |column| {
            fold_preprocessed_id(column, log_size, n_rows)
        });
        Ok(Self {
            n_rows,
            log_size,
            schedule,
            columns,
        })
    }

    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        (
            (0..FRI_FOLD_PREPROCESSED_COLUMNS)
                .map(|column| fold_preprocessed_id(column, self.log_size, self.n_rows))
                .collect(),
            self.columns.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FriFoldWitness {
    pub base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl FriFoldWitness {
    pub(crate) fn new(
        canonical: &CanonicalVerifierWitness,
        public: &FriFoldPublicWitness,
    ) -> Result<Self, FriSemanticAirError> {
        let mut schedule_index = 0usize;
        let mut rows = Vec::with_capacity(public.n_rows);
        for layer in &canonical.fri_fold_layers {
            if layer.fold_step != 1
                || layer.opened_coset_evaluations.len() != layer.folded_evaluations.len()
                || layer.decommitment_positions.len() != 2 * layer.opened_coset_evaluations.len()
            {
                return Err(FriSemanticAirError::FoldWitnessMismatch);
            }
            for (coset_index, (opened, output)) in layer
                .opened_coset_evaluations
                .iter()
                .zip(layer.folded_evaluations.iter().copied())
                .enumerate()
            {
                let [left, right] = opened.as_slice() else {
                    return Err(FriSemanticAirError::FoldWitnessMismatch);
                };
                let schedule = public
                    .schedule
                    .get(schedule_index)
                    .ok_or(FriSemanticAirError::FoldWitnessMismatch)?;
                let positions = &layer.decommitment_positions[2 * coset_index..2 * coset_index + 2];
                if layer.layer_index != schedule.layer_index
                    || positions != [schedule.left_position, schedule.right_position]
                    || layer.folded_query_positions.get(coset_index)
                        != Some(&schedule.folded_position)
                    || fold_value(*left, *right, schedule.inverse_twiddle, schedule.alpha) != output
                {
                    return Err(FriSemanticAirError::FoldWitnessMismatch);
                }
                let mut row = [BaseField::from(0u32); FRI_FOLD_AIR_NUM_COLUMNS];
                row[FOLD_LEFT_START..FOLD_RIGHT_START].copy_from_slice(&left.to_m31_array());
                row[FOLD_RIGHT_START..FOLD_OUTPUT_START].copy_from_slice(&right.to_m31_array());
                row[FOLD_OUTPUT_START..].copy_from_slice(&output.to_m31_array());
                rows.push(row);
                schedule_index += 1;
            }
        }
        if schedule_index != public.n_rows {
            return Err(FriSemanticAirError::FoldWitnessMismatch);
        }
        rows.resize(
            1usize << public.log_size,
            [BaseField::from(0u32); FRI_FOLD_AIR_NUM_COLUMNS],
        );
        Ok(Self {
            base_trace: rows_to_base_columns(&rows, public.log_size),
        })
    }

    pub(crate) fn write_interaction_trace(
        &self,
        public: &FriFoldPublicWitness,
        lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let n_vec_rows = 1usize << (public.log_size - LOG_N_LANES);
        let mut logup = LogupTraceGenerator::new(public.log_size);
        for pair_start in (0..N_FRI_FOLD_RELATIONS).step_by(2) {
            let mut column = logup.new_col();
            for vec_row in 0..n_vec_rows {
                let (numerator0, denominator0) = fold_fraction(
                    &self.base_trace,
                    &public.columns,
                    pair_start,
                    vec_row,
                    lookup_elements,
                );
                if pair_start + 1 < N_FRI_FOLD_RELATIONS {
                    let (numerator1, denominator1) = fold_fraction(
                        &self.base_trace,
                        &public.columns,
                        pair_start + 1,
                        vec_row,
                        lookup_elements,
                    );
                    column.write_frac(
                        vec_row,
                        numerator0 * denominator1 + numerator1 * denominator0,
                        denominator0 * denominator1,
                    );
                } else {
                    column.write_frac(vec_row, numerator0, denominator0);
                }
            }
            column.finalize_col();
        }
        logup.finalize_last()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FriFoldAir {
    log_size: u32,
    n_rows: usize,
    lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl FriFoldAir {
    pub(crate) const fn new(
        log_size: u32,
        n_rows: usize,
        lookup_elements: cairo_air::relations::CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_rows,
            lookup_elements,
        }
    }
}

impl FrameworkEval for FriFoldAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let fixed = (0..FRI_FOLD_PREPROCESSED_COLUMNS)
            .map(|column| {
                eval.get_preprocessed_column(fold_preprocessed_id(
                    column,
                    self.log_size,
                    self.n_rows,
                ))
            })
            .collect::<Vec<_>>();
        let left: [E::F; SECURE_EXTENSION_DEGREE] = array::from_fn(|_| eval.next_trace_mask());
        let right: [E::F; SECURE_EXTENSION_DEGREE] = array::from_fn(|_| eval.next_trace_mask());
        let output: [E::F; SECURE_EXTENSION_DEGREE] = array::from_fn(|_| eval.next_trace_mask());
        let active = fixed[F_PRE_ACTIVE].clone();
        let final_layer = fixed[F_PRE_FINAL_LAYER].clone();
        let inverse_twiddle = fixed[F_PRE_INVERSE_TWIDDLE].clone();
        let alpha: [E::F; SECURE_EXTENSION_DEGREE] =
            array::from_fn(|index| fixed[F_PRE_ALPHA_START + index].clone());
        let sum: [E::F; SECURE_EXTENSION_DEGREE] =
            array::from_fn(|index| left[index].clone() + right[index].clone());
        let difference: [E::F; SECURE_EXTENSION_DEGREE] = array::from_fn(|index| {
            (left[index].clone() - right[index].clone()) * inverse_twiddle.clone()
        });
        let alpha_difference = qm31_mul(&alpha, &difference);
        for coordinate in 0..SECURE_EXTENSION_DEGREE {
            eval.add_constraint(
                active.clone()
                    * (output[coordinate].clone()
                        - sum[coordinate].clone()
                        - alpha_difference[coordinate].clone()),
            );
            eval.add_constraint(
                final_layer.clone()
                    * (output[coordinate].clone()
                        - fixed[F_PRE_LAST_COEFF_START + coordinate].clone()),
            );
        }

        for (position_column, values) in
            [(F_PRE_LEFT_POSITION, &left), (F_PRE_RIGHT_POSITION, &right)]
        {
            for coordinate in 0..SECURE_EXTENSION_DEGREE {
                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(active.clone()),
                    &merkle_value_relation_values(
                        E::F::from(BaseField::from(0u32)),
                        E::F::from(BaseField::from(1u32)),
                        fixed[F_PRE_LAYER_INDEX].clone(),
                        fixed[position_column].clone(),
                        E::F::from(BaseField::from(coordinate as u32)),
                        values[coordinate].clone(),
                    ),
                ));
            }
        }
        for (selector, position_column, values) in [
            (F_PRE_LEFT_QUERY, F_PRE_LEFT_POSITION, &left),
            (F_PRE_RIGHT_QUERY, F_PRE_RIGHT_POSITION, &right),
        ] {
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                -E::EF::from(fixed[selector].clone()),
                &fri_query_relation_values(
                    fixed[F_PRE_LAYER_INDEX].clone(),
                    fixed[position_column].clone(),
                    values,
                ),
            ));
        }
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::from(active - final_layer),
            &fri_query_relation_values(
                fixed[F_PRE_LAYER_INDEX].clone() + E::F::from(BaseField::from(1u32)),
                fixed[F_PRE_FOLDED_POSITION].clone(),
                &output,
            ),
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

fn quotient_schedule(
    public_inputs: &RecursivePublicInputs,
    sampled_values: &[SecureField],
) -> Result<Vec<QuotientScheduleRow>, FriSemanticAirError> {
    ensure_supported_single_component_config(public_inputs)?;
    let (column_log_sizes, sample_points) = match public_inputs.verifier_program {
        RecursiveVerifierProgram::CpuV1 => {
            let mut allocator = TraceLocationAllocator::default();
            let component = FrameworkComponent::new(
                &mut allocator,
                CpuAir::new(public_inputs.log_size),
                SecureField::from(0u32),
            );
            let components = Components {
                components: vec![&component as &dyn Component],
                n_preprocessed_columns: 0,
            };
            let mut column_log_sizes = components.column_log_sizes();
            column_log_sizes.push(vec![public_inputs.log_size; 2 * SECURE_EXTENSION_DEGREE]);
            let mut sample_points = components.mask_points(
                public_inputs.oods_point,
                public_inputs.max_log_degree_bound,
                false,
            );
            sample_points.push(vec![
                vec![public_inputs.oods_point];
                2 * SECURE_EXTENSION_DEGREE
            ]);
            (column_log_sizes, sample_points)
        }
        RecursiveVerifierProgram::ReplicatedRowV1 => {
            let column_log_sizes = stwo::core::pcs::TreeVec(
                public_inputs
                    .l1_tree_metadata
                    .iter()
                    .map(|tree| tree.column_log_sizes.clone())
                    .collect(),
            );
            if column_log_sizes.len() != 3
                || !column_log_sizes[0].is_empty()
                || column_log_sizes[1].is_empty()
                || column_log_sizes[2].len() != 2 * SECURE_EXTENSION_DEGREE
            {
                return Err(FriSemanticAirError::InvalidColumnMetadata);
            }
            let sample_points = stwo::core::pcs::TreeVec(vec![
                Vec::new(),
                vec![vec![public_inputs.oods_point]; column_log_sizes[1].len()],
                vec![vec![public_inputs.oods_point]; 2 * SECURE_EXTENSION_DEGREE],
            ]);
            (column_log_sizes, sample_points)
        }
    };
    if column_log_sizes.len() != public_inputs.l1_tree_metadata.len()
        || column_log_sizes
            .iter()
            .zip(&public_inputs.l1_tree_metadata)
            .any(|(actual, expected)| actual != &expected.column_log_sizes)
    {
        return Err(FriSemanticAirError::InvalidColumnMetadata);
    }

    let expected_sample_count = sample_points
        .iter()
        .flat_map(|tree| tree.iter())
        .map(Vec::len)
        .sum::<usize>();
    if expected_sample_count != sampled_values.len() {
        return Err(FriSemanticAirError::InvalidSampleShape);
    }
    let mut sample_cursor = 0usize;
    let samples = TreeVec(
        sample_points
            .iter()
            .map(|tree| {
                tree.iter()
                    .map(|column| {
                        column
                            .iter()
                            .copied()
                            .map(|point| {
                                let value = sampled_values[sample_cursor];
                                sample_cursor += 1;
                                PointSample { point, value }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
    let lifting_log_size =
        public_inputs.log_size + public_inputs.config.fri_config.log_blowup_factor;
    let samples_with_randomness = build_samples_with_randomness_and_periodicity(
        &samples,
        column_log_sizes
            .iter()
            .cloned()
            .map(Vec::into_iter)
            .collect(),
        lifting_log_size,
        public_inputs.fri_quotient_random_coeff,
    );
    let sample_columns = samples_with_randomness.iter().flatten().collect::<Vec<_>>();
    let sample_batches = ColumnSampleBatch::new_vec(&sample_columns);
    let constants = quotient_constants(&sample_batches);
    let total_columns = column_log_sizes.iter().map(Vec::len).sum::<usize>();
    if total_columns == 0 {
        return Err(FriSemanticAirError::InvalidColumnMetadata);
    }

    let mut leaf_indices = Vec::with_capacity(column_log_sizes.len());
    for tree in column_log_sizes.iter() {
        let mut order = (0..tree.len()).collect::<Vec<_>>();
        order.sort_by_key(|column_index| tree[*column_index]);
        let mut inverse = vec![0usize; tree.len()];
        for (leaf_index, column_index) in order.into_iter().enumerate() {
            inverse[column_index] = leaf_index;
        }
        leaf_indices.push(inverse);
    }

    let domain = CanonicCoset::new(lifting_log_size).circle_domain();
    let mut schedule = Vec::with_capacity(public_inputs.query_positions.len() * total_columns);
    for (query_index, query_position) in public_inputs.query_positions.iter().copied().enumerate() {
        let domain_point = domain.at(bit_reverse_index(query_position, lifting_log_size));
        let mut queried_row = vec![BaseField::from(0u32); total_columns];
        let baseline =
            accumulate_row_quotients(&sample_batches, &queried_row, &constants, domain_point);
        let mut flat_column = 0usize;
        for (tree_index, tree) in column_log_sizes.iter().enumerate() {
            for column_index in 0..tree.len() {
                queried_row[flat_column] = BaseField::from(1u32);
                let coefficient = accumulate_row_quotients(
                    &sample_batches,
                    &queried_row,
                    &constants,
                    domain_point,
                ) - baseline;
                queried_row[flat_column] = BaseField::from(0u32);
                schedule.push(QuotientScheduleRow {
                    query_index,
                    query_position,
                    tree_index,
                    node_index: query_position,
                    leaf_value_index: leaf_indices[tree_index][column_index],
                    coefficient,
                    offset: if flat_column == 0 {
                        baseline
                    } else {
                        SecureField::from(0u32)
                    },
                    first: flat_column == 0,
                    last: flat_column + 1 == total_columns,
                });
                flat_column += 1;
            }
        }
    }
    Ok(schedule)
}

fn fold_schedule(
    public_inputs: &RecursivePublicInputs,
    draw_results: &[starknet_ff::FieldElement],
) -> Result<Vec<FoldScheduleRow>, FriSemanticAirError> {
    ensure_supported_single_component_config(public_inputs)?;
    let n_layers = 1 + public_inputs.fri_inner_layer_commitments.len();
    let expected_layers = public_inputs
        .max_log_degree_bound
        .checked_sub(public_inputs.config.fri_config.log_last_layer_degree_bound)
        .ok_or(FriSemanticAirError::InvalidLayerSchedule)? as usize;
    if n_layers != expected_layers
        || draw_results.len() != public_inputs.fri_inner_layer_commitments.len() + 5
        || public_inputs.fri_last_layer_poly.len() > 1
    {
        return Err(FriSemanticAirError::InvalidDrawSchedule);
    }
    let last_coefficient = public_inputs
        .fri_last_layer_poly
        .first()
        .copied()
        .unwrap_or_else(|| SecureField::from(0u32));
    let first_log_size =
        public_inputs.max_log_degree_bound + public_inputs.config.fri_config.log_blowup_factor;
    let mut queries = Queries::new(&public_inputs.query_positions, first_log_size);
    if queries.positions != public_inputs.query_positions {
        return Err(FriSemanticAirError::InvalidLayerSchedule);
    }
    let circle_domain = CanonicCoset::new(first_log_size).circle_domain();
    let mut line_domain = LineDomain::new(Coset::half_odds(
        public_inputs
            .max_log_degree_bound
            .checked_sub(1)
            .ok_or(FriSemanticAirError::InvalidLayerSchedule)?
            + public_inputs.config.fri_config.log_blowup_factor,
    ));
    let mut rows = Vec::new();
    for layer_index in 0..n_layers {
        let alpha = secure_field_from_draw_result(draw_results[3 + layer_index], 0);
        let mut query_index = 0usize;
        while query_index < queries.len() {
            let subset_start = (queries[query_index] >> 1) << 1;
            let subset_end = subset_start + 2;
            while query_index < queries.len() && queries[query_index] < subset_end {
                query_index += 1;
            }
            let domain_index = bit_reverse_index(subset_start, queries.log_domain_size);
            let inverse_twiddle = if layer_index == 0 {
                circle_domain.at(domain_index).y.inverse()
            } else {
                line_domain.at(domain_index).inverse()
            };
            rows.push(FoldScheduleRow {
                layer_index,
                left_position: subset_start,
                right_position: subset_start + 1,
                folded_position: subset_start >> 1,
                left_query: queries.binary_search(&subset_start).is_ok(),
                right_query: queries.binary_search(&(subset_start + 1)).is_ok(),
                inverse_twiddle,
                alpha,
                last_coefficient,
                first_layer: layer_index == 0,
                final_layer: layer_index + 1 == n_layers,
            });
        }
        queries = queries.fold(1);
        if layer_index > 0 {
            line_domain = line_domain.double();
        }
    }
    Ok(rows)
}

fn ensure_supported_single_component_config(
    public_inputs: &RecursivePublicInputs,
) -> Result<(), FriSemanticAirError> {
    if !matches!(
        public_inputs.verifier_program,
        RecursiveVerifierProgram::CpuV1 | RecursiveVerifierProgram::ReplicatedRowV1
    ) || public_inputs.config != PcsConfig::default()
        || public_inputs.max_log_degree_bound != public_inputs.log_size
        || public_inputs.config.fri_config.fold_step != 1
        || public_inputs.config.fri_config.log_last_layer_degree_bound != 0
    {
        return Err(FriSemanticAirError::InvalidConfig);
    }
    Ok(())
}

fn quotient_preprocessed_row(
    schedule: &QuotientScheduleRow,
) -> Result<[BaseField; PCS_QUOTIENT_PREPROCESSED_COLUMNS], FriSemanticAirError> {
    let mut row = [BaseField::from(0u32); PCS_QUOTIENT_PREPROCESSED_COLUMNS];
    row[Q_PRE_ACTIVE] = BaseField::from(1u32);
    row[Q_PRE_FIRST] = BaseField::from(schedule.first as u32);
    row[Q_PRE_LAST] = BaseField::from(schedule.last as u32);
    row[Q_PRE_TREE_INDEX] = to_field(schedule.tree_index)?;
    row[Q_PRE_NODE_INDEX] = to_field(schedule.node_index)?;
    row[Q_PRE_LEAF_VALUE_INDEX] = to_field(schedule.leaf_value_index)?;
    row[Q_PRE_QUERY_POSITION] = to_field(schedule.query_position)?;
    row[Q_PRE_COEFF_START..Q_PRE_OFFSET_START]
        .copy_from_slice(&schedule.coefficient.to_m31_array());
    row[Q_PRE_OFFSET_START..].copy_from_slice(&schedule.offset.to_m31_array());
    Ok(row)
}

fn fold_preprocessed_row(
    schedule: &FoldScheduleRow,
) -> Result<[BaseField; FRI_FOLD_PREPROCESSED_COLUMNS], FriSemanticAirError> {
    let mut row = [BaseField::from(0u32); FRI_FOLD_PREPROCESSED_COLUMNS];
    row[F_PRE_ACTIVE] = BaseField::from(1u32);
    row[F_PRE_LAYER_INDEX] = to_field(schedule.layer_index)?;
    row[F_PRE_FIRST_LAYER] = BaseField::from(schedule.first_layer as u32);
    row[F_PRE_FINAL_LAYER] = BaseField::from(schedule.final_layer as u32);
    row[F_PRE_LEFT_POSITION] = to_field(schedule.left_position)?;
    row[F_PRE_RIGHT_POSITION] = to_field(schedule.right_position)?;
    row[F_PRE_FOLDED_POSITION] = to_field(schedule.folded_position)?;
    row[F_PRE_LEFT_QUERY] = BaseField::from(schedule.left_query as u32);
    row[F_PRE_RIGHT_QUERY] = BaseField::from(schedule.right_query as u32);
    row[F_PRE_INVERSE_TWIDDLE] = schedule.inverse_twiddle;
    row[F_PRE_ALPHA_START..F_PRE_LAST_COEFF_START].copy_from_slice(&schedule.alpha.to_m31_array());
    row[F_PRE_LAST_COEFF_START..].copy_from_slice(&schedule.last_coefficient.to_m31_array());
    Ok(row)
}

fn fold_value(
    left: SecureField,
    right: SecureField,
    inverse_twiddle: BaseField,
    alpha: SecureField,
) -> SecureField {
    let f0 = left + right;
    let f1 = (left - right) * inverse_twiddle;
    f0 + alpha * f1
}

fn qm31_mul<F>(left: &[F; 4], right: &[F; 4]) -> [F; 4]
where
    F: Clone
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + From<BaseField>,
{
    let two = F::from(BaseField::from(2u32));
    let m1 = left[0].clone() * right[0].clone();
    let m2 = left[1].clone() * right[1].clone();
    let m3 = left[2].clone() * right[2].clone();
    let m4 = left[3].clone() * right[3].clone();
    let m5 = left[2].clone() * right[3].clone();
    let m6 = left[3].clone() * right[2].clone();
    let m7 = left[0].clone() * right[1].clone();
    let m8 = left[1].clone() * right[0].clone();
    let m9 = left[0].clone() * right[2].clone();
    let m10 = left[1].clone() * right[3].clone();
    let m11 = left[2].clone() * right[0].clone();
    let m12 = left[3].clone() * right[1].clone();
    let m13 = left[0].clone() * right[3].clone();
    let m14 = left[1].clone() * right[2].clone();
    let m15 = left[2].clone() * right[1].clone();
    let m16 = left[3].clone() * right[0].clone();
    [
        m1 - m2 + two.clone() * m3.clone() - two.clone() * m4.clone() - m5.clone() - m6.clone(),
        m7 + m8 + m3 - m4 + two.clone() * m5 + two * m6,
        m9 - m10 + m11 - m12,
        m13 + m14 + m15 + m16,
    ]
}

fn merkle_value_relation_values<F: Clone + From<BaseField>>(
    pcs_source: F,
    fri_source: F,
    source_arg: F,
    node_index: F,
    value_index: F,
    value: F,
) -> Vec<F> {
    vec![
        F::from(BaseField::from_u32_unchecked(
            MERKLE_QUERIED_VALUE_RELATION_ID,
        )),
        pcs_source,
        fri_source,
        source_arg,
        node_index,
        value_index,
        value,
    ]
}

fn fri_query_relation_values<F: Clone + From<BaseField>>(
    layer_index: F,
    position: F,
    value: &[F; SECURE_EXTENSION_DEGREE],
) -> Vec<F> {
    let mut values = Vec::with_capacity(3 + SECURE_EXTENSION_DEGREE);
    values.push(F::from(BaseField::from_u32_unchecked(
        FRI_QUERY_VALUE_RELATION_ID,
    )));
    values.push(layer_index);
    values.push(position);
    values.extend(value.iter().cloned());
    values
}

fn quotient_fraction(
    trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    fixed: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    relation_index: usize,
    vec_row: usize,
    lookup_elements: &cairo_air::relations::CommonLookupElements,
) -> (PackedSecureField, PackedSecureField) {
    let value = |column: usize| trace[column].values.data[vec_row];
    let fixed_value = |column: usize| fixed[column].values.data[vec_row];
    if relation_index == 0 {
        let values = merkle_value_relation_values(
            PackedBaseField::broadcast(BaseField::from(1u32)),
            PackedBaseField::broadcast(BaseField::from(0u32)),
            fixed_value(Q_PRE_TREE_INDEX),
            fixed_value(Q_PRE_NODE_INDEX),
            fixed_value(Q_PRE_LEAF_VALUE_INDEX),
            value(QUOTIENT_VALUE_COLUMN),
        );
        return (
            -PackedSecureField::from(fixed_value(Q_PRE_ACTIVE)),
            lookup_elements.combine(&values),
        );
    }
    let answer: [PackedBaseField; SECURE_EXTENSION_DEGREE] =
        array::from_fn(|index| value(QUOTIENT_ACC_AFTER_START + index));
    (
        PackedSecureField::from(fixed_value(Q_PRE_LAST)),
        lookup_elements.combine(&fri_query_relation_values(
            PackedBaseField::broadcast(BaseField::from(0u32)),
            fixed_value(Q_PRE_QUERY_POSITION),
            &answer,
        )),
    )
}

fn fold_fraction(
    trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    fixed: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    relation_index: usize,
    vec_row: usize,
    lookup_elements: &cairo_air::relations::CommonLookupElements,
) -> (PackedSecureField, PackedSecureField) {
    let value = |column: usize| trace[column].values.data[vec_row];
    let fixed_value = |column: usize| fixed[column].values.data[vec_row];
    let active = PackedSecureField::from(fixed_value(F_PRE_ACTIVE));
    if relation_index < 8 {
        let side = relation_index / SECURE_EXTENSION_DEGREE;
        let coordinate = relation_index % SECURE_EXTENSION_DEGREE;
        let (position_column, trace_start) = if side == 0 {
            (F_PRE_LEFT_POSITION, FOLD_LEFT_START)
        } else {
            (F_PRE_RIGHT_POSITION, FOLD_RIGHT_START)
        };
        let values = merkle_value_relation_values(
            PackedBaseField::broadcast(BaseField::from(0u32)),
            PackedBaseField::broadcast(BaseField::from(1u32)),
            fixed_value(F_PRE_LAYER_INDEX),
            fixed_value(position_column),
            PackedBaseField::broadcast(BaseField::from(coordinate as u32)),
            value(trace_start + coordinate),
        );
        return (-active, lookup_elements.combine(&values));
    }
    if relation_index < 10 {
        let left = relation_index == 8;
        let (selector, position, trace_start) = if left {
            (F_PRE_LEFT_QUERY, F_PRE_LEFT_POSITION, FOLD_LEFT_START)
        } else {
            (F_PRE_RIGHT_QUERY, F_PRE_RIGHT_POSITION, FOLD_RIGHT_START)
        };
        let query_value: [PackedBaseField; SECURE_EXTENSION_DEGREE] =
            array::from_fn(|index| value(trace_start + index));
        return (
            -PackedSecureField::from(fixed_value(selector)),
            lookup_elements.combine(&fri_query_relation_values(
                fixed_value(F_PRE_LAYER_INDEX),
                fixed_value(position),
                &query_value,
            )),
        );
    }
    let output: [PackedBaseField; SECURE_EXTENSION_DEGREE] =
        array::from_fn(|index| value(FOLD_OUTPUT_START + index));
    (
        active - PackedSecureField::from(fixed_value(F_PRE_FINAL_LAYER)),
        lookup_elements.combine(&fri_query_relation_values(
            fixed_value(F_PRE_LAYER_INDEX) + PackedBaseField::broadcast(BaseField::from(1u32)),
            fixed_value(F_PRE_FOLDED_POSITION),
            &output,
        )),
    )
}

fn rows_to_base_columns<const N: usize>(
    rows: &[[BaseField; N]],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    (0..N)
        .map(|column| {
            let values = rows.iter().map(|row| row[column]).collect::<Vec<_>>();
            let values = into_bit_reversed_circle_order(&values, log_size);
            CircleEvaluation::new(domain, BaseColumn::from_cpu(&values))
        })
        .collect()
}

fn rows_to_preprocessed_columns<const N: usize>(
    rows: &[[BaseField; N]],
    log_size: u32,
    id: impl Fn(usize) -> PreProcessedColumnId,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let domain = CanonicCoset::new(log_size).circle_domain();
    (0..N)
        .map(|column| {
            let values = rows.iter().map(|row| row[column]).collect::<Vec<_>>();
            let values = into_bit_reversed_circle_order(&values, log_size);
            (
                id(column),
                CircleEvaluation::new(domain, BaseColumn::from_cpu(&values)),
            )
        })
        .unzip()
}

fn into_bit_reversed_circle_order(values: &[BaseField], log_size: u32) -> Vec<BaseField> {
    let mut ordered = vec![BaseField::from(0u32); values.len()];
    for (coset_index, value) in values.iter().copied().enumerate() {
        let circle_index = coset_index_to_circle_domain_index(coset_index, log_size);
        ordered[bit_reverse_index(circle_index, log_size)] = value;
    }
    ordered
}

fn quotient_preprocessed_id(column: usize, log_size: u32, n_rows: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_pcs_quotient_{column}_{log_size}_{n_rows}"),
    }
}

fn fold_preprocessed_id(column: usize, log_size: u32, n_rows: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_fri_fold_{column}_{log_size}_{n_rows}"),
    }
}

fn padded_log_size(n_rows: usize) -> u32 {
    n_rows.next_power_of_two().max(N_LANES).ilog2()
}

fn to_field(value: usize) -> Result<BaseField, FriSemanticAirError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value < 0x7fff_ffff)
        .map(BaseField::from_u32_unchecked)
        .ok_or(FriSemanticAirError::MetadataOverflow)
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{
        FrameworkComponent, PREPROCESSED_TRACE_IDX, TraceLocationAllocator,
        assert_constraints_on_trace,
    };

    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::cpu_transcript_binding_air::CpuTranscriptBindingWitness;
    use crate::stwo_backend::recursive::merkle_leaf_air::{
        MerkleLeafPackingWitness, MerkleLeafPublicWitness,
    };
    use crate::stwo_backend::recursive::merkle_semantic_air::{
        MerklePublicBindingWitness, MerkleSemanticWitness,
    };
    use crate::stwo_backend::recursive::poseidon252_air::Poseidon252ClosureWitness;
    use crate::stwo_backend::recursive::poseidon252_replay::Poseidon252CallKind;
    use crate::stwo_backend::recursive::transcript_air::{
        TranscriptSemanticWitness, transcript_payload_values,
    };
    use crate::stwo_backend::recursive::verifier_program::{
        build_cpu_recursive_public_inputs, replay_cpu_verifier,
    };
    use crate::stwo_backend::trace_native::TraceBuilder;

    fn assert_component<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &TreeVec<Vec<&Vec<BaseField>>>,
    ) {
        let mut component_trace = trace
            .sub_tree(component.trace_locations())
            .map(|tree| tree.into_iter().cloned().collect());
        component_trace[PREPROCESSED_TRACE_IDX] = component
            .preprocessed_column_indices()
            .iter()
            .map(|index| trace[PREPROCESSED_TRACE_IDX][*index])
            .collect();
        let component_eval = component.deref();
        assert_constraints_on_trace(
            &component_trace,
            component.log_size(),
            |eval| {
                component_eval.evaluate(eval);
            },
            component.claimed_sum(),
        );
    }

    #[test]
    fn quotient_and_fri_fold_air_bind_canonical_replay() {
        crate::stwo_backend::recursive::run_large_stack_test(
            "quotient-and-fri-fold-air",
            256 * 1024 * 1024,
            || {
                let mut builder = TraceBuilder::new(10);
                builder.fill_padding_to_full();
                let proof = prove_cpu_trace(&builder.finalize()).expect("L1 proof should succeed");
                let public_inputs = build_cpu_recursive_public_inputs(&proof, 10).unwrap();
                let replay = replay_cpu_verifier(&proof, &public_inputs).unwrap();
                let canonical = CanonicalVerifierWitness::from_cpu_replay(&replay);
                let sampled_values = proof.0.sampled_values.clone().flatten_cols();
                let draw_results = canonical
                    .transcript_events
                    .iter()
                    .filter(|event| event.kind == Poseidon252CallKind::TranscriptDraw)
                    .map(|event| event.result)
                    .collect::<Vec<_>>();
                let quotient_public =
                    PcsQuotientPublicWitness::new(&public_inputs, &sampled_values).unwrap();
                let quotient = PcsQuotientWitness::new(&canonical, &quotient_public).unwrap();
                let fold_public = FriFoldPublicWitness::new(&public_inputs, &draw_results).unwrap();
                let fold = FriFoldWitness::new(&canonical, &fold_public).unwrap();
                let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
                let (quotient_interaction, quotient_sum) =
                    quotient.write_interaction_trace(&quotient_public, &lookup_elements);
                let (fold_interaction, fold_sum) =
                    fold.write_interaction_trace(&fold_public, &lookup_elements);
                assert_eq!(quotient_interaction.len(), PCS_QUOTIENT_INTERACTION_COLUMNS);
                assert_eq!(fold_interaction.len(), FRI_FOLD_INTERACTION_COLUMNS);

                let (mut ids, mut preprocessed) = quotient_public.preprocessed_columns();
                let (fold_ids, fold_preprocessed) = fold_public.preprocessed_columns();
                ids.extend(fold_ids);
                preprocessed.extend(fold_preprocessed);
                let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
                let quotient_component = FrameworkComponent::new(
                    &mut allocator,
                    PcsQuotientAir::new(
                        quotient_public.log_size,
                        quotient_public.n_rows,
                        lookup_elements.clone(),
                    ),
                    quotient_sum,
                );
                let fold_component = FrameworkComponent::new(
                    &mut allocator,
                    FriFoldAir::new(
                        fold_public.log_size,
                        fold_public.n_rows,
                        lookup_elements.clone(),
                    ),
                    fold_sum,
                );
                let mut base = quotient.base_trace;
                base.extend(fold.base_trace);
                let mut interaction = quotient_interaction;
                interaction.extend(fold_interaction);
                let mut trace = TreeVec::new(vec![
                    preprocessed
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    base.into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    interaction
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                ]);
                {
                    let trace_ref = trace.as_cols_ref();
                    assert_component(&quotient_component, &trace_ref);
                    assert_component(&fold_component, &trace_ref);
                }

                let quotient_span = quotient_component
                    .trace_locations()
                    .iter()
                    .find(|span| span.tree_index == 1)
                    .unwrap();
                let first_row = bit_reverse_index(
                    coset_index_to_circle_domain_index(0, quotient_public.log_size),
                    quotient_public.log_size,
                );
                trace[1][quotient_span.col_start + QUOTIENT_ACC_AFTER_START][first_row] +=
                    BaseField::from(1u32);
                let trace_ref = trace.as_cols_ref();
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        assert_component(&quotient_component, &trace_ref);
                    }))
                    .is_err()
                );
            },
        );
    }

    #[test]
    fn queried_value_and_fri_relations_close_globally() {
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let proof = prove_cpu_trace(&builder.finalize()).expect("L1 proof should succeed");
        let public_inputs = build_cpu_recursive_public_inputs(&proof, 10).unwrap();
        let replay = replay_cpu_verifier(&proof, &public_inputs).unwrap();
        let canonical = CanonicalVerifierWitness::from_cpu_replay(&replay);
        let sampled_values = proof.0.sampled_values.clone().flatten_cols();
        let draw_results = canonical
            .transcript_events
            .iter()
            .filter(|event| event.kind == Poseidon252CallKind::TranscriptDraw)
            .map(|event| event.result)
            .collect::<Vec<_>>();
        let pow_hash = canonical
            .transcript_events
            .iter()
            .find(|event| event.kind == Poseidon252CallKind::TranscriptPowNonce)
            .unwrap()
            .result;
        let payloads = transcript_payload_values(&canonical.transcript_events);
        let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
            &canonical.poseidon_calls,
            &payloads,
        )
        .unwrap();
        let transcript = TranscriptSemanticWitness::new(
            &canonical.transcript_events,
            &canonical.transcript_calls,
            &canonical.poseidon_calls,
            &poseidon.synthetic_memory.call_ids,
            &poseidon.synthetic_memory.extra_ids,
        )
        .unwrap();
        let transcript_binding = CpuTranscriptBindingWitness::new(
            &public_inputs,
            &sampled_values,
            &draw_results,
            proof.0.proof_of_work,
            pow_hash,
        )
        .unwrap();
        let merkle_binding = MerklePublicBindingWitness::new(&public_inputs).unwrap();
        let merkle = MerkleSemanticWitness::new(
            &canonical,
            &merkle_binding,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let leaf_public = MerkleLeafPublicWitness::new(&merkle_binding).unwrap();
        let leaf = MerkleLeafPackingWitness::new(
            &canonical,
            &leaf_public,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let quotient_public =
            PcsQuotientPublicWitness::new(&public_inputs, &sampled_values).unwrap();
        let quotient = PcsQuotientWitness::new(&canonical, &quotient_public).unwrap();
        let fold_public = FriFoldPublicWitness::new(&public_inputs, &draw_results).unwrap();
        let fold = FriFoldWitness::new(&canonical, &fold_public).unwrap();
        let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
        let poseidon = poseidon.write_interaction_trace(&lookup_elements).unwrap();
        let (_, transcript_sum) = transcript.write_interaction_trace(&lookup_elements);
        let (_, transcript_binding_sum) =
            transcript_binding.write_interaction_trace(&lookup_elements);
        let (_, merkle_sum) = merkle.write_interaction_trace(&lookup_elements);
        let (_, merkle_binding_sum) = merkle_binding.write_interaction_trace(&lookup_elements);
        let (_, leaf_sum) = leaf.write_interaction_trace(&leaf_public, &lookup_elements);
        let (_, quotient_sum) =
            quotient.write_interaction_trace(&quotient_public, &lookup_elements);
        let (_, fold_sum) = fold.write_interaction_trace(&fold_public, &lookup_elements);
        assert_eq!(
            poseidon.lookup_residual
                + transcript_sum
                + transcript_binding_sum
                + merkle_sum
                + merkle_binding_sum
                + leaf_sum
                + quotient_sum
                + fold_sum,
            SecureField::from(0u32)
        );
    }

    #[test]
    fn canonical_answer_or_fold_tampering_is_rejected() {
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let proof = prove_cpu_trace(&builder.finalize()).expect("L1 proof should succeed");
        let public_inputs = build_cpu_recursive_public_inputs(&proof, 10).unwrap();
        let replay = replay_cpu_verifier(&proof, &public_inputs).unwrap();
        let canonical = CanonicalVerifierWitness::from_cpu_replay(&replay);
        let sampled_values = proof.0.sampled_values.clone().flatten_cols();
        let draw_results = canonical
            .transcript_events
            .iter()
            .filter(|event| event.kind == Poseidon252CallKind::TranscriptDraw)
            .map(|event| event.result)
            .collect::<Vec<_>>();
        let quotient_public =
            PcsQuotientPublicWitness::new(&public_inputs, &sampled_values).unwrap();
        let fold_public = FriFoldPublicWitness::new(&public_inputs, &draw_results).unwrap();

        let mut tampered_answer = canonical.clone();
        tampered_answer.first_layer_answers[0] += SecureField::from(1u32);
        assert!(matches!(
            PcsQuotientWitness::new(&tampered_answer, &quotient_public),
            Err(FriSemanticAirError::QuotientWitnessMismatch)
        ));

        let mut tampered_fold = canonical;
        tampered_fold.fri_fold_layers[0].folded_evaluations[0] += SecureField::from(1u32);
        assert!(matches!(
            FriFoldWitness::new(&tampered_fold, &fold_public),
            Err(FriSemanticAirError::FoldWitnessMismatch)
        ));
    }
}
