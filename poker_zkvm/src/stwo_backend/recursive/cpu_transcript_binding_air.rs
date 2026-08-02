//! Fixed `CpuV1` transcript usage-point bindings.
//!
//! The canonical transcript AIR exports every externally meaningful absorbed value and every
//! challenge/PoW result through LogUp relations. This component consumes the exact fixed `CpuV1`
//! schedule reconstructed from the recursive statement and the committed semantic claim. The
//! table is preprocessed because every row is verifier-known before the recursive trace is opened.

use core::array;
use std::collections::BTreeSet;

use starknet_ff::FieldElement as FieldElement252;
use stwo::core::channel::Channel;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::queries::{Queries, draw_queries};
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_cairo_common::prover_types::cpu::FELT252_N_WORDS;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
};

use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;

use super::poseidon252_air::{N_KIND_SELECTORS, field_element_to_9_bit_limbs, kind_index};
use super::poseidon252_replay::{Poseidon252CallKind, RecordingPoseidon252Channel};
use super::public_inputs::RecursivePublicInputs;
use super::transcript_air::{TRANSCRIPT_DRAW_RESULT_RELATION_ID, TRANSCRIPT_PAYLOAD_RELATION_ID};

const N_BINDING_METADATA_COLUMNS: usize = 5 + N_KIND_SELECTORS;
const ACTIVE_COLUMN: usize = 0;
const PAYLOAD_COLUMN: usize = 1;
const RESULT_COLUMN: usize = 2;
const EVENT_INDEX_COLUMN: usize = 3;
const PAYLOAD_INDEX_COLUMN: usize = 4;
const KIND_COLUMNS_START: usize = 5;
const VALUE_COLUMNS_START: usize = KIND_COLUMNS_START + N_KIND_SELECTORS;
const CPU_TRANSCRIPT_BINDING_NUM_COLUMNS: usize = N_BINDING_METADATA_COLUMNS + FELT252_N_WORDS;

pub(crate) const CPU_TRANSCRIPT_BINDING_INTERACTION_COLUMNS: usize = 4;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CpuTranscriptBindingError {
    #[error("CpuV1 transcript binding requires PcsConfig::default()")]
    InvalidConfig,
    #[error("CpuV1 transcript binding requires exactly three L1 commitment roots")]
    InvalidCommitments,
    #[error(
        "CpuV1 transcript binding sampled-value count mismatch: expected {expected}, got {actual}"
    )]
    InvalidSampleCount { expected: usize, actual: usize },
    #[error(
        "CpuV1 transcript binding draw-result count mismatch: expected {expected}, got {actual}"
    )]
    InvalidDrawCount { expected: usize, actual: usize },
    #[error("CpuV1 transcript-derived challenge does not match the recursive statement")]
    ChallengeMismatch,
    #[error("CpuV1 transcript-derived query positions do not match the recursive statement")]
    QueryPositionsMismatch,
    #[error("CpuV1 transcript PoW result does not satisfy the configured difficulty")]
    InvalidProofOfWork,
    #[error("CpuV1 transcript binding metadata does not fit M31")]
    MetadataOverflow,
    #[error("recursive statement transcript does not match the selected verifier program")]
    StatementTranscriptMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingKind {
    Payload,
    Result,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingRow {
    kind: BindingKind,
    event_index: usize,
    payload_index: usize,
    event_kind: Poseidon252CallKind,
    value: FieldElement252,
}

impl BindingRow {
    fn flat(
        &self,
    ) -> Result<[BaseField; CPU_TRANSCRIPT_BINDING_NUM_COLUMNS], CpuTranscriptBindingError> {
        let mut row = [BaseField::from(0u32); CPU_TRANSCRIPT_BINDING_NUM_COLUMNS];
        row[ACTIVE_COLUMN] = BaseField::from(1u32);
        match self.kind {
            BindingKind::Payload => row[PAYLOAD_COLUMN] = BaseField::from(1u32),
            BindingKind::Result => row[RESULT_COLUMN] = BaseField::from(1u32),
        }
        row[EVENT_INDEX_COLUMN] = to_field(self.event_index)?;
        row[PAYLOAD_INDEX_COLUMN] = to_field(self.payload_index)?;
        row[KIND_COLUMNS_START + kind_index(self.event_kind)] = BaseField::from(1u32);
        row[VALUE_COLUMNS_START..].copy_from_slice(&field_element_to_9_bit_limbs(self.value));
        Ok(row)
    }
}

pub(crate) struct CpuTranscriptBindingWitness {
    pub n_rows: usize,
    pub log_size: u32,
    rows: Vec<[BaseField; CPU_TRANSCRIPT_BINDING_NUM_COLUMNS]>,
}

impl CpuTranscriptBindingWitness {
    pub(crate) fn new(
        public_inputs: &RecursivePublicInputs,
        sampled_values: &[SecureField],
        draw_results: &[FieldElement252],
        proof_of_work: u64,
        pow_hash: FieldElement252,
    ) -> Result<Self, CpuTranscriptBindingError> {
        if public_inputs.verifier_program
            == super::public_inputs::RecursiveVerifierProgram::ReplicatedRowV1
        {
            return Self::new_replicated_row(
                public_inputs,
                sampled_values,
                draw_results,
                proof_of_work,
                pow_hash,
            );
        }
        if !public_inputs.statement_transcript.is_empty() {
            return Err(CpuTranscriptBindingError::StatementTranscriptMismatch);
        }
        if public_inputs.config != PcsConfig::default() {
            return Err(CpuTranscriptBindingError::InvalidConfig);
        }
        if public_inputs.l1_commitments.len() != 3 {
            return Err(CpuTranscriptBindingError::InvalidCommitments);
        }
        let expected_sample_count = NUM_COLUMNS + 2 * SECURE_EXTENSION_DEGREE;
        if sampled_values.len() != expected_sample_count {
            return Err(CpuTranscriptBindingError::InvalidSampleCount {
                expected: expected_sample_count,
                actual: sampled_values.len(),
            });
        }
        let expected_draw_count = 5 + public_inputs.fri_inner_layer_commitments.len();
        if draw_results.len() != expected_draw_count {
            return Err(CpuTranscriptBindingError::InvalidDrawCount {
                expected: expected_draw_count,
                actual: draw_results.len(),
            });
        }

        if secure_field_from_draw_result(draw_results[0], 0)
            != public_inputs.composition_random_coeff
            || secure_field_from_draw_result(draw_results[2], 0)
                != public_inputs.fri_quotient_random_coeff
            || circle_point_from_draw_result(draw_results[1]) != public_inputs.oods_point
        {
            return Err(CpuTranscriptBindingError::ChallengeMismatch);
        }
        let query_draw = *draw_results.last().expect("draw count was checked");
        if query_positions_from_draw_result(query_draw, public_inputs)?
            != public_inputs.query_positions
        {
            return Err(CpuTranscriptBindingError::QueryPositionsMismatch);
        }
        if !pow_hash_is_valid(pow_hash, public_inputs.config.pow_bits) {
            return Err(CpuTranscriptBindingError::InvalidProofOfWork);
        }

        let mut rows = Vec::new();
        let mut event_index = 0usize;
        let mut draw_index = 0usize;

        let push_payload = |rows: &mut Vec<BindingRow>,
                            event_index: usize,
                            event_kind: Poseidon252CallKind,
                            payload_index: usize,
                            value: FieldElement252| {
            rows.push(BindingRow {
                kind: BindingKind::Payload,
                event_index,
                payload_index,
                event_kind,
                value,
            });
        };
        let push_result = |rows: &mut Vec<BindingRow>,
                           event_index: usize,
                           event_kind: Poseidon252CallKind,
                           value: FieldElement252| {
            rows.push(BindingRow {
                kind: BindingKind::Result,
                event_index,
                payload_index: 0,
                event_kind,
                value,
            });
        };

        for root in &public_inputs.l1_commitments[..2] {
            push_payload(
                &mut rows,
                event_index,
                Poseidon252CallKind::TranscriptMixRoot,
                1,
                *root,
            );
            event_index += 1;
        }
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptDraw,
            draw_results[draw_index],
        );
        draw_index += 1;
        event_index += 1;

        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptMixRoot,
            1,
            public_inputs.l1_commitments[2],
        );
        event_index += 1;
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptDraw,
            draw_results[draw_index],
        );
        draw_index += 1;
        event_index += 1;

        for (payload_index, value) in pack_secure_fields(sampled_values).into_iter().enumerate() {
            push_payload(
                &mut rows,
                event_index,
                Poseidon252CallKind::TranscriptMixFelts,
                payload_index + 1,
                value,
            );
        }
        event_index += 1;
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptDraw,
            draw_results[draw_index],
        );
        draw_index += 1;
        event_index += 1;

        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptMixRoot,
            1,
            public_inputs.fri_first_layer_commitment,
        );
        event_index += 1;
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptDraw,
            draw_results[draw_index],
        );
        draw_index += 1;
        event_index += 1;

        for root in &public_inputs.fri_inner_layer_commitments {
            push_payload(
                &mut rows,
                event_index,
                Poseidon252CallKind::TranscriptMixRoot,
                1,
                *root,
            );
            event_index += 1;
            push_result(
                &mut rows,
                event_index,
                Poseidon252CallKind::TranscriptDraw,
                draw_results[draw_index],
            );
            draw_index += 1;
            event_index += 1;
        }

        for (payload_index, value) in pack_secure_fields(&public_inputs.fri_last_layer_poly[..])
            .into_iter()
            .enumerate()
        {
            push_payload(
                &mut rows,
                event_index,
                Poseidon252CallKind::TranscriptMixFelts,
                payload_index + 1,
                value,
            );
        }
        event_index += 1;
        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptPowPrefix,
            0,
            FieldElement252::from(RecordingPoseidon252Channel::POW_PREFIX),
        );
        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptPowPrefix,
            2,
            FieldElement252::from(public_inputs.config.pow_bits),
        );
        event_index += 1;
        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptPowNonce,
            1,
            FieldElement252::from(proof_of_work),
        );
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptPowNonce,
            pow_hash,
        );
        event_index += 1;
        push_payload(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptMixU64,
            1,
            FieldElement252::from(proof_of_work),
        );
        event_index += 1;
        push_result(
            &mut rows,
            event_index,
            Poseidon252CallKind::TranscriptDraw,
            draw_results[draw_index],
        );
        draw_index += 1;
        debug_assert_eq!(draw_index, draw_results.len());

        let n_rows = rows.len();
        let padded_size = n_rows.next_power_of_two().max(N_LANES);
        let log_size = padded_size.ilog2();
        let mut flat_rows = rows
            .iter()
            .map(BindingRow::flat)
            .collect::<Result<Vec<_>, _>>()?;
        flat_rows.resize(
            padded_size,
            [BaseField::from(0u32); CPU_TRANSCRIPT_BINDING_NUM_COLUMNS],
        );
        Ok(Self {
            n_rows,
            log_size,
            rows: flat_rows,
        })
    }

    fn new_replicated_row(
        public_inputs: &RecursivePublicInputs,
        sampled_values: &[SecureField],
        draw_results: &[FieldElement252],
        proof_of_work: u64,
        pow_hash: FieldElement252,
    ) -> Result<Self, CpuTranscriptBindingError> {
        if public_inputs.config != PcsConfig::default() {
            return Err(CpuTranscriptBindingError::InvalidConfig);
        }
        if public_inputs.l1_commitments.len() != 3 || public_inputs.l1_tree_metadata.len() != 3 {
            return Err(CpuTranscriptBindingError::InvalidCommitments);
        }
        let expected_sample_count =
            public_inputs.l1_tree_metadata[1].column_log_sizes.len() + 2 * SECURE_EXTENSION_DEGREE;
        if sampled_values.len() != expected_sample_count {
            return Err(CpuTranscriptBindingError::InvalidSampleCount {
                expected: expected_sample_count,
                actual: sampled_values.len(),
            });
        }
        let expected_draw_count = 5 + public_inputs.fri_inner_layer_commitments.len();
        if draw_results.len() != expected_draw_count {
            return Err(CpuTranscriptBindingError::InvalidDrawCount {
                expected: expected_draw_count,
                actual: draw_results.len(),
            });
        }

        let mut channel = RecordingPoseidon252Channel::default();
        public_inputs.replay_statement_transcript(&mut channel);
        for root in &public_inputs.l1_commitments[..2] {
            channel.mix_root(*root);
        }
        let composition_random_coeff = channel.draw_secure_felt();
        channel.mix_root(public_inputs.l1_commitments[2]);
        let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
        channel.mix_felts(sampled_values);
        let fri_quotient_random_coeff = channel.draw_secure_felt();
        channel.mix_root(public_inputs.fri_first_layer_commitment);
        let _first_alpha = channel.draw_secure_felt();
        for root in &public_inputs.fri_inner_layer_commitments {
            channel.mix_root(*root);
            let _inner_alpha = channel.draw_secure_felt();
        }
        channel.mix_felts(&public_inputs.fri_last_layer_poly[..]);
        if !channel.verify_pow_nonce(public_inputs.config.pow_bits, proof_of_work) {
            return Err(CpuTranscriptBindingError::InvalidProofOfWork);
        }
        channel.mix_u64(proof_of_work);
        let first_layer_log_size = public_inputs
            .max_log_degree_bound
            .checked_add(public_inputs.config.fri_config.log_blowup_factor)
            .ok_or(CpuTranscriptBindingError::MetadataOverflow)?;
        let raw_query_positions = draw_queries(
            &mut channel,
            first_layer_log_size,
            public_inputs.config.fri_config.n_queries,
        );
        let query_positions = Queries::new(&raw_query_positions, first_layer_log_size).positions;
        if composition_random_coeff != public_inputs.composition_random_coeff
            || oods_point != public_inputs.oods_point
            || fri_quotient_random_coeff != public_inputs.fri_quotient_random_coeff
        {
            return Err(CpuTranscriptBindingError::ChallengeMismatch);
        }
        if query_positions != public_inputs.query_positions {
            return Err(CpuTranscriptBindingError::QueryPositionsMismatch);
        }

        let events = channel.events();
        let actual_draw_results = events
            .iter()
            .filter(|event| event.kind == Poseidon252CallKind::TranscriptDraw)
            .map(|event| event.result)
            .collect::<Vec<_>>();
        let actual_pow_hash = events
            .iter()
            .find(|event| event.kind == Poseidon252CallKind::TranscriptPowNonce)
            .map(|event| event.result)
            .ok_or(CpuTranscriptBindingError::InvalidProofOfWork)?;
        if actual_draw_results != draw_results || actual_pow_hash != pow_hash {
            return Err(CpuTranscriptBindingError::ChallengeMismatch);
        }

        let mut binding_rows = Vec::new();
        for event in &events {
            let mut push_payload = |payload_index: usize, value: FieldElement252| {
                binding_rows.push(BindingRow {
                    kind: BindingKind::Payload,
                    event_index: event.event_index,
                    payload_index,
                    event_kind: event.kind,
                    value,
                });
            };
            match event.kind {
                Poseidon252CallKind::TranscriptMixRoot | Poseidon252CallKind::TranscriptMixU64 => {
                    let value = *event
                        .absorbed_values
                        .get(1)
                        .ok_or(CpuTranscriptBindingError::StatementTranscriptMismatch)?;
                    push_payload(1, value);
                }
                Poseidon252CallKind::TranscriptMixFelts
                | Poseidon252CallKind::TranscriptMixU32s => {
                    // hash_many's first absorbed felt is its internal length/domain element.  The
                    // transcript semantic AIR derives that value from the event shape and exports
                    // only caller-controlled payloads, at one-based payload indices.
                    for (index, value) in event.absorbed_values.iter().copied().skip(1).enumerate()
                    {
                        push_payload(index + 1, value);
                    }
                }
                Poseidon252CallKind::TranscriptDraw => binding_rows.push(BindingRow {
                    kind: BindingKind::Result,
                    event_index: event.event_index,
                    payload_index: 0,
                    event_kind: event.kind,
                    value: event.result,
                }),
                Poseidon252CallKind::TranscriptPowPrefix => {
                    let prefix = *event
                        .absorbed_values
                        .first()
                        .ok_or(CpuTranscriptBindingError::StatementTranscriptMismatch)?;
                    let bits = *event
                        .absorbed_values
                        .get(2)
                        .ok_or(CpuTranscriptBindingError::StatementTranscriptMismatch)?;
                    push_payload(0, prefix);
                    push_payload(2, bits);
                }
                Poseidon252CallKind::TranscriptPowNonce => {
                    let nonce = *event
                        .absorbed_values
                        .get(1)
                        .ok_or(CpuTranscriptBindingError::StatementTranscriptMismatch)?;
                    push_payload(1, nonce);
                    binding_rows.push(BindingRow {
                        kind: BindingKind::Result,
                        event_index: event.event_index,
                        payload_index: 0,
                        event_kind: event.kind,
                        value: event.result,
                    });
                }
                Poseidon252CallKind::MerkleLeafAbsorb
                | Poseidon252CallKind::MerkleLeafFinalize
                | Poseidon252CallKind::MerkleParent => {
                    return Err(CpuTranscriptBindingError::StatementTranscriptMismatch);
                }
            }
        }

        let n_rows = binding_rows.len();
        let padded_size = n_rows.next_power_of_two().max(N_LANES);
        let log_size = padded_size.ilog2();
        let mut rows = binding_rows
            .iter()
            .map(BindingRow::flat)
            .collect::<Result<Vec<_>, _>>()?;
        rows.resize(
            padded_size,
            [BaseField::from(0u32); CPU_TRANSCRIPT_BINDING_NUM_COLUMNS],
        );
        Ok(Self {
            n_rows,
            log_size,
            rows,
        })
    }

    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        let domain = CanonicCoset::new(self.log_size).circle_domain();
        (0..CPU_TRANSCRIPT_BINDING_NUM_COLUMNS)
            .map(|column| {
                let values = self.rows.iter().map(|row| row[column]).collect::<Vec<_>>();
                let values = into_bit_reversed_circle_order(&values, self.log_size);
                (
                    binding_preprocessed_id(column, self.log_size, self.n_rows),
                    CircleEvaluation::new(domain, BaseColumn::from_cpu(&values)),
                )
            })
            .unzip()
    }

    pub(crate) fn write_interaction_trace(
        &self,
        common_lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (_, preprocessed) = self.preprocessed_columns();
        let n_vec_rows = 1usize << (self.log_size - LOG_N_LANES);
        let payload_relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            TRANSCRIPT_PAYLOAD_RELATION_ID,
        ));
        let result_relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            TRANSCRIPT_DRAW_RESULT_RELATION_ID,
        ));
        let mut logup = LogupTraceGenerator::new(self.log_size);
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let payload_active =
                PackedSecureField::from(preprocessed[PAYLOAD_COLUMN].values.data[vec_row]);
            let result_active =
                PackedSecureField::from(preprocessed[RESULT_COLUMN].values.data[vec_row]);
            let mut payload_values = Vec::with_capacity(3 + N_KIND_SELECTORS + FELT252_N_WORDS);
            payload_values.push(payload_relation_id);
            payload_values.push(preprocessed[EVENT_INDEX_COLUMN].values.data[vec_row]);
            payload_values.push(preprocessed[PAYLOAD_INDEX_COLUMN].values.data[vec_row]);
            payload_values.extend(
                preprocessed[KIND_COLUMNS_START..VALUE_COLUMNS_START]
                    .iter()
                    .map(|column| column.values.data[vec_row]),
            );
            payload_values.extend(
                preprocessed[VALUE_COLUMNS_START..]
                    .iter()
                    .map(|column| column.values.data[vec_row]),
            );
            let mut result_values = Vec::with_capacity(2 + N_KIND_SELECTORS + FELT252_N_WORDS);
            result_values.push(result_relation_id);
            result_values.push(preprocessed[EVENT_INDEX_COLUMN].values.data[vec_row]);
            result_values.extend(
                preprocessed[KIND_COLUMNS_START..VALUE_COLUMNS_START]
                    .iter()
                    .map(|column| column.values.data[vec_row]),
            );
            result_values.extend(
                preprocessed[VALUE_COLUMNS_START..]
                    .iter()
                    .map(|column| column.values.data[vec_row]),
            );
            let payload_denominator: PackedSecureField =
                common_lookup_elements.combine(&payload_values);
            let result_denominator: PackedSecureField =
                common_lookup_elements.combine(&result_values);
            let numerator: PackedSecureField =
                payload_active * result_denominator + result_active * payload_denominator;
            column.write_frac(
                vec_row,
                -numerator,
                payload_denominator * result_denominator,
            );
        }
        column.finalize_col();
        logup.finalize_last()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CpuTranscriptBindingAir {
    log_size: u32,
    n_rows: usize,
    common_lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl CpuTranscriptBindingAir {
    pub(crate) const fn new(
        log_size: u32,
        n_rows: usize,
        common_lookup_elements: cairo_air::relations::CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_rows,
            common_lookup_elements,
        }
    }
}

impl FrameworkEval for CpuTranscriptBindingAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.get_preprocessed_column(binding_preprocessed_id(
            ACTIVE_COLUMN,
            self.log_size,
            self.n_rows,
        ));
        let payload = eval.get_preprocessed_column(binding_preprocessed_id(
            PAYLOAD_COLUMN,
            self.log_size,
            self.n_rows,
        ));
        let result = eval.get_preprocessed_column(binding_preprocessed_id(
            RESULT_COLUMN,
            self.log_size,
            self.n_rows,
        ));
        let event_index = eval.get_preprocessed_column(binding_preprocessed_id(
            EVENT_INDEX_COLUMN,
            self.log_size,
            self.n_rows,
        ));
        let payload_index = eval.get_preprocessed_column(binding_preprocessed_id(
            PAYLOAD_INDEX_COLUMN,
            self.log_size,
            self.n_rows,
        ));
        let kind_selectors: [E::F; N_KIND_SELECTORS] = array::from_fn(|offset| {
            eval.get_preprocessed_column(binding_preprocessed_id(
                KIND_COLUMNS_START + offset,
                self.log_size,
                self.n_rows,
            ))
        });
        let value = (0..FELT252_N_WORDS)
            .map(|offset| {
                eval.get_preprocessed_column(binding_preprocessed_id(
                    VALUE_COLUMNS_START + offset,
                    self.log_size,
                    self.n_rows,
                ))
            })
            .collect::<Vec<_>>();
        let one = E::F::from(BaseField::from(1u32));
        eval.add_constraint(payload.clone() * result.clone());
        eval.add_constraint(payload.clone() + result.clone() - active.clone());

        let mut payload_values = Vec::with_capacity(3 + N_KIND_SELECTORS + FELT252_N_WORDS);
        payload_values.push(E::F::from(BaseField::from_u32_unchecked(
            TRANSCRIPT_PAYLOAD_RELATION_ID,
        )));
        payload_values.push(event_index.clone());
        payload_values.push(payload_index);
        payload_values.extend(kind_selectors.iter().cloned());
        payload_values.extend(value.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(payload),
            &payload_values,
        ));

        let mut result_values = Vec::with_capacity(2 + N_KIND_SELECTORS + FELT252_N_WORDS);
        result_values.push(E::F::from(BaseField::from_u32_unchecked(
            TRANSCRIPT_DRAW_RESULT_RELATION_ID,
        )));
        result_values.push(event_index);
        result_values.extend(kind_selectors);
        result_values.extend(value);
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(result),
            &result_values,
        ));
        eval.add_constraint(active.clone() * (one - active));
        eval.finalize_logup_in_pairs();
        eval
    }
}

pub(crate) fn mix_cpu_transcript_claim(
    channel: &mut impl Channel,
    sampled_values: &[SecureField],
    draw_results: &[FieldElement252],
    proof_of_work: u64,
    pow_hash: FieldElement252,
) {
    channel.mix_u64(u64::try_from(sampled_values.len()).expect("sample count fits u64"));
    channel.mix_felts(sampled_values);
    channel.mix_u64(u64::try_from(draw_results.len()).expect("draw count fits u64"));
    for result in draw_results {
        mix_felt252(channel, result);
    }
    channel.mix_u64(proof_of_work);
    mix_felt252(channel, &pow_hash);
}

fn binding_preprocessed_id(column: usize, log_size: u32, n_rows: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_cpu_transcript_binding_{column}_{log_size}_{n_rows}"),
    }
}

fn into_bit_reversed_circle_order(values: &[BaseField], log_size: u32) -> Vec<BaseField> {
    let mut ordered = vec![BaseField::from(0u32); values.len()];
    for (coset_index, value) in values.iter().copied().enumerate() {
        let circle_index = coset_index_to_circle_domain_index(coset_index, log_size);
        let row = bit_reverse_index(circle_index, log_size);
        ordered[row] = value;
    }
    ordered
}

fn to_field(value: usize) -> Result<BaseField, CpuTranscriptBindingError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value < 0x7fff_ffff)
        .map(BaseField::from_u32_unchecked)
        .ok_or(CpuTranscriptBindingError::MetadataOverflow)
}

fn pack_secure_fields(values: &[SecureField]) -> Vec<FieldElement252> {
    let shift = FieldElement252::from(1u64 << 31);
    values
        .chunks(2)
        .map(|chunk| {
            chunk
                .iter()
                .flat_map(|value| value.to_m31_array())
                .fold(FieldElement252::ONE, |acc, limb| {
                    acc * shift + FieldElement252::from(limb.0)
                })
        })
        .collect()
}

pub(crate) fn secure_field_from_draw_result(
    result: FieldElement252,
    secure_index: usize,
) -> SecureField {
    SecureField::from_m31_array(array::from_fn(|index| {
        BaseField::reduce(u64::from(extract_bits(
            result,
            31 * (SECURE_EXTENSION_DEGREE * secure_index + index),
            31,
        )))
    }))
}

fn circle_point_from_draw_result(result: FieldElement252) -> CirclePoint<SecureField> {
    let parameter = secure_field_from_draw_result(result, 0);
    let square = parameter * parameter;
    let inverse = (square + SecureField::from(1u32)).inverse();
    CirclePoint {
        x: (SecureField::from(1u32) - square) * inverse,
        y: (parameter + parameter) * inverse,
    }
}

fn query_positions_from_draw_result(
    result: FieldElement252,
    public_inputs: &RecursivePublicInputs,
) -> Result<Vec<usize>, CpuTranscriptBindingError> {
    let domain_log_size = public_inputs
        .max_log_degree_bound
        .checked_add(public_inputs.config.fri_config.log_blowup_factor)
        .ok_or(CpuTranscriptBindingError::MetadataOverflow)?;
    let log_domain_size = CanonicCoset::new(domain_log_size)
        .circle_domain()
        .log_size();
    let mask = (1u32 << log_domain_size) - 1;
    let positions = (0..public_inputs.config.fri_config.n_queries)
        .map(|index| usize::try_from(extract_bits(result, 32 * index, 32) & mask).unwrap())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(positions)
}

fn extract_bits(value: FieldElement252, start: usize, count: usize) -> u32 {
    debug_assert!(count <= 32 && start + count <= 252);
    let mut bytes = value.to_bytes_be();
    bytes.reverse();
    let mut result = 0u32;
    for bit in 0..count {
        let absolute = start + bit;
        let value = (bytes[absolute / 8] >> (absolute % 8)) & 1;
        result |= u32::from(value) << bit;
    }
    result
}

fn pow_hash_is_valid(hash: FieldElement252, n_bits: u32) -> bool {
    let bytes = hash.to_bytes_be();
    u128::from_be_bytes(bytes[16..].try_into().unwrap()).trailing_zeros() >= n_bits
}

fn mix_felt252(channel: &mut impl Channel, value: &FieldElement252) {
    let bytes = value.to_bytes_be();
    let words: [u32; 8] = array::from_fn(|index| {
        let offset = index * 4;
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    });
    channel.mix_u32s(&words);
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::sync::OnceLock;

    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{
        FrameworkComponent, PREPROCESSED_TRACE_IDX, TraceLocationAllocator,
        assert_constraints_on_trace,
    };

    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::fri_semantic_air::{
        FriFoldPublicWitness, FriFoldWitness, PcsQuotientPublicWitness, PcsQuotientWitness,
    };
    use crate::stwo_backend::recursive::merkle_leaf_air::{
        MerkleLeafPackingWitness, MerkleLeafPublicWitness,
    };
    use crate::stwo_backend::recursive::merkle_semantic_air::{
        MerklePublicBindingWitness, MerkleSemanticWitness,
    };
    use crate::stwo_backend::recursive::poseidon252_air::Poseidon252ClosureWitness;
    use crate::stwo_backend::recursive::replay_witness::CanonicalVerifierWitness;
    use crate::stwo_backend::recursive::transcript_air::{
        TranscriptSemanticWitness, ensure_lookup_balanced, transcript_payload_values,
    };
    use crate::stwo_backend::recursive::verifier_program::{
        build_cpu_recursive_public_inputs, replay_cpu_verifier,
    };
    use crate::stwo_backend::trace_native::TraceBuilder;

    struct Fixture {
        public_inputs: RecursivePublicInputs,
        canonical: CanonicalVerifierWitness,
        sampled_values: Vec<SecureField>,
        draw_results: Vec<FieldElement252>,
        proof_of_work: u64,
        pow_hash: FieldElement252,
    }

    fn fixture() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
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
                .collect();
            let pow_hash = canonical
                .transcript_events
                .iter()
                .find(|event| event.kind == Poseidon252CallKind::TranscriptPowNonce)
                .unwrap()
                .result;
            Fixture {
                public_inputs,
                canonical,
                sampled_values,
                draw_results,
                proof_of_work: proof.0.proof_of_work,
                pow_hash,
            }
        })
    }

    fn lookup_sums(fixture: &Fixture, binding: &CpuTranscriptBindingWitness) -> [SecureField; 8] {
        let payloads = transcript_payload_values(&fixture.canonical.transcript_events);
        let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
            &fixture.canonical.poseidon_calls,
            &payloads,
        )
        .unwrap();
        let transcript = TranscriptSemanticWitness::new(
            &fixture.canonical.transcript_events,
            &fixture.canonical.transcript_calls,
            &fixture.canonical.poseidon_calls,
            &poseidon.synthetic_memory.call_ids,
            &poseidon.synthetic_memory.extra_ids,
        )
        .unwrap();
        let merkle_binding = MerklePublicBindingWitness::new(&fixture.public_inputs).unwrap();
        let merkle = MerkleSemanticWitness::new(
            &fixture.canonical,
            &merkle_binding,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let merkle_leaf_public = MerkleLeafPublicWitness::new(&merkle_binding).unwrap();
        let merkle_leaf = MerkleLeafPackingWitness::new(
            &fixture.canonical,
            &merkle_leaf_public,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let quotient_public =
            PcsQuotientPublicWitness::new(&fixture.public_inputs, &fixture.sampled_values).unwrap();
        let quotient = PcsQuotientWitness::new(&fixture.canonical, &quotient_public).unwrap();
        let fri_fold_public =
            FriFoldPublicWitness::new(&fixture.public_inputs, &fixture.draw_results).unwrap();
        let fri_fold = FriFoldWitness::new(&fixture.canonical, &fri_fold_public).unwrap();
        let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
        let poseidon = poseidon.write_interaction_trace(&lookup_elements).unwrap();
        let (_, transcript_sum) = transcript.write_interaction_trace(&lookup_elements);
        let (_, binding_sum) = binding.write_interaction_trace(&lookup_elements);
        let (_, merkle_sum) = merkle.write_interaction_trace(&lookup_elements);
        let (_, merkle_binding_sum) = merkle_binding.write_interaction_trace(&lookup_elements);
        let (_, merkle_leaf_sum) =
            merkle_leaf.write_interaction_trace(&merkle_leaf_public, &lookup_elements);
        let (_, quotient_sum) =
            quotient.write_interaction_trace(&quotient_public, &lookup_elements);
        let (_, fri_fold_sum) =
            fri_fold.write_interaction_trace(&fri_fold_public, &lookup_elements);
        [
            poseidon.lookup_residual,
            transcript_sum,
            binding_sum,
            merkle_sum,
            merkle_binding_sum,
            merkle_leaf_sum,
            quotient_sum,
            fri_fold_sum,
        ]
    }

    fn assert_component(
        component: &FrameworkComponent<CpuTranscriptBindingAir>,
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
    fn fixed_cpu_transcript_usage_lookups_close_globally() {
        let fixture = fixture();
        let binding = CpuTranscriptBindingWitness::new(
            &fixture.public_inputs,
            &fixture.sampled_values,
            &fixture.draw_results,
            fixture.proof_of_work,
            fixture.pow_hash,
        )
        .unwrap();
        let [
            poseidon,
            transcript,
            binding,
            merkle,
            merkle_binding,
            merkle_leaf,
            quotient,
            fri_fold,
        ] = lookup_sums(&fixture, &binding);
        ensure_lookup_balanced(
            poseidon,
            &[
                transcript,
                binding,
                merkle,
                merkle_binding,
                merkle_leaf,
                quotient,
                fri_fold,
            ],
        )
        .unwrap();
    }

    #[test]
    fn fixed_cpu_transcript_binding_component_satisfies_air() {
        let fixture = fixture();
        let binding = CpuTranscriptBindingWitness::new(
            &fixture.public_inputs,
            &fixture.sampled_values,
            &fixture.draw_results,
            fixture.proof_of_work,
            fixture.pow_hash,
        )
        .unwrap();
        let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
        let (ids, preprocessed) = binding.preprocessed_columns();
        let (interaction, claimed_sum) = binding.write_interaction_trace(&lookup_elements);
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let component = FrameworkComponent::new(
            &mut allocator,
            CpuTranscriptBindingAir::new(binding.log_size, binding.n_rows, lookup_elements),
            claimed_sum,
        );
        let trace = TreeVec::new(vec![
            preprocessed
                .into_iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
            vec![],
            interaction
                .into_iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
        ]);
        assert_component(&component, &trace.as_cols_ref());
    }

    #[test]
    fn fixed_cpu_transcript_usage_rejects_root_and_sample_relabelling() {
        let fixture = fixture();
        let mut changed_inputs = fixture.public_inputs.clone();
        changed_inputs.l1_commitments[1] += FieldElement252::ONE;
        let changed_binding = CpuTranscriptBindingWitness::new(
            &changed_inputs,
            &fixture.sampled_values,
            &fixture.draw_results,
            fixture.proof_of_work,
            fixture.pow_hash,
        )
        .unwrap();
        let [
            poseidon,
            transcript,
            binding,
            merkle,
            merkle_binding,
            merkle_leaf,
            quotient,
            fri_fold,
        ] = lookup_sums(&fixture, &changed_binding);
        assert!(
            ensure_lookup_balanced(
                poseidon,
                &[
                    transcript,
                    binding,
                    merkle,
                    merkle_binding,
                    merkle_leaf,
                    quotient,
                    fri_fold,
                ],
            )
            .is_err()
        );

        let mut changed_samples = fixture.sampled_values.clone();
        changed_samples[0] += SecureField::from(1u32);
        let changed_binding = CpuTranscriptBindingWitness::new(
            &fixture.public_inputs,
            &changed_samples,
            &fixture.draw_results,
            fixture.proof_of_work,
            fixture.pow_hash,
        )
        .unwrap();
        let [
            poseidon,
            transcript,
            binding,
            merkle,
            merkle_binding,
            merkle_leaf,
            quotient,
            fri_fold,
        ] = lookup_sums(&fixture, &changed_binding);
        assert!(
            ensure_lookup_balanced(
                poseidon,
                &[
                    transcript,
                    binding,
                    merkle,
                    merkle_binding,
                    merkle_leaf,
                    quotient,
                    fri_fold,
                ],
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_cpu_transcript_usage_rejects_challenge_query_and_pow_relabelling() {
        let fixture = fixture();
        let mut changed_inputs = fixture.public_inputs.clone();
        changed_inputs.composition_random_coeff += SecureField::from(1u32);
        assert!(matches!(
            CpuTranscriptBindingWitness::new(
                &changed_inputs,
                &fixture.sampled_values,
                &fixture.draw_results,
                fixture.proof_of_work,
                fixture.pow_hash,
            ),
            Err(CpuTranscriptBindingError::ChallengeMismatch)
        ));

        let mut changed_inputs = fixture.public_inputs.clone();
        changed_inputs.query_positions[0] ^= 1;
        assert!(matches!(
            CpuTranscriptBindingWitness::new(
                &changed_inputs,
                &fixture.sampled_values,
                &fixture.draw_results,
                fixture.proof_of_work,
                fixture.pow_hash,
            ),
            Err(CpuTranscriptBindingError::QueryPositionsMismatch)
        ));

        assert!(matches!(
            CpuTranscriptBindingWitness::new(
                &fixture.public_inputs,
                &fixture.sampled_values,
                &fixture.draw_results,
                fixture.proof_of_work,
                FieldElement252::ONE,
            ),
            Err(CpuTranscriptBindingError::InvalidProofOfWork)
        ));
    }
}
