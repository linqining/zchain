//! Semantic AIR for Stwo's compressed multi-query Merkle replay.
//!
//! The fixed public binding table derives every leaf position, parent position, compressed
//! sibling position and call kind from the recursive statement. The committed semantic table
//! consumes the canonical Poseidon252 router calls, closes the full-width felt252 node multiset,
//! and binds every computed root to the public PCS/FRI commitments.
//!
//! Leaf-row packing is delegated to `merkle_leaf_air`: this module exports every leaf call with
//! verifier-fixed value ranges, while the leaf component proves the M31 packing and sponge-state
//! additions that construct those calls.

use std::collections::{BTreeSet, HashMap, HashSet};

use cairo_air::relations::MEMORY_ID_TO_BIG_RELATION_ID;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::verifier::LOG_PACKED_LEAF_SIZE;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_cairo_common::prover_types::cpu::{FELT252_N_WORDS, M31};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
};

use super::poseidon252_air::{
    MERKLE_POSEIDON_CALL_RELATION_ID, N_CALL_IDS, SyntheticPoseidonCallIds,
    field_element_to_9_bit_limbs,
};
use super::poseidon252_replay::Poseidon252CallKind;
use super::public_inputs::RecursivePublicInputs;
use super::replay_witness::{
    CanonicalMerkleNodeUseKind, CanonicalVerifierWitness, PoseidonCallSource,
};

const MERKLE_SCHEDULE_RELATION_ID: u32 = 1_990_310_001;
pub(crate) const MERKLE_LEAF_CALL_RELATION_ID: u32 = 1_990_310_002;
const MERKLE_NODE_RELATION_ID: u32 = 1_990_310_003;
pub(crate) const MERKLE_QUERIED_VALUE_RELATION_ID: u32 = 1_990_310_004;

const ACTIVE_COLUMN: usize = 0;
const CALL_ACTIVE_COLUMN: usize = 1;
const WITNESS_ACTIVE_COLUMN: usize = 2;
const PCS_SOURCE_COLUMN: usize = 3;
const FRI_SOURCE_COLUMN: usize = 4;
const SOURCE_ARG_COLUMN: usize = 5;
const SOURCE_INDEX_COLUMN: usize = 6;
const LEAF_ABSORB_COLUMN: usize = 7;
const LEAF_FINALIZE_COLUMN: usize = 8;
const PARENT_COLUMN: usize = 9;
const LEAF_CALL_INDEX_COLUMN: usize = 10;
const LEAF_CALL_COUNT_COLUMN: usize = 11;
const LAYER_COLUMN: usize = 12;
const NODE_INDEX_COLUMN: usize = 13;
const LEAF_VALUE_START_COLUMN: usize = 14;
const LEAF_VALUE_COUNT_COLUMN: usize = 15;
const CALL_ID_COLUMNS_START: usize = 16;
const CALL_VALUE_COLUMNS_START: usize = CALL_ID_COLUMNS_START + N_CALL_IDS;
const N_CALL_VALUES: usize = 6 * FELT252_N_WORDS;
const NODE_HASH_COLUMNS_START: usize = CALL_VALUE_COLUMNS_START + N_CALL_VALUES;

pub(crate) const MERKLE_SEMANTIC_AIR_NUM_COLUMNS: usize = NODE_HASH_COLUMNS_START + FELT252_N_WORDS;
pub(crate) const MERKLE_SEMANTIC_INTERACTION_COLUMNS: usize = 14usize.div_ceil(2) * 4;

const BINDING_ACTIVE_COLUMN: usize = 0;
const BINDING_SCHEDULE_COLUMN: usize = 1;
const BINDING_ROOT_COLUMN: usize = 2;
const BINDING_SCHEDULE_START: usize = 3;
const N_SCHEDULE_COLUMNS: usize = 14;
const BINDING_HASH_START: usize = BINDING_SCHEDULE_START + N_SCHEDULE_COLUMNS;

pub(crate) const MERKLE_BINDING_NUM_COLUMNS: usize = BINDING_HASH_START + FELT252_N_WORDS;
pub(crate) const MERKLE_BINDING_INTERACTION_COLUMNS: usize = 4;

#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleSemanticAirError {
    #[error("Merkle public roots and metadata have different lengths")]
    TreeCountMismatch,
    #[error("Merkle tree metadata is invalid for source {tree_source:?}")]
    InvalidTreeMetadata { tree_source: PoseidonCallSource },
    #[error("Merkle query positions are invalid for source {tree_source:?}")]
    InvalidQueryPositions { tree_source: PoseidonCallSource },
    #[error("FRI layer metadata is inconsistent with the public configuration")]
    InvalidFriLayout,
    #[error("Merkle metadata does not fit M31")]
    MetadataOverflow,
    #[error("canonical Merkle tree root does not match the public commitment")]
    RootMismatch,
    #[error("canonical Merkle Poseidon call mapping is inconsistent")]
    InvalidCallMapping,
    #[error("canonical compressed multi-query schedule differs from the public schedule")]
    ScheduleMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ScheduleKind {
    LeafAbsorb,
    LeafFinalize,
    Parent,
    Witness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ScheduleRow {
    source: PoseidonCallSource,
    source_index: usize,
    kind: ScheduleKind,
    leaf_call_index: usize,
    leaf_call_count: usize,
    layer: u32,
    node_index: usize,
    leaf_value_start: usize,
    leaf_value_count: usize,
}

impl ScheduleRow {
    fn fields(self) -> Result<[BaseField; N_SCHEDULE_COLUMNS], MerkleSemanticAirError> {
        let (pcs_source, fri_source, source_arg) = source_fields(self.source)?;
        let mut kinds = [BaseField::from(0u32); 4];
        kinds[match self.kind {
            ScheduleKind::LeafAbsorb => 0,
            ScheduleKind::LeafFinalize => 1,
            ScheduleKind::Parent => 2,
            ScheduleKind::Witness => 3,
        }] = BaseField::from(1u32);
        Ok([
            pcs_source,
            fri_source,
            source_arg,
            to_field(self.source_index)?,
            kinds[0],
            kinds[1],
            kinds[2],
            kinds[3],
            to_field(self.leaf_call_index)?,
            to_field(self.leaf_call_count)?,
            BaseField::from_u32_unchecked(self.layer),
            to_field(self.node_index)?,
            to_field(self.leaf_value_start)?,
            to_field(self.leaf_value_count)?,
        ])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MerkleLeafCallSchedule {
    pub source: PoseidonCallSource,
    pub source_index: usize,
    pub is_absorb: bool,
    pub leaf_call_index: usize,
    pub leaf_call_count: usize,
    pub node_index: usize,
    pub leaf_value_start: usize,
    pub leaf_value_count: usize,
}

impl ScheduleRow {
    fn leaf_call(self) -> Option<MerkleLeafCallSchedule> {
        match self.kind {
            ScheduleKind::LeafAbsorb | ScheduleKind::LeafFinalize => Some(MerkleLeafCallSchedule {
                source: self.source,
                source_index: self.source_index,
                is_absorb: self.kind == ScheduleKind::LeafAbsorb,
                leaf_call_index: self.leaf_call_index,
                leaf_call_count: self.leaf_call_count,
                node_index: self.node_index,
                leaf_value_start: self.leaf_value_start,
                leaf_value_count: self.leaf_value_count,
            }),
            ScheduleKind::Parent | ScheduleKind::Witness => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootRow {
    source: PoseidonCallSource,
    layer: u32,
    root: FieldElement252,
}

#[derive(Debug, Clone)]
struct PublicMerkleLayout {
    schedule: Vec<ScheduleRow>,
    roots: Vec<RootRow>,
}

#[derive(Debug, Clone)]
pub(crate) struct MerklePublicBindingWitness {
    pub n_rows: usize,
    pub log_size: u32,
    pub semantic_n_rows: usize,
    pub semantic_log_size: u32,
    rows: Vec<[BaseField; MERKLE_BINDING_NUM_COLUMNS]>,
    schedule: Vec<ScheduleRow>,
    roots: Vec<RootRow>,
}

impl MerklePublicBindingWitness {
    pub(crate) fn new(
        public_inputs: &RecursivePublicInputs,
    ) -> Result<Self, MerkleSemanticAirError> {
        let layout = build_public_layout(public_inputs)?;
        let semantic_n_rows = layout.schedule.len();
        let semantic_log_size = padded_log_size(semantic_n_rows);
        let mut rows = Vec::with_capacity(layout.schedule.len() + layout.roots.len());
        for schedule in &layout.schedule {
            let mut row = [BaseField::from(0u32); MERKLE_BINDING_NUM_COLUMNS];
            row[BINDING_ACTIVE_COLUMN] = BaseField::from(1u32);
            row[BINDING_SCHEDULE_COLUMN] = BaseField::from(1u32);
            let fields = schedule.fields()?;
            row[BINDING_SCHEDULE_START..BINDING_HASH_START].copy_from_slice(&fields);
            rows.push(row);
        }
        for root in &layout.roots {
            let mut row = [BaseField::from(0u32); MERKLE_BINDING_NUM_COLUMNS];
            row[BINDING_ACTIVE_COLUMN] = BaseField::from(1u32);
            row[BINDING_ROOT_COLUMN] = BaseField::from(1u32);
            let (pcs_source, fri_source, source_arg) = source_fields(root.source)?;
            row[BINDING_SCHEDULE_START] = pcs_source;
            row[BINDING_SCHEDULE_START + 1] = fri_source;
            row[BINDING_SCHEDULE_START + 2] = source_arg;
            row[BINDING_HASH_START - 2] = BaseField::from_u32_unchecked(root.layer);
            row[BINDING_HASH_START - 1] = BaseField::from(0u32);
            row[BINDING_HASH_START..].copy_from_slice(&field_element_to_9_bit_limbs(root.root));
            rows.push(row);
        }
        let n_rows = rows.len();
        let log_size = padded_log_size(n_rows);
        rows.resize(
            1usize << log_size,
            [BaseField::from(0u32); MERKLE_BINDING_NUM_COLUMNS],
        );
        Ok(Self {
            n_rows,
            log_size,
            semantic_n_rows,
            semantic_log_size,
            rows,
            schedule: layout.schedule,
            roots: layout.roots,
        })
    }

    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        rows_to_preprocessed_columns(&self.rows, self.log_size, |column| {
            merkle_binding_preprocessed_id(column, self.log_size, self.n_rows)
        })
    }

    pub(crate) fn semantic_preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        merkle_semantic_preprocessed_columns(self.semantic_log_size, self.semantic_n_rows)
    }

    pub(crate) fn leaf_call_schedule(&self) -> Vec<MerkleLeafCallSchedule> {
        self.schedule
            .iter()
            .filter_map(|schedule| schedule.leaf_call())
            .collect()
    }

    pub(crate) fn write_interaction_trace(
        &self,
        common_lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let (_, columns) = self.preprocessed_columns();
        let n_vec_rows = 1usize << (self.log_size - LOG_N_LANES);
        let mut logup = LogupTraceGenerator::new(self.log_size);
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let schedule_active =
                PackedSecureField::from(columns[BINDING_SCHEDULE_COLUMN].values.data[vec_row]);
            let root_active =
                PackedSecureField::from(columns[BINDING_ROOT_COLUMN].values.data[vec_row]);
            let schedule_denominator: PackedSecureField =
                common_lookup_elements.combine(&binding_schedule_values_packed(&columns, vec_row));
            let root_denominator: PackedSecureField =
                common_lookup_elements.combine(&binding_root_values_packed(&columns, vec_row));
            column.write_frac(
                vec_row,
                -schedule_active * root_denominator + root_active * schedule_denominator,
                schedule_denominator * root_denominator,
            );
        }
        column.finalize_col();
        logup.finalize_last()
    }
}

pub(crate) struct MerkleSemanticWitness {
    pub n_rows: usize,
    pub log_size: u32,
    pub base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl MerkleSemanticWitness {
    pub(crate) fn new(
        canonical: &CanonicalVerifierWitness,
        binding: &MerklePublicBindingWitness,
        call_ids: &[SyntheticPoseidonCallIds],
    ) -> Result<Self, MerkleSemanticAirError> {
        let expected_roots = binding
            .roots
            .iter()
            .map(|root| (root.source, root.root))
            .collect::<HashMap<_, _>>();
        if canonical.merkle_trees.iter().any(|tree| {
            expected_roots.get(&tree.source).copied().map_or_else(
                || {
                    tree.root.is_some()
                        || tree.leaf_start != tree.leaf_end
                        || tree.step_start != tree.step_end
                        || tree.poseidon_call_start != tree.poseidon_call_end
                },
                |expected| tree.root != Some(expected),
            )
        }) {
            return Err(MerkleSemanticAirError::RootMismatch);
        }

        let mut rows = Vec::new();
        let mut schedules = Vec::new();
        let mut covered_calls = HashSet::new();
        for tree in &canonical.merkle_trees {
            for leaf in &canonical.merkle_leaves[tree.leaf_start..tree.leaf_end] {
                let call_count = leaf.poseidon_call_end - leaf.poseidon_call_start;
                for (call_index, global_index) in
                    (leaf.poseidon_call_start..leaf.poseidon_call_end).enumerate()
                {
                    let call = canonical
                        .poseidon_calls
                        .get(global_index)
                        .ok_or(MerkleSemanticAirError::InvalidCallMapping)?;
                    let ids = call_ids
                        .get(global_index)
                        .ok_or(MerkleSemanticAirError::InvalidCallMapping)?;
                    let kind = if call_index + 1 == call_count {
                        ScheduleKind::LeafFinalize
                    } else {
                        ScheduleKind::LeafAbsorb
                    };
                    let expected_kind = match kind {
                        ScheduleKind::LeafAbsorb => Poseidon252CallKind::MerkleLeafAbsorb,
                        ScheduleKind::LeafFinalize => Poseidon252CallKind::MerkleLeafFinalize,
                        _ => unreachable!(),
                    };
                    let (leaf_value_start, leaf_value_count) =
                        leaf_call_value_range(leaf.values.len(), call_index, call_count)
                            .ok_or(MerkleSemanticAirError::InvalidCallMapping)?;
                    if call.source != tree.source
                        || call.call.kind != expected_kind
                        || !covered_calls.insert(global_index)
                    {
                        return Err(MerkleSemanticAirError::InvalidCallMapping);
                    }
                    let schedule = ScheduleRow {
                        source: tree.source,
                        source_index: call.source_index,
                        kind,
                        leaf_call_index: call_index,
                        leaf_call_count: call_count,
                        layer: 0,
                        node_index: leaf.position,
                        leaf_value_start,
                        leaf_value_count,
                    };
                    rows.push(semantic_call_row(schedule, &call.call, *ids)?);
                    schedules.push(schedule);
                }
            }
            for step in &canonical.merkle_steps[tree.step_start..tree.step_end] {
                let call = canonical
                    .poseidon_calls
                    .get(step.poseidon_call_index)
                    .ok_or(MerkleSemanticAirError::InvalidCallMapping)?;
                let ids = call_ids
                    .get(step.poseidon_call_index)
                    .ok_or(MerkleSemanticAirError::InvalidCallMapping)?;
                if call.source != tree.source
                    || call.call.kind != Poseidon252CallKind::MerkleParent
                    || call.call.input[0] != step.left
                    || call.call.input[1] != step.right
                    || call.call.output[0] != step.parent
                    || !covered_calls.insert(step.poseidon_call_index)
                {
                    return Err(MerkleSemanticAirError::InvalidCallMapping);
                }
                let schedule = ScheduleRow {
                    source: tree.source,
                    source_index: call.source_index,
                    kind: ScheduleKind::Parent,
                    leaf_call_index: 0,
                    leaf_call_count: 0,
                    layer: step.layer_index,
                    node_index: step.parent_index,
                    leaf_value_start: 0,
                    leaf_value_count: 0,
                };
                rows.push(semantic_call_row(schedule, &call.call, *ids)?);
                schedules.push(schedule);
            }
        }
        for node_use in &canonical.merkle_node_uses {
            if node_use.kind != CanonicalMerkleNodeUseKind::Witness {
                continue;
            }
            let schedule = ScheduleRow {
                source: node_use.source,
                source_index: 0,
                kind: ScheduleKind::Witness,
                leaf_call_index: 0,
                leaf_call_count: 0,
                layer: node_use.layer_index,
                node_index: node_use.node_index,
                leaf_value_start: 0,
                leaf_value_count: 0,
            };
            rows.push(semantic_witness_row(schedule, node_use.hash)?);
            schedules.push(schedule);
        }

        let expected_calls = canonical
            .poseidon_calls
            .iter()
            .enumerate()
            .filter(|(_, call)| call.source != PoseidonCallSource::Transcript)
            .map(|(index, _)| index)
            .collect::<HashSet<_>>();
        if covered_calls != expected_calls || multiset(&schedules) != multiset(&binding.schedule) {
            return Err(MerkleSemanticAirError::ScheduleMismatch);
        }

        let n_rows = rows.len();
        if n_rows != binding.semantic_n_rows {
            return Err(MerkleSemanticAirError::ScheduleMismatch);
        }
        let log_size = padded_log_size(n_rows);
        rows.resize(
            1usize << log_size,
            [BaseField::from(0u32); MERKLE_SEMANTIC_AIR_NUM_COLUMNS],
        );
        let domain = CanonicCoset::new(log_size).circle_domain();
        let base_trace = (0..MERKLE_SEMANTIC_AIR_NUM_COLUMNS)
            .map(|column| {
                let values = rows.iter().map(|row| row[column]).collect::<Vec<_>>();
                let values = into_bit_reversed_circle_order(&values, log_size);
                CircleEvaluation::new(domain, BaseColumn::from_cpu(&values))
            })
            .collect();
        Ok(Self {
            n_rows,
            log_size,
            base_trace,
        })
    }

    pub(crate) fn write_interaction_trace(
        &self,
        common_lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let n_vec_rows = 1usize << (self.log_size - LOG_N_LANES);
        let mut logup = LogupTraceGenerator::new(self.log_size);
        for pair_start in (0..14).step_by(2) {
            let mut column = logup.new_col();
            for vec_row in 0..n_vec_rows {
                let (numerator0, denominator0) = semantic_fraction(
                    &self.base_trace,
                    pair_start,
                    vec_row,
                    common_lookup_elements,
                );
                if pair_start + 1 < 14 {
                    let (numerator1, denominator1) = semantic_fraction(
                        &self.base_trace,
                        pair_start + 1,
                        vec_row,
                        common_lookup_elements,
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
pub(crate) struct MerkleSemanticAir {
    log_size: u32,
    n_rows: usize,
    common_lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl MerkleSemanticAir {
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

impl FrameworkEval for MerkleSemanticAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let columns = (0..MERKLE_SEMANTIC_AIR_NUM_COLUMNS)
            .map(|_| eval.next_trace_mask())
            .collect::<Vec<_>>();
        let active = columns[ACTIVE_COLUMN].clone();
        let call_active = columns[CALL_ACTIVE_COLUMN].clone();
        let witness_active = columns[WITNESS_ACTIVE_COLUMN].clone();
        let pcs_source = columns[PCS_SOURCE_COLUMN].clone();
        let fri_source = columns[FRI_SOURCE_COLUMN].clone();
        let leaf_absorb = columns[LEAF_ABSORB_COLUMN].clone();
        let leaf_finalize = columns[LEAF_FINALIZE_COLUMN].clone();
        let parent = columns[PARENT_COLUMN].clone();
        let one = E::F::from(M31::from(1));
        let expected_active =
            eval.get_preprocessed_column(merkle_semantic_active_id(self.log_size, self.n_rows));
        eval.add_constraint(active.clone() - expected_active);
        for flag in [
            &active,
            &call_active,
            &witness_active,
            &pcs_source,
            &fri_source,
            &leaf_absorb,
            &leaf_finalize,
            &parent,
        ] {
            eval.add_constraint(flag.clone() * (flag.clone() - one.clone()));
        }
        eval.add_constraint(call_active.clone() + witness_active.clone() - active.clone());
        eval.add_constraint(pcs_source.clone() + fri_source.clone() - active.clone());
        eval.add_constraint(
            leaf_absorb.clone() + leaf_finalize.clone() + parent.clone() - call_active.clone(),
        );
        eval.add_constraint(witness_active.clone() * columns[SOURCE_INDEX_COLUMN].clone());
        eval.add_constraint(
            (parent.clone() + witness_active.clone()) * columns[LEAF_CALL_INDEX_COLUMN].clone(),
        );
        eval.add_constraint(
            (parent.clone() + witness_active.clone()) * columns[LEAF_CALL_COUNT_COLUMN].clone(),
        );
        eval.add_constraint(
            (parent.clone() + witness_active.clone()) * columns[LEAF_VALUE_START_COLUMN].clone(),
        );
        eval.add_constraint(
            (parent.clone() + witness_active.clone()) * columns[LEAF_VALUE_COUNT_COLUMN].clone(),
        );
        eval.add_constraint(
            (leaf_absorb.clone() + leaf_finalize.clone()) * columns[LAYER_COLUMN].clone(),
        );
        eval.add_constraint(
            leaf_finalize.clone()
                * (columns[LEAF_CALL_INDEX_COLUMN].clone() + one.clone()
                    - columns[LEAF_CALL_COUNT_COLUMN].clone()),
        );
        for value in &columns[CALL_VALUE_COLUMNS_START..NODE_HASH_COLUMNS_START] {
            eval.add_constraint(witness_active.clone() * value.clone());
        }
        for id in &columns[CALL_ID_COLUMNS_START..CALL_VALUE_COLUMNS_START] {
            eval.add_constraint(witness_active.clone() * id.clone());
        }
        for value in &columns[NODE_HASH_COLUMNS_START..] {
            eval.add_constraint(call_active.clone() * value.clone());
        }

        let call_values = merkle_call_relation_values(&columns);
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(call_active.clone()),
            &call_values,
        ));
        for slot in 0..N_CALL_IDS {
            let mut memory_values = Vec::with_capacity(2 + FELT252_N_WORDS);
            memory_values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
            memory_values.push(columns[CALL_ID_COLUMNS_START + slot].clone());
            memory_values.extend(
                columns[CALL_VALUE_COLUMNS_START + slot * FELT252_N_WORDS
                    ..CALL_VALUE_COLUMNS_START + (slot + 1) * FELT252_N_WORDS]
                    .iter()
                    .cloned(),
            );
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(call_active.clone()),
                &memory_values,
            ));
        }
        let leaf_call = leaf_absorb.clone() + leaf_finalize.clone();
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(leaf_call),
            &leaf_call_relation_values(&columns),
        ));
        let schedule_values = schedule_relation_values(&columns);
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(active),
            &schedule_values,
        ));

        let leaf_hash = &columns[CALL_VALUE_COLUMNS_START + 3 * FELT252_N_WORDS
            ..CALL_VALUE_COLUMNS_START + 4 * FELT252_N_WORDS];
        let witness_hash = &columns[NODE_HASH_COLUMNS_START..];
        let parent_hash = leaf_hash;
        let left_hash =
            &columns[CALL_VALUE_COLUMNS_START..CALL_VALUE_COLUMNS_START + FELT252_N_WORDS];
        let right_hash = &columns[CALL_VALUE_COLUMNS_START + FELT252_N_WORDS
            ..CALL_VALUE_COLUMNS_START + 2 * FELT252_N_WORDS];
        let layer = columns[LAYER_COLUMN].clone();
        let node_index = columns[NODE_INDEX_COLUMN].clone();
        add_node_relation(
            &mut eval,
            &self.common_lookup_elements,
            -E::EF::from(leaf_finalize),
            &columns,
            layer.clone(),
            node_index.clone(),
            leaf_hash,
        );
        add_node_relation(
            &mut eval,
            &self.common_lookup_elements,
            -E::EF::from(witness_active),
            &columns,
            layer.clone(),
            node_index.clone(),
            witness_hash,
        );
        add_node_relation(
            &mut eval,
            &self.common_lookup_elements,
            -E::EF::from(parent.clone()),
            &columns,
            layer.clone() + one.clone(),
            node_index.clone(),
            parent_hash,
        );
        add_node_relation(
            &mut eval,
            &self.common_lookup_elements,
            E::EF::from(parent.clone()),
            &columns,
            layer.clone(),
            node_index.clone() + node_index.clone(),
            left_hash,
        );
        add_node_relation(
            &mut eval,
            &self.common_lookup_elements,
            E::EF::from(parent),
            &columns,
            layer,
            node_index.clone() + node_index + one,
            right_hash,
        );
        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MerklePublicBindingAir {
    log_size: u32,
    n_rows: usize,
    common_lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl MerklePublicBindingAir {
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

impl FrameworkEval for MerklePublicBindingAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let columns = (0..MERKLE_BINDING_NUM_COLUMNS)
            .map(|column| {
                eval.get_preprocessed_column(merkle_binding_preprocessed_id(
                    column,
                    self.log_size,
                    self.n_rows,
                ))
            })
            .collect::<Vec<_>>();
        let active = columns[BINDING_ACTIVE_COLUMN].clone();
        let schedule = columns[BINDING_SCHEDULE_COLUMN].clone();
        let root = columns[BINDING_ROOT_COLUMN].clone();
        let one = E::F::from(M31::from(1));
        for flag in [&active, &schedule, &root] {
            eval.add_constraint(flag.clone() * (flag.clone() - one.clone()));
        }
        eval.add_constraint(schedule.clone() + root.clone() - active);
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(schedule),
            &binding_schedule_values(&columns),
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(root),
            &binding_root_values(&columns),
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

pub(crate) fn merkle_semantic_preprocessed_columns(
    log_size: u32,
    n_rows: usize,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let size = 1usize << log_size;
    let values = (0..size)
        .map(|row| BaseField::from((row < n_rows) as u32))
        .collect::<Vec<_>>();
    let values = into_bit_reversed_circle_order(&values, log_size);
    (
        vec![merkle_semantic_active_id(log_size, n_rows)],
        vec![CircleEvaluation::new(
            CanonicCoset::new(log_size).circle_domain(),
            BaseColumn::from_cpu(&values),
        )],
    )
}

fn build_public_layout(
    public_inputs: &RecursivePublicInputs,
) -> Result<PublicMerkleLayout, MerkleSemanticAirError> {
    if public_inputs.l1_commitments.len() != public_inputs.l1_tree_metadata.len()
        || public_inputs.l1_commitments.is_empty()
    {
        return Err(MerkleSemanticAirError::TreeCountMismatch);
    }
    let lifting_log_size = public_inputs
        .l1_tree_metadata
        .last()
        .and_then(|tree| tree.tree_height(public_inputs.config))
        .ok_or(MerkleSemanticAirError::TreeCountMismatch)?;
    let preprocessed_height = public_inputs.l1_tree_metadata[0]
        .tree_height(public_inputs.config)
        .ok_or(MerkleSemanticAirError::TreeCountMismatch)?;
    let preprocessed_queries = prepare_preprocessed_query_positions(
        &public_inputs.query_positions,
        lifting_log_size,
        preprocessed_height,
    );
    let mut layout = PublicMerkleLayout {
        schedule: Vec::new(),
        roots: Vec::new(),
    };
    for (tree_index, (root, metadata)) in public_inputs
        .l1_commitments
        .iter()
        .zip(&public_inputs.l1_tree_metadata)
        .enumerate()
    {
        let source = PoseidonCallSource::PcsMerkle { tree_index };
        let height = metadata.tree_height(public_inputs.config).ok_or(
            MerkleSemanticAirError::InvalidTreeMetadata {
                tree_source: source,
            },
        )?;
        let positions = if tree_index == 0 {
            preprocessed_queries.as_slice()
        } else {
            public_inputs.query_positions.as_slice()
        };
        push_tree_layout(
            source,
            height,
            positions,
            metadata.column_log_sizes.len(),
            *root,
            &mut layout,
        )?;
    }

    let fri_roots = std::iter::once(public_inputs.fri_first_layer_commitment)
        .chain(public_inputs.fri_inner_layer_commitments.iter().copied())
        .collect::<Vec<_>>();
    let config = public_inputs.config.fri_config;
    let mut queries = public_inputs.query_positions.clone();
    queries.sort_unstable();
    queries.dedup();
    let first_domain_log_size = CanonicCoset::new(
        public_inputs
            .max_log_degree_bound
            .checked_add(config.log_blowup_factor)
            .ok_or(MerkleSemanticAirError::InvalidFriLayout)?,
    )
    .circle_domain()
    .log_size();
    let mut layer_log_degree = public_inputs.max_log_degree_bound;
    let mut domain_log_size = first_domain_log_size;
    for (layer_index, root) in fri_roots.into_iter().enumerate() {
        let fold_step = if layer_index == 0 {
            config.fold_step
        } else if layer_index + 1 == 1 + public_inputs.fri_inner_layer_commitments.len() {
            let remaining = layer_log_degree
                .checked_sub(config.log_last_layer_degree_bound)
                .ok_or(MerkleSemanticAirError::InvalidFriLayout)?;
            if !(1..=config.fold_step).contains(&remaining) {
                return Err(MerkleSemanticAirError::InvalidFriLayout);
            }
            remaining
        } else {
            config.fold_step
        };
        if fold_step == 0 || fold_step > domain_log_size {
            return Err(MerkleSemanticAirError::InvalidFriLayout);
        }
        let pack_leaves = domain_log_size >= LOG_PACKED_LEAF_SIZE && fold_step > 1;
        let leaf_log_size = if pack_leaves { LOG_PACKED_LEAF_SIZE } else { 0 };
        let leaf_positions = fri_merkle_positions(&queries, fold_step, leaf_log_size);
        let merkle_height = domain_log_size - leaf_log_size;
        push_tree_layout(
            PoseidonCallSource::FriMerkle { layer_index },
            merkle_height,
            &leaf_positions,
            SECURE_EXTENSION_DEGREE * (1usize << leaf_log_size),
            root,
            &mut layout,
        )?;
        queries = queries
            .into_iter()
            .map(|position| position >> fold_step)
            .collect::<Vec<_>>();
        queries.dedup();
        layer_log_degree = layer_log_degree
            .checked_sub(fold_step)
            .ok_or(MerkleSemanticAirError::InvalidFriLayout)?;
        domain_log_size = layer_log_degree
            .checked_add(config.log_blowup_factor)
            .ok_or(MerkleSemanticAirError::InvalidFriLayout)?;
    }
    if layer_log_degree != config.log_last_layer_degree_bound {
        return Err(MerkleSemanticAirError::InvalidFriLayout);
    }
    Ok(layout)
}

fn push_tree_layout(
    source: PoseidonCallSource,
    height: u32,
    positions: &[usize],
    values_per_leaf: usize,
    root: FieldElement252,
    layout: &mut PublicMerkleLayout,
) -> Result<(), MerkleSemanticAirError> {
    if height == 0 {
        return if values_per_leaf == 0 {
            Ok(())
        } else {
            Err(MerkleSemanticAirError::InvalidTreeMetadata {
                tree_source: source,
            })
        };
    }
    let domain_size =
        1usize
            .checked_shl(height)
            .ok_or(MerkleSemanticAirError::InvalidQueryPositions {
                tree_source: source,
            })?;
    let mut previous = positions.iter().copied().collect::<BTreeSet<_>>();
    if previous.is_empty() || previous.iter().any(|position| *position >= domain_size) {
        return Err(MerkleSemanticAirError::InvalidQueryPositions {
            tree_source: source,
        });
    }
    let leaf_call_count = leaf_poseidon_call_count(values_per_leaf);
    let mut source_index = 0usize;
    for position in &previous {
        for call_index in 0..leaf_call_count {
            let (leaf_value_start, leaf_value_count) =
                leaf_call_value_range(values_per_leaf, call_index, leaf_call_count).ok_or(
                    MerkleSemanticAirError::InvalidTreeMetadata {
                        tree_source: source,
                    },
                )?;
            layout.schedule.push(ScheduleRow {
                source,
                source_index,
                kind: if call_index + 1 == leaf_call_count {
                    ScheduleKind::LeafFinalize
                } else {
                    ScheduleKind::LeafAbsorb
                },
                leaf_call_index: call_index,
                leaf_call_count,
                layer: 0,
                node_index: *position,
                leaf_value_start,
                leaf_value_count,
            });
            source_index += 1;
        }
    }
    for layer in 0..height {
        let positions = previous.iter().copied().collect::<Vec<_>>();
        let mut current = BTreeSet::new();
        let mut index = 0usize;
        while index < positions.len() {
            let position = positions[index];
            let sibling_known = index + 1 < positions.len() && position ^ 1 == positions[index + 1];
            if sibling_known {
                index += 2;
            } else {
                layout.schedule.push(ScheduleRow {
                    source,
                    source_index: 0,
                    kind: ScheduleKind::Witness,
                    leaf_call_index: 0,
                    leaf_call_count: 0,
                    layer,
                    node_index: position ^ 1,
                    leaf_value_start: 0,
                    leaf_value_count: 0,
                });
                index += 1;
            }
            let parent_index = position >> 1;
            layout.schedule.push(ScheduleRow {
                source,
                source_index,
                kind: ScheduleKind::Parent,
                leaf_call_index: 0,
                leaf_call_count: 0,
                layer,
                node_index: parent_index,
                leaf_value_start: 0,
                leaf_value_count: 0,
            });
            source_index += 1;
            current.insert(parent_index);
        }
        previous = current;
    }
    if previous != BTreeSet::from([0usize]) {
        return Err(MerkleSemanticAirError::InvalidQueryPositions {
            tree_source: source,
        });
    }
    layout.roots.push(RootRow {
        source,
        layer: height,
        root,
    });
    Ok(())
}

fn fri_merkle_positions(queries: &[usize], fold_step: u32, leaf_log_size: u32) -> Vec<usize> {
    let mut positions = BTreeSet::new();
    let mut previous_subset = None;
    for query in queries {
        let subset_start = (query >> fold_step) << fold_step;
        if previous_subset == Some(subset_start) {
            continue;
        }
        previous_subset = Some(subset_start);
        for position in subset_start..subset_start + (1usize << fold_step) {
            positions.insert(position >> leaf_log_size);
        }
    }
    positions.into_iter().collect()
}

fn leaf_poseidon_call_count(values_per_leaf: usize) -> usize {
    values_per_leaf / 16 + usize::from(values_per_leaf % 16 > 8) + 1
}

fn leaf_call_value_range(
    values_per_leaf: usize,
    call_index: usize,
    call_count: usize,
) -> Option<(usize, usize)> {
    if call_count != leaf_poseidon_call_count(values_per_leaf) || call_index >= call_count {
        return None;
    }
    let full_absorbs = values_per_leaf / 16;
    let remainder = values_per_leaf % 16;
    if call_index < full_absorbs {
        return Some((16 * call_index, 16));
    }
    if remainder > 8 && call_index == full_absorbs {
        return Some((16 * full_absorbs, remainder));
    }
    if call_index + 1 == call_count {
        return Some(if remainder <= 8 {
            (16 * full_absorbs, remainder)
        } else {
            (values_per_leaf, 0)
        });
    }
    None
}

fn semantic_call_row(
    schedule: ScheduleRow,
    call: &super::poseidon252_replay::Poseidon252PermutationCall,
    ids: SyntheticPoseidonCallIds,
) -> Result<[BaseField; MERKLE_SEMANTIC_AIR_NUM_COLUMNS], MerkleSemanticAirError> {
    let mut row = semantic_metadata_row(schedule)?;
    row[CALL_ACTIVE_COLUMN] = BaseField::from(1u32);
    row[CALL_ID_COLUMNS_START..CALL_VALUE_COLUMNS_START].copy_from_slice(&ids.flat());
    let values = call
        .input
        .iter()
        .chain(&call.output)
        .flat_map(|value| field_element_to_9_bit_limbs(*value))
        .collect::<Vec<_>>();
    row[CALL_VALUE_COLUMNS_START..NODE_HASH_COLUMNS_START].copy_from_slice(&values);
    Ok(row)
}

fn semantic_witness_row(
    schedule: ScheduleRow,
    hash: FieldElement252,
) -> Result<[BaseField; MERKLE_SEMANTIC_AIR_NUM_COLUMNS], MerkleSemanticAirError> {
    let mut row = semantic_metadata_row(schedule)?;
    row[WITNESS_ACTIVE_COLUMN] = BaseField::from(1u32);
    row[NODE_HASH_COLUMNS_START..].copy_from_slice(&field_element_to_9_bit_limbs(hash));
    Ok(row)
}

fn semantic_metadata_row(
    schedule: ScheduleRow,
) -> Result<[BaseField; MERKLE_SEMANTIC_AIR_NUM_COLUMNS], MerkleSemanticAirError> {
    let mut row = [BaseField::from(0u32); MERKLE_SEMANTIC_AIR_NUM_COLUMNS];
    row[ACTIVE_COLUMN] = BaseField::from(1u32);
    let fields = schedule.fields()?;
    row[PCS_SOURCE_COLUMN] = fields[0];
    row[FRI_SOURCE_COLUMN] = fields[1];
    row[SOURCE_ARG_COLUMN] = fields[2];
    row[SOURCE_INDEX_COLUMN] = fields[3];
    row[LEAF_ABSORB_COLUMN] = fields[4];
    row[LEAF_FINALIZE_COLUMN] = fields[5];
    row[PARENT_COLUMN] = fields[6];
    row[LEAF_CALL_INDEX_COLUMN] = fields[8];
    row[LEAF_CALL_COUNT_COLUMN] = fields[9];
    row[LAYER_COLUMN] = fields[10];
    row[NODE_INDEX_COLUMN] = fields[11];
    row[LEAF_VALUE_START_COLUMN] = fields[12];
    row[LEAF_VALUE_COUNT_COLUMN] = fields[13];
    Ok(row)
}

fn multiset(rows: &[ScheduleRow]) -> HashMap<ScheduleRow, usize> {
    let mut counts = HashMap::new();
    for row in rows {
        *counts.entry(*row).or_default() += 1;
    }
    counts
}

fn padded_log_size(n_rows: usize) -> u32 {
    n_rows.next_power_of_two().max(N_LANES).ilog2()
}

fn source_fields(
    source: PoseidonCallSource,
) -> Result<(BaseField, BaseField, BaseField), MerkleSemanticAirError> {
    match source {
        PoseidonCallSource::Transcript => Err(MerkleSemanticAirError::InvalidCallMapping),
        PoseidonCallSource::PcsMerkle { tree_index } => Ok((
            BaseField::from(1u32),
            BaseField::from(0u32),
            to_field(tree_index)?,
        )),
        PoseidonCallSource::FriMerkle { layer_index } => Ok((
            BaseField::from(0u32),
            BaseField::from(1u32),
            to_field(layer_index)?,
        )),
    }
}

fn to_field(value: usize) -> Result<BaseField, MerkleSemanticAirError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value < 0x7fff_ffff)
        .map(BaseField::from_u32_unchecked)
        .ok_or(MerkleSemanticAirError::MetadataOverflow)
}

fn merkle_semantic_active_id(log_size: u32, n_rows: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_merkle_semantic_active_{log_size}_{n_rows}"),
    }
}

fn merkle_binding_preprocessed_id(
    column: usize,
    log_size: u32,
    n_rows: usize,
) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_merkle_binding_{column}_{log_size}_{n_rows}"),
    }
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
        let row = bit_reverse_index(circle_index, log_size);
        ordered[row] = value;
    }
    ordered
}

fn merkle_call_relation_values<F: Clone + From<BaseField>>(columns: &[F]) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + 2 + 2 + 3 + N_CALL_IDS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_POSEIDON_CALL_RELATION_ID,
    )));
    values.push(columns[SOURCE_INDEX_COLUMN].clone());
    values.push(columns[SOURCE_ARG_COLUMN].clone());
    values.push(columns[PCS_SOURCE_COLUMN].clone());
    values.push(columns[FRI_SOURCE_COLUMN].clone());
    values.push(columns[LEAF_ABSORB_COLUMN].clone());
    values.push(columns[LEAF_FINALIZE_COLUMN].clone());
    values.push(columns[PARENT_COLUMN].clone());
    values.extend(
        columns[CALL_ID_COLUMNS_START..CALL_VALUE_COLUMNS_START]
            .iter()
            .cloned(),
    );
    values
}

fn leaf_call_relation_values<F: Clone + From<BaseField>>(columns: &[F]) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + 10 + N_CALL_IDS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_LEAF_CALL_RELATION_ID,
    )));
    values.push(columns[PCS_SOURCE_COLUMN].clone());
    values.push(columns[FRI_SOURCE_COLUMN].clone());
    values.push(columns[SOURCE_ARG_COLUMN].clone());
    values.push(columns[SOURCE_INDEX_COLUMN].clone());
    values.push(columns[LEAF_ABSORB_COLUMN].clone());
    values.push(columns[LEAF_FINALIZE_COLUMN].clone());
    values.push(columns[LEAF_CALL_INDEX_COLUMN].clone());
    values.push(columns[LEAF_CALL_COUNT_COLUMN].clone());
    values.push(columns[NODE_INDEX_COLUMN].clone());
    values.push(columns[LEAF_VALUE_START_COLUMN].clone());
    values.push(columns[LEAF_VALUE_COUNT_COLUMN].clone());
    values.extend(
        columns[CALL_ID_COLUMNS_START..CALL_VALUE_COLUMNS_START]
            .iter()
            .cloned(),
    );
    values
}

fn schedule_relation_values<F: Clone + From<BaseField>>(columns: &[F]) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + N_SCHEDULE_COLUMNS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_SCHEDULE_RELATION_ID,
    )));
    values.push(columns[PCS_SOURCE_COLUMN].clone());
    values.push(columns[FRI_SOURCE_COLUMN].clone());
    values.push(columns[SOURCE_ARG_COLUMN].clone());
    values.push(columns[SOURCE_INDEX_COLUMN].clone());
    values.push(columns[LEAF_ABSORB_COLUMN].clone());
    values.push(columns[LEAF_FINALIZE_COLUMN].clone());
    values.push(columns[PARENT_COLUMN].clone());
    values.push(columns[WITNESS_ACTIVE_COLUMN].clone());
    values.push(columns[LEAF_CALL_INDEX_COLUMN].clone());
    values.push(columns[LEAF_CALL_COUNT_COLUMN].clone());
    values.push(columns[LAYER_COLUMN].clone());
    values.push(columns[NODE_INDEX_COLUMN].clone());
    values.push(columns[LEAF_VALUE_START_COLUMN].clone());
    values.push(columns[LEAF_VALUE_COUNT_COLUMN].clone());
    values
}

fn node_relation_values<F: Clone + From<BaseField>>(
    columns: &[F],
    layer: F,
    node_index: F,
    hash: &[F],
) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + 2 + 1 + 2 + FELT252_N_WORDS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_NODE_RELATION_ID,
    )));
    values.push(columns[PCS_SOURCE_COLUMN].clone());
    values.push(columns[FRI_SOURCE_COLUMN].clone());
    values.push(columns[SOURCE_ARG_COLUMN].clone());
    values.push(layer);
    values.push(node_index);
    values.extend(hash.iter().cloned());
    values
}

fn add_node_relation<E: EvalAtRow>(
    eval: &mut E,
    lookup_elements: &cairo_air::relations::CommonLookupElements,
    multiplicity: E::EF,
    columns: &[E::F],
    layer: E::F,
    node_index: E::F,
    hash: &[E::F],
) {
    eval.add_to_relation(RelationEntry::new(
        lookup_elements,
        multiplicity,
        &node_relation_values(columns, layer, node_index, hash),
    ));
}

fn binding_schedule_values<F: Clone + From<BaseField>>(columns: &[F]) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + N_SCHEDULE_COLUMNS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_SCHEDULE_RELATION_ID,
    )));
    values.extend(
        columns[BINDING_SCHEDULE_START..BINDING_HASH_START]
            .iter()
            .cloned(),
    );
    values
}

fn binding_root_values<F: Clone + From<BaseField>>(columns: &[F]) -> Vec<F> {
    let source_columns = &columns[BINDING_SCHEDULE_START..BINDING_SCHEDULE_START + 3];
    let layer = columns[BINDING_HASH_START - 2].clone();
    let node_index = columns[BINDING_HASH_START - 1].clone();
    let mut values = Vec::with_capacity(1 + 2 + 1 + 2 + FELT252_N_WORDS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_NODE_RELATION_ID,
    )));
    values.extend(source_columns.iter().cloned());
    values.push(layer);
    values.push(node_index);
    values.extend(columns[BINDING_HASH_START..].iter().cloned());
    values
}

fn binding_schedule_values_packed(
    columns: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    vec_row: usize,
) -> Vec<PackedBaseField> {
    let mut values = Vec::with_capacity(1 + N_SCHEDULE_COLUMNS);
    values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
        MERKLE_SCHEDULE_RELATION_ID,
    )));
    values.extend(
        columns[BINDING_SCHEDULE_START..BINDING_HASH_START]
            .iter()
            .map(|column| column.values.data[vec_row]),
    );
    values
}

fn binding_root_values_packed(
    columns: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    vec_row: usize,
) -> Vec<PackedBaseField> {
    let mut values = Vec::with_capacity(1 + 2 + 1 + 2 + FELT252_N_WORDS);
    values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
        MERKLE_NODE_RELATION_ID,
    )));
    values.extend(
        columns[BINDING_SCHEDULE_START..BINDING_SCHEDULE_START + 3]
            .iter()
            .map(|column| column.values.data[vec_row]),
    );
    values.push(columns[BINDING_HASH_START - 2].values.data[vec_row]);
    values.push(columns[BINDING_HASH_START - 1].values.data[vec_row]);
    values.extend(
        columns[BINDING_HASH_START..]
            .iter()
            .map(|column| column.values.data[vec_row]),
    );
    values
}

fn semantic_fraction(
    columns: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    relation_index: usize,
    vec_row: usize,
    lookup_elements: &cairo_air::relations::CommonLookupElements,
) -> (PackedSecureField, PackedSecureField) {
    let value = |column: usize| columns[column].values.data[vec_row];
    let call_active = PackedSecureField::from(value(CALL_ACTIVE_COLUMN));
    let witness_active = PackedSecureField::from(value(WITNESS_ACTIVE_COLUMN));
    let leaf_finalize = PackedSecureField::from(value(LEAF_FINALIZE_COLUMN));
    let leaf_call =
        PackedSecureField::from(value(LEAF_ABSORB_COLUMN) + value(LEAF_FINALIZE_COLUMN));
    let parent = PackedSecureField::from(value(PARENT_COLUMN));
    let active = PackedSecureField::from(value(ACTIVE_COLUMN));
    let source_columns = [value(PCS_SOURCE_COLUMN), value(FRI_SOURCE_COLUMN)];
    let source_arg = value(SOURCE_ARG_COLUMN);
    let layer = value(LAYER_COLUMN);
    let node_index = value(NODE_INDEX_COLUMN);
    let node_values = |layer: PackedBaseField, node_index: PackedBaseField, hash_start: usize| {
        let mut values = Vec::with_capacity(1 + 2 + 1 + 2 + FELT252_N_WORDS);
        values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            MERKLE_NODE_RELATION_ID,
        )));
        values.extend(source_columns);
        values.push(source_arg);
        values.push(layer);
        values.push(node_index);
        values.extend((0..FELT252_N_WORDS).map(|offset| value(hash_start + offset)));
        values
    };
    match relation_index {
        0 => {
            let mut values = Vec::with_capacity(1 + 2 + 2 + 3 + N_CALL_IDS);
            values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                MERKLE_POSEIDON_CALL_RELATION_ID,
            )));
            values.push(value(SOURCE_INDEX_COLUMN));
            values.push(source_arg);
            values.extend(source_columns);
            values.push(value(LEAF_ABSORB_COLUMN));
            values.push(value(LEAF_FINALIZE_COLUMN));
            values.push(value(PARENT_COLUMN));
            values.extend((0..N_CALL_IDS).map(|offset| value(CALL_ID_COLUMNS_START + offset)));
            (call_active, lookup_elements.combine(&values))
        }
        1..=6 => {
            let slot = relation_index - 1;
            let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
            values.push(PackedBaseField::broadcast(BaseField::from(
                MEMORY_ID_TO_BIG_RELATION_ID,
            )));
            values.push(value(CALL_ID_COLUMNS_START + slot));
            values.extend(
                (0..FELT252_N_WORDS).map(|offset| {
                    value(CALL_VALUE_COLUMNS_START + slot * FELT252_N_WORDS + offset)
                }),
            );
            (call_active, lookup_elements.combine(&values))
        }
        7 => {
            let mut values = Vec::with_capacity(1 + 11 + N_CALL_IDS);
            values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                MERKLE_LEAF_CALL_RELATION_ID,
            )));
            values.extend(source_columns);
            values.push(source_arg);
            values.push(value(SOURCE_INDEX_COLUMN));
            values.push(value(LEAF_ABSORB_COLUMN));
            values.push(value(LEAF_FINALIZE_COLUMN));
            values.push(value(LEAF_CALL_INDEX_COLUMN));
            values.push(value(LEAF_CALL_COUNT_COLUMN));
            values.push(node_index);
            values.push(value(LEAF_VALUE_START_COLUMN));
            values.push(value(LEAF_VALUE_COUNT_COLUMN));
            values.extend((0..N_CALL_IDS).map(|offset| value(CALL_ID_COLUMNS_START + offset)));
            (-leaf_call, lookup_elements.combine(&values))
        }
        8 => {
            let mut values = Vec::with_capacity(1 + N_SCHEDULE_COLUMNS);
            values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                MERKLE_SCHEDULE_RELATION_ID,
            )));
            values.extend(source_columns);
            values.push(source_arg);
            values.push(value(SOURCE_INDEX_COLUMN));
            values.push(value(LEAF_ABSORB_COLUMN));
            values.push(value(LEAF_FINALIZE_COLUMN));
            values.push(value(PARENT_COLUMN));
            values.push(value(WITNESS_ACTIVE_COLUMN));
            values.push(value(LEAF_CALL_INDEX_COLUMN));
            values.push(value(LEAF_CALL_COUNT_COLUMN));
            values.push(layer);
            values.push(node_index);
            values.push(value(LEAF_VALUE_START_COLUMN));
            values.push(value(LEAF_VALUE_COUNT_COLUMN));
            (active, lookup_elements.combine(&values))
        }
        9 => (
            -leaf_finalize,
            lookup_elements.combine(&node_values(
                layer,
                node_index,
                CALL_VALUE_COLUMNS_START + 3 * FELT252_N_WORDS,
            )),
        ),
        10 => (
            -witness_active,
            lookup_elements.combine(&node_values(layer, node_index, NODE_HASH_COLUMNS_START)),
        ),
        11 => (
            -parent,
            lookup_elements.combine(&node_values(
                layer + PackedBaseField::broadcast(BaseField::from(1u32)),
                node_index,
                CALL_VALUE_COLUMNS_START + 3 * FELT252_N_WORDS,
            )),
        ),
        12 => (
            parent,
            lookup_elements.combine(&node_values(
                layer,
                node_index + node_index,
                CALL_VALUE_COLUMNS_START,
            )),
        ),
        _ => (
            parent,
            lookup_elements.combine(&node_values(
                layer,
                node_index + node_index + PackedBaseField::broadcast(BaseField::from(1u32)),
                CALL_VALUE_COLUMNS_START + FELT252_N_WORDS,
            )),
        ),
    }
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
    use crate::stwo_backend::recursive::cpu_transcript_binding_air::CpuTranscriptBindingWitness;
    use crate::stwo_backend::recursive::fri_semantic_air::{
        FriFoldPublicWitness, FriFoldWitness, PcsQuotientPublicWitness, PcsQuotientWitness,
    };
    use crate::stwo_backend::recursive::merkle_leaf_air::{
        MerkleLeafPackingWitness, MerkleLeafPublicWitness,
    };
    use crate::stwo_backend::recursive::poseidon252_air::Poseidon252ClosureWitness;
    use crate::stwo_backend::recursive::transcript_air::{
        TranscriptSemanticWitness, transcript_payload_values,
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
                sampled_values: proof.0.sampled_values.clone().flatten_cols(),
                draw_results,
                proof_of_work: proof.0.proof_of_work,
                pow_hash,
            }
        })
    }

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
    fn canonical_merkle_node_multiset_closes_with_poseidon_router() {
        let fixture = fixture();
        let binding = MerklePublicBindingWitness::new(&fixture.public_inputs).unwrap();
        let payloads = transcript_payload_values(&fixture.canonical.transcript_events);
        let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
            &fixture.canonical.poseidon_calls,
            &payloads,
        )
        .unwrap();
        let merkle = MerkleSemanticWitness::new(
            &fixture.canonical,
            &binding,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let leaf_public = MerkleLeafPublicWitness::new(&binding).unwrap();
        let leaf = MerkleLeafPackingWitness::new(
            &fixture.canonical,
            &leaf_public,
            &poseidon.synthetic_memory.call_ids,
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
        let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
        let poseidon = poseidon.write_interaction_trace(&lookup_elements).unwrap();
        let (_, transcript_sum) = transcript.write_interaction_trace(&lookup_elements);
        let (_, merkle_sum) = merkle.write_interaction_trace(&lookup_elements);
        let (_, binding_sum) = binding.write_interaction_trace(&lookup_elements);
        let (_, leaf_sum) = leaf.write_interaction_trace(&leaf_public, &lookup_elements);
        let quotient_public =
            PcsQuotientPublicWitness::new(&fixture.public_inputs, &fixture.sampled_values).unwrap();
        let quotient = PcsQuotientWitness::new(&fixture.canonical, &quotient_public).unwrap();
        let (_, quotient_sum) =
            quotient.write_interaction_trace(&quotient_public, &lookup_elements);
        let fri_fold_public =
            FriFoldPublicWitness::new(&fixture.public_inputs, &fixture.draw_results).unwrap();
        let fri_fold = FriFoldWitness::new(&fixture.canonical, &fri_fold_public).unwrap();
        let (_, fri_fold_sum) =
            fri_fold.write_interaction_trace(&fri_fold_public, &lookup_elements);
        let transcript_binding = CpuTranscriptBindingWitness::new(
            &fixture.public_inputs,
            &fixture.sampled_values,
            &fixture.draw_results,
            fixture.proof_of_work,
            fixture.pow_hash,
        )
        .unwrap();
        let (_, transcript_binding_sum) =
            transcript_binding.write_interaction_trace(&lookup_elements);
        assert_eq!(
            poseidon.lookup_residual
                + transcript_sum
                + transcript_binding_sum
                + merkle_sum
                + binding_sum
                + leaf_sum
                + quotient_sum
                + fri_fold_sum,
            SecureField::from(0u32)
        );
    }

    #[test]
    fn public_root_and_query_relabelling_is_rejected() {
        let fixture = fixture();
        let mut changed = fixture.public_inputs.clone();
        changed.l1_commitments[1] += FieldElement252::ONE;
        let binding = MerklePublicBindingWitness::new(&changed).unwrap();
        let payloads = transcript_payload_values(&fixture.canonical.transcript_events);
        let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
            &fixture.canonical.poseidon_calls,
            &payloads,
        )
        .unwrap();
        assert!(matches!(
            MerkleSemanticWitness::new(
                &fixture.canonical,
                &binding,
                &poseidon.synthetic_memory.call_ids,
            ),
            Err(MerkleSemanticAirError::RootMismatch)
        ));

        let mut changed = fixture.public_inputs.clone();
        changed.query_positions[0] ^= 1;
        let binding = MerklePublicBindingWitness::new(&changed).unwrap();
        assert!(matches!(
            MerkleSemanticWitness::new(
                &fixture.canonical,
                &binding,
                &poseidon.synthetic_memory.call_ids,
            ),
            Err(MerkleSemanticAirError::ScheduleMismatch)
        ));
    }

    #[test]
    fn merkle_semantic_and_binding_components_satisfy_air() {
        let fixture = fixture();
        let binding = MerklePublicBindingWitness::new(&fixture.public_inputs).unwrap();
        let payloads = transcript_payload_values(&fixture.canonical.transcript_events);
        let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
            &fixture.canonical.poseidon_calls,
            &payloads,
        )
        .unwrap();
        let merkle = MerkleSemanticWitness::new(
            &fixture.canonical,
            &binding,
            &poseidon.synthetic_memory.call_ids,
        )
        .unwrap();
        let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
        let (mut ids, mut preprocessed) = binding.semantic_preprocessed_columns();
        let (binding_ids, binding_preprocessed) = binding.preprocessed_columns();
        ids.extend(binding_ids);
        preprocessed.extend(binding_preprocessed);
        let (merkle_interaction, merkle_sum) = merkle.write_interaction_trace(&lookup_elements);
        let (binding_interaction, binding_sum) = binding.write_interaction_trace(&lookup_elements);
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let merkle_component = FrameworkComponent::new(
            &mut allocator,
            MerkleSemanticAir::new(merkle.log_size, merkle.n_rows, lookup_elements.clone()),
            merkle_sum,
        );
        let binding_component = FrameworkComponent::new(
            &mut allocator,
            MerklePublicBindingAir::new(binding.log_size, binding.n_rows, lookup_elements),
            binding_sum,
        );
        let mut interaction = merkle_interaction;
        interaction.extend(binding_interaction);
        let trace = TreeVec::new(vec![
            preprocessed
                .into_iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
            merkle
                .base_trace
                .into_iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
            interaction
                .into_iter()
                .map(|evaluation| evaluation.values.to_cpu())
                .collect(),
        ]);
        let trace = trace.as_cols_ref();
        assert_component(&merkle_component, &trace);
        assert_component(&binding_component, &trace);
    }
}
