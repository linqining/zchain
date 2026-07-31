//! Official Cairo AIR closure for the Poseidon252 calls recorded by the recursive verifier.
//!
//! The semantic transcript/Merkle/FRI AIRs consume felt252 values. This module assigns those
//! values deterministic synthetic Cairo memory IDs and connects each six-ID permutation call to
//! the audited `PoseidonAggregator` relation. Six additional `MemoryIdToBig` lookups bind the IDs
//! to exact 28×9-bit limbs in the committed caller trace.

use std::array;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use cairo_air::cairo_components::CairoComponents;
use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::{CommonLookupElements, MEMORY_ID_TO_BIG_RELATION_ID};
use indexmap::IndexSet;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{PcsConfig, TreeSubspan};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{CommitmentTreeProver, ComponentProver};
use stwo_cairo_adapter::builtins::BuiltinSegments;
use stwo_cairo_adapter::memory::{Memory, MemoryBuilder, MemoryConfig, MemoryValue};
use stwo_cairo_adapter::opcodes::CasmStatesByOpcode;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;
use stwo_cairo_common::prover_types::cpu::{FELT252_N_WORDS, M31};
use stwo_cairo_common::prover_types::felt::split_f252;
use stwo_cairo_prover::utils::cairo_provers;
use stwo_cairo_prover::witness::cairo_claim_generator::{
    CairoClaimGenerator, CairoInteractionClaimGenerator,
};
use stwo_cairo_prover::witness::utils::TreeBuilder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator,
};

use super::poseidon252_replay::{Poseidon252CallKind, Poseidon252PermutationCall};
use super::replay_witness::{CanonicalPoseidonCall, PoseidonCallSource};

const POSEIDON_AGGREGATOR_RELATION_ID: u32 = 1_551_892_206;
const CANONICAL_POSEIDON_CALL_RELATION_ID: u32 = 1_261_438_649;
pub(crate) const TRANSCRIPT_POSEIDON_CALL_RELATION_ID: u32 = 1_834_672_531;
pub(crate) const MERKLE_POSEIDON_CALL_RELATION_ID: u32 = 1_834_672_533;
pub(crate) const N_CALL_IDS: usize = 6;
const N_CALL_VALUE_COLUMNS: usize = N_CALL_IDS * FELT252_N_WORDS;
const N_SOURCE_SELECTORS: usize = 3;
pub(crate) const N_KIND_SELECTORS: usize = 10;
const N_CALL_METADATA_COLUMNS: usize = 4 + N_SOURCE_SELECTORS + N_KIND_SELECTORS;
pub(crate) const POSEIDON252_CALL_AIR_NUM_COLUMNS: usize =
    N_CALL_METADATA_COLUMNS + N_CALL_IDS + N_CALL_VALUE_COLUMNS;
pub(crate) const POSEIDON252_CALL_INTERACTION_COLUMNS: usize = 16;
pub(crate) const POSEIDON252_SEMANTIC_INTERACTION_COLUMNS: usize = 20;

const POSEIDON_CLOSURE_COMPONENTS: [&str; 13] = [
    "range_check_9_9",
    "memory_id_to_big",
    "range_check_20",
    "cube_252",
    "poseidon_round_keys",
    "range_check_3_3_3_3_3",
    "poseidon_full_round_chain",
    "range_check_18",
    "range_check_252_width_27",
    "range_check_4_4_4_4",
    "range_check_4_4",
    "poseidon_3_partial_rounds_chain",
    "poseidon_aggregator",
];

#[derive(Debug, thiserror::Error)]
pub(crate) enum Poseidon252AirError {
    #[error("Poseidon252 AIR requires at least one permutation call")]
    EmptyCalls,
    #[error("canonical Poseidon252 call {index} has an invalid native input/output pair")]
    InvalidCall { index: usize },
    #[error("canonical Poseidon252 call metadata does not fit M31")]
    MetadataOverflow,
}

#[derive(Debug, Clone)]
struct CanonicalCallMetadata {
    active: BaseField,
    global_index: BaseField,
    source_index: BaseField,
    source_arg: BaseField,
    source_selectors: [BaseField; N_SOURCE_SELECTORS],
    kind_selectors: [BaseField; N_KIND_SELECTORS],
}

impl CanonicalCallMetadata {
    fn synthetic(
        index: usize,
        call: &Poseidon252PermutationCall,
    ) -> Result<Self, Poseidon252AirError> {
        let source = match call.kind {
            Poseidon252CallKind::MerkleLeafAbsorb
            | Poseidon252CallKind::MerkleLeafFinalize
            | Poseidon252CallKind::MerkleParent => PoseidonCallSource::PcsMerkle { tree_index: 0 },
            _ => PoseidonCallSource::Transcript,
        };
        Self::new(index, source, index, call.kind)
    }

    fn from_canonical(call: &CanonicalPoseidonCall) -> Result<Self, Poseidon252AirError> {
        Self::new(
            call.global_index,
            call.source,
            call.source_index,
            call.call.kind,
        )
    }

    fn new(
        global_index: usize,
        source: PoseidonCallSource,
        source_index: usize,
        kind: Poseidon252CallKind,
    ) -> Result<Self, Poseidon252AirError> {
        let to_field = |value: usize| {
            u32::try_from(value)
                .ok()
                .filter(|value| *value < 0x7fff_ffff)
                .map(BaseField::from_u32_unchecked)
                .ok_or(Poseidon252AirError::MetadataOverflow)
        };
        let (source_selector, source_arg) = match source {
            PoseidonCallSource::Transcript => (0, 0),
            PoseidonCallSource::PcsMerkle { tree_index } => (1, tree_index),
            PoseidonCallSource::FriMerkle { layer_index } => (2, layer_index),
        };
        let mut source_selectors = [BaseField::from_u32_unchecked(0); N_SOURCE_SELECTORS];
        source_selectors[source_selector] = BaseField::from_u32_unchecked(1);
        let mut kind_selectors = [BaseField::from_u32_unchecked(0); N_KIND_SELECTORS];
        kind_selectors[kind_index(kind)] = BaseField::from_u32_unchecked(1);
        Ok(Self {
            active: BaseField::from_u32_unchecked(1),
            global_index: to_field(global_index)?,
            source_index: to_field(source_index)?,
            source_arg: to_field(source_arg)?,
            source_selectors,
            kind_selectors,
        })
    }

    fn padding() -> Self {
        Self {
            active: BaseField::from_u32_unchecked(0),
            global_index: BaseField::from_u32_unchecked(0),
            source_index: BaseField::from_u32_unchecked(0),
            source_arg: BaseField::from_u32_unchecked(0),
            source_selectors: [BaseField::from_u32_unchecked(0); N_SOURCE_SELECTORS],
            kind_selectors: [BaseField::from_u32_unchecked(0); N_KIND_SELECTORS],
        }
    }

    fn flat(&self) -> [BaseField; N_CALL_METADATA_COLUMNS] {
        let mut values = [BaseField::from_u32_unchecked(0); N_CALL_METADATA_COLUMNS];
        values[0] = self.active;
        values[1] = self.global_index;
        values[2] = self.source_index;
        values[3] = self.source_arg;
        values[4..4 + N_SOURCE_SELECTORS].copy_from_slice(&self.source_selectors);
        values[4 + N_SOURCE_SELECTORS..].copy_from_slice(&self.kind_selectors);
        values
    }
}

pub(crate) const fn kind_index(kind: Poseidon252CallKind) -> usize {
    match kind {
        Poseidon252CallKind::MerkleLeafAbsorb => 0,
        Poseidon252CallKind::MerkleLeafFinalize => 1,
        Poseidon252CallKind::MerkleParent => 2,
        Poseidon252CallKind::TranscriptMixRoot => 3,
        Poseidon252CallKind::TranscriptMixFelts => 4,
        Poseidon252CallKind::TranscriptMixU32s => 5,
        Poseidon252CallKind::TranscriptMixU64 => 6,
        Poseidon252CallKind::TranscriptDraw => 7,
        Poseidon252CallKind::TranscriptPowPrefix => 8,
        Poseidon252CallKind::TranscriptPowNonce => 9,
    }
}

/// Six synthetic memory IDs used by one canonical permutation call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyntheticPoseidonCallIds {
    pub input: [BaseField; 3],
    pub output: [BaseField; 3],
}

impl SyntheticPoseidonCallIds {
    pub(crate) fn flat(self) -> [BaseField; N_CALL_IDS] {
        [
            self.input[0],
            self.input[1],
            self.input[2],
            self.output[0],
            self.output[1],
            self.output[2],
        ]
    }
}

/// Deterministic synthetic Cairo memory for the canonical Poseidon call table.
#[derive(Debug, Clone)]
pub(crate) struct SyntheticPoseidonMemory {
    pub memory: Arc<Memory>,
    pub call_ids: Vec<SyntheticPoseidonCallIds>,
    pub extra_ids: Vec<BaseField>,
}

impl SyntheticPoseidonMemory {
    fn new(calls: &[Poseidon252PermutationCall], extra_values: &[FieldElement252]) -> Self {
        let mut builder = MemoryBuilder::new(MemoryConfig::default());
        // Keep the official small-memory component non-empty. This value has zero multiplicity.
        builder.set(0, MemoryValue::Small(0));

        let mut next_address = 1u32;
        let mut call_addresses = Vec::with_capacity(calls.len());
        for call in calls {
            let mut addresses = [0u32; N_CALL_IDS];
            for (slot, value) in call.input.iter().chain(call.output.iter()).enumerate() {
                addresses[slot] = next_address;
                builder.set(
                    next_address,
                    MemoryValue::F252(field_element_to_u32_words(*value)),
                );
                next_address += 1;
            }
            call_addresses.push(addresses);
        }
        let mut extra_addresses = Vec::with_capacity(extra_values.len());
        for value in extra_values {
            extra_addresses.push(next_address);
            builder.set(
                next_address,
                MemoryValue::F252(field_element_to_u32_words(*value)),
            );
            next_address += 1;
        }

        let (memory, _) = builder.build();
        let call_ids = call_addresses
            .into_iter()
            .map(|addresses| {
                let ids = addresses
                    .map(|address| BaseField::from_u32_unchecked(memory.get_raw_id(address)));
                SyntheticPoseidonCallIds {
                    input: ids[..3].try_into().unwrap(),
                    output: ids[3..].try_into().unwrap(),
                }
            })
            .collect();
        let extra_ids = extra_addresses
            .into_iter()
            .map(|address| BaseField::from_u32_unchecked(memory.get_raw_id(address)))
            .collect();

        Self {
            memory: Arc::new(memory),
            call_ids,
            extra_ids,
        }
    }
}

fn field_element_to_u32_words(value: FieldElement252) -> [u32; 8] {
    let mut bytes = value.to_bytes_be();
    bytes.reverse();
    array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..(index + 1) * 4].try_into().unwrap())
    })
}

pub(crate) fn field_element_to_9_bit_limbs(value: FieldElement252) -> [BaseField; FELT252_N_WORDS] {
    split_f252(field_element_to_u32_words(value))
}

pub(crate) fn poseidon_active_column_id(log_size: u32, n_calls: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_poseidon_active_{log_size}_{n_calls}"),
    }
}

fn gen_prefix_active_column(
    id: PreProcessedColumnId,
    log_size: u32,
    n_active: usize,
) -> (
    PreProcessedColumnId,
    CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>,
) {
    let size = 1usize << log_size;
    assert!(n_active <= size, "active prefix exceeds trace size");
    let domain = CanonicCoset::new(log_size).circle_domain();
    let evaluation = CircleEvaluation::new(
        domain,
        BaseColumn::from_iter((0..size).map(|row| BaseField::from((row < n_active) as u32))),
    );
    (id, evaluation)
}

fn read_call_trace<E: EvalAtRow>(eval: &mut E) -> CanonicalCallTrace<E::F> {
    let active = eval.next_trace_mask();
    let global_index = eval.next_trace_mask();
    let source_index = eval.next_trace_mask();
    let source_arg = eval.next_trace_mask();
    let source_selectors = array::from_fn(|_| eval.next_trace_mask());
    let kind_selectors = array::from_fn(|_| eval.next_trace_mask());
    let ids = array::from_fn(|_| eval.next_trace_mask());
    let expected_limbs = array::from_fn(|_| array::from_fn(|_| eval.next_trace_mask()));
    CanonicalCallTrace {
        active,
        global_index,
        source_index,
        source_arg,
        source_selectors,
        kind_selectors,
        ids,
        expected_limbs,
    }
}

struct CanonicalCallTrace<F> {
    active: F,
    global_index: F,
    source_index: F,
    source_arg: F,
    source_selectors: [F; N_SOURCE_SELECTORS],
    kind_selectors: [F; N_KIND_SELECTORS],
    ids: [F; N_CALL_IDS],
    expected_limbs: [[F; FELT252_N_WORDS]; N_CALL_IDS],
}

fn constrain_call_metadata<E: EvalAtRow>(eval: &mut E, trace: &CanonicalCallTrace<E::F>) {
    let zero = E::F::from(M31::from(0));
    let one = E::F::from(M31::from(1));
    let two = E::F::from(M31::from(2));
    let three = E::F::from(M31::from(3));

    eval.add_constraint(trace.active.clone() * (trace.active.clone() - one.clone()));
    for selector in trace.source_selectors.iter().chain(&trace.kind_selectors) {
        eval.add_constraint(selector.clone() * (selector.clone() - one.clone()));
    }
    let source_sum = trace
        .source_selectors
        .iter()
        .cloned()
        .fold(zero.clone(), |sum, value| sum + value);
    let kind_sum = trace
        .kind_selectors
        .iter()
        .cloned()
        .fold(zero.clone(), |sum, value| sum + value);
    eval.add_constraint(source_sum - trace.active.clone());
    eval.add_constraint(kind_sum - trace.active.clone());

    let inactive = one.clone() - trace.active.clone();
    eval.add_constraint(inactive.clone() * trace.global_index.clone());
    eval.add_constraint(inactive.clone() * trace.source_index.clone());
    eval.add_constraint(inactive * trace.source_arg.clone());
    eval.add_constraint(trace.source_selectors[0].clone() * trace.source_arg.clone());

    let merkle_kind = trace.kind_selectors[0].clone()
        + trace.kind_selectors[1].clone()
        + trace.kind_selectors[2].clone();
    let transcript_kind = trace.kind_selectors[3..]
        .iter()
        .cloned()
        .fold(zero.clone(), |sum, value| sum + value);
    eval.add_constraint(trace.source_selectors[0].clone() * merkle_kind);
    eval.add_constraint(
        (trace.source_selectors[1].clone() + trace.source_selectors[2].clone()) * transcript_kind,
    );

    let hash_pair_kind = trace.kind_selectors[2].clone()
        + trace.kind_selectors[3].clone()
        + trace.kind_selectors[6].clone()
        + trace.kind_selectors[9].clone();
    let draw_kind = trace.kind_selectors[7].clone();
    for limb in 0..FELT252_N_WORDS {
        let expected_constant = if limb == 0 {
            hash_pair_kind.clone() * two.clone() + draw_kind.clone() * three.clone()
        } else {
            zero.clone()
        };
        eval.add_constraint(
            (hash_pair_kind.clone() + draw_kind.clone()) * trace.expected_limbs[2][limb].clone()
                - expected_constant,
        );
    }
}

fn canonical_call_relation_values<F: Clone>(trace: &CanonicalCallTrace<F>) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + N_CALL_METADATA_COLUMNS - 1 + N_CALL_IDS);
    values.push(trace.global_index.clone());
    values.push(trace.source_index.clone());
    values.push(trace.source_arg.clone());
    values.extend(trace.source_selectors.iter().cloned());
    values.extend(trace.kind_selectors.iter().cloned());
    values.extend(trace.ids.iter().cloned());
    values
}

fn add_memory_relations<E: EvalAtRow>(
    eval: &mut E,
    trace: &CanonicalCallTrace<E::F>,
    common_lookup_elements: &CommonLookupElements,
    multiplicity: E::EF,
) {
    for slot in 0..N_CALL_IDS {
        let mut memory_values = Vec::with_capacity(2 + FELT252_N_WORDS);
        memory_values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
        memory_values.push(trace.ids[slot].clone());
        memory_values.extend(trace.expected_limbs[slot].iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            common_lookup_elements,
            multiplicity.clone(),
            &memory_values,
        ));
    }
}

/// AIR-side caller of the official Poseidon closure.
///
/// Each row sends one positive `PoseidonAggregator(input_ids, output_ids)` entry and six positive
/// `MemoryIdToBig(id, expected_9_bit_limbs)` entries. The official aggregator and synthetic memory
/// table consume the opposite multiplicities.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalPoseidonCallAir {
    log_size: u32,
    n_calls: usize,
    common_lookup_elements: CommonLookupElements,
}

impl CanonicalPoseidonCallAir {
    pub(crate) const fn new(
        log_size: u32,
        n_calls: usize,
        common_lookup_elements: CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_calls,
            common_lookup_elements,
        }
    }
}

impl FrameworkEval for CanonicalPoseidonCallAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace = read_call_trace(&mut eval);
        let expected_active =
            eval.get_preprocessed_column(poseidon_active_column_id(self.log_size, self.n_calls));
        eval.add_constraint(trace.active.clone() - expected_active);
        constrain_call_metadata(&mut eval, &trace);

        let mut poseidon_values = Vec::with_capacity(1 + N_CALL_IDS);
        poseidon_values.push(E::F::from(M31::from(POSEIDON_AGGREGATOR_RELATION_ID)));
        poseidon_values.extend(trace.ids.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(E::F::from(M31::from(1))),
            &poseidon_values,
        ));

        add_memory_relations(
            &mut eval,
            &trace,
            &self.common_lookup_elements,
            E::EF::from(E::F::from(M31::from(1))),
        );

        let mut canonical_values = Vec::with_capacity(1 + N_CALL_METADATA_COLUMNS - 1 + N_CALL_IDS);
        canonical_values.push(E::F::from(M31::from_u32_unchecked(
            CANONICAL_POSEIDON_CALL_RELATION_ID,
        )));
        canonical_values.extend(canonical_call_relation_values(&trace));
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(trace.active),
            &canonical_values,
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}

/// Semantic-side mirror of the canonical call table.
///
/// This component consumes every active canonical call exactly once and binds the six IDs back to
/// the same committed felt252 limbs. Transcript, Merkle and FRI semantic tables can now key their
/// own lookups by stable call metadata without trusting host-side row alignment.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalPoseidonSemanticAir {
    log_size: u32,
    n_calls: usize,
    common_lookup_elements: CommonLookupElements,
}

impl CanonicalPoseidonSemanticAir {
    pub(crate) const fn new(
        log_size: u32,
        n_calls: usize,
        common_lookup_elements: CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_calls,
            common_lookup_elements,
        }
    }
}

impl FrameworkEval for CanonicalPoseidonSemanticAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace = read_call_trace(&mut eval);
        let expected_active =
            eval.get_preprocessed_column(poseidon_active_column_id(self.log_size, self.n_calls));
        eval.add_constraint(trace.active.clone() - expected_active);
        constrain_call_metadata(&mut eval, &trace);

        let active = E::EF::from(trace.active.clone());
        let mut canonical_values = Vec::with_capacity(1 + N_CALL_METADATA_COLUMNS - 1 + N_CALL_IDS);
        canonical_values.push(E::F::from(M31::from_u32_unchecked(
            CANONICAL_POSEIDON_CALL_RELATION_ID,
        )));
        canonical_values.extend(canonical_call_relation_values(&trace));
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            active.clone(),
            &canonical_values,
        ));
        add_memory_relations(&mut eval, &trace, &self.common_lookup_elements, active);

        let mut transcript_values = Vec::with_capacity(1 + 2 + N_KIND_SELECTORS + N_CALL_IDS);
        transcript_values.push(E::F::from(M31::from_u32_unchecked(
            TRANSCRIPT_POSEIDON_CALL_RELATION_ID,
        )));
        transcript_values.push(trace.global_index.clone());
        transcript_values.push(trace.source_index.clone());
        transcript_values.extend(trace.kind_selectors.iter().cloned());
        transcript_values.extend(trace.ids.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(trace.active.clone() * trace.source_selectors[0].clone()),
            &transcript_values,
        ));

        let mut merkle_values = Vec::with_capacity(1 + 2 + 2 + 3 + N_CALL_IDS);
        merkle_values.push(E::F::from(M31::from_u32_unchecked(
            MERKLE_POSEIDON_CALL_RELATION_ID,
        )));
        merkle_values.push(trace.source_index.clone());
        merkle_values.push(trace.source_arg.clone());
        merkle_values.push(trace.source_selectors[1].clone());
        merkle_values.push(trace.source_selectors[2].clone());
        merkle_values.extend(trace.kind_selectors[..3].iter().cloned());
        merkle_values.extend(trace.ids.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            -E::EF::from(
                trace.active
                    * (trace.source_selectors[1].clone() + trace.source_selectors[2].clone()),
            ),
            &merkle_values,
        ));

        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Default)]
struct EvalCollector {
    columns: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl TreeBuilder<SimdBackend> for EvalCollector {
    fn extend_evals(
        &mut self,
        columns: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) -> TreeSubspan {
        let col_start = self.columns.len();
        self.columns.extend(columns);
        TreeSubspan {
            tree_index: 1,
            col_start,
            col_end: self.columns.len(),
        }
    }
}

/// Base witness for the official Poseidon component closure plus the semantic caller table.
pub(crate) struct Poseidon252ClosureWitness {
    pub padded_calls: Vec<Poseidon252PermutationCall>,
    pub n_calls: usize,
    pub synthetic_memory: SyntheticPoseidonMemory,
    pub caller_log_size: u32,
    pub metadata_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub caller_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub expected_value_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_claim: CairoClaim,
    pub cairo_interaction_generator: CairoInteractionClaimGenerator,
    pub preprocessed_trace: Arc<PreProcessedTrace>,
}

impl Poseidon252ClosureWitness {
    pub(crate) fn new(calls: &[Poseidon252PermutationCall]) -> Result<Self, Poseidon252AirError> {
        let metadata = calls
            .iter()
            .enumerate()
            .map(|(index, call)| CanonicalCallMetadata::synthetic(index, call))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new_with_metadata(calls, metadata, &[])
    }

    pub(crate) fn from_canonical_calls(
        calls: &[CanonicalPoseidonCall],
    ) -> Result<Self, Poseidon252AirError> {
        let metadata = calls
            .iter()
            .map(CanonicalCallMetadata::from_canonical)
            .collect::<Result<Vec<_>, _>>()?;
        let calls = calls
            .iter()
            .map(|call| call.call.clone())
            .collect::<Vec<_>>();
        Self::new_with_metadata(&calls, metadata, &[])
    }

    pub(crate) fn from_canonical_calls_and_values(
        calls: &[CanonicalPoseidonCall],
        extra_values: &[FieldElement252],
    ) -> Result<Self, Poseidon252AirError> {
        let metadata = calls
            .iter()
            .map(CanonicalCallMetadata::from_canonical)
            .collect::<Result<Vec<_>, _>>()?;
        let calls = calls
            .iter()
            .map(|call| call.call.clone())
            .collect::<Vec<_>>();
        Self::new_with_metadata(&calls, metadata, extra_values)
    }

    fn new_with_metadata(
        calls: &[Poseidon252PermutationCall],
        mut metadata: Vec<CanonicalCallMetadata>,
        extra_values: &[FieldElement252],
    ) -> Result<Self, Poseidon252AirError> {
        if calls.is_empty() {
            return Err(Poseidon252AirError::EmptyCalls);
        }
        if let Some(index) = calls.iter().position(|call| !call.is_valid()) {
            return Err(Poseidon252AirError::InvalidCall { index });
        }

        let active_call_count = calls.len();
        let transcript_call_indices = metadata
            .iter()
            .enumerate()
            .filter_map(|(index, metadata)| {
                (metadata.source_selectors[0] == BaseField::from(1u32)).then_some(index)
            })
            .collect::<Vec<_>>();
        let merkle_call_indices = metadata
            .iter()
            .enumerate()
            .filter_map(|(index, metadata)| {
                (metadata.source_selectors[1] == BaseField::from(1u32)
                    || metadata.source_selectors[2] == BaseField::from(1u32))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let merkle_leaf_call_indices = metadata
            .iter()
            .enumerate()
            .filter_map(|(index, metadata)| {
                (metadata.kind_selectors[0] == BaseField::from(1u32)
                    || metadata.kind_selectors[1] == BaseField::from(1u32))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        let padded_size = active_call_count.next_power_of_two().max(N_LANES);
        let mut padded_calls = calls.to_vec();
        padded_calls.resize(padded_size, calls.last().unwrap().clone());
        metadata.resize_with(padded_size, CanonicalCallMetadata::padding);
        let caller_log_size = padded_size.ilog2();

        let synthetic_memory = SyntheticPoseidonMemory::new(&padded_calls, extra_values);
        let preprocessed_trace = Arc::new(PreProcessedTrace::canonical_without_pedersen());
        let component_names: IndexSet<&str> = POSEIDON_CLOSURE_COMPONENTS.into_iter().collect();
        let mut cairo_generator = CairoClaimGenerator::default();
        cairo_generator.fill_components(
            &component_names,
            CasmStatesByOpcode::default(),
            &BuiltinSegments::default(),
            Arc::clone(&synthetic_memory.memory),
            Arc::clone(&preprocessed_trace),
        );

        let aggregator = cairo_generator.poseidon_aggregator.as_ref().unwrap();
        for ids in &synthetic_memory.call_ids {
            aggregator
                .mults
                .entry((ids.input, ids.output))
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(1, Ordering::Relaxed);
        }

        // The aggregator itself adds one MemoryIdToBig use per ID while writing its trace. Add a
        // second use for the caller AIR's explicit value binding on every padded row, a third use
        // for the semantic consumer on active rows, and a fourth use for the transcript/Merkle
        // semantic call tables, and a fifth use for Merkle leaf packing rows. Extra transcript
        // payload values each add one further explicit semantic use below.
        let memory_id_to_big = cairo_generator.memory_id_to_big.as_ref().unwrap();
        for id in synthetic_memory.call_ids.iter().flat_map(|ids| ids.flat()) {
            memory_id_to_big.add_input(&id);
        }
        for id in synthetic_memory.call_ids[..active_call_count]
            .iter()
            .flat_map(|ids| ids.flat())
        {
            memory_id_to_big.add_input(&id);
        }
        for id in transcript_call_indices
            .into_iter()
            .flat_map(|index| synthetic_memory.call_ids[index].flat())
        {
            memory_id_to_big.add_input(&id);
        }
        for id in merkle_call_indices
            .into_iter()
            .flat_map(|index| synthetic_memory.call_ids[index].flat())
        {
            memory_id_to_big.add_input(&id);
        }
        for id in merkle_leaf_call_indices
            .into_iter()
            .flat_map(|index| synthetic_memory.call_ids[index].flat())
        {
            memory_id_to_big.add_input(&id);
        }
        for id in &synthetic_memory.extra_ids {
            memory_id_to_big.add_input(id);
        }

        let mut cairo_collector = EvalCollector::default();
        let (cairo_claim, cairo_interaction_generator) =
            cairo_generator.write_trace(&mut cairo_collector);
        let metadata_trace = gen_metadata_trace(&metadata, caller_log_size);
        let caller_trace = gen_caller_trace(&synthetic_memory.call_ids, caller_log_size);
        let expected_value_trace = gen_expected_value_trace(&padded_calls, caller_log_size);

        Ok(Self {
            padded_calls,
            n_calls: active_call_count,
            synthetic_memory,
            caller_log_size,
            metadata_trace,
            caller_trace,
            expected_value_trace,
            cairo_base_trace: cairo_collector.columns,
            cairo_claim,
            cairo_interaction_generator,
            preprocessed_trace,
        })
    }

    pub(crate) fn write_interaction_trace(
        self,
        common_lookup_elements: &CommonLookupElements,
    ) -> Result<Poseidon252ClosureInteraction, Poseidon252AirError> {
        let mut cairo_collector = EvalCollector::default();
        let cairo_interaction_claim = self
            .cairo_interaction_generator
            .write_interaction_trace(&mut cairo_collector, common_lookup_elements);
        let (caller_interaction_trace, caller_claimed_sum) = gen_caller_interaction_trace(
            &self.metadata_trace,
            &self.caller_trace,
            &self.expected_value_trace,
            self.caller_log_size,
            common_lookup_elements,
        );
        let (semantic_interaction_trace, semantic_claimed_sum) = gen_semantic_interaction_trace(
            &self.metadata_trace,
            &self.caller_trace,
            &self.expected_value_trace,
            self.caller_log_size,
            common_lookup_elements,
        );
        let lookup_residual = cairo_interaction_claim
            .flatten_interaction_claim()
            .into_iter()
            .sum::<SecureField>()
            + caller_claimed_sum
            + semantic_claimed_sum;

        Ok(Poseidon252ClosureInteraction {
            cairo_interaction_trace: cairo_collector.columns,
            caller_interaction_trace,
            semantic_interaction_trace,
            cairo_interaction_claim,
            caller_claimed_sum,
            semantic_claimed_sum,
            lookup_residual,
        })
    }

    /// Returns only the fixed official preprocessed columns used by the generated closure.
    /// Canonical call values are witness data and therefore remain in the committed base trace.
    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        let (mut ids, mut evaluations) =
            select_preprocessed_columns(&self.cairo_claim, &self.preprocessed_trace);
        let (active_id, active_evaluation) = gen_prefix_active_column(
            poseidon_active_column_id(self.caller_log_size, self.n_calls),
            self.caller_log_size,
            self.n_calls,
        );
        ids.push(active_id);
        evaluations.push(active_evaluation);
        (ids, evaluations)
    }

    pub(crate) fn caller_base_trace(
        &self,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        self.metadata_trace
            .iter()
            .chain(&self.caller_trace)
            .chain(&self.expected_value_trace)
            .cloned()
            .collect()
    }

    pub(crate) fn semantic_base_trace(
        &self,
    ) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        self.caller_base_trace()
    }
}

pub(crate) fn poseidon_preprocessed_columns_for_claim(
    cairo_claim: &CairoClaim,
    caller_log_size: u32,
    n_calls: usize,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let trace = PreProcessedTrace::canonical_without_pedersen();
    let (mut ids, mut evaluations) = select_preprocessed_columns(cairo_claim, &trace);
    let (active_id, active_evaluation) = gen_prefix_active_column(
        poseidon_active_column_id(caller_log_size, n_calls),
        caller_log_size,
        n_calls,
    );
    ids.push(active_id);
    evaluations.push(active_evaluation);
    (ids, evaluations)
}

pub(crate) fn recursive_preprocessed_commitment_root(
    config: PcsConfig,
    evaluations: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) -> Blake2sHash {
    let max_log_size = evaluations
        .iter()
        .map(|evaluation| evaluation.domain.log_size())
        .max()
        .expect("Poseidon closure preprocessed trace is non-empty");
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_log_size + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let polynomials = SimdBackend::interpolate_columns(evaluations, &twiddles);
    let tree = CommitmentTreeProver::<SimdBackend, Blake2sMerkleChannel>::new(
        polynomials,
        config.fri_config.log_blowup_factor,
        &twiddles,
        false,
        config.lifting_log_size,
        &BaseColumnPool::new(),
    );
    tree.commitment.root()
}

fn select_preprocessed_columns(
    cairo_claim: &CairoClaim,
    preprocessed_trace: &PreProcessedTrace,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let mut sequence_log_sizes: HashSet<u32> = cairo_claim.log_sizes()[1].iter().copied().collect();
    sequence_log_sizes.extend([6, 18, 20]);

    let mut ids = Vec::new();
    let mut evals = Vec::new();
    for column in &preprocessed_trace.columns {
        let id = column.id();
        let include = id
            .id
            .strip_prefix("seq_")
            .and_then(|log_size| log_size.parse::<u32>().ok())
            .is_some_and(|log_size| sequence_log_sizes.contains(&log_size))
            || id.id.starts_with("poseidon_round_keys_")
            || id.id.starts_with("range_check_9_9_column_")
            || id.id.starts_with("range_check_4_4_column_")
            || id.id.starts_with("range_check_4_4_4_4_column_")
            || id.id.starts_with("range_check_3_3_3_3_3_column_");
        if include {
            ids.push(id);
            evals.push(column.gen_column_simd());
        }
    }

    (ids, evals)
}

fn gen_metadata_trace(
    metadata: &[CanonicalCallMetadata],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    let rows = metadata
        .iter()
        .map(CanonicalCallMetadata::flat)
        .collect::<Vec<_>>();
    (0..N_CALL_METADATA_COLUMNS)
        .map(|column| {
            CircleEvaluation::new(
                domain,
                BaseColumn::from_iter(rows.iter().map(|row| row[column])),
            )
        })
        .collect()
}

pub(crate) struct Poseidon252ClosureInteraction {
    pub cairo_interaction_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub caller_interaction_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub semantic_interaction_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_interaction_claim: CairoInteractionClaim,
    pub caller_claimed_sum: SecureField,
    pub semantic_claimed_sum: SecureField,
    pub lookup_residual: SecureField,
}

/// Verifier/prover component bundle for the official Cairo Poseidon closure and both canonical
/// call tables. The supplied allocator is advanced past the generated Cairo structure before the
/// caller and semantic components are allocated, so subsequent recursive components can continue
/// from the exact same tree offsets on both sides.
pub(crate) struct Poseidon252ClosureComponents {
    pub cairo: CairoComponents,
    pub caller: FrameworkComponent<CanonicalPoseidonCallAir>,
    pub semantic: FrameworkComponent<CanonicalPoseidonSemanticAir>,
}

impl Poseidon252ClosureComponents {
    pub(crate) fn new(
        cairo_claim: &CairoClaim,
        common_lookup_elements: &CommonLookupElements,
        cairo_interaction_claim: &CairoInteractionClaim,
        caller_log_size: u32,
        n_calls: usize,
        caller_claimed_sum: SecureField,
        semantic_claimed_sum: SecureField,
        preprocessed_ids: &[PreProcessedColumnId],
        following_allocator: &mut TraceLocationAllocator,
    ) -> Self {
        let cairo = CairoComponents::new(
            cairo_claim,
            common_lookup_elements,
            cairo_interaction_claim,
            preprocessed_ids,
        );
        following_allocator.next_for_structure(&cairo_claim.log_sizes());
        let caller = FrameworkComponent::new(
            following_allocator,
            CanonicalPoseidonCallAir::new(caller_log_size, n_calls, common_lookup_elements.clone()),
            caller_claimed_sum,
        );
        let semantic = FrameworkComponent::new(
            following_allocator,
            CanonicalPoseidonSemanticAir::new(
                caller_log_size,
                n_calls,
                common_lookup_elements.clone(),
            ),
            semantic_claimed_sum,
        );
        Self {
            cairo,
            caller,
            semantic,
        }
    }

    pub(crate) fn prover_components(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        let mut components = cairo_provers(&self.cairo);
        components.push(&self.caller);
        components.push(&self.semantic);
        components
    }

    pub(crate) fn verifier_components(&self) -> Vec<&dyn Component> {
        let mut components = self.cairo.components();
        components.push(&self.caller);
        components.push(&self.semantic);
        components
    }
}

fn gen_caller_trace(
    calls: &[SyntheticPoseidonCallIds],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    (0..N_CALL_IDS)
        .map(|slot| {
            let column = BaseColumn::from_iter(calls.iter().map(|ids| ids.flat()[slot]));
            CircleEvaluation::new(domain, column)
        })
        .collect()
}

fn gen_expected_value_trace(
    calls: &[Poseidon252PermutationCall],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    let values: Vec<[[BaseField; FELT252_N_WORDS]; N_CALL_IDS]> = calls
        .iter()
        .map(|call| {
            let flat_values: [FieldElement252; N_CALL_IDS] = [
                call.input[0],
                call.input[1],
                call.input[2],
                call.output[0],
                call.output[1],
                call.output[2],
            ];
            flat_values.map(field_element_to_9_bit_limbs)
        })
        .collect();

    (0..N_CALL_IDS)
        .flat_map(|slot| {
            let values = &values;
            (0..FELT252_N_WORDS).map(move |limb| {
                let column = BaseColumn::from_iter(values.iter().map(|row| row[slot][limb]));
                CircleEvaluation::new(domain, column)
            })
        })
        .collect()
}

fn gen_caller_interaction_trace(
    metadata_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    caller_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    expected_value_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    common_lookup_elements: &CommonLookupElements,
) -> (
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
        POSEIDON_AGGREGATOR_RELATION_ID,
    ));
    let memory_relation_id =
        PackedBaseField::broadcast(BaseField::from(MEMORY_ID_TO_BIG_RELATION_ID));
    let mut logup = LogupTraceGenerator::new(log_size);

    let fraction =
        |relation_index: usize, vec_row: usize| -> (PackedSecureField, PackedSecureField) {
            if relation_index == 0 {
                let mut values = Vec::with_capacity(1 + N_CALL_IDS);
                values.push(relation_id);
                values.extend(
                    caller_trace
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                (
                    PackedSecureField::broadcast(SecureField::from(1u32)),
                    common_lookup_elements.combine(&values),
                )
            } else if relation_index <= N_CALL_IDS {
                let slot = relation_index - 1;
                let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
                values.push(memory_relation_id);
                values.push(caller_trace[slot].values.data[vec_row]);
                values.extend((0..FELT252_N_WORDS).map(|limb| {
                    expected_value_trace[slot * FELT252_N_WORDS + limb]
                        .values
                        .data[vec_row]
                }));
                (
                    PackedSecureField::broadcast(SecureField::from(1u32)),
                    common_lookup_elements.combine(&values),
                )
            } else {
                let mut values = Vec::with_capacity(1 + N_CALL_METADATA_COLUMNS - 1 + N_CALL_IDS);
                values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                    CANONICAL_POSEIDON_CALL_RELATION_ID,
                )));
                values.extend(
                    metadata_trace[1..]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    caller_trace
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                (
                    -PackedSecureField::from(metadata_trace[0].values.data[vec_row]),
                    common_lookup_elements.combine(&values),
                )
            }
        };

    const N_RELATIONS: usize = 2 + N_CALL_IDS;
    for pair_start in (0..N_RELATIONS).step_by(2) {
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let (numerator0, denominator0) = fraction(pair_start, vec_row);
            if pair_start + 1 < N_RELATIONS {
                let (numerator1, denominator1) = fraction(pair_start + 1, vec_row);
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

fn gen_semantic_interaction_trace(
    metadata_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    caller_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    expected_value_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    common_lookup_elements: &CommonLookupElements,
) -> (
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let memory_relation_id =
        PackedBaseField::broadcast(BaseField::from(MEMORY_ID_TO_BIG_RELATION_ID));
    let canonical_relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
        CANONICAL_POSEIDON_CALL_RELATION_ID,
    ));
    let mut logup = LogupTraceGenerator::new(log_size);

    let fraction =
        |relation_index: usize, vec_row: usize| -> (PackedSecureField, PackedSecureField) {
            let active = PackedSecureField::from(metadata_trace[0].values.data[vec_row]);
            if relation_index == 0 {
                let mut values = Vec::with_capacity(1 + N_CALL_METADATA_COLUMNS - 1 + N_CALL_IDS);
                values.push(canonical_relation_id);
                values.extend(
                    metadata_trace[1..]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    caller_trace
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                (active, common_lookup_elements.combine(&values))
            } else if relation_index <= N_CALL_IDS {
                let slot = relation_index - 1;
                let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
                values.push(memory_relation_id);
                values.push(caller_trace[slot].values.data[vec_row]);
                values.extend((0..FELT252_N_WORDS).map(|limb| {
                    expected_value_trace[slot * FELT252_N_WORDS + limb]
                        .values
                        .data[vec_row]
                }));
                (active, common_lookup_elements.combine(&values))
            } else if relation_index == 1 + N_CALL_IDS {
                let mut values = Vec::with_capacity(1 + 2 + N_KIND_SELECTORS + N_CALL_IDS);
                values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                    TRANSCRIPT_POSEIDON_CALL_RELATION_ID,
                )));
                values.push(metadata_trace[1].values.data[vec_row]);
                values.push(metadata_trace[2].values.data[vec_row]);
                values.extend(
                    metadata_trace[4 + N_SOURCE_SELECTORS..]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    caller_trace
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                let transcript_source = metadata_trace[4].values.data[vec_row];
                (
                    -(active * PackedSecureField::from(transcript_source)),
                    common_lookup_elements.combine(&values),
                )
            } else {
                let mut values = Vec::with_capacity(1 + 2 + 2 + 3 + N_CALL_IDS);
                values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
                    MERKLE_POSEIDON_CALL_RELATION_ID,
                )));
                values.push(metadata_trace[2].values.data[vec_row]);
                values.push(metadata_trace[3].values.data[vec_row]);
                values.push(metadata_trace[5].values.data[vec_row]);
                values.push(metadata_trace[6].values.data[vec_row]);
                values.extend(
                    metadata_trace[4 + N_SOURCE_SELECTORS..4 + N_SOURCE_SELECTORS + 3]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    caller_trace
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                let merkle_source =
                    metadata_trace[5].values.data[vec_row] + metadata_trace[6].values.data[vec_row];
                (
                    -(active * PackedSecureField::from(merkle_source)),
                    common_lookup_elements.combine(&values),
                )
            }
        };

    const N_RELATIONS: usize = 3 + N_CALL_IDS;
    for pair_start in (0..N_RELATIONS).step_by(2) {
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let (numerator0, denominator0) = fraction(pair_start, vec_row);
            if pair_start + 1 < N_RELATIONS {
                let (numerator1, denominator1) = fraction(pair_start + 1, vec_row);
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

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use starknet_crypto::poseidon_permute_comp;
    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{
        FrameworkComponent, PREPROCESSED_TRACE_IDX, TraceLocationAllocator,
        assert_constraints_on_trace,
    };

    use super::*;
    use crate::stwo_backend::recursive::poseidon252_replay::{
        Poseidon252CallKind, Poseidon252PermutationCall,
    };

    fn sample_call(seed: u64) -> Poseidon252PermutationCall {
        let input = [seed.into(), (seed + 1).into(), (seed + 2).into()];
        let mut output = input;
        poseidon_permute_comp(&mut output);
        Poseidon252PermutationCall {
            kind: Poseidon252CallKind::TranscriptMixFelts,
            input,
            output,
        }
    }

    fn assert_component<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &TreeVec<Vec<&Vec<M31>>>,
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
    fn synthetic_memory_reuses_equal_felt_values() {
        let call = sample_call(7);
        let memory = SyntheticPoseidonMemory::new(&[call.clone(), call], &[]);
        assert_eq!(memory.call_ids[0], memory.call_ids[1]);
        assert_eq!(memory.memory.f252_values.len(), 6);
    }

    #[test]
    fn official_poseidon_closure_balances_caller_and_memory_bindings() {
        let witness = Poseidon252ClosureWitness::new(&[sample_call(11), sample_call(19)]).unwrap();
        assert_eq!(witness.padded_calls.len(), N_LANES);
        assert_eq!(witness.caller_trace.len(), N_CALL_IDS);
        assert_eq!(witness.expected_value_trace.len(), N_CALL_VALUE_COLUMNS);
        assert_eq!(
            witness.caller_base_trace().len(),
            POSEIDON252_CALL_AIR_NUM_COLUMNS
        );
        assert_eq!(
            witness.semantic_base_trace().len(),
            POSEIDON252_CALL_AIR_NUM_COLUMNS
        );
        assert!(witness.cairo_claim.poseidon_aggregator.is_some());
        assert!(witness.cairo_claim.memory_id_to_big.is_some());

        let interaction = witness
            .write_interaction_trace(&CommonLookupElements::dummy())
            .unwrap();
        assert!(!interaction.cairo_interaction_trace.is_empty());
        assert_eq!(interaction.caller_interaction_trace.len(), 16);
        assert_eq!(interaction.semantic_interaction_trace.len(), 20);
        assert_ne!(interaction.lookup_residual, SecureField::from(0u32));
    }

    #[test]
    fn official_poseidon_closure_satisfies_every_air_component() {
        std::thread::Builder::new()
            .stack_size(128 * 1024 * 1024)
            .spawn(|| {
                let witness =
                    Poseidon252ClosureWitness::from_canonical_calls(&[CanonicalPoseidonCall {
                        global_index: 0,
                        source: PoseidonCallSource::Transcript,
                        source_index: 0,
                        call: sample_call(29),
                    }])
                    .unwrap();
                let common_lookup_elements = CommonLookupElements::dummy();
                let caller_log_size = witness.caller_log_size;
                let n_calls = witness.n_calls;
                let cairo_claim = witness.cairo_claim.clone();
                let (preprocessed_ids, preprocessed_trace) = witness.preprocessed_columns();
                let mut base_trace = witness.cairo_base_trace.clone();
                base_trace.extend(witness.caller_base_trace());
                base_trace.extend(witness.semantic_base_trace());
                let interaction = witness
                    .write_interaction_trace(&common_lookup_elements)
                    .unwrap();
                let mut interaction_trace = interaction.cairo_interaction_trace;
                interaction_trace.extend(interaction.caller_interaction_trace);
                interaction_trace.extend(interaction.semantic_interaction_trace);

                let mut component_allocator =
                    TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids);
                let components = Poseidon252ClosureComponents::new(
                    &cairo_claim,
                    &common_lookup_elements,
                    &interaction.cairo_interaction_claim,
                    caller_log_size,
                    n_calls,
                    interaction.caller_claimed_sum,
                    interaction.semantic_claimed_sum,
                    &preprocessed_ids,
                    &mut component_allocator,
                );
                assert_eq!(components.prover_components().len(), 16);
                assert_eq!(components.verifier_components().len(), 16);

                let trace = TreeVec::new(vec![
                    preprocessed_trace
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    base_trace
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    interaction_trace
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                ]);
                let trace = trace.as_cols_ref();

                assert_component(
                    components.cairo.poseidon_aggregator.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    components
                        .cairo
                        .poseidon_3_partial_rounds_chain
                        .as_ref()
                        .unwrap(),
                    &trace,
                );
                assert_component(
                    components.cairo.poseidon_full_round_chain.as_ref().unwrap(),
                    &trace,
                );
                assert_component(components.cairo.cube_252.as_ref().unwrap(), &trace);
                assert_component(
                    components.cairo.poseidon_round_keys.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    components.cairo.range_check_252_width_27.as_ref().unwrap(),
                    &trace,
                );
                for component in &components.cairo.memory_id_to_big {
                    assert_component(component, &trace);
                }
                assert_component(
                    components.cairo.memory_id_to_small.as_ref().unwrap(),
                    &trace,
                );
                assert_component(components.cairo.range_check_18.as_ref().unwrap(), &trace);
                assert_component(components.cairo.range_check_20.as_ref().unwrap(), &trace);
                assert_component(components.cairo.range_check_4_4.as_ref().unwrap(), &trace);
                assert_component(components.cairo.range_check_9_9.as_ref().unwrap(), &trace);
                assert_component(
                    components.cairo.range_check_4_4_4_4.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    components.cairo.range_check_3_3_3_3_3.as_ref().unwrap(),
                    &trace,
                );
                assert_component(&components.caller, &trace);
                assert_component(&components.semantic, &trace);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn rejects_invalid_native_call_before_witness_generation() {
        let mut call = sample_call(23);
        call.output[0] += FieldElement252::ONE;
        assert!(matches!(
            Poseidon252ClosureWitness::new(&[call]),
            Err(Poseidon252AirError::InvalidCall { index: 0 })
        ));
    }
}
