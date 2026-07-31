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

use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::{CommonLookupElements, MEMORY_ID_TO_BIG_RELATION_ID};
use indexmap::IndexSet;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{TreeSubspan, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_cairo_adapter::builtins::BuiltinSegments;
use stwo_cairo_adapter::memory::{Memory, MemoryBuilder, MemoryConfig, MemoryValue};
use stwo_cairo_adapter::opcodes::CasmStatesByOpcode;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTrace;
use stwo_cairo_common::prover_types::cpu::{FELT252_N_WORDS, M31};
use stwo_cairo_common::prover_types::felt::split_f252;
use stwo_cairo_prover::witness::cairo_claim_generator::{
    CairoClaimGenerator, CairoInteractionClaimGenerator,
};
use stwo_cairo_prover::witness::utils::TreeBuilder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
};

use super::poseidon252_replay::{Poseidon252CallKind, Poseidon252PermutationCall};
use super::replay_witness::{CanonicalPoseidonCall, PoseidonCallSource};

const POSEIDON_AGGREGATOR_RELATION_ID: u32 = 1_551_892_206;
const N_CALL_IDS: usize = 6;
const N_CALL_VALUE_COLUMNS: usize = N_CALL_IDS * FELT252_N_WORDS;
const N_SOURCE_SELECTORS: usize = 3;
const N_KIND_SELECTORS: usize = 10;
const N_CALL_METADATA_COLUMNS: usize = 4 + N_SOURCE_SELECTORS + N_KIND_SELECTORS;
pub(crate) const POSEIDON252_CALL_AIR_NUM_COLUMNS: usize =
    N_CALL_METADATA_COLUMNS + N_CALL_IDS + N_CALL_VALUE_COLUMNS;

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
    #[error("official Poseidon252 lookup closure is unbalanced: {0:?}")]
    UnbalancedLookup(SecureField),
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

const fn kind_index(kind: Poseidon252CallKind) -> usize {
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
    fn flat(self) -> [BaseField; N_CALL_IDS] {
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
}

impl SyntheticPoseidonMemory {
    fn new(calls: &[Poseidon252PermutationCall]) -> Self {
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

        Self {
            memory: Arc::new(memory),
            call_ids,
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

fn field_element_to_9_bit_limbs(value: FieldElement252) -> [BaseField; FELT252_N_WORDS] {
    split_f252(field_element_to_u32_words(value))
}

/// AIR-side caller of the official Poseidon closure.
///
/// Each row sends one positive `PoseidonAggregator(input_ids, output_ids)` entry and six positive
/// `MemoryIdToBig(id, expected_9_bit_limbs)` entries. The official aggregator and synthetic memory
/// table consume the opposite multiplicities.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalPoseidonCallAir {
    log_size: u32,
    common_lookup_elements: CommonLookupElements,
}

impl CanonicalPoseidonCallAir {
    pub(crate) const fn new(log_size: u32, common_lookup_elements: CommonLookupElements) -> Self {
        Self {
            log_size,
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
        let one = E::F::from(M31::from(1));
        let two = E::F::from(M31::from(2));
        let three = E::F::from(M31::from(3));
        let active = eval.next_trace_mask();
        let global_index = eval.next_trace_mask();
        let source_index = eval.next_trace_mask();
        let source_arg = eval.next_trace_mask();
        let source_selectors: Vec<E::F> = (0..N_SOURCE_SELECTORS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let kind_selectors: Vec<E::F> = (0..N_KIND_SELECTORS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let ids: Vec<E::F> = (0..N_CALL_IDS).map(|_| eval.next_trace_mask()).collect();
        let expected_limbs: Vec<Vec<E::F>> = (0..N_CALL_IDS)
            .map(|_| {
                (0..FELT252_N_WORDS)
                    .map(|_| eval.next_trace_mask())
                    .collect()
            })
            .collect();

        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        for selector in source_selectors.iter().chain(&kind_selectors) {
            eval.add_constraint(selector.clone() * (selector.clone() - one.clone()));
        }
        let zero = E::F::from(M31::from(0));
        let source_sum = source_selectors
            .iter()
            .cloned()
            .fold(zero.clone(), |sum, value| sum + value);
        let kind_sum = kind_selectors
            .iter()
            .cloned()
            .fold(zero.clone(), |sum, value| sum + value);
        eval.add_constraint(source_sum - active.clone());
        eval.add_constraint(kind_sum - active.clone());

        let inactive = one.clone() - active.clone();
        eval.add_constraint(inactive.clone() * global_index);
        eval.add_constraint(inactive.clone() * source_index);
        eval.add_constraint(inactive * source_arg.clone());
        eval.add_constraint(source_selectors[0].clone() * source_arg);

        let merkle_kind =
            kind_selectors[0].clone() + kind_selectors[1].clone() + kind_selectors[2].clone();
        let transcript_kind = kind_selectors[3..]
            .iter()
            .cloned()
            .fold(zero.clone(), |sum, value| sum + value);
        eval.add_constraint(source_selectors[0].clone() * merkle_kind);
        eval.add_constraint(
            (source_selectors[1].clone() + source_selectors[2].clone()) * transcript_kind,
        );

        let hash_pair_kind = kind_selectors[2].clone()
            + kind_selectors[3].clone()
            + kind_selectors[6].clone()
            + kind_selectors[9].clone();
        let draw_kind = kind_selectors[7].clone();
        for limb in 0..FELT252_N_WORDS {
            let expected_constant = if limb == 0 {
                hash_pair_kind.clone() * two.clone() + draw_kind.clone() * three.clone()
            } else {
                zero.clone()
            };
            eval.add_constraint(
                (hash_pair_kind.clone() + draw_kind.clone()) * expected_limbs[2][limb].clone()
                    - expected_constant,
            );
        }

        let mut poseidon_values = Vec::with_capacity(1 + N_CALL_IDS);
        poseidon_values.push(E::F::from(M31::from(POSEIDON_AGGREGATOR_RELATION_ID)));
        poseidon_values.extend(ids.iter().cloned());
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(E::F::from(M31::from(1))),
            &poseidon_values,
        ));

        for slot in 0..N_CALL_IDS {
            let mut memory_values = Vec::with_capacity(2 + FELT252_N_WORDS);
            memory_values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
            memory_values.push(ids[slot].clone());
            memory_values.extend(expected_limbs[slot].iter().cloned());
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(E::F::from(M31::from(1))),
                &memory_values,
            ));
        }

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
        Self::new_with_metadata(calls, metadata)
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
        Self::new_with_metadata(&calls, metadata)
    }

    fn new_with_metadata(
        calls: &[Poseidon252PermutationCall],
        mut metadata: Vec<CanonicalCallMetadata>,
    ) -> Result<Self, Poseidon252AirError> {
        if calls.is_empty() {
            return Err(Poseidon252AirError::EmptyCalls);
        }
        if let Some(index) = calls.iter().position(|call| !call.is_valid()) {
            return Err(Poseidon252AirError::InvalidCall { index });
        }

        let padded_size = calls.len().next_power_of_two().max(N_LANES);
        let mut padded_calls = calls.to_vec();
        padded_calls.resize(padded_size, calls.last().unwrap().clone());
        metadata.resize_with(padded_size, CanonicalCallMetadata::padding);
        let caller_log_size = padded_size.ilog2();

        let synthetic_memory = SyntheticPoseidonMemory::new(&padded_calls);
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
        // second use for the caller AIR's explicit value binding.
        let memory_id_to_big = cairo_generator.memory_id_to_big.as_ref().unwrap();
        for id in synthetic_memory.call_ids.iter().flat_map(|ids| ids.flat()) {
            memory_id_to_big.add_input(&id);
        }

        let mut cairo_collector = EvalCollector::default();
        let (cairo_claim, cairo_interaction_generator) =
            cairo_generator.write_trace(&mut cairo_collector);
        let metadata_trace = gen_metadata_trace(&metadata, caller_log_size);
        let caller_trace = gen_caller_trace(&synthetic_memory.call_ids, caller_log_size);
        let expected_value_trace = gen_expected_value_trace(&padded_calls, caller_log_size);

        Ok(Self {
            padded_calls,
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
            &self.caller_trace,
            &self.expected_value_trace,
            self.caller_log_size,
            common_lookup_elements,
        );
        let total_claimed_sum = cairo_interaction_claim
            .flatten_interaction_claim()
            .into_iter()
            .sum::<SecureField>()
            + caller_claimed_sum;
        if total_claimed_sum != SecureField::from(0u32) {
            return Err(Poseidon252AirError::UnbalancedLookup(total_claimed_sum));
        }

        Ok(Poseidon252ClosureInteraction {
            cairo_interaction_trace: cairo_collector.columns,
            caller_interaction_trace,
            cairo_interaction_claim,
            caller_claimed_sum,
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
        let mut sequence_log_sizes: HashSet<u32> =
            self.cairo_claim.log_sizes()[1].iter().copied().collect();
        sequence_log_sizes.extend([6, 18, 20]);

        let mut ids = Vec::new();
        let mut evals = Vec::new();
        for column in &self.preprocessed_trace.columns {
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

    pub(crate) fn cairo_log_sizes(&self) -> TreeVec<Vec<u32>> {
        self.cairo_claim.log_sizes()
    }
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
    pub cairo_interaction_claim: CairoInteractionClaim,
    pub caller_claimed_sum: SecureField,
}

pub(crate) fn audit_canonical_poseidon_closure(
    calls: &[CanonicalPoseidonCall],
) -> Result<(), Poseidon252AirError> {
    let witness = Poseidon252ClosureWitness::from_canonical_calls(calls)?;
    let common_lookup_elements = CommonLookupElements::dummy();
    let _ = witness.synthetic_memory.call_ids.len();
    let _ = witness.preprocessed_columns();
    let _ = witness.caller_base_trace();
    let _ = witness.cairo_log_sizes();
    witness.write_interaction_trace(&common_lookup_elements)?;
    Ok(())
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
    let one = PackedSecureField::broadcast(SecureField::from(1u32));
    let mut logup = LogupTraceGenerator::new(log_size);

    let denominator = |relation_index: usize, vec_row: usize| -> PackedSecureField {
        if relation_index == 0 {
            let mut values = Vec::with_capacity(1 + N_CALL_IDS);
            values.push(relation_id);
            values.extend(
                caller_trace
                    .iter()
                    .map(|column| column.values.data[vec_row]),
            );
            common_lookup_elements.combine(&values)
        } else {
            let slot = relation_index - 1;
            let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
            values.push(memory_relation_id);
            values.push(caller_trace[slot].values.data[vec_row]);
            values.extend((0..FELT252_N_WORDS).map(|limb| {
                expected_value_trace[slot * FELT252_N_WORDS + limb]
                    .values
                    .data[vec_row]
            }));
            common_lookup_elements.combine(&values)
        }
    };

    for pair_start in (0..7).step_by(2) {
        let mut column = logup.new_col();
        for vec_row in 0..n_vec_rows {
            let denominator0 = denominator(pair_start, vec_row);
            if pair_start + 1 < 7 {
                let denominator1 = denominator(pair_start + 1, vec_row);
                column.write_frac(
                    vec_row,
                    denominator0 + denominator1,
                    denominator0 * denominator1,
                );
            } else {
                column.write_frac(vec_row, one, denominator0);
            }
        }
        column.finalize_col();
    }
    logup.finalize_last()
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use cairo_air::cairo_components::CairoComponents;
    use starknet_crypto::poseidon_permute_comp;
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
        let memory = SyntheticPoseidonMemory::new(&[call.clone(), call]);
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
        assert!(witness.cairo_claim.poseidon_aggregator.is_some());
        assert!(witness.cairo_claim.memory_id_to_big.is_some());

        let interaction = witness
            .write_interaction_trace(&CommonLookupElements::dummy())
            .unwrap();
        assert!(!interaction.cairo_interaction_trace.is_empty());
        assert_eq!(interaction.caller_interaction_trace.len(), 16);
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
                let cairo_claim = witness.cairo_claim.clone();
                let cairo_log_sizes = witness.cairo_log_sizes();
                let (preprocessed_ids, preprocessed_trace) = witness.preprocessed_columns();
                let mut base_trace = witness.cairo_base_trace.clone();
                base_trace.extend(witness.caller_base_trace());
                let interaction = witness
                    .write_interaction_trace(&common_lookup_elements)
                    .unwrap();
                let mut interaction_trace = interaction.cairo_interaction_trace;
                interaction_trace.extend(interaction.caller_interaction_trace);

                let cairo_components = CairoComponents::new(
                    &cairo_claim,
                    &common_lookup_elements,
                    &interaction.cairo_interaction_claim,
                    &preprocessed_ids,
                );
                let mut caller_allocator =
                    TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids);
                caller_allocator.next_for_structure(&cairo_log_sizes);
                let caller_component = FrameworkComponent::new(
                    &mut caller_allocator,
                    CanonicalPoseidonCallAir::new(caller_log_size, common_lookup_elements),
                    interaction.caller_claimed_sum,
                );

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
                    cairo_components.poseidon_aggregator.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    cairo_components
                        .poseidon_3_partial_rounds_chain
                        .as_ref()
                        .unwrap(),
                    &trace,
                );
                assert_component(
                    cairo_components.poseidon_full_round_chain.as_ref().unwrap(),
                    &trace,
                );
                assert_component(cairo_components.cube_252.as_ref().unwrap(), &trace);
                assert_component(
                    cairo_components.poseidon_round_keys.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    cairo_components.range_check_252_width_27.as_ref().unwrap(),
                    &trace,
                );
                for component in &cairo_components.memory_id_to_big {
                    assert_component(component, &trace);
                }
                assert_component(
                    cairo_components.memory_id_to_small.as_ref().unwrap(),
                    &trace,
                );
                assert_component(cairo_components.range_check_18.as_ref().unwrap(), &trace);
                assert_component(cairo_components.range_check_20.as_ref().unwrap(), &trace);
                assert_component(cairo_components.range_check_4_4.as_ref().unwrap(), &trace);
                assert_component(cairo_components.range_check_9_9.as_ref().unwrap(), &trace);
                assert_component(
                    cairo_components.range_check_4_4_4_4.as_ref().unwrap(),
                    &trace,
                );
                assert_component(
                    cairo_components.range_check_3_3_3_3_3.as_ref().unwrap(),
                    &trace,
                );
                assert_component(&caller_component, &trace);
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
