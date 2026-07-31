//! Official Cairo AIR closure for the Poseidon252 calls recorded by the recursive verifier.
//!
//! The semantic transcript/Merkle/FRI AIRs consume felt252 values. This module assigns those
//! values deterministic synthetic Cairo memory IDs and connects each six-ID permutation call to
//! the audited `PoseidonAggregator` relation. Six additional `MemoryIdToBig` lookups bind the IDs
//! to the exact 28×9-bit limbs supplied by the semantic caller.

use std::array;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::{
    self, CommonLookupElements, MEMORY_ID_TO_BIG_RELATION_ID,
};
use indexmap::IndexSet;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{TreeSubspan, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{
    LOG_N_LANES, N_LANES, PackedBaseField,
};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_cairo_adapter::builtins::BuiltinSegments;
use stwo_cairo_adapter::memory::{Memory, MemoryBuilder, MemoryConfig, MemoryValue};
use stwo_cairo_adapter::opcodes::CasmStatesByOpcode;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    PreProcessedTrace,
};
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

use super::poseidon252_replay::Poseidon252PermutationCall;

const POSEIDON_AGGREGATOR_RELATION_ID: u32 = 1_551_892_206;
const N_CALL_IDS: usize = 6;
const N_CALL_VALUE_COLUMNS: usize = N_CALL_IDS * FELT252_N_WORDS;
pub(crate) const POSEIDON252_CALL_AIR_NUM_COLUMNS: usize = N_CALL_IDS;

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
                let ids = addresses.map(|address| {
                    BaseField::from_u32_unchecked(memory.get_raw_id(address))
                });
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

fn expected_value_column_id(slot: usize, limb: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_poseidon252_call_value_{slot}_limb_{limb}"),
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
    common_lookup_elements: CommonLookupElements,
}

impl CanonicalPoseidonCallAir {
    pub(crate) const fn new(
        log_size: u32,
        common_lookup_elements: CommonLookupElements,
    ) -> Self {
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
        let ids: Vec<E::F> = (0..N_CALL_IDS)
            .map(|_| eval.next_trace_mask())
            .collect();
        let expected_limbs: Vec<Vec<E::F>> = (0..N_CALL_IDS)
            .map(|slot| {
                (0..FELT252_N_WORDS)
                    .map(|limb| {
                        eval.get_preprocessed_column(expected_value_column_id(slot, limb))
                    })
                    .collect()
            })
            .collect();

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
    pub caller_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub expected_value_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_claim: CairoClaim,
    pub cairo_interaction_generator: CairoInteractionClaimGenerator,
    pub preprocessed_trace: Arc<PreProcessedTrace>,
}

impl Poseidon252ClosureWitness {
    pub(crate) fn new(
        calls: &[Poseidon252PermutationCall],
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
        let caller_log_size = padded_size.ilog2();

        let synthetic_memory = SyntheticPoseidonMemory::new(&padded_calls);
        let preprocessed_trace = Arc::new(PreProcessedTrace::canonical_without_pedersen());
        let component_names: IndexSet<&str> =
            POSEIDON_CLOSURE_COMPONENTS.into_iter().collect();
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
        for id in synthetic_memory
            .call_ids
            .iter()
            .flat_map(|ids| ids.flat())
        {
            memory_id_to_big.add_input(&id);
        }

        let mut cairo_collector = EvalCollector::default();
        let (cairo_claim, cairo_interaction_generator) =
            cairo_generator.write_trace(&mut cairo_collector);
        let caller_trace = gen_caller_trace(&synthetic_memory.call_ids, caller_log_size);
        let expected_value_trace = gen_expected_value_trace(&padded_calls, caller_log_size);

        Ok(Self {
            padded_calls,
            synthetic_memory,
            caller_log_size,
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

    /// Returns the minimal official preprocessed columns used by the generated closure, followed
    /// by the 168 caller value columns.
    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        let mut sequence_log_sizes: HashSet<u32> = self.cairo_claim.log_sizes()[1]
            .iter()
            .copied()
            .collect();
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

        for slot in 0..N_CALL_IDS {
            for limb in 0..FELT252_N_WORDS {
                ids.push(expected_value_column_id(slot, limb));
            }
        }
        evals.extend(self.expected_value_trace.iter().cloned());
        (ids, evals)
    }

    pub(crate) fn cairo_log_sizes(&self) -> TreeVec<Vec<u32>> {
        self.cairo_claim.log_sizes()
    }
}

pub(crate) struct Poseidon252ClosureInteraction {
    pub cairo_interaction_trace:
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub caller_interaction_trace:
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    pub cairo_interaction_claim: CairoInteractionClaim,
    pub caller_claimed_sum: SecureField,
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
                expected_value_trace[slot * FELT252_N_WORDS + limb].values.data[vec_row]
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
        PREPROCESSED_TRACE_IDX, FrameworkComponent, TraceLocationAllocator,
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
            kind: Poseidon252CallKind::MerkleParent,
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
        let witness =
            Poseidon252ClosureWitness::new(&[sample_call(11), sample_call(19)]).unwrap();
        assert_eq!(witness.padded_calls.len(), N_LANES);
        assert_eq!(witness.caller_trace.len(), POSEIDON252_CALL_AIR_NUM_COLUMNS);
        assert_eq!(witness.expected_value_trace.len(), N_CALL_VALUE_COLUMNS);
        assert!(witness.cairo_claim.poseidon_aggregator.is_some());
        assert!(witness.cairo_claim.memory_id_to_big.is_some());

        let interaction = witness
            .write_interaction_trace(&relations::CommonLookupElements::dummy())
            .unwrap();
        assert!(!interaction.cairo_interaction_trace.is_empty());
        assert_eq!(interaction.caller_interaction_trace.len(), 16);
    }

    #[test]
    fn official_poseidon_closure_satisfies_every_air_component() {
        std::thread::Builder::new()
            .stack_size(128 * 1024 * 1024)
            .spawn(|| {
                let witness = Poseidon252ClosureWitness::new(&[sample_call(29)]).unwrap();
                let common_lookup_elements = relations::CommonLookupElements::dummy();
                let caller_log_size = witness.caller_log_size;
                let cairo_claim = witness.cairo_claim.clone();
                let cairo_log_sizes = witness.cairo_log_sizes();
                let (preprocessed_ids, preprocessed_trace) = witness.preprocessed_columns();
                let mut base_trace = witness.cairo_base_trace.clone();
                base_trace.extend(witness.caller_trace.iter().cloned());
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

                assert_component(cairo_components.poseidon_aggregator.as_ref().unwrap(), &trace);
                assert_component(
                    cairo_components
                        .poseidon_3_partial_rounds_chain
                        .as_ref()
                        .unwrap(),
                    &trace,
                );
                assert_component(
                    cairo_components
                        .poseidon_full_round_chain
                        .as_ref()
                        .unwrap(),
                    &trace,
                );
                assert_component(cairo_components.cube_252.as_ref().unwrap(), &trace);
                assert_component(cairo_components.poseidon_round_keys.as_ref().unwrap(), &trace);
                assert_component(
                    cairo_components
                        .range_check_252_width_27
                        .as_ref()
                        .unwrap(),
                    &trace,
                );
                for component in &cairo_components.memory_id_to_big {
                    assert_component(component, &trace);
                }
                assert_component(cairo_components.memory_id_to_small.as_ref().unwrap(), &trace);
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
