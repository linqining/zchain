//! AIR for Stwo's lifted Poseidon252 Merkle leaf construction.
//!
//! Each row is one verifier-fixed leaf absorb/finalize call. The trace proves canonical M31 bit
//! decompositions, packs up to sixteen queried values into two felt252 messages with Stwo's
//! short-block length padding, and constrains the modular additions from the previous sponge state
//! into the exact Poseidon permutation inputs exported by the Merkle semantic router.

use core::array;

use cairo_air::relations::MEMORY_ID_TO_BIG_RELATION_ID;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs::poseidon252_merkle::construct_felt252_from_m31s;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo_cairo_common::prover_types::cpu::{FELT252_N_WORDS, M31, P_FELTS};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkEval, LogupTraceGenerator, ORIGINAL_TRACE_IDX, Relation, RelationEntry,
};

use super::merkle_semantic_air::{
    MERKLE_LEAF_CALL_RELATION_ID, MERKLE_QUERIED_VALUE_RELATION_ID, MerkleLeafCallSchedule,
    MerklePublicBindingWitness,
};
use super::poseidon252_air::{N_CALL_IDS, SyntheticPoseidonCallIds, field_element_to_9_bit_limbs};
use super::poseidon252_replay::Poseidon252CallKind;
use super::replay_witness::{CanonicalVerifierWitness, PoseidonCallSource};
use super::transcript_air::{N_ADDITION_CARRIES, modular_add_witness};

const N_VALUES_PER_CALL: usize = 16;
const N_BITS_PER_VALUE: usize = 31;
const N_BLOCKS: usize = 2;
const N_BLOCK_LENGTHS: usize = 9;

const PRE_ACTIVE: usize = 0;
const PRE_PCS_SOURCE: usize = 1;
const PRE_FRI_SOURCE: usize = 2;
const PRE_SOURCE_ARG: usize = 3;
const PRE_SOURCE_INDEX: usize = 4;
const PRE_ABSORB: usize = 5;
const PRE_FINALIZE: usize = 6;
const PRE_FIRST_IN_LEAF: usize = 7;
const PRE_CALL_INDEX: usize = 8;
const PRE_CALL_COUNT: usize = 9;
const PRE_NODE_INDEX: usize = 10;
const PRE_VALUE_START: usize = 11;
const PRE_VALUE_COUNT: usize = 12;
const PRE_VALUE_ACTIVE_START: usize = 13;
const PRE_BLOCK_LENGTH_START: usize = PRE_VALUE_ACTIVE_START + N_VALUES_PER_CALL;
const MERKLE_LEAF_PREPROCESSED_COLUMNS: usize = PRE_BLOCK_LENGTH_START + N_BLOCKS * N_BLOCK_LENGTHS;

const ABSORB_COLUMN: usize = 0;
const FINALIZE_COLUMN: usize = 1;
const BLOCK0_ACTIVE_COLUMN: usize = 2;
const ID_COLUMNS_START: usize = 3;
const CALL_VALUE_COLUMNS_START: usize = ID_COLUMNS_START + N_CALL_IDS;
const N_CALL_VALUE_COLUMNS: usize = N_CALL_IDS * FELT252_N_WORDS;
const VALUE_COLUMNS_START: usize = CALL_VALUE_COLUMNS_START + N_CALL_VALUE_COLUMNS;
const BIT_COLUMNS_START: usize = VALUE_COLUMNS_START + N_VALUES_PER_CALL;
const N_BIT_COLUMNS: usize = N_VALUES_PER_CALL * N_BITS_PER_VALUE;
const INVERSE_COLUMNS_START: usize = BIT_COLUMNS_START + N_BIT_COLUMNS;
const BLOCK_COLUMNS_START: usize = INVERSE_COLUMNS_START + N_VALUES_PER_CALL;
const N_BLOCK_COLUMNS: usize = N_BLOCKS * FELT252_N_WORDS;
const SUBTRACT_PRIME_COLUMNS_START: usize = BLOCK_COLUMNS_START + N_BLOCK_COLUMNS;
const CARRY_POS_COLUMNS_START: usize = SUBTRACT_PRIME_COLUMNS_START + N_BLOCKS;
const N_CARRY_COLUMNS: usize = N_BLOCKS * N_ADDITION_CARRIES;
const CARRY_NEG_COLUMNS_START: usize = CARRY_POS_COLUMNS_START + N_CARRY_COLUMNS;

pub(crate) const MERKLE_LEAF_AIR_NUM_COLUMNS: usize = CARRY_NEG_COLUMNS_START + N_CARRY_COLUMNS;
const N_LEAF_RELATIONS: usize = 7 + N_VALUES_PER_CALL;
pub(crate) const MERKLE_LEAF_INTERACTION_COLUMNS: usize = N_LEAF_RELATIONS.div_ceil(2) * 4;

#[derive(Debug, thiserror::Error)]
pub(crate) enum MerkleLeafAirError {
    #[error("canonical Merkle leaf schedule is empty")]
    EmptySchedule,
    #[error("Merkle leaf metadata does not fit M31")]
    MetadataOverflow,
    #[error("canonical Merkle leaf schedule differs from the public schedule")]
    ScheduleMismatch,
    #[error("canonical Merkle leaf call mapping is inconsistent")]
    InvalidCallMapping,
    #[error("canonical Merkle leaf value range is inconsistent")]
    InvalidValueRange,
    #[error("canonical Merkle leaf modular addition is inconsistent")]
    InvalidAddition,
}

#[derive(Debug, Clone)]
pub(crate) struct MerkleLeafPublicWitness {
    pub n_rows: usize,
    pub log_size: u32,
    schedule: Vec<MerkleLeafCallSchedule>,
    columns: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl MerkleLeafPublicWitness {
    pub(crate) fn new(binding: &MerklePublicBindingWitness) -> Result<Self, MerkleLeafAirError> {
        let schedule = binding.leaf_call_schedule();
        if schedule.is_empty() {
            return Err(MerkleLeafAirError::EmptySchedule);
        }
        let n_rows = schedule.len();
        let log_size = padded_log_size(n_rows);
        let mut rows = schedule
            .iter()
            .map(public_row)
            .collect::<Result<Vec<_>, _>>()?;
        rows.resize(
            1usize << log_size,
            [BaseField::from(0u32); MERKLE_LEAF_PREPROCESSED_COLUMNS],
        );
        let (_, columns) = rows_to_preprocessed_columns(&rows, log_size);
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
            (0..MERKLE_LEAF_PREPROCESSED_COLUMNS)
                .map(|column| leaf_preprocessed_id(column, self.log_size, self.n_rows))
                .collect(),
            self.columns.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MerkleLeafPackingWitness {
    pub n_rows: usize,
    pub log_size: u32,
    pub base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl MerkleLeafPackingWitness {
    pub(crate) fn new(
        canonical: &CanonicalVerifierWitness,
        public: &MerkleLeafPublicWitness,
        call_ids: &[SyntheticPoseidonCallIds],
    ) -> Result<Self, MerkleLeafAirError> {
        let mut rows = Vec::with_capacity(public.n_rows);
        for tree in &canonical.merkle_trees {
            for leaf in &canonical.merkle_leaves[tree.leaf_start..tree.leaf_end] {
                for (call_index, global_index) in
                    (leaf.poseidon_call_start..leaf.poseidon_call_end).enumerate()
                {
                    let schedule = public
                        .schedule
                        .get(rows.len())
                        .ok_or(MerkleLeafAirError::ScheduleMismatch)?;
                    let call = canonical
                        .poseidon_calls
                        .get(global_index)
                        .ok_or(MerkleLeafAirError::InvalidCallMapping)?;
                    let ids = call_ids
                        .get(global_index)
                        .ok_or(MerkleLeafAirError::InvalidCallMapping)?;
                    let call_count = leaf.poseidon_call_end - leaf.poseidon_call_start;
                    let expected_kind = if call_index + 1 == call_count {
                        Poseidon252CallKind::MerkleLeafFinalize
                    } else {
                        Poseidon252CallKind::MerkleLeafAbsorb
                    };
                    if schedule.source != tree.source
                        || schedule.source_index != call.source_index
                        || schedule.is_absorb
                            != (expected_kind == Poseidon252CallKind::MerkleLeafAbsorb)
                        || schedule.leaf_call_index != call_index
                        || schedule.leaf_call_count != call_count
                        || schedule.node_index != leaf.position
                        || call.source != tree.source
                        || call.call.kind != expected_kind
                    {
                        return Err(MerkleLeafAirError::ScheduleMismatch);
                    }
                    let values = leaf
                        .values
                        .get(
                            schedule.leaf_value_start
                                ..schedule.leaf_value_start + schedule.leaf_value_count,
                        )
                        .ok_or(MerkleLeafAirError::InvalidValueRange)?;
                    rows.push(leaf_row(
                        schedule,
                        values,
                        &call.call,
                        *ids,
                        call_index.checked_sub(1).and_then(|_| {
                            canonical
                                .poseidon_calls
                                .get(global_index - 1)
                                .map(|call| &call.call)
                        }),
                    )?);
                }
            }
        }
        if rows.len() != public.n_rows {
            return Err(MerkleLeafAirError::ScheduleMismatch);
        }
        let n_rows = rows.len();
        let log_size = padded_log_size(n_rows);
        rows.resize(
            1usize << log_size,
            vec![BaseField::from(0u32); MERKLE_LEAF_AIR_NUM_COLUMNS],
        );
        let domain = CanonicCoset::new(log_size).circle_domain();
        let base_trace = (0..MERKLE_LEAF_AIR_NUM_COLUMNS)
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
        public: &MerkleLeafPublicWitness,
        common_lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let n_vec_rows = 1usize << (self.log_size - LOG_N_LANES);
        let mut logup = LogupTraceGenerator::new(self.log_size);
        for pair_start in (0..N_LEAF_RELATIONS).step_by(2) {
            let mut column = logup.new_col();
            for vec_row in 0..n_vec_rows {
                let (numerator0, denominator0) = leaf_fraction(
                    &self.base_trace,
                    &public.columns,
                    pair_start,
                    vec_row,
                    common_lookup_elements,
                );
                if pair_start + 1 < N_LEAF_RELATIONS {
                    let (numerator1, denominator1) = leaf_fraction(
                        &self.base_trace,
                        &public.columns,
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
pub(crate) struct MerkleLeafPackingAir {
    log_size: u32,
    n_rows: usize,
    common_lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl MerkleLeafPackingAir {
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

#[derive(Clone)]
struct Pair<F> {
    current: F,
    next: F,
}

fn read_pair<E: EvalAtRow>(eval: &mut E) -> Pair<E::F> {
    let [current, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
    Pair { current, next }
}

struct LeafTrace<F> {
    absorb: Pair<F>,
    finalize: Pair<F>,
    block0_active: Pair<F>,
    ids: [Pair<F>; N_CALL_IDS],
    call_values: Vec<Vec<Pair<F>>>,
    values: [Pair<F>; N_VALUES_PER_CALL],
    bits: Vec<Vec<Pair<F>>>,
    inverse: [Pair<F>; N_VALUES_PER_CALL],
    blocks: Vec<Vec<Pair<F>>>,
    subtract_prime: [Pair<F>; N_BLOCKS],
    carry_pos: Vec<Vec<Pair<F>>>,
    carry_neg: Vec<Vec<Pair<F>>>,
}

fn read_trace<E: EvalAtRow>(eval: &mut E) -> LeafTrace<E::F> {
    LeafTrace {
        absorb: read_pair(eval),
        finalize: read_pair(eval),
        block0_active: read_pair(eval),
        ids: array::from_fn(|_| read_pair(eval)),
        call_values: (0..N_CALL_IDS)
            .map(|_| (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect())
            .collect(),
        values: array::from_fn(|_| read_pair(eval)),
        bits: (0..N_VALUES_PER_CALL)
            .map(|_| (0..N_BITS_PER_VALUE).map(|_| read_pair(eval)).collect())
            .collect(),
        inverse: array::from_fn(|_| read_pair(eval)),
        blocks: (0..N_BLOCKS)
            .map(|_| (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect())
            .collect(),
        subtract_prime: array::from_fn(|_| read_pair(eval)),
        carry_pos: (0..N_BLOCKS)
            .map(|_| (0..N_ADDITION_CARRIES).map(|_| read_pair(eval)).collect())
            .collect(),
        carry_neg: (0..N_BLOCKS)
            .map(|_| (0..N_ADDITION_CARRIES).map(|_| read_pair(eval)).collect())
            .collect(),
    }
}

impl FrameworkEval for MerkleLeafPackingAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace = read_trace(&mut eval);
        let fixed = (0..MERKLE_LEAF_PREPROCESSED_COLUMNS)
            .map(|column| {
                eval.get_preprocessed_column(leaf_preprocessed_id(
                    column,
                    self.log_size,
                    self.n_rows,
                ))
            })
            .collect::<Vec<_>>();
        let zero = E::F::from(M31::from(0));
        let one = E::F::from(M31::from(1));
        let active = fixed[PRE_ACTIVE].clone();
        let first = fixed[PRE_FIRST_IN_LEAF].clone();
        let absorb = trace.absorb.current.clone();
        let finalize = trace.finalize.current.clone();
        eval.add_constraint(absorb.clone() - fixed[PRE_ABSORB].clone());
        eval.add_constraint(finalize.clone() - fixed[PRE_FINALIZE].clone());
        eval.add_constraint(absorb.clone() + finalize.clone() - active.clone());
        eval.add_constraint(
            trace.block0_active.current.clone() - fixed[PRE_VALUE_ACTIVE_START].clone(),
        );
        for flag in [&trace.absorb, &trace.finalize, &trace.block0_active] {
            eval.add_constraint(flag.current.clone() * (flag.current.clone() - one.clone()));
        }

        for value_index in 0..N_VALUES_PER_CALL {
            let value_active = fixed[PRE_VALUE_ACTIVE_START + value_index].clone();
            eval.add_constraint(
                (one.clone() - value_active.clone()) * trace.values[value_index].current.clone(),
            );
            let mut reconstructed = zero.clone();
            let mut low_missing = zero.clone();
            for bit_index in 0..N_BITS_PER_VALUE {
                let bit = trace.bits[value_index][bit_index].current.clone();
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                eval.add_constraint((one.clone() - value_active.clone()) * bit.clone());
                reconstructed = reconstructed
                    + E::F::from(M31::from_u32_unchecked(1u32 << bit_index)) * bit.clone();
                if bit_index < N_BITS_PER_VALUE - 1 {
                    low_missing = low_missing
                        + E::F::from(M31::from_u32_unchecked(1u32 << bit_index))
                            * (one.clone() - bit);
                }
            }
            eval.add_constraint(trace.values[value_index].current.clone() - reconstructed);
            let top_bit = trace.bits[value_index][N_BITS_PER_VALUE - 1]
                .current
                .clone();
            let inverse = trace.inverse[value_index].current.clone();
            eval.add_constraint(top_bit.clone() * (low_missing * inverse.clone() - one.clone()));
            eval.add_constraint((one.clone() - top_bit) * inverse);
        }

        for block in 0..N_BLOCKS {
            for limb in 0..FELT252_N_WORDS {
                let expected = expected_block_limb::<E>(&trace, &fixed, block, limb, zero.clone());
                eval.add_constraint(trace.blocks[block][limb].current.clone() - expected);
            }
            let subtract = trace.subtract_prime[block].current.clone();
            eval.add_constraint(subtract.clone() * (subtract - one.clone()));
            for carry in 0..N_ADDITION_CARRIES {
                let positive = trace.carry_pos[block][carry].current.clone();
                let negative = trace.carry_neg[block][carry].current.clone();
                eval.add_constraint(positive.clone() * (positive.clone() - one.clone()));
                eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
                eval.add_constraint(positive * negative);
            }
        }

        for limb in 0..FELT252_N_WORDS {
            for block in 0..N_BLOCKS {
                let current_carry_in = if limb == 0 {
                    zero.clone()
                } else {
                    trace.carry_pos[block][limb - 1].current.clone()
                        - trace.carry_neg[block][limb - 1].current.clone()
                };
                let current_carry_out = if limb == N_ADDITION_CARRIES {
                    zero.clone()
                } else {
                    trace.carry_pos[block][limb].current.clone()
                        - trace.carry_neg[block][limb].current.clone()
                };
                let current_padding = if limb == 0 {
                    if block == 0 {
                        finalize.clone() * (one.clone() - trace.block0_active.current.clone())
                    } else {
                        finalize.clone() * trace.block0_active.current.clone()
                    }
                } else {
                    zero.clone()
                };
                let prime_limb = E::F::from(M31::from(P_FELTS[limb]));
                let first_addition =
                    trace.blocks[block][limb].current.clone() + current_padding + current_carry_in
                        - trace.call_values[block][limb].current.clone()
                        - trace.subtract_prime[block].current.clone() * prime_limb.clone()
                        - E::F::from(M31::from(512)) * current_carry_out;
                eval.add_constraint(first.clone() * first_addition);

                let next_carry_in = if limb == 0 {
                    zero.clone()
                } else {
                    trace.carry_pos[block][limb - 1].next.clone()
                        - trace.carry_neg[block][limb - 1].next.clone()
                };
                let next_carry_out = if limb == N_ADDITION_CARRIES {
                    zero.clone()
                } else {
                    trace.carry_pos[block][limb].next.clone()
                        - trace.carry_neg[block][limb].next.clone()
                };
                let next_padding = if limb == 0 {
                    if block == 0 {
                        trace.finalize.next.clone()
                            * (one.clone() - trace.block0_active.next.clone())
                    } else {
                        trace.finalize.next.clone() * trace.block0_active.next.clone()
                    }
                } else {
                    zero.clone()
                };
                let continued_addition = trace.call_values[3 + block][limb].current.clone()
                    + trace.blocks[block][limb].next.clone()
                    + next_padding
                    + next_carry_in
                    - trace.call_values[block][limb].next.clone()
                    - trace.subtract_prime[block].next.clone() * prime_limb
                    - E::F::from(M31::from(512)) * next_carry_out;
                eval.add_constraint(absorb.clone() * continued_addition);
            }
            eval.add_constraint(first.clone() * trace.call_values[2][limb].current.clone());
            eval.add_constraint(
                absorb.clone()
                    * (trace.call_values[2][limb].next.clone()
                        - trace.call_values[5][limb].current.clone()),
            );
        }

        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(active.clone()),
            &leaf_call_relation_values(&fixed, &trace),
        ));
        for slot in 0..N_CALL_IDS {
            let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
            values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
            values.push(trace.ids[slot].current.clone());
            values.extend(
                trace.call_values[slot]
                    .iter()
                    .map(|limb| limb.current.clone()),
            );
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(active.clone()),
                &values,
            ));
        }
        for value_index in 0..N_VALUES_PER_CALL {
            let value_active = fixed[PRE_VALUE_ACTIVE_START + value_index].clone();
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(value_active),
                &queried_value_relation_values(
                    &fixed,
                    fixed[PRE_VALUE_START].clone() + E::F::from(M31::from(value_index as u32)),
                    trace.values[value_index].current.clone(),
                ),
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

fn expected_block_limb<E: EvalAtRow>(
    trace: &LeafTrace<E::F>,
    fixed: &[E::F],
    block: usize,
    limb: usize,
    zero: E::F,
) -> E::F {
    let mut expected = zero;
    let value_base = block * 8;
    for length in 1..=8 {
        let selector = fixed[PRE_BLOCK_LENGTH_START + block * N_BLOCK_LENGTHS + length].clone();
        let mut selected = E::F::from(M31::from(0));
        for local_value in 0..length {
            for bit in 0..N_BITS_PER_VALUE {
                let bit_position = 31 * (length - 1 - local_value) + bit;
                if bit_position / 9 == limb {
                    selected = selected
                        + E::F::from(M31::from_u32_unchecked(1u32 << (bit_position % 9)))
                            * trace.bits[value_base + local_value][bit].current.clone();
                }
            }
        }
        if length < 8 && limb == FELT252_N_WORDS - 1 {
            selected = selected + E::F::from(M31::from_u32_unchecked((length as u32) << 5));
        }
        expected = expected + selector * selected;
    }
    expected
}

fn public_row(
    schedule: &MerkleLeafCallSchedule,
) -> Result<[BaseField; MERKLE_LEAF_PREPROCESSED_COLUMNS], MerkleLeafAirError> {
    if schedule.leaf_value_count > N_VALUES_PER_CALL {
        return Err(MerkleLeafAirError::InvalidValueRange);
    }
    let mut row = [BaseField::from(0u32); MERKLE_LEAF_PREPROCESSED_COLUMNS];
    row[PRE_ACTIVE] = BaseField::from(1u32);
    let (pcs_source, fri_source, source_arg) = source_fields(schedule.source)?;
    row[PRE_PCS_SOURCE] = pcs_source;
    row[PRE_FRI_SOURCE] = fri_source;
    row[PRE_SOURCE_ARG] = source_arg;
    row[PRE_SOURCE_INDEX] = to_field(schedule.source_index)?;
    row[PRE_ABSORB] = BaseField::from(schedule.is_absorb as u32);
    row[PRE_FINALIZE] = BaseField::from((!schedule.is_absorb) as u32);
    row[PRE_FIRST_IN_LEAF] = BaseField::from((schedule.leaf_call_index == 0) as u32);
    row[PRE_CALL_INDEX] = to_field(schedule.leaf_call_index)?;
    row[PRE_CALL_COUNT] = to_field(schedule.leaf_call_count)?;
    row[PRE_NODE_INDEX] = to_field(schedule.node_index)?;
    row[PRE_VALUE_START] = to_field(schedule.leaf_value_start)?;
    row[PRE_VALUE_COUNT] = to_field(schedule.leaf_value_count)?;
    for value in 0..schedule.leaf_value_count {
        row[PRE_VALUE_ACTIVE_START + value] = BaseField::from(1u32);
    }
    let block_lengths = [
        schedule.leaf_value_count.min(8),
        schedule.leaf_value_count.saturating_sub(8),
    ];
    for (block, length) in block_lengths.into_iter().enumerate() {
        row[PRE_BLOCK_LENGTH_START + block * N_BLOCK_LENGTHS + length] = BaseField::from(1u32);
    }
    Ok(row)
}

fn leaf_row(
    schedule: &MerkleLeafCallSchedule,
    values: &[BaseField],
    call: &super::poseidon252_replay::Poseidon252PermutationCall,
    ids: SyntheticPoseidonCallIds,
    previous_call: Option<&super::poseidon252_replay::Poseidon252PermutationCall>,
) -> Result<Vec<BaseField>, MerkleLeafAirError> {
    if values.len() != schedule.leaf_value_count || values.len() > N_VALUES_PER_CALL {
        return Err(MerkleLeafAirError::InvalidValueRange);
    }
    let mut row = vec![BaseField::from(0u32); MERKLE_LEAF_AIR_NUM_COLUMNS];
    row[ABSORB_COLUMN] = BaseField::from(schedule.is_absorb as u32);
    row[FINALIZE_COLUMN] = BaseField::from((!schedule.is_absorb) as u32);
    row[BLOCK0_ACTIVE_COLUMN] = BaseField::from((!values.is_empty()) as u32);
    row[ID_COLUMNS_START..CALL_VALUE_COLUMNS_START].copy_from_slice(&ids.flat());
    let call_values = call
        .input
        .iter()
        .chain(&call.output)
        .flat_map(|value| field_element_to_9_bit_limbs(*value))
        .collect::<Vec<_>>();
    row[CALL_VALUE_COLUMNS_START..VALUE_COLUMNS_START].copy_from_slice(&call_values);
    for (value_index, value) in values.iter().copied().enumerate() {
        row[VALUE_COLUMNS_START + value_index] = value;
        for bit in 0..N_BITS_PER_VALUE {
            row[BIT_COLUMNS_START + value_index * N_BITS_PER_VALUE + bit] =
                BaseField::from((value.0 >> bit) & 1);
        }
        if value.0 >> 30 == 1 {
            let low_missing = (0..30).fold(0u32, |sum, bit| {
                sum + (((value.0 >> bit) & 1 == 0) as u32) * (1u32 << bit)
            });
            if low_missing == 0 {
                return Err(MerkleLeafAirError::InvalidValueRange);
            }
            row[INVERSE_COLUMNS_START + value_index] =
                BaseField::from_u32_unchecked(low_missing).inverse();
        }
    }
    let blocks = [
        (!values.is_empty()).then(|| construct_felt252_from_m31s(&values[..values.len().min(8)])),
        (values.len() > 8).then(|| construct_felt252_from_m31s(&values[8..])),
    ];
    for (block, value) in blocks.into_iter().enumerate() {
        if let Some(value) = value {
            row[BLOCK_COLUMNS_START + block * FELT252_N_WORDS
                ..BLOCK_COLUMNS_START + (block + 1) * FELT252_N_WORDS]
                .copy_from_slice(&field_element_to_9_bit_limbs(value));
        }
    }
    let previous_state = previous_call.map_or([FieldElement252::ZERO; 3], |call| call.output);
    if previous_call.is_some_and(|call| call.kind == Poseidon252CallKind::MerkleLeafFinalize) {
        return Err(MerkleLeafAirError::InvalidCallMapping);
    }
    let padding = [
        !schedule.is_absorb && values.is_empty(),
        !schedule.is_absorb && !values.is_empty(),
    ];
    for block in 0..N_BLOCKS {
        let payload = blocks[block].unwrap_or(FieldElement252::ZERO);
        let (subtract, carry_pos, carry_neg) = modular_add_witness(
            previous_state[block],
            payload,
            padding[block],
            call.input[block],
        )
        .ok_or(MerkleLeafAirError::InvalidAddition)?;
        row[SUBTRACT_PRIME_COLUMNS_START + block] = subtract;
        row[CARRY_POS_COLUMNS_START + block * N_ADDITION_CARRIES
            ..CARRY_POS_COLUMNS_START + (block + 1) * N_ADDITION_CARRIES]
            .copy_from_slice(&carry_pos);
        row[CARRY_NEG_COLUMNS_START + block * N_ADDITION_CARRIES
            ..CARRY_NEG_COLUMNS_START + (block + 1) * N_ADDITION_CARRIES]
            .copy_from_slice(&carry_neg);
    }
    if call.input[2] != previous_state[2] {
        return Err(MerkleLeafAirError::InvalidAddition);
    }
    Ok(row)
}

fn leaf_call_relation_values<F: Clone + From<BaseField>>(
    fixed: &[F],
    trace: &LeafTrace<F>,
) -> Vec<F> {
    let mut values = Vec::with_capacity(1 + 11 + N_CALL_IDS);
    values.push(F::from(BaseField::from_u32_unchecked(
        MERKLE_LEAF_CALL_RELATION_ID,
    )));
    values.push(fixed[PRE_PCS_SOURCE].clone());
    values.push(fixed[PRE_FRI_SOURCE].clone());
    values.push(fixed[PRE_SOURCE_ARG].clone());
    values.push(fixed[PRE_SOURCE_INDEX].clone());
    values.push(trace.absorb.current.clone());
    values.push(trace.finalize.current.clone());
    values.push(fixed[PRE_CALL_INDEX].clone());
    values.push(fixed[PRE_CALL_COUNT].clone());
    values.push(fixed[PRE_NODE_INDEX].clone());
    values.push(fixed[PRE_VALUE_START].clone());
    values.push(fixed[PRE_VALUE_COUNT].clone());
    values.extend(trace.ids.iter().map(|id| id.current.clone()));
    values
}

fn queried_value_relation_values<F: Clone + From<BaseField>>(
    fixed: &[F],
    value_index: F,
    value: F,
) -> Vec<F> {
    vec![
        F::from(BaseField::from_u32_unchecked(
            MERKLE_QUERIED_VALUE_RELATION_ID,
        )),
        fixed[PRE_PCS_SOURCE].clone(),
        fixed[PRE_FRI_SOURCE].clone(),
        fixed[PRE_SOURCE_ARG].clone(),
        fixed[PRE_NODE_INDEX].clone(),
        value_index,
        value,
    ]
}

fn leaf_fraction(
    columns: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    fixed: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    relation_index: usize,
    vec_row: usize,
    lookup_elements: &cairo_air::relations::CommonLookupElements,
) -> (PackedSecureField, PackedSecureField) {
    let value = |column: usize| columns[column].values.data[vec_row];
    let fixed_value = |column: usize| fixed[column].values.data[vec_row];
    let active = PackedSecureField::from(fixed_value(PRE_ACTIVE));
    if relation_index == 0 {
        let mut values = Vec::with_capacity(1 + 11 + N_CALL_IDS);
        values.push(PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            MERKLE_LEAF_CALL_RELATION_ID,
        )));
        values.push(fixed_value(PRE_PCS_SOURCE));
        values.push(fixed_value(PRE_FRI_SOURCE));
        values.push(fixed_value(PRE_SOURCE_ARG));
        values.push(fixed_value(PRE_SOURCE_INDEX));
        values.push(value(ABSORB_COLUMN));
        values.push(value(FINALIZE_COLUMN));
        values.push(fixed_value(PRE_CALL_INDEX));
        values.push(fixed_value(PRE_CALL_COUNT));
        values.push(fixed_value(PRE_NODE_INDEX));
        values.push(fixed_value(PRE_VALUE_START));
        values.push(fixed_value(PRE_VALUE_COUNT));
        values.extend((0..N_CALL_IDS).map(|offset| value(ID_COLUMNS_START + offset)));
        return (active, lookup_elements.combine(&values));
    }
    if relation_index <= N_CALL_IDS {
        let slot = relation_index - 1;
        let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
        values.push(PackedBaseField::broadcast(BaseField::from(
            MEMORY_ID_TO_BIG_RELATION_ID,
        )));
        values.push(value(ID_COLUMNS_START + slot));
        values.extend(
            (0..FELT252_N_WORDS)
                .map(|limb| value(CALL_VALUE_COLUMNS_START + slot * FELT252_N_WORDS + limb)),
        );
        return (active, lookup_elements.combine(&values));
    }
    let value_index = relation_index - 1 - N_CALL_IDS;
    let value_active = PackedSecureField::from(fixed_value(PRE_VALUE_ACTIVE_START + value_index));
    let values = vec![
        PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            MERKLE_QUERIED_VALUE_RELATION_ID,
        )),
        fixed_value(PRE_PCS_SOURCE),
        fixed_value(PRE_FRI_SOURCE),
        fixed_value(PRE_SOURCE_ARG),
        fixed_value(PRE_NODE_INDEX),
        fixed_value(PRE_VALUE_START)
            + PackedBaseField::broadcast(BaseField::from(value_index as u32)),
        value(VALUE_COLUMNS_START + value_index),
    ];
    (value_active, lookup_elements.combine(&values))
}

fn source_fields(
    source: PoseidonCallSource,
) -> Result<(BaseField, BaseField, BaseField), MerkleLeafAirError> {
    match source {
        PoseidonCallSource::Transcript => Err(MerkleLeafAirError::ScheduleMismatch),
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

fn to_field(value: usize) -> Result<BaseField, MerkleLeafAirError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value < 0x7fff_ffff)
        .map(BaseField::from_u32_unchecked)
        .ok_or(MerkleLeafAirError::MetadataOverflow)
}

fn padded_log_size(n_rows: usize) -> u32 {
    n_rows.next_power_of_two().max(N_LANES).ilog2()
}

fn leaf_preprocessed_id(column: usize, log_size: u32, n_rows: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_merkle_leaf_{column}_{log_size}_{n_rows}"),
    }
}

fn rows_to_preprocessed_columns(
    rows: &[[BaseField; MERKLE_LEAF_PREPROCESSED_COLUMNS]],
    log_size: u32,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let domain = CanonicCoset::new(log_size).circle_domain();
    (0..MERKLE_LEAF_PREPROCESSED_COLUMNS)
        .map(|column| {
            let values = rows.iter().map(|row| row[column]).collect::<Vec<_>>();
            let values = into_bit_reversed_circle_order(&values, log_size);
            (
                leaf_preprocessed_id(column, log_size, rows.len()),
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
    use crate::stwo_backend::recursive::merkle_semantic_air::MerklePublicBindingWitness;
    use crate::stwo_backend::recursive::poseidon252_air::Poseidon252ClosureWitness;
    use crate::stwo_backend::recursive::transcript_air::transcript_payload_values;
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
    fn leaf_packing_constraints_bind_values_and_state_transitions() {
        crate::stwo_backend::recursive::run_large_stack_test(
            "merkle-leaf-packing-air",
            256 * 1024 * 1024,
            || {
                let mut builder = TraceBuilder::new(10);
                builder.fill_padding_to_full();
                let proof = prove_cpu_trace(&builder.finalize()).expect("L1 proof should succeed");
                let public_inputs = build_cpu_recursive_public_inputs(&proof, 10).unwrap();
                let replay = replay_cpu_verifier(&proof, &public_inputs).unwrap();
                let canonical = CanonicalVerifierWitness::from_cpu_replay(&replay);
                let payloads = transcript_payload_values(&canonical.transcript_events);
                let poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
                    &canonical.poseidon_calls,
                    &payloads,
                )
                .unwrap();
                let binding = MerklePublicBindingWitness::new(&public_inputs).unwrap();
                let public = MerkleLeafPublicWitness::new(&binding).unwrap();
                let leaf = MerkleLeafPackingWitness::new(
                    &canonical,
                    &public,
                    &poseidon.synthetic_memory.call_ids,
                )
                .unwrap();
                let lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
                let (ids, preprocessed) = public.preprocessed_columns();
                let (interaction, claimed_sum) =
                    leaf.write_interaction_trace(&public, &lookup_elements);
                assert_eq!(interaction.len(), MERKLE_LEAF_INTERACTION_COLUMNS);
                let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
                let component = FrameworkComponent::new(
                    &mut allocator,
                    MerkleLeafPackingAir::new(leaf.log_size, leaf.n_rows, lookup_elements),
                    claimed_sum,
                );
                let mut trace = TreeVec::new(vec![
                    preprocessed
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    leaf.base_trace
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                    interaction
                        .into_iter()
                        .map(|evaluation| evaluation.values.to_cpu())
                        .collect(),
                ]);
                {
                    let trace_ref = trace.as_cols_ref();
                    assert_component(&component, &trace_ref);
                }

                let original = component
                    .trace_locations()
                    .iter()
                    .find(|span| span.tree_index == 1)
                    .unwrap();
                let first_row = bit_reverse_index(
                    coset_index_to_circle_domain_index(0, leaf.log_size),
                    leaf.log_size,
                );
                let value_column = original.col_start + VALUE_COLUMNS_START;
                trace[1][value_column][first_row] += BaseField::from(1u32);
                let trace_ref = trace.as_cols_ref();
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        assert_component(&component, &trace_ref);
                    }))
                    .is_err()
                );
            },
        );
    }
}
