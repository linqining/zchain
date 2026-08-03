//! Semantic AIR for the canonical Poseidon252 transcript replay.
//!
//! The generic Poseidon semantic table exports every transcript permutation through a LogUp
//! relation. This component consumes that relation in canonical call order and constrains event
//! grouping, digest/counter transitions, draw counters, absorbed payloads and every felt252
//! addition used by `hash_many`. The modular additions use 28×9-bit limbs, an explicit
//! subtract-prime bit and signed carries encoded by disjoint positive/negative bits, keeping the
//! AIR degree at two.

use core::array;

use cairo_air::relations::MEMORY_ID_TO_BIG_RELATION_ID;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
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

use super::poseidon252_air::{
    N_CALL_IDS, N_KIND_SELECTORS, SyntheticPoseidonCallIds, TRANSCRIPT_POSEIDON_CALL_RELATION_ID,
    field_element_to_9_bit_limbs, kind_index,
};
use super::poseidon252_replay::{
    Poseidon252CallKind, Poseidon252PermutationCall, TranscriptPoseidonEvent,
};
use super::replay_witness::{CanonicalPoseidonCall, CanonicalTranscriptCall, PoseidonCallSource};

const N_PAYLOAD_SLOTS: usize = 2;
pub(crate) const N_ADDITION_CARRIES: usize = FELT252_N_WORDS - 1;
const N_EVENT_COLUMNS: usize = 21;
const PAYLOAD_ACTIVE_COLUMNS_START: usize = 17;
const N_CALL_VALUE_COLUMNS: usize = N_CALL_IDS * FELT252_N_WORDS;
const N_PAYLOAD_VALUE_COLUMNS: usize = N_PAYLOAD_SLOTS * FELT252_N_WORDS;
const N_CARRY_COLUMNS: usize = N_PAYLOAD_SLOTS * N_ADDITION_CARRIES;
const KIND_COLUMNS_START: usize = N_EVENT_COLUMNS;
const ID_COLUMNS_START: usize = KIND_COLUMNS_START + N_KIND_SELECTORS;
const CALL_VALUE_COLUMNS_START: usize = ID_COLUMNS_START + N_CALL_IDS;
const PAYLOAD_ID_COLUMNS_START: usize = CALL_VALUE_COLUMNS_START + N_CALL_VALUE_COLUMNS;
const PAYLOAD_VALUE_COLUMNS_START: usize = PAYLOAD_ID_COLUMNS_START + N_PAYLOAD_SLOTS;
const SUBTRACT_PRIME_COLUMNS_START: usize = PAYLOAD_VALUE_COLUMNS_START + N_PAYLOAD_VALUE_COLUMNS;
const CARRY_POS_COLUMNS_START: usize = SUBTRACT_PRIME_COLUMNS_START + N_PAYLOAD_SLOTS;
const CARRY_NEG_COLUMNS_START: usize = CARRY_POS_COLUMNS_START + N_CARRY_COLUMNS;
const DIGEST_BEFORE_COLUMNS_START: usize = CARRY_NEG_COLUMNS_START + N_CARRY_COLUMNS;
const DIGEST_AFTER_COLUMNS_START: usize = DIGEST_BEFORE_COLUMNS_START + FELT252_N_WORDS;
const RESULT_COLUMNS_START: usize = DIGEST_AFTER_COLUMNS_START + FELT252_N_WORDS;

pub(crate) const TRANSCRIPT_AIR_NUM_COLUMNS: usize = RESULT_COLUMNS_START + FELT252_N_WORDS;
pub(crate) const TRANSCRIPT_INTERACTION_COLUMNS: usize = 48;
pub(crate) const TRANSCRIPT_PAYLOAD_RELATION_ID: u32 = 1_972_100_151;
pub(crate) const TRANSCRIPT_DRAW_RESULT_RELATION_ID: u32 = 1_972_100_153;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TranscriptAirError {
    #[error("transcript AIR requires at least one permutation call")]
    EmptyCalls,
    #[error("transcript call metadata does not fit M31")]
    MetadataOverflow,
    #[error("canonical transcript call mapping is inconsistent at row {row}")]
    InvalidMapping { row: usize },
    #[error("canonical transcript event {event} is inconsistent")]
    InvalidEvent { event: usize },
    #[error("canonical transcript payload IDs are inconsistent")]
    InvalidPayloadIds,
    #[error("canonical transcript modular addition is inconsistent at row {row}")]
    InvalidAddition { row: usize },
    #[error("empty hash-many transcript payload is not supported yet")]
    EmptyHashManyPayload,
    #[error("transcript trace is too large for the exact three-limb draw counter encoding")]
    TraceTooLarge,
    #[error("transcript lookup closure is unbalanced: {0:?}")]
    UnbalancedLookup(SecureField),
}

fn event_uses_payload_values(kind: Poseidon252CallKind) -> bool {
    !matches!(kind, Poseidon252CallKind::TranscriptDraw)
}

pub(crate) fn transcript_payload_values(
    events: &[TranscriptPoseidonEvent],
) -> Vec<FieldElement252> {
    events
        .iter()
        .filter(|event| event_uses_payload_values(event.kind))
        .flat_map(|event| event.absorbed_values.iter().copied())
        .collect()
}

fn to_field(value: usize) -> Result<BaseField, TranscriptAirError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value < 0x7fff_ffff)
        .map(BaseField::from_u32_unchecked)
        .ok_or(TranscriptAirError::MetadataOverflow)
}

fn transcript_preprocessed_id(name: &str, log_size: u32, n_calls: usize) -> PreProcessedColumnId {
    PreProcessedColumnId {
        id: format!("recursive_transcript_{name}_{log_size}_{n_calls}"),
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

pub(crate) fn transcript_preprocessed_columns(
    log_size: u32,
    n_calls: usize,
) -> (
    Vec<PreProcessedColumnId>,
    Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
) {
    let size = 1usize << log_size;
    assert!(n_calls > 0 && n_calls <= size);
    let domain = CanonicCoset::new(log_size).circle_domain();
    let active = (0..size)
        .map(|row| BaseField::from((row < n_calls) as u32))
        .collect::<Vec<_>>();
    let first = (0..size)
        .map(|row| BaseField::from((row == 0) as u32))
        .collect::<Vec<_>>();
    let last = (0..size)
        .map(|row| BaseField::from((row + 1 == n_calls) as u32))
        .collect::<Vec<_>>();
    let active = into_bit_reversed_circle_order(&active, log_size);
    let first = into_bit_reversed_circle_order(&first, log_size);
    let last = into_bit_reversed_circle_order(&last, log_size);
    let definitions = [
        (
            transcript_preprocessed_id("active", log_size, n_calls),
            BaseColumn::from_cpu(&active),
        ),
        (
            transcript_preprocessed_id("first", log_size, n_calls),
            BaseColumn::from_cpu(&first),
        ),
        (
            transcript_preprocessed_id("last", log_size, n_calls),
            BaseColumn::from_cpu(&last),
        ),
    ];
    definitions
        .into_iter()
        .map(|(id, column)| (id, CircleEvaluation::new(domain, column)))
        .unzip()
}

#[derive(Debug, Clone)]
struct TranscriptRow {
    active: BaseField,
    global_index: BaseField,
    source_index: BaseField,
    event_index: BaseField,
    call_index: BaseField,
    call_count: BaseField,
    first_in_event: BaseField,
    last_in_event: BaseField,
    has_next_event: BaseField,
    first_input0: BaseField,
    first_input1: BaseField,
    updates_digest: BaseField,
    keeps_digest: BaseField,
    n_draws_before: BaseField,
    n_draws_after: BaseField,
    hash_first: BaseField,
    hash_final: BaseField,
    payload_active: [BaseField; N_PAYLOAD_SLOTS],
    padding: [BaseField; N_PAYLOAD_SLOTS],
    kind_selectors: [BaseField; N_KIND_SELECTORS],
    ids: [BaseField; N_CALL_IDS],
    call_values: [[BaseField; FELT252_N_WORDS]; N_CALL_IDS],
    payload_ids: [BaseField; N_PAYLOAD_SLOTS],
    payload_values: [[BaseField; FELT252_N_WORDS]; N_PAYLOAD_SLOTS],
    subtract_prime: [BaseField; N_PAYLOAD_SLOTS],
    carry_pos: [[BaseField; N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS],
    carry_neg: [[BaseField; N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS],
    digest_before: [BaseField; FELT252_N_WORDS],
    digest_after: [BaseField; FELT252_N_WORDS],
    result: [BaseField; FELT252_N_WORDS],
}

fn row_payload(
    event: &TranscriptPoseidonEvent,
    call_index: usize,
    payload_ids: &[BaseField],
) -> Result<
    (
        [Option<(FieldElement252, BaseField)>; N_PAYLOAD_SLOTS],
        [bool; 2],
    ),
    TranscriptAirError,
> {
    let no_payload = [None, None];
    let no_padding = [false, false];
    if !event_uses_payload_values(event.kind) {
        return if payload_ids.is_empty() {
            Ok((no_payload, no_padding))
        } else {
            Err(TranscriptAirError::InvalidPayloadIds)
        };
    }
    if payload_ids.len() != event.absorbed_values.len() {
        return Err(TranscriptAirError::InvalidPayloadIds);
    }
    let payload = |index: usize| Some((event.absorbed_values[index], payload_ids[index]));
    match event.kind {
        Poseidon252CallKind::TranscriptMixRoot
        | Poseidon252CallKind::TranscriptMixU64
        | Poseidon252CallKind::TranscriptPowNonce => {
            if call_index == 0 && event.absorbed_values.len() == 2 {
                Ok(([payload(0), payload(1)], no_padding))
            } else {
                Err(TranscriptAirError::InvalidPayloadIds)
            }
        }
        Poseidon252CallKind::TranscriptMixFelts
        | Poseidon252CallKind::TranscriptMixU32s
        | Poseidon252CallKind::TranscriptPowPrefix => {
            let full_pairs = event.absorbed_values.len() / 2;
            if call_index < full_pairs {
                Ok((
                    [payload(2 * call_index), payload(2 * call_index + 1)],
                    no_padding,
                ))
            } else if call_index == full_pairs {
                if event.absorbed_values.len().is_multiple_of(2) {
                    Ok((no_payload, [true, false]))
                } else {
                    Ok(([payload(2 * call_index), None], [false, true]))
                }
            } else {
                Err(TranscriptAirError::InvalidPayloadIds)
            }
        }
        Poseidon252CallKind::TranscriptDraw
        | Poseidon252CallKind::MerkleLeafAbsorb
        | Poseidon252CallKind::MerkleLeafFinalize
        | Poseidon252CallKind::MerkleParent => Err(TranscriptAirError::InvalidPayloadIds),
    }
}

pub(crate) fn modular_add_witness(
    state: FieldElement252,
    payload: FieldElement252,
    padding: bool,
    result: FieldElement252,
) -> Option<(
    BaseField,
    [BaseField; N_ADDITION_CARRIES],
    [BaseField; N_ADDITION_CARRIES],
)> {
    let state_limbs = field_element_to_9_bit_limbs(state);
    let payload_limbs = field_element_to_9_bit_limbs(payload);
    let result_limbs = field_element_to_9_bit_limbs(result);
    for subtract_prime in [0i32, 1] {
        let mut carry = 0i32;
        let mut carry_pos = [BaseField::from(0u32); N_ADDITION_CARRIES];
        let mut carry_neg = [BaseField::from(0u32); N_ADDITION_CARRIES];
        let mut valid = true;
        for limb in 0..FELT252_N_WORDS {
            let value = i32::try_from(state_limbs[limb].0).unwrap()
                + i32::try_from(payload_limbs[limb].0).unwrap()
                + i32::from(padding && limb == 0)
                + carry
                - i32::try_from(result_limbs[limb].0).unwrap()
                - subtract_prime * i32::try_from(P_FELTS[limb]).unwrap();
            if value % 512 != 0 {
                valid = false;
                break;
            }
            carry = value / 512;
            if !(-1..=1).contains(&carry) {
                valid = false;
                break;
            }
            if limb < N_ADDITION_CARRIES {
                carry_pos[limb] = BaseField::from((carry == 1) as u32);
                carry_neg[limb] = BaseField::from((carry == -1) as u32);
            }
        }
        if valid && carry == 0 {
            return Some((BaseField::from(subtract_prime as u32), carry_pos, carry_neg));
        }
    }
    None
}

impl TranscriptRow {
    fn new(
        row: usize,
        mapping: &CanonicalTranscriptCall,
        event: &TranscriptPoseidonEvent,
        call: &CanonicalPoseidonCall,
        previous_call: Option<&CanonicalPoseidonCall>,
        ids: SyntheticPoseidonCallIds,
        event_payload_ids: &[BaseField],
        n_rows: usize,
    ) -> Result<Self, TranscriptAirError> {
        let call_count = event.call_end - event.call_start;
        let first_in_event = mapping.call_index_in_event == 0;
        let last_in_event = mapping.call_index_in_event + 1 == call_count;
        let kind = call.call.kind;
        let mut kind_selectors = [BaseField::from(0u32); N_KIND_SELECTORS];
        kind_selectors[kind_index(kind)] = BaseField::from(1u32);
        let first_input0 = first_in_event
            && matches!(
                kind,
                Poseidon252CallKind::TranscriptMixRoot
                    | Poseidon252CallKind::TranscriptMixFelts
                    | Poseidon252CallKind::TranscriptMixU32s
                    | Poseidon252CallKind::TranscriptMixU64
                    | Poseidon252CallKind::TranscriptDraw
            );
        let first_input1 = first_in_event && kind == Poseidon252CallKind::TranscriptPowPrefix;
        let updates_digest = last_in_event
            && matches!(
                kind,
                Poseidon252CallKind::TranscriptMixRoot
                    | Poseidon252CallKind::TranscriptMixFelts
                    | Poseidon252CallKind::TranscriptMixU32s
                    | Poseidon252CallKind::TranscriptMixU64
            );
        let keeps_digest = last_in_event
            && matches!(
                kind,
                Poseidon252CallKind::TranscriptDraw
                    | Poseidon252CallKind::TranscriptPowPrefix
                    | Poseidon252CallKind::TranscriptPowNonce
            );
        let hash_many = matches!(
            kind,
            Poseidon252CallKind::TranscriptMixFelts
                | Poseidon252CallKind::TranscriptMixU32s
                | Poseidon252CallKind::TranscriptPowPrefix
        );
        let (payload, padding) =
            row_payload(event, mapping.call_index_in_event, event_payload_ids)?;
        let payload_active = payload.map(|value| BaseField::from(value.is_some() as u32));
        let payload_ids = payload.map(|value| value.map_or(BaseField::from(0u32), |value| value.1));
        let payload_felts =
            payload.map(|value| value.map_or(FieldElement252::ZERO, |value| value.0));
        let payload_values = payload_felts.map(field_element_to_9_bit_limbs);
        let mut subtract_prime = [BaseField::from(0u32); N_PAYLOAD_SLOTS];
        let mut carry_pos = [[BaseField::from(0u32); N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS];
        let mut carry_neg = [[BaseField::from(0u32); N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS];
        if hash_many {
            let state = if first_in_event {
                [FieldElement252::ZERO; N_PAYLOAD_SLOTS]
            } else {
                let previous_call =
                    previous_call.ok_or(TranscriptAirError::InvalidAddition { row })?;
                [previous_call.call.output[0], previous_call.call.output[1]]
            };
            for slot in 0..N_PAYLOAD_SLOTS {
                let Some((subtract, positive, negative)) = modular_add_witness(
                    state[slot],
                    payload_felts[slot],
                    padding[slot],
                    call.call.input[slot],
                ) else {
                    return Err(TranscriptAirError::InvalidAddition { row });
                };
                subtract_prime[slot] = subtract;
                carry_pos[slot] = positive;
                carry_neg[slot] = negative;
            }
        }
        let values = call_values(&call.call);
        Ok(Self {
            active: BaseField::from(1u32),
            global_index: to_field(call.global_index)?,
            source_index: to_field(call.source_index)?,
            event_index: to_field(mapping.event_index)?,
            call_index: to_field(mapping.call_index_in_event)?,
            call_count: to_field(call_count)?,
            first_in_event: BaseField::from(first_in_event as u32),
            last_in_event: BaseField::from(last_in_event as u32),
            has_next_event: BaseField::from((last_in_event && row + 1 < n_rows) as u32),
            first_input0: BaseField::from(first_input0 as u32),
            first_input1: BaseField::from(first_input1 as u32),
            updates_digest: BaseField::from(updates_digest as u32),
            keeps_digest: BaseField::from(keeps_digest as u32),
            n_draws_before: BaseField::from(event.n_draws_before),
            n_draws_after: BaseField::from(event.n_draws_after),
            hash_first: BaseField::from((hash_many && first_in_event) as u32),
            hash_final: BaseField::from((hash_many && last_in_event) as u32),
            payload_active,
            padding: padding.map(|value| BaseField::from(value as u32)),
            kind_selectors,
            ids: ids.flat(),
            call_values: values,
            payload_ids,
            payload_values,
            subtract_prime,
            carry_pos,
            carry_neg,
            digest_before: field_element_to_9_bit_limbs(event.digest_before),
            digest_after: field_element_to_9_bit_limbs(event.digest_after),
            result: field_element_to_9_bit_limbs(event.result),
        })
    }

    fn padding() -> Self {
        Self {
            active: BaseField::from(0u32),
            global_index: BaseField::from(0u32),
            source_index: BaseField::from(0u32),
            event_index: BaseField::from(0u32),
            call_index: BaseField::from(0u32),
            call_count: BaseField::from(0u32),
            first_in_event: BaseField::from(0u32),
            last_in_event: BaseField::from(0u32),
            has_next_event: BaseField::from(0u32),
            first_input0: BaseField::from(0u32),
            first_input1: BaseField::from(0u32),
            updates_digest: BaseField::from(0u32),
            keeps_digest: BaseField::from(0u32),
            n_draws_before: BaseField::from(0u32),
            n_draws_after: BaseField::from(0u32),
            hash_first: BaseField::from(0u32),
            hash_final: BaseField::from(0u32),
            payload_active: [BaseField::from(0u32); N_PAYLOAD_SLOTS],
            padding: [BaseField::from(0u32); N_PAYLOAD_SLOTS],
            kind_selectors: [BaseField::from(0u32); N_KIND_SELECTORS],
            ids: [BaseField::from(0u32); N_CALL_IDS],
            call_values: [[BaseField::from(0u32); FELT252_N_WORDS]; N_CALL_IDS],
            payload_ids: [BaseField::from(0u32); N_PAYLOAD_SLOTS],
            payload_values: [[BaseField::from(0u32); FELT252_N_WORDS]; N_PAYLOAD_SLOTS],
            subtract_prime: [BaseField::from(0u32); N_PAYLOAD_SLOTS],
            carry_pos: [[BaseField::from(0u32); N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS],
            carry_neg: [[BaseField::from(0u32); N_ADDITION_CARRIES]; N_PAYLOAD_SLOTS],
            digest_before: [BaseField::from(0u32); FELT252_N_WORDS],
            digest_after: [BaseField::from(0u32); FELT252_N_WORDS],
            result: [BaseField::from(0u32); FELT252_N_WORDS],
        }
    }

    fn flat(&self) -> Vec<BaseField> {
        let mut values = Vec::with_capacity(TRANSCRIPT_AIR_NUM_COLUMNS);
        values.extend([
            self.active,
            self.global_index,
            self.source_index,
            self.event_index,
            self.call_index,
            self.call_count,
            self.first_in_event,
            self.last_in_event,
            self.has_next_event,
            self.first_input0,
            self.first_input1,
            self.updates_digest,
            self.keeps_digest,
            self.n_draws_before,
            self.n_draws_after,
            self.hash_first,
            self.hash_final,
            self.payload_active[0],
            self.payload_active[1],
            self.padding[0],
            self.padding[1],
        ]);
        values.extend(self.kind_selectors);
        values.extend(self.ids);
        values.extend(
            self.call_values
                .iter()
                .flat_map(|limbs| limbs.iter().copied()),
        );
        values.extend(self.payload_ids);
        values.extend(
            self.payload_values
                .iter()
                .flat_map(|limbs| limbs.iter().copied()),
        );
        values.extend(self.subtract_prime);
        values.extend(
            self.carry_pos
                .iter()
                .flat_map(|carries| carries.iter().copied()),
        );
        values.extend(
            self.carry_neg
                .iter()
                .flat_map(|carries| carries.iter().copied()),
        );
        values.extend(self.digest_before);
        values.extend(self.digest_after);
        values.extend(self.result);
        debug_assert_eq!(values.len(), TRANSCRIPT_AIR_NUM_COLUMNS);
        values
    }
}

fn call_values(call: &Poseidon252PermutationCall) -> [[BaseField; FELT252_N_WORDS]; N_CALL_IDS] {
    [
        call.input[0],
        call.input[1],
        call.input[2],
        call.output[0],
        call.output[1],
        call.output[2],
    ]
    .map(field_element_to_9_bit_limbs)
}

pub(crate) struct TranscriptSemanticWitness {
    pub n_calls: usize,
    pub log_size: u32,
    pub base_trace: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

impl TranscriptSemanticWitness {
    pub(crate) fn new(
        events: &[TranscriptPoseidonEvent],
        mappings: &[CanonicalTranscriptCall],
        poseidon_calls: &[CanonicalPoseidonCall],
        call_ids: &[SyntheticPoseidonCallIds],
        payload_ids: &[BaseField],
    ) -> Result<Self, TranscriptAirError> {
        if mappings.is_empty() {
            return Err(TranscriptAirError::EmptyCalls);
        }
        let transcript_calls = poseidon_calls
            .iter()
            .filter_map(|call| match call.source {
                PoseidonCallSource::Transcript => Some(call.call.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut call_cursor = 0;
        let mut digest = FieldElement252::ZERO;
        let mut n_draws = 0;
        for (event_index, event) in events.iter().enumerate() {
            if event.event_index != event_index
                || event.call_start != call_cursor
                || event.digest_before != digest
                || event.n_draws_before != n_draws
                || !event.is_consistent_with(&transcript_calls)
            {
                return Err(TranscriptAirError::InvalidEvent {
                    event: event.event_index,
                });
            }
            if matches!(
                event.kind,
                Poseidon252CallKind::TranscriptMixFelts | Poseidon252CallKind::TranscriptMixU32s
            ) && event.absorbed_values.len() < 2
            {
                return Err(TranscriptAirError::EmptyHashManyPayload);
            }
            call_cursor = event.call_end;
            digest = event.digest_after;
            n_draws = event.n_draws_after;
        }
        if call_cursor != transcript_calls.len() {
            return Err(TranscriptAirError::InvalidEvent {
                event: events.len(),
            });
        }
        let mut payload_cursor = 0usize;
        let event_payload_ranges = events
            .iter()
            .map(|event| {
                let payload_count = if event_uses_payload_values(event.kind) {
                    event.absorbed_values.len()
                } else {
                    0
                };
                let range = payload_cursor..payload_cursor + payload_count;
                payload_cursor += payload_count;
                range
            })
            .collect::<Vec<_>>();
        if payload_cursor != payload_ids.len() {
            return Err(TranscriptAirError::InvalidPayloadIds);
        }

        let n_calls = mappings.len();
        let padded_size = n_calls.next_power_of_two().max(N_LANES);
        let log_size = padded_size.ilog2();
        if log_size >= 27
            || events
                .iter()
                .any(|event| event.n_draws_before >= (1 << 27) || event.n_draws_after >= (1 << 27))
        {
            return Err(TranscriptAirError::TraceTooLarge);
        }
        let mut rows = Vec::with_capacity(padded_size);
        for (row, mapping) in mappings.iter().enumerate() {
            let Some(event) = events.get(mapping.event_index) else {
                return Err(TranscriptAirError::InvalidMapping { row });
            };
            let Some(call) = poseidon_calls.get(mapping.global_poseidon_call_index) else {
                return Err(TranscriptAirError::InvalidMapping { row });
            };
            let Some(ids) = call_ids.get(mapping.global_poseidon_call_index) else {
                return Err(TranscriptAirError::InvalidMapping { row });
            };
            let event_payload_ids = payload_ids
                .get(event_payload_ranges[mapping.event_index].clone())
                .ok_or(TranscriptAirError::InvalidPayloadIds)?;
            let previous_call = mapping
                .call_index_in_event
                .checked_sub(1)
                .and_then(|_| poseidon_calls.get(mapping.global_poseidon_call_index - 1));
            if call.source != PoseidonCallSource::Transcript
                || mapping.global_poseidon_call_index != row
                || call.source_index != row
                || mapping.call_index_in_event + event.call_start != row
                || row >= event.call_end
                || call.call.kind != event.kind
            {
                return Err(TranscriptAirError::InvalidMapping { row });
            }
            rows.push(TranscriptRow::new(
                row,
                mapping,
                event,
                call,
                previous_call,
                *ids,
                event_payload_ids,
                n_calls,
            )?);
        }
        rows.resize_with(padded_size, TranscriptRow::padding);
        let rows = rows.into_iter().map(|row| row.flat()).collect::<Vec<_>>();
        let domain = CanonicCoset::new(log_size).circle_domain();
        let base_trace = (0..TRANSCRIPT_AIR_NUM_COLUMNS)
            .map(|column| {
                let values = rows.iter().map(|row| row[column]).collect::<Vec<_>>();
                let values = into_bit_reversed_circle_order(&values, log_size);
                CircleEvaluation::new(domain, BaseColumn::from_cpu(&values))
            })
            .collect();
        Ok(Self {
            n_calls,
            log_size,
            base_trace,
        })
    }

    pub(crate) fn preprocessed_columns(
        &self,
    ) -> (
        Vec<PreProcessedColumnId>,
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    ) {
        transcript_preprocessed_columns(self.log_size, self.n_calls)
    }

    pub(crate) fn write_interaction_trace(
        &self,
        common_lookup_elements: &cairo_air::relations::CommonLookupElements,
    ) -> (
        Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let n_vec_rows = 1usize << (self.log_size - LOG_N_LANES);
        let relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            TRANSCRIPT_POSEIDON_CALL_RELATION_ID,
        ));
        let memory_relation_id =
            PackedBaseField::broadcast(BaseField::from(MEMORY_ID_TO_BIG_RELATION_ID));
        let payload_relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            TRANSCRIPT_PAYLOAD_RELATION_ID,
        ));
        let result_relation_id = PackedBaseField::broadcast(BaseField::from_u32_unchecked(
            TRANSCRIPT_DRAW_RESULT_RELATION_ID,
        ));
        let mut logup = LogupTraceGenerator::new(self.log_size);
        let fraction = |relation_index: usize,
                        vec_row: usize|
         -> (PackedSecureField, PackedSecureField) {
            let active = PackedSecureField::from(self.base_trace[0].values.data[vec_row]);
            if relation_index == 0 {
                let mut values = Vec::with_capacity(1 + 2 + N_KIND_SELECTORS + N_CALL_IDS);
                values.push(relation_id);
                values.push(self.base_trace[1].values.data[vec_row]);
                values.push(self.base_trace[2].values.data[vec_row]);
                values.extend(
                    self.base_trace[KIND_COLUMNS_START..ID_COLUMNS_START]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    self.base_trace[ID_COLUMNS_START..CALL_VALUE_COLUMNS_START]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                (active, common_lookup_elements.combine(&values))
            } else if relation_index <= N_CALL_IDS {
                let slot = relation_index - 1;
                let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
                values.push(memory_relation_id);
                values.push(self.base_trace[ID_COLUMNS_START + slot].values.data[vec_row]);
                values.extend((0..FELT252_N_WORDS).map(|limb| {
                    self.base_trace[CALL_VALUE_COLUMNS_START + slot * FELT252_N_WORDS + limb]
                        .values
                        .data[vec_row]
                }));
                (active, common_lookup_elements.combine(&values))
            } else if relation_index < 1 + N_CALL_IDS + 2 * N_PAYLOAD_SLOTS {
                let payload_relation = relation_index - 1 - N_CALL_IDS;
                let slot = payload_relation / 2;
                let payload_active = PackedSecureField::from(
                    self.base_trace[PAYLOAD_ACTIVE_COLUMNS_START + slot]
                        .values
                        .data[vec_row],
                );
                if payload_relation.is_multiple_of(2) {
                    let mut values = Vec::with_capacity(2 + FELT252_N_WORDS);
                    values.push(memory_relation_id);
                    values.push(
                        self.base_trace[PAYLOAD_ID_COLUMNS_START + slot].values.data[vec_row],
                    );
                    values.extend((0..FELT252_N_WORDS).map(|limb| {
                        self.base_trace[PAYLOAD_VALUE_COLUMNS_START + slot * FELT252_N_WORDS + limb]
                            .values
                            .data[vec_row]
                    }));
                    (payload_active, common_lookup_elements.combine(&values))
                } else {
                    let first_in_event =
                        PackedSecureField::from(self.base_trace[6].values.data[vec_row]);
                    let mix_root = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 3].values.data[vec_row],
                    );
                    let mix_felts = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 4].values.data[vec_row],
                    );
                    let mix_u32s = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 5].values.data[vec_row],
                    );
                    let mix_u64 = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 6].values.data[vec_row],
                    );
                    let pow_prefix = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 8].values.data[vec_row],
                    );
                    let pow_nonce = PackedSecureField::from(
                        self.base_trace[KIND_COLUMNS_START + 9].values.data[vec_row],
                    );
                    let slot_is_zero = PackedSecureField::from(PackedBaseField::broadcast(
                        BaseField::from((slot == 0) as u32),
                    ));
                    let slot_is_one = PackedSecureField::from(PackedBaseField::broadcast(
                        BaseField::from((slot == 1) as u32),
                    ));
                    let pair_external = (mix_root + mix_u64 + pow_nonce) * slot_is_one;
                    let hash_many_kind = mix_felts + mix_u32s;
                    let hash_many_external = hash_many_kind * payload_active
                        - hash_many_kind * first_in_event * slot_is_zero;
                    let pow_external =
                        pow_prefix * payload_active - pow_prefix * first_in_event * slot_is_one;
                    let semantic_active = pair_external + hash_many_external + pow_external;
                    let call_index = self.base_trace[4].values.data[vec_row];
                    let hash_many_kind = self.base_trace[KIND_COLUMNS_START + 4].values.data
                        [vec_row]
                        + self.base_trace[KIND_COLUMNS_START + 5].values.data[vec_row]
                        + self.base_trace[KIND_COLUMNS_START + 8].values.data[vec_row];
                    let pair_kind = self.base_trace[KIND_COLUMNS_START + 3].values.data[vec_row]
                        + self.base_trace[KIND_COLUMNS_START + 6].values.data[vec_row]
                        + self.base_trace[KIND_COLUMNS_START + 9].values.data[vec_row];
                    let payload_index = hash_many_kind
                        * (call_index
                            + call_index
                            + PackedBaseField::broadcast(BaseField::from(slot as u32)))
                        + pair_kind * PackedBaseField::broadcast(BaseField::from(slot as u32));
                    let mut values = Vec::with_capacity(3 + N_KIND_SELECTORS + FELT252_N_WORDS);
                    values.push(payload_relation_id);
                    values.push(self.base_trace[3].values.data[vec_row]);
                    values.push(payload_index);
                    values.extend(
                        self.base_trace[KIND_COLUMNS_START..ID_COLUMNS_START]
                            .iter()
                            .map(|column| column.values.data[vec_row]),
                    );
                    values.extend((0..FELT252_N_WORDS).map(|limb| {
                        self.base_trace[PAYLOAD_VALUE_COLUMNS_START + slot * FELT252_N_WORDS + limb]
                            .values
                            .data[vec_row]
                    }));
                    (semantic_active, common_lookup_elements.combine(&values))
                }
            } else {
                let last_in_event =
                    PackedSecureField::from(self.base_trace[7].values.data[vec_row]);
                let result_kind = PackedSecureField::from(
                    self.base_trace[KIND_COLUMNS_START + 7].values.data[vec_row]
                        + self.base_trace[KIND_COLUMNS_START + 9].values.data[vec_row],
                );
                let mut values = Vec::with_capacity(2 + N_KIND_SELECTORS + FELT252_N_WORDS);
                values.push(result_relation_id);
                values.push(self.base_trace[3].values.data[vec_row]);
                values.extend(
                    self.base_trace[KIND_COLUMNS_START..ID_COLUMNS_START]
                        .iter()
                        .map(|column| column.values.data[vec_row]),
                );
                values.extend(
                    (0..FELT252_N_WORDS).map(|limb| {
                        self.base_trace[RESULT_COLUMNS_START + limb].values.data[vec_row]
                    }),
                );
                (
                    last_in_event * result_kind,
                    common_lookup_elements.combine(&values),
                )
            }
        };
        const N_RELATIONS: usize = 2 + N_CALL_IDS + 2 * N_PAYLOAD_SLOTS;
        for relation in 0..N_RELATIONS {
            let mut column = logup.new_col();
            for vec_row in 0..n_vec_rows {
                let (numerator, denominator) = fraction(relation, vec_row);
                column.write_frac(vec_row, numerator, denominator);
            }
            column.finalize_col();
        }
        logup.finalize_last()
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

struct TranscriptTrace<F> {
    active: Pair<F>,
    global_index: Pair<F>,
    source_index: Pair<F>,
    event_index: Pair<F>,
    call_index: Pair<F>,
    call_count: Pair<F>,
    first_in_event: Pair<F>,
    last_in_event: Pair<F>,
    has_next_event: Pair<F>,
    first_input0: Pair<F>,
    first_input1: Pair<F>,
    updates_digest: Pair<F>,
    keeps_digest: Pair<F>,
    n_draws_before: Pair<F>,
    n_draws_after: Pair<F>,
    hash_first: Pair<F>,
    hash_final: Pair<F>,
    payload_active: [Pair<F>; N_PAYLOAD_SLOTS],
    padding: [Pair<F>; N_PAYLOAD_SLOTS],
    kind_selectors: [Pair<F>; N_KIND_SELECTORS],
    ids: [Pair<F>; N_CALL_IDS],
    call_values: Vec<Vec<Pair<F>>>,
    payload_ids: [Pair<F>; N_PAYLOAD_SLOTS],
    payload_values: Vec<Vec<Pair<F>>>,
    subtract_prime: [Pair<F>; N_PAYLOAD_SLOTS],
    carry_pos: Vec<Vec<Pair<F>>>,
    carry_neg: Vec<Vec<Pair<F>>>,
    digest_before: Vec<Pair<F>>,
    digest_after: Vec<Pair<F>>,
    result: Vec<Pair<F>>,
}

fn read_trace<E: EvalAtRow>(eval: &mut E) -> TranscriptTrace<E::F> {
    TranscriptTrace {
        active: read_pair(eval),
        global_index: read_pair(eval),
        source_index: read_pair(eval),
        event_index: read_pair(eval),
        call_index: read_pair(eval),
        call_count: read_pair(eval),
        first_in_event: read_pair(eval),
        last_in_event: read_pair(eval),
        has_next_event: read_pair(eval),
        first_input0: read_pair(eval),
        first_input1: read_pair(eval),
        updates_digest: read_pair(eval),
        keeps_digest: read_pair(eval),
        n_draws_before: read_pair(eval),
        n_draws_after: read_pair(eval),
        hash_first: read_pair(eval),
        hash_final: read_pair(eval),
        payload_active: array::from_fn(|_| read_pair(eval)),
        padding: array::from_fn(|_| read_pair(eval)),
        kind_selectors: array::from_fn(|_| read_pair(eval)),
        ids: array::from_fn(|_| read_pair(eval)),
        call_values: (0..N_CALL_IDS)
            .map(|_| (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect())
            .collect(),
        payload_ids: array::from_fn(|_| read_pair(eval)),
        payload_values: (0..N_PAYLOAD_SLOTS)
            .map(|_| (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect())
            .collect(),
        subtract_prime: array::from_fn(|_| read_pair(eval)),
        carry_pos: (0..N_PAYLOAD_SLOTS)
            .map(|_| (0..N_ADDITION_CARRIES).map(|_| read_pair(eval)).collect())
            .collect(),
        carry_neg: (0..N_PAYLOAD_SLOTS)
            .map(|_| (0..N_ADDITION_CARRIES).map(|_| read_pair(eval)).collect())
            .collect(),
        digest_before: (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect(),
        digest_after: (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect(),
        result: (0..FELT252_N_WORDS).map(|_| read_pair(eval)).collect(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TranscriptSemanticAir {
    log_size: u32,
    n_calls: usize,
    common_lookup_elements: cairo_air::relations::CommonLookupElements,
}

impl TranscriptSemanticAir {
    pub(crate) const fn new(
        log_size: u32,
        n_calls: usize,
        common_lookup_elements: cairo_air::relations::CommonLookupElements,
    ) -> Self {
        Self {
            log_size,
            n_calls,
            common_lookup_elements,
        }
    }
}

impl FrameworkEval for TranscriptSemanticAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let trace = read_trace(&mut eval);
        let expected_active = eval.get_preprocessed_column(transcript_preprocessed_id(
            "active",
            self.log_size,
            self.n_calls,
        ));
        let fixed_first = eval.get_preprocessed_column(transcript_preprocessed_id(
            "first",
            self.log_size,
            self.n_calls,
        ));
        let fixed_last = eval.get_preprocessed_column(transcript_preprocessed_id(
            "last",
            self.log_size,
            self.n_calls,
        ));
        let zero = E::F::from(M31::from(0));
        let one = E::F::from(M31::from(1));

        eval.add_constraint(trace.active.current.clone() - expected_active.clone());
        for flag in [
            &trace.first_in_event,
            &trace.last_in_event,
            &trace.has_next_event,
        ] {
            eval.add_constraint(flag.current.clone() * (flag.current.clone() - one.clone()));
            eval.add_constraint(
                flag.current.clone() * (one.clone() - trace.active.current.clone()),
            );
        }
        for selector in &trace.kind_selectors {
            eval.add_constraint(
                selector.current.clone() * (selector.current.clone() - one.clone()),
            );
        }
        let transcript_kind_sum = trace.kind_selectors[3..]
            .iter()
            .fold(zero.clone(), |sum, selector| sum + selector.current.clone());
        eval.add_constraint(transcript_kind_sum - trace.active.current.clone());
        eval.add_constraint(
            trace.kind_selectors[..3]
                .iter()
                .fold(zero.clone(), |sum, selector| sum + selector.current.clone()),
        );
        for flag in [
            &trace.hash_first,
            &trace.hash_final,
            &trace.payload_active[0],
            &trace.payload_active[1],
            &trace.padding[0],
            &trace.padding[1],
        ] {
            eval.add_constraint(flag.current.clone() * (flag.current.clone() - one.clone()));
            eval.add_constraint(
                flag.current.clone() * (one.clone() - trace.active.current.clone()),
            );
        }
        let hash_many_kind = [4, 5, 8].into_iter().fold(zero.clone(), |sum, index| {
            sum + trace.kind_selectors[index].current.clone()
        });
        let pair_payload_kind = [3, 6, 9].into_iter().fold(zero.clone(), |sum, index| {
            sum + trace.kind_selectors[index].current.clone()
        });
        let no_payload_kind =
            trace.active.current.clone() - hash_many_kind.clone() - pair_payload_kind.clone();
        eval.add_constraint(
            trace.hash_first.current.clone()
                - trace.first_in_event.current.clone() * hash_many_kind.clone(),
        );
        eval.add_constraint(
            trace.hash_final.current.clone()
                - trace.last_in_event.current.clone() * hash_many_kind.clone(),
        );
        for slot in 0..N_PAYLOAD_SLOTS {
            eval.add_constraint(
                pair_payload_kind.clone()
                    * (trace.payload_active[slot].current.clone() - one.clone()),
            );
            eval.add_constraint(
                no_payload_kind.clone() * trace.payload_active[slot].current.clone(),
            );
            eval.add_constraint(
                (trace.active.current.clone() - trace.hash_final.current.clone())
                    * trace.padding[slot].current.clone(),
            );
            let payload_inactive = one.clone() - trace.payload_active[slot].current.clone();
            eval.add_constraint(payload_inactive.clone() * trace.payload_ids[slot].current.clone());
            for limb in &trace.payload_values[slot] {
                eval.add_constraint(payload_inactive.clone() * limb.current.clone());
            }
            eval.add_constraint(
                trace.subtract_prime[slot].current.clone()
                    * (trace.subtract_prime[slot].current.clone() - one.clone()),
            );
            eval.add_constraint(
                (trace.active.current.clone() - hash_many_kind.clone())
                    * trace.subtract_prime[slot].current.clone(),
            );
            for carry in 0..N_ADDITION_CARRIES {
                let positive = trace.carry_pos[slot][carry].current.clone();
                let negative = trace.carry_neg[slot][carry].current.clone();
                eval.add_constraint(positive.clone() * (positive.clone() - one.clone()));
                eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
                eval.add_constraint(positive.clone() * negative.clone());
                eval.add_constraint(
                    (trace.active.current.clone() - hash_many_kind.clone()) * (positive + negative),
                );
            }
        }
        eval.add_constraint(
            trace.hash_final.current.clone() * trace.payload_active[1].current.clone(),
        );
        eval.add_constraint(
            trace.hash_final.current.clone()
                * (trace.payload_active[0].current.clone() + trace.padding[0].current.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            trace.hash_final.current.clone()
                * (trace.padding[1].current.clone() - trace.payload_active[0].current.clone()),
        );

        let first_input0_kind = [3, 4, 5, 6, 7]
            .into_iter()
            .fold(zero.clone(), |sum, index| {
                sum + trace.kind_selectors[index].current.clone()
            });
        eval.add_constraint(
            trace.first_input0.current.clone()
                - trace.first_in_event.current.clone() * first_input0_kind,
        );
        eval.add_constraint(
            trace.first_input1.current.clone()
                - trace.first_in_event.current.clone() * trace.kind_selectors[8].current.clone(),
        );
        let updates_kind = [3, 4, 5, 6].into_iter().fold(zero.clone(), |sum, index| {
            sum + trace.kind_selectors[index].current.clone()
        });
        let keeps_kind = [7, 8, 9].into_iter().fold(zero.clone(), |sum, index| {
            sum + trace.kind_selectors[index].current.clone()
        });
        eval.add_constraint(
            trace.updates_digest.current.clone()
                - trace.last_in_event.current.clone() * updates_kind.clone(),
        );
        eval.add_constraint(
            trace.keeps_digest.current.clone()
                - trace.last_in_event.current.clone() * keeps_kind.clone(),
        );
        eval.add_constraint(
            trace.updates_digest.current.clone() + trace.keeps_digest.current.clone()
                - trace.last_in_event.current.clone(),
        );

        eval.add_constraint(fixed_first.clone() * trace.global_index.current.clone());
        eval.add_constraint(fixed_first.clone() * trace.source_index.current.clone());
        eval.add_constraint(fixed_first.clone() * trace.event_index.current.clone());
        eval.add_constraint(fixed_first.clone() * trace.call_index.current.clone());
        eval.add_constraint(
            fixed_first.clone() * (trace.first_in_event.current.clone() - one.clone()),
        );
        // A CPU proof starts with its first commitment root, while an application proof may first
        // absorb a verifier-trusted statement using mix_felts/mix_u32s/mix_u64.  In both cases the
        // first event must update the zero digest; the exact event kind and payload are fixed by
        // CpuTranscriptBindingAir's program-specific transcript schedule.
        eval.add_constraint(fixed_first.clone() * (updates_kind.clone() - one.clone()));
        eval.add_constraint(fixed_first.clone() * trace.n_draws_before.current.clone());
        for limb in &trace.digest_before {
            eval.add_constraint(fixed_first.clone() * limb.current.clone());
        }
        eval.add_constraint(
            fixed_last.clone() * (trace.last_in_event.current.clone() - one.clone()),
        );
        eval.add_constraint(fixed_last.clone() * trace.has_next_event.current.clone());

        eval.add_constraint(
            trace.first_in_event.current.clone() * trace.call_index.current.clone(),
        );
        eval.add_constraint(
            trace.last_in_event.current.clone()
                * (trace.call_index.current.clone() + one.clone()
                    - trace.call_count.current.clone()),
        );
        eval.add_constraint(
            trace.has_next_event.current.clone()
                - trace.last_in_event.current.clone() * trace.active.next.clone(),
        );

        let row_has_next = expected_active - fixed_last;
        eval.add_constraint(
            row_has_next.clone()
                * (trace.global_index.next.clone()
                    - trace.global_index.current.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            row_has_next.clone()
                * (trace.source_index.next.clone()
                    - trace.source_index.current.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            trace.active.current.clone()
                * (trace.global_index.current.clone() - trace.source_index.current.clone()),
        );

        let continues_event = trace.active.current.clone() - trace.last_in_event.current.clone();
        eval.add_constraint(continues_event.clone() * (one.clone() - trace.active.next.clone()));
        for slot in 0..N_PAYLOAD_SLOTS {
            eval.add_constraint(
                continues_event.clone()
                    * (trace.payload_active[slot].current.clone() - one.clone()),
            );
            eval.add_constraint(continues_event.clone() * trace.padding[slot].current.clone());
        }
        eval.add_constraint(
            continues_event.clone()
                * (trace.event_index.next.clone() - trace.event_index.current.clone()),
        );
        eval.add_constraint(
            continues_event.clone()
                * (trace.call_index.next.clone() - trace.call_index.current.clone() - one.clone()),
        );
        eval.add_constraint(continues_event.clone() * trace.first_in_event.next.clone());
        eval.add_constraint(
            continues_event.clone()
                * (trace.call_count.next.clone() - trace.call_count.current.clone()),
        );
        for selector in &trace.kind_selectors {
            eval.add_constraint(
                continues_event.clone() * (selector.next.clone() - selector.current.clone()),
            );
        }
        for (current, next) in trace
            .digest_before
            .iter()
            .chain(&trace.digest_after)
            .chain(&trace.result)
            .map(|pair| (&pair.current, &pair.next))
        {
            eval.add_constraint(continues_event.clone() * (next.clone() - current.clone()));
        }
        eval.add_constraint(
            continues_event.clone()
                * (trace.n_draws_before.next.clone() - trace.n_draws_before.current.clone()),
        );
        eval.add_constraint(
            continues_event.clone()
                * (trace.n_draws_after.next.clone() - trace.n_draws_after.current.clone()),
        );

        let starts_event = trace.has_next_event.current.clone();
        eval.add_constraint(
            starts_event.clone()
                * (trace.event_index.next.clone()
                    - trace.event_index.current.clone()
                    - one.clone()),
        );
        eval.add_constraint(starts_event.clone() * trace.call_index.next.clone());
        eval.add_constraint(
            starts_event.clone() * (trace.first_in_event.next.clone() - one.clone()),
        );
        for limb in 0..FELT252_N_WORDS {
            eval.add_constraint(
                starts_event.clone()
                    * (trace.digest_before[limb].next.clone()
                        - trace.digest_after[limb].current.clone()),
            );
        }
        eval.add_constraint(
            starts_event.clone()
                * (trace.n_draws_before.next.clone() - trace.n_draws_after.current.clone()),
        );

        let single_call_kind = [3, 6, 7, 9].into_iter().fold(zero.clone(), |sum, index| {
            sum + trace.kind_selectors[index].current.clone()
        });
        eval.add_constraint(
            single_call_kind.clone() * (trace.first_in_event.current.clone() - one.clone()),
        );
        eval.add_constraint(
            single_call_kind.clone() * (trace.last_in_event.current.clone() - one.clone()),
        );
        eval.add_constraint(single_call_kind * (trace.call_count.current.clone() - one.clone()));

        for limb in 0..FELT252_N_WORDS {
            eval.add_constraint(
                trace.first_input0.current.clone()
                    * (trace.digest_before[limb].current.clone()
                        - trace.call_values[0][limb].current.clone()),
            );
            eval.add_constraint(
                trace.first_input1.current.clone()
                    * (trace.digest_before[limb].current.clone()
                        - trace.call_values[1][limb].current.clone()),
            );
            eval.add_constraint(
                trace.updates_digest.current.clone()
                    * (trace.digest_after[limb].current.clone()
                        - trace.call_values[3][limb].current.clone()),
            );
            eval.add_constraint(
                trace.keeps_digest.current.clone()
                    * (trace.digest_after[limb].current.clone()
                        - trace.digest_before[limb].current.clone()),
            );
            eval.add_constraint(
                trace.last_in_event.current.clone()
                    * (trace.result[limb].current.clone()
                        - trace.call_values[3][limb].current.clone()),
            );
            eval.add_constraint(
                continues_event.clone()
                    * (trace.call_values[2][limb].next.clone()
                        - trace.call_values[5][limb].current.clone()),
            );
            for slot in 0..N_PAYLOAD_SLOTS {
                eval.add_constraint(
                    pair_payload_kind.clone()
                        * (trace.payload_values[slot][limb].current.clone()
                            - trace.call_values[slot][limb].current.clone()),
                );

                let current_carry_in = if limb == 0 {
                    zero.clone()
                } else {
                    trace.carry_pos[slot][limb - 1].current.clone()
                        - trace.carry_neg[slot][limb - 1].current.clone()
                };
                let current_carry_out = if limb == N_ADDITION_CARRIES {
                    zero.clone()
                } else {
                    trace.carry_pos[slot][limb].current.clone()
                        - trace.carry_neg[slot][limb].current.clone()
                };
                let current_padding = if limb == 0 {
                    trace.padding[slot].current.clone()
                } else {
                    zero.clone()
                };
                let prime_limb = E::F::from(M31::from(P_FELTS[limb]));
                let first_addition = trace.payload_values[slot][limb].current.clone()
                    + current_padding
                    + current_carry_in
                    - trace.call_values[slot][limb].current.clone()
                    - trace.subtract_prime[slot].current.clone() * prime_limb.clone()
                    - E::F::from(M31::from(512)) * current_carry_out;
                eval.add_constraint(trace.hash_first.current.clone() * first_addition);

                let next_carry_in = if limb == 0 {
                    zero.clone()
                } else {
                    trace.carry_pos[slot][limb - 1].next.clone()
                        - trace.carry_neg[slot][limb - 1].next.clone()
                };
                let next_carry_out = if limb == N_ADDITION_CARRIES {
                    zero.clone()
                } else {
                    trace.carry_pos[slot][limb].next.clone()
                        - trace.carry_neg[slot][limb].next.clone()
                };
                let next_padding = if limb == 0 {
                    trace.padding[slot].next.clone()
                } else {
                    zero.clone()
                };
                let continued_addition = trace.call_values[3 + slot][limb].current.clone()
                    + trace.payload_values[slot][limb].next.clone()
                    + next_padding
                    + next_carry_in
                    - trace.call_values[slot][limb].next.clone()
                    - trace.subtract_prime[slot].next.clone() * prime_limb
                    - E::F::from(M31::from(512)) * next_carry_out;
                eval.add_constraint(continues_event.clone() * continued_addition);
            }
        }

        let mix_kind = updates_kind;
        let draw_kind = trace.kind_selectors[7].current.clone();
        let pow_kind = keeps_kind - draw_kind.clone();
        eval.add_constraint(mix_kind * trace.n_draws_after.current.clone());
        eval.add_constraint(
            draw_kind.clone()
                * (trace.n_draws_after.current.clone()
                    - trace.n_draws_before.current.clone()
                    - one.clone()),
        );
        eval.add_constraint(
            pow_kind * (trace.n_draws_after.current.clone() - trace.n_draws_before.current.clone()),
        );
        let draw_counter = trace.call_values[1][0].current.clone()
            + E::F::from(M31::from(512)) * trace.call_values[1][1].current.clone()
            + E::F::from(M31::from(262_144)) * trace.call_values[1][2].current.clone();
        eval.add_constraint(
            draw_kind.clone() * (trace.n_draws_before.current.clone() - draw_counter),
        );
        for limb in &trace.call_values[1][3..] {
            eval.add_constraint(draw_kind.clone() * limb.current.clone());
        }

        let mut relation_values = Vec::with_capacity(1 + 2 + N_KIND_SELECTORS + N_CALL_IDS);
        relation_values.push(E::F::from(M31::from_u32_unchecked(
            TRANSCRIPT_POSEIDON_CALL_RELATION_ID,
        )));
        relation_values.push(trace.global_index.current);
        relation_values.push(trace.source_index.current);
        relation_values.extend(
            trace
                .kind_selectors
                .iter()
                .map(|selector| selector.current.clone()),
        );
        relation_values.extend(trace.ids.iter().map(|id| id.current.clone()));
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(trace.active.current.clone()),
            &relation_values,
        ));
        for slot in 0..N_CALL_IDS {
            let mut memory_values = Vec::with_capacity(2 + FELT252_N_WORDS);
            memory_values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
            memory_values.push(trace.ids[slot].current.clone());
            memory_values.extend(
                trace.call_values[slot]
                    .iter()
                    .map(|limb| limb.current.clone()),
            );
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(trace.active.current.clone()),
                &memory_values,
            ));
        }
        for slot in 0..N_PAYLOAD_SLOTS {
            let mut memory_values = Vec::with_capacity(2 + FELT252_N_WORDS);
            memory_values.push(E::F::from(MEMORY_ID_TO_BIG_RELATION_ID));
            memory_values.push(trace.payload_ids[slot].current.clone());
            memory_values.extend(
                trace.payload_values[slot]
                    .iter()
                    .map(|limb| limb.current.clone()),
            );
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(trace.payload_active[slot].current.clone()),
                &memory_values,
            ));

            let slot_value = E::F::from(M31::from(slot as u32));
            let slot_is_zero = E::F::from(M31::from((slot == 0) as u32));
            let slot_is_one = E::F::from(M31::from((slot == 1) as u32));
            let pair_external = (trace.kind_selectors[3].current.clone()
                + trace.kind_selectors[6].current.clone()
                + trace.kind_selectors[9].current.clone())
                * slot_is_one.clone();
            let semantic_hash_many_kind =
                trace.kind_selectors[4].current.clone() + trace.kind_selectors[5].current.clone();
            let hash_many_external = semantic_hash_many_kind.clone()
                * trace.payload_active[slot].current.clone()
                - semantic_hash_many_kind
                    * trace.first_in_event.current.clone()
                    * slot_is_zero.clone();
            let pow_external = trace.kind_selectors[8].current.clone()
                * trace.payload_active[slot].current.clone()
                - trace.kind_selectors[8].current.clone()
                    * trace.first_in_event.current.clone()
                    * slot_is_one;
            let semantic_active = pair_external + hash_many_external + pow_external;
            let hash_many_kind = trace.kind_selectors[4].current.clone()
                + trace.kind_selectors[5].current.clone()
                + trace.kind_selectors[8].current.clone();
            let pair_kind = trace.kind_selectors[3].current.clone()
                + trace.kind_selectors[6].current.clone()
                + trace.kind_selectors[9].current.clone();
            let payload_index = hash_many_kind
                * (trace.call_index.current.clone()
                    + trace.call_index.current.clone()
                    + slot_value.clone())
                + pair_kind * slot_value;
            let mut payload_values = Vec::with_capacity(3 + N_KIND_SELECTORS + FELT252_N_WORDS);
            payload_values.push(E::F::from(M31::from_u32_unchecked(
                TRANSCRIPT_PAYLOAD_RELATION_ID,
            )));
            payload_values.push(trace.event_index.current.clone());
            payload_values.push(payload_index);
            payload_values.extend(
                trace
                    .kind_selectors
                    .iter()
                    .map(|selector| selector.current.clone()),
            );
            payload_values.extend(
                trace.payload_values[slot]
                    .iter()
                    .map(|limb| limb.current.clone()),
            );
            eval.add_to_relation(RelationEntry::new(
                &self.common_lookup_elements,
                E::EF::from(semantic_active),
                &payload_values,
            ));
        }

        let result_active = trace.last_in_event.current.clone()
            * (trace.kind_selectors[7].current.clone() + trace.kind_selectors[9].current.clone());
        let mut result_values = Vec::with_capacity(2 + N_KIND_SELECTORS + FELT252_N_WORDS);
        result_values.push(E::F::from(M31::from_u32_unchecked(
            TRANSCRIPT_DRAW_RESULT_RELATION_ID,
        )));
        result_values.push(trace.event_index.current);
        result_values.extend(
            trace
                .kind_selectors
                .iter()
                .map(|selector| selector.current.clone()),
        );
        result_values.extend(trace.result.iter().map(|limb| limb.current.clone()));
        eval.add_to_relation(RelationEntry::new(
            &self.common_lookup_elements,
            E::EF::from(result_active),
            &result_values,
        ));
        eval.finalize_logup();
        eval
    }
}

pub(crate) fn ensure_lookup_balanced(
    poseidon_residual: SecureField,
    claimed_sums: &[SecureField],
) -> Result<(), TranscriptAirError> {
    let total = poseidon_residual + claimed_sums.iter().copied().sum::<SecureField>();
    if total == SecureField::from(0u32) {
        Ok(())
    } else {
        Err(TranscriptAirError::UnbalancedLookup(total))
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use stwo::core::channel::Channel;
    use stwo::core::pcs::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{
        FrameworkComponent, PREPROCESSED_TRACE_IDX, TraceLocationAllocator,
        assert_constraints_on_trace,
    };

    use super::*;
    use crate::stwo_backend::recursive::poseidon252_air::{
        Poseidon252ClosureComponents, Poseidon252ClosureWitness,
    };
    use crate::stwo_backend::recursive::poseidon252_replay::RecordingPoseidon252Channel;

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

    fn sample_witness() -> (
        Vec<CanonicalPoseidonCall>,
        Vec<TranscriptPoseidonEvent>,
        Vec<CanonicalTranscriptCall>,
    ) {
        let mut channel = RecordingPoseidon252Channel::default();
        channel.mix_root(FieldElement252::from(7u32));
        let _ = channel.draw_secure_felt();
        channel.mix_felts(&[SecureField::from(11u32), SecureField::from(13u32)]);
        channel.mix_u64(17);
        let calls = channel
            .calls()
            .into_iter()
            .enumerate()
            .map(|(index, call)| CanonicalPoseidonCall {
                global_index: index,
                source: PoseidonCallSource::Transcript,
                source_index: index,
                call,
            })
            .collect::<Vec<_>>();
        let events = channel.events();
        let mappings = events
            .iter()
            .flat_map(|event| {
                (event.call_start..event.call_end).map(move |call_index| CanonicalTranscriptCall {
                    event_index: event.event_index,
                    call_index_in_event: call_index - event.call_start,
                    global_poseidon_call_index: call_index,
                })
            })
            .collect();
        (calls, events, mappings)
    }

    #[test]
    fn transcript_semantics_export_usage_lookups_and_satisfy_air() {
        crate::stwo_backend::recursive::run_large_stack_test(
            "transcript-semantics-air",
            128 * 1024 * 1024,
            || {
                let (calls, events, mappings) = sample_witness();
                let payloads = transcript_payload_values(&events);
                let poseidon =
                    Poseidon252ClosureWitness::from_canonical_calls_and_values(&calls, &payloads)
                        .unwrap();
                let transcript = TranscriptSemanticWitness::new(
                    &events,
                    &mappings,
                    &calls,
                    &poseidon.synthetic_memory.call_ids,
                    &poseidon.synthetic_memory.extra_ids,
                )
                .unwrap();
                let common_lookup_elements = cairo_air::relations::CommonLookupElements::dummy();
                let mut preprocessed = poseidon.preprocessed_columns();
                let transcript_preprocessed = transcript.preprocessed_columns();
                preprocessed.0.extend(transcript_preprocessed.0);
                preprocessed.1.extend(transcript_preprocessed.1);

                let caller_log_size = poseidon.caller_log_size;
                let poseidon_n_calls = poseidon.n_calls;
                let cairo_claim = poseidon.cairo_claim.clone();
                let mut base_trace = poseidon.cairo_base_trace.clone();
                base_trace.extend(poseidon.caller_base_trace());
                base_trace.extend(poseidon.semantic_base_trace());
                base_trace.extend(transcript.base_trace.clone());
                let poseidon_interaction = poseidon
                    .write_interaction_trace(&common_lookup_elements)
                    .unwrap();
                let (transcript_interaction_trace, transcript_claimed_sum) =
                    transcript.write_interaction_trace(&common_lookup_elements);
                assert_eq!(
                    transcript_interaction_trace.len(),
                    TRANSCRIPT_INTERACTION_COLUMNS
                );
                assert!(
                    ensure_lookup_balanced(
                        poseidon_interaction.lookup_residual,
                        &[transcript_claimed_sum, SecureField::from(0u32)],
                    )
                    .is_err()
                );
                let mut interaction_trace = poseidon_interaction.cairo_interaction_trace;
                interaction_trace.extend(poseidon_interaction.caller_interaction_trace);
                interaction_trace.extend(poseidon_interaction.semantic_interaction_trace);
                interaction_trace.extend(transcript_interaction_trace);

                let mut allocator =
                    TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed.0);
                let poseidon_components = Poseidon252ClosureComponents::new(
                    &cairo_claim,
                    &common_lookup_elements,
                    &poseidon_interaction.cairo_interaction_claim,
                    caller_log_size,
                    poseidon_n_calls,
                    poseidon_interaction.caller_claimed_sum,
                    poseidon_interaction.semantic_claimed_sum,
                    &preprocessed.0,
                    &mut allocator,
                );
                let transcript_component = FrameworkComponent::new(
                    &mut allocator,
                    TranscriptSemanticAir::new(
                        transcript.log_size,
                        transcript.n_calls,
                        common_lookup_elements.clone(),
                    ),
                    transcript_claimed_sum,
                );
                let transcript_interaction = transcript_component
                    .trace_locations()
                    .iter()
                    .find(|span| span.tree_index == 2)
                    .unwrap();
                let poseidon_interaction_columns =
                    interaction_trace.len() - TRANSCRIPT_INTERACTION_COLUMNS;
                assert_eq!(
                    transcript_interaction.col_start,
                    poseidon_interaction_columns
                );
                assert_eq!(
                    transcript_interaction.col_end - transcript_interaction.col_start,
                    TRANSCRIPT_INTERACTION_COLUMNS
                );
                let transcript_original = transcript_component
                    .trace_locations()
                    .iter()
                    .find(|span| span.tree_index == 1)
                    .unwrap();
                let mut trace: TreeVec<Vec<Vec<BaseField>>> = TreeVec::new(vec![
                    preprocessed
                        .1
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
                {
                    let trace_ref = trace.as_cols_ref();
                    assert_component(&poseidon_components.caller, &trace_ref);
                    assert_component(&poseidon_components.semantic, &trace_ref);
                    assert_component(&transcript_component, &trace_ref);
                }
                let first_row = bit_reverse_index(
                    coset_index_to_circle_domain_index(0, transcript.log_size),
                    transcript.log_size,
                );
                trace[1][transcript_original.col_start][first_row] = BaseField::from(0u32);
                let trace_ref = trace.as_cols_ref();
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        assert_component(&transcript_component, &trace_ref);
                    }))
                    .is_err()
                );
                drop(trace_ref);
                trace[1][transcript_original.col_start][first_row] = BaseField::from(1u32);

                let hash_row = bit_reverse_index(
                    coset_index_to_circle_domain_index(2, transcript.log_size),
                    transcript.log_size,
                );
                let payload_column = transcript_original.col_start + PAYLOAD_VALUE_COLUMNS_START;
                let original_payload = trace[1][payload_column][hash_row];
                trace[1][payload_column][hash_row] = original_payload + BaseField::from(1u32);
                {
                    let trace_ref = trace.as_cols_ref();
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| {
                            assert_component(&transcript_component, &trace_ref);
                        }))
                        .is_err()
                    );
                }
                trace[1][payload_column][hash_row] = original_payload;

                let carry_column = transcript_original.col_start + CARRY_POS_COLUMNS_START;
                trace[1][carry_column][hash_row] =
                    BaseField::from(1u32) - trace[1][carry_column][hash_row];
                let trace_ref = trace.as_cols_ref();
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        assert_component(&transcript_component, &trace_ref);
                    }))
                    .is_err()
                );
            },
        );
    }

    #[test]
    fn rejects_tampered_event_chain_before_trace_generation() {
        let (calls, mut events, mappings) = sample_witness();
        let payloads = transcript_payload_values(&events);
        let poseidon =
            Poseidon252ClosureWitness::from_canonical_calls_and_values(&calls, &payloads).unwrap();
        events[1].digest_before += FieldElement252::ONE;
        assert!(matches!(
            TranscriptSemanticWitness::new(
                &events,
                &mappings,
                &calls,
                &poseidon.synthetic_memory.call_ids,
                &poseidon.synthetic_memory.extra_ids,
            ),
            Err(TranscriptAirError::InvalidEvent { .. })
        ));
    }

    #[test]
    fn modular_addition_witness_handles_felt252_prime_wrap() {
        let max = FieldElement252::ZERO - FieldElement252::ONE;
        let (subtract_prime, _, _) =
            modular_add_witness(max, FieldElement252::ZERO, true, FieldElement252::ZERO)
                .expect("p - 1 + 1 must have a valid modular addition witness");

        assert_eq!(subtract_prime, BaseField::from(1u32));
    }
}
