//! Poseidon252 permutation call recording for recursive verifier replay.
//!
//! Stwo's transcript and lifted Merkle hasher use several convenience hash APIs, but the
//! recursive AIR ultimately has to constrain the underlying three-element Hades permutations.
//! This module mirrors those APIs while retaining every permutation input and output in canonical
//! execution order.

use core::{array, iter};
use std::cell::RefCell;

use starknet_crypto::poseidon_permute_comp;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::vcs::utils::add_length_padding;
use stwo::core::vcs_lifted::poseidon252_merkle::ELEMENTS_IN_BUFFER;

const ELEMENTS_IN_BLOCK: usize = ELEMENTS_IN_BUFFER / 2;
const FELTS_PER_HASH: usize = 8;

/// The verifier operation that caused a Poseidon252 permutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Poseidon252CallKind {
    MerkleLeafAbsorb,
    MerkleLeafFinalize,
    MerkleParent,
    TranscriptMixRoot,
    TranscriptMixFelts,
    TranscriptMixU32s,
    TranscriptMixU64,
    TranscriptDraw,
    TranscriptPowPrefix,
    TranscriptPowNonce,
}

/// One exact Starknet Poseidon252 Hades permutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Poseidon252PermutationCall {
    pub kind: Poseidon252CallKind,
    pub input: [FieldElement252; 3],
    pub output: [FieldElement252; 3],
}

impl Poseidon252PermutationCall {
    /// Re-evaluates the native permutation. This is only a host-side audit check; the recursive
    /// proof still needs the non-native AIR to constrain the same relation.
    pub fn is_valid(&self) -> bool {
        let mut state = self.input;
        poseidon_permute_comp(&mut state);
        state == self.output
    }
}

fn permute_and_record(
    state: &mut [FieldElement252; 3],
    kind: Poseidon252CallKind,
    calls: &RefCell<Vec<Poseidon252PermutationCall>>,
) {
    let input = *state;
    poseidon_permute_comp(state);
    calls.borrow_mut().push(Poseidon252PermutationCall {
        kind,
        input,
        output: *state,
    });
}

/// Records the single permutation used by `poseidon_hash(left, right)`.
pub(crate) fn poseidon_hash_pair_with_call(
    left: FieldElement252,
    right: FieldElement252,
    kind: Poseidon252CallKind,
) -> (FieldElement252, Poseidon252PermutationCall) {
    let input = [left, right, FieldElement252::TWO];
    let mut output = input;
    poseidon_permute_comp(&mut output);
    (
        output[0],
        Poseidon252PermutationCall {
            kind,
            input,
            output,
        },
    )
}

fn construct_felt252_from_m31s(values: &[BaseField]) -> FieldElement252 {
    let shift: FieldElement252 = (1u64 << 31).into();
    let mut felt = values.iter().fold(FieldElement252::ZERO, |acc, value| {
        acc * shift + FieldElement252::from(value.0)
    });
    if values.len() < ELEMENTS_IN_BLOCK {
        add_length_padding(&mut felt, values.len());
    }
    felt
}

/// Replays the lifted Poseidon252 leaf hasher and records all absorb/finalize permutations.
pub(crate) fn hash_m31_leaf_with_calls(
    values: &[BaseField],
) -> (FieldElement252, Vec<Poseidon252PermutationCall>) {
    let calls = RefCell::new(Vec::new());
    let mut state = [FieldElement252::ZERO; 3];
    let mut chunks = values.chunks_exact(ELEMENTS_IN_BUFFER);
    for chunk in chunks.by_ref() {
        let (left, right) = chunk.split_at(ELEMENTS_IN_BLOCK);
        state[0] += construct_felt252_from_m31s(left);
        state[1] += construct_felt252_from_m31s(right);
        permute_and_record(&mut state, Poseidon252CallKind::MerkleLeafAbsorb, &calls);
    }

    let remainder: Vec<_> = chunks
        .remainder()
        .chunks(ELEMENTS_IN_BLOCK)
        .map(construct_felt252_from_m31s)
        .collect();
    let mut remainder_pairs = remainder.chunks_exact(2);
    for pair in remainder_pairs.by_ref() {
        state[0] += pair[0];
        state[1] += pair[1];
        permute_and_record(&mut state, Poseidon252CallKind::MerkleLeafAbsorb, &calls);
    }
    let final_remainder = remainder_pairs.remainder();
    if let Some(value) = final_remainder.first() {
        state[0] += *value;
    }
    state[final_remainder.len()] += FieldElement252::ONE;
    permute_and_record(&mut state, Poseidon252CallKind::MerkleLeafFinalize, &calls);

    (state[0], calls.into_inner())
}

/// A byte-for-byte transcript mirror of Stwo's `Poseidon252Channel` that records each underlying
/// permutation. It is used only to construct canonical recursive witness data.
#[derive(Clone, Default, Debug)]
pub(crate) struct RecordingPoseidon252Channel {
    digest: FieldElement252,
    n_draws: u32,
    calls: RefCell<Vec<Poseidon252PermutationCall>>,
}

impl RecordingPoseidon252Channel {
    pub const POW_PREFIX: u32 = 0x1234_5678;

    pub const fn digest(&self) -> FieldElement252 {
        self.digest
    }

    pub fn calls(&self) -> Vec<Poseidon252PermutationCall> {
        self.calls.borrow().clone()
    }

    pub fn mix_root(&mut self, root: FieldElement252) {
        let (digest, call) =
            poseidon_hash_pair_with_call(self.digest, root, Poseidon252CallKind::TranscriptMixRoot);
        self.calls.borrow_mut().push(call);
        self.update_digest(digest);
    }

    fn update_digest(&mut self, digest: FieldElement252) {
        self.digest = digest;
        self.n_draws = 0;
    }

    fn hash_many_and_record(
        &self,
        values: &[FieldElement252],
        kind: Poseidon252CallKind,
    ) -> FieldElement252 {
        let mut state = [FieldElement252::ZERO; 3];
        let mut chunks = values.chunks_exact(2);
        for chunk in chunks.by_ref() {
            state[0] += chunk[0];
            state[1] += chunk[1];
            permute_and_record(&mut state, kind, &self.calls);
        }
        let remainder = chunks.remainder();
        if let Some(value) = remainder.first() {
            state[0] += *value;
        }
        state[remainder.len()] += FieldElement252::ONE;
        permute_and_record(&mut state, kind, &self.calls);
        state[0]
    }

    fn draw_secure_felt252(&mut self) -> FieldElement252 {
        let mut state = [self.digest, self.n_draws.into(), FieldElement252::THREE];
        permute_and_record(&mut state, Poseidon252CallKind::TranscriptDraw, &self.calls);
        self.n_draws += 1;
        state[0]
    }

    fn draw_base_felts(&mut self) -> [BaseField; FELTS_PER_HASH] {
        let shift: FieldElement252 = (1u64 << 31).into();
        let mut current = self.draw_secure_felt252();
        let words: [u32; FELTS_PER_HASH] = array::from_fn(|_| {
            let next = current.floor_div(shift);
            let word = current - next * shift;
            current = next;
            word.try_into().expect("drawn M31 word fits u32")
        });
        words.map(|word| BaseField::reduce(u64::from(word)))
    }
}

impl Channel for RecordingPoseidon252Channel {
    const BYTES_PER_HASH: usize = 252 / 8;

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let shift: FieldElement252 = (1u64 << 31).into();
        let mut values = Vec::with_capacity(felts.len() / 2 + 2);
        values.push(self.digest);
        for chunk in felts.chunks(2) {
            values.push(
                chunk
                    .iter()
                    .flat_map(|value| value.to_m31_array())
                    .fold(FieldElement252::ONE, |acc, limb| {
                        acc * shift + FieldElement252::from(limb.0)
                    }),
            );
        }
        let digest = self.hash_many_and_record(&values, Poseidon252CallKind::TranscriptMixFelts);
        self.update_digest(digest);
    }

    fn mix_u32s(&mut self, data: &[u32]) {
        let shift: FieldElement252 = (1u64 << 32).into();
        let padding_len = 6 - ((data.len() + 6) % 7);
        let padded: Vec<_> = data
            .iter()
            .copied()
            .chain(iter::repeat_n(0, padding_len))
            .collect();
        let mut felts: Vec<_> = padded
            .chunks(7)
            .map(|chunk| {
                chunk.iter().fold(FieldElement252::ZERO, |acc, value| {
                    acc * shift + FieldElement252::from(*value)
                })
            })
            .collect();
        if padding_len != 0 {
            add_length_padding(
                felts.last_mut().expect("padded chunk must exist"),
                7 - padding_len,
            );
        }
        let values: Vec<_> = iter::once(self.digest).chain(felts).collect();
        let digest = self.hash_many_and_record(&values, Poseidon252CallKind::TranscriptMixU32s);
        self.update_digest(digest);
    }

    fn mix_u64(&mut self, value: u64) {
        let (digest, call) = poseidon_hash_pair_with_call(
            self.digest,
            value.into(),
            Poseidon252CallKind::TranscriptMixU64,
        );
        self.calls.borrow_mut().push(call);
        self.update_digest(digest);
    }

    fn draw_secure_felt(&mut self) -> SecureField {
        let felts = self.draw_base_felts();
        SecureField::from_m31_array(felts[..SECURE_EXTENSION_DEGREE].try_into().unwrap())
    }

    fn draw_secure_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut felts = iter::from_fn(|| Some(self.draw_base_felts())).flatten();
        iter::from_fn(|| {
            Some(SecureField::from_m31_array([
                felts.next()?,
                felts.next()?,
                felts.next()?,
                felts.next()?,
            ]))
        })
        .take(n_felts)
        .collect()
    }

    fn draw_u32s(&mut self) -> Vec<u32> {
        let shift: FieldElement252 = (1u64 << 32).into();
        let mut current = self.draw_secure_felt252();
        array::from_fn::<_, 7, _>(|_| {
            let next = current.floor_div(shift);
            let word = current - next * shift;
            current = next;
            word.try_into().expect("drawn word fits u32")
        })
        .to_vec()
    }

    fn verify_pow_nonce(&self, n_bits: u32, nonce: u64) -> bool {
        let prefixed_digest = self.hash_many_and_record(
            &[Self::POW_PREFIX.into(), self.digest, n_bits.into()],
            Poseidon252CallKind::TranscriptPowPrefix,
        );
        let (hash, call) = poseidon_hash_pair_with_call(
            prefixed_digest,
            nonce.into(),
            Poseidon252CallKind::TranscriptPowNonce,
        );
        self.calls.borrow_mut().push(call);
        let bytes = hash.to_bytes_be();
        let n_zeros = u128::from_be_bytes(bytes[16..].try_into().unwrap()).trailing_zeros();
        n_zeros >= n_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::channel::Poseidon252Channel;

    #[test]
    fn recording_channel_matches_stwo_channel() {
        let mut expected = Poseidon252Channel::default();
        let mut actual = RecordingPoseidon252Channel::default();
        let root = FieldElement252::from(123456u64);
        actual.mix_root(root);
        expected.update_digest(starknet_crypto::poseidon_hash(expected.digest(), root));

        let felts = [SecureField::from(7u32), SecureField::from(9u32)];
        expected.mix_felts(&felts);
        actual.mix_felts(&felts);
        assert_eq!(actual.digest(), expected.digest());

        assert_eq!(actual.draw_secure_felts(3), expected.draw_secure_felts(3));
        assert_eq!(actual.draw_u32s(), expected.draw_u32s());
        actual.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8]);
        expected.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8]);
        actual.mix_u64(42);
        expected.mix_u64(42);
        assert_eq!(actual.digest(), expected.digest());
        assert!(!actual.calls().is_empty());
        assert!(
            actual
                .calls()
                .iter()
                .all(Poseidon252PermutationCall::is_valid)
        );
    }
}
