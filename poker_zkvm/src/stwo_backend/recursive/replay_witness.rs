//! Canonical witness layout shared by the future transcript, Merkle, FRI and Poseidon AIRs.

use stwo::core::fields::qm31::SecureField;

use super::poseidon252_replay::Poseidon252PermutationCall;
use super::verifier_program::CpuVerifierReplay;

/// Protocol location of one Poseidon252 permutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoseidonCallSource {
    Transcript,
    PcsMerkle { tree_index: usize },
    FriMerkle { layer_index: usize },
}

/// One permutation together with its stable location in the canonical verifier replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalPoseidonCall {
    pub global_index: usize,
    pub source: PoseidonCallSource,
    pub source_index: usize,
    pub call: Poseidon252PermutationCall,
}

/// Exact pre-fold and post-fold values for one committed FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalFriFoldLayer {
    pub layer_index: usize,
    pub fold_step: u32,
    pub decommitment_positions: Vec<usize>,
    pub coset_domain_initial_indexes: Vec<usize>,
    pub opened_coset_evaluations: Vec<Vec<SecureField>>,
    pub folded_query_positions: Vec<usize>,
    pub folded_evaluations: Vec<SecureField>,
}

/// Flattened fixed-verifier witness consumed by the recursive AIR assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalVerifierWitness {
    pub poseidon_calls: Vec<CanonicalPoseidonCall>,
    pub fri_fold_layers: Vec<CanonicalFriFoldLayer>,
    pub last_layer_query_positions: Vec<usize>,
    pub last_layer_query_evaluations: Vec<SecureField>,
}

impl CanonicalVerifierWitness {
    pub fn from_cpu_replay(replay: &CpuVerifierReplay) -> Self {
        let mut poseidon_calls = Vec::new();
        let mut push_calls = |source, calls: &[Poseidon252PermutationCall]| {
            for (source_index, call) in calls.iter().cloned().enumerate() {
                poseidon_calls.push(CanonicalPoseidonCall {
                    global_index: poseidon_calls.len(),
                    source,
                    source_index,
                    call,
                });
            }
        };

        push_calls(
            PoseidonCallSource::Transcript,
            &replay.transcript_poseidon_calls,
        );
        for tree in &replay.merkle_trees {
            push_calls(
                PoseidonCallSource::PcsMerkle {
                    tree_index: tree.tree_index,
                },
                &tree.poseidon_calls,
            );
        }
        for layer in &replay.fri.layers {
            push_calls(
                PoseidonCallSource::FriMerkle {
                    layer_index: layer.layer_index,
                },
                &layer.merkle.poseidon_calls,
            );
        }

        let fri_fold_layers = replay
            .fri
            .layers
            .iter()
            .map(|layer| CanonicalFriFoldLayer {
                layer_index: layer.layer_index,
                fold_step: layer.fold_step,
                decommitment_positions: layer.decommitment_positions.clone(),
                coset_domain_initial_indexes: layer.coset_domain_initial_indexes.clone(),
                opened_coset_evaluations: layer.opened_coset_evaluations.clone(),
                folded_query_positions: layer.folded_query_positions.clone(),
                folded_evaluations: layer.folded_evaluations.clone(),
            })
            .collect();

        Self {
            poseidon_calls,
            fri_fold_layers,
            last_layer_query_positions: replay.fri.last_layer_query_positions.clone(),
            last_layer_query_evaluations: replay.fri.last_layer_query_evaluations.clone(),
        }
    }

    pub fn is_host_consistent(&self) -> bool {
        self.poseidon_calls
            .iter()
            .enumerate()
            .all(|(index, call)| call.global_index == index && call.call.is_valid())
            && self.fri_fold_layers.iter().all(|layer| {
                layer.opened_coset_evaluations.len() == layer.coset_domain_initial_indexes.len()
                    && layer.folded_query_positions.len() == layer.folded_evaluations.len()
            })
            && self.last_layer_query_positions.len() == self.last_layer_query_evaluations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::verifier_program::{
        build_cpu_recursive_public_inputs, replay_cpu_verifier,
    };
    use crate::stwo_backend::trace_native::TraceBuilder;

    #[test]
    fn flattens_complete_cpu_verifier_witness() {
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let proof = prove_cpu_trace(&builder.finalize()).expect("L1 proof should succeed");
        let inputs = build_cpu_recursive_public_inputs(&proof, 10).unwrap();
        let replay = replay_cpu_verifier(&proof, &inputs).unwrap();
        let witness = CanonicalVerifierWitness::from_cpu_replay(&replay);

        assert!(witness.is_host_consistent());
        assert_eq!(
            witness.poseidon_calls.len(),
            replay.all_poseidon_calls().len()
        );
        assert_eq!(witness.fri_fold_layers.len(), replay.fri.layers.len());
    }
}
