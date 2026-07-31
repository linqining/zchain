//! Canonical witness layout shared by the future transcript, Merkle, FRI and Poseidon AIRs.

use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::poseidon252_replay::{Poseidon252PermutationCall, TranscriptPoseidonEvent};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMerkleTree {
    pub source: PoseidonCallSource,
    pub root: Option<FieldElement252>,
    pub poseidon_call_start: usize,
    pub poseidon_call_end: usize,
    pub leaf_start: usize,
    pub leaf_end: usize,
    pub step_start: usize,
    pub step_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMerkleLeaf {
    pub source: PoseidonCallSource,
    pub position: usize,
    pub values: Vec<BaseField>,
    pub hash: FieldElement252,
    pub poseidon_call_start: usize,
    pub poseidon_call_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMerkleStep {
    pub source: PoseidonCallSource,
    pub layer_index: u32,
    pub parent_index: usize,
    pub left: FieldElement252,
    pub right: FieldElement252,
    pub parent: FieldElement252,
    pub witness_index: Option<usize>,
    pub poseidon_call_index: usize,
}

/// Flattened fixed-verifier witness consumed by the recursive AIR assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalVerifierWitness {
    pub poseidon_calls: Vec<CanonicalPoseidonCall>,
    pub transcript_events: Vec<TranscriptPoseidonEvent>,
    pub merkle_trees: Vec<CanonicalMerkleTree>,
    pub merkle_leaves: Vec<CanonicalMerkleLeaf>,
    pub merkle_steps: Vec<CanonicalMerkleStep>,
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
        drop(push_calls);
        let mut merkle_trees = Vec::new();
        let mut merkle_leaves = Vec::new();
        let mut merkle_steps = Vec::new();
        for tree in &replay.merkle_trees {
            let source = PoseidonCallSource::PcsMerkle {
                tree_index: tree.tree_index,
            };
            push_merkle_tree(
                tree,
                source,
                &mut poseidon_calls,
                &mut merkle_trees,
                &mut merkle_leaves,
                &mut merkle_steps,
            );
        }
        for layer in &replay.fri.layers {
            push_merkle_tree(
                &layer.merkle,
                PoseidonCallSource::FriMerkle {
                    layer_index: layer.layer_index,
                },
                &mut poseidon_calls,
                &mut merkle_trees,
                &mut merkle_leaves,
                &mut merkle_steps,
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
            transcript_events: replay.fri_challenges.transcript_poseidon_events.clone(),
            merkle_trees,
            merkle_leaves,
            merkle_steps,
            fri_fold_layers,
            last_layer_query_positions: replay.fri.last_layer_query_positions.clone(),
            last_layer_query_evaluations: replay.fri.last_layer_query_evaluations.clone(),
        }
    }

    pub fn is_host_consistent(&self) -> bool {
        let transcript_calls = self
            .poseidon_calls
            .iter()
            .filter_map(|call| match call.source {
                PoseidonCallSource::Transcript => Some(&call.call),
                _ => None,
            })
            .cloned()
            .collect::<Vec<_>>();
        let transcript_events_consistent =
            self.transcript_events
                .iter()
                .enumerate()
                .all(|(event_index, event)| {
                    let previous = event_index
                        .checked_sub(1)
                        .and_then(|index| self.transcript_events.get(index));
                    event.event_index == event_index
                        && event.call_start == previous.map_or(0, |previous| previous.call_end)
                        && previous.map_or(
                            event.digest_before == FieldElement252::ZERO
                                && event.n_draws_before == 0,
                            |previous| {
                                event.digest_before == previous.digest_after
                                    && event.n_draws_before == previous.n_draws_after
                            },
                        )
                        && event.is_consistent_with(&transcript_calls)
                })
                && self
                    .transcript_events
                    .last()
                    .is_some_and(|event| event.call_end == transcript_calls.len());

        let merkle_consistent = self.merkle_trees.iter().all(|tree| {
            tree.poseidon_call_start <= tree.poseidon_call_end
                && tree.poseidon_call_end <= self.poseidon_calls.len()
                && tree.leaf_start <= tree.leaf_end
                && tree.leaf_end <= self.merkle_leaves.len()
                && tree.step_start <= tree.step_end
                && tree.step_end <= self.merkle_steps.len()
                && self.merkle_leaves[tree.leaf_start..tree.leaf_end]
                    .iter()
                    .all(|leaf| {
                        leaf.source == tree.source && leaf_is_consistent(leaf, &self.poseidon_calls)
                    })
                && self.merkle_steps[tree.step_start..tree.step_end]
                    .iter()
                    .all(|step| {
                        step.source == tree.source && step_is_consistent(step, &self.poseidon_calls)
                    })
                && tree.root.map_or(tree.step_start == tree.step_end, |root| {
                    self.merkle_steps[tree.step_start..tree.step_end]
                        .last()
                        .is_some_and(|step| step.parent == root)
                })
        });

        transcript_events_consistent
            && merkle_consistent
            && self
                .poseidon_calls
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

fn push_merkle_tree(
    tree: &super::stwo_replay::MerkleTreeReplay,
    source: PoseidonCallSource,
    poseidon_calls: &mut Vec<CanonicalPoseidonCall>,
    merkle_trees: &mut Vec<CanonicalMerkleTree>,
    merkle_leaves: &mut Vec<CanonicalMerkleLeaf>,
    merkle_steps: &mut Vec<CanonicalMerkleStep>,
) {
    let poseidon_call_start = poseidon_calls.len();
    for (source_index, call) in tree.poseidon_calls.iter().cloned().enumerate() {
        poseidon_calls.push(CanonicalPoseidonCall {
            global_index: poseidon_calls.len(),
            source,
            source_index,
            call,
        });
    }
    let parent_call_indices = tree
        .poseidon_calls
        .iter()
        .enumerate()
        .filter_map(|(index, call)| {
            (call.kind == super::poseidon252_replay::Poseidon252CallKind::MerkleParent)
                .then_some(poseidon_call_start + index)
        })
        .collect::<Vec<_>>();
    let leaf_start = merkle_leaves.len();
    merkle_leaves.extend(tree.leaf_replays.iter().map(|leaf| CanonicalMerkleLeaf {
        source,
        position: leaf.position,
        values: leaf.values.clone(),
        hash: leaf.hash,
        poseidon_call_start: poseidon_call_start + leaf.poseidon_call_start,
        poseidon_call_end: poseidon_call_start + leaf.poseidon_call_end,
    }));
    let step_start = merkle_steps.len();
    merkle_steps.extend(tree.steps.iter().zip(parent_call_indices).map(
        |(step, poseidon_call_index)| CanonicalMerkleStep {
            source,
            layer_index: step.layer_index,
            parent_index: step.parent_index,
            left: step.left,
            right: step.right,
            parent: step.parent,
            witness_index: step.witness_index,
            poseidon_call_index,
        },
    ));
    merkle_trees.push(CanonicalMerkleTree {
        source,
        root: tree.computed_root,
        poseidon_call_start,
        poseidon_call_end: poseidon_calls.len(),
        leaf_start,
        leaf_end: merkle_leaves.len(),
        step_start,
        step_end: merkle_steps.len(),
    });
}

fn leaf_is_consistent(leaf: &CanonicalMerkleLeaf, calls: &[CanonicalPoseidonCall]) -> bool {
    let Some(leaf_calls) = calls.get(leaf.poseidon_call_start..leaf.poseidon_call_end) else {
        return false;
    };
    !leaf_calls.is_empty()
        && leaf_calls.iter().all(|call| call.source == leaf.source)
        && leaf_calls.last().is_some_and(|call| {
            call.call.kind == super::poseidon252_replay::Poseidon252CallKind::MerkleLeafFinalize
                && call.call.output[0] == leaf.hash
        })
}

fn step_is_consistent(step: &CanonicalMerkleStep, calls: &[CanonicalPoseidonCall]) -> bool {
    calls.get(step.poseidon_call_index).is_some_and(|call| {
        call.source == step.source
            && call.call.kind == super::poseidon252_replay::Poseidon252CallKind::MerkleParent
            && call.call.input == [step.left, step.right, FieldElement252::TWO]
            && call.call.output[0] == step.parent
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::poseidon252_air::Poseidon252ClosureWitness;
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
        let poseidon_closure =
            Poseidon252ClosureWitness::from_canonical_calls(&witness.poseidon_calls).unwrap();

        assert!(witness.is_host_consistent());
        assert!(poseidon_closure.padded_calls.len() >= witness.poseidon_calls.len());
        assert_eq!(
            witness.poseidon_calls.len(),
            replay.all_poseidon_calls().len()
        );
        assert_eq!(witness.fri_fold_layers.len(), replay.fri.layers.len());
        assert_eq!(
            witness.merkle_trees.len(),
            replay.merkle_trees.len() + replay.fri.layers.len()
        );
        assert_eq!(
            witness.merkle_steps.len(),
            replay
                .merkle_trees
                .iter()
                .map(|tree| tree.steps.len())
                .sum::<usize>()
                + replay
                    .fri
                    .layers
                    .iter()
                    .map(|layer| layer.merkle.steps.len())
                    .sum::<usize>()
        );

        let mut tampered_event = witness.clone();
        tampered_event.transcript_events[0].result += FieldElement252::ONE;
        assert!(!tampered_event.is_host_consistent());

        let mut tampered_merkle = witness.clone();
        tampered_merkle.merkle_steps[0].parent += FieldElement252::ONE;
        assert!(!tampered_merkle.is_host_consistent());
    }
}
