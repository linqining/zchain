//! Canonical witness layout shared by the future transcript, Merkle, FRI and Poseidon AIRs.

use std::collections::HashMap;

use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;

use super::poseidon252_replay::{Poseidon252PermutationCall, TranscriptPoseidonEvent};
use super::verifier_program::CpuVerifierReplay;

/// Protocol location of one Poseidon252 permutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Stable lookup key from one transcript permutation to its owning transcript event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalTranscriptCall {
    pub event_index: usize,
    pub call_index_in_event: usize,
    pub global_poseidon_call_index: usize,
}

/// Exact pre-fold and post-fold values for one committed FRI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalFriFoldLayer {
    pub layer_index: usize,
    pub fold_step: u32,
    pub alpha: SecureField,
    pub decommitment_positions: Vec<usize>,
    pub coset_domain_initial_indexes: Vec<usize>,
    pub opened_coset_evaluations: Vec<Vec<SecureField>>,
    pub folded_query_positions: Vec<usize>,
    pub folded_evaluations: Vec<SecureField>,
    pub merkle_leaf_start: usize,
    pub merkle_leaf_end: usize,
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

/// Provider/consumer row for the Merkle node multiset lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalMerkleNodeUseKind {
    Leaf,
    Witness,
    Parent,
    LeftChild,
    RightChild,
    Root,
}

impl CanonicalMerkleNodeUseKind {
    const fn multiplicity(self) -> i32 {
        match self {
            Self::Leaf | Self::Witness | Self::Parent => -1,
            Self::LeftChild | Self::RightChild | Self::Root => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalMerkleNodeUse {
    pub source: PoseidonCallSource,
    pub layer_index: u32,
    pub node_index: usize,
    pub hash: FieldElement252,
    pub kind: CanonicalMerkleNodeUseKind,
    pub step_index: Option<usize>,
}

/// Flattened fixed-verifier witness consumed by the recursive AIR assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalVerifierWitness {
    pub poseidon_calls: Vec<CanonicalPoseidonCall>,
    pub transcript_events: Vec<TranscriptPoseidonEvent>,
    pub transcript_calls: Vec<CanonicalTranscriptCall>,
    pub merkle_trees: Vec<CanonicalMerkleTree>,
    pub merkle_leaves: Vec<CanonicalMerkleLeaf>,
    pub merkle_steps: Vec<CanonicalMerkleStep>,
    pub merkle_node_uses: Vec<CanonicalMerkleNodeUse>,
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
        let transcript_calls = replay
            .fri_challenges
            .transcript_poseidon_events
            .iter()
            .flat_map(|event| {
                (event.call_start..event.call_end).map(move |source_call_index| {
                    CanonicalTranscriptCall {
                        event_index: event.event_index,
                        call_index_in_event: source_call_index - event.call_start,
                        global_poseidon_call_index: source_call_index,
                    }
                })
            })
            .collect();
        let mut merkle_trees = Vec::new();
        let mut merkle_leaves = Vec::new();
        let mut merkle_steps = Vec::new();
        let mut merkle_node_uses = Vec::new();
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
                &mut merkle_node_uses,
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
                &mut merkle_node_uses,
            );
        }

        let fri_fold_layers = replay
            .fri
            .layers
            .iter()
            .enumerate()
            .map(|(index, layer)| {
                let tree = &merkle_trees[replay.merkle_trees.len() + index];
                let alpha = if index == 0 {
                    replay.fri_challenges.first_layer_alpha
                } else {
                    replay.fri_challenges.inner_layer_alphas[index - 1]
                };
                CanonicalFriFoldLayer {
                    layer_index: layer.layer_index,
                    fold_step: layer.fold_step,
                    alpha,
                    decommitment_positions: layer.decommitment_positions.clone(),
                    coset_domain_initial_indexes: layer.coset_domain_initial_indexes.clone(),
                    opened_coset_evaluations: layer.opened_coset_evaluations.clone(),
                    folded_query_positions: layer.folded_query_positions.clone(),
                    folded_evaluations: layer.folded_evaluations.clone(),
                    merkle_leaf_start: tree.leaf_start,
                    merkle_leaf_end: tree.leaf_end,
                }
            })
            .collect();

        Self {
            poseidon_calls,
            transcript_events: replay.fri_challenges.transcript_poseidon_events.clone(),
            transcript_calls,
            merkle_trees,
            merkle_leaves,
            merkle_steps,
            merkle_node_uses,
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
        let transcript_call_mapping_consistent = self.transcript_calls.len()
            == transcript_calls.len()
            && self
                .transcript_calls
                .iter()
                .enumerate()
                .all(|(source_call_index, mapping)| {
                    self.transcript_events
                        .get(mapping.event_index)
                        .is_some_and(|event| {
                            mapping.global_poseidon_call_index == source_call_index
                                && source_call_index
                                    == event.call_start + mapping.call_index_in_event
                                && source_call_index < event.call_end
                        })
                });

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
            && transcript_call_mapping_consistent
            && merkle_consistent
            && merkle_node_uses_balance(&self.merkle_node_uses)
            && self
                .poseidon_calls
                .iter()
                .enumerate()
                .all(|(index, call)| call.global_index == index && call.call.is_valid())
            && self
                .fri_fold_layers
                .iter()
                .all(|layer| fri_layer_is_consistent(layer, &self.merkle_leaves))
            && self
                .fri_fold_layers
                .windows(2)
                .all(|layers| folded_queries_feed_next_layer(&layers[0], &layers[1]))
            && self.fri_fold_layers.last().is_some_and(|layer| {
                layer.folded_query_positions == self.last_layer_query_positions
                    && layer.folded_evaluations == self.last_layer_query_evaluations
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
    merkle_node_uses: &mut Vec<CanonicalMerkleNodeUse>,
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
    push_merkle_node_uses(tree, source, step_start, merkle_node_uses);
}

fn push_merkle_node_uses(
    tree: &super::stwo_replay::MerkleTreeReplay,
    source: PoseidonCallSource,
    global_step_start: usize,
    uses: &mut Vec<CanonicalMerkleNodeUse>,
) {
    let mut available = HashMap::new();
    for leaf in &tree.leaf_replays {
        available.insert((0u32, leaf.position), leaf.hash);
        uses.push(CanonicalMerkleNodeUse {
            source,
            layer_index: 0,
            node_index: leaf.position,
            hash: leaf.hash,
            kind: CanonicalMerkleNodeUseKind::Leaf,
            step_index: None,
        });
    }

    for (local_step_index, step) in tree.steps.iter().enumerate() {
        let step_index = global_step_start + local_step_index;
        let left_index = step.parent_index << 1;
        let right_index = left_index + 1;
        for (node_index, hash, kind) in [
            (left_index, step.left, CanonicalMerkleNodeUseKind::LeftChild),
            (
                right_index,
                step.right,
                CanonicalMerkleNodeUseKind::RightChild,
            ),
        ] {
            let key = (step.layer_index, node_index);
            if !available.contains_key(&key) {
                available.insert(key, hash);
                uses.push(CanonicalMerkleNodeUse {
                    source,
                    layer_index: step.layer_index,
                    node_index,
                    hash,
                    kind: CanonicalMerkleNodeUseKind::Witness,
                    step_index: Some(step_index),
                });
            }
            uses.push(CanonicalMerkleNodeUse {
                source,
                layer_index: step.layer_index,
                node_index,
                hash,
                kind,
                step_index: Some(step_index),
            });
        }

        let parent_key = (step.layer_index + 1, step.parent_index);
        available.insert(parent_key, step.parent);
        uses.push(CanonicalMerkleNodeUse {
            source,
            layer_index: step.layer_index + 1,
            node_index: step.parent_index,
            hash: step.parent,
            kind: CanonicalMerkleNodeUseKind::Parent,
            step_index: Some(step_index),
        });
    }

    if let Some(root) = tree.computed_root {
        let root_layer = tree.steps.last().map_or(0, |step| step.layer_index + 1);
        uses.push(CanonicalMerkleNodeUse {
            source,
            layer_index: root_layer,
            node_index: 0,
            hash: root,
            kind: CanonicalMerkleNodeUseKind::Root,
            step_index: None,
        });
    }
}

fn merkle_node_uses_balance(uses: &[CanonicalMerkleNodeUse]) -> bool {
    let mut balances = HashMap::<(PoseidonCallSource, u32, usize, [u8; 32]), i32>::new();
    for node_use in uses {
        *balances
            .entry((
                node_use.source,
                node_use.layer_index,
                node_use.node_index,
                node_use.hash.to_bytes_be(),
            ))
            .or_default() += node_use.kind.multiplicity();
    }
    balances.values().all(|balance| *balance == 0)
}

fn fri_layer_is_consistent(
    layer: &CanonicalFriFoldLayer,
    merkle_leaves: &[CanonicalMerkleLeaf],
) -> bool {
    if layer.opened_coset_evaluations.len() != layer.coset_domain_initial_indexes.len()
        || layer.folded_query_positions.len() != layer.folded_evaluations.len()
    {
        return false;
    }
    let Some(leaves) = merkle_leaves.get(layer.merkle_leaf_start..layer.merkle_leaf_end) else {
        return false;
    };
    let flattened = layer
        .opened_coset_evaluations
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let mut evaluation_offset = 0usize;
    for leaf in leaves {
        if leaf.source
            != (PoseidonCallSource::FriMerkle {
                layer_index: layer.layer_index,
            })
            || leaf.values.len() % 4 != 0
        {
            return false;
        }
        let evaluations_per_leaf = leaf.values.len() / 4;
        let Some(evaluations) =
            flattened.get(evaluation_offset..evaluation_offset + evaluations_per_leaf)
        else {
            return false;
        };
        let expected_values = evaluations
            .iter()
            .flat_map(|evaluation| evaluation.to_m31_array())
            .collect::<Vec<_>>();
        if leaf.values != expected_values {
            return false;
        }
        evaluation_offset += evaluations_per_leaf;
    }
    evaluation_offset == flattened.len()
}

fn folded_queries_feed_next_layer(
    current: &CanonicalFriFoldLayer,
    next: &CanonicalFriFoldLayer,
) -> bool {
    let next_opened = next
        .decommitment_positions
        .iter()
        .copied()
        .zip(next.opened_coset_evaluations.iter().flatten().copied())
        .collect::<HashMap<_, _>>();
    current
        .folded_query_positions
        .iter()
        .copied()
        .zip(current.folded_evaluations.iter().copied())
        .all(|(position, evaluation)| next_opened.get(&position) == Some(&evaluation))
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
        assert_eq!(
            witness.transcript_calls.len(),
            replay.transcript_poseidon_calls.len()
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

        let mut tampered_node_lookup = witness.clone();
        tampered_node_lookup.merkle_node_uses[0].node_index ^= 1;
        assert!(!tampered_node_lookup.is_host_consistent());

        let mut tampered_fri_leaf_binding = witness.clone();
        let fri_leaf = tampered_fri_leaf_binding.fri_fold_layers[0].merkle_leaf_start;
        tampered_fri_leaf_binding.merkle_leaves[fri_leaf].values[0] += BaseField::from(1u32);
        assert!(!tampered_fri_leaf_binding.is_host_consistent());

        let mut tampered_fri_chain = witness.clone();
        tampered_fri_chain.fri_fold_layers[0].folded_evaluations[0] += SecureField::from(1u32);
        assert!(!tampered_fri_chain.is_host_consistent());
    }
}
