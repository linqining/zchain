//! Stwo verifier 的确定性 Merkle 重放辅助。
//!
//! 本模块逐字复现 Stwo 2.3 `MerkleVerifierLifted::verify` 的查询排序、重复查询处理、
//! leaf 构造和压缩 `hash_witness` 消费顺序。生成的步骤将作为后续 verifier AIR 的
//! canonical witness；在 Poseidon252 non-native AIR 完成前，高层递归入口仍保持关闭。

use std::collections::HashSet;

use starknet_ff::FieldElement as FieldElement252;
use stwo::core::fields::m31::BaseField;
use stwo::core::pcs::utils::prepare_preprocessed_query_positions;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::core::ColumnVec;

use super::public_inputs::{RecursivePublicInputs, RecursiveTreeMetadata};

/// 一次 Merkle parent hash 的 canonical 重放步骤。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MerkleReplayStep {
    /// Commitment tree index。
    pub tree_index: usize,
    /// 从 leaf 开始的 layer index。
    pub layer_index: u32,
    /// 当前 parent node 的 index。
    pub parent_index: usize,
    /// 左 child hash。
    pub left: FieldElement252,
    /// 右 child hash。
    pub right: FieldElement252,
    /// `Poseidon252(left, right)`。
    pub parent: FieldElement252,
    /// 若 sibling 来自压缩 witness，则记录被消费的 witness index。
    pub witness_index: Option<usize>,
}

/// 单棵 commitment tree 的完整重放结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MerkleTreeReplay {
    /// Commitment tree index。
    pub tree_index: usize,
    /// 实际用于该 tree 的查询位置。
    pub query_positions: Vec<usize>,
    /// 去重 query 对应的 leaf hashes。
    pub leaves: Vec<(usize, FieldElement252)>,
    /// 按 Stwo verifier 执行顺序排列的 parent hash 步骤。
    pub steps: Vec<MerkleReplayStep>,
    /// 被完整消费的压缩 witness 数量。
    pub consumed_witness: usize,
    /// 计算得到的 root。
    pub computed_root: Option<FieldElement252>,
}

/// Merkle 重放失败。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum MerkleReplayError {
    /// Statement metadata 与 proof tree 数量不一致。
    #[error(
        "tree count mismatch: commitments={commitments}, metadata={metadata}, decommitments={decommitments}, queried_values={queried_values}"
    )]
    TreeCountMismatch {
        commitments: usize,
        metadata: usize,
        decommitments: usize,
        queried_values: usize,
    },
    /// 列 metadata 与 queried values 数量不一致。
    #[error("tree {tree_index} column count mismatch: metadata={metadata}, queried_values={queried_values}")]
    ColumnCountMismatch {
        tree_index: usize,
        metadata: usize,
        queried_values: usize,
    },
    /// 查询位置越界或非单调。
    #[error("query positions are not sorted or exceed tree {tree_index} height {height}")]
    InvalidQueryPositions { tree_index: usize, height: u32 },
    /// 同一 query 的重复值不一致。
    #[error("tree {tree_index} duplicated query {query_position} has inconsistent column values")]
    DuplicateQueryValueMismatch {
        tree_index: usize,
        query_position: usize,
    },
    /// 某列没有为每个 query 提供值。
    #[error("tree {tree_index} column {column_index} has {actual} values, expected {expected}")]
    QueryValueCountMismatch {
        tree_index: usize,
        column_index: usize,
        actual: usize,
        expected: usize,
    },
    /// 列 log size 或 lifting metadata 非法。
    #[error("tree {tree_index} has invalid column/lifting log sizes")]
    InvalidTreeMetadata { tree_index: usize },
    /// 压缩 witness 太短。
    #[error("tree {tree_index} Merkle witness is too short at layer {layer_index}")]
    WitnessTooShort { tree_index: usize, layer_index: u32 },
    /// 压缩 witness 太长。
    #[error("tree {tree_index} Merkle witness has {remaining} unconsumed hashes")]
    WitnessTooLong { tree_index: usize, remaining: usize },
    /// Root 不匹配。
    #[error("tree {tree_index} root mismatch")]
    RootMismatch { tree_index: usize },
    /// 非空 tree 最终没有归约为唯一 root。
    #[error("tree {tree_index} did not reduce to exactly one root")]
    InvalidFinalLayer { tree_index: usize },
}

/// 重放 L1 proof 的全部 PCS commitment trees。
pub(crate) fn replay_all_l1_merkle_trees(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Result<Vec<MerkleTreeReplay>, MerkleReplayError> {
    let commitments = &l1_proof.0.commitments;
    let decommitments = &l1_proof.0.decommitments;
    let queried_values = &l1_proof.0.queried_values;
    let metadata = &public_inputs.l1_tree_metadata;

    if commitments.len() != metadata.len()
        || commitments.len() != decommitments.len()
        || commitments.len() != queried_values.len()
        || public_inputs.l1_commitments.as_slice() != commitments.as_slice()
    {
        return Err(MerkleReplayError::TreeCountMismatch {
            commitments: commitments.len(),
            metadata: metadata.len(),
            decommitments: decommitments.len(),
            queried_values: queried_values.len(),
        });
    }

    let lifting_log_size = metadata
        .last()
        .and_then(|tree| tree.tree_height(public_inputs.config))
        .ok_or(MerkleReplayError::InvalidTreeMetadata {
            tree_index: metadata.len().saturating_sub(1),
        })?;
    let preprocessed_height = metadata
        .first()
        .and_then(|tree| tree.tree_height(public_inputs.config))
        .ok_or(MerkleReplayError::InvalidTreeMetadata { tree_index: 0 })?;
    let preprocessed_query_positions = prepare_preprocessed_query_positions(
        &public_inputs.query_positions,
        lifting_log_size,
        preprocessed_height,
    );

    commitments
        .iter()
        .zip(metadata.iter())
        .zip(decommitments.iter())
        .zip(queried_values.iter())
        .enumerate()
        .map(
            |(tree_index, (((root, tree_metadata), decommitment), values))| {
                let query_positions = if tree_index == 0 {
                    preprocessed_query_positions.as_slice()
                } else {
                    public_inputs.query_positions.as_slice()
                };
                replay_merkle_tree(
                    tree_index,
                    *root,
                    tree_metadata,
                    public_inputs.config,
                    query_positions,
                    values,
                    &decommitment.hash_witness,
                )
            },
        )
        .collect()
}

fn replay_merkle_tree(
    tree_index: usize,
    root: FieldElement252,
    metadata: &RecursiveTreeMetadata,
    config: PcsConfig,
    query_positions: &[usize],
    queried_values: &ColumnVec<Vec<BaseField>>,
    hash_witness: &[FieldElement252],
) -> Result<MerkleTreeReplay, MerkleReplayError> {
    let extended_column_log_sizes = metadata
        .extended_column_log_sizes(config)
        .ok_or(MerkleReplayError::InvalidTreeMetadata { tree_index })?;
    let height = metadata
        .tree_height(config)
        .ok_or(MerkleReplayError::InvalidTreeMetadata { tree_index })?;

    replay_merkle_tree_with_sizes(
        tree_index,
        root,
        &extended_column_log_sizes,
        height,
        query_positions,
        queried_values,
        hash_witness,
    )
}

pub(crate) fn replay_merkle_tree_with_sizes(
    tree_index: usize,
    root: FieldElement252,
    column_log_sizes: &[u32],
    height: u32,
    query_positions: &[usize],
    queried_values: &ColumnVec<Vec<BaseField>>,
    hash_witness: &[FieldElement252],
) -> Result<MerkleTreeReplay, MerkleReplayError> {
    if queried_values.len() != column_log_sizes.len() {
        return Err(MerkleReplayError::ColumnCountMismatch {
            tree_index,
            metadata: column_log_sizes.len(),
            queried_values: queried_values.len(),
        });
    }
    for (column_index, values) in queried_values.iter().enumerate() {
        if values.len() != query_positions.len() {
            return Err(MerkleReplayError::QueryValueCountMismatch {
                tree_index,
                column_index,
                actual: values.len(),
                expected: query_positions.len(),
            });
        }
    }

    if height == 0 {
        if !hash_witness.is_empty() {
            return Err(MerkleReplayError::WitnessTooLong {
                tree_index,
                remaining: hash_witness.len(),
            });
        }
        return Ok(MerkleTreeReplay {
            tree_index,
            query_positions: query_positions.to_vec(),
            leaves: Vec::new(),
            steps: Vec::new(),
            consumed_witness: 0,
            computed_root: None,
        });
    }

    let domain_size = 1usize
        .checked_shl(height)
        .ok_or(MerkleReplayError::InvalidQueryPositions { tree_index, height })?;
    if query_positions.windows(2).any(|pair| pair[0] > pair[1])
        || query_positions
            .iter()
            .any(|position| *position >= domain_size)
    {
        return Err(MerkleReplayError::InvalidQueryPositions { tree_index, height });
    }

    for (query_index, pair) in query_positions.windows(2).enumerate() {
        if pair[0] == pair[1]
            && queried_values
                .iter()
                .any(|column| column[query_index] != column[query_index + 1])
        {
            return Err(MerkleReplayError::DuplicateQueryValueMismatch {
                tree_index,
                query_position: pair[0],
            });
        }
    }

    let mut column_order: Vec<usize> = (0..queried_values.len()).collect();
    column_order.sort_by_key(|index| column_log_sizes[*index]);

    let mut unique_query_indices = Vec::new();
    let mut seen = HashSet::new();
    for (query_index, query_position) in query_positions.iter().copied().enumerate() {
        if seen.insert(query_position) {
            unique_query_indices.push(query_index);
        }
    }

    let mut leaves = Vec::with_capacity(unique_query_indices.len());
    for query_index in unique_query_indices {
        let mut hasher = Poseidon252MerkleHasher::default();
        let row: Vec<BaseField> = column_order
            .iter()
            .map(|column_index| queried_values[*column_index][query_index])
            .collect();
        hasher.update_leaf(&row);
        leaves.push((query_positions[query_index], hasher.finalize()));
    }

    let mut previous_layer = leaves.clone();
    let mut witness_index = 0usize;
    let mut steps = Vec::new();
    for layer_index in 0..height {
        let mut current_layer = Vec::new();
        let mut node_index = 0usize;
        while node_index < previous_layer.len() {
            let (index, hash) = previous_layer[node_index];
            let has_known_sibling = node_index + 1 < previous_layer.len()
                && index ^ 1 == previous_layer[node_index + 1].0;
            let (left, right, consumed_index) = if has_known_sibling {
                let sibling = previous_layer[node_index + 1].1;
                node_index += 2;
                (hash, sibling, None)
            } else {
                let sibling =
                    *hash_witness
                        .get(witness_index)
                        .ok_or(MerkleReplayError::WitnessTooShort {
                            tree_index,
                            layer_index,
                        })?;
                let consumed_index = witness_index;
                witness_index += 1;
                node_index += 1;
                if index & 1 == 0 {
                    (hash, sibling, Some(consumed_index))
                } else {
                    (sibling, hash, Some(consumed_index))
                }
            };
            let parent = Poseidon252MerkleHasher::hash_children((left, right));
            let parent_index = index >> 1;
            steps.push(MerkleReplayStep {
                tree_index,
                layer_index,
                parent_index,
                left,
                right,
                parent,
                witness_index: consumed_index,
            });
            current_layer.push((parent_index, parent));
        }
        previous_layer = current_layer;
    }

    if witness_index != hash_witness.len() {
        return Err(MerkleReplayError::WitnessTooLong {
            tree_index,
            remaining: hash_witness.len() - witness_index,
        });
    }
    let [(_, computed_root)] = previous_layer.as_slice() else {
        return Err(MerkleReplayError::InvalidFinalLayer { tree_index });
    };
    if *computed_root != root {
        return Err(MerkleReplayError::RootMismatch { tree_index });
    }

    Ok(MerkleTreeReplay {
        tree_index,
        query_positions: query_positions.to_vec(),
        leaves,
        steps,
        consumed_witness: witness_index,
        computed_root: Some(*computed_root),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::trace_gen::{
        extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
        extract_query_positions_from_l1,
    };
    use crate::stwo_backend::trace_native::TraceBuilder;
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};

    const TEST_LOG_SIZE: u32 = 10;
    const TEST_OODS_POINT: CirclePoint<SecureField> = CirclePoint {
        x: SecureField::from_u32_unchecked(1, 0, 0, 0),
        y: SecureField::from_u32_unchecked(0, 1, 0, 0),
    };

    fn make_l1_proof() -> StarkProof<Poseidon252MerkleHasher> {
        let mut builder = TraceBuilder::new(TEST_LOG_SIZE);
        builder.fill_padding_to_full();
        prove_cpu_trace(&builder.finalize()).expect("L1 proof generation should succeed")
    }

    fn make_public_inputs(l1_proof: &StarkProof<Poseidon252MerkleHasher>) -> RecursivePublicInputs {
        let config = PcsConfig::default();
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let composition_oods_eval =
            extract_composition_oods_eval_from_l1(l1_proof, TEST_OODS_POINT, TEST_LOG_SIZE)
                .expect("composition OODS extraction should succeed");
        let (fri_query_x, fri_query_eval) =
            extract_fri_query_from_l1(l1_proof, config, TEST_LOG_SIZE, &last_layer_poly)
                .expect("FRI query extraction should succeed");
        let query_positions =
            extract_query_positions_from_l1(l1_proof, config, TEST_LOG_SIZE, &last_layer_poly)
                .expect("query extraction should succeed");
        let tree_metadata = vec![
            RecursiveTreeMetadata::new(Vec::new()),
            RecursiveTreeMetadata::new(vec![TEST_LOG_SIZE; NUM_COLUMNS]),
            RecursiveTreeMetadata::new(vec![TEST_LOG_SIZE; 2 * SECURE_EXTENSION_DEGREE]),
        ];
        let fri_inner_layer_commitments = l1_proof
            .0
            .fri_proof
            .inner_layers
            .iter()
            .map(|layer| layer.commitment)
            .collect();

        RecursivePublicInputs::new(
            l1_proof.0.commitments.iter().copied().collect(),
            TEST_OODS_POINT,
            composition_oods_eval,
            l1_proof.0.fri_proof.first_layer.commitment,
            last_layer_poly,
            TEST_LOG_SIZE,
            config,
            query_positions,
            TEST_LOG_SIZE,
            fri_query_x,
            fri_query_eval,
        )
        .with_verifier_metadata(tree_metadata, fri_inner_layer_commitments)
    }

    #[test]
    fn replays_all_real_l1_merkle_trees() {
        let l1_proof = make_l1_proof();
        let inputs = make_public_inputs(&l1_proof);

        let replay = replay_all_l1_merkle_trees(&l1_proof, &inputs)
            .expect("canonical replay should match Stwo verifier");

        assert_eq!(replay.len(), l1_proof.0.commitments.len());
        assert_eq!(replay[0].computed_root, None);
        for tree in replay.iter().skip(1) {
            assert_eq!(
                tree.computed_root,
                Some(inputs.l1_commitments[tree.tree_index])
            );
            assert_eq!(
                tree.consumed_witness,
                l1_proof.0.decommitments[tree.tree_index].hash_witness.len()
            );
            assert!(!tree.steps.is_empty());
        }
    }

    #[test]
    fn rejects_tampered_compressed_witness() {
        let mut l1_proof = make_l1_proof();
        let inputs = make_public_inputs(&l1_proof);
        let witness = l1_proof.0.decommitments[1]
            .hash_witness
            .first_mut()
            .expect("non-empty trace tree witness");
        *witness += FieldElement252::ONE;

        assert!(matches!(
            replay_all_l1_merkle_trees(&l1_proof, &inputs),
            Err(MerkleReplayError::RootMismatch { tree_index: 1 })
        ));
    }

    #[test]
    fn rejects_missing_column_metadata() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_public_inputs(&l1_proof);
        inputs.l1_tree_metadata[1].column_log_sizes.pop();

        assert!(matches!(
            replay_all_l1_merkle_trees(&l1_proof, &inputs),
            Err(MerkleReplayError::ColumnCountMismatch { tree_index: 1, .. })
        ));
    }

    #[test]
    fn rejects_tampered_queried_value() {
        let mut l1_proof = make_l1_proof();
        let inputs = make_public_inputs(&l1_proof);
        l1_proof.0.queried_values[1][0][0] += BaseField::from(1u32);

        assert!(matches!(
            replay_all_l1_merkle_trees(&l1_proof, &inputs),
            Err(MerkleReplayError::RootMismatch { tree_index: 1 })
        ));
    }
}
