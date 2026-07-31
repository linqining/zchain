//! Stwo 2.3 FRI decommitment 的确定性重放。
//!
//! 本模块复现 first layer / inner layers 的 `fri_witness` 消费、packed-leaf Merkle
//! opening、circle/line folding 和 last-layer polynomial 检查。它提供后续 FRI verifier
//! AIR 的 canonical witness 布局；当前高层递归入口仍等待 transcript/Poseidon252 AIR。

use stwo::core::ColumnVec;
use stwo::core::channel::{Channel, MerkleChannel, Poseidon252Channel};
use stwo::core::circle::{CirclePoint, Coset};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::fri::{fold_circle_into_line, fold_coset};
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::proof::StarkProof;
use stwo::core::queries::{Queries, draw_queries};
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::vcs_lifted::verifier::{LOG_PACKED_LEAF_SIZE, PACKED_LEAF_SIZE};

use super::poseidon252_replay::{Poseidon252PermutationCall, RecordingPoseidon252Channel};
use super::stwo_replay::{MerkleReplayError, MerkleTreeReplay, replay_merkle_tree_with_sizes};

/// 从 L1 transcript 重放得到的 FRI challenges。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FriReplayChallenges {
    /// First-layer folding challenge。
    pub first_layer_alpha: SecureField,
    /// 各 inner layer folding challenge。
    pub inner_layer_alphas: Vec<SecureField>,
    /// FRI first-layer query positions。
    pub query_positions: Vec<usize>,
    /// Full fixed-verifier transcript permutation schedule, including PoW and query draws.
    pub transcript_poseidon_calls: Vec<Poseidon252PermutationCall>,
}

/// 单个 FRI committed layer 的重放结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FriLayerReplay {
    /// 0 表示 first layer，后续为 inner layer index + 1。
    pub layer_index: usize,
    /// 此层一次折叠的 log step。
    pub fold_step: u32,
    /// 补齐 folding coset 后的 decommitment positions。
    pub decommitment_positions: Vec<usize>,
    /// Exact coset evaluations consumed by this layer's fold, before folding.
    pub opened_coset_evaluations: Vec<Vec<SecureField>>,
    /// Natural-domain initial index corresponding to each opened coset.
    pub coset_domain_initial_indexes: Vec<usize>,
    /// 此层 Merkle opening 的完整重放。
    pub merkle: MerkleTreeReplay,
    /// 折叠后传给下一层的 query positions。
    pub folded_query_positions: Vec<usize>,
    /// 折叠后传给下一层的 evaluations。
    pub folded_evaluations: Vec<SecureField>,
}

/// 完整 FRI decommitment 重放结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FriReplay {
    /// First + inner committed layers。
    pub layers: Vec<FriLayerReplay>,
    /// Last layer 上的 query positions。
    pub last_layer_query_positions: Vec<usize>,
    /// 从前一层折叠得到并与 last-layer polynomial 比较的 evaluations。
    pub last_layer_query_evaluations: Vec<SecureField>,
}

/// FRI 重放失败。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum FriReplayError {
    /// Query evaluation 数量不匹配。
    #[error("FRI layer {layer_index} has {actual} query evaluations, expected {expected}")]
    QueryEvaluationCountMismatch {
        layer_index: usize,
        actual: usize,
        expected: usize,
    },
    /// `fri_witness` 太短。
    #[error("FRI layer {layer_index} evaluation witness is too short")]
    EvaluationWitnessTooShort { layer_index: usize },
    /// `fri_witness` 太长。
    #[error("FRI layer {layer_index} has {remaining} unconsumed evaluation witnesses")]
    EvaluationWitnessTooLong {
        layer_index: usize,
        remaining: usize,
    },
    /// FRI layer 数量或 fold step 非法。
    #[error("invalid FRI layer structure")]
    InvalidLayerStructure,
    /// FRI Merkle opening 失败。
    #[error("FRI layer {layer_index} Merkle replay failed: {source}")]
    Merkle {
        layer_index: usize,
        source: MerkleReplayError,
    },
    /// Last-layer polynomial 不匹配。
    #[error("FRI last-layer evaluation mismatch at query {query_position}")]
    LastLayerEvaluationMismatch { query_position: usize },
}

/// 针对当前单组件 transcript 顺序提取全部 FRI folding challenges 与 queries。
///
/// 该函数与现有 recursive PoC 一致，假定 composition commitment 之前没有 interaction
/// challenge/claimed-sum 消息。真实 Texas 多组件 proof 必须改用 method-specific transcript
/// schema，不能复用此函数。
pub(crate) fn extract_simple_fri_replay_challenges(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
    max_log_degree_bound: u32,
) -> Option<FriReplayChallenges> {
    let commitments = &l1_proof.0.commitments;
    let (composition_commitment, trace_commitments) = commitments.split_last()?;
    if trace_commitments.len() < 2 {
        return None;
    }

    let mut channel = RecordingPoseidon252Channel::default();
    for commitment in trace_commitments {
        channel.mix_root(*commitment);
    }
    let _composition_random_coeff = channel.draw_secure_felt();
    channel.mix_root(*composition_commitment);
    let _oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
    channel.mix_felts(&l1_proof.0.sampled_values.clone().flatten_cols());
    let _fri_quotient_random_coeff = channel.draw_secure_felt();

    let fri_proof = &l1_proof.0.fri_proof;
    channel.mix_root(fri_proof.first_layer.commitment);
    let first_layer_alpha = channel.draw_secure_felt();
    let mut inner_layer_alphas = Vec::with_capacity(fri_proof.inner_layers.len());
    for layer in &fri_proof.inner_layers {
        channel.mix_root(layer.commitment);
        inner_layer_alphas.push(channel.draw_secure_felt());
    }
    channel.mix_felts(&fri_proof.last_layer_poly[..]);

    if !channel.verify_pow_nonce(config.pow_bits, l1_proof.0.proof_of_work) {
        return None;
    }
    channel.mix_u64(l1_proof.0.proof_of_work);
    let first_layer_log_size =
        CanonicCoset::new(max_log_degree_bound.checked_add(config.fri_config.log_blowup_factor)?)
            .circle_domain()
            .log_size();
    let raw_query_positions = draw_queries(
        &mut channel,
        first_layer_log_size,
        config.fri_config.n_queries,
    );
    let query_positions = Queries::new(&raw_query_positions, first_layer_log_size).positions;

    Some(FriReplayChallenges {
        first_layer_alpha,
        inner_layer_alphas,
        query_positions,
        transcript_poseidon_calls: channel.calls(),
    })
}

/// 重放完整 FRI decommitment。
pub(crate) fn replay_fri_decommitment(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
    max_log_degree_bound: u32,
    challenges: &FriReplayChallenges,
    first_layer_query_evaluations: Vec<SecureField>,
) -> Result<FriReplay, FriReplayError> {
    let fri_config = config.fri_config;
    if challenges.inner_layer_alphas.len() != l1_proof.0.fri_proof.inner_layers.len() {
        return Err(FriReplayError::InvalidLayerStructure);
    }

    let first_layer_domain =
        CanonicCoset::new(max_log_degree_bound + fri_config.log_blowup_factor).circle_domain();
    let queries = Queries::new(&challenges.query_positions, first_layer_domain.log_size());
    let first_proof = &l1_proof.0.fri_proof.first_layer;
    let (first_positions, first_sparse) = rebuild_sparse_evaluation(
        0,
        &queries,
        &first_layer_query_evaluations,
        &first_proof.fri_witness,
        fri_config.fold_step,
    )?;
    let first_pack_leaves =
        first_layer_domain.log_size() >= LOG_PACKED_LEAF_SIZE && fri_config.fold_step > 1;
    let first_leaf_log_size = if first_pack_leaves {
        LOG_PACKED_LEAF_SIZE
    } else {
        0
    };
    let (first_merkle_positions, first_merkle_values) = build_merkle_inputs(
        &first_positions,
        first_sparse.subset_evaluations.iter().flatten().copied(),
        first_leaf_log_size,
    );
    let first_merkle_height = first_layer_domain.log_size() - first_leaf_log_size;
    let first_merkle = replay_merkle_tree_with_sizes(
        0,
        first_proof.commitment,
        &vec![first_merkle_height; SECURE_EXTENSION_DEGREE * (1 << first_leaf_log_size)],
        first_merkle_height,
        &first_merkle_positions,
        &first_merkle_values,
        &first_proof.decommitment.hash_witness,
    )
    .map_err(|source| FriReplayError::Merkle {
        layer_index: 0,
        source,
    })?;

    let first_opened_coset_evaluations = first_sparse.subset_evaluations.clone();
    let first_coset_domain_initial_indexes = first_sparse.subset_domain_initial_indexes.clone();
    let mut layer_queries = queries.fold(fri_config.fold_step);
    let mut layer_evaluations = first_sparse.fold_circle(
        challenges.first_layer_alpha,
        first_layer_domain,
        fri_config.fold_step,
    );
    let mut layers = vec![FriLayerReplay {
        layer_index: 0,
        fold_step: fri_config.fold_step,
        decommitment_positions: first_positions,
        opened_coset_evaluations: first_opened_coset_evaluations,
        coset_domain_initial_indexes: first_coset_domain_initial_indexes,
        merkle: first_merkle,
        folded_query_positions: layer_queries.positions.clone(),
        folded_evaluations: layer_evaluations.clone(),
    }];

    let mut layer_log_degree = max_log_degree_bound
        .checked_sub(fri_config.fold_step)
        .ok_or(FriReplayError::InvalidLayerStructure)?;
    let mut layer_domain = LineDomain::new(Coset::half_odds(
        layer_log_degree + fri_config.log_blowup_factor,
    ));
    let n_inner_layers = l1_proof.0.fri_proof.inner_layers.len();
    for (inner_index, ((proof, alpha), is_last)) in l1_proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .zip(&challenges.inner_layer_alphas)
        .zip((0..n_inner_layers).map(|index| index + 1 == n_inner_layers))
        .enumerate()
    {
        let fold_step = if is_last {
            let remaining = layer_log_degree
                .checked_sub(fri_config.log_last_layer_degree_bound)
                .ok_or(FriReplayError::InvalidLayerStructure)?;
            if !(1..=fri_config.fold_step).contains(&remaining) {
                return Err(FriReplayError::InvalidLayerStructure);
            }
            remaining
        } else {
            fri_config.fold_step
        };
        let layer_index = inner_index + 1;
        let (positions, sparse) = rebuild_sparse_evaluation(
            layer_index,
            &layer_queries,
            &layer_evaluations,
            &proof.fri_witness,
            fold_step,
        )?;
        let pack_leaves = layer_domain.log_size() >= LOG_PACKED_LEAF_SIZE && fold_step > 1;
        let leaf_log_size = if pack_leaves { LOG_PACKED_LEAF_SIZE } else { 0 };
        let (merkle_positions, merkle_values) = build_merkle_inputs(
            &positions,
            sparse.subset_evaluations.iter().flatten().copied(),
            leaf_log_size,
        );
        let merkle_height = layer_domain.log_size() - leaf_log_size;
        let merkle = replay_merkle_tree_with_sizes(
            layer_index,
            proof.commitment,
            &vec![merkle_height; SECURE_EXTENSION_DEGREE * (1 << leaf_log_size)],
            merkle_height,
            &merkle_positions,
            &merkle_values,
            &proof.decommitment.hash_witness,
        )
        .map_err(|source| FriReplayError::Merkle {
            layer_index,
            source,
        })?;

        let opened_coset_evaluations = sparse.subset_evaluations.clone();
        let coset_domain_initial_indexes = sparse.subset_domain_initial_indexes.clone();
        let folded_queries = layer_queries.fold(fold_step);
        let folded_evaluations = sparse.fold_line(*alpha, layer_domain, fold_step);
        layers.push(FriLayerReplay {
            layer_index,
            fold_step,
            decommitment_positions: positions,
            opened_coset_evaluations,
            coset_domain_initial_indexes,
            merkle,
            folded_query_positions: folded_queries.positions.clone(),
            folded_evaluations: folded_evaluations.clone(),
        });
        layer_queries = folded_queries;
        layer_evaluations = folded_evaluations;
        layer_log_degree = layer_log_degree
            .checked_sub(fold_step)
            .ok_or(FriReplayError::InvalidLayerStructure)?;
        layer_domain = layer_domain.repeated_double(fold_step);
    }

    if layer_log_degree != fri_config.log_last_layer_degree_bound
        || l1_proof.0.fri_proof.last_layer_poly.len()
            > (1usize << fri_config.log_last_layer_degree_bound)
    {
        return Err(FriReplayError::InvalidLayerStructure);
    }
    verify_last_layer(
        layer_domain,
        &l1_proof.0.fri_proof.last_layer_poly,
        &layer_queries,
        &layer_evaluations,
    )?;

    Ok(FriReplay {
        layers,
        last_layer_query_positions: layer_queries.positions,
        last_layer_query_evaluations: layer_evaluations,
    })
}

#[derive(Debug, Clone)]
struct SparseEvaluationReplay {
    subset_evaluations: Vec<Vec<SecureField>>,
    subset_domain_initial_indexes: Vec<usize>,
}

impl SparseEvaluationReplay {
    fn fold_circle(
        self,
        alpha: SecureField,
        source_domain: stwo::core::poly::circle::CircleDomain,
        fold_step: u32,
    ) -> Vec<SecureField> {
        self.subset_evaluations
            .into_iter()
            .zip(self.subset_domain_initial_indexes)
            .map(|(evaluations, domain_initial_index)| {
                let fold_domain_initial = source_domain.index_at(domain_initial_index);
                let circle_domain = stwo::core::poly::circle::CircleDomain::new(Coset::new(
                    fold_domain_initial,
                    fold_step - 1,
                ));
                let line_evaluations = fold_circle_into_line(&evaluations, circle_domain, alpha);
                if fold_step == 1 {
                    line_evaluations[0]
                } else {
                    let line_domain =
                        LineDomain::new(Coset::new(fold_domain_initial, fold_step - 1));
                    fold_coset(line_evaluations, line_domain, alpha * alpha)
                }
            })
            .collect()
    }

    fn fold_line(
        self,
        alpha: SecureField,
        source_domain: LineDomain,
        fold_step: u32,
    ) -> Vec<SecureField> {
        self.subset_evaluations
            .into_iter()
            .zip(self.subset_domain_initial_indexes)
            .map(|(evaluations, domain_initial_index)| {
                let fold_domain_initial = source_domain.coset().index_at(domain_initial_index);
                let fold_domain = LineDomain::new(Coset::new(fold_domain_initial, fold_step));
                fold_coset(evaluations, fold_domain, alpha)
            })
            .collect()
    }
}

fn rebuild_sparse_evaluation(
    layer_index: usize,
    queries: &Queries,
    query_evaluations: &[SecureField],
    witness_evaluations: &[SecureField],
    fold_step: u32,
) -> Result<(Vec<usize>, SparseEvaluationReplay), FriReplayError> {
    if query_evaluations.len() != queries.len() {
        return Err(FriReplayError::QueryEvaluationCountMismatch {
            layer_index,
            actual: query_evaluations.len(),
            expected: queries.len(),
        });
    }

    let mut witness_index = 0usize;
    let mut query_index = 0usize;
    let mut decommitment_positions = Vec::new();
    let mut subset_evaluations = Vec::new();
    let mut subset_domain_initial_indexes = Vec::new();
    while query_index < queries.len() {
        let subset_start = (queries[query_index] >> fold_step) << fold_step;
        let subset_end = subset_start + (1usize << fold_step);
        let mut evaluations = Vec::with_capacity(1usize << fold_step);
        for position in subset_start..subset_end {
            decommitment_positions.push(position);
            if query_index < queries.len() && queries[query_index] == position {
                evaluations.push(query_evaluations[query_index]);
                query_index += 1;
            } else {
                let value = *witness_evaluations
                    .get(witness_index)
                    .ok_or(FriReplayError::EvaluationWitnessTooShort { layer_index })?;
                witness_index += 1;
                evaluations.push(value);
            }
        }
        subset_evaluations.push(evaluations);
        subset_domain_initial_indexes
            .push(bit_reverse_index(subset_start, queries.log_domain_size));
    }
    if witness_index != witness_evaluations.len() {
        return Err(FriReplayError::EvaluationWitnessTooLong {
            layer_index,
            remaining: witness_evaluations.len() - witness_index,
        });
    }

    Ok((
        decommitment_positions,
        SparseEvaluationReplay {
            subset_evaluations,
            subset_domain_initial_indexes,
        },
    ))
}

fn build_merkle_inputs(
    decommitment_positions: &[usize],
    mut evaluations: impl Iterator<Item = SecureField>,
    leaf_log_size: u32,
) -> (Vec<usize>, ColumnVec<Vec<BaseField>>) {
    let leaf_size = 1usize << leaf_log_size;
    let mut merkle_positions = Vec::new();
    for position in decommitment_positions {
        let merkle_position = position >> leaf_log_size;
        if merkle_positions.last() != Some(&merkle_position) {
            merkle_positions.push(merkle_position);
        }
    }
    let mut merkle_values =
        vec![Vec::with_capacity(merkle_positions.len()); SECURE_EXTENSION_DEGREE * leaf_size];
    for _ in &merkle_positions {
        for offset in 0..leaf_size {
            let coordinates = evaluations
                .next()
                .expect("decommitment positions and evaluations have equal length")
                .to_m31_array();
            for (coordinate_index, value) in coordinates.into_iter().enumerate() {
                merkle_values[coordinate_index + offset * SECURE_EXTENSION_DEGREE].push(value);
            }
        }
    }
    debug_assert!(evaluations.next().is_none());
    debug_assert_eq!(
        leaf_size,
        if leaf_log_size == 0 {
            1
        } else {
            PACKED_LEAF_SIZE
        }
    );
    (merkle_positions, merkle_values)
}

fn verify_last_layer(
    domain: LineDomain,
    polynomial: &LinePoly,
    queries: &Queries,
    query_evaluations: &[SecureField],
) -> Result<(), FriReplayError> {
    for (&query_position, query_evaluation) in queries.iter().zip(query_evaluations) {
        let x = domain.at(bit_reverse_index(query_position, domain.log_size()));
        if *query_evaluation != polynomial.eval_at_point(x.into()) {
            return Err(FriReplayError::LastLayerEvaluationMismatch { query_position });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use super::*;
    use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
    use crate::stwo_backend::cpu_air::CpuAir;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::recursive::trace_gen::extract_query_positions_from_l1;
    use crate::stwo_backend::trace_native::TraceBuilder;
    use stwo::core::air::{Component, Components};
    use stwo::core::pcs::quotients::{PointSample, fri_answers};
    use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

    const TEST_LOG_SIZE: u32 = 10;

    fn make_l1_proof() -> StarkProof<Poseidon252MerkleHasher> {
        let mut builder = TraceBuilder::new(TEST_LOG_SIZE);
        builder.fill_padding_to_full();
        prove_cpu_trace(&builder.finalize()).expect("L1 proof generation should succeed")
    }

    fn make_component() -> FrameworkComponent<CpuAir> {
        let mut allocator = TraceLocationAllocator::default();
        FrameworkComponent::new(
            &mut allocator,
            CpuAir::new(TEST_LOG_SIZE),
            SecureField::from(0u32),
        )
    }

    fn compute_first_layer_answers(
        l1_proof: &StarkProof<Poseidon252MerkleHasher>,
        query_positions: &[usize],
    ) -> Vec<SecureField> {
        let config = PcsConfig::default();
        let component = make_component();
        let components = Components {
            components: vec![&component as &dyn Component],
            n_preprocessed_columns: 0,
        };
        let mut channel = Poseidon252Channel::default();
        let (composition_commitment, trace_commitments) = l1_proof
            .0
            .commitments
            .split_last()
            .expect("proof commitments");
        for commitment in trace_commitments {
            Poseidon252MerkleChannel::mix_root(&mut channel, *commitment);
        }
        let _composition_random_coeff = channel.draw_secure_felt();
        Poseidon252MerkleChannel::mix_root(&mut channel, *composition_commitment);
        let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);
        let mut sample_points = components.mask_points(oods_point, TEST_LOG_SIZE, false);
        sample_points.push(vec![vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);
        channel.mix_felts(&l1_proof.0.sampled_values.clone().flatten_cols());
        let quotient_random_coeff = channel.draw_secure_felt();

        let mut column_log_sizes = components.column_log_sizes();
        assert_eq!(column_log_sizes[1].len(), NUM_COLUMNS);
        column_log_sizes.push(vec![TEST_LOG_SIZE; 2 * SECURE_EXTENSION_DEGREE]);
        let samples = sample_points
            .zip_cols(l1_proof.0.sampled_values.clone())
            .map_cols(|(points, values)| {
                zip(points, values)
                    .map(|(point, value)| PointSample { point, value })
                    .collect()
            });
        let lifting_log_size = TEST_LOG_SIZE + config.fri_config.log_blowup_factor;
        fri_answers(
            column_log_sizes,
            samples,
            quotient_random_coeff,
            query_positions,
            l1_proof.0.queried_values.clone(),
            lifting_log_size,
        )
        .expect("FRI quotient answers should be computable")
    }

    #[test]
    fn replays_complete_real_fri_decommitment() {
        let l1_proof = make_l1_proof();
        let config = PcsConfig::default();
        let challenges = extract_simple_fri_replay_challenges(&l1_proof, config, TEST_LOG_SIZE)
            .expect("FRI challenges should replay");
        let expected_queries = extract_query_positions_from_l1(
            &l1_proof,
            config,
            TEST_LOG_SIZE,
            &l1_proof.0.fri_proof.last_layer_poly,
        )
        .expect("existing transcript replay should succeed");
        assert_eq!(challenges.query_positions, expected_queries);
        let first_layer_answers =
            compute_first_layer_answers(&l1_proof, &challenges.query_positions);

        let replay = replay_fri_decommitment(
            &l1_proof,
            config,
            TEST_LOG_SIZE,
            &challenges,
            first_layer_answers,
        )
        .expect("complete FRI replay should match Stwo verifier");

        assert_eq!(
            replay.layers.len(),
            1 + l1_proof.0.fri_proof.inner_layers.len()
        );
        assert!(!replay.last_layer_query_positions.is_empty());
        assert_eq!(
            replay.last_layer_query_positions.len(),
            replay.last_layer_query_evaluations.len()
        );
    }

    #[test]
    fn rejects_tampered_fri_evaluation_witness() {
        let mut l1_proof = make_l1_proof();
        let config = PcsConfig::default();
        let challenges =
            extract_simple_fri_replay_challenges(&l1_proof, config, TEST_LOG_SIZE).unwrap();
        let first_layer_answers =
            compute_first_layer_answers(&l1_proof, &challenges.query_positions);
        let witness = l1_proof.0.fri_proof.first_layer.fri_witness.first_mut();
        let Some(witness) = witness else {
            panic!("default FRI proof should contain first-layer evaluation witness");
        };
        *witness += SecureField::from(1u32);

        assert!(matches!(
            replay_fri_decommitment(
                &l1_proof,
                config,
                TEST_LOG_SIZE,
                &challenges,
                first_layer_answers,
            ),
            Err(FriReplayError::Merkle { layer_index: 0, .. })
                | Err(FriReplayError::LastLayerEvaluationMismatch { .. })
        ));
    }

    #[test]
    fn rejects_tampered_last_layer_polynomial() {
        let mut l1_proof = make_l1_proof();
        let config = PcsConfig::default();
        let challenges =
            extract_simple_fri_replay_challenges(&l1_proof, config, TEST_LOG_SIZE).unwrap();
        let first_layer_answers =
            compute_first_layer_answers(&l1_proof, &challenges.query_positions);
        let mut coefficients = l1_proof
            .0
            .fri_proof
            .last_layer_poly
            .clone()
            .into_ordered_coefficients();
        coefficients[0] += SecureField::from(1u32);
        l1_proof.0.fri_proof.last_layer_poly = LinePoly::new(coefficients);

        assert!(matches!(
            replay_fri_decommitment(
                &l1_proof,
                config,
                TEST_LOG_SIZE,
                &challenges,
                first_layer_answers,
            ),
            Err(FriReplayError::LastLayerEvaluationMismatch { .. })
        ));
    }
}
