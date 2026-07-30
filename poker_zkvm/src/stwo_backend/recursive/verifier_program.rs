//! 固定的 L1 verifier 程序与 canonical host replay。
//!
//! `StarkProof` 不携带可信的 component layout、interaction transcript 或 mask points。
//! 本模块只接受代码内固定的 `CpuV1` schema，并逐步重放 Stwo 2.3 verifier：commitment
//! transcript、composition OODS、全部 PCS trees 和完整 FRI decommitment。

use std::iter::zip;

use stwo::core::air::{Component, Components};
use stwo::core::channel::{Channel, MerkleChannel, Poseidon252Channel};
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::{SecureField, SECURE_EXTENSION_DEGREE};
use stwo::core::pcs::quotients::{fri_answers, PointSample};
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
use crate::stwo_backend::cpu_air::CpuAir;

use super::fri_replay::{
    extract_simple_fri_replay_challenges, replay_fri_decommitment, FriReplay, FriReplayChallenges,
    FriReplayError,
};
use super::public_inputs::{
    RecursivePublicInputs, RecursiveTreeMetadata, RecursiveVerifierProgram,
};
use super::stwo_replay::{replay_all_l1_merkle_trees, MerkleReplayError, MerkleTreeReplay};
use super::trace_gen::extract_composition_oods_eval_from_l1;

/// 固定 CPU verifier 的完整 canonical replay 产物。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CpuVerifierReplay {
    pub composition_random_coeff: SecureField,
    pub oods_point: CirclePoint<SecureField>,
    pub composition_oods_eval: SecureField,
    pub fri_quotient_random_coeff: SecureField,
    pub tree_metadata: Vec<RecursiveTreeMetadata>,
    pub fri_challenges: FriReplayChallenges,
    pub first_layer_answers: Vec<SecureField>,
    pub merkle_trees: Vec<MerkleTreeReplay>,
    pub fri: FriReplay,
}

/// 固定 verifier replay 失败。
#[derive(Debug, thiserror::Error)]
pub enum VerifierProgramError {
    /// Statement selected a verifier program not implemented by this build.
    #[error("unsupported recursive verifier program")]
    UnsupportedProgram,
    /// `CpuV1` only supports the fixed default PCS configuration.
    #[error("CpuV1 requires PcsConfig::default()")]
    InvalidConfig,
    /// Proof and statement log sizes do not match the fixed CPU component.
    #[error("CpuV1 max_log_degree_bound/log_size mismatch")]
    InvalidLogSize,
    /// Commitment trees do not match preprocessed/original/composition layout.
    #[error("CpuV1 proof must contain exactly preprocessed, original and composition trees")]
    InvalidCommitmentLayout,
    /// OODS samples do not match the fixed component mask layout.
    #[error("CpuV1 sampled_values do not match the fixed component mask points")]
    InvalidSampledValues,
    /// The claimed split-composition sample differs from the fixed CPU AIR evaluation.
    #[error("CpuV1 composition OODS evaluation does not match CpuAir")]
    CompositionOodsMismatch,
    /// Recursive statement fields differ from values replayed from the L1 proof.
    #[error("recursive public inputs do not match the fixed CpuV1 verifier replay")]
    PublicInputsMismatch,
    /// PCS quotient answer construction failed.
    #[error("failed to compute fixed CpuV1 FRI quotient answers: {0}")]
    FriAnswers(String),
    /// The fixed FRI transcript could not be derived.
    #[error("failed to derive fixed CpuV1 FRI transcript")]
    FriTranscript,
    /// Canonical Merkle replay failed.
    #[error("Merkle replay failed: {0}")]
    Merkle(String),
    /// Canonical FRI replay failed.
    #[error("FRI replay failed: {0}")]
    Fri(String),
}

impl From<MerkleReplayError> for VerifierProgramError {
    fn from(error: MerkleReplayError) -> Self {
        Self::Merkle(error.to_string())
    }
}

impl From<FriReplayError> for VerifierProgramError {
    fn from(error: FriReplayError) -> Self {
        Self::Fri(error.to_string())
    }
}

/// 从真实 `prove_cpu_trace` proof 构造完整递归 statement。
///
/// 返回值只描述固定 `CpuV1` verifier，不接受调用方提供 component layout 或 transcript
/// schedule。
#[allow(clippy::missing_errors_doc)]
pub fn build_cpu_recursive_public_inputs(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    log_size: u32,
) -> Result<RecursivePublicInputs, VerifierProgramError> {
    let derived = derive_cpu_verifier_core(l1_proof, log_size, PcsConfig::default())?;
    let fri_query_x =
        first_last_layer_query_x(&derived.fri_challenges, PcsConfig::default(), log_size)?;
    let fri_query_eval = l1_proof
        .0
        .fri_proof
        .last_layer_poly
        .eval_at_point(fri_query_x);
    let inputs = RecursivePublicInputs::new(
        l1_proof.0.commitments.iter().copied().collect(),
        derived.oods_point,
        derived.composition_oods_eval,
        l1_proof.0.fri_proof.first_layer.commitment,
        l1_proof.0.fri_proof.last_layer_poly.clone(),
        log_size,
        PcsConfig::default(),
        derived.fri_challenges.query_positions.clone(),
        log_size,
        fri_query_x,
        fri_query_eval,
    )
    .with_verifier_metadata(
        derived.tree_metadata,
        l1_proof
            .0
            .fri_proof
            .inner_layers
            .iter()
            .map(|layer| layer.commitment)
            .collect(),
    )
    .with_verifier_challenges(
        derived.composition_random_coeff,
        derived.fri_quotient_random_coeff,
    );
    Ok(inputs)
}

/// 验证公开 statement 与固定 CPU verifier replay 完全一致。
pub(crate) fn replay_cpu_verifier(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Result<CpuVerifierReplay, VerifierProgramError> {
    if public_inputs.verifier_program != RecursiveVerifierProgram::CpuV1 {
        return Err(VerifierProgramError::UnsupportedProgram);
    }
    let derived = derive_cpu_verifier_core(l1_proof, public_inputs.log_size, public_inputs.config)?;
    let expected_inner_commitments: Vec<_> = l1_proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| layer.commitment)
        .collect();
    let expected_query_x = first_last_layer_query_x(
        &derived.fri_challenges,
        public_inputs.config,
        public_inputs.max_log_degree_bound,
    )?;
    let expected_query_eval = l1_proof
        .0
        .fri_proof
        .last_layer_poly
        .eval_at_point(expected_query_x);
    if public_inputs.max_log_degree_bound != public_inputs.log_size
        || public_inputs.l1_commitments.as_slice() != l1_proof.0.commitments.as_slice()
        || public_inputs.l1_tree_metadata != derived.tree_metadata
        || public_inputs.oods_point != derived.oods_point
        || public_inputs.composition_random_coeff != derived.composition_random_coeff
        || public_inputs.composition_oods_eval != derived.composition_oods_eval
        || public_inputs.fri_quotient_random_coeff != derived.fri_quotient_random_coeff
        || public_inputs.fri_first_layer_commitment != l1_proof.0.fri_proof.first_layer.commitment
        || public_inputs.fri_inner_layer_commitments != expected_inner_commitments
        || public_inputs.fri_last_layer_poly != l1_proof.0.fri_proof.last_layer_poly
        || public_inputs.query_positions != derived.fri_challenges.query_positions
        || public_inputs.fri_query_x != expected_query_x
        || public_inputs.fri_query_eval != expected_query_eval
    {
        return Err(VerifierProgramError::PublicInputsMismatch);
    }

    let merkle_trees = replay_all_l1_merkle_trees(l1_proof, public_inputs)?;
    let fri = replay_fri_decommitment(
        l1_proof,
        public_inputs.config,
        public_inputs.max_log_degree_bound,
        &derived.fri_challenges,
        derived.first_layer_answers.clone(),
    )?;

    Ok(CpuVerifierReplay {
        composition_random_coeff: derived.composition_random_coeff,
        oods_point: derived.oods_point,
        composition_oods_eval: derived.composition_oods_eval,
        fri_quotient_random_coeff: derived.fri_quotient_random_coeff,
        tree_metadata: derived.tree_metadata,
        fri_challenges: derived.fri_challenges,
        first_layer_answers: derived.first_layer_answers,
        merkle_trees,
        fri,
    })
}

struct CpuVerifierCore {
    composition_random_coeff: SecureField,
    oods_point: CirclePoint<SecureField>,
    composition_oods_eval: SecureField,
    fri_quotient_random_coeff: SecureField,
    tree_metadata: Vec<RecursiveTreeMetadata>,
    fri_challenges: FriReplayChallenges,
    first_layer_answers: Vec<SecureField>,
}

fn derive_cpu_verifier_core(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    log_size: u32,
    config: PcsConfig,
) -> Result<CpuVerifierCore, VerifierProgramError> {
    if config != PcsConfig::default() {
        return Err(VerifierProgramError::InvalidConfig);
    }
    if log_size == 0 {
        return Err(VerifierProgramError::InvalidLogSize);
    }
    if l1_proof.0.commitments.len() != 3 {
        return Err(VerifierProgramError::InvalidCommitmentLayout);
    }

    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        CpuAir::new(log_size),
        SecureField::from(0u32),
    );
    let components = Components {
        components: vec![&component as &dyn Component],
        n_preprocessed_columns: 0,
    };
    let max_log_degree_bound = components.composition_log_degree_bound() - 1;
    if max_log_degree_bound != log_size {
        return Err(VerifierProgramError::InvalidLogSize);
    }

    let mut column_log_sizes = components.column_log_sizes();
    if column_log_sizes.len() != 2
        || !column_log_sizes[0].is_empty()
        || column_log_sizes[1].len() != NUM_COLUMNS
    {
        return Err(VerifierProgramError::InvalidCommitmentLayout);
    }
    column_log_sizes.push(vec![log_size; 2 * SECURE_EXTENSION_DEGREE]);
    let tree_metadata = column_log_sizes
        .iter()
        .cloned()
        .map(RecursiveTreeMetadata::new)
        .collect();

    let mut channel = Poseidon252Channel::default();
    Poseidon252MerkleChannel::mix_root(&mut channel, l1_proof.0.commitments[0]);
    Poseidon252MerkleChannel::mix_root(&mut channel, l1_proof.0.commitments[1]);
    let composition_random_coeff = channel.draw_secure_felt();
    Poseidon252MerkleChannel::mix_root(&mut channel, l1_proof.0.commitments[2]);
    let oods_point = CirclePoint::<SecureField>::get_random_point(&mut channel);

    let mut sample_points = components.mask_points(oods_point, max_log_degree_bound, false);
    sample_points.push(vec![vec![oods_point]; 2 * SECURE_EXTENSION_DEGREE]);
    if !same_sample_shape(&sample_points, &l1_proof.0.sampled_values) {
        return Err(VerifierProgramError::InvalidSampledValues);
    }
    let composition_oods_eval =
        extract_composition_oods_eval_from_l1(l1_proof, oods_point, max_log_degree_bound)
            .ok_or(VerifierProgramError::InvalidSampledValues)?;
    let computed_composition = components.eval_composition_polynomial_at_point(
        oods_point,
        &l1_proof.0.sampled_values,
        composition_random_coeff,
        max_log_degree_bound,
    );
    if composition_oods_eval != computed_composition {
        return Err(VerifierProgramError::CompositionOodsMismatch);
    }

    channel.mix_felts(&l1_proof.0.sampled_values.clone().flatten_cols());
    let fri_quotient_random_coeff = channel.draw_secure_felt();
    let fri_challenges =
        extract_simple_fri_replay_challenges(l1_proof, config, max_log_degree_bound)
            .ok_or(VerifierProgramError::FriTranscript)?;

    let samples = sample_points
        .zip_cols(l1_proof.0.sampled_values.clone())
        .map_cols(|(points, values)| {
            zip(points, values)
                .map(|(point, value)| PointSample { point, value })
                .collect()
        });
    let lifting_log_size = log_size + config.fri_config.log_blowup_factor;
    let first_layer_answers = fri_answers(
        column_log_sizes,
        samples,
        fri_quotient_random_coeff,
        &fri_challenges.query_positions,
        l1_proof.0.queried_values.clone(),
        lifting_log_size,
    )
    .map_err(|error| VerifierProgramError::FriAnswers(error.to_string()))?;

    Ok(CpuVerifierCore {
        composition_random_coeff,
        oods_point,
        composition_oods_eval,
        fri_quotient_random_coeff,
        tree_metadata,
        fri_challenges,
        first_layer_answers,
    })
}

fn same_sample_shape<T, U>(
    expected: &stwo::core::pcs::TreeVec<Vec<Vec<T>>>,
    actual: &stwo::core::pcs::TreeVec<Vec<Vec<U>>>,
) -> bool {
    expected.len() == actual.len()
        && expected
            .iter()
            .zip(actual.iter())
            .all(|(expected_tree, actual_tree)| {
                expected_tree.len() == actual_tree.len()
                    && expected_tree.iter().zip(actual_tree.iter()).all(
                        |(expected_column, actual_column)| {
                            expected_column.len() == actual_column.len()
                        },
                    )
            })
}

fn first_last_layer_query_x(
    challenges: &FriReplayChallenges,
    config: PcsConfig,
    max_log_degree_bound: u32,
) -> Result<SecureField, VerifierProgramError> {
    use stwo::core::circle::Coset;
    use stwo::core::poly::line::LineDomain;
    use stwo::core::utils::bit_reverse_index;

    let first_query = *challenges
        .query_positions
        .first()
        .ok_or(VerifierProgramError::FriTranscript)?;
    let first_layer_log_size = max_log_degree_bound
        .checked_add(config.fri_config.log_blowup_factor)
        .and_then(|value| value.checked_add(1))
        .ok_or(VerifierProgramError::FriTranscript)?;
    let last_layer_log_size =
        config.fri_config.log_last_layer_degree_bound + config.fri_config.log_blowup_factor;
    let total_fold = first_layer_log_size
        .checked_sub(last_layer_log_size)
        .ok_or(VerifierProgramError::FriTranscript)?;
    let last_layer_query = first_query >> total_fold;
    let domain = LineDomain::new(Coset::half_odds(last_layer_log_size));
    Ok(domain
        .at(bit_reverse_index(last_layer_query, domain.log_size()))
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::trace_native::TraceBuilder;

    const TEST_LOG_SIZE: u32 = 10;

    fn make_l1_proof() -> StarkProof<Poseidon252MerkleHasher> {
        let mut builder = TraceBuilder::new(TEST_LOG_SIZE);
        builder.fill_padding_to_full();
        prove_cpu_trace(&builder.finalize()).expect("L1 proof generation should succeed")
    }

    #[test]
    fn fixed_cpu_program_replays_complete_verifier() {
        let proof = make_l1_proof();
        let inputs = build_cpu_recursive_public_inputs(&proof, TEST_LOG_SIZE).unwrap();
        let replay = replay_cpu_verifier(&proof, &inputs).unwrap();

        assert_eq!(replay.merkle_trees.len(), 3);
        assert_eq!(
            replay.fri.layers.len(),
            1 + proof.0.fri_proof.inner_layers.len()
        );
        assert_eq!(replay.oods_point, inputs.oods_point);
    }

    #[test]
    fn fixed_cpu_program_rejects_relabelled_oods_point() {
        let proof = make_l1_proof();
        let mut inputs = build_cpu_recursive_public_inputs(&proof, TEST_LOG_SIZE).unwrap();
        inputs.oods_point.x += SecureField::from(1u32);

        assert!(matches!(
            replay_cpu_verifier(&proof, &inputs),
            Err(VerifierProgramError::PublicInputsMismatch)
        ));
    }

    #[test]
    fn fixed_cpu_program_rejects_wrong_column_schema() {
        let proof = make_l1_proof();
        let mut inputs = build_cpu_recursive_public_inputs(&proof, TEST_LOG_SIZE).unwrap();
        inputs.l1_tree_metadata[1].column_log_sizes.pop();

        assert!(matches!(
            replay_cpu_verifier(&proof, &inputs),
            Err(VerifierProgramError::PublicInputsMismatch)
        ));
    }
}
