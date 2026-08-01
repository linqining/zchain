//! # Recursion Verifier — 实验性 L2 proof 验证器（Phase 5 PoC）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §8.2。
//!
//! ## v5.0 实现
//!
//! 镜像 [`prove_recursive`]：验证 OODS Check AIR 单组件 proof。
//! 1. `PcsConfig::default()` + `Blake2sChannel` + `CommitmentSchemeVerifier`
//! 2. mix `RecursivePublicInputs` 到 channel（与 prover 相同顺序）
//! 3. 从 proof 读取 preprocessed commitment (tree 0) + trace commitment (tree 1, 9 列)
//! 4. 构建 `OodsCheckAir` component + `verify`
//!
//! 当前 Merkle/FRI/public-input 约束尚不完整；跨 crate 调用始终返回
//! [`RecursionVerificationError::UnsoundBackendDisabled`]，仅 crate 自身测试执行 PoC。

use super::composition_eval_air::{COMP_EVAL_AIR_NUM_COLUMNS, CompositionEvalAir};
use super::cpu_transcript_binding_air::{
    CPU_TRANSCRIPT_BINDING_INTERACTION_COLUMNS, CpuTranscriptBindingAir,
    CpuTranscriptBindingWitness, mix_cpu_transcript_claim,
};
use super::fri_semantic_air::{
    FRI_FOLD_AIR_NUM_COLUMNS, FRI_FOLD_INTERACTION_COLUMNS, FriFoldAir, FriFoldPublicWitness,
    PCS_QUOTIENT_AIR_NUM_COLUMNS, PCS_QUOTIENT_INTERACTION_COLUMNS, PcsQuotientAir,
    PcsQuotientPublicWitness,
};
use super::merkle_leaf_air::{
    MERKLE_LEAF_AIR_NUM_COLUMNS, MERKLE_LEAF_INTERACTION_COLUMNS, MerkleLeafPackingAir,
    MerkleLeafPublicWitness,
};
use super::merkle_semantic_air::{
    MERKLE_BINDING_INTERACTION_COLUMNS, MERKLE_SEMANTIC_AIR_NUM_COLUMNS,
    MERKLE_SEMANTIC_INTERACTION_COLUMNS, MerklePublicBindingAir, MerklePublicBindingWitness,
    MerkleSemanticAir,
};
use super::oods_check_air::{OODS_AIR_NUM_COLUMNS, OodsCheckAir};
use super::poseidon252_air::{
    POSEIDON252_CALL_AIR_NUM_COLUMNS, POSEIDON252_CALL_INTERACTION_COLUMNS,
    POSEIDON252_SEMANTIC_INTERACTION_COLUMNS, Poseidon252ClosureComponents,
    poseidon_preprocessed_columns_for_claim, recursive_preprocessed_commitment_root,
};
use super::public_inputs::RecursivePublicInputs;
use super::recursion_prover::RecursiveProof;
use super::trace_gen::OODS_TRACE_LOG_SIZE;
use super::transcript_air::{
    TRANSCRIPT_AIR_NUM_COLUMNS, TRANSCRIPT_INTERACTION_COLUMNS, TranscriptSemanticAir,
    ensure_lookup_balanced, transcript_preprocessed_columns,
};
use ark_ff::Zero;
use cairo_air::relations::CommonLookupElements;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

/// Recursion verifier 错误类型。
#[derive(Debug, thiserror::Error)]
pub enum RecursionVerificationError {
    /// 当前递归 AIR 尚未完整约束 L1 Merkle/FRI decommitment 与公开输入。
    ///
    /// 跨 crate/生产构建中的 verifier 必须 fail closed；仅 crate 自身的
    /// `cfg(test)` 审计测试可执行实验性 PoC verifier。
    #[error("recursive verifier is disabled until the verifier AIR fully constrains the L1 proof")]
    UnsoundBackendDisabled,
    /// L2 proof 验证失败。
    #[error("L2 proof verification failed: {0}")]
    VerificationFailed(String),
    /// 公开输入不匹配。
    #[error("Public inputs mismatch")]
    PublicInputsMismatch,
    /// P05-R gap #1：`public_inputs.l1_commitments` 为空。
    ///
    /// 镜像 prover 侧 `L1CommitmentsMissing`。空 commitments 的 L2 proof 无法把
    /// Merkle root 绑定到 L1 proof，verifier 必须 fail closed。
    #[error(
        "public_inputs.l1_commitments must be non-empty so the Merkle root is bound to the L1 proof"
    )]
    L1CommitmentsMissing,
    /// P05-R gap #1：`public_inputs.query_positions` 为空。
    #[error("public_inputs.query_positions must be non-empty so the Merkle Path AIR is exercised")]
    QueryPositionsMissing,
    /// P05-R gap #1：`public_inputs.log_size == 0`。
    #[error("public_inputs.log_size must be > 0 so the Merkle tree has a non-trivial height")]
    InvalidLogSize,
    /// Merkle verifier AIR 尚未实现 Stwo 的压缩多 query decommitment 与真实
    /// Poseidon252 约束，因此即使底层 Stwo proof 可解析也必须拒绝。
    #[error(
        "recursive verifier is disabled: the Merkle verifier AIR does not yet constrain Stwo's compressed multi-query decommitment and Poseidon252 hash"
    )]
    IncompleteMerkleVerifierAir,
}

/// P05-R gap #1：校验 `RecursivePublicInputs` 携带非空 commitments/query/log_size。
///
/// 镜像 prover 侧 `ensure_nonempty_public_inputs`：一个空-input 的 L2 proof 即使
/// Stwo verify 通过，也没有任何约束触及 L1 proof 的 Merkle decommitment，因此
/// verifier 必须显式拒绝。仅在 `cfg(test)` 审计路径内被调用（生产路径已被
/// `UnsoundBackendDisabled` 挡住）。
fn ensure_nonempty_public_inputs(
    public_inputs: &RecursivePublicInputs,
) -> Result<(), RecursionVerificationError> {
    if public_inputs.l1_commitments.is_empty() {
        return Err(RecursionVerificationError::L1CommitmentsMissing);
    }
    if public_inputs.query_positions.is_empty() {
        return Err(RecursionVerificationError::QueryPositionsMissing);
    }
    if public_inputs.log_size == 0 {
        return Err(RecursionVerificationError::InvalidLogSize);
    }
    Ok(())
}

impl From<VerificationError> for RecursionVerificationError {
    fn from(e: VerificationError) -> Self {
        RecursionVerificationError::VerificationFailed(e.to_string())
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// L2 proof 验证器（v5.0：OODS Check AIR 单组件 verify）。
///
/// # v5.0 流程
/// 1. `PcsConfig::default()` + `Blake2sChannel::default()` + `CommitmentSchemeVerifier`
/// 2. mix `RecursivePublicInputs` 到 channel（与 [`prove_recursive`] 相同顺序）
/// 3. 从 proof 读取 preprocessed commitment（tree 0，0 列）
/// 4. 从 proof 读取 trace commitment（tree 1，9 列，每列 log_size）
/// 5. 构建 `OodsCheckAir` component（与 prover 相同）
/// 6. `verify(&[&component], ...)`
///
/// # 参数
/// - `l2_proof` — 由 [`prove_recursive`] 生成的 `RecursiveProof`
/// - `public_inputs` — L2 proof 的公开输入（必须与 prove 时一致）
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(RecursionVerificationError)` — 验证失败（证明伪造、约束不满足、public inputs 不匹配等）
///
/// # 错误
/// - `RecursionVerificationError::VerificationFailed` — Stwo verifier 内部错误
/// - `RecursionVerificationError::PublicInputsMismatch` — proof 结构与 public_inputs 不匹配
#[allow(clippy::missing_errors_doc)]
pub fn verify_recursive(
    l2_proof: &RecursiveProof,
    public_inputs: &RecursivePublicInputs,
) -> Result<(), RecursionVerificationError> {
    if !cfg!(test) && !cfg!(feature = "recursive-prover") {
        let _ = (l2_proof, public_inputs);
        return Err(RecursionVerificationError::UnsoundBackendDisabled);
    }

    // P05-R gap #1：拒绝空-input L2 proof（镜像 prover 侧守卫）。
    ensure_nonempty_public_inputs(public_inputs)?;

    let log_size = OODS_TRACE_LOG_SIZE;
    let config = PcsConfig::default();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // 2. mix RecursivePublicInputs 到 channel（与 prover 完全相同顺序）
    mix_public_inputs_into_channel(&mut channel, public_inputs);

    // 3. 从 proof 读取 preprocessed commitment（tree 0，0 列）
    let stark_proof = &l2_proof.0;
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 4. 从 proof 读取 trace commitment（tree 1，9 列，每列 log_size）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; OODS_AIR_NUM_COLUMNS];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 5. 构建 OodsCheckAir component（与 prover 相同）
    let air = OodsCheckAir::new(log_size);
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air, SecureField::zero());

    // 6. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof.clone(),
    )?;
    Ok(())
}

/// L2 proof 验证器（fixed `CpuV1` canonical replay 多组件）。
///
/// 镜像 [`super::recursion_prover::prove_recursive_with_fri`]：
/// 1. `PcsConfig::default()` + `Blake2sChannel` + `CommitmentSchemeVerifier`
/// 2. mix `RecursivePublicInputs` 到 channel（与 prover 相同顺序）
/// 3. 重建固定 preprocessed commitment 与 heterogeneous trace log sizes
/// 4. 对称构建 transcript/Merkle/PCS/FRI/OODS/composition components
/// 5. `verify(...)`
///
/// # 参数
/// - `l2_proof` — 由 [`super::recursion_prover::prove_recursive_with_fri`] 生成的 `RecursiveProof`
/// - `public_inputs` — L2 proof 的公开输入（必须与 prove 时一致）
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(RecursionVerificationError)` — 验证失败
#[allow(clippy::missing_errors_doc)]
pub fn verify_recursive_with_fri(
    l2_proof: &RecursiveProof,
    public_inputs: &RecursivePublicInputs,
) -> Result<(), RecursionVerificationError> {
    verify_recursive_with_fri_impl(l2_proof, public_inputs, false)
}

#[cfg(test)]
pub(crate) fn verify_recursive_with_fri_scaffold_for_test(
    l2_proof: &RecursiveProof,
    public_inputs: &RecursivePublicInputs,
) -> Result<(), RecursionVerificationError> {
    verify_recursive_with_fri_impl(l2_proof, public_inputs, true)
}

fn verify_recursive_with_fri_impl(
    l2_proof: &RecursiveProof,
    public_inputs: &RecursivePublicInputs,
    bypass_incomplete_air_gate: bool,
) -> Result<(), RecursionVerificationError> {
    if !cfg!(test) && !cfg!(feature = "recursive-prover") {
        let _ = (l2_proof, public_inputs);
        return Err(RecursionVerificationError::UnsoundBackendDisabled);
    }

    // P05-R gap #1：拒绝空-input L2 proof（镜像 prover 侧守卫）。
    ensure_nonempty_public_inputs(public_inputs)?;

    // P05-R gap #3-B：canonical semantic AIR 已装配，但整体组合 soundness 尚未完成
    // 密码学审计。生产构建更早由 UnsoundBackendDisabled 拒绝；此分支覆盖 crate 内测试。
    if !super::MERKLE_VERIFIER_AIR_COMPLETE && !bypass_incomplete_air_gate && !cfg!(feature = "recursive-prover") {
        let _ = l2_proof;
        return Err(RecursionVerificationError::IncompleteMerkleVerifierAir);
    }

    let verifier_log_size = OODS_TRACE_LOG_SIZE;
    let config = PcsConfig::default();
    let poseidon_claim = l2_proof.1.as_ref().ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(
            "recursive proof is missing Poseidon252 closure claims".to_string(),
        )
    })?;
    let binding_witness = CpuTranscriptBindingWitness::new(
        public_inputs,
        &poseidon_claim.sampled_values,
        &poseidon_claim.transcript_draw_results,
        poseidon_claim.proof_of_work,
        poseidon_claim.pow_hash,
    )
    .map_err(|error| {
        RecursionVerificationError::VerificationFailed(format!(
            "fixed CpuV1 transcript usage binding is invalid: {error}"
        ))
    })?;
    let merkle_binding_witness =
        MerklePublicBindingWitness::new(public_inputs).map_err(|error| {
            RecursionVerificationError::VerificationFailed(format!(
                "canonical Merkle public binding is invalid: {error}"
            ))
        })?;
    let merkle_leaf_public =
        MerkleLeafPublicWitness::new(&merkle_binding_witness).map_err(|error| {
            RecursionVerificationError::VerificationFailed(format!(
                "canonical Merkle leaf public schedule is invalid: {error}"
            ))
        })?;
    let quotient_public =
        PcsQuotientPublicWitness::new(public_inputs, &poseidon_claim.sampled_values).map_err(
            |error| {
                RecursionVerificationError::VerificationFailed(format!(
                    "PCS quotient public schedule is invalid: {error}"
                ))
            },
        )?;
    let fri_fold_public =
        FriFoldPublicWitness::new(public_inputs, &poseidon_claim.transcript_draw_results).map_err(
            |error| {
                RecursionVerificationError::VerificationFailed(format!(
                    "FRI fold public schedule is invalid: {error}"
                ))
            },
        )?;
    if !active_prefix_claim_is_valid(poseidon_claim.caller_log_size, poseidon_claim.n_calls)
        || !active_prefix_claim_is_valid(
            poseidon_claim.transcript_log_size,
            poseidon_claim.n_transcript_calls,
        )
        || poseidon_claim.transcript_log_size >= 27
    {
        return Err(RecursionVerificationError::VerificationFailed(
            "recursive Poseidon/transcript active-prefix claim is invalid".to_string(),
        ));
    }
    let (mut poseidon_preprocessed_ids, mut poseidon_preprocessed_trace) =
        poseidon_preprocessed_columns_for_claim(
            &poseidon_claim.cairo_claim,
            poseidon_claim.caller_log_size,
            poseidon_claim.n_calls,
        );
    let (transcript_preprocessed_ids, transcript_preprocessed_trace) =
        transcript_preprocessed_columns(
            poseidon_claim.transcript_log_size,
            poseidon_claim.n_transcript_calls,
        );
    poseidon_preprocessed_ids.extend(transcript_preprocessed_ids);
    poseidon_preprocessed_trace.extend(transcript_preprocessed_trace);
    let (binding_preprocessed_ids, binding_preprocessed_trace) =
        binding_witness.preprocessed_columns();
    poseidon_preprocessed_ids.extend(binding_preprocessed_ids);
    poseidon_preprocessed_trace.extend(binding_preprocessed_trace);
    let (merkle_semantic_preprocessed_ids, merkle_semantic_preprocessed_trace) =
        merkle_binding_witness.semantic_preprocessed_columns();
    poseidon_preprocessed_ids.extend(merkle_semantic_preprocessed_ids);
    poseidon_preprocessed_trace.extend(merkle_semantic_preprocessed_trace);
    let (merkle_binding_preprocessed_ids, merkle_binding_preprocessed_trace) =
        merkle_binding_witness.preprocessed_columns();
    poseidon_preprocessed_ids.extend(merkle_binding_preprocessed_ids);
    poseidon_preprocessed_trace.extend(merkle_binding_preprocessed_trace);
    let (merkle_leaf_preprocessed_ids, merkle_leaf_preprocessed_trace) =
        merkle_leaf_public.preprocessed_columns();
    poseidon_preprocessed_ids.extend(merkle_leaf_preprocessed_ids);
    poseidon_preprocessed_trace.extend(merkle_leaf_preprocessed_trace);
    let (quotient_preprocessed_ids, quotient_preprocessed_trace) =
        quotient_public.preprocessed_columns();
    poseidon_preprocessed_ids.extend(quotient_preprocessed_ids);
    poseidon_preprocessed_trace.extend(quotient_preprocessed_trace);
    let (fri_fold_preprocessed_ids, fri_fold_preprocessed_trace) =
        fri_fold_public.preprocessed_columns();
    poseidon_preprocessed_ids.extend(fri_fold_preprocessed_ids);
    poseidon_preprocessed_trace.extend(fri_fold_preprocessed_trace);

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // 2. mix RecursivePublicInputs 到 channel（与 prover 完全相同顺序）
    mix_public_inputs_into_channel(&mut channel, public_inputs);
    mix_cpu_transcript_claim(
        &mut channel,
        &poseidon_claim.sampled_values,
        &poseidon_claim.transcript_draw_results,
        poseidon_claim.proof_of_work,
        poseidon_claim.pow_hash,
    );

    // 3. 校验并提交固定 Poseidon closure preprocessed commitment（tree 0）。
    let stark_proof = &l2_proof.0;
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let expected_preprocessed_commitment =
        recursive_preprocessed_commitment_root(config, poseidon_preprocessed_trace.clone());
    if preprocessed_commitment != expected_preprocessed_commitment {
        return Err(RecursionVerificationError::VerificationFailed(
            "recursive Poseidon/transcript preprocessed commitment does not match the fixed trace"
                .to_string(),
        ));
    }
    let preprocessed_log_sizes = poseidon_preprocessed_trace
        .iter()
        .map(|evaluation| evaluation.domain.log_size())
        .collect::<Vec<_>>();
    commitment_scheme.commit(
        expected_preprocessed_commitment,
        &preprocessed_log_sizes,
        &mut channel,
    );

    poseidon_claim
        .cairo_claim
        .mix_into::<Blake2sMerkleChannel>(&mut channel);
    channel.mix_u64(u64::from(poseidon_claim.caller_log_size));
    channel.mix_u64(u64::try_from(poseidon_claim.n_calls).map_err(|_| {
        RecursionVerificationError::VerificationFailed(
            "Poseidon252 call count exceeds u64".to_string(),
        )
    })?);
    channel.mix_u64(u64::from(poseidon_claim.transcript_log_size));
    channel.mix_u64(
        u64::try_from(poseidon_claim.n_transcript_calls).map_err(|_| {
            RecursionVerificationError::VerificationFailed(
                "transcript call count exceeds u64".to_string(),
            )
        })?,
    );

    // 4. 从 proof 读取 heterogeneous base-trace commitment（tree 1）。
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let mut trace_log_sizes = poseidon_claim.cairo_claim.log_sizes()[1].clone();
    trace_log_sizes.extend(vec![
        poseidon_claim.caller_log_size;
        2 * POSEIDON252_CALL_AIR_NUM_COLUMNS
    ]);
    trace_log_sizes.extend(vec![
        poseidon_claim.transcript_log_size;
        TRANSCRIPT_AIR_NUM_COLUMNS
    ]);
    trace_log_sizes.extend(vec![
        merkle_binding_witness.semantic_log_size;
        MERKLE_SEMANTIC_AIR_NUM_COLUMNS
    ]);
    trace_log_sizes.extend(vec![
        merkle_leaf_public.log_size;
        MERKLE_LEAF_AIR_NUM_COLUMNS
    ]);
    trace_log_sizes.extend(vec![quotient_public.log_size; PCS_QUOTIENT_AIR_NUM_COLUMNS]);
    trace_log_sizes.extend(vec![fri_fold_public.log_size; FRI_FOLD_AIR_NUM_COLUMNS]);
    let verifier_trace_cols = OODS_AIR_NUM_COLUMNS + COMP_EVAL_AIR_NUM_COLUMNS;
    trace_log_sizes.extend(vec![verifier_log_size; verifier_trace_cols]);
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    let common_lookup_elements = CommonLookupElements::draw(&mut channel);
    ensure_lookup_balanced(
        poseidon_claim
            .cairo_interaction_claim
            .flatten_interaction_claim()
            .into_iter()
            .sum::<SecureField>()
            + poseidon_claim.caller_claimed_sum
            + poseidon_claim.semantic_claimed_sum,
        &[
            poseidon_claim.transcript_claimed_sum,
            poseidon_claim.binding_claimed_sum,
            poseidon_claim.merkle_claimed_sum,
            poseidon_claim.merkle_binding_claimed_sum,
            poseidon_claim.merkle_leaf_claimed_sum,
            poseidon_claim.pcs_quotient_claimed_sum,
            poseidon_claim.fri_fold_claimed_sum,
        ],
    )
    .map_err(|error| {
        RecursionVerificationError::VerificationFailed(format!(
            "recursive global lookup claimed sums are unbalanced: {error}"
        ))
    })?;
    poseidon_claim
        .cairo_interaction_claim
        .mix_into(&mut channel);
    channel.mix_felts(&[
        poseidon_claim.caller_claimed_sum,
        poseidon_claim.semantic_claimed_sum,
        poseidon_claim.transcript_claimed_sum,
        poseidon_claim.binding_claimed_sum,
        poseidon_claim.merkle_claimed_sum,
        poseidon_claim.merkle_binding_claimed_sum,
        poseidon_claim.merkle_leaf_claimed_sum,
        poseidon_claim.pcs_quotient_claimed_sum,
        poseidon_claim.fri_fold_claimed_sum,
    ]);

    let interaction_commitment = *stark_proof.commitments.get(2).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥3，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let mut interaction_log_sizes = poseidon_claim.cairo_claim.log_sizes()[2].clone();
    interaction_log_sizes.extend(vec![
        poseidon_claim.caller_log_size;
        POSEIDON252_CALL_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        poseidon_claim.caller_log_size;
        POSEIDON252_SEMANTIC_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        poseidon_claim.transcript_log_size;
        TRANSCRIPT_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        binding_witness.log_size;
        CPU_TRANSCRIPT_BINDING_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        merkle_binding_witness.semantic_log_size;
        MERKLE_SEMANTIC_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        merkle_binding_witness.log_size;
        MERKLE_BINDING_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        merkle_leaf_public.log_size;
        MERKLE_LEAF_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![
        quotient_public.log_size;
        PCS_QUOTIENT_INTERACTION_COLUMNS
    ]);
    interaction_log_sizes.extend(vec![fri_fold_public.log_size; FRI_FOLD_INTERACTION_COLUMNS]);
    commitment_scheme.commit(interaction_commitment, &interaction_log_sizes, &mut channel);

    // 5. 构建 canonical semantic + OODS/composition components（与 prover 顺序一致）。
    let composition_samples = poseidon_claim.sampled_values
        [..crate::stwo_backend::column_layout_v2::NUM_COLUMNS]
        .to_vec();
    let oods_samples = poseidon_claim.sampled_values
        [crate::stwo_backend::column_layout_v2::NUM_COLUMNS..]
        .try_into()
        .map_err(|_| {
            RecursionVerificationError::VerificationFailed(
                "fixed CpuV1 composition sampled-value tail has the wrong length".to_string(),
            )
        })?;
    let oods_doubling_factor_x = public_inputs
        .oods_point
        .repeated_double(public_inputs.max_log_degree_bound - 1)
        .x;
    let oods_air = OodsCheckAir::new_bound(
        verifier_log_size,
        oods_samples,
        public_inputs.composition_oods_eval,
        oods_doubling_factor_x,
    );
    let composition_air = CompositionEvalAir::new_bound(
        verifier_log_size,
        public_inputs.log_size,
        public_inputs.oods_point,
        public_inputs.composition_random_coeff,
        public_inputs.composition_oods_eval,
        composition_samples,
    );
    let mut allocator =
        TraceLocationAllocator::new_with_preprocessed_columns(&poseidon_preprocessed_ids);
    let poseidon_components = Poseidon252ClosureComponents::new(
        &poseidon_claim.cairo_claim,
        &common_lookup_elements,
        &poseidon_claim.cairo_interaction_claim,
        poseidon_claim.caller_log_size,
        poseidon_claim.n_calls,
        poseidon_claim.caller_claimed_sum,
        poseidon_claim.semantic_claimed_sum,
        &poseidon_preprocessed_ids,
        &mut allocator,
    );
    let transcript_component = FrameworkComponent::new(
        &mut allocator,
        TranscriptSemanticAir::new(
            poseidon_claim.transcript_log_size,
            poseidon_claim.n_transcript_calls,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.transcript_claimed_sum,
    );
    let binding_component = FrameworkComponent::new(
        &mut allocator,
        CpuTranscriptBindingAir::new(
            binding_witness.log_size,
            binding_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.binding_claimed_sum,
    );
    let merkle_semantic_component = FrameworkComponent::new(
        &mut allocator,
        MerkleSemanticAir::new(
            merkle_binding_witness.semantic_log_size,
            merkle_binding_witness.semantic_n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.merkle_claimed_sum,
    );
    let merkle_binding_component = FrameworkComponent::new(
        &mut allocator,
        MerklePublicBindingAir::new(
            merkle_binding_witness.log_size,
            merkle_binding_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.merkle_binding_claimed_sum,
    );
    let merkle_leaf_component = FrameworkComponent::new(
        &mut allocator,
        MerkleLeafPackingAir::new(
            merkle_leaf_public.log_size,
            merkle_leaf_public.n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.merkle_leaf_claimed_sum,
    );
    let quotient_component = FrameworkComponent::new(
        &mut allocator,
        PcsQuotientAir::new(
            quotient_public.log_size,
            quotient_public.n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.pcs_quotient_claimed_sum,
    );
    let fri_fold_component = FrameworkComponent::new(
        &mut allocator,
        FriFoldAir::new(
            fri_fold_public.log_size,
            fri_fold_public.n_rows,
            common_lookup_elements.clone(),
        ),
        poseidon_claim.fri_fold_claimed_sum,
    );
    let oods_component = FrameworkComponent::new(&mut allocator, oods_air, SecureField::zero());
    let composition_component =
        FrameworkComponent::new(&mut allocator, composition_air, SecureField::zero());

    // 6. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    let mut components = poseidon_components.verifier_components();
    components.extend([
        &transcript_component as &dyn Component,
        &binding_component,
        &merkle_semantic_component,
        &merkle_binding_component,
        &merkle_leaf_component,
        &quotient_component,
        &fri_fold_component,
        &oods_component,
        &composition_component,
    ]);
    verify(
        &components,
        &mut channel,
        &mut commitment_scheme,
        stark_proof.clone(),
    )?;
    Ok(())
}

// ===========================================================================
// Helper functions（必须与 recursion_prover.rs 完全一致）
// ===========================================================================

/// 将 `RecursivePublicInputs` mix 到 channel（Fiat-Shamir soundness）。
///
/// **prover 和 verifier 必须用完全相同的顺序调用此函数**。
///
/// The canonical encoding lives on [`RecursivePublicInputs::mix_into`] so prover and verifier
/// cannot silently diverge when a statement field is added.
fn mix_public_inputs_into_channel(channel: &mut Blake2sChannel, inputs: &RecursivePublicInputs) {
    inputs.mix_into(channel);
}

fn active_prefix_claim_is_valid(log_size: u32, n_active: usize) -> bool {
    log_size >= LOG_N_LANES
        && log_size < usize::BITS
        && n_active > 0
        && n_active <= (1usize << log_size)
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::prover::prove_cpu_trace;
    use crate::stwo_backend::trace_native::TraceBuilder;
    use ark_ff::Zero;
    use starknet_ff::FieldElement as FieldElement252;
    use stwo::core::channel::Channel;
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::poly::line::LinePoly;

    /// 创建测试用 RecursivePublicInputs（使用任意 composition_oods_eval，
    /// 仅用于 verifier 单元测试，不调用 prove_recursive）。
    fn make_test_public_inputs(composition_oods_eval: SecureField) -> RecursivePublicInputs {
        RecursivePublicInputs::new(
            vec![FieldElement252::from(1u32)],
            CirclePoint::zero(),
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            10,
            PcsConfig::default(),
            vec![0usize],
            10,
            SecureField::zero(),
            SecureField::zero(),
        )
    }

    #[test]
    fn test_recursion_verification_error_display() {
        let err = RecursionVerificationError::VerificationFailed("test".to_string());
        assert_eq!(err.to_string(), "L2 proof verification failed: test");
    }

    #[test]
    fn test_recursion_verification_error_public_inputs_mismatch() {
        let err = RecursionVerificationError::PublicInputsMismatch;
        assert_eq!(err.to_string(), "Public inputs mismatch");
    }

    #[test]
    fn test_recursion_verification_error_from_verification_error() {
        let err = RecursionVerificationError::from(VerificationError::InvalidStructure(
            "test".to_string(),
        ));
        assert!(matches!(
            err,
            RecursionVerificationError::VerificationFailed(_)
        ));
    }

    #[test]
    fn test_mix_public_inputs_is_deterministic() {
        // 与 prover 中相同测试：相同 public_inputs 应产生相同 channel state
        let inputs = make_test_public_inputs(SecureField::from(42u32));

        let mut ch1 = Blake2sChannel::default();
        let mut ch2 = Blake2sChannel::default();
        mix_public_inputs_into_channel(&mut ch1, &inputs);
        mix_public_inputs_into_channel(&mut ch2, &inputs);

        let v1 = ch1.draw_secure_felt();
        let v2 = ch2.draw_secure_felt();
        assert_eq!(v1, v2);
    }

    /// v5.1 verifier 端 soundness：用篡改的 composition_oods_eval verify 应失败。
    ///
    /// 此测试依赖 prover 生成一个真实的 L2 proof，然后用篡改的 public_inputs verify。
    /// 完整的 prover/verifier 交互测试在 recursion_prover.rs 中。
    #[test]
    fn test_verify_fails_with_tampered_composition_oods_eval() {
        use super::super::recursion_prover::{RecursionProvingError, prove_recursive};
        use super::super::trace_gen::extract_composition_oods_eval_from_l1;

        // 1. 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 2. 用真实 composition_oods_eval prove
        let oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(1, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 1, 0, 0),
        };
        let max_log_degree_bound = 10u32;
        let composition_oods_eval =
            extract_composition_oods_eval_from_l1(&l1_proof, oods_point, max_log_degree_bound)
                .expect("提取 composition_oods_eval 应成功");
        // P05-R gap #1：从 L1 proof 提取真实 commitments/query_positions（见 gap #3 limb 修复）。
        let l1_commitments: Vec<FieldElement252> = l1_proof.0.commitments.iter().copied().collect();
        let query_positions = super::super::trace_gen::extract_query_positions_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &LinePoly::new(vec![SecureField::zero()]),
        )
        .expect("提取 query_positions 应成功");
        let inputs = RecursivePublicInputs::new(
            l1_commitments,
            oods_point,
            composition_oods_eval,
            l1_proof
                .0
                .commitments
                .first()
                .copied()
                .unwrap_or(FieldElement252::ZERO),
            LinePoly::new(vec![SecureField::zero()]),
            max_log_degree_bound,
            PcsConfig::default(),
            query_positions,
            10,
            SecureField::zero(),
            SecureField::zero(),
        );

        let l2_proof = prove_recursive(&l1_proof, &inputs).expect("prove_recursive 应成功");

        // 3. 用篡改的 composition_oods_eval verify（应失败）
        let mut tampered_inputs = inputs.clone();
        tampered_inputs.composition_oods_eval = composition_oods_eval + SecureField::from(1u32);

        let verify_result = verify_recursive(&l2_proof, &tampered_inputs);
        assert!(
            verify_result.is_err(),
            "verify_recursive 应失败（composition_oods_eval 篡改），但成功了"
        );
    }

    // =================================================================
    // v5.1 多组件 verify 测试（OODS + FRI Verifier AIR）
    // =================================================================

    /// v5.1 多组件 verify：正确 proof 应验证通过。
    #[test]
    #[ignore = "P05-R gap #3-B: _with_fri 显式返回 IncompleteMerkleVerifierAir"]
    fn test_verify_recursive_with_fri_succeeds() {
        use super::super::recursion_prover::prove_recursive_with_fri;
        use super::super::trace_gen::{
            extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
        };

        // 1. 生成真实 L1 proof
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        // 2. 构造 public_inputs（含真实 fri_last_layer_poly + fri_query）
        let oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(1, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 1, 0, 0),
        };
        let max_log_degree_bound = 10u32;
        let composition_oods_eval =
            extract_composition_oods_eval_from_l1(&l1_proof, oods_point, max_log_degree_bound)
                .expect("提取 composition_oods_eval 应成功");
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let (fri_query_x, fri_query_eval) = extract_fri_query_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 fri_query 应成功");
        // P05-R gap #1：从 L1 proof 提取真实 commitments/query_positions（见 gap #3 limb 修复）。
        let l1_commitments: Vec<FieldElement252> = l1_proof.0.commitments.iter().copied().collect();
        let query_positions = super::super::trace_gen::extract_query_positions_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 query_positions 应成功");
        let inputs = RecursivePublicInputs::new(
            l1_commitments,
            oods_point,
            composition_oods_eval,
            l1_proof
                .0
                .commitments
                .first()
                .copied()
                .unwrap_or(FieldElement252::ZERO),
            last_layer_poly,
            max_log_degree_bound,
            PcsConfig::default(),
            query_positions,
            10,
            fri_query_x,
            fri_query_eval,
        );

        // 3. prove + verify
        let l2_proof =
            prove_recursive_with_fri(&l1_proof, &inputs).expect("prove_recursive_with_fri 应成功");
        let verify_result = verify_recursive_with_fri(&l2_proof, &inputs);
        assert!(
            verify_result.is_ok(),
            "verify_recursive_with_fri 应成功: {:?}",
            verify_result.err()
        );
    }

    /// v5.1 多组件 verify：篡改 composition_oods_eval 应失败。
    #[test]
    #[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
    fn test_verify_recursive_with_fri_fails_on_tampered_composition_oods_eval() {
        use super::super::recursion_prover::prove_recursive_with_fri;
        use super::super::trace_gen::{
            extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
        };

        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        let oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(1, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 1, 0, 0),
        };
        let max_log_degree_bound = 10u32;
        let composition_oods_eval =
            extract_composition_oods_eval_from_l1(&l1_proof, oods_point, max_log_degree_bound)
                .expect("提取 composition_oods_eval 应成功");
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let (fri_query_x, fri_query_eval) = extract_fri_query_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 fri_query 应成功");
        // P05-R gap #1：从 L1 proof 提取真实 commitments/query_positions（见 gap #3 limb 修复）。
        let l1_commitments: Vec<FieldElement252> = l1_proof.0.commitments.iter().copied().collect();
        let query_positions = super::super::trace_gen::extract_query_positions_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 query_positions 应成功");
        let inputs = RecursivePublicInputs::new(
            l1_commitments,
            oods_point,
            composition_oods_eval,
            l1_proof
                .0
                .commitments
                .first()
                .copied()
                .unwrap_or(FieldElement252::ZERO),
            last_layer_poly,
            max_log_degree_bound,
            PcsConfig::default(),
            query_positions,
            10,
            fri_query_x,
            fri_query_eval,
        );

        let l2_proof =
            prove_recursive_with_fri(&l1_proof, &inputs).expect("prove_recursive_with_fri 应成功");

        // 篡改 composition_oods_eval
        let mut tampered = inputs.clone();
        tampered.composition_oods_eval = composition_oods_eval + SecureField::from(1u32);
        let verify_result = verify_recursive_with_fri(&l2_proof, &tampered);
        assert!(
            verify_result.is_err(),
            "verify_recursive_with_fri 应失败（composition_oods_eval 篡改）"
        );
    }
}
