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

use super::fri_verifier_air::{FriVerifierAir, FRI_AIR_NUM_COLUMNS};
use super::merkle_path_air::{MerklePathAir, MERKLE_AIR_NUM_COLUMNS};
use super::oods_check_air::{OodsCheckAir, OODS_AIR_NUM_COLUMNS};
use super::public_inputs::RecursivePublicInputs;
use super::recursion_prover::RecursiveProof;
use super::trace_gen::{compute_fri_trace_log_size, OODS_TRACE_LOG_SIZE};
use ark_ff::Zero;
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::{verify, VerificationError};
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
    if !cfg!(test) {
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

/// L2 proof 验证器（v5.1 多组件：OODS Check AIR + FRI Verifier AIR）。
///
/// 镜像 [`super::recursion_prover::prove_recursive_with_fri`]：
/// 1. `PcsConfig::default()` + `Blake2sChannel` + `CommitmentSchemeVerifier`
/// 2. mix `RecursivePublicInputs` 到 channel（与 prover 相同顺序）
/// 3. 从 proof 读取 preprocessed commitment (tree 0) + trace commitment (tree 1, 109 列)
/// 4. 构建 `OodsCheckAir` + `FriVerifierAir` components（共享 `TraceLocationAllocator`）
/// 5. `verify(&[&oods_component, &fri_component], ...)`
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
    if !cfg!(test) {
        let _ = (l2_proof, public_inputs);
        return Err(RecursionVerificationError::UnsoundBackendDisabled);
    }

    // P05-R gap #1：拒绝空-input L2 proof（镜像 prover 侧守卫）。
    ensure_nonempty_public_inputs(public_inputs)?;

    // P05-R gap #3-B：canonical Merkle/FRI replay 尚未由 Poseidon252/transcript AIR
    // 完整约束。生产构建更早由 UnsoundBackendDisabled 拒绝；此分支覆盖 crate 内测试。
    if !super::MERKLE_VERIFIER_AIR_COMPLETE {
        let _ = l2_proof;
        return Err(RecursionVerificationError::IncompleteMerkleVerifierAir);
    }

    // 计算 unified_log_size（与 prover 完全一致）
    let fri_log_size = compute_fri_trace_log_size(&public_inputs.fri_last_layer_poly);
    let unified_log_size = OODS_TRACE_LOG_SIZE.max(fri_log_size);
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

    // 4. 从 proof 读取 trace commitment（tree 1，OODS 73 cols + FRI 68 cols + Merkle 67 cols = 208 cols）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        RecursionVerificationError::VerificationFailed(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let total_trace_cols = OODS_AIR_NUM_COLUMNS + FRI_AIR_NUM_COLUMNS + MERKLE_AIR_NUM_COLUMNS;
    let trace_log_sizes = vec![unified_log_size; total_trace_cols];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 5. 构建 OODS + FRI + Merkle components（与 prover 相同顺序，共享 TraceLocationAllocator）
    let oods_air = OodsCheckAir::new(unified_log_size);
    let fri_air = FriVerifierAir::new(unified_log_size);
    let merkle_air = MerklePathAir::new(unified_log_size);
    let mut allocator = TraceLocationAllocator::default();
    let oods_component = FrameworkComponent::new(&mut allocator, oods_air, SecureField::zero());
    let fri_component = FrameworkComponent::new(&mut allocator, fri_air, SecureField::zero());
    let merkle_component = FrameworkComponent::new(&mut allocator, merkle_air, SecureField::zero());

    // 6. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&oods_component, &fri_component, &merkle_component],
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
        use super::super::recursion_prover::{prove_recursive, RecursionProvingError};
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
