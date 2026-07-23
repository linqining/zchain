//! # Recursion Verifier — L2 proof 验证器（Phase 5 — v5.0）
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

use super::oods_check_air::{OodsCheckAir, OODS_AIR_NUM_COLUMNS};
use super::fri_verifier_air::{FriVerifierAir, FRI_AIR_NUM_COLUMNS};
use super::merkle_path_air::{MerklePathAir, MERKLE_AIR_NUM_COLUMNS};
use super::public_inputs::RecursivePublicInputs;
use super::recursion_prover::RecursiveProof;
use super::trace_gen::{compute_fri_trace_log_size, OODS_TRACE_LOG_SIZE};
use ark_ff::Zero;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::verifier::{verify, VerificationError};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

/// Recursion verifier 错误类型。
#[derive(Debug, thiserror::Error)]
pub enum RecursionVerificationError {
    /// L2 proof 验证失败。
    #[error("L2 proof verification failed: {0}")]
    VerificationFailed(String),
    /// 公开输入不匹配。
    #[error("Public inputs mismatch")]
    PublicInputsMismatch,
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

    // 4. 从 proof 读取 trace commitment（tree 1，OODS 73 cols + FRI 68 cols + Merkle 60 cols = 201 cols）
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
/// # Mix 顺序
/// 1. `PcsConfig`（用 Stwo 原生 `mix_into`，包含 pow_bits + FriConfig + lifting_log_size）
/// 2. `max_log_degree_bound`（u32）
/// 3. `composition_oods_eval`（SecureField）
/// 4. `oods_point.x` + `oods_point.y`（2 × SecureField）
/// 5. `fri_last_layer_poly` 系数（v5.1 soundness fix，bit-reversed 表示）
/// 6. `fri_query_x` + `fri_query_eval`（v5.2 soundness fix）
fn mix_public_inputs_into_channel(channel: &mut Blake2sChannel, inputs: &RecursivePublicInputs) {
    // 1. PcsConfig
    inputs.config.mix_into(channel);

    // 2. max_log_degree_bound
    channel.mix_u32s(&[inputs.max_log_degree_bound]);

    // 3. composition_oods_eval
    channel.mix_felts(&[inputs.composition_oods_eval]);

    // 4. oods_point（x, y）
    channel.mix_felts(&[inputs.oods_point.x, inputs.oods_point.y]);

    // 5. fri_last_layer_poly 系数（v5.1 soundness fix）
    // 将 last_layer_poly 的所有系数 mix 到 channel，绑定 poly 到 L2 proof。
    // 这关闭了 v5.1 soundness gap：之前 poly 未 mix，verifier 无法检测 poly 篡改。
    // 注：LinePoly 内部存储为 bit-reversed 系数，prover 和 verifier 都用相同表示，
    // 所以 mix bit-reversed 系数是 soundness-preserving 的。
    channel.mix_felts(&inputs.fri_last_layer_poly[..]);

    // 6. fri_query_x + fri_query_eval（v5.2 soundness fix）
    // 将 FRI query point 和 evaluation mix 到 channel，绑定到 L2 Fiat-Shamir。
    // 防止 prover 选择在特定 x 处通过但其他点失败的伪造多项式。
    channel.mix_felts(&[inputs.fri_query_x, inputs.fri_query_eval]);
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
    use stwo::core::circle::CirclePoint;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::poly::line::LinePoly;
    use starknet_ff::FieldElement as FieldElement252;

    /// 创建测试用 RecursivePublicInputs（使用任意 composition_oods_eval，
    /// 仅用于 verifier 单元测试，不调用 prove_recursive）。
    fn make_test_public_inputs(composition_oods_eval: SecureField) -> RecursivePublicInputs {
        RecursivePublicInputs::new(
            Vec::new(),
            CirclePoint::zero(),
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            10,
            PcsConfig::default(),
            Vec::new(),
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
        let err = RecursionVerificationError::from(VerificationError::InvalidStructure("test".to_string()));
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
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            &l1_proof,
            oods_point,
            max_log_degree_bound,
        )
        .expect("提取 composition_oods_eval 应成功");
        let inputs = RecursivePublicInputs::new(
            Vec::new(),
            oods_point,
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            max_log_degree_bound,
            PcsConfig::default(),
            Vec::new(),
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
    fn test_verify_recursive_with_fri_succeeds() {
        use super::super::recursion_prover::prove_recursive_with_fri;
        use super::super::trace_gen::{extract_composition_oods_eval_from_l1, extract_fri_query_from_l1};

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
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            &l1_proof,
            oods_point,
            max_log_degree_bound,
        )
        .expect("提取 composition_oods_eval 应成功");
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let (fri_query_x, fri_query_eval) = extract_fri_query_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 fri_query 应成功");
        let inputs = RecursivePublicInputs::new(
            Vec::new(),
            oods_point,
            composition_oods_eval,
            FieldElement252::ZERO,
            last_layer_poly,
            max_log_degree_bound,
            PcsConfig::default(),
            Vec::new(),
            10,
            fri_query_x,
            fri_query_eval,
        );

        // 3. prove + verify
        let l2_proof = prove_recursive_with_fri(&l1_proof, &inputs)
            .expect("prove_recursive_with_fri 应成功");
        let verify_result = verify_recursive_with_fri(&l2_proof, &inputs);
        assert!(
            verify_result.is_ok(),
            "verify_recursive_with_fri 应成功: {:?}",
            verify_result.err()
        );
    }

    /// v5.1 多组件 verify：篡改 composition_oods_eval 应失败。
    #[test]
    fn test_verify_recursive_with_fri_fails_on_tampered_composition_oods_eval() {
        use super::super::recursion_prover::prove_recursive_with_fri;
        use super::super::trace_gen::{extract_composition_oods_eval_from_l1, extract_fri_query_from_l1};

        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let l1_proof = prove_cpu_trace(&trace).expect("L1 prove 应成功");

        let oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(1, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 1, 0, 0),
        };
        let max_log_degree_bound = 10u32;
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            &l1_proof,
            oods_point,
            max_log_degree_bound,
        )
        .expect("提取 composition_oods_eval 应成功");
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        let (fri_query_x, fri_query_eval) = extract_fri_query_from_l1(
            &l1_proof,
            PcsConfig::default(),
            max_log_degree_bound,
            &last_layer_poly,
        )
        .expect("提取 fri_query 应成功");
        let inputs = RecursivePublicInputs::new(
            Vec::new(),
            oods_point,
            composition_oods_eval,
            FieldElement252::ZERO,
            last_layer_poly,
            max_log_degree_bound,
            PcsConfig::default(),
            Vec::new(),
            10,
            fri_query_x,
            fri_query_eval,
        );

        let l2_proof = prove_recursive_with_fri(&l1_proof, &inputs)
            .expect("prove_recursive_with_fri 应成功");

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
