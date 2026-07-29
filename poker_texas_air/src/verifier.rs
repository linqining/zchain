//! Verifier 入口 — 单方法 verify + 聚合 verify。
//!
//! ## API
//!
//! - [`verify_create_table`] — 验证 `create_table` 方法的 L1 proof
//! - [`verify_method`] — 泛型 verify，支持任意 method AIR（阶段 2-4）
//! - [`verify_aggregator`] — 验证 Aggregator proof

use stwo::core::channel::Poseidon252Channel;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::verifier::{VerificationError, verify};
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, TraceLocationAllocator};

use crate::airs::lifecycle::create_table::{CreateTableAir, cols};
use crate::airs::TexasAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::prover::{CreateTableProof, MethodProof};
use crate::public_inputs::TexasPublicInputs;

/// 验证 `create_table` 方法的 L1 proof。
///
/// # 参数
/// - `proof`: 由 [`crate::prover::prove_create_table`] 生成的 proof
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(TexasAirError)` — 验证失败（proof 伪造、约束不满足等）
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_create_table_against(
    proof: CreateTableProof,
    expected_air: CreateTableAir,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let config = PcsConfig::default();
    expected_public_inputs.verify_roots()?;
    expected_public_inputs.verify_air_statement(&expected_air.statement())?;
    let log_size = expected_air.log_size();
    let stark_proof = &proof.stark_proof;

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    // Only verifier-supplied public inputs define the statement/transcript.
    expected_public_inputs.mix_into(&mut channel);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0，0 列）
    //    prover 提交了空 preprocessed trace，所以 column_log_sizes 为空
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，cols::NUM_COLUMNS 列）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; cols::NUM_COLUMNS];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. Build from the independently reconstructed AIR, never proof.air.
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        expected_air,
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 5. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        proof.stark_proof,
    )
    .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))?;

    Ok(())
}

/// Test-only compatibility entry point. It deliberately trusts proof-carried
/// metadata and is omitted from production builds.
#[cfg(any(test, feature = "test-helpers"))]
pub fn verify_create_table(proof: CreateTableProof) -> TexasAirResult<()> {
    let expected_air = proof.air.clone();
    let expected_public_inputs = proof.public_inputs.clone();
    verify_create_table_against(proof, expected_air, &expected_public_inputs)
}

/// 泛型 method verify — 验证任意 method AIR 的 L1 proof。
///
/// 阶段 2-4 通用 verify 入口。所有 17 个新方法（lifecycle/actions/crypto）
/// 通过此函数验证 proof，无需为每个方法定义专用 verify 函数。
///
/// # 参数
/// - `proof`: 由 [`crate::prover::prove_method`] 生成的 `MethodProof<A>`
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(TexasAirError)` — 验证失败
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_method_against<A>(
    proof: MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()>
where
    A: TexasAir,
{
    let config = PcsConfig::default();
    expected_public_inputs.verify_roots()?;
    expected_public_inputs.verify_air_statement(&expected_air.statement())?;
    let log_size = expected_air.log_size();
    let num_columns = expected_air.trace_num_columns();
    let stark_proof = proof.stark_proof.clone();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    expected_public_inputs.mix_into(&mut channel);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0，空 trace）
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，num_columns 列）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; num_columns];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. Build the component from verifier-trusted AIR data.
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        expected_air,
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 5. 验证
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
    .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))?;

    Ok(())
}

/// Test-only compatibility entry point. Production callers must provide an
/// independently trusted statement through [`verify_method_against`].
#[cfg(any(test, feature = "test-helpers"))]
pub fn verify_method<A>(proof: MethodProof<A>) -> TexasAirResult<()>
where
    A: TexasAir,
{
    let expected_air = proof.air.clone();
    let expected_public_inputs = proof.public_inputs.clone();
    verify_method_against(proof, expected_air, &expected_public_inputs)
}

/// 验证 Aggregator proof。
///
/// 委托给 [`crate::aggregator_verifier::verify_aggregator`]。
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_aggregator(proof: crate::aggregator_prover::AggregatorProof) -> TexasAirResult<()> {
    crate::aggregator_verifier::verify_aggregator(proof)
}
