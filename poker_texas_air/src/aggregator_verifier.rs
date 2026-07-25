//! Aggregator Verifier — 验证二叉树聚合的 Stwo proof。
//!
//! ## 流程
//!
//! 1. 从 `AggregatorProof` 读取 AIR 公开输入 + StarkProof
//! 2. 构造 Channel + CommitmentSchemeVerifier
//! 3. 从 proof 读取 preprocessed + trace commitments
//! 4. 构建 AIR component（与 prover 端使用相同 AIR 实例）
//! 5. 调用 `stwo::core::verifier::verify` 验证 proof
//!
//! ## 简化策略
//!
//! 阶段 4 PoC：只验证顶层聚合的 Stwo proof。
//! 完整版（阶段 5）应递归验证每层 proof + 验证子 proof 的 Stwo verification。

use stwo::core::channel::Poseidon252Channel;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::verifier::{verify, VerificationError};
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::aggregator_air::cols;
use crate::aggregator_prover::AggregatorProof;
use crate::error::{TexasAirError, TexasAirResult};

/// 验证 Aggregator proof。
///
/// # 参数
/// - `proof`: 由 [`crate::aggregator_prover::prove_aggregator`] 生成的 proof
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(TexasAirError)` — 验证失败
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_aggregator(proof: AggregatorProof) -> TexasAirResult<()> {
    let config = PcsConfig::default();
    let log_size = proof.log_size;
    let stark_proof = proof.stark_proof.clone();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0）
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

    // 4. 构建 AIR component（与 prover 端使用相同的 AIR 实例）
    let air = proof.air.clone();
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air,
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 5. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
    .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))?;

    Ok(())
}
