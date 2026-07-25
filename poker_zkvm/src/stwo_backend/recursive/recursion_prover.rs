//! # Recursion Prover — 聚合 4 个 Verifier AIR 的 L2 prover（Phase 5 — v5.1）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §8.1。
//!
//! ## v5.1 实现
//!
//! 实现 OODS Check AIR 单组件 prove（含 composition eval soundness）：
//! 1. **Prover 端 consistency check**：验证 `public_inputs.composition_oods_eval` 与
//!    L1 proof 的 `sampled_values` 推导值一致（提前失败，避免 Stwo 内部 panic）
//! 2. 生成 OODS Check AIR trace（`gen_oods_check_trace`，73 列 × 4 行）
//! 3. mix `RecursivePublicInputs` 到 channel（Fiat-Shamir soundness）
//! 4. 提交空 preprocessed trace (tree 0) + original trace (tree 1, 73 列)
//! 5. 构建 `OodsCheckAir` component + `prove`
//!
//! ## v5.1 多组件 prove（OODS + FRI）
//!
//! `prove_recursive_with_fri` 在单组件基础上新增 FRI Verifier AIR 作为第二个 component：
//! 1. 计算 `unified_log_size = max(OODS_TRACE_LOG_SIZE, compute_fri_trace_log_size(...))`
//! 2. 生成 OODS trace，用 `pad_oods_trace_to_log_size` pad 到 `unified_log_size`
//! 3. 生成 FRI trace（自然 `unified_log_size`）
//! 4. Tree 1: OODS (73 cols) + FRI (36 cols) = 109 cols，统一 `unified_log_size`
//! 5. 构建 OODS component + FRI component（共享 `TraceLocationAllocator`）
//! 6. `prove(&[&oods_component, &fri_component], ...)`
//!
//! v5.2 将扩展为 4 个 Verifier AIR 的多组件聚合 proof。

use super::oods_check_air::{OodsCheckAir, OODS_AIR_NUM_COLUMNS};
use super::fri_verifier_air::{FriVerifierAir, FRI_AIR_NUM_COLUMNS};
use super::merkle_path_air::{MerklePathAir, MERKLE_AIR_NUM_COLUMNS};
use super::public_inputs::RecursivePublicInputs;
use super::trace_gen::{
    compute_fri_trace_log_size, extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
    gen_fri_verifier_trace, gen_merkle_path_trace, gen_oods_check_trace, pad_fri_trace_to_log_size,
    pad_merkle_trace_to_log_size, pad_oods_trace_to_log_size, OODS_TRACE_LOG_SIZE,
};
use ark_ff::Zero;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::channel::{Blake2sChannel, Channel, Poseidon252Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::poseidon252_merkle::{Poseidon252MerkleChannel, Poseidon252MerkleHasher};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, ProvingError};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

/// L2 recursive proof（封装 StarkProof）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecursiveProof(pub StarkProof<Blake2sMerkleHasher>);

/// Recursion prover 错误类型。
#[derive(Debug, thiserror::Error)]
pub enum RecursionProvingError {
    /// L1 proof 在 recursion 过程中验证失败。
    #[error("L1 proof verification failed during recursion")]
    L1VerificationFailed,
    /// Stwo prover 内部错误。
    #[error("Stwo proving error: {0}")]
    StwoError(String),
    /// Prover 端 consistency check 失败：`public_inputs.composition_oods_eval` 与 L1 proof 不一致。
    #[error("composition_oods_eval mismatch: public_inputs claims {claimed}, but L1 proof sampled_values derive {derived}")]
    CompositionOodsEvalMismatch {
        /// public_inputs 中声称的 composition_oods_eval
        claimed: SecureField,
        /// 从 L1 proof sampled_values 推导的 composition_oods_eval
        derived: SecureField,
    },
    /// Prover 端 consistency check 失败：`public_inputs.fri_query_x` / `fri_query_eval`
    /// 与从 L1 proof Fiat-Shamir transcript 重新推导的值不一致。
    #[error("fri_query mismatch: claimed_x={claimed_x}, derived_x={derived_x}, claimed_eval={claimed_eval}, derived_eval={derived_eval}")]
    FriQueryMismatch {
        /// public_inputs 中声称的 fri_query_x
        claimed_x: SecureField,
        /// 从 L1 transcript 推导的 fri_query_x
        derived_x: SecureField,
        /// public_inputs 中声称的 fri_query_eval
        claimed_eval: SecureField,
        /// 从 L1 transcript 推导的 fri_query_eval
        derived_eval: SecureField,
    },
    /// L1 proof 结构不匹配（sampled_values 缺失或格式错误）。
    #[error("L1 proof structure invalid: {0}")]
    L1ProofStructureInvalid(String),
}

impl From<ProvingError> for RecursionProvingError {
    fn from(e: ProvingError) -> Self {
        RecursionProvingError::StwoError(e.to_string())
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// 聚合 4 个 Verifier AIR 的 L2 prover（v5.1：OODS Check AIR 单组件 + composition eval soundness）。
///
/// # v5.1 流程
/// 1. **Prover 端 consistency check**：用 `extract_composition_oods_eval_from_l1`
///    从 L1 proof 的 `sampled_values` 推导 `composition_oods_eval`，验证与
///    `public_inputs.composition_oods_eval` 一致（提前失败，避免 Stwo 内部 panic）
/// 2. 生成 OODS Check AIR trace（73 列 × 4 行，含 sampled_values + QM31 乘法中间值）
/// 3. `PcsConfig::default()` + `SimdBackend::precompute_twiddles`
/// 4. `Blake2sChannel::default()` + `CommitmentSchemeProver`
/// 5. mix `RecursivePublicInputs` 到 channel（Fiat-Shamir soundness）
/// 6. 提交 Tree 0（空 preprocessed）+ Tree 1（73 列 original trace）
/// 7. `FrameworkComponent::new(allocator, OodsCheckAir, SecureField::zero())`
/// 8. `prove(&[&component], ...) → StarkProof`
///
/// # 参数
/// - `l1_proof` — L1 Stwo proof（v5.1 从中提取 `sampled_values`）
/// - `public_inputs` — L2 proof 的公开输入（包含 L1 proof 的公开承诺）
///
/// # 返回
/// `RecursiveProof` — 可由 [`verify_recursive`] 验证
///
/// # 错误
/// - `RecursionProvingError::CompositionOodsEvalMismatch` — prover 端 consistency check 失败
/// - `RecursionProvingError::L1ProofStructureInvalid` — L1 proof 结构不匹配
/// - `RecursionProvingError::StwoError` — Stwo prover 内部错误（AIR 约束不满足等）
///
/// # v5.1 soundness 说明
/// v5.1 的 ComputedOodsEval 由 L1 proof 的 `sampled_values` 推导（非 trivial）：
/// - AIR 约束 O6-O33 强制 Computed = Left + Product（per M31 component）
/// - AIR 约束 O34-O37 强制 ComputedOodsEval = LeftEval + Product（QM31 乘法分解）
/// - AIR 约束 O2-O5 强制 ClaimedOodsEval == ComputedOodsEval
///
/// 如果 `public_inputs.composition_oods_eval` 与 L1 proof 实际值不一致：
/// - Prover 端 consistency check 会提前失败（返回 `CompositionOodsEvalMismatch`）
/// - 即使绕过 prover check，AIR 约束 O2-O5 也会导致 Stwo prover 返回 `ConstraintsNotSatisfied`
#[allow(clippy::missing_errors_doc)]
pub fn prove_recursive(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Result<RecursiveProof, RecursionProvingError> {
    let log_size = OODS_TRACE_LOG_SIZE;

    // 1. Prover 端 consistency check（v5.1 新增）
    // 提前验证 public_inputs.composition_oods_eval 与 L1 proof 一致，
    // 避免下游 gen_oods_check_trace 生成的 trace 违反 AIR 约束 O2-O5。
    let derived_eval = extract_composition_oods_eval_from_l1(
        l1_proof,
        public_inputs.oods_point,
        public_inputs.max_log_degree_bound,
    )
    .ok_or_else(|| {
        RecursionProvingError::L1ProofStructureInvalid(
            "无法从 L1 proof 提取 composition_oods_eval（sampled_values 结构不匹配）".to_string(),
        )
    })?;

    if derived_eval != public_inputs.composition_oods_eval {
        return Err(RecursionProvingError::CompositionOodsEvalMismatch {
            claimed: public_inputs.composition_oods_eval,
            derived: derived_eval,
        });
    }

    // 2. 生成 OODS Check AIR trace（73 列 × 4 行）
    let trace_cols = gen_oods_check_trace(l1_proof, public_inputs);
    assert_eq!(
        trace_cols.len(),
        OODS_AIR_NUM_COLUMNS,
        "OODS trace 列数={}，期望={OODS_AIR_NUM_COLUMNS}",
        trace_cols.len()
    );

    // 3. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 4. Channel + CommitmentSchemeProver
    let mut channel = Blake2sChannel::default();

    // 5. mix RecursivePublicInputs 到 channel（Fiat-Shamir）
    mix_public_inputs_into_channel(&mut channel, public_inputs);

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // 6. 提交空 preprocessed trace（tree 0）
    // OodsCheckAir 无 preprocessed columns
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 7. 提交 original trace（tree 1，73 列）
    {
        let columns = trace_cols_to_evaluations(&trace_cols, log_size);
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 8. 构建 OodsCheckAir component
    let air = OodsCheckAir::new(log_size);
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air, SecureField::zero());

    // 9. 生成证明
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)?;
    Ok(RecursiveProof(stark_proof))
}

/// 聚合 OODS Check AIR + FRI Verifier AIR 的多组件 L2 prover（v5.1 多组件）。
///
/// 在 [`prove_recursive`] 的基础上，新增 FRI Verifier AIR 作为第二个 component，
/// 验证 L1 proof 的 FRI last_layer check：`query_eval == last_layer_poly.eval_at_point(x)`。
///
/// # v5.1 多组件流程
///
/// 1. **Prover 端 consistency check**（同 `prove_recursive`）
/// 2. 计算 `unified_log_size = max(OODS_TRACE_LOG_SIZE, compute_fri_trace_log_size(last_layer_poly))`
/// 3. 生成 OODS trace（73 cols × 4 rows），用 `pad_oods_trace_to_log_size` pad到 `unified_log_size`
/// 4. 生成 FRI trace（36 cols × `2^unified_log_size` rows）
/// 5. `PcsConfig::default()` + `SimdBackend::precompute_twiddles`（domain = `unified_log_size + blowup`）
/// 6. `Blake2sChannel::default()` + `CommitmentSchemeProver`
/// 7. mix `RecursivePublicInputs` 到 channel（Fiat-Shamir soundness）
/// 8. 提交 Tree 0（空 preprocessed）+ Tree 1（OODS 73 cols + FRI 36 cols = 109 cols）
/// 9. 构建 `OodsCheckAir` component + `FriVerifierAir` component（共享 `TraceLocationAllocator`）
/// 10. `prove(&[&oods_component, &fri_component], ...) → StarkProof`
///
/// # 多组件 log_size 统一
///
/// Stwo 要求同一 committed tree 中所有列必须有相同 log_size。
/// OODS trace 自然 log_size=2（4 rows），FRI trace 自然 log_size 取决于 `last_layer_poly.len()`。
/// 此函数用 `pad_oods_trace_to_log_size` 将 OODS trace pad 到 `unified_log_size`，
/// 同时将 `FriVerifierAir::new(unified_log_size)` 和 `OodsCheckAir::new(unified_log_size)`
/// 都用统一 log_size 构造。
///
/// # 参数
/// - `l1_proof` — L1 Stwo proof
/// - `public_inputs` — L2 proof 的公开输入
///
/// # 返回
/// `RecursiveProof` — 可由 [`super::recursion_verifier::verify_recursive_with_fri`] 验证
///
/// # 错误
/// 同 [`prove_recursive`]，加上 FRI trace 生成可能触发的 panic（如 `last_layer_poly` 为空）。
#[allow(clippy::missing_errors_doc)]
pub fn prove_recursive_with_fri(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Result<RecursiveProof, RecursionProvingError> {
    // 1. Prover 端 consistency check（同 prove_recursive）
    let derived_eval = extract_composition_oods_eval_from_l1(
        l1_proof,
        public_inputs.oods_point,
        public_inputs.max_log_degree_bound,
    )
    .ok_or_else(|| {
        RecursionProvingError::L1ProofStructureInvalid(
            "无法从 L1 proof 提取 composition_oods_eval（sampled_values 结构不匹配）".to_string(),
        )
    })?;

    if derived_eval != public_inputs.composition_oods_eval {
        return Err(RecursionProvingError::CompositionOodsEvalMismatch {
            claimed: public_inputs.composition_oods_eval,
            derived: derived_eval,
        });
    }

    // 1b. Prover 端 FRI query consistency check（v5.2 soundness fix）
    // 验证 public_inputs.fri_query_x / fri_query_eval 与从 L1 proof Fiat-Shamir transcript
    // 重新推导的值一致。防止 prover 伪造 query point。
    let (derived_x, derived_fri_eval) = extract_fri_query_from_l1(
        l1_proof,
        public_inputs.config,
        public_inputs.max_log_degree_bound,
        &public_inputs.fri_last_layer_poly,
    )
    .ok_or_else(|| {
        RecursionProvingError::L1ProofStructureInvalid(
            "无法从 L1 proof 提取 fri_query（commitment 数量不足或 FriVerifier 构造失败）".to_string(),
        )
    })?;

    if derived_x != public_inputs.fri_query_x || derived_fri_eval != public_inputs.fri_query_eval {
        return Err(RecursionProvingError::FriQueryMismatch {
            claimed_x: public_inputs.fri_query_x,
            derived_x,
            claimed_eval: public_inputs.fri_query_eval,
            derived_eval: derived_fri_eval,
        });
    }

    // 2. 计算 unified_log_size
    let fri_log_size = compute_fri_trace_log_size(&public_inputs.fri_last_layer_poly);
    let unified_log_size = OODS_TRACE_LOG_SIZE.max(fri_log_size);

    // 3. 生成 OODS trace 并 pad 到 unified_log_size
    let oods_trace_cols = gen_oods_check_trace(l1_proof, public_inputs);
    assert_eq!(
        oods_trace_cols.len(),
        OODS_AIR_NUM_COLUMNS,
        "OODS trace 列数={}，期望={OODS_AIR_NUM_COLUMNS}",
        oods_trace_cols.len()
    );
    let oods_trace_padded = pad_oods_trace_to_log_size(oods_trace_cols, unified_log_size);

    // 4. 生成 FRI trace（自然 unified_log_size，因为 unified_log_size >= fri_log_size）
    // 注：gen_fri_verifier_trace 使用 public_inputs.fri_last_layer_poly 计算 num_rows，
    // 当 unified_log_size > fri_log_size 时，FRI trace 的行数 < 2^unified_log_size，
    // 需要额外 pad 到 unified_log_size。
    let fri_trace_cols = gen_fri_verifier_trace(l1_proof, public_inputs);
    assert_eq!(
        fri_trace_cols.len(),
        FRI_AIR_NUM_COLUMNS,
        "FRI trace 列数={}，期望={FRI_AIR_NUM_COLUMNS}",
        fri_trace_cols.len()
    );
    let fri_trace_padded = pad_fri_trace_to_log_size(fri_trace_cols, unified_log_size);

    // 5. 生成 Merkle Path trace（v5.1 新增）
    let merkle_trace_cols = gen_merkle_path_trace(l1_proof, public_inputs);
    let merkle_trace_padded = if merkle_trace_cols.is_empty() {
        vec![vec![BaseField::zero(); 1usize << unified_log_size]; MERKLE_AIR_NUM_COLUMNS]
    } else {
        assert_eq!(
            merkle_trace_cols.len(),
            MERKLE_AIR_NUM_COLUMNS,
            "Merkle trace 列数={}，期望={MERKLE_AIR_NUM_COLUMNS}",
            merkle_trace_cols.len()
        );
        pad_merkle_trace_to_log_size(merkle_trace_cols, unified_log_size)
    };

    // 6. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(unified_log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 7. Channel + CommitmentSchemeProver
    let mut channel = Blake2sChannel::default();

    // 8. mix RecursivePublicInputs 到 channel（与 prove_recursive 相同顺序）
    mix_public_inputs_into_channel(&mut channel, public_inputs);

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // 9. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 10. 提交 original trace（tree 1，OODS 73 cols + FRI 68 cols + Merkle 60 cols = 201 cols）
    {
        let oods_evals = trace_cols_to_evaluations(&oods_trace_padded, unified_log_size);
        let fri_evals = trace_cols_to_evaluations(&fri_trace_padded, unified_log_size);
        let merkle_evals = trace_cols_to_evaluations(&merkle_trace_padded, unified_log_size);
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(oods_evals);
        tree_builder.extend_evals(fri_evals);
        tree_builder.extend_evals(merkle_evals);
        tree_builder.commit(&mut channel);
    }

    // 11. 构建 OODS + FRI + Merkle components（共享 TraceLocationAllocator）
    let oods_air = OodsCheckAir::new(unified_log_size);
    let fri_air = FriVerifierAir::new(unified_log_size);
    let merkle_air = MerklePathAir::new(unified_log_size);
    let mut allocator = TraceLocationAllocator::default();
    let oods_component = FrameworkComponent::new(&mut allocator, oods_air, SecureField::zero());
    let fri_component = FrameworkComponent::new(&mut allocator, fri_air, SecureField::zero());
    let merkle_component = FrameworkComponent::new(&mut allocator, merkle_air, SecureField::zero());

    // 12. 生成多组件证明（3 个 AIR）
    let stark_proof = prove(
        &[&oods_component, &fri_component, &merkle_component],
        &mut channel,
        commitment_scheme,
    )?;
    Ok(RecursiveProof(stark_proof))
}

// ===========================================================================
// Helper functions
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
///
/// # v5.1 扩展
/// 将追加 mix：`l1_commitments`（每个 Blake2sHash）+ `fri_first_layer_commitment`
/// + `fri_last_layer_poly`（通过 `into_ordered_coefficients`）。
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

/// 将 `Vec<Vec<BaseField>>` trace 转换为 Stwo `CircleEvaluation` 列。
///
/// # 算法
/// 对每列：
/// 1. `BaseColumn::from_cpu(&col)` — `&[M31]` → `BaseColumn`（SIMD 友好）
/// 2. `CircleEvaluation::new(domain, base_col)` — 在 canonical coset 上构造求值
/// 3. `.bit_reverse()` — 转换为 `BitReversedOrder`（Stwo 提交要求）
fn trace_cols_to_evaluations(
    cols: &[Vec<BaseField>],
    log_size: u32,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    cols.iter()
        .map(|col| {
            assert_eq!(
                col.len(),
                1usize << log_size,
                "trace 列长度={}，期望 2^{log_size}={}",
                col.len(),
                1usize << log_size
            );
            let base_col = BaseColumn::from_cpu(col.as_slice());
            CircleEvaluation::<SimdBackend, BaseField>::new(domain, base_col).bit_reverse()
        })
        .collect()
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
    use stwo::core::poly::line::LinePoly;
    use stwo::core::vcs::blake2_hash::Blake2sHash;

    /// 测试用 OODS point（任意非零值，确保 `repeated_double` 不退化为零）。
    ///
    /// **注意**：v5.1 中 `composition_oods_eval` 必须从 L1 proof 提取，且与 `oods_point` +
    /// `max_log_degree_bound` 严格绑定。修改 `oods_point` 会改变 `doubling_factor.x`，
    /// 从而改变 `composition_oods_eval` 的推导值。
    const TEST_OODS_POINT: CirclePoint<SecureField> = CirclePoint {
        x: SecureField::from_u32_unchecked(1, 0, 0, 0),
        y: SecureField::from_u32_unchecked(0, 1, 0, 0),
    };

    /// 测试用 max_log_degree_bound。
    const TEST_MAX_LOG_DEGREE_BOUND: u32 = 10;

    /// 生成一个真实的 L1 Stwo proof（用于 `prove_recursive` 的 l1_proof 参数）。
    ///
    /// 使用 padding-only CPU trace（log_size=10，1024 行），prove_cpu_trace 生成。
    fn make_l1_proof() -> StarkProof<Poseidon252MerkleHasher> {
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        prove_cpu_trace(&trace).expect("L1 prove 应成功（全 padding trace）")
    }

    /// 创建测试用 RecursivePublicInputs，使用从 L1 proof 提取的真实 composition_oods_eval。
    ///
    /// v5.1 中 `composition_oods_eval` 必须与 L1 proof 的 sampled_values 一致，
    /// 否则 `prove_recursive` 的 prover 端 consistency check 会失败。
    fn make_test_public_inputs_from_l1(
        l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    ) -> RecursivePublicInputs {
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            l1_proof,
            TEST_OODS_POINT,
            TEST_MAX_LOG_DEGREE_BOUND,
        )
        .expect("提取 composition_oods_eval 应成功");
        RecursivePublicInputs::new(
            Vec::new(),
            TEST_OODS_POINT,
            composition_oods_eval,
            FieldElement252::ZERO,
            LinePoly::new(vec![SecureField::zero()]),
            TEST_MAX_LOG_DEGREE_BOUND,
            PcsConfig::default(),
            Vec::new(),
            10,
            SecureField::zero(),
            SecureField::zero(),
        )
    }

    #[test]
    fn test_recursion_proving_error_display() {
        let err = RecursionProvingError::L1VerificationFailed;
        assert_eq!(
            err.to_string(),
            "L1 proof verification failed during recursion"
        );
    }

    #[test]
    fn test_recursion_proving_error_from_proving_error() {
        let err = RecursionProvingError::from(ProvingError::ConstraintsNotSatisfied);
        assert!(matches!(
            err,
            RecursionProvingError::StwoError(_)
        ));
    }

    #[test]
    fn test_recursion_proving_error_composition_oods_eval_mismatch_display() {
        let err = RecursionProvingError::CompositionOodsEvalMismatch {
            claimed: SecureField::from(1u32),
            derived: SecureField::from(2u32),
        };
        let s = err.to_string();
        assert!(s.contains("composition_oods_eval mismatch"), "实际: {s}");
        // 模板: "public_inputs claims {claimed}, but L1 proof sampled_values derive {derived}"
        assert!(s.contains("public_inputs claims"), "实际: {s}");
        assert!(s.contains("L1 proof sampled_values derive"), "实际: {s}");
        // 验证 SecureField Display 值（QM31 = `(a + bi) + (c + di)u`）
        assert!(s.contains("(1 + 0i)"), "实际: {s}");
        assert!(s.contains("(2 + 0i)"), "实际: {s}");
    }

    #[test]
    fn test_recursion_proving_error_l1_proof_structure_invalid_display() {
        let err = RecursionProvingError::L1ProofStructureInvalid("bad structure".to_string());
        let s = err.to_string();
        assert!(s.contains("L1 proof structure invalid"), "实际: {s}");
        assert!(s.contains("bad structure"), "实际: {s}");
    }

    #[test]
    fn test_trace_cols_to_evaluations_dimensions() {
        let log_size = 2u32;
        let num_rows = 1usize << log_size;
        let cols: Vec<Vec<BaseField>> = (0..OODS_AIR_NUM_COLUMNS)
            .map(|i| {
                (0..num_rows)
                    .map(|j| BaseField::from((i + j) as u32))
                    .collect()
            })
            .collect();

        let evals = trace_cols_to_evaluations(&cols, log_size);
        assert_eq!(evals.len(), OODS_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_mix_public_inputs_is_deterministic() {
        // 相同的 public_inputs 应该产生相同的 channel state
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_from_l1(&l1_proof);

        let mut ch1 = Blake2sChannel::default();
        let mut ch2 = Blake2sChannel::default();
        mix_public_inputs_into_channel(&mut ch1, &inputs);
        mix_public_inputs_into_channel(&mut ch2, &inputs);

        // draw 一个 SecureField，验证两个 channel 状态一致
        let v1 = ch1.draw_secure_felt();
        let v2 = ch2.draw_secure_felt();
        assert_eq!(v1, v2);
    }

    /// v5.1 prove/verify roundtrip 测试 — OODS Check AIR 单组件 + composition eval soundness。
    ///
    /// 验证：用真实 L1 proof 提取的 composition_oods_eval，prove_recursive 应成功。
    #[test]
    fn test_prove_recursive_succeeds() {
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_from_l1(&l1_proof);

        let result = prove_recursive(&l1_proof, &inputs);
        assert!(result.is_ok(), "prove_recursive 应成功: {:?}", result.err());
        let recursive_proof = result.unwrap();
        assert!(
            recursive_proof.0.commitments.len() >= 3,
            "L2 proof 应包含 ≥3 个 commitments，实际 {}",
            recursive_proof.0.commitments.len()
        );
    }

    /// v5.1 prove/verify roundtrip — 完整 roundtrip 应成功。
    #[test]
    fn test_prove_verify_roundtrip_recursive() {
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_from_l1(&l1_proof);

        // prove
        let l2_proof = prove_recursive(&l1_proof, &inputs).expect("prove_recursive 失败");

        // verify（相同 public_inputs）
        let verify_result = super::super::recursion_verifier::verify_recursive(&l2_proof, &inputs);
        assert!(
            verify_result.is_ok(),
            "verify_recursive 应成功: {:?}",
            verify_result.err()
        );
    }

    /// v5.1 soundness 测试 1 — 篡改 public_inputs.composition_oods_eval 应导致 prove 失败。
    ///
    /// prover 端 consistency check 会检测到 mismatch，返回 `CompositionOodsEvalMismatch`。
    #[test]
    fn test_prove_fails_with_tampered_composition_oods_eval() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_test_public_inputs_from_l1(&l1_proof);

        // 篡改 composition_oods_eval（添加 1）
        inputs.composition_oods_eval = inputs.composition_oods_eval + SecureField::from(1u32);

        let result = prove_recursive(&l1_proof, &inputs);
        assert!(
            result.is_err(),
            "prove_recursive 应失败（composition_oods_eval 不匹配），但成功了"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, RecursionProvingError::CompositionOodsEvalMismatch { .. }),
            "期望 CompositionOodsEvalMismatch，实际: {err}"
        );
    }

    /// v5.1 soundness 测试 2 — 篡改 verify 时的 public_inputs 应导致 verify 失败。
    ///
    /// prove 时使用正确的 composition_oods_eval，verify 时篡改 oods_point，
    /// channel state 不一致 → verify 失败。
    #[test]
    fn test_verify_fails_with_mismatched_public_inputs() {
        let l1_proof = make_l1_proof();
        let inputs_prove = make_test_public_inputs_from_l1(&l1_proof);

        // prove
        let l2_proof = prove_recursive(&l1_proof, &inputs_prove).expect("prove_recursive 失败");

        // 创建篡改的 public_inputs（修改 oods_point，但不改 composition_oods_eval，
        // 使 channel state 不一致）
        let mut inputs_verify = inputs_prove.clone();
        inputs_verify.oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(2, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 2, 0, 0),
        };

        // verify（篡改 public_inputs）
        let verify_result = super::super::recursion_verifier::verify_recursive(&l2_proof, &inputs_verify);
        assert!(
            verify_result.is_err(),
            "verify_recursive 应失败（public_inputs 不匹配），但成功了"
        );
    }

    // =================================================================
    // v5.1 多组件 proof 测试（OODS + FRI Verifier AIR）
    // =================================================================

    /// 创建带真实 `fri_last_layer_poly` 的测试 `RecursivePublicInputs`，
    /// 同时使用从 L1 proof 提取的真实 `composition_oods_eval` 和 `fri_query`。
    fn make_test_public_inputs_with_fri_from_l1(
        l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    ) -> RecursivePublicInputs {
        let composition_oods_eval = extract_composition_oods_eval_from_l1(
            l1_proof,
            TEST_OODS_POINT,
            TEST_MAX_LOG_DEGREE_BOUND,
        )
        .expect("提取 composition_oods_eval 应成功");
        let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
        // v5.2：从 L1 proof 的 Fiat-Shamir transcript 提取真实 FRI query point
        let (fri_query_x, fri_query_eval) = extract_fri_query_from_l1(
            l1_proof,
            PcsConfig::default(),
            TEST_MAX_LOG_DEGREE_BOUND,
            &last_layer_poly,
        )
        .expect("提取 fri_query 应成功");
        RecursivePublicInputs::new(
            Vec::new(),
            TEST_OODS_POINT,
            composition_oods_eval,
            FieldElement252::ZERO,
            last_layer_poly,
            TEST_MAX_LOG_DEGREE_BOUND,
            PcsConfig::default(),
            Vec::new(),
            10,
            fri_query_x,
            fri_query_eval,
        )
    }

    /// v5.1 多组件 prove 应成功：OODS + FRI Verifier AIR 联合 proof。
    #[test]
    fn test_prove_recursive_with_fri_succeeds() {
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        let result = prove_recursive_with_fri(&l1_proof, &inputs);
        assert!(
            result.is_ok(),
            "prove_recursive_with_fri 应成功: {:?}",
            result.err()
        );
        let recursive_proof = result.unwrap();
        // 多组件 proof 应包含 ≥3 个 commitments（tree 0 空 + tree 1 trace + tree 2 composition）
        assert!(
            recursive_proof.0.commitments.len() >= 3,
            "L2 multi-component proof 应包含 ≥3 个 commitments，实际 {}",
            recursive_proof.0.commitments.len()
        );
    }

    /// v5.1 多组件 prove/verify roundtrip 应成功。
    #[test]
    fn test_prove_verify_roundtrip_recursive_with_fri() {
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // prove
        let l2_proof =
            prove_recursive_with_fri(&l1_proof, &inputs).expect("prove_recursive_with_fri 失败");

        // verify（相同 public_inputs）
        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri(&l2_proof, &inputs);
        assert!(
            verify_result.is_ok(),
            "verify_recursive_with_fri 应成功: {:?}",
            verify_result.err()
        );
    }

    /// v5.1 多组件 soundness 测试 — 篡改 composition_oods_eval 应导致 prove 失败。
    #[test]
    fn test_prove_with_fri_fails_on_tampered_composition_oods_eval() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // 篡改 composition_oods_eval
        inputs.composition_oods_eval = inputs.composition_oods_eval + SecureField::from(1u32);

        let result = prove_recursive_with_fri(&l1_proof, &inputs);
        assert!(
            result.is_err(),
            "prove_recursive_with_fri 应失败（composition_oods_eval 不匹配）"
        );
        assert!(
            matches!(
                result.unwrap_err(),
                RecursionProvingError::CompositionOodsEvalMismatch { .. }
            ),
            "期望 CompositionOodsEvalMismatch"
        );
    }

    /// v5.1 多组件 soundness 测试 — 篡改 verify 时的 public_inputs 应导致 verify 失败。
    #[test]
    fn test_verify_with_fri_fails_on_mismatched_public_inputs() {
        let l1_proof = make_l1_proof();
        let inputs_prove = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // prove
        let l2_proof = prove_recursive_with_fri(&l1_proof, &inputs_prove)
            .expect("prove_recursive_with_fri 失败");

        // 篡改 oods_point（channel state 不一致）
        let mut inputs_verify = inputs_prove.clone();
        inputs_verify.oods_point = CirclePoint {
            x: SecureField::from_u32_unchecked(2, 0, 0, 0),
            y: SecureField::from_u32_unchecked(0, 2, 0, 0),
        };

        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri(&l2_proof, &inputs_verify);
        assert!(
            verify_result.is_err(),
            "verify_recursive_with_fri 应失败（public_inputs 不匹配）"
        );
    }

    /// v5.2 多组件 soundness 测试 — 篡改 fri_last_layer_poly 后 prove 仍应成功
    /// （FRI AIR 约束只检查 trace 内部一致性，不检查 poly 与 L1 proof 的一致性）。
    ///
    /// prove 成功是因为 `gen_fri_verifier_trace` 使用 `public_inputs.fri_last_layer_poly`
    /// 计算 `query_eval = poly.eval_at_point(x)` 和 Horner 累积值，trace 内部一致。
    /// 篡改的 poly 通过 channel mix 绑定到 L2 proof（v5.1 soundness fix），
    /// 因此 verifier 用不同 poly 验证时会失败（见
    /// `test_verify_with_fri_fails_on_tampered_last_layer_poly`）。
    ///
    /// v5.2 注意：篡改 poly 后必须同步更新 `fri_query_eval`，否则 prover 端
    /// FRI query consistency check 会因 `fri_query_eval` 与篡改后 poly 不一致而失败。
    /// `fri_query_x` 不需要更新（只依赖 L1 transcript，不依赖 poly）。
    #[test]
    fn test_prove_with_fri_fails_on_tampered_last_layer_poly() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // 篡改 fri_last_layer_poly：将每个系数 +1
        // 注意：必须用 `from_ordered_coefficients` 而非 `new`，因为
        // `into_ordered_coefficients()` 返回 natural-order 系数，而 `new()` 期望
        // bit-reversed 系数。错误使用会导致 eval_at_point（基于 bit-reversed）
        // 与 Horner（基于 natural-order）不一致，触发 AIR 约束 F6 失败。
        let tampered_coeffs: Vec<SecureField> = inputs
            .fri_last_layer_poly
            .clone()
            .into_ordered_coefficients()
            .into_iter()
            .map(|c| c + SecureField::from(1u32))
            .collect();
        inputs.fri_last_layer_poly = LinePoly::from_ordered_coefficients(tampered_coeffs);

        // v5.2：同步更新 fri_query_eval 以匹配篡改后的 poly
        // （query_x 不变，因为 query_x 只依赖 L1 transcript，不依赖 poly）
        inputs.fri_query_eval = inputs.fri_last_layer_poly.eval_at_point(inputs.fri_query_x);

        // prove 应该成功（trace 内部一致，不依赖 poly 与 L1 proof 的一致性）
        let prove_result = prove_recursive_with_fri(&l1_proof, &inputs);
        assert!(
            prove_result.is_ok(),
            "prove_recursive_with_fri 应成功（篡改 poly 不影响 prove）: {:?}",
            prove_result.err()
        );
    }

    /// v5.1 多组件 soundness 测试 — 用 tampered last_layer_poly verify 应失败。
    ///
    /// v5.1 soundness fix：`fri_last_layer_poly` 系数被 mix 到 channel，
    /// 所以 verify 时使用与 prove 不同的 poly 会导致 channel state 不一致 → verify 失败。
    #[test]
    fn test_verify_with_fri_fails_on_tampered_last_layer_poly() {
        let l1_proof = make_l1_proof();
        let inputs_prove = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // prove 用正确的 inputs
        let l2_proof = prove_recursive_with_fri(&l1_proof, &inputs_prove)
            .expect("prove_recursive_with_fri 失败");

        // 篡改 verify 时的 fri_last_layer_poly（保持长度不变，仅修改系数）
        // 注意：用 `from_ordered_coefficients` 而非 `new`，因为
        // `into_ordered_coefficients()` 返回 natural-order 系数。
        let mut inputs_verify = inputs_prove.clone();
        let tampered_coeffs: Vec<SecureField> = inputs_verify
            .fri_last_layer_poly
            .clone()
            .into_ordered_coefficients()
            .into_iter()
            .map(|c| c + SecureField::from(1u32))
            .collect();
        inputs_verify.fri_last_layer_poly = LinePoly::from_ordered_coefficients(tampered_coeffs);

        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri(&l2_proof, &inputs_verify);
        assert!(
            verify_result.is_err(),
            "verify_recursive_with_fri 应失败（last_layer_poly 篡改）"
        );
    }

    /// v5.2 soundness 测试 — 篡改 `fri_query_x` 后 prove 应失败（prover 端 consistency check）。
    ///
    /// 验证 v5.2 soundness fix：`extract_fri_query_from_l1` 在 prover 端重新从 L1 proof
    /// 的 Fiat-Shamir transcript 推导 query point，并与 `public_inputs.fri_query_x`
    /// 对比。如果不一致，返回 `FriQueryMismatch` 错误。
    ///
    /// 这关闭了 v5.1 soundness gap：此前 `gen_fri_verifier_trace` 硬编码 `query_x = 1`，
    /// 允许恶意 prover 选择在 x=1 处通过但其他点失败的伪造多项式。
    #[test]
    fn test_recursive_fri_soundness_tamper_query_x() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // 篡改 fri_query_x：加 1（确保与真实值不同）
        inputs.fri_query_x = inputs.fri_query_x + SecureField::from(1u32);

        // prove 应失败，返回 FriQueryMismatch
        let prove_result = prove_recursive_with_fri(&l1_proof, &inputs);
        assert!(
            matches!(
                prove_result,
                Err(RecursionProvingError::FriQueryMismatch { .. })
            ),
            "prove_recursive_with_fri 应返回 FriQueryMismatch（篡改 query_x）: {:?}",
            prove_result.err()
        );
    }

    /// v5.2 soundness 测试 — 篡改 `fri_query_eval`（但不篡改 query_x）后 prove 应失败。
    ///
    /// 验证 prover 端 consistency check 不仅检查 query_x，还检查 query_eval。
    /// 如果只篡改 eval 而不篡改 x，prover 会发现 `derived_eval != claimed_eval`。
    #[test]
    fn test_recursive_fri_soundness_tamper_query_eval() {
        let l1_proof = make_l1_proof();
        let mut inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        // 篡改 fri_query_eval：加 1（确保与真实值不同）
        inputs.fri_query_eval = inputs.fri_query_eval + SecureField::from(1u32);

        // prove 应失败，返回 FriQueryMismatch
        let prove_result = prove_recursive_with_fri(&l1_proof, &inputs);
        assert!(
            matches!(
                prove_result,
                Err(RecursionProvingError::FriQueryMismatch { .. })
            ),
            "prove_recursive_with_fri 应返回 FriQueryMismatch（篡改 query_eval）: {:?}",
            prove_result.err()
        );
    }
}
