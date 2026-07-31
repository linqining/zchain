//! # Recursion Prover — 实验性 Verifier AIR 的 L2 prover（Phase 5 PoC）
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
//! ## 多组件 prove（canonical verifier replay）
//!
//! `prove_recursive_with_fri` 将固定 `CpuV1` transcript、Poseidon252、canonical Merkle
//! replay、PCS quotient、FRI fold、OODS 和 composition evaluation 对称装配进
//! preprocessed/base/interaction commitments。旧的 `FriVerifierAir` 与 `MerklePathAir`
//! 占位组件不再进入该证明路径。
//!
//! 当前 Merkle/FRI/public-input 约束尚不完整；跨 crate 调用始终返回
//! [`RecursionProvingError::UnsoundBackendDisabled`]，仅 crate 自身测试执行 PoC。

use super::composition_eval_air::{COMP_EVAL_AIR_NUM_COLUMNS, CompositionEvalAir};
use super::cpu_transcript_binding_air::{
    CpuTranscriptBindingAir, CpuTranscriptBindingWitness, mix_cpu_transcript_claim,
};
use super::fri_semantic_air::{
    FriFoldAir, FriFoldPublicWitness, FriFoldWitness, PcsQuotientAir, PcsQuotientPublicWitness,
    PcsQuotientWitness,
};
use super::merkle_leaf_air::{
    MerkleLeafPackingAir, MerkleLeafPackingWitness, MerkleLeafPublicWitness,
};
use super::merkle_semantic_air::{
    MerklePublicBindingAir, MerklePublicBindingWitness, MerkleSemanticAir, MerkleSemanticWitness,
};
use super::oods_check_air::{OODS_AIR_NUM_COLUMNS, OodsCheckAir};
use super::poseidon252_air::{Poseidon252ClosureComponents, Poseidon252ClosureWitness};
use super::public_inputs::RecursivePublicInputs;
use super::replay_witness::CanonicalVerifierWitness;
use super::trace_gen::{
    OODS_TRACE_LOG_SIZE, extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
    gen_composition_eval_trace, gen_oods_check_trace, pad_oods_trace_to_log_size,
};
use super::transcript_air::{
    TranscriptSemanticAir, TranscriptSemanticWitness, ensure_lookup_balanced,
    transcript_payload_values,
};
use super::verifier_program::replay_cpu_verifier;
use ark_ff::Zero;
use cairo_air::relations::CommonLookupElements;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::{ComponentProver, ProvingError, prove};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

/// L2 recursive proof（封装 StarkProof）。
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecursiveProof(
    pub StarkProof<Blake2sMerkleHasher>,
    pub(crate) Option<RecursivePoseidonClaim>,
);

impl core::fmt::Debug for RecursiveProof {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecursiveProof")
            .field("stark_proof", &self.0)
            .field("has_poseidon_claim", &self.1.is_some())
            .finish()
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct RecursivePoseidonClaim {
    pub cairo_claim: cairo_air::claims::CairoClaim,
    pub cairo_interaction_claim: cairo_air::claims::CairoInteractionClaim,
    pub caller_log_size: u32,
    pub n_calls: usize,
    pub transcript_log_size: u32,
    pub n_transcript_calls: usize,
    pub caller_claimed_sum: SecureField,
    pub semantic_claimed_sum: SecureField,
    pub transcript_claimed_sum: SecureField,
    pub binding_claimed_sum: SecureField,
    pub merkle_claimed_sum: SecureField,
    pub merkle_binding_claimed_sum: SecureField,
    pub merkle_leaf_claimed_sum: SecureField,
    pub pcs_quotient_claimed_sum: SecureField,
    pub fri_fold_claimed_sum: SecureField,
    pub sampled_values: Vec<SecureField>,
    pub transcript_draw_results: Vec<FieldElement252>,
    pub proof_of_work: u64,
    pub pow_hash: FieldElement252,
}

/// Recursion prover 错误类型。
#[derive(Debug, thiserror::Error)]
pub enum RecursionProvingError {
    /// 当前递归 AIR 尚未完整约束 L1 Merkle/FRI decommitment 与公开输入。
    ///
    /// 为避免实验性 PoC 被生产调用方误认为 sound recursion，跨 crate 构建中的
    /// 递归 prover 始终 fail closed；仅 crate 自身的 `cfg(test)` 审计测试可执行 PoC。
    #[error("recursive prover is disabled until the verifier AIR fully constrains the L1 proof")]
    UnsoundBackendDisabled,
    /// L1 proof 在 recursion 过程中验证失败。
    #[error("L1 proof verification failed during recursion")]
    L1VerificationFailed,
    /// Stwo prover 内部错误。
    #[error("Stwo proving error: {0}")]
    StwoError(String),
    /// Prover 端 consistency check 失败：`public_inputs.composition_oods_eval` 与 L1 proof 不一致。
    #[error(
        "composition_oods_eval mismatch: public_inputs claims {claimed}, but L1 proof sampled_values derive {derived}"
    )]
    CompositionOodsEvalMismatch {
        /// public_inputs 中声称的 composition_oods_eval
        claimed: SecureField,
        /// 从 L1 proof sampled_values 推导的 composition_oods_eval
        derived: SecureField,
    },
    /// Prover 端 consistency check 失败：`public_inputs.fri_query_x` / `fri_query_eval`
    /// 与从 L1 proof Fiat-Shamir transcript 重新推导的值不一致。
    #[error(
        "fri_query mismatch: claimed_x={claimed_x}, derived_x={derived_x}, claimed_eval={claimed_eval}, derived_eval={derived_eval}"
    )]
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
    /// P05-R gap #1 soundness fix：`public_inputs.l1_commitments` 为空。
    ///
    /// 空 commitments 会让 Merkle Path AIR 的 final-root 检查（约束 M37）退化为
    /// 零 root，且 `gen_merkle_path_trace` 的 root 绑定落到 `FieldElement252::ZERO`
    /// 分支（`trace_gen.rs`），无法证明声明承诺来自被递归验证的 L1 proof。
    /// 入口显式拒绝，避免 PoC 调用方走空-input 的 unsound no-op 路径。
    #[error(
        "public_inputs.l1_commitments must be non-empty so the Merkle root is bound to the L1 proof"
    )]
    L1CommitmentsMissing,
    /// P05-R gap #1 soundness fix：`public_inputs.query_positions` 为空。
    ///
    /// 空 query_positions 会让 `gen_merkle_path_trace` 提前返回 `Vec::new()`，
    /// Merkle Path AIR 因此完全不参与 L2 proof，也就没有任何约束触及 L1 proof 的
    /// Merkle decommitment。入口显式拒绝。
    #[error("public_inputs.query_positions must be non-empty so the Merkle Path AIR is exercised")]
    QueryPositionsMissing,
    /// P05-R gap #1 soundness fix：`public_inputs.log_size == 0`。
    ///
    /// `log_size` 决定 Merkle tree 高度；为 0 时 tree_height=0，hash chain 为空，
    /// final-root 检查退化为 trivial。入口显式拒绝。
    #[error("public_inputs.log_size must be > 0 so the Merkle tree has a non-trivial height")]
    InvalidLogSize,
    /// Merkle/FRI canonical replay 已实现，但尚未被真实 Poseidon252 non-native AIR、
    /// transcript AIR 与 composition verifier AIR 完整约束，不能生成 sound L2 proof。
    #[error(
        "recursive prover is disabled: canonical Merkle/FRI replay is not yet constrained by the Poseidon252 and transcript verifier AIR"
    )]
    IncompleteMerkleVerifierAir,
    /// 固定 `CpuV1` verifier 的完整 host replay 失败。
    #[error("fixed CpuV1 verifier replay failed: {0}")]
    FixedVerifierReplayFailed(String),
}

impl From<ProvingError> for RecursionProvingError {
    fn from(e: ProvingError) -> Self {
        RecursionProvingError::StwoError(e.to_string())
    }
}

// ===========================================================================
// Public API
// ===========================================================================

/// P05-R gap #1：校验 `RecursivePublicInputs` 携带足以驱动 Merkle Path AIR 的非空输入。
///
/// 此前 PoC 调用方可传空 `l1_commitments` / 空 `query_positions`，使
/// `gen_merkle_path_trace` 走 no-op 分支或把 final root 绑定到零 root，
/// 从而让 L2 proof 在不触及任何 L1 Merkle decommitment 的情况下通过。
/// 该守卫在 fail-closed 门之后、任何 trace 生成之前执行，把 unsound 的空-input
/// 路径显式拒绝。仅在 `cfg(test)` 审计路径内被调用（生产路径已被
/// `UnsoundBackendDisabled` 挡住）。
fn ensure_nonempty_public_inputs(
    public_inputs: &RecursivePublicInputs,
) -> Result<(), RecursionProvingError> {
    if public_inputs.l1_commitments.is_empty() {
        return Err(RecursionProvingError::L1CommitmentsMissing);
    }
    if public_inputs.query_positions.is_empty() {
        return Err(RecursionProvingError::QueryPositionsMissing);
    }
    if public_inputs.log_size == 0 {
        return Err(RecursionProvingError::InvalidLogSize);
    }
    Ok(())
}

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
    if !cfg!(test) {
        let _ = (l1_proof, public_inputs);
        return Err(RecursionProvingError::UnsoundBackendDisabled);
    }

    // P05-R gap #1：强制非空 commitments/query/log_size，拒绝让 Merkle Path AIR
    // 退化为 no-op 的空-input unsound 路径。
    ensure_nonempty_public_inputs(public_inputs)?;

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
    Ok(RecursiveProof(stark_proof, None))
}

/// 聚合 fixed `CpuV1` canonical verifier AIR 的多组件 L2 prover。
///
/// # 多组件流程
///
/// 1. **Prover 端 consistency check**（同 `prove_recursive`）
/// 2. 构造 transcript/Poseidon/Merkle/PCS/FRI semantic witnesses
/// 3. 生成 OODS 与 composition traces
/// 4. 提交固定 preprocessed、heterogeneous base 与 interaction trees
/// 5. 构建全部 semantic components（共享 `TraceLocationAllocator`）
/// 6. `prove(...) → StarkProof`
///
/// 旧 `FriVerifierAir` / `MerklePathAir` 仅保留为历史 PoC，不再装配进完整路径。
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
    prove_recursive_with_fri_impl(l1_proof, public_inputs, false)
}

#[cfg(test)]
pub(crate) fn prove_recursive_with_fri_scaffold_for_test(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
) -> Result<RecursiveProof, RecursionProvingError> {
    prove_recursive_with_fri_impl(l1_proof, public_inputs, true)
}

fn prove_recursive_with_fri_impl(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    public_inputs: &RecursivePublicInputs,
    bypass_incomplete_air_gate: bool,
) -> Result<RecursiveProof, RecursionProvingError> {
    if !cfg!(test) {
        let _ = (l1_proof, public_inputs);
        return Err(RecursionProvingError::UnsoundBackendDisabled);
    }

    // P05-R gap #1：强制非空 commitments/query/log_size，拒绝让 Merkle Path AIR
    // 退化为 no-op 的空-input unsound 路径。
    ensure_nonempty_public_inputs(public_inputs)?;

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
            "无法从 L1 proof 提取 fri_query（commitment 数量不足或 FriVerifier 构造失败）"
                .to_string(),
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

    // 固定 method verifier：重建 CpuAir component、mask points、composition OODS、全部
    // tree commitments 与完整 FRI。该检查禁止 prover 自报 transcript/component schema。
    // 它仍是 host replay；下方 gate 继续关闭，直到同一计算被 AIR 约束。
    let replay = replay_cpu_verifier(l1_proof, public_inputs)
        .map_err(|error| RecursionProvingError::FixedVerifierReplayFailed(error.to_string()))?;
    let canonical_witness = CanonicalVerifierWitness::from_cpu_replay(&replay);
    if !canonical_witness.is_host_consistent() {
        return Err(RecursionProvingError::FixedVerifierReplayFailed(
            "canonical verifier witness is internally inconsistent".to_string(),
        ));
    }
    let transcript_payloads = transcript_payload_values(&canonical_witness.transcript_events);
    let sampled_values = l1_proof.0.sampled_values.clone().flatten_cols();
    let transcript_draw_results = canonical_witness
        .transcript_events
        .iter()
        .filter(|event| {
            event.kind == super::poseidon252_replay::Poseidon252CallKind::TranscriptDraw
        })
        .map(|event| event.result)
        .collect::<Vec<_>>();
    let pow_hash = canonical_witness
        .transcript_events
        .iter()
        .find(|event| {
            event.kind == super::poseidon252_replay::Poseidon252CallKind::TranscriptPowNonce
        })
        .map(|event| event.result)
        .ok_or_else(|| {
            RecursionProvingError::FixedVerifierReplayFailed(
                "canonical transcript is missing the PoW nonce result".to_string(),
            )
        })?;
    let binding_witness = CpuTranscriptBindingWitness::new(
        public_inputs,
        &sampled_values,
        &transcript_draw_results,
        l1_proof.0.proof_of_work,
        pow_hash,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "fixed CpuV1 transcript usage binding failed: {error}"
        ))
    })?;
    let audit_poseidon = Poseidon252ClosureWitness::from_canonical_calls_and_values(
        &canonical_witness.poseidon_calls,
        &transcript_payloads,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Poseidon252 AIR closure audit failed: {error}"
        ))
    })?;
    let audit_transcript = TranscriptSemanticWitness::new(
        &canonical_witness.transcript_events,
        &canonical_witness.transcript_calls,
        &canonical_witness.poseidon_calls,
        &audit_poseidon.synthetic_memory.call_ids,
        &audit_poseidon.synthetic_memory.extra_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical transcript AIR witness audit failed: {error}"
        ))
    })?;
    let audit_merkle_binding = MerklePublicBindingWitness::new(public_inputs).map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Merkle public binding audit failed: {error}"
        ))
    })?;
    let audit_merkle = MerkleSemanticWitness::new(
        &canonical_witness,
        &audit_merkle_binding,
        &audit_poseidon.synthetic_memory.call_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Merkle semantic witness audit failed: {error}"
        ))
    })?;
    let audit_merkle_leaf_public =
        MerkleLeafPublicWitness::new(&audit_merkle_binding).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical Merkle leaf public schedule audit failed: {error}"
            ))
        })?;
    let audit_merkle_leaf = MerkleLeafPackingWitness::new(
        &canonical_witness,
        &audit_merkle_leaf_public,
        &audit_poseidon.synthetic_memory.call_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Merkle leaf packing audit failed: {error}"
        ))
    })?;
    let audit_quotient_public = PcsQuotientPublicWitness::new(public_inputs, &sampled_values)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical PCS quotient public schedule audit failed: {error}"
            ))
        })?;
    let audit_quotient = PcsQuotientWitness::new(&canonical_witness, &audit_quotient_public)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical PCS quotient witness audit failed: {error}"
            ))
        })?;
    let audit_fri_fold_public = FriFoldPublicWitness::new(public_inputs, &transcript_draw_results)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical FRI fold public schedule audit failed: {error}"
            ))
        })?;
    let audit_fri_fold =
        FriFoldWitness::new(&canonical_witness, &audit_fri_fold_public).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical FRI fold witness audit failed: {error}"
            ))
        })?;
    let audit_lookup_elements = CommonLookupElements::dummy();
    let (_, audit_transcript_sum) =
        audit_transcript.write_interaction_trace(&audit_lookup_elements);
    let (_, audit_binding_sum) = binding_witness.write_interaction_trace(&audit_lookup_elements);
    let (_, audit_merkle_sum) = audit_merkle.write_interaction_trace(&audit_lookup_elements);
    let (_, audit_merkle_binding_sum) =
        audit_merkle_binding.write_interaction_trace(&audit_lookup_elements);
    let (_, audit_merkle_leaf_sum) = audit_merkle_leaf
        .write_interaction_trace(&audit_merkle_leaf_public, &audit_lookup_elements);
    let (_, audit_quotient_sum) =
        audit_quotient.write_interaction_trace(&audit_quotient_public, &audit_lookup_elements);
    let (_, audit_fri_fold_sum) =
        audit_fri_fold.write_interaction_trace(&audit_fri_fold_public, &audit_lookup_elements);
    let audit_poseidon_interaction = audit_poseidon
        .write_interaction_trace(&audit_lookup_elements)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical Poseidon252 interaction audit failed: {error}"
            ))
        })?;
    ensure_lookup_balanced(
        audit_poseidon_interaction.lookup_residual,
        &[
            audit_transcript_sum,
            audit_binding_sum,
            audit_merkle_sum,
            audit_merkle_binding_sum,
            audit_merkle_leaf_sum,
            audit_quotient_sum,
            audit_fri_fold_sum,
        ],
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical transcript/Poseidon lookup audit failed: {error}"
        ))
    })?;

    // P05-R gap #3-B：canonical replay 已有 transcript/Merkle/PCS/FRI semantic AIR，
    // 但整体 challenge/use-point 组合 soundness 尚未完成密码学审计。保持显式 fail-closed。
    if !super::MERKLE_VERIFIER_AIR_COMPLETE && !bypass_incomplete_air_gate {
        return Err(RecursionProvingError::IncompleteMerkleVerifierAir);
    }

    let poseidon_witness = Poseidon252ClosureWitness::from_canonical_calls_and_values(
        &canonical_witness.poseidon_calls,
        &transcript_payloads,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Poseidon252 witness generation failed: {error}"
        ))
    })?;
    let poseidon_cairo_claim = poseidon_witness.cairo_claim.clone();
    let poseidon_caller_log_size = poseidon_witness.caller_log_size;
    let poseidon_n_calls = poseidon_witness.n_calls;
    let transcript_witness = TranscriptSemanticWitness::new(
        &canonical_witness.transcript_events,
        &canonical_witness.transcript_calls,
        &canonical_witness.poseidon_calls,
        &poseidon_witness.synthetic_memory.call_ids,
        &poseidon_witness.synthetic_memory.extra_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical transcript witness generation failed: {error}"
        ))
    })?;
    let transcript_log_size = transcript_witness.log_size;
    let n_transcript_calls = transcript_witness.n_calls;
    let merkle_binding_witness =
        MerklePublicBindingWitness::new(public_inputs).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical Merkle public binding generation failed: {error}"
            ))
        })?;
    let merkle_witness = MerkleSemanticWitness::new(
        &canonical_witness,
        &merkle_binding_witness,
        &poseidon_witness.synthetic_memory.call_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Merkle semantic witness generation failed: {error}"
        ))
    })?;
    let merkle_leaf_public =
        MerkleLeafPublicWitness::new(&merkle_binding_witness).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical Merkle leaf public schedule generation failed: {error}"
            ))
        })?;
    let merkle_leaf_witness = MerkleLeafPackingWitness::new(
        &canonical_witness,
        &merkle_leaf_public,
        &poseidon_witness.synthetic_memory.call_ids,
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical Merkle leaf packing generation failed: {error}"
        ))
    })?;
    let quotient_public =
        PcsQuotientPublicWitness::new(public_inputs, &sampled_values).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "PCS quotient public schedule generation failed: {error}"
            ))
        })?;
    let quotient_witness =
        PcsQuotientWitness::new(&canonical_witness, &quotient_public).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "PCS quotient witness generation failed: {error}"
            ))
        })?;
    let fri_fold_public = FriFoldPublicWitness::new(public_inputs, &transcript_draw_results)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "FRI fold public schedule generation failed: {error}"
            ))
        })?;
    let fri_fold_witness =
        FriFoldWitness::new(&canonical_witness, &fri_fold_public).map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "FRI fold witness generation failed: {error}"
            ))
        })?;
    let (mut poseidon_preprocessed_ids, mut poseidon_preprocessed_trace) =
        poseidon_witness.preprocessed_columns();
    let (transcript_preprocessed_ids, transcript_preprocessed_trace) =
        transcript_witness.preprocessed_columns();
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
    let mut poseidon_base_trace = poseidon_witness.cairo_base_trace.clone();
    poseidon_base_trace.extend(poseidon_witness.caller_base_trace());
    poseidon_base_trace.extend(poseidon_witness.semantic_base_trace());
    poseidon_base_trace.extend(transcript_witness.base_trace.clone());
    poseidon_base_trace.extend(merkle_witness.base_trace.clone());
    poseidon_base_trace.extend(merkle_leaf_witness.base_trace.clone());
    poseidon_base_trace.extend(quotient_witness.base_trace.clone());
    poseidon_base_trace.extend(fri_fold_witness.base_trace.clone());

    // 2. OODS 与 fixed CpuV1 composition evaluator 共用最小 4-row verifier domain。
    let verifier_log_size = OODS_TRACE_LOG_SIZE;

    // 3. 生成 OODS trace。
    let oods_trace_cols = gen_oods_check_trace(l1_proof, public_inputs);
    assert_eq!(
        oods_trace_cols.len(),
        OODS_AIR_NUM_COLUMNS,
        "OODS trace 列数={}，期望={OODS_AIR_NUM_COLUMNS}",
        oods_trace_cols.len()
    );
    let mut oods_trace_padded = pad_oods_trace_to_log_size(oods_trace_cols, verifier_log_size);
    for column in &mut oods_trace_padded {
        let bound_value = column[0];
        column.fill(bound_value);
    }

    // 4. 固定 CpuAir composition evaluation：185 个 QM31 samples = 740 个 M31 columns。
    let composition_trace = gen_composition_eval_trace(l1_proof, verifier_log_size);
    assert_eq!(
        composition_trace.len(),
        COMP_EVAL_AIR_NUM_COLUMNS,
        "Composition trace 列数不匹配"
    );
    poseidon_base_trace.extend(trace_cols_to_evaluations(
        &oods_trace_padded,
        verifier_log_size,
    ));
    poseidon_base_trace.extend(trace_cols_to_evaluations(
        &composition_trace,
        verifier_log_size,
    ));

    // 6. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let max_log_size = poseidon_preprocessed_trace
        .iter()
        .chain(&poseidon_base_trace)
        .map(|evaluation| evaluation.domain.log_size())
        .max()
        .unwrap_or(verifier_log_size)
        .max(verifier_log_size);
    let big_domain = CanonicCoset::new(max_log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 7. Channel + CommitmentSchemeProver
    let mut channel = Blake2sChannel::default();

    // 8. mix RecursivePublicInputs 到 channel（与 prove_recursive 相同顺序）
    mix_public_inputs_into_channel(&mut channel, public_inputs);
    mix_cpu_transcript_claim(
        &mut channel,
        &sampled_values,
        &transcript_draw_results,
        l1_proof.0.proof_of_work,
        pow_hash,
    );

    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
    // 9. 提交固定 Poseidon closure preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(poseidon_preprocessed_trace);
        tree_builder.commit(&mut channel);
    }

    poseidon_cairo_claim.mix_into::<Blake2sMerkleChannel>(&mut channel);
    channel.mix_u64(u64::from(poseidon_caller_log_size));
    channel.mix_u64(u64::try_from(poseidon_n_calls).map_err(|_| {
        RecursionProvingError::L1ProofStructureInvalid(
            "canonical Poseidon252 call count exceeds u64".to_string(),
        )
    })?);
    channel.mix_u64(u64::from(transcript_log_size));
    channel.mix_u64(u64::try_from(n_transcript_calls).map_err(|_| {
        RecursionProvingError::L1ProofStructureInvalid(
            "canonical transcript call count exceeds u64".to_string(),
        )
    })?);

    // 10. 提交 original trace：官方 Poseidon closure + canonical caller/semantic + verifier AIRs。
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(poseidon_base_trace);
        tree_builder.commit(&mut channel);
    }

    let common_lookup_elements = CommonLookupElements::draw(&mut channel);
    let poseidon_interaction = poseidon_witness
        .write_interaction_trace(&common_lookup_elements)
        .map_err(|error| {
            RecursionProvingError::FixedVerifierReplayFailed(format!(
                "canonical Poseidon252 interaction generation failed: {error}"
            ))
        })?;
    let (transcript_interaction_trace, transcript_claimed_sum) =
        transcript_witness.write_interaction_trace(&common_lookup_elements);
    let (binding_interaction_trace, binding_claimed_sum) =
        binding_witness.write_interaction_trace(&common_lookup_elements);
    let (merkle_interaction_trace, merkle_claimed_sum) =
        merkle_witness.write_interaction_trace(&common_lookup_elements);
    let (merkle_binding_interaction_trace, merkle_binding_claimed_sum) =
        merkle_binding_witness.write_interaction_trace(&common_lookup_elements);
    let (merkle_leaf_interaction_trace, merkle_leaf_claimed_sum) =
        merkle_leaf_witness.write_interaction_trace(&merkle_leaf_public, &common_lookup_elements);
    let (quotient_interaction_trace, pcs_quotient_claimed_sum) =
        quotient_witness.write_interaction_trace(&quotient_public, &common_lookup_elements);
    let (fri_fold_interaction_trace, fri_fold_claimed_sum) =
        fri_fold_witness.write_interaction_trace(&fri_fold_public, &common_lookup_elements);
    ensure_lookup_balanced(
        poseidon_interaction.lookup_residual,
        &[
            transcript_claimed_sum,
            binding_claimed_sum,
            merkle_claimed_sum,
            merkle_binding_claimed_sum,
            merkle_leaf_claimed_sum,
            pcs_quotient_claimed_sum,
            fri_fold_claimed_sum,
        ],
    )
    .map_err(|error| {
        RecursionProvingError::FixedVerifierReplayFailed(format!(
            "canonical transcript/Poseidon lookup is unbalanced: {error}"
        ))
    })?;
    poseidon_interaction
        .cairo_interaction_claim
        .mix_into(&mut channel);
    channel.mix_felts(&[
        poseidon_interaction.caller_claimed_sum,
        poseidon_interaction.semantic_claimed_sum,
        transcript_claimed_sum,
        binding_claimed_sum,
        merkle_claimed_sum,
        merkle_binding_claimed_sum,
        merkle_leaf_claimed_sum,
        pcs_quotient_claimed_sum,
        fri_fold_claimed_sum,
    ]);
    let mut interaction_trace = poseidon_interaction.cairo_interaction_trace;
    interaction_trace.extend(poseidon_interaction.caller_interaction_trace);
    interaction_trace.extend(poseidon_interaction.semantic_interaction_trace);
    interaction_trace.extend(transcript_interaction_trace);
    interaction_trace.extend(binding_interaction_trace);
    interaction_trace.extend(merkle_interaction_trace);
    interaction_trace.extend(merkle_binding_interaction_trace);
    interaction_trace.extend(merkle_leaf_interaction_trace);
    interaction_trace.extend(quotient_interaction_trace);
    interaction_trace.extend(fri_fold_interaction_trace);
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(interaction_trace);
        tree_builder.commit(&mut channel);
    }

    // 11. 构建 canonical semantic + OODS/composition components。
    let composition_samples =
        sampled_values[..crate::stwo_backend::column_layout_v2::NUM_COLUMNS].to_vec();
    let oods_samples = sampled_values[crate::stwo_backend::column_layout_v2::NUM_COLUMNS..]
        .try_into()
        .map_err(|_| {
            RecursionProvingError::FixedVerifierReplayFailed(
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
        &poseidon_cairo_claim,
        &common_lookup_elements,
        &poseidon_interaction.cairo_interaction_claim,
        poseidon_caller_log_size,
        poseidon_n_calls,
        poseidon_interaction.caller_claimed_sum,
        poseidon_interaction.semantic_claimed_sum,
        &poseidon_preprocessed_ids,
        &mut allocator,
    );
    let transcript_component = FrameworkComponent::new(
        &mut allocator,
        TranscriptSemanticAir::new(
            transcript_log_size,
            n_transcript_calls,
            common_lookup_elements.clone(),
        ),
        transcript_claimed_sum,
    );
    let binding_component = FrameworkComponent::new(
        &mut allocator,
        CpuTranscriptBindingAir::new(
            binding_witness.log_size,
            binding_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        binding_claimed_sum,
    );
    let merkle_semantic_component = FrameworkComponent::new(
        &mut allocator,
        MerkleSemanticAir::new(
            merkle_witness.log_size,
            merkle_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        merkle_claimed_sum,
    );
    let merkle_binding_component = FrameworkComponent::new(
        &mut allocator,
        MerklePublicBindingAir::new(
            merkle_binding_witness.log_size,
            merkle_binding_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        merkle_binding_claimed_sum,
    );
    let merkle_leaf_component = FrameworkComponent::new(
        &mut allocator,
        MerkleLeafPackingAir::new(
            merkle_leaf_witness.log_size,
            merkle_leaf_witness.n_rows,
            common_lookup_elements.clone(),
        ),
        merkle_leaf_claimed_sum,
    );
    let quotient_component = FrameworkComponent::new(
        &mut allocator,
        PcsQuotientAir::new(
            quotient_public.log_size,
            quotient_public.n_rows,
            common_lookup_elements.clone(),
        ),
        pcs_quotient_claimed_sum,
    );
    let fri_fold_component = FrameworkComponent::new(
        &mut allocator,
        FriFoldAir::new(
            fri_fold_public.log_size,
            fri_fold_public.n_rows,
            common_lookup_elements.clone(),
        ),
        fri_fold_claimed_sum,
    );
    let oods_component = FrameworkComponent::new(&mut allocator, oods_air, SecureField::zero());
    let composition_component =
        FrameworkComponent::new(&mut allocator, composition_air, SecureField::zero());

    // 12. 生成完整 closure + verifier AIR 多组件证明。
    let mut components = poseidon_components.prover_components();
    let verifier_components: [&dyn ComponentProver<SimdBackend>; 9] = [
        &transcript_component as &dyn ComponentProver<SimdBackend>,
        &binding_component,
        &merkle_semantic_component,
        &merkle_binding_component,
        &merkle_leaf_component,
        &quotient_component,
        &fri_fold_component,
        &oods_component,
        &composition_component,
    ];
    components.extend(verifier_components);
    let stark_proof = prove(&components, &mut channel, commitment_scheme)?;
    Ok(RecursiveProof(
        stark_proof,
        Some(RecursivePoseidonClaim {
            cairo_claim: poseidon_cairo_claim,
            cairo_interaction_claim: poseidon_interaction.cairo_interaction_claim,
            caller_log_size: poseidon_caller_log_size,
            n_calls: poseidon_n_calls,
            transcript_log_size,
            n_transcript_calls,
            caller_claimed_sum: poseidon_interaction.caller_claimed_sum,
            semantic_claimed_sum: poseidon_interaction.semantic_claimed_sum,
            transcript_claimed_sum,
            binding_claimed_sum,
            merkle_claimed_sum,
            merkle_binding_claimed_sum,
            merkle_leaf_claimed_sum,
            pcs_quotient_claimed_sum,
            fri_fold_claimed_sum,
            sampled_values,
            transcript_draw_results,
            proof_of_work: l1_proof.0.proof_of_work,
            pow_hash,
        }),
    ))
}

// ===========================================================================
// Helper functions
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
    use stwo::core::channel::Channel;
    use stwo::core::circle::CirclePoint;
    use stwo::core::poly::line::LinePoly;

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
        super::super::verifier_program::build_cpu_recursive_public_inputs(
            l1_proof,
            TEST_MAX_LOG_DEGREE_BOUND,
        )
        .expect("固定 CpuV1 verifier statement 构造应成功")
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
        assert!(matches!(err, RecursionProvingError::StwoError(_)));
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
            matches!(
                err,
                RecursionProvingError::CompositionOodsEvalMismatch { .. }
            ),
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
        let verify_result =
            super::super::recursion_verifier::verify_recursive(&l2_proof, &inputs_verify);
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
        super::super::verifier_program::build_cpu_recursive_public_inputs(
            l1_proof,
            TEST_MAX_LOG_DEGREE_BOUND,
        )
        .expect("固定 CpuV1 verifier statement 构造应成功")
    }

    /// v5.1 多组件 prove 应成功：OODS + FRI Verifier AIR 联合 proof。
    #[test]
    #[ignore = "P05-R gap #3-B: _with_fri 显式返回 IncompleteMerkleVerifierAir"]
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

    /// Gate 后完整 semantic scaffold 应 roundtrip，并拒绝 statement/envelope 篡改。
    #[test]
    fn test_semantic_scaffold_roundtrip_recursive_with_fri() {
        let l1_proof = make_l1_proof();
        let inputs = make_test_public_inputs_with_fri_from_l1(&l1_proof);

        let l2_proof = prove_recursive_with_fri_scaffold_for_test(&l1_proof, &inputs)
            .expect("gate 后完整 semantic scaffold prove 失败");

        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri_scaffold_for_test(
                &l2_proof, &inputs,
            );
        assert!(
            verify_result.is_ok(),
            "gate 后完整 semantic scaffold verify 应成功: {:?}",
            verify_result.err()
        );

        let mut tampered_inputs = inputs.clone();
        tampered_inputs.l1_commitments[0] += FieldElement252::from(1u32);
        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri_scaffold_for_test(
                &l2_proof,
                &tampered_inputs,
            );
        assert!(
            verify_result.is_err(),
            "gate 后 scaffold 必须拒绝篡改的 RecursivePublicInputs"
        );

        let mut tampered_envelope = l2_proof.clone();
        tampered_envelope
            .1
            .as_mut()
            .expect("scaffold proof 必须携带 Poseidon252 claim")
            .n_transcript_calls += 1;
        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri_scaffold_for_test(
                &tampered_envelope,
                &inputs,
            );
        assert!(
            verify_result.is_err(),
            "gate 后 scaffold 必须拒绝篡改的 RecursivePoseidonClaim 元数据"
        );

        let mut tampered_lookup_claim = l2_proof.clone();
        tampered_lookup_claim
            .1
            .as_mut()
            .expect("scaffold proof 必须携带 Poseidon252 claim")
            .transcript_claimed_sum += SecureField::from(1u32);
        let verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri_scaffold_for_test(
                &tampered_lookup_claim,
                &inputs,
            );
        assert!(
            matches!(
                &verify_result,
                Err(super::super::recursion_verifier::RecursionVerificationError::VerificationFailed(message))
                    if message.contains("global lookup claimed sums are unbalanced")
            ),
            "verifier 必须独立拒绝不平衡的全局 lookup claims: {verify_result:?}"
        );

        let production_verify_result =
            super::super::recursion_verifier::verify_recursive_with_fri(&l2_proof, &inputs);
        assert!(
            matches!(
                production_verify_result,
                Err(super::super::recursion_verifier::RecursionVerificationError::IncompleteMerkleVerifierAir)
            ),
            "未完成密码学审计前，生产 verifier gate 必须保持 fail-closed: {production_verify_result:?}"
        );
    }

    /// v5.1 多组件 soundness 测试 — 篡改 composition_oods_eval 应导致 prove 失败。
    #[test]
    #[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
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
    #[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
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
    #[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
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
    #[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
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
