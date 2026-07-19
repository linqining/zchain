//! # Stwo Prover 集成（Phase 2.5）
//!
//! 严格遵循 `.trae/documents/stwo_phase2_cpu_air_design.md` Step 2.5：
//! - 集成 Stwo 原生 Prover/Verifier API
//! - 输入 `NativeTrace`（97 列 × 2^log_size 行）→ 输出 `StarkProof`
//! - prove/verify roundtrip 的主入口
//!
//! ## 工作流
//!
//! ### Prover
//! 1. `PcsConfig::default()` + `SimdBackend::precompute_twiddles(...)`
//! 2. `Blake2sChannel::default()` + `CommitmentSchemeProver::new(config, &twiddles)`
//! 3. 提交空 preprocessed trace（tree 0）→ `tree_builder.extend_evals(vec![]); commit()`
//! 4. 提交 original trace（tree 1，97 列）→ `tree_builder.extend_evals(columns); commit()`
//! 5. `FrameworkComponent::new(&mut allocator, CpuAir, SecureField::zero())`
//! 6. `prove(&[&component], &mut channel, commitment_scheme)` → `StarkProof`
//!
//! ### Verifier
//! 1. `PcsConfig::default()` + `Blake2sChannel::default()` + `CommitmentSchemeVerifier::new(config)`
//! 2. 从 proof 读取 preprocessed commitment → `commitment_scheme.commit(...)`
//! 3. 从 proof 读取 trace commitment → `commitment_scheme.commit(...)`
//! 4. `FrameworkComponent::new(...)`（与 prover 相同的 AIR）
//! 5. `verify(&[&component], &mut channel, &mut commitment_scheme, proof)`
//!
//! ## 参考
//! - Stwo stwo-book: Prover Workflow
//! - `stwo-2.3.0/src/prover/mod.rs` — `prove()` 函数
//! - `stwo-2.3.0/src/core/verifier.rs` — `verify()` 函数
//! - `stwo-2.3.0/benches/pcs.rs` — `precompute_twiddles` + `CircleEvaluation` 用法

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::verifier::{verify, VerificationError};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, ProvingError};
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use super::cpu_air::CpuAir;
use super::column_layout_v2::NUM_COLUMNS;
use super::trace_native::NativeTrace;

/// Blake2s Merkle Hasher 类型别名。
pub type CpuProof = StarkProof<Blake2sMerkleHasher>;

// ===========================================================================
// NativeTrace → Stwo CircleEvaluation 转换
// ===========================================================================

/// 将 `NativeTrace`（列主序 `Vec<Vec<M31>>`）转换为 Stwo `CircleEvaluation` 列。
///
/// # 算法
/// 对每列：
/// 1. `BaseColumn::from_cpu(&col)` — `&[M31]` → `BaseColumn`（SIMD 友好）
/// 2. `CircleEvaluation::new(domain, base_col)` — 在 canonical coset 上构造求值
/// 3. `.bit_reverse()` — 转换为 `BitReversedOrder`（Stwo 提交要求）
///
/// # 参数
/// - `trace` — 97 列 × 2^log_size 行的原生 M31 trace
///
/// # 返回
/// 97 个 `CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>` 列
fn native_trace_to_evaluations(
    trace: &NativeTrace,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    assert_eq!(
        trace.cols.len(),
        NUM_COLUMNS,
        "native_trace_to_evaluations: trace.cols.len()={} != NUM_COLUMNS={}",
        trace.cols.len(),
        NUM_COLUMNS
    );
    let domain = CanonicCoset::new(trace.log_size).circle_domain();
    trace
        .cols
        .iter()
        .map(|col| {
            let base_col = BaseColumn::from_cpu(col.as_slice());
            CircleEvaluation::<SimdBackend, BaseField>::new(domain, base_col).bit_reverse()
        })
        .collect()
}

// ===========================================================================
// Prover 主入口
// ===========================================================================

/// 生成 CPU trace 的 Stwo STARK 证明。
///
/// # 参数
/// - `trace` — 97 列 × 2^log_size 行的原生 M31 trace（由 `trace_to_native` 生成）
///
/// # 返回
/// `StarkProof<Blake2sMerkleHasher>` — 可由 [`verify_cpu_proof`] 验证
///
/// # 错误
/// - `ProvingError::ConstraintsNotSatisfied` — AIR 约束不满足（trace 生成有 bug）
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::prove_cpu_trace;
/// use poker_zkvm::stwo_backend::trace_native::trace_to_native;
///
/// let native_trace = trace_to_native(&emulator_trace);
/// let proof = prove_cpu_trace(&native_trace).expect("prove failed");
/// ```
pub fn prove_cpu_trace(trace: &NativeTrace) -> Result<CpuProof, ProvingError> {
    let log_size = trace.log_size;

    // 1. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 2. Channel + CommitmentSchemeProver
    let mut channel = Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

    // 3. 提交空 preprocessed trace（tree 0）
    // CpuAir 无 preprocessed columns（所有列都在 original trace）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. 提交 original trace（tree 1，97 列）
    {
        let columns = native_trace_to_evaluations(trace);
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 5. 构建 AIR component
    let air = CpuAir::new(log_size);
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air, SecureField::from(0u32));

    // 6. 生成证明
    prove(&[&component], &mut channel, commitment_scheme)
}

// ===========================================================================
// Verifier 主入口
// ===========================================================================

/// 验证 CPU trace 的 Stwo STARK 证明。
///
/// # 参数
/// - `proof` — 由 [`prove_cpu_trace`] 生成的 `StarkProof`
/// - `log_size` — log2(trace 行数)，须与 prover 一致
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(VerificationError)` — 验证失败（证明伪造、约束不满足等）
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::{prove_cpu_trace, verify_cpu_proof};
///
/// let proof = prove_cpu_trace(&native_trace)?;
/// verify_cpu_proof(proof, native_trace.log_size)?;
/// ```
pub fn verify_cpu_proof(proof: CpuProof, log_size: u32) -> Result<(), VerificationError> {
    let config = PcsConfig::default();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0，0 列）
    //    prover 提交了空 preprocessed tree，verifier 需镜像读取
    let preprocessed_commitment = *proof.commitments.get(0).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，97 列，每列 log_size）
    let trace_commitment = *proof.commitments.get(1).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; NUM_COLUMNS];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. 构建 AIR component（与 prover 相同）
    let air = CpuAir::new(log_size);
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air, SecureField::from(0u32));

    // 5. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        proof,
    )
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
    use crate::stwo_backend::trace_native::{NativeTrace, TraceBuilder};
    use stwo::core::fields::m31::M31;

    /// 辅助：构造一个全 padding 的最小 NativeTrace（log_size=10，1024 行）。
    fn make_padding_only_trace() -> NativeTrace {
        let mut builder = TraceBuilder::new(10);
        builder.fill_padding_to_full();
        builder.finalize()
    }

    #[test]
    fn test_native_trace_to_evaluations_column_count() {
        let trace = make_padding_only_trace();
        let evals = native_trace_to_evaluations(&trace);
        assert_eq!(evals.len(), NUM_COLUMNS);
    }

    #[test]
    fn test_prove_padding_only_trace() {
        // 全 padding trace 的约束：
        // - IsPadding = 1（binality 满足）
        // - 其他 indicator = 0（one-hot 满足：Σ Is_i = 1，因为 IsPadding=1）
        // - ADD/ADDI/SUB 约束被 IsAdd=IsAddi=IsSub=0 gating 为 0
        // 因此应 prove 成功
        let trace = make_padding_only_trace();
        let proof = prove_cpu_trace(&trace).expect("prove 应成功（全 padding trace 满足所有约束）");
        assert!(proof.commitments.len() >= 3, "proof 应包含 ≥3 个 commitments");
    }

    #[test]
    fn test_verify_padding_only_trace() {
        let trace = make_padding_only_trace();
        let log_size = trace.log_size;
        let proof = prove_cpu_trace(&trace).expect("prove 应成功");
        verify_cpu_proof(proof, log_size).expect("verify 应成功");
    }

    #[test]
    fn test_prove_verify_roundtrip_padding_only() {
        // 完整 roundtrip：prove → verify
        let trace = make_padding_only_trace();
        let log_size = trace.log_size;

        // prove
        let proof = prove_cpu_trace(&trace).expect("prove 失败");

        // verify
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }

    /// 辅助：构造一个包含单条 ADD 指令的 NativeTrace。
    fn make_single_add_trace() -> NativeTrace {
        use crate::stwo_backend::column_layout_v2::*;
        use crate::stwo_backend::trace_native::u32_to_m31_limbs;

        let mut builder = TraceBuilder::new(10); // 1024 行

        // 构造一行 ADD 指令的 trace：
        // ADD x1, x2, x3 → x1 = x2 + x3
        // 假设 x2 = 100, x3 = 200, x1 = 300
        let rs1_val: u32 = 100;
        let rs2_val: u32 = 200;
        let rd_val: u32 = 300;

        let mut row = vec![M31::from(0u32); NUM_COLUMNS];

        // PC = 0
        let pc_limbs = u32_to_m31_limbs(0);
        for i in 0..4 {
            row[COL_PC_BASE + i] = pc_limbs[i];
        }
        // next_pc = 4
        let next_pc_limbs = u32_to_m31_limbs(4);
        for i in 0..4 {
            row[COL_PC_NEXT_BASE + i] = next_pc_limbs[i];
        }
        // OpA = 1 (rd), OpB = 2 (rs1), OpC = 3 (rs2)
        row[COL_OP_A] = M31::from(1u32);
        row[COL_OP_B] = M31::from(2u32);
        row[COL_OP_C] = M31::from(3u32);
        row[COL_IMM_C] = M31::from(0u32); // R-type, 无立即数

        // ValueA (写前值) = 0, ValueAEff (写后值) = 300
        for (base, val) in [
            (COL_VALUE_A_BASE, 0u32),
            (COL_VALUE_A_EFF_BASE, rd_val),
            (COL_VALUE_B_BASE, rs1_val),
            (COL_VALUE_C_BASE, rs2_val),
        ] {
            let limbs = u32_to_m31_limbs(val);
            for i in 0..4 {
                row[base + i] = limbs[i];
            }
        }

        // IsAdd = 1
        row[IS_ADD] = M31::from(1u32);

        // 计算 ADD carries: 100 + 200 = 300
        // 低 16 位: 100 + 200 = 300 < 65536, carry0 = 0
        // 高 16 位: 0 + 0 + 0 = 0, carry1 = 0
        row[COL_CARRY_FLAG_BASE] = M31::from(0u32);
        row[COL_CARRY_FLAG_BASE + 1] = M31::from(0u32);

        builder.fill_row(&row);
        builder.fill_padding_to_full();
        builder.finalize()
    }

    #[test]
    fn test_prove_verify_roundtrip_single_add() {
        let trace = make_single_add_trace();
        let log_size = trace.log_size;

        // prove
        let proof = prove_cpu_trace(&trace).expect("prove 失败：ADD 约束应满足");

        // verify
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }
}