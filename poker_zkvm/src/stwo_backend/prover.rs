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
    use crate::isa::Instruction;
    use crate::stwo_backend::column_layout_v2::NUM_COLUMNS;
    use crate::stwo_backend::trace_native::{step_to_m31_row, NativeTrace, TraceBuilder};
    use crate::trace::Step;
    use stwo::core::fields::m31::M31;

    /// 构造一个最小 Step（仅含 instruction + pc + post-registers，prev_registers 由参数传入）。
    fn make_step(pc: u32, instruction: Instruction, post_registers: [u32; 32]) -> Step {
        Step {
            step_index: 0,
            pc,
            instruction,
            registers: post_registers,
            mem_access: Vec::new(),
        }
    }

    /// 构造一个零初始化寄存器快照（x0 永远为 0）。
    fn zero_registers() -> [u32; 32] {
        [0u32; 32]
    }

    /// 单步 trace prove/verify roundtrip 通用辅助。
    /// 输入：pc, instruction, prev_registers, post_registers。
    fn prove_verify_single_step(
        pc: u32,
        instruction: Instruction,
        prev_registers: &[u32; 32],
        post_registers: [u32; 32],
    ) {
        let step = make_step(pc, instruction, post_registers);
        let row = step_to_m31_row(&step, prev_registers);

        let mut builder = TraceBuilder::new(10); // 1024 行
        builder.fill_row(&row);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let log_size = trace.log_size;

        let proof = prove_cpu_trace(&trace).expect("prove 失败");
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }

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

    // =======================================================================
    // Phase 2.7 测试：LUI / AUIPC / JAL / JALR / BEQ (taken & not-taken)
    // =======================================================================
    // 这些测试通过 step_to_m31_row 自动生成 row（含 Helper1/Helper2/Shamt），
    // 验证 Phase 2.7 新增的 25 条约束（PC 递增 + JAL/JALR/Branch + LUI/AUIPC + Taken binality）
    // 与现有 14 条约束协同工作。

    #[test]
    fn test_prove_verify_roundtrip_lui() {
        // LUI x1, 0x1000（imm 已左移 12 位 = 0x1000000）
        // rd_eff = imm = 0x00100000
        let mut post = zero_registers();
        post[1] = 0x0010_0000;
        prove_verify_single_step(0, Instruction::Lui { rd: 1, imm: 0x0010_0000 }, &zero_registers(), post);
    }

    #[test]
    fn test_prove_verify_roundtrip_auipc() {
        // AUIPC x1, 0x1000（imm 已左移 12 位 = 0x1000000）
        // rd_eff = pc + imm = 0 + 0x0010_0000 = 0x0010_0000
        let mut post = zero_registers();
        post[1] = 0x0010_0000;
        prove_verify_single_step(0, Instruction::Auipc { rd: 1, imm: 0x0010_0000 }, &zero_registers(), post);
    }

    #[test]
    fn test_prove_verify_roundtrip_jal() {
        // JAL x1, 8（跳转到 pc+8=8，rd=x1 存返回地址 pc+4=4）
        let mut post = zero_registers();
        post[1] = 4; // rd = pc + 4
        prove_verify_single_step(0, Instruction::Jal { rd: 1, imm: 8 }, &zero_registers(), post);
    }

    #[test]
    fn test_prove_verify_roundtrip_jalr() {
        // JALR x1, x2, 4（跳转到 (x2 + 4) & !1 = 4，rd=x1 存返回地址 pc+4=4）
        let mut prev = zero_registers();
        prev[2] = 0; // x2 = 0
        let mut post = prev;
        post[1] = 4; // rd = pc + 4 = 4
        prove_verify_single_step(0, Instruction::Jalr { rd: 1, rs1: 2, imm: 4 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_beq_taken() {
        // BEQ x2, x3, 16（x2 == x3，taken=1，next_pc = pc + 16 = 16）
        let mut prev = zero_registers();
        prev[2] = 42; // x2 = 42
        prev[3] = 42; // x3 = 42
        let post = prev; // BEQ 不写寄存器
        prove_verify_single_step(0, Instruction::Beq { rs1: 2, rs2: 3, imm: 16 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_beq_not_taken() {
        // BEQ x2, x3, 16（x2 != x3，taken=0，next_pc = pc + 4 = 4）
        let mut prev = zero_registers();
        prev[2] = 42; // x2 = 42
        prev[3] = 7;  // x3 = 7
        let post = prev;
        prove_verify_single_step(0, Instruction::Beq { rs1: 2, rs2: 3, imm: 16 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_bne_taken() {
        // BNE x2, x3, 8（x2 != x3，taken=1，next_pc = pc + 8 = 8）
        let mut prev = zero_registers();
        prev[2] = 42;
        prev[3] = 7;
        let post = prev;
        prove_verify_single_step(0, Instruction::Bne { rs1: 2, rs2: 3, imm: 8 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_blt_taken() {
        // BLT x2, x3, 8（有符号 x2 < x3，taken=1）
        let mut prev = zero_registers();
        prev[2] = 5;
        prev[3] = 10;
        let post = prev;
        prove_verify_single_step(0, Instruction::Blt { rs1: 2, rs2: 3, imm: 8 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_bltu_taken() {
        // BLTU x2, x3, 8（无符号 x2 < x3，taken=1）
        let mut prev = zero_registers();
        prev[2] = 5;
        prev[3] = 10;
        let post = prev;
        prove_verify_single_step(0, Instruction::Bltu { rs1: 2, rs2: 3, imm: 8 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_sub() {
        // SUB x1, x2, x3 → x1 = x2 - x3 = 100 - 30 = 70
        let mut prev = zero_registers();
        prev[2] = 100;
        prev[3] = 30;
        let mut post = prev;
        post[1] = 70;
        prove_verify_single_step(0, Instruction::Sub { rd: 1, rs1: 2, rs2: 3 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_sub_borrow() {
        // SUB x1, x2, x3 → x1 = 30 - 100 = -70 mod 2^32 = 0xFFFFFFBA
        // 测试借位场景
        let mut prev = zero_registers();
        prev[2] = 30;
        prev[3] = 100;
        let mut post = prev;
        post[1] = 30u32.wrapping_sub(100);
        prove_verify_single_step(0, Instruction::Sub { rd: 1, rs1: 2, rs2: 3 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_addi() {
        // ADDI x1, x2, 50 → x1 = 100 + 50 = 150
        let mut prev = zero_registers();
        prev[2] = 100;
        let mut post = prev;
        post[1] = 150;
        prove_verify_single_step(0, Instruction::Addi { rd: 1, rs1: 2, imm: 50 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_add_with_carry() {
        // ADD x1, x2, x3 → x1 = 0xFFFE + 0x0002 = 0x10000（产生 16-bit 进位）
        let mut prev = zero_registers();
        prev[2] = 0x0000_FFFE;
        prev[3] = 0x0000_0002;
        let mut post = prev;
        post[1] = 0x0001_0000;
        prove_verify_single_step(0, Instruction::Add { rd: 1, rs1: 2, rs2: 3 }, &prev, post);
    }

    #[test]
    fn test_prove_verify_roundtrip_multi_instruction() {
        // 多指令序列：ADD → ADDI → SUB → BEQ (taken)
        // Step 0: ADD x1, x2, x3 → x1 = 100 + 200 = 300, pc 0→4
        // Step 1: ADDI x4, x1, 50 → x4 = 300 + 50 = 350, pc 4→8
        // Step 2: SUB x5, x4, x1 → x5 = 350 - 300 = 50, pc 8→12
        // Step 3: BEQ x5, x5, 8（taken，next_pc = 12 + 8 = 20）
        let mut prev = zero_registers();
        prev[2] = 100;
        prev[3] = 200;

        // Step 0: ADD x1, x2, x3 → x1 = 300
        let mut post0 = prev;
        post0[1] = 300;
        let step0 = make_step(0, Instruction::Add { rd: 1, rs1: 2, rs2: 3 }, post0);
        let row0 = step_to_m31_row(&step0, &prev);
        prev = post0;

        // Step 1: ADDI x4, x1, 50 → x4 = 350
        let mut post1 = prev;
        post1[4] = 350;
        let step1 = make_step(4, Instruction::Addi { rd: 4, rs1: 1, imm: 50 }, post1);
        let row1 = step_to_m31_row(&step1, &prev);
        prev = post1;

        // Step 2: SUB x5, x4, x1 → x5 = 50
        let mut post2 = prev;
        post2[5] = 50;
        let step2 = make_step(8, Instruction::Sub { rd: 5, rs1: 4, rs2: 1 }, post2);
        let row2 = step_to_m31_row(&step2, &prev);
        prev = post2;

        // Step 3: BEQ x5, x5, 8（taken，跳到 pc + 8 = 20）
        let step3 = make_step(12, Instruction::Beq { rs1: 5, rs2: 5, imm: 8 }, prev);
        let row3 = step_to_m31_row(&step3, &prev);

        // 构建 trace
        let mut builder = TraceBuilder::new(10); // 1024 行
        builder.fill_row(&row0);
        builder.fill_row(&row1);
        builder.fill_row(&row2);
        builder.fill_row(&row3);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let log_size = trace.log_size;

        let proof = prove_cpu_trace(&trace).expect("prove 失败：多指令序列应满足所有约束");
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }
}