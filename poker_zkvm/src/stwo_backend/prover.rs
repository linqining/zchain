//! # Stwo Prover 集成（Phase 2.5）
//!
//! 严格遵循 `.trae/documents/stwo_phase2_cpu_air_design.md` Step 2.5：
//! - 集成 Stwo 原生 Prover/Verifier API
//! - 输入 `NativeTrace`（87 列（v3）× 2^log_size 行）→ 输出 `StarkProof`
//! - prove/verify roundtrip 的主入口
//!
//! ## 工作流
//!
//! ### Prover
//! 1. `PcsConfig::default()` + `SimdBackend::precompute_twiddles(...)`
//! 2. `Poseidon252Channel::default()` + `CommitmentSchemeProver::new(config, &twiddles)`
//! 3. 提交空 preprocessed trace（tree 0）→ `tree_builder.extend_evals(vec![]); commit()`
//! 4. 提交 original trace（tree 1，87 列（v3））→ `tree_builder.extend_evals(columns); commit()`
//! 5. `FrameworkComponent::new(&mut allocator, CpuAir, SecureField::zero())`
//! 6. `prove(&[&component], &mut channel, commitment_scheme)` → `StarkProof`
//!
//! ### Verifier
//! 1. `PcsConfig::default()` + `Poseidon252Channel::default()` + `CommitmentSchemeVerifier::new(config)`
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

use ark_ff::Zero;
use stwo::core::channel::{Blake2sChannel, Channel, Poseidon252Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::verifier::{verify, VerificationError};
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo::core::vcs_lifted::poseidon252_merkle::{Poseidon252MerkleChannel, Poseidon252MerkleHasher};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedBaseField, LOG_N_LANES};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, ProvingError};
use stwo_constraint_framework::{
    FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, TraceLocationAllocator,
};

use super::cpu_air::CpuAir;
use super::column_layout_v2::{COL_MEM_ADDR_BASE, COL_VALUE_A_EFF_BASE, COL_VALUE_C_BASE, IS_LOAD, IS_STORE, NUM_COLUMNS};
use super::lookups::MemoryLookup;
use super::memory_air::{
    MEM_COL_ADDR_BASE, MEM_COL_IS_PADDING, MEM_COL_IS_STORE, MEM_COL_VAL_CUR_BASE, MEM_NUM_COLUMNS,
    MemoryAir,
};
use super::trace_native::{memory_trace_to_evaluations, MemoryTrace, NativeTrace};

/// Poseidon252 Merkle Hasher 类型别名（递归路径）。
pub type CpuProof = StarkProof<Poseidon252MerkleHasher>;

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
/// - `trace` — 87 列（v3）× 2^log_size 行的原生 M31 trace
///
/// # 返回
/// 87 个 `CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>` 列
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
/// - `trace` — 87 列（v3）× 2^log_size 行的原生 M31 trace（由 `trace_to_native` 生成）
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
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 3. 提交空 preprocessed trace（tree 0）
    // CpuAir 无 preprocessed columns（所有列都在 original trace）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. 提交 original trace（tree 1，87 列（v3））
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
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0，0 列）
    //    prover 提交了空 preprocessed tree，verifier 需镜像读取
    let preprocessed_commitment = *proof.commitments.get(0).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，87 列（v3），每列 log_size）
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
// Phase 3.5：多组件 prover/verify（CPU + Memory logup）
// ===========================================================================
//
// 多组件 logup 架构（参考 Stwo state_machine 示例）：
//
// ```text
// Tree 0 (preprocessed): 空
// Tree 1 (original):     CPU trace (87 cols) + Memory trace (25 cols) = 112 cols
// Tree 2 (interaction):  CPU logup (4 cols) + Memory logup (4 cols) = 8 cols
// ```
//
// ## Prover 流程
//
// 1. PcsConfig + twiddles + Blake2sChannel + CommitmentSchemeProver
// 2. 提交 Tree 0（空 preprocessed）
// 3. 提交 Tree 1（CPU + Memory original trace）
// 4. **从 channel draw MemoryLookup**（在 Tree 1 commit 之后，Tree 2 之前）
// 5. 调用 `gen_cpu_interaction_trace` + `gen_mem_interaction_trace` 生成 Tree 2 列
// 6. **Soundness check**：`claimed_sum_cpu + claimed_sum_mem == 0`
// 7. `channel.mix_felts(&[sum_cpu, sum_mem])` — 通信给 verifier
// 8. 提交 Tree 2（CPU + Memory interaction）
// 9. 构建 `CpuAir::new_with_lookup` + `MemoryAir::new` 两个 component（带 claimed_sum）
// 10. `prove(&[&cpu, &mem], ...)`
//
// ## Verifier 流程
//
// 镜像 prover：commit Tree 0 → commit Tree 1 → draw lookup → soundness check →
// mix_felts → commit Tree 2 → `verify(&[&cpu, &mem], ...)`
//
// ## Logup 协议
//
// - CPU 每行发送 **claim**：`multiplicity = is_load + is_store`（非 Load/Store 行 = 0）
//   - values = `[MemAddr×4, mem_value×4, IsStore×1]`
//   - mem_value = `is_load * rd_eff + is_store * rs2_value`
// - Memory 每行发送 **yield**：`multiplicity = -1 * (1 - IsPadding)`（padding 行 = 0）
//   - values = `[MemAddr×4, MemValCur×4, MemIsStore×1]`
// - 一致性条件：`Σ(CPU claims) + Σ(Memory yields) == 0`，即 `claimed_sum_cpu + claimed_sum_mem == 0`
//
// ## 关键 API
//
// - `LogupTraceGenerator::new(log_size)` → `new_col()` → `write_frac(vec_row, num, denom)`
//   → `finalize_col()` → `finalize_last()` 返回 `(4 CircleEvaluation, claimed_sum)`
// - `FrameworkComponent::new(allocator, air, claimed_sum)` — 第三个参数为该组件的 logup sum
// - `MemoryLookup::draw(&mut channel)` — 必须在 Tree 1 commit 之后调用
// - `channel.mix_felts(&[...])` — 通信 claimed_sums 给 verifier

/// 多组件 proof 结构：CPU + Memory 联合 STARK proof。
///
/// # 字段
/// - `stark_proof` — Stwo StarkProof（包含 Tree 0/1/2 commitments + composition poly commitment + FRI）
/// - `claimed_sum_cpu` — CPU logup 列的总和（须满足 `claimed_sum_cpu + claimed_sum_mem == 0`）
/// - `claimed_sum_mem` — Memory logup 列的总和
///
/// # 序列化注意
/// `claimed_sum_cpu` 和 `claimed_sum_mem` 是 prover→verifier 通信的辅助数据，
/// 通过 `channel.mix_felts` 注入 channel，但仍需保存在 proof 中以便 verifier 重放。
#[derive(Debug, Clone)]
pub struct CpuMemoryProof {
    /// Stwo STARK proof
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// CPU logup 列总 sum
    pub claimed_sum_cpu: SecureField,
    /// Memory logup 列总 sum
    pub claimed_sum_mem: SecureField,
}

/// 生成 CPU logup interaction trace 列。
///
/// # 算法
/// 对每个 `vec_row`（SIMD 向量行，每行 16 个 lane）：
/// 1. 从 CPU original trace 读取 9 个 claim value（PackedBaseField）
///    - `claim_values[0..4] = MemAddr[0..4]`
///    - `claim_values[4..8] = is_load * ValueAEff + is_store * ValueC`（mem_value）
///    - `claim_values[8] = IsStore`
/// 2. 计算 `denom = lookup.combine(&claim_values) → PackedSecureField`
/// 3. 计算 `num = PackedSecureField::from(is_load + is_store)`（multiplicity）
/// 4. `col_gen.write_frac(vec_row, num, denom)`
/// 5. `finalize_col()` + `finalize_last()` 返回 (4 CircleEvaluations, claimed_sum)
///
/// # 参数
/// - `cpu_trace` — CPU original trace evaluations（87 列（v3），bit-reversed order）
/// - `log_size` — log2(行数)
/// - `lookup` — MemoryLookup relation 实例（已从 channel draw）
///
/// # 返回
/// (4 个 CircleEvaluation, claimed_sum) — 4 列即 SecureField 的 4 个坐标
fn gen_cpu_interaction_trace(
    cpu_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    lookup: &MemoryLookup,
) -> (Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, SecureField) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut log_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = log_gen.new_col();

    for vec_row in 0..n_vec_rows {
        // 读取 indicator 列
        let is_load_packed = cpu_trace[IS_LOAD].values.data[vec_row];
        let is_store_packed = cpu_trace[IS_STORE].values.data[vec_row];

        // 构造 9 元 claim_values = [MemAddr×4, mem_value×4, IsStore×1]
        let mut claim_values: [PackedBaseField; 9] = [PackedBaseField::zero(); 9];
        for i in 0..4 {
            claim_values[i] = cpu_trace[COL_MEM_ADDR_BASE + i].values.data[vec_row];
        }
        for i in 0..4 {
            let value_a_eff = cpu_trace[COL_VALUE_A_EFF_BASE + i].values.data[vec_row];
            let value_c = cpu_trace[COL_VALUE_C_BASE + i].values.data[vec_row];
            // mem_value = is_load * rd_eff + is_store * rs2_value
            claim_values[4 + i] = is_load_packed * value_a_eff + is_store_packed * value_c;
        }
        claim_values[8] = is_store_packed;

        // denom = lookup.combine(&claim_values) → PackedSecureField
        let denom: PackedSecureField = lookup.combine(&claim_values);

        // num = (is_load + is_store) as PackedSecureField
        let multiplicity_packed = is_load_packed + is_store_packed;
        let num: PackedSecureField = PackedSecureField::from(multiplicity_packed);

        col_gen.write_frac(vec_row, num, denom);
    }

    col_gen.finalize_col();
    log_gen.finalize_last()
}

/// 生成 Memory logup interaction trace 列。
///
/// # 算法
/// 对每个 `vec_row`：
/// 1. 从 Memory original trace 读取 9 个 lookup value（PackedBaseField）
///    - `lookup_values[0..4] = MemAddr[0..4]`
///    - `lookup_values[4..8] = MemValCur[0..4]`
///    - `lookup_values[8] = MemIsStore`
/// 2. 计算 `denom = lookup.combine(&lookup_values) → PackedSecureField`
/// 3. 计算 `num = neg_one * is_non_padding`（multiplicity = -1 for non-padding, 0 for padding）
/// 4. `col_gen.write_frac(vec_row, num, denom)`
/// 5. `finalize_col()` + `finalize_last()` 返回 (4 CircleEvaluations, claimed_sum)
///
/// # Soundness
/// padding 行 multiplicity = 0（不贡献 sum），确保 CPU padding 行（multiplicity = 0）
/// 与 Memory padding 行（multiplicity = 0）保持一致，使 `claimed_sum_cpu + claimed_sum_mem == 0`
/// 可被满足。
fn gen_mem_interaction_trace(
    mem_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    lookup: &MemoryLookup,
) -> (Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, SecureField) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut log_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = log_gen.new_col();

    let neg_one: PackedSecureField = PackedSecureField::broadcast(SecureField::from(-1i32));
    let one_packed: PackedBaseField = PackedBaseField::broadcast(BaseField::from(1u32));

    for vec_row in 0..n_vec_rows {
        let is_padding_packed = mem_trace[MEM_COL_IS_PADDING].values.data[vec_row];
        // is_non_padding = 1 - IsPadding
        let is_non_padding = one_packed - is_padding_packed;

        // 构造 9 元 lookup_values = [MemAddr×4, MemValCur×4, MemIsStore×1]
        let mut lookup_values: [PackedBaseField; 9] = [PackedBaseField::zero(); 9];
        for i in 0..4 {
            lookup_values[i] = mem_trace[MEM_COL_ADDR_BASE + i].values.data[vec_row];
        }
        for i in 0..4 {
            lookup_values[4 + i] = mem_trace[MEM_COL_VAL_CUR_BASE + i].values.data[vec_row];
        }
        lookup_values[8] = mem_trace[MEM_COL_IS_STORE].values.data[vec_row];

        // denom = lookup.combine(&lookup_values) → PackedSecureField
        let denom: PackedSecureField = lookup.combine(&lookup_values);

        // num = neg_one * is_non_padding (PackedSecureField * PackedBaseField)
        let num: PackedSecureField = neg_one * PackedSecureField::from(is_non_padding);

        col_gen.write_frac(vec_row, num, denom);
    }

    col_gen.finalize_col();
    log_gen.finalize_last()
}

/// 多组件 prove 主入口：CPU + Memory 联合 STARK proof。
///
/// # 参数
/// - `cpu_trace` — CPU original trace（87 列（v3）× 2^log_size 行）
/// - `mem_trace` — Memory original trace（25 列 × 2^log_size 行）
///
/// # 返回
/// `CpuMemoryProof` — 包含 StarkProof + claimed_sums
///
/// # 错误
/// - `ProvingError::ConstraintsNotSatisfied` — AIR 约束不满足
/// - panic — `claimed_sum_cpu + claimed_sum_mem != 0`（soundness 失败，trace 生成有 bug）
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::prove_cpu_memory_trace;
/// use poker_zkvm::stwo_backend::trace_native::{trace_to_native, trace_to_memory_trace};
///
/// let cpu_trace = trace_to_native(&emulator_trace);
/// let mem_trace = trace_to_memory_trace(&emulator_trace);
/// let proof = prove_cpu_memory_trace(&cpu_trace, &mem_trace).expect("prove failed");
/// ```
pub fn prove_cpu_memory_trace(
    cpu_trace: &NativeTrace,
    mem_trace: &MemoryTrace,
) -> Result<CpuMemoryProof, ProvingError> {
    let log_size = cpu_trace.log_size;
    assert_eq!(
        log_size, mem_trace.log_size,
        "CPU and Memory trace log_size mismatch: {} vs {}",
        log_size, mem_trace.log_size
    );

    // 1. PCS 配置 + twiddles 预计算
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 2. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 3. Tree 0：空 preprocessed（CPU + Memory 均无 preprocessed columns）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 4. Tree 1：CPU original trace (87 cols) + Memory original trace (25 cols) = 112 cols
    // 注：`extend_evals` 消费 Vec，需先 clone 一份用于后续 logup interaction trace 生成。
    let cpu_evals = native_trace_to_evaluations(cpu_trace);
    let mem_evals = memory_trace_to_evaluations(mem_trace);

    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(cpu_evals.clone());
        tree_builder.extend_evals(mem_evals.clone());
        tree_builder.commit(&mut channel);
    }

    // 5. 从 channel draw MemoryLookup（必须在 Tree 1 commit 之后）
    let memory_lookup = MemoryLookup::draw(&mut channel);

    // 6. 生成 interaction traces（Tree 2）
    // 注：cpu_evals / mem_evals 的 bit-reversed order 与 LogupTraceGenerator 的 vec_row
    // iteration 一致，因此 logup 列也按相同的 bit-reversed order 生成。
    let (cpu_interaction_evals, claimed_sum_cpu) =
        gen_cpu_interaction_trace(&cpu_evals, log_size, &memory_lookup);
    let (mem_interaction_evals, claimed_sum_mem) =
        gen_mem_interaction_trace(&mem_evals, log_size, &memory_lookup);

    // 7. Soundness check：claimed_sum_cpu + claimed_sum_mem == 0
    let total_sum = claimed_sum_cpu + claimed_sum_mem;
    assert_eq!(
        total_sum,
        SecureField::zero(),
        "Soundness check failed: claimed_sum_cpu ({:?}) + claimed_sum_mem ({:?}) != 0",
        claimed_sum_cpu,
        claimed_sum_mem
    );

    // 8. 通信 claimed_sums 给 verifier（通过 channel.mix_felts）
    channel.mix_felts(&[claimed_sum_cpu, claimed_sum_mem]);

    // 9. Tree 2：CPU interaction (4 cols) + Memory interaction (4 cols) = 8 cols
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(cpu_interaction_evals);
        tree_builder.extend_evals(mem_interaction_evals);
        tree_builder.commit(&mut channel);
    }

    // 10. 构建 components（顺序与 Tree 1/2 列分配一致：CPU 先，Memory 后）
    let cpu_air = CpuAir::new_with_lookup(log_size, memory_lookup.clone());
    let mem_air = MemoryAir::new(log_size, memory_lookup.clone());
    let mut allocator = TraceLocationAllocator::default();
    let cpu_component = FrameworkComponent::new(&mut allocator, cpu_air, claimed_sum_cpu);
    let mem_component = FrameworkComponent::new(&mut allocator, mem_air, claimed_sum_mem);

    // 11. 生成证明
    let stark_proof = prove(&[&cpu_component, &mem_component], &mut channel, commitment_scheme)?;

    Ok(CpuMemoryProof {
        stark_proof,
        claimed_sum_cpu,
        claimed_sum_mem,
    })
}

/// 验证 CPU + Memory 联合 STARK proof。
///
/// # 参数
/// - `proof` — 由 [`prove_cpu_memory_trace`] 生成的 `CpuMemoryProof`
/// - `log_size` — log2(trace 行数)，须与 prover 一致
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(VerificationError)` — 验证失败（证明伪造、约束不满足、soundness 失败等）
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::{prove_cpu_memory_trace, verify_cpu_memory_proof};
///
/// let proof = prove_cpu_memory_trace(&cpu_trace, &mem_trace)?;
/// verify_cpu_memory_proof(proof, cpu_trace.log_size)?;
/// ```
pub fn verify_cpu_memory_proof(
    proof: CpuMemoryProof,
    log_size: u32,
) -> Result<(), VerificationError> {
    let CpuMemoryProof {
        stark_proof,
        claimed_sum_cpu,
        claimed_sum_mem,
    } = proof;

    let config = PcsConfig::default();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 Tree 0 commitment（空 preprocessed，0 列）
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 Tree 1 commitment（CPU 87 cols + Memory 25 cols = 112 cols）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let total_trace_cols = NUM_COLUMNS + MEM_NUM_COLUMNS;
    let trace_log_sizes = vec![log_size; total_trace_cols];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. 从 channel draw MemoryLookup（与 prover 镜像）
    let memory_lookup = MemoryLookup::draw(&mut channel);

    // 5. Soundness check（verifier 端也验证）
    let total_sum = claimed_sum_cpu + claimed_sum_mem;
    if total_sum != SecureField::zero() {
        return Err(VerificationError::InvalidStructure(format!(
            "Soundness check failed: claimed_sum_cpu ({:?}) + claimed_sum_mem ({:?}) != 0",
            claimed_sum_cpu, claimed_sum_mem
        )));
    }

    // 6. 通信 claimed_sums（与 prover 镜像）
    channel.mix_felts(&[claimed_sum_cpu, claimed_sum_mem]);

    // 7. 从 proof 读取 Tree 2 commitment（CPU 4 cols + Memory 4 cols = 8 cols）
    let interaction_commitment = *stark_proof.commitments.get(2).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥3，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let interaction_log_sizes = vec![log_size; 8];
    commitment_scheme.commit(interaction_commitment, &interaction_log_sizes, &mut channel);

    // 8. 构建 components（与 prover 一致）
    let cpu_air = CpuAir::new_with_lookup(log_size, memory_lookup.clone());
    let mem_air = MemoryAir::new(log_size, memory_lookup.clone());
    let mut allocator = TraceLocationAllocator::default();
    let cpu_component = FrameworkComponent::new(&mut allocator, cpu_air, claimed_sum_cpu);
    let mem_component = FrameworkComponent::new(&mut allocator, mem_air, claimed_sum_mem);

    // 9. 验证
    verify(
        &[&cpu_component, &mem_component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
}

// ===========================================================================
// Phase 4 Tier 2: Poseidon 单组件 Prover/Verifier（Step 4.2.4）
// ===========================================================================

use super::lookups::PoseidonLookup;
use super::poseidon_air::{
    PoseidonAir, POSEIDON_AIR_COL_INPUT_BASE, POSEIDON_AIR_COL_IS_LAST_ROUND,
    POSEIDON_AIR_COL_IS_PADDING, POSEIDON_AIR_COL_OUTPUT_BASE, POSEIDON_AIR_NUM_COLUMNS,
    POSEIDON_SYSCALL_ID,
};
use super::trace_native::{gen_poseidon_trace, poseidon_trace_to_evaluations, PoseidonHashCall};

/// Poseidon 单组件 STARK proof 结构。
///
/// # 字段
/// - `stark_proof` — Stwo StarkProof（包含 Tree 0/1/2 commitments + composition poly + FRI）
/// - `claimed_sum` — Poseidon logup 列总 sum（= -N，N = hash 调用数）
///
/// # Soundness
/// 单组件模式下，`claimed_sum` 不要求 == 0（无 CPU 端 claim 平衡）。
/// `claimed_sum = -N`，其中 N = `hash_calls.len()`，因为每个 hash 的 `IsLastRound` 行
/// 发送 multiplicity = -1。Verifier 通过 `channel.mix_felts` 接收 `claimed_sum` 并验证
/// AIR 声明的 relation 一致。
///
/// # 用途
/// 用于独立验证 Poseidon AIR 约束的正确性（Step 4.2.4）。
/// 3 组件集成（CPU + Memory + Poseidon）在 Step 4.2.5 实现。
#[derive(Debug, Clone)]
pub struct PoseidonProof {
    /// Stwo STARK proof
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// Poseidon logup 列总 sum（= -N，N = hash 调用数；空 trace 时为 0）
    pub claimed_sum: SecureField,
}

/// 生成 Poseidon logup interaction trace 列。
///
/// # 算法
/// 对每个 `vec_row`（SIMD 向量行，每行 16 个 lane）：
/// 1. 从 Poseidon original trace 读取 9 个 lookup value（PackedBaseField）
///    - `lookup_values[0] = SyscallId`（常量 0x03）
///    - `lookup_values[1..4] = Input[0..3]`
///    - `lookup_values[4..7] = Output[0..3]`
///    - `lookup_values[7] = IsLastRound`
///    - `lookup_values[8] = IsPadding`
/// 2. 计算 `denom = lookup.combine(&lookup_values) → PackedSecureField`
/// 3. 计算 `num = neg_one * IsLastRound * (1 - IsPadding)`（multiplicity）
/// 4. `col_gen.write_frac(vec_row, num, denom)`
/// 5. `finalize_col()` + `finalize_last()` 返回 (4 CircleEvaluations, claimed_sum)
///
/// # Soundness
/// - `IsLastRound=1` 且非 padding 的行 multiplicity = -1（每个 hash yield 一次）
/// - 其他行 multiplicity = 0
/// - 总 sum = -N（N = hash 调用数）；空 trace 时 sum = 0
fn gen_poseidon_interaction_trace(
    poseidon_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    lookup: &PoseidonLookup,
) -> (Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>, SecureField) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut log_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = log_gen.new_col();

    let neg_one: PackedSecureField = PackedSecureField::broadcast(SecureField::from(-1i32));
    let one_packed: PackedBaseField = PackedBaseField::broadcast(BaseField::from(1u32));
    let syscall_id_packed: PackedBaseField =
        PackedBaseField::broadcast(BaseField::from(POSEIDON_SYSCALL_ID));

    for vec_row in 0..n_vec_rows {
        let is_last_packed = poseidon_trace[POSEIDON_AIR_COL_IS_LAST_ROUND].values.data[vec_row];
        let is_padding_packed = poseidon_trace[POSEIDON_AIR_COL_IS_PADDING].values.data[vec_row];
        // is_non_padding = 1 - IsPadding
        let is_non_padding = one_packed - is_padding_packed;

        // 构造 9 元 lookup_values
        let mut lookup_values: [PackedBaseField; 9] = [PackedBaseField::zero(); 9];
        lookup_values[0] = syscall_id_packed;
        for i in 0..3 {
            lookup_values[1 + i] =
                poseidon_trace[POSEIDON_AIR_COL_INPUT_BASE + i].values.data[vec_row];
        }
        for i in 0..3 {
            lookup_values[4 + i] =
                poseidon_trace[POSEIDON_AIR_COL_OUTPUT_BASE + i].values.data[vec_row];
        }
        lookup_values[7] = is_last_packed;
        lookup_values[8] = is_padding_packed;

        // denom = lookup.combine(&lookup_values)
        let denom: PackedSecureField = lookup.combine(&lookup_values);

        // num = neg_one * is_last * is_non_padding
        let multiplicity_base: PackedBaseField = is_last_packed * is_non_padding;
        let num: PackedSecureField = neg_one * PackedSecureField::from(multiplicity_base);

        col_gen.write_frac(vec_row, num, denom);
    }

    col_gen.finalize_col();
    log_gen.finalize_last()
}

/// Poseidon 单组件 prove 主入口。
///
/// # 参数
/// - `hash_calls` — Poseidon hash 调用列表
///
/// # 返回
/// `PoseidonProof` — 包含 StarkProof + claimed_sum
///
/// # 错误
/// - `ProvingError::ConstraintsNotSatisfied` — AIR 约束不满足
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::prove_poseidon_trace;
/// use poker_zkvm::stwo_backend::trace_native::PoseidonHashCall;
/// use stwo::core::fields::m31::BaseField;
///
/// let call = PoseidonHashCall::from_input([
///     BaseField::from(1u32),
///     BaseField::from(2u32),
///     BaseField::from(3u32),
/// ]);
/// let proof = prove_poseidon_trace(&[call]).expect("prove failed");
/// ```
pub fn prove_poseidon_trace(
    hash_calls: &[PoseidonHashCall],
) -> Result<PoseidonProof, ProvingError> {
    // 1. 生成 Poseidon trace
    let poseidon_trace = gen_poseidon_trace(hash_calls);
    let log_size = poseidon_trace.log_size;

    // 2. PCS 配置 + twiddles 预计算（v2.1 简化版）
    //
    // v2.1 关键变化：PoseidonAir 的 `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2），
    // `constraint_log_degree = 1 ≤ log_blowup_factor = 1`，强制使用 `EvaluationMode::SubDomain`。
    // SubDomain 模式与 MemoryAir 已验证可用，使用 `PcsConfig::default()` 即可：
    // - 无需 `lifting_log_size = Some(...)`
    // - 无需 `set_store_polynomials_coefficients()`
    // - 无需扩大 twiddles 预计算域
    //
    // v1.0 卡点根因：原 `max_constraint_log_degree_bound = log_size + 3`（约束度 6）触发
    // `ExtendToEvalDomain` 模式，需特殊 PcsConfig，且与 logup interaction 集成存在边界 case。
    // v2.1 中间列降度方案消除了该问题。详见 `.trae/documents/stwo_phase4_tier2_replan.md` §3。
    let config = PcsConfig::default();
    let blowup_log = config.fri_config.log_blowup_factor;
    let big_domain = CanonicCoset::new(log_size + blowup_log);
    let twiddles = SimdBackend::precompute_twiddles(big_domain.half_coset());

    // 3. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);

    // 4. Tree 0：空 preprocessed（Poseidon AIR 无 preprocessed columns）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 5. Tree 1：Poseidon original trace (30 cols, v2.1)
    let poseidon_evals = poseidon_trace_to_evaluations(&poseidon_trace);
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(poseidon_evals.clone());
        tree_builder.commit(&mut channel);
    }

    // 6. 从 channel draw PoseidonLookup（必须在 Tree 1 commit 之后）
    let poseidon_lookup = PoseidonLookup::draw(&mut channel);

    // 7. 生成 interaction trace（Tree 2）
    let (poseidon_interaction_evals, claimed_sum) =
        gen_poseidon_interaction_trace(&poseidon_evals, log_size, &poseidon_lookup);

    // 8. 通信 claimed_sum 给 verifier（通过 channel.mix_felts）
    channel.mix_felts(&[claimed_sum]);

    // 9. Tree 2：Poseidon interaction (4 cols)
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(poseidon_interaction_evals);
        tree_builder.commit(&mut channel);
    }

    // 10. 构建 component
    let poseidon_air = PoseidonAir::new(log_size, poseidon_lookup.clone());
    let mut allocator = TraceLocationAllocator::default();
    let poseidon_component = FrameworkComponent::new(&mut allocator, poseidon_air, claimed_sum);

    // 11. 生成证明
    let stark_proof = prove(&[&poseidon_component], &mut channel, commitment_scheme)?;

    Ok(PoseidonProof {
        stark_proof,
        claimed_sum,
    })
}

/// 验证 Poseidon 单组件 STARK proof。
///
/// # 参数
/// - `proof` — 由 [`prove_poseidon_trace`] 生成的 `PoseidonProof`
/// - `log_size` — log2(trace 行数)，须与 prover 一致
///
/// # 返回
/// - `Ok(())` — 验证通过
/// - `Err(VerificationError)` — 验证失败（证明伪造、约束不满足等）
///
/// # 示例
/// ```ignore
/// use poker_zkvm::stwo_backend::prover::{prove_poseidon_trace, verify_poseidon_proof};
/// use poker_zkvm::stwo_backend::trace_native::PoseidonHashCall;
/// use stwo::core::fields::m31::BaseField;
///
/// let call = PoseidonHashCall::from_input([
///     BaseField::from(1u32),
///     BaseField::from(2u32),
///     BaseField::from(3u32),
/// ]);
/// let proof = prove_poseidon_trace(&[call])?;
/// verify_poseidon_proof(proof, 5)?; // log_size = 5（32 行）
/// ```
pub fn verify_poseidon_proof(
    proof: PoseidonProof,
    log_size: u32,
) -> Result<(), VerificationError> {
    let PoseidonProof {
        stark_proof,
        claimed_sum,
    } = proof;

    // v2.1：与 prover 一致，使用 PcsConfig::default()（SubDomain 模式）。
    // PoseidonAir 的约束度 ≤ 2 → max_constraint_log_degree_bound = log_size + 1，
    // constraint_log_degree = 1 ≤ log_blowup_factor = 1 → SubDomain 模式。
    // 详见 `.trae/documents/stwo_phase4_tier2_replan.md` §3.6。
    let config = PcsConfig::default();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 Tree 0 commitment（空 preprocessed，0 列）
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 Tree 1 commitment（Poseidon 21 cols）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; POSEIDON_AIR_NUM_COLUMNS];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. 从 channel draw PoseidonLookup（与 prover 镜像）
    let poseidon_lookup = PoseidonLookup::draw(&mut channel);

    // 5. 通信 claimed_sum（与 prover 镜像）
    channel.mix_felts(&[claimed_sum]);

    // 6. 从 proof 读取 Tree 2 commitment（Poseidon 4 cols interaction）
    let interaction_commitment = *stark_proof.commitments.get(2).ok_or_else(|| {
        VerificationError::InvalidStructure(format!(
            "proof.commitments 长度不足：期望 ≥3，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let interaction_log_sizes = vec![log_size; 4];
    commitment_scheme.commit(interaction_commitment, &interaction_log_sizes, &mut channel);

    // 7. 构建 component（与 prover 一致）
    let poseidon_air = PoseidonAir::new(log_size, poseidon_lookup.clone());
    let mut allocator = TraceLocationAllocator::default();
    let poseidon_component = FrameworkComponent::new(&mut allocator, poseidon_air, claimed_sum);

    // 8. 验证
    verify(
        &[&poseidon_component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
}

// ===========================================================================
// v3：3 组件 Poseidon 集成已移除
// ===========================================================================
// 原实现依赖 ECALL Args/Outputs 列（24 列），v3 列布局已移除这些列。
// 如需恢复 3 组件集成，需先在 column_layout_v2.rs 中恢复 ECALL Args/Outputs 列。
// 保留的路径：
// - prove_cpu_trace / verify_cpu_proof（单组件 CPU）
// - prove_cpu_memory_trace / verify_cpu_memory_proof（2 组件 CPU + Memory）
// - prove_poseidon_trace / verify_poseidon_proof（单组件 Poseidon，独立运行）

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::stwo_backend::column_layout_v2::{
        COL_SYSCALL_ID, IS_ECALL, IS_PADDING, NUM_COLUMNS,
    };
    use crate::stwo_backend::trace_native::{
        step_to_m31_row, trace_to_memory_trace, trace_to_native, NativeTrace, TraceBuilder,
    };
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

    /// 构造一个带内存访问记录的 Step（用于 Load/Store 测试）。
    fn make_step_with_mem(
        pc: u32,
        instruction: Instruction,
        post_registers: [u32; 32],
        mem_access: Vec<crate::trace::MemAccess>,
    ) -> Step {
        Step {
            step_index: 0,
            pc,
            instruction,
            registers: post_registers,
            mem_access,
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

    /// 单步 trace prove/verify roundtrip 通用辅助（带 mem_access，用于 Load/Store）。
    fn prove_verify_single_step_with_mem(
        pc: u32,
        instruction: Instruction,
        prev_registers: &[u32; 32],
        post_registers: [u32; 32],
        mem_access: Vec<crate::trace::MemAccess>,
    ) {
        let step = make_step_with_mem(pc, instruction, post_registers, mem_access);
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

        // v3：ValueA 已移除（死列），仅填充 ValueAEff/ValueB/ValueC
        for (base, val) in [
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

    // ----- Phase 3 Load/Store prove/verify roundtrip 测试 -----

    #[test]
    fn test_prove_verify_roundtrip_lw() {
        // LW x1, x2, 8（从 x2+8 地址加载 4 字节到 x1）
        // x2 = 0x1000，addr = 0x1000 + 8 = 0x1008
        // 加载值 = 0xDEADBEEF，写入 x1
        let mut prev = zero_registers();
        prev[2] = 0x1000;
        let mut post = prev;
        post[1] = 0xDEADBEEF;
        let mem_access = vec![crate::trace::MemAccess {
            addr: 0x1008,
            op: crate::trace::MemOp::Read,
            value: 0xDEADBEEF,
            size: 4,
        }];
        prove_verify_single_step_with_mem(
            0,
            Instruction::Lw { rd: 1, rs1: 2, imm: 8 },
            &prev,
            post,
            mem_access,
        );
    }

    #[test]
    fn test_prove_verify_roundtrip_lb() {
        // LB x1, x2, 0（从 x2 地址加载 1 字节，符号扩展到 32 位）
        // x2 = 0x2000，addr = 0x2000
        // 加载值 = 0x80（符号扩展为 0xFFFFFF80）
        let mut prev = zero_registers();
        prev[2] = 0x2000;
        let mut post = prev;
        post[1] = 0xFFFFFF80;
        let mem_access = vec![crate::trace::MemAccess {
            addr: 0x2000,
            op: crate::trace::MemOp::Read,
            value: 0xFFFFFF80,
            size: 1,
        }];
        prove_verify_single_step_with_mem(
            0,
            Instruction::Lb { rd: 1, rs1: 2, imm: 0 },
            &prev,
            post,
            mem_access,
        );
    }

    #[test]
    fn test_prove_verify_roundtrip_lbu() {
        // LBU x1, x2, 4（从 x2+4 地址加载 1 字节，零扩展到 32 位）
        // x2 = 0x3000，addr = 0x3004
        // 加载值 = 0x80（零扩展为 0x00000080）
        let mut prev = zero_registers();
        prev[2] = 0x3000;
        let mut post = prev;
        post[1] = 0x00000080;
        let mem_access = vec![crate::trace::MemAccess {
            addr: 0x3004,
            op: crate::trace::MemOp::Read,
            value: 0x00000080,
            size: 1,
        }];
        prove_verify_single_step_with_mem(
            0,
            Instruction::Lbu { rd: 1, rs1: 2, imm: 4 },
            &prev,
            post,
            mem_access,
        );
    }

    #[test]
    fn test_prove_verify_roundtrip_sw() {
        // SW x2, x3, 16（将 x3 的值存到 x2+16 地址）
        // x2 = 0x4000，addr = 0x4000 + 16 = 0x4010
        // 存储值 = x3 = 0xCAFEBABE
        let mut prev = zero_registers();
        prev[2] = 0x4000;
        prev[3] = 0xCAFEBABE;
        let post = prev; // Store 不写寄存器
        let mem_access = vec![crate::trace::MemAccess {
            addr: 0x4010,
            op: crate::trace::MemOp::Write,
            value: 0xCAFEBABE,
            size: 4,
        }];
        prove_verify_single_step_with_mem(
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 16 },
            &prev,
            post,
            mem_access,
        );
    }

    #[test]
    fn test_prove_verify_roundtrip_sb() {
        // SB x2, x3, 0（将 x3 的低字节存到 x2 地址）
        // x2 = 0x5000，addr = 0x5000
        // 存储值 = x3 = 0xAB（低字节）
        let mut prev = zero_registers();
        prev[2] = 0x5000;
        prev[3] = 0xAB;
        let post = prev;
        let mem_access = vec![crate::trace::MemAccess {
            addr: 0x5000,
            op: crate::trace::MemOp::Write,
            value: 0xAB,
            size: 1,
        }];
        prove_verify_single_step_with_mem(
            0,
            Instruction::Sb { rs1: 2, rs2: 3, imm: 0 },
            &prev,
            post,
            mem_access,
        );
    }

    #[test]
    fn test_prove_verify_roundtrip_lw_sw_sequence() {
        // 混合 Load/Store 序列：
        // Step 0: SW x2, x3, 0（x3=0x12345678 存到 x2+0）
        // Step 1: LW x4, x2, 0（从 x2+0 加载到 x4，期望 x4 = 0x12345678）
        let mut prev = zero_registers();
        prev[2] = 0x6000;
        prev[3] = 0x12345678;

        // Step 0: SW
        let post0 = prev;
        let step0 = make_step_with_mem(
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 0 },
            post0,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Write,
                value: 0x12345678,
                size: 4,
            }],
        );
        let row0 = step_to_m31_row(&step0, &prev);
        prev = post0;

        // Step 1: LW
        let mut post1 = prev;
        post1[4] = 0x12345678;
        let step1 = make_step_with_mem(
            4,
            Instruction::Lw { rd: 4, rs1: 2, imm: 0 },
            post1,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Read,
                value: 0x12345678,
                size: 4,
            }],
        );
        let row1 = step_to_m31_row(&step1, &prev);

        let mut builder = TraceBuilder::new(10);
        builder.fill_row(&row0);
        builder.fill_row(&row1);
        builder.fill_padding_to_full();
        let trace = builder.finalize();
        let log_size = trace.log_size;

        let proof = prove_cpu_trace(&trace).expect("prove 失败：LW/SW 序列应满足所有约束");
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }

    // ----- Phase 3.5 多组件 prove/verify roundtrip 测试（CPU + Memory logup）-----

    /// 构造一个带 step_index 的 Step（用于多组件测试，Memory trace 依赖 step_index 作为 TsCur）。
    fn make_step_indexed(
        step_index: u64,
        pc: u32,
        instruction: Instruction,
        post_registers: [u32; 32],
        mem_access: Vec<crate::trace::MemAccess>,
    ) -> Step {
        Step {
            step_index,
            pc,
            instruction,
            registers: post_registers,
            mem_access,
        }
    }

    /// 多组件 prove/verify roundtrip 通用辅助。
    /// 输入：emulator Trace（已包含所有 Step），自动生成 CPU + Memory trace 并 prove/verify。
    fn prove_verify_multi_component(emulator_trace: &crate::trace::Trace) {
        let cpu_trace = trace_to_native(emulator_trace);
        let mem_trace = trace_to_memory_trace(emulator_trace);
        let log_size = cpu_trace.log_size;
        assert_eq!(
            log_size, mem_trace.log_size,
            "CPU 和 Memory trace 的 log_size 必须一致"
        );

        let proof = prove_cpu_memory_trace(&cpu_trace, &mem_trace).expect("prove 失败");
        verify_cpu_memory_proof(proof, log_size).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_multi_padding_only() {
        // 空 emulator Trace：0 步 → CPU trace 全 padding + Memory trace 全 padding
        // CPU padding 行：IsPadding=1，multiplicity=0（无 Load/Store）
        // Memory padding 行：IsPadding=1，multiplicity=0
        // soundness：claimed_sum_cpu=0, claimed_sum_mem=0，total=0 ✓
        let emulator_trace = crate::trace::Trace::new();
        prove_verify_multi_component(&emulator_trace);
    }

    #[test]
    fn test_prove_verify_multi_lw() {
        // LW x1, x2, 8（从 x2+8 地址加载 4 字节到 x1）
        // x2 = 0x1000，addr = 0x1008，加载值 = 0xDEADBEEF
        //
        // CPU claim：values=(0x1008, 0xDEADBEEF, IsStore=0)，multiplicity=+1
        // Memory yield：values=(0x1008, 0xDEADBEEF, IsStore=0)，multiplicity=-1
        // soundness：+1 + (-1) = 0 ✓
        let mut prev = zero_registers();
        prev[2] = 0x1000;
        let initial_prev = prev; // 保存 step 0 的 prev_registers
        let mut post = prev;
        post[1] = 0xDEADBEEF;
        let step = make_step_indexed(
            0,
            0,
            Instruction::Lw { rd: 1, rs1: 2, imm: 8 },
            post,
            vec![crate::trace::MemAccess {
                addr: 0x1008,
                op: crate::trace::MemOp::Read,
                value: 0xDEADBEEF,
                size: 4,
            }],
        );
        let mut emulator_trace = crate::trace::Trace::new();
        emulator_trace.set_initial_registers(initial_prev);
        emulator_trace.push_step(step);
        prove_verify_multi_component(&emulator_trace);
    }

    #[test]
    fn test_prove_verify_multi_sw() {
        // SW x2, x3, 16（将 x3 的值存到 x2+16 地址）
        // x2 = 0x4000，addr = 0x4010，存储值 = 0xCAFEBABE
        //
        // CPU claim：values=(0x4010, 0xCAFEBABE, IsStore=1)，multiplicity=+1
        // Memory yield：values=(0x4010, 0xCAFEBABE, IsStore=1)，multiplicity=-1
        // soundness：+1 + (-1) = 0 ✓
        let mut prev = zero_registers();
        prev[2] = 0x4000;
        prev[3] = 0xCAFEBABE;
        let initial_prev = prev; // 保存 step 0 的 prev_registers
        let post = prev; // Store 不写寄存器
        let step = make_step_indexed(
            0,
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 16 },
            post,
            vec![crate::trace::MemAccess {
                addr: 0x4010,
                op: crate::trace::MemOp::Write,
                value: 0xCAFEBABE,
                size: 4,
            }],
        );
        let mut emulator_trace = crate::trace::Trace::new();
        emulator_trace.set_initial_registers(initial_prev);
        emulator_trace.push_step(step);
        prove_verify_multi_component(&emulator_trace);
    }

    #[test]
    fn test_prove_verify_multi_lw_sw_sequence() {
        // SW + LW 序列（同地址）：
        // Step 0: SW x2, x3, 0（x3=0x12345678 存到 x2+0=0x6000）
        // Step 1: LW x4, x2, 0（从 x2+0=0x6000 加载到 x4，期望 x4=0x12345678）
        //
        // Memory trace（按 (addr, ts) 排序）：
        //   Row 0: addr=0x6000, val=0x12345678, ts=0, IsStore=1, IsFirstAccess=1
        //   Row 1: addr=0x6000, val=0x12345678, ts=1, IsStore=0, IsFirstAccess=0
        //     (ValPrev=0x12345678=prev.ValCur, TsPrev=0=prev.TsCur)
        //
        // CPU claims:
        //   Row 0: (0x6000, 0x12345678, IsStore=1)，mult=+1
        //   Row 1: (0x6000, 0x12345678, IsStore=0)，mult=+1
        // Memory yields:
        //   Row 0: (0x6000, 0x12345678, IsStore=1)，mult=-1
        //   Row 1: (0x6000, 0x12345678, IsStore=0)，mult=-1
        // soundness：(+1++1) + (-1+-1) = 0 ✓
        let mut prev = zero_registers();
        prev[2] = 0x6000;
        prev[3] = 0x12345678;
        let initial_prev = prev; // 保存 step 0 的 prev_registers

        // Step 0: SW
        let post0 = prev;
        let step0 = make_step_indexed(
            0,
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 0 },
            post0,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Write,
                value: 0x12345678,
                size: 4,
            }],
        );
        prev = post0;

        // Step 1: LW
        let mut post1 = prev;
        post1[4] = 0x12345678;
        let step1 = make_step_indexed(
            1,
            4,
            Instruction::Lw { rd: 4, rs1: 2, imm: 0 },
            post1,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Read,
                value: 0x12345678,
                size: 4,
            }],
        );

        let mut emulator_trace = crate::trace::Trace::new();
        emulator_trace.set_initial_registers(initial_prev);
        emulator_trace.push_step(step0);
        emulator_trace.push_step(step1);
        prove_verify_multi_component(&emulator_trace);
    }

    #[test]
    fn test_prove_verify_multi_mixed_load_store_different_addrs() {
        // 不同地址的 Load/Store 混合：
        // Step 0: SW x2, x3, 0（addr=0x7000, val=0xAABBCCDD）
        // Step 1: LW x4, x5, 0（addr=0x8000, val=0x11223344）
        //
        // Memory trace（按 (addr, ts) 排序）：
        //   Row 0: addr=0x7000, val=0xAABBCCDD, ts=0, IsStore=1, IsFirstAccess=1
        //   Row 1: addr=0x8000, val=0x11223344, ts=1, IsStore=0, IsFirstAccess=1
        //     (不同 addr，IsFirstAccess=1, ValPrev=0, TsPrev=0)
        //
        // CPU claims:
        //   Row 0: (0x7000, 0xAABBCCDD, IsStore=1)，mult=+1
        //   Row 1: (0x8000, 0x11223344, IsStore=0)，mult=+1
        // Memory yields:
        //   Row 0: (0x7000, 0xAABBCCDD, IsStore=1)，mult=-1
        //   Row 1: (0x8000, 0x11223344, IsStore=0)，mult=-1
        // soundness：(+1++1) + (-1+-1) = 0 ✓
        let mut prev = zero_registers();
        prev[2] = 0x7000;
        prev[3] = 0xAABBCCDD;
        prev[5] = 0x8000;
        let initial_prev = prev; // 保存 step 0 的 prev_registers

        // Step 0: SW
        let post0 = prev;
        let step0 = make_step_indexed(
            0,
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 0 },
            post0,
            vec![crate::trace::MemAccess {
                addr: 0x7000,
                op: crate::trace::MemOp::Write,
                value: 0xAABBCCDD,
                size: 4,
            }],
        );
        prev = post0;

        // Step 1: LW
        let mut post1 = prev;
        post1[4] = 0x11223344;
        let step1 = make_step_indexed(
            1,
            4,
            Instruction::Lw { rd: 4, rs1: 5, imm: 0 },
            post1,
            vec![crate::trace::MemAccess {
                addr: 0x8000,
                op: crate::trace::MemOp::Read,
                value: 0x11223344,
                size: 4,
            }],
        );

        let mut emulator_trace = crate::trace::Trace::new();
        emulator_trace.set_initial_registers(initial_prev);
        emulator_trace.push_step(step0);
        emulator_trace.push_step(step1);
        prove_verify_multi_component(&emulator_trace);
    }

    /// 诊断测试：打印 Memory trace 的前几行值，手动验证连续性约束。
    #[test]
    fn test_diag_memory_trace_values() {
        use crate::stwo_backend::memory_air::{
            MEM_COL_ADDR_BASE, MEM_COL_IS_FIRST_ACCESS, MEM_COL_IS_PADDING, MEM_COL_IS_STORE,
            MEM_COL_TS_CUR_BASE, MEM_COL_TS_PREV_BASE, MEM_COL_VAL_CUR_BASE, MEM_COL_VAL_PREV_BASE,
        };
        use crate::stwo_backend::trace_native::{trace_to_memory_trace, MemoryTrace};

        fn read_word(trace: &MemoryTrace, row: usize, base: usize) -> u32 {
            let mut val = 0u32;
            for i in 0..4 {
                let v = trace.cols[base + i][row].0;
                val |= v << (8 * i);
            }
            val
        }

        // 同地址 SW + LW 序列
        let mut prev = zero_registers();
        prev[2] = 0x6000;
        prev[3] = 0x12345678;
        let initial_prev = prev;

        let post0 = prev;
        let step0 = make_step_indexed(
            0,
            0,
            Instruction::Sw { rs1: 2, rs2: 3, imm: 0 },
            post0,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Write,
                value: 0x12345678,
                size: 4,
            }],
        );
        prev = post0;

        let mut post1 = prev;
        post1[4] = 0x12345678;
        let step1 = make_step_indexed(
            1,
            4,
            Instruction::Lw { rd: 4, rs1: 2, imm: 0 },
            post1,
            vec![crate::trace::MemAccess {
                addr: 0x6000,
                op: crate::trace::MemOp::Read,
                value: 0x12345678,
                size: 4,
            }],
        );

        let mut emulator_trace = crate::trace::Trace::new();
        emulator_trace.set_initial_registers(initial_prev);
        emulator_trace.push_step(step0);
        emulator_trace.push_step(step1);

        let mem_trace = trace_to_memory_trace(&emulator_trace);
        println!("Memory trace log_size = {}", mem_trace.log_size);
        println!("Memory trace num_rows = {}", mem_trace.num_rows());

        // 打印前 4 行
        for row in 0..4 {
            let addr = read_word(&mem_trace, row, MEM_COL_ADDR_BASE);
            let val_cur = read_word(&mem_trace, row, MEM_COL_VAL_CUR_BASE);
            let val_prev = read_word(&mem_trace, row, MEM_COL_VAL_PREV_BASE);
            let ts_cur = read_word(&mem_trace, row, MEM_COL_TS_CUR_BASE);
            let ts_prev = read_word(&mem_trace, row, MEM_COL_TS_PREV_BASE);
            let is_store = mem_trace.cols[MEM_COL_IS_STORE][row].0;
            let is_padding = mem_trace.cols[MEM_COL_IS_PADDING][row].0;
            let is_first = mem_trace.cols[MEM_COL_IS_FIRST_ACCESS][row].0;
            println!(
                "Row {}: addr=0x{:08X} val_cur=0x{:08X} val_prev=0x{:08X} ts_cur={} ts_prev={} is_store={} is_padding={} is_first={}",
                row, addr, val_cur, val_prev, ts_cur, ts_prev, is_store, is_padding, is_first
            );
        }

        // 手动验证 row 1 的连续性约束
        // is_continuation = (1 - is_padding) * (1 - is_first) at row 1
        let row1_is_padding = mem_trace.cols[MEM_COL_IS_PADDING][1].0;
        let row1_is_first = mem_trace.cols[MEM_COL_IS_FIRST_ACCESS][1].0;
        let row1_is_cont = (1 - row1_is_padding) * (1 - row1_is_first);
        println!("\nRow 1 is_continuation = {}", row1_is_cont);

        if row1_is_cont == 1 {
            let row0_val_cur = read_word(&mem_trace, 0, MEM_COL_VAL_CUR_BASE);
            let row1_val_prev = read_word(&mem_trace, 1, MEM_COL_VAL_PREV_BASE);
            let row0_ts_cur = read_word(&mem_trace, 0, MEM_COL_TS_CUR_BASE);
            let row1_ts_prev = read_word(&mem_trace, 1, MEM_COL_TS_PREV_BASE);
            println!(
                "Continuity check: row1.ValPrev=0x{:08X} vs row0.ValCur=0x{:08X} → {}",
                row1_val_prev,
                row0_val_cur,
                if row1_val_prev == row0_val_cur { "OK" } else { "MISMATCH" }
            );
            println!(
                "Continuity check: row1.TsPrev={} vs row0.TsCur={} → {}",
                row1_ts_prev,
                row0_ts_cur,
                if row1_ts_prev == row0_ts_cur { "OK" } else { "MISMATCH" }
            );
        }
    }

    // =======================================================================
    // Phase 4 Tier 1 测试：ECALL dispatch 约束
    // =======================================================================
    //
    // 验证内容：
    // 1. ECALL 行 prove/verify 通过（不破坏现有功能）
    // 2. 非 ECALL 行 ECALL 列 zero gating soundness（篡改被拒绝）
    // 3. IS_ECALL binality soundness（非 0/1 值被拒绝）
    //
    // Tier 1 限制：
    // - 不启用 ecall_lookup（用 new_with_lookup 而非 new_with_ecall_lookup）
    // - ECALL 行的 25 列 ECALL dispatch 暂填 0（Tier 2 实施 Precompile AIR 后填充）
    // - 不测试 ECALL logup claim + yield 平衡（Tier 2+ 测试）

    /// 辅助：构造一个包含单条 ECALL 指令的 NativeTrace。
    ///
    /// ECALL 行布局：
    /// - IS_ECALL = 1（indicator one-hot）
    /// - PC = 0, PcNext = 4（ECALL 不跳转，pc+4）
    /// - 25 列 ECALL dispatch 全为 0（Tier 1 trace 填充暂留 0）
    fn make_single_ecall_trace() -> NativeTrace {
        use crate::stwo_backend::column_layout_v2::*;
        use crate::stwo_backend::trace_native::u32_to_m31_limbs;

        let mut builder = TraceBuilder::new(10); // 1024 行

        let mut row = vec![M31::from(0u32); NUM_COLUMNS];

        // PC = 0
        let pc_limbs = u32_to_m31_limbs(0);
        for i in 0..4 {
            row[COL_PC_BASE + i] = pc_limbs[i];
        }
        // next_pc = 4（ECALL 后继续执行下一条指令）
        let next_pc_limbs = u32_to_m31_limbs(4);
        for i in 0..4 {
            row[COL_PC_NEXT_BASE + i] = next_pc_limbs[i];
        }

        // IS_ECALL = 1（indicator one-hot，其他 indicator 全为 0）
        row[IS_ECALL] = M31::from(1u32);

        // 25 列 ECALL dispatch 全为 0（Tier 1 trace 填充暂留 0）
        // row 已用 vec![M31::from(0u32); NUM_COLUMNS] 初始化，无需额外操作

        builder.fill_row(&row);
        builder.fill_padding_to_full();
        builder.finalize()
    }

    #[test]
    fn test_prove_verify_roundtrip_ecall() {
        // Phase 4 Tier 1：含 ECALL 指令的 trace prove/verify 通过
        // 验证：
        // - IS_ECALL binality 约束（C57）：IS_ECALL * (IS_ECALL - 1) = 1 * 0 = 0 ✓
        // - ECALL zero gating（C58-C82）：ECALL 行 IS_ECALL=1，(1-1)*col = 0 自动成立 ✓
        // - 非 ECALL（padding）行：IS_ECALL=0，(1-0)*0 = 0 ✓
        let trace = make_single_ecall_trace();
        let log_size = trace.log_size;

        let proof = prove_cpu_trace(&trace).expect("prove 失败：ECALL 约束应满足");
        verify_cpu_proof(proof, log_size).expect("verify 失败");
    }

    #[test]
    fn test_ecall_zero_gating_soundness() {
        // Phase 4 Tier 1 soundness：非 ECALL 行的 ECALL 列必须为 0
        //
        // 篡改：将 padding 行（非 ECALL）的 SyscallId 列设为 1（非 0）
        // 预期：prove 失败（zero gating 约束 (1-IS_ECALL)*SyscallId = 1*1 = 1 != 0）
        let mut trace = make_single_ecall_trace();

        // 找到第一个 padding 行（row 1，因为 row 0 是 ECALL 行）
        let padding_row = 1;
        assert_eq!(
            trace.cols[IS_PADDING][padding_row].0,
            1,
            "row {} 应为 padding 行",
            padding_row
        );
        assert_eq!(
            trace.cols[IS_ECALL][padding_row].0,
            0,
            "padding 行 IS_ECALL 应为 0"
        );

        // 篡改：padding 行的 SyscallId 列设为 1
        trace.cols[COL_SYSCALL_ID][padding_row] = M31::from(1u32);

        // 预期 prove 失败（zero gating 约束被违反）
        let result = prove_cpu_trace(&trace);
        assert!(
            result.is_err(),
            "篡改非 ECALL 行的 SyscallId 应导致 prove 失败（zero gating soundness）"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("ConstraintsNotSatisfied")
                || err_msg.contains("Constraint"),
            "错误应为 ConstraintsNotSatisfied，实际：{}",
            err_msg
        );
    }

    #[test]
    fn test_ecall_binality_soundness() {
        // Phase 4 Tier 1 soundness：IS_ECALL 必须 ∈ {0, 1}
        //
        // 篡改：将 ECALL 行的 IS_ECALL 设为 2（非 0/1）
        // 预期：prove 失败（binality 约束 IS_ECALL * (IS_ECALL - 1) = 2 * 1 = 2 != 0）
        //       同时 indicator one-hot 约束 Σ Is_i = 2 + 0 + ... != 1 也会失败
        let mut trace = make_single_ecall_trace();

        // row 0 是 ECALL 行
        assert_eq!(trace.cols[IS_ECALL][0].0, 1, "row 0 应为 ECALL 行");

        // 篡改：IS_ECALL = 2（非 binary）
        trace.cols[IS_ECALL][0] = M31::from(2u32);

        // 预期 prove 失败
        let result = prove_cpu_trace(&trace);
        assert!(
            result.is_err(),
            "篡改 IS_ECALL 为非 binary 值应导致 prove 失败（binality soundness）"
        );
    }

    #[test]
    fn test_ecall_zero_gating_padding_row_all_zeros() {
        // v3：验证 padding 行的 ECALL dispatch 列（仅 SyscallId，1 列）全为 0
        // 这是 zero gating 约束的前提（trace 生成器正确填充）
        let trace = make_single_ecall_trace();

        // 检查所有 padding 行（row 1 到 1023）的 SyscallId 列为 0
        for row in 1..1024 {
            assert_eq!(
                trace.cols[COL_SYSCALL_ID][row].0,
                0,
                "padding row {} col {} 应为 0",
                row,
                COL_SYSCALL_ID
            );
        }
    }

    // ----- Phase 4 Tier 2: Poseidon 单组件 prover 测试 -----

    #[test]
    fn test_prove_verify_poseidon_empty() {
        // 空 hash_calls：trace 全 padding，claimed_sum = 0
        // 验证 Poseidon AIR padding 行约束（binality + one-hot + zero transition）
        let proof = prove_poseidon_trace(&[]).expect("prove 失败");
        // 空 trace log_size = 5（32 行）
        // v2.1：StarkProof.commitments.len() == 4（Tree 0 + Tree 1 + Tree 2 + composition poly tree）
        // 即使 Tree 0 为空也有 commitment。原 v1.0 断言 == 3 错误。
        assert_eq!(proof.stark_proof.commitments.len(), 4);
        // claimed_sum 应为 0（无 IsLastRound=1 的真实行）
        assert_eq!(proof.claimed_sum, SecureField::zero());

        // verify roundtrip
        verify_poseidon_proof(proof, 5).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_poseidon_single_hash() {
        // 单次 hash：30 行真实 + 2 行 padding = 32 行（log_size=5）
        // v2.1 关键里程碑：验证 SubDomain 评估模式有效（中间列降度方案解决 v1.0
        // `ConstraintsNotSatisfied` 卡点）。prove 成功即证明 AIR 约束满足。
        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let proof = prove_poseidon_trace(&[call]).expect("prove 失败");

        // v2.1 claimed_sum 机制修正：
        // Stwo `LogupTraceGenerator::finalize_last()` 返回 `claimed_sum = sum(num/denom)`
        // （而非 `sum(num)`，见 stwo-constraint-framework-2.3.0/src/prover/logup.rs:109-148）。
        // 单 hash 时只有 1 行 `num=-1`（IsLastRound=1 且非 padding），其余行 `num=0`，
        // 故 `claimed_sum = -1/denom_last_row`。denom 含从 channel draw 的随机 PoseidonLookup，
        // 因此 claimed_sum 是非确定的复杂 SecureField 值，无法断言具体数值。
        // 仅验证：
        // 1. prove 成功（AIR 约束满足 — v2.1 核心验证点）
        // 2. verify roundtrip 成功（证明完整性）
        // 3. claimed_sum ≠ 0（至少有一个非零贡献）
        assert_ne!(
            proof.claimed_sum,
            SecureField::zero(),
            "单 hash 的 claimed_sum 不应为 0"
        );

        // verify roundtrip
        verify_poseidon_proof(proof, 5).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_poseidon_multiple_hashes() {
        // 多次 hash：3 次 × 30 行 = 90 行 → log_size = 7（128 行）
        let calls = vec![
            PoseidonHashCall::from_input([
                BaseField::from(1u32),
                BaseField::from(2u32),
                BaseField::from(3u32),
            ]),
            PoseidonHashCall::from_input([
                BaseField::from(4u32),
                BaseField::from(5u32),
                BaseField::from(6u32),
            ]),
            PoseidonHashCall::from_input([
                BaseField::from(7u32),
                BaseField::from(8u32),
                BaseField::from(9u32),
            ]),
        ];
        let proof = prove_poseidon_trace(&calls).expect("prove 失败");

        // v2.1 claimed_sum 机制修正：见 test_prove_verify_poseidon_single_hash 注释。
        // 3 hash 时 `claimed_sum = sum_i(-1/denom_i)`（3 个 IsLastRound 行各贡献 -1/denom）。
        // denom 含随机 PoseidonLookup，无法断言具体数值，仅验证 prove+verify 成功 + 非零。
        assert_ne!(
            proof.claimed_sum,
            SecureField::zero(),
            "3 hash 的 claimed_sum 不应为 0"
        );

        // verify roundtrip
        verify_poseidon_proof(proof, 7).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_poseidon_invalid_log_size() {
        // 错误的 log_size 应导致 verify 失败
        let call = PoseidonHashCall::from_input([
            BaseField::from(1u32),
            BaseField::from(2u32),
            BaseField::from(3u32),
        ]);
        let proof = prove_poseidon_trace(&[call]).expect("prove 失败");

        // 用错误的 log_size（6 而非 5）验证，应失败
        let result = verify_poseidon_proof(proof, 6);
        assert!(result.is_err(), "用错误的 log_size 验证应失败");
    }

    #[test]
    fn test_prove_verify_poseidon_zero_input() {
        // 全零 input 的 hash：验证 Poseidon AIR 处理边界情况
        let call = PoseidonHashCall::from_input([
            BaseField::from(0u32),
            BaseField::from(0u32),
            BaseField::from(0u32),
        ]);
        let proof = prove_poseidon_trace(&[call]).expect("prove 失败");
        // v2.1 claimed_sum 机制修正：见 test_prove_verify_poseidon_single_hash 注释。
        // claimed_sum = -1/denom（非确定值），仅验证 prove+verify 成功 + 非零。
        assert_ne!(
            proof.claimed_sum,
            SecureField::zero(),
            "zero input 的 claimed_sum 不应为 0"
        );
        verify_poseidon_proof(proof, 5).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_poseidon_high_value_input() {
        // 高值 input（接近 M31_MAX = 2^31-2）的 hash
        let call = PoseidonHashCall::from_input([
            BaseField::from(2_000_000_000u32),
            BaseField::from(1_500_000_000u32),
            BaseField::from(2_147_483_646u32), // M31_MAX - 1
        ]);
        let proof = prove_poseidon_trace(&[call]).expect("prove 失败");
        // v2.1 claimed_sum 机制修正：见 test_prove_verify_poseidon_single_hash 注释。
        assert_ne!(
            proof.claimed_sum,
            SecureField::zero(),
            "high value input 的 claimed_sum 不应为 0"
        );
        verify_poseidon_proof(proof, 5).expect("verify 失败");
    }

    #[test]
    fn test_prove_verify_poseidon_many_hashes_padding() {
        // 多次 hash 导致 padding：5 次 × 30 行 = 150 行 → log_size = 8（256 行）
        // 验证 padding 行约束在更大规模下也成立
        let calls: Vec<PoseidonHashCall> = (0..5)
            .map(|i| {
                PoseidonHashCall::from_input([
                    BaseField::from(i + 1),
                    BaseField::from(i + 2),
                    BaseField::from(i + 3),
                ])
            })
            .collect();
        let proof = prove_poseidon_trace(&calls).expect("prove 失败");

        // v2.1 claimed_sum 机制修正：见 test_prove_verify_poseidon_single_hash 注释。
        // 5 hash 时 `claimed_sum = sum_i(-1/denom_i)`（非确定值），仅验证非零。
        assert_ne!(
            proof.claimed_sum,
            SecureField::zero(),
            "5 hash 的 claimed_sum 不应为 0"
        );

        // verify roundtrip
        verify_poseidon_proof(proof, 8).expect("verify 失败");
    }
}