//! # Stwo Prover — Circle STARK 证明生成
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 1.1" 与 §"proof 序列化格式"：
//! - [`StwoProverConfig`] — prover 配置（替代 [`crate::prover::ProverConfig`]）
//! - [`StwoProver`] — Stwo prover 入口（替代 HypernovaProver）
//! - [`StwoProof`] — 序列化的 STWO proof 结构
//! - [`serialize_stwo_proof`] / [`deserialize_stwo_proof`] — 二进制序列化
//!
//! ## STWO proof 序列化格式
//!
//! ```text
//! STWO proof format:
//!   magic: b"STWO" (4B)
//!   version: u8 (1B)
//!   public_io_commitment: [u8; 32] (32B)
//!   ccs_commitment: [u8; 32] (32B) — 保留用于兼容性
//!   stwo_proof_len: u32 LE (4B)
//!   stwo_proof: Vec<u8>
//! ```
//!
//! ## 当前状态（Phase 1.3）
//!
//! `StwoProver::prove()` 已接入 `stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>`，
//! 完整流程：ELF → trace → StwoTraceTable → CircleEvaluation → FrameworkComponent →
//! stark_proof → bincode 序列化 → StwoProof。

use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::isa::executor::execute_elf;
use crate::prover::ZkPublicIo;
use crate::prover::hash_public_io;
use crate::trace::Trace;
use crate::stwo_backend::air::cpu::CpuAirEval;
use crate::stwo_backend::air::opcode_table::{OpcodeLookupElements, OpcodeTableEval};
use crate::stwo_backend::column_layout::COL_OPCODE;
use crate::stwo_backend::trace::convert_trace_to_stwo;

// Stwo prover 相关导入（Phase 1.3 接入）
use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::prover::backend::simd::m31::N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::{SimdBackend, column::BaseColumn};
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::{BitReversedOrder, NaturalOrder};
use stwo::prover::{prove as stwo_prove, ComponentProver};
use stwo_constraint_framework::{
    FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, TraceLocationAllocator,
};

/// STWO proof magic 字节（替代 `b"HYPN"`）。
pub const STWO_MAGIC: &[u8; 4] = b"STWO";

/// STWO proof 格式版本。
pub const STWO_VERSION: u8 = 1;

/// STWO proof 总大小上限（与 Hypernova `MAX_ZKVM_PROOF_SIZE` 一致 = 64KB）。
///
/// Stwo raw STARK proof 通常 ~42KB；若超出 64KB，需 STARK-to-SNARK wrapping（Phase 5 评估）。
pub const MAX_STWO_PROOF_SIZE: usize = 64 * 1024;

/// Stwo prover 配置（替代 [`crate::prover::ProverConfig`]）。
///
/// 与 `ProverConfig` 的差异：
/// - 移除 `batch_size` / `max_n_vars` / `max_recursion_depth`（Stwo 无 fold，单次 prove）
/// - 移除 `parallel_ccs_compile` / `rayon_threads`（Stwo 内部管理并行度）
/// - 新增 `air_log_size`（AIR trace 行数 = 2^air_log_size）
#[derive(Clone, Debug)]
pub struct StwoProverConfig {
    /// AIR trace 行数 = `2^air_log_size`（默认 20，对应 1M step）。
    ///
    /// 实际行数取 `max(trace_len_padded, 2^air_log_size)`。
    /// Phase 1.3 POC 将根据 poker ELF 实际 trace 长度调整。
    pub air_log_size: u32,
    /// proof 字节数上限（默认 [`MAX_STWO_PROOF_SIZE`]）。
    pub proof_size_limit: usize,
    /// VRF 派生 seed（与 [`crate::prover::ProverConfig::randomness_seed`] 一致）。
    ///
    /// Phase 1.1 暂保留 BN254 Fr 类型以兼容 [`crate::prover::ZkPublicIo`]。
    /// Phase 4.x 评估是否改为纯 M31 表达。
    pub randomness_seed: crate::ccs::Fr,
}

impl Default for StwoProverConfig {
    fn default() -> Self {
        Self {
            air_log_size: 20,
            proof_size_limit: MAX_STWO_PROOF_SIZE,
            randomness_seed: crate::ccs::Fr::zero(),
        }
    }
}

impl StwoProverConfig {
    /// 校验配置参数合法性。
    pub fn validate(&self) -> Result<(), ZkvmError> {
        // 下限 10：SimdBackend MIN_LOG_SIZE=10（2^10=1024 行）
        // 上限 25：2^25=32M step，超出会 OOM（1M step × 47 列 × 4B ≈ 188MB，32M step ≈ 6GB）
        if self.air_log_size < 10 || self.air_log_size > 25 {
            return Err(ZkvmError::Other(format!(
                "StwoProverConfig: air_log_size {} 不在 [10, 25] 范围（SimdBackend MIN_LOG_SIZE=10, 上限 25 防 OOM）",
                self.air_log_size
            )));
        }
        if self.proof_size_limit == 0 {
            return Err(ZkvmError::Other(
                "StwoProverConfig: proof_size_limit 须 > 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Stwo prover 入口（替代 HypernovaProver）。
///
/// Phase 1.3 将接入 `stwo::prover::Prover`，完整实现 `prove()` 方法。
#[derive(Clone, Debug, Default)]
pub struct StwoProver {
    /// prover 配置
    pub config: StwoProverConfig,
}

/// 序列化的 STWO proof。
///
/// 参见模块级文档的"STWO proof 序列化格式"。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StwoProof {
    /// public_io 哈希承诺（32B）
    pub public_io_commitment: [u8; 32],
    /// CCS commitment（保留用于兼容性，32B）
    ///
    /// Stwo 主 AIR 无 CCS 概念，但保留此字段以兼容 poker_l1 链上 verifier 接口。
    /// 值为 AIR 结构的 hash commitment（Phase 4.x 实现时定义）。
    pub ccs_commitment: [u8; 32],
    /// Stwo 原生 proof 字节
    pub stwo_proof: Vec<u8>,
}

impl StwoProver {
    /// 创建新 prover 实例。
    pub fn new(config: StwoProverConfig) -> Self {
        Self { config }
    }

    /// 端到端证明生成：ELF → 执行 → trace → AIR → Stwo prove → STWO proof。
    ///
    /// # 流程（Phase 1.3）
    /// 1. `execute_elf(elf_bytes, input)` 生成 `ExecuteResult { trace, ... }`
    /// 2. `prove_internal(&trace, public_io)` 接入 Stwo prover
    ///
    /// # 参数
    /// - `elf_bytes` — ELF 字节
    /// - `input` — 程序输入
    /// - `public_io` — 公共输入输出（与 proof 绑定）
    ///
    /// # Errors
    /// - `ZkvmError::InvalidZkProofFormat` — ELF 校验失败（透传 `execute_elf`）
    /// - `ZkvmError::Other` — trace 为空 / Stwo prove 失败 / proof 序列化失败 / 超大小限制
    pub fn prove(
        &self,
        elf_bytes: &[u8],
        input: &[u8],
        public_io: &ZkPublicIo,
    ) -> Result<StwoProof, ZkvmError> {
        let exec_result = execute_elf(elf_bytes, input)?;
        self.prove_internal(&exec_result.trace, public_io)
    }

    /// 仅用 trace 生成 proof（绕过 `execute_elf`）。
    ///
    /// 仅供 POC 测试使用；生产环境应使用 [`Self::prove`]。
    ///
    /// 通过 `test-helpers` feature 门控，避免生产环境误用。
    ///
    /// # 参数
    /// - `trace` — 已构造的执行轨迹
    /// - `public_io` — 公共输入输出（与 proof 绑定）
    ///
    /// # Errors
    /// 同 [`Self::prove`] 第 2 步起的错误。
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn prove_from_trace(
        &self,
        trace: &Trace,
        public_io: &ZkPublicIo,
    ) -> Result<StwoProof, ZkvmError> {
        self.prove_internal(trace, public_io)
    }

    /// Stwo prove 内部实现（Step 2-11，由 `prove` 与 `prove_from_trace` 共享）。
    ///
    /// # 流程
    /// 1. `convert_trace_to_stwo(trace)` → `StwoTraceTable`
    /// 2. 计算 `log_size`（trace 行数 = 2^log_size）
    /// 3. `StwoTraceTable.columns` → `Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>`
    /// 4. 构造 `Blake2sChannel` + `PcsConfig::default()` + `twiddles` + `CommitmentSchemeProver`
    /// 5. commit 空 preprocessed tree（占位）+ original trace tree
    /// 6. 构造 `FrameworkComponent<CpuAirEval>`
    /// 7. `stwo::prover::prove::<SimdBackend, Blake2sMerkleChannel>` → `StarkProof<Blake2sMerkleHasher>`
    /// 8. `bincode::serialize(&stark_proof)` → `Vec<u8>`
    /// 9. 校验 proof 大小，组装 `StwoProof`
    fn prove_internal(
        &self,
        trace: &Trace,
        public_io: &ZkPublicIo,
    ) -> Result<StwoProof, ZkvmError> {
        // 1. trace → StwoTraceTable
        let stwo_trace = convert_trace_to_stwo(trace)?;

        // 2. 计算 log_size（trace 行数 = 2^log_size）
        let log_size_u32 = u32::try_from(stwo_trace.num_rows.trailing_zeros())
            .map_err(|e| ZkvmError::Other(format!("log_size u32 转换失败: {e}")))?;
        if (1usize << log_size_u32) != stwo_trace.num_rows {
            return Err(ZkvmError::Other(format!(
                "StwoProver::prove: num_rows {} 不是 2 的幂",
                stwo_trace.num_rows
            )));
        }
        if log_size_u32 < 10 {
            return Err(ZkvmError::Other(format!(
                "StwoProver::prove: log_size {} < 10 (SimdBackend MIN_LOG_SIZE=10, 2^10=1024 行)",
                log_size_u32
            )));
        }
        // 上限校验（防 OOM）
        if log_size_u32 > self.config.air_log_size {
            return Err(ZkvmError::Other(format!(
                "StwoProver::prove: log_size {} > 配置上限 {}",
                log_size_u32, self.config.air_log_size
            )));
        }

        // 3. StwoTraceTable.columns → Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
        //
        // Phase 2.1d Fix #4（关键修复）：`row_to_position` 索引不匹配。
        //
        // `build_row_to_position` 通过 `circle_domain_next_row` 迭代填充
        // `row_to_position[bit_reversed_index] = position`——**以位反转为键**
        //（因 `circle_domain_next_row` 的返回值是 `bit_reverse_index(...)`，即位反转索引）。
        //
        // 但 prover.rs 原代码使用自然顺序索引 `row` 查找：`values[row] = row_to_position[row]`，
        // 然后调用 `.bit_reverse()` 物理重排 values 数组。这导致最终 BitReversedOrder 的值
        // 与 `assert_constraints_on_trace` 测试期望的 `idx_col[bit_reversed_index] = position`
        // 不一致，使 OODS 检查失败（`ConstraintsNotSatisfied`）。
        //
        // 数学验证（log_size=3, n=8）：
        // - `row_to_position`（位反转为键）：`[0]=0, [7]=1, [4]=2, [3]=3, [2]=4, [5]=5, [6]=6, [1]=7`
        //   即数组形式 `[0,7,4,3,2,5,6,1]`（索引 0..7 对应位反转索引 0,1,2,...,7）
        // - 原代码 `values[row]=row_to_position[row]`（NaturalOrder）= `[0,7,4,3,2,5,6,1]`
        // - `.bit_reverse()` 后：`bit_rev[i]=values[bit_reverse_index(i,3)]`=`[0,2,4,6,7,5,3,1]` ❌
        // - 期望（与测试一致）：`bit_rev[i]=row_to_position[i]`=`[0,7,4,3,2,5,6,1]` ✓
        //
        // **修复**：构造 NaturalOrder 时用 `bit_reverse_index(row, log_size)` 查找 `row_to_position`：
        // - `values[row] = row_to_position[bit_reverse_index(row, log_size)]`
        // - `.bit_reverse()` 后：`bit_rev[i] = values[bit_reverse_index(i, log_size)]`
        //   = `row_to_position[bit_reverse_index(bit_reverse_index(i, log_size), log_size)]`
        //   = `row_to_position[i]`（双重 bit_reverse = identity）✓
        //
        // 验证依据：cpu.rs::test_cpu_air_eval_group_a_sequential_passes 使用
        // `build_group_a_circle_domain_trace` 构造 `idx_col[bit_reversed_index] = position`，
        // 通过 `assert_constraints_on_trace`，二者遍历顺序一致。
        //
        // **Phase 2.3.1 扩展**：Fix #4 重映射从仅 idx 列扩展到所有 13 列。
        //
        // 原因：Group B 约束 `(pc[next] - next_pc[cur]) * (1 - is_last_row) == 0` 是 transition
        // 约束，要求"CircleDomain order 中相邻行"对应"step order 中相邻步"。
        // 但 `circle_domain_next_row` 不满足 `bit_reverse(next) == bit_reverse(cur) + 1`
        //（实测 log_size=2/3/4/10 均不满足），所以若不重映射 pc/next_pc 列，
        // CircleDomain order 中"下一行"的 pc 值不是真正"下一步"的 pc，Group B 失败。
        //
        // 重映射后：对所有列 `col`，`col_natural[r] = trace_col[row_to_position[bit_reverse(r)]]`，
        // `.bit_reverse()` 后 `col_bitrev[i] = trace_col[row_to_position[i]]`，
        // 即 BitReversedOrder 中 row i 的值 = step `row_to_position[i]` 的 trace 值。
        //
        // 在 CircleDomain order 中（evaluator 遍历 position p，current_row = 满足
        // `row_to_position[current_row] == p` 的 row）：
        // - `value[position p] = col_bitrev[current_row_p] = trace_col[row_to_position[current_row_p]]`
        //   = `trace_col[p]` = step p 的 trace 值 ✓
        //
        // 因此 transition 约束在 CircleDomain order 中检查的就是 step order 中相邻步的关系：
        // - Group A: `idx[p+1] - idx[p] - 1 == 0` ⟺ `step[p+1].idx - step[p].idx - 1 == 0` ✓
        // - Group B: `pc[p+1] - next_pc[p] == 0` ⟺ `step[p+1].pc - step[p].next_pc == 0` ✓
        //   （因 `step[p].next_pc = step[p+1].pc`，由 `compile_step_witness` 保证）
        //
        // **Padding 注意**：当 trace 步数非 2 的幂时，padding 行（step_idx >= num_steps）
        // 的 trace 值为 0。这可能导致 Group B 在 real/padding 边界处失败。
        // Phase 2.3.x+ 需通过填充 padding 行的 pc/next_pc 或约束 masking 解决。
        // 当前 e2e 测试使用 2 的幂步数（1024, 1M），无 padding。
        let domain = CanonicCoset::new(log_size_u32).circle_domain();
        let row_to_position =
            crate::stwo_backend::air::cpu::build_row_to_position(log_size_u32);
        let num_rows = 1usize << log_size_u32;
        let trace_evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> =
            stwo_trace
                .columns
                .iter()
                .enumerate()
                .map(|(col_idx, col)| {
                    // Phase 2.3.1：对所有列应用 Fix #4 重映射（不再仅 idx 列）。
                    //
                    // 对 row r（natural order），查找 `step_idx = row_to_position[bit_reverse(r)]`，
                    // 取 `col[step_idx]` 作为 natural 值。`.bit_reverse()` 后，
                    // `bit_rev[i] = col[row_to_position[i]]` = step `row_to_position[i]` 的 trace 值。
                    //
                    // 对 idx 列（col 0）：`col[step_idx] = step_idx`（因 `step[s].idx = s`），
                    // 等价于旧逻辑 `BaseField::from(row_to_position[br] as u32)`，行为不变。
                    let _ = col_idx; // 列索引不再用于分支，保留参数避免改动签名
                    let values: BaseColumn = (0..num_rows)
                        .map(|row| {
                            let br = bit_reverse_index(row, log_size_u32);
                            let step_idx = row_to_position[br];
                            col[step_idx]
                        })
                        .collect();
                    let natural = CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(
                        domain, values,
                    );
                    // 显式指定 NaturalOrder 以消除 bit_reverse() 二义性
                    //（NaturalOrder::bit_reverse() → BitReversedOrder 是唯一适用的方法）
                    natural.bit_reverse()
                })
                .collect();

        // Phase 2.3.2：构造 OpcodeTable original trace（2 列，拼接到 CPU 13 列后）。
        //
        // OpcodeTable 是 LogUp 协议的 "table 侧"（yield），CPU 是 "use 侧"（claim）。
        // - `opcode_value` 列：row j ∈ [0, 34] = j；padding rows = 0
        // - `multiplicity` 列：row j ∈ [0, 34] = -count_j（M31 中存储为 P - count_j）；padding = 0
        //
        // 列序：CPU 13 列 (col 0-12) + OpcodeTable 2 列 (col 13-14) = 15 列 total。
        // `TraceLocationAllocator` 按组件构造顺序分配偏移：CPU 先注册 → cols 0-12，
        // OpcodeTable 后注册 → cols 13-14。
        //
        // **Fix #4 重映射**：与 CPU 列一致，应用 `row_to_position[bit_reverse(row)]` 重映射，
        // 使 BitReversedOrder 中 `col[i] = step[row_to_position[i]]` 的值。
        //
        // **opcode 计数**：遍历 CPU trace 的 opcode 列（col 12），统计每个 opcode 值 0..=34
        // 的出现次数。padding 行的 opcode = 0 也计入 count_0（LogUp 仍能成立，因 table 侧
        // 也 yield 相应数量的 -count_0）。
        const NUM_OPCODES: usize = crate::constraints::NUM_CATEGORIES; // 35 (0..=34)
        let opcode_col_natural: &Vec<BaseField> = &stwo_trace.columns[COL_OPCODE];
        let mut counts = [0u32; NUM_OPCODES];
        for &opcode_m31 in opcode_col_natural.iter() {
            let opcode_u32 = opcode_m31.0; // M31 inner u32 value
            if (opcode_u32 as usize) < NUM_OPCODES {
                counts[opcode_u32 as usize] += 1;
            }
            // opcode > 34 的行不计数；LogUp sum 将不匹配，proof 会失败（预期行为 = range check 失败）
        }

        // 构造 OpcodeTable 的 2 列（step order，后续应用 Fix #4 重映射）
        let opcode_value_step: Vec<BaseField> = (0..num_rows)
            .map(|step| {
                if step < NUM_OPCODES {
                    BaseField::from(step as u32)
                } else {
                    BaseField::from(0u32) // padding: opcode_value = 0
                }
            })
            .collect();
        let multiplicity_step: Vec<BaseField> = (0..num_rows)
            .map(|step| {
                if step < NUM_OPCODES {
                    // -count_j as M31 = P - count_j = 0 - count_j (in M31 arithmetic)
                    BaseField::from(0u32) - BaseField::from(counts[step])
                } else {
                    BaseField::from(0u32) // padding: multiplicity = 0
                }
            })
            .collect();

        // 应用 Fix #4 重映射 + bit_reverse，与 CPU trace_evals 构造逻辑一致
        let opcode_table_evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> =
            [opcode_value_step, multiplicity_step]
                .into_iter()
                .map(|step_col| {
                    let values: BaseColumn = (0..num_rows)
                        .map(|row| {
                            let br = bit_reverse_index(row, log_size_u32);
                            let step_idx = row_to_position[br];
                            step_col[step_idx]
                        })
                        .collect();
                    let natural = CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(
                        domain, values,
                    );
                    natural.bit_reverse()
                })
                .collect();

        // 4. 构造 channel + PcsConfig + twiddles + CommitmentSchemeProver
        let mut channel = Blake2sChannel::default();
        // Phase 2.1d：使用 `PcsConfig::default()`，不显式设置 `lifting_log_size`。
        //
        // **关键修复**：之前显式设置 `lifting_log_size = Some(max_constraint_log_degree_bound + 1)`
        //（当时 = L+3，因 max_constraint_log_degree_bound 错误为 L+2），导致
        // `max_log_degree_bound = L+2`，而 prover 的 `domain_log_size = L`，
        // verifier mask_points step = `G_{2^(L+2)}` ≠ prover step = `G_{2^L}`
        // → `ConstraintsNotSatisfied`（OODS 检查失败）。
        //
        // 修正 `max_constraint_log_degree_bound` 为 `L+1` 后（见 cpu.rs）：
        // - `EvaluationMode::infer` 返回 `SubDomain { log_expansion: 0 }`（因 `1 > 1` 为 false）
        // - SubDomain 模式直接借用 committed evals，无需 `set_store_polynomials_coefficients()`
        // - 所有 tree（preprocessed/trace/composition）的 commitment domain 大小一致（`2^(L+1)`），
        //   default `lifting_log_size = None` 会推断为 `split_composition_log_size = L+1`，
        //   使 `max_log_degree_bound = (L+1) - 1 = L`，与 `trace_log_size = L` 一致 ✓
        let config = PcsConfig::default();
        let max_constraint_log_degree_bound = CpuAirEval::new(
            log_size_u32,
            crate::stwo_backend::air::opcode_table::OpcodeLookupElements::dummy(),
        )
        .max_constraint_log_degree_bound();
        // twiddles 按 Stwo book 公式：
        // `CanonicCoset::new(log_size + LOG_CONSTRAINT_EVAL_BLOWUP_FACTOR + log_blowup_factor)`
        // = `CanonicCoset::new(max_constraint_log_degree_bound + log_blowup_factor)`
        // = `CanonicCoset::new((L+1) + 1) = CanonicCoset::new(L+2)`
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(
                max_constraint_log_degree_bound + config.fri_config.log_blowup_factor,
            )
            .circle_domain()
            .half_coset,
        );
        let mut commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // 5. commit preprocessed tree（is_last_row + is_lui column）+ original trace tree
        // Phase 2.1：preprocessed tree 包含 is_last_row column（末行=1，其余=0），
        // 用于 Group A 约束的 cyclic 边界豁免：(idx_next - idx_cur - 1) * (1 - is_last_row) == 0
        //
        // Phase 2.1d Fix #4（同 idx 列修复）：is_last_row 必须按 CircleDomain ordering
        // 标记末 position，且通过 `bit_reverse_index` 查找 `row_to_position`（以位反转为键）。
        //
        // CircleDomain order 中最后一个 position（n_rows-1）对应的 bit_reversed_index 才是
        // "末行"，而非自然顺序的 row n_rows-1。通过
        // `row_to_position[bit_reverse_index(i, log_size)] == n_rows - 1` 正确标记末 position。
        // `.bit_reverse()` 后，BitReversedOrder 中 `is_last_row[i] = 1` 当且仅当
        // `row_to_position[i] == n_rows - 1`，与 `assert_constraints_on_trace` 测试一致。
        //
        // Phase 2.3.3-a：新增 is_lui preprocessed column（LUI 行=1，其余=0）。
        // 用于 Group E LUI 约束的 indicator gating：`is_lui * (rd_val - imm) == 0`。
        // 构造方法：与 is_last_row 一致应用 Fix #4 重映射，对每行查找对应 step 的 opcode，
        // 若 opcode == 0（LUI）则置 1，否则置 0。
        {
            let is_last_row_col: Vec<BaseField> = (0..num_rows)
                .map(|i| {
                    let br = bit_reverse_index(i, log_size_u32);
                    if row_to_position[br] == num_rows - 1 {
                        BaseField::from(1u32)
                    } else {
                        BaseField::from(0u32)
                    }
                })
                .collect();
            let is_last_row_natural =
                CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(
                    domain,
                    // CircleEvaluation::new 期望 Col<SimdBackend, BaseField> = BaseColumn，
                    // 需通过 `.iter().copied().collect()` 将 Vec<BaseField> 转换为 BaseColumn
                    //（BaseColumn 实现了 FromIterator<BaseField>，与上方 trace_evals 构造一致）。
                    is_last_row_col.iter().copied().collect(),
                );
            let is_last_row_eval = is_last_row_natural.bit_reverse();

            // Phase 2.3.3-a/b：构造 Group E indicator preprocessed columns
            //
            // 所有 indicator column 共享相同构造模式：
            // 1. 对 row i（natural order），查找 step_idx = row_to_position[bit_reverse(i)]
            // 2. 取 opcode_col_natural[step_idx] 的 u32 值
            // 3. 若 predicate(opcode_u32) 为真则置 1，否则置 0
            // 4. `.bit_reverse()` 转为 BitReversedOrder
            //
            // `.bit_reverse()` 后，BitReversedOrder 中 `indicator[i] = 1` 当且仅当
            // predicate(opcode[row_to_position[i]]) 为真，与 evaluate 期望一致。
            //
            // 闭包封装避免代码重复（4 个 indicator 共享同一构造逻辑）。
            let make_indicator = |predicate: &dyn Fn(u32) -> bool| -> CircleEvaluation<SimdBackend, BaseField, BitReversedOrder> {
                let col: Vec<BaseField> = (0..num_rows)
                    .map(|i| {
                        let br = bit_reverse_index(i, log_size_u32);
                        let step_idx = row_to_position[br];
                        let opcode_u32 = opcode_col_natural[step_idx].0;
                        if predicate(opcode_u32) {
                            BaseField::from(1u32)
                        } else {
                            BaseField::from(0u32)
                        }
                    })
                    .collect();
                let natural = CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(
                    domain,
                    col.iter().copied().collect(),
                );
                natural.bit_reverse()
            };

            // Phase 2.3.3-a：is_lui（opcode == 0）
            let is_lui_eval = make_indicator(&|op| op == 0);

            // Phase 2.3.3-b：is_auipc（opcode == 1）
            let is_auipc_eval = make_indicator(&|op| op == 1);

            // Phase 2.3.3-b：is_slt（opcode ∈ {13, 14, 24, 25} = SLTI/SLTIU/SLT/SLTU）
            let is_slt_eval = make_indicator(&|op| matches!(op, 13 | 14 | 24 | 25));

            // Phase 2.3.3-b：is_logical_shift（opcode ∈ {15..=20, 23, 26..=30}
            //   = XORI/ORI/ANDI/SLLI/SRLI/SRAI/SLL/XOR/SRL/SRA/OR/AND）
            let is_logical_shift_eval =
                make_indicator(&|op| matches!(op, 15..=20 | 23 | 26..=30));

            // Phase 2.3.4-b：is_addi（opcode == 12 = ADDI）
            // 用于 Group E ADDI 约束的 indicator gating（limb decomposition）：
            //   - Low:  `is_addi * (rs1_val + imm - rd_val - 2^30 * carry_low) == 0`
            //   - High: `is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) == 0`
            let is_addi_eval = make_indicator(&|op| op == 12);

            // Phase 2.3.4-b：is_add（opcode == 21 = ADD）
            // 用于 Group E ADD 约束的 indicator gating（limb decomposition）：
            //   - Low:  `is_add * (rs1_val + rs2_val - rd_val - 2^30 * carry_low) == 0`
            //   - High: `is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) == 0`
            let is_add_eval = make_indicator(&|op| op == 21);

            // Phase 2.3.4-b：is_sub（opcode == 22 = SUB）
            // 用于 Group E SUB 约束的 indicator gating（limb decomposition，borrow 语义）：
            //   - Low:  `is_sub * (rs1_val - rs2_val - rd_val + 2^30 * carry_low) == 0`
            //   - High: `is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) == 0`
            //
            // **注意**：SUB 中 `carry` 列表示 borrow bit（=1 表示借位），与 ADD 中 `carry` 列表示
            // overflow bit 语义不同，但 Group F 二值性约束对两者都适用。
            let is_sub_eval = make_indicator(&|op| op == 22);

            // Phase 2.3.4-b：preprocessed tree 从 5 列扩展为 8 列
            //（is_last_row + is_lui + is_auipc + is_slt + is_logical_shift + is_addi + is_add + is_sub）
            let mut pp_builder = commitment_scheme.tree_builder();
            pp_builder.extend_evals(vec![
                is_last_row_eval,
                is_lui_eval,
                is_auipc_eval,
                is_slt_eval,
                is_logical_shift_eval,
                is_addi_eval,
                is_add_eval,
                is_sub_eval,
            ]);
            pp_builder.commit(&mut channel);

            // original trace tree（ORIGINAL_TRACE_IDX = 1）
            // Phase 2.3.2：CPU 13 列 + OpcodeTable 2 列 = 15 列 total
            let mut trace_builder = commitment_scheme.tree_builder();
            trace_builder.extend_evals(trace_evals);
            trace_builder.extend_evals(opcode_table_evals);
            trace_builder.commit(&mut channel);
        }

        // 6. Phase 2.3.2 LogUp 集成
        //
        // 在 original trace commit 后，从 channel 抽取随机挑战 `OpcodeLookupElements`（z, alpha）。
        // 这是 LogUp 协议的安全要求：prover 不能在 commit 前知道 z，否则可以伪造 lookup。
        //
        // 然后构建两组件的 interaction trace（cumsum 列）：
        // - CPU 侧 LogupTraceGenerator：每行写 frac = +1 / (opcode - z)
        // - OpcodeTable 侧 LogupTraceGenerator：row j 写 frac = -count_j / (j - z)，padding 写 0
        //
        // 两组件的 interaction trace（各 4 BaseField 列 = 1 SecureField cumsum）拼接为
        // 8 BaseField 列，commit 为 interaction tree（INTERACTION_TRACE_IDX = 2）。
        //
        // 最后用 `claimed_sum`（每组件 LogUp frac 总和）构造两个 FrameworkComponent。
        let opcode_lookup = OpcodeLookupElements::draw(&mut channel);

        // --- CPU LogupTraceGenerator ---
        // 每行 frac = +1 / (opcode - z)，其中 opcode 来自 CPU trace col 12（Fix #4 重映射后）。
        // num/den 按 SIMD vec_row 打包（每 PackedSecureField 含 16 lanes）。
        //
        // **den 计算**：通过 `Relation::combine(&opcode_lookup, &[opcode_val])` 计算
        // `opcode_val - z`（N=1 lookup: combine = alpha^0 * opcode - z = opcode - z）。
        // 不直接访问 `opcode_lookup.0.z`（私有字段）。
        let n_vec_rows = num_rows / N_LANES;
        let mut cpu_log_gen = LogupTraceGenerator::new(log_size_u32);
        let mut cpu_col_gen = cpu_log_gen.new_col();
        for vec_row in 0..n_vec_rows {
            let nums_arr = [SecureField::from(BaseField::from(1u32)); N_LANES];
            let mut dens_arr = [SecureField::from(BaseField::from(0u32)); N_LANES];
            for lane in 0..N_LANES {
                let logical_row = vec_row * N_LANES + lane;
                // logical_row 在 BitReversedOrder 中对应 step `row_to_position[logical_row]`
                //（因 trace_evals[col].values[logical_row] = col[row_to_position[logical_row]]）
                let step_idx = row_to_position[logical_row];
                let opcode_val = opcode_col_natural[step_idx]; // BaseField
                // den = combine([opcode]) = opcode - z
                dens_arr[lane] =
                    Relation::<BaseField, SecureField>::combine(&opcode_lookup, &[opcode_val]);
            }
            let packed_num = PackedSecureField::from_array(nums_arr);
            let packed_den = PackedSecureField::from_array(dens_arr);
            cpu_col_gen.write_frac(vec_row, packed_num, packed_den);
        }
        cpu_col_gen.finalize_col();
        let (cpu_interaction_trace, cpu_claimed_sum) = cpu_log_gen.finalize_last();

        // --- OpcodeTable LogupTraceGenerator ---
        // row j (step = row_to_position[logical_row]) 写 frac = -count_j / (j - z)（j < 35）
        // padding rows 写 frac = 0 / (0 - z) = 0
        let mut table_log_gen = LogupTraceGenerator::new(log_size_u32);
        let mut table_col_gen = table_log_gen.new_col();
        for vec_row in 0..n_vec_rows {
            let mut nums_arr = [SecureField::from(BaseField::from(0u32)); N_LANES];
            let mut dens_arr = [SecureField::from(BaseField::from(0u32)); N_LANES];
            for lane in 0..N_LANES {
                let logical_row = vec_row * N_LANES + lane;
                let step_idx = row_to_position[logical_row];
                if step_idx < NUM_OPCODES {
                    let opcode_j = BaseField::from(step_idx as u32);
                    let count_j = counts[step_idx];
                    // num = -count_j as SecureField
                    nums_arr[lane] = SecureField::from(BaseField::from(0u32))
                        - SecureField::from(BaseField::from(count_j));
                    // den = j - z = combine([j])
                    dens_arr[lane] =
                        Relation::<BaseField, SecureField>::combine(&opcode_lookup, &[opcode_j]);
                } else {
                    // padding: num = 0, den = combine([0]) = 0 - z = -z (非零，frac = 0)
                    dens_arr[lane] = Relation::<BaseField, SecureField>::combine(
                        &opcode_lookup,
                        &[BaseField::from(0u32)],
                    );
                }
            }
            let packed_num = PackedSecureField::from_array(nums_arr);
            let packed_den = PackedSecureField::from_array(dens_arr);
            table_col_gen.write_frac(vec_row, packed_num, packed_den);
        }
        table_col_gen.finalize_col();
        let (table_interaction_trace, table_claimed_sum) = table_log_gen.finalize_last();

        // --- Commit interaction tree ---
        // 8 BaseField 列 = CPU cumsum (4) + OpcodeTable cumsum (4)
        // 顺序与组件构造顺序一致：CPU 先 → interaction cols 0-3，OpcodeTable 后 → cols 4-7
        {
            let mut interaction_builder = commitment_scheme.tree_builder();
            interaction_builder.extend_evals(cpu_interaction_trace);
            interaction_builder.extend_evals(table_interaction_trace);
            interaction_builder.commit(&mut channel);
        }

        // 7. 构造两个 FrameworkComponent
        //
        // **关键**：组件构造顺序决定列偏移分配。
        // - CPU 先构造：original cols 0-12，interaction cols 0-3
        // - OpcodeTable 后构造：original cols 13-14，interaction cols 4-7
        //
        // `FrameworkComponent::new` 内部调用 `InfoEvaluator` 探测 `mask_offsets`，
        // 然后通过 `TraceLocationAllocator::next_for_structure` 分配列偏移。
        let mut location_allocator = TraceLocationAllocator::default();
        let cpu_eval = CpuAirEval::new(log_size_u32, opcode_lookup.clone());
        let cpu_component =
            FrameworkComponent::new(&mut location_allocator, cpu_eval, cpu_claimed_sum);

        let table_eval = OpcodeTableEval::new(log_size_u32, opcode_lookup.clone());
        let table_component =
            FrameworkComponent::new(&mut location_allocator, table_eval, table_claimed_sum);

        // 8. 调用 stwo::prover::prove（传入两组件）
        let components: &[&dyn ComponentProver<SimdBackend>] = &[&cpu_component, &table_component];
        let stark_proof = stwo_prove::<SimdBackend, Blake2sMerkleChannel>(
            components,
            &mut channel,
            commitment_scheme,
        )
        .map_err(|e| ZkvmError::Other(format!("Stwo prove 失败: {e:?}")))?;

        // 9. 序列化 StarkProof → Vec<u8>（用 bincode）
        let stwo_proof_bytes = bincode::serialize(&stark_proof)
            .map_err(|e| ZkvmError::Other(format!("StarkProof bincode 序列化失败: {e}")))?;

        // 10. 校验 proof 大小
        if stwo_proof_bytes.len() > self.config.proof_size_limit {
            return Err(ZkvmError::Other(format!(
                "Stwo proof 大小 {} 超出限制 {}",
                stwo_proof_bytes.len(),
                self.config.proof_size_limit
            )));
        }

        // 11. 组装 StwoProof
        let public_io_commitment = hash_stwo_public_io(public_io);
        let proof = StwoProof {
            public_io_commitment,
            ccs_commitment: [0u8; 32], // Phase 1.3：暂不绑定 ccs_commitment
            stwo_proof: stwo_proof_bytes,
        };

        Ok(proof)
    }
}

/// 序列化 `StwoProof` 为字节流。
///
/// 格式参见模块级文档的"STWO proof 序列化格式"。
pub fn serialize_stwo_proof(proof: &StwoProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 32 + 32 + 4 + proof.stwo_proof.len());
    out.extend_from_slice(STWO_MAGIC);
    out.push(STWO_VERSION);
    out.extend_from_slice(&proof.public_io_commitment);
    out.extend_from_slice(&proof.ccs_commitment);
    out.extend_from_slice(&(proof.stwo_proof.len() as u32).to_le_bytes());
    out.extend_from_slice(&proof.stwo_proof);
    out
}

/// 反序列化字节流为 `StwoProof`。
///
/// # 错误
/// - `InvalidZkProofFormat` — magic 不匹配 / version 不支持 / 长度字段越界
pub fn deserialize_stwo_proof(bytes: &[u8]) -> Result<StwoProof, ZkvmError> {
    // 总长度优先校验（防 OOM DoS）
    if bytes.len() > MAX_STWO_PROOF_SIZE {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "STWO proof 总长度 {} > MAX_STWO_PROOF_SIZE {}",
            bytes.len(),
            MAX_STWO_PROOF_SIZE
        )));
    }
    // 最小长度：magic(4) + version(1) + pio(32) + ccs(32) + len(4) = 73
    if bytes.len() < 73 {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "STWO proof 过短（{} < 73 字节最小长度）",
            bytes.len()
        )));
    }
    // magic 校验
    if &bytes[0..4] != STWO_MAGIC {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "STWO magic 不匹配: {:?}（期望 {:?}）",
            &bytes[0..4],
            STWO_MAGIC
        )));
    }
    // version 校验
    let version = bytes[4];
    if version != STWO_VERSION {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "STWO version 不支持: {}（仅支持 {}）",
            version, STWO_VERSION
        )));
    }
    // 读取固定字段
    let mut pos = 5usize;
    let mut public_io_commitment = [0u8; 32];
    public_io_commitment.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    let mut ccs_commitment = [0u8; 32];
    ccs_commitment.copy_from_slice(&bytes[pos..pos + 32]);
    pos += 32;
    // 读取 stwo_proof_len（u32 LE）
    let stwo_proof_len = u32::from_le_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
    ]) as usize;
    pos += 4;
    // 长度校验（防 OOM）
    let end = pos
        .checked_add(stwo_proof_len)
        .ok_or_else(|| ZkvmError::InvalidZkProofFormat("STWO proof: stwo_proof_len overflow".to_string()))?;
    if end > bytes.len() {
        return Err(ZkvmError::InvalidZkProofFormat(format!(
            "STWO proof: stwo_proof_len {} 越界（pos {} + len {} > bytes {}）",
            stwo_proof_len, pos, stwo_proof_len, bytes.len()
        )));
    }
    let stwo_proof = bytes[pos..end].to_vec();
    Ok(StwoProof {
        public_io_commitment,
        ccs_commitment,
        stwo_proof,
    })
}

/// 计算 `ZkPublicIo` 的 32B 哈希承诺（复用 Hypernova prover 的 `hash_public_io`）。
///
/// Stwo 与 Hypernova 共享同一 `ZkPublicIo` 结构，故 public_io 绑定校验逻辑完全复用。
pub fn hash_stwo_public_io(public_io: &ZkPublicIo) -> [u8; 32] {
    hash_public_io(public_io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField;

    #[test]
    fn test_stwo_proof_serialize_deserialize_roundtrip() {
        let proof = StwoProof {
            public_io_commitment: [0xAB; 32],
            ccs_commitment: [0xCD; 32],
            stwo_proof: vec![0x11, 0x22, 0x33, 0x44],
        };
        let bytes = serialize_stwo_proof(&proof);
        let restored = deserialize_stwo_proof(&bytes).expect("deserialize 失败");
        assert_eq!(restored, proof);
    }

    #[test]
    fn test_stwo_proof_rejects_wrong_magic() {
        let mut bytes = serialize_stwo_proof(&StwoProof {
            public_io_commitment: [0; 32],
            ccs_commitment: [0; 32],
            stwo_proof: vec![],
        });
        // 改坏 magic
        bytes[0] = b'X';
        assert!(deserialize_stwo_proof(&bytes).is_err());
    }

    #[test]
    fn test_stwo_proof_rejects_too_short() {
        assert!(deserialize_stwo_proof(b"STW").is_err());
        assert!(deserialize_stwo_proof(b"STWOX").is_err());
    }

    #[test]
    fn test_stwo_proof_rejects_oversized_length() {
        // 构造一个 stwo_proof_len 越界的 proof
        let mut bytes = vec![0u8; 73];
        bytes[0..4].copy_from_slice(STWO_MAGIC);
        bytes[4] = STWO_VERSION;
        // stwo_proof_len = u32::MAX（位于 offset 69..73）
        bytes[69..73].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(deserialize_stwo_proof(&bytes).is_err());
    }

    #[test]
    fn test_stwo_prover_config_validate() {
        // 合法配置（默认 air_log_size=20）
        assert!(StwoProverConfig::default().validate().is_ok());
        // air_log_size < 10（SimdBackend MIN_LOG_SIZE）
        let mut cfg = StwoProverConfig::default();
        cfg.air_log_size = 9;
        assert!(cfg.validate().is_err());
        // air_log_size > 25（OOM 阈值）
        cfg.air_log_size = 26;
        assert!(cfg.validate().is_err());
        // 边界值 10 合法
        cfg.air_log_size = 10;
        assert!(cfg.validate().is_ok());
        // 边界值 25 合法
        cfg.air_log_size = 25;
        assert!(cfg.validate().is_ok());
        // proof_size_limit = 0
        cfg.air_log_size = 20;
        cfg.proof_size_limit = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_stwo_prover_returns_error_on_empty_elf() {
        // 空 ELF 应在 execute_elf 阶段失败（validate_elf 拒绝空字节）
        let prover = StwoProver::default();
        let public_io = ZkPublicIo {
            input: vec![],
            output: vec![],
            randomness_seed: crate::ccs::Fr::zero(),
            initial_commitment: crate::ccs::Fr::zero(),
            final_commitment: crate::ccs::Fr::zero(),
            event_hashes: vec![],
        };
        let result = prover.prove(b"", b"", &public_io);
        assert!(result.is_err(), "空 ELF 应返回错误");
    }
}