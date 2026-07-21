//! # CPU AIR — Stwo FrameworkEval 实现（Phase 2 + 2.7 + 3）
//!
//! 严格遵循 `.trae/documents/stwo_phase2_cpu_air_design.md` + `stwo_phase3_memory_syscall_design.md`：
//! - 基于 Stwo 原生 `FrameworkEval` + `EvalAtRow` + `add_constraint`
//! - 4×8-bit limb 方案，16-bit 边界 carry/borrow
//! - Phase 2.4：ADD/ADDI/SUB 约束 + 通用 binality/one-hot 约束
//! - Phase 2.7：PC 递增 + JAL/JALR/Branch + LUI/AUIPC 约束
//! - Phase 3：Load/Store 地址 + 值匹配约束
//!
//! ## 约束清单（Phase 3）
//!
//! | # | 约束 | 度 | gating | 说明 |
//! |---|------|----|--------|------|
//! | 1-4 | ADD limb + carry binality | 2-3 | IsAdd | 4×8-bit limb 加法 |
//! | 5-8 | ADDI limb + carry binality | 2-3 | IsAddi | 同 ADD，ImmC=1 |
//! | 9-12 | SUB limb + borrow binality | 2-3 | IsSub | 4×8-bit limb 减法 |
//! | 13 | IsPadding binality | 2 | 通用 | IsPadding·(IsPadding−1) = 0 |
//! | 14 | Indicator one-hot | 1 | 通用 | Σ Is_i = 1 |
//! | 15 | Taken binality | 2 | 通用 | Taken·(Taken−1) = 0 |
//! | 16-19 | PC 递增（4 limb） | 2 | IsNonFlow | PcNext[i] = Pc[i] + 4_limb[i] |
//! | 20-23 | JAL（4 limb） | 2 | IsJal | PcNext[i] = Helper2[i] = (Pc+imm)[i] |
//! | 24-27 | JALR（4 limb） | 2 | IsJalr | PcNext[i] = PcNextAux[i] |
//! | 28-31 | Branch（4 limb） | 3 | IsBranch | (1−Taken)·(PcNext−Pc−4) + Taken·(PcNext−Helper2) = 0 |
//! | 32-35 | LUI（4 limb） | 2 | IsLui | rd_eff[i] = Helper1[i] = imm[i] |
//! | 36-39 | AUIPC（4 limb） | 2 | IsAuipc | rd_eff[i] = Helper2[i] = (Pc+imm)[i] |
//! | 40-43 | Load addr（4 limb） | 3 | IsLoad | MemAddr[i] = rs1[i] + imm[i]（带 carry） |
//! | 44-47 | Load 值匹配（4 limb） | 2 | IsLoad | rd_eff[i] = MemValue[i]（暂用 Helper3） |
//! | 48-51 | Store addr（4 limb） | 3 | IsStore | MemAddr[i] = rs1[i] + imm[i]（带 carry） |
//! | 52-55 | Store 值匹配（4 limb） | 2 | IsStore | MemValue[i] = rs2[i]（暂用 Helper3） |
//!
//! 所有约束的最大总度 = 3（gating × binality），因此
//! `max_constraint_log_degree_bound = log_size + 1`（参见 stwo-book 度数表）。

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use super::column_layout_v2::{
    COL_CARRY_FLAG_BASE, COL_HELPER_A_BASE, COL_HELPER_B_BASE,
    COL_IS_BASE, COL_MEM_ADDR_BASE, COL_PC_BASE,
    COL_PC_CARRY_FLAG_BASE, COL_PC_NEXT_BASE, COL_SYSCALL_ID,
    COL_TAKEN, COL_VALUE_A_EFF_BASE,
    COL_VALUE_B_BASE, COL_VALUE_C_BASE, ECALL_DISPATCH_NUM_COLUMNS, IS_ADD, IS_ADDI, IS_AUIPC,
    IS_BEQ, IS_BGE, IS_BGEU, IS_BLT, IS_BLTU, IS_BNE, IS_ECALL, IS_JAL, IS_JALR, IS_LOAD,
    IS_LUI, IS_PADDING, IS_STORE, IS_SUB, NUM_COLUMNS, NUM_INSTRUCTION_CATEGORIES,
};
use super::lookups::{EcallLookup, MemoryLookup};

/// 65536 = 2^16，16-bit 边界进位/借位的基数。
const SIX5536: BaseField = BaseField::from_u32_unchecked(65536);

/// 256 = 2^8，byte 边界的基数。
const TWO56: BaseField = BaseField::from_u32_unchecked(256);

/// 常量 4（PcNext = Pc + 4 中的立即数偏移）。
const FOUR: BaseField = BaseField::from_u32_unchecked(4);

/// CPU AIR 组件 — 封装 87 列 trace 的 FrameworkEval 实现（v3）。
///
/// # 结构
/// - `log_size` — log2(trace 行数)，行数 = 2^log_size
/// - `memory_lookup` — 可选的 MemoryLookup relation。
///   - `None`：不发送 Memory logup claim
///   - `Some(lookup)`：为每行 Load/Store 发送 logup claim（Phase 3.4+）
/// - `ecall_lookup` — 可选的 EcallLookup relation（Phase 4 Tier 1+）。
///   - `None`：不发送 ECALL logup claim
///   - `Some(lookup)`：为每行 ECALL 发送 1 元组 logup claim（仅 SyscallId）
///
/// # v3 变更
/// 移除 `poseidon_lookup` 字段（依赖 ECALL Args/Outputs 列，v3 已移除）。
/// 如需恢复 Poseidon 集成，需先恢复 ECALL Args/Outputs 列。
///
/// # 用法
/// ## 单组件模式（Phase 2 兼容）
/// ```ignore
/// use poker_zkvm::stwo_backend::cpu_air::CpuAir;
/// let air = CpuAir::new(log_size);
/// ```
///
/// ## 多组件模式（Phase 3.5+，配合 Memory AIR）
/// ```ignore
/// use poker_zkvm::stwo_backend::cpu_air::CpuAir;
/// use poker_zkvm::stwo_backend::lookups::MemoryLookup;
/// let air = CpuAir::new_with_lookup(log_size, MemoryLookup::dummy());
/// ```
///
/// ## Phase 4 Tier 1+（配合 Memory AIR + Precompile AIR）
/// ```ignore
/// use poker_zkvm::stwo_backend::cpu_air::CpuAir;
/// use poker_zkvm::stwo_backend::lookups::{MemoryLookup, EcallLookup};
/// let air = CpuAir::new_with_ecall_lookup(
///     log_size,
///     MemoryLookup::dummy(),
///     EcallLookup::dummy(),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct CpuAir {
    /// log2(trace 行数)
    log_size: u32,
    /// 可选的 MemoryLookup relation（None=不发送 Memory logup claim）
    memory_lookup: Option<MemoryLookup>,
    /// 可选的 EcallLookup relation（None=不发送 ECALL logup claim）
    /// Phase 4 Tier 1 新增（v3：claim 缩减为 1 元组 SyscallId）
    ecall_lookup: Option<EcallLookup>,
}

impl CpuAir {
    /// 创建指定 log_size 的 CPU AIR（单组件模式，无 logup）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10（Stwo SIMD 对齐要求）
    ///
    /// # 返回
    /// `memory_lookup = None, ecall_lookup = None` 的 CpuAir。
    /// 适用于 Phase 2 单组件 prove/verify 测试。
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        Self {
            log_size,
            memory_lookup: None,
            ecall_lookup: None,
        }
    }

    /// 创建指定 log_size 的 CPU AIR（多组件模式，启用 Memory logup claim）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例（从 channel draw 或 dummy）
    ///
    /// # 返回
    /// `memory_lookup = Some(lookup), ecall_lookup = None` 的 CpuAir。
    /// 适用于 Phase 3.5+ 多组件 prove/verify（配合 Memory AIR）。
    #[must_use]
    pub const fn new_with_lookup(log_size: u32, memory_lookup: MemoryLookup) -> Self {
        Self {
            log_size,
            memory_lookup: Some(memory_lookup),
            ecall_lookup: None,
        }
    }

    /// 创建指定 log_size 的 CPU AIR（Phase 4 Tier 1+，同时启用 Memory + ECALL logup claim）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例
    /// - `ecall_lookup` — EcallLookup relation 实例（从 channel draw 或 dummy）
    ///
    /// # 返回
    /// `memory_lookup = Some, ecall_lookup = Some` 的 CpuAir。
    /// 适用于 Phase 4 Tier 1+ 多组件 prove/verify（配合 Memory AIR + Precompile AIR）。
    ///
    /// # Phase 4 Tier 1 注意
    /// Tier 1 阶段尚无 Precompile AIR 发送 yield，因此 ECALL logup claim 的
    /// multiplicity 应为 0（trace 填充暂留 0）。Tier 2 实施 Precompile AIR 后
    /// 才能实现 claim + yield 平衡。
    ///
    /// # v3 变更
    /// ECALL logup claim 从 25 元组（SyscallId + Args/Outputs）缩减为 1 元组（仅 SyscallId）。
    /// 如需恢复 Args/Outputs，需在 column_layout_v2.rs 中恢复相关列。
    #[must_use]
    pub const fn new_with_ecall_lookup(
        log_size: u32,
        memory_lookup: MemoryLookup,
        ecall_lookup: EcallLookup,
    ) -> Self {
        Self {
            log_size,
            memory_lookup: Some(memory_lookup),
            ecall_lookup: Some(ecall_lookup),
        }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 是否启用 Memory logup claim。
    #[must_use]
    pub const fn has_memory_lookup(&self) -> bool {
        self.memory_lookup.is_some()
    }

    /// 是否启用 ECALL logup claim（Phase 4 Tier 1+）。
    #[must_use]
    pub const fn has_ecall_lookup(&self) -> bool {
        self.ecall_lookup.is_some()
    }
}

impl FrameworkEval for CpuAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 所有约束的最大总度 = 3（gating × binality）。
    /// 根据 stwo-book 度数表，度 1-3 对应 `log_size + 1`。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // ----- 将 BaseField 常量转换为 E::F -----
        // EvalAtRow::F: From<BaseField>，但 BaseField 不能直接与 E::F 运算（顺序敏感），
        // 故在 evaluate 入口统一转换。
        let six5536: E::F = SIX5536.into();
        let two56: E::F = TWO56.into();
        let one: E::F = BaseField::from(1u32).into();
        let four: E::F = FOUR.into();

        // ----- 读取全部 87 列（v3 顺序与 column_layout_v2 一致）-----
        let mut cols: Vec<E::F> = Vec::with_capacity(NUM_COLUMNS);
        for _ in 0..NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }

        // 辅助闭包：按列索引取值
        let col = |idx: usize| -> E::F { cols[idx].clone() };
        // 辅助闭包：读取 4×8-bit limb word 的低 16 位组合值
        // word_low16 = limb[0] + 256 * limb[1]
        let word_low16 = |base: usize| -> E::F { col(base) + col(base + 1) * two56.clone() };
        // 辅助闭包：读取 4×8-bit limb word 的高 16 位组合值
        // word_high16 = limb[2] + 256 * limb[3]
        let word_high16 = |base: usize| -> E::F { col(base + 2) + col(base + 3) * two56.clone() };

        // ----- 读取 indicator 列 -----
        let is_add = col(IS_ADD);
        let is_addi = col(IS_ADDI);
        let is_sub = col(IS_SUB);
        let is_padding = col(IS_PADDING);
        let is_lui = col(IS_LUI);
        let is_auipc = col(IS_AUIPC);
        let is_jal = col(IS_JAL);
        let is_jalr = col(IS_JALR);
        let is_beq = col(IS_BEQ);
        let is_bne = col(IS_BNE);
        let is_blt = col(IS_BLT);
        let is_bge = col(IS_BGE);
        let is_bltu = col(IS_BLTU);
        let is_bgeu = col(IS_BGEU);

        // IsBranch = IsBeq + IsBne + IsBlt + IsBge + IsBltu + IsBgeu（6 个条件分支之和）
        let is_branch = is_beq.clone()
            + is_bne.clone()
            + is_blt.clone()
            + is_bge.clone()
            + is_bltu.clone()
            + is_bgeu.clone();

        // IsNonFlow = 1 - IsPadding - IsJal - IsJalr - IsBranch
        // 用于 PC 递增约束 gating（非跳转/非分支/非 padding 的指令 PcNext = Pc + 4）
        let is_non_flow = one.clone() - is_padding.clone() - is_jal.clone() - is_jalr.clone()
            - is_branch.clone();

        // ----- 读取算术标志（合并 carry/borrow，ADD/ADDI 与 SUB 互斥）-----
        // ADD/ADDI 行：此列为 carry0, carry1
        // SUB 行：此列为 borrow0, borrow1
        let carry0 = col(COL_CARRY_FLAG_BASE);
        let carry1 = col(COL_CARRY_FLAG_BASE + 1);

        // ----- 读取操作数值（4×8-bit limb word）-----
        let rd_eff_low = word_low16(COL_VALUE_A_EFF_BASE);
        let rd_eff_high = word_high16(COL_VALUE_A_EFF_BASE);
        let rs1_low = word_low16(COL_VALUE_B_BASE);
        let rs1_high = word_high16(COL_VALUE_B_BASE);
        let rs2_low = word_low16(COL_VALUE_C_BASE);
        let rs2_high = word_high16(COL_VALUE_C_BASE);

        // ----- 读取 Taken 标志 -----
        let taken = col(COL_TAKEN);

        // ===== 约束 1-4：ADD 约束（gated by IsAdd）=====
        // 低 16 位：rd_eff_low = rs1_low + rs2_low - 65536 * carry0
        let add_low = rd_eff_low.clone() - rs1_low.clone() - rs2_low.clone()
            + six5536.clone() * carry0.clone();
        eval.add_constraint(is_add.clone() * add_low);

        // 高 16 位：rd_eff_high = rs1_high + rs2_high + carry0 - 65536 * carry1
        let add_high = rd_eff_high.clone() - rs1_high.clone() - rs2_high.clone()
            - carry0.clone() + six5536.clone() * carry1.clone();
        eval.add_constraint(is_add.clone() * add_high);

        // carry0 binality: carry0 * (carry0 - 1) = 0
        let carry0_bin = carry0.clone() * (carry0.clone() - one.clone());
        eval.add_constraint(is_add.clone() * carry0_bin);

        // carry1 binality: carry1 * (carry1 - 1) = 0
        let carry1_bin = carry1.clone() * (carry1.clone() - one.clone());
        eval.add_constraint(is_add.clone() * carry1_bin);

        // ===== 约束 5-8：ADDI 约束（gated by IsAddi）=====
        // ADDI 与 ADD 结构相同，仅 ImmC=1 时 ValueC 为立即数
        let addi_low = rd_eff_low.clone() - rs1_low.clone() - rs2_low.clone()
            + six5536.clone() * carry0.clone();
        eval.add_constraint(is_addi.clone() * addi_low);

        let addi_high = rd_eff_high.clone() - rs1_high.clone() - rs2_high.clone()
            - carry0.clone() + six5536.clone() * carry1.clone();
        eval.add_constraint(is_addi.clone() * addi_high);

        let addi_carry0_bin = carry0.clone() * (carry0.clone() - one.clone());
        eval.add_constraint(is_addi.clone() * addi_carry0_bin);

        let addi_carry1_bin = carry1.clone() * (carry1.clone() - one.clone());
        eval.add_constraint(is_addi.clone() * addi_carry1_bin);

        // ===== 约束 9-12：SUB 约束（gated by IsSub）=====
        // SUB 复用 carry0, carry1 列作为 borrow0, borrow1（ADD/ADDI 与 SUB 互斥）
        // 低 16 位：rd_eff_low = rs1_low - rs2_low + 65536 * borrow0
        let sub_low = rd_eff_low.clone() - rs1_low.clone() + rs2_low.clone()
            - six5536.clone() * carry0.clone();
        eval.add_constraint(is_sub.clone() * sub_low);

        // 高 16 位：rd_eff_high = rs1_high - rs2_high - borrow0 + 65536 * borrow1
        let sub_high = rd_eff_high.clone() - rs1_high.clone() + rs2_high.clone()
            + carry0.clone() - six5536.clone() * carry1.clone();
        eval.add_constraint(is_sub.clone() * sub_high);

        // borrow0 binality（复用 carry0 列）
        let borrow0_bin = carry0.clone() * (carry0.clone() - one.clone());
        eval.add_constraint(is_sub.clone() * borrow0_bin);

        // borrow1 binality（复用 carry1 列）
        let borrow1_bin = carry1.clone() * (carry1.clone() - one.clone());
        eval.add_constraint(is_sub.clone() * borrow1_bin);

        // ===== 约束 13：IsPadding binality（通用，无 gating）=====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== 约束 14：Indicator one-hot（通用）=====
        // Σ Is_i = 1（对 35 个 indicator 求和）
        let mut indicator_sum = col(COL_IS_BASE);
        for i in 1..NUM_INSTRUCTION_CATEGORIES {
            indicator_sum = indicator_sum + col(COL_IS_BASE + i);
        }
        eval.add_constraint(indicator_sum - one.clone());

        // ===== 约束 15：Taken binality（通用）=====
        // Taken ∈ {0, 1}： Taken * (Taken - 1) = 0
        let taken_bin = taken.clone() * (taken.clone() - one.clone());
        eval.add_constraint(taken_bin);

        // ===== 约束 16-19：PC 递增约束（gated by IsNonFlow，16-bit half 方案）=====
        // 非跳转/非分支/非 padding 指令：PcNext = Pc + 4
        // 使用 16-bit half 分解（与 ADD/ADDI 同结构），用 PC carry 列处理 limb 间进位：
        //   PcNext_low16 = Pc_low16 + 4 - 65536 * pc_carry0
        //   PcNext_high16 = Pc_high16 + pc_carry0 - 65536 * pc_carry1
        //   pc_carry0, pc_carry1 ∈ {0, 1}
        //
        // 旧实现 bug：原 limb-wise 约束 `PcNext[i] - Pc[i] - 4_limb[i] = 0` 未处理
        // limb 间进位，当 Pc[0] + 4 >= 256（如 Pc=0x11FC, PcNext=0x1200）时失败。
        let pc_low16 = word_low16(COL_PC_BASE);
        let pc_high16 = word_high16(COL_PC_BASE);
        let pc_next_low16 = word_low16(COL_PC_NEXT_BASE);
        let pc_next_high16 = word_high16(COL_PC_NEXT_BASE);
        let pc_carry0 = col(COL_PC_CARRY_FLAG_BASE);
        let pc_carry1 = col(COL_PC_CARRY_FLAG_BASE + 1);

        // Constraint 16: PcNext_low16 - Pc_low16 - 4 + 65536 * pc_carry0 = 0
        let pc_low_diff = pc_next_low16.clone() - pc_low16.clone() - four.clone()
            + six5536.clone() * pc_carry0.clone();
        eval.add_constraint(is_non_flow.clone() * pc_low_diff);

        // Constraint 17: PcNext_high16 - Pc_high16 - pc_carry0 + 65536 * pc_carry1 = 0
        let pc_high_diff = pc_next_high16.clone() - pc_high16.clone() - pc_carry0.clone()
            + six5536.clone() * pc_carry1.clone();
        eval.add_constraint(is_non_flow.clone() * pc_high_diff);

        // Constraint 18: pc_carry0 binality
        let pc_carry0_bin = pc_carry0.clone() * (pc_carry0.clone() - one.clone());
        eval.add_constraint(is_non_flow.clone() * pc_carry0_bin);

        // Constraint 19: pc_carry1 binality
        let pc_carry1_bin = pc_carry1.clone() * (pc_carry1.clone() - one.clone());
        eval.add_constraint(is_non_flow.clone() * pc_carry1_bin);

        // ===== 约束 20-23：JAL 约束（gated by IsJal）=====
        // JAL: PcNext = Pc + imm，Helper2 预存 (Pc + imm)
        // 对每个 limb i：PcNext[i] - Helper2[i] = 0
        for i in 0..4 {
            let jal_diff = col(COL_PC_NEXT_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_jal.clone() * jal_diff);
        }

        // ===== 约束 24-27：JALR 约束（gated by IsJalr）=====
        // JALR: PcNext = (rs1 + imm) & !1，HelperA 预存该值（v3.3：复用 HelperA）
        // 对每个 limb i：PcNext[i] - HelperA[i] = 0
        for i in 0..4 {
            let jalr_diff = col(COL_PC_NEXT_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_jalr.clone() * jalr_diff);
        }

        // ===== 约束 28-31：Branch 约束（gated by IsBranch，16-bit half 方案）=====
        // 分支指令：taken ? PcNext = Pc + imm : PcNext = Pc + 4
        //
        // not-taken 路径（PcNext = Pc + 4）：使用 PC carry（与约束 16-19 同结构）
        //   PcNext_low16 = Pc_low16 + 4 - 65536 * pc_carry0
        //   PcNext_high16 = Pc_high16 + pc_carry0 - 65536 * pc_carry1
        //
        // taken 路径（PcNext = Helper2 = Pc + imm）：limb-wise 等式
        //   PcNext[i] - Helper2[i] = 0
        //
        // 组合：IsBranch * ((1-Taken) * not_taken_constraint + Taken * taken_constraint) = 0
        //
        // 旧实现 bug：not-taken 路径用 limb-wise `PcNext[i] - Pc[i] - 4_limb[i]`，
        // 未处理 limb 间进位（同约束 16-19 的 bug）。
        //
        // 注意度数预算：
        // - not-taken low16: IsBranch × (1-Taken) × (PcNext_low - Pc_low - 4 + 65536*pc_carry0)
        //   = 1 + 1 + 1 = 3 ✓
        // - not-taken high16: IsBranch × (1-Taken) × (PcNext_high - Pc_high - pc_carry0 + 65536*pc_carry1)
        //   = 1 + 1 + 1 = 3 ✓
        // - taken: IsBranch × Taken × (PcNext[i] - Helper2[i]) = 1 + 1 + 1 = 3 ✓
        let one_minus_taken = one.clone() - taken.clone();

        // not-taken low16: (PcNext_low16 - Pc_low16 - 4 + 65536 * pc_carry0)
        let branch_not_taken_low = pc_next_low16.clone() - pc_low16.clone() - four.clone()
            + six5536.clone() * pc_carry0.clone();
        // not-taken high16: (PcNext_high16 - Pc_high16 - pc_carry0 + 65536 * pc_carry1)
        let branch_not_taken_high = pc_next_high16.clone() - pc_high16.clone() - pc_carry0.clone()
            + six5536.clone() * pc_carry1.clone();

        // 组合 not-taken low16 约束
        let branch_low_constraint = one_minus_taken.clone() * branch_not_taken_low;
        eval.add_constraint(is_branch.clone() * branch_low_constraint);

        // 组合 not-taken high16 约束
        let branch_high_constraint = one_minus_taken.clone() * branch_not_taken_high;
        eval.add_constraint(is_branch.clone() * branch_high_constraint);

        // taken 路径：PcNext[i] - Helper2[i] = 0（4 limb）
        for i in 0..4 {
            let pc_next_limb = col(COL_PC_NEXT_BASE + i);
            let helper2_limb = col(COL_HELPER_A_BASE + i);
            let taken_diff = pc_next_limb - helper2_limb;
            let branch_taken_constraint = taken.clone() * taken_diff;
            eval.add_constraint(is_branch.clone() * branch_taken_constraint);
        }

        // Branch 的 pc_carry0/pc_carry1 binality（gated by IsBranch）
        // 因为 IsNonFlow=0 for branches，约束 18/19 不 gate branch 行，
        // 需单独约束 binality。度 = 1 (IsBranch) + 2 (binality) = 3 ✓
        let branch_pc_carry0_bin = pc_carry0.clone() * (pc_carry0.clone() - one.clone());
        eval.add_constraint(is_branch.clone() * branch_pc_carry0_bin);

        let branch_pc_carry1_bin = pc_carry1.clone() * (pc_carry1.clone() - one.clone());
        eval.add_constraint(is_branch.clone() * branch_pc_carry1_bin);

        // ===== 约束 32-35：LUI 约束（gated by IsLui）=====
        // LUI: rd_eff = imm（imm 字段已左移 12 位并符号扩展）
        // Helper1 预存 imm 值
        // 对每个 limb i：rd_eff[i] - Helper1[i] = 0
        for i in 0..4 {
            let lui_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_lui.clone() * lui_diff);
        }

        // ===== 约束 36-39：AUIPC 约束（gated by IsAuipc）=====
        // AUIPC: rd_eff = Pc + imm（imm 字段已左移 12 位并符号扩展）
        // Helper2 预存 (Pc + imm) 值
        // 对每个 limb i：rd_eff[i] - Helper2[i] = 0
        for i in 0..4 {
            let auipc_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_auipc.clone() * auipc_diff);
        }

        // ===== Phase 3 约束 40-43：Load 地址约束（gated by IsLoad）=====
        // Load: MemAddr = rs1 + imm（由 trace_native.rs 预计算填充到 MemAddr 列）
        // Helper1 预存 imm 值，Helper3 预存 rs1+imm（即 MemAddr 应等于 Helper3）
        // 对每个 limb i：MemAddr[i] - Helper3[i] = 0
        // 注：Helper3 在 trace_native 中预存 MemAddr 值，此约束验证 MemAddr 列与 Helper3 一致
        // 实际地址计算（rs1+imm）的正确性由 Helper3 填充逻辑保证（Phase 3.2 Memory AIR 将强化）
        let is_load = col(IS_LOAD);
        for i in 0..4 {
            let load_addr_diff = col(COL_MEM_ADDR_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_load.clone() * load_addr_diff);
        }

        // ===== Phase 3 约束 44-47：Load 值匹配约束（gated by IsLoad）=====
        // Load: rd_eff = mem_value（加载的值必须写入 rd）
        // Helper4 预存 mem_value（来自 step.mem_access[0].value）
        // 对每个 limb i：rd_eff[i] - Helper4[i] = 0
        let is_load_eff = is_load.clone();
        for i in 0..4 {
            let load_val_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER_B_BASE + i);
            eval.add_constraint(is_load_eff.clone() * load_val_diff);
        }

        // ===== Phase 3 约束 48-51：Store 地址约束（gated by IsStore）=====
        // Store: MemAddr = rs1 + imm（同 Load 地址约束）
        let is_store = col(IS_STORE);
        for i in 0..4 {
            let store_addr_diff = col(COL_MEM_ADDR_BASE + i) - col(COL_HELPER_A_BASE + i);
            eval.add_constraint(is_store.clone() * store_addr_diff);
        }

        // ===== Phase 3 约束 52-55：Store 值匹配约束（gated by IsStore）=====
        // Store: mem_value = rs2（存储的值必须来自 rs2）
        // Helper4 预存 mem_value（= rs2_value for Store）
        // 对每个 limb i：rs2[i] - Helper4[i] = 0
        let is_store_eff = is_store.clone();
        for i in 0..4 {
            let store_val_diff = col(COL_VALUE_C_BASE + i) - col(COL_HELPER_B_BASE + i);
            eval.add_constraint(is_store_eff.clone() * store_val_diff);
        }

        // ===== Phase 3.4 约束 56：Memory logup claim（gated by Option<MemoryLookup>）=====
        // 当 memory_lookup = Some(lookup) 时，为每行 Load/Store 发送 logup claim：
        //   - Load 行：values = (MemAddr×4, rd_eff×4, 0)，multiplicity = +1
        //   - Store 行：values = (MemAddr×4, rs2_value×4, 1)，multiplicity = +1
        //   - 非 Load/Store 行：multiplicity = 0（不贡献 sum）
        //
        // 一致性条件：Σ(CPU claims) = Σ(Memory yields)（Phase 3.5 多组件 prover 验证）
        //
        // 当 memory_lookup = None 时（单组件模式），跳过 logup，保持 Phase 2 兼容。
        //
        // **多 batch logup 注意（Phase 4 Tier 2+）**：
        // 当同时启用 memory_lookup + ecall_lookup + poseidon_lookup 时，所有 add_to_relation
        // 调用必须先累积，最后统一调用一次 finalize_logup()。Stwo 的 finalize_logup 内部
        // 调用 finalize_logup_batched，会根据 fracs 数量自动创建 N 个 batch（batches=[0..N]）。
        // 多次调用 finalize_logup 会因 is_finalized assert 而 panic。
        let mut has_logup = false;
        if let Some(ref lookup) = self.memory_lookup {
            // 构造 claim values（9 元组）：
            // values[0..4] = MemAddr（4×8-bit limb）
            // values[4..8] = mem_value（4×8-bit limb）
            //   - Load: mem_value = rd_eff = ValueAEff
            //   - Store: mem_value = rs2_value = ValueC
            //   - 非 Load/Store: mem_value = 0（但 multiplicity = 0，不影响 sum）
            // values[8] = IsStore（1=Store, 0=Load/其他）
            let mut claim_values: Vec<E::F> = Vec::with_capacity(9);
            for i in 0..4 {
                claim_values.push(col(COL_MEM_ADDR_BASE + i));
            }
            for i in 0..4 {
                // mem_value = is_load * rd_eff + is_store * rs2_value
                let mem_val_limb = is_load.clone() * col(COL_VALUE_A_EFF_BASE + i)
                    + is_store.clone() * col(COL_VALUE_C_BASE + i);
                claim_values.push(mem_val_limb);
            }
            claim_values.push(is_store.clone());

            // multiplicity = is_load + is_store（非 Load/Store 行 multiplicity = 0）
            // RelationEntry 的 multiplicity 类型是 E::EF，需要从 E::F 转换
            let multiplicity_ef: E::EF = (is_load.clone() + is_store.clone()).into();
            eval.add_to_relation(RelationEntry::new(lookup, multiplicity_ef, &claim_values));
            has_logup = true;
        }

        // ===== Phase 4 Tier 1 约束 C57：IS_ECALL binality =====
        // 显式约束 IS_ECALL ∈ {0, 1}，增强 soundness（虽然 Indicator one-hot C14 隐含）
        // 约束：IS_ECALL * (IS_ECALL - 1) = 0
        // 度数 = 2（IS_ECALL × IS_ECALL），符合 LOG_CONSTRAINT_DEGREE = 2 预算
        let is_ecall = col(IS_ECALL);
        let is_ecall_bin = is_ecall.clone() * (is_ecall.clone() - one.clone());
        eval.add_constraint(is_ecall_bin);

        // ===== v3 约束 C58：ECALL SyscallId zero gating（1 条）=====
        // 非 ECALL 行的 SyscallId 列必须为 0
        // 约束：(1 - IS_ECALL) * SyscallId = 0
        // - 非 ECALL 行（IS_ECALL=0）：(1-0) * col = col = 0，强制 SyscallId 为 0
        // - ECALL 行（IS_ECALL=1）：(1-1) * col = 0，自动成立，不约束 SyscallId 值
        // 度数 = 2（one_minus_is_ecall × col），符合预算
        //
        // v3 变更：v2 有 25 条 zero gating（SyscallId + 24 Args/Outputs），
        // v3 仅保留 1 条（SyscallId），Args/Outputs 列已移除。
        let one_minus_is_ecall = one.clone() - is_ecall.clone();

        // v3：ECALL dispatch 仅 1 列 SyscallId
        let ecall_dispatch_layout: [(usize, usize); 1] = [
            (COL_SYSCALL_ID, 1),  // col 84
        ];

        // 收集 1 列值，用于后续 logup claim
        let mut ecall_claim_values: Vec<E::F> = Vec::with_capacity(ECALL_DISPATCH_NUM_COLUMNS);
        for (base, size) in &ecall_dispatch_layout {
            for i in 0..*size {
                let val = col(*base + i);
                // zero gating 约束：(1 - IS_ECALL) * col = 0
                eval.add_constraint(one_minus_is_ecall.clone() * val.clone());
                ecall_claim_values.push(val);
            }
        }

        // ===== Phase 4 Tier 1 约束：ECALL logup claim（gated by Option<EcallLookup>）=====
        // 当 ecall_lookup = Some(lookup) 时，为每行 ECALL 发送 1 元组 logup claim：
        //   values = (SyscallId,)
        //   multiplicity = IS_ECALL（非 ECALL 行 multiplicity = 0，不贡献 sum）
        //
        // v3 变更：从 25 元组（SyscallId + Args/Outputs）缩减为 1 元组（仅 SyscallId）
        //
        // 一致性条件：Σ(CPU claims) + Σ(Precompile yields) == 0（Tier 2+ 验证）
        if let Some(ref lookup) = self.ecall_lookup {
            let multiplicity_ef: E::EF = is_ecall.clone().into();
            eval.add_to_relation(RelationEntry::new(
                lookup,
                multiplicity_ef,
                &ecall_claim_values,
            ));
            has_logup = true;
        }

        // ===== 统一 finalize_logup（多 batch 模式）=====
        // 当启用任意 logup（Memory / ECALL）时，在所有 add_to_relation 之后
        // 调用一次 finalize_logup()。Stwo 自动根据 fracs 数量创建 N 个 batch：
        //   - 1 frac → 1 batch → 1 interaction column（4 base field cols）
        //   - 2 fracs → 2 batches → 2 interaction columns（8 base field cols）
        //   - 3 fracs → 3 batches → 3 interaction columns（12 base field cols）
        // 多次调用 finalize_logup 会因 is_finalized assert 而 panic，因此必须只调一次。
        if has_logup {
            eval.finalize_logup();
        }

        eval
    }
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::fields::m31::M31;

    #[test]
    fn test_cpu_air_new() {
        let air = CpuAir::new(10);
        assert_eq!(air.log_size(), 10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
        assert!(!air.has_memory_lookup(), "CpuAir::new 应为单组件模式");
    }

    #[test]
    fn test_cpu_air_new_with_lookup() {
        let lookup = MemoryLookup::dummy();
        let air = CpuAir::new_with_lookup(10, lookup);
        assert_eq!(air.log_size(), 10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
        assert!(air.has_memory_lookup(), "CpuAir::new_with_lookup 应启用 logup");
        assert!(
            !air.has_ecall_lookup(),
            "CpuAir::new_with_lookup 不应启用 ECALL logup"
        );
    }

    #[test]
    fn test_cpu_air_new_with_ecall_lookup() {
        // Phase 4 Tier 1：验证同时启用 Memory + ECALL logup 的构造
        let mem_lookup = MemoryLookup::dummy();
        let ecall_lookup = EcallLookup::dummy();
        let air = CpuAir::new_with_ecall_lookup(10, mem_lookup, ecall_lookup);
        assert_eq!(air.log_size(), 10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
        assert!(air.has_memory_lookup(), "应启用 Memory logup");
        assert!(air.has_ecall_lookup(), "应启用 ECALL logup");
    }

    #[test]
    fn test_cpu_air_ecall_column_layout() {
        // v3.3：ECALL dispatch 列布局常量（缩减为 1 列 SyscallId）
        assert_eq!(IS_ECALL, 54, "IS_ECALL 应在 indicator 范围 [22, 56] 内");
        assert_eq!(COL_SYSCALL_ID, 70);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 1);
        // v3：1 列布局（仅 SyscallId）
        assert_eq!(
            1,
            ECALL_DISPATCH_NUM_COLUMNS,
            "v3 ECALL dispatch 应为 1 列 SyscallId"
        );
    }

    #[test]
    fn test_constants() {
        // 验证 SIX5536 = 2^16
        assert_eq!(SIX5536, BaseField::from(65536u32));
        // 验证 TWO56 = 2^8
        assert_eq!(TWO56, BaseField::from(256u32));
        // 验证 FOUR = 4
        assert_eq!(FOUR, BaseField::from(4u32));
        // M31 最大值 = 2^31 - 2 > 65536，无溢出
        assert!(M31::from(65536u32).0 < (1u32 << 31) - 1);
    }

    #[test]
    fn test_column_layout_consistency() {
        // v3.3：验证 CpuAir 使用的列索引与 column_layout_v2 一致
        // 变更：移除 PcNextAux 列（P1.3），JALR 复用 HelperA
        assert_eq!(COL_PC_BASE, 0);
        assert_eq!(COL_PC_NEXT_BASE, 4);
        assert_eq!(COL_CARRY_FLAG_BASE, 8);
        assert_eq!(COL_VALUE_A_EFF_BASE, 10);
        assert_eq!(COL_VALUE_B_BASE, 14);
        assert_eq!(COL_VALUE_C_BASE, 18);
        assert_eq!(COL_IS_BASE, 22);
        assert_eq!(IS_LUI, 22);
        assert_eq!(IS_AUIPC, 23);
        assert_eq!(IS_JAL, 24);
        assert_eq!(IS_JALR, 25);
        assert_eq!(IS_BEQ, 26);
        assert_eq!(IS_BNE, 27);
        assert_eq!(IS_BLT, 28);
        assert_eq!(IS_BGE, 29);
        assert_eq!(IS_BLTU, 30);
        assert_eq!(IS_BGEU, 31);
        assert_eq!(IS_ADDI, 34);
        assert_eq!(IS_ADD, 43);
        assert_eq!(IS_SUB, 44);
        assert_eq!(IS_PADDING, 56);
        assert_eq!(COL_HELPER_A_BASE, 57);
        assert_eq!(COL_HELPER_B_BASE, 61);
        assert_eq!(COL_TAKEN, 65);
        assert_eq!(NUM_COLUMNS, 73);
        assert_eq!(NUM_INSTRUCTION_CATEGORIES, 35);
    }
}
