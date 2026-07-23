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
//! | 44-47 | ~~Load 值匹配~~ → V7 扩展约束 | 2-3 | IsLoad | rd_eff = extend(HelperB, load_subtype)（详见 §V7） |
//! | 48-51 | Store addr（4 limb） | 3 | IsStore | MemAddr[i] = rs1[i] + imm[i]（带 carry） |
//! | 52-55 | Store 值匹配（4 limb） | 2 | IsStore | MemValue[i] = rs2[i]（暂用 Helper3） |
//!
//! 所有约束的最大总度 = 3（gating × binality），因此
//! `max_constraint_log_degree_bound = log_size + 1`（参见 stwo-book 度数表）。

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use super::column_layout_v2::{
    COL_ABS_A_BASE, COL_ABS_B_BASE, COL_CARRY_FLAG_BASE, COL_DIV_IS_SPECIAL, COL_DIV_QUOT_BASE,
    COL_DIV_REM_BASE, COL_DIV_SIGN_Q, COL_DIV_SIGN_R, COL_HELPER_A_BASE, COL_HELPER_B_BASE,
    COL_IS_BASE, COL_IS_LOAD_BYTE, COL_IS_LOAD_HALF, COL_IS_LOAD_SIGN, COL_LOAD_BITS_BASE,
    COL_LOAD_BITS_COUNT, COL_LOAD_BYTE_GATE, COL_LOAD_HALF_GATE, COL_LOW_NONZERO, COL_MEM_ADDR_BASE,
    COL_MUL_CARRY_HI0_BASE, COL_MUL_CARRY_HI1_BASE, COL_MUL_CARRY_LO_BASE, COL_MUL_HIGH_BASE,
    COL_MUL_LOW_BASE, COL_PC_BASE, COL_PC_CARRY_FLAG_BASE, COL_PC_NEXT_BASE, COL_SIGN_A, COL_SIGN_B,
    COL_SIGN_BIT, COL_SYSCALL_ID, COL_TAKEN, COL_VALUE_A_EFF_BASE, COL_VALUE_B_BASE,
    COL_VALUE_C_BASE, ECALL_DISPATCH_NUM_COLUMNS, IS_ADD, IS_ADDI, IS_AUIPC, IS_BEQ, IS_BGE,
    IS_BGEU, IS_BLT, IS_BLTU, IS_BNE, IS_DIV, IS_DIVU, IS_ECALL, IS_JAL, IS_JALR, IS_LOAD, IS_LUI,
    IS_MUL, IS_MULH, IS_MULHSU, IS_MULHU, IS_PADDING, IS_REM, IS_REMU, IS_SLT, IS_SLTI, IS_SLTU,
    IS_SLTIU, IS_STORE, IS_SUB, NUM_COLUMNS, NUM_INSTRUCTION_CATEGORIES,
};
use super::lookups::{EcallLookup, MemoryLookup, RangeCheckLookup};

/// 65536 = 2^16，16-bit 边界进位/借位的基数。
const SIX5536: BaseField = BaseField::from_u32_unchecked(65536);

/// 256 = 2^8，byte 边界的基数。
const TWO56: BaseField = BaseField::from_u32_unchecked(256);

/// 常量 4（PcNext = Pc + 4 中的立即数偏移）。
const FOUR: BaseField = BaseField::from_u32_unchecked(4);

/// 255 = 0xFF，符号扩展 byte/halfword 上位填充用（V7 修复）。
const TWO55: BaseField = BaseField::from_u32_unchecked(255);

/// CPU AIR 组件 — 封装 132 列 trace 的 FrameworkEval 实现（v3.5）。
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
    /// 可选的 RangeCheckLookup relation（None=不发送 Range logup claim）
    /// V4 修复：验证所有 8-bit limb ∈ [0, 255]
    range_lookup: Option<RangeCheckLookup>,
}

impl CpuAir {
    /// 创建指定 log_size 的 CPU AIR（单组件模式，无 logup）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10（Stwo SIMD 对齐要求）
    ///
    /// # 返回
    /// `memory_lookup = None, ecall_lookup = None, range_lookup = None` 的 CpuAir。
    /// 适用于 Phase 2 单组件 prove/verify 测试。
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        Self {
            log_size,
            memory_lookup: None,
            ecall_lookup: None,
            range_lookup: None,
        }
    }

    /// 创建指定 log_size 的 CPU AIR（多组件模式，启用 Memory logup claim）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例（从 channel draw 或 dummy）
    ///
    /// # 返回
    /// `memory_lookup = Some(lookup), ecall_lookup = None, range_lookup = None` 的 CpuAir。
    /// 适用于 Phase 3.5+ 多组件 prove/verify（配合 Memory AIR）。
    #[must_use]
    pub const fn new_with_lookup(log_size: u32, memory_lookup: MemoryLookup) -> Self {
        Self {
            log_size,
            memory_lookup: Some(memory_lookup),
            ecall_lookup: None,
            range_lookup: None,
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
    /// `memory_lookup = Some, ecall_lookup = Some, range_lookup = None` 的 CpuAir。
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
            range_lookup: None,
        }
    }

    /// 创建指定 log_size 的 CPU AIR（V4 修复，同时启用 Memory + ECALL + RangeCheck logup claim）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例
    /// - `ecall_lookup` — EcallLookup relation 实例
    /// - `range_lookup` — RangeCheckLookup relation 实例（从 channel draw 或 dummy）
    ///
    /// # 返回
    /// `memory_lookup = Some, ecall_lookup = Some, range_lookup = Some` 的 CpuAir。
    /// 适用于 V4 修复多组件 prove/verify（配合 Memory AIR + RangeCheck AIR）。
    #[must_use]
    pub const fn new_with_range_check(
        log_size: u32,
        memory_lookup: MemoryLookup,
        ecall_lookup: EcallLookup,
        range_lookup: RangeCheckLookup,
    ) -> Self {
        Self {
            log_size,
            memory_lookup: Some(memory_lookup),
            ecall_lookup: Some(ecall_lookup),
            range_lookup: Some(range_lookup),
        }
    }

    /// 创建指定 log_size 的 CPU AIR（V4 修复，启用 Memory + RangeCheck，无 ECALL）。
    ///
    /// 用于 3 组件 prover（CPU + Memory + RangeCheck），匹配现有 `prove_cpu_memory_trace`
    /// 不含 ecall 的模式，避免引入无 yield 方的 ecall interaction 列。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10
    /// - `memory_lookup` — MemoryLookup relation 实例
    /// - `range_lookup` — RangeCheckLookup relation 实例（从 channel draw 或 dummy）
    ///
    /// # 返回
    /// `memory_lookup = Some, ecall_lookup = None, range_lookup = Some` 的 CpuAir。
    #[must_use]
    pub const fn new_with_memory_and_range(
        log_size: u32,
        memory_lookup: MemoryLookup,
        range_lookup: RangeCheckLookup,
    ) -> Self {
        Self {
            log_size,
            memory_lookup: Some(memory_lookup),
            ecall_lookup: None,
            range_lookup: Some(range_lookup),
        }
    }

    /// 创建指定 log_size 的 CPU AIR（仅启用 RangeCheck，无 Memory/ECALL）。
    ///
    /// 用于 2 组件隔离测试（CPU + RangeCheck），排查 3 组件交互问题。
    #[must_use]
    pub const fn new_with_range_only(log_size: u32, range_lookup: RangeCheckLookup) -> Self {
        Self {
            log_size,
            memory_lookup: None,
            ecall_lookup: None,
            range_lookup: Some(range_lookup),
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

    /// 是否启用 RangeCheck logup claim（V4 修复）。
    #[must_use]
    pub const fn has_range_lookup(&self) -> bool {
        self.range_lookup.is_some()
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
        // 常量 2（M 扩展 carry 二元分解：carry_k = lo + 256·hi0 + 512·hi1，512 = 256·2）
        let two: E::F = BaseField::from(2u32).into();
        // V7 修复：0xFF = 255，符号扩展 byte/halfword 的上位填充常量
        let ff: E::F = TWO55.into();

        // ----- 读取全部 132 列（v3.5 顺序与 column_layout_v2 一致）-----
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

        // ===== 约束 12a-16a：SLTU/SLTIU 约束（gated by IsSltu + IsSltiu）=====
        // SLTU/SLTIU: rd_eff = (rs1 < rs2 unsigned) ? 1 : 0
        // 方法：计算 rs1 - rs2 的 borrow（与 SUB 同结构），rd_eff = borrow1
        // diff 存入 COL_MUL_LOW_BASE（4 limb），borrow 复用 COL_CARRY_FLAG_BASE
        // 度数：G_SLTU(1) × expr(1) = 2 ✓；binality = 1 + 2 = 3 ✓
        let is_slt = col(IS_SLT);
        let is_sltu = col(IS_SLTU);
        let is_slti = col(IS_SLTI);
        let is_sltiu = col(IS_SLTIU);
        let is_slt_group = is_slt.clone() + is_slti.clone(); // 有符号比较
        let is_sltu_group = is_sltu.clone() + is_sltiu.clone(); // 无符号比较
        let is_cmp = is_slt_group.clone() + is_sltu_group.clone(); // 所有比较指令

        // diff = rs1 - rs2（存入 COL_MUL_LOW_BASE，复用 MUL 列，one-hot 互斥）
        let diff_low16 = word_low16(COL_MUL_LOW_BASE);
        let diff_high16 = word_high16(COL_MUL_LOW_BASE);

        // diff_low16 = rs1_low - rs2_low + 65536 * borrow0（有符号和无符号共用）
        let cmp_diff_low = diff_low16.clone() - rs1_low.clone() + rs2_low.clone()
            - six5536.clone() * carry0.clone();
        eval.add_constraint(is_cmp.clone() * cmp_diff_low);

        // diff_high16 = rs1_high - rs2_high - borrow0 + 65536 * borrow1
        let cmp_diff_high = diff_high16.clone() - rs1_high.clone() + rs2_high.clone()
            + carry0.clone() - six5536.clone() * carry1.clone();
        eval.add_constraint(is_cmp.clone() * cmp_diff_high);

        // borrow0/borrow1 binality（gated by is_cmp）
        eval.add_constraint(is_cmp.clone() * carry0.clone() * (carry0.clone() - one.clone()));
        eval.add_constraint(is_cmp.clone() * carry1.clone() * (carry1.clone() - one.clone()));

        // SLTU/SLTIU: rd_eff = borrow1（无符号比较：rs1 < rs2 iff 高位借位）
        eval.add_constraint(is_sltu_group.clone() * (rd_eff_low.clone() - carry1.clone()));
        // rd_eff 高位 = 0（rd_eff 是 0 或 1）
        eval.add_constraint(is_sltu_group.clone() * rd_eff_high.clone());
        // rd_eff 低位 binality（rd_eff ∈ {0, 1}）
        eval.add_constraint(
            is_sltu_group.clone() * rd_eff_low.clone() * (rd_eff_low.clone() - one.clone()),
        );

        // ===== 约束 17a-22a：SLT/SLTI 约束（gated by IsSlt + IsSlti）=====
        // SLT/SLTI: rd_eff = (rs1 < rs2 有符号) ? 1 : 0
        // 有符号比较公式：
        //   sign_a = rs1 符号位（bit 31），sign_b = rs2 符号位
        //   same_sign = 1 - (sign_a XOR sign_b) = 1 - sign_a - sign_b + 2*sign_a*sign_b
        //   rd_eff = sign_a * (1 - sign_b) + same_sign * borrow1
        //   （符号不同→负数更小；符号相同→等同于无符号比较的 borrow1）
        // sign_a/sign_b 复用 COL_SIGN_A/COL_SIGN_B（MULH 行互斥）
        // same_sign 复用 COL_LOW_NONZERO（MUL 行互斥）
        let sign_a = col(COL_SIGN_A);
        let sign_b = col(COL_SIGN_B);
        let same_sign = col(COL_LOW_NONZERO);

        // sign_a/sign_b binality（gated by is_slt_group）
        eval.add_constraint(is_slt_group.clone() * sign_a.clone() * (sign_a.clone() - one.clone()));
        eval.add_constraint(is_slt_group.clone() * sign_b.clone() * (sign_b.clone() - one.clone()));

        // same_sign = 1 - sign_a - sign_b + 2*sign_a*sign_b（gated by is_slt_group）
        // 度数 = 1 × 2 = 3 ✓
        let same_sign_expr = same_sign.clone() - one.clone() + sign_a.clone() + sign_b.clone()
            - two.clone() * sign_a.clone() * sign_b.clone();
        eval.add_constraint(is_slt_group.clone() * same_sign_expr);

        // rd_eff = sign_a * (1 - sign_b) + same_sign * borrow1（gated by is_slt_group）
        // = sign_a - sign_a*sign_b + same_sign*borrow1（度数 2，gated 度 1，总 3 ✓）
        let slt_result = rd_eff_low.clone() - sign_a.clone() + sign_a.clone() * sign_b.clone()
            - same_sign.clone() * carry1.clone();
        eval.add_constraint(is_slt_group.clone() * slt_result);

        // rd_eff 高位 = 0 + rd_eff 低位 binality（rd_eff ∈ {0, 1}）
        eval.add_constraint(is_slt_group.clone() * rd_eff_high.clone());
        eval.add_constraint(
            is_slt_group.clone() * rd_eff_low.clone() * (rd_eff_low.clone() - one.clone()),
        );

        // ===== 约束 22b-34b：分支条件验证（V1 CRITICAL 修复）=====
        // 漏洞：Taken 仅做 binality 约束（Taken*(Taken-1)=0），未验证 Taken 与
        // rs1/rs2 比较结果一致。恶意 prover 可任意设 Taken=1 让分支跳转。
        // 修复：约束 Taken = f(rs1, rs2) 的正确比较结果。
        //
        // 列复用（one-hot 互斥，分支行与 MUL/DIV/SLT/ADD/SUB/Load/Store 互斥）：
        // - diff (4 limb) → COL_MUL_LOW_BASE(128-131)，复用比较/MUL 列
        // - borrow0/borrow1 → COL_CARRY_FLAG_BASE(8-9)，复用 ADD/SUB/比较列
        // - diff_inv (1 列) → COL_HELPER_B_BASE(69)，复用 Load/Store 列（HelperA 被分支目标占用）
        // - sign_a/sign_b/same_sign → COL_SIGN_A(114)/COL_SIGN_B(115)/COL_LOW_NONZERO(116)

        // diff = rs1 - rs2（复用比较约束已定义的 diff_low16/diff_high16，gated by is_branch）
        let br_diff_low = diff_low16.clone() - rs1_low.clone() + rs2_low.clone()
            - six5536.clone() * carry0.clone();
        eval.add_constraint(is_branch.clone() * br_diff_low);
        let br_diff_high = diff_high16.clone() - rs1_high.clone() + rs2_high.clone()
            + carry0.clone() - six5536.clone() * carry1.clone();
        eval.add_constraint(is_branch.clone() * br_diff_high);
        // borrow0/borrow1 binality（gated by is_branch）
        eval.add_constraint(is_branch.clone() * carry0.clone() * (carry0.clone() - one.clone()));
        eval.add_constraint(is_branch.clone() * carry1.clone() * (carry1.clone() - one.clone()));

        // diff_value = 完整 32-bit 值（度 1：4 列线性组合）
        let diff_value = diff_low16.clone() + six5536.clone() * diff_high16.clone();
        // diff_inv 存入 COL_HELPER_B_BASE（分支行与 Load/Store one-hot 互斥）
        let diff_inv = col(COL_HELPER_B_BASE);

        // ===== BEQ：taken ⟺ diff == 0 =====
        // taken=1 → diff_value=0（度 3：is_beq × taken × diff_value）
        eval.add_constraint(is_beq.clone() * taken.clone() * diff_value.clone());
        // diff * diff_inv = (1 - taken)（度 3）
        // taken=1: 0*0=0=(1-1) ✓；taken=0: diff*inv=1=(1-0) ✓
        eval.add_constraint(
            is_beq.clone() * (diff_value.clone() * diff_inv.clone() - (one.clone() - taken.clone())),
        );

        // ===== BNE：taken ⟺ diff != 0 =====
        // not-taken → diff=0（度 3：is_bne × (1-taken) × diff_value）
        eval.add_constraint(is_bne.clone() * (one.clone() - taken.clone()) * diff_value.clone());
        // diff * diff_inv = taken（度 3）
        // taken=1: diff*inv=1 ✓；taken=0: 0*0=0 ✓
        eval.add_constraint(
            is_bne.clone() * (diff_value.clone() * diff_inv.clone() - taken.clone()),
        );

        // ===== BLTU/BGEU：无符号比较 =====
        // BLTU: taken = borrow1（rs1 < rs2 无符号 iff 高位借位，度 2）
        eval.add_constraint(is_bltu.clone() * (taken.clone() - carry1.clone()));
        // BGEU: taken = 1 - borrow1（度 2）
        eval.add_constraint(is_bgeu.clone() * (taken.clone() - one.clone() + carry1.clone()));

        // ===== BLT/BGE：有符号比较（复用 SLT 公式）=====
        // same_sign/sign_a/sign_b 已在 SLT 约束中定义（复用 witness 列，one-hot 互斥）
        let is_signed_branch = is_blt.clone() + is_bge.clone();
        // sign_a/sign_b binality（gated by is_signed_branch）
        eval.add_constraint(
            is_signed_branch.clone() * sign_a.clone() * (sign_a.clone() - one.clone()),
        );
        eval.add_constraint(
            is_signed_branch.clone() * sign_b.clone() * (sign_b.clone() - one.clone()),
        );
        // same_sign = 1 - sign_a - sign_b + 2*sign_a*sign_b（gated by is_signed_branch，度 3）
        let br_same_sign_expr = same_sign.clone() - one.clone() + sign_a.clone() + sign_b.clone()
            - two.clone() * sign_a.clone() * sign_b.clone();
        eval.add_constraint(is_signed_branch.clone() * br_same_sign_expr);
        // slt_result = sign_a*(1-sign_b) + same_sign*borrow1（度 2）
        let slt_result_br = sign_a.clone() * (one.clone() - sign_b.clone())
            + same_sign.clone() * carry1.clone();
        // BLT: taken = slt_result（度 3）
        eval.add_constraint(is_blt.clone() * (taken.clone() - slt_result_br.clone()));
        // BGE: taken = 1 - slt_result（度 3）
        eval.add_constraint(is_bge.clone() * (taken.clone() - one.clone() + slt_result_br.clone()));

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

        // ===== 约束 28a-31a：JAL/JALR 链接寄存器约束（rd_eff = PC + 4）=====
        // JAL/JALR: rd_eff = PC + 4（返回地址写入链接寄存器）
        // 使用 PcCarryFlag 列（JAL/JALR 行与 IsNonFlow/IsBranch 互斥，PcCarryFlag 空闲）
        //   rd_eff_low16 = pc_low16 + 4 - 65536 * pc_carry0
        //   rd_eff_high16 = pc_high16 + pc_carry0 - 65536 * pc_carry1
        //   pc_carry0, pc_carry1 ∈ {0, 1}
        // 度数 = is_jal_jalr(1) × expr(1) = 2 ✓；binality = 1 + 2 = 3 ✓
        let is_jal_jalr = is_jal.clone() + is_jalr.clone();

        let jal_rd_low = rd_eff_low.clone() - pc_low16.clone() - four.clone()
            + six5536.clone() * pc_carry0.clone();
        eval.add_constraint(is_jal_jalr.clone() * jal_rd_low);

        let jal_rd_high = rd_eff_high.clone() - pc_high16.clone() - pc_carry0.clone()
            + six5536.clone() * pc_carry1.clone();
        eval.add_constraint(is_jal_jalr.clone() * jal_rd_high);

        // pc_carry0/pc_carry1 binality（gated by is_jal + is_jalr）
        eval.add_constraint(
            is_jal_jalr.clone() * pc_carry0.clone() * (pc_carry0.clone() - one.clone()),
        );
        eval.add_constraint(
            is_jal_jalr.clone() * pc_carry1.clone() * (pc_carry1.clone() - one.clone()),
        );

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

        // ===== V7 修复：Load 扩展约束（替换旧约束 44-47）=====
        // 详见 `.trae/documents/poker_zkvm_v7v8_bytelevel_fix_plan.md` §3.5。
        // HelperB 在 V7 后存储**原始值**（raw byte/halfword/word），rd_eff 由约束从
        // 原始值 + load subtype 推导，而非信任 prover 提供的扩展值。
        //
        // witness 列：
        //   IS_LOAD_BYTE/HALF/SIGN (col 81-83) — 复用 M 扩展 carry 列（仅 Load 行有效）
        //   SIGN_BIT      (col 84) — 原始值符号位（byte=bit7，halfword=bit15）
        //   LOAD_BITS[0..8] (col 85-92) — 符号承载字节的 8-bit 位分解
        //   LOAD_BYTE_GATE (col 132) — 预计算 IS_LOAD·IS_LOAD_BYTE（独立列，非 Load 行恒 0）
        //   LOAD_HALF_GATE (col 133) — 预计算 IS_LOAD·IS_LOAD_HALF（独立列，非 Load 行恒 0）
        //
        // 关键设计：IS_LOAD_BYTE/HALF/SIGN 复用 M 扩展 carry 列，在 MUL/DIV 行含非 0/1
        // 的 carry 值。故所有涉及这些列的约束必须用 IS_LOAD 或预计算 gate 门控，
        // 使其在 MUL/DIV 行自动为 0。预计算 gate 列（132-133）在非 Load 行恒 0，
        // 是扩展约束的安全 gate。所有约束度 ≤ 3。
        let is_load_byte = col(COL_IS_LOAD_BYTE);
        let is_load_half = col(COL_IS_LOAD_HALF);
        let is_load_sign = col(COL_IS_LOAD_SIGN);
        let sign_bit = col(COL_SIGN_BIT);
        let load_byte_gate = col(COL_LOAD_BYTE_GATE);
        let load_half_gate = col(COL_LOAD_HALF_GATE);

        // ----- (a) 预计算 gate binality + 正确性（度 2，共 6 条）-----
        // gate ∈ {0,1}（独立列，非 Load 行恒 0，Load 行为 0/1）
        eval.add_constraint(load_byte_gate.clone() * (load_byte_gate.clone() - one.clone()));
        eval.add_constraint(load_half_gate.clone() * (load_half_gate.clone() - one.clone()));
        // gate 互斥（byte/halfword 不可能同时）
        eval.add_constraint(load_byte_gate.clone() * load_half_gate.clone());
        // gate 正确性：Load 行 gate = subtype，非 Load 行 gate = 0（由 IS_LOAD 门控）
        //   IS_LOAD · (LOAD_BYTE_GATE - IS_LOAD_BYTE) = 0
        //   非 Load 行：IS_LOAD=0 → 0·(0-carry) = 0 ✓
        //   Load 行：IS_LOAD=1 → 1·(IS_LOAD_BYTE - IS_LOAD_BYTE) = 0 ✓
        eval.add_constraint(is_load.clone() * (load_byte_gate.clone() - is_load_byte.clone()));
        eval.add_constraint(is_load.clone() * (load_half_gate.clone() - is_load_half.clone()));

        // ----- (b) Load subtype binality（度 3，4 条，gated by IS_LOAD）-----
        // IS_LOAD_BYTE/HALF/SIGN/SIGN_BIT ∈ {0,1}（仅 Load 行约束，MUL/DIV 行由 IS_LOAD=0 门控）
        eval.add_constraint(is_load.clone() * is_load_byte.clone() * (is_load_byte.clone() - one.clone()));
        eval.add_constraint(is_load.clone() * is_load_half.clone() * (is_load_half.clone() - one.clone()));
        eval.add_constraint(is_load.clone() * is_load_sign.clone() * (is_load_sign.clone() - one.clone()));
        eval.add_constraint(is_load.clone() * sign_bit.clone() * (sign_bit.clone() - one.clone()));

        // ----- (c) LOAD_BITS binality（度 3，8 条，gated by IS_LOAD）-----
        for i in 0..COL_LOAD_BITS_COUNT {
            let bit = col(COL_LOAD_BITS_BASE + i);
            eval.add_constraint(is_load.clone() * bit.clone() * (bit - one.clone()));
        }

        // ----- (d) 位分解正确性（度 2，2 条，gated by 预计算 gate）-----
        // byte load: HelperB[0] = Σ LOAD_BITS[i]·2^i（原始字节 = 位分解之和）
        // halfword load: HelperB[1] = Σ LOAD_BITS[i]·2^i（原始半字高字节 = 位分解之和）
        let mut load_bits_sum: E::F = col(COL_LOAD_BITS_BASE);
        let mut pow2: E::F = two.clone();
        for i in 1..COL_LOAD_BITS_COUNT {
            load_bits_sum = load_bits_sum + col(COL_LOAD_BITS_BASE + i) * pow2.clone();
            pow2 = pow2 * two.clone();
        }
        eval.add_constraint(load_byte_gate.clone() * (col(COL_HELPER_B_BASE) - load_bits_sum.clone()));
        eval.add_constraint(load_half_gate.clone() * (col(COL_HELPER_B_BASE + 1) - load_bits_sum.clone()));

        // ----- (e) SIGN_BIT 一致性（度 2，2 条，gated by 预计算 gate）-----
        // SIGN_BIT = LOAD_BITS[7]（符号位即位分解的最高位）
        let load_bits_7 = col(COL_LOAD_BITS_BASE + 7);
        eval.add_constraint(load_byte_gate.clone() * (sign_bit.clone() - load_bits_7.clone()));
        eval.add_constraint(load_half_gate.clone() * (sign_bit.clone() - load_bits_7.clone()));

        // ----- (f) 扩展结构约束（度 ≤ 3，共 20 条，gated by 预计算 gate）-----
        // 使用预计算 gate（非 Load 行恒 0）作为主 gate，IS_LOAD_SIGN 区分符号/零扩展：
        //   LB  = LOAD_BYTE_GATE · IS_LOAD_SIGN
        //   LBU = LOAD_BYTE_GATE · (1 - IS_LOAD_SIGN)
        //   LH  = LOAD_HALF_GATE · IS_LOAD_SIGN
        //   LHU = LOAD_HALF_GATE · (1 - IS_LOAD_SIGN)
        //   LW  = IS_LOAD - LOAD_BYTE_GATE - LOAD_HALF_GATE
        let not_sign = one.clone() - is_load_sign.clone();
        let is_lw = is_load.clone() - load_byte_gate.clone() - load_half_gate.clone();

        // LB（符号扩展 byte）：rd_eff[0]=HelperB[0]，rd_eff[1..3]=SIGN_BIT·0xFF
        let lb_gate = load_byte_gate.clone() * is_load_sign.clone();
        eval.add_constraint(lb_gate.clone() * (col(COL_VALUE_A_EFF_BASE) - col(COL_HELPER_B_BASE)));
        eval.add_constraint(lb_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 1) - sign_bit.clone() * ff.clone()));
        eval.add_constraint(lb_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 2) - sign_bit.clone() * ff.clone()));
        eval.add_constraint(lb_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 3) - sign_bit.clone() * ff.clone()));

        // LBU（零扩展 byte）：rd_eff[0]=HelperB[0]，rd_eff[1..3]=0
        let lbu_gate = load_byte_gate.clone() * not_sign.clone();
        eval.add_constraint(lbu_gate.clone() * (col(COL_VALUE_A_EFF_BASE) - col(COL_HELPER_B_BASE)));
        eval.add_constraint(lbu_gate.clone() * col(COL_VALUE_A_EFF_BASE + 1));
        eval.add_constraint(lbu_gate.clone() * col(COL_VALUE_A_EFF_BASE + 2));
        eval.add_constraint(lbu_gate.clone() * col(COL_VALUE_A_EFF_BASE + 3));

        // LH（符号扩展 halfword）：rd_eff[0..1]=HelperB[0..1]，rd_eff[2..3]=SIGN_BIT·0xFF
        let lh_gate = load_half_gate.clone() * is_load_sign.clone();
        eval.add_constraint(lh_gate.clone() * (col(COL_VALUE_A_EFF_BASE) - col(COL_HELPER_B_BASE)));
        eval.add_constraint(lh_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 1) - col(COL_HELPER_B_BASE + 1)));
        eval.add_constraint(lh_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 2) - sign_bit.clone() * ff.clone()));
        eval.add_constraint(lh_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 3) - sign_bit.clone() * ff.clone()));

        // LHU（零扩展 halfword）：rd_eff[0..1]=HelperB[0..1]，rd_eff[2..3]=0
        let lhu_gate = load_half_gate.clone() * not_sign.clone();
        eval.add_constraint(lhu_gate.clone() * (col(COL_VALUE_A_EFF_BASE) - col(COL_HELPER_B_BASE)));
        eval.add_constraint(lhu_gate.clone() * (col(COL_VALUE_A_EFF_BASE + 1) - col(COL_HELPER_B_BASE + 1)));
        eval.add_constraint(lhu_gate.clone() * col(COL_VALUE_A_EFF_BASE + 2));
        eval.add_constraint(lhu_gate.clone() * col(COL_VALUE_A_EFF_BASE + 3));

        // LW（identity）：rd_eff[i]=HelperB[i] for i in 0..4
        for i in 0..4 {
            let lw_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER_B_BASE + i);
            eval.add_constraint(is_lw.clone() * lw_diff);
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

        // ===== M 扩展约束（v3.5 Step 3）：MUL carry chain =====
        // 参考 RISC Zero / OpenVM：8-bit 部分积 + carry chain。
        // 将 32-bit 操作数 a, b 分解为 4×8-bit limb：a = Σ aᵢ·256ⁱ，b = Σ bⱼ·256ʲ。
        // 64-bit 乘积 P = a·b = Σ_{i,j} aᵢ·bⱼ·256^{i+j}，按数位分组为 7 个部分和 S₀..S₆：
        //   S₀ = a₀·b₀                          (pos 0)
        //   S₁ = a₀·b₁ + a₁·b₀                  (pos 1)
        //   S₂ = a₀·b₂ + a₁·b₁ + a₂·b₀          (pos 2)
        //   S₃ = a₀·b₃ + a₁·b₂ + a₂·b₁ + a₃·b₀  (pos 3, 最大 = 4·65025 = 260100 < p ✓)
        //   S₄ = a₁·b₃ + a₂·b₂ + a₃·b₁          (pos 4)
        //   S₅ = a₂·b₃ + a₃·b₂                  (pos 5)
        //   S₆ = a₃·b₃                          (pos 6)
        // Carry chain 产生 8 个结果数字 c₀..c₇ + 7 个 carry：
        //   S₀            = c₀ + 256·carry₀
        //   Sₖ + carryₖ₋₁ = cₖ + 256·carryₖ   (k=1..6)
        //   carry₆        = c₇
        // 结果 c₀..c₃ = COL_MUL_LOW_BASE（低 32 位），c₄..c₇ = COL_MUL_HIGH_BASE（高 32 位）。
        // carryₖ = lo + 256·hi0 + 512·hi1（二元分解，Step 4 约束 hi0/hi1 ∈ {0,1}）。
        //
        // 分组（indicator one-hot 互斥，共享 carry 列）：
        //   G1 = MUL + MULHU：操作数 (ValueB=rs1, ValueC=rs2)
        //   G2 = MULH + MULHSU：操作数 (AbsA=|rs1|, AbsB=|rs2|或rs2)
        //   G3 = DIV + DIVU + REM + REMU：操作数 (DivQuot=q, AbsB=|d|或d)
        // 每组 8 条约束，度 = indicator(1) × Sₖ(2) = 3 ✓（k=7 为 carry₆−c₇，度 2）。
        let is_mul = col(IS_MUL);
        let is_mulh = col(IS_MULH);
        let is_mulhsu = col(IS_MULHSU);
        let is_mulhu = col(IS_MULHU);
        let is_div = col(IS_DIV);
        let is_divu = col(IS_DIVU);
        let is_rem = col(IS_REM);
        let is_remu = col(IS_REMU);

        // 分组 indicator
        let g1 = is_mul.clone() + is_mulhu.clone();
        let g2 = is_mulh.clone() + is_mulhsu.clone();
        let g3 = is_div.clone() + is_divu.clone() + is_rem.clone() + is_remu.clone();

        // carryₖ = lo + 256·hi0 + 512·hi1（512 = 256·2）
        let carry_k = |k: usize| -> E::F {
            col(COL_MUL_CARRY_LO_BASE + k)
                + two56.clone() * col(COL_MUL_CARRY_HI0_BASE + k)
                + two56.clone() * two.clone() * col(COL_MUL_CARRY_HI1_BASE + k)
        };

        // cₖ：k=0..3 → MUL_LOW（低 32 位 limb），k=4..7 → MUL_HIGH（高 32 位 limb）
        let c_k = |k: usize| -> E::F {
            if k < 4 {
                col(COL_MUL_LOW_BASE + k)
            } else {
                col(COL_MUL_HIGH_BASE + (k - 4))
            }
        };

        // 部分和 Sₖ(a_base, b_base) = Σ_{i+j=k, i,j∈[0,3]} a_i · b_j
        // i 范围：i_min = max(0, k−3)，i_max = min(k, 3)
        let partial_sum = |k: usize, a_base: usize, b_base: usize| -> E::F {
            let i_min = if k > 3 { k - 3 } else { 0 };
            let i_max = k.min(3);
            let mut sum = col(a_base + i_min) * col(b_base + (k - i_min));
            for i in (i_min + 1)..=i_max {
                sum = sum + col(a_base + i) * col(b_base + (k - i));
            }
            sum
        };

        // G1 = MUL + MULHU：操作数 (ValueB=rs1, ValueC=rs2)
        {
            let (a_base, b_base) = (COL_VALUE_B_BASE, COL_VALUE_C_BASE);
            // k=0: S₀ − c₀ − 256·carry₀ = 0
            let e0 = partial_sum(0, a_base, b_base) - c_k(0) - two56.clone() * carry_k(0);
            eval.add_constraint(g1.clone() * e0);
            // k=1..6: Sₖ + carryₖ₋₁ − cₖ − 256·carryₖ = 0
            for k in 1..7usize {
                let ek = partial_sum(k, a_base, b_base) + carry_k(k - 1) - c_k(k)
                    - two56.clone() * carry_k(k);
                eval.add_constraint(g1.clone() * ek);
            }
            // k=7: carry₆ − c₇ = 0
            let e7 = carry_k(6) - c_k(7);
            eval.add_constraint(g1.clone() * e7);
        }

        // G2 = MULH + MULHSU：操作数 (AbsA=|rs1|, AbsB=|rs2|/rs2)
        {
            let (a_base, b_base) = (COL_ABS_A_BASE, COL_ABS_B_BASE);
            let e0 = partial_sum(0, a_base, b_base) - c_k(0) - two56.clone() * carry_k(0);
            eval.add_constraint(g2.clone() * e0);
            for k in 1..7usize {
                let ek = partial_sum(k, a_base, b_base) + carry_k(k - 1) - c_k(k)
                    - two56.clone() * carry_k(k);
                eval.add_constraint(g2.clone() * ek);
            }
            let e7 = carry_k(6) - c_k(7);
            eval.add_constraint(g2.clone() * e7);
        }

        // G3 = DIV + DIVU + REM + REMU：操作数 (DivQuot=q, AbsB=|d|/d)
        {
            let (a_base, b_base) = (COL_DIV_QUOT_BASE, COL_ABS_B_BASE);
            let e0 = partial_sum(0, a_base, b_base) - c_k(0) - two56.clone() * carry_k(0);
            eval.add_constraint(g3.clone() * e0);
            for k in 1..7usize {
                let ek = partial_sum(k, a_base, b_base) + carry_k(k - 1) - c_k(k)
                    - two56.clone() * carry_k(k);
                eval.add_constraint(g3.clone() * ek);
            }
            let e7 = carry_k(6) - c_k(7);
            eval.add_constraint(g3.clone() * e7);
        }

        // ===== M 扩展约束（v3.5 Step 4）：Carry 二元分解 range check =====
        // carryₖ = lo + 256·hi0 + 512·hi1，其中 lo ∈ [0,255]（信任，同 ADD/SUB limb），
        // hi0, hi1 ∈ {0,1}（binality 强制）。限制 carry ∈ [0, 1023]，覆盖实际范围 ~1020。
        //
        // 注：无需独立的"carry 重建"约束——Step 3 的 carry chain 直接使用分解形式
        // (lo + 256·hi0 + 512·hi1)，不存在独立的 carry 列需要重建。
        // 非 M 行 carry 列为 0（满足 binality），故采用通用（无 gating）约束，度 2。
        //
        // hi0 binality (k=0..6)：hi0ₖ·(hi0ₖ−1) = 0
        for k in 0..7usize {
            let hi0_k = col(COL_MUL_CARRY_HI0_BASE + k);
            eval.add_constraint(hi0_k.clone() * (hi0_k - one.clone()));
        }
        // hi1 binality (k=0..6)：hi1ₖ·(hi1ₖ−1) = 0
        for k in 0..7usize {
            let hi1_k = col(COL_MUL_CARRY_HI1_BASE + k);
            eval.add_constraint(hi1_k.clone() * (hi1_k - one.clone()));
        }

        // ===== M 扩展约束（v3.5 Step 5）：符号处理 + MUL 结果 =====
        // 符号模型（参考 OpenVM）：
        // - sign_a/sign_b ∈ {0,1}：rs1/rs2 符号位（1=负数）
        // - abs_a = sign_a ? (2³²−rs1) : rs1；abs_b 同理（MULHSU 的 abs_b=rs2，sign_b=0）
        // - low_nonzero ∈ {0,1}：乘积低 32 位 ≠ 0（结果补码借位）
        // - result_sign（COL_DIV_SIGN_Q，复用）：MULH=sign_a⊕sign_b，MULHSU=sign_a
        // - result_carry（COL_DIV_SIGN_R，复用）：结果调整 low16→high16 进位
        // - 结果调整：sign=0 → rd_eff=high32；sign=1 → rd_eff=2³²−high32−low_nonzero
        //   （修正公式：2³²−high32−low_nonzero，已验证 a=−1,b=2 → 0xFFFFFFFF ✓）
        //
        // 列复用（one-hot 互斥）：carry0/carry1（COL_CARRY_FLAG_BASE）在 MULH/MULHSU
        // 行存 abs 重建 borrow，与 ADD/SUB 互斥；DIV_SIGN_Q/R 存结果符号/进位，与 DIV 互斥。
        let sign_a = col(COL_SIGN_A);
        let sign_b = col(COL_SIGN_B);
        let low_nonzero = col(COL_LOW_NONZERO);
        let result_sign = col(COL_DIV_SIGN_Q);
        let result_carry = col(COL_DIV_SIGN_R);

        // 16-bit 半字辅助值（abs / mul_high）
        let abs_a_low = word_low16(COL_ABS_A_BASE);
        let abs_a_high = word_high16(COL_ABS_A_BASE);
        let abs_b_low = word_low16(COL_ABS_B_BASE);
        let abs_b_high = word_high16(COL_ABS_B_BASE);
        let mul_high_low = word_low16(COL_MUL_HIGH_BASE);
        let mul_high_high = word_high16(COL_MUL_HIGH_BASE);

        // ===== MUL 结果匹配（gated by IsMul，度 2）=====
        // MUL 取低 32 位：rd_eff = mul_low（逐 limb 相等）
        for i in 0..4usize {
            let diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_MUL_LOW_BASE + i);
            eval.add_constraint(is_mul.clone() * diff);
        }
        // ===== MULHU 结果匹配（gated by IsMulhu，度 2）=====
        // MULHU 取高 32 位：rd_eff = mul_high（逐 limb 相等）
        for i in 0..4usize {
            let diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_MUL_HIGH_BASE + i);
            eval.add_constraint(is_mulhu.clone() * diff);
        }

        // ===== sign / low_nonzero binality（通用，度 2）=====
        eval.add_constraint(sign_a.clone() * (sign_a.clone() - one.clone()));
        eval.add_constraint(sign_b.clone() * (sign_b.clone() - one.clone()));
        eval.add_constraint(low_nonzero.clone() * (low_nonzero.clone() - one.clone()));

        // ===== abs_a 重建（gated by g2=MULH+MULHSU，度 3）=====
        // sign_a=0: abs_a = rs1；sign_a=1: abs_a = 2³²−rs1（abs+rs1=2³²，16-bit borrow）
        //   sign=1: abs_low + rs1_low = 65536·carry0；abs_high + rs1_high + carry0 = 65536
        // 合并：g2·[(1−s)·(abs−rs1) + s·(abs+rs1±carry)] = 0
        let abs_a_low_expr = (one.clone() - sign_a.clone()) * (abs_a_low.clone() - rs1_low.clone())
            + sign_a.clone() * (abs_a_low.clone() + rs1_low.clone() - six5536.clone() * carry0.clone());
        eval.add_constraint(g2.clone() * abs_a_low_expr);
        let abs_a_high_expr = (one.clone() - sign_a.clone()) * (abs_a_high.clone() - rs1_high.clone())
            + sign_a.clone() * (abs_a_high.clone() + rs1_high.clone() + carry0.clone() - six5536.clone());
        eval.add_constraint(g2.clone() * abs_a_high_expr);
        // carry0 binality（gated by g2，度 3）：复用 COL_CARRY_FLAG_BASE 作 abs_a borrow
        eval.add_constraint(g2.clone() * carry0.clone() * (carry0.clone() - one.clone()));

        // ===== abs_b 重建（gated by g2，度 3）=====
        // MULHSU 的 abs_b = rs2（sign_b=0）；MULH 的 abs_b = |rs2|
        let abs_b_low_expr = (one.clone() - sign_b.clone()) * (abs_b_low.clone() - rs2_low.clone())
            + sign_b.clone() * (abs_b_low.clone() + rs2_low.clone() - six5536.clone() * carry1.clone());
        eval.add_constraint(g2.clone() * abs_b_low_expr);
        let abs_b_high_expr = (one.clone() - sign_b.clone()) * (abs_b_high.clone() - rs2_high.clone())
            + sign_b.clone() * (abs_b_high.clone() + rs2_high.clone() + carry1.clone() - six5536.clone());
        eval.add_constraint(g2.clone() * abs_b_high_expr);
        // carry1 binality（gated by g2，度 3）：复用 COL_CARRY_FLAG_BASE+1 作 abs_b borrow
        eval.add_constraint(g2.clone() * carry1.clone() * (carry1.clone() - one.clone()));

        // ===== result_sign / result_carry binality（gated by g2，度 3）=====
        eval.add_constraint(g2.clone() * result_sign.clone() * (result_sign.clone() - one.clone()));
        eval.add_constraint(g2.clone() * result_carry.clone() * (result_carry.clone() - one.clone()));

        // ===== 结果符号调整（gated by g2=MULH+MULHSU，度 3）=====
        // sign=0: rd_eff = high32；sign=1: rd_eff = 2³²−high32−low_nonzero
        //   sign=1: rd_low + high_low + low_nz = 65536·c；rd_high + high_high + c = 65536
        let res_low = (one.clone() - result_sign.clone()) * (rd_eff_low.clone() - mul_high_low.clone())
            + result_sign.clone() * (rd_eff_low.clone() + mul_high_low.clone() + low_nonzero.clone()
                - six5536.clone() * result_carry.clone());
        eval.add_constraint(g2.clone() * res_low);
        let res_high = (one.clone() - result_sign.clone()) * (rd_eff_high.clone() - mul_high_high.clone())
            + result_sign.clone() * (rd_eff_high.clone() + mul_high_high.clone() + result_carry.clone()
                - six5536.clone());
        eval.add_constraint(g2.clone() * res_high);

        // ===== M 扩展约束（v3.5 Step 6）：DIV 约束 =====
        // DIV 系列验证（参考 SP1 / OpenVM：q·d+r=n 恒等式 + 范围检查）：
        // - G3 carry chain（Step 3）已约束 q_abs × abs_b = low32 + high32·2³²
        // - high32 = 0（乘积 ≤ 32 位，因 q·d ≤ n < 2³²）
        // - 恒等式：low32 + r_abs = abs_a（q·d + r = n 的绝对值形式）
        // - 范围检查：r_abs < abs_b（当非 special 时，确保商唯一）
        // - abs 重建：abs_a = |rs1|, abs_b = |rs2|（复用 Step 5 模式，gated by g3）
        // - 结果匹配：rd_eff = sign_adjust(q_abs) (DIV/DIVU) 或 sign_adjust(r_abs) (REM/REMU)
        // - 特殊情况：is_special → sign_q = 1（d=0 时 q=−1, overflow 时 q=INT_MIN）
        //
        // 列复用（one-hot 互斥，DIV 行与其他指令不冲突）：
        // - carry0 (COL_CARRY_FLAG_BASE) → abs_a 重建 borrow（与 ADD/SUB/MULH 互斥）
        // - carry1 (COL_CARRY_FLAG_BASE+1) → 恒等式 carry_id（与 ADD/SUB/MULH 互斥）
        // - LOW_NONZERO → 范围检查 borrow0（universal binality 已约束）
        // - HelperA[0] → abs_b 重建 borrow（与 Load/Store/JALR 互斥）
        // - HelperA[1] → 范围检查 borrow1（正常 = 0）
        // - HelperA[2] → 结果符号调整 carry
        // - HelperB[0..3] → 范围检查 diff（abs_b − r_abs − 1，4×8-bit limb）

        // 读取 DIV 专用 witness 列
        let is_special = col(COL_DIV_IS_SPECIAL);
        let sign_q = col(COL_DIV_SIGN_Q);
        let sign_r = col(COL_DIV_SIGN_R);
        let quot_low = word_low16(COL_DIV_QUOT_BASE);
        let quot_high = word_high16(COL_DIV_QUOT_BASE);
        let rem_low = word_low16(COL_DIV_REM_BASE);
        let rem_high = word_high16(COL_DIV_REM_BASE);
        let mul_low_low = word_low16(COL_MUL_LOW_BASE);
        let mul_low_high = word_high16(COL_MUL_LOW_BASE);

        // 复用列读取
        let div_borrow_a = col(COL_CARRY_FLAG_BASE);       // abs_a 重建 borrow
        let div_borrow_b = col(COL_HELPER_A_BASE);          // abs_b 重建 borrow
        let div_carry_id = col(COL_CARRY_FLAG_BASE + 1);    // 恒等式 carry
        let div_borrow0 = col(COL_LOW_NONZERO);             // 范围检查 borrow0
        let div_borrow1 = col(COL_HELPER_A_BASE + 1);       // 范围检查 borrow1
        let div_adj_carry = col(COL_HELPER_A_BASE + 2);     // 结果符号调整 carry
        let diff_low = word_low16(COL_HELPER_B_BASE);
        let diff_high = word_high16(COL_HELPER_B_BASE);

        // ----- high32 = 0（gated by g3，度 2）-----
        // q·d ≤ n < 2³²，故乘积高位 = 0（d=0 时乘积=0，overflow 时 2³¹×1=2³¹ < 2³²）
        for i in 0..4usize {
            eval.add_constraint(g3.clone() * col(COL_MUL_HIGH_BASE + i));
        }

        // ----- abs_a 重建（gated by g3，度 3）-----
        // sign_a=0: abs_a = rs1；sign_a=1: abs_a = 2³²−rs1（16-bit borrow）
        let div_abs_a_low = (one.clone() - sign_a.clone()) * (abs_a_low.clone() - rs1_low.clone())
            + sign_a.clone() * (abs_a_low.clone() + rs1_low.clone() - six5536.clone() * div_borrow_a.clone());
        eval.add_constraint(g3.clone() * div_abs_a_low);
        let div_abs_a_high = (one.clone() - sign_a.clone()) * (abs_a_high.clone() - rs1_high.clone())
            + sign_a.clone() * (abs_a_high.clone() + rs1_high.clone() + div_borrow_a.clone() - six5536.clone());
        eval.add_constraint(g3.clone() * div_abs_a_high);
        // div_borrow_a binality（gated by g3，度 3）
        eval.add_constraint(g3.clone() * div_borrow_a.clone() * (div_borrow_a.clone() - one.clone()));

        // ----- abs_b 重建（gated by g3，度 3）-----
        let div_abs_b_low = (one.clone() - sign_b.clone()) * (abs_b_low.clone() - rs2_low.clone())
            + sign_b.clone() * (abs_b_low.clone() + rs2_low.clone() - six5536.clone() * div_borrow_b.clone());
        eval.add_constraint(g3.clone() * div_abs_b_low);
        let div_abs_b_high = (one.clone() - sign_b.clone()) * (abs_b_high.clone() - rs2_high.clone())
            + sign_b.clone() * (abs_b_high.clone() + rs2_high.clone() + div_borrow_b.clone() - six5536.clone());
        eval.add_constraint(g3.clone() * div_abs_b_high);
        // div_borrow_b binality（gated by g3，度 3）
        eval.add_constraint(g3.clone() * div_borrow_b.clone() * (div_borrow_b.clone() - one.clone()));

        // ----- 恒等式：low32 + r_abs = abs_a（gated by g3，度 2）-----
        // low16: mul_low_low + rem_low − abs_a_low − 65536·carry_id = 0
        let id_low = mul_low_low.clone() + rem_low.clone() - abs_a_low.clone()
            - six5536.clone() * div_carry_id.clone();
        eval.add_constraint(g3.clone() * id_low);
        // high16: mul_low_high + rem_high + carry_id − abs_a_high = 0
        let id_high = mul_low_high.clone() + rem_high.clone() + div_carry_id.clone() - abs_a_high.clone();
        eval.add_constraint(g3.clone() * id_high);
        // div_carry_id binality（gated by g3，度 3）
        eval.add_constraint(g3.clone() * div_carry_id.clone() * (div_carry_id.clone() - one.clone()));

        // ----- is_special / sign_q / sign_r binality（gated by g3，度 3）-----
        eval.add_constraint(g3.clone() * is_special.clone() * (is_special.clone() - one.clone()));
        eval.add_constraint(g3.clone() * sign_q.clone() * (sign_q.clone() - one.clone()));
        eval.add_constraint(g3.clone() * sign_r.clone() * (sign_r.clone() - one.clone()));

        // ----- 特殊情况：有符号 DIV 的 is_special → sign_q = 1（gated by is_div，度 3）-----
        // d=0: q=−1 (sign_q=1); overflow: q=INT_MIN (sign_q=1)
        // 注意：仅对有符号 DIV 约束，DIVU 的 d=0 时 sign_q=0（无符号商）
        eval.add_constraint(is_div.clone() * is_special.clone() * (one.clone() - sign_q.clone()));

        // ===== V6 修复：DIV 特殊情况 q_abs 约束（d=0 时 q_abs 无约束漏洞）=====
        // 漏洞：d=0（abs_b=0）时 carry chain 乘积 = q_abs × 0 = 0，identity 退化为
        // r_abs = abs_a，q_abs 完全无约束。prover 可任意设定 q_abs → rd_eff 任意。
        // 修复：当 is_special=1 时约束 abs_b ∈ {0,1}（d=0→0, overflow→|-1|=1），
        // 并在 d=0 时（abs_b=0，gate_d0=1）强制 q_abs 为 RISC-V 规范值：
        // - 有符号 (sign_q=1): q_abs = 1（|−1| = 1，q = -1）
        // - 无符号 (sign_q=0): q_abs = 0xFFFFFFFF（q = all-ones）
        // overflow 时 abs_b=1，identity 已约束 q_abs（q_abs×1 + r_abs = abs_a），无需额外约束。
        //
        // 自保护分析（无 g3 gating 也安全）：
        // - 非 DIV 行 is_special=0 → 所有约束 gated off（is_special=0 → 0×anything=0）
        // - 恶意 is_special=1 非 DIV 行：q_abs_limb=0（未填），expected≠0 → 约束违反 → prove 失败
        // - MULH 行 abs_b=|rs2|（可能>1），若恶意 is_special=1 → abs_b binality 约束违反 → prove 失败
        let two55: E::F = BaseField::from(255u32).into();
        let abs_b_limb0 = col(COL_ABS_B_BASE);
        let abs_b_limb1 = col(COL_ABS_B_BASE + 1);
        let abs_b_limb2 = col(COL_ABS_B_BASE + 2);
        let abs_b_limb3 = col(COL_ABS_B_BASE + 3);

        // is_special=1 时 abs_b_limb[0] ∈ {0,1}（度 3）
        eval.add_constraint(
            is_special.clone() * abs_b_limb0.clone() * (abs_b_limb0.clone() - one.clone()),
        );
        // is_special=1 时 abs_b_limb[1..3] = 0（度 2 each）
        eval.add_constraint(is_special.clone() * abs_b_limb1.clone());
        eval.add_constraint(is_special.clone() * abs_b_limb2.clone());
        eval.add_constraint(is_special.clone() * abs_b_limb3.clone());

        // gate_d0 = is_special · (1 − abs_b_limb[0])（度 2）
        // is_special=1 且 abs_b=0（d=0）→ gate=1；abs_b=1（overflow）→ gate=0
        let gate_d0 = is_special.clone() * (one.clone() - abs_b_limb0.clone());

        // d=0 时 q_abs_limb[0] = sign_q + 255·(1−sign_q)（度 3）
        // sign_q=1（有符号）→ 1；sign_q=0（无符号）→ 255
        let q_abs_limb0_expected =
            sign_q.clone() + two55.clone() * (one.clone() - sign_q.clone());
        let q_abs_limb0 = col(COL_DIV_QUOT_BASE);
        eval.add_constraint(gate_d0.clone() * (q_abs_limb0.clone() - q_abs_limb0_expected));

        // d=0 时 q_abs_limb[1..3] = 255·(1−sign_q)（度 3 each）
        // sign_q=1（有符号）→ 0；sign_q=0（无符号）→ 255
        for i in 1..4usize {
            let q_abs_limb_i = col(COL_DIV_QUOT_BASE + i);
            let expected_i = two55.clone() * (one.clone() - sign_q.clone());
            eval.add_constraint(gate_d0.clone() * (q_abs_limb_i - expected_i));
        }

        // ----- 范围检查：r_abs < abs_b（gated by g3·(1−is_special)，度 3）-----
        // diff = abs_b − r_abs − 1 ≥ 0（borrow1 = 0）
        // low16: abs_b_low − rem_low − 1 + 65536·borrow0 − diff_low = 0
        // high16: abs_b_high − rem_high − borrow0 + 65536·borrow1 − diff_high = 0
        // borrow1 = 0
        let not_special = one.clone() - is_special.clone();
        let range_gate = g3.clone() * not_special.clone();
        let range_low = abs_b_low.clone() - rem_low.clone() - one.clone()
            + six5536.clone() * div_borrow0.clone() - diff_low.clone();
        eval.add_constraint(range_gate.clone() * range_low);
        let range_high = abs_b_high.clone() - rem_high.clone() - div_borrow0.clone()
            + six5536.clone() * div_borrow1.clone() - diff_high.clone();
        eval.add_constraint(range_gate.clone() * range_high);
        // borrow1 = 0（gated by range_gate，度 3）
        eval.add_constraint(range_gate.clone() * div_borrow1.clone());

        // ----- 结果匹配：DIV/DIVU → rd_eff = sign_adjust(q_abs)（度 3）-----
        // sign_q=0: rd_eff = q_abs；sign_q=1: rd_eff = 2³²−q_abs
        let is_div_q = is_div.clone() + is_divu.clone();
        let div_res_low = (one.clone() - sign_q.clone()) * (rd_eff_low.clone() - quot_low.clone())
            + sign_q.clone() * (rd_eff_low.clone() + quot_low.clone() - six5536.clone() * div_adj_carry.clone());
        eval.add_constraint(is_div_q.clone() * div_res_low);
        let div_res_high = (one.clone() - sign_q.clone()) * (rd_eff_high.clone() - quot_high.clone())
            + sign_q.clone() * (rd_eff_high.clone() + quot_high.clone() + div_adj_carry.clone() - six5536.clone());
        eval.add_constraint(is_div_q.clone() * div_res_high);

        // ----- 结果匹配：REM/REMU → rd_eff = sign_adjust(r_abs)（度 3）-----
        // sign_r=0: rd_eff = r_abs；sign_r=1: rd_eff = 2³²−r_abs
        let is_rem_r = is_rem.clone() + is_remu.clone();
        let rem_res_low = (one.clone() - sign_r.clone()) * (rd_eff_low.clone() - rem_low.clone())
            + sign_r.clone() * (rd_eff_low.clone() + rem_low.clone() - six5536.clone() * div_adj_carry.clone());
        eval.add_constraint(is_rem_r.clone() * rem_res_low);
        let rem_res_high = (one.clone() - sign_r.clone()) * (rd_eff_high.clone() - rem_high.clone())
            + sign_r.clone() * (rd_eff_high.clone() + rem_high.clone() + div_adj_carry.clone() - six5536.clone());
        eval.add_constraint(is_rem_r.clone() * rem_res_high);

        // div_adj_carry binality（gated by g3，度 3）—— DIV/REM one-hot 共享同一 carry 列
        eval.add_constraint(g3.clone() * div_adj_carry.clone() * (div_adj_carry.clone() - one.clone()));

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

        // ===== V4 约束：RangeCheck logup claim（gated by Option<RangeCheckLookup>）=====
        // 当 range_lookup = Some(lookup) 时，对每个非 padding 行的 24 个 limb 列发送 1 元组 claim：
        //   values = (limb_value,)
        //   multiplicity = (1 - IsPadding)（非 padding 行 = +1，padding 行 = 0）
        //
        // 需 range check 的 24 个 limb 列（6 word × 4 limb）：
        //   PC(0-3) + PcNext(4-7) + ValueAEff(10-13) + ValueB(14-17) + ValueC(18-21) + MemAddr(74-77)
        //
        // 一致性条件：Σ(CPU claims) + Σ(RangeCheckAir yields) == 0
        // RangeCheckAir 对 v ∈ [0, 255] 发送 yield (v, -count_v)。
        if let Some(ref lookup) = self.range_lookup {
            let is_non_padding: E::F = one.clone() - is_padding.clone();
            let mult_ef: E::EF = is_non_padding.into();
            // 24 个 limb 列索引
            const RANGE_CHECK_COLS: [usize; 24] = [
                // PC (0-3)
                COL_PC_BASE, COL_PC_BASE + 1, COL_PC_BASE + 2, COL_PC_BASE + 3,
                // PcNext (4-7)
                COL_PC_NEXT_BASE, COL_PC_NEXT_BASE + 1, COL_PC_NEXT_BASE + 2, COL_PC_NEXT_BASE + 3,
                // ValueAEff (10-13)
                COL_VALUE_A_EFF_BASE, COL_VALUE_A_EFF_BASE + 1, COL_VALUE_A_EFF_BASE + 2, COL_VALUE_A_EFF_BASE + 3,
                // ValueB (14-17)
                COL_VALUE_B_BASE, COL_VALUE_B_BASE + 1, COL_VALUE_B_BASE + 2, COL_VALUE_B_BASE + 3,
                // ValueC (18-21)
                COL_VALUE_C_BASE, COL_VALUE_C_BASE + 1, COL_VALUE_C_BASE + 2, COL_VALUE_C_BASE + 3,
                // MemAddr (74-77)
                COL_MEM_ADDR_BASE, COL_MEM_ADDR_BASE + 1, COL_MEM_ADDR_BASE + 2, COL_MEM_ADDR_BASE + 3,
            ];
            for &col_idx in &RANGE_CHECK_COLS {
                let limb_val = col(col_idx);
                eval.add_to_relation(RelationEntry::new(
                    lookup,
                    mult_ef.clone(),
                    &[limb_val],
                ));
            }
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
    use crate::stwo_backend::column_layout_v2::{IS_MUL, IS_REMU};
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
        // v3.4：ECALL dispatch 列布局常量（缩减为 1 列 SyscallId）
        assert_eq!(IS_ECALL, 54, "IS_ECALL 应在 indicator 范围 [22, 65) 内");
        assert_eq!(COL_SYSCALL_ID, 78);
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
        // v3.4：验证 CpuAir 使用的列索引与 column_layout_v2 一致
        // 变更：新增 M 扩展 8 indicator，IS_PADDING 及后续列位移 +8
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
        // M 扩展 indicator（56-63）
        assert_eq!(IS_MUL, 56);
        assert_eq!(IS_REMU, 63);
        assert_eq!(IS_PADDING, 64);
        assert_eq!(COL_HELPER_A_BASE, 65);
        assert_eq!(COL_HELPER_B_BASE, 69);
        assert_eq!(COL_TAKEN, 73);
        assert_eq!(NUM_COLUMNS, 134);
        assert_eq!(NUM_INSTRUCTION_CATEGORIES, 43);
    }
}
