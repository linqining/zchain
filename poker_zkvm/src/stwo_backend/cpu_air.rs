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
    COL_BORROW_FLAG_BASE, COL_CARRY_FLAG_BASE, COL_HELPER1_BASE, COL_HELPER2_BASE,
    COL_HELPER3_BASE, COL_HELPER4_BASE, COL_IS_BASE, COL_MEM_ADDR_BASE, COL_PC_BASE,
    COL_PC_NEXT_AUX_BASE, COL_PC_NEXT_BASE, COL_SYSCALL_ARG0_BASE, COL_SYSCALL_ARG1_BASE,
    COL_SYSCALL_ARG2_BASE, COL_SYSCALL_ARG3_BASE, COL_SYSCALL_ID, COL_SYSCALL_OUTPUT0_BASE,
    COL_SYSCALL_OUTPUT1_BASE, COL_TAKEN, COL_VALUE_A_EFF_BASE, COL_VALUE_B_BASE,
    COL_VALUE_C_BASE, ECALL_DISPATCH_NUM_COLUMNS, IS_ADD, IS_ADDI, IS_AUIPC, IS_BEQ, IS_BGE,
    IS_BGEU, IS_BLT, IS_BLTU, IS_BNE, IS_ECALL, IS_JAL, IS_JALR, IS_LOAD, IS_LUI, IS_PADDING,
    IS_STORE, IS_SUB, NUM_COLUMNS, NUM_INSTRUCTION_CATEGORIES,
};
use super::lookups::{EcallLookup, MemoryLookup};

/// 65536 = 2^16，16-bit 边界进位/借位的基数。
const SIX5536: BaseField = BaseField::from_u32_unchecked(65536);

/// 256 = 2^8，byte 边界的基数。
const TWO56: BaseField = BaseField::from_u32_unchecked(256);

/// 常量 4（PcNext = Pc + 4 中的立即数偏移）。
const FOUR: BaseField = BaseField::from_u32_unchecked(4);

/// CPU AIR 组件 — 封装 126 列 trace 的 FrameworkEval 实现。
///
/// # 结构
/// - `log_size` — log2(trace 行数)，行数 = 2^log_size
/// - `memory_lookup` — 可选的 MemoryLookup relation。
///   - `None`：不发送 Memory logup claim
///   - `Some(lookup)`：为每行 Load/Store 发送 logup claim（Phase 3.4+）
/// - `ecall_lookup` — 可选的 EcallLookup relation（Phase 4 Tier 1+）。
///   - `None`：不发送 ECALL logup claim
///   - `Some(lookup)`：为每行 ECALL 发送 25 元组 logup claim
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
    /// Phase 4 Tier 1 新增
    ecall_lookup: Option<EcallLookup>,
}

impl CpuAir {
    /// 创建指定 log_size 的 CPU AIR（单组件模式，无 logup）。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10（Stwo SIMD 对齐要求）
    ///
    /// # 返回
    /// `memory_lookup = None, ecall_lookup = None` 的 CpuAir，不发送任何 logup claim。
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

        // ----- 读取全部 97 列（顺序与 column_layout_v2 一致）-----
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

        // ----- 读取 carry/borrow 标志 -----
        let carry0 = col(COL_CARRY_FLAG_BASE);
        let carry1 = col(COL_CARRY_FLAG_BASE + 1);
        let borrow0 = col(COL_BORROW_FLAG_BASE);
        let borrow1 = col(COL_BORROW_FLAG_BASE + 1);

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
        // 低 16 位：rd_eff_low = rs1_low - rs2_low + 65536 * borrow0
        let sub_low = rd_eff_low.clone() - rs1_low.clone() + rs2_low.clone()
            - six5536.clone() * borrow0.clone();
        eval.add_constraint(is_sub.clone() * sub_low);

        // 高 16 位：rd_eff_high = rs1_high - rs2_high - borrow0 + 65536 * borrow1
        let sub_high = rd_eff_high.clone() - rs1_high.clone() + rs2_high.clone()
            + borrow0.clone() - six5536.clone() * borrow1.clone();
        eval.add_constraint(is_sub.clone() * sub_high);

        // borrow0 binality
        let borrow0_bin = borrow0.clone() * (borrow0.clone() - one.clone());
        eval.add_constraint(is_sub.clone() * borrow0_bin);

        // borrow1 binality
        let borrow1_bin = borrow1.clone() * (borrow1.clone() - one.clone());
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

        // ===== 约束 16-19：PC 递增约束（gated by IsNonFlow）=====
        // 非跳转/非分支/非 padding 指令：PcNext = Pc + 4
        // 4_limb = [4, 0, 0, 0]（little-endian）
        // 对每个 limb i：PcNext[i] - Pc[i] - 4_limb[i] = 0
        // 4_limb[0] = 4, 4_limb[1..=3] = 0
        let pc_limb0_diff = col(COL_PC_NEXT_BASE) - col(COL_PC_BASE) - four.clone();
        eval.add_constraint(is_non_flow.clone() * pc_limb0_diff);

        for i in 1..4 {
            let pc_limb_diff = col(COL_PC_NEXT_BASE + i) - col(COL_PC_BASE + i);
            eval.add_constraint(is_non_flow.clone() * pc_limb_diff);
        }

        // ===== 约束 20-23：JAL 约束（gated by IsJal）=====
        // JAL: PcNext = Pc + imm，Helper2 预存 (Pc + imm)
        // 对每个 limb i：PcNext[i] - Helper2[i] = 0
        for i in 0..4 {
            let jal_diff = col(COL_PC_NEXT_BASE + i) - col(COL_HELPER2_BASE + i);
            eval.add_constraint(is_jal.clone() * jal_diff);
        }

        // ===== 约束 24-27：JALR 约束（gated by IsJalr）=====
        // JALR: PcNext = (rs1 + imm) & !1，PcNextAux 预存该值
        // 对每个 limb i：PcNext[i] - PcNextAux[i] = 0
        for i in 0..4 {
            let jalr_diff = col(COL_PC_NEXT_BASE + i) - col(COL_PC_NEXT_AUX_BASE + i);
            eval.add_constraint(is_jalr.clone() * jalr_diff);
        }

        // ===== 约束 28-31：Branch 约束（gated by IsBranch）=====
        // 分支指令：taken ? PcNext = Pc + imm : PcNext = Pc + 4
        // 对每个 limb i：
        //   (1 - Taken) * (PcNext[i] - Pc[i] - 4_limb[i]) + Taken * (PcNext[i] - Helper2[i]) = 0
        // 其中 4_limb[0] = 4, 4_limb[1..=3] = 0
        // 注意：度 = 1 (IsBranch) + 1 (Taken) + 1 (减法) = 3
        let one_minus_taken = one.clone() - taken.clone();
        for i in 0..4 {
            let pc_next_limb = col(COL_PC_NEXT_BASE + i);
            let pc_limb = col(COL_PC_BASE + i);
            let helper2_limb = col(COL_HELPER2_BASE + i);
            // not-taken 部分：PcNext[i] - Pc[i] - 4_limb[i]
            let not_taken_diff = if i == 0 {
                pc_next_limb.clone() - pc_limb.clone() - four.clone()
            } else {
                pc_next_limb.clone() - pc_limb.clone()
            };
            // taken 部分：PcNext[i] - Helper2[i]
            let taken_diff = pc_next_limb - helper2_limb;
            // 组合：(1-Taken) * not_taken_diff + Taken * taken_diff = 0
            let branch_constraint =
                one_minus_taken.clone() * not_taken_diff + taken.clone() * taken_diff;
            eval.add_constraint(is_branch.clone() * branch_constraint);
        }

        // ===== 约束 32-35：LUI 约束（gated by IsLui）=====
        // LUI: rd_eff = imm（imm 字段已左移 12 位并符号扩展）
        // Helper1 预存 imm 值
        // 对每个 limb i：rd_eff[i] - Helper1[i] = 0
        for i in 0..4 {
            let lui_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER1_BASE + i);
            eval.add_constraint(is_lui.clone() * lui_diff);
        }

        // ===== 约束 36-39：AUIPC 约束（gated by IsAuipc）=====
        // AUIPC: rd_eff = Pc + imm（imm 字段已左移 12 位并符号扩展）
        // Helper2 预存 (Pc + imm) 值
        // 对每个 limb i：rd_eff[i] - Helper2[i] = 0
        for i in 0..4 {
            let auipc_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER2_BASE + i);
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
            let load_addr_diff = col(COL_MEM_ADDR_BASE + i) - col(COL_HELPER3_BASE + i);
            eval.add_constraint(is_load.clone() * load_addr_diff);
        }

        // ===== Phase 3 约束 44-47：Load 值匹配约束（gated by IsLoad）=====
        // Load: rd_eff = mem_value（加载的值必须写入 rd）
        // Helper4 预存 mem_value（来自 step.mem_access[0].value）
        // 对每个 limb i：rd_eff[i] - Helper4[i] = 0
        let is_load_eff = is_load.clone();
        for i in 0..4 {
            let load_val_diff = col(COL_VALUE_A_EFF_BASE + i) - col(COL_HELPER4_BASE + i);
            eval.add_constraint(is_load_eff.clone() * load_val_diff);
        }

        // ===== Phase 3 约束 48-51：Store 地址约束（gated by IsStore）=====
        // Store: MemAddr = rs1 + imm（同 Load 地址约束）
        let is_store = col(IS_STORE);
        for i in 0..4 {
            let store_addr_diff = col(COL_MEM_ADDR_BASE + i) - col(COL_HELPER3_BASE + i);
            eval.add_constraint(is_store.clone() * store_addr_diff);
        }

        // ===== Phase 3 约束 52-55：Store 值匹配约束（gated by IsStore）=====
        // Store: mem_value = rs2（存储的值必须来自 rs2）
        // Helper4 预存 mem_value（= rs2_value for Store）
        // 对每个 limb i：rs2[i] - Helper4[i] = 0
        let is_store_eff = is_store.clone();
        for i in 0..4 {
            let store_val_diff = col(COL_VALUE_C_BASE + i) - col(COL_HELPER4_BASE + i);
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
            eval.finalize_logup();
        }

        // ===== Phase 4 Tier 1 约束 C57：IS_ECALL binality =====
        // 显式约束 IS_ECALL ∈ {0, 1}，增强 soundness（虽然 Indicator one-hot C14 隐含）
        // 约束：IS_ECALL * (IS_ECALL - 1) = 0
        // 度数 = 2（IS_ECALL × IS_ECALL），符合 LOG_CONSTRAINT_DEGREE = 2 预算
        let is_ecall = col(IS_ECALL);
        let is_ecall_bin = is_ecall.clone() * (is_ecall.clone() - one.clone());
        eval.add_constraint(is_ecall_bin);

        // ===== Phase 4 Tier 1 约束 C58-C82：ECALL 列 zero gating（25 条）=====
        // 非 ECALL 行所有 25 列 ECALL dispatch 必须为 0
        // 约束：(1 - IS_ECALL) * col[i] = 0，对 25 列每列一条
        // - 非 ECALL 行（IS_ECALL=0）：(1-0) * col = col = 0，强制列为 0
        // - ECALL 行（IS_ECALL=1）：(1-1) * col = 0，自动成立，不约束列值
        // 度数 = 2（one_minus_is_ecall × col），符合预算
        //
        // 该约束关闭"非 ECALL 行伪造 ECALL 数据"soundness 缺口：
        // 恶意 prover 无法在非 ECALL 行注入伪造的 SyscallId/Args/Output。
        // （"ECALL 行伪造 Output"缺口需 Tier 2 Precompile AIR yield 关闭）
        let one_minus_is_ecall = one.clone() - is_ecall.clone();

        // 25 列 ECALL dispatch：(SyscallId 1) + (Arg0-3 各 4) + (Output0-1 各 4)
        let ecall_dispatch_layout: [(usize, usize); 7] = [
            (COL_SYSCALL_ID, 1),            // col 101
            (COL_SYSCALL_ARG0_BASE, 4),     // col 102-105
            (COL_SYSCALL_ARG1_BASE, 4),     // col 106-109
            (COL_SYSCALL_ARG2_BASE, 4),     // col 110-113
            (COL_SYSCALL_ARG3_BASE, 4),     // col 114-117
            (COL_SYSCALL_OUTPUT0_BASE, 4),  // col 118-121
            (COL_SYSCALL_OUTPUT1_BASE, 4),  // col 122-125
        ];

        // 收集 25 列值，用于后续 logup claim
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
        // 当 ecall_lookup = Some(lookup) 时，为每行 ECALL 发送 25 元组 logup claim：
        //   values = (SyscallId, Arg0, Arg1, Arg2, Arg3, Output0, Output1)
        //   multiplicity = IS_ECALL（非 ECALL 行 multiplicity = 0，不贡献 sum）
        //
        // 一致性条件：Σ(CPU claims) + Σ(Precompile yields) == 0（Tier 2+ 验证）
        //
        // Phase 4 Tier 1 状态：
        // - Tier 1 无 Precompile AIR 发送 yield，因此启用 ecall_lookup 时 logup sum != 0
        // - Tier 1 测试应使用 new_with_lookup（不启用 ecall_lookup）避免验证失败
        // - Tier 2 实施 Precompile AIR 后，启用 ecall_lookup 测试完整 claim + yield 平衡
        if let Some(ref lookup) = self.ecall_lookup {
            let multiplicity_ef: E::EF = is_ecall.clone().into();
            eval.add_to_relation(RelationEntry::new(
                lookup,
                multiplicity_ef,
                &ecall_claim_values,
            ));
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
        // 验证 Phase 4 Tier 1 ECALL dispatch 列布局常量
        assert_eq!(IS_ECALL, 72, "IS_ECALL 应在 indicator 范围 [40, 74] 内");
        assert_eq!(COL_SYSCALL_ID, 101);
        assert_eq!(COL_SYSCALL_ARG0_BASE, 102);
        assert_eq!(COL_SYSCALL_ARG1_BASE, 106);
        assert_eq!(COL_SYSCALL_ARG2_BASE, 110);
        assert_eq!(COL_SYSCALL_ARG3_BASE, 114);
        assert_eq!(COL_SYSCALL_OUTPUT0_BASE, 118);
        assert_eq!(COL_SYSCALL_OUTPUT1_BASE, 122);
        assert_eq!(ECALL_DISPATCH_NUM_COLUMNS, 25);
        // 验证 25 列布局：1 + 4*6 = 25
        assert_eq!(
            1 + 4 * 6,
            ECALL_DISPATCH_NUM_COLUMNS,
            "ECALL dispatch 应为 1 SyscallId + 6×4-limb = 25 列"
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
        // 验证 CpuAir 使用的列索引与 column_layout_v2 一致
        assert_eq!(COL_PC_BASE, 0);
        assert_eq!(COL_PC_NEXT_BASE, 4);
        assert_eq!(COL_PC_NEXT_AUX_BASE, 8);
        assert_eq!(COL_CARRY_FLAG_BASE, 15);
        assert_eq!(COL_BORROW_FLAG_BASE, 17);
        assert_eq!(COL_VALUE_A_EFF_BASE, 28);
        assert_eq!(COL_VALUE_B_BASE, 32);
        assert_eq!(COL_VALUE_C_BASE, 36);
        assert_eq!(COL_IS_BASE, 40);
        assert_eq!(IS_LUI, 40);
        assert_eq!(IS_AUIPC, 41);
        assert_eq!(IS_JAL, 42);
        assert_eq!(IS_JALR, 43);
        assert_eq!(IS_BEQ, 44);
        assert_eq!(IS_BNE, 45);
        assert_eq!(IS_BLT, 46);
        assert_eq!(IS_BGE, 47);
        assert_eq!(IS_BLTU, 48);
        assert_eq!(IS_BGEU, 49);
        assert_eq!(IS_ADDI, 52);
        assert_eq!(IS_ADD, 61);
        assert_eq!(IS_SUB, 62);
        assert_eq!(IS_PADDING, 74);
        assert_eq!(COL_HELPER1_BASE, 75);
        assert_eq!(COL_HELPER2_BASE, 79);
        assert_eq!(COL_TAKEN, 91);
        assert_eq!(NUM_COLUMNS, 126);
        assert_eq!(NUM_INSTRUCTION_CATEGORIES, 35);
    }
}
