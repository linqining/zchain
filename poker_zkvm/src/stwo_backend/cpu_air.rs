//! # CPU AIR — Stwo FrameworkEval 实现（Phase 2 + 2.7）
//!
//! 严格遵循 `.trae/documents/stwo_phase2_cpu_air_design.md`：
//! - 基于 Stwo 原生 `FrameworkEval` + `EvalAtRow` + `add_constraint`
//! - 4×8-bit limb 方案，16-bit 边界 carry/borrow
//! - Phase 2.4：ADD/ADDI/SUB 约束 + 通用 binality/one-hot 约束
//! - Phase 2.7：PC 递增 + JAL/JALR/Branch + LUI/AUIPC 约束
//!
//! ## 约束清单（Phase 2.7）
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
//!
//! 所有约束的最大总度 = 3（gating × binality），因此
//! `max_constraint_log_degree_bound = log_size + 1`（参见 stwo-book 度数表）。

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use super::column_layout_v2::{
    COL_BORROW_FLAG_BASE, COL_CARRY_FLAG_BASE, COL_HELPER1_BASE, COL_HELPER2_BASE, COL_IS_BASE,
    COL_PC_BASE, COL_PC_NEXT_AUX_BASE, COL_PC_NEXT_BASE, COL_TAKEN, COL_VALUE_A_EFF_BASE,
    COL_VALUE_B_BASE, COL_VALUE_C_BASE, IS_ADD, IS_ADDI, IS_AUIPC, IS_BEQ, IS_BGE, IS_BGEU,
    IS_BLT, IS_BLTU, IS_BNE, IS_JAL, IS_JALR, IS_LUI, IS_PADDING, IS_SUB, NUM_COLUMNS,
    NUM_INSTRUCTION_CATEGORIES,
};

/// 65536 = 2^16，16-bit 边界进位/借位的基数。
const SIX5536: BaseField = BaseField::from_u32_unchecked(65536);

/// 256 = 2^8，byte 边界的基数。
const TWO56: BaseField = BaseField::from_u32_unchecked(256);

/// 常量 4（PcNext = Pc + 4 中的立即数偏移）。
const FOUR: BaseField = BaseField::from_u32_unchecked(4);

/// CPU AIR 组件 — 封装 97 列 trace 的 FrameworkEval 实现。
///
/// # 结构
/// - `log_size` — log2(trace 行数)，行数 = 2^log_size
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::cpu_air::CpuAir;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = CpuAir::new(log_size);
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CpuAir {
    /// log2(trace 行数)
    log_size: u32,
}

impl CpuAir {
    /// 创建指定 log_size 的 CPU AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须 ≥ 10（Stwo SIMD 对齐要求）
    #[must_use]
    pub const fn new(log_size: u32) -> Self {
        Self { log_size }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
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
        assert_eq!(NUM_COLUMNS, 97);
        assert_eq!(NUM_INSTRUCTION_CATEGORIES, 35);
    }
}
