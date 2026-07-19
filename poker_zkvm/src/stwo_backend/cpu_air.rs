//! # CPU AIR — Stwo FrameworkEval 实现（Phase 2）
//!
//! 严格遵循 `.trae/documents/stwo_phase2_cpu_air_design.md`：
//! - 基于 Stwo 原生 `FrameworkEval` + `EvalAtRow` + `add_constraint`
//! - 4×8-bit limb 方案，16-bit 边界 carry/borrow
//! - Phase 2.4 实现 ADD/ADDI/SUB 约束 + 通用 binality/one-hot 约束
//!
//! ## 约束清单（Phase 2.4）
//!
//! | # | 约束 | 度 | gating | 说明 |
//! |---|------|----|--------|------|
//! | 1 | ADD low-16 limb | 2 | IsAdd | ValueAEff[0..2] = ValueB[0..2] + ValueC[0..2] - 65536·carry0 |
//! | 2 | ADD high-16 limb | 2 | IsAdd | ValueAEff[2..4] = ValueB[2..4] + ValueC[2..4] + carry0 - 65536·carry1 |
//! | 3 | ADD carry0 binality | 3 | IsAdd | carry0·(carry0−1) = 0 |
//! | 4 | ADD carry1 binality | 3 | IsAdd | carry1·(carry1−1) = 0 |
//! | 5-8 | ADDI 同 ADD | — | IsAddi | ImmC=1 时 ValueC 为立即数 |
//! | 9 | SUB low-16 limb | 2 | IsSub | ValueAEff[0..2] = ValueB[0..2] − ValueC[0..2] + 65536·borrow0 |
//! | 10 | SUB high-16 limb | 2 | IsSub | ValueAEff[2..4] = ValueB[2..4] − ValueC[2..4] − borrow0 + 65536·borrow1 |
//! | 11 | SUB borrow0 binality | 3 | IsSub | borrow0·(borrow0−1) = 0 |
//! | 12 | SUB borrow1 binality | 3 | IsSub | borrow1·(borrow1−1) = 0 |
//! | 13 | IsPadding binality | 2 | 通用 | IsPadding·(IsPadding−1) = 0 |
//! | 14 | Indicator one-hot | 1 | 通用 | Σ Is_i = 1 |
//!
//! 所有约束的最大总度 = 3（gating × binality），因此
//! `max_constraint_log_degree_bound = log_size + 1`（参见 stwo-book 度数表）。

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use super::column_layout_v2::{
    COL_BORROW_FLAG_BASE, COL_CARRY_FLAG_BASE, COL_IMM_C, COL_IS_BASE, COL_OP_A, COL_OP_B,
    COL_OP_C, COL_PC_BASE, COL_PC_NEXT_BASE, COL_PC_NEXT_AUX_BASE, COL_VALUE_A_BASE,
    COL_VALUE_A_EFF_BASE, COL_VALUE_B_BASE, COL_VALUE_C_BASE, IS_ADD, IS_ADDI, IS_PADDING,
    IS_SUB, NUM_COLUMNS, NUM_INSTRUCTION_CATEGORIES, WORD_LIMB_COUNT,
};

/// 65536 = 2^16，16-bit 边界进位/借位的基数。
const SIX5536: BaseField = BaseField::from_u32_unchecked(65536);

/// 256 = 2^8，byte 边界的基数。
const TWO56: BaseField = BaseField::from_u32_unchecked(256);

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
///     SecureField::zero(),
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

        // ----- 读取全部 97 列（顺序与 column_layout_v2 一致）-----
        let mut cols: Vec<E::F> = Vec::with_capacity(NUM_COLUMNS);
        for _ in 0..NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }

        // 辅助闭包：按列索引取值
        let col = |idx: usize| -> E::F { cols[idx].clone() };
        // 辅助闭包：读取 4×8-bit limb word 的低 16 位组合值
        // word_low16 = limb[0] + 256 * limb[1]
        let word_low16 = |base: usize| -> E::F {
            col(base) + col(base + 1) * two56.clone()
        };
        // 辅助闭包：读取 4×8-bit limb word 的高 16 位组合值
        // word_high16 = limb[2] + 256 * limb[3]
        let word_high16 = |base: usize| -> E::F {
            col(base + 2) + col(base + 3) * two56.clone()
        };

        // ----- 读取 indicator 列 -----
        let is_add = col(IS_ADD);
        let is_addi = col(IS_ADDI);
        let is_sub = col(IS_SUB);
        let is_padding = col(IS_PADDING);

        // ----- 读取 carry/borrow 标志 -----
        let carry0 = col(COL_CARRY_FLAG_BASE);
        let carry1 = col(COL_CARRY_FLAG_BASE + 1);
        let borrow0 = col(COL_BORROW_FLAG_BASE);
        let borrow1 = col(COL_BORROW_FLAG_BASE + 1);

        // ----- 读取操作数值 -----
        let rd_eff_low = word_low16(COL_VALUE_A_EFF_BASE);
        let rd_eff_high = word_high16(COL_VALUE_A_EFF_BASE);
        let rs1_low = word_low16(COL_VALUE_B_BASE);
        let rs1_high = word_high16(COL_VALUE_B_BASE);
        let rs2_low = word_low16(COL_VALUE_C_BASE);
        let rs2_high = word_high16(COL_VALUE_C_BASE);

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
        eval.add_constraint(indicator_sum - one);

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
        // M31 最大值 = 2^31 - 2 > 65536，无溢出
        assert!(M31::from(65536u32).0 < (1u32 << 31) - 1);
    }

    #[test]
    fn test_column_layout_consistency() {
        // 验证 CpuAir 使用的列索引与 column_layout_v2 一致
        assert_eq!(COL_PC_BASE, 0);
        assert_eq!(COL_PC_NEXT_BASE, 4);
        assert_eq!(COL_PC_NEXT_AUX_BASE, 8);
        assert_eq!(COL_OP_A, 12);
        assert_eq!(COL_OP_B, 13);
        assert_eq!(COL_OP_C, 14);
        assert_eq!(COL_CARRY_FLAG_BASE, 15);
        assert_eq!(COL_BORROW_FLAG_BASE, 17);
        assert_eq!(COL_IMM_C, 19);
        assert_eq!(COL_VALUE_A_BASE, 24);
        assert_eq!(COL_VALUE_A_EFF_BASE, 28);
        assert_eq!(COL_VALUE_B_BASE, 32);
        assert_eq!(COL_VALUE_C_BASE, 36);
        assert_eq!(COL_IS_BASE, 40);
        assert_eq!(IS_ADD, 61);
        assert_eq!(IS_ADDI, 52);
        assert_eq!(IS_SUB, 62);
        assert_eq!(IS_PADDING, 74);
        assert_eq!(NUM_COLUMNS, 97);
        assert_eq!(NUM_INSTRUCTION_CATEGORIES, 35);
        assert_eq!(WORD_LIMB_COUNT, 4);
    }
}
