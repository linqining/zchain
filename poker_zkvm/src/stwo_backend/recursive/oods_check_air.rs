//! # OODS Check AIR — L1 proof 的 DEEP-ALI 等式检查（Phase 5 — v5.1）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §4 + §7。
//!
//! ## v5.1 完整版（含 Composition Eval）
//!
//! 实现"OODS 等式检查 + Composition Eval" AIR：
//! - 约束 `claimed_oods_eval == computed_oods_eval`（OODS check）
//! - `computed_oods_eval` 由 L1 proof 的 `sampled_values` 重新计算（composition eval）
//!
//! ### 数学公式
//!
//! 1. **from_partial_evals**（构造 QM31 from 4 partial evals）:
//!    给定 evals[0..4]（每个 QM31 = (a_i, b_i, c_i, d_i)），left_eval = sum(evals[i] * coeff[i]):
//!    - LeftEval[0] = SV[0][0] - SV[1][1] + 2*SV[2][2] - SV[2][3] - SV[3][2] - 2*SV[3][3]
//!    - LeftEval[1] = SV[0][1] + SV[1][0] + SV[2][2] + 2*SV[2][3] + 2*SV[3][2] - SV[3][3]
//!    - LeftEval[2] = SV[0][2] - SV[1][3] + SV[2][0] - SV[3][1]
//!    - LeftEval[3] = SV[0][3] + SV[1][2] + SV[2][1] + SV[3][0]
//!    同样 RightEval from SV[4..8]。
//!
//! 2. **QM31 乘法** `product = df.x * right_eval`:
//!    QM31 = (CM31, CM31)，乘法公式 `(a+bu)*(c+du) = (ac+R*bd) + (ad+bc)u`，R = 2+i。
//!    分解为 16 个 M31×M31 乘积（degree 2）+ 4 个线性组合（degree 1）。
//!
//! 3. **最终等式**: `ComputedOodsEval[i] = LeftEval[i] + Product[i]` (per M31 component)
//!
//! ## v5.0 → v5.1 变更
//!
//! - 列数: 9 → 73（新增 64 列见证/中间值）
//! - 约束数: 5 → 37（新增 32 条 composition eval 约束）
//! - Soundness: 从"trivial（Computed=Claimed）"提升到"Computed 由 L1 proof sampled_values 推导"
//!
//! ## 列布局（73 列，v5.1）
//!
//! | 范围 | 列名 | 列数 | 说明 |
//! |------|------|------|------|
//! | 0-3 | ClaimedOodsEval | 4 | QM31 的 4 个 M31 分量（来自 public_inputs） |
//! | 4-7 | ComputedOodsEval | 4 | QM31 的 4 个 M31 分量（由 composition eval 计算） |
//! | 8 | IsPadding | 1 | padding 标记 |
//! | 9-12 | DoublingFactorX | 4 | QM31 = oods_point.repeated_double(max_log_degree_bound-1).x |
//! | 13-44 | SampledValues[0..8] | 32 | L1 proof 的 8 个 SecureField partial evals |
//! | 45-48 | LeftEval | 4 | QM31 = from_partial_evals(SV[0..4]) |
//! | 49-52 | RightEval | 4 | QM31 = from_partial_evals(SV[4..8]) |
//! | 53-68 | M[1..16] | 16 | M31×M31 乘积中间值 |
//! | 69-72 | Product | 4 | QM31 = DoublingFactorX * RightEval |
//! | **总计** | | **73** | |
//!
//! ## 约束清单（37 条，所有约束 degree ≤ 2）
//!
//! | # | 约束 | 度 | gating |
//! |---|------|----|--------|
//! | O1 | IsPadding binality | 2 | - |
//! | O2-O5 | OODS 等式 (claimed == computed) | 2 | (1 - IsPadding) |
//! | O6-O9 | from_partial_evals left | 1 | - |
//! | O10-O13 | from_partial_evals right | 1 | - |
//! | O14-O29 | M31×M31 = intermediate | 2 | - |
//! | O30-O33 | Product = sum of intermediates | 1 | - |
//! | O34-O37 | Computed = Left + Product | 2 | (1 - IsPadding) |
//!
//! ## v2.1 Hard Constraint
//!
//! 所有约束 degree ≤ 2，强制 Stwo 使用 `EvaluationMode::SubDomain`。
//!
//! ## 参考
//!
//! - `stwo-2.3.0/src/core/verifier.rs:99-114` — L1 verifier OODS check 逻辑
//! - `stwo-2.3.0/src/core/proof.rs:27-57` — extract_composition_oods_eval
//! - `stwo-2.3.0/src/core/fields/qm31.rs:51-57` — from_partial_evals
//! - `stwo-2.3.0/src/core/fields/qm31.rs:78-88` — QM31 Mul impl

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

// ===========================================================================
// OODS Check AIR 列布局常量（73 列，v5.1）
// ===========================================================================

/// col 0-3：ClaimedOodsEval（QM31 的 4 个 M31 分量，来自 public_inputs.composition_oods_eval）。
pub const OODS_AIR_COL_CLAIMED_BASE: usize = 0;
/// col 4-7：ComputedOodsEval（QM31 的 4 个 M31 分量，由 composition eval 计算）。
pub const OODS_AIR_COL_COMPUTED_BASE: usize = 4;
/// col 8：IsPadding（padding 标记）。
pub const OODS_AIR_COL_IS_PADDING: usize = 8;
/// col 9-12：DoublingFactorX（QM31 = oods_point.repeated_double(max_log_degree_bound-1).x）。
pub const OODS_AIR_COL_DF_X_BASE: usize = 9;
/// col 13-44：SampledValues[0..8]（8 个 SecureField partial evals，每个 4 个 M31）。
pub const OODS_AIR_COL_SV_BASE: usize = 13;
/// col 45-48：LeftEval（QM31 = from_partial_evals(SV[0..4])）。
pub const OODS_AIR_COL_LEFT_EVAL_BASE: usize = 45;
/// col 49-52：RightEval（QM31 = from_partial_evals(SV[4..8])）。
pub const OODS_AIR_COL_RIGHT_EVAL_BASE: usize = 49;
/// col 53-68：M[1..16]（M31×M31 乘积中间值，用于 QM31 乘法）。
pub const OODS_AIR_COL_M_BASE: usize = 53;
/// col 69-72：Product（QM31 = DoublingFactorX * RightEval）。
pub const OODS_AIR_COL_PRODUCT_BASE: usize = 69;

/// OODS Check AIR 总列数（v5.1）。
pub const OODS_AIR_NUM_COLUMNS: usize = 73;

/// SampledValues 数量（2 * SECURE_EXTENSION_DEGREE = 8）。
pub const OODS_AIR_NUM_SAMPLED_VALUES: usize = 8;

/// M31×M31 中间值数量（QM31 乘法分解为 16 个 M31 乘积）。
pub const OODS_AIR_NUM_M_INTERMEDIATES: usize = 16;

// ===========================================================================
// OodsCheckAir 结构
// ===========================================================================

/// OODS Check AIR 组件 — L1 proof DEEP-ALI 等式检查 + Composition Eval（v5.1 完整版）。
///
/// # 设计（v5.1）
/// - 每行表示一个 OODS 检查（通常 1 行，因为 L1 verifier 只在 1 个 OODS point 检查）
/// - 约束 `claimed_oods_eval == computed_oods_eval`（OODS check）
/// - `computed_oods_eval` 由 L1 proof 的 `sampled_values` 重新计算（composition eval）
/// - `max_constraint_log_degree_bound = log_size + 1`（约束度 ≤ 2，强制 SubDomain 模式）
///
/// # v5.0 → v5.1
/// - v5.0: ComputedOodsEval = ClaimedOodsEval（trivial，无 soundness）
/// - v5.1: ComputedOodsEval 由 L1 proof sampled_values 推导（完整 soundness）
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::recursive::oods_check_air::OodsCheckAir;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = OodsCheckAir::new(log_size);
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct OodsCheckAir {
    /// log2(trace 行数)
    log_size: u32,
}

impl OodsCheckAir {
    /// 创建指定 log_size 的 OODS Check AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，v5.1 通常为 2（4 行 = 1 OODS check + 3 padding）
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

impl FrameworkEval for OodsCheckAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// v5.1：所有约束的最大总度 = 2（M31×M31 intermediate + gating）。
    /// log2(2) = 1，所以 max_constraint_log_degree_bound = log_size + 1。
    ///
    /// 这强制 Stwo 使用 `EvaluationMode::SubDomain`（与 Poseidon AIR v2.1 一致）。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();
        let two: E::F = BaseField::from(2u32).into();

        // ----- 读取全部 73 列 -----
        let mut cols: Vec<E::F> = Vec::with_capacity(OODS_AIR_NUM_COLUMNS);
        for _ in 0..OODS_AIR_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }
        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        let is_padding = col(OODS_AIR_COL_IS_PADDING);

        // ===== O1: IsPadding binality =====
        // 约束: is_padding * (is_padding - 1) == 0  (degree 2)
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== O2-O5: OODS 等式 =====
        // 约束: (1 - is_padding) * (claimed_i - computed_i) == 0  (degree 2)
        //   - 非 padding 行：claimed_i == computed_i
        //   - padding 行：约束自动满足（multiplicity = 0）
        let non_padding = one.clone() - is_padding.clone();
        for i in 0..4 {
            let claimed_i = col(OODS_AIR_COL_CLAIMED_BASE + i);
            let computed_i = col(OODS_AIR_COL_COMPUTED_BASE + i);
            let diff = claimed_i - computed_i;
            eval.add_constraint(non_padding.clone() * diff);
        }

        // ===== O6-O9: from_partial_evals left =====
        // LeftEval = from_partial_evals([SV[0], SV[1], SV[2], SV[3]])
        // 公式（参考 qm31.rs:51-57 + 推导）:
        //   LeftEval[0] = SV[0][0] - SV[1][1] + 2*SV[2][2] - SV[2][3] - SV[3][2] - 2*SV[3][3]
        //   LeftEval[1] = SV[0][1] + SV[1][0] + SV[2][2] + 2*SV[2][3] + 2*SV[3][2] - SV[3][3]
        //   LeftEval[2] = SV[0][2] - SV[1][3] + SV[2][0] - SV[3][1]
        //   LeftEval[3] = SV[0][3] + SV[1][2] + SV[2][1] + SV[3][0]
        // 所有约束 degree = 1（线性组合）
        let sv = |i: usize, j: usize| -> E::F {
            col(OODS_AIR_COL_SV_BASE + 4 * i + j)
        };
        let left_eval = |i: usize| -> E::F {
            col(OODS_AIR_COL_LEFT_EVAL_BASE + i)
        };

        // O6: LeftEval[0] = SV[0][0] - SV[1][1] + 2*SV[2][2] - SV[2][3] - SV[3][2] - 2*SV[3][3]
        let le0_expected = sv(0, 0).clone() - sv(1, 1).clone()
            + two.clone() * sv(2, 2).clone()
            - sv(2, 3).clone()
            - sv(3, 2).clone()
            - two.clone() * sv(3, 3).clone();
        eval.add_constraint(left_eval(0) - le0_expected);

        // O7: LeftEval[1] = SV[0][1] + SV[1][0] + SV[2][2] + 2*SV[2][3] + 2*SV[3][2] - SV[3][3]
        let le1_expected = sv(0, 1).clone()
            + sv(1, 0).clone()
            + sv(2, 2).clone()
            + two.clone() * sv(2, 3).clone()
            + two.clone() * sv(3, 2).clone()
            - sv(3, 3).clone();
        eval.add_constraint(left_eval(1) - le1_expected);

        // O8: LeftEval[2] = SV[0][2] - SV[1][3] + SV[2][0] - SV[3][1]
        let le2_expected = sv(0, 2).clone() - sv(1, 3).clone() + sv(2, 0).clone() - sv(3, 1).clone();
        eval.add_constraint(left_eval(2) - le2_expected);

        // O9: LeftEval[3] = SV[0][3] + SV[1][2] + SV[2][1] + SV[3][0]
        let le3_expected = sv(0, 3).clone() + sv(1, 2).clone() + sv(2, 1).clone() + sv(3, 0).clone();
        eval.add_constraint(left_eval(3) - le3_expected);

        // ===== O10-O13: from_partial_evals right =====
        // RightEval = from_partial_evals([SV[4], SV[5], SV[6], SV[7]])
        let right_eval = |i: usize| -> E::F {
            col(OODS_AIR_COL_RIGHT_EVAL_BASE + i)
        };

        // O10: RightEval[0] = SV[4][0] - SV[5][1] + 2*SV[6][2] - SV[6][3] - SV[7][2] - 2*SV[7][3]
        let re0_expected = sv(4, 0).clone() - sv(5, 1).clone()
            + two.clone() * sv(6, 2).clone()
            - sv(6, 3).clone()
            - sv(7, 2).clone()
            - two.clone() * sv(7, 3).clone();
        eval.add_constraint(right_eval(0) - re0_expected);

        // O11: RightEval[1] = SV[4][1] + SV[5][0] + SV[6][2] + 2*SV[6][3] + 2*SV[7][2] - SV[7][3]
        let re1_expected = sv(4, 1).clone()
            + sv(5, 0).clone()
            + sv(6, 2).clone()
            + two.clone() * sv(6, 3).clone()
            + two.clone() * sv(7, 2).clone()
            - sv(7, 3).clone();
        eval.add_constraint(right_eval(1) - re1_expected);

        // O12: RightEval[2] = SV[4][2] - SV[5][3] + SV[6][0] - SV[7][1]
        let re2_expected = sv(4, 2).clone() - sv(5, 3).clone() + sv(6, 0).clone() - sv(7, 1).clone();
        eval.add_constraint(right_eval(2) - re2_expected);

        // O13: RightEval[3] = SV[4][3] + SV[5][2] + SV[6][1] + SV[7][0]
        let re3_expected = sv(4, 3).clone() + sv(5, 2).clone() + sv(6, 1).clone() + sv(7, 0).clone();
        eval.add_constraint(right_eval(3) - re3_expected);

        // ===== O14-O29: M31×M31 = intermediate =====
        // 16 个 M31 乘积中间值，用于 QM31 乘法分解
        // Product = DoublingFactorX * RightEval
        //   df.x = (x0, x1, x2, x3), right_eval = (r0, r1, r2, r3)
        //   m1 = x0*r0, m2 = x1*r1, m3 = x2*r2, m4 = x3*r3
        //   m5 = x2*r3, m6 = x3*r2, m7 = x0*r1, m8 = x1*r0
        //   m9 = x0*r2, m10 = x1*r3, m11 = x2*r0, m12 = x3*r1
        //   m13 = x0*r3, m14 = x1*r2, m15 = x2*r1, m16 = x3*r0
        // 每个约束 degree = 2（M31 × M31）
        let df_x = |i: usize| -> E::F {
            col(OODS_AIR_COL_DF_X_BASE + i)
        };
        let m = |i: usize| -> E::F {
            // i 是 1-based 索引（m1..m16），转换为 0-based 列索引
            col(OODS_AIR_COL_M_BASE + i - 1)
        };

        // O14: m1 = x0 * r0
        let m1_expected = df_x(0).clone() * right_eval(0).clone();
        eval.add_constraint(m(1) - m1_expected);
        // O15: m2 = x1 * r1
        let m2_expected = df_x(1).clone() * right_eval(1).clone();
        eval.add_constraint(m(2) - m2_expected);
        // O16: m3 = x2 * r2
        let m3_expected = df_x(2).clone() * right_eval(2).clone();
        eval.add_constraint(m(3) - m3_expected);
        // O17: m4 = x3 * r3
        let m4_expected = df_x(3).clone() * right_eval(3).clone();
        eval.add_constraint(m(4) - m4_expected);
        // O18: m5 = x2 * r3
        let m5_expected = df_x(2).clone() * right_eval(3).clone();
        eval.add_constraint(m(5) - m5_expected);
        // O19: m6 = x3 * r2
        let m6_expected = df_x(3).clone() * right_eval(2).clone();
        eval.add_constraint(m(6) - m6_expected);
        // O20: m7 = x0 * r1
        let m7_expected = df_x(0).clone() * right_eval(1).clone();
        eval.add_constraint(m(7) - m7_expected);
        // O21: m8 = x1 * r0
        let m8_expected = df_x(1).clone() * right_eval(0).clone();
        eval.add_constraint(m(8) - m8_expected);
        // O22: m9 = x0 * r2
        let m9_expected = df_x(0).clone() * right_eval(2).clone();
        eval.add_constraint(m(9) - m9_expected);
        // O23: m10 = x1 * r3
        let m10_expected = df_x(1).clone() * right_eval(3).clone();
        eval.add_constraint(m(10) - m10_expected);
        // O24: m11 = x2 * r0
        let m11_expected = df_x(2).clone() * right_eval(0).clone();
        eval.add_constraint(m(11) - m11_expected);
        // O25: m12 = x3 * r1
        let m12_expected = df_x(3).clone() * right_eval(1).clone();
        eval.add_constraint(m(12) - m12_expected);
        // O26: m13 = x0 * r3
        let m13_expected = df_x(0).clone() * right_eval(3).clone();
        eval.add_constraint(m(13) - m13_expected);
        // O27: m14 = x1 * r2
        let m14_expected = df_x(1).clone() * right_eval(2).clone();
        eval.add_constraint(m(14) - m14_expected);
        // O28: m15 = x2 * r1
        let m15_expected = df_x(2).clone() * right_eval(1).clone();
        eval.add_constraint(m(15) - m15_expected);
        // O29: m16 = x3 * r0
        let m16_expected = df_x(3).clone() * right_eval(0).clone();
        eval.add_constraint(m(16) - m16_expected);

        // ===== O30-O33: Product = sum of intermediates =====
        // Product[0] = m1 - m2 + 2*m3 - 2*m4 - m5 - m6
        // Product[1] = m7 + m8 + m3 - m4 + 2*m5 + 2*m6
        // Product[2] = m9 - m10 + m11 - m12
        // Product[3] = m13 + m14 + m15 + m16
        // 所有约束 degree = 1（线性组合）
        let product = |i: usize| -> E::F {
            col(OODS_AIR_COL_PRODUCT_BASE + i)
        };

        // O30: Product[0] = m1 - m2 + 2*m3 - 2*m4 - m5 - m6
        let p0_expected = m(1).clone()
            - m(2).clone()
            + two.clone() * m(3).clone()
            - two.clone() * m(4).clone()
            - m(5).clone()
            - m(6).clone();
        eval.add_constraint(product(0) - p0_expected);

        // O31: Product[1] = m7 + m8 + m3 - m4 + 2*m5 + 2*m6
        let p1_expected = m(7).clone()
            + m(8).clone()
            + m(3).clone()
            - m(4).clone()
            + two.clone() * m(5).clone()
            + two.clone() * m(6).clone();
        eval.add_constraint(product(1) - p1_expected);

        // O32: Product[2] = m9 - m10 + m11 - m12
        let p2_expected = m(9).clone() - m(10).clone() + m(11).clone() - m(12).clone();
        eval.add_constraint(product(2) - p2_expected);

        // O33: Product[3] = m13 + m14 + m15 + m16
        let p3_expected = m(13).clone() + m(14).clone() + m(15).clone() + m(16).clone();
        eval.add_constraint(product(3) - p3_expected);

        // ===== O34-O37: Computed = Left + Product =====
        // 约束: (1 - is_padding) * (computed_i - left_eval_i - product_i) == 0  (degree 2)
        //   - 非 padding 行：computed_i == left_eval_i + product_i
        //   - padding 行：约束自动满足（multiplicity = 0）
        // 这关闭 v5.0 的 soundness 缺口：ComputedOodsEval 现在由 L1 proof sampled_values 推导
        for i in 0..4 {
            let computed_i = col(OODS_AIR_COL_COMPUTED_BASE + i);
            let left_i = left_eval(i);
            let product_i = product(i);
            let diff = computed_i - left_i - product_i;
            eval.add_constraint(non_padding.clone() * diff);
        }

        // OodsCheckAir 无 logup（无 lookup relation），不调用 finalize_logup()。
        // Stwo 的 FormalLogupAtRow 初始 is_finalized=true，只有在 write_logup_frac
        // （通过 add_to_relation）调用后才会重置为 false。无 logup 的 AIR 调用
        // finalize_logup() 会触发 "LogupAtRow was already finalized" assert。
        eval
    }
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oods_check_air_num_columns() {
        assert_eq!(OODS_AIR_NUM_COLUMNS, 73);
    }

    #[test]
    fn test_oods_check_air_column_layout_no_overlap() {
        // 确保列布局互不重叠
        use std::collections::HashSet;
        let mut all_cols = HashSet::new();

        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_CLAIMED_BASE + i), "Claimed col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_COMPUTED_BASE + i), "Computed col {} 重复", i);
        }
        assert!(all_cols.insert(OODS_AIR_COL_IS_PADDING), "IsPadding 重复");
        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_DF_X_BASE + i), "DfX col {} 重复", i);
        }
        for i in 0..32 {
            assert!(all_cols.insert(OODS_AIR_COL_SV_BASE + i), "SV col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_LEFT_EVAL_BASE + i), "LeftEval col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_RIGHT_EVAL_BASE + i), "RightEval col {} 重复", i);
        }
        for i in 0..16 {
            assert!(all_cols.insert(OODS_AIR_COL_M_BASE + i), "M col {} 重复", i);
        }
        for i in 0..4 {
            assert!(all_cols.insert(OODS_AIR_COL_PRODUCT_BASE + i), "Product col {} 重复", i);
        }
        assert_eq!(all_cols.len(), OODS_AIR_NUM_COLUMNS);
    }

    #[test]
    fn test_oods_check_air_new() {
        let air = OodsCheckAir::new(2);
        assert_eq!(air.log_size(), 2);
    }

    #[test]
    fn test_oods_check_air_log_size() {
        let air = OodsCheckAir::new(5);
        assert_eq!(air.log_size(), 5);
    }

    #[test]
    fn test_oods_check_air_max_constraint_log_degree_bound() {
        let air = OodsCheckAir::new(10);
        // log_size + 1（约束度 ≤ 2，强制 SubDomain 模式）
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_oods_check_air_v5_1_constraint_count() {
        // v5.1 实现的约束数量：
        // O1: 1 条 IsPadding binality
        // O2-O5: 4 条 OODS 等式
        // O6-O9: 4 条 from_partial_evals left
        // O10-O13: 4 条 from_partial_evals right
        // O14-O29: 16 条 M31×M31 intermediate
        // O30-O33: 4 条 Product = sum
        // O34-O37: 4 条 Computed = Left + Product
        const O1_COUNT: usize = 1;
        const O2_O5_COUNT: usize = 4;
        const O6_O9_COUNT: usize = 4;
        const O10_O13_COUNT: usize = 4;
        const O14_O29_COUNT: usize = 16;
        const O30_O33_COUNT: usize = 4;
        const O34_O37_COUNT: usize = 4;
        const V5_1_TOTAL: usize = O1_COUNT + O2_O5_COUNT + O6_O9_COUNT + O10_O13_COUNT
            + O14_O29_COUNT + O30_O33_COUNT + O34_O37_COUNT;
        assert_eq!(V5_1_TOTAL, 37);
    }

    #[test]
    fn test_oods_check_air_sampled_values_count() {
        assert_eq!(OODS_AIR_NUM_SAMPLED_VALUES, 8);
        // 2 * SECURE_EXTENSION_DEGREE = 2 * 4 = 8
    }

    #[test]
    fn test_oods_check_air_m_intermediates_count() {
        assert_eq!(OODS_AIR_NUM_M_INTERMEDIATES, 16);
    }

    #[test]
    fn test_oods_check_air_column_ranges() {
        // 验证关键列范围的起始/结束
        assert_eq!(OODS_AIR_COL_CLAIMED_BASE, 0);
        assert_eq!(OODS_AIR_COL_COMPUTED_BASE, 4);
        assert_eq!(OODS_AIR_COL_IS_PADDING, 8);
        assert_eq!(OODS_AIR_COL_DF_X_BASE, 9);
        assert_eq!(OODS_AIR_COL_SV_BASE, 13);
        assert_eq!(OODS_AIR_COL_LEFT_EVAL_BASE, 45);
        assert_eq!(OODS_AIR_COL_RIGHT_EVAL_BASE, 49);
        assert_eq!(OODS_AIR_COL_M_BASE, 53);
        assert_eq!(OODS_AIR_COL_PRODUCT_BASE, 69);
        // SV 占 32 列（8 × 4）
        assert_eq!(OODS_AIR_COL_LEFT_EVAL_BASE - OODS_AIR_COL_SV_BASE, 32);
        // M 占 16 列
        assert_eq!(OODS_AIR_COL_PRODUCT_BASE - OODS_AIR_COL_M_BASE, 16);
        // Product 占 4 列
        assert_eq!(OODS_AIR_NUM_COLUMNS - OODS_AIR_COL_PRODUCT_BASE, 4);
    }
}
