//! # RangeCheck AIR — 8-bit limb 范围检查 AIR（V4 修复 + V4.1 bit decomposition）
//!
//! 验证 CPU trace 中所有 8-bit limb 值 ∈ [0, 255]。
//!
//! ## 设计
//!
//! - 256 个 real row（value = 0..255），pad 到 CPU trace 的 log_size
//! - 每行发送 logup yield：(value, multiplicity)，multiplicity ≤ 0
//! - CPU AIR 发送对应的 claim：(limb_value, +1)
//! - 一致性条件：Σ(CPU claims) + Σ(RangeCheck yields) == 0
//! - **V4.1 修复**：用 bit decomposition 替代 increment 约束（offset -2 在
//!   CircleDomain 上无法正确访问前一 trace row，导致 `ConstraintsNotSatisfied`）
//!
//! ## 列布局（12 列）
//!
//! | 范围 | 列名 | 说明 |
//! |------|------|------|
//! | 0 | value | limb 值 v ∈ [0, 255]（real row），0（padding row） |
//! | 1 | multiplicity | -(该值在 CPU limb 中出现次数)（real row），0（padding row） |
//! | 2 | is_padding | 1=padding row，0=real row |
//! | 3 | is_first | 1=row 0（首个 real row），0=其他 |
//! | 4-11 | bit0-bit7 | value 的 8-bit 分解（bit_i ∈ {0,1}） |
//!
//! ## 约束清单
//!
//! | # | 约束 | 度 | gating | 说明 |
//! |---|------|----|--------|------|
//! | R1 | is_padding binality | 2 | 通用 | IsPadding·(IsPadding−1) = 0 |
//! | R2 | is_first binality | 2 | 通用 | IsFirst·(IsFirst−1) = 0 |
//! | R3 | is_padding · is_first 互斥 | 2 | 通用 | IsPadding·IsFirst = 0 |
//! | R4 | first row value=0 | 2 | IsFirst | IsFirst·value = 0 |
//! | R5 | padding multiplicity=0 | 2 | IsPadding | IsPadding·multiplicity = 0 |
//! | R6-R13 | bit0-bit7 binality | 2 | 通用 | bit_i·(bit_i−1) = 0 |
//! | R14 | value decomposition | 1 | 通用 | value = Σ bit_i·2^i |
//!
//! ## Soundness 分析（V4.1）
//!
//! 1. **bit binality**：确保每个 bit_i ∈ {0, 1}
//! 2. **decomposition**：确保 value = Σ bit_i·2^i，即 value ∈ [0, 255]
//! 3. **logup**：确保每个 CPU limb 值都出现在表中
//! 4. **结论**：所有 CPU limb 值 ∈ [0, 255] ✓
//!
//! 旧 increment 约束（value = prev_value + 1）依赖 offset -2 访问前一 trace row，
//! 但 CircleDomain 的两半结构与 bit-reverse 排序导致 offset -2 无法正确映射到
//! 前一行。bit decomposition 不需要 offset 访问，完全避免了此问题。

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval, RelationEntry};

use super::lookups::RangeCheckLookup;

// ===========================================================================
// RangeCheckAir 列布局常量（12 列）
// ===========================================================================

/// RangeCheck AIR 列数（V4.1：4 基础列 + 8 bit 列）。
pub const RC_NUM_COLUMNS: usize = 12;

/// col 0：value（limb 值，real row = 0..255，padding row = 0）
pub const RC_COL_VALUE: usize = 0;
/// col 1：multiplicity（负数 = 出现次数的负值，padding row = 0）
pub const RC_COL_MULTIPLICITY: usize = 1;
/// col 2：is_padding
pub const RC_COL_IS_PADDING: usize = 2;
/// col 3：is_first（row 0 = 1，其余 = 0）
pub const RC_COL_IS_FIRST: usize = 3;
/// col 4-11：bit0-bit7（value 的 8-bit 分解，bit_i ∈ {0,1}）
pub const RC_COL_BIT0: usize = 4;
/// bit1（value 的第 1 位，权重 2）
pub const RC_COL_BIT1: usize = 5;
/// bit2（value 的第 2 位，权重 4）
pub const RC_COL_BIT2: usize = 6;
/// bit3（value 的第 3 位，权重 8）
pub const RC_COL_BIT3: usize = 7;
/// bit4（value 的第 4 位，权重 16）
pub const RC_COL_BIT4: usize = 8;
/// bit5（value 的第 5 位，权重 32）
pub const RC_COL_BIT5: usize = 9;
/// bit6（value 的第 6 位，权重 64）
pub const RC_COL_BIT6: usize = 10;
/// bit7（value 的第 7 位，权重 128）
pub const RC_COL_BIT7: usize = 11;

/// RangeCheck 表的大小（256 = 2^8，即 8-bit 值域 [0, 255]）。
pub const RANGE_CHECK_TABLE_SIZE: usize = 256;

// ===========================================================================
// RangeCheckAir 结构
// ===========================================================================

/// RangeCheck AIR 组件 — 8-bit limb 范围检查 FrameworkEval。
///
/// # 设计
/// - 256 个 real row（value = 0..255），pad 到 CPU trace 的 log_size
/// - 每行发送 logup yield：(value, multiplicity)
/// - multiplicity = -(该值在 CPU limb 中出现的总次数)
/// - padding 行 multiplicity = 0（不贡献 sum）
///
/// # 用法
/// ```ignore
/// use poker_zkvm::stwo_backend::range_check_air::RangeCheckAir;
/// use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
/// use stwo::core::fields::qm31::SecureField;
///
/// let air = RangeCheckAir::new(log_size, RangeCheckLookup::dummy());
/// let component = FrameworkComponent::new(
///     &mut TraceLocationAllocator::default(),
///     air,
///     SecureField::from(0u32),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RangeCheckAir {
    /// log2(trace 行数)，与 CPU trace 相同
    log_size: u32,
    /// RangeCheckLookup relation（用于 logup yield）
    range_lookup: RangeCheckLookup,
}

impl RangeCheckAir {
    /// 创建指定 log_size 的 RangeCheck AIR。
    ///
    /// # 参数
    /// - `log_size` — log2(行数)，须与 CPU trace 相同（≥ 8，因 256 real rows + padding）
    /// - `range_lookup` — RangeCheckLookup relation 实例（从 channel draw 或 dummy）
    #[must_use]
    pub const fn new(log_size: u32, range_lookup: RangeCheckLookup) -> Self {
        Self { log_size, range_lookup }
    }

    /// 获取 log_size。
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl FrameworkEval for RangeCheckAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    /// 所有约束的最大总度 = 2（bit binality: bit·(bit-1)）。
    /// V4.1：移除 degree-3 increment 约束后，max degree 降为 2。
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();

        // ----- 读取全部 12 列 -----
        // V4.1：所有列通过 next_trace_mask 读取，不再需要 offset -2
        let mut cols: Vec<E::F> = Vec::with_capacity(RC_NUM_COLUMNS);
        for _ in 0..RC_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }

        let col = |idx: usize| -> E::F { cols[idx].clone() };

        // ----- 读取 flag 列 -----
        let is_padding = col(RC_COL_IS_PADDING);
        let is_first = col(RC_COL_IS_FIRST);
        let value = col(RC_COL_VALUE);
        let multiplicity = col(RC_COL_MULTIPLICITY);

        // ===== 约束 R1：is_padding binality =====
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // ===== 约束 R2：is_first binality =====
        let first_bin = is_first.clone() * (is_first.clone() - one.clone());
        eval.add_constraint(first_bin);

        // ===== 约束 R3：is_padding · is_first 互斥 =====
        let mutex = is_padding.clone() * is_first.clone();
        eval.add_constraint(mutex);

        // ===== 约束 R4：first row value=0 =====
        let first_value = is_first.clone() * value.clone();
        eval.add_constraint(first_value);

        // ===== 约束 R5：padding multiplicity=0 =====
        let padding_mult = is_padding.clone() * multiplicity.clone();
        eval.add_constraint(padding_mult);

        // ===== 约束 R6-R13：bit0-bit7 binality =====
        // 每个 bit_i ∈ {0, 1}：bit_i · (bit_i - 1) = 0
        for i in 0..8usize {
            let bit = col(RC_COL_BIT0 + i);
            let bit_bin = bit.clone() * (bit - one.clone());
            eval.add_constraint(bit_bin);
        }

        // ===== 约束 R14：value decomposition =====
        // value = bit0·1 + bit1·2 + bit2·4 + ... + bit7·128
        let mut reconstructed = col(RC_COL_BIT0);
        let mut power_of_two = one.clone();
        for i in 1..8usize {
            power_of_two = power_of_two.clone() + power_of_two.clone();
            reconstructed = reconstructed + col(RC_COL_BIT0 + i) * power_of_two.clone();
        }
        let decomp_diff = value.clone() - reconstructed;
        eval.add_constraint(decomp_diff);

        // ===== Logup yield =====
        // 非 padding 行：multiplicity = -(count_v)
        // padding 行：multiplicity = 0（约束 R5 保证）
        // yield = (value, multiplicity)
        let lookup_values = vec![value];
        let multiplicity_ef: E::EF = multiplicity.into();
        eval.add_to_relation(RelationEntry::new(
            &self.range_lookup,
            multiplicity_ef,
            &lookup_values,
        ));
        eval.finalize_logup();

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
    fn test_range_check_air_new() {
        let air = RangeCheckAir::new(10, RangeCheckLookup::dummy());
        assert_eq!(air.log_size(), 10);
        assert_eq!(air.max_constraint_log_degree_bound(), 11);
    }

    #[test]
    fn test_rc_num_columns() {
        assert_eq!(RC_NUM_COLUMNS, 12);
    }

    #[test]
    fn test_range_check_table_size() {
        assert_eq!(RANGE_CHECK_TABLE_SIZE, 256);
    }
}
