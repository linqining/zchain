//! # Composition Eval AIR — L1 proof 的 composition polynomial evaluation（Phase 5 — v5.0 骨架）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md` §7。
//!
//! ## v5.0 简化版
//!
//! v5.0：Composition Eval AIR 是 stub（直接 claim computed_eval，不验证计算）。
//! v5.1 将扩展为完整 composition polynomial evaluation，重新实现所有 L1 约束。

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

/// Composition Eval AIR 总列数（v5.0 stub：10 列）。
pub const COMP_EVAL_AIR_NUM_COLUMNS: usize = 10;

/// Composition Eval AIR 组件（v5.0 stub）。
#[derive(Debug, Clone)]
pub struct CompositionEvalAir {
    log_size: u32,
}

impl CompositionEvalAir {
    /// 创建指定 log_size 的 Composition Eval AIR。
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

impl FrameworkEval for CompositionEvalAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = BaseField::from(1u32).into();

        // 读取所有列（v5.0 stub，不添加约束）
        let mut cols: Vec<E::F> = Vec::with_capacity(COMP_EVAL_AIR_NUM_COLUMNS);
        for _ in 0..COMP_EVAL_AIR_NUM_COLUMNS {
            cols.push(eval.next_trace_mask());
        }

        // IsPadding binality（col 9 假设为 padding flag）
        let is_padding = cols[9].clone();
        let padding_bin = is_padding.clone() * (is_padding.clone() - one.clone());
        eval.add_constraint(padding_bin);

        // v5.1 将在此处添加完整 composition polynomial evaluation 约束
        // CompositionEvalAir v5.0 无 logup（无 lookup relation），不调用 finalize_logup()。
        eval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comp_eval_air_num_columns() {
        assert_eq!(COMP_EVAL_AIR_NUM_COLUMNS, 10);
    }

    #[test]
    fn test_comp_eval_air_new() {
        let air = CompositionEvalAir::new(3);
        assert_eq!(air.log_size(), 3);
    }

    #[test]
    fn test_comp_eval_air_max_constraint_log_degree_bound() {
        let air = CompositionEvalAir::new(5);
        assert_eq!(air.max_constraint_log_degree_bound(), 6);
    }
}
