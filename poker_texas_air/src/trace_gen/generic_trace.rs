//! 通用 trace 生成器 — 适用于任意 method AIR。
//!
//! 阶段 2-4 引入：避免为每个方法（17 个）复制粘贴 trace 生成模板。
//!
//! ## 设计
//!
//! 所有单步方法 AIR 的 trace 生成流程一致：
//! 1. 选择 `log_size = 10`（Stwo SIMD 对齐最小值）
//! 2. 把同一条 active statement 复制到 1024 行（关闭 all-padding 绕过）
//! 3. 返回 `MethodTrace`
//!
//! 调用方负责构造 active row 与 AIR 实例，本模块只提供 trace 装配辅助。
//!
//! ## 使用示例
//!
//! ```ignore
//! use poker_texas_air::airs::actions::fold::{FoldAir, FoldInput, FoldRow};
//! use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
//! use poker_texas_air::trace_gen::MethodTrace;
//!
//! let input = FoldInput { seat_index: 0 };
//! let row = FoldRow::active(&input, [ZERO; 4], [ZERO; 4], 1, 0, 0, 0, 1, 2, 2);
//! let trace = gen_method_trace(FoldAir::num_columns(), &row.to_vec(), &FoldRow::padding().to_vec());
//! ```

use stwo::core::fields::m31::M31;

use crate::error::TexasAirResult;
use crate::trace_gen::MethodTrace;

/// Stwo SIMD 对齐要求的最小 log_size（1024 行）。
pub const MIN_LOG_SIZE: u32 = 10;

/// 通用 trace 生成器：把 active row 复制成完整 `MethodTrace`。
///
/// # 参数
/// - `num_columns`: trace 列数
/// - `active_row`: verifier-bound active 行
/// - `padding_row`: 兼容旧调用方，仅校验列宽
///
/// # 返回
/// `MethodTrace`，含 `log_size = 10`、1024 行。
///
/// # Errors
///
/// 当行长度不匹配 `num_columns` 时返回 `TraceGenError`。
///
/// # Panics
///
/// 不会 panic（所有错误通过 `Result` 返回）。
pub fn gen_method_trace(
    num_columns: usize,
    active_row: &[M31],
    padding_row: &[M31],
) -> TexasAirResult<MethodTrace> {
    gen_method_trace_with_log_size(MIN_LOG_SIZE, num_columns, active_row, padding_row)
}

/// 通用 trace 生成器（可指定 log_size）。
///
/// 当业务行数 > 1 时，调用方可指定更大的 `log_size`。
///
/// # 参数
/// - `log_size`: log2(行数)，须 ≥ [`MIN_LOG_SIZE`]
/// - `num_columns`: trace 列数
/// - `active_row`: active 行（行 0）的列向量
/// - `padding_row`: padding 行（行 1..2^log_size）的列向量
///
/// # Errors
///
/// 当行长度不匹配 `num_columns` 时返回 `TraceGenError`。
pub fn gen_method_trace_with_log_size(
    log_size: u32,
    num_columns: usize,
    active_row: &[M31],
    padding_row: &[M31],
) -> TexasAirResult<MethodTrace> {
    let mut trace = MethodTrace::new(log_size, num_columns);
    trace.write_active_with_padding(active_row, padding_row)?;
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::common::ZERO;

    #[test]
    fn test_gen_method_trace_basic() {
        let num_cols = 5;
        let active = vec![M31::from(1u32); num_cols];
        let padding = vec![ZERO; num_cols];
        let trace = gen_method_trace(num_cols, &active, &padding).unwrap();
        assert_eq!(trace.log_size, MIN_LOG_SIZE);
        assert_eq!(trace.num_columns, num_cols);
        assert_eq!(trace.cols.len(), num_cols);
        assert_eq!(trace.cols[0].len(), 1usize << MIN_LOG_SIZE);
        // 行 0 是 active
        assert_eq!(trace.cols[0][0], M31::from(1u32));
        // 所有行都复制 active statement，AIR 无需信任 first-row witness。
        assert_eq!(trace.cols[0][1], M31::from(1u32));
    }

    #[test]
    fn test_gen_method_trace_row_length_mismatch() {
        let active = vec![M31::from(1u32); 5];
        let padding = vec![ZERO; 6]; // 错误长度
        let result = gen_method_trace(5, &active, &padding);
        assert!(result.is_err());
    }
}
