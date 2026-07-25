//! `tick` AIR — 超时驱动（permissionless）。
//!
//! ## 业务规约
//! 1. 根据当前 `round_state` 和超时配置触发状态转换
//! 2. 严格优先级：reconstruct > shuffle > reveal > 正常逻辑 > fallback

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `tick` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_CURRENT_TIME` 起始列（4 limb）。
    pub const INPUT_CURRENT_TIME_BASE: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_TIMEOUT_KIND` 列（0=shuffle, 1=reveal, 2=reconstruct, 3=betting）。
    pub const INPUT_TIMEOUT_KIND: usize = COMMON_NUM_COLUMNS + 4;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 5;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 6;
}

/// `tick` 输入参数。
#[derive(Debug, Clone)]
pub struct TickInput {
    /// 当前时间戳。
    pub current_time: u64,
    /// 超时类型。
    pub timeout_kind: u8,
}

/// `tick` AIR。
#[derive(Debug, Clone)]
pub struct TickAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: TickInput,
    /// 调用前 state_root。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl TickAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for TickAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Tick);
        let is_active = common.is_active.clone();

        let _input_time_0 = eval.next_trace_mask();
        let _input_time_1 = eval.next_trace_mask();
        let _input_time_2 = eval.next_trace_mask();
        let _input_time_3 = eval.next_trace_mask();
        let input_timeout_kind = eval.next_trace_mask();
        let _output_new_round_state = eval.next_trace_mask();

        // 约束：timeout_kind == input.timeout_kind
        let expected: E::F = M31::from(u32::from(self.input.timeout_kind)).into();
        eval.add_constraint(is_active * (input_timeout_kind - expected));
        eval
    }
}

/// `tick` trace 行。
#[derive(Debug, Clone)]
pub struct TickRow {
    /// 通用列。
    pub common: CommonRow,
    /// 当前时间。
    pub input_current_time: [M31; 4],
    /// 超时类型。
    pub input_timeout_kind: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
}

impl TickRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &TickInput,
        pre_state_root: [M31; 4], post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
        pre_round_state: u8, post_round_state: u8,
    ) -> Self {
        use crate::airs::common::u64_to_m31_limbs;
        Self {
            common: CommonRow::active(
                MethodKind::Tick, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                pre_round_state, post_round_state, 0, 0, 0, 0,
            ),
            input_current_time: u64_to_m31_limbs(input.current_time),
            input_timeout_kind: M31::from(u32::from(input.timeout_kind)),
            output_new_round_state: M31::from(u32::from(post_round_state)),
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self { common: CommonRow::padding(), input_current_time: [ZERO; 4], input_timeout_kind: ZERO, output_new_round_state: ZERO }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.extend_from_slice(&self.input_current_time);
        v.push(self.input_timeout_kind);
        v.push(self.output_new_round_state);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
