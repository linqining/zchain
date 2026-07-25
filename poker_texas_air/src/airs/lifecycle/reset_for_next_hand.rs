//! `reset_for_next_hand` AIR — 显式重置桌台到 WAITING。
//!
//! ## 业务规约
//! 1. 清除座位状态（folded, all_in, is_waiting 等）
//! 2. 重置 pot, side_pots, community_cards
//! 3. `round_state = ROUND_WAITING`
//! 4. `version += 1`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `reset_for_next_hand` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 0;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 1;
}

/// `reset_for_next_hand` 输入参数（无额外参数）。
#[derive(Debug, Clone, Default)]
pub struct ResetForNextHandInput;

/// `reset_for_next_hand` AIR。
#[derive(Debug, Clone)]
pub struct ResetForNextHandAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: ResetForNextHandInput,
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

impl ResetForNextHandAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for ResetForNextHandAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::ResetForNextHand);
        let is_active = common.is_active.clone();

        let output_new_round_state = eval.next_trace_mask();

        // 约束：output_new_round_state == ROUND_WAITING (== 0)
        eval.add_constraint(is_active * output_new_round_state);
        eval
    }
}

/// `reset_for_next_hand` trace 行。
#[derive(Debug, Clone)]
pub struct ResetForNextHandRow {
    /// 通用列。
    pub common: CommonRow,
    /// 新 round_state。
    pub output_new_round_state: M31,
}

impl ResetForNextHandRow {
    /// active 行。
    #[must_use]
    pub fn active(
        _input: &ResetForNextHandInput,
        pre_state_root: [M31; 4], post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
        pre_round_state: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::ResetForNextHand, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                pre_round_state, 0, // post = WAITING
                0, 0, 0, 0,
            ),
            output_new_round_state: ZERO, // ROUND_WAITING = 0
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self { common: CommonRow::padding(), output_new_round_state: ZERO }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.output_new_round_state);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
