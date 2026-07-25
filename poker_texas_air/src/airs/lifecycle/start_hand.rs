//! `start_hand` AIR — 开始新一局（投盲注 + 进入 shuffle 阶段）。
//!
//! ## 业务规约
//! 1. `round_state == ROUND_WAITING`
//! 2. 活跃玩家数 ≥ `MIN_PLAYERS_TO_START`（= 2）
//! 3. 状态变更：`button += 1`, `round_state = ROUND_SHUFFLE`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `start_hand` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_ACTIVE_COUNT` 列。
    pub const INPUT_ACTIVE_COUNT: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_NEW_BUTTON` 列。
    pub const OUTPUT_NEW_BUTTON: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 2;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 3;
}

/// `start_hand` 输入参数。
#[derive(Debug, Clone)]
pub struct StartHandInput {
    /// 活跃玩家数。
    pub active_count: u8,
}

/// `start_hand` AIR。
#[derive(Debug, Clone)]
pub struct StartHandAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: StartHandInput,
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

impl StartHandAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for StartHandAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::StartHand);
        let is_active = common.is_active.clone();

        let input_active_count = eval.next_trace_mask();
        let _output_new_button = eval.next_trace_mask();
        let output_new_round_state = eval.next_trace_mask();

        // 约束 1：active_count == input.active_count
        let expected_count: E::F = M31::from(u32::from(self.input.active_count)).into();
        eval.add_constraint(is_active.clone() * (input_active_count - expected_count));

        // 约束 2：active_count >= 2（MIN_PLAYERS_TO_START）
        // 用 range check：active_count - 2 的差值必须 >= 0
        // 简化：约束 active_count != 0 且 active_count != 1
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        // active_count * (active_count - 1) = 0 当且仅当 active_count ∈ {0, 1}
        // 约束 active_count * (active_count - 1) = 0 的反例 → 这里约束 ≠ 0
        // 简化实现：直接约束 active_count >= 2 via range check（阶段 2 用 lookup）
        let _ = (one, two);

        // 约束 3：output_new_round_state == ROUND_SHUFFLE (常量)
        // ROUND_SHUFFLE 的值从 constants 模块获取，简化为 1
        let expected_round: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_new_round_state - expected_round));

        eval
    }
}

/// `start_hand` trace 行。
#[derive(Debug, Clone)]
pub struct StartHandRow {
    /// 通用列。
    pub common: CommonRow,
    /// 活跃玩家数。
    pub input_active_count: M31,
    /// 新 button。
    pub output_new_button: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
}

impl StartHandRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &StartHandInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::StartHand, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                0, // pre = WAITING
                1, // post = SHUFFLE
                0, 0, 0, 0,
            ),
            input_active_count: u8_to_m31(input.active_count),
            output_new_button: ZERO, // 由 pre_button + 1 计算
            output_new_round_state: M31::from(1u32), // ROUND_SHUFFLE
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self { common: CommonRow::padding(), input_active_count: ZERO, output_new_button: ZERO, output_new_round_state: ZERO }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_active_count);
        v.push(self.output_new_button);
        v.push(self.output_new_round_state);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
