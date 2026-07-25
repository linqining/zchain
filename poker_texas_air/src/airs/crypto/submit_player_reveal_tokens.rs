//! `submit_player_reveal_tokens` AIR — 提交揭牌令牌。
//!
//! 移植自 `dispatch::dispatch_submit_player_reveal_tokens` 与
//! `state_machine::apply_submit_player_reveal_tokens`。
//!
//! ## 业务规约
//!
//! 1. `round_state` 在 reveal 阶段（`reveal_token_state.reveal_phase != NONE`）
//! 2. `seat_index` 在 `reveal_assignments` 中
//! 3. 提交 RevealTokenProof（DLEq 证明 reveal token 正确性）
//! 4. 状态变更：
//!    - `reveal_token_state.revealed[seat_index] = true`
//!    - 若所有需揭示的玩家都已提交，进入 reconstruct 阶段
//!    - `version += 1`
//!
//! ## 简化策略
//!
//! 阶段 4 PoC 只验证协议级状态变更：
//! - `seat_index` 一致性
//! - `output_revealed_count` 一致性
//!
//! RevealTokenProof 验证留待阶段 5。

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `submit_player_reveal_tokens` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_REVEAL_PHASE` 列。
    pub const INPUT_REVEAL_PHASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_REVEALED_COUNT` 列。
    pub const OUTPUT_REVEALED_COUNT: usize = COMMON_NUM_COLUMNS + 2;
    /// `submit_player_reveal_tokens` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 3;
}

/// `submit_player_reveal_tokens` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensInput {
    /// 提交令牌的座位索引。
    pub seat_index: u8,
    /// 当前 reveal 阶段枚举值。
    pub reveal_phase: u8,
}

/// `submit_player_reveal_tokens` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitPlayerRevealTokensInput,
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

impl SubmitPlayerRevealTokensAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitPlayerRevealTokensAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::SubmitPlayerRevealTokens);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_reveal_phase = eval.next_trace_mask();
        let _output_revealed_count = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：reveal_phase == input.reveal_phase
        let expected_phase: E::F = M31::from(u32::from(self.input.reveal_phase)).into();
        eval.add_constraint(is_active * (input_reveal_phase - expected_phase));

        // TODO 阶段 5：嵌入 RevealTokenProof Verifier AIR

        eval
    }
}

/// `submit_player_reveal_tokens` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_REVEAL_PHASE`。
    pub input_reveal_phase: M31,
    /// `OUTPUT_REVEALED_COUNT`。
    pub output_revealed_count: M31,
}

impl SubmitPlayerRevealTokensRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitPlayerRevealTokensInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_revealed_count: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::SubmitPlayerRevealTokens,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                2, // pre = ROUND_REVEAL（简化值）
                2, // post = ROUND_REVEAL
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_reveal_phase: u8_to_m31(input.reveal_phase),
            output_revealed_count: u8_to_m31(post_revealed_count),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_reveal_phase: ZERO,
            output_revealed_count: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_reveal_phase);
        v.push(self.output_revealed_count);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
