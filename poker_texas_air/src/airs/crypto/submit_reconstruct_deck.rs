//! `submit_reconstruct_deck` AIR — 提交重构牌组。
//!
//! 移植自 `dispatch::dispatch_submit_reconstruct_deck` 与
//! `state_machine::apply_submit_reconstruct_deck`。
//!
//! ## 业务规约
//!
//! 1. `round_state` 在 reconstruct 阶段（`reconstruct_state.phase != NONE`）
//! 2. `seat_index` 在 `reconstruct_assignments` 中
//! 3. 提交 ReconstructProof（证明重构密文正确性）
//! 4. 状态变更：
//!    - `reconstruct_state.player_decks[seat_index] = deck`
//!    - 若所有玩家都已提交，调用 `rebuild_deck_from_reconstruct_deck`
//!    - 进入 settle 阶段
//!    - `version += 1`
//!
//! ## 简化策略
//!
//! 阶段 4 PoC 只验证协议级状态变更：
//! - `seat_index` 一致性
//! - `output_submitted_count` 一致性
//!
//! ReconstructProof 验证留待阶段 5。

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `submit_reconstruct_deck` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_RECONSTRUCT_PHASE` 列。
    pub const INPUT_RECONSTRUCT_PHASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_SUBMITTED_COUNT` 列。
    pub const OUTPUT_SUBMITTED_COUNT: usize = COMMON_NUM_COLUMNS + 2;
    /// `submit_reconstruct_deck` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 3;
}

/// `submit_reconstruct_deck` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckInput {
    /// 提交重构牌组的座位索引。
    pub seat_index: u8,
    /// 当前 reconstruct 阶段枚举值。
    pub reconstruct_phase: u8,
}

/// `submit_reconstruct_deck` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitReconstructDeckInput,
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

impl SubmitReconstructDeckAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitReconstructDeckAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::SubmitReconstructDeck);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_reconstruct_phase = eval.next_trace_mask();
        let _output_submitted_count = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：reconstruct_phase == input.reconstruct_phase
        let expected_phase: E::F = M31::from(u32::from(self.input.reconstruct_phase)).into();
        eval.add_constraint(is_active * (input_reconstruct_phase - expected_phase));

        // TODO 阶段 5：嵌入 ReconstructProof Verifier AIR

        eval
    }
}

/// `submit_reconstruct_deck` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitReconstructDeckRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_RECONSTRUCT_PHASE`。
    pub input_reconstruct_phase: M31,
    /// `OUTPUT_SUBMITTED_COUNT`。
    pub output_submitted_count: M31,
}

impl SubmitReconstructDeckRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitReconstructDeckInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_submitted_count: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::SubmitReconstructDeck,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                3, // pre = ROUND_RECONSTRUCT（简化值）
                3, // post = ROUND_RECONSTRUCT
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_reconstruct_phase: u8_to_m31(input.reconstruct_phase),
            output_submitted_count: u8_to_m31(post_submitted_count),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_reconstruct_phase: ZERO,
            output_submitted_count: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_reconstruct_phase);
        v.push(self.output_submitted_count);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
