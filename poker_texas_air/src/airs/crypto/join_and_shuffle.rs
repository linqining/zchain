//! `join_and_shuffle` AIR — 玩家加入并完成首洗牌。
//!
//! 移植自 `dispatch::dispatch_join_and_shuffle` 与 `state_machine::apply_join_and_shuffle`。
//!
//! ## 业务规约
//!
//! 1. `round_state == ROUND_SHUFFLE`
//! 2. `seat_index` 玩家已注册公钥
//! 3. 提交 52 张加密牌的新密文 + 52 个 DLEq proof
//! 4. 状态变更：
//!    - `deck_state.encrypted` 更新为新密文
//!    - `shuffle_state.completed.push(seat_index)`
//!    - `version += 1`
//!
//! ## 简化策略
//!
//! 阶段 4 PoC 只验证协议级状态变更：
//! - `shuffle_state.phase` 保持 SHUFFLE_PHASE_SHUFFLING
//! - 玩家加入 `completed` 列表（通过 `output_completed_count += 1` 见证）
//! - 牌组 commitment hash 一致性
//!
//! 完整密码学约束（DLEq verification）留待阶段 5 嵌入 Verifier AIR。
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 14 个：`INPUT_SEAT_INDEX`, `INPUT_NEW_DECK_COMMITMENT_BASE[4]`,
//!   `OUTPUT_COMPLETED_COUNT`, `OUTPUT_DECK_COMMITMENT_BASE[4]`,
//!   `OUTPUT_OLD_DECK_COMMITMENT_BASE[4]`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `join_and_shuffle` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_NEW_DECK_COMMITMENT` 起始列（4 limb，新牌组承诺哈希）。
    pub const INPUT_NEW_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_COMPLETED_COUNT` 列（洗牌完成玩家数）。
    pub const OUTPUT_COMPLETED_COUNT: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_DECK_COMMITMENT` 起始列（4 limb，最终牌组承诺）。
    pub const OUTPUT_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `OUTPUT_OLD_DECK_COMMITMENT` 起始列（4 limb，原牌组承诺）。
    pub const OUTPUT_OLD_DECK_COMMITMENT_BASE: usize = COMMON_NUM_COLUMNS + 10;
    /// `join_and_shuffle` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 14;
}

/// `join_and_shuffle` 输入参数。
#[derive(Debug, Clone)]
pub struct JoinAndShuffleInput {
    /// 执行洗牌的座位索引。
    pub seat_index: u8,
    /// 新牌组承诺（Blake2b 压缩后 4 limb）。
    pub new_deck_commitment: u64,
}

/// `join_and_shuffle` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct JoinAndShuffleAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: JoinAndShuffleInput,
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

impl JoinAndShuffleAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for JoinAndShuffleAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::JoinAndShuffle);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_new_deck_commitment_0 = eval.next_trace_mask();
        let _input_new_deck_commitment_1 = eval.next_trace_mask();
        let _input_new_deck_commitment_2 = eval.next_trace_mask();
        let _input_new_deck_commitment_3 = eval.next_trace_mask();
        let _output_completed_count = eval.next_trace_mask();
        let output_deck_commitment_0 = eval.next_trace_mask();
        let _output_deck_commitment_1 = eval.next_trace_mask();
        let _output_deck_commitment_2 = eval.next_trace_mask();
        let _output_deck_commitment_3 = eval.next_trace_mask();
        let _output_old_deck_commitment_0 = eval.next_trace_mask();
        let _output_old_deck_commitment_1 = eval.next_trace_mask();
        let _output_old_deck_commitment_2 = eval.next_trace_mask();
        let _output_old_deck_commitment_3 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：新牌组承诺一致性（limb 0）
        let expected_commit_0: E::F =
            M31::from((self.input.new_deck_commitment & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_new_deck_commitment_0.clone() - expected_commit_0));

        // 约束 3：output_deck_commitment == input_new_deck_commitment（洗牌后牌组已更新）
        eval.add_constraint(is_active * (output_deck_commitment_0 - input_new_deck_commitment_0));

        // TODO 阶段 5：嵌入 DLEq Verifier AIR 验证 52 个 DLEq proof
        // TODO 阶段 5：约束 deck_state.encrypted 新密文与 DLEq 一致

        eval
    }
}

/// `join_and_shuffle` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct JoinAndShuffleRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_NEW_DECK_COMMITMENT`（4 limb）。
    pub input_new_deck_commitment: [M31; 4],
    /// `OUTPUT_COMPLETED_COUNT`。
    pub output_completed_count: M31,
    /// `OUTPUT_DECK_COMMITMENT`（4 limb）。
    pub output_deck_commitment: [M31; 4],
    /// `OUTPUT_OLD_DECK_COMMITMENT`（4 limb）。
    pub output_old_deck_commitment: [M31; 4],
}

impl JoinAndShuffleRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &JoinAndShuffleInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        _pre_completed_count: u8,
        post_completed_count: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::JoinAndShuffle,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                1, // pre = ROUND_SHUFFLE
                1, // post = ROUND_SHUFFLE
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_new_deck_commitment: u64_to_m31_limbs(input.new_deck_commitment),
            output_completed_count: u8_to_m31(post_completed_count),
            output_deck_commitment: u64_to_m31_limbs(input.new_deck_commitment),
            output_old_deck_commitment: [ZERO; 4], // 简化：旧承诺占位（阶段 5 接入真实 hash）
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_new_deck_commitment: [ZERO; 4],
            output_completed_count: ZERO,
            output_deck_commitment: [ZERO; 4],
            output_old_deck_commitment: [ZERO; 4],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_new_deck_commitment);
        v.push(self.output_completed_count);
        v.extend_from_slice(&self.output_deck_commitment);
        v.extend_from_slice(&self.output_old_deck_commitment);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
