//! `kick_player` AIR — 踢出玩家（管理员操作）。
//!
//! 移植自 `dispatch::dispatch_kick_player` 与 `state_machine::apply_kick_player`。
//!
//! ## 业务规约
//!
//! 1. 调用者是管理员（admin）
//! 2. 目标座位存在且 occupied
//! 3. 退还玩家剩余 stack 到其地址
//! 4. 状态变更：
//!    - `seat.player = EMPTY_PLAYER`
//!    - `seat.stack = 0`, `seat.folded = false`, `seat.all_in = false`
//!    - `seat.is_waiting = true`
//!    - `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 6 个：`INPUT_SEAT_INDEX`, `OUTPUT_REFUND_BASE[4]`,
//!   `OUTPUT_KICKED`
//!
//! 简化版只验证 seat_index 一致性 + output_kicked == 1。

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `kick_player` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_REFUND` 起始列（4 limb，退还玩家 stack）。
    pub const OUTPUT_REFUND_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_KICKED` 列（1 = 已踢出）。
    pub const OUTPUT_KICKED: usize = COMMON_NUM_COLUMNS + 5;
    /// `kick_player` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 6;
}

/// `kick_player` 输入参数。
#[derive(Debug, Clone)]
pub struct KickPlayerInput {
    /// 被踢出的座位索引。
    pub seat_index: u8,
    /// 退还金额（= seat.stack）。
    pub refund: u64,
}

/// `kick_player` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct KickPlayerAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: KickPlayerInput,
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

impl KickPlayerAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for KickPlayerAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::KickPlayer);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let output_refund_0 = eval.next_trace_mask();
        let _output_refund_1 = eval.next_trace_mask();
        let _output_refund_2 = eval.next_trace_mask();
        let _output_refund_3 = eval.next_trace_mask();
        let output_kicked = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：refund 一致性（limb 0）
        let expected_refund_0: E::F = M31::from((self.input.refund & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (output_refund_0 - expected_refund_0));

        // 约束 3：output_kicked == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active * (output_kicked - one));

        // TODO 阶段 3 完整版：约束 admin 签名

        eval
    }
}

/// `kick_player` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct KickPlayerRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `OUTPUT_REFUND`（4 limb）。
    pub output_refund: [M31; 4],
    /// `OUTPUT_KICKED`。
    pub output_kicked: M31,
}

impl KickPlayerRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &KickPlayerInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::KickPlayer,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                post_round_state,
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            output_refund: u64_to_m31_limbs(input.refund),
            output_kicked: M31::from(1u32),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            output_refund: [ZERO; 4],
            output_kicked: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.output_refund);
        v.push(self.output_kicked);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
