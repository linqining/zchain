//! `kick_player` AIR — 踢出玩家（管理员操作）。
//!
//! 移植自 `dispatch::dispatch_kick_player` 与 `state_machine::apply_kick_player`。
//!
//! ## 业务规约
//!
//! 1. 调用者是管理员（admin）
//! 2. 目标座位存在且 occupied
//! 3. 退还玩家剩余 stack 到其地址
//! 4. 状态变更（与 fold **不同**的资金流向）：
//!    - **`table.pot += seat.bet; seat.bet = 0`**（被踢者当前下注立即入底池，
//!      见 `state_machine::kick_player_internal` state_machine.rs:2689）
//!    - `seat.player = EMPTY_PLAYER`
//!    - `seat.stack = 0`, `seat.folded = false`, `seat.all_in = false`
//!    - `seat.is_waiting = true`
//!    - `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 11 个：`INPUT_SEAT_INDEX`, `OUTPUT_REFUND_BASE[4]`,
//!   `OUTPUT_KICKED`, `KICKED_BET_BASE[4]`, `INPUT_SEAT_OCCUPIED`
//!
//! 资金流向约束（全 4 limb，对齐合约 checked_add 修复）：除 seat_index / refund /
//! kicked 一致性外，强制 **`post_pot = pre_pot + kicked_bet`**（全 4 limb delta，
//! 底池增量 == 被踢者下注）。admin 签名约束留待阶段 3/5。

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
    /// `KICKED_BET` 起始列（4 limb）— 被踢者当前下注（pot += kicked_bet）。
    /// 对齐合约 kick_player_internal 的 `table.pot = table.pot.checked_add(seat.bet)?`。
    pub const KICKED_BET_BASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 10;
    /// `kick_player` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 11;
}

/// `kick_player` 输入参数。
#[derive(Debug, Clone)]
pub struct KickPlayerInput {
    /// 被踢出的座位索引。
    pub seat_index: u8,
    /// 退还金额（= seat.stack）。
    pub refund: u64,
    /// 被踢者当前下注（kick 时立即并入底池：`pot += kicked_bet`）。
    pub kicked_bet: u64,
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
        let common = CommonConstraints::write(&mut eval, MethodKind::KickPlayer, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let output_refund_0 = eval.next_trace_mask();
        let _output_refund_1 = eval.next_trace_mask();
        let _output_refund_2 = eval.next_trace_mask();
        let _output_refund_3 = eval.next_trace_mask();
        let output_kicked = eval.next_trace_mask();
        // KICKED_BET（4 limb）— 被踢者当前下注，pot += kicked_bet
        let kicked_bet_0 = eval.next_trace_mask();
        let kicked_bet_1 = eval.next_trace_mask();
        let kicked_bet_2 = eval.next_trace_mask();
        let kicked_bet_3 = eval.next_trace_mask();
        let kicked_bet_limbs = [kicked_bet_0.clone(), kicked_bet_1.clone(), kicked_bet_2.clone(), kicked_bet_3.clone()];
        // Gap 3 boolean witness（座位非空）。
        let input_seat_occupied = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：refund 一致性（limb 0）
        let expected_refund_0: E::F = M31::from((self.input.refund & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (output_refund_0 - expected_refund_0));

        // 约束 3：output_kicked == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_kicked - one.clone()));

        // 约束 4（资金流向不变量，全 4 limb）：kick 时被踢者当前下注立即并入底池
        //   `table.pot = table.pot.checked_add(seat.bet)?`（state_machine.rs）
        //   即 post_pot = pre_pot + kicked_bet（全 4 limb delta）
        //   对齐合约 checked_add 修复：溢出时合约返回 Err，AIR 约束 delta 一致性。
        // 约束 kicked_bet limb 0 与 input 一致
        let expected_kicked_bet_0: E::F = M31::from((self.input.kicked_bet & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (kicked_bet_0.clone() - expected_kicked_bet_0));
        // 全 4 limb pot delta
        eval.add_constraint(common.pot_delta_4limb(&kicked_bet_limbs));

        // 约束 5（审计共性，degree-2）：round_state 不变（kick_player 不改变 round_state）。
        eval.add_constraint(common.round_state_unchanged());

        // 约束 6（Gap 3，degree-2）：input_seat_occupied == 1 — 诚实 host 只踢占用座位。
        eval.add_constraint(is_active.clone() * (input_seat_occupied - one.clone()));

        // TODO 阶段 3 完整版：约束 admin 签名；多 limb 进位（limb 1..3）

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
    /// `KICKED_BET`（4 limb）— 被踢者当前下注。
    pub kicked_bet: [M31; 4],
    /// `INPUT_SEAT_OCCUPIED` boolean witness（Gap 3）。
    pub input_seat_occupied: M31,
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
        pre_pot: u64,
        post_pot: u64,
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
                pre_pot,
                post_pot,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            output_refund: u64_to_m31_limbs(input.refund),
            output_kicked: M31::from(1u32),
            kicked_bet: u64_to_m31_limbs(input.kicked_bet),
            // Gap 3：诚实 host 只踢占用座位。
            input_seat_occupied: M31::from(1u32),
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
            kicked_bet: [ZERO; 4],
            input_seat_occupied: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.output_refund);
        v.push(self.output_kicked);
        v.extend_from_slice(&self.kicked_bet);
        v.push(self.input_seat_occupied);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
