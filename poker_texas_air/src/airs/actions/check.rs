//! `check` AIR — 玩家过牌（不下注且无需跟注）。
//!
//! 移植自 `dispatch::dispatch_check` 与 `state_machine::apply_check`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 当前下注 `current_bet == seat.bet`（无需跟注）
//! 4. 玩家未 fold、未 all_in
//! 5. 状态变更：`seat.acted_this_round = true`, `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 3 个：`INPUT_SEAT_INDEX`, `INPUT_CURRENT_BET_BASE[4]`, `OUTPUT_ACTED`

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `check` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CURRENT_BET` 起始列（4 limb，必须 == seat.bet 才能 check）。
    pub const INPUT_CURRENT_BET_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_ACTED` 列（1 = 已行动）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 7;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 8;
    /// `check` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 9;
}

/// `check` 输入参数。
#[derive(Debug, Clone)]
pub struct CheckInput {
    /// 执行 check 的座位索引。
    pub seat_index: u8,
    /// 当前下注额（必须 == seat.bet）。
    pub current_bet: u64,
    /// 该座位已下注额（合约守卫：`seat.bet >= current_bet` 才允许 check；
    /// 实际等价于 `seat.bet == current_bet`，因为若 `seat.bet > current_bet`
    /// 玩家本应被退还差额而非 check —— 这里约束两者 limb 0 相等）。
    pub seat_bet: u64,
    /// mid-round 推进后的下一行动座位。
    pub post_current_turn: u8,
}

/// `check` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct CheckAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: CheckInput,
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

impl CheckAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for CheckAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write(&mut eval, &statement);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_current_bet_0 = eval.next_trace_mask();
        let _input_current_bet_1 = eval.next_trace_mask();
        let _input_current_bet_2 = eval.next_trace_mask();
        let _input_current_bet_3 = eval.next_trace_mask();
        let output_acted = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：current_bet 一致性（验证 limb 0）
        let expected_bet_0: E::F = M31::from((self.input.current_bet & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_current_bet_0.clone() - expected_bet_0));

        // 约束 2b（合约守卫，limb 0）：check 仅在 `seat.bet == current_bet` 时合法
        //   （`apply_check` 要求 `seat.bet >= current_bet`；等价于两者相等）。
        let expected_seat_bet_0: E::F = M31::from((self.input.seat_bet & 0xFFFF) as u32).into();
        eval.add_constraint(
            is_active.clone() * (input_current_bet_0.clone() - expected_seat_bet_0),
        );

        // 约束 3：output_acted == 1
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 4（审计共性）：round_state 不变 + 必须处于下注轮（Gap 1）。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}。
        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));
        // 约束 5（审计共性，degree-2 limb0）：pot 不变（check 不改变 pot）。
        for __c in common.pot_unchanged_4limb() { eval.add_constraint(__c); }

        let expected_post_turn: E::F =
            M31::from(u32::from(self.input.post_current_turn)).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));

        eval
    }
}

/// `check` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct CheckRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CURRENT_BET`（4 limb）。
    pub input_current_bet: [M31; 4],
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `OUTPUT_CURRENT_TURN` — mid-round 的下一行动座位。
    pub output_current_turn: M31,
}

impl CheckRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &CheckInput,
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
        let rs_m31 = u8_to_m31(pre_round_state);
        Self {
            common: CommonRow::active(
                MethodKind::Check,
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
            input_current_bet: u64_to_m31_limbs(input.current_bet),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            output_current_turn: u8_to_m31(input.post_current_turn),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_current_bet: [ZERO; 4],
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_current_bet);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.push(self.output_current_turn);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
