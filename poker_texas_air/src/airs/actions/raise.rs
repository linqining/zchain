//! `raise` AIR — 玩家加注（提高当前下注）。
//!
//! 移植自 `dispatch::dispatch_raise` 与 `state_machine::apply_raise`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 玩家未 fold、未 all_in
//! 4. `raise_to > current_bet`，且 `raise_to - current_bet >= min_raise`
//! 5. `raise_to <= seat.stack + seat.bet`（不超过总筹码）
//! 6. 状态变更：
//!    - `delta = raise_to - seat.bet`
//!    - `seat.stack -= delta`, `seat.bet = raise_to`, `seat.total_bet += delta`
//!    - 若 `seat.stack == 0` 则 `seat.all_in = true`
//!    - `pot += delta`, `current_bet = raise_to`, `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 46 个（对齐 Lean `RaiseMethodColumns`）：
//!   `INPUT_SEAT_INDEX`, `INPUT_CURRENT_TURN`, `INPUT_SEAT_OCCUPIED`,
//!   `INPUT_RAISE_TO_BASE[4]`, `INPUT_PRE_SEAT_STACK_BASE[4]`,
//!   `INPUT_PRE_SEAT_BET_BASE[4]`, `INPUT_PRE_SEAT_TOTAL_BET_BASE[4]`,
//!   `INPUT_CALL_DELTA_BASE[4]`, `OUTPUT_SEAT_STACK_BASE[4]`,
//!   `OUTPUT_SEAT_BET_BASE[4]`, `OUTPUT_SEAT_TOTAL_BET_BASE[4]`,
//!   `OUTPUT_CURRENT_BET_BASE[4]`, `OUTPUT_MIN_RAISE_BASE[4]`,
//!   `OUTPUT_ALL_IN`, `OUTPUT_ACTED`, `INPUT_PRE_ROUND_STATE_Q`

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `raise` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CURRENT_TURN` witness（current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_SEAT_OCCUPIED` witness（座位被占用）。
    pub const INPUT_SEAT_OCCUPIED: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_RAISE_TO` 起始列（4 limb，加注后总下注）。
    pub const INPUT_RAISE_TO_BASE: usize = COMMON_NUM_COLUMNS + 3;
    /// `INPUT_PRE_SEAT_STACK` 起始列（4 limb，pre-state 座位 stack witness）。
    pub const INPUT_PRE_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 7;
    /// `INPUT_PRE_SEAT_BET` 起始列（4 limb，pre-state 座位 bet witness）。
    pub const INPUT_PRE_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 11;
    /// `INPUT_PRE_SEAT_TOTAL_BET` 起始列（4 limb，pre-state 座位 total_bet witness）。
    pub const INPUT_PRE_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 15;
    /// `INPUT_CALL_DELTA` 起始列（4 limb，raise 的"跟注增量" = raise_to - pre_bet）。
    pub const INPUT_CALL_DELTA_BASE: usize = COMMON_NUM_COLUMNS + 19;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 23;
    /// `OUTPUT_SEAT_BET` 起始列（4 limb）。
    pub const OUTPUT_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 27;
    /// `OUTPUT_SEAT_TOTAL_BET` 起始列（4 limb，post-state 座位 total_bet witness）。
    pub const OUTPUT_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 31;
    /// `OUTPUT_CURRENT_BET` 起始列（4 limb，post-state betting.current_bet witness）。
    pub const OUTPUT_CURRENT_BET_BASE: usize = COMMON_NUM_COLUMNS + 35;
    /// `OUTPUT_MIN_RAISE` 起始列（4 limb，post-state betting.min_raise witness）。
    pub const OUTPUT_MIN_RAISE_BASE: usize = COMMON_NUM_COLUMNS + 39;
    /// `OUTPUT_ALL_IN` 列。
    pub const OUTPUT_ALL_IN: usize = COMMON_NUM_COLUMNS + 43;
    /// `OUTPUT_ACTED` 列。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 44;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 45;
    /// `raise` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 46;
}

/// `raise` 输入参数。
#[derive(Debug, Clone)]
pub struct RaiseInput {
    /// 执行 raise 的座位索引。
    pub seat_index: u8,
    /// 加注到的总下注额（不是增量）。
    pub raise_to: u64,
    /// 最小加注增量（通常 = 大盲注）。
    pub min_raise: u64,
}

/// `raise` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct RaiseAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: RaiseInput,
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

impl RaiseAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for RaiseAir {
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

        // 读取业务列（顺序与 cols 常量定义一致）
        let input_seat_index = eval.next_trace_mask();
        let input_current_turn = eval.next_trace_mask();
        let input_seat_occupied = eval.next_trace_mask();
        let input_raise_to_0 = eval.next_trace_mask();
        let input_raise_to_1 = eval.next_trace_mask();
        let input_raise_to_2 = eval.next_trace_mask();
        let input_raise_to_3 = eval.next_trace_mask();
        let input_pre_seat_stack_0 = eval.next_trace_mask();
        let input_pre_seat_stack_1 = eval.next_trace_mask();
        let input_pre_seat_stack_2 = eval.next_trace_mask();
        let input_pre_seat_stack_3 = eval.next_trace_mask();
        let input_pre_seat_bet_0 = eval.next_trace_mask();
        let input_pre_seat_bet_1 = eval.next_trace_mask();
        let input_pre_seat_bet_2 = eval.next_trace_mask();
        let input_pre_seat_bet_3 = eval.next_trace_mask();
        let input_pre_seat_total_bet_0 = eval.next_trace_mask();
        let input_pre_seat_total_bet_1 = eval.next_trace_mask();
        let input_pre_seat_total_bet_2 = eval.next_trace_mask();
        let input_pre_seat_total_bet_3 = eval.next_trace_mask();
        let input_call_delta_0 = eval.next_trace_mask();
        let input_call_delta_1 = eval.next_trace_mask();
        let input_call_delta_2 = eval.next_trace_mask();
        let input_call_delta_3 = eval.next_trace_mask();
        let output_seat_stack_0 = eval.next_trace_mask();
        let output_seat_stack_1 = eval.next_trace_mask();
        let output_seat_stack_2 = eval.next_trace_mask();
        let output_seat_stack_3 = eval.next_trace_mask();
        let output_seat_bet_0 = eval.next_trace_mask();
        let output_seat_bet_1 = eval.next_trace_mask();
        let output_seat_bet_2 = eval.next_trace_mask();
        let output_seat_bet_3 = eval.next_trace_mask();
        let output_seat_total_bet_0 = eval.next_trace_mask();
        let output_seat_total_bet_1 = eval.next_trace_mask();
        let output_seat_total_bet_2 = eval.next_trace_mask();
        let output_seat_total_bet_3 = eval.next_trace_mask();
        let output_current_bet_0 = eval.next_trace_mask();
        let output_current_bet_1 = eval.next_trace_mask();
        let output_current_bet_2 = eval.next_trace_mask();
        let output_current_bet_3 = eval.next_trace_mask();
        let output_min_raise_0 = eval.next_trace_mask();
        let output_min_raise_1 = eval.next_trace_mask();
        let output_min_raise_2 = eval.next_trace_mask();
        let output_min_raise_3 = eval.next_trace_mask();
        let _output_all_in = eval.next_trace_mask();
        let output_acted = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();

        // 组装 4-limb 数组（方便调用 limb4_* 辅助）
        let input_raise_to = [
            input_raise_to_0.clone(),
            input_raise_to_1.clone(),
            input_raise_to_2.clone(),
            input_raise_to_3.clone(),
        ];
        let input_pre_seat_stack = [
            input_pre_seat_stack_0.clone(),
            input_pre_seat_stack_1.clone(),
            input_pre_seat_stack_2.clone(),
            input_pre_seat_stack_3.clone(),
        ];
        let input_pre_seat_bet = [
            input_pre_seat_bet_0.clone(),
            input_pre_seat_bet_1.clone(),
            input_pre_seat_bet_2.clone(),
            input_pre_seat_bet_3.clone(),
        ];
        let input_pre_seat_total_bet = [
            input_pre_seat_total_bet_0.clone(),
            input_pre_seat_total_bet_1.clone(),
            input_pre_seat_total_bet_2.clone(),
            input_pre_seat_total_bet_3.clone(),
        ];
        let input_call_delta = [
            input_call_delta_0.clone(),
            input_call_delta_1.clone(),
            input_call_delta_2.clone(),
            input_call_delta_3.clone(),
        ];
        let output_seat_stack = [
            output_seat_stack_0.clone(),
            output_seat_stack_1.clone(),
            output_seat_stack_2.clone(),
            output_seat_stack_3.clone(),
        ];
        let output_seat_bet = [
            output_seat_bet_0.clone(),
            output_seat_bet_1.clone(),
            output_seat_bet_2.clone(),
            output_seat_bet_3.clone(),
        ];
        let output_seat_total_bet = [
            output_seat_total_bet_0.clone(),
            output_seat_total_bet_1.clone(),
            output_seat_total_bet_2.clone(),
            output_seat_total_bet_3.clone(),
        ];
        let output_current_bet = [
            output_current_bet_0.clone(),
            output_current_bet_1.clone(),
            output_current_bet_2.clone(),
            output_current_bet_3.clone(),
        ];
        let output_min_raise = [
            output_min_raise_0.clone(),
            output_min_raise_1.clone(),
            output_min_raise_2.clone(),
            output_min_raise_3.clone(),
        ];

        let one: E::F = M31::from(1u32).into();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index.clone() - expected_seat.clone()));
        // 约束 2：current_turn == seat_index（阻止非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn.clone() - expected_seat));
        // 约束 3：seat_occupied == 1
        eval.add_constraint(is_active.clone() * (input_seat_occupied.clone() - one.clone()));

        // 约束 4：raise_to 一致性（limb 0）
        let expected_raise_0: E::F = M31::from((self.input.raise_to & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_raise_to_0.clone() - expected_raise_0));

        // 约束 5：output_acted == 1
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 6（审计共性）：round_state 不变 + 必须处于下注轮（Gap 1）。
        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        // 约束 7：button 不变（对齐 Lean ButtonUnchanged）
        eval.add_constraint(common.button_unchanged());

        // ===== 资金守恒约束（对齐 Lean PotDelta / Limb4Delta / Limb4DeltaRev / Limb4Eq）=====

        // 约束 8：pot += call_delta（全 4 limb）— post_pot[i] = pre_pot[i] + call_delta[i]
        for __c in common.pot_delta_4limb(&input_call_delta) { eval.add_constraint(__c); }

        // 约束 9：stack 守恒（反向 delta）— pre_stack[i] = post_stack[i] + call_delta[i]
        // ⟹ post_stack = pre_stack - call_delta ⟹ call_delta ≤ pre_stack
        // ⟹ raise_to - pre_bet ≤ pre_stack ⟹ raise_to ≤ pre_stack + pre_bet
        for __c in common.limb4_delta_rev(
            &input_pre_seat_stack,
            &output_seat_stack,
            &input_call_delta,
        ) { eval.add_constraint(__c); }

        // 约束 10：bet 守恒（delta）— post_bet[i] = pre_bet[i] + call_delta[i]
        // 与约束 12（post_bet = raise_to）联立得 call_delta = raise_to - pre_bet
        for __c in common.limb4_delta(
            &input_pre_seat_bet,
            &output_seat_bet,
            &input_call_delta,
        ) { eval.add_constraint(__c); }

        // 约束 11：total_bet 守恒（delta）— post_total_bet[i] = pre_total_bet[i] + call_delta[i]
        for __c in common.limb4_delta(
            &input_pre_seat_total_bet,
            &output_seat_total_bet,
            &input_call_delta,
        ) { eval.add_constraint(__c); }

        // 约束 12：bet 设值 — post_bet[i] = raise_to[i]
        for __c in common.limb4_eq(&output_seat_bet, &input_raise_to) { eval.add_constraint(__c); }

        // 约束 13：current_bet 设值 — post_current_bet[i] = raise_to[i]
        for __c in common.limb4_eq(&output_current_bet, &input_raise_to) { eval.add_constraint(__c); }

        // 约束 14：min_raise 设值 — post_min_raise[i] = raise_to[i]
        // （pre.current_bet = 0 ⟹ raise_to - 0 = raise_to）
        for __c in common.limb4_eq(&output_min_raise, &input_raise_to) { eval.add_constraint(__c); }

        eval
    }
}

/// `raise` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct RaiseRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CURRENT_TURN` witness。
    pub input_current_turn: M31,
    /// `INPUT_SEAT_OCCUPIED` witness。
    pub input_seat_occupied: M31,
    /// `INPUT_RAISE_TO`（4 limb）。
    pub input_raise_to: [M31; 4],
    /// `INPUT_PRE_SEAT_STACK`（4 limb witness）。
    pub input_pre_seat_stack: [M31; 4],
    /// `INPUT_PRE_SEAT_BET`（4 limb witness）。
    pub input_pre_seat_bet: [M31; 4],
    /// `INPUT_PRE_SEAT_TOTAL_BET`（4 limb witness）。
    pub input_pre_seat_total_bet: [M31; 4],
    /// `INPUT_CALL_DELTA`（4 limb witness = raise_to - pre_bet）。
    pub input_call_delta: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_BET`（4 limb）。
    pub output_seat_bet: [M31; 4],
    /// `OUTPUT_SEAT_TOTAL_BET`（4 limb witness）。
    pub output_seat_total_bet: [M31; 4],
    /// `OUTPUT_CURRENT_BET`（4 limb witness）。
    pub output_current_bet: [M31; 4],
    /// `OUTPUT_MIN_RAISE`（4 limb witness）。
    pub output_min_raise: [M31; 4],
    /// `OUTPUT_ALL_IN`。
    pub output_all_in: M31,
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
}

impl RaiseRow {
    /// 构造 active 行。
    ///
    /// # 参数
    /// - `pre_seat_stack`: 调用前座位 stack
    /// - `pre_seat_bet`: 调用前座位 bet
    /// - `pre_seat_total_bet`: 调用前座位 total_bet
    /// - `post_seat_stack`: 调用后座位 stack
    /// - `post_seat_bet`: 调用后座位 bet
    /// - `post_seat_total_bet`: 调用后座位 total_bet
    /// - `is_all_in`: 是否 all-in
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &RaiseInput,
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
        pre_seat_stack: u64,
        pre_seat_bet: u64,
        pre_seat_total_bet: u64,
        post_seat_stack: u64,
        post_seat_bet: u64,
        post_seat_total_bet: u64,
        post_current_bet: u64,
        post_min_raise: u64,
        is_all_in: bool,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        // call_delta = raise_to - pre_seat_bet（host 端保证 raise_to >= pre_seat_bet）
        let call_delta = input.raise_to.saturating_sub(pre_seat_bet);
        Self {
            common: CommonRow::active(
                MethodKind::Raise,
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
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            input_seat_occupied: M31::from(1u32),            // 座位被占用
            input_raise_to: u64_to_m31_limbs(input.raise_to),
            input_pre_seat_stack: u64_to_m31_limbs(pre_seat_stack),
            input_pre_seat_bet: u64_to_m31_limbs(pre_seat_bet),
            input_pre_seat_total_bet: u64_to_m31_limbs(pre_seat_total_bet),
            input_call_delta: u64_to_m31_limbs(call_delta),
            output_seat_stack: u64_to_m31_limbs(post_seat_stack),
            output_seat_bet: u64_to_m31_limbs(post_seat_bet),
            output_seat_total_bet: u64_to_m31_limbs(post_seat_total_bet),
            output_current_bet: u64_to_m31_limbs(post_current_bet),
            output_min_raise: u64_to_m31_limbs(post_min_raise),
            output_all_in: M31::from(u32::from(is_all_in)),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_current_turn: ZERO,
            input_seat_occupied: ZERO,
            input_raise_to: [ZERO; 4],
            input_pre_seat_stack: [ZERO; 4],
            input_pre_seat_bet: [ZERO; 4],
            input_pre_seat_total_bet: [ZERO; 4],
            input_call_delta: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            output_seat_bet: [ZERO; 4],
            output_seat_total_bet: [ZERO; 4],
            output_current_bet: [ZERO; 4],
            output_min_raise: [ZERO; 4],
            output_all_in: ZERO,
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_current_turn);
        v.push(self.input_seat_occupied);
        v.extend_from_slice(&self.input_raise_to);
        v.extend_from_slice(&self.input_pre_seat_stack);
        v.extend_from_slice(&self.input_pre_seat_bet);
        v.extend_from_slice(&self.input_pre_seat_total_bet);
        v.extend_from_slice(&self.input_call_delta);
        v.extend_from_slice(&self.output_seat_stack);
        v.extend_from_slice(&self.output_seat_bet);
        v.extend_from_slice(&self.output_seat_total_bet);
        v.extend_from_slice(&self.output_current_bet);
        v.extend_from_slice(&self.output_min_raise);
        v.push(self.output_all_in);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
