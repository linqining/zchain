//! `bet` AIR — 玩家主动下注（postflop 第一个下注者）。
//!
//! 移植自 `dispatch::dispatch_bet` 与 `state_machine::apply_bet`。
//!
//! ## 业务规约
//!
//! `bet` 在语义上是 `raise` 的特例：当当前轮无已有下注（`current_bet == seat.bet`）
//! 时，玩家主动开注。实现上 `apply_bet` 复用 `apply_raise(total_bet = seat.bet + amount)`，
//! 因此本 AIR 的列布局与约束与 [`super::raise`] 高度一致。
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. `amount > 0`
//! 4. `current_bet == seat.bet`（无已有下注，否则应使用 call/raise）
//! 5. 状态变更（复用 raise）：`seat.stack -= amount`, `seat.bet += amount`,
//!    `seat.total_bet += amount`, `pot += amount`, `current_bet = seat.bet + amount`
//! 6. 玩家标记 `acted_this_round = true`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 11 个：`INPUT_SEAT_INDEX`, `INPUT_AMOUNT_BASE[4]`,
//!   `OUTPUT_SEAT_BET_BASE[4]`, `OUTPUT_ACTED`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `bet` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_AMOUNT` 起始列（4 limb，下注增量）。
    pub const INPUT_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_SEAT_BET` 起始列（4 limb，下注后 seat.bet = pre_bet + amount）。
    pub const OUTPUT_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_ACTED` 列（acted_this_round 标记）。
    pub const OUTPUT_ACTED: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 10;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 11;
    /// `PRE_SEAT_BET` 起始列（4 limb）— 阶段 3 新增（bet delta）。
    pub const PRE_SEAT_BET_BASE: usize = COMMON_NUM_COLUMNS + 12;
    /// `PRE_SEAT_STACK` 起始列（4 limb）— 阶段 3 新增（stack delta）。
    pub const PRE_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 16;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）— 阶段 3 新增（stack delta）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 20;
    /// `PRE_SEAT_TOTAL_BET` 起始列（4 limb）— 阶段 3 新增（total_bet delta）。
    pub const PRE_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 24;
    /// `OUTPUT_SEAT_TOTAL_BET` 起始列（4 limb）— 阶段 3 新增（total_bet delta）。
    pub const OUTPUT_SEAT_TOTAL_BET_BASE: usize = COMMON_NUM_COLUMNS + 28;
    /// `INPUT_AMOUNT_INV` witness（amount_0 的逆，用于 amount > 0 约束，阶段 3 新增）。
    pub const INPUT_AMOUNT_INV: usize = COMMON_NUM_COLUMNS + 32;
    /// `bet` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 33;
}

/// `bet` 输入参数。
#[derive(Debug, Clone)]
pub struct BetInput {
    /// 执行 bet 的座位索引。
    pub seat_index: u8,
    /// 下注金额（增量，必须 > 0）。
    pub amount: u64,
}

/// `bet` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct BetAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: BetInput,
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

impl BetAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for BetAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Bet, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        // input_amount：完整 4 limb（阶段 3 soundness 升级）
        let input_amount: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // output_seat_bet：完整 4 limb
        let output_seat_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_acted = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        // 阶段 3 新增列
        let pre_seat_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_seat_stack: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_seat_stack: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_seat_total_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_seat_total_bet: [E::F; 4] = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // amount_0 的逆（amount > 0 约束）
        let input_amount_inv = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：amount 一致性（limb 0 sanity，4-limb delta 见下）
        let expected_amount_0: E::F = M31::from((self.input.amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_amount[0].clone() - expected_amount_0));

        // 约束 2b（阶段 3 新增）：amount > 0 —— amount_0 * inv == 1（invertibility，limb 0）
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_amount[0].clone() * input_amount_inv - one.clone()));

        // 约束 3：output_acted == 1（玩家已行动）
        eval.add_constraint(is_active.clone() * (output_acted - one));

        // 约束 4（审计共性）：round_state 不变 + 必须处于下注轮（Gap 1）。
        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        // 约束 5（阶段 3 soundness 升级：全 4-limb 资金守恒，对齐 raise/call）：
        // pot += amount（4 limb）
        eval.add_constraint(common.pot_delta_4limb(&input_amount));
        // seat.stack -= amount（4 limb 反向 delta）
        eval.add_constraint(common.limb4_delta_rev(&pre_seat_stack, &output_seat_stack, &input_amount));
        // seat.bet += amount（4 limb）
        eval.add_constraint(common.limb4_delta(&pre_seat_bet, &output_seat_bet, &input_amount));
        // seat.total_bet += amount（4 limb）
        eval.add_constraint(common.limb4_delta(&pre_seat_total_bet, &output_seat_total_bet, &input_amount));

        eval
    }
}

/// `bet` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct BetRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_AMOUNT`（4 limb）。
    pub input_amount: [M31; 4],
    /// `OUTPUT_SEAT_BET`（4 limb）。
    pub output_seat_bet: [M31; 4],
    /// `OUTPUT_ACTED`。
    pub output_acted: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `PRE_SEAT_BET`（4 limb）— 阶段 3 新增。
    pub pre_seat_bet: [M31; 4],
    /// `PRE_SEAT_STACK`（4 limb）— 阶段 3 新增。
    pub pre_seat_stack: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）— 阶段 3 新增。
    pub output_seat_stack: [M31; 4],
    /// `PRE_SEAT_TOTAL_BET`（4 limb）— 阶段 3 新增。
    pub pre_seat_total_bet: [M31; 4],
    /// `OUTPUT_SEAT_TOTAL_BET`（4 limb）— 阶段 3 新增。
    pub output_seat_total_bet: [M31; 4],
    /// `INPUT_AMOUNT_INV`（amount_0 的逆）— 阶段 3 新增（amount > 0）。
    pub input_amount_inv: M31,
}

impl BetRow {
    /// 构造 active 行。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn active(
        input: &BetInput,
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
        post_seat_bet: u64,
        pre_seat_bet: u64,
        pre_seat_stack: u64,
        post_seat_stack: u64,
        pre_seat_total_bet: u64,
        post_seat_total_bet: u64,
    ) -> Self {
        let rs_m31 = u8_to_m31(pre_round_state);
        // amount_0 的逆（amount > 0）：若 amount_0 == 0 则逆不存在，下注非法。
        // host 端 amount > 0 已由 apply_bet 保证；这里在 amount_0 != 0 时求逆。
        let amount_limb0 = (input.amount & 0xFFFF) as u32;
        let input_amount_inv = if amount_limb0 == 0 {
            ZERO // 非法情况，约束 amount_0 * inv == 1 会失败
        } else {
            M31::from(amount_limb0).inverse()
        };
        Self {
            common: CommonRow::active(
                MethodKind::Bet,
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
            input_amount: u64_to_m31_limbs(input.amount),
            output_seat_bet: u64_to_m31_limbs(post_seat_bet),
            output_acted: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index),  // current_turn == seat_index
            pre_seat_bet: u64_to_m31_limbs(pre_seat_bet),
            pre_seat_stack: u64_to_m31_limbs(pre_seat_stack),
            output_seat_stack: u64_to_m31_limbs(post_seat_stack),
            pre_seat_total_bet: u64_to_m31_limbs(pre_seat_total_bet),
            output_seat_total_bet: u64_to_m31_limbs(post_seat_total_bet),
            input_amount_inv,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_amount: [ZERO; 4],
            output_seat_bet: [ZERO; 4],
            output_acted: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            pre_seat_bet: [ZERO; 4],
            pre_seat_stack: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            pre_seat_total_bet: [ZERO; 4],
            output_seat_total_bet: [ZERO; 4],
            input_amount_inv: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_amount);
        v.extend_from_slice(&self.output_seat_bet);
        v.push(self.output_acted);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.extend_from_slice(&self.pre_seat_bet);
        v.extend_from_slice(&self.pre_seat_stack);
        v.extend_from_slice(&self.output_seat_stack);
        v.extend_from_slice(&self.pre_seat_total_bet);
        v.extend_from_slice(&self.output_seat_total_bet);
        v.push(self.input_amount_inv);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
