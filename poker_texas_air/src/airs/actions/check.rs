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

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
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
    /// `check` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 6;
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
        let common = CommonConstraints::write(&mut eval, MethodKind::Check, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_current_bet_0 = eval.next_trace_mask();
        let _input_current_bet_1 = eval.next_trace_mask();
        let _input_current_bet_2 = eval.next_trace_mask();
        let _input_current_bet_3 = eval.next_trace_mask();
        let output_acted = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

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

        // 约束 4（审计共性，degree-2）：round_state 不变（check 不改变下注阶段）。
        eval.add_constraint(common.round_state_unchanged());
        // 约束 5（审计共性，degree-2 limb0）：pot 不变（check 不改变 pot）。
        eval.add_constraint(common.pot_unchanged_limb0());

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
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_current_bet);
        v.push(self.output_acted);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
