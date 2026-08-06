//! `auto_fold` AIR — 玩家超时自动 fold（仅 table creator 可发起）。
//!
//! 移植自 `dispatch::dispatch_auto_fold` 与 `state_machine::apply_auto_fold`。
//!
//! ## 业务规约
//!
//! 1. 当前处于下注轮
//! 2. `seat_index == current_turn`
//! 3. 玩家未 fold、未 all_in
//! 4. 触发条件：`current_time - turn_started_at >= turn_timeout`
//! 5. 状态变更：`seat.folded = true`, `version += 1`
//!
//! 与 [`crate::airs::actions::fold`] 的区别：
//! - `fold`：玩家主动操作
//! - `auto_fold`：由 table creator 在超时后发起
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 42 个：seat、完整 timeout 输入、64-bit 饱和 deadline 加法和
//!   `current_time >= deadline` 的借位证明，以及 fold/turn 输出。
//!
//! `DispatchContext::block_timestamp` 是 consensus input。该值由
//! `Orchestrator` 从重放的 dispatch task 取出，而非由 prover 自行选择。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31, u64_to_m31_limbs,
};
use crate::method_kind::MethodKind;

/// `auto_fold` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_CURRENT_TIME` 起始列（4 limb）。
    pub const INPUT_CURRENT_TIME_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_FOLDED` 列。
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub const INPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 7;
    /// `OUTPUT_CURRENT_TURN` — mid-round 推进后的下一行动座位。
    pub const OUTPUT_CURRENT_TURN: usize = COMMON_NUM_COLUMNS + 8;
    /// `PRE_BETTING_STARTED_AT` 起始列（4 limb）。
    pub const PRE_BETTING_STARTED_AT_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `BETTING_TIMEOUT_MS` 起始列（4 limb）。
    pub const BETTING_TIMEOUT_MS_BASE: usize = COMMON_NUM_COLUMNS + 13;
    /// 目标座位调用前 `time_bank_ms` 起始列（4 limb）。
    pub const PRE_TIME_BANK_MS_BASE: usize = COMMON_NUM_COLUMNS + 17;
    /// `started + timeout` 的模 `2^64` 和起始列（4 limb）。
    pub const DEADLINE_SUM_BASE: usize = COMMON_NUM_COLUMNS + 21;
    /// 饱和后的 deadline 起始列（4 limb）。
    pub const DEADLINE_BASE: usize = COMMON_NUM_COLUMNS + 25;
    /// deadline 加法的三个 limb carry 起始列。
    pub const DEADLINE_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 29;
    /// deadline 加法的最终 overflow witness。
    pub const DEADLINE_ADD_OVERFLOW: usize = COMMON_NUM_COLUMNS + 32;
    /// `current_time - deadline` 的差起始列（4 limb）。
    pub const TIME_ELAPSED_BASE: usize = COMMON_NUM_COLUMNS + 33;
    /// `current_time - deadline` 的四个 limb borrow 起始列。
    pub const TIME_SUB_BORROW_BASE: usize = COMMON_NUM_COLUMNS + 37;
    /// `betting_started_at != 0` 的非零逆元 witness。
    pub const PRE_BETTING_STARTED_AT_INV: usize = COMMON_NUM_COLUMNS + 41;
    /// `auto_fold` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 42;
}

/// `auto_fold` 输入参数。
#[derive(Debug, Clone)]
pub struct AutoFoldInput {
    /// 超时被自动 fold 的座位索引。
    pub seat_index: u8,
    /// 触发时的当前时间戳。
    pub current_time: u64,
    /// 调用前本轮下注计时开始时间。
    pub pre_betting_started_at: u64,
    /// 调用前下注超时配置。
    pub betting_timeout_ms: u64,
    /// 目标座位调用前的 Time Bank 余额。
    pub pre_time_bank_ms: u64,
    /// mid-round 推进后的下一行动座位。
    pub post_current_turn: u8,
}

/// `auto_fold` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct AutoFoldAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: AutoFoldInput,
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

impl AutoFoldAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for AutoFoldAir {
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
        let input_current_time = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let output_folded = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();
        // Gap: current_turn == seat_index witness
        let input_current_turn = eval.next_trace_mask();
        let output_current_turn = eval.next_trace_mask();
        let pre_betting_started_at = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let betting_timeout_ms = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_time_bank_ms = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_sum = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_add_overflow = eval.next_trace_mask();
        let time_elapsed = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let time_sub_borrow = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_betting_started_at_inv = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat.clone()));
        // 约束: current_turn == seat_index（Gap: 阻止为非当前行动座位构造动作）
        eval.add_constraint(is_active.clone() * (input_current_turn - expected_seat));

        // 约束 2：所有 timeout 输入都与 trusted AIR statement 完整绑定；此前只
        // 绑定 current_time 的 limb 0，会允许跨 16-bit 边界的伪造时间戳。
        let expected_current_time = u64_to_m31_limbs(self.input.current_time);
        let expected_started_at = u64_to_m31_limbs(self.input.pre_betting_started_at);
        let expected_timeout = u64_to_m31_limbs(self.input.betting_timeout_ms);
        let expected_time_bank = u64_to_m31_limbs(self.input.pre_time_bank_ms);
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (input_current_time[i].clone() - expected_current_time[i].into()),
            );
            eval.add_constraint(
                is_active.clone()
                    * (pre_betting_started_at[i].clone() - expected_started_at[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (betting_timeout_ms[i].clone() - expected_timeout[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (pre_time_bank_ms[i].clone() - expected_time_bank[i].into()),
            );
            // L1 rejects auto-fold while any Time Bank remains. Enforce every
            // limb, not merely the low limb, to prevent a high-limb bypass.
            eval.add_constraint(is_active.clone() * pre_time_bank_ms[i].clone());
        }

        // `betting_started_at == 0` means the timer was never started and is
        // explicitly rejected by dispatch. The limbs are canonical 16-bit
        // values, so their M31 sum is zero iff all four limbs are zero.
        let started_sum = pre_betting_started_at[0].clone()
            + pre_betting_started_at[1].clone()
            + pre_betting_started_at[2].clone()
            + pre_betting_started_at[3].clone();
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(
            is_active.clone() * (started_sum * pre_betting_started_at_inv - one.clone()),
        );

        // `deadline = started.saturating_add(timeout)`. First prove the
        // 64-bit limb addition (including its final overflow bit), then select
        // the wrapping sum or u64::MAX exactly as Rust's saturating_add does.
        let limb_base: E::F = M31::from(1u32 << 16).into();
        for carry in deadline_add_carry.iter() {
            eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
        }
        eval.add_constraint(
            deadline_add_overflow.clone() * (deadline_add_overflow.clone() - one.clone()),
        );
        eval.add_constraint(
            pre_betting_started_at[0].clone() + betting_timeout_ms[0].clone()
                - deadline_sum[0].clone()
                - limb_base.clone() * deadline_add_carry[0].clone(),
        );
        for i in 1..3 {
            eval.add_constraint(
                pre_betting_started_at[i].clone()
                    + betting_timeout_ms[i].clone()
                    + deadline_add_carry[i - 1].clone()
                    - deadline_sum[i].clone()
                    - limb_base.clone() * deadline_add_carry[i].clone(),
            );
        }
        eval.add_constraint(
            pre_betting_started_at[3].clone()
                + betting_timeout_ms[3].clone()
                + deadline_add_carry[2].clone()
                - deadline_sum[3].clone()
                - limb_base.clone() * deadline_add_overflow.clone(),
        );
        let limb_max: E::F = M31::from(0xFFFFu32).into();
        for i in 0..4 {
            eval.add_constraint(
                deadline[i].clone()
                    - deadline_sum[i].clone()
                    - deadline_add_overflow.clone() * (limb_max.clone() - deadline_sum[i].clone()),
            );
        }

        // Prove `current_time >= deadline` through a complete little-endian
        // 4×16-bit subtraction. The final borrow must be zero; this is the
        // exact unsigned comparison, including high-limb / borrow boundaries.
        for borrow in time_sub_borrow.iter() {
            eval.add_constraint(borrow.clone() * (borrow.clone() - one.clone()));
        }
        eval.add_constraint(
            input_current_time[0].clone() - deadline[0].clone()
                + limb_base.clone() * time_sub_borrow[0].clone()
                - time_elapsed[0].clone(),
        );
        for i in 1..4 {
            eval.add_constraint(
                input_current_time[i].clone()
                    - deadline[i].clone()
                    - time_sub_borrow[i - 1].clone()
                    + limb_base.clone() * time_sub_borrow[i].clone()
                    - time_elapsed[i].clone(),
            );
        }
        eval.add_constraint(time_sub_borrow[3].clone());

        // 约束 3：output_folded == 1
        eval.add_constraint(is_active.clone() * (output_folded - one));

        // 约束 4（审计共性）：round_state 不变 + 必须处于下注轮（Gap 1）。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}。
        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));
        // 约束 5（审计共性）：pot 完整 4-limb 不变（auto_fold 不改变 pot）。
        for __c in common.pot_unchanged_4limb() {
            eval.add_constraint(__c);
        }

        let expected_post_turn: E::F = M31::from(u32::from(self.input.post_current_turn)).into();
        eval.add_constraint(is_active * (output_current_turn - expected_post_turn));

        eval
    }
}

/// `auto_fold` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct AutoFoldRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_CURRENT_TIME`（4 limb）。
    pub input_current_time: [M31; 4],
    /// `OUTPUT_FOLDED`。
    pub output_folded: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
    /// `INPUT_CURRENT_TURN` witness（Gap: current_turn == seat_index）。
    pub input_current_turn: M31,
    /// `OUTPUT_CURRENT_TURN` — mid-round 的下一行动座位。
    pub output_current_turn: M31,
    /// 调用前下注计时开始时间。
    pub pre_betting_started_at: [M31; 4],
    /// 下注超时配置。
    pub betting_timeout_ms: [M31; 4],
    /// 目标座位调用前 Time Bank。
    pub pre_time_bank_ms: [M31; 4],
    /// `started + timeout` 的模 `2^64` 结果。
    pub deadline_sum: [M31; 4],
    /// Rust `saturating_add` 后的 deadline。
    pub deadline: [M31; 4],
    /// `deadline_sum` 加法的中间 carries。
    pub deadline_add_carry: [M31; 3],
    /// `deadline_sum` 加法是否发生 u64 overflow。
    pub deadline_add_overflow: M31,
    /// `current_time - deadline` 的 4-limb 差。
    pub time_elapsed: [M31; 4],
    /// `current_time - deadline` 的 4-limb borrows（最高 limb 必须为 0）。
    pub time_sub_borrow: [M31; 4],
    /// `pre_betting_started_at` 全零检查的逆元。
    pub pre_betting_started_at_inv: M31,
}

impl AutoFoldRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &AutoFoldInput,
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
        let rs_m31 = u8_to_m31(pre_round_state);
        let pre_betting_started_at = u64_to_m31_limbs(input.pre_betting_started_at);
        let betting_timeout_ms = u64_to_m31_limbs(input.betting_timeout_ms);
        let pre_time_bank_ms = u64_to_m31_limbs(input.pre_time_bank_ms);
        let (deadline_sum_u64, deadline_overflow) = input
            .pre_betting_started_at
            .overflowing_add(input.betting_timeout_ms);
        let deadline_u64 = input
            .pre_betting_started_at
            .saturating_add(input.betting_timeout_ms);
        let deadline_sum = u64_to_m31_limbs(deadline_sum_u64);
        let deadline = u64_to_m31_limbs(deadline_u64);

        let mut add_carry = 0u32;
        let mut deadline_add_carry = [ZERO; 3];
        for i in 0..3 {
            let sum = pre_betting_started_at[i].0 + betting_timeout_ms[i].0 + add_carry;
            add_carry = sum >> 16;
            deadline_add_carry[i] = M31::from(add_carry);
        }

        let current_time = u64_to_m31_limbs(input.current_time);
        let mut time_elapsed = [ZERO; 4];
        let mut time_sub_borrow = [ZERO; 4];
        let mut borrow = 0i64;
        for i in 0..4 {
            let difference = i64::from(current_time[i].0) - i64::from(deadline[i].0) - borrow;
            if difference < 0 {
                time_elapsed[i] = M31::from((difference + (1_i64 << 16)) as u32);
                borrow = 1;
            } else {
                time_elapsed[i] = M31::from(difference as u32);
                borrow = 0;
            }
            time_sub_borrow[i] = M31::from(borrow as u32);
        }
        let started_limb_sum = pre_betting_started_at
            .iter()
            .fold(ZERO, |sum, limb| sum + *limb);
        let pre_betting_started_at_inv = if started_limb_sum == ZERO {
            ZERO
        } else {
            started_limb_sum.inverse()
        };
        Self {
            common: CommonRow::active(
                MethodKind::AutoFold,
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
            input_current_time: current_time,
            output_folded: M31::from(1u32),
            // Gap 1 witness：pre_round_state²（M31 域内）
            input_pre_round_state_q: rs_m31 * rs_m31,
            input_current_turn: u8_to_m31(input.seat_index), // current_turn == seat_index
            output_current_turn: u8_to_m31(input.post_current_turn),
            pre_betting_started_at,
            betting_timeout_ms,
            pre_time_bank_ms,
            deadline_sum,
            deadline,
            deadline_add_carry,
            deadline_add_overflow: M31::from(u32::from(deadline_overflow)),
            time_elapsed,
            time_sub_borrow,
            pre_betting_started_at_inv,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_current_time: [ZERO; 4],
            output_folded: ZERO,
            input_pre_round_state_q: ZERO,
            input_current_turn: ZERO,
            output_current_turn: ZERO,
            pre_betting_started_at: [ZERO; 4],
            betting_timeout_ms: [ZERO; 4],
            pre_time_bank_ms: [ZERO; 4],
            deadline_sum: [ZERO; 4],
            deadline: [ZERO; 4],
            deadline_add_carry: [ZERO; 3],
            deadline_add_overflow: ZERO,
            time_elapsed: [ZERO; 4],
            time_sub_borrow: [ZERO; 4],
            pre_betting_started_at_inv: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_current_time);
        v.push(self.output_folded);
        v.push(self.input_pre_round_state_q);
        v.push(self.input_current_turn);
        v.push(self.output_current_turn);
        v.extend_from_slice(&self.pre_betting_started_at);
        v.extend_from_slice(&self.betting_timeout_ms);
        v.extend_from_slice(&self.pre_time_bank_ms);
        v.extend_from_slice(&self.deadline_sum);
        v.extend_from_slice(&self.deadline);
        v.extend_from_slice(&self.deadline_add_carry);
        v.push(self.deadline_add_overflow);
        v.extend_from_slice(&self.time_elapsed);
        v.extend_from_slice(&self.time_sub_borrow);
        v.push(self.pre_betting_started_at_inv);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
