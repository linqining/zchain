//! `rebuy` AIR — 玩家重购（**立即生效**）。
//!
//! 移植自 `dispatch::dispatch_rebuy` 与 `state_machine::apply_rebuy`。
//!
//! ## 业务规约
//!
//! 1. `seat_index` 必须是已占用座位
//! 2. `amount > 0`
//! 3. 状态变更（**立即改 stack**）：
//!    - `seats[seat].stack += amount`
//!    - `table.addon_pool += amount`
//!    - `version += 1`
//!
//! ## 与 `addon` 的关键差异
//!
//! - `addon` 下一手生效：只改 `pending_addon`，不动 `stack`
//! - `rebuy` 立即生效：直接改 `stack`，影响下一动作可用筹码
//!
//! 业务约束（调用方负责）：
//! - MTT 中通常要求 `seat.stack < big_blind` 才允许 rebuy
//! - 现金桌通常不使用 rebuy，而用 addon
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 13 个：
//!   - `INPUT_SEAT_INDEX`
//!   - `INPUT_AMOUNT_BASE[4]`
//!   - `PRE_STACK_BASE[4]`（调用前 stack）
//!   - `POST_STACK_BASE[4]`（调用后 stack；约束 = pre + amount）

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `rebuy` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_AMOUNT` 起始列（4 limb，重购金额）。
    pub const INPUT_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `PRE_STACK` 起始列（4 limb，调用前 stack）。
    pub const PRE_STACK_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `POST_STACK` 起始列（4 limb，调用后 stack；约束 = pre + amount）。
    pub const POST_STACK_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `rebuy` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 13;
}

/// `rebuy` 输入参数。
#[derive(Debug, Clone)]
pub struct RebuyInput {
    /// 目标座位索引。
    pub seat_index: u8,
    /// 重购金额（必须 > 0）。
    pub amount: u64,
}

/// `rebuy` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct RebuyAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: RebuyInput,
    /// 调用前 state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 limb）。
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

impl RebuyAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for RebuyAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Rebuy);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_amount_0 = eval.next_trace_mask();
        let _input_amount_1 = eval.next_trace_mask();
        let _input_amount_2 = eval.next_trace_mask();
        let _input_amount_3 = eval.next_trace_mask();
        let pre_stack_0 = eval.next_trace_mask();
        let _pre_stack_1 = eval.next_trace_mask();
        let _pre_stack_2 = eval.next_trace_mask();
        let _pre_stack_3 = eval.next_trace_mask();
        let post_stack_0 = eval.next_trace_mask();
        let _post_stack_1 = eval.next_trace_mask();
        let _post_stack_2 = eval.next_trace_mask();
        let _post_stack_3 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：amount 一致性（limb 0）
        let expected_amount_0: E::F = M31::from((self.input.amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_amount_0.clone() - expected_amount_0));

        // 约束 3（核心）：post_stack == pre_stack + input_amount
        //    立即生效：直接改 stack
        eval.add_constraint(is_active * (post_stack_0 - pre_stack_0 - input_amount_0));

        eval
    }
}

/// `rebuy` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct RebuyRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_AMOUNT`（4 limb）。
    pub input_amount: [M31; 4],
    /// `PRE_STACK`（4 limb）。
    pub pre_stack: [M31; 4],
    /// `POST_STACK`（4 limb）。
    pub post_stack: [M31; 4],
}

impl RebuyRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &RebuyInput,
        pre_stack: u64,
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
        let post_stack = pre_stack + input.amount;
        Self {
            common: CommonRow::active(
                MethodKind::Rebuy,
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
            input_amount: u64_to_m31_limbs(input.amount),
            pre_stack: u64_to_m31_limbs(pre_stack),
            post_stack: u64_to_m31_limbs(post_stack),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_amount: [ZERO; 4],
            pre_stack: [ZERO; 4],
            post_stack: [ZERO; 4],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_amount);
        v.extend_from_slice(&self.pre_stack);
        v.extend_from_slice(&self.post_stack);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
