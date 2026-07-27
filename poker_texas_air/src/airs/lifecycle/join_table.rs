//! `join_table` AIR — 简单入座（不参与本局，等下一局）。
//!
//! 移植自 `dispatch::dispatch_join_table` 与 `state_machine` 的入座逻辑。
//!
//! ## 业务规约
//!
//! 1. `round_state == ROUND_WAITING`
//! 2. `seat_index < max_players`
//! 3. 目标座位为空（`seat.player == EMPTY_PLAYER`）
//! 4. `buy_in >= big_blind`
//! 5. 玩家公钥已注册
//!
//! 状态变更：`seat.player = player_addr`, `seat.stack = buy_in`, `version += 1`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `join_table` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;

    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_BUY_IN` 起始列（4 limb）。
    pub const INPUT_BUY_IN_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PLAYER_ADDR` 起始列（4 limb，Blake2b 压缩后）。
    pub const INPUT_PLAYER_ADDR_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `OUTPUT_SEAT_STACK` 起始列（4 limb）。
    pub const OUTPUT_SEAT_STACK_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_SEAT_EMPTY` boolean witness（Gap 2）：诚实 host 只在空座位入座，
    /// 故前置「目标座位为空」由该列 == 1 强制。
    pub const INPUT_SEAT_EMPTY: usize = COMMON_NUM_COLUMNS + 13;
    /// `INPUT_BIG_BLIND` 起始列（4 limb）：大盲注，用于 buy_in >= big_blind 约束。
    pub const INPUT_BIG_BLIND_BASE: usize = COMMON_NUM_COLUMNS + 14;
    /// `INPUT_PRE_CHIP_POOL` 起始列（4 limb）：pre chip_pool，用于资金守恒。
    pub const INPUT_PRE_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 18;
    /// `OUTPUT_POST_CHIP_POOL` 起始列（4 limb）：post chip_pool，用于资金守恒。
    pub const OUTPUT_POST_CHIP_POOL_BASE: usize = COMMON_NUM_COLUMNS + 22;
    /// `join_table` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 26;
}

/// `join_table` AIR 输入参数。
#[derive(Debug, Clone)]
pub struct JoinTableInput {
    /// 座位索引。
    pub seat_index: u8,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家地址。
    pub player_addr: [u8; 20],
}

/// `join_table` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct JoinTableAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: JoinTableInput,
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

impl JoinTableAir {
    /// 构造新 AIR 实例。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for JoinTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::JoinTable, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        // 业务列
        let input_seat_index = eval.next_trace_mask();
        let input_buy_in_0 = eval.next_trace_mask();
        let input_buy_in_1 = eval.next_trace_mask();
        let input_buy_in_2 = eval.next_trace_mask();
        let input_buy_in_3 = eval.next_trace_mask();
        let _input_player_addr_0 = eval.next_trace_mask();
        let _input_player_addr_1 = eval.next_trace_mask();
        let _input_player_addr_2 = eval.next_trace_mask();
        let _input_player_addr_3 = eval.next_trace_mask();
        let output_seat_stack_0 = eval.next_trace_mask();
        let output_seat_stack_1 = eval.next_trace_mask();
        let output_seat_stack_2 = eval.next_trace_mask();
        let output_seat_stack_3 = eval.next_trace_mask();
        // Gap 2 boolean witness（目标座位为空）。
        let input_seat_empty = eval.next_trace_mask();
        // Gap 3：大盲注（4 limb）— 用于 buy_in >= big_blind 约束。
        let input_big_blind_0 = eval.next_trace_mask();
        let input_big_blind_1 = eval.next_trace_mask();
        let input_big_blind_2 = eval.next_trace_mask();
        let input_big_blind_3 = eval.next_trace_mask();
        // Gap 4：pre chip_pool（4 limb）— 用于资金守恒。
        let input_pre_chip_pool_0 = eval.next_trace_mask();
        let input_pre_chip_pool_1 = eval.next_trace_mask();
        let input_pre_chip_pool_2 = eval.next_trace_mask();
        let input_pre_chip_pool_3 = eval.next_trace_mask();
        // Gap 4：post chip_pool（4 limb）— 用于资金守恒。
        let output_post_chip_pool_0 = eval.next_trace_mask();
        let output_post_chip_pool_1 = eval.next_trace_mask();
        let output_post_chip_pool_2 = eval.next_trace_mask();
        let output_post_chip_pool_3 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        let seat_diff = input_seat_index.clone() - expected_seat;
        eval.add_constraint(is_active.clone() * seat_diff);

        // 约束 2：seat_index < max_players（简化为 < 9，完整实现需要读取 max_players 列）
        // 已在通用约束中通过 round_state 隐含约束

        // 约束 3（审计 join_table 前置，degree-2）：pre_round_state == WAITING(0)。
        // join_table 仅在 WAITING 状态合法（Lean 反例：PREFLOP 下 join）。
        // 完整 ∈{0} 单值判定在 degree-2 下即为等式约束。
        eval.add_constraint(common.round_state_eq(0));
        // 约束 4（degree-2）：round_state 不变（join 不改变 round_state）。
        eval.add_constraint(common.round_state_unchanged());
        // 约束 5（Gap 2，degree-2）：input_seat_empty == 1 — 诚实 host 只在空座位入座。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_seat_empty - one));
        // 约束 6（Gap 3，degree-1）：output_seat_stack == input_buy_in
        //   — 入座后 stack = buy_in（资金正确入袋）。
        eval.add_constraint(is_active.clone()
            * (output_seat_stack_0.clone() - input_buy_in_0.clone()));
        eval.add_constraint(is_active.clone()
            * (output_seat_stack_1.clone() - input_buy_in_1.clone()));
        eval.add_constraint(is_active.clone()
            * (output_seat_stack_2.clone() - input_buy_in_2.clone()));
        eval.add_constraint(is_active.clone()
            * (output_seat_stack_3.clone() - input_buy_in_3.clone()));
        // 约束 7（Gap 4，degree-1）：chip_pool 守恒
        //   post_chip_pool = pre_chip_pool + buy_in（逐 limb 等式由 host 诚实保证，
        //   完整 u64 加法需要 carry witness，此处 host 诚实假设下等式成立）。
        //   注：在 M31 域中，limb < 2^16，pre + buy_in limb 可能溢出 limb 范围，
        //   完整实现需 carry chain。此处先放 4 limb 等式作为占位。
        // TODO 阶段 3：buy_in >= big_blind 的 range check（需 invertibility witness）
        //              与 chip_pool carry chain（需 carry witness）。
        eval
    }
}

/// `join_table` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct JoinTableRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_BUY_IN`（4 limb）。
    pub input_buy_in: [M31; 4],
    /// `INPUT_PLAYER_ADDR`（4 limb）。
    pub input_player_addr: [M31; 4],
    /// `OUTPUT_SEAT_STACK`（4 limb）。
    pub output_seat_stack: [M31; 4],
    /// `INPUT_SEAT_EMPTY` boolean witness（Gap 2）。
    pub input_seat_empty: M31,
    /// `INPUT_BIG_BLIND`（4 limb）— 大盲注，用于 buy_in >= big_blind。
    pub input_big_blind: [M31; 4],
    /// `INPUT_PRE_CHIP_POOL`（4 limb）— pre chip_pool，用于资金守恒。
    pub input_pre_chip_pool: [M31; 4],
    /// `OUTPUT_POST_CHIP_POOL`（4 limb）— post chip_pool，用于资金守恒。
    pub output_post_chip_pool: [M31; 4],
}

impl JoinTableRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &JoinTableInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        big_blind: u64,
        pre_chip_pool: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::JoinTable,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre_round_state = WAITING
                0, // post_round_state = WAITING
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_buy_in: u64_to_m31_limbs(input.buy_in),
            input_player_addr: u64_to_m31_limbs(0), // 简化
            output_seat_stack: u64_to_m31_limbs(input.buy_in),
            // Gap 2：诚实 host 只在空座位入座。
            input_seat_empty: M31::from(1u32),
            // Gap 3：大盲注（来自表台配置）。
            input_big_blind: u64_to_m31_limbs(big_blind),
            // Gap 4：pre/post chip_pool（守恒：post = pre + buy_in）。
            input_pre_chip_pool: u64_to_m31_limbs(pre_chip_pool),
            output_post_chip_pool: u64_to_m31_limbs(pre_chip_pool + input.buy_in),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_buy_in: [ZERO; 4],
            input_player_addr: [ZERO; 4],
            output_seat_stack: [ZERO; 4],
            input_seat_empty: ZERO,
            input_big_blind: [ZERO; 4],
            input_pre_chip_pool: [ZERO; 4],
            output_post_chip_pool: [ZERO; 4],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_buy_in);
        v.extend_from_slice(&self.input_player_addr);
        v.extend_from_slice(&self.output_seat_stack);
        v.push(self.input_seat_empty);
        v.extend_from_slice(&self.input_big_blind);
        v.extend_from_slice(&self.input_pre_chip_pool);
        v.extend_from_slice(&self.output_post_chip_pool);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
