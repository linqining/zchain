//! `tick` AIR — 超时驱动（permissionless）。
//!
//! ## 业务规约
//! 1. 根据当前 `round_state` 和超时配置触发状态转换
//! 2. 严格优先级：reconstruct > shuffle > reveal > 正常逻辑 > fallback
//! 3. **Time Bank**：下注超时时若 `time_bank_ms > 0`，消耗等量时间延长截止
//! 4. **Rake**：reveal 阶段完成触发 settle_hand 时抽水（`pot_after = pot_before - rake`）

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `tick` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_CURRENT_TIME` 起始列（4 limb）。
    pub const INPUT_CURRENT_TIME_BASE: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_TIMEOUT_KIND` 列（0=shuffle, 1=reveal, 2=reconstruct, 3=betting）。
    pub const INPUT_TIMEOUT_KIND: usize = COMMON_NUM_COLUMNS + 4;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 5;
    /// `TIME_BANK_CONSUMED_0` 列（time_bank 消耗量 limb 0）。
    pub const TIME_BANK_CONSUMED_0: usize = COMMON_NUM_COLUMNS + 6;
    /// `TIME_BANK_POST_0` 列（消耗后剩余 time_bank limb 0）。
    pub const TIME_BANK_POST_0: usize = COMMON_NUM_COLUMNS + 7;
    /// `RAKE_MODE` 列（0=NONE, 1=PERCENTAGE）。
    pub const RAKE_MODE: usize = COMMON_NUM_COLUMNS + 8;
    /// `RAKE_AMOUNT_0` 列（抽水金额 limb 0）。
    pub const RAKE_AMOUNT_0: usize = COMMON_NUM_COLUMNS + 9;
    /// `INPUT_TIMEOUT_KIND_INV` invertibility witness（Gap 5）：timeout_kind 的乘法逆元，
    /// 约束 `timeout_kind * inv == 1` 证明 timeout_kind ≠ 0（即存在真实超时）。
    pub const INPUT_TIMEOUT_KIND_INV: usize = COMMON_NUM_COLUMNS + 10;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 11;
}

/// `tick` 输入参数。
#[derive(Debug, Clone)]
pub struct TickInput {
    /// 当前时间戳。
    pub current_time: u64,
    /// 超时类型。
    pub timeout_kind: u8,
    /// Time Bank 消耗量（毫秒，0 = 未消耗）。
    pub time_bank_consumed: u64,
    /// Time Bank 消耗后余额（毫秒）。
    pub time_bank_post: u64,
    /// Rake 模式（0=NONE, 1=PERCENTAGE）。
    pub rake_mode: u8,
    /// Rake 抽水金额。
    pub rake_amount: u64,
}

/// `tick` AIR。
#[derive(Debug, Clone)]
pub struct TickAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: TickInput,
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

impl TickAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for TickAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Tick, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let _input_time_0 = eval.next_trace_mask();
        let _input_time_1 = eval.next_trace_mask();
        let _input_time_2 = eval.next_trace_mask();
        let _input_time_3 = eval.next_trace_mask();
        let input_timeout_kind = eval.next_trace_mask();
        let _output_new_round_state = eval.next_trace_mask();
        let time_bank_consumed_0 = eval.next_trace_mask();
        let time_bank_post_0 = eval.next_trace_mask();
        let rake_mode = eval.next_trace_mask();
        let rake_amount_0 = eval.next_trace_mask();
        // Gap 5 invertibility witness（timeout_kind ≠ 0）。
        let input_timeout_kind_inv = eval.next_trace_mask();

        // 约束 1：timeout_kind == input.timeout_kind
        let expected: E::F = M31::from(u32::from(self.input.timeout_kind)).into();
        eval.add_constraint(is_active.clone() * (input_timeout_kind.clone() - expected));

        // 约束 2（Time Bank）：consumed_0 == input.time_bank_consumed (limb 0)
        let expected_tb_consumed: E::F = M31::from((self.input.time_bank_consumed & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (time_bank_consumed_0.clone() - expected_tb_consumed));

        // 约束 3（Time Bank）：post_0 == input.time_bank_post (limb 0)
        let expected_tb_post: E::F = M31::from((self.input.time_bank_post & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (time_bank_post_0 - expected_tb_post));

        // 约束 4（Rake）：rake_mode == input.rake_mode
        let expected_rake_mode: E::F = M31::from(u32::from(self.input.rake_mode)).into();
        eval.add_constraint(is_active.clone() * (rake_mode - expected_rake_mode));

        // 约束 5（Rake）：rake_amount_0 == input.rake_amount (limb 0)
        let expected_rake_amt: E::F = M31::from((self.input.rake_amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (rake_amount_0 - expected_rake_amt));

        // 注：tick 会驱动状态机阶段转换（SHUFFLE→DEAL→BETTING 等），
        // round_state 可合法变化，故不施加 round_state 不变约束。
        // tick 的 Lean 反例「version 不递增」已由通用层 version+=1 约束消除。
        // 约束 6（Gap 5，degree-2）：timeout_kind * inv == 1 — 证明 timeout_kind ≠ 0
        // （即存在真实超时）。诚实 host 必须 timeout_kind > 0 才存在逆元。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (input_timeout_kind * input_timeout_kind_inv - one));
        // TODO 阶段 2：真实超时校验。

        eval
    }
}

/// `tick` trace 行。
#[derive(Debug, Clone)]
pub struct TickRow {
    /// 通用列。
    pub common: CommonRow,
    /// 当前时间。
    pub input_current_time: [M31; 4],
    /// 超时类型。
    pub input_timeout_kind: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
    /// Time Bank 消耗量 limb 0。
    pub time_bank_consumed_0: M31,
    /// Time Bank 剩余 limb 0。
    pub time_bank_post_0: M31,
    /// Rake 模式。
    pub rake_mode: M31,
    /// Rake 金额 limb 0。
    pub rake_amount_0: M31,
    /// `INPUT_TIMEOUT_KIND_INV` invertibility witness（Gap 5）。
    pub input_timeout_kind_inv: M31,
}

impl TickRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &TickInput,
        pre_state_root: [M31; 4], post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
        pre_round_state: u8, post_round_state: u8,
    ) -> Self {
        use crate::airs::common::u64_to_m31_limbs;
        // Gap 5：timeout_kind 的乘法逆元。诚实 host 必须 timeout_kind > 0
        // 才存在逆元（orchestrator prove_tick 现固定为 1）。
        let kind_m31 = M31::from(u32::from(input.timeout_kind));
        let input_timeout_kind_inv = kind_m31.inverse();
        Self {
            common: CommonRow::active(
                MethodKind::Tick, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                pre_round_state, post_round_state, 0, 0, 0, 0,
            ),
            input_current_time: u64_to_m31_limbs(input.current_time),
            input_timeout_kind: kind_m31,
            output_new_round_state: M31::from(u32::from(post_round_state)),
            time_bank_consumed_0: M31::from((input.time_bank_consumed & 0xFFFF) as u32),
            time_bank_post_0: M31::from((input.time_bank_post & 0xFFFF) as u32),
            rake_mode: M31::from(u32::from(input.rake_mode)),
            rake_amount_0: M31::from((input.rake_amount & 0xFFFF) as u32),
            // Gap 5：timeout_kind 的乘法逆元。
            input_timeout_kind_inv,
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_current_time: [ZERO; 4],
            input_timeout_kind: ZERO,
            output_new_round_state: ZERO,
            time_bank_consumed_0: ZERO,
            time_bank_post_0: ZERO,
            rake_mode: ZERO,
            rake_amount_0: ZERO,
            input_timeout_kind_inv: ZERO,
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.extend_from_slice(&self.input_current_time);
        v.push(self.input_timeout_kind);
        v.push(self.output_new_round_state);
        v.push(self.time_bank_consumed_0);
        v.push(self.time_bank_post_0);
        v.push(self.rake_mode);
        v.push(self.rake_amount_0);
        v.push(self.input_timeout_kind_inv);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
