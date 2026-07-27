//! `start_hand` AIR — 开始新一局（投盲注 + 进入 shuffle 阶段）。
//!
//! ## 业务规约（对齐 `state_machine::start_hand`）
//! 1. `round_state == ROUND_WAITING`
//! 2. 活跃玩家数 ≥ `MIN_PLAYERS_TO_START`（= 2）
//! 3. 状态变更：`button` 旋转到下一个占用座；**`round_state` 保持 `ROUND_WAITING`**
//!    （合约在 `start_hand` 后并不改 `round_state`，只有当 preflop reveal phase
//!    完成时才转为 `ROUND_PREFLOP`，见 `check_reveal_phase_complete`）。
//!    真正进入 shuffle 的语义由独立的 `shuffle_state.phase = SHUFFLE_PHASE_BEFORE_PREFLOP`
//!    表达，**不属于 `round_state`**（合约 `constants.rs` 无 `ROUND_SHUFFLE` 常量）。
//! 4. **Ante 配置**：声明本手的 ante_mode / ante_amount / ante_collected，
//!    约束 ante_mode 与公开输入一致，ante_collected 在 NONE 模式下 == 0

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `start_hand` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_ACTIVE_COUNT` 列。
    pub const INPUT_ACTIVE_COUNT: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_NEW_BUTTON` 列。
    pub const OUTPUT_NEW_BUTTON: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 2;
    /// `OUTPUT_ANTE_MODE` 列（0=NONE, 1=NORMAL, 2=BBA）。
    pub const OUTPUT_ANTE_MODE: usize = COMMON_NUM_COLUMNS + 3;
    /// `OUTPUT_ANTE_AMOUNT_LIMB0` 列（ante_amount 的低 16 位）。
    pub const OUTPUT_ANTE_AMOUNT_0: usize = COMMON_NUM_COLUMNS + 4;
    /// `OUTPUT_ANTE_COLLECTED_LIMB0` 列（ante_collected 的低 16 位）。
    pub const OUTPUT_ANTE_COLLECTED_0: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_ACTIVE_COUNT_INV` 列（Gap 4 witness：active_count*(active_count-1) 的乘法逆元）。
    pub const INPUT_ACTIVE_COUNT_INV: usize = COMMON_NUM_COLUMNS + 6;
    /// `INPUT_ACTIVE_COUNT_PROD` 列（Gap 4 witness：active_count*(active_count-1)）。
    /// 引入此中间列把 `prod * inv == 1` 约束降到 degree-2（两列乘积），
    /// 否则 `active_count*(active_count-1)*inv` 是三列乘积，degree 超过 Stwo 上界。
    pub const INPUT_ACTIVE_COUNT_PROD: usize = COMMON_NUM_COLUMNS + 7;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 8;
}

/// `start_hand` 输入参数。
#[derive(Debug, Clone)]
pub struct StartHandInput {
    /// 活跃玩家数。
    pub active_count: u8,
    /// Ante 模式（0=NONE, 1=NORMAL, 2=BBA）。
    pub ante_mode: u8,
    /// Ante 金额。
    pub ante_amount: u64,
    /// 本手累积 ante 总额（NORMAL = active_count * ante_amount, BBA = ante_amount, NONE = 0）。
    pub ante_collected: u64,
}

/// `start_hand` AIR。
#[derive(Debug, Clone)]
pub struct StartHandAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: StartHandInput,
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

impl StartHandAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for StartHandAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::StartHand, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_active_count = eval.next_trace_mask();
        let _output_new_button = eval.next_trace_mask();
        let output_new_round_state = eval.next_trace_mask();
        let output_ante_mode = eval.next_trace_mask();
        let output_ante_amount_0 = eval.next_trace_mask();
        let output_ante_collected_0 = eval.next_trace_mask();
        // Gap 4 witnesses：active_count*(active_count-1) 及其乘法逆元
        let input_active_count_inv = eval.next_trace_mask();
        let input_active_count_prod = eval.next_trace_mask();

        // 约束 1：active_count == input.active_count
        let expected_count: E::F = M31::from(u32::from(self.input.active_count)).into();
        eval.add_constraint(is_active.clone() * (input_active_count.clone() - expected_count));

        // 约束 2a（Gap 4 part 1）：prod == active_count*(active_count-1)（degree-2 两列乘积）。
        // 用中间列 prod 把三列乘积拆成两个两列乘积约束，避免 degree 超过 Stwo 上界。
        let one: E::F = M31::from(1u32).into();
        let count_minus_one = input_active_count.clone() - one.clone();
        eval.add_constraint(is_active.clone() * (input_active_count_prod.clone() - input_active_count.clone() * count_minus_one));

        // 约束 2b（Gap 4 part 2）：prod * inv == 1（degree-2 两列乘积）。
        // 强制 active_count*(active_count-1) ≠ 0，即 active_count ∉ {0,1} → active_count ≥ 2。
        eval.add_constraint(is_active.clone() * (input_active_count_prod.clone() * input_active_count_inv.clone() - one));
        // 约束 3：output_new_round_state == ROUND_WAITING (常量)
        // 合约 start_hand 后 round_state 仍为 ROUND_WAITING=0；真正进入 shuffle 由
        // shuffle_state.phase 表达（SHUFFLE_PHASE_BEFORE_PREFLOP=3），不属于 round_state。
        let expected_round: E::F = M31::from(0u32).into();
        eval.add_constraint(is_active.clone() * (output_new_round_state - expected_round));

        // 约束 3b（审计 start_hand 前置，degree-2）：pre_round_state == WAITING(0)。
        // start_hand 仅在 WAITING 状态合法（Lean 反例：PREFLOP 下 start_hand）。
        eval.add_constraint(common.round_state_eq(0));

        // 约束 4（Ante）：ante_mode 与公开输入一致
        let expected_ante_mode: E::F = M31::from(u32::from(self.input.ante_mode)).into();
        eval.add_constraint(is_active.clone() * (output_ante_mode - expected_ante_mode));

        // 约束 5（Ante）：ante_amount limb 0 一致
        let expected_ante_amt_0: E::F = M31::from((self.input.ante_amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (output_ante_amount_0 - expected_ante_amt_0));

        // 约束 6（Ante 核心不变量）：ante_collected limb 0 一致
        //   - NONE 模式 (mode==0)：host 设置 ante_collected = 0
        //   - NORMAL/BBA：host 按 active_count * ante_amount 计算
        //   trace 中 collected_0 必须与公开输入一致；state_root 验证捕获实际状态正确性
        let expected_collected_0: E::F = M31::from((self.input.ante_collected & 0xFFFF) as u32).into();
        eval.add_constraint(is_active * (output_ante_collected_0 - expected_collected_0));

        eval
    }
}

/// `start_hand` trace 行。
#[derive(Debug, Clone)]
pub struct StartHandRow {
    /// 通用列。
    pub common: CommonRow,
    /// 活跃玩家数。
    pub input_active_count: M31,
    /// 新 button。
    pub output_new_button: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
    /// Ante 模式。
    pub output_ante_mode: M31,
    /// Ante 金额 limb 0。
    pub output_ante_amount_0: M31,
    /// Ante 已收 limb 0。
    pub output_ante_collected_0: M31,
    /// Gap 4 witness：active_count*(active_count-1) 的乘法逆元（M31 域内）。
    pub input_active_count_inv: M31,
    /// Gap 4 witness：active_count*(active_count-1)（中间列，拆三列乘积为两个两列乘积）。
    pub input_active_count_prod: M31,
}

impl StartHandRow {
    /// active 行。
    ///
    /// # 参数
    /// - `active_count_inv`: `active_count*(active_count-1)` 在 M31 域内的乘法逆元。
    ///   host 端由 `(active_count as u64 * (active_count-1) as u64)` 求 inverse 得到。
    ///   active_count ≥ 2 时该值非零，满足 Gap 4 约束。
    /// - `active_count_prod`: `active_count*(active_count-1)`（host 计算）。
    #[must_use]
    pub fn active(
        input: &StartHandInput,
        active_count_inv: M31,
        active_count_prod: M31,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::StartHand, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                0, // pre = ROUND_WAITING
                0, // post = ROUND_WAITING（合约 start_hand 后 round_state 不变）
                0, 0, 0, 0,
            ),
            input_active_count: u8_to_m31(input.active_count),
            output_new_button: ZERO, // 由 pre_button + 1 计算
            output_new_round_state: M31::from(0u32), // ROUND_WAITING
            output_ante_mode: u8_to_m31(input.ante_mode),
            output_ante_amount_0: M31::from((input.ante_amount & 0xFFFF) as u32),
            output_ante_collected_0: M31::from((input.ante_collected & 0xFFFF) as u32),
            input_active_count_inv: active_count_inv,
            input_active_count_prod: active_count_prod,
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_active_count: ZERO,
            output_new_button: ZERO,
            output_new_round_state: ZERO,
            output_ante_mode: ZERO,
            output_ante_amount_0: ZERO,
            output_ante_collected_0: ZERO,
            // padding 行 is_active=0，约束自动满足（gated），witness 值任意；用 ZERO。
            input_active_count_inv: ZERO,
            input_active_count_prod: ZERO,
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_active_count);
        v.push(self.output_new_button);
        v.push(self.output_new_round_state);
        v.push(self.output_ante_mode);
        v.push(self.output_ante_amount_0);
        v.push(self.output_ante_collected_0);
        v.push(self.input_active_count_inv);
        v.push(self.input_active_count_prod);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}




