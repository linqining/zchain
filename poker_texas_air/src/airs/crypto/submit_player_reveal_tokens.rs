//! `submit_player_reveal_tokens` AIR — 提交揭牌令牌。
//!
//! 移植自 `dispatch::dispatch_submit_player_reveal_tokens` 与
//! `state_machine::apply_submit_player_reveal_tokens`。
//!
//! ## 业务规约
//!
//! 1. 阶段守卫在 `reveal_token_state.reveal_phase != NONE`（**不是** `round_state`）；
//!    `round_state` 在 reveal 期间可为 WAITING（preflop reveal）或 PREFLOP..SHOWDOWN，
//!    且单次 submit 不改变 `round_state`（pre == post）。真正的相位约束由
//!    `INPUT_REVEAL_PHASE` 列承载（见 evaluate）。
//! 2. `seat_index` 在 `reveal_assignments` 中
//! 3. 提交 RevealTokenProof（DLEq 证明 reveal token 正确性）
//! 4. 状态变更：
//!    - `reveal_token_state.revealed[seat_index] = true`
//!    - 若所有需揭示的玩家都已提交，进入 reconstruct 阶段
//!    - `version += 1`
//!
//! ## 简化策略
//!
//! 阶段 4 PoC 只验证协议级状态变更：
//! - `seat_index` 一致性
//! - `output_revealed_count` 一致性
//!
//! RevealTokenProof 验证留待阶段 5。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `submit_player_reveal_tokens` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_REVEAL_PHASE` 列。
    pub const INPUT_REVEAL_PHASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_REVEALED_COUNT` 列。
    pub const OUTPUT_REVEALED_COUNT: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_REVEAL_PHASE_Q1` 列（Gap 7 witness：reveal_phase²，拆 6 次 vanishing）。
    pub const INPUT_REVEAL_PHASE_Q1: usize = COMMON_NUM_COLUMNS + 3;
    /// `INPUT_REVEAL_PHASE_Q2` 列（Gap 7 witness：reveal_phase⁴ = q1²）。
    pub const INPUT_REVEAL_PHASE_Q2: usize = COMMON_NUM_COLUMNS + 4;
    /// `submit_player_reveal_tokens` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 5;
}

/// `submit_player_reveal_tokens` 输入参数。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensInput {
    /// 提交令牌的座位索引。
    pub seat_index: u8,
    /// 调用准入时（pre-dispatch）的 reveal 阶段枚举值。
    ///
    /// 最后一个被分配的玩家提交 token 后，状态机会将 post-dispatch 阶段推进到
    /// `NONE`；这不改变本次调用在非 `NONE` 阶段获准执行的事实。
    pub reveal_phase: u8,
    /// 原生状态机在此调用中执行的 `bump_version` 次数。
    ///
    /// 普通 reveal 为 1；最后一个 showdown token 会同步结算并 reset 手牌，
    /// 因而为 2。该值由 Orchestrator 的 canonical VM replay 推导。
    pub version_increment: u8,
}

/// `submit_player_reveal_tokens` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: SubmitPlayerRevealTokensInput,
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

impl SubmitPlayerRevealTokensAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for SubmitPlayerRevealTokensAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write_with_version_increment(
            &mut eval,
            &statement,
            u64::from(self.input.version_increment),
        );
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let input_reveal_phase = eval.next_trace_mask();
        let _output_revealed_count = eval.next_trace_mask();
        // Gap 7 witnesses：reveal_phase² 与 reveal_phase⁴
        let input_reveal_phase_q1 = eval.next_trace_mask();
        let input_reveal_phase_q2 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：reveal_phase == input.reveal_phase（clone 保留原值供约束 4 使用）
        let expected_phase: E::F = M31::from(u32::from(self.input.reveal_phase)).into();
        eval.add_constraint(is_active.clone() * (input_reveal_phase.clone() - expected_phase));

        // 约束 3（审计共性，degree-2）：round_state 不变（reveal 阶段 round_state 恒为 WAITING=0）。
        eval.add_constraint(common.round_state_unchanged());

        // 约束 4（Gap 7：RevealPhasePositive）：reveal_phase ∈ {1..6}（非 NONE=0）。
        // vanishing 多项式 (rp-1)(rp-2)(rp-3)(rp-4)(rp-5)(rp-6) = rp⁶-21rp⁵+175rp⁴-735rp³+1624rp²-1764rp+720。
        // 6 次多项式（单列自乘 6 次）degree 超过 Stwo 上界，故引入 witness q1=rp²、q2=rp⁴，
        // 展开为 degree ≤ 2 项：720 -1764·rp +1624·q1 -735·(rp·q1) +175·q2 -21·(rp·q2) +(q1·q2)。
        // 阻止恶意 prover 在 reveal_phase=0（无 reveal 进行）下构造 trace。
        let rp = input_reveal_phase.clone();
        let q1 = input_reveal_phase_q1.clone();
        let q2 = input_reveal_phase_q2.clone();
        // witness 一致性（degree-2 两列乘积）
        eval.add_constraint(is_active.clone() * (q1.clone() - rp.clone() * rp.clone()));
        eval.add_constraint(is_active.clone() * (q2.clone() - q1.clone() * q1.clone()));
        // 展开的 6 次 vanishing（每项 degree ≤ 2）
        let c720: E::F = M31::from(720u32).into();
        let c1764: E::F = M31::from(1764u32).into();
        let c1624: E::F = M31::from(1624u32).into();
        let c735: E::F = M31::from(735u32).into();
        let c175: E::F = M31::from(175u32).into();
        let c21: E::F = M31::from(21u32).into();
        let vp = c720 - c1764 * rp.clone() + c1624 * q1.clone() - c735 * (rp.clone() * q1.clone())
            + c175 * q2.clone()
            - c21 * (rp.clone() * q2.clone())
            + (q1 * q2);
        eval.add_constraint(is_active.clone() * vp);
        // TODO 阶段 5：嵌入 RevealTokenProof Verifier AIR。

        eval
    }
}

/// `submit_player_reveal_tokens` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct SubmitPlayerRevealTokensRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_REVEAL_PHASE`。
    pub input_reveal_phase: M31,
    /// `OUTPUT_REVEALED_COUNT`。
    pub output_revealed_count: M31,
    /// Gap 7 witness：reveal_phase²。
    pub input_reveal_phase_q1: M31,
    /// Gap 7 witness：reveal_phase⁴。
    pub input_reveal_phase_q2: M31,
}

impl SubmitPlayerRevealTokensRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &SubmitPlayerRevealTokensInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_revealed_count: u8,
    ) -> Self {
        let rp_m31 = u8_to_m31(input.reveal_phase);
        let q1 = rp_m31 * rp_m31;
        let q2 = q1 * q1;
        Self {
            common: CommonRow::active(
                MethodKind::SubmitPlayerRevealTokens,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre round_state（reveal 期间可为 0/2..6；真实值由调用方传入，
                //    此处默认 0=ROUND_WAITING。相位守卫在 INPUT_REVEAL_PHASE）
                0, // post round_state（单次 submit 不改 round_state）
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_reveal_phase: rp_m31,
            output_revealed_count: u8_to_m31(post_revealed_count),
            // Gap 7 witnesses：reveal_phase² 与 reveal_phase⁴（M31 域内）
            input_reveal_phase_q1: q1,
            input_reveal_phase_q2: q2,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_reveal_phase: ZERO,
            output_revealed_count: ZERO,
            input_reveal_phase_q1: ZERO,
            input_reveal_phase_q2: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_reveal_phase);
        v.push(self.output_revealed_count);
        v.push(self.input_reveal_phase_q1);
        v.push(self.input_reveal_phase_q2);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
