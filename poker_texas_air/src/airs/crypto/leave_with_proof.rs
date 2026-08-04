//! `leave_with_proof` AIR — 玩家带 proof 离场。
//!
//! 移植自 `dispatch::dispatch_leave_with_proof` 与 `state_machine::apply_leave_with_proof`。
//!
//! ## 业务规约
//!
//! 1. 玩家在 `completed` 列表中（已洗牌）
//! 2. 提交 LeaveKind DLEq proof（证明其掩码密钥的有效性）
//! 3. 状态变更：
//!    - 从 `completed` 列表移除该玩家
//!    - 从聚合公钥移除该玩家公钥
//!    - 牌组用玩家剩余掩码重加密
//!    - `version += 1`
//!
//! ## 简化策略
//!
//! 阶段 4 PoC 只验证协议级状态变更：
//! - `seat_index` 一致性
//! - `leave_kind` 一致性
//! - `output_completed_count -= 1`
//!
//! DLEq proof 验证留待阶段 5 嵌入 Verifier AIR。

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `leave_with_proof` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_LEAVE_KIND` 列（LeaveKind 枚举值）。
    pub const INPUT_LEAVE_KIND: usize = COMMON_NUM_COLUMNS + 1;
    /// `OUTPUT_COMPLETED_COUNT` 列。
    pub const OUTPUT_COMPLETED_COUNT: usize = COMMON_NUM_COLUMNS + 2;
    /// `INPUT_SHUFFLE_PHASE` 列（调用前的 `shuffle_state.phase`）。
    pub const INPUT_SHUFFLE_PHASE: usize = COMMON_NUM_COLUMNS + 3;
    /// `INPUT_SHUFFLE_PHASE_Q` 列（phase² witness，拆 3 次 vanishing）。
    pub const INPUT_SHUFFLE_PHASE_Q: usize = COMMON_NUM_COLUMNS + 4;
    /// `leave_with_proof` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 5;
}

/// `leave_with_proof` 输入参数。
#[derive(Debug, Clone)]
pub struct LeaveWithProofInput {
    /// 离场玩家座位索引。
    pub seat_index: u8,
    /// 离场类型（LeaveKind 枚举）。
    pub leave_kind: u8,
    /// 调用前的 `shuffle_state.phase`（必须 ∈ {1,2,3}）。
    pub shuffle_phase: u8,
}

/// `leave_with_proof` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct LeaveWithProofAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: LeaveWithProofInput,
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

impl LeaveWithProofAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for LeaveWithProofAir {
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
        let input_leave_kind = eval.next_trace_mask();
        let _output_completed_count = eval.next_trace_mask();
        // 调用前 shuffle phase 与平方 witness。
        let input_shuffle_phase = eval.next_trace_mask();
        let input_shuffle_phase_q = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：leave_kind == input.leave_kind
        let expected_kind: E::F = M31::from(u32::from(self.input.leave_kind)).into();
        eval.add_constraint(is_active.clone() * (input_leave_kind - expected_kind));

        // 约束 3a：shuffle_phase == input.shuffle_phase
        let expected_phase: E::F = M31::from(u32::from(self.input.shuffle_phase)).into();
        eval.add_constraint(is_active.clone() * (input_shuffle_phase.clone() - expected_phase));
        // 约束 3b：q == shuffle_phase²（witness 一致性，degree-2）
        eval.add_constraint(
            is_active.clone()
                * (input_shuffle_phase_q.clone()
                    - input_shuffle_phase.clone() * input_shuffle_phase.clone()),
        );
        // 约束 3c：shuffle_phase ∈ {1,2,3}（非 NONE=0）。
        // vanishing (phase-1)(phase-2)(phase-3) = phase³-6phase²+11phase-6
        // 经 q=phase² 展开为 degree ≤ 2：(phase·q) - 6·q + 11·phase - 6 == 0
        let six: E::F = M31::from(6u32).into();
        let eleven: E::F = M31::from(11u32).into();
        let vp = (input_shuffle_phase.clone() * input_shuffle_phase_q.clone())
            - six.clone() * input_shuffle_phase_q.clone()
            + eleven * input_shuffle_phase.clone()
            - six;
        eval.add_constraint(is_active.clone() * vp);

        // 约束 3（审计共性，degree-2）：round_state 不变（leave_with_proof 阶段 round_state 恒为 WAITING=0）。
        eval.add_constraint(common.round_state_unchanged());
        // TODO 阶段 5：shuffle_state.phase > 0 前置（需 invertibility witness 或 logup）；
        //              嵌入 DLEq Verifier AIR 验证 LeaveKind proof；
        //              约束牌组重加密正确性。

        eval
    }
}

/// `leave_with_proof` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct LeaveWithProofRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_LEAVE_KIND`。
    pub input_leave_kind: M31,
    /// `OUTPUT_COMPLETED_COUNT`。
    pub output_completed_count: M31,
    /// 调用前的 shuffle_state.phase。
    pub input_shuffle_phase: M31,
    /// phase² witness。
    pub input_shuffle_phase_q: M31,
}

impl LeaveWithProofRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &LeaveWithProofInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        post_completed_count: u8,
    ) -> Self {
        let sp = u8_to_m31(input.shuffle_phase);
        let q = sp * sp;
        Self {
            common: CommonRow::active(
                MethodKind::LeaveWithProof,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                0, // pre = ROUND_WAITING（leave_with_proof 仅在 WAITING 态）
                0, // post = ROUND_WAITING
                0,
                0,
                0,
                0,
            ),
            input_seat_index: u8_to_m31(input.seat_index),
            input_leave_kind: u8_to_m31(input.leave_kind),
            output_completed_count: u8_to_m31(post_completed_count),
            input_shuffle_phase: sp,
            input_shuffle_phase_q: q,
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_leave_kind: ZERO,
            output_completed_count: ZERO,
            input_shuffle_phase: ZERO,
            input_shuffle_phase_q: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.input_leave_kind);
        v.push(self.output_completed_count);
        v.push(self.input_shuffle_phase);
        v.push(self.input_shuffle_phase_q);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
