//! `fold` AIR — 玩家主动 fold（弃牌）。
//!
//! 移植自 `dispatch::dispatch_fold` 与 `state_machine::apply_fold`。
//!
//! ## 业务规约
//!
//! 1. 当前 `round_state ∈ {PREFLOP, FLOP, TURN, RIVER}`（下注轮）
//! 2. `seat_index` 是当前行动玩家（`current_turn == seat_index`）
//! 3. 玩家未 fold、未 all_in
//! 4. 状态变更：`seat.folded = true`, `version += 1`
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 2 个：`INPUT_SEAT_INDEX`, `OUTPUT_FOLDED`

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `fold` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `OUTPUT_FOLDED` 列（1 = 已 fold，0 = 未 fold）。
    pub const OUTPUT_FOLDED: usize = COMMON_NUM_COLUMNS + 1;
    /// `INPUT_PRE_ROUND_STATE_Q` 列（Gap 1 witness：pre_round_state²，拆 4 次 vanishing）。
    pub const INPUT_PRE_ROUND_STATE_Q: usize = COMMON_NUM_COLUMNS + 2;
    /// `fold` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 3;
}

/// `fold` 输入参数。
#[derive(Debug, Clone)]
pub struct FoldInput {
    /// 执行 fold 的座位索引。
    pub seat_index: u8,
}

/// `fold` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct FoldAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: FoldInput,
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

impl FoldAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for FoldAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Fold, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let input_seat_index = eval.next_trace_mask();
        let output_folded = eval.next_trace_mask();
        // Gap 1 witness：pre_round_state²
        let input_pre_round_state_q = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：output_folded == 1（fold 后座位标记为 folded）
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(is_active.clone() * (output_folded - one));

        // 约束 3（审计 B 档共性）：round_state 不变 + 必须处于下注轮（Gap 1）。
        // round_state_is_betting 用 degree-4 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0
        // 经 q=rs² witness 展开为 degree-2 项，强制 rs ∈ {PREFLOP,FLOP,TURN,RIVER}，
        // 阻止恶意 prover 在 ROUND_WAITING 下构造 fold trace。
        eval.add_constraint(common.round_state_unchanged());
        eval.add_constraint(common.round_state_q_constraint(input_pre_round_state_q.clone()));
        eval.add_constraint(common.round_state_is_betting(input_pre_round_state_q));

        // 约束 4（审计 fold：pot 不变，degree-2 limb0）：fold 不改变 pot。
        eval.add_constraint(common.pot_unchanged_limb0());

        eval
    }
}

/// `fold` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct FoldRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `OUTPUT_FOLDED`。
    pub output_folded: M31,
    /// Gap 1 witness：pre_round_state²。
    pub input_pre_round_state_q: M31,
}

impl FoldRow {
    /// 构造 active 行。
    #[must_use]
    pub fn active(
        input: &FoldInput,
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
        Self {
            common: CommonRow::active(
                MethodKind::Fold,
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
            output_folded: M31::from(1u32),
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
            output_folded: ZERO,
            input_pre_round_state_q: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.push(self.output_folded);
        v.push(self.input_pre_round_state_q);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
