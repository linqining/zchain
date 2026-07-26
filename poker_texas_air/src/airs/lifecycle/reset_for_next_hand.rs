//! `reset_for_next_hand` AIR — 显式重置桌台到 WAITING。
//!
//! ## 业务规约
//! 1. **合并 addon**：`stack += pending_addon; pending_addon = 0`（第一阶段，在清理 stack==0 之前）
//! 2. 清除座位状态（folded, all_in, is_waiting 等）
//! 3. 重置 pot, side_pots, community_cards
//! 4. `round_state = ROUND_WAITING`
//! 5. `version += 1`
//!
//! ## addon 合并约束（v2 新增）
//!
//! reset 时对每个有 `pending_addon > 0` 的座位：
//! - `stack_post == stack_pre + pending_addon_pre`
//! - `pending_addon_post == 0`
//!
//! AIR 层简化（PoC）：只约束合并后 `pending_addon_post == 0`（关键不变量）。
//! 完整 stack += pending_addon 约束留待 state_root 完整字段化后。
//! 当前通过 state_root pre/post 完整承诺（host 端保证计算正确）。

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO};
use crate::method_kind::MethodKind;

/// `reset_for_next_hand` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 0;
    /// `POST_PENDING_ADDON` 起始列（4 limb，reset 后必须全 0）。
    ///
    /// 业务含义：reset 第一阶段合并 `pending_addon` 到 `stack` 后必须清零。
    /// 这是 addon「下一手生效」机制的核心不变量。
    pub const POST_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 5;
}

/// `reset_for_next_hand` 输入参数（无额外参数）。
#[derive(Debug, Clone, Default)]
pub struct ResetForNextHandInput;

/// `reset_for_next_hand` AIR。
#[derive(Debug, Clone)]
pub struct ResetForNextHandAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: ResetForNextHandInput,
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

impl ResetForNextHandAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize { cols::NUM_COLUMNS }
}

impl FrameworkEval for ResetForNextHandAir {
    fn log_size(&self) -> u32 { self.log_size }
    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::ResetForNextHand, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        let output_new_round_state = eval.next_trace_mask();
        // 读取 POST_PENDING_ADDON 4 limb
        let post_pending_0 = eval.next_trace_mask();
        let post_pending_1 = eval.next_trace_mask();
        let post_pending_2 = eval.next_trace_mask();
        let post_pending_3 = eval.next_trace_mask();

        // 约束 1：output_new_round_state == ROUND_WAITING (== 0)
        eval.add_constraint(is_active.clone() * output_new_round_state);

        // 约束 2（核心 addon 不变量）：reset 后 POST_PENDING_ADDON 必须全 0
        //    业务语义：pending_addon 已合并到 stack，必须清零，避免重复入账
        eval.add_constraint(is_active.clone() * post_pending_0);
        eval.add_constraint(is_active.clone() * post_pending_1);
        eval.add_constraint(is_active.clone() * post_pending_2);
        eval.add_constraint(is_active * post_pending_3);

        eval
    }
}

/// `reset_for_next_hand` trace 行。
#[derive(Debug, Clone)]
pub struct ResetForNextHandRow {
    /// 通用列。
    pub common: CommonRow,
    /// 新 round_state。
    pub output_new_round_state: M31,
    /// reset 后的 pending_addon（必须全 0，addon 已合并）。
    pub post_pending_addon: [M31; 4],
}

impl ResetForNextHandRow {
    /// active 行。
    ///
    /// # 参数
    /// - `_pre_pending_addon`: reset 前的 pending_addon（仅用于文档化，AIR 不直接约束）
    ///
    /// 业务流程：host 端在调用此 AIR 前已执行 `stack += pending_addon`，
    /// 此处 `post_pending_addon` 固定为 0。
    #[must_use]
    pub fn active(
        _input: &ResetForNextHandInput,
        _pre_pending_addon: u64,
        pre_state_root: [M31; 4], post_state_root: [M31; 4],
        table_id: u64, hand_id: u32, call_seq: u32,
        pre_version: u64, post_version: u64,
        pre_round_state: u8,
    ) -> Self {
        Self {
            common: CommonRow::active(
                MethodKind::ResetForNextHand, pre_state_root, post_state_root,
                table_id, hand_id, call_seq, pre_version, post_version,
                pre_round_state, 0, // post = WAITING
                0, 0, 0, 0,
            ),
            output_new_round_state: ZERO, // ROUND_WAITING = 0
            // 关键：reset 后 pending_addon 必须清零（addon 已合并到 stack）
            post_pending_addon: [ZERO; 4],
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            output_new_round_state: ZERO,
            post_pending_addon: [ZERO; 4],
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.output_new_round_state);
        v.extend_from_slice(&self.post_pending_addon);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
