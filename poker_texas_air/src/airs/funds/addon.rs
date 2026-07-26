//! `addon` AIR — 玩家追加筹码（**下一手生效**）。
//!
//! 移植自 `dispatch::dispatch_addon` 与 `state_machine::apply_addon`。
//!
//! ## 业务规约
//!
//! 1. `seat_index` 必须是已占用座位（`is_occupied()`）
//! 2. `amount > 0`
//! 3. 状态变更（**关键：不动 stack**）：
//!    - `seats[seat].pending_addon += amount`
//!    - `table.addon_pool += amount`
//!    - `version += 1`
//!
//! ## 为什么不动 stack
//!
//! addon 设计为「下一手生效」：
//! - **不破坏当前 `side_pot` 分层**（all-in 后的钱不能凭空增加）
//! - **不允许玩家利用 addon 在 all-in 后"加码"破坏结算**
//! - 实际入账发生在 `reset_for_next_hand` 第一阶段（合并到 stack）
//!
//! ## AIR 列布局
//!
//! - 通用列 37 个
//! - 业务列 11 个：
//!   - `INPUT_SEAT_INDEX`
//!   - `INPUT_AMOUNT_BASE[4]`（4 limb，追加金额）
//!   - `PRE_PENDING_ADDON_BASE[4]`（4 limb，调用前 pending_addon）
//!   - `POST_PENDING_ADDON_BASE[4]`（4 limb，调用后 pending_addon；约束 = pre + amount）
//!
//! 共 37 + 1 + 4 + 4 + 4 = 50 列？实际下文 `NUM_COLUMNS` 设为 37 + 13 = 50（对齐于 limb 表）。
//!
//! 简化版（PoC）：只约束 limb 0 一致性，高 limb 由 host 端保证（M31 域内 16 bit）。

use stwo_constraint_framework::{EvalAtRow, FrameworkEval};
use stwo::core::fields::m31::M31;

use crate::airs::common::{
    u64_to_m31_limbs, u8_to_m31, CommonConstraints, CommonRow, COMMON_NUM_COLUMNS, ZERO,
};
use crate::method_kind::MethodKind;

/// `addon` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_SEAT_INDEX` 列。
    pub const INPUT_SEAT_INDEX: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_AMOUNT` 起始列（4 limb，追加金额）。
    pub const INPUT_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 1;
    /// `PRE_PENDING_ADDON` 起始列（4 limb，调用前 pending_addon）。
    pub const PRE_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `POST_PENDING_ADDON` 起始列（4 limb，调用后 pending_addon）。
    pub const POST_PENDING_ADDON_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// `addon` AIR 总列数。
    pub const NUM_COLUMNS: usize = COMMON_NUM_COLUMNS + 13;
}

/// `addon` 输入参数。
#[derive(Debug, Clone)]
pub struct AddonInput {
    /// 目标座位索引。
    pub seat_index: u8,
    /// 追加金额（必须 > 0）。
    pub amount: u64,
}

/// `addon` AIR 公开输入。
#[derive(Debug, Clone)]
pub struct AddonAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: AddonInput,
    /// 调用前 state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root（4 limb）。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号（addon 可在任意时刻调用，hand_id 标识调用时的手牌）。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl AddonAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for AddonAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let common = CommonConstraints::write(&mut eval, MethodKind::Addon, self.pre_version, self.post_version);
        let is_active = common.is_active.clone();

        // 读取业务列
        let input_seat_index = eval.next_trace_mask();
        let input_amount_0 = eval.next_trace_mask();
        let _input_amount_1 = eval.next_trace_mask();
        let _input_amount_2 = eval.next_trace_mask();
        let _input_amount_3 = eval.next_trace_mask();
        let pre_pending_0 = eval.next_trace_mask();
        let _pre_pending_1 = eval.next_trace_mask();
        let _pre_pending_2 = eval.next_trace_mask();
        let _pre_pending_3 = eval.next_trace_mask();
        let post_pending_0 = eval.next_trace_mask();
        let _post_pending_1 = eval.next_trace_mask();
        let _post_pending_2 = eval.next_trace_mask();
        let _post_pending_3 = eval.next_trace_mask();

        // 约束 1：seat_index == input.seat_index
        let expected_seat: E::F = M31::from(u32::from(self.input.seat_index)).into();
        eval.add_constraint(is_active.clone() * (input_seat_index - expected_seat));

        // 约束 2：amount 一致性（验证 limb 0）
        // 16 bit 内足够覆盖常规 addon 金额（< 65536）
        let expected_amount_0: E::F = M31::from((self.input.amount & 0xFFFF) as u32).into();
        eval.add_constraint(is_active.clone() * (input_amount_0.clone() - expected_amount_0));

        // 约束 3（核心）：post_pending_addon == pre_pending_addon + input_amount
        //    关键不变量：addon 精确累加到 pending_addon，不动 stack
        //    只约束 limb 0（M31 域内 + 16 bit 内不会溢出）
        eval.add_constraint(is_active.clone() * (post_pending_0 - pre_pending_0 - input_amount_0));

        // 约束 4（审计共性，degree-2）：round_state 不变（addon 不改变 round_state）。
        eval.add_constraint(common.round_state_unchanged());
        // TODO 阶段 3：amount > 0（需 invertibility witness 列，degree-2）；
        //              addon_pool += amount 守恒（需新增 addon_pool 列）。

        eval
    }
}

/// `addon` AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct AddonRow {
    /// 通用列。
    pub common: CommonRow,
    /// `INPUT_SEAT_INDEX`。
    pub input_seat_index: M31,
    /// `INPUT_AMOUNT`（4 limb）。
    pub input_amount: [M31; 4],
    /// `PRE_PENDING_ADDON`（4 limb）。
    pub pre_pending_addon: [M31; 4],
    /// `POST_PENDING_ADDON`（4 limb）。
    pub post_pending_addon: [M31; 4],
}

impl AddonRow {
    /// 构造 active 行。
    ///
    /// # 参数
    /// - `input`: addon 输入（seat_index + amount）
    /// - `pre_pending_addon`: 调用前的 pending_addon 值
    /// - 其他通用字段（state_root / table_id / hand_id / version / round_state / pot）
    #[must_use]
    pub fn active(
        input: &AddonInput,
        pre_pending_addon: u64,
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
        // post_pending = pre_pending + amount（host 端预计算，AIR 端约束一致性）
        let post_pending = pre_pending_addon + input.amount;
        Self {
            common: CommonRow::active(
                MethodKind::Addon,
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
            pre_pending_addon: u64_to_m31_limbs(pre_pending_addon),
            post_pending_addon: u64_to_m31_limbs(post_pending),
        }
    }

    /// 构造 padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_seat_index: ZERO,
            input_amount: [ZERO; 4],
            pre_pending_addon: [ZERO; 4],
            post_pending_addon: [ZERO; 4],
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.input_seat_index);
        v.extend_from_slice(&self.input_amount);
        v.extend_from_slice(&self.pre_pending_addon);
        v.extend_from_slice(&self.post_pending_addon);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
