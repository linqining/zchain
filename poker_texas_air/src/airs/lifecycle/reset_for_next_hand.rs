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

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u8_to_m31};
use crate::authorization_binding::AdminAuthorizationAirBinding;
use crate::method_kind::MethodKind;
use crate::precompile_binding::DIGEST_LIMBS;

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
    /// `INPUT_SHUFFLE_PHASE` 列（Gap 6：调用时的 shuffle_state.phase）。
    pub const INPUT_SHUFFLE_PHASE: usize = COMMON_NUM_COLUMNS + 5;
    /// `INPUT_SHUFFLE_PHASE_Q` 列（Gap 6 witness：shuffle_phase²，拆 3 次 vanishing）。
    pub const INPUT_SHUFFLE_PHASE_Q: usize = COMMON_NUM_COLUMNS + 6;
    /// Creator authorization ABI version.
    pub const AUTH_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 7;
    /// Creator authorization role.
    pub const AUTH_ROLE: usize = COMMON_NUM_COLUMNS + 8;
    /// Creator authorization request digest.
    pub const AUTH_REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 9;
    /// Creator authorization receipt digest.
    pub const AUTH_RECEIPT_DIGEST_BASE: usize = AUTH_REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// 总列数。
    pub const NUM_COLUMNS: usize = AUTH_RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `reset_for_next_hand` 输入参数。
#[derive(Debug, Clone)]
pub struct ResetForNextHandInput {
    /// 调用时的 `shuffle_state.phase`（Gap 6：必须 ∈ {0,1,2,3}）。
    pub shuffle_phase: u8,
    /// Verifier-issued table-creator authorization receipt.
    pub authorization: AdminAuthorizationAirBinding,
}

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
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for ResetForNextHandAir {
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

        let output_new_round_state = eval.next_trace_mask();
        // 读取 POST_PENDING_ADDON 4 limb
        let post_pending_0 = eval.next_trace_mask();
        let post_pending_1 = eval.next_trace_mask();
        let post_pending_2 = eval.next_trace_mask();
        let post_pending_3 = eval.next_trace_mask();

        // Gap 6：shuffle_phase 与 witness q
        let input_shuffle_phase = eval.next_trace_mask();
        let input_shuffle_phase_q = eval.next_trace_mask();
        let auth_abi_version = eval.next_trace_mask();
        let auth_role = eval.next_trace_mask();
        let auth_request_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let auth_receipt_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：output_new_round_state == ROUND_WAITING (== 0)
        eval.add_constraint(is_active.clone() * output_new_round_state);

        // 约束 2（核心 addon 不变量）：reset 后 POST_PENDING_ADDON 必须全 0
        //    业务语义：pending_addon 已合并到 stack，必须清零，避免重复入账
        eval.add_constraint(is_active.clone() * post_pending_0);
        eval.add_constraint(is_active.clone() * post_pending_1);
        eval.add_constraint(is_active.clone() * post_pending_2);
        eval.add_constraint(is_active.clone() * post_pending_3);
        for limb in &common.post_pot {
            eval.add_constraint(is_active.clone() * limb.clone());
        }

        // 约束（Gap 6 part 1）：shuffle_phase == input.shuffle_phase
        let expected_phase: E::F = M31::from(u32::from(self.input.shuffle_phase)).into();
        eval.add_constraint(is_active.clone() * (input_shuffle_phase.clone() - expected_phase));
        // 约束（Gap 6 part 2）：q == shuffle_phase²（witness 一致性，degree-2）
        eval.add_constraint(
            is_active.clone()
                * (input_shuffle_phase_q.clone()
                    - input_shuffle_phase.clone() * input_shuffle_phase.clone()),
        );
        // 约束（Gap 6 part 3）：shuffle_phase ∈ {0,1,2,3}。
        // VM 允许显式重置尚未开局的 WAITING/NONE 桌台，因此不能排除 0。
        // vanishing phase(phase-1)(phase-2)(phase-3)
        // = phase⁴-6phase³+11phase²-6phase；经 q=phase² 展开为 degree ≤ 2。
        let six: E::F = M31::from(6u32).into();
        let eleven: E::F = M31::from(11u32).into();
        let vp = input_shuffle_phase_q.clone() * input_shuffle_phase_q.clone()
            - six.clone() * input_shuffle_phase.clone() * input_shuffle_phase_q.clone()
            + eleven * input_shuffle_phase_q.clone()
            - six * input_shuffle_phase.clone();
        eval.add_constraint(is_active.clone() * vp);

        let expected_abi: E::F = M31::from(u32::from(self.input.authorization.abi_version)).into();
        let expected_role: E::F = M31::from(u32::from(self.input.authorization.role)).into();
        eval.add_constraint(is_active.clone() * (auth_abi_version - expected_abi));
        eval.add_constraint(is_active.clone() * (auth_role - expected_role));
        for limb in 0..DIGEST_LIMBS {
            eval.add_constraint(
                is_active.clone()
                    * (auth_request_digest[limb].clone()
                        - E::F::from(self.input.authorization.request_digest[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (auth_receipt_digest[limb].clone()
                        - E::F::from(self.input.authorization.receipt_digest[limb])),
            );
        }

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
    /// Gap 6：调用时的 shuffle_state.phase。
    pub input_shuffle_phase: M31,
    /// Gap 6 witness：shuffle_phase²。
    pub input_shuffle_phase_q: M31,
    /// Verifier-issued table-creator authorization binding.
    pub authorization: AdminAuthorizationAirBinding,
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
        input: &ResetForNextHandInput,
        _pre_pending_addon: u64,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
    ) -> Self {
        let sp = u8_to_m31(input.shuffle_phase);
        let q = sp * sp;
        Self {
            common: CommonRow::active(
                MethodKind::ResetForNextHand,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                0, // post = WAITING
                0,
                0,
                0,
                0,
            ),
            output_new_round_state: ZERO, // ROUND_WAITING = 0
            // 关键：reset 后 pending_addon 必须清零（addon 已合并到 stack）
            post_pending_addon: [ZERO; 4],
            input_shuffle_phase: sp,
            input_shuffle_phase_q: q,
            authorization: input.authorization,
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            output_new_round_state: ZERO,
            post_pending_addon: [ZERO; 4],
            input_shuffle_phase: ZERO,
            input_shuffle_phase_q: ZERO,
            authorization: AdminAuthorizationAirBinding {
                abi_version: 0,
                role: 0,
                request_digest: [ZERO; DIGEST_LIMBS],
                receipt_digest: [ZERO; DIGEST_LIMBS],
            },
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.push(self.output_new_round_state);
        v.extend_from_slice(&self.post_pending_addon);
        v.push(self.input_shuffle_phase);
        v.push(self.input_shuffle_phase_q);
        v.push(M31::from(u32::from(self.authorization.abi_version)));
        v.push(M31::from(u32::from(self.authorization.role)));
        v.extend_from_slice(&self.authorization.request_digest);
        v.extend_from_slice(&self.authorization.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}
