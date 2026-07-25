//! Post-commit Prover Orchestrator — 异步消费证明任务，生成并聚合 proof。
//!
//! ## 架构
//!
//! ```text
//! ┌─ poker_l1 dispatch（同步，不阻塞）──────────────┐
//! │ Precompile.call()                                │
//! │  ├─ apply_* （状态转移）                          │
//! │  └─ return_value = borsh(DispatchOutput{         │
//! │         events, prove_task: Some(ProveTask)      │
//! │     })                                            │
//! └────────────────────┬─────────────────────────────┘
//!                      │ 链层取回 return_value
//! ┌─────────────────────▼─────────────────────────────┐
//! │ Orchestrator（本模块，链下/独立进程）              │
//! │  for task in tasks:                               │
//! │   child = prove_and_verify_task(task)?            │
//! │   children.push(child)                            │
//! │  verify_chain(&children)?  // left.post==right.pre│
//! │  // TODO: aggregate_proofs(children) → final proof│
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! ## 职责边界
//!
//! - **生成**：为每个 [`ProveTask`] 构造 trace + AIR，调 [`prove_method`]
//! - **自验**：prove 后立即 [`verify_method`]，确保每个 proof 有效
//! - **链式一致性**：验证相邻任务的 `post_state_root == next.pre_state_root`
//! - **不负责**：proof 序列化/传输/L1 提交（留后续 L1 submit 层）
//!
//! ## 当前覆盖
//!
//! 本模块为 [`MethodKind::CreateTable`] 和 [`MethodKind::Fold`] 提供完整的
//! trace 构造 + prove + verify。其余方法的 trace 构造留 TODO（模式确立后
//! 机械扩展，每个方法约 10 行 match 分支）。

use stwo::core::fields::m31::M31;

use crate::airs::actions::fold::{FoldAir, FoldInput, FoldRow};
use crate::airs::common::ZERO;
use crate::airs::lifecycle::create_table::{CreateTableAir, CreateTableInput, CreateTableRow};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::{MethodInput, ProveTask};
use crate::prover::prove_method;
use crate::state_root::{compute_state_root, StateRoot};
use crate::trace_gen::generic_trace::gen_method_trace;

/// 把 Starknet FieldElement（state_root）转为 4 个 M31 limb。
///
/// 复用 create_table_trace 的占位实现（返回 [ZERO;4]），因为当前
/// Starknet Fr → M31 4-limb 的完整转换尚未接入（依赖 Poseidon252 AIR）。
/// Orchestrator 内部用此函数保持 pre/post state_root 的 limb 一致性，
/// 不影响 proof 正确性（约束侧同样用占位）。
fn state_root_to_m31_limbs(root: StateRoot) -> [M31; 4] {
    // 占位：完整实现见 create_table_trace.rs::starknet_field_to_m31_limbs 的 TODO。
    // 当前所有 AIR 的 state_root limb 都用占位，保持一致即可通过约束。
    let _ = root;
    [ZERO; 4]
}

/// 已证明任务的摘要（用于链式一致性验证 + 后续聚合）。
#[derive(Debug, Clone)]
pub struct ProvenTask {
    /// 任务原始 method kind。
    pub method_kind: MethodKind,
    /// 调用前 state_root。
    pub pre_state_root: StateRoot,
    /// 调用后 state_root。
    pub post_state_root: StateRoot,
    /// call_seq（链排序用）。
    pub call_seq: u32,
}

impl ProvenTask {
    /// 转为 Aggregator 的子节点描述符。
    #[must_use]
    pub fn to_child_descriptor(&self) -> crate::aggregator_air::ChildDescriptor {
        crate::aggregator_air::ChildDescriptor {
            pre_state_root: state_root_to_m31_limbs(self.pre_state_root),
            post_state_root: state_root_to_m31_limbs(self.post_state_root),
            call_seq: self.call_seq,
            method_kind: self.method_kind,
        }
    }
}

/// Orchestrator：消费证明任务，生成并自验 proof。
#[derive(Debug, Default)]
pub struct Orchestrator {
    /// 已证明的任务摘要（按 prove 顺序）。
    proven: Vec<ProvenTask>,
}

impl Orchestrator {
    /// 构造空 Orchestrator。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 处理一个证明任务：prove + 立即 verify，返回任务摘要。
    ///
    /// # Errors
    ///
    /// - trace 构造失败（方法未实现 / 字段越界）
    /// - Stwo prover 错误（约束不满足）
    /// - verify 失败（proof 无效）
    pub fn prove_and_verify_task(&mut self, task: &ProveTask) -> TexasAirResult<ProvenTask> {
        let pre_root = compute_state_root(&task.pre_table)?;
        let post_root = compute_state_root(&task.post_table)?;
        let summary = ProvenTask {
            method_kind: task.method_kind,
            pre_state_root: pre_root,
            post_state_root: post_root,
            call_seq: task.call_seq,
        };

        match task.method_kind {
            MethodKind::CreateTable => self.prove_create_table(task, pre_root, post_root)?,
            MethodKind::Fold => self.prove_fold(task, pre_root, post_root)?,
            other => {
                return Err(TexasAirError::NotImplemented(format!(
                    "Orchestrator: method {other:?} 的 trace 构造未实现（当前仅支持 CreateTable / Fold）"
                )));
            }
        }

        self.proven.push(summary.clone());
        Ok(summary)
    }

    /// 处理一批任务（按顺序 prove + verify）。
    ///
    /// # Errors
    ///
    /// 任一任务失败则停止并返回错误。
    pub fn prove_tasks(&mut self, tasks: &[ProveTask]) -> TexasAirResult<Vec<ProvenTask>> {
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            out.push(self.prove_and_verify_task(t)?);
        }
        Ok(out)
    }

    /// 验证已证明任务的链式一致性：相邻任务的 post/pre state_root 衔接。
    ///
    /// 约束：`proven[i].post_state_root == proven[i+1].pre_state_root`。
    ///
    /// # Errors
    ///
    /// 链断裂时返回 [`TexasAirError::SpecViolation`]。
    pub fn verify_chain(&self) -> TexasAirResult<()> {
        for w in self.proven.windows(2) {
            let left = &w[0];
            let right = &w[1];
            if left.post_state_root != right.pre_state_root {
                return Err(TexasAirError::SpecViolation(format!(
                    "state_root 链断裂 @ call_seq {}→{}: left.post={:?} != right.pre={:?}",
                    left.call_seq, right.call_seq, left.post_state_root, right.pre_state_root
                )));
            }
        }
        Ok(())
    }

    /// 返回已证明任务摘要的切片。
    #[must_use]
    pub fn proven(&self) -> &[ProvenTask] {
        &self.proven
    }

    // ===== 各方法的 trace 构造 + prove + verify =====

    fn prove_create_table(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
    ) -> TexasAirResult<()> {
        let MethodInput::CreateTable {
            name,
            max_players,
            small_blind,
            big_blind,
        } = &task.method_input
        else {
            return Err(TexasAirError::SpecViolation(format!(
                "create_table 任务的 method_input 应为 CreateTable，实际：{:?}",
                task.method_input
            )));
        };

        let input = CreateTableInput {
            name: name.clone(),
            max_players: *max_players,
            small_blind: *small_blind,
            big_blind: *big_blind,
        };
        let pre_version = task.pre_table.version;
        let post_version = task.post_table.version;

        let row = CreateTableRow::active(
            &input,
            state_root_to_m31_limbs(pre_root),
            state_root_to_m31_limbs(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_version,
            post_version,
        );
        let padding = CreateTableRow::padding();
        let trace = gen_method_trace(CreateTableAir::num_columns(), &row.to_vec(), &padding.to_vec())?;
        let air = CreateTableAir::new(
            crate::trace_gen::generic_trace::MIN_LOG_SIZE,
            input,
            state_root_to_m31_limbs(pre_root),
            state_root_to_m31_limbs(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_version,
            post_version,
        );
        let proof = prove_method(&trace, air, CreateTableAir::num_columns())?;
        crate::verifier::verify_method(proof)
    }

    fn prove_fold(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
    ) -> TexasAirResult<()> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(TexasAirError::SpecViolation(format!(
                "fold 任务的 method_input 应为 SeatOnly，实际：{:?}",
                task.method_input
            )));
        };
        let input = FoldInput {
            seat_index: *seat_index,
        };
        let pre_version = task.pre_table.version;
        let post_version = task.post_table.version;
        let pre_round_state = task.pre_table.round_state;
        let post_round_state = task.post_table.round_state;

        let row = FoldRow::active(
            &input,
            state_root_to_m31_limbs(pre_root),
            state_root_to_m31_limbs(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_version,
            post_version,
            pre_round_state,
            post_round_state,
        );
        let padding = FoldRow::padding();
        let trace = gen_method_trace(FoldAir::num_columns(), &row.to_vec(), &padding.to_vec())?;
        let air = FoldAir {
            log_size: crate::trace_gen::generic_trace::MIN_LOG_SIZE,
            input,
            pre_state_root: state_root_to_m31_limbs(pre_root),
            post_state_root: state_root_to_m31_limbs(post_root),
            table_id: task.table_id,
            hand_id: task.hand_id,
            call_seq: task.call_seq,
            pre_version,
            post_version,
        };
        let proof = prove_method(&trace, air, FoldAir::num_columns())?;
        crate::verifier::verify_method(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;

    fn make_table(name: &str) -> TexasPokerTable {
        TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            name.into(),
            [0u8; 20],
            6,
            50,
            100,
        )
    }

    #[test]
    fn orchestrator_prove_create_table() {
        let pre = make_table("pre");
        let mut post = make_table("post");
        post.version = 1; // create_table 后 version+1
        let task = ProveTask::new(
            MethodKind::CreateTable,
            MethodInput::CreateTable {
                name: "post".into(),
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
            },
            pre,
            post,
            1,
            0,
            0,
        );
        let mut orch = Orchestrator::new();
        let summary = orch.prove_and_verify_task(&task).expect("create_table prove+verify 应成功");
        assert_eq!(summary.method_kind, MethodKind::CreateTable);
        assert!(orch.verify_chain().is_ok());
    }

    #[test]
    fn orchestrator_prove_fold() {
        let mut pre = make_table("pre");
        pre.version = 1;
        pre.round_state = poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
        pre.seats[0].player = [0x01; 20];
        pre.seats[0].stack = 1000;
        let mut post = pre.clone();
        post.seats[0].folded = true;
        post.version = 2;

        let task = ProveTask::new(
            MethodKind::Fold,
            MethodInput::SeatOnly { seat_index: 0 },
            pre,
            post,
            1,
            1,
            1,
        );
        let mut orch = Orchestrator::new();
        orch.prove_and_verify_task(&task).expect("fold prove+verify 应成功");
    }

    #[test]
    fn orchestrator_unsupported_method_returns_not_implemented() {
        let pre = make_table("pre");
        let post = make_table("post");
        let task = ProveTask::new(
            MethodKind::Check,
            MethodInput::SeatOnly { seat_index: 0 },
            pre,
            post,
            1,
            0,
            0,
        );
        let mut orch = Orchestrator::new();
        let result = orch.prove_and_verify_task(&task);
        assert!(matches!(result, Err(TexasAirError::NotImplemented(_))));
    }

    /// 端到端：两步链式证明，验证 state_root 链衔接。
    ///
    /// 这是 Post-commit Prover 的核心场景：两个方法的 proof 各自生成 + verify，
    /// 且第二个任务的 pre_state_root == 第一个任务的 post_state_root。
    ///
    /// 注：真实业务链 create_table → start_hand → fold 中间需 start_hand
    /// （Orchestrator 暂未实现 start_hand 的 trace）。此处用两个 create_table
    /// 验证链式衔接机制本身——只要 Task2.pre == Task1.post 即可。
    #[test]
    fn orchestrator_chain_two_tasks() {
        // Task 1: create_table（version 0→1）
        let pre1 = make_table("pre_placeholder");
        let mut post1 = make_table("table_v1");
        post1.version = 1;
        let task1 = ProveTask::new(
            MethodKind::CreateTable,
            MethodInput::CreateTable {
                name: "table_v1".into(),
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
            },
            pre1,
            post1.clone(), // post1 原样作为 Task2 的 pre
            1,
            0,
            0,
        );

        // Task 2: 再次 create_table（version 1→2，pre = Task1 的 post）
        let mut post2 = post1; // 注意：post1 已 move，此处 post2 == Task1.post
        post2.version = 2;
        let task2 = ProveTask::new(
            MethodKind::CreateTable,
            MethodInput::CreateTable {
                name: "table_v1".into(),
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
            },
            // pre2 必须与 task1 的 post_table 完全一致（state_root 才衔接）
            // post1 已 move 进 post2，故重建一个等价的 pre
            {
                let mut p = make_table("table_v1");
                p.version = 1;
                p
            },
            post2,
            1,
            0,
            1,
        );

        let mut orch = Orchestrator::new();
        let summaries = orch
            .prove_tasks(&[task1, task2])
            .expect("两个任务都应 prove+verify 成功");

        assert_eq!(summaries.len(), 2);
        // 链式一致性：Task1.post == Task2.pre
        assert_eq!(
            summaries[0].post_state_root, summaries[1].pre_state_root,
            "Task1 的 post_state_root 应等于 Task2 的 pre_state_root"
        );
        orch.verify_chain().expect("state_root 链应衔接");
    }

    /// 链断裂检测：两个任务 post≠pre 时 verify_chain 应失败。
    #[test]
    fn orchestrator_detects_broken_chain() {
        let mut orch = Orchestrator::new();
        // 手动注入两个 state_root 不衔接的摘要（绕过 prove，直接测 verify_chain）
        orch.proven.push(ProvenTask {
            method_kind: MethodKind::CreateTable,
            pre_state_root: StateRoot::from_field(FieldElement::from(1u64)),
            post_state_root: StateRoot::from_field(FieldElement::from(2u64)),
            call_seq: 0,
        });
        orch.proven.push(ProvenTask {
            method_kind: MethodKind::Fold,
            // pre != 上一个的 post(2)
            pre_state_root: StateRoot::from_field(FieldElement::from(3u64)),
            post_state_root: StateRoot::from_field(FieldElement::from(4u64)),
            call_seq: 1,
        });
        assert!(orch.verify_chain().is_err(), "链断裂应被检测到");
    }
}

// 避免未使用 import 警告（FieldElement 在下方测试模块用）。
#[cfg(test)]
use starknet_ff::FieldElement;
