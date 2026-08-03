//! Post-commit Prover Orchestrator — 异步消费证明任务并生成 host-verified chain。
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
//! │   prove = prove_method(task)?                     │
//! │   receipt = native_verify(proof, trusted_pi)?     │
//! │   verified_chain.push(receipt)?                   │
//! │  // 当前停在 VerifiedChain；无可信 final recursion │
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! ## 职责边界
//!
//! - **生成**：为每个 [`ProveTask`] 构造 trace + AIR，调 [`prove_method`]
//! - **自验**：prove 后立即用 verifier 独立提供的 AIR/PI 原生验证，并签发 receipt
//! - **链式一致性**：只聚合 verifier receipt，检查 table/hand/call_seq/
//!   full state root/version 连续性
//! - **信任边界**：该路径是 O(N) 宿主验证，不是 recursive/succinct proof
//! - **外部锚定**：本模块验证“给定 pre-state 上该 dispatch 的 VM 语义有效”；调用方仍须
//!   从已认证区块/receipt 取得任务，或把首尾 state root 与外部共识状态比对。本模块不证明
//!   `ProveTask.context` 自身已被链共识认证
//! - **不负责**：proof 序列化/传输/L1 提交（留后续 L1 submit 层）
//!
//! ## 当前覆盖
//!
//! 23 个 VM selector 都能进入统一任务格式；其中 21 个已有 trace 构造 + prove +
//! verify 路径。`request_leave_after_hand` 与 `fold_with_proof` 只允许任务被编码和
//! 反序列化，生产 Orchestrator 明确 fail-closed，不签发 proof/receipt。后者尤其尚未
//! 证明 DLEq layer removal，也未覆盖可能发生的 `advance_turn`/settlement。

use poker_protocol::precompile::{
    build_bls12381_reconstruction_v3_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::TranscriptId;
use stwo::core::fields::m31::M31;

use crate::airs::actions::auto_fold::{AutoFoldAir, AutoFoldInput, AutoFoldRow};
use crate::airs::actions::bet::{BetAir, BetInput, BetRow};
use crate::airs::actions::call::{CallAir, CallInput, CallRow};
use crate::airs::actions::check::{CheckAir, CheckInput, CheckRow};
use crate::airs::actions::fold::{FoldAir, FoldInput, FoldRow};
use crate::airs::actions::force_fold::{ForceFoldAir, ForceFoldInput, ForceFoldRow};
use crate::airs::actions::kick_player::{KickPlayerAir, KickPlayerInput, KickPlayerRow};
use crate::airs::actions::raise::{RaiseAir, RaiseInput, RaiseRow};
use crate::airs::crypto::join_and_shuffle::{
    JoinAndShuffleAir, JoinAndShuffleInput, JoinAndShuffleRow,
};
use crate::airs::crypto::leave_with_proof::{
    LeaveWithProofAir, LeaveWithProofInput, LeaveWithProofRow,
};
use crate::airs::crypto::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use crate::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use crate::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use crate::airs::funds::addon::{AddonAir, AddonInput, AddonRow};
use crate::airs::funds::rebuy::{RebuyAir, RebuyInput, RebuyRow};
use crate::airs::lifecycle::create_table::{CreateTableAir, CreateTableInput, CreateTableRow};
use crate::airs::lifecycle::join_table::{JoinTableAir, JoinTableInput, JoinTableRow};
use crate::airs::lifecycle::leave_table::{LeaveTableAir, LeaveTableInput, LeaveTableRow};
use crate::airs::lifecycle::reset_for_next_hand::{
    ResetForNextHandAir, ResetForNextHandInput, ResetForNextHandRow,
};
use crate::airs::lifecycle::start_hand::{StartHandAir, StartHandInput, StartHandRow};
use crate::airs::lifecycle::tick::{TickAir, TickInput, TickRow};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{precompile_call_context, PrecompileCallBinding};
use crate::prove_task::{dispatch_call_digest, DispatchOutput, MethodInput, ProveTask};
use crate::prover::prove_method;
#[cfg(feature = "recursive-prover")]
use crate::recursive::prove_method_recursive;
use crate::recursive::verify_method_recursive_proof;
use crate::state_root::{state_root_to_air_limbs, table_state_preimage, StateRoot};
use crate::trace_gen::generic_trace::{gen_method_trace, MIN_LOG_SIZE};
use crate::verified_chain::{
    verify_method_against_and_issue_receipt, ExpectedChainAnchor, VerificationReceipt,
    VerifiedChain, VerifiedChainBuilder,
};

fn state_root_to_m31_limbs(root: StateRoot) -> [M31; 4] {
    state_root_to_air_limbs(root)
}

/// 已处理任务的 descriptor 摘要。
///
/// 该类型便于日志和实验性 Aggregator AIR，但它不是 proof 验证回执，
/// 不能用来构造 [`VerifiedChain`]。可信链只由原生 verifier 签发的
/// [`VerificationReceipt`] 构造。
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
    /// 转为实验性 descriptor-only Aggregator 的子节点描述符。
    ///
    /// 返回值不能证明任何子 proof 已被验证，生产 Aggregator 入口会
    /// fail closed。
    #[must_use]
    pub fn to_child_descriptor(&self) -> crate::aggregator_air::ChildDescriptor {
        crate::aggregator_air::ChildDescriptor {
            pre_state_root: state_root_to_m31_limbs(self.pre_state_root),
            post_state_root: state_root_to_m31_limbs(self.post_state_root),
            call_seq: self.call_seq,
            method_kind: self.method_kind,
            recursive_proof: None,
        }
    }
}

/// Orchestrator：消费证明任务，生成并自验 proof。
#[derive(Debug, Default)]
pub struct Orchestrator {
    /// 已证明的任务摘要（按 prove 顺序）。
    proven: Vec<ProvenTask>,
    /// 只有原生 verifier 成功后才会签发的验证回执。
    verified_chain_builder: VerifiedChainBuilder,
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
        let mut backend = NativeMethodProofBackend;
        let (summary, receipt) = self.process_task(task, &mut backend)?;
        self.verified_chain_builder.push_receipt(receipt)?;
        self.proven.push(summary.clone());
        Ok(summary)
    }

    /// Replay an authenticated task, reconstruct its trusted AIR/public inputs, and directly
    /// verify a recursive STWO proof without accepting or regenerating the inner method proof.
    ///
    /// The caller remains responsible for authenticating `task` against L1 consensus/state. This
    /// function treats every task field as untrusted, replays the VM dispatch, and derives the AIR
    /// and replicated row locally before invoking the recursive verifier.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled selector, failed VM replay, task/row mismatch, or invalid
    /// recursive proof/public inputs.
    pub fn verify_recursive_task(
        task: &ProveTask,
        recursive_proof: &poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof,
        recursive_inputs: &poker_zkvm::stwo_backend::recursive::RecursivePublicInputs,
    ) -> TexasAirResult<()> {
        let orchestrator = Self::new();
        let mut backend = RecursiveMethodVerifierBackend {
            recursive_proof,
            recursive_inputs,
        };
        orchestrator.process_task(task, &mut backend).map(|_| ())
    }

    /// Replay one task, generate its inner method proof, and immediately wrap it in a recursive
    /// STWO proof. The returned value intentionally excludes the inner proof.
    ///
    /// # Errors
    ///
    /// Returns an error for failed task replay, method proving, native verification, or recursive
    /// proving.
    #[cfg(feature = "recursive-prover")]
    pub fn prove_recursive_task(
        task: &ProveTask,
    ) -> TexasAirResult<(
        poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof,
        poker_zkvm::stwo_backend::recursive::RecursivePublicInputs,
    )> {
        let orchestrator = Self::new();
        let mut backend = RecursiveMethodProverBackend;
        orchestrator
            .process_task(task, &mut backend)
            .map(|(_, recursive)| recursive)
    }

    fn process_task<B: MethodBackend>(
        &self,
        task: &ProveTask,
        backend: &mut B,
    ) -> TexasAirResult<(ProvenTask, B::Output)> {
        // These selectors are part of the VM/task wire format, but their AIR
        // statements are not yet trustworthy. Reject them before dispatch
        // replay or any proof construction so no partial receipt can escape.
        match task.method_kind {
            MethodKind::RequestLeaveAfterHand => {
                return Err(unsupported_registered_method(task.method_kind));
            }
            MethodKind::FoldWithProof => {
                return Err(unsupported_registered_method(task.method_kind));
            }
            _ => {}
        }

        validate_full_dispatch_task(task)?;
        let pre_image = table_state_preimage(&task.pre_table)?;
        let post_image = table_state_preimage(&task.post_table)?;
        let pre_root = StateRoot(starknet_crypto::poseidon_hash_many(&pre_image));
        let post_root = StateRoot(starknet_crypto::poseidon_hash_many(&post_image));
        // 完整公开输入（preimage + 重算 root + 元数据），用于 state_root 绑定。
        let pi = crate::public_inputs::TexasPublicInputs {
            pre_image,
            post_image,
            pre_state_root: pre_root,
            post_state_root: post_root,
            kind: task.method_kind,
            table_id: task.table_id,
            hand_id: task.hand_id,
            call_seq: task.call_seq,
            pre_version: task.pre_table.version,
            post_version: task.post_table.version,
            dispatch_call_digest: dispatch_call_digest(
                &task.context,
                &task.selector,
                &task.raw_args,
            )?,
            precompile_binding: None,
            expected_trace_row: None,
        };
        let summary = ProvenTask {
            method_kind: task.method_kind,
            pre_state_root: pre_root,
            post_state_root: post_root,
            call_seq: task.call_seq,
        };

        let output = match task.method_kind {
            MethodKind::CreateTable => {
                self.prove_create_table(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::JoinTable => {
                self.prove_join_table(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::LeaveTable => {
                self.prove_leave_table(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::StartHand => {
                self.prove_start_hand(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::Tick => self.prove_tick(task, pre_root, post_root, &pi, backend)?,
            MethodKind::ResetForNextHand => {
                self.prove_reset_for_next_hand(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::Fold => self.prove_fold(task, pre_root, post_root, &pi, backend)?,
            MethodKind::Check => self.prove_check(task, pre_root, post_root, &pi, backend)?,
            MethodKind::Call => self.prove_call(task, pre_root, post_root, &pi, backend)?,
            MethodKind::Raise => self.prove_raise(task, pre_root, post_root, &pi, backend)?,
            MethodKind::AutoFold => {
                self.prove_auto_fold(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::ForceFold => {
                self.prove_force_fold(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::KickPlayer => {
                self.prove_kick_player(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::Addon => self.prove_addon(task, pre_root, post_root, &pi, backend)?,
            MethodKind::Rebuy => self.prove_rebuy(task, pre_root, post_root, &pi, backend)?,
            MethodKind::Bet => self.prove_bet(task, pre_root, post_root, &pi, backend)?,
            MethodKind::JoinAndShuffle => {
                self.prove_join_and_shuffle(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::LeaveWithProof => {
                self.prove_leave_with_proof(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::SubmitShuffleV2 => {
                self.prove_submit_shuffle_v2(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::SubmitPlayerRevealTokens => {
                self.prove_submit_reveal_tokens(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::SubmitReconstructDeck => {
                self.prove_submit_reconstruct_deck(task, pre_root, post_root, &pi, backend)?
            }
            MethodKind::RequestLeaveAfterHand | MethodKind::FoldWithProof => {
                return Err(unsupported_registered_method(task.method_kind));
            }
        };

        Ok((summary, output))
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

    /// Prove and natively verify the provided task slice, returning an unanchored
    /// host-side continuity artifact.
    ///
    /// This convenience entry point always starts from a fresh orchestrator so
    /// a previous batch cannot be spliced into the result accidentally. Runtime
    /// and verification cost are O(N) in the number of method proofs.
    ///
    /// # Errors
    ///
    /// Returns an error if any proof fails native verification, the slice is
    /// empty, or receipt metadata/state continuity is broken. This function
    /// alone does not prove block inclusion or that the slice is a complete batch.
    pub fn prove_and_verify_chain(tasks: &[ProveTask]) -> TexasAirResult<VerifiedChain> {
        let mut orchestrator = Self::new();
        orchestrator.prove_tasks(tasks)?;
        orchestrator.verified_chain()
    }

    /// Prove and verify an exact chain range against consensus-derived anchors.
    ///
    /// Production callers should prefer this over unanchored continuity checks.
    /// The expected endpoints and per-call digests must come from authenticated
    /// block/transaction data, not from the same tasks being proved.
    ///
    /// # Errors
    ///
    /// Returns an error for proof/dispatch failure, discontinuity, or any anchor
    /// mismatch (including omitted prefix/suffix calls within the expected range).
    pub fn prove_and_verify_chain_against(
        tasks: &[ProveTask],
        expected: &ExpectedChainAnchor,
    ) -> TexasAirResult<VerifiedChain> {
        let chain = Self::prove_and_verify_chain(tasks)?;
        chain.verify_against_anchor(expected)?;
        Ok(chain)
    }

    /// 验证已证明任务的完整链式一致性。
    ///
    /// 只使用原生 verifier 签发的 receipt，同时检查 table/hand、
    /// call_seq、完整 state root 与 state version 的连续性。
    ///
    /// # Errors
    ///
    /// 链断裂时返回 [`TexasAirError::RecursionError`]。
    pub fn verify_chain(&self) -> TexasAirResult<()> {
        self.verified_chain().map(|_| ())
    }

    /// 生成未外部锚定的宿主侧已验证链。
    ///
    /// 这是 O(N) 原生 proof 验证和相邻连续性的接受产物，不证明任务来自区块，
    /// 也不证明这是某 hand/batch 的完整范围。生产调用方应进一步使用
    /// [`VerifiedChain::verify_against_anchor`]，且不能把结果当成 succinct recursive proof。
    ///
    /// # Errors
    ///
    /// 空链，或 table/hand/call_seq/state-root/version 不连续时返回错误。
    pub fn verified_chain(&self) -> TexasAirResult<VerifiedChain> {
        self.verified_chain_builder.snapshot()
    }

    /// 返回已证明任务摘要的切片。
    #[must_use]
    pub fn proven(&self) -> &[ProvenTask] {
        &self.proven
    }

    /// 开始一条新的已验证 receipt 链片段。
    ///
    /// 已验证 receipt 链按设计以单局 `hand_id` 为边界（相邻 receipt 的 `hand_id`
    /// 必须相同，见 `verified_chain::validate_adjacent_receipts`）。当跨局推进
    /// （如 `start_hand` 使 `hand_id` 递增）时，旧的局内链无法继续承接新 receipt，
    /// 调用本方法清空 `verified_chain_builder` 的 receipts，使新一局从空链重新累积。
    ///
    /// 已证明任务的 `proven` 摘要历史**不清除**（聚合入口仍可见全部任务）；
    /// 仅 `verify_chain` / `verified_chain` 反映当前局的连续性。
    ///
    /// 生产语义不变：链仍只做未外部锚定的相邻连续性检查，不声称 block inclusion。
    pub fn start_new_chain_segment(&mut self) {
        self.verified_chain_builder.clear_receipts();
    }

    // ===== 各方法的 trace 构造 + prove + verify =====

    fn prove_create_table<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
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
        run(
            backend,
            CreateTableAir::num_columns(),
            &row,
            &CreateTableRow::padding(),
            pi,
            move || {
                CreateTableAir::new(
                    MIN_LOG_SIZE,
                    input,
                    state_root_to_m31_limbs(pre_root),
                    state_root_to_m31_limbs(post_root),
                    task.table_id,
                    task.hand_id,
                    task.call_seq,
                    pre_version,
                    post_version,
                )
            },
        )
    }

    fn prove_fold<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(TexasAirError::SpecViolation(format!(
                "fold 任务的 method_input 应为 SeatOnly，实际：{:?}",
                task.method_input
            )));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::Fold {
                seat_index: *seat_index,
            },
        )?;
        let input = FoldInput {
            seat_index: *seat_index,
            post_current_turn,
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
        run(
            backend,
            FoldAir::num_columns(),
            &row,
            &FoldRow::padding(),
            pi,
            move || FoldAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: state_root_to_m31_limbs(pre_root),
                post_state_root: state_root_to_m31_limbs(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version,
                post_version,
            },
        )
    }

    // ===== 以下为其余 19 个方法的 trace 构造（模式同 prove_create_table / prove_fold）=====
    //
    // 设计说明：
    // - pre/post 业务字段（round_state / pot / version / seat 标量）从 task 的
    //   pre_table / post_table 快照直接读取；这些快照由 poker_l1 dispatch 真实
    //   产生，状态转移正确性来自合约，电路只做"输入一致性 + AIR 现有约束"证明。
    // - state_root limb 用 state_root_to_m31_limbs（占位）保持一致。
    // - seat_index 越界返回 SpecViolation（host 端不应产生越界任务）。

    /// 读取 `table.seats[seat_index]`，越界返回错误。
    fn seat(
        table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        seat_index: u8,
    ) -> TexasAirResult<poker_l1::vm::contracts::texas_poker::types::Seat> {
        table
            .seats
            .get(usize::from(seat_index))
            .cloned()
            .ok_or_else(|| {
                TexasAirError::SpecViolation(format!(
                    "seat_index {seat_index} 越界（seats.len={}）",
                    table.seats.len()
                ))
            })
    }

    fn prove_join_table<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Join { player, buy_in } = &task.method_input else {
            return Err(input_mismatch("join_table", "Join", &task.method_input));
        };
        let input = JoinTableInput {
            seat_index: find_join_seat(&task.post_table, player)?,
            buy_in: *buy_in,
            player_addr: *player,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let row = JoinTableRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            task.pre_table.big_blind,
            task.pre_table.chip_pool,
            task.pre_table.addon_pool,
        );
        run(
            backend,
            JoinTableAir::num_columns(),
            &row,
            &JoinTableRow::padding(),
            pi,
            move || JoinTableAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_leave_table<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(input_mismatch(
                "leave_table",
                "SeatOnly",
                &task.method_input,
            ));
        };
        let input = LeaveTableInput {
            seat_index: *seat_index,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let refund = pre_seat
            .stack
            .checked_add(pre_seat.pending_addon)
            .ok_or_else(|| TexasAirError::SpecViolation("leave_table refund overflow".into()))?;
        let expected_post_chip_pool =
            task.pre_table
                .chip_pool
                .checked_sub(refund)
                .ok_or_else(|| {
                    TexasAirError::SpecViolation("leave_table chip_pool underflow".into())
                })?;
        let expected_post_addon_pool = task
            .pre_table
            .addon_pool
            .checked_sub(pre_seat.pending_addon)
            .ok_or_else(|| {
                TexasAirError::SpecViolation("leave_table addon_pool underflow".into())
            })?;
        if task.post_table.chip_pool != expected_post_chip_pool
            || task.post_table.addon_pool != expected_post_addon_pool
        {
            return Err(TexasAirError::SpecViolation(
                "leave_table post funds do not match non-underflowing pool subtraction".into(),
            ));
        }
        let row = LeaveTableRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_seat.stack,
            pre_seat.pending_addon,
            task.pre_table.chip_pool,
            task.post_table.chip_pool,
            task.pre_table.addon_pool,
            task.post_table.addon_pool,
        );
        run(
            backend,
            LeaveTableAir::num_columns(),
            &row,
            &LeaveTableRow::padding(),
            pi,
            move || LeaveTableAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_start_hand<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let input = StartHandInput {
            active_count: count_active_occupied(&task.pre_table),
            ante_mode: task.post_table.ante_mode,
            ante_amount: task.post_table.ante_amount,
            ante_collected: task.post_table.ante_collected,
        };
        // Gap 4 witness：active_count*(active_count-1) 在 M31 域内的乘法逆元 + 乘积。
        // active_count ≥ 2（合约 start_hand 前置）时该乘积非零，inverse 存在。
        let count_m31 = M31::from(u32::from(input.active_count));
        let count_minus_one = count_m31 - M31::from(1u32);
        let active_count_prod = count_m31 * count_minus_one;
        let active_count_inv = active_count_prod.inverse();
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let row = StartHandRow::active(
            &input,
            active_count_inv,
            active_count_prod,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
        );
        run(
            backend,
            StartHandAir::num_columns(),
            &row,
            &StartHandRow::padding(),
            pi,
            move || StartHandAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_tick<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        // tick 无 prove_task（dispatch 返回 None），但保留接线以备手动/集成驱动。
        let MethodInput::Empty = &task.method_input else {
            return Err(input_mismatch("tick", "Empty", &task.method_input));
        };
        let input = TickInput {
            current_time: 0,
            // Gap 5：tick AIR 现要求 timeout_kind > 0（invertibility witness 约束
            // `timeout_kind * inv == 1`）。tick 暂无 prove_task，此处固定为 1 以使
            // inverse(1) = 1 存在、约束可满足。真实驱动时由调用方按超时类型传入。
            timeout_kind: 1,
            time_bank_consumed: 0,
            time_bank_post: 0,
            rake_mode: task.post_table.rake_mode,
            rake_amount: task.post_table.rake_collected,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let row = TickRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
        );
        run(
            backend,
            TickAir::num_columns(),
            &row,
            &TickRow::padding(),
            pi,
            move || TickAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_reset_for_next_hand<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Empty = &task.method_input else {
            return Err(input_mismatch(
                "reset_for_next_hand",
                "Empty",
                &task.method_input,
            ));
        };
        let input = ResetForNextHandInput {
            shuffle_phase: task.post_table.shuffle_state.phase,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let pre_r = task.pre_table.round_state;
        let row = ResetForNextHandRow::active(
            &input,
            0, // _pre_pending_addon（未用）
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
        );
        run(
            backend,
            ResetForNextHandAir::num_columns(),
            &row,
            &ResetForNextHandRow::padding(),
            pi,
            move || ResetForNextHandAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_check<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(input_mismatch("check", "SeatOnly", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::Check {
                seat_index: *seat_index,
            },
        )?;
        let seat = Self::seat(&task.pre_table, *seat_index)?;
        let current_bet = task
            .pre_table
            .betting_round
            .as_ref()
            .map_or(0, |b| b.current_bet);
        let input = CheckInput {
            seat_index: *seat_index,
            current_bet,
            seat_bet: seat.bet,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let (pre_pot, post_pot) = (task.pre_table.pot, task.post_table.pot);
        let row = CheckRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
            pre_pot,
            post_pot,
        );
        run(
            backend,
            CheckAir::num_columns(),
            &row,
            &CheckRow::padding(),
            pi,
            move || CheckAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_call<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(input_mismatch("call", "SeatOnly", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::Call {
                seat_index: *seat_index,
            },
        )?;
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let post_seat = Self::seat(&task.post_table, *seat_index)?;
        let call_amount = pre_seat.stack.saturating_sub(post_seat.stack);
        let pre_current_bet = task
            .pre_table
            .betting_round
            .as_ref()
            .expect("mid-round validator requires betting_round")
            .current_bet;
        let input = CallInput {
            seat_index: *seat_index,
            call_amount,
            pre_current_bet,
            pre_seat_bet: pre_seat.bet,
            pre_seat_stack: pre_seat.stack,
            pre_seat_total_bet: pre_seat.total_bet,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let (pre_pot, post_pot) = (task.pre_table.pot, task.post_table.pot);
        let row = CallRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
            pre_pot,
            post_pot,
            post_seat.stack,
            post_seat.bet,
            post_seat.all_in,
            pre_seat.bet,
            pre_seat.stack,
            post_seat.total_bet,
            pre_seat.total_bet,
        );
        run(
            backend,
            CallAir::num_columns(),
            &row,
            &CallRow::padding(),
            pi,
            move || CallAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_raise<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Raise {
            seat_index,
            total_bet,
        } = &task.method_input
        else {
            return Err(input_mismatch("raise", "Raise", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::Raise {
                seat_index: *seat_index,
                total_bet: *total_bet,
            },
        )?;
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let post_seat = Self::seat(&task.post_table, *seat_index)?;
        let pre_round = task
            .pre_table
            .betting_round
            .as_ref()
            .expect("mid-round validator requires betting_round");
        let min_raise = pre_round.min_raise;
        let post_current_bet = task
            .post_table
            .betting_round
            .as_ref()
            .map_or(0, |b| b.current_bet);
        let post_min_raise = task
            .post_table
            .betting_round
            .as_ref()
            .map_or(0, |b| b.min_raise);
        let input = RaiseInput {
            seat_index: *seat_index,
            raise_to: *total_bet,
            min_raise,
            pre_current_bet: pre_round.current_bet,
            pre_seat_stack: pre_seat.stack,
            pre_seat_bet: pre_seat.bet,
            pre_seat_total_bet: pre_seat.total_bet,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let (pre_pot, post_pot) = (task.pre_table.pot, task.post_table.pot);
        let row = RaiseRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
            pre_pot,
            post_pot,
            pre_seat.stack,
            pre_seat.bet,
            pre_seat.total_bet,
            post_seat.stack,
            post_seat.bet,
            post_seat.total_bet,
            post_current_bet,
            post_min_raise,
            post_seat.all_in,
        );
        run(
            backend,
            RaiseAir::num_columns(),
            &row,
            &RaiseRow::padding(),
            pi,
            move || RaiseAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_bet<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Bet { seat_index, amount } = &task.method_input else {
            return Err(input_mismatch("bet", "Bet", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::Bet {
                seat_index: *seat_index,
                amount: *amount,
            },
        )?;
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let post_seat = Self::seat(&task.post_table, *seat_index)?;
        let pre_round = task
            .pre_table
            .betting_round
            .as_ref()
            .expect("mid-round validator requires betting_round");
        let input = BetInput {
            seat_index: *seat_index,
            amount: *amount,
            pre_current_bet: pre_round.current_bet,
            pre_min_raise: pre_round.min_raise,
            pre_seat_bet: pre_seat.bet,
            pre_seat_stack: pre_seat.stack,
            pre_seat_total_bet: pre_seat.total_bet,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let (pre_pot, post_pot) = (task.pre_table.pot, task.post_table.pot);
        let row = BetRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
            pre_pot,
            post_pot,
            post_seat.bet,
            pre_seat.bet,
            pre_seat.stack,
            post_seat.stack,
            pre_seat.total_bet,
            post_seat.total_bet,
        );
        run(
            backend,
            BetAir::num_columns(),
            &row,
            &BetRow::padding(),
            pi,
            move || BetAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_auto_fold<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(input_mismatch("auto_fold", "SeatOnly", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::AutoFold {
                seat_index: *seat_index,
            },
        )?;
        let input = AutoFoldInput {
            seat_index: *seat_index,
            current_time: 0,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let row = AutoFoldRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
        );
        run(
            backend,
            AutoFoldAir::num_columns(),
            &row,
            &AutoFoldRow::padding(),
            pi,
            move || AutoFoldAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_force_fold<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SeatOnly { seat_index } = &task.method_input else {
            return Err(input_mismatch("force_fold", "SeatOnly", &task.method_input));
        };
        let post_current_turn = validate_native_mid_round_action(
            task,
            NativeMidRoundAction::ForceFold {
                seat_index: *seat_index,
            },
        )?;
        let input = ForceFoldInput {
            seat_index: *seat_index,
            post_current_turn,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let row = ForceFoldRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
        );
        run(
            backend,
            ForceFoldAir::num_columns(),
            &row,
            &ForceFoldRow::padding(),
            pi,
            move || ForceFoldAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_kick_player<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Kick {
            seat_index,
            reason: _,
        } = &task.method_input
        else {
            return Err(input_mismatch("kick_player", "Kick", &task.method_input));
        };
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let expected_post_pot = task
            .pre_table
            .pot
            .checked_add(pre_seat.bet)
            .ok_or_else(|| TexasAirError::SpecViolation("kick_player pot overflow".into()))?;
        let expected_post_version = task.pre_table.version.saturating_add(1);
        if task.post_table.round_state != task.pre_table.round_state
            || task.post_table.pot != expected_post_pot
            || task.post_table.version != expected_post_version
        {
            return Err(TexasAirError::UnsupportedBettingTransition(
                "kick_player triggered nested advance/reset/settlement or a multi-version transition; current AIR supports only round-unchanged, pot += kicked_bet, single-version transitions".into(),
            ));
        }
        let input = KickPlayerInput {
            seat_index: *seat_index,
            refund: pre_seat.stack,
            kicked_bet: pre_seat.bet,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let (pre_pot, post_pot) = (task.pre_table.pot, task.post_table.pot);
        let row = KickPlayerRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
            pre_pot,
            post_pot,
        );
        run(
            backend,
            KickPlayerAir::num_columns(),
            &row,
            &KickPlayerRow::padding(),
            pi,
            move || KickPlayerAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_addon<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Funds { seat_index, amount } = &task.method_input else {
            return Err(input_mismatch("addon", "Funds", &task.method_input));
        };
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let input = AddonInput {
            seat_index: *seat_index,
            amount: *amount,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let row = AddonRow::active(
            &input,
            pre_seat.pending_addon,
            task.pre_table.chip_pool,
            task.post_table.chip_pool,
            task.pre_table.addon_pool,
            task.post_table.addon_pool,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
        );
        run(
            backend,
            AddonAir::num_columns(),
            &row,
            &AddonRow::padding(),
            pi,
            move || AddonAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_rebuy<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::Funds { seat_index, amount } = &task.method_input else {
            return Err(input_mismatch("rebuy", "Funds", &task.method_input));
        };
        let pre_seat = Self::seat(&task.pre_table, *seat_index)?;
        let input = RebuyInput {
            seat_index: *seat_index,
            amount: *amount,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let (pre_r, post_r) = (task.pre_table.round_state, task.post_table.round_state);
        let row = RebuyRow::active(
            &input,
            pre_seat.stack,
            task.pre_table.chip_pool,
            task.post_table.chip_pool,
            task.pre_table.addon_pool,
            task.post_table.addon_pool,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_r,
            post_r,
        );
        run(
            backend,
            RebuyAir::num_columns(),
            &row,
            &RebuyRow::padding(),
            pi,
            move || RebuyAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_join_and_shuffle<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::JoinAndShuffle {
            seat_index,
            player: _,
            buy_in: _,
            raw_args: _,
        } = &task.method_input
        else {
            return Err(input_mismatch(
                "join_and_shuffle",
                "JoinAndShuffle",
                &task.method_input,
            ));
        };
        let input = JoinAndShuffleInput {
            seat_index: *seat_index,
            new_deck_commitment: deck_commitment(&task.post_table),
            shuffle_phase: task.post_table.shuffle_state.phase,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let pre_cc = task.pre_table.shuffle_state.completed_players.len() as u8;
        let post_cc = task.post_table.shuffle_state.completed_players.len() as u8;
        let row = JoinAndShuffleRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            pre_cc,
            post_cc,
        );
        run(
            backend,
            JoinAndShuffleAir::num_columns(),
            &row,
            &JoinAndShuffleRow::padding(),
            pi,
            move || JoinAndShuffleAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_leave_with_proof<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::LeaveWithProof {
            seat_index,
            raw_args: _,
        } = &task.method_input
        else {
            return Err(input_mismatch(
                "leave_with_proof",
                "LeaveWithProof",
                &task.method_input,
            ));
        };
        let input = LeaveWithProofInput {
            seat_index: *seat_index,
            leave_kind: 0,
            shuffle_phase: task.post_table.shuffle_state.phase,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let post_cc = task.post_table.shuffle_state.completed_players.len() as u8;
        let row = LeaveWithProofRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            post_cc,
        );
        run(
            backend,
            LeaveWithProofAir::num_columns(),
            &row,
            &LeaveWithProofRow::padding(),
            pi,
            move || LeaveWithProofAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_submit_shuffle_v2<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SubmitShuffleV2 {
            seat_index,
            raw_args,
        } = &task.method_input
        else {
            return Err(input_mismatch(
                "submit_shuffle_v2",
                "SubmitShuffleV2",
                &task.method_input,
            ));
        };
        let args: poker_l1::vm::contracts::texas_poker::dispatch::SubmitShuffleV2Args =
            borsh::from_slice(raw_args).map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_shuffle_v2 raw args borsh: {error}"
                ))
            })?;
        if args.seat_index != *seat_index {
            return Err(TexasAirError::SpecViolation(
                "submit_shuffle_v2 method input seat differs from raw args".into(),
            ));
        }
        let aggregated_pk = task
            .pre_table
            .deck_state
            .aggregated_pk
            .as_ref()
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "submit_shuffle_v2 requires a non-empty aggregated public key".into(),
                )
            })?;
        let call_context = precompile_call_context(
            MethodKind::SubmitShuffleV2,
            *seat_index,
            pi.table_id,
            pi.hand_id,
            pi.call_seq,
            pi.pre_version,
            pi.post_version,
            pi.pre_state_root,
            pi.post_state_root,
            pi.dispatch_call_digest,
        );
        let request = build_bls12381_shuffle_request(
            b"zk_shuffle_proof_v2",
            &call_context,
            TranscriptId::FiatShamirSha3,
            &aggregated_pk.0,
            &task.pre_table.deck_state.encrypted,
            &args.output_cards,
            &args.shuffle_proof,
        )
        .map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "submit_shuffle_v2 precompile request construction failed: {error}"
            ))
        })?;
        let binding = PrecompileCallBinding::verify_shuffle(&request)?;
        let input = SubmitShuffleV2Input {
            seat_index: *seat_index,
            new_deck_commitment: deck_commitment(&task.post_table),
            shuffle_phase: task.post_table.shuffle_state.phase,
            precompile: binding.air_binding(),
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let post_cc = task.post_table.shuffle_state.completed_players.len() as u8;
        let row = SubmitShuffleV2Row::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            post_cc,
        );
        let mut bound_pi = pi.clone();
        bound_pi.precompile_binding = Some(binding);
        run(
            backend,
            SubmitShuffleV2Air::num_columns(),
            &row,
            &SubmitShuffleV2Row::padding(),
            &bound_pi,
            move || SubmitShuffleV2Air {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_submit_reveal_tokens<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SubmitPlayerRevealTokens {
            seat_index,
            raw_args: _,
        } = &task.method_input
        else {
            return Err(input_mismatch(
                "submit_player_reveal_tokens",
                "SubmitPlayerRevealTokens",
                &task.method_input,
            ));
        };
        let input = SubmitPlayerRevealTokensInput {
            seat_index: *seat_index,
            reveal_phase: task.post_table.reveal_token_state.reveal_phase,
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let post_rc = task.post_table.reveal_token_state.assignments.len() as u8;
        let row = SubmitPlayerRevealTokensRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            post_rc,
        );
        run(
            backend,
            SubmitPlayerRevealTokensAir::num_columns(),
            &row,
            &SubmitPlayerRevealTokensRow::padding(),
            pi,
            move || SubmitPlayerRevealTokensAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }

    fn prove_submit_reconstruct_deck<B: MethodBackend>(
        &self,
        task: &ProveTask,
        pre_root: StateRoot,
        post_root: StateRoot,
        pi: &crate::public_inputs::TexasPublicInputs,
        backend: &mut B,
    ) -> TexasAirResult<B::Output> {
        let MethodInput::SubmitReconstructDeck {
            seat_index,
            raw_args,
        } = &task.method_input
        else {
            return Err(input_mismatch(
                "submit_reconstruct_deck",
                "SubmitReconstructDeck",
                &task.method_input,
            ));
        };
        let args: poker_l1::vm::contracts::texas_poker::dispatch::SubmitReconstructDeckArgs =
            borsh::from_slice(raw_args).map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "submit_reconstruct_deck raw args borsh: {error}"
                ))
            })?;
        if args.seat_index != *seat_index {
            return Err(TexasAirError::SpecViolation(
                "submit_reconstruct_deck method input seat differs from raw args".into(),
            ));
        }
        let call_context = precompile_call_context(
            MethodKind::SubmitReconstructDeck,
            *seat_index,
            pi.table_id,
            pi.hand_id,
            pi.call_seq,
            pi.pre_version,
            pi.post_version,
            pi.pre_state_root,
            pi.post_state_root,
            pi.dispatch_call_digest,
        );
        let request = build_bls12381_reconstruction_v3_request(
            poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL,
            &call_context,
            TranscriptId::FiatShamirSha3,
            &args.statement,
            &args.proof,
        )
        .map_err(|error| {
            TexasAirError::SpecViolation(format!(
                "submit_reconstruct_deck precompile request construction failed: {error}"
            ))
        })?;
        let binding = PrecompileCallBinding::verify_reconstruction_v3(&request)?;
        let input = SubmitReconstructDeckInput {
            seat_index: *seat_index,
            reconstruct_phase: task.pre_table.reconstruct_state.phase,
            precompile: binding.air_binding(),
        };
        let (pre_v, post_v) = (task.pre_table.version, task.post_table.version);
        let post_sc = task.post_table.reconstruct_state.player_decks.len() as u8;
        let row = SubmitReconstructDeckRow::active(
            &input,
            srm(pre_root),
            srm(post_root),
            task.table_id,
            task.hand_id,
            task.call_seq,
            pre_v,
            post_v,
            post_sc,
        );
        let mut bound_pi = pi.clone();
        bound_pi.precompile_binding = Some(binding);
        run(
            backend,
            SubmitReconstructDeckAir::num_columns(),
            &row,
            &SubmitReconstructDeckRow::padding(),
            &bound_pi,
            move || SubmitReconstructDeckAir {
                log_size: MIN_LOG_SIZE,
                input,
                pre_state_root: srm(pre_root),
                post_state_root: srm(post_root),
                table_id: task.table_id,
                hand_id: task.hand_id,
                call_seq: task.call_seq,
                pre_version: pre_v,
                post_version: post_v,
            },
        )
    }
}

// ===== Orchestrator 内部辅助函数 =====

/// Replay the exact public VM dispatch carried by a proof task.
///
/// This is the host trust boundary for P05-H: the verifier does not accept a
/// prover-selected `(pre, post, method_input)` tuple. It reruns the same public
/// dispatch with the task-carried caller/context, selector, and raw Borsh
/// arguments, then requires the complete post table and task metadata to match.
/// Authentication of the task source remains an external consensus responsibility.
pub(crate) fn validate_full_dispatch_task(task: &ProveTask) -> TexasAirResult<()> {
    if task.selector != task.method_kind.selector() {
        return Err(TexasAirError::SpecViolation(format!(
            "{}: task selector does not match MethodKind",
            task.method_kind.method_name()
        )));
    }

    let mut replayed_post = task.pre_table.clone();
    let result = poker_l1::vm::contracts::texas_poker::dispatch::dispatch(
        &task.context,
        &mut replayed_post,
        &task.selector,
        &task.raw_args,
    )
    .map_err(|e| {
        TexasAirError::SpecViolation(format!(
            "{}: full VM dispatch replay failed: {e}",
            task.method_kind.method_name()
        ))
    })?;

    if replayed_post != task.post_table {
        return Err(TexasAirError::SpecViolation(format!(
            "{}: task post_table does not equal full VM dispatch replay",
            task.method_kind.method_name()
        )));
    }

    let output: DispatchOutput = borsh::from_slice(&result.return_value).map_err(|e| {
        TexasAirError::SerializationError(format!(
            "{}: replayed dispatch output borsh: {e}",
            task.method_kind.method_name()
        ))
    })?;
    let replayed_task = output.prove_task.ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{}: state-changing dispatch replay produced no prove task",
            task.method_kind.method_name()
        ))
    })?;

    let task_matches = replayed_task.method_kind == task.method_kind
        && replayed_task.method_input == task.method_input
        && replayed_task.context == task.context
        && replayed_task.selector == task.selector
        && replayed_task.raw_args == task.raw_args
        && replayed_task.pre_table == task.pre_table
        && replayed_task.post_table == task.post_table
        && replayed_task.table_id == task.table_id
        && replayed_task.hand_id == task.hand_id
        && replayed_task.call_seq == task.call_seq;
    if !task_matches {
        return Err(TexasAirError::SpecViolation(format!(
            "{}: task fields do not match the task regenerated by VM dispatch",
            task.method_kind.method_name()
        )));
    }

    Ok(())
}

/// 当前 action AIR 只覆盖 `advance_turn` 的 mid-round 分支。
#[derive(Debug, Clone, Copy)]
enum NativeMidRoundAction {
    Fold { seat_index: u8 },
    Check { seat_index: u8 },
    Call { seat_index: u8 },
    Raise { seat_index: u8, total_bet: u64 },
    Bet { seat_index: u8, amount: u64 },
    AutoFold { seat_index: u8 },
    ForceFold { seat_index: u8 },
}

impl NativeMidRoundAction {
    fn name(self) -> &'static str {
        match self {
            Self::Fold { .. } => "fold",
            Self::Check { .. } => "check",
            Self::Call { .. } => "call",
            Self::Raise { .. } => "raise",
            Self::Bet { .. } => "bet",
            Self::AutoFold { .. } => "auto_fold",
            Self::ForceFold { .. } => "force_fold",
        }
    }
}

/// 先重放真实 VM action 并逐字段比对 post table，再收窄到 AIR 已覆盖的
/// mid-round 分支。这样诚实 prover 不会把 end-of-round/settlement transition
/// 塞进简化 AIR；生产 verifier 侧还会由 trusted-row 绑定再次检查 witness。
fn validate_native_mid_round_action(
    task: &ProveTask,
    action: NativeMidRoundAction,
) -> TexasAirResult<u8> {
    let method = action.name();
    let pre = &task.pre_table;
    let post = &task.post_table;

    if pre.betting_round.is_none() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: pre-state is not a betting round"
        )));
    }
    if post.round_state != pre.round_state
        || post.betting_round.is_none()
        || post.current_turn.is_none()
        || post.pot != pre.pot
    {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method} triggered collect_bets_to_pot / advance_round / settlement; \
             current AIR proves only same-round transitions with unchanged pot and Some(current_turn)"
        )));
    }

    let mut expected = pre.clone();
    let mut events = Vec::new();
    let vm_result = match action {
        NativeMidRoundAction::Fold { seat_index } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_fold(
                &mut expected,
                seat_index,
                &mut events,
            )
        }
        NativeMidRoundAction::Check { seat_index } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_check(
                &mut expected,
                seat_index,
                &mut events,
            )
        }
        NativeMidRoundAction::Call { seat_index } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_call(
                &mut expected,
                seat_index,
                &mut events,
            )
        }
        NativeMidRoundAction::Raise {
            seat_index,
            total_bet,
        } => poker_l1::vm::contracts::texas_poker::state_machine::apply_raise(
            &mut expected,
            seat_index,
            total_bet,
            &mut events,
        ),
        NativeMidRoundAction::Bet { seat_index, amount } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_bet(
                &mut expected,
                seat_index,
                amount,
                &mut events,
            )
        }
        NativeMidRoundAction::AutoFold { seat_index } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_fold_internal(
                &mut expected,
                seat_index,
                poker_l1::vm::contracts::texas_poker::constants::FOLD_REASON_AUTO_TIMEOUT,
                &mut events,
            )
        }
        NativeMidRoundAction::ForceFold { seat_index } => {
            poker_l1::vm::contracts::texas_poker::state_machine::apply_fold_internal(
                &mut expected,
                seat_index,
                poker_l1::vm::contracts::texas_poker::constants::FOLD_REASON_FORCE_ADMIN,
                &mut events,
            )
        }
    };
    vm_result.map_err(|e| {
        TexasAirError::SpecViolation(format!("{method}: native VM replay failed: {e}"))
    })?;

    // dispatch() advances consensus sequence metadata after a successful state-machine call.
    expected.call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: call_seq overflow during replay"))
    })?;
    expected.hand_id = pre.hand_id;

    if expected != *post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: ProveTask post_table does not equal native VM replay result"
        )));
    }
    if task.call_seq != post.call_seq || task.hand_id != post.hand_id {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: task metadata does not match post-table sequence metadata"
        )));
    }

    Ok(post.current_turn.expect("checked Some above"))
}

/// `state_root_to_m31_limbs` 的短别名。
fn srm(root: StateRoot) -> [M31; 4] {
    state_root_to_m31_limbs(root)
}

trait MethodBackend {
    type Output;

    fn execute<A: crate::airs::TexasAir>(
        &mut self,
        num_columns: usize,
        row: &[M31],
        padding: &[M31],
        air: A,
        public_inputs: crate::public_inputs::TexasPublicInputs,
    ) -> TexasAirResult<Self::Output>;
}

struct NativeMethodProofBackend;

impl MethodBackend for NativeMethodProofBackend {
    type Output = VerificationReceipt;

    fn execute<A: crate::airs::TexasAir>(
        &mut self,
        num_columns: usize,
        row: &[M31],
        padding: &[M31],
        air: A,
        public_inputs: crate::public_inputs::TexasPublicInputs,
    ) -> TexasAirResult<Self::Output> {
        let trace = gen_method_trace(num_columns, row, padding)?;
        let proof = prove_method(&trace, air.clone(), num_columns, public_inputs.clone())?;
        verify_method_against_and_issue_receipt(proof, air, &public_inputs)
    }
}

struct RecursiveMethodVerifierBackend<'a> {
    recursive_proof:
        &'a poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof,
    recursive_inputs: &'a poker_zkvm::stwo_backend::recursive::RecursivePublicInputs,
}

#[cfg(feature = "recursive-prover")]
struct RecursiveMethodProverBackend;

#[cfg(feature = "recursive-prover")]
impl MethodBackend for RecursiveMethodProverBackend {
    type Output = (
        poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof,
        poker_zkvm::stwo_backend::recursive::RecursivePublicInputs,
    );

    fn execute<A: crate::airs::TexasAir>(
        &mut self,
        num_columns: usize,
        row: &[M31],
        padding: &[M31],
        air: A,
        public_inputs: crate::public_inputs::TexasPublicInputs,
    ) -> TexasAirResult<Self::Output> {
        let trace = gen_method_trace(num_columns, row, padding)?;
        let method_proof =
            prove_method(&trace, air.clone(), num_columns, public_inputs.clone())?;
        prove_method_recursive(&method_proof, air, &public_inputs)
    }
}

impl MethodBackend for RecursiveMethodVerifierBackend<'_> {
    type Output = ();

    fn execute<A: crate::airs::TexasAir>(
        &mut self,
        num_columns: usize,
        row: &[M31],
        padding: &[M31],
        air: A,
        public_inputs: crate::public_inputs::TexasPublicInputs,
    ) -> TexasAirResult<Self::Output> {
        if row.len() != num_columns || padding.len() != num_columns {
            return Err(TexasAirError::SpecViolation(format!(
                "trusted row/padding width mismatch: row={}, padding={}, expected={num_columns}",
                row.len(),
                padding.len()
            )));
        }
        verify_method_recursive_proof(
            self.recursive_proof,
            self.recursive_inputs,
            air,
            &public_inputs,
        )
    }
}

/// Shared trusted-statement path for native method proving and recursive-only verification.
fn run<B, A, F>(
    backend: &mut B,
    num_columns: usize,
    row: &impl ToM31Vec,
    padding: &impl ToM31Vec,
    public_inputs: &crate::public_inputs::TexasPublicInputs,
    build_air: F,
) -> TexasAirResult<B::Output>
where
    B: MethodBackend,
    A: crate::airs::TexasAir,
    F: FnOnce() -> A,
{
    let row_values = row.to_vec_m31();
    let air = build_air();
    let mut bound_public_inputs = public_inputs.clone();
    bound_public_inputs.bind_expected_trace_row(&row_values)?;
    backend.execute(
        num_columns,
        &row_values,
        &padding.to_vec_m31(),
        air,
        bound_public_inputs,
    )
}

/// 能产出 `Vec<M31>` 的抽象（避免与 CommonRow 的 `to_vec` 命名冲突）。
trait ToM31Vec {
    fn to_vec_m31(&self) -> Vec<M31>;
}
impl<T: RowToVec> ToM31Vec for T {
    fn to_vec_m31(&self) -> Vec<M31> {
        self.row_to_vec()
    }
}

/// 各 `*Row` 实现的统一接口（转发到各自的 `to_vec`）。
trait RowToVec {
    fn row_to_vec(&self) -> Vec<M31>;
}

// 为所有用到的 Row 实现转发宏。
macro_rules! impl_row_to_vec {
    ($($t:ty),+ $(,)?) => {
        $(
            impl RowToVec for $t {
                fn row_to_vec(&self) -> Vec<M31> { self.to_vec() }
            }
        )+
    };
}
impl_row_to_vec!(
    CreateTableRow,
    FoldRow,
    JoinTableRow,
    LeaveTableRow,
    StartHandRow,
    TickRow,
    ResetForNextHandRow,
    CheckRow,
    CallRow,
    RaiseRow,
    BetRow,
    AutoFoldRow,
    ForceFoldRow,
    KickPlayerRow,
    AddonRow,
    RebuyRow,
    JoinAndShuffleRow,
    LeaveWithProofRow,
    SubmitShuffleV2Row,
    SubmitPlayerRevealTokensRow,
    SubmitReconstructDeckRow,
);

/// 构造"方法输入与 MethodInput variant 不匹配"错误。
fn input_mismatch(method: &str, expected: &str, actual: &MethodInput) -> TexasAirError {
    TexasAirError::SpecViolation(format!(
        "{method} 任务的 method_input 应为 {expected}，实际：{actual:?}"
    ))
}

/// Registered VM selectors whose proof statements are intentionally disabled.
///
/// Keeping one canonical error constructor makes the production match and its
/// defense-in-depth fallback agree on the exact fail-closed boundary.
fn unsupported_registered_method(kind: MethodKind) -> TexasAirError {
    let reason = match kind {
        MethodKind::RequestLeaveAfterHand => {
            "request_leave_after_hand AIR 尚未完成 VM→AIR→Lean 语义证明；\
             该 selector 只允许生成/反序列化 ProveTask，Orchestrator fail-closed，no proof/receipt"
        }
        MethodKind::FoldWithProof => {
            "fold_with_proof AIR 尚未证明 DLEq crypto layer removal，也未覆盖\
             advance_turn/settlement；Orchestrator fail-closed，no proof/receipt"
        }
        _ => "internal error: method is not a registered fail-closed selector",
    };
    TexasAirError::NotImplemented(reason.into())
}

/// 在 post_table 中找到 player 占用的座位（join_table / join_and_shuffle 用）。
fn find_join_seat(
    table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    player: &poker_l1::Address,
) -> TexasAirResult<u8> {
    table
        .seats
        .iter()
        .position(|s| &s.player == player)
        .map(|i| i as u8)
        .ok_or_else(|| {
            TexasAirError::SpecViolation(format!("join 后未在 seats 中找到 player {player:?}"))
        })
}

/// 计算 `deck_state.encrypted` 的低位承诺（PoC：取长度作占位）。
fn deck_commitment(table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable) -> u64 {
    table.deck_state.encrypted.len() as u64
}

/// 统计活跃占用座数（与合约 `count_active_occupied` 语义一致）。
fn count_active_occupied(
    table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
) -> u8 {
    table.seats.iter().filter(|s| s.is_occupied()).count() as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::ObjectID;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::vm::contracts::dispatch::DispatchContext;
    use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
    use poker_l1::vm::contracts::texas_poker::constants::{ROUND_FLOP, ROUND_PREFLOP};
    use poker_l1::vm::contracts::texas_poker::dispatch::{
        self as texas_dispatch, AddonArgs, BetArgs, CreateTableArgs, KickPlayerArgs, RaiseArgs,
        RebuyArgs, SeatIndexArgs,
    };
    use poker_l1::vm::contracts::texas_poker::state_machine;
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

    fn test_context(caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    /// Execute the real public dispatch and consume the exact task emitted in
    /// `return_value`. Tests must not hand-maintain task metadata in parallel
    /// with the VM wire format, because that would bypass the boundary under test.
    fn dispatch_task(
        pre_table: TexasPokerTable,
        caller: poker_l1::Address,
        selector: [u8; 32],
        raw_args: Vec<u8>,
    ) -> (ProveTask, TexasPokerTable) {
        let context = test_context(caller);
        let mut post_table = pre_table.clone();
        let result = texas_dispatch::dispatch(&context, &mut post_table, &selector, &raw_args)
            .expect("test dispatch should succeed");
        let output: DispatchOutput =
            borsh::from_slice(&result.return_value).expect("dispatch output should decode");
        let task = output
            .prove_task
            .expect("state-changing dispatch should emit a prove task");
        assert_eq!(task.pre_table, pre_table);
        assert_eq!(task.post_table, post_table);
        assert_eq!(task.context, context);
        assert_eq!(task.selector, selector);
        assert_eq!(task.raw_args, raw_args);
        (task, post_table)
    }

    fn registered_but_unsupported_task(
        method_kind: MethodKind,
        method_input: MethodInput,
        raw_args: Vec<u8>,
    ) -> ProveTask {
        let pre = make_table("unsupported-pre");
        let mut post = pre.clone();
        post.version = pre.version + 1;
        ProveTask::new(
            method_kind,
            method_input,
            DispatchContext {
                caller: pre.creator,
                caller_pubkey: TaggedPubkey {
                    tag: 0,
                    raw: vec![0xCC; 32],
                },
                chain_id: 1,
                block_height: 100,
                block_timestamp: 1_000_000,
            },
            method_kind.selector(),
            raw_args,
            pre,
            post,
            1,
            0,
            1,
        )
    }

    fn assert_registered_method_fails_closed(task: ProveTask) {
        let encoded = borsh::to_vec(&task).expect("registered task should serialize");
        let decoded: ProveTask =
            borsh::from_slice(&encoded).expect("registered task should deserialize");

        let mut orchestrator = Orchestrator::new();
        let error = orchestrator
            .prove_and_verify_task(&decoded)
            .expect_err("unsupported registered selector must issue no proof/receipt");
        assert!(
            matches!(error, TexasAirError::NotImplemented(_)),
            "registered unsupported selector must fail with an explicit boundary: {error}"
        );
        assert!(
            error.to_string().contains("no proof/receipt"),
            "error must state that no receipt is issued: {error}"
        );
        assert!(
            orchestrator.proven().is_empty(),
            "fail-closed task must leave no proven descriptor"
        );
        assert!(
            orchestrator.verified_chain().is_err(),
            "fail-closed task must leave no verifier-issued receipt"
        );
    }

    #[test]
    fn request_leave_after_hand_task_deserializes_but_issues_no_receipt() {
        let raw_args = borsh::to_vec(&SeatIndexArgs { seat_index: 0 })
            .expect("request_leave_after_hand args should serialize");
        let task = registered_but_unsupported_task(
            MethodKind::RequestLeaveAfterHand,
            MethodInput::RequestLeaveAfterHand { seat_index: 0 },
            raw_args,
        );
        assert_registered_method_fails_closed(task);
    }

    #[test]
    fn fold_with_proof_task_deserializes_but_issues_no_receipt() {
        // The task wire format must remain forward-compatible even while its
        // cryptographic AIR is disabled. The opaque bytes are deliberately not
        // interpreted because rejection happens before proof construction.
        let raw_args = vec![0xF0, 0x1D, 0xCA, 0xFE];
        let task = registered_but_unsupported_task(
            MethodKind::FoldWithProof,
            MethodInput::FoldWithProof {
                seat_index: 0,
                raw_args: raw_args.clone(),
            },
            raw_args,
        );
        assert_registered_method_fails_closed(task);
    }

    #[test]
    fn orchestrator_prove_create_table() {
        let pre = make_table("pre");
        let raw_args = borsh::to_vec(&CreateTableArgs {
            name: "post".into(),
            max_players: 6,
            small_blind: 50,
            big_blind: 100,
        })
        .expect("create_table args should serialize");
        let (task, post) = dispatch_task(
            pre,
            [0xA1; 20],
            texas_dispatch::selectors::create_table(),
            raw_args,
        );
        assert_eq!(post.version, 1);
        assert_eq!(post.call_seq, 1);
        let mut orch = Orchestrator::new();
        let summary = orch
            .prove_and_verify_task(&task)
            .expect("create_table prove+verify 应成功");
        assert_eq!(summary.method_kind, MethodKind::CreateTable);
        assert!(orch.verify_chain().is_ok());
    }

    #[test]
    fn orchestrator_prove_fold() {
        let mut pre = make_table("pre");
        pre.version = 1;
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1000;
        }
        let caller = pre.seats[0].player;
        let (task, _) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::fold(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("fold args should serialize"),
        );
        let mut orch = Orchestrator::new();
        orch.prove_and_verify_task(&task)
            .expect("fold prove+verify 应成功");
    }

    #[cfg(feature = "recursive-prover")]
    #[test]
    #[ignore = "recursive STWO proving is intentionally expensive"]
    fn l1_registry_directly_verifies_recursive_fold_envelope_without_inner_proof() {
        let mut pre = make_table("recursive-l1-fold");
        pre.version = 1;
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }
        let caller = pre.seats[0].player;
        let (task, _) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::fold(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("fold args should serialize"),
        );

        let (recursive_proof, recursive_inputs) =
            Orchestrator::prove_recursive_task(&task).expect("recursive proof should be produced");
        let envelope = crate::recursive_envelope::TexasRecursiveProofEnvelope::new(
            task.clone(),
            recursive_inputs,
            recursive_proof,
        );
        let encoded = envelope.encode().expect("envelope should encode");
        assert!(
            encoded.len() <= poker_l1::offline::zk_verifier::MAX_ZK_PROOF_BYTES,
            "recursive envelope size {} exceeds the L1 zk_verify limit {}",
            encoded.len(),
            poker_l1::offline::zk_verifier::MAX_ZK_PROOF_BYTES,
        );
        let decoded = crate::recursive_envelope::TexasRecursiveProofEnvelope::decode(&encoded)
            .expect("envelope should round-trip");
        assert_eq!(decoded.task().method_kind, MethodKind::Fold);

        let public_io = crate::l1_verifier::texas_recursive_public_io(&task).unwrap();
        let anchor = crate::verified_chain::ExpectedChainAnchor::new(
            task.table_id,
            task.hand_id,
            task.call_seq,
            crate::state_root::compute_state_root(&task.pre_table).unwrap(),
            crate::state_root::compute_state_root(&task.post_table).unwrap(),
            task.pre_table.version,
            task.post_table.version,
            vec![dispatch_call_digest(&task.context, &task.selector, &task.raw_args).unwrap()],
        )
        .unwrap();
        let mut registry = poker_l1::offline::zk_verifier::ZkVerifierRegistry::new();
        crate::l1_verifier::register_texas_stwo_recursive_verifier(&mut registry).unwrap();

        let stub_result = crate::l1_verifier::verify_authenticated_texas_recursive_transition(
            &registry,
            poker_l1::DEFAULT_CHAIN_ID,
            &encoded,
            &task,
        );
        assert!(matches!(
            stub_result,
            Err(poker_l1::error::PokerL1Error::ZkVerifierNotProduction { .. })
        ));

        registry.set_verifier_status(
            poker_l1::DEFAULT_CHAIN_ID,
            poker_l1::offline::zk_verifier::VerifierStatus::Production,
        );
        let authenticated =
            crate::l1_verifier::verify_consensus_anchored_texas_recursive_transition(
                &registry,
                poker_l1::DEFAULT_CHAIN_ID,
                &encoded,
                &task,
                &anchor,
            )
            .expect("authenticated L1 transition should verify");
        assert!(authenticated.verified);

        let mut different_authenticated_task = task.clone();
        different_authenticated_task.post_table.version += 1;
        assert!(
            crate::l1_verifier::verify_consensus_anchored_texas_recursive_transition(
                &registry,
                poker_l1::DEFAULT_CHAIN_ID,
                &encoded,
                &different_authenticated_task,
                &anchor,
            )
            .is_err()
        );

        let result = registry
            .zk_verify(
                poker_l1::DEFAULT_CHAIN_ID,
                poker_l1::offline::zk_verifier::SCHEME_STWO,
                &encoded,
                &public_io,
                3,
                1_000,
            )
            .expect("registry verification should execute");
        assert!(result.verified);

        let mut relabeled_public_io = public_io;
        relabeled_public_io.final_commitment[0] ^= 1;
        let relabeled = registry
            .zk_verify(
                poker_l1::DEFAULT_CHAIN_ID,
                poker_l1::offline::zk_verifier::SCHEME_STWO,
                &encoded,
                &relabeled_public_io,
                3,
                1_000,
            )
            .expect("mismatched public I/O should return a negative result");
        assert!(!relabeled.verified);
    }

    #[test]
    fn orchestrator_accepts_addon_ripple_carry() {
        let mut pre = make_table("addon-ripple-carry");
        pre.seats[0].player = [0x41; 20];
        pre.seats[0].stack = 100;
        pre.seats[0].pending_addon = 65_535;
        pre.chip_pool = 100;
        pre.addon_pool = 65_535;
        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::addon(),
            borsh::to_vec(&AddonArgs {
                seat_index: 0,
                amount: 1,
            })
            .expect("addon args should serialize"),
        );
        assert_eq!(post.seats[0].pending_addon, 65_536);
        assert_eq!(post.addon_pool, 65_536);
        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("native replay and AIR must accept addon carry");
    }

    #[test]
    fn orchestrator_accepts_rebuy_ripple_carry() {
        let mut pre = make_table("rebuy-ripple-carry");
        pre.seats[0].player = [0x42; 20];
        pre.seats[0].stack = 65_535;
        pre.chip_pool = 65_535;
        pre.addon_pool = 65_535;
        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::rebuy(),
            borsh::to_vec(&RebuyArgs {
                seat_index: 0,
                amount: 1,
            })
            .expect("rebuy args should serialize"),
        );
        assert_eq!(post.seats[0].stack, 65_536);
        assert_eq!(post.addon_pool, 65_535);
        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("native replay and AIR must accept rebuy carry");
    }

    #[test]
    fn orchestrator_accepts_kick_player_pot_ripple_carry() {
        let mut pre = make_table("kick-ripple-carry");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.pot = 65_535;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }
        pre.seats[2].bet = 1;
        pre.seats[2].total_bet = 1;
        pre.chip_pool = 3_000;
        let creator = pre.creator;
        let (task, post) = dispatch_task(
            pre,
            creator,
            texas_dispatch::selectors::kick_player(),
            borsh::to_vec(&KickPlayerArgs {
                seat_index: 2,
                reason: 1,
            })
            .expect("kick args should serialize"),
        );
        assert_eq!(post.pot, 65_536);
        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("native replay and AIR must accept kick pot carry");
    }

    #[test]
    fn orchestrator_accepts_leave_table_funds_ripple_carry() {
        let mut pre = make_table("leave-ripple-carry");
        pre.seats[0].player = [0x43; 20];
        pre.seats[0].stack = 65_535;
        pre.seats[0].pending_addon = 1;
        pre.chip_pool = 65_536;
        pre.addon_pool = 65_536;
        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::leave_table(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("leave args should serialize"),
        );
        assert_eq!(post.chip_pool, 0);
        assert_eq!(post.addon_pool, 65_535);
        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("native replay and AIR must accept leave_table refund/subtraction carry");
    }

    /// P06 回归：真实 VM 的非零 mid-round call 不收池，且可完成 prove+verify。
    #[test]
    fn orchestrator_accepts_nonzero_mid_round_call() {
        let mut pre = make_table("mid-round-call");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.pot = 25;
        pre.hand_id = 7;
        pre.call_seq = 11;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }
        pre.seats[0].bet = 50;
        pre.seats[1].bet = 100;
        pre.seats[2].bet = 100;

        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::call(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("call args should serialize"),
        );
        assert_eq!(post.pot, pre.pot, "mid-round call must not collect bets");
        assert_eq!(post.current_turn, Some(1));
        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("nonzero mid-round call should prove and verify");
    }

    /// P06 回归：完整加注更新 current_bet/min_raise，但 mid-round 不收池。
    #[test]
    fn orchestrator_accepts_normal_mid_round_raise() {
        let mut pre = make_table("normal-mid-round-raise");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.pot = 55;
        pre.hand_id = 8;
        pre.call_seq = 20;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }
        pre.seats[1].bet = 100;
        pre.seats[2].bet = 100;

        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::raise(),
            borsh::to_vec(&RaiseArgs {
                seat_index: 0,
                total_bet: 300,
            })
            .expect("raise args should serialize"),
        );
        let post_round = post.betting_round.expect("raise remains in betting round");
        assert_eq!(post_round.current_bet, 300);
        assert_eq!(post_round.min_raise, 200);
        assert_eq!(post.pot, pre.pot);
        assert_eq!(post.current_turn, Some(1));

        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("normal mid-round raise should prove and verify");
    }

    /// P06 回归：短 all-in 合法，但不能降低/重设既有 min_raise。
    #[test]
    fn orchestrator_accepts_short_all_in_raise_without_reopening() {
        let mut pre = make_table("short-all-in-raise");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound {
            current_bet: 300,
            min_raise: 200,
        });
        pre.current_turn = Some(0);
        pre.pot = 77;
        pre.hand_id = 9;
        pre.call_seq = 30;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }
        pre.seats[0].stack = 400;
        pre.seats[1].bet = 300;
        pre.seats[2].bet = 300;

        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::raise(),
            borsh::to_vec(&RaiseArgs {
                seat_index: 0,
                total_bet: 400,
            })
            .expect("raise args should serialize"),
        );
        let post_round = post.betting_round.expect("raise remains in betting round");
        assert_eq!(post_round.current_bet, 400);
        assert_eq!(
            post_round.min_raise, 200,
            "short all-in must not reopen action"
        );
        assert!(post.seats[0].all_in);
        assert_eq!(post.pot, pre.pot);

        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("short all-in mid-round raise should prove and verify");
    }

    /// P06 回归：bet 只覆盖 postflop 无既有下注的 mid-round 开注。
    #[test]
    fn orchestrator_accepts_postflop_mid_round_bet() {
        let mut pre = make_table("postflop-bet");
        pre.round_state = ROUND_FLOP;
        pre.betting_round = Some(BettingRound::new(100, 0));
        pre.current_turn = Some(0);
        pre.pot = 300;
        pre.hand_id = 10;
        pre.call_seq = 40;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
        }

        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::bet(),
            borsh::to_vec(&BetArgs {
                seat_index: 0,
                amount: 200,
            })
            .expect("bet args should serialize"),
        );
        let post_round = post.betting_round.expect("bet remains in betting round");
        assert_eq!(post_round.current_bet, 200);
        assert_eq!(post_round.min_raise, 200);
        assert_eq!(post.seats[0].bet, 200);
        assert_eq!(post.pot, pre.pot);
        assert_eq!(post.current_turn, Some(1));

        Orchestrator::new()
            .prove_and_verify_task(&task)
            .expect("postflop mid-round bet should prove and verify");
    }

    /// P06 回归：最后一个对手 fold 会直接结算/重置，当前 action AIR 必须拒绝。
    #[test]
    fn orchestrator_rejects_last_opponent_fold_settlement() {
        let mut pre = make_table("fold-settlement");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.pot = 250;
        pre.hand_id = 11;
        pre.call_seq = 50;
        for i in 0..2 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
            pre.seats[i].bet = 100;
            pre.seats[i].total_bet = 100;
        }

        let caller = pre.seats[0].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::fold(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("fold args should serialize"),
        );
        assert_ne!(post.round_state, pre.round_state);
        assert!(post.current_turn.is_none());
        assert!(post.betting_round.is_none());

        assert!(matches!(
            Orchestrator::new().prove_and_verify_task(&task),
            Err(TexasAirError::UnsupportedBettingTransition(_))
        ));
    }

    /// P06 回归：heads-up 最后一个 check 会收池并推进轮次，简化 action AIR
    /// 必须在生产 prover 入口显式 fail-closed。
    #[test]
    fn orchestrator_rejects_heads_up_end_round_check() {
        let mut pre = make_table("end-round-check");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(1);
        pre.hand_id = 3;
        pre.call_seq = 4;
        for i in 0..2 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 900;
            pre.seats[i].bet = 100;
            pre.seats[i].total_bet = 100;
        }
        pre.seats[0].acted_this_round = true;
        state_machine::set_initial_encrypted_deck(&mut pre).unwrap();

        let caller = pre.seats[1].player;
        let (task, post) = dispatch_task(
            pre.clone(),
            caller,
            texas_dispatch::selectors::check(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).expect("check args should serialize"),
        );
        assert_ne!(post.round_state, pre.round_state);
        assert!(post.current_turn.is_none());
        assert!(post.pot > pre.pot);

        let result = Orchestrator::new().prove_and_verify_task(&task);
        assert!(matches!(
            result,
            Err(TexasAirError::UnsupportedBettingTransition(_))
        ));
    }

    /// A WAITING-state kick may internally reset the table and bump version
    /// more than once. The single-step kick AIR must reject that composite path.
    #[test]
    fn orchestrator_rejects_kick_that_triggers_nested_reset() {
        let mut pre = make_table("kick-nested-reset");
        pre.seats[0].player = [0x31; 20];
        pre.seats[0].stack = 1_000;
        pre.chip_pool = 1_000;
        let creator = pre.creator;
        let (task, post) = dispatch_task(
            pre.clone(),
            creator,
            texas_dispatch::selectors::kick_player(),
            borsh::to_vec(&KickPlayerArgs {
                seat_index: 0,
                reason: 1,
            })
            .expect("kick args should serialize"),
        );
        assert!(post.version > pre.version.saturating_add(1));
        assert!(matches!(
            Orchestrator::new().prove_and_verify_task(&task),
            Err(TexasAirError::UnsupportedBettingTransition(_))
        ));
    }

    /// 回归：Check 方法现已接入 Orchestrator（不再返回 NotImplemented）。
    ///
    /// 之前 Check 是"未实现"的代表；启用的 21 个方法接线后，此测试确认 Check
    /// 走完了 trace 构造路径（成功或返回非 NotImplemented 的业务错误均算通过）。
    #[test]
    fn orchestrator_check_is_now_supported() {
        let mut pre = make_table("pre");
        pre.round_state = poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
            pre.seats[i].bet = 100;
        }
        let caller = pre.seats[0].player;
        let (task, _) = dispatch_task(
            pre,
            caller,
            texas_dispatch::selectors::check(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("check args should serialize"),
        );
        let mut orch = Orchestrator::new();
        orch.prove_and_verify_task(&task)
            .expect("enabled check path should prove and verify");
    }

    /// 端到端：两步链式证明，验证 state_root 链衔接。
    ///
    /// 这是 Post-commit Prover 的核心场景：两个方法的 proof 各自生成 + verify，
    /// 且第二个任务的 pre_state_root == 第一个任务的 post_state_root。
    ///
    /// 使用两个真实、连续的 mid-round dispatch，避免手工拼接无效 create-table 状态。
    #[test]
    fn orchestrator_chain_two_tasks() {
        let mut pre = make_table("two-real-dispatches");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.hand_id = 7;
        pre.call_seq = 11;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
            pre.seats[i].bet = 100;
        }
        pre.seats[0].bet = 50;

        let (task1, after_call) = dispatch_task(
            pre,
            [1; 20],
            texas_dispatch::selectors::call(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("call args should serialize"),
        );
        assert_eq!(after_call.current_turn, Some(1));
        let (task2, _) = dispatch_task(
            after_call,
            [2; 20],
            texas_dispatch::selectors::raise(),
            borsh::to_vec(&RaiseArgs {
                seat_index: 1,
                total_bet: 300,
            })
            .expect("raise args should serialize"),
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

    /// P05-H-core 回归：完整 VM replay + native verify 产出的链可由精确范围 anchor
    /// 约束。测试中的 anchor 为了夹具方便从 task 计算；生产中必须来自已认证 block/receipt。
    #[test]
    fn orchestrator_chain_matches_exact_external_anchor_shape() {
        let mut pre = make_table("anchored-two-dispatches");
        pre.round_state = ROUND_PREFLOP;
        pre.betting_round = Some(BettingRound::new(100, 100));
        pre.current_turn = Some(0);
        pre.hand_id = 9;
        pre.call_seq = 20;
        for i in 0..3 {
            pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
            pre.seats[i].stack = 1_000;
            pre.seats[i].bet = 100;
        }
        pre.seats[0].bet = 50;

        let (task1, after_call) = dispatch_task(
            pre,
            [1; 20],
            texas_dispatch::selectors::call(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).expect("call args should serialize"),
        );
        let (task2, _) = dispatch_task(
            after_call,
            [2; 20],
            texas_dispatch::selectors::raise(),
            borsh::to_vec(&RaiseArgs {
                seat_index: 1,
                total_bet: 300,
            })
            .expect("raise args should serialize"),
        );

        let anchor = ExpectedChainAnchor::new(
            task1.table_id,
            task1.hand_id,
            task1.call_seq,
            crate::state_root::compute_state_root(&task1.pre_table).unwrap(),
            crate::state_root::compute_state_root(&task2.post_table).unwrap(),
            task1.pre_table.version,
            task2.post_table.version,
            vec![
                dispatch_call_digest(&task1.context, &task1.selector, &task1.raw_args).unwrap(),
                dispatch_call_digest(&task2.context, &task2.selector, &task2.raw_args).unwrap(),
            ],
        )
        .unwrap();

        let chain = Orchestrator::prove_and_verify_chain_against(&[task1, task2], &anchor)
            .expect("exact anchored range should prove and verify");
        assert_eq!(chain.len(), 2);
    }

    /// Descriptor-only 摘要不能进入可信链。
    #[test]
    fn descriptor_only_summaries_cannot_enter_trusted_chain() {
        let mut orch = Orchestrator::new();
        // 手动注入 descriptor 摘要，绕过 native verifier。即使摘要形式上
        // 包含 roots/seq，也不会产生 VerificationReceipt。
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
        assert!(
            matches!(orch.verify_chain(), Err(TexasAirError::RecursionError(_))),
            "descriptor-only 摘要不得构成可信链"
        );
    }
}

// 避免未使用 import 警告（FieldElement 在下方测试模块用）。
#[cfg(test)]
use starknet_ff::FieldElement;
