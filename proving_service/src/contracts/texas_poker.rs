//! `TexasPokerPlugin` —— 首个 [`crate::plugin::ContractPlugin`] 实现。
//!
//! 封装 `poker_l1` 的 texas_poker 合约 + `poker_texas_air` 的 Orchestrator：
//!
//! - 内部持有可变的 `TexasPokerTable` 状态。
//! - `dispatch` 委托 `poker_l1::vm::contracts::texas_poker::dispatch::dispatch`，
//!   从 `return_value` 原样反序列化出 `DispatchOutput`。VM dispatch 自己推进并写入
//!   `call_seq`/`hand_id`；服务层不得覆盖 VM 任务字段。
//! - `prove_task` 委托 `Orchestrator::prove_and_verify_task`（prove + 立即 verify）。

use borsh::BorshDeserialize;

use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::dispatch as texas_dispatch;
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;

use poker_texas_air::airs::composition::{
    ArchivedCompositionProofBundle, supports_composite_proof,
};
use poker_texas_air::consensus_anchor::ConsensusAnchorMaterial;
use poker_texas_air::dual_proof::dual_proof_from_archived;
use poker_texas_air::orchestrator::{ArchivedProvenTask, Orchestrator, ProvenTask};
use poker_texas_air::outer_aggregate::{
    MIN_OUTER_CHILDREN, OuterAggregateBundle, aggregate_dual_proofs, verify_outer_aggregate,
};
use poker_texas_air::proof_archive::ArchivedMethodProof;
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
use poker_texas_air::tagged_method::ArchivedTaggedBatchProofPackage;
use poker_texas_air::verified_chain::ExpectedChainAnchor;

use crate::plugin::{DispatchOutcome, PluginError, PluginResult, PluginStats};

/// texas_poker 合约插件。
#[derive(Clone)]
pub struct TexasPokerPlugin {
    /// 桌台状态（dispatch 就地修改）。
    table: TexasPokerTable,
    /// 证明编排器（累积已证明任务）。
    orchestrator: Orchestrator,
    /// 累计 dispatch 次数（统计用）。
    dispatch_count: u64,
    /// 累计 prove 次数（统计用）。
    prove_count: u64,
    /// Canonical tasks retained alongside durable archives for outer aggregation.
    proved_tasks: Vec<ProveTask>,
    /// Durable archives corresponding one-to-one with `proved_tasks`.
    proved_archives: Vec<poker_texas_air::proof_archive::ArchivedMethodProof>,
    /// First task index in the currently active hand segment.
    segment_start: usize,
    /// Composite tasks waiting for one heterogeneous method + Stage proof package.
    deferred_tagged_tasks: Vec<ProveTask>,
    /// Verified two-proof packages produced for completed composite batches.
    tagged_batches: Vec<ArchivedTaggedBatchProofPackage>,
}

impl TexasPokerPlugin {
    /// 构造插件，传入初始桌台（通常由 `create_table` 创建）。
    #[must_use]
    pub fn new(table: TexasPokerTable) -> Self {
        Self {
            table,
            orchestrator: Orchestrator::new(),
            dispatch_count: 0,
            prove_count: 0,
            proved_tasks: Vec::new(),
            proved_archives: Vec::new(),
            segment_start: 0,
            deferred_tagged_tasks: Vec::new(),
            tagged_batches: Vec::new(),
        }
    }

    /// Rehydrate a durable service table after a process restart.
    ///
    /// The in-memory verified-chain segment starts empty after recovery. Durable
    /// proof packages can be reverified independently from the repository, while
    /// the persisted table snapshot and counters make the next canonical VM
    /// dispatch deterministic.
    #[must_use]
    pub fn from_persisted_state(
        table: TexasPokerTable,
        dispatch_count: u64,
        prove_count: u64,
    ) -> Self {
        Self {
            table,
            orchestrator: Orchestrator::new(),
            dispatch_count,
            prove_count,
            proved_tasks: Vec::new(),
            proved_archives: Vec::new(),
            segment_start: 0,
            deferred_tagged_tasks: Vec::new(),
            tagged_batches: Vec::new(),
        }
    }

    /// 借用当前桌台状态（供 runner / 调试观察）。
    pub fn table(&self) -> &TexasPokerTable {
        &self.table
    }

    /// 借用已证明任务摘要（供聚合 / 链校验）。
    pub fn proven(&self) -> &[ProvenTask] {
        self.orchestrator.proven()
    }

    /// 开始一条新的已验证 receipt 链片段。
    ///
    /// 跨局推进（`start_hand` 使 `hand_id` 递增）后，旧局内链无法承接新 receipt，
    /// 调用本方法清空链 receipts，使新一局从空链重新累积（见
    /// [`poker_texas_air::orchestrator::Orchestrator::start_new_chain_segment`]）。
    pub fn start_new_chain_segment(&mut self) {
        self.orchestrator.start_new_chain_segment();
        self.segment_start = self.proved_tasks.len();
    }

    /// Register the occupied seats as the canonical deck-key contributor lineage.
    ///
    /// 真实协议中每个玩家经 `join_table` 完成 key ownership 验证并设置 contributor bit；
    /// aggregate key 只由 contributor mask + seat pk 派生，不进入 canonical state。
    ///
    /// 本驱动用兼容 `join_table` 入座，所以在 `start_hand` 前把所有 occupied、
    /// non-identity seat 纳入 lineage，并要求调用方给出的总公钥与派生结果一致。
    pub fn register_aggregated_pk(
        &mut self,
        pk: poker_protocol::crypto::ECPoint,
    ) -> PluginResult<()> {
        let mut contributor_mask = 0u16;
        for (seat_index, seat) in self.table.seats.iter().enumerate() {
            if seat.is_occupied()
                && seat.pk().is_some_and(|pk| {
                    !poker_l1::vm::contracts::texas_poker::utils::g1_is_identity(&pk.0)
                })
            {
                contributor_mask |= 1u16 << seat_index;
            }
        }
        let mut candidate = self.table.clone();
        candidate.deck_state.contributor_mask = contributor_mask;
        let derived = candidate.derived_aggregated_pk().map_err(|error| {
            PluginError::Precondition(format!(
                "cannot derive aggregate public key from occupied contributor seats: {error}"
            ))
        })?;
        if derived != Some(pk) {
            return Err(PluginError::Precondition(
                "registered aggregate public key does not match contributor seat lineage".into(),
            ));
        }
        self.table = candidate;
        Ok(())
    }

    /// Prove, verify, and archive one canonical task for durable service storage.
    ///
    /// Hand-boundary handling is identical to the compatibility `prove_task`
    /// trait method. The prove counter advances only after proof generation,
    /// native verification, archive encoding, and receipt insertion all succeed.
    pub fn prove_task_archived(&mut self, task: &ProveTask) -> PluginResult<ArchivedProvenTask> {
        if !self.deferred_tagged_tasks.is_empty() {
            return Err(PluginError::Precondition(
                "cannot use per-task proving while a tagged batch is pending".into(),
            ));
        }
        if task.pre_table.hand_id != task.post_table.hand_id {
            self.orchestrator.start_new_chain_segment();
            self.segment_start = self.proved_tasks.len();
        }
        let archived = self
            .orchestrator
            .prove_verify_and_archive_task(task)
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        self.proved_tasks.push(task.clone());
        self.proved_archives.push(archived.archive.clone());
        self.prove_count += 1;
        Ok(archived)
    }

    /// Queue a composite transition without starting a per-task prover.
    ///
    /// A later [`Self::finalize_tagged_batches`] call proves the entire contiguous run with one
    /// narrow heterogeneous method proof and one tagged Stage proof.
    pub fn queue_tagged_batch_task(&mut self, task: &ProveTask) -> PluginResult<()> {
        if !supports_composite_proof(task.method_kind) {
            return Err(PluginError::Precondition(format!(
                "method {} is outside the tagged composition pipeline",
                task.method_kind.method_name()
            )));
        }
        if task.pre_table.hand_id != task.post_table.hand_id {
            return Err(PluginError::Precondition(
                "composite batch task must not cross a hand boundary".into(),
            ));
        }
        if let Some(previous) = self.deferred_tagged_tasks.last() {
            let expected_call_seq = previous.call_seq.checked_add(1).ok_or_else(|| {
                PluginError::Precondition("deferred tagged batch call_seq overflow".into())
            })?;
            if task.table_id != previous.table_id
                || task.hand_id != previous.hand_id
                || task.call_seq != expected_call_seq
                || task.pre_table != previous.post_table
            {
                return Err(PluginError::Precondition(
                    "tagged batch tasks must be exact-state contiguous".into(),
                ));
            }
        }
        self.deferred_tagged_tasks.push(task.clone());
        Ok(())
    }

    /// Finalize all queued transitions as two-proof tagged packages.
    ///
    /// Orchestrator and plugin histories are committed only after every chunk succeeds. On error,
    /// the original pending list and receipt chain remain available for a retry.
    pub fn finalize_tagged_batches(&mut self) -> PluginResult<usize> {
        if self.deferred_tagged_tasks.is_empty() {
            return Ok(0);
        }
        let mut staged_orchestrator = self.orchestrator.clone();
        let mut completed = Vec::new();
        for tasks in self
            .deferred_tagged_tasks
            .chunks(poker_texas_air::prove_task::MAX_METHOD_BATCH_ROWS)
        {
            let package = staged_orchestrator
                .prove_verify_and_accept_tagged_batch(tasks)
                .map_err(|error| PluginError::Prover(error.to_string()))?;
            completed.push(package);
        }
        let count = completed.len();
        self.orchestrator = staged_orchestrator;
        self.prove_count = self
            .prove_count
            .checked_add(
                u64::try_from(self.deferred_tagged_tasks.len()).map_err(|_| {
                    PluginError::Precondition("tagged task count does not fit u64".into())
                })?,
            )
            .ok_or_else(|| PluginError::Precondition("prove counter overflow".into()))?;
        self.tagged_batches.extend(completed);
        self.deferred_tagged_tasks.clear();
        Ok(count)
    }

    /// Verified throughput-oriented two-proof packages retained by this plugin instance.
    #[must_use]
    pub fn tagged_batches(&self) -> &[ArchivedTaggedBatchProofPackage] {
        &self.tagged_batches
    }

    /// Canonical composite tasks currently waiting for one shared package.
    #[must_use]
    pub fn pending_tagged_tasks(&self) -> &[ProveTask] {
        &self.deferred_tagged_tasks
    }

    /// Reverify and restore one self-contained tagged package without changing
    /// persisted counters or the already recovered table snapshot.
    pub fn restore_tagged_batch(
        &mut self,
        package: &ArchivedTaggedBatchProofPackage,
    ) -> PluginResult<Vec<ProvenTask>> {
        let tasks = package
            .validate_and_replay_tasks()
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        self.restore_tagged_batch_with_replayed_tasks(&tasks, package)
    }

    /// Reverify and restore a tagged package using tasks retained by service package decoding.
    pub fn restore_tagged_batch_with_replayed_tasks(
        &mut self,
        tasks: &[ProveTask],
        package: &ArchivedTaggedBatchProofPackage,
    ) -> PluginResult<Vec<ProvenTask>> {
        if !self.deferred_tagged_tasks.is_empty() {
            return Err(PluginError::Precondition(
                "cannot restore a completed tagged package while tasks are pending".into(),
            ));
        }
        let summaries = self
            .orchestrator
            .restore_verified_tagged_batch_with_replayed_tasks(tasks, package)
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        self.tagged_batches.push(package.clone());
        Ok(summaries)
    }

    /// Reverify and restore one durable proof without changing persisted counters.
    ///
    /// Service startup calls this in journal order after loading the canonical
    /// task and proof archive from a completed job sidecar. A hand transition
    /// starts a fresh receipt-chain segment, matching the live proving path.
    /// The table snapshot is not mutated: it has already been recovered from the
    /// repository and every task is independently replayed by the Orchestrator.
    pub fn restore_archived_task(
        &mut self,
        task: &ProveTask,
        archive: &ArchivedMethodProof,
        composition_archive: Option<&ArchivedCompositionProofBundle>,
    ) -> PluginResult<ProvenTask> {
        if task.pre_table.hand_id != task.post_table.hand_id {
            self.orchestrator.start_new_chain_segment();
            self.segment_start = self.proved_tasks.len();
        }
        let summary = self
            .orchestrator
            .restore_verified_archived_task(task, archive, composition_archive)
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        self.proved_tasks.push(task.clone());
        self.proved_archives.push(archive.clone());
        Ok(summary)
    }

    /// Build and independently verify a host-verified outer aggregate for the
    /// longest contiguous crypto-proof run in the current hand segment.
    ///
    /// This is deliberately an O(N) verified transport package, not recursive
    /// compression. Non-crypto methods are never converted into descriptor
    /// children, and a run with fewer than two children is rejected.
    pub fn aggregate_crypto_proofs(&self) -> PluginResult<OuterAggregateBundle> {
        let start = self.segment_start.min(self.proved_tasks.len());
        let tasks = &self.proved_tasks[start..];
        let archives = &self.proved_archives[start..];
        if tasks.len() != archives.len() {
            return Err(PluginError::Precondition(
                "stored task/archive history is inconsistent".into(),
            ));
        }
        let mut best_start = None;
        let mut best_end = 0usize;
        let mut run_start = 0usize;
        for (index, task) in tasks.iter().enumerate() {
            let supported = matches!(
                task.method_kind,
                poker_texas_air::method_kind::MethodKind::SubmitShuffleV2
                    | poker_texas_air::method_kind::MethodKind::SubmitReconstructDeck
                    | poker_texas_air::method_kind::MethodKind::FoldWithProof
                    | poker_texas_air::method_kind::MethodKind::SubmitPlayerRevealTokens
            );
            if !supported {
                if index - run_start > best_end.saturating_sub(best_start.unwrap_or(0)) {
                    best_start = Some(run_start);
                    best_end = index;
                }
                run_start = index + 1;
            }
        }
        if tasks.len() - run_start > best_end.saturating_sub(best_start.unwrap_or(0)) {
            best_start = Some(run_start);
            best_end = tasks.len();
        }
        let run_start = best_start.ok_or_else(|| {
            PluginError::Precondition("current hand has no contiguous crypto proof run".into())
        })?;
        if best_end - run_start < MIN_OUTER_CHILDREN {
            return Err(PluginError::Precondition(format!(
                "outer aggregation requires at least {MIN_OUTER_CHILDREN} contiguous crypto proofs, found {}",
                best_end - run_start
            )));
        }
        let run_tasks = &tasks[run_start..best_end];
        let children = run_tasks
            .iter()
            .zip(&archives[run_start..best_end])
            .map(|(task, archive)| dual_proof_from_archived(task, archive))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        let bundle = aggregate_dual_proofs(run_tasks, children)
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        verify_outer_aggregate(run_tasks, &bundle)
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        Ok(bundle)
    }

    /// 尝试 descriptor-only Aggregator 入口。
    ///
    /// 当前生产入口应返回 `UntrustedAggregationDisabled`；此方法存在是为了让服务
    /// 明确观测 fail-closed，而不是宣称已经生成可信单聚合证明。
    ///
    /// # Errors
    ///
    /// 聚合失败（如 children 少于 2 个、链断裂）时返回错误。
    pub fn aggregate_proofs(&mut self) -> PluginResult<()> {
        let children: Vec<_> = self
            .orchestrator
            .proven()
            .iter()
            .map(|p| p.to_child_descriptor())
            .collect();
        if children.len() < 2 {
            return Err(PluginError::Precondition(format!(
                "聚合至少需要 2 个已证明任务，当前 {}",
                children.len()
            )));
        }
        let proof = poker_texas_air::prover::aggregate_proofs(children).map_err(|error| {
            if matches!(
                error,
                poker_texas_air::error::TexasAirError::UntrustedAggregationDisabled
            ) {
                PluginError::UntrustedAggregationDisabled
            } else {
                PluginError::Prover(error.to_string())
            }
        })?;
        poker_texas_air::verifier::verify_aggregator(proof)
            .map_err(|e| PluginError::Prover(e.to_string()))
    }

    /// 构造测试用 DispatchContext（caller_pubkey 用占位）。
    fn make_ctx(&self, caller: poker_l1::Address) -> DispatchContext {
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

    /// Execute a dispatch with the exact context supplied by the transaction
    /// adapter.
    ///
    /// The loopback development API historically received only an address and
    /// therefore used [`Self::make_ctx`] as a compatibility fallback.  A
    /// receipt that is later anchored to a consensus transaction must instead
    /// use this method: its `caller` and `caller_pubkey` are committed by
    /// `dispatch_call_digest` and must be identical to the context rebuilt
    /// from that transaction.
    pub fn dispatch_with_context(
        &mut self,
        context: &DispatchContext,
        selector: &[u8; 32],
        args: &[u8],
    ) -> PluginResult<DispatchOutcome> {
        if texas_dispatch::CanonicalCommand::from_selector(selector).is_none() {
            return Err(PluginError::Dispatch(format!(
                "selector {} is retired and rejected by fresh and archive replay",
                hex::encode(selector)
            )));
        }
        let result = texas_dispatch::dispatch(context, &mut self.table, selector, args)
            .map_err(|e| PluginError::Dispatch(e.to_string()))?;

        // Deserialize return_value as poker_texas_air::DispatchOutput (the
        // Borsh contract is shared across the VM and proving crates).
        let output: DispatchOutput = BorshDeserialize::try_from_slice(&result.return_value)
            .map_err(|e| PluginError::Decode(format!("{e}")))?;

        // The VM owns all task metadata.  Consume it unchanged so the
        // Orchestrator replay sees precisely the context authenticated by the
        // transaction adapter.
        let prove_task = output.prove_task.clone();
        self.dispatch_count += 1;

        Ok(DispatchOutcome { output, prove_task })
    }

    /// 用共识来源的 [`ExpectedChainAnchor`] 锚定当前已证明 receipt 链（P05-H-source）。
    ///
    /// 与 [`ContractPlugin::verify_chain`](crate::plugin::ContractPlugin::verify_chain)
    /// 的区别：后者只做未外部锚定的相邻连续性检查；本方法额外校验链端点
    /// （table/hand/call_seq 范围、full-width state root/version）和每个 dispatch
    /// digest 都与共识来源 anchor 一致。anchor 本身应由
    /// [`poker_texas_air::consensus_anchor::build_anchor_from_consensus`] 从已认证
    /// block/receipt 构造，而不是从正在被证明的 task 自推。
    ///
    /// # Errors
    ///
    /// 链不连续或任一 anchored 字段/digest 不匹配时返回错误。
    pub fn verify_chain_against_consensus(&self, anchor: &ExpectedChainAnchor) -> PluginResult<()> {
        if !self.deferred_tagged_tasks.is_empty() {
            return Err(PluginError::Precondition(
                "cannot verify a receipt chain while tagged tasks are pending".into(),
            ));
        }
        let chain = self
            .orchestrator
            .verified_chain()
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        chain
            .verify_against_anchor(anchor)
            .map_err(|e| PluginError::Prover(e.to_string()))
    }

    /// 从原始共识材料构造 anchor 并验证当前 receipt chain。
    ///
    /// 这是生产适配器的唯一入口：服务不会接受由同一批未认证 prove task
    /// 自行拼出的 endpoint/digest。`material.build()` 先验证 block certificate
    /// 的 quorum 签名和所有 SMT inclusion proof，随后本方法才将得到的完整
    /// range 与本进程已原生验证的 receipt 逐项比对。
    ///
    /// # Errors
    ///
    /// 无效共识材料、空/不连续 receipt chain 或任一 anchor 字段不匹配时返回错误。
    pub fn verify_chain_from_consensus_material(
        &self,
        material: &ConsensusAnchorMaterial,
    ) -> PluginResult<ExpectedChainAnchor> {
        let anchor = material
            .build()
            .map_err(|error| PluginError::Prover(error.to_string()))?;
        self.verify_chain_against_consensus(&anchor)?;
        Ok(anchor)
    }
}

impl crate::plugin::ContractPlugin for TexasPokerPlugin {
    fn name(&self) -> &str {
        "texas_poker"
    }

    fn dispatch(
        &mut self,
        caller: poker_l1::Address,
        selector: &[u8; 32],
        args: &[u8],
    ) -> PluginResult<DispatchOutcome> {
        let ctx = self.make_ctx(caller);
        self.dispatch_with_context(&ctx, selector, args)
    }

    fn prove_task(&mut self, task: &ProveTask) -> PluginResult<ProvenTask> {
        Ok(self.prove_task_archived(task)?.summary)
    }

    fn verify_chain(&self) -> PluginResult<()> {
        if !self.deferred_tagged_tasks.is_empty() {
            return Err(PluginError::Precondition(
                "cannot verify a receipt chain while tagged tasks are pending".into(),
            ));
        }
        // 只检查本地 receipt 的相邻连续性（O(N) host 接受产物）。
        // 生产路径应改用 [`TexasPokerPlugin::verify_chain_against_consensus`]，
        // 传入由 `build_anchor_from_consensus` 从已认证 block/receipt 构造的 anchor，
        // 才能声称 block inclusion / 完整 batch。
        self.orchestrator
            .verify_chain()
            .map_err(|e| PluginError::Prover(e.to_string()))
    }

    fn aggregate(&mut self) -> PluginResult<()> {
        self.aggregate_proofs()
    }

    fn stats(&self) -> PluginStats {
        PluginStats {
            name: self.name().into(),
            dispatch_count: self.dispatch_count,
            prove_count: self.prove_count,
            chain_length: self.orchestrator.proven().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::dispatch::SubmitShuffleV2Args;
    use poker_l1::vm::contracts::texas_poker::types::{NO_SEAT, SeatStatus, ShuffleState};
    use poker_protocol::crypto::curve::{
        Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric,
    };
    use poker_protocol::crypto::types::ECPoint;
    use poker_protocol::zk_shuffle::ShuffleProof;
    use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
    use rand::rngs::OsRng;

    const FIXTURE_TIMESTAMP_MS: u64 = 2_000_000;

    fn context(caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xD1; 32],
            },
            chain_id: 377,
            block_height: 12_345,
            block_timestamp: FIXTURE_TIMESTAMP_MS,
        }
    }

    fn next_shuffle_task(
        pre_table: TexasPokerTable,
        aggregated_pk: <Bls12381Curve as Curve>::Point,
        permutation: &[usize],
    ) -> (ProveTask, TexasPokerTable) {
        let seat_index = pre_table.shuffle_state().derived_current_shuffler();
        assert_ne!(seat_index, NO_SEAT, "a shuffler should remain");
        let input_cards = pre_table.deck_state.encrypted.to_vec();
        let rerandomizers: Vec<_> = (0..input_cards.len())
            .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
            .collect();
        let output_cards: Vec<_> = (0..input_cards.len())
            .map(|index| {
                input_cards[permutation[index]].re_encrypt(&aggregated_pk, &rerandomizers[index])
            })
            .collect();
        let shuffle_proof = ShuffleProof::prove(
            &input_cards,
            &output_cards,
            permutation,
            &rerandomizers,
            &aggregated_pk,
            &mut OsRng,
            &mut FiatShamirTranscript::new(b"zk_shuffle_proof_v2"),
        )
        .expect("shuffle proof should build");
        let raw_args = borsh::to_vec(&SubmitShuffleV2Args {
            seat_index,
            output_cards,
            shuffle_proof,
        })
        .expect("shuffle args should encode");
        let caller = pre_table.seats[usize::from(seat_index)].player();
        let mut post_table = pre_table;
        let result = texas_dispatch::dispatch(
            &context(caller),
            &mut post_table,
            &texas_dispatch::selectors::submit_shuffle_v2(),
            &raw_args,
        )
        .expect("sequential shuffle should dispatch");
        let output: DispatchOutput =
            borsh::from_slice(&result.return_value).expect("dispatch output should decode");
        (
            output.prove_task.expect("shuffle should emit a prove task"),
            post_table,
        )
    }

    fn sequential_shuffle_tasks() -> (Vec<ProveTask>, TexasPokerTable) {
        let seat_secrets: Vec<_> = (0..2)
            .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
            .collect();
        let seat_keys: Vec<_> = seat_secrets
            .iter()
            .map(|secret| <Bls12381Curve as Curve>::base_g() * secret)
            .collect();
        let aggregated_pk = seat_keys[0] + seat_keys[1];
        let input_cards: Vec<_> = (0..52)
            .map(|index| {
                let card = Bls12381Curve::hash_to_curve(
                    format!("restart-aggregate/card/{index}").as_bytes(),
                );
                ElGamalCiphertextGeneric::encrypt(
                    &card,
                    &aggregated_pk,
                    &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
                )
            })
            .collect();
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB8; 20], 901),
            "restart-aggregate".into(),
            [0xC0; 20],
            2,
            50,
            100,
        );
        table.call_seq = 20;
        table.hand_id = 9;
        for (index, key) in seat_keys.into_iter().enumerate() {
            table.seats[index] = poker_l1::vm::contracts::texas_poker::types::Seat::occupied(
                [u8::try_from(index + 1).unwrap(); 20],
                1_000,
                ECPoint(key),
                SeatStatus::Active,
            )
            .expect("shuffle fixture seat should be canonical");
        }
        table.deck_state.encrypted = input_cards.try_into().unwrap();
        table.deck_state.contributor_mask = 0b11;
        assert_eq!(
            table.derived_aggregated_pk().unwrap(),
            Some(ECPoint(aggregated_pk))
        );
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                FIXTURE_TIMESTAMP_MS,
            )
            .unwrap();

        let mut first_permutation: Vec<usize> = (0..52).collect();
        first_permutation[..8].copy_from_slice(&[3, 0, 7, 1, 6, 2, 5, 4]);
        let (first, table) = next_shuffle_task(table, aggregated_pk, &first_permutation);
        let mut second_permutation: Vec<usize> = (0..52).collect();
        second_permutation[..8].copy_from_slice(&[1, 7, 3, 5, 0, 6, 4, 2]);
        let (second, table) = next_shuffle_task(table, aggregated_pk, &second_permutation);
        (vec![first, second], table)
    }

    #[test]
    fn fresh_service_dispatch_rejects_every_retired_selector_before_mutation() {
        let creator = [0xA7; 20];
        let table = TexasPokerTable::new(
            ObjectID::new([0xB7; 20], 77),
            "active-selectors-only".into(),
            creator,
            2,
            50,
            100,
        );
        let mut plugin = TexasPokerPlugin::new(table.clone());
        for selector in [
            texas_dispatch::compute_method_selector("join_and_shuffle"),
            texas_dispatch::compute_method_selector("leave_with_proof"),
            texas_dispatch::compute_method_selector("auto_fold"),
            texas_dispatch::compute_method_selector("kick_player"),
            texas_dispatch::compute_method_selector("reset_for_next_hand"),
        ] {
            let error = match plugin.dispatch_with_context(&context(creator), &selector, &[]) {
                Ok(_) => panic!("fresh service calls must reject retired selectors"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("retired"), "{error}");
            assert_eq!(plugin.table(), &table);
            assert_eq!(plugin.dispatch_count, 0);
        }
    }

    #[test]
    fn restored_archives_aggregate_and_reject_reorder_or_tampering() {
        let (tasks, persisted_table) = sequential_shuffle_tasks();
        let mut proving = Orchestrator::new();
        let archives: Vec<_> = tasks
            .iter()
            .map(|task| {
                proving
                    .prove_verify_and_archive_task(task)
                    .expect("method proof should archive")
                    .archive
            })
            .collect();

        let mut mismatched = TexasPokerPlugin::from_persisted_state(persisted_table.clone(), 2, 2);
        assert!(
            mismatched
                .restore_archived_task(&tasks[0], &archives[1], None)
                .is_err(),
            "an archive from a later task must not verify against an earlier task"
        );
        assert!(
            mismatched.proven().is_empty(),
            "failed archive restoration must be atomic"
        );

        let mut reversed = TexasPokerPlugin::from_persisted_state(persisted_table.clone(), 2, 2);
        reversed
            .restore_archived_task(&tasks[1], &archives[1], None)
            .expect("an independently valid first receipt may start a recovered segment");
        assert!(
            reversed
                .restore_archived_task(&tasks[0], &archives[0], None)
                .is_err(),
            "reversing journal order must break receipt-chain continuity"
        );
        assert_eq!(
            reversed.proven().len(),
            1,
            "the rejected out-of-order receipt must not mutate recovered history"
        );
        assert!(
            reversed.aggregate_crypto_proofs().is_err(),
            "a partial reversed recovery must not produce an aggregate"
        );

        let mut tampered_bytes = archives[0]
            .to_bytes()
            .expect("archive should encode for corruption testing");
        *tampered_bytes
            .last_mut()
            .expect("archive should contain a proof payload") ^= 0x01;
        let tampered = ArchivedMethodProof::from_bytes(&tampered_bytes)
            .expect("the corrupted payload should remain a well-formed archive envelope");
        let mut corrupted = TexasPokerPlugin::from_persisted_state(persisted_table.clone(), 2, 2);
        assert!(
            corrupted
                .restore_archived_task(&tasks[0], &tampered, None)
                .is_err(),
            "native STARK verification must reject a corrupted archive"
        );
        assert!(
            corrupted.proven().is_empty(),
            "tampered archive rejection must leave recovered history unchanged"
        );

        let mut restored = TexasPokerPlugin::from_persisted_state(persisted_table, 2, 2);
        for (task, archive) in tasks.iter().zip(&archives) {
            restored
                .restore_archived_task(task, archive, None)
                .expect("restart should reverify and restore each archive");
        }
        let aggregate = restored
            .aggregate_crypto_proofs()
            .expect("restored crypto run should aggregate");
        assert_eq!(aggregate.children().len(), 2);
        assert_eq!(aggregate.hand_id(), tasks[0].hand_id);
        assert_eq!(restored.proven().len(), 2);
    }
}
