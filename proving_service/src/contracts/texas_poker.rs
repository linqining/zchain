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

use poker_texas_air::orchestrator::{Orchestrator, ProvenTask};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
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
    }

    /// 注册聚合公钥（`aggregated_pk`）到桌台 deck_state。
    ///
    /// 真实协议中每个玩家经 `join_and_shuffle` 入座时会把自己的 pk 累加进
    /// `deck_state.aggregated_pk`；该值是后续 `submit_shuffle_v2` 的 shuffle proof
    /// 绑定的共享公钥（proof 把它作为广义 Schnorr 的基点之一，禁止 identity）。
    ///
    /// 本驱动用 `join_table`（不设 aggregated_pk）入座以便 `start_hand` 后能洗牌，
    /// 故需在 `start_hand` 前显式注册聚合 pk（= Σ player pk），使 shuffle proof
    /// 可生成。仅在 WAITING 态、对局未开始时调用；`start_hand` 会保留该值
    /// （`set_initial_encrypted_deck` 不清 aggregated_pk）。
    pub fn register_aggregated_pk(&mut self, pk: poker_protocol::crypto::ECPoint) {
        self.table.deck_state.aggregated_pk = Some(pk);
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
        let chain = self
            .orchestrator
            .verified_chain()
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        chain
            .verify_against_anchor(anchor)
            .map_err(|e| PluginError::Prover(e.to_string()))
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
        let result = texas_dispatch::dispatch(&ctx, &mut self.table, selector, args)
            .map_err(|e| PluginError::Dispatch(e.to_string()))?;

        // 反序列化 return_value 为 poker_texas_air::DispatchOutput（borsh 跨 crate 兼容）
        let output: DispatchOutput = BorshDeserialize::try_from_slice(&result.return_value)
            .map_err(|e| PluginError::Decode(format!("{e}")))?;

        // 任务元数据由 VM dispatch 写入。原样消费，确保 Orchestrator 的完整
        // dispatch replay 能逐字段匹配 regenerated task；本地服务不声称 block inclusion。
        let prove_task = output.prove_task.clone();
        self.dispatch_count += 1;

        Ok(DispatchOutcome { output, prove_task })
    }

    fn prove_task(&mut self, task: &ProveTask) -> PluginResult<ProvenTask> {
        // `start_hand` is the only normal transition that advances `hand_id`. A receipt chain is
        // deliberately scoped to one hand, so perform the segment boundary here instead of
        // relying on an individual HTTP/CLI caller to remember it.
        if task.pre_table.hand_id != task.post_table.hand_id {
            self.orchestrator.start_new_chain_segment();
        }
        let summary = self
            .orchestrator
            .prove_and_verify_task(task)
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        self.prove_count += 1;
        Ok(summary)
    }

    fn verify_chain(&self) -> PluginResult<()> {
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
