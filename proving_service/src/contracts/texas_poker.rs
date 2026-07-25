//! `TexasPokerPlugin` —— 首个 [`crate::plugin::ContractPlugin`] 实现。
//!
//! 封装 `poker_l1` 的 texas_poker 合约 + `poker_texas_air` 的 Orchestrator：
//!
//! - 内部持有可变的 `TexasPokerTable` 状态。
//! - `dispatch` 委托 `poker_l1::vm::contracts::texas_poker::dispatch::dispatch`，
//!   从 `return_value` 反序列化出 `DispatchOutput`，并覆盖 `call_seq`（合约当前
//!   硬编码 0，这里递增以支持 state_root 链排序）。
//! - `prove_task` 委托 `Orchestrator::prove_and_verify_task`（prove + 立即 verify）。

use borsh::BorshDeserialize;

use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::dispatch as texas_dispatch;
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;

use poker_texas_air::orchestrator::{Orchestrator, ProvenTask};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};

use crate::plugin::{DispatchOutcome, PluginError, PluginResult, PluginStats};

/// texas_poker 合约插件。
pub struct TexasPokerPlugin {
    /// 桌台状态（dispatch 就地修改）。
    table: TexasPokerTable,
    /// 证明编排器（累积已证明任务）。
    orchestrator: Orchestrator,
    /// dispatch 调用序号（每次 dispatch 递增，用于 state_root 链排序）。
    call_seq: u32,
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
            call_seq: 0,
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

    /// 聚合所有已证明任务为单证明（委托 Orchestrator → aggregator）。
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
        let proof = poker_texas_air::prover::aggregate_proofs(children)
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        poker_texas_air::verifier::verify_aggregator(proof)
            .map_err(|e| PluginError::Prover(e.to_string()))
    }

    /// 构造测试用 DispatchContext（caller_pubkey 用占位）。
    fn make_ctx(&self, caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey { tag: 0, raw: vec![0xBB; 32] },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
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

        // 覆盖 call_seq（合约硬编码 0；这里递增以支持 state_root 链排序）
        let prove_task = output.prove_task.as_ref().map(|t| {
            let mut t = t.clone();
            t.call_seq = self.call_seq;
            t
        });
        self.call_seq = self.call_seq.wrapping_add(1);
        self.dispatch_count += 1;

        Ok(DispatchOutcome { output, prove_task })
    }

    fn prove_task(&mut self, task: &ProveTask) -> PluginResult<ProvenTask> {
        let summary = self
            .orchestrator
            .prove_and_verify_task(task)
            .map_err(|e| PluginError::Prover(e.to_string()))?;
        self.prove_count += 1;
        Ok(summary)
    }

    fn verify_chain(&self) -> PluginResult<()> {
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
