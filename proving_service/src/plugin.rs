//! 合约插件抽象 —— 服务加载不同合约的统一接口。
//!
//! 每个合约实现 [`ContractPlugin`]，服务即可对其 dispatch 并证明。
//! 首个实现是 [`crate::contracts::texas_poker::TexasPokerPlugin`]。

use poker_texas_air::orchestrator::ProvenTask;
use poker_texas_air::prove_task::DispatchOutput;

/// 合约插件错误。
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// 底层合约 dispatch 错误（poker_l1 PokerL1Error 转字符串）。
    #[error("dispatch error: {0}")]
    Dispatch(String),
    /// 反序列化 return_value 失败（borsh 兼容性问题）。
    #[error("decode return_value: {0}")]
    Decode(String),
    /// 证明层错误（Orchestrator / Stwo）。
    #[error("prover error: {0}")]
    Prover(String),
    /// 状态前置条件不满足（如阶段顺序错误）。
    #[error("precondition: {0}")]
    Precondition(String),
    /// descriptor-only 聚合被生产安全边界按预期拒绝。
    #[error("untrusted descriptor-only aggregation is disabled")]
    UntrustedAggregationDisabled,
}

/// 插件结果别名。
pub type PluginResult<T> = Result<T, PluginError>;

/// 单步 dispatch 的产出：反序列化后的 DispatchOutput + 是否带有 prove_task。
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    /// 反序列化后的 DispatchOutput（events + 可选 prove_task）。
    pub output: DispatchOutput,
    /// 本次 dispatch 产生的证明任务（None 表示该方法无需证明，如 tick）。
    pub prove_task: Option<poker_texas_air::prove_task::ProveTask>,
}

/// 插件运行统计（供 `/plugins` 端点回报）。
#[derive(Debug, Clone, Default)]
pub struct PluginStats {
    /// 插件名（合约标识）。
    pub name: String,
    /// 累计 dispatch 次数。
    pub dispatch_count: u64,
    /// 累计 prove 次数（含 verify）。
    pub prove_count: u64,
    /// 当前 state_root 链长度（已证明任务数）。
    pub chain_length: usize,
}

/// 合约插件 trait —— 服务通过它驱动任意合约的 dispatch + 证明。
///
/// 实现要点：
/// - `dispatch` 委托合约自身的 dispatch 函数，并从 `return_value` 反序列化出
///   `DispatchOutput`（borsh 跨 crate 兼容）。
/// - `prove` 把 `ProveTask` 交给 `poker_texas_air::Orchestrator`（prove + 立即 verify）。
/// - `verify_chain` 校验已证明任务的本地 state_root 相邻连续性；是否外部锚定由具体
///   实现另行声明。
pub trait ContractPlugin: Send + Sync {
    /// 插件名（如 `"texas_poker"`）。
    fn name(&self) -> &str;

    /// 执行单步合约调用：selector + borsh(args) → DispatchOutcome。
    ///
    /// `caller` 由服务指定（模拟 DispatchContext.caller）。
    fn dispatch(
        &mut self,
        caller: poker_l1::Address,
        selector: &[u8; 32],
        args: &[u8],
    ) -> PluginResult<DispatchOutcome>;

    /// 证明一个任务（prove + 立即 verify），返回任务摘要。
    fn prove_task(
        &mut self,
        task: &poker_texas_air::prove_task::ProveTask,
    ) -> PluginResult<ProvenTask>;

    /// 校验已证明任务的本地 state_root 链式一致性。
    fn verify_chain(&self) -> PluginResult<()>;

    /// 聚合所有已证明任务为单证明（可选；默认未实现）。
    fn aggregate(&mut self) -> PluginResult<()> {
        Err(PluginError::Precondition("aggregate 未实现".into()))
    }

    /// 返回运行统计。
    fn stats(&self) -> PluginStats;
}
