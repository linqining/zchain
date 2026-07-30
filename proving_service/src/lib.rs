//! # proving_service — 链下证明服务
//!
//! 以**合约插件**形式加载不同合约，复用合约自身的 `dispatch` 产生 pre/post 状态
//! 快照，再交给 `poker_texas_air` 的 Orchestrator 生成并原生验证 method STARK proof。
//! descriptor-only 聚合生产入口保持 fail-closed，当前服务不生成可信单聚合 proof。
//!
//! ## 架构
//!
//! ```text
//! ┌─ ContractPlugin（trait）──────────────────────────┐
//! │  TexasPokerPlugin（首个实现）                      │
//! │   ├─ dispatch(selector, args)                      │
//! │   │    └─ 委托 poker_l1::vm::contracts::texas_poker::dispatch::dispatch
//! │   │       → return_value = borsh(DispatchOutput{ events, prove_task })
//! │   ├─ prove_task(task) → 委托 poker_texas_air::Orchestrator
//! │   └─ verify_chain() / aggregate()                  │
//! └────────────────────────────────────────────────────┘
//! ```
//!
//! ## 当前覆盖
//!
//! - [`plugin::ContractPlugin`] trait：统一的"加载合约"抽象，未来其他合约实现即可加载。
//! - [`contracts::texas_poker::TexasPokerPlugin`]：封装 texas_poker 合约 + Orchestrator。
//! - [`runner::HandRunner`]：驱动 6 步 WAITING 状态覆盖片段，串联未外部锚定的
//!   host-verified state-root 链；它不是完整一手牌，也不证明 block inclusion。
//! - [`server`]：axum HTTP 服务（`POST /hands/run`、fail-closed 的 `POST /dispatch`、
//!   `GET /plugins`）。
//!
//! ## 设计原则
//!
//! - **状态转移正确性来自合约**：服务不重算业务逻辑，只 dispatch 真实合约并证明。
//! - **证明管线复用 poker_texas_air**：服务只负责编排，不实现 AIR。

pub mod contracts;
pub mod plugin;
pub mod runner;
pub mod server;

pub use plugin::{ContractPlugin, DispatchOutcome, PluginError, PluginResult, PluginStats};
pub use runner::HandRunner;

/// 服务错误（统一包装合约层 / 证明层 / 编排层错误）。
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// 合约插件错误。
    #[error("plugin error: {0}")]
    Plugin(#[from] PluginError),
    /// 证明层（Orchestrator / Stwo）错误。
    #[error("prover error: {0}")]
    Prover(String),
    /// 编排错误（阶段顺序、状态前置条件不满足等）。
    #[error("runner error: {0}")]
    Runner(String),
}

/// 服务结果别名。
pub type ServiceResult<T> = Result<T, ServiceError>;
