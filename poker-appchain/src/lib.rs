//! # poker-appchain — 专用扑克结算 L1（appchain）
//!
//! Hyperliquid 模式的扑克专用链：链内无 gas，收入来自可证明 rake。
//! 费率是状态机里的数据（策略注册表），不是协议参数。
//!
//! ## 模块地图（对应 docs/plan-appchain-v1.md）
//!
//! - **M1 Note 账本**：[`note`]（note/承诺/nullifier/资产类隔离）、
//!   [`merkle`]（Poseidon 承诺树）、[`nullifier_set`]（防双花）
//! - **M5 费率**：[`fee`]（FeePolicy 注册表 ZERO/FIXED_RAKE + 分账）
//! - **M2 结算关系**：[`settlement`]（SettleNotes 守恒 + 费率 + P 层签名覆盖，
//!   fail-closed 校验，AIR witness 形状就绪）
//! - **M3 Sequencer**：[`ops`]（封闭操作集）、[`soft_confirm`]（软确认链）、
//!   [`wal`]（写前日志）、[`sequencer`]（查重/准入/限流/应用）
//! - **M4 证明管道**：[`pipeline`]（worker 池/批次聚合/积压降级）
//! - **M7 出入金**：[`vault`]（托管对账）
//! - **M8 安全**：[`watcher`]（等价性/分叉检测）；攻击回归在 `tests/`
//! - **M9 可观测**：[`metrics`]（计数器/直方图 + 文本导出 + 告警规则）
//! - **M6 客户端**：[`client_view`]（余额聚合视图最小实现）
//!
//! ## 纪律
//!
//! - `#![deny(unsafe_code)]`、`#![deny(missing_docs)]`，与主 workspace 一致
//! - 所有跨边界结构走 borsh 稳定字节 ABI（见 `docs/` 下 ABI 规范）
//! - 校验 fail-closed：任何未覆盖语义一律拒绝
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod client_view;
pub mod error;
pub mod fee;
pub mod felt;
pub mod keys;
pub mod merkle;
pub mod metrics;
pub mod note;
pub mod nullifier_set;
pub mod ops;
pub mod pipeline;
pub mod sequencer;
pub mod settlement;
pub mod soft_confirm;
pub mod vault;
pub mod wal;
pub mod watcher;

pub use error::{AppchainError, AppchainResult};
