//! A 档 — 表台生命周期方法 AIRs（6 个）。
//!
//! - [`create_table`] — 创建新桌台
//! - [`join_table`] — 简单入座
//! - [`leave_table`] — 简单离座
//! - [`start_hand`] — 开始新一局
//! - [`tick`] — 超时驱动
//! - [`reset_for_next_hand`] — 显式重置桌台

pub mod create_table;
pub mod join_table;
pub mod leave_table;
pub mod reset_for_next_hand;
pub mod start_hand;
pub mod tick;
