//! Method AIRs — 18 个方法各自专用 AIR。
//!
//! ## 分类
//!
//! - [`lifecycle`] — A 档：6 个表台生命周期方法
//! - [`actions`] — B 档：7 个玩家动作方法
//! - [`crypto`] — C 档：5 个密码学协议方法
//!
//! ## 通用模板
//!
//! 所有 AIR 共享 [`common`] 模块的通用列布局与约束工具。

pub mod common;
pub mod lifecycle;
pub mod actions;
pub mod crypto;
