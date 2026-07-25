//! B 档 — 玩家动作方法 AIRs（8 个）。
//!
//! - [`fold`] — 玩家主动 fold（弃牌）
//! - [`check`] — 玩家过牌（不下注且无需跟注）
//! - [`call`] — 玩家跟注（匹配当前最高下注）
//! - [`raise`] — 玩家加注（提高当前下注）
//! - [`bet`] — 玩家主动下注（postflop 第一个下注者，语义等同 raise）
//! - [`auto_fold`] — 玩家超时自动 fold
//! - [`force_fold`] — 管理员强制 fold 玩家
//! - [`kick_player`] — 踢出玩家（管理员操作）
//!
//! ## 约束模板
//!
//! 每个 action AIR 验证：
//! 1. 通用约束（[`crate::airs::common::CommonConstraints`]）
//! 2. `seat_index == input.seat_index`（输入一致性）
//! 3. 业务约束（如 `fold` 约束 `output_folded == 1`，`call` 约束 `output_call_amount == input.amount`）

pub mod fold;
pub mod check;
pub mod call;
pub mod raise;
pub mod bet;
pub mod auto_fold;
pub mod force_fold;
pub mod kick_player;
