//! C 档 — Mental Poker 协议方法 AIRs（5 个）。
//!
//! - [`join_and_shuffle`] — 玩家加入并完成首洗牌
//! - [`leave_with_proof`] — 玩家带 proof 离场
//! - [`submit_shuffle_v2`] — 玩家提交洗牌结果（V2）
//! - [`submit_player_reveal_tokens`] — 提交揭牌令牌
//! - [`submit_reconstruct_deck`] — 提交重构牌组
//!
//! ## 简化策略
//!
//! Mental Poker 协议涉及复杂密码学：
//! - ElGamal 加密牌组
//! - DLEq 零知识证明（每张牌一个）
//! - Reconstruct 多方重构
//! - Reveal Token 揭示
//!
//! 完整实现需嵌入 [`poker_zkvm::stwo_backend::recursive`] 的 Verifier AIR
//! 作为子组件（递归验证这些密码学 proof）。**阶段 4 PoC** 采用简化策略：
//! - AIR 只验证协议级状态变更（shuffle_state.phase / reveal_phase / reconstruct_phase 转换）
//! - 验证 proof 引用（commitment hash）一致性
//! - 完整密码学约束留待阶段 5（嵌入 Verifier AIR）
//!
//! ## AIR 列布局
//!
//! 所有 crypto AIR 共享通用 37 列 + 业务列（每个方法自定义）。

pub mod join_and_shuffle;
pub mod fold_with_proof;
pub mod leave_with_proof;
pub mod submit_player_reveal_tokens;
pub mod submit_reconstruct_deck;
pub mod submit_shuffle_v2;
