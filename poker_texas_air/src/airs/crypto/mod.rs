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
//! 这些 AIR 因此不能单独作为 DLEq / shuffle / reveal / reconstruct
//! proof 已验证的可转移证据。当前生产 receipt 路径的信任边界是
//! [`crate::orchestrator::Orchestrator`]：它先重放完整原生 VM dispatch，再验证
//! method AIR。`poker_l1` 在非 crate 内单元测试构建中已禁止运行时
//! `zk_skip_*` 绕过，所以该 host replay 会执行真实密码学验证。
//! 完整的 recursive AIR 子证明仍未实现。
//!
//! ## AIR 列布局
//!
//! 所有 crypto AIR 共享通用 37 列 + 业务列（每个方法自定义）。

pub mod join_and_shuffle;
pub mod leave_with_proof;
pub mod submit_player_reveal_tokens;
pub mod submit_reconstruct_deck;
pub mod submit_shuffle_v2;
