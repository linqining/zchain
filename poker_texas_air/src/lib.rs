//! # poker_texas_air — Texas Poker method AIR + host verification
//!
//! VM 当前注册 23 个 selector；其中 21 个有 method AIR / host prove+verify 路径，
//! `request_leave_after_hand` 与 `fold_with_proof` 在生产 Orchestrator 中显式
//! fail-closed。当前 Aggregator 只处理 descriptor，尚不能递归验证子 proof。
//!
//! ## 架构分层
//!
//! - **Layer 0**: Method AIRs（21 个启用；2 个注册 selector 禁用）
//! - **Layer 1**: Host verification receipts（完整 VM dispatch replay 后逐 proof 原生验证）
//! - **Layer 2**: Aggregator AIR PoC（只聚合 descriptor，不验证子 proof，生产入口禁用）
//! - **Layer 3**: Final Recursion（尚未形成可用闭环）
//!
//! ## 设计文档
//!
//! 详见 `.trae/documents/poker_texas_air_custom_circuit_plan.md`。
//!
//! ## 复用率 ~85%
//!
//! - 审计结论：`poker_zkvm` recursive 模块目前只能作为实验性 PoC，不能作为可信 verifier
//! - state root 在可信 host 端从 canonical Borsh preimage 重算，并与完整公开输入一起
//!   混入 Fiat–Shamir；当前 method AIR 内没有嵌入 Poseidon verifier 组件
//! - 直接复用 `poker_zkvm::stwo_backend::range_check_air`（列范围检查）
//! - 直接复用 `poker_l1::vm::contracts::texas_poker::types::TexasPokerTable`（业务类型）

#![deny(unsafe_code)]
#![deny(missing_docs)]

// Integration tests use this feature to exercise deliberately untrusted PoC
// entry points. Refuse release artifacts that accidentally enable it through
// `--all-features`; checked production APIs remain available without it.
#[cfg(all(feature = "test-helpers", not(debug_assertions)))]
compile_error!("poker_texas_air/test-helpers must not be enabled in release builds");

// ===== Layer 0: Method AIRs =====
pub mod airs;
pub mod trace_gen;

// ===== 公共基础设施 =====
pub mod error;
pub mod merkle_tree;
pub mod method_kind;
pub mod public_inputs;
pub mod state_root;
pub mod verified_chain;

// ===== Post-commit Prover =====
// 证明任务（数据契约）+ Orchestrator（异步消费任务生成/聚合 proof）。
// 详见 orchestrator.rs 的架构说明。
pub mod orchestrator;
pub mod prove_task;

// ===== Layer 2: Aggregator AIR =====
// 阶段 4 PoC：Aggregator AIR 不再 feature-gated（不依赖 poker_zkvm recursive）。
// descriptor-only prove/verify 生产入口默认拒绝，只保留显式测试入口。
pub mod aggregator_air;
pub mod aggregator_prover;
pub mod aggregator_verifier;

// ===== Prover / Verifier 入口 =====
pub mod prover;
pub mod verifier;
