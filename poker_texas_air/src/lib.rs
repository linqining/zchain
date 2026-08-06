//! # poker_texas_air — Texas Poker method AIR + host verification
//!
//! VM 当前注册的 23 个 selector 均有 method AIR / host prove+verify 路径。批量
//! Aggregator 仍是 descriptor-only PoC，不能作为递归压缩证明使用。
//!
//! ## 架构分层
//!
//! - **Layer 0**: Method AIRs（23 个启用）
//! - **Layer 1**: Host verification receipts（完整 VM dispatch replay 后逐 proof 原生验证）
//! - **Layer 2**: Host-verified outer precompile（O(N) child replay + final digest AIR）
//! - **Layer 3**: Texas 自有递归协议（尚未实现，生产验证入口保持关闭）
//!
//! ## 设计文档
//!
//! 详见 `.trae/documents/poker_texas_air_custom_circuit_plan.md`。
//!
//! ## 复用率 ~85%
//!
//! - state root 在可信 host 端从 canonical Borsh preimage 重算，并与完整公开输入一起
//!   混入 Fiat–Shamir；当前 method AIR 内没有嵌入 Poseidon verifier 组件
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
pub mod deck_commitment;
pub mod dual_proof;
pub mod error;
pub mod merkle_tree;
pub mod method_kind;
pub mod outer_aggregate;
pub mod outer_precompile;
pub mod precompile_binding;
pub mod proof_archive;
pub mod prove_timing;
pub mod public_inputs;
pub mod settlement_binding;
pub mod state_root;
pub mod verified_chain;

// ===== Post-commit Prover =====
// 证明任务（数据契约）+ Orchestrator（异步消费任务生成/聚合 proof）。
// 详见 orchestrator.rs 的架构说明。
pub mod orchestrator;
pub mod prove_task;

// ===== Layer 2: Aggregator AIR =====
// 阶段 4 PoC：Aggregator AIR 不再 feature-gated。
// descriptor-only prove/verify 生产入口默认拒绝，只保留显式测试入口。
pub mod aggregator_air;
pub mod aggregator_prover;
pub mod aggregator_verifier;
pub mod authorization_binding;

// P05-H-source：从已认证共识材料构造 ExpectedChainAnchor。
pub mod consensus_anchor;

// ===== Prover / Verifier 入口 =====
pub mod prover;
pub mod verifier;
