//! # poker_texas_air — Texas Poker 自定义电路 + Aggregator AIR PoC
//!
//! 把 `poker_l1/src/vm/contracts/texas_poker` 的 21 个方法各自实现为专用 AIR
//! （业务语义直接电路化）。当前 Aggregator 只处理 descriptor，尚不能递归验证子 proof。
//!
//! ## 架构分层
//!
//! - **Layer 0**: Method AIRs（21 个，每方法一个专用 AIR）
//! - **Layer 1**: Host verification receipts（逐个原生验证；当前没有可信递归 verifier）
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
//! - 直接复用 `poker_zkvm::stwo_backend::poseidon_air::PoseidonAir`（state_root 哈希）
//! - 直接复用 `poker_zkvm::stwo_backend::range_check_air`（列范围检查）
//! - 直接复用 `poker_l1::vm::contracts::texas_poker::types::TexasPokerTable`（业务类型）

#![deny(unsafe_code)]
#![deny(missing_docs)]

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
pub mod prove_task;
pub mod orchestrator;

// ===== Layer 2: Aggregator AIR =====
// 阶段 4 PoC：Aggregator AIR 不再 feature-gated（不依赖 poker_zkvm recursive）。
// descriptor-only prove/verify 生产入口默认拒绝，只保留显式测试入口。
pub mod aggregator_air;
pub mod aggregator_prover;
pub mod aggregator_verifier;

// ===== Prover / Verifier 入口 =====
pub mod prover;
pub mod verifier;
