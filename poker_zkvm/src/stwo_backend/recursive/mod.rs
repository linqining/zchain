//! # Phase 5 — Stwo 递归证明层（Verifier AIR）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md`（v5.0 MVP 设计）。
//!
//! ## 目标
//!
//! 实现 Stwo 递归证明：L2 proof = Stwo Verifier AIR 证明 "L1 proof 通过 verify"。
//! L2 proof 大小目标 < 20KB，链上验证 < 100ms。
//!
//! ## 架构
//!
//! 4 个 Verifier AIR + 1 个 Recursion Aggregator：
//! - [`oods_check_air`] — OODS（Out-Of-Domain Sampling）等式检查 AIR
//! - [`merkle_path_air`] — Merkle Path Verifier AIR（Poseidon252 哈希链）
//! - [`fri_verifier_air`] — FRI Verifier AIR（last_layer check + commit/decommit）
//! - [`composition_eval_air`] — Composition polynomial evaluation AIR
//! - [`recursion_prover`] — 聚合 4 个 AIR 的 Recursion Prover
//! - [`recursion_verifier`] — Recursion Verifier
//! - [`public_inputs`] — RecursivePublicInputs 公开输入定义
//! - [`trace_gen`] — 4 个 AIR 的 trace 生成器
//!
//! ## v5.0 vs v5.1
//!
//! - **v5.0（MVP）**：3 个 AIR（OODS + FRI last_layer + Merkle Path）+ 简化 Composition Eval
//! - **v5.1（生产）**：4 个完整 AIR，完整 soundness
//!
//! ## v2.1 Hard Constraint
//!
//! 所有 AIR 约束 degree ≤ 2，强制 Stwo 使用 `EvaluationMode::SubDomain`（与 Phase 4 一致）。
//!
//! ## 参考
//!
//! - `stwo-2.3.0/src/core/verifier.rs` — `verify_ex` 主流程
//! - `stwo-2.3.0/src/core/pcs/verifier.rs` — `CommitmentSchemeVerifier`
//! - `stwo-2.3.0/src/core/fri.rs` — `FriVerifier` + `FriProof`
//! - `stwo-2.3.0/src/core/vcs_lifted/verifier.rs` — `MerkleVerifierLifted`

pub mod composition_eval_air;
pub mod e2e_test;
pub mod fri_verifier_air;
pub mod merkle_path_air;
pub mod oods_check_air;
pub mod public_inputs;
pub mod recursion_prover;
pub mod recursion_verifier;
pub mod trace_gen;

pub use public_inputs::RecursivePublicInputs;