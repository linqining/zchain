//! # Phase 5 — Stwo 递归证明实验层（Verifier AIR PoC）
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md`（v5.0 MVP 设计）。
//!
//! ## 目标
//!
//! 目标是实现 Stwo 递归证明：L2 proof = Stwo Verifier AIR 证明 "L1 proof 通过 verify"。
//! 当前实现尚未完整约束 Merkle/FRI decommitment 与公开输入，只能作为 crate 内审计 PoC。
//! 跨 crate 的 prove/verify 入口一律 fail closed。
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
//! - **v5.1（实验）**：3 个不完整 verifier AIR；尚不具备生产 soundness
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

/// 仅当 canonical Merkle/FRI replay 已被完整约束进 AIR、真实 Poseidon252 non-native
/// 算术和 method-specific transcript/composition verifier 均完成审计后才能改为 `true`。
///
/// `stwo_replay` / `fri_replay` 已完成 host 侧精确重放，但 host witness 生成正确不等于
/// AIR 已约束该 witness，因此当前值必须保持 `false`。
pub(crate) const MERKLE_VERIFIER_AIR_COMPLETE: bool = false;

pub(crate) mod composition_eval_air;
#[cfg(test)]
mod e2e_test;
pub(crate) mod fri_replay;
pub(crate) mod fri_verifier_air;
pub(crate) mod merkle_path_air;
pub(crate) mod oods_check_air;
pub mod public_inputs;
pub mod recursion_prover;
pub mod recursion_verifier;
pub(crate) mod stwo_replay;
pub mod trace_gen;

pub use public_inputs::{RecursivePublicInputs, RecursiveTreeMetadata};
