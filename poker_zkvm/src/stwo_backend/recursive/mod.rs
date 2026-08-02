//! # Stwo 原生递归验证层
//!
//! 详见 `.trae/documents/stwo_phase5_verifier_air_design.md`（v5.0 MVP 设计）。
//!
//! ## 目标
//!
//! `prove_recursive_with_fri` / `verify_recursive_with_fri` 将固定 verifier transcript、
//! Poseidon252、compressed multi-query Merkle、PCS quotient、FRI fold、OODS 与
//! method-specific composition binding 装配为一个新的 STWO proof。`ReplicatedRowV1`
//! 允许应用 crate 重建可信 component，并在不接收 inner proof 的情况下直接验证该 proof。
//!
//! 完整验证路径仅在显式启用 `recursive-verifier`（或包含它的 `recursive-prover`）feature
//! 时对跨 crate 调用开放。该路径已有完整回归和防篡改覆盖，但尚未经过独立密码学审计，
//! 因此不能等同于 production approval。旧的仅 OODS、`MerklePathAir` 和
//! `FriVerifierAir` PoC 不进入完整路径。
//!
//! ## 架构
//!
//! Active verifier components：
//! - [`transcript_air`] — verifier transcript 与 Poseidon252 调用链
//! - [`cpu_transcript_binding_air`] — commitments、challenges、PoW、query 使用绑定
//! - [`merkle_semantic_air`] — compressed multi-query Merkle schedule/root binding
//! - [`merkle_leaf_air`] — STWO lifted Poseidon252 leaf packing
//! - [`fri_semantic_air`] — PCS quotient 与逐层 FRI fold
//! - [`oods_check_air`] — OODS（Out-Of-Domain Sampling）等式检查 AIR
//! - [`composition_eval_air`] — 固定 CPU composition 或应用 sampled-values binding
//! - [`recursion_prover`] — 聚合以上 AIR 的 Recursion Prover
//! - [`recursion_verifier`] — Recursion Verifier
//! - [`public_inputs`] — RecursivePublicInputs 公开输入定义
//!
//! `merkle_path_air`、`fri_verifier_air` 及其旧 trace generator 只保留用于历史回归，
//! 不得作为完整递归验证路径的 soundness 依据。
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

/// 独立密码学审计完成标志。
///
/// Active semantic AIR、host replay、完整回归和 application composition binding 已闭环；
/// 但内部测试通过不等于独立审计完成，因此默认构建仍保持 fail-closed。显式启用
/// `recursive-verifier` 表示调用方接受该实验性边界，而不是修改本标志。
pub(crate) const RECURSIVE_AIR_EXTERNAL_AUDIT_COMPLETE: bool = false;

pub(crate) mod composition_eval_air;
pub(crate) mod cpu_transcript_binding_air;
#[cfg(test)]
mod e2e_test;
pub(crate) mod fri_replay;
pub(crate) mod fri_semantic_air;
pub(crate) mod fri_verifier_air;
pub(crate) mod merkle_leaf_air;
pub(crate) mod merkle_path_air;
pub(crate) mod merkle_semantic_air;
pub(crate) mod oods_check_air;
pub(crate) mod poseidon252_air;
pub(crate) mod poseidon252_replay;
pub mod public_inputs;
pub mod recursion_prover;
pub mod recursion_verifier;
pub(crate) mod replay_witness;
pub(crate) mod stwo_replay;
pub mod trace_gen;
pub(crate) mod transcript_air;
pub(crate) mod verifier_program;

pub use public_inputs::{
    RecursivePublicInputs, RecursiveStatementOp, RecursiveStatementRecorder, RecursiveTreeMetadata,
    RecursiveVerifierProgram,
};
pub use recursion_verifier::verify_replicated_row_with_component;
pub use verifier_program::{
    VerifierProgramError, build_cpu_recursive_public_inputs,
    build_replicated_row_recursive_public_inputs,
};
