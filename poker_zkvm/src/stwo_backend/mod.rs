//! # Stwo Backend — Circle STARK 证明后端（v2 Phase 1）
//!
//! 严格遵循 `.trae/documents/hypernova_to_stwo_migration_plan_v2.md`（v2 FROZEN）+
//! `.trae/documents/stwo_phase1_native_trace_design.md`：
//! - **目标**：将 poker_zkvm 证明系统完全切换到 Stwo（Circle STARK + AIR + FRI on M31）
//! - **核心变更**：原生 M31 trace 生成（4×8-bit limb），无 BN254 Fr 域转换
//! - **参考实现**：Nexus zkVM 0.3.6 `prover/src/trace/trace_builder.rs`
//!
//! ## 模块结构
//!
//! - [`column_layout_v2`] — 97 列布局（4×8-bit limb，参考 Nexus zkVM 0.3.6）
//! - [`trace_native`] — 原生 M31 trace 生成（NativeTrace + TraceBuilder）
//! - [`cpu_air`] — CPU AIR（Stwo `FrameworkEval`，ADD/ADDI/SUB 约束）
//! - [`prover`] — Stwo Prover/Verifier 集成（`prove_cpu_trace` + `verify_cpu_proof`）
//!
//! ## 后续阶段（v2 计划）
//!
//! - **Phase 2**：CPU AIR 重写（`cpu_air.rs` + `prover.rs`）✅ ADD/ADDI/SUB + Prover 骨架
//! - **Phase 3**：内存 & Syscall AIR
//! - **Phase 4**：Precompile 迁移到 AIR
//! - **Phase 5**：递归证明层（自建 Stwo Verifier AIR）
//! - **Phase 6**：E2E + 性能基准
//!
//! ## v1 文件已删除（Phase 1 清理）
//!
//! 以下 v1 文件已在 Phase 1 删除（依赖 `crate::ccs`/`crate::constraints`/`crate::field`）：
//! - `field.rs`（域转换工具 `fr_to_m31_single`，已被原生 M31 取代）
//! - `column_layout.rs`（旧 2×30-bit limb 布局，已被 `column_layout_v2.rs` 取代）
//! - `trace.rs`（旧 trace 转换，已被 `trace_native.rs` 取代）
//! - `verifier.rs`（旧 Stwo POC，Phase 5 重写）
//! - `air/`（整个目录，Phase 2 用 Stwo 原生 FrameworkEval 重写）
//!
//! 注：`prover.rs` 已在 Phase 2.5 重写为 Stwo 原生 Prover 集成。

pub mod column_layout_v2;
pub mod cpu_air;
pub mod lookups;
pub mod memory_air;
pub mod poseidon_air;
#[allow(missing_docs)] // SmallFpConfig derive 宏生成的 associated functions 无需文档
pub mod poseidon_m31;
pub mod prover;
pub mod range_check_air;
pub mod recursive;
pub mod sha256_air;
pub mod trace_native;
