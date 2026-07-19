//! # poker_zkvm — Stwo Circle STARK 零知识虚拟机（v2）
//!
//! 基于 Stwo（Circle STARK + AIR + FRI on M31）的 RISC-V zkVM。
//! 完全放弃 Hypernova 兼容，trace 原生在 M31 中生成（4×8-bit limb）。
//!
//! 严格遵循 `.trae/documents/hypernova_to_stwo_migration_plan_v2.md`（v2 FROZEN）。
//!
//! ## 模块层次（v2）
//!
//! - **Layer 0**：[`error`] — 基础错误类型
//! - **Layer 1**：[`compiler`] / [`isa`] / [`trace`] / [`syscalls`] — 前端 + 执行
//! - **Layer 2**：[`stwo_backend`] — Stwo 证明后端（原生 M31 trace + AIR + FRI）
//!
//! ## v2 迁移状态（Phase 1 进行中）
//!
//! - ✅ Phase 1 Step 1.6/1.7/1.8：原生 M31 trace 生成（`column_layout_v2` + `trace_native`）
//! - ✅ Phase 1 Step 1.2：删除 ~7,761 行 Hypernova 代码（ccs/hypernova/fold/recursion/pcs/ipa 等）
//! - ⬜ Phase 2：CPU AIR 重写（基于 Stwo `FrameworkEval`）
//! - ⬜ Phase 3：内存 & Syscall AIR
//! - ⬜ Phase 4：Precompile 迁移到 AIR
//! - ⬜ Phase 5：递归证明层（自建 Stwo Verifier AIR）
//! - ⬜ Phase 6：E2E + 性能基准
//!
//! ## 已删除的 v1 模块（Phase 1 清理）
//!
//! 以下 v1 模块已在 Phase 1 删除（完全放弃 Hypernova 兼容）：
//! - `ccs` / `hypernova` / `fold` / `recursion` / `cyclic` / `cyclegfold` — Hypernova 折叠算法
//! - `pcs` — IPA PCS over BN254（Stwo 用 FRI PCS）
//! - `transcript` — 旧 Fiat-Shamir transcript（Stwo 用 Blake2sChannel）
//! - `lookup` / `constraints` — 旧 CCS 约束系统（Stwo 用 AIR 约束）
//! - `prover` / `verifier` — 旧 Hypernova prover/verifier
//! - `crypto_arkworks` — arkworks BN254 绑定
//! - `field` — BN254 Fr 域元素抽象（v2 用原生 M31）
//! - `precompiles` — Phase 4 用 AIR 重写
//! - `service` / `bin` — Phase 6 重写
//!
//! ## 安全约定
//!
//! - 全 crate `#![deny(unsafe_code)]`
//! - 全 crate `#![deny(missing_docs)]`
//! - 所有变长字段反序列化使用 `checked_add` / `checked_mul` 防 32-bit wrap
//! - 所有外部输入（ELF / proof / public_io）须经过校验后才使用

#![deny(unsafe_code)]
#![deny(missing_docs)]

// alloc crate 在 std 环境下需显式声明，供 prelude 模块 re-export
extern crate alloc;

// ===== Layer 0 — Foundation =====
pub mod error;

// ===== Layer 1 — Frontend & Execution =====
pub mod compiler;
pub mod isa;
pub mod syscalls;
pub mod trace;

// ===== Layer 2 — Stwo Backend（v2 原生 M31 trace）=====
pub mod stwo_backend;

// ===== 测试辅助（test-helpers feature 门控）=====
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;
