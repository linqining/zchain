//! # poker_zkvm — Hypernova + CCS 零知识虚拟机
//!
//! 严格遵循 `build-hypernova-zkvm` spec v1.4（FROZEN）：
//! - **Layer 0 (Phase 0-1)**：[`error`] / [`field`] / [`transcript`] — 基础类型与 Fiat-Shamir
//! - **Layer 1 (Phase 1.5)**：[`pcs`] — IPA over BN254（NUMS generators）
//! - **Layer 2 (Phase 2-4)**：[`compiler`] / [`isa`] / [`trace`] / [`syscalls`] — 前端 + 执行
//! - **Layer 3 (Phase 5-6)**：[`ccs`] / [`lookup`] / [`constraints`] — 约束系统
//! - **Layer 3.5 (Phase 6)**：[`fold`] — Hypernova 折叠算法（LCCCS + CCCCS + fold_step + sumcheck + fold_loop）
//! - **Layer 4 (Phase 7-9)**：[`hypernova`] — 折叠 + sumcheck + proof + verifier
//! - **Layer 5 (Phase 10-11)**：[`prover`] / [`verifier`] — 端到端证明与验证
//! - **Layer 6 (Phase 12-13)**：[`cyclegfold`] / [`recursion`] — 递归聚合与压缩
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

// ===== Layer 0 — Foundation（Phase 0-1）=====
pub mod error;
pub mod field;
pub mod transcript;

// ===== Layer 1 — Crypto Primitives（Phase 1.5）=====
pub mod pcs;

// ===== Layer 2 — Frontend & Execution（Phase 2-4）=====
pub mod compiler;
pub mod isa;
pub mod syscalls;
pub mod trace;

// ===== Layer 3 — Constraint System（Phase 5-6）=====
pub mod ccs;
pub mod constraints;
pub mod lookup;

// ===== Layer 3.5 — Hypernova Fold（Phase 6）=====
pub mod fold;

// ===== Layer 4 — Hypernova Protocol（Phase 7-9）=====
pub mod cyclic;
pub mod hypernova;

// ===== Layer 5 — Precompile Circuits & Prover/Verifier（Phase 10-11）=====
pub mod precompiles;
pub mod prover;
pub mod verifier;

// ===== Stwo 迁移后端（Phase 1.5 POC 已完成）=====
// 详见 .trae/documents/hypernova_to_stwo_migration_plan.md
// 全量替换 Hypernova + CCS + IPA → Stwo Circle STARK + AIR + FRI on M31
// Phase 5 完成后将替代 Layer 1/3/3.5/4/6 的 Hypernova 相关模块
//
// ## Phase 1.5 POC 状态（决策门报告见 stwo_poc_decision_report.md）
//
// - ✅ Stwo prove 端到端流程跑通（CpuAirEval 实现 FrameworkEval，47 列 mask 全注册）
// - ✅ 序列化/反序列化往返一致（bincode + StwoProof 封装）
// - ✅ proof 大小合理（1024 步 8.3KB / 1M 步 21.2KB，远小于 64KB 限制）
// - ⚠️ 性能决策门未达标：1M 步 62014ms vs 目标 ≤86.7ms（仅 0.1x vs Hypernova 8670ms 基准）
//   后续优化方向：减少 trace 列数（47→精简）、启用 parallel feature、GPU backend
pub mod stwo_backend;

// ===== 跨 VM 共享 — CryptoProvider 实现（Phase 3）=====
pub mod crypto_arkworks;

// ===== Layer 6 — Recursion & Compression（Phase 12-13）=====
pub mod cyclegfold;
pub mod recursion;

// ===== 测试辅助（test-helpers feature 门控）=====
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

// ===== Phase 3: zkvm 服务化（service feature 门控）=====
#[cfg(feature = "service")]
pub mod service;
