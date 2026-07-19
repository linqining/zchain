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
