//! 链下执行 + ZK 证明验证模块（Phase 5a 实现）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **Task 21**：[`state`] — OfflineState commitment + checkout/checkin tx
//! - **Task 22**：[`zk_verifier`] — ZkVerifier trait + ZkVerifierRegistry 热插拔 + zk_verify syscall
//! - **Task 23**：[`hypernova`] — Hypernova Proof + public_io 边界（O15）+ verifier stub
//! - **Task 24**：[`groth16`] — Groth16Vk / Groth16Proof + CRS fingerprint（SEC-M10）+ verifier stub
//! - **Task 25**：[`ipa`] — IpaProof + verifier stub
//! - **Task 26**：[`ccs`] — CCS 电路 trait + Hypernova fold step + 多步折叠循环
//! - **NEW-M5**：[`ack_chain`] — RFC 6962 风格 ack_chain_hash Merkle 树
//!
//! ## 模块依赖关系
//!
//! ```text
//! ack_chain ──┐
//!             ├──► state ──┐
//! zk_verifier ┘            │
//!      ▲                    │
//!      ├── hypernova ──┐    │
//!      ├── groth16    ├──► ccs
//!      └── ipa        │
//!                       │
//!                       └──► （chain 模块后续 Phase 5b/5c 使用）
//! ```
//!
//! ## 安全说明
//!
//! - 全部模块 `deny(unsafe_code)`
//! - ZK verifier MVP 阶段均为 stub（`VerifierStatus::Stub`），仅校验 proof 格式合法性
//! - Production 升级须治理 90% quorum + `parameter_delay_blocks` timelock（NEW-C1）

pub mod ack_chain;
pub mod ccs;
pub mod groth16;
pub mod hypernova;
pub mod ipa;
pub mod state;
pub mod zk_verifier;

// 公共常量（Phase 5a 跨模块共享）
/// ack_chain Merkle 树域分离字节 — 叶子节点前缀（RFC 6962）。
pub const ACK_MERKLE_LEAF_PREFIX: u8 = 0x00;
/// ack_chain Merkle 树域分离字节 — 内部节点前缀（RFC 6962）。
pub const ACK_MERKLE_INTERNAL_PREFIX: u8 = 0x01;
/// ACK 签名域分离常量（NEW-H3 / SEC-C3）。
pub const ACK_DOMAIN_TAG: u8 = 0x02;
/// refuse_ack 签名域分离常量。
pub const REFUSE_ACK_DOMAIN_TAG: u8 = 0x03;
/// operator_ack 签名域分离常量（H5 修复）。
pub const OPERATOR_ACK_DOMAIN_TAG: u8 = 0x04;

/// Hypernova fold_step_count 上限（O15 修复）。
pub const MAX_FOLD_STEP_COUNT: u32 = 1000;
/// max_ack_chain_length 默认值（SEC2-M4）。
pub const DEFAULT_MAX_ACK_CHAIN_LENGTH: u32 = 1000;
/// max_ack_chain_length 下限（SEC2-M4）。
pub const MIN_MAX_ACK_CHAIN_LENGTH: u32 = 100;
/// max_ack_chain_length 上限（SEC2-M4）。
pub const MAX_MAX_ACK_CHAIN_LENGTH: u32 = 10_000;
/// max_partial_checkin_count 默认值（SEC-H1）。
pub const DEFAULT_MAX_PARTIAL_CHECKIN_COUNT: u32 = 3;
/// max_partial_checkin_count 下限（SEC-H1）。
pub const MIN_MAX_PARTIAL_CHECKIN_COUNT: u32 = 1;
/// max_partial_checkin_count 上限（SEC-H1）。
pub const MAX_MAX_PARTIAL_CHECKIN_COUNT: u32 = 10;
