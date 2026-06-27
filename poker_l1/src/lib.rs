//! poker_l1 — Poker L1 区块链核心库
//!
//! 模块结构按 spec.md (FROZEN 2026-06-27) 组织：
//! - [`object_model`]：对象模型（Object / ObjectID / Ownership / ObjectStore + Sparse Merkle Tree）
//! - [`signature`]：多曲线钱包签名（tagged pubkey / secp256k1 / ed25519）
//! - [`account`]：账户抽象与交易安全
//! - [`transaction`]：交易结构
//! - [`block`]：区块结构
//! - [`consensus`]：DAG vertex 与 commit certificate
//! - [`storage`]：链存储（BlockStore / ObjectStore / DagVertexStore）
//! - [`vm`]：rBPF VM 与 syscalls（Phase 3）
//!
//! 其他阶段模块（crypto_precompiles / offline / network / bridge / governance / node）
//! 当前为 stub，待对应 Phase 实现。
//!
//! # 安全说明
//!
//! 全库 `deny(unsafe_code)`；唯一例外是 [`vm`] 模块（`allow(unsafe_code)`），
//! 因为 `solana_rbpf` 的 syscall 注册机制需要裸指针交互（`*mut EbpfVm<C>`）。
//! 所有 unsafe 操作封装在 `vm` 模块内，附安全不变式注释。

#![deny(unsafe_code)]
#![deny(rust_2021_compatibility)]
#![warn(missing_docs)]
#![warn(clippy::all, clippy::nursery)]

pub mod account;
pub mod block;
pub mod bridge;
pub mod consensus;
pub mod crypto_precompiles;
pub mod error;
pub mod governance;
pub mod network;
pub mod node;
pub mod object_model;
pub mod offline;
pub mod signature;
pub mod storage;
pub mod transaction;
pub mod vm;

/// 网络标识（chain_id）类型。spec 中 chain_id 用于跨链重放保护（M10 / SEC-L4）。
pub type ChainId = u64;

/// 区块高度类型。
pub type BlockHeight = u64;

/// 毫秒级时间戳。
pub type TimestampMs = u64;

/// 玩家地址（20 字节，由 blake2b_256(tagged_pubkey)[0..20] 派生）。
pub type Address = [u8; 20];

/// 32 字节哈希（blake2b_256 输出）。
pub type Hash = [u8; 32];

/// Genesis 默认 chain_id；testnet=0x70_6f_6b_31（"pok1"）。生产网络由 genesis 配置。
pub const DEFAULT_CHAIN_ID: ChainId = 0x706F_6B31;
