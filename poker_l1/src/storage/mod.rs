//! 链存储（Task 4 — Phase 1 实现）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）的 Phase 1 范围，提供三大持久化存储：
//!
//! - [`BlockStore`]（SubTask 4.1）：按 `block_hash` / `height` 双向索引的区块存储，
//!   支持 tip 跟踪；WriteBatch 保证 block + height 索引原子写入。
//! - [`ObjectDb`]（SubTask 4.2 + 4.4）：持久化对象存储 + 内存 Sparse Merkle Tree，
//!   支持全局状态根计算（所有 live 对象的 Sparse Merkle Root）与 Merkle 包含 / 非包含证明。
//! - [`DagVertexStore`]（SubTask 4.3）：DAG vertex 持久化存储，按 `vertex_hash` /
//!   `(epoch, round)` / `author_pubkey` 三维索引。
//!
//! 通用约束：
//! - 后端：RocksDB（CF 分离不同索引）
//! - 序列化：BCS（`bcs::to_bytes` / `bcs::from_bytes`）
//! - key 编码：u64 用 little-endian 8 字节
//! - DB 句柄通过 `Arc<DB>` 共享，可被多线程并发访问
//! - 错误转换：`rocksdb::Error` → `PokerL1Error::Rocksdb`，BCS 错误 → `PokerL1Error::Serialization`

pub mod block_store;
pub mod dag_vertex_store;
pub mod object_db;

pub use block_store::BlockStore;
pub use dag_vertex_store::DagVertexStore;
pub use object_db::ObjectDb;
