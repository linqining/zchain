//! # Stwo Backend — Circle STARK 证明后端（Phase 1.1 骨架）
//!
//! 严格遵循 `.trae/documents/hypernova_to_stwo_migration_plan.md`（v1 FROZEN）：
//! - **目标**：将 poker_zkvm 证明系统从 Hypernova（CCS + IPA on BN254）全量替换为
//!   Stwo（Circle STARK + AIR + FRI on M31），预期 ~1000× prove 加速
//! - **总工期**：14-20 周（3.5-5 个月），分 5 个 Phase
//! - **当前 Phase**：Phase 1.1（骨架搭建）
//!
//! ## 模块结构
//!
//! - [`field`] — BN254 Fr ↔ M31 域转换工具
//! - [`trace`] — poker_zkvm `Trace` → Stwo `TraceTable` 转换
//! - [`prover`] — `StwoProver`（替代 HypernovaProver）+ `StwoProverConfig`
//! - [`verifier`] — `StwoVerifier`（替代 Hypernova verifier）
//! - [`air`] — Stwo AIR 组件（CPU / Memory / ControlFlow / Syscall）
//!
//! ## 设计决策（来自迁移计划）
//!
//! 1. **proof 序列化格式**：`b"STWO"` magic 替代 `b"HYPN"`，保留 `public_io_commitment` 绑定
//! 2. **scheme_id 语义**：`SCHEME_HYPERNOVA = 1` 重命名为 `SCHEME_STWO`（数值不变，兼容已部署合约）
//! 3. **precompile 双接口**：纯算术 precompile 走 `build_air()`，椭圆曲线 precompile 保持 `build_ccs()` 独立证明
//! 4. **M31 field 转换**：32-bit 值用 2 limb M31 表示，9 limb × 32-bit 用于 254-bit 值
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供模块骨架与类型定义，AIR 组件实现留待 Phase 1.2-2.x。`StwoProver::prove()` 与
//! `StwoVerifier::verify()` 当前返回 [`ZkvmError::Other`]，待 Phase 1.3 POC 接入真实 Stwo prover。

pub mod air;
pub mod column_layout;
pub mod column_layout_v2;
pub mod field;
pub mod prover;
pub mod trace;
pub mod trace_native;
pub mod verifier;

// STWO magic 常量重导出，供 verifier.rs / poker_l1 集成使用
pub use prover::{
    deserialize_stwo_proof, serialize_stwo_proof, StwoProof, StwoProver, StwoProverConfig,
    STWO_MAGIC,
};
pub use verifier::{verify_stwo, StwoVerifier};