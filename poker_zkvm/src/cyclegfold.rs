//! CycleFold SNARK 压缩扩展点（Phase 12 — Task 12.x 实现）。
//!
//! Phase 9 已在 [`crate::recursion`] 实现 CycleFold 树形聚合 + 递归 verifier 电路定义
//! （原生验证模拟）。本模块留作 Phase 12 Spartan / Groth16 最终压缩的扩展点：
//!
//! - 将 `recursion::aggregate` 输出的 final proof 通过 Spartan / Groth16 压缩到 ≤ 10KB
//! - 真实 R1CS / PLONKish 电路编译（替代 Phase 9 的原生验证模拟）
//! - 超长计算分段聚合（proof > 64KB 触发再聚合）
//! - 递归终止条件（≤ 64KB 或 [`crate::prover::MAX_RECURSION_DEPTH`] = 16 层）
