//! CycleFold 递归聚合（Phase 12 — Task 12.x 实现）。
//!
//! 将在 Phase 12 实现：
//! - BN254 / Grumpkin cycle（递归 verifier 电路）
//! - 超长计算分段聚合（proof > 64KB 触发再聚合）
//! - 递归终止条件（≤ 64KB 或 MAX_RECURSION_DEPTH = 16 层）
