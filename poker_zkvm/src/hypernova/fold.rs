//! Hypernova 折叠核心（Phase 7 — Task 7.x 实现）。
//!
//! 将在 Phase 7 实现：
//! - `Lcccs`（relaxed CCS instance，含 `v_L: Vec<FieldElement>`）
//! - `Ccccs`（不存储 v_C）
//! - `fold(lcccs, ccccs, r) -> FoldedInstance`（u' = u_L + r·u_C）
