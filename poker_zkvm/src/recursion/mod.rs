//! Spartan / Groth16 最终压缩器（Phase 13 — Task 13.x 实现）。
//!
//! 将在 Phase 13 实现：
//! - Spartan 递归压缩（链上 verifier 仅验证 Spartan proof，~160k gas）
//! - IPA verify 链下化（~1000k gas 移到链下）
//! - 复用 `poker_l1/src/offline/groth16.rs` 既有 Groth16 verifier
