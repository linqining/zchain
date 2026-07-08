//! Hypernova verifier（Phase 9 — Task 9.x 实现）。
//!
//! 将在 Phase 9 实现：
//! - 链上 verifier Production 实现（替换 poker_l1 stub 的 `Err(Other)` 分支）
//! - 三步反序列化（总长度优先校验防 OOM DoS）
//! - final sumcheck 等式校验 + cross-language claim 校验
//! - GAS_HYPERNOVA_VERIFY = 300000（v1.4 Min3-006 明细：~170-180k × 1.5）
