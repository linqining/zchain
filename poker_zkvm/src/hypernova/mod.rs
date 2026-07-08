//! Hypernova 折叠协议（Phase 7-9 — Task 7.x-9.x 实现）。
//!
//! 将在 Phase 7-9 实现（严格遵循 spec v1.4 最终数学定义）：
//! - `fold` — LCCCS + CCCCS 折叠（`u' = u_L + r·u_C`，`v'[j] = v_L[j] + r·v_C[j](r_x_L)`）
//! - `sumcheck` — 外层 sumcheck（claimed sum = u' 标量）+ 内层 batched sumcheck（单 r_y）
//! - `proof` — Proof 结构与序列化
//! - `verifier` — 链上 verifier（三步反序列化 + soundness 校验）
//!
//! 关键数学定义（v1.4）：
//! - CCCCS 不存储 v_C（多项式，折叠时在 r_x_L 求值）
//! - 外层 sumcheck G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} (v_L[j](X) + r·v_C[j](X))]
//! - cross-language claim：`Σ_j γ^j·v'[j] == (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`

pub mod fold;
pub mod proof;
pub mod sumcheck;
pub mod verifier;
