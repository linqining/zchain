//! Hypernova sumcheck（Phase 8 — Task 8.x 实现）。
//!
//! 将在 Phase 8 实现（spec v1.4）：
//! - 外层 sumcheck：claimed sum = u'（标量，非 v' 向量）
//! - G(X) = eq(X, r_x_L) · Σ_i [c_i · Π_{j∈S_i} (v_L[j](X) + r·v_C[j](X))]
//! - 内层 batched sumcheck：challenge γ → 单 r_y
//! - cross-language claim：`Σ_j γ^j·v'[j] == (Σ_j γ^j·M_j(r_x_L, r_y))·z'(r_y)`
