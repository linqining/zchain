//! Hypernova 折叠算法（Phase 6 — Task 6.x 实现）。
//!
//! 严格遵循 spec.md L346-419（v1.4 FROZEN）与 Hypernova 原论文（eprint 2023/573）。
//!
//! ## 模块结构
//!
//! - [`ccs`] — CCS 扩展方法（`to_lcccs` / `to_cccs` / `ccs_commitment` / 矩阵多线性多项式表示）
//! - [`lcccs`] — LCCCS 实例（relaxed 约束 `Σ c_i · Π v_L[j] = u_L`，u_L 可非 0）
//! - [`ccccs`] — CCCCS 实例（v1.3 修正 C2-002 — 不存储 v_C 字段）
//! - [`fold_step`] — 单步折叠（`u' = u_L + r·u_C` / `v'[j] = v_L[j] + r·v_C[j](r_x_L)`）
//! - [`sumcheck`] — 外层 sumcheck（claimed sum = u' 标量）+ 内层 batched sumcheck（单 r_y）
//! - [`fold_loop`] — 多步折叠循环 + PCS opening 在 r_y 处打开 z'
//!
//! ## v1.3 关键修正（对照原论文）
//!
//! - **C2-001**：内层 batched sumcheck 产生单个 `r_y`（非 t+1 维元组）
//! - **C2-002**：CCCCS 实例不存储 `v_C` 字段（v_C[j] 是多项式，折叠时在 r_x_L 求值）
//! - **C2-003**：外层 sumcheck claimed sum = `u'` 标量（非 v' 向量，非 0）
//! - **M2-001**：LCCCS relaxed 约束 `Σ c_i · Π v'[j] = u'`（u' 可非 0）
//!
//! ## 折叠核心等式
//!
//! ```text
//! u'      = u_L + r · u_C                                  (标量)
//! x'      = x_L + r · x_C                                  (向量)
//! trace'  = trace_L + r · trace_C                          (向量)
//! r_x'    = r_x_L                                          (沿用 LCCCS_L)
//! v'[j]   = v_L[j] + r · v_C[j](r_x_L)                    (分量级)
//! z'      = z_L + r · z_C                                  (folded witness)
//! ```
//!
//! 其中 `v_C[j](r_x_L) = Σ_y M_j(r_x_L, y) · z_C(y)` 通过内层 batched sumcheck 计算并验证。

pub mod ccccs;
pub mod ccs;
pub mod fold_loop;
pub mod fold_step;
pub mod lcccs;
pub mod sumcheck;
