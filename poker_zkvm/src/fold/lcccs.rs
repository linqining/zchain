//! LCCCS（Linearized CCCS）实例（Phase 6 — Task 6.2）。
//!
//! 严格遵循 spec.md L350-357（v1.4 FROZEN）与 Hypernova 原论文。
//!
//! ## 数据结构
//!
//! ```text
//! Lcccs {
//!     ccs_ref: Ccs,                  // CCS 结构引用（克隆）
//!     u_l: Fr,                       // relaxed 标量（可非 0；下标 L 表示 Linearized）
//!     x_l: Vec<Fr>,                  // 公共输入
//!     trace_l: Vec<Fr>,              // witness 向量 z_L
//!     r_x_l: Vec<Fr>,                // 外层 sumcheck challenge（长度 = log2(num_rows)）
//!     v_l: Vec<Fr>,                  // 长度 = num_matrices，v_L[j] = Σ_y M_j(r_x_L, y)·z_L(y)
//! }
//! ```
//!
//! ## relaxed 约束（v1.3 修正 M2-001）
//!
//! `Σ_i c_i · Π_{j∈S_i} v_l[j] = u_l`（u_l 可非 0；非原始 CCS 的 = 0）
//!
//! ## 实现决策
//!
//! - **r_x_l 类型**：spec 标注为 `FieldElement`（单标量），但外层 sumcheck 实际产生
//!   `log2(num_rows)` 个 challenge（每轮一个）。本实现使用 `Vec<Fr>` 以匹配数学现实，
//!   spec 的单 FieldElement 是简化标注（见 alternatives.md）。
//! - **命名**：使用 snake_case（`u_l` / `v_l` / `r_x_l`）匹配 Rust 约定，
//!   数学公式中对应 `u_L` / `v_L` / `r_x_L`（下标 L 表示 Linearized）。

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;

/// LCCCS（Linearized CCCS）实例 — relaxed CCS 实例（spec L350-357）。
///
/// v_l 在 r_x_l 处求值为标量向量，relaxed 约束允许 u_l 非 0。
#[derive(Debug, Clone)]
pub struct Lcccs {
    /// CCS 结构（克隆，含矩阵 M_j / 子集 S_i / 系数 c_i）。
    pub ccs_ref: Ccs,
    /// relaxed 标量参数（可非 0；初始 CCS 实例 u_l = 0）。数学符号 `u_L`。
    pub u_l: Fr,
    /// 公共输入向量。数学符号 `x_L`。
    pub x_l: Vec<Fr>,
    /// witness 向量 z_L（长度 = ccs_ref.num_vars）。
    pub trace_l: Vec<Fr>,
    /// 外层 sumcheck challenge（长度 = log2(num_rows)）。数学符号 `r_x_L`。
    pub r_x_l: Vec<Fr>,
    /// 每矩阵在 r_x_l 处的求值（长度 = num_matrices）。数学符号 `v_L`。
    /// `v_l[j] = Σ_y M_j(r_x_l, y) · z_L(y) = Σ_r eq(r_x_l, r) · (M_j · z_L)[r]`
    pub v_l: Vec<Fr>,
}

impl Lcccs {
    /// 创建 LCCCS 实例并校验字段维度。
    ///
    /// # 参数
    /// - `ccs_ref` — CCS 结构
    /// - `u_l` — relaxed 标量（数学符号 `u_L`）
    /// - `x_l` — 公共输入
    /// - `trace_l` — witness 向量 z_L
    /// - `r_x_l` — 外层 sumcheck challenge
    /// - `v_l` — 每矩阵在 r_x_l 处的求值
    ///
    /// # 错误
    /// - `trace_l.len() != ccs_ref.num_vars`
    /// - `v_l.len() != ccs_ref.num_matrices()`
    /// - `r_x_l.len() != log2(num_rows)`（当 num_rows 是 2 的幂时）
    pub fn new(
        ccs_ref: Ccs,
        u_l: Fr,
        x_l: Vec<Fr>,
        trace_l: Vec<Fr>,
        r_x_l: Vec<Fr>,
        v_l: Vec<Fr>,
    ) -> Result<Self, ZkvmError> {
        if trace_l.len() != ccs_ref.num_vars {
            return Err(ZkvmError::Other(format!(
                "Lcccs::new: trace_l.len() {} != ccs_ref.num_vars {}",
                trace_l.len(),
                ccs_ref.num_vars
            )));
        }
        if v_l.len() != ccs_ref.num_matrices() {
            return Err(ZkvmError::Other(format!(
                "Lcccs::new: v_l.len() {} != ccs_ref.num_matrices() {}",
                v_l.len(),
                ccs_ref.num_matrices()
            )));
        }
        let num_rows = ccs_ref.num_rows();
        if num_rows > 0 && num_rows.is_power_of_two() {
            let expected_r_x_len = num_rows.trailing_zeros() as usize;
            if r_x_l.len() != expected_r_x_len {
                return Err(ZkvmError::Other(format!(
                    "Lcccs::new: r_x_l.len() {} != log2(num_rows) = {}",
                    r_x_l.len(),
                    expected_r_x_len
                )));
            }
        }
        Ok(Self {
            ccs_ref,
            u_l,
            x_l,
            trace_l,
            r_x_l,
            v_l,
        })
    }

    /// 校验 relaxed 约束（v1.3 修正 M2-001）。
    ///
    /// `Σ_i c_i · Π_{j∈S_i} v_l[j] = u_l`（u_l 可非 0）
    ///
    /// 注意：此校验仅检查 v_l 与 u_l 的一致性，不重新计算 v_l（v_l 已在创建时计算并存储）。
    /// 重新计算 v_l 需 witness z_L 与 r_x_l，由 [`crate::fold::ccs::CcsHypernovaExt::recompute_v`]
    /// 提供（用于 soundness 校验）。
    pub fn satisfied(&self) -> Result<bool, ZkvmError> {
        let computed_u = compute_relaxed_constraint(&self.ccs_ref, &self.v_l);
        Ok(computed_u == self.u_l)
    }
}

/// 计算 relaxed 约束 `Σ_i c_i · Π_{j∈S_i} v[j]`（共享工具函数）。
///
/// 给定向量 `v`（长度 = num_matrices），返回标量结果。
/// 若结果 = u_l 则 LCCCS satisfied；若结果 = u_c 则 CCCCS satisfied（在 x_c 处）。
pub fn compute_relaxed_constraint(ccs: &Ccs, v: &[Fr]) -> Fr {
    let mut sum = Fr::zero();
    for (i, s) in ccs.subsets.iter().enumerate() {
        let mut prod = Fr::one();
        for &j in s {
            prod = prod.mul(&v[j]);
        }
        let term = ccs.coeffs[i].mul(&prod);
        sum = sum.add(&term);
    }
    sum
}

/// 计算 `eq(x, r) = Π_i (x_i · r_i + (1-x_i)·(1-r_i))`（多线性基函数）。
///
/// - `x` — challenge 向量（长度 = m = log2(num_rows)）
/// - `r` — 行索引（boolean 向量，r 的二进制表示）
///
/// 对于 `r` 的第 i 位 `b_i`：
/// - 若 `b_i = 1`：`eq(x_i, 1) = x_i`
/// - 若 `b_i = 0`：`eq(x_i, 0) = 1 - x_i`
pub fn eq_eval(x: &[Fr], r: usize) -> Result<Fr, ZkvmError> {
    let mut result = Fr::one();
    let mut r_bits = r;
    for &x_i in x {
        let bit = (r_bits & 1) == 1;
        r_bits >>= 1;
        let term = if bit {
            x_i
        } else {
            Fr::one().sub(&x_i)
        };
        result = result.mul(&term);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 构造乘法约束 CCS — x * y = z（1 row, 4 vars, 3 matrices）。
    /// z = [1, x, y, z_val]
    /// M_0 = [[0,1,0,0]] → M_0·z = x
    /// M_1 = [[0,0,1,0]] → M_1·z = y
    /// M_2 = [[0,0,0,1]] → M_2·z = z_val
    /// S_0 = {0,1}, c_0 = 1   → x * y
    /// S_1 = {2},    c_1 = -1 → -z_val
    /// 约束：x*y - z_val = 0
    fn make_mul_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();

        Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0, 1], vec![2]],
            vec![f(1), neg_f(1)],
        )
        .expect("Ccs 构造应成功")
    }

    // ===== eq_eval 测试 =====

    #[test]
    fn test_eq_eval_single_var_at_0() {
        // eq(x, 0) = 1 - x
        // x = 5: eq(5, 0) = 1 - 5 = -4
        let x = vec![f(5)];
        let result = eq_eval(&x, 0).expect("eq_eval 应成功");
        assert_eq!(result, Fr::one().sub(&f(5)));
    }

    #[test]
    fn test_eq_eval_single_var_at_1() {
        // eq(x, 1) = x
        // x = 5: eq(5, 1) = 5
        let x = vec![f(5)];
        let result = eq_eval(&x, 1).expect("eq_eval 应成功");
        assert_eq!(result, f(5));
    }

    #[test]
    fn test_eq_eval_two_vars() {
        // eq((x0, x1), r) for r ∈ {0,1,2,3}
        // r 的第 i 位是 (r >> i) & 1
        // r=0: bit0=0, bit1=0 → (1-x0)(1-x1)
        // r=1: bit0=1, bit1=0 → x0 * (1-x1)
        // r=2: bit0=0, bit1=1 → (1-x0) * x1
        // r=3: bit0=1, bit1=1 → x0 * x1
        let x = vec![f(3), f(7)];
        // r=0: (1-3)(1-7) = (-2)(-6) = 12
        assert_eq!(eq_eval(&x, 0).unwrap(), f(12));
        // r=1: 3 * (1-7) = 3 * (-6) = -18
        assert_eq!(eq_eval(&x, 1).unwrap(), neg_f(18));
        // r=2: (1-3) * 7 = (-2) * 7 = -14
        assert_eq!(eq_eval(&x, 2).unwrap(), neg_f(14));
        // r=3: 3 * 7 = 21
        assert_eq!(eq_eval(&x, 3).unwrap(), f(21));
    }

    #[test]
    fn test_eq_eval_boolean_point() {
        // 当 x 是 boolean（0 或 1）时，eq(x, r) 是 indicator function
        // eq((1, 0), r=1) = 1（因 r=1 的 bits 是 01，匹配 x=(1,0)）
        // eq((1, 0), r=0) = 0
        // eq((1, 0), r=2) = 0
        // eq((1, 0), r=3) = 0
        let x = vec![f(1), f(0)];
        assert_eq!(eq_eval(&x, 1).unwrap(), f(1));
        assert_eq!(eq_eval(&x, 0).unwrap(), f(0));
        assert_eq!(eq_eval(&x, 2).unwrap(), f(0));
        assert_eq!(eq_eval(&x, 3).unwrap(), f(0));
    }

    // ===== compute_relaxed_constraint 测试 =====

    #[test]
    fn test_compute_relaxed_constraint_zero() {
        // 对于 satisfied CCS（z=valid）, v = [x, y, z_val]，约束 x*y - z_val = 0
        let ccs = make_mul_ccs();
        // x=3, y=4, z_val=12 → v = [3, 4, 12]
        let v = vec![f(3), f(4), f(12)];
        let result = compute_relaxed_constraint(&ccs, &v);
        // S_0={0,1}, c_0=1 → 1 * 3 * 4 = 12
        // S_1={2}, c_1=-1 → -1 * 12 = -12
        // sum = 12 + (-12) = 0
        assert_eq!(result, Fr::zero());
    }

    #[test]
    fn test_compute_relaxed_constraint_nonzero() {
        // 篡改 v 使约束不满足
        let ccs = make_mul_ccs();
        // x=3, y=4, z_val=13 → v = [3, 4, 13], 约束 = 12 - 13 = -1
        let v = vec![f(3), f(4), f(13)];
        let result = compute_relaxed_constraint(&ccs, &v);
        assert_eq!(result, neg_f(1));
    }

    // ===== Lcccs::new 测试 =====

    #[test]
    fn test_lcccs_new_valid() {
        let ccs = make_mul_ccs();
        // num_rows = 1, log2(1) = 0, r_x_l 应为空 vec
        let v_l = vec![f(3), f(4), f(12)];
        let lcccs = Lcccs::new(
            ccs.clone(),
            Fr::zero(), // u_l = 0
            vec![],     // x_l
            vec![f(1), f(3), f(4), f(12)], // trace_l = z
            vec![],     // r_x_l (num_rows=1, log2=0)
            v_l,
        )
        .expect("Lcccs 构造应成功");
        assert_eq!(lcccs.u_l, Fr::zero());
        assert_eq!(lcccs.v_l.len(), 3);
    }

    #[test]
    fn test_lcccs_new_wrong_trace_length() {
        let ccs = make_mul_ccs();
        let result = Lcccs::new(
            ccs,
            Fr::zero(),
            vec![],
            vec![f(1), f(2), f(3)], // 长度 3 != num_vars 4
            vec![],
            vec![f(1), f(2), f(3)],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_lcccs_new_wrong_v_length() {
        let ccs = make_mul_ccs();
        let result = Lcccs::new(
            ccs,
            Fr::zero(),
            vec![],
            vec![f(1), f(3), f(4), f(12)],
            vec![],
            vec![f(1), f(2)], // 长度 2 != num_matrices 3
        );
        assert!(result.is_err());
    }

    // ===== Lcccs::satisfied 测试 =====

    #[test]
    fn test_lcccs_satisfied_u_zero() {
        // u_l = 0, v_l 满足约束（satisfied CCS）
        let ccs = make_mul_ccs();
        let v_l = vec![f(3), f(4), f(12)]; // x*y - z = 12 - 12 = 0
        let lcccs = Lcccs::new(
            ccs,
            Fr::zero(), // u_l = 0
            vec![],
            vec![f(1), f(3), f(4), f(12)],
            vec![],
            v_l,
        )
        .unwrap();
        assert!(lcccs.satisfied().unwrap());
    }

    #[test]
    fn test_lcccs_satisfied_u_nonzero() {
        // u_l ≠ 0, v_l 对应 u_l（relaxed 形式）
        let ccs = make_mul_ccs();
        // x=3, y=4, z_val=13 → 约束 = 12 - 13 = -1
        let v_l = vec![f(3), f(4), f(13)];
        let lcccs = Lcccs::new(
            ccs,
            neg_f(1), // u_l = -1
            vec![],
            vec![f(1), f(3), f(4), f(13)],
            vec![],
            v_l,
        )
        .unwrap();
        assert!(lcccs.satisfied().unwrap());
    }

    #[test]
    fn test_lcccs_not_satisfied_u_mismatch() {
        // u_l 与 v_l 不一致
        let ccs = make_mul_ccs();
        let v_l = vec![f(3), f(4), f(12)]; // 约束 = 0
        let lcccs = Lcccs::new(
            ccs,
            f(99), // u_l = 99 ≠ 0
            vec![],
            vec![f(1), f(3), f(4), f(12)],
            vec![],
            v_l,
        )
        .unwrap();
        assert!(!lcccs.satisfied().unwrap());
    }

    #[test]
    fn test_lcccs_not_satisfied_tampered_v() {
        // 篡改 v_l 使约束不匹配 u_l
        let ccs = make_mul_ccs();
        let v_l = vec![f(3), f(4), f(99)]; // 约束 = 12 - 99 = -87
        let lcccs = Lcccs::new(
            ccs,
            Fr::zero(), // u_l = 0 ≠ -87
            vec![],
            vec![f(1), f(3), f(4), f(12)],
            vec![],
            v_l,
        )
        .unwrap();
        assert!(!lcccs.satisfied().unwrap());
    }
}
