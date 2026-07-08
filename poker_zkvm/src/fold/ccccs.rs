//! CCCCS（Committed CCCS）实例（Phase 6 — Task 6.3）。
//!
//! 严格遵循 spec.md L359-364（v1.4 FROZEN）与 Hypernova 原论文。
//!
//! ## 数据结构（v1.3 修正 C2-002 — 不存储 v_C 字段）
//!
//! ```text
//! Ccccs {
//!     ccs_ref: Ccs,                          // CCS 结构引用（克隆）
//!     u_c: Fr,                               // relaxed 标量（可非 0）
//!     x_c: Vec<Fr>,                          // 公共求值点（长度 = log2(num_rows)）
//!     trace_c: Vec<Fr>,                      // witness 向量 z_C
//!     witness_commitment_c: IpaCommitment,   // witness 多项式承诺
//! }
//! ```
//!
//! ## v1.3 关键修正 C2-002 — 不存储 v_C
//!
//! `v_C[j](X) = Σ_y M_j(X, y) · z_C(y)` 是关于 X 的多项式（非标量）。
//! 在 CCCCS 创建时 `r_x_L`（来自配对的 LCCCS）尚不存在，因此无法预计算 v_C。
//! v_C[j] 在折叠时于 `r_x_L` 处求值，通过内层 batched sumcheck 计算并验证。
//!
//! ## satisfied 校验
//!
//! `Σ_i c_i · Π_{j∈S_i} (Σ_y M_j(x_c, y) · z_C(y)) = u_c`
//!
//! 此校验在 `x_c` 处求值（不同于 LCCCS 在 `r_x_l` 处求值），u_c 可非 0。
//! 对于 satisfied CCS 实例，u_c = 0 在任意 `x_c` 处成立。

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::lcccs::{compute_relaxed_constraint, eq_eval};
use crate::pcs::ipa::IpaCommitment;

/// CCCCS（Committed CCCS）实例 — 不存储 v_C 字段（v1.3 修正 C2-002）。
///
/// witness 多项式承诺绑定 z_C，防 prover 在 challenge 派生后替换 witness。
#[derive(Debug, Clone)]
pub struct Ccccs {
    /// CCS 结构（克隆，含矩阵 M_j / 子集 S_i / 系数 c_i）。
    pub ccs_ref: Ccs,
    /// relaxed 标量参数（可非 0；初始 CCS 实例 u_c = 0）。数学符号 `u_C`。
    pub u_c: Fr,
    /// 公共求值点（长度 = log2(num_rows)）。数学符号 `x_C`。
    pub x_c: Vec<Fr>,
    /// witness 向量 z_C（长度 = ccs_ref.num_vars）。
    pub trace_c: Vec<Fr>,
    /// witness 多项式承诺（IPA G1 仿射点）。
    pub witness_commitment_c: IpaCommitment,
}

impl Ccccs {
    /// 创建 CCCCS 实例并校验字段维度。
    ///
    /// # 参数
    /// - `ccs_ref` — CCS 结构
    /// - `u_c` — relaxed 标量（数学符号 `u_C`）
    /// - `x_c` — 公共求值点
    /// - `trace_c` — witness 向量 z_C
    /// - `witness_commitment_c` — witness 多项式承诺
    ///
    /// # 错误
    /// - `trace_c.len() != ccs_ref.num_vars`
    /// - `x_c.len() != log2(num_rows)`（当 num_rows 是 2 的幂时）
    pub fn new(
        ccs_ref: Ccs,
        u_c: Fr,
        x_c: Vec<Fr>,
        trace_c: Vec<Fr>,
        witness_commitment_c: IpaCommitment,
    ) -> Result<Self, ZkvmError> {
        if trace_c.len() != ccs_ref.num_vars {
            return Err(ZkvmError::Other(format!(
                "Ccccs::new: trace_c.len() {} != ccs_ref.num_vars {}",
                trace_c.len(),
                ccs_ref.num_vars
            )));
        }
        let num_rows = ccs_ref.num_rows();
        if num_rows > 0 && num_rows.is_power_of_two() {
            let expected_x_len = num_rows.trailing_zeros() as usize;
            if x_c.len() != expected_x_len {
                return Err(ZkvmError::Other(format!(
                    "Ccccs::new: x_c.len() {} != log2(num_rows) = {}",
                    x_c.len(),
                    expected_x_len
                )));
            }
        }
        Ok(Self {
            ccs_ref,
            u_c,
            x_c,
            trace_c,
            witness_commitment_c,
        })
    }

    /// 校验 CCCCS 满足性（spec L364）。
    ///
    /// `Σ_i c_i · Π_{j∈S_i} (Σ_y M_j(x_c, y) · z_C(y)) = u_c`
    ///
    /// 内部计算 `v_c[j] at x_c = Σ_r eq(x_c, r) · (M_j · z_C)[r]`，然后检查
    /// relaxed 约束 `Σ_i c_i · Π v_c[j] = u_c`。
    ///
    /// 注意：此校验重新计算 v_c（在 x_c 处），不同于 LCCCS 直接存储 v_l。
    /// 这体现了 v_C 是多项式（非标量）的语义。
    pub fn satisfied(&self) -> Result<bool, ZkvmError> {
        let v_c = self.compute_v_at_x_c()?;
        let computed_u = compute_relaxed_constraint(&self.ccs_ref, &v_c);
        Ok(computed_u == self.u_c)
    }

    /// 计算 `v_c[j] at x_c = Σ_r eq(x_c, r) · (M_j · z_C)[r]`（spec L364 内层求和）。
    ///
    /// 对每个矩阵 `j ∈ [0, num_matrices)`：
    /// 1. 计算 `M_j · z_C`（矩阵-向量乘积，长度 = num_rows）
    /// 2. 加权求和：`v_c[j] = Σ_r eq(x_c, r) · (M_j · z_C)[r]`
    ///
    /// 这是 v_C 多项式在 `x_c` 处的求值（标量）。
    pub fn compute_v_at_x_c(&self) -> Result<Vec<Fr>, ZkvmError> {
        (0..self.ccs_ref.matrices.len())
            .map(|j| self.compute_vj_at_x_c(j))
            .collect()
    }

    /// 计算单个 `v_c[j] at x_c`。
    fn compute_vj_at_x_c(&self, j: usize) -> Result<Fr, ZkvmError> {
        let mz = self.ccs_ref.matrices[j].evaluate(&self.trace_c)?;
        let mut v = Fr::zero();
        for (r, &mz_r) in mz.iter().enumerate() {
            let eq_weight = eq_eval(&self.x_c, r)?;
            v = v.add(&eq_weight.mul(&mz_r));
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
    use crate::pcs::ipa::IpaCommitment;
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 构造乘法约束 CCS — x * y = z（1 row, 4 vars, 3 matrices）。
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

    /// 构造一个 stub IPA commitment（使用 G1 生成元）。
    fn stub_commitment() -> IpaCommitment {
        IpaCommitment(G1Affine::generator())
    }

    // ===== Ccccs::new 测试 =====

    #[test]
    fn test_ccccs_new_valid() {
        let ccs = make_mul_ccs();
        // num_rows = 1, log2(1) = 0, x_c 应为空 vec
        let ccccs = Ccccs::new(
            ccs.clone(),
            Fr::zero(),
            vec![], // x_c
            vec![f(1), f(3), f(4), f(12)], // trace_c = z
            stub_commitment(),
        )
        .expect("Ccccs 构造应成功");
        assert_eq!(ccccs.u_c, Fr::zero());
        assert_eq!(ccccs.trace_c.len(), 4);
    }

    #[test]
    fn test_ccccs_new_wrong_trace_length() {
        let ccs = make_mul_ccs();
        let result = Ccccs::new(
            ccs,
            Fr::zero(),
            vec![],
            vec![f(1), f(2), f(3)], // 长度 3 != num_vars 4
            stub_commitment(),
        );
        assert!(result.is_err());
    }

    // ===== Ccccs::satisfied 测试 =====

    #[test]
    fn test_ccccs_satisfied_u_zero() {
        // satisfied CCS: x*y - z_val = 0, x=3, y=4, z=12
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            Fr::zero(), // u_c = 0
            vec![],     // x_c (num_rows=1, log2=0)
            vec![f(1), f(3), f(4), f(12)],
            stub_commitment(),
        )
        .unwrap();
        assert!(ccccs.satisfied().unwrap());
    }

    #[test]
    fn test_ccccs_satisfied_u_nonzero() {
        // 不满足 CCS: x*y - z_val = -1, x=3, y=4, z=13 → u_c = -1
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            neg_f(1), // u_c = -1
            vec![],
            vec![f(1), f(3), f(4), f(13)],
            stub_commitment(),
        )
        .unwrap();
        assert!(ccccs.satisfied().unwrap());
    }

    #[test]
    fn test_ccccs_not_satisfied_u_mismatch() {
        // u_c 与 z_C 不一致
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            f(99), // u_c = 99 ≠ 0
            vec![],
            vec![f(1), f(3), f(4), f(12)], // 满足 CCS, 实际 u_c = 0
            stub_commitment(),
        )
        .unwrap();
        assert!(!ccccs.satisfied().unwrap());
    }

    #[test]
    fn test_ccccs_not_satisfied_tampered_trace() {
        // 篡改 trace_c 使约束不满足
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            Fr::zero(), // u_c = 0
            vec![],
            vec![f(1), f(3), f(4), f(99)], // z_val=99, 约束 = 12 - 99 = -87 ≠ 0
            stub_commitment(),
        )
        .unwrap();
        assert!(!ccccs.satisfied().unwrap());
    }

    // ===== compute_v_at_x_c 测试 =====

    #[test]
    fn test_ccccs_compute_v_at_x_c() {
        // 对于 x*y - z_val = 0, z = [1, 3, 4, 12]
        // v_c[0] = M_0 · z = x = 3 (at row 0, only 1 row)
        // v_c[1] = M_1 · z = y = 4
        // v_c[2] = M_2 · z = z_val = 12
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            Fr::zero(),
            vec![], // x_c empty (num_rows=1)
            vec![f(1), f(3), f(4), f(12)],
            stub_commitment(),
        )
        .unwrap();
        let v = ccccs.compute_v_at_x_c().unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], f(3)); // x
        assert_eq!(v[1], f(4)); // y
        assert_eq!(v[2], f(12)); // z_val
    }

    #[test]
    fn test_ccccs_no_v_c_field_stored() {
        // v_C 不存储为字段（v1.3 修正 C2-002）
        // Ccccs 结构仅有: ccs_ref, u_c, x_c, trace_c, witness_commitment_c
        let ccs = make_mul_ccs();
        let ccccs = Ccccs::new(
            ccs,
            Fr::zero(),
            vec![],
            vec![f(1), f(3), f(4), f(12)],
            stub_commitment(),
        )
        .unwrap();
        // 结构体字段数 = 5（无 v_c 字段）
        // 此测试通过类型系统保证：Ccccs 无 v_c 字段
        // （Rust 编译期保证，运行时仅验证可访问字段）
        assert_eq!(ccccs.trace_c.len(), 4);
        assert_eq!(ccccs.u_c, Fr::zero());
        // witness_commitment_c 存在（IpaCommitment 类型）
        let _commitment = &ccccs.witness_commitment_c;
    }

    // ===== 多行 CCS 测试（验证 x_c 非空场景）=====

    /// 构造 2-row CCS：row 0 = x+y-z, row 1 = x*y-w
    /// z = [1, x, y, z_val, w_val]
    /// M_0(x for add):     row 0 = [0,1,0,0,0], row 1 = [0,0,0,0,0]
    /// M_1(y for add):     row 0 = [0,0,1,0,0], row 1 = [0,0,0,0,0]
    /// M_2(z_val):         row 0 = [0,0,0,1,0], row 1 = [0,0,0,0,0]
    /// M_3(x for mul):     row 0 = [0,0,0,0,0], row 1 = [0,1,0,0,0]
    /// M_4(y for mul):     row 0 = [0,0,0,0,0], row 1 = [0,0,1,0,0]
    /// M_5(w_val):         row 0 = [0,0,0,0,0], row 1 = [0,0,0,0,1]
    /// S_0={0}, c_0=1; S_1={1}, c_1=1; S_2={2}, c_2=-1
    /// S_3={3,4}, c_3=1; S_4={5}, c_4=-1
    fn make_multi_row_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(2, 5);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(2, 5);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(2, 5);
        m2.add_entry(0, 3, f(1)).unwrap();
        let mut m3 = SparseMatrix::new(2, 5);
        m3.add_entry(1, 1, f(1)).unwrap();
        let mut m4 = SparseMatrix::new(2, 5);
        m4.add_entry(1, 2, f(1)).unwrap();
        let mut m5 = SparseMatrix::new(2, 5);
        m5.add_entry(1, 4, f(1)).unwrap();

        Ccs::new(
            5,
            vec![m0, m1, m2, m3, m4, m5],
            vec![vec![0], vec![1], vec![2], vec![3, 4], vec![5]],
            vec![f(1), f(1), neg_f(1), f(1), neg_f(1)],
        )
        .expect("multi-row Ccs 构造应成功")
    }

    #[test]
    fn test_ccccs_multi_row_satisfied_at_x_c() {
        // 2-row CCS, x_c 长度 = log2(2) = 1
        // x=3, y=4, z_val=7, w_val=12 → row 0: 3+4-7=0, row 1: 3*4-12=0
        let ccs = make_multi_row_ccs();
        let z = vec![f(1), f(3), f(4), f(7), f(12)];

        // x_c = [0] → 在 row 0 处求值（eq([0], 0)=1, eq([0], 1)=0）
        // v_c = [3, 4, 7, 0, 0, 0]（row 1 贡献为 0）
        // 约束 = 3 + 4 - 7 + 0*0 - 0 = 0 ✓
        let ccccs = Ccccs::new(
            ccs.clone(),
            Fr::zero(),
            vec![f(0)], // x_c = [0]
            z.clone(),
            stub_commitment(),
        )
        .unwrap();
        assert!(ccccs.satisfied().unwrap());

        // x_c = [1] → 在 row 1 处求值
        // v_c = [0, 0, 0, 3, 4, 12]（row 0 贡献为 0）
        // 约束 = 0 + 0 - 0 + 3*4 - 12 = 0 ✓
        let ccccs2 = Ccccs::new(
            ccs.clone(),
            Fr::zero(),
            vec![f(1)], // x_c = [1]
            z.clone(),
            stub_commitment(),
        )
        .unwrap();
        assert!(ccccs2.satisfied().unwrap());

        // x_c = [0.5] → 在 row 0 和 row 1 的混合处求值
        // eq([0.5], 0) = 0.5, eq([0.5], 1) = 0.5
        // v_c[0] = 0.5*3 + 0.5*0 = 1.5 (M_0·z at row 0 = 3, row 1 = 0)
        // v_c[1] = 0.5*4 + 0.5*0 = 2
        // v_c[2] = 0.5*7 + 0.5*0 = 3.5
        // v_c[3] = 0.5*0 + 0.5*3 = 1.5
        // v_c[4] = 0.5*0 + 0.5*4 = 2
        // v_c[5] = 0.5*0 + 0.5*12 = 6
        // 约束 = 1.5 + 2 - 3.5 + 1.5*2 - 6 = 0 + 3 - 6 = -3 ≠ 0
        // （x_c 非布尔点时，CCS 约束不一定满足 — 这是多项式身份只在布尔点成立）
        let ccccs3 = Ccccs::new(
            ccs,
            Fr::zero(), // u_c = 0, 但实际约束 = -3
            vec![f(2).inverse().unwrap()], // x_c = [0.5] (2 的逆元)
            z,
            stub_commitment(),
        )
        .unwrap();
        // satisfied 应返回 false（因 u_c=0 但实际约束 ≠ 0）
        assert!(!ccccs3.satisfied().unwrap());
    }
}
