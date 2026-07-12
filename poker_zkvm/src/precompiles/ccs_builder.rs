//! CCS 约束构建器（Stage 3 — Phase A）。
//!
//! 提供程序化 API 声明 CCS 约束，内部遵循 row isolation 模式：
//! 每个矩阵仅单一行有非零项，确保 subset 不污染其他行。
//!
//! # 支持的约束类型
//!
//! - 乘法：`z[a] * z[b] - z[result] = 0`
//! - 线性：`sum(coeff * z[col]) = 0`
//! - 位检查：`z[col] * (1 - z[col]) = 0`（即 `z[col]^2 - z[col] = 0`）
//!
//! # Row isolation 模式
//!
//! 每个矩阵仅单一行有非零项。CCS 语义要求 ALL subsets 贡献到 ALL rows，
//! 因此必须用行隔离使无关 subset 在对应行求值为 0（因 `(M_j · z)[other_row] = 0`，
//! 乘积为 0）。

use crate::ccs::{Ccs, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;

/// CCS 约束类型（内部表示）。
#[derive(Debug, Clone)]
enum Constraint {
    /// `z[a] * z[b] - z[result] = 0`
    Multiplication {
        a: usize,
        b: usize,
        result: usize,
        row: usize,
    },
    /// `sum(coeff * z[col]) = 0`
    Linear {
        terms: Vec<(usize, Fr)>,
        row: usize,
    },
    /// `z[col]^2 - z[col] = 0`
    BitCheck { col: usize, row: usize },
}

/// CCS 约束构建器。
///
/// 通过高级 API 声明约束，[`CcsBuilder::build`] 生成行隔离矩阵 + subsets + coeffs。
///
/// # 变量分配
///
/// - 变量索引 0 保留给常数 1（witness[0] = `Fr::one()`）
/// - [`alloc_var`](Self::alloc_var) 从索引 1 开始分配
///
/// # 用法
///
/// ```text
/// let mut builder = CcsBuilder::new();
/// let x = builder.alloc_var();      // 1
/// let x2 = builder.alloc_var();     // 2
/// let row = builder.alloc_row();    // 0
/// builder.add_multiplication(row, x, x, x2);  // x * x = x2
/// let ccs = builder.build()?;
/// ```
#[derive(Debug, Clone)]
pub struct CcsBuilder {
    next_var: usize,
    next_row: usize,
    constraints: Vec<Constraint>,
}

impl CcsBuilder {
    /// 创建空构建器（变量 0 保留给常数 1）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_var: 1,
            next_row: 0,
            constraints: Vec::new(),
        }
    }

    /// 分配新变量，返回索引（从 1 开始）。
    #[must_use]
    pub fn alloc_var(&mut self) -> usize {
        let idx = self.next_var;
        self.next_var += 1;
        idx
    }

    /// 分配新行，返回索引（从 0 开始）。
    #[must_use]
    pub fn alloc_row(&mut self) -> usize {
        let idx = self.next_row;
        self.next_row += 1;
        idx
    }

    /// 当前已分配的变量数（含常数 1）。
    #[must_use]
    pub fn num_vars(&self) -> usize {
        self.next_var
    }

    /// 当前已分配的行数。
    #[must_use]
    pub fn num_rows(&self) -> usize {
        self.next_row
    }

    /// 约束 `z[a] * z[b] = z[result]`（在指定 row）。
    ///
    /// 生成 3 个行隔离矩阵 + 2 个 subsets：
    /// - `S_0 = {M_a, M_b}`, `c_0 = +1` → `z[a] * z[b]`
    /// - `S_1 = {M_result}`, `c_1 = -1` → `-z[result]`
    pub fn add_multiplication(&mut self, row: usize, a: usize, b: usize, result: usize) {
        self.constraints
            .push(Constraint::Multiplication { a, b, result, row });
    }

    /// 约束 `sum(coeff * z[col]) = 0`（在指定 row）。
    ///
    /// 每个 term 生成 1 个行隔离矩阵 + 1 个单元素 subset。
    pub fn add_linear(&mut self, row: usize, terms: &[(usize, Fr)]) {
        self.constraints
            .push(Constraint::Linear {
                terms: terms.to_vec(),
                row,
            });
    }

    /// 约束 `z[col] * (1 - z[col]) = 0`（在指定 row）。
    ///
    /// 生成 1 个行隔离矩阵 + 2 个 subsets：
    /// - `S_0 = {M_col, M_col}`, `c_0 = +1` → `z[col]^2`
    /// - `S_1 = {M_col}`, `c_1 = -1` → `-z[col]`
    pub fn add_bit_check(&mut self, row: usize, col: usize) {
        self.constraints.push(Constraint::BitCheck { col, row });
    }

    /// 生成 CCS 结构。
    ///
    /// # 错误
    /// - 变量/行索引越界
    /// - Linear 约束 terms 为空
    pub fn build(self) -> Result<Ccs, ZkvmError> {
        let num_vars = self.next_var;
        let num_rows = self.next_row;
        let neg_one = Fr::one().neg();

        let mut matrices: Vec<SparseMatrix> = Vec::new();
        let mut subsets: Vec<Vec<usize>> = Vec::new();
        let mut coeffs: Vec<Fr> = Vec::new();

        let check_var = |v: usize, ctx: &str| -> Result<(), ZkvmError> {
            if v >= num_vars {
                return Err(ZkvmError::Other(format!(
                    "CcsBuilder::build: {ctx} 变量索引 {v} >= num_vars {num_vars}"
                )));
            }
            Ok(())
        };
        let check_row = |r: usize, ctx: &str| -> Result<(), ZkvmError> {
            if r >= num_rows {
                return Err(ZkvmError::Other(format!(
                    "CcsBuilder::build: {ctx} 行索引 {r} >= num_rows {num_rows}"
                )));
            }
            Ok(())
        };

        for constraint in &self.constraints {
            match constraint {
                Constraint::Multiplication { a, b, result, row } => {
                    check_var(*a, "Multiplication a")?;
                    check_var(*b, "Multiplication b")?;
                    check_var(*result, "Multiplication result")?;
                    check_row(*row, "Multiplication row")?;

                    let idx_a = matrices.len();
                    let mut m_a = SparseMatrix::new(num_rows, num_vars);
                    m_a.add_entry(*row, *a, Fr::one())?;
                    matrices.push(m_a);

                    let idx_b = matrices.len();
                    let mut m_b = SparseMatrix::new(num_rows, num_vars);
                    m_b.add_entry(*row, *b, Fr::one())?;
                    matrices.push(m_b);

                    let idx_result = matrices.len();
                    let mut m_result = SparseMatrix::new(num_rows, num_vars);
                    m_result.add_entry(*row, *result, Fr::one())?;
                    matrices.push(m_result);

                    subsets.push(vec![idx_a, idx_b]);
                    coeffs.push(Fr::one());
                    subsets.push(vec![idx_result]);
                    coeffs.push(neg_one);
                }
                Constraint::Linear { terms, row } => {
                    check_row(*row, "Linear row")?;
                    if terms.is_empty() {
                        return Err(ZkvmError::Other(
                            "CcsBuilder::build: Linear constraint with empty terms".to_string(),
                        ));
                    }

                    let mut term_indices = Vec::with_capacity(terms.len());
                    for (col, _coeff) in terms {
                        check_var(*col, "Linear term col")?;
                        let idx = matrices.len();
                        let mut m = SparseMatrix::new(num_rows, num_vars);
                        m.add_entry(*row, *col, Fr::one())?;
                        matrices.push(m);
                        term_indices.push(idx);
                    }

                    for (i, (_col, coeff)) in terms.iter().enumerate() {
                        subsets.push(vec![term_indices[i]]);
                        coeffs.push(*coeff);
                    }
                }
                Constraint::BitCheck { col, row } => {
                    check_var(*col, "BitCheck col")?;
                    check_row(*row, "BitCheck row")?;

                    let idx = matrices.len();
                    let mut m = SparseMatrix::new(num_rows, num_vars);
                    m.add_entry(*row, *col, Fr::one())?;
                    matrices.push(m);

                    subsets.push(vec![idx, idx]);
                    coeffs.push(Fr::one());
                    subsets.push(vec![idx]);
                    coeffs.push(neg_one);
                }
            }
        }

        Ccs::new(num_vars, matrices, subsets, coeffs)
    }
}

impl Default for CcsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::ZkvmField;

    #[test]
    fn test_ccs_builder_multiplication() {
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let x2 = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_multiplication(row, x, x, x2);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_vars, 3);
        assert_eq!(ccs.num_rows(), 1);
        assert_eq!(ccs.num_matrices(), 3);
        assert_eq!(ccs.num_constraints(), 2);

        let witness = vec![Fr::one(), Fr::from_u32_with_wrap(3), Fr::from_u32_with_wrap(9)];
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let bad = vec![Fr::one(), Fr::from_u32_with_wrap(3), Fr::from_u32_with_wrap(10)];
        assert!(!ccs.satisfied_by(&bad).expect("satisfied_by bad"));
    }

    #[test]
    fn test_ccs_builder_linear() {
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let y = builder.alloc_var();
        let result = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_linear(row, &[
            (x, Fr::one()),
            (y, Fr::one()),
            (result, Fr::one().neg()),
        ]);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_vars, 4);
        assert_eq!(ccs.num_rows(), 1);

        let witness = vec![
            Fr::one(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(4),
            Fr::from_u32_with_wrap(7),
        ];
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let bad = vec![
            Fr::one(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(4),
            Fr::from_u32_with_wrap(8),
        ];
        assert!(!ccs.satisfied_by(&bad).expect("satisfied_by bad"));
    }

    #[test]
    fn test_ccs_builder_bit_check() {
        let mut builder = CcsBuilder::new();
        let bit = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_bit_check(row, bit);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_vars, 2);
        assert_eq!(ccs.num_rows(), 1);
        assert_eq!(ccs.num_matrices(), 1);
        assert_eq!(ccs.num_constraints(), 2);

        assert!(ccs.satisfied_by(&[Fr::one(), Fr::zero()]).expect("bit=0"));
        assert!(ccs.satisfied_by(&[Fr::one(), Fr::one()]).expect("bit=1"));
        assert!(
            !ccs.satisfied_by(&[Fr::one(), Fr::from_u32_with_wrap(2)]).expect("bit=2 should fail")
        );
    }

    #[test]
    fn test_ccs_builder_chained() {
        // 链式约束: x² → x⁴ → x⁵ (匹配 Poseidon MVP S-box 语义)
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let x2 = builder.alloc_var();
        let x4 = builder.alloc_var();
        let x5 = builder.alloc_var();
        let row0 = builder.alloc_row();
        let row1 = builder.alloc_row();
        let row2 = builder.alloc_row();

        builder.add_multiplication(row0, x, x, x2);
        builder.add_multiplication(row1, x2, x2, x4);
        builder.add_multiplication(row2, x4, x, x5);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_vars, 5);
        assert_eq!(ccs.num_rows(), 3);
        assert_eq!(ccs.num_matrices(), 9);
        assert_eq!(ccs.num_constraints(), 6);

        let witness = vec![
            Fr::one(),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(9),
            Fr::from_u32_with_wrap(81),
            Fr::from_u32_with_wrap(243),
        ];
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let mut tampered = witness.clone();
        tampered[4] = Fr::from_u32_with_wrap(244);
        assert!(!ccs.satisfied_by(&tampered).expect("tampered x5"));
    }

    #[test]
    fn test_ccs_builder_row_isolation() {
        let mut builder = CcsBuilder::new();
        let a = builder.alloc_var();
        let b = builder.alloc_var();
        let c = builder.alloc_var();
        let d = builder.alloc_var();
        let e = builder.alloc_var();
        let f = builder.alloc_var();
        let row0 = builder.alloc_row();
        let row1 = builder.alloc_row();

        builder.add_multiplication(row0, a, b, c);
        builder.add_multiplication(row1, d, e, f);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_rows(), 2);

        let witness = vec![
            Fr::one(),
            Fr::from_u32_with_wrap(2),
            Fr::from_u32_with_wrap(3),
            Fr::from_u32_with_wrap(6),
            Fr::from_u32_with_wrap(4),
            Fr::from_u32_with_wrap(5),
            Fr::from_u32_with_wrap(20),
        ];
        assert!(ccs.satisfied_by(&witness).expect("satisfied_by"));

        let mut tampered = witness.clone();
        tampered[6] = Fr::from_u32_with_wrap(21);
        assert!(!ccs.satisfied_by(&tampered).expect("tampered f"));
    }

    #[test]
    fn test_ccs_builder_var_index_out_of_bounds() {
        let mut builder = CcsBuilder::new();
        builder.add_multiplication(0, 5, 6, 7);
        assert!(builder.build().is_err(), "变量索引越界应返回错误");
    }

    #[test]
    fn test_ccs_builder_row_index_out_of_bounds() {
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let x2 = builder.alloc_var();
        builder.add_multiplication(0, x, x, x2);
        assert!(builder.build().is_err(), "行索引越界应返回错误");
    }

    #[test]
    fn test_ccs_builder_empty() {
        let builder = CcsBuilder::new();
        let ccs = builder.build().expect("空 builder 应成功");
        assert_eq!(ccs.num_vars, 1);
        assert_eq!(ccs.num_matrices(), 0);
        assert_eq!(ccs.num_constraints(), 0);
    }

    #[test]
    fn test_ccs_builder_linear_with_constant() {
        // 约束 1 - x = 0 (即 x = 1)，使用常数变量 0
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let row = builder.alloc_row();
        builder.add_linear(row, &[(0, Fr::one()), (x, Fr::one().neg())]);

        let ccs = builder.build().expect("build 应成功");

        assert!(ccs.satisfied_by(&[Fr::one(), Fr::one()]).expect("x=1"));
        assert!(
            !ccs.satisfied_by(&[Fr::one(), Fr::from_u32_with_wrap(2)]).expect("x=2 should fail")
        );
    }

    #[test]
    fn test_ccs_builder_mixed_constraints() {
        // 混合约束: x * y = z (乘法) + z 是 bit (位检查)
        let mut builder = CcsBuilder::new();
        let x = builder.alloc_var();
        let y = builder.alloc_var();
        let z = builder.alloc_var();
        let row0 = builder.alloc_row();
        let row1 = builder.alloc_row();

        builder.add_multiplication(row0, x, y, z);
        builder.add_bit_check(row1, z);

        let ccs = builder.build().expect("build 应成功");
        assert_eq!(ccs.num_vars, 4);
        assert_eq!(ccs.num_rows(), 2);

        // x=1, y=1, z=1 (1*1=1, 1 是 bit)
        assert!(ccs
            .satisfied_by(&[Fr::one(), Fr::one(), Fr::one(), Fr::one()])
            .expect("valid"));

        // x=1, y=0, z=0 (1*0=0, 0 是 bit)
        assert!(ccs
            .satisfied_by(&[Fr::one(), Fr::one(), Fr::zero(), Fr::zero()])
            .expect("valid"));

        // x=2, y=3, z=6 (2*3=6, 6 不是 bit → 位检查失败)
        assert!(
            !ccs.satisfied_by(&[
                Fr::one(),
                Fr::from_u32_with_wrap(2),
                Fr::from_u32_with_wrap(3),
                Fr::from_u32_with_wrap(6)
            ])
            .expect("z not bit")
        );
    }
}
