//! CCS（Customizable Constraint System）约束系统（Phase 5 — Task 5.0）。
//!
//! 严格遵循 spec.md L268-312（v1.4 FROZEN）与 CCS 标准定义：
//! - 矩阵 `M_1, ..., M_t`（稀疏表示）
//! - 子集 `S_1, ..., S_q`（每个 `S_i ⊆ {0, ..., t-1}`）
//! - 系数 `c_1, ..., c_q`
//! - 约束等式：`Σ_i c_i · Π_{j∈S_i} ⟨M_j, z⟩ = 0`（逐行成立）
//!
//! ## 数据结构层次
//!
//! - [`SparseEntry`] — COO 格式单条目 `(row, col, value)`
//! - [`SparseMatrix`] — 稀疏矩阵 `{num_rows, num_cols, entries}`
//! - [`Ccs`] — CCS 结构 `{num_vars, matrices, subsets, coeffs}`
//! - [`CcsInstance`] — CCS 实例 `{ccs, witness, public_inputs}`
//!
//! ## 设计决策（D1/D2，已批准）
//!
//! - CCS 数据结构放 `ccs/mod.rs`（非 `fold/` 或 `constraints/`）
//! - SparseMatrix 用 COO 格式 `Vec<SparseEntry>`（非稠密矩阵或 HashMap）

use crate::error::ZkvmError;
use crate::field::{Bn254ScalarField, ZkvmField};

/// CCS 域元素类型（BN254 标量域）。
pub type Fr = Bn254ScalarField;

/// COO 格式稀疏矩阵单条目。
///
/// `(row, col, value)` 三元组，表示矩阵第 `row` 行第 `col` 列的值为 `value`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseEntry {
    /// 行索引（0-based）。
    pub row: usize,
    /// 列索引（0-based）。
    pub col: usize,
    /// 非零值。
    pub value: Fr,
}

impl SparseEntry {
    /// 序列化为字节：`row(u64 LE) || col(u64 LE) || value(32B canonical)`。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&self.row.to_le_bytes());
        out.extend_from_slice(&self.col.to_le_bytes());
        out.extend_from_slice(&self.value.to_canonical_bytes());
        out
    }

    /// 从字节反序列化（精确读取 48 字节）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkvmError> {
        if bytes.len() < 48 {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "SparseEntry::from_bytes: 输入长度 {} < 48",
                bytes.len()
            )));
        }
        let row = u64::from_le_bytes(bytes[0..8].try_into().expect("8 字节切片"));
        let col = u64::from_le_bytes(bytes[8..16].try_into().expect("8 字节切片"));
        let value = Fr::from_canonical_bytes(&bytes[16..48])?;
        Ok(Self {
            row: row as usize,
            col: col as usize,
            value,
        })
    }
}

/// COO 格式稀疏矩阵。
///
/// 维度 `num_rows × num_cols`，仅存储非零项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMatrix {
    /// 行数。
    pub num_rows: usize,
    /// 列数。
    pub num_cols: usize,
    /// 非零项列表（COO 格式）。
    pub entries: Vec<SparseEntry>,
}

impl SparseMatrix {
    /// 创建空稀疏矩阵（指定维度）。
    pub fn new(num_rows: usize, num_cols: usize) -> Self {
        Self {
            num_rows,
            num_cols,
            entries: Vec::new(),
        }
    }

    /// 添加非零项。
    ///
    /// # 参数
    /// - `row` — 行索引（须 < num_rows）
    /// - `col` — 列索引（须 < num_cols）
    /// - `value` — 非零值
    ///
    /// # 错误
    /// - 行/列越界返回 `ZkvmError::Other`
    pub fn add_entry(&mut self, row: usize, col: usize, value: Fr) -> Result<(), ZkvmError> {
        if row >= self.num_rows {
            return Err(ZkvmError::Other(format!(
                "SparseMatrix::add_entry: row {row} >= num_rows {}",
                self.num_rows
            )));
        }
        if col >= self.num_cols {
            return Err(ZkvmError::Other(format!(
                "SparseMatrix::add_entry: col {col} >= num_cols {}",
                self.num_cols
            )));
        }
        self.entries.push(SparseEntry { row, col, value });
        Ok(())
    }

    /// 查询 `(row, col)` 处的值（返回首个匹配，未找到返回 `Fr::zero()`）。
    pub fn get(&self, row: usize, col: usize) -> Fr {
        for e in &self.entries {
            if e.row == row && e.col == col {
                return e.value;
            }
        }
        Fr::zero()
    }

    /// 计算矩阵-向量乘积 `M · z`，返回长度 `num_rows` 的向量。
    ///
    /// 每个元素 `result[r] = Σ_j M[r][j] · z[j]`。
    ///
    /// # 错误
    /// - `z.len() != num_cols` 返回 `ZkvmError::Other`
    pub fn evaluate(&self, z: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if z.len() != self.num_cols {
            return Err(ZkvmError::Other(format!(
                "SparseMatrix::evaluate: z.len() {} != num_cols {}",
                z.len(),
                self.num_cols
            )));
        }
        let mut result = vec![Fr::zero(); self.num_rows];
        for e in &self.entries {
            let term = e.value.mul(&z[e.col]);
            result[e.row] = result[e.row].add(&term);
        }
        Ok(result)
    }

    /// 序列化为字节：`num_rows(u64 LE) || num_cols(u64 LE) || entries_count(u32 LE) || entries...`。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.num_rows.to_le_bytes());
        out.extend_from_slice(&self.num_cols.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), ZkvmError> {
        if bytes.len() < 20 {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "SparseMatrix::from_bytes: 输入长度 {} < 20",
                bytes.len()
            )));
        }
        let num_rows = u64::from_le_bytes(bytes[0..8].try_into().expect("8 字节切片")) as usize;
        let num_cols = u64::from_le_bytes(bytes[8..16].try_into().expect("8 字节切片")) as usize;
        let entries_count =
            u32::from_le_bytes(bytes[16..20].try_into().expect("4 字节切片")) as usize;
        let mut rest = &bytes[20..];
        let mut entries = Vec::with_capacity(entries_count);
        for i in 0..entries_count {
            let entry = SparseEntry::from_bytes(rest)?;
            // 维度校验
            if entry.row >= num_rows {
                return Err(ZkvmError::InvalidZkProofFormat(format!(
                    "SparseMatrix::from_bytes: entry[{i}].row {} >= num_rows {num_rows}",
                    entry.row
                )));
            }
            if entry.col >= num_cols {
                return Err(ZkvmError::InvalidZkProofFormat(format!(
                    "SparseMatrix::from_bytes: entry[{i}].col {} >= num_cols {num_cols}",
                    entry.col
                )));
            }
            entries.push(entry);
            rest = &rest[48..];
        }
        Ok((
            Self {
                num_rows,
                num_cols,
                entries,
            },
            rest,
        ))
    }
}

/// CCS（Customizable Constraint System）结构。
///
/// 约束等式：对每个行 `r ∈ {0, ..., num_rows-1}`，
/// `Σ_i c_i · Π_{j∈S_i} (M_j · z)[r] = 0`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ccs {
    /// 见证向量 `z` 的长度（等于每个矩阵的 `num_cols`）。
    pub num_vars: usize,
    /// 约束矩阵列表 `M_0, ..., M_{t-1}`。
    pub matrices: Vec<SparseMatrix>,
    /// 子集列表 `S_0, ..., S_{q-1}`（每个 `S_i` 是矩阵索引的子集）。
    pub subsets: Vec<Vec<usize>>,
    /// 系数列表 `c_0, ..., c_{q-1}`。
    pub coeffs: Vec<Fr>,
}

impl Ccs {
    /// 创建 CCS 结构。
    ///
    /// # 参数
    /// - `num_vars` — 见证向量长度
    /// - `matrices` — 约束矩阵列表
    /// - `subsets` — 子集列表（每个子集是矩阵索引）
    /// - `coeffs` — 系数列表（长度须等于 subsets 长度）
    ///
    /// # 错误
    /// - 矩阵列数 != num_vars
    /// - subsets 与 coeffs 长度不匹配
    /// - 子集索引越界
    pub fn new(
        num_vars: usize,
        matrices: Vec<SparseMatrix>,
        subsets: Vec<Vec<usize>>,
        coeffs: Vec<Fr>,
    ) -> Result<Self, ZkvmError> {
        // 校验矩阵列数
        for (i, m) in matrices.iter().enumerate() {
            if m.num_cols != num_vars {
                return Err(ZkvmError::Other(format!(
                    "Ccs::new: matrix {i} num_cols {} != num_vars {num_vars}",
                    m.num_cols
                )));
            }
        }
        // 校验 subsets 与 coeffs 长度
        if subsets.len() != coeffs.len() {
            return Err(ZkvmError::Other(format!(
                "Ccs::new: subsets.len() {} != coeffs.len() {}",
                subsets.len(),
                coeffs.len()
            )));
        }
        // 校验子集索引越界
        for (i, s) in subsets.iter().enumerate() {
            for &j in s {
                if j >= matrices.len() {
                    return Err(ZkvmError::Other(format!(
                        "Ccs::new: subset {i} index {j} >= matrices.len() {}",
                        matrices.len()
                    )));
                }
            }
        }
        Ok(Self {
            num_vars,
            matrices,
            subsets,
            coeffs,
        })
    }

    /// 矩阵数量 `t`。
    pub fn num_matrices(&self) -> usize {
        self.matrices.len()
    }

    /// 子集（约束方程）数量 `q`。
    pub fn num_constraints(&self) -> usize {
        self.subsets.len()
    }

    /// 约束行数（取第一个矩阵的 num_rows，所有矩阵须同高）。
    pub fn num_rows(&self) -> usize {
        self.matrices.first().map_or(0, |m| m.num_rows)
    }

    /// 校验见证向量 `z` 是否满足 CCS 约束。
    ///
    /// 逐行计算 `Σ_i c_i · Π_{j∈S_i} (M_j · z)[r]`，全部为 0 则返回 `true`。
    ///
    /// # 性能
    ///
    /// - **快速路径**：当所有矩阵都是 row-isolated（≤1 个非零项，如 `CcsBuilder` 生成的 CCS），
    ///   时间复杂度 O(matrices + subsets + num_rows)，内存 O(matrices + num_rows)。
    /// - **通用路径**：矩阵有多个非零项时，回退到原始 O(matrices × num_rows) 实现。
    ///
    /// # 错误
    /// - `z.len() != num_vars`
    /// - 矩阵 evaluate 失败（维度不匹配）
    pub fn satisfied_by(&self, z: &[Fr]) -> Result<bool, ZkvmError> {
        if z.len() != self.num_vars {
            return Err(ZkvmError::Other(format!(
                "Ccs::satisfied_by: z.len() {} != num_vars {}",
                z.len(),
                self.num_vars
            )));
        }

        let num_rows = self.num_rows();
        if num_rows == 0 || self.matrices.is_empty() {
            return Ok(true);
        }

        let all_row_isolated = self.matrices.iter().all(|m| m.entries.len() <= 1);
        if all_row_isolated {
            self.satisfied_by_row_isolated(z, num_rows)
        } else {
            self.satisfied_by_general(z, num_rows)
        }
    }

    /// 快速路径：所有矩阵 row-isolated（≤1 entry）。
    ///
    /// 对每个矩阵 j，`(M_j · z)` 仅在 `entry.row` 处非零，值为 `entry.value * z[entry.col]`。
    /// 对每个 subset S_i，所有矩阵应属于同一行（`CcsBuilder` 保证），否则乘积为 0。
    fn satisfied_by_row_isolated(&self, z: &[Fr], num_rows: usize) -> Result<bool, ZkvmError> {
        let mut row_sums = vec![Fr::zero(); num_rows];

        let matrix_vals: Vec<(usize, Fr)> = self
            .matrices
            .iter()
            .map(|m| {
                if let Some(e) = m.entries.first() {
                    (e.row, e.value.mul(&z[e.col]))
                } else {
                    (0, Fr::zero())
                }
            })
            .collect();

        let mut empty_subset_sum = Fr::zero();
        for (i, s) in self.subsets.iter().enumerate() {
            if s.is_empty() {
                empty_subset_sum = empty_subset_sum.add(&self.coeffs[i]);
                continue;
            }
            let row = matrix_vals[s[0]].0;
            let mut prod = self.coeffs[i];
            let mut all_same_row = true;
            for &j in s {
                let (j_row, j_val) = matrix_vals[j];
                if j_row != row {
                    all_same_row = false;
                    break;
                }
                prod = prod.mul(&j_val);
            }
            if all_same_row {
                row_sums[row] = row_sums[row].add(&prod);
            }
        }

        if !empty_subset_sum.is_zero() {
            for sum in &mut row_sums {
                *sum = sum.add(&empty_subset_sum);
            }
        }

        for sum in &row_sums {
            if !sum.is_zero() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 通用路径：矩阵可能有多个非零项（原始实现）。
    fn satisfied_by_general(&self, z: &[Fr], num_rows: usize) -> Result<bool, ZkvmError> {
        let mz: Vec<Vec<Fr>> = self
            .matrices
            .iter()
            .map(|m| m.evaluate(z))
            .collect::<Result<Vec<_>, _>>()?;

        let row_vals: Vec<Vec<Fr>> = (0..num_rows)
            .map(|r| mz.iter().map(|col| col[r]).collect())
            .collect();

        for row in &row_vals {
            let mut sum = Fr::zero();
            for (i, s) in self.subsets.iter().enumerate() {
                let mut prod = Fr::one();
                for &j in s {
                    prod = prod.mul(&row[j]);
                }
                let term = self.coeffs[i].mul(&prod);
                sum = sum.add(&term);
            }
            if !sum.is_zero() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 序列化为字节：`num_vars(u64 LE) || matrices_count(u32 LE) || matrices... || subsets_count(u32 LE) || subsets... || coeffs_count(u32 LE) || coeffs...`。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.num_vars.to_le_bytes());
        out.extend_from_slice(&(self.matrices.len() as u32).to_le_bytes());
        for m in &self.matrices {
            out.extend_from_slice(&m.to_bytes());
        }
        out.extend_from_slice(&(self.subsets.len() as u32).to_le_bytes());
        for s in &self.subsets {
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            for &idx in s {
                out.extend_from_slice(&(idx as u32).to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.coeffs.len() as u32).to_le_bytes());
        for c in &self.coeffs {
            out.extend_from_slice(&c.to_canonical_bytes());
        }
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkvmError> {
        let mut rest = bytes;
        if rest.len() < 12 {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "Ccs::from_bytes: 输入长度 {} < 12",
                rest.len()
            )));
        }
        let num_vars = u64::from_le_bytes(rest[0..8].try_into().expect("8 字节切片")) as usize;
        let matrices_count =
            u32::from_le_bytes(rest[8..12].try_into().expect("4 字节切片")) as usize;
        rest = &rest[12..];
        let mut matrices = Vec::with_capacity(matrices_count);
        for i in 0..matrices_count {
            let (m, r) = SparseMatrix::from_bytes(rest)?;
            if m.num_cols != num_vars {
                return Err(ZkvmError::InvalidZkProofFormat(format!(
                    "Ccs::from_bytes: matrix[{i}].num_cols {} != num_vars {num_vars}",
                    m.num_cols
                )));
            }
            matrices.push(m);
            rest = r;
        }
        if rest.len() < 4 {
            return Err(ZkvmError::InvalidZkProofFormat(
                "Ccs::from_bytes: subsets_count 截断".to_string(),
            ));
        }
        let subsets_count = u32::from_le_bytes(rest[0..4].try_into().expect("4 字节切片")) as usize;
        rest = &rest[4..];
        let mut subsets = Vec::with_capacity(subsets_count);
        for i in 0..subsets_count {
            if rest.len() < 4 {
                return Err(ZkvmError::InvalidZkProofFormat(format!(
                    "Ccs::from_bytes: subset[{i}].len 截断",
                )));
            }
            let s_len = u32::from_le_bytes(rest[0..4].try_into().expect("4 字节切片")) as usize;
            rest = &rest[4..];
            if rest.len() < s_len * 4 {
                return Err(ZkvmError::InvalidZkProofFormat(format!(
                    "Ccs::from_bytes: subset[{i}] 内容截断（需要 {} 字节，剩余 {}）",
                    s_len * 4,
                    rest.len()
                )));
            }
            let mut s = Vec::with_capacity(s_len);
            for j in 0..s_len {
                let idx = u32::from_le_bytes(
                    rest[j * 4..j * 4 + 4].try_into().expect("4 字节切片"),
                ) as usize;
                if idx >= matrices_count {
                    return Err(ZkvmError::InvalidZkProofFormat(format!(
                        "Ccs::from_bytes: subset[{i}][{j}] index {idx} >= matrices_count {matrices_count}",
                    )));
                }
                s.push(idx);
            }
            rest = &rest[s_len * 4..];
            subsets.push(s);
        }
        if rest.len() < 4 {
            return Err(ZkvmError::InvalidZkProofFormat(
                "Ccs::from_bytes: coeffs_count 截断".to_string(),
            ));
        }
        let coeffs_count =
            u32::from_le_bytes(rest[0..4].try_into().expect("4 字节切片")) as usize;
        rest = &rest[4..];
        if subsets_count != coeffs_count {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "Ccs::from_bytes: subsets_count {subsets_count} != coeffs_count {coeffs_count}",
            )));
        }
        if rest.len() < coeffs_count * 32 {
            return Err(ZkvmError::InvalidZkProofFormat(format!(
                "Ccs::from_bytes: coeffs 内容截断（需要 {} 字节，剩余 {}）",
                coeffs_count * 32,
                rest.len()
            )));
        }
        let mut coeffs = Vec::with_capacity(coeffs_count);
        for i in 0..coeffs_count {
            let c = Fr::from_canonical_bytes(&rest[i * 32..i * 32 + 32])?;
            coeffs.push(c);
        }
        Ok(Self {
            num_vars,
            matrices,
            subsets,
            coeffs,
        })
    }
}

/// CCS 实例（含约束结构 + 见证 + 公共输入）。
///
/// 对应 Task 6.1.4 — 新类型，含矩阵结构与域元素 witness（非 hash-based）。
#[derive(Debug, Clone)]
pub struct CcsInstance {
    /// CCS 约束结构。
    pub ccs: Ccs,
    /// 见证向量 `z`（长度 = ccs.num_vars）。
    pub witness: Vec<Fr>,
    /// 公共输入（z 的子集或附加公共值）。
    pub public_inputs: Vec<Fr>,
}

impl CcsInstance {
    /// 创建 CCS 实例并校验 witness 长度。
    pub fn new(
        ccs: Ccs,
        witness: Vec<Fr>,
        public_inputs: Vec<Fr>,
    ) -> Result<Self, ZkvmError> {
        if witness.len() != ccs.num_vars {
            return Err(ZkvmError::Other(format!(
                "CcsInstance::new: witness.len() {} != ccs.num_vars {}",
                witness.len(),
                ccs.num_vars
            )));
        }
        Ok(Self {
            ccs,
            witness,
            public_inputs,
        })
    }

    /// 校验 witness 是否满足 CCS 约束。
    pub fn is_satisfied(&self) -> Result<bool, ZkvmError> {
        self.ccs.satisfied_by(&self.witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助：构造负 Fr（用减法实现，避免直接构造大数）。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    // ===== SparseEntry / SparseMatrix 测试 =====

    #[test]
    fn test_sparse_matrix_add_and_get() {
        let mut m = SparseMatrix::new(2, 3);
        m.add_entry(0, 1, f(5)).expect("add_entry 应成功");
        m.add_entry(1, 2, f(7)).expect("add_entry 应成功");

        assert_eq!(m.get(0, 1), f(5));
        assert_eq!(m.get(1, 2), f(7));
        // 未设置的格子返回 0
        assert_eq!(m.get(0, 0), Fr::zero());
        assert_eq!(m.get(1, 0), Fr::zero());
    }

    #[test]
    fn test_sparse_matrix_add_entry_out_of_bounds() {
        let mut m = SparseMatrix::new(2, 3);
        // 行越界
        assert!(m.add_entry(2, 0, f(1)).is_err());
        // 列越界
        assert!(m.add_entry(0, 3, f(1)).is_err());
        // 合法
        assert!(m.add_entry(1, 2, f(1)).is_ok());
    }

    #[test]
    fn test_sparse_matrix_evaluate() {
        // 2×3 矩阵：
        // [1, 0, 2]
        // [0, 3, 0]
        let mut m = SparseMatrix::new(2, 3);
        m.add_entry(0, 0, f(1)).unwrap();
        m.add_entry(0, 2, f(2)).unwrap();
        m.add_entry(1, 1, f(3)).unwrap();

        // z = [4, 5, 6]
        let z = vec![f(4), f(5), f(6)];
        let result = m.evaluate(&z).expect("evaluate 应成功");
        // row 0: 1*4 + 2*6 = 16
        assert_eq!(result[0], f(16));
        // row 1: 3*5 = 15
        assert_eq!(result[1], f(15));
    }

    #[test]
    fn test_sparse_matrix_evaluate_wrong_dim() {
        let m = SparseMatrix::new(2, 3);
        let z = vec![f(1), f(2)]; // 长度 2 != 3
        assert!(m.evaluate(&z).is_err());
    }

    #[test]
    fn test_sparse_matrix_empty() {
        let m = SparseMatrix::new(3, 4);
        assert_eq!(m.entries.len(), 0);
        assert_eq!(m.get(0, 0), Fr::zero());

        // 空矩阵 evaluate 全 0
        let z = vec![f(1); 4];
        let result = m.evaluate(&z).expect("evaluate 应成功");
        assert_eq!(result.len(), 3);
        for v in &result {
            assert!(v.is_zero());
        }
    }

    #[test]
    fn test_sparse_matrix_overwrite() {
        // 同一位置多次 add_entry，evaluate 时累加
        let mut m = SparseMatrix::new(1, 1);
        m.add_entry(0, 0, f(3)).unwrap();
        m.add_entry(0, 0, f(4)).unwrap(); // 累加 → 实际值 7

        let z = vec![f(1)];
        let result = m.evaluate(&z).expect("evaluate 应成功");
        assert_eq!(result[0], f(7)); // 3 + 4 = 7
    }

    // ===== Ccs 测试 =====

    /// 辅助：构造乘法约束 CCS — x * y = z
    ///
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

    #[test]
    fn test_ccs_satisfied_by_simple() {
        let ccs = make_mul_ccs();
        // x=3, y=4, z=12 → 3*4 - 12 = 0 ✓
        let z = vec![f(1), f(3), f(4), f(12)];
        assert!(ccs.satisfied_by(&z).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ccs_satisfied_by_violated() {
        let ccs = make_mul_ccs();
        // x=3, y=4, z=13 → 3*4 - 13 = -1 ≠ 0 ✗
        let z = vec![f(1), f(3), f(4), f(13)];
        assert!(!ccs.satisfied_by(&z).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ccs_satisfied_by_zero_case() {
        let ccs = make_mul_ccs();
        // x=0, y=5, z=0 → 0*5 - 0 = 0 ✓
        let z = vec![f(1), f(0), f(5), f(0)];
        assert!(ccs.satisfied_by(&z).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ccs_satisfied_by_wrong_length() {
        let ccs = make_mul_ccs();
        let z = vec![f(1), f(2), f(3)]; // 长度 3 != 4
        assert!(ccs.satisfied_by(&z).is_err());
    }

    #[test]
    fn test_ccs_multiple_matrices() {
        // 约束：row 0 为加法 x + y = z_val，row 1 为乘法 x * y = w_val
        // z = [1, x, y, z_val, w_val]
        //
        // CCS 中所有 subset 对所有行求和，因此用行隔离矩阵使无关 subset 在对应行为 0：
        // M_0 (x for add):     row 0 = [0,1,0,0,0], row 1 = [0,0,0,0,0]
        // M_1 (y for add):     row 0 = [0,0,1,0,0], row 1 = [0,0,0,0,0]
        // M_2 (z_val):         row 0 = [0,0,0,1,0], row 1 = [0,0,0,0,0]
        // M_3 (x for mul):     row 0 = [0,0,0,0,0], row 1 = [0,1,0,0,0]
        // M_4 (y for mul):     row 0 = [0,0,0,0,0], row 1 = [0,0,1,0,0]
        // M_5 (w_val):         row 0 = [0,0,0,0,0], row 1 = [0,0,0,0,1]
        //
        // S_0={0}, c_0=1  → [x, 0]
        // S_1={1}, c_1=1  → [y, 0]
        // S_2={2}, c_2=-1 → [-z_val, 0]
        // S_3={3,4}, c_3=1 → [0, x*y]
        // S_4={5}, c_4=-1 → [0, -w_val]
        // row 0: x + y - z_val + 0 + 0 = 0
        // row 1: 0 + 0 + 0 + x*y - w_val = 0
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

        let ccs = Ccs::new(
            5,
            vec![m0, m1, m2, m3, m4, m5],
            vec![vec![0], vec![1], vec![2], vec![3, 4], vec![5]],
            vec![f(1), f(1), neg_f(1), f(1), neg_f(1)],
        )
        .expect("Ccs 构造应成功");

        // x=3, y=4, z_val=7, w_val=12
        // row 0: 3 + 4 - 7 = 0 ✓
        // row 1: 3*4 - 12 = 0 ✓
        let z_ok = vec![f(1), f(3), f(4), f(7), f(12)];
        assert!(ccs.satisfied_by(&z_ok).expect("satisfied_by 应成功"));

        // x=3, y=4, z_val=7, w_val=13
        // row 0: 3 + 4 - 7 = 0 ✓
        // row 1: 3*4 - 13 = -1 ≠ 0 ✗
        let z_bad = vec![f(1), f(3), f(4), f(7), f(13)];
        assert!(!ccs.satisfied_by(&z_bad).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ccs_new_validation_errors() {
        // 矩阵列数不匹配
        let m = SparseMatrix::new(1, 3);
        let result = Ccs::new(4, vec![m], vec![vec![0]], vec![f(1)]);
        assert!(result.is_err());

        // subsets 与 coeffs 长度不匹配
        let m = SparseMatrix::new(1, 4);
        let result = Ccs::new(4, vec![m], vec![vec![0]], vec![]);
        assert!(result.is_err());

        // 子集索引越界
        let m = SparseMatrix::new(1, 4);
        let result = Ccs::new(4, vec![m], vec![vec![1]], vec![f(1)]);
        assert!(result.is_err());
    }

    // ===== CcsInstance 测试 =====

    #[test]
    fn test_ccs_instance_new_type() {
        let ccs = make_mul_ccs();
        let witness = vec![f(1), f(3), f(4), f(12)];
        let public_inputs = vec![f(1)]; // public_io = [1]（常量）

        let instance =
            CcsInstance::new(ccs, witness, public_inputs).expect("CcsInstance 构造应成功");
        assert!(instance.is_satisfied().expect("is_satisfied 应成功"));
        assert_eq!(instance.public_inputs.len(), 1);
    }

    #[test]
    fn test_ccs_instance_wrong_witness_length() {
        let ccs = make_mul_ccs();
        let witness = vec![f(1), f(2), f(3)]; // 长度 3 != 4
        let result = CcsInstance::new(ccs, witness, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ccs_instance_is_satisfied_violated() {
        let ccs = make_mul_ccs();
        let witness = vec![f(1), f(3), f(4), f(13)]; // 3*4 ≠ 13
        let instance = CcsInstance::new(ccs, witness, vec![]).unwrap();
        assert!(!instance.is_satisfied().expect("is_satisfied 应成功"));
    }

    #[test]
    fn test_ccs_num_matrices_and_constraints() {
        let ccs = make_mul_ccs();
        assert_eq!(ccs.num_matrices(), 3);
        assert_eq!(ccs.num_constraints(), 2);
        assert_eq!(ccs.num_rows(), 1);
    }

    /// 空子集语义测试：空子集的乘积为 1（乘法单位元）。
    #[test]
    fn test_ccs_empty_subset() {
        // z = [x]
        // M_0 = [[1]] → M_0·z = x
        // S_0 = {} (空), c_0 = 5 → 5 * 1 = 5（常数约束）
        // S_1 = {0},  c_1 = -1  → -x
        // 约束：5 - x = 0 → x = 5
        let mut m0 = SparseMatrix::new(1, 1);
        m0.add_entry(0, 0, f(1)).unwrap();

        let ccs = Ccs::new(
            1,
            vec![m0],
            vec![vec![], vec![0]],
            vec![f(5), neg_f(1)],
        )
        .expect("Ccs 构造应成功");

        // x = 5 → 5 - 5 = 0 ✓
        let z_ok = vec![f(5)];
        assert!(ccs.satisfied_by(&z_ok).expect("satisfied_by 应成功"));

        // x = 3 → 5 - 3 = 2 ≠ 0 ✗
        let z_bad = vec![f(3)];
        assert!(!ccs.satisfied_by(&z_bad).expect("satisfied_by 应成功"));
    }

    // ===== Phase 8 Step 1: CCS 序列化测试 =====

    #[test]
    fn test_ccs_serialization_roundtrip() {
        let ccs = make_mul_ccs();
        let bytes = ccs.to_bytes();
        let restored = Ccs::from_bytes(&bytes).expect("from_bytes 应成功");
        assert_eq!(ccs, restored);
    }

    #[test]
    fn test_ccs_serialization_empty_matrices() {
        // 空矩阵列表的 CCS
        let ccs = Ccs::new(4, vec![], vec![vec![]], vec![f(7)]).expect("Ccs 构造应成功");
        let bytes = ccs.to_bytes();
        let restored = Ccs::from_bytes(&bytes).expect("from_bytes 应成功");
        assert_eq!(ccs, restored);
    }

    #[test]
    fn test_ccs_serialization_large_matrices() {
        // 多矩阵 + 多约束 CCS（复用 test_ccs_multiple_matrices 结构）
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

        let ccs = Ccs::new(
            5,
            vec![m0, m1, m2, m3, m4, m5],
            vec![vec![0], vec![1], vec![2], vec![3, 4], vec![5]],
            vec![f(1), f(1), neg_f(1), f(1), neg_f(1)],
        )
        .expect("Ccs 构造应成功");

        let bytes = ccs.to_bytes();
        let restored = Ccs::from_bytes(&bytes).expect("from_bytes 应成功");
        assert_eq!(ccs, restored);
        // 序列化后的 CCS 仍能正确求值
        let z = vec![f(1), f(3), f(4), f(7), f(12)];
        assert!(restored.satisfied_by(&z).expect("satisfied_by 应成功"));
    }

    #[test]
    fn test_ccs_serialization_malformed_input() {
        // 输入过短
        assert!(Ccs::from_bytes(&[0u8; 5]).is_err());
        // 截断的矩阵数据
        let ccs = make_mul_ccs();
        let mut bytes = ccs.to_bytes();
        bytes.truncate(bytes.len() - 10);
        assert!(Ccs::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_ccs_serialization_dimension_validation() {
        // 构造合法 CCS 序列化
        let ccs = make_mul_ccs();
        let bytes = ccs.to_bytes();
        // 篡改 num_vars 使其与矩阵 num_cols 不匹配
        let mut tampered = bytes.clone();
        tampered[0] = 0xFF; // num_vars 改为一个大数低字节
        tampered[1] = 0xFF;
        tampered[2] = 0xFF;
        tampered[3] = 0xFF;
        let result = Ccs::from_bytes(&tampered);
        assert!(result.is_err(), "维度不匹配应返回错误");
    }
}
