//! CCS 扩展方法（Phase 6 — Task 6.1）。
//!
//! 为现有 [`crate::ccs::Ccs`] 添加 Hypernova 折叠所需的扩展方法。
//!
//! ## 扩展方法
//!
//! - [`Ccs::to_lcccs`] — 由 CCS + witness z + r_x_l 生成 LCCCS 实例
//! - [`Ccs::to_cccs`] — 由 CCS + witness z + commitment 生成 CCCCS 实例
//! - [`Ccs::ccs_commitment`] — Blake2b 哈希绑定矩阵内容（防矩阵替换攻击）
//! - [`Ccs::compute_v_at`] — 计算 `v[j] = Σ_r eq(r_x, r) · (M_j · z)[r]`（共享工具）
//!
//! ## 实现决策
//!
//! - **扩展方式**：使用 inherent impl（非 trait ext），因 `Ccs` 与扩展在同一 crate
//! - **to_lcccs 签名**：spec 标注 `to_lcccs(z)`，但 r_x_l 是必要参数（v_l 在 r_x_l 处求值），
//!   本实现显式接受 r_x_l（见 alternatives.md）
//! - **ccs_commitment**：Blake2b 串联 hash（非 Merkle root），因矩阵数量少（t ≤ 10），
//!   串联 hash 足够防碰撞且实现简单

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::fold::ccccs::Ccccs;
use crate::fold::lcccs::{Lcccs, eq_eval};
use crate::pcs::ipa::IpaCommitment;

/// CCS 承诺域分离标签。
const CCS_COMMIT_DOMAIN: &[u8] = b"poker_zkvm_ccs_commit";

/// Hypernova 折叠所需的 CCS 扩展方法。
///
/// 这些方法在 `Ccs` 上扩展 LCCCS/CCCCS 生成与承诺计算能力。
impl Ccs {
    /// 由 CCS + witness z + r_x_l 生成 LCCCS 实例（spec SubTask 6.1.3）。
    ///
    /// # 参数
    /// - `z` — witness 向量（长度 = num_vars）
    /// - `r_x_l` — 外层 sumcheck challenge（长度 = log2(num_rows)）
    /// - `x_l` — 公共输入向量（可为空）
    ///
    /// # 返回
    /// LCCCS 实例，其中：
    /// - `u_l = 0`（初始 CCS 实例，假设 z 满足 CCS 约束；任意 r_x_l 处 u_l = 0）
    /// - `trace_l = z`
    /// - `r_x_l = r_x_l`
    /// - `v_l[j] = Σ_r eq(r_x_l, r) · (M_j · z)[r]`
    ///
    /// # 错误
    /// - `z.len() != num_vars`
    /// - `r_x_l.len() != log2(num_rows)`
    /// - 矩阵 evaluate 失败
    ///
    /// # 数学说明
    ///
    /// 对于 satisfied CCS（z 满足约束），`u_l = Σ_i c_i · Π v_l[j] = 0` 在任意 r_x_l 处成立。
    /// 这是因为 CCS 约束 `Σ_i c_i · Π ⟨M_j, z⟩ = 0` 逐行成立，
    /// 而 `v_l[j] = Σ_r eq(r_x_l, r) · (M_j · z)[r]` 是 `M_j · z` 在 r_x_l 处的多线性扩展求值，
    /// relaxed 约束 `Σ_i c_i · Π v_l[j]` 是 CCS 约束的多线性扩展在 r_x_l 处的求值。
    pub fn to_lcccs(&self, z: &[Fr], r_x_l: &[Fr], x_l: Vec<Fr>) -> Result<Lcccs, ZkvmError> {
        if z.len() != self.num_vars {
            return Err(ZkvmError::Other(format!(
                "to_lcccs: z.len() {} != num_vars {}",
                z.len(),
                self.num_vars
            )));
        }
        // 计算 v_l[j] for each j
        let v_l = self.compute_v_at(z, r_x_l)?;
        // u_l = relaxed 约束结果（对 satisfied CCS 应为 0）
        let u_l = crate::fold::lcccs::compute_relaxed_constraint(self, &v_l);
        Lcccs::new(self.clone(), u_l, x_l, z.to_vec(), r_x_l.to_vec(), v_l)
    }

    /// 由 CCS + witness z + commitment 生成 CCCCS 实例（spec SubTask 6.1.3）。
    ///
    /// # 参数
    /// - `z` — witness 向量（长度 = num_vars）
    /// - `x_c` — 公共求值点（长度 = log2(num_rows)）
    /// - `witness_commitment_c` — witness 多项式承诺（IPA G1 点）
    ///
    /// # 返回
    /// CCCCS 实例，其中：
    /// - `u_c = 0`（初始 CCS 实例，假设 z 满足 CCS 约束）
    /// - `trace_c = z`
    /// - `x_c = x_c`
    /// - `witness_commitment_c = witness_commitment_c`
    /// - **不存储 v_c**（v1.3 修正 C2-002 — v_c 是多项式，折叠时在 r_x_l 求值）
    ///
    /// # 错误
    /// - `z.len() != num_vars`
    /// - `x_c.len() != log2(num_rows)`
    pub fn to_cccs(
        &self,
        z: &[Fr],
        x_c: Vec<Fr>,
        witness_commitment_c: IpaCommitment,
    ) -> Result<Ccccs, ZkvmError> {
        if z.len() != self.num_vars {
            return Err(ZkvmError::Other(format!(
                "to_cccs: z.len() {} != num_vars {}",
                z.len(),
                self.num_vars
            )));
        }
        // u_c = 0（假设 z 满足 CCS 约束；在 x_c 处求值应为 0）
        Ccccs::new(
            self.clone(),
            Fr::zero(),
            x_c,
            z.to_vec(),
            witness_commitment_c,
        )
    }

    /// 计算 `v[j] = Σ_r eq(r_x, r) · (M_j · z)[r]`（共享工具方法）。
    ///
    /// 对每个矩阵 `j ∈ [0, num_matrices)`：
    /// 1. 计算 `M_j · z`（矩阵-向量乘积，长度 = num_rows）
    /// 2. 加权求和：`v[j] = Σ_r eq(r_x, r) · (M_j · z)[r]`
    ///
    /// 这是 LCCCS 的 v_l 和 CCCCS 的 v_c 在任意点 r_x 处的求值。
    ///
    /// # 错误
    /// - `z.len() != num_vars`
    /// - 矩阵 evaluate 失败
    pub fn compute_v_at(&self, z: &[Fr], r_x: &[Fr]) -> Result<Vec<Fr>, ZkvmError> {
        if z.len() != self.num_vars {
            return Err(ZkvmError::Other(format!(
                "compute_v_at: z.len() {} != num_vars {}",
                z.len(),
                self.num_vars
            )));
        }
        (0..self.matrices.len())
            .map(|j| self.compute_vj_at(z, r_x, j))
            .collect()
    }

    /// 计算单个 `v[j] = Σ_r eq(r_x, r) · (M_j · z)[r]`。
    fn compute_vj_at(&self, z: &[Fr], r_x: &[Fr], j: usize) -> Result<Fr, ZkvmError> {
        let mz = self.matrices[j].evaluate(z)?;
        let mut v = Fr::zero();
        for (r, &mz_r) in mz.iter().enumerate() {
            let eq_weight = eq_eval(r_x, r)?;
            v = v.add(&eq_weight.mul(&mz_r));
        }
        Ok(v)
    }

    /// 计算 CCS 承诺（Blake2b 串联 hash，绑定矩阵内容 — spec L432-434）。
    ///
    /// 防止 attacker 替换矩阵内容（v1.1 仅绑定 ccs_struct_params 尺寸，不足以防内容替换）。
    ///
    /// # 返回
    /// 32 bytes Blake2b 哈希输出。
    ///
    /// # 编码格式
    ///
    /// 串联以下数据（每段前加 8 bytes LE 长度前缀）：
    /// - `num_vars` / `num_matrices` / `num_constraints`（结构参数）
    /// - 每个矩阵：`num_rows` / `num_cols` / `entries_count` + 所有 entries
    /// - 每个 entry：`row` / `col` / `value`（32 bytes canonical）
    /// - 每个子集：`len` + 所有索引
    /// - 每个系数：32 bytes canonical
    pub fn ccs_commitment(&self) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(CCS_COMMIT_DOMAIN);

        // 结构参数
        hasher.update(&(self.num_vars as u64).to_le_bytes());
        hasher.update(&(self.matrices.len() as u64).to_le_bytes());
        hasher.update(&(self.subsets.len() as u64).to_le_bytes());

        // 每个矩阵
        for m in &self.matrices {
            hasher.update(&(m.num_rows as u64).to_le_bytes());
            hasher.update(&(m.num_cols as u64).to_le_bytes());
            hasher.update(&(m.entries.len() as u64).to_le_bytes());
            for e in &m.entries {
                hasher.update(&(e.row as u64).to_le_bytes());
                hasher.update(&(e.col as u64).to_le_bytes());
                hasher.update(&e.value.to_canonical_bytes());
            }
        }

        // 子集
        for s in &self.subsets {
            hasher.update(&(s.len() as u64).to_le_bytes());
            for &j in s {
                hasher.update(&(j as u64).to_le_bytes());
            }
        }

        // 系数
        for c in &self.coeffs {
            hasher.update(&c.to_canonical_bytes());
        }

        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
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

    /// 构造 2-row CCS：row 0 = x+y-z, row 1 = x*y-w
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

    /// 构造 stub commitment。
    fn stub_commitment() -> IpaCommitment {
        IpaCommitment(G1Affine::generator())
    }

    // ===== to_lcccs 测试 =====

    #[test]
    fn test_to_lcccs_single_row() {
        // 1-row CCS, r_x_l 为空（log2(1) = 0）
        let ccs = make_mul_ccs();
        let z = vec![f(1), f(3), f(4), f(12)]; // x=3, y=4, z_val=12

        let lcccs = ccs.to_lcccs(&z, &[], vec![]).expect("to_lcccs 应成功");

        // u_l = 0（satisfied CCS）
        assert_eq!(lcccs.u_l, Fr::zero());
        // v_l = [x, y, z_val] = [3, 4, 12]
        assert_eq!(lcccs.v_l.len(), 3);
        assert_eq!(lcccs.v_l[0], f(3));
        assert_eq!(lcccs.v_l[1], f(4));
        assert_eq!(lcccs.v_l[2], f(12));
        // LCCCS 应 satisfied
        assert!(lcccs.satisfied().unwrap());
    }

    #[test]
    fn test_to_lcccs_multi_row_at_boolean_point() {
        // 2-row CCS, r_x_l = [0]（在 row 0 处求值）
        let ccs = make_multi_row_ccs();
        let z = vec![f(1), f(3), f(4), f(7), f(12)]; // x=3, y=4, z_val=7, w_val=12

        let lcccs = ccs.to_lcccs(&z, &[f(0)], vec![]).expect("to_lcccs 应成功");

        // 在 row 0 处: v_l = [3, 4, 7, 0, 0, 0]
        // 约束 = 3 + 4 - 7 + 0*0 - 0 = 0
        assert_eq!(lcccs.u_l, Fr::zero());
        assert!(lcccs.satisfied().unwrap());

        // 在 row 1 处: r_x_l = [1]
        let lcccs2 = ccs.to_lcccs(&z, &[f(1)], vec![]).expect("to_lcccs 应成功");

        // v_l = [0, 0, 0, 3, 4, 12]
        // 约束 = 0 + 0 - 0 + 3*4 - 12 = 0
        assert_eq!(lcccs2.u_l, Fr::zero());
        assert!(lcccs2.satisfied().unwrap());
    }

    #[test]
    fn test_to_lcccs_wrong_z_length() {
        let ccs = make_mul_ccs();
        let result = ccs.to_lcccs(&[f(1), f(2), f(3)], &[], vec![]); // 长度 3 != 4
        assert!(result.is_err());
    }

    #[test]
    fn test_to_lcccs_unsatisfied_ccs() {
        // z 不满足 CCS: x*y - z_val = 12 - 13 = -1
        let ccs = make_mul_ccs();
        let z = vec![f(1), f(3), f(4), f(13)];

        let lcccs = ccs.to_lcccs(&z, &[], vec![]).expect("to_lcccs 应成功");

        // u_l = -1（relaxed 约束结果）
        assert_eq!(lcccs.u_l, neg_f(1));
        // LCCCS 仍 satisfied（u_l 与 v_l 一致）
        assert!(lcccs.satisfied().unwrap());
    }

    // ===== to_cccs 测试 =====

    #[test]
    fn test_to_cccs_single_row() {
        let ccs = make_mul_ccs();
        let z = vec![f(1), f(3), f(4), f(12)];

        let ccccs = ccs
            .to_cccs(&z, vec![], stub_commitment())
            .expect("to_cccs 应成功");

        assert_eq!(ccccs.u_c, Fr::zero());
        assert_eq!(ccccs.trace_c, z);
        assert!(ccccs.satisfied().unwrap());
    }

    #[test]
    fn test_to_cccs_multi_row() {
        let ccs = make_multi_row_ccs();
        let z = vec![f(1), f(3), f(4), f(7), f(12)];

        let ccccs = ccs
            .to_cccs(&z, vec![f(0)], stub_commitment())
            .expect("to_cccs 应成功");

        assert_eq!(ccccs.u_c, Fr::zero());
        assert!(ccccs.satisfied().unwrap());
    }

    #[test]
    fn test_to_cccs_wrong_z_length() {
        let ccs = make_mul_ccs();
        let result = ccs.to_cccs(&[f(1), f(2), f(3)], vec![], stub_commitment());
        assert!(result.is_err());
    }

    // ===== compute_v_at 测试 =====

    #[test]
    fn test_compute_v_at_single_row() {
        let ccs = make_mul_ccs();
        let z = vec![f(1), f(3), f(4), f(12)];

        let v = ccs.compute_v_at(&z, &[]).expect("compute_v_at 应成功");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], f(3)); // x
        assert_eq!(v[1], f(4)); // y
        assert_eq!(v[2], f(12)); // z_val
    }

    #[test]
    fn test_compute_v_at_multi_row_mixed_point() {
        // 2-row CCS, r_x = [0.5] → 混合 row 0 和 row 1
        let ccs = make_multi_row_ccs();
        let z = vec![f(1), f(3), f(4), f(7), f(12)];
        let half = f(2).inverse().unwrap(); // 0.5

        let v = ccs.compute_v_at(&z, &[half]).expect("compute_v_at 应成功");
        // M_0·z = [3, 0] → v[0] = 0.5*3 + 0.5*0 = 1.5
        // M_1·z = [4, 0] → v[1] = 0.5*4 + 0.5*0 = 2
        // M_2·z = [7, 0] → v[2] = 0.5*7 + 0.5*0 = 3.5
        // M_3·z = [0, 3] → v[3] = 0.5*0 + 0.5*3 = 1.5
        // M_4·z = [0, 4] → v[4] = 0.5*0 + 0.5*4 = 2
        // M_5·z = [0, 12] → v[5] = 0.5*0 + 0.5*12 = 6
        assert_eq!(v.len(), 6);
        let three_halves = f(3).mul(&half); // 1.5
        assert_eq!(v[0], three_halves);
        assert_eq!(v[1], f(2));
        let seven_halves = f(7).mul(&half); // 3.5
        assert_eq!(v[2], seven_halves);
        assert_eq!(v[3], three_halves);
        assert_eq!(v[4], f(2));
        assert_eq!(v[5], f(6));
    }

    // ===== ccs_commitment 测试 =====

    #[test]
    fn test_ccs_commitment_deterministic() {
        let ccs1 = make_mul_ccs();
        let ccs2 = make_mul_ccs();
        assert_eq!(ccs1.ccs_commitment(), ccs2.ccs_commitment());
    }

    #[test]
    fn test_ccs_commitment_different_ccs() {
        // 不同 CCS 结构应产生不同承诺
        let ccs1 = make_mul_ccs();
        let ccs2 = make_multi_row_ccs();
        assert_ne!(ccs1.ccs_commitment(), ccs2.ccs_commitment());
    }

    #[test]
    fn test_ccs_commitment_tampered_matrix() {
        // 篡改矩阵内容应改变承诺
        let ccs1 = make_mul_ccs();

        // 构造篡改版本：M_0 的 entry 值改为 2
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(2)).unwrap(); // 值 1 → 2
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();
        let ccs2 = Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0, 1], vec![2]],
            vec![f(1), neg_f(1)],
        )
        .expect("Ccs 构造应成功");

        assert_ne!(ccs1.ccs_commitment(), ccs2.ccs_commitment());
    }

    #[test]
    fn test_ccs_commitment_tampered_subset() {
        // 篡改子集应改变承诺
        let ccs1 = make_mul_ccs();

        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();
        // 篡改：S_0 = {0, 1} → {0}（去掉索引 1）
        let ccs2 = Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0], vec![2]], // S_0 改为 {0}
            vec![f(1), neg_f(1)],
        )
        .expect("Ccs 构造应成功");

        assert_ne!(ccs1.ccs_commitment(), ccs2.ccs_commitment());
    }

    #[test]
    fn test_ccs_commitment_tampered_coeff() {
        // 篡改系数应改变承诺
        let ccs1 = make_mul_ccs();

        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let mut m2 = SparseMatrix::new(1, 4);
        m2.add_entry(0, 3, f(1)).unwrap();
        // 篡改：c_0 = 1 → 2
        let ccs2 = Ccs::new(
            4,
            vec![m0, m1, m2],
            vec![vec![0, 1], vec![2]],
            vec![f(2), neg_f(1)], // c_0 改为 2
        )
        .expect("Ccs 构造应成功");

        assert_ne!(ccs1.ccs_commitment(), ccs2.ccs_commitment());
    }
}
