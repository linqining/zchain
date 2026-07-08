//! LogUp lookup 协议（Phase 5 — Task 5.6）。
//!
//! 严格遵循 spec.md L268-312 + tasks.md L153-159（v1.4 FROZEN）：
//! - [`LookupTable`] — 内置表（u8/u16 range、AND/OR/XOR 真值表）
//! - [`LogUpProof`] — 严格 Fiat-Shamir absorb 顺序：`C_T → C_f → C_m → β`
//! - 校验等式：`Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`
//!
//! # LogUp 协议概述
//!
//! LogUp（Logarithmic Universal lookup）是 lookup argument，将 lookup 验证
//! 归约为有理函数等式校验。相比传统 Plookup 的 grand product 方案，
//! LogUp 使用倒数和（sum of reciprocals），在多表场景下更高效。
//!
//! ## 角色
//!
//! - **Table** `T = [t_0, ..., t_{N-1}]` — 查找表（合法值集合）
//! - **Witness** `F = [f_0, ..., f_{M-1}]` — 执行 trace 中的 lookup 输入
//! - **Multiplicity** `M = [m_0, ..., m_{N-1}]` — 每个表项被引用的次数
//!
//! ## 核心等式
//!
//! ```text
//! Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)
//! ```
//!
//! 其中 `β` 是在承诺后派生的 challenge。
//!
//! ## 严格 absorb 顺序（防 β 操纵攻击）
//!
//! 1. Prover 计算并承诺 `C_T = commit(T)`, `C_f = commit(F)`, `C_m = commit(M)`
//! 2. `transcript.absorb(LOOKUP_TAG || C_T)`
//! 3. `transcript.absorb(LOOKUP_TAG || C_f)`
//! 4. `transcript.absorb(LOOKUP_TAG || C_m)`
//! 5. `β ← transcript.challenge(LOOKUP_TAG)`
//!
//! **β 必须在 witness 承诺之后派生**，防止 prover 看到 β 后调整 multiplicity。
//!
//! # MVP 范围
//!
//! - 承诺使用 Blake2b hash-to-field（binding，collision-resistant）
//! - 生产环境应替换为 Pedersen 向量承诺（`pcs/ipa.rs`）
//! - `to_ccs_instance()` 提供简化 CCS 编码（单行 `lhs - rhs = 0`），
//!   完整 per-entry binding（inv 变量）留待 Hypernova 折叠集成阶段

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::ccs::{Ccs, CcsInstance, Fr, SparseMatrix};
use crate::error::ZkvmError;
use crate::field::ZkvmField;
use crate::transcript::{Transcript, LOOKUP_DOMAIN_TAG};

/// 承诺域分离标签（内部使用，与 transcript 的 domain_tag 区分）。
const COMMIT_DOMAIN: &[u8] = b"poker_zkvm_lookup_commit";

/// 计算域元素切片的承诺（binding hash-to-field）。
///
/// 使用 Blake2b 将任意长度域元素切片映射为单个域元素。
/// 承诺是 binding 的：找到两个不同切片产生相同承诺等价于 Blake2b 碰撞。
///
/// 生产环境应替换为 Pedersen 向量承诺（`pcs/ipa.rs`）。
fn commit_field_slice(elems: &[Fr]) -> Fr {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(COMMIT_DOMAIN);
    let len = elems.len() as u32;
    hasher.update(&len.to_le_bytes());
    for elem in elems {
        hasher.update(&elem.to_canonical_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    Fr::from_canonical_bytes(&out).expect("32 bytes Blake2b 输出应能转为域元素")
}

/// Lookup 表。
///
/// 包含合法值集合 `t_0, ..., t_{N-1}`，witness 中的每个值必须出现在表中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTable {
    /// 表项列表 `t_0, ..., t_{N-1}`。
    pub entries: Vec<Fr>,
}

impl LookupTable {
    /// 创建空表。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// 从切片创建表。
    #[must_use]
    pub fn from_entries(entries: Vec<Fr>) -> Self {
        Self { entries }
    }

    /// u8 range 表（`0..=255`）。
    ///
    /// 用于 range check：witness 中的值必须在 `[0, 255]` 范围内。
    #[must_use]
    pub fn u8_range() -> Self {
        Self {
            entries: (0..=255u32).map(Fr::from_u32_with_wrap).collect(),
        }
    }

    /// u16 range 表（`0..=65535`）。
    ///
    /// 用于 range check：witness 中的值必须在 `[0, 65535]` 范围内。
    #[must_use]
    pub fn u16_range() -> Self {
        Self {
            entries: (0..=65535u32).map(Fr::from_u32_with_wrap).collect(),
        }
    }

    /// AND 真值表。
    ///
    /// 4 个条目，每条编码为 `t = (x << 2) | (y << 1) | (x & y)`，
    /// 其中 `x, y ∈ {0, 1}`。
    ///
    /// witness 中的值 `f = (x << 2) | (y << 1) | result`，
    /// 查找成功等价于 `result == x & y`。
    #[must_use]
    pub fn and_truth_table() -> Self {
        let mut entries = Vec::with_capacity(4);
        for x in 0..=1u32 {
            for y in 0..=1u32 {
                let result = x & y;
                let packed = (x << 2) | (y << 1) | result;
                entries.push(Fr::from_u32_with_wrap(packed));
            }
        }
        Self { entries }
    }

    /// OR 真值表。
    ///
    /// 4 个条目，编码 `t = (x << 2) | (y << 1) | (x | y)`。
    #[must_use]
    pub fn or_truth_table() -> Self {
        let mut entries = Vec::with_capacity(4);
        for x in 0..=1u32 {
            for y in 0..=1u32 {
                let result = x | y;
                let packed = (x << 2) | (y << 1) | result;
                entries.push(Fr::from_u32_with_wrap(packed));
            }
        }
        Self { entries }
    }

    /// XOR 真值表。
    ///
    /// 4 个条目，编码 `t = (x << 2) | (y << 1) | (x ^ y)`。
    #[must_use]
    pub fn xor_truth_table() -> Self {
        let mut entries = Vec::with_capacity(4);
        for x in 0..=1u32 {
            for y in 0..=1u32 {
                let result = x ^ y;
                let packed = (x << 2) | (y << 1) | result;
                entries.push(Fr::from_u32_with_wrap(packed));
            }
        }
        Self { entries }
    }

    /// 表长度。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 计算表承诺 `C_T`。
    #[must_use]
    pub fn commitment(&self) -> Fr {
        commit_field_slice(&self.entries)
    }

    /// 查找值在表中的索引（首个匹配），未找到返回 `None`。
    pub fn find(&self, value: &Fr) -> Option<usize> {
        self.entries.iter().position(|t| t == value)
    }
}

impl Default for LookupTable {
    fn default() -> Self {
        Self::new()
    }
}

/// LogUp 承诺三元组 `(C_T, C_f, C_m)`。
///
/// Verifier 通过此三元组重算 β 并校验承诺一致。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogUpCommitments {
    /// 表承诺 `C_T`。
    pub c_t: Fr,
    /// witness 承诺 `C_f`。
    pub c_f: Fr,
    /// multiplicity 承诺 `C_m`。
    pub c_m: Fr,
}

/// LogUp lookup 证明。
///
/// 包含 table、witness、multiplicity 与 β challenge。
/// 通过严格 Fiat-Shamir absorb 顺序确保 soundness。
#[derive(Debug, Clone)]
pub struct LogUpProof {
    /// 表项 `t_0, ..., t_{N-1}`。
    pub table: Vec<Fr>,
    /// witness 流 `f_0, ..., f_{M-1}`（执行 trace 中的 lookup 输入）。
    pub witness: Vec<Fr>,
    /// multiplicity `m_0, ..., m_{N-1}`（每个表项被引用的次数）。
    pub multiplicity: Vec<Fr>,
    /// β challenge（在 witness 承诺后派生）。
    pub beta: Fr,
}

impl LogUpProof {
    /// Prover 端：创建 LogUp 证明。
    ///
    /// 严格 absorb 顺序（spec L155）：
    /// 1. 计算承诺 `C_T = commit(table)`, `C_f = commit(witness)`, `C_m = commit(multiplicity)`
    /// 2. `transcript.absorb(LOOKUP_TAG || C_T)`
    /// 3. `transcript.absorb(LOOKUP_TAG || C_f)`
    /// 4. `transcript.absorb(LOOKUP_TAG || C_m)`
    /// 5. `β ← transcript.challenge(LOOKUP_TAG)`
    ///
    /// # 错误
    /// - `table.len() != multiplicity.len()` 返回 `ZkvmError::Other`
    ///
    /// # 返回
    /// `(LogUpProof, LogUpCommitments)` — 证明与承诺三元组
    pub fn create(
        table: Vec<Fr>,
        witness: Vec<Fr>,
        multiplicity: Vec<Fr>,
    ) -> Result<(Self, LogUpCommitments), ZkvmError> {
        if table.len() != multiplicity.len() {
            return Err(ZkvmError::Other(format!(
                "LogUpProof::create: table.len() {} != multiplicity.len() {}",
                table.len(),
                multiplicity.len()
            )));
        }

        // 1. 计算承诺（binding hash-to-field）
        let c_t = commit_field_slice(&table);
        let c_f = commit_field_slice(&witness);
        let c_m = commit_field_slice(&multiplicity);

        // 2-5. 严格 absorb 顺序 + β 派生
        let mut transcript = Transcript::new();
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &c_t);
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &c_f);
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &c_m);
        let beta = transcript.challenge(LOOKUP_DOMAIN_TAG);

        Ok((
            Self {
                table,
                witness,
                multiplicity,
                beta,
            },
            LogUpCommitments { c_t, c_f, c_m },
        ))
    }

    /// Verifier 端：校验 LogUp 等式。
    ///
    /// 校验步骤：
    /// 1. 重算 β（严格 absorb 顺序）并比对
    /// 2. 校验承诺一致（table/witness/multiplicity 与 `C_T/C_f/C_m` 匹配）
    /// 3. 校验等式 `Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`
    ///
    /// # 错误
    /// - `β` 与 `t_i` 或 `f_j` 碰撞（`denom = 0`）返回 `ZkvmError::Other`
    /// - `table.len() != multiplicity.len()` 返回 `ZkvmError::Other`
    pub fn verify(&self, commits: &LogUpCommitments) -> Result<bool, ZkvmError> {
        // 1. 重算 β（严格顺序）
        let mut transcript = Transcript::new();
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &commits.c_t);
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &commits.c_f);
        transcript.absorb_field(LOOKUP_DOMAIN_TAG, &commits.c_m);
        let beta_expected = transcript.challenge(LOOKUP_DOMAIN_TAG);

        if beta_expected != self.beta {
            return Ok(false);
        }

        // 2. 校验承诺一致（binding check）
        if commit_field_slice(&self.table) != commits.c_t {
            return Ok(false);
        }
        if commit_field_slice(&self.witness) != commits.c_f {
            return Ok(false);
        }
        if commit_field_slice(&self.multiplicity) != commits.c_m {
            return Ok(false);
        }

        // 3. 校验 LogUp 等式
        self.verify_equation()
    }

    /// 校验 LogUp 核心等式：`Σ_i m_i / (β - t_i) == Σ_j 1 / (β - f_j)`。
    ///
    /// 使用域元素逆元计算有理函数求值。
    ///
    /// # 错误
    /// - `β` 与 `t_i` 或 `f_j` 碰撞（`denom = 0`）返回 `ZkvmError::Other`
    /// - `table.len() != multiplicity.len()` 返回 `ZkvmError::Other`
    pub fn verify_equation(&self) -> Result<bool, ZkvmError> {
        if self.table.len() != self.multiplicity.len() {
            return Err(ZkvmError::Other(format!(
                "LogUpProof::verify_equation: table.len() {} != multiplicity.len() {}",
                self.table.len(),
                self.multiplicity.len()
            )));
        }

        // LHS = Σ_i m_i / (β - t_i)
        let mut lhs = Fr::zero();
        for (t, m) in self.table.iter().zip(&self.multiplicity) {
            let denom = self.beta.sub(t);
            if denom.is_zero() {
                return Err(ZkvmError::Other(
                    "LogUpProof::verify_equation: β 与 t_i 碰撞（denom = 0）".to_string(),
                ));
            }
            let inv = denom.inverse().ok_or_else(|| {
                ZkvmError::Other(
                    "LogUpProof::verify_equation: (β - t_i) 逆元不存在".to_string(),
                )
            })?;
            lhs = lhs.add(&m.mul(&inv));
        }

        // RHS = Σ_j 1 / (β - f_j)
        let mut rhs = Fr::zero();
        for f in &self.witness {
            let denom = self.beta.sub(f);
            if denom.is_zero() {
                return Err(ZkvmError::Other(
                    "LogUpProof::verify_equation: β 与 f_j 碰撞（denom = 0）".to_string(),
                ));
            }
            let inv = denom.inverse().ok_or_else(|| {
                ZkvmError::Other(
                    "LogUpProof::verify_equation: (β - f_j) 逆元不存在".to_string(),
                )
            })?;
            rhs = rhs.add(&inv);
        }

        Ok(lhs == rhs)
    }

    /// 转为 CCS 实例（附加 CCS 实例，可被 Hypernova 折叠）。
    ///
    /// MVP 编码：单行约束 `lhs - rhs = 0`，witness = `[1, lhs_sum, rhs_sum]`。
    ///
    /// 完整 per-entry binding（inv 变量 + `(β - t_i) * inv_t_i - 1 = 0` 约束）
    /// 留待 Hypernova 折叠集成阶段实现。
    ///
    /// # 错误
    /// - `β` 碰撞或逆元不存在返回 `ZkvmError::Other`
    pub fn to_ccs_instance(&self) -> Result<CcsInstance, ZkvmError> {
        // 计算 lhs = Σ_i m_i / (β - t_i)
        let mut lhs = Fr::zero();
        for (t, m) in self.table.iter().zip(&self.multiplicity) {
            let denom = self.beta.sub(t);
            if denom.is_zero() {
                return Err(ZkvmError::Other(
                    "to_ccs_instance: β 与 t_i 碰撞".to_string(),
                ));
            }
            let inv = denom
                .inverse()
                .ok_or_else(|| ZkvmError::Other("to_ccs_instance: 逆元不存在".to_string()))?;
            lhs = lhs.add(&m.mul(&inv));
        }

        // 计算 rhs = Σ_j 1 / (β - f_j)
        let mut rhs = Fr::zero();
        for f in &self.witness {
            let denom = self.beta.sub(f);
            if denom.is_zero() {
                return Err(ZkvmError::Other(
                    "to_ccs_instance: β 与 f_j 碰撞".to_string(),
                ));
            }
            let inv = denom
                .inverse()
                .ok_or_else(|| ZkvmError::Other("to_ccs_instance: 逆元不存在".to_string()))?;
            rhs = rhs.add(&inv);
        }

        // CCS: witness z = [1, lhs, rhs], 约束 lhs - rhs = 0
        // 矩阵 M_lhs 在 (0,1)=1, M_rhs 在 (0,2)=1
        // subset S_0={0} c_0=+1 (lhs), S_1={1} c_1=-1 (rhs)
        let mut m_lhs = SparseMatrix::new(1, 3);
        m_lhs.add_entry(0, 1, Fr::one()).expect("M_lhs 构造应成功");

        let mut m_rhs = SparseMatrix::new(1, 3);
        m_rhs.add_entry(0, 2, Fr::one()).expect("M_rhs 构造应成功");

        let neg_one = Fr::zero().sub(&Fr::one());

        let ccs = Ccs::new(
            3,
            vec![m_lhs, m_rhs],
            vec![vec![0], vec![1]],
            vec![Fr::one(), neg_one],
        )
        .expect("LogUp CCS 构造应成功");

        let witness = vec![Fr::one(), lhs, rhs];
        let public_inputs = vec![self.beta];

        CcsInstance::new(ccs, witness, public_inputs)
    }
}

/// 从 witness 流计算 multiplicity（prover 辅助函数）。
///
/// 遍历 witness，统计每个表项被引用的次数。
/// 每个 witness 值匹配首个相等的表项（线性扫描）。
///
/// # 参数
/// - `table` — lookup 表
/// - `witness` — lookup 输入流
///
/// # 返回
/// 长度等于 `table.len()` 的 multiplicity 向量
#[must_use]
pub fn compute_multiplicity(table: &LookupTable, witness: &[Fr]) -> Vec<Fr> {
    let mut multiplicity = vec![Fr::zero(); table.entries.len()];
    for f in witness {
        for (i, t) in table.entries.iter().enumerate() {
            if f == t {
                multiplicity[i] = multiplicity[i].add(&Fr::one());
                break;
            }
        }
    }
    multiplicity
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助：构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    // ===== commit_field_slice 测试 =====

    #[test]
    fn test_commit_deterministic() {
        let elems = vec![f(1), f(2), f(3)];
        assert_eq!(commit_field_slice(&elems), commit_field_slice(&elems));
    }

    #[test]
    fn test_commit_different_input() {
        let a = vec![f(1), f(2)];
        let b = vec![f(1), f(3)];
        assert_ne!(commit_field_slice(&a), commit_field_slice(&b));
    }

    #[test]
    fn test_commit_different_length() {
        let a = vec![f(1), f(2)];
        let b = vec![f(1), f(2), f(3)];
        assert_ne!(commit_field_slice(&a), commit_field_slice(&b));
    }

    #[test]
    fn test_commit_empty() {
        let c = commit_field_slice(&[]);
        // 空切片应产生有效承诺（非零，因有 domain prefix）
        assert_ne!(c, Fr::zero());
    }

    // ===== LookupTable 测试 =====

    #[test]
    fn test_lookup_table_new() {
        let t = LookupTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn test_lookup_table_from_entries() {
        let entries = vec![f(10), f(20), f(30)];
        let t = LookupTable::from_entries(entries.clone());
        assert_eq!(t.len(), 3);
        assert_eq!(t.entries, entries);
    }

    #[test]
    fn test_lookup_table_u8_range() {
        let t = LookupTable::u8_range();
        assert_eq!(t.len(), 256);
        // 首项 = 0
        assert_eq!(t.entries[0], Fr::zero());
        // 末项 = 255
        assert_eq!(t.entries[255], f(255));
        // 中间项 = 128
        assert_eq!(t.entries[128], f(128));
    }

    #[test]
    fn test_lookup_table_u16_range() {
        let t = LookupTable::u16_range();
        assert_eq!(t.len(), 65536);
        assert_eq!(t.entries[0], Fr::zero());
        assert_eq!(t.entries[65535], f(65535));
    }

    #[test]
    fn test_lookup_table_and_truth_table() {
        let t = LookupTable::and_truth_table();
        assert_eq!(t.len(), 4);
        // packed = (x << 2) | (y << 1) | (x & y)
        // (x=0, y=0) → result=0, packed = 0b000 = 0
        assert_eq!(t.entries[0], f(0));
        // (x=0, y=1) → result=0, packed = 0b010 = 2
        assert_eq!(t.entries[1], f(2));
        // (x=1, y=0) → result=0, packed = 0b100 = 4
        assert_eq!(t.entries[2], f(4));
        // (x=1, y=1) → result=1, packed = 0b111 = 7
        assert_eq!(t.entries[3], f(7));
    }

    #[test]
    fn test_lookup_table_or_truth_table() {
        let t = LookupTable::or_truth_table();
        assert_eq!(t.len(), 4);
        // (0,0) → 0, packed = 0b000 = 0
        assert_eq!(t.entries[0], f(0));
        // (0,1) → 1, packed = 0b011 = 3
        assert_eq!(t.entries[1], f(3));
        // (1,0) → 1, packed = 0b101 = 5
        assert_eq!(t.entries[2], f(5));
        // (1,1) → 1, packed = 0b111 = 7
        assert_eq!(t.entries[3], f(7));
    }

    #[test]
    fn test_lookup_table_xor_truth_table() {
        let t = LookupTable::xor_truth_table();
        assert_eq!(t.len(), 4);
        // (0,0) → 0, packed = 0b000 = 0
        assert_eq!(t.entries[0], f(0));
        // (0,1) → 1, packed = 0b011 = 3
        assert_eq!(t.entries[1], f(3));
        // (1,0) → 1, packed = 0b101 = 5
        assert_eq!(t.entries[2], f(5));
        // (1,1) → 0, packed = 0b110 = 6
        assert_eq!(t.entries[3], f(6));
    }

    #[test]
    fn test_lookup_table_commitment() {
        let t1 = LookupTable::from_entries(vec![f(1), f(2)]);
        let t2 = LookupTable::from_entries(vec![f(1), f(2)]);
        let t3 = LookupTable::from_entries(vec![f(1), f(3)]);
        assert_eq!(t1.commitment(), t2.commitment());
        assert_ne!(t1.commitment(), t3.commitment());
    }

    #[test]
    fn test_lookup_table_find() {
        let t = LookupTable::from_entries(vec![f(10), f(20), f(30)]);
        assert_eq!(t.find(&f(20)), Some(1));
        assert_eq!(t.find(&f(99)), None);
    }

    // ===== compute_multiplicity 测试 =====

    #[test]
    fn test_compute_multiplicity_basic() {
        let table = LookupTable::from_entries(vec![f(1), f(2), f(3)]);
        // witness: [1, 2, 2, 3, 3, 3]
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let m = compute_multiplicity(&table, &witness);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0], f(1), "t=1 被引用 1 次");
        assert_eq!(m[1], f(2), "t=2 被引用 2 次");
        assert_eq!(m[2], f(3), "t=3 被引用 3 次");
    }

    #[test]
    fn test_compute_multiplicity_zero_refs() {
        let table = LookupTable::from_entries(vec![f(1), f(2), f(3)]);
        // witness: [1, 1] — t=3 未被引用
        let witness = vec![f(1), f(1)];
        let m = compute_multiplicity(&table, &witness);
        assert_eq!(m[0], f(2));
        assert_eq!(m[1], Fr::zero());
        assert_eq!(m[2], Fr::zero(), "t=3 multiplicity 应为 0");
    }

    #[test]
    fn test_compute_multiplicity_empty_witness() {
        let table = LookupTable::from_entries(vec![f(1), f(2)]);
        let m = compute_multiplicity(&table, &[]);
        assert_eq!(m, vec![Fr::zero(), Fr::zero()]);
    }

    // ===== LogUpProof::create + verify 正例测试 =====

    #[test]
    fn test_logup_create_basic() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (proof, commits) = LogUpProof::create(table, witness, multiplicity).expect("create");
        assert_eq!(proof.table.len(), 3);
        assert_eq!(proof.witness.len(), 6);
        assert_eq!(proof.multiplicity.len(), 3);
        // β 应非零（challenge 几乎不可能为 0）
        assert!(!proof.beta.is_zero());
        // 承诺应非零
        assert!(!commits.c_t.is_zero());
        assert!(!commits.c_f.is_zero());
        assert!(!commits.c_m.is_zero());
    }

    #[test]
    fn test_logup_verify_positive() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (proof, commits) = LogUpProof::create(table, witness, multiplicity).expect("create");
        assert!(proof.verify(&commits).expect("verify"));
    }

    #[test]
    fn test_logup_verify_m_i_zero() {
        // m_i = 0 的合法边界情况：t=3 未被引用
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2)];
        let multiplicity = vec![f(1), f(2), f(0)]; // m_2 = 0

        let (proof, commits) = LogUpProof::create(table, witness, multiplicity).expect("create");
        assert!(proof.verify(&commits).expect("verify"));
    }

    #[test]
    fn test_logup_verify_empty_witness() {
        // 空 witness：所有 m_i = 0，LHS = 0，RHS = 0
        let table = vec![f(1), f(2)];
        let witness = vec![];
        let multiplicity = vec![f(0), f(0)];

        let (proof, commits) = LogUpProof::create(table, witness, multiplicity).expect("create");
        assert!(proof.verify(&commits).expect("verify"));
    }

    #[test]
    fn test_logup_verify_with_u8_range_table() {
        // 端到端：u8 range 表 + 少量 witness
        let table = LookupTable::u8_range();
        let witness = vec![f(0), f(128), f(255), f(42), f(42)];
        let multiplicity = compute_multiplicity(&table, &witness);

        let (proof, commits) =
            LogUpProof::create(table.entries, witness, multiplicity).expect("create");
        assert!(proof.verify(&commits).expect("verify"));
    }

    #[test]
    fn test_logup_verify_with_xor_truth_table() {
        // 端到端：XOR 真值表
        let table = LookupTable::xor_truth_table();
        // witness: (0,0)→0, (1,1)→0, (0,1)→1
        let witness = vec![f(0), f(6), f(3)];
        let multiplicity = compute_multiplicity(&table, &witness);

        let (proof, commits) =
            LogUpProof::create(table.entries, witness, multiplicity).expect("create");
        assert!(proof.verify(&commits).expect("verify"));
    }

    #[test]
    fn test_logup_verify_equation_directly() {
        // 直接验证等式（不经承诺）
        let table = vec![f(1), f(2)];
        let witness = vec![f(1), f(2), f(2)];
        let multiplicity = vec![f(1), f(2)];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");
        assert!(proof.verify_equation().expect("verify_equation"));
    }

    #[test]
    fn test_logup_create_length_mismatch() {
        let table = vec![f(1), f(2)];
        let witness = vec![f(1)];
        let multiplicity = vec![f(1)]; // 长度 != table.len()

        let result = LogUpProof::create(table, witness, multiplicity);
        assert!(result.is_err(), "table.len() != multiplicity.len() 应返回错误");
    }

    // ===== soundness 负例测试 =====

    #[test]
    fn test_logup_soundness_tampered_table() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (mut proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("create");
        // 篡改 table（与承诺不一致）
        proof.table[0] = f(99);
        assert!(
            !proof.verify(&commits).expect("verify"),
            "篡改 table 后应验证失败（承诺不匹配）"
        );
    }

    #[test]
    fn test_logup_soundness_tampered_witness() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (mut proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("create");
        // 篡改 witness（与承诺不一致）
        proof.witness[0] = f(99);
        assert!(
            !proof.verify(&commits).expect("verify"),
            "篡改 witness 后应验证失败（承诺不匹配）"
        );
    }

    #[test]
    fn test_logup_soundness_tampered_multiplicity() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (mut proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("create");
        // 篡改 multiplicity（与承诺不一致）
        proof.multiplicity[0] = f(99);
        assert!(
            !proof.verify(&commits).expect("verify"),
            "篡改 multiplicity 后应验证失败（承诺不匹配）"
        );
    }

    #[test]
    fn test_logup_soundness_forged_multiplicity() {
        // 伪造 multiplicity：prover 试图用错误的 multiplicity 通过验证
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let correct_mult = vec![f(1), f(2), f(3)];
        let forged_mult = vec![f(1), f(1), f(3)]; // m_1 从 2 改为 1

        // 用正确的 multiplicity 创建证明 + 承诺
        let (proof, commits) =
            LogUpProof::create(table.clone(), witness.clone(), correct_mult).expect("create");

        // 用伪造的 multiplicity 创建另一个证明（但使用原承诺）
        let mut forged_proof = proof.clone();
        forged_proof.multiplicity = forged_mult.clone();

        // 验证应失败：multiplicity 与 C_m 承诺不匹配
        assert!(
            !forged_proof.verify(&commits).expect("verify"),
            "伪造 multiplicity 应验证失败（承诺不匹配）"
        );

        // 即使单独创建新承诺，等式也不成立（multiplicity 与 witness 不对应）
        let (forged_proof2, forged_commits) =
            LogUpProof::create(table, witness, forged_mult).expect("create");
        assert!(
            !forged_proof2.verify_equation().expect("verify_equation"),
            "伪造 multiplicity 即使重新承诺，等式也应不成立"
        );
        assert!(
            !forged_proof2.verify(&forged_commits).expect("verify"),
            "重新承诺后承诺一致，但等式不成立 → verify 应返回 false"
        );
    }

    #[test]
    fn test_logup_soundness_beta_timing_attack() {
        // β 派生时机攻击：prover 在看到 β 后调整 multiplicity
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let correct_mult = vec![f(1), f(2), f(3)];

        // 正常创建
        let (proof, commits) =
            LogUpProof::create(table, witness, correct_mult).expect("create");
        let original_beta = proof.beta;

        // 攻击者试图用不同 multiplicity 但保留原 β
        let forged_mult = vec![f(2), f(1), f(3)];
        let mut attack_proof = proof.clone();
        attack_proof.multiplicity = forged_mult;

        // 验证应失败：multiplicity 与 C_m 不匹配
        assert!(
            !attack_proof.verify(&commits).expect("verify"),
            "β 时机攻击：篡改 multiplicity 后承诺不匹配"
        );

        // β 未变（证明攻击者保留了原 β）
        assert_eq!(attack_proof.beta, original_beta);
    }

    #[test]
    fn test_logup_soundness_beta_recomputed_differs() {
        // 验证：不同承诺序列产生不同 β
        let table = vec![f(1), f(2)];
        let witness1 = vec![f(1), f(2)];
        let witness2 = vec![f(1), f(1)];
        let mult1 = vec![f(1), f(1)];
        let mult2 = vec![f(2), f(0)];

        let (proof1, _) = LogUpProof::create(table.clone(), witness1, mult1).expect("create");
        let (proof2, _) = LogUpProof::create(table, witness2, mult2).expect("create");

        // 不同 witness/multiplicity → 不同 C_f/C_m → 不同 β
        assert_ne!(
            proof1.beta, proof2.beta,
            "不同承诺应产生不同 β（防止 β 操纵）"
        );
    }

    #[test]
    fn test_logup_soundness_wrong_commits() {
        // 使用错误的承诺三元组验证
        let table = vec![f(1), f(2)];
        let witness = vec![f(1), f(2)];
        let multiplicity = vec![f(1), f(1)];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");

        // 构造错误的承诺（全零）
        let wrong_commits = LogUpCommitments {
            c_t: Fr::zero(),
            c_f: Fr::zero(),
            c_m: Fr::zero(),
        };

        // 验证应失败：重算 β 不匹配
        assert!(
            !proof.verify(&wrong_commits).expect("verify"),
            "错误承诺应使 β 重算不匹配"
        );
    }

    #[test]
    fn test_logup_soundness_witness_not_in_table() {
        // witness 包含不在表中的值 → multiplicity 全 0 但 witness 非空
        // 等式不成立：LHS = 0, RHS ≠ 0
        let table = vec![f(1), f(2)];
        let witness = vec![f(99)]; // 99 不在表中
        let multiplicity = vec![f(0), f(0)]; // 全 0（因 witness 不匹配任何表项）

        let (proof, commits) =
            LogUpProof::create(table, witness, multiplicity).expect("create");
        // 承诺一致，β 一致，但等式不成立
        assert!(
            !proof.verify(&commits).expect("verify"),
            "witness 不在表中时等式应不成立（LHS=0, RHS≠0）"
        );
    }

    // ===== to_ccs_instance 测试 =====

    #[test]
    fn test_logup_to_ccs_instance_satisfied() {
        let table = vec![f(1), f(2), f(3)];
        let witness = vec![f(1), f(2), f(2), f(3), f(3), f(3)];
        let multiplicity = vec![f(1), f(2), f(3)];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");
        let instance = proof.to_ccs_instance().expect("to_ccs_instance");
        assert!(instance.is_satisfied().expect("is_satisfied"));
        // 公共输入为 β
        assert_eq!(instance.public_inputs.len(), 1);
        assert_eq!(instance.public_inputs[0], proof.beta);
    }

    #[test]
    fn test_logup_to_ccs_instance_structure() {
        let table = vec![f(1), f(2)];
        let witness = vec![f(1), f(2)];
        let multiplicity = vec![f(1), f(1)];

        let (proof, _) = LogUpProof::create(table, witness, multiplicity).expect("create");
        let instance = proof.to_ccs_instance().expect("to_ccs_instance");

        assert_eq!(instance.ccs.num_vars, 3, "witness 应为 3 变量 [1, lhs, rhs]");
        assert_eq!(instance.ccs.num_matrices(), 2);
        assert_eq!(instance.ccs.num_constraints(), 2);
        assert_eq!(instance.ccs.num_rows(), 1);
    }

    // ===== Default impl 测试 =====

    #[test]
    fn test_lookup_table_default() {
        let t = LookupTable::default();
        assert!(t.is_empty());
    }
}
