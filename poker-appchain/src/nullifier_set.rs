//! M1：nullifier 集（防双花）。
//!
//! 集根用插入序确定性折叠：`root_0 = 0`，`root_i = poseidon(root_{i-1}, nf_i)`。
//! 折叠序 = 插入序 = WAL 重放序，所以根是重放稳定的；任何集合差异（增删）
//! 都会传播到根。

use std::collections::HashSet;

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};

/// nullifier 集合：O(1) 查重 + O(log n) 无需——根维护 O(1) 摊销（只追加）。
#[derive(Debug, Clone, Default)]
pub struct NullifierSet {
    spent: HashSet<FieldElement>,
    fold_root: FieldElement,
    /// 折叠计数（= 已花费 note 数）。
    pub spent_count: u64,
}

impl NullifierSet {
    /// 空集。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前折叠根（重放稳定）。
    #[must_use]
    pub fn root(&self) -> FieldElement {
        self.fold_root
    }

    /// 查重（不修改）。
    #[must_use]
    pub fn contains(&self, nf: &FieldElement) -> bool {
        self.spent.contains(nf)
    }

    /// 插入新 nullifier。
    ///
    /// # Errors
    /// 已存在 → [`AppchainError::DoubleSpend`]。
    pub fn insert(&mut self, nf: FieldElement) -> AppchainResult<()> {
        if !self.spent.insert(nf) {
            return Err(AppchainError::DoubleSpend);
        }
        self.fold_root = poseidon_hash_many(&[self.fold_root, nf]);
        self.spent_count += 1;
        Ok(())
    }

    /// 试插入（查重 + 插入原子化，sequencer 并发路径用）。
    ///
    /// # Errors
    /// 已存在 → [`AppchainError::DoubleSpend`]。
    pub fn try_consume(&mut self, nf: FieldElement) -> AppchainResult<bool> {
        self.insert(nf)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::felt_from_u64;

    #[test]
    fn double_spend_detected() {
        let mut s = NullifierSet::new();
        s.insert(felt_from_u64(1)).unwrap();
        assert!(s.insert(felt_from_u64(1)).is_err());
        assert!(s.contains(&felt_from_u64(1)));
    }

    #[test]
    fn root_is_insertion_order_sensitive() {
        let mut a = NullifierSet::new();
        let mut b = NullifierSet::new();
        a.insert(felt_from_u64(1)).unwrap();
        a.insert(felt_from_u64(2)).unwrap();
        b.insert(felt_from_u64(2)).unwrap();
        b.insert(felt_from_u64(1)).unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn root_is_prefix_stable() {
        // 已有序列插入新元素后，旧根不再复现（单向）。
        let mut s = NullifierSet::new();
        s.insert(felt_from_u64(7)).unwrap();
        let r1 = s.root();
        s.insert(felt_from_u64(8)).unwrap();
        let r2 = s.root();
        assert_ne!(r1, r2);
    }
}
