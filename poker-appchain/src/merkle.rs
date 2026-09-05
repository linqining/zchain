//! M1：Poseidon 增量承诺树（append-only binary Merkle）。
//!
//! 固定深度 32（容量 2^32 叶，远超 v1 需求），零叶 = `FieldElement::ZERO`。
//! 包含证明 = 兄弟哈希路径；验证在 O(depth) 内完成，客户端（wasm）可独立执行。

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::error::{AppchainError, AppchainResult};

/// 树深度（叶容量 2^32）。
pub const TREE_DEPTH: usize = 32;

/// append-only Poseidon Merkle 树。
#[derive(Debug, Clone)]
pub struct PoseidonMerkleTree {
    /// levels[0] = 叶层（最多 capacity 个），levels[d] = 上层。
    levels: Vec<Vec<FieldElement>>,
    leaf_count: u64,
}

/// 包含证明（兄弟路径，自叶向根）。ABI 用 32B 规范编码（FieldElement 无
/// borsh impl，见 ABI.md 的 felt 编码规则）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct InclusionProof {
    /// 叶在叶层的索引。
    pub leaf_index: u64,
    /// 兄弟哈希路径（长度 = depth，32B 规范编码）。
    pub siblings: Vec<[u8; 32]>,
}

impl PoseidonMerkleTree {
    /// 空树。
    #[must_use]
    pub fn new() -> Self {
        Self {
            levels: vec![Vec::new()],
            leaf_count: 0,
        }
    }

    /// 当前叶数。
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// 追加一叶，返回其索引。
    ///
    /// # Errors
    /// 超容量（实际不可达）→ [`AppchainError::OutOfRange`]。
    pub fn append(&mut self, leaf: FieldElement) -> AppchainResult<u64> {
        if self.leaf_count >= 1u64 << TREE_DEPTH {
            return Err(AppchainError::OutOfRange("merkle capacity"));
        }
        let idx = self.leaf_count;
        self.levels[0].push(leaf);
        self.rehash_path(idx as usize);
        self.leaf_count += 1;
        Ok(idx)
    }

    fn rehash_path(&mut self, mut idx: usize) {
        for depth in 0..TREE_DEPTH {
            if self.levels.len() <= depth + 1 {
                self.levels.push(Vec::new());
            }
            let level_len = self.levels[depth].len();
            let parent = idx / 2;
            let sibling = idx ^ 1;
            let sib_val = if sibling < level_len {
                self.levels[depth][sibling]
            } else {
                FieldElement::ZERO
            };
            let (l, r) = if idx % 2 == 0 {
                (self.levels[depth][idx], sib_val)
            } else {
                (sib_val, self.levels[depth][idx])
            };
            let h = poseidon_hash_many(&[l, r]);
            let upper = &mut self.levels[depth + 1];
            if parent < upper.len() {
                upper[parent] = h;
            } else {
                debug_assert_eq!(parent, upper.len());
                upper.push(h);
            }
            idx = parent;
        }
    }

    /// 当前根。
    #[must_use]
    pub fn root(&self) -> FieldElement {
        let top = self.levels.last().expect("levels never empty");
        top.first().copied().unwrap_or(FieldElement::ZERO)
    }

    /// 生成叶索引的包含证明。
    ///
    /// # Errors
    /// 索引越界 → [`AppchainError::NoteNotFound`]。
    pub fn proof(&self, leaf_index: u64) -> AppchainResult<InclusionProof> {
        if leaf_index >= self.leaf_count {
            return Err(AppchainError::NoteNotFound);
        }
        let mut cur_idx = leaf_index as usize;
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for depth in 0..TREE_DEPTH {
            let level_len = self.levels[depth].len();
            let sibling = cur_idx ^ 1;
            let sib_val = if sibling < level_len {
                self.levels[depth][sibling]
            } else {
                FieldElement::ZERO
            };
            siblings.push(crate::felt::felt_to_bytes32(&sib_val));
            cur_idx /= 2;
        }
        Ok(InclusionProof {
            leaf_index,
            siblings,
        })
    }

    /// 离线验证包含证明（客户端可执行，不依赖树实例）。
    #[must_use]
    pub fn verify_proof(
        leaf: FieldElement,
        proof: &InclusionProof,
        root: FieldElement,
    ) -> bool {
        if proof.siblings.len() != TREE_DEPTH {
            return false;
        }
        let mut idx = proof.leaf_index;
        let mut cur = leaf;
        for sib in &proof.siblings {
            // 兄弟值来自域元素的规范字节编码，≥ p 一律拒绝（fail-closed）
            let Ok(sib_felt) = crate::felt::felt_from_bytes32_exact(sib) else {
                return false;
            };
            let (l, r) = if idx % 2 == 0 {
                (cur, sib_felt)
            } else {
                (sib_felt, cur)
            };
            cur = poseidon_hash_many(&[l, r]);
            idx /= 2;
        }
        cur == root
    }
}

impl Default for PoseidonMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::felt::felt_from_u64;

    #[test]
    fn append_root_proof_roundtrip() {
        let mut t = PoseidonMerkleTree::new();
        let mut idxs = Vec::new();
        for i in 0..13u64 {
            idxs.push(t.append(felt_from_u64(i + 1)).unwrap());
        }
        let root = t.root();
        for (i, idx) in idxs.iter().enumerate() {
            let p = t.proof(*idx).unwrap();
            assert!(
                PoseidonMerkleTree::verify_proof(felt_from_u64(i as u64 + 1), &p, root),
                "leaf {i} proof must verify"
            );
        }
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut t = PoseidonMerkleTree::new();
        let i0 = t.append(felt_from_u64(1)).unwrap();
        t.append(felt_from_u64(2)).unwrap();
        let root = t.root();
        let mut p = t.proof(i0).unwrap();
        p.siblings[0] = crate::felt::felt_to_bytes32(&FieldElement::from(999u64));
        assert!(!PoseidonMerkleTree::verify_proof(
            felt_from_u64(1),
            &p,
            root
        ));
    }

    #[test]
    fn out_of_range_proof_rejected() {
        let t = PoseidonMerkleTree::new();
        assert!(t.proof(0).is_err());
    }

    #[test]
    fn roots_differ_by_insertion_history() {
        let mut a = PoseidonMerkleTree::new();
        let mut b = PoseidonMerkleTree::new();
        a.append(felt_from_u64(1)).unwrap();
        a.append(felt_from_u64(2)).unwrap();
        b.append(felt_from_u64(2)).unwrap();
        b.append(felt_from_u64(1)).unwrap();
        assert_ne!(a.root(), b.root());
    }
}
