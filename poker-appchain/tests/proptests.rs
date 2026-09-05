//! M1-ACC-1 属性测试：任意插入/消费序列下包含证明正确、nullifier 全局唯一。

use proptest::prelude::*;

use poker_appchain::felt::felt_from_u64;
use poker_appchain::merkle::PoseidonMerkleTree;
use poker_appchain::nullifier_set::NullifierSet;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn merkle_proofs_survive_any_append_order(insertions in proptest::collection::vec(any::<u64>(), 1..80)) {
        let mut tree = PoseidonMerkleTree::new();
        let mut idxs = Vec::with_capacity(insertions.len());
        for (i, v) in insertions.iter().enumerate() {
            let idx = tree.append(felt_from_u64((*v).wrapping_add(i as u64 | 1))).unwrap();
            idxs.push(idx);
        }
        let root = tree.root();
        for (i, idx) in idxs.iter().enumerate() {
            let p = tree.proof(*idx).unwrap();
            prop_assert!(
                PoseidonMerkleTree::verify_proof(
                    felt_from_u64((insertions[i]).wrapping_add(i as u64 | 1)),
                    &p,
                    root
                ),
                "leaf {i} proof must verify against final root"
            );
        }
    }

    #[test]
    fn nullifier_set_rejects_any_duplicate(values in proptest::collection::vec(any::<u64>(), 1..60)) {
        let mut set = NullifierSet::new();
        let mut seen = std::collections::HashSet::new();
        for v in values {
            let f = felt_from_u64(v);
            if seen.insert(v) {
                set.insert(f).unwrap();
                prop_assert!(set.contains(&f));
            } else {
                prop_assert!(matches!(
                    set.insert(f),
                    Err(poker_appchain::AppchainError::DoubleSpend)
                ));
            }
        }
    }
}
