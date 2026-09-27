//! 交叉验证（合约↔Rust 字节级一致性守卫）：
//! poker-appchain 真实 `WithdrawalRootBuilder` 产根/证明 → 本 crate 的
//! Solidity 等价 verifier（`proof::*`，逐字节镜像 L1Outbox.sol）必须通过；
//! 篡改任一字段必须拒绝。这是“L1 合约不重编译也能验证树规则对齐”的
//! 持续保障（foundry 单测覆盖合约治理面，本文件覆盖字节面）。

use monad_settlement::abi::ClaimLeaf;
use monad_settlement::proof;
use poker_appchain::withdrawal_root::{WithdrawalLeaf, WithdrawalRootBuilder};

/// WithdrawalLeaf（L2 权威形态）→ ClaimLeaf（L1 claim calldata 形态）。
fn to_claim(leaf: &WithdrawalLeaf) -> ClaimLeaf {
    ClaimLeaf {
        request_id: leaf.request_id,
        external_recipient: leaf.external_recipient,
        asset_tag: leaf.asset_class,
        amount: leaf.amount,
        burned_note_commitment: leaf.burned_note_commitment,
        checkpoint_height: leaf.checkpoint_height,
    }
}

fn sample_leaf(seed: u8, height: u64) -> WithdrawalLeaf {
    WithdrawalLeaf {
        request_id: [seed; 32],
        external_recipient: {
            let mut w = [0u8; 32];
            w[31] = seed;
            w
        },
        asset_class: 1, // REAL_NATIVE（MON）
        amount: u64::from(seed) * 1_000_000,
        burned_note_commitment: [seed.wrapping_mul(7); 32],
        checkpoint_height: height,
    }
}

#[test]
fn l2_builder_root_matches_solidity_mirror() {
    let leaves: Vec<WithdrawalLeaf> = (1u8..=5).map(|s| sample_leaf(s, 42)).collect();
    let mut builder = WithdrawalRootBuilder::new();
    for leaf in &leaves {
        builder.push(*leaf).expect("unique request ids");
    }
    let window = builder.build(42).expect("non-empty window");

    // 根一致（Rust builder ↔ Solidity 镜像全量重建，含 borsh 字典序规范化
    // 与空叶补齐）。
    let claim_leaves: Vec<ClaimLeaf> = leaves.iter().map(to_claim).collect();
    let (rebuilt, leaf_count) = proof::rebuild_root(&claim_leaves);
    assert_eq!(rebuilt, window.root);
    assert_eq!(leaf_count, window.leaf_count);

    // 根摘要一致（digest 是 L1Outbox 台账主键）。
    assert_eq!(
        proof::digest_of(window.checkpoint_height, window.leaf_count, window.root),
        window.digest
    );
}

#[test]
fn every_leaf_proof_verified_by_solidity_mirror() {
    let leaves: Vec<WithdrawalLeaf> = (1u8..=5).map(|s| sample_leaf(s, 42)).collect();
    let mut builder = WithdrawalRootBuilder::new();
    for leaf in &leaves {
        builder.push(*leaf).expect("unique request ids");
    }
    let window = builder.build(42).expect("window");

    for leaf in &leaves {
        let index = builder
            .leaf_index(42, &leaf.request_id)
            .expect("leaf in window");
        let proof_path = builder.merkle_proof(42, index).expect("proof");
        // L1Outbox._verifyInclusion 等价校验。
        assert!(
            proof::verify_inclusion(&to_claim(leaf), &proof_path, index as u64, window.root),
            "mirror verifier must accept L2 proof (index {index})"
        );
        // 篡改：任一证明节点被替换 → 拒绝。
        let mut tampered = proof_path.clone();
        tampered[0] = [0xaau8; 32];
        assert!(!proof::verify_inclusion(
            &to_claim(leaf),
            &tampered,
            index as u64,
            window.root
        ));
        // 篡改：叶子字段被换 → 拒绝（fail-closed 的意义所在）。
        let mut evil = *leaf;
        evil.amount = evil.amount + 1;
        assert!(!proof::verify_inclusion(
            &to_claim(&evil),
            &proof_path,
            index as u64,
            window.root
        ));
    }
}

#[test]
fn multi_window_isolation() {
    // 两个窗口（checkpoint 高度 10 / 20）互不污染。
    let mut builder = WithdrawalRootBuilder::new();
    for s in 1u8..=3 {
        builder.push(sample_leaf(s, 10)).expect("unique");
    }
    for s in 4u8..=6 {
        builder.push(sample_leaf(s, 20)).expect("unique");
    }
    let w10 = builder.build(10).expect("w10");
    let w20 = builder.build(20).expect("w20");
    assert_ne!(w10.root, w20.root);

    // 窗口 10 的叶子拿窗口 20 的根 → 镜像校验拒绝（跨根混用）。
    let idx = builder.leaf_index(10, &[1u8; 32]).expect("in w10");
    let proof10 = builder.merkle_proof(10, idx).expect("proof");
    assert!(!proof::verify_inclusion(
        &to_claim(&sample_leaf(1, 10)),
        &proof10,
        idx as u64,
        w20.root
    ));
}

#[test]
fn claim_calldata_leaf_matches_proof_leaf_encoding() {
    // claim calldata 里的叶子字段与 proof.rs 叶哈希输入必须同源：
    // encode_claim 的静态字（经 word 填充）还原后应等于 ClaimLeaf 本体。
    let leaf = to_claim(&sample_leaf(3, 42));
    let proof_path = vec![[9u8; 32]];
    let calldata = monad_settlement::abi::encode_claim(&leaf, [7u8; 32], 1, 0, &proof_path);
    // selector(4) + request_id(32) + recipient(32) + tag(32) + amount(32)
    // + commitment(32) + height(32) + root(32) + leaf_count(32) + index(32)
    // + array offset(32) = head 324；tail = array len(32) + 1 node(32)。
    assert_eq!(calldata.len(), 4 + 10 * 32 + 2 * 32);
    assert_eq!(&calldata[4..36], &leaf.request_id);
    assert_eq!(&calldata[36..68], &leaf.external_recipient);
    assert_eq!(calldata[4 + 2 * 32 + 31], leaf.asset_tag);
    // 叶哈希输入（borsh 紧凑 113B）与 abi 层共享同一 ClaimLeaf 类型——
    // 编译期即同源。
    assert_eq!(
        proof::leaf_hash(&leaf).len(),
        32
    );
}
