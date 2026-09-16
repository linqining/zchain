//! M7-ACC-5 集成回归：withdrawal root 聚合 + permissionless claim（§5.4）。
//!
//! 覆盖：聚合确定性（同输入同根/顺序无关）、inclusion 正例、非成员叶拒、
//! 未 finalized 拒（未知根/未注册根）、重复领拒（同实例 + **跨实例重载后**
//! 仍拒）、篡改叶任一字段证明失败（6 字段逐一）、fee 场景（amount 含费 →
//! leaf.amount = 净额，vault 队列 → leaf → 根 → claim 全链路）。
//!
//! 边界：链上 Vault 合约、STARK 验证挂接、checkpoint 字段集成属后续
//! （见 `docs/ABI_WITHDRAWAL_ROOT.md`）。

use poker_appchain::error::AppchainError;
use poker_appchain::note::AssetClass;
use poker_appchain::real_policy::{FinalityEvidence, WithdrawalProvenance};
use poker_appchain::vault::{
    CustodyLedger, PendingWithdrawal, WithdrawalFeeConfig, WithdrawalRequest,
};
use poker_appchain::withdrawal_root::{
    ClaimLedger, FinalizedRoot, WithdrawalLeaf, WithdrawalRoot, WithdrawalRootBuilder,
    verify_inclusion,
};

/// REAL 判别值（与 `note::AssetClass::Real` 一致）。
const REAL: u8 = 1;

/// 固定字段叶子。
fn leaf(seed: u8, amount: u64, height: u64) -> WithdrawalLeaf {
    WithdrawalLeaf {
        request_id: [seed; 32],
        external_recipient: [seed.wrapping_add(0x40); 32],
        asset_class: REAL,
        amount,
        burned_note_commitment: [seed.wrapping_add(0x80); 32],
        checkpoint_height: height,
    }
}

/// 单窗聚合辅助：叶集 → (根, 逐叶 proof)。
fn build_window(height: u64, leaves: &[WithdrawalLeaf]) -> (WithdrawalRoot, Vec<Vec<[u8; 32]>>) {
    let mut b = WithdrawalRootBuilder::new();
    for l in leaves {
        b.push(*l).unwrap();
    }
    let root = b.build(height).unwrap();
    let proofs = (0..leaves.len())
        .map(|i| b.merkle_proof(height, i).unwrap())
        .collect();
    (root, proofs)
}

/// PLAY provenance（finality 门豁免类，vault 侧直接受理）。
fn play_prov() -> WithdrawalProvenance {
    WithdrawalProvenance {
        asset_class: AssetClass::Play,
        source_op_index: 3,
    }
}

// ===== 1. 聚合确定性 =====

/// 同输入同根：不同提交顺序、不同构建器实例都得到同一根与摘要；
/// 任一叶字段差异 / 窗口高度差异改变根；空窗不产根。
#[test]
fn aggregation_deterministic_same_input_same_root() {
    let height = 42;
    let leaves = [
        leaf(1, 100, height),
        leaf(2, 250, height),
        leaf(3, 7, height),
    ];

    let mut a = WithdrawalRootBuilder::new();
    let mut b = WithdrawalRootBuilder::new();
    for l in leaves {
        a.push(l).unwrap();
    }
    for l in leaves.iter().rev() {
        b.push(*l).unwrap();
    }
    let ra = a.build(height).unwrap();
    let rb = b.build(height).unwrap();
    assert_eq!(ra, rb, "同输入（不同提交序）必须同根同摘要");

    // 任何绑定字段差异改变根
    for i in 0..3 {
        let mut tampered = leaves[i];
        match i {
            0 => tampered.amount += 1,
            1 => tampered.external_recipient[0] ^= 1,
            _ => tampered.burned_note_commitment[0] ^= 1,
        }
        let mut c = WithdrawalRootBuilder::new();
        for (j, l) in leaves.iter().enumerate() {
            c.push(if j == i { tampered } else { *l }).unwrap();
        }
        assert_ne!(c.build(height).unwrap(), ra, "字段 {i} 差异必须改变根");
    }

    // 窗口高度 = 分窗键：同批叶换高度 → 另一窗口、另一根
    let mut d = WithdrawalRootBuilder::new();
    for l in leaves {
        d.push(WithdrawalLeaf {
            checkpoint_height: height + 1,
            ..l
        })
        .unwrap();
    }
    let rd = d.build(height + 1).unwrap();
    assert_ne!(rd.root, ra.root);
    assert_eq!(d.build_all().len(), 1);

    // 空窗不产根
    let empty = WithdrawalRootBuilder::new();
    assert!(matches!(
        empty.build(height),
        Err(AppchainError::OutOfRange("withdrawal window is empty"))
    ));
    assert!(empty.build_all().is_empty());

    // 同 request_id 重复入窗 → 拒（fail-closed）
    let mut e = WithdrawalRootBuilder::new();
    e.push(leaves[0]).unwrap();
    assert!(matches!(
        e.push(leaves[0]),
        Err(AppchainError::WithdrawalConflict(_))
    ));
}

// ===== 2/3. inclusion 正例 + 非成员叶拒 =====

#[test]
fn inclusion_positive_and_non_member_rejected() {
    let height = 7;
    let leaves = [
        leaf(1, 100, height),
        leaf(2, 200, height),
        leaf(3, 300, height),
    ];
    let (root, proofs) = build_window(height, &leaves);

    // 正例：每个成员叶逐一对自身 proof 校验通过
    for (i, l) in leaves.iter().enumerate() {
        assert!(
            verify_inclusion(l, &proofs[i], i as u64, root.root),
            "index {i}"
        );
    }

    // 非成员叶：任何位置的 proof 都不通过
    let alien = leaf(9, 100, height);
    for (i, proof) in proofs.iter().enumerate() {
        assert!(!verify_inclusion(&alien, proof, i as u64, root.root));
    }
    // 非本窗叶（checkpoint_height 不同）同样非成员
    let mut other_window = leaves[0];
    other_window.checkpoint_height = height + 1;
    assert!(!verify_inclusion(&other_window, &proofs[0], 0, root.root));

    // 非成员 claim：根已 finalized，但叶不在树中 → 证明拒绝
    let mut ledger = ClaimLedger::new();
    ledger.mark_finalized(&root).unwrap();
    let err = ledger
        .claim(root.digest, &alien, &proofs[0], 0)
        .unwrap_err();
    assert!(
        matches!(err, AppchainError::WithdrawalProofInvalid(_)),
        "非成员叶必须走证明拒绝路径"
    );

    // 索引挪用 / 证明截断 → 拒
    assert!(!verify_inclusion(&leaves[0], &proofs[1], 1, root.root));
    let truncated = &proofs[2][..proofs[2].len() - 1];
    assert!(!verify_inclusion(&leaves[2], truncated, 2, root.root));
}

// ===== 4. 未 finalized 拒 =====

#[test]
fn unfinalized_root_claim_rejected() {
    let (root, proofs_leaves) = {
        let leaves = [leaf(1, 100, 9), leaf(2, 200, 9)];
        let mut b = WithdrawalRootBuilder::new();
        for l in leaves {
            b.push(l).unwrap();
        }
        let root = b.build(9).unwrap();
        let proofs = (0..2)
            .map(|i| b.merkle_proof(9, i).unwrap())
            .collect::<Vec<_>>();
        (root, (leaves, proofs))
    };
    let (leaves, proofs) = proofs_leaves;
    let mut ledger = ClaimLedger::new();

    // 负例 A：未知 digest → RootNotFinalized（fail-closed：未注册 = 未 finalized）
    let unknown = WithdrawalRoot::digest_of(9, 2, [0xEE; 32]);
    let err = ledger
        .claim(unknown, &leaves[0], &proofs[0], 0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::RootNotFinalized { .. }));

    // 负例 B：根已聚合但未 mark_finalized → RootNotFinalized
    let err = ledger
        .claim(root.digest, &leaves[0], &proofs[0], 0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::RootNotFinalized { .. }));
    assert_eq!(ledger.claimed_count(), 0);
    assert!(!ledger.is_finalized(&root.digest));

    // 叶 checkpoint_height 被篡改（摘要重绑定失败）→ RootNotFinalized
    ledger.mark_finalized(&root).unwrap();
    let mut wrong_window = leaves[0];
    wrong_window.checkpoint_height = 8;
    let err = ledger
        .claim(root.digest, &wrong_window, &proofs[0], 0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::RootNotFinalized { .. }));

    // mark_finalized 后同一 claim 放行
    ledger
        .claim(root.digest, &leaves[0], &proofs[0], 0)
        .expect("finalized root accepts valid claim");
    assert!(ledger.is_claimed(&leaves[0].request_id));
}

// ===== 5. 重复领拒（含跨实例重载）=====

#[test]
fn double_claim_rejected_and_survives_reload() {
    let dir = std::env::temp_dir().join("poker-appchain-withdrawal-root-it");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("claims-it.jsonl");
    let _ = std::fs::remove_file(&path);

    let leaves = [leaf(1, 100, 9), leaf(2, 200, 9)];
    let (root, proofs) = build_window(9, &leaves);

    // 实例 A：注册根 + 领取第一叶
    {
        let mut a = ClaimLedger::open(&path).unwrap();
        a.mark_finalized(&root).unwrap();
        a.claim(root.digest, &leaves[0], &proofs[0], 0).unwrap();
        // 同实例重复领取 → AlreadyClaimed
        let err = a.claim(root.digest, &leaves[0], &proofs[0], 0).unwrap_err();
        assert!(matches!(err, AppchainError::AlreadyClaimed { .. }));
    }

    // 实例 B（重载 sidecar）：状态等价 + 跨实例重领仍拒
    let mut b = ClaimLedger::open(&path).unwrap();
    assert_eq!(
        b.finalized_root(&root.digest),
        Some(FinalizedRoot {
            checkpoint_height: 9,
            leaf_count: 2,
            root: root.root,
        }),
        "重载等价：finalized 根记录与实例 A 一致"
    );
    assert!(
        b.is_claimed(&leaves[0].request_id),
        "重载等价：领取状态恢复"
    );
    let err = b.claim(root.digest, &leaves[0], &proofs[0], 0).unwrap_err();
    assert!(
        matches!(err, AppchainError::AlreadyClaimed { .. }),
        "跨实例重载后重复领取仍拒"
    );

    // 未领过的请求不受影响
    b.claim(root.digest, &leaves[1], &proofs[1], 1).unwrap();
    drop(b);

    // 实例 C：两笔领取全部恢复（重载等价断言）
    let c = ClaimLedger::open(&path).unwrap();
    assert_eq!(c.finalized_count(), 1);
    assert_eq!(c.claimed_count(), 2);
    assert!(c.is_claimed(&leaves[0].request_id));
    assert!(c.is_claimed(&leaves[1].request_id));
}

// ===== 6. 篡改叶任一字段 → 证明失败 =====

#[test]
fn every_tampered_leaf_field_breaks_proof() {
    let height = 5;
    let original = leaf(1, 100, height);
    let other = leaf(2, 200, height);
    let (root, proofs) = build_window(height, &[original, other]);
    let mut ledger = ClaimLedger::new();
    ledger.mark_finalized(&root).unwrap();

    /// 叶字段篡改器（测试用）。
    type Mutation = (&'static str, Box<dyn Fn(&mut WithdrawalLeaf)>);
    let mutations: [Mutation; 6] = [
        (
            "request_id",
            Box::new(|l: &mut WithdrawalLeaf| l.request_id[0] ^= 1),
        ),
        (
            "external_recipient",
            Box::new(|l: &mut WithdrawalLeaf| l.external_recipient[0] ^= 1),
        ),
        (
            "asset_class",
            Box::new(|l: &mut WithdrawalLeaf| l.asset_class = 2),
        ),
        ("amount", Box::new(|l: &mut WithdrawalLeaf| l.amount += 1)),
        (
            "burned_note_commitment",
            Box::new(|l: &mut WithdrawalLeaf| l.burned_note_commitment[0] ^= 1),
        ),
        (
            "checkpoint_height",
            Box::new(|l: &mut WithdrawalLeaf| l.checkpoint_height += 1),
        ),
    ];
    for (name, mutate) in mutations {
        let mut tampered = original;
        mutate(&mut tampered);
        assert!(
            !verify_inclusion(&tampered, &proofs[0], 0, root.root),
            "篡改 {name} 后包含证明必须失败"
        );
        // claim 校验链也必须拒绝（checkpoint_height 篡改走摘要重绑定 →
        // RootNotFinalized；其余字段走证明失败 → WithdrawalProofInvalid）
        let result = ledger.claim(root.digest, &tampered, &proofs[0], 0);
        if name == "checkpoint_height" {
            assert!(
                matches!(result, Err(AppchainError::RootNotFinalized { .. })),
                "篡改 checkpoint_height → 摘要重绑定拒绝"
            );
        } else {
            assert!(
                matches!(result, Err(AppchainError::WithdrawalProofInvalid(_))),
                "篡改 {name} → claim 证明拒绝"
            );
        }
    }
    // 原叶不受影响，照常可领
    ledger
        .claim(root.digest, &original, &proofs[0], 0)
        .expect("untampered leaf still claimable");
}

// ===== 7. fee 场景：vault 队列 → leaf（净额）→ 根 → claim 全链路 =====

/// amount 含费 → leaf.amount = 打款净额；投影排序确定；已打款条目退出投影；
/// 全链路（根聚合 → finalized → claim）走通；重领拒绝。
#[test]
fn vault_fee_net_amount_flows_into_leaf_and_claim() {
    let mut vault = CustodyLedger::new().with_withdrawal_fee(WithdrawalFeeConfig { flat_fee: 25 });

    // 两笔排队（amount 含费 100/50 → 净额 75/25）
    vault
        .enqueue_withdrawal_at(
            WithdrawalRequest {
                request_id: [0xA1; 32],
                payout_address: [0xB1; 32],
                amount: 100,
            },
            play_prov(),
            FinalityEvidence::default(),
            1_000,
        )
        .unwrap();
    vault
        .enqueue_withdrawal_at(
            WithdrawalRequest {
                request_id: [0xA2; 32],
                payout_address: [0xB2; 32],
                amount: 50,
            },
            play_prov(),
            FinalityEvidence::default(),
            1_001,
        )
        .unwrap();

    // 投影：金额为净额（fee 从余额内扣）、request_id 字典序
    let pending = vault.pending_withdrawal_leaves();
    assert_eq!(
        pending,
        vec![
            PendingWithdrawal {
                request_id: [0xA1; 32],
                external_recipient: [0xB1; 32],
                payout_amount: 75,
            },
            PendingWithdrawal {
                request_id: [0xA2; 32],
                external_recipient: [0xB2; 32],
                payout_amount: 25,
            },
        ],
        "投影金额 = amount − fee（净额）"
    );

    // 叶构造：净额进 amount；burned commitment / asset_class 由调用方补齐
    // （诚实降级：v1 队列不逐条保留，见 ABI_WITHDRAWAL_ROOT.md 边界）
    let leaves: Vec<WithdrawalLeaf> = pending
        .into_iter()
        .map(|p| p.into_leaf(REAL, [0xCC; 32], 9))
        .collect();
    assert_eq!(leaves[0].amount, 75, "leaf.amount = 打款净额");
    assert_eq!(leaves[1].amount, 25);

    // 根聚合 → finalized → claim 全链路
    let (root, proofs) = build_window(9, &leaves);
    let fee_log = std::env::temp_dir()
        .join("poker-appchain-withdrawal-root-it")
        .join("claims-fee.jsonl");
    let _ = std::fs::remove_file(&fee_log);
    let mut ledger = ClaimLedger::open(&fee_log).unwrap();
    ledger.mark_finalized(&root).unwrap();
    ledger
        .claim(root.digest, &leaves[0], &proofs[0], 0)
        .expect("净额叶全链路 claim 成功");
    let err = ledger
        .claim(root.digest, &leaves[0], &proofs[0], 0)
        .unwrap_err();
    assert!(matches!(err, AppchainError::AlreadyClaimed { .. }));

    // 已打款条目退出投影（打款侧闭环不影响 claim 侧已聚合的根）
    vault.mark_paid([0xA1; 32], [0xDD; 32]).unwrap();
    let pending = vault.pending_withdrawal_leaves();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request_id, [0xA2; 32]);

    // 零费回归：默认配置下 leaf.amount == 请求金额
    let mut free = CustodyLedger::new();
    free.enqueue_withdrawal_at(
        WithdrawalRequest {
            request_id: [0xA3; 32],
            payout_address: [0xB3; 32],
            amount: 70,
        },
        play_prov(),
        FinalityEvidence::default(),
        2_000,
    )
    .unwrap();
    let p = free.pending_withdrawal_leaves();
    assert_eq!(p.len(), 1);
    let l = p[0].into_leaf(REAL, [0xCC; 32], 3);
    assert_eq!(l.amount, 70, "零费：净额 == 金额");
}
