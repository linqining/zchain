//! M8：攻击回归套件（每项 = 注入攻击 + 期望拒绝/告警）。
//!
//! 对应 plan-appchain-v1.md M8-ACC-1..6：
//! 1. 双花（软确认层并发 + 顺序重放）
//! 2. 伪造结算（缺 P 层签名）
//! 3. 污染 note 上桌（未证明买入）
//! 4. 结算重放（hand_binding 重复）
//! 5. 费率篡改（换策略/改抽取额）
//! 6. 等价性分叉（双链导出冲突检测）

mod common;

use common::{
    deposit_and_find, find_note, new_sequencer, rake_policy, two_player_settlement,
    TestUser,
};
use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::SequencerKey;
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::soft_confirm::{
    genesis_prev_hash, verify_chain, SignedFrame, SoftConfirmFrame,
};
use poker_appchain::watcher::fork_report;
use std::sync::{Arc, Mutex};

/// M8-ACC-1a：同一 note 两笔并发转账，恰好一笔成功（线程竞争）。
#[test]
fn acc1_concurrent_double_spend_exactly_one_wins() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let dep = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Play, 1);
    let out_a = NoteSpec {
        asset_class: AssetClass::Play,
        amount: 1_000,
        owner: a.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let out_b = NoteSpec {
        asset_class: AssetClass::Play,
        amount: 1_000,
        owner: b.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let op1 = Operation::Transfer {
        spends: vec![a.transfer_auth(&dep, &[out_a.clone()])],
        notes: vec![dep.clone()],
        outputs: vec![out_a],
    };
    let op2 = Operation::Transfer {
        spends: vec![a.transfer_auth(&dep, &[out_b.clone()])],
        notes: vec![dep.clone()],
        outputs: vec![out_b],
    };
    let shared = Arc::new(Mutex::new(seq));
    let s1 = Arc::clone(&shared);
    let s2 = Arc::clone(&shared);
    let h1 = std::thread::spawn(move || s1.lock().unwrap().submit(op1, 2_000).is_ok());
    let h2 = std::thread::spawn(move || s2.lock().unwrap().submit(op2, 2_000).is_ok());
    let wins = h1.join().unwrap() as u8 + h2.join().unwrap() as u8;
    assert_eq!(wins, 1, "exactly one of the two spends must win");
    // 赢家的余额恰好 1000，输家 0
    let seq = shared.lock().unwrap();
    assert_eq!(seq.state().balances_of(&b.pk()).1 + seq.state().balances_of(&a.pk()).1, 1_000);
}

/// M8-ACC-1b：跨操作 scope 重放——BUYIN 授权不能用于 TRANSFER。
#[test]
fn acc1_scope_replay_rejected() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let dep = deposit_and_find(&mut seq, &a, 500, AssetClass::Play, 1);
    seq.submit(Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero }, 1_000)
        .unwrap();
    seq.mark_proven_through(seq.state().seq);
    // 效果摘要按 BuyIn 正确计算，但 scope 用了 TRANSFER → scope 防线独立可测
    let buyin_effect = Operation::BuyIn {
        table_id: 1,
        spends: vec![],
        notes: vec![],
        seat_owner: a.pk(),
    }
    .effect_digest();
    // 用 TRANSFER scope 的签名提交 BuyIn → 签名验证失败
    let err = seq
        .submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![a.auth(&dep, scope::TRANSFER, &buyin_effect)], // 错误 scope
                notes: vec![dep],
                seat_owner: a.pk(),
            },
            2_000,
        )
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::BadSignature));
}

/// M8-ACC-2：缺/坏 P 层签名的结算被拒。
#[test]
fn acc2_forged_settlement_rejected() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: 1, policy }, 1_000).unwrap();
    let dep_a = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Real, 1);
    let dep_b = deposit_and_find(&mut seq, &b, 2_000, AssetClass::Real, 2);
    seq.mark_proven_through(seq.state().seq);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![a.buyin_auth(&dep_a, 1, a.pk())],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.buyin_auth(&dep_b, 1, b.pk())],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_note(&seq, &a, 1_000);
    let seat_b = find_note(&seq, &b, 2_000);

    // 攻击者（无 B 签名）构造结算：把 B 的钱划走
    let mut record = two_player_settlement(
        1, &a, &b, &seat_a, &seat_b,
        3_000, 500, 2_350, &policy, 0x11,
    );
    // 伪造 B 的授权：换成 A 冒签（密钥不对）
    let forged = a.settle_auth(&seat_b, &record);
    record.inputs[1].spend = forged;
    let err = seq
        .submit(Operation::Settle(Box::new(record)), 3_000)
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::BadSignature));
}

/// M8-ACC-3：污染 note（未证明产出）上桌被拒。
#[test]
fn acc3_unproven_note_cannot_buyin() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let dep = deposit_and_find(&mut seq, &a, 500, AssetClass::Real, 1);
    seq.submit(Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero }, 1_000)
        .unwrap();
    // 不推进 proven 水位，直接买入
    let err = seq
        .submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![a.buyin_auth(&dep, 1, a.pk())],
                notes: vec![dep],
                seat_owner: a.pk(),
            },
            2_000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected("note not proven")
    ));
}

/// M8-ACC-4：同一 hand_binding 结算重放被拒。
#[test]
fn acc4_settlement_replay_rejected() {
    let mut seq = new_sequencer();
    let (record, _policy) = setup_settled_hand(&mut seq, 0x21);
    let err = seq
        .submit(Operation::Settle(Box::new(record)), 4_000)
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::SettlementReplay));
}

/// M8-ACC-5：费率篡改（换策略承诺 / 改抽取额）被拒。
#[test]
fn acc5_fee_tampering_rejected() {
    // 5a. 换策略承诺：**只**换 commitment（其余不动 → 签名仍有效——
    // settle_effect 刻意不含 policy_commitment，该字段由注册表冻结检查
    // 强制；这正是两层防线各司其职的验证）
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let mut seq = new_sequencer();
    let (record, _a, _b) = setup_unsettled_hand(&mut seq, 0x41);
    let mut swapped = record;
    swapped.policy_commitment = FeePolicy::Zero.commitment_bytes();
    let err = seq
        .submit(Operation::Settle(Box::new(swapped)), 4_000)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::FeeMismatch { .. }),
        "swapped policy commitment must fail fee check, got {err:?}"
    );

    // 5b. 谎报抽取额压低 rake：合谋签名者按篡改后的记录**完整重签**
    // （pot/payout_root 都在结算效果摘要内，需重签才过签名防线）：
    // rake.total 150→100，plan.rake 同步 100，payouts 同步上调、分账 note
    // 同步 20/80——记录整体自洽，唯一的拒绝来源就是
    // rake.total(=plan.rake=100) ≠ policy.rake_of(pot=3000)=150。
    let mut seq2 = new_sequencer();
    let (record2, a2, b2) = setup_unsettled_hand(&mut seq2, 0x42);
    let mut underreport = record2;
    underreport.rake.total = 100;
    underreport.rake.treasury_out = Some(poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Real,
        amount: 20,
        owner: treasury.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    });
    underreport.rake.operator_out = Some(poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Real,
        amount: 80,
        owner: operator.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    });
    underreport.payouts[1].amount = 2_400; // Σpayouts = pot − 100
    underreport.plan = poker_appchain::settlement::flat_settlement_plan(3_000, 0b11, {
        let mut awards = [0u64; 9];
        awards[0] = 500;
        awards[1] = 2_400;
        awards
    });
    underreport.inputs[0].spend = a2.settle_auth(&underreport.inputs[0].note, &underreport);
    underreport.inputs[1].spend = b2.settle_auth(&underreport.inputs[1].note, &underreport);
    let err = seq2
        .submit(Operation::Settle(Box::new(underreport)), 4_100)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::FeeMismatch { .. }),
        "under-reported rake must fail the fee relation, got {err:?}"
    );

    // 5c. 谎报 pot（3000 → 2999）压低抽取：即便同步改 plan + payouts 并
    // 完整重签（签名防线全过），Σseat notes(3000) ≠ plan.gross_pot(2999)
    // 的贡献守恒仍然拒绝——pot 不再是独立可信输入（plan-appchain §5.2-2）。
    let mut seq3 = new_sequencer();
    let (record3, a3, b3) = setup_unsettled_hand(&mut seq3, 0x43);
    let mut underreport_pot = record3;
    underreport_pot.pot = 2_999;
    underreport_pot.payouts[1].amount = 2_349;
    underreport_pot.plan = poker_appchain::settlement::flat_settlement_plan(2_999, 0b11, {
        let mut awards = [0u64; 9];
        awards[0] = 500;
        awards[1] = 2_349;
        awards
    });
    underreport_pot.inputs[0].spend = a3.settle_auth(&underreport_pot.inputs[0].note, &underreport_pot);
    underreport_pot.inputs[1].spend = b3.settle_auth(&underreport_pot.inputs[1].note, &underreport_pot);
    let err = seq3
        .submit(Operation::Settle(Box::new(underreport_pot)), 4_200)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::AdmissionRejected("seat inputs do not equal plan gross pot")),
        "under-reported pot must fail contribution conservation, got {err:?}"
    );
}

/// M8-ACC-6：等价性分叉——向 watcher 喂两条冲突软确认链，分叉被定位。
#[test]
fn acc6_fork_detection() {
    let key = SequencerKey::from_seed(&[99; 32]);
    // 诚实链：3 帧
    let mut honest = Vec::new();
    let mut prev = genesis_prev_hash();
    for i in 0..3u64 {
        let f = SignedFrame::sign(
            SoftConfirmFrame {
                index: i,
                prev_hash: prev,
                op: Operation::OpenTable { table_id: i + 1, policy: FeePolicy::Zero },
                state_root: [0xAA; 32],
                ts_ms: 1_000 + i,
            },
            &key,
        )
        .unwrap();
        prev = f.hash().unwrap();
        honest.push(f);
    }
    // 恶意链：同 index 但 state_root 不同（对受害者展示的另一条历史）
    let mut evil = Vec::new();
    let mut prev = genesis_prev_hash();
    for i in 0..3u64 {
        let f = SignedFrame::sign(
            SoftConfirmFrame {
                index: i,
                prev_hash: prev,
                op: Operation::OpenTable { table_id: i + 1, policy: FeePolicy::Zero },
                state_root: [0xBB; 32],
                ts_ms: 1_000 + i,
            },
            &key,
        )
        .unwrap();
        prev = f.hash().unwrap();
        evil.push(f);
    }
    // 两条链各自签名都有效——分叉只能靠等价性比较发现
    verify_chain(&honest, &key.public).unwrap();
    verify_chain(&evil, &key.public).unwrap();
    let report = fork_report(&honest, &evil);
    assert_eq!(report.fork_at, Some(0), "fork must be located");
}

/// M8-ACC-6b：诚实链导出自比较无分叉。
#[test]
fn acc6b_no_fork_on_identical_chain() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    deposit_and_find(&mut seq, &a, 100, AssetClass::Play, 1);
    let chain = seq.export_chain();
    assert!(poker_appchain::watcher::require_equivalent(&chain, &chain).is_ok());
}

/// P0-2：pot 与 plan.gross_pot 不一致被拒（pot 不再是独立可信输入）。
#[test]
fn p0_2_pot_plan_gross_mismatch_rejected() {
    let mut seq = new_sequencer();
    let (record, _a, _b) = setup_unsettled_hand(&mut seq, 0x51);
    let mut tampered = record;
    tampered.pot = 2_999; // plan.gross_pot 仍 3_000
    let err = seq
        .submit(Operation::Settle(Box::new(tampered)), 4_000)
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected(
            "plan gross pot does not match record pot"
        )
    ));
}

/// P0-2：plan 自身守恒破裂被拒（settlement-core validate fail-closed）。
#[test]
fn p0_2_plan_conservation_broken_rejected() {
    let mut seq = new_sequencer();
    let (record, _a, _b) = setup_unsettled_hand(&mut seq, 0x52);
    let mut tampered = record;
    tampered.plan.pots[0].net_amount += 1; // gross/rake/net 不再守恒
    let err = seq
        .submit(Operation::Settle(Box::new(tampered)), 4_000)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::Codec(_)),
        "broken plan conservation must fail plan.validate, got {err:?}"
    );
}

/// P0-7：payout 与 plan.awards 不符（金额投影）被拒。
#[test]
fn p0_7_payout_awards_mismatch_rejected() {
    let mut seq = new_sequencer();
    let (record, a, b) = setup_unsettled_hand(&mut seq, 0x53);
    let mut tampered = record;
    tampered.payouts[1].amount += 1; // 偏离 plan 投影（签名也不同）
    tampered.inputs[0].spend = a.settle_auth(&tampered.inputs[0].note, &tampered);
    tampered.inputs[1].spend = b.settle_auth(&tampered.inputs[1].note, &tampered);
    let err = seq
        .submit(Operation::Settle(Box::new(tampered)), 4_000)
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected(
            "payout does not match plan projection (table/pot/runout/amount)"
        )
    ));
}

/// P0-7：payout 索引越界（pot_index 超出 plan 层数）被拒。
#[test]
fn p0_7_payout_index_out_of_range_rejected() {
    let mut seq = new_sequencer();
    let (record, a, b) = setup_unsettled_hand(&mut seq, 0x54);
    let mut tampered = record;
    tampered.payouts[0].pot_index = 5; // plan 只有 1 层
    tampered.payouts[1].pot_index = 5;
    tampered.inputs[0].spend = a.settle_auth(&tampered.inputs[0].note, &tampered);
    tampered.inputs[1].spend = b.settle_auth(&tampered.inputs[1].note, &tampered);
    let err = seq
        .submit(Operation::Settle(Box::new(tampered)), 4_000)
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected(
            "payout does not match plan projection (table/pot/runout/amount)"
        )
    ));
}

/// P0-7：payout_root 篡改被**签名判据**拒绝——赔付结构整体平移（记录
/// 自洽：Σpayouts 不变、plan.awards 同步、投影一致），但花费授权仍是
/// 旧 payout_root 上的签名 → BadSignature（玩家签名覆盖精确赔付结构）。
#[test]
fn p0_7_payout_root_tamper_rejected_by_signature() {
    let mut seq = new_sequencer();
    let (record, _a, _b) = setup_unsettled_hand(&mut seq, 0x55);
    let mut shifted = record;
    shifted.payouts[0].amount -= 1; // A→B 挪 1 筹码
    shifted.payouts[1].amount += 1;
    shifted.plan = poker_appchain::settlement::flat_settlement_plan(3_000, 0b11, {
        let mut awards = [0u64; 9];
        awards[0] = 499;
        awards[1] = 2_351;
        awards
    });
    // 刻意不重签：settle_effect 因 payout_root 变化而改变
    let err = seq
        .submit(Operation::Settle(Box::new(shifted)), 4_000)
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::BadSignature));
}

/// 构造 canonical 布局（scope v2）的手牌归档字节：终态镜像 pot 可指定，
/// 前后状态根/终态承诺可指定（validate_settlement 第 11 条的直接判据）。
fn archive_scope_bytes(pot: u64, pre_root: [u8; 32], post_root: [u8; 32]) -> Vec<u8> {
    use poker_appchain::settlement::{
        BlindOpeningScope, RakeOpeningScope, TexasArchiveScope,
    };
    let mut image = vec![0u8; poker_appchain::settlement::CANONICAL_STATE_IMAGE_BORSH_BYTES];
    image[poker_appchain::settlement::STATE_IMAGE_POT_OFFSET..][..8]
        .copy_from_slice(&pot.to_le_bytes());
    let scope = TexasArchiveScope {
        log_size: 10,
        num_columns: 1_574,
        table_id: 1,
        first_hand_id: 1,
        last_hand_id: 1,
        first_call_seq: 0,
        last_call_seq: 2,
        transition_count: 3,
        first_transition_kind: 0,
        last_transition_kind: 0,
        reveal_timeout_cascade_count: 0,
        reveal_timeout_cascade_schedule: [u8::MAX; 9],
        batch_digest: [2; 32],
        pre_state_commitment: [3; 32],
        post_state_commitment: [4; 32],
        pre_state_root: pre_root,
        post_state_root: post_root,
        pre_lifecycle_root: [0; 32],
        post_lifecycle_root: [0; 32],
        pre_overlay_root: [0; 32],
        post_overlay_root: [0; 32],
        pre_settlement_commitment: [0; 32],
        post_settlement_commitment: [0; 32],
        pre_custody_commitment: [0; 32],
        post_custody_commitment: [0; 32],
        pre_state_image_bytes: image.clone(),
        post_state_image_bytes: image,
        range_claimed_sum: [0; 4],
        rake_opening: None::<RakeOpeningScope>,
        blind_opening: None::<BlindOpeningScope>,
    };
    borsh::to_vec(&scope).unwrap()
}

/// P0-2：终态镜像 pot ≠ record.pot 的归档绑定被拒；一致时校验通过
/// （直接调用 validate_settlement，走第 11 条 scope 级绑定）。
#[test]
fn p0_2_gross_pot_bound_to_terminal_state_image() {
    use poker_appchain::settlement::{
        parse_archive_scope, validate_settlement, HandProofBinding,
    };
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    let seat_a = Note::new(AssetClass::Real, 1_000, a.pk(), [0x71; 32], Some(1)).unwrap();
    let seat_b = Note::new(AssetClass::Real, 2_000, b.pk(), [0x72; 32], Some(1)).unwrap();
    let record = two_player_settlement(
        1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, 0x56,
    );
    assert!(validate_settlement(&record, &policy).is_ok());

    // 正例绑定：镜像 pot == record.pot == 3_000
    let mut bound = record.clone();
    bound.hand_proof = Some(HandProofBinding {
        archive_bytes: archive_scope_bytes(3_000, [0x11; 32], [0x22; 32]),
        post_state_commitment: [4; 32],
        pre_state_root: [0x11; 32],
        post_state_root: [0x22; 32],
    });
    assert!(validate_settlement(&bound, &policy).is_ok());
    // scope 可解析且镜像 pot 逐字节 == record.pot
    let scope = parse_archive_scope(&bound.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(scope.table_id, bound.table_id);
    assert_eq!(
        u64::from_le_bytes(
            scope.post_state_image_bytes
                [poker_appchain::settlement::STATE_IMAGE_POT_OFFSET..][..8]
                .try_into()
                .unwrap()
        ),
        bound.pot
    );

    // 负例 A：镜像 pot 谎报 1（终态与结算脱钩）→ 拒绝
    let mut unbound = record.clone();
    unbound.hand_proof = Some(HandProofBinding {
        archive_bytes: archive_scope_bytes(1, [0x11; 32], [0x22; 32]),
        post_state_commitment: [4; 32],
        pre_state_root: [0x11; 32],
        post_state_root: [0x22; 32],
    });
    let err = validate_settlement(&unbound, &policy).unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected(
            "archive terminal state pot does not match record pot"
        )
    ));

    // 负例 B：声明状态根与归档不一致 → 拒绝
    let mut wrong_root = record;
    wrong_root.hand_proof = Some(HandProofBinding {
        archive_bytes: archive_scope_bytes(3_000, [0x11; 32], [0x22; 32]),
        post_state_commitment: [4; 32],
        pre_state_root: [0x33; 32], // ≠ 归档 pre_state_root
        post_state_root: [0x22; 32],
    });
    let err = validate_settlement(&wrong_root, &policy).unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AdmissionRejected("archive state root mismatch")
    ));
}

// ===== 审计 P2：no-WAL 模式变更前预检（拒绝必须零状态变更）=====
//
// 背景：无 WAL 的内存模式 apply 直接落 `self.state`（无克隆态回滚），
// 旧路径「先变更、后在 fallible 调用上失败」会留下半变更状态（note 已
// 删 / 幂等键已烧 / burn 未记账）。以下负例钉死：拒绝路径零状态变更。

/// 构造对**任意声明 nullifier** 完整签名的 v1 提现 op（nullifier 只需被
/// 签名覆盖，链上不做派生核对——正是双花投毒的攻击面）。
fn withdraw_with_nullifier(
    user: &TestUser,
    note: &Note,
    request_id: [u8; 32],
    nullifier: [u8; 32],
) -> Operation {
    use poker_appchain::keys::{spend_digest, EcdsaSig};
    use poker_appchain::settlement::SpendAuth;
    let effect = Operation::WithdrawRequest {
        spend: SpendAuth {
            commitment: [0; 32],
            nullifier: [0; 32],
            sig: EcdsaSig { bytes: [0; 64] },
        },
        note: note.clone(),
        request_id,
        payout_recipient: [0xEE; 32],
    }
    .effect_digest();
    let d = spend_digest(&note.commitment_bytes(), &nullifier, scope::WITHDRAW, &effect);
    Operation::WithdrawRequest {
        spend: SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier,
            sig: user.key.sign(&d),
        },
        note: note.clone(),
        request_id,
        payout_recipient: [0xEE; 32],
    }
}

/// 双花 nullifier 的提现被整笔拒绝：第二张 note **不被删除**、request_id
/// **不被烧**、burn 不记账（旧路径：withdrawal_ids.insert 后 consume 失败
/// → note 已删 + 幂等键已烧的半变更状态）。
#[test]
fn withdraw_double_spend_rejected_without_partial_state() {
    let mut seq = new_sequencer(); // 无 WAL：apply 直接落 self.state
    let a = TestUser::new(1);
    let n1 = deposit_and_find(&mut seq, &a, 100, AssetClass::Play, 1);
    let n2 = deposit_and_find(&mut seq, &a, 200, AssetClass::Play, 2);

    // 首笔：n1 正常销毁（声明 nullifier = n1 的派生 nullifier）
    let nf1 = poker_appchain::felt::felt_to_bytes32(&n1.nullifier(&a.secret));
    seq.submit(withdraw_with_nullifier(&a, &n1, [0x71; 32], nf1), 2_000)
        .unwrap();

    // 攻击形状：第二张 note n2 复用 nf1（签名覆盖即可，无需是 n2 的派生值）
    let err = seq
        .submit(withdraw_with_nullifier(&a, &n2, [0x72; 32], nf1), 2_100)
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::DoubleSpend));

    // 零状态变更：note 仍在、request_id 未烧、burn 未记账
    assert!(
        seq.state().notes.contains_key(&n2.commitment_bytes()),
        "拒绝的提现不得删除 note"
    );
    assert!(
        !seq.state().withdrawal_ids.contains(&[0x72; 32]),
        "拒绝的提现不得烧幂等键"
    );
    assert_eq!(seq.state().burned, vec![([0x71; 32], 100)]);
    assert_eq!(seq.state().nullifiers.spent_count, 1);
}

/// 非规范 felt nullifier（≥ p）的提现在变更前被拒：note 仍在、幂等键未烧
/// （旧路径：note 先删，felt_from_bytes32_exact 才失败）。
#[test]
fn withdraw_noncanonical_nullifier_rejected_without_partial_state() {
    let mut seq = new_sequencer();
    let a = TestUser::new(2);
    let n = deposit_and_find(&mut seq, &a, 300, AssetClass::Play, 1);

    let err = seq
        .submit(withdraw_with_nullifier(&a, &n, [0x81; 32], [0xFF; 32]), 2_000)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::OutOfRange("felt bytes")),
        "非规范 felt 必须在变更前拒绝，got {err:?}"
    );
    assert!(seq.state().notes.contains_key(&n.commitment_bytes()));
    assert!(!seq.state().withdrawal_ids.contains(&[0x81; 32]));
    assert!(seq.state().burned.is_empty());
}

/// 投毒转账（同 op 两笔 spend 声明同一 nullifier）整笔拒绝：两张 note
/// 都不被删除（旧路径：第 1 张先被删、第 2 张才在 nullifier 步失败）。
#[test]
fn transfer_poisoned_double_nullifier_rejected_without_partial_state() {
    let mut seq = new_sequencer();
    let a = TestUser::new(3);
    let n1 = deposit_and_find(&mut seq, &a, 100, AssetClass::Play, 1);
    let n2 = deposit_and_find(&mut seq, &a, 200, AssetClass::Play, 2);
    let nf1 = poker_appchain::felt::felt_to_bytes32(&n1.nullifier(&a.secret));

    let outputs = vec![NoteSpec {
        asset_class: AssetClass::Play,
        amount: 300,
        owner: a.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    }];
    let effect = Operation::Transfer {
        spends: vec![],
        notes: vec![],
        outputs: outputs.clone(),
    }
    .effect_digest();
    let mk_spend = |n: &Note| {
        use poker_appchain::keys::spend_digest;
        use poker_appchain::settlement::SpendAuth;
        let d = spend_digest(&n.commitment_bytes(), &nf1, scope::TRANSFER, &effect);
        SpendAuth {
            commitment: n.commitment_bytes(),
            nullifier: nf1,
            sig: a.key.sign(&d),
        }
    };
    let err = seq
        .submit(
            Operation::Transfer {
                spends: vec![mk_spend(&n1), mk_spend(&n2)],
                notes: vec![n1.clone(), n2.clone()],
                outputs,
            },
            2_000,
        )
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::DoubleSpend));
    // 两张 note 都存活（旧路径 n1 已被删除）
    assert!(seq.state().notes.contains_key(&n1.commitment_bytes()));
    assert!(seq.state().notes.contains_key(&n2.commitment_bytes()));
    assert_eq!(
        seq.state().balances_of(&a.pk()).1,
        300,
        "拒绝的转账不得改变余额"
    );
}

// ===== 测试脚手架 =====

/// 标准 setup：开 rake 桌 + 双方入金买入（未结算），返回待提交的合法结算
/// 记录与双方用户（供合谋重签场景使用）。
fn setup_unsettled_hand(
    seq: &mut Sequencer,
    binding_byte: u8,
) -> (
    poker_appchain::settlement::SettlementRecord,
    TestUser,
    TestUser,
) {
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: 1, policy }, 1_000).unwrap();
    let dep_a = deposit_and_find(seq, &a, 1_000, AssetClass::Real, 1);
    let dep_b = deposit_and_find(seq, &b, 2_000, AssetClass::Real, 2);
    seq.mark_proven_through(seq.state().seq);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![a.buyin_auth(&dep_a, 1, a.pk())],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.buyin_auth(&dep_b, 1, b.pk())],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_note(seq, &a, 1_000);
    let seat_b = find_note(seq, &b, 2_000);
    let record = two_player_settlement(
        1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, binding_byte,
    );
    (record, a, b)
}

/// 标准 setup：开 rake 桌 + 双方入金买入 + 结算一次，返回（结算记录副本, 策略）。
fn setup_settled_hand(
    seq: &mut Sequencer,
    binding_byte: u8,
) -> (poker_appchain::settlement::SettlementRecord, FeePolicy) {
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    seq.submit(Operation::OpenTable { table_id: 1, policy }, 1_000).unwrap();
    let dep_a = deposit_and_find(seq, &a, 1_000, AssetClass::Real, 1);
    let dep_b = deposit_and_find(seq, &b, 2_000, AssetClass::Real, 2);
    seq.mark_proven_through(seq.state().seq);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![a.buyin_auth(&dep_a, 1, a.pk())],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.buyin_auth(&dep_b, 1, b.pk())],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_note(seq, &a, 1_000);
    let seat_b = find_note(seq, &b, 2_000);
    let record = two_player_settlement(
        1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, binding_byte,
    );
    seq.submit(Operation::Settle(Box::new(record.clone())), 3_000)
        .unwrap();
    (record, policy)
}

const _: fn() -> SequencerConfig = SequencerConfig::default;
