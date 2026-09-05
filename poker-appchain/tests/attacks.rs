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
use poker_appchain::note::{AssetClass, NoteSpec};
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
    };
    let out_b = NoteSpec {
        asset_class: AssetClass::Play,
        amount: 1_000,
        owner: b.pk(),
        table_id: None,
    };
    let op1 = Operation::Transfer {
        spends: vec![a.auth(&dep, scope::TRANSFER)],
        notes: vec![dep.clone()],
        outputs: vec![out_a],
    };
    let op2 = Operation::Transfer {
        spends: vec![a.auth(&dep, scope::TRANSFER)],
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
    // 用 TRANSFER scope 的签名提交 BuyIn → 签名验证失败
    let err = seq
        .submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![a.auth(&dep, scope::TRANSFER)], // 错误 scope
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
            spends: vec![a.auth(&dep_a, scope::BUYIN)],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.auth(&dep_b, scope::BUYIN)],
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
        1_500, 500, 2_425, &policy, 0x11,
    );
    // 伪造 B 的授权：换成 A 冒签（密钥不对）
    let forged = a.settle_auth(&seat_b, &[0x11; 32]);
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
                spends: vec![a.auth(&dep, scope::BUYIN)],
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
    // 5a. 换策略承诺：rake 桌结算伪造成零费（抽取归零、赔付补差保持守恒）
    let mut seq = new_sequencer();
    let record = setup_unsettled_hand(&mut seq, 0x41);
    let mut swapped = record;
    swapped.policy_commitment = FeePolicy::Zero.commitment_bytes();
    swapped.rake.total = 0;
    swapped.rake.treasury_out = None;
    swapped.rake.operator_out = None;
    swapped.payouts[0].amount += 75; // rake 归零的差额补给 A（守恒保持）
    let err = seq
        .submit(Operation::Settle(Box::new(swapped)), 4_000)
        .unwrap_err();
    assert!(
        matches!(err, poker_appchain::AppchainError::FeeMismatch { .. }),
        "swapped policy commitment must fail fee check, got {err:?}"
    );

    // 5b. 谎报 pot（1500 → 1400）压低抽取：费率函数校验拒绝。
    // 注意：rake note 不变（75），守恒仍成立——拒绝只能来自费率关系，
    // 这正是 fee_of(pot) 校验存在的意义。
    let mut seq2 = new_sequencer();
    let record2 = setup_unsettled_hand(&mut seq2, 0x42);
    let mut underreport = record2;
    underreport.pot = 1_400;
    let err = seq2
        .submit(Operation::Settle(Box::new(underreport)), 4_100)
        .unwrap_err();
    assert!(matches!(err, poker_appchain::AppchainError::FeeMismatch { .. }));
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

// ===== 测试脚手架 =====

/// 标准 setup：开 rake 桌 + 双方入金买入（未结算），返回待提交的合法结算记录。
fn setup_unsettled_hand(
    seq: &mut Sequencer,
    binding_byte: u8,
) -> poker_appchain::settlement::SettlementRecord {
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
            spends: vec![a.auth(&dep_a, scope::BUYIN)],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.auth(&dep_b, scope::BUYIN)],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_note(seq, &a, 1_000);
    let seat_b = find_note(seq, &b, 2_000);
    two_player_settlement(
        1, &a, &b, &seat_a, &seat_b, 1_500, 500, 2_425, &policy, binding_byte,
    )
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
            spends: vec![a.auth(&dep_a, scope::BUYIN)],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![b.auth(&dep_b, scope::BUYIN)],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_note(seq, &a, 1_000);
    let seat_b = find_note(seq, &b, 2_000);
    let record = two_player_settlement(
        1, &a, &b, &seat_a, &seat_b, 1_500, 500, 2_425, &policy, binding_byte,
    );
    seq.submit(Operation::Settle(Box::new(record.clone())), 3_000)
        .unwrap();
    (record, policy)
}

const _: fn() -> SequencerConfig = SequencerConfig::default;
