//! §5.4 集成回归：vault 提现 finality 门槛（P0-3 同批落地）。
//!
//! 语义分层：
//! - sequencer 软确认层照常受理 REAL 提现销毁（§5.1：软确认不设证明门槛，
//!   销毁即负债入账）；
//! - 托管打款侧（`CustodyLedger`）对 REAL note 强制 v1 finality 门——来源
//!   op 已被证明水位覆盖 **且** 所属批次根已记录（`mark_proven_through_with_root`
//!   快照）；未满足 → `WithdrawalNotFinalized`；
//! - PLAY note 软确认即可提（豁免）；关闭开关 = 显式 opt-out（非生产）。

mod common;

use common::{deposit_and_find, new_sequencer, TestUser};
use poker_appchain::error::AppchainError;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, EcdsaSig};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::sequencer::Sequencer;
use poker_appchain::settlement::SpendAuth;
use poker_appchain::vault::{CustodyLedger, WithdrawalRequest};
use std::sync::{Arc, Mutex};

/// 测试用固定收款地址（op 的 payout_recipient 与 vault 受理载荷共用，
/// 保证 P1 一致性断言可过）。
const PAYOUT: [u8; 32] = [0xEE; 32];

/// 在 sequencer 上软确认一笔提现销毁（返回实际提交的 op 副本——P1 后
/// 受理侧需要 op 做收款人一致性核对）。
fn burn_note(
    seq: &mut Sequencer,
    user: &TestUser,
    note: &Note,
    request_id: [u8; 32],
) -> Operation {
    let op = withdraw_op(user, note, request_id, PAYOUT);
    seq.submit(op.clone(), 2_000)
        .expect("soft-confirm layer accepts withdrawal burn (finality gate is payout-side)");
    op
}

/// 构造一笔对 `payout_recipient` 完整签名的 v1 提现 op（P1：收款人进
/// 效果摘要 → 进 spend 签名）。
fn withdraw_op(
    user: &TestUser,
    note: &Note,
    request_id: [u8; 32],
    payout_recipient: [u8; 32],
) -> Operation {
    let effect = Operation::WithdrawRequest {
        spend: SpendAuth {
            commitment: [0; 32],
            nullifier: [0; 32],
            sig: EcdsaSig { bytes: [0; 64] },
        },
        note: note.clone(),
        request_id,
        payout_recipient,
    }
    .effect_digest();
    let nf = felt_to_bytes32(&note.nullifier(&user.secret));
    let d = spend_digest(&note.commitment_bytes(), &nf, scope::WITHDRAW, &effect);
    let spend = SpendAuth {
        commitment: note.commitment_bytes(),
        nullifier: nf,
        sig: user.key.sign(&d),
    };
    Operation::WithdrawRequest {
        spend,
        note: note.clone(),
        request_id,
        payout_recipient,
    }
}

/// 托管侧提现申请（op 绑定受理入口；provenance/证据取自 sequencer 快照）。
fn vault_request(
    ledger: &mut CustodyLedger,
    seq: &Sequencer,
    note: &Note,
    op: &Operation,
) -> Result<poker_appchain::vault::WithdrawalEntry, AppchainError> {
    let Operation::WithdrawRequest { request_id, note: op_note, payout_recipient, .. } = op
    else {
        panic!("vault_request requires a v1 WithdrawRequest op");
    };
    let provenance = seq.withdrawal_provenance(note).expect("note in ledger");
    let finality = seq.finality_evidence();
    ledger
        .enqueue_withdrawal_for_op(
            WithdrawalRequest {
                request_id: *request_id,
                payout_address: *payout_recipient,
                amount: op_note.amount,
            },
            op,
            provenance,
            finality,
            1_000,
        )
        .cloned()
}

/// 主流程：REAL 提现——软确认销毁成功，托管侧在 finality 前拒绝、
/// 批次根记录后放行（正例 + 两个负例）。
#[test]
fn real_withdrawal_finality_gate_end_to_end() {
    let metrics = Arc::new(MetricsRegistry::new());
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let note = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Real, 1);
    let mut ledger = CustodyLedger::new().with_metrics(Arc::clone(&metrics));
    let request_id = [0x11; 32];

    // 软确认层：销毁照常受理（提现门槛在托管打款侧）
    let op = burn_note(&mut seq, &a, &note, request_id);

    // 负例 A：无水位无批次根 → WithdrawalNotFinalized（op 0）
    let err = vault_request(&mut ledger, &seq, &note, &op).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::WithdrawalNotFinalized {
            op_index: 0,
            watermark: 0
        }
    ));
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 1);

    // 负例 B：水位覆盖但批次根未记录（mark_proven_through 直推）→ 仍拒
    seq.mark_proven_through(seq.state().seq - 1);
    assert!(seq.proven_watermark() >= 1);
    let err = vault_request(&mut ledger, &seq, &note, &op).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::WithdrawalNotFinalized { .. }
    ));
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);

    // 正例：批次根记录（模拟证明管道批次回调）→ 放行
    seq.mark_proven_through_with_root(seq.state().seq - 1, [0xAB; 32]);
    let entry = vault_request(&mut ledger, &seq, &note, &op).expect("finalized");
    assert_eq!(entry.status, poker_appchain::vault::WithdrawalStatus::Queued);
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);
}

/// PLAY note 提现不做 finality 要求（软确认即可提，§5.1 分层）。
#[test]
fn play_withdrawal_exempt_from_finality() {
    let mut seq = new_sequencer();
    let a = TestUser::new(2);
    let note = deposit_and_find(&mut seq, &a, 500, AssetClass::Play, 1);
    let mut ledger = CustodyLedger::new();
    let request_id = [0x22; 32];
    let op = burn_note(&mut seq, &a, &note, request_id);
    let entry = vault_request(&mut ledger, &seq, &note, &op)
        .expect("PLAY withdrawal needs no finality");
    assert_eq!(entry.status, poker_appchain::vault::WithdrawalStatus::Queued);
}

/// finality 开关关闭 = 显式 opt-out（仅限非生产）：REAL 未证明可提现。
#[test]
fn finality_opt_out_is_explicit_and_non_default() {
    let seq = Arc::new(Mutex::new(new_sequencer()));
    let mut seq = seq.lock().unwrap();
    let a = TestUser::new(3);
    let note = deposit_and_find(&mut seq, &a, 700, AssetClass::Real, 1);
    let request_id = [0x33; 32];
    let op = burn_note(&mut seq, &a, &note, request_id);

    // 默认构造 fail-closed
    let mut strict = CustodyLedger::new();
    assert!(vault_request(&mut strict, &seq, &note, &op).is_err());

    // 显式 opt-out 放行（构造点即语义声明）
    let mut lenient = CustodyLedger::new().without_finality_gate();
    assert!(!lenient.finality_required());
    let entry = vault_request(&mut lenient, &seq, &note, &op)
        .expect("explicit opt-out accepts unproven REAL withdrawal");
    assert_eq!(entry.status, poker_appchain::vault::WithdrawalStatus::Queued);
}

/// provenance 不可伪造：账本中不存在的 note 无法构造来源 op 证据。
#[test]
fn provenance_requires_ledger_entry() {
    let seq = new_sequencer();
    let a = TestUser::new(4);
    let alien = Note::new(AssetClass::Real, 100, a.pk(), [0x77; 32], None).unwrap();
    assert!(seq.withdrawal_provenance(&alien).is_none());
}

// ===== 审计 P1：v1 提现签名必须绑定收款人 =====

/// 同一签名授权不能被挪到另一个收款地址：仅换 payout_recipient → 效果
/// 摘要必变 → 持旧签名的第二笔 op 被签名防线拒绝（BadSignature）。
#[test]
fn withdraw_effect_digest_binds_payout_recipient() {
    let mut seq = new_sequencer();
    let a = TestUser::new(5);
    let note = deposit_and_find(&mut seq, &a, 300, AssetClass::Play, 1);
    let request_id = [0x44; 32];

    // 摘要层：同 request_id/note/签名、不同收款人 → 不同 effect digest
    let signed_for_a = withdraw_op(&a, &note, request_id, [0xAA; 32]);
    let Operation::WithdrawRequest { spend, note: op_note, .. } = signed_for_a.clone() else {
        panic!("withdraw_op must produce a v1 WithdrawRequest");
    };
    let hijacked_to_b = Operation::WithdrawRequest {
        spend, // 收款人 A 上的签名
        note: op_note,
        request_id,
        payout_recipient: [0xBB; 32], // 运营商偷换收款地址
    };
    assert_ne!(
        signed_for_a.effect_digest(),
        hijacked_to_b.effect_digest(),
        "收款人必须改变效果摘要"
    );

    // 签名层：持 A 的签名、提交 B 的收款人 → BadSignature
    let err = seq.submit(hijacked_to_b, 2_000).unwrap_err();
    assert!(matches!(err, AppchainError::BadSignature));

    // 正例：原样提交（收款人 A）受理，note 正常销毁
    seq.submit(signed_for_a, 2_100).unwrap();
    assert!(
        seq.state().notes.get(&note.commitment_bytes()).is_none(),
        "原签名 op 正常销毁 note"
    );
}

/// 托管受理 fail-closed：受理载荷与链上 op 收款人失配 → 拒绝；幂等键/
/// 金额失配同样拒绝；全等才入队。
#[test]
fn vault_enqueue_rejects_mismatched_payout_recipient() {
    let mut seq = new_sequencer();
    let a = TestUser::new(6);
    let note = deposit_and_find(&mut seq, &a, 500, AssetClass::Play, 1);
    let request_id = [0x55; 32];
    let op = burn_note(&mut seq, &a, &note, request_id);

    // 收款人被换成运营商地址 → WithdrawalConflict（账本不得记录未签名收款人）
    let mut ledger = CustodyLedger::new();
    let hijacked = WithdrawalRequest {
        request_id,
        payout_address: [0x99; 32], // ≠ op.payout_recipient（PAYOUT）
        amount: note.amount,
    };
    let err = ledger
        .enqueue_withdrawal_for_op(
            hijacked,
            &op,
            seq.withdrawal_provenance(&note).unwrap(),
            seq.finality_evidence(),
            1_000,
        )
        .unwrap_err();
    assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
    assert_eq!(ledger.queued_withdrawals(), 0, "失配不得入队");

    // 幂等键失配同样拒绝
    let wrong_id = WithdrawalRequest {
        request_id: [0x66; 32],
        payout_address: PAYOUT,
        amount: note.amount,
    };
    assert!(ledger
        .enqueue_withdrawal_for_op(
            wrong_id,
            &op,
            seq.withdrawal_provenance(&note).unwrap(),
            seq.finality_evidence(),
            1_000,
        )
        .is_err());

    // 全等（PAYOUT）→ 入队成功，且队列打款目标 == 签名收款人
    let entry = vault_request(&mut ledger, &seq, &note, &op).unwrap();
    assert_eq!(entry.request.payout_address, PAYOUT);
    let payouts = ledger.queued_payouts();
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].0.payout_address, PAYOUT);
}
