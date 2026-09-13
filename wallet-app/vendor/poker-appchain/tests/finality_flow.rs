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

/// 在 sequencer 上软确认一笔提现销毁（返回被销毁的 note）。
fn burn_note(seq: &mut Sequencer, user: &TestUser, note: &Note, request_id: [u8; 32]) {
    let effect = Operation::WithdrawRequest {
        spend: SpendAuth {
            commitment: [0; 32],
            nullifier: [0; 32],
            sig: EcdsaSig { bytes: [0; 64] },
        },
        note: note.clone(),
        request_id,
    }
    .effect_digest();
    let nf = felt_to_bytes32(&note.nullifier(&user.secret));
    let d = spend_digest(&note.commitment_bytes(), &nf, scope::WITHDRAW, &effect);
    let spend = SpendAuth {
        commitment: note.commitment_bytes(),
        nullifier: nf,
        sig: user.key.sign(&d),
    };
    seq.submit(
        Operation::WithdrawRequest {
            spend,
            note: note.clone(),
            request_id,
        },
        2_000,
    )
    .expect("soft-confirm layer accepts withdrawal burn (finality gate is payout-side)");
}

/// 托管侧提现申请（provenance/证据取自 sequencer 快照）。
fn vault_request(
    ledger: &mut CustodyLedger,
    seq: &Sequencer,
    note: &Note,
    request_id: [u8; 32],
) -> Result<poker_appchain::vault::WithdrawalEntry, AppchainError> {
    let provenance = seq.withdrawal_provenance(note).expect("note in ledger");
    let finality = seq.finality_evidence();
    ledger
        .enqueue_withdrawal(
            WithdrawalRequest {
                request_id,
                payout_address: [0xEE; 32],
                amount: note.amount,
            },
            provenance,
            finality,
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
    burn_note(&mut seq, &a, &note, request_id);

    // 负例 A：无水位无批次根 → WithdrawalNotFinalized（op 0）
    let err = vault_request(&mut ledger, &seq, &note, request_id).unwrap_err();
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
    let err = vault_request(&mut ledger, &seq, &note, request_id).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::WithdrawalNotFinalized { .. }
    ));
    assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);

    // 正例：批次根记录（模拟证明管道批次回调）→ 放行
    seq.mark_proven_through_with_root(seq.state().seq - 1, [0xAB; 32]);
    let entry = vault_request(&mut ledger, &seq, &note, request_id).expect("finalized");
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
    burn_note(&mut seq, &a, &note, request_id);
    let entry = vault_request(&mut ledger, &seq, &note, request_id)
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
    burn_note(&mut seq, &a, &note, request_id);

    // 默认构造 fail-closed
    let mut strict = CustodyLedger::new();
    assert!(vault_request(&mut strict, &seq, &note, request_id).is_err());

    // 显式 opt-out 放行（构造点即语义声明）
    let mut lenient = CustodyLedger::new().without_finality_gate();
    assert!(!lenient.finality_required());
    let entry = vault_request(&mut lenient, &seq, &note, request_id)
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
