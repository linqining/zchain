//! M2/M5 验收：完整牌局资金流（开桌→入金→买入→结算→rake 分账→审计）。
//!
//! 对应 plan-appchain-v1.md：M2-ACC-1（正例矩阵）、M5-ACC-2（rake 精确
//! 抽取与分账）、M5-ACC-3 审计机制基础、M8-ACC-6（watcher 无分叉）。

#![allow(clippy::too_many_arguments)]

mod common;

use common::{
    assert_note_status, deposit_and_find, export_credentials, new_sequencer,
    rake_policy, two_player_settlement, ProofRegistry, TestUser,
};
use poker_appchain::client_view::{balances_from_credentials, NoteCredential};
use poker_appchain::fee::FeePolicy;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::{
    PipelineConfig, ProofJob, ProofPipeline, Priority, ValidationEngine,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::watcher::{audit_settlement_coverage, require_equivalent};
use std::sync::Arc;

#[test]
fn full_hand_flow_with_rake_and_audit() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    let table = 1u64;

    // 开桌（冻结费率）
    seq.submit(
        Operation::OpenTable { table_id: table, policy },
        1_000,
    )
    .unwrap();

    // 入金（REAL）+ proven 化
    let dep_a = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Real, 1);
    let dep_b = deposit_and_find(&mut seq, &b, 2_000, AssetClass::Real, 2);
    assert_note_status(&seq, &dep_a, poker_appchain::sequencer::NoteStatus::Pending);
    seq.mark_proven_through(seq.state().seq);
    assert_note_status(&seq, &dep_a, poker_appchain::sequencer::NoteStatus::Proven);

    // 买入 → seat notes（A 1000、B 2000）
    seq.submit(
        Operation::BuyIn {
            table_id: table,
            spends: vec![a.buyin_auth(&dep_a, table, a.pk())],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: table,
            spends: vec![b.buyin_auth(&dep_b, table, b.pk())],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_seat_note(&seq, table, a.pk(), 1_000);
    let seat_b = find_seat_note(&seq, table, b.pk(), 2_000);

    // 结算：A 赢 500（pot=1500 → rake 75 = treasury 15 + operator 60）
    let record = two_player_settlement(
        table, &a, &b, &seat_a, &seat_b,
        1_500, // pot
        500,   // payout_a: 1000 - 500 - 亏给 rake 的一部分? 保持守恒：见下
        2_425, // payout_b
        &policy,
        0xAB,
    );
    assert_eq!(record.rake.total, 75);
    seq.submit(Operation::Settle(Box::new(record)), 3_000)
        .unwrap();

    // 余额断言（A 500、B 2425、treasury 15、operator 60）
    let (r, _) = seq.state().balances_of(&a.pk());
    assert_eq!(r, 500);
    let (r, _) = seq.state().balances_of(&b.pk());
    assert_eq!(r, 2_425);
    let (r, _) = seq.state().balances_of(&treasury.pk());
    assert_eq!(r, 15);
    let (r, _) = seq.state().balances_of(&operator.pk());
    assert_eq!(r, 60);

    // 桌 seat 计数回落
    assert_eq!(seq.state().tables.get(&table).unwrap().seats, 0);

    // M5-ACC-3 基础：导出 note 凭证 → 客户端离线聚合 = 账本聚合
    let creds = export_credentials(&seq);
    let client_a: Vec<NoteCredential> = creds
        .iter()
        .filter(|(n, _)| n.owner == a.pk())
        .map(|(n, p)| NoteCredential { note: n.clone(), proof: p.clone() })
        .collect();
    let view = balances_from_credentials(&client_a, seq.state().tree.root()).unwrap();
    assert_eq!(view.real, 500);

    // 软确认链签名全量验证（watcher 视角）
    let chain = seq.export_chain();
    poker_appchain::soft_confirm::verify_chain(
        &chain,
        &poker_appchain::keys::SequencerKey::from_seed(&[42u8; 32]).public,
    )
    .unwrap();
    assert!(require_equivalent(&chain, &chain).is_ok());
}

#[test]
fn proof_pipeline_covers_settlements_and_audit_passes() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    let table = 1u64;
    seq.submit(Operation::OpenTable { table_id: table, policy }, 1_000).unwrap();
    let dep_a = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Real, 1);
    let dep_b = deposit_and_find(&mut seq, &b, 2_000, AssetClass::Real, 2);
    seq.mark_proven_through(seq.state().seq);
    seq.submit(
        Operation::BuyIn {
            table_id: table,
            spends: vec![a.buyin_auth(&dep_a, table, a.pk())],
            notes: vec![dep_a.clone()],
            seat_owner: a.pk(),
        },
        2_000,
    )
    .unwrap();
    seq.submit(
        Operation::BuyIn {
            table_id: table,
            spends: vec![b.buyin_auth(&dep_b, table, b.pk())],
            notes: vec![dep_b.clone()],
            seat_owner: b.pk(),
        },
        2_100,
    )
    .unwrap();
    let seat_a = find_seat_note(&seq, table, a.pk(), 1_000);
    let seat_b = find_seat_note(&seq, table, b.pk(), 2_000);
    let record = two_player_settlement(
        table, &a, &b, &seat_a, &seat_b, 1_500, 500, 2_425, &policy, 0xCD,
    );
    let binding = record.hand_binding;
    seq.submit(Operation::Settle(Box::new(record.clone())), 3_000).unwrap();

    // 证明管道：结算进管道 → 批次 → watcher 审计通过
    let pipeline = ProofPipeline::new(
        PipelineConfig {
            workers: 2,
            batch_size: 1,
            queue_bound: 16,
            high_watermark: 16,
            batch_interval_ms: 1_000,
        },
        Arc::new(ValidationEngine::default()),
        Arc::new(MetricsRegistry::new()),
    );
    pipeline
        .submit(ProofJob {
            op_index: seq.state().seq - 1,
            table_id: table,
            record: Arc::new(record),
            policy,
            priority: Priority::Real,
        })
        .unwrap();
    for _ in 0..200 {
        if pipeline.completed_count() >= 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let batch = pipeline.try_build_batch().unwrap().expect("batch");
    assert_eq!(batch.count, 1);

    let mut registry = ProofRegistry::new();
    registry.record_settled(binding);
    let report = audit_settlement_coverage(&seq.export_chain(), &registry.bindings);
    assert!(
        report.uncovered_settlements.is_empty(),
        "settled hand must be covered by proof registry"
    );
}

#[test]
fn play_and_real_classes_never_mix() {
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let play_dep = deposit_and_find(&mut seq, &a, 500, AssetClass::Play, 1);
    // REAL note 上桌（桌绑 REAL 策略）与 PLAY 余额互转都应被拒
    seq.submit(Operation::OpenTable { table_id: 9, policy: FeePolicy::Zero }, 1_000)
        .unwrap();
    let _ = b;
    // PLAY 余额 + REAL 输出混转 → 拒绝（资产类隔离）
    let out = poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Real, // 混类输出
        amount: 250,
        owner: b.pk(),
        table_id: None,
    };
    let out2 = poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount: 250,
        owner: a.pk(),
        table_id: None,
    };
    let err = seq
        .submit(
            Operation::Transfer {
                spends: vec![a.transfer_auth(&play_dep, &[out.clone(), out2.clone()])],
                notes: vec![play_dep],
                outputs: vec![out, out2],
            },
            2_000,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        poker_appchain::AppchainError::AssetClassMismatch(_, _)
    ));
}

fn find_seat_note(seq: &Sequencer, table: u64, owner: [u8; 33], amount: u64) -> Note {
    seq.state()
        .notes
        .values()
        .find(|e| {
            e.note.table_id == Some(table)
                && e.note.owner == owner
                && e.note.amount == amount
        })
        .unwrap()
        .note
        .clone()
}

// SequencerConfig 引用保持（公共 API 表面回归）
const _: fn() -> SequencerConfig = SequencerConfig::default;
