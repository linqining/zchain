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
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::{
    PipelineConfig, ProofJob, ProofPipeline, Priority, ValidationEngine,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    validate_settlement, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use poker_appchain::watcher::{audit_settlement_coverage, require_equivalent};
use poker_settlement_core::{derive_settlement_plan, SettlementBoards, TableSnapshot};
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

    // 结算（v1.2：pot = Σseat notes = 3000；5% → rake 150 = treasury 30 + operator 120）
    // A 保 500（本手输 500），B 拿 2350（赢 500 − rake 150）
    let record = two_player_settlement(
        table, &a, &b, &seat_a, &seat_b,
        3_000, // pot = Σseat notes（plan.gross_pot）
        500,   // payout_a
        2_350, // payout_b（Σpayouts = pot − rake）
        &policy,
        0xAB,
    );
    assert_eq!(record.rake.total, 150);
    assert_eq!(record.plan.gross_pot, 3_000);
    assert_eq!(record.plan.rake, 150);
    seq.submit(Operation::Settle(Box::new(record)), 3_000)
        .unwrap();

    // 余额断言（A 500、B 2350、treasury 30、operator 120）
    let (r, _) = seq.state().balances_of(&a.pk());
    assert_eq!(r, 500);
    let (r, _) = seq.state().balances_of(&b.pk());
    assert_eq!(r, 2_350);
    let (r, _) = seq.state().balances_of(&treasury.pk());
    assert_eq!(r, 30);
    let (r, _) = seq.state().balances_of(&operator.pk());
    assert_eq!(r, 120);

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
fn uncalled_return_layer_hand_settles_with_contested_only_rake() {
    // B9 / ABI v1.2.2：含 uncalled 返还层的手按 contested-only 口径计费。
    // 牌局：3 人 REAL 桌——座0 全下加注 200、座1 覆盖全下 500、座2 弃牌
    // （50 死钱）；showdown 座1 赢。plan 分层 = [450 contested（含死钱）,
    // 300 uncalled 返还座1]，rake 基数 = 450（5% → 22），而**非**全额
    // gross 750（5% → 37）。旧口径（v1.2.1 前）按 750 计费会把这样一手
    // 合法手 fail-closed 误拒；v1.2.2 起正常结算。
    let mut seq = new_sequencer();
    let raiser = TestUser::new(1); // 座0：全下 200，输
    let shover = TestUser::new(2); // 座1：全下 500，赢（300 为 uncalled 返还）
    let folder = TestUser::new(3); // 座2：preflop 弃牌，死钱 50
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    let table = 21u64;
    seq.submit(Operation::OpenTable { table_id: table, policy }, 1_000).unwrap();

    let dep_raiser = deposit_and_find(&mut seq, &raiser, 200, AssetClass::Real, 0x51);
    let dep_shover = deposit_and_find(&mut seq, &shover, 500, AssetClass::Real, 0x52);
    let dep_folder = deposit_and_find(&mut seq, &folder, 50, AssetClass::Real, 0x53);
    seq.mark_proven_through(seq.state().seq);
    for (user, dep) in [(&raiser, &dep_raiser), (&shover, &dep_shover), (&folder, &dep_folder)] {
        seq.submit(
            Operation::BuyIn {
                table_id: table,
                spends: vec![user.buyin_auth(dep, table, user.pk())],
                notes: vec![dep.clone()],
                seat_owner: user.pk(),
            },
            2_000,
        )
        .unwrap();
    }
    let seat_raiser = find_seat_note(&seq, table, raiser.pk(), 200);
    let seat_shover = find_seat_note(&seq, table, shover.pk(), 500);
    let seat_folder = find_seat_note(&seq, table, folder.pk(), 50);

    // plan 派生（poker-settlement-core 单一事实源，与 poker_l1 canonical 同码）：
    // 座0 ♠2♠3，座1 ♠A♠K，单板 ♠Q♠J♠10♥2♦2 → 座1 皇家同花顺独大。
    let total_bets = [200u64, 500, 50];
    let inactive = [false, false, true];
    let all_in = [true, true, false];
    let holes: [&[u8]; 3] = [&[0u8, 1], &[12, 11], &[]];
    let snapshot = TableSnapshot {
        seat_count: 3,
        button: 0,
        total_bets: &total_bets,
        inactive: &inactive,
        all_in: &all_in,
        hole_cards: &holes,
        rake_mode: poker_settlement_core::RAKE_MODE_PERCENTAGE,
        rake_bps: 500,
        // 注意：TableSnapshot.rake_cap 是硬上限数值（非 FeePolicy 的 0=无封顶
        // 语义）；取 1_000 与 e2e 场景一致，本手 rake 22 不触发。
        rake_cap: 1_000,
    };
    let boards = SettlementBoards::single(vec![10, 9, 8, 13, 26]);
    let plan = derive_settlement_plan(&snapshot, &boards).expect("settlement plan");
    assert_eq!(plan.gross_pot, 750);
    assert_eq!(plan.pots.len(), 2);
    assert!(plan.pots[0].is_contested());
    assert_eq!(plan.pots[0].gross_amount, 450);
    assert!(!plan.pots[1].is_contested(), "uncalled 返还层");
    assert_eq!(plan.pots[1].gross_amount, 300);
    assert_eq!(plan.pots[1].rake, 0, "uncalled 层零 rake（plan.validate 强制）");
    // 跨 crate 口径一致性（B9 核心）：plan.rake == policy.rake_of(rake_base)
    assert_eq!(plan.rake_base(), 450);
    assert_eq!(u64::from(plan.rake), policy.rake_of(plan.rake_base()));
    assert_eq!(plan.rake, 22);
    // 旧口径对照：全额 gross 计费（37）与 contested-only（22）不同——
    // 同一记录在 v1.2.1 前必然 FeeMismatch 拒绝
    assert_eq!(policy.rake_of(plan.gross_pot), 37);
    assert_ne!(u64::from(plan.rake), policy.rake_of(plan.gross_pot));
    // 投影：contested 层净 428 归座1，uncalled 层 300 全额返还座1
    assert_eq!(plan.pots[0].runouts[0].awards[1], 428);
    assert_eq!(plan.pots[1].runouts[0].awards[1], 300);
    assert_eq!(plan.awards[1], 728);
    assert_eq!(plan.awards[0], 0);
    assert_eq!(plan.awards[2], 0);

    // 结算记录：payouts 与 plan 投影一一对应（pot0/pot1 各一笔，均归座1）
    let mk = |amount: u64, pot_index: u8| NoteSpec {
        asset_class: AssetClass::Real,
        amount,
        owner: shover.pk(),
        table_id: None,
        pot_index,
        runout_index: 0,
    };
    let mk_rake = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: AssetClass::Real,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    let (t_exp, o_exp) = policy.split_of(22);
    assert_eq!((t_exp, o_exp), (4, 18));
    let mut record = SettlementRecord {
        table_id: table,
        hand_binding: [0xB9; 32],
        policy_commitment: policy.commitment_bytes(),
        pot: 750,
        inputs: vec![
            SettleInput {
                note: seat_raiser.clone(),
                spend: SpendAuth {
                    commitment: seat_raiser.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_shover.clone(),
                spend: SpendAuth {
                    commitment: seat_shover.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
            SettleInput {
                note: seat_folder.clone(),
                spend: SpendAuth {
                    commitment: seat_folder.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        ],
        payouts: vec![mk(428, 0), mk(300, 1)],
        rake: RakeSplitRecord {
            total: 22,
            treasury_out: Some(mk_rake(t_exp, treasury.pk())),
            operator_out: Some(mk_rake(o_exp, operator.pk())),
        },
        plan: plan.clone(),
        hand_proof: None,
    };
    record.inputs[0].spend = raiser.settle_auth(&seat_raiser, &record);
    record.inputs[1].spend = shover.settle_auth(&seat_shover, &record);
    record.inputs[2].spend = folder.settle_auth(&seat_folder, &record);
    validate_settlement(&record, &policy).expect("uncalled-layer hand must settle (B9)");
    seq.submit(Operation::Settle(Box::new(record.clone())), 3_000)
        .expect("previously rejected hand now settles at soft-confirm");

    // 资金断言：赢家 728（含 300 uncalled 返还），rake 22 = treasury 4 + operator 18
    assert_eq!(seq.state().balances_of(&raiser.pk()), (0, 0));
    assert_eq!(seq.state().balances_of(&shover.pk()), (728, 0));
    assert_eq!(seq.state().balances_of(&folder.pk()), (0, 0));
    assert_eq!(seq.state().balances_of(&treasury.pk()), (4, 0));
    assert_eq!(seq.state().balances_of(&operator.pk()), (18, 0));
    assert_eq!(seq.state().tables.get(&table).unwrap().seats, 0);

    // ===== 负例回归（B9 后仍全拒）=====

    // 负例 1：跨层挪 rake——把 contested 层的 rake 挪 10 进 uncalled 返还层
    // （总额自洽、plan.rake 不变）。plan.validate 在签名验证前即拒：
    // uncontested 层必须零 rake（"跨层挪 rake"通路整体封死）。
    {
        let mut shifted = record.clone();
        shifted.plan.pots[0].rake = 12;
        shifted.plan.pots[0].net_amount = 438;
        shifted.plan.pots[0].runouts[0].amount = 438;
        shifted.plan.pots[0].runouts[0].awards[1] = 438;
        shifted.plan.pots[1].rake = 10; // uncalled 层被塞 rake → fail-closed
        shifted.plan.pots[1].net_amount = 290;
        shifted.plan.pots[1].runouts[0].amount = 290;
        shifted.plan.pots[1].runouts[0].awards[1] = 290;
        let err = validate_settlement(&shifted, &policy).unwrap_err();
        assert!(
            matches!(err, poker_appchain::AppchainError::Codec(_)),
            "cross-layer rake shift must be rejected by plan.validate, got {err:?}"
        );
    }

    // 负例 2：整体自洽的低报 rake（plan/分账/payouts 同步 21 并完整重签，
    // 签名/守恒/投影/分账全过）——唯一拒点是费率关系
    // rake.total(21) != policy.rake_of(rake_base=450)=22。
    {
        let mut under = record.clone();
        under.plan.pots[0].rake = 21;
        under.plan.pots[0].net_amount = 429;
        under.plan.pots[0].runouts[0].amount = 429;
        under.plan.pots[0].runouts[0].awards[1] = 429;
        under.plan.rake = 21;
        under.plan.total_awards = 729;
        under.plan.awards[1] = 729;
        under.rake.total = 21;
        let (t, o) = policy.split_of(21);
        under.rake.treasury_out = Some(mk(t, 0));
        under.rake.operator_out = Some(mk(o, 0));
        under.payouts = vec![mk(429, 0), mk(300, 1)];
        under.inputs[0].spend = raiser.settle_auth(&seat_raiser, &under);
        under.inputs[1].spend = shover.settle_auth(&seat_shover, &under);
        under.inputs[2].spend = folder.settle_auth(&seat_folder, &under);
        let err = validate_settlement(&under, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                poker_appchain::AppchainError::FeeMismatch { expected: 22, got: 21 }
            ),
            "under-reported rake must fail the contested-only fee relation, got {err:?}"
        );
    }
}

#[test]
fn proof_pipeline_covers_settlements_and_audit_passes() {
    // 注（P0-3）：本测试走 ValidationEngine（host attestation）——该引擎
    // 对 REAL 结算一律拒绝出证（`RealRequiresStarkProof`，真实 STARK 路径
    // 的 REAL 全流程回归见 poker-appchain-texasair 适配器测试）。管道覆盖
    // /审计语义与资产类无关，故用 PLAY 资金流验证；Priority::Real 仅影响
    // 调度，与出证策略门无关。
    let mut seq = new_sequencer();
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let treasury = TestUser::new(7);
    let operator = TestUser::new(8);
    let policy = rake_policy(&treasury, &operator);
    let table = 1u64;
    seq.submit(Operation::OpenTable { table_id: table, policy }, 1_000).unwrap();
    let dep_a = deposit_and_find(&mut seq, &a, 1_000, AssetClass::Play, 1);
    let dep_b = deposit_and_find(&mut seq, &b, 2_000, AssetClass::Play, 2);
    // 只标记到最后的实际操作（0..=seq-1）——结算 op 留给批次回调覆盖
    seq.mark_proven_through(seq.state().seq - 1);
    let proven_before_settle = seq.proven_watermark();
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
        table, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, 0xCD,
    );
    let binding = record.hand_binding;
    seq.submit(Operation::Settle(Box::new(record.clone())), 3_000).unwrap();
    let settle_op_index = seq.state().seq - 1;
    // P0-5：批次验证通过前水位停在存款阶段（不得越过未证明的结算 op）
    assert_eq!(seq.proven_watermark(), proven_before_settle);
    assert!(proven_before_settle < settle_op_index);

    // 证明管道：结算进管道 → 批次 → watcher 审计通过。
    // P0-5 接线（与生产装配点同构）：批次验证通过回调推进 sequencer 水位。
    let seq = Arc::new(std::sync::Mutex::new(seq));
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
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    pipeline
        .submit(ProofJob {
            op_index: settle_op_index,
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
    assert_eq!(batch.through_op, settle_op_index);
    // P0-5：接线真实生效——水位由批次回调推进到结算 op
    assert_eq!(seq.lock().unwrap().proven_watermark(), settle_op_index);

    let mut registry = ProofRegistry::new();
    registry.record_settled(binding);
    let report = audit_settlement_coverage(&seq.lock().unwrap().export_chain(), &registry.bindings);
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
        pot_index: 0,
        runout_index: 0,
    };
    let out2 = poker_appchain::note::NoteSpec {
        asset_class: AssetClass::Play,
        amount: 250,
        owner: a.pk(),
        table_id: None,
        pot_index: 0,
        runout_index: 0,
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
