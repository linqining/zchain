//! M9：多桌机器人压测——容量报告生成器。
//!
//! 模拟 N 桌并发对局（每手：入金→推证明水位→买入→结算），直接驱动
//! sequencer + 证明管道，输出 JSON 容量报告。
//!
//! 用法：`cargo run -p poker-appchain --release --bin loadtest -- --tables 64 --hands 50`
//!
//! 注意：报告里的"证明就绪"是 host-validate 引擎（机制基准）；stwo 真
//! 引擎接入后用同一脚本复测（见 docs/plan-appchain-v1-blockers.md）。

use std::sync::Arc;
use std::time::{Duration, Instant};

use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::{evaluate_alerts, MetricsRegistry};
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::pipeline::{
    PipelineConfig, ProofJob, ProofPipeline, Priority, ValidationEngine,
};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    settle_spend_scope, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};

struct Robot {
    key: OwnerKey,
    secret: [u8; 32],
}

impl Robot {
    fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
            secret: [seed; 32],
        }
    }

    fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
    }

    fn buyin_auth(&self, note: &Note, effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            scope::BUYIN,
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }

    fn settle_auth(&self, note: &Note, binding: &[u8; 32], effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            &settle_spend_scope(binding),
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }
}

fn find_proven_note(seq: &Sequencer, owner: &[u8; 33], amount: u64) -> Note {
    seq.state()
        .notes
        .values()
        .find(|e| {
            e.note.owner == *owner
                && e.note.amount == amount
                && e.note.table_id.is_none()
                && e.status == NoteStatus::Proven
        })
        .map(|e| e.note.clone())
        .unwrap_or_else(|| panic!("no proven {amount}-note for owner"))
}

fn parse_arg(name: &str, default: usize) -> usize {
    std::env::args()
        .position(|a| a == name)
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let tables = parse_arg("--tables", 64);
    let hands_per_table = parse_arg("--hands", 50);
    let players = parse_arg("--players", 2).clamp(2, 9);

    let metrics = Arc::new(MetricsRegistry::new());
    let mut seq = Sequencer::new(
        SequencerKey::from_seed(&[7u8; 32]),
        SequencerConfig {
            // 压测档：放开限流（基准测吞吐，不测 DoS 防御——限流本身有
            // 单元与验收测试覆盖）
            ops_per_min: u32::MAX,
            open_table_per_min: u32::MAX,
            ..SequencerConfig::default()
        },
        Arc::clone(&metrics),
    );
    let pipeline = ProofPipeline::new(
        PipelineConfig {
            workers: 4,
            queue_bound: 8_192,
            high_watermark: 6_000,
            batch_size: 64,
            batch_interval_ms: 5_000,
        },
        Arc::new(ValidationEngine::default()),
        Arc::clone(&metrics),
    );

    let robots: Vec<Robot> = (1..=players as u8).map(Robot::new).collect();
    let t0 = Instant::now();
    let mut lat_us: Vec<u64> = Vec::new();
    let mut settle_count = 0u64;
    let mut binding: u64 = 0;

    for table in 1..=tables {
        seq.submit(
            Operation::OpenTable {
                table_id: table as u64,
                policy: FeePolicy::Zero,
            },
            1_100,
        )
        .unwrap();

        for _hand in 0..hands_per_table {
            binding += 1;
            let binding_be = binding.to_be_bytes();

            // 1. 每人入金 1_000（幂等 id 唯一）
            for (pi, r) in robots.iter().enumerate() {
                let mut deposit_id = [0u8; 32];
                deposit_id[0] = table as u8;
                deposit_id[1] = pi as u8;
                deposit_id[2..10].copy_from_slice(&binding_be);
                seq.submit(
                    Operation::Deposit {
                        deposit_id,
                        owner: r.pk(),
                        asset_class: AssetClass::Play,
                        amount: 1_000,
                    },
                    1_500,
                )
                .unwrap();
            }
            // 2. 推证明水位（桌准入只收 proven note）
            seq.mark_proven_through(seq.state().seq);
            // 3. 买入（消费 proven 余额 note → 铸 seat note）
            for r in &robots {
                let note = find_proven_note(&seq, &r.pk(), 1_000);
                let effect = Operation::BuyIn {
                    table_id: table as u64,
                    spends: vec![],
                    notes: vec![],
                    seat_owner: r.pk(),
                }
                .effect_digest();
                let t = Instant::now();
                seq.submit(
                    Operation::BuyIn {
                        table_id: table as u64,
                        spends: vec![r.buyin_auth(&note, &effect)],
                        notes: vec![note],
                        seat_owner: r.pk(),
                    },
                    1_600,
                )
                .unwrap();
                lat_us.push(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX));
            }
            // 本桌 seat note（table_id = Some(table)，Pending 可直接结算）
            let seats: Vec<Note> = seq
                .state()
                .notes
                .values()
                .filter(|e| e.note.table_id == Some(table as u64))
                .map(|e| e.note.clone())
                .collect();
            assert_eq!(seats.len(), robots.len(), "one seat note per robot");
            let mut binding32 = [0u8; 32];
            binding32[..8].copy_from_slice(&binding_be);
            // 4. 结算（零费：全 seat 消费 → 等额赔付）。两段构造：
            // 先成型记录，再按结算效果摘要逐个补签名（S1）
            let mut record = SettlementRecord {
                table_id: table as u64,
                hand_binding: binding32,
                policy_commitment: FeePolicy::Zero.commitment_bytes(),
                pot: 1_000 * seats.len() as u64,
                inputs: seats
                    .iter()
                    .map(|n| SettleInput {
                        note: n.clone(),
                        spend: poker_appchain::settlement::SpendAuth {
                            commitment: n.commitment_bytes(),
                            nullifier: [0; 32],
                            sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                        },
                    })
                    .collect(),
                payouts: seats
                    .iter()
                    .map(|n| poker_appchain::note::NoteSpec {
                        asset_class: AssetClass::Play,
                        amount: n.amount,
                        owner: n.owner,
                        table_id: None,
                    })
                    .collect(),
                rake: RakeSplitRecord {
                    total: 0,
                    treasury_out: None,
                    operator_out: None,
                },
                hand_proof: None,
            };
            for (i, n) in seats.iter().enumerate() {
                // 按 note 的 owner 找机器人（HashMap 迭代序不定）
                let r = robots
                    .iter()
                    .find(|r| r.pk() == n.owner)
                    .expect("seat owner is a robot");
                record.inputs[i].spend = r.settle_auth(n, &binding32, &poker_appchain::settlement::settle_effect(&record));
            }
            let op_index = seq.state().seq;
            seq.submit(Operation::Settle(Box::new(record.clone())), 2_000)
                .unwrap();
            settle_count += 1;
            pipeline
                .submit(ProofJob {
                    op_index,
                    table_id: table as u64,
                    record: Arc::new(record),
                    policy: FeePolicy::Zero,
                    priority: Priority::Play,
                })
                .unwrap();
        }
    }

    // 证明就绪等待
    let prove_start = Instant::now();
    loop {
        if pipeline.completed_count() >= settle_count {
            break;
        }
        if prove_start.elapsed() > Duration::from_secs(120) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let total_elapsed = t0.elapsed();

    lat_us.sort_unstable();
    let pct = |q: f64| -> u64 {
        lat_us
            .get(((lat_us.len() as f64 - 1.0) * q).round() as usize)
            .copied()
            .unwrap_or(0)
    };
    let report = serde_json::json!({
        "tables": tables,
        "hands_per_table": hands_per_table,
        "players": players,
        "settlements": settle_count,
        "proof_completed": pipeline.completed_count(),
        "buyin_soft_confirm_us": { "p50": pct(0.5), "p99": pct(0.99), "max": lat_us.last().copied().unwrap_or(0) },
        "wall_clock_s": total_elapsed.as_secs_f64(),
        "ops_total": seq.state().seq,
        "alert_count": evaluate_alerts(&pipeline.health()).len(),
        "engine": poker_appchain::pipeline::SettlementProver::name(&ValidationEngine::default()),
    });
    println!("{report:#}");
}
