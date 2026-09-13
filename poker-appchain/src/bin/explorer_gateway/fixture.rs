//! explorer gateway — `--gen-fixture` 演示数据生成器。
//!
//! 生成最小合法的 appchain 数据（与 `loadtest.rs` 同一操作流）：
//! `OpenTable → Deposit ×2 → mark_proven_through → BuyIn ×2（真实 spend
//! 签名）→ Settle（真实 settle_effect 签名）`，第二手用第一手的赔付
//! note 再走一轮 BuyIn → Settle（不推水位 → 演示 soft_accepted 层级）。
//!
//! E2 闭环（v1.2.3）：第一手结算后由**真实证明管道**出证——
//! `ValidationEngine` prove → `drain_completions`（挂账
//! `proof_registry.jsonl`）→ `try_build_batch` 产出真实批次根 →
//! `aggregate_due` 产出一条 outer aggregate 记录（`aggregate.log`）。
//! 归档记录不是手写伪数据：与 proven log 的批次根同源（同一 pipeline）。
//!
//! 输出（`<dir>` 下）：
//! - `appchain.wal` — 经内存 sequencer 出链后由 `WalWriter::create` +
//!   `with_fsync(false)` 落盘；
//! - `proven.log` — 契约格式 JSONL（第一手结算后一条批次根记录）；
//! - `proof_registry.jsonl` — proof 归档注册表（第一手结算的 bundle）；
//! - `aggregate.log` — outer aggregate 聚合记录（一条）；
//! - stdout 打印 sequencer public hex 与文件路径（供脚本接线）。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::pipeline::{PipelineConfig, Priority, ProofJob, ProofPipeline, ValidationEngine};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    flat_settlement_plan, settle_spend_scope, settle_effect, RakeSplitRecord,
    SettleInput, SettlementRecord, SpendAuth,
};
use poker_appchain::wal::WalWriter;

use super::aggregate_log::{encode_line as encode_aggregate_line, AggregateEntry};
use super::proven_log::{encode_line, ProvenEntry};

/// 演示桌（1 桌 2 人 2 手）。
const TABLE_ID: u64 = 1;
const PLAYERS: usize = 2;
const HANDS: usize = 2;
const BUY_IN: u64 = 1_000;

/// 生成 fixture，返回 sequencer public（32B）。
///
/// # Errors
/// 目录创建/WAL 写入失败 → Err。
pub fn generate(dir: &Path) -> Result<[u8; 32], String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("fixture dir: {e}"))?;
    let wal_path = dir.join("appchain.wal");
    let proven_path = dir.join("proven.log");
    let proof_registry_path = dir.join("proof_registry.jsonl");
    let aggregate_path = dir.join("aggregate.log");
    let _ = std::fs::remove_file(&proof_registry_path);
    let _ = std::fs::remove_file(&aggregate_path);

    // E2 闭环：真实证明管道（bundle 自然落 proof 注册表——不是手写伪记录）。
    let pipeline = ProofPipeline::new(
        PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 16,
            high_watermark: 16,
            batch_interval_ms: 1_000,
        },
        Arc::new(ValidationEngine::default()),
        Arc::new(MetricsRegistry::new()),
    );
    pipeline
        .attach_proof_registry(&proof_registry_path)
        .map_err(|e| format!("fixture proof registry: {e}"))?;
    pipeline.with_registry_fsync(false);

    let seq_key = SequencerKey::from_seed(&[0xA1; 32]);
    let public = seq_key.public;

    let mut seq = Sequencer::new(
        seq_key,
        SequencerConfig {
            // fixture 生成是离线构造：放开在线限流（与 loadtest 同纪律）。
            ops_per_min: u32::MAX,
            open_table_per_min: u32::MAX,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );

    let players: Vec<Player> = (0..PLAYERS)
        .map(|i| Player::new(11 + i as u8))
        .collect();

    seq.submit(
        Operation::OpenTable {
            table_id: TABLE_ID,
            policy: FeePolicy::Zero,
        },
        1_100,
    )
    .map_err(err)?;

    let mut proven_entries: Vec<ProvenEntry> = Vec::new();
    let mut aggregate_entries: Vec<AggregateEntry> = Vec::new();

    for hand in 0..HANDS {
        let binding_be = (hand as u64 + 1).to_be_bytes();
        let mut binding32 = [0u8; 32];
        binding32[..8].copy_from_slice(&binding_be);

        if hand == 0 {
            // 第一手：每人入金 1_000（幂等 id 唯一）→ 推水位 → 买入。
            for (pi, p) in players.iter().enumerate() {
                let mut deposit_id = [0u8; 32];
                deposit_id[0] = TABLE_ID as u8;
                deposit_id[1] = pi as u8;
                deposit_id[2..10].copy_from_slice(&binding_be);
                seq.submit(
                    Operation::Deposit {
                        deposit_id,
                        owner: p.key.public_bytes(),
                        asset_class: AssetClass::Play,
                        amount: BUY_IN,
                    },
                    1_500,
                )
                .map_err(err)?;
            }
            seq.mark_proven_through(seq.state().seq);
        }

        // 买入：消费 proven 余额/赔付 note（真实 spend 签名）。
        for p in &players {
            let note = find_proven_note(&seq, &p.key.public_bytes());
            let effect = Operation::BuyIn {
                table_id: TABLE_ID,
                spends: vec![],
                notes: vec![],
                seat_owner: p.key.public_bytes(),
            }
            .effect_digest();
            seq.submit(
                Operation::BuyIn {
                    table_id: TABLE_ID,
                    spends: vec![p.buyin_auth(&note, &effect)],
                    notes: vec![note],
                    seat_owner: p.key.public_bytes(),
                },
                1_600,
            )
            .map_err(err)?;
        }

        // 结算：等额买入零费计划（单层 contested pot，全员平分）。
        let seats: Vec<Note> = players
            .iter()
            .map(|p| {
                seq.state()
                    .note_entries_of(&p.key.public_bytes())
                    .into_iter()
                    .find(|e| e.note.table_id == Some(TABLE_ID))
                    .map(|e| e.note.clone())
                    .expect("one seat note per player")
            })
            .collect();
        let pot = BUY_IN * seats.len() as u64;
        let mask = if seats.len() >= 16 {
            u16::MAX
        } else {
            (1u16 << seats.len()) - 1
        };
        let mut awards = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
        for a in awards.iter_mut().take(seats.len()) {
            *a = BUY_IN;
        }
        let plan = flat_settlement_plan(pot, mask, awards);
        let mut record = SettlementRecord {
            table_id: TABLE_ID,
            hand_binding: binding32,
            policy_commitment: FeePolicy::Zero.commitment_bytes(),
            pot,
            inputs: seats
                .iter()
                .map(|n| SettleInput {
                    note: n.clone(),
                    spend: SpendAuth {
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
                    pot_index: 0,
                    runout_index: 0,
                })
                .collect(),
            rake: RakeSplitRecord {
                total: 0,
                treasury_out: None,
                operator_out: None,
            },
            plan,
            hand_proof: None,
        };
        let effect = settle_effect(&record);
        for (i, n) in seats.iter().enumerate() {
            let p = players
                .iter()
                .find(|p| p.key.public_bytes() == n.owner)
                .expect("seat owner is a player");
            record.inputs[i].spend = p.settle_auth(n, &binding32, &effect);
        }
        seq.submit(Operation::Settle(Box::new(record.clone())), 2_000)
            .map_err(err)?;

        // 第一手结算后：真实证明管道出证 → 批次根 + 推水位（契约格式
        // JSONL；第二手不推——演示 soft_accepted 层级）。批次根折叠语义与
        // 生产管道一致：ProofJob 携带 job.record.hand_binding（pipeline.rs
        // 批次段），bundle 经 drain_completions 自然落 proof 注册表，
        // try_build_batch 产出批次根——watcher 独立重算同口径。
        if hand == 0 {
            let op_index = seq.state().seq;
            pipeline
                .submit(ProofJob {
                    op_index,
                    table_id: TABLE_ID,
                    record: Arc::new(record.clone()),
                    policy: FeePolicy::Zero,
                    priority: Priority::Play,
                })
                .map_err(|e| format!("fixture pipeline submit: {e}"))?;
            poll_until(
                || pipeline.completed_count() >= 1,
                "pipeline proves the settlement",
            )?;
            let batch = pipeline
                .try_build_batch()
                .map_err(|e| format!("fixture pipeline batch: {e}"))?
                .ok_or("fixture pipeline: batch not built")?;
            let ts_ms = seq.chain().last().map(|f| f.frame.ts_ms).unwrap_or(0);
            seq.mark_proven_through_with_root(batch.through_op, batch.root);
            proven_entries.push(ProvenEntry {
                op_index: batch.through_op,
                batch_root: batch.root,
                ts_ms,
            });
            // M4 outer aggregate：驱动定期聚合产出一条记录（空窗口 Err）。
            let rec = pipeline
                .aggregate_due(ts_ms, 1_000)
                .map_err(|e| format!("fixture aggregate: {e}"))?
                .ok_or("fixture aggregate: window did not fire")?;
            aggregate_entries.push(AggregateEntry {
                index: rec.index,
                through_op: rec.through_op,
                root: rec.root,
                ts_ms: rec.ts_ms,
                batch_count: rec.batch_count,
            });
        }
    }

    // WAL 落盘（链出全后一次性写：create + with_fsync(false)）。
    let frames = seq.export_chain();
    let mut wal = WalWriter::create(&wal_path)
        .map(|w| w.with_fsync(false))
        .map_err(|e| format!("fixture wal create: {e}"))?;
    for f in &frames {
        wal.append(f).map_err(|e| format!("fixture wal append: {e}"))?;
    }
    wal.sync().map_err(|e| format!("fixture wal sync: {e}"))?;

    // proven log（契约 JSONL；逐行带换行追加）。
    let mut log = String::new();
    for e in &proven_entries {
        log.push_str(&encode_line(e));
    }
    std::fs::write(&proven_path, log).map_err(|e| format!("fixture proven log: {e}"))?;

    // aggregate log（契约 JSONL；一条 outer aggregate 记录）。
    let mut agg = String::new();
    for e in &aggregate_entries {
        agg.push_str(&encode_aggregate_line(e));
    }
    std::fs::write(&aggregate_path, agg).map_err(|e| format!("fixture aggregate log: {e}"))?;

    // 归档条数从注册表读回（生成器自检：读不回 = 生成失败）。
    let proof_count = poker_appchain::proof_registry::read_registry(&proof_registry_path)
        .map_err(|e| format!("fixture proof registry readback: {e}"))?
        .len();

    println!(
        "{}",
        serde_json::json!({
            "sequencer_public": hex::encode(public),
            "wal": wal_path.display().to_string(),
            "proven_log": proven_path.display().to_string(),
            "proof_registry": proof_registry_path.display().to_string(),
            "aggregate_log": aggregate_path.display().to_string(),
            "frames": frames.len(),
            "settlements": seq.chain().iter().filter(|f| matches!(f.frame.op, poker_appchain::ops::Operation::Settle(_))).count(),
            "proofs": proof_count,
            "aggregates": aggregate_entries.len(),
        })
    );
    Ok(public)
}

/// 轮询等待条件成立（5s 预算；超时 → Err，fail-closed 不产出残缺 fixture）。
fn poll_until(f: impl Fn() -> bool, what: &str) -> Result<(), String> {
    for _ in 0..1_000 {
        if f() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err(format!("fixture: condition not reached within 5s: {what}"))
}

/// 统一错误转换。
fn err(e: poker_appchain::error::AppchainError) -> String {
    format!("fixture submit: {e}")
}

/// 演示玩家（OwnerKey 与 spend secret 成对，与 loadtest::Robot 同构）。
struct Player {
    key: OwnerKey,
    secret: [u8; 32],
}

impl Player {
    fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).expect("owner key from seed"),
            secret: [seed; 32],
        }
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

/// 取该 owner 名下 proven、非桌内、金额 = BUY_IN 的 note（与 loadtest 同纪律）。
fn find_proven_note(seq: &Sequencer, owner: &[u8; 33]) -> Note {
    seq.state()
        .note_entries_of(owner)
        .into_iter()
        .find(|e| {
            e.note.amount == BUY_IN && e.note.table_id.is_none() && e.status == NoteStatus::Proven
        })
        .map(|e| e.note.clone())
        .unwrap_or_else(|| panic!("no proven {BUY_IN}-note for owner"))
}
