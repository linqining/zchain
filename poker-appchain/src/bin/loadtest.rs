//! M9：多桌机器人压测——容量报告生成器。
//!
//! 模拟 N 桌并发对局（每手：入金→推证明水位→买入→结算），直接驱动
//! sequencer + 证明管道，输出 JSON 容量报告。
//!
//! 用法：
//!
//! ```text
//! loadtest --tables 64 --hands 50                       # 定量模式（基线口径）
//! loadtest --tables 64 --duration-secs 3600             # 长压测模式（M9-ACC-1）
//!          [--hand-interval-ms 250] [--players 2] [--out <file>]
//! ```
//!
//! - 定量模式：每桌 `--hands` 手后结束（与既有 64×50 基线逐操作同构）；
//! - 长压测模式（`--duration-secs N`）：持续到时限，桌循环开新手；
//!   输出容量报告（总手数、TPH 曲线采样、soft_confirm p99、proof_ready
//!   p95、积压峰值、告警次数）。`--hand-interval-ms` 为全局节流
//!   （0 = 不限速；模拟真实桌速建议 250ms ≈ 4 手/秒全局）。
//!   进度每 30s 打一行 `soak-progress ...` 到 stderr（中断时可取部分
//!   数据，不虚报）。
//!
//! 注意：报告里的"证明就绪"是 host-validate 引擎（机制基准）；stwo 真
//! 引擎接入后用同一脚本复测（见 docs/plan-appchain-v1-blockers.md）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    // B5：经 owner 二级索引取该 owner 的 note（O(1) 命中 + k 次过滤），
    // 不再全账本 O(n) 线性扫描——64 桌压测墙钟主因即此处
    seq.state()
        .note_entries_of(owner)
        .into_iter()
        .find(|e| {
            e.note.amount == amount
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

fn str_arg(name: &str) -> Option<String> {
    std::env::args()
        .position(|a| a == name)
        .and_then(|i| std::env::args().nth(i + 1))
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// 一手牌的链侧生成（入金→推水位→买入→结算），持 sequencer 锁执行；
/// 证明任务由调用方在**释放锁之后**入队（管道的批次回调会回锁 sequencer
/// ——持锁提交会造成 seq ↔ pipeline 锁序倒置死锁）。
struct HandDriver<'a> {
    seq: &'a mut Sequencer,
    metrics: &'a Arc<MetricsRegistry>,
    robots: &'a [Robot],
    /// 全局手绑定序号（单调递增，跨桌唯一）。
    binding: u64,
    /// 本 driver 累积的 buyin 提交延迟（微秒；soft_confirm 代理指标）。
    lat_us: Vec<u64>,
}

/// 证明任务入队所需的产物（链侧生成完毕后交 pipeline）。
struct ProofTask {
    op_index: u64,
    table_id: u64,
    record: SettlementRecord,
}

impl<'a> HandDriver<'a> {
    fn prepare_hand(&mut self, table: u64) -> ProofTask {
        self.binding += 1;
        let binding_be = self.binding.to_be_bytes();

        // 1. 每人入金 1_000（幂等 id 唯一）
        for (pi, r) in self.robots.iter().enumerate() {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = table as u8;
            deposit_id[1] = pi as u8;
            deposit_id[2..10].copy_from_slice(&binding_be);
            self.seq
                .submit(
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
        let cur = self.seq.state().seq;
        self.seq.mark_proven_through(cur);
        // 3. 买入（消费 proven 余额 note → 铸 seat note）
        for r in self.robots.iter() {
            let note = find_proven_note(self.seq, &r.pk(), 1_000);
            let effect = Operation::BuyIn {
                table_id: table,
                spends: vec![],
                notes: vec![],
                seat_owner: r.pk(),
            }
            .effect_digest();
            let t = Instant::now();
            self.seq
                .submit(
                    Operation::BuyIn {
                        table_id: table,
                        spends: vec![r.buyin_auth(&note, &effect)],
                        notes: vec![note],
                        seat_owner: r.pk(),
                    },
                    1_600,
                )
                .unwrap();
            self.lat_us
                .push(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX));
        }
        // 本桌 seat note（table_id = Some(table)，Pending 可直接结算）。
        // B5：逐 robot 经 owner 二级索引取，不再全账本 O(n) 扫描
        let seats: Vec<Note> = self
            .robots
            .iter()
            .map(|r| {
                self.seq
                    .state()
                    .note_entries_of(&r.pk())
                    .into_iter()
                    .find(|e| e.note.table_id == Some(table))
                    .map(|e| e.note.clone())
                    .expect("one seat note per robot")
            })
            .collect();
        assert_eq!(seats.len(), self.robots.len(), "one seat note per robot");
        let mut binding32 = [0u8; 32];
        binding32[..8].copy_from_slice(&binding_be);
        // v1.2：等额买入零费计划（单层 contested pot，全员平分；P0-2）
        let plan = {
            use poker_settlement_core::{
                RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule,
                SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS,
            };
            let gross = 1_000u64 * seats.len() as u64;
            let mask =
                if seats.len() >= 16 { u16::MAX } else { (1u16 << seats.len()) - 1 };
            // awards 只对实际座位非零（Σawards 必须 == runout.amount ==
            // gross，否则 plan.validate fail-closed 拒绝）
            let mut awards = [0u64; SETTLEMENT_SEATS];
            for a in awards.iter_mut().take(seats.len()) {
                *a = 1_000;
            }
            let mut runout = RunoutPotPlan::inactive();
            runout.amount = gross;
            runout.winner_mask = mask;
            runout.awards = awards;
            SettlementPlan {
                version: SETTLEMENT_PLAN_VERSION,
                schedule: SettlementRunoutSchedule::Single,
                gross_pot: gross,
                rake: 0,
                total_awards: gross,
                winner_mask: mask,
                awards,
                pots: vec![SettlementPotPlan {
                    pot_index: 0,
                    gross_amount: gross,
                    rake: 0,
                    net_amount: gross,
                    eligible_mask: mask,
                    runouts: [runout, RunoutPotPlan::inactive()],
                }],
            }
        };
        // 4. 结算（零费：全 seat 消费 → 等额赔付）。两段构造：
        // 先成型记录，再按结算效果摘要逐个补签名（S1）
        let mut record = SettlementRecord {
            table_id: table,
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
        for (i, n) in seats.iter().enumerate() {
            // 按 note 的 owner 找机器人（HashMap 迭代序不定）
            let r = self
                .robots
                .iter()
                .find(|r| r.pk() == n.owner)
                .expect("seat owner is a robot");
            record.inputs[i].spend =
                r.settle_auth(n, &binding32, &poker_appchain::settlement::settle_effect(&record));
        }
        let op_index = self.seq.state().seq;
        self.seq
            .submit(Operation::Settle(Box::new(record.clone())), 2_000)
            .unwrap();
        // M9 per-table 指标：结算计数 + TPH 窗口
        let now_ms = unix_ms();
        self.metrics.record_table_settlement(table, now_ms);
        self.metrics.add_table_counter(table, "table_ops_total", 1);
        ProofTask {
            op_index,
            table_id: table,
            record,
        }
    }
}

/// 证明任务入队（定量模式：满即 panic——既有语义；长压测：退避重试，
/// 不丢手、不虚报吞吐）。返回 (背压等待毫秒, 峰值队列深)。
fn submit_proof(
    pipeline: &ProofPipeline,
    task: ProofTask,
    backpressure: bool,
    backpressure_ms: u64,
    backlog_peak: u64,
) -> (u64, u64) {
    loop {
        let depth = pipeline.health().proof_queue_depth;
        let peak = depth.max(backlog_peak);
        match pipeline.submit(ProofJob {
            op_index: task.op_index,
            table_id: task.table_id,
            record: Arc::new(task.record.clone()),
            policy: FeePolicy::Zero,
            priority: Priority::Play,
        }) {
            Ok(()) => return (backpressure_ms, peak),
            Err(_) if backpressure => {
                // 队列满：退避重试（真实浸没语义——不丢手、不虚报吞吐）
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => panic!("pipeline submit rejected: {e}"),
        }
    }
}

/// 采样行（TPH 曲线一点）。
fn sample_json(
    elapsed_s: u64,
    hands: u64,
    tph: f64,
    pipeline: &ProofPipeline,
    metrics: &MetricsRegistry,
) -> serde_json::Value {
    serde_json::json!({
        "elapsed_s": elapsed_s,
        "hands": hands,
        "tph": (tph * 100.0).round() / 100.0,
        "queue_depth": pipeline.health().proof_queue_depth,
        "completed": pipeline.completed_count(),
        "soft_confirm_p99_us": metrics.hist_summary("buyin_submit_us").map(|s| s.p99),
        "proof_ready_p95_ms": metrics.hist_summary("proof_ready_ms").map(|s| s.p95),
    })
}

fn write_out(out_path: &Option<String>, text: &str) {
    if let Some(p) = out_path {
        let _ = std::fs::write(p, text);
        eprintln!("report-written path={p}");
    }
}

fn main() {
    let tables = parse_arg("--tables", 64);
    let hands_per_table = parse_arg("--hands", 50);
    let players = parse_arg("--players", 2).clamp(2, 9);
    let duration_secs = parse_arg("--duration-secs", 0);
    let hand_interval_ms = parse_arg("--hand-interval-ms", 0);
    let out_path = str_arg("--out");

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
    let pipeline = Arc::new(ProofPipeline::new(
        PipelineConfig {
            workers: 4,
            queue_bound: 8_192,
            high_watermark: 6_000,
            batch_size: 64,
            batch_interval_ms: 5_000,
        },
        Arc::new(ValidationEngine::default()),
        Arc::clone(&metrics),
    ));

    let robots: Vec<Robot> = (1..=players as u8).map(Robot::new).collect();
    let t0 = Instant::now();

    if duration_secs > 0 {
        run_duration_mode(
            seq,
            &pipeline,
            &metrics,
            &robots,
            tables,
            duration_secs,
            hand_interval_ms,
            t0,
            out_path,
        );
        return;
    }

    // ===== 定量模式（既有基线口径：tables × hands）=====
    let mut lat_us: Vec<u64> = Vec::new();
    let mut settle_count = 0u64;
    let mut binding: u64 = 0;
    let mut backlog_peak = 0u64;

    for table in 1..=tables as u64 {
        seq.submit(
            Operation::OpenTable {
                table_id: table,
                policy: FeePolicy::Zero,
            },
            1_100,
        )
        .unwrap();

        for _hand in 0..hands_per_table {
            let mut driver = HandDriver {
                seq: &mut seq,
                metrics: &metrics,
                robots: &robots,
                binding,
                lat_us: Vec::new(),
            };
            let task = driver.prepare_hand(table);
            binding = driver.binding;
            lat_us.append(&mut driver.lat_us);
            drop(driver);
            let (_bp, peak) = submit_proof(&pipeline, task, false, 0, backlog_peak);
            backlog_peak = peak;
            settle_count += 1;
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

    // P0-5 接线（与生产装配点同构）：批次构建 + 验证通过回调 → sequencer
    // 证明水位真实推进（不再直接跳水位）。注：本压测为内存模式（无 WAL），
    // 不受 fsync 开关影响；若挂 WAL 复测可用 WalWriter::with_fsync(false)。
    let seq = Arc::new(Mutex::new(seq));
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    let mut batches_built = 0u64;
    while pipeline.try_build_batch().unwrap().is_some() {
        batches_built += 1;
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
        "mode": "fixed",
        "tables": tables,
        "hands_per_table": hands_per_table,
        "players": players,
        "settlements": settle_count,
        "proof_completed": pipeline.completed_count(),
        "batches_built": batches_built,
        "backlog_peak": backlog_peak,
        "proven_watermark": seq.lock().unwrap().proven_watermark(),
        "buyin_soft_confirm_us": { "p50": pct(0.5), "p99": pct(0.99), "max": lat_us.last().copied().unwrap_or(0) },
        // M9-ACC-4 四延迟报告：soft_confirm/proof_ready 实测分位；
        // bft_finality/claimable 未上线，恒为 null（见 MetricsRegistry::latency_report）
        "latency_report": metrics.latency_report(),
        "wall_clock_s": total_elapsed.as_secs_f64(),
        "ops_total": seq.lock().unwrap().state().seq,
        "alert_count": evaluate_alerts(&pipeline.health()).len(),
        "engine": poker_appchain::pipeline::SettlementProver::name(&ValidationEngine::default()),
    });
    let text = serde_json::to_string_pretty(&report).expect("report json");
    println!("{text}");
    write_out(&out_path, &text);
}

/// 长压测模式（M9-ACC-1 完整口径）：桌循环开新手至时限。
#[allow(clippy::too_many_arguments)]
fn run_duration_mode(
    seq: Sequencer,
    pipeline: &Arc<ProofPipeline>,
    metrics: &Arc<MetricsRegistry>,
    robots: &[Robot],
    tables: usize,
    duration_secs: usize,
    hand_interval_ms: usize,
    t0: Instant,
    out_path: Option<String>,
) {
    let deadline = t0 + Duration::from_secs(duration_secs as u64);
    // P0-5 接线（与生产装配点同构）：批次构建 + 验证通过回调 → 水位真实
    // 推进（先入 Arc<Mutex> 再挂回调）。
    let seq = Arc::new(Mutex::new(seq));
    // 开桌（每桌一次；策略开桌即冻结）
    {
        let mut guard = seq.lock().unwrap();
        for table in 1..=tables as u64 {
            guard
                .submit(
                    Operation::OpenTable {
                        table_id: table,
                        policy: FeePolicy::Zero,
                    },
                    1_100,
                )
                .unwrap();
        }
    }
    pipeline.set_on_batch_proven({
        let seq = Arc::clone(&seq);
        Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
    });
    // 组批驱动线程：周期 try_build_batch（批量 64），避免浸没尾部大排空
    let stop_batcher = Arc::new(AtomicBool::new(false));
    let batches_built_bg = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let batcher_pipeline = Arc::clone(pipeline);
    let batcher_stop = Arc::clone(&stop_batcher);
    let batcher_batches = Arc::clone(&batches_built_bg);
    std::thread::Builder::new()
        .name("soak-batcher".into())
        .spawn(move || {
            while !batcher_stop.load(Ordering::Relaxed) {
                loop {
                    match batcher_pipeline.try_build_batch() {
                        Ok(Some(_)) => {
                            batcher_batches.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })
        .expect("spawn soak batcher");

    let mut binding: u64 = 0;
    let mut backpressure_ms = 0u64;
    let mut backlog_peak = 0u64;
    let mut hands: u64 = 0;
    let mut lat_us: Vec<u64> = Vec::new();
    let mut samples: Vec<serde_json::Value> = Vec::new();
    let mut alert_events = 0u64;
    let mut rules_seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut last_sample = Instant::now();
    let mut last_sample_hands = 0u64;
    let mut last_progress = Instant::now();
    let mut next_hand_at = Instant::now();

    // 主循环：全局按手序轮转桌（hands % tables）；节流、采样、进度行。
    let mut cycle: usize = 0;
    'outer: loop {
        if Instant::now() >= deadline {
            break 'outer;
        }
        let table = (cycle % tables) as u64 + 1;
        cycle += 1;
        let task = {
            let mut guard = seq.lock().unwrap();
            let mut driver = HandDriver {
                seq: &mut guard,
                metrics,
                robots,
                binding,
                lat_us: Vec::new(),
            };
            let task = driver.prepare_hand(table);
            binding = driver.binding;
            lat_us.append(&mut driver.lat_us);
            task
        }; // seq 锁已释放——pipeline 的批次回调会回锁 sequencer
        let (bp, peak) = submit_proof(pipeline, task, true, backpressure_ms, backlog_peak);
        backpressure_ms = bp;
        backlog_peak = peak;
        hands += 1;

        // 手动节流（模拟真实桌速；0 = 不限速）
        if hand_interval_ms > 0 {
            let now = Instant::now();
            if next_hand_at > now {
                std::thread::sleep(next_hand_at - now);
            } else {
                next_hand_at = now;
            }
            next_hand_at += Duration::from_millis(hand_interval_ms as u64);
        }

        // 采样（每 30s）：TPH 曲线 + 队列深 + 告警 + 分位
        if last_sample.elapsed() >= Duration::from_secs(30) {
            let window_hours = last_sample.elapsed().as_secs_f64() / 3600.0;
            let tph = (hands - last_sample_hands) as f64 / window_hours.max(1.0 / 3600.0);
            let alerts = evaluate_alerts(&pipeline.health());
            alert_events += alerts.len() as u64;
            for a in &alerts {
                rules_seen.insert(a.rule.to_owned());
            }
            samples.push(sample_json(
                t0.elapsed().as_secs(),
                hands,
                tph,
                pipeline,
                metrics,
            ));
            last_sample = Instant::now();
            last_sample_hands = hands;
        }
        // 进度行（每 30s；stderr——中断时可取部分数据，不虚报）
        if last_progress.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "soak-progress elapsed_s={} hands={} tph_avg={:.0} queue_depth={} completed={} backlog_peak={}",
                t0.elapsed().as_secs(),
                hands,
                hands as f64 / (t0.elapsed().as_secs_f64() / 3600.0).max(1.0 / 3600.0),
                pipeline.health().proof_queue_depth,
                pipeline.completed_count(),
                backlog_peak,
            );
            last_progress = Instant::now();
        }
    }

    // 收尾：停组批线程 → 排空组批 → 等待证明完成（上限 300s）
    stop_batcher.store(true, Ordering::Relaxed);
    let mut batches_built = batches_built_bg.load(Ordering::Relaxed);
    while pipeline.try_build_batch().unwrap().is_some() {
        batches_built += 1;
    }
    let prove_start = Instant::now();
    loop {
        if pipeline.completed_count() >= hands {
            break;
        }
        if prove_start.elapsed() > Duration::from_secs(300) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // 最终告警采样 + 报告
    {
        let alerts = evaluate_alerts(&pipeline.health());
        alert_events += alerts.len() as u64;
        for a in &alerts {
            rules_seen.insert(a.rule.to_owned());
        }
        samples.push(sample_json(
            t0.elapsed().as_secs(),
            hands,
            0.0,
            pipeline,
            metrics,
        ));
    }
    lat_us.sort_unstable();
    let pct = |q: f64| -> u64 {
        lat_us
            .get(((lat_us.len() as f64 - 1.0) * q).round() as usize)
            .copied()
            .unwrap_or(0)
    };
    let elapsed_hours = t0.elapsed().as_secs_f64() / 3600.0;
    let avg_tph = hands as f64 / elapsed_hours.max(1.0 / 3600.0);
    let report = serde_json::json!({
        "mode": "duration",
        "tables": tables,
        "players": robots.len(),
        "duration_secs": duration_secs,
        "hand_interval_ms": hand_interval_ms,
        "hands_total": hands,
        "settlements": hands,
        "tph_unit": "hands_per_hour",
        "tph_avg": (avg_tph * 100.0).round() / 100.0,
        "tph_samples": samples,
        "buyin_soft_confirm_us": { "p50": pct(0.5), "p99": pct(0.99), "max": lat_us.last().copied().unwrap_or(0) },
        // M9-ACC-4 四延迟报告 + 每桌 TPH（M9 per-table）
        "latency_report": metrics.latency_report_at(unix_ms()),
        "proof": {
            "completed": pipeline.completed_count(),
            "batches_built": batches_built,
            "backlog_peak": backlog_peak,
            "backpressure_wait_ms": backpressure_ms,
            "proven_watermark": seq.lock().unwrap().proven_watermark(),
        },
        "alert_events": alert_events,
        "alert_rules_seen": rules_seen.iter().cloned().collect::<Vec<_>>(),
        "alert_count": alert_events,
        "wall_clock_s": t0.elapsed().as_secs_f64(),
        "ops_total": seq.lock().unwrap().state().seq,
        "engine": poker_appchain::pipeline::SettlementProver::name(&ValidationEngine::default()),
        "note": "duration 模式：proof_ready 为 host-validate 机制基准（见 bin 头注释）",
    });
    let text = serde_json::to_string_pretty(&report).expect("report json");
    println!("{text}");
    write_out(&out_path, &text);
}
