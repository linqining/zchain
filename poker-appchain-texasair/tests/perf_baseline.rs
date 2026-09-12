//! 性能基准落档数据源（M4-ACC-1/2 + B3/M0-ACC-1）。
//!
//! 全部测试标 `#[ignore]`（真实 stwo 出证，不拖慢默认套件），显式触发：
//!
//! ```text
//! cargo test --release --test perf_baseline -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` 保证计时干净（三个基准共用进程 CPU/rayon 全局池，
//! 并行跑会互相污染样本）；基准内部也用 `BENCH_LOCK` 互斥，即使忘加
//! `--test-threads=1` 也不会交叉计时。
//!
//! 三个基准（对应 `docs/plan-appchain-perf.md` 三张表）：
//! 1. `m4_acc_1_hand_end_to_verifiable_ready`——手结束 → 证明可验证就绪
//!    延迟：witness 集就绪 → `prove_canonical_tagged_batch` +
//!    `verify_canonical_tagged_proof` 完成的墙钟，N=20 重复（证明确定
//!    性：全部归档 `batch_digest` 一致断言），报告 p50/p95/p99 并对照
//!    3s 回归门槛（plan §M4-ACC-1）。
//! 2. `m4_acc_2_concurrent_table_throughput`——吞吐线性：1/4/16/64 桌
//!    并发（每桌独立 witness 集与 prove 调用，线程池并发提交），测单位
//!    手平均成本曲线，门槛：增长 ≤ 线性 + 15%（plan §M4-ACC-2）。
//! 3. `m0_acc_1_street_split_vs_whole_hand`——逐街流式 vs 整手对比
//!    （B3/M0-ACC-1）：同一手 witness 序列按 k=1/2/5 切段独立 prove，
//!    断言归档承诺链（段 i 的 post == 段 i+1 的 pre），对比首证明就绪
//!    延迟 / 总 prove / 总 verify / 证明字节总量。
//!
//! 原始样本以 JSON 写入
//! `$TMPDIR/poker-appchain-texasair-perf-baseline.json`（每个基准结束
//! 时覆盖写全量快照），stdout 以 `PERF ` 前缀输出机器可读行，供
//! `docs/plan-appchain-perf.md` 落档引用。

use std::sync::{Arc, Barrier, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use poker_texas_air::canonical_rake_opening::{CanonicalBlindOpening, CanonicalRakeOpening};
use poker_texas_air::texas_canonical::{
    CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

// ===== 场景常量（与 tests/e2e_full_hand.rs 的 5-witness 一手同构） =====

/// 基准桌 ID 基值（各模式/桌位/轮次在基值上偏移，保证批次 scope 互异）。
const BASE_TABLE_ID: u64 = 4200;
/// 买入/手牌起始筹码。
const BUY_IN: u64 = 500;
/// BB 弃牌后的死钱。
const FOLDER_NOTE: u64 = 50;
/// gross pot == Σ seat note == 终态镜像 pot。
const GROSS_POT: u64 = BUY_IN * 2 + FOLDER_NOTE;

// ===== 门槛（写死进回归；判定随原始数据一并落档） =====

/// M4-ACC-1 主门槛：手结束 → 证明可验证就绪 ≤ 3s p95（plan §M4）。
const M4_ACC_1_GATE_P95_MS: f64 = 3_000.0;
/// M4-ACC-1 退路门槛（plan §4 风险 #1：整手退路放宽至 ≤ 30s）。
const M4_ACC_1_FALLBACK_P95_MS: f64 = 30_000.0;
/// M4-ACC-2 门槛：单位手成本增长 ≤ 线性 + 15%。
const M4_ACC_2_LINEAR_SLACK: f64 = 1.15;
/// M4-ACC-1 样本数（证明确定性 → 重复测的纯是时间分布）。
const LATENCY_SAMPLES: usize = 20;
/// M4-ACC-2 并发桌数档位。
const CONC_LEVELS: [usize; 4] = [1, 4, 16, 64];
/// M4-ACC-2 每档重复轮数（每轮 T 桌并发各证一手）。
const CONC_ROUNDS: usize = 3;
/// B3 对比每模式重复次数。
const B3_REPS: usize = 10;

/// 基准互斥锁（跨测试串行化，防止 harness 并行执行交叉计时）。
static BENCH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
/// 原始样本 JSON 汇总（顶层键片段累积，测试结束时快照写临时文件）。
static RESULTS: OnceLock<Mutex<String>> = OnceLock::new();

fn results() -> &'static Mutex<String> {
    RESULTS.get_or_init(|| {
        Mutex::new(String::from(
            "{\n\"meta\":{\"crate\":\"poker-appchain-texasair\",\
             \"bench\":\"perf_baseline\",\"date\":\"2026-09-12\"},",
        ))
    })
}

/// 基准互斥锁获取（容忍前序基准 panic 造成的毒化：计时互斥不承载
/// 不变量，直接复用底层 guard 即可）。
fn bench_lock() -> std::sync::MutexGuard<'static, ()> {
    BENCH_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// 追加一段完整的顶层 JSON 键片段（`"key":{...},`）。
fn record_json(fragment: &str) {
    let mutex = results();
    let mut out = mutex.lock().unwrap_or_else(PoisonError::into_inner);
    out.push_str(fragment);
}

/// 非破坏性快照：修剪尾逗号 + 收口花括号。每个基准结束时覆盖写临时
/// 文件——无论测试执行顺序如何，最后写的快照总是全量。
fn snapshot_json() -> String {
    let mutex = results();
    let mut json = mutex.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if json.ends_with(',') {
        json.pop();
    }
    json.push('}');
    json
}

fn write_snapshot() {
    let path = std::env::temp_dir().join("poker-appchain-texasair-perf-baseline.json");
    std::fs::write(&path, snapshot_json()).expect("write perf baseline json");
    println!("PERF results_json path={}", path.display());
}

/// 机器可读输出行（`PERF ` 前缀，--nocapture 下可 grep）。
fn perf_line(line: &str) {
    println!("PERF {line}");
}

/// 最近秩分位数（样本需已升序排序）：p50/p95/p99。
/// 小样本（n=20）下 p99 退化为最大值，落档时如实标注。
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let n = sorted.len();
    assert!(!sorted.is_empty(), "percentile of empty samples");
    let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
    sorted[rank - 1]
}

/// 就地排序并返回 (p50, p95, p99)。
fn stats(samples: &mut [f64]) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.total_cmp(b));
    (
        percentile(samples, 0.50),
        percentile(samples, 0.95),
        percentile(samples, 0.99),
    )
}

// ===== canonical witness 构造（镜像 tests/e2e_full_hand.rs 已证模式） =====

fn active_seat(stack: u64, bet: u64, total_bet: u64, index: usize) -> CanonicalSeat {
    CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted: false,
        stack,
        bet,
        total_bet,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [70 + index as u8; 32],
        key_commitment: [80 + index as u8; 32],
        hole_cards_commitment: [90 + index as u8; 32],
    }
}

/// hand-start 镜像：preflop 下注街，盲注已发布（SB 座1=25、BB 座2=50），
/// UTG（按钮座0）行动。custody 恒等式：pot 0 + Σ(stack+bet) == chip_pool。
fn hand_start_image(table_id: u64) -> CanonicalStateImage {
    let mut image = CanonicalStateImage {
        abi_version: CANONICAL_ABI_VERSION,
        table_id,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Betting,
        phase_subtag: 1,
        street: 1,
        current_turn: 0,
        deadline_ms: 42_500,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 3_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 50,
        min_raise: 50,
        chip_pool: BUY_IN * 3,
        pot: 0,
        button: 0,
        max_players: 3,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [1; 32],
        deck_commitment: [2; 32],
        reveal_commitment: [3; 32],
        reconstruction_commitment: [4; 32],
        run_it_twice_commitment: [5; 32],
        rules_commitment: [6; 32],
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
    };
    image.seats[0] = active_seat(BUY_IN, 0, 0, 0); // 按钮/UTG
    image.seats[1] = active_seat(BUY_IN - 25, 25, 25, 1); // SB
    image.seats[2] = active_seat(BUY_IN - 50, 50, 50, 2); // BB
    image
}

/// 完整一手牌 witness 序列（单 batch，5 行）：加注 → 全下 → 弃牌 → 全下
/// 跟注 → 收池。构造即自检（host 侧 `validate_shape`），与
/// `tests/e2e_full_hand.rs::full_hand_witnesses` 逐行同构。
fn full_hand_witnesses(table_id: u64) -> Vec<CanonicalTransitionWitness> {
    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut CanonicalStateImage)| {
        let pre = rows
            .last()
            .map(|r| r.post.clone())
            .unwrap_or_else(|| hand_start_image(table_id));
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: CanonicalRakeOpening::ZERO,
            blind_opening: CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
            .validate_shape()
            .unwrap_or_else(|e| panic!("witness {seq} ({kind:?}) shape invalid: {e}"));
        rows.push(witness);
    };

    // R1：UTG 加注到 200（increment 150 ≥ min_raise 50 → 重开行动）。
    step(
        CanonicalTransitionKind::Raise,
        [70; 32],
        0,
        200,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 1;
            post.current_bet = 200;
            post.min_raise = 150;
            post.acted_mask = 0b001;
            post.seats[0].acted = true;
            post.seats[0].stack = BUY_IN - 200;
            post.seats[0].bet = 200;
            post.seats[0].total_bet = 200;
        },
    );

    // R2：SB 全下 500（increment 300 ≥ min_raise 150 → 再次重开）。
    step(
        CanonicalTransitionKind::Raise,
        [71; 32],
        1,
        500,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 2;
            post.current_bet = 500;
            post.min_raise = 300;
            post.acted_mask = 0b010;
            post.seats[1].acted = true;
            post.seats[1].status = CanonicalSeatStatus::AllIn;
            post.seats[1].stack = 0;
            post.seats[1].bet = 500;
            post.seats[1].total_bet = 500;
            post.seats[0].acted = false;
        },
    );

    // R3：BB 弃牌——盲注 50 成死钱（fold 保留 bet/stack，由收池行入池）。
    step(
        CanonicalTransitionKind::Fold,
        [72; 32],
        2,
        0,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 0;
            post.acted_mask = 0b110;
            post.seats[2].status = CanonicalSeatStatus::Folded;
            post.seats[2].acted = true;
        },
    );

    // R4：UTG 全下跟注 300（两家等额全下，无 uncalled 返还层）。
    step(
        CanonicalTransitionKind::Call,
        [70; 32],
        0,
        300,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = NO_CANONICAL_SEAT;
            post.acted_mask = 0b111;
            post.seats[0].acted = true;
            post.seats[0].status = CanonicalSeatStatus::AllIn;
            post.seats[0].stack = 0;
            post.seats[0].bet = 500;
            post.seats[0].total_bet = 500;
        },
    );

    // R5：AdvanceRound 微步——全部下注收池（pot 0 → 1050），翻牌 reveal
    // 开局（street 1→2、subtag 2、3 张 flop 指派）。
    let advance_pre = rows.last().expect("pre-advance row").post.clone();
    let mut advance_post = advance_pre.clone();
    advance_post.call_seq = 5;
    advance_post.phase = CanonicalPhase::Revealing;
    advance_post.phase_subtag = 2;
    advance_post.street = 2;
    advance_post.deadline_ms = 45_000;
    advance_post.current_turn = NO_CANONICAL_SEAT;
    advance_post.current_bet = 0;
    advance_post.min_raise = 0;
    advance_post.pot = GROSS_POT;
    advance_post.protocol_pending_mask = 0b111;
    for seat in &mut advance_post.seats {
        seat.bet = 0;
    }
    let mut advance = CanonicalTransitionWitness {
        pre: advance_pre,
        post: advance_post,
        kind: CanonicalTransitionKind::AdvanceRound,
        actor: [0; 32],
        action: CanonicalActionPayload {
            seat: NO_CANONICAL_SEAT,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening {
            pre_cards_dealt: 6,  // 3 名参与者 × 2 张底牌
            post_cards_dealt: 9, // + 3 张翻牌
            pre_board_len: 0,
            post_board_len: 0, // reveal token 兑现前牌面长度不变
            pre_second_board_len: 0,
            post_second_board_len: 0,
            run_it_twice: false,
            reveal_purpose: 2,
            assignment_count: 3,
            assignments: {
                let mut slots =
                    [CanonicalBoardRevealAssignment::EMPTY; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS];
                for (position, slot) in slots.iter_mut().take(3).enumerate() {
                    *slot = CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 6 + position as u8,
                        runout_index: 0,
                        board_position: position as u8,
                        pending_mask: 0b111,
                        submitted_mask: 0,
                    };
                }
                slots
            },
        },
        protocol_completion: Default::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening: CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    advance.seal();
    advance.validate_shape().expect("advance opening shape");
    rows.push(advance);
    rows
}

/// 按 `groups` 给出的每段行数切块（总行数必须恰好划分完毕）。
fn split_witnesses(
    rows: &[CanonicalTransitionWitness],
    groups: &[usize],
) -> Vec<Vec<CanonicalTransitionWitness>> {
    assert_eq!(groups.iter().sum::<usize>(), rows.len(), "split covers all");
    let mut cursor = 0;
    groups
        .iter()
        .map(|g| {
            let seg = rows[cursor..cursor + *g].to_vec();
            cursor += *g;
            seg
        })
        .collect()
}

/// 单批出证并计时（秒）。
fn prove_batch(witnesses: &[CanonicalTransitionWitness]) -> (f64, ArchivedCanonicalTaggedProof) {
    let started = Instant::now();
    let archive = prove_canonical_tagged_batch(witnesses).expect("canonical batch proof");
    (started.elapsed().as_secs_f64(), archive)
}

/// 独立验证器复核并计时（秒）。
fn verify_batch(archive: &ArchivedCanonicalTaggedProof) -> f64 {
    let started = Instant::now();
    verify_canonical_tagged_proof(archive).expect("canonical batch verify");
    started.elapsed().as_secs_f64()
}

/// 归档 borsh 信封字节数（证明字节总量的口径）。
fn archive_bytes(archive: &ArchivedCanonicalTaggedProof) -> usize {
    borsh::to_vec(archive).expect("archive encoding").len()
}

/// 归档承诺链连续性断言：段 i 的 post == 段 i+1 的 pre（承诺 + 状态根）。
fn assert_chained(segments: &[ArchivedCanonicalTaggedProof]) {
    for window in segments.windows(2) {
        assert_eq!(
            window[0].post_state_commitment, window[1].pre_state_commitment,
            "segment chain broken at state commitment"
        );
        assert_eq!(
            window[0].post_state_root, window[1].pre_state_root,
            "segment chain broken at state root"
        );
    }
}

/// 预热：进程级 twiddle 树与列池初始化（prover_context 局部缓存）不计入
/// 稳态样本；冷启动单点由调用方单独记录。
fn warmup() -> f64 {
    let witnesses = full_hand_witnesses(BASE_TABLE_ID);
    let started = Instant::now();
    let (prove_s, archive) = prove_batch(&witnesses);
    verify_batch(&archive);
    let cold_total = started.elapsed().as_secs_f64() * 1e3;
    println!(
        "PERF warmup cold_prove_ms={:.1} cold_total_ms={cold_total:.1}",
        prove_s * 1e3
    );
    prove_s * 1e3
}

// =====================================================================
// M4-ACC-1：手结束 → 证明可验证就绪延迟（≤ 3s p95 回归门槛）
// =====================================================================

#[ignore = "slow prove bench: cargo test --release --test perf_baseline -- --ignored --nocapture --test-threads=1"]
#[test]
fn m4_acc_1_hand_end_to_verifiable_ready() {
    let _guard = bench_lock();
    let cold_prove_ms = warmup();

    // witness 集就绪（度量起点之前的构造不计时，对应"手结束即有完整
    // witness 序列"的 M4 语义；构造本身是微秒级内存操作）。
    let witnesses = full_hand_witnesses(BASE_TABLE_ID);
    assert_eq!(witnesses.len(), 5);

    let mut prove_ms: Vec<f64> = Vec::with_capacity(LATENCY_SAMPLES);
    let mut verify_ms: Vec<f64> = Vec::with_capacity(LATENCY_SAMPLES);
    let mut ready_ms: Vec<f64> = Vec::with_capacity(LATENCY_SAMPLES);
    let mut digests: Vec<[u8; 32]> = Vec::with_capacity(LATENCY_SAMPLES);
    for i in 0..LATENCY_SAMPLES {
        // 度量：witness 集就绪 → prove + verify 完成的墙钟。
        let started = Instant::now();
        let archive = prove_canonical_tagged_batch(&witnesses).expect("canonical batch proof");
        let prove_done = started.elapsed().as_secs_f64();
        verify_canonical_tagged_proof(&archive).expect("canonical batch verify");
        let ready = started.elapsed().as_secs_f64();
        prove_ms.push(prove_done * 1e3);
        verify_ms.push((ready - prove_done) * 1e3);
        ready_ms.push(ready * 1e3);
        digests.push(archive.batch_digest);
        perf_line(&format!(
            "m4_acc_1 sample i={i} prove_ms={:.1} verify_ms={:.1} ready_ms={:.1} bytes={}",
            prove_done * 1e3,
            (ready - prove_done) * 1e3,
            ready * 1e3,
            archive_bytes(&archive)
        ));
    }

    // 证明确定性：同一 witness 集 20 次出证的批次摘要必须逐字节一致
    // （Fiat–Shamir 无随机源；重复测的纯是时间分布）。
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "prove must be deterministic across repetitions"
    );

    let (p50, p95, p99) = stats(&mut ready_ms);
    let (vp50, vp95, vp99) = stats(&mut verify_ms);
    let (pp50, pp95, pp99) = stats(&mut prove_ms);
    let pass = p95 <= M4_ACC_1_GATE_P95_MS;
    perf_line(&format!(
        "m4_acc_1 stats prove_p50_ms={pp50:.1} prove_p95_ms={pp95:.1} prove_p99_ms={pp99:.1} \
         verify_p50_ms={vp50:.1} verify_p95_ms={vp95:.1} verify_p99_ms={vp99:.1} \
         ready_p50_ms={p50:.1} ready_p95_ms={p95:.1} ready_p99_ms={p99:.1} \
         gate_p95_ms={M4_ACC_1_GATE_P95_MS} verdict={}",
        if pass { "PASS" } else { "FAIL" }
    ));

    // 回归门槛写死：3s p95（退路 30s 双保险断言，plan §4 风险 #1）。
    assert!(
        p95 <= M4_ACC_1_GATE_P95_MS,
        "M4-ACC-1 regression gate: verifiable-ready p95 {p95:.1}ms exceeds 3s gate"
    );
    assert!(
        p95 <= M4_ACC_1_FALLBACK_P95_MS,
        "M4-ACC-1 fallback ceiling: verifiable-ready p95 {p95:.1}ms exceeds 30s"
    );

    record_json(&format!(
        "\"m4_acc_1\":{{\"samples\":{LATENCY_SAMPLES},\"cold_prove_ms\":{cold_prove_ms:.1},\
         \"prove_p50_ms\":{pp50:.1},\"prove_p95_ms\":{pp95:.1},\"prove_p99_ms\":{pp99:.1},\
         \"verify_p50_ms\":{vp50:.1},\"verify_p95_ms\":{vp95:.1},\"verify_p99_ms\":{vp99:.1},\
         \"ready_p50_ms\":{p50:.1},\"ready_p95_ms\":{p95:.1},\"ready_p99_ms\":{p99:.1},\
         \"gate_p95_ms\":{M4_ACC_1_GATE_P95_MS},\"verdict\":\"{}\"}},",
        if pass { "PASS" } else { "FAIL" }
    ));
    write_snapshot();
}

// =====================================================================
// M4-ACC-2：吞吐线性——1/4/16/64 桌并发单位手成本增长 ≤ 线性 + 15%
// =====================================================================

#[ignore = "slow prove bench: cargo test --release --test perf_baseline -- --ignored --nocapture --test-threads=1"]
#[test]
fn m4_acc_2_concurrent_table_throughput() {
    let _guard = bench_lock();
    warmup();

    let mut per_hand_level_p50: Vec<f64> = Vec::with_capacity(CONC_LEVELS.len());
    let mut json_levels = String::new();

    for (li, &tables) in CONC_LEVELS.iter().enumerate() {
        let mut round_per_hand_ms: Vec<f64> = Vec::with_capacity(CONC_ROUNDS);
        let mut round_wall_ms: Vec<f64> = Vec::with_capacity(CONC_ROUNDS);

        for round in 0..CONC_ROUNDS {
            // 每桌独立 witness 集（独立 table_id，批次 scope 互异）；
            // 构造在计时墙钟之外（度量对象是证明成本，非内存拷贝）。
            let sets: Vec<Vec<CanonicalTransitionWitness>> = (0..tables)
                .map(|t| full_hand_witnesses(BASE_TABLE_ID + 1000 + t as u64 + round as u64 * 7))
                .collect();
            let barrier = Arc::new(Barrier::new(tables));
            let started = Instant::now();
            let thread_stats: Vec<f64> = std::thread::scope(|scope| {
                let handles: Vec<_> = sets
                    .into_iter()
                    .map(|witnesses| {
                        let barrier = Arc::clone(&barrier);
                        scope.spawn(move || {
                            barrier.wait(); // 对齐起跑，避免构造抖动计入并发窗
                            let (prove_s, archive) = prove_batch(&witnesses);
                            verify_batch(&archive);
                            prove_s * 1e3
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("prover thread"))
                    .collect()
            });
            let wall_ms = started.elapsed().as_secs_f64() * 1e3;
            let mut per_thread = thread_stats;
            let (med, _, max) = stats(&mut per_thread);
            round_wall_ms.push(wall_ms);
            round_per_hand_ms.push(wall_ms / tables as f64);
            perf_line(&format!(
                "m4_acc_2 level_tables={tables} round={round} wall_ms={wall_ms:.1} \
                 per_hand_ms={:.1} thread_prove_median_ms={med:.1} thread_prove_max_ms={max:.1}",
                wall_ms / tables as f64
            ));
        }

        let (ph50, ph95, ph99) = stats(&mut round_per_hand_ms);
        let (w50, _, _) = stats(&mut round_wall_ms);
        // 增长倍数与并行效率（相对 1 档基准；1 档自身 growth = 1.0）。
        let base = if li == 0 { ph50 } else { per_hand_level_p50[0] };
        let growth = ph50 / base;
        let speedup = base * tables as f64 / w50;
        let efficiency = speedup / tables as f64;
        perf_line(&format!(
            "m4_acc_2 level_tables={tables} per_hand_p50_ms={ph50:.1} per_hand_p95_ms={ph95:.1} \
             per_hand_p99_ms={ph99:.1} growth_vs_1x={growth:.2} speedup={speedup:.2} \
             efficiency={efficiency:.2} samples={CONC_ROUNDS}"
        ));
        assert!(
            growth <= M4_ACC_2_LINEAR_SLACK * tables as f64,
            "M4-ACC-2 regression gate: per-hand cost growth {growth:.2}x exceeds linear+15% \
             ({:.2}x) at {tables} concurrent tables",
            M4_ACC_2_LINEAR_SLACK * tables as f64
        );
        per_hand_level_p50.push(ph50);
        json_levels.push_str(&format!(
            "{{\"tables\":{tables},\"rounds\":{CONC_ROUNDS},\
              \"per_hand_p50_ms\":{ph50:.1},\"per_hand_p95_ms\":{ph95:.1},\
              \"per_hand_p99_ms\":{ph99:.1},\"growth_vs_1x\":{growth:.2},\
              \"speedup\":{speedup:.2},\"efficiency\":{efficiency:.2}}},"
        ));
    }

    if json_levels.ends_with(',') {
        json_levels.pop();
    }
    record_json(&format!("\"m4_acc_2\":{{\"levels\":[{json_levels}]}},"));
    write_snapshot();
}

// =====================================================================
// B3 / M0-ACC-1：逐街流式 vs 整手对比
// =====================================================================

/// 一个切分模式一轮的样本：各段 prove/verify 耗时 + 字节量。
struct SplitSample {
    /// 每段 prove 耗时（ms，顺序执行）。
    segment_prove_ms: Vec<f64>,
    /// 每段 verify 耗时（ms，按序）。
    segment_verify_ms: Vec<f64>,
    /// 每段归档 borsh 字节数。
    segment_bytes: Vec<usize>,
}

/// 顺序证完 + 按序验完一个切分模式的一轮，断言承诺链连续。
fn run_split_round(segments: &[Vec<CanonicalTransitionWitness>]) -> SplitSample {
    let mut archives: Vec<ArchivedCanonicalTaggedProof> = Vec::with_capacity(segments.len());
    let mut prove_ms = Vec::with_capacity(segments.len());
    for seg in segments {
        let (secs, archive) = prove_batch(seg);
        prove_ms.push(secs * 1e3);
        archives.push(archive);
    }
    let mut verify_ms = Vec::with_capacity(archives.len());
    let mut bytes = Vec::with_capacity(archives.len());
    for archive in &archives {
        verify_ms.push(verify_batch(archive) * 1e3);
        bytes.push(archive_bytes(archive));
    }
    // 链式衔接断言：段 i 的 post == 段 i+1 的 pre（承诺 + 状态根）。
    assert_chained(&archives);
    SplitSample {
        segment_prove_ms: prove_ms,
        segment_verify_ms: verify_ms,
        segment_bytes: bytes,
    }
}

fn sum(xs: &[f64]) -> f64 {
    xs.iter().sum()
}

#[allow(clippy::type_complexity)]
fn summarize_mode(name: &str, samples: &[SplitSample]) -> String {
    let first_ready: Vec<f64> = samples.iter().map(|s| s.segment_prove_ms[0]).collect();
    let total_prove: Vec<f64> = samples.iter().map(|s| sum(&s.segment_prove_ms)).collect();
    let total_verify: Vec<f64> = samples.iter().map(|s| sum(&s.segment_verify_ms)).collect();
    let total_bytes: Vec<usize> = samples
        .iter()
        .map(|s| s.segment_bytes.iter().sum())
        .collect();
    let seg_prove: Vec<f64> = samples
        .iter()
        .flat_map(|s| s.segment_prove_ms.iter().copied())
        .collect();

    let mut first = first_ready;
    let mut tprove = total_prove;
    let mut tverify = total_verify;
    let mut seg_all = seg_prove;
    let (f50, _, _) = stats(&mut first);
    let (p50, p95, p99) = stats(&mut tprove);
    let (v50, v95, v99) = stats(&mut tverify);
    let (seg_p50, _, _) = stats(&mut seg_all);
    let bytes_p50 = {
        let mut b: Vec<f64> = total_bytes.iter().map(|x| *x as f64).collect();
        stats(&mut b).0
    };
    perf_line(&format!(
        "m0_acc_1 mode={name} reps={B3_REPS} first_ready_p50_ms={f50:.1} \
         total_prove_p50_ms={p50:.1} total_prove_p95_ms={p95:.1} total_prove_p99_ms={p99:.1} \
         total_verify_p50_ms={v50:.1} total_verify_p95_ms={v95:.1} total_verify_p99_ms={v99:.1} \
         bytes_p50={bytes_p50} segment_prove_p50_ms={seg_p50:.1}"
    ));
    format!(
        "{{\"mode\":\"{name}\",\"reps\":{B3_REPS},\"first_ready_p50_ms\":{f50:.1},\
         \"total_prove_p50_ms\":{p50:.1},\"total_prove_p95_ms\":{p95:.1},\
         \"total_prove_p99_ms\":{p99:.1},\"total_verify_p50_ms\":{v50:.1},\
         \"total_verify_p95_ms\":{v95:.1},\"total_verify_p99_ms\":{v99:.1},\
         \"bytes_p50\":{bytes_p50},\"segment_prove_p50_ms\":{seg_p50:.1}}},"
    )
}

#[ignore = "slow prove bench: cargo test --release --test perf_baseline -- --ignored --nocapture --test-threads=1"]
#[test]
fn m0_acc_1_street_split_vs_whole_hand() {
    let _guard = bench_lock();
    warmup();

    // 一手完整 witness 序列（5 行：Raise/Raise/Fold/Call/AdvanceRound）。
    // 可切边界如实记录：本手在直接可证管道内只有 **1 个 street 边界**
    // （preflop 下注街 → AdvanceRound 收池进 street 2 reveal 开局）。
    // 更长的多街序列需要 SubmitReveal 完成行，而该行要求 rules-opening
    // 证明通道（`TableRules` 类型不经 poker_texas_air 公开导出，外部
    // 集成测试不可构造——见 tests/e2e_full_hand.rs 头注与 poker_texas_air
    // `canonical_full_hand_proof_perf_sweep` 的 TODO #22 续链缺口说明），
    // 因此逐街实验以该 1 个真实 street 边界为主切分（k=2），并补充
    // k=5 的"逐动作"细粒度切分暴露粒度-成本曲线。
    let rows = full_hand_witnesses(BASE_TABLE_ID + 2000);
    assert_eq!(rows.len(), 5);

    let mut whole_samples: Vec<SplitSample> = Vec::with_capacity(B3_REPS);
    let mut street_samples: Vec<SplitSample> = Vec::with_capacity(B3_REPS);
    let mut fine_samples: Vec<SplitSample> = Vec::with_capacity(B3_REPS);
    for rep in 0..B3_REPS {
        // 各模式独立桌 ID（批次 scope 互异，避免任何同 scope 复用嫌疑）。
        let whole = run_split_round(&split_witnesses(
            &full_hand_witnesses(BASE_TABLE_ID + 2000 + rep as u64 * 3),
            &[5],
        ));
        let street = run_split_round(&split_witnesses(
            &full_hand_witnesses(BASE_TABLE_ID + 3000 + rep as u64 * 3),
            &[4, 1],
        ));
        let fine = run_split_round(&split_witnesses(
            &full_hand_witnesses(BASE_TABLE_ID + 4000 + rep as u64 * 3),
            &[1, 1, 1, 1, 1],
        ));
        whole_samples.push(whole);
        street_samples.push(street);
        fine_samples.push(fine);
    }

    let whole_json = summarize_mode("whole_k1", &whole_samples);
    let street_json = summarize_mode("street_k2", &street_samples);
    let fine_json = summarize_mode("action_k5", &fine_samples);

    // 流式上界补充：k=5 各段并发提交（各段 witness 在出证前已知，流式
    // 管道可全段并行 prove），度量首段就绪墙钟与全段就绪墙钟。
    let mut par_first_ms: Vec<f64> = Vec::with_capacity(B3_REPS);
    let mut par_all_ms: Vec<f64> = Vec::with_capacity(B3_REPS);
    for rep in 0..B3_REPS {
        let segments = split_witnesses(
            &full_hand_witnesses(BASE_TABLE_ID + 5000 + rep as u64 * 3),
            &[1, 1, 1, 1, 1],
        );
        let started = Instant::now();
        let thread_times: Vec<f64> = std::thread::scope(|scope| {
            let handles: Vec<_> = segments
                .into_iter()
                .map(|seg| {
                    scope.spawn(move || {
                        let (prove_s, archive) = prove_batch(&seg);
                        verify_batch(&archive);
                        prove_s * 1e3
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("seg thread"))
                .collect()
        });
        let all_ms = started.elapsed().as_secs_f64() * 1e3;
        let first = thread_times.iter().cloned().fold(f64::INFINITY, f64::min);
        par_first_ms.push(first);
        par_all_ms.push(all_ms);
        perf_line(&format!(
            "m0_acc_1 mode=parallel_k5 rep={rep} first_ready_ms={first:.1} all_ready_ms={all_ms:.1}"
        ));
    }
    let (pf50, _, _) = stats(&mut par_first_ms);
    let (pa50, _, _) = stats(&mut par_all_ms);
    perf_line(&format!(
        "m0_acc_1 mode=parallel_k5 reps={B3_REPS} first_ready_p50_ms={pf50:.1} \
         all_ready_p50_ms={pa50:.1}"
    ));

    // 决策数据点落 JSON（判定与理由在 plan-appchain-perf.md 决策记录节）。
    for (key, frag) in [
        ("m0_acc_1_whole", whole_json),
        ("m0_acc_1_street", street_json),
        ("m0_acc_1_fine", fine_json),
    ] {
        let obj = frag.trim_end_matches(',');
        record_json(&format!("\"{key}\":{obj},"));
    }
    record_json(&format!(
        "\"m0_acc_1_parallel\":{{\"mode\":\"parallel_k5\",\"reps\":{B3_REPS},\
         \"first_ready_p50_ms\":{pf50:.1},\"all_ready_p50_ms\":{pa50:.1}}},"
    ));
    write_snapshot();
}
