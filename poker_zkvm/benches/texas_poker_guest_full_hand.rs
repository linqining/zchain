//! Texas Poker Guest (ZKVM port) — 完整一手牌性能基准 + 与 MVP 对比
//!
//! **Phase 5.2/5.3**：测量移植后的 guest ELF 在真实 RV32I 模拟器中运行完整 Mental
//! Poker 一手牌的性能，并与现有 MVP（`build_texas_poker_full_hand_elf`，217 条手写
//! 指令）对比。
//!
//! # 测量项（对齐方案 Phase 5.2）
//!
//! - ELF 字节数（guest vs MVP 217 条手写指令）
//! - trace 步数（每 dispatch 单独 + 全手牌聚合）
//! - `execute_elf` 时间
//! - `trace_to_native` + `trace_to_memory_trace` 转换时间
//! - `prove_cpu_trace` / `prove_cpu_memory_trace` 时间
//! - `verify_cpu_proof` / `verify_cpu_memory_proof` 时间
//! - proof 字节数
//!
//! # 运行方式
//!
//! ```bash
//! # 先编译 guest ELF
//! cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release
//! # 运行基准
//! cd /Users/mac/projects/zchain && cargo +nightly-2026-04-15 bench -p poker_zkvm --features test-helpers --bench texas_poker_guest_full_hand -- --nocapture
//! ```
//!
//! # 设计要点
//!
//! - **Stateless 模型**：guest 每次 `execute_elf` 接收一个 `ZkvmInput`，返回一个
//!   `ZkvmOutput`。一手牌 = 14 次 dispatch 链。每次 dispatch 产生独立 trace。
//! - **prove 策略**：生产中每个 dispatch 单独 prove。本基准取全手牌中**最大单次
//!   dispatch trace**（通常为 `submit_shuffle_v2` 或 `submit_player_reveal_tokens`，
//!   因含 BLS G1 运算）作为代表性最坏情形，测量 prove/verify 时间与 proof 大小。
//!   若 trace 过大导致 prove 不可行（OOM/超时），优雅记录为 "N/A"。
//! - **MVP 对比**：MVP 把整手牌编译为单个 217 条指令 ELF，一次 `execute_elf` +
//!   prove 完成全手牌。guest 则需 14 次。对比表量化两种架构的 trade-off。

#![allow(missing_docs)]

use std::path::PathBuf;
use std::time::Instant;

use borsh::BorshDeserialize;

use poker_zkvm::isa::executor::execute_elf;
use poker_zkvm::stwo_backend::prover::{
    prove_cpu_memory_trace, prove_cpu_trace, verify_cpu_memory_proof, verify_cpu_proof,
};
use poker_zkvm::stwo_backend::trace_native::{trace_to_memory_trace_with_log_size, trace_to_native};
use poker_zkvm::test_helpers::{
    build_texas_poker_full_hand_elf, make_full_hand_input, texas_poker_full_hand_expected,
};

use texas_poker_guest::dispatch::{
    selectors, CreateTableArgs, DispatchContext, JoinTableArgs, SeatIndexArgs,
    SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
use texas_poker_guest::events::TexasPokerEvent;
use texas_poker_guest::io::{ZkvmInput, ZkvmOutput};
use texas_poker_guest::types::TexasPokerTable;
use texas_poker_guest::G1Point;

// ========== ELF 路径与读取 ==========

/// 返回编译后的 guest ELF 路径。
fn guest_elf_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("guests/texas_poker/target/riscv32i-unknown-none-elf/release/texas_poker_guest");
    p
}

/// 读取 guest ELF 字节。若文件不存在则给出明确的引导消息。
fn read_guest_elf() -> Vec<u8> {
    let path = guest_elf_path();
    if !path.exists() {
        panic!(
            "guest ELF 未找到：{}\n请先执行：\n  cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release",
            path.display()
        );
    }
    std::fs::read(&path).unwrap_or_else(|e| panic!("读取 guest ELF 失败 {path:?}: {e}"))
}

// ========== BLS 辅助（与 E2E 测试一致）==========

/// 生成有效的 BLS12-381 G1 压缩点（generator * scalar）。
fn valid_g1(scalar: u64) -> G1Point {
    use blstrs::G1Projective;
    use pairing::group::Group;
    let g = G1Projective::generator();
    let s = blstrs::Scalar::from(scalar);
    let p = g * s;
    G1Point(p.to_compressed())
}

/// BLS12-381 G1 单位元（identity）的压缩表示。
fn identity_g1() -> G1Point {
    use blstrs::G1Projective;
    use pairing::group::Group;
    let id = G1Projective::identity();
    G1Point(id.to_compressed())
}

fn is_in_list(list: &[u8], value: u8) -> bool {
    list.iter().any(|&v| v == value)
}

// ========== dispatch 辅助 ==========

fn make_context() -> DispatchContext {
    DispatchContext {
        caller: [0xAA; 20],
        chain_id: 1,
        block_height: 100,
        block_timestamp: 1_700_000_000_000,
    }
}

fn make_initial_table() -> TexasPokerTable {
    TexasPokerTable::new([0x42; 32], "placeholder".into(), 6, 25, 50)
}

/// 单次 dispatch 记录。
#[derive(Debug, Clone)]
struct DispatchRecord {
    label: String,
    trace_steps: usize,
    execute_ms: f64,
    /// 保留该 dispatch 的 raw trace，用于后续 prove 测量（仅最大者保留，其余释放）。
    #[allow(dead_code)]
    trace: Option<poker_zkvm::trace::Trace>,
}

/// 通过 `execute_elf` 执行一次 dispatch，返回 (更新后的 table, events, dispatch 记录)。
fn dispatch_timed(
    elf: &[u8],
    table: &TexasPokerTable,
    ctx: &DispatchContext,
    selector: [u8; 32],
    args_bytes: &[u8],
    label: &str,
    keep_trace: bool,
) -> (TexasPokerTable, Vec<TexasPokerEvent>, DispatchRecord) {
    let input = ZkvmInput {
        table: table.clone(),
        context: *ctx,
        method_selector: selector,
        args: args_bytes.to_vec(),
    };
    let input_borsh = borsh::to_vec(&input).expect("ZkvmInput borsh 序列化应成功");
    let mut elf_input = (input_borsh.len() as u32).to_le_bytes().to_vec();
    elf_input.extend_from_slice(&input_borsh);

    let t0 = Instant::now();
    let result = execute_elf(elf, &elf_input).expect("ELF 执行应成功（dispatch 不应 panic）");
    let execute_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let trace_steps = result.trace.len();

    let output: ZkvmOutput = BorshDeserialize::try_from_slice(&result.output)
        .unwrap_or_else(|e| panic!("ZkvmOutput 反序列化失败: {e}"));

    let record = DispatchRecord {
        label: label.to_string(),
        trace_steps,
        execute_ms,
        trace: if keep_trace { Some(result.trace) } else { None },
    };
    (output.table, output.events, record)
}

// ========== Guest 全手牌运行 ==========

/// Guest 全手牌性能报告。
#[derive(Debug)]
struct GuestReport {
    elf_bytes: usize,
    dispatches: Vec<DispatchRecord>,
    total_execute_ms: f64,
    total_trace_steps: usize,
    /// 最大单次 dispatch 的 trace（用于 prove 测量）。
    largest_dispatch_label: String,
    largest_trace_steps: usize,
    largest_log_size: u32,
    trace_convert_ms: f64,
    prove_ms: Option<f64>,
    verify_ms: Option<f64>,
    proof_bytes: Option<usize>,
    proof_ok: bool,
}

/// 运行完整 Mental Poker 一手牌（14 次 dispatch），收集性能数据。
fn run_guest_full_hand(elf: &[u8]) -> GuestReport {
    let ctx = make_context();
    let mut table = make_initial_table();
    let elf_bytes = elf.len();
    let id_point = identity_g1();

    let mut dispatches: Vec<DispatchRecord> = Vec::new();

    // 宏：执行一次 dispatch，更新 table 并记录性能数据（含 trace 可选保留）。
    macro_rules! dispatch {
        ($sel:expr, $args:expr, $label:expr, $keep:expr) => {{
            let (new_table, _events, record) =
                dispatch_timed(elf, &table, &ctx, $sel, $args, $label, $keep);
            dispatches.push(record);
            table = new_table;
        }};
    }

    // 1. create_table
    let create = CreateTableArgs { name: "full_hand".into(), max_players: 2, small_blind: 10, big_blind: 20 };
    dispatch!(selectors::create_table(), &borsh::to_vec(&create).unwrap(), "1.create_table", false);

    // 2. join_table × 2
    let j1 = JoinTableArgs { player: [0x11; 20], buy_in: 1000, pk: valid_g1(1) };
    dispatch!(selectors::join_table(), &borsh::to_vec(&j1).unwrap(), "2a.join_table p1", false);
    let j2 = JoinTableArgs { player: [0x22; 20], buy_in: 2000, pk: valid_g1(2) };
    dispatch!(selectors::join_table(), &borsh::to_vec(&j2).unwrap(), "2b.join_table p2", false);

    // 3. start_hand
    dispatch!(selectors::start_hand(), &[], "3.start_hand", false);

    // 4-5. submit_shuffle_v2 × 2（保留 trace 用于 prove，shuffle 含 add_pk_to_c2 G1 运算）
    let s0 = SubmitShuffleV2Args { seat_index: 0, output_cards: table.deck_state.encrypted.clone(), shuffle_proof: Vec::new() };
    dispatch!(selectors::submit_shuffle_v2(), &borsh::to_vec(&s0).unwrap(), "4.shuffle seat0", true);
    let s1 = SubmitShuffleV2Args { seat_index: 1, output_cards: table.deck_state.encrypted.clone(), shuffle_proof: Vec::new() };
    dispatch!(selectors::submit_shuffle_v2(), &borsh::to_vec(&s1).unwrap(), "5.shuffle seat1", true);

    // 6. preflop reveal × 2（保留 trace）
    let r0 = SubmitRevealTokensArgs { seat_index: 0, assignment_indices: vec![2, 3], reveal_tokens: vec![id_point; 2], proofs: vec![Vec::new(); 2] };
    dispatch!(selectors::submit_player_reveal_tokens(), &borsh::to_vec(&r0).unwrap(), "6a.preflop reveal s0", true);
    let r1 = SubmitRevealTokensArgs { seat_index: 1, assignment_indices: vec![0, 1], reveal_tokens: vec![id_point; 2], proofs: vec![Vec::new(); 2] };
    dispatch!(selectors::submit_player_reveal_tokens(), &borsh::to_vec(&r1).unwrap(), "6b.preflop reveal s1", true);

    // 7-13. 4 轮 (betting + community reveal)
    let round_labels = ["preflop", "flop", "turn", "river"];
    for (i, &round_label) in round_labels.iter().enumerate() {
        // betting
        for _ in 0..6 {
            let turn = match table.current_turn { Some(s) => s, None => break };
            let current_bet = table.betting_round.as_ref().map(|r| r.current_bet).unwrap_or(0);
            let seat_bet = table.seats[turn as usize].bet;
            let selector = if seat_bet < current_bet { selectors::call() } else { selectors::check() };
            let args = SeatIndexArgs { seat_index: turn };
            dispatch!(selector, &borsh::to_vec(&args).unwrap(), &format!("{}.bet {} s{}", 7 + 2 * i, round_label, turn), false);
            if table.betting_round.is_none() || table.current_turn.is_none() { break; }
        }
        // community reveal（river 之后无更多 reveal，由 showdown 处理）
        if i < 3 {
            for seat in 0u8..2 {
                let mine: Vec<u8> = table.reveal_token_state.assignments.iter().enumerate()
                    .filter_map(|(idx, a)| if !a.decrypted && is_in_list(&a.pending_players, seat) { Some(idx as u8) } else { None })
                    .collect();
                if mine.is_empty() { continue; }
                let rv = SubmitRevealTokensArgs { seat_index: seat, assignment_indices: mine.clone(), reveal_tokens: vec![id_point; mine.len()], proofs: vec![Vec::new(); mine.len()] };
                dispatch!(selectors::submit_player_reveal_tokens(), &borsh::to_vec(&rv).unwrap(), &format!("{}.reveal {} s{}", 8 + 2 * i, round_labels[i + 1], seat), false);
            }
        }
    }

    // 14. showdown reveal + settle（保留 trace）
    for seat in 0u8..2 {
        let mine: Vec<u8> = table.reveal_token_state.assignments.iter().enumerate()
            .filter_map(|(idx, a)| if !a.decrypted && is_in_list(&a.pending_players, seat) { Some(idx as u8) } else { None })
            .collect();
        if mine.is_empty() { continue; }
        let rv = SubmitRevealTokensArgs { seat_index: seat, assignment_indices: mine.clone(), reveal_tokens: vec![id_point; mine.len()], proofs: vec![Vec::new(); mine.len()] };
        dispatch!(selectors::submit_player_reveal_tokens(), &borsh::to_vec(&rv).unwrap(), &format!("14.showdown reveal s{}", seat), true);
    }

    // 聚合
    let total_execute_ms: f64 = dispatches.iter().map(|d| d.execute_ms).sum();
    let total_trace_steps: usize = dispatches.iter().map(|d| d.trace_steps).sum();

    // 找最大 trace（用于 prove 测量）
    let mut largest_idx = 0usize;
    for (i, d) in dispatches.iter().enumerate() {
        if d.trace_steps > dispatches[largest_idx].trace_steps {
            largest_idx = i;
        }
    }
    let largest_dispatch_label = dispatches[largest_idx].label.clone();
    let largest_trace_steps = dispatches[largest_idx].trace_steps;

    // prove 测量：取最大 dispatch 的 trace
    let mut prove_ms = None;
    let mut verify_ms = None;
    let mut proof_bytes = None;
    let mut proof_ok = false;
    let mut largest_log_size = 0u32;
    let mut trace_convert_ms = 0.0;

    if let Some(largest_trace) = dispatches[largest_idx].trace.as_ref() {
        let t1 = Instant::now();
        let cpu_trace = trace_to_native(largest_trace);
        // 对齐 Memory trace log_size 到 CPU trace（修复 guest 大 trace 内存访问稀疏导致的 mismatch）
        let mem_trace = trace_to_memory_trace_with_log_size(largest_trace, cpu_trace.log_size);
        trace_convert_ms = t1.elapsed().as_secs_f64() * 1000.0;
        largest_log_size = cpu_trace.log_size;

        println!("\n>>> prove 测量：最大 dispatch = '{largest_dispatch_label}' ({largest_trace_steps} steps, log_size={largest_log_size})");

        // 先尝试 CPU-only prove（更快），成功后再尝试 CPU+Memory prove。
        // 注：`CpuProof = StarkProof<...>`（类型别名，无 stark_proof 字段），
        // 直接序列化整个 proof；`CpuMemoryProof` 是 struct，有 `.stark_proof` 字段。
        match prove_cpu_trace(&cpu_trace) {
            Ok(cpu_proof) => {
                let pb = bincode::serialize(&cpu_proof).map(|b| b.len()).unwrap_or(0);
                println!("    prove_cpu_trace 成功: proof_bytes={pb}");
                match verify_cpu_proof(cpu_proof, largest_log_size) {
                    Ok(()) => {
                        println!("    verify_cpu_proof 成功");
                    }
                    Err(e) => println!("    verify_cpu_proof 失败: {e:?}"),
                }
            }
            Err(e) => println!("    prove_cpu_trace 失败: {e:?}"),
        }

        // CPU+Memory prove（生产路径）
        let t2 = Instant::now();
        match prove_cpu_memory_trace(&cpu_trace, &mem_trace) {
            Ok(proof) => {
                let p_ms = t2.elapsed().as_secs_f64() * 1000.0;
                let pb = bincode::serialize(&proof.stark_proof).map(|b| b.len()).unwrap_or(0);
                println!("    prove_cpu_memory_trace 成功: {p_ms:.2} ms, proof={pb} bytes ({:.2} KB)", pb as f64 / 1024.0);

                let t3 = Instant::now();
                let verify_result = verify_cpu_memory_proof(proof, largest_log_size);
                let v_ms = t3.elapsed().as_secs_f64() * 1000.0;
                let ok = verify_result.is_ok();
                println!("    verify_cpu_memory_proof: {v_ms:.2} ms — {}", if ok { "✓" } else { "✗" });

                prove_ms = Some(p_ms);
                verify_ms = Some(v_ms);
                proof_bytes = Some(pb);
                proof_ok = ok;
            }
            Err(e) => {
                let p_ms = t2.elapsed().as_secs_f64() * 1000.0;
                println!("    prove_cpu_memory_trace 失败 ({p_ms:.2} ms): {e:?}");
            }
        }
    }

    GuestReport {
        elf_bytes,
        dispatches,
        total_execute_ms,
        total_trace_steps,
        largest_dispatch_label,
        largest_trace_steps,
        largest_log_size,
        trace_convert_ms,
        prove_ms,
        verify_ms,
        proof_bytes,
        proof_ok,
    }
}

impl GuestReport {
    fn print(&self) {
        println!("\n{}", "=".repeat(80));
        println!("Guest ELF（移植后）完整一手牌 — 性能基准");
        println!("{}", "=".repeat(80));
        println!("ELF 大小:          {:>10} bytes", self.elf_bytes);
        println!("dispatch 次数:     {:>10}", self.dispatches.len());
        println!("总 trace 步数:     {:>10} steps", self.total_trace_steps);
        println!("总执行时间:        {:>10.2} ms", self.total_execute_ms);
        println!("\n--- 每 dispatch 明细 ---");
        println!("{:<34} {:>12} {:>12}", "dispatch", "steps", "ms");
        for d in &self.dispatches {
            println!("{:<34} {:>12} {:>12.2}", d.label, d.trace_steps, d.execute_ms);
        }
        println!("\n--- prove/verify（最大 dispatch: '{}'）---", self.largest_dispatch_label);
        println!("最大 dispatch trace 步数:  {:>10} steps", self.largest_trace_steps);
        println!("最大 dispatch log_size:    {:>10} (2^{} = {} rows)", self.largest_log_size, self.largest_log_size, 1u64 << self.largest_log_size);
        println!("Trace 转换时间:             {:>10.2} ms", self.trace_convert_ms);
        match self.prove_ms {
            Some(ms) => println!("Prove 时间:                 {:>10.2} ms", ms),
            None => println!("Prove 时间:                 {:>10}", "N/A"),
        }
        match self.verify_ms {
            Some(ms) => println!("Verify 时间:                {:>10.2} ms", ms),
            None => println!("Verify 时间:                {:>10}", "N/A"),
        }
        match self.proof_bytes {
            Some(b) => println!("Proof 大小:                 {:>10} bytes ({:.2} KB)", b, b as f64 / 1024.0),
            None => println!("Proof 大小:                 {:>10}", "N/A"),
        }
        println!("Proof 验证:                 {}", if self.proof_ok { "✓ 通过" } else { "✗ 失败/N/A" });
    }
}

// ========== MVP 对比 ==========

/// MVP（217 条手写指令）性能报告。
#[derive(Debug)]
struct MvpReport {
    elf_bytes: usize,
    input_bytes: usize,
    trace_steps: usize,
    trace_log_size: u32,
    execute_ms: f64,
    trace_convert_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    output: u8,
    expected: u8,
    output_correct: bool,
    proof_ok: bool,
}

/// 运行 MVP 全手牌基准（P1 顺子 vs P2 对子）。
fn run_mvp_full_hand() -> Result<MvpReport, Box<dyn std::error::Error>> {
    let p1 = [14u8, 13, 12, 11, 10];
    let p2 = [2u8, 2, 3, 4, 5];

    let elf = build_texas_poker_full_hand_elf();
    let elf_bytes = elf.len();
    let input = make_full_hand_input(p1, p2);
    let input_bytes = input.len();
    let expected = texas_poker_full_hand_expected(&input);

    let t0 = Instant::now();
    let result = execute_elf(&elf, &input)?;
    let execute_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let trace_steps = result.trace.len();
    let output = result.output.get(0).copied().unwrap_or(255);
    let output_correct = output == expected;

    let t1 = Instant::now();
    let cpu_trace = trace_to_native(&result.trace);
    let mem_trace = trace_to_memory_trace_with_log_size(&result.trace, cpu_trace.log_size);
    let trace_convert_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let trace_log_size = cpu_trace.log_size;

    let t2 = Instant::now();
    let proof = prove_cpu_memory_trace(&cpu_trace, &mem_trace)?;
    let prove_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = bincode::serialize(&proof.stark_proof)?.len();

    let t3 = Instant::now();
    let verify_result = verify_cpu_memory_proof(proof, trace_log_size);
    let verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
    let proof_ok = verify_result.is_ok();

    Ok(MvpReport {
        elf_bytes,
        input_bytes,
        trace_steps,
        trace_log_size,
        execute_ms,
        trace_convert_ms,
        prove_ms,
        verify_ms,
        proof_bytes,
        output,
        expected,
        output_correct,
        proof_ok,
    })
}

impl MvpReport {
    fn print(&self) {
        println!("\n{}", "=".repeat(80));
        println!("MVP（217 条手写指令）完整一手牌 — 性能基准");
        println!("{}", "=".repeat(80));
        println!("ELF 大小:          {:>10} bytes", self.elf_bytes);
        println!("输入大小:          {:>10} bytes", self.input_bytes);
        println!("Trace 步数:        {:>10} steps", self.trace_steps);
        println!("Trace log_size:    {:>10} (2^{} = {} rows)", self.trace_log_size, self.trace_log_size, 1u64 << self.trace_log_size);
        println!("执行时间:          {:>10.2} ms", self.execute_ms);
        println!("Trace 转换:        {:>10.2} ms", self.trace_convert_ms);
        println!("Prove 时间:        {:>10.2} ms", self.prove_ms);
        println!("Verify 时间:       {:>10.2} ms", self.verify_ms);
        println!("Proof 大小:        {:>10} bytes ({:.2} KB)", self.proof_bytes, self.proof_bytes as f64 / 1024.0);
        println!("输出 (winner):     {} (期望 {}) {}", self.output, self.expected, if self.output_correct { "✓" } else { "✗" });
        println!("Proof 验证:        {}", if self.proof_ok { "✓ 通过" } else { "✗ 失败" });
    }
}

// ========== 对比表 ==========

fn print_comparison(guest: &GuestReport, mvp: &Option<MvpReport>) {
    println!("\n{}", "=".repeat(80));
    println!("对比报告：Guest (移植后) vs MVP (217 条手写指令)");
    println!("{}", "=".repeat(80));
    println!("{:<28} {:>20} {:>20} {:>14}", "指标", "Guest (移植)", "MVP (手写)", "倍数");
    println!("{}", "-".repeat(82));

    let row = |label: &str, guest_v: String, mvp_v: String, ratio: String| {
        println!("{:<28} {:>20} {:>20} {:>14}", label, guest_v, mvp_v, ratio);
    };

    row("ELF 字节数",
        format!("{}", guest.elf_bytes),
        mvp.as_ref().map(|m| m.elf_bytes.to_string()).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.1}x", guest.elf_bytes as f64 / m.elf_bytes as f64)).unwrap_or_default());

    row("架构说明",
        "Rust no_std (全合约)".into(),
        "手写 RV32I (牌型比较)".into(),
        "—".into());

    row("dispatch 次数/手牌",
        format!("{}", guest.dispatches.len()),
        "1 (单 ELF)".into(),
        format!("{:.1}x", guest.dispatches.len() as f64));

    row("总 trace 步数",
        format!("{}", guest.total_trace_steps),
        mvp.as_ref().map(|m| m.trace_steps.to_string()).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.1}x", guest.total_trace_steps as f64 / m.trace_steps as f64)).unwrap_or_default());

    row("总执行时间 (ms)",
        format!("{:.2}", guest.total_execute_ms),
        mvp.as_ref().map(|m| format!("{:.2}", m.execute_ms)).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.1}x", guest.total_execute_ms / m.execute_ms)).unwrap_or_default());

    row("单次最大 dispatch 步数",
        format!("{}", guest.largest_trace_steps),
        mvp.as_ref().map(|m| m.trace_steps.to_string()).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.1}x", guest.largest_trace_steps as f64 / m.trace_steps as f64)).unwrap_or_default());

    row("Prove 时间 (ms)",
        guest.prove_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.2}", m.prove_ms)).unwrap_or_else(|| "N/A".into()),
        match (guest.prove_ms, mvp.as_ref().map(|m| m.prove_ms)) {
            (Some(g), Some(m)) => format!("{:.1}x", g / m),
            _ => "—".into(),
        });

    row("Verify 时间 (ms)",
        guest.verify_ms.map(|v| format!("{:.2}", v)).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| format!("{:.2}", m.verify_ms)).unwrap_or_else(|| "N/A".into()),
        match (guest.verify_ms, mvp.as_ref().map(|m| m.verify_ms)) {
            (Some(g), Some(m)) => format!("{:.1}x", g / m),
            _ => "—".into(),
        });

    row("Proof 大小 (bytes)",
        guest.proof_bytes.map(|v| format!("{}", v)).unwrap_or_else(|| "N/A".into()),
        mvp.as_ref().map(|m| m.proof_bytes.to_string()).unwrap_or_else(|| "N/A".into()),
        match (guest.proof_bytes, mvp.as_ref().map(|m| m.proof_bytes)) {
            (Some(g), Some(m)) => format!("{:.1}x", g as f64 / m as f64),
            _ => "—".into(),
        });

    println!("{}", "-".repeat(82));
    println!("注：Guest 为完整 Mental Poker 协议（洗牌/揭牌/下注/结算全状态机），");
    println!("    MVP 仅实现牌型比较胜负判定。两者功能域不同，倍数仅反映复杂度差异。");
    println!("    Guest prove 基于「单次最大 dispatch」trace（生产中每 dispatch 独立 prove）。");
}

// ========== main ==========

fn main() {
    println!("Texas Poker Guest (ZKVM port) — Phase 5.2/5.3 性能基准 + MVP 对比\n");

    // 1. Guest 全手牌
    let guest_elf = read_guest_elf();
    let guest = run_guest_full_hand(&guest_elf);
    guest.print();

    // 2. MVP 全手牌（用于对比）
    println!("\n>>> 运行 MVP（217 条手写指令）基准...");
    let mvp = match run_mvp_full_hand() {
        Ok(r) => {
            r.print();
            Some(r)
        }
        Err(e) => {
            eprintln!("MVP 基准失败: {e}");
            None
        }
    };

    // 3. 对比表
    print_comparison(&guest, &mvp);

    // 4. CSV
    println!("\n=== CSV: guest per-dispatch ===");
    println!("dispatch,trace_steps,execute_ms");
    for d in &guest.dispatches {
        println!("{},{},{:.3}", d.label, d.trace_steps, d.execute_ms);
    }

    println!("\n=== CSV: summary ===");
    println!("variant,elf_bytes,total_trace_steps,total_execute_ms,largest_trace_steps,prove_ms,verify_ms,proof_bytes");
    println!("guest,{},{},{:.3},{},{},{},{}",
        guest.elf_bytes, guest.total_trace_steps, guest.total_execute_ms,
        guest.largest_trace_steps,
        guest.prove_ms.map(|v| format!("{:.3}", v)).unwrap_or_default(),
        guest.verify_ms.map(|v| format!("{:.3}", v)).unwrap_or_default(),
        guest.proof_bytes.unwrap_or(0));
    if let Some(m) = &mvp {
        println!("mvp,{},{},{:.3},{},{:.3},{:.3},{}",
            m.elf_bytes, m.trace_steps, m.execute_ms,
            m.trace_steps, m.prove_ms, m.verify_ms, m.proof_bytes);
    }
}
