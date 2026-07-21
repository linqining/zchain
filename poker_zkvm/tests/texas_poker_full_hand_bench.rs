//! Texas Poker 完整一手牌 E2E 性能基准
//!
//! 运行方式：
//! ```bash
//! cargo test -p poker_zkvm --features test-helpers --test texas_poker_full_hand_bench -- --nocapture --ignored
//! ```
//!
//! 或作为 benchmark：
//! ```bash
//! cargo bench -p poker_zkvm --features test-helpers --bench texas_poker_full_hand
//! ```

#![allow(missing_docs)]

use std::time::Instant;

use poker_zkvm::isa::executor::execute_elf;
use poker_zkvm::stwo_backend::prover::{
    prove_cpu_memory_trace, prove_cpu_trace, verify_cpu_memory_proof, verify_cpu_proof,
};
use poker_zkvm::stwo_backend::trace_native::{trace_to_memory_trace, trace_to_native};
use poker_zkvm::test_helpers::{
    build_texas_poker_full_hand_elf, make_full_hand_input, texas_poker_full_hand_expected,
};

/// 性能测量结果
#[derive(Debug, Clone)]
struct PerfReport {
    /// 场景名称
    scenario: String,
    /// ELF 字节数
    elf_bytes: usize,
    /// 输入字节数
    input_bytes: usize,
    /// trace 步数
    trace_steps: usize,
    /// trace log_size（pad 后）
    trace_log_size: u32,
    /// 执行时间（execute_elf）
    execute_ms: f64,
    /// trace 转换时间（trace_to_native + trace_to_memory_trace）
    trace_convert_ms: f64,
    /// prove 时间
    prove_ms: f64,
    /// verify 时间
    verify_ms: f64,
    /// proof 字节数
    proof_bytes: usize,
    /// proof KB
    proof_kb: f64,
    /// 程序输出（winner）
    output: u8,
    /// 期望输出
    expected: u8,
    /// 输出是否正确
    output_correct: bool,
    /// prove + verify 是否成功
    proof_verified: bool,
}

impl PerfReport {
    /// 打印性能报告到 stdout
    fn print(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║  Texas Poker 完整一手牌 — 性能基准报告                            ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  场景: {:<58} ║", self.scenario);
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  ELF 大小:        {:>8} bytes                              ║", self.elf_bytes);
        println!("║  输入大小:        {:>8} bytes                              ║", self.input_bytes);
        println!("║  Trace 步数:      {:>8} steps                              ║", self.trace_steps);
        println!("║  Trace log_size:  {:>8} (2^{} = {} rows)               ║",
                 self.trace_log_size, self.trace_log_size, 1u64 << self.trace_log_size);
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  执行时间 (execute_elf):     {:>10.3} ms                    ║", self.execute_ms);
        println!("║  Trace 转换时间:             {:>10.3} ms                    ║", self.trace_convert_ms);
        println!("║  Prove 时间:                 {:>10.3} ms                    ║", self.prove_ms);
        println!("║  Verify 时间:                {:>10.3} ms                    ║", self.verify_ms);
        println!("║  总时间 (exec+conv+prove):   {:>10.3} ms                    ║",
                 self.execute_ms + self.trace_convert_ms + self.prove_ms);
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  Proof 大小:      {:>8} bytes ({:.2} KB)                    ║",
                 self.proof_bytes, self.proof_kb);
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  输出 (winner):   {} (期望: {})  {}                ║",
                 self.output, self.expected,
                 if self.output_correct { "✓ 正确" } else { "✗ 错误" });
        println!("║  Proof 验证:      {}                                           ║",
                 if self.proof_verified { "✓ 通过" } else { "✗ 失败" });
        println!("╚══════════════════════════════════════════════════════════════════╝");
    }

    /// 打印 CSV 格式（便于复制到表格）
    fn print_csv_header() {
        println!("\n=== CSV 格式 ===");
        println!("scenario,elf_bytes,input_bytes,trace_steps,trace_log_size,execute_ms,trace_convert_ms,prove_ms,verify_ms,proof_bytes,proof_kb,output,expected,output_correct,proof_verified");
    }

    fn print_csv(&self) {
        println!("{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{},{:.3},{},{},{},{}",
            self.scenario,
            self.elf_bytes,
            self.input_bytes,
            self.trace_steps,
            self.trace_log_size,
            self.execute_ms,
            self.trace_convert_ms,
            self.prove_ms,
            self.verify_ms,
            self.proof_bytes,
            self.proof_kb,
            self.output,
            self.expected,
            self.output_correct,
            self.proof_verified,
        );
    }
}

/// 运行完整一手牌流程并收集性能数据
fn run_full_hand_benchmark(
    scenario: &str,
    p1: [u8; 5],
    p2: [u8; 5],
) -> Result<PerfReport, Box<dyn std::error::Error>> {
    println!("\n>>> 运行场景: {scenario}");
    println!("    P1 牌: {:?}", p1);
    println!("    P2 牌: {:?}", p2);

    // 1. 构建 ELF
    let elf = build_texas_poker_full_hand_elf();
    let elf_bytes = elf.len();
    println!("    ELF 大小: {elf_bytes} bytes");

    // 2. 构建输入
    let input = make_full_hand_input(p1, p2);
    let input_bytes = input.len();
    let expected = texas_poker_full_hand_expected(&input);
    println!("    期望 winner: {expected}");

    // 3. 执行 ELF
    let t0 = Instant::now();
    let result = execute_elf(&elf, &input)?;
    let execute_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let trace_steps = result.trace.len();
    println!("    执行完成: {trace_steps} steps, {:.3} ms", execute_ms);

    // 4. 验证输出
    let output = result.output.get(0).copied().unwrap_or(255);
    let output_correct = output == expected;
    println!("    输出: {output} (期望: {expected}) — {}",
        if output_correct { "✓" } else { "✗" });

    if !output_correct {
        return Err(format!("输出不正确: {output} != {expected}").into());
    }

    // 5. trace 转换
    let t1 = Instant::now();
    let cpu_trace = trace_to_native(&result.trace);
    let mem_trace = trace_to_memory_trace(&result.trace);
    let trace_convert_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let trace_log_size = cpu_trace.log_size;
    println!("    Trace 转换: log_size={trace_log_size}, {:.3} ms", trace_convert_ms);

    // 6. prove
    println!("    开始 prove...");
    let t2 = Instant::now();
    let proof = prove_cpu_memory_trace(&cpu_trace, &mem_trace)?;
    let prove_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let proof_bytes = bincode::serialize(&proof.stark_proof)?.len();
    let proof_kb = proof_bytes as f64 / 1024.0;
    println!("    Prove 完成: {:.3} ms, proof = {:.2} KB", prove_ms, proof_kb);

    // 7. verify
    let t3 = Instant::now();
    let verify_result = verify_cpu_memory_proof(proof, trace_log_size);
    let verify_ms = t3.elapsed().as_secs_f64() * 1000.0;
    let proof_verified = verify_result.is_ok();
    println!("    Verify: {:.3} ms — {}",
        verify_ms,
        if proof_verified { "✓ 通过" } else { "✗ 失败" });

    if !proof_verified {
        return Err(format!("verify 失败: {:?}", verify_result.err()).into());
    }

    Ok(PerfReport {
        scenario: scenario.to_string(),
        elf_bytes,
        input_bytes,
        trace_steps,
        trace_log_size,
        execute_ms,
        trace_convert_ms,
        prove_ms,
        verify_ms,
        proof_bytes,
        proof_kb,
        output,
        expected,
        output_correct,
        proof_verified,
    })
}

/// 二分法找出导致 prove 失败的步骤
#[test]
#[ignore = "调试用：二分法定位失败步骤"]
fn test_texas_poker_bisect_prove_failure() {
    use poker_zkvm::trace::Trace;

    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);

    let result = execute_elf(&elf, &input).expect("execute 失败");
    let total_steps = result.trace.len();
    println!("总步数: {total_steps}");

    // 二分法：找出第一个导致 prove 失败的步数
    let mut lo = 1usize;
    let mut hi = total_steps;

    while lo < hi {
        let mid = (lo + hi) / 2;
        // 截取前 mid 步
        let mut sub_trace = Trace::new();
        sub_trace.set_initial_registers(*result.trace.initial_registers());
        for (i, step) in result.trace.iter().enumerate().take(mid) {
            sub_trace.push_step(poker_zkvm::trace::Step::from_log(i as u64, poker_zkvm::trace::StepLog {
                pc: step.pc,
                instruction: step.instruction.clone(),
                registers: step.registers,
                mem_access: step.mem_access.clone(),
            }));
        }

        let native = trace_to_native(&sub_trace);
        let prove_result = prove_cpu_trace(&native);
        if prove_result.is_ok() {
            println!("  前 {mid} 步: ✓ prove 成功");
            lo = mid + 1;
        } else {
            println!("  前 {mid} 步: ✗ prove 失败: {:?}", prove_result.err());
            hi = mid;
        }
    }

    println!("\n第一个失败点: 前 {lo} 步导致 prove 失败 (即 step index {} 是新增的失败行)", lo - 1);
    let fail_step = lo;
    let failing_row = lo - 1; // 新增的失败行索引

    // 打印 prove 的实际错误信息
    {
        let mut sub_trace = Trace::new();
        sub_trace.set_initial_registers(*result.trace.initial_registers());
        for (i, step) in result.trace.iter().enumerate().take(fail_step) {
            sub_trace.push_step(poker_zkvm::trace::Step::from_log(i as u64, poker_zkvm::trace::StepLog {
                pc: step.pc,
                instruction: step.instruction.clone(),
                registers: step.registers,
                mem_access: step.mem_access.clone(),
            }));
        }
        let native = trace_to_native(&sub_trace);
        let prove_result = prove_cpu_trace(&native);
        println!("\n=== prove 实际错误信息 ===");
        match &prove_result {
            Ok(_) => println!("Ok"),
            Err(e) => {
                // 只打印错误类型，不打印完整 proof 数据
                let dbg = format!("{:?}", e);
                // 截取前 500 字符（错误类型 + 部分 detail）
                println!("Err (前 500 字符): {}", &dbg[..dbg.len().min(500)]);
                println!("错误变体名: {}", std::any::type_name_of_val(e));
            }
        }
    }

    // 打印失败步骤的指令
    if failing_row < total_steps {
        let step = result.trace.iter().nth(failing_row).unwrap();
        println!("\n失败 step {}: pc=0x{:08X} {:?}", failing_row, step.pc, step.instruction);
        println!("  registers (前 10): {:?}", &step.registers[..10.min(step.registers.len())]);
        println!("  mem_access: {} entries", step.mem_access.len());
        for ma in &step.mem_access {
            println!("    addr=0x{:08X} op={:?} value=0x{:08X} size={}",
                ma.addr, ma.op, ma.value, ma.size);
        }
    }

    // 验证：前 lo-1 步成功，前 lo 步失败
    let mut sub_trace = Trace::new();
    sub_trace.set_initial_registers(*result.trace.initial_registers());
    for (i, step) in result.trace.iter().enumerate().take(fail_step) {
        sub_trace.push_step(poker_zkvm::trace::Step::from_log(i as u64, poker_zkvm::trace::StepLog {
            pc: step.pc,
            instruction: step.instruction.clone(),
            registers: step.registers,
            mem_access: step.mem_access.clone(),
        }));
    }
    let native = trace_to_native(&sub_trace);

    // 打印失败行的所有列值
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    println!("\n=== 失败行 (row {failing_row}) 的所有非零列 ===");
    let mut nonzero_cols = Vec::new();
    for (col_idx, col_vals) in native.cols.iter().enumerate() {
        let val = col_vals[failing_row].0 as u32;
        if val != 0 {
            nonzero_cols.push((col_idx, val));
        }
    }
    for (col_idx, val) in &nonzero_cols {
        let name = column_name(*col_idx).unwrap_or("?");
        println!("  col[{col_idx:3}] ({name:>20}) = {val} (0x{val:08X})");
    }
    println!("共 {} 个非零列", nonzero_cols.len());

    // 打印最后 3 步的简要信息
    println!("\n=== 最后 3 步的 NativeTrace 简要 ===");
    let start = failing_row.saturating_sub(2);
    for row in start..=failing_row {
        let pc = cpu_trace_pc(&native, row);
        let next_pc = cpu_trace_next_pc(&native, row);
        let taken = native.cols[COL_TAKEN][row].0 as u32;
        let is_padding = native.cols[IS_PADDING][row].0 as u32;
        let is_ecall = native.cols[IS_ECALL][row].0 as u32;
        let mut indicators = Vec::new();
        for (name, idx) in indicator_names() {
            if native.cols[*idx][row].0 as u32 == 1 {
                indicators.push(*name);
            }
        }
        println!("  row {row}: pc=0x{pc:08X} next_pc=0x{next_pc:08X} taken={taken} padding={is_padding} ecall={is_ecall} ind={:?}",
            indicators);

        // 检查 ECALL zero gating: 非 ECALL 行，ECALL dispatch 列（仅 SyscallId）必须为 0
        if is_ecall == 0 {
            let val = native.cols[COL_SYSCALL_ID][row].0 as u32;
            if val != 0 {
                println!("    ⚠ ECALL col SyscallId (base={COL_SYSCALL_ID}) 非零: val={val}");
            }
        }

        // 检查 ADD/ADDI/SUB 约束
        let is_add = native.cols[IS_ADD][row].0 as u32;
        let is_addi = native.cols[IS_ADDI][row].0 as u32;
        let is_sub = native.cols[IS_SUB][row].0 as u32;
        if is_add == 1 || is_addi == 1 {
            let rd_eff_low = native.cols[COL_VALUE_A_EFF_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_A_EFF_BASE + 1][row].0 as u32;
            let rd_eff_high = native.cols[COL_VALUE_A_EFF_BASE + 2][row].0 as u32
                + 256 * native.cols[COL_VALUE_A_EFF_BASE + 3][row].0 as u32;
            let rs1_low = native.cols[COL_VALUE_B_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_B_BASE + 1][row].0 as u32;
            let rs1_high = native.cols[COL_VALUE_B_BASE + 2][row].0 as u32
                + 256 * native.cols[COL_VALUE_B_BASE + 3][row].0 as u32;
            let rs2_low = native.cols[COL_VALUE_C_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_C_BASE + 1][row].0 as u32;
            let rs2_high = native.cols[COL_VALUE_C_BASE + 2][row].0 as u32
                + 256 * native.cols[COL_VALUE_C_BASE + 3][row].0 as u32;
            let carry0 = native.cols[COL_CARRY_FLAG_BASE][row].0 as u32;
            let carry1 = native.cols[COL_CARRY_FLAG_BASE + 1][row].0 as u32;
            let expected_low = (rs1_low as i64 + rs2_low as i64 - 65536 * carry0 as i64) as u32;
            let expected_high = (rs1_high as i64 + rs2_high as i64 + carry0 as i64 - 65536 * carry1 as i64) as u32;
            let low_ok = rd_eff_low == expected_low;
            let high_ok = rd_eff_high == expected_high;
            println!("    ADD/ADDI: rd_eff=0x{:04X}{:04X} rs1=0x{:04X}{:04X} rs2=0x{:04X}{:04X} carry={carry0},{carry1} low={} high={}",
                rd_eff_high, rd_eff_low, rs1_high, rs1_low, rs2_high, rs2_low,
                if low_ok {"✓"} else {"✗"}, if high_ok {"✓"} else {"✗"});
        }
        if is_sub == 1 {
            let rd_eff_low = native.cols[COL_VALUE_A_EFF_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_A_EFF_BASE + 1][row].0 as u32;
            let rs1_low = native.cols[COL_VALUE_B_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_B_BASE + 1][row].0 as u32;
            let rs2_low = native.cols[COL_VALUE_C_BASE][row].0 as u32
                + 256 * native.cols[COL_VALUE_C_BASE + 1][row].0 as u32;
            let borrow0 = native.cols[COL_BORROW_FLAG_BASE][row].0 as u32;
            let expected_low = (rs1_low as i64 - rs2_low as i64 + 65536 * borrow0 as i64) as u32;
            let low_ok = rd_eff_low == expected_low;
            println!("    SUB: rd_eff_low=0x{rd_eff_low:04X} rs1_low=0x{rs1_low:04X} rs2_low=0x{rs2_low:04X} borrow0={borrow0} {}",
                if low_ok {"✓"} else {"✗"});
        }
        // 检查 Branch 约束
        let is_branch: u32 = (0..6).map(|i| native.cols[IS_BEQ + i][row].0 as u32).sum();
        if is_branch == 1 {
            let helper2_low = native.cols[COL_HELPER2_BASE][row].0 as u32
                + 256 * native.cols[COL_HELPER2_BASE + 1][row].0 as u32;
            let helper2_high = native.cols[COL_HELPER2_BASE + 2][row].0 as u32
                + 256 * native.cols[COL_HELPER2_BASE + 3][row].0 as u32;
            let _pc_plus_imm = (pc.wrapping_add(native.cols[COL_HELPER1_BASE][row].0 as u32
                | (native.cols[COL_HELPER1_BASE + 1][row].0 as u32) << 8
                | (native.cols[COL_HELPER1_BASE + 2][row].0 as u32) << 16
                | (native.cols[COL_HELPER1_BASE + 3][row].0 as u32) << 24)) as u32;
            let next_pc_low = next_pc & 0xFFFF;
            let next_pc_high = (next_pc >> 16) & 0xFFFF;
            println!("    Branch: taken={taken} pc=0x{pc:08X} next_pc=0x{next_pc:08X} helper2=0x{:04X}{:04X} pc+4=0x{:08X}",
                helper2_high, helper2_low, pc.wrapping_add(4));
            if taken == 1 {
                println!("      taken: next_pc should = helper2: {}", if next_pc_low == helper2_low && next_pc_high == helper2_high {"✓"} else {"✗"});
            } else {
                println!("      not-taken: next_pc should = pc+4: {}", if next_pc == pc.wrapping_add(4) {"✓"} else {"✗"});
            }
        }
    }
}

/// 返回列索引对应的人类可读名称（仅常用列）。
fn column_name(idx: usize) -> Option<&'static str> {
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    Some(match idx {
        x if x == COL_PC_BASE => "PC[0]",
        x if x == COL_PC_BASE + 1 => "PC[1]",
        x if x == COL_PC_BASE + 2 => "PC[2]",
        x if x == COL_PC_BASE + 3 => "PC[3]",
        x if x == COL_PC_NEXT_BASE => "PCNext[0]",
        x if x == COL_PC_NEXT_BASE + 1 => "PCNext[1]",
        x if x == COL_PC_NEXT_BASE + 2 => "PCNext[2]",
        x if x == COL_PC_NEXT_BASE + 3 => "PCNext[3]",
        x if x == COL_PC_NEXT_AUX_BASE => "PCNextAux[0]",
        x if x == COL_PC_NEXT_AUX_BASE + 1 => "PCNextAux[1]",
        x if x == COL_PC_NEXT_AUX_BASE + 2 => "PCNextAux[2]",
        x if x == COL_PC_NEXT_AUX_BASE + 3 => "PCNextAux[3]",
        x if x == COL_VALUE_A_EFF_BASE => "ValueAEff[0]",
        x if x == COL_VALUE_A_EFF_BASE + 1 => "ValueAEff[1]",
        x if x == COL_VALUE_A_EFF_BASE + 2 => "ValueAEff[2]",
        x if x == COL_VALUE_A_EFF_BASE + 3 => "ValueAEff[3]",
        x if x == COL_VALUE_B_BASE => "ValueB[0]",
        x if x == COL_VALUE_B_BASE + 1 => "ValueB[1]",
        x if x == COL_VALUE_B_BASE + 2 => "ValueB[2]",
        x if x == COL_VALUE_B_BASE + 3 => "ValueB[3]",
        x if x == COL_VALUE_C_BASE => "ValueC[0]",
        x if x == COL_VALUE_C_BASE + 1 => "ValueC[1]",
        x if x == COL_VALUE_C_BASE + 2 => "ValueC[2]",
        x if x == COL_VALUE_C_BASE + 3 => "ValueC[3]",
        x if x == COL_MEM_ADDR_BASE => "MemAddr[0]",
        x if x == COL_MEM_ADDR_BASE + 1 => "MemAddr[1]",
        x if x == COL_MEM_ADDR_BASE + 2 => "MemAddr[2]",
        x if x == COL_MEM_ADDR_BASE + 3 => "MemAddr[3]",
        x if x == COL_HELPER1_BASE => "Helper1[0]",
        x if x == COL_HELPER1_BASE + 1 => "Helper1[1]",
        x if x == COL_HELPER1_BASE + 2 => "Helper1[2]",
        x if x == COL_HELPER1_BASE + 3 => "Helper1[3]",
        x if x == COL_HELPER2_BASE => "Helper2[0]",
        x if x == COL_HELPER2_BASE + 1 => "Helper2[1]",
        x if x == COL_HELPER2_BASE + 2 => "Helper2[2]",
        x if x == COL_HELPER2_BASE + 3 => "Helper2[3]",
        x if x == COL_HELPER3_BASE => "Helper3[0]",
        x if x == COL_HELPER3_BASE + 1 => "Helper3[1]",
        x if x == COL_HELPER3_BASE + 2 => "Helper3[2]",
        x if x == COL_HELPER3_BASE + 3 => "Helper3[3]",
        x if x == COL_HELPER4_BASE => "Helper4[0]",
        x if x == COL_HELPER4_BASE + 1 => "Helper4[1]",
        x if x == COL_HELPER4_BASE + 2 => "Helper4[2]",
        x if x == COL_HELPER4_BASE + 3 => "Helper4[3]",
        x if x == COL_TAKEN => "Taken",
        x if x == COL_CARRY_FLAG_BASE => "Carry0",
        x if x == COL_CARRY_FLAG_BASE + 1 => "Carry1",
        x if x == COL_BORROW_FLAG_BASE => "Borrow0",
        x if x == COL_BORROW_FLAG_BASE + 1 => "Borrow1",
        x if x == COL_SYSCALL_ID => "SyscallId",
        // indicators
        x if x == IS_ADD => "IsAdd",
        x if x == IS_ADDI => "IsAddi",
        x if x == IS_SUB => "IsSub",
        x if x == IS_LUI => "IsLui",
        x if x == IS_AUIPC => "IsAuipc",
        x if x == IS_JAL => "IsJal",
        x if x == IS_JALR => "IsJalr",
        x if x == IS_BEQ => "IsBeq",
        x if x == IS_BNE => "IsBne",
        x if x == IS_BLT => "IsBlt",
        x if x == IS_BGE => "IsBge",
        x if x == IS_BLTU => "IsBltu",
        x if x == IS_BGEU => "IsBgeu",
        x if x == IS_LOAD => "IsLoad",
        x if x == IS_STORE => "IsStore",
        x if x == IS_ECALL => "IsEcall",
        x if x == IS_EBREAK => "IsEbreak",
        x if x == IS_FENCE => "IsFence",
        x if x == IS_SLT => "IsSlt",
        x if x == IS_SLTU => "IsSltu",
        x if x == IS_SLTI => "IsSlti",
        x if x == IS_SLTIU => "IsSltiu",
        x if x == IS_XOR => "IsXor",
        x if x == IS_XORI => "IsXori",
        x if x == IS_OR => "IsOr",
        x if x == IS_ORI => "IsOri",
        x if x == IS_AND => "IsAnd",
        x if x == IS_ANDI => "IsAndi",
        x if x == IS_SLL => "IsSll",
        x if x == IS_SLLI => "IsSlli",
        x if x == IS_SRL => "IsSrl",
        x if x == IS_SRLI => "IsSrli",
        x if x == IS_SRA => "IsSra",
        x if x == IS_SRAI => "IsSrai",
        x if x == IS_PADDING => "IsPadding",
        _ => return None,
    })
}

fn cpu_trace_pc(trace: &poker_zkvm::stwo_backend::trace_native::NativeTrace, row: usize) -> u32 {
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    trace.cols[COL_PC_BASE][row].0 as u32
        | (trace.cols[COL_PC_BASE + 1][row].0 as u32) << 8
        | (trace.cols[COL_PC_BASE + 2][row].0 as u32) << 16
        | (trace.cols[COL_PC_BASE + 3][row].0 as u32) << 24
}

fn cpu_trace_next_pc(trace: &poker_zkvm::stwo_backend::trace_native::NativeTrace, row: usize) -> u32 {
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    trace.cols[COL_PC_NEXT_BASE][row].0 as u32
        | (trace.cols[COL_PC_NEXT_BASE + 1][row].0 as u32) << 8
        | (trace.cols[COL_PC_NEXT_BASE + 2][row].0 as u32) << 16
        | (trace.cols[COL_PC_NEXT_BASE + 3][row].0 as u32) << 24
}

fn indicator_names<'a>() -> &'a [(&'a str, usize)] {
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    &[("ADD", IS_ADD), ("ADDI", IS_ADDI), ("SUB", IS_SUB),
      ("LUI", IS_LUI), ("AUIPC", IS_AUIPC),
      ("JAL", IS_JAL), ("JALR", IS_JALR),
      ("BEQ", IS_BEQ), ("BNE", IS_BNE),
      ("BLT", IS_BLT), ("BGE", IS_BGE),
      ("BLTU", IS_BLTU), ("BGEU", IS_BGEU),
      ("LOAD", IS_LOAD), ("STORE", IS_STORE),
      ("ECALL", IS_ECALL), ("EBREAK", IS_EBREAK),
      ("FENCE", IS_FENCE),
      ("SLT", IS_SLT), ("SLTU", IS_SLTU),
      ("SLTI", IS_SLTI), ("SLTIU", IS_SLTIU),
      ("XOR", IS_XOR), ("XORI", IS_XORI),
      ("OR", IS_OR), ("ORI", IS_ORI),
      ("AND", IS_AND), ("ANDI", IS_ANDI),
      ("SLL", IS_SLL), ("SLLI", IS_SLLI),
      ("SRL", IS_SRL), ("SRLI", IS_SRLI),
      ("SRA", IS_SRA), ("SRAI", IS_SRAI),
      ("PADDING", IS_PADDING),
    ]
}

/// 快速验证：仅 execute + prove_cpu_trace（单组件，不含 Memory lookup）
#[test]
#[ignore = "调试用：验证 execute + prove_cpu_trace 能否通过"]
fn test_texas_poker_execute_and_prove_cpu_only() {
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);
    let expected = texas_poker_full_hand_expected(&input);

    println!("执行 ELF...");
    let result = execute_elf(&elf, &input).expect("execute 失败");
    println!("trace 步数: {}", result.trace.len());
    println!("output: {:?} (期望: {expected})", result.output);

    assert_eq!(result.output.get(0).copied().unwrap_or(255), expected);

    // 打印前 20 步的诊断信息
    println!("\n=== 前 20 步诊断 ===");
    let mut prev_regs = *result.trace.initial_registers();
    for (i, step) in result.trace.iter().enumerate().take(20) {
        let insn_name = format!("{:?}", step.instruction);
        let pc = step.pc;
        let next_pc = if !step.registers.is_empty() {
            // 简单显示
            0
        } else { 0 };
        println!("  step {i}: pc=0x{pc:08X} insn={insn_name}");
        println!("    mem_access: {} entries", step.mem_access.len());
        for ma in &step.mem_access {
            println!("      addr=0x{:08X} op={:?} value=0x{:08X} size={}",
                ma.addr, ma.op, ma.value, ma.size);
        }
        // 显示前 5 个寄存器的变化
        for r in 0..5 {
            let prev = prev_regs[r];
            let cur = step.registers[r];
            if prev != cur {
                println!("    x{r}: 0x{prev:08X} → 0x{cur:08X}");
            }
        }
        prev_regs.copy_from_slice(&step.registers);
    }

    println!("\ntrace_to_native...");
    let cpu_trace = trace_to_native(&result.trace);
    println!("log_size: {}", cpu_trace.log_size);

    // 检查 NativeTrace 的前几行是否有异常
    use poker_zkvm::stwo_backend::column_layout_v2::*;
    println!("\n=== NativeTrace 前 5 行诊断 ===");
    for row in 0..5.min(cpu_trace.cols[0].len()) {
        let is_padding = cpu_trace.cols[IS_PADDING][row].0 as u32;
        let indicator = if is_padding == 1 { "PADDING" } else { "INSTR" };
        let pc = cpu_trace.cols[COL_PC_BASE][row].0 as u32
            | (cpu_trace.cols[COL_PC_BASE + 1][row].0 as u32) << 8
            | (cpu_trace.cols[COL_PC_BASE + 2][row].0 as u32) << 16
            | (cpu_trace.cols[COL_PC_BASE + 3][row].0 as u32) << 24;
        let next_pc = cpu_trace.cols[COL_PC_NEXT_BASE][row].0 as u32
            | (cpu_trace.cols[COL_PC_NEXT_BASE + 1][row].0 as u32) << 8
            | (cpu_trace.cols[COL_PC_NEXT_BASE + 2][row].0 as u32) << 16
            | (cpu_trace.cols[COL_PC_NEXT_BASE + 3][row].0 as u32) << 24;
        let taken = cpu_trace.cols[COL_TAKEN][row].0 as u32;
        // 打印所有 indicator
        let mut active_indicators = Vec::new();
        for (name, col_idx) in [
            ("ADD", IS_ADD), ("ADDI", IS_ADDI), ("SUB", IS_SUB),
            ("LUI", IS_LUI), ("AUIPC", IS_AUIPC),
            ("JAL", IS_JAL), ("JALR", IS_JALR),
            ("BEQ", IS_BEQ), ("BNE", IS_BNE),
            ("BLT", IS_BLT), ("BGE", IS_BGE),
            ("BLTU", IS_BLTU), ("BGEU", IS_BGEU),
            ("LOAD", IS_LOAD), ("STORE", IS_STORE),
            ("ECALL", IS_ECALL), ("EBREAK", IS_EBREAK),
            ("FENCE", IS_FENCE),
            ("SLT", IS_SLT), ("SLTU", IS_SLTU),
            ("SLTI", IS_SLTI), ("SLTIU", IS_SLTIU),
            ("XOR", IS_XOR), ("XORI", IS_XORI),
            ("OR", IS_OR), ("ORI", IS_ORI),
            ("AND", IS_AND), ("ANDI", IS_ANDI),
            ("SLL", IS_SLL), ("SLLI", IS_SLLI),
            ("SRL", IS_SRL), ("SRLI", IS_SRLI),
            ("SRA", IS_SRA), ("SRAI", IS_SRAI),
        ] {
            if cpu_trace.cols[col_idx][row].0 as u32 == 1 {
                active_indicators.push(name);
            }
        }
        println!("  row {row}: {indicator} pc=0x{pc:08X} next_pc=0x{next_pc:08X} taken={taken} indicators={:?}",
            active_indicators);
    }

    // 统计所有 indicator 的总和（应每行 = 1）
    println!("\n=== Indicator sum 检查（前 10 非padding 行） ===");
    let mut checked = 0;
    for row in 0..cpu_trace.cols[0].len() {
        if cpu_trace.cols[IS_PADDING][row].0 as u32 == 1 {
            continue;
        }
        let mut sum = 0u32;
        for i in 0..NUM_INSTRUCTION_CATEGORIES {
            sum += cpu_trace.cols[COL_IS_BASE + i][row].0 as u32;
        }
        if sum != 1 {
            println!("  row {row}: indicator sum = {sum}（应=1）⚠️");
        }
        checked += 1;
        if checked >= 10 {
            break;
        }
    }
    println!("  检查了 {checked} 行");

    println!("\nprove_cpu_trace...");
    let proof = prove_cpu_trace(&cpu_trace).expect("prove_cpu_trace 失败");
    println!("prove 成功！commitments: {}", proof.commitments.len());

    println!("verify_cpu_proof...");
    verify_cpu_proof(proof, cpu_trace.log_size).expect("verify_cpu_proof 失败");
    println!("verify 成功！");
}

/// 完整一手牌性能基准测试
#[test]
#[ignore = "性能基准测试，需手动运行: cargo test -- --ignored --nocapture"]
fn test_texas_poker_full_hand_benchmark() {
    println!("\n{}", "=".repeat(80));
    println!("Texas Poker 完整一手牌 — E2E 性能基准");
    println!("{}", "=".repeat(80));

    let scenarios: Vec<(&str, [u8; 5], [u8; 5])> = vec![
        // 场景 1: P1 顺子 vs P2 对子 — P1 胜
        ("P1-straight-vs-P2-pair", [14, 13, 12, 11, 10], [2, 2, 3, 4, 5]),
        // 场景 2: P2 顺子 vs P1 对子 — P2 胜
        ("P1-pair-vs-P2-straight", [2, 2, 3, 4, 5], [14, 13, 12, 11, 10]),
        // 场景 3: 平局
        ("tie-same-straight", [10, 9, 8, 7, 6], [10, 9, 8, 7, 6]),
        // 场景 4: 同牌型比最大值
        ("same-cat-higher-max", [14, 3, 5, 7, 9], [10, 3, 5, 7, 9]),
    ];

    let mut reports = Vec::new();

    for (name, p1, p2) in &scenarios {
        match run_full_hand_benchmark(name, *p1, *p2) {
            Ok(report) => {
                report.print();
                reports.push(report);
            }
            Err(e) => {
                eprintln!("场景 {name} 失败: {e}");
                panic!("场景 {name} 失败: {e}");
            }
        }
    }

    // 打印汇总
    PerfReport::print_csv_header();
    for r in &reports {
        r.print_csv();
    }

    // 汇总统计
    println!("\n=== 汇总统计 ===");
    let n = reports.len();
    let avg_execute: f64 = reports.iter().map(|r| r.execute_ms).sum::<f64>() / n as f64;
    let avg_prove: f64 = reports.iter().map(|r| r.prove_ms).sum::<f64>() / n as f64;
    let avg_verify: f64 = reports.iter().map(|r| r.verify_ms).sum::<f64>() / n as f64;
    let avg_proof_kb: f64 = reports.iter().map(|r| r.proof_kb).sum::<f64>() / n as f64;
    let avg_steps: f64 = reports.iter().map(|r| r.trace_steps as f64).sum::<f64>() / n as f64;

    println!("场景数:            {n}");
    println!("平均 trace 步数:   {avg_steps:.0}");
    println!("平均执行时间:      {avg_execute:.3} ms");
    println!("平均 prove 时间:   {avg_prove:.3} ms");
    println!("平均 verify 时间:  {avg_verify:.3} ms");
    println!("平均 proof 大小:   {avg_proof_kb:.2} KB");
    println!("\n所有场景的输出正确性: {}",
        if reports.iter().all(|r| r.output_correct) { "✓ 全部正确" } else { "✗ 有错误" });
    println!("所有场景的 proof 验证: {}",
        if reports.iter().all(|r| r.proof_verified) { "✓ 全部通过" } else { "✗ 有失败" });
}
