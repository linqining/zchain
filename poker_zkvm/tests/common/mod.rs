//! Phase 12 集成测试公共辅助 — 三个示例电路的 ELF 生成器。
//!
//! 由于 `riscv32i-unknown-none-elf` target 未安装，所有 ELF 通过内存字节构造生成，
//! 复用 `poker_zkvm::test_helpers` 中的 RV32I 编码器与 ELF32 构建器。
//!
//! 各测试文件（e2e_fibonacci / e2e_sha256_chain / e2e_poker_hand_eval / soundness_tests）
//! 仅使用本模块的部分函数，因此允许 dead_code。

#![allow(dead_code)]

use poker_zkvm::test_helpers::{add, addi, beq, build_elf32, ecall, encode_text, lb, lui, nop, sw};

// ===========================================================================
// Fibonacci 电路
// ===========================================================================

/// 构建 Fibonacci(N) 计算电路的 ELF。
///
/// # RV32I 程序（while-loop 结构，counter 在循环顶部检查）
///
/// ```text
/// # 寄存器分配：x1=a, x2=b, x3=temp, x4=counter
/// # Init (3 条)
/// ADDI x1, x0, 0       # a = fib(0) = 0
/// ADDI x2, x0, 1       # b = fib(1) = 1
/// ADDI x4, x0, N       # counter = N
/// # Loop check (1 条)
/// BEQ  x4, x0, +24     # if counter==0 → skip to output (6 instr ahead = +24)
/// # Loop body (5 条)
/// ADD  x3, x1, x2      # temp = a + b
/// ADDI x1, x2, 0       # a = b
/// ADDI x2, x3, 0       # b = temp
/// ADDI x4, x4, -1      # counter--
/// BEQ  x0, x0, -20     # unconditional jump back to loop check (5 instr back = -20)
/// # Output (5 条)
/// SW   x1, 0(x0)       # store a = fib(N) to address 0
/// ADDI x10, x0, 0      # a0 = 0 (output ptr)
/// ADDI x11, x0, 4      # a1 = 4 (output len)
/// ADDI x17, x0, 2      # a7 = 2 (commit_output)
/// ECALL                # commit_output
/// ```
///
/// # Trace 步数
///
/// `3 + 6*N + 1 + 5 = 6N + 9`
///
/// N=0 → 9 步，N=100 → 609 步。batch_size=3 → 3/203 batches。
///
/// # 参数
/// - `n` — Fibonacci 迭代次数（须 ≤ 2047，受 ADDI 12 位立即数限制）
pub fn build_fibonacci_elf(n: u32) -> Vec<u8> {
    assert!(
        n <= 2047,
        "build_fibonacci_elf: n 须 ≤ 2047（ADDI 12 位立即数限制）"
    );

    let text: Vec<u32> = vec![
        // Init (instr 0-2)
        addi(1, 0, 0),        // x1 = a = 0
        addi(2, 0, 1),        // x2 = b = 1
        addi(4, 0, n as i32), // x4 = counter = N
        // Loop check (instr 3): BEQ x4, x0, +24 → jump to instr 9 (6 ahead)
        beq(4, 0, 24),
        // Loop body (instr 4-7)
        add(3, 1, 2),   // x3 = temp = a + b
        addi(1, 2, 0),  // x1 = a = b
        addi(2, 3, 0),  // x2 = b = temp
        addi(4, 4, -1), // x4 = counter--
        // Unconditional jump back (instr 8): BEQ x0, x0, -20 → jump to instr 3 (5 back)
        beq(0, 0, -20),
        // Output (instr 9-13)
        sw(1, 0, 0),    // SW x1, 0(x0) — store a = fib(N) to addr 0
        addi(10, 0, 0), // a0 = 0
        addi(11, 0, 4), // a1 = 4
        addi(17, 0, 2), // a7 = 2 (commit_output)
        ecall(),        // ECALL
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

/// 计算 Fibonacci(N) mod 2^32（与 ZKVM 32 位寄存器语义一致）。
pub fn fibonacci_expected(n: u32) -> u32 {
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let temp = a.wrapping_add(b);
        a = b;
        b = temp;
    }
    a
}

// ===========================================================================
// SHA-256 哈希链电路
// ===========================================================================

/// 构建 SHA-256 哈希链电路的 ELF。
///
/// # RV32I 程序（while-loop 结构，counter 在循环顶部检查）
///
/// ```text
/// # 寄存器分配：x20=0x2000 (数据缓冲区), x4=counter
/// # Setup (6 条)
/// LUI  x20, 0x2        # x20 = 0x2000
/// ADDI x10, x20, 0     # a0 = 0x2000
/// ADDI x11, x0, 32     # a1 = 32
/// ADDI x17, x0, 1      # a7 = 1 (read_input)
/// ECALL                # read_input(0x2000, 32)
/// ADDI x4, x0, N       # counter = N
/// # Loop check (1 条)
/// BEQ  x4, x0, +32     # if counter==0 → skip to output (8 instr ahead = +32)
/// # Loop body (6 条)
/// ADDI x10, x20, 0     # a0 = 0x2000 (input ptr)
/// ADDI x11, x0, 32     # a1 = 32 (input len)
/// ADDI x12, x20, 0     # a2 = 0x2000 (output ptr, in-place)
/// ADDI x17, x0, 4      # a7 = 4 (sha256)
/// ECALL                # sha256(0x2000, 32, 0x2000)
/// ADDI x4, x4, -1      # counter--
/// # Jump back (1 条)
/// BEQ  x0, x0, -28     # unconditional jump back to loop check (7 instr back = -28)
/// # Output (4 条)
/// ADDI x10, x20, 0     # a0 = 0x2000
/// ADDI x11, x0, 32     # a1 = 32
/// ADDI x17, x0, 2      # a7 = 2 (commit_output)
/// ECALL                # commit_output
/// ```
///
/// # Trace 步数
///
/// `6 + 8*N + 1 + 4 = 8N + 11`
///
/// N=0 → 11 步，N=10 → 91 步。batch_size=3 → 4/31 batches。
///
/// # 参数
/// - `iterations` — SHA-256 哈希迭代次数（须 ≤ 2047）
pub fn build_sha256_chain_elf(iterations: u32) -> Vec<u8> {
    assert!(
        iterations <= 2047,
        "build_sha256_chain_elf: iterations 须 ≤ 2047"
    );

    let text: Vec<u32> = vec![
        // Setup (instr 0-5)
        lui(20, 0x2),                  // x20 = 0x2000
        addi(10, 20, 0),               // a0 = 0x2000
        addi(11, 0, 32),               // a1 = 32
        addi(17, 0, 1),                // a7 = 1 (read_input)
        ecall(),                       // read_input
        addi(4, 0, iterations as i32), // counter = N
        // Loop check (instr 6): BEQ x4, x0, +32 → jump to instr 14 (8 ahead = output section)
        beq(4, 0, 32),
        // Loop body (instr 7-12)
        addi(10, 20, 0), // a0 = 0x2000
        addi(11, 0, 32), // a1 = 32
        addi(12, 20, 0), // a2 = 0x2000 (in-place)
        addi(17, 0, 4),  // a7 = 4 (sha256)
        ecall(),         // sha256
        addi(4, 4, -1),  // counter--
        // Unconditional jump back (instr 13): BEQ x0, x0, -28 → jump to instr 6 (7 back)
        beq(0, 0, -28),
        // Output (instr 14-17)
        addi(10, 20, 0), // a0 = 0x2000
        addi(11, 0, 32), // a1 = 32
        addi(17, 0, 2),  // a7 = 2 (commit_output)
        ecall(),         // commit_output
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

// ===========================================================================
// 扑克牌型评估电路（简化版）
// ===========================================================================

/// 构建扑克牌型评估电路的 ELF（简化版 — 计算牌面值之和）。
///
/// # RV32I 程序
///
/// ```text
/// # 寄存器分配：x20=0x2000, x1-x5=5张牌, x6=sum
/// # Setup (5 条)
/// LUI  x20, 0x2        # x20 = 0x2000
/// ADDI x10, x20, 0     # a0 = 0x2000
/// ADDI x11, x0, 5      # a1 = 5 (5 张牌)
/// ADDI x17, x0, 1      # a7 = 1 (read_input)
/// ECALL                # read_input(0x2000, 5)
/// # Load & Sum (9 条)
/// LB   x1, 0(x20)      # card1
/// LB   x2, 1(x20)      # card2
/// LB   x3, 2(x20)      # card3
/// LB   x4, 3(x20)      # card4
/// LB   x5, 4(x20)      # card5
/// ADD  x6, x1, x2      # sum = card1 + card2
/// ADD  x6, x6, x3      # sum += card3
/// ADD  x6, x6, x4      # sum += card4
/// ADD  x6, x6, x5      # sum += card5
/// # Output (5 条)
/// SW   x6, 0(x0)       # store sum to addr 0
/// ADDI x10, x0, 0      # a0 = 0
/// ADDI x11, x0, 4      # a1 = 4
/// ADDI x17, x0, 2      # a7 = 2 (commit_output)
/// ECALL                # commit_output
/// ```
///
/// # Trace 步数
///
/// 19 步。batch_size=3 → 7 batches。
///
/// # 输入
///
/// 5 字节，每字节代表一张牌的面值（1-13）。超过 127 会因 LB 符号扩展变为负数。
pub fn build_poker_hand_eval_elf() -> Vec<u8> {
    let text: Vec<u32> = vec![
        // Setup
        lui(20, 0x2),    // x20 = 0x2000
        addi(10, 20, 0), // a0 = 0x2000
        addi(11, 0, 5),  // a1 = 5
        addi(17, 0, 1),  // a7 = 1 (read_input)
        ecall(),         // read_input
        // Load 5 cards
        lb(1, 20, 0), // x1 = card1
        lb(2, 20, 1), // x2 = card2
        lb(3, 20, 2), // x3 = card3
        lb(4, 20, 3), // x4 = card4
        lb(5, 20, 4), // x5 = card5
        // Sum
        add(6, 1, 2), // x6 = card1 + card2
        add(6, 6, 3), // x6 += card3
        add(6, 6, 4), // x6 += card4
        add(6, 6, 5), // x6 += card5
        // Output
        sw(6, 0, 0),    // SW x6, 0(x0) — store sum to addr 0
        addi(10, 0, 0), // a0 = 0
        addi(11, 0, 4), // a1 = 4
        addi(17, 0, 2), // a7 = 2 (commit_output)
        ecall(),        // ECALL
    ];

    let text_bytes = encode_text(&text);
    build_elf32(0x1000, 0x1000, &text_bytes)
}

// ===========================================================================
// 最小合法 ELF（供 soundness 测试使用）
// ===========================================================================

/// 构建最小合法 ELF（3 NOP + commit_output + ECALL，5 条指令）。
///
/// 供 soundness 测试作为篡改起点。
pub fn build_minimal_valid_elf() -> Vec<u8> {
    let text = encode_text(&[
        nop(),
        nop(),
        nop(),
        addi(17, 0, 2), // a7 = 2 (commit_output)
        ecall(),
    ]);
    build_elf32(0x1000, 0x1000, &text)
}

/// 构建最小合法 ELF，返回 text 段在文件中的偏移量（供注入篡改指令使用）。
pub fn build_minimal_valid_elf_with_text_offset() -> (Vec<u8>, usize) {
    let text = encode_text(&[nop(), nop(), nop(), addi(17, 0, 2), ecall()]);
    let text_offset = 84; // 52 (ELF header) + 32 (prog header)
    let elf = build_elf32(0x1000, 0x1000, &text);
    (elf, text_offset)
}
