//! Fibonacci 电路示例 — 计算第 N 个 Fibonacci 数（mod 2^32）。
//!
//! 本文件是 host 可编译的算法文档，展示 ZKVM 中 Fibonacci 计算电路的算法逻辑
//! 与对应的 RV32I 指令序列。不依赖 RISC-V target。
//!
//! # 运行
//!
//! ```bash
//! cargo run -p poker_zkvm --example fibonacci
//! cargo run -p poker_zkvm --example fibonacci -- 100
//! ```
//!
//! # RV32I 程序（while-loop 结构）
//!
//! 寄存器分配：`x1=a, x2=b, x3=temp, x4=counter`
//!
//! ```text
//! # Init (3 条)
//! ADDI x1, x0, 0       # a = fib(0) = 0
//! ADDI x2, x0, 1       # b = fib(1) = 1
//! ADDI x4, x0, N       # counter = N
//! # Loop check (1 条)
//! BEQ  x4, x0, +24     # if counter==0 → skip to output (6 instr ahead)
//! # Loop body (4 条)
//! ADD  x3, x1, x2      # temp = a + b
//! ADDI x1, x2, 0       # a = b
//! ADDI x2, x3, 0       # b = temp
//! ADDI x4, x4, -1      # counter--
//! # Jump back (1 条)
//! BEQ  x0, x0, -20     # unconditional → loop check (5 instr back)
//! # Output (5 条)
//! SW   x1, 0(x0)       # store a = fib(N) to address 0
//! ADDI x10, x0, 0      # a0 = 0 (output ptr)
//! ADDI x11, x0, 4      # a1 = 4 (output len)
//! ADDI x17, x0, 2      # a7 = 2 (commit_output)
//! ECALL                # commit_output
//! ```
//!
//! # Trace 步数
//!
//! `3 + 6*N + 1 + 5 = 6N + 9`（含 jump-back 与 loop-check 各 1 步/轮）
//!
//! - N=0 → 9 步，N=100 → 609 步
//! - MVP batch_size=3：N=0 → 3 batches，N=100 → 203 batches

/// 计算 Fibonacci(N) mod 2^32（与 ZKVM 32 位寄存器语义一致）。
///
/// 迭代 N 次后 `a` 即为 fib(N)：
/// - fib(0) = 0, fib(1) = 1, fib(2) = 1, fib(10) = 55, fib(100) = 3314859971
fn fibonacci_expected(n: u32) -> u32 {
    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let temp = a.wrapping_add(b);
        a = b;
        b = temp;
    }
    a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: u32 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let result = fibonacci_expected(n);
    println!("=== Fibonacci ZKVM 示例 ===");
    println!("N         = {n}");
    println!("fib(N)    = {result} (mod 2^32)");

    // 步数与 batch 估算（MVP batch_size=3）
    let steps = 6 * n as usize + 9;
    let batches = steps.div_ceil(3);
    println!("trace 步数 = {steps}  (公式 6N+9)");
    println!("batches   = {batches}  (batch_size=3)");

    // 示例输出
    println!("\n--- 算法对照表 ---");
    for &k in &[0u32, 1, 2, 5, 10, 50, 100] {
        println!("fib({k:3}) = {0}", fibonacci_expected(k));
    }

    println!("\n--- ZKVM 集成 ---");
    println!("ELF 构建器：poker_zkvm::test_helpers + tests/common/mod.rs::build_fibonacci_elf");
    println!("E2E 测试  ：poker_zkvm/tests/e2e_fibonacci.rs (7 项测试)");
}
