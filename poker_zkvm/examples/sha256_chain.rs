//! SHA-256 哈希链示例 — 计算 N 次连续 SHA-256 哈希（in-place）。
//!
//! 本文件是 host 可编译的算法文档，展示 ZKVM 中 SHA-256 哈希链电路的算法逻辑
//! 与对应的 RV32I 指令序列。不依赖 RISC-V target。
//!
//! # 运行
//!
//! ```bash
//! cargo run -p poker_zkvm --example sha256_chain
//! cargo run -p poker_zkvm --example sha256_chain -- 10
//! ```
//!
//! # RV32I 程序（while-loop 结构）
//!
//! 寄存器分配：`x20=0x2000`（数据缓冲区），`x4=counter`
//!
//! ```text
//! # Setup (6 条)
//! LUI  x20, 0x2        # x20 = 0x2000
//! ADDI x10, x20, 0     # a0 = 0x2000
//! ADDI x11, x0, 32     # a1 = 32
//! ADDI x17, x0, 1      # a7 = 1 (read_input)
//! ECALL                # read_input(0x2000, 32)
//! ADDI x4, x0, N       # counter = N
//! # Loop check (1 条)
//! BEQ  x4, x0, +32     # if counter==0 → skip to output (8 instr ahead)
//! # Loop body (6 条)
//! ADDI x10, x20, 0     # a0 = 0x2000 (input ptr)
//! ADDI x11, x0, 32     # a1 = 32 (input len)
//! ADDI x12, x20, 0     # a2 = 0x2000 (output ptr, in-place)
//! ADDI x17, x0, 4      # a7 = 4 (sha256)
//! ECALL                # sha256(0x2000, 32, 0x2000)
//! ADDI x4, x4, -1      # counter--
//! # Jump back (1 条)
//! BEQ  x0, x0, -28     # unconditional → loop check (7 instr back)
//! # Output (4 条)
//! ADDI x10, x20, 0     # a0 = 0x2000
//! ADDI x11, x0, 32     # a1 = 32
//! ADDI x17, x0, 2      # a7 = 2 (commit_output)
//! ECALL                # commit_output
//! ```
//!
//! # Trace 步数
//!
//! `6 + 8*N + 1 + 4 = 8N + 11`
//!
//! - N=0 → 11 步，N=10 → 91 步
//! - MVP batch_size=3：N=10 → 31 batches
//!
//! # Syscall ABI
//!
//! | a7 | SyscallId      | 行为                                  |
//! |----|------------------|---------------------------------------|
//! | 1  | ReadInput        | 从 input 区读取 `a1` 字节到 `a0`       |
//! | 2  | CommitOutput     | 提交 `a0` 起的 `a1` 字节作为 public io |
//! | 4  | Sha256           | 计算 SHA-256(`a0`, `a1`) 写入 `a2`     |

use sha2::{Digest, Sha256};

/// 计算 SHA-256 哈希链：`H^n(input)`（in-place，与 ZKVM 语义一致）。
///
/// - N=0 → 返回原 input
/// - N=1 → SHA-256(input)
/// - N=k → SHA-256(SHA-256(...(input)))（k 次）
fn sha256_chain_expected(input: &[u8], iterations: u32) -> [u8; 32] {
    let mut state: [u8; 32] = if input.len() == 32 {
        let mut s = [0u8; 32];
        s.copy_from_slice(input);
        s
    } else {
        // 首次：对任意长度 input 先做一次哈希到 32 字节
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&result);
        s
    };

    for _ in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(state);
        state.copy_from_slice(&hasher.finalize());
    }
    state
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iterations: u32 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    // 默认 input：32 字节零
    let input = [0u8; 32];
    let output = sha256_chain_expected(&input, iterations);

    println!("=== SHA-256 哈希链 ZKVM 示例 ===");
    println!("iterations = {iterations}");
    println!("input      = {}", hex_encode(&input));
    println!("output     = {}", hex_encode(&output));

    // 步数与 batch 估算
    let steps = 8 * iterations as usize + 11;
    let batches = steps.div_ceil(3);
    println!("trace 步数 = {steps}  (公式 8N+11)");
    println!("batches   = {batches}  (batch_size=3)");

    // 算法对照表
    println!("\n--- 算法对照表（input=32B 零）---");
    for &n in &[0u32, 1, 5, 10] {
        let h = sha256_chain_expected(&input, n);
        println!("H^{n:2}(0x00*32) = {}", hex_encode(&h));
    }

    println!("\n--- ZKVM 集成 ---");
    println!("ELF 构建器：tests/common/mod.rs::build_sha256_chain_elf");
    println!("E2E 测试  ：poker_zkvm/tests/e2e_sha256_chain.rs (5 项测试)");
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
