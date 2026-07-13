//! 扑克牌型评估示例 — 计算 5 张牌面值之和（简化版）。
//!
//! 本文件是 host 可编译的算法文档，展示 ZKVM 中扑克牌型评估电路的算法逻辑
//! 与对应的 RV32I 指令序列。不依赖 RISC-V target。
//!
//! # 运行
//!
//! ```bash
//! cargo run -p poker_zkvm --example poker_hand_eval
//! cargo run -p poker_zkvm --example poker_hand_eval -- 2 7 11 1 13
//! ```
//!
//! # RV32I 程序
//!
//! 寄存器分配：`x20=0x2000`（数据缓冲区），`x1-x5=5张牌`，`x6=sum`
//!
//! ```text
//! # Setup (5 条)
//! LUI  x20, 0x2        # x20 = 0x2000
//! ADDI x10, x20, 0     # a0 = 0x2000
//! ADDI x11, x0, 5      # a1 = 5 (5 张牌)
//! ADDI x17, x0, 1      # a7 = 1 (read_input)
//! ECALL                # read_input(0x2000, 5)
//! # Load & Sum (9 条)
//! LB   x1, 0(x20)      # card1
//! LB   x2, 1(x20)      # card2
//! LB   x3, 2(x20)      # card3
//! LB   x4, 3(x20)      # card4
//! LB   x5, 4(x20)      # card5
//! ADD  x6, x1, x2      # sum = card1 + card2
//! ADD  x6, x6, x3      # sum += card3
//! ADD  x6, x6, x4      # sum += card4
//! ADD  x6, x6, x5      # sum += card5
//! # Output (5 条)
//! SW   x6, 0(x0)       # store sum to addr 0
//! ADDI x10, x0, 0      # a0 = 0
//! ADDI x11, x0, 4      # a1 = 4
//! ADDI x17, x0, 2      # a7 = 2 (commit_output)
//! ECALL                # commit_output
//! ```
//!
//! # Trace 步数
//!
//! 19 步（固定）。MVP batch_size=3 → 7 batches。
//!
//! # 输入
//!
//! 5 字节，每字节代表一张牌的面值（1-13）。超过 127 会因 `LB` 符号扩展变为负数。

/// 计算扑克牌面值之和（与 ZKVM 32 位寄存器语义一致）。
///
/// 输入 5 字节牌面值，返回累加和。`LB` 符号扩展：≥128 的字节视为负数。
fn poker_hand_eval_expected(cards: &[u8; 5]) -> u32 {
    let sum_i32: i32 = cards
        .iter()
        .map(|&c| c as i8 as i32) // 模拟 LB 符号扩展
        .sum();
    sum_i32 as u32
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let cards: [u8; 5] = if args.len() >= 6 {
        let mut c = [0u8; 5];
        for i in 0..5 {
            c[i] = args[i + 1].parse().unwrap_or(0);
        }
        c
    } else {
        [2, 7, 11, 1, 13] // 默认：A, 7, J, A, K → sum=34
    };

    let sum = poker_hand_eval_expected(&cards);
    println!("=== 扑克牌型评估 ZKVM 示例 ===");
    println!("cards     = {:?}", cards);
    println!("sum       = {sum}");

    // 步数与 batch 估算（固定 19 步）
    let steps = 19usize;
    let batches = steps.div_ceil(3);
    println!("trace 步数 = {steps}  (固定)");
    println!("batches   = {batches}  (batch_size=3)");

    // 算法对照表
    println!("\n--- 算法对照表 ---");
    for (label, hand) in &[
        ("Aces", [1u8, 1, 1, 1, 1]),
        ("Mixed", [2u8, 7, 11, 1, 13]),
        ("HighCards", [10u8, 11, 12, 13, 1]),
        ("AllKings", [13u8, 13, 13, 13, 13]),
        ("MaxSafe", [127u8, 127, 127, 127, 127]),
    ] {
        println!(
            "{label:10} {:?} → sum = {}",
            hand,
            poker_hand_eval_expected(hand)
        );
    }

    println!("\n--- 注意 ---");
    println!("LB 符号扩展：牌面值 ≥ 128 会被视为负数。");
    println!("完整牌型评估（同花/顺子/葫芦等）需更复杂电路，留待 Phase 12+ 实现。");

    println!("\n--- ZKVM 集成 ---");
    println!("ELF 构建器：tests/common/mod.rs::build_poker_hand_eval_elf");
    println!("E2E 测试  ：poker_zkvm/tests/e2e_poker_hand_eval.rs (5 项测试)");
}
