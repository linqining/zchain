//! Phase 2.2 — texas_poker 完整一手牌流程 E2E 执行测试。
//!
//! 验证 [`build_texas_poker_full_hand_elf`] 在 zkvm 中的端到端执行行为：
//! 1. ELF 通过 `validate_elf` 校验
//! 2. `execute_elf` 完成无 panic，trace 步数在预期区间
//! 3. RV32I 程序计算结果与 host 参考实现 [`texas_poker_full_hand_expected`] 一致
//!
//! ## 测试矩阵
//!
//! | 用例 | P1 | P2 | 期望 winner |
//! |------|----|----|-------------|
//! | p1_wins | A K Q J 10 (straight) | 2 2 3 4 5 (pair) | 1 |
//! | p2_wins | 2 2 3 4 5 (pair) | A K Q J 10 (straight) | 2 |
//! | tie | 10 9 8 7 6 (straight) | 10 9 8 7 6 (straight) | 0 |
//! | same_cat_higher_max | 14 3 5 7 9 (highcard, max=14) | 10 3 5 7 9 (highcard, max=10) | 1 |
//!
//! ## 关键设计
//!
//! - **不调用 `prove()`**：prove 涉及 CCS 编译 + Hypernova 折叠，耗时较长；
//!   本测试专注于"ELF 执行正确性"，prove+verify 留待 Phase 4.4 端到端测试。
//! - **直接 `execute_elf`**：执行后检查 `result.output[0]` 与 `texas_poker_full_hand_expected(&input)` 一致。
//! - **trace 步数检查**：220 条指令 → 约 280-450 trace 步（含 syscall 分派开销）。

#![allow(dead_code)]

use poker_zkvm::compiler::elf_validator::validate_elf;
use poker_zkvm::isa::executor::execute_elf;
use poker_zkvm::test_helpers::{
    build_texas_poker_full_hand_elf, make_full_hand_input, texas_poker_full_hand_expected,
};

// ===========================================================================
// 1. ELF 校验测试
// ===========================================================================

#[test]
fn test_full_hand_elf_loads() {
    let elf = build_texas_poker_full_hand_elf();
    // validate_elf 应成功，返回 ElfMetadata
    let metadata = validate_elf(&elf).expect("ELF 校验应通过");
    // 校验入口地址（build_elf32 设置 entry=0x1000）
    assert_eq!(metadata.entry, 0x1000, "ELF entry 应为 0x1000");
}

// ===========================================================================
// 2. ELF 执行测试
// ===========================================================================

#[test]
fn test_full_hand_elf_executes() {
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    // 输出长度 = 1 字节（winner）
    assert_eq!(result.output.len(), 1, "输出应为 1 字节 winner");
    // 不应为空
    assert!(!result.trace.is_empty(), "trace 不应为空");
}

// ===========================================================================
// 3. P1 胜用例
// ===========================================================================

#[test]
fn test_full_hand_p1_wins() {
    // P1 = A K Q J 10 → straight (category=5, max=14)
    // P2 = 2 2 3 4 5 → pair of 2s (category=2, max=5)
    let p1 = [14u8, 13, 12, 11, 10];
    let p2 = [2u8, 2, 3, 4, 5];
    let input = make_full_hand_input(p1, p2);
    let expected = texas_poker_full_hand_expected(&input);
    assert_eq!(expected, 1, "host 参考实现应判定 P1 胜");

    let elf = build_texas_poker_full_hand_elf();
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    assert_eq!(
        result.output.len(),
        1,
        "输出应为 1 字节（commit_output(0, 1)）"
    );
    assert_eq!(
        result.output[0], 1,
        "RV32I 程序应判定 P1 胜 (output[0]=1)"
    );
}

// ===========================================================================
// 4. P2 胜用例
// ===========================================================================

#[test]
fn test_full_hand_p2_wins() {
    // P1 = 2 2 3 4 5 → pair
    // P2 = 14 13 12 11 10 → straight
    let p1 = [2u8, 2, 3, 4, 5];
    let p2 = [14u8, 13, 12, 11, 10];
    let input = make_full_hand_input(p1, p2);
    let expected = texas_poker_full_hand_expected(&input);
    assert_eq!(expected, 2, "host 参考实现应判定 P2 胜");

    let elf = build_texas_poker_full_hand_elf();
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    assert_eq!(result.output.len(), 1, "输出应为 1 字节");
    assert_eq!(
        result.output[0], 2,
        "RV32I 程序应判定 P2 胜 (output[0]=2)"
    );
}

// ===========================================================================
// 5. 平局用例
// ===========================================================================

#[test]
fn test_full_hand_tie() {
    // 两方相同牌型 → 平局
    let p1 = [10u8, 9, 8, 7, 6]; // straight, max=10
    let p2 = [10u8, 9, 8, 7, 6]; // straight, max=10
    let input = make_full_hand_input(p1, p2);
    let expected = texas_poker_full_hand_expected(&input);
    assert_eq!(expected, 0, "host 参考实现应判定平局");

    let elf = build_texas_poker_full_hand_elf();
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    assert_eq!(result.output.len(), 1, "输出应为 1 字节");
    assert_eq!(
        result.output[0], 0,
        "RV32I 程序应判定平局 (output[0]=0)"
    );
}

// ===========================================================================
// 6. 同类高 max 用例（验证 Compare 阶段 max_diff 分支）
// ===========================================================================

#[test]
fn test_full_hand_same_cat_higher_max() {
    // 两方都是 highcard (category=0)，比 max
    // P1 max = 14, P2 max = 10 → P1 胜
    let p1 = [14u8, 3, 5, 7, 9];
    let p2 = [10u8, 3, 5, 7, 9];
    let input = make_full_hand_input(p1, p2);
    let expected = texas_poker_full_hand_expected(&input);
    assert_eq!(expected, 1, "host 参考实现应判定 P1 max 更高胜");

    let elf = build_texas_poker_full_hand_elf();
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    assert_eq!(result.output.len(), 1, "输出应为 1 字节");
    assert_eq!(
        result.output[0], 1,
        "RV32I 程序应判定 P1 max 更高胜 (output[0]=1)"
    );
}

// ===========================================================================
// 7. trace 长度检查
// ===========================================================================

#[test]
fn test_full_hand_trace_length() {
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");

    // 220 条指令，但 BNE/BEQ 分支跳过的指令不计入 trace 步数。
    // 实测约 173 步（max/min 更新有大量分支跳过：当 max >= xN 时跳过 ADDI）。
    // 区间 [150, 400] 覆盖正常执行范围，超出则提示异常。
    let steps = result.trace.len();
    assert!(
        steps >= 150,
        "trace 步数 {steps} 过少，预期 >= 150（含 syscall 分派开销）"
    );
    assert!(
        steps <= 400,
        "trace 步数 {steps} 过多，预期 <= 400（含 syscall 分派开销）"
    );
    // 打印实际步数（cargo test -- --nocapture 可见）
    println!("texas_poker_full_hand trace steps = {steps}");
}
