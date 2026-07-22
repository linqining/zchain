//! Texas Poker ZKVM Guest — Phase 1 集成测试。
//!
//! 验证编译后的 RV32I ELF 能在 poker_zkvm 中加载、校验、执行。
//!
//! 运行前置：
//! ```bash
//! cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker
//! cargo +nightly-2026-04-15 build --release
//! ```
//!
//! 运行方式：
//! ```bash
//! cargo test -p poker_zkvm --features test-helpers --test texas_poker_guest_phase1 -- --nocapture
//! ```

#![cfg(feature = "test-helpers")]

use std::path::PathBuf;

use poker_zkvm::compiler::elf_validator::validate_elf;
use poker_zkvm::isa::executor::execute_elf;

/// 返回编译后的 guest ELF 路径。
///
/// guest crate 在 `poker_zkvm/guests/texas_poker/` 下独立 workspace，
/// release 编译产物位于其自己的 target 目录。
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

#[test]
fn test_phase1_guest_elf_exists() {
    let path = guest_elf_path();
    assert!(
        path.exists(),
        "guest ELF 不存在：{}. 请先编译 guest crate。",
        path.display()
    );
    let metadata = std::fs::metadata(&path).expect("读取 ELF metadata");
    println!("guest ELF 路径: {}", path.display());
    println!("guest ELF 大小: {} bytes", metadata.len());
    assert!(metadata.len() > 0, "ELF 文件为空");
    assert!(metadata.len() < 1024 * 1024, "ELF 文件超过 1MB（异常）");
}

#[test]
fn test_phase1_validate_elf_passes_11_checks() {
    let elf = read_guest_elf();
    let metadata = validate_elf(&elf).expect("ELF 应通过 11 项校验");

    println!("ELF entry: 0x{:08x}", metadata.entry);
    println!("ELF segments: {}", metadata.segments.len());
    assert!(metadata.entry > 0, "entry 不应为 0");
    assert!(
        metadata.text.is_some(),
        "应存在可执行段（PF_X）"
    );
    let text = metadata.text.as_ref().unwrap();
    println!(
        "text 段: vaddr=0x{:08x}, memsz={}, data.len()={}",
        text.vaddr,
        text.memsz,
        text.data.len()
    );
    assert!(text.memsz > 0, "text 段大小应 > 0");
    assert!(
        text.data.len() % 4 == 0,
        "text 段字节数应为 4 的倍数（RV32I 4 字节指令对齐）"
    );
}

#[test]
fn test_phase1_execute_returns_0x42_on_empty_input() {
    let elf = read_guest_elf();

    // guest entry.rs 约定输入格式: [4 字节 LE 长度 N][N 字节数据]
    // Phase 4.4: zkvm_main 对空 input 返回 [0x42]（health check 向后兼容）。
    // 传入 N=0（4 字节 LE 长度前缀 + 0 字节数据）。
    let input = vec![0u8; 4];

    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");

    println!("trace 步数: {}", result.trace.len());
    println!("output: {:?} ({} bytes)", result.output, result.output.len());
    println!("events: {}", result.events.len());
    println!("logs: {}", result.logs.len());

    assert_eq!(
        result.output,
        vec![0x42],
        "guest 对空输入应输出 [0x42]（health check），实际输出: {:?}",
        result.output
    );
}

#[test]
fn test_phase1_execute_with_completely_empty_input() {
    let elf = read_guest_elf();
    // 完全空输入（甚至连长度前缀都没有）
    let input: Vec<u8> = vec![];
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");
    // guest entry.rs 在 buf.len() < 4 时 input_len=0 → 空输入 → [0x42]
    assert_eq!(result.output, vec![0x42]);
}

#[test]
fn test_phase1_execute_invalid_borsh_input_fails() {
    // Phase 4.4: 验证 dispatch 路径在 ELF 中可达。
    // 传入非空但非法的 borsh 输入 → guest 反序列化失败 → 执行异常终止。
    // 可能的错误形态：
    // - `zkvm_panic`（panic_msg 调用，若 borsh 返回 Err）
    // - `uninitialized read`（若 garbage 字节被误读为长度/指针导致越界访问）
    // 两种都表明 guest 未产生有效输出，验证 dispatch 路径已接入。
    let elf = read_guest_elf();

    // 4 字节 LE 长度 = 16 + 16 字节垃圾数据（不是合法 ZkvmInput borsh）
    let mut input = vec![16u8, 0, 0, 0]; // LE 长度 = 16
    input.extend_from_slice(&[0xFFu8; 16]); // 垃圾 borsh

    let result = execute_elf(&elf, &input);

    assert!(
        result.is_err(),
        "非法 borsh 输入应导致 guest 执行失败，实际: {result:?}"
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    println!("非法输入错误（符合预期）: {msg}");
    // 接受 panic 或 uninitialized read —— 两者都表示 guest 未产生有效输出
    assert!(
        msg.contains("panic")
            || msg.contains("uninitialized")
            || msg.contains("UnsupportedInstruction")
            || msg.contains("zkvm_panic"),
        "错误应表明 guest 执行失败，实际: {msg}"
    );
}

#[test]
fn test_phase1_trace_steps_reasonable() {
    let elf = read_guest_elf();
    let input = vec![0u8; 4];
    let result = execute_elf(&elf, &input).expect("ELF 执行应成功");

    let steps = result.trace.len();
    println!("trace 步数: {steps}");

    // Phase 1 骨架步数主要来自：
    // 1. Rust no_std 启动 + panicking infrastructure 初始化
    // 2. entry.rs 中 vec![0u8; 64*1024] 分配 64KB 输入 buffer（含循环清零）
    // 3. read_input_raw syscall 写满 64KB buffer
    // 4. alloc crate 框架开销
    // 实测 ~49215 步，远低于 MAX_ZKVM_TRACE_STEPS = 1_048_576。
    // 上限 200000 给足余量，同时能捕获异常膨胀（如 release profile 失效）。
    assert!(
        steps < 200_000,
        "trace 步数 {steps} 过大，预期 < 200000（实测约 50000）"
    );
    assert!(steps > 0, "trace 步数不应为 0");
}
