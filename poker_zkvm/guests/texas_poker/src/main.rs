//! Texas Poker ZKVM Guest — binary entry point。
//!
//! 双模式编译：
//! - 默认（riscv32i-unknown-none-elf）：no_std + no_main，编译为 RV32I ELF
//! - std-test feature：std + 有 main，跑 host 单元测试
//!
//! # Phase 4.4：dispatch 接入
//!
//! `zkvm_main` 接收 `ZkvmInput`（borsh 序列化的 `table + context + selector + args`），
//! 调用 `dispatch::dispatch`，返回 `ZkvmOutput`（borsh 序列化的更新后 table + events）。
//!
//! 空 input 触发 Phase 1 health check（返回 `[0x42]`），用于验证 guest ELF 可执行性。

#![cfg_attr(not(feature = "std-test"), no_std)]
#![cfg_attr(not(feature = "std-test"), no_main)]

// std-test 模式引入 std（供测试用）
#[cfg(feature = "std-test")]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;

// 仅 riscv32i 模式注册 _start + panic_handler
#[cfg(not(feature = "std-test"))]
zkvm_guest_sdk::entry_point!();

use texas_poker_guest::io::{zkvm_main_logic, ZkvmErrorKind};

/// guest 主逻辑入口（riscv32i 模式由 entry_point 调用）。
///
/// # 输入约定
///
/// `input` 为 `ZkvmInput` 的 borsh 序列化字节（4 字节 LE 长度前缀已由
/// `guest_sdk::entry` 解析）。空 input 返回 `[0x42]`（Phase 1 health check）。
///
/// # 输出约定
///
/// 成功返回 `ZkvmOutput` 的 borsh 序列化字节（由 `commit_output` 写出）。
/// 失败返回 `Err(&'static str)`，guest 调用 `panic_msg` 终止。
#[no_mangle]
pub extern "Rust" fn zkvm_main(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    match zkvm_main_logic(input) {
        Ok(output) => Ok(output),
        // Phase 1 向后兼容：空输入 = health check，返回 [0x42]
        Err(ZkvmErrorKind::EmptyInput) => Ok(alloc::vec![0x42]),
        Err(e) => Err(e.as_static_str()),
    }
}

// std-test 模式需要一个 main（cargo test 对 bin crate 需要 main）
#[cfg(feature = "std-test")]
fn main() {}
