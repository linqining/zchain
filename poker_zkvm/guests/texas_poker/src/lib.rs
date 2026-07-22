//! Texas Poker ZKVM Guest — library crate。
//!
//! 双模式编译：
//! - 默认（riscv32i-unknown-none-elf）：`no_std`，编译为 RV32I ELF
//! - `std-test` feature：`std`，供 host 端测试作为 dev-dependency 引入，
//!   直接构造 `ZkvmInput` / `ZkvmOutput` / `*Args` 等类型（不需手动拼 borsh bytes）。
//!
//! # 模块结构
//!
//! 所有子模块 `pub` 暴露，使 host 端 E2E 测试可访问完整的类型层级：
//! - `io`：`ZkvmInput` / `ZkvmOutput` / `zkvm_main_logic`
//! - `dispatch`：`DispatchContext` / `selectors` / 18 个 `*Args` 结构体
//! - `types`：`TexasPokerTable` / `Seat` / `DeckState` / `ShuffleState` 等
//! - `events`：`TexasPokerEvent` 枚举
//! - `state_machine`：状态转换逻辑
//! - `card` / `hand_evaluator` / `betting` / `side_pot`：纯逻辑模块
//! - `constants` / `blake2b` / `utils`：辅助模块

#![cfg_attr(not(feature = "std-test"), no_std)]

// std-test 模式引入 std（供测试用）
#[cfg(feature = "std-test")]
extern crate std;

#[macro_use]
extern crate alloc;

pub mod betting;
pub mod blake2b;
pub mod card;
pub mod constants;
pub mod dispatch;
pub mod events;
pub mod hand_evaluator;
pub mod io;
pub mod side_pot;
pub mod state_machine;
pub mod types;
pub mod utils;

// 重导出 BLS crypto 类型，使 host 端 E2E 测试可直接构造 G1Point/Scalar/ElGamalCiphertext
// （JoinTableArgs.pk / CreateTableArgs 等字段需要这些类型）。
// 在 std-test 模式下 zkvm_guest_sdk::bls 的 syscall 函数是 unreachable!() stub，
// 但类型本身（字节数组 newtype）可用，不会触发 panic。
pub use zkvm_guest_sdk::bls::{ElGamalCiphertext, G1Point, Scalar};
