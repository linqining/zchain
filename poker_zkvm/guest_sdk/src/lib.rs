//! no_std SDK for poker_zkvm guest crates.
//!
//! 提供 syscall 包装、bump allocator、entry trampoline 和 BLS 类型。

#![no_std]
#![allow(clippy::missing_safety_doc)]

// extern crate alloc 并宏导出，使 vec! / format! 等宏在所有子模块可用。
#[macro_use]
extern crate alloc;

pub mod allocator;
pub mod bls;
pub mod entry;
pub mod game;
pub mod hash;
pub mod io;
pub mod prelude;
pub mod syscalls;

pub use prelude::*;
