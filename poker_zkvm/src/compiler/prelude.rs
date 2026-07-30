//! ZKVM prelude 模块 — 为 no_std 用户代码提供基础类型与宏（spec L176-179）。
//!
//! re-export `alloc` 核心类型（[`Vec`] / [`Box`] / [`String`] / [`format!`]），
//! 定义 [`entry!`] / [`test!`] 宏标记用户入口与测试函数。
//!
//! ## 使用示例
//!
//! ```ignore
//! #![no_std]
//! use zkvm::prelude::*;
//!
//! #[zkvm::entry]
//! fn main(input: &[u8]) -> Result<Vec<u8>, zkvm::Error> {
//!     let mut output = Vec::new();
//!     output.extend_from_slice(input);
//!     Ok(output)
//! }
//! ```

// ===== alloc 类型 re-export =====

/// 堆分配的向量（re-export from `alloc`）。
pub use alloc::boxed::Box;
/// `format!` 宏（re-export from `alloc`）。
pub use alloc::format;
/// 堆分配的字符串（re-export from `alloc`）。
pub use alloc::string::String;
/// `vec!` 宏（re-export from `alloc`）。
pub use alloc::vec;
/// 堆分配的向量（re-export from `alloc`）。
pub use alloc::vec::Vec;

// ===== 入口 / 测试标记宏 =====

/// 标记用户入口函数（spec L172-174）。
///
/// 被标记的函数签名应为 `fn main(input: &[u8]) -> Result<Vec<u8>, _>`。
/// `compile_crate` 编译时生成 `_start` trampoline：
/// 1. `zkvm_read_input` syscall 读取输入
/// 2. 调用被标记的 `main`
/// 3. `Ok` → `zkvm_commit_output` 提交输出
/// 4. `Err` / panic → `zkvm_panic` syscall
///
/// 当前为 pass-through（标记后原样输出），实际 trampoline 生成在
/// [`compile_crate`](super::compile_crate) 中通过源码分析处理。
/// 未来版本可替换为过程宏自动生成 trampoline。
#[macro_export]
macro_rules! entry {
    ($item:item) => {
        $item
    };
}

/// 标记 ZKVM 测试函数（spec L72, SubTask 2.3.3）。
///
/// `cargo zkvm test` 子命令扫描源码中 `#[zkvm::test]` 标记的函数，
/// 自动执行 compile → run → prove → verify 流程。
///
/// 当前为 pass-through，供 `cargo zkvm test` 源码扫描识别。
#[macro_export]
macro_rules! test {
    ($item:item) => {
        $item
    };
}

// 将宏 re-export 到 prelude 路径
pub use crate::entry;
pub use crate::test;

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_reexports_vec() {
        let v: Vec<u8> = vec![1, 2, 3];
        assert_eq!(v.len(), 3);
        let empty: Vec<u8> = Vec::new();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_prelude_reexports_string() {
        let s: String = String::from("hello");
        assert_eq!(s, "hello");
        let formatted: String = format!("value = {}", 42);
        assert_eq!(formatted, "value = 42");
    }

    #[test]
    fn test_prelude_reexports_box() {
        let b: Box<u32> = Box::new(42);
        assert_eq!(*b, 42);
    }

    #[test]
    fn test_entry_macro_pass_through() {
        entry! {
            fn my_entry_fn() -> u32 {
                42
            }
        }
        assert_eq!(my_entry_fn(), 42);
    }

    #[test]
    fn test_entry_macro_preserves_fn_signature() {
        entry! {
            fn entry_with_args(a: u32, b: u32) -> u32 {
                a + b
            }
        }
        assert_eq!(entry_with_args(3, 4), 7);
    }

    #[test]
    fn test_test_macro_pass_through() {
        test! {
            fn my_zkvm_test_fn() -> bool {
                true
            }
        }
        assert!(my_zkvm_test_fn());
    }

    #[test]
    fn test_test_macro_preserves_fn_signature() {
        test! {
            fn zkvm_test_with_args(x: u32) -> u32 {
                x * 2
            }
        }
        assert_eq!(zkvm_test_with_args(21), 42);
    }
}
