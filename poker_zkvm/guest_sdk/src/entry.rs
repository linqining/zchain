//! ZKVM guest entry trampoline + panic handler。
//!
//! 输入格式约定：[4 字节 LE 长度 N][N 字节数据]
//! 输出格式：直接 commit_output(output_bytes)

use alloc::vec::Vec;
use crate::syscalls;

/// 最大输入大小（64KB）。
pub const MAX_INPUT_SIZE: usize = 64 * 1024;

/// guest entry 逻辑。由 guest crate 的 `_start` 调用。
///
/// guest crate 须提供 `extern "Rust" { fn zkvm_main(input: &[u8]) -> Result<Vec<u8>, &'static str>; }`
pub fn zkvm_entry() -> ! {
    extern "Rust" {
        fn zkvm_main(input: &[u8]) -> Result<Vec<u8>, &'static str>;
    }

    // 1. 分配输入 buffer 并读取
    let mut buf = vec![0u8; MAX_INPUT_SIZE];
    syscalls::read_input_raw(&mut buf);

    // 2. 解析 4 字节 LE 长度前缀
    let input_len = if buf.len() >= 4 {
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize
    } else {
        0
    };

    // 3. 截取实际输入
    let input: &[u8] = if input_len > 0 && input_len <= MAX_INPUT_SIZE - 4 {
        &buf[4..4 + input_len]
    } else {
        &[]
    };

    // 4. 调用 guest main
    match unsafe { zkvm_main(input) } {
        Ok(output) => syscalls::commit_output(&output),
        Err(_msg) => syscalls::panic_msg("guest error"),
    }
}

/// 在 guest crate 中注册 `_start` 和 `#[panic_handler]`。
///
/// 用法：
/// ```ignore
/// zkvm_guest_sdk::entry_point!();
///
/// #[no_mangle]
/// pub extern "Rust" fn zkvm_main(input: &[u8]) -> Result<Vec<u8>, &'static str> {
///     Ok(vec![0x42])
/// }
/// ```
#[macro_export]
macro_rules! entry_point {
    () => {
        /// ELF entry point。
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            $crate::entry::zkvm_entry()
        }

        #[panic_handler]
        fn _zkvm_panic_handler(_info: &core::panic::PanicInfo) -> ! {
            $crate::syscalls::panic_msg("panic")
        }
    };
}
