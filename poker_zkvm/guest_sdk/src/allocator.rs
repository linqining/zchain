//! Bump allocator — 无 free，适合 ZKVM guest 短生命周期。
//!
//! # 并发说明
//!
//! riscv32im-unknown-none-elf target 默认不支持 atomic 指令（无 A 扩展），
//! 且 ZKVM guest 为单线程无抢占，因此使用 `static mut` + unsafe 直接读写
//! 替代 `AtomicU32::compare_exchange`。这是 sound 的因为：
//! 1. guest crate 是 `no_std + no_main`，无 OS 线程
//! 2. syscall 不会在 guest 内引入并发（host 执行 syscall 时 guest 暂停）

use alloc::alloc::{GlobalAlloc, Layout};

/// 堆起始地址（与 host `poker_zkvm/src/isa/state.rs::HEAP_START` 一致）。
pub const HEAP_START: u32 = 0x1000_0000;
/// 堆大小（8MB，留 8MB 给栈/全局）。
pub const HEAP_SIZE: u32 = 8 * 1024 * 1024;

/// 堆指针（单线程，无 atomic）。
static mut HEAP_NEXT: u32 = HEAP_START;

/// Bump allocator。单线程 guest，无竞态。
pub struct BumpAlloc;

unsafe impl GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align() as u32;
        let size = layout.size() as u32;

        // 单线程：直接读写 HEAP_NEXT，无需 CAS
        let cur = HEAP_NEXT;
        let aligned = (cur + align - 1) & !(align - 1);
        let next = match aligned.checked_add(size) {
            Some(n) => n,
            None => super::syscalls::panic_msg("heap exhausted: size overflow"),
        };
        if next > HEAP_START + HEAP_SIZE {
            super::syscalls::panic_msg("heap exhausted: out of range");
        }
        HEAP_NEXT = next;
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator: 无操作
    }
}

/// 仅在 riscv32 target 注册全局 allocator。
/// std-test 模式（非 riscv32 target）使用 std 默认 allocator。
#[cfg(target_arch = "riscv32")]
#[global_allocator]
static ALLOC: BumpAlloc = BumpAlloc;
