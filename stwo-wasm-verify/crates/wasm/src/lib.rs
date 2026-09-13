//! Path A crate B — canonical STARK 验证器的 wasm C ABI。
//!
//! 手写 C ABI + node/浏览器直接 `WebAssembly.instantiate`（探针已验证模式，
//! 见 stwo-wasm-probe/src/lib.rs 的 abi 模块；不引入 wasm-bindgen 与
//! wasm-bindgen-cli 工具链）。
//!
//! 调用约定（与探针同型，前缀 sv_ = stwo-verify）：
//! ```text
//! ptr = sv_alloc(len)                 // 线性内存里开一段调用方可写缓冲
//! ... 宿主把 borsh 归档字节写入 [ptr, ptr+len) ...
//! rc = sv_verify(ptr, len)            // 0=验证通过 -1=归档解码失败
//!                                     // -2=验证拒绝 -3=内部错误
//! n  = sv_stats(ptr, cap)             // 上次验证的 JSON stats（含 verifier 版本）
//! n  = sv_last_error(ptr, cap)        // 最近错误消息明文
//! sv_free(ptr, len)                   // 归还缓冲
//! ```
//! 计时：本模块不做任何时钟调用（wasm32-unknown-unknown 无时钟 syscall，
//! `std::time::Instant` 会 panic——探针实测）；墙钟由宿主测量。

use stwo_verify_core::verify_canonical_proof_wasm;

thread_local! {
    static LAST_STATS: core::cell::RefCell<String> = const { core::cell::RefCell::new(String::new()) };
    static LAST_ERROR: core::cell::RefCell<String> = const { core::cell::RefCell::new(String::new()) };
}

fn set_last(stats: String, err: String) {
    LAST_STATS.with(|s| *s.borrow_mut() = stats);
    LAST_ERROR.with(|e| *e.borrow_mut() = err);
}

/// 为调用方分配 `len` 字节（来自 wasm 线性内存；用 `sv_free` 归还）。
///
/// # Safety
/// 返回指针仅在 `sv_free(ptr, len)` 前有效。
#[no_mangle]
pub extern "C" fn sv_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` 必须来自 `sv_alloc` 且 `len` 与分配时一致。
#[no_mangle]
pub unsafe extern "C" fn sv_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }
}

/// 验证 [ptr, ptr+len) 处的 borsh canonical 归档。
/// 返回 0 = 验证通过；<0 = 失败（-1 归档解码失败，-2 验证拒绝，-3 内部错误）。
///
/// # Safety
/// ptr/len 必须指向调用方经 `sv_alloc` 写入的可读缓冲。
#[no_mangle]
pub unsafe extern "C" fn sv_verify(ptr: *const u8, len: usize) -> i32 {
    let bytes = match std::panic::catch_unwind(|| unsafe { slice_from_raw(ptr, len) }) {
        Ok(b) => b,
        Err(_) => {
            set_last(String::new(), "bad pointer".into());
            return -3;
        }
    };
    match verify_canonical_proof_wasm(bytes) {
        Ok(stats) => {
            let rc = if stats.verified { 0 } else { -2 };
            let err = stats.error.clone().unwrap_or_default();
            set_last(stats.to_json(), err);
            rc
        }
        Err(msg) => {
            set_last(String::new(), msg);
            -1
        }
    }
}

/// 最近一次验证的 JSON stats 拷到调用方缓冲，返回拷贝字节数
///（返回值 > cap 表示被截断，可按返回值重试）。
///
/// # Safety
/// ptr/cap 指向调用方可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sv_stats(ptr: *mut u8, cap: usize) -> usize {
    let msg = LAST_STATS.with(|s| s.borrow().clone());
    copy_out(msg.as_bytes(), ptr, cap)
}

/// 最近一次错误消息拷到调用方缓冲，返回拷贝字节数。
///
/// # Safety
/// ptr/cap 指向调用方可写缓冲。
#[no_mangle]
pub unsafe extern "C" fn sv_last_error(ptr: *mut u8, cap: usize) -> usize {
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    copy_out(msg.as_bytes(), ptr, cap)
}

/// 验证器身份串长度（含 verifier 版本的 stats JSON 较长，宿主可先探长度）。
#[no_mangle]
pub extern "C" fn sv_stats_len() -> usize {
    LAST_STATS.with(|s| s.borrow().len())
}

unsafe fn slice_from_raw(ptr: *const u8, len: usize) -> &'static [u8] {
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

unsafe fn copy_out(bytes: &[u8], ptr: *mut u8, cap: usize) -> usize {
    let n = bytes.len().min(cap);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, n);
    }
    bytes.len()
}
