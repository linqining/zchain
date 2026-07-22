//! 哈希便捷 API。

use crate::syscalls;

/// Poseidon 哈希，输出 32 字节。
pub fn poseidon(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    syscalls::poseidon(data, &mut out);
    out
}

/// SHA-256 哈希，输出 32 字节。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    syscalls::sha256(data, &mut out);
    out
}

/// Keccak-256 哈希，输出 32 字节。
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    syscalls::keccak256(data, &mut out);
    out
}

/// Blake2b-256 哈希，输出 32 字节（Phase 4）。
///
/// 与 `dispatch.rs::compute_method_selector` 算法一致。
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    syscalls::blake2b_256(data, &mut out);
    out
}
