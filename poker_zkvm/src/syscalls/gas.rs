//! ZKVM Syscall gas 计费（Phase 4 — Task 4.3）。
//!
//! 严格遵循 spec.md L646 / L653 / L660 / L669（v1.4 FROZEN）：
//! - Poseidon: `GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * num_blocks`
//! - SHA-256: 按字节计费
//! - ECDSA: `GAS_ZKVM_ECDSA_VERIFY = 100_000`（spec L660）
//! - ReadState: `GAS_ZKVM_READ_STATE_PER_SLOT * num_slots`（spec L669）
//!
//! # 设计说明
//!
//! gas 计费是 on-chain 概念，host 执行不实际扣 gas。
//! [`syscall_gas`] 函数供 executor / prover 估算 syscall gas 开销。

use crate::syscalls::SyscallId;

/// `read_input` 基础 gas。
pub const GAS_ZKVM_READ_INPUT_BASE: u64 = 10;

/// `commit_output` 基础 gas。
pub const GAS_ZKVM_COMMIT_OUTPUT_BASE: u64 = 10;

/// `poseidon` 基础 gas（spec L646）。
pub const GAS_ZKVM_POSEIDON_BASE: u64 = 100;

/// `poseidon` 每 32-byte block 的 gas（spec L646）。
pub const GAS_ZKVM_POSEIDON_PER_BLOCK: u64 = 50;

/// `sha256` 每字节 gas（spec L653）。
pub const GAS_ZKVM_SHA256_PER_BYTE: u64 = 1;

/// `ecdsa_verify` 固定 gas（spec L660，与既有 `GAS_SECP256K1_VERIFY` 对齐）。
pub const GAS_ZKVM_ECDSA_VERIFY: u64 = 100_000;

/// `emit_event` 基础 gas。
pub const GAS_ZKVM_EMIT_EVENT_BASE: u64 = 10;

/// `emit_event` 每字节 gas。
pub const GAS_ZKVM_EMIT_EVENT_PER_BYTE: u64 = 1;

/// `log` 基础 gas。
pub const GAS_ZKVM_LOG_BASE: u64 = 10;

/// `log` 每字节 gas。
pub const GAS_ZKVM_LOG_PER_BYTE: u64 = 1;

/// `panic` 固定 gas。
pub const GAS_ZKVM_PANIC: u64 = 10;

/// `get_randomness` 固定 gas。
pub const GAS_ZKVM_GET_RANDOMNESS: u64 = 100;

/// `read_state` 每 slot 的 gas（spec L669）。
pub const GAS_ZKVM_READ_STATE_PER_SLOT: u64 = 50;

/// Syscall gas 参数（从寄存器读取后传入）。
///
/// 不同 syscall 使用不同字段：
/// - `read_input` / `commit_output` / `poseidon` / `sha256` / `emit_event` / `log` / `panic` → `input_len`
/// - `read_state` → `num_slots`
/// - `ecdsa_verify` / `get_randomness` → 不使用参数（固定 gas）
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallGasArgs {
    /// 输入长度（字节）— 用于 PER_BYTE / PER_BLOCK 计算。
    pub input_len: u32,
    /// slot 数量 — 用于 `read_state` 的 PER_SLOT 计算。
    pub num_slots: u32,
}

/// 计算 syscall 的 gas 开销。
///
/// # 公式
///
/// | Syscall | 公式 |
/// |---------|------|
/// | `ReadInput` | `GAS_ZKVM_READ_INPUT_BASE` |
/// | `CommitOutput` | `GAS_ZKVM_COMMIT_OUTPUT_BASE` |
/// | `Poseidon` | `BASE + PER_BLOCK * ceil(input_len / 32)` |
/// | `Sha256` | `PER_BYTE * input_len` |
/// | `EcdsaVerify` | `GAS_ZKVM_ECDSA_VERIFY`（固定） |
/// | `EmitEvent` | `BASE + PER_BYTE * input_len` |
/// | `Log` | `BASE + PER_BYTE * input_len` |
/// | `Panic` | `GAS_ZKVM_PANIC`（固定） |
/// | `GetRandomness` | `GAS_ZKVM_GET_RANDOMNESS`（固定） |
/// | `ReadState` | `PER_SLOT * num_slots` |
#[must_use]
pub fn syscall_gas(id: SyscallId, args: &SyscallGasArgs) -> u64 {
    match id {
        SyscallId::ReadInput => GAS_ZKVM_READ_INPUT_BASE,
        SyscallId::CommitOutput => GAS_ZKVM_COMMIT_OUTPUT_BASE,
        SyscallId::Poseidon => {
            let num_blocks = (args.input_len as u64).div_ceil(32);
            GAS_ZKVM_POSEIDON_BASE + GAS_ZKVM_POSEIDON_PER_BLOCK * num_blocks
        }
        SyscallId::Sha256 => GAS_ZKVM_SHA256_PER_BYTE * args.input_len as u64,
        SyscallId::EcdsaVerify => GAS_ZKVM_ECDSA_VERIFY,
        SyscallId::EmitEvent => {
            GAS_ZKVM_EMIT_EVENT_BASE + GAS_ZKVM_EMIT_EVENT_PER_BYTE * args.input_len as u64
        }
        SyscallId::Log => GAS_ZKVM_LOG_BASE + GAS_ZKVM_LOG_PER_BYTE * args.input_len as u64,
        SyscallId::Panic => GAS_ZKVM_PANIC,
        SyscallId::GetRandomness => GAS_ZKVM_GET_RANDOMNESS,
        SyscallId::ReadState => GAS_ZKVM_READ_STATE_PER_SLOT * args.num_slots as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 常量值测试 =====

    #[test]
    fn test_gas_constants_values() {
        assert_eq!(GAS_ZKVM_READ_INPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_COMMIT_OUTPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_POSEIDON_BASE, 100);
        assert_eq!(GAS_ZKVM_POSEIDON_PER_BLOCK, 50);
        assert_eq!(GAS_ZKVM_SHA256_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_ECDSA_VERIFY, 100_000);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_BASE, 10);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_LOG_BASE, 10);
        assert_eq!(GAS_ZKVM_LOG_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_PANIC, 10);
        assert_eq!(GAS_ZKVM_GET_RANDOMNESS, 100);
        assert_eq!(GAS_ZKVM_READ_STATE_PER_SLOT, 50);
    }

    // ===== 固定 gas syscall 测试 =====

    #[test]
    fn test_fixed_gas_syscalls() {
        let args = SyscallGasArgs::default();
        assert_eq!(syscall_gas(SyscallId::ReadInput, &args), 10);
        assert_eq!(syscall_gas(SyscallId::CommitOutput, &args), 10);
        assert_eq!(syscall_gas(SyscallId::EcdsaVerify, &args), 100_000);
        assert_eq!(syscall_gas(SyscallId::Panic, &args), 10);
        assert_eq!(syscall_gas(SyscallId::GetRandomness, &args), 100);
    }

    // ===== Poseidon gas 测试（PER_BLOCK 乘法）=====

    #[test]
    fn test_poseidon_gas_calculation() {
        // 0 字节 → 0 blocks → 100 (仅 base)
        let args = SyscallGasArgs { input_len: 0, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 100);

        // 1 字节 → 1 block → 100 + 50 = 150
        let args = SyscallGasArgs { input_len: 1, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 150);

        // 32 字节 → 1 block → 150
        let args = SyscallGasArgs { input_len: 32, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 150);

        // 33 字节 → 2 blocks → 100 + 100 = 200
        let args = SyscallGasArgs { input_len: 33, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 200);

        // 64 字节 → 2 blocks → 200
        let args = SyscallGasArgs { input_len: 64, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 200);

        // 65 字节 → 3 blocks → 100 + 150 = 250
        let args = SyscallGasArgs { input_len: 65, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Poseidon, &args), 250);
    }

    // ===== SHA-256 gas 测试（PER_BYTE 乘法）=====

    #[test]
    fn test_sha256_gas_calculation() {
        let args = SyscallGasArgs { input_len: 0, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 0);

        let args = SyscallGasArgs { input_len: 1, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 1);

        let args = SyscallGasArgs { input_len: 100, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 100);

        let args = SyscallGasArgs { input_len: 1024, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Sha256, &args), 1024);
    }

    // ===== emit_event / log gas 测试（BASE + PER_BYTE）=====

    #[test]
    fn test_emit_event_gas_calculation() {
        let args = SyscallGasArgs { input_len: 0, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::EmitEvent, &args), 10);

        let args = SyscallGasArgs { input_len: 100, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::EmitEvent, &args), 110);
    }

    #[test]
    fn test_log_gas_calculation() {
        let args = SyscallGasArgs { input_len: 0, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Log, &args), 10);

        let args = SyscallGasArgs { input_len: 50, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::Log, &args), 60);
    }

    // ===== read_state gas 测试（PER_SLOT 乘法）=====

    #[test]
    fn test_read_state_gas_calculation() {
        let args = SyscallGasArgs { num_slots: 0, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 0);

        let args = SyscallGasArgs { num_slots: 1, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 50);

        let args = SyscallGasArgs { num_slots: 5, ..Default::default() };
        assert_eq!(syscall_gas(SyscallId::ReadState, &args), 250);
    }

    // ===== 全 syscall 覆盖测试 =====

    #[test]
    fn test_all_syscalls_have_gas() {
        let args = SyscallGasArgs { input_len: 32, num_slots: 1 };
        for id in SyscallId::all() {
            let gas = syscall_gas(id, &args);
            assert!(gas < u64::MAX, "syscall {id:?} gas 不应溢出");
        }
    }
}
