//! 10 个 ZKVM Syscall 的 Host 实现（Phase 4 — Task 4.2）。
//!
//! 严格遵循 spec.md L193-265 / L637-669（v1.4 FROZEN）：
//! - 每个 syscall 为一个 struct，实现 [`Syscall`] trait
//! - ABI：a0-a6 寄存器传参，a0 寄存器返回值
//! - gas 计费通过 [`crate::syscalls::gas::syscall_gas`] 估算
//!
//! # Syscall 列表
//!
//! | Struct | ID | ABI | 说明 |
//! |--------|----|-----|------|
//! | [`ReadInputSyscall`] | 0x01 | (ptr, len) | 从 host input buffer 读取 |
//! | [`CommitOutputSyscall`] | 0x02 | (ptr, len) | 写入 host output buffer |
//! | [`PoseidonSyscall`] | 0x03 | (ptr, len, out_ptr) | Poseidon 哈希 |
//! | [`Sha256Syscall`] | 0x04 | (ptr, len, out_ptr) | SHA-256 哈希 |
//! | [`EcdsaVerifySyscall`] | 0x05 | (msg_ptr, msg_len, sig_ptr, pubkey_ptr) → bool | ECDSA 验证 |
//! | [`EmitEventSyscall`] | 0x06 | (ptr, len) | 事件进 public_io（绑定 step_index） |
//! | [`LogSyscall`] | 0x07 | (ptr, len) | 写入 host event log |
//! | [`PanicSyscall`] | 0x08 | (ptr, len) | 终止执行 |
//! | [`GetRandomnessSyscall`] | 0x09 | (out_ptr) | 从 host seed 派生（deterministic） |
//! | [`ReadStateSyscall`] | 0x0A | (slot, out_ptr) | 仅允许白名单 slot |

use ark_bn254::Fr;
use sha2::{Digest, Sha256};

use crate::error::ZkvmError;
use crate::isa::state::{HEAP_START, VmState};
use crate::syscalls::gas::{SyscallGasArgs, syscall_gas};
use crate::syscalls::poseidon::{fr_to_bytes_le, poseidon_hash, poseidon_hash_bytes};
use crate::syscalls::{Syscall, SyscallContext, SyscallId};

// ===== Slot 白名单常量（spec L232-236）=====

/// `SLOT_GAME_STATE = 0x01`（spec L232）。
pub const SLOT_GAME_STATE: u32 = 0x01;
/// `SLOT_PLAYER_HANDS = 0x02`（spec L233）。
pub const SLOT_PLAYER_HANDS: u32 = 0x02;
/// `SLOT_POT_AMOUNT = 0x03`（spec L234）。
pub const SLOT_POT_AMOUNT: u32 = 0x03;
/// `SLOT_CURRENT_TURN = 0x04`（spec L235）。
pub const SLOT_CURRENT_TURN: u32 = 0x04;
/// `SLOT_ACK_CHAIN = 0x05`（spec L236）。
pub const SLOT_ACK_CHAIN: u32 = 0x05;

/// 检查 slot 是否在白名单内。
#[must_use]
pub fn is_whitelisted_slot(slot: u32) -> bool {
    matches!(
        slot,
        SLOT_GAME_STATE | SLOT_PLAYER_HANDS | SLOT_POT_AMOUNT | SLOT_CURRENT_TURN | SLOT_ACK_CHAIN
    )
}

// ===== 辅助函数 =====

/// 从 VM 内存读取字节序列 `[addr, addr+len)`。
pub(crate) fn read_vm_bytes(state: &VmState, addr: u32, len: u32) -> Result<Vec<u8>, ZkvmError> {
    let mut bytes = Vec::with_capacity(len as usize);
    for i in 0..len {
        let byte_addr = addr.wrapping_add(i);
        bytes.push(state.read_memory_byte(byte_addr)?);
    }
    Ok(bytes)
}

/// 将字节序列写入 VM 内存 `[addr, addr+bytes.len())`。
pub(crate) fn write_vm_bytes(state: &mut VmState, addr: u32, bytes: &[u8]) -> Result<(), ZkvmError> {
    for (i, &byte) in bytes.iter().enumerate() {
        let byte_addr = addr.wrapping_add(i as u32);
        state.write_memory_byte(byte_addr, byte)?;
    }
    Ok(())
}

// ===== 1. ReadInput (0x01) =====

/// `zkvm_read_input(ptr, len)` — 从 host input buffer 读取。
///
/// ABI：
/// - a0 = ptr（写入目标地址；若 a0=0 则用 `HEAP_START` 向后兼容）
/// - a1 = len（期望读取长度）
/// - 返回：a0 = ptr（实际写入地址），a1 = actual_len（实际读取长度）
#[derive(Debug, Clone, Default)]
pub struct ReadInputSyscall;

impl Syscall for ReadInputSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::ReadInput
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);

        // 向后兼容：若 a0=0 则用 HEAP_START
        let write_addr = if ptr == 0 { HEAP_START } else { ptr };

        // 实际读取长度 = min(ctx.input.len(), len)
        let actual_len = (ctx.input.len() as u32).min(len);

        // 写入 VM 内存
        for i in 0..actual_len {
            let byte_addr = write_addr.wrapping_add(i);
            state.write_memory_byte(byte_addr, ctx.input[i as usize])?;
        }

        // 设返回值
        state.write_register(crate::syscalls::REG_A0, write_addr);
        state.write_register(crate::syscalls::REG_A1, actual_len);
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::ReadInput, &args)
    }
}

// ===== 2. CommitOutput (0x02) =====

/// `zkvm_commit_output(ptr, len)` — 写入 host output buffer 并 halt。
///
/// ABI：
/// - a0 = ptr（读取源地址）
/// - a1 = len（读取长度）
/// - halt = true
#[derive(Debug, Clone, Default)]
pub struct CommitOutputSyscall;

impl Syscall for CommitOutputSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::CommitOutput
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);

        let output = read_vm_bytes(state, ptr, len)?;
        ctx.output = output;
        ctx.halted = true;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(crate::syscalls::REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::CommitOutput, &args)
    }
}

// ===== 3. Poseidon (0x03) =====

/// `zkvm_poseidon(ptr, len, out_ptr)` — Poseidon 哈希。
///
/// ABI：
/// - a0 = ptr（输入数据地址）
/// - a1 = len（输入数据长度）
/// - a2 = out_ptr（32 字节输出地址）
#[derive(Debug, Clone, Default)]
pub struct PoseidonSyscall;

impl Syscall for PoseidonSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Poseidon
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);
        let out_ptr = state.read_register(crate::syscalls::REG_A2);

        let input = read_vm_bytes(state, ptr, len)?;
        let hash = poseidon_hash_bytes(&input);
        let bytes = fr_to_bytes_le(&hash);
        write_vm_bytes(state, out_ptr, &bytes)?;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(crate::syscalls::REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Poseidon, &args)
    }
}

// ===== 4. Sha256 (0x04) =====

/// `zkvm_sha256(ptr, len, out_ptr)` — SHA-256 哈希。
///
/// ABI：
/// - a0 = ptr（输入数据地址）
/// - a1 = len（输入数据长度）
/// - a2 = out_ptr（32 字节输出地址）
#[derive(Debug, Clone, Default)]
pub struct Sha256Syscall;

impl Syscall for Sha256Syscall {
    fn id(&self) -> SyscallId {
        SyscallId::Sha256
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);
        let out_ptr = state.read_register(crate::syscalls::REG_A2);

        let input = read_vm_bytes(state, ptr, len)?;
        let mut hasher = Sha256::new();
        hasher.update(&input);
        let result = hasher.finalize();
        write_vm_bytes(state, out_ptr, &result)?;
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(crate::syscalls::REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Sha256, &args)
    }
}

// ===== 5. EcdsaVerify (0x05) =====

/// `zkvm_ecdsa_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — ECDSA 验证。
///
/// ABI：
/// - a0 = msg_ptr（消息地址）
/// - a1 = msg_len（消息长度）
/// - a2 = sig_ptr（64 字节 compact 签名地址）
/// - a3 = pubkey_ptr（33 字节 compressed 公钥地址）
/// - 返回：a0 = 1（成功）/ 0（失败）
///
/// # 注意
///
/// 验证失败（包括格式错误）返回 a0=0，不返回 Err（spec 要求 bool 返回）。
#[derive(Debug, Clone, Default)]
pub struct EcdsaVerifySyscall;

impl Syscall for EcdsaVerifySyscall {
    fn id(&self) -> SyscallId {
        SyscallId::EcdsaVerify
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let msg_ptr = state.read_register(crate::syscalls::REG_A0);
        let msg_len = state.read_register(crate::syscalls::REG_A1);
        let sig_ptr = state.read_register(crate::syscalls::REG_A2);
        let pubkey_ptr = state.read_register(crate::syscalls::REG_A3);

        // 读取消息（先哈希为 32 字节 digest）
        let msg_bytes = read_vm_bytes(state, msg_ptr, msg_len)?;
        let msg_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(&msg_bytes);
            hasher.finalize().into()
        };

        // 读取签名（64 字节 compact）
        let sig_bytes = read_vm_bytes(state, sig_ptr, 64)?;
        // 读取公钥（33 字节 compressed）
        let pubkey_bytes = read_vm_bytes(state, pubkey_ptr, 33)?;

        // 验证
        let verified = verify_ecdsa(&msg_hash, &sig_bytes, &pubkey_bytes);

        // 设返回值（1=成功，0=失败）
        state.write_register(crate::syscalls::REG_A0, if verified { 1 } else { 0 });
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::EcdsaVerify, &args)
    }
}

/// ECDSA 验证（secp256k1）。
///
/// 任何错误（格式错误、验证失败）都返回 `false`。
fn verify_ecdsa(msg_hash: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> bool {
    use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};

    let secp = Secp256k1::verification_only();

    // 解析签名
    let Ok(sig_obj) = Signature::from_compact(sig) else {
        return false;
    };

    // 解析公钥
    let Ok(pubkey_obj) = PublicKey::from_slice(pubkey) else {
        return false;
    };

    // 验证
    let msg = Message::from_digest(*msg_hash);
    secp.verify_ecdsa(&msg, &sig_obj, &pubkey_obj).is_ok()
}

// ===== 6. EmitEvent (0x06) =====

/// `zkvm_emit_event(ptr, len)` — 事件进 public_io（绑定 step_index）。
///
/// ABI：
/// - a0 = ptr（事件内容地址）
/// - a1 = len（事件内容长度）
///
/// # event_hash 计算（spec L246）
///
/// `event_hash = Poseidon(poseidon_hash_bytes(content) || Fr::from(step_index))`
///
/// step_index 绑定防止 event 重排攻击。
#[derive(Debug, Clone, Default)]
pub struct EmitEventSyscall;

impl Syscall for EmitEventSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::EmitEvent
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);

        let content = read_vm_bytes(state, ptr, len)?;
        let content_hash = poseidon_hash_bytes(&content);
        let step_fr = Fr::from(ctx.step_index);
        let event_hash = poseidon_hash(&[content_hash, step_fr]);
        ctx.events.push(event_hash);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(crate::syscalls::REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::EmitEvent, &args)
    }
}

// ===== 7. Log (0x07) =====

/// `zkvm_log(ptr, len)` — 写入 host event log。
///
/// ABI：
/// - a0 = ptr（日志消息地址）
/// - a1 = len（日志消息长度）
#[derive(Debug, Clone, Default)]
pub struct LogSyscall;

impl Syscall for LogSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Log
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);

        let msg = read_vm_bytes(state, ptr, len)?;
        ctx.logs.push(msg);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        let len = state.read_register(crate::syscalls::REG_A1);
        let args = SyscallGasArgs {
            input_len: len,
            ..Default::default()
        };
        syscall_gas(SyscallId::Log, &args)
    }
}

// ===== 8. Panic (0x08) =====

/// `zkvm_panic(ptr, len)` — 终止执行。
///
/// ABI：
/// - a0 = ptr（错误消息地址）
/// - a1 = len（错误消息长度）
///
/// # Errors
///
/// 返回 `Err(ZkvmError::Other("zkvm_panic: {msg}"))`。
#[derive(Debug, Clone, Default)]
pub struct PanicSyscall;

impl Syscall for PanicSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::Panic
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let ptr = state.read_register(crate::syscalls::REG_A0);
        let len = state.read_register(crate::syscalls::REG_A1);

        let msg_bytes = read_vm_bytes(state, ptr, len)?;
        let msg = String::from_utf8_lossy(&msg_bytes);
        Err(ZkvmError::Other(format!("zkvm_panic: {msg}")))
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::Panic, &args)
    }
}

// ===== 9. GetRandomness (0x09) =====

/// `zkvm_get_randomness(out_ptr)` — 从 host seed 派生（deterministic）。
///
/// ABI：
/// - a0 = out_ptr（32 字节输出地址）
///
/// # 派生函数（spec L220-223）
///
/// `output = Poseidon(seed || initial_commitment || final_commitment || call_counter)`
///
/// - `seed` = public_io 的 `randomness_seed`（来自链上 VRF）
/// - `initial_commitment` / `final_commitment` = public_io 中既有字段
/// - `call_counter` = 调用序号（从 0 开始单调递增）
#[derive(Debug, Clone, Default)]
pub struct GetRandomnessSyscall;

impl Syscall for GetRandomnessSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::GetRandomness
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let out_ptr = state.read_register(crate::syscalls::REG_A0);

        let counter_fr = Fr::from(ctx.randomness_counter);
        let output = poseidon_hash(&[
            ctx.randomness_seed,
            ctx.initial_commitment,
            ctx.final_commitment,
            counter_fr,
        ]);

        let bytes = fr_to_bytes_le(&output);
        write_vm_bytes(state, out_ptr, &bytes)?;

        ctx.randomness_counter += 1;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::GetRandomness, &args)
    }
}

// ===== 10. ReadState (0x0A) =====

/// `zkvm_read_state(slot, out_ptr)` — 仅允许白名单 slot。
///
/// ABI：
/// - a0 = slot（状态槽 ID，须在白名单 0x01-0x05 内）
/// - a1 = out_ptr（输出地址）
///
/// # slot 白名单（spec L232-236）
///
/// - `SLOT_GAME_STATE = 0x01`
/// - `SLOT_PLAYER_HANDS = 0x02`
/// - `SLOT_POT_AMOUNT = 0x03`
/// - `SLOT_CURRENT_TURN = 0x04`
/// - `SLOT_ACK_CHAIN = 0x05`
///
/// # Errors
///
/// - `ZkvmError::InvalidSlot(slot)` — 非白名单 slot
/// - 透传 `host_state.read_slot` 的错误
#[derive(Debug, Clone, Default)]
pub struct ReadStateSyscall;

impl Syscall for ReadStateSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::ReadState
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let slot = state.read_register(crate::syscalls::REG_A0);
        let out_ptr = state.read_register(crate::syscalls::REG_A1);

        if !is_whitelisted_slot(slot) {
            return Err(ZkvmError::InvalidSlot(slot));
        }

        let value = ctx.host_state.read_slot(slot)?;
        write_vm_bytes(state, out_ptr, &value)?;
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs {
            num_slots: 1,
            ..Default::default()
        };
        syscall_gas(SyscallId::ReadState, &args)
    }
}

// ===== 注册全部 host syscall 的辅助函数 =====

/// 创建注册全部 host syscall 的 [`SyscallRegistry`](crate::syscalls::SyscallRegistry)。
///
/// 包含：
/// - 基础 syscall（0x01-0x0A，10 个）
/// - BLS12-381 syscall（0x10-0x15，6 个，E2E Phase 1）
/// - BLS12-381 扩展 syscall（0x16-0x1B，6 个，Phase 3）
/// - GameState mock syscall（0x20-0x21，2 个，E2E Phase 1）
/// - Game-specific syscall（0x30-0x32，3 个，E2E Phase 1）
/// - Mental Poker proof verify + hash syscall（0x33-0x36，4 个，Phase 4）
///
/// 注：0x0B-0x0F（keccak256/modexp/merkle_verify/ed25519/bn254_pairing）暂无 host 实现，
/// 注册表对应 slot 为 None，dispatch 时返回 `Unregistered` 错误。
///
/// 供 executor 和测试使用。
#[must_use]
pub fn create_full_registry() -> crate::syscalls::SyscallRegistry {
    let mut registry = crate::syscalls::SyscallRegistry::new_empty();
    // 基础 syscall（0x01-0x0A，10 个 host 实现）
    registry.register(Box::new(ReadInputSyscall)).unwrap();
    registry.register(Box::new(CommitOutputSyscall)).unwrap();
    registry.register(Box::new(PoseidonSyscall)).unwrap();
    registry.register(Box::new(Sha256Syscall)).unwrap();
    registry.register(Box::new(EcdsaVerifySyscall)).unwrap();
    registry.register(Box::new(EmitEventSyscall)).unwrap();
    registry.register(Box::new(LogSyscall)).unwrap();
    registry.register(Box::new(PanicSyscall)).unwrap();
    registry.register(Box::new(GetRandomnessSyscall)).unwrap();
    registry.register(Box::new(ReadStateSyscall)).unwrap();
    // E2E Phase 1 — BLS12-381 syscall（0x10-0x15，6 个）
    registry
        .register(Box::new(crate::syscalls::bls12381::Bls12381HashToCurveSyscall))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381ScalarMulSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::bls12381::Bls12381G1AddSyscall))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::bls12381::Bls12381G1MulSyscall))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::bls12381::Bls12381PairingSyscall))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381HashToScalarSyscall,
        ))
        .unwrap();
    // Phase 3 — BLS12-381 扩展 syscall（0x16-0x1B，6 个）
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381ScalarAddSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381ScalarSubSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381ScalarNegSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381ScalarInvSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::bls12381::Bls12381G1SubSyscall))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::bls12381::Bls12381G1GeneratorSyscall,
        ))
        .unwrap();
    // E2E Phase 1 — GameState mock syscall（0x20-0x21，2 个）
    registry
        .register(Box::new(
            crate::syscalls::game_state::GameStateReadSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::game_state::GameStateWriteSyscall,
        ))
        .unwrap();
    // E2E Phase 1 — Game-specific syscall（0x30-0x32，3 个）
    registry
        .register(Box::new(crate::syscalls::game::CardEncodeSyscall))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::game::CardDecodeSyscall))
        .unwrap();
    registry
        .register(Box::new(crate::syscalls::game::ShuffleVerifySyscall))
        .unwrap();
    // Phase 4 — Mental Poker proof verify + hash syscall（0x33-0x36，4 个）
    registry
        .register(Box::new(
            crate::syscalls::proof_verify::Blake2b256Syscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::proof_verify::VerifyDleqProofSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::proof_verify::VerifyReconstructProofSyscall,
        ))
        .unwrap();
    registry
        .register(Box::new(
            crate::syscalls::proof_verify::VerifyRevealTokenProofSyscall,
        ))
        .unwrap();
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::state::VmState;
    use crate::syscalls::{REG_A0, REG_A1, REG_A2, REG_A3, SyscallContext, SyscallRegistry};

    // ===== 辅助函数 =====

    /// 创建注册全部 10 个 host syscall 的 registry。
    fn full_registry() -> SyscallRegistry {
        create_full_registry()
    }

    /// 写入字节到 VM 内存。
    fn write_bytes(state: &mut VmState, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            state.write_memory_byte(addr + i as u32, b).unwrap();
        }
    }

    /// 从 VM 内存读取字节。
    fn read_bytes(state: &VmState, addr: u32, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| state.read_memory_byte(addr + i as u32).unwrap())
            .collect()
    }

    // ===== 1. ReadInput 测试 =====

    #[test]
    fn test_read_input_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![0xAB, 0xCD, 0xEF]);

        // a0 = 0x2000, a1 = 3
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 3);

        registry.dispatch(0x01, &mut ctx, &mut state).unwrap();

        // 验证内存写入
        assert_eq!(read_bytes(&state, 0x2000, 3), vec![0xAB, 0xCD, 0xEF]);
        // 验证返回值
        assert_eq!(state.read_register(REG_A0), 0x2000);
        assert_eq!(state.read_register(REG_A1), 3);
    }

    #[test]
    fn test_read_input_backward_compat() {
        // a0 = 0 → 使用 HEAP_START
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![0x42]);

        state.write_register(REG_A0, 0);
        state.write_register(REG_A1, 1);

        registry.dispatch(0x01, &mut ctx, &mut state).unwrap();

        assert_eq!(state.read_register(REG_A0), HEAP_START);
        assert_eq!(state.read_register(REG_A1), 1);
        assert_eq!(state.read_memory_byte(HEAP_START).unwrap(), 0x42);
    }

    #[test]
    fn test_read_input_truncated() {
        // 请求 5 字节但 input 只有 3 字节
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![1, 2, 3]);

        state.write_register(REG_A0, 0x3000);
        state.write_register(REG_A1, 5);

        registry.dispatch(0x01, &mut ctx, &mut state).unwrap();

        assert_eq!(state.read_register(REG_A1), 3, "actual_len 应为 3");
        assert_eq!(read_bytes(&state, 0x3000, 3), vec![1, 2, 3]);
    }

    // ===== 2. CommitOutput 测试 =====

    #[test]
    fn test_commit_output_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        write_bytes(&mut state, 0x2000, b"hello");
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 5);

        registry.dispatch(0x02, &mut ctx, &mut state).unwrap();

        assert!(ctx.is_halted());
        assert_eq!(ctx.output, b"hello");
    }

    #[test]
    fn test_commit_output_empty() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 0);

        registry.dispatch(0x02, &mut ctx, &mut state).unwrap();

        assert!(ctx.is_halted());
        assert!(ctx.output.is_empty());
    }

    #[test]
    fn test_commit_output_echo() {
        // read_input + commit_output echo
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(b"world".to_vec());

        // read_input
        state.write_register(REG_A0, 0x4000);
        state.write_register(REG_A1, 5);
        registry.dispatch(0x01, &mut ctx, &mut state).unwrap();

        // commit_output（用返回的 ptr 和 len）
        let ptr = state.read_register(REG_A0);
        let len = state.read_register(REG_A1);
        state.write_register(REG_A0, ptr);
        state.write_register(REG_A1, len);
        registry.dispatch(0x02, &mut ctx, &mut state).unwrap();

        assert_eq!(ctx.output, b"world");
    }

    // ===== 3. Poseidon 测试 =====

    #[test]
    fn test_poseidon_syscall_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        write_bytes(&mut state, 0x2000, b"test data");
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 9);
        state.write_register(REG_A2, 0x3000);

        registry.dispatch(0x03, &mut ctx, &mut state).unwrap();

        // 验证输出 32 字节
        let output = read_bytes(&state, 0x3000, 32);
        assert_eq!(output.len(), 32);

        // 验证与直接调用一致
        let expected = fr_to_bytes_le(&poseidon_hash_bytes(b"test data"));
        assert_eq!(output, expected);
    }

    #[test]
    fn test_poseidon_syscall_empty_input() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 0);
        state.write_register(REG_A2, 0x3000);

        registry.dispatch(0x03, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x3000, 32);
        let expected = fr_to_bytes_le(&poseidon_hash_bytes(b""));
        assert_eq!(output, expected);
    }

    #[test]
    fn test_poseidon_syscall_deterministic() {
        let registry = full_registry();

        // 第一次
        let mut state1 = VmState::new();
        let mut ctx1 = SyscallContext::new(vec![]);
        write_bytes(&mut state1, 0x2000, b"abc");
        state1.write_register(REG_A0, 0x2000);
        state1.write_register(REG_A1, 3);
        state1.write_register(REG_A2, 0x3000);
        registry.dispatch(0x03, &mut ctx1, &mut state1).unwrap();
        let out1 = read_bytes(&state1, 0x3000, 32);

        // 第二次
        let mut state2 = VmState::new();
        let mut ctx2 = SyscallContext::new(vec![]);
        write_bytes(&mut state2, 0x2000, b"abc");
        state2.write_register(REG_A0, 0x2000);
        state2.write_register(REG_A1, 3);
        state2.write_register(REG_A2, 0x3000);
        registry.dispatch(0x03, &mut ctx2, &mut state2).unwrap();
        let out2 = read_bytes(&state2, 0x3000, 32);

        assert_eq!(out1, out2, "相同输入应产生相同输出");
    }

    // ===== 4. Sha256 测试 =====

    #[test]
    fn test_sha256_syscall_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        write_bytes(&mut state, 0x2000, b"hello");
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 5);
        state.write_register(REG_A2, 0x3000);

        registry.dispatch(0x04, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x3000, 32);
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let expected: [u8; 32] = {
            let mut arr = [0u8; 32];
            hex::decode_to_slice(
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                &mut arr,
            )
            .unwrap();
            arr
        };
        assert_eq!(output, expected.to_vec());
    }

    #[test]
    fn test_sha256_syscall_empty() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 0);
        state.write_register(REG_A2, 0x3000);

        registry.dispatch(0x04, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x3000, 32);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = {
            let mut arr = [0u8; 32];
            hex::decode_to_slice(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                &mut arr,
            )
            .unwrap();
            arr
        };
        assert_eq!(output, expected.to_vec());
    }

    #[test]
    fn test_sha256_syscall_large_input() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        let input = vec![0x42u8; 100];
        write_bytes(&mut state, 0x2000, &input);
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 100);
        state.write_register(REG_A2, 0x3000);

        registry.dispatch(0x04, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x3000, 32);
        assert_eq!(output.len(), 32);
    }

    // ===== 5. EcdsaVerify 测试 =====

    #[test]
    fn test_ecdsa_verify_valid_signature() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        // 生成密钥对和签名
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = secret_key.public_key(&secp);

        let msg = b"test message";
        let msg_hash: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(msg);
            hasher.finalize().into()
        };
        let sig = secp.sign_ecdsa(&Message::from_digest(msg_hash), &secret_key);
        let sig_compact = sig.serialize_compact();
        let pubkey_compressed = public_key.serialize();

        // 写入 VM 内存
        write_bytes(&mut state, 0x2000, msg);
        write_bytes(&mut state, 0x3000, &sig_compact);
        write_bytes(&mut state, 0x4000, &pubkey_compressed);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, msg.len() as u32);
        state.write_register(REG_A2, 0x3000);
        state.write_register(REG_A3, 0x4000);

        registry.dispatch(0x05, &mut ctx, &mut state).unwrap();

        assert_eq!(state.read_register(REG_A0), 1, "有效签名应返回 1");
    }

    #[test]
    fn test_ecdsa_verify_invalid_signature() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        // 使用错误的签名
        let msg = b"test message";
        let bad_sig = vec![0u8; 64]; // 全零签名
        let bad_pubkey = vec![0u8; 33]; // 全零公钥

        write_bytes(&mut state, 0x2000, msg);
        write_bytes(&mut state, 0x3000, &bad_sig);
        write_bytes(&mut state, 0x4000, &bad_pubkey);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, msg.len() as u32);
        state.write_register(REG_A2, 0x3000);
        state.write_register(REG_A3, 0x4000);

        registry.dispatch(0x05, &mut ctx, &mut state).unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "无效签名应返回 0");
    }

    #[test]
    fn test_ecdsa_verify_wrong_message() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        // 生成密钥对和签名（针对 msg1）
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let public_key = secret_key.public_key(&secp);

        let msg1 = b"original message";
        let msg_hash1: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(msg1);
            hasher.finalize().into()
        };
        let sig = secp.sign_ecdsa(&Message::from_digest(msg_hash1), &secret_key);
        let sig_compact = sig.serialize_compact();
        let pubkey_compressed = public_key.serialize();

        // 但验证时用 msg2（不同消息）
        let msg2 = b"tampered message";
        write_bytes(&mut state, 0x2000, msg2);
        write_bytes(&mut state, 0x3000, &sig_compact);
        write_bytes(&mut state, 0x4000, &pubkey_compressed);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, msg2.len() as u32);
        state.write_register(REG_A2, 0x3000);
        state.write_register(REG_A3, 0x4000);

        registry.dispatch(0x05, &mut ctx, &mut state).unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "错误消息应返回 0");
    }

    #[test]
    fn test_ecdsa_verify_gas_cost() {
        let syscall = EcdsaVerifySyscall;
        let state = VmState::new();
        let gas = syscall.gas_cost(&state);
        assert_eq!(gas, 100_000);
    }

    // ===== 6. EmitEvent 测试 =====

    #[test]
    fn test_emit_event_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);
        ctx.step_index = 42;

        write_bytes(&mut state, 0x2000, b"event data");
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 10);

        registry.dispatch(0x06, &mut ctx, &mut state).unwrap();

        assert_eq!(ctx.events.len(), 1, "应有一个 event");
        // 验证 event_hash = Poseidon(poseidon_hash_bytes(content) || step_index)
        let content_hash = poseidon_hash_bytes(b"event data");
        let expected = poseidon_hash(&[content_hash, Fr::from(42u64)]);
        assert_eq!(ctx.events[0], expected);
    }

    #[test]
    fn test_emit_event_step_index_binding() {
        // 不同 step_index 应产生不同 event_hash
        let registry = full_registry();

        // step_index = 1
        let mut state1 = VmState::new();
        let mut ctx1 = SyscallContext::new(vec![]);
        ctx1.step_index = 1;
        write_bytes(&mut state1, 0x2000, b"data");
        state1.write_register(REG_A0, 0x2000);
        state1.write_register(REG_A1, 4);
        registry.dispatch(0x06, &mut ctx1, &mut state1).unwrap();

        // step_index = 2
        let mut state2 = VmState::new();
        let mut ctx2 = SyscallContext::new(vec![]);
        ctx2.step_index = 2;
        write_bytes(&mut state2, 0x2000, b"data");
        state2.write_register(REG_A0, 0x2000);
        state2.write_register(REG_A1, 4);
        registry.dispatch(0x06, &mut ctx2, &mut state2).unwrap();

        assert_ne!(
            ctx1.events[0], ctx2.events[0],
            "不同 step_index 应产生不同 hash"
        );
    }

    #[test]
    fn test_emit_event_multiple() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        for i in 0..3 {
            ctx.step_index = i;
            write_bytes(&mut state, 0x2000, b"event");
            state.write_register(REG_A0, 0x2000);
            state.write_register(REG_A1, 5);
            registry.dispatch(0x06, &mut ctx, &mut state).unwrap();
        }

        assert_eq!(ctx.events.len(), 3, "应有 3 个 events");
    }

    // ===== 7. Log 测试 =====

    #[test]
    fn test_log_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        write_bytes(&mut state, 0x2000, b"log message");
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 11);

        registry.dispatch(0x07, &mut ctx, &mut state).unwrap();

        assert_eq!(ctx.logs.len(), 1);
        assert_eq!(ctx.logs[0], b"log message");
    }

    #[test]
    fn test_log_empty() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 0);

        registry.dispatch(0x07, &mut ctx, &mut state).unwrap();

        assert_eq!(ctx.logs.len(), 1);
        assert!(ctx.logs[0].is_empty());
    }

    // ===== 8. Panic 测试 =====

    #[test]
    fn test_panic_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        let msg = b"error occurred";
        write_bytes(&mut state, 0x2000, msg);
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, msg.len() as u32);

        let err = registry.dispatch(0x08, &mut ctx, &mut state).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("zkvm_panic: error occurred")),
            "应返回 zkvm_panic 错误，got {err:?}"
        );
    }

    #[test]
    fn test_panic_empty_message() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 0);

        let err = registry.dispatch(0x08, &mut ctx, &mut state).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg == "zkvm_panic: "),
            "空消息应返回 'zkvm_panic: '"
        );
    }

    // ===== 9. GetRandomness 测试 =====

    #[test]
    fn test_get_randomness_basic() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        // 设置 randomness 参数
        ctx.randomness_seed = Fr::from(100u64);
        ctx.initial_commitment = Fr::from(200u64);
        ctx.final_commitment = Fr::from(300u64);

        state.write_register(REG_A0, 0x5000);

        registry.dispatch(0x09, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x5000, 32);
        assert_eq!(output.len(), 32);

        // 验证与直接计算一致
        let expected = poseidon_hash(&[
            Fr::from(100u64),
            Fr::from(200u64),
            Fr::from(300u64),
            Fr::from(0u64), // counter = 0
        ]);
        assert_eq!(output, fr_to_bytes_le(&expected));

        // counter 应递增
        assert_eq!(ctx.randomness_counter, 1);
    }

    #[test]
    fn test_get_randomness_counter_increments() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);
        ctx.randomness_seed = Fr::from(1u64);

        // 第一次调用 (counter=0)
        state.write_register(REG_A0, 0x5000);
        registry.dispatch(0x09, &mut ctx, &mut state).unwrap();
        let out1 = read_bytes(&state, 0x5000, 32);

        // 第二次调用 (counter=1)
        state.write_register(REG_A0, 0x5100);
        registry.dispatch(0x09, &mut ctx, &mut state).unwrap();
        let out2 = read_bytes(&state, 0x5100, 32);

        assert_ne!(out1, out2, "不同 counter 应产生不同 randomness");
        assert_eq!(ctx.randomness_counter, 2);
    }

    #[test]
    fn test_get_randomness_deterministic() {
        let registry = full_registry();

        // 第一次
        let mut state1 = VmState::new();
        let mut ctx1 = SyscallContext::new(vec![]);
        ctx1.randomness_seed = Fr::from(42u64);
        state1.write_register(REG_A0, 0x5000);
        registry.dispatch(0x09, &mut ctx1, &mut state1).unwrap();
        let out1 = read_bytes(&state1, 0x5000, 32);

        // 第二次（相同参数）
        let mut state2 = VmState::new();
        let mut ctx2 = SyscallContext::new(vec![]);
        ctx2.randomness_seed = Fr::from(42u64);
        state2.write_register(REG_A0, 0x5000);
        registry.dispatch(0x09, &mut ctx2, &mut state2).unwrap();
        let out2 = read_bytes(&state2, 0x5000, 32);

        assert_eq!(out1, out2, "相同 seed + counter 应产生相同 randomness");
    }

    // ===== 10. ReadState 测试 =====

    #[test]
    fn test_read_state_whitelisted_slot() {
        use crate::syscalls::host_state::ZkvmHostState;

        /// 测试用 host state — 返回固定值。
        #[derive(Debug)]
        struct TestHostState;
        impl ZkvmHostState for TestHostState {
            fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError> {
                Ok(vec![slot as u8, 0xAA])
            }
        }

        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]).with_host_state(Box::new(TestHostState));

        // 读取 SLOT_GAME_STATE (0x01)
        state.write_register(REG_A0, SLOT_GAME_STATE);
        state.write_register(REG_A1, 0x6000);

        registry.dispatch(0x0A, &mut ctx, &mut state).unwrap();

        let output = read_bytes(&state, 0x6000, 2);
        assert_eq!(output, vec![0x01, 0xAA]);
    }

    #[test]
    fn test_read_state_all_whitelisted_slots() {
        use crate::syscalls::host_state::ZkvmHostState;

        #[derive(Debug)]
        struct TestHostState;
        impl ZkvmHostState for TestHostState {
            fn read_slot(&self, _slot: u32) -> Result<Vec<u8>, ZkvmError> {
                Ok(vec![0xFF])
            }
        }

        let registry = full_registry();
        let whitelisted = [
            SLOT_GAME_STATE,
            SLOT_PLAYER_HANDS,
            SLOT_POT_AMOUNT,
            SLOT_CURRENT_TURN,
            SLOT_ACK_CHAIN,
        ];

        for slot in whitelisted {
            let mut state = VmState::new();
            let mut ctx = SyscallContext::new(vec![]).with_host_state(Box::new(TestHostState));

            state.write_register(REG_A0, slot);
            state.write_register(REG_A1, 0x6000);

            registry.dispatch(0x0A, &mut ctx, &mut state).unwrap();
            assert_eq!(state.read_memory_byte(0x6000).unwrap(), 0xFF);
        }
    }

    #[test]
    fn test_read_state_non_whitelisted_slot() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        // 非白名单 slot
        state.write_register(REG_A0, 0x06);
        state.write_register(REG_A1, 0x6000);

        let err = registry.dispatch(0x0A, &mut ctx, &mut state).unwrap_err();
        assert!(
            matches!(err, ZkvmError::InvalidSlot(0x06)),
            "应返回 InvalidSlot(6)，got {err:?}"
        );
    }

    #[test]
    fn test_read_state_slot_zero_rejected() {
        let registry = full_registry();
        let mut state = VmState::new();
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, 0x00);
        state.write_register(REG_A1, 0x6000);

        let err = registry.dispatch(0x0A, &mut ctx, &mut state).unwrap_err();
        assert!(matches!(err, ZkvmError::InvalidSlot(0x00)));
    }

    #[test]
    fn test_read_state_stub_host_state_error() {
        let registry = full_registry();
        let mut state = VmState::new();
        // 默认 StubHostState
        let mut ctx = SyscallContext::new(vec![]);

        state.write_register(REG_A0, SLOT_GAME_STATE);
        state.write_register(REG_A1, 0x6000);

        let err = registry.dispatch(0x0A, &mut ctx, &mut state).unwrap_err();
        assert!(
            matches!(err, ZkvmError::Other(ref msg) if msg.contains("stub host state")),
            "stub 应返回错误，got {err:?}"
        );
    }

    // ===== 全注册表测试 =====

    #[test]
    fn test_full_registry_all_registered() {
        let registry = full_registry();
        // 31 个 = 10 基础 + 12 BLS12-381 + 2 GameState + 3 Game-specific + 4 Phase 4 proof verify
        assert_eq!(registry.len(), 31, "应注册 31 个 syscall");
        assert!(!registry.is_empty());
    }
}
