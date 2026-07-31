//! GameState Mock Syscall 实现（E2E Phase 1 — Task 1.4）。
//!
//! 为 zkvm 新增 2 个 GameState mock syscall，在 zkvm 内模拟 ObjectDb 读写。
//! 状态存储在 `SyscallContext.game_state: HashMap<u32, Vec<u8>>` 中，
//! 跨 syscall 调用持久（同一执行上下文内）。
//!
//! # Syscall 列表
//!
//! | ID | 名称 | ABI | 说明 |
//! |----|------|-----|------|
//! | 0x20 | `game_state_read` | (slot, out_ptr, out_len) → actual_len | 从 game_state 读取 |
//! | 0x21 | `game_state_write` | (slot, in_ptr, in_len) | 写入 game_state |
//!
//! # Slot 白名单（与 `host.rs::is_whitelisted_slot` 一致）
//!
//! - `SLOT_GAME_STATE = 0x01`
//! - `SLOT_PLAYER_HANDS = 0x02`
//! - `SLOT_POT_AMOUNT = 0x03`
//! - `SLOT_CURRENT_TURN = 0x04`
//! - `SLOT_ACK_CHAIN = 0x05`
//!
//! # 设计说明
//!
//! 与 `ReadStateSyscall` (0x0A) 的区别：
//! - `ReadState` 通过 `ZkvmHostState` trait 从 host 侧读取链上状态（生产环境用）
//! - `GameStateRead/Write` 在 `SyscallContext.game_state` 中读写（E2E 测试 mock 用）
//!
//! 两者共存：合约在 zkvm 中运行时用 `GameState*` mock 链上状态；
//! 链上 verifier 校验 proof 时通过 `ReadState` 读取真实链上状态。

use crate::error::ZkvmError;
use crate::isa::state::VmState;
use crate::syscalls::gas::{SyscallGasArgs, syscall_gas};
use crate::syscalls::host::{is_whitelisted_slot, read_vm_bytes, write_vm_bytes};
use crate::syscalls::{REG_A0, REG_A1, REG_A2, Syscall, SyscallContext, SyscallId};

// ===== 1. GameStateRead (0x20) =====

/// `zkvm_game_state_read(slot, out_ptr, out_len) -> actual_len` — 从 game_state 读取。
///
/// ABI：
/// - a0 = slot（必须在白名单内）
/// - a1 = out_ptr（输出地址）
/// - a2 = out_len（输出 buffer 最大长度）
/// - 返回：a0 = actual_len（实际读取长度；0 表示 slot 未写入或长度为 0）
///
/// # 截断行为
///
/// 若 slot 值长度 > out_len，仅写入前 out_len 字节，返回 actual_len = out_len。
/// 调用方应通过比较返回值与预期长度判断是否被截断。
///
/// # 错误
///
/// slot 不在白名单内时返回 `Err(ZkvmError::Other(...))`（与 `ReadStateSyscall` 一致）。
#[derive(Debug, Clone, Default)]
pub struct GameStateReadSyscall;

impl Syscall for GameStateReadSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::GameStateRead
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let slot = state.read_register(REG_A0);
        let out_ptr = state.read_register(REG_A1);
        let out_len = state.read_register(REG_A2);

        // 校验 slot 白名单
        if !is_whitelisted_slot(slot) {
            return Err(ZkvmError::Other(format!(
                "game_state_read: slot {slot} not in whitelist"
            )));
        }

        // 从 game_state 读取
        let value = ctx.game_state.get(&slot).cloned().unwrap_or_default();
        let actual_len = (value.len() as u32).min(out_len);

        // 写入 VM 内存（截断至 out_len）
        if actual_len > 0 {
            write_vm_bytes(state, out_ptr, &value[..actual_len as usize])?;
        }

        // 设返回值
        state.write_register(REG_A0, actual_len);
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::GameStateRead, &args)
    }
}

// ===== 2. GameStateWrite (0x21) =====

/// `zkvm_game_state_write(slot, in_ptr, in_len)` — 写入 game_state。
///
/// ABI：
/// - a0 = slot（必须在白名单内）
/// - a1 = in_ptr（输入地址）
/// - a2 = in_len（输入长度）
///
/// # 错误
///
/// slot 不在白名单内时返回 `Err(ZkvmError::Other(...))`。
#[derive(Debug, Clone, Default)]
pub struct GameStateWriteSyscall;

impl Syscall for GameStateWriteSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::GameStateWrite
    }

    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> {
        let slot = state.read_register(REG_A0);
        let in_ptr = state.read_register(REG_A1);
        let in_len = state.read_register(REG_A2);

        // 校验 slot 白名单
        if !is_whitelisted_slot(slot) {
            return Err(ZkvmError::Other(format!(
                "game_state_write: slot {slot} not in whitelist"
            )));
        }

        // 从 VM 内存读取
        let value = if in_len == 0 {
            Vec::new()
        } else {
            read_vm_bytes(state, in_ptr, in_len)?
        };

        // 写入 game_state（覆盖已有值）
        ctx.game_state.insert(slot, value);

        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        // in_len 用于 PER_BYTE 计费
        let in_len = state.read_register(REG_A2);
        let args = SyscallGasArgs {
            input_len: in_len,
            ..Default::default()
        };
        syscall_gas(SyscallId::GameStateWrite, &args)
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::state::VmState;
    use crate::syscalls::host::{
        SLOT_ACK_CHAIN, SLOT_CURRENT_TURN, SLOT_GAME_STATE, SLOT_PLAYER_HANDS, SLOT_POT_AMOUNT,
    };
    use crate::syscalls::{REG_A0, REG_A1, REG_A2, SyscallContext};

    // ===== 辅助函数 =====

    /// 创建默认 VmState。
    fn new_state() -> VmState {
        VmState::new()
    }

    /// 创建默认 SyscallContext。
    fn new_ctx() -> SyscallContext {
        SyscallContext::new(vec![])
    }

    /// 写入字节到 VM 内存。
    fn write_bytes(state: &mut VmState, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            state.write_memory_byte(addr + i as u32, b).unwrap();
        }
    }

    /// 从 VM 内存读取字节。
    fn read_bytes(state: &VmState, addr: u32, len: u32) -> Vec<u8> {
        (0..len)
            .map(|i| state.read_memory_byte(addr + i).unwrap())
            .collect()
    }

    // ===== GameStateRead 测试 =====

    #[test]
    fn test_game_state_read_empty_slot() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        state.write_register(REG_A0, SLOT_GAME_STATE);
        state.write_register(REG_A1, 0x1000);
        state.write_register(REG_A2, 32);

        GameStateReadSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // 空 slot 返回 actual_len=0
        assert_eq!(state.read_register(REG_A0), 0);
    }

    #[test]
    fn test_game_state_read_invalid_slot() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // slot=0x99 不在白名单
        state.write_register(REG_A0, 0x99);
        state.write_register(REG_A1, 0x1000);
        state.write_register(REG_A2, 32);

        let result = GameStateReadSyscall.host_execute(&mut ctx, &mut state);
        assert!(result.is_err(), "非法 slot 应返回 Err");
    }

    #[test]
    fn test_game_state_read_truncation() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // 预写入 64 字节到 slot
        let data: Vec<u8> = (0..64).collect();
        ctx.game_state.insert(SLOT_GAME_STATE, data.clone());

        // 读取但 out_len=32（截断）
        state.write_register(REG_A0, SLOT_GAME_STATE);
        state.write_register(REG_A1, 0x1000);
        state.write_register(REG_A2, 32);

        GameStateReadSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // actual_len = min(64, 32) = 32
        assert_eq!(state.read_register(REG_A0), 32);
        let read = read_bytes(&state, 0x1000, 32);
        assert_eq!(read, &data[..32]);
    }

    // ===== GameStateWrite 测试 =====

    #[test]
    fn test_game_state_write_basic() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
        write_bytes(&mut state, 0x2000, &data);

        state.write_register(REG_A0, SLOT_POT_AMOUNT);
        state.write_register(REG_A1, 0x2000);
        state.write_register(REG_A2, 4);

        GameStateWriteSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // 验证 game_state 已更新
        assert_eq!(ctx.game_state.get(&SLOT_POT_AMOUNT), Some(&data));
    }

    #[test]
    fn test_game_state_write_invalid_slot() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        state.write_register(REG_A0, 0x99); // 非法 slot
        state.write_register(REG_A1, 0x2000);
        state.write_register(REG_A2, 4);

        let result = GameStateWriteSyscall.host_execute(&mut ctx, &mut state);
        assert!(result.is_err(), "非法 slot 应返回 Err");
    }

    #[test]
    fn test_game_state_write_empty_value() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        state.write_register(REG_A0, SLOT_CURRENT_TURN);
        state.write_register(REG_A1, 0x2000);
        state.write_register(REG_A2, 0); // 空 value

        GameStateWriteSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // 验证 game_state 中有空 Vec
        assert_eq!(ctx.game_state.get(&SLOT_CURRENT_TURN), Some(&Vec::new()));
    }

    #[test]
    fn test_game_state_write_overwrites() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // 第一次写入
        let data1 = vec![0x11; 8];
        write_bytes(&mut state, 0x2000, &data1);
        state.write_register(REG_A0, SLOT_PLAYER_HANDS);
        state.write_register(REG_A1, 0x2000);
        state.write_register(REG_A2, 8);
        GameStateWriteSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // 第二次写入（覆盖）
        let data2 = vec![0x22; 4];
        write_bytes(&mut state, 0x3000, &data2);
        state.write_register(REG_A0, SLOT_PLAYER_HANDS);
        state.write_register(REG_A1, 0x3000);
        state.write_register(REG_A2, 4);
        GameStateWriteSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // 验证被覆盖
        assert_eq!(ctx.game_state.get(&SLOT_PLAYER_HANDS), Some(&data2));
    }

    // ===== Write → Read 往返测试 =====

    #[test]
    fn test_game_state_write_read_round_trip() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let data: Vec<u8> = (0..48).collect();

        // Write
        write_bytes(&mut state, 0x2000, &data);
        state.write_register(REG_A0, SLOT_ACK_CHAIN);
        state.write_register(REG_A1, 0x2000);
        state.write_register(REG_A2, 48);
        GameStateWriteSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        // Read
        state.write_register(REG_A0, SLOT_ACK_CHAIN);
        state.write_register(REG_A1, 0x3000);
        state.write_register(REG_A2, 48);
        GameStateReadSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 48);
        let read = read_bytes(&state, 0x3000, 48);
        assert_eq!(read, data);
    }

    #[test]
    fn test_game_state_all_whitelisted_slots() {
        // 测试所有 5 个白名单 slot 都能正常 write→read
        let slots = [
            SLOT_GAME_STATE,
            SLOT_PLAYER_HANDS,
            SLOT_POT_AMOUNT,
            SLOT_CURRENT_TURN,
            SLOT_ACK_CHAIN,
        ];
        for slot in slots {
            let mut state = new_state();
            let mut ctx = new_ctx();
            let data = vec![slot as u8; 16];

            // Write
            write_bytes(&mut state, 0x2000, &data);
            state.write_register(REG_A0, slot);
            state.write_register(REG_A1, 0x2000);
            state.write_register(REG_A2, 16);
            GameStateWriteSyscall
                .host_execute(&mut ctx, &mut state)
                .unwrap();

            // Read
            state.write_register(REG_A0, slot);
            state.write_register(REG_A1, 0x3000);
            state.write_register(REG_A2, 16);
            GameStateReadSyscall
                .host_execute(&mut ctx, &mut state)
                .unwrap();

            assert_eq!(state.read_register(REG_A0), 16, "slot={slot} actual_len");
            let read = read_bytes(&state, 0x3000, 16);
            assert_eq!(read, data, "slot={slot} data mismatch");
        }
    }

    // ===== Syscall ID 测试 =====

    #[test]
    fn test_syscall_ids() {
        assert_eq!(GameStateReadSyscall.id(), SyscallId::GameStateRead);
        assert_eq!(GameStateWriteSyscall.id(), SyscallId::GameStateWrite);
    }

    // ===== Gas 计费测试 =====

    #[test]
    fn test_gas_costs_nonzero() {
        let state = new_state();
        assert!(GameStateReadSyscall.gas_cost(&state) > 0);
        assert!(GameStateWriteSyscall.gas_cost(&state) > 0);
    }

    #[test]
    fn test_game_state_write_gas_scales_with_len() {
        let mut state_small = new_state();
        state_small.write_register(REG_A2, 16);
        let gas_small = GameStateWriteSyscall.gas_cost(&state_small);

        let mut state_large = new_state();
        state_large.write_register(REG_A2, 1024);
        let gas_large = GameStateWriteSyscall.gas_cost(&state_large);

        assert!(gas_large > gas_small, "in_len=1024 应比 in_len=16 收费更高");
    }
}
