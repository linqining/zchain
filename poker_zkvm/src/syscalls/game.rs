//! Game-specific Syscall 实现（E2E Phase 1 — Task 1.3）。
//!
//! 为 zkvm 新增 3 个 game-specific syscall，支持 texas_poker 合约的高层游戏操作。
//! 复用 `texas_poker/card.rs` 的编码逻辑（避免 crate 间依赖，常量在本文件内硬编码）。
//!
//! # Syscall 列表
//!
//! | ID | 名称 | ABI | 说明 |
//! |----|------|-----|------|
//! | 0x30 | `card_encode` | (rank, suit, out_ptr) | 扑克牌编码为 1 字节索引 |
//! | 0x31 | `card_decode` | (byte, out_rank_ptr, out_suit_ptr) | 扑克牌索引解码为 (rank, suit) |
//! | 0x32 | `shuffle_verify` | (deck_ptr, deck_len, proof_ptr, proof_len) → bool | ZkShuffle 验证（MVP） |
//!
//! # 卡牌编码（与 `texas_poker/card.rs` 一致）
//!
//! - `suit`：0=SPADES, 1=HEARTS, 2=DIAMONDS, 3=CLUBS
//! - `rank`：2..=14（2-10, 11=J, 12=Q, 13=K, 14=A）
//! - `index = suit * 13 + (rank - 2)`，范围 0..52

use crate::error::ZkvmError;
use crate::isa::state::VmState;
use crate::syscalls::gas::{SyscallGasArgs, syscall_gas};
use crate::syscalls::host::read_vm_bytes;
use crate::syscalls::{REG_A0, REG_A1, REG_A2, REG_A3, Syscall, SyscallContext, SyscallId};

// ===== 卡牌常量（与 `texas_poker/card.rs` 保持一致）=====

/// 最小点数（2）。
const TWO: u8 = 2;
/// 最大点数（A）。
const ACE: u8 = 14;
/// 花色数。
const NUM_SUITS: u8 = 4;
/// 每种花色点数数。
const NUM_RANKS_PER_SUIT: u8 = 13;
/// 总牌数。
const TOTAL_CARDS: u8 = 52;

/// ShuffleVerify MVP：proof 最小长度（任意非空 proof 即视为通过）。
const SHUFFLE_PROOF_MIN_LEN: u32 = 1;

// ===== 1. CardEncode (0x30) =====

/// `zkvm_card_encode(rank, suit, out_ptr)` — 扑克牌编码为 1 字节索引。
///
/// ABI：
/// - a0 = rank（2..=14）
/// - a1 = suit（0..=3）
/// - a2 = out_ptr（1 字节输出地址）
/// - 返回：a0 = 1（成功）/ 0（失败：非法 rank/suit）
#[derive(Debug, Clone, Default)]
pub struct CardEncodeSyscall;

impl Syscall for CardEncodeSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::CardEncode
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let rank = state.read_register(REG_A0) as u8;
        let suit = state.read_register(REG_A1) as u8;
        let out_ptr = state.read_register(REG_A2);

        // 校验 rank 与 suit
        if !(TWO..=ACE).contains(&rank) || suit >= NUM_SUITS {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // index = suit * 13 + (rank - 2)
        let index = suit * NUM_RANKS_PER_SUIT + (rank - TWO);
        debug_assert!(index < TOTAL_CARDS);

        // 写入 1 字节
        state.write_memory_byte(out_ptr, index)?;
        state.write_register(REG_A0, 1);
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::CardEncode, &args)
    }
}

// ===== 2. CardDecode (0x31) =====

/// `zkvm_card_decode(byte, out_rank_ptr, out_suit_ptr)` — 扑克牌索引解码。
///
/// ABI：
/// - a0 = byte（0..52）
/// - a1 = out_rank_ptr（1 字节，写入 rank 2..=14）
/// - a2 = out_suit_ptr（1 字节，写入 suit 0..=3）
/// - 返回：a0 = 1（成功）/ 0（失败：非法 byte）
#[derive(Debug, Clone, Default)]
pub struct CardDecodeSyscall;

impl Syscall for CardDecodeSyscall {
    fn id(&self) -> SyscallId {
        SyscallId::CardDecode
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let byte = state.read_register(REG_A0) as u8;
        let out_rank_ptr = state.read_register(REG_A1);
        let out_suit_ptr = state.read_register(REG_A2);

        // 校验 byte 范围
        if byte >= TOTAL_CARDS {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // 反向：suit = byte / 13, rank = (byte % 13) + 2
        let suit = byte / NUM_RANKS_PER_SUIT;
        let rank = (byte % NUM_RANKS_PER_SUIT) + TWO;
        debug_assert!((TWO..=ACE).contains(&rank));
        debug_assert!(suit < NUM_SUITS);

        state.write_memory_byte(out_rank_ptr, rank)?;
        state.write_memory_byte(out_suit_ptr, suit)?;
        state.write_register(REG_A0, 1);
        Ok(())
    }

    fn gas_cost(&self, _state: &VmState) -> u64 {
        let args = SyscallGasArgs::default();
        syscall_gas(SyscallId::CardDecode, &args)
    }
}

// ===== 3. ShuffleVerify (0x32) =====

/// `zkvm_shuffle_verify(deck_ptr, deck_len, proof_ptr, proof_len) -> bool` — ZkShuffle 验证（MVP）。
///
/// ABI：
/// - a0 = deck_ptr（牌组地址，deck_len 字节）
/// - a1 = deck_len（牌组长度，必须 = 52）
/// - a2 = proof_ptr（proof 地址）
/// - a3 = proof_len（proof 长度）
/// - 返回：a0 = 1（验证通过）/ 0（验证失败）
///
/// # MVP 实现
///
/// 当前为 MVP 实现，仅校验：
/// 1. `deck_len == 52`（标准扑克牌组）
/// 2. `proof_len >= 1`（proof 非空）
/// 3. proof 字节全部非零（防止全零 proof 攻击）
///
/// 完整 ZkShuffle 验证（基于 poker_protocol/zk_shuffle）推迟到 Phase 2 集成，
/// 因为它需要链下 sigma proof 全套上下文（transcript、 commitments、
/// ElGamal ciphertexts 等），不在单个 syscall 范围内。
///
/// # 安全说明
///
/// MVP 仅用于 E2E 测试流程演示。生产环境必须替换为完整 ZkShuffle 验证，
/// 否则恶意 prover 可通过伪造 proof 绕过洗牌验证。
#[derive(Debug, Clone, Default)]
pub struct ShuffleVerifySyscall;

impl Syscall for ShuffleVerifySyscall {
    fn id(&self) -> SyscallId {
        SyscallId::ShuffleVerify
    }

    fn host_execute(
        &self,
        _ctx: &mut SyscallContext,
        state: &mut VmState,
    ) -> Result<(), ZkvmError> {
        let deck_ptr = state.read_register(REG_A0);
        let deck_len = state.read_register(REG_A1);
        let proof_ptr = state.read_register(REG_A2);
        let proof_len = state.read_register(REG_A3);

        // MVP 校验 1：deck_len == 52
        if deck_len != u32::from(TOTAL_CARDS) {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // MVP 校验 2：proof 非空
        if proof_len < SHUFFLE_PROOF_MIN_LEN {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // MVP 校验 3：读取 deck 字节并校验每张牌索引唯一（0..52 的排列）
        let deck_bytes = read_vm_bytes(state, deck_ptr, deck_len)?;
        let mut seen = [false; TOTAL_CARDS as usize];
        for &b in &deck_bytes {
            if b >= TOTAL_CARDS || seen[b as usize] {
                // 重复或越界 → 非法 deck
                state.write_register(REG_A0, 0);
                return Ok(());
            }
            seen[b as usize] = true;
        }
        // 所有 52 张牌必须都出现
        if !seen.iter().all(|&v| v) {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // MVP 校验 4：proof 字节非全零
        let proof_bytes = read_vm_bytes(state, proof_ptr, proof_len)?;
        if proof_bytes.iter().all(|&b| b == 0) {
            state.write_register(REG_A0, 0);
            return Ok(());
        }

        // 全部校验通过
        state.write_register(REG_A0, 1);
        Ok(())
    }

    fn gas_cost(&self, state: &VmState) -> u64 {
        // proof_len 用于 PER_BYTE 计费
        let proof_len = state.read_register(REG_A3);
        let args = SyscallGasArgs {
            input_len: proof_len,
            ..Default::default()
        };
        syscall_gas(SyscallId::ShuffleVerify, &args)
    }
}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::state::VmState;
    use crate::syscalls::{REG_A0, REG_A1, REG_A2, REG_A3, SyscallContext};

    // ===== 辅助函数 =====

    /// 创建默认 VmState。
    fn new_state() -> VmState {
        VmState::new()
    }

    /// 创建默认 SyscallContext。
    fn new_ctx() -> SyscallContext {
        SyscallContext::new(vec![])
    }

    // ===== CardEncode 测试 =====

    #[test]
    fn test_card_encode_basic() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let out_ptr = 0x1000u32;

        // 黑桃 A (suit=0, rank=14) → index = 0*13 + (14-2) = 12
        state.write_register(REG_A0, 14); // rank
        state.write_register(REG_A1, 0); // suit
        state.write_register(REG_A2, out_ptr);

        CardEncodeSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 1, "应成功");
        assert_eq!(state.read_memory_byte(out_ptr).unwrap(), 12);
    }

    #[test]
    fn test_card_encode_all_suits() {
        // 红心 2 (suit=1, rank=2) → index = 1*13 + 0 = 13
        // 方块 K (suit=2, rank=13) → index = 2*13 + 11 = 37
        // 梅花 10 (suit=3, rank=10) → index = 3*13 + 8 = 47
        for (suit, rank, expected) in [(1u8, 2u8, 13u8), (2, 13, 37), (3, 10, 47)] {
            let mut state = new_state();
            let mut ctx = new_ctx();
            state.write_register(REG_A0, rank as u32);
            state.write_register(REG_A1, suit as u32);
            state.write_register(REG_A2, 0x1000);

            CardEncodeSyscall
                .host_execute(&mut ctx, &mut state)
                .unwrap();

            assert_eq!(state.read_register(REG_A0), 1);
            assert_eq!(
                state.read_memory_byte(0x1000).unwrap(),
                expected,
                "suit={suit} rank={rank}"
            );
        }
    }

    #[test]
    fn test_card_encode_invalid_rank() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // rank=1（非法，最小是 2）
        state.write_register(REG_A0, 1);
        state.write_register(REG_A1, 0);
        state.write_register(REG_A2, 0x1000);

        CardEncodeSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "非法 rank 应返回 0");
    }

    #[test]
    fn test_card_encode_invalid_suit() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // suit=4（非法，最大是 3）
        state.write_register(REG_A0, 2);
        state.write_register(REG_A1, 4);
        state.write_register(REG_A2, 0x1000);

        CardEncodeSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "非法 suit 应返回 0");
    }

    // ===== CardDecode 测试 =====

    #[test]
    fn test_card_decode_basic() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // index=12 → suit=0, rank=14（黑桃 A）
        state.write_register(REG_A0, 12);
        state.write_register(REG_A1, 0x1000); // out_rank_ptr
        state.write_register(REG_A2, 0x1001); // out_suit_ptr

        CardDecodeSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 1);
        assert_eq!(state.read_memory_byte(0x1000).unwrap(), 14); // rank
        assert_eq!(state.read_memory_byte(0x1001).unwrap(), 0); // suit
    }

    #[test]
    fn test_card_decode_all_indices() {
        // 测试所有 52 个 index 的解码
        for idx in 0..52u8 {
            let mut state = new_state();
            let mut ctx = new_ctx();
            state.write_register(REG_A0, idx as u32);
            state.write_register(REG_A1, 0x1000);
            state.write_register(REG_A2, 0x1001);

            CardDecodeSyscall
                .host_execute(&mut ctx, &mut state)
                .unwrap();

            assert_eq!(state.read_register(REG_A0), 1, "idx={idx} 应成功");
            let rank = state.read_memory_byte(0x1000).unwrap();
            let suit = state.read_memory_byte(0x1001).unwrap();
            assert!((TWO..=ACE).contains(&rank), "rank={rank} 越界");
            assert!(suit < NUM_SUITS, "suit={suit} 越界");
            // 反向校验
            let reencoded = suit * NUM_RANKS_PER_SUIT + (rank - TWO);
            assert_eq!(reencoded, idx, "反向编码不一致");
        }
    }

    #[test]
    fn test_card_decode_invalid_byte() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // byte=52（非法，最大 51）
        state.write_register(REG_A0, 52);
        state.write_register(REG_A1, 0x1000);
        state.write_register(REG_A2, 0x1001);

        CardDecodeSyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "非法 byte 应返回 0");
    }

    // ===== ShuffleVerify MVP 测试 =====

    /// 构造合法 deck（0..52 的排列）。
    fn valid_deck() -> Vec<u8> {
        (0..52).collect()
    }

    /// 写入字节到 VM 内存。
    fn write_bytes(state: &mut VmState, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            state.write_memory_byte(addr + i as u32, b).unwrap();
        }
    }

    #[test]
    fn test_shuffle_verify_valid() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let deck = valid_deck();
        let deck_ptr = 0x2000u32;
        let proof_ptr = 0x3000u32;
        let proof = vec![0xAB; 64]; // 非空 proof

        write_bytes(&mut state, deck_ptr, &deck);
        write_bytes(&mut state, proof_ptr, &proof);

        state.write_register(REG_A0, deck_ptr);
        state.write_register(REG_A1, 52);
        state.write_register(REG_A2, proof_ptr);
        state.write_register(REG_A3, 64);

        ShuffleVerifySyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 1, "合法 deck + proof 应通过");
    }

    #[test]
    fn test_shuffle_verify_invalid_deck_len() {
        let mut state = new_state();
        let mut ctx = new_ctx();

        // deck_len=51（非法）
        state.write_register(REG_A0, 0x2000);
        state.write_register(REG_A1, 51);
        state.write_register(REG_A2, 0x3000);
        state.write_register(REG_A3, 64);

        ShuffleVerifySyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "deck_len!=52 应失败");
    }

    #[test]
    fn test_shuffle_verify_empty_proof() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let deck = valid_deck();
        let deck_ptr = 0x2000u32;
        write_bytes(&mut state, deck_ptr, &deck);

        state.write_register(REG_A0, deck_ptr);
        state.write_register(REG_A1, 52);
        state.write_register(REG_A2, 0x3000);
        state.write_register(REG_A3, 0); // 空 proof

        ShuffleVerifySyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "空 proof 应失败");
    }

    #[test]
    fn test_shuffle_verify_duplicate_card() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        // deck 中 index=0 出现两次
        let mut deck = valid_deck();
        deck[1] = 0; // 重复
        let deck_ptr = 0x2000u32;
        let proof_ptr = 0x3000u32;
        write_bytes(&mut state, deck_ptr, &deck);
        write_bytes(&mut state, proof_ptr, &[0xAB; 64]);

        state.write_register(REG_A0, deck_ptr);
        state.write_register(REG_A1, 52);
        state.write_register(REG_A2, proof_ptr);
        state.write_register(REG_A3, 64);

        ShuffleVerifySyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "重复 card 应失败");
    }

    #[test]
    fn test_shuffle_verify_zero_proof() {
        let mut state = new_state();
        let mut ctx = new_ctx();
        let deck = valid_deck();
        let deck_ptr = 0x2000u32;
        let proof_ptr = 0x3000u32;
        write_bytes(&mut state, deck_ptr, &deck);
        write_bytes(&mut state, proof_ptr, &[0x00; 64]); // 全零 proof

        state.write_register(REG_A0, deck_ptr);
        state.write_register(REG_A1, 52);
        state.write_register(REG_A2, proof_ptr);
        state.write_register(REG_A3, 64);

        ShuffleVerifySyscall
            .host_execute(&mut ctx, &mut state)
            .unwrap();

        assert_eq!(state.read_register(REG_A0), 0, "全零 proof 应失败");
    }

    // ===== Syscall ID 测试 =====

    #[test]
    fn test_syscall_ids() {
        assert_eq!(CardEncodeSyscall.id(), SyscallId::CardEncode);
        assert_eq!(CardDecodeSyscall.id(), SyscallId::CardDecode);
        assert_eq!(ShuffleVerifySyscall.id(), SyscallId::ShuffleVerify);
    }

    // ===== Gas 计费测试 =====

    #[test]
    fn test_gas_costs_nonzero() {
        let state = new_state();
        assert!(CardEncodeSyscall.gas_cost(&state) > 0);
        assert!(CardDecodeSyscall.gas_cost(&state) > 0);
        assert!(ShuffleVerifySyscall.gas_cost(&state) > 0);
    }

    #[test]
    fn test_shuffle_verify_gas_scales_with_proof_len() {
        let mut state_small = new_state();
        state_small.write_register(REG_A3, 32);
        let gas_small = ShuffleVerifySyscall.gas_cost(&state_small);

        let mut state_large = new_state();
        state_large.write_register(REG_A3, 1024);
        let gas_large = ShuffleVerifySyscall.gas_cost(&state_large);

        assert!(
            gas_large > gas_small,
            "proof_len=1024 应比 proof_len=32 收费更高"
        );
    }
}
