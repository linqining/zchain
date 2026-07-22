//! 游戏相关 syscall 便捷 API。

use crate::syscalls;

/// 扑克牌编码：rank (0-12) + suit (0-3) → 1 字节。
pub fn card_encode(rank: u8, suit: u8) -> u8 {
    let mut out = [0u8; 1];
    syscalls::card_encode(rank, suit, &mut out);
    out[0]
}

/// 扑克牌解码：1 字节 → (rank, suit)。
pub fn card_decode(byte: u8) -> (u8, u8) {
    let mut rank = [0u8; 1];
    let mut suit = [0u8; 1];
    syscalls::card_decode(byte, &mut rank, &mut suit);
    (rank[0], suit[0])
}

/// ZKShuffle 验证。
pub fn shuffle_verify(deck: &[u8], proof: &[u8]) -> bool {
    syscalls::shuffle_verify(deck, proof)
}

/// GameState 读取。返回 host 写入的实际字节数。
pub fn game_state_read(slot: u32, buf: &mut [u8]) -> u32 {
    syscalls::game_state_read(slot, buf)
}

/// GameState 写入。
pub fn game_state_write(slot: u32, data: &[u8]) {
    syscalls::game_state_write(slot, data)
}
