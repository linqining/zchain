//! Texas Poker 合约状态常量（移植自 `texas_poker_move/sources/table_constants.move`）。
//!
//! 所有常量值与 Move 端逐字节一致，确保状态机语义不变。

// ===== 玩家与牌组 =====

/// 最少开局玩家数。
pub const MIN_PLAYERS_TO_START: u8 = 2;

/// 最多玩家数。
pub const MAX_PLAYERS: u8 = 9;

/// 每个玩家手牌数（德州扑克固定 2 张）。
pub const CARDS_PER_PLAYER: u8 = 2;

/// 牌组总数。
pub const N_CARDS: u8 = 52;

/// 公共牌 owner 哨兵值（`u64::MAX`）。
pub const COMMUNITY_CARD_OWNER: u64 = u64::MAX;

// ===== Round 状态（round_state 字段）=====

/// 等待开始。
pub const ROUND_WAITING: u8 = 0;
/// 翻牌前。
pub const ROUND_PREFLOP: u8 = 2;
/// 翻牌（3 张公共牌）。
pub const ROUND_FLOP: u8 = 3;
/// 转牌（第 4 张公共牌）。
pub const ROUND_TURN: u8 = 4;
/// 河牌（第 5 张公共牌）。
pub const ROUND_RIVER: u8 = 5;
/// 摊牌。
pub const ROUND_SHOWDOWN: u8 = 6;

// ===== Shuffle Phase（shuffle_state.phase 字段）=====

pub const SHUFFLE_PHASE_NONE: u8 = 0;
pub const SHUFFLE_PHASE_WAITING: u8 = 1;
pub const SHUFFLE_PHASE_RECONSTRUCT: u8 = 2;
pub const SHUFFLE_PHASE_BEFORE_PREFLOP: u8 = 3;

// ===== Reveal Phase（reveal_token_state.reveal_phase 字段）=====

pub const REVEAL_PHASE_NONE: u8 = 0;
pub const REVEAL_PHASE_PREFLOP: u8 = 1;
pub const REVEAL_PHASE_REDEAL: u8 = 2;
pub const REVEAL_PHASE_FLOP: u8 = 3;
pub const REVEAL_PHASE_TURN: u8 = 4;
pub const REVEAL_PHASE_RIVER: u8 = 5;
pub const REVEAL_PHASE_SHOWDOWN: u8 = 6;

// ===== Reconstruct Phase（reconstruct_state.phase 字段）=====

pub const RECONSTRUCT_PHASE_NONE: u8 = 0;
pub const RECONSTRUCT_PHASE_COLLECTING: u8 = 1;
pub const RECONSTRUCT_PHASE_COMPLETE: u8 = 2;

// ===== 下注动作位掩码（betting.rs 用）=====

pub const ACTION_FOLD: u8 = 1;
pub const ACTION_CHECK: u8 = 2;
pub const ACTION_CALL: u8 = 4;
pub const ACTION_RAISE: u8 = 8;

// ===== 退款类型 =====

pub const REFUND_TYPE_STACK_ONLY: u8 = 0;
pub const REFUND_TYPE_STACK_AND_BET: u8 = 1;
pub const REFUND_TYPE_BET_ONLY: u8 = 2;

// ===== 踢人原因 =====

pub const KICK_REASON_TIMEOUT: u8 = 0;
pub const KICK_REASON_ADMIN: u8 = 1;
pub const KICK_REASON_RECONSTRUCT_TIMEOUT: u8 = 2;

// ===== 重置原因 =====

pub const RESET_REASON_TIMEOUT: u8 = 0;
pub const RESET_REASON_KICK: u8 = 1;
pub const RESET_REASON_RECONSTRUCT_FAIL: u8 = 2;
pub const RESET_REASON_LAST_PLAYER_STANDING: u8 = 3;
pub const RESET_REASON_STATE_INCONSISTENT: u8 = 4;

// ===== 弃牌原因 =====

pub const FOLD_REASON_MANUAL: u8 = 0;
pub const FOLD_REASON_AUTO_TIMEOUT: u8 = 1;
pub const FOLD_REASON_FORCE_ADMIN: u8 = 2;

// ===== 牌组重建原因 =====

pub const DECK_REBUILD_REASON_SHUFFLE_TIMEOUT: u8 = 0;
pub const DECK_REBUILD_REASON_RECONSTRUCT_COMPLETE: u8 = 1;

// ===== 金额与超时 =====

/// 1 SUI = 100000 stack（保留语义，zchain 直接用 u64 chip）。
pub const STACK_TO_SUI_RATIO: u64 = 100_000;

/// 最小超时阈值（毫秒）。
pub const MIN_TIMEOUT_MS: u64 = 1_000;

/// 默认超时配置（毫秒）。
pub const DEFAULT_SHUFFLE_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_REVEAL_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_BETTING_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_RECONSTRUCT_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_SHOWDOWN_DISPLAY_MS: u64 = 3_000;
pub const DEFAULT_HAND_COMPLETE_WAIT_MS: u64 = 5_000;
pub const DEFAULT_READY_WAIT_MS: u64 = 5_000;

/// 边池总下注上限（防溢出）。
pub const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_state_constants() {
        assert_eq!(ROUND_WAITING, 0);
        assert_eq!(ROUND_PREFLOP, 2);
        assert_eq!(ROUND_FLOP, 3);
        assert_eq!(ROUND_TURN, 4);
        assert_eq!(ROUND_RIVER, 5);
        assert_eq!(ROUND_SHOWDOWN, 6);
    }

    #[test]
    fn test_shuffle_phase_constants() {
        assert_eq!(SHUFFLE_PHASE_NONE, 0);
        assert_eq!(SHUFFLE_PHASE_BEFORE_PREFLOP, 3);
    }

    #[test]
    fn test_player_limits() {
        assert_eq!(MIN_PLAYERS_TO_START, 2);
        assert_eq!(MAX_PLAYERS, 9);
        assert_eq!(CARDS_PER_PLAYER, 2);
        assert_eq!(N_CARDS, 52);
    }
}
