//! Texas Poker 下注规则（移植自 `texas_poker_move/sources/betting.move`）。
//!
//! 包含下注轮状态、跟注/加注/检查的校验与处理逻辑。
//! 关键修复点（与 Move 端一致）：
//! - M-D7: `can_raise` 用 `stack > to_call` 允许短 all-in
//! - M-D8: 减法前 assert 防 u64 下溢

use serde::{Deserialize, Serialize};

use super::constants::{ACTION_CALL, ACTION_CHECK, ACTION_FOLD, ACTION_RAISE};

/// 下注轮状态。
///
/// 对应 Move `BettingRound` struct（betting.move:24-30）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BettingRound {
    /// 当前轮最高下注。
    pub current_bet: u64,
    /// 最小加注增量。
    pub min_raise: u64,
    /// 大盲注（= min_raise 初始值）。
    pub big_blind: u64,
    /// 最后一个加注者的 seat_index。
    pub last_raiser_seat: Option<u8>,
    /// 已处理动作数（含 fold）。
    pub actions_taken: u64,
}

impl BettingRound {
    /// 创建 preflop 下注轮（current_bet = big_blind, min_raise = big_blind）。
    #[must_use]
    pub fn new_preflop(big_blind: u64) -> Self {
        assert!(big_blind > 0, "big_blind 必须 > 0");
        Self {
            current_bet: big_blind,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat: None,
            actions_taken: 0,
        }
    }

    /// 创建 postflop 下注轮（current_bet = 0, min_raise = big_blind）。
    #[must_use]
    pub fn new_postflop(big_blind: u64) -> Self {
        assert!(big_blind > 0, "big_blind 必须 > 0");
        Self {
            current_bet: 0,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat: None,
            actions_taken: 0,
        }
    }

    /// 计算跟注所需筹码。
    ///
    /// `chips_to_call = max(current_bet - seat_bet, 0)`。
    #[must_use]
    pub fn chips_to_call(&self, seat_bet: u64) -> u64 {
        if self.current_bet > seat_bet {
            self.current_bet - seat_bet
        } else {
            0
        }
    }

    /// 是否可以 check（chips_to_call == 0）。
    #[must_use]
    pub fn can_check(&self, seat_bet: u64) -> bool {
        self.chips_to_call(seat_bet) == 0
    }

    /// 是否可以 call（chips_to_call > 0 && stack > 0）。
    #[must_use]
    pub fn can_call(&self, seat_bet: u64, stack: u64) -> bool {
        self.chips_to_call(seat_bet) > 0 && stack > 0
    }

    /// 是否可以 raise（stack > chips_to_call，M-D7：允许短 all-in）。
    #[must_use]
    pub fn can_raise(&self, seat_bet: u64, stack: u64) -> bool {
        let to_call = self.chips_to_call(seat_bet);
        stack > to_call
    }

    /// 获取可用动作位掩码。
    #[must_use]
    pub fn available_actions(&self, seat_bet: u64, stack: u64) -> u8 {
        let mut mask = 0u8;
        mask |= ACTION_FOLD; // fold 永远可用
        if self.can_check(seat_bet) {
            mask |= ACTION_CHECK;
        }
        if self.can_call(seat_bet, stack) {
            mask |= ACTION_CALL;
        }
        if self.can_raise(seat_bet, stack) {
            mask |= ACTION_RAISE;
        }
        mask
    }

    /// 处理 call，返回实际跟注金额（处理 all-in 时 call < chips_to_call）。
    ///
    /// 镜像 `betting.move` 中 call 处理逻辑：
    /// `call_amount = min(chips_to_call, stack)`
    #[must_use]
    pub fn process_call(&self, seat_bet: u64, stack: u64) -> u64 {
        let to_call = self.chips_to_call(seat_bet);
        to_call.min(stack)
    }

    /// 处理 raise，返回玩家需补的筹码（needed = total_bet - seat_bet）。
    ///
    /// 镜像 `betting.move:102-136`（process_raise）：
    /// - 校验 total_bet > current_bet
    /// - 校验 total_bet > seat_bet
    /// - 计算 raise_amount = total_bet - current_bet
    /// - all-in 情况：仅当 raise_amount >= min_raise 时更新状态
    /// - 非 all-in：强制 min_raise 检查并更新状态
    ///
    /// # Errors
    /// - `total_bet <= current_bet`
    /// - `total_bet <= seat_bet`
    /// - `needed > stack`
    /// - 非 all-in 且 `raise_amount < min_raise`
    pub fn process_raise(
        &mut self,
        total_bet: u64,
        seat_id: u8,
        seat_bet: u64,
        stack: u64,
    ) -> Result<u64, BettingError> {
        if total_bet <= self.current_bet {
            return Err(BettingError::InvalidRaiseAmount);
        }
        if total_bet <= seat_bet {
            return Err(BettingError::InvalidRaiseAmount);
        }
        // M-D8: 减法前 assert 防止 u64 下溢
        assert!(total_bet > self.current_bet);
        let raise_amount = total_bet - self.current_bet;
        assert!(total_bet > seat_bet);
        let needed = total_bet - seat_bet;

        if needed > stack {
            return Err(BettingError::CannotRaise);
        }

        if needed == stack {
            // all-in 情况：仅当 raise_amount >= min_raise 时才更新状态
            if raise_amount >= self.min_raise {
                self.min_raise = raise_amount;
                self.last_raiser_seat = Some(seat_id);
            }
            // 短 all-in（raise_amount < min_raise）：不更新，不重新打开行动权
        } else {
            // 非 all-in：强制 min_raise 检查并更新状态
            if raise_amount < self.min_raise {
                return Err(BettingError::InvalidRaiseAmount);
            }
            self.min_raise = raise_amount;
            self.last_raiser_seat = Some(seat_id);
        }

        self.current_bet = total_bet;
        self.actions_taken += 1;
        Ok(needed)
    }
}

/// 下注错误类型。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BettingError {
    #[error("invalid raise amount")]
    InvalidRaiseAmount,
    #[error("cannot raise: insufficient stack")]
    CannotRaise,
    #[error("not player's turn")]
    NotPlayerTurn,
    #[error("player folded or all-in")]
    PlayerInactive,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_preflop() {
        let round = BettingRound::new_preflop(100);
        assert_eq!(round.current_bet, 100);
        assert_eq!(round.min_raise, 100);
        assert_eq!(round.big_blind, 100);
        assert!(round.last_raiser_seat.is_none());
    }

    #[test]
    fn test_new_postflop() {
        let round = BettingRound::new_postflop(100);
        assert_eq!(round.current_bet, 0);
        assert_eq!(round.min_raise, 100);
    }

    #[test]
    fn test_chips_to_call() {
        let round = BettingRound::new_preflop(100);
        assert_eq!(round.chips_to_call(0), 100); // SB 需补 100
        assert_eq!(round.chips_to_call(50), 50); // SB 已下 50，需补 50
        assert_eq!(round.chips_to_call(100), 0); // BB 已下 100，无需补
        assert_eq!(round.chips_to_call(200), 0); // 超过 current_bet，无需补
    }

    #[test]
    fn test_can_check() {
        let round = BettingRound::new_preflop(100);
        assert!(!round.can_check(0)); // SB 不能 check
        assert!(round.can_check(100)); // BB 能 check
    }

    #[test]
    fn test_process_call() {
        let round = BettingRound::new_preflop(100);
        assert_eq!(round.process_call(0, 1000), 100); // 正常 call
        assert_eq!(round.process_call(0, 50), 50); // all-in call（< to_call）
        assert_eq!(round.process_call(100, 1000), 0); // 已满，无需 call
    }

    #[test]
    fn test_process_raise_normal() {
        let mut round = BettingRound::new_preflop(100);
        // 正常加注：current_bet=100, raise to 300, raise_amount=200 >= min_raise=100
        let needed = round.process_raise(300, 0, 0, 1000).unwrap();
        assert_eq!(needed, 300);
        assert_eq!(round.current_bet, 300);
        assert_eq!(round.min_raise, 200);
        assert_eq!(round.last_raiser_seat, Some(0));
    }

    #[test]
    fn test_process_raise_all_in_sufficient() {
        let mut round = BettingRound::new_preflop(100);
        // all-in 加注：stack=300, total_bet=300, needed=300=stack, raise_amount=200 >= min_raise
        let needed = round.process_raise(300, 0, 0, 300).unwrap();
        assert_eq!(needed, 300);
        assert_eq!(round.min_raise, 200); // 更新
        assert_eq!(round.last_raiser_seat, Some(0));
    }

    #[test]
    fn test_process_raise_all_in_short() {
        let mut round = BettingRound::new_preflop(100);
        round.process_raise(300, 0, 0, 1000).unwrap(); // min_raise 现在是 200
        // 短 all-in：total_bet=400, raise_amount=100 < min_raise=200, needed=400=stack
        let needed = round.process_raise(400, 1, 0, 400).unwrap();
        assert_eq!(needed, 400);
        // min_raise 不更新（短 all-in）
        assert_eq!(round.min_raise, 200);
        assert_eq!(round.last_raiser_seat, Some(0)); // 不更新 last_raiser
        assert_eq!(round.current_bet, 400); // 但 current_bet 更新
    }

    #[test]
    fn test_process_raise_below_min_rejected() {
        let mut round = BettingRound::new_preflop(100);
        // 非 all-in，raise_amount < min_raise
        let result = round.process_raise(150, 0, 0, 1000);
        assert_eq!(result, Err(BettingError::InvalidRaiseAmount));
    }

    #[test]
    fn test_process_raise_insufficient_stack() {
        let mut round = BettingRound::new_preflop(100);
        // needed > stack
        let result = round.process_raise(500, 0, 0, 400);
        assert_eq!(result, Err(BettingError::CannotRaise));
    }

    #[test]
    fn test_available_actions() {
        let round = BettingRound::new_preflop(100);
        // SB: bet=0, stack=1000 → fold + call + raise
        let actions = round.available_actions(0, 1000);
        assert!(actions & ACTION_FOLD != 0);
        assert!(actions & ACTION_CALL != 0);
        assert!(actions & ACTION_RAISE != 0);
        assert!(actions & ACTION_CHECK == 0);

        // BB: bet=100, stack=1000 → fold + check + raise
        let actions = round.available_actions(100, 1000);
        assert!(actions & ACTION_CHECK != 0);
        assert!(actions & ACTION_CALL == 0);
    }
}
