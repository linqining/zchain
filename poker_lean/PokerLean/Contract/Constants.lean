/-!
# 合约常量定义

与 `poker_l1/src/vm/contracts/texas_poker/` 中的常量一致。
-/

namespace PokerLean

namespace Constants

/-! 最大玩家数 -/
def MAX_PLAYERS : Nat := 9

/-! 最小玩家数 -/
def MIN_PLAYERS : Nat := 2

/-! 买入倍数（大盲的倍数） -/
def BUYIN_MULTIPLIER : Nat := 10

/-! 最小买入 = 10 × big_blind（以 big_blind 为单位） -/
def minBuyIn (big_blind : Nat) : Nat := BUYIN_MULTIPLIER * big_blind

/-! 最小加注 = big_blind -/
def minRaise (big_blind : Nat) : Nat := big_blind

/-! 最小加注增量 -/
def minRaiseIncrement (current_bet : Nat) : Nat := current_bet

/-! Rake 比例（5%，以整数表示） -/
def RAKE_NUMERATOR : Nat := 5
def RAKE_DENOMINATOR : Nat := 100

/-! 最小 Rake（以大盲为单位） -/
def minRake (big_blind : Nat) : Nat := big_blind / 2

/-! 暗池保留率 -/
def MAUNTAIN_RATIO : Nat := 995  -- 99.5%

/-! 每多一手增加的时间（秒） -/
def EXTRA_TIME_PER_HAND : Nat := 180

end Constants

end PokerLean
