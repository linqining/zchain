import PokerLeanExtracted.Model.Constants

/-!
# 下注轮规则（移植自 `poker_lean/PokerLean/State/{Types,Betting}.lean`，镜像 `betting.rs`）

Mathlib-free 纯定义。Rust `process_raise` 返回 `Result<u64, BettingError>` 并
`&mut self`；此处用 `Option (BettingRound × Nat)` 表达成功新状态 + needed。
-/

namespace TexasPoker

structure BettingRound where
  current_bet : Nat
  min_raise : Nat
deriving Repr, DecidableEq

namespace BettingRound

/-- 跟注所需筹码 = `current_bet - seat_bet`（Nat 截断 = Rust saturating_sub）。 -/
def chips_to_call (r : BettingRound) (seat_bet : Nat) : Nat :=
  r.current_bet - seat_bet

/-- 是否可以 check（`chips_to_call == 0`）。 -/
def can_check (r : BettingRound) (seat_bet : Nat) : Bool :=
  decide (chips_to_call r seat_bet = 0)

/-- 是否可以 call（`chips_to_call > 0 && stack > 0`）。 -/
def can_call (r : BettingRound) (seat_bet stack : Nat) : Bool :=
  decide (chips_to_call r seat_bet > 0) && decide (stack > 0)

/-- 是否可以 raise（`stack > chips_to_call`，允许短 all-in）。 -/
def can_raise (r : BettingRound) (seat_bet stack : Nat) : Bool :=
  decide (stack > chips_to_call r seat_bet)

/-- 动作位掩码：fold 永远置位。 -/
def available_actions (r : BettingRound) (seat_bet stack : Nat) : Nat :=
  ACTION_FOLD |||
  (if can_check r seat_bet then ACTION_CHECK else 0) |||
  (if can_call r seat_bet stack then ACTION_CALL else 0) |||
  (if can_raise r seat_bet stack then ACTION_RAISE else 0)

/-- 处理 call：实际跟注金额（all-in 时可能 < chips_to_call）。 -/
def process_call (r : BettingRound) (seat_bet stack : Nat) : Nat :=
  min (chips_to_call r seat_bet) stack

/-- 处理 raise：成功返回 (新状态, needed)，none 表错误。 -/
def process_raise (r : BettingRound) (total_bet seat_bet stack : Nat)
    : Option (BettingRound × Nat) :=
  if total_bet > r.current_bet ∧ total_bet > seat_bet then
    if total_bet - seat_bet > stack then none
    else if total_bet - r.current_bet ≥ r.min_raise then
      some ({ current_bet := total_bet, min_raise := total_bet - r.current_bet },
            total_bet - seat_bet)
    else if total_bet - seat_bet = stack then
      some ({ current_bet := total_bet, min_raise := r.min_raise },
            total_bet - seat_bet)
    else
      none
  else none

end BettingRound
end TexasPoker
