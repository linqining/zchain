import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types

/-!
# 下注轮规则（镜像 `poker_l1/src/vm/contracts/texas_poker/betting.rs`）

与 Rust `betting.rs` 逐函数对应。`BettingRound` 结构已在 `Types.lean` 定义
（2 字段 `current_bet` / `min_raise`，与 Rust `betting.rs:17-23` 一致）。

本文件补全：`chips_to_call` / `can_check` / `can_call` / `can_raise` /
`available_actions` / `process_call` / `process_raise`，并证明关键性质。

## 建模说明

- Rust `u64` 的 `saturating_sub` ⟷ Lean `Nat` 减法（天然截断到 0）。
- Rust `process_raise` 返回 `Result<u64, BettingError>` 并 `&mut self`；
  Lean 用 `Option (BettingRound × Nat)` 表达「成功返回新状态 + needed」，
  `none` 表任意错误（`InvalidRaiseAmount` / `CannotRaise`）。
- 金额用 `Nat`，溢出上界由 `Invariants.lean` 的 `inv_chip_bounds` 约束。
-/

namespace TexasPoker

open Constants

namespace BettingRound

@[simp] theorem new_current_bet (bb cb : Nat) : (new bb cb).current_bet = cb := rfl
@[simp] theorem new_min_raise   (bb cb : Nat) : (new bb cb).min_raise   = bb := rfl

/-! ## chips_to_call（对应 `betting.rs:36-40`） -/

/-- 跟注所需筹码 = `current_bet - seat_bet`（Nat 减法截断到 0）。

对应 `betting.rs:38-40` `chips_to_call`。 -/
def chips_to_call (r : BettingRound) (seat_bet : Nat) : Nat :=
  r.current_bet - seat_bet

@[simp] theorem chips_to_call_def (r : BettingRound) (seat_bet : Nat) :
    chips_to_call r seat_bet = r.current_bet - seat_bet := rfl

/-- `chips_to_call` 与 Rust `saturating_sub` 语义一致：截断到 0。

对应 `betting.rs:39`。Plan 中 `chips_to_call_correct` 定理。 -/
theorem chips_to_call_correct (r : BettingRound) (seat_bet : Nat) :
    chips_to_call r seat_bet = max (r.current_bet - seat_bet) 0 := by
  simp only [chips_to_call]
  exact (Nat.max_eq_left (Nat.zero_le _)).symm

/-! ## can_check / can_call / can_raise（对应 `betting.rs:42-58`） -/

/-- 是否可以 check（`chips_to_call == 0`）。对应 `betting.rs:44-46`。 -/
def can_check (r : BettingRound) (seat_bet : Nat) : Bool :=
  decide (chips_to_call r seat_bet = 0)

/-- 是否可以 call（`chips_to_call > 0 && stack > 0`）。对应 `betting.rs:50-52`。 -/
def can_call (r : BettingRound) (seat_bet stack : Nat) : Bool :=
  decide (chips_to_call r seat_bet > 0) && decide (stack > 0)

/-- 是否可以 raise（`stack > chips_to_call`，允许短 all-in）。对应 `betting.rs:56-58`。 -/
def can_raise (r : BettingRound) (seat_bet stack : Nat) : Bool :=
  decide (stack > chips_to_call r seat_bet)

@[simp] theorem can_check_iff (r : BettingRound) (seat_bet : Nat) :
    can_check r seat_bet = true ↔ chips_to_call r seat_bet = 0 := by
  simp only [can_check, decide_eq_true_iff]

@[simp] theorem can_call_iff (r : BettingRound) (seat_bet stack : Nat) :
    can_call r seat_bet stack = true ↔
      chips_to_call r seat_bet > 0 ∧ stack > 0 := by
  simp only [can_call, Bool.and_eq_true_iff, decide_eq_true_iff]

@[simp] theorem can_raise_iff (r : BettingRound) (seat_bet stack : Nat) :
    can_raise r seat_bet stack = true ↔ stack > chips_to_call r seat_bet := by
  simp only [can_raise, decide_eq_true_iff]

/-! ## ACTION 位不相交性（具体 Nat 事实，由 decide 证明）

`ACTION_FOLD=1`(bit0), `ACTION_CHECK=2`(bit1), `ACTION_CALL=4`(bit2), `ACTION_RAISE=8`(bit3)
两两不相交。 -/

theorem ACTION_disj_fold_check : ACTION_FOLD &&& ACTION_CHECK = 0 := by decide
theorem ACTION_disj_fold_call  : ACTION_FOLD &&& ACTION_CALL  = 0 := by decide
theorem ACTION_disj_fold_raise : ACTION_FOLD &&& ACTION_RAISE = 0 := by decide
theorem ACTION_disj_check_call  : ACTION_CHECK &&& ACTION_CALL  = 0 := by decide
theorem ACTION_disj_check_raise : ACTION_CHECK &&& ACTION_RAISE = 0 := by decide
theorem ACTION_disj_call_raise  : ACTION_CALL  &&& ACTION_RAISE = 0 := by decide

/-! ## available_actions（对应 `betting.rs:60-74`）

采用 `base ||| (if c then BIT else 0)` 形式，便于按位提取证明。 -/

/-- 获取可用动作位掩码。对应 `betting.rs:62-74`。`fold` 永远置位。 -/
def available_actions (r : BettingRound) (seat_bet stack : Nat) : Nat :=
  ACTION_FOLD |||
  (if can_check r seat_bet then ACTION_CHECK else 0) |||
  (if can_call r seat_bet stack then ACTION_CALL else 0) |||
  (if can_raise r seat_bet stack then ACTION_RAISE else 0)

/-- 辅助：`(if c then k else 0) &&& k = if c then k else 0`。 -/
private theorem if_band_self (c : Bool) (k : Nat) :
    (if c then k else 0) &&& k = if c then k else 0 := by
  by_cases hc : c = true
  · rw [if_pos hc, Nat.and_self]
  · rw [if_neg hc, Nat.zero_and]

/-- 辅助：`a &&& k = 0` ⟹ `(if c then a else 0) &&& k = 0`。 -/
private theorem if_band_disj (c : Bool) (a k : Nat) (h : a &&& k = 0) :
    (if c then a else 0) &&& k = 0 := by
  by_cases hc : c = true
  · rw [if_pos hc]; exact h
  · rw [if_neg hc, Nat.zero_and]

/-- CHECK 位提取：掩码的 CHECK 位仅由 `can_check` 控制。 -/
theorem available_actions_check_band (r : BettingRound) (seat_bet stack : Nat) :
    available_actions r seat_bet stack &&& ACTION_CHECK =
      (if can_check r seat_bet then ACTION_CHECK else 0) := by
  simp only [available_actions]
  rw [Nat.and_distrib_right, Nat.and_distrib_right, Nat.and_distrib_right]
  rw [ACTION_disj_fold_check, if_band_self,
      if_band_disj _ ACTION_CALL ACTION_CHECK ACTION_disj_check_call,
      if_band_disj _ ACTION_RAISE ACTION_CHECK ACTION_disj_check_raise]
  simp only [Nat.or_zero, Nat.zero_or]

/-- CALL 位提取。 -/
theorem available_actions_call_band (r : BettingRound) (seat_bet stack : Nat) :
    available_actions r seat_bet stack &&& ACTION_CALL =
      (if can_call r seat_bet stack then ACTION_CALL else 0) := by
  simp only [available_actions]
  rw [Nat.and_distrib_right, Nat.and_distrib_right, Nat.and_distrib_right]
  rw [ACTION_disj_fold_call,
      if_band_disj _ ACTION_CHECK ACTION_CALL ACTION_disj_check_call, if_band_self,
      if_band_disj _ ACTION_RAISE ACTION_CALL ACTION_disj_call_raise]
  simp only [Nat.or_zero, Nat.zero_or]

/-- RAISE 位提取。 -/
theorem available_actions_raise_band (r : BettingRound) (seat_bet stack : Nat) :
    available_actions r seat_bet stack &&& ACTION_RAISE =
      (if can_raise r seat_bet stack then ACTION_RAISE else 0) := by
  simp only [available_actions]
  rw [Nat.and_distrib_right, Nat.and_distrib_right, Nat.and_distrib_right]
  rw [ACTION_disj_fold_raise,
      if_band_disj _ ACTION_CHECK ACTION_RAISE ACTION_disj_check_raise,
      if_band_disj _ ACTION_CALL ACTION_RAISE ACTION_disj_call_raise, if_band_self]
  simp only [Nat.or_zero, Nat.zero_or]

/-- FOLD 位提取：恒置位。 -/
theorem available_actions_fold_band (r : BettingRound) (seat_bet stack : Nat) :
    available_actions r seat_bet stack &&& ACTION_FOLD = ACTION_FOLD := by
  simp only [available_actions]
  rw [Nat.and_distrib_right, Nat.and_distrib_right, Nat.and_distrib_right]
  rw [Nat.and_self,
      if_band_disj _ ACTION_CHECK ACTION_FOLD ACTION_disj_fold_check,
      if_band_disj _ ACTION_CALL ACTION_FOLD ACTION_disj_fold_call,
      if_band_disj _ ACTION_RAISE ACTION_FOLD ACTION_disj_fold_raise]
  simp only [Nat.or_zero, Nat.zero_or]

/-- `fold` 永远在可用动作中。 -/
theorem available_actions_fold_always (r : BettingRound) (seat_bet stack : Nat) :
    available_actions r seat_bet stack &&& ACTION_FOLD ≠ 0 := by
  rw [available_actions_fold_band]; decide

/-- `check` 在掩码中当且仅当 `can_check`。 -/
theorem available_actions_check_iff (r : BettingRound) (seat_bet stack : Nat) :
    (available_actions r seat_bet stack &&& ACTION_CHECK) ≠ 0 ↔
    can_check r seat_bet = true := by
  rw [available_actions_check_band]
  by_cases hc : can_check r seat_bet = true
  · simp only [hc, if_true]; decide
  · simp only [hc, if_false, Nat.zero_and]; decide

/-- `call` 在掩码中当且仅当 `can_call`。 -/
theorem available_actions_call_iff (r : BettingRound) (seat_bet stack : Nat) :
    (available_actions r seat_bet stack &&& ACTION_CALL) ≠ 0 ↔
    can_call r seat_bet stack = true := by
  rw [available_actions_call_band]
  by_cases hc : can_call r seat_bet stack = true
  · simp only [hc, if_true]; decide
  · simp only [hc, if_false, Nat.zero_and]; decide

/-- `raise` 在掩码中当且仅当 `can_raise`。 -/
theorem available_actions_raise_iff (r : BettingRound) (seat_bet stack : Nat) :
    (available_actions r seat_bet stack &&& ACTION_RAISE) ≠ 0 ↔
    can_raise r seat_bet stack = true := by
  rw [available_actions_raise_band]
  by_cases hc : can_raise r seat_bet stack = true
  · simp only [hc, if_true]; decide
  · simp only [hc, if_false, Nat.zero_and]; decide

/-! ## process_call（对应 `betting.rs:76-80`） -/

/-- 处理 call，返回实际跟注金额（all-in 时可能 < chips_to_call）。对应 `betting.rs:78-80`。 -/
def process_call (r : BettingRound) (seat_bet stack : Nat) : Nat :=
  min (chips_to_call r seat_bet) stack

theorem process_call_le_chips_to_call (r : BettingRound) (seat_bet stack : Nat) :
    process_call r seat_bet stack ≤ chips_to_call r seat_bet :=
  Nat.min_le_left _ _

theorem process_call_le_stack (r : BettingRound) (seat_bet stack : Nat) :
    process_call r seat_bet stack ≤ stack :=
  Nat.min_le_right _ _

/-! ## process_raise（对应 `betting.rs:94-121`）

核心规则：
- `total_bet > current_bet` 且 `total_bet > seat_bet`（否则 `InvalidRaiseAmount`）。
- `needed = total_bet - seat_bet`；`needed > stack` 则 `CannotRaise`。
- `raise_amount = total_bet - current_bet`：
  - `≥ min_raise`：合法，更新 `min_raise := raise_amount`。
  - `< min_raise` 且 all-in（`needed == stack`）：合法，**不**更新 `min_raise`。
  - `< min_raise` 且非 all-in：拒绝。 -/

/-- `process_raise`：成功返回 `(新状态, needed)`，`none` 表错误。对应 `betting.rs:94-121`。

注：内联 `raise_amount` / `needed`（不用 `let`），便于 `rw` + `if_pos/if_neg` 推理。 -/
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

/-! ### process_raise 成功结构抽取（主引理） -/

/-- **主引理**：`process_raise` 成功时的完整结构。

成功 ⟹ (1) `total_bet > current_bet` 且 `> seat_bet`；(2) `needed ≤ stack`；
       (3) `n = needed`；(4) `r'.current_bet = total_bet`；
       (5) 要么 `raise_amount ≥ min_raise` 且 `r'.min_raise = raise_amount`，
           要么短 all-in（`raise_amount < min_raise` 且 `needed = stack`）且 `r'.min_raise = r.min_raise`。 -/
theorem process_raise_success_structure (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    total_bet > r.current_bet ∧ total_bet > seat_bet ∧
    (total_bet - seat_bet) ≤ stack ∧
    n = total_bet - seat_bet ∧
    r'.current_bet = total_bet ∧
    ((total_bet - r.current_bet ≥ r.min_raise ∧ r'.min_raise = total_bet - r.current_bet) ∨
     (¬ (total_bet - r.current_bet ≥ r.min_raise) ∧ (total_bet - seat_bet) = stack ∧
      r'.min_raise = r.min_raise)) := by
  -- 外层条件：total_bet > current_bet ∧ total_bet > seat_bet
  by_cases h_gt : total_bet > r.current_bet ∧ total_bet > seat_bet
  case pos =>
    -- 注意：先使用 h_gt 做 rw，再拆解（obtain 会消耗 h_gt）
    rw [process_raise, if_pos h_gt] at h
    obtain ⟨h_cb, h_sb⟩ := h_gt
    -- 内层 1：needed > stack ?
    by_cases h_stack : total_bet - seat_bet > stack
    · rw [if_pos h_stack] at h
      exact absurd h (by simp)  -- none = some _ 不可由 decide 证（含自由变量）
    · rw [if_neg h_stack] at h
      -- 内层 2：raise_amount ≥ min_raise ?
      by_cases h_ra : total_bet - r.current_bet ≥ r.min_raise
      · rw [if_pos h_ra] at h
        -- 两层 injection：先拆 some，再拆 Prod
        injection h with hpair
        injection hpair with h1 h2
        subst h1
        refine ⟨h_cb, h_sb, ?_, h2.symm, rfl, Or.inl ⟨h_ra, rfl⟩⟩
        · omega  -- h_stack : ¬(needed > stack) ⊢ needed ≤ stack
      · rw [if_neg h_ra] at h
        -- 内层 3：needed = stack ?
        by_cases h_eq : total_bet - seat_bet = stack
        · rw [if_pos h_eq] at h
          injection h with hpair
          injection hpair with h1 h2
          subst h1
          refine ⟨h_cb, h_sb, ?_, h2.symm, rfl, Or.inr ⟨h_ra, h_eq, rfl⟩⟩
          · omega  -- h_eq : needed = stack ⊢ needed ≤ stack
        · rw [if_neg h_eq] at h
          exact absurd h (by simp)  -- none = some _
  case neg =>
    rw [process_raise, if_neg h_gt] at h
    exact absurd h (by simp)  -- none = some _

/-! ### 核心定理 1：process_raise 严格增加 current_bet -/

theorem process_raise_strictly_increases_current_bet (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    r'.current_bet > r.current_bet := by
  obtain ⟨h_cb, _, _, _, h_r_cb, _⟩ := process_raise_success_structure _ _ _ _ _ _ h
  rw [h_r_cb]; exact h_cb

/-! ### 核心定理 2：min_raise 非递减 -/

theorem process_raise_min_raise_nondecreasing (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    r'.min_raise ≥ r.min_raise := by
  obtain ⟨_, _, _, _, _, h_or⟩ := process_raise_success_structure _ _ _ _ _ _ h
  rcases h_or with ⟨h_ra, h_mr⟩ | ⟨_, _, h_mr⟩
  · rw [h_mr]; exact h_ra
  · rw [h_mr]

/-! ### 核心定理 3：成功时 current_bet 被设为 total_bet -/

theorem process_raise_success_current_bet (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    r'.current_bet = total_bet := by
  obtain ⟨_, _, _, _, h_r_cb, _⟩ := process_raise_success_structure _ _ _ _ _ _ h
  exact h_r_cb

/-! ### 成功时 needed = total_bet - seat_bet -/

theorem process_raise_success_needed (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    n = total_bet - seat_bet := by
  obtain ⟨_, _, _, h_n, _, _⟩ := process_raise_success_structure _ _ _ _ _ _ h
  exact h_n

/-! ### 成功时 needed ≤ stack -/

theorem process_raise_success_needed_le_stack (r : BettingRound)
    (total_bet seat_bet stack : Nat) (r' : BettingRound) (n : Nat)
    (h : process_raise r total_bet seat_bet stack = some (r', n)) :
    n ≤ stack := by
  obtain ⟨_, _, h_s, h_n, _, _⟩ := process_raise_success_structure _ _ _ _ _ _ h
  rw [h_n]; exact h_s

/-! ### 核心定理 4：available_actions 的 soundness -/

theorem available_actions_sound (r : BettingRound) (seat_bet stack : Nat) :
    (available_actions r seat_bet stack &&& ACTION_FOLD ≠ 0) ∧
    ((available_actions r seat_bet stack &&& ACTION_CHECK ≠ 0) → can_check r seat_bet = true) ∧
    ((available_actions r seat_bet stack &&& ACTION_CALL ≠ 0) → can_call r seat_bet stack = true) ∧
    ((available_actions r seat_bet stack &&& ACTION_RAISE ≠ 0) → can_raise r seat_bet stack = true) := by
  refine ⟨available_actions_fold_always r seat_bet stack,
          available_actions_check_iff r seat_bet stack |>.mp,
          available_actions_call_iff r seat_bet stack |>.mp,
          available_actions_raise_iff r seat_bet stack |>.mp⟩

/-! ### 辅助：can_check / can_call 与金额的关系 -/

theorem can_check_iff_le (r : BettingRound) (seat_bet : Nat) :
    can_check r seat_bet = true ↔ r.current_bet ≤ seat_bet := by
  rw [can_check_iff, chips_to_call]
  constructor
  · exact Nat.le_of_sub_eq_zero
  · exact Nat.sub_eq_zero_of_le

theorem can_call_iff_gt (r : BettingRound) (seat_bet stack : Nat) :
    can_call r seat_bet stack = true ↔ r.current_bet > seat_bet ∧ stack > 0 := by
  rw [can_call_iff, chips_to_call]
  constructor
  · intro ⟨h, hs⟩
    refine ⟨?_, hs⟩
    -- h : r.current_bet - seat_bet > 0 ⊢ r.current_bet > seat_bet
    -- omega 能处理 Nat 截断减法：若 a ≤ b 则 a - b = 0，与 h 矛盾
    omega
  · intro ⟨h, hs⟩
    exact ⟨Nat.sub_pos_of_lt h, hs⟩

end BettingRound

end TexasPoker
