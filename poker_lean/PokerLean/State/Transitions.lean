import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.Betting

/-!
# 下注动作的座位更新前缀（非完整 VM transition）

本文件建模 Rust `apply_fold` / `apply_check` / `apply_call` / `apply_raise`
在调用 `advance_turn` 之前的座位级更新，并证明该局部前缀的
**chip 守恒**（筹码不增不减）。VM 公开方法并非“纯下注动作”：
它们会无条件进入 `advance_turn`，可能收池、推进 round 或结算。

## 建模说明

- **座位级操作**（`Seat.apply_*`）是纯函数，直接镜像 Rust 对单个 `Seat` 的修改。
- **桌台级前缀抽象**（`TexasPokerTable.apply_*`）用 `update_nth` 更新第 i 个座位 + `version + 1`。
- **chip 守恒公式**：`total_chips = Σ(stack + bet) + pot + rake_collected + addon_pool + Σ pending_addon`。
  - **不含 `total_bet`**：它是记录字段（= bet + 已入 pot 部分），非独立筹码池；包含会双重计数。
- **未建模的完整 post-state**：`advance_turn` / `collect_bets_to_pot` /
  `advance_round` / `end_without_showdown` / settlement / `timestamps` 更新 /
  `raise` 重置其他玩家 `acted_this_round`。它们可能改变 pot、round、
  多个 seat 和 `current_turn`；因此本文件的 post-state 不能当作完整 VM post-state。
- Rust `checked_sub` / `checked_add` 的溢出检查 ⟷ Lean `Nat` 无溢出 + `inv_chip_bounds` 不变量（Phase 2c）。
-/

namespace TexasPoker

/-! ## List 更新辅助函数 -/

/-- 更新第 i 个元素（0-indexed）。越界时列表不变。 -/
def update_nth {α : Type} : List α → Nat → (α → α) → List α
  | [], _, _ => []
  | x :: xs, 0, f => f x :: xs
  | x :: xs, n + 1, f => x :: update_nth xs n f

@[simp] theorem update_nth_nil {α : Type} (i : Nat) (f : α → α) :
    update_nth [] i f = [] := rfl

@[simp] theorem update_nth_zero {α : Type} (x : α) (xs : List α) (f : α → α) :
    update_nth (x :: xs) 0 f = f x :: xs := rfl

@[simp] theorem update_nth_succ {α : Type} (x : α) (xs : List α) (n : Nat) (f : α → α) :
    update_nth (x :: xs) (n + 1) f = x :: update_nth xs n f := rfl

/-- `update_nth` 保持列表长度。 -/
theorem update_nth_length {α : Type} (l : List α) (i : Nat) (f : α → α) :
    (update_nth l i f).length = l.length := by
  induction l generalizing i with
  | nil => rfl
  | cons x xs ih =>
    cases i with
    | zero => rfl
    | succ n => simp [update_nth, ih n]

/-! ## List 求和与 update_nth 的关键引理 -/

/-- 若 `g` 对**所有**元素保持 `f`，则 `update_nth` 保持 `f` 的求和。 -/
theorem sum_map_update_nth_all {α : Type} (l : List α) (i : Nat) (g : α → α) (f : α → Nat)
    (h : ∀ x, f (g x) = f x) :
    ((update_nth l i g).map f).sum = (l.map f).sum := by
  induction l generalizing i with
  | nil => rfl
  | cons x xs ih =>
    cases i with
    | zero => simp [update_nth, List.map_cons, List.sum_cons, h x]
    | succ n => simp [update_nth, List.map_cons, List.sum_cons, ih n]

/-- 若 `g` 对第 i 个元素保持 `f`，则 `update_nth` 保持 `f` 的求和（仅需该元素满足）。 -/
theorem sum_map_update_nth_at {α : Type} (l : List α) (i : Nat) (g : α → α) (f : α → Nat)
    (h_len : i < l.length)
    (h_at : f (g (List.get l ⟨i, h_len⟩)) = f (List.get l ⟨i, h_len⟩)) :
    ((update_nth l i g).map f).sum = (l.map f).sum := by
  induction l generalizing i with
  | nil => simp at h_len
  | cons x xs ih =>
    cases i with
    | zero =>
      simp [update_nth, List.map_cons, List.sum_cons]
      have hget : List.get (x :: xs) ⟨0, h_len⟩ = x := rfl
      rw [hget] at h_at
      rw [h_at]
    | succ n =>
      simp [update_nth, List.map_cons, List.sum_cons]
      have h_len' : n < xs.length := by simp at h_len; exact h_len
      have h_get : List.get (x :: xs) ⟨n + 1, h_len⟩ = List.get xs ⟨n, h_len'⟩ := rfl
      rw [h_get] at h_at
      exact ih n h_len' h_at

/-! ## 筹码定义 -/

/-- 座位级筹码 = stack + bet（chip 守恒的核心量）。 -/
def seat_chips (s : Seat) : Nat := s.stack + s.bet

/-- 桌台级总筹码 = Σ(stack + bet + pending_addon) + pot + rake_collected。

**不含以下锁仓/子集字段**（否则与座位筹码双重计数）：
- `total_bet`：= bet + 已入 pot 部分，是历史记录。
- `chip_pool`：完整 TableVault 锁仓，与 seat stack/bet/pending/pot 表示的是同一批资金。
- `addon_pool`：`chip_pool` 中 pending addon 的子集；rebuy 不增加它，下一手合并
  pending addon 时相应扣减，因此也不应计入 `total_chips`。
- `ante_collected`：pot 中已含 ante，`ante_collected` 是其子集记录。 -/
def total_chips (t : TexasPokerTable) : Nat :=
  (t.seats.map seat_chips).sum + t.pot + t.rake_collected +
  (t.seats.map Seat.pending_addon).sum

/-! ## 座位级操作（手工镜像 Rust 的局部 seat mutation） -/

namespace Seat

/-- 座位级 fold：标记弃牌，无筹码变动。对应 `state_machine.rs:1922-1923`。 -/
def apply_fold (s : Seat) : Seat :=
  { s with folded := true, acted_this_round := true }

/-- 座位级 check：标记已行动，无筹码变动。对应 `state_machine.rs:1968`。 -/
def apply_check (s : Seat) : Seat :=
  { s with acted_this_round := true }

/-- 座位级 call：从 stack 移 call_amt 到 bet。对应 `state_machine.rs:2003-2017`。

`call_amt = min(chips_to_call, stack)`，对应 Rust `process_call`。 -/
def apply_call (s : Seat) (r : BettingRound) : Seat :=
  let call_amt := r.process_call s.bet s.stack
  { s with
    stack := s.stack - call_amt,
    bet := s.bet + call_amt,
    total_bet := s.total_bet + call_amt,
    all_in := decide (s.stack - call_amt = 0) && decide (call_amt > 0),
    acted_this_round := true }

/-- 座位级 raise：从 stack 移 needed 到 bet，bet 设为 total_bet。对应 `state_machine.rs:2066-2079`。

`needed = total_bet - old_bet`，由 `process_raise` 计算并校验。 -/
def apply_raise (s : Seat) (total_bet : Nat) (needed : Nat) : Seat :=
  { s with
    stack := s.stack - needed,
    bet := total_bet,
    total_bet := s.total_bet + needed,
    all_in := decide (s.stack - needed = 0),
    acted_this_round := true }

/-! ### 座位级 chip 守恒 -/

/-- fold 不改变 seat_chips。 -/
theorem apply_fold_seat_chips (s : Seat) : seat_chips s.apply_fold = seat_chips s := rfl

/-- check 不改变 seat_chips。 -/
theorem apply_check_seat_chips (s : Seat) : seat_chips s.apply_check = seat_chips s := rfl

/-- call 保持 seat_chips：stack 减 call_amt，bet 加 call_amt，净变化为 0。

`call_amt ≤ stack`（由 `process_call = min _ stack` 保证），故截断减法无损。 -/
theorem apply_call_seat_chips (s : Seat) (r : BettingRound) :
    seat_chips (s.apply_call r) = seat_chips s := by
  simp [apply_call, seat_chips, BettingRound.process_call]
  have h_le : min (r.current_bet - s.bet) s.stack ≤ s.stack := Nat.min_le_right _ _
  omega

/-- raise 保持 seat_chips：stack 减 needed，bet 加 needed（via total_bet = old_bet + needed）。

需 `total_bet = s.bet + needed`（来自 `process_raise` + `total_bet > s.bet`）和 `needed ≤ s.stack`。 -/
theorem apply_raise_seat_chips (s : Seat) (total_bet : Nat) (needed : Nat)
    (h_needed : total_bet = s.bet + needed) (h_le : needed ≤ s.stack) :
    seat_chips (s.apply_raise total_bet needed) = seat_chips s := by
  simp [apply_raise, seat_chips]
  omega

/-- fold 不改变 pending_addon。 -/
theorem apply_fold_pending_addon (s : Seat) : s.apply_fold.pending_addon = s.pending_addon := rfl

/-- check 不改变 pending_addon。 -/
theorem apply_check_pending_addon (s : Seat) : s.apply_check.pending_addon = s.pending_addon := rfl

/-- call 不改变 pending_addon。 -/
theorem apply_call_pending_addon (s : Seat) (r : BettingRound) :
    (s.apply_call r).pending_addon = s.pending_addon := rfl

/-- raise 不改变 pending_addon。 -/
theorem apply_raise_pending_addon (s : Seat) (total_bet needed : Nat) :
    (s.apply_raise total_bet needed).pending_addon = s.pending_addon := rfl

/-- fold 不改变 stack。 -/
theorem apply_fold_stack (s : Seat) : s.apply_fold.stack = s.stack := rfl

/-- fold 不改变 bet。 -/
theorem apply_fold_bet (s : Seat) : s.apply_fold.bet = s.bet := rfl

/-- check 不改变 stack。 -/
theorem apply_check_stack (s : Seat) : s.apply_check.stack = s.stack := rfl

/-- check 不改变 bet。 -/
theorem apply_check_bet (s : Seat) : s.apply_check.bet = s.bet := rfl

/-- call 后 stack 减少 call_amt。 -/
theorem apply_call_stack (s : Seat) (r : BettingRound) :
    (s.apply_call r).stack = s.stack - r.process_call s.bet s.stack := by
  simp [apply_call]

/-- call 后 bet 增加 call_amt。 -/
theorem apply_call_bet (s : Seat) (r : BettingRound) :
    (s.apply_call r).bet = s.bet + r.process_call s.bet s.stack := by
  simp [apply_call]

/-- raise 后 stack 减少 needed。 -/
theorem apply_raise_stack (s : Seat) (total_bet needed : Nat) :
    (s.apply_raise total_bet needed).stack = s.stack - needed := rfl

/-- raise 后 bet = total_bet。 -/
theorem apply_raise_bet (s : Seat) (total_bet needed : Nat) :
    (s.apply_raise total_bet needed).bet = total_bet := rfl

/-- raise 后 total_bet 增加 needed。 -/
theorem apply_raise_total_bet (s : Seat) (total_bet needed : Nat) :
    (s.apply_raise total_bet needed).total_bet = s.total_bet + needed := rfl

/-- call 后 acted_this_round = true。 -/
theorem apply_call_acted (s : Seat) (r : BettingRound) :
    (s.apply_call r).acted_this_round = true := rfl

/-- raise 后 acted_this_round = true。 -/
theorem apply_raise_acted (s : Seat) (total_bet needed : Nat) :
    (s.apply_raise total_bet needed).acted_this_round = true := rfl

/-- fold 后 folded = true。 -/
theorem apply_fold_folded (s : Seat) : s.apply_fold.folded = true := rfl

end Seat

/-! ## 桌台级局部前缀抽象 -/

/-- 桌台级 fold 的座位更新前缀：更新第 i 个座位 + version + 1。 -/
def apply_fold (t : TexasPokerTable) (i : Nat) : TexasPokerTable :=
  { t with
    seats := update_nth t.seats i Seat.apply_fold,
    version := t.version + 1 }

/-- 桌台级 check 的座位更新前缀：更新第 i 个座位 + version + 1。 -/
def apply_check (t : TexasPokerTable) (i : Nat) : TexasPokerTable :=
  { t with
    seats := update_nth t.seats i Seat.apply_check,
    version := t.version + 1 }

/-- 桌台级 call 的座位更新前缀：更新第 i 个座位 + version + 1。

`betting_round = none` 时返回原桌台（Rust 中会返回 Err，此处简化）。
该定义不包含后续 `advance_turn`。 -/
def apply_call (t : TexasPokerTable) (i : Nat) : TexasPokerTable :=
  match t.betting_round with
  | none => t
  | some r =>
    { t with
      seats := update_nth t.seats i (fun s => s.apply_call r),
      version := t.version + 1 }

/-- 桌台级 raise 的座位更新前缀：给定 `process_raise` 成功结果，更新桌台。

该定义不包含后续 `advance_turn`。`Option` 包装在 `apply_raise_opt` 中。 -/
def apply_raise (t : TexasPokerTable) (i : Nat) (total_bet : Nat)
    (r' : BettingRound) (needed : Nat) : TexasPokerTable :=
  { t with
    seats := update_nth t.seats i (fun s => Seat.apply_raise s total_bet needed),
    betting_round := some r',
    version := t.version + 1 }

/-- 桌台级 raise（Option 版）：调用 `process_raise`，成功则返回新桌台。 -/
def apply_raise_opt (t : TexasPokerTable) (i : Nat) (total_bet : Nat) : Option TexasPokerTable :=
  match t.betting_round, t.seats.get? i with
  | some r, some seat =>
    match r.process_raise total_bet seat.bet seat.stack with
    | some (r', needed) => some (apply_raise t i total_bet r' needed)
    | none => none
  | _, _ => none

/-! ## 桌台级 chip 守恒 -/

/-- 辅助：更新第 i 个座位后，pot / rake_collected / addon_pool 不变。 -/
theorem apply_preserves_non_seat_chips (t : TexasPokerTable) (i : Nat) (g : Seat → Seat) :
    let t' := { t with seats := update_nth t.seats i g, version := t.version + 1 : TexasPokerTable }
    t'.pot = t.pot ∧ t'.rake_collected = t.rake_collected ∧ t'.addon_pool = t.addon_pool ∧
    t'.seats.length = t.seats.length := by
  intro t'
  simp [t', update_nth_length]

/-- fold 保持 total_chips：fold 不动筹码。 -/
theorem apply_fold_chip_conservation (t : TexasPokerTable) (i : Nat) :
    total_chips (apply_fold t i) = total_chips t := by
  simp [apply_fold, total_chips, update_nth_length]
  have h_chips : ((update_nth t.seats i Seat.apply_fold).map seat_chips).sum =
      (t.seats.map seat_chips).sum :=
    sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_fold_seat_chips s)
  have h_pa : ((update_nth t.seats i Seat.apply_fold).map Seat.pending_addon).sum =
      (t.seats.map Seat.pending_addon).sum :=
    sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_fold_pending_addon s)
  rw [h_chips, h_pa]

/-- check 保持 total_chips：check 不动筹码。 -/
theorem apply_check_chip_conservation (t : TexasPokerTable) (i : Nat) :
    total_chips (apply_check t i) = total_chips t := by
  simp [apply_check, total_chips, update_nth_length]
  have h_chips : ((update_nth t.seats i Seat.apply_check).map seat_chips).sum =
      (t.seats.map seat_chips).sum :=
    sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_check_seat_chips s)
  have h_pa : ((update_nth t.seats i Seat.apply_check).map Seat.pending_addon).sum =
      (t.seats.map Seat.pending_addon).sum :=
    sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_check_pending_addon s)
  rw [h_chips, h_pa]

/-- call 保持 total_chips：stack 减 call_amt，bet 加 call_amt，净变化 0。

`betting_round = none` 时桌台不变，平凡保持。 -/
theorem apply_call_chip_conservation (t : TexasPokerTable) (i : Nat) :
    total_chips (apply_call t i) = total_chips t := by
  cases h_br : t.betting_round with
  | none => simp [apply_call, h_br]
  | some r =>
    simp [apply_call, h_br, total_chips, update_nth_length]
    have h_chips : ((update_nth t.seats i (fun s => s.apply_call r)).map seat_chips).sum =
        (t.seats.map seat_chips).sum :=
      sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_call_seat_chips s r)
    have h_pa : ((update_nth t.seats i (fun s => s.apply_call r)).map Seat.pending_addon).sum =
        (t.seats.map Seat.pending_addon).sum :=
      sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_call_pending_addon s r)
    rw [h_chips, h_pa]

/-- raise 保持 total_chips：stack 减 needed，bet 加 needed（via total_bet = old_bet + needed）。

需 `i < seats.length`（座位存在）+ `process_raise` 成功的前置条件。 -/
theorem apply_raise_chip_conservation (t : TexasPokerTable) (i : Nat) (total_bet : Nat)
    (r' : BettingRound) (needed : Nat) (r : BettingRound) (seat : Seat)
    (h_round : t.betting_round = some r)
    (h_len : i < t.seats.length)
    (h_seat : t.seats.get ⟨i, h_len⟩ = seat)
    (h_process : r.process_raise total_bet seat.bet seat.stack = some (r', needed)) :
    total_chips (apply_raise t i total_bet r' needed) = total_chips t := by
  -- 从 process_raise 成功提取关键信息
  obtain ⟨h_cb, h_sb, h_le_stack, h_needed_eq, h_r_cb, h_or⟩ :=
    BettingRound.process_raise_success_structure r total_bet seat.bet seat.stack r' needed h_process
  -- h_needed_eq : needed = total_bet - seat.bet
  -- h_le_stack : total_bet - seat.bet ≤ seat.stack
  -- h_sb : total_bet > seat.bet → total_bet = seat.bet + needed（无截断）
  have h_needed : total_bet = seat.bet + needed := by omega
  -- needed ≤ seat.stack（从 h_le_stack + h_needed_eq 推出）
  have h_needed_le_stack : needed ≤ seat.stack := by rw [h_needed_eq]; exact h_le_stack
  -- 简化 total_chips
  simp [apply_raise, total_chips, update_nth_length, h_round]
  -- seat_chips：对第 i 个元素（= seat）保持
  have h_chips : ((update_nth t.seats i (fun s => Seat.apply_raise s total_bet needed)).map seat_chips).sum =
      (t.seats.map seat_chips).sum := by
    apply sum_map_update_nth_at t.seats i _ seat_chips h_len
    rw [h_seat]
    exact Seat.apply_raise_seat_chips seat total_bet needed h_needed h_needed_le_stack
  -- pending_addon：对所有元素保持
  have h_pa : ((update_nth t.seats i (fun s => Seat.apply_raise s total_bet needed)).map Seat.pending_addon).sum =
      (t.seats.map Seat.pending_addon).sum :=
    sum_map_update_nth_all _ _ _ _ (fun s => Seat.apply_raise_pending_addon s total_bet needed)
  rw [h_chips, h_pa]

/-! ## 版本号严格递增 -/

theorem apply_fold_version (t : TexasPokerTable) (i : Nat) :
    (apply_fold t i).version = t.version + 1 := rfl

theorem apply_check_version (t : TexasPokerTable) (i : Nat) :
    (apply_check t i).version = t.version + 1 := rfl

theorem apply_call_version (t : TexasPokerTable) (i : Nat) (h : t.betting_round.isSome) :
    (apply_call t i).version = t.version + 1 := by
  cases h_br : t.betting_round with
  | none => simp [h_br] at h
  | some r => simp [apply_call, h_br]

theorem apply_raise_version (t : TexasPokerTable) (i : Nat) (total_bet : Nat)
    (r' : BettingRound) (needed : Nat) :
    (apply_raise t i total_bet r' needed).version = t.version + 1 := rfl

/-! ## 局部前缀中 round_state 不变（不是完整 VM transition 的结论） -/

theorem apply_fold_round_state (t : TexasPokerTable) (i : Nat) :
    (apply_fold t i).round_state = t.round_state := rfl

theorem apply_check_round_state (t : TexasPokerTable) (i : Nat) :
    (apply_check t i).round_state = t.round_state := rfl

theorem apply_call_round_state (t : TexasPokerTable) (i : Nat) :
    (apply_call t i).round_state = t.round_state := by
  cases h : t.betting_round with
  | none => simp [apply_call, h]
  | some r => simp [apply_call, h]

theorem apply_raise_round_state (t : TexasPokerTable) (i : Nat) (total_bet : Nat)
    (r' : BettingRound) (needed : Nat) :
    (apply_raise t i total_bet r' needed).round_state = t.round_state := rfl

/-! ## 局部前缀中 pot 不变（pot 在后续 `collect_bets_to_pot` 中才改变） -/

theorem apply_fold_pot (t : TexasPokerTable) (i : Nat) :
    (apply_fold t i).pot = t.pot := rfl

theorem apply_check_pot (t : TexasPokerTable) (i : Nat) :
    (apply_check t i).pot = t.pot := rfl

theorem apply_call_pot (t : TexasPokerTable) (i : Nat) :
    (apply_call t i).pot = t.pot := by
  cases h : t.betting_round with
  | none => simp [apply_call, h]
  | some r => simp [apply_call, h]

theorem apply_raise_pot (t : TexasPokerTable) (i : Nat) (total_bet : Nat)
    (r' : BettingRound) (needed : Nat) :
    (apply_raise t i total_bet r' needed).pot = t.pot := rfl

end TexasPoker
