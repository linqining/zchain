import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.Betting
import PokerLean.State.Transitions

/-!
# 状态不变量与扩展 chip 守恒（Phase 2c）

镜像 `state_machine.rs` 中超出 `apply_fold/check/call/raise` 的资金操作，
并定义贯穿全协议的 6 个核心状态不变量。

## 内容

1. **扩展 chip 守恒引理**（5 个）：
   - `apply_addon_chip_conservation`：`total_chips` 增 `amount`（外部入金）
   - `apply_rebuy_chip_conservation`：`total_chips` 增 `amount`（外部入金）
   - `collect_rake_chip_conservation`：`total_chips` 守恒
   - `refund_seat_chip_delta`：单座位退款 delta
   - `collect_ante_chip_delta`：`total_chips` 增 `actual`（Rust 双重计入偏差）

2. **6 个状态不变量**（对应 Plan §6 关键不变量清单 #1-#6）

3. **不变量保持定理**：`apply_fold/check/call/raise` 保持各不变量

## 已知偏差与限制

- **Rust `collect_ante`**（`state_machine.rs:3281-3331`）：同时更新 `bet` 与 `pot`，
  导致 `collect_bets_to_pot` 后续双重计入。本文件如实镜像并证明 delta 关系。
- **`betting_round_completion`**：被 `apply_fold/check/call` 保持，**不被** `apply_raise` 保持
  （raise 重开下注）。由完整下注轮后恢复（Phase 6）。
- **`current_turn_player_active`**（强版）：被 `apply_check` 保持；被 `apply_fold/call/raise`
  打破，由 `advance_turn` 恢复（Phase 6）。本文件仅定义。
- **`version_strictly_monotone`**：保持需前置 `version < U64_MAX`（防 u64 溢出）。
-/

namespace TexasPoker

open Constants

/-! ## 辅助：update_nth 通用保持引理 -/

/-- 若 `f` 对**所有**元素保持 `field`，则 `update_nth` 保持所有元素的 `field ≤ bound`。 -/
theorem update_nth_preserves_field_bound (l : List Seat) (i : Nat) (f : Seat → Seat)
    (field : Seat → Nat) (bound : Nat)
    (h_bound : ∀ s ∈ l, field s ≤ bound)
    (h_preserve : ∀ s, field (f s) = field s) :
    ∀ s ∈ update_nth l i f, field s ≤ bound := by
  induction l generalizing i with
  | nil => intro s hs; simp [update_nth] at hs
  | cons x xs ih =>
    intro s hs
    have h_bound' : ∀ s ∈ xs, field s ≤ bound := fun s' hs' =>
      h_bound s' (List.mem_cons_of_mem x hs')
    cases i with
    | zero =>
      simp [update_nth] at hs
      cases hs with
      | inl h => rw [h, h_preserve]; exact h_bound x (List.mem_cons_self x xs)
      | inr h => exact h_bound s (List.mem_cons_of_mem x h)
    | succ n =>
      simp [update_nth] at hs
      cases hs with
      | inl h => rw [h]; exact h_bound x (List.mem_cons_self x xs)
      | inr h => exact ih n h_bound' s h

/-- 若 `f` 对第 i 个元素保持 `field`（值相等），则 `update_nth` 保持所有元素的 `field ≤ bound`。 -/
theorem update_nth_preserves_field_bound_at (l : List Seat) (i : Nat) (f : Seat → Seat)
    (field : Seat → Nat) (bound : Nat)
    (h_bound : ∀ s ∈ l, field s ≤ bound)
    (h_len : i < l.length)
    (h_at : field (f (l.get ⟨i, h_len⟩)) = field (l.get ⟨i, h_len⟩)) :
    ∀ s ∈ update_nth l i f, field s ≤ bound := by
  induction l generalizing i with
  | nil => simp at h_len
  | cons x xs ih =>
    intro s hs
    have h_bound' : ∀ s ∈ xs, field s ≤ bound := fun s' hs' =>
      h_bound s' (List.mem_cons_of_mem x hs')
    cases i with
    | zero =>
      have hget : (x :: xs).get ⟨0, h_len⟩ = x := rfl
      rw [hget] at h_at
      simp [update_nth] at hs
      cases hs with
      | inl h => rw [h, h_at]; exact h_bound x (List.mem_cons_self x xs)
      | inr h => exact h_bound s (List.mem_cons_of_mem x h)
    | succ n =>
      have h_len' : n < xs.length := by simp at h_len; exact h_len
      have h_get : (x :: xs).get ⟨n + 1, h_len⟩ = xs.get ⟨n, h_len'⟩ := rfl
      rw [h_get] at h_at
      simp [update_nth] at hs
      cases hs with
      | inl h => rw [h]; exact h_bound x (List.mem_cons_self x xs)
      | inr h => exact ih n h_bound' h_len' h_at s h

/-- 若 `f` 在第 i 个元素处使 `field` 增 `delta`，则 `update_nth` 使 `Σ field` 增 `delta`。 -/
theorem sum_map_update_nth_delta (l : List Seat) (i : Nat) (f : Seat → Seat)
    (field : Seat → Nat) (delta : Nat) (h_len : i < l.length)
    (h_at : field (f (l.get ⟨i, h_len⟩)) = field (l.get ⟨i, h_len⟩) + delta) :
    ((update_nth l i f).map field).sum = (l.map field).sum + delta := by
  induction l generalizing i with
  | nil => simp at h_len
  | cons x xs ih =>
    cases i with
    | zero =>
      have hget : (x :: xs).get ⟨0, h_len⟩ = x := rfl
      rw [hget] at h_at
      simp only [update_nth_zero, List.map_cons, List.sum_cons]
      rw [h_at]; omega
    | succ n =>
      have h_len' : n < xs.length := by simp at h_len; exact h_len
      have h_get : (x :: xs).get ⟨n + 1, h_len⟩ = xs.get ⟨n, h_len'⟩ := rfl
      rw [h_get] at h_at
      simp only [update_nth_succ, List.map_cons, List.sum_cons]
      have := ih n h_len' h_at
      omega

/-- 通用 Prop 保持：若 `f` 在第 i 个元素处保持 `P`，且所有原元素满足 `P`，则更新后全满足。 -/
theorem update_nth_preserves_prop (l : List Seat) (i : Nat) (f : Seat → Seat)
    (P : Seat → Prop)
    (h_len : i < l.length)
    (h_all : ∀ s ∈ l, P s)
    (h_at : P (f (l.get ⟨i, h_len⟩))) :
    ∀ s ∈ update_nth l i f, P s := by
  induction l generalizing i with
  | nil => simp at h_len
  | cons x xs ih =>
    intro s hs
    have h_all' : ∀ s ∈ xs, P s := fun s' hs' => h_all s' (List.mem_cons_of_mem x hs')
    cases i with
    | zero =>
      have hget : (x :: xs).get ⟨0, h_len⟩ = x := rfl
      rw [hget] at h_at
      simp only [update_nth_zero, List.mem_cons] at hs
      cases hs with
      | inl h => subst h; exact h_at
      | inr h => exact h_all s (List.mem_cons_of_mem x h)
    | succ n =>
      have h_len' : n < xs.length := by simp at h_len; exact h_len
      have h_get : (x :: xs).get ⟨n + 1, h_len⟩ = xs.get ⟨n, h_len'⟩ := rfl
      rw [h_get] at h_at
      simp only [update_nth_succ, List.mem_cons] at hs
      cases hs with
      | inl h => rw [h]; exact h_all x (List.mem_cons_self x xs)
      | inr h => exact ih n h_len' h_all' h_at s h

/-! ## 扩展 chip 守恒：apply_addon / apply_rebuy / collect_rake / refund / collect_ante -/

/-- `apply_addon`：对应 `state_machine.rs:2984-3033`。 -/
def apply_addon (t : TexasPokerTable) (i : Nat) (amount : Nat) : TexasPokerTable :=
  { t with
    seats := update_nth t.seats i (fun s => { s with pending_addon := s.pending_addon + amount }),
    addon_pool := t.addon_pool + amount,
    version := t.version + 1 }

/-- `apply_rebuy`：对应 `state_machine.rs:3057-3104`。 -/
def apply_rebuy (t : TexasPokerTable) (i : Nat) (amount : Nat) : TexasPokerTable :=
  { t with
    seats := update_nth t.seats i (fun s => { s with stack := s.stack + amount }),
    addon_pool := t.addon_pool + amount,
    version := t.version + 1 }

/-- `collect_rake`：对应 `state_machine.rs:3345-3357`。 -/
def collect_rake (t : TexasPokerTable) (rake : Nat) (h_rake_le : rake ≤ t.pot) : TexasPokerTable :=
  { t with
    pot := t.pot - rake,
    rake_collected := t.rake_collected + rake,
    version := t.version + 1 }

/-- `refund_predicate`：对应 `state_machine.rs:2654`。 -/
def refund_predicate (s : Seat) : Bool :=
  s.is_occupied && !s.folded && !s.left_during_hand && s.total_bet > 0 && !s.refunded

/-- `refund_seat`：对应 `state_machine.rs:2653-2670` 循环体。 -/
def refund_seat (s : Seat) : Seat :=
  if refund_predicate s then
    { s with stack := s.stack + s.total_bet, refunded := true, bet := 0, total_bet := 0 }
  else
    { s with bet := 0, total_bet := 0 }

/-- `refund_all_bets`：对应 `state_machine.rs:2652-2673`。 -/
def refund_all_bets (t : TexasPokerTable) : TexasPokerTable :=
  { t with
    seats := t.seats.map refund_seat,
    pot := 0,
    version := t.version + 1 }

/-- `collect_ante_step`：对应 `state_machine.rs:3305-3330`。 -/
def collect_ante_step (t : TexasPokerTable) (i : Nat) (amount : Nat) : TexasPokerTable :=
  let actual := min amount (t.get_seat i).stack
  { t with
    seats := update_nth t.seats i fun s =>
      { s with
        stack := s.stack - actual,
        bet := s.bet + actual,
        total_bet := s.total_bet + actual,
        all_in := if s.stack - actual = 0 then true else s.all_in },
    ante_collected := t.ante_collected + actual,
    pot := t.pot + actual,
    version := t.version + 1 }

/-! ### apply_addon chip 守恒 -/

theorem apply_addon_seat_chips_sum (t : TexasPokerTable) (i : Nat) (amount : Nat) :
    ((apply_addon t i amount).seats.map seat_chips).sum =
    (t.seats.map seat_chips).sum := by
  have h : ∀ s : Seat, seat_chips { s with pending_addon := s.pending_addon + amount } = seat_chips s := by
    intro s; simp [seat_chips]
  exact sum_map_update_nth_all _ _ _ _ h

theorem apply_addon_pending_sum (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    ((apply_addon t i amount).seats.map Seat.pending_addon).sum =
    (t.seats.map Seat.pending_addon).sum + amount := by
  have h_apply : (apply_addon t i amount).seats =
      update_nth t.seats i (fun s => { s with pending_addon := s.pending_addon + amount }) := rfl
  rw [h_apply]
  apply sum_map_update_nth_delta _ _ _ _ amount h_len
  rfl

/-- **apply_addon chip 守恒**：`total_chips` 增 `amount`。 -/
theorem apply_addon_chip_conservation (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    total_chips (apply_addon t i amount) = total_chips t + amount := by
  unfold total_chips
  rw [apply_addon_seat_chips_sum, apply_addon_pending_sum t i amount h_len]
  simp only [apply_addon]
  omega

/-! ### apply_rebuy chip 守恒 -/

theorem apply_rebuy_seat_chips_sum (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    ((apply_rebuy t i amount).seats.map seat_chips).sum =
    (t.seats.map seat_chips).sum + amount := by
  have h_apply : (apply_rebuy t i amount).seats =
      update_nth t.seats i (fun s => { s with stack := s.stack + amount }) := rfl
  rw [h_apply]
  apply sum_map_update_nth_delta _ _ _ _ amount h_len
  simp [seat_chips]
  omega

theorem apply_rebuy_pending_sum (t : TexasPokerTable) (i : Nat) (amount : Nat) :
    ((apply_rebuy t i amount).seats.map Seat.pending_addon).sum =
    (t.seats.map Seat.pending_addon).sum := by
  have h : ∀ s : Seat, Seat.pending_addon { s with stack := s.stack + amount } = s.pending_addon := by
    intro s; rfl
  exact sum_map_update_nth_all _ _ _ _ h

/-- **apply_rebuy chip 守恒**：`total_chips` 增 `amount`。 -/
theorem apply_rebuy_chip_conservation (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    total_chips (apply_rebuy t i amount) = total_chips t + amount := by
  unfold total_chips
  rw [apply_rebuy_seat_chips_sum t i amount h_len, apply_rebuy_pending_sum]
  simp only [apply_rebuy]
  omega

/-! ### collect_rake chip 守恒 -/

theorem collect_rake_seats_unchanged (t : TexasPokerTable) (rake : Nat) (h_rake_le : rake ≤ t.pot) :
    (collect_rake t rake h_rake_le).seats = t.seats := rfl

/-- **collect_rake chip 守恒**：`total_chips` 不变。 -/
theorem collect_rake_chip_conservation (t : TexasPokerTable) (rake : Nat) (h_rake_le : rake ≤ t.pot) :
    total_chips (collect_rake t rake h_rake_le) = total_chips t := by
  simp [total_chips, collect_rake, collect_rake_seats_unchanged]
  omega

/-! ### refund_seat chip delta -/

theorem refund_seat_pending_addon (s : Seat) :
    (refund_seat s).pending_addon = s.pending_addon := by
  simp [refund_seat, refund_predicate]
  split_ifs <;> rfl

/-- `refund_seat` 后 seat_chips 变化：在 `bet = 0` 前置下增 `total_bet`（若退款）或不变。 -/
theorem refund_seat_chip_delta (s : Seat) (h_bet_zero : s.bet = 0) :
    seat_chips (refund_seat s) = seat_chips s +
      if refund_predicate s then s.total_bet else 0 := by
  by_cases h : refund_predicate s = true
  · -- 退款分支：stack += total_bet, bet = 0
    have h_rs : refund_seat s = { s with stack := s.stack + s.total_bet, refunded := true, bet := 0, total_bet := 0 } := by
      simp [refund_seat, h]
    rw [h_rs]
    -- seat_chips { s with stack := s.stack + s.total_bet, bet := 0, ... } = (s.stack + s.total_bet) + 0
    show (s.stack + s.total_bet) + 0 = (s.stack + s.bet) + if refund_predicate s = true then s.total_bet else 0
    rw [if_pos h]
    omega
  · -- 不退款分支：bet = 0, total_bet = 0（stack 不变）
    -- h : ¬(refund_predicate s = true) 直接让 simp 把 if 归约到 else 分支
    have h_rs : refund_seat s = { s with bet := 0, total_bet := 0 } := by
      simp [refund_seat, h]
    rw [h_rs]
    show (s.stack + 0) = (s.stack + s.bet) + if refund_predicate s = true then s.total_bet else 0
    rw [if_neg h]
    omega

/-! ### collect_ante chip delta -/

/-- 辅助：`get_seat i` 在界内等价于 `List.get`。 -/
theorem get_seat_eq_get (t : TexasPokerTable) (i : Nat) (h_len : i < t.seats.length) :
    t.get_seat i = t.seats.get ⟨i, h_len⟩ := by
  exact List.getD_eq_getElem t.seats Seat.empty h_len

/-- 辅助：`collect_ante_step` 后 pot = t.pot + actual。 -/
theorem collect_ante_step_pot (t : TexasPokerTable) (i : Nat) (amount : Nat) :
    (collect_ante_step t i amount).pot = t.pot + min amount (t.get_seat i).stack := by
  simp [collect_ante_step]

/-- 辅助：`collect_ante_step` 后 rake_collected 不变。 -/
theorem collect_ante_step_rake (t : TexasPokerTable) (i : Nat) (amount : Nat) :
    (collect_ante_step t i amount).rake_collected = t.rake_collected := by
  simp [collect_ante_step]

theorem collect_ante_step_seat_chips_sum (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    ((collect_ante_step t i amount).seats.map seat_chips).sum =
    (t.seats.map seat_chips).sum := by
  have h_seat_eq : t.get_seat i = t.seats.get ⟨i, h_len⟩ := get_seat_eq_get t i h_len
  -- 展开后 actual = min amount (t.get_seat i).stack = min amount (t.seats.get ⟨i, h_len⟩).stack
  have h_apply : (collect_ante_step t i amount).seats =
      update_nth t.seats i fun s =>
        { s with
          stack := s.stack - min amount (t.get_seat i).stack,
          bet := s.bet + min amount (t.get_seat i).stack,
          total_bet := s.total_bet + min amount (t.get_seat i).stack,
          all_in := if s.stack - min amount (t.get_seat i).stack = 0 then true else s.all_in } := rfl
  rw [h_apply]
  apply sum_map_update_nth_at _ _ _ seat_chips h_len
  -- 目标：seat_chips (f (t.seats.get ⟨i, h_len⟩)) = seat_chips (t.seats.get ⟨i, h_len⟩)
  -- 其中 f s = { s with stack := s.stack - actual, bet := s.bet + actual, ... }
  -- actual = min amount (t.get_seat i).stack = min amount (t.seats.get ⟨i, h_len⟩).stack
  simp only [seat_chips]
  -- 用 h_seat_eq 归一化 actual
  rw [h_seat_eq]
  -- 现在 actual = min amount (t.seats.get ⟨i, h_len⟩).stack ≤ (t.seats.get ⟨i, h_len⟩).stack
  have h_le : min amount (t.seats.get ⟨i, h_len⟩).stack ≤ (t.seats.get ⟨i, h_len⟩).stack :=
    Nat.min_le_right _ _
  omega

theorem collect_ante_step_pending_sum (t : TexasPokerTable) (i : Nat) (amount : Nat) :
    ((collect_ante_step t i amount).seats.map Seat.pending_addon).sum =
    (t.seats.map Seat.pending_addon).sum := by
  have h : ∀ s : Seat, Seat.pending_addon
      { s with
        stack := s.stack - min amount (t.get_seat i).stack,
        bet := s.bet + min amount (t.get_seat i).stack,
        total_bet := s.total_bet + min amount (t.get_seat i).stack,
        all_in := if s.stack - min amount (t.get_seat i).stack = 0 then true else s.all_in } =
      s.pending_addon := by
    intro s; rfl
  have h_apply : (collect_ante_step t i amount).seats =
      update_nth t.seats i fun s =>
        { s with
          stack := s.stack - min amount (t.get_seat i).stack,
          bet := s.bet + min amount (t.get_seat i).stack,
          total_bet := s.total_bet + min amount (t.get_seat i).stack,
          all_in := if s.stack - min amount (t.get_seat i).stack = 0 then true else s.all_in } := rfl
  rw [h_apply]
  exact sum_map_update_nth_all _ _ _ _ h

/-- **collect_ante chip delta**：`total_chips` 增 `actual`（Rust 双重计入偏差）。 -/
theorem collect_ante_chip_delta (t : TexasPokerTable) (i : Nat) (amount : Nat)
    (h_len : i < t.seats.length) :
    total_chips (collect_ante_step t i amount) = total_chips t +
      min amount (t.get_seat i).stack := by
  unfold total_chips
  rw [collect_ante_step_seat_chips_sum t i amount h_len,
      collect_ante_step_pending_sum t i amount,
      collect_ante_step_pot, collect_ante_step_rake]
  omega

/-! ## 6 个核心状态不变量 -/

/-- u64 上界（直接用字面量，便于 `omega` 处理）。 -/
def U64_MAX : Nat := 18446744073709551615

@[simp] theorem U64_MAX_eq : U64_MAX = 18446744073709551615 := rfl

/-- **不变量 1：金额上界**。 -/
def inv_chip_bounds (t : TexasPokerTable) : Prop :=
  t.pot ≤ MAX_TOTAL_BET ∧
  t.ante_collected ≤ MAX_TOTAL_BET ∧
  t.rake_collected ≤ MAX_TOTAL_BET ∧
  t.addon_pool ≤ MAX_TOTAL_BET ∧
  ∀ s ∈ t.seats,
    s.total_bet + s.stack ≤ MAX_TOTAL_BET ∧
    s.stack + s.bet ≤ MAX_TOTAL_BET ∧
    s.pending_addon ≤ MAX_TOTAL_BET

/-- **不变量 2：状态一致性**（子相位互斥）。 -/
def inv_state_consistency (t : TexasPokerTable) : Prop :=
  t.is_betting_round = true →
    t.shuffle_state.phase = SHUFFLE_PHASE_NONE ∧
    t.reveal_token_state.reveal_phase = REVEAL_PHASE_NONE ∧
    t.reconstruct_state.phase = RECONSTRUCT_PHASE_NONE

/-- **不变量 3：当前行动者索引良构**（强版需 `advance_turn`，Phase 6）。 -/
def current_turn_well_formed (t : TexasPokerTable) : Prop :=
  ∀ i, t.current_turn = some i →
    i < t.max_players ∧ i < t.seats.length

/-- **强版不变量 3'**：当前行动者参与中、未弃牌、未 all-in（Phase 6 配合 `advance_turn`）。 -/
def current_turn_player_active (t : TexasPokerTable) : Prop :=
  ∀ i, t.current_turn = some i →
    (∃ s, t.seats.get? i = some s ∧
      s.is_participating = true ∧
      s.folded = false ∧
      s.all_in = false)

/-- **不变量 4：下注轮完成性**（被 `apply_fold/check/call` 保持，不被 `apply_raise` 保持）。 -/
def betting_round_completion (t : TexasPokerTable) : Prop :=
  t.betting_round.isSome →
    (∀ s ∈ t.seats, s.is_participating = true →
      s.acted_this_round = true ∧
      s.bet = (t.betting_round.getD (BettingRound.new 0 0)).current_bet)

/-- **不变量 5：addon 挂起语义**（恒真占位，完整语义在 Phase 6）。 -/
def addon_pending_semantics (t : TexasPokerTable) : Prop :=
  ∀ s ∈ t.seats, s.pending_addon > 0 → True

/-- **不变量 6：版本单调**（`version ≤ U64_MAX`；mutation 需 `version < U64_MAX` 前置）。 -/
def version_strictly_monotone (t : TexasPokerTable) : Prop :=
  t.version ≤ U64_MAX

/-- 全部 6 个不变量的合取。 -/
def all_invariants (t : TexasPokerTable) : Prop :=
  inv_chip_bounds t ∧ inv_state_consistency t ∧
  current_turn_well_formed t ∧ betting_round_completion t ∧
  addon_pending_semantics t ∧ version_strictly_monotone t

/-! ## apply_* 保持不变量 -/

/-! ### inv_state_consistency 保持（apply_* 不动 round_state / 子相位字段） -/

theorem apply_fold_preserves_inv_state_consistency (t : TexasPokerTable) (i : Nat) :
    inv_state_consistency t → inv_state_consistency (apply_fold t i) := fun h => h

theorem apply_check_preserves_inv_state_consistency (t : TexasPokerTable) (i : Nat) :
    inv_state_consistency t → inv_state_consistency (apply_check t i) := fun h => h

/-- `apply_call` 用 `match`，需分情况归约。 -/
theorem apply_call_preserves_inv_state_consistency (t : TexasPokerTable) (i : Nat) :
    inv_state_consistency t → inv_state_consistency (apply_call t i) := by
  intro h
  cases h_br : t.betting_round with
  | none => simp only [apply_call, h_br]; exact h
  | some r => simp only [apply_call, h_br]; exact h

theorem apply_raise_preserves_inv_state_consistency (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat) :
    inv_state_consistency t → inv_state_consistency (apply_raise t i total_bet r' needed) :=
  fun h => h

/-! ### version_strictly_monotone 保持（需 `version < U64_MAX` 前置防溢出） -/

theorem apply_fold_preserves_version (t : TexasPokerTable) (i : Nat)
    (h_pre : t.version < U64_MAX) :
    version_strictly_monotone t → version_strictly_monotone (apply_fold t i) := by
  intro h
  have h_ver : (apply_fold t i).version = t.version + 1 := apply_fold_version t i
  unfold version_strictly_monotone at *
  rw [h_ver, U64_MAX_eq] at *
  omega

theorem apply_check_preserves_version (t : TexasPokerTable) (i : Nat)
    (h_pre : t.version < U64_MAX) :
    version_strictly_monotone t → version_strictly_monotone (apply_check t i) := by
  intro h
  have h_ver : (apply_check t i).version = t.version + 1 := apply_check_version t i
  unfold version_strictly_monotone at *
  rw [h_ver, U64_MAX_eq] at *
  omega

theorem apply_call_preserves_version (t : TexasPokerTable) (i : Nat)
    (h_pre : t.version < U64_MAX) (h : t.betting_round.isSome) :
    version_strictly_monotone t → version_strictly_monotone (apply_call t i) := by
  intro hv
  have h_ver : (apply_call t i).version = t.version + 1 := apply_call_version t i h
  unfold version_strictly_monotone at *
  rw [h_ver, U64_MAX_eq] at *
  omega

theorem apply_raise_preserves_version (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat)
    (h_pre : t.version < U64_MAX) :
    version_strictly_monotone t →
    version_strictly_monotone (apply_raise t i total_bet r' needed) := by
  intro h
  have h_ver : (apply_raise t i total_bet r' needed).version = t.version + 1 :=
    apply_raise_version t i total_bet r' needed
  unfold version_strictly_monotone at *
  rw [h_ver, U64_MAX_eq] at *
  omega

/-! ### addon_pending_semantics 保持（恒真） -/

theorem apply_fold_preserves_addon_semantics (t : TexasPokerTable) (i : Nat) :
    addon_pending_semantics t → addon_pending_semantics (apply_fold t i) := by
  intro h; simp [addon_pending_semantics]

theorem apply_check_preserves_addon_semantics (t : TexasPokerTable) (i : Nat) :
    addon_pending_semantics t → addon_pending_semantics (apply_check t i) := by
  intro h; simp [addon_pending_semantics]

theorem apply_call_preserves_addon_semantics (t : TexasPokerTable) (i : Nat) :
    addon_pending_semantics t → addon_pending_semantics (apply_call t i) := by
  intro h; simp [addon_pending_semantics]

theorem apply_raise_preserves_addon_semantics (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat) :
    addon_pending_semantics t →
    addon_pending_semantics (apply_raise t i total_bet r' needed) := by
  intro h; simp [addon_pending_semantics]

/-! ### current_turn_well_formed 保持 -/

theorem apply_fold_preserves_current_turn (t : TexasPokerTable) (i : Nat) :
    current_turn_well_formed t → current_turn_well_formed (apply_fold t i) := by
  intro h j hj
  have := h j hj
  refine ⟨this.1, ?_⟩
  have h_len : (apply_fold t i).seats.length = t.seats.length := by
    simp [apply_fold, update_nth_length]
  rw [h_len]; exact this.2

theorem apply_check_preserves_current_turn (t : TexasPokerTable) (i : Nat) :
    current_turn_well_formed t → current_turn_well_formed (apply_check t i) := by
  intro h j hj
  have := h j hj
  refine ⟨this.1, ?_⟩
  have h_len : (apply_check t i).seats.length = t.seats.length := by
    simp [apply_check, update_nth_length]
  rw [h_len]; exact this.2

/-- `apply_call` 用 `match`，需显式归一化 `current_turn` / `max_players` / `seats.length`。 -/
theorem apply_call_preserves_current_turn (t : TexasPokerTable) (i : Nat) :
    current_turn_well_formed t → current_turn_well_formed (apply_call t i) := by
  intro h j hj
  -- (apply_call t i).current_turn = t.current_turn（apply_call 不改 current_turn 字段）
  have h_ct : (apply_call t i).current_turn = t.current_turn := by
    cases h_br : t.betting_round with
    | none => simp [apply_call, h_br]
    | some r => simp [apply_call, h_br]
  rw [h_ct] at hj
  -- match 使 (apply_call t i).max_players 卡住，需显式归一化
  have h_max : (apply_call t i).max_players = t.max_players := by
    cases h_br : t.betting_round with
    | none => simp [apply_call, h_br]
    | some r => simp [apply_call, h_br]
  have h_len : (apply_call t i).seats.length = t.seats.length := by
    cases h_br : t.betting_round with
    | none => simp [apply_call, h_br]
    | some r => simp [apply_call, h_br, update_nth_length]
  rw [h_max]
  have this := h j hj
  refine ⟨this.1, ?_⟩
  rw [h_len]; exact this.2

theorem apply_raise_preserves_current_turn (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat) :
    current_turn_well_formed t →
    current_turn_well_formed (apply_raise t i total_bet r' needed) := by
  intro h j hj
  have := h j hj
  refine ⟨this.1, ?_⟩
  have h_len : (apply_raise t i total_bet r' needed).seats.length = t.seats.length := by
    simp [apply_raise, update_nth_length]
  rw [h_len]; exact this.2

/-! ### betting_round_completion 保持 -/

/-- 辅助：`(apply_fold t i).betting_round = t.betting_round`。 -/
theorem apply_fold_betting_round (t : TexasPokerTable) (i : Nat) :
    (apply_fold t i).betting_round = t.betting_round := rfl

/-- 辅助：`(apply_check t i).betting_round = t.betting_round`。 -/
theorem apply_check_betting_round (t : TexasPokerTable) (i : Nat) :
    (apply_check t i).betting_round = t.betting_round := rfl

/-- 辅助：`(apply_call t i).betting_round = t.betting_round`（需分情况）。 -/
theorem apply_call_betting_round (t : TexasPokerTable) (i : Nat) :
    (apply_call t i).betting_round = t.betting_round := by
  cases h_br : t.betting_round with
  | none => simp [apply_call, h_br]
  | some r => simp [apply_call, h_br]

/-- `apply_fold` 保持 `betting_round_completion`：fold 使 seats[i] 不再 participating。 -/
theorem apply_fold_preserves_betting_completion (t : TexasPokerTable) (i : Nat)
    (h_len : i < t.seats.length) :
    betting_round_completion t → betting_round_completion (apply_fold t i) := by
  intro h hbr s hs hpart
  have hbr' : t.betting_round.isSome := by
    rw [← apply_fold_betting_round t i]; exact hbr
  have h_mem : s ∈ update_nth t.seats i Seat.apply_fold := by
    simp [apply_fold] at hs; exact hs
  -- 归一化目标的 current_bet
  have h_cb_app : ((apply_fold t i).betting_round.getD (BettingRound.new 0 0)).current_bet =
      (t.betting_round.getD (BettingRound.new 0 0)).current_bet := by
    rw [apply_fold_betting_round]
  rw [h_cb_app]
  -- 第 i 个座位：fold 后 folded=true → is_participating=false → 蕴涵平凡
  have h_at : (Seat.apply_fold (t.seats.get ⟨i, h_len⟩)).is_participating = true →
      (Seat.apply_fold (t.seats.get ⟨i, h_len⟩)).acted_this_round = true ∧
      (Seat.apply_fold (t.seats.get ⟨i, h_len⟩)).bet =
        (t.betting_round.getD (BettingRound.new 0 0)).current_bet := by
    intro hp
    simp [Seat.apply_fold, Seat.is_participating] at hp
  have h_all : ∀ s' ∈ t.seats, s'.is_participating = true →
      s'.acted_this_round = true ∧
      s'.bet = (t.betting_round.getD (BettingRound.new 0 0)).current_bet :=
    fun s' hs' => h hbr' s' hs'
  exact update_nth_preserves_prop t.seats i Seat.apply_fold
    (fun s' => s'.is_participating = true → s'.acted_this_round = true ∧
      s'.bet = (t.betting_round.getD (BettingRound.new 0 0)).current_bet)
    h_len h_all h_at s h_mem hpart

/-- `apply_check` 保持 `betting_round_completion`：check 不改 bet，acted 保持 true。 -/
theorem apply_check_preserves_betting_completion (t : TexasPokerTable) (i : Nat)
    (h_len : i < t.seats.length) :
    betting_round_completion t → betting_round_completion (apply_check t i) := by
  intro h hbr s hs hpart
  have hbr' : t.betting_round.isSome := by
    rw [← apply_check_betting_round t i]; exact hbr
  have h_mem : s ∈ update_nth t.seats i Seat.apply_check := by
    simp [apply_check] at hs; exact hs
  have h_cb_app : ((apply_check t i).betting_round.getD (BettingRound.new 0 0)).current_bet =
      (t.betting_round.getD (BettingRound.new 0 0)).current_bet := by
    rw [apply_check_betting_round]
  rw [h_cb_app]
  have h_at : (Seat.apply_check (t.seats.get ⟨i, h_len⟩)).is_participating = true →
      (Seat.apply_check (t.seats.get ⟨i, h_len⟩)).acted_this_round = true ∧
      (Seat.apply_check (t.seats.get ⟨i, h_len⟩)).bet =
        (t.betting_round.getD (BettingRound.new 0 0)).current_bet := by
    intro hp
    -- check 不改 bet/is_participating，故 hp 直接给出原座位的 is_participating = true
    have h_orig := h hbr' (t.seats.get ⟨i, h_len⟩) (List.get_mem t.seats i h_len) hp
    refine ⟨rfl, ?_⟩
    -- check 不改 bet，h_orig.2 给出 bet = cb
    exact h_orig.2
  have h_all : ∀ s' ∈ t.seats, s'.is_participating = true →
      s'.acted_this_round = true ∧
      s'.bet = (t.betting_round.getD (BettingRound.new 0 0)).current_bet :=
    fun s' hs' => h hbr' s' hs'
  exact update_nth_preserves_prop t.seats i Seat.apply_check
    (fun s' => s'.is_participating = true → s'.acted_this_round = true ∧
      s'.bet = (t.betting_round.getD (BettingRound.new 0 0)).current_bet)
    h_len h_all h_at s h_mem hpart

/-- `apply_call` 保持 `betting_round_completion`：call 在已匹配时不动 bet。

**关键**：`apply_call` 用 `match t.betting_round`，故 `(apply_call t i).betting_round`
不与 `t.betting_round` 定义性相等；需显式 `rw` 归一化到 `r.current_bet`。 -/
theorem apply_call_preserves_betting_completion (t : TexasPokerTable) (i : Nat)
    (h_len : i < t.seats.length) :
    betting_round_completion t → betting_round_completion (apply_call t i) := by
  intro h
  cases h_br : t.betting_round with
  | none =>
    intro hbr
    have h_eq : (apply_call t i).betting_round = none := by simp [apply_call, h_br]
    simp [h_eq] at hbr
  | some r =>
    intro hbr s hs hpart
    have h_br'_eq : (apply_call t i).betting_round = some r := by simp [apply_call, h_br]
    have h_mem : s ∈ update_nth t.seats i (fun s' => s'.apply_call r) := by
      simp [apply_call, h_br] at hs; exact hs
    have h_cb_app : ((apply_call t i).betting_round.getD (BettingRound.new 0 0)).current_bet
        = r.current_bet := by rw [h_br'_eq]; rfl
    have h_cb_t : (t.betting_round.getD (BettingRound.new 0 0)).current_bet = r.current_bet := by
      rw [h_br]; rfl
    rw [h_cb_app]
    have h_at : (Seat.apply_call (t.seats.get ⟨i, h_len⟩) r).is_participating = true →
        (Seat.apply_call (t.seats.get ⟨i, h_len⟩) r).acted_this_round = true ∧
        (Seat.apply_call (t.seats.get ⟨i, h_len⟩) r).bet = r.current_bet := by
      intro hp
      -- apply_call 不改 is_participating（不动 folded/left_during_hand/is_waiting）
      have h_orig := h (by simp [h_br]) (t.seats.get ⟨i, h_len⟩)
        (List.get_mem t.seats i h_len) hp
      rw [h_cb_t] at h_orig
      -- h_orig.2 : (t.seats.get ⟨i, h_len⟩).bet = r.current_bet
      -- call_amt = process_call r seat.bet seat.stack = min (current_bet - seat.bet) stack
      -- 由 h_orig.2：seat.bet = current_bet → current_bet - seat.bet = 0 → min 0 stack = 0
      -- 故新 bet = seat.bet + 0 = seat.bet = r.current_bet
      refine ⟨rfl, ?_⟩
      rw [Seat.apply_call_bet, h_orig.2]
      simp only [BettingRound.process_call, BettingRound.chips_to_call_def, Nat.sub_self]
      omega
    have h_all : ∀ s' ∈ t.seats, s'.is_participating = true →
        s'.acted_this_round = true ∧ s'.bet = r.current_bet := by
      intro s' hs'
      have hthis := h (by simp [h_br]) s' hs'
      rw [h_cb_t] at hthis
      exact hthis
    exact update_nth_preserves_prop t.seats i (fun s' => s'.apply_call r)
      (fun s' => s'.is_participating = true → s'.acted_this_round = true ∧ s'.bet = r.current_bet)
      h_len h_all h_at s h_mem hpart

/-! `apply_raise` **不保持** `betting_round_completion`（raise 重开下注）。
Phase 6 通过 `advance_turn` + 完整下注轮恢复。 -/

/-! ### inv_chip_bounds 保持 -/

/-- `apply_fold` 保持 `inv_chip_bounds`：fold 不动 stack/bet/total_bet/pending_addon。 -/
theorem apply_fold_preserves_inv_chip_bounds (t : TexasPokerTable) (i : Nat) :
    inv_chip_bounds t → inv_chip_bounds (apply_fold t i) := by
  intro h
  rcases h with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  refine ⟨h_pot, h_ante, h_rake, h_addon, ?_⟩
  intro s hs
  have h_mem : s ∈ update_nth t.seats i Seat.apply_fold := by
    simp [apply_fold] at hs; exact hs
  have h_ts := update_nth_preserves_field_bound t.seats i Seat.apply_fold
    (fun s => s.total_bet + s.stack) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).1) (fun s => by simp [Seat.apply_fold])
  have h_sb := update_nth_preserves_field_bound t.seats i Seat.apply_fold
    (fun s => s.stack + s.bet) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).2.1) (fun s => by simp [Seat.apply_fold])
  have h_pa := update_nth_preserves_field_bound t.seats i Seat.apply_fold
    (fun s => s.pending_addon) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).2.2) (fun s => by simp [Seat.apply_fold])
  exact ⟨h_ts s h_mem, h_sb s h_mem, h_pa s h_mem⟩

/-- `apply_check` 保持 `inv_chip_bounds`。 -/
theorem apply_check_preserves_inv_chip_bounds (t : TexasPokerTable) (i : Nat) :
    inv_chip_bounds t → inv_chip_bounds (apply_check t i) := by
  intro h
  rcases h with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  refine ⟨h_pot, h_ante, h_rake, h_addon, ?_⟩
  intro s hs
  have h_mem : s ∈ update_nth t.seats i Seat.apply_check := by
    simp [apply_check] at hs; exact hs
  have h_ts := update_nth_preserves_field_bound t.seats i Seat.apply_check
    (fun s => s.total_bet + s.stack) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).1) (fun s => by simp [Seat.apply_check])
  have h_sb := update_nth_preserves_field_bound t.seats i Seat.apply_check
    (fun s => s.stack + s.bet) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).2.1) (fun s => by simp [Seat.apply_check])
  have h_pa := update_nth_preserves_field_bound t.seats i Seat.apply_check
    (fun s => s.pending_addon) MAX_TOTAL_BET
    (fun s hs => (h_seats s hs).2.2) (fun s => by simp [Seat.apply_check])
  exact ⟨h_ts s h_mem, h_sb s h_mem, h_pa s h_mem⟩

/-- `apply_call` 保持 `inv_chip_bounds`：seat_chips 守恒 + total_bet+stack 守恒。 -/
theorem apply_call_preserves_inv_chip_bounds (t : TexasPokerTable) (i : Nat)
    (h_len : i < t.seats.length) (h_br : t.betting_round.isSome) :
    inv_chip_bounds t → inv_chip_bounds (apply_call t i) := by
  intro h
  rcases h with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  cases h_br_eq : t.betting_round with
  | none =>
    simp [apply_call, h_br_eq] at h_br
  | some r =>
    have h_pot' : (apply_call t i).pot = t.pot := by simp [apply_call, h_br_eq]
    have h_ante' : (apply_call t i).ante_collected = t.ante_collected := by simp [apply_call, h_br_eq]
    have h_rake' : (apply_call t i).rake_collected = t.rake_collected := by simp [apply_call, h_br_eq]
    have h_addon' : (apply_call t i).addon_pool = t.addon_pool := by simp [apply_call, h_br_eq]
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [h_pot']; exact h_pot
    · rw [h_ante']; exact h_ante
    · rw [h_rake']; exact h_rake
    · rw [h_addon']; exact h_addon
    · intro s hs
      have h_mem : s ∈ update_nth t.seats i (fun s' => s'.apply_call r) := by
        simp [apply_call, h_br_eq] at hs; exact hs
      have h_sc : ∀ s' : Seat,
          (s'.apply_call r).stack + (s'.apply_call r).bet = s'.stack + s'.bet :=
        fun s' => Seat.apply_call_seat_chips s' r
      have h_ts : ∀ s' : Seat,
          (s'.apply_call r).total_bet + (s'.apply_call r).stack = s'.total_bet + s'.stack := by
        intro s'
        simp [Seat.apply_call, BettingRound.process_call, seat_chips]
        have h_le : min (r.current_bet - s'.bet) s'.stack ≤ s'.stack := Nat.min_le_right _ _
        omega
      have h_pa : ∀ s' : Seat, (s'.apply_call r).pending_addon = s'.pending_addon :=
        fun s' => Seat.apply_call_pending_addon s' r
      have h_ts_bound := update_nth_preserves_field_bound t.seats i
        (fun s' => s'.apply_call r) (fun s' => s'.total_bet + s'.stack) MAX_TOTAL_BET
        (fun s' hs' => (h_seats s' hs').1) h_ts
      have h_sb_bound := update_nth_preserves_field_bound t.seats i
        (fun s' => s'.apply_call r) (fun s' => s'.stack + s'.bet) MAX_TOTAL_BET
        (fun s' hs' => (h_seats s' hs').2.1) h_sc
      have h_pa_bound := update_nth_preserves_field_bound t.seats i
        (fun s' => s'.apply_call r) (fun s' => s'.pending_addon) MAX_TOTAL_BET
        (fun s' hs' => (h_seats s' hs').2.2) h_pa
      exact ⟨h_ts_bound s h_mem, h_sb_bound s h_mem, h_pa_bound s h_mem⟩

/-- `apply_raise` 保持 `inv_chip_bounds`，在 `process_raise` 成功前置下成立。 -/
theorem apply_raise_preserves_inv_chip_bounds (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat) (r : BettingRound) (seat : Seat)
    (h_round : t.betting_round = some r)
    (h_len : i < t.seats.length)
    (h_seat : t.seats.get ⟨i, h_len⟩ = seat)
    (h_process : r.process_raise total_bet seat.bet seat.stack = some (r', needed)) :
    inv_chip_bounds t → inv_chip_bounds (apply_raise t i total_bet r' needed) := by
  intro h
  rcases h with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  -- pot / ante / rake / addon 不变
  have h_pot' : (apply_raise t i total_bet r' needed).pot = t.pot := rfl
  have h_ante' : (apply_raise t i total_bet r' needed).ante_collected = t.ante_collected := rfl
  have h_rake' : (apply_raise t i total_bet r' needed).rake_collected = t.rake_collected := rfl
  have h_addon' : (apply_raise t i total_bet r' needed).addon_pool = t.addon_pool := rfl
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rw [h_pot']; exact h_pot
  · rw [h_ante']; exact h_ante
  · rw [h_rake']; exact h_rake
  · rw [h_addon']; exact h_addon
  · obtain ⟨h_cb, h_sb, h_le_stack, h_needed_eq, h_r_cb, h_or⟩ :=
      BettingRound.process_raise_success_structure r total_bet seat.bet seat.stack r' needed h_process
    have h_needed : total_bet = seat.bet + needed := by omega
    have h_needed_le_stack : needed ≤ seat.stack := by rw [h_needed_eq]; exact h_le_stack
    intro s hs
    have h_mem : s ∈ update_nth t.seats i (fun s' => Seat.apply_raise s' total_bet needed) := by
      simp [apply_raise] at hs; exact hs
    have h_pa : ∀ s' : Seat, (Seat.apply_raise s' total_bet needed).pending_addon = s'.pending_addon :=
      fun s' => rfl
    have h_pa_bound := update_nth_preserves_field_bound t.seats i
      (fun s' => Seat.apply_raise s' total_bet needed) (fun s' => s'.pending_addon) MAX_TOTAL_BET
      (fun s' hs' => (h_seats s' hs').2.2) h_pa
    have h_sb_at : (Seat.apply_raise seat total_bet needed).stack +
        (Seat.apply_raise seat total_bet needed).bet = seat.stack + seat.bet := by
      simp [Seat.apply_raise, seat_chips]; omega
    have h_sb_bound := update_nth_preserves_field_bound_at t.seats i
      (fun s' => Seat.apply_raise s' total_bet needed) (fun s' => s'.stack + s'.bet) MAX_TOTAL_BET
      (fun s' hs' => (h_seats s' hs').2.1) h_len (by rw [h_seat]; exact h_sb_at)
    have h_ts_at : (Seat.apply_raise seat total_bet needed).total_bet +
        (Seat.apply_raise seat total_bet needed).stack = seat.total_bet + seat.stack := by
      simp [Seat.apply_raise]; omega
    have h_ts_bound := update_nth_preserves_field_bound_at t.seats i
      (fun s' => Seat.apply_raise s' total_bet needed) (fun s' => s'.total_bet + s'.stack) MAX_TOTAL_BET
      (fun s' hs' => (h_seats s' hs').1) h_len (by rw [h_seat]; exact h_ts_at)
    exact ⟨h_ts_bound s h_mem, h_sb_bound s h_mem, h_pa_bound s h_mem⟩

end TexasPoker
