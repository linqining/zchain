import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.Transitions
import PokerLean.State.Invariants
import PokerLean.State.RoundMachine
import PokerLean.State.SidePot
import PokerLean.State.SubPhases

/-!
# 顶层集成定理（Phase 6a）

镜像 `state_machine.rs` 中 `end_without_showdown` / `settle_hand` /
`reset_for_next_hand` 的资金操作，并证明贯穿全协议的顶层集成定理：

1. **`reset_for_next_hand` chip 守恒**：`pending_addon → stack` 合并守恒
2. **`reset_for_next_hand` 清理性**：清零 pot / side_pots / community_cards /
   betting_round / per-seat bet / total_bet / folded / all_in
3. **`end_without_showdown` chip 守恒**：`pot → winner.stack` + `rake → rake_collected`
4. **顶层集成**：`apply_fold/check/call` 保持 `all_invariants`

## 关键前提：`bet = 0`

Rust 中 `collect_bets_to_pot`（`state_machine.rs:573-602`）在每轮结束时
将各 seat 的 `bet` 合并到 `pot` 并清零 `bet`。因此 `reset_for_next_hand`
被调用时（`settle_hand` / `end_without_showdown` 末尾），所有 seat 的 `bet` 已为 0。
本文件的守恒定理此前提建模。
-/

namespace TexasPoker

open Constants

/-! ## Phase 6a.1: `reset_for_next_hand` 建模与守恒证明 -/

/-- 座位级 reset：合并 pending_addon 到 stack，清零 per-hand 字段。

对应 `state_machine.rs:2796-2849` 中对单个 seat 的操作。 -/
def reset_seat (s : Seat) : Seat :=
  { s with
    stack := s.stack + s.pending_addon,
    pending_addon := 0,
    bet := 0,
    total_bet := 0,
    folded := false,
    all_in := false,
    acted_this_round := false }

/-- 桌台级 `reset_for_next_hand`（简化版）。

镜像 `state_machine.rs:2788-2958`。 -/
def reset_for_next_hand (t : TexasPokerTable) : TexasPokerTable :=
  { t with
    seats := t.seats.map reset_seat,
    pot := 0,
    side_pots := [],
    community_cards := [],
    betting_round := none,
    current_turn := none,
    round_state := Constants.ROUND_WAITING,
    shuffle_state := ShuffleState.default,
    reveal_token_state := RevealTokenState.default,
    reconstruct_state := ReconstructState.default,
    version := t.version + 1 }

/-! ### reset_seat 基本性质 -/

theorem reset_seat_stack (s : Seat) :
    (reset_seat s).stack = s.stack + s.pending_addon := rfl

theorem reset_seat_pending_zero (s : Seat) :
    (reset_seat s).pending_addon = 0 := rfl

theorem reset_seat_bet_zero (s : Seat) :
    (reset_seat s).bet = 0 := rfl

theorem reset_seat_total_bet_zero (s : Seat) :
    (reset_seat s).total_bet = 0 := rfl

theorem reset_seat_folded_false (s : Seat) :
    (reset_seat s).folded = false := rfl

theorem reset_seat_all_in_false (s : Seat) :
    (reset_seat s).all_in = false := rfl

/-! ### 辅助引理：列表级 reset_seat 求和 -/

/-- 在 `bet = 0` 前置下，`reset_seat` 使 `Σ seat_chips` 增 `Σ pending_addon`。 -/
theorem reset_seat_list_seat_chips_sum (l : List Seat)
    (h_bet : ∀ s ∈ l, s.bet = 0) :
    ((l.map reset_seat).map seat_chips).sum =
    (l.map seat_chips).sum + (l.map Seat.pending_addon).sum := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons, reset_seat, seat_chips]
    have h_xs : ∀ s ∈ xs, s.bet = 0 := fun s hs => h_bet s (List.mem_cons_of_mem x hs)
    have := ih h_xs
    have hx := h_bet x (List.mem_cons_self x xs)
    omega

/-- `reset_seat` 使 `Σ pending_addon` 归零。 -/
theorem reset_seat_list_pending_sum (l : List Seat) :
    ((l.map reset_seat).map Seat.pending_addon).sum = 0 := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.map_cons, List.sum_cons, reset_seat_pending_zero, ih]

/-! ### reset_for_next_hand chip 守恒 -/

/-- **定理 1（reset_for_next_hand chip 守恒）**：`total_chips` 不变。

前置：
- 所有 seat 的 `bet = 0`（bets 已通过 `collect_bets_to_pot` 合并到 pot）
- `t.pot = 0`（pot 已通过 `settle_hand`/`end_without_showdown` 分配给赢家）

证明：reset 后
- `Σ seat_chips` = `Σ (stack + pending_addon)` = `Σ seat_chips + Σ pending_addon`（bet=0 前置）
- `Σ pending_addon` = 0
- `pot` = 0 = `t.pot`（前置）
- `rake_collected` 不变
- 故 `total_chips` 守恒。 -/
theorem reset_for_next_hand_chip_conservation (t : TexasPokerTable)
    (h_all_bet_zero : ∀ s ∈ t.seats, s.bet = 0)
    (h_pot_zero : t.pot = 0) :
    total_chips (reset_for_next_hand t) = total_chips t := by
  unfold total_chips
  simp only [reset_for_next_hand]
  rw [reset_seat_list_seat_chips_sum t.seats h_all_bet_zero,
      reset_seat_list_pending_sum t.seats, h_pot_zero]
  omega

/-! ### reset_for_next_hand 清理性 -/

theorem reset_for_next_hand_pot_zero (t : TexasPokerTable) :
    (reset_for_next_hand t).pot = 0 := rfl

theorem reset_for_next_hand_side_pots_nil (t : TexasPokerTable) :
    (reset_for_next_hand t).side_pots = [] := rfl

theorem reset_for_next_hand_community_nil (t : TexasPokerTable) :
    (reset_for_next_hand t).community_cards = [] := rfl

theorem reset_for_next_hand_betting_round_none (t : TexasPokerTable) :
    (reset_for_next_hand t).betting_round = none := rfl

theorem reset_for_next_hand_current_turn_none (t : TexasPokerTable) :
    (reset_for_next_hand t).current_turn = none := rfl

theorem reset_for_next_hand_round_waiting (t : TexasPokerTable) :
    (reset_for_next_hand t).round_state = Constants.ROUND_WAITING := rfl

theorem reset_for_next_hand_shuffle_default (t : TexasPokerTable) :
    (reset_for_next_hand t).shuffle_state = ShuffleState.default := rfl

theorem reset_for_next_hand_reveal_default (t : TexasPokerTable) :
    (reset_for_next_hand t).reveal_token_state = RevealTokenState.default := rfl

theorem reset_for_next_hand_reconstruct_default (t : TexasPokerTable) :
    (reset_for_next_hand t).reconstruct_state = ReconstructState.default := rfl

theorem reset_for_next_hand_version_inc (t : TexasPokerTable) :
    (reset_for_next_hand t).version = t.version + 1 := rfl

theorem reset_for_next_hand_seats_length (t : TexasPokerTable) :
    (reset_for_next_hand t).seats.length = t.seats.length := by
  simp [reset_for_next_hand, List.length_map]

theorem reset_for_next_hand_seat_bet_zero (t : TexasPokerTable) :
    ∀ s ∈ (reset_for_next_hand t).seats, s.bet = 0 := by
  intro s hs
  obtain ⟨x, _, heq⟩ := List.mem_map.mp hs
  subst heq
  exact reset_seat_bet_zero x

theorem reset_for_next_hand_seat_total_bet_zero (t : TexasPokerTable) :
    ∀ s ∈ (reset_for_next_hand t).seats, s.total_bet = 0 := by
  intro s hs
  obtain ⟨x, _, heq⟩ := List.mem_map.mp hs
  subst heq
  exact reset_seat_total_bet_zero x

theorem reset_for_next_hand_seat_folded_false (t : TexasPokerTable) :
    ∀ s ∈ (reset_for_next_hand t).seats, s.folded = false := by
  intro s hs
  obtain ⟨x, _, heq⟩ := List.mem_map.mp hs
  subst heq
  exact reset_seat_folded_false x

theorem reset_for_next_hand_seat_all_in_false (t : TexasPokerTable) :
    ∀ s ∈ (reset_for_next_hand t).seats, s.all_in = false := by
  intro s hs
  obtain ⟨x, _, heq⟩ := List.mem_map.mp hs
  subst heq
  exact reset_seat_all_in_false x

theorem reset_for_next_hand_seat_pending_zero (t : TexasPokerTable) :
    ∀ s ∈ (reset_for_next_hand t).seats, s.pending_addon = 0 := by
  intro s hs
  obtain ⟨x, _, heq⟩ := List.mem_map.mp hs
  subst heq
  exact reset_seat_pending_zero x

/-! ## Phase 6a.2: `end_without_showdown` chip 守恒 -/

/-- pre-table：`pot` 经 `rake` 扣除后全部给 `winner`，`rake` 入 `rake_collected`。

提取为命名定义，便于用 `rfl` 证字段引理、避免 struct 投影被 `omega` 视为不透明。 -/
def end_without_showdown_pre (t : TexasPokerTable) (winner_idx : Nat) (rake : Nat) :
    TexasPokerTable :=
  { t with
    pot := 0,
    rake_collected := t.rake_collected + rake,
    seats := update_nth t.seats winner_idx
      (fun s => { s with stack := s.stack + (t.pot - rake) }),
    version := t.version + 2 }

theorem end_without_showdown_pre_pot (t : TexasPokerTable) (winner_idx : Nat) (rake : Nat) :
    (end_without_showdown_pre t winner_idx rake).pot = 0 := rfl

theorem end_without_showdown_pre_rake (t : TexasPokerTable) (winner_idx : Nat) (rake : Nat) :
    (end_without_showdown_pre t winner_idx rake).rake_collected = t.rake_collected + rake := rfl

theorem end_without_showdown_pre_seats (t : TexasPokerTable) (winner_idx : Nat) (rake : Nat) :
    (end_without_showdown_pre t winner_idx rake).seats =
      update_nth t.seats winner_idx
        (fun s => { s with stack := s.stack + (t.pot - rake) }) := rfl

/-- `end_without_showdown`（简化模型）。

资金流：`pot` 经 `rake` 扣除后全部给 `winner`，然后 reset。 -/
def end_without_showdown (t : TexasPokerTable) (winner_idx : Nat) (rake : Nat)
    (h_rake_le : rake ≤ t.pot) : TexasPokerTable :=
  reset_for_next_hand (end_without_showdown_pre t winner_idx rake)

/-- 辅助：`update_nth` 保持 `bet` 字段（当 `f` 不修改 `bet` 时）。 -/
theorem update_nth_preserves_bet (l : List Seat) (i : Nat) (f : Seat → Seat)
    (h_len : i < l.length)
    (h_f : ∀ s, (f s).bet = s.bet)
    (h_all : ∀ s ∈ l, s.bet = 0) :
    ∀ s ∈ update_nth l i f, s.bet = 0 := by
  apply update_nth_preserves_prop l i f (fun s => s.bet = 0) h_len h_all
  rw [h_f]
  exact h_all _ (List.get_mem _ _ _)

/-- **定理 2（end_without_showdown chip 守恒）**：`total_chips` 不变。 -/
theorem end_without_showdown_chip_conservation (t : TexasPokerTable)
    (winner_idx : Nat) (rake : Nat)
    (h_rake_le : rake ≤ t.pot)
    (h_len : winner_idx < t.seats.length)
    (h_all_bet_zero : ∀ s ∈ t.seats, s.bet = 0) :
    total_chips (end_without_showdown t winner_idx rake h_rake_le) = total_chips t := by
  -- t_pre = end_without_showdown_pre t winner_idx rake
  have h_f_bet : ∀ s : Seat, ({ s with stack := s.stack + (t.pot - rake) }).bet = s.bet := by
    intro s; rfl
  have h_pre_bet : ∀ s ∈ (end_without_showdown_pre t winner_idx rake).seats, s.bet = 0 := by
    rw [end_without_showdown_pre_seats]
    exact update_nth_preserves_bet _ _ _ h_len h_f_bet h_all_bet_zero
  have h_pre_pot : (end_without_showdown_pre t winner_idx rake).pot = 0 :=
    end_without_showdown_pre_pot t winner_idx rake
  -- 证明 total_chips t_pre = total_chips t
  have h_pre_chips : total_chips (end_without_showdown_pre t winner_idx rake) = total_chips t := by
    unfold total_chips
    rw [end_without_showdown_pre_seats, end_without_showdown_pre_pot,
        end_without_showdown_pre_rake]
    -- seats.map seat_chips: 第 winner_idx 个增 (t.pot - rake)
    have h_seat_sum : ((update_nth t.seats winner_idx
        (fun s => { s with stack := s.stack + (t.pot - rake) })).map seat_chips).sum =
        (t.seats.map seat_chips).sum + (t.pot - rake) := by
      apply sum_map_update_nth_delta _ _ _ seat_chips (t.pot - rake) h_len
      simp [seat_chips]; omega
    have h_pending_sum : ((update_nth t.seats winner_idx
        (fun s => { s with stack := s.stack + (t.pot - rake) })).map Seat.pending_addon).sum =
        (t.seats.map Seat.pending_addon).sum := by
      apply sum_map_update_nth_all; intro s; rfl
    rw [h_seat_sum, h_pending_sum]
    omega
  -- 应用 reset_for_next_hand 守恒
  unfold end_without_showdown
  rw [reset_for_next_hand_chip_conservation _ h_pre_bet h_pre_pot]
  exact h_pre_chips

/-! ## Phase 6a.3: 顶层集成定理 -/

/-- **定理 3（apply_fold 保持 all_invariants）**。 -/
theorem apply_fold_preserves_all_invariants (t : TexasPokerTable) (i : Nat)
    (h_ver : t.version < U64_MAX) (h_len : i < t.seats.length) :
    all_invariants t → all_invariants (apply_fold t i) := by
  intro h
  unfold all_invariants at *
  rcases h with ⟨h1, h1b, h2, h3, h4, h5, h6⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact apply_fold_preserves_inv_chip_bounds t i h1
  · exact h1b
  · exact apply_fold_preserves_inv_state_consistency t i h2
  · exact apply_fold_preserves_current_turn t i h3
  · exact apply_fold_preserves_betting_completion t i h_len h4
  · exact apply_fold_preserves_addon_semantics t i h5
  · exact apply_fold_preserves_version t i h_ver h6

/-- **定理 4（apply_check 保持 all_invariants）**。 -/
theorem apply_check_preserves_all_invariants (t : TexasPokerTable) (i : Nat)
    (h_ver : t.version < U64_MAX) (h_len : i < t.seats.length) :
    all_invariants t → all_invariants (apply_check t i) := by
  intro h
  unfold all_invariants at *
  rcases h with ⟨h1, h1b, h2, h3, h4, h5, h6⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact apply_check_preserves_inv_chip_bounds t i h1
  · exact h1b
  · exact apply_check_preserves_inv_state_consistency t i h2
  · exact apply_check_preserves_current_turn t i h3
  · exact apply_check_preserves_betting_completion t i h_len h4
  · exact apply_check_preserves_addon_semantics t i h5
  · exact apply_check_preserves_version t i h_ver h6

/-- **定理 5（apply_call 保持 all_invariants）**。 -/
theorem apply_call_preserves_all_invariants (t : TexasPokerTable) (i : Nat)
    (h_ver : t.version < U64_MAX) (h_len : i < t.seats.length)
    (h_br : t.betting_round.isSome) :
    all_invariants t → all_invariants (apply_call t i) := by
  intro h
  unfold all_invariants at *
  rcases h with ⟨h1, h1b, h2, h3, h4, h5, h6⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact apply_call_preserves_inv_chip_bounds t i h_len h_br h1
  · -- total_chips_bound: apply_call 不改 chip_pool / addon_pool
    have h_eq : total_chips_bound (apply_call t i) = total_chips_bound t := by
      cases h_br_eq : t.betting_round with
      | none => simp [apply_call, h_br_eq, total_chips_bound]
      | some r => simp [apply_call, h_br_eq, total_chips_bound]
    rw [h_eq]
    exact h1b
  · exact apply_call_preserves_inv_state_consistency t i h2
  · exact apply_call_preserves_current_turn t i h3
  · exact apply_call_preserves_betting_completion t i h_len h4
  · exact apply_call_preserves_addon_semantics t i h5
  · exact apply_call_preserves_version t i h_ver h_br h6

/-! ## Phase 6a.4: `reset_for_next_hand` 后状态良构 -/

theorem reset_for_next_hand_state_consistency (t : TexasPokerTable) :
    inv_state_consistency (reset_for_next_hand t) := by
  unfold inv_state_consistency
  intro h
  simp [TexasPokerTable.is_betting_round, reset_for_next_hand] at h
  -- ROUND_WAITING ≠ ROUND_PREFLOP/FLOP/TURN/RIVER
  exact absurd h (by decide)

theorem reset_for_next_hand_betting_completion (t : TexasPokerTable) :
    betting_round_completion (reset_for_next_hand t) := by
  unfold betting_round_completion
  intro h
  simp [reset_for_next_hand] at h

theorem reset_for_next_hand_addon_semantics (t : TexasPokerTable) :
    addon_pending_semantics (reset_for_next_hand t) := by
  unfold addon_pending_semantics
  intro s _ _
  trivial

theorem reset_for_next_hand_current_turn_wf (t : TexasPokerTable) :
    current_turn_well_formed (reset_for_next_hand t) := by
  unfold current_turn_well_formed
  intro i h
  simp [reset_for_next_hand] at h

theorem reset_for_next_hand_version_mono (t : TexasPokerTable)
    (h_ver : t.version < U64_MAX) :
    version_strictly_monotone (reset_for_next_hand t) := by
  unfold version_strictly_monotone
  rw [reset_for_next_hand_version_inc, U64_MAX_eq] at *
  omega

theorem reset_for_next_hand_total_chips_bound (t : TexasPokerTable) :
    total_chips_bound t → total_chips_bound (reset_for_next_hand t) := by
  unfold total_chips_bound reset_for_next_hand
  intro h
  exact h

/-- `reset_for_next_hand` 不修改 `chip_pool`。 -/
theorem reset_for_next_hand_chip_pool (t : TexasPokerTable) :
    (reset_for_next_hand t).chip_pool = t.chip_pool := rfl

/-- `reset_for_next_hand` 不修改 `addon_pool`。 -/
theorem reset_for_next_hand_addon_pool (t : TexasPokerTable) :
    (reset_for_next_hand t).addon_pool = t.addon_pool := rfl

/-- `reset_for_next_hand` 不修改 `ante_collected`。 -/
theorem reset_for_next_hand_ante_collected (t : TexasPokerTable) :
    (reset_for_next_hand t).ante_collected = t.ante_collected := rfl

/-- `reset_for_next_hand` 不修改 `rake_collected`。 -/
theorem reset_for_next_hand_rake_collected (t : TexasPokerTable) :
    (reset_for_next_hand t).rake_collected = t.rake_collected := rfl

/-- **定理 6（reset_for_next_hand 保持 all_invariants）**。

前置：
- `t.version < U64_MAX`（防溢出）
- `total_chips_bound t`（reset 不修改 chip_pool / addon_pool）
- 所有 seat 的 `stack + pending_addon ≤ MAX_TOTAL_BET`（reset 后 total_bet=0，
  stack 增 pending_addon）
- `t.ante_collected ≤ MAX_TOTAL_BET`、`t.rake_collected ≤ MAX_TOTAL_BET`
  （reset 不修改这些字段） -/
theorem reset_for_next_hand_preserves_all_invariants (t : TexasPokerTable)
    (h_ver : t.version < U64_MAX)
    (h_tcb : total_chips_bound t)
    (h_ante : t.ante_collected ≤ MAX_TOTAL_BET)
    (h_rake : t.rake_collected ≤ MAX_TOTAL_BET)
    (h_stack_pending : ∀ s ∈ t.seats, s.stack + s.pending_addon ≤ MAX_TOTAL_BET) :
    all_invariants (reset_for_next_hand t) := by
  unfold all_invariants
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- inv_chip_bounds
    unfold inv_chip_bounds
    rw [reset_for_next_hand_pot_zero, reset_for_next_hand_ante_collected,
        reset_for_next_hand_rake_collected, reset_for_next_hand_addon_pool]
    refine ⟨Nat.zero_le _, h_ante, h_rake, ?_, ?_⟩
    · -- addon_pool ≤ MAX_TOTAL_BET: from total_chips_bound (chip_pool + addon_pool ≤ MAX)
      have h_tcb' := h_tcb
      unfold total_chips_bound at h_tcb'
      exact le_trans (Nat.le_add_left _ _) h_tcb'
    · intro s hs
      obtain ⟨x, hx, heq⟩ := List.mem_map.mp hs
      subst heq
      simp only [reset_seat]
      refine ⟨?_, ?_, Nat.zero_le _⟩
      · -- total_bet + stack = 0 + (x.stack + x.pending_addon)
        have := h_stack_pending x hx
        omega
      · -- stack + bet = (x.stack + x.pending_addon) + 0
        have := h_stack_pending x hx
        omega
  · exact reset_for_next_hand_total_chips_bound t h_tcb
  · exact reset_for_next_hand_state_consistency t
  · exact reset_for_next_hand_current_turn_wf t
  · exact reset_for_next_hand_betting_completion t
  · exact reset_for_next_hand_addon_semantics t
  · exact reset_for_next_hand_version_mono t h_ver

/-! ## Phase 6a.5: `apply_raise` 集成（核心不变量保持）

**说明**：`apply_raise` **不**保持 `betting_round_completion`（这是设计上正确的：
raise 重开下注轮，将其他玩家的 `acted_this_round` 重置为 false，并将 `current_bet`
提高到新值，故原"全部已行动且 bet=current_bet"不再成立）。完整下注轮结束后由
`advance_turn` / 新一轮 `apply_call/check/fold` 恢复。

我们因此定义 `core_invariants`（剔除 `betting_round_completion`）并证 `apply_raise`
保持之。这完成了「下注动作保持核心不变量」的集成论证。 -/

/-- **核心不变量**：`all_invariants` 剔除 `betting_round_completion`。

`apply_raise` 不保持 `betting_round_completion`（设计上正确，raise 重开下注），
但保持其余 6 个不变量。 -/
def core_invariants (t : TexasPokerTable) : Prop :=
  inv_chip_bounds t ∧ total_chips_bound t ∧ inv_state_consistency t ∧
  current_turn_well_formed t ∧ addon_pending_semantics t ∧ version_strictly_monotone t

/-- `all_invariants` 蕴含 `core_invariants`。 -/
theorem all_invariants_implies_core (t : TexasPokerTable) :
    all_invariants t → core_invariants t := by
  unfold all_invariants core_invariants
  intro ⟨h1, h1b, h2, h3, h4, h5, h6⟩
  exact ⟨h1, h1b, h2, h3, h5, h6⟩
  -- 丢弃 h4 (betting_round_completion)，因 core_invariants 不含此项

/-- **定理 5b（apply_raise 保持 core_invariants）**。

`apply_raise` 不保持 `betting_round_completion`（设计上正确，raise 重开下注），
但保持其余 6 个核心不变量。 -/
theorem apply_raise_preserves_core_invariants (t : TexasPokerTable) (i : Nat)
    (total_bet : Nat) (r' : BettingRound) (needed : Nat)
    (r : BettingRound) (seat : Seat)
    (h_round : t.betting_round = some r)
    (h_len : i < t.seats.length)
    (h_seat : t.seats.get ⟨i, h_len⟩ = seat)
    (h_process : r.process_raise total_bet seat.bet seat.stack = some (r', needed))
    (h_ver : t.version < U64_MAX) :
    core_invariants t → core_invariants (apply_raise t i total_bet r' needed) := by
  intro h
  unfold core_invariants at *
  obtain ⟨h1, h1b, h2, h3, h4, h5⟩ := h
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact apply_raise_preserves_inv_chip_bounds t i total_bet r' needed r seat
      h_round h_len h_seat h_process h1
  · -- total_chips_bound: apply_raise 不改 chip_pool / addon_pool
    have h_eq : total_chips_bound (apply_raise t i total_bet r' needed) = total_chips_bound t := by
      unfold total_chips_bound apply_raise
      rfl
    rw [h_eq]; exact h1b
  · exact apply_raise_preserves_inv_state_consistency t i total_bet r' needed h2
  · exact apply_raise_preserves_current_turn t i total_bet r' needed h3
  · exact apply_raise_preserves_addon_semantics t i total_bet r' needed h4
  · exact apply_raise_preserves_version t i total_bet r' needed h_ver h5

/-! ## Phase 6a.6: 顶层集成定理

任意下注动作（fold/check/call/raise）保持核心不变量；fold/check/call 进一步保持
`betting_round_completion`。这是「状态转移正确性」的核心结论。 -/

/-- **顶层集成定理**：任意合法下注动作保持核心不变量。

- `apply_fold/check/call`：在 `all_invariants` 前置下保持全部 `all_invariants`
- `apply_raise`：在 `core_invariants` 前置下保持 `core_invariants`
  （剔除 `betting_round_completion`，因 raise 重开下注）

这是「Texas Hold'em 状态机转移正确性」的核心结论：任意合法下注动作后，
6 个核心不变量（金额上界、全局上界、状态一致性、当前回合良构、addon 语义、版本单调）
均保持；fold/check/call 进一步保持下注轮完成性。 -/
theorem state_transition_preserves_invariants (t : TexasPokerTable) (i : Nat)
    (h_ver : t.version < U64_MAX) (h_len : i < t.seats.length) :
    -- fold / check / call：保持 all_invariants（在 all_invariants 前置下）
    (all_invariants t → all_invariants (apply_fold t i)) ∧
    (all_invariants t → all_invariants (apply_check t i)) ∧
    (all_invariants t → t.betting_round.isSome → all_invariants (apply_call t i)) ∧
    -- raise：保持 core_invariants（在 core_invariants 前置下）
    (∀ r total_bet r' needed seat,
      t.betting_round = some r →
      t.seats.get ⟨i, h_len⟩ = seat →
      r.process_raise total_bet seat.bet seat.stack = some (r', needed) →
      core_invariants t → core_invariants (apply_raise t i total_bet r' needed)) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact apply_fold_preserves_all_invariants t i h_ver h_len
  · exact apply_check_preserves_all_invariants t i h_ver h_len
  · intro h_all h_br
    exact apply_call_preserves_all_invariants t i h_ver h_len h_br h_all
  · intro r total_bet r' needed seat h_round h_seat h_process h_core
    exact apply_raise_preserves_core_invariants t i total_bet r' needed r seat
      h_round h_len h_seat h_process h_ver h_core

end TexasPoker
