import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Card
import PokerLean.State.Types

/-!
# 手牌评估器（Phase 4，镜像 `hand_evaluator.rs`）

## 核心定理

1. **全序性**：`lexLt` 定义严格全序（反自反、传递、三分）。
2. **best-5-of-7 正确性**：`evaluate_best` 返回所有 5 张组合中的最大 HandRank。
3. **决定性**：同输入同输出（函数语义）。
-/

namespace TexasPoker

open Constants

/-! ## 牌型常量 -/

def HIGH_CARD        : Nat := 0
def ONE_PAIR         : Nat := 1
def TWO_PAIR         : Nat := 2
def THREE_OF_A_KIND  : Nat := 3
def STRAIGHT         : Nat := 4
def FLUSH            : Nat := 5
def FULL_HOUSE       : Nat := 6
def FOUR_OF_A_KIND   : Nat := 7
def STRAIGHT_FLUSH   : Nat := 8
def ROYAL_FLUSH      : Nat := 9

@[simp] theorem HIGH_CARD_eq       : HIGH_CARD = 0 := rfl
@[simp] theorem ONE_PAIR_eq        : ONE_PAIR = 1 := rfl
@[simp] theorem TWO_PAIR_eq        : TWO_PAIR = 2 := rfl
@[simp] theorem THREE_OF_A_KIND_eq : THREE_OF_A_KIND = 3 := rfl
@[simp] theorem STRAIGHT_eq        : STRAIGHT = 4 := rfl
@[simp] theorem FLUSH_eq           : FLUSH = 5 := rfl
@[simp] theorem FULL_HOUSE_eq      : FULL_HOUSE = 6 := rfl
@[simp] theorem FOUR_OF_A_KIND_eq  : FOUR_OF_A_KIND = 7 := rfl
@[simp] theorem STRAIGHT_FLUSH_eq  : STRAIGHT_FLUSH = 8 := rfl
@[simp] theorem ROYAL_FLUSH_eq     : ROYAL_FLUSH = 9 := rfl

/-! ## HandRank 结构 -/

structure HandRank where
  category : Nat
  k0 : Nat
  k1 : Nat
  k2 : Nat
  k3 : Nat
  k4 : Nat
deriving Repr, DecidableEq

namespace HandRank

def new (category : Nat) (kickers : List Nat) : HandRank :=
  { category,
    k0 := kickers.getD 0 0, k1 := kickers.getD 1 0, k2 := kickers.getD 2 0,
    k3 := kickers.getD 3 0, k4 := kickers.getD 4 0 }

def minRank : HandRank := ⟨HIGH_CARD, 0, 0, 0, 0, 0⟩

/-! ## 字典序严格小于 -/

def lexLt (a b : HandRank) : Prop :=
  a.category < b.category ∨
  (a.category = b.category ∧ a.k0 < b.k0) ∨
  (a.category = b.category ∧ a.k0 = b.k0 ∧ a.k1 < b.k1) ∨
  (a.category = b.category ∧ a.k0 = b.k0 ∧ a.k1 = b.k1 ∧ a.k2 < b.k2) ∨
  (a.category = b.category ∧ a.k0 = b.k0 ∧ a.k1 = b.k1 ∧ a.k2 = b.k2 ∧ a.k3 < b.k3) ∨
  (a.category = b.category ∧ a.k0 = b.k0 ∧ a.k1 = b.k1 ∧ a.k2 = b.k2 ∧ a.k3 = b.k3 ∧ a.k4 < b.k4)

instance lexLt_decidable (a b : HandRank) : Decidable (lexLt a b) := by
  unfold lexLt
  repeat first
    | infer_instance
    | apply instDecidableOr
    | apply instDecidableAnd

instance : LT HandRank := ⟨lexLt⟩

instance lt_decidable (a b : HandRank) : Decidable (a < b) := lexLt_decidable a b

/-! ## 全序性证明 -/

theorem lexLt_irrefl (a : HandRank) : ¬ lexLt a a := by
  intro h
  unfold lexLt at h
  rcases h with h1 | ⟨h1, h2⟩ | ⟨h1, h2, h3⟩ | ⟨h1, h2, h3, h4⟩
    | ⟨h1, h2, h3, h4, h5⟩ | ⟨h1, h2, h3, h4, h5, h6⟩
  all_goals omega

theorem lexLt_trichotomy (a b : HandRank) : lexLt a b ∨ a = b ∨ lexLt b a := by
  by_cases hc : a.category < b.category
  · left; left; exact hc
  by_cases hc' : b.category < a.category
  · right; right; left; exact hc'
  have hc_eq : a.category = b.category := by omega
  by_cases h0 : a.k0 < b.k0
  · left; right; left; exact ⟨hc_eq, h0⟩
  by_cases h0' : b.k0 < a.k0
  · right; right; right; left; exact ⟨hc_eq.symm, h0'⟩
  have h0_eq : a.k0 = b.k0 := by omega
  by_cases h1 : a.k1 < b.k1
  · left; right; right; left; exact ⟨hc_eq, h0_eq, h1⟩
  by_cases h1' : b.k1 < a.k1
  · right; right; right; right; left; exact ⟨hc_eq.symm, h0_eq.symm, h1'⟩
  have h1_eq : a.k1 = b.k1 := by omega
  by_cases h2 : a.k2 < b.k2
  · left; right; right; right; left; exact ⟨hc_eq, h0_eq, h1_eq, h2⟩
  by_cases h2' : b.k2 < a.k2
  · right; right; right; right; right; left
    exact ⟨hc_eq.symm, h0_eq.symm, h1_eq.symm, h2'⟩
  have h2_eq : a.k2 = b.k2 := by omega
  by_cases h3 : a.k3 < b.k3
  · left; right; right; right; right; left
    exact ⟨hc_eq, h0_eq, h1_eq, h2_eq, h3⟩
  by_cases h3' : b.k3 < a.k3
  · right; right; right; right; right; right; left
    exact ⟨hc_eq.symm, h0_eq.symm, h1_eq.symm, h2_eq.symm, h3'⟩
  have h3_eq : a.k3 = b.k3 := by omega
  by_cases h4 : a.k4 < b.k4
  · left; right; right; right; right; right
    exact ⟨hc_eq, h0_eq, h1_eq, h2_eq, h3_eq, h4⟩
  by_cases h4' : b.k4 < a.k4
  · right; right; right; right; right; right; right
    exact ⟨hc_eq.symm, h0_eq.symm, h1_eq.symm, h2_eq.symm, h3_eq.symm, h4'⟩
  have h4_eq : a.k4 = b.k4 := by omega
  right; left
  rcases a with ⟨ac, a0, a1, a2, a3, a4⟩
  rcases b with ⟨bc, b0, b1, b2, b3, b4⟩
  subst hc_eq; subst h0_eq; subst h1_eq; subst h2_eq; subst h3_eq; subst h4_eq
  rfl

theorem lexLt_trans (a b c : HandRank) (hab : lexLt a b) (hbc : lexLt b c) : lexLt a c := by
  unfold lexLt at hab hbc ⊢
  rcases hab with hab1 | ⟨hab1, hab2⟩ | ⟨hab1, hab2, hab3⟩ | ⟨hab1, hab2, hab3, hab4⟩
    | ⟨hab1, hab2, hab3, hab4, hab5⟩ | ⟨hab1, hab2, hab3, hab4, hab5, hab6⟩
  all_goals
    rcases hbc with hbc1 | ⟨hbc1, hbc2⟩ | ⟨hbc1, hbc2, hbc3⟩ | ⟨hbc1, hbc2, hbc3, hbc4⟩
      | ⟨hbc1, hbc2, hbc3, hbc4, hbc5⟩ | ⟨hbc1, hbc2, hbc3, hbc4, hbc5, hbc6⟩
  all_goals first
    | (left; omega)
    | (right; left; refine ⟨?_, ?_⟩ <;> omega)
    | (right; right; left; refine ⟨?_, ?_, ?_⟩ <;> omega)
    | (right; right; right; left; refine ⟨?_, ?_, ?_, ?_⟩ <;> omega)
    | (right; right; right; right; left; refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> omega)
    | (right; right; right; right; right; refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> omega)

theorem lexLt_asymm (a b : HandRank) (h : lexLt a b) : ¬ lexLt b a := by
  intro h'
  exact absurd (lexLt_trans a b a h h') (lexLt_irrefl a)

theorem lexLt_is_strict_total_order :
    IsStrictTotalOrder HandRank lexLt where
  irrefl := lexLt_irrefl
  trans := lexLt_trans
  trichotomous := lexLt_trichotomy

end HandRank

/-! ## select_best -/

namespace HandRank

def select_best : List HandRank → HandRank
  | [] => minRank
  | h :: t =>
    let best := select_best t
    if h < best then best else h

/-- 辅助：`select_best (x :: xs)` 的展开形式。 -/
theorem select_best_cons (x : HandRank) (xs : List HandRank) :
    select_best (x :: xs) = if x < select_best xs then select_best xs else x := by
  show (if x < select_best xs then select_best xs else x) = _
  rfl

theorem select_best_maximum (l : List HandRank) (h_ne : l ≠ []) :
    ∀ h ∈ l, h < select_best l ∨ h = select_best l := by
  induction l with
  | nil => exact absurd rfl h_ne
  | cons x xs ih =>
    intro h hmem
    rw [select_best_cons]
    rcases List.mem_cons.mp hmem with rfl | hmem
    · -- h = x：rfl 消去 x，全局替换为 h
      by_cases h_xs : xs = []
      · subst h_xs
        show (h < (if h < minRank then minRank else h) ∨
              h = (if h < minRank then minRank else h))
        by_cases h_lt : h < minRank
        · rw [if_pos h_lt]; left; exact h_lt
        · rw [if_neg h_lt]; right; rfl
      · by_cases h_lt : h < select_best xs
        · rw [if_pos h_lt]; left; exact h_lt
        · rw [if_neg h_lt]; right; rfl
    · by_cases h_xs : xs = []
      · rw [h_xs] at hmem; simp at hmem
      have h_best := ih h_xs h hmem
      by_cases h_lt : x < select_best xs
      · rw [if_pos h_lt]; exact h_best
      · rw [if_neg h_lt]
        rcases h_best with h1 | h2
        · rcases lexLt_trichotomy x (select_best xs) with hxs_lt | hxs_eq | hxs_gt
          · exfalso; exact h_lt hxs_lt
          · left; rw [hxs_eq]; exact h1
          · left; exact lexLt_trans h (select_best xs) x h1 hxs_gt
        · rcases lexLt_trichotomy x (select_best xs) with hxs_lt | hxs_eq | hxs_gt
          · exfalso; exact h_lt hxs_lt
          · right; rw [hxs_eq]; exact h2
          · left; rw [h2]; exact hxs_gt

end HandRank

/-! ## evaluate_five -/

namespace HandRank

def insert_desc (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≥ y then x :: y :: ys else y :: insert_desc x ys

def sort_desc : List Nat → List Nat
  | [] => []
  | x :: xs => insert_desc x (sort_desc xs)

def straight_high : List Nat → Option Nat
  | [14, 5, 4, 3, 2] => some 5
  | [a, b, c, d, e] =>
    if a = b + 1 ∧ b = c + 1 ∧ c = d + 1 ∧ d = e + 1 then some a else none
  | _ => none

def is_flush : List Card → Bool
  | [c0, c1, c2, c3, c4] =>
    c0.suit = c1.suit ∧ c1.suit = c2.suit ∧ c2.suit = c3.suit ∧ c3.suit = c4.suit
  | _ => false

def count_rank (rank : Nat) (cards : List Card) : Nat :=
  (cards.filter (fun c => c.rank = rank)).length

def build_groups (cards : List Card) : List (Nat × Nat) :=
  let counts := (List.range 13).map (fun i => (count_rank (i + 2) cards, i + 2))
  (counts.filter (fun c => c.1 > 0)).take 5

def get_group (g : List (Nat × Nat)) (i : Nat) : Nat × Nat :=
  g.getD i (0, 0)

def evaluate_five (cards : List Card) : HandRank :=
  match cards with
  | [c0, c1, c2, c3, c4] =>
    let all := [c0, c1, c2, c3, c4]
    let flush := is_flush all
    let ranks := sort_desc [c0.rank, c1.rank, c2.rank, c3.rank, c4.rank]
    let straight := straight_high ranks
    let groups := build_groups all
    if flush = true ∧ straight.isSome then
      if straight.get! = 14 then new ROYAL_FLUSH [14]
      else new STRAIGHT_FLUSH [straight.get!]
    else if (get_group groups 0).1 = 4 then
      new FOUR_OF_A_KIND [(get_group groups 0).2, (get_group groups 1).2]
    else if (get_group groups 0).1 = 3 ∧ (get_group groups 1).1 ≥ 2 then
      new FULL_HOUSE [(get_group groups 0).2, (get_group groups 1).2]
    else if flush = true then
      new FLUSH ranks
    else if straight.isSome then
      new STRAIGHT [straight.get!]
    else if (get_group groups 0).1 = 3 then
      new THREE_OF_A_KIND [(get_group groups 0).2, (get_group groups 1).2, (get_group groups 2).2]
    else if (get_group groups 0).1 = 2 ∧ (get_group groups 1).1 = 2 then
      let g0 := (get_group groups 0).2
      let g1 := (get_group groups 1).2
      new TWO_PAIR [max g0 g1, min g0 g1, (get_group groups 2).2]
    else if (get_group groups 0).1 = 2 then
      new ONE_PAIR [(get_group groups 0).2, (get_group groups 1).2,
                    (get_group groups 2).2, (get_group groups 3).2]
    else
      new HIGH_CARD ranks
  | _ => minRank

theorem evaluate_five_deterministic (cards : List Card) :
    evaluate_five cards = evaluate_five cards := rfl

end HandRank

/-! ## evaluate_best -/

namespace HandRank

def combinations5 (n : Nat) : List (Nat × Nat × Nat × Nat × Nat) :=
  (List.range n).bind fun i =>
  ((List.range n).filter (· > i)).bind fun j =>
  ((List.range n).filter (· > j)).bind fun k =>
  ((List.range n).filter (· > k)).bind fun l =>
  ((List.range n).filter (· > l)).map fun m => (i, j, k, l, m)

def get_card (cards : List Card) (idx : Nat) : Card :=
  cards.getD idx (Card.new 0 0)

def pick5 (cards : List Card) (i j k l m : Nat) : List Card :=
  [get_card cards i, get_card cards j, get_card cards k, get_card cards l, get_card cards m]

def evaluate_best (cards : List Card) : HandRank :=
  let n := cards.length
  if n < 5 then
    let padded := cards ++ List.replicate (5 - n) (Card.new 0 0)
    evaluate_five padded
  else
    let combs := combinations5 n
    let ranks := combs.map (fun (i, j, k, l, m) =>
      evaluate_five (pick5 cards i j k l m))
    select_best ranks

theorem evaluate_best_deterministic (cards : List Card) :
    evaluate_best cards = evaluate_best cards := rfl

theorem combinations5_nonempty (n : Nat) (h : n ≥ 5) :
    combinations5 n ≠ [] := by
  intro h_empty
  have h_mem : (0, 1, 2, 3, 4) ∈ combinations5 n := by
    simp [combinations5, List.mem_bind, List.mem_map, List.mem_filter,
          List.mem_range]
    refine ⟨0, by omega, ?_⟩
    refine ⟨1, by omega, ?_⟩
    refine ⟨2, by omega, ?_⟩
    refine ⟨3, by omega, ?_⟩
    refine ⟨4, by omega, ?_⟩
    omega
  rw [h_empty] at h_mem
  exact List.not_mem_nil _ h_mem

theorem evaluate_best_is_maximum (cards : List Card) (h_len : cards.length ≥ 5) :
    ∀ h ∈ (combinations5 cards.length).map (fun (i, j, k, l, m) =>
      evaluate_five (pick5 cards i j k l m)),
    h < evaluate_best cards ∨ h = evaluate_best cards := by
  intro h hmem
  simp only [evaluate_best, if_neg (by omega : ¬cards.length < 5)]
  have h_ne : ((combinations5 cards.length).map (fun (i, j, k, l, m) =>
    evaluate_five (pick5 cards i j k l m))) ≠ [] := by
    intro h_empty
    rw [List.map_eq_nil_iff] at h_empty
    exact combinations5_nonempty _ h_len h_empty
  exact select_best_maximum _ h_ne h hmem

end HandRank

/-! ## find_winners -/

namespace HandRank

def find_winners (hands : List (Nat × List Card)) : List Nat :=
  if hands = [] then []
  else
    let ranks := hands.map (fun (s, c) => (s, evaluate_best c))
    let best := select_best (ranks.map (·.2))
    (ranks.filter (fun (s, r) => r = best)).map (·.1)

theorem find_winners_deterministic (hands : List (Nat × List Card)) :
    find_winners hands = find_winners hands := rfl

theorem find_winners_empty (hands : List (Nat × List Card)) :
    hands = [] → find_winners hands = [] := by
  intro h
  simp [find_winners, h]

end HandRank

/-! ## 主定理 -/

namespace HandRank

/-- **主定理 1（全序性）**：`lexLt` 是严格全序。 -/
theorem hand_rank_total_order :
    IsStrictTotalOrder HandRank lexLt :=
  lexLt_is_strict_total_order

/-- **主定理 2（决定性）** -/
theorem evaluate_best_is_deterministic (cards : List Card) :
    evaluate_best cards = evaluate_best cards := rfl

/-- **主定理 3（best-5-of-7 最大性）** -/
theorem evaluate_best_maximum (cards : List Card) (h_len : cards.length ≥ 5) :
    ∀ i j k l m,
      i < cards.length → j < cards.length → k < cards.length →
      l < cards.length → m < cards.length →
      i < j → j < k → k < l → l < m →
      evaluate_five (pick5 cards i j k l m) < evaluate_best cards ∨
      evaluate_five (pick5 cards i j k l m) = evaluate_best cards := by
  intro i j k l m hi hj hk hl hm hij jkl klm lm
  have h_mem : (i, j, k, l, m) ∈ combinations5 cards.length := by
    simp [combinations5, List.mem_bind, List.mem_map, List.mem_filter,
          List.mem_range]
    refine ⟨i, by omega, ?_⟩
    refine ⟨j, by omega, ?_⟩
    refine ⟨k, by omega, ?_⟩
    refine ⟨l, by omega, ?_⟩
    refine ⟨m, by omega, ?_⟩
    omega
  have h_in : evaluate_five (pick5 cards i j k l m) ∈
      (combinations5 cards.length).map (fun (i, j, k, l, m) =>
        evaluate_five (pick5 cards i j k l m)) :=
    List.mem_map_of_mem _ h_mem
  exact evaluate_best_is_maximum cards h_len _ h_in

end HandRank

end TexasPoker
