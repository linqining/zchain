import PokerLeanExtracted.Model.Card

/-!
# 手牌评估器（移植自 `poker_lean/PokerLean/State/HandEvaluator.lean`，镜像
`poker_l1/src/vm/contracts/texas_poker/hand_evaluator.rs`）

含 2026-09-24 差分对拍修复后的 `build_groups`（(count, rank) 降序 + (0,0) 填充）
与 `evaluate_best` 填充花色循环（0,1,2,3）。Mathlib-free 纯定义。
-/

namespace TexasPoker

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

/-- 字典序严格序：category 优先，kickers 逐位。 -/
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

/-! ## select_best -/

def select_best : List HandRank → HandRank
  | [] => minRank
  | h :: t =>
    let best := select_best t
    if h < best then best else h

/-! ## 排序工具 -/

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

/-! ## 分组（(count, rank) 降序 + (0,0) 填充，镜像 hand_evaluator.rs:170-180） -/

def count_rank (rank : Nat) (cards : List Card) : Nat :=
  (cards.filter (fun c => c.rank = rank)).length

def pair_ge (a b : Nat × Nat) : Bool :=
  a.1 > b.1 ∨ (a.1 = b.1 ∧ a.2 ≥ b.2)

def insert_group_desc (x : Nat × Nat) : List (Nat × Nat) → List (Nat × Nat)
  | [] => [x]
  | y :: ys => if pair_ge x y then x :: y :: ys else y :: insert_group_desc x ys

def sort_groups_desc : List (Nat × Nat) → List (Nat × Nat)
  | [] => []
  | x :: xs => insert_group_desc x (sort_groups_desc xs)

def pad_groups (g : List (Nat × Nat)) : List (Nat × Nat) :=
  g ++ List.replicate (5 - min g.length 5) (0, 0)

def build_groups (cards : List Card) : List (Nat × Nat) :=
  let counts := (List.range 13).map (fun i => (count_rank (i + 2) cards, i + 2))
  pad_groups (sort_groups_desc (counts.filter (fun c => c.1 > 0)))

def get_group (g : List (Nat × Nat)) (i : Nat) : Nat × Nat :=
  g.getD i (0, 0)

/-! ## evaluate_five -/

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

/-! ## evaluate_best -/

def combinations5 (n : Nat) : List (Nat × Nat × Nat × Nat × Nat) :=
  (List.range n).flatMap fun i =>
  ((List.range n).filter (· > i)).flatMap fun j =>
  ((List.range n).filter (· > j)).flatMap fun k =>
  ((List.range n).filter (· > k)).flatMap fun l =>
  ((List.range n).filter (· > l)).map fun m => (i, j, k, l, m)

def get_card (cards : List Card) (idx : Nat) : Card :=
  cards.getD idx (Card.new 0 0)

def pick5 (cards : List Card) (i j k l m : Nat) : List Card :=
  [get_card cards i, get_card cards j, get_card cards k, get_card cards l, get_card cards m]

def evaluate_best (cards : List Card) : HandRank :=
  let n := cards.length
  if n < 5 then
    let padded := cards ++ (List.range (5 - n)).map (fun i => Card.new (i % 4) 0)
    evaluate_five padded
  else
    let combs := combinations5 n
    let ranks := combs.map (fun (i, j, k, l, m) =>
      evaluate_five (pick5 cards i j k l m))
    select_best ranks

/-! ## find_winners -/

def find_winners (hands : List (Nat × List Card)) : List Nat :=
  if hands = [] then []
  else
    let ranks := hands.map (fun (s, c) => (s, evaluate_best c))
    let best := select_best (ranks.map (·.2))
    (ranks.filter (fun (s, r) => r = best)).map (·.1)

end HandRank
end TexasPoker
