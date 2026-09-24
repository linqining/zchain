import PokerLeanExtracted.Model.Constants

/-!
# 边池分层（移植自 `poker_lean/PokerLean/State/{Types,SidePot}.lean`，镜像
`poker-settlement-core/src/side_pot.rs`）

Mathlib-free 纯定义。
-/

namespace TexasPoker

/-! ## 数据结构 -/

/-- 单座位下注快照（bet/folded/all_in），对应三个并行数组。 -/
structure SeatBet where
  bet : Nat
  folded : Bool
  all_in : Bool
deriving Repr, DecidableEq

/-- 单层 pot。 -/
structure SidePot where
  amount : Nat
  eligible_seats : Nat
deriving Repr, DecidableEq

namespace SidePot

def new (amount eligible_seats : Nat) : SidePot := ⟨amount, eligible_seats⟩

def seatBit (j : Nat) : Nat := 1 <<< j

end SidePot

/-! ## 单层贡献 -/

def contrib (bet prev level : Nat) : Nat :=
  if bet > prev then min bet level - prev else 0

def slice_amount (seats : List SeatBet) (prev level : Nat) : Nat :=
  (seats.map (fun s => contrib s.bet prev level)).sum

def slice_eligible : List SeatBet → Nat → Nat → Nat → Nat
  | [], _, _, _ => 0
  | s :: ss, j, prev, _ =>
    (if s.bet > prev ∧ s.folded = false then SidePot.seatBit j else 0) |||
    slice_eligible ss (j + 1) prev 0

def slice_layer (seats : List SeatBet) (prev level : Nat) : Nat × Nat :=
  (slice_amount seats prev level, slice_eligible seats 0 prev level)

/-! ## push_or_merge -/

def modify_last {α : Type} (f : α → α) : List α → List α
  | [] => []
  | [x] => [f x]
  | x :: xs => x :: modify_last f xs

def push_or_merge (pots : List SidePot) (amount eligible : Nat) : List SidePot :=
  if amount = 0 then pots
  else if eligible = 0 ∧ pots ≠ [] then
    modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots
  else
    pots ++ [SidePot.new amount eligible]

/-! ## 排序（insertion_sort，语义等价 Rust sort_unstable） -/

def insert_sorted (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≤ y then x :: y :: ys else y :: insert_sorted x ys

def insertion_sort : List Nat → List Nat
  | [] => []
  | x :: xs => insert_sorted x (insertion_sort xs)

/-- all-in 玩家（bet > 0）的下注水位列表。 -/
def all_in_bets (seats : List SeatBet) : List Nat :=
  (seats.filter (fun s => s.all_in = true && s.bet > 0)).map SeatBet.bet

/-! ## 顶层折叠 -/

def calculate_side_pots_fold_from (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total : Nat) : List SidePot × Nat :=
  levels.foldl (fun (pots, prev) level =>
    if level ≤ prev then (pots, prev)
    else
      let amt := slice_amount seats prev level
      let elig := slice_eligible seats 0 prev level
      (push_or_merge pots amt elig, level)) (pots, prev)

def calculate_side_pots_fold (seats : List SeatBet) (levels : List Nat) (total_pot : Nat) :
    List SidePot × Nat :=
  calculate_side_pots_fold_from seats levels [] 0 total_pot

def remaining_contrib (seats : List SeatBet) (prev : Nat) : Nat :=
  (seats.map (fun s => s.bet - min s.bet prev)).sum

/-- 计算边池分层（顶层入口）。 -/
def calculate_side_pots (seats : List SeatBet) : List SidePot :=
  let total := (seats.map SeatBet.bet).sum
  let levels := insertion_sort (all_in_bets seats)
  let r := calculate_side_pots_fold seats levels total
  let pots := r.1
  let prev := r.2
  let pots2 := if prev < total then
                 push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total)
               else pots
  if pots2 = [] then [SidePot.new total 0] else pots2

end TexasPoker
