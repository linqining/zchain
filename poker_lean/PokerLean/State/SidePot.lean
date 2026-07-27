import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types

/-!
# Side Pot 分层正确性（Phase 3）

镜像 `poker_l1/src/vm/contracts/texas_poker/side_pot.rs`，证明：
- `side_pot_conservation`：各层 pot 金额之和 = 总下注
- `folded_not_eligible`：已 fold 的座位永不合格
- `side_pot_amount_nonneg`：金额非负
- `side_pot_deterministic`：同输入同输出（函数语义）

## 建模说明

- 输入用 `List SeatBet`（bet/folded/all_in 三元组），消除长度不匹配错误（Rust 的
  `LengthMismatch` 在 Lean 中结构性不可达）。
- `eligible_seats` 用 `Nat` 位掩码（Rust `u16`，MAX_PLAYERS=9 足够；Lean `Nat` 无溢出）。
- Rust `sort_unstable` → 自定义 `insertion_sort`（语义等价：均产出非降序列；决定性保持）。
- Rust `u64::MAX` 最外层水位 → 用 `total_pot`（≥ 每个 bet，故 `min bet total_pot = bet`）。
- Rust `checked_add` 溢出保护 → Lean `Nat` 无溢出 + `inv_chip_bounds`（Phase 2）。

## 守恒证明核心思路

关键恒等式：`contrib b prev level = min b level - min b prev`（Nat 截断减法）。

折叠不变量：`pots_sum + Σ_s (s.bet - min s.bet prev) = constant`。
- 初始：`pots = [], prev = 0` → `0 + Σ s.bet = total`。
- 处理层 `(prev, level)`：`slice_amount + remaining(level) = remaining(prev)`（望远镜求和）。
- 终态：`prev ≥ total` → `remaining = 0` → `pots_sum = total`。
-/

namespace TexasPoker

open Constants

/-! ## 输入结构 -/

/-- 单座位的下注快照（bet/folded/all_in）。对应 `calculate_side_pots` 三个并行数组。 -/
structure SeatBet where
  /-- 该座位本局总下注。 -/
  bet : Nat
  /-- 是否已 fold。 -/
  folded : Bool
  /-- 是否 all-in。 -/
  all_in : Bool
deriving Repr, DecidableEq

/-! ## 单层贡献 -/

/-- 单座位在 `[prev, level)` 区间的贡献 = `if bet > prev then min bet level - prev else 0`。

对应 `side_pot.rs:175-176` `cap - prev_level`（`bet > prev_level` 保证不截断）。 -/
def contrib (bet prev level : Nat) : Nat :=
  if bet > prev then min bet level - prev else 0

/-- 切片单层金额 = Σ_j contrib(seats[j].bet, prev, level)。 -/
def slice_amount (seats : List SeatBet) (prev level : Nat) : Nat :=
  (seats.map (fun s => contrib s.bet prev level)).sum

/-- 切片单层合格位掩码：第 j 位置 1 当且仅当 seats[j].bet > prev 且 seats[j] 未 fold。

对应 `side_pot.rs:172-182`。用递归定义便于归纳证明。 -/
def slice_eligible : List SeatBet → Nat → Nat → Nat → Nat
  | [], _, _, _ => 0
  | s :: ss, j, prev, _ =>
    (if s.bet > prev ∧ s.folded = false then SidePot.seatBit j else 0) |||
    slice_eligible ss (j + 1) prev 0

/-- 切片单层 = (金额, 合格掩码)。 -/
def slice_layer (seats : List SeatBet) (prev level : Nat) : Nat × Nat :=
  (slice_amount seats prev level, slice_eligible seats 0 prev level)

/-- `contrib` 非负（平凡，Nat）。 -/
theorem contrib_nonneg (bet prev level : Nat) : 0 ≤ contrib bet prev level := by
  simp only [contrib]
  split_ifs <;> omega

/-- **关键恒等式**：`contrib b prev level = min b level - min b prev`（Nat 截断减法）。

这是守恒证明的核心：使望远镜求和成立。 -/
theorem contrib_eq_min_diff (b prev level : Nat) :
    contrib b prev level = min b level - min b prev := by
  simp only [contrib]
  by_cases h : b > prev
  · -- b > prev: contrib = min b level - prev; min b prev = prev (因 prev < b)
    rw [if_pos h]
    have hmin : min b prev = prev := Nat.min_eq_right (Nat.le_of_lt h)
    rw [hmin]
  · -- b ≤ prev: contrib = 0; min b prev = b ≥ min b level → min b level - b = 0
    rw [if_neg h]
    have hle : b ≤ prev := Nat.le_of_not_lt h
    have hmin : min b prev = b := Nat.min_eq_left hle
    rw [hmin]
    omega

/-- `min` 关于第二参数单调。 -/
theorem min_le_min_right (b prev level : Nat) (h : prev ≤ level) :
    min b prev ≤ min b level := by omega

/-! ## push_or_merge -/

/-- 修改列表最后一个元素。 -/
def modify_last {α : Type} (f : α → α) : List α → List α
  | [] => []
  | [x] => [f x]
  | x :: xs => x :: modify_last f xs

/-- `push_or_merge`：对应 `side_pot.rs:190-200`。

- `amount = 0`：不变。
- `eligible = 0 ∧ pots ≠ []`：金额并入最后一层（合并）。
- 否则：push 新层。 -/
def push_or_merge (pots : List SidePot) (amount eligible : Nat) : List SidePot :=
  if amount = 0 then pots
  else if eligible = 0 ∧ pots ≠ [] then
    modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots
  else
    pots ++ [SidePot.new amount eligible]

/-- `modify_last` 保持列表长度。 -/
theorem modify_last_length {α : Type} (f : α → α) (l : List α) :
    (modify_last f l).length = l.length := by
  induction l with
  | nil => rfl
  | cons x xs ih =>
    cases xs with
    | nil => rfl
    | cons y ys => simp [modify_last, ih]

/-- `modify_last` 非空时，金额和增加 `amount`。 -/
theorem modify_last_amount_sum (pots : List SidePot) (amount : Nat) (h_ne : pots ≠ []) :
    (modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots).map
      SidePot.amount |>.sum =
      (pots.map SidePot.amount).sum + amount := by
  induction pots with
  | nil => simp at h_ne
  | cons x xs ih =>
    cases xs with
    | nil => simp [modify_last, SidePot.new]
    | cons y ys =>
      simp [modify_last]
      have h_ne' : y :: ys ≠ [] := by simp
      have ih' := ih h_ne'
      simp only [List.map_cons, List.sum_cons] at ih' ⊢
      omega

/-- **push_or_merge 金额守恒**：结果金额和 = 原金额和 + amount。 -/
theorem push_or_merge_amount_sum (pots : List SidePot) (amount eligible : Nat) :
    (push_or_merge pots amount eligible).map SidePot.amount |>.sum =
      (pots.map SidePot.amount).sum + amount := by
  by_cases h_amt : amount = 0
  · simp [push_or_merge, h_amt]
  · by_cases h_elig : eligible = 0
    · by_cases h_empty : pots = []
      · simp [push_or_merge, h_amt, h_elig, h_empty, SidePot.new]
      · simp [push_or_merge, h_amt, h_elig, h_empty]
        exact modify_last_amount_sum pots amount h_empty
    · simp [push_or_merge, h_amt, h_elig, SidePot.new]
      omega

/-! ## 排序（insertion_sort，语义等价 Rust sort_unstable） -/

/-- 升序插入。 -/
def insert_sorted (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≤ y then x :: y :: ys else y :: insert_sorted x ys

/-- 升序排序（非降序，保留重复）。 -/
def insertion_sort : List Nat → List Nat
  | [] => []
  | x :: xs => insert_sorted x (insertion_sort xs)

/-- `insert_sorted` 的成员关系。 -/
theorem mem_insert_sorted (x z : Nat) (l : List Nat) :
    z ∈ insert_sorted x l ↔ z = x ∨ z ∈ l := by
  induction l with
  | nil => simp [insert_sorted, List.mem_singleton]
  | cons y ys ih =>
    simp only [insert_sorted]
    split_ifs with h
    · simp [List.mem_cons]
    · constructor
      · rintro (rfl | h)
        · right; left
        · rcases ih.mp h with rfl | hmem
          · right; left
          · right; right; exact hmem
      · rintro (rfl | h)
        · left
        · rcases h with rfl | hmem
          · right; left
          · right; right; exact ih.mpr (Or.inr hmem)

/-- `insert_sorted` 保持非降序。 -/
theorem insert_sorted_sorted (x : Nat) (l : List Nat) (h : List.Sorted (· ≤ ·) l) :
    List.Sorted (· ≤ ·) (insert_sorted x l) := by
  induction l with
  | nil => simp [insert_sorted, List.Sorted]
  | cons y ys ih =>
    simp only [insert_sorted]
    split_ifs with hxy
    · -- x ≤ y: result is x :: y :: ys
      rw [List.sorted_cons]
      refine ⟨?_, h⟩
      intro z hz
      rcases List.mem_cons.mp hz with rfl | hzmem
      · exact hxy
      · exact List.rel_of_sorted_cons h z hzmem
    · -- ¬(x ≤ y), i.e. y < x: result is y :: insert_sorted x ys
      rw [List.sorted_cons]
      refine ⟨?_, ih h.of_cons⟩
      intro z hz
      rcases (mem_insert_sorted x z ys).mp hz with rfl | hzmem
      · omega
      · exact List.rel_of_sorted_cons h z hzmem

/-- `insertion_sort` 产出非降序列。 -/
theorem insertion_sort_sorted (l : List Nat) : List.Sorted (· ≤ ·) (insertion_sort l) := by
  induction l with
  | nil => simp [insertion_sort, List.Sorted]
  | cons x xs ih => exact insert_sorted_sorted x (insertion_sort xs) ih

/-- all-in 玩家（bet > 0）的下注水位列表。 -/
def all_in_bets (seats : List SeatBet) : List Nat :=
  (seats.filter (fun s => s.all_in = true && s.bet > 0)).map SeatBet.bet

/-! ## 通用折叠（可变初始 accumulator） -/

/-- 通用折叠：从任意 `(pots, prev)` 开始。 -/
def calculate_side_pots_fold_from (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total : Nat) : List SidePot × Nat :=
  levels.foldl (fun (pots, prev) level =>
    if level ≤ prev then (pots, prev)
    else
      let amt := slice_amount seats prev level
      let elig := slice_eligible seats 0 prev level
      (push_or_merge pots amt elig, level)) (pots, prev)

/-- `calculate_side_pots_fold` = 从 `([], 0)` 开始的通用折叠。 -/
def calculate_side_pots_fold (seats : List SeatBet) (levels : List Nat) (total_pot : Nat) :
    List SidePot × Nat :=
  calculate_side_pots_fold_from seats levels [] 0 total_pot

/-- `remaining_contrib seats prev = Σ_s (s.bet - min s.bet prev)`。

表示 `[prev, ∞)` 区间尚未切片的总额。 -/
def remaining_contrib (seats : List SeatBet) (prev : Nat) : Nat :=
  (seats.map (fun s => s.bet - min s.bet prev)).sum

/-- `slice_amount + remaining(level) = remaining(prev)`（核心望远镜等式）。

对每个座位：`(min b level - min b prev) + (b - min b level) = b - min b prev`。 -/
theorem slice_plus_remaining (seats : List SeatBet) (prev level : Nat) (h_prev_le_level : prev ≤ level) :
    slice_amount seats prev level + remaining_contrib seats level = remaining_contrib seats prev := by
  -- slice_amount = Σ contrib s.bet prev level = Σ (min s.bet level - min s.bet prev)
  unfold slice_amount remaining_contrib
  -- 逐元素归纳
  induction seats with
  | nil => simp [contrib]
  | cons s ss ih =>
    simp only [List.map_cons, List.sum_cons]
    -- contrib s.bet prev level + (s.bet - min s.bet level) = s.bet - min s.bet prev
    have h_key : contrib s.bet prev level + (s.bet - min s.bet level) = s.bet - min s.bet prev := by
      rw [contrib_eq_min_diff]
      -- (min s.bet level - min s.bet prev) + (s.bet - min s.bet level) = s.bet - min s.bet prev
      have h1 : min s.bet prev ≤ min s.bet level := min_le_min_right s.bet prev level h_prev_le_level
      omega
    -- 应用归纳假设
    have h_contrib := h_key
    have h_rest := ih
    -- 重组
    have : contrib s.bet prev level + (s.bet - min s.bet level) + 
           ((ss.map (fun s => contrib s.bet prev level)).sum + (ss.map (fun s => s.bet - min s.bet level)).sum) =
           (s.bet - min s.bet prev) + (ss.map (fun s => s.bet - min s.bet prev)).sum := by
      rw [← h_key]
      have : ((ss.map (fun s => contrib s.bet prev level)).sum + (ss.map (fun s => s.bet - min s.bet level)).sum) =
             ((ss.map (fun s => s.bet - min s.bet prev)).sum) := h_rest
      omega
    exact this

/-- **折叠不变量**：`pots_sum + remaining(prev) = initial_pots_sum + remaining(initial_prev)`。

这是守恒证明的核心：折叠保持 `pots_sum + remaining` 恒定。 -/
theorem fold_invariant (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total : Nat) :
    (calculate_side_pots_fold_from seats levels pots prev total).1.map SidePot.amount |>.sum +
    remaining_contrib seats (calculate_side_pots_fold_from seats levels pots prev total).2 =
    (pots.map SidePot.amount).sum + remaining_contrib seats prev := by
  induction levels generalizing pots prev with
  | nil =>
    -- 空列表：foldl 返回 (pots, prev)
    simp [calculate_side_pots_fold_from]
  | cons l ls ih =>
    -- 第一步：处理 l
    simp only [calculate_side_pots_fold_from, List.foldl_cons]
    by_cases h_le : l ≤ prev
    · -- l ≤ prev：跳过，递归从 (pots, prev) 继续
      rw [if_pos h_le]
      exact ih pots prev
    · -- l > prev：处理 (prev, l)，递归从 (push_or_merge ..., l) 继续
      rw [if_neg h_le]
      -- 设 pots' = push_or_merge pots (slice_amount ...) (slice_eligible ...)
      -- prev' = l
      -- 由 ih：pots'_sum + remaining(l) = pots_sum + slice_amount + remaining(l)
      --        = pots_sum + remaining(prev)  (by slice_plus_remaining)
      have h_prev_le_l : prev ≤ l := Nat.le_of_not_lt (fun h => h_le (Nat.le_of_lt h))
      have h_step : (calculate_side_pots_fold_from seats ls
          (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) l total).1.map
          SidePot.amount |>.sum +
          remaining_contrib seats
            (calculate_side_pots_fold_from seats ls
              (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) l total).2 =
          (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)).map
            SidePot.amount |>.sum + remaining_contrib seats l := by
        exact ih (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) l
      rw [h_step]
      -- push_or_merge_amount_sum: (push_or_merge ...).map amount |>.sum = pots_sum + slice_amount
      have h_push : (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)).map
          SidePot.amount |>.sum = (pots.map SidePot.amount).sum + slice_amount seats prev l :=
        push_or_merge_amount_sum pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)
      rw [h_push]
      -- slice_plus_remaining: slice_amount + remaining(l) = remaining(prev)
      exact slice_plus_remaining seats prev l h_prev_le_l

/-! ## 顶层 calculate_side_pots -/

/-- 计算边池分层。对应 `side_pot.rs:110-158`。 -/
def calculate_side_pots (seats : List SeatBet) : List SidePot :=
  let total := (seats.map SeatBet.bet).sum
  let levels := insertion_sort (all_in_bets seats)
  let (pots, prev) := calculate_side_pots_fold seats levels total
  let pots := if prev < total then
                let amt := slice_amount seats prev total
                let elig := slice_eligible seats 0 prev total
                push_or_merge pots amt elig
              else pots
  if pots = [] then [SidePot.new total 0] else pots

/-! ## 关键定理 -/

/-- `side_pot` 金额非负。 -/
theorem side_pot_amount_nonneg (p : SidePot) : 0 ≤ p.amount := Nat.zero_le _

/-- 辅助：`remaining_contrib seats 0 = Σ s.bet`（因 `min b 0 = 0`）。 -/
theorem remaining_contrib_zero (seats : List SeatBet) :
    remaining_contrib seats 0 = (seats.map SeatBet.bet).sum := by
  simp [remaining_contrib]
  induction seats with
  | nil => rfl
  | cons s ss ih =>
    simp [List.map_cons, List.sum_cons]
    show s.bet - min s.bet 0 + (ss.map (fun s => s.bet - min s.bet 0)).sum = s.bet + (ss.map SeatBet.bet).sum
    rw [Nat.min_eq_right (Nat.zero_le s.bet)]
    simp at ih
    rw [ih]
    simp

/-- 辅助：`total ≥ s.bet → remaining_contrib seats total = 0`（因 `min b total = b`）。 -/
theorem remaining_contrib_total (seats : List SeatBet) (total : Nat)
    (h_all_le : ∀ s ∈ seats, s.bet ≤ total) :
    remaining_contrib seats total = 0 := by
  simp [remaining_contrib]
  induction seats with
  | nil => rfl
  | cons s ss ih =>
    simp [List.map_cons, List.sum_cons]
    have hs : s.bet ≤ total := h_all_le s (List.mem_cons_self s ss)
    have hss : ∀ s' ∈ ss, s'.bet ≤ total := fun s' hs' => h_all_le s' (List.mem_cons_of_mem s hs')
    rw [Nat.min_eq_left hs]
    have := ih hss
    omega

/-- **守恒定理**：各层 pot 金额之和 = 总下注。

对应 `side_pot.rs` 测试中 `result.total() == sum_bets` 的断言。

证明：由 `fold_invariant`，折叠后 `pots_sum + remaining(prev) = 0 + remaining(0) = Σ s.bet = total`。
若 `prev < total`，外层补足 `slice_amount seats prev total`，`remaining(total) = 0`。
若 `prev ≥ total`，`remaining(prev) = 0`（因 `min s.bet prev = s.bet`）。
空列表兜底 `pots = [total]`，平凡守恒。 -/
theorem side_pot_conservation (seats : List SeatBet) :
    (calculate_side_pots seats).map SidePot.amount |>.sum =
      (seats.map SeatBet.bet).sum := by
  -- 展开 calculate_side_pots
  unfold calculate_side_pots
  -- 设 total = Σ s.bet, levels = insertion_sort (all_in_bets seats)
  set total := (seats.map SeatBet.bet).sum with h_total_def
  set levels := insertion_sort (all_in_bets seats) with h_levels_def
  -- 折叠
  set fold_result := calculate_side_pots_fold seats levels total with h_fold_def
  set pots := fold_result.1 with h_pots_def
  set prev := fold_result.2 with h_prev_def
  -- 外层
  set pots2 := if prev < total then
                 let amt := slice_amount seats prev total
                 let elig := slice_eligible seats 0 prev total
                 push_or_merge pots amt elig
               else pots with h_pots2_def
  -- 关键：total = Σ s.bet（由定义）
  -- 由 fold_invariant: pots_sum + remaining(prev) = 0 + remaining(0) = Σ s.bet = total
  have h_fold_inv : (pots.map SidePot.amount).sum + remaining_contrib seats prev =
      (seats.map SeatBet.bet).sum := by
    have h := fold_invariant seats levels [] 0 total
    -- calculate_side_pots_fold_from seats levels [] 0 total = calculate_side_pots_fold seats levels total
    have h_eq : calculate_side_pots_fold_from seats levels [] 0 total = calculate_side_pots_fold seats levels total := rfl
    rw [h_eq] at h
    -- h: (fold_result.1.map amount).sum + remaining_contrib seats fold_result.2 = ([]).map amount |>.sum + remaining_contrib seats 0
    -- = 0 + remaining_contrib seats 0 = remaining_contrib seats 0 = Σ s.bet
    rw [h_pots_def, h_prev_def] at h
    rw [List.map_nil, List.sum_nil, zero_add] at h
    rw [← h_total_def]
    exact h
  -- total ≥ 每个 s.bet（因 total = Σ s.bet ≥ s.bet）
  have h_total_ge : ∀ s ∈ seats, s.bet ≤ total := by
    intro s hs
    exact List.le_sum_of_mem (List.map SeatBet.bet seats) (List.mem_map_of_mem SeatBet.bet hs)
  -- 分情况讨论 pots2 = []
  by_cases h_pots2_empty : pots2 = []
  · -- pots2 = []：结果为 [SidePot.new total 0]
    simp [h_pots2_empty]
    show total = (seats.map SeatBet.bet).sum
    exact h_total_def
  · -- pots2 ≠ []：结果为 pots2
    simp [h_pots2_empty]
    -- 需证 (pots2.map amount).sum = total
    -- 分情况：prev < total 或 prev ≥ total
    by_cases h_prev_lt : prev < total
    · -- prev < total：pots2 = push_or_merge pots (slice_amount seats prev total) (slice_eligible ...)
      have h_pots2_eq : pots2 = push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total) := by
        simp [h_pots2_def, h_prev_lt]
      rw [h_pots2_eq]
      -- (push_or_merge ...).map amount |>.sum = pots_sum + slice_amount seats prev total
      rw [push_or_merge_amount_sum]
      -- 需证 pots_sum + slice_amount + remaining(total) ... 不，直接证 pots_sum + slice_amount = total
      -- 由 fold_inv: pots_sum + remaining(prev) = total
      -- 由 slice_plus_remaining: slice_amount + remaining(total) = remaining(prev)（当 prev ≤ total）
      have h_prev_le_total : prev ≤ total := Nat.le_of_lt h_prev_lt
      have h_slice_rem : slice_amount seats prev total + remaining_contrib seats total = remaining_contrib seats prev :=
        slice_plus_remaining seats prev total h_prev_le_total
      have h_rem_total : remaining_contrib seats total = 0 :=
        remaining_contrib_total seats total h_total_ge
      -- pots_sum + slice_amount = total
      omega
    · -- prev ≥ total：pots2 = pots
      have h_prev_ge : prev ≥ total := Nat.le_of_not_lt h_prev_lt
      have h_pots2_eq : pots2 = pots := by
        simp [h_pots2_def, h_prev_lt]
      rw [h_pots2_eq]
      -- 需证 pots_sum = total
      -- 由 fold_inv: pots_sum + remaining(prev) = total
      -- prev ≥ total ≥ s.bet → remaining(prev) = 0
      have h_rem_prev : remaining_contrib seats prev = 0 := by
        apply remaining_contrib_total seats prev
        intro s hs
        exact Nat.le_trans (h_total_ge s hs) h_prev_ge
      omega

/-! ## folded 永不合格

证明策略（自底向上）：
1. `seatBit_eq_two_pow`：`seatBit k = 2^k`（用 `Nat.shiftLeft_eq`）。
2. `seatBit_and_seatBit_of_ne`：`k ≠ i → seatBit k &&& seatBit i = 0`（用 `Nat.and_two_pow`
   + `Nat.testBit_two_pow_of_ne`）。
3. `and_or_distrib_right`：`(a ||| b) &&& c = (a &&& c) ||| (b &&& c)`（用
   `Nat.land_comm` + `Nat.and_or_distrib_left`）。
4. `slice_eligible_and_seatBit_below`：`m < j → slice_eligible seats j prev level &&& seatBit m = 0`
   （bit 低于起始 j 永不置位）。
5. `slice_eligible_and_seatBit_folded`：j ≤ m 且 seats[m-j].folded = true → AND = 0。
6. `slice_eligible_folded_not_set`：j=0 的特例（对外的接口）。
7. `all_pots_zero_bit` + `push_or_merge_preserves_zero_bit` + `fold_preserves_zero_bit`：
   折叠保持「所有 pot 的 bit i = 0」。
8. `folded_not_eligible`：顶层组合。 -/

/-- `seatBit k = 2^k`（由 `1 <<< k = 1 * 2^k`）。 -/
theorem seatBit_eq_two_pow (k : Nat) : SidePot.seatBit k = 2 ^ k := by
  show 1 <<< k = 2 ^ k
  rw [Nat.shiftLeft_eq, one_mul]

/-- **不同位掩码 AND 为 0**：`k ≠ i → seatBit k &&& seatBit i = 0`。

证明：`seatBit k &&& seatBit i = 2^k &&& 2^i = (2^k).testBit i).toNat * 2^i`（由
`Nat.and_two_pow`），而 `k ≠ i → (2^k).testBit i = false`（由 `Nat.testBit_two_pow_of_ne`），
故 = `0 * 2^i = 0`。 -/
theorem seatBit_and_seatBit_of_ne {k i : Nat} (h : k ≠ i) :
    SidePot.seatBit k &&& SidePot.seatBit i = 0 := by
  rw [seatBit_eq_two_pow, seatBit_eq_two_pow, Nat.and_two_pow]
  have htb : (2 ^ k).testBit i = false := Nat.testBit_two_pow_of_ne h
  rw [htb, Bool.toNat_false, zero_mul]

/-- `(a ||| b) &&& c = (a &&& c) ||| (b &&& c)`（右分配律）。

由 `Nat.land_comm` + `Nat.and_or_distrib_left` 推出。 -/
theorem and_or_distrib_right (a b c : Nat) :
    (a ||| b) &&& c = (a &&& c) ||| (b &&& c) := by
  rw [Nat.land_comm, Nat.and_or_distrib_left, Nat.land_comm c a, Nat.land_comm c b]

/-- **低于起始 j 的位永不置位**：`m < j → slice_eligible seats j prev level &&& seatBit m = 0`。

证明：递归时每步 `seatBit j` 与 `seatBit m`（m < j）AND = 0（不同位），归纳保持。

注：归纳泛化 `level`，因递归调用用 `level = 0` 而外层用任意 `level`。 -/
theorem slice_eligible_and_seatBit_below (seats : List SeatBet) (j prev level m : Nat)
    (h_mj : m < j) :
    slice_eligible seats j prev level &&& SidePot.seatBit m = 0 := by
  induction seats generalizing j m level with
  | nil => simp [slice_eligible]
  | cons s ss ih =>
    simp only [slice_eligible]
    rw [and_or_distrib_right]
    have h_first : (if s.bet > prev ∧ s.folded = false then SidePot.seatBit j else 0)
        &&& SidePot.seatBit m = 0 := by
      split_ifs with h_cond
      · -- seatBit j &&& seatBit m，j ≠ m（因 m < j）
        exact seatBit_and_seatBit_of_ne (by omega)
      · simp
    have h_second : slice_eligible ss (j + 1) prev 0 &&& SidePot.seatBit m = 0 :=
      ih (j + 1) m 0 (by omega)
    simp [h_first, h_second]

/-- **folded 座位在任意起点 j 的切片中均不合格**（广义版）。

若 `j ≤ m`、`m - j < seats.length`、`seats[m-j].folded = true`，则
`slice_eligible seats j prev level &&& seatBit m = 0`。

证明：分 `m = j`（当前座位 folded → 条件 false）与 `m > j`（不同位 AND = 0，递归保持）。 -/
theorem slice_eligible_and_seatBit_folded (seats : List SeatBet) (j prev level m : Nat)
    (h_jle : j ≤ m) (h_idx : m - j < seats.length)
    (h_folded : (seats.get ⟨m - j, h_idx⟩).folded = true) :
    slice_eligible seats j prev level &&& SidePot.seatBit m = 0 := by
  revert h_jle h_idx h_folded
  induction seats generalizing j m level with
  | nil => intro _ h_idx; simp at h_idx
  | cons s ss ih =>
    intros h_jle h_idx h_folded
    simp only [slice_eligible]
    rw [and_or_distrib_right]
    -- 第一部分：(if s.bet > prev ∧ s.folded = false then seatBit j else 0) &&& seatBit m
    have h_first : (if s.bet > prev ∧ s.folded = false then SidePot.seatBit j else 0)
        &&& SidePot.seatBit m = 0 := by
      by_cases hmj : m = j
      · -- m = j：s.folded = true → 条件 false
        have h_mj_zero : m - j = 0 := by omega
        rw [h_mj_zero] at h_idx h_folded
        -- (s::ss).get ⟨0, h_idx⟩ = s（List.get 定义）
        have h_get : (s :: ss).get ⟨0, h_idx⟩ = s := rfl
        rw [h_get] at h_folded
        have h_not_cond : ¬ (s.bet > prev ∧ s.folded = false) := by
          intro h
          rw [h_folded] at h
          simp at h
        rw [if_neg h_not_cond]
        simp
      · -- m ≠ j → j < m → seatBit j &&& seatBit m = 0
        have hjm_ne : j ≠ m := by omega
        split_ifs with h_cond
        · exact seatBit_and_seatBit_of_ne hjm_ne
        · simp
    -- 第二部分：slice_eligible ss (j+1) prev 0 &&& seatBit m
    have h_second : slice_eligible ss (j + 1) prev 0 &&& SidePot.seatBit m = 0 := by
      by_cases hmj : m = j
      · -- m = j < j+1，用 _below 引理
        exact slice_eligible_and_seatBit_below ss (j + 1) prev 0 m (by omega)
      · -- m ≠ j，j ≤ m → j < m → j+1 ≤ m
        have h_jl_m : j < m := by omega
        have h_j1_le_m : j + 1 ≤ m := Nat.succ_le_of_lt h_jl_m
        -- h_idx' : m - (j+1) < ss.length
        have h_idx' : m - (j + 1) < ss.length := by
          have h_len : (s :: ss).length = ss.length + 1 := rfl
          rw [h_len] at h_idx
          omega
        -- h_folded' : (ss.get ⟨m-(j+1), h_idx'⟩).folded = true
        have h_folded' : (ss.get ⟨m - (j + 1), h_idx'⟩).folded = true := by
          -- 由 List.get_cons_succ：(s::ss).get ⟨(m-j-1)+1, h_idx⟩ = ss.get ⟨m-j-1, ...⟩
          have h_mj_succ : m - j = (m - j - 1) + 1 := by omega
          have h_get : (s :: ss).get ⟨m - j, h_idx⟩ =
              ss.get ⟨m - j - 1, Nat.lt_of_succ_lt_succ h_idx⟩ := by
            rw [h_mj_succ]
            exact List.get_cons_succ s ss (m - j - 1) h_idx
          rw [h_get] at h_folded
          -- h_folded : (ss.get ⟨m-j-1, Nat.lt_of_succ_lt_succ h_idx⟩).folded = true
          -- m-(j+1) = m-j-1
          have h_eq : m - (j + 1) = m - j - 1 := by omega
          rw [h_eq] at h_idx'
          -- h_idx' : m-j-1 < ss.length（重写后）
          -- 用 Fin 证明不相关性匹配
          convert h_folded using 2
        exact ih (j + 1) m 0 h_j1_le_m h_idx' h_folded'
    simp [h_first, h_second]

/-- `slice_eligible` 对 folded 座位不置位（j=0 特例，对外接口）。 -/
theorem slice_eligible_folded_not_set (seats : List SeatBet) (i : Nat) (prev level : Nat)
    (h_i : i < seats.length) (h_folded : (seats.get ⟨i, h_i⟩).folded = true) :
    slice_eligible seats 0 prev level &&& SidePot.seatBit i = 0 := by
  apply slice_eligible_and_seatBit_folded seats 0 prev level i
  · -- 0 ≤ i
    exact Nat.zero_le i
  · -- i - 0 < seats.length
    rw [Nat.sub_zero]; exact h_i
  · -- seats.get ⟨i-0, ...⟩.folded = true
    rwa [Nat.sub_zero] at h_folded

/-! ### 折叠保持「所有 pot 的 bit i = 0」 -/

/-- 谓词：所有 pot 的 eligible_seats 第 i 位均为 0。 -/
def all_pots_zero_bit (pots : List SidePot) (i : Nat) : Prop :=
  ∀ p ∈ pots, p.eligible_seats &&& SidePot.seatBit i = 0

/-- `modify_last` 保持 `eligible_seats` 字段（仅改 amount）。 -/
theorem modify_last_preserves_eligible (pots : List SidePot) (amount : Nat) :
    all_pots_zero_bit pots i →
    all_pots_zero_bit (modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots) i := by
  intro h_all p hp
  induction pots with
  | nil => simp at hp
  | cons x xs ih =>
    cases xs with
    | nil =>
      -- modify_last f [x] = [f x]
      simp [modify_last] at hp
      simp [modify_last]
      -- p = SidePot.new (x.amount + amount) x.eligible_seats
      -- eligible_seats = x.eligible_seats，由 h_all x (mem_cons_self)
      have : p.eligible_seats = x.eligible_seats := by
        rw [hp]; rfl
      rw [this]
      exact h_all x (List.mem_cons_self x [])
    | cons y ys =>
      -- modify_last f (x :: y :: ys) = x :: modify_last f (y :: ys)
      simp [modify_last] at hp
      rcases hp with rfl | hp
      · -- p = x
        exact h_all x (List.mem_cons_self x (y :: ys))
      · -- p ∈ modify_last f (y :: ys)
        have h_xs_zero : all_pots_zero_bit (y :: ys) i := fun p' hp' =>
          h_all p' (List.mem_cons_of_mem x hp')
        exact ih h_xs_zero hp

/-- **push_or_merge 保持零位**：若 pots 全零位且 eligible 零位，结果全零位。 -/
theorem push_or_merge_preserves_zero_bit (pots : List SidePot) (amount eligible i : Nat)
    (h_pots : all_pots_zero_bit pots i) (h_elig : eligible &&& SidePot.seatBit i = 0) :
    all_pots_zero_bit (push_or_merge pots amount eligible) i := by
  intro p hp
  by_cases h_amt : amount = 0
  · -- push_or_merge = pots
    simp [push_or_merge, h_amt] at hp
    exact h_pots p hp
  by_cases h_elig_zero : eligible = 0
  · by_cases h_empty : pots = []
    · -- push_or_merge = [SidePot.new amount 0]（pots = []）
      simp [push_or_merge, h_amt, h_elig_zero, h_empty, SidePot.new] at hp
      -- p = SidePot.new amount 0，eligible_seats = 0
      simp [hp]
      -- 0 &&& seatBit i = 0
      simp
    · -- push_or_merge = modify_last ... pots
      simp [push_or_merge, h_amt, h_elig_zero, h_empty] at hp
      have h_in : p ∈ modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots := hp
      have : all_pots_zero_bit (modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots) i :=
        modify_last_preserves_eligible pots amount h_pots
      exact this p h_in
  · -- push_or_merge = pots ++ [SidePot.new amount eligible]
    simp [push_or_merge, h_amt, h_elig_zero, SidePot.new] at hp
    rcases hp with hp | rfl
    · exact h_pots p hp
    · -- p = SidePot.new amount eligible，eligible_seats = eligible
      simp
      exact h_elig

/-- **折叠保持零位**：`calculate_side_pots_fold_from` 从零位初始 pots 出发，
   在 seat i folded 的前提下，结果所有 pot 的 bit i = 0。

关键：`slice_eligible seats 0 prev level &&& seatBit i = 0` 对任意 `prev level` 成立
（由 `slice_eligible_folded_not_set`），故每步 `push_or_merge` 都保持零位。 -/
theorem fold_preserves_zero_bit (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total i : Nat)
    (h_i_len : i < seats.length)
    (h_i_folded : (seats.get ⟨i, h_i_len⟩).folded = true) :
    all_pots_zero_bit pots i →
    all_pots_zero_bit (calculate_side_pots_fold_from seats levels pots prev total).1 i := by
  induction levels generalizing pots prev with
  | nil => intro h_init; exact h_init
  | cons l ls ih =>
    intro h_init
    simp only [calculate_side_pots_fold_from, List.foldl_cons]
    by_cases h_le : l ≤ prev
    · -- 跳过：递归从 (pots, prev)
      rw [if_pos h_le]
      exact ih pots prev h_init
    · -- 处理 (prev, l)：push_or_merge pots (slice_amount ...) (slice_eligible ...)
      rw [if_neg h_le]
      -- slice_eligible seats 0 prev l &&& seatBit i = 0（因 seat i folded）
      have h_elig_zero : slice_eligible seats 0 prev l &&& SidePot.seatBit i = 0 :=
        slice_eligible_folded_not_set seats i prev l h_i_len h_i_folded
      -- push_or_merge 保持零位
      have h_pots' : all_pots_zero_bit
          (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) i :=
        push_or_merge_preserves_zero_bit pots (slice_amount seats prev l)
          (slice_eligible seats 0 prev l) i h_init h_elig_zero
      -- 递归：从 (pots', l) 继续
      exact ih (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) l h_pots'

/-- **folded 永不合格**：已 fold 的座位在所有 pot 的 eligible_seats 中位 0。

对应 `side_pot.rs:178` `if !folded[j]` 条件。

证明：
1. `calculate_side_pots_fold` 从 `[]` 出发，由 `fold_preserves_zero_bit` 结果全零位。
2. 外层 `push_or_merge`（若 `prev < total`）的 eligible = `slice_eligible ...`，bit i = 0（folded）。
3. 空兜底 `[SidePot.new total 0]`，mask = 0，bit i = 0。
4. `isEligible mask i = (mask &&& seatBit i) ≠ 0`，bit i = 0 即 `isEligible = false`。 -/
theorem folded_not_eligible (seats : List SeatBet) (i : Nat)
    (h_i : i < seats.length) (h_folded : (seats.get ⟨i, h_i⟩).folded = true) :
    ∀ p ∈ calculate_side_pots seats, SidePot.isEligible p.eligible_seats i = false := by
  -- 展开 calculate_side_pots
  unfold calculate_side_pots
  -- 绑定中间量
  set total := (seats.map SeatBet.bet).sum with h_total_def
  set levels := insertion_sort (all_in_bets seats) with h_levels_def
  set fold_result := calculate_side_pots_fold seats levels total with h_fold_def
  set pots := fold_result.1 with h_pots_def
  set prev := fold_result.2 with h_prev_def
  set pots2 := if prev < total then
                 push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total)
               else pots with h_pots2_def
  -- 结果 = if pots2 = [] then [SidePot.new total 0] else pots2
  intro p hp
  -- 由 fold_preserves_zero_bit：pots 全零位
  have h_pots_zero : all_pots_zero_bit pots i := by
    have h := fold_preserves_zero_bit seats levels [] 0 total i h_i h_folded
    -- calculate_side_pots_fold_from seats levels [] 0 total = calculate_side_pots_fold seats levels total
    have h_eq : calculate_side_pots_fold_from seats levels [] 0 total = calculate_side_pots_fold seats levels total := rfl
    rw [h_eq] at h
    -- h : all_pots_zero_bit [] i → all_pots_zero_bit fold_result.1 i
    have h_nil : all_pots_zero_bit [] i := by simp [all_pots_zero_bit]
    exact h h_nil
  -- pots2 全零位
  have h_pots2_zero : all_pots_zero_bit pots2 i := by
    by_cases h_prev_lt : prev < total
    · -- pots2 = push_or_merge pots (slice_amount ...) (slice_eligible ...)
      have h_pots2_eq : pots2 = push_or_merge pots (slice_amount seats prev total)
          (slice_eligible seats 0 prev total) := by
        simp [h_pots2_def, h_prev_lt]
      rw [h_pots2_eq]
      have h_elig_zero : slice_eligible seats 0 prev total &&& SidePot.seatBit i = 0 :=
        slice_eligible_folded_not_set seats i prev total h_i h_folded
      exact push_or_merge_preserves_zero_bit pots (slice_amount seats prev total)
        (slice_eligible seats 0 prev total) i h_pots_zero h_elig_zero
    · -- pots2 = pots
      have h_pots2_eq : pots2 = pots := by simp [h_pots2_def, h_prev_lt]
      rw [h_pots2_eq]
      exact h_pots_zero
  -- 分情况：pots2 = [] 或 ≠ []
  by_cases h_pots2_empty : pots2 = []
  · -- 结果 = [SidePot.new total 0]，p = SidePot.new total 0
    simp [h_pots2_empty] at hp
    -- hp : p = SidePot.new total 0
    rw [hp]
    -- SidePot.new total 0 = ⟨total, 0⟩，eligible_seats = 0
    -- isEligible 0 i = (0 &&& seatBit i) ≠ 0 = 0 ≠ 0 = false
    simp [SidePot.new, SidePot.isEligible]
  · -- 结果 = pots2，p ∈ pots2
    simp [h_pots2_empty] at hp
    -- p ∈ pots2，由 h_pots2_zero：p.eligible_seats &&& seatBit i = 0
    have h_bit_zero : p.eligible_seats &&& SidePot.seatBit i = 0 := h_pots2_zero p hp
    -- isEligible p.eligible_seats i = (p.eligible_seats &&& seatBit i) ≠ 0 = 0 ≠ 0 = false
    show SidePot.isEligible p.eligible_seats i = false
    rw [SidePot.isEligible, h_bit_zero]
    decide

/-- **决定性**：同输入同输出（Lean 全函数天然决定性）。 -/
theorem side_pot_deterministic (seats : List SeatBet) :
    calculate_side_pots seats = calculate_side_pots seats := rfl

end TexasPoker
