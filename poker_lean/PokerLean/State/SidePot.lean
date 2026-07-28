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
    ((modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots).map
      SidePot.amount).sum =
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
    ((push_or_merge pots amount eligible).map SidePot.amount).sum =
      (pots.map SidePot.amount).sum + amount := by
  by_cases h_amt : amount = 0
  · simp [push_or_merge, h_amt]
  · by_cases h_elig : eligible = 0
    · by_cases h_empty : pots = []
      · simp [push_or_merge, h_amt, h_elig, h_empty, SidePot.new]
      · simp [push_or_merge, h_amt, h_elig, h_empty]
        exact modify_last_amount_sum pots amount h_empty
    · simp [push_or_merge, h_amt, h_elig, SidePot.new]

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
    · -- x ≤ y: insert_sorted x (y :: ys) = x :: y :: ys
      simp [List.mem_cons]
    · -- ¬(x ≤ y): insert_sorted x (y :: ys) = y :: insert_sorted x ys
      -- 目标：z ∈ y :: insert_sorted x ys ↔ z = x ∨ z ∈ y :: ys
      -- 即：(z = y ∨ (z = x ∨ z ∈ ys)) ↔ (z = x ∨ (z = y ∨ z ∈ ys))
      simp only [List.mem_cons, ih]
      tauto

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
      · -- h : Sorted (·≤·) (y :: ys) → rel_of_sorted_cons 给出 y ≤ z；结合 hxy : x ≤ y 得 x ≤ z
        exact Nat.le_trans hxy (List.rel_of_sorted_cons h z hzmem)
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
    -- 关键恒等式：contrib + (s.bet - min s.bet level) = s.bet - min s.bet prev
    have h_key : contrib s.bet prev level + (s.bet - min s.bet level) = s.bet - min s.bet prev := by
      rw [contrib_eq_min_diff]
      have h1 : min s.bet prev ≤ min s.bet level := min_le_min_right s.bet prev level h_prev_le_level
      omega
    -- ih: (ss.map contrib).sum + (ss.map (s.bet - min level)).sum = (ss.map (s.bet - min prev)).sum
    -- 目标含结合律重排，omega 处理线性算术即可
    omega

/-- 辅助：`calculate_side_pots_fold_from` 在 `l ≤ prev` 时跳过 `l`。 -/
theorem calculate_side_pots_fold_from_cons_le (seats : List SeatBet) (l : Nat) (ls : List Nat)
    (pots : List SidePot) (prev total : Nat) (h : l ≤ prev) :
    calculate_side_pots_fold_from seats (l :: ls) pots prev total =
    calculate_side_pots_fold_from seats ls pots prev total := by
  simp only [calculate_side_pots_fold_from, List.foldl_cons, if_pos h]

/-- 辅助：`calculate_side_pots_fold_from` 在 `l > prev` 时处理 `(prev, l)` 层。 -/
theorem calculate_side_pots_fold_from_cons_gt (seats : List SeatBet) (l : Nat) (ls : List Nat)
    (pots : List SidePot) (prev total : Nat) (h : ¬l ≤ prev) :
    calculate_side_pots_fold_from seats (l :: ls) pots prev total =
    calculate_side_pots_fold_from seats ls
      (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) l total := by
  simp only [calculate_side_pots_fold_from, List.foldl_cons, if_neg h]

/-- **折叠不变量**：`pots_sum + remaining(prev) = initial_pots_sum + remaining(initial_prev)`。

这是守恒证明的核心：折叠保持 `pots_sum + remaining` 恒定。 -/
theorem fold_invariant (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total : Nat) :
    ((calculate_side_pots_fold_from seats levels pots prev total).1.map SidePot.amount).sum +
    remaining_contrib seats (calculate_side_pots_fold_from seats levels pots prev total).2 =
    (pots.map SidePot.amount).sum + remaining_contrib seats prev := by
  induction levels generalizing pots prev with
  | nil =>
    -- 空列表：foldl 返回 (pots, prev)
    simp [calculate_side_pots_fold_from]
  | cons l ls ih =>
    by_cases h_le : l ≤ prev
    · -- l ≤ prev：跳过，递归从 (pots, prev) 继续
      rw [calculate_side_pots_fold_from_cons_le seats l ls pots prev total h_le]
      exact ih pots prev
    · -- l > prev：处理 (prev, l)，递归从 (push_or_merge ..., l) 继续
      have h_prev_le_l : prev ≤ l := Nat.le_of_not_lt (fun h => h_le (Nat.le_of_lt h))
      rw [calculate_side_pots_fold_from_cons_gt seats l ls pots prev total h_le]
      -- 用 set 绑定 pots' 避免重复展开
      set pots' := push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)
      -- ih pots' l : fold_sum(pots', l) + remaining(fold(pots', l).2) = (pots'.map amount).sum + remaining(l)
      have h_step := ih pots' l
      -- 重写 LHS：fold_sum(pots', l) + remaining(fold(pots', l).2) → (pots'.map amount).sum + remaining(l)
      rw [h_step]
      -- (pots'.map amount).sum = (pots.map amount).sum + slice_amount（push_or_merge 守恒）
      have h_push := push_or_merge_amount_sum pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)
      rw [h_push]
      -- slice_amount + remaining(l) = remaining(prev)（望远镜求和）
      -- 目标含 (pots.map amount).sum + 前缀，omega 处理线性算术
      have h_slice := slice_plus_remaining seats prev l h_prev_le_l
      omega

/-! ## 顶层 calculate_side_pots -/

/-- 计算边池分层。对应 `side_pot.rs:110-158`。

注：用 `let r := ...; let pots := r.1; let prev := r.2` 而非 `let (pots, prev) := ...`，
因后者是 `match`（不按定义性归约），前者是 `let`（按定义性归约），便于 `show` 展开。 -/
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

/-! ## 关键定理 -/

/-- `side_pot` 金额非负。 -/
theorem side_pot_amount_nonneg (p : SidePot) : 0 ≤ p.amount := Nat.zero_le _

/-- 辅助：`remaining_contrib seats 0 = Σ s.bet`（因 `min b 0 = 0`）。 -/
theorem remaining_contrib_zero (seats : List SeatBet) :
    remaining_contrib seats 0 = (seats.map SeatBet.bet).sum := by
  induction seats with
  | nil => rfl
  | cons s ss ih =>
    simp only [remaining_contrib, List.map_cons, List.sum_cons]
    rw [Nat.min_eq_right (Nat.zero_le s.bet), Nat.sub_zero]
    simp only [remaining_contrib] at ih
    omega

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
    ((calculate_side_pots seats).map SidePot.amount).sum =
      (seats.map SeatBet.bet).sum := by
  -- 用 set 创建缩写（calculate_side_pots 的 let 定义按定义性归约）
  set total := (seats.map SeatBet.bet).sum with h_total_def
  set levels := insertion_sort (all_in_bets seats) with h_levels_def
  set r := calculate_side_pots_fold seats levels total with h_r_def
  set pots := r.1 with h_pots_def
  set prev := r.2 with h_prev_def
  set pots2 := if prev < total then
                 push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total)
               else pots with h_pots2_def
  -- show 展开 calculate_side_pots（let 定义性归约）
  show ((if pots2 = [] then [SidePot.new total 0] else pots2).map SidePot.amount).sum = total
  -- fold_invariant: pots_sum + remaining(prev) = 0 + remaining(0) = Σ s.bet = total
  have h_fold_inv : (pots.map SidePot.amount).sum + remaining_contrib seats prev = total := by
    have h := fold_invariant seats levels [] 0 total
    -- calculate_side_pots_fold_from seats levels [] 0 total = r (by rfl, since r = calculate_side_pots_fold ...)
    have h_eq : calculate_side_pots_fold_from seats levels [] 0 total = r := rfl
    rw [h_eq] at h
    -- h: (r.1.map amount).sum + remaining_contrib seats r.2 = ([]map amount).sum + remaining_contrib seats 0
    simp only [List.map_nil, List.sum_nil, zero_add] at h
    rw [remaining_contrib_zero, ← h_total_def] at h
    -- h: (r.1.map amount).sum + remaining_contrib seats r.2 = total
    -- pots = r.1, prev = r.2 by local definitions (defeq)
    exact h
  -- total ≥ 每个 s.bet
  have h_total_ge : ∀ s ∈ seats, s.bet ≤ total := by
    intro s hs
    have h_mem : s.bet ∈ (seats.map SeatBet.bet) := List.mem_map_of_mem _ hs
    have h_le : s.bet ≤ (seats.map SeatBet.bet).sum := List.le_sum_of_mem h_mem
    rwa [← h_total_def] at h_le
  -- 分情况讨论 pots2 = []
  by_cases h_pots2_empty : pots2 = []
  · -- pots2 = []：结果为 [SidePot.new total 0]
    rw [if_pos h_pots2_empty]
    simp [SidePot.new]
  · -- pots2 ≠ []：结果为 pots2
    rw [if_neg h_pots2_empty]
    -- 需证 (pots2.map amount).sum = total
    by_cases h_prev_lt : prev < total
    · -- prev < total：pots2 = push_or_merge pots ...
      have h_pots2_eq : pots2 = push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total) := by
        rw [h_pots2_def, if_pos h_prev_lt]
      rw [h_pots2_eq, push_or_merge_amount_sum]
      have h_prev_le_total : prev ≤ total := Nat.le_of_lt h_prev_lt
      have h_slice_rem : slice_amount seats prev total + remaining_contrib seats total = remaining_contrib seats prev :=
        slice_plus_remaining seats prev total h_prev_le_total
      have h_rem_total : remaining_contrib seats total = 0 :=
        remaining_contrib_total seats total h_total_ge
      omega
    · -- prev ≥ total：pots2 = pots
      have h_prev_ge : prev ≥ total := Nat.le_of_not_lt h_prev_lt
      have h_pots2_eq : pots2 = pots := by
        rw [h_pots2_def, if_neg h_prev_lt]
      rw [h_pots2_eq]
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
      ih (j + 1) 0 m (by omega)
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
        subst hmj
        -- m - m = 0（Nat.sub_self）
        have h_sub : m - m = 0 := Nat.sub_self m
        have h_idx0 : 0 < (s :: ss).length := h_sub ▸ h_idx
        have h_fin_eq : (⟨m - m, h_idx⟩ : Fin (s :: ss).length) = ⟨0, h_idx0⟩ := by
          apply Fin.ext; exact h_sub
        rw [h_fin_eq] at h_folded
        -- (s::ss).get ⟨0, _⟩ = s（simp 归约）
        simp at h_folded
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
        -- 注意：不修改 h_idx（避免破坏 h_folded 的类型依赖）
        have h_idx' : m - (j + 1) < ss.length := by
          have h_len : (s :: ss).length = ss.length + 1 := rfl
          have h_idx_norm : m - j < ss.length + 1 := h_len ▸ h_idx
          omega
        -- h_folded' : (ss.get ⟨m-(j+1), h_idx'⟩).folded = true
        -- 核心思路：⟨m-j, h_idx⟩ = Fin.succ ⟨m-(j+1), h_idx'⟩（Fin.ext + val 相等）
        -- 然后 (s::ss).get (Fin.succ i) = ss.get i（List.get_cons_succ'，定义为 rfl）
        have h_folded' : (ss.get ⟨m - (j + 1), h_idx'⟩).folded = true := by
          have h_fin : (⟨m - j, h_idx⟩ : Fin (s :: ss).length) =
                       Fin.succ ⟨m - (j + 1), h_idx'⟩ := by
            apply Fin.ext
            show m - j = (m - (j + 1)) + 1
            omega
          rw [h_fin, List.get_cons_succ'] at h_folded
          exact h_folded
        -- ih 参数顺序：generalizing j m level，但 ih 绑定顺序为 (j, level, m)
        -- （按目标中变量出现顺序），故 ih (j+1) 0 m 表示 j:=j+1, level:=0, m:=m
        exact ih (j + 1) 0 m h_j1_le_m h_idx' h_folded'
    simp [h_first, h_second]

/-- `slice_eligible` 对 folded 座位不置位（j=0 特例，对外接口）。 -/
theorem slice_eligible_folded_not_set (seats : List SeatBet) (i : Nat) (prev level : Nat)
    (h_i : i < seats.length) (h_folded : (seats.get ⟨i, h_i⟩).folded = true) :
    slice_eligible seats 0 prev level &&& SidePot.seatBit i = 0 := by
  -- i - 0 ≡ i（定义性归约），故 h_i 和 h_folded 直接匹配
  exact slice_eligible_and_seatBit_folded seats 0 prev level i (Nat.zero_le i) h_i h_folded

/-! ### 折叠保持「所有 pot 的 bit i = 0」 -/

/-- 谓词：所有 pot 的 eligible_seats 第 i 位均为 0。 -/
def all_pots_zero_bit (pots : List SidePot) (i : Nat) : Prop :=
  ∀ p ∈ pots, p.eligible_seats &&& SidePot.seatBit i = 0

/-- `modify_last` 保持 `eligible_seats` 字段（仅改 amount）。 -/
theorem modify_last_preserves_eligible (pots : List SidePot) (amount i : Nat)
    (h_all : all_pots_zero_bit pots i) :
    all_pots_zero_bit (modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots) i := by
  intro p hp
  induction pots with
  | nil =>
    -- modify_last f [] = []
    simp [modify_last] at hp
  | cons x xs ih =>
    cases xs with
    | nil =>
      -- modify_last f [x] = [f x]
      have h_mod : modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) [x] =
          [SidePot.new (x.amount + amount) x.eligible_seats] := rfl
      rw [h_mod, List.mem_singleton] at hp
      have heq : p.eligible_seats = x.eligible_seats := by
        rw [hp]; rfl
      rw [heq]
      exact h_all x (List.mem_cons_self x [])
    | cons y ys =>
      -- modify_last f (x :: y :: ys) = x :: modify_last f (y :: ys)
      have h_mod : modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) (x :: y :: ys) =
          x :: modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) (y :: ys) := rfl
      rw [h_mod, List.mem_cons] at hp
      cases hp with
      | inl h =>
        have : x.eligible_seats &&& SidePot.seatBit i = 0 := h_all x (List.mem_cons_self x (y :: ys))
        rw [← h] at this
        exact this
      | inr h =>
        have h_xs_zero : all_pots_zero_bit (y :: ys) i := fun p' hp' =>
          h_all p' (List.mem_cons_of_mem x hp')
        exact ih h_xs_zero h

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
      -- p = SidePot.new amount 0，eligible_seats = 0 → 0 &&& seatBit i = 0
      simp [hp]
    · -- push_or_merge = modify_last ... pots
      simp [push_or_merge, h_amt, h_elig_zero, h_empty] at hp
      have h_in : p ∈ modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots := hp
      have : all_pots_zero_bit (modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots) i :=
        modify_last_preserves_eligible pots amount i h_pots
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

/-- **calculate_side_pots 所有 pot 的 bit i = 0**（当 seat i folded 时）。

辅助引理：将 `calculate_side_pots` 的结构（fold → 外层 push_or_merge → 空兜底）
统一归约为 `all_pots_zero_bit`，避免在 `folded_not_eligible` 中直接处理 `hp` 的
`if-then-else` 展开（`set`/`simp` 交互会导致缩写丢失）。

证明：
1. `pots`（fold 结果）全零位：由 `fold_preserves_zero_bit`，初始 `[]` 全零位，每步保持。
2. `pots2`（外层 `push_or_merge` 或 `pots`）全零位：若 `prev < total`，eligible 的 bit i = 0
   （`slice_eligible_folded_not_set`），`push_or_merge_preserves_zero_bit`；否则 = `pots`。
3. 最终结果 `if pots2 = [] then [SidePot.new total 0] else pots2`：空兜底 mask = 0，bit i = 0；
   非空则 = `pots2`，已证全零位。 -/
theorem calculate_side_pots_all_zero_bit (seats : List SeatBet) (i : Nat)
    (h_i : i < seats.length) (h_folded : (seats.get ⟨i, h_i⟩).folded = true) :
    all_pots_zero_bit (calculate_side_pots seats) i := by
  -- 绑定中间量（set 创建缩写，后续用 h_def 展开）
  set total := (seats.map SeatBet.bet).sum with h_total_def
  set levels := insertion_sort (all_in_bets seats) with h_levels_def
  set fold_result := calculate_side_pots_fold seats levels total with h_fold_def
  set pots := fold_result.1 with h_pots_def
  set prev := fold_result.2 with h_prev_def
  set pots2 := if prev < total then
                 push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total)
               else pots with h_pots2_def
  -- 1. pots 全零位（由 fold_preserves_zero_bit）
  have h_pots_zero : all_pots_zero_bit pots i := by
    have h := fold_preserves_zero_bit seats levels [] 0 total i h_i h_folded
    have h_eq : calculate_side_pots_fold_from seats levels [] 0 total = fold_result := rfl
    rw [h_eq] at h
    exact h (by simp [all_pots_zero_bit])
  -- 2. pots2 全零位
  have h_pots2_zero : all_pots_zero_bit pots2 i := by
    rw [h_pots2_def]  -- 展开 pots2 为 if-then-else
    by_cases h_prev_lt : prev < total
    · rw [if_pos h_prev_lt]
      have h_elig_zero : slice_eligible seats 0 prev total &&& SidePot.seatBit i = 0 :=
        slice_eligible_folded_not_set seats i prev total h_i h_folded
      exact push_or_merge_preserves_zero_bit pots (slice_amount seats prev total)
        (slice_eligible seats 0 prev total) i h_pots_zero h_elig_zero
    · rw [if_neg h_prev_lt]
      exact h_pots_zero
  -- 3. 最终结果：if pots2 = [] then [SidePot.new total 0] else pots2
  -- 用 show 将 calculate_side_pots seats 归约为 if-then-else（定义性 let 归约 + set 缩写）
  show all_pots_zero_bit (if pots2 = [] then [SidePot.new total 0] else pots2) i
  by_cases h_empty : pots2 = []
  · rw [if_pos h_empty]
    simp [all_pots_zero_bit, SidePot.new]
  · rw [if_neg h_empty]
    exact h_pots2_zero

/-- **folded 永不合格**：已 fold 的座位在所有 pot 的 eligible_seats 中位 0。

对应 `side_pot.rs:178` `if !folded[j]` 条件。

证明：由 `calculate_side_pots_all_zero_bit`，所有 pot 的 `eligible_seats &&& seatBit i = 0`。
`isEligible mask i = (mask &&& seatBit i) ≠ 0`，bit i = 0 即 `isEligible = false`。 -/
theorem folded_not_eligible (seats : List SeatBet) (i : Nat)
    (h_i : i < seats.length) (h_folded : (seats.get ⟨i, h_i⟩).folded = true) :
    ∀ p ∈ calculate_side_pots seats, SidePot.isEligible p.eligible_seats i = false := by
  intro p hp
  have h_all : all_pots_zero_bit (calculate_side_pots seats) i :=
    calculate_side_pots_all_zero_bit seats i h_i h_folded
  have h_bit : p.eligible_seats &&& SidePot.seatBit i = 0 := h_all p hp
  show SidePot.isEligible p.eligible_seats i = false
  rw [SidePot.isEligible, h_bit]
  decide

/-! ## 资格嵌套性（nested eligibility）

证明 `∀ i < j, eligible(pots[j]) ⊆ eligible(pots[i])`（Plan agent 缺失项 #3）。

核心思路：
1. `slice_eligible` 在 `prev` 上单调递减（`prev1 ≤ prev2 → elig(prev2) ⊆ elig(prev1)`）。
2. fold 中 `prev` 非降（levels 排序 + 跳过 `≤ prev` 的层），故每层 eligible 嵌套。
3. `push_or_merge` 保持嵌套（新层 eligible ⊆ 所有现有层，因现有层在更小 `prev` 创建）。 -/

/-- 位掩码子集：`a` 的所有位都在 `b` 中（`a &&& b = a`）。 -/
def mask_subset (a b : Nat) : Prop := a &&& b = a

/-- `pots_nested`：每个 pot 的 eligible ⊇ 后续所有 pot 的 eligible。 -/
def pots_nested : List SidePot → Prop
  | [] => True
  | p :: ps => (∀ q ∈ ps, mask_subset q.eligible_seats p.eligible_seats) ∧ pots_nested ps

/-- 不相交 AND 分配：交叉项为 0 时 `(a|||b) &&& (c|||d) = (a&&&c) ||| (b&&&d)`。 -/
theorem and_or_or_disjoint (a b c d : Nat) (h_ad : a &&& d = 0) (h_bc : b &&& c = 0) :
    (a ||| b) &&& (c ||| d) = (a &&& c) ||| (b &&& d) := by
  rw [and_or_distrib_right, Nat.and_or_distrib_left, Nat.and_or_distrib_left, h_ad, h_bc]
  simp

/-- **`slice_eligible` 在 prev 上单调递减**：`prev1 ≤ prev2 → elig(prev2) ⊆ elig(prev1)`。

证明：对 seats 归纳（泛化 j）。每座位 `bet > prev2 → bet > prev1`（因 `prev1 ≤ prev2`），
故 prev2 的位掩码是 prev1 的子集。利用 `seatBit j` 与 `slice_eligible ss (j+1)` 位不相交
（`slice_eligible_and_seatBit_below`）分解 AND。 -/
theorem slice_eligible_subset (seats : List SeatBet) (j prev1 prev2 : Nat) (h : prev1 ≤ prev2) :
    slice_eligible seats j prev2 0 &&& slice_eligible seats j prev1 0 = slice_eligible seats j prev2 0 := by
  induction seats generalizing j with
  | nil => simp [slice_eligible]
  | cons s ss ih =>
    simp only [slice_eligible]
    have h_mono : s.bet > prev2 ∧ s.folded = false → s.bet > prev1 ∧ s.folded = false := by
      intro h'; exact ⟨by omega, h'.2⟩
    have h_disj2 : (if s.bet > prev2 ∧ s.folded = false then SidePot.seatBit j else 0)
        &&& slice_eligible ss (j + 1) prev1 0 = 0 := by
      split_ifs with h_c
      · rw [Nat.land_comm]
        exact slice_eligible_and_seatBit_below ss (j + 1) prev1 0 j (by omega)
      · simp
    have h_disj1 : slice_eligible ss (j + 1) prev2 0
        &&& (if s.bet > prev1 ∧ s.folded = false then SidePot.seatBit j else 0) = 0 := by
      split_ifs with h_c
      · exact slice_eligible_and_seatBit_below ss (j + 1) prev2 0 j (by omega)
      · simp
    rw [and_or_or_disjoint _ _ _ _ h_disj2 h_disj1, ih (j + 1)]
    by_cases h_cond2 : s.bet > prev2 ∧ s.folded = false
    · rw [if_pos h_cond2, if_pos (h_mono h_cond2)]
      have h_self : SidePot.seatBit j &&& SidePot.seatBit j = SidePot.seatBit j := by simp
      rw [h_self]
    · rw [if_neg h_cond2]; simp

/-- `slice_eligible` 的第 4 参数（level）被忽略：`slice_eligible seats j prev level = slice_eligible seats j prev 0`。

由定义：cons 分支中第 4 参数为 `_`，递归调用固定传 `0`。 -/
theorem slice_eligible_irrel_level (seats : List SeatBet) (j prev level : Nat) :
    slice_eligible seats j prev level = slice_eligible seats j prev 0 := by
  induction seats generalizing j with
  | nil => rfl
  | cons _ _ _ => simp only [slice_eligible]

/-- `mask_subset` 传递性：`a ⊆ b ∧ b ⊆ c → a ⊆ c`。 -/
theorem mask_subset_trans (a b c : Nat) (h_ab : mask_subset a b) (h_bc : mask_subset b c) :
    mask_subset a c := by
  unfold mask_subset at *
  rw [← h_ab, Nat.land_assoc, h_bc]

/-- `modify_last` 保持每个元素的 `eligible_seats`：结果中每个 p 的 eligible_seats 来自原列表某元素。 -/
theorem modify_last_eligible_eq (pots : List SidePot) (amount : Nat) (p : SidePot)
    (hp : p ∈ modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots) :
    ∃ q ∈ pots, p.eligible_seats = q.eligible_seats := by
  induction pots with
  | nil => simp [modify_last] at hp
  | cons x xs ih =>
    cases xs with
    | nil =>
      simp only [modify_last, List.mem_singleton] at hp
      subst hp
      exact ⟨x, List.mem_cons_self x [], rfl⟩
    | cons y ys =>
      simp only [modify_last, List.mem_cons] at hp
      rcases hp with rfl | hp'
      · exact ⟨p, List.mem_cons_self p (y :: ys), rfl⟩
      · obtain ⟨q, hq, hq'⟩ := ih hp'
        exact ⟨q, List.mem_cons_of_mem x hq, hq'⟩

/-- `modify_last` 保持 `pots_nested`（仅改 amount，不改 eligible_seats）。 -/
theorem modify_last_preserves_nested (pots : List SidePot) (amount : Nat) (h : pots_nested pots) :
    pots_nested (modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots) := by
  induction pots with
  | nil => simp [modify_last, pots_nested]
  | cons x xs ih =>
    cases xs with
    | nil => simp [modify_last, pots_nested]
    | cons y ys =>
      obtain ⟨h_first, h_rest⟩ := h
      simp only [modify_last, pots_nested]
      refine ⟨?_, ?_⟩
      · intro q hq
        obtain ⟨q', hq', hq_eq⟩ := modify_last_eligible_eq (y :: ys) amount q hq
        rw [hq_eq]
        exact h_first q' hq'
      · exact ih h_rest

/-- `pots ++ [x]` 的嵌套性：若 pots 嵌套且 x.eligible ⊆ 所有 p ∈ pots 的 eligible，则结果嵌套。 -/
theorem pots_nested_append_single (pots : List SidePot) (x : SidePot)
    (h_nested : pots_nested pots)
    (h_subset : ∀ p ∈ pots, mask_subset x.eligible_seats p.eligible_seats) :
    pots_nested (pots ++ [x]) := by
  induction pots with
  | nil => simp [pots_nested]
  | cons p ps ih =>
    obtain ⟨h_first, h_rest⟩ := h_nested
    simp only [List.cons_append, pots_nested]
    refine ⟨?_, ?_⟩
    · intro q hq
      rcases List.mem_append.mp hq with hq_ps | hq_new
      · exact h_first q hq_ps
      · rcases List.mem_singleton.mp hq_new with rfl
        exact h_subset p (List.mem_cons_self p ps)
    · exact ih h_rest (fun p' hp' => h_subset p' (List.mem_cons_of_mem p hp'))

/-- **`push_or_merge` 保持嵌套**：若 pots 嵌套且新 eligible ⊆ 所有现有 pot 的 eligible，
则结果嵌套。 -/
theorem push_or_merge_preserves_nested (pots : List SidePot) (amount eligible : Nat)
    (h_nested : pots_nested pots)
    (h_subset : ∀ p ∈ pots, mask_subset eligible p.eligible_seats) :
    pots_nested (push_or_merge pots amount eligible) := by
  by_cases h_amt : amount = 0
  · -- amount = 0: 结果 = pots
    have h_eq : push_or_merge pots amount eligible = pots := by
      unfold push_or_merge; rw [if_pos h_amt]
    rw [h_eq]; exact h_nested
  by_cases h_elig : eligible = 0
  · by_cases h_empty : pots = []
    · -- pots = []: 条件 False → else → [] ++ [SidePot.new amount 0]
      have h_cond : ¬(eligible = 0 ∧ pots ≠ []) := fun h => h.2 h_empty
      have h_eq : push_or_merge pots amount eligible = pots ++ [SidePot.new amount eligible] := by
        unfold push_or_merge; rw [if_neg h_amt, if_neg h_cond]
      rw [h_eq, h_empty, h_elig]
      simp [pots_nested, SidePot.new]
    · -- eligible = 0 ∧ pots ≠ []: 结果 = modify_last
      have h_cond : eligible = 0 ∧ pots ≠ [] := ⟨h_elig, h_empty⟩
      have h_eq : push_or_merge pots amount eligible =
          modify_last (fun p => SidePot.new (p.amount + amount) p.eligible_seats) pots := by
        unfold push_or_merge; rw [if_neg h_amt, if_pos h_cond]
      rw [h_eq]
      exact modify_last_preserves_nested pots amount h_nested
  · -- eligible ≠ 0: 条件 False → else → pots ++ [SidePot.new amount eligible]
    have h_cond : ¬(eligible = 0 ∧ pots ≠ []) := fun h => h_elig h.1
    have h_eq : push_or_merge pots amount eligible = pots ++ [SidePot.new amount eligible] := by
      unfold push_or_merge; rw [if_neg h_amt, if_neg h_cond]
    rw [h_eq]
    exact pots_nested_append_single pots (SidePot.new amount eligible) h_nested h_subset

/-- `push_or_merge` 保持 "above" 性质：若所有 p ∈ pots 满足 base ⊆ p.eligible，
且 base ⊆ eligible，则结果中所有元素满足 base ⊆ p.eligible。 -/
theorem push_or_merge_preserves_above (pots : List SidePot) (amount eligible base : Nat)
    (h_above : ∀ p ∈ pots, mask_subset base p.eligible_seats)
    (h_base_elig : mask_subset base eligible) :
    ∀ p ∈ push_or_merge pots amount eligible, mask_subset base p.eligible_seats := by
  intro p hp
  by_cases h_amt : amount = 0
  · have h_eq : push_or_merge pots amount eligible = pots := by
      unfold push_or_merge; rw [if_pos h_amt]
    rw [h_eq] at hp
    exact h_above p hp
  by_cases h_elig : eligible = 0
  · by_cases h_empty : pots = []
    · have h_cond : ¬(eligible = 0 ∧ pots ≠ []) := fun h => h.2 h_empty
      have h_eq : push_or_merge pots amount eligible = pots ++ [SidePot.new amount eligible] := by
        unfold push_or_merge; rw [if_neg h_amt, if_neg h_cond]
      rw [h_eq] at hp
      rcases List.mem_append.mp hp with h_pots | h_new
      · exact h_above p h_pots
      · rcases List.mem_singleton.mp h_new with rfl
        exact h_base_elig
    · have h_cond : eligible = 0 ∧ pots ≠ [] := ⟨h_elig, h_empty⟩
      have h_eq : push_or_merge pots amount eligible =
          modify_last (fun q => SidePot.new (q.amount + amount) q.eligible_seats) pots := by
        unfold push_or_merge; rw [if_neg h_amt, if_pos h_cond]
      rw [h_eq] at hp
      obtain ⟨q, hq, h_eq⟩ := modify_last_eligible_eq pots amount p hp
      rw [h_eq]
      exact h_above q hq
  · have h_cond : ¬(eligible = 0 ∧ pots ≠ []) := fun h => h_elig h.1
    have h_eq : push_or_merge pots amount eligible = pots ++ [SidePot.new amount eligible] := by
      unfold push_or_merge; rw [if_neg h_amt, if_neg h_cond]
    rw [h_eq] at hp
    rcases List.mem_append.mp hp with h_pots | h_new
    · exact h_above p h_pots
    · rcases List.mem_singleton.mp h_new with rfl
      exact h_base_elig

/-- **fold 保持嵌套 + eligible ⊇ slice_eligible(prev)**：加强不变量。

不变量：`pots_nested pots ∧ ∀ p ∈ pots, slice_eligible(prev) ⊆ p.eligible`。
- 初始 (`pots = []`, `prev = 0`): 平凡。
- 处理层 `(prev, l)` (`l > prev`):
  - 新 eligible = `slice_eligible(prev)`。
  - 由不变量，所有现有 pot 的 eligible ⊇ `slice_eligible(prev)` = 新 eligible。
  - `push_or_merge` 保持嵌套。
  - 新 prev = l。`slice_eligible(l) ⊆ slice_eligible(prev)`（单调性），且 `slice_eligible(prev) ⊆ 所有 pot`，
    故 `slice_eligible(l) ⊆ 所有 pot`。
- 跳过 (`l ≤ prev`): 不变量不变。 -/
theorem fold_preserves_nested (seats : List SeatBet) (levels : List Nat)
    (pots : List SidePot) (prev total : Nat)
    (h_nested : pots_nested pots)
    (h_above : ∀ p ∈ pots, mask_subset (slice_eligible seats 0 prev 0) p.eligible_seats) :
    pots_nested (calculate_side_pots_fold_from seats levels pots prev total).1 ∧
    ∀ p ∈ (calculate_side_pots_fold_from seats levels pots prev total).1,
      mask_subset (slice_eligible seats 0 (calculate_side_pots_fold_from seats levels pots prev total).2 0)
        p.eligible_seats := by
  induction levels generalizing pots prev with
  | nil =>
    simp [calculate_side_pots_fold_from]
    exact ⟨h_nested, h_above⟩
  | cons l ls ih =>
    by_cases h_le : l ≤ prev
    · rw [calculate_side_pots_fold_from_cons_le seats l ls pots prev total h_le]
      exact ih pots prev h_nested h_above
    · have h_prev_le_l : prev ≤ l := Nat.le_of_not_lt (fun h => h_le (Nat.le_of_lt h))
      rw [calculate_side_pots_fold_from_cons_gt seats l ls pots prev total h_le]
      -- 1. push_or_merge 保持嵌套
      have h_elig_eq : slice_eligible seats 0 prev l = slice_eligible seats 0 prev 0 :=
        slice_eligible_irrel_level seats 0 prev l
      have h_subset : ∀ p ∈ pots, mask_subset (slice_eligible seats 0 prev l) p.eligible_seats := by
        rw [h_elig_eq]; exact h_above
      have h_nested' : pots_nested
          (push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)) :=
        push_or_merge_preserves_nested pots (slice_amount seats prev l) (slice_eligible seats 0 prev l)
          h_nested h_subset
      -- 2. 新 prev = l: slice_eligible(l) ⊆ 所有 pot 的 eligible
      have h_mono : mask_subset (slice_eligible seats 0 l 0) (slice_eligible seats 0 prev 0) :=
        slice_eligible_subset seats 0 prev l h_prev_le_l
      have h_above' : ∀ p ∈ push_or_merge pots (slice_amount seats prev l) (slice_eligible seats 0 prev l),
        mask_subset (slice_eligible seats 0 l 0) p.eligible_seats := by
        intro p hp
        rw [h_elig_eq] at hp
        have h_above_base : ∀ q ∈ pots, mask_subset (slice_eligible seats 0 l 0) q.eligible_seats := by
          intro q hq
          exact mask_subset_trans _ _ _ h_mono (h_above q hq)
        exact push_or_merge_preserves_above pots (slice_amount seats prev l)
          (slice_eligible seats 0 prev 0) (slice_eligible seats 0 l 0) h_above_base h_mono p hp
      exact ih _ _ h_nested' h_above'

/-- **资格嵌套定理**：`∀ i < j, eligible(pots[j]) ⊆ eligible(pots[i])`。

对应 Plan agent 缺失项 #3。

证明：由 `fold_preserves_nested`，fold 结果嵌套。外层 `push_or_merge`（若 `prev < total`）
的新 eligible = `slice_eligible(prev)`，是所有现有 pot 的子集（不变量），故嵌套保持。
空兜底 `[SidePot.new total 0]` 平凡嵌套。 -/
theorem side_pot_eligibility_nested (seats : List SeatBet) :
    pots_nested (calculate_side_pots seats) := by
  set total := (seats.map SeatBet.bet).sum with h_total_def
  set levels := insertion_sort (all_in_bets seats) with h_levels_def
  set r := calculate_side_pots_fold seats levels total with h_r_def
  set pots := r.1 with h_pots_def
  set prev := r.2 with h_prev_def
  set pots2 := if prev < total then
                 push_or_merge pots (slice_amount seats prev total) (slice_eligible seats 0 prev total)
               else pots with h_pots2_def
  -- 1. fold 结果 pots 嵌套 + eligible ⊇ slice_eligible(prev)
  have h_fold := fold_preserves_nested seats levels [] 0 total (by simp [pots_nested])
    (by simp [pots_nested])
  have h_eq : calculate_side_pots_fold_from seats levels [] 0 total = r := rfl
  rw [h_eq] at h_fold
  obtain ⟨h_pots_nested, h_pots_above⟩ := h_fold
  -- 2. pots2 嵌套
  have h_pots2_nested : pots_nested pots2 := by
    rw [h_pots2_def]
    by_cases h_prev_lt : prev < total
    · rw [if_pos h_prev_lt]
      have h_elig_eq : slice_eligible seats 0 prev total = slice_eligible seats 0 prev 0 :=
        slice_eligible_irrel_level seats 0 prev total
      have h_subset : ∀ p ∈ pots, mask_subset (slice_eligible seats 0 prev total) p.eligible_seats := by
        rw [h_elig_eq]; exact h_pots_above
      exact push_or_merge_preserves_nested pots (slice_amount seats prev total)
        (slice_eligible seats 0 prev total) h_pots_nested h_subset
    · rw [if_neg h_prev_lt]
      exact h_pots_nested
  -- 3. 最终结果：if pots2 = [] then [SidePot.new total 0] else pots2
  show pots_nested (if pots2 = [] then [SidePot.new total 0] else pots2)
  by_cases h_empty : pots2 = []
  · rw [if_pos h_empty]
    simp [pots_nested, SidePot.new]
  · rw [if_neg h_empty]
    exact h_pots2_nested

/-- **决定性**：同输入同输出（Lean 全函数天然决定性）。 -/
theorem side_pot_deterministic (seats : List SeatBet) :
    calculate_side_pots seats = calculate_side_pots seats := rfl

end TexasPoker
