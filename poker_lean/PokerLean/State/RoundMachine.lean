import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types

/-!
# Round 状态机（镜像 `state_machine.rs:586-613` `advance_round` + `reset_for_next_hand`）

Round 状态合法转移与单调性证明。

合法转移图（对应 `state_machine.rs:586-613` `advance_round` + `start_hand` + `reset_for_next_hand`）：

```
WAITING → PREFLOP → FLOP → TURN → RIVER → SHOWDOWN
   ↑__________________________________|  (reset)
   ↑__________________________________|  (end_without_showdown)
   ↑________________________|            (超时 reset)
```

任何状态都可经 `reset_for_next_hand` 回到 `WAITING`。

**实现说明**：`RoundStep` 用 `abbrev`（透明定义）而非 `inductive`，
因为 Lean 4 的 `cases` 对索引归纳类型不自动替换目标中的索引变量，
导致 `rfl` 无法证明 `s = ROUND_WAITING`。用 `abbrev` 后 `rcases` 可直接
展开析取范式并经命名模式 `⟨h1, h2⟩` 拆解等式，再用 `subst` 替换。
-/

namespace TexasPoker

/-! ## RoundState 枚举（对应 `constants.rs:24-35` 的 ROUND_* 常量）-/

inductive RoundState where
  | ROUND_WAITING   : RoundState
  | ROUND_PREFLOP   : RoundState
  | ROUND_FLOP      : RoundState
  | ROUND_TURN      : RoundState
  | ROUND_RIVER     : RoundState
  | ROUND_SHOWDOWN  : RoundState
deriving Repr, DecidableEq

namespace RoundState

/-- 与 Rust `constants.rs` 逐字节对齐：
    WAITING=0, PREFLOP=2, FLOP=3, TURN=4, RIVER=5, SHOWDOWN=6（值 1 未使用）。 -/
def toNat : RoundState → Nat
  | ROUND_WAITING  => 0
  | ROUND_PREFLOP  => 2
  | ROUND_FLOP     => 3
  | ROUND_TURN     => 4
  | ROUND_RIVER    => 5
  | ROUND_SHOWDOWN => 6

/-- 从 Nat 构造 RoundState。 -/
def fromNat (n : Nat) : RoundState :=
  if n = 2 then ROUND_PREFLOP
  else if n = 3 then ROUND_FLOP
  else if n = 4 then ROUND_TURN
  else if n = 5 then ROUND_RIVER
  else if n = 6 then ROUND_SHOWDOWN
  else ROUND_WAITING

/-! ### toNat 值引理 -/

@[simp] theorem toNat_waiting  : (ROUND_WAITING  : RoundState).toNat = 0 := rfl
@[simp] theorem toNat_preflop  : (ROUND_PREFLOP  : RoundState).toNat = 2 := rfl
@[simp] theorem toNat_flop     : (ROUND_FLOP     : RoundState).toNat = 3 := rfl
@[simp] theorem toNat_turn     : (ROUND_TURN     : RoundState).toNat = 4 := rfl
@[simp] theorem toNat_river    : (ROUND_RIVER    : RoundState).toNat = 5 := rfl
@[simp] theorem toNat_showdown : (ROUND_SHOWDOWN : RoundState).toNat = 6 := rfl

/-! ### toNat 单射性（不同构造子有不同 toNat）-/

theorem toNat_injective (s₁ s₂ : RoundState) (h : s₁.toNat = s₂.toNat) : s₁ = s₂ := by
  cases s₁ <;> cases s₂ <;> simp_all [toNat]

/-- toNat 严格区分 6 个构造子。 -/
theorem ne_of_toNat_ne (s₁ s₂ : RoundState) (h : s₁.toNat ≠ s₂.toNat) : s₁ ≠ s₂ := by
  intro heq; apply h; rw [heq]

/-! ### fromNat 引理 -/

theorem fromNat_zero  : fromNat 0 = ROUND_WAITING := rfl
theorem fromNat_two   : fromNat 2 = ROUND_PREFLOP := rfl
theorem fromNat_three : fromNat 3 = ROUND_FLOP := rfl
theorem fromNat_four  : fromNat 4 = ROUND_TURN := rfl
theorem fromNat_five  : fromNat 5 = ROUND_RIVER := rfl
theorem fromNat_six   : fromNat 6 = ROUND_SHOWDOWN := rfl

/-- fromNat ∘ toNat = id（往返一致）。 -/
theorem fromNat_toNat (s : RoundState) : fromNat s.toNat = s := by
  cases s <;> rfl

/-! ### is_betting_round -/

/-- 是否处于下注轮（PREFLOP/FLOP/TURN/RIVER）。 -/
def is_betting_round : RoundState → Bool
  | ROUND_PREFLOP => true
  | ROUND_FLOP    => true
  | ROUND_TURN    => true
  | ROUND_RIVER   => true
  | _             => false

@[simp] theorem waiting_not_betting : (ROUND_WAITING : RoundState).is_betting_round = false := rfl
@[simp] theorem preflop_is_betting  : (ROUND_PREFLOP : RoundState).is_betting_round = true := rfl
@[simp] theorem flop_is_betting     : (ROUND_FLOP : RoundState).is_betting_round = true := rfl
@[simp] theorem turn_is_betting     : (ROUND_TURN : RoundState).is_betting_round = true := rfl
@[simp] theorem river_is_betting    : (ROUND_RIVER : RoundState).is_betting_round = true := rfl
@[simp] theorem showdown_not_betting : (ROUND_SHOWDOWN : RoundState).is_betting_round = false := rfl

end RoundState

-- 打开 RoundState 命名空间，使构造子（ROUND_WAITING 等）可直接引用。
open RoundState

/-! ## 合法转移关系

`RoundStep` 定义为析取范式（`abbrev`），对应 Rust 代码路径：
- `start`：`start_hand`（`state_machine.rs:2128-2178`）最终进入 `ROUND_PREFLOP`
- `preflop_flop` / `flop_turn` / `turn_river` / `river_showdown`：`advance_round`（`state_machine.rs:588-611`）
- `reset`：`reset_for_next_hand`（`state_machine.rs:2837`）/ `end_without_showdown` / 超时路径
  将任意状态重置为 `ROUND_WAITING` -/

abbrev RoundStep (s s' : RoundState) : Prop :=
  (s = ROUND_WAITING ∧ s' = ROUND_PREFLOP) ∨
  (s = ROUND_PREFLOP ∧ s' = ROUND_FLOP) ∨
  (s = ROUND_FLOP ∧ s' = ROUND_TURN) ∨
  (s = ROUND_TURN ∧ s' = ROUND_RIVER) ∨
  (s = ROUND_RIVER ∧ s' = ROUND_SHOWDOWN) ∨
  (s' = ROUND_WAITING)

/-- 命名构造子：`start` 转移。 -/
def RoundStep.start : RoundStep ROUND_WAITING ROUND_PREFLOP :=
  Or.inl ⟨rfl, rfl⟩

/-- 命名构造子：`preflop_flop` 转移。 -/
def RoundStep.preflop_flop : RoundStep ROUND_PREFLOP ROUND_FLOP :=
  Or.inr (Or.inl ⟨rfl, rfl⟩)

/-- 命名构造子：`flop_turn` 转移。 -/
def RoundStep.flop_turn : RoundStep ROUND_FLOP ROUND_TURN :=
  Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))

/-- 命名构造子：`turn_river` 转移。 -/
def RoundStep.turn_river : RoundStep ROUND_TURN ROUND_RIVER :=
  Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩)))

/-- 命名构造子：`river_showdown` 转移。 -/
def RoundStep.river_showdown : RoundStep ROUND_RIVER ROUND_SHOWDOWN :=
  Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))))

/-- 命名构造子：`reset` 转移（任意状态回到 WAITING）。 -/
def RoundStep.reset (s : RoundState) : RoundStep s ROUND_WAITING :=
  Or.inr (Or.inr (Or.inr (Or.inr (Or.inr rfl))))

/-! ## 辅助：展开 RoundStep 并拆解 -/

/-- **辅助**：展开 `RoundStep` 为析取范式。 -/
theorem round_step_iff (s s' : RoundState) :
    RoundStep s s' ↔
    (s = ROUND_WAITING ∧ s' = ROUND_PREFLOP) ∨
    (s = ROUND_PREFLOP ∧ s' = ROUND_FLOP) ∨
    (s = ROUND_FLOP ∧ s' = ROUND_TURN) ∨
    (s = ROUND_TURN ∧ s' = ROUND_RIVER) ∨
    (s = ROUND_RIVER ∧ s' = ROUND_SHOWDOWN) ∨
    (s' = ROUND_WAITING) := Iff.rfl

/-- **辅助**：`DecidableEq` 推出不同构造子不等。 -/
theorem round_ne (s₁ s₂ : RoundState) (h : s₁.toNat ≠ s₂.toNat) : s₁ ≠ s₂ :=
  ne_of_toNat_ne s₁ s₂ h

/-! ## 核心定理 -/

/-- **定理 1（round 单调性）**：任何合法转移要么 `toNat` 不减，要么目标为 `WAITING`。

对应 Rust：`advance_round`（`state_machine.rs:586-613`）只前推；
`reset_for_next_hand`（`state_machine.rs:2837`）回到 `WAITING`。 -/
theorem round_monotonic (s s' : RoundState) (h : RoundStep s s') :
    s.toNat ≤ s'.toNat ∨ s' = ROUND_WAITING := by
  obtain h := round_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · subst h1; subst h2; left; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; left; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; left; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; left; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; left; simp only [RoundState.toNat]; omega
  · right; exact h2

/-- **定理 2（round 无跳级）**：从 `PREFLOP` 一步无法到达 `RIVER`。

任何合法转移最多推进一个相位，不可跨相位跳级。
对应 Rust：`advance_round` 只做 `PREFLOP→FLOP`，不跳到 `RIVER`。 -/
theorem round_no_skip_preflop_to_river :
    ¬ RoundStep ROUND_PREFLOP ROUND_RIVER := by
  intro h
  obtain h := round_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  -- 6 分支分别对应 RoundStep 的 6 个析取项；s=PREFLOP, s'=RIVER 时
  -- 每个分支至少一个等式为假（不同构造子），用 `decide` 证其否定。
  · exact absurd h1 (by decide)   -- PREFLOP = WAITING ✗
  · exact absurd h2 (by decide)   -- RIVER  = FLOP    ✗
  · exact absurd h1 (by decide)   -- PREFLOP = FLOP   ✗
  · exact absurd h1 (by decide)   -- PREFLOP = TURN   ✗ (此处 h2: RIVER=RIVER 为真，必用 h1)
  · exact absurd h1 (by decide)   -- PREFLOP = RIVER  ✗
  · exact absurd h2 (by decide)   -- RIVER  = WAITING ✗

/-- **定理 3（前向严格递增）**：非 reset 转移（目标 ≠ `WAITING`）`toNat` 严格递增。 -/
theorem round_forward_strict_increasing
    (s s' : RoundState) (h : RoundStep s s') (hne : s' ≠ ROUND_WAITING) :
    s.toNat < s'.toNat := by
  obtain h := round_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  -- `simp only [RoundState.toNat]` 仅展开 toNat 到具体 Nat，不闭合 `<` 目标，留予 omega。
  · subst h1; subst h2; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; simp only [RoundState.toNat]; omega
  · subst h1; subst h2; simp only [RoundState.toNat]; omega
  · exact absurd h2 hne

/-- **定理 4（reset 只回 WAITING）**：若转移目标不是 `WAITING`，则为前向严格递增。

对应 Rust：`reset_for_next_hand`（`state_machine.rs:2837`）总是设 `round_state = ROUND_WAITING`。 -/
theorem round_reset_only_to_waiting
    (s s' : RoundState) (h : RoundStep s s') (hne : s' ≠ ROUND_WAITING) :
    s.toNat < s'.toNat :=
  round_forward_strict_increasing s s' h hne

/-- **定理 5（WAITING 前向只去 PREFLOP）**：从 `WAITING` 出发的非 reset 转移只能去 `PREFLOP`。

对应 `start_hand`（`state_machine.rs:2132`）：仅当 `round_state == ROUND_WAITING` 时启动。 -/
theorem round_from_waiting_forward_only_to_preflop
    (s' : RoundState) (h : RoundStep ROUND_WAITING s') (hne : s' ≠ ROUND_WAITING) :
    s' = ROUND_PREFLOP := by
  obtain h := round_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact h2
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h2 hne

/-- **定理 6（SHOWDOWN 后必回 WAITING）**：从 `SHOWDOWN` 出发的合法转移目标必为 `WAITING`。

对应 `settle_hand`（`state_machine.rs:2479-2541`）后调用 `reset_for_next_hand`。 -/
theorem round_from_showdown_only_to_waiting
    (s' : RoundState) (h : RoundStep ROUND_SHOWDOWN s') :
    s' = ROUND_WAITING := by
  obtain h := round_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact absurd h1 (by decide)
  · exact h2

end TexasPoker
