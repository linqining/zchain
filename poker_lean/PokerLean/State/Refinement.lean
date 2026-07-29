import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.Betting
import PokerLean.State.Transitions
import PokerLean.State.Invariants
import PokerLean.State.RoundMachine
import PokerLean.State.SidePot
import PokerLean.State.SubPhases
import PokerLean.State.Theorems

/-!
# Phase 6b: 局部模型↔代码精化论证（Refinement）

本文件建立若干 **座位级算术前缀** 与 Rust `checked_*` 代码的
手工精化引理。它没有将 Rust 源码嵌入 Lean，也没有闭合完整 VM
`apply_* → advance_turn → collect/advance/settlement` 的实现级精化。

## 精化策略（手工镜像 + panic-freedom 论证）

由于无法在 Lean 中直接嵌入 Rust 源码（无 Rust frontend），采用**手工精化论证**：

1. **类型映射**（§1）：Lean `Nat` ↔ Rust `u64`，由 `≤ U64_MAX` 上界约束。
   Lean 截断减法 `a - b` ↔ Rust `u64::saturating_sub`；溢出由不变量排除。
2. **panic-freedom 义务**（§2）：Rust 每处 `checked_add/checked_sub/checked_mul`
   的成功条件（无溢出/下溢）由 Lean 不变量蕴含。
3. **Rust checked 操作建模**（§3）：将 Rust `checked_add/checked_sub` 建模为
   `Option Nat` 函数，证明在 panic-freedom 下其语义等于 Lean `Nat` 运算。
4. **座位更新前缀精化**（§4）：Rust 座位级 call/raise 算术（用 `checked_*`）
   在 panic-freedom 下产出与 Lean `Seat.apply_call/apply_raise` 相同的座位字段。
5. **chip 守恒迁移**（§5）：精化（§4）+ Lean chip 守恒（Phase 2-3）⟹
   Rust chip 守恒（每个 `checked_*` 成功 ⟹ 不 panic ⟹ 字段值 = Lean 字段值 ⟹ 守恒）。

## 关键界引理

`inv_chip_bounds` 保证所有筹码量 ≤ `MAX_TOTAL_BET = 10^18`。
两个 ≤ `MAX_TOTAL_BET` 的量相加 ≤ `2×10^18 < U64_MAX = 2^64-1 ≈ 1.8×10^19`。
故 Rust `checked_add` 在不变量下永不溢出 —— 这是连接「Lean `Nat` 无溢出」
与「Rust `u64` 有溢出」的桥梁。

## 重要说明：为何不证 `total_chips ≤ U64_MAX`

`total_chips = Σ(stack + bet + pending_addon) + pot + rake_collected` 是跨所有座位的求和，
在 `max_players = 9` 下可达 `9 × 3 × MAX_TOTAL_BET > U64_MAX`，故 `total_chips ≤ U64_MAX`
**不成立**。但 Rust chip 守恒**不要求**总和 ≤ U64_MAX：Rust 的每个 `checked_add(a, b)`
只要求**单步** `a + b ≤ U64_MAX`（由 §2 panic-freedom 保证），单步成功 ⟹ Rust 字段值
= Lean `Nat` 字段值 ⟹ 跨字段求和的守恒性从 Lean 迁移到 Rust。本文件据此组织证明。
-/

namespace TexasPoker

open Constants

/-! ## §0 关键界引理 -/

/-- `MAX_TOTAL_BET` 的字面量值（= 10^18）。 -/
theorem MAX_TOTAL_BET_eq : MAX_TOTAL_BET = 1000000000000000000 := rfl

/-- `2 * MAX_TOTAL_BET ≤ U64_MAX`：两个有界量相加不溢出 u64。

`2 × 10^18 = 2,000,000,000,000,000,000 < 18,446,744,073,709,551,615 = 2^64 - 1`。 -/
theorem two_mul_MAX_TOTAL_BET_le_U64_MAX :
    2 * MAX_TOTAL_BET ≤ U64_MAX := by
  rw [MAX_TOTAL_BET_eq, U64_MAX_eq]
  decide

/-- `MAX_TOTAL_BET ≤ U64_MAX`：单个有界量不溢出 u64。 -/
theorem MAX_TOTAL_BET_le_U64_MAX : MAX_TOTAL_BET ≤ U64_MAX := by
  rw [MAX_TOTAL_BET_eq, U64_MAX_eq]
  decide

/-! ## §1 类型映射（Lean ↔ Rust）

| Lean (State 模型)      | Rust (state_machine.rs)        | 说明 |
|------------------------|--------------------------------|------|
| `Nat`                  | `u64`                          | 由 `≤ U64_MAX` 约束 |
| `a - b`（截断）        | `u64::saturating_sub(a, b)`    | 不变量保证 `b ≤ a`，故无截断 |
| `a + b`                | `u64::checked_add(a, b)?`      | 不变量保证 `a + b ≤ U64_MAX` |
| `Seat`                 | `Seat`                         | 14 字段逐字段对应 |
| `TexasPokerTable`      | `TexasPokerTable`              | 全字段对应 |
| `BettingRound`         | `BettingRound`                 | `current_bet` / `min_raise` |
| `SidePot`              | `SidePot`                      | `amount` / `eligible_seats` |

密码学类型（`ECPoint` / `ECScalar` / `ElGamalCiphertext`）为不透明占位，
状态机证明不依赖其内部结构（见 `Types.lean:16-36`）。
-/

/-! ## §2 panic-freedom 义务

每个 Rust `checked_*` 操作对应一个 Lean 不变量蕴含的成功条件。
我们用 `u64_add_ok a b := a + b ≤ U64_MAX` 与 `u64_sub_ok a b := b ≤ a`
建模 Rust `checked_add`/`checked_sub` 的成功（无 `Ok_or_else` 早退）。
-/

/-- Rust `checked_add(a, b)` 成功的条件：`a + b ≤ U64_MAX`。 -/
def u64_add_ok (a b : Nat) : Prop := a + b ≤ U64_MAX

/-- Rust `checked_sub(a, b)` 成功的条件：`b ≤ a`（无下溢）。 -/
def u64_sub_ok (a b : Nat) : Prop := b ≤ a

/-! ### §2.1 `process_call` panic-freedom（`state_machine.rs:2071-2080`）

Rust：
```rust
seat.stack = seat.stack.checked_sub(call_amt)?;   // 2071-2072
seat.bet = seat.bet.checked_add(call_amt)?;       // 2075-2076
seat.total_bet = seat.total_bet.checked_add(call_amt)?; // 2079-2080
```
其中 `call_amt = min(current_bet - seat.bet, seat.stack)`（`process_call`）。
-/

/-- `process_call` 的 `checked_sub(seat.stack, call_amt)` 成功：`call_amt ≤ stack`。

由 `call_amt = min(current_bet - bet, stack) ≤ stack` 直接得到。 -/
theorem process_call_sub_ok (s : Seat) (r : BettingRound) :
    u64_sub_ok s.stack (r.process_call s.bet s.stack) := by
  unfold u64_sub_ok BettingRound.process_call
  exact Nat.min_le_right _ _

/-- `process_call` 的 `checked_add(seat.bet, call_amt)` 成功。

`bet + call_amt ≤ bet + stack ≤ MAX_TOTAL_BET ≤ U64_MAX`
（由 `inv_chip_bounds` 的 `stack + bet ≤ MAX_TOTAL_BET`）。 -/
theorem process_call_bet_add_ok (s : Seat) (r : BettingRound)
    (h_bound : s.stack + s.bet ≤ MAX_TOTAL_BET) :
    u64_add_ok s.bet (r.process_call s.bet s.stack) := by
  unfold u64_add_ok
  have h_ca_le : r.process_call s.bet s.stack ≤ s.stack :=
    Nat.min_le_right _ _
  have h_max := MAX_TOTAL_BET_le_U64_MAX
  omega

/-- `process_call` 的 `checked_add(seat.total_bet, call_amt)` 成功。

`total_bet + call_amt ≤ total_bet + stack ≤ MAX_TOTAL_BET ≤ U64_MAX`
（由 `inv_chip_bounds` 的 `total_bet + stack ≤ MAX_TOTAL_BET`）。 -/
theorem process_call_total_bet_add_ok (s : Seat) (r : BettingRound)
    (h_bound : s.total_bet + s.stack ≤ MAX_TOTAL_BET) :
    u64_add_ok s.total_bet (r.process_call s.bet s.stack) := by
  unfold u64_add_ok
  have h_ca_le : r.process_call s.bet s.stack ≤ s.stack :=
    Nat.min_le_right _ _
  have h_max := MAX_TOTAL_BET_le_U64_MAX
  omega

/-- **`process_call` 全 panic-freedom**：三处 `checked_*` 均成功。 -/
theorem process_call_panic_free (s : Seat) (r : BettingRound)
    (h1 : s.stack + s.bet ≤ MAX_TOTAL_BET)
    (h2 : s.total_bet + s.stack ≤ MAX_TOTAL_BET) :
    u64_sub_ok s.stack (r.process_call s.bet s.stack) ∧
    u64_add_ok s.bet (r.process_call s.bet s.stack) ∧
    u64_add_ok s.total_bet (r.process_call s.bet s.stack) :=
  ⟨process_call_sub_ok s r,
   process_call_bet_add_ok s r h1,
   process_call_total_bet_add_ok s r h2⟩

/-! ### §2.2 `process_raise` panic-freedom（`state_machine.rs:2136-2142`）

Rust：
```rust
seat.stack = seat.stack.checked_sub(needed)?;            // 2136-2137
seat.total_bet = seat.total_bet.checked_add(needed)?;    // 2141-2142
```
其中 `needed = total_bet - seat.bet`（由 `process_raise` 校验 `total_bet > seat.bet`）。
-/

/-- `process_raise` 的 `checked_sub(seat.stack, needed)` 成功。

需 `needed ≤ seat.stack`（由 `process_raise` 成功前置保证）。 -/
theorem process_raise_sub_ok (s : Seat) (needed : Nat)
    (h_needed_le_stack : needed ≤ s.stack) :
    u64_sub_ok s.stack needed := by
  exact h_needed_le_stack

/-- `process_raise` 的 `checked_add(seat.total_bet, needed)` 成功。

`total_bet + needed ≤ total_bet + stack ≤ MAX_TOTAL_BET ≤ U64_MAX`
（由 `inv_chip_bounds` 的 `total_bet + stack ≤ MAX_TOTAL_BET`）。 -/
theorem process_raise_total_bet_add_ok (s : Seat) (needed : Nat)
    (h_needed_le_stack : needed ≤ s.stack)
    (h_bound : s.total_bet + s.stack ≤ MAX_TOTAL_BET) :
    u64_add_ok s.total_bet needed := by
  unfold u64_add_ok
  have h_max := MAX_TOTAL_BET_le_U64_MAX
  omega

/-- **`process_raise` 全 panic-freedom**。 -/
theorem process_raise_panic_free (s : Seat) (needed : Nat)
    (h_needed_le_stack : needed ≤ s.stack)
    (h_bound : s.total_bet + s.stack ≤ MAX_TOTAL_BET) :
    u64_sub_ok s.stack needed ∧ u64_add_ok s.total_bet needed :=
  ⟨process_raise_sub_ok s needed h_needed_le_stack,
   process_raise_total_bet_add_ok s needed h_needed_le_stack h_bound⟩

/-! ### §2.3 `collect_bets_to_pot` panic-freedom（`state_machine.rs:573-602`）

Rust：
```rust
table.pot = table.pot.checked_add(s.bet)?;  // 580
```
对每个 seat 的 `bet` 累加到 `pot`。
-/

/-- `collect_bets_to_pot` 单步 `checked_add(pot, bet)` 成功。

前置：累加过程中 `pot` 已含之前 seats 的 bet，故需更强的 `pot + Σ bet ≤ MAX_TOTAL_BET`。
由 `inv_chip_bounds` 的 `pot ≤ MAX_TOTAL_BET` 与各 `bet ≤ MAX_TOTAL_BET`，
加上 `2 * MAX_TOTAL_BET ≤ U64_MAX` 保证两量相加不溢出。 -/
theorem collect_bets_to_pot_add_ok (pot bet : Nat)
    (h_pot : pot ≤ MAX_TOTAL_BET) (h_bet : bet ≤ MAX_TOTAL_BET) :
    u64_add_ok pot bet := by
  unfold u64_add_ok
  have h_2max := two_mul_MAX_TOTAL_BET_le_U64_MAX
  omega

/-! ### §2.4 `end_without_showdown` panic-freedom（`state_machine.rs:2505-2557`）

Rust：
```rust
let rake = collect_rake(table)?;                      // 2520
let pot = table.pot;                                   // 2525
table.seats[winner].stack.checked_add(pot)?;          // 2535-2536
```
-/

/-- `end_without_showdown` 的 `checked_add(winner.stack, pot)` 成功。

`winner.stack + pot ≤ MAX_TOTAL_BET + MAX_TOTAL_BET = 2*MAX ≤ U64_MAX`
（`stack ≤ MAX`、`pot ≤ MAX`）。 -/
theorem end_without_showdown_stack_add_ok (winner_stack pot : Nat)
    (h_stack : winner_stack ≤ MAX_TOTAL_BET) (h_pot : pot ≤ MAX_TOTAL_BET) :
    u64_add_ok winner_stack pot := by
  unfold u64_add_ok
  have h_2max := two_mul_MAX_TOTAL_BET_le_U64_MAX
  omega

/-! ### §2.5 `reset_for_next_hand` panic-freedom（`state_machine.rs:2788-2958`）

Rust：
```rust
seat.stack = seat.stack.checked_add(seat.pending_addon)?;  // 2802-2803
```
-/

/-- `reset_for_next_hand` 的 `checked_add(stack, pending_addon)` 成功。

前置 `stack + pending_addon ≤ MAX_TOTAL_BET`（定理 6 前置）⟹ `≤ U64_MAX`。 -/
theorem reset_for_next_hand_stack_add_ok (stack pending_addon : Nat)
    (h : stack + pending_addon ≤ MAX_TOTAL_BET) :
    u64_add_ok stack pending_addon := by
  unfold u64_add_ok
  have h_max := MAX_TOTAL_BET_le_U64_MAX
  omega

/-! ### §2.6 version 递增 panic-freedom

Rust 所有方法 `table.version = table.version.checked_add(1)?` 或 saturating_add。
-/

/-- version 递增 `checked_add(version, 1)` 成功：`version < U64_MAX` ⟹ `version + 1 ≤ U64_MAX`。 -/
theorem version_inc_add_ok (version : Nat) (h : version < U64_MAX) :
    u64_add_ok version 1 := by
  unfold u64_add_ok
  omega

/-! ## §3 Rust `checked_*` 操作建模

将 Rust `checked_add` / `checked_sub` 建模为 `Option Nat` 函数，并证明在 panic-freedom
条件下其语义等于 Lean `Nat` 运算。这是连接「Rust 显式溢出检查」与「Lean 无溢出 `Nat`」
的桥梁。
-/

/-- Rust `u64::checked_add(a, b)`：成功返回 `some (a + b)`，溢出返回 `none`。 -/
def rust_checked_add (a b : Nat) : Option Nat :=
  if a + b ≤ U64_MAX then some (a + b) else none

/-- Rust `u64::checked_sub(a, b)`：成功返回 `some (a - b)`，下溢返回 `none`。 -/
def rust_checked_sub (a b : Nat) : Option Nat :=
  if b ≤ a then some (a - b) else none

/-- `rust_checked_add` 在 panic-freedom 下等于 `some (a + b)`。

对应 Rust：`checked_add(a, b)?` 在 `a + b ≤ U64_MAX` 时返回 `Some(a + b)`，
`?` 操作符将其解包，故后续代码见到的值即 `a + b`，与 Lean `Nat` 加法一致。 -/
theorem rust_checked_add_eq (a b : Nat) (h : u64_add_ok a b) :
    rust_checked_add a b = some (a + b) := by
  unfold rust_checked_add u64_add_ok at *
  rw [if_pos h]

/-- `rust_checked_sub` 在 panic-freedom 下等于 `some (a - b)`。

对应 Rust：`checked_sub(a, b)?` 在 `b ≤ a` 时返回 `Some(a - b)`，
与 Lean `Nat` 截断减法一致（`b ≤ a` 时无截断）。 -/
theorem rust_checked_sub_eq (a b : Nat) (h : u64_sub_ok a b) :
    rust_checked_sub a b = some (a - b) := by
  unfold rust_checked_sub u64_sub_ok at *
  rw [if_pos h]

/-! ## §4 状态转移精化（座位级）

镜像 Rust `state_machine.rs:2071-2142` 的座位级 `apply_call` / `apply_raise`，
其中每个算术运算用 `rust_checked_*` 替换。证明：在 panic-freedom 前置下，
Rust 版本（返回 `Option Seat`）等于 `some (Lean Seat.apply_*)`。

这是精化论证的核心：Rust 的 `checked_*` 成功 ⟹ Rust 字段值 = Lean 字段值。
-/

/-- Rust 座位级 `apply_call`（`state_machine.rs:2071-2085`）。

对应 Rust 代码（伪代码）：
```rust
let call_amt = process_call(r, seat.bet, seat.stack);
seat.stack = seat.stack.checked_sub(call_amt)?;       // 2071-2072
seat.bet = seat.bet.checked_add(call_amt)?;           // 2075-2076
seat.total_bet = seat.total_bet.checked_add(call_amt)?; // 2079-2080
if seat.stack == 0 && call_amt > 0 { seat.all_in = true; }  // 2081-2084
seat.acted_this_round = true;                         // 2085
```
任一 `checked_*` 失败则函数返回 `Err`（Lean 中建模为 `none`）。

注：内联 `r.process_call s.bet s.stack`（不用 `let`），便于 `rw` 直接匹配模式。 -/
def rust_apply_call (s : Seat) (r : BettingRound) : Option Seat :=
  match rust_checked_sub s.stack (r.process_call s.bet s.stack) with
  | none => none
  | some stack' =>
    match rust_checked_add s.bet (r.process_call s.bet s.stack) with
    | none => none
    | some _bet' =>
      match rust_checked_add s.total_bet (r.process_call s.bet s.stack) with
      | none => none
      | some _total_bet' =>
        some { s with
          stack := stack',
          bet := s.bet + r.process_call s.bet s.stack,
          total_bet := s.total_bet + r.process_call s.bet s.stack,
          all_in := decide (stack' = 0) && decide (r.process_call s.bet s.stack > 0),
          acted_this_round := true }

/-- **`rust_apply_call` 精化到 Lean `Seat.apply_call`**。

在 `process_call` 的三处 `checked_*` 均 panic-freedom 的前置下，Rust 版本
返回 `some (Seat.apply_call s r)`，即与 Lean 模型产出完全相同的座位状态。

证明骨架：
- `rust_checked_sub s.stack call_amt = some (s.stack - call_amt)`（§3 + `u64_sub_ok`）
- `rust_checked_add s.bet call_amt = some (s.bet + call_amt)`（§3 + `u64_add_ok`）
- `rust_checked_add s.total_bet call_amt = some (s.total_bet + call_amt)`（§3 + `u64_add_ok`）
- 代入后 `rust_apply_call` 化简为 `some { stack := s.stack - call_amt, ... }`
- 与 `Seat.apply_call` 展开式逐字段相等（`stack' = s.stack - call_amt` 决定 `all_in` 一致） -/
theorem rust_apply_call_refines (s : Seat) (r : BettingRound)
    (h1 : u64_sub_ok s.stack (r.process_call s.bet s.stack))
    (h2 : u64_add_ok s.bet (r.process_call s.bet s.stack))
    (h3 : u64_add_ok s.total_bet (r.process_call s.bet s.stack)) :
    rust_apply_call s r = some (Seat.apply_call s r) := by
  unfold rust_apply_call Seat.apply_call
  rw [rust_checked_sub_eq s.stack _ h1,
      rust_checked_add_eq s.bet _ h2,
      rust_checked_add_eq s.total_bet _ h3]

/-- Rust 座位级 `apply_raise`（`state_machine.rs:2136-2142`）。

对应 Rust 代码（伪代码）：
```rust
seat.stack = seat.stack.checked_sub(needed)?;          // 2136-2137
seat.bet = total_bet;                                   // 2140
seat.total_bet = seat.total_bet.checked_add(needed)?;  // 2141-2142
if seat.stack == 0 { seat.all_in = true; }              // 2143-2145
seat.acted_this_round = true;                           // 2146
```
`needed = total_bet - seat.bet`，由 `process_raise` 成功结果提供。 -/
def rust_apply_raise (s : Seat) (total_bet needed : Nat) : Option Seat :=
  match rust_checked_sub s.stack needed with
  | none => none
  | some stack' =>
    match rust_checked_add s.total_bet needed with
    | none => none
    | some _total_bet' =>
      some { s with
        stack := stack',
        bet := total_bet,
        total_bet := s.total_bet + needed,
        all_in := decide (stack' = 0),
        acted_this_round := true }

/-- **`rust_apply_raise` 精化到 Lean `Seat.apply_raise`**。

在 `process_raise` 的两处 `checked_*` 均 panic-freedom 的前置下，Rust 版本
返回 `some (Seat.apply_raise s total_bet needed)`。 -/
theorem rust_apply_raise_refines (s : Seat) (total_bet needed : Nat)
    (h1 : u64_sub_ok s.stack needed)
    (h2 : u64_add_ok s.total_bet needed) :
    rust_apply_raise s total_bet needed = some (Seat.apply_raise s total_bet needed) := by
  unfold rust_apply_raise Seat.apply_raise
  rw [rust_checked_sub_eq s.stack needed h1,
      rust_checked_add_eq s.total_bet needed h2]

/-! ## §5 chip 守恒迁移（Lean ⟹ Rust）

精化（§4）+ Lean chip 守恒（Phase 2-3）⟹ Rust chip 守恒。

核心论证：Rust `checked_*` 成功（panic-freedom，§2）⟹ Rust 不早退 ⟹
Rust 字段值 = Lean `Nat` 字段值（§4）⟹ Lean `seat_chips` 守恒迁移到 Rust。
-/

/-- **`rust_apply_call` 保持 `seat_chips`**（panic-freedom 前置下）。

由 §4 精化（`rust_apply_call s r = some (Seat.apply_call s r)`）+ Lean
`apply_call_seat_chips`（`Seat.apply_call` 保持 `seat_chips`）直接得到。 -/
theorem rust_apply_call_conserves_seat_chips (s : Seat) (r : BettingRound)
    (h1 : u64_sub_ok s.stack (r.process_call s.bet s.stack))
    (h2 : u64_add_ok s.bet (r.process_call s.bet s.stack))
    (h3 : u64_add_ok s.total_bet (r.process_call s.bet s.stack)) :
    ∃ s', rust_apply_call s r = some s' ∧ seat_chips s' = seat_chips s := by
  refine ⟨Seat.apply_call s r, rust_apply_call_refines s r h1 h2 h3,
          Seat.apply_call_seat_chips s r⟩

/-- **`rust_apply_raise` 保持 `seat_chips`**（panic-freedom 前置下）。

由 §4 精化 + Lean `apply_raise_seat_chips`（需 `total_bet = s.bet + needed`、
`needed ≤ s.stack`）得到。`total_bet = s.bet + needed` 来自 `process_raise`
成功结构（`needed = total_bet - seat_bet`）；`needed ≤ s.stack` 来自
`process_raise` 的 `CannotRaise` 检查。 -/
theorem rust_apply_raise_conserves_seat_chips (s : Seat) (total_bet needed : Nat)
    (h1 : u64_sub_ok s.stack needed)
    (h2 : u64_add_ok s.total_bet needed)
    (h_tb : total_bet = s.bet + needed) :
    ∃ s', rust_apply_raise s total_bet needed = some s' ∧ seat_chips s' = seat_chips s := by
  have h_le : needed ≤ s.stack := by
    unfold u64_sub_ok at h1; exact h1
  refine ⟨Seat.apply_raise s total_bet needed,
          rust_apply_raise_refines s total_bet needed h1 h2,
          Seat.apply_raise_seat_chips s total_bet needed h_tb h_le⟩

/-! ### §5.1 从 `inv_chip_bounds` 推出 `apply_call` 全 panic-freedom

`inv_chip_bounds` 的逐字段界直接蕴含 §2.1 的 panic-freedom 前置，
故 Rust `apply_call` 在 `inv_chip_bounds` 下永不 panic。 -/
theorem inv_chip_bounds_implies_apply_call_panic_free (s : Seat) (r : BettingRound)
    (h_bound : s.total_bet + s.stack ≤ MAX_TOTAL_BET ∧
               s.stack + s.bet ≤ MAX_TOTAL_BET ∧
               s.pending_addon ≤ MAX_TOTAL_BET) :
    u64_sub_ok s.stack (r.process_call s.bet s.stack) ∧
    u64_add_ok s.bet (r.process_call s.bet s.stack) ∧
    u64_add_ok s.total_bet (r.process_call s.bet s.stack) := by
  refine ⟨process_call_sub_ok s r, ?_, ?_⟩
  · exact process_call_bet_add_ok s r h_bound.2.1
  · exact process_call_total_bet_add_ok s r h_bound.1

/-! ### §5.2 桌台级 call 局部前缀（非完整 Rust `apply_call`）

本节只把座位级 `apply_call` 作用到第 i 个 seat，并检查 `version + 1`
抽象中的 chip 守恒与局部 `checked_*` 成功条件。它不建模后续
`advance_turn`，因而不是桌台级 Rust `apply_call` 的完整精化。

定理名中的 `rust` 为历史命名；机器检查的结论只是 Lean 局部前缀
守恒 + 对应座位算术的 panic-freedom 条件。 -/
theorem apply_call_rust_chip_conservation_via_refinement (t : TexasPokerTable)
    (i : Nat) (r : BettingRound)
    (h_br : t.betting_round = some r)
    (h_bounds : inv_chip_bounds t)
    (h_len : i < t.seats.length) :
    -- Lean 局部前缀守恒
    total_chips (apply_call t i) = total_chips t ∧
    -- panic-freedom: 第 i 个 seat 的三处 checked_* 均成功
    u64_sub_ok (t.seats.get ⟨i, h_len⟩).stack
               (r.process_call (t.seats.get ⟨i, h_len⟩).bet
                               (t.seats.get ⟨i, h_len⟩).stack) ∧
    u64_add_ok (t.seats.get ⟨i, h_len⟩).bet
               (r.process_call (t.seats.get ⟨i, h_len⟩).bet
                               (t.seats.get ⟨i, h_len⟩).stack) ∧
    u64_add_ok (t.seats.get ⟨i, h_len⟩).total_bet
               (r.process_call (t.seats.get ⟨i, h_len⟩).bet
                               (t.seats.get ⟨i, h_len⟩).stack) := by
  -- Lean 守恒（Phase 2 已证）
  have h_cons := apply_call_chip_conservation t i
  -- panic-freedom（由 inv_chip_bounds 推出）
  have h_seat_mem : t.seats.get ⟨i, h_len⟩ ∈ t.seats := List.get_mem _ _ _
  rcases h_bounds with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  have h_bounds_seat := h_seats _ h_seat_mem
  have h_pf :=
    inv_chip_bounds_implies_apply_call_panic_free (t.seats.get ⟨i, h_len⟩) r h_bounds_seat
  exact ⟨h_cons, h_pf⟩

/-! ### §5.3 fold/check 座位更新前缀（无 `checked_*`）

`apply_fold` / `apply_check` 无算术运算（仅置 bool 标记），Rust 中无 `checked_*`，
故座位更新前缀无算术 panic 风险。下列定理只证明 Lean 前缀守恒，
不包含完整 `advance_turn` 分支。 -/
theorem apply_fold_rust_chip_conservation (t : TexasPokerTable) (i : Nat) :
    total_chips (apply_fold t i) = total_chips t :=
  apply_fold_chip_conservation t i

theorem apply_check_rust_chip_conservation (t : TexasPokerTable) (i : Nat) :
    total_chips (apply_check t i) = total_chips t :=
  apply_check_chip_conservation t i

/-! ### §5.4 `end_without_showdown` 的 Lean 模型守恒 + 算术义务

`end_without_showdown`（`state_machine.rs:2505-2557`）的资金流：
1. `collect_rake`：`pot -= rake`, `rake_collected += rake`（chip 守恒）
2. `winner.stack += pot`（`checked_add`，panic-freedom 由 §2.4 保证）
3. `pot = 0`
4. `reset_for_next_hand`：合并 `pending_addon → stack`（chip 守恒）

Lean 已在 `Theorems.lean` 证明 `end_without_showdown_chip_conservation`，下列定理
再给出 winner stack 加法的一个数值上界义务。这不证明 Rust 实现的完整
分支、循环、事件和 post-state 精化；定理名中的 `rust` 为历史命名。 -/
theorem end_without_showdown_rust_chip_conservation (t : TexasPokerTable)
    (winner_idx : Nat) (rake : Nat)
    (h_rake_le : rake ≤ t.pot)
    (h_len : winner_idx < t.seats.length)
    (h_all_bet_zero : ∀ s ∈ t.seats, s.bet = 0)
    (h_bounds : inv_chip_bounds t) :
    -- Lean 抽象模型的 chip 守恒
    total_chips (end_without_showdown t winner_idx rake h_rake_le) = total_chips t ∧
    -- panic-freedom: winner.stack + pot ≤ U64_MAX
    u64_add_ok (t.seats.get ⟨winner_idx, h_len⟩).stack t.pot := by
  refine ⟨end_without_showdown_chip_conservation t winner_idx rake h_rake_le h_len
            h_all_bet_zero, ?_⟩
  have h_seat_mem : t.seats.get ⟨winner_idx, h_len⟩ ∈ t.seats := List.get_mem _ _ _
  rcases h_bounds with ⟨h_pot, h_ante, h_rake, h_addon, h_seats⟩
  have h_bounds_seat := h_seats _ h_seat_mem
  -- seat 的 stack ≤ MAX_TOTAL_BET（由 stack + bet ≤ MAX ⟹ stack ≤ MAX）
  have h_stack_le : (t.seats.get ⟨winner_idx, h_len⟩).stack ≤ MAX_TOTAL_BET := by
    have h_sb := h_bounds_seat.2.1
    omega
  exact end_without_showdown_stack_add_ok _ _ h_stack_le h_pot

/-! ### §5.5 `reset_for_next_hand` 的 Lean 模型守恒

`reset_for_next_hand`（`state_machine.rs:2788-2958`）的资金操作：
`seat.stack = seat.stack.checked_add(seat.pending_addon)?`（每个 seat）。

Lean 已在 `Theorems.lean` 证明 `reset_for_next_hand_chip_conservation`。本节没有建立
Rust 循环/早退/post-state 的完整精化；定理名中的 `rust` 为历史命名。 -/
theorem reset_for_next_hand_rust_chip_conservation (t : TexasPokerTable)
    (h_all_bet_zero : ∀ s ∈ t.seats, s.bet = 0)
    (h_pot_zero : t.pot = 0) :
    -- Lean 抽象模型的 chip 守恒
    total_chips (reset_for_next_hand t) = total_chips t :=
  reset_for_next_hand_chip_conservation t h_all_bet_zero h_pot_zero

/-! ## §6 精化论证总结

### 证明链条

1. **Lean 模型正确性**（Phase 1-5）：
   - `apply_fold/check/call/raise` 保持 `total_chips`（`Transitions.lean`）
   - `apply_addon/rebuy/collect_rake/collect_ante` 保持 `total_chips` 增量（`Invariants.lean`）
   - `end_without_showdown` / `reset_for_next_hand` 保持 `total_chips`（`Theorems.lean`）
   - 6 个核心不变量被各操作保持（`Invariants.lean` / `Theorems.lean`）
   - 子相位转移保持 `chips_unchanged`（`SubPhases.lean`）

2. **panic-freedom**（§2）：
   - 每个 Rust `checked_*` 的成功条件由 `inv_chip_bounds` 蕴含
   - 关键界：`2 * MAX_TOTAL_BET ≤ U64_MAX`（§0），保证两个有界量相加不溢出 u64

3. **Rust 局部算术前缀 = Lean 座位操作**（§3-§4）：
   - `rust_checked_add/sub` 在 panic-freedom 下 = `some (a + b)` / `some (a - b)`
   - `rust_apply_call` = `some (Seat.apply_call)` 在 panic-freedom 下
   - `rust_apply_raise` = `some (Seat.apply_raise)` 在 panic-freedom 下

4. **chip 守恒迁移**（§5）：
   - Lean `total_chips` 守恒 + 精化（Rust 字段值 = Lean 字段值）⟹ Rust `total_chips` 守恒
   - 不需要 `total_chips ≤ U64_MAX`（Rust 单步 `checked_*` 成功即可，无需总和 ≤ U64_MAX）

### 已覆盖的局部函数/抽象（非完整 VM 方法精化）

| Rust 函数                | Lean 模型              | panic-freedom | chip 守恒 |
|--------------------------|------------------------|---------------|-----------|
| `process_call`           | `BettingRound.process_call` | §2.1     | N/A（纯计算） |
| `process_raise`          | `BettingRound.process_raise`| §2.2     | N/A |
| `apply_call` 座位更新前缀 | `Seat.apply_call` | §2.1 + §5.2 | §5.2 |
| `apply_raise` 座位更新前缀 | `Seat.apply_raise` | §2.2 | §5（座位级）|
| `apply_fold` 座位更新前缀 | `Seat.apply_fold` | 无 `checked_*`| §5.3 |
| `apply_check` 座位更新前缀 | `Seat.apply_check` | 无 `checked_*`| §5.3 |
| `collect_bets_to_pot`    | Lean 抽象模型       | §2.3 | 模型内守恒；Rust 完整精化未建立 |
| `end_without_showdown`   | Lean 抽象模型 | §2.4 + §2.5 | 模型内守恒；Rust 完整精化未建立 |
| `reset_for_next_hand`    | `reset_for_next_hand`  | §2.5          | §5.5      |
| `collect_rake`           | `collect_rake`         | N/A           | Lean 已证 |
| `apply_addon`/`rebuy`    | `apply_addon`/`rebuy`  | §2（类似）    | Lean 已证 |

### 限制与未覆盖项

1. **`advance_turn` / `collect_bets_to_pot` / `advance_round` / settlement 的完整精化未建立**。
   现有 Lean 模块包含若干抽象函数和模型内不变量，但没有证明它们与
   Rust 完整分支、调用顺序及 post-state 逐字段一致。
2. **密码学函数**（`join_and_shuffle` / `submit_shuffle_v2` / `submit_reveal_tokens` /
   `submit_reconstruct_deck`）：状态机证明不依赖其内部结构（密码学类型为不透明占位），
   其 panic-freedom 由各自的前置检查（phase gating）保证，不在本文件详证。
3. **`total_chips ≤ U64_MAX`**：不成立（跨座位求和可超 U64_MAX），但 Rust chip 守恒
   不需要此条件（每个单步 `checked_*` 成功即可），见 §5 说明。
4. **Rust 源码本身**：未在 Lean 中嵌入（无 Rust frontend），精化论证基于手工镜像。
   类型映射和行号引用只是 review 证据，不构成机器可检查的 Rust↔Lean 等价证明。
-/

end TexasPoker
