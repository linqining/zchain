import Mathlib

/-!
# 基础工具引理

为状态机证明提供的 `Nat` / `List` 工具引理。
仅包含后续阶段确实需要的最小集合，按需扩充。

注意：Lean 4 的 `Nat` 减法天然是截断（saturating）的，即 `a - b = 0` when `a < b`，
因此 Rust 的 `u64::saturating_sub` 直接对应 Lean `Nat.sub`，无需额外封装。
Mathlib 已提供 `List.sum_append` / `List.sum_cons` / `Nat.sub_le` 等，此处不重复。

与 Rust 代码无直接对应（纯证明支持层）。
-/

namespace TexasPoker

/-! ## Nat 截断减法便捷引理（对应 Rust `saturating_sub`）-/

/-- Lean `Nat.sub` 天然截断：`a < b → a - b = 0`。 -/
theorem Nat.sub_eq_zero_of_lt {a b : Nat} (h : a < b) : a - b = 0 :=
  Nat.sub_eq_zero_of_le (Nat.le_of_lt h)

/-! ## List 求和便捷引理 -/

theorem List.sum_nonneg (l : List Nat) : 0 ≤ l.sum := by
  induction l with
  | nil => simp
  | cons h t ih => rw [List.sum_cons]; omega

end TexasPoker
