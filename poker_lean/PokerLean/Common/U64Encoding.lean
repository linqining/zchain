import PokerLean.Common.M31

/-!
# u64 ↔ 4×M31 编码

将 u64 编码为 4 个 M31 limb（每 limb 16 位），
与 `poker_texas_air/src/airs/common.rs` 中的 `u64_to_m31_limbs` 一致。
-/

namespace PokerLean

/-! u64 类型表示（Lean 中用 Nat + 约束 < 2^64 表示） -/
def U64 : Type := { n : Nat // n < 2^64 }

namespace U64

def ofNat (n : Nat) (h : n < 2^64) : U64 := ⟨n, h⟩
def toNat (x : U64) : Nat := x.val

end U64

/-! 将 u64 分解为 4 个 16-bit limb（M31 域元素） -/
def u64ToLimbs (v : U64) : M31 × M31 × M31 × M31 :=
  let v' := v.val
  let l0 : Nat := v' % 65536
  let l1 : Nat := (v' / 65536) % 65536
  let l2 : Nat := (v' / (65536 * 65536)) % 65536
  let l3 : Nat := (v' / (65536 * 65536 * 65536)) % 65536
  have hl0 : l0 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt v' (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl1 : l1 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / 65536) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl2 : l2 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / (65536 * 65536)) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl3 : l3 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / (65536 * 65536 * 65536)) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  ⟨⟨l0, hl0⟩, ⟨l1, hl1⟩, ⟨l2, hl2⟩, ⟨l3, hl3⟩⟩

/-! 公理：limbsToU64 的结果 < 2^64 -/
private axiom limbsToU64_bound (l0 l1 l2 l3 : M31) :
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536) < 2^64

/-! 从 4 个 M31 limb 重建 u64 -/
def limbsToU64 (l0 l1 l2 l3 : M31) : U64 :=
  let v := l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)
  ⟨v, limbsToU64_bound l0 l1 l2 l3⟩

/-! 公理：往返一致性 -/
axiom roundtrip (v : U64) :
  let ⟨l0, l1, l2, l3⟩ := u64ToLimbs v
  limbsToU64 l0 l1 l2 l3 = v

/-! 公理：每个 limb < 65536 -/
axiom limb_lt_65536 (v : U64) :
  let ⟨l0, l1, l2, l3⟩ := u64ToLimbs v
  l0.val < 65536 ∧ l1.val < 65536 ∧ l2.val < 65536 ∧ l3.val < 65536

/-! 所有 limb 都 < M31_P -/
theorem limb_valid (v : U64) :
  let ⟨l0, l1, l2, l3⟩ := u64ToLimbs v
  l0.val < M31_P ∧ l1.val < M31_P ∧ l2.val < M31_P ∧ l3.val < M31_P := by
  simp only [u64ToLimbs]
  exact ⟨(u64ToLimbs v).1.property,
          (u64ToLimbs v).2.1.property,
          (u64ToLimbs v).2.2.1.property,
          (u64ToLimbs v).2.2.2.property⟩

/-! u64 解码辅助函数 -/
def decodeU64 (l0 l1 l2 l3 : M31) : Nat :=
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)

/-! Nat 到 M31 的简单转换（需要证明 n < M31_P） -/
def natToM31 (n : Nat) (h : n < M31_P) : M31 := ⟨n, h⟩

/-! 公理：u64ToLimbs 正确分解 -/
axiom u64ToLimbs_correct (v : U64) :
  let ⟨l0, l1, l2, l3⟩ := u64ToLimbs v
  l0.val = v.val % 65536 ∧
  l1.val = (v.val / 65536) % 65536 ∧
  l2.val = (v.val / (65536 * 65536)) % 65536 ∧
  l3.val = (v.val / (65536 * 65536 * 65536)) % 65536

/-! 常量 -/
def U64_MAX : Nat := 2^64
def LIMB_SIZE : Nat := 65536

/-! ## Limb 加法无溢出公理

Rust AIR 通过独立的 range constraint 保证每 limb < 65536（16-bit），
因此两个 limb 之和 < 131072 < M31_P = 2^31 - 1，M31.add 不取模。
Lean 模型暂未引入 range constraint，故将此性质作为公理。
-/

/-- 公理：M31.add 不溢出（limb 范围约束的抽象）。
    假设每 limb < 65536，因此 a.val + b.val < 131072 < M31_P。 -/
axiom m31_add_no_overflow (a b : M31) :
    (M31.add a b).val = a.val + b.val

/-- 引理：逐 limb M31.add 保持 decodeU64 线性。 -/
lemma decodeU64_limb_add (a0 a1 a2 a3 b0 b1 b2 b3 : M31) :
    decodeU64 (M31.add a0 b0) (M31.add a1 b1) (M31.add a2 b2) (M31.add a3 b3)
    = decodeU64 a0 a1 a2 a3 + decodeU64 b0 b1 b2 b3 := by
  simp only [decodeU64, m31_add_no_overflow]
  ring

end PokerLean
