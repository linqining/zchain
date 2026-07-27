import PokerLean.Common.M31

namespace PokerLean

/-!
# Poseidon252 哈希 — 抽象接口

将 Poseidon252 哈希建模为未解释函数（uninterpreted function），
通过公理刻画其核心性质（单射性）。

在 soundness 证明中，我们不需要验证 Poseidon 实现的正确性，
而是证明：**如果 AIR 约束满足且 state_root 正确（即 state_root = hash(preimage)），
那么合约语义必然满足。**
-/

/-- 状态预映像（抽象：表示 TexasPokerTable 的字段编码列表）。 -/
structure StatePreimage where
  /-- 预映像字段列表（每个字段为 M31）。 -/
  fields : List M31
deriving Repr

/-- 状态根（4×M31 limb，与 AIR 通用列对齐）。 -/
def StateRoot : Type := M31 × M31 × M31 × M31

/-- Poseidon252 哈希函数（抽象）。 -/
axiom poseidon_hash (preimage : StatePreimage) : StateRoot

/-- Poseidon 哈希的单射性公理（抗碰撞）。 -/
axiom poseidon_hash_injective :
  ∀ (pre1 pre2 : StatePreimage),
    poseidon_hash pre1 = poseidon_hash pre2 →
    pre1 = pre2

/-- 空预映像的哈希（零状态根）。 -/
axiom poseidon_hash_empty :
  poseidon_hash (StatePreimage.mk []) = (M31.zero, M31.zero, M31.zero, M31.zero)

/-- 预映像相等当且仅当字段列表相等。 -/
theorem state_preimage_eq_iff (pre1 pre2 : StatePreimage) :
  pre1 = pre2 ↔ pre1.fields = pre2.fields := by
  constructor
  · intro h; rw [h]
  · intro h
    cases pre1 with | mk f1 => cases pre2 with | mk f2 =>
      have hfi : f1 = f2 := by simpa [StatePreimage.mk.injEq] using h
      rw [hfi]

/-- poseidon_hash 的单射性（字段级别版本）。 -/
theorem poseidon_hash_injective_fields :
  ∀ (f1 f2 : List M31),
    poseidon_hash (StatePreimage.mk f1) = poseidon_hash (StatePreimage.mk f2) →
    f1 = f2 := by
  intro f1 f2 h
  have h' : StatePreimage.mk f1 = StatePreimage.mk f2 :=
    poseidon_hash_injective (StatePreimage.mk f1) (StatePreimage.mk f2) h
  have hf : (StatePreimage.mk f1).fields = (StatePreimage.mk f2).fields :=
    congrArg StatePreimage.fields h'
  simpa using hf

end PokerLean