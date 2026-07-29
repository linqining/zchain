import PokerLean.Common.M31

namespace PokerLean

/-!
# Poseidon252 哈希 — 抽象接口

将 Poseidon252 哈希建模为未解释函数（uninterpreted function）。

这里刻意**不**假设精确单射性。`StatePreimage` 包含任意长度的 `List M31`，
而 `StateRoot` 只有有限个值；从整个输入域到有限输出域的精确单射在数学上
不可能成立。真实系统所依赖的是限定编码域上的碰撞抗性，这是密码学安全假设，
不能用 Lean 中的全称等式公理冒充。

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

/-- 预映像相等当且仅当字段列表相等。 -/
theorem state_preimage_eq_iff (pre1 pre2 : StatePreimage) :
  pre1 = pre2 ↔ pre1.fields = pre2.fields := by
  constructor
  · intro h; rw [h]
  · intro h
    cases pre1 with | mk f1 => cases pre2 with | mk f2 =>
      have hfi : f1 = f2 := by simpa [StatePreimage.mk.injEq] using h
      rw [hfi]

end PokerLean
