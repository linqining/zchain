import PokerLean.Common.CommonColumns

/-!
# AIR 电路约束基础接口

定义 AIR 约束的通用接口：
- 约束是关于行数据的谓词
- 满足所有约束的行即被接受
-/

namespace PokerLean

/-! AIR 约束：一行数据需要满足的谓词 -/
def AirConstraint (row : CommonRow) (method_kind : MethodKind) : Type :=
  { P : Prop // P }

/-! AIR 接受谓词：所有约束同时满足 -/
structure AirAcceptance (row : CommonRow) (kind : MethodKind) where
  common_ok : Prop
  hcommon : common_ok ↔ CommonConstraints row kind
  method_specific_ok : Prop

/-! AIR 接受的一行 -/
def AirRowAcceptable (row : CommonRow) (kind : MethodKind) : Prop :=
  ∃ a : AirAcceptance row kind, a.common_ok ∧ a.method_specific_ok

/-! AIR 接受的 table-wide 约束（多行交互） -/
structure AirTableConstraints where
  rows : List CommonRow
  all_rows_ok : ∀ row ∈ rows,
    AirRowAcceptable row ((MethodKind.lookup row.method_kind.toNat).getD MethodKind.CreateTable)

/-! Nat 到 M31 的转换（需要证明 n < M31_P） -/
def nat_to_m31 (n : Nat) (h : n < M31_P) : M31 := ⟨n, h⟩

end PokerLean
