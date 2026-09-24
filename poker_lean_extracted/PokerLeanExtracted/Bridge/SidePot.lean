import PokerSettlementCore.Funs
import PokerLeanExtracted.Model.SidePot

/-!
# Bridge 等价定理（方案 A1）：提取代码 ≡ 手写模型

`PokerSettlementCore/` 是 Aeneas 从**真实 Rust**（`poker-settlement-core/src/side_pot.rs`）
自动提取的 Lean 纯函数；`Model/` 是 `poker_lean` 手写镜像模型的 Mathlib-free 副本。
本文件逐步建立二者的表示转换与函数等价。

表示对应：
- 提取侧 `Std.U64` / `Std.U16`（UScalar，字段 `bv : BitVec`）↔ 模型侧 `Nat`
- 提取侧 `Result α`（ITree，panic 分支）↔ 模型侧全函数（panic-freedom 由前置保证）

已建立（本文件）：
- Bridge #1 `side_pot_new_ok`：提取 `SidePot::new` ≡ ok 构造（rfl）
- Bridge #2 `seat_bit_equiv`：提取 `seat_bit` ≡ 模型 `seatBit`（`j < 16` 时）

待建立（下一步，见 rust-to-lean-proof-schemes.md）：
- `is_eligible_equiv`、`insert_sorted_u64 ≡ insert_sorted`、
  `sum_bets` / `slice_layer` / `push_or_merge` / `calculate_side_pots` 全函数等价
  （需 Aeneas ITree 单子的 simp 引理集 + Vec ↔ List 表示转换引理）。
-/

namespace TexasPoker.Bridge

open Aeneas Aeneas.Std

/-! ## 表示转换 -/

/-- 提取 `SidePot` → 模型 `SidePot`（U64/U16 → Nat，经 `.bv.toNat`）。 -/
def sidePotToModel (p : poker_settlement_core.side_pot.SidePot) : TexasPoker.SidePot :=
  ⟨p.amount.bv.toNat, p.eligible_seats.bv.toNat⟩

/-! ## Bridge #1：构造函数等价 -/

/-- 提取 `SidePot::new` 即 ok 包装的记录构造（定义性事实，rfl 可证）。 -/
theorem side_pot_new_ok (a : BitVec 64) (e : BitVec 16) :
    poker_settlement_core.side_pot.SidePot.new ⟨a⟩ ⟨e⟩
      = Result.ok { amount := ⟨a⟩, eligible_seats := ⟨e⟩ } := by
  rfl

/-- 转换后与模型 `SidePot.new` 一致（记录级，rfl；与 `side_pot_new_ok` 合起来
即 Bridge #1 的完整内容：提取构造 ≡ ok 构造 ≡ 模型构造）。 -/
theorem side_pot_new_to_model (a : BitVec 64) (e : BitVec 16) :
    sidePotToModel { amount := ⟨a⟩, eligible_seats := ⟨e⟩ } = ⟨a.toNat, e.toNat⟩ := by
  rfl

/-! ## Bridge #2：位掩码工具等价 -/

/-- 提取 `seat_bit` ≡ 模型 `seatBit`（移位不溢出时）。

Rust `1u16 << j` 在 j ≥ 16 时 panic（提取侧 `fail .integerOverflow`），
模型侧（Nat 全函数）无此分支，故要求 `j < 16`。
`2 ^ j` 即模型 `seatBit j = 1 <<< j` 的 Nat 语义。 -/
theorem seat_bit_equiv (j : Nat) (h : j < 16) :
    poker_settlement_core.side_pot.seat_bit ⟨BitVec.ofNat 8 j⟩
      = Result.ok ⟨BitVec.ofNat 16 (2 ^ j)⟩ := by
  have h256 : j < 256 := by omega
  have hv : (⟨BitVec.ofNat 8 j⟩ : U8).val = j := by
    simp [UScalar.val, h256]
  have h1 : (1#u16.bv).toNat = 1 := by rfl
  rw [poker_settlement_core.side_pot.seat_bit]
  simp only [HShiftLeft.hShiftLeft, UScalar.shiftLeft_UScalar, UScalar.shiftLeft, hv,
    show UScalarTy.U16.numBits = 16 from rfl]
  rw [if_pos h, BitVec.shiftLeft, h1, Nat.one_shiftLeft]
  rfl

end TexasPoker.Bridge
