/-!
# 扑克牌（移植自 `poker_lean/PokerLean/State/Card.lean`）

仅移植 Bridge 需要的定义（fromIndex / toIndex）。
-/

namespace TexasPoker

structure Card where
  suit : Nat
  rank : Nat
deriving Repr, DecidableEq

namespace Card

def TWO : Nat := 2

def new (suit rank : Nat) : Card := ⟨suit, rank⟩

/-- 从 0..51 索引构造牌：`⟨idx / 13, (idx % 13) + 2⟩`（与 Rust `from_index` 一致）。 -/
def fromIndex (idx : Nat) : Card :=
  ⟨idx / 13, (idx % 13) + TWO⟩

/-- 转为 0..51 索引：`suit * 13 + (rank - 2)`。 -/
def toIndex (c : Card) : Nat := c.suit * 13 + (c.rank - TWO)

end Card
end TexasPoker
