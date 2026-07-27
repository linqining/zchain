import Mathlib

/-!
# 扑克牌数据结构（镜像 `poker_l1/src/vm/contracts/texas_poker/card.rs`）

`Card` 使用 table.move 编码：suit 0-3, rank 2-14。
与 Rust `Card` struct（`card.rs:40-46`）逐字段一致。
-/

namespace TexasPoker

/-! ## 花色常量（对应 `card.rs:14-19`，table.move 编码）-/

def SPADES   : Nat := 0
def HEARTS   : Nat := 1
def DIAMONDS : Nat := 2
def CLUBS    : Nat := 3

/-! ## 点数常量（对应 `card.rs:22-35`）-/

def TWO   : Nat := 2
def THREE : Nat := 3
def FOUR  : Nat := 4
def FIVE  : Nat := 5
def SIX   : Nat := 6
def SEVEN : Nat := 7
def EIGHT : Nat := 8
def NINE  : Nat := 9
def TEN   : Nat := 10
def JACK  : Nat := 11
def QUEEN : Nat := 12
def KING  : Nat := 13
def ACE   : Nat := 14

/-- 主牌结构（table.move 编码：suit 0-3, rank 2-14）。

对应 Rust `Card` struct（`card.rs:40-46`）。 -/
structure Card where
  /-- 花色：0=SPADES, 1=HEARTS, 2=DIAMONDS, 3=CLUBS。 -/
  suit : Nat
  /-- 点数：2..=14（2-10, 11=J, 12=Q, 13=K, 14=A）。 -/
  rank : Nat
deriving Repr, DecidableEq

namespace Card

/-- 构造新牌。对应 `card.rs:50-53` `Card::new`。 -/
def new (suit rank : Nat) : Card := ⟨suit, rank⟩

/-- 校验牌的合法性。对应 `card.rs:56-58` `Card::is_valid`。 -/
def isValid (c : Card) : Bool :=
  c.suit ≤ CLUBS ∧ TWO ≤ c.rank ∧ c.rank ≤ ACE

/-- 转为 0..51 索引（suit * 13 + (rank - 2)）。对应 `card.rs:62-64` `to_index`。 -/
def toIndex (c : Card) : Nat := c.suit * 13 + (c.rank - TWO)

/-- 从 0..51 索引构造牌。对应 `card.rs:68-74` `from_index`。 -/
def fromIndex (idx : Nat) : Card :=
  ⟨idx / 13, (idx % 13) + TWO⟩

/-! ## 常量值引理（便于 simp/omega 展开）-/

@[simp] theorem SPADES_eq : SPADES = 0 := rfl
@[simp] theorem HEARTS_eq : HEARTS = 1 := rfl
@[simp] theorem DIAMONDS_eq : DIAMONDS = 2 := rfl
@[simp] theorem CLUBS_eq : CLUBS = 3 := rfl
@[simp] theorem TWO_eq : TWO = 2 := rfl
@[simp] theorem ACE_eq : ACE = 14 := rfl

/-! ## 合法性引理 -/

theorem isValid_spades_ace : (new SPADES ACE).isValid = true := by
  simp [isValid, new]

theorem isValid_clubs_two : (new CLUBS TWO).isValid = true := by
  simp [isValid, new]

theorem isValid_invalid_suit : (new 4 ACE).isValid = false := by
  simp [isValid, new, CLUBS]

theorem isValid_invalid_rank_low : (new SPADES 1).isValid = false := by
  simp [isValid, new, TWO]

theorem isValid_invalid_rank_high : (new SPADES 15).isValid = false := by
  simp [isValid, new, ACE]

/-! ## 索引往返引理 -/

/-- `to_index` / `from_index` 对合法索引往返一致。对应 `card.rs:180-186` 测试。 -/
theorem toIndex_fromIndex (idx : Nat) (h : idx < 52) :
    (fromIndex idx).toIndex = idx := by
  simp [toIndex, fromIndex, TWO]
  omega

/-- 合法牌的索引 < 52。 -/
theorem toIndex_lt_52 (c : Card) (h : c.isValid = true) : c.toIndex < 52 := by
  simp [isValid, toIndex, TWO] at h
  obtain ⟨hs, hrl, hrh⟩ := h
  simp [toIndex, TWO]
  omega

end Card

end TexasPoker
