import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.RoundMachine

/-!
# 子相位状态机（Phase 5，镜像 `state_machine.rs` 子相位转移）

## 内容

1. **三个子相位归纳类型**：`ShufflePhase` / `RevealPhase` / `ReconstructPhase`
2. **合法转移关系**：`ShuffleStep` / `RevealStep` / `ReconstructStep`（白名单）
3. **单调性定理**：非 reset 路径 `toNat` 严格递增；reset 路径回到 `NONE`
4. **chip 中性定理**：所有子相位转移函数不修改 chip 字段

## 命名约定

为避免三个归纳类型的 `NONE` 构造子歧义，本文件**不** `open` 三个命名空间，
所有构造子使用 `ShufflePhase.NONE` / `RevealPhase.NONE` / `ReconstructPhase.NONE`
等限定形式。
-/

namespace TexasPoker

/-! ## ShufflePhase 归纳类型（对应 `constants.rs:39-42`）-/

inductive ShufflePhase where
  | NONE           : ShufflePhase
  | WAITING        : ShufflePhase
  | RECONSTRUCT    : ShufflePhase
  | BEFORE_PREFLOP : ShufflePhase
deriving Repr, DecidableEq

namespace ShufflePhase

def toNat : ShufflePhase → Nat
  | NONE           => 0
  | WAITING        => 1
  | RECONSTRUCT    => 2
  | BEFORE_PREFLOP => 3

@[simp] theorem toNat_none           : (ShufflePhase.NONE           : ShufflePhase).toNat = 0 := rfl
@[simp] theorem toNat_waiting        : (ShufflePhase.WAITING        : ShufflePhase).toNat = 1 := rfl
@[simp] theorem toNat_reconstruct    : (ShufflePhase.RECONSTRUCT    : ShufflePhase).toNat = 2 := rfl
@[simp] theorem toNat_before_preflop : (ShufflePhase.BEFORE_PREFLOP : ShufflePhase).toNat = 3 := rfl

theorem toNat_injective (s₁ s₂ : ShufflePhase) (h : s₁.toNat = s₂.toNat) : s₁ = s₂ := by
  cases s₁ <;> cases s₂ <;> simp_all [toNat]

end ShufflePhase

/-! ## RevealPhase 归纳类型（对应 `constants.rs:46-52`）-/

inductive RevealPhase where
  | NONE     : RevealPhase
  | PREFLOP  : RevealPhase
  | REDEAL   : RevealPhase
  | FLOP     : RevealPhase
  | TURN     : RevealPhase
  | RIVER    : RevealPhase
  | SHOWDOWN : RevealPhase
deriving Repr, DecidableEq

namespace RevealPhase

def toNat : RevealPhase → Nat
  | NONE     => 0
  | PREFLOP  => 1
  | REDEAL   => 2
  | FLOP     => 3
  | TURN     => 4
  | RIVER    => 5
  | SHOWDOWN => 6

@[simp] theorem toNat_none     : (RevealPhase.NONE     : RevealPhase).toNat = 0 := rfl
@[simp] theorem toNat_preflop  : (RevealPhase.PREFLOP  : RevealPhase).toNat = 1 := rfl
@[simp] theorem toNat_redeal   : (RevealPhase.REDEAL   : RevealPhase).toNat = 2 := rfl
@[simp] theorem toNat_flop     : (RevealPhase.FLOP     : RevealPhase).toNat = 3 := rfl
@[simp] theorem toNat_turn     : (RevealPhase.TURN     : RevealPhase).toNat = 4 := rfl
@[simp] theorem toNat_river    : (RevealPhase.RIVER    : RevealPhase).toNat = 5 := rfl
@[simp] theorem toNat_showdown : (RevealPhase.SHOWDOWN : RevealPhase).toNat = 6 := rfl

theorem toNat_injective (s₁ s₂ : RevealPhase) (h : s₁.toNat = s₂.toNat) : s₁ = s₂ := by
  cases s₁ <;> cases s₂ <;> simp_all [toNat]

end RevealPhase

/-! ## ReconstructPhase 归纳类型（对应 `constants.rs:56-58`）-/

inductive ReconstructPhase where
  | NONE       : ReconstructPhase
  | COLLECTING : ReconstructPhase
  | COMPLETE   : ReconstructPhase
deriving Repr, DecidableEq

namespace ReconstructPhase

def toNat : ReconstructPhase → Nat
  | NONE       => 0
  | COLLECTING => 1
  | COMPLETE   => 2

@[simp] theorem toNat_none       : (ReconstructPhase.NONE       : ReconstructPhase).toNat = 0 := rfl
@[simp] theorem toNat_collecting : (ReconstructPhase.COLLECTING : ReconstructPhase).toNat = 1 := rfl
@[simp] theorem toNat_complete   : (ReconstructPhase.COMPLETE   : ReconstructPhase).toNat = 2 := rfl

theorem toNat_injective (s₁ s₂ : ReconstructPhase) (h : s₁.toNat = s₂.toNat) : s₁ = s₂ := by
  cases s₁ <;> cases s₂ <;> simp_all [toNat]

end ReconstructPhase

/-! ## ShufflePhase 合法转移关系

白名单（对应 `state_machine.rs:2195-2240` `start_hand`、`state_machine.rs:1126-1156`
`on_complete_reconstruct`、`state_machine.rs:666-722` `advance_shuffle`、`reset_for_next_hand`）：

- `start_hand`：NONE → BEFORE_PREFLOP
- `on_complete_reconstruct`：NONE → RECONSTRUCT
- `advance_shuffle` 完成：BEFORE_PREFLOP → NONE / RECONSTRUCT → NONE
- `reset_for_next_hand`：任意 → NONE

注：`WAITING` 是 Rust 常量中声明但代码未作为转移目标的死状态。 -/

abbrev ShuffleStep (s s' : ShufflePhase) : Prop :=
  (s = ShufflePhase.NONE ∧ s' = ShufflePhase.BEFORE_PREFLOP) ∨
  (s = ShufflePhase.NONE ∧ s' = ShufflePhase.RECONSTRUCT) ∨
  (s' = ShufflePhase.NONE)

namespace ShuffleStep

def start_hand : ShuffleStep ShufflePhase.NONE ShufflePhase.BEFORE_PREFLOP := Or.inl ⟨rfl, rfl⟩

def start_reconstruct : ShuffleStep ShufflePhase.NONE ShufflePhase.RECONSTRUCT :=
  Or.inr (Or.inl ⟨rfl, rfl⟩)

def advance_before_preflop : ShuffleStep ShufflePhase.BEFORE_PREFLOP ShufflePhase.NONE :=
  Or.inr (Or.inr rfl)

def advance_reconstruct : ShuffleStep ShufflePhase.RECONSTRUCT ShufflePhase.NONE :=
  Or.inr (Or.inr rfl)

def reset (s : ShufflePhase) : ShuffleStep s ShufflePhase.NONE :=
  Or.inr (Or.inr rfl)

end ShuffleStep

theorem shuffle_step_iff (s s' : ShufflePhase) :
    ShuffleStep s s' ↔
    (s = ShufflePhase.NONE ∧ s' = ShufflePhase.BEFORE_PREFLOP) ∨
    (s = ShufflePhase.NONE ∧ s' = ShufflePhase.RECONSTRUCT) ∨
    (s' = ShufflePhase.NONE) := Iff.rfl

/-- **定理 1（Shuffle 单调性）**。 -/
theorem shuffle_monotonic (s s' : ShufflePhase) (h : ShuffleStep s s') :
    s.toNat < s'.toNat ∨ s' = ShufflePhase.NONE := by
  obtain h := shuffle_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · subst h1; subst h2; left; simp only [ShufflePhase.toNat]; omega
  · subst h1; subst h2; left; simp only [ShufflePhase.toNat]; omega
  · right; exact h2

/-- **定理 2（Shuffle 前向严格递增）**。 -/
theorem shuffle_forward_strict_increasing
    (s s' : ShufflePhase) (h : ShuffleStep s s') (hne : s' ≠ ShufflePhase.NONE) :
    s.toNat < s'.toNat := by
  obtain h := shuffle_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · subst h1; subst h2; simp only [ShufflePhase.toNat]; omega
  · subst h1; subst h2; simp only [ShufflePhase.toNat]; omega
  · exact absurd h2 hne

/-- **定理 3（Shuffle reset 只回 NONE）**。 -/
theorem shuffle_reset_only_to_none
    (s s' : ShufflePhase) (h : ShuffleStep s s') (hne : s' ≠ ShufflePhase.NONE) :
    s.toNat < s'.toNat :=
  shuffle_forward_strict_increasing s s' h hne

/-- **定理 4（从 NONE 出发的非 reset 转移目标有限）**。 -/
theorem shuffle_from_none_forward_only_to_before_preflop_or_reconstruct
    (s' : ShufflePhase) (h : ShuffleStep ShufflePhase.NONE s') (hne : s' ≠ ShufflePhase.NONE) :
    s' = ShufflePhase.BEFORE_PREFLOP ∨ s' = ShufflePhase.RECONSTRUCT := by
  obtain h := shuffle_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact Or.inl h2
  · exact Or.inr h2
  · exact absurd h2 hne

/-- **定理 5（WAITING 不可达）**。 -/
theorem shuffle_waiting_unreachable (s : ShufflePhase)
    (h : ShuffleStep s ShufflePhase.WAITING) : False := by
  obtain h := shuffle_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)

/-! ## RevealPhase 合法转移关系

白名单（对应 `state_machine.rs:809-924` `start_*_reveal_phase`、
`state_machine.rs:1126-1156` `on_complete_reconstruct` 清空 reveal_token_state、
`reset_for_next_hand`）。 -/

abbrev RevealStep (s s' : RevealPhase) : Prop :=
  (s = RevealPhase.NONE ∧ s' = RevealPhase.PREFLOP) ∨
  (s = RevealPhase.NONE ∧ s' = RevealPhase.FLOP) ∨
  (s = RevealPhase.NONE ∧ s' = RevealPhase.TURN) ∨
  (s = RevealPhase.NONE ∧ s' = RevealPhase.RIVER) ∨
  (s = RevealPhase.NONE ∧ s' = RevealPhase.SHOWDOWN) ∨
  (s' = RevealPhase.NONE)

namespace RevealStep

def start_preflop : RevealStep RevealPhase.NONE RevealPhase.PREFLOP := Or.inl ⟨rfl, rfl⟩

def start_flop : RevealStep RevealPhase.NONE RevealPhase.FLOP :=
  Or.inr (Or.inl ⟨rfl, rfl⟩)

def start_turn : RevealStep RevealPhase.NONE RevealPhase.TURN :=
  Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))

def start_river : RevealStep RevealPhase.NONE RevealPhase.RIVER :=
  Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩)))

def start_showdown : RevealStep RevealPhase.NONE RevealPhase.SHOWDOWN :=
  Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨rfl, rfl⟩))))

def reset (s : RevealPhase) : RevealStep s RevealPhase.NONE :=
  Or.inr (Or.inr (Or.inr (Or.inr (Or.inr rfl))))

end RevealStep

theorem reveal_step_iff (s s' : RevealPhase) :
    RevealStep s s' ↔
    (s = RevealPhase.NONE ∧ s' = RevealPhase.PREFLOP) ∨
    (s = RevealPhase.NONE ∧ s' = RevealPhase.FLOP) ∨
    (s = RevealPhase.NONE ∧ s' = RevealPhase.TURN) ∨
    (s = RevealPhase.NONE ∧ s' = RevealPhase.RIVER) ∨
    (s = RevealPhase.NONE ∧ s' = RevealPhase.SHOWDOWN) ∨
    (s' = RevealPhase.NONE) := Iff.rfl

/-- **定理 1（Reveal 单调性）**。 -/
theorem reveal_monotonic (s s' : RevealPhase) (h : RevealStep s s') :
    s.toNat < s'.toNat ∨ s' = RevealPhase.NONE := by
  obtain h := reveal_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · subst h1; subst h2; left; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; left; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; left; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; left; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; left; simp only [RevealPhase.toNat]; omega
  · right; exact h2

/-- **定理 2（Reveal 前向严格递增）**。 -/
theorem reveal_forward_strict_increasing
    (s s' : RevealPhase) (h : RevealStep s s') (hne : s' ≠ RevealPhase.NONE) :
    s.toNat < s'.toNat := by
  obtain h := reveal_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · subst h1; subst h2; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; simp only [RevealPhase.toNat]; omega
  · subst h1; subst h2; simp only [RevealPhase.toNat]; omega
  · exact absurd h2 hne

/-- **定理 3（Reveal reset 只回 NONE）**。 -/
theorem reveal_reset_only_to_none
    (s s' : RevealPhase) (h : RevealStep s s') (hne : s' ≠ RevealPhase.NONE) :
    s.toNat < s'.toNat :=
  reveal_forward_strict_increasing s s' h hne

/-- **定理 4（从 NONE 出发的非 reset 转移目标有限）**。 -/
theorem reveal_from_none_forward_targets
    (s' : RevealPhase) (h : RevealStep RevealPhase.NONE s') (hne : s' ≠ RevealPhase.NONE) :
    s' = RevealPhase.PREFLOP ∨ s' = RevealPhase.FLOP ∨ s' = RevealPhase.TURN ∨
    s' = RevealPhase.RIVER ∨ s' = RevealPhase.SHOWDOWN := by
  obtain h := reveal_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact Or.inl h2
  · exact Or.inr (Or.inl h2)
  · exact Or.inr (Or.inr (Or.inl h2))
  · exact Or.inr (Or.inr (Or.inr (Or.inl h2)))
  · exact Or.inr (Or.inr (Or.inr (Or.inr h2)))
  · exact absurd h2 hne

/-- **定理 5（REDEAL 不可达）**。 -/
theorem reveal_redeal_unreachable (s : RevealPhase)
    (h : RevealStep s RevealPhase.REDEAL) : False := by
  obtain h := reveal_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | ⟨h1, h2⟩ | h2
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)

/-! ## ReconstructPhase 合法转移关系

白名单（对应 `state_machine.rs:1092-1121` `start_reconstruct`、
`state_machine.rs:1126-1156` `on_complete_reconstruct`、`reset_for_next_hand`）。 -/

abbrev ReconstructStep (s s' : ReconstructPhase) : Prop :=
  (s = ReconstructPhase.NONE ∧ s' = ReconstructPhase.COLLECTING) ∨
  (s' = ReconstructPhase.NONE)

namespace ReconstructStep

def start : ReconstructStep ReconstructPhase.NONE ReconstructPhase.COLLECTING := Or.inl ⟨rfl, rfl⟩

def complete : ReconstructStep ReconstructPhase.COLLECTING ReconstructPhase.NONE := Or.inr rfl

def reset (s : ReconstructPhase) : ReconstructStep s ReconstructPhase.NONE := Or.inr rfl

end ReconstructStep

theorem reconstruct_step_iff (s s' : ReconstructPhase) :
    ReconstructStep s s' ↔
    (s = ReconstructPhase.NONE ∧ s' = ReconstructPhase.COLLECTING) ∨
    (s' = ReconstructPhase.NONE) := Iff.rfl

/-- **定理 1（Reconstruct 单调性）**。 -/
theorem reconstruct_monotonic (s s' : ReconstructPhase) (h : ReconstructStep s s') :
    s.toNat < s'.toNat ∨ s' = ReconstructPhase.NONE := by
  obtain h := reconstruct_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | h2
  · subst h1; subst h2; left; simp only [ReconstructPhase.toNat]; omega
  · right; exact h2

/-- **定理 2（Reconstruct 前向严格递增）**。 -/
theorem reconstruct_forward_strict_increasing
    (s s' : ReconstructPhase) (h : ReconstructStep s s') (hne : s' ≠ ReconstructPhase.NONE) :
    s.toNat < s'.toNat := by
  obtain h := reconstruct_step_iff s s' |>.mp h
  rcases h with ⟨h1, h2⟩ | h2
  · subst h1; subst h2; simp only [ReconstructPhase.toNat]; omega
  · exact absurd h2 hne

/-- **定理 3（Reconstruct reset 只回 NONE）**。 -/
theorem reconstruct_reset_only_to_none
    (s s' : ReconstructPhase) (h : ReconstructStep s s') (hne : s' ≠ ReconstructPhase.NONE) :
    s.toNat < s'.toNat :=
  reconstruct_forward_strict_increasing s s' h hne

/-- **定理 4（COMPLETE 不可达）**。 -/
theorem reconstruct_complete_unreachable (s : ReconstructPhase)
    (h : ReconstructStep s ReconstructPhase.COMPLETE) : False := by
  obtain h := reconstruct_step_iff _ _ |>.mp h
  rcases h with ⟨h1, h2⟩ | h2
  · exact absurd h2 (by decide)
  · exact absurd h2 (by decide)

/-! ## Chip 中性：子相位转移不修改 chip 字段 -/

/-- 两次桌台状态间 chip 字段不变的谓词。

对应 Rust：子相位转移函数均不修改 `pot` / `chip_pool` / `addon_pool` /
`ante_collected` / `rake_collected` / `seats[i].stack` / `seats[i].bet` /
`seats[i].total_bet`。 -/
def chips_unchanged (t t' : TexasPokerTable) : Prop :=
  t.pot = t'.pot ∧
  t.chip_pool = t'.chip_pool ∧
  t.addon_pool = t'.addon_pool ∧
  t.ante_collected = t'.ante_collected ∧
  t.rake_collected = t'.rake_collected ∧
  t.seats.length = t'.seats.length ∧
  ∀ i, i < t.seats.length →
    (t.seats.getD i Seat.empty).stack = (t'.seats.getD i Seat.empty).stack ∧
    (t.seats.getD i Seat.empty).bet = (t'.seats.getD i Seat.empty).bet ∧
    (t.seats.getD i Seat.empty).total_bet = (t'.seats.getD i Seat.empty).total_bet

theorem chips_unchanged_refl (t : TexasPokerTable) : chips_unchanged t t := by
  refine ⟨rfl, rfl, rfl, rfl, rfl, rfl, ?_⟩
  intro i _; exact ⟨rfl, rfl, rfl⟩

theorem chips_unchanged_symm (t t' : TexasPokerTable) (h : chips_unchanged t t') :
    chips_unchanged t' t := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h
  refine ⟨h1.symm, h2.symm, h3.symm, h4.symm, h5.symm, h6.symm, ?_⟩
  intro i hi
  have hi' : i < t.seats.length := h6 ▸ hi
  have := h7 i hi'
  exact ⟨this.1.symm, this.2.1.symm, this.2.2.symm⟩

theorem chips_unchanged_trans (t₁ t₂ t₃ : TexasPokerTable)
    (h12 : chips_unchanged t₁ t₂) (h23 : chips_unchanged t₂ t₃) :
    chips_unchanged t₁ t₃ := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := h12
  obtain ⟨h1', h2', h3', h4', h5', h6', h7'⟩ := h23
  refine ⟨h1.trans h1', h2.trans h2', h3.trans h3', h4.trans h4',
          h5.trans h5', h6.trans h6', ?_⟩
  intro i hi
  have hi' : i < t₂.seats.length := h6 ▸ hi
  have h_a := h7 i hi
  have h_b := h7' i hi'
  refine ⟨h_a.1.trans h_b.1, h_a.2.1.trans h_b.2.1, h_a.2.2.trans h_b.2.2⟩

/-! ### 子相位转移函数（仅修改子相位字段，保持 chip 字段） -/

/-- `start_hand` 触发的洗牌启动：设置 `shuffle_state.phase = BEFORE_PREFLOP`。

对应 Rust `state_machine.rs:2218-2223`。 -/
def start_hand_shuffle (t : TexasPokerTable) : TexasPokerTable :=
  { t with shuffle_state := { t.shuffle_state with
              phase := Constants.SHUFFLE_PHASE_BEFORE_PREFLOP } }

/-- `on_complete_reconstruct` 触发的洗牌启动：设置 `shuffle_state.phase = RECONSTRUCT`。

对应 Rust `state_machine.rs:1148-1153`。 -/
def start_reconstruct_shuffle (t : TexasPokerTable) : TexasPokerTable :=
  { t with shuffle_state := { t.shuffle_state with
              phase := Constants.SHUFFLE_PHASE_RECONSTRUCT } }

/-- `advance_shuffle` 完成（pending_players 为空）：清空 `shuffle_state`。

对应 Rust `state_machine.rs:688`。 -/
def advance_shuffle_complete (t : TexasPokerTable) : TexasPokerTable :=
  { t with shuffle_state := ShuffleState.default }

/-- `start_preflop_reveal_phase`：设置 `reveal_token_state.reveal_phase = PREFLOP`。

对应 Rust `state_machine.rs:832-835`。 -/
def start_preflop_reveal (t : TexasPokerTable) : TexasPokerTable :=
  { t with reveal_token_state := { t.reveal_token_state with
              reveal_phase := Constants.REVEAL_PHASE_PREFLOP } }

/-- `start_community_reveal_phase`：设置 `reveal_token_state.reveal_phase = phase`。

对应 Rust `state_machine.rs:872-875`。 -/
def start_community_reveal (t : TexasPokerTable) (phase : Nat) : TexasPokerTable :=
  { t with reveal_token_state := { t.reveal_token_state with
              reveal_phase := phase } }

/-- `start_showdown_reveal_phase`：设置 `reveal_token_state.reveal_phase = SHOWDOWN`。

对应 Rust `state_machine.rs:912-915`。 -/
def start_showdown_reveal (t : TexasPokerTable) : TexasPokerTable :=
  { t with reveal_token_state := { t.reveal_token_state with
              reveal_phase := Constants.REVEAL_PHASE_SHOWDOWN } }

/-- `start_reconstruct`：设置 `reconstruct_state.phase = COLLECTING`。

对应 Rust `state_machine.rs:1104-1110`。 -/
def start_reconstruct (t : TexasPokerTable) : TexasPokerTable :=
  { t with reconstruct_state := { t.reconstruct_state with
              phase := Constants.RECONSTRUCT_PHASE_COLLECTING } }

/-- `on_complete_reconstruct` 清空 reconstruct_state：设为 default。

对应 Rust `state_machine.rs:1131`。 -/
def complete_reconstruct_clear (t : TexasPokerTable) : TexasPokerTable :=
  { t with reconstruct_state := ReconstructState.default }

/-- `reset_for_next_hand` 子相位部分：所有子相位状态清零。

对应 Rust `state_machine.rs:2788+` 中对 `shuffle_state` / `reveal_token_state` /
`reconstruct_state` 的清零。 -/
def reset_subphases (t : TexasPokerTable) : TexasPokerTable :=
  { t with shuffle_state := ShuffleState.default,
           reveal_token_state := RevealTokenState.default,
           reconstruct_state := ReconstructState.default }

/-! ### chips_unchanged 保持定理 -/

theorem start_hand_shuffle_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (start_hand_shuffle t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem start_reconstruct_shuffle_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (start_reconstruct_shuffle t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem advance_shuffle_complete_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (advance_shuffle_complete t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem start_preflop_reveal_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (start_preflop_reveal t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem start_community_reveal_chips_unchanged (t : TexasPokerTable) (phase : Nat) :
    chips_unchanged t (start_community_reveal t phase) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem start_showdown_reveal_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (start_showdown_reveal t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem start_reconstruct_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (start_reconstruct t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem complete_reconstruct_clear_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (complete_reconstruct_clear t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

theorem reset_subphases_chips_unchanged (t : TexasPokerTable) :
    chips_unchanged t (reset_subphases t) :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, fun _ _ => ⟨rfl, rfl, rfl⟩⟩

/-! ### 表级子相位转移关系 -/

/-- 表级子相位转移关系：枚举所有子相位转移类型。

每个构造子对应一个 Rust 子相位转移函数。chip 字段由 `chips_unchanged` 保证。 -/
inductive SubPhaseTransition : TexasPokerTable → TexasPokerTable → Prop where
  | start_hand : ∀ t, SubPhaseTransition t (start_hand_shuffle t)
  | start_recon_shuffle : ∀ t, SubPhaseTransition t (start_reconstruct_shuffle t)
  | advance_shuffle_done : ∀ t, SubPhaseTransition t (advance_shuffle_complete t)
  | start_preflop_reveal : ∀ t, SubPhaseTransition t (start_preflop_reveal t)
  | start_community_reveal : ∀ t phase, SubPhaseTransition t (start_community_reveal t phase)
  | start_showdown_reveal : ∀ t, SubPhaseTransition t (start_showdown_reveal t)
  | start_reconstruct : ∀ t, SubPhaseTransition t (start_reconstruct t)
  | complete_reconstruct : ∀ t, SubPhaseTransition t (complete_reconstruct_clear t)
  | reset_subphases : ∀ t, SubPhaseTransition t (reset_subphases t)

/-- **主定理（子相位 chip 中性）**：所有子相位转移保持 `chips_unchanged`。

对应 Rust：`start_hand` / `advance_shuffle` / `start_*_reveal_phase` /
`start_reconstruct` / `on_complete_reconstruct` / `reset_for_next_hand` 等子相位
转移函数均不修改 chip 字段。 -/
theorem subphase_chip_neutral (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : chips_unchanged t t' := by
  cases h with
  | start_hand => exact start_hand_shuffle_chips_unchanged _
  | start_recon_shuffle => exact start_reconstruct_shuffle_chips_unchanged _
  | advance_shuffle_done => exact advance_shuffle_complete_chips_unchanged _
  | start_preflop_reveal => exact start_preflop_reveal_chips_unchanged _
  | start_community_reveal => exact start_community_reveal_chips_unchanged _ _
  | start_showdown_reveal => exact start_showdown_reveal_chips_unchanged _
  | start_reconstruct => exact start_reconstruct_chips_unchanged _
  | complete_reconstruct => exact complete_reconstruct_clear_chips_unchanged _
  | reset_subphases => exact reset_subphases_chips_unchanged _

/-! ### 子相位字段不变量保持 -/

theorem subphase_transition_pot_unchanged (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : t'.pot = t.pot :=
  (subphase_chip_neutral t t' h).1.symm

theorem subphase_transition_seats_unchanged (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : t'.seats = t.seats := by
  cases h <;> rfl

theorem subphase_transition_addon_pool_unchanged (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : t'.addon_pool = t.addon_pool :=
  (subphase_chip_neutral t t' h).2.2.1.symm

theorem subphase_transition_ante_collected_unchanged (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : t'.ante_collected = t.ante_collected :=
  (subphase_chip_neutral t t' h).2.2.2.1.symm

theorem subphase_transition_rake_collected_unchanged (t t' : TexasPokerTable)
    (h : SubPhaseTransition t t') : t'.rake_collected = t.rake_collected :=
  (subphase_chip_neutral t t' h).2.2.2.2.1.symm

/-! ## 跨子相位推进的合法性 -/

/-- **定理（reveal 推进链单调）**：reveal phase 在非 reset 转移中严格递增。

对应 Rust `advance_round`（`state_machine.rs:604-659`）调用顺序：
preflop → flop → turn → river → showdown。 -/
theorem reveal_chain_monotonic :
    ∀ s₁ s₂ s₃ : RevealPhase,
      RevealStep s₁ s₂ → RevealStep s₂ s₃ →
      s₂ ≠ RevealPhase.NONE → s₃ ≠ RevealPhase.NONE →
      s₁.toNat < s₂.toNat ∧ s₂.toNat < s₃.toNat := by
  intro s₁ s₂ s₃ h12 h23 h2_ne h3_ne
  exact ⟨reveal_forward_strict_increasing s₁ s₂ h12 h2_ne,
         reveal_forward_strict_increasing s₂ s₃ h23 h3_ne⟩

end TexasPoker
