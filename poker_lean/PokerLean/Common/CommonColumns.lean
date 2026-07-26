import PokerLean.Common.M31
import PokerLean.Common.U64Encoding

namespace PokerLean

def COMMON_NUM_COLUMNS : Nat := 37

namespace ColIdx
  def IS_ACTIVE : Nat := 0
  def METHOD_KIND : Nat := 1
  def PRE_STATE_ROOT_BASE : Nat := 2
  def POST_STATE_ROOT_BASE : Nat := 6
  def TABLE_ID_BASE : Nat := 10
  def HAND_ID : Nat := 14
  def CALL_SEQ : Nat := 15
  def PRE_VERSION_BASE : Nat := 16
  def POST_VERSION_BASE : Nat := 20
  def PRE_ROUND_STATE : Nat := 24
  def POST_ROUND_STATE : Nat := 25
  def PRE_POT_BASE : Nat := 26
  def POST_POT_BASE : Nat := 30
  def PRE_BUTTON : Nat := 34
  def POST_BUTTON : Nat := 35
  def IS_PADDING : Nat := 36
end ColIdx

inductive MethodKind where
  | CreateTable        | JoinTable         | LeaveTable
  | StartHand          | Tick              | ResetForNextHand
  | Fold               | Check             | Call
  | Raise              | AutoFold          | ForceFold
  | KickPlayer         | Addon             | Rebuy
  | JoinAndShuffle     | LeaveWithProof    | SubmitShuffleV2
  | SubmitPlayerRevealTokens | SubmitReconstructDeck
  | Bet
deriving Repr, DecidableEq

namespace MethodKind

def toNat : MethodKind → Nat
  | CreateTable => 0 | JoinTable => 1 | LeaveTable => 2
  | StartHand => 3 | Tick => 4 | ResetForNextHand => 5
  | Fold => 6 | Check => 7 | Call => 8
  | Raise => 9 | AutoFold => 10 | ForceFold => 11
  | KickPlayer => 12 | Addon => 13 | Rebuy => 14
  | JoinAndShuffle => 15 | LeaveWithProof => 16 | SubmitShuffleV2 => 17
  | SubmitPlayerRevealTokens => 18 | SubmitReconstructDeck => 19
  | Bet => 20

def lookup (n : Nat) : Option MethodKind :=
  if n = 0 then some CreateTable
  else if n = 1 then some JoinTable
  else if n = 2 then some LeaveTable
  else if n = 3 then some StartHand
  else if n = 4 then some Tick
  else if n = 5 then some ResetForNextHand
  else if n = 6 then some Fold
  else if n = 7 then some Check
  else if n = 8 then some Call
  else if n = 9 then some Raise
  else if n = 10 then some AutoFold
  else if n = 11 then some ForceFold
  else if n = 12 then some KickPlayer
  else if n = 13 then some Addon
  else if n = 14 then some Rebuy
  else if n = 15 then some JoinAndShuffle
  else if n = 16 then some LeaveWithProof
  else if n = 17 then some SubmitShuffleV2
  else if n = 18 then some SubmitPlayerRevealTokens
  else if n = 19 then some SubmitReconstructDeck
  else if n = 20 then some Bet
  else none

theorem lookup_toNat_roundtrip (k : MethodKind) :
  lookup (toNat k) = some k := by
  cases k <;> simp [lookup, toNat] <;> rfl

theorem toNat_lt_M31P (k : MethodKind) : toNat k < M31_P := by
  cases k <;> simp [toNat, M31_P] <;> norm_num

end MethodKind

structure CommonRow where
  is_active : M31
  method_kind : M31
  pre_state_root : M31 × M31 × M31 × M31
  post_state_root : M31 × M31 × M31 × M31
  table_id : M31 × M31 × M31 × M31
  hand_id : M31
  call_seq : M31
  pre_version : M31 × M31 × M31 × M31
  post_version : M31 × M31 × M31 × M31
  pre_round_state : M31
  post_round_state : M31
  pre_pot : M31 × M31 × M31 × M31
  post_pot : M31 × M31 × M31 × M31
  pre_button : M31
  post_button : M31
  is_padding : M31
deriving Repr

namespace CommonRow

def active (kind : MethodKind)
    (pre_sr post_sr : M31 × M31 × M31 × M31)
    (table_id : M31 × M31 × M31 × M31)
    (hand_id call_seq : M31)
    (pre_ver post_ver : M31 × M31 × M31 × M31)
    (pre_rs post_rs : M31)
    (pre_pot post_pot : M31 × M31 × M31 × M31)
    (pre_btn post_btn : M31) : CommonRow :=
  {
    is_active := M31.one
    method_kind := ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩
    pre_state_root := pre_sr
    post_state_root := post_sr
    table_id := table_id
    hand_id := hand_id
    call_seq := call_seq
    pre_version := pre_ver
    post_version := post_ver
    pre_round_state := pre_rs
    post_round_state := post_rs
    pre_pot := pre_pot
    post_pot := post_pot
    pre_button := pre_btn
    post_button := post_btn
    is_padding := M31.zero
  }

def padding : CommonRow :=
  {
    is_active := M31.zero
    method_kind := M31.zero
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.one
  }

end CommonRow

def CommonConstraints (row : CommonRow) (kind : MethodKind) : Prop :=
  (M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero) ∧
  (M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero) ∧
  (M31.mul row.is_active row.is_padding = M31.zero) ∧
  (M31.mul row.is_active
    (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero)

def ActiveRowConstraints (row : CommonRow) (kind : MethodKind) : Prop :=
  row.is_active = M31.one ∧
  row.is_padding = M31.zero ∧
  row.method_kind = ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩

def PaddingRowConstraints (row : CommonRow) : Prop :=
  row.is_active = M31.zero ∧
  row.is_padding = M31.one

lemma mul_zero_y (y : M31) :
  M31.mul M31.zero y = M31.zero := by
  simp [M31.mul, M31.zero, Nat.mul_zero, Nat.zero_mod]

lemma sub_self_eq_zero (x : M31) :
  M31.sub x x = M31.zero := by
  cases x with
  | mk val hval =>
    simp [M31.sub, M31.zero, Subtype.ext_iff, Subtype.val]
    <;> omega

lemma mul_one_sub_one :
  M31.mul M31.one (M31.sub M31.one M31.one) = M31.zero := by
  simp [M31.mul, M31.sub, M31.one, M31.zero, Subtype.ext_iff, Subtype.val]
  <;> ring

lemma mul_zero_sub_one :
  M31.mul M31.zero (M31.sub M31.zero M31.one) = M31.zero := by
  simp [M31.mul, M31.zero, Subtype.ext_iff, Subtype.val, Nat.mul_zero, Nat.zero_mod]

lemma mul_sub_one_eq_zero (x : M31) (h : x = M31.one) :
  M31.mul x (M31.sub x M31.one) = M31.zero := by
  rw [h]
  exact mul_one_sub_one

lemma mul_sub_zero_eq_zero (x : M31) (h : x = M31.zero) :
  M31.mul x (M31.sub x M31.one) = M31.zero := by
  rw [h]
  exact mul_zero_sub_one

lemma mul_sub_one_self_eq_zero (x : M31) (h : x = M31.one) :
  M31.mul x (M31.sub x M31.one) = M31.zero := mul_sub_one_eq_zero x h

lemma mul_sub_zero_self_eq_zero (x : M31) (h : x = M31.zero) :
  M31.mul x (M31.sub x M31.one) = M31.zero := mul_sub_zero_eq_zero x h

theorem active_row_satisfies_common (row : CommonRow) (kind : MethodKind)
    (h : ActiveRowConstraints row kind) :
  CommonConstraints row kind := by
  unfold ActiveRowConstraints at h
  rcases h with ⟨h_active, h_padding, h_kind⟩
  have hA : M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero := by
    simp [h_active]
    exact mul_one_sub_one
  have hB : M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero := by
    simp [h_padding]
    exact mul_zero_sub_one
  have hC : M31.mul row.is_active row.is_padding = M31.zero := by
    rw [h_padding]
    apply M31.mul_zero_right
  have hD : M31.mul row.is_active
      (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero := by
    have h_diff : M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩ = M31.zero := by
      rw [h_kind]
      apply sub_self_eq_zero
    rw [h_diff]
    apply M31.mul_zero_right
  unfold CommonConstraints
  exact ⟨hA, hB, hC, hD⟩

theorem padding_row_satisfies_common (row : CommonRow) (kind : MethodKind)
    (h : PaddingRowConstraints row) :
  CommonConstraints row kind := by
  unfold PaddingRowConstraints at h
  rcases h with ⟨h_active, h_padding⟩
  have hA : M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero := by
    simp [h_active]
    exact mul_zero_sub_one
  have hB : M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero := by
    simp [h_padding]
    exact mul_one_sub_one
  have hC : M31.mul row.is_active row.is_padding = M31.zero := by
    rw [h_active]
    apply M31.mul_zero_left
  have hD : M31.mul row.is_active
      (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero := by
    simp [h_active]
    apply M31.mul_zero_y
  unfold CommonConstraints
  exact ⟨hA, hB, hC, hD⟩

end PokerLean