import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.MoreActions
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 更多动作方法的 AIR 形式化 -/

/-- AutoFold 业务列 -/
structure AutoFoldMethodColumns where
  input_seat_index : M31
  input_current_time : M31 × M31 × M31 × M31
  output_folded : M31
deriving Repr

def AutoFoldMethodConstraints
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_time.1 = ⟨expected_current_time % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_folded = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  PotUnchangedLimb0 row

def AutoFoldAirAcceptable
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    : Prop :=
  CommonConstraints row MethodKind.AutoFold ∧
  AutoFoldMethodConstraints row ext expected_seat_index hlt expected_current_time ∧
  row.method_kind = ⟨MethodKind.AutoFold.toNat, MethodKind.toNat_lt_M31P MethodKind.AutoFold⟩ ∧
  row.is_active = M31.one

/-- ForceFold 业务列 -/
structure ForceFoldMethodColumns where
  input_seat_index : M31
  output_folded : M31
deriving Repr

def ForceFoldMethodConstraints
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.output_folded = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  PotUnchangedLimb0 row

def ForceFoldAirAcceptable
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.ForceFold ∧
  ForceFoldMethodConstraints row ext expected_seat_index hlt ∧
  row.method_kind = ⟨MethodKind.ForceFold.toNat, MethodKind.toNat_lt_M31P MethodKind.ForceFold⟩ ∧
  row.is_active = M31.one

/-- KickPlayer 业务列 -/
structure KickPlayerMethodColumns where
  input_seat_index : M31
  output_refund : M31 × M31 × M31 × M31
  output_kicked : M31
deriving Repr

def KickPlayerMethodConstraints
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.output_refund.1 = ⟨expected_refund % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_kicked = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row

def KickPlayerAirAcceptable
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    : Prop :=
  CommonConstraints row MethodKind.KickPlayer ∧
  KickPlayerMethodConstraints row ext expected_seat_index hlt expected_refund ∧
  row.method_kind = ⟨MethodKind.KickPlayer.toNat, MethodKind.toNat_lt_M31P MethodKind.KickPlayer⟩ ∧
  row.is_active = M31.one

/-- 通用提取函数（三种方法共享） -/
def extractPreTableFromActionAir
    (row : CommonRow)
    (max_players : Nat)
    (mk : MethodKind)
    : TexasPokerTable := {
  table_id := 0
  name_hash := 0
  seats := List.replicate max_players Seat.empty
  max_players := max_players
  small_blind := 0
  big_blind := 0
  ante := 0
  version := decodeU64 row.pre_version.1 row.pre_version.2.1
      row.pre_version.2.2.1 row.pre_version.2.2.2
  round_state := RoundState.fromNat row.pre_round_state.val
  betting := {
    current_bet := 0
    current_turn := 0
    dealer_seat := row.pre_button.val
    pot := decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2
    side_pots := []
    min_raise := 0
    last_aggressor := 0
    num_raises := 0
  }
  shuffle_state := { phase := 0, current_shuffler := none, pending_players := [], completed_players := [] }
  reveal_state := { reveal_phase := 0, num_assignments := 0 }
  deck_state := DeckState.DeckIdle
  reconstruct_state := ReconstructState.ReconstructIdle
  hand_id := row.hand_id.val
  call_seq := row.call_seq.val
  chip_pool := 0
  addon_pool := 0
  pending_addon_total := 0
  pending_rebuy_total := 0
  rake := 0
  table_fee := 0
  is_private := false
  started_at := 0
  timeout := 0
  last_action_time := 0
}

def extractPostTableFromActionAir
    (row : CommonRow)
    (max_players : Nat)
    (mk : MethodKind)
    : TexasPokerTable :=
  let pre := extractPreTableFromActionAir row max_players mk
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    betting := {
      pre.betting with
      pot := decodeU64 row.post_pot.1 row.post_pot.2.1
          row.post_pot.2.2.1 row.post_pot.2.2.2
      dealer_seat := row.post_button.val
    }
  }

def extractAutoFoldParamsFromAir (ext : AutoFoldMethodColumns) : AutoFoldParams := {
  seat_index := ext.input_seat_index.val
  current_time := decodeU64 ext.input_current_time.1 ext.input_current_time.2.1
      ext.input_current_time.2.2.1 ext.input_current_time.2.2.2
}

def extractForceFoldParamsFromAir (ext : ForceFoldMethodColumns) : ForceFoldParams := {
  seat_index := ext.input_seat_index.val
}

def extractKickPlayerParamsFromAir (ext : KickPlayerMethodColumns) : KickPlayerParams := {
  seat_index := ext.input_seat_index.val
  reason := 0
}

end PokerLean
