import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Raise
import PokerLean.AIR.AirBase

namespace PokerLean

/-- verifier 从 canonical table 重建的 raise AIR 常量。 -/
structure RaiseTrustedInputs where
  min_raise : Nat
  pre_current_bet : Nat
  pre_seat_stack : Nat
  pre_seat_bet : Nat
  pre_seat_total_bet : Nat
  post_current_turn : M31
deriving Repr

/-- raise 的逻辑列模型。`trusted` 不是 trace column。 -/
structure RaiseMethodColumns where
  trusted : RaiseTrustedInputs
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_raise_to : M31 × M31 × M31 × M31
  input_pre_seat_stack : M31 × M31 × M31 × M31
  input_pre_seat_bet : M31 × M31 × M31 × M31
  input_pre_seat_total_bet : M31 × M31 × M31 × M31
  input_call_delta : M31 × M31 × M31 × M31
  output_seat_stack : M31 × M31 × M31 × M31
  output_seat_bet : M31 × M31 × M31 × M31
  output_seat_total_bet : M31 × M31 × M31 × M31
  output_current_bet : M31 × M31 × M31 × M31
  output_min_raise : M31 × M31 × M31 × M31
  output_all_in : M31
  output_acted : M31
  output_current_turn : M31
deriving Repr

/-- Rust `RaiseAir::evaluate` 中 trusted-u64 / checked arithmetic 的 Nat 级模型。 -/
structure RaiseTrustedFacts
    (ext : RaiseMethodColumns) (expected_raise_to : Nat) : Prop where
  raise_witness : decodeLimb4 ext.input_raise_to = expected_raise_to
  pre_stack_witness : decodeLimb4 ext.input_pre_seat_stack = ext.trusted.pre_seat_stack
  pre_bet_witness : decodeLimb4 ext.input_pre_seat_bet = ext.trusted.pre_seat_bet
  pre_total_witness :
    decodeLimb4 ext.input_pre_seat_total_bet = ext.trusted.pre_seat_total_bet
  delta_witness : decodeLimb4 ext.input_call_delta =
    expected_raise_to - ext.trusted.pre_seat_bet
  raise_u64 : expected_raise_to < U64_MAX
  min_raise_u64 : ext.trusted.min_raise < U64_MAX
  pre_current_bet_u64 : ext.trusted.pre_current_bet < U64_MAX
  pre_stack_u64 : ext.trusted.pre_seat_stack < U64_MAX
  pre_bet_u64 : ext.trusted.pre_seat_bet < U64_MAX
  pre_total_u64 : ext.trusted.pre_seat_total_bet < U64_MAX
  above_current : expected_raise_to > ext.trusted.pre_current_bet
  above_seat_bet : expected_raise_to > ext.trusted.pre_seat_bet
  needed_le_stack :
    expected_raise_to - ext.trusted.pre_seat_bet ≤ ext.trusted.pre_seat_stack
  min_or_short_all_in :
    expected_raise_to - ext.trusted.pre_current_bet ≥ ext.trusted.min_raise ∨
    expected_raise_to - ext.trusted.pre_seat_bet = ext.trusted.pre_seat_stack
  post_total_u64 :
    ext.trusted.pre_seat_total_bet +
      (expected_raise_to - ext.trusted.pre_seat_bet) < U64_MAX
  output_stack : decodeLimb4 ext.output_seat_stack =
    ext.trusted.pre_seat_stack -
      (expected_raise_to - ext.trusted.pre_seat_bet)
  output_bet : decodeLimb4 ext.output_seat_bet = expected_raise_to
  output_total : decodeLimb4 ext.output_seat_total_bet =
    ext.trusted.pre_seat_total_bet +
      (expected_raise_to - ext.trusted.pre_seat_bet)
  output_current_bet : decodeLimb4 ext.output_current_bet = expected_raise_to
  output_min_raise : decodeLimb4 ext.output_min_raise =
    if expected_raise_to - ext.trusted.pre_current_bet ≥ ext.trusted.min_raise then
      expected_raise_to - ext.trusted.pre_current_bet
    else ext.trusted.min_raise
  output_all_in : ext.output_all_in =
    if expected_raise_to - ext.trusted.pre_seat_bet = ext.trusted.pre_seat_stack then
      M31.one else M31.zero
  output_turn : ext.output_current_turn = ext.trusted.post_current_turn

def extractPreTableFromRaiseAir
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) : TexasPokerTable :=
  let tbl : TexasPokerTable := {
    table_id := 0
    name_hash := 0
    seats := List.replicate max_players Seat.empty
    max_players := max_players
    small_blind := 0
    big_blind := 0
    ante := 0
    version := decodeLimb4 row.pre_version
    round_state := RoundState.fromNat row.pre_round_state.val
    betting := {
      current_bet := ext.trusted.pre_current_bet
      current_turn := ext.input_current_turn.val
      dealer_seat := row.pre_button.val
      pot := decodeLimb4 row.pre_pot
      side_pots := []
      min_raise := ext.trusted.min_raise
      last_aggressor := 0
      num_raises := 0
    }
    shuffle_state := {
      phase := 0
      current_shuffler := none
      pending_players := []
      completed_players := []
    }
    reveal_state := {
      reveal_phase := 0
      num_assignments := 0
    }
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
  tbl.update_seat ext.input_seat_index.val (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    stack := ext.trusted.pre_seat_stack
    bet := ext.trusted.pre_seat_bet
    total_bet := ext.trusted.pre_seat_total_bet })

def extractPostTableFromRaiseAir
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    TexasPokerTable :=
  let pre := extractPreTableFromRaiseAir row ext max_players
  let post := { pre with
    version := decodeLimb4 row.post_version
    round_state := RoundState.fromNat row.post_round_state.val
    betting := { pre.betting with
      pot := decodeLimb4 row.post_pot
      dealer_seat := row.post_button.val
      current_bet := decodeLimb4 ext.output_current_bet
      min_raise := decodeLimb4 ext.output_min_raise
      current_turn := ext.output_current_turn.val }
  }
  post.update_seat seat_index (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    stack := decodeLimb4 ext.output_seat_stack
    bet := decodeLimb4 ext.output_seat_bet
    total_bet := decodeLimb4 ext.output_seat_total_bet
    all_in := decide (ext.output_all_in.val = M31.one.val)
    acted_this_round := true })

def RaiseMethodConstraints
    (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_raise_to max_players : Nat) : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.output_acted = M31.one ∧
  RaiseTrustedFacts ext expected_raise_to ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  ButtonUnchanged row ∧
  PotUnchanged row ∧
  let pre_table := extractPreTableFromRaiseAir row ext max_players
  let post_table := extractPostTableFromRaiseAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def RaiseAirAcceptable
    (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat) (expected_trusted : RaiseTrustedInputs)
    (max_players : Nat) : Prop :=
  CommonConstraints row MethodKind.Raise ∧
  ext.trusted = expected_trusted ∧
  RaiseMethodConstraints row ext expected_seat_index hlt expected_raise_to max_players ∧
  row.method_kind = ⟨MethodKind.Raise.toNat, MethodKind.toNat_lt_M31P MethodKind.Raise⟩ ∧
  row.is_active = M31.one

def extractRaiseParamsFromAir (ext : RaiseMethodColumns) : RaiseParams := {
  seat_index := ext.input_seat_index.val
  raise_to := decodeLimb4 ext.input_raise_to
  post_current_turn := ext.output_current_turn.val
}

end PokerLean
