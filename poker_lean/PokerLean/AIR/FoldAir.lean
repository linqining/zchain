import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Fold
import PokerLean.AIR.AirBase

namespace PokerLean

structure FoldMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  output_folded : M31
deriving Repr

structure FoldRow where
  common : CommonRow
  method : FoldMethodColumns
deriving Repr

def extractPreTableFromFoldAir
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (max_players : Nat)
    : TexasPokerTable :=
  let tbl : TexasPokerTable := {
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
      current_turn := ext.input_current_turn.val
      dealer_seat := row.pre_button.val
      pot := decodeU64 row.pre_pot.1 row.pre_pot.2.1
          row.pre_pot.2.2.1 row.pre_pot.2.2.2
      side_pots := []
      min_raise := 0
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
  tbl.update_seat ext.input_seat_index.val
    (fun s => { s with player := PlayerId.ofNat 1 })

def extractPostTableFromFoldAir
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromFoldAir row ext max_players
  let post := { pre with
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
  post.update_seat seat_index Seat.mark_folded

def FoldMethodConstraints
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.output_folded = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  PotUnchanged row ∧
  ButtonUnchanged row ∧
  let pre_table := extractPreTableFromFoldAir row ext max_players
  let post_table := extractPostTableFromFoldAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def FoldAirAcceptable
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.Fold ∧
  FoldMethodConstraints row ext expected_seat_index max_players hlt ∧
  row.method_kind = ⟨MethodKind.Fold.toNat, MethodKind.toNat_lt_M31P MethodKind.Fold⟩ ∧
  row.is_active = M31.one

def extractFoldParamsFromAir
    (ext : FoldMethodColumns)
    : FoldParams := {
  seat_index := ext.input_seat_index.val
}

end PokerLean
