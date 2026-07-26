import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.CreateTable

namespace PokerLean

structure CreateTableRow extends CommonRow where
  output_max_players : M31
  output_small_blind : M31 × M31 × M31 × M31
  output_big_blind : M31 × M31 × M31 × M31
  output_is_private : M31
  output_timeout : M31
deriving Repr

namespace CreateTableRow

def maxPlayers (r : CreateTableRow) : Nat := r.output_max_players.val

def smallBlind (r : CreateTableRow) : Nat :=
  let ⟨l0, l1, l2, l3⟩ := r.output_small_blind
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)

def bigBlind (r : CreateTableRow) : Nat :=
  let ⟨l0, l1, l2, l3⟩ := r.output_big_blind
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)

def isPrivate (r : CreateTableRow) : Bool := r.output_is_private.val ≠ 0

def timeout_val (r : CreateTableRow) : Nat := r.output_timeout.val

end CreateTableRow

def CreateTableMethodConstraints (row : CommonRow) (ext : CreateTableRow) : Prop :=
  2 ≤ ext.maxPlayers ∧ ext.maxPlayers ≤ 9 ∧
  ext.bigBlind > 0 ∧
  ext.smallBlind ≤ ext.bigBlind ∧
  row.pre_version = (M31.zero, M31.zero, M31.zero, M31.zero) ∧
  row.post_pot = (M31.zero, M31.zero, M31.zero, M31.zero) ∧
  row.post_button = M31.zero ∧
  row.post_round_state = M31.zero ∧
  row.post_version = (M31.one, M31.zero, M31.zero, M31.zero) ∧
  row.post_round_state = row.pre_round_state ∧
  VersionIncrementConstraint row

def CreateTableAirAcceptable (row : CommonRow) (ext : CreateTableRow) : Prop :=
  CommonConstraints row MethodKind.CreateTable ∧
  CreateTableMethodConstraints row ext ∧
  row.is_active = M31.one ∧
  row.is_padding = M31.zero

def extractParamsFromAir (ext : CreateTableRow) : CreateTableParams := {
  table_id := 0
  name_hash := 0
  max_players := ext.maxPlayers
  small_blind := ext.smallBlind
  big_blind := ext.bigBlind
  is_private := ext.isPrivate
  timeout := ext.timeout_val
}

def extractPreTableFromAir (row : CommonRow) : TexasPokerTable :=
  TexasPokerTable.empty_table

def extractPostTableFromAir (row : CommonRow) (ext : CreateTableRow) : TexasPokerTable :=
  let params := extractParamsFromAir ext
  let ⟨p0, p1, p2, p3⟩ := row.post_pot
  let pot_val : Nat := p0.val + p1.val * 65536 + p2.val * (65536 * 65536) + p3.val * (65536 * 65536 * 65536)
  let btn_val : Nat := row.post_button.val
  let ⟨v0, v1, v2, v3⟩ := row.post_version
  let ver_val : Nat := v0.val + v1.val * 65536 + v2.val * (65536 * 65536) + v3.val * (65536 * 65536 * 65536)
  {
    table_id := params.table_id
    name_hash := params.name_hash
    seats := List.replicate params.max_players Seat.empty
    max_players := params.max_players
    small_blind := params.small_blind
    big_blind := params.big_blind
    ante := 0
    version := ver_val
    round_state := RoundState.fromNat row.post_round_state.val
    betting := {
      current_bet := 0
      current_turn := 0
      dealer_seat := btn_val
      pot := pot_val
      side_pots := []
      min_raise := params.big_blind
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
    hand_id := 0
    call_seq := 0
    chip_pool := 0
    addon_pool := 0
    pending_addon_total := 0
    pending_rebuy_total := 0
    rake := 0
    table_fee := 0
    is_private := params.is_private
    started_at := 0
    timeout := params.timeout
    last_action_time := 0
  }

end PokerLean
