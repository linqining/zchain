import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Check
import PokerLean.AIR.AirBase

namespace PokerLean

structure CheckMethodColumns where
  input_seat_index : M31
  input_current_bet : M31 × M31 × M31 × M31
  output_acted : M31
deriving Repr

/-- check AIR 的方法约束（对应 Rust 的 evaluate 函数） -/
def CheckMethodConstraints
    (row : CommonRow)
    (ext : CheckMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_bet : Nat)
    (expected_seat_bet : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_bet.1 = ⟨expected_current_bet % 65536, by unfold M31_P; omega⟩ ∧
  ext.input_current_bet.1 = ⟨expected_seat_bet % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_acted = M31.one

def CheckAirAcceptable
    (row : CommonRow)
    (ext : CheckMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_bet : Nat)
    (expected_seat_bet : Nat)
    : Prop :=
  CommonConstraints row MethodKind.Check ∧
  CheckMethodConstraints row ext expected_seat_index hlt expected_current_bet expected_seat_bet ∧
  row.method_kind = ⟨MethodKind.Check.toNat, MethodKind.toNat_lt_M31P MethodKind.Check⟩ ∧
  row.is_active = M31.one

/-- 从 AIR 行提取 pre 状态 -/
def extractPreTableFromCheckAir
    (row : CommonRow)
    (max_players : Nat)
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

/-- 从 AIR 行提取 post 状态 -/
def extractPostTableFromCheckAir
    (row : CommonRow)
    (ext : CheckMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromCheckAir row max_players
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

/-- 从 AIR 提取 check 参数 -/
def extractCheckParamsFromAir
    (ext : CheckMethodColumns)
    : CheckParams := {
  seat_index := ext.input_seat_index.val
}

end PokerLean
