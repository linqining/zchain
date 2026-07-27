import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Call
import PokerLean.AIR.AirBase

namespace PokerLean

/-- call 业务列。

    含 pre-state 座位 witness（stack/bet/total_bet），用于通过 `StateRootConsistency`
    绑定到 committed pre_state_root，并通过逐 limb delta 约束保证资金守恒。 -/
structure CallMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_call_amount : M31 × M31 × M31 × M31
  /-- pre-state 座位 stack（4 limb witness） -/
  input_pre_seat_stack : M31 × M31 × M31 × M31
  /-- pre-state 座位 bet（4 limb witness） -/
  input_pre_seat_bet : M31 × M31 × M31 × M31
  /-- pre-state 座位 total_bet（4 limb witness） -/
  input_pre_seat_total_bet : M31 × M31 × M31 × M31
  output_seat_stack : M31 × M31 × M31 × M31
  output_seat_bet : M31 × M31 × M31 × M31
  /-- post-state 座位 total_bet（4 limb witness） -/
  output_seat_total_bet : M31 × M31 × M31 × M31
  output_all_in : M31
  output_acted : M31
deriving Repr

/-- 从 AIR 行提取 pre 状态。
    座位 stack/bet/total_bet 来自 witness 列，由 `StateRootConsistency` 绑定到 pre_state_root。 -/
def extractPreTableFromCallAir
    (row : CommonRow)
    (ext : CallMethodColumns)
    (max_players : Nat)
    : TexasPokerTable :=
  let pre_stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
      ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2
  let pre_bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
      ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2
  let pre_total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
      ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2
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
    (fun _ => { Seat.empty with
      player := PlayerId.ofNat 1
      stack := pre_stack
      bet := pre_bet
      total_bet := pre_total_bet })

/-- 从 AIR 行提取 post 状态。
    座位 stack/bet/total_bet 来自 witness 列，由 delta 约束绑定到 pre-state。 -/
def extractPostTableFromCallAir
    (row : CommonRow)
    (ext : CallMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromCallAir row ext max_players
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
  let new_stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
      ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2
  let new_bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
      ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2
  let new_total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
      ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2
  post.update_seat seat_index
    (fun _ => { Seat.empty with
      player := PlayerId.ofNat 1
      stack := new_stack
      bet := new_bet
      total_bet := new_total_bet
      acted_this_round := true })

/-- call AIR 的方法约束。

    闭合的 Gap：
    - RoundStateIsBetting：阻止非下注轮 call
    - CurrentTurnMatches：阻止非当前行动座位 call
    - SeatOccupied：阻止空座位 call
    - ButtonUnchanged：dealer_seat 不变
    - PotDelta（全 4 limb）：post_pot = pre_pot + call_amount
    - StackDelta（反向）：pre_stack = post_stack + call_amount → post_stack = pre_stack - call_amount
    - BetDelta：post_bet = pre_bet + call_amount
    - TotalBetDelta：post_total_bet = pre_total_bet + call_amount
    - StateRootConsistency：witness 绑定到 committed state root -/
def CallMethodConstraints
    (row : CommonRow)
    (ext : CallMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat)
    (max_players : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.input_call_amount.1 = ⟨expected_call_amount % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_acted = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  ButtonUnchanged row ∧
  -- 资金守恒：pot += call_amount（全 4 limb）
  PotDelta row ext.input_call_amount ∧
  -- stack 守恒：pre_stack = post_stack + call_amount → post_stack = pre_stack - call_amount
  Limb4DeltaRev ext.input_pre_seat_stack ext.output_seat_stack ext.input_call_amount ∧
  -- bet 守恒：post_bet = pre_bet + call_amount
  Limb4Delta ext.input_pre_seat_bet ext.output_seat_bet ext.input_call_amount ∧
  -- total_bet 守恒：post_total_bet = pre_total_bet + call_amount
  Limb4Delta ext.input_pre_seat_total_bet ext.output_seat_total_bet ext.input_call_amount ∧
  let pre_table := extractPreTableFromCallAir row ext max_players
  let post_table := extractPostTableFromCallAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def CallAirAcceptable
    (row : CommonRow)
    (ext : CallMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat)
    (max_players : Nat)
    : Prop :=
  CommonConstraints row MethodKind.Call ∧
  CallMethodConstraints row ext expected_seat_index hlt expected_call_amount max_players ∧
  row.method_kind = ⟨MethodKind.Call.toNat, MethodKind.toNat_lt_M31P MethodKind.Call⟩ ∧
  row.is_active = M31.one

/-- 从 AIR 提取 call 参数 -/
def extractCallParamsFromAir
    (ext : CallMethodColumns)
    : CallParams := {
  seat_index := ext.input_seat_index.val
  call_amount := decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
      ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2
}

end PokerLean
