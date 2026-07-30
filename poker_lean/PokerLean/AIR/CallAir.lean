import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Call
import PokerLean.AIR.AirBase

namespace PokerLean

/-- verifier 从 canonical pre/post table 重建的 call 逻辑输入。

这些值对应 Rust `CallInput` 中不属于 trace column 的 AIR 常量。把它们显式
放进 Lean 模型，并在 `CallAirAcceptable` 中与 `expected_trusted` 相等，避免把
prover 自选常量误当成可信状态。 -/
structure CallTrustedInputs where
  pre_current_bet : Nat
  pre_seat_bet : Nat
  pre_seat_stack : Nat
  pre_seat_total_bet : Nat
  post_current_turn : M31
deriving Repr

/-- call 的逻辑列模型。`trusted` 是 verifier logical input，不是 trace column。 -/
structure CallMethodColumns where
  trusted : CallTrustedInputs
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_call_amount : M31 × M31 × M31 × M31
  input_pre_seat_stack : M31 × M31 × M31 × M31
  input_pre_seat_bet : M31 × M31 × M31 × M31
  input_pre_seat_total_bet : M31 × M31 × M31 × M31
  output_seat_stack : M31 × M31 × M31 × M31
  output_seat_bet : M31 × M31 × M31 × M31
  output_seat_total_bet : M31 × M31 × M31 × M31
  output_all_in : M31
  output_acted : M31
  /-- Rust trace 中真实存在的 `OUTPUT_CURRENT_TURN`。 -/
  output_current_turn : M31
deriving Repr

/-- Rust call AIR 中由 verifier-trusted u64 常量决定的金额事实。

这里直接在 Nat/u64 解码层表达 checked arithmetic，不再把无 carry 的逐 limb
`Limb4Delta` 当成 Rust `checked_add`/`checked_sub` 的等价模型。 -/
structure CallTrustedFacts
    (ext : CallMethodColumns) (expected_call_amount : Nat) : Prop where
  amount_witness : decodeLimb4 ext.input_call_amount = expected_call_amount
  pre_stack_witness : decodeLimb4 ext.input_pre_seat_stack = ext.trusted.pre_seat_stack
  pre_bet_witness : decodeLimb4 ext.input_pre_seat_bet = ext.trusted.pre_seat_bet
  pre_total_witness :
    decodeLimb4 ext.input_pre_seat_total_bet = ext.trusted.pre_seat_total_bet
  amount_u64 : expected_call_amount < U64_MAX
  pre_current_bet_u64 : ext.trusted.pre_current_bet < U64_MAX
  pre_stack_u64 : ext.trusted.pre_seat_stack < U64_MAX
  pre_bet_u64 : ext.trusted.pre_seat_bet < U64_MAX
  pre_total_u64 : ext.trusted.pre_seat_total_bet < U64_MAX
  exact_amount : expected_call_amount =
    min (ext.trusted.pre_current_bet - ext.trusted.pre_seat_bet)
      ext.trusted.pre_seat_stack
  post_bet_u64 : ext.trusted.pre_seat_bet + expected_call_amount < U64_MAX
  post_total_u64 : ext.trusted.pre_seat_total_bet + expected_call_amount < U64_MAX
  output_stack : decodeLimb4 ext.output_seat_stack =
    ext.trusted.pre_seat_stack - expected_call_amount
  output_bet : decodeLimb4 ext.output_seat_bet =
    ext.trusted.pre_seat_bet + expected_call_amount
  output_total : decodeLimb4 ext.output_seat_total_bet =
    ext.trusted.pre_seat_total_bet + expected_call_amount
  output_all_in : ext.output_all_in =
    if expected_call_amount > 0 ∧ expected_call_amount = ext.trusted.pre_seat_stack then
      M31.one else M31.zero
  output_turn : ext.output_current_turn = ext.trusted.post_current_turn

/-- 从可信逻辑输入与 trace witness 提取 call pre-state。 -/
def extractPreTableFromCallAir
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) : TexasPokerTable :=
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
  tbl.update_seat ext.input_seat_index.val (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    stack := ext.trusted.pre_seat_stack
    bet := ext.trusted.pre_seat_bet
    total_bet := ext.trusted.pre_seat_total_bet })

/-- 提取 Rust P06 所接受的 same-round call post-state。 -/
def extractPostTableFromCallAir
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    TexasPokerTable :=
  let pre := extractPreTableFromCallAir row ext max_players
  let post := { pre with
    version := decodeLimb4 row.post_version
    round_state := RoundState.fromNat row.post_round_state.val
    betting := { pre.betting with
      pot := decodeLimb4 row.post_pot
      dealer_seat := row.post_button.val
      current_turn := ext.output_current_turn.val }
  }
  post.update_seat seat_index (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    stack := decodeLimb4 ext.output_seat_stack
    bet := decodeLimb4 ext.output_seat_bet
    total_bet := decodeLimb4 ext.output_seat_total_bet
    all_in := decide (ext.output_all_in.val = M31.one.val)
    acted_this_round := true })

/-- call 的手写 Lean mid-round 约束模型。 -/
def CallMethodConstraints
    (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_call_amount max_players : Nat) : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.output_acted = M31.one ∧
  CallTrustedFacts ext expected_call_amount ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  ButtonUnchanged row ∧
  PotUnchanged row ∧
  let pre_table := extractPreTableFromCallAir row ext max_players
  let post_table := extractPostTableFromCallAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def CallAirAcceptable
    (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat) (expected_trusted : CallTrustedInputs)
    (max_players : Nat) : Prop :=
  CommonConstraints row MethodKind.Call ∧
  ext.trusted = expected_trusted ∧
  CallMethodConstraints row ext expected_seat_index hlt expected_call_amount max_players ∧
  row.method_kind = ⟨MethodKind.Call.toNat, MethodKind.toNat_lt_M31P MethodKind.Call⟩ ∧
  row.is_active = M31.one

/-- 从 AIR 提取 call 参数，包括 verifier 绑定的下一行动座位。 -/
def extractCallParamsFromAir (ext : CallMethodColumns) : CallParams := {
  seat_index := ext.input_seat_index.val
  call_amount := decodeLimb4 ext.input_call_amount
  post_current_turn := ext.output_current_turn.val
}

end PokerLean
