import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Bet
import PokerLean.AIR.AirBase

namespace PokerLean

/-- bet 业务列。

    含 pre-state 座位 witness（stack/bet/total_bet）和 post-state betting witness
    （current_bet/min_raise），用于通过 `StateRootConsistency` 绑定到 committed state root，
    并通过逐 limb delta/equality 约束保证资金守恒。

    这是手写的 mid-round 抽象列。Rust P06 的 trusted pre-amount 字段与
    `post_current_turn` 守卫尚未在此列布局中镜像。 -/
structure BetMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_bet_amount : M31 × M31 × M31 × M31
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
  /-- post-state betting.current_bet（4 limb witness） -/
  output_current_bet : M31 × M31 × M31 × M31
  /-- post-state betting.min_raise（4 limb witness） -/
  output_min_raise : M31 × M31 × M31 × M31
  output_all_in : M31
  output_acted : M31
deriving Repr

/-- 从 AIR 行提取 pre 状态。 -/
def extractPreTableFromBetAir
    (row : CommonRow)
    (ext : BetMethodColumns)
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

/-- 从 AIR 行提取 post 状态。 -/
def extractPostTableFromBetAir
    (row : CommonRow)
    (ext : BetMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromBetAir row ext max_players
  let post_current_bet := decodeU64 ext.output_current_bet.1 ext.output_current_bet.2.1
      ext.output_current_bet.2.2.1 ext.output_current_bet.2.2.2
  let post_min_raise := decodeU64 ext.output_min_raise.1 ext.output_min_raise.2.1
      ext.output_min_raise.2.2.1 ext.output_min_raise.2.2.2
  let post := { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    betting := {
      pre.betting with
      pot := decodeU64 row.post_pot.1 row.post_pot.2.1
          row.post_pot.2.2.1 row.post_pot.2.2.2
      dealer_seat := row.post_button.val
      current_bet := post_current_bet
      min_raise := post_min_raise
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

/-- bet AIR 的 mid-round 方法约束。

    在该手写局部模型中约束：
    - AmountPositive：bet_amount > 0
    - PotUnchanged（全 4 limb）：mid-round 时 post_pot = pre_pot
    - Limb4DeltaRev（stack）：pre_stack = post_stack + bet_amount → bet_amount ≤ pre_stack
    - Limb4Eq（bet）：post_bet = bet_amount
    - Limb4Delta（total_bet）：post_total_bet = pre_total_bet + bet_amount
    - Limb4Eq（current_bet）：post_current_bet = bet_amount
    - Limb4Eq（min_raise）：post_min_raise = bet_amount -/
def BetMethodConstraints
    (row : CommonRow)
    (ext : BetMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_bet_amount : Nat)
    (max_players : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.input_bet_amount.1 = ⟨expected_bet_amount % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_acted = M31.one ∧
  AmountPositive ext.input_bet_amount.1 ext.input_bet_amount.2.1 ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  ButtonUnchanged row ∧
  -- mid-round 不收池：筹码仍在 seat.bet，pot 全 4 limb 不变
  PotUnchanged row ∧
  -- stack 守恒：pre_stack = post_stack + bet_amount → post_stack = pre_stack - bet_amount
  Limb4DeltaRev ext.input_pre_seat_stack ext.output_seat_stack ext.input_bet_amount ∧
  -- bet 守恒：post_bet = bet_amount（bet 是设值，不是累加）
  Limb4Eq ext.output_seat_bet ext.input_bet_amount ∧
  -- total_bet 守恒：post_total_bet = pre_total_bet + bet_amount
  Limb4Delta ext.input_pre_seat_total_bet ext.output_seat_total_bet ext.input_bet_amount ∧
  -- current_bet 守恒：post_current_bet = bet_amount
  Limb4Eq ext.output_current_bet ext.input_bet_amount ∧
  -- min_raise 守恒：post_min_raise = bet_amount
  Limb4Eq ext.output_min_raise ext.input_bet_amount ∧
  let pre_table := extractPreTableFromBetAir row ext max_players
  let post_table := extractPostTableFromBetAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def BetAirAcceptable
    (row : CommonRow)
    (ext : BetMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_bet_amount : Nat)
    (max_players : Nat)
    : Prop :=
  CommonConstraints row MethodKind.Bet ∧
  BetMethodConstraints row ext expected_seat_index hlt expected_bet_amount max_players ∧
  row.method_kind = ⟨MethodKind.Bet.toNat, MethodKind.toNat_lt_M31P MethodKind.Bet⟩ ∧
  row.is_active = M31.one

/-- 从 AIR 提取 bet 参数 -/
def extractBetParamsFromAir
    (ext : BetMethodColumns)
    : BetParams := {
  seat_index := ext.input_seat_index.val
  bet_amount := decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
      ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2
}

end PokerLean
