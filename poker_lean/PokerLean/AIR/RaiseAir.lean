import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Raise
import PokerLean.AIR.AirBase

namespace PokerLean

/-- raise 业务列。

    含 pre-state 座位 witness（stack/bet/total_bet）、raise 专用的"跟注增量"
    witness（`input_call_delta` = `raise_to - pre.bet`，4 limb）以及 post-state
    betting witness（current_bet/min_raise），用于通过 `StateRootConsistency`
    绑定到 committed state root，并通过逐 limb delta/equality 约束保证资金守恒。

    核心关系（`delta := raise_to - pre.bet`）：
    - `Limb4Delta pre_bet post_bet delta` + `Limb4Eq post_bet raise_to`
      ⟹ `decodeU64 delta = raise_to - pre.bet`（且 `raise_to ≥ pre.bet` 自动成立）
    - `PotDelta delta`：`post_pot = pre_pot + delta`
    - `Limb4DeltaRev pre_stack post_stack delta`：`post_stack = pre_stack - delta`
    - `Limb4Delta pre_total_bet post_total_bet delta`：
      `post_total_bet = pre_total_bet + delta`
    - `Limb4Eq post_current_bet raise_to`（`pre.current_bet = 0` ⟹ `delta` 即新 min_raise）
    - `Limb4Eq post_min_raise raise_to`（`pre.current_bet = 0` ⟹ `min_raise = raise_to`） -/
structure RaiseMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_raise_to : M31 × M31 × M31 × M31
  /-- pre-state 座位 stack（4 limb witness） -/
  input_pre_seat_stack : M31 × M31 × M31 × M31
  /-- pre-state 座位 bet（4 limb witness） -/
  input_pre_seat_bet : M31 × M31 × M31 × M31
  /-- pre-state 座位 total_bet（4 limb witness） -/
  input_pre_seat_total_bet : M31 × M31 × M31 × M31
  /-- raise 的"跟注增量" witness = `raise_to - pre.bet`（4 limb） -/
  input_call_delta : M31 × M31 × M31 × M31
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
def extractPreTableFromRaiseAir
    (row : CommonRow)
    (ext : RaiseMethodColumns)
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
def extractPostTableFromRaiseAir
    (row : CommonRow)
    (ext : RaiseMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromRaiseAir row ext max_players
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

/-- raise AIR 的方法约束。

    闭合的 Gap：
    - AmountPositive：raise_to > 0（因 pre.current_bet = 0 ⟹ raise_to > current_bet）
    - PotDelta（全 4 limb，对 call_delta）：post_pot = pre_pot + (raise_to - pre_bet)
    - Limb4DeltaRev（stack，对 call_delta）：
      pre_stack = post_stack + delta ⟹ raise_to ≤ pre_stack + pre_bet
    - Limb4Delta（pre_bet → post_bet，对 call_delta）+ Limb4Eq（post_bet = raise_to）：
      post_bet = raise_to（且 delta = raise_to - pre_bet）
    - Limb4Delta（total_bet，对 call_delta）：post_total_bet = pre_total_bet + delta
    - Limb4Eq（current_bet）：post_current_bet = raise_to
    - Limb4Eq（min_raise）：post_min_raise = raise_to（pre.current_bet = 0） -/
def RaiseMethodConstraints
    (row : CommonRow)
    (ext : RaiseMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat)
    (max_players : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.input_raise_to.1 = ⟨expected_raise_to % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_acted = M31.one ∧
  AmountPositive ext.input_raise_to.1 ext.input_raise_to.2.1
    ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  ButtonUnchanged row ∧
  -- 资金守恒：pot += call_delta（全 4 limb）
  PotDelta row ext.input_call_delta ∧
  -- stack 守恒：pre_stack = post_stack + call_delta
  --   ⟹ post_stack = pre_stack - delta ⟹ delta ≤ pre_stack
  --   ⟹ raise_to - pre_bet ≤ pre_stack ⟹ raise_to ≤ pre_stack + pre_bet
  Limb4DeltaRev ext.input_pre_seat_stack ext.output_seat_stack ext.input_call_delta ∧
  -- bet 守恒：post_bet = pre_bet + call_delta（与下方 post_bet = raise_to 联立
  --   得 call_delta = raise_to - pre_bet，且 raise_to ≥ pre_bet 自动成立）
  Limb4Delta ext.input_pre_seat_bet ext.output_seat_bet ext.input_call_delta ∧
  -- total_bet 守恒：post_total_bet = pre_total_bet + call_delta
  Limb4Delta ext.input_pre_seat_total_bet ext.output_seat_total_bet ext.input_call_delta ∧
  -- bet 设值：post_bet = raise_to
  Limb4Eq ext.output_seat_bet ext.input_raise_to ∧
  -- current_bet 守恒：post_current_bet = raise_to
  Limb4Eq ext.output_current_bet ext.input_raise_to ∧
  -- min_raise 守恒：post_min_raise = raise_to（pre.current_bet = 0 ⟹ raise_to - 0 = raise_to）
  Limb4Eq ext.output_min_raise ext.input_raise_to ∧
  let pre_table := extractPreTableFromRaiseAir row ext max_players
  let post_table := extractPostTableFromRaiseAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def RaiseAirAcceptable
    (row : CommonRow)
    (ext : RaiseMethodColumns)
    (expected_seat_index : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat)
    (max_players : Nat)
    : Prop :=
  CommonConstraints row MethodKind.Raise ∧
  RaiseMethodConstraints row ext expected_seat_index hlt expected_raise_to max_players ∧
  row.method_kind = ⟨MethodKind.Raise.toNat, MethodKind.toNat_lt_M31P MethodKind.Raise⟩ ∧
  row.is_active = M31.one

/-- 从 AIR 提取 raise 参数 -/
def extractRaiseParamsFromAir
    (ext : RaiseMethodColumns)
    : RaiseParams := {
  seat_index := ext.input_seat_index.val
  raise_to := decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
      ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2
}

end PokerLean
