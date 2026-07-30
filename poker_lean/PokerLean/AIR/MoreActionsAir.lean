import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.MoreActions
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 更多动作方法的 AIR 形式化 -/

/-! ## 通用提取函数（内部辅助） -/

/-- 通用 pre 表提取（不带 ext，作为内部辅助函数）。
    注意：current_turn 设为 0，由调用方覆盖。 -/
def extractPreTableFromActionAir
    (row : CommonRow)
    (max_players : Nat)
    (_mk : MethodKind)
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

/-- 通用 post 表提取（不带 ext，作为内部辅助函数）。 -/
def extractPostTableFromActionAir
    (row : CommonRow)
    (max_players : Nat)
    (_mk : MethodKind)
    : TexasPokerTable :=
  let pre := extractPreTableFromActionAir row max_players _mk
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

/-- AutoFold 业务列 -/
structure AutoFoldMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  input_current_time : M31 × M31 × M31 × M31
  output_folded : M31
deriving Repr

/-- auto_fold 专用 pre 状态提取：使用 ext.input_current_turn.val 作为 current_turn，
    并将 acting seat 标记为已占用。 -/
def extractPreTableFromAutoFoldAir
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (max_players : Nat)
    : TexasPokerTable :=
  let base := extractPreTableFromActionAir row max_players MethodKind.AutoFold
  let with_turn := { base with betting := { base.betting with
    current_turn := ext.input_current_turn.val } }
  with_turn.update_seat ext.input_seat_index.val
    (fun s => { s with player := PlayerId.ofNat 1 })

/-- auto_fold 专用 post 状态提取：将 acting seat 标记为 folded。 -/
def extractPostTableFromAutoFoldAir
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromAutoFoldAir row ext max_players
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

def AutoFoldMethodConstraints
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_current_turn = ext.input_seat_index ∧
  ext.input_seat_occupied = M31.one ∧
  ext.input_current_time.1 = ⟨expected_current_time % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_folded = M31.one ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  RoundStateIsBetting row ∧
  PotUnchanged row ∧
  ButtonUnchanged row ∧
  let pre_table := extractPreTableFromAutoFoldAir row ext max_players
  let post_table := extractPostTableFromAutoFoldAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def AutoFoldAirAcceptable
    (row : CommonRow)
    (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    : Prop :=
  CommonConstraints row MethodKind.AutoFold ∧
  AutoFoldMethodConstraints row ext expected_seat_index max_players hlt expected_current_time ∧
  row.method_kind = ⟨MethodKind.AutoFold.toNat, MethodKind.toNat_lt_M31P MethodKind.AutoFold⟩ ∧
  row.is_active = M31.one

/-- ForceFold 业务列 -/
structure ForceFoldMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  output_folded : M31
deriving Repr

/-- force_fold 专用 pre 状态提取。 -/
def extractPreTableFromForceFoldAir
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
    (max_players : Nat)
    : TexasPokerTable :=
  let base := extractPreTableFromActionAir row max_players MethodKind.ForceFold
  let with_turn := { base with betting := { base.betting with
    current_turn := ext.input_current_turn.val } }
  with_turn.update_seat ext.input_seat_index.val
    (fun s => { s with player := PlayerId.ofNat 1 })

/-- force_fold 专用 post 状态提取：将 acting seat 标记为 folded。 -/
def extractPostTableFromForceFoldAir
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromForceFoldAir row ext max_players
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

def ForceFoldMethodConstraints
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
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
  let pre_table := extractPreTableFromForceFoldAir row ext max_players
  let post_table := extractPostTableFromForceFoldAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def ForceFoldAirAcceptable
    (row : CommonRow)
    (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.ForceFold ∧
  ForceFoldMethodConstraints row ext expected_seat_index max_players hlt ∧
  row.method_kind = ⟨MethodKind.ForceFold.toNat, MethodKind.toNat_lt_M31P MethodKind.ForceFold⟩ ∧
  row.is_active = M31.one

/-- KickPlayer 业务列 -/
structure KickPlayerMethodColumns where
  input_seat_index : M31
  input_current_turn : M31
  input_seat_occupied : M31
  output_refund : M31 × M31 × M31 × M31
  /-- 被踢者当前下注（4 limb）— pot += kicked_bet（对齐 Rust AIR kick_player.rs 的 kicked_bet witness） -/
  kicked_bet : M31 × M31 × M31 × M31
  /-- pot += kicked_bet 的 3 个 ripple-carry bit。 -/
  pot_add_carry : M31 × M31 × M31
  output_kicked : M31
deriving Repr

/-- kick_player 专用前状态提取（设置目标座位为已占用，current_turn 来自 ext）。

    关键：被踢者的 `bet` 设为 `decodeU64 ext.kicked_bet`，对齐 AIR 的
    `KICKED_BET` witness（`post_pot = pre_pot + kicked_bet`）。这使得 soundness
    约束 #10 `post.pot = pre.pot + pre.get_seat(seat_index).bet` 可由
    `PotDelta` ripple-carry 约束直接推出。 -/
def extractPreTableFromKickPlayerAir
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (max_players : Nat)
    : TexasPokerTable :=
  let base := extractPreTableFromActionAir row max_players MethodKind.KickPlayer
  let with_turn := { base with betting := { base.betting with
    current_turn := ext.input_current_turn.val } }
  with_turn.update_seat ext.input_seat_index.val
    (fun s => { s with
      player := PlayerId.ofNat 1
      bet := decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
               ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 })

/-- kick_player 专用后状态提取（目标座位标记为 kicked：保留 player，
    folded/left_during_hand = true，stack/bet 清零）。

    注：post 状态的 pot 来自 row.post_pot（由 PotDelta ripple-carry 约束绑定到
    pre_pot + kicked_bet），对齐 Rust AIR `pot_delta_4limb`。 -/
def extractPostTableFromKickPlayerAir
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromKickPlayerAir row ext max_players
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    betting := { pre.betting with
      pot := decodeU64 row.post_pot.1 row.post_pot.2.1
          row.post_pot.2.2.1 row.post_pot.2.2.2 }
    seats := List.modify Seat.kicked seat_index pre.seats
  }

def KickPlayerMethodConstraints
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    : Prop :=
  row.is_active = M31.one →
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_seat_occupied = M31.one ∧
  ext.output_refund.1 = ⟨expected_refund % 65536, by unfold M31_P; omega⟩ ∧
  ext.output_kicked = M31.one ∧
  -- 目标座位必须被占用（kick_player 前置条件）
  SeatOccupied ext.input_seat_occupied ∧
  VersionIncrementConstraint row ∧
  RoundStateUnchanged row ∧
  ButtonUnchanged row ∧
  -- pot 守恒：post_pot = pre_pot + kicked_bet（规范 ripple-carry 加法）
  PotDelta row ext.kicked_bet ext.pot_add_carry ∧
  let pre_table := extractPreTableFromKickPlayerAir row ext max_players
  let post_table := extractPostTableFromKickPlayerAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def KickPlayerAirAcceptable
    (row : CommonRow)
    (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    : Prop :=
  CommonConstraints row MethodKind.KickPlayer ∧
  KickPlayerMethodConstraints row ext expected_seat_index max_players hlt expected_refund ∧
  row.method_kind = ⟨MethodKind.KickPlayer.toNat, MethodKind.toNat_lt_M31P MethodKind.KickPlayer⟩ ∧
  row.is_active = M31.one

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
