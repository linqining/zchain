import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Crypto
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 密码学方法 AIR 形式化

对齐 `poker_texas_air/src/airs/crypto/`。

所有 5 个密码学方法的 AIR 约束：
- seat_index 和某个输入参数与公开输入一致
- version 递增（post_version = pre_version + 1）
- round_state 不变（post_round_state = pre_round_state）
- 对阶段只建模粗粒度 gating（正数或非 Idle）
- 对抽象提取状态加入 `StateRootConsistency`

本模型**不验证** DLEq、ZKShuffle、RevealToken、Reconstruct 等密码学证明，
也没有证明上述抽象阶段/root 谓词与真实 Rust trace、公开输入及外部验证器等价。
-/

/-! ## 通用提取函数 -/

def extractPreTableFromCryptoAir
    (row : CommonRow)
    (max_players : Nat)
    (shuffle_phase : Nat)
    (reveal_phase : Nat)
    (reconstruct_state : Nat)
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
    phase := shuffle_phase
    current_shuffler := none
    pending_players := []
    completed_players := []
  }
  reveal_state := {
    reveal_phase := reveal_phase
    num_assignments := 0
  }
  deck_state := DeckState.DeckIdle
  reconstruct_state := ReconstructState.fromNat reconstruct_state
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

def extractPostTableFromCryptoAir
    (row : CommonRow)
    (max_players : Nat)
    (shuffle_phase : Nat)
    (reveal_phase : Nat)
    (reconstruct_state : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase reconstruct_state
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
  }

/-! ## join_and_shuffle AIR -/

structure JoinAndShuffleMethodColumns where
  input_seat_index : M31
  input_new_deck_commitment_0 : M31
  input_shuffle_phase : M31
  output_deck_commitment_0 : M31
deriving Repr

def JoinAndShuffleMethodConstraints
    (row : CommonRow)
    (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat)
    (expected_commit_0 : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_new_deck_commitment_0 = ⟨expected_commit_0 % 65536, by unfold M31_P; omega⟩ ∧
  ShufflePhasePositive ext.input_shuffle_phase ∧
  ext.output_deck_commitment_0 = ext.input_new_deck_commitment_0 ∧
  let pre_table := extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  let post_table := extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def JoinAndShuffleAirAcceptable
    (row : CommonRow)
    (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat)
    (expected_commit_0 : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.JoinAndShuffle ∧
  JoinAndShuffleMethodConstraints row ext expected_seat_index expected_commit_0 max_players hlt ∧
  row.method_kind = ⟨MethodKind.JoinAndShuffle.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinAndShuffle⟩ ∧
  row.is_active = M31.one

/-! ## leave_with_proof AIR -/

structure LeaveWithProofMethodColumns where
  input_seat_index : M31
  input_leave_kind : M31
  input_shuffle_phase : M31
deriving Repr

def LeaveWithProofMethodConstraints
    (row : CommonRow)
    (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat)
    (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_leave_kind = nat_to_m31 expected_leave_kind hltk ∧
  ShufflePhasePositive ext.input_shuffle_phase ∧
  let pre_table := extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  let post_table := extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def LeaveWithProofAirAcceptable
    (row : CommonRow)
    (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat)
    (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.LeaveWithProof ∧
  LeaveWithProofMethodConstraints row ext expected_seat_index expected_leave_kind max_players hlt hltk ∧
  row.method_kind = ⟨MethodKind.LeaveWithProof.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveWithProof⟩ ∧
  row.is_active = M31.one

/-! ## submit_shuffle_v2 AIR -/

structure SubmitShuffleV2MethodColumns where
  input_seat_index : M31
  input_new_deck_commitment_0 : M31
  input_shuffle_phase : M31
deriving Repr

def SubmitShuffleV2MethodConstraints
    (row : CommonRow)
    (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat)
    (expected_commit_0 : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_new_deck_commitment_0 = ⟨expected_commit_0 % 65536, by unfold M31_P; omega⟩ ∧
  ShufflePhasePositive ext.input_shuffle_phase ∧
  let pre_table := extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  let post_table := extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def SubmitShuffleV2AirAcceptable
    (row : CommonRow)
    (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat)
    (expected_commit_0 : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.SubmitShuffleV2 ∧
  SubmitShuffleV2MethodConstraints row ext expected_seat_index expected_commit_0 max_players hlt ∧
  row.method_kind = ⟨MethodKind.SubmitShuffleV2.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitShuffleV2⟩ ∧
  row.is_active = M31.one

/-! ## submit_player_reveal_tokens AIR -/

structure SubmitRevealTokensMethodColumns where
  input_seat_index : M31
  input_reveal_phase : M31
deriving Repr

def SubmitRevealTokensMethodConstraints
    (row : CommonRow)
    (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat)
    (expected_reveal_phase : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_reveal_phase = nat_to_m31 expected_reveal_phase hltp ∧
  RevealPhasePositive ext.input_reveal_phase ∧
  let pre_table := extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0
  let post_table := extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def SubmitRevealTokensAirAcceptable
    (row : CommonRow)
    (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat)
    (expected_reveal_phase : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.SubmitPlayerRevealTokens ∧
  SubmitRevealTokensMethodConstraints row ext expected_seat_index expected_reveal_phase max_players hlt hltp ∧
  row.method_kind = ⟨MethodKind.SubmitPlayerRevealTokens.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitPlayerRevealTokens⟩ ∧
  row.is_active = M31.one

/-! ## submit_reconstruct_deck AIR -/

structure SubmitReconstructDeckMethodColumns where
  input_seat_index : M31
  input_reconstruct_state : M31
deriving Repr

def SubmitReconstructDeckMethodConstraints
    (row : CommonRow)
    (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat)
    (expected_reconstruct_state : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_state < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_reconstruct_state = nat_to_m31 expected_reconstruct_state hltp ∧
  ReconstructStateNotIdle ext.input_reconstruct_state ∧
  let pre_table := extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val
  let post_table := extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def SubmitReconstructDeckAirAcceptable
    (row : CommonRow)
    (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat)
    (expected_reconstruct_state : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_state < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.SubmitReconstructDeck ∧
  SubmitReconstructDeckMethodConstraints row ext expected_seat_index expected_reconstruct_state max_players hlt hltp ∧
  row.method_kind = ⟨MethodKind.SubmitReconstructDeck.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitReconstructDeck⟩ ∧
  row.is_active = M31.one

def extractJoinAndShuffleParamsFromAir (ext : JoinAndShuffleMethodColumns) : JoinAndShuffleParams := {
  seat_index := ext.input_seat_index.val
  deck_commitment := ext.input_new_deck_commitment_0.val
}

def extractLeaveWithProofParamsFromAir (ext : LeaveWithProofMethodColumns) : LeaveWithProofParams := {
  seat_index := ext.input_seat_index.val
  leave_kind := ext.input_leave_kind.val
}

def extractSubmitShuffleV2ParamsFromAir (ext : SubmitShuffleV2MethodColumns) : SubmitShuffleV2Params := {
  seat_index := ext.input_seat_index.val
  deck_commitment := ext.input_new_deck_commitment_0.val
}

def extractSubmitRevealTokensParamsFromAir (ext : SubmitRevealTokensMethodColumns) : SubmitRevealTokensParams := {
  seat_index := ext.input_seat_index.val
  reveal_phase := ext.input_reveal_phase.val
}

def extractSubmitReconstructDeckParamsFromAir (ext : SubmitReconstructDeckMethodColumns) : SubmitReconstructDeckParams := {
  seat_index := ext.input_seat_index.val
  reconstruct_phase := ext.input_reconstruct_state.val
}

end PokerLean
