import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.MoreActions
import PokerLean.AIR.AirBase
import PokerLean.AIR.MoreActionsAir

namespace PokerLean

/-! # auto_fold / force_fold / kick_player 的 soundness 反例 -/

/-- auto_fold AIR 不是 sound 的：在 ROUND_WAITING 状态下 auto_fold 的反例 -/
theorem auto_fold_air_not_sound :
  ∃ (row : CommonRow) (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (expected_current_time : Nat)
    (hlt : expected_seat_index < M31_P),
    AutoFoldAirAcceptable row ext expected_seat_index max_players hlt expected_current_time ∧
    ¬ ContractAutoFold
      (extractPreTableFromActionAir row max_players MethodKind.AutoFold)
      (extractAutoFoldParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.AutoFold) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : AutoFoldMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_current_time := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_folded := M31.one
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.AutoFold.toNat, MethodKind.toNat_lt_M31P MethodKind.AutoFold⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.one
    post_round_state := M31.one
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromActionAir base_row 2 MethodKind.AutoFold
  let post_table := extractPostTableFromActionAir base_row 2 MethodKind.AutoFold
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩
  · -- AutoFoldAirAcceptable
    unfold AutoFoldAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.AutoFold.toNat, MethodKind.toNat_lt_M31P MethodKind.AutoFold⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold AutoFoldMethodConstraints
      intro h_active
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_time : ext.input_current_time.1 = ⟨0 % 65536, M31_P_pos⟩ := by simp [ext]; rfl
      have h_folded : ext.output_folded = M31.one := by simp [ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      have h_rs_betting : RoundStateIsBetting row := by
        have h_val : row.pre_round_state.val = 1 := by
          have hrs : row.pre_round_state = M31.one := by simp [row]
          rw [hrs]
          simp [M31.one]
        exact round_state_1_is_betting row h_active h_val
      have h_pot : PotUnchangedLimb0 row := by
        unfold PotUnchangedLimb0
        simp [row]
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_seat, h_time, h_folded, h_ver, h_rs, h_rs_betting, h_pot, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractAutoFold
    intro h
    rcases h with ⟨_, _, _, _, h_folded, _⟩
    have h_idx : (extractAutoFoldParamsFromAir ext).seat_index = 0 := by
      simp [extractAutoFoldParamsFromAir, ext, nat_to_m31]
    have h_empty_post :
      (extractPostTableFromActionAir row 2 MethodKind.AutoFold).get_seat 0 = Seat.empty := by
        simp [TexasPokerTable.get_seat, extractPostTableFromActionAir, extractPreTableFromActionAir, List.getD, List.replicate]
    simp [h_idx] at h_folded
    have h_contra : False := by
      simp [h_empty_post, Seat.empty, Seat.folded] at h_folded
    exact h_contra

/-- force_fold AIR 不是 sound 的：在 ROUND_WAITING 状态下 force_fold 的反例 -/
theorem force_fold_air_not_sound :
  ∃ (row : CommonRow) (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    ForceFoldAirAcceptable row ext expected_seat_index max_players hlt ∧
    ¬ ContractForceFold
      (extractPreTableFromActionAir row max_players MethodKind.ForceFold)
      (extractForceFoldParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.ForceFold) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : ForceFoldMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    output_folded := M31.one
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.ForceFold.toNat, MethodKind.toNat_lt_M31P MethodKind.ForceFold⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.one
    post_round_state := M31.one
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromActionAir base_row 2 MethodKind.ForceFold
  let post_table := extractPostTableFromActionAir base_row 2 MethodKind.ForceFold
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, hlt0, ?_, ?_⟩
  · -- ForceFoldAirAcceptable
    unfold ForceFoldAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.ForceFold.toNat, MethodKind.toNat_lt_M31P MethodKind.ForceFold⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold ForceFoldMethodConstraints
      intro h_active
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_folded : ext.output_folded = M31.one := by simp [ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      have h_rs_betting : RoundStateIsBetting row := by
        have h_val : row.pre_round_state.val = 1 := by
          have hrs : row.pre_round_state = M31.one := by simp [row]
          rw [hrs]
          simp [M31.one]
        exact round_state_1_is_betting row h_active h_val
      have h_pot : PotUnchangedLimb0 row := by
        unfold PotUnchangedLimb0
        simp [row]
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_seat, h_folded, h_ver, h_rs, h_rs_betting, h_pot, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractForceFold
    intro h
    rcases h with ⟨_, _, _, _, h_post_folded, _⟩
    have h_idx : (extractForceFoldParamsFromAir ext).seat_index = 0 := by
      simp [extractForceFoldParamsFromAir, ext, nat_to_m31]
    have h_false :
      ((extractPostTableFromActionAir row 2 MethodKind.ForceFold).get_seat 0 |>.folded) = false := by
        simp [extractPostTableFromActionAir, extractPreTableFromActionAir, TexasPokerTable.get_seat, List.getD, List.replicate, Seat.empty]
    have h_contra : False := by
      simp [h_idx] at h_post_folded
      rw [h_false] at h_post_folded
      simp at h_post_folded
    exact h_contra

/-- kick_player AIR 不是 sound 的：在空座位上 kick 的反例 -/
theorem kick_player_air_not_sound :
  ∃ (row : CommonRow) (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (expected_refund : Nat)
    (hlt : expected_seat_index < M31_P),
    KickPlayerAirAcceptable row ext expected_seat_index max_players hlt expected_refund ∧
    ¬ ContractKickPlayer
      (extractPreTableFromActionAir row max_players MethodKind.KickPlayer)
      (extractKickPlayerParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.KickPlayer) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : KickPlayerMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_seat_is_occupied := M31.one
    output_refund := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_kicked := M31.one
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.KickPlayer.toNat, MethodKind.toNat_lt_M31P MethodKind.KickPlayer⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.one
    post_round_state := M31.one
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromKickPlayerAir base_row 2 0
  let post_table := extractPostTableFromKickPlayerAir base_row ext 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩
  · -- KickPlayerAirAcceptable
    unfold KickPlayerAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.KickPlayer.toNat, MethodKind.toNat_lt_M31P MethodKind.KickPlayer⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold KickPlayerMethodConstraints
      intro h_active
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_refund1 : ext.output_refund.1 = ⟨0 % 65536, by unfold M31_P; omega⟩ := by
        simp [ext]
        simp [M31.zero]
      have h_kicked : ext.output_kicked = M31.one := by simp [ext]
      have h_occ : SeatOccupied ext.input_seat_is_occupied := by
        simp [SeatOccupied, ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      have h_rs_betting : RoundStateIsBetting row := by
        have h_val : row.pre_round_state.val = 1 := by
          have hrs : row.pre_round_state = M31.one := by simp [row]
          rw [hrs]
          simp [M31.one]
        exact round_state_1_is_betting row h_active h_val
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_seat, h_refund1, h_kicked, h_occ, h_ver, h_rs, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractKickPlayer: seat is not occupied (empty seats)
    intro h
    rcases h with ⟨_h_seat, h_occupied, _⟩
    have h_player_eq :
        ((extractPreTableFromActionAir row 2 MethodKind.KickPlayer).get_seat
            (extractKickPlayerParamsFromAir ext).seat_index).player = EMPTY_PLAYER := by
      simp [extractPreTableFromActionAir, extractKickPlayerParamsFromAir, ext,
            TexasPokerTable.get_seat, Seat.empty, List.getD, List.replicate, nat_to_m31]
    have h_not_eq :
        ((extractPreTableFromActionAir row 2 MethodKind.KickPlayer).get_seat
            (extractKickPlayerParamsFromAir ext).seat_index).player ≠ EMPTY_PLAYER := by
      have := h_occupied
      simp [Seat.is_occupied] at this
      exact this
    exact absurd h_player_eq h_not_eq

end PokerLean