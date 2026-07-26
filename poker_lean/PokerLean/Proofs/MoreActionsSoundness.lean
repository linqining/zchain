import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
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
    AutoFoldAirAcceptable row ext expected_seat_index hlt expected_current_time ∧
    ¬ ContractAutoFold
      (extractPreTableFromActionAir row max_players MethodKind.AutoFold)
      (extractAutoFoldParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.AutoFold) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.AutoFold.toNat, MethodKind.toNat_lt_M31P MethodKind.AutoFold⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : AutoFoldMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_current_time := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_folded := M31.one
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
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
      intro _
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_time : ext.input_current_time.1 = ⟨0 % 65536, by unfold M31_P; omega⟩ := by simp [ext]; rfl
      have h_folded : ext.output_folded = M31.one := by simp [ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      have h_pot : PotUnchangedLimb0 row := by
        unfold PotUnchangedLimb0
        simp [row]
      exact ⟨h_seat, h_time, h_folded, h_ver, h_rs, h_pot⟩
    · simp [row]
    · rfl
  · -- ¬ ContractAutoFold
    intro h
    have hbetting :
      (extractPreTableFromActionAir row 2 MethodKind.AutoFold).round_state.is_betting_round := by
      rcases h with ⟨h1, _⟩; exact h1
    have hrs :
      (extractPreTableFromActionAir row 2 MethodKind.AutoFold).round_state = RoundState.ROUND_WAITING := by rfl
    rw [hrs] at hbetting
    exact RoundState.round_state_waiting_is_not_betting hbetting

/-- force_fold AIR 不是 sound 的：在 ROUND_WAITING 状态下 force_fold 的反例 -/
theorem force_fold_air_not_sound :
  ∃ (row : CommonRow) (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    ForceFoldAirAcceptable row ext expected_seat_index hlt ∧
    ¬ ContractForceFold
      (extractPreTableFromActionAir row max_players MethodKind.ForceFold)
      (extractForceFoldParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.ForceFold) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.ForceFold.toNat, MethodKind.toNat_lt_M31P MethodKind.ForceFold⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : ForceFoldMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_folded := M31.one
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
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
      intro _
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
      have h_pot : PotUnchangedLimb0 row := by
        unfold PotUnchangedLimb0
        simp [row]
      exact ⟨h_seat, h_folded, h_ver, h_rs, h_pot⟩
    · simp [row]
    · rfl
  · -- ¬ ContractForceFold
    intro h
    have hbetting :
      (extractPreTableFromActionAir row 2 MethodKind.ForceFold).round_state.is_betting_round := by
      rcases h with ⟨h1, _⟩; exact h1
    have hrs :
      (extractPreTableFromActionAir row 2 MethodKind.ForceFold).round_state = RoundState.ROUND_WAITING := by rfl
    rw [hrs] at hbetting
    exact RoundState.round_state_waiting_is_not_betting hbetting

/-- kick_player AIR 不是 sound 的：在空座位上 kick 的反例 -/
theorem kick_player_air_not_sound :
  ∃ (row : CommonRow) (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (expected_refund : Nat)
    (hlt : expected_seat_index < M31_P),
    KickPlayerAirAcceptable row ext expected_seat_index hlt expected_refund ∧
    ¬ ContractKickPlayer
      (extractPreTableFromActionAir row max_players MethodKind.KickPlayer)
      (extractKickPlayerParamsFromAir ext)
      (extractPostTableFromActionAir row max_players MethodKind.KickPlayer) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.KickPlayer.toNat, MethodKind.toNat_lt_M31P MethodKind.KickPlayer⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : KickPlayerMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_refund := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_kicked := M31.one
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
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
      intro _
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_refund : ext.output_refund.1 = ⟨0 % 65536, by unfold M31_P; omega⟩ := by simp [ext]; rfl
      have h_kicked : ext.output_kicked = M31.one := by simp [ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      exact ⟨h_seat, h_refund, h_kicked, h_ver, h_rs⟩
    · simp [row]
    · rfl
  · -- ¬ ContractKickPlayer: seat is not occupied (empty seats)
    intro h
    rcases h with ⟨_h_seat, h_occupied, _⟩
    -- The extracted pre-table has all empty seats, so seat.player = EMPTY_PLAYER.
    -- This contradicts h_occupied which requires the seat to be occupied.
    have h_player_eq :
        ((extractPreTableFromActionAir row 2 MethodKind.KickPlayer).get_seat
            (extractKickPlayerParamsFromAir ext).seat_index).player = EMPTY_PLAYER := by
      simp [extractPreTableFromActionAir, extractKickPlayerParamsFromAir, ext,
            TexasPokerTable.get_seat, Seat.empty, List.getD, List.replicate, nat_to_m31]
    -- h_occupied (after Coe Bool Prop) says is_occupied = true, i.e. player ≠ EMPTY_PLAYER.
    -- We just proved player = EMPTY_PLAYER, contradiction.
    have h_not_eq :
        ((extractPreTableFromActionAir row 2 MethodKind.KickPlayer).get_seat
            (extractKickPlayerParamsFromAir ext).seat_index).player ≠ EMPTY_PLAYER := by
      have := h_occupied
      simp [Seat.is_occupied] at this
      exact this
    exact absurd h_player_eq h_not_eq

end PokerLean
