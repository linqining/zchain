import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Call
import PokerLean.AIR.AirBase
import PokerLean.AIR.CallAir

namespace PokerLean

/-- call AIR 不是 sound 的：在 ROUND_WAITING 状态下 call 的反例 -/
theorem call_air_not_sound :
  ∃ (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (expected_call_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    CallAirAcceptable row ext expected_seat_index hlt expected_call_amount ∧
    ¬ ContractCall
      (extractPreTableFromCallAir row max_players)
      (extractCallParamsFromAir ext)
      (extractPostTableFromCallAir row ext max_players expected_seat_index) := by
  -- 构造反例：pre_round_state = 0 (ROUND_WAITING)
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Call.toNat, MethodKind.toNat_lt_M31P MethodKind.Call⟩
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
  let ext : CallMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_call_amount := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_seat_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_seat_bet := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_all_in := M31.zero
    output_acted := M31.one
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩

  · -- Part 1: CallAirAcceptable
    unfold CallAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨?_, ?_, ?_, ?_⟩
      · exact mul_sub_one_self_eq_zero row.is_active rfl
      · exact mul_sub_zero_self_eq_zero row.is_padding rfl
      · exact M31.mul_zero_right row.is_active
      · have hsub : M31.sub row.method_kind
          ⟨MethodKind.Call.toNat, MethodKind.toNat_lt_M31P MethodKind.Call⟩ = M31.zero := by
          simp [row]; apply sub_self_eq_zero
        rw [hsub]; apply M31.mul_zero_right
    · -- CallMethodConstraints
      unfold CallMethodConstraints
      intro _h_active
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_amt : ext.input_call_amount.1 = ⟨0 % 65536, by unfold M31_P; omega⟩ := by simp [ext]; rfl
      have h_acted : ext.output_acted = M31.one := by simp [ext]
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint
        simp [row]
        unfold decodeU64
        simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged
        simp [row]
      exact ⟨h_seat, h_amt, h_acted, h_ver, h_rs⟩
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = M31.one
      rfl

  · -- Part 2: ¬ ContractCall ...
    intro h
    have hbetting :
      (extractPreTableFromCallAir row 2).round_state.is_betting_round := by
      rcases h with ⟨h1, _⟩
      exact h1
    have hrs :
      (extractPreTableFromCallAir row 2).round_state = RoundState.ROUND_WAITING := by rfl
    rw [hrs] at hbetting
    exact RoundState.round_state_waiting_is_not_betting hbetting

end PokerLean
