import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.LeaveTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.LeaveTableAir

namespace PokerLean

set_option linter.unusedVariables false in

/-- # leave_table AIR soundness 反例 -/

theorem leave_table_air_not_sound :
  ∃ (row : CommonRow) (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    LeaveTableAirAcceptable row ext expected_seat_index max_players hlt ∧
    ¬ ContractLeaveTable
      (extractPreTableFromLeaveTableAir row max_players (expected_seat_index + 1))
      (extractLeaveTableParamsFromAir ext)
      (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : LeaveTableMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_seat_is_occupied := M31.one
    output_refund := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.LeaveTable.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveTable⟩
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
  let pre_table := extractPreTableFromLeaveTableAir base_row 2 0
  let post_table := extractPostTableFromLeaveTableAir base_row ext 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }
  refine ⟨row, ext, 0, 2, hlt0, ?_, ?_⟩
  · -- LeaveTableAirAcceptable
    unfold LeaveTableAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.LeaveTable.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveTable⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · -- LeaveTableMethodConstraints
      unfold LeaveTableMethodConstraints
      intro h_active
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      have h_rs : RoundStateEq row 0 M31_P_pos := by
        unfold RoundStateEq; simp [row]; unfold M31.zero; simp
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by
        simp [ext, nat_to_m31]
      have h_seat_occ : SeatOccupied ext.input_seat_is_occupied := by
        unfold SeatOccupied; simp [ext]
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_ver, h_rs, h_seat, h_seat_occ, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractLeaveTable
    intro h
    rcases h with ⟨_, _, h_occ, _⟩
    have h_idx : (extractLeaveTableParamsFromAir ext).seat_index = 0 := by
      simp [extractLeaveTableParamsFromAir, ext, nat_to_m31]
    have h_not_occ :
        ((extractPreTableFromLeaveTableAir row 2 1).get_seat 0 |>.is_occupied) = false := by
      simp [extractPreTableFromLeaveTableAir, Seat.is_occupied, Seat.empty, EMPTY_PLAYER,
            TexasPokerTable.get_seat, TexasPokerTable.update_seat, List.getD, List.replicate, List.modify]
    have h_contra : False := by
      have h_occ' : ((extractPreTableFromLeaveTableAir row 2 1).get_seat 0).is_occupied = true := by
        simp [h_idx] at h_occ
        exact h_occ
      rw [h_not_occ] at h_occ'
      simp at h_occ'
    exact h_contra

end PokerLean