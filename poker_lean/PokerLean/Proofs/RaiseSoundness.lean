import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Raise
import PokerLean.AIR.AirBase
import PokerLean.AIR.RaiseAir

namespace PokerLean

/-- raise AIR 不是 sound 的：在 ROUND_WAITING 状态下 raise 的反例 -/
theorem raise_air_not_sound :
  ∃ (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (expected_raise_to : Nat)
    (hlt : expected_seat_index < M31_P),
    RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to max_players ∧
    ¬ ContractRaise
      (extractPreTableFromRaiseAir row max_players)
      (extractRaiseParamsFromAir ext)
      (extractPostTableFromRaiseAir row ext max_players expected_seat_index) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : RaiseMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_raise_to := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_seat_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_seat_bet := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_all_in := M31.zero
    output_acted := M31.one
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Raise.toNat, MethodKind.toNat_lt_M31P MethodKind.Raise⟩
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
  let pre_table := extractPreTableFromRaiseAir base_row 2
  let post_table := extractPostTableFromRaiseAir base_row ext 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩

  · -- Part 1: RaiseAirAcceptable row ext 0 2 0 hlt0
    unfold RaiseAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨?_, ?_, ?_, ?_⟩
      · exact mul_sub_one_self_eq_zero row.is_active rfl
      · exact mul_sub_zero_self_eq_zero row.is_padding rfl
      · exact M31.mul_zero_right row.is_active
      · have hsub : M31.sub row.method_kind
          ⟨MethodKind.Raise.toNat, MethodKind.toNat_lt_M31P MethodKind.Raise⟩ = M31.zero := by
          simp [row]
          apply sub_self_eq_zero
        rw [hsub]
        apply M31.mul_zero_right
    · -- RaiseMethodConstraints
      unfold RaiseMethodConstraints
      intro h_active
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by simp [ext, nat_to_m31]
      have h_amt : ext.input_raise_to.1 = ⟨0 % 65536, M31_P_pos⟩ := by simp [ext]; rfl
      have h_acted : ext.output_acted = M31.one := by simp [ext]
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
      exact ⟨h_seat, h_amt, h_acted, h_ver, h_rs, h_rs_betting, h_src⟩
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = M31.one
      rfl

  · -- Part 2: ¬ ContractRaise ...
    intro h
    rcases h with ⟨_h_betting, _h_idx, _h_turn, h_participating, _⟩
    have h_seat_empty :
      (extractPreTableFromRaiseAir row 2).get_seat 0 = Seat.empty := by
        simp [extractPreTableFromRaiseAir, TexasPokerTable.get_seat, List.getD, List.replicate]
    have h_not_participating :
      ¬ ((extractPreTableFromRaiseAir row 2).get_seat 0 |>.is_participating) := by
        rw [h_seat_empty]
        simp [Seat.empty, Seat.is_participating, EMPTY_PLAYER, PlayerId.ofNat]
    exact h_not_participating h_participating

end PokerLean
