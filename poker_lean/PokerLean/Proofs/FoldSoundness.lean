import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Fold
import PokerLean.AIR.AirBase
import PokerLean.AIR.FoldAir

namespace PokerLean

theorem fold_air_not_sound :
  ∃ (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    FoldAirAcceptable row ext expected_seat_index hlt ∧
    ¬ ContractFold
      (extractPreTableFromFoldAir row max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Fold.toNat, MethodKind.toNat_lt_M31P MethodKind.Fold⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : FoldMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_folded := M31.one
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, hlt0, ?_, ?_⟩

  · -- Part 1: FoldAirAcceptable row ext 0 hlt0
    unfold FoldAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨?_, ?_, ?_, ?_⟩
      · exact mul_sub_one_self_eq_zero row.is_active rfl
      · exact mul_sub_zero_self_eq_zero row.is_padding rfl
      · exact M31.mul_zero_right row.is_active
      · have hsub : M31.sub row.method_kind
          ⟨MethodKind.Fold.toNat, MethodKind.toNat_lt_M31P MethodKind.Fold⟩ = M31.zero := by
          simp [row]
          apply sub_self_eq_zero
        rw [hsub]
        apply M31.mul_zero_right
    · -- FoldMethodConstraints
      unfold FoldMethodConstraints
      intro h_active
      simp [ext, nat_to_m31]
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = M31.one
      rfl

  · -- Part 2: ¬ ContractFold ...
    intro h
    have hbetting :
      (extractPreTableFromFoldAir row 2).round_state.is_betting_round := by
      rcases h with ⟨h1, _⟩
      exact h1
    have hrs :
      (extractPreTableFromFoldAir row 2).round_state = RoundState.ROUND_WAITING := by rfl
    rw [hrs] at hbetting
    exact RoundState.round_state_waiting_is_not_betting hbetting

end PokerLean