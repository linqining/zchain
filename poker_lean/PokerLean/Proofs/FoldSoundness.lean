import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
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
    FoldAirAcceptable row ext expected_seat_index max_players hlt ∧
    ¬ ContractFold
      (extractPreTableFromFoldAir row max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : FoldMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    output_folded := M31.one
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Fold.toNat, MethodKind.toNat_lt_M31P MethodKind.Fold⟩
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
  let pre_table := extractPreTableFromFoldAir base_row 2
  let post_table := extractPostTableFromFoldAir base_row ext 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, hlt0, ?_, ?_⟩

  · -- Part 1: FoldAirAcceptable row ext 0 2 hlt0
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
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = M31.one
      rfl

  · -- Part 2: ¬ ContractFold ...
    intro h
    rcases h with ⟨_h_betting, _h_idx, _h_turn, h_participating, _⟩
    have h_seat_empty :
      (extractPreTableFromFoldAir row 2).get_seat 0 = Seat.empty := by
        simp [extractPreTableFromFoldAir, TexasPokerTable.get_seat, List.getD, List.replicate]
    have h_not_participating :
      ¬ ((extractPreTableFromFoldAir row 2).get_seat 0 |>.is_participating) := by
        rw [h_seat_empty]
        simp [Seat.empty, Seat.is_participating, EMPTY_PLAYER, PlayerId.ofNat]
    exact h_not_participating h_participating

end PokerLean
