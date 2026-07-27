import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.JoinTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.JoinTableAir

namespace PokerLean

set_option linter.unusedVariables false in

/-- # join_table AIR soundness 反例 -/

theorem join_table_air_not_sound :
  ∃ (row : CommonRow) (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (player : PlayerId)
    (hlt : expected_seat_index < M31_P),
    JoinTableAirAcceptable row ext expected_seat_index max_players hlt ∧
    ¬ ContractJoinTable
      (extractPreTableFromJoinTableAir row max_players)
      (extractJoinTableParamsFromAir ext player)
      (extractPostTableFromJoinTableAir row ext max_players expected_seat_index) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  let ext : JoinTableMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_buy_in := (M31.zero, M31.zero, M31.zero, M31.zero)
    input_player_addr := (M31.zero, M31.zero, M31.zero, M31.zero)
    input_seat_is_occupied := M31.zero
    output_seat_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.JoinTable.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinTable⟩
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
  let pre_table := extractPreTableFromJoinTableAir base_row 2
  let post_table := extractPostTableFromJoinTableAir base_row ext 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }
  refine ⟨row, ext, 0, 2, PlayerId.ofNat 1, hlt0, ?_, ?_⟩
  · -- JoinTableAirAcceptable
    unfold JoinTableAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.JoinTable.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinTable⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · -- JoinTableMethodConstraints
      unfold JoinTableMethodConstraints
      intro h_active
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      have h_rs : RoundStateEq row 0 M31_P_pos := by
        unfold RoundStateEq; simp [row]; unfold M31.zero; simp
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by
        simp [ext, nat_to_m31]
      have h_seat_empty : SeatEmpty ext.input_seat_is_occupied := by
        unfold SeatEmpty; simp [ext]
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_ver, h_rs, h_seat, h_seat_empty, h_src⟩
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = 1
      rfl
  · -- ¬ ContractJoinTable
    intro h
    rcases h with ⟨_, _, _, _, _, h_player, _⟩
    have h_contra :
      ((extractPostTableFromJoinTableAir row ext 2 0).get_seat 0 |>.player) ≠ PlayerId.ofNat 1 := by
        simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
              TexasPokerTable.get_seat, Seat.empty, EMPTY_PLAYER]
      <;> decide
    exact h_contra h_player

end PokerLean