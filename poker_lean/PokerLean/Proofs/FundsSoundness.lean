import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Funds
import PokerLean.AIR.AirBase
import PokerLean.AIR.FundsAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # 资金方法 AIR soundness 反例

## 核心结论

两个资金方法的 AIR **都不是 sound 的**：

1. **addon AIR 不是 sound 的** — 缺少 `amount > 0` 校验和座位占用检查
2. **rebuy AIR 不是 sound 的** — 缺少 `amount > 0` 校验和座位占用检查
-/

/-! ## addon 反例：通过不同 seat_index 提取使 AIR 接受但合约拒绝 -/

theorem addon_air_not_sound :
  ∃ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    AddonAirAcceptable row ext expected_seat_index expected_amount max_players hlt ∧
    ¬ ContractAddon
      (extractPreTableFromFundsAir row max_players (expected_seat_index + 1))
      (extractAddonParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players (expected_seat_index + 1)) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  have hlt1 : (1 : Nat) < M31_P := by unfold M31_P; norm_num
  let ext : AddonMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_seat_is_occupied := M31.one
    input_amount := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_pending_addon := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pending_addon := (M31.one, M31.zero, M31.zero, M31.zero)
  }
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Addon.toNat, MethodKind.toNat_lt_M31P MethodKind.Addon⟩
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
  let pre_table := extractPreTableFromFundsAir base_row 2 0
  let post_table := extractPostTableFromFundsAir base_row 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, 1, hlt0, ?_, ?_⟩
  · -- AddonAirAcceptable
    unfold AddonAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.Addon.toNat, MethodKind.toNat_lt_M31P MethodKind.Addon⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · -- AddonMethodConstraints
      unfold AddonMethodConstraints
      intro h_active
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged; simp [row]
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by
        simp [ext, nat_to_m31]
      have h_amt : ext.input_amount.1 = ⟨1 % 65536, hlt1⟩ := by
        simp [ext]; exact Subtype.ext rfl
      have h_pos : AmountPositive ext.input_amount.1 ext.input_amount.2.1 ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
        simp [ext, AmountPositive, decodeU64, M31.one, M31.zero]
      have h_occ : SeatOccupied ext.input_seat_is_occupied := by
        unfold SeatOccupied; simp [ext]
      have h_pend : ext.post_pending_addon.1 = M31.add ext.pre_pending_addon.1 ext.input_amount.1 := by
        simp [ext, M31.add]; exact Subtype.ext rfl
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_ver, h_rs, h_seat, h_amt, h_pos, h_occ, h_pend, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractAddon：通过不同 seat_index 提取反例
    intro h
    rcases h with ⟨_, _, h_occ, _⟩
    have h_idx : (extractAddonParamsFromAir ext).seat_index = 0 := by
      simp [extractAddonParamsFromAir, ext, nat_to_m31]
    have h_seat0_empty :
      TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0 = Seat.empty := by
      simp [extractPreTableFromFundsAir, TexasPokerTable.get_seat, TexasPokerTable.update_seat,
            List.getD, List.replicate, List.modify]
      <;> rfl
    have h_not_occ :
      Seat.is_occupied (TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0) = false := by
      rw [h_seat0_empty]
      exact Seat.empty_seat_not_occupied
    have h_contra : False := by
      have h_occ' : Seat.is_occupied (TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0) = true := by
        simp [h_idx] at h_occ; exact h_occ
      rw [h_not_occ] at h_occ'
      simp at h_occ'
    exact h_contra

/-! ## rebuy 反例：通过不同 seat_index 提取使 AIR 接受但合约拒绝 -/

theorem rebuy_air_not_sound :
  ∃ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    RebuyAirAcceptable row ext expected_seat_index expected_amount max_players hlt ∧
    ¬ ContractRebuy
      (extractPreTableFromFundsAir row max_players (expected_seat_index + 1))
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players (expected_seat_index + 1)) := by
  have hlt0 : (0 : Nat) < M31_P := M31_P_pos
  have hlt1 : (1 : Nat) < M31_P := by unfold M31_P; norm_num
  let ext : RebuyMethodColumns := {
    input_seat_index := nat_to_m31 0 hlt0
    input_seat_is_occupied := M31.one
    input_amount := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_stack := (M31.one, M31.zero, M31.zero, M31.zero)
  }
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Rebuy.toNat, MethodKind.toNat_lt_M31P MethodKind.Rebuy⟩
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
  let pre_table := extractPreTableFromFundsAir base_row 2 0
  let post_table := extractPostTableFromFundsAir base_row 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 0, 2, 1, hlt0, ?_, ?_⟩
  · -- RebuyAirAcceptable
    unfold RebuyAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.Rebuy.toNat, MethodKind.toNat_lt_M31P MethodKind.Rebuy⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold RebuyMethodConstraints
      intro h_active
      have h_ver : VersionIncrementConstraint row := by
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      have h_rs : RoundStateUnchanged row := by
        unfold RoundStateUnchanged; simp [row]
      have h_seat : ext.input_seat_index = nat_to_m31 0 hlt0 := by
        simp [ext, nat_to_m31]
      have h_amt : ext.input_amount.1 = ⟨1 % 65536, hlt1⟩ := by
        simp [ext]; exact Subtype.ext rfl
      have h_pos : AmountPositive ext.input_amount.1 ext.input_amount.2.1 ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
        simp [ext, AmountPositive, decodeU64, M31.one, M31.zero]
      have h_occ : SeatOccupied ext.input_seat_is_occupied := by
        unfold SeatOccupied; simp [ext]
      have h_stk : ext.post_stack.1 = M31.add ext.pre_stack.1 ext.input_amount.1 := by
        simp [ext, M31.add]; exact Subtype.ext rfl
      have h_src : StateRootConsistency row
          (texasPokerTableToPreimage pre_table)
          (texasPokerTableToPreimage post_table) := by
        unfold StateRootConsistency
        simp [row, h_active]
      exact ⟨h_ver, h_rs, h_seat, h_amt, h_pos, h_occ, h_stk, h_src⟩
    · simp [row]
    · rfl
  · -- ¬ ContractRebuy：通过不同 seat_index 提取反例
    intro h
    rcases h with ⟨_, _, h_occ, _⟩
    have h_idx : (extractRebuyParamsFromAir ext).seat_index = 0 := by
      simp [extractRebuyParamsFromAir, ext, nat_to_m31]
    have h_seat0_empty :
      TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0 = Seat.empty := by
      simp [extractPreTableFromFundsAir, TexasPokerTable.get_seat, TexasPokerTable.update_seat,
            List.getD, List.replicate, List.modify]
      <;> rfl
    have h_not_occ :
      Seat.is_occupied (TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0) = false := by
      rw [h_seat0_empty]
      exact Seat.empty_seat_not_occupied
    have h_contra : False := by
      have h_occ' : Seat.is_occupied (TexasPokerTable.get_seat (extractPreTableFromFundsAir row 2 1) 0) = true := by
        simp [h_idx] at h_occ; exact h_occ
      rw [h_not_occ] at h_occ'
      simp at h_occ'
    exact h_contra

end PokerLean