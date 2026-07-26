import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
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

/-! ## addon 反例：amount = 0（合约要求 amount > 0） -/

theorem addon_air_not_sound :
  ∃ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    AddonAirAcceptable row ext expected_seat_index expected_amount hlt ∧
    ¬ ContractAddon
      (extractPreTableFromFundsAir row max_players)
      (extractAddonParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players) := by
  -- 构造反例行：amount = 0
  -- AIR 约束 post_pending_0 = pre_pending_0 + 0 = pre_pending_0，满足
  -- 但合约要求 amount > 0
  let row : CommonRow := {
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
  let ext : AddonMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_amount := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_pending_addon := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pending_addon := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩
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
      intro _
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · show ext.input_amount.1 = ⟨0 % 65536, by unfold M31_P; omega⟩
        simp [ext]
        exact Subtype.ext rfl
      · show ext.post_pending_addon.1 = M31.add ext.pre_pending_addon.1 ext.input_amount.1
        simp [ext, M31.add]
        exact Subtype.ext rfl
    · simp [row]
    · rfl
  · -- ¬ ContractAddon：amount = 0，不满足 > 0
    intro h
    rcases h with ⟨_, h_amt, _⟩
    -- amount = decodeU64(0,0,0,0) = 0
    have h_amount_zero :
      (extractAddonParamsFromAir ext).amount = 0 := by
      unfold extractAddonParamsFromAir ext decodeU64
      simp [M31.zero]
    rw [h_amount_zero] at h_amt
    exact absurd h_amt (Nat.lt_irrefl 0)

/-! ## rebuy 反例：amount = 0（合约要求 amount > 0） -/

theorem rebuy_air_not_sound :
  ∃ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    RebuyAirAcceptable row ext expected_seat_index expected_amount hlt ∧
    ¬ ContractRebuy
      (extractPreTableFromFundsAir row max_players)
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players) := by
  -- 构造反例行：amount = 0
  let row : CommonRow := {
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
  let ext : RebuyMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_amount := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩
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
      intro _
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · show ext.input_amount.1 = ⟨0 % 65536, by unfold M31_P; omega⟩
        simp [ext]
        exact Subtype.ext rfl
      · show ext.post_stack.1 = M31.add ext.pre_stack.1 ext.input_amount.1
        simp [ext, M31.add]
        exact Subtype.ext rfl
    · simp [row]
    · rfl
  · -- ¬ ContractRebuy：amount = 0，不满足 > 0
    intro h
    rcases h with ⟨_, h_amt, _⟩
    have h_amount_zero :
      (extractRebuyParamsFromAir ext).amount = 0 := by
      unfold extractRebuyParamsFromAir ext decodeU64
      simp [M31.zero]
    rw [h_amount_zero] at h_amt
    exact absurd h_amt (Nat.lt_irrefl 0)

end PokerLean
