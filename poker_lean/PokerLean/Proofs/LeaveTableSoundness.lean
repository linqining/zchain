import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.LeaveTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.LeaveTableAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # leave_table AIR soundness 反例

## 核心结论

`leave_table` AIR **不是 sound 的**。AIR 仅约束 `seat_index == input.seat_index`，
但缺少以下关键约束：

1. **缺少 round_state gating**：不校验 `pre.round_state == ROUND_WAITING`
2. **缺少座位占用检查**：允许 leave 一个空座位
3. **缺少资金守恒**：不校验 chip_pool/addon_pool 扣减
4. **缺少 version 递增校验**

本文件构造反例 1：在 `ROUND_PREFLOP` 状态下执行 leave_table。
-/

/-- leave_table AIR 不是 sound 的：在 ROUND_PREFLOP 状态下 leave 的反例 -/
theorem leave_table_air_not_sound :
  ∃ (row : CommonRow) (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    LeaveTableAirAcceptable row ext expected_seat_index hlt ∧
    ¬ ContractLeaveTable
      (extractPreTableFromLeaveTableAir row max_players)
      (extractLeaveTableParamsFromAir ext)
      (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) := by
  -- 构造反例行：pre_round_state = 1（ROUND_PREFLOP）
  -- AIR 不约束 round_state，因此接受此行
  -- 但合约要求 round_state == ROUND_WAITING，因此违反合约语义
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.LeaveTable.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveTable⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    -- 关键：pre_round_state = 1 表示 ROUND_PREFLOP（非 WAITING）
    pre_round_state := M31.one
    post_round_state := M31.one
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : LeaveTableMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_refund := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
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
    · unfold LeaveTableMethodConstraints
      intro _
      simp [ext, nat_to_m31]
    · simp [row]
    · rfl
  · -- ¬ ContractLeaveTable：pre.round_state ≠ ROUND_WAITING
    intro h
    have h_rs :
      (extractPreTableFromLeaveTableAir row 2).round_state = RoundState.ROUND_WAITING := by
      rcases h with ⟨h_rs_pre, _⟩
      exact h_rs_pre
    have h_actual :
      (extractPreTableFromLeaveTableAir row 2).round_state = RoundState.ROUND_PREFLOP := by
      simp [extractPreTableFromLeaveTableAir, row]
      exact RoundState.fromNat_one
    rw [h_actual] at h_rs
    exact absurd h_rs (by decide)

end PokerLean
