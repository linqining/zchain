import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.JoinTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.JoinTableAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # join_table AIR soundness 反例

## 核心结论

`join_table` AIR **不是 sound 的**。AIR 仅约束 `seat_index == input.seat_index`，
但缺少以下关键约束：

1. **缺少 round_state gating**：不校验 `pre.round_state == ROUND_WAITING`
   - 反例：在 `ROUND_PREFLOP`（下注轮）状态下也能"加入"
2. **缺少座位空性检查**：允许加入已占用的座位
3. **缺少 buy_in >= big_blind 校验**
4. **缺少资金守恒**：不校验 `chip_pool += buy_in`
5. **缺少 version 递增校验**

本文件构造反例 1（最根本的缺陷）：在 `ROUND_PREFLOP` 状态下执行 join_table。
-/

/-- join_table AIR 不是 sound 的：在 ROUND_PREFLOP 状态下 join 的反例 -/
theorem join_table_air_not_sound :
  ∃ (row : CommonRow) (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (player : PlayerId)
    (hlt : expected_seat_index < M31_P),
    JoinTableAirAcceptable row ext expected_seat_index hlt ∧
    ¬ ContractJoinTable
      (extractPreTableFromJoinTableAir row max_players)
      (extractJoinTableParamsFromAir ext player)
      (extractPostTableFromJoinTableAir row ext max_players expected_seat_index) := by
  -- 构造反例行：pre_round_state = 1（ROUND_PREFLOP）
  -- AIR 不约束 round_state，因此接受此行
  -- 但合约要求 round_state == ROUND_WAITING，因此违反合约语义
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.JoinTable.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinTable⟩
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
  let ext : JoinTableMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_buy_in := (M31.zero, M31.zero, M31.zero, M31.zero)
    input_player_addr := (M31.zero, M31.zero, M31.zero, M31.zero)
    output_seat_stack := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
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
      intro _
      simp [ext, nat_to_m31]
    · -- row.method_kind = ...
      simp [row]
    · -- row.is_active = 1
      rfl
  · -- ¬ ContractJoinTable：pre.round_state ≠ ROUND_WAITING
    intro h
    -- 从合约语义中提取 pre.round_state = ROUND_WAITING
    have h_rs :
      (extractPreTableFromJoinTableAir row 2).round_state = RoundState.ROUND_WAITING := by
      rcases h with ⟨h_rs_pre, _⟩
      exact h_rs_pre
    -- 但 extractPreTableFromJoinTableAir 的 round_state = fromNat 1 = ROUND_PREFLOP
    -- （row.pre_round_state = M31.one，其 .val = 1）
    have h_actual :
      (extractPreTableFromJoinTableAir row 2).round_state = RoundState.ROUND_PREFLOP := by
      simp [extractPreTableFromJoinTableAir, row]
      exact RoundState.fromNat_one
    -- ROUND_PREFLOP ≠ ROUND_WAITING
    rw [h_actual] at h_rs
    exact absurd h_rs (by decide)

end PokerLean
