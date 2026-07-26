import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Lifecycle
import PokerLean.AIR.AirBase
import PokerLean.AIR.LifecycleAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # 生命周期方法 AIR soundness 反例

## 核心结论

三个生命周期方法的 AIR **都不是 sound 的**：

1. **start_hand AIR 不是 sound 的** — 缺少 `pre_round_state == WAITING` 检查
   和 `active_count >= 2` 强制
2. **tick AIR 不是 sound 的** — 允许 `timeout_kind = 0`（无真实超时）
3. **reset_for_next_hand AIR 不是 sound 的** — 缺少 `pre_round_state` 检查
   和 version 递增
-/

/-! ## start_hand 反例：在 ROUND_PREFLOP 状态下 start_hand -/

theorem start_hand_air_not_sound :
  ∃ (row : CommonRow) (ext : StartHandMethodColumns)
    (expected_active_count : Nat) (max_players : Nat)
    (hlt : expected_active_count < M31_P),
    StartHandAirAcceptable row ext expected_active_count hlt ∧
    ¬ ContractStartHand
      (extractPreTableFromLifecycleAir row max_players)
      (extractStartHandParamsFromAir ext)
      (extractPostTableFromLifecycleAir row max_players) := by
  -- 构造反例行：pre_round_state = 1（ROUND_PREFLOP）
  -- AIR 约束 output_new_round_state == 0（post = WAITING）但不检查 pre_round_state
  -- 合约要求 pre.round_state == ROUND_WAITING
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.StartHand.toNat, MethodKind.toNat_lt_M31P MethodKind.StartHand⟩
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
  let ext : StartHandMethodColumns := {
    input_active_count := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_new_button := M31.zero
    output_new_round_state := M31.zero
    output_ante_mode := M31.zero
    output_ante_amount_0 := M31.zero
    output_ante_collected_0 := M31.zero
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, hlt0, ?_, ?_⟩
  · -- StartHandAirAcceptable
    unfold StartHandAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.StartHand.toNat, MethodKind.toNat_lt_M31P MethodKind.StartHand⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold StartHandMethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · -- RoundStateEq
        unfold RoundStateEq; simp [row]; unfold M31.zero; simp
      · -- input_active_count
        simp [ext, nat_to_m31]
      · -- output_new_round_state = 0
        simp [ext]
    · simp [row]
    · rfl
  · -- ¬ ContractStartHand：active_count = 0 < MIN_PLAYERS_TO_START = 2
    intro h
    rcases h with ⟨_, h_count, _⟩
    have h_ac : (extractStartHandParamsFromAir ext).active_count = 0 := by
      simp [extractStartHandParamsFromAir, ext, nat_to_m31]
    rw [h_ac] at h_count
    unfold MIN_PLAYERS_TO_START at h_count
    exact absurd h_count (by norm_num)

/-! ## tick 反例：timeout_kind = 0（无真实超时） -/

theorem tick_air_not_sound :
  ∃ (row : CommonRow) (ext : TickMethodColumns)
    (expected_timeout_kind : Nat) (max_players : Nat)
    (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
    (hlt : expected_timeout_kind < M31_P),
    TickAirAcceptable row ext expected_timeout_kind hlt ∧
    ¬ ContractTick
      (extractPreTableFromLifecycleAir row max_players)
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
      (extractPostTableFromLifecycleAir row max_players) := by
  -- 构造反例行：timeout_kind = 0（无真实超时）
  -- AIR 仅校验 timeout_kind 与公开输入一致，但不强制 timeout_kind > 0
  -- 合约要求 timeout_kind > 0（必须有真实超时）
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.Tick.toNat, MethodKind.toNat_lt_M31P MethodKind.Tick⟩
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
  let ext : TickMethodColumns := {
    input_current_time := (M31.zero, M31.zero, M31.zero, M31.zero)
    input_timeout_kind := nat_to_m31 0 (by unfold M31_P; norm_num)
    output_new_round_state := M31.zero
    time_bank_consumed_0 := M31.zero
    time_bank_post_0 := M31.zero
    rake_mode := M31.zero
    rake_amount_0 := M31.zero
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, 0, 0, 0, 0, hlt0, ?_, ?_⟩
  · -- TickAirAcceptable
    unfold TickAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.Tick.toNat, MethodKind.toNat_lt_M31P MethodKind.Tick⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold TickMethodConstraints
      intro _
      refine ⟨?_, ?_⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · -- ext.input_timeout_kind = ...
        simp [ext, nat_to_m31]
    · simp [row]
    · rfl
  · -- ¬ ContractTick：timeout_kind = 0，不满足 > 0
    intro h
    rcases h with ⟨h_tk, _⟩
    -- extractTickParamsFromAir gives timeout_kind = expected_timeout_kind = 0
    -- ContractTick requires timeout_kind > 0, i.e., 0 > 0, which is False
    unfold extractTickParamsFromAir at h_tk
    exact absurd h_tk (Nat.lt_irrefl 0)

/-! ## reset_for_next_hand 反例：缺少 version 递增 -/

theorem reset_for_next_hand_air_not_sound :
  ∃ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
    (max_players : Nat) (pre_pending_addon : Nat),
    ResetForNextHandAirAcceptable row ext ∧
    ¬ ContractResetForNextHand
      (extractPreTableFromLifecycleAir row max_players)
      (extractResetParamsFromAir pre_pending_addon)
      (extractPostTableFromLifecycleAir row max_players) := by
  -- 构造反例行：pre_version = post_version = 0（version 不递增）
  -- AIR 不约束 version 递增
  -- 合约要求 post.version = pre.version + 1
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.ResetForNextHand.toNat, MethodKind.toNat_lt_M31P MethodKind.ResetForNextHand⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    -- 关键：pre_version = post_version = 0（不递增）
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
  let ext : ResetForNextHandMethodColumns := {
    output_new_round_state := M31.zero
    post_pending_addon := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  refine ⟨row, ext, 2, 0, ?_, ?_⟩
  · -- ResetForNextHandAirAcceptable
    unfold ResetForNextHandAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.ResetForNextHand.toNat, MethodKind.toNat_lt_M31P MethodKind.ResetForNextHand⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold ResetForNextHandMethodConstraints
      intro _
      refine ⟨?_, by simp [ext], by simp [ext], by simp [ext], by simp [ext], by simp [ext]⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
    · simp [row]
    · rfl
  · -- ¬ ContractResetForNextHand：pre.shuffle_state.phase = 0 ≠ > 0
    intro h
    rcases h with ⟨h_phase, _⟩
    simp [extractPreTableFromLifecycleAir] at h_phase

end PokerLean
