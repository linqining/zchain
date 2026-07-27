import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
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
    StartHandAirAcceptable row ext expected_active_count max_players hlt ∧
    ¬ ContractStartHand
      (extractPreTableFromLifecycleAir row max_players 0)
      (extractStartHandParamsFromAir ext)
      (extractPostTableFromLifecycleAir row max_players 0) := by
  have hlt0 : (2 : Nat) < M31_P := by unfold M31_P; norm_num
  let ext : StartHandMethodColumns := {
    input_active_count := nat_to_m31 2 hlt0
    output_new_button := M31.zero
    output_new_round_state := M31.zero
    output_ante_mode := M31.zero
    output_ante_amount_0 := M31.zero
    output_ante_collected_0 := M31.zero
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
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
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromLifecycleAir base_row 2 0
  let post_table := extractPostTableFromLifecycleAir base_row 2 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 2, 2, hlt0, ?_, ?_⟩
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
      intro h_active
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · -- RoundStateEq
        unfold RoundStateEq; simp [row]; unfold M31.zero; simp
      · -- input_active_count
        simp [ext, nat_to_m31]
      · -- ActiveCountAtLeastTwo
        simp [ext, ActiveCountAtLeastTwo, nat_to_m31]
      · -- output_new_round_state = 0
        simp [ext]
      · -- StateRootConsistency
        have h_src : StateRootConsistency row
            (texasPokerTableToPreimage pre_table)
            (texasPokerTableToPreimage post_table) := by
          unfold StateRootConsistency
          simp [row, h_active]
        exact h_src
    · simp [row]
    · rfl
  · -- ¬ ContractStartHand：active_count = 2 ≠ 实际空座位数 = 0
    intro h
    rcases h with ⟨_, _, h_count, _⟩
    have h_ac : (extractStartHandParamsFromAir ext).active_count = 2 := by
      simp [extractStartHandParamsFromAir, ext, nat_to_m31]
    rw [h_ac] at h_count
    have h_fold :
        (extractPreTableFromLifecycleAir row 2 0).seats.foldl
          (fun acc s => acc + if s.is_occupied then 1 else 0) 0 = 0 := by
      simp [extractPreTableFromLifecycleAir, List.foldl, List.replicate, Seat.empty, Seat.is_occupied]
    rw [h_fold] at h_count
    simp at h_count

/-! ## tick 反例：timeout_kind = 0（无真实超时） -/

theorem tick_air_not_sound :
  ∃ (row : CommonRow) (ext : TickMethodColumns)
    (expected_timeout_kind : Nat) (max_players : Nat)
    (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
    (hlt : expected_timeout_kind < M31_P),
    TickAirAcceptable row ext expected_timeout_kind max_players hlt ∧
    ¬ ContractTick
      (extractPreTableFromLifecycleAir row max_players 0)
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
      (extractPostTableFromLifecycleAir row (max_players + 1) 0) := by
  have hlt0 : (1 : Nat) < M31_P := by unfold M31_P; norm_num
  let ext : TickMethodColumns := {
    input_current_time := (M31.zero, M31.zero, M31.zero, M31.zero)
    input_timeout_kind := nat_to_m31 1 hlt0
    output_new_round_state := M31.zero
    time_bank_consumed_0 := M31.zero
    time_bank_post_0 := M31.zero
    rake_mode := M31.zero
    rake_amount_0 := M31.zero
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
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
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromLifecycleAir base_row 0 0
  let post_table := extractPostTableFromLifecycleAir base_row 0 0
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

  refine ⟨row, ext, 1, 0, 0, 0, 0, 0, hlt0, ?_, ?_⟩
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
      intro h_active
      refine ⟨?_, ?_, ?_, ?_⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · -- ext.input_timeout_kind = ...
        simp [ext, nat_to_m31]
      · -- TimeoutKindPositive
        simp [ext, TimeoutKindPositive, nat_to_m31]
      · -- StateRootConsistency
        have h_src : StateRootConsistency row
            (texasPokerTableToPreimage pre_table)
            (texasPokerTableToPreimage post_table) := by
          unfold StateRootConsistency
          simp [row, h_active]
        exact h_src
    · simp [row]
    · rfl
  · -- ¬ ContractTick：post.max_players ≠ pre.max_players
    intro h
    rcases h with ⟨_, _, h_max, _⟩
    have h_pre_max : (extractPreTableFromLifecycleAir row 0 0).max_players = 0 := by
      simp [extractPreTableFromLifecycleAir]
    have h_post_max : (extractPostTableFromLifecycleAir row 1 0).max_players = 1 := by
      simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]
    rw [h_post_max, h_pre_max] at h_max
    simp at h_max

/-! ## reset_for_next_hand 反例：缺少 version 递增 -/

theorem reset_for_next_hand_air_not_sound :
  ∃ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
    (max_players : Nat) (pre_pending_addon : Nat),
    ResetForNextHandAirAcceptable row ext max_players ∧
    ¬ ContractResetForNextHand
      (extractPreTableFromLifecycleAir row max_players 0)
      (extractResetParamsFromAir pre_pending_addon)
      (extractPostTableFromLifecycleAir row (max_players + 1) 0) := by
  have hlt1 : (1 : Nat) < M31_P := by unfold M31_P; norm_num
  let ext : ResetForNextHandMethodColumns := {
    input_shuffle_phase := nat_to_m31 1 hlt1
    output_new_round_state := M31.zero
    post_pending_addon := (M31.zero, M31.zero, M31.zero, M31.zero)
  }
  -- Step 1: Create base row with placeholder state roots
  let base_row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.ResetForNextHand.toNat, MethodKind.toNat_lt_M31P MethodKind.ResetForNextHand⟩
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
  -- Step 2: Extract tables and compute correct state roots
  let pre_table := extractPreTableFromLifecycleAir base_row 2 1
  let post_table := extractPostTableFromLifecycleAir base_row 2 1
  let pre_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage pre_table)
  let post_sr : StateRoot := poseidon_hash (texasPokerTableToPreimage post_table)
  -- Step 3: Create final row with correct state roots
  let row : CommonRow := { base_row with pre_state_root := pre_sr, post_state_root := post_sr }

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
      intro h_active
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- VersionIncrementConstraint
        unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · -- ShufflePhasePositive
        simp [ext, ShufflePhasePositive, nat_to_m31]
      · -- output_new_round_state = 0
        simp [ext]
      · -- post_pending_addon.1 = 0
        simp [ext]
      · -- post_pending_addon.2.1 = 0
        simp [ext]
      · -- post_pending_addon.2.2.1 = 0
        simp [ext]
      · -- post_pending_addon.2.2.2 = 0
        simp [ext]
      · -- StateRootConsistency
        have h_src : StateRootConsistency row
            (texasPokerTableToPreimage pre_table)
            (texasPokerTableToPreimage post_table) := by
          unfold StateRootConsistency
          simp [row, h_active]
        exact h_src
    · simp [row]
    · rfl
  · -- ¬ ContractResetForNextHand：pre.shuffle_state.phase = 0 ≠ > 0
    intro h
    rcases h with ⟨h_phase, _, _, _⟩
    have h_pre_phase : (extractPreTableFromLifecycleAir row 2 0).shuffle_state.phase = 0 := by
      simp [extractPreTableFromLifecycleAir]
    rw [h_pre_phase] at h_phase
    simp at h_phase

end PokerLean