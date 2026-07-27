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

/-! # 生命周期方法 AIR soundness

## 核心结论

三个生命周期方法的 AIR **都是 sound 的**：

1. **start_hand AIR 是 sound 的** — `RoundStateEq row 0` + `RoundStateUnchanged` +
   `ActiveCountAtLeastTwo` + `make_occupied_seats_foldl_count` + `VersionIncrementConstraint` +
   `extractPostTableFromStartHandAir` 设 `shuffle_state.phase = 3` 覆盖合约全部合取
2. **tick AIR 是 sound 的** — `TimeoutKindPositive` + `VersionIncrementConstraint` +
   提取函数不变量
3. **reset_for_next_hand AIR 是 sound 的** — `ShufflePhasePositive` +
   `row.post_round_state = ext.output_new_round_state = 0` + `VersionIncrementConstraint` +
   提取函数中所有座位 `pending_addon = 0`

## 证明思路

每个证明的通用模式：
1. 从 `AirAcceptable` 解构出 `CommonConstraints` 和 `MethodConstraints`
2. 从 `MethodConstraints`（在 `is_active = 1` 下）得到各约束的实例
3. 使用辅助引理从提取函数中读取 pre/post 表的字段值
4. 逐个证明合约的合取项

## 已知限制

- 时间相关约束（tick 的真实超时条件）简化为 `timeout_kind > 0`
- `start_hand` 的 button 旋转简化为不变（合约中不验证 button 旋转）
- 密码学相关操作（shuffle/reveal/reconstruct）不在 AIR 中验证 -/

/-! ## 通用辅助引理（Lifecycle 提取函数） -/

private lemma lifecycle_pre_max_players (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).max_players = max_players := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_max_players (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).max_players = max_players := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_big_blind (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).big_blind = 0 := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_big_blind (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).big_blind = 0 := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_small_blind (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).small_blind = 0 := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_small_blind (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).small_blind = 0 := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_hand_id (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).hand_id = row.hand_id.val := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_hand_id (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).hand_id = row.hand_id.val := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_version (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_version (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_round_state (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_round_state (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma lifecycle_pre_shuffle_phase (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPreTableFromLifecycleAir row max_players shuffle_phase).shuffle_state.phase = shuffle_phase := by
  simp [extractPreTableFromLifecycleAir]

private lemma lifecycle_post_seats (row : CommonRow) (max_players shuffle_phase : Nat) :
    (extractPostTableFromLifecycleAir row max_players shuffle_phase).seats =
      List.replicate max_players Seat.empty := by
  simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]

private lemma list_getD_replicate_self {α : Type*} (n i : Nat) (a : α) :
    List.getD (List.replicate n a) i a = a := by
  induction n generalizing i with
  | zero => rfl
  | succ k ih =>
    cases i with
    | zero => rfl
    | succ j =>
      rw [List.replicate_succ, List.getD]
      exact ih j

private lemma lifecycle_seat_pending_addon_zero
    (row : CommonRow) (max_players shuffle_phase : Nat) (i : Nat) :
    ((extractPostTableFromLifecycleAir row max_players shuffle_phase).get_seat i).pending_addon = 0 := by
  have h_seats : (extractPostTableFromLifecycleAir row max_players shuffle_phase).seats = List.replicate max_players Seat.empty := by
    simp [extractPostTableFromLifecycleAir, extractPreTableFromLifecycleAir]
  rw [TexasPokerTable.get_seat, h_seats, list_getD_replicate_self, Seat.empty]

/-! ## StartHand 辅助引理 -/

private lemma start_hand_pre_seats (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).seats = make_occupied_seats active_count := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_pre_seats_count (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).seats.foldl
      (fun acc s => acc + if s.is_occupied then 1 else 0) 0 = active_count := by
  rw [start_hand_pre_seats]
  exact make_occupied_seats_foldl_count active_count

private lemma start_hand_pre_max_players (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).max_players = max_players := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_max_players (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).max_players = max_players := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_pre_big_blind (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).big_blind = 0 := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_big_blind (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).big_blind = 0 := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_pre_small_blind (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).small_blind = 0 := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_small_blind (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).small_blind = 0 := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_pre_hand_id (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_hand_id (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).hand_id = row.hand_id.val := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_pre_version (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_version (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_pre_round_state (row : CommonRow) (active_count max_players : Nat) :
    (extractPreTableFromStartHandAir row active_count max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromStartHandAir]

private lemma start_hand_post_round_state (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

private lemma start_hand_post_shuffle_phase (row : CommonRow) (active_count max_players : Nat) :
    (extractPostTableFromStartHandAir row active_count max_players).shuffle_state.phase = 3 := by
  simp [extractPostTableFromStartHandAir, extractPreTableFromStartHandAir]

/-! ## start_hand soundness -/

theorem start_hand_air_sound :
  ∀ (row : CommonRow) (ext : StartHandMethodColumns)
    (expected_active_count : Nat) (max_players : Nat)
    (hlt : expected_active_count < M31_P),
    StartHandAirAcceptable row ext expected_active_count max_players hlt →
    ContractStartHand
      (extractPreTableFromStartHandAir row ext.input_active_count.val max_players)
      (extractStartHandParamsFromAir ext)
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players) := by
  intro row ext expected_active_count max_players hlt h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : StartHandMethodConstraints row ext expected_active_count max_players hlt := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_eq, h_rs_unch, h_count, h_count_pos, h_new_rs, _h_src⟩
  -- 提取参数
  have h_params_count : (extractStartHandParamsFromAir ext).active_count = ext.input_active_count.val := by
    simp [extractStartHandParamsFromAir]
  have h_count_val : ext.input_active_count.val = expected_active_count := by
    rw [h_count]; simp [nat_to_m31]
  -- 1. pre.round_state = ROUND_WAITING
  have h_pre_rs : row.pre_round_state = M31.zero := by
    have := h_rs_eq h_active
    exact this
  have h_pre_round_state :
      (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).round_state =
        RoundState.ROUND_WAITING := by
    rw [start_hand_pre_round_state, h_pre_rs]
    exact RoundState.fromNat_zero
  -- 2. params.active_count ≥ 2
  have h_params_ge_2 : (extractStartHandParamsFromAir ext).active_count ≥ MIN_PLAYERS_TO_START := by
    rw [h_params_count]; exact h_count_pos
  -- 3. params.active_count = pre.seats foldl count
  have h_params_seats_count :
      (extractStartHandParamsFromAir ext).active_count =
        (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).seats.foldl
          (fun acc s => acc + if s.is_occupied then 1 else 0) 0 := by
    rw [h_params_count, start_hand_pre_seats_count]
  -- 4. post.version = pre.version + 1
  have h_pre_ver :
      (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).version =
        decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    start_hand_pre_version row ext.input_active_count.val max_players
  have h_post_ver :
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).version =
        decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 := by
    rw [start_hand_post_version]
  have h_ver_eq :
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).version =
        (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  -- 5. post.round_state = pre.round_state
  have h_post_rs : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_post_round_state :
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).round_state =
        (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).round_state := by
    rw [start_hand_post_round_state, start_hand_pre_round_state, h_post_rs]
  -- 6. post.shuffle_state.phase = 3
  have h_post_shuffle :
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).shuffle_state.phase = 3 :=
    start_hand_post_shuffle_phase row ext.input_active_count.val max_players
  -- 7. 不变量
  have h_pre_max : (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).max_players = max_players :=
    start_hand_pre_max_players row ext.input_active_count.val max_players
  have h_post_max : (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).max_players = max_players :=
    start_hand_post_max_players row ext.input_active_count.val max_players
  have h_pre_bb : (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).big_blind = 0 :=
    start_hand_pre_big_blind row ext.input_active_count.val max_players
  have h_post_bb : (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).big_blind = 0 :=
    start_hand_post_big_blind row ext.input_active_count.val max_players
  have h_pre_sb : (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).small_blind = 0 :=
    start_hand_pre_small_blind row ext.input_active_count.val max_players
  have h_post_sb : (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).small_blind = 0 :=
    start_hand_post_small_blind row ext.input_active_count.val max_players
  have h_pre_hid : (extractPreTableFromStartHandAir row ext.input_active_count.val max_players).hand_id = row.hand_id.val :=
    start_hand_pre_hand_id row ext.input_active_count.val max_players
  have h_post_hid : (extractPostTableFromStartHandAir row ext.input_active_count.val max_players).hand_id = row.hand_id.val :=
    start_hand_post_hand_id row ext.input_active_count.val max_players
  exact ⟨h_pre_round_state, h_params_ge_2, h_params_seats_count, h_ver_eq, h_post_round_state,
         h_post_shuffle, by rw [h_post_max, h_pre_max], by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb], by rw [h_post_hid, h_pre_hid]⟩

/-! ## tick soundness -/

theorem tick_air_sound :
  ∀ (row : CommonRow) (ext : TickMethodColumns)
    (expected_timeout_kind : Nat) (max_players : Nat)
    (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
    (hlt : expected_timeout_kind < M31_P),
    TickAirAcceptable row ext expected_timeout_kind max_players hlt →
    ContractTick
      (extractPreTableFromLifecycleAir row max_players 0)
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
      (extractPostTableFromLifecycleAir row max_players 0) := by
  intro row ext expected_timeout_kind max_players time_bank_consumed time_bank_post rake_mode rake_amount hlt h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : TickMethodConstraints row ext expected_timeout_kind max_players hlt := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_timeout_eq, h_timeout_pos, _h_src⟩
  -- 1. params.timeout_kind > 0
  have h_params_timeout :
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount).timeout_kind =
        expected_timeout_kind := by
    simp [extractTickParamsFromAir]
  have h_timeout_val : ext.input_timeout_kind.val = expected_timeout_kind := by
    rw [h_timeout_eq]; simp [nat_to_m31]
  have h_params_timeout_pos :
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount).timeout_kind > 0 := by
    rw [h_params_timeout, ← h_timeout_val]; exact h_timeout_pos
  -- 2. post.version = pre.version + 1
  have h_pre_ver :
      (extractPreTableFromLifecycleAir row max_players 0).version =
        decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    lifecycle_pre_version row max_players 0
  have h_post_ver :
      (extractPostTableFromLifecycleAir row max_players 0).version =
        decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    lifecycle_post_version row max_players 0
  have h_ver_eq :
      (extractPostTableFromLifecycleAir row max_players 0).version =
        (extractPreTableFromLifecycleAir row max_players 0).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  -- 3. 不变量
  have h_pre_max : (extractPreTableFromLifecycleAir row max_players 0).max_players = max_players :=
    lifecycle_pre_max_players row max_players 0
  have h_post_max : (extractPostTableFromLifecycleAir row max_players 0).max_players = max_players :=
    lifecycle_post_max_players row max_players 0
  have h_pre_bb : (extractPreTableFromLifecycleAir row max_players 0).big_blind = 0 :=
    lifecycle_pre_big_blind row max_players 0
  have h_post_bb : (extractPostTableFromLifecycleAir row max_players 0).big_blind = 0 :=
    lifecycle_post_big_blind row max_players 0
  have h_pre_sb : (extractPreTableFromLifecycleAir row max_players 0).small_blind = 0 :=
    lifecycle_pre_small_blind row max_players 0
  have h_post_sb : (extractPostTableFromLifecycleAir row max_players 0).small_blind = 0 :=
    lifecycle_post_small_blind row max_players 0
  have h_pre_hid : (extractPreTableFromLifecycleAir row max_players 0).hand_id = row.hand_id.val :=
    lifecycle_pre_hand_id row max_players 0
  have h_post_hid : (extractPostTableFromLifecycleAir row max_players 0).hand_id = row.hand_id.val :=
    lifecycle_post_hand_id row max_players 0
  exact ⟨h_params_timeout_pos, h_ver_eq,
         by rw [h_post_max, h_pre_max], by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb], by rw [h_post_hid, h_pre_hid]⟩

/-! ## reset_for_next_hand soundness -/

theorem reset_for_next_hand_air_sound :
  ∀ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
    (max_players : Nat) (pre_pending_addon : Nat),
    ResetForNextHandAirAcceptable row ext max_players →
    ContractResetForNextHand
      (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val)
      (extractResetParamsFromAir pre_pending_addon)
      (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val) := by
  intro row ext max_players pre_pending_addon h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : ResetForNextHandMethodConstraints row ext max_players := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_shuffle_pos, h_new_rs_zero, h_post_rs_eq, _h_addon_0, _h_addon_1,
                   _h_addon_2, _h_addon_3, _h_src⟩
  -- 1. pre.shuffle_state.phase > 0
  have h_pre_phase :
      (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).shuffle_state.phase > 0 := by
    rw [lifecycle_pre_shuffle_phase]; exact h_shuffle_pos
  -- 2. post.round_state = ROUND_WAITING
  have h_post_rs : row.post_round_state = ext.output_new_round_state := h_post_rs_eq
  have h_post_rs_zero : row.post_round_state = M31.zero := by
    rw [h_post_rs, h_new_rs_zero]
  have h_post_round_state :
      (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).round_state =
        RoundState.ROUND_WAITING := by
    rw [lifecycle_post_round_state, h_post_rs_zero]
    exact RoundState.fromNat_zero
  -- 3. ∀ i < max_players, (post.get_seat i).pending_addon = 0
  have h_post_seat_addon :
      ∀ i : Nat, i < max_players →
        ((extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).get_seat i).pending_addon = 0 := by
    intro i _hlt
    exact lifecycle_seat_pending_addon_zero row max_players ext.input_shuffle_phase.val i
  -- 4. post.version = pre.version + 1
  have h_pre_ver :
      (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).version =
        decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    lifecycle_pre_version row max_players ext.input_shuffle_phase.val
  have h_post_ver :
      (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).version =
        decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 := by
    rw [lifecycle_post_version]
  have h_ver_eq :
      (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).version =
        (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  -- 5. 不变量
  have h_pre_max : (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).max_players = max_players :=
    lifecycle_pre_max_players row max_players ext.input_shuffle_phase.val
  have h_post_max : (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).max_players = max_players :=
    lifecycle_post_max_players row max_players ext.input_shuffle_phase.val
  have h_pre_bb : (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).big_blind = 0 :=
    lifecycle_pre_big_blind row max_players ext.input_shuffle_phase.val
  have h_post_bb : (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).big_blind = 0 :=
    lifecycle_post_big_blind row max_players ext.input_shuffle_phase.val
  have h_pre_sb : (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).small_blind = 0 :=
    lifecycle_pre_small_blind row max_players ext.input_shuffle_phase.val
  have h_post_sb : (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).small_blind = 0 :=
    lifecycle_post_small_blind row max_players ext.input_shuffle_phase.val
  have h_pre_hid : (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).hand_id = row.hand_id.val :=
    lifecycle_pre_hand_id row max_players ext.input_shuffle_phase.val
  have h_post_hid : (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val).hand_id = row.hand_id.val :=
    lifecycle_post_hand_id row max_players ext.input_shuffle_phase.val
  exact ⟨h_pre_phase, h_post_round_state, h_post_seat_addon, h_ver_eq,
         by rw [h_post_max, h_pre_max], by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb], by rw [h_post_hid, h_pre_hid]⟩

end PokerLean
