import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.LeaveTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.LeaveTableAir

namespace PokerLean

/-! # leave_table AIR soundness

    闭合的 Gap：
    - RoundStateEq(0) + RoundStateUnchanged：仅在 WAITING 状态离座
    - SeatOccupied：目标座位必须被占用
    - RefundConservation：refund = seat.stack + seat.pending_addon
    - ChipPoolLeaveConservation：post_chip_pool = pre_chip_pool - seat.stack
    - AddonPoolLeaveConservation：post_addon_pool = pre_addon_pool - seat.pending_addon
    - VersionIncrementConstraint：version += 1
    - post 状态提取：目标座位正确清空为 Seat.empty
-/

/-! ## 辅助引理（pre 状态提取） -/

private lemma leave_pre_round_state
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_max_players
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_version
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_chip_pool
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).chip_pool =
      decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
        ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2 := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_addon_pool
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_big_blind
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_small_blind
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

private lemma leave_pre_hand_id
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPreTableFromLeaveTableAir, TexasPokerTable.update_seat]

/-! ## 辅助引理（post 状态提取） -/

private lemma leave_post_version
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_round_state
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_chip_pool
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).chip_pool =
      decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
        ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2 := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_addon_pool
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
        ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_max_players
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_big_blind
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_small_blind
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

private lemma leave_post_hand_id
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
        TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

/-- pre 状态中目标座位为已占用（player=1, stack=input_seat_stack, pending_addon=input_seat_pending_addon）。 -/
private lemma leave_pre_get_seat_at_index
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).get_seat seat_index =
      { player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
            ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2,
        bet := 0, total_bet := 0,
        folded := false, all_in := false, acted_this_round := false,
        is_waiting := false, left_during_hand := false,
        pending_addon := decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
            ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2,
        time_bank_ms := 0 } := by
  simp only [extractPreTableFromLeaveTableAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

/-- pre 状态中非目标座位为 Seat.empty。 -/
private lemma leave_pre_get_seat_other
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).get_seat i = Seat.empty := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromLeaveTableAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- post 状态中目标座位为 Seat.empty（离开后清空）。 -/
private lemma leave_post_get_seat_at_index
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).get_seat seat_index =
      Seat.empty := by
  simp only [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

/-- post 状态中非目标座位与 pre 相同。 -/
private lemma leave_post_get_seat_other
    (row : CommonRow) (ext : LeaveTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromLeaveTableAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromLeaveTableAir row ext max_players seat_index).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromLeaveTableAir, extractPreTableFromLeaveTableAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-! ## 参数提取引理 -/

private lemma leave_params_seat
    (ext : LeaveTableMethodColumns) :
    (extractLeaveTableParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractLeaveTableParamsFromAir; rfl

/-! ## leave_table AIR soundness 主定理

    闭合的 Gap：
    - Gap 1 (RoundStateEq(0))：仅在 WAITING 状态离座
    - SeatOccupied：目标座位必须被占用
    - RefundConservation：refund = stack + pending_addon
    - ChipPoolLeaveConservation：post_chip_pool = pre_chip_pool - stack
    - AddonPoolLeaveConservation：post_addon_pool = pre_addon_pool - pending_addon
    - VersionIncrementConstraint：version += 1
    - post 状态提取：目标座位正确清空为 Seat.empty -/
theorem leave_table_air_sound :
  ∀ (row : CommonRow) (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    LeaveTableAirAcceptable row ext expected_seat_index max_players hlt →
    ContractLeaveTable
      (extractPreTableFromLeaveTableAir row ext max_players expected_seat_index)
      (extractLeaveTableParamsFromAir ext)
      (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index max_players hlt hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : LeaveTableMethodConstraints row ext expected_seat_index max_players hlt :=
    h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_eq, h_rs_unch, h_seat_eq, _h_occ,
                    _h_refund, h_chip_pool, h_addon_pool, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractLeaveTableParamsFromAir ext).seat_index = expected_seat_index := by
    rw [leave_params_seat, h_seat_val]
  have h_seat_lt : expected_seat_index < max_players := hseat
  -- 4. 约束前提展开（active 成立）
  have h_rs_val : row.pre_round_state.val = 0 := by
    rw [h_rs_eq h_active]
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_chip_pool' : decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
                        ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2 =
                      decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
                        ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2 -
                      decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
                        ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2 := h_chip_pool
  have h_addon_pool' : decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
                         ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 =
                       decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
                         ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 -
                       decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
                         ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2 :=
    h_addon_pool
  -- 5. 座位级引理
  have h_pre_seat : (extractPreTableFromLeaveTableAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
            ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2,
        bet := 0, total_bet := 0,
        folded := false, all_in := false, acted_this_round := false,
        is_waiting := false, left_during_hand := false,
        pending_addon := decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
            ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2,
        time_bank_ms := 0 } :=
    leave_pre_get_seat_at_index row ext max_players expected_seat_index h_seat_lt
  have h_post_seat : (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      Seat.empty :=
    leave_post_get_seat_at_index row ext max_players expected_seat_index h_seat_lt
  -- 6. 证明 ContractLeaveTable 的 21 个合取
  unfold ContractLeaveTable
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state = ROUND_WAITING
    rw [leave_pre_round_state, h_rs_val]; rfl
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, leave_pre_max_players]; exact hseat
  · -- 3. (pre.get_seat params.seat_index).is_occupied = true
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_occupied, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 4. (post.get_seat params.seat_index).player = EMPTY_PLAYER
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 5. (post.get_seat ...).stack = 0
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 6. (post.get_seat ...).bet = 0
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 7. (post.get_seat ...).total_bet = 0
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 8. (post.get_seat ...).folded = false
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 9. (post.get_seat ...).all_in = false
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 10. (post.get_seat ...).is_waiting = false
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 11. (post.get_seat ...).left_during_hand = false
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 12. (post.get_seat ...).acted_this_round = false
    rw [h_params_seat, h_post_seat]
    rfl
  · -- 13. ∀ i, i ≠ seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [leave_pre_max_players] at h_lt
    exact leave_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 14. post.chip_pool = pre.chip_pool - (pre.get_seat ...).stack
    rw [leave_post_chip_pool, leave_pre_chip_pool]
    rw [h_params_seat, h_pre_seat]
    exact h_chip_pool'
  · -- 15. post.addon_pool = pre.addon_pool - (pre.get_seat ...).pending_addon
    rw [leave_post_addon_pool, leave_pre_addon_pool]
    rw [h_params_seat, h_pre_seat]
    exact h_addon_pool'
  · -- 16. post.version = pre.version + 1
    rw [leave_post_version, leave_pre_version]; exact h_ver'
  · -- 17. post.round_state = pre.round_state
    rw [leave_post_round_state, leave_pre_round_state, h_rs']
  · -- 18. post.max_players = pre.max_players
    rw [leave_post_max_players, leave_pre_max_players]
  · -- 19. post.big_blind = pre.big_blind
    rw [leave_post_big_blind, leave_pre_big_blind]
  · -- 20. post.small_blind = pre.small_blind
    rw [leave_post_small_blind, leave_pre_small_blind]
  · -- 21. post.hand_id = pre.hand_id
    rw [leave_post_hand_id, leave_pre_hand_id]

end PokerLean
