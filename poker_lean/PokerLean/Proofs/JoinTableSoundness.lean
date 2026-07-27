import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.JoinTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.JoinTableAir

namespace PokerLean

/-! # join_table AIR soundness

    闭合的 Gap：
    - RoundStateEq(0) + RoundStateUnchanged：仅在 WAITING 状态入座
    - SeatEmpty：目标座位必须为空
    - BuyInGeBigBlind：买入金额 ≥ 大盲注
    - ChipPoolConservation：post_chip_pool = pre_chip_pool + buy_in
    - PlayerAddrNonEmpty：玩家地址 ≠ 0（防止以 EMPTY_PLAYER 入座）
    - VersionIncrementConstraint：version += 1
    - post 状态提取：目标座位正确填充 player/stack/folded 等字段
-/

/-! ## 辅助引理（pre 状态提取） -/

private lemma join_pre_round_state
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_max_players
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_version
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_big_blind
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).big_blind =
      decodeU64 ext.input_big_blind.1 ext.input_big_blind.2.1
        ext.input_big_blind.2.2.1 ext.input_big_blind.2.2.2 := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_small_blind
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_chip_pool
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).chip_pool =
      decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
        ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2 := by
  simp [extractPreTableFromJoinTableAir]

private lemma join_pre_hand_id
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromJoinTableAir]

/-! ## 辅助引理（post 状态提取） -/

private lemma join_post_version
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_round_state
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_chip_pool
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).chip_pool =
      decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
        ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2 := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_max_players
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_big_blind
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).big_blind =
      decodeU64 ext.input_big_blind.1 ext.input_big_blind.2.1
        ext.input_big_blind.2.2.1 ext.input_big_blind.2.2.2 := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_small_blind
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

private lemma join_post_hand_id
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
        TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

/-- pre 状态中所有座位均为 Seat.empty（因为 pre 不使用 update_seat）。 -/
private lemma join_pre_get_seat
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (i : Nat) :
    (extractPreTableFromJoinTableAir row ext max_players).get_seat i = Seat.empty := by
  simp only [extractPreTableFromJoinTableAir, TexasPokerTable.get_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?, List.getElem?_replicate]
  split_ifs <;> rfl

/-- post 状态中目标座位的值。 -/
private lemma join_post_get_seat_at_index
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).get_seat seat_index =
      { player := PlayerId.ofNat (decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
            ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2),
        stack := decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
            ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2,
        bet := 0,
        total_bet := 0,
        folded := false,
        all_in := false,
        acted_this_round := false,
        is_waiting := false,
        left_during_hand := false,
        pending_addon := 0,
        time_bank_ms := 0 } := by
  simp only [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

/-- post 状态中非目标座位与 pre 相同。 -/
private lemma join_post_get_seat_other
    (row : CommonRow) (ext : JoinTableMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromJoinTableAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromJoinTableAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromJoinTableAir, extractPreTableFromJoinTableAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-! ## 参数提取引理 -/

private lemma join_params_seat
    (ext : JoinTableMethodColumns) :
    (extractJoinTableParamsFromAir' ext).seat_index = ext.input_seat_index.val := by
  unfold extractJoinTableParamsFromAir'; rfl

private lemma join_params_buy_in
    (ext : JoinTableMethodColumns) :
    (extractJoinTableParamsFromAir' ext).buy_in =
      decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
        ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2 := by
  unfold extractJoinTableParamsFromAir'; rfl

private lemma join_params_player
    (ext : JoinTableMethodColumns) :
    (extractJoinTableParamsFromAir' ext).player =
      PlayerId.ofNat (decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
        ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2) := by
  unfold extractJoinTableParamsFromAir'; rfl

/-! ## join_table AIR soundness 主定理

    闭合的 Gap：
    - Gap 1 (RoundStateEq(0))：仅在 WAITING 状态入座
    - SeatEmpty：目标座位必须为空
    - BuyInGeBigBlind：买入金额 ≥ 大盲注
    - ChipPoolConservation：post_chip_pool = pre_chip_pool + buy_in
    - PlayerAddrNonEmpty：玩家地址 ≠ 0（防止以 EMPTY_PLAYER 入座）
    - VersionIncrementConstraint：version += 1
    - post 状态提取：目标座位正确填充 player/stack/folded 等字段 -/
theorem join_table_air_sound :
  ∀ (row : CommonRow) (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    JoinTableAirAcceptable row ext expected_seat_index max_players hlt →
    ContractJoinTable
      (extractPreTableFromJoinTableAir row ext max_players)
      (extractJoinTableParamsFromAir' ext)
      (extractPostTableFromJoinTableAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index max_players hlt hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : JoinTableMethodConstraints row ext expected_seat_index max_players hlt :=
    h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_eq, h_rs_unch, h_seat_eq, _h_seat_empty,
                    h_buy_in, h_chip_pool, h_player_nonempty, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractJoinTableParamsFromAir' ext).seat_index = expected_seat_index := by
    rw [join_params_seat, h_seat_val]
  have h_seat_lt : expected_seat_index < max_players := hseat
  -- 4. 约束前提展开（active 成立）
  have h_rs_val : row.pre_round_state.val = 0 := by
    rw [h_rs_eq h_active]
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_buy_in' : decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
                     ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2 ≥
                   decodeU64 ext.input_big_blind.1 ext.input_big_blind.2.1
                     ext.input_big_blind.2.2.1 ext.input_big_blind.2.2.2 := h_buy_in
  have h_chip_pool' : decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
                        ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2 =
                      decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
                        ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2 +
                      decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
                        ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2 := h_chip_pool
  have h_player_ne : decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
                       ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2 ≠ 0 :=
    h_player_nonempty
  -- 5. 座位级引理
  have h_pre_seat : (extractPreTableFromJoinTableAir row ext max_players).get_seat expected_seat_index =
      Seat.empty := join_pre_get_seat row ext max_players expected_seat_index
  have h_post_seat : (extractPostTableFromJoinTableAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { player := PlayerId.ofNat (decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
            ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2),
        stack := decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
            ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2,
        bet := 0, total_bet := 0,
        folded := false, all_in := false, acted_this_round := false,
        is_waiting := false, left_during_hand := false,
        pending_addon := 0, time_bank_ms := 0 } :=
    join_post_get_seat_at_index row ext max_players expected_seat_index h_seat_lt
  -- 6. 证明 ContractJoinTable 的 21 个合取
  unfold ContractJoinTable
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state = ROUND_WAITING
    rw [join_pre_round_state, h_rs_val]; rfl
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, join_pre_max_players]; exact h_seat_lt
  · -- 3. (pre.get_seat params.seat_index).player = EMPTY_PLAYER
    rw [h_params_seat, h_pre_seat]
    rfl
  · -- 4. params.buy_in ≥ pre.big_blind
    rw [join_params_buy_in, join_pre_big_blind]; exact h_buy_in'
  · -- 5. ∀ i, (pre.get_seat i).player ≠ params.player
    intro i h_lt
    rw [join_pre_get_seat, join_params_player]
    simp [Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
    exact ne_comm.mp h_player_ne
  · -- 6. (post.get_seat params.seat_index).player = params.player
    rw [h_params_seat, h_post_seat, join_params_player]
  · -- 7. (post.get_seat params.seat_index).stack = params.buy_in
    rw [h_params_seat, h_post_seat, join_params_buy_in]
  · -- 8. (post.get_seat ...).folded = false
    rw [h_params_seat, h_post_seat]
  · -- 9. (post.get_seat ...).left_during_hand = false
    rw [h_params_seat, h_post_seat]
  · -- 10. (post.get_seat ...).all_in = false
    rw [h_params_seat, h_post_seat]
  · -- 11. (post.get_seat ...).acted_this_round = false
    rw [h_params_seat, h_post_seat]
  · -- 12. (post.get_seat ...).bet = 0
    rw [h_params_seat, h_post_seat]
  · -- 13. (post.get_seat ...).total_bet = 0
    rw [h_params_seat, h_post_seat]
  · -- 14. ∀ i, i ≠ seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [join_pre_max_players] at h_lt
    exact join_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 15. post.chip_pool = pre.chip_pool + params.buy_in
    rw [join_post_chip_pool, join_pre_chip_pool, join_params_buy_in]; exact h_chip_pool'
  · -- 16. post.version = pre.version + 1
    rw [join_post_version, join_pre_version]; exact h_ver'
  · -- 17. post.round_state = pre.round_state
    rw [join_post_round_state, join_pre_round_state, h_rs']
  · -- 18. post.max_players = pre.max_players
    rw [join_post_max_players, join_pre_max_players]
  · -- 19. post.big_blind = pre.big_blind
    rw [join_post_big_blind, join_pre_big_blind]
  · -- 20. post.small_blind = pre.small_blind
    rw [join_post_small_blind, join_pre_small_blind]
  · -- 21. post.hand_id = pre.hand_id
    rw [join_post_hand_id, join_pre_hand_id]

end PokerLean
