import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Check
import PokerLean.AIR.AirBase
import PokerLean.AIR.CheckAir

namespace PokerLean

/-! ## 辅助引理（pre 状态提取） -/

private lemma check_pre_round_betting
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromCheckAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromCheckAir, TexasPokerTable.update_seat]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma check_pre_max_players
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_current_turn
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_version
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_round_state
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_pot
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_dealer_seat
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_current_bet
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).betting.current_bet = 0 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_big_blind
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_small_blind
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_chip_pool
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_pre_hand_id
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) :
    (extractPreTableFromCheckAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromCheckAir, TexasPokerTable.update_seat]

/-! ## 辅助引理（post 状态提取） -/

private lemma check_post_version
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_round_state
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_pot
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_dealer_seat
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_max_players
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_big_blind
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_small_blind
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_chip_pool
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_hand_id
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

private lemma check_post_current_bet
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCheckAir row ext max_players seat_index).betting.current_bet = 0 := by
  simp [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

/-- 在 pre table 中，input_seat_index 位置的座位是 occupied 的（player := 1）。 -/
private lemma check_pre_get_seat_at_input
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromCheckAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
  simp only [extractPreTableFromCheckAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

/-- 当 i ≠ ext.input_seat_index.val 且 i < max_players 时，pre.get_seat i = Seat.empty -/
private lemma check_pre_get_seat_other
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromCheckAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromCheckAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- 在 post table 中，seat_index 位置的座位是 acted 后的 occupied seat。 -/
private lemma check_post_get_seat_at_index
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromCheckAir row ext max_players seat_index).get_seat seat_index =
      { { Seat.empty with player := PlayerId.ofNat 1 } with acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

/-- 在 post table 中，当 i ≠ seat_index 且 i < max_players 时，post.get_seat i = pre.get_seat i -/
private lemma check_post_get_seat_other
    (row : CommonRow) (ext : CheckMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromCheckAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromCheckAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromCheckAir, extractPreTableFromCheckAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- `extractCheckParamsFromAir ext` 的 seat_index = ext.input_seat_index.val -/
private lemma check_params_seat
    (ext : CheckMethodColumns) :
    (extractCheckParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractCheckParamsFromAir; rfl

/-! ## check AIR soundness 主定理

    闭合的 Gap：
    - Gap 1 (RoundStateIsBetting)：阻止非下注轮 check
    - CurrentTurnMatches：阻止非当前行动座位 check
    - SeatOccupied：阻止空座位 check
    - PotUnchanged（全 4 limb）：底池守恒
    - ButtonUnchanged：dealer_seat 不变
    - acted_this_round extraction：post 状态正确反映 acted_this_round=true -/
theorem check_air_sound :
  ∀ (row : CommonRow) (ext : CheckMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_current_bet : Nat) (expected_seat_bet : Nat)
    (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    CheckAirAcceptable row ext expected_seat_index hlt expected_current_bet expected_seat_bet max_players →
    ContractCheck
      (extractPreTableFromCheckAir row ext max_players)
      (extractCheckParamsFromAir ext)
      (extractPostTableFromCheckAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_current_bet expected_seat_bet max_players hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : CheckMethodConstraints row ext expected_seat_index hlt
                    expected_current_bet expected_seat_bet max_players := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_cb, _h_sb, _h_acted,
                    h_ver, h_rs_unch, h_rsb, h_pot_unch, h_btn_unch, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractCheckParamsFromAir ext).seat_index = expected_seat_index := by
    rw [check_params_seat, h_seat_val]
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]; exact hseat
  -- 4. 约束前提展开（active 成立）
  have h_rsb' : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
                row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5 := h_rsb h_active
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_pot' : row.post_pot.1 = row.pre_pot.1 ∧
                row.post_pot.2.1 = row.pre_pot.2.1 ∧
                row.post_pot.2.2.1 = row.pre_pot.2.2.1 ∧
                row.post_pot.2.2.2 = row.pre_pot.2.2.2 := h_pot_unch h_active
  have h_btn' : row.post_button = row.pre_button := h_btn_unch h_active
  have h_pot_eq : decodeU64 row.post_pot.1 row.post_pot.2.1
                    row.post_pot.2.2.1 row.post_pot.2.2.2 =
                  decodeU64 row.pre_pot.1 row.pre_pot.2.1
                    row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
    rcases h_pot' with ⟨h0, h1, h2, h3⟩; rw [h0, h1, h2, h3]
  -- 5. 座位级引理
  have h_pre_seat : (extractPreTableFromCheckAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
    rw [← h_seat_val]
    exact check_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromCheckAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { { Seat.empty with player := PlayerId.ofNat 1 } with acted_this_round := true } :=
    check_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- 6. 证明 ContractCheck 的 24 个合取
  unfold ContractCheck
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact check_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, check_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, check_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. (pre.get_seat params.seat_index).is_participating
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 5. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 6. ¬ (pre.get_seat params.seat_index).all_in
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 7. (pre.get_seat params.seat_index).bet = pre.betting.current_bet
    rw [h_params_seat, h_pre_seat, check_pre_current_bet]
    simp [Seat.empty]
  · -- 8. (post.get_seat params.seat_index).acted_this_round = true
    rw [h_params_seat, h_post_seat]
  · -- 9. (post.get_seat ...).folded = (pre.get_seat ...).folded
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 10. stack
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 11. bet
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 12. total_bet
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 13. player
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 14. ∀ i, i ≠ params.seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [check_pre_max_players] at h_lt
    exact check_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 15. post.version = pre.version + 1
    rw [check_post_version, check_pre_version]; exact h_ver'
  · -- 16. post.round_state = pre.round_state
    rw [check_post_round_state, check_pre_round_state, h_rs']
  · -- 17. post.betting.pot = pre.betting.pot
    rw [check_post_pot, check_pre_pot]; exact h_pot_eq
  · -- 18. post.betting.current_bet = pre.betting.current_bet
    rw [check_post_current_bet, check_pre_current_bet]
  · -- 19. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [check_post_dealer_seat, check_pre_dealer_seat, h_btn']
  · -- 20. post.max_players = pre.max_players
    exact check_post_max_players row ext max_players expected_seat_index
  · -- 21. post.big_blind = pre.big_blind
    rw [check_post_big_blind, check_pre_big_blind]
  · -- 22. post.small_blind = pre.small_blind
    rw [check_post_small_blind, check_pre_small_blind]
  · -- 23. post.chip_pool = pre.chip_pool
    rw [check_post_chip_pool, check_pre_chip_pool]
  · -- 24. post.hand_id = pre.hand_id
    rw [check_post_hand_id, check_pre_hand_id]

end PokerLean
