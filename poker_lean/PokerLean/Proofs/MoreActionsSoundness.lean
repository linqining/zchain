import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.MoreActions
import PokerLean.AIR.AirBase
import PokerLean.AIR.MoreActionsAir

namespace PokerLean

/-! # auto_fold / force_fold / kick_player 的 soundness 定理

    闭合的 Gap：
    - CurrentTurnMatches (auto_fold/force_fold)：阻止非当前行动座位动作
    - SeatOccupied：阻止空座位动作
    - PotUnchanged (auto_fold/force_fold)：底池守恒
    - ButtonUnchanged：dealer_seat 不变
    - mark_folded extraction：post 状态正确反映 folded=true
    - kick_player post extraction：目标座位清空（player=EMPTY_PLAYER） -/

/-! ## auto_fold 辅助引理 -/

private lemma autofold_pre_round_betting
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromAutoFoldAir row ext max_players).round_state.is_betting_round := by
  have h_rs : (extractPreTableFromAutoFoldAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
    simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]
  rw [h_rs]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma autofold_pre_max_players
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_current_turn
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_version
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_round_state
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_pot
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_dealer_seat
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_big_blind
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_small_blind
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_chip_pool
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_pre_hand_id
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromAutoFoldAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_version
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_round_state
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_pot
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_dealer_seat
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_max_players
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_big_blind
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_small_blind
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_chip_pool
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma autofold_post_hand_id
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

/-! ### auto_fold 座位访问引理 -/

private lemma autofold_pre_get_seat_at_input
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromAutoFoldAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
  simp only [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

private lemma autofold_pre_get_seat_other
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromAutoFoldAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromAutoFoldAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma autofold_post_get_seat_at_index
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).get_seat seat_index =
      Seat.mark_folded { Seat.empty with player := PlayerId.ofNat 1 } := by
  subst h_seat_eq
  simp only [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma autofold_post_get_seat_other
    (row : CommonRow) (ext : AutoFoldMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromAutoFoldAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromAutoFoldAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromAutoFoldAir, extractPreTableFromAutoFoldAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma autofold_params_seat
    (ext : AutoFoldMethodColumns) :
    (extractAutoFoldParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  simp [extractAutoFoldParamsFromAir]

/-! ### auto_fold AIR soundness 主定理 -/

theorem auto_fold_air_sound :
  ∀ (row : CommonRow) (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    (hseat : expected_seat_index < max_players),
    AutoFoldAirAcceptable row ext expected_seat_index max_players hlt expected_current_time →
    ContractAutoFold
      (extractPreTableFromAutoFoldAir row ext max_players)
      (extractAutoFoldParamsFromAir ext)
      (extractPostTableFromAutoFoldAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index max_players hlt expected_current_time hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : AutoFoldMethodConstraints row ext expected_seat_index max_players hlt
      expected_current_time := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_time, _h_folded,
                    h_ver, h_rs_unch, h_rsb, h_pot_unch, h_btn_unch, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractAutoFoldParamsFromAir ext).seat_index = expected_seat_index := by
    rw [autofold_params_seat, h_seat_val]
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
  have h_pre_seat : (extractPreTableFromAutoFoldAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
    rw [← h_seat_val]
    exact autofold_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromAutoFoldAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      Seat.mark_folded { Seat.empty with player := PlayerId.ofNat 1 } :=
    autofold_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- 6. 证明 ContractAutoFold 的 16 个合取
  unfold ContractAutoFold
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact autofold_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, autofold_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, autofold_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 5. (post.get_seat params.seat_index).folded = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.mark_folded, Seat.empty]
  · -- 6. (post.get_seat params.seat_index).acted_this_round = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.mark_folded, Seat.empty]
  · -- 7. ∀ i, i ≠ params.seat_index → i < pre.max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [autofold_pre_max_players] at h_lt
    exact autofold_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 8. post.version = pre.version + 1
    rw [autofold_post_version, autofold_pre_version]; exact h_ver'
  · -- 9. post.round_state = pre.round_state
    rw [autofold_post_round_state, autofold_pre_round_state, h_rs']
  · -- 10. post.betting.pot = pre.betting.pot
    rw [autofold_post_pot, autofold_pre_pot]; exact h_pot_eq
  · -- 11. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [autofold_post_dealer_seat, autofold_pre_dealer_seat, h_btn']
  · -- 12. post.max_players = pre.max_players
    exact autofold_post_max_players row ext max_players expected_seat_index
  · -- 13. post.big_blind = pre.big_blind
    rw [autofold_post_big_blind, autofold_pre_big_blind]
  · -- 14. post.small_blind = pre.small_blind
    rw [autofold_post_small_blind, autofold_pre_small_blind]
  · -- 15. post.chip_pool = pre.chip_pool
    rw [autofold_post_chip_pool, autofold_pre_chip_pool]
  · -- 16. post.hand_id = pre.hand_id
    rw [autofold_post_hand_id, autofold_pre_hand_id]

/-! ## force_fold 辅助引理 -/

private lemma forcefold_pre_round_betting
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromForceFoldAir row ext max_players).round_state.is_betting_round := by
  have h_rs : (extractPreTableFromForceFoldAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
    simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]
  rw [h_rs]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma forcefold_pre_max_players
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_current_turn
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_version
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_round_state
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_pot
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_dealer_seat
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_big_blind
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_small_blind
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_chip_pool
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_pre_hand_id
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromForceFoldAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromForceFoldAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_version
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_round_state
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_pot
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_dealer_seat
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_max_players
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_big_blind
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_small_blind
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_chip_pool
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma forcefold_post_hand_id
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

/-! ### force_fold 座位访问引理 -/

private lemma forcefold_pre_get_seat_at_input
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromForceFoldAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
  simp only [extractPreTableFromForceFoldAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

private lemma forcefold_pre_get_seat_other
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromForceFoldAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromForceFoldAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma forcefold_post_get_seat_at_index
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).get_seat seat_index =
      Seat.mark_folded { Seat.empty with player := PlayerId.ofNat 1 } := by
  subst h_seat_eq
  simp only [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma forcefold_post_get_seat_other
    (row : CommonRow) (ext : ForceFoldMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromForceFoldAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromForceFoldAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromForceFoldAir, extractPreTableFromForceFoldAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma forcefold_params_seat
    (ext : ForceFoldMethodColumns) :
    (extractForceFoldParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  simp [extractForceFoldParamsFromAir]

/-! ### force_fold AIR soundness 主定理 -/

theorem force_fold_air_sound :
  ∀ (row : CommonRow) (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    ForceFoldAirAcceptable row ext expected_seat_index max_players hlt →
    ContractForceFold
      (extractPreTableFromForceFoldAir row ext max_players)
      (extractForceFoldParamsFromAir ext)
      (extractPostTableFromForceFoldAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index max_players hlt hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : ForceFoldMethodConstraints row ext expected_seat_index max_players hlt :=
    h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_folded,
                    h_ver, h_rs_unch, h_rsb, h_pot_unch, h_btn_unch, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractForceFoldParamsFromAir ext).seat_index = expected_seat_index := by
    rw [forcefold_params_seat, h_seat_val]
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
  have h_pre_seat : (extractPreTableFromForceFoldAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with player := PlayerId.ofNat 1 } := by
    rw [← h_seat_val]
    exact forcefold_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromForceFoldAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      Seat.mark_folded { Seat.empty with player := PlayerId.ofNat 1 } :=
    forcefold_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- 6. 证明 ContractForceFold 的 16 个合取
  unfold ContractForceFold
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact forcefold_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, forcefold_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, forcefold_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 5. (post.get_seat params.seat_index).folded = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.mark_folded, Seat.empty]
  · -- 6. (post.get_seat params.seat_index).acted_this_round = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.mark_folded, Seat.empty]
  · -- 7. ∀ i, i ≠ params.seat_index → i < pre.max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [forcefold_pre_max_players] at h_lt
    exact forcefold_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 8. post.version = pre.version + 1
    rw [forcefold_post_version, forcefold_pre_version]; exact h_ver'
  · -- 9. post.round_state = pre.round_state
    rw [forcefold_post_round_state, forcefold_pre_round_state, h_rs']
  · -- 10. post.betting.pot = pre.betting.pot
    rw [forcefold_post_pot, forcefold_pre_pot]; exact h_pot_eq
  · -- 11. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [forcefold_post_dealer_seat, forcefold_pre_dealer_seat, h_btn']
  · -- 12. post.max_players = pre.max_players
    exact forcefold_post_max_players row ext max_players expected_seat_index
  · -- 13. post.big_blind = pre.big_blind
    rw [forcefold_post_big_blind, forcefold_pre_big_blind]
  · -- 14. post.small_blind = pre.small_blind
    rw [forcefold_post_small_blind, forcefold_pre_small_blind]
  · -- 15. post.chip_pool = pre.chip_pool
    rw [forcefold_post_chip_pool, forcefold_pre_chip_pool]
  · -- 16. post.hand_id = pre.hand_id
    rw [forcefold_post_hand_id, forcefold_pre_hand_id]

/-! ## kick_player 辅助引理 -/

private lemma kick_pre_max_players
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_version
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_round_state
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_pot
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_big_blind
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_small_blind
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_pre_hand_id
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) :
    (extractPreTableFromKickPlayerAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_version
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_round_state
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_pot
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_max_players
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_big_blind
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_small_blind
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

private lemma kick_post_hand_id
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
         extractPreTableFromActionAir, TexasPokerTable.update_seat]

/-! ### kick_player 座位访问引理 -/

/-- kick_player 的 pre 座位在 input_seat_index 处是 occupied（player := 1，bet = kicked_bet）。 -/
private lemma kick_pre_get_seat_at_input
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromKickPlayerAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1
        bet := decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
                 ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 } := by
  simp only [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

/-- kick_player 的 pre 座位在 i ≠ input_seat_index 时为 Seat.empty。 -/
private lemma kick_pre_get_seat_other
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromKickPlayerAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromKickPlayerAir, extractPreTableFromActionAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- kick_player 的 post 座位在 seat_index 处被标记为 kicked（保留 player，folded/left_during_hand = true，
    stack/bet 清零 — `Seat.kicked` 覆盖 bet 为 0，与 pre seat 的 bet 值无关）。 -/
private lemma kick_post_get_seat_at_index
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).get_seat seat_index =
      Seat.kicked { Seat.empty with
        player := PlayerId.ofNat 1
        bet := decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
                 ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 } := by
  subst h_seat_eq
  simp only [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

/-- kick_player 的 post 座位在 i ≠ seat_index 时与 pre 相同。 -/
private lemma kick_post_get_seat_other
    (row : CommonRow) (ext : KickPlayerMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromKickPlayerAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromKickPlayerAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromKickPlayerAir, extractPreTableFromKickPlayerAir,
             extractPreTableFromActionAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma kick_params_seat
    (ext : KickPlayerMethodColumns) :
    (extractKickPlayerParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  simp [extractKickPlayerParamsFromAir]

/-! ### kick_player AIR soundness 主定理 -/

theorem kick_player_air_sound :
  ∀ (row : CommonRow) (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    (hseat : expected_seat_index < max_players),
    KickPlayerAirAcceptable row ext expected_seat_index max_players hlt expected_refund →
    ContractKickPlayer
      (extractPreTableFromKickPlayerAir row ext max_players)
      (extractKickPlayerParamsFromAir ext)
      (extractPostTableFromKickPlayerAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index max_players hlt expected_refund hseat h_air
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : KickPlayerMethodConstraints row ext expected_seat_index max_players hlt
      expected_refund := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, _h_occ, _h_refund, _h_kicked, _h_seat_occ,
                    h_ver, h_rs_unch, h_btn_unch, h_pot_delta, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractKickPlayerParamsFromAir ext).seat_index = expected_seat_index := by
    rw [kick_params_seat, h_seat_val]
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]; exact hseat
  -- 4. 约束前提展开（active 成立）
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  -- 5. 座位级引理
  have h_pre_seat : (extractPreTableFromKickPlayerAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1
        bet := decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
                 ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 } := by
    rw [← h_seat_val]
    exact kick_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromKickPlayerAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      Seat.kicked { Seat.empty with
        player := PlayerId.ofNat 1
        bet := decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
                 ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 } :=
    kick_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- 5b. 资金守恒派生：从 PotDelta ripple-carry 得到 decodeU64 级等式
  have h_pot_eq : decodeU64 row.post_pot.1 row.post_pot.2.1
                    row.post_pot.2.2.1 row.post_pot.2.2.2 =
                  decodeU64 row.pre_pot.1 row.pre_pot.2.1
                    row.pre_pot.2.2.1 row.pre_pot.2.2.2 +
                  decodeU64 ext.kicked_bet.1 ext.kicked_bet.2.1
                    ext.kicked_bet.2.2.1 ext.kicked_bet.2.2.2 :=
    pot_delta_implies_decode_eq row ext.kicked_bet ext.pot_add_carry h_active h_pot_delta
  -- 6. 证明 ContractKickPlayer 的 17 个合取
  unfold ContractKickPlayer
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. params.seat_index < pre.max_players
    rw [h_params_seat, kick_pre_max_players]; exact hseat
  · -- 2. (pre.get_seat params.seat_index).is_occupied
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_occupied, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 3. (post.get_seat params.seat_index).stack = 0
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 4. (post.get_seat params.seat_index).bet = 0
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 5. (post.get_seat params.seat_index).folded = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 6. (post.get_seat params.seat_index).left_during_hand = true
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 7. (post.get_seat params.seat_index).all_in = false
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 8. (post.get_seat params.seat_index).acted_this_round = false
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 9. (post.get_seat params.seat_index).is_waiting = false
    rw [h_params_seat, h_post_seat]
    simp [Seat.kicked, Seat.empty]
  · -- 10. post.betting.pot = pre.betting.pot + (pre.get_seat params.seat_index).bet
    -- 由 PotDelta ripple-carry 推出 decodeU64 级守恒：
    --   decodeU64 post_pot = decodeU64 pre_pot + decodeU64 kicked_bet
    -- 且 pre 座位 bet = decodeU64 kicked_bet（extraction 对齐 witness）。
    rw [kick_post_pot, kick_pre_pot, h_params_seat, h_pre_seat]
    simp [Seat.empty]
    exact h_pot_eq
  · -- 11. ∀ i, i ≠ params.seat_index → i < pre.max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [kick_pre_max_players] at h_lt
    exact kick_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 12. post.version = pre.version + 1
    rw [kick_post_version, kick_pre_version]; exact h_ver'
  · -- 13. post.round_state = pre.round_state
    rw [kick_post_round_state, kick_pre_round_state, h_rs']
  · -- 14. post.max_players = pre.max_players
    exact kick_post_max_players row ext max_players expected_seat_index
  · -- 15. post.big_blind = pre.big_blind
    rw [kick_post_big_blind, kick_pre_big_blind]
  · -- 16. post.small_blind = pre.small_blind
    rw [kick_post_small_blind, kick_pre_small_blind]
  · -- 17. post.hand_id = pre.hand_id
    rw [kick_post_hand_id, kick_pre_hand_id]

end PokerLean
