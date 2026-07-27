import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Bet
import PokerLean.AIR.AirBase
import PokerLean.AIR.BetAir

namespace PokerLean

/-! ## 辅助引理（pre 状态提取） -/

private lemma bet_pre_round_betting
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromBetAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromBetAir, TexasPokerTable.update_seat]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma bet_pre_max_players
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_current_turn
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_version
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_round_state
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_pot
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_dealer_seat
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_current_bet
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.current_bet = 0 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_min_raise
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.min_raise = 0 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_big_blind
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_small_blind
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_chip_pool
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_hand_id
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

/-! ## 辅助引理（post 状态提取） -/

private lemma bet_post_version
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_round_state
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_pot
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_dealer_seat
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_max_players
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_big_blind
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_small_blind
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_chip_pool
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_hand_id
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_current_bet
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.current_bet =
      decodeU64 ext.output_current_bet.1 ext.output_current_bet.2.1
        ext.output_current_bet.2.2.1 ext.output_current_bet.2.2.2 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_min_raise
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.min_raise =
      decodeU64 ext.output_min_raise.1 ext.output_min_raise.2.1
        ext.output_min_raise.2.2.1 ext.output_min_raise.2.2.2 := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

private lemma bet_pre_get_seat_at_input
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromBetAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
  simp only [extractPreTableFromBetAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

private lemma bet_pre_get_seat_other
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromBetAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromBetAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma bet_post_get_seat_at_index
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromBetAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some, Seat.empty]

private lemma bet_post_get_seat_other
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromBetAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromBetAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromBetAir, extractPreTableFromBetAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma bet_params_seat
    (ext : BetMethodColumns) :
    (extractBetParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractBetParamsFromAir; rfl

private lemma bet_params_amount
    (ext : BetMethodColumns) :
    (extractBetParamsFromAir ext).bet_amount =
      decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
        ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 := by
  unfold extractBetParamsFromAir; rfl

/-! ## bet AIR soundness 主定理

    所有 Gap 均已闭合：
    - RoundStateIsBetting：阻止非下注轮 bet
    - CurrentTurnMatches：阻止非当前行动座位 bet
    - SeatOccupied：阻止空座位 bet
    - ButtonUnchanged：dealer_seat 不变
    - AmountPositive：bet_amount > 0
    - PotDelta（全 4 limb）：post_pot = pre_pot + bet_amount
    - Limb4DeltaRev（stack）：pre_stack = post_stack + bet_amount → bet_amount ≤ pre_stack
    - Limb4Eq（bet）：post_bet = bet_amount
    - Limb4Delta（total_bet）：post_total_bet = pre_total_bet + bet_amount
    - Limb4Eq（current_bet）：post_current_bet = bet_amount
    - Limb4Eq（min_raise）：post_min_raise = bet_amount
    - StateRootConsistency：witness 绑定到 committed state root -/
theorem bet_air_sound :
  ∀ (row : CommonRow) (ext : BetMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_bet_amount : Nat) (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    BetAirAcceptable row ext expected_seat_index hlt expected_bet_amount max_players →
    ContractBet
      (extractPreTableFromBetAir row ext max_players)
      (extractBetParamsFromAir ext)
      (extractPostTableFromBetAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_bet_amount max_players hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : BetMethodConstraints row ext expected_seat_index hlt
                    expected_bet_amount max_players := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_amt, _h_acted,
                    h_amt_pos, h_ver, h_rs_unch, h_rsb, _h_btn_unch,
                    h_pot_delta, h_stack_delta, h_bet_eq, h_total_delta,
                    h_cb_eq, h_mr_eq, _h_src⟩
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractBetParamsFromAir ext).seat_index = expected_seat_index := by
    rw [bet_params_seat, h_seat_val]
  have h_params_amount : (extractBetParamsFromAir ext).bet_amount =
      decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
        ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 := bet_params_amount ext
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]; exact hseat
  have h_rsb' : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
                row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5 := h_rsb h_active
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_btn' : row.post_button = row.pre_button := _h_btn_unch h_active
  -- 资金守恒派生
  have h_pot_eq : decodeU64 row.post_pot.1 row.post_pot.2.1
                    row.post_pot.2.2.1 row.post_pot.2.2.2 =
                  decodeU64 row.pre_pot.1 row.pre_pot.2.1
                    row.pre_pot.2.2.1 row.pre_pot.2.2.2 +
                  decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                    ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    pot_delta_implies_decode_eq row ext.input_bet_amount h_active h_pot_delta
  have h_pre_stack : decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
                       ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2 =
                     decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
                       ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2 +
                     decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                       ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    limb4_delta_rev_implies_decode_eq ext.input_pre_seat_stack ext.output_seat_stack
      ext.input_bet_amount h_stack_delta
  have h_post_bet_eq : decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
                         ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 =
                       decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                         ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_seat_bet ext.input_bet_amount h_bet_eq
  have h_post_total_eq : decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
                           ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2 =
                         decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
                           ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 +
                         decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                           ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    limb4_delta_implies_decode_eq ext.input_pre_seat_total_bet ext.output_seat_total_bet
      ext.input_bet_amount h_total_delta
  have h_post_cb_eq : decodeU64 ext.output_current_bet.1 ext.output_current_bet.2.1
                        ext.output_current_bet.2.2.1 ext.output_current_bet.2.2.2 =
                      decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                        ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_current_bet ext.input_bet_amount h_cb_eq
  have h_post_mr_eq : decodeU64 ext.output_min_raise.1 ext.output_min_raise.2.1
                        ext.output_min_raise.2.2.1 ext.output_min_raise.2.2.2 =
                      decodeU64 ext.input_bet_amount.1 ext.input_bet_amount.2.1
                        ext.input_bet_amount.2.2.1 ext.input_bet_amount.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_min_raise ext.input_bet_amount h_mr_eq
  -- 座位级引理
  have h_pre_seat : (extractPreTableFromBetAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
    rw [← h_seat_val]
    exact bet_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromBetAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } :=
    bet_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- ContractBet 有 28 个合取
  unfold ContractBet
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact bet_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, bet_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, bet_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. (pre.get_seat params.seat_index).is_participating
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 5. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 6. ¬ (pre.get_seat params.seat_index).all_in
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 7. pre.betting.current_bet = 0
    exact bet_pre_current_bet row ext max_players
  · -- 8. params.bet_amount > 0
    rw [h_params_amount]; exact h_amt_pos
  · -- 9. params.bet_amount ≤ pre.stack
    rw [h_params_seat, h_pre_seat, h_params_amount]
    simp [Seat.empty]
    omega
  · -- 10. params.bet_amount ≥ pre.min_raise — pre.min_raise = 0, bet_amount ≥ 0
    rw [bet_pre_min_raise]
    exact Nat.zero_le _
  · -- 11. post.bet = bet_amount
    rw [h_params_seat, h_post_seat, h_params_amount]
    simp [Seat.empty]
    exact h_post_bet_eq
  · -- 12. post.stack = pre.stack - bet_amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp [Seat.empty]
    omega
  · -- 13. post.total_bet = pre.total_bet + bet_amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp [Seat.empty]
    exact h_post_total_eq
  · -- 14. (post.get_seat ...).acted_this_round = true
    rw [h_params_seat, h_post_seat]
  · -- 15. (post.get_seat ...).folded = (pre.get_seat ...).folded
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 16. (post.get_seat ...).player = (pre.get_seat ...).player
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 17. ∀ i, i ≠ params.seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [bet_pre_max_players] at h_lt
    exact bet_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 18. post.version = pre.version + 1
    rw [bet_post_version, bet_pre_version]; exact h_ver'
  · -- 19. post.round_state = pre.round_state
    rw [bet_post_round_state, bet_pre_round_state, h_rs']
  · -- 20. post.betting.pot = pre.betting.pot + params.bet_amount
    rw [bet_post_pot, bet_pre_pot, h_params_amount]; exact h_pot_eq
  · -- 21. post.betting.current_bet = params.bet_amount
    rw [bet_post_current_bet, h_params_amount]; exact h_post_cb_eq
  · -- 22. post.betting.min_raise = params.bet_amount
    rw [bet_post_min_raise, h_params_amount]; exact h_post_mr_eq
  · -- 23. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [bet_post_dealer_seat, bet_pre_dealer_seat, h_btn']
  · -- 24. post.max_players = pre.max_players
    exact bet_post_max_players row ext max_players expected_seat_index
  · -- 25. post.big_blind = pre.big_blind
    rw [bet_post_big_blind, bet_pre_big_blind]
  · -- 26. post.small_blind = pre.small_blind
    rw [bet_post_small_blind, bet_pre_small_blind]
  · -- 27. post.chip_pool = pre.chip_pool
    rw [bet_post_chip_pool, bet_pre_chip_pool]
  · -- 28. post.hand_id = pre.hand_id
    rw [bet_post_hand_id, bet_pre_hand_id]

end PokerLean
