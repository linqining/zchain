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

private lemma bet_pre_round_postflop
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 3 ∨ row.pre_round_state.val = 4 ∨
         row.pre_round_state.val = 5) :
    (extractPreTableFromBetAir row ext max_players).round_state.is_postflop_betting := by
  simp only [extractPreTableFromBetAir, TexasPokerTable.update_seat]
  rcases h with h | h | h <;>
    rw [h] <;> simp [RoundState.fromNat, RoundState.is_postflop_betting]

private lemma bet_pre_max_players
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_current_turn
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_current_bet
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.current_bet =
      ext.trusted.pre_current_bet := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_min_raise
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.min_raise =
      ext.trusted.pre_min_raise := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_version
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).version = decodeLimb4 row.pre_version := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_round_state
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_pot
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.pot = decodeLimb4 row.pre_pot := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_pre_dealer_seat
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat) :
    (extractPreTableFromBetAir row ext max_players).betting.dealer_seat = row.pre_button.val := by
  simp [extractPreTableFromBetAir, TexasPokerTable.update_seat]

private lemma bet_post_version
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).version =
      decodeLimb4 row.post_version := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_round_state
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_pot
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.pot =
      decodeLimb4 row.post_pot := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_current_bet
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.current_bet =
      decodeLimb4 ext.output_current_bet := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_min_raise
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.min_raise =
      decodeLimb4 ext.output_min_raise := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_current_turn
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.current_turn =
      ext.output_current_turn.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_dealer_seat
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_post_max_players
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromBetAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.update_seat]

private lemma bet_pre_get_seat_at_input
    (row : CommonRow) (ext : BetMethodColumns) (max_players : Nat)
    (h_lt : ext.input_seat_index.val < max_players) :
    (extractPreTableFromBetAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := ext.trusted.pre_seat_stack,
        bet := ext.trusted.pre_seat_bet,
        total_bet := ext.trusted.pre_seat_total_bet } := by
  simp only [extractPreTableFromBetAir, TexasPokerTable.get_seat,
    TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
    List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
    Option.map_some, Option.getD_some]

private lemma bet_post_get_seat_at_index
    (row : CommonRow) (ext : BetMethodColumns) (max_players seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index) (h_lt : seat_index < max_players) :
    (extractPostTableFromBetAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeLimb4 ext.output_seat_stack,
          bet := decodeLimb4 ext.output_seat_bet } with
        total_bet := decodeLimb4 ext.output_seat_total_bet,
        all_in := decide
          (decodeLimb4 ext.input_bet_amount = ext.trusted.pre_seat_stack),
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromBetAir, extractPreTableFromBetAir,
    TexasPokerTable.get_seat, TexasPokerTable.update_seat,
    List.getD_eq_getD_get?, List.get?_eq_getElem?, List.getElem?_modify_eq,
    List.getElem?_replicate, h_lt, if_true, Option.map_some, Option.getD_some,
    Seat.empty]

private lemma bet_params_seat (ext : BetMethodColumns) :
    (extractBetParamsFromAir ext).seat_index = ext.input_seat_index.val := rfl

private lemma bet_params_amount (ext : BetMethodColumns) :
    (extractBetParamsFromAir ext).bet_amount = decodeLimb4 ext.input_bet_amount := rfl

private lemma bet_params_turn (ext : BetMethodColumns) :
    (extractBetParamsFromAir ext).post_current_turn = ext.output_current_turn.val := rfl

/-- Rust trusted-u64 规则同步后的 bet mid-round soundness。

只覆盖 FLOP/TURN/RIVER 且未触发 collect-bets、round advance 或 settlement
的路径；不声称 Rust physical row 与本手写逻辑 record 已有逐列 refinement。 -/
theorem bet_air_sound :
  ∀ (row : CommonRow) (ext : BetMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_bet_amount : Nat) (expected_trusted : BetTrustedInputs)
    (max_players : Nat) (hseat : expected_seat_index < max_players),
    BetAirAcceptable row ext expected_seat_index hlt expected_bet_amount
      expected_trusted max_players →
    ContractBet
      (extractPreTableFromBetAir row ext max_players)
      (extractBetParamsFromAir ext)
      (extractPostTableFromBetAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_bet_amount expected_trusted
    max_players hseat h_air
  rcases h_air with ⟨_h_common, _h_trusted, h_method, _h_kind, h_active⟩
  rcases h_method h_active with
    ⟨h_seat_eq, h_turn_eq, _h_occ, _h_acted, h_money, h_ver, h_rs_unch,
      h_rsb, h_btn_unch, h_pot_unch, _h_src⟩
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]
    simp [nat_to_m31]
  have h_params_seat : (extractBetParamsFromAir ext).seat_index = expected_seat_index := by
    rw [bet_params_seat, h_seat_val]
  have h_params_amount : (extractBetParamsFromAir ext).bet_amount = expected_bet_amount := by
    rw [bet_params_amount]
    exact h_money.amount_witness
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]
    exact hseat
  have h_round : row.pre_round_state.val = 3 ∨ row.pre_round_state.val = 4 ∨
      row.pre_round_state.val = 5 := h_rsb h_active
  have h_ver' : decodeLimb4 row.post_version = decodeLimb4 row.pre_version + 1 :=
    h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_btn' : row.post_button = row.pre_button := h_btn_unch h_active
  have h_pot' : decodeLimb4 row.post_pot = decodeLimb4 row.pre_pot :=
    pot_unchanged_implies_decode_eq row h_active h_pot_unch
  have h_pre_seat :
      (extractPreTableFromBetAir row ext max_players).get_seat expected_seat_index =
        { Seat.empty with
          player := PlayerId.ofNat 1,
          stack := ext.trusted.pre_seat_stack,
          bet := ext.trusted.pre_seat_bet,
          total_bet := ext.trusted.pre_seat_total_bet } := by
    rw [← h_seat_val]
    exact bet_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat := bet_post_get_seat_at_index row ext max_players
    expected_seat_index h_seat_val hseat
  unfold ContractBet
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact bet_pre_round_postflop row ext max_players h_round
  · rw [h_params_seat, bet_pre_max_players]
    exact hseat
  · rw [h_params_seat, bet_pre_current_turn, h_turn_eq]
    exact h_seat_val
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [bet_pre_current_bet, h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.current_le_seat_bet
  · rw [h_params_amount]
    exact h_money.amount_positive
  · rw [h_params_seat, h_pre_seat, h_params_amount, bet_pre_current_bet]
    simpa [Seat.empty] using h_money.total_above_current
  · rw [h_params_amount, h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.amount_le_stack
  · rw [h_params_seat, h_pre_seat, h_params_amount, bet_pre_current_bet,
      bet_pre_min_raise]
    simpa [Seat.empty] using h_money.min_or_short_all_in
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_bet
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_stack
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_total
  · rw [h_params_seat, h_post_seat]
  · rw [h_params_seat, h_post_seat, h_params_amount, h_pre_seat]
    simp [h_money.amount_witness, Seat.empty]
  · rw [h_params_seat, h_post_seat, h_pre_seat]
  · rw [h_params_seat, h_post_seat, h_pre_seat]
  · rw [bet_post_version, bet_pre_version]
    exact h_ver'
  · rw [bet_post_round_state, bet_pre_round_state, h_rs']
  · rw [bet_post_pot, bet_pre_pot]
    exact h_pot'
  · rw [bet_post_current_bet, h_params_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_current_bet
  · rw [bet_post_min_raise, h_params_seat, h_pre_seat, h_params_amount,
      bet_pre_current_bet, bet_pre_min_raise]
    simpa [Seat.empty] using h_money.output_min_raise
  · rw [bet_post_current_turn, bet_params_turn, h_money.output_turn]
  · rw [bet_post_dealer_seat, bet_pre_dealer_seat, h_btn']
  · exact bet_post_max_players row ext max_players expected_seat_index
  · simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromBetAir, extractPreTableFromBetAir,
      TexasPokerTable.update_seat]

end PokerLean
