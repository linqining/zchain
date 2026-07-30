import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Raise
import PokerLean.AIR.AirBase
import PokerLean.AIR.RaiseAir

namespace PokerLean

private lemma raise_pre_round_betting
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromRaiseAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]
  rcases h with h | h | h | h <;>
    rw [h] <;> simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma raise_pre_max_players
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_current_turn
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_current_bet
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.current_bet =
      ext.trusted.pre_current_bet := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_min_raise
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.min_raise =
      ext.trusted.min_raise := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_version
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).version = decodeLimb4 row.pre_version := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_round_state
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_pot
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.pot = decodeLimb4 row.pre_pot := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_dealer_seat
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.dealer_seat = row.pre_button.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_version
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).version =
      decodeLimb4 row.post_version := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_round_state
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_pot
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.pot =
      decodeLimb4 row.post_pot := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_current_bet
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.current_bet =
      decodeLimb4 ext.output_current_bet := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_min_raise
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.min_raise =
      decodeLimb4 ext.output_min_raise := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_current_turn
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.current_turn =
      ext.output_current_turn.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_dealer_seat
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_post_max_players
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.update_seat]

private lemma raise_pre_get_seat_at_input
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat)
    (h_lt : ext.input_seat_index.val < max_players) :
    (extractPreTableFromRaiseAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := ext.trusted.pre_seat_stack,
        bet := ext.trusted.pre_seat_bet,
        total_bet := ext.trusted.pre_seat_total_bet } := by
  simp only [extractPreTableFromRaiseAir, TexasPokerTable.get_seat,
    TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
    List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
    Option.map_some, Option.getD_some]

private lemma raise_post_get_seat_at_index
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index) (h_lt : seat_index < max_players) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeLimb4 ext.output_seat_stack,
          bet := decodeLimb4 ext.output_seat_bet } with
        total_bet := decodeLimb4 ext.output_seat_total_bet,
        all_in := decide (ext.output_all_in.val = M31.one.val),
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
    TexasPokerTable.get_seat, TexasPokerTable.update_seat,
    List.getD_eq_getD_get?, List.get?_eq_getElem?, List.getElem?_modify_eq,
    List.getElem?_replicate, h_lt, if_true, Option.map_some, Option.getD_some,
    Seat.empty]

private lemma raise_params_seat (ext : RaiseMethodColumns) :
    (extractRaiseParamsFromAir ext).seat_index = ext.input_seat_index.val := rfl

private lemma raise_params_amount (ext : RaiseMethodColumns) :
    (extractRaiseParamsFromAir ext).raise_to = decodeLimb4 ext.input_raise_to := rfl

private lemma raise_params_turn (ext : RaiseMethodColumns) :
    (extractRaiseParamsFromAir ext).post_current_turn = ext.output_current_turn.val := rfl

/-- Rust trusted-u64 规则同步后的 raise mid-round soundness。 -/
theorem raise_air_sound :
  ∀ (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat) (expected_trusted : RaiseTrustedInputs)
    (max_players : Nat) (hseat : expected_seat_index < max_players),
    RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to
      expected_trusted max_players →
    ContractRaise
      (extractPreTableFromRaiseAir row ext max_players)
      (extractRaiseParamsFromAir ext)
      (extractPostTableFromRaiseAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_raise_to expected_trusted
    max_players hseat h_air
  rcases h_air with ⟨_h_common, _h_trusted, h_method, _h_kind, h_active⟩
  rcases h_method h_active with
    ⟨h_seat_eq, h_turn_eq, _h_occ, _h_acted, h_money, h_ver, h_rs_unch,
      h_rsb, h_btn_unch, h_pot_unch, _h_src⟩
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]
    simp [nat_to_m31]
  have h_params_seat : (extractRaiseParamsFromAir ext).seat_index = expected_seat_index := by
    rw [raise_params_seat, h_seat_val]
  have h_params_amount : (extractRaiseParamsFromAir ext).raise_to = expected_raise_to := by
    rw [raise_params_amount]
    exact h_money.raise_witness
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]
    exact hseat
  have h_round : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
      row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5 := h_rsb h_active
  have h_ver' : decodeLimb4 row.post_version = decodeLimb4 row.pre_version + 1 :=
    h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_btn' : row.post_button = row.pre_button := h_btn_unch h_active
  have h_pot' : decodeLimb4 row.post_pot = decodeLimb4 row.pre_pot :=
    pot_unchanged_implies_decode_eq row h_active h_pot_unch
  have h_pre_seat :
      (extractPreTableFromRaiseAir row ext max_players).get_seat expected_seat_index =
        { Seat.empty with
          player := PlayerId.ofNat 1,
          stack := ext.trusted.pre_seat_stack,
          bet := ext.trusted.pre_seat_bet,
          total_bet := ext.trusted.pre_seat_total_bet } := by
    rw [← h_seat_val]
    exact raise_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat := raise_post_get_seat_at_index row ext max_players
    expected_seat_index h_seat_val hseat
  unfold ContractRaise
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact raise_pre_round_betting row ext max_players h_round
  · rw [h_params_seat, raise_pre_max_players]
    exact hseat
  · rw [h_params_seat, raise_pre_current_turn, h_turn_eq]
    exact h_seat_val
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [h_params_amount, raise_pre_current_bet]
    exact h_money.above_current
  · rw [h_params_amount, h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.above_seat_bet
  · rw [h_params_amount, raise_pre_current_bet, raise_pre_min_raise,
      h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.min_or_short_all_in
  · rw [h_params_amount, h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.needed_le_stack
  · rw [h_params_seat, h_post_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_bet
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_stack
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_total
  · rw [h_params_seat, h_post_seat]
  · rw [h_params_seat, h_post_seat, h_params_amount, h_pre_seat]
    by_cases h_all_in : expected_raise_to - ext.trusted.pre_seat_bet =
        ext.trusted.pre_seat_stack
    · have h_output : ext.output_all_in = M31.one := by
        have h := h_money.output_all_in
        rw [if_pos h_all_in] at h
        exact h
      have h_left : ext.output_all_in.val = M31.one.val :=
        congrArg Subtype.val h_output
      simp [h_left, h_all_in]
    · have h_output : ext.output_all_in = M31.zero := by
        have h := h_money.output_all_in
        rw [if_neg h_all_in] at h
        exact h
      have h_left : ¬ext.output_all_in.val = M31.one.val := by
        rw [h_output]
        norm_num [M31.zero, M31.one]
      simp [h_left, h_all_in]
  · rw [h_params_seat, h_post_seat, h_pre_seat]
  · rw [h_params_seat, h_post_seat, h_pre_seat]
  · rw [raise_post_version, raise_pre_version]
    exact h_ver'
  · rw [raise_post_round_state, raise_pre_round_state, h_rs']
  · rw [raise_post_pot, raise_pre_pot]
    exact h_pot'
  · rw [raise_post_current_bet, h_params_amount]
    exact h_money.output_current_bet
  · rw [raise_post_min_raise, h_params_amount, raise_pre_current_bet,
      raise_pre_min_raise]
    exact h_money.output_min_raise
  · rw [raise_post_current_turn, raise_params_turn, h_money.output_turn]
  · rw [raise_post_dealer_seat, raise_pre_dealer_seat, h_btn']
  · exact raise_post_max_players row ext max_players expected_seat_index
  · simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir,
      TexasPokerTable.update_seat]

end PokerLean
