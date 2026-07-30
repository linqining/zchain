import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Call
import PokerLean.AIR.AirBase
import PokerLean.AIR.CallAir

namespace PokerLean

private lemma call_pre_round_betting
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromCallAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromCallAir, TexasPokerTable.update_seat]
  rcases h with h | h | h | h <;>
    rw [h] <;> simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma call_pre_max_players
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_current_turn
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_current_bet
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.current_bet =
      ext.trusted.pre_current_bet := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_version
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).version = decodeLimb4 row.pre_version := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_round_state
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_pot
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.pot = decodeLimb4 row.pre_pot := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_dealer_seat
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.dealer_seat = row.pre_button.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_version
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).version =
      decodeLimb4 row.post_version := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_round_state
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_pot
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.pot =
      decodeLimb4 row.post_pot := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_current_turn
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.current_turn =
      ext.output_current_turn.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_current_bet
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.current_bet =
      ext.trusted.pre_current_bet := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_dealer_seat
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_post_max_players
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.update_seat]

private lemma call_pre_get_seat_at_input
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat)
    (h_lt : ext.input_seat_index.val < max_players) :
    (extractPreTableFromCallAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := ext.trusted.pre_seat_stack,
        bet := ext.trusted.pre_seat_bet,
        total_bet := ext.trusted.pre_seat_total_bet } := by
  simp only [extractPreTableFromCallAir, TexasPokerTable.get_seat,
    TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
    List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
    Option.map_some, Option.getD_some]

private lemma call_post_get_seat_at_index
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index) (h_lt : seat_index < max_players) :
    (extractPostTableFromCallAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeLimb4 ext.output_seat_stack,
          bet := decodeLimb4 ext.output_seat_bet } with
        total_bet := decodeLimb4 ext.output_seat_total_bet,
        all_in := decide (ext.output_all_in.val = M31.one.val),
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.get_seat, TexasPokerTable.update_seat,
    List.getD_eq_getD_get?, List.get?_eq_getElem?, List.getElem?_modify_eq,
    List.getElem?_replicate, h_lt, if_true, Option.map_some, Option.getD_some,
    Seat.empty]

private lemma call_post_get_seat_other
    (row : CommonRow) (ext : CallMethodColumns) (max_players seat_index i : Nat)
    (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromCallAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromCallAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromCallAir, extractPreTableFromCallAir,
    TexasPokerTable.get_seat, TexasPokerTable.update_seat,
    List.getD_eq_getD_get?, List.get?_eq_getElem?,
    List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
    Option.getD_some]

private lemma call_params_seat (ext : CallMethodColumns) :
    (extractCallParamsFromAir ext).seat_index = ext.input_seat_index.val := rfl

private lemma call_params_amount (ext : CallMethodColumns) :
    (extractCallParamsFromAir ext).call_amount = decodeLimb4 ext.input_call_amount := rfl

private lemma call_params_turn (ext : CallMethodColumns) :
    (extractCallParamsFromAir ext).post_current_turn = ext.output_current_turn.val := rfl

/-- Rust trusted-u64 规则同步后的 call mid-round soundness。

该定理仍不覆盖 collect-bets/round-advance/settlement，也不声称已证明 Rust
`expected_trace_row → BoundAir` 与本手写 Lean record 的实现级 refinement。 -/
theorem call_air_sound :
  ∀ (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat) (expected_trusted : CallTrustedInputs)
    (max_players : Nat) (hseat : expected_seat_index < max_players),
    CallAirAcceptable row ext expected_seat_index hlt expected_call_amount
      expected_trusted max_players →
    ContractCall
      (extractPreTableFromCallAir row ext max_players)
      (extractCallParamsFromAir ext)
      (extractPostTableFromCallAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_call_amount expected_trusted
    max_players hseat h_air
  rcases h_air with ⟨_h_common, _h_trusted, h_method, _h_kind, h_active⟩
  rcases h_method h_active with
    ⟨h_seat_eq, h_turn_eq, _h_occ, _h_acted, h_money, h_ver, h_rs_unch,
      h_rsb, h_btn_unch, h_pot_unch, _h_src⟩
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]
    simp [nat_to_m31]
  have h_params_seat : (extractCallParamsFromAir ext).seat_index = expected_seat_index := by
    rw [call_params_seat, h_seat_val]
  have h_params_amount :
      (extractCallParamsFromAir ext).call_amount = expected_call_amount := by
    rw [call_params_amount]
    exact h_money.amount_witness
  have h_seat_lt : ext.input_seat_index.val < max_players := by
    rw [h_seat_val]
    exact hseat
  have h_round : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
      row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5 := h_rsb h_active
  have h_ver' : decodeLimb4 row.post_version = decodeLimb4 row.pre_version + 1 :=
    h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  have h_btn' : row.post_button = row.pre_button := h_btn_unch h_active
  have h_pot' : decodeLimb4 row.post_pot = decodeLimb4 row.pre_pot := by
    exact pot_unchanged_implies_decode_eq row h_active h_pot_unch
  have h_pre_seat :
      (extractPreTableFromCallAir row ext max_players).get_seat expected_seat_index =
        { Seat.empty with
          player := PlayerId.ofNat 1,
          stack := ext.trusted.pre_seat_stack,
          bet := ext.trusted.pre_seat_bet,
          total_bet := ext.trusted.pre_seat_total_bet } := by
    rw [← h_seat_val]
    exact call_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat := call_post_get_seat_at_index row ext max_players
    expected_seat_index h_seat_val hseat
  unfold ContractCall
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact call_pre_round_betting row ext max_players h_round
  · rw [h_params_seat, call_pre_max_players]
    exact hseat
  · rw [h_params_seat, call_pre_current_turn, h_turn_eq]
    exact h_seat_val
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · rw [h_params_amount, call_pre_current_bet, h_params_seat, h_pre_seat]
    simpa [Seat.empty] using h_money.exact_amount
  · rw [h_params_amount, h_params_seat, h_pre_seat]
    simp only [Seat.empty]
    rw [h_money.exact_amount]
    exact Nat.min_le_right _ _
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_stack
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_bet
  · rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simpa [Seat.empty] using h_money.output_total
  · rw [h_params_seat, h_post_seat]
  · rw [h_params_seat, h_post_seat, h_params_amount, h_pre_seat]
    by_cases h_all_in : expected_call_amount > 0 ∧
        expected_call_amount = ext.trusted.pre_seat_stack
    · have h_output : ext.output_all_in = M31.one := by
        have h := h_money.output_all_in
        rw [if_pos h_all_in] at h
        exact h
      have h_left : ext.output_all_in.val = M31.one.val :=
        congrArg Subtype.val h_output
      rcases h_all_in with ⟨h_pos, h_eq⟩
      have h_stack_pos : ext.trusted.pre_seat_stack > 0 := by omega
      simp [h_left, h_pos, h_eq, h_stack_pos]
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
  · intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [call_pre_max_players] at h_lt
    exact call_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · rw [call_post_version, call_pre_version]
    exact h_ver'
  · rw [call_post_round_state, call_pre_round_state, h_rs']
  · rw [call_post_pot, call_pre_pot]
    exact h_pot'
  · rw [call_post_current_turn, call_params_turn, h_money.output_turn]
  · rw [call_post_current_bet, call_pre_current_bet]
  · rw [call_post_dealer_seat, call_pre_dealer_seat, h_btn']
  · exact call_post_max_players row ext max_players expected_seat_index
  · simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
      TexasPokerTable.update_seat]
  · simp [extractPostTableFromCallAir, extractPreTableFromCallAir,
      TexasPokerTable.update_seat]

end PokerLean
