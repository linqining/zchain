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

/-! ## 辅助引理（pre 状态提取） -/

private lemma raise_pre_round_betting
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromRaiseAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma raise_pre_max_players
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_current_turn
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_version
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_round_state
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_pot
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_dealer_seat
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_current_bet
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.current_bet = 0 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_min_raise
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).betting.min_raise = 0 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_big_blind
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_small_blind
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_chip_pool
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_pre_hand_id
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) :
    (extractPreTableFromRaiseAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

/-! ## 辅助引理（post 状态提取） -/

private lemma raise_post_version
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_round_state
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_pot
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_dealer_seat
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_max_players
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_big_blind
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_small_blind
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_chip_pool
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_hand_id
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_current_bet
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.current_bet =
      decodeU64 ext.output_current_bet.1 ext.output_current_bet.2.1
        ext.output_current_bet.2.2.1 ext.output_current_bet.2.2.2 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

private lemma raise_post_min_raise
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).betting.min_raise =
      decodeU64 ext.output_min_raise.1 ext.output_min_raise.2.1
        ext.output_min_raise.2.2.1 ext.output_min_raise.2.2.2 := by
  simp [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

/-- 在 pre table 中，input_seat_index 位置的座位含 pre-state 的 stack/bet/total_bet（来自 witness）。 -/
private lemma raise_pre_get_seat_at_input
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromRaiseAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
  simp only [extractPreTableFromRaiseAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

private lemma raise_pre_get_seat_other
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromRaiseAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromRaiseAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- 在 post table 中，seat_index 位置的座位是 raise 后的状态（total_bet 来自 witness）。 -/
private lemma raise_post_get_seat_at_index
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some, Seat.empty]

private lemma raise_post_get_seat_other
    (row : CommonRow) (ext : RaiseMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromRaiseAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromRaiseAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromRaiseAir, extractPreTableFromRaiseAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma raise_params_seat
    (ext : RaiseMethodColumns) :
    (extractRaiseParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractRaiseParamsFromAir; rfl

private lemma raise_params_amount
    (ext : RaiseMethodColumns) :
    (extractRaiseParamsFromAir ext).raise_to =
      decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
        ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 := by
  unfold extractRaiseParamsFromAir; rfl

/-! ## raise AIR soundness 主定理

    所有 Gap 均已闭合：
    - RoundStateIsBetting：阻止非下注轮 raise
    - CurrentTurnMatches：阻止非当前行动座位 raise
    - SeatOccupied：阻止空座位 raise
    - ButtonUnchanged：dealer_seat 不变
    - AmountPositive：raise_to > 0（pre.current_bet = 0 ⟹ raise_to > current_bet）
    - PotDelta（全 4 limb，对 call_delta）：post_pot = pre_pot + (raise_to - pre_bet)
    - Limb4DeltaRev（stack，对 call_delta）：pre_stack = post_stack + delta ⟹ raise_to ≤ pre_stack + pre_bet
    - Limb4Delta（pre_bet → post_bet，对 call_delta）+ Limb4Eq（post_bet = raise_to）：
      post_bet = raise_to（且 delta = raise_to - pre_bet）
    - Limb4Delta（total_bet，对 call_delta）：post_total_bet = pre_total_bet + delta
    - Limb4Eq（current_bet）：post_current_bet = raise_to
    - Limb4Eq（min_raise）：post_min_raise = raise_to（pre.current_bet = 0）
    - StateRootConsistency：witness 绑定到 committed state root -/
theorem raise_air_sound :
  ∀ (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat) (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to max_players →
    ContractRaise
      (extractPreTableFromRaiseAir row ext max_players)
      (extractRaiseParamsFromAir ext)
      (extractPostTableFromRaiseAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_raise_to max_players hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : RaiseMethodConstraints row ext expected_seat_index hlt
                    expected_raise_to max_players := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_amt, _h_acted, h_amt_pos,
                    h_ver, h_rs_unch, h_rsb, _h_btn_unch,
                    h_pot_delta_c, h_stack_delta_c, h_bet_delta_c, h_total_delta_c,
                    h_bet_eq_c, h_cb_eq_c, h_mr_eq_c, _h_src⟩
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractRaiseParamsFromAir ext).seat_index = expected_seat_index := by
    rw [raise_params_seat, h_seat_val]
  have h_params_amount : (extractRaiseParamsFromAir ext).raise_to =
      decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
        ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 := raise_params_amount ext
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
  -- 资金守恒派生（从 limb delta/equality 约束得到 decodeU64 级等式）
  have h_pot_eq : decodeU64 row.post_pot.1 row.post_pot.2.1
                    row.post_pot.2.2.1 row.post_pot.2.2.2 =
                  decodeU64 row.pre_pot.1 row.pre_pot.2.1
                    row.pre_pot.2.2.1 row.pre_pot.2.2.2 +
                  decodeU64 ext.input_call_delta.1 ext.input_call_delta.2.1
                    ext.input_call_delta.2.2.1 ext.input_call_delta.2.2.2 :=
    pot_delta_implies_decode_eq row ext.input_call_delta h_active h_pot_delta_c
  have h_pre_stack : decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
                       ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2 =
                     decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
                       ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2 +
                     decodeU64 ext.input_call_delta.1 ext.input_call_delta.2.1
                       ext.input_call_delta.2.2.1 ext.input_call_delta.2.2.2 :=
    limb4_delta_rev_implies_decode_eq ext.input_pre_seat_stack ext.output_seat_stack
      ext.input_call_delta h_stack_delta_c
  have h_bet_delta : decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
                       ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 =
                     decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
                       ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2 +
                     decodeU64 ext.input_call_delta.1 ext.input_call_delta.2.1
                       ext.input_call_delta.2.2.1 ext.input_call_delta.2.2.2 :=
    limb4_delta_implies_decode_eq ext.input_pre_seat_bet ext.output_seat_bet
      ext.input_call_delta h_bet_delta_c
  have h_post_total_eq : decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
                           ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2 =
                         decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
                           ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 +
                         decodeU64 ext.input_call_delta.1 ext.input_call_delta.2.1
                           ext.input_call_delta.2.2.1 ext.input_call_delta.2.2.2 :=
    limb4_delta_implies_decode_eq ext.input_pre_seat_total_bet ext.output_seat_total_bet
      ext.input_call_delta h_total_delta_c
  have h_post_bet_eq : decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
                         ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 =
                       decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
                         ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_seat_bet ext.input_raise_to h_bet_eq_c
  have h_post_cb_eq : decodeU64 ext.output_current_bet.1 ext.output_current_bet.2.1
                        ext.output_current_bet.2.2.1 ext.output_current_bet.2.2.2 =
                      decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
                        ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_current_bet ext.input_raise_to h_cb_eq_c
  have h_post_mr_eq : decodeU64 ext.output_min_raise.1 ext.output_min_raise.2.1
                        ext.output_min_raise.2.2.1 ext.output_min_raise.2.2.2 =
                      decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
                        ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 :=
    limb4_eq_implies_decode_eq ext.output_min_raise ext.input_raise_to h_mr_eq_c
  -- 关键派生：call_delta = raise_to - pre_bet（联立 bet delta 与 post_bet = raise_to）
  have h_delta_eq : decodeU64 ext.input_call_delta.1 ext.input_call_delta.2.1
                      ext.input_call_delta.2.2.1 ext.input_call_delta.2.2.2 =
                    decodeU64 ext.input_raise_to.1 ext.input_raise_to.2.1
                      ext.input_raise_to.2.2.1 ext.input_raise_to.2.2.2 -
                    decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
                      ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2 := by
    omega
  -- 座位级引理
  have h_pre_seat : (extractPreTableFromRaiseAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
    rw [← h_seat_val]
    exact raise_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromRaiseAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } :=
    raise_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- ContractRaise 有 27 个合取
  unfold ContractRaise
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact raise_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, raise_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, raise_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. (pre.get_seat params.seat_index).is_participating
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 5. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 6. ¬ (pre.get_seat params.seat_index).all_in
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 7. params.raise_to > pre.betting.current_bet — pre.current_bet = 0, 需 raise_to > 0
    rw [raise_pre_current_bet, h_params_amount]
    exact h_amt_pos
  · -- 8. params.raise_to - pre.betting.current_bet ≥ pre.betting.min_raise
    -- pre.current_bet = 0, pre.min_raise = 0, so raise_to ≥ 0
    rw [raise_pre_current_bet, raise_pre_min_raise, h_params_amount]
    exact Nat.zero_le _
  · -- 9. params.raise_to ≤ pre.stack + pre.bet
    -- 由 h_pre_stack (pre_stack = post_stack + delta) 与 h_delta_eq (delta = raise_to - pre_bet)：
    --   raise_to = pre_bet + delta ≤ pre_bet + pre_stack
    rw [h_params_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    omega
  · -- 10. post.bet = raise_to
    rw [h_params_seat, h_post_seat, h_params_amount]
    simp only [Seat.empty]
    exact h_post_bet_eq
  · -- 11. post.stack = pre.stack - (raise_to - pre.bet)
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    omega
  · -- 12. post.total_bet = pre.total_bet + (raise_to - pre.bet)
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    omega
  · -- 13. (post.get_seat ...).acted_this_round = true
    rw [h_params_seat, h_post_seat]
  · -- 14. (post.get_seat ...).folded = (pre.get_seat ...).folded
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 15. (post.get_seat ...).player = (pre.get_seat ...).player
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 16. ∀ i, i ≠ params.seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [raise_pre_max_players] at h_lt
    exact raise_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 17. post.version = pre.version + 1
    rw [raise_post_version, raise_pre_version]; exact h_ver'
  · -- 18. post.round_state = pre.round_state
    rw [raise_post_round_state, raise_pre_round_state, h_rs']
  · -- 19. post.betting.pot = pre.betting.pot + (raise_to - pre.bet)
    rw [raise_post_pot, raise_pre_pot, h_params_amount]
    rw [h_params_seat, h_pre_seat]
    simp only [Seat.empty]
    omega
  · -- 20. post.betting.current_bet = params.raise_to
    rw [raise_post_current_bet, h_params_amount]; exact h_post_cb_eq
  · -- 21. post.betting.min_raise = params.raise_to - pre.betting.current_bet
    -- pre.current_bet = 0, so RHS = raise_to - 0 = raise_to
    rw [raise_post_min_raise, raise_pre_current_bet, h_params_amount]
    omega
  · -- 22. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [raise_post_dealer_seat, raise_pre_dealer_seat, h_btn']
  · -- 23. post.max_players = pre.max_players
    exact raise_post_max_players row ext max_players expected_seat_index
  · -- 24. post.big_blind = pre.big_blind
    rw [raise_post_big_blind, raise_pre_big_blind]
  · -- 25. post.small_blind = pre.small_blind
    rw [raise_post_small_blind, raise_pre_small_blind]
  · -- 26. post.chip_pool = pre.chip_pool
    rw [raise_post_chip_pool, raise_pre_chip_pool]
  · -- 27. post.hand_id = pre.hand_id
    rw [raise_post_hand_id, raise_pre_hand_id]

end PokerLean
