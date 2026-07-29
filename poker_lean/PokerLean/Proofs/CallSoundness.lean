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

/-! ## 辅助引理（pre 状态提取） -/

private lemma call_pre_round_betting
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromCallAir row ext max_players).round_state.is_betting_round := by
  simp only [extractPreTableFromCallAir, TexasPokerTable.update_seat]
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

private lemma call_pre_max_players
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).max_players = max_players := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_current_turn
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.current_turn =
      ext.input_current_turn.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_version
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_round_state
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_pot
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.pot =
      decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_dealer_seat
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.dealer_seat =
      row.pre_button.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_current_bet
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).betting.current_bet = 0 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_big_blind
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).big_blind = 0 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_small_blind
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).small_blind = 0 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_chip_pool
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).chip_pool = 0 := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_pre_hand_id
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) :
    (extractPreTableFromCallAir row ext max_players).hand_id = row.hand_id.val := by
  simp [extractPreTableFromCallAir, TexasPokerTable.update_seat]

/-! ## 辅助引理（post 状态提取） -/

private lemma call_post_version
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_round_state
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_pot
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.pot =
      decodeU64 row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_dealer_seat
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.dealer_seat =
      row.post_button.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_max_players
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_big_blind
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_small_blind
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_chip_pool
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).chip_pool = 0 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_hand_id
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

private lemma call_post_current_bet
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromCallAir row ext max_players seat_index).betting.current_bet = 0 := by
  simp [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.update_seat]

/-! ## 座位访问引理 -/

/-- 在 pre table 中，input_seat_index 位置的座位含 pre-state 的 stack/bet/total_bet（来自 witness）。 -/
private lemma call_pre_get_seat_at_input
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat)
    (h_seat_val : ext.input_seat_index.val < max_players) :
    (extractPreTableFromCallAir row ext max_players).get_seat ext.input_seat_index.val =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
  simp only [extractPreTableFromCallAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_seat_val, if_true,
             Option.map_some, Option.getD_some]

/-- 当 i ≠ ext.input_seat_index.val 且 i < max_players 时，pre.get_seat i = Seat.empty -/
private lemma call_pre_get_seat_other
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat)
    (i : Nat) (h_ne : i ≠ ext.input_seat_index.val) (h_lt : i < max_players) :
    (extractPreTableFromCallAir row ext max_players).get_seat i = Seat.empty := by
  have h_ne' : ext.input_seat_index.val ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromCallAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- 在 post table 中，seat_index 位置的座位是 call 后的状态（total_bet 来自 witness）。 -/
private lemma call_post_get_seat_at_index
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_seat_eq : ext.input_seat_index.val = seat_index)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromCallAir row ext max_players seat_index).get_seat seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } := by
  subst h_seat_eq
  simp only [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some, Seat.empty]

/-- 在 post table 中，当 i ≠ seat_index 且 i < max_players 时，post.get_seat i = pre.get_seat i -/
private lemma call_post_get_seat_other
    (row : CommonRow) (ext : CallMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromCallAir row ext max_players seat_index).get_seat i =
    (extractPreTableFromCallAir row ext max_players).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromCallAir, extractPreTableFromCallAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

/-- `extractCallParamsFromAir ext` 的 seat_index = ext.input_seat_index.val -/
private lemma call_params_seat
    (ext : CallMethodColumns) :
    (extractCallParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractCallParamsFromAir; rfl

/-- `extractCallParamsFromAir ext` 的 call_amount = decodeU64 ext.input_call_amount -/
private lemma call_params_amount
    (ext : CallMethodColumns) :
    (extractCallParamsFromAir ext).call_amount =
      decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
        ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2 := by
  unfold extractCallParamsFromAir; rfl

/-! ## call AIR 的 mid-round 模型内 soundness 定理

    该定理只在手写 Lean mid-round 局部模型内成立：
    - RoundStateIsBetting：阻止非下注轮 call
    - CurrentTurnMatches：阻止非当前行动座位 call
    - SeatOccupied：阻止空座位 call
    - ButtonUnchanged：dealer_seat 不变
    - PotUnchanged（全 4 limb）：post_pot = pre_pot
    - Limb4DeltaRev（stack）：pre_stack = post_stack + call_amount → call_amount ≤ pre_stack
    - Limb4Delta（bet）：post_bet = pre_bet + call_amount
    - Limb4Delta（total_bet）：post_total_bet = pre_total_bet + call_amount
    - StateRootConsistency：witness 绑定到抽象 committed state root

    它不涵盖 VM 的 end-of-round/settlement 分支，也未证明新 Rust
    `post_current_turn`/trusted-amount 列与本 Lean 列结构等价。 -/
theorem call_air_sound :
  ∀ (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat) (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    CallAirAcceptable row ext expected_seat_index hlt expected_call_amount max_players →
    -- Limb range constraints（由 Rust AIR 的独立 range constraint 保证）
    Limb4Range16 ext.input_call_amount →
    Limb4Range16 ext.output_seat_stack →
    Limb4Range16 ext.input_pre_seat_bet →
    Limb4Range16 ext.input_pre_seat_total_bet →
    ContractCall
      (extractPreTableFromCallAir row ext max_players)
      (extractCallParamsFromAir ext)
      (extractPostTableFromCallAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index hlt expected_call_amount max_players hseat h_air
    h_range_amt h_range_post_stack h_range_pre_bet h_range_pre_total
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : CallMethodConstraints row ext expected_seat_index hlt
                    expected_call_amount max_players := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_seat_eq, h_turn_eq, _h_occ, _h_amt, _h_acted,
                    h_ver, h_rs_unch, h_rsb, _h_btn_unch, h_pot_unch,
                    h_stack_delta, h_bet_delta, h_total_delta, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractCallParamsFromAir ext).seat_index = expected_seat_index := by
    rw [call_params_seat, h_seat_val]
  have h_params_amount : (extractCallParamsFromAir ext).call_amount =
      decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
        ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2 := call_params_amount ext
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
  have h_btn' : row.post_button = row.pre_button := _h_btn_unch h_active
  -- 5. 资金守恒派生（mid-round pot 不变，座位筹码仅在 stack/bet 间移动）
  have h_pot_eq : decodeU64 row.post_pot.1 row.post_pot.2.1
                    row.post_pot.2.2.1 row.post_pot.2.2.2 =
                  decodeU64 row.pre_pot.1 row.pre_pot.2.1
                    row.pre_pot.2.2.1 row.pre_pot.2.2.2 :=
    pot_unchanged_implies_decode_eq row h_active h_pot_unch
  have h_pre_stack : decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
                       ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2 =
                     decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
                       ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2 +
                     decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
                       ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2 :=
    limb4_delta_rev_implies_decode_eq ext.input_pre_seat_stack ext.output_seat_stack
      ext.input_call_amount h_range_post_stack h_range_amt h_stack_delta
  have h_post_bet_eq : decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
                         ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 =
                       decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
                         ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2 +
                       decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
                         ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2 :=
    limb4_delta_implies_decode_eq ext.input_pre_seat_bet ext.output_seat_bet
      ext.input_call_amount h_range_pre_bet h_range_amt h_bet_delta
  have h_post_total_eq : decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
                           ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2 =
                         decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
                           ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 +
                         decodeU64 ext.input_call_amount.1 ext.input_call_amount.2.1
                           ext.input_call_amount.2.2.1 ext.input_call_amount.2.2.2 :=
    limb4_delta_implies_decode_eq ext.input_pre_seat_total_bet ext.output_seat_total_bet
      ext.input_call_amount h_range_pre_total h_range_amt h_total_delta
  -- 6. 座位级引理
  have h_pre_seat : (extractPreTableFromCallAir row ext max_players).get_seat expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.input_pre_seat_stack.1 ext.input_pre_seat_stack.2.1
            ext.input_pre_seat_stack.2.2.1 ext.input_pre_seat_stack.2.2.2,
        bet := decodeU64 ext.input_pre_seat_bet.1 ext.input_pre_seat_bet.2.1
            ext.input_pre_seat_bet.2.2.1 ext.input_pre_seat_bet.2.2.2,
        total_bet := decodeU64 ext.input_pre_seat_total_bet.1 ext.input_pre_seat_total_bet.2.1
            ext.input_pre_seat_total_bet.2.2.1 ext.input_pre_seat_total_bet.2.2.2 } := by
    rw [← h_seat_val]
    exact call_pre_get_seat_at_input row ext max_players h_seat_lt
  have h_post_seat : (extractPostTableFromCallAir row ext max_players expected_seat_index).get_seat expected_seat_index =
      { { { Seat.empty with player := PlayerId.ofNat 1 } with
          stack := decodeU64 ext.output_seat_stack.1 ext.output_seat_stack.2.1
            ext.output_seat_stack.2.2.1 ext.output_seat_stack.2.2.2,
          bet := decodeU64 ext.output_seat_bet.1 ext.output_seat_bet.2.1
            ext.output_seat_bet.2.2.1 ext.output_seat_bet.2.2.2 } with
        total_bet := decodeU64 ext.output_seat_total_bet.1 ext.output_seat_total_bet.2.1
            ext.output_seat_total_bet.2.2.1 ext.output_seat_total_bet.2.2.2,
        acted_this_round := true } :=
    call_post_get_seat_at_index row ext max_players expected_seat_index h_seat_val hseat
  -- 7. 证明 ContractCall 的 24 个合取
  unfold ContractCall
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. pre.round_state.is_betting_round
    exact call_pre_round_betting row ext max_players h_rsb'
  · -- 2. params.seat_index < pre.max_players
    rw [h_params_seat, call_pre_max_players]; exact hseat
  · -- 3. pre.betting.current_turn = params.seat_index
    rw [h_params_seat, call_pre_current_turn, h_turn_eq]; exact h_seat_val
  · -- 4. (pre.get_seat params.seat_index).is_participating
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_participating, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 5. ¬ (pre.get_seat params.seat_index).folded
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 6. ¬ (pre.get_seat params.seat_index).all_in
    rw [h_params_seat, h_pre_seat]
    simp [Seat.empty]
  · -- 7. params.call_amount ≤ (pre.get_seat params.seat_index).stack
    -- 由 stack delta: pre_stack = post_stack + call_amount, post_stack ≥ 0 → call_amount ≤ pre_stack
    rw [h_params_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    omega
  · -- 8. (post.get_seat ...).stack = (pre.get_seat ...).stack - params.call_amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    omega
  · -- 9. (post.get_seat ...).bet = (pre.get_seat ...).bet + params.call_amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    exact h_post_bet_eq
  · -- 10. (post.get_seat ...).total_bet = (pre.get_seat ...).total_bet + params.call_amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    simp only [Seat.empty]
    exact h_post_total_eq
  · -- 11. (post.get_seat params.seat_index).acted_this_round = true
    rw [h_params_seat, h_post_seat]
  · -- 12. (post.get_seat ...).folded = (pre.get_seat ...).folded
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 13. (post.get_seat ...).player = (pre.get_seat ...).player
    rw [h_params_seat, h_post_seat, h_pre_seat]
  · -- 14. ∀ i, i ≠ params.seat_index → i < max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [call_pre_max_players] at h_lt
    exact call_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 15. post.version = pre.version + 1
    rw [call_post_version, call_pre_version]; exact h_ver'
  · -- 16. post.round_state = pre.round_state
    rw [call_post_round_state, call_pre_round_state, h_rs']
  · -- 17. mid-round: post.betting.pot = pre.betting.pot
    rw [call_post_pot, call_pre_pot]; exact h_pot_eq
  · -- 18. post.betting.current_bet = pre.betting.current_bet
    rw [call_post_current_bet, call_pre_current_bet]
  · -- 19. post.betting.dealer_seat = pre.betting.dealer_seat
    rw [call_post_dealer_seat, call_pre_dealer_seat, h_btn']
  · -- 20. post.max_players = pre.max_players
    exact call_post_max_players row ext max_players expected_seat_index
  · -- 21. post.big_blind = pre.big_blind
    rw [call_post_big_blind, call_pre_big_blind]
  · -- 22. post.small_blind = pre.small_blind
    rw [call_post_small_blind, call_pre_small_blind]
  · -- 23. post.chip_pool = pre.chip_pool
    rw [call_post_chip_pool, call_pre_chip_pool]
  · -- 24. post.hand_id = pre.hand_id
    rw [call_post_hand_id, call_pre_hand_id]

end PokerLean
