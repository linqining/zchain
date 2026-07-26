import PokerLean.Contract.Types

namespace PokerLean

structure CallParams where
  seat_index : Nat
  call_amount : Nat
deriving Repr

/-- call 方法的合约语义：`apply_call` 的前置条件和状态变更 -/
def ContractCall
    (pre : TexasPokerTable)
    (params : CallParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  (pre.get_seat params.seat_index).is_participating ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  ¬ (pre.get_seat params.seat_index).all_in ∧
  params.call_amount ≤ (pre.get_seat params.seat_index).stack ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - params.call_amount ∧
  (post.get_seat params.seat_index).bet = (pre.get_seat params.seat_index).bet + params.call_amount ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + params.call_amount ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot + params.call_amount ∧
  post.betting.current_bet = pre.betting.current_bet ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- call 合约语义的部分版本（AIR 能验证的子集） -/
def ContractCallPartial
    (pre : TexasPokerTable)
    (params : CallParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- ContractCall 蕴含 ContractCallPartial -/
theorem contract_call_implies_partial
    (pre : TexasPokerTable) (params : CallParams) (post : TexasPokerTable)
    (h : ContractCall pre params post) :
    ContractCallPartial pre params post := by
  rcases h with ⟨h_round, h_seat, _h_turn, _h_part, _h_folded, _h_allin, _h_amt_le,
                  _h_stack, _h_bet, _h_total, _h_acted, _h_fold2, _h_player, _h_others,
                  h_ver, h_rs, _h_pot, _h_cb, h_dealer,
                  h_mp, h_bb, h_sb, h_cp, h_hi⟩
  unfold ContractCallPartial
  tauto

end PokerLean
