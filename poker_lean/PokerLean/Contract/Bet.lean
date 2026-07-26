import PokerLean.Contract.Types

namespace PokerLean

structure BetParams where
  seat_index : Nat
  bet_amount : Nat
deriving Repr

/-- bet 方法的合约语义 -/
def ContractBet
    (pre : TexasPokerTable)
    (params : BetParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  (pre.get_seat params.seat_index).is_participating ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  ¬ (pre.get_seat params.seat_index).all_in ∧
  pre.betting.current_bet = 0 ∧
  params.bet_amount > 0 ∧
  params.bet_amount ≤ (pre.get_seat params.seat_index).stack ∧
  params.bet_amount ≥ pre.betting.min_raise ∧
  (post.get_seat params.seat_index).bet = params.bet_amount ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - params.bet_amount ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + params.bet_amount ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot + params.bet_amount ∧
  post.betting.current_bet = params.bet_amount ∧
  post.betting.min_raise = params.bet_amount ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- bet 合约语义的部分版本 -/
def ContractBetPartial
    (pre : TexasPokerTable)
    (params : BetParams)
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

theorem contract_bet_implies_partial
    (pre : TexasPokerTable) (params : BetParams) (post : TexasPokerTable)
    (h : ContractBet pre params post) :
    ContractBetPartial pre params post := by
  rcases h with ⟨h_round, h_seat, _h_turn, _h_part, _h_folded, _h_allin,
                  _h_cb0, _h_amt_gt, _h_amt_le, _h_min,
                  _h_bet, _h_stack, _h_total, _h_acted, _h_fold2, _h_player, _h_others,
                  h_ver, h_rs, _h_pot, _h_cb, _h_mr, h_dealer,
                  h_mp, h_bb, h_sb, h_cp, h_hi⟩
  unfold ContractBetPartial
  tauto

end PokerLean
