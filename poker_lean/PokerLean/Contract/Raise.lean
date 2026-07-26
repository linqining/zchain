import PokerLean.Contract.Types

namespace PokerLean

structure RaiseParams where
  seat_index : Nat
  raise_to : Nat
deriving Repr

/-- raise 方法的合约语义 -/
def ContractRaise
    (pre : TexasPokerTable)
    (params : RaiseParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  (pre.get_seat params.seat_index).is_participating ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  ¬ (pre.get_seat params.seat_index).all_in ∧
  params.raise_to > pre.betting.current_bet ∧
  params.raise_to - pre.betting.current_bet ≥ pre.betting.min_raise ∧
  params.raise_to ≤ (pre.get_seat params.seat_index).stack + (pre.get_seat params.seat_index).bet ∧
  (post.get_seat params.seat_index).bet = params.raise_to ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - (params.raise_to - (pre.get_seat params.seat_index).bet) ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + (params.raise_to - (pre.get_seat params.seat_index).bet) ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot + (params.raise_to - (pre.get_seat params.seat_index).bet) ∧
  post.betting.current_bet = params.raise_to ∧
  post.betting.min_raise = params.raise_to - pre.betting.current_bet ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- raise 合约语义的部分版本 -/
def ContractRaisePartial
    (pre : TexasPokerTable)
    (params : RaiseParams)
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

/-- ContractRaise 蕴含 ContractRaisePartial -/
theorem contract_raise_implies_partial
    (pre : TexasPokerTable) (params : RaiseParams) (post : TexasPokerTable)
    (h : ContractRaise pre params post) :
    ContractRaisePartial pre params post := by
  rcases h with ⟨h_round, h_seat, _h_turn, _h_part, _h_folded, _h_allin,
                  _h_gt, _h_min, _h_le,
                  _h_bet, _h_stack, _h_total, _h_acted, _h_fold2, _h_player, _h_others,
                  h_ver, h_rs, _h_pot, _h_cb, _h_mr, h_dealer,
                  h_mp, h_bb, h_sb, h_cp, h_hi⟩
  unfold ContractRaisePartial
  tauto

end PokerLean
