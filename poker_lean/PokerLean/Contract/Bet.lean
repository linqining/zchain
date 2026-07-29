import PokerLean.Contract.Types

namespace PokerLean

structure BetParams where
  seat_index : Nat
  bet_amount : Nat
  /-- mid-round 推进后的下一行动座位。 -/
  post_current_turn : Nat
deriving Repr

/-- bet 的 **mid-round 局部语义**。

该谓词只描述未触发收池/推进/settlement 时的座位更新：下注筹码
仍位于 `seat.bet`，pot 不变，round 不变。它不是 VM `apply_bet`
（内部委托 raise 并调用 `advance_turn`）的完整语义，也未建模
raise 对其他玩家 `acted_this_round` 的重置。 -/
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
  pre.betting.current_bet ≤ (pre.get_seat params.seat_index).bet ∧
  params.bet_amount > 0 ∧
  (pre.get_seat params.seat_index).bet + params.bet_amount > pre.betting.current_bet ∧
  params.bet_amount ≤ (pre.get_seat params.seat_index).stack ∧
  ((pre.get_seat params.seat_index).bet + params.bet_amount - pre.betting.current_bet ≥
      pre.betting.min_raise ∨
    params.bet_amount = (pre.get_seat params.seat_index).stack) ∧
  (post.get_seat params.seat_index).bet =
    (pre.get_seat params.seat_index).bet + params.bet_amount ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - params.bet_amount ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + params.bet_amount ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.current_bet =
    (pre.get_seat params.seat_index).bet + params.bet_amount ∧
  post.betting.min_raise =
    (if (pre.get_seat params.seat_index).bet + params.bet_amount - pre.betting.current_bet ≥
        pre.betting.min_raise then
      (pre.get_seat params.seat_index).bet + params.bet_amount - pre.betting.current_bet
    else
      pre.betting.min_raise) ∧
  post.betting.current_turn = params.post_current_turn ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- bet mid-round 局部语义的部分版本。 -/
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
  unfold ContractBet at h
  unfold ContractBetPartial
  tauto

end PokerLean
