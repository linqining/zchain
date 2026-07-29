import PokerLean.Contract.Types

namespace PokerLean

structure RaiseParams where
  seat_index : Nat
  raise_to : Nat
  /-- mid-round 推进后的下一行动座位。 -/
  post_current_turn : Nat
deriving Repr

/-- raise 的 **mid-round 局部语义**。

该谓词只描述未触发收池/推进/settlement 时的座位更新：增量进入
`seat.bet`，pot 不变，round 不变。它还省略了 VM raise 对其他玩家
`acted_this_round` 的重置等字段，因此不是 VM `apply_raise` 的完整语义。 -/
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
  (params.raise_to - pre.betting.current_bet ≥ pre.betting.min_raise ∨
    params.raise_to - (pre.get_seat params.seat_index).bet =
      (pre.get_seat params.seat_index).stack) ∧
  params.raise_to ≤ (pre.get_seat params.seat_index).stack + (pre.get_seat params.seat_index).bet ∧
  (post.get_seat params.seat_index).bet = params.raise_to ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - (params.raise_to - (pre.get_seat params.seat_index).bet) ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + (params.raise_to - (pre.get_seat params.seat_index).bet) ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.current_bet = params.raise_to ∧
  post.betting.min_raise =
    (if params.raise_to - pre.betting.current_bet ≥ pre.betting.min_raise then
      params.raise_to - pre.betting.current_bet
    else
      pre.betting.min_raise) ∧
  post.betting.current_turn = params.post_current_turn ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- raise mid-round 局部语义的部分版本。 -/
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
  unfold ContractRaise at h
  unfold ContractRaisePartial
  tauto

end PokerLean
