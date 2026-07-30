import PokerLean.Contract.Types

namespace PokerLean

structure CallParams where
  seat_index : Nat
  call_amount : Nat
  /-- mid-round 推进后的下一行动座位。 -/
  post_current_turn : Nat
deriving Repr

/-- call 的 **mid-round 局部语义**。

该谓词只描述座位筹码更新以及 `advance_turn` 未结束当前下注轮时的
post-state：筹码仍留在 `seat.bet`，pot 不变，round 不变。它不是 VM
`apply_call` 的完整语义；收池、推进 round 和 settlement 分支未在此建模。 -/
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
  params.call_amount =
    min (pre.betting.current_bet - (pre.get_seat params.seat_index).bet)
      (pre.get_seat params.seat_index).stack ∧
  params.call_amount ≤ (pre.get_seat params.seat_index).stack ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack - params.call_amount ∧
  (post.get_seat params.seat_index).bet = (pre.get_seat params.seat_index).bet + params.call_amount ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet + params.call_amount ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).all_in = decide
    (params.call_amount > 0 ∧
      params.call_amount = (pre.get_seat params.seat_index).stack) ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.current_turn = params.post_current_turn ∧
  post.betting.current_bet = pre.betting.current_bet ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- call mid-round 局部语义的部分版本（手写 Lean AIR 能验证的子集）。 -/
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
  unfold ContractCall at h
  unfold ContractCallPartial
  tauto

end PokerLean
