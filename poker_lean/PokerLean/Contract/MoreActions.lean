import PokerLean.Contract.Types

namespace PokerLean

/-! # 更多动作方法的合约语义 -/

/-- AutoFold 参数 -/
structure AutoFoldParams where
  seat_index : Nat
  current_time : Nat
deriving Repr

/-- auto_fold 合约语义 -/
def ContractAutoFold
    (pre : TexasPokerTable)
    (params : AutoFoldParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).folded = true ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- ForceFold 参数 -/
structure ForceFoldParams where
  seat_index : Nat
deriving Repr

/-- force_fold 合约语义 -/
def ContractForceFold
    (pre : TexasPokerTable)
    (params : ForceFoldParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  (post.get_seat params.seat_index).folded = true ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- KickPlayer 参数 -/
structure KickPlayerParams where
  seat_index : Nat
  reason : Nat
deriving Repr

/-- kick_player 合约语义 -/
def ContractKickPlayer
    (pre : TexasPokerTable)
    (params : KickPlayerParams)
    (post : TexasPokerTable)
    : Prop :=
  params.seat_index < pre.max_players ∧
  (pre.get_seat params.seat_index).is_occupied ∧
  (post.get_seat params.seat_index).player = EMPTY_PLAYER ∧
  (post.get_seat params.seat_index).stack = 0 ∧
  (post.get_seat params.seat_index).folded = true ∧
  (post.get_seat params.seat_index).left_during_hand = true ∧
  post.betting.pot = pre.betting.pot + (pre.get_seat params.seat_index).bet ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

end PokerLean
