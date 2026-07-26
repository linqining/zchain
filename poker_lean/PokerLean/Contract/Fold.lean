import PokerLean.Contract.Types

namespace PokerLean

structure FoldParams where
  seat_index : Nat
deriving Repr

def ContractFold
    (pre : TexasPokerTable)
    (params : FoldParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  (pre.get_seat params.seat_index).is_participating ∧
  (post.get_seat params.seat_index).folded = true ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).stack = (pre.get_seat params.seat_index).stack ∧
  (post.get_seat params.seat_index).bet = (pre.get_seat params.seat_index).bet ∧
  (post.get_seat params.seat_index).total_bet = (pre.get_seat params.seat_index).total_bet ∧
  (post.get_seat params.seat_index).player = (pre.get_seat params.seat_index).player ∧
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.current_bet = pre.betting.current_bet ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

theorem fold_post_folded (pre : TexasPokerTable)
    (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
  (post.get_seat params.seat_index).folded = true := by
  rcases h with ⟨_, _, _, _, hfolded, _⟩
  exact hfolded

theorem fold_version_inc (pre : TexasPokerTable)
    (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
  post.version = pre.version + 1 := by
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hver, _⟩
  exact hver

theorem fold_round_state_unchanged (pre : TexasPokerTable)
    (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
  post.round_state = pre.round_state := by
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, _, hrs, _⟩
  exact hrs

end PokerLean
