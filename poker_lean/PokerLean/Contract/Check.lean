import PokerLean.Contract.Types

namespace PokerLean

structure CheckParams where
  seat_index : Nat
deriving Repr

/-- check 方法的合约语义：`apply_check` 的前置条件和状态变更 -/
def ContractCheck
    (pre : TexasPokerTable)
    (params : CheckParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  pre.betting.current_turn = params.seat_index ∧
  (pre.get_seat params.seat_index).is_participating ∧
  ¬ (pre.get_seat params.seat_index).folded ∧
  ¬ (pre.get_seat params.seat_index).all_in ∧
  (pre.get_seat params.seat_index).bet = pre.betting.current_bet ∧
  (post.get_seat params.seat_index).acted_this_round = true ∧
  (post.get_seat params.seat_index).folded = (pre.get_seat params.seat_index).folded ∧
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

/-- check 合约语义的部分版本（AIR 能验证的子集） -/
def ContractCheckPartial
    (pre : TexasPokerTable)
    (params : CheckParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state.is_betting_round ∧
  params.seat_index < pre.max_players ∧
  post.version = pre.version + 1 ∧
  post.round_state = pre.round_state ∧
  post.betting.pot = pre.betting.pot ∧
  post.betting.dealer_seat = pre.betting.dealer_seat ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.chip_pool = pre.chip_pool ∧
  post.hand_id = pre.hand_id

/-- ContractCheck 蕴含 ContractCheckPartial -/
theorem contract_check_implies_partial
    (pre : TexasPokerTable) (params : CheckParams) (post : TexasPokerTable)
    (h : ContractCheck pre params post) :
    ContractCheckPartial pre params post := by
  rcases h with ⟨h_round, h_seat, _h_turn, _h_part, _h_folded, _h_allin, _h_bet,
                  _h_acted, _h_fold2, _h_stack, _h_bet2, _h_total, _h_player, _h_others,
                  h_ver, h_rs, h_pot, _h_cb, h_dealer,
                  h_mp, h_bb, h_sb, h_cp, h_hi⟩
  unfold ContractCheckPartial
  tauto

end PokerLean
