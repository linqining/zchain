import PokerLean.Contract.Types

namespace PokerLean

structure CreateTableParams where
  table_id : Nat
  name_hash : Nat
  max_players : Nat
  small_blind : Nat
  big_blind : Nat
  is_private : Bool
  timeout : Nat
deriving Repr

namespace CreateTableParams
def Valid (p : CreateTableParams) : Prop :=
  2 ≤ p.max_players ∧ p.max_players ≤ 9 ∧
  p.big_blind > 0 ∧ p.small_blind ≤ p.big_blind
end CreateTableParams

def ContractCreateTable
    (pre : TexasPokerTable)
    (params : CreateTableParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.version = 0 ∧
  pre.round_state = RoundState.ROUND_WAITING ∧
  List.isEmpty pre.seats ∧
  params.Valid ∧
  post.table_id = params.table_id ∧
  post.name_hash = params.name_hash ∧
  post.max_players = params.max_players ∧
  post.small_blind = params.small_blind ∧
  post.big_blind = params.big_blind ∧
  post.is_private = params.is_private ∧
  post.timeout = params.timeout ∧
  post.version = pre.version + 1 ∧
  post.round_state = RoundState.ROUND_WAITING ∧
  post.all_seats_empty ∧
  post.seats.length = params.max_players ∧
  post.betting.pot = 0 ∧
  post.betting.dealer_seat = 0 ∧
  post.betting.current_turn = 0 ∧
  post.betting.current_bet = 0 ∧
  post.betting.min_raise = params.big_blind ∧
  List.isEmpty post.betting.side_pots ∧
  post.shuffle_state.phase = 0 ∧
  post.reveal_state.reveal_phase = 0 ∧
  post.deck_state = DeckState.DeckIdle ∧
  post.reconstruct_state = ReconstructState.ReconstructIdle ∧
  post.ante = 0 ∧
  post.chip_pool = 0 ∧
  post.addon_pool = 0 ∧
  post.pending_addon_total = 0 ∧
  post.pending_rebuy_total = 0 ∧
  post.rake = 0 ∧
  post.table_fee = 0 ∧
  post.hand_id = 0 ∧
  post.call_seq = 0 ∧
  post.started_at = 0 ∧
  post.last_action_time = 0

theorem create_table_exists (pre : TexasPokerTable) (params : CreateTableParams)
    (hpre : pre.version = 0 ∧ pre.round_state = RoundState.ROUND_WAITING ∧ List.isEmpty pre.seats)
    (hvalid : params.Valid) :
  ∃ post : TexasPokerTable, ContractCreateTable pre params post := by
  rcases hpre with ⟨hpre_ver, hpre_rs, hpre_s⟩
  rcases hvalid with ⟨hmp_lo, hmp_hi, hbb, hsb⟩
  let post := TexasPokerTable.init params.table_id params.name_hash
    params.max_players params.small_blind params.big_blind
    params.is_private params.timeout
    ⟨hmp_lo, hmp_hi⟩ hbb hsb
  refine ⟨post, ?_⟩
  have h_post_def :
    post = TexasPokerTable.init params.table_id params.name_hash
      params.max_players params.small_blind params.big_blind
      params.is_private params.timeout
      ⟨hmp_lo, hmp_hi⟩ hbb hsb := rfl
  rw [h_post_def]
  unfold ContractCreateTable
  have hvalid' : params.Valid := ⟨hmp_lo, hmp_hi, hbb, hsb⟩
  simp [TexasPokerTable.init, TexasPokerTable.all_seats_empty, Seat.empty,
        List.length_replicate, List.all_replicate, hpre_ver, hpre_rs,
        hpre_s, hvalid']

end PokerLean
