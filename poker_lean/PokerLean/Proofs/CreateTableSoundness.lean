import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.CreateTable
import PokerLean.AIR.AirBase
import PokerLean.AIR.CreateTableAir

namespace PokerLean

private lemma decodeU64_zero (l0 l1 l2 l3 : M31)
    (h : (l0, l1, l2, l3) = (M31.zero, M31.zero, M31.zero, M31.zero)) :
  decodeU64 l0 l1 l2 l3 = 0 := by
  rcases h with ⟨rfl, rfl, rfl, rfl⟩
  unfold decodeU64 M31.zero
  <;> ring

private lemma decodeU64_one (l0 l1 l2 l3 : M31)
    (h : (l0, l1, l2, l3) = (M31.one, M31.zero, M31.zero, M31.zero)) :
  decodeU64 l0 l1 l2 l3 = 1 := by
  rcases h with ⟨rfl, rfl, rfl, rfl⟩
  unfold decodeU64 M31.one M31.zero
  <;> ring

private def decodeLimb (l : M31) : Nat := l.val

private lemma decodeLimb_zero (l : M31) (h : l = M31.zero) :
  decodeLimb l = 0 := by
  unfold decodeLimb
  rw [h]
  rfl

private lemma params_valid
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractParamsFromAir ext).Valid := by
  have h' : CreateTableMethodConstraints row ext := h
  simp [CreateTableMethodConstraints] at h'
  exact ⟨h'.1, h'.2.1, h'.2.2.1, h'.2.2.2.1⟩

private lemma post_pot_zero
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).betting.pot = 0 := by
  have h' : CreateTableMethodConstraints row ext := h
  simp [CreateTableMethodConstraints] at h'
  have hpot : row.post_pot = (M31.zero, M31.zero, M31.zero, M31.zero) := h'.2.2.2.2.2.1
  unfold extractPostTableFromAir
  exact decodeU64_zero row.post_pot.1 row.post_pot.2.1 row.post_pot.2.2.1 row.post_pot.2.2.2 hpot

private lemma post_dealer_zero
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).betting.dealer_seat = 0 := by
  have h' : CreateTableMethodConstraints row ext := h
  simp [CreateTableMethodConstraints] at h'
  have hbtn : row.post_button = M31.zero := h'.2.2.2.2.2.2.1
  unfold extractPostTableFromAir
  exact decodeLimb_zero row.post_button hbtn

private lemma post_version_one
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).version = 1 := by
  have h' : CreateTableMethodConstraints row ext := h
  simp [CreateTableMethodConstraints] at h'
  have hv : row.post_version = (M31.one, M31.zero, M31.zero, M31.zero) := h'.2.2.2.2.2.2.2.2.1
  unfold extractPostTableFromAir
  exact decodeU64_one row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 hv

private lemma post_round_waiting
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).round_state = RoundState.ROUND_WAITING := by
  have h' : CreateTableMethodConstraints row ext := h
  simp [CreateTableMethodConstraints] at h'
  have hrs : row.post_round_state = M31.zero := h'.2.2.2.2.2.2.2.1
  have hval : row.post_round_state.val = 0 := by rw [hrs]; rfl
  unfold extractPostTableFromAir
  rw [hval]
  rw [RoundState.round_state_ofNat_zero]

private lemma post_seats_correct
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).all_seats_empty ∧
  (extractPostTableFromAir row ext).seats.length = (extractParamsFromAir ext).max_players := by
  have hmp : 2 ≤ ext.maxPlayers ∧ ext.maxPlayers ≤ 9 := by
    simp [CreateTableMethodConstraints] at h; exact ⟨h.1, h.2.1⟩
  unfold extractPostTableFromAir extractParamsFromAir
  simp [TexasPokerTable.all_seats_empty, Seat.empty, List.all, List.length, List.replicate]
  <;> omega

private lemma post_other_fields
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).betting.current_turn = 0 ∧
  (extractPostTableFromAir row ext).betting.current_bet = 0 ∧
  (extractPostTableFromAir row ext).betting.min_raise = (extractParamsFromAir ext).big_blind ∧
  List.isEmpty (extractPostTableFromAir row ext).betting.side_pots ∧
  (extractPostTableFromAir row ext).shuffle_state.phase = 0 ∧
  (extractPostTableFromAir row ext).reveal_state.reveal_phase = 0 ∧
  (extractPostTableFromAir row ext).deck_state = DeckState.DeckIdle ∧
  (extractPostTableFromAir row ext).reconstruct_state = ReconstructState.ReconstructIdle ∧
  (extractPostTableFromAir row ext).ante = 0 ∧
  (extractPostTableFromAir row ext).chip_pool = 0 ∧
  (extractPostTableFromAir row ext).addon_pool = 0 ∧
  (extractPostTableFromAir row ext).pending_addon_total = 0 ∧
  (extractPostTableFromAir row ext).pending_rebuy_total = 0 ∧
  (extractPostTableFromAir row ext).rake = 0 ∧
  (extractPostTableFromAir row ext).table_fee = 0 ∧
  (extractPostTableFromAir row ext).hand_id = 0 ∧
  (extractPostTableFromAir row ext).call_seq = 0 ∧
  (extractPostTableFromAir row ext).started_at = 0 ∧
  (extractPostTableFromAir row ext).last_action_time = 0 := by
  unfold extractPostTableFromAir extractParamsFromAir
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

private lemma post_table_fields
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext) :
  (extractPostTableFromAir row ext).table_id = (extractParamsFromAir ext).table_id ∧
  (extractPostTableFromAir row ext).name_hash = (extractParamsFromAir ext).name_hash ∧
  (extractPostTableFromAir row ext).max_players = (extractParamsFromAir ext).max_players ∧
  (extractPostTableFromAir row ext).small_blind = (extractParamsFromAir ext).small_blind ∧
  (extractPostTableFromAir row ext).big_blind = (extractParamsFromAir ext).big_blind ∧
  (extractPostTableFromAir row ext).is_private = (extractParamsFromAir ext).is_private ∧
  (extractPostTableFromAir row ext).timeout = (extractParamsFromAir ext).timeout := by
  unfold extractPostTableFromAir extractParamsFromAir
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem create_table_soundness
    (row : CommonRow)
    (ext : CreateTableRow)
    (h_air : CreateTableAirAcceptable row ext) :
  ContractCreateTable
    (extractPreTableFromAir row)
    (extractParamsFromAir ext)
    (extractPostTableFromAir row ext) := by
  rcases h_air with ⟨_h_common, h_method, _, _⟩
  have h_valid : (extractParamsFromAir ext).Valid := params_valid row ext h_method
  have h_pre_ver : (extractPreTableFromAir row).version = 0 := by
    unfold extractPreTableFromAir TexasPokerTable.empty_table; rfl
  have h_pre_rs : (extractPreTableFromAir row).round_state = RoundState.ROUND_WAITING := by
    unfold extractPreTableFromAir TexasPokerTable.empty_table; rfl
  have h_pre_s : List.isEmpty (extractPreTableFromAir row).seats := by
    unfold extractPreTableFromAir TexasPokerTable.empty_table; rfl
  have h_pot : (extractPostTableFromAir row ext).betting.pot = 0 :=
    post_pot_zero row ext h_method
  have h_dealer : (extractPostTableFromAir row ext).betting.dealer_seat = 0 :=
    post_dealer_zero row ext h_method
  have h_rs : (extractPostTableFromAir row ext).round_state = RoundState.ROUND_WAITING :=
    post_round_waiting row ext h_method
  have h_seats :
    (extractPostTableFromAir row ext).all_seats_empty ∧
    (extractPostTableFromAir row ext).seats.length = (extractParamsFromAir ext).max_players :=
    post_seats_correct row ext h_method
  have h_ver : (extractPostTableFromAir row ext).version = 1 :=
    post_version_one row ext h_method
  have h_ver2 : (extractPreTableFromAir row).version + 1 = 1 := by
    unfold extractPreTableFromAir TexasPokerTable.empty_table; rfl
  have h_other :
    (extractPostTableFromAir row ext).betting.current_turn = 0 ∧
    (extractPostTableFromAir row ext).betting.current_bet = 0 ∧
    (extractPostTableFromAir row ext).betting.min_raise = (extractParamsFromAir ext).big_blind ∧
    List.isEmpty (extractPostTableFromAir row ext).betting.side_pots ∧
    (extractPostTableFromAir row ext).shuffle_state.phase = 0 ∧
    (extractPostTableFromAir row ext).reveal_state.reveal_phase = 0 ∧
    (extractPostTableFromAir row ext).deck_state = DeckState.DeckIdle ∧
    (extractPostTableFromAir row ext).reconstruct_state = ReconstructState.ReconstructIdle ∧
    (extractPostTableFromAir row ext).ante = 0 ∧
    (extractPostTableFromAir row ext).chip_pool = 0 ∧
    (extractPostTableFromAir row ext).addon_pool = 0 ∧
    (extractPostTableFromAir row ext).pending_addon_total = 0 ∧
    (extractPostTableFromAir row ext).pending_rebuy_total = 0 ∧
    (extractPostTableFromAir row ext).rake = 0 ∧
    (extractPostTableFromAir row ext).table_fee = 0 ∧
    (extractPostTableFromAir row ext).hand_id = 0 ∧
    (extractPostTableFromAir row ext).call_seq = 0 ∧
    (extractPostTableFromAir row ext).started_at = 0 ∧
    (extractPostTableFromAir row ext).last_action_time = 0 :=
    post_other_fields row ext h_method
  have h_tbl :
    (extractPostTableFromAir row ext).table_id = (extractParamsFromAir ext).table_id ∧
    (extractPostTableFromAir row ext).name_hash = (extractParamsFromAir ext).name_hash ∧
    (extractPostTableFromAir row ext).max_players = (extractParamsFromAir ext).max_players ∧
    (extractPostTableFromAir row ext).small_blind = (extractParamsFromAir ext).small_blind ∧
    (extractPostTableFromAir row ext).big_blind = (extractParamsFromAir ext).big_blind ∧
    (extractPostTableFromAir row ext).is_private = (extractParamsFromAir ext).is_private ∧
    (extractPostTableFromAir row ext).timeout = (extractParamsFromAir ext).timeout :=
    post_table_fields row ext h_method

  rcases h_seats with ⟨h_empty, h_len⟩
  rcases h_other with ⟨h_ct, h_cb, h_mr, h_sp, h_sph, h_sr, h_sd, h_src,
                        h_ante, h_cp, h_ap, h_pa, h_pr, h_rake, h_tf, h_hi, h_cs, h_sa, h_la⟩
  rcases h_tbl with ⟨h_tid, h_nh, h_mp, h_sb2, h_bb2, h_ip, h_to⟩

  have h_ver_final : (extractPostTableFromAir row ext).version =
      (extractPreTableFromAir row).version + 1 := by
    simpa [h_ver, h_ver2]

  show ContractCreateTable (extractPreTableFromAir row) (extractParamsFromAir ext) (extractPostTableFromAir row ext)
  unfold ContractCreateTable
  tauto

lemma create_table_soundness_simple
    (row : CommonRow) (ext : CreateTableRow) :
  CreateTableAirAcceptable row ext →
  ∃ (pre post : TexasPokerTable) (params : CreateTableParams),
    ContractCreateTable pre params post := by
  intro h
  refine ⟨extractPreTableFromAir row,
           extractPostTableFromAir row ext,
           extractParamsFromAir ext,
           create_table_soundness row ext h⟩

end PokerLean
