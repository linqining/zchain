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
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractParamsFromAir ext).Valid := by
  have h' : CreateTableMethodConstraints row ext ext.maxPlayers := h
  simp [CreateTableMethodConstraints] at h'
  exact ⟨h'.1, h'.2.1, h'.2.2.1, h'.2.2.2.1⟩

private lemma post_pot_zero
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.pot = 0 := by
  have h' : CreateTableMethodConstraints row ext ext.maxPlayers := h
  simp [CreateTableMethodConstraints] at h'
  have hpot : row.post_pot = (M31.zero, M31.zero, M31.zero, M31.zero) := h'.2.2.2.2.2.1
  unfold extractPostTableFromCreateTableAir
  exact decodeU64_zero row.post_pot.1 row.post_pot.2.1 row.post_pot.2.2.1 row.post_pot.2.2.2 hpot

private lemma post_dealer_zero
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.dealer_seat = 0 := by
  have h' : CreateTableMethodConstraints row ext ext.maxPlayers := h
  simp [CreateTableMethodConstraints] at h'
  have hbtn : row.post_button = M31.zero := h'.2.2.2.2.2.2.1
  unfold extractPostTableFromCreateTableAir
  exact decodeLimb_zero row.post_button hbtn

private lemma post_version_one
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).version = 1 := by
  have h' : CreateTableMethodConstraints row ext ext.maxPlayers := h
  simp [CreateTableMethodConstraints] at h'
  have hv : row.post_version = (M31.one, M31.zero, M31.zero, M31.zero) := h'.2.2.2.2.2.2.2.2.1
  unfold extractPostTableFromCreateTableAir
  exact decodeU64_one row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 hv

private lemma post_round_waiting
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).round_state = RoundState.ROUND_WAITING := by
  have h' : CreateTableMethodConstraints row ext ext.maxPlayers := h
  simp [CreateTableMethodConstraints] at h'
  have hrs : row.post_round_state = M31.zero := h'.2.2.2.2.2.2.2.1
  have hval : row.post_round_state.val = 0 := by rw [hrs]; rfl
  unfold extractPostTableFromCreateTableAir
  rw [hval]
  rw [RoundState.round_state_ofNat_zero]

private lemma post_seats_correct
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).all_seats_empty ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).seats.length = (extractParamsFromAir ext).max_players := by
  have hmp : 2 ≤ ext.maxPlayers ∧ ext.maxPlayers ≤ 9 := by
    simp [CreateTableMethodConstraints] at h; exact ⟨h.1, h.2.1⟩
  unfold extractPostTableFromCreateTableAir extractParamsFromAir
  simp [TexasPokerTable.all_seats_empty, Seat.empty, List.all, List.length, List.replicate]
  <;> omega

private lemma post_other_fields
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.current_turn = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.current_bet = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.min_raise = (extractParamsFromAir ext).big_blind ∧
  List.isEmpty (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.side_pots ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).shuffle_state.phase = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).reveal_state.reveal_phase = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).deck_state = DeckState.DeckIdle ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).reconstruct_state = ReconstructState.ReconstructIdle ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).ante = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).chip_pool = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).addon_pool = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).pending_addon_total = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).pending_rebuy_total = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).rake = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).table_fee = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).hand_id = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).call_seq = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).started_at = 0 ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).last_action_time = 0 := by
  unfold extractPostTableFromCreateTableAir extractParamsFromAir
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

private lemma post_table_fields
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableMethodConstraints row ext ext.maxPlayers) :
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).table_id = (extractParamsFromAir ext).table_id ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).name_hash = (extractParamsFromAir ext).name_hash ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).max_players = (extractParamsFromAir ext).max_players ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).small_blind = (extractParamsFromAir ext).small_blind ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).big_blind = (extractParamsFromAir ext).big_blind ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).is_private = (extractParamsFromAir ext).is_private ∧
  (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).timeout = (extractParamsFromAir ext).timeout := by
  unfold extractPostTableFromCreateTableAir extractParamsFromAir
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem create_table_soundness
    (row : CommonRow)
    (ext : CreateTableRow)
    (h_air : CreateTableAirAcceptable row ext ext.maxPlayers) :
  ContractCreateTable
    (extractPreTableFromCreateTableAir row ext.maxPlayers)
    (extractParamsFromAir ext)
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0) := by
  rcases h_air with ⟨_h_common, h_method, _, _⟩
  have h_valid : (extractParamsFromAir ext).Valid := params_valid row ext h_method
  have h_pre_ver : (extractPreTableFromCreateTableAir row ext.maxPlayers).version = 0 := by
    unfold extractPreTableFromCreateTableAir TexasPokerTable.empty_table; rfl
  have h_pre_rs : (extractPreTableFromCreateTableAir row ext.maxPlayers).round_state = RoundState.ROUND_WAITING := by
    unfold extractPreTableFromCreateTableAir TexasPokerTable.empty_table; rfl
  have h_pre_s : List.isEmpty (extractPreTableFromCreateTableAir row ext.maxPlayers).seats := by
    unfold extractPreTableFromCreateTableAir TexasPokerTable.empty_table; rfl
  have h_pot : (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.pot = 0 :=
    post_pot_zero row ext h_method
  have h_dealer : (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.dealer_seat = 0 :=
    post_dealer_zero row ext h_method
  have h_rs : (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).round_state = RoundState.ROUND_WAITING :=
    post_round_waiting row ext h_method
  have h_seats :
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).all_seats_empty ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).seats.length = (extractParamsFromAir ext).max_players :=
    post_seats_correct row ext h_method
  have h_ver : (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).version = 1 :=
    post_version_one row ext h_method
  have h_ver2 : (extractPreTableFromCreateTableAir row ext.maxPlayers).version + 1 = 1 := by
    unfold extractPreTableFromCreateTableAir TexasPokerTable.empty_table; rfl
  have h_other :
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.current_turn = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.current_bet = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.min_raise = (extractParamsFromAir ext).big_blind ∧
    List.isEmpty (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).betting.side_pots ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).shuffle_state.phase = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).reveal_state.reveal_phase = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).deck_state = DeckState.DeckIdle ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).reconstruct_state = ReconstructState.ReconstructIdle ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).ante = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).chip_pool = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).addon_pool = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).pending_addon_total = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).pending_rebuy_total = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).rake = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).table_fee = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).hand_id = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).call_seq = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).started_at = 0 ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).last_action_time = 0 :=
    post_other_fields row ext h_method
  have h_tbl :
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).table_id = (extractParamsFromAir ext).table_id ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).name_hash = (extractParamsFromAir ext).name_hash ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).max_players = (extractParamsFromAir ext).max_players ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).small_blind = (extractParamsFromAir ext).small_blind ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).big_blind = (extractParamsFromAir ext).big_blind ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).is_private = (extractParamsFromAir ext).is_private ∧
    (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).timeout = (extractParamsFromAir ext).timeout :=
    post_table_fields row ext h_method

  rcases h_seats with ⟨h_empty, h_len⟩
  rcases h_other with ⟨h_ct, h_cb, h_mr, h_sp, h_sph, h_sr, h_sd, h_src,
                        h_ante, h_cp, h_ap, h_pa, h_pr, h_rake, h_tf, h_hi, h_cs, h_sa, h_la⟩
  rcases h_tbl with ⟨h_tid, h_nh, h_mp, h_sb2, h_bb2, h_ip, h_to⟩

  have h_ver_final : (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0).version =
      (extractPreTableFromCreateTableAir row ext.maxPlayers).version + 1 := by
    simpa [h_ver, h_ver2]

  show ContractCreateTable (extractPreTableFromCreateTableAir row ext.maxPlayers) (extractParamsFromAir ext) (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0)
  unfold ContractCreateTable
  tauto

lemma create_table_soundness_simple
    (row : CommonRow) (ext : CreateTableRow) :
  CreateTableAirAcceptable row ext ext.maxPlayers →
  ∃ (pre post : TexasPokerTable) (params : CreateTableParams),
    ContractCreateTable pre params post := by
  intro h
  refine ⟨extractPreTableFromCreateTableAir row ext.maxPlayers,
           extractPostTableFromCreateTableAir row ext ext.maxPlayers 0,
           extractParamsFromAir ext,
           create_table_soundness row ext h⟩

end PokerLean