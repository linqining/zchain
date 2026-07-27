import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Fold
import PokerLean.AIR.AirBase
import PokerLean.AIR.FoldAir
import PokerLean.Proofs.FullSoundness

namespace PokerLean

/-- `decodeU64` 与 `decodeU64'` 相等 -/
lemma decodeU64_eq_decodeU64' (l0 l1 l2 l3 : M31) :
    decodeU64 l0 l1 l2 l3 = decodeU64' l0 l1 l2 l3 := rfl

/-- update_seat 不改变 round_state 字段 -/
@[simp] lemma update_seat_round_state (t : TexasPokerTable) (idx : Nat) (f : Seat → Seat) :
    (t.update_seat idx f).round_state = t.round_state := rfl

/-- update_seat 不改变 version 字段 -/
@[simp] lemma update_seat_version (t : TexasPokerTable) (idx : Nat) (f : Seat → Seat) :
    (t.update_seat idx f).version = t.version := rfl

/-- update_seat 不改变 betting 字段 -/
@[simp] lemma update_seat_betting (t : TexasPokerTable) (idx : Nat) (f : Seat → Seat) :
    (t.update_seat idx f).betting = t.betting := rfl

/-- `ContractFoldPartial`: AIR 能验证的 ContractFold 子集。

    这是 `ContractFold` 的一个弱化版本，只检查 AIR 实际追踪的字段。
    被省略的字段（seat 状态、current_turn、current_bet 等）是 AIR 的已知盲区。 -/
def ContractFoldPartial
    (pre : TexasPokerTable)
    (params : FoldParams)
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

/-- 辅助引理：如果 pre_round_state.val ∈ {2,3,4,5}，则 is_betting_round 为 true -/
lemma fold_pre_round_betting
    (row : CommonRow) (ext : FoldMethodColumns) (max_players : Nat)
    (h : row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
         row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5) :
    (extractPreTableFromFoldAir row ext max_players).round_state.is_betting_round := by
  unfold extractPreTableFromFoldAir
  rcases h with h1 | h2 | h3 | h4
  · rw [h1]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h2]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h3]; simp [RoundState.fromNat, RoundState.is_betting_round]
  · rw [h4]; simp [RoundState.fromNat, RoundState.is_betting_round]

/-- 辅助引理：version 递增约束 -/
lemma fold_ver_inc
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat)
    (h : decodeU64' row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 =
      decodeU64' row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 + 1) :
    (extractPostTableFromFoldAir row ext max_players seat_index).version =
    (extractPreTableFromFoldAir row ext max_players).version + 1 := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  simp only [decodeU64_eq_decodeU64', update_seat_version, update_seat_betting]
  rw [h]

/-- 辅助引理：round_state 不变 -/
lemma fold_rs_same
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat)
    (h : row.post_round_state = row.pre_round_state) :
    (extractPostTableFromFoldAir row ext max_players seat_index).round_state =
    (extractPreTableFromFoldAir row ext max_players).round_state := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  simp only [update_seat_round_state]
  rw [h]

/-- 辅助引理：pot 不变 -/
lemma fold_pot_same
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat)
    (h : decodeU64' row.post_pot.1 row.post_pot.2.1
        row.post_pot.2.2.1 row.post_pot.2.2.2 =
      decodeU64' row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2) :
    (extractPostTableFromFoldAir row ext max_players seat_index).betting.pot =
    (extractPreTableFromFoldAir row ext max_players).betting.pot := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  simp only [decodeU64_eq_decodeU64', update_seat_version, update_seat_betting]
  rw [h]

/-- 辅助引理：dealer_seat 不变 -/
lemma fold_dealer_same
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat)
    (h : row.post_button = row.pre_button) :
    (extractPostTableFromFoldAir row ext max_players seat_index).betting.dealer_seat =
    (extractPreTableFromFoldAir row ext max_players).betting.dealer_seat := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  simp only [update_seat_betting]
  rw [h]

/-- 辅助引理：max_players 不变（由提取函数保证） -/
lemma fold_mp_same
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromFoldAir row ext max_players seat_index).max_players =
    (extractPreTableFromFoldAir row ext max_players).max_players := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  rfl

/-- 辅助引理：其他不变字段（big_blind, small_blind, chip_pool, hand_id） -/
lemma fold_other_same
    (row : CommonRow) (ext : FoldMethodColumns)
    (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromFoldAir row ext max_players seat_index).big_blind =
      (extractPreTableFromFoldAir row ext max_players).big_blind ∧
    (extractPostTableFromFoldAir row ext max_players seat_index).small_blind =
      (extractPreTableFromFoldAir row ext max_players).small_blind ∧
    (extractPostTableFromFoldAir row ext max_players seat_index).chip_pool =
      (extractPreTableFromFoldAir row ext max_players).chip_pool ∧
    (extractPostTableFromFoldAir row ext max_players seat_index).hand_id =
      (extractPreTableFromFoldAir row ext max_players).hand_id := by
  unfold extractPostTableFromFoldAir extractPreTableFromFoldAir
  exact ⟨rfl, rfl, rfl, rfl⟩

/-- 辅助引理：extractFoldParamsFromAir 的 seat_index = ext.input_seat_index.val -/
lemma fold_params_seat
    (ext : FoldMethodColumns) :
    (extractFoldParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  unfold extractFoldParamsFromAir; rfl

/-- 辅助引理：pre.max_players = max_players -/
lemma fold_pre_mp
    (row : CommonRow) (ext : FoldMethodColumns) (max_players : Nat) :
    (extractPreTableFromFoldAir row ext max_players).max_players = max_players := by
  unfold extractPreTableFromFoldAir; rfl

/-- 辅助引理：FoldMethodConstraints 蕴含 input_seat_index = expected_seat_index -/
lemma fold_input_seat_eq
    (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index max_players : Nat) (hlt : expected_seat_index < M31_P)
    (h : FoldMethodConstraints row ext expected_seat_index max_players hlt)
    (hactive : row.is_active = M31.one) :
    ext.input_seat_index = nat_to_m31 expected_seat_index hlt := by
  have h_conj := h hactive
  exact h_conj.1

/-- 主定理：FullFoldAirAcceptable 蕴含 ContractFoldPartial（部分 soundness）

    这证明 AIR 约束正确执行了它能验证的合约语义子集。
    对于 AIR 未追踪的字段（seat 状态、current_turn、current_bet 等），
    合约语义无法被 AIR 保证，需要额外的约束或信任假设。 -/
theorem full_fold_partial_soundness
    (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (h_air : FullFoldAirAcceptable row ext expected_seat_index max_players hlt) :
    ContractFoldPartial
      (extractPreTableFromFoldAir row ext max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) := by
  rcases h_air with ⟨_hc, hfull, hactive, _hpadding⟩
  rcases hfull with ⟨hmethod, h_round, h_seat_bound, h_ver, h_pot, h_rs, h_btn⟩
  -- 从 hmethod 提取 input_seat_index = expected_seat_index
  have h_input_seat : ext.input_seat_index = nat_to_m31 expected_seat_index hlt :=
    fold_input_seat_eq row ext expected_seat_index max_players hlt hmethod hactive
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_input_seat]; unfold nat_to_m31; simp
  unfold ContractFoldPartial
  constructor
  · exact fold_pre_round_betting row ext max_players h_round
  constructor
  · rw [fold_params_seat, fold_pre_mp, h_seat_val]
    exact h_seat_bound
  constructor
  · exact fold_ver_inc row ext max_players expected_seat_index h_ver
  constructor
  · exact fold_rs_same row ext max_players expected_seat_index h_rs
  constructor
  · exact fold_pot_same row ext max_players expected_seat_index h_pot
  constructor
  · exact fold_dealer_same row ext max_players expected_seat_index h_btn
  constructor
  · exact fold_mp_same row ext max_players expected_seat_index
  rcases fold_other_same row ext max_players expected_seat_index with
    ⟨h_bb, h_sb, h_cp, h_hi⟩
  constructor
  · exact h_bb
  constructor
  · exact h_sb
  constructor
  · exact h_cp
  exact h_hi

/-- ContractFoldPartial 是 ContractFold 的弱化：ContractFold 蕴含 ContractFoldPartial -/
theorem contract_fold_implies_partial
    (pre : TexasPokerTable) (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
    ContractFoldPartial pre params post := by
  rcases h with ⟨h_round, h_seat, _h_turn, _h_part, _h_folded, _h_acted,
                  _h_stack, _h_bet, _h_total, _h_player, _h_others,
                  h_ver, h_rs, h_pot, _h_cb, h_dealer,
                  h_mp, h_bb, h_sb, h_cp, h_hi⟩
  unfold ContractFoldPartial
  constructor
  · exact h_round
  constructor
  · exact h_seat
  constructor
  · exact h_ver
  constructor
  · exact h_rs
  constructor
  · exact h_pot
  constructor
  · exact h_dealer
  constructor
  · exact h_mp
  constructor
  · exact h_bb
  constructor
  · exact h_sb
  constructor
  · exact h_cp
  exact h_hi

end PokerLean
