import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Crypto
import PokerLean.AIR.AirBase
import PokerLean.AIR.CryptoAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # 密码学方法 AIR soundness

## 核心结论

5 个密码学方法的 AIR **都是 sound 的**：

1. **join_and_shuffle AIR 是 sound 的** — `ShufflePhasePositive` + `VersionIncrementConstraint` +
   `StateRootConsistency` + 提取函数一致性覆盖合约全部合取
2. **leave_with_proof AIR 是 sound 的** — 同上
3. **submit_shuffle_v2 AIR 是 sound 的** — 同上
4. **submit_player_reveal_tokens AIR 是 sound 的** — `RevealPhasePositive` + `VersionIncrementConstraint`
5. **submit_reconstruct_deck AIR 是 sound 的** — `ReconstructStateNotIdle` + `VersionIncrementConstraint`

## 证明思路

每个证明的通用模式：
1. 从 `AirAcceptable` 解构出 `CommonConstraints` 和 `MethodConstraints`
2. 从 `MethodConstraints`（在 `is_active = 1` 下）得到各约束的实例
3. `VersionIncrementConstraint` ⟹ `post.version = pre.version + 1`
4. 阶段 gating（`ShufflePhasePositive` / `RevealPhasePositive` / `ReconstructStateNotIdle`）
   配合提取函数中对应字段使用 witness 的 `.val`，⟹ 合约前置条件
5. 提取函数中 `max_players` / `big_blind` / `small_blind` / `hand_id` 在 pre/post 中相同，
   ⟹ 合约不变量
6. `params.seat_index` 由 `ext.input_seat_index = nat_to_m31 expected_seat_index hlt` 与
   `hseat : expected_seat_index < max_players` 保证

## 已知限制

密码学证明本身（DLEq, ZKShuffle, RevealToken, Reconstruct）不在 AIR 中验证，
假设由外部 ZK 验证器负责。soundness 证明仅覆盖状态转换语义。 -/

/-! ## 通用辅助引理 -/

private lemma crypto_pre_max_players (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).max_players = max_players := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_post_max_players (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPostTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).max_players = max_players := by
  simp [extractPostTableFromCryptoAir, extractPreTableFromCryptoAir]

private lemma crypto_pre_big_blind (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).big_blind = 0 := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_post_big_blind (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPostTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).big_blind = 0 := by
  simp [extractPostTableFromCryptoAir, extractPreTableFromCryptoAir]

private lemma crypto_pre_small_blind (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).small_blind = 0 := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_post_small_blind (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPostTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).small_blind = 0 := by
  simp [extractPostTableFromCryptoAir, extractPreTableFromCryptoAir]

private lemma crypto_pre_hand_id (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).hand_id = row.hand_id.val := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_post_hand_id (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPostTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).hand_id = row.hand_id.val := by
  simp [extractPostTableFromCryptoAir, extractPreTableFromCryptoAir]

private lemma crypto_pre_version (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_post_version (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPostTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromCryptoAir, extractPreTableFromCryptoAir]

private lemma crypto_pre_shuffle_phase (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).shuffle_state.phase = shuffle_phase := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_pre_reveal_phase (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).reveal_state.reveal_phase = reveal_phase := by
  simp [extractPreTableFromCryptoAir]

private lemma crypto_pre_reconstruct_state (row : CommonRow) (max_players shuffle_phase reveal_phase recon : Nat) :
    (extractPreTableFromCryptoAir row max_players shuffle_phase reveal_phase recon).reconstruct_state =
      ReconstructState.fromNat recon := by
  simp [extractPreTableFromCryptoAir]

/-! ## join_and_shuffle soundness -/

theorem join_and_shuffle_air_sound :
  ∀ (row : CommonRow) (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    JoinAndShuffleAirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt →
    ContractJoinAndShuffle
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractJoinAndShuffleParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) := by
  intro row ext expected_seat_index expected_commit_0 max_players hlt hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : JoinAndShuffleMethodConstraints row ext expected_seat_index
                    expected_commit_0 max_players hlt := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_commit, h_shuffle_pos, _h_deck_eq, _h_src⟩
  -- params.seat_index < pre.max_players
  have h_params_seat : (extractJoinAndShuffleParamsFromAir ext).seat_index = expected_seat_index := by
    simp [extractJoinAndShuffleParamsFromAir, h_seat_eq, nat_to_m31]
  have h_pre_max : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_pre_max_players row max_players ext.input_shuffle_phase.val 0 0
  -- pre.shuffle_state.phase > 0
  have h_pre_phase : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).shuffle_state.phase > 0 := by
    rw [crypto_pre_shuffle_phase]; exact h_shuffle_pos
  -- post.version = pre.version + 1
  have h_pre_ver : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    crypto_pre_version row max_players ext.input_shuffle_phase.val 0 0
  have h_post_ver : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    crypto_post_version row max_players ext.input_shuffle_phase.val 0 0
  have h_ver_eq : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  -- 不变量
  have h_post_max : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_post_max_players row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_bb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_pre_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_bb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_post_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_sb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_pre_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_sb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_post_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_hid : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_pre_hand_id row max_players ext.input_shuffle_phase.val 0 0
  have h_post_hid : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_post_hand_id row max_players ext.input_shuffle_phase.val 0 0
  exact ⟨by rw [h_params_seat, h_pre_max]; exact hseat, h_pre_phase, h_ver_eq,
         by rw [h_post_max, h_pre_max],
         by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb],
         by rw [h_post_hid, h_pre_hid]⟩

/-! ## leave_with_proof soundness -/

theorem leave_with_proof_air_sound :
  ∀ (row : CommonRow) (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat) (expected_leave_kind : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P)
    (hseat : expected_seat_index < max_players),
    LeaveWithProofAirAcceptable row ext expected_seat_index expected_leave_kind max_players hlt hltk →
    ContractLeaveWithProof
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractLeaveWithProofParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) := by
  intro row ext expected_seat_index expected_leave_kind max_players hlt hltk hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : LeaveWithProofMethodConstraints row ext expected_seat_index
                    expected_leave_kind max_players hlt hltk := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_leave, h_shuffle_pos, _h_src⟩
  have h_params_seat : (extractLeaveWithProofParamsFromAir ext).seat_index = expected_seat_index := by
    simp [extractLeaveWithProofParamsFromAir, h_seat_eq, nat_to_m31]
  have h_pre_max : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_pre_max_players row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_phase : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).shuffle_state.phase > 0 := by
    rw [crypto_pre_shuffle_phase]; exact h_shuffle_pos
  have h_pre_ver : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    crypto_pre_version row max_players ext.input_shuffle_phase.val 0 0
  have h_post_ver : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    crypto_post_version row max_players ext.input_shuffle_phase.val 0 0
  have h_ver_eq : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  have h_post_max : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_post_max_players row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_bb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_pre_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_bb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_post_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_sb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_pre_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_sb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_post_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_hid : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_pre_hand_id row max_players ext.input_shuffle_phase.val 0 0
  have h_post_hid : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_post_hand_id row max_players ext.input_shuffle_phase.val 0 0
  exact ⟨by rw [h_params_seat, h_pre_max]; exact hseat, h_pre_phase, h_ver_eq,
         by rw [h_post_max, h_pre_max],
         by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb],
         by rw [h_post_hid, h_pre_hid]⟩

/-! ## submit_shuffle_v2 soundness -/

theorem submit_shuffle_v2_air_sound :
  ∀ (row : CommonRow) (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitShuffleV2AirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt →
    ContractSubmitShuffleV2
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractSubmitShuffleV2ParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) := by
  intro row ext expected_seat_index expected_commit_0 max_players hlt hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : SubmitShuffleV2MethodConstraints row ext expected_seat_index
                    expected_commit_0 max_players hlt := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_commit, h_shuffle_pos, _h_src⟩
  have h_params_seat : (extractSubmitShuffleV2ParamsFromAir ext).seat_index = expected_seat_index := by
    simp [extractSubmitShuffleV2ParamsFromAir, h_seat_eq, nat_to_m31]
  have h_pre_max : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_pre_max_players row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_phase : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).shuffle_state.phase > 0 := by
    rw [crypto_pre_shuffle_phase]; exact h_shuffle_pos
  have h_pre_ver : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    crypto_pre_version row max_players ext.input_shuffle_phase.val 0 0
  have h_post_ver : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    crypto_post_version row max_players ext.input_shuffle_phase.val 0 0
  have h_ver_eq : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version =
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  have h_post_max : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).max_players = max_players :=
    crypto_post_max_players row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_bb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_pre_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_bb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).big_blind = 0 :=
    crypto_post_big_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_sb : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_pre_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_post_sb : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).small_blind = 0 :=
    crypto_post_small_blind row max_players ext.input_shuffle_phase.val 0 0
  have h_pre_hid : (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_pre_hand_id row max_players ext.input_shuffle_phase.val 0 0
  have h_post_hid : (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0).hand_id = row.hand_id.val :=
    crypto_post_hand_id row max_players ext.input_shuffle_phase.val 0 0
  exact ⟨by rw [h_params_seat, h_pre_max]; exact hseat, h_pre_phase, h_ver_eq,
         by rw [h_post_max, h_pre_max],
         by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb],
         by rw [h_post_hid, h_pre_hid]⟩

/-! ## submit_player_reveal_tokens soundness -/

theorem submit_player_reveal_tokens_air_sound :
  ∀ (row : CommonRow) (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat) (expected_reveal_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitRevealTokensAirAcceptable row ext expected_seat_index expected_reveal_phase max_players hlt hltp →
    ContractSubmitRevealTokens
      (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0)
      (extractSubmitRevealTokensParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0) := by
  intro row ext expected_seat_index expected_reveal_phase max_players hlt hltp hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : SubmitRevealTokensMethodConstraints row ext expected_seat_index
                    expected_reveal_phase max_players hlt hltp := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_reveal, h_reveal_pos, _h_src⟩
  have h_params_seat : (extractSubmitRevealTokensParamsFromAir ext).seat_index = expected_seat_index := by
    simp [extractSubmitRevealTokensParamsFromAir, h_seat_eq, nat_to_m31]
  have h_pre_max : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).max_players = max_players :=
    crypto_pre_max_players row max_players 0 ext.input_reveal_phase.val 0
  have h_pre_phase : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).reveal_state.reveal_phase > 0 := by
    rw [crypto_pre_reveal_phase]; exact h_reveal_pos
  have h_pre_ver : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    crypto_pre_version row max_players 0 ext.input_reveal_phase.val 0
  have h_post_ver : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    crypto_post_version row max_players 0 ext.input_reveal_phase.val 0
  have h_ver_eq : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).version =
      (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  have h_post_max : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).max_players = max_players :=
    crypto_post_max_players row max_players 0 ext.input_reveal_phase.val 0
  have h_pre_bb : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).big_blind = 0 :=
    crypto_pre_big_blind row max_players 0 ext.input_reveal_phase.val 0
  have h_post_bb : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).big_blind = 0 :=
    crypto_post_big_blind row max_players 0 ext.input_reveal_phase.val 0
  have h_pre_sb : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).small_blind = 0 :=
    crypto_pre_small_blind row max_players 0 ext.input_reveal_phase.val 0
  have h_post_sb : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).small_blind = 0 :=
    crypto_post_small_blind row max_players 0 ext.input_reveal_phase.val 0
  have h_pre_hid : (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).hand_id = row.hand_id.val :=
    crypto_pre_hand_id row max_players 0 ext.input_reveal_phase.val 0
  have h_post_hid : (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0).hand_id = row.hand_id.val :=
    crypto_post_hand_id row max_players 0 ext.input_reveal_phase.val 0
  exact ⟨by rw [h_params_seat, h_pre_max]; exact hseat, h_pre_phase, h_ver_eq,
         by rw [h_post_max, h_pre_max],
         by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb],
         by rw [h_post_hid, h_pre_hid]⟩

/-! ## submit_reconstruct_deck soundness -/

theorem submit_reconstruct_deck_air_sound :
  ∀ (row : CommonRow) (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat) (expected_reconstruct_state : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_state < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitReconstructDeckAirAcceptable row ext expected_seat_index expected_reconstruct_state max_players hlt hltp →
    ContractSubmitReconstructDeck
      (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val)
      (extractSubmitReconstructDeckParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val) := by
  intro row ext expected_seat_index expected_reconstruct_state max_players hlt hltp hseat h_air
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : SubmitReconstructDeckMethodConstraints row ext expected_seat_index
                    expected_reconstruct_state max_players hlt hltp := h_air.2.1
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_recon, h_recon_not_idle, _h_src⟩
  have h_params_seat : (extractSubmitReconstructDeckParamsFromAir ext).seat_index = expected_seat_index := by
    simp [extractSubmitReconstructDeckParamsFromAir, h_seat_eq, nat_to_m31]
  have h_pre_max : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).max_players = max_players :=
    crypto_pre_max_players row max_players 0 0 ext.input_reconstruct_state.val
  have h_pre_recon : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).reconstruct_state =
      ReconstructState.fromNat ext.input_reconstruct_state.val :=
    crypto_pre_reconstruct_state row max_players 0 0 ext.input_reconstruct_state.val
  have h_pre_recon_not_idle :
      (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).reconstruct_state ≠
        ReconstructState.ReconstructIdle := by
    rw [h_pre_recon]
    exact reconstruct_state_not_idle_implies_fromNat ext.input_reconstruct_state h_recon_not_idle
  have h_pre_ver : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 :=
    crypto_pre_version row max_players 0 0 ext.input_reconstruct_state.val
  have h_post_ver : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).version =
      decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2 :=
    crypto_post_version row max_players 0 0 ext.input_reconstruct_state.val
  have h_ver_eq : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).version =
      (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).version + 1 := by
    rw [h_post_ver, h_pre_ver]; exact h_ver h_active
  have h_post_max : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).max_players = max_players :=
    crypto_post_max_players row max_players 0 0 ext.input_reconstruct_state.val
  have h_pre_bb : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).big_blind = 0 :=
    crypto_pre_big_blind row max_players 0 0 ext.input_reconstruct_state.val
  have h_post_bb : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).big_blind = 0 :=
    crypto_post_big_blind row max_players 0 0 ext.input_reconstruct_state.val
  have h_pre_sb : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).small_blind = 0 :=
    crypto_pre_small_blind row max_players 0 0 ext.input_reconstruct_state.val
  have h_post_sb : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).small_blind = 0 :=
    crypto_post_small_blind row max_players 0 0 ext.input_reconstruct_state.val
  have h_pre_hid : (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).hand_id = row.hand_id.val :=
    crypto_pre_hand_id row max_players 0 0 ext.input_reconstruct_state.val
  have h_post_hid : (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val).hand_id = row.hand_id.val :=
    crypto_post_hand_id row max_players 0 0 ext.input_reconstruct_state.val
  exact ⟨by rw [h_params_seat, h_pre_max]; exact hseat, h_pre_recon_not_idle, h_ver_eq,
         by rw [h_post_max, h_pre_max],
         by rw [h_post_bb, h_pre_bb],
         by rw [h_post_sb, h_pre_sb],
         by rw [h_post_hid, h_pre_hid]⟩

end PokerLean
