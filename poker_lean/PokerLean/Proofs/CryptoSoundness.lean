import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Crypto
import PokerLean.AIR.AirBase
import PokerLean.AIR.CryptoAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # 密码学方法 AIR soundness 反例

## 核心结论

5 个密码学方法的 AIR **都不是 sound 的**：

1. **join_and_shuffle AIR 不是 sound 的** — 缺少 version 递增、shuffle_state.phase 检查
2. **leave_with_proof AIR 不是 sound 的** — 缺少 version 递增、shuffle_state.phase 检查
3. **submit_shuffle_v2 AIR 不是 sound 的** — 缺少 version 递增、shuffle_state.phase 检查
4. **submit_player_reveal_tokens AIR 不是 sound 的** — 缺少 version 递增、reveal_phase 检查
5. **submit_reconstruct_deck AIR 不是 sound 的** — 缺少 version 递增、reconstruct_state 检查

## 反例构造思路

每个反例都使用 `pre_version = post_version = 0`：
- AIR 约束 **不强制** version 递增，因此满足 AIR
- 合约要求 `post.version = pre.version + 1`，即 `0 = 1`，矛盾

此外：
- `extractPreTableFromCryptoAir` 将 `shuffle_state.phase` 设为 0，
  违反合约的 `pre.shuffle_state.phase > 0` 要求
- `extractPreTableFromCryptoAir` 将 `reveal_state.reveal_phase` 设为 0，
  违反 `submit_player_reveal_tokens` 合约的 `pre.reveal_state.reveal_phase > 0`
- `extractPreTableFromCryptoAir` 将 `reconstruct_state` 设为 `ReconstructIdle`，
  违反 `submit_reconstruct_deck` 合约的 `pre.reconstruct_state ≠ ReconstructIdle`
-/

/-! ## join_and_shuffle 反例：version 不递增（且 shuffle_state.phase = 0） -/

theorem join_and_shuffle_air_not_sound :
  ∃ (row : CommonRow) (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_commit_0 : Nat)
    (hlt : expected_seat_index < M31_P),
    JoinAndShuffleAirAcceptable row ext expected_seat_index expected_commit_0 hlt ∧
    ¬ ContractJoinAndShuffle
      (extractPreTableFromCryptoAir row max_players)
      (extractJoinAndShuffleParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) := by
  -- 反例：pre_version = post_version = 0（不递增）
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.JoinAndShuffle.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinAndShuffle⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : JoinAndShuffleMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_new_deck_commitment_0 := M31.zero
    output_deck_commitment_0 := M31.zero
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 2, 0, hlt0, ?_, ?_⟩
  · -- JoinAndShuffleAirAcceptable
    unfold JoinAndShuffleAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · -- CommonConstraints
      unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.JoinAndShuffle.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinAndShuffle⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · -- JoinAndShuffleMethodConstraints
      unfold JoinAndShuffleMethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · show ext.input_new_deck_commitment_0 = ⟨0 % 65536, by unfold M31_P; omega⟩
        simp [ext]
        exact Subtype.ext rfl
      · show ext.output_deck_commitment_0 = ext.input_new_deck_commitment_0
        simp [ext]
    · show row.method_kind = ⟨MethodKind.JoinAndShuffle.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinAndShuffle⟩
      simp [row]
    · show row.is_active = M31.one
      rfl
  · -- ¬ ContractJoinAndShuffle：shuffle_state.phase = 0，违反 > 0
    intro h
    rcases h with ⟨_, h_phase, _, _⟩
    have h_phase_zero : (extractPreTableFromCryptoAir row 2).shuffle_state.phase = 0 := by
      unfold extractPreTableFromCryptoAir
      simp [row]
    rw [h_phase_zero] at h_phase
    exact absurd h_phase (by norm_num)

/-! ## leave_with_proof 反例：version 不递增 -/

theorem leave_with_proof_air_not_sound :
  ∃ (row : CommonRow) (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat) (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P),
    LeaveWithProofAirAcceptable row ext expected_seat_index expected_leave_kind hlt hltk ∧
    ¬ ContractLeaveWithProof
      (extractPreTableFromCryptoAir row max_players)
      (extractLeaveWithProofParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.LeaveWithProof.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveWithProof⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : LeaveWithProofMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_leave_kind := nat_to_m31 0 (by unfold M31_P; norm_num)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 0, 2, hlt0, hlt0, ?_, ?_⟩
  · -- LeaveWithProofAirAcceptable
    unfold LeaveWithProofAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.LeaveWithProof.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveWithProof⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold LeaveWithProofMethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · simp [ext, nat_to_m31]
    · show row.method_kind = ⟨MethodKind.LeaveWithProof.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveWithProof⟩
      simp [row]
    · rfl
  · -- ¬ ContractLeaveWithProof：shuffle_state.phase = 0，违反 > 0
    intro h
    rcases h with ⟨_, h_phase, _, _⟩
    have h_phase_zero : (extractPreTableFromCryptoAir row 2).shuffle_state.phase = 0 := by
      unfold extractPreTableFromCryptoAir
      simp [row]
    rw [h_phase_zero] at h_phase
    exact absurd h_phase (by norm_num)

/-! ## submit_shuffle_v2 反例：version 不递增 -/

theorem submit_shuffle_v2_air_not_sound :
  ∃ (row : CommonRow) (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    SubmitShuffleV2AirAcceptable row ext expected_seat_index expected_commit_0 hlt ∧
    ¬ ContractSubmitShuffleV2
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitShuffleV2ParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.SubmitShuffleV2.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitShuffleV2⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : SubmitShuffleV2MethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_new_deck_commitment_0 := M31.zero
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 0, 2, hlt0, ?_, ?_⟩
  · -- SubmitShuffleV2AirAcceptable
    unfold SubmitShuffleV2AirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.SubmitShuffleV2.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitShuffleV2⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold SubmitShuffleV2MethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · show ext.input_new_deck_commitment_0 = ⟨0 % 65536, by unfold M31_P; omega⟩
        simp [ext]
        exact Subtype.ext rfl
    · show row.method_kind = ⟨MethodKind.SubmitShuffleV2.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitShuffleV2⟩
      simp [row]
    · rfl
  · -- ¬ ContractSubmitShuffleV2：shuffle_state.phase = 0，违反 > 0
    intro h
    rcases h with ⟨_, h_phase, _, _⟩
    have h_phase_zero : (extractPreTableFromCryptoAir row 2).shuffle_state.phase = 0 := by
      unfold extractPreTableFromCryptoAir
      simp [row]
    rw [h_phase_zero] at h_phase
    exact absurd h_phase (by norm_num)

/-! ## submit_player_reveal_tokens 反例：version 不递增 -/

theorem submit_player_reveal_tokens_air_not_sound :
  ∃ (row : CommonRow) (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat) (expected_reveal_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P),
    SubmitRevealTokensAirAcceptable row ext expected_seat_index expected_reveal_phase hlt hltp ∧
    ¬ ContractSubmitRevealTokens
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitRevealTokensParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.SubmitPlayerRevealTokens.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitPlayerRevealTokens⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : SubmitRevealTokensMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_reveal_phase := nat_to_m31 0 (by unfold M31_P; norm_num)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 0, 2, hlt0, hlt0, ?_, ?_⟩
  · -- SubmitRevealTokensAirAcceptable
    unfold SubmitRevealTokensAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.SubmitPlayerRevealTokens.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitPlayerRevealTokens⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold SubmitRevealTokensMethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · simp [ext, nat_to_m31]
    · show row.method_kind = ⟨MethodKind.SubmitPlayerRevealTokens.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitPlayerRevealTokens⟩
      simp [row]
    · rfl
  · -- ¬ ContractSubmitRevealTokens：reveal_phase = 0，违反 > 0
    intro h
    rcases h with ⟨_, h_phase, _, _⟩
    have h_phase_zero : (extractPreTableFromCryptoAir row 2).reveal_state.reveal_phase = 0 := by
      unfold extractPreTableFromCryptoAir
      simp [row]
    rw [h_phase_zero] at h_phase
    exact absurd h_phase (by norm_num)

/-! ## submit_reconstruct_deck 反例：version 不递增
    （且 reconstruct_state = ReconstructIdle，违反合约要求 ≠ ReconstructIdle） -/

theorem submit_reconstruct_deck_air_not_sound :
  ∃ (row : CommonRow) (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat) (expected_reconstruct_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_phase < M31_P),
    SubmitReconstructDeckAirAcceptable row ext expected_seat_index expected_reconstruct_phase hlt hltp ∧
    ¬ ContractSubmitReconstructDeck
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitReconstructDeckParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) := by
  let row : CommonRow := {
    is_active := M31.one
    method_kind := ⟨MethodKind.SubmitReconstructDeck.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitReconstructDeck⟩
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.one, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.zero
  }
  let ext : SubmitReconstructDeckMethodColumns := {
    input_seat_index := nat_to_m31 0 (by unfold M31_P; norm_num)
    input_reconstruct_phase := nat_to_m31 0 (by unfold M31_P; norm_num)
  }
  have hlt0 : (0 : Nat) < M31_P := by unfold M31_P; norm_num
  refine ⟨row, ext, 0, 0, 2, hlt0, hlt0, ?_, ?_⟩
  · -- SubmitReconstructDeckAirAcceptable
    unfold SubmitReconstructDeckAirAcceptable
    refine ⟨?_, ?_, ?_, ?_⟩
    · unfold CommonConstraints
      refine ⟨mul_sub_one_self_eq_zero row.is_active rfl,
              mul_sub_zero_self_eq_zero row.is_padding rfl,
              M31.mul_zero_right row.is_active, ?_⟩
      have hsub : M31.sub row.method_kind
        ⟨MethodKind.SubmitReconstructDeck.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitReconstructDeck⟩ = M31.zero := by
        simp [row]; apply sub_self_eq_zero
      rw [hsub]; apply M31.mul_zero_right
    · unfold SubmitReconstructDeckMethodConstraints
      intro _
      refine ⟨?_, ?_, ?_, ?_⟩
      · unfold VersionIncrementConstraint; simp [row]; unfold decodeU64; simp [M31.one, M31.zero]
      · unfold RoundStateUnchanged; simp [row]
      · simp [ext, nat_to_m31]
      · simp [ext, nat_to_m31]
    · show row.method_kind = ⟨MethodKind.SubmitReconstructDeck.toNat, MethodKind.toNat_lt_M31P MethodKind.SubmitReconstructDeck⟩
      simp [row]
    · rfl
  · -- ¬ ContractSubmitReconstructDeck：reconstruct_state = ReconstructIdle，违反 ≠ ReconstructIdle
    intro h
    rcases h with ⟨_, h_recon, _, _⟩
    have h_idle : (extractPreTableFromCryptoAir row 2).reconstruct_state = ReconstructState.ReconstructIdle := by
      unfold extractPreTableFromCryptoAir
      simp [row]
    rw [h_idle] at h_recon
    have h_eq : ReconstructState.ReconstructIdle = ReconstructState.ReconstructIdle := by rfl
    exact h_recon h_eq

end PokerLean
