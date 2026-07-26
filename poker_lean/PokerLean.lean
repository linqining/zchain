import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Constants
import PokerLean.Contract.CreateTable
import PokerLean.Contract.Fold
import PokerLean.Contract.Check
import PokerLean.Contract.Call
import PokerLean.Contract.Raise
import PokerLean.Contract.Bet
import PokerLean.Contract.MoreActions
import PokerLean.Contract.JoinTable
import PokerLean.Contract.LeaveTable
import PokerLean.Contract.Lifecycle
import PokerLean.Contract.Funds
import PokerLean.Contract.Crypto
import PokerLean.AIR.AirBase
import PokerLean.AIR.CreateTableAir
import PokerLean.AIR.FoldAir
import PokerLean.AIR.CheckAir
import PokerLean.AIR.CallAir
import PokerLean.AIR.RaiseAir
import PokerLean.AIR.BetAir
import PokerLean.AIR.MoreActionsAir
import PokerLean.AIR.JoinTableAir
import PokerLean.AIR.LeaveTableAir
import PokerLean.AIR.LifecycleAir
import PokerLean.AIR.FundsAir
import PokerLean.AIR.CryptoAir
import PokerLean.Proofs.CreateTableSoundness
import PokerLean.Proofs.FoldSoundness
import PokerLean.Proofs.FullSoundness
import PokerLean.Proofs.FoldPartialSoundness
import PokerLean.Proofs.CheckSoundness
import PokerLean.Proofs.CallSoundness
import PokerLean.Proofs.RaiseSoundness
import PokerLean.Proofs.BetSoundness
import PokerLean.Proofs.MoreActionsSoundness
import PokerLean.Proofs.JoinTableSoundness
import PokerLean.Proofs.LeaveTableSoundness
import PokerLean.Proofs.LifecycleSoundness
import PokerLean.Proofs.FundsSoundness
import PokerLean.Proofs.CryptoSoundness

namespace PokerLean

/-! ## create_table: ✅ AIR 约束是 sound 的 -/

/-- 主定理：create_table AIR 约束蕴含合约语义（soundness） -/
theorem create_table_soundness_main
    (row : CommonRow) (ext : CreateTableRow)
    (h : CreateTableAirAcceptable row ext) :
    ContractCreateTable
      (extractPreTableFromAir row)
      (extractParamsFromAir ext)
      (extractPostTableFromAir row ext) :=
  create_table_soundness row ext h

/-- 完整约束版本：FullCreateTableAirAcceptable 蕴含合约语义 -/
theorem full_create_table_soundness_main
    (row : CommonRow) (ext : CreateTableRow)
    (h : FullCreateTableAirAcceptable row ext) :
    ContractCreateTable
      (extractPreTableFromAir row)
      (extractParamsFromAir ext)
      (extractPostTableFromAir row ext) :=
  full_create_table_soundness row ext h

/-! ## fold: ❌ AIR 约束不是 sound 的（反例） -/

/-- fold AIR 不满足 soundness 的反例存在性 -/
theorem fold_not_sound_main :
    ∃ (row : CommonRow) (ext : FoldMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (hlt : expected_seat_index < M31_P),
      FoldAirAcceptable row ext expected_seat_index hlt ∧
      ¬ ContractFold
        (extractPreTableFromFoldAir row max_players)
        (extractFoldParamsFromAir ext)
        (extractPostTableFromFoldAir row ext max_players expected_seat_index) :=
  fold_air_not_sound

/-- fold AIR 部分.soundness：FullFoldAirAcceptable 蕴含 ContractFoldPartial -/
theorem full_fold_partial_soundness_main
    (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (h : FullFoldAirAcceptable row ext expected_seat_index max_players hlt) :
    ContractFoldPartial
      (extractPreTableFromFoldAir row max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) :=
  full_fold_partial_soundness row ext expected_seat_index max_players hlt h

/-- ContractFold 蕴含 ContractFoldPartial（弱化关系） -/
theorem contract_fold_implies_partial_main
    (pre : TexasPokerTable) (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
    ContractFoldPartial pre params post :=
  contract_fold_implies_partial pre params post h

/-! ## check: ❌ AIR 约束不是 sound 的（反例） -/

/-- check AIR 不满足 soundness 的反例存在性 -/
theorem check_not_sound_main :
    ∃ (row : CommonRow) (ext : CheckMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_current_bet : Nat) (expected_seat_bet : Nat)
      (hlt : expected_seat_index < M31_P),
      CheckAirAcceptable row ext expected_seat_index hlt expected_current_bet expected_seat_bet ∧
      ¬ ContractCheck
        (extractPreTableFromCheckAir row max_players)
        (extractCheckParamsFromAir ext)
        (extractPostTableFromCheckAir row ext max_players expected_seat_index) :=
  check_air_not_sound

/-- ContractCheck 蕴含 ContractCheckPartial（弱化关系） -/
theorem contract_check_implies_partial_main
    (pre : TexasPokerTable) (params : CheckParams) (post : TexasPokerTable)
    (h : ContractCheck pre params post) :
    ContractCheckPartial pre params post :=
  contract_check_implies_partial pre params post h

/-! ## call: ❌ AIR 约束不是 sound 的（反例） -/

/-- call AIR 不满足 soundness 的反例存在性 -/
theorem call_not_sound_main :
    ∃ (row : CommonRow) (ext : CallMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_call_amount : Nat)
      (hlt : expected_seat_index < M31_P),
      CallAirAcceptable row ext expected_seat_index hlt expected_call_amount ∧
      ¬ ContractCall
        (extractPreTableFromCallAir row max_players)
        (extractCallParamsFromAir ext)
        (extractPostTableFromCallAir row ext max_players expected_seat_index) :=
  call_air_not_sound

/-- ContractCall 蕴含 ContractCallPartial（弱化关系） -/
theorem contract_call_implies_partial_main
    (pre : TexasPokerTable) (params : CallParams) (post : TexasPokerTable)
    (h : ContractCall pre params post) :
    ContractCallPartial pre params post :=
  contract_call_implies_partial pre params post h

/-! ## raise: ❌ AIR 约束不是 sound 的（反例） -/

/-- raise AIR 不满足 soundness 的反例存在性 -/
theorem raise_not_sound_main :
    ∃ (row : CommonRow) (ext : RaiseMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_raise_to : Nat)
      (hlt : expected_seat_index < M31_P),
      RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to ∧
      ¬ ContractRaise
        (extractPreTableFromRaiseAir row max_players)
        (extractRaiseParamsFromAir ext)
        (extractPostTableFromRaiseAir row ext max_players expected_seat_index) :=
  raise_air_not_sound

/-- ContractRaise 蕴含 ContractRaisePartial（弱化关系） -/
theorem contract_raise_implies_partial_main
    (pre : TexasPokerTable) (params : RaiseParams) (post : TexasPokerTable)
    (h : ContractRaise pre params post) :
    ContractRaisePartial pre params post :=
  contract_raise_implies_partial pre params post h

/-! ## bet: ❌ AIR 约束不是 sound 的（反例） -/

/-- bet AIR 不满足 soundness 的反例存在性 -/
theorem bet_not_sound_main :
    ∃ (row : CommonRow) (ext : BetMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_bet_amount : Nat)
      (hlt : expected_seat_index < M31_P),
      BetAirAcceptable row ext expected_seat_index hlt expected_bet_amount ∧
      ¬ ContractBet
        (extractPreTableFromBetAir row max_players)
        (extractBetParamsFromAir ext)
        (extractPostTableFromBetAir row ext max_players expected_seat_index) :=
  bet_air_not_sound

/-- ContractBet 蕴含 ContractBetPartial（弱化关系） -/
theorem contract_bet_implies_partial_main
    (pre : TexasPokerTable) (params : BetParams) (post : TexasPokerTable)
    (h : ContractBet pre params post) :
    ContractBetPartial pre params post :=
  contract_bet_implies_partial pre params post h

/-! ## auto_fold / force_fold / kick_player: ❌ AIR 约束不是 sound 的（反例）-/

/-- auto_fold AIR 不满足 soundness 的反例存在性 -/
theorem auto_fold_not_sound_main :
    ∃ (row : CommonRow) (ext : AutoFoldMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_current_time : Nat)
      (hlt : expected_seat_index < M31_P),
      AutoFoldAirAcceptable row ext expected_seat_index hlt expected_current_time ∧
      ¬ ContractAutoFold
        (extractPreTableFromActionAir row max_players MethodKind.AutoFold)
        (extractAutoFoldParamsFromAir ext)
        (extractPostTableFromActionAir row max_players MethodKind.AutoFold) :=
  auto_fold_air_not_sound

/-- force_fold AIR 不满足 soundness 的反例存在性 -/
theorem force_fold_not_sound_main :
    ∃ (row : CommonRow) (ext : ForceFoldMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (hlt : expected_seat_index < M31_P),
      ForceFoldAirAcceptable row ext expected_seat_index hlt ∧
      ¬ ContractForceFold
        (extractPreTableFromActionAir row max_players MethodKind.ForceFold)
        (extractForceFoldParamsFromAir ext)
        (extractPostTableFromActionAir row max_players MethodKind.ForceFold) :=
  force_fold_air_not_sound

/-- kick_player AIR 不满足 soundness 的反例存在性 -/
theorem kick_player_not_sound_main :
    ∃ (row : CommonRow) (ext : KickPlayerMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (expected_refund : Nat)
      (hlt : expected_seat_index < M31_P),
      KickPlayerAirAcceptable row ext expected_seat_index hlt expected_refund ∧
      ¬ ContractKickPlayer
        (extractPreTableFromActionAir row max_players MethodKind.KickPlayer)
        (extractKickPlayerParamsFromAir ext)
        (extractPostTableFromActionAir row max_players MethodKind.KickPlayer) :=
  kick_player_air_not_sound

/-! ## join_table: ❌ AIR 约束不是 sound 的（反例）-/

/-- join_table AIR 不满足 soundness 的反例存在性 -/
theorem join_table_not_sound_main :
    ∃ (row : CommonRow) (ext : JoinTableMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (player : PlayerId)
      (hlt : expected_seat_index < M31_P),
      JoinTableAirAcceptable row ext expected_seat_index hlt ∧
      ¬ ContractJoinTable
        (extractPreTableFromJoinTableAir row max_players)
        (extractJoinTableParamsFromAir ext player)
        (extractPostTableFromJoinTableAir row ext max_players expected_seat_index) :=
  join_table_air_not_sound

/-! ## leave_table: ❌ AIR 约束不是 sound 的（反例）-/

/-- leave_table AIR 不满足 soundness 的反例存在性 -/
theorem leave_table_not_sound_main :
    ∃ (row : CommonRow) (ext : LeaveTableMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (hlt : expected_seat_index < M31_P),
      LeaveTableAirAcceptable row ext expected_seat_index hlt ∧
      ¬ ContractLeaveTable
        (extractPreTableFromLeaveTableAir row max_players)
        (extractLeaveTableParamsFromAir ext)
        (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) :=
  leave_table_air_not_sound

/-! ## start_hand / tick / reset_for_next_hand: ❌ AIR 约束不是 sound 的（反例）-/

/-- start_hand AIR 不满足 soundness 的反例存在性 -/
theorem start_hand_not_sound_main :
    ∃ (row : CommonRow) (ext : StartHandMethodColumns)
      (expected_active_count : Nat) (max_players : Nat)
      (hlt : expected_active_count < M31_P),
      StartHandAirAcceptable row ext expected_active_count hlt ∧
      ¬ ContractStartHand
        (extractPreTableFromLifecycleAir row max_players)
        (extractStartHandParamsFromAir ext)
        (extractPostTableFromLifecycleAir row max_players) :=
  start_hand_air_not_sound

/-- tick AIR 不满足 soundness 的反例存在性 -/
theorem tick_not_sound_main :
    ∃ (row : CommonRow) (ext : TickMethodColumns)
      (expected_timeout_kind : Nat) (max_players : Nat)
      (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
      (hlt : expected_timeout_kind < M31_P),
      TickAirAcceptable row ext expected_timeout_kind hlt ∧
      ¬ ContractTick
        (extractPreTableFromLifecycleAir row max_players)
        (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
        (extractPostTableFromLifecycleAir row max_players) :=
  tick_air_not_sound

/-- reset_for_next_hand AIR 不满足 soundness 的反例存在性 -/
theorem reset_for_next_hand_not_sound_main :
    ∃ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
      (max_players : Nat) (pre_pending_addon : Nat),
      ResetForNextHandAirAcceptable row ext ∧
      ¬ ContractResetForNextHand
        (extractPreTableFromLifecycleAir row max_players)
        (extractResetParamsFromAir pre_pending_addon)
        (extractPostTableFromLifecycleAir row max_players) :=
  reset_for_next_hand_air_not_sound

/-! ## addon / rebuy: ❌ AIR 约束不是 sound 的（反例）-/

/-- addon AIR 不满足 soundness 的反例存在性 -/
theorem addon_not_sound_main :
  ∃ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    AddonAirAcceptable row ext expected_seat_index expected_amount hlt ∧
    ¬ ContractAddon
      (extractPreTableFromFundsAir row max_players)
      (extractAddonParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players) :=
  addon_air_not_sound

/-- rebuy AIR 不满足 soundness 的反例存在性 -/
theorem rebuy_not_sound_main :
  ∃ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    RebuyAirAcceptable row ext expected_seat_index expected_amount hlt ∧
    ¬ ContractRebuy
      (extractPreTableFromFundsAir row max_players)
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players) :=
  rebuy_air_not_sound

/-! ## 密码学方法（Mental Poker 协议）: ❌ AIR 约束不是 sound 的（反例）-/

/-- join_and_shuffle AIR 不满足 soundness 的反例存在性 -/
theorem join_and_shuffle_not_sound_main :
  ∃ (row : CommonRow) (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_commit_0 : Nat)
    (hlt : expected_seat_index < M31_P),
    JoinAndShuffleAirAcceptable row ext expected_seat_index expected_commit_0 hlt ∧
    ¬ ContractJoinAndShuffle
      (extractPreTableFromCryptoAir row max_players)
      (extractJoinAndShuffleParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) :=
  join_and_shuffle_air_not_sound

/-- leave_with_proof AIR 不满足 soundness 的反例存在性 -/
theorem leave_with_proof_not_sound_main :
  ∃ (row : CommonRow) (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat) (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P),
    LeaveWithProofAirAcceptable row ext expected_seat_index expected_leave_kind hlt hltk ∧
    ¬ ContractLeaveWithProof
      (extractPreTableFromCryptoAir row max_players)
      (extractLeaveWithProofParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) :=
  leave_with_proof_air_not_sound

/-- submit_shuffle_v2 AIR 不满足 soundness 的反例存在性 -/
theorem submit_shuffle_v2_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    SubmitShuffleV2AirAcceptable row ext expected_seat_index expected_commit_0 hlt ∧
    ¬ ContractSubmitShuffleV2
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitShuffleV2ParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) :=
  submit_shuffle_v2_air_not_sound

/-- submit_player_reveal_tokens AIR 不满足 soundness 的反例存在性 -/
theorem submit_player_reveal_tokens_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat) (expected_reveal_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P),
    SubmitRevealTokensAirAcceptable row ext expected_seat_index expected_reveal_phase hlt hltp ∧
    ¬ ContractSubmitRevealTokens
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitRevealTokensParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) :=
  submit_player_reveal_tokens_air_not_sound

/-- submit_reconstruct_deck AIR 不满足 soundness 的反例存在性 -/
theorem submit_reconstruct_deck_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat) (expected_reconstruct_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_phase < M31_P),
    SubmitReconstructDeckAirAcceptable row ext expected_seat_index expected_reconstruct_phase hlt hltp ∧
    ¬ ContractSubmitReconstructDeck
      (extractPreTableFromCryptoAir row max_players)
      (extractSubmitReconstructDeckParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players) :=
  submit_reconstruct_deck_air_not_sound

/-! ## 总结

通过 Lean 形式化验证，我们证明了 21 个方法的 soundness 状况：

### ✅ Sound（1 个）
1. **create_table AIR 是 sound 的** — AIR 约束完全蕴含合约语义

### ❌ Not Sound（20 个，均存在反例）
2. **fold AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 fold）
3. **check AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 check）
4. **call AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 call）
5. **raise AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 raise）
6. **bet AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 bet）
7. **auto_fold AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 auto_fold）
8. **force_fold AIR 不是 sound 的** — 存在反例（ROUND_WAITING 下 force_fold）
9. **kick_player AIR 不是 sound 的** — 存在反例（在空座位上 kick_player）
10. **join_table AIR 不是 sound 的** — 存在反例（在 ROUND_PREFLOP 下 join_table）
11. **leave_table AIR 不是 sound 的** — 存在反例（在 ROUND_PREFLOP 下 leave_table）
12. **start_hand AIR 不是 sound 的** — 存在反例（在 ROUND_PREFLOP 下 start_hand）
13. **tick AIR 不是 sound 的** — 存在反例（timeout_kind = 0 无真实超时）
14. **reset_for_next_hand AIR 不是 sound 的** — 存在反例（version 不递增）
15. **addon AIR 不是 sound 的** — 存在反例（amount = 0 不满足 > 0）
16. **rebuy AIR 不是 sound 的** — 存在反例（amount = 0 不满足 > 0）
17. **join_and_shuffle AIR 不是 sound 的** — 存在反例（version 不递增、shuffle_state.phase = 0）
18. **leave_with_proof AIR 不是 sound 的** — 存在反例（version 不递增、shuffle_state.phase = 0）
19. **submit_shuffle_v2 AIR 不是 sound 的** — 存在反例（version 不递增、shuffle_state.phase = 0）
20. **submit_player_reveal_tokens AIR 不是 sound 的** — 存在反例（version 不递增、reveal_phase = 0）
21. **submit_reconstruct_deck AIR 不是 sound 的** — 存在反例（version 不递增、reconstruct_state = ReconstructIdle）

### 20 个有问题的方法的 soundness 缺陷分类：
- **动作方法**（fold/check/call/raise/bet/auto_fold/force_fold）：
  缺少 round_state gating、current_turn 检查
- **kick_player**：额外缺少 seat.is_occupied 验证
- **生命周期方法**（join_table/leave_table/start_hand）：
  缺少 round_state == WAITING gating、座位状态检查
- **tick**：缺少真实超时条件验证
- **reset_for_next_hand**：缺少 version 递增
- **资金方法**（addon/rebuy）：缺少 amount > 0 校验、座位占用检查、资金守恒
- **密码学方法**（join_and_shuffle/leave_with_proof/submit_shuffle_v2/
  submit_player_reveal_tokens/submit_reconstruct_deck）：
  缺少 shuffle_state/reveal_state/reconstruct_state 阶段 gating、
  密码学证明验证（假设由外部 ZK 验证器负责）
- **所有 20 个有问题的方法**共同缺陷：
  缺少 state root 一致性验证、缺少 version 递增约束

### 核心结论

当前 `poker_texas_air` 电路约束对于原合约 `poker_l1` 的约束 **不是 sound 的**：
仅在 `create_table` 方法上 AIR 是 sound 的；
其他 20 个方法都存在反例，使得 AIR 约束可被满足但合约语义被违反。
要达到 soundness，AIR 实现需要补齐以下约束：
1. **version 递增约束**：`post_version = pre_version + 1`（所有 20 个非 create_table 方法）
2. **state root 一致性**：`post_state_root = Poseidon252(pre_state, changes)`
3. **方法 gating**：根据合约语义强制 round_state/shuffle_state/reveal_state/reconstruct_state 阶段
4. **业务前置条件**：amount > 0、seat.is_occupied、current_turn = seat_index 等
5. **业务后置条件**：资金守恒、座位状态变更等
-/

end PokerLean
