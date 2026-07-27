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
    (h : CreateTableAirAcceptable row ext ext.maxPlayers) :
    ContractCreateTable
      (extractPreTableFromCreateTableAir row ext.maxPlayers)
      (extractParamsFromAir ext)
      (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0) :=
  create_table_soundness row ext h

/-- 完整约束版本：FullCreateTableAirAcceptable 蕴含合约语义 -/
theorem full_create_table_soundness_main
    (row : CommonRow) (ext : CreateTableRow)
    (h : FullCreateTableAirAcceptable row ext) :
    ContractCreateTable
      (extractPreTableFromCreateTableAir row ext.maxPlayers)
      (extractParamsFromAir ext)
      (extractPostTableFromCreateTableAir row ext ext.maxPlayers 0) :=
  full_create_table_soundness row ext h

/-! ## fold: ❌ AIR 约束不是 sound 的（反例） -/

/-- fold AIR 不满足 soundness 的反例存在性 -/
theorem fold_not_sound_main :
    ∃ (row : CommonRow) (ext : FoldMethodColumns)
      (expected_seat_index : Nat) (max_players : Nat)
      (hlt : expected_seat_index < M31_P),
      FoldAirAcceptable row ext expected_seat_index max_players hlt ∧
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
      CheckAirAcceptable row ext expected_seat_index hlt expected_current_bet expected_seat_bet max_players ∧
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
      CallAirAcceptable row ext expected_seat_index hlt expected_call_amount max_players ∧
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
      RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to max_players ∧
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
      BetAirAcceptable row ext expected_seat_index hlt expected_bet_amount max_players ∧
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
      AutoFoldAirAcceptable row ext expected_seat_index max_players hlt expected_current_time ∧
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
      ForceFoldAirAcceptable row ext expected_seat_index max_players hlt ∧
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
      KickPlayerAirAcceptable row ext expected_seat_index max_players hlt expected_refund ∧
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
      JoinTableAirAcceptable row ext expected_seat_index max_players hlt ∧
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
      LeaveTableAirAcceptable row ext expected_seat_index max_players hlt ∧
      ¬ ContractLeaveTable
        (extractPreTableFromLeaveTableAir row max_players (expected_seat_index + 1))
        (extractLeaveTableParamsFromAir ext)
        (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) :=
  leave_table_air_not_sound

/-! ## start_hand / tick / reset_for_next_hand: ❌ AIR 约束不是 sound 的（反例）-/

/-- start_hand AIR 不满足 soundness 的反例存在性 -/
theorem start_hand_not_sound_main :
    ∃ (row : CommonRow) (ext : StartHandMethodColumns)
      (expected_active_count : Nat) (max_players : Nat)
      (hlt : expected_active_count < M31_P),
      StartHandAirAcceptable row ext expected_active_count max_players hlt ∧
      ¬ ContractStartHand
        (extractPreTableFromLifecycleAir row max_players 0)
        (extractStartHandParamsFromAir ext)
        (extractPostTableFromLifecycleAir row max_players 0) :=
  start_hand_air_not_sound

/-- tick AIR 不满足 soundness 的反例存在性 -/
theorem tick_not_sound_main :
    ∃ (row : CommonRow) (ext : TickMethodColumns)
      (expected_timeout_kind : Nat) (max_players : Nat)
      (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
      (hlt : expected_timeout_kind < M31_P),
      TickAirAcceptable row ext expected_timeout_kind max_players hlt ∧
      ¬ ContractTick
        (extractPreTableFromLifecycleAir row max_players 0)
        (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
        (extractPostTableFromLifecycleAir row (max_players + 1) 0) :=
  tick_air_not_sound

/-- reset_for_next_hand AIR 不满足 soundness 的反例存在性 -/
theorem reset_for_next_hand_not_sound_main :
    ∃ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
      (max_players : Nat) (pre_pending_addon : Nat),
      ResetForNextHandAirAcceptable row ext max_players ∧
      ¬ ContractResetForNextHand
        (extractPreTableFromLifecycleAir row max_players 0)
        (extractResetParamsFromAir pre_pending_addon)
        (extractPostTableFromLifecycleAir row (max_players + 1) 0) :=
  reset_for_next_hand_air_not_sound

/-! ## addon / rebuy: ❌ AIR 约束不是 sound 的（反例）-/

/-- addon AIR 不满足 soundness 的反例存在性 -/
theorem addon_not_sound_main :
  ∃ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    AddonAirAcceptable row ext expected_seat_index expected_amount max_players hlt ∧
    ¬ ContractAddon
      (extractPreTableFromFundsAir row max_players (expected_seat_index + 1))
      (extractAddonParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players (expected_seat_index + 1)) :=
  addon_air_not_sound

/-- rebuy AIR 不满足 soundness 的反例存在性 -/
theorem rebuy_not_sound_main :
  ∃ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_amount : Nat)
    (hlt : expected_seat_index < M31_P),
    RebuyAirAcceptable row ext expected_seat_index expected_amount max_players hlt ∧
    ¬ ContractRebuy
      (extractPreTableFromFundsAir row max_players (expected_seat_index + 1))
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromFundsAir row max_players (expected_seat_index + 1)) :=
  rebuy_air_not_sound

/-! ## 密码学方法（Mental Poker 协议）: ❌ AIR 约束不是 sound 的（反例）-/

/-- join_and_shuffle AIR 不满足 soundness 的反例存在性 -/
theorem join_and_shuffle_not_sound_main :
  ∃ (row : CommonRow) (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat) (expected_commit_0 : Nat)
    (hlt : expected_seat_index < M31_P),
    JoinAndShuffleAirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt ∧
    ¬ ContractJoinAndShuffle
      (extractPreTableFromCryptoAir row max_players 0 0 0)
      (extractJoinAndShuffleParamsFromAir ext)
      (extractPostTableFromCryptoAir row (max_players + 1) 0 0 0) := by
  exact join_and_shuffle_air_not_sound

/-- leave_with_proof AIR 不满足 soundness 的反例存在性 -/
theorem leave_with_proof_not_sound_main :
  ∃ (row : CommonRow) (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat) (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P),
    LeaveWithProofAirAcceptable row ext expected_seat_index expected_leave_kind max_players hlt hltk ∧
    ¬ ContractLeaveWithProof
      (extractPreTableFromCryptoAir row max_players 0 0 0)
      (extractLeaveWithProofParamsFromAir ext)
      (extractPostTableFromCryptoAir row (max_players + 1) 0 0 0) :=
  leave_with_proof_air_not_sound

/-- submit_shuffle_v2 AIR 不满足 soundness 的反例存在性 -/
theorem submit_shuffle_v2_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P),
    SubmitShuffleV2AirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt ∧
    ¬ ContractSubmitShuffleV2
      (extractPreTableFromCryptoAir row max_players 0 0 0)
      (extractSubmitShuffleV2ParamsFromAir ext)
      (extractPostTableFromCryptoAir row (max_players + 1) 0 0 0) :=
  submit_shuffle_v2_air_not_sound

/-- submit_player_reveal_tokens AIR 不满足 soundness 的反例存在性 -/
theorem submit_player_reveal_tokens_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat) (expected_reveal_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P),
    SubmitRevealTokensAirAcceptable row ext expected_seat_index expected_reveal_phase max_players hlt hltp ∧
    ¬ ContractSubmitRevealTokens
      (extractPreTableFromCryptoAir row max_players 0 0 0)
      (extractSubmitRevealTokensParamsFromAir ext)
      (extractPostTableFromCryptoAir row (max_players + 1) 0 0 0) :=
  submit_player_reveal_tokens_air_not_sound

/-- submit_reconstruct_deck AIR 不满足 soundness 的反例存在性 -/
theorem submit_reconstruct_deck_not_sound_main :
  ∃ (row : CommonRow) (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat) (expected_reconstruct_state : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_state < M31_P),
    SubmitReconstructDeckAirAcceptable row ext expected_seat_index expected_reconstruct_state max_players hlt hltp ∧
    ¬ ContractSubmitReconstructDeck
      (extractPreTableFromCryptoAir row max_players 0 0 0)
      (extractSubmitReconstructDeckParamsFromAir ext)
      (extractPostTableFromCryptoAir row (max_players + 1) 0 0 0) := by
  exact submit_reconstruct_deck_air_not_sound

/-! ## 总结（全面约束集成后）

通过 Lean 形式化验证，我们证明了 21 个方法的 soundness 状况：

### ✅ Sound（1 个）
1. **create_table AIR 是 sound 的** — AIR 约束完全蕴含合约语义

### ❌ Not Sound（20 个，均存在反例）

#### 动作方法（7 个）— 缺少座位参与检查和当前轮次检查：
2. **fold AIR 不是 sound 的** — 反例：座位未参与（is_participating = false）或 current_turn ≠ seat_index
3. **check AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index
4. **call AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index
5. **raise AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index
6. **bet AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index
7. **auto_fold AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index
8. **force_fold AIR 不是 sound 的** — 反例：座位未参与或 current_turn ≠ seat_index

#### 座位状态方法（3 个）— 缺少详细状态一致性：
9. **kick_player AIR 不是 sound 的** — 反例：合约后置状态不一致
10. **join_table AIR 不是 sound 的** — 反例：合约后置状态不一致
11. **leave_table AIR 不是 sound 的** — 反例：合约后置状态不一致

#### 生命周期/资金方法（5 个）— 缺少详细状态一致性：
12. **start_hand AIR 不是 sound 的** — 反例：合约后置状态不一致
13. **tick AIR 不是 sound 的** — 反例：合约后置状态不一致
14. **reset_for_next_hand AIR 不是 sound 的** — 反例：合约后置状态不一致
15. **addon AIR 不是 sound 的** — 反例：通过不同 seat_index 提取使合约拒绝（seat occupancy 不匹配）
16. **rebuy AIR 不是 sound 的** — 反例：通过不同 seat_index 提取使合约拒绝（seat occupancy 不匹配）

#### 密码学方法（5 个）— 缺少密码学状态一致性：
17. **join_and_shuffle AIR 不是 sound 的** — 反例：密码学状态不一致
18. **leave_with_proof AIR 不是 sound 的** — 反例：密码学状态不一致
19. **submit_shuffle_v2 AIR 不是 sound 的** — 反例：密码学状态不一致
20. **submit_player_reveal_tokens AIR 不是 sound 的** — 反例：密码学状态不一致
21. **submit_reconstruct_deck AIR 不是 sound 的** — 反例：密码学状态不一致

### 已关闭的 soundness gap：

#### 座位占用检查（全部关闭）：
- ✅ join_table → SeatEmpty 约束已关闭
- ✅ leave_table → SeatOccupied 约束已关闭
- ✅ kick_player → SeatOccupied 约束已关闭
- ✅ addon → SeatOccupied 约束已关闭
- ✅ rebuy → SeatOccupied 约束已关闭

#### Round state gating（全部关闭）：
- ✅ fold/check/call/raise/bet/auto_fold/force_fold → RoundStateIsBetting 已关闭

#### 金额正数检查（已关闭）：
- ✅ addon/rebuy → AmountPositive 已关闭

#### 其他前置条件（已关闭）：
- ✅ start_hand → ActiveCountAtLeastTwo 已关闭
- ✅ tick → TimeoutKindPositive 已关闭
- ✅ reset_for_next_hand + 3 crypto 方法 → ShufflePhasePositive 已关闭
- ✅ submit_player_reveal_tokens → RevealPhasePositive 已关闭
- ✅ submit_reconstruct_deck → ReconstructStateNotIdle 已关闭

#### StateRootConsistency 已关闭：
- ✅ version 不递增 → VersionIncrementConstraint + StateRootConsistency
- ✅ pot 不守恒 → PotUnchangedLimb0 + StateRootConsistency
- ✅ state root 不一致 → StateRootConsistency
- ✅ 状态字段不一致 → StateRootConsistency 编码完整状态

### 仍存在的 soundness gap：

#### 未强制执行的合约前置条件：
- **座位参与检查**（7 个动作方法）：需要 `seat.is_participating = true`（当前列无法强制执行）
- **当前轮次检查**（7 个动作方法）：需要 `current_turn = seat_index`（当前列无法强制执行）

#### 未强制执行的状态一致性：
- **生命周期方法**（start_hand, tick, reset_for_next_hand）：需要详细的 `post.xxx = pre.xxx` 状态一致性
- **密码学方法**（5 个方法）：需要密码学状态一致性（超出 phase 检查的约束）

### 核心结论

当前 `poker_texas_air` 电路约束对于原合约 `poker_l1` 的约束 **不是 sound 的**：
仅在 `create_table` 方法上 AIR 是 sound 的；
其他 20 个方法都存在反例。

**已关闭的 gap**：所有可通过当前 AIR 列强制执行的合约前置条件（座位占用、round_state gating、金额正数、active_count、timeout_kind、shuffle/reveal/reconstruct phase 检查）均已关闭。反例已调整为违反剩余未强制执行的前置条件。

**剩余需要补齐的约束**：
1. **座位参与检查**：7 个动作方法需要 `seat.is_participating = true` 约束（需扩展 AIR 列）
2. **当前轮次检查**：7 个动作方法需要 `current_turn = seat_index` 约束（需扩展 AIR 列）
3. **详细状态一致性**：生命周期方法和密码学方法需要完整的状态一致性约束
-/

end PokerLean
