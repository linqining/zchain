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
import PokerLean.State.Basic
import PokerLean.State.Card
import PokerLean.State.Constants
import PokerLean.State.Types
import PokerLean.State.Betting
import PokerLean.State.Transitions
import PokerLean.State.Invariants
import PokerLean.State.RoundMachine
import PokerLean.State.SidePot
import PokerLean.State.HandEvaluator
import PokerLean.State.SubPhases
import PokerLean.State.Theorems
import PokerLean.State.Refinement
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
import PokerLean.Audit.SoundnessAudit

namespace PokerLean

/-! ## create_table: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

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

/-! ## fold: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- fold AIR soundness：AIR 约束蕴含合约语义 -/
theorem fold_sound_main :
  ∀ (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    FoldAirAcceptable row ext expected_seat_index max_players hlt →
    ContractFold
      (extractPreTableFromFoldAir row ext max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) :=
  fold_air_sound

/-- fold AIR 部分.soundness：FullFoldAirAcceptable 蕴含 ContractFoldPartial -/
theorem full_fold_partial_soundness_main
    (row : CommonRow) (ext : FoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (h : FullFoldAirAcceptable row ext expected_seat_index max_players hlt) :
    ContractFoldPartial
      (extractPreTableFromFoldAir row ext max_players)
      (extractFoldParamsFromAir ext)
      (extractPostTableFromFoldAir row ext max_players expected_seat_index) :=
  full_fold_partial_soundness row ext expected_seat_index max_players hlt h

/-- ContractFold 蕴含 ContractFoldPartial（弱化关系） -/
theorem contract_fold_implies_partial_main
    (pre : TexasPokerTable) (params : FoldParams) (post : TexasPokerTable)
    (h : ContractFold pre params post) :
    ContractFoldPartial pre params post :=
  contract_fold_implies_partial pre params post h

/-! ## check: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- check AIR soundness：AIR 约束蕴含合约语义 -/
theorem check_sound_main :
  ∀ (row : CommonRow) (ext : CheckMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_current_bet : Nat) (expected_seat_bet : Nat)
    (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    CheckAirAcceptable row ext expected_seat_index hlt expected_current_bet expected_seat_bet max_players →
    ContractCheck
      (extractPreTableFromCheckAir row ext max_players)
      (extractCheckParamsFromAir ext)
      (extractPostTableFromCheckAir row ext max_players expected_seat_index) :=
  check_air_sound

/-- ContractCheck 蕴含 ContractCheckPartial（弱化关系） -/
theorem contract_check_implies_partial_main
    (pre : TexasPokerTable) (params : CheckParams) (post : TexasPokerTable)
    (h : ContractCheck pre params post) :
    ContractCheckPartial pre params post :=
  contract_check_implies_partial pre params post h

/-! ## call: ✅ 手写 mid-round 模型内的 AIR 约束是 sound 的 -/

/-- call AIR soundness：手写 AIR 约束蕴含 mid-round 局部合约语义。 -/
theorem call_sound_main :
  ∀ (row : CommonRow) (ext : CallMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_call_amount : Nat) (expected_trusted : CallTrustedInputs)
    (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    CallAirAcceptable row ext expected_seat_index hlt expected_call_amount
      expected_trusted max_players →
    ContractCall
      (extractPreTableFromCallAir row ext max_players)
      (extractCallParamsFromAir ext)
      (extractPostTableFromCallAir row ext max_players expected_seat_index) :=
  call_air_sound

/-- ContractCall 蕴含 ContractCallPartial（弱化关系） -/
theorem contract_call_implies_partial_main
    (pre : TexasPokerTable) (params : CallParams) (post : TexasPokerTable)
    (h : ContractCall pre params post) :
    ContractCallPartial pre params post :=
  contract_call_implies_partial pre params post h

/-! ## raise: ✅ 手写 mid-round 模型内的 AIR 约束是 sound 的 -/

/-- raise AIR soundness：手写 AIR 约束蕴含 mid-round 局部合约语义。 -/
theorem raise_sound_main :
  ∀ (row : CommonRow) (ext : RaiseMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_raise_to : Nat) (expected_trusted : RaiseTrustedInputs)
    (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    RaiseAirAcceptable row ext expected_seat_index hlt expected_raise_to
      expected_trusted max_players →
    ContractRaise
      (extractPreTableFromRaiseAir row ext max_players)
      (extractRaiseParamsFromAir ext)
      (extractPostTableFromRaiseAir row ext max_players expected_seat_index) :=
  raise_air_sound

/-- ContractRaise 蕴含 ContractRaisePartial（弱化关系） -/
theorem contract_raise_implies_partial_main
    (pre : TexasPokerTable) (params : RaiseParams) (post : TexasPokerTable)
    (h : ContractRaise pre params post) :
    ContractRaisePartial pre params post :=
  contract_raise_implies_partial pre params post h

/-! ## bet: ✅ 手写 mid-round 模型内的 AIR 约束是 sound 的 -/

/-- bet AIR soundness：手写 AIR 约束蕴含 mid-round 局部合约语义。 -/
theorem bet_sound_main :
  ∀ (row : CommonRow) (ext : BetMethodColumns)
    (expected_seat_index : Nat) (hlt : expected_seat_index < M31_P)
    (expected_bet_amount : Nat) (expected_trusted : BetTrustedInputs)
    (max_players : Nat)
    (hseat : expected_seat_index < max_players),
    BetAirAcceptable row ext expected_seat_index hlt expected_bet_amount
      expected_trusted max_players →
    ContractBet
      (extractPreTableFromBetAir row ext max_players)
      (extractBetParamsFromAir ext)
      (extractPostTableFromBetAir row ext max_players expected_seat_index) :=
  bet_air_sound

/-- ContractBet 蕴含 ContractBetPartial（弱化关系） -/
theorem contract_bet_implies_partial_main
    (pre : TexasPokerTable) (params : BetParams) (post : TexasPokerTable)
    (h : ContractBet pre params post) :
    ContractBetPartial pre params post :=
  contract_bet_implies_partial pre params post h

/-! ## auto_fold / force_fold / kick_player: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- auto_fold AIR soundness：AIR 约束蕴含合约语义 -/
theorem auto_fold_sound_main :
  ∀ (row : CommonRow) (ext : AutoFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_current_time : Nat)
    (hseat : expected_seat_index < max_players),
    AutoFoldAirAcceptable row ext expected_seat_index max_players hlt expected_current_time →
    ContractAutoFold
      (extractPreTableFromAutoFoldAir row ext max_players)
      (extractAutoFoldParamsFromAir ext)
      (extractPostTableFromAutoFoldAir row ext max_players expected_seat_index) :=
  auto_fold_air_sound

/-- force_fold AIR soundness：AIR 约束蕴含合约语义 -/
theorem force_fold_sound_main :
  ∀ (row : CommonRow) (ext : ForceFoldMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    ForceFoldAirAcceptable row ext expected_seat_index max_players hlt →
    ContractForceFold
      (extractPreTableFromForceFoldAir row ext max_players)
      (extractForceFoldParamsFromAir ext)
      (extractPostTableFromForceFoldAir row ext max_players expected_seat_index) :=
  force_fold_air_sound

/-- kick_player AIR soundness：AIR 约束蕴含合约语义 -/
theorem kick_player_sound_main :
  ∀ (row : CommonRow) (ext : KickPlayerMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (expected_refund : Nat)
    (hseat : expected_seat_index < max_players),
    KickPlayerAirAcceptable row ext expected_seat_index max_players hlt expected_refund →
    Limb4Range16 ext.kicked_bet →
    Limb4Range16 row.pre_pot →
    ContractKickPlayer
      (extractPreTableFromKickPlayerAir row ext max_players)
      (extractKickPlayerParamsFromAir ext)
      (extractPostTableFromKickPlayerAir row ext max_players expected_seat_index) :=
  kick_player_air_sound

/-! ## join_table: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- join_table AIR soundness：AIR 约束蕴含合约语义 -/
theorem join_table_sound_main :
  ∀ (row : CommonRow) (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    JoinTableAirAcceptable row ext expected_seat_index max_players hlt →
    ContractJoinTable
      (extractPreTableFromJoinTableAir row ext max_players)
      (extractJoinTableParamsFromAir' ext)
      (extractPostTableFromJoinTableAir row ext max_players expected_seat_index) :=
  join_table_air_sound

/-! ## leave_table: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- leave_table AIR soundness：AIR 约束蕴含合约语义 -/
theorem leave_table_sound_main :
  ∀ (row : CommonRow) (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    LeaveTableAirAcceptable row ext expected_seat_index max_players hlt →
    ContractLeaveTable
      (extractPreTableFromLeaveTableAir row ext max_players expected_seat_index)
      (extractLeaveTableParamsFromAir ext)
      (extractPostTableFromLeaveTableAir row ext max_players expected_seat_index) :=
  leave_table_air_sound

/-! ## start_hand / tick / reset_for_next_hand: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- start_hand AIR soundness：AIR 约束蕴含合约语义 -/
theorem start_hand_sound_main :
  ∀ (row : CommonRow) (ext : StartHandMethodColumns)
    (expected_active_count : Nat) (max_players : Nat)
    (hlt : expected_active_count < M31_P),
    StartHandAirAcceptable row ext expected_active_count max_players hlt →
    ContractStartHand
      (extractPreTableFromStartHandAir row ext.input_active_count.val max_players)
      (extractStartHandParamsFromAir ext)
      (extractPostTableFromStartHandAir row ext.input_active_count.val max_players) :=
  start_hand_air_sound

/-- tick AIR soundness：AIR 约束蕴含合约语义 -/
theorem tick_sound_main :
  ∀ (row : CommonRow) (ext : TickMethodColumns)
    (expected_timeout_kind : Nat) (max_players : Nat)
    (time_bank_consumed time_bank_post rake_mode rake_amount : Nat)
    (hlt : expected_timeout_kind < M31_P),
    TickAirAcceptable row ext expected_timeout_kind max_players hlt →
    ContractTick
      (extractPreTableFromLifecycleAir row max_players 0)
      (extractTickParamsFromAir ext expected_timeout_kind time_bank_consumed time_bank_post rake_mode rake_amount)
      (extractPostTableFromLifecycleAir row max_players 0) :=
  tick_air_sound

/-- reset_for_next_hand AIR soundness：AIR 约束蕴含合约语义 -/
theorem reset_for_next_hand_sound_main :
  ∀ (row : CommonRow) (ext : ResetForNextHandMethodColumns)
    (max_players : Nat) (pre_pending_addon : Nat),
    ResetForNextHandAirAcceptable row ext max_players →
    ContractResetForNextHand
      (extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val)
      (extractResetParamsFromAir pre_pending_addon)
      (extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val) :=
  reset_for_next_hand_air_sound

/-! ## addon / rebuy: ✅ AIR soundness（正确提取下成立，需 limb 范围约束）-/

/-- addon AIR soundness 主定理（正确提取下成立；需 limb 范围约束由独立 range constraint 保证） -/
theorem addon_sound_main :
  ∀ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (expected_amount : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    AddonAirAcceptable row ext expected_seat_index expected_amount max_players hlt →
    Limb4Range16 ext.pre_pending_addon →
    Limb4Range16 ext.input_amount →
    ContractAddon
      (extractPreTableFromAddonAir row ext max_players expected_seat_index)
      (extractAddonParamsFromAir ext)
      (extractPostTableFromAddonAir row ext max_players expected_seat_index) :=
  addon_air_sound

/-- rebuy AIR soundness 主定理（正确提取下成立；需 limb 范围约束由独立 range constraint 保证） -/
theorem rebuy_sound_main :
  ∀ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (expected_amount : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    RebuyAirAcceptable row ext expected_seat_index expected_amount max_players hlt →
    Limb4Range16 ext.pre_stack →
    Limb4Range16 ext.input_amount →
    ContractRebuy
      (extractPreTableFromRebuyAir row ext max_players expected_seat_index)
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromRebuyAir row ext max_players expected_seat_index) :=
  rebuy_air_sound

/-! ## 密码学方法（Mental Poker 协议）: ✅ 手写 Lean 模型内 AIR 约束是 sound 的 -/

/-- join_and_shuffle AIR soundness：AIR 约束蕴含合约语义 -/
theorem join_and_shuffle_sound_main :
  ∀ (row : CommonRow) (ext : JoinAndShuffleMethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    JoinAndShuffleAirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt →
    ContractJoinAndShuffle
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractJoinAndShuffleParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) :=
  join_and_shuffle_air_sound

/-- leave_with_proof AIR soundness：AIR 约束蕴含合约语义 -/
theorem leave_with_proof_sound_main :
  ∀ (row : CommonRow) (ext : LeaveWithProofMethodColumns)
    (expected_seat_index : Nat) (expected_leave_kind : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltk : expected_leave_kind < M31_P)
    (hseat : expected_seat_index < max_players),
    LeaveWithProofAirAcceptable row ext expected_seat_index expected_leave_kind max_players hlt hltk →
    ContractLeaveWithProof
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractLeaveWithProofParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) :=
  leave_with_proof_air_sound

/-- submit_shuffle_v2 AIR soundness：AIR 约束蕴含合约语义 -/
theorem submit_shuffle_v2_sound_main :
  ∀ (row : CommonRow) (ext : SubmitShuffleV2MethodColumns)
    (expected_seat_index : Nat) (expected_commit_0 : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitShuffleV2AirAcceptable row ext expected_seat_index expected_commit_0 max_players hlt →
    ContractSubmitShuffleV2
      (extractPreTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0)
      (extractSubmitShuffleV2ParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players ext.input_shuffle_phase.val 0 0) :=
  submit_shuffle_v2_air_sound

/-- submit_player_reveal_tokens AIR soundness：AIR 约束蕴含合约语义 -/
theorem submit_player_reveal_tokens_sound_main :
  ∀ (row : CommonRow) (ext : SubmitRevealTokensMethodColumns)
    (expected_seat_index : Nat) (expected_reveal_phase : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reveal_phase < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitRevealTokensAirAcceptable row ext expected_seat_index expected_reveal_phase max_players hlt hltp →
    ContractSubmitRevealTokens
      (extractPreTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0)
      (extractSubmitRevealTokensParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players 0 ext.input_reveal_phase.val 0) :=
  submit_player_reveal_tokens_air_sound

/-- submit_reconstruct_deck AIR soundness：AIR 约束蕴含合约语义 -/
theorem submit_reconstruct_deck_sound_main :
  ∀ (row : CommonRow) (ext : SubmitReconstructDeckMethodColumns)
    (expected_seat_index : Nat) (expected_reconstruct_state : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hltp : expected_reconstruct_state < M31_P)
    (hseat : expected_seat_index < max_players),
    SubmitReconstructDeckAirAcceptable row ext expected_seat_index expected_reconstruct_state max_players hlt hltp →
    ContractSubmitReconstructDeck
      (extractPreTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val)
      (extractSubmitReconstructDeckParamsFromAir ext)
      (extractPostTableFromCryptoAir row max_players 0 0 ext.input_reconstruct_state.val) :=
  submit_reconstruct_deck_air_sound

/-! ## 结论：selector 0--20 的 21 个模型内定理，不是实现级证明

本文件导出了 selector 0--20 的 21 个 Lean theorem wrapper。Rust/VM 当前还有
selector 21 `request_leave_after_hand` 与 22 `fold_with_proof`，本文件未覆盖。
已有 wrapper 证明的是手写
`*AirAcceptable` 谓词到手写 `Contract*` 谓词的模型内蕴含关系。

这些定理目前**不能**被表述为：

* 真实 Rust AIR 接受必然推出 VM 合约语义；
* state-root/public-input 已与 trace witness 建立端到端等价；
* caller/creator 授权、完整轮次推进、结算与密码学子证明均已覆盖；
* Aggregator 已递归验证全部 method proof。

此外，若干 theorem 仍显式需要 `Limb4Range16`、seat index 范围等额外前提。
当前可信声明、未覆盖 selector/层次以及 21 个底层 theorem 的 `#print axioms` 输出见
`PokerLean.Audit.TrustBoundary`。只有建立 Rust AIR→Lean AIR 与 VM→Lean Contract
的精化桥之后，才能升级为实现级 soundness 结论。
-/

end PokerLean
