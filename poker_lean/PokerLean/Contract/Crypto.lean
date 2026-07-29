import PokerLean.Contract.Types

namespace PokerLean

/-! # 密码学方法合约语义

对齐 `poker_l1/src/vm/contracts/texas_poker/state_machine.rs` 中的 Mental Poker 协议方法。

5 个密码学方法：
- `join_and_shuffle` — 玩家加入并完成首洗牌
- `leave_with_proof` — 玩家带 proof 离场
- `submit_shuffle_v2` — 提交洗牌结果
- `submit_player_reveal_tokens` — 提交揭牌令牌
- `submit_reconstruct_deck` — 提交重构牌组

真实合约还要求精确的阶段、调用者/座位权限、密码学证明有效性以及相应状态更新。
本文件当前只保留粗粒度阶段条件、`version += 1` 和少量字段不变式；
DLEq、ZKShuffle、RevealToken、Reconstruct 验证及完整状态转移不在这些谓词中。
-/

/-! ## join_and_shuffle 合约语义 -/

structure JoinAndShuffleParams where
  seat_index : Nat
  deck_commitment : Nat
deriving Repr

def ContractJoinAndShuffle
    (pre : TexasPokerTable)
    (params : JoinAndShuffleParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件
  params.seat_index < pre.max_players ∧
  pre.shuffle_state.phase > 0 ∧
  -- 后置状态
  post.version = pre.version + 1 ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## leave_with_proof 合约语义 -/

structure LeaveWithProofParams where
  seat_index : Nat
  leave_kind : Nat
deriving Repr

def ContractLeaveWithProof
    (pre : TexasPokerTable)
    (params : LeaveWithProofParams)
    (post : TexasPokerTable)
    : Prop :=
  params.seat_index < pre.max_players ∧
  pre.shuffle_state.phase > 0 ∧
  post.version = pre.version + 1 ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## submit_shuffle_v2 合约语义 -/

structure SubmitShuffleV2Params where
  seat_index : Nat
  deck_commitment : Nat
deriving Repr

def ContractSubmitShuffleV2
    (pre : TexasPokerTable)
    (params : SubmitShuffleV2Params)
    (post : TexasPokerTable)
    : Prop :=
  params.seat_index < pre.max_players ∧
  pre.shuffle_state.phase > 0 ∧
  post.version = pre.version + 1 ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## submit_player_reveal_tokens 合约语义 -/

structure SubmitRevealTokensParams where
  seat_index : Nat
  reveal_phase : Nat
deriving Repr

def ContractSubmitRevealTokens
    (pre : TexasPokerTable)
    (params : SubmitRevealTokensParams)
    (post : TexasPokerTable)
    : Prop :=
  params.seat_index < pre.max_players ∧
  pre.reveal_state.reveal_phase > 0 ∧
  post.version = pre.version + 1 ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## submit_reconstruct_deck 合约语义 -/

structure SubmitReconstructDeckParams where
  seat_index : Nat
  reconstruct_phase : Nat
deriving Repr

def ContractSubmitReconstructDeck
    (pre : TexasPokerTable)
    (params : SubmitReconstructDeckParams)
    (post : TexasPokerTable)
    : Prop :=
  params.seat_index < pre.max_players ∧
  pre.reconstruct_state ≠ ReconstructState.ReconstructIdle ∧
  post.version = pre.version + 1 ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

end PokerLean
