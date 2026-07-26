import PokerLean.Contract.Types

namespace PokerLean

/-! # 生命周期方法合约语义（start_hand, tick, reset_for_next_hand）

对齐 `poker_l1/src/vm/contracts/texas_poker/state_machine.rs`。
-/

/-! ## start_hand 合约语义

合约要求（state_machine.rs:1995-2036）：
1. `round_state == ROUND_WAITING`
2. `count_active_occupied(seats) >= MIN_PLAYERS_TO_START`（= 2）
3. caller 是 creator
4. 状态变更：move_button, set_initial_encrypted_deck, shuffle_state.phase = BEFORE_PREFLOP
5. version += 1
-/

/-- start_hand 参数 -/
structure StartHandParams where
  active_count : Nat
  ante_mode : Nat
  ante_amount : Nat
  ante_collected : Nat
deriving Repr

/-- MIN_PLAYERS_TO_START 常量 -/
def MIN_PLAYERS_TO_START : Nat := 2

/-- start_hand 合约语义 -/
def ContractStartHand
    (pre : TexasPokerTable)
    (params : StartHandParams)
    (post : TexasPokerTable)
    : Prop :=
  pre.round_state = RoundState.ROUND_WAITING ∧
  -- 活跃玩家数 >= 2
  params.active_count ≥ MIN_PLAYERS_TO_START ∧
  -- active_count 必须与实际座位一致（简化模型）
  params.active_count = pre.seats.foldl (fun acc s => acc + if s.is_occupied then 1 else 0) 0 ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- round_state 保持 WAITING（start_hand 后进入 shuffle，由 shuffle_state.phase 表达）
  post.round_state = pre.round_state ∧
  -- shuffle_state 进入 BEFORE_PREFLOP
  post.shuffle_state.phase = 3 ∧
  -- 不变量
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## tick 合约语义

合约要求（state_machine.rs:2042+）：
tick 是 permissionless 超时驱动，复杂度高（reconstruct > shuffle > reveal > normal > fallback）。
关键约束：
1. 必须有真实的超时条件（某个玩家/阶段超时）
2. 状态变更符合超时逻辑
3. version += 1
-/

/-- tick 参数 -/
structure TickParams where
  now_ms : Nat
  timeout_kind : Nat
  time_bank_consumed : Nat
  time_bank_post : Nat
  rake_mode : Nat
  rake_amount : Nat
deriving Repr

/-- tick 合约语义（简化模型：必须有超时条件且 version 递增） -/
def ContractTick
    (pre : TexasPokerTable)
    (params : TickParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 必须有真实的超时（timeout_kind > 0 表示触发了某种超时处理）
  params.timeout_kind > 0 ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 不变量
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## reset_for_next_hand 合约语义

合约要求：
1. reset 到 WAITING 状态
2. pending_addon 必须合并到 stack（post pending_addon = 0）
3. version += 1
-/

/-- reset_for_next_hand 参数 -/
structure ResetForNextHandParams where
  pre_pending_addon : Nat
deriving Repr

/-- reset_for_next_hand 合约语义 -/
def ContractResetForNextHand
    (pre : TexasPokerTable)
    (params : ResetForNextHandParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件：必须在牌局结束后调用（round_state 不是 WAITING 或 shuffle 已开始）
  -- 简化：仅要求 shuffle_state.phase > 0（表示已在牌局流程中）
  pre.shuffle_state.phase > 0 ∧
  -- 后置：round_state = WAITING
  post.round_state = RoundState.ROUND_WAITING ∧
  -- pending_addon 必须清零（已合并到 stack）
  (∀ i : Nat, i < pre.max_players →
    (post.get_seat i).pending_addon = 0) ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 不变量
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-- 推论：start_hand 要求 round_state == WAITING -/
theorem start_hand_pre_waiting (pre : TexasPokerTable)
    (params : StartHandParams) (post : TexasPokerTable)
    (h : ContractStartHand pre params post) :
  pre.round_state = RoundState.ROUND_WAITING := by
  rcases h with ⟨h_rs, _⟩
  exact h_rs

/-- 推论：start_hand 要求 active_count >= 2 -/
theorem start_hand_active_count_ge_2 (pre : TexasPokerTable)
    (params : StartHandParams) (post : TexasPokerTable)
    (h : ContractStartHand pre params post) :
  params.active_count ≥ MIN_PLAYERS_TO_START := by
  rcases h with ⟨_, h_count, _⟩
  exact h_count

/-- 推论：reset_for_next_hand 后 round_state == WAITING -/
theorem reset_post_waiting (pre : TexasPokerTable)
    (params : ResetForNextHandParams) (post : TexasPokerTable)
    (h : ContractResetForNextHand pre params post) :
  post.round_state = RoundState.ROUND_WAITING := by
  rcases h with ⟨_, h_rs, _⟩
  exact h_rs

end PokerLean
