import PokerLean.Contract.Types

namespace PokerLean

/-! # 资金方法合约语义（addon, rebuy）

对齐 `poker_l1/src/vm/contracts/texas_poker/state_machine.rs`。
-/

/-! ## addon 合约语义

合约要求（state_machine.rs:2788-2837）：
1. `seat_index < max_players`
2. `amount > 0`
3. `seat.is_occupied()` — 座位必须被占用
4. `seat.pending_addon += amount`
5. `table.addon_pool += amount`（资金守恒）
6. `table.bump_version()` — version += 1
-/

/-- addon 参数 -/
structure AddonParams where
  seat_index : Nat
  amount : Nat
deriving Repr

/-- addon 合约语义 -/
def ContractAddon
    (pre : TexasPokerTable)
    (params : AddonParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件
  params.seat_index < pre.max_players ∧
  params.amount > 0 ∧
  (pre.get_seat params.seat_index).is_occupied = true ∧
  -- 后置状态
  (post.get_seat params.seat_index).pending_addon =
    (pre.get_seat params.seat_index).pending_addon + params.amount ∧
  -- 资金守恒
  post.addon_pool = pre.addon_pool + params.amount ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 其他座位不变
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  -- 不变量
  post.round_state = pre.round_state ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-! ## rebuy 合约语义

合约要求（state_machine.rs:2861-2910）：
1. `seat_index < max_players`
2. `amount > 0`
3. `seat.is_occupied()` — 座位必须被占用
4. `seat.stack += amount`（立即生效）
5. `table.addon_pool += amount`（资金守恒）
6. `table.bump_version()` — version += 1
-/

/-- rebuy 参数 -/
structure RebuyParams where
  seat_index : Nat
  amount : Nat
deriving Repr

/-- rebuy 合约语义 -/
def ContractRebuy
    (pre : TexasPokerTable)
    (params : RebuyParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件
  params.seat_index < pre.max_players ∧
  params.amount > 0 ∧
  (pre.get_seat params.seat_index).is_occupied = true ∧
  -- 后置状态
  (post.get_seat params.seat_index).stack =
    (pre.get_seat params.seat_index).stack + params.amount ∧
  -- 资金守恒
  post.addon_pool = pre.addon_pool + params.amount ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 其他座位不变
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  -- 不变量
  post.round_state = pre.round_state ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-- 推论：addon 要求 amount > 0 -/
theorem addon_amount_pos (pre : TexasPokerTable)
    (params : AddonParams) (post : TexasPokerTable)
    (h : ContractAddon pre params post) :
  params.amount > 0 := by
  rcases h with ⟨_, h_amt, _⟩
  exact h_amt

/-- 推论：rebuy 要求 amount > 0 -/
theorem rebuy_amount_pos (pre : TexasPokerTable)
    (params : RebuyParams) (post : TexasPokerTable)
    (h : ContractRebuy pre params post) :
  params.amount > 0 := by
  rcases h with ⟨_, h_amt, _⟩
  exact h_amt

end PokerLean
