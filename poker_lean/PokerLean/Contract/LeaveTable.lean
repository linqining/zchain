import PokerLean.Contract.Types

namespace PokerLean

/-! # leave_table 合约语义

对齐 `poker_l1/src/vm/contracts/texas_poker/dispatch.rs::dispatch_leave_table`
与 `state_machine::can_leave_state`。

## 合约业务规约（来自 dispatch.rs:849-904）

1. `require_caller_is_seat_player` — caller 是该座位的玩家（AIR 层无法验证）
2. `can_leave_state(table)` — `round_state == ROUND_WAITING`
3. `seat_index < max_players`
4. `seat.is_occupied()` — 座位必须被占用
5. 退款：`refund = seat.stack + seat.pending_addon`
6. 资金守恒：
   - `addon_pool -= pending_addon`
   - `chip_pool -= refund`，其中 `refund = seat.stack + seat.pending_addon`
7. 座位清空：`seat = Seat::empty()`
8. `table.bump_version()` — version += 1
-/

/-- leave_table 参数 -/
structure LeaveTableParams where
  /-- 座位索引 -/
  seat_index : Nat
deriving Repr

/-- leave_table 合约语义：状态转换谓词 -/
def ContractLeaveTable
    (pre : TexasPokerTable)
    (params : LeaveTableParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件
  pre.round_state = RoundState.ROUND_WAITING ∧
  params.seat_index < pre.max_players ∧
  -- 座位必须被占用
  (pre.get_seat params.seat_index).is_occupied = true ∧
  -- 后置状态：座位被清空
  (post.get_seat params.seat_index).player = EMPTY_PLAYER ∧
  (post.get_seat params.seat_index).stack = 0 ∧
  (post.get_seat params.seat_index).bet = 0 ∧
  (post.get_seat params.seat_index).total_bet = 0 ∧
  (post.get_seat params.seat_index).folded = false ∧
  (post.get_seat params.seat_index).all_in = false ∧
  (post.get_seat params.seat_index).is_waiting = false ∧
  (post.get_seat params.seat_index).left_during_hand = false ∧
  (post.get_seat params.seat_index).acted_this_round = false ∧
  -- 其他座位不变
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  -- 资金守恒
  post.chip_pool = pre.chip_pool -
    ((pre.get_seat params.seat_index).stack +
      (pre.get_seat params.seat_index).pending_addon) ∧
  post.addon_pool = pre.addon_pool - (pre.get_seat params.seat_index).pending_addon ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 不变量
  post.round_state = pre.round_state ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-- 推论：leave_table 要求 round_state == WAITING -/
theorem leave_table_pre_waiting (pre : TexasPokerTable)
    (params : LeaveTableParams) (post : TexasPokerTable)
    (h : ContractLeaveTable pre params post) :
  pre.round_state = RoundState.ROUND_WAITING := by
  rcases h with ⟨h_rs, _⟩
  exact h_rs

/-- 推论：leave_table 要求座位被占用 -/
theorem leave_table_pre_seat_occupied (pre : TexasPokerTable)
    (params : LeaveTableParams) (post : TexasPokerTable)
    (h : ContractLeaveTable pre params post) :
  (pre.get_seat params.seat_index).is_occupied = true := by
  rcases h with ⟨_, _, h_occ, _⟩
  exact h_occ

end PokerLean
