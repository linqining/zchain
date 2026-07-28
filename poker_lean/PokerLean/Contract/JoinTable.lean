import PokerLean.Contract.Types
import PokerLean.State.Constants

namespace PokerLean

open TexasPoker.Constants

/-! # join_table 合约语义

对齐 `poker_l1/src/vm/contracts/texas_poker/dispatch.rs::dispatch_join_table`
与 `state_machine::can_join_state`。

## 合约业务规约（来自 dispatch.rs:780-846）

1. `input.player == context.caller`（caller 授权，AIR 层无法验证）
2. `can_join_state(table)` — `round_state == ROUND_WAITING`
3. `is_pk_registered(&table.seats, &pk)` 为 false（pk 未注册）
4. `input.buy_in >= table.big_blind`
5. **全局上界**：`chip_pool + addon_pool + buy_in <= MAX_TOTAL_BET`（溢出修复）
6. `find_empty_seat()` 自动分配座位（合约不接收 seat_index 参数）
7. 座位字段更新：
   - `seat.player = input.player`
   - `seat.stack = input.buy_in`
   - `seat.is_waiting = false`
   - `seat.folded = false`
   - `seat.left_during_hand = false`
   - `seat.all_in = false`
   - `seat.acted_this_round = false`
   - `seat.bet = 0`
   - `seat.total_bet = 0`
8. `table.chip_pool += input.buy_in`（资金守恒）
9. `table.bump_version()`（version saturating_add(1)）
-/

/-- join_table 参数 -/
structure JoinTableParams where
  /-- 座位索引（AIR 层显式指定，合约层自动分配） -/
  seat_index : Nat
  /-- 买入金额 -/
  buy_in : Nat
  /-- 玩家 ID -/
  player : PlayerId
deriving Repr

/-- join_table 合约语义：状态转换谓词 -/
def ContractJoinTable
    (pre : TexasPokerTable)
    (params : JoinTableParams)
    (post : TexasPokerTable)
    : Prop :=
  -- 前置条件
  pre.round_state = RoundState.ROUND_WAITING ∧
  params.seat_index < pre.max_players ∧
  -- 目标座位必须为空
  (pre.get_seat params.seat_index).player = EMPTY_PLAYER ∧
  -- 买入金额必须 >= 大盲注
  params.buy_in ≥ pre.big_blind ∧
  -- 全局上界检查（对齐合约 apply_join 溢出修复）
  pre.chip_pool + pre.addon_pool + params.buy_in ≤ MAX_TOTAL_BET ∧
  -- pk 不能已注册（简化：玩家不能已在其他座位）
  (∀ i : Nat, i < pre.max_players →
    (pre.get_seat i).player ≠ params.player) ∧
  -- 后置状态：座位被占用
  (post.get_seat params.seat_index).player = params.player ∧
  (post.get_seat params.seat_index).stack = params.buy_in ∧
  (post.get_seat params.seat_index).folded = false ∧
  (post.get_seat params.seat_index).left_during_hand = false ∧
  (post.get_seat params.seat_index).all_in = false ∧
  (post.get_seat params.seat_index).acted_this_round = false ∧
  (post.get_seat params.seat_index).bet = 0 ∧
  (post.get_seat params.seat_index).total_bet = 0 ∧
  -- 其他座位不变
  (∀ i : Nat, i ≠ params.seat_index →
    i < pre.max_players →
    post.get_seat i = pre.get_seat i) ∧
  -- 资金守恒：chip_pool += buy_in
  post.chip_pool = pre.chip_pool + params.buy_in ∧
  -- version 递增
  post.version = pre.version + 1 ∧
  -- 不变量
  post.round_state = pre.round_state ∧
  post.max_players = pre.max_players ∧
  post.big_blind = pre.big_blind ∧
  post.small_blind = pre.small_blind ∧
  post.hand_id = pre.hand_id

/-- 推论：join_table 后目标座位被占用 -/
theorem join_table_post_occupied (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  (post.get_seat params.seat_index).player = params.player := by
  rcases h with ⟨_, _, _, _, _, _, h_player, _⟩
  exact h_player

/-- 推论：join_table 要求 round_state == WAITING -/
theorem join_table_pre_waiting (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  pre.round_state = RoundState.ROUND_WAITING := by
  rcases h with ⟨h_rs, _⟩
  exact h_rs

/-- 推论：join_table 要求 buy_in >= big_blind -/
theorem join_table_buy_in_ge_big_blind (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  params.buy_in ≥ pre.big_blind := by
  rcases h with ⟨_, _, _, h_bi, _⟩
  exact h_bi

/-- 推论：join_table 满足全局上界 -/
theorem join_table_within_bound (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  pre.chip_pool + pre.addon_pool + params.buy_in ≤ MAX_TOTAL_BET := by
  rcases h with ⟨_, _, _, _, h_bound, _⟩
  exact h_bound

/-- 推论：join_table 要求目标座位为空 -/
theorem join_table_pre_seat_empty (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  (pre.get_seat params.seat_index).player = EMPTY_PLAYER := by
  rcases h with ⟨_, _, h_empty, _⟩
  exact h_empty

/-- 推论：join_table 后 chip_pool 增加 buy_in -/
theorem join_table_chip_pool_inc (pre : TexasPokerTable)
    (params : JoinTableParams) (post : TexasPokerTable)
    (h : ContractJoinTable pre params post) :
  post.chip_pool = pre.chip_pool + params.buy_in := by
  rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, h_chip, _⟩
  exact h_chip

end PokerLean
