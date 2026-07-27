import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.JoinTable
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # join_table AIR 形式化

对齐 `poker_texas_air/src/airs/lifecycle/join_table.rs`。

## AIR 列布局（共 26 业务列）

通用列 37 个 + 业务列：
- `INPUT_SEAT_INDEX`（1）
- `INPUT_BUY_IN`（4 limb）
- `INPUT_PLAYER_ADDR`（4 limb）
- `OUTPUT_SEAT_STACK`（4 limb）
- `INPUT_SEAT_EMPTY`（1）
- `INPUT_BIG_BLIND`（4 limb）— Gap 闭合：buy_in >= big_blind
- `INPUT_PRE_CHIP_POOL`（4 limb）— Gap 闭合：资金守恒
- `OUTPUT_POST_CHIP_POOL`（4 limb）— Gap 闭合：资金守恒

## 闭合的 Gap

- `RoundStateEq(0)` + `RoundStateUnchanged`：仅在 WAITING 状态入座
- `SeatEmpty`：目标座位必须为空
- `BuyInGeBigBlind`：买入金额 ≥ 大盲注
- `ChipPoolConservation`：post_chip_pool = pre_chip_pool + buy_in
- `VersionIncrementConstraint`：version += 1
- post 状态提取：目标座位正确填充 player/stack/folded 等字段
-/

/-- join_table 业务列 -/
structure JoinTableMethodColumns where
  /-- 输入：座位索引 -/
  input_seat_index : M31
  /-- 输入：买入金额（4 limb） -/
  input_buy_in : M31 × M31 × M31 × M31
  /-- 输入：玩家地址（4 limb） -/
  input_player_addr : M31 × M31 × M31 × M31
  /-- 输入：座位占用状态（0 = 空，1 = 占用）- 必须为空 -/
  input_seat_is_occupied : M31
  /-- 输入：大盲注（4 limb）- 用于 buy_in >= big_blind 约束 -/
  input_big_blind : M31 × M31 × M31 × M31
  /-- 输入：pre chip_pool（4 limb）- 用于资金守恒 -/
  input_pre_chip_pool : M31 × M31 × M31 × M31
  /-- 输出：post chip_pool（4 limb）- 用于资金守恒 -/
  output_post_chip_pool : M31 × M31 × M31 × M31
  /-- 输出：座位 stack（4 limb） -/
  output_seat_stack : M31 × M31 × M31 × M31
deriving Repr

/-- 从 AIR 行提取前状态表 -/
def extractPreTableFromJoinTableAir
    (row : CommonRow)
    (ext : JoinTableMethodColumns)
    (max_players : Nat)
    : TexasPokerTable := {
  table_id := 0
  name_hash := 0
  seats := List.replicate max_players Seat.empty
  max_players := max_players
  small_blind := 0
  big_blind := decodeU64 ext.input_big_blind.1 ext.input_big_blind.2.1
      ext.input_big_blind.2.2.1 ext.input_big_blind.2.2.2
  ante := 0
  version := decodeU64 row.pre_version.1 row.pre_version.2.1
      row.pre_version.2.2.1 row.pre_version.2.2.2
  round_state := RoundState.fromNat row.pre_round_state.val
  betting := {
    current_bet := 0
    current_turn := 0
    dealer_seat := row.pre_button.val
    pot := decodeU64 row.pre_pot.1 row.pre_pot.2.1
        row.pre_pot.2.2.1 row.pre_pot.2.2.2
    side_pots := []
    min_raise := 0
    last_aggressor := 0
    num_raises := 0
  }
  shuffle_state := {
    phase := 0
    current_shuffler := none
    pending_players := []
    completed_players := []
  }
  reveal_state := {
    reveal_phase := 0
    num_assignments := 0
  }
  deck_state := DeckState.DeckIdle
  reconstruct_state := ReconstructState.ReconstructIdle
  hand_id := row.hand_id.val
  call_seq := row.call_seq.val
  chip_pool := decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
      ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2
  addon_pool := 0
  pending_addon_total := 0
  pending_rebuy_total := 0
  rake := 0
  table_fee := 0
  is_private := false
  started_at := 0
  timeout := 0
  last_action_time := 0
}

/-- 从 AIR 行提取后状态表 -/
def extractPostTableFromJoinTableAir
    (row : CommonRow)
    (ext : JoinTableMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromJoinTableAir row ext max_players
  let buy_in := decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
      ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2
  let post_chip_pool := decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
      ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2
  let player_addr := decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
      ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2
  let post := { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    chip_pool := post_chip_pool
  }
  -- 将目标座位设置为玩家入座：player = player_addr, stack = buy_in, folded = false 等
  post.update_seat seat_index (fun _ => {
    player := PlayerId.ofNat player_addr
    stack := buy_in
    bet := 0
    total_bet := 0
    folded := false
    all_in := false
    acted_this_round := false
    is_waiting := false
    left_during_hand := false
    pending_addon := 0
    time_bank_ms := 0
  })

/-- 从 AIR 提取 join_table 参数 -/
def extractJoinTableParamsFromAir
    (ext : JoinTableMethodColumns)
    (player : PlayerId)
    : JoinTableParams := {
  seat_index := ext.input_seat_index.val
  buy_in := decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
      ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2
  player := player
}

/-- 从 AIR 提取 join_table 参数（直接从 witness 列解码 player_addr） -/
def extractJoinTableParamsFromAir'
    (ext : JoinTableMethodColumns)
    : JoinTableParams := {
  seat_index := ext.input_seat_index.val
  buy_in := decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
      ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2
  player := PlayerId.ofNat (decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
      ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2)
}

/-- buy_in >= big_blind 约束：买入金额必须 ≥ 大盲注。
    对齐 Rust 合约 `dispatch_join_table` 的 `input.buy_in >= table.big_blind` 前置条件。 -/
def BuyInGeBigBlind (ext : JoinTableMethodColumns) : Prop :=
  decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
      ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2
  ≥
  decodeU64 ext.input_big_blind.1 ext.input_big_blind.2.1
      ext.input_big_blind.2.2.1 ext.input_big_blind.2.2.2

/-- chip_pool 守恒约束：post_chip_pool = pre_chip_pool + buy_in。
    对齐 Rust 合约 `dispatch_join_table` 的 `table.chip_pool += input.buy_in`。 -/
def ChipPoolConservation (ext : JoinTableMethodColumns) : Prop :=
  decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
      ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2
  =
  decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
      ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2
  +
  decodeU64 ext.input_buy_in.1 ext.input_buy_in.2.1
      ext.input_buy_in.2.2.1 ext.input_buy_in.2.2.2

/-- player_addr 非空约束：玩家地址 ≠ 0（即 ≠ EMPTY_PLAYER）。
    对齐 Rust 合约 `dispatch_join_table` 中 `input.player ≠ EMPTY_PLAYER` 的隐含前置条件
    （玩家不能以空 ID 入座，否则 pk 注册检查失效）。 -/
def PlayerAddrNonEmpty (ext : JoinTableMethodColumns) : Prop :=
  decodeU64 ext.input_player_addr.1 ext.input_player_addr.2.1
      ext.input_player_addr.2.2.1 ext.input_player_addr.2.2.2
  ≠ 0

/-- join_table 方法特定约束（对齐 join_table.rs 的 evaluate） -/
def JoinTableMethodConstraints
    (row : CommonRow)
    (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  -- 当 is_active = 1 时：
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧
  RoundStateEq row 0 (by unfold M31_P; omega) ∧
  RoundStateUnchanged row ∧
  -- 约束 1：seat_index == input.seat_index
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  -- 约束 2：目标座位必须为空（join_table 前置条件）
  SeatEmpty ext.input_seat_is_occupied ∧
  -- 约束 3：buy_in >= big_blind
  BuyInGeBigBlind ext ∧
  -- 约束 4：chip_pool 守恒（post = pre + buy_in）
  ChipPoolConservation ext ∧
  -- 约束 5：player_addr 非空（防止以 EMPTY_PLAYER 入座）
  PlayerAddrNonEmpty ext ∧
  -- 状态根一致性
  let pre_table := extractPreTableFromJoinTableAir row ext max_players
  let post_table := extractPostTableFromJoinTableAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

/-- join_table AIR 接受谓词（完整） -/
def JoinTableAirAcceptable
    (row : CommonRow)
    (ext : JoinTableMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.JoinTable ∧
  JoinTableMethodConstraints row ext expected_seat_index max_players hlt ∧
  row.method_kind = ⟨MethodKind.JoinTable.toNat, MethodKind.toNat_lt_M31P MethodKind.JoinTable⟩ ∧
  row.is_active = M31.one

end PokerLean
