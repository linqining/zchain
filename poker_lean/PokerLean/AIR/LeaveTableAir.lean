import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.LeaveTable
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # leave_table AIR 形式化

对齐 `poker_texas_air/src/airs/lifecycle/leave_table.rs`。

## AIR 列布局

通用列 37 个 + 业务列：
- `INPUT_SEAT_INDEX`（1）
- `OUTPUT_REFUND`（4 limb）
- `INPUT_SEAT_OCCUPIED`（1）
- `INPUT_SEAT_STACK`（4 limb）— Gap 闭合：退款 = stack + pending_addon
- `INPUT_SEAT_PENDING_ADDON`（4 limb）— Gap 闭合：addon_pool 守恒
- `INPUT_PRE_CHIP_POOL`（4 limb）— Gap 闭合：chip_pool 守恒
- `OUTPUT_POST_CHIP_POOL`（4 limb）— Gap 闭合：chip_pool 守恒
- `INPUT_PRE_ADDON_POOL`（4 limb）— Gap 闭合：addon_pool 守恒
- `OUTPUT_POST_ADDON_POOL`（4 limb）— Gap 闭合：addon_pool 守恒

## 闭合的 Gap

- `RoundStateEq(0)` + `RoundStateUnchanged`：仅在 WAITING 状态离座
- `SeatOccupied`：目标座位必须被占用
- `RefundConservation`：refund = seat.stack + seat.pending_addon
- `ChipPoolConservation`：post_chip_pool = pre_chip_pool - seat.stack
- `AddonPoolConservation`：post_addon_pool = pre_addon_pool - seat.pending_addon
- `VersionIncrementConstraint`：version += 1
- post 状态提取：目标座位正确清空
-/

/-- leave_table 业务列 -/
structure LeaveTableMethodColumns where
  /-- 输入：座位索引 -/
  input_seat_index : M31
  /-- 输入：座位占用状态（0 = 空，1 = 占用）- 必须为占用 -/
  input_seat_is_occupied : M31
  /-- 输入：座位 stack（4 limb）- 用于退款计算 -/
  input_seat_stack : M31 × M31 × M31 × M31
  /-- 输入：座位 pending_addon（4 limb）- 用于退款和 addon_pool 守恒 -/
  input_seat_pending_addon : M31 × M31 × M31 × M31
  /-- 输入：pre chip_pool（4 limb）- 用于资金守恒 -/
  input_pre_chip_pool : M31 × M31 × M31 × M31
  /-- 输出：post chip_pool（4 limb）- 用于资金守恒 -/
  output_post_chip_pool : M31 × M31 × M31 × M31
  /-- 输入：pre addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  input_pre_addon_pool : M31 × M31 × M31 × M31
  /-- 输出：post addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  output_post_addon_pool : M31 × M31 × M31 × M31
  /-- 输出：退款金额（4 limb） -/
  output_refund : M31 × M31 × M31 × M31
deriving Repr

/-- 从 AIR 行提取前状态表 -/
def extractPreTableFromLeaveTableAir
    (row : CommonRow)
    (ext : LeaveTableMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let seat_stack := decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
      ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2
  let seat_pending_addon := decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
      ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2
  let base : TexasPokerTable := {
    table_id := 0
    name_hash := 0
    seats := List.replicate max_players Seat.empty
    max_players := max_players
    small_blind := 0
    big_blind := 0
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
    addon_pool := decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
    pending_addon_total := 0
    pending_rebuy_total := 0
    rake := 0
    table_fee := 0
    is_private := false
    started_at := 0
    timeout := 0
    last_action_time := 0
  }
  -- 设置目标座位为已占用，并设置 stack 和 pending_addon
  base.update_seat seat_index (fun _ => {
    player := PlayerId.ofNat 1
    stack := seat_stack
    bet := 0
    total_bet := 0
    folded := false
    all_in := false
    acted_this_round := false
    is_waiting := false
    left_during_hand := false
    pending_addon := seat_pending_addon
    time_bank_ms := 0
  })

/-- 从 AIR 行提取后状态表 -/
def extractPostTableFromLeaveTableAir
    (row : CommonRow)
    (ext : LeaveTableMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromLeaveTableAir row ext max_players seat_index
  let post_chip_pool := decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
      ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2
  let post_addon_pool := decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  let post := { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    chip_pool := post_chip_pool
    addon_pool := post_addon_pool
  }
  -- 离开后目标座位清空
  post.update_seat seat_index (fun _ => Seat.empty)

/-- 从 AIR 提取 leave_table 参数 -/
def extractLeaveTableParamsFromAir
    (ext : LeaveTableMethodColumns)
    : LeaveTableParams := {
  seat_index := ext.input_seat_index.val
}

/-- 退款守恒约束：refund = seat.stack + seat.pending_addon。
    对齐 Rust 合约 `dispatch_leave_table` 的 `refund = seat.stack + seat.pending_addon`。 -/
def RefundConservation (ext : LeaveTableMethodColumns) : Prop :=
  decodeU64 ext.output_refund.1 ext.output_refund.2.1
      ext.output_refund.2.2.1 ext.output_refund.2.2.2
  =
  decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
      ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2
  +
  decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
      ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2

/-- chip_pool 守恒约束：post_chip_pool = pre_chip_pool - seat.stack。
    对齐 Rust 合约 `dispatch_leave_table` 的 `chip_pool -= seat.stack`。 -/
def ChipPoolLeaveConservation (ext : LeaveTableMethodColumns) : Prop :=
  decodeU64 ext.output_post_chip_pool.1 ext.output_post_chip_pool.2.1
      ext.output_post_chip_pool.2.2.1 ext.output_post_chip_pool.2.2.2
  =
  decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
      ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2
  -
  decodeU64 ext.input_seat_stack.1 ext.input_seat_stack.2.1
      ext.input_seat_stack.2.2.1 ext.input_seat_stack.2.2.2

/-- addon_pool 守恒约束：post_addon_pool = pre_addon_pool - seat.pending_addon。
    对齐 Rust 合约 `dispatch_leave_table` 的 `addon_pool -= pending_addon`。 -/
def AddonPoolLeaveConservation (ext : LeaveTableMethodColumns) : Prop :=
  decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  =
  decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  -
  decodeU64 ext.input_seat_pending_addon.1 ext.input_seat_pending_addon.2.1
      ext.input_seat_pending_addon.2.2.1 ext.input_seat_pending_addon.2.2.2

/-- leave_table 方法特定约束 -/
def LeaveTableMethodConstraints
    (row : CommonRow)
    (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧
  RoundStateEq row 0 (by unfold M31_P; omega) ∧
  RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  -- 目标座位必须被占用（leave_table 前置条件）
  SeatOccupied ext.input_seat_is_occupied ∧
  -- 退款守恒：refund = stack + pending_addon
  RefundConservation ext ∧
  -- chip_pool 守恒：post = pre - stack
  ChipPoolLeaveConservation ext ∧
  -- addon_pool 守恒：post = pre - pending_addon
  AddonPoolLeaveConservation ext ∧
  -- 状态根一致性
  let pre_table := extractPreTableFromLeaveTableAir row ext max_players expected_seat_index
  let post_table := extractPostTableFromLeaveTableAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

/-- leave_table AIR 接受谓词 -/
def LeaveTableAirAcceptable
    (row : CommonRow)
    (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.LeaveTable ∧
  LeaveTableMethodConstraints row ext expected_seat_index max_players hlt ∧
  row.method_kind = ⟨MethodKind.LeaveTable.toNat, MethodKind.toNat_lt_M31P MethodKind.LeaveTable⟩ ∧
  row.is_active = M31.one

end PokerLean
