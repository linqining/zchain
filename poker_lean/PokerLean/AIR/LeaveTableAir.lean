import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.LeaveTable
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # leave_table AIR 形式化

对齐 `poker_texas_air/src/airs/lifecycle/leave_table.rs`。

## AIR 列布局（共 42 列）

通用列 37 个 + 业务列 5 个：
- `INPUT_SEAT_INDEX`（1）
- `OUTPUT_REFUND`（4 limb）

## AIR 约束（来自 leave_table.rs:73-87）

约束 1：`is_active * (input_seat_index - expected_seat_index) = 0`
  — 仅校验 seat_index 与公开输入一致

**缺失的关键约束**：
- 无 round_state gating（不校验 round_state == WAITING）
- 无座位占用检查（允许 leave 一个空座位）
- 无退款金额校验
- 无 chip_pool/addon_pool 更新校验（资金守恒）
- 无 version 递增校验
-/

/-- leave_table 业务列 -/
structure LeaveTableMethodColumns where
  /-- 输入：座位索引 -/
  input_seat_index : M31
  /-- 输入：座位占用状态（0 = 空，1 = 占用）- 必须为占用 -/
  input_seat_is_occupied : M31
  /-- 输出：退款金额（4 limb） -/
  output_refund : M31 × M31 × M31 × M31
deriving Repr

/-- 从 AIR 行提取前状态表 -/
def extractPreTableFromLeaveTableAir
    (row : CommonRow)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
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
  chip_pool := 0
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
  -- 设置目标座位为已占用
  base.update_seat seat_index (fun _ => { Seat.empty with player := PlayerId.ofNat 1 })

/-- 从 AIR 行提取后状态表 -/
def extractPostTableFromLeaveTableAir
    (row : CommonRow)
    (_ext : LeaveTableMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromLeaveTableAir row max_players seat_index
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    -- 离开后目标座位清空
    seats := List.modify (fun _ => Seat.empty) seat_index pre.seats
  }

/-- 从 AIR 提取 leave_table 参数 -/
def extractLeaveTableParamsFromAir
    (ext : LeaveTableMethodColumns)
    : LeaveTableParams := {
  seat_index := ext.input_seat_index.val
}

/-- leave_table 方法特定约束 -/
def LeaveTableMethodConstraints
    (row : CommonRow)
    (ext : LeaveTableMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateEq row 0 (by unfold M31_P; omega) ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  -- 目标座位必须被占用（leave_table 前置条件）
  SeatOccupied ext.input_seat_is_occupied ∧
  let pre_table := extractPreTableFromLeaveTableAir row max_players expected_seat_index
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