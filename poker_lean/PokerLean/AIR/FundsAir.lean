import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Funds
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 资金方法 AIR 形式化（addon, rebuy）

对齐 `poker_texas_air/src/airs/funds/`。

## 闭合的 Gap

- `AmountPositive`：金额 > 0
- `SeatOccupied`：座位必须被占用
- `AddonPoolFundsConservation`：post_addon_pool = pre_addon_pool + amount
- `VersionIncrementConstraint`：version += 1
- `RoundStateUnchanged`：round_state 不变
- post 状态提取：正确更新 seat.pending_addon / seat.stack 和 addon_pool
-/

/-! ## 通用提取函数（内部辅助） -/
/-- 通用 pre 表提取（不带 ext，作为内部辅助函数）。
    将 `seat_index` 位置的座位标记为 occupied（player := 1），其余座位保持 empty。 -/
def extractPreTableFromFundsAir
    (row : CommonRow)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let tbl : TexasPokerTable := {
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
  tbl.update_seat seat_index (fun _ => { Seat.empty with player := PlayerId.ofNat 1 })

/-- 向后兼容别名：原 `extractPreTableFromFundsAirBase` 现已合并为 `extractPreTableFromFundsAir` -/
def extractPreTableFromFundsAirBase
    (row : CommonRow) (max_players : Nat) (seat_index : Nat) : TexasPokerTable :=
  extractPreTableFromFundsAir row max_players seat_index

/-! ## addon AIR -/

/-- addon 业务列 -/
structure AddonMethodColumns where
  input_seat_index : M31
  input_seat_is_occupied : M31
  input_amount : M31 × M31 × M31 × M31
  pre_pending_addon : M31 × M31 × M31 × M31
  post_pending_addon : M31 × M31 × M31 × M31
  /-- 输入：pre addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  input_pre_addon_pool : M31 × M31 × M31 × M31
  /-- 输出：post addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  output_post_addon_pool : M31 × M31 × M31 × M31
deriving Repr

/-- addon_pool 守恒约束：post_addon_pool = pre_addon_pool + amount。
    对齐 Rust 合约 `dispatch_addon` 的 `addon_pool += amount`。 -/
def AddonPoolFundsConservation (ext : AddonMethodColumns) : Prop :=
  decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  =
  decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  +
  decodeU64 ext.input_amount.1 ext.input_amount.2.1
      ext.input_amount.2.2.1 ext.input_amount.2.2.2

/-- 从 AIR 行提取 addon pre 状态表 -/
def extractPreTableFromAddonAir
    (row : CommonRow)
    (ext : AddonMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre_addon_pool := decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  let seat_pending_addon := decodeU64 ext.pre_pending_addon.1 ext.pre_pending_addon.2.1
      ext.pre_pending_addon.2.2.1 ext.pre_pending_addon.2.2.2
  let base := extractPreTableFromFundsAir row max_players seat_index
  let updated : TexasPokerTable := { base with addon_pool := pre_addon_pool }
  updated.update_seat seat_index (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    pending_addon := seat_pending_addon })

/-- 从 AIR 行提取 addon post 状态表 -/
def extractPostTableFromAddonAir
    (row : CommonRow)
    (ext : AddonMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromAddonAir row ext max_players seat_index
  let post_addon_pool := decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  let post_pending_addon := decodeU64 ext.post_pending_addon.1 ext.post_pending_addon.2.1
      ext.post_pending_addon.2.2.1 ext.post_pending_addon.2.2.2
  let updated : TexasPokerTable := { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    addon_pool := post_addon_pool
  }
  updated.update_seat seat_index (fun s => { s with pending_addon := post_pending_addon })

def AddonMethodConstraints
    (row : CommonRow)
    (ext : AddonMethodColumns)
    (expected_seat_index : Nat)
    (expected_amount : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_amount.1 = ⟨expected_amount % 65536, by unfold M31_P; omega⟩ ∧
  AmountPositive ext.input_amount.1 ext.input_amount.2.1 ext.input_amount.2.2.1 ext.input_amount.2.2.2 ∧
  SeatOccupied ext.input_seat_is_occupied ∧
  -- pending_addon 守恒：post = pre + amount（逐 limb）
  ext.post_pending_addon.1 = M31.add ext.pre_pending_addon.1 ext.input_amount.1 ∧
  ext.post_pending_addon.2.1 = M31.add ext.pre_pending_addon.2.1 ext.input_amount.2.1 ∧
  ext.post_pending_addon.2.2.1 = M31.add ext.pre_pending_addon.2.2.1 ext.input_amount.2.2.1 ∧
  ext.post_pending_addon.2.2.2 = M31.add ext.pre_pending_addon.2.2.2 ext.input_amount.2.2.2 ∧
  -- addon_pool 守恒：post = pre + amount
  AddonPoolFundsConservation ext ∧
  let pre_table := extractPreTableFromAddonAir row ext max_players expected_seat_index
  let post_table := extractPostTableFromAddonAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def AddonAirAcceptable
    (row : CommonRow)
    (ext : AddonMethodColumns)
    (expected_seat_index : Nat)
    (expected_amount : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.Addon ∧
  AddonMethodConstraints row ext expected_seat_index expected_amount max_players hlt ∧
  row.method_kind = ⟨MethodKind.Addon.toNat, MethodKind.toNat_lt_M31P MethodKind.Addon⟩ ∧
  row.is_active = M31.one

/-! ## rebuy AIR -/

/-- rebuy 业务列 -/
structure RebuyMethodColumns where
  input_seat_index : M31
  input_seat_is_occupied : M31
  input_amount : M31 × M31 × M31 × M31
  pre_stack : M31 × M31 × M31 × M31
  post_stack : M31 × M31 × M31 × M31
  /-- 输入：pre addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  input_pre_addon_pool : M31 × M31 × M31 × M31
  /-- 输出：post addon_pool（4 limb）- 用于 addon_pool 守恒 -/
  output_post_addon_pool : M31 × M31 × M31 × M31
deriving Repr

/-- rebuy 的 addon_pool 守恒约束：post_addon_pool = pre_addon_pool + amount。 -/
def RebuyAddonPoolConservation (ext : RebuyMethodColumns) : Prop :=
  decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  =
  decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  +
  decodeU64 ext.input_amount.1 ext.input_amount.2.1
      ext.input_amount.2.2.1 ext.input_amount.2.2.2

/-- 从 AIR 行提取 rebuy pre 状态表 -/
def extractPreTableFromRebuyAir
    (row : CommonRow)
    (ext : RebuyMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre_addon_pool := decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  let seat_stack := decodeU64 ext.pre_stack.1 ext.pre_stack.2.1
      ext.pre_stack.2.2.1 ext.pre_stack.2.2.2
  let base := extractPreTableFromFundsAir row max_players seat_index
  let updated : TexasPokerTable := { base with addon_pool := pre_addon_pool }
  updated.update_seat seat_index (fun _ => { Seat.empty with
    player := PlayerId.ofNat 1
    stack := seat_stack })

/-- 从 AIR 行提取 rebuy post 状态表 -/
def extractPostTableFromRebuyAir
    (row : CommonRow)
    (ext : RebuyMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromRebuyAir row ext max_players seat_index
  let post_addon_pool := decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
      ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2
  let post_stack := decodeU64 ext.post_stack.1 ext.post_stack.2.1
      ext.post_stack.2.2.1 ext.post_stack.2.2.2
  let updated : TexasPokerTable := { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    addon_pool := post_addon_pool
  }
  updated.update_seat seat_index (fun s => { s with stack := post_stack })

def RebuyMethodConstraints
    (row : CommonRow)
    (ext : RebuyMethodColumns)
    (expected_seat_index : Nat)
    (expected_amount : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateUnchanged row ∧
  ext.input_seat_index = nat_to_m31 expected_seat_index hlt ∧
  ext.input_amount.1 = ⟨expected_amount % 65536, by unfold M31_P; omega⟩ ∧
  AmountPositive ext.input_amount.1 ext.input_amount.2.1 ext.input_amount.2.2.1 ext.input_amount.2.2.2 ∧
  SeatOccupied ext.input_seat_is_occupied ∧
  -- stack 守恒：post = pre + amount（逐 limb）
  ext.post_stack.1 = M31.add ext.pre_stack.1 ext.input_amount.1 ∧
  ext.post_stack.2.1 = M31.add ext.pre_stack.2.1 ext.input_amount.2.1 ∧
  ext.post_stack.2.2.1 = M31.add ext.pre_stack.2.2.1 ext.input_amount.2.2.1 ∧
  ext.post_stack.2.2.2 = M31.add ext.pre_stack.2.2.2 ext.input_amount.2.2.2 ∧
  -- addon_pool 守恒：post = pre + amount
  RebuyAddonPoolConservation ext ∧
  let pre_table := extractPreTableFromRebuyAir row ext max_players expected_seat_index
  let post_table := extractPostTableFromRebuyAir row ext max_players expected_seat_index
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def RebuyAirAcceptable
    (row : CommonRow)
    (ext : RebuyMethodColumns)
    (expected_seat_index : Nat)
    (expected_amount : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.Rebuy ∧
  RebuyMethodConstraints row ext expected_seat_index expected_amount max_players hlt ∧
  row.method_kind = ⟨MethodKind.Rebuy.toNat, MethodKind.toNat_lt_M31P MethodKind.Rebuy⟩ ∧
  row.is_active = M31.one

def extractAddonParamsFromAir (ext : AddonMethodColumns) : AddonParams := {
  seat_index := ext.input_seat_index.val
  amount := decodeU64 ext.input_amount.1 ext.input_amount.2.1
      ext.input_amount.2.2.1 ext.input_amount.2.2.2
}

def extractRebuyParamsFromAir (ext : RebuyMethodColumns) : RebuyParams := {
  seat_index := ext.input_seat_index.val
  amount := decodeU64 ext.input_amount.1 ext.input_amount.2.1
      ext.input_amount.2.2.1 ext.input_amount.2.2.2
}

end PokerLean
