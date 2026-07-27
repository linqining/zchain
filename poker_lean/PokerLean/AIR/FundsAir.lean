import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Funds
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 资金方法 AIR 形式化（addon, rebuy）

对齐 `poker_texas_air/src/airs/funds/`。
-/

/-! ## 通用提取函数 -/

def extractPreTableFromFundsAir
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

def extractPostTableFromFundsAir
    (row : CommonRow)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromFundsAir row max_players seat_index
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
  }

/-! ## addon AIR

AIR 约束（addon.rs:104-138）：
1. `seat_index == input.seat_index`
2. `amount_0 == input.amount` (limb 0)
3. `post_pending_0 == pre_pending_0 + input_amount_0` (limb 0)

**缺失的关键约束**：
- 无 `amount > 0` 校验
- 无 `seat.is_occupied()` 检查
- 无 `addon_pool += amount` 校验（资金守恒）
- 无 version 递增校验
- 仅校验 limb 0，非完整 4-limb
-/

structure AddonMethodColumns where
  input_seat_index : M31
  input_seat_is_occupied : M31
  input_amount : M31 × M31 × M31 × M31
  pre_pending_addon : M31 × M31 × M31 × M31
  post_pending_addon : M31 × M31 × M31 × M31
deriving Repr

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
  -- 目标座位必须被占用（addon 前置条件）
  SeatOccupied ext.input_seat_is_occupied ∧
  ext.post_pending_addon.1 = M31.add ext.pre_pending_addon.1 ext.input_amount.1 ∧
  let pre_table := extractPreTableFromFundsAir row max_players expected_seat_index
  let post_table := extractPostTableFromFundsAir row max_players expected_seat_index
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

/-! ## rebuy AIR

AIR 约束（rebuy.rs:102-133）：
1. `seat_index == input.seat_index`
2. `amount_0 == input.amount` (limb 0)
3. `post_stack_0 == pre_stack_0 + input_amount_0` (limb 0)

**缺失的关键约束**：
- 无 `amount > 0` 校验
- 无 `seat.is_occupied()` 检查
- 无 `addon_pool += amount` 校验（资金守恒）
- 无 version 递增校验
- 仅校验 limb 0，非完整 4-limb
-/

structure RebuyMethodColumns where
  input_seat_index : M31
  input_seat_is_occupied : M31
  input_amount : M31 × M31 × M31 × M31
  pre_stack : M31 × M31 × M31 × M31
  post_stack : M31 × M31 × M31 × M31
deriving Repr

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
  -- 目标座位必须被占用（rebuy 前置条件）
  SeatOccupied ext.input_seat_is_occupied ∧
  ext.post_stack.1 = M31.add ext.pre_stack.1 ext.input_amount.1 ∧
  let pre_table := extractPreTableFromFundsAir row max_players expected_seat_index
  let post_table := extractPostTableFromFundsAir row max_players expected_seat_index
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
