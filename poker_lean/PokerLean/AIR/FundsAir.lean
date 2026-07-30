import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Funds
import PokerLean.AIR.AirBase
import PokerLean.State.Constants

namespace PokerLean

open TexasPoker.Constants

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
  /-- 输入：pre chip_pool（4 limb）- 用于全局上界检查（对齐 Rust AIR PRE_CHIP_POOL witness） -/
  input_pre_chip_pool : M31 × M31 × M31 × M31
  /-- BOUND_DIFF（4 limb）- diff = MAX_TOTAL_BET - (chip_pool + addon_pool + amount) -/
  input_bound_diff : M31 × M31 × M31 × M31
  /-- BOUND_CARRY_LO（3 个低位 bit）- 2-bit carry 分解的 lo 部分 -/
  input_bound_carry_lo : M31 × M31 × M31
  /-- BOUND_CARRY_HI（3 个高位 bit）- 2-bit carry 分解的 hi 部分 -/
  input_bound_carry_hi : M31 × M31 × M31
  /-- pending_addon += amount 的 3 个 ripple-carry bit。 -/
  pending_add_carry : M31 × M31 × M31
  /-- addon_pool += amount 的 3 个 ripple-carry bit。 -/
  addon_pool_add_carry : M31 × M31 × M31
deriving Repr

/-- addon_pool 守恒约束，使用与 Rust AIR 相同的 ripple-carry chain。 -/
def AddonPoolFundsConservation (ext : AddonMethodColumns) : Prop :=
  Limb4Delta ext.input_pre_addon_pool ext.output_post_addon_pool ext.input_amount
    ext.addon_pool_add_carry

/-- 全局上界检查约束：within_bound == 1。
    对齐合约 `if chip_pool + addon_pool + amount > MAX_TOTAL_BET { return Err }`。
    对齐 Rust AIR `CommonConstraints::within_bound_check`。

    注：这是保留的旧弱谓词。完整版本见下方 `BoundCheck4Limb` 及
    `FundsSoundness.lean` 的模型内证明；这里不应被单独解释为完整上界验证。 -/
def WithinBoundConstraint (within_bound : M31) : Prop :=
  within_bound = M31.one

/-! ## 全局上界 range check（阶段 3：替代 WithinBoundConstraint 的完整实现）

对齐 Rust AIR `CommonConstraints::bound_check_4limb`。

验证 `chip_pool + addon_pool + amount + diff = MAX_TOTAL_BET`（逐 limb + 2-bit carry），
其中 `diff = MAX_TOTAL_BET - (chip_pool + addon_pool + amount) ≥ 0`。

由于每 limb < 65536 且 carry ∈ {0,1,2,3}，4 数 limb 之和 < 4×65536 = 262144
< M31_P = 2^31−1，M31 运算无取模，limb 方程等价于 Nat 方程。
配合 `Limb4Range16` range constraint（diff 全 limb < 65536）可推出
`decodeU64(cp) + decodeU64(ap) + decodeU64(am) ≤ MAX_TOTAL_BET`。
-/

/-- MAX_TOTAL_BET 的 4-limb 分解（每 limb 16 bit）。 -/
def max_total_bet_limbs : Nat × Nat × Nat × Nat :=
  (MAX_TOTAL_BET % 65536,
   (MAX_TOTAL_BET / 65536) % 65536,
   (MAX_TOTAL_BET / (65536 * 65536)) % 65536,
   (MAX_TOTAL_BET / (65536 * 65536 * 65536)) % 65536)

/-- 3 个 M31 值均为 boolean（0 或 1）的谓词。 -/
def Boolean3 (b : M31 × M31 × M31) : Prop :=
  match b with
  | (x, y, z) =>
    (x = M31.zero ∨ x = M31.one) ∧
    (y = M31.zero ∨ y = M31.one) ∧
    (z = M31.zero ∨ z = M31.one)

/-- 全局上界 range check 约束：`cp + ap + am + df = MAX_TOTAL_BET`（逐 limb + 2-bit carry）。

    carry 分解为 `lo + 2*hi`，lo/hi 为 boolean（由 `Boolean3` 约束）。
    limb 方程以 Nat 表达（M31 运算在小值下无取模，等价于 Nat 方程）。

    对齐 Rust AIR `CommonConstraints::bound_check_4limb`。 -/
def BoundCheck4Limb
    (cp ap am df : M31 × M31 × M31 × M31)
    (carry_lo carry_hi : M31 × M31 × M31) : Prop :=
  match carry_lo, carry_hi with
  | (lo0, lo1, lo2), (hi0, hi1, hi2) =>
    Boolean3 carry_lo ∧ Boolean3 carry_hi ∧
    cp.1.val + ap.1.val + am.1.val + df.1.val = max_total_bet_limbs.1 + (lo0.val + 2 * hi0.val) * 65536 ∧
    cp.2.1.val + ap.2.1.val + am.2.1.val + df.2.1.val + (lo0.val + 2 * hi0.val) =
      max_total_bet_limbs.2.1 + (lo1.val + 2 * hi1.val) * 65536 ∧
    cp.2.2.1.val + ap.2.2.1.val + am.2.2.1.val + df.2.2.1.val + (lo1.val + 2 * hi1.val) =
      max_total_bet_limbs.2.2.1 + (lo2.val + 2 * hi2.val) * 65536 ∧
    cp.2.2.2.val + ap.2.2.2.val + am.2.2.2.val + df.2.2.2.val + (lo2.val + 2 * hi2.val) =
      max_total_bet_limbs.2.2.2

/-- 从 AIR 行提取 addon pre 状态表 -/
def extractPreTableFromAddonAir
    (row : CommonRow)
    (ext : AddonMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre_addon_pool := decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  let pre_chip_pool := decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
      ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2
  let seat_pending_addon := decodeU64 ext.pre_pending_addon.1 ext.pre_pending_addon.2.1
      ext.pre_pending_addon.2.2.1 ext.pre_pending_addon.2.2.2
  let base := extractPreTableFromFundsAir row max_players seat_index
  let updated : TexasPokerTable := { base with
    addon_pool := pre_addon_pool
    chip_pool := pre_chip_pool }
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
  -- pending_addon 守恒：规范 u64 ripple-carry 加法
  Limb4Delta ext.pre_pending_addon ext.post_pending_addon ext.input_amount
    ext.pending_add_carry ∧
  -- addon_pool 守恒：post = pre + amount
  AddonPoolFundsConservation ext ∧
  -- 全局上界 range check（对齐合约溢出修复 + Rust AIR bound_check_4limb）
  BoundCheck4Limb ext.input_pre_chip_pool ext.input_pre_addon_pool
    ext.input_amount ext.input_bound_diff
    ext.input_bound_carry_lo ext.input_bound_carry_hi ∧
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
  /-- 输入：pre chip_pool（4 limb）- 用于全局上界检查（对齐 Rust AIR PRE_CHIP_POOL witness） -/
  input_pre_chip_pool : M31 × M31 × M31 × M31
  /-- BOUND_DIFF（4 limb）- diff = MAX_TOTAL_BET - (chip_pool + addon_pool + amount) -/
  input_bound_diff : M31 × M31 × M31 × M31
  /-- BOUND_CARRY_LO（3 个低位 bit）- 2-bit carry 分解的 lo 部分 -/
  input_bound_carry_lo : M31 × M31 × M31
  /-- BOUND_CARRY_HI（3 个高位 bit）- 2-bit carry 分解的 hi 部分 -/
  input_bound_carry_hi : M31 × M31 × M31
  /-- stack += amount 的 3 个 ripple-carry bit。 -/
  stack_add_carry : M31 × M31 × M31
  /-- addon_pool += amount 的 3 个 ripple-carry bit。 -/
  addon_pool_add_carry : M31 × M31 × M31
deriving Repr

/-- rebuy 的 addon_pool 守恒约束，使用规范 ripple-carry 加法。 -/
def RebuyAddonPoolConservation (ext : RebuyMethodColumns) : Prop :=
  Limb4Delta ext.input_pre_addon_pool ext.output_post_addon_pool ext.input_amount
    ext.addon_pool_add_carry

/-- 从 AIR 行提取 rebuy pre 状态表 -/
def extractPreTableFromRebuyAir
    (row : CommonRow)
    (ext : RebuyMethodColumns)
    (max_players : Nat)
    (seat_index : Nat)
    : TexasPokerTable :=
  let pre_addon_pool := decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
      ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2
  let pre_chip_pool := decodeU64 ext.input_pre_chip_pool.1 ext.input_pre_chip_pool.2.1
      ext.input_pre_chip_pool.2.2.1 ext.input_pre_chip_pool.2.2.2
  let seat_stack := decodeU64 ext.pre_stack.1 ext.pre_stack.2.1
      ext.pre_stack.2.2.1 ext.pre_stack.2.2.2
  let base := extractPreTableFromFundsAir row max_players seat_index
  let updated : TexasPokerTable := { base with
    addon_pool := pre_addon_pool
    chip_pool := pre_chip_pool }
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
  -- stack 守恒：规范 u64 ripple-carry 加法
  Limb4Delta ext.pre_stack ext.post_stack ext.input_amount ext.stack_add_carry ∧
  -- addon_pool 守恒：post = pre + amount
  RebuyAddonPoolConservation ext ∧
  -- 全局上界 range check（对齐合约溢出修复 + Rust AIR bound_check_4limb）
  BoundCheck4Limb ext.input_pre_chip_pool ext.input_pre_addon_pool
    ext.input_amount ext.input_bound_diff
    ext.input_bound_carry_lo ext.input_bound_carry_hi ∧
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

/-! ## bound_check_4limb 关键引理

从 `BoundCheck4Limb` 的逐 limb 方程 + 2-bit carry 分解推出 u64 级别的等式
`decodeU64(cp) + decodeU64(ap) + decodeU64(am) + decodeU64(df) = decodeU64(max_total_bet_limbs)`。

证明思路：将 4 个 limb 方程分别乘以 65536^i (i=0,1,2,3) 后求和，
carry 项 `c_i * 65536^{i+1}` 在相邻 limb 间对消，留下纯 u64 等式。
-/

/-- `max_total_bet_limbs` 的 4-limb 重建等于 `MAX_TOTAL_BET`。
    由 `MAX_TOTAL_BET = 10^18 < 2^64 = 65536^4` 保证 4-limb 分解无损。 -/
lemma max_total_bet_limbs_correct :
    max_total_bet_limbs.1 + max_total_bet_limbs.2.1 * 65536 +
    max_total_bet_limbs.2.2.1 * (65536 * 65536) +
    max_total_bet_limbs.2.2.2 * (65536 * 65536 * 65536) = MAX_TOTAL_BET := by
  unfold max_total_bet_limbs MAX_TOTAL_BET
  norm_num

/-- 从 `BoundCheck4Limb` 推出 4 个 u64 之和等于 `MAX_TOTAL_BET`。
    核心：逐 limb 方程乘以 65536^i 后求和，carry 项对消。 -/
lemma bound_check_4limb_sum (cp ap am df : M31 × M31 × M31 × M31)
    (carry_lo carry_hi : M31 × M31 × M31)
    (h : BoundCheck4Limb cp ap am df carry_lo carry_hi) :
    decodeU64 cp.1 cp.2.1 cp.2.2.1 cp.2.2.2 +
    decodeU64 ap.1 ap.2.1 ap.2.2.1 ap.2.2.2 +
    decodeU64 am.1 am.2.1 am.2.2.1 am.2.2.2 +
    decodeU64 df.1 df.2.1 df.2.2.1 df.2.2.2 =
    max_total_bet_limbs.1 + max_total_bet_limbs.2.1 * 65536 +
    max_total_bet_limbs.2.2.1 * (65536 * 65536) +
    max_total_bet_limbs.2.2.2 * (65536 * 65536 * 65536) := by
  -- 解构 carry 元组，使 BoundCheck4Limb 中的 match 归约
  rcases carry_lo with ⟨lo0, lo1, lo2⟩
  rcases carry_hi with ⟨hi0, hi1, hi2⟩
  -- unfold 归约 match（不计算 max_total_bet_limbs 的具体值）
  unfold BoundCheck4Limb at h
  -- 提取 4 个 limb 方程（跳过 2 个 Boolean3 约束）
  rcases h with ⟨_, _, heq0, heq1, heq2, heq3⟩
  -- 逐 limb 方程乘以 65536^i 后求和，carry 项对消
  unfold decodeU64
  linear_combination
    heq0 * 1 +
    heq1 * 65536 +
    heq2 * (65536 * 65536) +
    heq3 * (65536 * 65536 * 65536)

/-- 从 `BoundCheck4Limb` 推出 `decodeU64(cp) + decodeU64(ap) + decodeU64(am) ≤ MAX_TOTAL_BET`。
    由 `bound_check_4limb_sum` + `decodeU64(df) ≥ 0` 推出。 -/
lemma bound_check_4limb_le (cp ap am df : M31 × M31 × M31 × M31)
    (carry_lo carry_hi : M31 × M31 × M31)
    (h : BoundCheck4Limb cp ap am df carry_lo carry_hi) :
    decodeU64 cp.1 cp.2.1 cp.2.2.1 cp.2.2.2 +
    decodeU64 ap.1 ap.2.1 ap.2.2.1 ap.2.2.2 +
    decodeU64 am.1 am.2.1 am.2.2.1 am.2.2.2 ≤ MAX_TOTAL_BET := by
  have h_sum := bound_check_4limb_sum cp ap am df carry_lo carry_hi h
  rw [max_total_bet_limbs_correct] at h_sum
  -- h_sum: decodeU64(cp) + ... + decodeU64(df) = MAX_TOTAL_BET
  -- Goal: decodeU64(cp) + ... + decodeU64(am) ≤ MAX_TOTAL_BET
  -- 由 decodeU64(df) ≥ 0（Nat 自带非负性）+ omega 推出
  omega

end PokerLean
