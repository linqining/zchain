import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Lifecycle
import PokerLean.AIR.AirBase

namespace PokerLean

/-! # 生命周期方法 AIR 形式化（start_hand, tick, reset_for_next_hand）

对齐 `poker_texas_air/src/airs/lifecycle/`。
-/

/-! ## 通用提取函数（三种方法共享） -/

def extractPreTableFromLifecycleAir
    (row : CommonRow)
    (max_players : Nat)
    (shuffle_phase : Nat)
    : TexasPokerTable := {
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
    phase := shuffle_phase
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

def extractPostTableFromLifecycleAir
    (row : CommonRow)
    (max_players : Nat)
    (shuffle_phase : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromLifecycleAir row max_players shuffle_phase
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
  }

/-! ## start_hand 专用提取函数

`start_hand` 需要反映 AIR witness `input_active_count` 对应的实际座位占用数。
通用 `extractPreTableFromLifecycleAir` 创建全空座位（foldl count = 0），
无法满足合约 `active_count = count of occupied seats`。
专用提取函数创建 `active_count` 个占用座位，使 foldl count = active_count。

同时 `start_hand` 合约要求 `post.shuffle_state.phase = 3`（BEFORE_PREFLOP），
专用后置提取函数设置该值，由 StateRootConsistency 强制。 -/

/-- 创建 `n` 个占用座位（player ≠ EMPTY_PLAYER）。 -/
def make_occupied_seats (n : Nat) : List Seat :=
  List.replicate n { Seat.empty with player := PlayerId.ofNat 1 }

/-- `make_occupied_seats` 的 foldl count = n（全部被占用）。 -/
theorem make_occupied_seats_foldl_count (n : Nat) :
    (make_occupied_seats n).foldl
      (fun acc s => acc + if s.is_occupied then 1 else 0) 0 = n := by
  have h_occ : ({ Seat.empty with player := PlayerId.ofNat 1 } : Seat).is_occupied = true := by
    simp [Seat.is_occupied, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  -- Helper: foldl f acc l = acc + foldl f 0 l (for additive f)
  have h_foldl_eq : ∀ (acc : Nat) (l : List Seat),
      l.foldl (fun acc s => acc + if s.is_occupied = true then 1 else 0) acc =
      acc + l.foldl (fun acc s => acc + if s.is_occupied = true then 1 else 0) 0 := by
    intro acc l
    induction l generalizing acc with
    | nil => rfl
    | cons x xs ih =>
      rw [List.foldl_cons, List.foldl_cons]
      have h1 := ih (acc + if x.is_occupied = true then 1 else 0)
      have h2 := ih (if x.is_occupied = true then 1 else 0)
      rw [h1, Nat.zero_add, h2]
      omega
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [make_occupied_seats]
    simp only [make_occupied_seats] at ih
    rw [List.replicate_succ, List.foldl_cons, h_foldl_eq, ih]
    simp [h_occ]
    omega

/-- start_hand 专用前置提取：创建 `active_count` 个占用座位，`shuffle_state.phase = 0`。 -/
def extractPreTableFromStartHandAir
    (row : CommonRow)
    (active_count : Nat)
    (max_players : Nat)
    : TexasPokerTable :=
  { table_id := 0
    name_hash := 0
    seats := make_occupied_seats active_count
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
    reveal_state := { reveal_phase := 0, num_assignments := 0 }
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

/-- start_hand 专用后置提取：`shuffle_state.phase = 3`（BEFORE_PREFLOP），version 递增。 -/
def extractPostTableFromStartHandAir
    (row : CommonRow)
    (active_count : Nat)
    (max_players : Nat)
    : TexasPokerTable :=
  let pre := extractPreTableFromStartHandAir row active_count max_players
  { pre with
    version := decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2
    round_state := RoundState.fromNat row.post_round_state.val
    shuffle_state := { pre.shuffle_state with phase := 3 }
  }

/-! ## start_hand AIR

AIR 约束（start_hand.rs:86-133）：
1. `input_active_count == expected_count`
2. (NOT enforced) `active_count >= 2` — explicitly "simplified"
3. `output_new_round_state == 0` (ROUND_WAITING)
4-6. Ante consistency

**真实 Rust AIR 中缺失、但下方 Lean 模型作为额外假设加入的约束**：
- 无 `pre_round_state == WAITING` 检查
- 无 `active_count >= 2` 强制（约束 2 被注释为"简化"）
- 无 version 递增检查
- 无 state root 验证

因此 `start_hand_air_sound` 只对加强后的 Lean 谓词成立，不能直接推出该 Rust AIR sound。
-/

structure StartHandMethodColumns where
  input_active_count : M31
  output_new_button : M31
  output_new_round_state : M31
  output_ante_mode : M31
  output_ante_amount_0 : M31
  output_ante_collected_0 : M31
deriving Repr

def StartHandMethodConstraints
    (row : CommonRow)
    (ext : StartHandMethodColumns)
    (expected_active_count : Nat)
    (max_players : Nat)
    (hlt : expected_active_count < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧ RoundStateEq row 0 (by unfold M31_P; omega) ∧
  RoundStateUnchanged row ∧
  ext.input_active_count = nat_to_m31 expected_active_count hlt ∧
  ActiveCountAtLeastTwo ext.input_active_count ∧
  ext.output_new_round_state = M31.zero ∧
  let pre_table := extractPreTableFromStartHandAir row ext.input_active_count.val max_players
  let post_table := extractPostTableFromStartHandAir row ext.input_active_count.val max_players
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def StartHandAirAcceptable
    (row : CommonRow)
    (ext : StartHandMethodColumns)
    (expected_active_count : Nat)
    (max_players : Nat)
    (hlt : expected_active_count < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.StartHand ∧
  StartHandMethodConstraints row ext expected_active_count max_players hlt ∧
  row.method_kind = ⟨MethodKind.StartHand.toNat, MethodKind.toNat_lt_M31P MethodKind.StartHand⟩ ∧
  row.is_active = M31.one

/-! ## tick AIR

AIR 约束（tick.rs:85-121）：
1. `timeout_kind == input.timeout_kind`
2-3. Time bank consistency
4-5. Rake consistency

**真实 Rust AIR 中缺失、但下方 Lean 模型部分作为额外假设加入的约束**：
- 无 round_state gating
- 无真实超时条件验证（不校验 timeout_kind > 0）
- 无 version 递增检查

Lean 仅加入 `timeout_kind > 0` 与版本递增，仍未建模真实超时判定。
-/

structure TickMethodColumns where
  input_current_time : M31 × M31 × M31 × M31
  input_timeout_kind : M31
  output_new_round_state : M31
  time_bank_consumed_0 : M31
  time_bank_post_0 : M31
  rake_mode : M31
  rake_amount_0 : M31
deriving Repr

def TickMethodConstraints
    (row : CommonRow)
    (ext : TickMethodColumns)
    (expected_timeout_kind : Nat)
    (max_players : Nat)
    (hlt : expected_timeout_kind < M31_P)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧
  ext.input_timeout_kind = nat_to_m31 expected_timeout_kind hlt ∧
  TimeoutKindPositive ext.input_timeout_kind ∧
  let pre_table := extractPreTableFromLifecycleAir row max_players 0
  let post_table := extractPostTableFromLifecycleAir row max_players 0
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def TickAirAcceptable
    (row : CommonRow)
    (ext : TickMethodColumns)
    (expected_timeout_kind : Nat)
    (max_players : Nat)
    (hlt : expected_timeout_kind < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.Tick ∧
  TickMethodConstraints row ext expected_timeout_kind max_players hlt ∧
  row.method_kind = ⟨MethodKind.Tick.toNat, MethodKind.toNat_lt_M31P MethodKind.Tick⟩ ∧
  row.is_active = M31.one

/-! ## reset_for_next_hand AIR

AIR 约束（reset_for_next_hand.rs:76-98）：
1. `output_new_round_state == 0` (ROUND_WAITING)
2. `post_pending_addon == 0` (all 4 limbs)

**真实 Rust AIR 中缺失、但下方 Lean 模型部分作为额外假设加入的约束**：
- 无 `pre_round_state` 检查（不验证是否在结算后状态）
- 无 version 递增检查
- 无 state root 验证

Lean 加入版本递增、粗粒度 shuffle phase 与抽象 root 一致性，仍未覆盖真实 reset 前置条件。
-/

structure ResetForNextHandMethodColumns where
  input_shuffle_phase : M31
  output_new_round_state : M31
  post_pending_addon : M31 × M31 × M31 × M31
deriving Repr

def ResetForNextHandMethodConstraints
    (row : CommonRow)
    (ext : ResetForNextHandMethodColumns)
    (max_players : Nat)
    : Prop :=
  row.is_active = M31.one →
  VersionIncrementConstraint row ∧
  ShufflePhasePositive ext.input_shuffle_phase ∧
  ext.output_new_round_state = M31.zero ∧
  -- 强制 post_round_state = WAITING（与 output_new_round_state = 0 一致）
  row.post_round_state = ext.output_new_round_state ∧
  ext.post_pending_addon.1 = M31.zero ∧
  ext.post_pending_addon.2.1 = M31.zero ∧
  ext.post_pending_addon.2.2.1 = M31.zero ∧
  ext.post_pending_addon.2.2.2 = M31.zero ∧
  let pre_table := extractPreTableFromLifecycleAir row max_players ext.input_shuffle_phase.val
  let post_table := extractPostTableFromLifecycleAir row max_players ext.input_shuffle_phase.val
  StateRootConsistency row
    (texasPokerTableToPreimage pre_table)
    (texasPokerTableToPreimage post_table)

def ResetForNextHandAirAcceptable
    (row : CommonRow)
    (ext : ResetForNextHandMethodColumns)
    (max_players : Nat)
    : Prop :=
  CommonConstraints row MethodKind.ResetForNextHand ∧
  ResetForNextHandMethodConstraints row ext max_players ∧
  row.method_kind = ⟨MethodKind.ResetForNextHand.toNat, MethodKind.toNat_lt_M31P MethodKind.ResetForNextHand⟩ ∧
  row.is_active = M31.one

def extractStartHandParamsFromAir (ext : StartHandMethodColumns) : StartHandParams := {
  active_count := ext.input_active_count.val
  ante_mode := ext.output_ante_mode.val
  ante_amount := ext.output_ante_amount_0.val
  ante_collected := ext.output_ante_collected_0.val
}

def extractTickParamsFromAir
    (_ext : TickMethodColumns)
    (timeout_kind : Nat)
    (time_bank_consumed : Nat)
    (time_bank_post : Nat)
    (rake_mode : Nat)
    (rake_amount : Nat)
    : TickParams := {
  now_ms := 0
  timeout_kind := timeout_kind
  time_bank_consumed := time_bank_consumed
  time_bank_post := time_bank_post
  rake_mode := rake_mode
  rake_amount := rake_amount
}

def extractResetParamsFromAir (pre_pending_addon : Nat) : ResetForNextHandParams := {
  pre_pending_addon := pre_pending_addon
}

end PokerLean
