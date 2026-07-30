import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Contract.Types

namespace PokerLean

def COMMON_NUM_COLUMNS : Nat := 37

namespace ColIdx
  def IS_ACTIVE : Nat := 0
  def METHOD_KIND : Nat := 1
  def PRE_STATE_ROOT_BASE : Nat := 2
  def POST_STATE_ROOT_BASE : Nat := 6
  def TABLE_ID_BASE : Nat := 10
  def HAND_ID : Nat := 14
  def CALL_SEQ : Nat := 15
  def PRE_VERSION_BASE : Nat := 16
  def POST_VERSION_BASE : Nat := 20
  def PRE_ROUND_STATE : Nat := 24
  def POST_ROUND_STATE : Nat := 25
  def PRE_POT_BASE : Nat := 26
  def POST_POT_BASE : Nat := 30
  def PRE_BUTTON : Nat := 34
  def POST_BUTTON : Nat := 35
  def IS_PADDING : Nat := 36
end ColIdx

inductive MethodKind where
  | CreateTable        | JoinTable         | LeaveTable
  | StartHand          | Tick              | ResetForNextHand
  | Fold               | Check             | Call
  | Raise              | AutoFold          | ForceFold
  | KickPlayer         | Addon             | Rebuy
  | JoinAndShuffle     | LeaveWithProof    | SubmitShuffleV2
  | SubmitPlayerRevealTokens | SubmitReconstructDeck
  | Bet
deriving Repr, DecidableEq

namespace MethodKind

def toNat : MethodKind → Nat
  | CreateTable => 0 | JoinTable => 1 | LeaveTable => 2
  | StartHand => 3 | Tick => 4 | ResetForNextHand => 5
  | Fold => 6 | Check => 7 | Call => 8
  | Raise => 9 | AutoFold => 10 | ForceFold => 11
  | KickPlayer => 12 | Addon => 13 | Rebuy => 14
  | JoinAndShuffle => 15 | LeaveWithProof => 16 | SubmitShuffleV2 => 17
  | SubmitPlayerRevealTokens => 18 | SubmitReconstructDeck => 19
  | Bet => 20

def lookup (n : Nat) : Option MethodKind :=
  if n = 0 then some CreateTable
  else if n = 1 then some JoinTable
  else if n = 2 then some LeaveTable
  else if n = 3 then some StartHand
  else if n = 4 then some Tick
  else if n = 5 then some ResetForNextHand
  else if n = 6 then some Fold
  else if n = 7 then some Check
  else if n = 8 then some Call
  else if n = 9 then some Raise
  else if n = 10 then some AutoFold
  else if n = 11 then some ForceFold
  else if n = 12 then some KickPlayer
  else if n = 13 then some Addon
  else if n = 14 then some Rebuy
  else if n = 15 then some JoinAndShuffle
  else if n = 16 then some LeaveWithProof
  else if n = 17 then some SubmitShuffleV2
  else if n = 18 then some SubmitPlayerRevealTokens
  else if n = 19 then some SubmitReconstructDeck
  else if n = 20 then some Bet
  else none

theorem lookup_toNat_roundtrip (k : MethodKind) :
  lookup (toNat k) = some k := by
  cases k <;> simp [lookup, toNat] <;> rfl

theorem toNat_lt_M31P (k : MethodKind) : toNat k < M31_P := by
  cases k <;> simp [toNat, M31_P] <;> norm_num

end MethodKind

structure CommonRow where
  is_active : M31
  method_kind : M31
  pre_state_root : M31 × M31 × M31 × M31
  post_state_root : M31 × M31 × M31 × M31
  table_id : M31 × M31 × M31 × M31
  hand_id : M31
  call_seq : M31
  pre_version : M31 × M31 × M31 × M31
  post_version : M31 × M31 × M31 × M31
  pre_round_state : M31
  post_round_state : M31
  pre_pot : M31 × M31 × M31 × M31
  post_pot : M31 × M31 × M31 × M31
  pre_button : M31
  post_button : M31
  is_padding : M31
deriving Repr

namespace CommonRow

def active (kind : MethodKind)
    (pre_sr post_sr : M31 × M31 × M31 × M31)
    (table_id : M31 × M31 × M31 × M31)
    (hand_id call_seq : M31)
    (pre_ver post_ver : M31 × M31 × M31 × M31)
    (pre_rs post_rs : M31)
    (pre_pot post_pot : M31 × M31 × M31 × M31)
    (pre_btn post_btn : M31) : CommonRow :=
  {
    is_active := M31.one
    method_kind := ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩
    pre_state_root := pre_sr
    post_state_root := post_sr
    table_id := table_id
    hand_id := hand_id
    call_seq := call_seq
    pre_version := pre_ver
    post_version := post_ver
    pre_round_state := pre_rs
    post_round_state := post_rs
    pre_pot := pre_pot
    post_pot := post_pot
    pre_button := pre_btn
    post_button := post_btn
    is_padding := M31.zero
  }

def padding : CommonRow :=
  {
    is_active := M31.zero
    method_kind := M31.zero
    pre_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_state_root := (M31.zero, M31.zero, M31.zero, M31.zero)
    table_id := (M31.zero, M31.zero, M31.zero, M31.zero)
    hand_id := M31.zero
    call_seq := M31.zero
    pre_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_version := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_round_state := M31.zero
    post_round_state := M31.zero
    pre_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    post_pot := (M31.zero, M31.zero, M31.zero, M31.zero)
    pre_button := M31.zero
    post_button := M31.zero
    is_padding := M31.one
  }

end CommonRow

def CommonConstraints (row : CommonRow) (kind : MethodKind) : Prop :=
  (M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero) ∧
  (M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero) ∧
  (M31.mul row.is_active row.is_padding = M31.zero) ∧
  (M31.mul row.is_active
    (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero)

def ActiveRowConstraints (row : CommonRow) (kind : MethodKind) : Prop :=
  row.is_active = M31.one ∧
  row.is_padding = M31.zero ∧
  row.method_kind = ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩

def PaddingRowConstraints (row : CommonRow) : Prop :=
  row.is_active = M31.zero ∧
  row.is_padding = M31.one

/-- 版本递增约束：active 行要求 post_version = pre_version + 1（整数意义下）。 -/
def VersionIncrementConstraint (row : CommonRow) : Prop :=
  row.is_active = M31.one →
  decodeU64 row.post_version.1 row.post_version.2.1 row.post_version.2.2.1 row.post_version.2.2.2
  =
  decodeU64 row.pre_version.1 row.pre_version.2.1 row.pre_version.2.2.1 row.pre_version.2.2.2 + 1

/-- round_state 不变约束：active 行要求 post_round_state = pre_round_state。 -/
def RoundStateUnchanged (row : CommonRow) : Prop :=
  row.is_active = M31.one → row.post_round_state = row.pre_round_state

/-- round_state 前置约束：active 行要求 pre_round_state = expected。 -/
def RoundStateEq (row : CommonRow) (expected : Nat) (hlt : expected < M31_P) : Prop :=
  row.is_active = M31.one → row.pre_round_state = ⟨expected, hlt⟩

/-- pot limb0 不变约束：active 行要求 post_pot limb0 = pre_pot limb0。 -/
def PotUnchangedLimb0 (row : CommonRow) : Prop :=
  row.is_active = M31.one → row.post_pot.1 = row.pre_pot.1

/-- pot 全 limb 不变约束：active 行要求 post_pot 全 4 limb = pre_pot 全 4 limb。
    对齐 Rust `pot_unchanged` 的完整实现（4×8-bit limb 逐 limb 比较）。 -/
def PotUnchanged (row : CommonRow) : Prop :=
  row.is_active = M31.one →
  row.post_pot.1 = row.pre_pot.1 ∧
  row.post_pot.2.1 = row.pre_pot.2.1 ∧
  row.post_pot.2.2.1 = row.pre_pot.2.2.1 ∧
  row.post_pot.2.2.2 = row.pre_pot.2.2.2

/-- `PotUnchanged` 在整数解码层面也保持 pot。该引理不需要 range
    假设，因为四个 limb 是逐项相等，而非通过域内加法推导。 -/
lemma pot_unchanged_implies_decode_eq (row : CommonRow)
    (h_active : row.is_active = M31.one) (h : PotUnchanged row) :
    decodeU64 row.post_pot.1 row.post_pot.2.1 row.post_pot.2.2.1 row.post_pot.2.2.2 =
    decodeU64 row.pre_pot.1 row.pre_pot.2.1 row.pre_pot.2.2.1 row.pre_pot.2.2.2 := by
  rcases h h_active with ⟨h0, h1, h2, h3⟩
  rw [h0, h1, h2, h3]

/-- pot limb0 delta 约束：active 行要求 post_pot limb0 = pre_pot limb0 + amt limb0（M31 域内）。
    保留给真正将某笔已有 bet 收入 pot 的动作；mid-round call/raise/bet
    现使用 `PotUnchanged`。 -/
def PotDeltaLimb0 (row : CommonRow) (amt0 : M31) : Prop :=
  row.is_active = M31.one →
  row.post_pot.1.val = (row.pre_pot.1.val + amt0.val) % M31_P

/-- 三个 ripple-carry witness 均为 boolean。 -/
def Carry3Boolean (carry : M31 × M31 × M31) : Prop :=
  match carry with
  | (c0, c1, c2) =>
    (c0 = M31.zero ∨ c0 = M31.one) ∧
    (c1 = M31.zero ∨ c1 = M31.one) ∧
    (c2 = M31.zero ∨ c2 = M31.one)

/-- 规范 4×16-bit u64 加法：`post = pre + amt`，带 3 级 ripple carry。
    最高 limb 无 carry-out，因此同时表达 Rust `checked_add` 成功。 -/
def Limb4Delta (pre post amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31) : Prop :=
  match carry with
  | (c0, c1, c2) =>
    Carry3Boolean carry ∧
    pre.1.val + amt.1.val = post.1.val + c0.val * 65536 ∧
    pre.2.1.val + amt.2.1.val + c0.val = post.2.1.val + c1.val * 65536 ∧
    pre.2.2.1.val + amt.2.2.1.val + c1.val = post.2.2.1.val + c2.val * 65536 ∧
    pre.2.2.2.val + amt.2.2.2.val + c2.val = post.2.2.2.val

/-- pot 全 4 limb delta 约束，使用与 Rust AIR 相同的 ripple-carry witness。 -/
def PotDelta (row : CommonRow) (amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31) : Prop :=
  row.is_active = M31.one → Limb4Delta row.pre_pot row.post_pot amt carry

/-- 4-limb 相等约束。 -/
def Limb4Eq (a b : M31 × M31 × M31 × M31) : Prop :=
  a.1 = b.1 ∧ a.2.1 = b.2.1 ∧ a.2.2.1 = b.2.2.1 ∧ a.2.2.2 = b.2.2.2

/-- 规范 4-limb 减法 `post = pre - amt`，反向写成 `pre = post + amt`。
    使用与 Rust AIR 相同的 ripple-carry chain，因此允许跨 limb 借位并禁止下溢。 -/
def Limb4DeltaRev (pre post amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31) : Prop :=
  Limb4Delta post pre amt carry

lemma limb4_eq_implies_decode_eq (a b : M31 × M31 × M31 × M31)
    (h : Limb4Eq a b) :
    decodeU64 a.1 a.2.1 a.2.2.1 a.2.2.2 = decodeU64 b.1 b.2.1 b.2.2.1 b.2.2.2 := by
  rcases h with ⟨h0, h1, h2, h3⟩
  rw [h0, h1, h2, h3]

lemma limb4_delta_implies_decode_eq (pre post amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31)
    (h : Limb4Delta pre post amt carry) :
    decodeU64 post.1 post.2.1 post.2.2.1 post.2.2.2 =
    decodeU64 pre.1 pre.2.1 pre.2.2.1 pre.2.2.2 +
    decodeU64 amt.1 amt.2.1 amt.2.2.1 amt.2.2.2 := by
  rcases carry with ⟨c0, c1, c2⟩
  unfold Limb4Delta at h
  rcases h with ⟨_, h0, h1, h2, h3⟩
  unfold decodeU64
  omega

lemma limb4_delta_rev_implies_decode_eq (pre post amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31)
    (h : Limb4DeltaRev pre post amt carry) :
    decodeU64 pre.1 pre.2.1 pre.2.2.1 pre.2.2.2 =
    decodeU64 post.1 post.2.1 post.2.2.1 post.2.2.2 +
    decodeU64 amt.1 amt.2.1 amt.2.2.1 amt.2.2.2 := by
  exact limb4_delta_implies_decode_eq post pre amt carry h

lemma pot_delta_implies_decode_eq (row : CommonRow) (amt : M31 × M31 × M31 × M31)
    (carry : M31 × M31 × M31)
    (h_active : row.is_active = M31.one)
    (h : PotDelta row amt carry) :
    decodeU64 row.post_pot.1 row.post_pot.2.1 row.post_pot.2.2.1 row.post_pot.2.2.2 =
    decodeU64 row.pre_pot.1 row.pre_pot.2.1 row.pre_pot.2.2.1 row.pre_pot.2.2.2 +
    decodeU64 amt.1 amt.2.1 amt.2.2.1 amt.2.2.2 := by
  have h' := h h_active
  exact limb4_delta_implies_decode_eq row.pre_pot row.post_pot amt carry h'

/-- button 不变约束：active 行要求 post_button = pre_button。
    fold/check 等动作不改变 dealer_seat（button）。 -/
def ButtonUnchanged (row : CommonRow) : Prop :=
  row.is_active = M31.one → row.post_button = row.pre_button

/-! ## State Root 一致性约束

Poseidon252 将状态（preimage）哈希为 state_root。
StateRootConsistency 要求 AIR 行中的 pre_state_root 和 post_state_root
与对应的 preimage 哈希值匹配。

该谓词只表达“给定的 preimage 经抽象哈希后等于行内 root”。它不会从 root
反推出唯一 preimage，也不会证明该 preimage 就是真实 Rust trace/public input
所编码的状态；这些性质需要另行建立编码精化与密码学绑定。
-/

/-- State root 一致性约束。
   给定 pre/post 的 StatePreimage，要求 state_root 字段匹配 Poseidon 哈希。 -/
def StateRootConsistency (row : CommonRow)
    (pre_pre post_pre : StatePreimage) : Prop :=
  row.is_active = M31.one →
  row.pre_state_root = poseidon_hash pre_pre ∧
  row.post_state_root = poseidon_hash post_pre

/-- State root 一致性（等价 formulation：直接使用 StateRoot 类型）。 -/
def StateRootConsistency' (row : CommonRow)
    (pre_sr post_sr : StateRoot) : Prop :=
  row.is_active = M31.one →
  row.pre_state_root = pre_sr ∧
  row.post_state_root = post_sr

lemma mul_zero_y (y : M31) :
  M31.mul M31.zero y = M31.zero := by
  simp [M31.mul, M31.zero, Nat.mul_zero, Nat.zero_mod]

lemma sub_self_eq_zero (x : M31) :
  M31.sub x x = M31.zero := by
  cases x with
  | mk val hval =>
    simp [M31.sub, M31.zero, Subtype.ext_iff, Subtype.val]
    <;> omega

lemma mul_one_sub_one :
  M31.mul M31.one (M31.sub M31.one M31.one) = M31.zero := by
  simp [M31.mul, M31.sub, M31.one, M31.zero, Subtype.ext_iff, Subtype.val]
  <;> ring

lemma mul_zero_sub_one :
  M31.mul M31.zero (M31.sub M31.zero M31.one) = M31.zero := by
  simp [M31.mul, M31.zero, Subtype.ext_iff, Subtype.val, Nat.mul_zero, Nat.zero_mod]

lemma mul_sub_one_eq_zero (x : M31) (h : x = M31.one) :
  M31.mul x (M31.sub x M31.one) = M31.zero := by
  rw [h]
  exact mul_one_sub_one

lemma mul_sub_zero_eq_zero (x : M31) (h : x = M31.zero) :
  M31.mul x (M31.sub x M31.one) = M31.zero := by
  rw [h]
  exact mul_zero_sub_one

lemma mul_sub_one_self_eq_zero (x : M31) (h : x = M31.one) :
  M31.mul x (M31.sub x M31.one) = M31.zero := mul_sub_one_eq_zero x h

lemma mul_sub_zero_self_eq_zero (x : M31) (h : x = M31.zero) :
  M31.mul x (M31.sub x M31.one) = M31.zero := mul_sub_zero_eq_zero x h

/-! ## 阶段 Gating 约束 -/

/-- round_state 是 betting 轮（PREFLOP=2/FLOP=3/TURN=4/RIVER=5）约束。
    与 Rust `round_state_is_betting` 的 vanishing (rs-2)(rs-3)(rs-4)(rs-5)==0 语义一致。 -/
def RoundStateIsBetting (row : CommonRow) : Prop :=
  row.is_active = M31.one →
  row.pre_round_state.val = 2 ∨ row.pre_round_state.val = 3 ∨
  row.pre_round_state.val = 4 ∨ row.pre_round_state.val = 5

/-- bet 专用轮次约束：只允许 FLOP/TURN/RIVER，排除 PREFLOP。 -/
def RoundStateIsPostflopBetting (row : CommonRow) : Prop :=
  row.is_active = M31.one →
  row.pre_round_state.val = 3 ∨ row.pre_round_state.val = 4 ∨
  row.pre_round_state.val = 5

/-- round_state 不是 betting 轮（即 ROUND_WAITING=0）约束。 -/
def RoundStateIsWaiting (row : CommonRow) : Prop :=
  row.is_active = M31.one → row.pre_round_state.val = 0

/-! ## 业务前置条件约束 -/

/-- u64 金额 > 0 约束（4 limb 解码后 > 0）。 -/
def AmountPositive (l0 l1 l2 l3 : M31) : Prop :=
  decodeU64 l0 l1 l2 l3 > 0

/-- timeout_kind > 0 约束。 -/
def TimeoutKindPositive (timeout_kind : M31) : Prop :=
  timeout_kind.val > 0

/-- active_count ≥ 2 约束。 -/
def ActiveCountAtLeastTwo (active_count : M31) : Prop :=
  active_count.val ≥ 2

/-! ## 密码学阶段 Gating 约束 -/

/-- shuffle phase > 0 约束（shuffle 已开始）。 -/
def ShufflePhasePositive (shuffle_phase : M31) : Prop :=
  shuffle_phase.val > 0

/-- reveal phase > 0 约束（揭牌已开始）。 -/
def RevealPhasePositive (reveal_phase : M31) : Prop :=
  reveal_phase.val > 0

/-- reconstruct_state ≠ Idle 约束（重构已开始）。
   0 = ReconstructIdle, 1 = Reconstructing, 2 = Reconstructed。
   对齐 `ReconstructState.fromNat`：`fromNat n ≠ ReconstructIdle ↔ n = 1 ∨ n = 2`。 -/
def ReconstructStateNotIdle (reconstruct_state : M31) : Prop :=
  reconstruct_state.val = 1 ∨ reconstruct_state.val = 2

/-- `ReconstructStateNotIdle` 蕴含 `fromNat val ≠ ReconstructIdle`。 -/
lemma reconstruct_state_not_idle_implies_fromNat
    (reconstruct_state : M31) (h : ReconstructStateNotIdle reconstruct_state) :
    ReconstructState.fromNat reconstruct_state.val ≠ ReconstructState.ReconstructIdle := by
  rcases h with h1 | h2
  · rw [h1]; simp [ReconstructState.fromNat]
  · rw [h2]; simp [ReconstructState.fromNat]

/-! ## 座位状态约束 -/

/-- 座位必须被占用（is_occupied = true）。 -/
def SeatOccupied (seat_is_occupied : M31) : Prop :=
  seat_is_occupied = M31.one

/-- 座位必须为空（is_occupied = false）。 -/
def SeatEmpty (seat_is_occupied : M31) : Prop :=
  seat_is_occupied = M31.zero

/-! ## 辅助引理 -/

/-- M31 val = 2 满足 RoundStateIsBetting（PREFLOP）。 -/
lemma round_state_2_is_betting (row : CommonRow)
    (h : row.is_active = M31.one)
    (hrs : row.pre_round_state.val = 2) :
    RoundStateIsBetting row := by
  unfold RoundStateIsBetting
  simp [h, hrs]

/-- M31 val = 3 满足 RoundStateIsBetting（FLOP）。 -/
lemma round_state_3_is_betting (row : CommonRow)
    (h : row.is_active = M31.one)
    (hrs : row.pre_round_state.val = 3) :
    RoundStateIsBetting row := by
  unfold RoundStateIsBetting
  simp [h, hrs]

/-- M31 val = 4 满足 RoundStateIsBetting（TURN）。 -/
lemma round_state_4_is_betting (row : CommonRow)
    (h : row.is_active = M31.one)
    (hrs : row.pre_round_state.val = 4) :
    RoundStateIsBetting row := by
  unfold RoundStateIsBetting
  simp [h, hrs]

/-- M31 val = 5 满足 RoundStateIsBetting（RIVER）。 -/
lemma round_state_5_is_betting (row : CommonRow)
    (h : row.is_active = M31.one)
    (hrs : row.pre_round_state.val = 5) :
    RoundStateIsBetting row := by
  unfold RoundStateIsBetting
  simp [h, hrs]

theorem active_row_satisfies_common (row : CommonRow) (kind : MethodKind)
    (h : ActiveRowConstraints row kind) :
  CommonConstraints row kind := by
  unfold ActiveRowConstraints at h
  rcases h with ⟨h_active, h_padding, h_kind⟩
  have hA : M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero := by
    simp [h_active]
    exact mul_one_sub_one
  have hB : M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero := by
    simp [h_padding]
    exact mul_zero_sub_one
  have hC : M31.mul row.is_active row.is_padding = M31.zero := by
    rw [h_padding]
    apply M31.mul_zero_right
  have hD : M31.mul row.is_active
      (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero := by
    have h_diff : M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩ = M31.zero := by
      rw [h_kind]
      apply sub_self_eq_zero
    rw [h_diff]
    apply M31.mul_zero_right
  unfold CommonConstraints
  exact ⟨hA, hB, hC, hD⟩

theorem padding_row_satisfies_common (row : CommonRow) (kind : MethodKind)
    (h : PaddingRowConstraints row) :
  CommonConstraints row kind := by
  unfold PaddingRowConstraints at h
  rcases h with ⟨h_active, h_padding⟩
  have hA : M31.mul row.is_active (M31.sub row.is_active M31.one) = M31.zero := by
    simp [h_active]
    exact mul_zero_sub_one
  have hB : M31.mul row.is_padding (M31.sub row.is_padding M31.one) = M31.zero := by
    simp [h_padding]
    exact mul_one_sub_one
  have hC : M31.mul row.is_active row.is_padding = M31.zero := by
    rw [h_active]
    apply M31.mul_zero_left
  have hD : M31.mul row.is_active
      (M31.sub row.method_kind ⟨kind.toNat, MethodKind.toNat_lt_M31P kind⟩) = M31.zero := by
    simp [h_active]
    apply M31.mul_zero_y
  unfold CommonConstraints
  exact ⟨hA, hB, hC, hD⟩

end PokerLean
