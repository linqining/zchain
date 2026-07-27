import Mathlib
import PokerLean.State.Constants
import PokerLean.State.Card

/-!
# 核心数据结构（镜像 `poker_l1/src/vm/contracts/texas_poker/types.rs`）

与 Rust `types.rs` 逐字段对应。所有金额字段用 `Nat`（Lean `Nat` 减法天然截断，
对应 Rust `u64::saturating_sub`；溢出上界由 `inv_chip_bounds` 不变量保证）。
密码学类型（`ECPoint` / `ECScalar` / `ElGamalCiphertext`）用不透明类型占位，
状态机证明不依赖其内部结构。
-/

namespace TexasPoker

/-! ## 密码学类型占位

对应 Rust `ECPoint` / `ECScalar` / `ElGamalCiphertext`（基于 BLS12-381）。
状态机证明不依赖其内部结构，故用占位 structure 提供干净的 `DecidableEq` / `Inhabited`。
真实语义见 `Refinement.lean`。
-/

/-- G1 点占位（对应 Rust `ECPoint(pub G1Projective)` newtype）。 -/
structure ECPoint where
  private repr : Unit := ()
deriving Repr, DecidableEq, Inhabited

/-- 标量占位（对应 Rust `ECScalar(pub BlsScalar)` newtype）。 -/
structure ECScalar where
  private repr : Unit := ()
deriving Repr, DecidableEq, Inhabited

/-- ElGamal 密文占位（对应 Rust `ElGamalCiphertext`）。 -/
structure ElGamalCiphertext where
  private repr : Unit := ()
deriving Repr, DecidableEq, Inhabited

/-! ## 地址与 ObjectID -/

/-- 玩家地址（对应 Rust `Address = [u8; 20]`）。用 `Nat` 简化，`0` 表示空。
    用 `abbrev` 以继承 `Nat` 的 `OfNat` / `Repr` / `DecidableEq` 实例。 -/
abbrev Address := Nat

/-- 空地址哨兵（对应 `types.rs:56` `EMPTY_PLAYER = [0; 20]`）。 -/
def EMPTY_PLAYER : Address := 0

/-- ObjectID（对应 Rust `ObjectID`）。用 `Nat` 简化。 -/
abbrev ObjectID := Nat

/-! ## 座位状态枚举（对应 `types.rs:69-83` `SeatStatus`）-/

inductive SeatStatus where
  | Empty    : SeatStatus
  | Waiting  : SeatStatus
  | Active   : SeatStatus
  | Folded   : SeatStatus
  | AllIn    : SeatStatus
  | Out      : SeatStatus
deriving Repr, DecidableEq

/-! ## 座位（对应 `types.rs:91-143` `Seat`，14 字段）-/

structure Seat where
  /-- 玩家地址（`EMPTY_PLAYER` 表示空座位）。 -/
  player : Address
  /-- 玩家筹码栈。 -/
  stack : Nat
  /-- 玩家手牌（最多 2 张）。 -/
  hand : List Card
  /-- 本轮已下注（每轮开始时清零，累加到 total_bet）。 -/
  bet : Nat
  /-- 本局总下注（用于 side pot 计算）。 -/
  total_bet : Nat
  /-- 是否已弃牌。 -/
  folded : Bool
  /-- 是否 all-in。 -/
  all_in : Bool
  /-- 本轮是否已行动。 -/
  acted_this_round : Bool
  /-- 本局不参与，等下一局开始（对应 Move `is_waiting`）。 -/
  is_waiting : Bool
  /-- 本局中途离开（被踢），total_bet 保留供 side pot 计算。 -/
  left_during_hand : Bool
  /-- 玩家 ElGamal 公钥（G1 点）。 -/
  pk : ECPoint
  /-- total_bet 是否已退款（避免重复退款）。 -/
  refunded : Bool
  /-- 待入账的 addon 金额（下一手 `reset_for_next_hand` 时合并到 `stack`）。 -/
  pending_addon : Nat
  /-- 玩家 Time Bank 剩余额度（毫秒）。 -/
  time_bank_ms : Nat
  /-- 玩家请求「下局开始前离场」。 -/
  want_leave : Bool
deriving Repr

namespace Seat

/-- 构造空座位。对应 `types.rs:147-166` `Seat::empty`。 -/
def empty : Seat :=
  { player := EMPTY_PLAYER,
    stack := 0, hand := [], bet := 0, total_bet := 0,
    folded := false, all_in := false, acted_this_round := false,
    is_waiting := false, left_during_hand := false,
    pk := default, refunded := false,
    pending_addon := 0, time_bank_ms := Constants.DEFAULT_TIME_BANK_MS,
    want_leave := false }

/-- 判断座位是否被活跃占用。对应 `types.rs:170-172` `is_occupied`。 -/
def is_occupied (s : Seat) : Bool :=
  s.player != EMPTY_PLAYER && ! s.left_during_hand

/-- 判断座位是否为空。 -/
def is_empty (s : Seat) : Bool := s.player == EMPTY_PLAYER

/-- 获取座位状态枚举。对应 `types.rs:176-190` `status`。 -/
def status (s : Seat) : SeatStatus :=
  if s.player == EMPTY_PLAYER then SeatStatus.Empty
  else if s.left_during_hand then SeatStatus.Out
  else if s.is_waiting then SeatStatus.Waiting
  else if s.folded then SeatStatus.Folded
  else if s.all_in then SeatStatus.AllIn
  else SeatStatus.Active

/-- 座位是否参与本局（非空、未离开、未等待、未弃牌）。 -/
def is_participating (s : Seat) : Bool :=
  s.player != EMPTY_PLAYER && ! s.left_during_hand
    && ! s.is_waiting && ! s.folded

/-- 标记弃牌。 -/
def mark_folded (s : Seat) : Seat :=
  { s with folded := true, acted_this_round := true }

end Seat

/-! ## 下注轮状态（对应 `betting.rs:17-23` `BettingRound`，2 字段）-/

structure BettingRound where
  /-- 当前轮最高下注。 -/
  current_bet : Nat
  /-- 最小加注增量（初始 = big_blind）。 -/
  min_raise : Nat
deriving Repr, DecidableEq

namespace BettingRound

/-- 创建下注轮。对应 `betting.rs:27-34` `BettingRound::new`。 -/
def new (big_blind current_bet : Nat) : BettingRound :=
  { current_bet := current_bet, min_raise := big_blind }

end BettingRound

/-! ## 边池（对应 `side_pot.rs:36-42` `SidePot`）-/

structure SidePot where
  /-- 该层 pot 总金额。 -/
  amount : Nat
  /-- 有资格争夺该层 pot 的座位位掩码（bit j = 1 → seat j eligible）。
      Rust 用 `u16`，Lean 用 `Nat`，由 `≤ 65535` 不变量约束。 -/
  eligible_seats : Nat
deriving Repr, DecidableEq

namespace SidePot

/-- 构造新 SidePot。对应 `side_pot.rs:46-52`。 -/
def new (amount eligible_seats : Nat) : SidePot := ⟨amount, eligible_seats⟩

/-- 第 j 位置 1。对应 `side_pot.rs:21-23` `seat_bit`。 -/
def seatBit (j : Nat) : Nat := 1 <<< j

/-- 测试第 j 位是否置 1。对应 `side_pot.rs:27-29` `is_eligible`。 -/
def isEligible (mask j : Nat) : Bool := (mask &&& seatBit j) ≠ 0

end SidePot

/-! ## 洗牌状态（对应 `types.rs:198-207` `ShuffleState`）-/

structure ShuffleState where
  /-- 洗牌阶段（SHUFFLE_PHASE_*）。 -/
  phase : Nat
  /-- 当前洗牌者 seat_index。 -/
  current_shuffler : Option Nat
  /-- 等待洗牌的玩家列表。 -/
  pending_players : List Nat
  /-- 已完成洗牌的玩家列表。 -/
  completed_players : List Nat
deriving Repr, DecidableEq

namespace ShuffleState

def default : ShuffleState :=
  { phase := Constants.SHUFFLE_PHASE_NONE, current_shuffler := none,
    pending_players := [], completed_players := [] }

end ShuffleState

/-! ## Reveal Token 状态（对应 `types.rs:247-253` `RevealTokenState`）-/

structure RevealAssignment where
  encrypted_card_index : Nat
  pending_players : List Nat
  reveal_tokens : List Nat  -- 简化：token seat_index 列表
  decrypted : Bool
deriving Repr, DecidableEq

structure RevealTokenState where
  reveal_phase : Nat
  assignments : List RevealAssignment
deriving Repr, DecidableEq

namespace RevealTokenState

def default : RevealTokenState :=
  { reveal_phase := Constants.REVEAL_PHASE_NONE, assignments := [] }

end RevealTokenState

/-! ## Reconstruct 状态（对应 `types.rs:278-288` `ReconstructState`）-/

structure ReconstructState where
  phase : Nat
  pending_players : List Nat
  coefficient : Option ECScalar
  player_decks : List Nat  -- 简化：seat_index 列表
deriving Repr, DecidableEq

namespace ReconstructState

def default : ReconstructState :=
  { phase := Constants.RECONSTRUCT_PHASE_NONE, pending_players := [],
    coefficient := none, player_decks := [] }

end ReconstructState

/-! ## 牌组状态（对应 `types.rs:375-387` `DeckState`）-/

structure DeckState where
  encrypted : List ElGamalCiphertext
  aggregated_pk : Option ECPoint
  plaintext : List ECPoint
  cards_dealt : Nat
  decrypted_cards : List Nat  -- 简化：索引列表
deriving Repr, DecidableEq

namespace DeckState

def default : DeckState :=
  { encrypted := [], aggregated_pk := none, plaintext := [],
    cards_dealt := 0, decrypted_cards := [] }

end DeckState

/-! ## 超时配置（对应 `types.rs:304-320` `TimeoutConfig`）-/

structure TimeoutConfig where
  shuffle_timeout_ms : Nat
  reveal_timeout_ms : Nat
  betting_timeout_ms : Nat
  reconstruct_timeout_ms : Nat
  showdown_display_ms : Nat
  hand_complete_wait_ms : Nat
  ready_wait_ms : Nat
deriving Repr, DecidableEq

/-! ## 时间戳集合（对应 `types.rs:339-355` `Timestamps`）-/

structure Timestamps where
  ready_at : Nat
  shuffle_started_at : Nat
  reveal_started_at : Nat
  betting_started_at : Nat
  reconstruct_started_at : Nat
  showdown_at : Nat
  hand_complete_at : Nat
deriving Repr, DecidableEq

/-! ## 桌台配置（对应 `types.rs:404-417` `TableConfig`）-/

structure TableConfig where
  zk_skip_enabled : Bool
  zk_skip_shuffle : Bool
  zk_skip_reveal : Bool
  zk_skip_reconstruct : Bool
  zk_skip_remask : Bool
deriving Repr, DecidableEq

/-! ## 桌台主结构（对应 `types.rs:466-565` `TexasPokerTable`，全字段）-/

structure TexasPokerTable where
  /-- 桌台 ObjectID。 -/
  id : ObjectID
  /-- 桌台名称。 -/
  name : String
  /-- 桌台创建者。 -/
  creator : Address
  /-- 最大玩家数（2..=9）。 -/
  max_players : Nat
  /-- 小盲注金额。 -/
  small_blind : Nat
  /-- 大盲注金额。 -/
  big_blind : Nat
  /-- 座位列表（长度 = max_players）。 -/
  seats : List Seat
  /-- 庄家位。 -/
  button : Nat
  /-- 当前底池。 -/
  pot : Nat
  /-- 边池列表。 -/
  side_pots : List SidePot
  /-- 公共牌（最多 5 张）。 -/
  community_cards : List Card
  /-- 当前回合状态（ROUND_*）。 -/
  round_state : Nat
  /-- 当前下注轮状态。 -/
  betting_round : Option BettingRound
  /-- 当前行动玩家 seat_index。 -/
  current_turn : Option Nat
  /-- 加密牌组状态。 -/
  deck_state : DeckState
  /-- 协议状态：洗牌。 -/
  shuffle_state : ShuffleState
  /-- 协议状态：reveal token。 -/
  reveal_token_state : RevealTokenState
  /-- 协议状态：reconstruct。 -/
  reconstruct_state : ReconstructState
  /-- 超时配置。 -/
  timeout_config : TimeoutConfig
  /-- 时间戳集合。 -/
  timestamps : Timestamps
  /-- 玩家存入资金池。 -/
  chip_pool : Nat
  /-- Addon 资金池。 -/
  addon_pool : Nat
  /-- Ante 模式。 -/
  ante_mode : Nat
  /-- Ante 金额。 -/
  ante_amount : Nat
  /-- 本手已累积的 ante 总额。 -/
  ante_collected : Nat
  /-- Rake 模式。 -/
  rake_mode : Nat
  /-- Rake 比例（bps）。 -/
  rake_bps : Nat
  /-- Rake 上限。 -/
  rake_cap : Nat
  /-- 本手已抽水金额。 -/
  rake_collected : Nat
  /-- Run It Twice 模式。 -/
  rit_mode : Nat
  /-- 桌台配置。 -/
  config : TableConfig
  /-- 状态版本号（每次更新 +1）。 -/
  version : Nat
deriving Repr

namespace TexasPokerTable

/-- 获取第 idx 个座位（越界返回空座位）。 -/
def get_seat (t : TexasPokerTable) (idx : Nat) : Seat :=
  t.seats.getD idx Seat.empty

/-- 更新第 idx 个座位（越界无操作）。 -/
def update_seat (t : TexasPokerTable) (idx : Nat) (f : Seat → Seat) : TexasPokerTable :=
  { t with seats := t.seats.mapIdx fun i s => if i = idx then f s else s }

/-- 是否处于下注轮（PREFLOP/FLOP/TURN/RIVER）。 -/
def is_betting_round (t : TexasPokerTable) : Bool :=
  t.round_state == Constants.ROUND_PREFLOP ||
  t.round_state == Constants.ROUND_FLOP ||
  t.round_state == Constants.ROUND_TURN ||
  t.round_state == Constants.ROUND_RIVER

end TexasPokerTable

end TexasPoker
