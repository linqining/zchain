import Mathlib

/-!
# 合约常量（镜像 `poker_l1/src/vm/contracts/texas_poker/constants.rs`）

所有常量值与 Rust 端逐字节一致，确保状态机语义不变。

注意：`ROUND_*` 状态值存在跳号（PREFLOP=2，值 1 未使用），
本文件保留该跳号以与 Rust `constants.rs:25-35` 一致。
-/

namespace TexasPoker

namespace Constants

/-! ## 玩家与牌组（对应 `constants.rs:5-20`）-/

/-- 最少开局玩家数（`MIN_PLAYERS_TO_START`）。 -/
def MIN_PLAYERS_TO_START : Nat := 2

/-- 最多玩家数（`MAX_PLAYERS`）。 -/
def MAX_PLAYERS : Nat := 9

/-- 每个玩家手牌数（`CARDS_PER_PLAYER`，德州扑克固定 2 张）。 -/
def CARDS_PER_PLAYER : Nat := 2

/-- 牌组总数（`N_CARDS`）。 -/
def N_CARDS : Nat := 52

/-! ## Round 状态（对应 `constants.rs:22-35`，`round_state` 字段取值）-/

def ROUND_WAITING   : Nat := 0
def ROUND_PREFLOP   : Nat := 2
def ROUND_FLOP      : Nat := 3
def ROUND_TURN      : Nat := 4
def ROUND_RIVER     : Nat := 5
def ROUND_SHOWDOWN  : Nat := 6

/-! ## Shuffle Phase（对应 `constants.rs:37-42`，`shuffle_state.phase` 字段取值）-/

def SHUFFLE_PHASE_NONE           : Nat := 0
def SHUFFLE_PHASE_WAITING        : Nat := 1
def SHUFFLE_PHASE_RECONSTRUCT    : Nat := 2
def SHUFFLE_PHASE_BEFORE_PREFLOP : Nat := 3

/-! ## Reveal Phase（对应 `constants.rs:44-52`，`reveal_token_state.reveal_phase` 字段取值）-/

def REVEAL_PHASE_NONE     : Nat := 0
def REVEAL_PHASE_PREFLOP  : Nat := 1
def REVEAL_PHASE_REDEAL   : Nat := 2
def REVEAL_PHASE_FLOP     : Nat := 3
def REVEAL_PHASE_TURN     : Nat := 4
def REVEAL_PHASE_RIVER    : Nat := 5
def REVEAL_PHASE_SHOWDOWN : Nat := 6

/-! ## Reconstruct Phase（对应 `constants.rs:54-58`，`reconstruct_state.phase` 字段取值）-/

def RECONSTRUCT_PHASE_NONE       : Nat := 0
def RECONSTRUCT_PHASE_COLLECTING : Nat := 1
def RECONSTRUCT_PHASE_COMPLETE   : Nat := 2

/-! ## 下注动作位掩码（对应 `constants.rs:60-65`，`betting.rs` 用）-/

def ACTION_FOLD  : Nat := 1
def ACTION_CHECK : Nat := 2
def ACTION_CALL  : Nat := 4
def ACTION_RAISE : Nat := 8

/-! ## 退款类型（对应 `constants.rs:67-71`）-/

def REFUND_TYPE_STACK_ONLY    : Nat := 0
def REFUND_TYPE_STACK_AND_BET : Nat := 1
def REFUND_TYPE_BET_ONLY      : Nat := 2

/-! ## 踢人原因（对应 `constants.rs:73-77`）-/

def KICK_REASON_TIMEOUT            : Nat := 0
def KICK_REASON_ADMIN              : Nat := 1
def KICK_REASON_RECONSTRUCT_TIMEOUT : Nat := 2

/-! ## 重置原因（对应 `constants.rs:79-85`）-/

def RESET_REASON_TIMEOUT              : Nat := 0
def RESET_REASON_KICK                 : Nat := 1
def RESET_REASON_RECONSTRUCT_FAIL     : Nat := 2
def RESET_REASON_LAST_PLAYER_STANDING : Nat := 3
def RESET_REASON_STATE_INCONSISTENT   : Nat := 4

/-! ## 弃牌原因（对应 `constants.rs:87-91`）-/

def FOLD_REASON_MANUAL      : Nat := 0
def FOLD_REASON_AUTO_TIMEOUT : Nat := 1
def FOLD_REASON_FORCE_ADMIN : Nat := 2

/-! ## 牌组重建原因（对应 `constants.rs:93-96`）-/

def DECK_REBUILD_REASON_SHUFFLE_TIMEOUT     : Nat := 0
def DECK_REBUILD_REASON_RECONSTRUCT_COMPLETE : Nat := 1

/-! ## 金额与超时（对应 `constants.rs:98-116`）-/

/-- 边池总下注上限（防溢出，对应 `MAX_TOTAL_BET`）。 -/
def MAX_TOTAL_BET : Nat := 1000000000000000000

/-- 最小超时阈值（毫秒）。 -/
def MIN_TIMEOUT_MS : Nat := 1000

def DEFAULT_SHUFFLE_TIMEOUT_MS    : Nat := 30000
def DEFAULT_REVEAL_TIMEOUT_MS     : Nat := 30000
def DEFAULT_BETTING_TIMEOUT_MS    : Nat := 30000
def DEFAULT_RECONSTRUCT_TIMEOUT_MS : Nat := 30000
def DEFAULT_SHOWDOWN_DISPLAY_MS   : Nat := 3000
def DEFAULT_HAND_COMPLETE_WAIT_MS : Nat := 5000
def DEFAULT_READY_WAIT_MS         : Nat := 5000

/-! ## Ante 模式（对应 `constants.rs:118-125`）-/

def ANTE_MODE_NONE   : Nat := 0
def ANTE_MODE_NORMAL : Nat := 1
def ANTE_MODE_BBA    : Nat := 2

/-! ## Time Bank（对应 `constants.rs:127-133`）-/

def DEFAULT_TIME_BANK_MS          : Nat := 30000
def TIME_BANK_REFILL_PER_HAND_MS  : Nat := 10000

/-! ## Rake 模式（对应 `constants.rs:135-146`）-/

def RAKE_MODE_NONE      : Nat := 0
def RAKE_MODE_PERCENTAGE : Nat := 1

def DEFAULT_RAKE_BPS : Nat := 500
def DEFAULT_RAKE_CAP : Nat := 1000

/-! ## Run It Twice 模式（对应 `constants.rs:148-153`）-/

def RIT_MODE_DISABLED : Nat := 0
def RIT_MODE_TWICE    : Nat := 1

end Constants

/-! ## Round 状态值基础引理 -/

namespace Constants

theorem round_waiting_is_zero : ROUND_WAITING = 0 := rfl
theorem round_preflop_is_two : ROUND_PREFLOP = 2 := rfl
theorem round_flop_is_three : ROUND_FLOP = 3 := rfl
theorem round_turn_is_four : ROUND_TURN = 4 := rfl
theorem round_river_is_five : ROUND_RIVER = 5 := rfl
theorem round_showdown_is_six : ROUND_SHOWDOWN = 6 := rfl

/-- Round 状态值的严格升序（除 WAITING=0 外）。 -/
theorem round_strictly_increasing :
    ROUND_WAITING < ROUND_PREFLOP ∧
    ROUND_PREFLOP < ROUND_FLOP ∧
    ROUND_FLOP < ROUND_TURN ∧
    ROUND_TURN < ROUND_RIVER ∧
    ROUND_RIVER < ROUND_SHOWDOWN := by
  simp [ROUND_WAITING, ROUND_PREFLOP, ROUND_FLOP,
         ROUND_TURN, ROUND_RIVER, ROUND_SHOWDOWN]

end Constants

end TexasPoker
