/-!
# 常量（移植自 `poker_lean/PokerLean/State/Constants.lean`，镜像 `constants.rs`）

Mathlib-free：本文件只含纯定义，供 `poker_lean_extracted` 项目的 Bridge 等价
定理引用。权威证明版本在 `poker_lean`（Lean 4.13 + Mathlib）。
-/

namespace TexasPoker

/-- u64 上限（2^64 - 1）。 -/
def U64_MAX : Nat := 18446744073709551615

/-- 单座位总下注上限（10^18）。 -/
def MAX_TOTAL_BET : Nat := 1000000000000000000

/-- 动作位掩码（对应 `constants.rs:62-65`）。 -/
def ACTION_FOLD  : Nat := 1
def ACTION_CHECK : Nat := 2
def ACTION_CALL  : Nat := 4
def ACTION_RAISE : Nat := 8

end TexasPoker
