import Lake
open Lake DSL

package poker_lean where
  name := `poker_lean

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.13.0"

@[default_target]
lean_lib PokerLean where
  roots := #[`PokerLean]

/-- 差分对拍 runner（方案 C）：编译为原生二进制，避免解释器栈溢出。 -/
@[default_target]
lean_exe differential where
  root := `Differential.Main
