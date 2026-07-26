import Lake
open Lake DSL

package poker_lean where
  name := `poker_lean

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.13.0"

@[default_target]
lean_lib PokerLean where
  roots := #[`PokerLean]
