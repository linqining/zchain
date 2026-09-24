import Lake
open Lake DSL

package poker_lean_extracted where
  name := `poker_lean_extracted

require aeneas from "../tools_external/aeneas/backends/lean"
require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.31.0"

@[default_target]
lean_lib PokerLeanExtracted where
  roots := #[`PokerLeanExtracted, `PokerSettlementCore]
