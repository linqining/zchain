import PokerLeanExtracted.Model.Constants
import PokerLeanExtracted.Model.Card
import PokerLeanExtracted.Model.Betting
import PokerLeanExtracted.Model.SidePot
import PokerLeanExtracted.Model.HandEvaluator
import PokerLeanExtracted.Bridge.SidePot

/-!
# poker_lean_extracted — Aeneas 提取 + Bridge 等价定理项目

架构（`.trae/documents/rust-to-lean-proof-schemes.md` 方案 A1）：

- `Extracted/`：Aeneas 从真实 Rust 代码生成的 Lean 纯函数（**不手改**）
- `Model/`：`poker_lean`（Lean 4.13 + Mathlib）手写镜像模型的 Mathlib-free
  定义副本（供等价定理引用；权威证明在 poker_lean）
- `Bridge/`：等价定理 `Extracted.fn ≡ Model.fn`（待 Aeneas 产物落地）

工具链：Lean 4.31.0 + Aeneas 库（`tools_external/aeneas`，路径依赖）+ Mathlib
v4.31.0（云缓存）。与 `poker_lean` 的 4.13 相互隔离，跨版本一致性由
`scripts/lean_diff_check.sh` 差分对拍（三方：Rust / 4.13 模型 / 提取代码）保证。
-/
