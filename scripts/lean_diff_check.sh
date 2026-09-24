#!/usr/bin/env bash
# 差分对拍（方案 C）：Rust 真实实现 vs Lean 手工镜像模型
# 文档：.trae/documents/rust-to-lean-proof-schemes.md
#
# 用法：scripts/lean_diff_check.sh [用例目录（默认 /tmp/zchain_diff）]
# 退出码：0 = 全部一致；1 = 存在不一致；2 = 数据问题

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIFF_DIR="${1:-${ZCHAIN_DIFF_DIR:-/tmp/zchain_diff}}"

echo "== 1/2 Rust 侧生成向量（真实实现输出）=="
cd "$ROOT/poker_l1"
ZCHAIN_DIFF_DIR="$DIFF_DIR" cargo test -p poker_l1 --lib differential -- --nocapture

echo "== 2/2 Lean 侧模型求值并比对 =="
cd "$ROOT/poker_lean"
lake env lean --run Differential/Main.lean "$DIFF_DIR"
