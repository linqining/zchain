#!/usr/bin/env bash
# check_vendor_drift.sh — 检测 wallet-app/vendor/<crate> 快照与 canonical <crate>/
# 的漂移（信息性 CI 步骤使用，continue-on-error）。
#
# 语义：
# - 对每个 crate 用 `diff -rq` 递归比较 vendor 快照与 canonical 目录；
# - 排除 Cargo.lock 与 target/（本地构建状态，不属源码漂移）；
# - 每个 crate 输出差异/缺失文件的前 20 行 + 总数；
# - 任一 crate 存在漂移即 exit 1（调用方决定是否阻塞）。
#
# 兼容性：避免 mapfile 等 bash 4+ 特性（macOS 默认 bash 3.2 可运行）。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/wallet-app/vendor"
CRATES="poker-appchain poker-wallet poker-settlement-core"
MAX_LINES=20

drift_total=0
checked=0

for crate in $CRATES; do
  checked=$((checked + 1))
  canonical="$REPO_ROOT/$crate"
  vendored="$VENDOR_DIR/$crate"

  if [ ! -d "$canonical" ]; then
    echo "[DRIFT] $crate: canonical 目录缺失：$canonical"
    drift_total=$((drift_total + 1))
    continue
  fi
  if [ ! -d "$vendored" ]; then
    echo "[DRIFT] $crate: vendor 快照目录缺失：$vendored"
    drift_total=$((drift_total + 1))
    continue
  fi

  # diff -rq 有差异时 exit 1，属预期，不做失败处理。
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done < <(diff -rq --exclude=Cargo.lock --exclude=target "$vendored" "$canonical" || true)

  count=${#lines[@]}
  if [ "$count" -eq 0 ]; then
    echo "[OK]    $crate: vendor 快照与 canonical 一致（0 差异）"
    continue
  fi

  echo "[DRIFT] $crate: $count 处差异/缺失（前 $MAX_LINES 行）："
  i=0
  for line in "${lines[@]}"; do
    i=$((i + 1))
    if [ "$i" -gt "$MAX_LINES" ]; then
      echo "  ……（其余 $((count - MAX_LINES)) 行省略）"
      break
    fi
    echo "  $line"
  done
  drift_total=$((drift_total + 1))
done

echo
echo "vendor drift 汇总：$drift_total/$checked 个 crate 存在漂移。"
if [ "$drift_total" -gt 0 ]; then
  echo "（信息性检查：漂移不代表构建失败，但 vendor 快照需要重新同步时请以 canonical 为准。）"
  exit 1
fi
exit 0
