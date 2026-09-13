#!/usr/bin/env bash
# =============================================================================
# M9-ACC-3 演练证据：sequencer 重启（WAL 全量重放）恢复时间（RTO）实测。
#
# 流程（对应 docs/runbook.md §1 演练步骤）：
#   1. rake_audit selftest 生成 demo WAL，记录"重启前"链头哈希（HEAD_before）；
#   2. 模拟重启：重新执行 Sequencer::replay（经 rake_audit export 触发，
#      内部对全链验签 + 逐帧状态根重验），计时并取"重启后"链头哈希；
#   3. HEAD_before == HEAD_after（stdout 与 audit.json 双通道比对）→ PASS；
#   4. 对导出的审计文件再跑一次 verify（应零差异，退出码 0）。
#
# 说明：计时段 = replay + 审计 JSON 写出（export 子命令），是 RTO 的保守
# 上界（纯 replay 更快）。RTO_TARGET_MS 未设置时只打印 RTO 不做门槛判定。
#
# 用法：scripts/drill_sequencer_restart.sh
# 环境变量：RAKE_AUDIT_BIN（默认 target/release/rake_audit）、RTO_TARGET_MS
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${RAKE_AUDIT_BIN:-$REPO_ROOT/target/release/rake_audit}"

if [ ! -x "$BIN" ]; then
  echo "[drill] 未找到 $BIN，先构建（--release）……"
  (cd "$REPO_ROOT" && cargo build --release -p poker-appchain --bin rake_audit)
  BIN="$REPO_ROOT/target/release/rake_audit"
fi

# 毫秒时钟：优先 perl（macOS 自带），回退 python3
now_ms() {
  if command -v perl >/dev/null 2>&1; then
    perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1000'
  else
    python3 -c 'import time; print(round(time.time()*1000))'
  fi
}

WORK="$(mktemp -d /tmp/zchain-drill-sequencer-restart.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "== [1/4] selftest 生成 demo WAL（3 手，含 uncalled 返还层与 ZERO 桌）=="
"$BIN" selftest --dir "$WORK" | tee "$WORK/selftest.out"
WAL="$(grep '^WAL=' "$WORK/selftest.out" | cut -d= -f2-)"
PUB="$(grep '^SEQUENCER_PUBLIC=' "$WORK/selftest.out" | cut -d= -f2-)"
HEAD_BEFORE="$(grep '^WAL_HEAD_HASH=' "$WORK/selftest.out" | cut -d= -f2-)"
echo "HEAD_before = $HEAD_BEFORE"

echo "== [2/4] 模拟重启：WAL 全量重放（验签 + 状态根重验）并导出审计 =="
T0="$(now_ms)"
"$BIN" export \
  --appchain-wal "$WAL" \
  --sequencer-public "$PUB" \
  --from-ts 0 --to-ts 99999999999999 \
  --out "$WORK/audit.json" | tee "$WORK/export.out"
T1="$(now_ms)"
RTO_MS=$((T1 - T0))
HEAD_AFTER_STDOUT="$(grep -o 'wal_head_hash=[0-9a-f]*' "$WORK/export.out" | head -1 | cut -d= -f2-)"
HEAD_AFTER_JSON="$(grep '"wal_head_hash"' "$WORK/audit.json" | grep -o '[0-9a-f]\{64\}' | head -1)"

echo "== [3/4] 链头哈希比对（重启前 vs 重启后；stdout 与审计文件双通道）=="
echo "HEAD_after  = $HEAD_AFTER_STDOUT"
STATUS=PASS
if [ "$HEAD_BEFORE" != "$HEAD_AFTER_STDOUT" ] || [ "$HEAD_BEFORE" != "$HEAD_AFTER_JSON" ]; then
  STATUS=FAIL
  echo "MISMATCH: 重放后的链头哈希与重启前不一致"
fi

echo "== [4/4] 审计文件独立复验（期望退出码 0 = 零差异）=="
if ! "$BIN" verify --audit "$WORK/audit.json"; then
  STATUS=FAIL
  echo "verify 失败"
fi

echo
echo "RTO(replay+export) = ${RTO_MS} ms  [目标值（待实测校准）；计时含审计 JSON 写出，为 RTO 上界]"
if [ -n "${RTO_TARGET_MS:-}" ]; then
  if [ "$RTO_MS" -le "$RTO_TARGET_MS" ]; then
    echo "RTO 门槛 ${RTO_TARGET_MS} ms：达标"
  else
    echo "RTO 门槛 ${RTO_TARGET_MS} ms：超限"
    STATUS=FAIL
  fi
fi

echo "DRILL_${STATUS}: sequencer restart (WAL replay) head_hash 一致性 + RTO 见上"
[ "$STATUS" = "PASS" ]
