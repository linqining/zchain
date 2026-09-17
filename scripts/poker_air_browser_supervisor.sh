#!/usr/bin/env bash
# browser 阶段监督进程：崩溃自动重启，直到 DONE（达标+Portal 验收）或次数
# 耗尽。独立于 dev_poker_air.sh 进程树（nohup/disown 启动）——主脚本对
# node/chrome 的信号操作不会再级联杀死监督者本身。
# 用法: poker_air_browser_supervisor.sh <run_dir> <target_hands> [attempts]
set -u
RUN_DIR="${1:?run_dir}"
TARGET="${2:?target}"
ATTEMPTS="${3:-10}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo $$ > "$RUN_DIR/browser-supervisor.pid"
rm -f "$RUN_DIR/browser.done" "$RUN_DIR/browser.failed"
attempts=0
while [ "$attempts" -lt "$ATTEMPTS" ]; do
  attempts=$((attempts + 1))
  echo "[$(date +%T)] browser attempt $attempts/$ATTEMPTS 启动" >> "$RUN_DIR/browser.log"
  node "$ROOT/scripts/poker_air_browser.mjs" >> "$RUN_DIR/browser.log" 2>&1
  code=$?
  if [ "$code" = 0 ] && grep -q "DONE:" "$RUN_DIR/browser.log" 2>/dev/null; then
    echo "[$(date +%T)] browser DONE" >> "$RUN_DIR/browser.log"
    touch "$RUN_DIR/browser.done"
    exit 0
  fi
  echo "[$(date +%T)] [supervisor] attempt $attempts failed (exit $code)；清理 Chrome 残留后重启" >> "$RUN_DIR/browser.log"
  pkill -f "poker_air_chrome" 2>/dev/null || true
  sleep 10
done
touch "$RUN_DIR/browser.failed"
echo "[$(date +%T)] [supervisor] exhausted $ATTEMPTS attempts" >> "$RUN_DIR/browser.log"
exit 1
