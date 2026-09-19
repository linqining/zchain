#!/usr/bin/env bash
# 牌桌设计稿逐屏出图 —— 与 design/figma/build.mjs 同一 Chrome for Testing 定位方式
# 用法: ./render.sh [屏 id...]        默认全部
#       GROUND=night ./render.sh t1   出夜场底
set -euo pipefail
cd "$(dirname "$0")"

CHROME="${ZCHAIN_CFT_CHROME:-}"
if [[ -z "$CHROME" ]]; then
  CHROME=$(find /tmp/chrome -maxdepth 6 -name "Google Chrome for Testing" -type f 2>/dev/null | head -1)
fi
if [[ -z "$CHROME" ]]; then echo "Chrome for Testing 未找到;请设置 ZCHAIN_CFT_CHROME"; exit 1; fi

GROUND="${GROUND:-paper}"
SRC="$PWD/zchain-table-ui.html"
OUT="png"; mkdir -p "$OUT"
IDS=("$@"); if [[ ${#IDS[@]} -eq 0 ]]; then IDS=(t1 t2 t3 t4 t5 t6 g1 g2 ds); fi

for id in "${IDS[@]}"; do
  f="$OUT/${GROUND}--${id}.png"
  "$CHROME" --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size=1280,800 --screenshot="$f" \
    "file://$SRC?g=$GROUND#$id" 2>/dev/null
  printf '%-4s → %s\n' "$id" "$f"
done
