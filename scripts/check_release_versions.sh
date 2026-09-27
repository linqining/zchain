#!/usr/bin/env bash
# WEB-ACC-5：发布版本一致性检查。
#
# 比对以下位置引用的 ABI 版本串，全部一致且非空 → exit 0，否则 exit 1：
#   1. poker-appchain/docs/ABI.md        标题行的版本（ABI 唯一事实源）
#   2. website/build.py                  SITE["ABI_VERSION"]
#   3. website/build.py                  FOOTER_VERSION 中的 "ABI vX.Y.Z"
#   4. website/docs-status.md            "ABI_VERSION = vX.Y.Z" 约定值
#
# 注：website/ 已迁移至 poker_texas_air 仓库。第 2-4 项默认在相邻仓库
# ../poker_texas_air/website 查找（可用 WEBSITE_DIR 环境变量覆盖）；
# 找不到时跳过这三项，仅校验 ABI.md。
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SEMVER_RE='v[0-9]+(\.[0-9]+){1,2}'   # 仓库实际使用 v1.3 与 v1.2.2 两档写法，统一宽松提取

abi_md="$(head -1 poker-appchain/docs/ABI.md | grep -oE "$SEMVER_RE" | head -1)"

WEBSITE_DIR="${WEBSITE_DIR:-../poker_texas_air/website}"
site_active=0
build_py=""; footer=""; docs_status=""
if [ -f "$WEBSITE_DIR/build.py" ]; then
  site_active=1
  build_py="$(grep -oE '"ABI_VERSION": "v[0-9.]+"' "$WEBSITE_DIR/build.py" | grep -oE "$SEMVER_RE" | head -1)"
  footer="$(grep -oE '"FOOTER_VERSION": "[^"]*"' "$WEBSITE_DIR/build.py" | grep -oE "ABI $SEMVER_RE" | grep -oE "$SEMVER_RE" | head -1)"
  docs_status="$(grep -m1 -oE "ABI_VERSION = $SEMVER_RE" "$WEBSITE_DIR/docs-status.md" | grep -oE "$SEMVER_RE" | head -1)"
else
  echo "SKIP: 未找到 $WEBSITE_DIR/build.py（website 已迁移至 poker_texas_air 仓库），跳过官网版本检查"
fi

echo "ABI.md           : ${abi_md:-<missing>}"
if [ "$site_active" = 1 ]; then
  echo "build.py ABI     : ${build_py:-<missing>}"
  echo "build.py FOOTER  : ${footer:-<missing>}"
  echo "docs-status.md   : ${docs_status:-<missing>}"
else
  echo "build.py ABI     : <skipped>"
  echo "build.py FOOTER  : <skipped>"
  echo "docs-status.md   : <skipped>"
fi

fail=0
[ -z "$abi_md" ] && fail=1
if [ "$site_active" = 1 ]; then
  for v in "$build_py" "$footer" "$docs_status"; do
    if [ -z "$v" ]; then
      fail=1
    elif [ "$v" != "$abi_md" ]; then
      fail=1
    fi
  done
fi

if [ "$fail" = "0" ]; then
  echo "OK: 版本串一致（${abi_md}）"
  exit 0
fi
echo "FAIL: 版本串缺失或不一致（以 ABI.md 为准修正）"
exit 1
