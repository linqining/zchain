#!/usr/bin/env bash
# WEB-ACC-5：发布版本一致性检查。
#
# 比对以下位置引用的 ABI 版本串，全部一致且非空 → exit 0，否则 exit 1：
#   1. poker-appchain/docs/ABI.md        标题行的版本（ABI 唯一事实源）
#   2. website/build.py                  SITE["ABI_VERSION"]
#   3. website/build.py                  FOOTER_VERSION 中的 "ABI vX.Y.Z"
#   4. website/docs-status.md            "ABI_VERSION = vX.Y.Z" 约定值
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SEMVER_RE='v[0-9]+\.[0-9]+\.[0-9]+'

abi_md="$(head -1 poker-appchain/docs/ABI.md | grep -oE "$SEMVER_RE" | head -1)"
build_py="$(grep -oE '"ABI_VERSION": "v[0-9.]+"' website/build.py | grep -oE "$SEMVER_RE" | head -1)"
footer="$(grep -oE '"FOOTER_VERSION": "[^"]*"' website/build.py | grep -oE "ABI $SEMVER_RE" | grep -oE "$SEMVER_RE" | head -1)"
docs_status="$(grep -m1 -oE "ABI_VERSION = $SEMVER_RE" website/docs-status.md | grep -oE "$SEMVER_RE" | head -1)"

echo "ABI.md           : ${abi_md:-<missing>}"
echo "build.py ABI     : ${build_py:-<missing>}"
echo "build.py FOOTER  : ${footer:-<missing>}"
echo "docs-status.md   : ${docs_status:-<missing>}"

fail=0
for v in "$abi_md" "$build_py" "$footer" "$docs_status"; do
  if [ -z "$v" ]; then
    fail=1
  elif [ "$v" != "$abi_md" ]; then
    fail=1
  fi
done

if [ "$fail" = "0" ]; then
  echo "OK: 版本串一致（$abi_md）"
  exit 0
fi
echo "FAIL: 版本串缺失或不一致（以 ABI.md 为准修正）"
exit 1
