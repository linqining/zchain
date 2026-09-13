#!/usr/bin/env bash
# =============================================================================
# scripts/extension_reproducible_build.sh — 扩展可复现构建（WALLET-ACC-8 的
# 仓库内工程面；plan §6.12.4 Extension 1.0）
#
# 做什么：
#   1. 锁定输入并记录：
#      - node 版本（构建/打包环境指纹的一部分；本扩展无 bundler，node 只
#        用于测试与校验，不参与产物字节）；
#      - vendor/wallet-core 的 wasm + 胶水 SHA-256（**锁定输入，不在本脚本
#        内重建**——wasm 构建依赖本机 LLVM clang + wasm-bindgen 0.2.127，
#        产物哈希随工具链变化；发布时以"提交的字节"为准并在此复核）；
#      - 源文件树 SHA-256 清单（git archive 式：内容哈希，路径排序）。
#   2. 两阶段构建：build1/ 与 build2/ 各从零组装一次扩展文件树，统一
#      mtime（SOURCE_DATE_EPOCH，默认 = HEAD 提交时间）、统一文件排序、
#      zip -X（剔除扩展字段）后打包，两个 zip **逐字节比对**：
#      - 一致 → 输出 `REPRODUCIBLE PASS` + 包哈希；
#      - 不一致 → 列出差异文件（常见嫌疑：zip 时间戳/排序/权限）。
#   3. 产出 `extension/dist-checksums.txt`（文件清单 + SHA-256），供发布附随
#      （使用者可对下载的包逐文件复核）。
#
# 诚实边界（不虚标）：
#   - 本脚本覆盖**仓库内可复现的工程面**（文件树 → 包字节）。Extension 1.0
#     的完整可复现声明还要求：wasm 从源码的可复现重建（固定工具链容器）、
#     签名发布（codesign/notarization）与 SBOM——属外部交付，见
#     extension/ACCEPTANCE.md 与 website/RELEASE_PREREQUISITES.md（B4/B 组）。
#   - 已知非确定源清单（如实）：
#     a) vendor/wallet-core/*.wasm：本脚本不重建，按锁定输入复核哈希；
#     b) zip 归档元数据：已用固定 mtime + 排序 + -X 消除；若宿主 zip 版本
#        差异引入 zip64/压缩实现差异，脚本会如实 FAIL 并列出差异；
#     c) .DS_Store / 日志 / E2E 产物截图等本机噪声：一律排除在包外。
#
# 用法（仓库根目录）：
#   bash scripts/extension_reproducible_build.sh
# 环境变量：
#   SOURCE_DATE_EPOCH  固定时间戳（缺省 = git HEAD 提交时间）
# 退出码：0 = REPRODUCIBLE PASS；1 = FAIL（不一致或输入缺失）。
# =============================================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT="$ROOT/extension"
OUT="$EXT/dist-checksums.txt"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/zchain_ext_repro.XXXXXX")"
KEEP="${REPRO_KEEP_ON_FAIL:-0}"
cleanup() {
  if [ "$KEEP" = "1" ] && [ "${STATUS:-}" != "PASS" ] && [ -d "$WORK" ]; then
    mv "$WORK" "$WORK-kept" 2>/dev/null || true
    echo "workdir kept: $WORK-kept（设 REPRO_KEEP_ON_FAIL=0 关闭）"
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- sha256 包装（macOS shasum / Linux sha256sum）----
sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@" | awk '{print $1"  "$2}'
  else sha256sum "$@"; fi
}

# ---- SOURCE_DATE_EPOCH（reproducible-builds.org 约定）----
SDE="${SOURCE_DATE_EPOCH:-}"
if [ -z "$SDE" ]; then
  SDE="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
case "$SDE" in ''|*[!0-9]*) SDE=0;; esac
# touch 时间格式（BSD/macOS 用 -t；GNU 用 -d @epoch——按探测选择）
if touch -d "@$SDE" "$WORK/.probe" 2>/dev/null; then TOUCH() { touch -d "@$SDE" "$@"; }
else
  FMT="$(date -r "$SDE" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$SDE" +%Y%m%d%H%M.%S 2>/dev/null || echo 197001010000.00)"
  TOUCH() { touch -t "$FMT" "$@"; }
fi

echo "== Extension reproducible build =="
echo "SOURCE_DATE_EPOCH = $SDE"

# ---- (1) 锁定输入 ----
NODE_VER="$(node --version 2>/dev/null || echo 'node-unavailable')"
WASM="$EXT/vendor/wallet-core/wallet_core_wasm_bg.wasm"
GLUE="$EXT/vendor/wallet-core/wallet_core_wasm.js"
[ -f "$WASM" ] || { echo "FAIL: 缺少 $WASM（vendor 产物必须先行提交/就位）"; exit 1; }
WASM_SHA="$(sha256 "$WASM" | awk '{print $1}')"
GLUE_SHA="$(sha256 "$GLUE" | awk '{print $1}')"

# 源文件树哈希清单（git archive 式：内容 + 规范化路径，不含本脚本产物）
MANIFEST="$WORK/source-manifest.txt"
: > "$MANIFEST"
while IFS= read -r f; do
  H="$(sha256 "$EXT/$f" | awk '{print $1}')"
  printf '%s  %s\n' "$H" "$f" >> "$MANIFEST"
done < <(cd "$EXT" && find . -type f ! -name '.DS_Store' ! -name 'dist-checksums.txt' \
  ! -name '*.log' ! -path './build*' | LC_ALL=C sort | sed 's|^\./||')

TREE_SHA="$(awk '{print $1}' "$MANIFEST" | LC_ALL=C sort | sha256 | awk '{print $1}')"
echo "node              = $NODE_VER"
echo "wasm sha256       = $WASM_SHA"
echo "glue sha256       = $GLUE_SHA"
echo "source tree sha   = $TREE_SHA ($(wc -l < "$MANIFEST" | tr -d ' ') files)"

# ---- (2) 两阶段构建 ----
# 组装 = 纯文件复制 + mtime 归一（扩展无编译/bundler 步骤；"构建"的确定性
# 责任在归档：排序 + 固定 mtime + zip -X）。两个阶段完全独立执行两遍。
build_stage() {
  local stage="$1"
  mkdir -p "$stage"
  (cd "$EXT" && find . -type f ! -name '.DS_Store' ! -name 'dist-checksums.txt' \
    ! -name '*.log' ! -path './build*' | LC_ALL=C sed 's|^\./||') > "$WORK/files.txt"
  while IFS= read -r rel; do
    mkdir -p "$stage/$(dirname "$rel")"
    cp -p "$EXT/$rel" "$stage/$rel"
  done < "$WORK/files.txt"
  # 归一化：mtime（目录+文件）、权限位收敛（0644）。
  # 注意：**绝不能用 `find -exec TOUCH {} +`**——macOS 大小写不敏感文件系统会
  # 把函数名 TOUCH 解析成 /usr/bin/touch（丢掉 -t 参数）→ mtime 变成"现在"
  # → 两阶段相差数秒 → 归档必然不可复现（这是本脚本开发期实际踩过的坑）。
  # 函数只允许直接调用；find 只调用带完整参数的外部命令。
  TOUCH "$stage"
  while IFS= read -r d; do TOUCH "$d"; done < <(find "$stage" -mindepth 1 -type d | LC_ALL=C sort)
  while IFS= read -r rel; do TOUCH "$stage/$rel"; done < "$WORK/files.txt"
  LC_ALL=C sort "$WORK/files.txt" | while IFS= read -r rel; do chmod 0644 "$stage/$rel" 2>/dev/null || true; done
  # 打包：-X 剔除 uid/gid/扩展时间戳字段；文件列表经 sort 固定条目顺序；
  # 从 stage 内打包使 zip 内路径与宿主绝对路径无关。
  (cd "$stage" && LC_ALL=C sort "$WORK/files.txt" | zip -X -q "$stage.zip" -@)
}

build_stage "$WORK/build1"
build_stage "$WORK/build2"

ZIP1="$WORK/build1.zip"
ZIP2="$WORK/build2.zip"
S1="$(sha256 "$ZIP1" | awk '{print $1}')"
S2="$(sha256 "$ZIP2" | awk '{print $1}')"

# ---- (3) 比对与产出 ----
STATUS="PASS"
if [ "$S1" != "$S2" ]; then
  STATUS="FAIL"
  echo ""
  echo "REPRODUCIBLE FAIL — 两阶段包不一致"
  echo "  build1 sha256 = $S1"
  echo "  build2 sha256 = $S2"
  echo "  差异文件（按成员哈希比对；常见嫌疑：zip 时间戳/权限/条目顺序）："
  # 逐成员哈希比对（unzip -p 单流哈希，与成员名对齐）
  for f in $(unzip -Z1 "$ZIP1" | LC_ALL=C sort); do
    H1="$(unzip -p "$ZIP1" "$f" | sha256 | awk '{print $1}')"
    H2="$(unzip -p "$ZIP2" "$f" | sha256 | awk '{print $1}')"
    [ "$H1" != "$H2" ] && echo "    DIFF: $f"
  done
  # 成员集合差异
  comm -3 <(unzip -Z1 "$ZIP1" | LC_ALL=C sort) <(unzip -Z1 "$ZIP2" | LC_ALL=C sort) | sed 's/^/    SET: /'
else
  echo ""
  echo "REPRODUCIBLE PASS"
  echo "  build1 sha256 = $S1"
  echo "  build2 sha256 = $S2"
fi

# dist-checksums.txt：打包文件的清单 + SHA-256（发布附随件）。
{
  echo "# ZChain Wallet Extension — dist checksums（extension_reproducible_build.sh 产出）"
  echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# reproducible: $STATUS"
  echo "# package: extension-0.4.0-alpha.zip sha256: $S1"
  echo "# node: $NODE_VER"
  echo "# vendor/wallet_core_wasm_bg.wasm sha256: $WASM_SHA"
  echo "# vendor/wallet_core_wasm.js sha256: $GLUE_SHA"
  echo "# source-tree sha256 (sorted content hashes): $TREE_SHA"
  echo "# SOURCE_DATE_EPOCH: $SDE"
  echo "#"
  cat "$MANIFEST"
} > "$OUT"
echo "dist-checksums: ${OUT}（$(grep -c . "$OUT") 行）"

[ "$STATUS" = "PASS" ] || exit 1
