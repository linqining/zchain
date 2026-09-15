#!/usr/bin/env bash
# =============================================================================
# extension/scripts/pack.sh — 插件打包脚本（产出可在 Chrome 安装的扩展包）
#
# 做什么：
#   1. 校验 manifest.json（JSON 合法、MV3 关键字段）与运行时必需文件；
#   2. 快速静态检查：对所有打包内 .js 执行 node --check（语法层）；
#   3. 组装运行时文件树（排除 tests/、demo/、日志、e2e 产物、.DS_Store 等
#      开发文件）→ dist/unpacked/（可直接被 Chrome“加载已解压的扩展程序”）；
#   4. 打包 dist/zchain-wallet-extension-v<版本>.zip：
#      - manifest.json 位于 zip 根（Chrome Web Store / 解压加载的要求）；
#      - 固定 mtime + 排序 + zip -X（产物字节确定，便于复核）；
#   5. 产出 SHA256SUMS.txt（zip 与逐文件哈希），打印 Chrome 安装步骤。
#
# 用法：
#   bash extension/scripts/pack.sh                 # 打包 + 静态校验
#   bash extension/scripts/pack.sh --verify        # 追加：Chrome 真实加载验证
#   bash extension/scripts/pack.sh --out DIR       # 自定义输出目录（默认 extension/dist）
#   bash extension/scripts/pack.sh --skip-checks   # 跳过 node --check（更快）
#
# Chrome 安装（三选一）：
#   a) 加载已解压的扩展程序：chrome://extensions → 开发者模式 →
#      “加载已解压的扩展程序” → 选择 dist/unpacked/（或解压后的 zip 目录）；
#   b) Chrome Web Store：直接上传 dist/*.zip（开发者后台）；
#   c) Chrome for Testing / Chromium / 企业策略白名单：
#      chrome --load-extension=/绝对路径/dist/unpacked
#      （Google 品牌 Chrome 137+ 命令行 --load-extension 已被禁用，用 a/b）。
#
# 退出码：0 = 打包成功（--verify 时含加载验证 PASS）；1 = 失败。
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/dist"
VERIFY=0
SKIP_CHECKS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_DIR="$(cd "$2" && pwd)"; shift 2 ;;
    --verify) VERIFY=1; shift ;;
    --skip-checks) SKIP_CHECKS=1; shift ;;
    *) echo "未知参数：$1（支持 --out DIR / --verify / --skip-checks）" >&2; exit 1 ;;
  esac
done

echo "==> 打包目录：${ROOT}"
echo "==> 输出目录：${OUT_DIR}"

# ---- 1. manifest 校验 ----
MANIFEST="${ROOT}/manifest.json"
if [ ! -f "${MANIFEST}" ]; then echo "FAIL: 缺少 manifest.json" >&2; exit 1; fi
MANIFEST_INFO="$(node -e '
  const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  if (m.manifest_version !== 3) throw new Error("manifest_version 必须 = 3");
  for (const k of ["name", "version", "background", "action"]) {
    if (m[k] === undefined) throw new Error("缺少字段: " + k);
  }
  process.stdout.write([m.version, m.version_name ?? "-", "MV3-OK"].join("|"));
' "${MANIFEST}")"
VERSION="$(echo "${MANIFEST_INFO}" | cut -d'|' -f1)"
VERSION_NAME="$(echo "${MANIFEST_INFO}" | cut -d'|' -f2)"
echo "==> 版本：${VERSION}（${VERSION_NAME}）| MV3-OK"

# ---- 2. 运行时必需文件 ----
REQUIRED="manifest.json background/service_worker.js popup/popup.html popup/popup.js \
content/bridge.js content/inpage.js common/evm/crypto.js common/stark/curve.js \
vendor/wallet-core/wallet_core_wasm_bg.wasm vendor/wallet-core/wallet_core_wasm.js \
vendor/stwo-verify/stwo_verify_wasm.wasm portal/portal.html adapters/index.js"
for f in ${REQUIRED}; do
  if [ ! -f "${ROOT}/${f}" ]; then echo "FAIL: 缺少运行时文件 ${f}" >&2; exit 1; fi
done
echo "==> 运行时必需文件齐全（${#REQUIRED} 项抽查）"

# ---- 3. 组装运行时文件树 ----
STAGE="${OUT_DIR}/unpacked"
rm -rf "${STAGE}"
mkdir -p "${STAGE}"
# 只复制运行时面：开发目录（tests/ demo/ docs/ scripts/）与产物（日志/截图/
# result json/SHA 清单）一律不进包。
cp "${MANIFEST}" "${STAGE}/"
[ -f "${ROOT}/README.md" ] && cp "${ROOT}/README.md" "${STAGE}/"
for dir in background popup content common adapters portal vendor; do
  cp -R "${ROOT}/${dir}" "${STAGE}/${dir}"
done
# 清理包内噪声（macOS 元数据等）
find "${STAGE}" -name '.DS_Store' -type f -delete 2>/dev/null || true

# ---- 4. 静态校验（node --check 所有 .js；不通过则打包失败）----
if [ "${SKIP_CHECKS}" = "0" ]; then
  JS_COUNT=0
  while IFS= read -r js; do
    node --check "${js}" || { echo "FAIL: 语法错误 ${js}" >&2; exit 1; }
    JS_COUNT=$((JS_COUNT + 1))
  done < <(find "${STAGE}" -name '*.js' -type f | LC_ALL=C sort)
  echo "==> node --check 通过：${JS_COUNT} 个 .js"
  # wasm 体积抽查（防止空文件/截断）
  WASM_BYTES=$(wc -c < "${STAGE}/vendor/wallet-core/wallet_core_wasm_bg.wasm" | tr -d ' ')
  if [ "${WASM_BYTES}" -lt 100000 ]; then echo "FAIL: wallet-core wasm 异常（${WASM_BYTES} 字节）" >&2; exit 1; fi
  echo "==> wallet-core wasm 体积正常（${WASM_BYTES} 字节）"
fi

FILE_COUNT=$(find "${STAGE}" -type f | wc -l | tr -d ' ')
echo "==> 运行时文件树：${FILE_COUNT} 个文件 → ${STAGE}"

# ---- 5. 打包 zip（manifest 在根；固定 mtime + 排序 + -X）----
mkdir -p "${OUT_DIR}"
ZIP_PATH="${OUT_DIR}/zchain-wallet-extension-v${VERSION}.zip"
rm -f "${ZIP_PATH}"
# 固定时间戳（缺省 = git HEAD 提交时间）：同一份源码两次打包字节一致
STAMP="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT}" log -1 --format=%ct 2>/dev/null || true)}"
STAMP="${STAMP:-$(date +%s)}"
while IFS= read -r d; do touch -t "$(date -r "${STAMP}" +%Y%m%d%H%M.%S)" "${d}"; done \
  < <(find "${STAGE}" -mindepth 1 -type d | LC_ALL=C sort)
find "${STAGE}" -type f | LC_ALL=C sort | while IFS= read -r f; do
  touch -t "$(date -r "${STAMP}" +%Y%m%d%H%M.%S)" "${f}"
done
FILES_LIST="${OUT_DIR}/.files.txt"
(cd "${STAGE}" && find . -type f | LC_ALL=C sort | sed 's|^\./||') > "${FILES_LIST}"
(cd "${STAGE}" && LC_ALL=C sort "${FILES_LIST}" | zip -X -q "${ZIP_PATH}" -@)
rm -f "${FILES_LIST}"

# ---- 6. SHA256 清单 ----
if command -v shasum >/dev/null 2>&1; then SHA_CMD="shasum -a 256"; else SHA_CMD="sha256sum"; fi
SUMS="${OUT_DIR}/SHA256SUMS.txt"
{
  echo "# zchain-wallet-extension v${VERSION}"
  ${SHA_CMD} "${ZIP_PATH}" | awk -v z="$(basename "${ZIP_PATH}")" '{print $1"  "z}'
  (cd "${STAGE}" && find . -type f | LC_ALL=C sort | sed 's|^\./||') | while IFS= read -r f; do
    ${SHA_CMD} "${STAGE}/${f}" | awk -v f="${f}" '{print $1"  "f}'
  done
} > "${SUMS}"

ZIP_SHA=$(${SHA_CMD} "${ZIP_PATH}" | awk '{print $1}')
ZIP_SIZE=$(wc -c < "${ZIP_PATH}" | tr -d ' ')
echo "==> 打包完成：${ZIP_PATH}（${ZIP_SIZE} 字节）"
echo "    SHA-256: ${ZIP_SHA}"
echo "    校验清单：${SUMS}"

# ---- 7. Chrome 安装说明 ----
cat <<'EOF'

Chrome 安装方式（三选一）：
  a) chrome://extensions → 打开“开发者模式”→“加载已解压的扩展程序”
     → 选择目录：dist/unpacked（或把 zip 解压后选择该目录）
  b) Chrome Web Store 开发者后台直接上传 dist/*.zip
  c) Chrome for Testing / Chromium：--load-extension=<dist/unpacked 绝对路径>
     （Google 品牌 Chrome 137+ 已禁用命令行 --load-extension，请用 a/b）
EOF

# ---- 8. 可选：真实加载验证 ----
if [ "${VERIFY}" = "1" ]; then
  echo "==> 验证：Chrome 真实加载 dist/unpacked ..."
  node "${ROOT}/scripts/verify_pack.mjs" "${STAGE}"
  echo "==> 验证 PASS：service worker 启动 + popup 渲染正常"
fi
