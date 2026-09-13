#!/usr/bin/env bash
# M8：本地 CI 等价门——与 .github/workflows/ci.yml 同一组检查，本地汇总
# PASS/FAIL/SKIP 并以汇总退出码收束（任一 FAIL → 1）。
#
# 用法：
#   bash scripts/ci_local.sh            # 跑全部门
#   bash scripts/ci_local.sh <gate>...  # 只跑指定门（build/test-core/...）
#
# 说明：gateway-smoke 依赖 scripts/explorer_gateway_smoke.sh（独立交付物）；
# 脚本尚不存在时该项标 SKIP 并在输出注明，不影响其余门的真跑。
# 全部 Rust 构建与测试一律 --release；toolchain 由根 rust-toolchain.toml 决定。

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
SKIP=0
declare -a RESULTS=()

run_gate() {
  local name="$1"
  shift
  local log
  # BSD mktemp：X 序列必须在模板末尾
  log="$(mktemp "${TMPDIR:-/tmp}/ci_local.$$.XXXXXXXX")"
  if "$@" >"$log" 2>&1; then
    RESULTS+=("PASS  $name")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL  $name  (log: $log)")
    FAIL=$((FAIL + 1))
  fi
}

skip_gate() {
  local name="$1"
  local reason="$2"
  RESULTS+=("SKIP  $name  ($reason)")
  SKIP=$((SKIP + 1))
}

gate_build()            { cargo build --release; }
gate_test_core_l1()     { cargo test --release -p poker_l1 --lib; }
gate_test_core_appchain() { cargo test --release -p poker-appchain; }
gate_test_core_settle() { cargo test --release -p poker-settlement-core; }
gate_test_core_wallet() { cargo test --release -p poker-wallet; }
gate_test_extension()   { bash -c 'cd extension && node --test tests/*.test.js tests/adapters/*.test.js'; }
gate_website_build()    { python3 website/build.py; }
gate_website_banned()   { python3 website/tools/scan_banned_words.py; }
gate_website_links()    { python3 website/tools/check_links.py; }
gate_website_a11y()     { python3 website/tools/check_a11y.py; }

gate_gateway_smoke() {
  if [ -f scripts/explorer_gateway_smoke.sh ]; then
    bash scripts/explorer_gateway_smoke.sh
  else
    return 42  # 由调用方翻译为 SKIP
  fi
}

run_gateway_gate() {
  local log
  log="$(mktemp "${TMPDIR:-/tmp}/ci_local.$$.XXXXXXXX")"
  gate_gateway_smoke >"$log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ]; then
    RESULTS+=("PASS  gateway-smoke")
    PASS=$((PASS + 1))
  elif [ $rc -eq 42 ]; then
    RESULTS+=("SKIP  gateway-smoke  (scripts/explorer_gateway_smoke.sh 尚未交付；CI 中为独立 job)")
    SKIP=$((SKIP + 1))
  else
    RESULTS+=("FAIL  gateway-smoke  (log: $log)")
    FAIL=$((FAIL + 1))
  fi
}

WANT=("$@")
if [ ${#WANT[@]} -eq 0 ]; then
  WANT=(build test-core test-extension website-scans gateway-smoke fuzz-smoke release-prep)
fi

wants() {
  local g
  for g in "${WANT[@]}"; do
    [ "$g" = "$1" ] && return 0
  done
  return 1
}

if wants build; then
  echo "== gate: build =="
  run_gate "build (cargo build --release)" gate_build
fi

if wants test-core; then
  echo "== gate: test-core =="
  run_gate "test-core: poker_l1 --lib" gate_test_core_l1
  run_gate "test-core: poker-appchain" gate_test_core_appchain
  run_gate "test-core: poker-settlement-core" gate_test_core_settle
  run_gate "test-core: poker-wallet" gate_test_core_wallet
fi

if wants test-extension; then
  echo "== gate: test-extension =="
  run_gate "test-extension: node --test" gate_test_extension
fi

if wants website-scans; then
  echo "== gate: website-scans =="
  run_gate "website: build.py" gate_website_build
  run_gate "website: scan_banned_words" gate_website_banned
  run_gate "website: check_links" gate_website_links
  run_gate "website: check_a11y" gate_website_a11y
fi

if wants gateway-smoke; then
  echo "== gate: gateway-smoke =="
  run_gateway_gate
fi

if wants fuzz-smoke; then
  echo "== gate: fuzz-smoke =="
  # 短预算冒烟与 .github/workflows/ci.yml 的 fuzz-smoke job 同口径；
  # cargo-fuzz 未安装时 SKIP（CI runner 上由 job 自行安装）。
  if command -v cargo-fuzz >/dev/null 2>&1; then
    run_gate "fuzz-smoke: note_abi" bash -c 'cd fuzz && cargo fuzz run note_abi -- -max_total_time=120'
    run_gate "fuzz-smoke: soft_confirm_api" bash -c 'cd fuzz && cargo fuzz run soft_confirm_api -- -max_total_time=120'
    run_gate "fuzz-smoke: settlement_witness" bash -c 'cd fuzz && cargo fuzz run settlement_witness -- -max_total_time=120'
  else
    skip_gate "fuzz-smoke (cargo-fuzz 未安装；CI fuzz-smoke job 覆盖，完整预算见 fuzz/README.md)"
  fi
fi

if wants release-prep; then
  echo "== gate: release-prep =="
  # WEB-ACC-5：SBOM（CycloneDX，全 workspace，JSON）+ 版本一致性检查，
  # 与 .github/workflows/ci.yml 的 release-prep job 同口径；
  # cargo-cyclonedx 未安装时 SKIP（CI runner 上由 job 自行安装）。
  if command -v cargo-cyclonedx >/dev/null 2>&1; then
    run_gate "release-prep: cargo cyclonedx (SBOM json)" bash -c 'cargo cyclonedx --all --format json'
    run_gate "release-prep: version consistency" bash scripts/check_release_versions.sh
  else
    skip_gate "release-prep (cargo-cyclonedx 未安装；CI release-prep job 覆盖)"
  fi
fi

echo
echo "==================== ci_local summary ===================="
for r in "${RESULTS[@]}"; do
  echo "$r"
done
echo "=========================================================="
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"

if [ $FAIL -gt 0 ]; then
  exit 1
fi
exit 0
