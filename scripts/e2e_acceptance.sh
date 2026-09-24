#!/usr/bin/env bash
# e2e 验收矩阵（常规测试入口；2026-09-13 立档）。
#
# 运行全量验收：workspace release 套件 + extension 单测/wasm 冒烟 +
# 节点 e2e（单进程/多节点）+ 场景演练（串行——并发 7 节点演练会因 CPU
# 争用产生时序假阴性）+ 独立 workspace（wallet-app / poker-appchain-texasair /
# stwo-wasm-verify）+ fuzz 冒烟。结果逐门记录到 docs/test-records/ 下
# 带时间戳的记录文件（常规测试留痕，M9 运维口径）。
#
# 用法：
#   bash scripts/e2e_acceptance.sh                 # 全量（约 20–40 分钟）
#   bash scripts/e2e_acceptance.sh quick           # 核心门（跳过 fuzz 与长演练）
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
RECORD_DIR="${ROOT}/docs/test-records"
RECORD="${RECORD_DIR}/e2e-${TS}.txt"
mkdir -p "${RECORD_DIR}"

PASS=0
FAIL=0
declare -a RESULTS

record() { # record <name> <exit_code>
  if [ "$2" -eq 0 ]; then
    RESULTS+=("PASS|$1")
    PASS=$((PASS + 1))
    echo "PASS  $1" | tee -a "$RECORD"
  else
    RESULTS+=("FAIL|$1")
    FAIL=$((FAIL + 1))
    echo "FAIL  $1" | tee -a "$RECORD"
  fi
}

run() { # run <name> <cmd...>
  local name="$1"; shift
  echo ">> $name" | tee -a "$RECORD"
  "$@" >> "$RECORD" 2>&1
  record "$name" $?
}

{
  echo "# zchain e2e 验收记录 ${TS}"
  echo "# host: $(uname -srm) / $(date '+%F %T')"
  echo "# mode: ${1:-full}"
} > "$RECORD"

MODE="${1:-full}"

# ===== 1. workspace release 套件（CI 同口径） =====
run "cargo-release:poker_l1-lib"        cargo test --release -p poker_l1 --lib
run "cargo-release:poker-appchain"      cargo test --release -p poker-appchain
run "cargo-release:poker-settlement-core" cargo test --release -p poker-settlement-core
run "cargo-release:poker-wallet"        cargo test --release -p poker-wallet
run "cargo-release:vm-common"           cargo test -p vm-common --lib
run "cargo-release:zchain-build"        cargo build --release -p zchain

# ===== 2. 节点 e2e =====
run "e2e:single-process"    ./target/release/zchain test-e2e --data-dir "/tmp/zchain-acc-${TS}"
run "e2e:multi-node-3"      env ZCHAIN_BIN=./target/release/zchain bash scripts/multi_node_e2e.sh 3

# ===== 3. 场景演练（串行） =====
run "drill:censorship"      bash scripts/scenario_censorship_drill.sh ./target/release/zchain
run "drill:checkpoint-seven" bash scripts/scenario_checkpoint_seven.sh ./target/release/zchain
run "drill:kill-one-of-four" bash scripts/scenario_kill_one_of_four.sh ./target/release/zchain
run "drill:restart-catchup" bash scripts/scenario_restart_catchup.sh ./target/release/zchain
run "drill:sequencer-restart" bash scripts/drill_sequencer_restart.sh
run "smoke:explorer-gateway" bash scripts/explorer_gateway_smoke.sh

# ===== 3b. 桥回归门（锚定正常路径 + 幽灵 nonce 故障注入）=====
run "drill:bridge-anchor"     bash scripts/scenario_bridge_anchor.sh ./target/release/zchain
run "drill:bridge-ghost-nonce" bash scripts/scenario_bridge_ghost_nonce.sh ./target/release/zchain

# ===== 4. extension（Node + 浏览器 E2E） =====
run "extension:unit"        bash -c "cd extension && npm test"
run "extension:wasm-smoke"  bash -c "cd extension && node tests/wasm_smoke.mjs"
run "extension:e2e-run02"   bash -c "cd extension && node tests/e2e/run_02.mjs"
run "extension:e2e-run03"   bash -c "cd extension && node tests/e2e/run_03.mjs"
run "extension:e2e-run04"   bash -c "cd extension && node tests/e2e/run_04.mjs"

# ===== 5. 独立 workspace =====
run "wallet-app:zwallet"    bash -c "cd wallet-app && cargo test -p zwallet --release"
run "texasair:e2e-full-hand" bash -c "cd poker-appchain-texasair && cargo test --release --test e2e_full_hand"
run "stwo:native-core"      bash -c "cd stwo-wasm-verify && cargo test -p stwo-verify-core"

# ===== 6. fuzz 冒烟（full 模式；60s/target） =====
if [ "$MODE" != "quick" ]; then
  run "fuzz:note_abi"           bash -c "cd fuzz && cargo fuzz run note_abi -- -max_total_time=60"
  run "fuzz:soft_confirm_api"   bash -c "cd fuzz && cargo fuzz run soft_confirm_api -- -max_total_time=60"
  run "fuzz:settlement_witness" bash -c "cd fuzz && cargo fuzz run settlement_witness -- -max_total_time=60"
  # M5-ACC-3 常规留痕：1000 手审计复验零差异
  AUDIT_DIR="$(mktemp -d /tmp/rake_audit_acc_XXXXXX)"
  run "audit:rake-1000-hands" bash -c "
    set -e
    ./target/release/rake_audit selftest --dir '${AUDIT_DIR}' --hands 1000 > '${AUDIT_DIR}/selftest.log'
    PUB=\$(sed -n 's/^SEQUENCER_PUBLIC=//p' '${AUDIT_DIR}/selftest.log')
    FROM=\$(sed -n 's/^FIRST_TS=//p' '${AUDIT_DIR}/selftest.log')
    TO=\$(sed -n 's/^LAST_TS=//p' '${AUDIT_DIR}/selftest.log')
    ./target/release/rake_audit export --appchain-wal '${AUDIT_DIR}/selftest.wal' \
      --sequencer-public \"\$PUB\" --from-ts \"\$FROM\" --to-ts \"\$TO\" \
      --out '${AUDIT_DIR}/audit.json'
    ./target/release/rake_audit verify --audit '${AUDIT_DIR}/audit.json'
  "
fi

# ===== 汇总 =====
{
  echo ""
  echo "# summary: PASS=${PASS} FAIL=${FAIL} mode=${MODE}"
  echo "# note: 场景演练必须串行执行（并发 7 节点演练会因 CPU 争用产生"
  echo "#       commit 引擎时序假阴性，见 scenario 脚本头注）。"
} >> "$RECORD"

echo "=============================="
echo "e2e 验收汇总: PASS=${PASS} FAIL=${FAIL} (record: ${RECORD})"
[ "$FAIL" -eq 0 ]
