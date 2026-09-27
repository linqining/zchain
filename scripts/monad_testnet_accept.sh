#!/usr/bin/env bash
# =============================================================================
# monad_testnet_accept.sh — Monad 测试网链上 E2E 验收一键执行（含证据落档）。
#
# 前置（唯一人工步骤）：经 https://faucet.monad.xyz 人工过验证领取 ≥1 MON
# 到某个测试 key，然后：
#
#   export MONAD_TESTNET_KEY=0x…   # 带水测试钥
#   ./scripts/monad_testnet_accept.sh
#
# 行为：solc 字节码缺失时自动编译 → monad_e2e（部署+互联+上锚+入金+提现+
# 大额延迟，逐项 PASS/FAIL + JSON 摘要）→ 输出与链上证据全文落档
# docs/test-records/。退出码 = 失败项数（0 = 验收闭环）。
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${MONAD_TESTNET_KEY:-}" ]]; then
  echo "error: MONAD_TESTNET_KEY 未设置。" >&2
  echo "  1) 浏览器打开 https://faucet.monad.xyz 过验证领取 ≥1 MON（任意 key）；" >&2
  echo "  2) export MONAD_TESTNET_KEY=0x<该 key 的私钥>；" >&2
  echo "  3) 重跑本脚本。" >&2
  exit 2
fi

L1_RPC="${L1_RPC:-https://testnet-rpc.monad.xyz}"
CHAIN_ID="${CHAIN_ID:-10143}"
OUT_DOC="docs/test-records/2026-09-27-monad-testnet-acceptance"

# 1) 字节码（无 foundry 环境用 solc 直编；已编译则跳过）。
echo "[accept] 编译结算合约栈（每次强制重编，防旧字节码上链）……"
contracts/monad/build_solc.sh

# 2) 一键 E2E（逐项 PASS/FAIL + JSON 摘要），全文落档。
STAMP=$(date +%Y%m%d-%H%M%S)
LOG="${OUT_DOC}-chain-e2e-${STAMP}.txt"
mkdir -p "$(dirname "$LOG")"
echo "[accept] 执行链上 E2E（约 3-5 分钟），日志 → $LOG"
set +e
cargo run -q -p monad-settlement --bin monad_e2e -- \
  --l1-rpc "$L1_RPC" --chain-id "$CHAIN_ID" \
  --key-env MONAD_TESTNET_KEY \
  --bytecode-dir contracts/monad/out/solc \
  --deposits-file /tmp/monad-e2e-deposits.jsonl 2>&1 | tee "$LOG"
CODE=${PIPESTATUS[0]}
set -e

echo
if [[ "$CODE" == "0" ]]; then
  echo "[accept] [PASS] 链上 E2E 全部通过; 输出已存 $LOG"
  echo "[accept] 收尾: 将 JSON 摘要与交易哈希回填 docs/monad-l2-settlement.md 6.3"
else
  echo "[accept] [FAIL] 存在失败项 (exit=${CODE}); 详情见 $LOG"
fi
exit "$CODE"
