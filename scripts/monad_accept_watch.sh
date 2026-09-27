#!/usr/bin/env bash
# =============================================================================
# monad_accept_watch.sh — 领水监听 + 自动链上验收（后台守护）。
#
# 原理：官方水龙头领水只需填地址。用户在正常浏览器领水到
#   0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266（anvil[0] 公开测试钥，
#   私钥公开已知），本脚本轮询该地址余额；到账 ≥0.1 MON 即自动执行
#   scripts/monad_testnet_accept.sh（部署+互联+上锚+入金+提现+大额延迟
#   全流程），并把证据落档。
#
# 用法：bash scripts/monad_accept_watch.sh [轮询分钟数，默认 90]
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

ADDR=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RPC=${L1_RPC:-https://testnet-rpc.monad.xyz}
MIN_WEI=100000000000000000   # 0.1 MON
MINUTES=${1:-90}
MARKER=docs/test-records/.monad-e2e-done

[[ -f $MARKER ]] && { echo "[watch] 验收已完成（$MARKER 存在），退出"; exit 0; }

echo "[watch] 监听 $ADDR 的 Monad 测试网余额（每 60s，至多 ${MINUTES}min）"
for i in $(seq 1 "$MINUTES"); do
  BAL_HEX=$(curl -s -m 10 -X POST "$RPC" -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["'"$ADDR"'","latest"]}' \
    | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')
  if [[ -n "$BAL_HEX" ]]; then
    BAL=$((16#${BAL_HEX#0x}))
    if (( BAL >= MIN_WEI )); then
      echo "[watch] $(date '+%F %T') 到账：$BAL wei（$((BAL / 1000000000000000)) mMON）→ 启动链上 E2E"
      export MONAD_TESTNET_KEY=$KEY
      ./scripts/monad_testnet_accept.sh
      code=$?
      if [[ $code == 0 ]]; then
        mkdir -p docs/test-records
        touch "$MARKER"
        echo "[watch] ✅ 链上 E2E 验收闭环（标记 $MARKER）"
      else
        echo "[watch] ❌ E2E 存在失败项（exit=$code）；监听继续（资金仍够可自动重试）"
        exit $code
      fi
      exit 0
    fi
  fi
  sleep 60
done
echo "[watch] ${MINUTES} 分钟内未检测到到账，退出（可随时重跑本脚本）"
exit 0
