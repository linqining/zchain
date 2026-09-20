#!/usr/bin/env bash
# dev_poker_air.sh — poker_texas_air × zchain 一键联调环境（对照
# poker_texas_air/scripts/dev.sh 的 zchain 版）。
#
# 流程：zchain 单 validator 链（RPC 18545，genesis 预充值桥账户）→
# poker_texas_air 合约部署/绑定记录上链（deploy-record tx）→ texas 游戏
# 服务器（STARKNET_RPC_URL 留空 = dev 模式；结算出口 = 嵌入式 appchain，
# 每手出 STARK 证明并落 sequencer.wal）→ explorer_gateway（18900 读
# appchain WAL + 代理 zchain L1，扩展数据面）→ 结算桥（逐笔 appchain
# 结算锚定为 zchain Public tx，get_tx 确认）→ vite 前端（5173）→
# 真实 Chrome for Testing 加载 extension 钱包 → ZChain Wallet 登录入座 →
# 自动打牌直到 TARGET_HANDS（默认 100）手全部结算并锚定上链。
#
# 用法：
#   scripts/dev_poker_air.sh                     # 完整流程（目标 1000 手）
#   scripts/dev_poker_air.sh --skip-build       # 跳过 cargo/pnpm 构建
#   scripts/dev_poker_air.sh --no-browser       # 不拉浏览器（无头联调）
#   scripts/dev_poker_air.sh --target N         # 目标手数（默认 1000）
#   scripts/dev_poker_air.sh --keep             # 脚本退出不清理进程
#
# 环境变量：RUN_DIR（运行目录，默认 /tmp/poker-air-zchain-1000）
#   BROWSER_TIMEOUT_SECS（浏览器阶段超时，默认 43200=12h）
#   STRATEGY（random=随机边缘策略 raise/all-in/fold/call/check；passive=旧版）
#
# 关键日志：
#   $RUN_DIR/{zchain,gateway,texas-server,vite,bridge,browser}.log
# 验收：bridge 打印 "target reached: N >= N" 且浏览器脚本退出码 0。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AIR_ROOT="${AIR_ROOT:-/Users/mac/projects/poker_texas_air}"
RUN_DIR="${RUN_DIR:-/tmp/poker-air-zchain-1000}"
ZCHAIN_RPC_HOST="${ZCHAIN_RPC_HOST:-127.0.0.1}"
ZCHAIN_RPC_PORT="${ZCHAIN_RPC_PORT:-18545}"
ZCHAIN_P2P_PORT="${ZCHAIN_P2P_PORT:-19000}"
GATEWAY_PORT="${GATEWAY_PORT:-18900}"
GAME_PORT="${GAME_PORT:-9001}"
CLIENT_PORT="${CLIENT_PORT:-5173}"
TARGET_HANDS="${TARGET_HANDS:-1000}"
BROWSER_TIMEOUT_SECS="${BROWSER_TIMEOUT_SECS:-43200}"
STRATEGY="${STRATEGY:-random}"
PROFILE=release
SKIP_BUILD=0
NO_BROWSER=0
KEEP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-browser) NO_BROWSER=1; shift ;;
    --keep) KEEP=1; shift ;;
    --target) TARGET_HANDS="${2:?--target 缺参数}"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

log() { echo "[poker-air] $*"; }
mkdir -p "$RUN_DIR"

# ---------- 0) 停旧实例 ----------
log "清理旧实例…"
pkill -f "target/release/zchain.*poker-air" 2>/dev/null || true
pkill -f "explorer_gateway.*$RUN_DIR" 2>/dev/null || true
pkill -f "target/release/texas" 2>/dev/null || true
pkill -f "target/debug/texas" 2>/dev/null || true
pkill -f "poker_air_bridge.py bridge" 2>/dev/null || true
pkill -f "poker_air_browser.mjs" 2>/dev/null || true
for port in "$ZCHAIN_RPC_PORT" "$GATEWAY_PORT" "$GAME_PORT" "$CLIENT_PORT"; do
  # 远程模式下本地 ZCHAIN_RPC_PORT 可能是 SSH 隧道监听（远程链的通道），
  # 不能当旧实例清理。
  if [[ "$port" == "$ZCHAIN_RPC_PORT" && "${ZCHAIN_REMOTE:-0}" == "1" ]]; then
    continue
  fi
  if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    kill $(lsof -tiTCP:"$port" -sTCP:LISTEN) 2>/dev/null || true
  fi
done
sleep 1

PIDS=()
cleanup() {
  if [[ "$KEEP" == 1 ]]; then
    log "--keep：保留全部进程"
    return
  fi
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  # 脱离的浏览器监督者：仅在未达标时终止（达标后它自己已退出）
  if [[ -f "$RUN_DIR/browser-supervisor.pid" ]] && [[ ! -f "$RUN_DIR/browser.done" ]]; then
    kill "$(cat "$RUN_DIR/browser-supervisor.pid")" 2>/dev/null || true
    pkill -f "poker_air_chrome" 2>/dev/null || true
  fi
  log "已停止全部后台进程（--keep 可保留）"
}
trap cleanup EXIT

# ---------- 1) 构建 ----------
ZCHAIN_BIN="$ROOT/target/release/zchain"
GATEWAY_BIN="$ROOT/target/release/explorer_gateway"
TEXAS_BIN="$AIR_ROOT/target/release/texas"
if [[ "$SKIP_BUILD" != 1 ]]; then
  log "构建 zchain（zchain + explorer_gateway，release）…"
  (cd "$ROOT" && cargo build --release -p zchain -p poker-appchain --bin zchain --bin explorer_gateway) \
    >>"$RUN_DIR/build.log" 2>&1 || { echo "zchain 构建失败，见 $RUN_DIR/build.log"; tail -20 "$RUN_DIR/build.log"; exit 1; }
  log "构建 texas 服务器（release）…"
  (cd "$AIR_ROOT" && cargo build -p texas --bin texas --release) \
    >>"$RUN_DIR/build.log" 2>&1 || { echo "texas 构建失败，见 $RUN_DIR/build.log"; tail -20 "$RUN_DIR/build.log"; exit 1; }
else
  log "跳过构建"
fi
[[ -x "$ZCHAIN_BIN" ]] || { echo "缺少 $ZCHAIN_BIN"; exit 1; }
[[ -x "$GATEWAY_BIN" ]] || { echo "缺少 $GATEWAY_BIN"; exit 1; }
[[ -x "$TEXAS_BIN" ]] || { echo "缺少 $TEXAS_BIN"; exit 1; }

# ---------- 2) 密钥 + genesis ----------
log "生成 validator / bridge 密钥（$RUN_DIR/keys）…"
KEYS_DIR="$RUN_DIR/keys"; mkdir -p "$KEYS_DIR"
if [[ ! -f "$KEYS_DIR/validator.key" ]]; then
  "$ZCHAIN_BIN" keygen --scheme secp256k1 >"$KEYS_DIR/validator.json"
  grep '"secret_key_hex"' "$KEYS_DIR/validator.json" | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' >"$KEYS_DIR/validator.key"
  grep '"raw_hex"' "$KEYS_DIR/validator.json" | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' >"$KEYS_DIR/validator.pub"
fi
if [[ ! -f "$KEYS_DIR/bridge.key" ]]; then
  "$ZCHAIN_BIN" keygen --scheme secp256k1 >"$KEYS_DIR/bridge.json"
  grep '"secret_key_hex"' "$KEYS_DIR/bridge.json" | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' >"$KEYS_DIR/bridge.key"
  grep '"raw_hex"' "$KEYS_DIR/bridge.json" | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' >"$KEYS_DIR/bridge.pub"
  grep '"address_hex"' "$KEYS_DIR/bridge.json" | head -1 | sed -E 's/.*"address_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' >"$KEYS_DIR/bridge.addr"
fi
VALIDATOR_PUB=$(cat "$KEYS_DIR/validator.pub")
BRIDGE_PUB=$(cat "$KEYS_DIR/bridge.pub")
BRIDGE_KEY=$(cat "$KEYS_DIR/bridge.key")
BRIDGE_ADDR=$(cat "$KEYS_DIR/bridge.addr")
openssl rand -hex 32 >"$KEYS_DIR/validator.vrf" 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$KEYS_DIR/validator.vrf"

GENESIS_VALIDATORS="$RUN_DIR/genesis_validators.json"
cat >"$GENESIS_VALIDATORS" <<EOF
[{"pubkey_hex": "$VALIDATOR_PUB", "vrf_pubkey_hex": "02$(printf '0%.0s' {1..64})", "stake": 0}]
EOF
GENESIS_ALLOC="$RUN_DIR/genesis_alloc.json"
cat >"$GENESIS_ALLOC" <<EOF
[
  {"pubkey_hex": "$VALIDATOR_PUB", "balance": 1000000000},
  {"pubkey_hex": "$BRIDGE_PUB", "balance": 1000000000}
]
EOF

# ---------- 3) zchain 节点（本地单 validator，或远程 4 节点常驻链）----------
rpc_call() {
  python3 - "$1" "$2" "${ZCHAIN_RPC_HOST}" <<'PYEOF'
import json, socket, sys
method, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
params = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
s = socket.create_connection((host, port), timeout=5)
s.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) + "\n").encode())
buf = b""
while b"\n" not in buf:
    c = s.recv(65536)
    if not c:
        break
    buf += c
print(buf.split(b"\n", 1)[0].decode())
PYEOF
}
if [[ "${ZCHAIN_REMOTE:-0}" == "1" || ( "$ZCHAIN_RPC_HOST" != "127.0.0.1" && "$ZCHAIN_RPC_HOST" != "localhost" ) ]]; then
  # 远程模式：链已在远程服务器以 4 节点常驻部署（scripts/deploy_4node.sh，
  # RPC_HOST=0.0.0.0 且 EXTRA_ALLOC_PUBS 含本 RUN_DIR 的 bridge.pub——远程链
  # 无 transfer 交易，桥账户必须有 genesis 余额才能提交锚定 tx）。
  # ZCHAIN_REMOTE=1 允许 RPC 经 SSH 隧道映射到 127.0.0.1（安全组未放行时）。
  log "远程 zchain 模式：${ZCHAIN_RPC_HOST}:${ZCHAIN_RPC_PORT}（4 节点常驻链）"
  REMOTE_OK=0
  for i in $(seq 1 60); do
    if rpc_call get_block_count "$ZCHAIN_RPC_PORT" >/dev/null 2>&1; then REMOTE_OK=1; break; fi
    sleep 1
  done
  [ "$REMOTE_OK" == 1 ] || { echo "远程 zchain RPC 不可达: $ZCHAIN_RPC_HOST:$ZCHAIN_RPC_PORT"; exit 1; }
else
  log "启动 zchain validator（RPC :${ZCHAIN_RPC_PORT}，出块 500ms）…"
  "$ZCHAIN_BIN" node \
    --role validator \
    --data-dir "$RUN_DIR/chain" \
    --rpc-listen "127.0.0.1:$ZCHAIN_RPC_PORT" \
    --p2p-listen "127.0.0.1:$ZCHAIN_P2P_PORT" \
    --validator-key-file "$KEYS_DIR/validator.key" \
    --vrf-key-file "$KEYS_DIR/validator.vrf" \
    --genesis-validators "$GENESIS_VALIDATORS" \
    --genesis-alloc "$GENESIS_ALLOC" \
    --block-interval-ms 500 \
    >"$RUN_DIR/zchain.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 60); do
    if rpc_call get_block_count "$ZCHAIN_RPC_PORT" >/dev/null 2>&1; then break; fi
    sleep 1
  done
fi
HEIGHT=$(rpc_call get_block_count "$ZCHAIN_RPC_PORT" 2>/dev/null | python3 -c 'import json,sys; print((json.load(sys.stdin).get("result") or {}).get("height") or 0)' 2>/dev/null || echo 0)
log "zchain 已就绪（height=${HEIGHT}，日志 $RUN_DIR/zchain.log）"

# ---------- 4) poker_texas_air 合约部署/绑定记录上链 ----------
log "提交 poker_texas_air 合约部署记录到 zchain…"
SEQ_SEED=$(printf '5e%.0s' {1..32})
ATT_SEED=$(printf 'a7%.0s' {1..32})
SEQ_PUB=$(python3 "$ROOT/scripts/poker_air_bridge.py" pubkeys --sequencer-seed-hex "$SEQ_SEED" | awk '{print $2}')
ATT_PUB=$(python3 "$ROOT/scripts/poker_air_bridge.py" pubkeys --attestor-seed-hex "$ATT_SEED" | awk '{print $2}')
log "appchain sequencer_pub=$SEQ_PUB attestor_verifier_key=$ATT_PUB"
DEPLOY_OUT=$(python3 "$ROOT/scripts/poker_air_bridge.py" deploy-record \
  --secret-key-hex "$BRIDGE_KEY" --address "$BRIDGE_ADDR" --rpc-port "$ZCHAIN_RPC_PORT" \
  --rpc-host "$ZCHAIN_RPC_HOST" \
  --zchain-bin "$ZCHAIN_BIN" \
  --meta "{\"sequencer_public\":\"$SEQ_PUB\",\"attestor_verifier_key\":\"$ATT_PUB\",\"settlement_exit\":\"appchain\",\"air_engine\":\"poker-appchain-texasair\"}")
log "部署记录已上链: $DEPLOY_OUT"

# ---------- 5) texas 游戏服务器（appchain 出口，dev prover）----------
log "生成服务器环境（$RUN_DIR/texas.env）…"
cat >"$RUN_DIR/texas.env" <<EOF
PORT=$GAME_PORT
JWT_SECRET=poker-air-zchain-dev-secret
TEXAS_ENV=dev
TEXAS_PROVER_MODE=dev
TEXAS_DEV_BOT_ENABLED=1
TEXAS_APPCHAIN=1
TEXAS_APPCHAIN_WAL_DIR=$RUN_DIR/appchain
TEXAS_APPCHAIN_SEQUENCER_SEED=$SEQ_SEED
TEXAS_APPCHAIN_ATTESTOR_SEED=$ATT_SEED
TEXAS_APPCHAIN_ASSET=play
TEXAS_APPCHAIN_PROVIDER=mock
STARKNET_SETTLEMENT_EXIT=appchain
STARKNET_AUTH_STRICT=false
# rake=0：结算计划不含 rake 项（appchain 出口的 treasury 分成独立于
# STARKNET_RAKE_*；legacy 回退路径的 settle_hand calldata 也因此可构建）
STARKNET_RAKE_BPS=0
RUST_LOG=info
BETTING_TIMEOUT_SECS=8
BOT_LOOP_SECS=0
EOF
# STARKNET_RPC_URL 刻意不设置：dev 模式（买入不入账，结算走 appchain 出口）。
log "启动 texas 服务器（:${GAME_PORT}，结算出口=appchain→zchain）…"
(cd "$AIR_ROOT" && set -a && source "$RUN_DIR/texas.env" && set +a && exec "$TEXAS_BIN") \
  >"$RUN_DIR/texas-server.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 90); do
  curl -sf "http://127.0.0.1:$GAME_PORT/" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$GAME_PORT/" >/dev/null 2>&1 || {
  echo "texas 服务器启动超时，日志："; tail -30 "$RUN_DIR/texas-server.log"; exit 1; }
log "texas 服务器就绪: http://127.0.0.1:$GAME_PORT"

# ---------- 6) explorer_gateway（扩展数据面，读 WAL + 代理 L1）----------
log "启动 explorer_gateway（:${GATEWAY_PORT}，WAL=$RUN_DIR/appchain/sequencer.wal）…"
"$GATEWAY_BIN" \
  --appchain-wal "$RUN_DIR/appchain/sequencer.wal" \
  --sequencer-public "$SEQ_PUB" \
  --l1-rpc "http://$ZCHAIN_RPC_HOST:$ZCHAIN_RPC_PORT" \
  --listen "127.0.0.1:$GATEWAY_PORT" \
  --public \
  >"$RUN_DIR/gateway.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$GATEWAY_PORT/api/v1/status" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$GATEWAY_PORT/api/v1/status" >/dev/null 2>&1 || {
  echo "gateway 启动超时，日志："; tail -20 "$RUN_DIR/gateway.log"; exit 1; }
log "gateway 就绪: http://127.0.0.1:$GATEWAY_PORT"

# ---------- 7) 结算桥（appchain 结算 → zchain tx）----------
log "启动结算桥（目标 $TARGET_HANDS 手）…"
python3 "$ROOT/scripts/poker_air_bridge.py" bridge \
  --secret-key-hex "$BRIDGE_KEY" --address "$BRIDGE_ADDR" --rpc-port "$ZCHAIN_RPC_PORT" \
  --rpc-host "$ZCHAIN_RPC_HOST" \
  --zchain-bin "$ZCHAIN_BIN" --gateway-bin "$GATEWAY_BIN" \
  --wal "$RUN_DIR/appchain/sequencer.wal" \
  --sequencer-public "$SEQ_PUB" \
  --state-file "$RUN_DIR/bridge_state.json" \
  --poll-secs 8 --target "$TARGET_HANDS" \
  >"$RUN_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
PIDS+=($!)

# ---------- 8) vite 前端 ----------
CLIENT_DIR="$AIR_ROOT/client"
if [[ ! -d "$CLIENT_DIR/node_modules" ]]; then
  log "安装前端依赖（pnpm install）…"
  (cd "$CLIENT_DIR" && pnpm install) >>"$RUN_DIR/build.log" 2>&1 || {
    echo "pnpm install 失败"; tail -20 "$RUN_DIR/build.log"; exit 1; }
fi
cat >"$CLIENT_DIR/.env.development.local" <<EOF
# 由 zchain scripts/dev_poker_air.sh 生成（poker_texas_air × zchain 联调）。
# 不注入直签账户/测试账户：身份一律来自真实连接的 ZChain 钱包扩展。
VITE_SERVER_PORT=$GAME_PORT
EOF
log "启动前端（vite :$CLIENT_PORT → 服务器 :${GAME_PORT}）…"
# --host 127.0.0.1：默认 host 'localhost' 需要一次 getaddrinfo，构建高负载时
# 观察到瞬时 ENOTFOUND 直接拖死前端；显式绑回环地址彻底去掉该依赖。
(cd "$CLIENT_DIR" && GAME_SERVER_URL="http://127.0.0.1:$GAME_PORT" exec ./node_modules/.bin/vite --host 127.0.0.1 --port "$CLIENT_PORT" --strictPort) \
  >"$RUN_DIR/vite.log" 2>&1 &
VITE_PID=$!
PIDS+=($!)
for i in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CLIENT_PORT/" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "http://127.0.0.1:$CLIENT_PORT/" >/dev/null 2>&1 || {
  echo "vite 启动超时，日志："; tail -20 "$RUN_DIR/vite.log"; exit 1; }
# 预热：vite 首次按需变换整个模块图可能耗时 ~60s，先触发变换再拉浏览器，
# 否则浏览器阶段会在登录按钮等待上白烧超时。
log "预热 vite 模块图…"
curl -sf "http://127.0.0.1:$CLIENT_PORT/src/main.tsx" >/dev/null 2>&1 || true
for i in $(seq 1 120); do
  T0=$(date +%s%N 2>/dev/null || echo "0")
  curl -sf -o /dev/null --max-time 10 "http://127.0.0.1:$CLIENT_PORT/src/main.tsx" 2>/dev/null && break
  sleep 1
done
log "前端就绪: http://localhost:$CLIENT_PORT"

# ---------- 9) dev bot 驱动循环（空座自动重注入，驱动连续手牌）----------
BOT1_WALLET="0x00000000000000000000000000000000000000b01"
BOT2_WALLET="0x00000000000000000000000000000000000000b02"
log "启动 bot 驱动循环（table 1, seat 2/3，空座自动重注入）…"
(
  while true; do
    S=$(curl -s --max-time 5 "http://127.0.0.1:$GAME_PORT/api/tables/1" | \
      python3 -c '
import json, sys
try: d = json.load(sys.stdin)
except Exception: d = {}
print(",".join((w or "").lower() for w in (d.get("players") or {}).values()))' 2>/dev/null || echo "")
    for pair in "$BOT1_WALLET 2" "$BOT2_WALLET 3"; do
      wallet="${pair% *}"; seat="${pair#* }"
      if ! echo ",$S," | grep -qi ",$wallet,"; then
        r=$(curl -s --max-time 10 -X POST "http://127.0.0.1:$GAME_PORT/api/dev/bot" \
          -H 'Content-Type: application/json' \
          -d "{\"wallet\":\"$wallet\",\"seatId\":$seat}")
        echo "$(date +%T) inject seat$seat → $r"
      fi
    done
    sleep 3
  done
) >"$RUN_DIR/bots.log" 2>&1 &
PIDS+=($!)
log "bot 驱动已启动（deposit 校验在 dev 模式自动放行）"

# ---------- 10) 真实浏览器 + ZChain 扩展打牌（独立监督进程）----------
# 监督者以 nohup/disown 完全脱离主脚本进程树：主脚本对浏览器 node 的任何
# 信号操作都不会级联；主脚本经 sentinel 文件（browser.done / browser.failed）
# 感知浏览器阶段成败。
if [[ "$NO_BROWSER" != 1 ]]; then
  log "启动真实浏览器（Chrome for Testing + extension）打牌，目标 ${TARGET_HANDS} 手（策略 ${STRATEGY}）…"
  rm -f "$RUN_DIR/browser.done" "$RUN_DIR/browser.failed"
  nohup env POKER_AIR_RUN_DIR="$RUN_DIR" TARGET_HANDS="$TARGET_HANDS" \
    TIMEOUT_SECS="$BROWSER_TIMEOUT_SECS" STRATEGY="$STRATEGY" \
    GAME_API="http://127.0.0.1:$GAME_PORT" POKER_URL="http://127.0.0.1:$CLIENT_PORT" \
    EXT_PATH="$ROOT/extension" \
    bash "$ROOT/scripts/poker_air_browser_supervisor.sh" "$RUN_DIR" "$TARGET_HANDS" 10 \
    >"$RUN_DIR/browser-supervisor.log" 2>&1 &
  disown
  log "浏览器监督进程已脱离启动（pid $(cat "$RUN_DIR/browser-supervisor.pid" 2>/dev/null || echo "?")）"
else
  log "--no-browser：跳过浏览器阶段"
fi

# ---------- 11) 收尾监控 ----------
# 浏览器监督者已脱离进程树：成败经 sentinel 文件感知（browser.done /
# browser.failed）。桥仍以进程存活 + "target reached" 日志判定。
BRIDGE_OK=0
BRIDGE_DEAD=0
BRIDGE_DEAD_SECS=0
while true; do
  if [ -f "$RUN_DIR/browser.failed" ]; then
    log "✗ 浏览器监督进程报告失败（重启次数耗尽），最近日志："
    tail -15 "$RUN_DIR/browser.log" || true
    break
  fi
  if [ "$BRIDGE_DEAD" == 0 ] && ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    if grep -q "target reached" "$RUN_DIR/bridge.log" 2>/dev/null; then BRIDGE_OK=1; fi
    BRIDGE_DEAD=1
  fi
  if [ -f "$RUN_DIR/browser.done" ]; then
    BROWSER_OK=1
    grep -q "target reached" "$RUN_DIR/bridge.log" 2>/dev/null && BRIDGE_OK=1
    break
  fi
  if [ "$BRIDGE_DEAD" == 1 ]; then
    BRIDGE_DEAD_SECS=$((BRIDGE_DEAD_SECS + 5))
    if [ "$BRIDGE_DEAD_SECS" -ge 1800 ]; then
      log "桥已退出 ${BRIDGE_DEAD_SECS}s 而浏览器未收尾，超时收尾"
      break
    fi
  fi
  sleep 5
done
if [[ "$BRIDGE_OK" == 1 ]]; then log "✓ 结算桥已锚定 $TARGET_HANDS 手到 zchain"; else
  log "✗ 结算桥未达标，最近日志："; tail -10 "$RUN_DIR/bridge.log" || true; fi
if [[ "$NO_BROWSER" != 1 ]]; then
  if [ -f "$RUN_DIR/browser.done" ]; then log "✓ 浏览器打牌达标（DONE sentinel）"; else
    log "✗ 浏览器阶段异常，最近日志："; tail -15 "$RUN_DIR/browser.log" || true; fi
fi
FINAL_HEIGHT=$(rpc_call get_block_count "$ZCHAIN_RPC_PORT" 2>/dev/null | python3 -c 'import json,sys; print((json.load(sys.stdin).get("result") or {}).get("height") or 0)' 2>/dev/null || echo '?')
log "zchain 最终高度: $FINAL_HEIGHT"
if [[ "$BRIDGE_OK" == 1 && ( "$NO_BROWSER" == 1 || "$BROWSER_OK" == 1 ) ]]; then
  log "全部完成 ✓（$TARGET_HANDS 手，已全部结算并提交 zchain）"
  exit 0
fi
exit 1
