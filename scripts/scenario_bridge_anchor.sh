#!/usr/bin/env bash
# Scenario: 结算锚定桥正常路径回归门（bridge e2e gate）。
#
# 被测对象：scripts/poker_air_bridge.py（appchain WAL 结算 → zchain L1
# Public tx 锚定）+ explorer_gateway --write-index（fail-closed 全量重放
# 验签）+ zchain 4 节点 DAG 共识。
#
# 流程：
#   1. rake_audit selftest 生成 demo WAL（含 N 手 Settle 记录）；
#   2. explorer_gateway --write-index 预生成 archive index，统计 Settle
#      行数作为锚定目标（EXPECT）；
#   3. keygen 桥账户（genesis 预充值），起 4 节点链（200ms 出块）；
#   4. poker_air_bridge.py bridge --stream-only --target EXPECT 常驻锚定；
#   5. 断言（无幽灵 anchored 记录的完整口径，见
#      docs/test-records/2026-09-21-remote-4node-full-reanchor.md 三重证据）：
#      a. state 文件 anchored 数 == EXPECT（全部锚定）；
#      b. anchored nonce 恰为 {0..EXPECT-1}：连续、无重复（同 nonce 双记
#         即幽灵，2026-09-21 远程 3029 笔实测 10 条幽灵的病灶）；
#      c. 全部 4 节点 get_account nonce == EXPECT（每笔都真正执行入块；
#         get_tx 只读内存 tx_cache 不能作入块证据）。
#
# 用法：scripts/scenario_bridge_anchor.sh [ZCHAIN_BIN]
# 环境变量：BRIDGE_HANDS（默认 6）、GATEWAY_BIN、RAKE_AUDIT_BIN、
#           KEEP_WORK=1（保留现场目录）
#
# 与 scenario_bridge_ghost_nonce.sh 的差异：本脚本只测正常路径；故障注入
# （kill 全节点 + 重启续跑）见后者。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-$REPO_ROOT/target/debug/zchain}}"
GATEWAY_BIN="${GATEWAY_BIN:-$REPO_ROOT/target/release/explorer_gateway}"
RAKE_AUDIT_BIN="${RAKE_AUDIT_BIN:-$REPO_ROOT/target/release/rake_audit}"
BRIDGE_PY="$REPO_ROOT/scripts/poker_air_bridge.py"
HANDS="${BRIDGE_HANDS:-6}"
KEEP_WORK="${KEEP_WORK:-0}"

WORK="$(mktemp -d /tmp/zchain_bridge_anchor.XXXXXX)"
# 端口默认避开 deploy_4node/de scenario 系列的 18545/19000（本机可能有
# 常驻部署占用）。RPC_BASE 必须满足 (port-5)%4==0——桥按该式推导
# fan 端口组（port..port+3），18549 与 18545 同余。
RPC_BASE="${RPC_BASE:-18549}"
P2P_BASE="${P2P_BASE:-19010}"
N=4

cleanup() {
  if [ -f "${WORK}/.started" ]; then
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "${WORK}/.started"
    for _ in $(seq 1 120); do
      alive=0
      while read -r pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < "${WORK}/.started"
      [ "$alive" -eq 0 ] && break
      sleep 0.5
    done
  fi
  if [ "$KEEP_WORK" = "1" ]; then
    echo "keep workdir: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# ---- 二进制自举（缺则构建，同 drill_sequencer_restart.sh 模式）----
if [ ! -x "$ZCHAIN_BIN" ]; then
  echo "[bridge-anchor] 构建 zchain（debug）……"
  (cd "$REPO_ROOT" && cargo build -p zchain)
fi
if [ ! -x "$GATEWAY_BIN" ] || [ ! -x "$RAKE_AUDIT_BIN" ]; then
  echo "[bridge-anchor] 构建 rake_audit / explorer_gateway（release）……"
  (cd "$REPO_ROOT" && cargo build --release -p poker-appchain --bin rake_audit --bin explorer_gateway)
fi
for f in "$ZCHAIN_BIN" "$GATEWAY_BIN" "$RAKE_AUDIT_BIN" "$BRIDGE_PY"; do
  [ -e "$f" ] || { echo "FAIL: 缺文件 $f" >&2; exit 1; }
done

echo "=== scenario: bridge anchor (normal path), workdir $WORK ==="

# ===== 1. demo WAL（Settle 结算记录）=====
"$RAKE_AUDIT_BIN" selftest --dir "$WORK/walgen" --hands "$HANDS" > "$WORK/selftest.out"
WAL="$(grep '^WAL=' "$WORK/selftest.out" | cut -d= -f2-)"
SEQ_PUB="$(grep '^SEQUENCER_PUBLIC=' "$WORK/selftest.out" | cut -d= -f2-)"
[ -n "$WAL" ] && [ -n "$SEQ_PUB" ] || { echo "FAIL: selftest 输出解析失败" >&2; cat "$WORK/selftest.out" >&2; exit 1; }
echo "WAL=$WAL"
echo "SEQUENCER_PUBLIC=$SEQ_PUB"

# ===== 2. 预生成 archive index，统计锚定目标 =====
INDEX="$WORK/bridge_archive_index.jsonl"
"$GATEWAY_BIN" --write-index "$INDEX" --appchain-wal "$WAL" --sequencer-public "$SEQ_PUB" \
  || { echo "FAIL: gateway --write-index 失败" >&2; exit 1; }
EXPECT="$(python3 - "$INDEX" <<'PY'
import json, sys
n = 0
with open(sys.argv[1]) as f:
    for i, line in enumerate(f):
        line = line.strip()
        if not line or i == 0:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("kind") == "Settle" and obj.get("binding_hex"):
            n += 1
print(n)
PY
)"
[ "${EXPECT:-0}" -ge 1 ] || { echo "FAIL: index 中无 Settle 行（EXPECT=${EXPECT}）" >&2; exit 1; }
echo "EXPECT（Settle 行数）=${EXPECT}"

# ===== 3. 桥账户 + validator 密钥 =====
BK_JSON="$("$ZCHAIN_BIN" keygen --scheme secp256k1)"
BRIDGE_SK="$(echo "$BK_JSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
BRIDGE_ADDR="$(echo "$BK_JSON" | grep '"address_hex"' | head -1 | sed -E 's/.*"address_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
BRIDGE_PUB="$(echo "$BK_JSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
[ -n "$BRIDGE_SK" ] && [ -n "$BRIDGE_ADDR" ] && [ -n "$BRIDGE_PUB" ] \
  || { echo "FAIL: 桥账户 keygen 解析失败" >&2; exit 1; }

SECRETS=(); PUBKEYS=()
for ((i=0; i<N; i++)); do
  KEYJSON="$("$ZCHAIN_BIN" keygen --scheme secp256k1)"
  SECRETS+=("$(echo "$KEYJSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  PUBKEYS+=("$(echo "$KEYJSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  openssl rand -hex 32 > "${WORK}/vrf_${i}"
  printf '%s' "${SECRETS[i]}" > "${WORK}/sk_${i}"
done

# ===== 4. genesis（validator stake=0 + 桥账户预充值——桥账户无 genesis
# 余额则无法支付锚定 tx，见 deploy_4node.sh EXTRA_ALLOC_PUBS 注释）=====
GV="$WORK/gv.json"; ALLOC="$WORK/alloc.json"
echo "[" > "$GV"
for ((i=0; i<N; i++)); do
  C=","; [ $i -eq $((N-1)) ] && C=""
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"vrf_pubkey_hex\": \"02$(printf '%064d' $i)\", \"stake\": 0}$C" >> "$GV"
done
echo "]" >> "$GV"
echo "[" > "$ALLOC"
for ((i=0; i<N; i++)); do
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"balance\": 100000000000}," >> "$ALLOC"
done
echo "  {\"pubkey_hex\": \"${BRIDGE_PUB}\", \"balance\": 100000000000}" >> "$ALLOC"
echo "]" >> "$ALLOC"
python3 -c "import json; json.load(open('$ALLOC'))" || { echo "FAIL: alloc.json 非法" >&2; exit 1; }

# ===== 5. 起 4 节点 =====
wait_ports_free() {
  for _ in $(seq 1 40); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${RPC_BASE}") 2>/dev/null; then
      return 0
    fi
    exec 3>&- 2>/dev/null || true
    sleep 0.5
  done
  echo "WARN: RPC 端口 ${RPC_BASE} 迟迟未释放，继续尝试" >&2
}
: > "${WORK}/.started"
start_nodes() {
  wait_ports_free
  for idx in "$@"; do
    args=(node --role validator --data-dir "${WORK}/node_${idx}" \
      --rpc-listen 127.0.0.1:$((RPC_BASE+idx)) --p2p-listen 127.0.0.1:$((P2P_BASE+idx)) \
      --validator-key-file "${WORK}/sk_${idx}" --vrf-key-file "${WORK}/vrf_${idx}" \
      --genesis-validators "$GV" --genesis-alloc "$ALLOC" --block-interval-ms 200)
    for ((j=0; j<N; j++)); do
      [ "$idx" -ne "$j" ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
    done
    "$ZCHAIN_BIN" "${args[@]}" >> "${WORK}/node_${idx}.log" 2>&1 &
    echo $! >> "${WORK}/.started"
  done
}
start_nodes 0 1 2 3

echo -n "等待 4 节点出块"
ALL=0
for ((t=0; t<90; t++)); do
  ALL=1
  for ((i=0; i<N; i++)); do
    grep -q "commit_round=" "${WORK}/node_${i}.log" 2>/dev/null || ALL=0
  done
  [ "$ALL" -eq 1 ] && break
  echo -n "."; sleep 1
done
echo
[ "$ALL" -eq 1 ] || { echo "FAIL: 节点未出块" >&2; exit 1; }

# ===== 6. 桥常驻锚定（stream 模式 = nonce 严格 admission 的生产路径）=====
STATE="$WORK/bridge_state.json"
echo "启动锚定桥（target=${EXPECT}）……"
set +e
python3 "$BRIDGE_PY" bridge \
  --secret-key-hex "$BRIDGE_SK" --address "$BRIDGE_ADDR" \
  --rpc-port "$RPC_BASE" --rpc-host 127.0.0.1 \
  --wal "$WAL" --sequencer-public "$SEQ_PUB" \
  --gateway-bin "$GATEWAY_BIN" --zchain-bin "$ZCHAIN_BIN" \
  --state-file "$STATE" \
  --stream-only --target "$EXPECT" --max-rounds 10 \
  --poll-secs 2 --wait-secs 30 2>&1 | tee "$WORK/bridge.log"
BRIDGE_RC=${PIPESTATUS[0]}
set -e
[ "$BRIDGE_RC" -eq 0 ] || { echo "FAIL: bridge 退出码 ${BRIDGE_RC}（见 $WORK/bridge.log）" >&2; exit 1; }
grep -q "target reached" "$WORK/bridge.log" || { echo "FAIL: bridge 未达 target" >&2; exit 1; }

# ===== 7. 无幽灵断言（三重证据：entries / nonce 连续性 / 链上 nonce）=====
python3 - "$STATE" "$BRIDGE_ADDR" "$EXPECT" "$RPC_BASE" "$N" "$REPO_ROOT" <<'PY'
import json, sys
from pathlib import Path

state_path, addr, expect, rpc_base, n, repo = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
sys.path.insert(0, str(Path(repo) / "scripts"))
from poker_air_bridge import NodeRpc  # 复用同一 RPC 客户端语义

state = json.loads(Path(state_path).read_text())
anchored = state.get("anchored", {})
fails = []

# (a) 全部锚定
if len(anchored) != expect:
    fails.append(f"anchored 数 {len(anchored)} != EXPECT {expect}")

# (b) nonce 恰为 {0..EXPECT-1}：连续 + 唯一（同 nonce 双记 = 幽灵）
nonces = sorted(int(v.get("nonce", -1)) for v in anchored.values())
want = list(range(expect))
if nonces != want:
    dup = len(nonces) != len(set(nonces))
    fails.append(f"anchored nonce 序列异常（dup={dup}）：{nonces[:20]}… 期望 {want[:20]}…")

# (c) 全部节点链上 nonce == EXPECT（每笔真正执行；跨节点一致）
chain_nonces = []
for i in range(n):
    rpc = NodeRpc("127.0.0.1", rpc_base + i, timeout=5.0)
    try:
        chain_nonces.append(rpc.get_account_nonce(addr))
    except Exception as e:  # noqa: BLE001
        chain_nonces.append(f"ERR:{e}")
if any(not isinstance(x, int) or x != expect for x in chain_nonces):
    fails.append(f"链上 nonce 不一致/未达预期 {expect}：{chain_nonces}")

if fails:
    print("ASSERT FAIL:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print(f"ASSERT OK: anchored={len(anchored)}/{expect} nonces={nonces[0]}..{nonces[-1]} chain_nonce={chain_nonces}")
PY

echo "=== scenario PASSED ==="
