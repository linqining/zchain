#!/usr/bin/env bash
# Scenario: 结算锚定桥故障注入门——复刻 2026-09-21「同 nonce 幽灵 anchored
# 记录」bug 的触发条件（commit 4b3da1a 根修），固化为其回归测试。
#
# 原 bug 机理（scripts/poker_air_bridge.py strict_chain_nonce docstring）：
#   chain_nonce 四路读取全部失败 → 回退陈旧本地游标 → 陈旧 nonce 的
#   submit 被节点静默拒绝 → 确认判据「chain_nonce > nonce」误判已确认
#   → 同一 nonce 被两个 binding 记入 anchored（其一从未上链）。
# 根修：读取失败 fail-closed（跳过本轮，绝不用陈旧 nonce 提交）。
#
# 流程：
#   1. 起链（4 节点）+ demo WAL + 预充值桥账户（同 scenario_bridge_anchor.sh）；
#   2. Phase A（正常）：锚定前 2 笔（--target 2）；
#   3. Phase B（注入）：kill 全部节点 → 桥跑一轮（链 nonce 完全不可读）：
#      断言 fail-closed 消息出现（"chain nonce 不可读，本轮跳过批量" +
#      "chain nonce 持续不可读，退出本轮 stream"）且 anchored 无新增、
#      无任何携带陈旧 nonce 的提交尝试；
#   4. Phase C（恢复）：同数据目录重启全部节点，断言链恢复出块；
#   5. Phase D（续跑）：同 state 文件重启桥锚完剩余笔数；
#   6. Phase E（无幽灵终检）：
#      a. anchored 数 == EXPECT；
#      b. anchored nonce 恰为 {0..EXPECT-1}（连续、唯一——同 nonce 双记
#         即幽灵）；
#      c. 全部节点链上 nonce == EXPECT 且 ≥ 每个 anchored nonce + 1
#         （每笔都已真正执行，无「记录在案但从未上链」的幽灵）。
#
# 用法：scripts/scenario_bridge_ghost_nonce.sh [ZCHAIN_BIN]
# 环境变量：BRIDGE_HANDS（默认 8，需 ≥4）、GATEWAY_BIN、RAKE_AUDIT_BIN、
#           KEEP_WORK=1（保留现场目录）

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-$REPO_ROOT/target/debug/zchain}}"
GATEWAY_BIN="${GATEWAY_BIN:-$REPO_ROOT/target/release/explorer_gateway}"
RAKE_AUDIT_BIN="${RAKE_AUDIT_BIN:-$REPO_ROOT/target/release/rake_audit}"
BRIDGE_PY="$REPO_ROOT/scripts/poker_air_bridge.py"
HANDS="${BRIDGE_HANDS:-8}"
KEEP_WORK="${KEEP_WORK:-0}"

WORK="$(mktemp -d /tmp/zchain_bridge_ghost.XXXXXX)"
# 端口默认避开 deploy_4node/scenario 系列的 18545/19000（本机可能有常驻
# 部署占用）。RPC_BASE 必须满足 (port-5)%4==0——桥按该式推导 fan 端口组。
RPC_BASE="${RPC_BASE:-18549}"
P2P_BASE="${P2P_BASE:-19010}"
N=4

cleanup() {
  if [ -f "${WORK}/.started" ]; then
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "${WORK}/.started"
  fi
  if [ "$KEEP_WORK" = "1" ]; then
    echo "keep workdir: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

if [ ! -x "$ZCHAIN_BIN" ]; then
  echo "[bridge-ghost] 构建 zchain（debug）……"
  (cd "$REPO_ROOT" && cargo build -p zchain)
fi
if [ ! -x "$GATEWAY_BIN" ] || [ ! -x "$RAKE_AUDIT_BIN" ]; then
  echo "[bridge-ghost] 构建 rake_audit / explorer_gateway（release）……"
  (cd "$REPO_ROOT" && cargo build --release -p poker-appchain --bin rake_audit --bin explorer_gateway)
fi

echo "=== scenario: bridge ghost-nonce fault injection, workdir $WORK ==="

# ===== 1. WAL + index + EXPECT =====
"$RAKE_AUDIT_BIN" selftest --dir "$WORK/walgen" --hands "$HANDS" > "$WORK/selftest.out"
WAL="$(grep '^WAL=' "$WORK/selftest.out" | cut -d= -f2-)"
SEQ_PUB="$(grep '^SEQUENCER_PUBLIC=' "$WORK/selftest.out" | cut -d= -f2-)"
[ -n "$WAL" ] && [ -n "$SEQ_PUB" ] || { echo "FAIL: selftest 输出解析失败" >&2; exit 1; }

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
[ "${EXPECT:-0}" -ge 4 ] || { echo "FAIL: Settle 行数 $EXPECT < 4（用 BRIDGE_HANDS≥4）" >&2; exit 1; }
echo "EXPECT=$EXPECT"

# ===== 2. 密钥 + genesis + 起 4 节点 =====
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
stop_nodes() {
  if [ -s "${WORK}/.started" ]; then
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "${WORK}/.started"
    # 等进程真正退出：节点优雅关闭含长 join（实测 SIGTERM 后 ~2.5 分钟才
    # 释放端口；不等就重启 → 新进程 bind 失败秒死 → Phase C 假阴性）。
    for _ in $(seq 1 360); do
      alive=0
      while read -r pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < "${WORK}/.started"
      [ "$alive" -eq 0 ] && break
      sleep 0.5
    done
    : > "${WORK}/.started"
  fi
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

STATE="$WORK/bridge_state.json"

# ===== Phase A：正常锚定前 2 笔 =====
echo "== Phase A: 锚定前 2 笔（正常路径）=="
set +e
python3 "$BRIDGE_PY" bridge \
  --secret-key-hex "$BRIDGE_SK" --address "$BRIDGE_ADDR" \
  --rpc-port "$RPC_BASE" --rpc-host 127.0.0.1 \
  --wal "$WAL" --sequencer-public "$SEQ_PUB" \
  --gateway-bin "$GATEWAY_BIN" --zchain-bin "$ZCHAIN_BIN" \
  --state-file "$STATE" \
  --stream-only --target 2 --max-rounds 10 --poll-secs 2 --wait-secs 30 \
  2>&1 | tee "$WORK/bridge_a.log"
RC_A=${PIPESTATUS[0]}
set -e
[ "$RC_A" -eq 0 ] && grep -q "target reached" "$WORK/bridge_a.log" \
  || { echo "FAIL: Phase A 未锚定 2 笔" >&2; exit 1; }
ANCHORED_A=$(python3 -c "import json;print(len(json.load(open('$STATE')).get('anchored',{})))")
[ "$ANCHORED_A" = "2" ] || { echo "FAIL: Phase A anchored=$ANCHORED_A != 2" >&2; exit 1; }
echo "Phase A OK: anchored=2"

# ===== Phase B：kill 全部节点 → 桥一轮全读取失败（fail-closed 断言）=====
echo "== Phase B: kill 全部 4 节点，注入「链 nonce 四路读取失败」=="
PRE_MARKS=()
for ((i=0; i<N; i++)); do PRE_MARKS+=("$(wc -l < "${WORK}/node_${i}.log" | tr -d ' ')"); done
stop_nodes
sleep 2

set +e
# 期望一轮内：strict_chain_nonce 重试耗尽 → 两条 fail-closed 消息 → 本轮跳过。
timeout 150 python3 "$BRIDGE_PY" bridge \
  --secret-key-hex "$BRIDGE_SK" --address "$BRIDGE_ADDR" \
  --rpc-port "$RPC_BASE" --rpc-host 127.0.0.1 \
  --wal "$WAL" --sequencer-public "$SEQ_PUB" \
  --gateway-bin "$GATEWAY_BIN" --zchain-bin "$ZCHAIN_BIN" \
  --state-file "$STATE" \
  --max-rounds 1 --poll-secs 1 --wait-secs 10 \
  2>&1 | tee "$WORK/bridge_b.log"
RC_B=${PIPESTATUS[0]}
set -e
[ "$RC_B" -eq 0 ] || { echo "FAIL: Phase B 桥异常退出 rc=$RC_B" >&2; exit 1; }

# 不带 --stream-only：批量路径与 stream 路径的 fail-closed 都必须触发。
fail_closed_ok=1
grep -q "chain nonce 不可读，本轮跳过批量" "$WORK/bridge_b.log" || { fail_closed_ok=0; echo "缺失 fail-closed 消息：批量路径未跳过（陈旧 nonce 提交风险）" >&2; }
grep -q "chain nonce 持续不可读，退出本轮 stream" "$WORK/bridge_b.log" || { fail_closed_ok=0; echo "缺失 fail-closed 消息：stream 路径未退出（陈旧 nonce 提交风险）" >&2; }
[ "$fail_closed_ok" -eq 1 ] || exit 1

python3 - "$STATE" <<'PY' || exit 1
import json, sys
state = json.loads(open(sys.argv[1]).read())
anchored = state.get("anchored", {})
if len(anchored) != 2:
    print(f"FAIL: 断链期间 anchored 变化：{len(anchored)} != 2（疑似幽灵记录）")
    sys.exit(1)
print("Phase B OK: fail-closed 生效，anchored 保持 2，无陈旧 nonce 提交")
PY

# ===== Phase C：同数据目录重启全部节点，链恢复出块 =====
echo "== Phase C: 重启全部节点（同数据目录），等待恢复出块 =="
start_nodes 0 1 2 3
# 恢复窗口 120s：实测全灭重启后首笔 commit ~20s（含 BlockStore 易失导致
# 的历史波重放，见 docs/test-records/2026-09-24-bridge-gates-consensus-poc-p0-4.md）
RESUMED=0
for ((t=0; t<120; t++)); do
  RESUMED=1
  for ((i=0; i<N; i++)); do
    # 不能写 `tail | grep -q`：pipefail 下 grep -q 命中即退出会使 tail 收
    # SIGPIPE（141），整条管道被判失败——恰在匹配成功时误判（bash 3.2 实测）。
    tail -n +$((PRE_MARKS[i]+1)) "${WORK}/node_${i}.log" | grep -a "commit_round=" > /dev/null || RESUMED=0
  done
  [ "$RESUMED" -eq 1 ] && break
  echo -n "."; sleep 1
done
echo
[ "$RESUMED" -eq 1 ] || { echo "FAIL: 重启后未恢复出块" >&2; exit 1; }
echo "Phase C OK: 链恢复出块"

# ===== Phase D：续跑锚完剩余 =====
echo "== Phase D: 续跑锚定至 EXPECT=$EXPECT =="
set +e
python3 "$BRIDGE_PY" bridge \
  --secret-key-hex "$BRIDGE_SK" --address "$BRIDGE_ADDR" \
  --rpc-port "$RPC_BASE" --rpc-host 127.0.0.1 \
  --wal "$WAL" --sequencer-public "$SEQ_PUB" \
  --gateway-bin "$GATEWAY_BIN" --zchain-bin "$ZCHAIN_BIN" \
  --state-file "$STATE" \
  --stream-only --target "$EXPECT" --max-rounds 10 --poll-secs 2 --wait-secs 30 \
  2>&1 | tee "$WORK/bridge_d.log"
RC_D=${PIPESTATUS[0]}
set -e
[ "$RC_D" -eq 0 ] && grep -q "target reached" "$WORK/bridge_d.log" \
  || { echo "FAIL: Phase D 未达 target" >&2; exit 1; }

# ===== Phase E：无幽灵终检 =====
python3 - "$STATE" "$BRIDGE_ADDR" "$EXPECT" "$RPC_BASE" "$N" "$REPO_ROOT" <<'PY'
import json, sys
from pathlib import Path

state_path, addr, expect, rpc_base, n, repo = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6]
sys.path.insert(0, str(Path(repo) / "scripts"))
from poker_air_bridge import NodeRpc

state = json.loads(Path(state_path).read_text())
anchored = state.get("anchored", {})
fails = []

if len(anchored) != expect:
    fails.append(f"anchored 数 {len(anchored)} != EXPECT {expect}")

nonces = sorted(int(v.get("nonce", -1)) for v in anchored.values())
if nonces != list(range(expect)) or len(set(nonces)) != len(nonces):
    fails.append(f"anchored nonce 序列异常（幽灵=同 nonce 双记/断档）：{nonces}")

chain_nonces = []
for i in range(n):
    rpc = NodeRpc("127.0.0.1", rpc_base + i, timeout=5.0)
    try:
        chain_nonces.append(rpc.get_account_nonce(addr))
    except Exception as e:  # noqa: BLE001
        chain_nonces.append(f"ERR:{e}")
if any(not isinstance(x, int) or x != expect for x in chain_nonces):
    fails.append(f"链上 nonce 未收敛到 {expect}：{chain_nonces}")
else:
    # 每笔 anchored nonce 都必须已被链执行（nonce < chain_nonce），
    # 否则即「记录在案但从未上链」的幽灵。
    ghosts = [v for v in nonces if v >= expect]
    if ghosts:
        fails.append(f"幽灵 nonce（未被执行却记 anchored）：{ghosts}")

if fails:
    print("ASSERT FAIL:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print(f"ASSERT OK: anchored={len(anchored)}/{expect} nonces=0..{nonces[-1]} chain_nonce={chain_nonces[0]}（全部节点一致，无幽灵）")
PY

echo "=== scenario PASSED ==="
