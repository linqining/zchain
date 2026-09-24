#!/usr/bin/env bash
# Probe: tx 提交 → 链上确认（账户 nonce 推进）延迟测量。
#
# 背景：docs/test-records/ 的演练记录只有吞吐口径（4.5s/笔/分片），
# 缺少可重复的直接延迟回归（2026-09-24 代码审查缺口）。本探针起 4 节点
# 链，从预充值账户连续提交 N 笔 Public tx，逐笔测量 submit → nonce 推进
# 的墙钟时延，输出 p50/p95/最大值与总耗时（机器可读 JSON 行 + 人类摘要）。
#
# 用法：scripts/probe_tx_latency.sh [ZCHAIN_BIN] [N_TX]
# 环境变量：BLOCK_INTERVAL_MS（默认 200）、RPC_BASE/P2P_BASE、KEEP_WORK=1
#
# 判读：serial p50 ≈ 波成熟（3 轮）+ commit 发现 + 投票/装配的端到端延迟。
#       burst total/N ≈ 稳态吞吐周期。仅测量，不设门槛（延迟目标另行立项）。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-$REPO_ROOT/target/debug/zchain}}"
NTX="${2:-20}"
BLOCK_INTERVAL_MS="${BLOCK_INTERVAL_MS:-200}"
KEEP_WORK="${KEEP_WORK:-0}"

WORK="$(mktemp -d /tmp/zchain_latency_probe.XXXXXX)"
RPC_BASE="${RPC_BASE:-18561}"
P2P_BASE="${P2P_BASE:-19100}"
N=4

cleanup() {
  if [ -f "${WORK}/.started" ]; then
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "${WORK}/.started"
    # PID 收割：节点优雅关闭实测 ~2.5 分钟；不收割则下一次探针/场景会
    # 因端口残留 bind 失败假阴性。
    for _ in $(seq 1 120); do
      alive=0
      while read -r pid; do kill -0 "$pid" 2>/dev/null && alive=1; done < "${WORK}/.started"
      [ "$alive" -eq 0 ] && break
      sleep 0.5
    done
  fi
  if [ "$KEEP_WORK" = "1" ]; then echo "keep workdir: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

[ -x "$ZCHAIN_BIN" ] || { echo "zchain 二进制不存在：$ZCHAIN_BIN" >&2; exit 1; }

# ---- 密钥 + genesis（探测账户预充值）----
PROBE_JSON="$("$ZCHAIN_BIN" keygen --scheme secp256k1)"
PROBE_SK="$(echo "$PROBE_JSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
PROBE_ADDR="$(echo "$PROBE_JSON" | grep '"address_hex"' | head -1 | sed -E 's/.*"address_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
PROBE_PUB="$(echo "$PROBE_JSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"

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
echo "  {\"pubkey_hex\": \"${PROBE_PUB}\", \"balance\": 100000000000}" >> "$ALLOC"
echo "]" >> "$ALLOC"

wait_ports_free() {
  for _ in $(seq 1 360); do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/${RPC_BASE}") 2>/dev/null; then return 0; fi
    exec 3>&- 2>/dev/null || true
    sleep 0.5
  done
}

: > "${WORK}/.started"
wait_ports_free
for ((i=0; i<N; i++)); do
  args=(node --role validator --data-dir "${WORK}/node_${i}" \
    --rpc-listen 127.0.0.1:$((RPC_BASE+i)) --p2p-listen 127.0.0.1:$((P2P_BASE+i)) \
    --validator-key-file "${WORK}/sk_${i}" --vrf-key-file "${WORK}/vrf_${i}" \
    --genesis-validators "$GV" --genesis-alloc "$ALLOC" \
    --block-interval-ms "$BLOCK_INTERVAL_MS")
  for ((j=0; j<N; j++)); do
    [ "$i" -ne "$j" ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
  done
  "$ZCHAIN_BIN" "${args[@]}" >> "${WORK}/node_${i}.log" 2>&1 &
  echo $! >> "${WORK}/.started"
done

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

# ---- 探测：串行逐笔（单笔端到端延迟）+ 突发（稳态吞吐）----
python3 - "$ZCHAIN_BIN" "$PROBE_SK" "$PROBE_ADDR" "$RPC_BASE" "$N" "$NTX" <<'PY'
import json, socket, subprocess, sys, time

zchain_bin, sk, addr, rpc_base, n_nodes, ntx = (
    sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]),
)

def call(port, method, params):
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall((req + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0].decode())

def nonce():
    resp = call(rpc_base, "get_account", {"address": list(bytes.fromhex(addr))})
    acct = resp.get("result") or {}
    return int(acct.get("nonce", 0))

def build_and_submit(nonce_val):
    out = subprocess.run(
        [zchain_bin, "tx", "--secret-key-hex", sk,
         "--payload", f'{{"v":"latency_probe","n":{nonce_val}}}', "--nonce", str(nonce_val)],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(out.stdout.strip().splitlines()[-1])
    call(rpc_base, "submit_tx", {"tx_bytes": [int(x) for x in data["tx_bytes"]]})

def wait_nonce(target, deadline_s=60.0):
    t0 = time.time()
    while time.time() - t0 < deadline_s:
        try:
            if nonce() >= target:
                return time.time() - t0
        except Exception:
            pass
        time.sleep(0.05)
    return None

def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))]

# ---- 串行：单笔端到端 ----
serial = []
for i in range(ntx):
    t0 = time.time()
    build_and_submit(i)
    d = wait_nonce(i + 1)
    if d is None:
        print(json.dumps({"error": f"serial tx {i} timeout"}))
        sys.exit(1)
    serial.append(time.time() - t0)

# ---- 突发（在途窗口 + 2s 重提；节点为严格 nonce 准入——一次性提交
# 会被 "nonce too high" 拒收，须按生产桥口径：未执行的在途 tx 定期重提）----
t_burst = time.time()
last_submit = {}
while time.time() - t_burst < 300.0:
    try:
        chain_now = nonce()
    except Exception:
        chain_now = 0
    if chain_now >= 2 * ntx:
        break
    for i in range(ntx, 2 * ntx):
        if i >= chain_now and time.time() - last_submit.get(i, 0.0) > 2.0:
            build_and_submit(i)
            last_submit[i] = time.time()
    time.sleep(0.2)
burst_total = None
if nonce() >= 2 * ntx:
    burst_total = time.time() - t_burst

result = {
    "probe": "tx_latency",
    "n_nodes": n_nodes,
    "block_interval_ms_probe": None,
    "serial": {
        "count": len(serial),
        "p50_ms": round(pct(serial, 50) * 1000, 1),
        "p95_ms": round(pct(serial, 95) * 1000, 1),
        "max_ms": round(max(serial) * 1000, 1),
        "mean_ms": round(sum(serial) / len(serial) * 1000, 1),
    },
    "burst": {
        "count": ntx,
        "total_s": round(burst_total, 2) if burst_total else None,
        "per_tx_ms": round(burst_total * 1000 / ntx, 1) if burst_total else None,
    },
}
print("PROBE_JSON=" + json.dumps(result, ensure_ascii=False))
print(
    f"serial p50={result['serial']['p50_ms']}ms p95={result['serial']['p95_ms']}ms "
    f"max={result['serial']['max_ms']}ms | burst {ntx}tx total="
    f"{result['burst']['total_s']}s ({result['burst']['per_tx_ms']}ms/tx)"
)
PY
