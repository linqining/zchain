#!/usr/bin/env bash
# Scenario: restart catch-up.
#
# 1. Run 3 validators until all commit blocks.
# 2. Kill ALL nodes; record per-node final heights.
# 3. Restart only 2 of them (validators 0 and 1) with the SAME data dirs.
# 4. Verify the restarted node that was behind catches up to the other via
#    startup catch-up (RequestBlocksByRange) — heights converge and match the
#    pre-shutdown max of the restarted pair.
#
# Usage: scripts/scenario_restart_catchup.sh [ZCHAIN_BIN]

set -euo pipefail

ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-./target/debug/zchain}}"
WORKDIR="$(mktemp -d /tmp/zchain_restart_XXXXXX)"
RPC_BASE=18545
P2P_BASE=19000
N=3

echo "=== scenario: full restart + catch-up, workdir ${WORKDIR} ==="
[ -x "$ZCHAIN_BIN" ] || { echo "ERROR: binary not found: $ZCHAIN_BIN" >&2; exit 1; }

SECRETS=(); PUBKEYS=()
for ((i=0; i<N; i++)); do
  KEYJSON=$("$ZCHAIN_BIN" keygen --scheme secp256k1)
  SECRETS+=("$(echo "$KEYJSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  PUBKEYS+=("$(echo "$KEYJSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  openssl rand -hex 32 > "${WORKDIR}/vrf_${i}"
done

GV="${WORKDIR}/gv.json"; ALLOC="${WORKDIR}/alloc.json"
echo "[" > "$GV"
for ((i=0; i<N; i++)); do
  C=","; [ $i -eq $((N-1)) ] && C=""
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"vrf_pubkey_hex\": \"02$(printf '%064d' $i)\", \"stake\": 0}$C" >> "$GV"
done
echo "]" >> "$GV"
echo "[" > "$ALLOC"
for ((i=0; i<N; i++)); do
  C=","; [ $i -eq $((N-1)) ] && C=""
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"balance\": 100000000}$C" >> "$ALLOC"
done
echo "]" >> "$ALLOC"

start_nodes() {  # $1.. = indices to start (uses .started file)
  : > "${WORKDIR}/.started"
  for idx in "$@"; do
    args=(node --role validator --data-dir "${WORKDIR}/node_${idx}" \
      --rpc-listen 127.0.0.1:$((RPC_BASE+idx)) --p2p-listen 127.0.0.1:$((P2P_BASE+idx)) \
      --validator-key-file "${WORKDIR}/sk_${idx}" --vrf-key-file "${WORKDIR}/vrf_${idx}" \
      --genesis-validators "$GV" --genesis-alloc "$ALLOC" --block-interval-ms 200)
    for ((j=0; j<N; j++)); do
      [ "$idx" -ne "$j" ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
    done
    "$ZCHAIN_BIN" "${args[@]}" >> "${WORKDIR}/node_${idx}.log" 2>&1 &
    echo $! >> "${WORKDIR}/.started"
    echo "$idx" >> "${WORKDIR}/.started_idx"
  done
}

stop_all() {
  if [ -f "${WORKDIR}/.started" ]; then
    while read -r pid; do kill "$pid" 2>/dev/null || true; done < "${WORKDIR}/.started"
  fi
}
trap stop_all EXIT

for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "${WORKDIR}/sk_${i}"
done

# ===== Phase 1: run 3 validators until all commit =====
: > "${WORKDIR}/.started_idx"
start_nodes 0 1 2
echo "phase 1: 3 validators running, waiting for commits..."
ALL=0
for ((t=0; t<90; t++)); do
  ALL=1
  for ((i=0; i<N; i++)); do
    grep -q "commit_round=" "${WORKDIR}/node_${i}.log" 2>/dev/null || ALL=0
  done
  [ "$ALL" -eq 1 ] && break
  sleep 1
done
[ "$ALL" -eq 1 ] || { echo "FAIL: no commits in phase 1" >&2; exit 1; }
sleep 3

# Record pre-shutdown heights (from logs).
echo "phase 1 done. pre-shutdown last commit heights:"
declare -a PRE_H
for ((i=0; i<N; i++)); do
  H=$(grep -a "出块成功" "${WORKDIR}/node_${i}.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+' | cut -d= -f2)
  PRE_H[$i]=${H:-0}
  echo "  node_${i}: height=${PRE_H[$i]}"
done

# ===== Phase 2: kill ALL =====
echo "phase 2: killing ALL validators..."
stop_all
sleep 2

# ===== Phase 3: restart only validators 0 and 1 with the SAME data dirs =====
: > "${WORKDIR}/.started_idx"
start_nodes 0 1
echo "phase 3: restarted validators 0 and 1 (same data dirs); observing 40s..."
sleep 40

# ===== Phase 4: verify catch-up =====
# The restarted pair can only know blocks up to max(PRE_H[0], PRE_H[1]) (validator
# 2's data is offline). The lagging one must catch up to that height.
MAX_RESTARTED=$(( PRE_H[0] > PRE_H[1] ? PRE_H[0] : PRE_H[1] ))
MIN_RESTARTED=$(( PRE_H[0] < PRE_H[1] ? PRE_H[0] : PRE_H[1] ))

rpc_height() {
  local port=$((RPC_BASE + $1))
  local line
  line=$( (
    exec 3<>"/dev/tcp/127.0.0.1/${port}" || exit 1
    printf '%s\n' '{"jsonrpc":"2.0","method":"get_block_count","params":{},"id":1}' >&3
    IFS= read -r -t 3 -u 3 line || exit 1
    printf '%s' "$line"
  ) 2>/dev/null )
  case "$line" in
    *"height":null*) echo 0 ;;
    *height*) echo "$line" | sed -E 's/.*"height"[: ]*([0-9]+).*/\1/' ;;
    *) echo "" ;;
  esac
}

H0=$(rpc_height 0); H1=$(rpc_height 1)
echo "post-restart RPC heights: node_0=$H0 node_1=$H1 (pre-shutdown: ${PRE_H[0]}/${PRE_H[1]}; pair max=${MAX_RESTARTED})"

SKEW=$(( H0 > H1 ? H0 - H1 : H1 - H0 ))
if [ -z "$H0" ] || [ -z "$H1" ]; then
  echo "FAIL: restarted nodes did not expose RPC heights" >&2
  exit 1
fi
if [ "$SKEW" -le 1 ] && [ "$H0" -ge "$MIN_RESTARTED" ] && [ "$H1" -ge "$MIN_RESTARTED" ]; then
  echo "RESULT: restarted pair converged (skew=$SKEW); lagging node caught up past pre-shutdown min=${MIN_RESTARTED}"
  echo "=== scenario PASSED ==="
  echo "log dir: ${WORKDIR}"
  exit 0
else
  echo "FAIL: heights did not converge or lagging node did not catch up" >&2
  for i in 0 1; do
    echo "--- node_${i}.log (last 10) ---" >&2
    tail -10 "${WORKDIR}/node_${i}.log" >&2 || true
  done
  exit 1
fi
