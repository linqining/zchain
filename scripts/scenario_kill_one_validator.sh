#!/usr/bin/env bash
# Scenario: 3 validators produce blocks -> kill one -> do the remaining 2 keep committing?
#
# Quorum semantics: required_quorum(n) = 2n/3 + 1 (strict), so for n=3 the
# certificate quorum is 3 of 3 — 2/3 is NOT sufficient. Expected outcome:
# the two survivors keep producing DAG vertices but CANNOT commit new blocks
# (height freezes). This script documents the actual behavior.
#
# Usage: scripts/scenario_kill_one_validator.sh [ZCHAIN_BIN]

set -euo pipefail

ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-./target/debug/zchain}}"
WORKDIR="$(mktemp -d /tmp/zchain_kill_one_XXXXXX)"
RPC_BASE=18545
P2P_BASE=19000
N=3

echo "=== scenario: kill one of ${N} validators, workdir ${WORKDIR} ==="
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

PIDS=()
for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "${WORKDIR}/sk_${i}"
  args=(node --role validator --data-dir "${WORKDIR}/node_${i}" \
    --rpc-listen 127.0.0.1:$((RPC_BASE+i)) --p2p-listen 127.0.0.1:$((P2P_BASE+i)) \
    --validator-key-file "${WORKDIR}/sk_${i}" --vrf-key-file "${WORKDIR}/vrf_${i}" \
    --genesis-validators "$GV" --genesis-alloc "$ALLOC" --block-interval-ms 200)
  for ((j=0; j<N; j++)); do
    [ $i -ne $j ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
  done
  "$ZCHAIN_BIN" "${args[@]}" > "${WORKDIR}/node_${i}.log" 2>&1 &
  PIDS+=($!)
done
trap 'for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done' EXIT

# Wait until all three commit blocks.
echo "waiting for all validators to commit blocks..."
for ((t=0; t<90; t++)); do
  ALL=1
  for ((i=0; i<N; i++)); do
    grep -q "commit_round=" "${WORKDIR}/node_${i}.log" 2>/dev/null || ALL=0
  done
  [ "$ALL" -eq 1 ] && break
  sleep 1
done
if [ "$ALL" -ne 1 ]; then
  echo "FAIL: not all validators committed before kill" >&2
  exit 1
fi
echo "all 3 validators committing. Heights before kill:"
for ((i=0; i<N; i++)); do
  echo "  node_${i}: $(grep -a '出块成功' "${WORKDIR}/node_${i}.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+') (last commit)"
done

# Kill validator 2.
echo "killing validator 2 (pid ${PIDS[2]})..."
kill "${PIDS[2]}"

# Give the survivors a few seconds to assemble any certificate that was already
# fully signed BEFORE the kill (the dead validator's vote stays valid); only
# commits beyond this window indicate post-kill liveness.
sleep 4
BASE_0=$(grep -ac "出块成功" "${WORKDIR}/node_0.log" || true)
BASE_1=$(grep -ac "出块成功" "${WORKDIR}/node_1.log" || true)

# Observe survivors for 30s.
echo "observing survivors for 30s..."
sleep 30
COMMIT_LINES_0=$(grep -ac "出块成功" "${WORKDIR}/node_0.log" || true)
COMMIT_LINES_1=$(grep -ac "出块成功" "${WORKDIR}/node_1.log" || true)
LAST_0=$(grep -a "出块成功" "${WORKDIR}/node_0.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+')
LAST_1=$(grep -a "出块成功" "${WORKDIR}/node_1.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+')
NEW_0=$((COMMIT_LINES_0 - BASE_0))
NEW_1=$((COMMIT_LINES_1 - BASE_1))
echo "post-kill-window commits: node_0 +${NEW_0} (last=${LAST_0}) | node_1 +${NEW_1} (last=${LAST_1})"

QUORUM_DOC="required_quorum(3) = 2*3/3+1 = 3 (strict >2/3): certificate needs ALL 3 signatures"
if [ "$NEW_0" -eq 0 ] && [ "$NEW_1" -eq 0 ]; then
  echo "RESULT: survivors produce vertices but commit NOTHING new — chain halted."
  echo "  reason: $QUORUM_DOC (2/3 is NOT sufficient by design)"
  echo "=== scenario PASSED (documented halt) ==="
  echo "log dir: ${WORKDIR}"
  exit 0
else
  echo "RESULT: survivors CONTINUED committing new blocks (+${NEW_0}/+${NEW_1})."
  echo "  NOTE: $QUORUM_DOC — continued commits would contradict documented quorum semantics."
  echo "=== scenario finished (unexpected continued liveness) ==="
  echo "log dir: ${WORKDIR}"
  exit 1
fi
