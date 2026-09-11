#!/usr/bin/env bash
# Scenario: 4 validators produce blocks -> kill one -> the 3 survivors keep committing.
#
# Quorum semantics: required_quorum(n) = 2n/3 + 1 (strict), so for n=4 the
# certificate quorum is 3 of 4 — after killing one validator the survivors
# exactly meet quorum and the chain MUST stay live. This demonstrates 1-fault
# tolerance of the 4-validator deployment (contrast: n=3 tolerates 0 faults,
# see scenario_kill_one_validator.sh).
#
# Usage: scripts/scenario_kill_one_of_four.sh [ZCHAIN_BIN]

set -euo pipefail

ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-./target/debug/zchain}}"
WORKDIR="$(mktemp -d /tmp/zchain_kill_one4_XXXXXX)"
RPC_BASE=18645
P2P_BASE=19100
N=4

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

# Wait until all four commit blocks.
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
  for ((i=0; i<N; i++)); do tail -5 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true; done
  exit 1
fi
echo "all 4 validators committing. Heights before kill:"
for ((i=0; i<N; i++)); do
  echo "  node_${i}: $(grep -a '出块成功' "${WORKDIR}/node_${i}.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+') (last commit)"
done

# Kill validator 3.
echo "killing validator 3 (pid ${PIDS[3]})..."
kill "${PIDS[3]}"

# Let in-flight certificates (signed before the kill) settle.
sleep 4
BASES=()
for ((i=0; i<3; i++)); do
  BASES+=("$(grep -ac '出块成功' "${WORKDIR}/node_${i}.log" || true)")
done

# Observe survivors for 30s: 3 survivors == quorum(4) = 3, commits MUST continue.
echo "observing 3 survivors for 30s (expect continued commits, quorum(4)=3)..."
sleep 30
TOTAL_NEW=0
SUMMARY=""
for ((i=0; i<3; i++)); do
  NOW=$(grep -ac '出块成功' "${WORKDIR}/node_${i}.log" || true)
  NEW=$((NOW - ${BASES[i]}))
  LAST=$(grep -a '出块成功' "${WORKDIR}/node_${i}.log" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -oE 'height=[0-9]+')
  TOTAL_NEW=$((TOTAL_NEW + NEW))
  SUMMARY="${SUMMARY} node_${i} +${NEW} (last=${LAST}) |"
done
echo "post-kill-window commits:${SUMMARY}"

if [ "$TOTAL_NEW" -gt 0 ]; then
  echo "RESULT: survivors CONTINUED committing after losing 1 of 4 validators."
  echo "  quorum(4) = 2*4/3+1 = 3 — 3 survivors exactly meet quorum (1-fault tolerance)."
  echo "=== scenario PASSED (4-node 1-fault tolerance) ==="
  echo "log dir: ${WORKDIR}"
  exit 0
else
  echo "RESULT: chain halted after kill — expected liveness with 3/4 survivors."
  echo "=== scenario FAILED ===" >&2
  echo "log dir: ${WORKDIR}" >&2
  exit 1
fi
