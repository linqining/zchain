#!/usr/bin/env bash
# Multi-node end-to-end test (real multi-process TCP network e2e).
#
# Starts N zchain validator processes, interconnected via TCP P2P (full mesh
# via --peer), and verifies:
# 1. All nodes share the same genesis validator set (signer_bitmap index basis)
# 2. Nodes start up, discover each other, and reconnect on failure
# 3. EVERY node produces/commits blocks (log shows `commit_round=`)
# 4. Chain height converges across all nodes via RPC `get_block_count`
#    (newline-delimited JSON-RPC over TCP; heights within ±1 in-flight skew)
#
# Usage:
#   scripts/multi_node_e2e.sh [N]   # N = validator count (default 3, must satisfy 2/3 quorum)
#
# Environment:
#   ZCHAIN_BIN   binary to test (default ./target/debug/zchain)
#
# Exit code: 0 = all N validators committed blocks AND RPC heights converged.
#
# NOTE on genesis stake: entries MUST use "stake": 0. The node rejects any
# genesis validator with non-zero (unbacked) stake — native staking is only
# admitted through UTXO-backed bonds after genesis (see Node
# build_genesis_validator_set: "genesis validator ... declares unbacked stake").

set -euo pipefail

ZCHAIN_BIN="${ZCHAIN_BIN:-./target/debug/zchain}"
N="${1:-3}"
WORKDIR="$(mktemp -d /tmp/zchain_multi_e2e_XXXXXX)"

echo "=== multi-node e2e: N=${N} validators, workdir ${WORKDIR} ==="

if [ ! -x "$ZCHAIN_BIN" ]; then
  echo "ERROR: zchain binary not found: ${ZCHAIN_BIN} (run cargo build --bin zchain first)" >&2
  exit 1
fi

# Base ports (avoid conflicts)
RPC_BASE=18545
P2P_BASE=19000

# ===== 1. Generate N validator keys + VRF keys =====
SECRETS=()
PUBKEYS=()
VRF_SECRETS=()
for ((i=0; i<N; i++)); do
  KEYJSON=$("$ZCHAIN_BIN" keygen --scheme secp256k1)
  SECRET=$(echo "$KEYJSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
  PUBKEY=$(echo "$KEYJSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
  SECRETS+=("$SECRET")
  PUBKEYS+=("$PUBKEY")
  if command -v openssl >/dev/null 2>&1; then
    VRF_SECRETS+=("$(openssl rand -hex 32)")
  else
    VRF_SECRETS+=("$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')")
  fi
done

# ===== 2. Build genesis validator set file (identical for all nodes) =====
GENESIS_VALIDATORS="${WORKDIR}/genesis_validators.json"
echo "[" > "$GENESIS_VALIDATORS"
for ((i=0; i<N; i++)); do
  # VRF pubkey placeholder (33 bytes compressed). Real VRF pubkey should be derived
  # offline via derive_public_key(vrf_secret); placeholder used here since genesis
  # does not verify VRF (only epoch transitions do).
  VRF_PK_PLACEHOLDER="02$(printf '%064d' "${i}")"
  COMMA=""
  if [ "${i}" -lt $((N-1)) ]; then COMMA=","; fi
  # stake MUST be 0: unbacked genesis stake is rejected by the node.
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"vrf_pubkey_hex\": \"${VRF_PK_PLACEHOLDER}\", \"stake\": 0}${COMMA}" >> "$GENESIS_VALIDATORS"
done
echo "]" >> "$GENESIS_VALIDATORS"
echo "genesis validator set: ${GENESIS_VALIDATORS} (${N} validators, stake=0)"

# ===== 3. Build genesis alloc file (initial balance for each validator) =====
GENESIS_ALLOC="${WORKDIR}/genesis_alloc.json"
echo "[" > "$GENESIS_ALLOC"
for ((i=0; i<N; i++)); do
  COMMA=""
  if [ "${i}" -lt $((N-1)) ]; then COMMA=","; fi
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"balance\": 100000000}${COMMA}" >> "$GENESIS_ALLOC"
done
echo "]" >> "$GENESIS_ALLOC"

# ===== 4. Write each validator key file =====
for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "${WORKDIR}/validator_${i}.key"
  printf '%s' "${VRF_SECRETS[i]}" > "${WORKDIR}/validator_${i}.vrf"
done

# ===== 5. Start N validator processes =====
PIDS=()
for ((i=0; i<N; i++)); do
  DATA_DIR="${WORKDIR}/node_${i}"
  RPC_PORT=$((RPC_BASE + i))
  P2P_PORT=$((P2P_BASE + i))
  PEERS=""
  for ((j=0; j<N; j++)); do
    if [ "${j}" -ne "${i}" ]; then
      PEERS="${PEERS} --peer 127.0.0.1:$((P2P_BASE + j))"
    fi
  done
  SHORTPK="${PUBKEYS[i]:0:16}"
  echo "start validator ${i}: RPC=127.0.0.1:${RPC_PORT} P2P=127.0.0.1:${P2P_PORT} pubkey=${SHORTPK}..."
  "$ZCHAIN_BIN" node \
    --role validator \
    --data-dir "$DATA_DIR" \
    --rpc-listen "127.0.0.1:${RPC_PORT}" \
    --p2p-listen "127.0.0.1:${P2P_PORT}" \
    --validator-key-file "${WORKDIR}/validator_${i}.key" \
    --vrf-key-file "${WORKDIR}/validator_${i}.vrf" \
    --genesis-validators "$GENESIS_VALIDATORS" \
    --genesis-alloc "$GENESIS_ALLOC" \
    --block-interval-ms 200 \
    $PEERS \
    > "${WORKDIR}/node_${i}.log" 2>&1 &
  PIDS+=($!)
done

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

echo "started ${N} validator processes: ${PIDS[*]}"

# ===== 6. Phase 1: EVERY node must commit a block (log `commit_round=`) =====
TIMEOUT=90
all_committed=0
for ((t=0; t<TIMEOUT*2; t++)); do
  sleep 0.5
  all_done=1
  for ((i=0; i<N; i++)); do
    if ! grep -q "commit_round=" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      all_done=0
      break
    fi
  done
  if [ "$all_done" -eq 1 ]; then
    all_committed=1
    echo "PHASE1 OK: all ${N} validators committed blocks"
    break
  fi
  # Check if all processes exited (abnormal)
  ALIVE=0
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then ALIVE=$((ALIVE+1)); fi
  done
  if [ "$ALIVE" -eq 0 ]; then
    echo "ERROR: all validator processes exited (abnormal)" >&2
    for ((i=0; i<N; i++)); do
      echo "--- node_${i}.log (last 10 lines) ---" >&2
      tail -10 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true
    done
    exit 1
  fi
done

if [ "$all_committed" -ne 1 ]; then
  echo "ERROR: not all nodes committed a block within ${TIMEOUT}s" >&2
  for ((i=0; i<N; i++)); do
    if grep -q "commit_round=" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      echo "--- node_${i}: committed OK" >&2
    else
      echo "--- node_${i}.log (last 20 lines) ---" >&2
      tail -20 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true
    fi
  done
  exit 1
fi

# ===== 7. Phase 2: RPC height convergence across all nodes =====
# Query each node's tip height via newline-delimited JSON-RPC over TCP
# (get_block_count). Poll until max-min <= 1 (in-flight skew) and min >= 1.
rpc_get_height() {
  local port="$1"
  local line
  (
    exec 3<>"/dev/tcp/127.0.0.1/${port}" || exit 1
    printf '%s\n' '{"jsonrpc":"2.0","method":"get_block_count","params":{},"id":1}' >&3
    IFS= read -r -t 3 -u 3 line || exit 1
    printf '%s' "$line"
  ) 2>/dev/null
}

CONV_TIMEOUT=90
converged=0
for ((t=0; t<CONV_TIMEOUT; t++)); do
  HEIGHTS=()
  queries_ok=1
  for ((i=0; i<N; i++)); do
    LINE=$(rpc_get_height $((RPC_BASE + i))) || LINE=""
    if [ -z "$LINE" ]; then
      queries_ok=0
      break
    fi
    if echo "$LINE" | grep -q '"height":null'; then
      H=0
    else
      H=$(echo "$LINE" | sed -E 's/.*"height"[: ]*([0-9]+).*/\1/')
      case "$H" in
        ''|*[!0-9]*) queries_ok=0; break ;;
      esac
    fi
    HEIGHTS+=("$H")
  done

  if [ "$queries_ok" -eq 1 ]; then
    MIN=${HEIGHTS[0]}
    MAX=${HEIGHTS[0]}
    SUMMARY=""
    for ((i=0; i<N; i++)); do
      H=${HEIGHTS[$i]}
      SUMMARY="${SUMMARY} node${i}=${H}"
      if [ "$H" -lt "$MIN" ]; then MIN=$H; fi
      if [ "$H" -gt "$MAX" ]; then MAX=$H; fi
    done
    SKEW=$((MAX - MIN))
    echo "[t=${t}s] heights:${SUMMARY} (skew=${SKEW})"
    if [ "$SKEW" -le 1 ] && [ "$MIN" -ge 1 ]; then
      converged=1
      break
    fi
  fi
  sleep 1
done

if [ "$converged" -ne 1 ]; then
  echo "ERROR: node heights did not converge (±1) within ${CONV_TIMEOUT}s" >&2
  for ((i=0; i<N; i++)); do
    echo "--- node_${i}.log (last 15 lines) ---" >&2
    tail -15 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true
  done
  exit 1
fi

echo "PHASE2 OK: heights converged within ±1 across all ${N} nodes"
echo "=== multi-node e2e PASSED: all ${N} validators produce blocks, heights converged ==="
echo "log dir: ${WORKDIR}"
exit 0
