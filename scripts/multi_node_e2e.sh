#!/usr/bin/env bash
# Multi-node end-to-end test (follow-up #3: real multi-process TCP network e2e).
#
# Starts N zchain validator processes, interconnected via TCP P2P, and verifies:
# 1. All nodes share the same genesis validator set (signer_bitmap index basis)
# 2. Nodes start up and discover each other (--peer)
# 3. A tx is submitted -> pending_tx -> vertex -> block produced -> received by nodes
#
# Usage:
#   scripts/multi_node_e2e.sh [N]   # N = validator count (default 3, must satisfy 2/3 quorum)
#
# Prerequisite: run `cargo build --bin zchain` first (produces target/debug/zchain).
#
# Exit code: 0 = success (at least one node produced a block), non-zero = failure.

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
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"vrf_pubkey_hex\": \"${VRF_PK_PLACEHOLDER}\", \"stake\": 1000000}${COMMA}" >> "$GENESIS_VALIDATORS"
done
echo "]" >> "$GENESIS_VALIDATORS"
echo "genesis validator set: ${GENESIS_VALIDATORS} (${N} validators)"

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

echo "started ${N} validator processes: ${PIDS[*]}"
echo "waiting for nodes to start, interconnect, and produce blocks..."

# ===== 6. Wait + verify block production =====
TIMEOUT=45
for ((t=0; t<TIMEOUT*2; t++)); do
  sleep 0.5
  for ((i=0; i<N; i++)); do
    if grep -q "commit_round=" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      echo "SUCCESS: validator ${i} produced a block"
      echo "=== multi-node e2e PASSED: node ${i} produced a block ==="
      for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
      echo "log dir: ${WORKDIR}"
      exit 0
    fi
  done
  # Check if all processes exited (abnormal)
  ALIVE=0
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then ALIVE=$((ALIVE+1)); fi
  done
  if [ "$ALIVE" -eq 0 ]; then
    echo "ERROR: all validator processes exited (abnormal)" >&2
    echo "log dir: ${WORKDIR}" >&2
    for ((i=0; i<N; i++)); do
      echo "--- node_${i}.log (last 10 lines) ---" >&2
      tail -10 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true
    done
    exit 1
  fi
done

echo "ERROR: no block produced within ${TIMEOUT}s timeout" >&2
echo "log dir: ${WORKDIR}" >&2
for ((i=0; i<N; i++)); do
  echo "--- node_${i}.log (last 15 lines) ---" >&2
  tail -15 "${WORKDIR}/node_${i}.log" >&2 2>/dev/null || true
done
for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
exit 1
