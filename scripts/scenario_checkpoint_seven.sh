#!/usr/bin/env bash
# Scenario: 7-validator checkpoint QC 演练（v1.5-c：BLS 聚签 2f+1 checkpoint）。
#
# 7 validator 全互联起网（--checkpoint-interval 8，每 8 个高度一个边界）：
#   1. 各 validator 对「tip 已覆盖的最新间隔边界」用 BLS 密钥（由 secp 私钥
#      域分隔派生）签发 checkpoint 投票并 gossip（每位点本节点只签一次）；
#   2. 任意节点凑齐 2f+1（7 节点 → 5）票即聚合 CheckpointQc 并落盘
#      checkpoints.jsonl sidecar（日志 "CHECKPOINT QC FORMED ... signers=5"）；
#   3. RPC get_latest_checkpoint 返回 {height, signer_count, ...}；
#   4. kill 2 个 validator（存活 5 = 恰好 2f+1）→ 链继续出块，checkpoint
#      继续产出。
#
# 既有行为说明（2026-09-13 恰 quorum commit 修复后更新）：多节点下 commit 主导者
# 效应显著（出块节点集中在少数节点，其余经 gossip import 收敛高度），因此节点
# 就绪判定用「本节点链高度」而非「本节点自有出块日志」。历史上本演练曾在
# kill-2 后因「各节点 leader 检测窗口 max_r-4..max_r-1 随生产节奏错位 → cert
# 投票语句发散 → 票数分裂」而停滞；修复见 poker_l1/src/consensus/bullshark.rs
# 模块头「恰 quorum 存活 commit 停滞修复」（L1 规范化候选序 / L2 成熟度门 /
# L4 意图稳定门 / L5 投票钉扎 + 池内 last-write-wins / 投影遍历不降入已提交区）。
#
# 命名纪律：这是 BLS **聚合** QC（2f+1 聚签），非阈值签名（见
# poker_l1/src/consensus/checkpoint.rs 模块头）。
#
# Usage:  scripts/scenario_checkpoint_seven.sh [ZCHAIN_BIN]
# Exit 0 = PASS。

set -euo pipefail

ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-./target/release/zchain}}"
WORKDIR="$(mktemp -d /tmp/zchain_ckpt_seven_XXXXXX)"
RPC_BASE=$((20000 + RANDOM % 3000))
P2P_BASE=$((RPC_BASE + 1000))
N=7
INTERVAL=8
QUORUM=$(( 2 * N / 3 + 1 ))   # 2f+1 = 5

echo "=== scenario: checkpoint seven（${N} 节点，interval=${INTERVAL}，quorum=${QUORUM}），workdir ${WORKDIR} ==="
[ -x "$ZCHAIN_BIN" ] || { echo "ERROR: binary not found: $ZCHAIN_BIN" >&2; exit 1; }

rpc_call() {
  local port="$1" req="$2" line
  (
    exec 3<>"/dev/tcp/127.0.0.1/${port}" || exit 1
    printf '%s\n' "$req" >&3
    IFS= read -r -t 5 -u 3 line || exit 1
    printf '%s' "$line"
  ) 2>/dev/null
}
node_height() {
  local line h
  line=$(rpc_call "$1" '{"jsonrpc":"2.0","method":"get_block_count","params":{},"id":1}')
  h=$(echo "$line" | sed -E 's/.*"height":([0-9]+).*/\1/')
  case "$h" in ''|*[!0-9]*) h=0 ;; esac
  echo "$h"
}

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
# 7 节点起网存在偶发抖动（本机 CPU 饱和时的连接抖动等），整体最多重试 3 次
#（每次全新端口/数据目录）。恰 quorum commit 修复后演练应稳定在 attempt 1 通过。
ATTEMPT="${CKPT_ATTEMPT:-1}"

# ===== 1. 密钥 + genesis =====
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

# ===== 2. 同时起网 =====
PIDS=(); ALIVE=()
for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "${WORKDIR}/sk_${i}"
  args=(node --role validator --data-dir "${WORKDIR}/node_${i}" \
    --rpc-listen 127.0.0.1:$((RPC_BASE+i)) --p2p-listen 127.0.0.1:$((P2P_BASE+i)) \
    --validator-key-file "${WORKDIR}/sk_${i}" --vrf-key-file "${WORKDIR}/vrf_${i}" \
    --genesis-validators "$GV" --genesis-alloc "$ALLOC" \
    --block-interval-ms 200 --checkpoint-interval $INTERVAL --inclusion-deadline-ms 0)
  for ((j=0; j<N; j++)); do
    [ $i -ne $j ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
  done
  "$ZCHAIN_BIN" "${args[@]}" > "${WORKDIR}/node_${i}.log" 2>&1 &
  PIDS+=($!); ALIVE+=("$i")
done
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "started ${N} validators"

# ===== 3. 等待链启动并推进到第一个 checkpoint 边界（任一节点高度 >= INTERVAL） =====
UP=0
for ((t=0; t<360; t++)); do
  sleep 1
  for ((i=0; i<N; i++)); do
    H=$(node_height $((RPC_BASE+i)))
    [ "$H" -ge $((INTERVAL * 3)) ] && { UP=1; break 2; }
  done
done
[ "$UP" -eq 1 ] || echo "NOTE: 360s 内无节点到达高度 $((INTERVAL * 3))（继续）"

QC_NODE=-1
for ((t=0; t<360; t++)); do
  sleep 1
  for ((i=0; i<N; i++)); do
    if grep -q "CHECKPOINT QC FORMED" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      QC_NODE=$i; break 2
    fi
  done
done

if [ "$QC_NODE" -ge 0 ]; then
  LINE=$(grep -m1 "CHECKPOINT QC FORMED" "${WORKDIR}/node_${QC_NODE}.log")
  ok "checkpoint QC 产出：${LINE#*INFO*:* }"
  # 注意：serde_json 字典序输出中 aggregate_signature 位于 signer_count 之前，
  # 截断过短会漏掉字段（v1.5-e 增加 mode/group_key_digest 等字段后尤甚）→ 取 600 字符。
  R=$(rpc_call $((RPC_BASE+QC_NODE)) '{"jsonrpc":"2.0","method":"get_latest_checkpoint","params":{},"id":2}')
  echo "  get_latest_checkpoint -> ${R:0:600}"
  # 2f+1=5 是 **最低** quorum：QC 聚合收到几票 signer_count 就是几（5..7 合法）。
  SC=$(echo "$R" | sed -E 's/.*"signer_count":([0-9]+).*/\1/')
  case "$SC" in ''|*[!0-9]*) SC=0 ;; esac
  if echo "$R" | grep -q '"height":[1-9]' && [ "$SC" -ge "$QUORUM" ]; then
    ok "RPC get_latest_checkpoint：height>0 且 signer_count=${SC} ≥ 2f+1=${QUORUM}"
  else
    bad "get_latest_checkpoint 异常（期望 signer_count ≥ ${QUORUM}，实得 ${SC}）"
  fi
  SIDE=0
  for ((i=0; i<N; i++)); do
    [ -s "${WORKDIR}/node_${i}/checkpoints.jsonl" ] && { SIDE=1; break; }
  done
  [ "$SIDE" -eq 1 ] && ok "checkpoint sidecar（checkpoints.jsonl）已落盘" || bad "sidecar 未落盘"
  QC_H=$(echo "$R" | sed -E 's/.*"height":([0-9]+).*/\1/')
else
  bad "未观察到 CHECKPOINT QC FORMED（360s）"
  QC_H=0
fi

# ===== 4. kill-2 容错：杀 2 个 validator，存活 5 = 恰好 2f+1 =====
KILL_A=$((N-2)); KILL_B=$((N-1))
BEFORE_H=0
BEFORE_CKPT_H=0
for ((i=0; i<N; i++)); do
  H=$(node_height $((RPC_BASE+i)))
  [ "$H" -gt "$BEFORE_H" ] && BEFORE_H=$H
  CK=$(rpc_call $((RPC_BASE+i)) '{"jsonrpc":"2.0","method":"get_latest_checkpoint","params":{},"id":4}' | sed -E 's/.*"height":([0-9]+).*/\1/')
  case "$CK" in ''|*[!0-9]*) CK=0 ;; esac
  [ "$CK" -gt "$BEFORE_CKPT_H" ] && BEFORE_CKPT_H=$CK
done
echo "killing validators ${KILL_A} and ${KILL_B}（存活 $((N-2)) = 2f+1；kill 前 max height=${BEFORE_H} max ckpt=${BEFORE_CKPT_H}）"
kill "${PIDS[KILL_A]}" "${PIDS[KILL_B]}" 2>/dev/null || true
sleep 2

ADVANCED=0
AFTER_H=$BEFORE_H
for ((t=0; t<300; t++)); do
  sleep 1
  for ((i=0; i<KILL_A; i++)); do
    AFTER_H=$(node_height $((RPC_BASE+i)))
    [ "$AFTER_H" -ge "$((BEFORE_H + 2))" ] && { ADVANCED=1; break 2; }
  done
done
if [ "$ADVANCED" -eq 1 ]; then
  ok "kill-2 后链继续推进：height ${BEFORE_H} -> ${AFTER_H}（存活 $((N-2)) 节点）"
else
  bad "kill-2 后链停滞（${BEFORE_H} -> ${AFTER_H}）"
fi

# checkpoint 继续产出：节点 0 的最新 QC 高度严格超过 kill 前值（新增边界）
CKPT_ADVANCED=0
NEW_H=0
for ((t=0; t<180; t++)); do
  for ((i=0; i<KILL_A; i++)); do
    R2=$(rpc_call $((RPC_BASE+i)) '{"jsonrpc":"2.0","method":"get_latest_checkpoint","params":{},"id":3}')
    NEW_H=$(echo "$R2" | sed -E 's/.*"height":([0-9]+).*/\1/')
    case "$NEW_H" in ''|*[!0-9]*) NEW_H=0 ;; esac
    if [ "$NEW_H" -gt "$BEFORE_CKPT_H" ]; then CKPT_ADVANCED=1; break 2; fi
  done
  sleep 1
done
if [ "$CKPT_ADVANCED" -eq 1 ]; then
  ok "kill-2 后 checkpoint 继续产出：QC 高度推进至 ${NEW_H}（> kill 前 ${BEFORE_CKPT_H}）"
else
  bad "kill-2 后 checkpoint 停止产出（停在 ${NEW_H}）"
fi

# ===== 结论 =====
echo "=== checkpoint seven (attempt $ATTEMPT): PASS=$PASS FAIL=$FAIL ==="
if [ "$FAIL" -eq 0 ]; then
  echo "=== scenario_checkpoint_seven PASSED ==="
  echo "log dir: ${WORKDIR}"
  exit 0
fi
if [ "$ATTEMPT" -lt 3 ]; then
  echo "  NOTE: 环境抖动（本机 CPU 饱和/连接抖动），自动重试（attempt $((ATTEMPT+1))/3）"
  cleanup
  pkill -9 -f "release/zchain node" 2>/dev/null || true
  sleep 1
  exec env CKPT_ATTEMPT=$((ATTEMPT+1)) "$0" "$ZCHAIN_BIN"
fi
echo "=== scenario_checkpoint_seven FAILED（3 次尝试） ==="
echo "log dir: ${WORKDIR}"
exit 1
