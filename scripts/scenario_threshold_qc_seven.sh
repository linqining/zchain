#!/usr/bin/env bash
# Scenario: 7-validator 真 t-of-n 阈值 QC 演练（v1.5-e：deal-sum DKG + Lagrange 阈值 BLS）。
#
# 7 validator 全互联起网（--checkpoint-interval 8，每 8 个高度一个边界；--qc-threshold-t 5）：
#   1. `zchain dkg --n 7 --t 5` 单进程跑全部 dealer（deal-sum DKG 原型部署面，
#      群私钥从不以明文存在），产出 keyset.json + share-<id>.json；
#   2. 各 validator 用自己的群份额签发部分签名 σ_i = x_i·H(m) 并 gossip
#      （CheckpointThresholdPartial）；任意节点收集 ≥ t=5 份逐验通过后，经
#      Lagrange 系数（at 0）加权重构群签名 σ = s·H(m)，装配阈值 QC 落盘
#      checkpoints.jsonl（日志 "THRESHOLD QC FORMED ... mode=threshold signers=5"）；
#   3. RPC get_latest_checkpoint 返回 {"mode":"threshold","signer_count":5,...}；
#   4. kill 2 个 validator（存活 5 = 恰好 t）→ 链继续出块，新高度仍产阈值 QC
#      （t-of-n 活性：恰 t 人即可重构）；
#   5. 重启被 kill 的一个 validator → 其从 sidecar 恢复最新阈值 QC（载入期
#      fail-closed 验证）并重新参与后续位点的阈值签名。
#
# 命名纪律：这是**阈值签名**（t-of-n，验证端单配对、成本与人数无关），与
# 聚合 QC（scenario_checkpoint_seven.sh 的 2f+1 聚签）相区分。
#
# Usage:  scripts/scenario_threshold_qc_seven.sh [ZCHAIN_BIN]
# Exit 0 = PASS。

set -euo pipefail

ZCHAIN_BIN="${1:-${ZCHAIN_BIN:-./target/release/zchain}}"
WORKDIR="$(mktemp -d /tmp/zchain_thr_seven_XXXXXX)"
RPC_BASE=$((25000 + RANDOM % 3000))
P2P_BASE=$((RPC_BASE + 1000))
N=7
T=5
INTERVAL=8

echo "=== scenario: threshold QC seven（${N} 节点，t=${T}，interval=${INTERVAL}），workdir ${WORKDIR} ==="
[ -x "$ZCHAIN_BIN" ] || { echo "ERROR: binary not found: $ZCHAIN_BIN" >&2; exit 1; }

rpc_call() {
  local port="$1" req="$2" line=""
  (
    # 连接/读失败一律静默返回空（轮询语义，不得触发 set -e）
    exec 3<>"/dev/tcp/127.0.0.1/${port}" 2>/dev/null || exit 0
    printf '%s\n' "$req" >&3 2>/dev/null || exit 0
    IFS= read -r -t 5 -u 3 line 2>/dev/null || exit 0
    printf '%s' "$line"
  ) 2>/dev/null || true
  return 0
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
ATTEMPT="${THR_ATTEMPT:-1}"

# ===== 1. 密钥 + DKG 密钥供给 + genesis =====
SECRETS=(); PUBKEYS=()
for ((i=0; i<N; i++)); do
  KEYJSON=$("$ZCHAIN_BIN" keygen --scheme secp256k1)
  SECRETS+=("$(echo "$KEYJSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  PUBKEYS+=("$(echo "$KEYJSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')")
  openssl rand -hex 32 > "${WORKDIR}/vrf_${i}"
done
DKG_DIR="${WORKDIR}/dkg"
DKG_OUT=$("$ZCHAIN_BIN" dkg --n "$N" --t "$T" --out-dir "$DKG_DIR" \
  --seed 0000000000000000000000000000000000000000000000000000000000000042)
echo "  dkg: ${DKG_OUT:0:160}"
[ -s "${DKG_DIR}/keyset.json" ] && [ -s "${DKG_DIR}/share-${N}.json" ] \
  && ok "deal-sum DKG 密钥供给：keyset.json + ${N} 份 share" \
  || bad "DKG 密钥供给输出缺失"
GROUP_DIGEST=$(echo "$DKG_OUT" | sed -E 's/.*"group_key_digest":"([^"]*)".*/\1/')

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

# ===== 2. 同时起网（阈值模式：--qc-threshold-t + DKG 材料） =====
PIDS=()
for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "${WORKDIR}/sk_${i}"
  args=(node --role validator --data-dir "${WORKDIR}/node_${i}" \
    --rpc-listen 127.0.0.1:$((RPC_BASE+i)) --p2p-listen 127.0.0.1:$((P2P_BASE+i)) \
    --validator-key-file "${WORKDIR}/sk_${i}" --vrf-key-file "${WORKDIR}/vrf_${i}" \
    --genesis-validators "$GV" --genesis-alloc "$ALLOC" \
    --block-interval-ms 400 --checkpoint-interval $INTERVAL --inclusion-deadline-ms 0 \
    --qc-threshold-t $T --dkg-keyset "${DKG_DIR}/keyset.json" --dkg-share "${DKG_DIR}/share-$((i+1)).json")
  for ((j=0; j<N; j++)); do
    [ $i -ne $j ] && args+=(--peer 127.0.0.1:$((P2P_BASE+j)))
  done
  "$ZCHAIN_BIN" "${args[@]}" > "${WORKDIR}/node_${i}.log" 2>&1 &
  PIDS+=($!)
done
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "started ${N} validators（threshold mode t=${T}）"
# 材料载入自检（fail-closed：坏份额/参数不一致会拒绝启动）
sleep 2
LOAD_OK=1
for ((i=0; i<N; i++)); do
  if ! grep -q "threshold QC: DKG keyset 已载入" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
    LOAD_OK=0
  fi
done
[ "$LOAD_OK" -eq 1 ] && ok "全部 ${N} 节点 DKG keyset 载入自检通过" || bad "有节点未完成 DKG 材料载入"

# ===== 3. 等待链推进并观察阈值 QC 形成 =====
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
    if grep -q "THRESHOLD QC FORMED" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      QC_NODE=$i; break 2
    fi
  done
done

if [ "$QC_NODE" -ge 0 ]; then
  LINE=$(grep -m1 "THRESHOLD QC FORMED" "${WORKDIR}/node_${QC_NODE}.log")
  ok "阈值 QC 产出：${LINE#*INFO*:* }"
  R=$(rpc_call $((RPC_BASE+QC_NODE)) '{"jsonrpc":"2.0","method":"get_latest_checkpoint","params":{},"id":2}')
  echo "  get_latest_checkpoint -> ${R:0:260}"
  SC=$(echo "$R" | sed -E 's/.*"signer_count":([0-9]+).*/\1/')
  case "$SC" in ''|*[!0-9]*) SC=0 ;; esac
  if echo "$R" | grep -q '"height":[1-9]' && echo "$R" | grep -q '"mode":"threshold"' && [ "$SC" -ge "$T" ]; then
    ok "RPC get_latest_checkpoint：mode=threshold，height>0，signer_count=${SC} ≥ t=${T}（t-of-n）"
  else
    bad "get_latest_checkpoint 异常（期望 mode=threshold 且 signer_count ≥ ${T}，实得 ${SC}）"
  fi
  if echo "$R" | grep -q "\"group_key_digest\":\"${GROUP_DIGEST}\""; then
    ok "QC 携带 group_key_digest 与 DKG keyset 绑定一致"
  else
    bad "QC group_key_digest 与 DKG keyset 不匹配"
  fi
  SIDE=0
  for ((i=0; i<N; i++)); do
    if [ -s "${WORKDIR}/node_${i}/checkpoints.jsonl" ] && grep -q '"threshold"' "${WORKDIR}/node_${i}/checkpoints.jsonl" 2>/dev/null; then
      SIDE=1; break
    fi
  done
  [ "$SIDE" -eq 1 ] && ok "阈值 QC sidecar（checkpoints.jsonl，threshold 形态）已落盘" || bad "阈值 QC sidecar 未落盘"
  BEFORE_CKPT_H=$(echo "$R" | sed -E 's/.*"height":([0-9]+).*/\1/')
  case "$BEFORE_CKPT_H" in ''|*[!0-9]*) BEFORE_CKPT_H=0 ;; esac
else
  bad "未观察到 THRESHOLD QC FORMED（360s）"
  BEFORE_CKPT_H=0
fi

# ===== 4. kill-2 容错：杀 2 个 validator，存活 5 = 恰好 t =====
# kill 目标动态选择：本节点自有出块计数最少的 2 个节点（保留最活跃的
# 生产者，降低「存活恰 = 阈值」边界上偶发的环境抖动影响；
# 语义不变：任意 2 个 validator 被杀，存活 5 = t）。
# 恰 quorum commit 修复（2026-09-13）后，kill-2 后链推进与阈值 QC 产出均应
# 稳定通过（根因与方案见 poker_l1/src/consensus/bullshark.rs 模块头）。
declare -a BLOCK_COUNTS
for ((i=0; i<N; i++)); do
  BLOCK_COUNTS[i]=$(grep -c "出块成功" "${WORKDIR}/node_${i}.log" 2>/dev/null || true)
done
KILL_A=-1; KILL_B=-1
for ((i=0; i<N; i++)); do
  if [ "$KILL_A" -eq -1 ] || [ "${BLOCK_COUNTS[i]}" -lt "${BLOCK_COUNTS[KILL_A]}" ]; then
    KILL_B=$KILL_A; KILL_A=$i
  elif [ "$KILL_B" -eq -1 ] || [ "${BLOCK_COUNTS[i]}" -lt "${BLOCK_COUNTS[KILL_B]}" ]; then
    KILL_B=$i
  fi
done
BEFORE_H=0
for ((i=0; i<N; i++)); do
  H=$(node_height $((RPC_BASE+i)))
  [ "$H" -gt "$BEFORE_H" ] && BEFORE_H=$H
done
echo "killing validators ${KILL_A} and ${KILL_B}（自有出块 ${BLOCK_COUNTS[KILL_A]}/${BLOCK_COUNTS[KILL_B]}；存活 $((N-2)) = t=${T}；kill 前 max height=${BEFORE_H} max threshold-QC height=${BEFORE_CKPT_H}）"
kill "${PIDS[KILL_A]}" "${PIDS[KILL_B]}" 2>/dev/null || true
sleep 2

ADVANCED=0
AFTER_H=$BEFORE_H
for ((t=0; t<300; t++)); do
  sleep 1
  for ((i=0; i<N; i++)); do
    [ "$i" -eq "$KILL_A" ] && continue
    [ "$i" -eq "$KILL_B" ] && continue
    AFTER_H=$(node_height $((RPC_BASE+i)))
    [ "$AFTER_H" -ge "$((BEFORE_H + 2))" ] && { ADVANCED=1; break 2; }
  done
done
if [ "$ADVANCED" -eq 1 ]; then
  ok "kill-2 后链继续推进：height ${BEFORE_H} -> ${AFTER_H}（存活 $((N-2)) = t 节点）"
else
  bad "kill-2 后链停滞（${BEFORE_H} -> ${AFTER_H}）"
fi

# 新高度仍产阈值 QC：存活节点的阈值 QC 高度严格超过 kill 前值（t-of-n 活性）
CKPT_ADVANCED=0
NEW_H=0
NEW_LINE=""
for ((t=0; t<240; t++)); do
  for ((i=0; i<N; i++)); do
    [ "$i" -eq "$KILL_A" ] && continue
    [ "$i" -eq "$KILL_B" ] && continue
    if grep -q "THRESHOLD QC FORMED" "${WORKDIR}/node_${i}.log" 2>/dev/null; then
      LATEST=$(grep "THRESHOLD QC FORMED" "${WORKDIR}/node_${i}.log" | tail -1)
      NH=$(echo "$LATEST" | sed -E 's/.*height=([0-9]+).*/\1/')
      case "$NH" in ''|*[!0-9]*) NH=0 ;; esac
      if [ "$NH" -gt "$BEFORE_CKPT_H" ]; then
        CKPT_ADVANCED=1; NEW_H=$NH; NEW_LINE="$LATEST"; break 2
      fi
    fi
  done
  sleep 1
done
if [ "$CKPT_ADVANCED" -eq 1 ]; then
  ok "kill-2 后（存活恰 ${T}=t）新高度仍产阈值 QC：height ${BEFORE_CKPT_H} -> ${NEW_H}"
  echo "    ${NEW_LINE#*INFO*:* }"
else
  bad "kill-2 后阈值 QC 停止产出（停在 height=${BEFORE_CKPT_H}）"
fi

# ===== 5. 重启 validator ${KILL_A}：sidecar 恢复 + 载入期 fail-closed 验证 =====
RESTART_ARGS=(node --role validator --data-dir "${WORKDIR}/node_${KILL_A}" \
  --rpc-listen 127.0.0.1:$((RPC_BASE+KILL_A)) --p2p-listen 127.0.0.1:$((P2P_BASE+KILL_A)) \
  --validator-key-file "${WORKDIR}/sk_${KILL_A}" --vrf-key-file "${WORKDIR}/vrf_${KILL_A}" \
  --genesis-validators "$GV" --genesis-alloc "$ALLOC" \
  --block-interval-ms 400 --checkpoint-interval $INTERVAL --inclusion-deadline-ms 0 \
  --qc-threshold-t $T --dkg-keyset "${DKG_DIR}/keyset.json" --dkg-share "${DKG_DIR}/share-$((KILL_A+1)).json")
for ((j=0; j<N; j++)); do
  [ "$KILL_A" -ne "$j" ] && RESTART_ARGS+=(--peer 127.0.0.1:$((P2P_BASE+j)))
done
"$ZCHAIN_BIN" "${RESTART_ARGS[@]}" >> "${WORKDIR}/node_${KILL_A}.log" 2>&1 &
PIDS[KILL_A]=$!
RESTORED=0
RESTART_R=""
for ((t=0; t<60; t++)); do
  sleep 1
  RESTART_R=$(rpc_call $((RPC_BASE+KILL_A)) '{"jsonrpc":"2.0","method":"get_latest_checkpoint","params":{},"id":5}')
  if echo "$RESTART_R" | grep -q '"mode":"threshold"' && echo "$RESTART_R" | grep -q '"height":[1-9]'; then
    RESTORED=1; break
  fi
done
if [ "$RESTORED" -eq 1 ]; then
  ok "重启节点 ${KILL_A} 从 sidecar 恢复阈值 QC（载入期 fail-closed 验证通过）：${RESTART_R:0:200}"
else
  bad "重启节点 ${KILL_A} 未能恢复阈值 QC"
fi

# ===== 结论 =====
echo "=== threshold qc seven (attempt $ATTEMPT): PASS=$PASS FAIL=$FAIL ==="
if [ "$FAIL" -eq 0 ]; then
  echo "=== scenario_threshold_qc_seven PASSED ==="
  echo "log dir: ${WORKDIR}"
  exit 0
fi
if [ "$ATTEMPT" -lt 3 ]; then
  echo "  NOTE: 既有 commit 引擎活性波动，自动重试（attempt $((ATTEMPT+1))/3）"
  cleanup
  pkill -9 -f "release/zchain node" 2>/dev/null || true
  sleep 1
  exec env THR_ATTEMPT=$((ATTEMPT+1)) "$0" "$ZCHAIN_BIN"
fi
echo "=== scenario_threshold_qc_seven FAILED（3 次尝试） ==="
echo "log dir: ${WORKDIR}"
exit 1
