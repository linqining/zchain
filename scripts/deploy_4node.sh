#!/usr/bin/env bash
# 常驻 4 节点 zchain 部署（本地/服务器通用）。
#
# 与 scripts/multi_node_e2e.sh 的差异：不自动清理——节点常驻运行，
# 供 poker_texas_air 服务与结算桥接长期使用。重复执行会先停掉旧实例
# （按 pid 文件）再重新部署。
#
# 用法：
#   bash scripts/deploy_4node.sh [N]        # N = 节点数（默认 4）
#   bash scripts/deploy_4node.sh stop       # 停止全部节点
#
# 产物布局（DEPLOY_DIR，默认 /tmp/zchain-4node，服务器建议 /opt/zchain-4node）：
#   genesis_validators.json / genesis_alloc.json
#   validator_{i}.key / validator_{i}.vrf
#   node_{i}/ 数据目录 + node_{i}.log 日志 + node_{i}.pid
#   rpc_ports.txt（RPC 端口清单）
set -euo pipefail

ZCHAIN_BIN="${ZCHAIN_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug/zchain}"
N="${1:-4}"
DEPLOY_DIR="${DEPLOY_DIR:-/tmp/zchain-4node}"
RPC_BASE="${RPC_BASE:-18545}"
P2P_BASE="${P2P_BASE:-19000}"
BLOCK_INTERVAL_MS="${BLOCK_INTERVAL_MS:-200}"
# RPC 监听地址：远程部署（外部服务/浏览器需要访问链）时设 0.0.0.0。
RPC_HOST="${RPC_HOST:-127.0.0.1}"
# 额外 genesis 充值账户（逗号分隔 pubkey_hex）：如本地结算桥账户——
# 远程链无 transfer 交易，桥账户必须有 genesis 余额才能提交锚定 tx。
EXTRA_ALLOC_PUBS="${EXTRA_ALLOC_PUBS:-}"

if [[ "${N}" == "stop" ]]; then
  for pid_file in "${DEPLOY_DIR}"/node_*.pid; do
    [ -f "$pid_file" ] || continue
    pid=$(cat "$pid_file")
    kill "$pid" 2>/dev/null || true
    echo "stopped node pid=$pid ($pid_file)"
  done
  exit 0
fi

case "$N" in
  ''|*[!0-9]*) echo "N 必须是数字（默认 4）" >&2; exit 1 ;;
esac
if [[ "$N" -lt 1 ]]; then echo "N ≥ 1" >&2; exit 1; fi

[ -x "$ZCHAIN_BIN" ] || { echo "zchain 二进制不存在：$ZCHAIN_BIN（先 cargo build -p zchain）" >&2; exit 1; }

mkdir -p "$DEPLOY_DIR"
cd "$DEPLOY_DIR"

# 0) 停旧实例 + 清旧数据（密钥/genesis 重新生成，旧 RocksDB 必然不兼容）
for pid_file in node_*.pid; do
  [ -f "$pid_file" ] || continue
  pid=$(cat "$pid_file") && kill "$pid" 2>/dev/null || true
  rm -f "$pid_file"
done
sleep 1
for d in node_*/; do
  [ -d "$d" ] && rm -rf "$d"
done

echo "=== zchain 4 节点部署：N=$N dir=$DEPLOY_DIR ==="

# ===== 1. 生成 N 个 validator 密钥 + VRF 密钥 =====
SECRETS=(); PUBKEYS=()
for ((i=0; i<N; i++)); do
  KEYJSON=$("$ZCHAIN_BIN" keygen --scheme secp256k1)
  SECRET=$(echo "$KEYJSON" | grep '"secret_key_hex"' | head -1 | sed -E 's/.*"secret_key_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
  PUBKEY=$(echo "$KEYJSON" | grep '"raw_hex"' | head -1 | sed -E 's/.*"raw_hex"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
  SECRETS+=("$SECRET"); PUBKEYS+=("$PUBKEY")
done

# ===== 2. genesis validator set（stake 必须 0：链拒绝无抵押 genesis 质押）=====
GENESIS_VALIDATORS="$DEPLOY_DIR/genesis_validators.json"
echo "[" > "$GENESIS_VALIDATORS"
for ((i=0; i<N; i++)); do
  COMMA=""; [ "${i}" -lt $((N-1)) ] && COMMA=","
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"vrf_pubkey_hex\": \"02$(printf '%064d' "${i}")\", \"stake\": 0}${COMMA}" >> "$GENESIS_VALIDATORS"
done
echo "]" >> "$GENESIS_VALIDATORS"

# ===== 3. genesis 余额分配（每 validator 1e11 基础单位 + 额外账户）=====
GENESIS_ALLOC="$DEPLOY_DIR/genesis_alloc.json"
echo "[" > "$GENESIS_ALLOC"
for ((i=0; i<N; i++)); do
  echo "  {\"pubkey_hex\": \"${PUBKEYS[i]}\", \"balance\": 100000000000}," >> "$GENESIS_ALLOC"
done
EXTRA_COUNT=0
if [[ -n "$EXTRA_ALLOC_PUBS" ]]; then
  IFS=',' read -ra EXTRA_PUBS <<< "$EXTRA_ALLOC_PUBS"
  EXTRA_COUNT=${#EXTRA_PUBS[@]}
  for ((i=0; i<EXTRA_COUNT; i++)); do
    COMMA=""; [ "$((i+1))" -lt "$EXTRA_COUNT" ] && COMMA=","
    echo "  {\"pubkey_hex\": \"$(echo "${EXTRA_PUBS[i]}" | tr -d '[:space:]')\", \"balance\": 100000000000}${COMMA}" >> "$GENESIS_ALLOC"
  done
fi
# 收尾：extra 为空时 validator 段末尾多一个逗号——用临时文件重写（BSD/GNU
# sed 通用，避免 -i 参数差异）。
if [[ "$EXTRA_COUNT" -eq 0 ]]; then
  TMP_ALLOC="$DEPLOY_DIR/genesis_alloc.json.tmp"
  sed 's/100000000000},$/100000000000}/' "$GENESIS_ALLOC" > "$TMP_ALLOC" \
    && mv "$TMP_ALLOC" "$GENESIS_ALLOC"
fi
echo "]" >> "$GENESIS_ALLOC"
python3 -c "import json,sys; json.load(open('$GENESIS_ALLOC'))" \
  || { echo "genesis_alloc.json 非法 JSON" >&2; exit 1; }

# ===== 4. 密钥文件 =====
for ((i=0; i<N; i++)); do
  printf '%s' "${SECRETS[i]}" > "validator_${i}.key"
  printf '%s' "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "validator_${i}.vrf"
  chmod 600 "validator_${i}.key"
done

# ===== 5. 启动 N 个 validator（常驻）=====
for ((i=0; i<N; i++)); do
  RPC_PORT=$((RPC_BASE + i))
  P2P_PORT=$((P2P_BASE + i))
  PEERS=""
  for ((j=0; j<N; j++)); do
    [ "${j}" -ne "${i}" ] && PEERS="${PEERS} --peer 127.0.0.1:$((P2P_BASE + j))"
  done
  "$ZCHAIN_BIN" node \
    --role validator \
    --data-dir "$DEPLOY_DIR/node_${i}" \
    --rpc-listen "${RPC_HOST}:${RPC_PORT}" \
    --p2p-listen "127.0.0.1:${P2P_PORT}" \
    --validator-key-file "$DEPLOY_DIR/validator_${i}.key" \
    --vrf-key-file "$DEPLOY_DIR/validator_${i}.vrf" \
    --genesis-validators "$GENESIS_VALIDATORS" \
    --genesis-alloc "$GENESIS_ALLOC" \
    --block-interval-ms "$BLOCK_INTERVAL_MS" \
    $PEERS \
    > "node_${i}.log" 2>&1 &
  echo $! > "node_${i}.pid"
  echo "  node ${i}: RPC=${RPC_HOST}:${RPC_PORT} P2P=127.0.0.1:${P2P_PORT} pid=$!"
done

# ===== 6. 健康检查：每个节点日志出现 commit_round=（真实出块）=====
echo -n "等待全部节点出块"
TIMEOUT=90
ok=0
for ((t=0; t<TIMEOUT*2; t++)); do
  sleep 0.5
  ok=1
  for ((i=0; i<N; i++)); do
    grep -q "commit_round=" "node_${i}.log" 2>/dev/null || { ok=0; break; }
  done
  [ "$ok" -eq 1 ] && break
  echo -n "."
done
echo
if [ "$ok" -ne 1 ]; then
  echo "部署失败：节点未在 ${TIMEOUT}s 内出块（查看 $DEPLOY_DIR/node_*.log）" >&2
  exit 1
fi
echo "✅ 全部 $N 个节点 DAG 共识出块正常"

ls "$RPC_BASE" >/dev/null 2>&1 || true
seq "$RPC_BASE" "$((RPC_BASE + N - 1))" > rpc_ports.txt
echo "RPC 端口清单：$(cat rpc_ports.txt | tr '\n' ' ')"
echo "部署目录：$DEPLOY_DIR"
