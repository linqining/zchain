#!/usr/bin/env bash
# explorer_gateway 冒烟脚本（E1 只读实时数据面 + E2 领域查询验收）。
#
# 流程：cargo build --release（仅 explorer_gateway bin）→ `--gen-fixture`
# 生成 demo WAL + proven log → 后台起网关（127.0.0.1 随机可用端口探测）→
# curl 各端点断言关键字段（grep；serde_json 输出为字母序键）→ 打印
# PASS/FAIL → 清理进程与临时目录。
#
# 用法：bash scripts/explorer_gateway_smoke.sh
# 退出码：0 = 全部 PASS；1 = 存在 FAIL。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/explorer_gateway"
WORK="$(mktemp -d /tmp/explorer-gateway-smoke.XXXXXX)"
PORT="${SMOKE_PORT:-18900}"
BASE="http://127.0.0.1:$PORT"
GATEWAY_PID=""

PASS_COUNT=0
FAIL_COUNT=0
INDEX_GW_PID=""
INDEX_PORT="${SMOKE_INDEX_PORT:-$(( ${SMOKE_PORT:-18900} + 1 ))}"
INDEX_BASE="http://127.0.0.1:$INDEX_PORT"

cleanup() {
  for pid in "$GATEWAY_PID" "$INDEX_GW_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    fi
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

report() { # report <name> <0|1>
  if [ "$2" = "0" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "PASS: $1"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "FAIL: $1"
  fi
}

echo "== explorer_gateway smoke =="
echo "workdir: $WORK"

# ===== 1. 构建（release + pinned nightly；explorer_gateway + appchain_watcher）=====
echo "-- cargo build --release -p poker-appchain --bin explorer_gateway --bin appchain_watcher"
if cargo build --release -p poker-appchain --bin explorer_gateway --bin appchain_watcher >/dev/null 2>&1 && [ -x "$BIN" ]; then
  report "build explorer_gateway + appchain_watcher (release)" 0
else
  report "build explorer_gateway + appchain_watcher (release)" 1
  echo "build failed; aborting"
  exit 1
fi

# ===== 2. 生成 fixture（demo WAL + proven log + proof registry + aggregate log）=====
GEN_JSON="$("$BIN" --gen-fixture "$WORK/fixture" 2>"$WORK/gen.err")"
if [ $? -ne 0 ]; then
  report "gen-fixture" 1
  cat "$WORK/gen.err"
  exit 1
fi
report "gen-fixture writes demo WAL + proven log + proof registry + aggregate log" 0
WAL="$WORK/fixture/appchain.wal"
PROVEN="$WORK/fixture/proven.log"
REGISTRY="$WORK/fixture/proof_registry.jsonl"
AGGREGATE="$WORK/fixture/aggregate.log"
PUB="$(echo "$GEN_JSON" | grep -o '"sequencer_public":"[0-9a-f]*"' | cut -d'"' -f4)"
if [ "${#PUB}" = "64" ] && [ -s "$WAL" ] && [ -s "$PROVEN" ] && [ -s "$REGISTRY" ] && [ -s "$AGGREGATE" ]; then
  report "fixture artifacts present (sequencer_public=64hex, sidecars non-empty)" 0
else
  report "fixture artifacts present (sequencer_public=64hex, sidecars non-empty)" 1
  exit 1
fi

# ===== 3. 启动网关（replay + proven log 恢复 + proof/aggregate 装载 + 快照）=====
"$BIN" \
  --appchain-wal "$WAL" \
  --sequencer-public "$PUB" \
  --proven-log "$PROVEN" \
  --proof-registry "$REGISTRY" \
  --aggregate-log "$AGGREGATE" \
  --listen "127.0.0.1:$PORT" \
  --snapshot-out "$WORK/snapshot" \
  >"$WORK/gateway.log" 2>"$WORK/gateway.err" &
GATEWAY_PID=$!

# 等待监听（最多 5s）
UP=1
for _ in $(seq 1 50); do
  if curl -sf -o /dev/null "$BASE/api/v1/status"; then UP=0; break; fi
  kill -0 "$GATEWAY_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$UP" = "0" ] && kill -0 "$GATEWAY_PID" 2>/dev/null; then
  report "gateway up on $BASE (mode=replay)" 0
else
  report "gateway up on $BASE (mode=replay)" 1
  cat "$WORK/gateway.err"
  exit 1
fi
if grep -q "非生产配置" "$WORK/gateway.err"; then
  report "no non-production warning on loopback bind" 1
else
  report "no non-production warning on loopback bind" 0
fi

# ===== 4. /api/v1/status =====
STATUS="$(curl -s "$BASE/api/v1/status")"
echo "-- /api/v1/status: $STATUS"
echo "$STATUS" | grep -q '"env":"devnet"'; report "status.env == devnet" $?
echo "$STATUS" | grep -q '"watermark_source":"proven_log"'; report "status.watermark_source == proven_log" $?
echo "$STATUS" | grep -q '"watermark":6'; report "status.watermark == 6 (from proven log)" $?
echo "$STATUS" | grep -q '"frame_count":9'; report "status.frame_count == 9" $?
echo "$STATUS" | grep -q '"settlement_count":2'; report "status.settlement_count == 2" $?
echo "$STATUS" | grep -q '"sequencer_public":"'"$PUB"'"'; report "status.sequencer_public matches fixture" $?
echo "$STATUS" | grep -qE '"latest_batch_root":"[0-9a-f]{64}"'; report "status.latest_batch_root 64hex" $?
echo "$STATUS" | grep -q '"batch_covered_through":6'; report "status.batch_covered_through == 6" $?

# 响应头
HEADERS="$(curl -s -D - -o /dev/null "$BASE/api/v1/status")"
echo "$HEADERS" | grep -qi '^x-zchain-gateway: replay-v1'; report "header X-Zchain-Gateway: replay-v1" $?
echo "$HEADERS" | grep -qi '^cache-control: max-age=5'; report "status Cache-Control: max-age=5" $?
if echo "$HEADERS" | grep -qi '^access-control-allow-origin'; then
  report "no CORS header without --public (fail-closed)" 1
else
  report "no CORS header without --public (fail-closed)" 0
fi

# ===== 5. /api/v1/frames =====
FRAMES="$(curl -s "$BASE/api/v1/frames?offset=0&limit=2")"
echo "$FRAMES" | grep -q '"total":9'; report "frames.total == 9" $?
echo "$FRAMES" | grep -q '"op":"OpenTable"'; report "frames summary has op type name" $?
echo "$FRAMES" | grep -q '"op_detail"'; report "frames do not inline op detail" $([ $? -ne 0 ] && echo 0 || echo 1)
CAPPED="$(curl -s "$BASE/api/v1/frames?limit=1000")"
echo "$CAPPED" | grep -q '"limit":200'; report "frames limit capped at 200" $?
curl -s -o /dev/null -w '' "$BASE/api/v1/frames?offset=abc"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/frames?offset=abc")"
report "frames?offset=abc -> 400" $([ "$CODE" = "400" ] && echo 0 || echo 1)

# ===== 6. /api/v1/settlements =====
SETTLE="$(curl -s "$BASE/api/v1/settlements")"
echo "$SETTLE" | grep -q '"total":2'; report "settlements.total == 2" $?
echo "$SETTLE" | grep -q '"level":"proven"'; report "settlements level proven present" $?
echo "$SETTLE" | grep -q '"level":"soft_accepted"'; report "settlements level soft_accepted present" $?
echo "$SETTLE" | grep -q '"rake_total":0'; report "settlements rake_total == 0 (zero-fee demo)" $?
echo "$SETTLE" | grep -qE '"owner_short":"[0-9a-f]{8}…[0-9a-f]{8}"'; report "settlements payout owner abbreviated" $?
FILTERED="$(curl -s "$BASE/api/v1/settlements?table_id=99")"
echo "$FILTERED" | grep -q '"total":0'; report "settlements?table_id=99 filters all" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/settlements?table_id=zz")"
report "settlements?table_id=zz -> 400" $([ "$CODE" = "400" ] && echo 0 || echo 1)

# ===== 7. /api/v1/settlement/{hand_binding} =====
BINDING="$(echo "$SETTLE" | grep -o '"hand_binding":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
DETAIL="$(curl -s "$BASE/api/v1/settlement/$BINDING")"
echo "$DETAIL" | grep -q '"hand_binding":"'"$BINDING"'"'; report "settlement detail hit by hand_binding" $?
echo "$DETAIL" | grep -q '"policy_commitment"'; report "settlement detail has policy_commitment" $?
echo "$DETAIL" | grep -q '"nullifier"'; report "settlement detail has input nullifiers" $?
echo "$DETAIL" | grep -q '"gross_pot":2000'; report "settlement detail plan.gross_pot == 2000" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/settlement/$(printf 'd%.0s' $(seq 1 64))")"
report "settlement detail miss -> 404" $([ "$CODE" = "404" ] && echo 0 || echo 1)
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/settlement/deadbeef")"
report "settlement detail bad hex -> 400" $([ "$CODE" = "400" ] && echo 0 || echo 1)

# ===== 8. /api/v1/batch_roots 与 /api/v1/metrics =====
ROOTS="$(curl -s "$BASE/api/v1/batch_roots")"
echo "$ROOTS" | grep -q '"op_index":6'; report "batch_roots lists op_index 6" $?
METRICS="$(curl -s "$BASE/api/v1/metrics")"
echo "$METRICS" | grep -q '"mode":"replay"'; report "metrics mode == replay" $?

# ===== 8b. E2 归档闭环：/api/v1/settlement → payout_root → /api/v1/proof =====
echo "$DETAIL" | grep -q '"payout_root":"[0-9a-f]\{64\}"'; report "settlement detail has payout_root (64hex)" $?
ZERO_ROOT="$(printf '0%.0s' $(seq 1 64))"
if echo "$DETAIL" | grep -q "\"payout_root\":\"$ZERO_ROOT\""; then
  report "payout_root non-zero" 1
else
  report "payout_root non-zero" 0
fi
echo "$DETAIL" | grep -q '"engine":"host-validate-v2"'; report "settlement proof link engine hit (registry)" $?
echo "$DETAIL" | grep -q '"href":"/api/v1/proof/'"$BINDING"'"'; report "settlement proof link href" $?
PROOFS="$(curl -s "$BASE/api/v1/proofs")"
echo "$PROOFS" | grep -q '"total":1'; report "proofs total == 1 (real pipeline archive)" $?
echo "$PROOFS" | grep -q '"engine":"host-validate-v2"'; report "proofs list carries engine metadata" $?
echo "$PROOFS" | grep -q '"payload_bytes":64'; report "proofs list gives payload byte size (no payload inline)" $?
PROOF_DL="$(curl -s -D "$WORK/proof.headers" "$BASE/api/v1/proof/$BINDING")"
echo "$PROOF_DL" | grep -q '"binding_hex":"'"$BINDING"'"'; report "proof download binding matches settlement" $?
echo "$PROOF_DL" | grep -q '"op_index":6'; report "proof download op_index == 6" $?
echo "$PROOF_DL" | grep -qE '"payload_b64":"[A-Za-z0-9+/]+={0,2}"'; report "proof download has payload_b64" $?
grep -qi '^x-zchain-engine: host-validate-v2' "$WORK/proof.headers"; report "proof download header X-Zchain-Engine" $?
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/proof/$(printf 'e%.0s' $(seq 1 64))")"
report "proof download miss -> 404" $([ "$CODE" = "404" ] && echo 0 || echo 1)
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/proof/deadbeef")"
report "proof download bad hex -> 400" $([ "$CODE" = "400" ] && echo 0 || echo 1)

# ===== 8c. M4 outer aggregate：/api/v1/aggregates 与 status 增字段 =====
AGGS="$(curl -s "$BASE/api/v1/aggregates")"
echo "$AGGS" | grep -q '"index":0'; report "aggregates lists index 0" $?
echo "$AGGS" | grep -q '"through_op":6'; report "aggregates through_op == 6" $?
echo "$AGGS" | grep -q '"batch_count":1'; report "aggregates batch_count == 1" $?
echo "$AGGS" | grep -qE '"root":"[0-9a-f]{64}"'; report "aggregates root 64hex" $?
echo "$STATUS" | grep -qE '"latest_aggregate_root":"[0-9a-f]{64}"'; report "status.latest_aggregate_root 64hex" $?
echo "$STATUS" | grep -q '"latest_aggregate_through_op":6'; report "status.latest_aggregate_through_op == 6" $?

# ===== 8d. watcher aggregate 校验（正例 exit 0；负例换根 exit 1）=====
WATCHER="$ROOT/target/release/appchain_watcher"
if [ -x "$WATCHER" ]; then
  if "$WATCHER" --appchain-wal "$WAL" --sequencer-public "$PUB" \
      --proven-log "$PROVEN" --aggregate-log "$AGGREGATE" >"$WORK/watcher.ok" 2>&1; then
    report "watcher aggregate positive case exits 0" 0
  else
    report "watcher aggregate positive case exits 0" 1
  fi
  # 负例：换掉 aggregate log 的 root → aggregate_mismatch → exit 1
  sed 's/"root":"[0-9a-f]*"/"root":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"/' \
    "$AGGREGATE" > "$WORK/aggregate.bad"
  if "$WATCHER" --appchain-wal "$WAL" --sequencer-public "$PUB" \
      --proven-log "$PROVEN" --aggregate-log "$WORK/aggregate.bad" >"$WORK/watcher.bad" 2>&1; then
    report "watcher aggregate mismatch exits 1" 1
  else
    RC=$?
    if [ "$RC" = "1" ] && grep -q "aggregate_mismatch" "$WORK/watcher.bad"; then
      report "watcher aggregate mismatch exits 1" 0
    else
      report "watcher aggregate mismatch exits 1" 1
    fi
  fi
else
  report "watcher binary present (cargo build skipped)" 1
fi

# ===== 8e. E2 archive 索引：--write-index 构建 + --index-file 直连模式 =====
# 构建（回放时同步构建并落盘；fail-closed——坏 WAL 构建即失败）
INDEX_FILE="$WORK/fixture/archive_index.jsonl"
if "$BIN" --write-index "$INDEX_FILE" --appchain-wal "$WAL" --sequencer-public "$PUB" \
    --proof-registry "$REGISTRY" >"$WORK/index.out" 2>"$WORK/index.err"; then
  report "write-index builds archive index (exit 0)" 0
else
  report "write-index builds archive index (exit 0)" 1
  cat "$WORK/index.err"
fi
grep -q "^INDEX_WRITTEN=" "$WORK/index.out"
report "write-index prints INDEX_WRITTEN" $?
grep -q "INDEX_FRAMES=9 " "$WORK/index.out"; report "index header frame_count == 9" $?
grep -q "INDEX_SETTLEMENTS=2 " "$WORK/index.out"; report "index header settlement_count == 2" $?
grep -q "INDEX_PROOFS=1" "$WORK/index.out"; report "index proof lines == 1 (registry attached)" $?
grep -qE "^INDEX_DIGEST=[0-9a-f]{64}$" "$WORK/index.out"; report "index digest 64hex" $?

# index 模式网关：跳过全量 replay 直接服务查询
"$BIN" \
  --appchain-wal "$WAL" \
  --sequencer-public "$PUB" \
  --index-file "$INDEX_FILE" \
  --proven-log "$PROVEN" \
  --proof-registry "$REGISTRY" \
  --aggregate-log "$AGGREGATE" \
  --listen "127.0.0.1:$INDEX_PORT" \
  >"$WORK/index_gateway.log" 2>"$WORK/index_gateway.err" &
INDEX_GW_PID=$!
UP2=1
for _ in $(seq 1 50); do
  if curl -sf -o /dev/null "$INDEX_BASE/api/v1/status"; then UP2=0; break; fi
  kill -0 "$INDEX_GW_PID" 2>/dev/null || break
  sleep 0.1
done
if [ "$UP2" = "0" ] && kill -0 "$INDEX_GW_PID" 2>/dev/null; then
  report "index-mode gateway up on $INDEX_BASE" 0
else
  report "index-mode gateway up on $INDEX_BASE" 1
  cat "$WORK/index_gateway.err"
fi
grep -q "mode=index" "$WORK/index_gateway.log"; report "index gateway banner mode=index" $?
grep -q "index 完成" "$WORK/index_gateway.err"; report "index gateway loaded without replay" $?

ISTATUS="$(curl -s "$INDEX_BASE/api/v1/status")"
echo "$ISTATUS" | grep -q '"data_source":"index"'; report "index status.data_source == index" $?
echo "$ISTATUS" | grep -q '"frame_count":9'; report "index status.frame_count == 9 (matches replay)" $?
echo "$ISTATUS" | grep -q '"settlement_count":2'; report "index status.settlement_count == 2" $?
echo "$ISTATUS" | grep -q '"watermark":6'; report "index status.watermark == 6 (proven log)" $?
# 链头一致：index 头部行的 chain_head == replay 链头
RINDEX="$(echo "$STATUS" | grep -o '"chain_head":{[^}]*}' | grep -o '"index":[0-9]*' | cut -d: -f2)"
IINDEX="$(echo "$ISTATUS" | grep -o '"chain_head":{[^}]*}' | grep -o '"index":[0-9]*' | cut -d: -f2)"
if [ -n "$RINDEX" ] && [ "$RINDEX" = "$IINDEX" ]; then
  report "index chain_head index == replay ($RINDEX)" 0
else
  report "index chain_head index == replay (replay=$RINDEX index=$IINDEX)" 1
fi
RHASH="$(echo "$STATUS" | grep -o '"chain_head":{[^}]*}' | grep -o '"hash":"[0-9a-f]*"' | cut -d'"' -f4)"
IHASH="$(echo "$ISTATUS" | grep -o '"chain_head":{[^}]*}' | grep -o '"hash":"[0-9a-f]*"' | cut -d'"' -f4)"
if [ -n "$RHASH" ] && [ "$RHASH" = "$IHASH" ]; then
  report "index chain_head hash == replay" 0
else
  report "index chain_head hash == replay" 1
fi

IFRAMES="$(curl -s "$INDEX_BASE/api/v1/frames?offset=0&limit=200")"
RFRAMES="$(curl -s "$BASE/api/v1/frames?offset=0&limit=200")"
report "index frames payload == replay frames payload" $([ "$IFRAMES" = "$RFRAMES" ] && echo 0 || echo 1)
ISETTLE="$(curl -s "$INDEX_BASE/api/v1/settlements")"
RSETTLE_FULL="$(curl -s "$BASE/api/v1/settlements")"
report "index settlements total == 2" $(echo "$ISETTLE" | grep -q '"total":2' && echo 0 || echo 1)
report "index settlements payload == replay settlements payload" $([ "$ISETTLE" = "$RSETTLE_FULL" ] && echo 0 || echo 1)
IBINDING="$(echo "$ISETTLE" | grep -o '"hand_binding":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
IDETAIL="$(curl -s "$INDEX_BASE/api/v1/settlement/$IBINDING")"
RDETAIL_BINDING="$(echo "$DETAIL" | grep -o '"hand_binding":"[0-9a-f]*"' | head -1 | cut -d'"' -f4)"
report "index detail binding == replay detail binding" $([ "$IBINDING" = "$RDETAIL_BINDING" ] && echo 0 || echo 1)
echo "$IDETAIL" | grep -q '"payout_root"'; report "index detail has payout_root (targeted wal read)" $?
echo "$IDETAIL" | grep -q '"engine":"host-validate-v2"'; report "index detail proof engine via registry" $?

# 负例：篡改索引 digest → 启动拒绝（fail-closed）
sed 's/"digest":"[0-9a-f]\{4\}/"digest":"eeee/' "$INDEX_FILE" > "$WORK/index.tampered"
"$BIN" --appchain-wal "$WAL" --sequencer-public "$PUB" \
  --index-file "$WORK/index.tampered" --listen "127.0.0.1:$((INDEX_PORT + 1))" \
  >"$WORK/tampered.log" 2>"$WORK/tampered.err"
report "tampered index digest rejected at startup (exit non-zero)" $([ $? -ne 0 ] && echo 0 || echo 1)
grep -q "digest mismatch" "$WORK/tampered.err"; report "tampered index error mentions digest" $?

# 关闭 index 模式网关（避免占用端口与限流干扰）
kill "$INDEX_GW_PID" 2>/dev/null
wait "$INDEX_GW_PID" 2>/dev/null
INDEX_GW_PID=""

# ===== 9. L1 代理未配置 → 404；方法/路径纪律 =====
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/l1/metrics")"
report "l1 proxy unconfigured -> 404" $([ "$CODE" = "404" ] && echo 0 || echo 1)
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nope")"
report "unknown path -> 404" $([ "$CODE" = "404" ] && echo 0 || echo 1)
CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/v1/status")"
report "POST -> 405 (read-only)" $([ "$CODE" = "405" ] && echo 0 || echo 1)

# ===== 10. 静态快照 =====
if [ -s "$WORK/snapshot/explorer.json" ] && grep -q '"mode": "replay"' "$WORK/snapshot/explorer.json"; then
  report "snapshot explorer.json written (mode=replay)" 0
else
  report "snapshot explorer.json written (mode=replay)" 1
fi

# ===== 11. 限流（默认 10 req/s / 突发 20；放在最后以免干扰前述断言）=====
COUNT_429=0
for _ in $(seq 1 40); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/status")" || true
  [ "$CODE" = "429" ] && COUNT_429=$((COUNT_429 + 1))
done
report "rate limit trips 429 under burst ($COUNT_429/40 rejected)" $([ "$COUNT_429" -ge 1 ] && echo 0 || echo 1)

# ===== 汇总 =====
echo "== smoke summary: $PASS_COUNT PASS / $FAIL_COUNT FAIL =="
[ "$FAIL_COUNT" = "0" ]
