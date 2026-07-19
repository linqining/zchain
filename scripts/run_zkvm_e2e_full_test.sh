#!/bin/bash
# =============================================================================
# Phase 5.6 — zkvm 端到端完整测试脚本
#
# 完整覆盖用户四大目标：
#   1) zkvm 作为常驻服务运行（zchain zkvm-server 后台 daemon）
#   2) poker_l1/src/vm/contracts/texas_poker 整个合约编译为 ELF 在 zkvm 中实际运行
#      （build_texas_poker_full_hand_elf，~220 条 RV32I 指令）
#   3) 展示完整一手牌流程（sigma 协议 + RV32I eval + LCCCS 分阶段提交 + 最终 proof）
#   4) 使用并行证明配置，测试实际最低证明延迟（--parallel-sweep + --sweep-runs）
#
# 用法：
#   bash scripts/run_zkvm_e2e_full_test.sh                # 完整流程（默认）
#   SWEEP_RUNS=5 bash scripts/run_zkvm_e2e_full_test.sh   # 每配置跑 5 次（更稳定中位数）
#   SKIP_NODE=1 bash scripts/run_zkvm_e2e_full_test.sh    # 跳过 validator 节点启动
#   SKIP_SWEEP=1 bash scripts/run_zkvm_e2e_full_test.sh   # 跳过并行扫描（仅基础流程）
#
# 输出：
#   /tmp/zkvm_e2e_full_<timestamp>.log         demo 完整日志 + JSON 摘要
#   /tmp/zkvm_e2e_server_<timestamp>.log       zkvm-server 日志
#   /tmp/zkvm_e2e_node_<timestamp>.log         validator 节点日志
#   stdout                                      性能摘要
# =============================================================================

set -euo pipefail

# ---------- 配置 ----------
ZCHAIN_BIN="${ZCHAIN_BIN:-./target/release/zchain}"
ZKVM_SERVER_LISTEN="${ZKVM_SERVER_LISTEN:-127.0.0.1:9527}"
NODE_RPC_LISTEN="${NODE_RPC_LISTEN:-127.0.0.1:8545}"
SWEEP_RUNS="${SWEEP_RUNS:-3}"            # --sweep-runs 每配置重复 prove 次数
SWEEP_ELF="${SWEEP_ELF:-eval}"            # --sweep-elf {eval|full}：eval=快速（~1s/prove），full=完整合约（~4min/prove）
PARALLEL_THREADS="${PARALLEL_THREADS:-8}" # zkvm-server 后台线程数
SKIP_NODE="${SKIP_NODE:-0}"
SKIP_SWEEP="${SKIP_SWEEP:-0}"
RELEASE_PROFILE="${RELEASE_PROFILE:-release}" # release / debug

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEMO_LOG="/tmp/zkvm_e2e_full_${TIMESTAMP}.log"
SERVER_LOG="/tmp/zkvm_e2e_server_${TIMESTAMP}.log"
NODE_LOG="/tmp/zkvm_e2e_node_${TIMESTAMP}.log"

# ---------- 颜色输出 ----------
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

# ---------- trap cleanup ----------
ZKVM_PID=""
NODE_PID=""
cleanup() {
    log_info "清理后台进程..."
    if [[ -n "$ZKVM_PID" ]] && kill -0 "$ZKVM_PID" 2>/dev/null; then
        kill "$ZKVM_PID" 2>/dev/null || true
        wait "$ZKVM_PID" 2>/dev/null || true
        log_info "zkvm-server (pid=$ZKVM_PID) 已停止"
    fi
    if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        log_info "validator node (pid=$NODE_PID) 已停止"
    fi
}
trap cleanup EXIT INT TERM

# ---------- Step 0: 编译 ----------
log_step "Step 0: 编译 zchain ($RELEASE_PROFILE profile)"
if [[ "$RELEASE_PROFILE" == "release" ]]; then
    cargo build --release -p zchain 2>&1 | tail -5
else
    cargo build -p zchain 2>&1 | tail -5
fi

if [[ ! -x "$ZCHAIN_BIN" ]]; then
    log_error "zchain 二进制不存在：$ZCHAIN_BIN"
    exit 1
fi
log_info "✓ 编译完成：$ZCHAIN_BIN"

# ---------- Step 1: 启动 zkvm-server（常驻服务） ----------
log_step "Step 1: 启动 zkvm-server（常驻服务，parallel-threads=${PARALLEL_THREADS}）"
log_info "  listen: $ZKVM_SERVER_LISTEN"
log_info "  log:    $SERVER_LOG"

RUST_LOG=info "$ZCHAIN_BIN" zkvm-server \
    --listen "$ZKVM_SERVER_LISTEN" \
    --batch-size 256 \
    --parallel-threads "$PARALLEL_THREADS" \
    > "$SERVER_LOG" 2>&1 &
ZKVM_PID=$!
log_info "  pid:    $ZKVM_PID"

# ---------- Step 2: 等待 zkvm-server 就绪 ----------
log_step "Step 2: 等待 zkvm-server 就绪（/health 检查）"
SERVER_READY=0
for i in $(seq 1 60); do
    if curl -sf "http://$ZKVM_SERVER_LISTEN/health" > /dev/null 2>&1; then
        SERVER_READY=1
        log_info "✓ zkvm-server 就绪（等待 ${i} × 0.5s）"
        break
    fi
    sleep 0.5
done
if [[ "$SERVER_READY" -ne 1 ]]; then
    log_error "zkvm-server 60s 内未就绪，最近 30 行日志："
    tail -30 "$SERVER_LOG" || true
    exit 1
fi

# ---------- Step 3: 服务端 health/stats 自检 ----------
log_step "Step 3: 服务端 health/stats 自检"
HEALTH_JSON=$(curl -sf "http://$ZKVM_SERVER_LISTEN/health")
log_info "  /health: $HEALTH_JSON"
STATS_JSON=$(curl -sf "http://$ZKVM_SERVER_LISTEN/stats")
log_info "  /stats:  $STATS_JSON"

# ---------- Step 4: 启动 validator 节点（可选） ----------
DEMO_FLAGS="--log-file $DEMO_LOG"
if [[ "$SKIP_NODE" -eq 1 ]]; then
    log_warn "Step 4: 跳过 validator 节点启动（SKIP_NODE=1）— demo 将以 --local-only 模式运行"
    DEMO_FLAGS="$DEMO_FLAGS --local-only"
else
    log_step "Step 4: 启动 validator 节点"
    log_info "  rpc-listen: $NODE_RPC_LISTEN"
    log_info "  log:        $NODE_LOG"

    RUST_LOG=info "$ZCHAIN_BIN" node \
        --role validator \
        --data-dir "/tmp/zkvm-e2e-data-${TIMESTAMP}" \
        --rpc-listen "$NODE_RPC_LISTEN" \
        > "$NODE_LOG" 2>&1 &
    NODE_PID=$!
    log_info "  pid:        $NODE_PID"

    # 等待节点就绪
    log_step "Step 4b: 等待 validator 节点就绪"
    NODE_READY=0
    for i in $(seq 1 60); do
        if curl -sf "http://$NODE_RPC_LISTEN/health" > /dev/null 2>&1 \
           || curl -sf -X POST "http://$NODE_RPC_LISTEN/" \
                -H "Content-Type: application/json" \
                -d '{"jsonrpc":"2.0","method":"chain_id","params":[],"id":1}' > /dev/null 2>&1; then
            NODE_READY=1
            log_info "✓ validator 节点就绪（等待 ${i} × 0.5s）"
            break
        fi
        sleep 0.5
    done
    if [[ "$NODE_READY" -ne 1 ]]; then
        log_warn "validator 节点 30s 内未就绪，降级为 --local-only 模式"
        log_warn "最近 30 行节点日志："
        tail -30 "$NODE_LOG" 2>/dev/null || true
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        NODE_PID=""
        DEMO_FLAGS="$DEMO_FLAGS --local-only"
    else
        DEMO_FLAGS="$DEMO_FLAGS --rpc $NODE_RPC_LISTEN"
    fi
fi

# ---------- Step 5: 运行完整 E2E 测试（含 sigma + RV32I + LCCCS partial demo） ----------
log_step "Step 5: 运行完整 E2E 测试（poker-zkvm-demo）"
log_info "  log: $DEMO_LOG"
log_info "  flags: $DEMO_FLAGS --partial-prove-demo --parallel-threads $PARALLEL_THREADS"

RUST_LOG=info "$ZCHAIN_BIN" poker-zkvm-demo \
    $DEMO_FLAGS \
    --partial-prove-demo \
    --parallel-threads "$PARALLEL_THREADS"

log_info "✓ 完整 E2E 测试完成"

# ---------- Step 6: 并行配置扫描（实际最低证明延迟） ----------
if [[ "$SKIP_SWEEP" -eq 1 ]]; then
    log_warn "Step 6: 跳过并行配置扫描（SKIP_SWEEP=1）"
else
    log_step "Step 6: 并行证明配置扫描（--parallel-sweep --sweep-runs ${SWEEP_RUNS} --sweep-elf ${SWEEP_ELF}）"
    log_info "  扫描配置: sequential_baseline + threads 1/2/4/8"
    log_info "  每配置重复: $SWEEP_RUNS 次（取中位数）"
    log_info "  ELF: $SWEEP_ELF"
    log_info "  总 prove 次数: $((5 * SWEEP_RUNS + 5)) 次（5 配置 × $SWEEP_RUNS + 5 等价性校验）"

    SWEEP_LOG="/tmp/zkvm_e2e_sweep_${TIMESTAMP}.log"
    RUST_LOG=info "$ZCHAIN_BIN" poker-zkvm-demo \
        --local-only \
        --parallel-sweep \
        --sweep-runs "$SWEEP_RUNS" \
        --sweep-elf "$SWEEP_ELF" \
        --log-file "$SWEEP_LOG"

    log_info "✓ 并行扫描完成"
    log_info "  sweep log: $SWEEP_LOG"
fi

# ---------- Step 7: 输出性能摘要 ----------
log_step "Step 7: 性能摘要"

echo ""
echo "================================================================"
echo "                    zkvm E2E 完整测试性能摘要"
echo "================================================================"
echo "时间戳:        $TIMESTAMP"
echo "demo log:      $DEMO_LOG"
echo "server log:    $SERVER_LOG"
if [[ -n "$NODE_PID" ]]; then
    echo "node log:      $NODE_LOG"
fi
echo ""
echo "----- demo 日志关键测时 -----"
grep -E "(\[rv32i\]|\[partial\]|\[sweep\]|总耗时|best_prove|speedup)" "$DEMO_LOG" 2>/dev/null || true

if [[ "$SKIP_SWEEP" -ne 1 ]]; then
    SWEEP_LOG="/tmp/zkvm_e2e_sweep_${TIMESTAMP}.log"
    echo ""
    echo "----- 并行扫描结果 -----"
    grep -E "(\[sweep\].*BEST|\[sweep\].*最佳配置|\[sweep\].*加速比|\[sweep\].*sequential_baseline|\[sweep\].*threads_)" "$SWEEP_LOG" 2>/dev/null || true
fi

echo ""
echo "----- 服务端统计 -----"
curl -sf "http://$ZKVM_SERVER_LISTEN/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null \
    || curl -sf "http://$ZKVM_SERVER_LISTEN/stats" 2>/dev/null \
    || echo "(stats 不可用)"

echo ""
echo "----- JSON 摘要（demo log 末尾） -----"
if [[ -f "$DEMO_LOG" ]]; then
    # 提取 PERF_SUMMARY_JSON 后的 JSON 内容
    sed -n '/--- PERF_SUMMARY_JSON ---/,$ p' "$DEMO_LOG" | tail -n +2 | python3 -m json.tool 2>/dev/null \
        || sed -n '/--- PERF_SUMMARY_JSON ---/,$ p' "$DEMO_LOG" | tail -n +2
fi

echo ""
echo "================================================================"
log_info "✓ zkvm E2E 完整测试全部通过"
echo "================================================================"

exit 0
