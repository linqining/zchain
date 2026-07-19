# zkvm E2E 完整测试 — Phase 2-5 续执行计划

> **目标**（用户原话）：
> 1. zkvm 类似服务器一样一直运行
> 2. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker` 以 ELF 形式（实际 zkvm 运行的方式）加载运行
> 3. 看到整体的一手流程，如初始的 lcccs 注册到链上，最后有些结束提交最终 proof
> 4. 使用并行证明配置，以测试实际最低证明延迟
>
> **本文件定位**：Phase 1 已完成（152 测试通过），本文档为 Phase 2-5 续执行计划。

---

## 1. 当前状态（Phase 1 探索结论）

### 1.1 Phase 1 已完成 ✅

| 文件 | 行数 | 状态 |
|------|------|------|
| `poker_zkvm/src/syscalls/mod.rs` | 914 | ✅ SyscallId 26 variant + SyscallContext.game_state 字段 |
| `poker_zkvm/src/syscalls/bls12381.rs` | 815 | ✅ 6 个 BLS12-381 syscall，20 个测试 |
| `poker_zkvm/src/syscalls/game.rs` | 542 | ✅ 3 个 game syscall，15 个测试 |
| `poker_zkvm/src/syscalls/game_state.rs` | 433 | ✅ 2 个 GameState mock syscall，12 个测试 |
| `poker_zkvm/src/syscalls/host.rs` | 1327 | ✅ create_full_registry() 注册 21 个 syscall |
| `poker_zkvm/src/isa/executor.rs` | - | ✅ 修复 unknown syscall id 测试（0x16） |

**验证**：`cargo check --workspace` 通过（322 pre-existing warnings，无 error）。

### 1.2 Phase 2-5 关键发现

| Phase | 关键发现 |
|-------|---------|
| Phase 2 | `test_helpers.rs` 611 行，已有 `build_poker_hand_eval_v2_elf` / `build_poker_hand_compare_elf` 模式可复用；插入点在 line 459 之后 |
| Phase 3 | `poker_zkvm/src/service/` 模块不存在；workspace 已有 `tokio` 但无 `axum/hyper/reqwest`；`main.rs` 现有风格用 `std::net::TcpListener` |
| Phase 4 | **重大发现**：`poker_l1/src/offline/state.rs` 已实现完整 `PartialCheckinTx` / `CheckinTx` / `execute_partial_checkin` / `execute_checkin`，链上侧无需新建 |
| Phase 5 | `constraints/mod.rs:410-447` `compile_trace_to_ccs` 单线程 for 循环；`rayon` 已在 workspace 且 `ipa.rs`/`sumcheck.rs` 已使用 |

### 1.3 关键技术决策（基于上次会话已批准）

| 决策 | 选择 | 理由 |
|------|------|------|
| **ELF 范围** | 完整 texas_poker 合约 ELF 化（手工 RV32I 汇编） | 用户原话"以 ELF 形式加载运行"，手工汇编直接调用 26 个 syscall |
| **跳过 trait 重构** | 是 — 直接做 ELF 构造，不重构 2814 行 `state_machine.rs` | trait 重构 ~1600 行风险高；手工汇编绕过 trait 直接 syscall，更贴近"实际 zkvm 运行方式" |
| **服务化方式** | 完整 HTTP server + 缓存层 | 用户原话"类似服务器一样一直运行" |
| **HTTP 框架** | `axum` + `tokio` | tokio 生态主流；用户已批准"完整 HTTP server"；引入仅影响 `poker_zkvm` crate，不污染 `zchain` 主二进制 |
| **LCCCS 提交** | 复用 `poker_l1::offline::state::PartialCheckinTx` 真实分阶段 | 已实现，无需新建链上类型 |
| **partial_checkin 次数** | 2 次 partial + 1 次 final | 平衡真实性与复杂度 |
| **并行策略** | rayon（CCS 编译 + sumcheck 内部） | 已在 workspace；不改 fold_loop 顺序 |

---

## 2. Phase 2 — texas_poker 合约 ELF 化（~800 行）

### 2.1 构造完整一手牌 ELF

**文件**：`poker_zkvm/src/test_helpers.rs`（修改，line 459 之后追加）

**新增函数**：`pub fn build_texas_poker_full_hand_elf() -> Vec<u8>`（~250 行 RV32I 汇编）

**ELF 程序流程**（覆盖用户需求 #2 — 完整一手牌）：

```text
Phase 1: Setup
  - LUI x20, 0x2          // x20 = 0x2000 输入缓冲区基址
  - ADDI a0, x20, 0; ADDI a1, x0, 52; ADDI a7, x0, 1; ECALL  // read_input(0x2000, 52) 读取 52 张 deck

Phase 2: GameState 写入（模拟 ObjectDb 注册初始状态）
  - ADDI a0, x0, 0x20; ADDI a1, x20, 0; ADDI a2, x0, 52; ADDI a7, x0, 0x21; ECALL
    // game_state_write(slot=0x20, in_ptr=0x2000, in_len=52) → SLOT_PLAYER_HANDS

Phase 3: GameState 读回验证
  - ADDI a0, x0, 0x20; ADDI a1, x20, 0x100; ADDI a2, x0, 52; ADDI a7, x0, 0x20; ECALL
    // game_state_read(slot=0x20, out_ptr=0x2100, out_len=52) → 返回 actual_len

Phase 4: CardEncode + CardDecode 往返（验证牌编码一致性）
  - 对 deck[0..5] 循环：card_decode(byte) → (rank, suit) → card_encode(rank, suit) → byte'
  - 校验 byte == byte'，失败则 panic

Phase 5: ShuffleVerify（MVP — 校验 deck 是 0..52 排列 + proof 非空）
  - ADDI a0, x20, 0; ADDI a1, x0, 52; ADDI a2, x20, 0x200; ADDI a3, x0, 64; ADDI a7, x0, 0x32; ECALL
    // shuffle_verify(deck_ptr=0x2000, deck_len=52, proof_ptr=0x2200, proof_len=64)

Phase 6: BLS12-381 hash_to_curve（模拟洗牌密码学）
  - ADDI a0, x20, 0; ADDI a1, x0, 32; ADDI a2, x20, 0x300; ADDI a7, x0, 0x10; ECALL
    // bls_hash_to_curve(msg_ptr=0x2000, msg_len=32, out_ptr=0x2300) → 48B G1 point

Phase 7: BLS12-381 hash_to_scalar（派生标量用于下注签名）
  - ADDI a0, x20, 0; ADDI a1, x0, 32; ADDI a2, x20, 0x400; ADDI a7, x0, 0x15; ECALL
    // bls_hash_to_scalar(msg_ptr=0x2000, msg_len=32, out_ptr=0x2400) → 32B scalar

Phase 8: 牌型评估（复用 build_poker_hand_eval_v2_elf 的 max/min + pair_count 逻辑）
  - 对 P1 的 5 张牌计算 category + max_rank
  - 对 P2 的 5 张牌计算 category + max_rank
  - 比较 → winner (1=P1, 2=P2, 0=tie)

Phase 9: commit_output
  - SB winner, 0(x0); ADDI a0, x0, 0; ADDI a1, x0, 1; ADDI a7, x0, 2; ECALL
```

**寄存器分配**：
| 寄存器 | 用途 |
|--------|------|
| x20 | 0x2000 输入缓冲区基址 |
| x1-x5 | P1 5 张牌 |
| x6-x10 | P2 5 张牌 |
| x11 | pair_count P1 |
| x12 | pair_count P2 |
| x13 | winner |
| x14/x15 | 临时 |
| x16 | actual_len 返回值 |
| x10/x11/x17 | syscall 参数 a0/a1/a7 |

**输入格式**（52 字节）：
```text
[0..5]   P1 牌（rank 2..14）
[5..10]  P2 牌（rank 2..14）
[10..52] shuffle proof（42 字节填充 + 22 字节零，满足 64 字节 proof 要求）
```

### 2.2 ELF 加载执行测试

**文件**：`poker_zkvm/tests/texas_poker_full_hand.rs`（新建，~150 行）

**测试用例**：
1. `test_full_hand_elf_loads` — ELF validate 通过
2. `test_full_hand_elf_executes` — 执行完成（无 panic）
3. `test_full_hand_p1_wins` — P1 牌型 > P2 → output[0] == 1
4. `test_full_hand_p2_wins` — P2 牌型 > P1 → output[0] == 2
5. `test_full_hand_tie` — 平局 → output[0] == 0
6. `test_full_hand_trace_length` — trace 长度在合理范围（预估 200-400 步）

**Phase 2 验证**：
```bash
cargo test -p poker_zkvm --lib test_helpers
cargo test -p poker_zkvm --test texas_poker_full_hand
cargo check --workspace
```

---

## 3. Phase 3 — zkvm 服务化（HTTP server + 缓存层，~900 行）

### 3.1 ProverService 实现

**文件**：`poker_zkvm/src/service/mod.rs`（新建，~350 行）

**核心结构**：
```rust
pub struct ProverService {
    /// CCS registry — 启动时构造，所有请求复用（避免重复 compile_trace_to_ccs）
    ccs_registry: Arc<Vec<Ccs>>,
    /// IPA PCS 缓存 — 按 n_vars 缓存（避免重复 setup）
    ipa_pcs_cache: Arc<RwLock<HashMap<usize, IpaPcs>>>,
    /// 已完成 proof 缓存 — 按 (elf_hash, input_hash) 缓存（避免重复 prove）
    proof_cache: Arc<RwLock<HashMap<[u8; 32], ProofCacheEntry>>>,
    /// 配置
    config: ProverServiceConfig,
    /// 统计
    stats: Arc<ProverServiceStats>,
}

pub struct ProverServiceConfig {
    pub batch_size: usize,
    pub max_n_vars: usize,
    pub proof_size_limit: usize,
    pub max_recursion_depth: u32,
    pub proof_cache_capacity: usize,  // 默认 16
    pub parallel_ccs_compile: bool,    // Phase 5 启用
}

impl ProverService {
    pub fn new(config: ProverServiceConfig) -> Result<Self, ZkvmError>;
    pub async fn prove(&self, elf: &[u8], input: &[u8]) -> Result<ProveResponse, ZkvmError>;
    pub async fn verify(&self, proof: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError>;
    pub fn stats(&self) -> ProverServiceStats;
}
```

**关键设计**：
- `prove()` 内部用 `tokio::task::spawn_blocking` 包装 `zkvm_prove`（避免阻塞 async runtime）
- proof_cache 命中时直接返回（避免重复 prove 同一 ELF+input）
- ipa_pcs_cache 按 `n_vars` 缓存 IPA PCS（构造昂贵）

### 3.2 HTTP server 实现

**文件**：`poker_zkvm/src/service/http.rs`（新建，~300 行）

**依赖**：在 `poker_zkvm/Cargo.toml` 添加 `axum = "0.7"` + `tokio = { version = "1", features = ["full"] }` + `tower = "0.4"`

**接口**：
| 方法 | 路径 | 请求 | 响应 |
|------|------|------|------|
| POST | `/prove` | `{ elf_hex, input_hex }` | `{ proof_hex, public_io, elapsed_ms, cache_hit }` |
| POST | `/verify` | `{ proof_hex, public_io }` | `{ valid, elapsed_ms }` |
| GET  | `/health` | - | `{ status, uptime_s, request_count, proofs_generated }` |
| GET  | `/stats` | - | `{ ccs_cache_size, ipa_pcs_cache_size, proof_cache_size, total_proofs, avg_latency_ms }` |
| POST | `/shutdown` | - | `{ status: "shutting_down" }` |

**axum 路由**：
```rust
let app = Router::new()
    .route("/prove", post(handlers::prove))
    .route("/verify", post(handlers::verify))
    .route("/health", get(handlers::health))
    .route("/stats", get(handlers::stats))
    .route("/shutdown", post(handlers::shutdown))
    .with_state(app_state);
```

**优雅关闭**：监听 SIGINT/SIGTERM，drain in-flight 请求后退出。

### 3.3 类型定义

**文件**：`poker_zkvm/src/service/types.rs`（新建，~100 行）

```rust
#[derive(Serialize, Deserialize)]
pub struct ProveRequest { pub elf_hex: String, pub input_hex: String }

#[derive(Serialize, Deserialize)]
pub struct ProveResponse {
    pub proof_hex: String,
    pub public_io_hex: String,
    pub elapsed_ms: u64,
    pub cache_hit: bool,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyRequest { pub proof_hex: String, pub public_io_hex: String }

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse { pub valid: bool, pub elapsed_ms: u64 }

#[derive(Serialize, Deserialize)]
pub struct HealthResponse { pub status: String, pub uptime_s: u64, pub request_count: u64, pub proofs_generated: u64 }

#[derive(Serialize, Deserialize)]
pub struct StatsResponse {
    pub ccs_cache_size: usize,
    pub ipa_pcs_cache_size: usize,
    pub proof_cache_size: usize,
    pub total_proofs: u64,
    pub avg_latency_ms: u64,
}
```

### 3.4 客户端 SDK

**文件**：`poker_zkvm/src/service/client.rs`（新建，~100 行）

```rust
pub struct ZkvmClient { base_url: String, http: reqwest::Client }

impl ZkvmClient {
    pub fn new(base_url: &str) -> Self;
    pub async fn prove(&self, elf: &[u8], input: &[u8]) -> Result<ProveResponse, ZkvmError>;
    pub async fn verify(&self, proof: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError>;
    pub async fn health(&self) -> Result<HealthResponse, ZkvmError>;
}
```

**依赖**：`reqwest = { version = "0.12", features = ["json"], default-features = false, features = ["rustls-tls"] }`

### 3.5 `zkvm-server` 子命令

**文件**：`src/main.rs`（修改，添加 ~30 行）

```rust
"zkvm-server" => {
    if let Err(e) = run_zkvm_server(rest) {
        error!("zkvm-server 失败：{e}");
        std::process::exit(1);
    }
}
```

**新增 `run_zkvm_server`**（在 `src/main.rs` 末尾或新文件 `src/zkvm_server.rs`）：
- 解析 `--listen <addr>`（默认 `127.0.0.1:9527`）
- 解析 `--batch-size <n>`（默认 256）
- 启动 `ProverService` + axum server
- 优雅关闭

### 3.6 集成测试

**文件**：`poker_zkvm/tests/service_e2e.rs`（新建，~150 行）

**测试用例**：
1. `test_health` — GET /health 返回 200
2. `test_prove_verify_roundtrip` — POST /prove → POST /verify → valid=true
3. `test_proof_cache_hit` — 同一 ELF+input 二次 prove → cache_hit=true
4. `test_invalid_elf` — 非法 ELF → 400 错误
5. `test_stats` — GET /stats 返回正确字段

**Phase 3 验证**：
```bash
cargo test -p poker_zkvm --lib service
cargo test -p poker_zkvm --test service_e2e
# 手动启动测试：
zchain zkvm-server --listen 127.0.0.1:9527 &
curl http://127.0.0.1:9527/health
```

---

## 4. Phase 4 — 链上 LCCCS 分阶段提交（~600 行）

### 4.1 poker_zkvm 扩展 PartialProveState API

**文件**：`poker_zkvm/src/prover/partial.rs`（新建，~250 行）

**核心结构**：
```rust
pub struct PartialProveState {
    pub ccs: Ccs,
    pub initial_lcccs: Lcccs,
    pub initial_witness_commitment: IpaCommitment,
    pub ccccs_queue: Vec<Ccccs>,           // 剩余待折叠的 CCCCS
    pub folded_step_count: u32,             // 已折叠步数
    pub intermediate_commitment: Hash,      // 中间状态承诺
    pub transcript: Transcript,             // Fiat-Shamir transcript 状态
    pub pcs: IpaPcs,                        // IPA PCS（保持单例避免重复构造）
    pub r_x_l: Vec<ZkvmFr>,                 // 公共 challenge
    pub batch_public_inputs: Vec<Vec<ZkvmFr>>,
    pub ccs_commitment: [u8; 32],
    pub public_io_commitment: [u8; 32],
}

pub struct PartialProof {
    pub proof_partial: Vec<u8>,             // 序列化的部分 fold 证明
    pub folded_step_count: u32,
    pub intermediate_commitment: Hash,
    pub ack_chain_partial_hash: Hash,       // 前 N 个 ack 的哈希
}

pub fn prove_partial_start(
    elf_bytes: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<PartialProveState, ZkvmError>;

pub fn prove_partial_fold(
    state: &mut PartialProveState,
    fold_steps: usize,                      // 本次折叠的步数
) -> Result<PartialProof, ZkvmError>;

pub fn prove_final_fold(
    state: PartialProveState,
) -> Result<(Vec<u8>, ZkPublicIo), ZkvmError>;  // 完整 HypernovaProof + public_io
```

**实现策略**：
- `prove_partial_start`：复用 `prove()` 的 step 1-8（ELF 执行 + trace padding + CCS 编译 + initial LCCCS + CCCCS 构造）
- `prove_partial_fold`：从 `ccccs_queue` 取出 N 个 CCCCS，调用 `fold_step::fold` + `sumcheck::prove`，更新 `folded_step_count` + `intermediate_commitment`
- `prove_final_fold`：折叠剩余 CCCCS + PCS opening + 序列化完整 proof
- ack_chain_partial_hash 使用 `poker_l1::offline::ack_chain::compute_ack_chain_partial_hash`

### 4.2 demo 集成 — 真实分阶段提交

**文件**：`src/poker_zkvm_demo.rs`（修改，扩展 `run_full_hand`，~250 行新代码）

**新增函数**：
```rust
/// Phase F: 链上 LCCCS 分阶段提交（partial_checkin × 2 + final checkin）
fn run_lcccs_phased_submit(
    rpc_listen: &str,
    elf: &[u8],
    input: &[u8],
    config: &ProverConfig,
) -> Result<u8, String> {
    // 1. prove_partial_start → initial LCCCS
    let mut state = poker_zkvm::prover::partial::prove_partial_start(elf, input, config)
        .map_err(|e| format!("partial_start: {e}"))?;
    info!("[chain] initial LCCCS 已构造，准备分阶段提交");

    // 2. prove_partial_fold (fold 2 batches) → PartialProof #1
    let partial1 = poker_zkvm::prover::partial::prove_partial_fold(&mut state, 2)
        .map_err(|e| format!("partial_fold #1: {e}"))?;
    let partial_tx1 = build_partial_checkin_tx(&partial1);
    submit_partial_checkin_via_rpc(rpc_listen, &partial_tx1)?;
    info!("[chain] PartialCheckinTx #1 confirmed (folded_step_count={})",
          partial1.folded_step_count);

    // 3. prove_partial_fold (fold 2 batches) → PartialProof #2
    let partial2 = poker_zkvm::prover::partial::prove_partial_fold(&mut state, 2)
        .map_err(|e| format!("partial_fold #2: {e}"))?;
    let partial_tx2 = build_partial_checkin_tx(&partial2);
    submit_partial_checkin_via_rpc(rpc_listen, &partial_tx2)?;
    info!("[chain] PartialCheckinTx #2 confirmed (folded_step_count={})",
          partial2.folded_step_count);

    // 4. prove_final_fold → 完整 HypernovaProof
    let (proof_bytes, public_io) = poker_zkvm::prover::partial::prove_final_fold(state)
        .map_err(|e| format!("final_fold: {e}"))?;
    let checkin_tx = build_checkin_tx(&proof_bytes, &public_io, /*has_partial_checkin=*/true);
    submit_checkin_via_rpc(rpc_listen, &checkin_tx)?;
    info!("[chain] CheckinTx confirmed (final proof, {} bytes)", proof_bytes.len());

    // 5. 验证链上 last_partial_fold 已清空 + verify_proof_onchain 通过
    verify_onchain_final_state(rpc_listen)?;
    Ok(0)
}
```

**辅助函数**：
- `build_partial_checkin_tx(partial: &PartialProof) -> PartialCheckinTx` — 构造链上 PartialCheckinTx
- `build_checkin_tx(proof, public_io, has_partial) -> CheckinTx` — 构造链上 CheckinTx
- `submit_partial_checkin_via_rpc(rpc, tx)` — 通过 JSON-RPC 提交
- `submit_checkin_via_rpc(rpc, tx)` — 通过 JSON-RPC 提交
- `verify_onchain_final_state(rpc)` — 查询链上 Game 对象确认 last_partial_fold = None

### 4.3 RPC demo 扩展

**文件**：`src/poker_rpc_demo.rs`（修改，添加 ~100 行）

**新增函数**：
- `submit_partial_checkin_via_rpc(rpc_listen, tx: &PartialCheckinTx) -> Result<(), String>`
- `submit_checkin_via_rpc(rpc_listen, tx: &CheckinTx) -> Result<(), String>`
- `query_last_partial_fold(rpc_listen, game_id) -> Result<Option<LastPartialFold>, String>`

### 4.4 端到端测试

**文件**：`poker_l1/tests/phase12_e2e_lcccs.rs`（新建，~150 行）

**测试用例**：
1. 启动 validator 节点（in-process）
2. `prove_partial_start` → 提交 `PartialCheckinTx #1`
3. `prove_partial_fold` → 提交 `PartialCheckinTx #2`
4. `prove_final_fold` → 提交 `CheckinTx`
5. 查询链上 `last_partial_fold == None` + `partial_checkin_count == 2`
6. 链上 `verify_proof_onchain` 通过

**Phase 4 验证**：
```bash
cargo test -p poker_zkvm --lib prover::partial
cargo test -p poker_l1 --test phase12_e2e_lcccs
zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_e2e.log
# 日志应含：
#   "initial LCCCS 已构造"
#   "PartialCheckinTx #1 confirmed (folded_step_count=2)"
#   "PartialCheckinTx #2 confirmed (folded_step_count=4)"
#   "CheckinTx confirmed (final proof, NNNN bytes)"
```

---

## 5. Phase 5 — 并行证明配置 + 性能测试（~400 行）

### 5.1 启用 compile_trace_to_ccs 多 batch 并行

**文件**：`poker_zkvm/src/constraints/mod.rs`（修改，~50 行改动）

**改动**：line 436-444 batch 循环改为 `rayon::par_iter`

```rust
// 修改前（line 435-444）：
let mut instances = Vec::with_capacity(num_batches);
for batch_id in 0..num_batches {
    let start = batch_id * batch_size;
    let end = usize::min(start + batch_size, num_steps);
    let batch_steps: Vec<&crate::trace::Step> = (start..end)
        .map(|i| trace.step(i))
        .collect::<Result<Vec<_>, _>>()?;
    let instance = compile_batch_to_ccs(&batch_steps, batch_id as u64)?;
    instances.push(instance);
}

// 修改后：
use rayon::prelude::*;
let instances: Vec<CcsInstance> = (0..num_batches)
    .into_par_iter()
    .map(|batch_id| -> Result<CcsInstance, ZkvmError> {
        let start = batch_id * batch_size;
        let end = usize::min(start + batch_size, num_steps);
        let batch_steps: Vec<&crate::trace::Step> = (start..end)
            .map(|i| trace.step(i))
            .collect::<Result<Vec<_>, _>>()?;
        compile_batch_to_ccs(&batch_steps, batch_id as u64)
    })
    .collect::<Result<Vec<_>, _>>()?;
```

**注意**：`compile_batch_to_ccs` 是纯函数（无共享状态），并行安全。

### 5.2 ProverConfig 扩展 + RAYON_NUM_THREADS 配置

**文件**：`poker_zkvm/src/prover/mod.rs`（修改，~50 行）

**ProverConfig 新增字段**：
```rust
pub struct ProverConfig {
    // ... 既有字段 ...
    /// rayon 线程数（None = 使用 RAYON_NUM_THREADS 环境变量或默认值）
    pub rayon_threads: Option<usize>,
    /// 是否启用 CCS 编译并行化（默认 true）
    pub parallel_ccs_compile: bool,
}
```

**ThreadPool 初始化**（在 `prove()` 入口）：
```rust
if let Some(threads) = config.rayon_threads {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| ZkvmError::Other(format!("rayon pool: {e}")))?;
    pool.install(|| {
        // 实际 prove 逻辑
        prove_inner(elf_bytes, input, config)
    })
} else {
    prove_inner(elf_bytes, input, config)
}
```

### 5.3 ProverServiceConfig 与 ProverConfig 对齐

**文件**：`poker_zkvm/src/service/mod.rs`（修改，~30 行）

`ProverServiceConfig` 新增 `rayon_threads: Option<usize>` + `parallel_ccs_compile: bool`，传递给 `ProverConfig`。

### 5.4 性能基准测试

**文件**：`poker_zkvm/benches/prove_bench.rs`（新建，~200 行）

**基准场景**：
1. `bench_prove_cold` — 冷启动 prove（无缓存）
2. `bench_prove_warm` — 热缓存 prove（同 ELF+input 二次）
3. `bench_ccs_compile_sequential` — 单线程 CCS 编译
4. `bench_ccs_compile_parallel_4` — 4 线程 CCS 编译
5. `bench_ccs_compile_parallel_8` — 8 线程 CCS 编译
6. `bench_partial_fold` — 分阶段 fold 延迟
7. `bench_final_fold` — 最终 fold + PCS opening 延迟
8. `bench_full_hand_elf` — 完整一手牌 ELF 端到端延迟

**输出格式**：
```text
bench_prove_cold                ... bench: 12,345 ms
bench_prove_warm                ... bench:    12 ms (cache hit)
bench_ccs_compile_sequential    ... bench:  8,234 ms
bench_ccs_compile_parallel_4    ... bench:  2,567 ms (3.2x speedup)
bench_ccs_compile_parallel_8    ... bench:  1,823 ms (4.5x speedup)
bench_partial_fold              ... bench:  2,456 ms
bench_final_fold                ... bench:  3,678 ms
bench_full_hand_elf             ... bench: 15,234 ms
```

### 5.5 端到端性能日志

**文件**：`src/poker_zkvm_demo.rs`（修改，~100 行）

**新增 `--parallel-threads <n>` 参数**：
- 启动时设置 `RAYON_NUM_THREADS=n`
- 在 `PerfSummary` 中记录：
  - `ccs_compile_ms` — CCS 编译耗时
  - `fold_loop_ms` — fold 循环耗时
  - `pcs_opening_ms` — PCS opening 耗时
  - `partial_fold_count` — partial fold 次数
  - `total_proof_ms` — 端到端 prove 耗时
  - `parallel_threads` — 实际使用的线程数

### 5.6 完整测试脚本

**文件**：`scripts/run_zkvm_e2e_full_test.sh`（新建，~80 行）

```bash
#!/bin/bash
set -e

# 1. 启动 zkvm-server（后台）
zchain zkvm-server --listen 127.0.0.1:9527 --batch-size 256 --parallel-threads 8 &
ZKVM_PID=$!
trap "kill $ZKVM_PID 2>/dev/null" EXIT

# 2. 等待 server 就绪
for i in {1..30}; do
    curl -sf http://127.0.0.1:9527/health && break
    sleep 0.5
done

# 3. 启动 validator 节点（后台）
zchain node --role validator --data-dir /tmp/zkvm-e2e-data --rpc-listen 127.0.0.1:8545 &
NODE_PID=$!
trap "kill $NODE_PID 2>/dev/null" EXIT

# 4. 等待节点就绪
sleep 3

# 5. 运行完整 E2E 测试
zchain poker-zkvm-demo \
    --rpc 127.0.0.1:8545 \
    --zkvm-server http://127.0.0.1:9527 \
    --parallel-threads 8 \
    --log-file /tmp/zkvm_e2e_full.log

# 6. 输出性能摘要
echo "===== 性能摘要 ====="
grep -E "(ccs_compile|fold_loop|pcs_opening|total_proof|partial_fold)" /tmp/zkvm_e2e_full.log
```

**Phase 5 验证**：
```bash
cargo bench -p poker_zkvm --bench prove_bench
bash scripts/run_zkvm_e2e_full_test.sh
# 日志含完整 4 阶段耗时 + 最低延迟配置（8 线程）
```

---

## 6. 假设与决策

### 6.1 关键假设

1. **完整一手牌 ELF trace 预估 200-400 步**，对应 1-2 batch（batch_size=256），需 pad 到 256 步
2. **zkvm server 单次 prove 延迟预估 5-15 秒**（batch_size=256 + 8 线程）
3. **链上 partial_checkin 提交延迟预估 1.5s**（3 个 block × 500ms）
4. **CCS 编译并行加速比预估 3-5x**（4-8 线程，受 Amdahl 定律限制 — fold_loop 仍串行）
5. **proof_cache 命中时延迟 < 50ms**（仅 hex 序列化 + 网络往返）

### 6.2 风险与缓解

| 风险 | 缓解 |
|------|------|
| 手工汇编完整一手牌 ELF trace 步数超预期（>1024） | 降级为"最小完整流程"（init + 1 次 shuffle verify + showdown）；调整 batch_size |
| axum 引入导致 `poker_zkvm` 编译时间大幅增加 | axum 仅在 `service` feature 下启用；非 service 用户无影响 |
| `ProverService` proof_cache 内存膨胀 | LRU 淘汰（默认 capacity=16）；可配置 |
| `PartialProveState` 跨 fold_step 共享 transcript 状态与 `fold_loop` 不一致 | 单元测试验证 partial_fold N 次后 final_fold 的 proof == 直接 prove 的 proof |
| rayon `pool.install()` 与 axum tokio runtime 冲突 | 严格用 `tokio::task::spawn_blocking` 包装 prove 调用；rayon pool 在 blocking 线程内 install |
| 链上 PartialCheckinTx 提交失败（签名/校验） | 单元测试验证签名/构造后再上链；失败重试 3 次 |

### 6.3 跳过项（明确不实现）

1. **texas_poker trait 重构**（原 Phase 2.1-2.3）— 手工汇编直接调用 syscall，无需 trait 抽象
2. **Spartan/Groth16 压缩完整实现** — 已有 stub，本次不扩展
3. **CycleFold 递归压缩** — proof_size_limit=64KB，单实例 proof 不超限
4. **zkvm-server TLS** — 仅本地 127.0.0.1 监听，生产部署需额外 TLS 反代
5. **axum middleware 认证** — 仅本地测试，生产部署需加 auth middleware

---

## 7. 执行顺序

```
Phase 2（texas_poker 合约 ELF 化，~800 行）
  2.1 build_texas_poker_full_hand_elf（test_helpers.rs 扩展）
  2.2 ELF 加载执行测试（tests/texas_poker_full_hand.rs）
  ↓
Phase 3（zkvm 服务化，~900 行）
  3.1 ProverService（service/mod.rs）
  3.2 HTTP server（service/http.rs）+ axum 依赖
  3.3 类型定义（service/types.rs）
  3.4 客户端 SDK（service/client.rs）
  3.5 zkvm-server 子命令（main.rs）
  3.6 集成测试（tests/service_e2e.rs）
  ↓
Phase 4（链上 LCCCS 分阶段提交，~600 行）
  4.1 PartialProveState API（prover/partial.rs）
  4.2 demo 集成（poker_zkvm_demo.rs 扩展）
  4.3 RPC demo 扩展（poker_rpc_demo.rs）
  4.4 端到端测试（tests/phase12_e2e_lcccs.rs）
  ↓
Phase 5（并行证明配置 + 性能测试，~400 行）
  5.1 compile_trace_to_ccs 并行化（constraints/mod.rs）
  5.2 ProverConfig rayon_threads（prover/mod.rs）
  5.3 ProverServiceConfig 对齐（service/mod.rs）
  5.4 性能基准（benches/prove_bench.rs）
  5.5 端到端性能日志（poker_zkvm_demo.rs）
  5.6 完整测试脚本（scripts/run_zkvm_e2e_full_test.sh）
```

**总剩余工作量**：~2700 行新代码 + ~200 行改动

---

## 8. 关键文件清单

### 新建文件（11 个）
- `poker_zkvm/tests/texas_poker_full_hand.rs` — Phase 2 ELF 测试
- `poker_zkvm/src/service/mod.rs` — Phase 3 ProverService
- `poker_zkvm/src/service/http.rs` — Phase 3 HTTP server
- `poker_zkvm/src/service/types.rs` — Phase 3 请求/响应类型
- `poker_zkvm/src/service/client.rs` — Phase 3 客户端 SDK
- `poker_zkvm/tests/service_e2e.rs` — Phase 3 集成测试
- `poker_zkvm/src/prover/partial.rs` — Phase 4 PartialProveState API
- `poker_l1/tests/phase12_e2e_lcccs.rs` — Phase 4 端到端测试
- `poker_zkvm/benches/prove_bench.rs` — Phase 5 性能基准
- `scripts/run_zkvm_e2e_full_test.sh` — Phase 5 端到端脚本
- `src/zkvm_server.rs` — Phase 3 zkvm-server 子命令入口

### 修改文件（8 个）
- `poker_zkvm/src/test_helpers.rs` — 追加 `build_texas_poker_full_hand_elf`（Phase 2）
- `poker_zkvm/Cargo.toml` — 新增 `axum` + `reqwest` + `tower` 依赖（Phase 3）
- `poker_zkvm/src/lib.rs` — 注册 `pub mod service;` + `pub mod prover::partial;`（Phase 3-4）
- `poker_zkvm/src/prover/mod.rs` — ProverConfig 新增 `rayon_threads` + `parallel_ccs_compile`（Phase 5）
- `poker_zkvm/src/constraints/mod.rs` — `compile_trace_to_ccs` 并行化（Phase 5）
- `src/main.rs` — 新增 `zkvm-server` 子命令分发（Phase 3）
- `src/poker_zkvm_demo.rs` — 集成 Phase 4 LCCCS 分阶段 + Phase 5 性能日志（Phase 4-5）
- `src/poker_rpc_demo.rs` — 新增 partial_checkin / checkin 提交辅助函数（Phase 4）

---

## 9. 最终端到端验证

完整测试通过标准：

1. ✅ **Phase 2**：`cargo test -p poker_zkvm --test texas_poker_full_hand` 通过
   - 完整一手牌 ELF 执行，trace 长度 200-400 步
   - P1/P2 胜/平局三种结果正确

2. ✅ **Phase 3**：`cargo test -p poker_zkvm --test service_e2e` 通过
   - `curl http://127.0.0.1:9527/health` 返回 200
   - prove → verify 往返成功
   - proof_cache 命中正确

3. ✅ **Phase 4**：`cargo test -p poker_l1 --test phase12_e2e_lcccs` 通过
   - `poker-zkvm-demo` 日志含：
     - `initial LCCCS 已构造`
     - `PartialCheckinTx #1 confirmed (folded_step_count=2)`
     - `PartialCheckinTx #2 confirmed (folded_step_count=4)`
     - `CheckinTx confirmed (final proof, NNNN bytes)`
   - 链上 `last_partial_fold == None` + `partial_checkin_count == 2`
   - 链上 `verify_proof_onchain` 通过

4. ✅ **Phase 5**：`cargo bench -p poker_zkvm --bench prove_bench` 通过
   - 8 线程 CCS 编译加速比 ≥ 3x
   - `bash scripts/run_zkvm_e2e_full_test.sh` 通过
   - 日志含完整 4 阶段耗时 + 最低延迟配置

---

## 10. 总结

本计划在 Phase 1（已完成，152 测试通过）基础上，明确：

1. **Phase 2**（~800 行）：手工 RV32I 汇编构造完整一手牌 ELF，覆盖 init → game_state write/read → card encode/decode → shuffle_verify → BLS12-381 → 牌型评估 → showdown。**跳过 trait 重构**（原 Phase 2.1-2.3），直接做 ELF 构造。

2. **Phase 3**（~900 行）：完整 HTTP server + 缓存层，引入 `axum` + `tokio` + `reqwest`。ProverService 含 proof_cache + ipa_pcs_cache，axum 暴露 /prove /verify /health /stats /shutdown。

3. **Phase 4**（~600 行）：**复用** `poker_l1::offline::state::PartialCheckinTx`（已实现），新增 `poker_zkvm::prover::partial::PartialProveState` API。demo 中实现 2 次 partial_checkin + 1 次 final checkin 真实分阶段提交。

4. **Phase 5**（~400 行）：rayon 并行化 `compile_trace_to_ccs`，ProverConfig 新增 `rayon_threads` + `parallel_ccs_compile`。性能基准测试 8 线程最低延迟。

5. **执行原则**：每个 Phase 独立可验证，前一个