# zkvm E2E 完整测试 — Phase 2-5 执行就绪计划

> **本文件定位**：基于上一会话已批准的 `zkvm_e2e_phase2_5_resume_plan.md`（740 行）+ 本会话 Phase 1 重新盘点，给出**执行就绪**的精简实施计划。所有决策已 frozen，executor 可直接落地。
>
> **用户原话目标**：
>
> 1. zkvm 类似服务器一样一直运行
> 2. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker` 以 ELF 形式（实际 zkvm 运行的方式）加载运行
> 3. 看到整体的一手流程：初始 LCCCS 注册到链上 → 最终 proof 提交
> 4. 使用并行证明配置，测试实际最低证明延迟

***

## 1. 当前状态（Phase 1 重新盘点结论）

### 1.1 已完成 ✅

| 文件                                      | 行数   | 状态                                                                                                   |
| --------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------- |
| `poker_zkvm/src/syscalls/mod.rs`        | 914  | ✅ SyscallId 26 variant + SyscallContext.game\_state                                                  |
| `poker_zkvm/src/syscalls/bls12381.rs`   | 815  | ✅ 6 个 BLS12-381 syscall，20 测试                                                                        |
| `poker_zkvm/src/syscalls/game.rs`       | 542  | ✅ 3 个 game syscall（CardEncode/CardDecode/ShuffleVerify），15 测试                                        |
| `poker_zkvm/src/syscalls/game_state.rs` | 433  | ✅ 2 个 GameState mock syscall，12 测试                                                                   |
| `poker_zkvm/src/syscalls/host.rs`       | 1327 | ✅ create\_full\_registry() 注册 21 个 syscall                                                           |
| `poker_l1/src/offline/state.rs`         | -    | ✅ `PartialCheckinTx`/`CheckinTx`/`LastPartialFold` + `execute_partial_checkin`/`execute_checkin` 已实现 |

**验证**：后台 `cargo check --workspace` 通过（322 pre-existing warnings，0 error）。

### 1.2 Phase 2-5 待实现（本计划目标）

| Phase | 文件                                                                    | 状态              |
| ----- | --------------------------------------------------------------------- | --------------- |
| 2.1   | `poker_zkvm/src/test_helpers.rs` 追加 `build_texas_poker_full_hand_elf` | ❌ 不存在           |
| 2.2   | `poker_zkvm/tests/texas_poker_full_hand.rs`                           | ❌ 不存在           |
| 3.1   | `poker_zkvm/src/service/mod.rs` (ProverService)                       | ❌ 目录不存在         |
| 3.2   | `poker_zkvm/src/service/http.rs` (axum server)                        | ❌ 不存在           |
| 3.3   | `poker_zkvm/src/service/types.rs`                                     | ❌ 不存在           |
| 3.4   | `poker_zkvm/src/service/client.rs`                                    | ❌ 不存在           |
| 3.5   | `src/zkvm_server.rs` + `main.rs` zkvm-server 子命令                      | ❌ 不存在           |
| 3.6   | `poker_zkvm/tests/service_e2e.rs`                                     | ❌ 不存在           |
| 4.1   | `poker_zkvm/src/prover/partial.rs` (PartialProveState API)            | ❌ 不存在           |
| 4.2   | `src/poker_zkvm_demo.rs` 扩展 LCCCS 分阶段提交                               | ⚠️ 既有 demo 无分阶段 |
| 4.3   | `src/poker_rpc_demo.rs` 扩展 partial\_checkin/checkin RPC               | ⚠️ 既有无          |
| 4.4   | `poker_l1/tests/phase12_e2e_lcccs.rs`                                 | ❌ 不存在           |
| 5.1   | `poker_zkvm/src/constraints/mod.rs:410-447` 并行化                       | ❌ 仍单线程          |
| 5.2   | `poker_zkvm/src/prover/mod.rs` ProverConfig 新增 rayon\_threads         | ❌ 仅 7 字段        |
| 5.3   | `poker_zkvm/src/service/mod.rs` ProverServiceConfig 对齐                | ❌ 不存在           |
| 5.4   | `poker_zkvm/benches/prove_bench.rs`                                   | ❌ 不存在           |
| 5.5   | `src/poker_zkvm_demo.rs` 性能日志扩展                                       | ❌ 既有无           |
| 5.6   | `scripts/run_zkvm_e2e_full_test.sh`                                   | ❌ 不存在           |

### 1.3 关键技术事实（基于本会话 Phase 1 实地验证）

* **`ProverConfig`** **当前字段**（`prover/mod.rs:58-77`）：`batch_size`, `max_n_vars`, `proof_size_limit`, `max_recursion_depth`, `randomness_seed`, `initial_commitment`, `final_commitment` — **无 rayon\_threads/parallel\_ccs\_compile**

* **`HypernovaProof`** 在 `fold::fold_loop` 中定义（非 `prover/mod.rs`），含 `initial_lcccs + fold_steps + final_sumcheck + pcs_opening`

* **`texas_poker/hand_evaluator.rs`** 有完整 10 类牌型评估（HIGH\_CARD=0..=ROYAL\_FLUSH=9），`HandRank::to_u64()` 用 `category | (kickers[i] << 8*(i+1))` 编码

* **`test_helpers.rs`** 501 行，已有辅助函数：`encode_r/i/s/b/u/j`, `addi/add/sub/slt/sw/sb/lw/lb/bne/beq/lui/jal/ecall/nop` — **无 SLLI 辅助函数**

* **`poker_zkvm/Cargo.toml`** 无 `axum`/`tokio`/`reqwest`/`tower` 依赖（待新增）

* **`rayon`** 已在 workspace，`poker_zkvm/src/pcs/ipa.rs` 与 `sumcheck.rs` 已使用

***

## 2. Phase 2 — texas\_poker 合约 ELF 化（\~800 行）

### 2.1 `build_texas_poker_full_hand_elf()`（test\_helpers.rs 追加）

**文件**：`poker_zkvm/src/test_helpers.rs`（在 `poker_hand_compare_expected` 函数之后追加，约 line 500）

**新增函数签名**：

```rust
/// 构建完整一手牌流程 ELF — 覆盖 init → game_state write/read → card encode/decode →
/// shuffle_verify → BLS hash → 牌型评估(P1+P2) → showdown → commit_output。
///
/// 输入（62 字节）：
///   [0..52]   deck（0..51 的排列，供 shuffle_verify 校验）
///   [52..57]  P1 牌 rank（5 字节，值 2..=14）
///   [57..62]  P2 牌 rank（5 字节，值 2..=14）
///
/// 输出（1 字节）：
///   addr 0: winner（1=P1, 2=P2, 0=tie）
pub fn build_texas_poker_full_hand_elf() -> Vec<u8>
```

**ELF 程序 9 个 Phase（约 230 条指令）**：

```text
Phase 1: Setup (5 条)
  LUI x20, 0x2           # x20 = 0x2000 输入缓冲区基址
  ADDI a0, x20, 0        # a0 = 0x2000
  ADDI a1, x0, 62        # a1 = 62（input 长度）
  ADDI a7, x0, 1         # a7 = 1 (read_input)
  ECALL

Phase 2: GameState 写入（模拟初始状态上链，5 条）
  ADDI a0, x0, 0x02      # slot = SLOT_PLAYER_HANDS = 0x02
  ADDI a1, x20, 0        # in_ptr = 0x2000 (deck[0..52])
  ADDI a2, x0, 52        # in_len = 52
  ADDI a7, x0, 0x21      # a7 = 0x21 (game_state_write)
  ECALL

Phase 3: GameState 读回验证（5 条）
  ADDI a0, x0, 0x02      # slot = SLOT_PLAYER_HANDS
  ADDI a1, x20, 0x100    # out_ptr = 0x2100
  ADDI a2, x0, 52        # out_len = 52
  ADDI a7, x0, 0x20      # a7 = 0x20 (game_state_read)
  ECALL
  # a0 现含 actual_len（应 = 52）

Phase 4: CardEncode + CardDecode 往返（10 条）
  # 对 deck[0] 做 byte→(rank,suit)→byte' 校验
  LB x14, 0(x20)         # x14 = deck[0]
  ADDI a0, x0, 0         # a0 = byte（占位，下条覆盖）
  ADDI a0, x14, 0        # a0 = deck[0]
  ADDI a1, x20, 0x200    # out_rank_ptr = 0x2200
  ADDI a2, x20, 0x201    # out_suit_ptr = 0x2201
  ADDI a7, x0, 0x31      # a7 = 0x31 (card_decode)
  ECALL
  # 现重新 encode 回 byte'
  LB a0, 0x200(x20)      # a0 = rank
  LB a1, 0x201(x20)      # a1 = suit
  ADDI a2, x20, 0x202    # out_ptr = 0x2202
  ADDI a7, x0, 0x30      # a7 = 0x30 (card_encode)
  ECALL
  # 比对 deck[0] == 0x2202 字节（验证编码一致性，省略 — 视为合法流程演示）

Phase 5: ShuffleVerify（5 条）
  ADDI a0, x20, 0        # deck_ptr = 0x2000
  ADDI a1, x0, 52        # deck_len = 52
  ADDI a2, x20, 0x400    # proof_ptr = 0x2400（取 input 末尾 32B 作 mock proof）
  ADDI a3, x0, 32        # proof_len = 32
  ADDI a7, x0, 0x32      # a7 = 0x32 (shuffle_verify)
  ECALL

Phase 6: BLS hash_to_curve（5 条）
  ADDI a0, x20, 0        # msg_ptr = 0x2000
  ADDI a1, x0, 32        # msg_len = 32
  ADDI a2, x20, 0x500    # out_ptr = 0x2500 (48B G1 point)
  ADDI a7, x0, 0x10      # a7 = 0x10 (bls_hash_to_curve)
  ECALL

Phase 7: BLS hash_to_scalar（5 条）
  ADDI a0, x20, 0        # msg_ptr = 0x2000
  ADDI a1, x0, 32        # msg_len = 32
  ADDI a2, x20, 0x600    # out_ptr = 0x2600 (32B scalar)
  ADDI a7, x0, 0x15      # a7 = 0x15 (bls_hash_to_scalar)
  ECALL

Phase 8: P1 + P2 牌型评估 + 比较（约 190 条）
  # P1 评估（rank 在 input[52..57]）
  ADDI x21, x20, 52      # x21 = &P1[0]
  LB x1, 0(x21); LB x2, 1(x21); LB x3, 2(x21); LB x4, 3(x21); LB x5, 4(x21)
  # max/min 扫描（5 条 init + 4 张 × 5 条 = 25 条）
  # pair_count（C(5,2)=10 对 × 3 条 = 30 条）
  # category 推断（约 15 条）
  # 输出 P1 (category, max) 到 (x23, x24)

  # P2 评估（input[57..62]）
  ADDI x22, x20, 57      # x22 = &P2[0]
  LB x6, 0(x22); ... LB x10, 4(x22)
  # 同样 70 条
  # 输出 P2 (category, max) 到 (x25, x26)

  # 比较（约 15 条）— 不使用 SLLI 合并，直接两次比较
  # if x23 != x25: winner = (x23 > x25) ? 1 : 2
  # else if x24 != x26: winner = (x24 > x26) ? 1 : 2
  # else winner = 0
  # 结果存 x13

Phase 9: commit_output（5 条）
  SB x13, 0(x0)          # 输出 winner 到 addr 0
  ADDI a0, x0, 0         # output_ptr = 0
  ADDI a1, x0, 1         # output_len = 1
  ADDI a7, x0, 2         # a7 = 2 (commit_output)
  ECALL
```

**关键设计决策**：

1. **不使用 SLLI**：test\_helpers.rs 无 SLLI 辅助函数，比较逻辑改为两次 SLT + BNE（先比 category，再比 max\_rank），避免引入新指令辅助函数
2. **输入布局修正**：62 字节 = 52B deck 排列 + 5B P1 ranks + 5B P2 ranks。原计划 52 字节输入存在逻辑矛盾（deck\[0..10] 当 rank 用无法通过 shuffle\_verify 排列校验），本计划拆分为独立区域
3. **shuffle proof 复用**：取 deck\[0..32] 作为 mock proof（非全零且长度=32 ≥ 1），满足 ShuffleVerify MVP 校验
4. **trace 长度预估**：\~230 条指令 → 执行约 250-400 步（含 syscall 内部步） → 单 batch（batch\_size=256）足以容纳

### 2.2 ELF 加载执行测试

**文件**：`poker_zkvm/tests/texas_poker_full_hand.rs`（新建，\~150 行）

**测试用例**：

1. `test_full_hand_elf_loads` — `validate_elf` 通过
2. `test_full_hand_elf_executes` — 执行完成无 panic
3. `test_full_hand_p1_wins` — P1=完牌(A,K,Q,J,10), P2=一对(2,2,3,4,5) → output\[0] == 1
4. `test_full_hand_p2_wins` — 反向 → output\[0] == 2
5. `test_full_hand_tie` — P1==P2 → output\[0] == 0
6. `test_full_hand_trace_length` — trace 步数在 \[200, 600] 区间

**Phase 2 验证命令**：

```bash
cargo test -p poker_zkvm --lib test_helpers
cargo test -p poker_zkvm --test texas_poker_full_hand
cargo check --workspace
```

***

## 3. Phase 3 — zkvm 服务化（HTTP server + 缓存层，\~900 行）

### 3.1 ProverService 实现

**文件**：`poker_zkvm/src/service/mod.rs`（新建，\~350 行）

```rust
pub struct ProverService {
    ccs_registry: Arc<Vec<Ccs>>,                              // 启动时构造
    ipa_pcs_cache: Arc<RwLock<HashMap<usize, IpaPcs>>>,        // 按 n_vars 缓存
    proof_cache: Arc<RwLock<HashMap<[u8;32], ProofCacheEntry>>>, // 按 (elf_hash, input_hash)
    config: ProverServiceConfig,
    stats: Arc<AtomicProverStats>,
}

pub struct ProverServiceConfig {
    pub batch_size: usize,
    pub max_n_vars: usize,
    pub proof_size_limit: usize,
    pub max_recursion_depth: u32,
    pub proof_cache_capacity: usize,  // 默认 16
    pub parallel_ccs_compile: bool,   // Phase 5 启用
    pub rayon_threads: Option<usize>, // Phase 5
}

impl ProverService {
    pub fn new(config: ProverServiceConfig) -> Result<Self, ZkvmError>;
    pub async fn prove(&self, elf: &[u8], input: &[u8]) -> Result<ProveResponse, ZkvmError>;
    pub async fn verify(&self, proof: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError>;
    pub fn stats(&self) -> ProverStats;
}
```

**关键实现**：

* `prove()` 用 `tokio::task::spawn_blocking` 包装 `zkvm_prove`（避免阻塞 async runtime）

* proof\_cache 命中时直接返回，LRU 淘汰（capacity=16）

* ipa\_pcs\_cache 按 `n_vars` 缓存（构造昂贵）

### 3.2 HTTP server 实现

**文件**：`poker_zkvm/src/service/http.rs`（新建，\~300 行）

**依赖**（`poker_zkvm/Cargo.toml` 新增）：

```toml
axum = { version = "0.7", optional = true }
tokio = { version = "1", features = ["full"], optional = true }
tower = { version = "0.4", optional = true }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false, optional = true }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[features]
service = ["dep:axum", "dep:tokio", "dep:tower", "dep:reqwest"]
```

**接口**：

| 方法   | 路径          | 说明                                                                                     |
| ---- | ----------- | -------------------------------------------------------------------------------------- |
| POST | `/prove`    | `{elf_hex, input_hex}` → `{proof_hex, public_io_hex, elapsed_ms, cache_hit}`           |
| POST | `/verify`   | `{proof_hex, public_io_hex}` → `{valid, elapsed_ms}`                                   |
| GET  | `/health`   | `{status, uptime_s, request_count, proofs_generated}`                                  |
| GET  | `/stats`    | `{ccs_cache_size, ipa_pcs_cache_size, proof_cache_size, total_proofs, avg_latency_ms}` |
| POST | `/shutdown` | `{status: "shutting_down"}`                                                            |

**优雅关闭**：监听 SIGINT/SIGTERM，drain in-flight 请求后退出。

### 3.3 类型定义

**文件**：`poker_zkvm/src/service/types.rs`（新建，\~100 行）— `ProveRequest/Response`, `VerifyRequest/Response`, `HealthResponse`, `StatsResponse`（serde 序列化）

### 3.4 客户端 SDK

**文件**：`poker_zkvm/src/service/client.rs`（新建，\~100 行）— `ZkvmClient::prove/verify/health`，基于 reqwest

### 3.5 `zkvm-server` 子命令

**文件**：`src/zkvm_server.rs`（新建，\~80 行）+ `src/main.rs` 添加分发（\~10 行）

```rust
// src/main.rs match 分发新增：
"zkvm-server" => {
    if let Err(e) = zchain::zkvm_server::run(rest) {
        error!("zkvm-server 失败：{e}");
        std::process::exit(1);
    }
}
```

**参数**：`--listen <addr>`（默认 `127.0.0.1:9527`）、`--batch-size <n>`（默认 256）、`--parallel-threads <n>`（默认 None，使用 RAYON\_NUM\_THREADS）

### 3.6 集成测试

**文件**：`poker_zkvm/tests/service_e2e.rs`（新建，\~150 行）

**测试用例**：

1. `test_health` — GET /health 返回 200
2. `test_prove_verify_roundtrip` — POST /prove → POST /verify → valid=true
3. `test_proof_cache_hit` — 同一 ELF+input 二次 prove → cache\_hit=true
4. `test_invalid_elf` — 非法 ELF → 400 错误
5. `test_stats` — GET /stats 返回正确字段

**Phase 3 验证命令**：

```bash
cargo test -p poker_zkvm --lib service
cargo test -p poker_zkvm --test service_e2e
zchain zkvm-server --listen 127.0.0.1:9527 &
curl http://127.0.0.1:9527/health
```

***

## 4. Phase 4 — 链上 LCCCS 分阶段提交（\~600 行）

### 4.1 PartialProveState API

**文件**：`poker_zkvm/src/prover/partial.rs`（新建，\~250 行）

```rust
pub struct PartialProveState {
    pub ccs: Ccs,
    pub initial_lcccs: Lcccs,
    pub ccccs_queue: Vec<Ccccs>,           // 剩余待折叠
    pub folded_step_count: u32,            // 已折叠步数
    pub intermediate_commitment: [u8; 32], // 中间状态承诺
    pub transcript: Transcript,            // Fiat-Shamir 状态
    pub pcs: IpaPcs,                       // IPA PCS 单例
    pub r_x_l: Vec<ZkvmFr>,                // 公共 challenge
    pub batch_public_inputs: Vec<Vec<ZkvmFr>>,
    pub ccs_commitment: [u8; 32],
    pub public_io_commitment: [u8; 32],
}

pub struct PartialProof {
    pub proof_partial: Vec<u8>,
    pub folded_step_count: u32,
    pub intermediate_commitment: [u8; 32],
    pub ack_chain_partial_hash: [u8; 32],
}

pub fn prove_partial_start(elf: &[u8], input: &[u8], config: &ProverConfig)
    -> Result<PartialProveState, ZkvmError>;
pub fn prove_partial_fold(state: &mut PartialProveState, fold_steps: usize)
    -> Result<PartialProof, ZkvmError>;
pub fn prove_final_fold(state: PartialProveState)
    -> Result<(Vec<u8>, ZkPublicIo), ZkvmError>;
```

**实现策略**：

* `prove_partial_start`：复用 `prove()` 的 step 1-8（ELF 执行 + trace padding + CCS 编译 + initial LCCCS + CCCCS 构造）— 将 `prove()` 拆分为可暂停形态

* `prove_partial_fold`：从 `ccccs_queue` 取 N 个 CCCCS，调用 `fold_step::fold` + `sumcheck::prove`，更新 `folded_step_count` + `intermediate_commitment`

* `prove_final_fold`：折叠剩余 CCCCS + PCS opening + 序列化完整 proof

* `ack_chain_partial_hash` 使用 `poker_l1::offline::ack_chain::compute_ack_chain_partial_hash`

**注册**：`poker_zkvm/src/prover/mod.rs` 顶部添加 `pub mod partial;`

### 4.2 demo 集成 — 真实分阶段提交

**文件**：`src/poker_zkvm_demo.rs`（修改，\~250 行新代码）

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
    let mut state = poker_zkvm::prover::partial::prove_partial_start(elf, input, config)?;
    info!("[chain] initial LCCCS 已构造，准备分阶段提交");

    // 2. prove_partial_fold (fold 2 batches) → PartialProof #1
    let partial1 = poker_zkvm::prover::partial::prove_partial_fold(&mut state, 2)?;
    submit_partial_checkin_via_rpc(rpc_listen, &build_partial_checkin_tx(&partial1))?;
    info!("[chain] PartialCheckinTx #1 confirmed (folded_step_count={})", partial1.folded_step_count);

    // 3. prove_partial_fold (fold 2 batches) → PartialProof #2
    let partial2 = poker_zkvm::prover::partial::prove_partial_fold(&mut state, 2)?;
    submit_partial_checkin_via_rpc(rpc_listen, &build_partial_checkin_tx(&partial2))?;
    info!("[chain] PartialCheckinTx #2 confirmed (folded_step_count={})", partial2.folded_step_count);

    // 4. prove_final_fold → 完整 HypernovaProof
    let (proof_bytes, public_io) = poker_zkvm::prover::partial::prove_final_fold(state)?;
    submit_checkin_via_rpc(rpc_listen, &build_checkin_tx(&proof_bytes, &public_io, true))?;
    info!("[chain] CheckinTx confirmed (final proof, {} bytes)", proof_bytes.len());

    // 5. 链上 last_partial_fold 应为 None + verify_proof_onchain 通过
    verify_onchain_final_state(rpc_listen)?;
    Ok(0)
}
```

**辅助函数**（同文件或 `poker_rpc_demo.rs`）：

* `build_partial_checkin_tx(partial: &PartialProof) -> PartialCheckinTx`

* `build_checkin_tx(proof, public_io, has_partial) -> CheckinTx`

* `submit_partial_checkin_via_rpc(rpc, tx) -> Result<(), String>`

* `submit_checkin_via_rpc(rpc, tx) -> Result<(), String>`

* `verify_onchain_final_state(rpc) -> Result<(), String>`

### 4.3 RPC demo 扩展

**文件**：`src/poker_rpc_demo.rs`（修改，\~100 行）— 上述 submit/query 辅助函数实现

### 4.4 端到端测试

**文件**：`poker_l1/tests/phase12_e2e_lcccs.rs`（新建，\~150 行）

**测试用例**：

1. 启动 in-process validator 节点
2. `prove_partial_start` → 提交 `PartialCheckinTx #1`
3. `prove_partial_fold` → 提交 `PartialCheckinTx #2`
4. `prove_final_fold` → 提交 `CheckinTx`
5. 查询链上 `last_partial_fold == None` + `partial_checkin_count == 2`
6. 链上 `verify_proof_onchain` 通过

**Phase 4 验证命令**：

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

***

## 5. Phase 5 — 并行证明配置 + 性能测试（\~400 行）

### 5.1 启用 `compile_trace_to_ccs` 多 batch 并行

**文件**：`poker_zkvm/src/constraints/mod.rs:410-447`（修改 \~50 行）

```rust
// 修改前：单线程 for batch_id in 0..num_batches
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

### 5.2 `ProverConfig` 扩展 + RAYON\_NUM\_THREADS

**文件**：`poker_zkvm/src/prover/mod.rs:58-77`（修改 \~50 行）

`ProverConfig` 新增 2 字段：

```rust
pub rayon_threads: Option<usize>,     // None = 使用 RAYON_NUM_THREADS 环境变量
pub parallel_ccs_compile: bool,       // 默认 true
```

**ThreadPool 初始化**（在 `prove()` 入口）：

```rust
if let Some(threads) = config.rayon_threads {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| ZkvmError::Other(format!("rayon pool: {e}")))?;
    pool.install(|| prove_inner(elf_bytes, input, config))
} else {
    prove_inner(elf_bytes, input, config)
}
```

### 5.3 `ProverServiceConfig` 与 `ProverConfig` 对齐

**文件**：`poker_zkvm/src/service/mod.rs`（修改 \~30 行）— 已在 3.1 中包含 `rayon_threads` + `parallel_ccs_compile`，传递给 `ProverConfig`

### 5.4 性能基准测试

**文件**：`poker_zkvm/benches/prove_bench.rs`（新建，\~200 行）

**基准场景**：

1. `bench_prove_cold` — 冷启动 prove（无缓存）
2. `bench_prove_warm` — 热缓存 prove（同 ELF+input 二次）
3. `bench_ccs_compile_sequential` — 单线程 CCS 编译
4. `bench_ccs_compile_parallel_4` — 4 线程
5. `bench_ccs_compile_parallel_8` — 8 线程
6. `bench_partial_fold` — 分阶段 fold 延迟
7. `bench_final_fold` — 最终 fold + PCS opening 延迟
8. `bench_full_hand_elf` — 完整一手牌 ELF 端到端延迟

### 5.5 端到端性能日志

**文件**：`src/poker_zkvm_demo.rs`（修改，\~100 行）

新增 `--parallel-threads <n>` 参数 + `PerfSummary` 字段：

* `ccs_compile_ms`, `fold_loop_ms`, `pcs_opening_ms`

* `partial_fold_count`, `total_proof_ms`, `parallel_threads`

### 5.6 完整测试脚本

**文件**：`scripts/run_zkvm_e2e_full_test.sh`（新建，\~80 行）

```bash
#!/bin/bash
set -e
# 1. 启动 zkvm-server（后台，8 线程）
zchain zkvm-server --listen 127.0.0.1:9527 --batch-size 256 --parallel-threads 8 &
ZKVM_PID=$!; trap "kill $ZKVM_PID 2>/dev/null" EXIT
# 2. 等待 server 就绪
for i in {1..30}; do curl -sf http://127.0.0.1:9527/health && break; sleep 0.5; done
# 3. 启动 validator 节点（后台）
zchain node --role validator --data-dir /tmp/zkvm-e2e-data --rpc-listen 127.0.0.1:8545 &
NODE_PID=$!; trap "kill $NODE_PID 2>/dev/null" EXIT
# 4. 等待节点就绪
sleep 3
# 5. 运行完整 E2E 测试
zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --zkvm-server http://127.0.0.1:9527 \
    --parallel-threads 8 --log-file /tmp/zkvm_e2e_full.log
# 6. 输出性能摘要
echo "===== 性能摘要 ====="
grep -E "(ccs_compile|fold_loop|pcs_opening|total_proof|partial_fold)" /tmp/zkvm_e2e_full.log
```

**Phase 5 验证命令**：

```bash
cargo bench -p poker_zkvm --bench prove_bench
bash scripts/run_zkvm_e2e_full_test.sh
```

***

## 6. 假设与决策

### 6.1 关键 frozen 决策（无需再询问）

| 决策          | 选择                                              | 理由                                      |
| ----------- | ----------------------------------------------- | --------------------------------------- |
| ELF 范围      | 完整 texas\_poker 合约 ELF 化（手工 RV32I 汇编）           | 用户原话"以 ELF 形式加载运行"                      |
| 跳过 trait 重构 | 是 — 直接做 ELF 构造                                  | trait 重构风险高；手工汇编绕过 trait 直接 syscall     |
| 服务化方式       | 完整 HTTP server + 缓存层                            | 用户原话"类似服务器一样一直运行"                       |
| HTTP 框架     | axum + tokio（feature gated）                     | tokio 生态主流；feature gate 不污染 zchain 主二进制 |
| LCCCS 提交    | 复用 `poker_l1::offline::state::PartialCheckinTx` | 已实现，无需新建链上类型                            |
| partial 次数  | 2 次 partial + 1 次 final                         | 平衡真实性与复杂度                               |
| 并行策略        | rayon（CCS 编译 + sumcheck 内部）                     | 已在 workspace；不改 fold\_loop 顺序           |
| 评分逻辑        | 不使用 SLLI，两次 SLT + BNE 比较                        | test\_helpers.rs 无 SLLI 辅助，避免新增         |
| 输入布局        | 62 字节 = 52B deck + 5B P1 + 5B P2                | 修复原计划 52B 输入与 shuffle\_verify 排列校验的矛盾   |

### 6.2 风险与缓解

| 风险                                                               | 缓解                                                                |
| ---------------------------------------------------------------- | ----------------------------------------------------------------- |
| 手工汇编 ELF trace 步数超 600                                           | 降级为"最小完整流程"（init + 1 次 shuffle verify + showdown）；调整 batch\_size  |
| axum 引入导致编译时间增加                                                  | `service` feature 门控，非 service 用户无影响                              |
| `PartialProveState` 跨 fold\_step 共享 transcript 与 `fold_loop` 不一致 | 单元测试验证 partial\_fold N 次后 final\_fold 的 proof == 直接 prove 的 proof |
| rayon `pool.install()` 与 axum tokio runtime 冲突                   | 严格用 `tokio::task::spawn_blocking` 包装 prove 调用                     |
| 链上 PartialCheckinTx 提交失败                                         | 单元测试验证签名/构造后再上链；失败重试 3 次                                          |

### 6.3 明确不实现（跳过项）

1. texas\_poker trait 重构 — 手工汇编直接调用 syscall
2. Spartan/Groth16 压缩完整实现 — 已有 stub
3. CycleFold 递归压缩 — proof\_size\_limit=64KB
4. zkvm-server TLS / 认证 middleware — 仅本地 127.0.0.1 测试

***

## 7. 执行顺序与依赖

```
Phase 2（texas_poker 合约 ELF 化，~800 行）
  2.1 build_texas_poker_full_hand_elf（test_helpers.rs）
  2.2 ELF 加载执行测试（tests/texas_poker_full_hand.rs）
  ↓
Phase 3（zkvm 服务化，~900 行）— 可与 Phase 4 并行
  3.1 ProverService（service/mod.rs）
  3.2 HTTP server（service/http.rs）+ Cargo.toml axum 依赖
  3.3 类型定义（service/types.rs）
  3.4 客户端 SDK（service/client.rs）
  3.5 zkvm-server 子命令（src/zkvm_server.rs + main.rs）
  3.6 集成测试（tests/service_e2e.rs）
  ↓
Phase 4（链上 LCCCS 分阶段提交，~600 行）— 依赖 Phase 2 ELF
  4.1 PartialProveState API（prover/partial.rs）
  4.2 demo 集成（poker_zkvm_demo.rs 扩展）
  4.3 RPC demo 扩展（poker_rpc_demo.rs）
  4.4 端到端测试（poker_l1/tests/phase12_e2e_lcccs.rs）
  ↓
Phase 5（并行证明配置 + 性能测试，~400 行）— 依赖 Phase 3+4
  5.1 compile_trace_to_ccs 并行化（constraints/mod.rs）
  5.2 ProverConfig rayon_threads（prover/mod.rs）
  5.3 ProverServiceConfig 对齐（service/mod.rs）
  5.4 性能基准（benches/prove_bench.rs）
  5.5 端到端性能日志（poker_zkvm_demo.rs）
  5.6 完整测试脚本（scripts/run_zkvm_e2e_full_test.sh）
```

**总剩余工作量**：\~2700 行新代码 + \~200 行改动

***

## 8. 关键文件清单

### 新建文件（11 个）

| 文件                                          | Phase | 用途                    |
| ------------------------------------------- | ----- | --------------------- |
| `poker_zkvm/tests/texas_poker_full_hand.rs` | 2.2   | ELF 测试                |
| `poker_zkvm/src/service/mod.rs`             | 3.1   | ProverService         |
| `poker_zkvm/src/service/http.rs`            | 3.2   | HTTP server           |
| `poker_zkvm/src/service/types.rs`           | 3.3   | 请求/响应类型               |
| `poker_zkvm/src/service/client.rs`          | 3.4   | 客户端 SDK               |
| `poker_zkvm/tests/service_e2e.rs`           | 3.6   | 集成测试                  |
| `poker_zkvm/src/prover/partial.rs`          | 4.1   | PartialProveState API |
| `poker_l1/tests/phase12_e2e_lcccs.rs`       | 4.4   | 端到端测试                 |
| `poker_zkvm/benches/prove_bench.rs`         | 5.4   | 性能基准                  |
| `scripts/run_zkvm_e2e_full_test.sh`         | 5.6   | 端到端脚本                 |
| `src/zkvm_server.rs`                        | 3.5   | zkvm-server 子命令入口     |

### 修改文件（7 个）

| 文件                                  | Phase    | 改动                                                                    |
| ----------------------------------- | -------- | --------------------------------------------------------------------- |
| `poker_zkvm/src/test_helpers.rs`    | 2.1      | 追加 `build_texas_poker_full_hand_elf`                                  |
| `poker_zkvm/Cargo.toml`             | 3.2      | 新增 `service` feature + axum/tokio/reqwest/tower 依赖                    |
| `poker_zkvm/src/lib.rs`             | 3.1, 4.1 | 注册 `pub mod service;` + `pub mod prover::partial;`（在 prover/mod.rs 内） |
| `poker_zkvm/src/prover/mod.rs`      | 4.1, 5.2 | `pub mod partial;` + ProverConfig 新增 2 字段                             |
| `poker_zkvm/src/constraints/mod.rs` | 5.1      | `compile_trace_to_ccs` 并行化                                            |
| `src/main.rs`                       | 3.5      | 新增 `zkvm-server` 子命令分发                                                |
| `src/poker_zkvm_demo.rs`            | 4.2, 5.5 | LCCCS 分阶段 + 性能日志                                                      |
| `src/poker_rpc_demo.rs`             | 4.3      | partial\_checkin / checkin 提交辅助函数                                     |

***

## 9. 最终端到端验证

完整测试通过标准：

1. ✅ **Phase 2**：`cargo test -p poker_zkvm --test texas_poker_full_hand` 通过

   * 完整一手牌 ELF 执行，trace 长度 200-600 步

   * P1/P2 胜/平局三种结果正确

2. ✅ **Phase 3**：`cargo test -p poker_zkvm --test service_e2e` 通过

   * `curl http://127.0.0.1:9527/health` 返回 200

   * prove → verify 往返成功

   * proof\_cache 命中正确

3. ✅ **Phase 4**：`cargo test -p poker_l1 --test phase12_e2e_lcccs` 通过

   * `poker-zkvm-demo` 日志含：

     * `initial LCCCS 已构造`

     * `PartialCheckinTx #1 confirmed (folded_step_count=2)`

     * `PartialCheckinTx #2 confirmed (folded_step_count=4)`

     * `CheckinTx confirmed (final proof, NNNN bytes)`

   * 链上 `last_partial_fold == None` + `partial_checkin_count == 2`

   * 链上 `verify_proof_onchain` 通过

4. ✅ **Phase 5**：`cargo bench -p poker_zkvm --bench prove_bench` 通过

   * 8 线程 CCS 编译加速比 ≥ 3x

   * `bash scripts/run_zkvm_e2e_full_test.sh` 通过

   * 日志含完整 4 阶段耗时 + 最低延迟配置

***

## 10. 总结

本计划在 Phase 1（已完成，152 测试通过，cargo check 通过）基础上，明确 4 个 Phase 共 \~2700 行新代码 + \~200 行改动：

1. **Phase 2**（\~800 行）：手工 RV32I 汇编构造完整一手牌 ELF，覆盖 init → game\_state write/read → card encode/decode → shuffle\_verify → BLS12-381 → 牌型评估 → showdown。**跳过 trait 重构**，直接做 ELF 构造。**不使用 SLLI**，比较用两次 SLT + BNE。**输入 62 字节**（52B deck + 5B P1 + 5B P2），修复原计划逻辑矛盾。

2. **Phase 3**（\~900 行）：完整 HTTP server + 缓存层，引入 `axum` + `tokio` + `reqwest`（`service` feature 门控）。ProverService 含 proof\_cache + ipa\_pcs\_cache，axum 暴露 /prove /verify /health /stats /shutdown。

3. **Phase 4**（\~600 行）：**复用** `poker_l1::offline::state::PartialCheckinTx`（已实现），新增 `poker_zkvm::prover::partial::PartialProveState` API。demo 中实现 2 次 partial\_checkin + 1 次 final checkin 真实分阶段提交。

4. **Phase 5**（\~400 行）：rayon 并行化 `compile_trace_to_ccs`，ProverConfig 新增 `rayon_threads` + `parallel_ccs_compile`。性能基准测试 8 线程最低延迟。

5. **执行原则**：每个 Phase 独立可验证，前一个 Phase 通过后才进入下一个。Phase 3 与 Phase 4 可部分并行（不互相依赖）。

