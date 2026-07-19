# zkvm 端到端完整测试实施计划

> **目标**：构建完整的 zkvm 端到端测试，覆盖 4 个核心需求：
> 1. zkvm 类似服务器一样一直运行（完整 HTTP server + 缓存层）
> 2. texas_poker 合约以 ELF 形式（实际 zkvm 运行的方式）加载运行（完整合约 ELF 化）
> 3. 看到整体的一手流程：初始 LCCCS 注册到链上 → fold steps → 最终 proof 提交（PartialCheckinTx 真实分阶段）
> 4. 使用并行证明配置，测试实际最低证明延迟

---

## 1. 当前状态分析（Phase 1 探索结论）

### 1.1 已有基础（可直接复用）

| 组件 | 文件路径 | 状态 |
|------|---------|------|
| poker_zkvm prove() | `poker_zkvm/src/prover/mod.rs:940-1113` | ✅ 完整端到端 prover |
| poker_zkvm verify_production() | `poker_zkvm/src/verifier.rs:70-358` | ✅ 完整 soundness 链 |
| ProverConfig | `poker_zkvm/src/prover/mod.rs:58-95` | ✅ batch_size=256 默认 |
| default_ccs_registry() | `poker_zkvm/src/prover/mod.rs:1348-1358` | ✅ batch_size=3/256 两种 |
| PartialCheckinTx | `poker_l1/src/offline/state.rs` | ✅ 已定义 + execute_partial_checkin |
| CheckinTx | `poker_l1/src/transaction/mod.rs:100-300` | ✅ 完整 proof 提交路径 |
| LastPartialFold | `poker_l1/src/offline/state.rs` | ✅ 链上中间状态锚点 |
| GameContract.last_partial_fold | `poker_l1/src/vm/contracts/types.rs` | ✅ 链上字段已存在 |
| execute_checkin | `poker_l1/src/offline/state.rs` | ✅ 完整 proof 提交执行 |
| HypernovaVerifier | `poker_l1/src/offline/hypernova.rs:216-243` | ✅ 调用 verify_production |
| 5 个 sigma proof | `poker_protocol/src/zk_shuffle/` | ✅ ZKShuffle/Reveal/Reconstruct/Remask/Leave |
| 现有 demo | `src/poker_zkvm_demo.rs`（960 行） | ✅ 上一阶段完成（sigma + 牌型评估 ELF） |
| 现有 RPC 框架 | `src/poker_rpc_demo.rs`（531 行） | ✅ create_table/join/start_hand 4-tx 流程 |

### 1.2 关键缺口（必须新建）

| 缺口 | 影响 | 工作量预估 |
|------|------|----------|
| **zkvm 缺 BLS12-381 syscall** | texas_poker 合约依赖 hash_to_curve / scalar_mul / pairing，但 zkvm 只有 Bn254Pairing，无 BLS12-381 | ~600 行 |
| **zkvm 缺 game-specific syscall** | 合约需要 card encode/decode、shuffle verify 等高层操作 | ~400 行 |
| **zkvm 缺 ObjectDb mock syscall** | 合约依赖 ObjectDb 读写链上状态，需在 zkvm 中模拟 | ~300 行 |
| **texas_poker 合约耦合 ObjectDb** | 9452 行合约源码直接调用 ObjectDb，需重构为 syscall 接口 | ~1500 行 |
| **ELF 构造工具链不足** | 现有 build_poker_hand_eval_v2_elf 仅手工汇编，无法承载完整合约 | ~800 行 |
| **无 zkvm 服务化框架** | prove() 是同步函数，无 HTTP server / 缓存层 | ~1500 行 |
| **无分阶段提交集成** | PartialCheckinTx 已存在但未集成到 demo | ~500 行 |
| **并行证明未充分启用** | compile_trace_to_ccs 多 batch 未并行；RAYON_NUM_THREADS 未配置 | ~200 行 |

**总工作量预估**：~5800 行新代码 + 大量改造。

### 1.3 关键技术约束

- **zkvm 是 RV32I 32 位**：BLS12-381 G1/G2 point（48/96 字节 compressed）需多寄存器拼接
- **texas_poker 合约 9452 行**：dispatch 18 个方法，state_machine 2814 行，需逐步剥离
- **CCS 注册表是 batch_size=3 和 256 两种**：完整合约 ELF trace 可能 > 256 步，需要 CycleFold 压缩
- **fold_loop 数学上必须顺序**：每步依赖前一步的 folded LCCCS，但 sumcheck 内部可并行
- **rayon 与 tokio 调度冲突**：HTTP server 必须用 `tokio::task::spawn_blocking` 调用 prove()
- **链上 partial_checkin_count 默认上限 3**：分阶段提交最多 3 次 partial + 1 次 final

---

## 2. 实施分阶段（5 个 Phase）

考虑到工作量巨大，严格分 5 个 Phase，每个 Phase 独立可验证，前一个 Phase 测试通过才进入下一个。

### Phase 1 — zkvm syscall 扩展（基础层）

**目标**：为 zkvm 新增 BLS12-381 / game-specific / ObjectDb mock 三类 syscall，让合约可以在 zkvm 中调用外部功能。

**文件改动**：

#### 1.1 扩展 SyscallId 枚举
- **文件**：`poker_zkvm/src/syscalls/mod.rs`
- **改动**：在现有 `SyscallId` 枚举（已到 `Bn254Pairing = 0x0F`）后新增：
  ```rust
  Bls12381HashToCurve = 0x10,    // zkvm_bls_hash_to_curve(msg_ptr, msg_len, out_ptr)
  Bls12381ScalarMul = 0x11,      // zkvm_bls_scalar_mul(a_ptr, b_ptr, out_ptr)
  Bls12381G1Add = 0x12,          // zkvm_bls_g1_add(a_ptr, b_ptr, out_ptr)
  Bls12381G1Mul = 0x13,          // zkvm_bls_g1_mul(point_ptr, scalar_ptr, out_ptr)
  Bls12381Pairing = 0x14,        // zkvm_bls_pairing(a_ptr, b_ptr, c_ptr, d_ptr) -> bool
  Bls12381HashToScalar = 0x15,   // zkvm_bls_hash_to_scalar(msg_ptr, msg_len, out_ptr)
  GameStateRead = 0x20,          // zkvm_game_state_read(slot, out_ptr, out_len)
  GameStateWrite = 0x21,         // zkvm_game_state_write(slot, in_ptr, in_len)
  CardEncode = 0x30,             // zkvm_card_encode(rank, suit, out_ptr)
  CardDecode = 0x31,             // zkvm_card_decode(byte, out_rank_ptr, out_suit_ptr)
  ShuffleVerify = 0x32,          // zkvm_shuffle_verify(...)
  ```
- **为什么**：texas_poker 合约 `utils.rs` 直接调用 `G1Projective::hash_to_curve`、`scalar_mul` 等，这些 BLS12-381 操作无法在 RV32I 中直接执行，必须通过 syscall 委托给 host。

#### 1.2 实现 BLS12-381 syscall handlers
- **文件**：`poker_zkvm/src/syscalls/bls12381.rs`（新建，~300 行）
- **内容**：
  - `handle_bls_hash_to_curve`：调用 `blst::blst_hash_to_g1`
  - `handle_bls_scalar_mul`：调用 `BlsScalar::mul`
  - `handle_bls_g1_add`：调用 `G1Projective::add`
  - `handle_bls_g1_mul`：调用 `G1Projective::mul`
  - `handle_bls_pairing`：调用 `blst::blst_core_verify_pk_in_g1`（或 e(P1,Q1)·e(P2,Q2) 配对等式）
  - `handle_bls_hash_to_scalar`：调用 `hash_to_scalar`（与 `texas_poker/utils.rs` 一致）
- **依赖**：`blst` crate（BLS12-381 生产级实现，已在 poker_protocol 中使用）

#### 1.3 实现 game-specific syscall handlers
- **文件**：`poker_zkvm/src/syscalls/game.rs`（新建，~200 行）
- **内容**：
  - `handle_card_encode` / `handle_card_decode`：复用 `texas_poker/card.rs` 逻辑
  - `handle_shuffle_verify`：复用 `poker_protocol/zk_shuffle/shuffle_proof::verify`
- **为什么**：避免在 RV32I 中重新实现复杂密码学逻辑，通过 syscall 复用现有 Rust 实现。

#### 1.4 实现 GameState mock syscall
- **文件**：`poker_zkvm/src/syscalls/game_state.rs`（新建，~150 行）
- **内容**：
  - `GameState` 结构体（HashMap<slot, Vec<u8>>）存入 `StubHostState`
  - `handle_game_state_read` / `handle_game_state_write`：从 HashMap 读写
- **为什么**：合约依赖 ObjectDb 读写链上状态，在 zkvm 中用 in-memory HashMap 模拟。

#### 1.5 注册新 syscall 到 SyscallRegistry
- **文件**：`poker_zkvm/src/syscalls/mod.rs`
- **改动**：在 `SyscallRegistry::default()` 中注册所有新 handler

#### 1.6 单元测试
- **文件**：`poker_zkvm/src/syscalls/bls12381.rs` / `game.rs` / `game_state.rs` 内嵌 `#[cfg(test)]` 模块
- **测试覆盖**：
  - 每个 syscall handler 至少 2 个测试（正常 + 边界）
  - BLS12-381 syscall 与 poker_protocol 直接调用结果一致性校验

**Phase 1 验证**：
```bash
cargo test -p poker_zkvm --lib syscalls::bls12381
cargo test -p poker_zkvm --lib syscalls::game
cargo test -p poker_zkvm --lib syscalls::game_state
cargo check --workspace
```

---

### Phase 2 — texas_poker 合约 ELF 化（最复杂阶段）

**目标**：将 9452 行 texas_poker 合约核心逻辑重构为可通过 RV32I ELF 在 zkvm 中运行的形式，构造覆盖完整一手牌流程的 ELF。

**子阶段拆分**（按合约模块）：

#### 2.1 抽象合约与 syscall 接口
- **文件**：`poker_l1/src/vm/contracts/texas_poker/utils.rs`（修改，~200 行改动）
- **改动**：将所有直接调用 BLS12-381 / ObjectDb 的函数改为通过 trait 抽象：
  ```rust
  pub trait CryptoProvider {
      fn hash_to_curve(&self, msg: &[u8]) -> G1Projective;
      fn scalar_mul(&self, a: &BlsScalar, b: &BlsScalar) -> BlsScalar;
      fn g1_add(&self, a: &G1Projective, b: &G1Projective) -> G1Projective;
      fn g1_mul(&self, p: &G1Projective, s: &BlsScalar) -> G1Projective;
      fn pairing(&self, ...) -> bool;
      fn hash_to_scalar(&self, msg: &[u8]) -> BlsScalar;
  }
  
  pub trait StateProvider {
      fn read_state(&self, slot: u32) -> Vec<u8>;
      fn write_state(&mut self, slot: u32, data: &[u8]);
  }
  ```
- **实现两个 provider**：
  - `NativeCryptoProvider`（生产环境，直接调用 ark-bls12-381）
  - `ZkvmCryptoProvider`（zkvm 环境，通过 syscall 调用 host）
- **为什么**：保持合约源码单一代码库，通过 trait 切换执行环境。

#### 2.2 重构 state_machine.rs 使用 trait
- **文件**：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs`（修改，~800 行改动）
- **改动**：
  - 所有 `pub fn xxx(db: &mut ObjectDb, ...)` 改为 `pub fn xxx<C: CryptoProvider, S: StateProvider>(crypto: &C, state: &mut S, ...)`
  - 保留业务逻辑不变，仅替换底层调用
- **测试**：用 `NativeCryptoProvider` + `MockStateProvider` 跑现有所有测试，确保行为一致

#### 2.3 实现 ZkvmCryptoProvider / ZkvmStateProvider
- **文件**：`poker_l1/src/vm/contracts/texas_poker/zkvm_provider.rs`（新建，~400 行）
- **内容**：
  - `ZkvmCryptoProvider`：每个方法通过 `ecall` 触发对应 syscall
  - `ZkvmStateProvider`：通过 `GameStateRead/Write` syscall 读写
- **依赖**：Phase 1 的 syscall 实现

#### 2.4 构造完整一手牌 ELF
- **文件**：`poker_zkvm/src/test_helpers.rs`（扩展，~600 行新代码）
- **新增函数**：`build_texas_poker_full_hand_elf()` 
  - 包含一手牌完整生命周期：
    1. 初始化桌子（2 玩家、初始筹码）
    2. start_hand（设置 deck、shuffle_state）
    3. shuffle 验证（调用 Bls12381Pairing syscall）
    4. reveal_token 验证
    5. reconstruct deck
    6. 下注轮（preflop / flop / turn / river，简化为 check-call）
    7. showdown（评估牌型 + 比较胜者）
  - 实现方式：手工编写 RV32I 汇编（复用 test_helpers.rs 的 `addi/lw/sw/ecall` 等编码函数）
- **为什么**：用户明确要求"以 elf 的形式（实际 zkvm 运行的方式）加载运行"，手工汇编是最贴近实际 zkvm 运行的方式（无 RISC-V 工具链依赖）。

#### 2.5 ELF 校验 + 加载测试
- **文件**：`poker_zkvm/src/test_helpers.rs` 内嵌测试 + `poker_zkvm/tests/texas_poker_elf.rs`（新建）
- **测试**：
  - `validate_elf(&elf)` 通过
  - `execute_elf_with_config(&elf, ...)` 返回预期 output
  - trace 长度合理（< 1024 步，单 batch 证明）
  - 所有 syscall 调用成功

**Phase 2 验证**：
```bash
cargo test -p poker_l1 --lib vm::contracts::texas_poker  # 原有测试不退化
cargo test -p poker_zkvm --lib test_helpers  # 新 ELF 构造测试
cargo test -p poker_zkvm --test texas_poker_elf  # ELF 加载执行测试
cargo check --workspace
```

**Phase 2 风险**：
- 手工汇编编写完整一手牌 ELF 极其耗时，可能需要简化为"最小完整流程"（init + shuffle verify + showdown）
- state_machine.rs 2814 行重构风险高，需逐步替换并保留原测试

---

### Phase 3 — zkvm 服务化（HTTP server + 缓存层）

**目标**：实现 zkvm HTTP server，常驻运行，支持多客户端并发 prove 请求，缓存 CCS 注册表 + 复用 IpaPcs。

**文件改动**：

#### 3.1 ProverService 实现
- **文件**：`poker_zkvm/src/service/mod.rs`（新建，~500 行）
- **内容**：
  ```rust
  pub struct ProverService {
      ccs_registry: Arc<Vec<Ccs>>,           // 启动时构造，复用
      ipa_pcs_cache: Arc<RwLock<HashMap<usize, IpaPcs>>>,  // 按 n_vars 缓存
      request_counter: AtomicU64,
      config: ProverServiceConfig,
  }
  
  impl ProverService {
      pub fn new(config: ProverServiceConfig) -> Self;
      pub async fn prove(&self, req: ProveRequest) -> Result<ProveResponse, ProveError>;
      pub async fn verify(&self, req: VerifyRequest) -> Result<bool, ProveError>;
      pub fn stats(&self) -> ServiceStats;
  }
  ```
- **关键设计**：
  - `prove` 内部用 `tokio::task::spawn_blocking` 包装 `zkvm_prove`（避免阻塞 tokio runtime）
  - CCS 注册表启动时构造一次，所有请求复用
  - IpaPcs 按 `n_vars` 缓存（key = log2(num_vars)），避免每次 prove 重建
  - 并发请求通过 `Arc` 共享，无锁读 CCS / IpaPcs

#### 3.2 HTTP server 实现
- **文件**：`poker_zkvm/src/service/http.rs`（新建，~400 行）
- **依赖**：`axum` + `tokio` + `serde_json`
- **接口**：
  - `POST /prove` — body: `{ elf_hex, input_hex, config }` → `{ proof_hex, public_io, elapsed_ms }`
  - `POST /verify` — body: `{ proof_hex, public_io, ccs_registry_hash }` → `{ valid, elapsed_ms }`
  - `GET /health` → `{ status, uptime, request_count }`
  - `GET /stats` → `{ ccs_cache_size, ipa_pcs_cache_size, total_proofs, avg_latency_ms }`
- **启动**：`ProverService::serve(addr)` 启动 axum server，监听指定端口

#### 3.3 请求/响应类型定义
- **文件**：`poker_zkvm/src/service/types.rs`（新建，~200 行）
- **内容**：`ProveRequest` / `ProveResponse` / `VerifyRequest` / `VerifyResponse` / `ServiceStats` 等

#### 3.4 客户端 SDK
- **文件**：`poker_zkvm/src/service/client.rs`（新建，~200 行）
- **内容**：`ProverClient` 异步客户端，封装 HTTP 调用
- **为什么**：方便 demo 程序调用 zkvm server

#### 3.5 集成测试
- **文件**：`poker_zkvm/tests/service_e2e.rs`（新建，~200 行）
- **测试**：
  - 启动 server → 客户端发 prove 请求 → 收到 proof → 发 verify 请求 → 验证通过
  - 多客户端并发 prove 测试（4 并发）
  - 缓存命中测试（第二次 prove 同 ELF 应更快）

#### 3.6 新增 zchain 子命令 `zkvm-server`
- **文件**：`src/main.rs`（修改）
- **内容**：新增 `zchain zkvm-server --listen 127.0.0.1:9527` 子命令，启动 ProverService HTTP server
- **为什么**：用户要求"zkvm 类似服务器一样一直运行"，提供 CLI 启动入口

**Phase 3 验证**：
```bash
cargo test -p poker_zkvm --lib service
cargo test -p poker_zkvm --test service_e2e
# 启动 server
zchain zkvm-server --listen 127.0.0.1:9527 &
# 健康检查
curl http://127.0.0.1:9527/health
cargo check --workspace
```

---

### Phase 4 — 链上 LCCCS 分阶段提交集成

**目标**：实现真正的 PartialCheckinTx 分阶段提交，链下构建初始 LCCCS → 提交 partial proof 到链上 → 继续 fold → 最终 CheckinTx 提交完整 proof。

**文件改动**：

#### 4.1 扩展 poker_zkvm 支持分阶段 prove
- **文件**：`poker_zkvm/src/prover/mod.rs`（修改，~300 行新代码）
- **新增函数**：
  ```rust
  pub struct PartialProveState {
      pub ccs_ref: Ccs,
      pub initial_lcccs: Lcccs,
      pub initial_witness_commitment: IpaCommitment,
      pub ccccs_instances: Vec<Ccccs>,  // 待 fold 的剩余实例
      pub ccccs_commitments: Vec<IpaCommitment>,
      pub folded_step_count: u32,
      pub intermediate_commitment: Hash,
      pub transcript: Transcript,  // 续传状态
  }
  
  pub fn prove_partial_start(elf, input, config) -> Result<PartialProveState, ZkvmError>;
  pub fn prove_partial_fold(state: &mut PartialProveState, steps: usize) -> Result<PartialProof, ZkvmError>;
  pub fn prove_final_fold(state: PartialProveState) -> Result<HypernovaProof, ZkvmError>;
  ```
- **为什么**：现有 `prove()` 是一次性函数，无法分阶段。PartialProveState 保存中间状态，支持跨调用续传。

#### 4.2 构造 PartialCheckinTx 并提交
- **文件**：`src/poker_rpc_demo.rs`（扩展，~250 行新代码）
- **新增函数**：
  ```rust
  pub(crate) fn build_and_submit_partial_checkin(
      rpc: &str,
      game_id: ObjectID,
      partial_proof: &[u8],
      folded_step_count: u32,
      intermediate_commitment: Hash,
      ack_chain_partial: Vec<AckEntry>,
      scheme_id: u32,
  ) -> Result<Hash, String>;
  ```
- **流程**：
  1. 构造 `PartialCheckinTx`
  2. 签名（`proof_kind` = Zkvm）
  3. 通过 RPC `submit_tx` 提交
  4. `wait_for_block_with_tx` 等待确认
  5. 查询 `GameContract.last_partial_fold` 验证链上已更新

#### 4.3 构造最终 CheckinTx 提交完整 proof
- **文件**：`src/poker_rpc_demo.rs`（扩展，~150 行新代码）
- **新增函数**：
  ```rust
  pub(crate) fn build_and_submit_final_checkin(
      rpc: &str,
      game_id: ObjectID,
      final_proof: &[u8],
      public_io: &ZkPublicIo,
      ack_chain: Vec<AckEntry>,
      scheme_id: u32,
  ) -> Result<Hash, String>;
  ```
- **流程**：
  1. 构造 `CheckinTx`（`proof_kind` = Zkvm，与 partial 一致）
  2. 签名（包含 `proof_kind` 字段，grace period 后新签名）
  3. 通过 RPC `submit_tx` 提交
  4. 等待确认
  5. 查询 `GameContract.last_partial_fold` 应为 None（已 finalize）

#### 4.4 集成到 demo 主流程
- **文件**：`src/poker_zkvm_demo.rs`（扩展，~400 行新代码）
- **新增阶段**：
  ```rust
  // Phase F — LCCCS 分阶段提交
  // 1. 创建链上 GameContract（如已存在则复用）
  // 2. prove_partial_start → initial LCCCS
  // 3. 提交 PartialCheckinTx #1（folded_step_count=0, intermediate_commitment=initial）
  // 4. prove_partial_fold (fold 2 steps) → PartialProof
  // 5. 提交 PartialCheckinTx #2（folded_step_count=2）
  // 6. prove_final_fold → HypernovaProof
  // 7. 提交 CheckinTx（完整 proof）
  // 8. 验证链上 last_partial_fold = None + verify_proof_onchain 通过
  ```

#### 4.5 端到端测试
- **文件**：`poker_l1/tests/phase12_e2e_lcccs.rs`（新建，~200 行）
- **测试**：
  - 启动链节点
  - 创建 GameContract
  - 执行分阶段提交流程
  - 验证每步链上状态正确

**Phase 4 验证**：
```bash
cargo test -p poker_l1 --test phase12_e2e_lcccs
cargo check --workspace
# 端到端运行
zchain node --role validator ... &
zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_e2e.log
# 验证日志含 "PartialCheckinTx #1 confirmed" / "PartialCheckinTx #2 confirmed" / "CheckinTx confirmed"
```

---

### Phase 5 — 并行证明配置 + 性能测试

**目标**：启用所有可能的并行优化，测试实际最低证明延迟，输出完整性能报告。

**文件改动**：

#### 5.1 启用 compile_trace_to_ccs 多 batch 并行
- **文件**：`poker_zkvm/src/constraints/mod.rs`（修改，~100 行改动）
- **改动**：将 `compile_trace_to_ccs` 内的 batch 循环改为 `rayon::par_iter`：
  ```rust
  let ccs_instances: Vec<CcsInstance> = batches
      .par_iter()
      .map(|batch| compile_batch_to_ccs(batch, ccs_template))
      .collect::<Result<_, _>>()?;
  ```
- **为什么**：多 batch CCS 构造是独立的，可并行。Explore agent 确认这是当前未启用的优化点。

#### 5.2 配置 RAYON_NUM_THREADS
- **文件**：`poker_zkvm/src/service/mod.rs`（在 Phase 3 基础上扩展，~50 行）
- **改动**：ProverService 启动时根据 `num_cpus` 设置 `RAYON_NUM_THREADS`（默认 = num_cpus，可配置）
- **环境变量**：支持 `ZKVM_RAYON_THREADS` 覆盖

#### 5.3 扩展 ProverConfig 增加 parallel 字段
- **文件**：`poker_zkvm/src/prover/mod.rs`（修改，~80 行改动）
- **新增字段**：
  ```rust
  pub struct ProverConfig {
      // ... 现有字段
      /// rayon 线程数（None = 使用 RAYON_NUM_THREADS 环境变量或 num_cpus）
      pub rayon_threads: Option<usize>,
      /// CCS 编译是否并行（默认 true）
      pub parallel_ccs_compile: bool,
  }
  ```

#### 5.4 性能基准测试
- **文件**：`poker_zkvm/benches/prove_bench.rs`（新建，~200 行）
- **依赖**：`criterion` crate
- **基准**：
  - 单次 prove（不同 batch_size: 3 / 64 / 256 / 1024）
  - 单次 verify
  - 不同 RAYON_NUM_THREADS（1 / 2 / 4 / 8 / 16）
  - 缓存命中 vs 冷启动
- **输出**：HTML 报告 + JSON 数据

#### 5.5 端到端性能日志增强
- **文件**：`src/poker_zkvm_demo.rs`（扩展，~150 行改动）
- **新增 PerfSummary 字段**：
  ```rust
  pub struct PerfSummary {
      // ... 现有字段
      pub parallel_config: ParallelConfig,
      pub lcccs_stages: LcccsStagesTimings,
  }
  
  pub struct ParallelConfig {
      pub rayon_threads: usize,
      pub parallel_ccs_compile: bool,
      pub batch_size: usize,
      pub total_batches: usize,
      pub total_fold_steps: usize,
  }
  
  pub struct LcccsStagesTimings {
      pub initial_lcccs_construction_ms: f64,
      pub partial_checkin_1_submit_ms: f64,
      pub partial_fold_2_steps_ms: f64,
      pub partial_checkin_2_submit_ms: f64,
      pub final_fold_ms: f64,
      pub final_checkin_submit_ms: f64,
      pub onchain_verify_ms: f64,
  }
  ```

#### 5.6 完整端到端测试运行脚本
- **文件**：`scripts/run_zkvm_e2e_full_test.sh`（新建，~100 行 bash）
- **内容**：
  ```bash
  #!/bin/bash
  # 1. 启动链节点
  zchain node --role validator ... &
  # 2. 启动 zkvm server
  zchain zkvm-server --listen 127.0.0.1:9527 &
  # 3. 运行 demo（连接 zkvm server + 链 RPC）
  RAYON_NUM_THREADS=8 zchain poker-zkvm-demo \
    --rpc 127.0.0.1:8545 \
    --zkvm-server 127.0.0.1:9527 \
    --log-file /tmp/zkvm_e2e_full.log
  # 4. 输出性能报告
  cat /tmp/zkvm_e2e_full.log | tail -100
  ```

**Phase 5 验证**：
```bash
cargo bench -p poker_zkvm --bench prove_bench
cargo test -p poker_zkvm --lib service  # 服务化测试
bash scripts/run_zkvm_e2e_full_test.sh  # 端到端
# 验证日志含完整 4 个阶段的耗时 + 最低延迟配置
```

---

## 3. 假设与决策

### 3.1 关键假设

1. **BLS12-381 syscall 性能**：通过 syscall 委托给 host 比在 RV32I 中模拟快 100x+（合理假设，因 RV32I 是 32 位模拟）
2. **完整一手牌 ELF trace**：预估 500-1000 步，对应 2-4 个 batch（batch_size=256），3 个 fold steps
3. **proof 大小**：多 fold steps 后预估 ~245KB，需 Spartan 压缩至 64KB 上链
4. **zkvm server 单次 prove 延迟**：batch_size=256 + 8 线程，预估 5-15 秒（基于现有 demo 测时）
5. **链上 partial_checkin 提交延迟**：每个 block 500ms，partial_checkin_count=2 + final checkin = 3 个 block ≈ 1.5s

### 3.2 关键决策

| 决策 | 选项 | 理由 |
|------|------|------|
| BLS12-381 实现 | `blst` crate | 生产级、已在 poker_protocol 使用、性能最优 |
| HTTP 框架 | `axum` | tokio 生态主流、类型安全、中间件丰富 |
| ELF 构造方式 | 手工 RV32I 汇编 | 避免引入 RISC-V 工具链依赖，复用 test_helpers.rs 现有编码函数 |
| 合约重构策略 | trait 抽象 + 双 provider | 保持单一代码库，trait 切换 Native/Zkvm 环境 |
| 并行策略 | rayon（CCS 编译 + sumcheck 内部） | 不改 fold_loop 顺序（数学依赖），仅在独立步骤启用并行 |
| partial_checkin 次数 | 2 次 partial + 1 次 final | 平衡真实性与复杂度（默认上限 3） |

### 3.3 未选择的替代方案（记录）

- **替代 A：扩展现有 build_poker_hand_eval_v2_elf**（用户已否决）— 工作量小但不满足"完整合约 ELF 化"
- **替代 B：进程内常驻多轮 prove**（用户已否决）— 不满足"类似服务器"
- **替代 C：CheckinTx 一次性提交**（用户已否决）— 不满足"初始 LCCCS 注册到链上"
- **替代 D：RISC-V 工具链编译 Rust 源码为 ELF** — 工作量极大（需配置 riscv32i target + no_std 适配），且与现有手工汇编风格不一致

---

## 4. 风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| Phase 2 合约重构导致原有测试退化 | 高 | 保留 NativeCryptoProvider 跑原有测试，每步重构后立即验证 |
| 手工汇编完整一手牌 ELF 工作量超预期 | 高 | 可降级为"最小完整流程"（init + 1 次 shuffle verify + showdown） |
| BLS12-381 syscall 在 zkvm 中性能不佳 | 中 | benchmark 对比 Native vs Zkvm provider，必要时优化 syscall 批处理 |
| HTTP server 与 rayon 调度冲突 | 中 | 严格用 `spawn_blocking` 隔离 prove 调用 |
| PartialCheckinTx 链上验证失败 | 中 | 先在单元测试中验证签名/构造，再上链 |
| 链上 GameContract 状态不一致 | 中 | 每步查询链上状态，与预期对比 |

---

## 5. 验证步骤（总体）

### 5.1 每个 Phase 完成后验证

```bash
# Phase 1
cargo test -p poker_zkvm --lib syscalls::bls12381
cargo test -p poker_zkvm --lib syscalls::game
cargo test -p poker_zkvm --lib syscalls::game_state

# Phase 2
cargo test -p poker_l1 --lib vm::contracts::texas_poker  # 原有测试不退化
cargo test -p poker_zkvm --test texas_poker_elf

# Phase 3
cargo test -p poker_zkvm --test service_e2e
curl http://127.0.0.1:9527/health

# Phase 4
cargo test -p poker_l1 --test phase12_e2e_lcccs
zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_e2e.log

# Phase 5
cargo bench -p poker_zkvm --bench prove_bench
bash scripts/run_zkvm_e2e_full_test.sh
```

### 5.2 最终端到端验证

1. 启动链节点（`zchain node --role validator ...`）
2. 启动 zkvm server（`zchain zkvm-server --listen 127.0.0.1:9527`）
3. 运行完整 demo（`RAYON_NUM_THREADS=8 zchain poker-zkvm-demo --rpc ... --zkvm-server ... --log-file ...`）
4. 日志应包含：
   - ✅ Phase 1：所有 syscall 调用成功
   - ✅ Phase 2：完整一手牌 ELF 加载执行（trace ~500-1000 步）
   - ✅ Phase 3：zkvm server 接收 prove 请求 + 返回 proof + 缓存命中
   - ✅ Phase 4：PartialCheckinTx #1 confirmed / #2 confirmed / CheckinTx confirmed + 链上 verify 通过
   - ✅ Phase 5：并行证明配置（8 线程）+ 最低延迟报告
5. JSON 摘要写入日志末尾，包含完整 4 个阶段的耗时

---

## 6. 实施顺序与依赖

```
Phase 1 (syscall 扩展)
   ↓
Phase 2 (合约 ELF 化) — 依赖 Phase 1
   ↓
Phase 3 (服务化) — 可与 Phase 2 部分并行
   ↓
Phase 4 (链上分阶段提交) — 依赖 Phase 2 + Phase 3
   ↓
Phase 5 (并行 + 性能) — 依赖 Phase 4
```

**总工作量预估**：
- Phase 1：~1350 行（syscalls + 测试）
- Phase 2：~2600 行（trait 重构 + provider + ELF + 测试）
- Phase 3：~1500 行（service + http + client + 测试）
- Phase 4：~1000 行（partial prove + RPC + demo 集成）
- Phase 5：~600 行（并行 + bench + 脚本）
- **合计**：~7050 行新代码

**预估总耗时**：20-30 小时（基于现有代码库熟悉度）

---

## 7. 关键文件清单（待修改/新建）

### 新建文件
- `poker_zkvm/src/syscalls/bls12381.rs` — BLS12-381 syscall handlers
- `poker_zkvm/src/syscalls/game.rs` — game-specific syscall handlers
- `poker_zkvm/src/syscalls/game_state.rs` — GameState mock syscall
- `poker_l1/src/vm/contracts/texas_poker/zkvm_provider.rs` — ZkvmCryptoProvider / ZkvmStateProvider
- `poker_zkvm/src/service/mod.rs` — ProverService
- `poker_zkvm/src/service/http.rs` — HTTP server
- `poker_zkvm/src/service/types.rs` — 请求/响应类型
- `poker_zkvm/src/service/client.rs` — 客户端 SDK
- `poker_zkvm/tests/texas_poker_elf.rs` — ELF 加载测试
- `poker_zkvm/tests/service_e2e.rs` — 服务化集成测试
- `poker_l1/tests/phase12_e2e_lcccs.rs` — 链上分阶段测试
- `poker_zkvm/benches/prove_bench.rs` — 性能基准
- `scripts/run_zkvm_e2e_full_test.sh` — 端到端脚本

### 修改文件
- `poker_zkvm/src/syscalls/mod.rs` — 注册新 syscall
- `poker_l1/src/vm/contracts/texas_poker/utils.rs` — CryptoProvider / StateProvider trait
- `poker_l1/src/vm/contracts/texas_poker/state_machine.rs` — 重构使用 trait
- `poker_zkvm/src/test_helpers.rs` — 新增 build_texas_poker_full_hand_elf
- `poker_zkvm/src/prover/mod.rs` — 新增 PartialProveState + prove_partial_*
- `poker_zkvm/src/constraints/mod.rs` — compile_trace_to_ccs 并行化
- `src/poker_zkvm_demo.rs` — 集成 Phase F (LCCCS 分阶段)
- `src/poker_rpc_demo.rs` — 新增 build_and_submit_partial_checkin / final_checkin
- `src/main.rs` — 新增 `zkvm-server` 子命令

---

## 8. 总结

本计划严格按用户 4 个核心需求拆分为 5 个 Phase：

1. **Phase 1（syscall 扩展）** — 满足需求 #2 的基础设施（让合约能在 zkvm 中调用 BLS12-381 / 状态 / 卡牌操作）
2. **Phase 2（合约 ELF 化）** — 满足需求 #2（完整 texas_poker 合约以 ELF 形式运行）
3. **Phase 3（服务化）** — 满足需求 #1（zkvm 类似服务器一直运行，HTTP server + 缓存层）
4. **Phase 4（链上分阶段提交）** — 满足需求 #3（PartialCheckinTx 真实分阶段：初始 LCCCS → fold steps → 最终 proof）
5. **Phase 5（并行 + 性能）** — 满足需求 #4（compile_trace_to_ccs 并行 + RAYON_NUM_THREADS + benchmark）

每个 Phase 独立可验证，前一个 Phase 测试通过才进入下一个。总工作量预估 ~7