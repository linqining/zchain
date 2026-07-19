# zkvm E2E 完整测试 — 续执行计划

> **目标**（用户原话）：
> 1. zkvm 类似服务器一样一直运行
> 2. `/Users/mac/projects/zchain/poker_l1/src/vm/contracts/texas_poker` 以 ELF 形式（实际 zkvm 运行的方式）加载运行
> 3. 看到整体的一手流程，如初始的 lcccs 注册到链上，最后有些结束提交最终 proof
> 4. 使用并行证明配置，以测试实际最低证明延迟
>
> **本文件定位**：原计划 `/Users/mac/projects/zchain/.trae/documents/zkvm_e2e_full_test_plan.md` 的续执行版本，记录已完成进度 + 剩余工作，作为执行期间的活跃任务清单。

---

## 1. 当前状态（Phase 1 探索结论）

### 1.1 已完成（Phase 1.1 + 部分 1.2）

| 文件 | 状态 | 内容 |
|------|------|------|
| `poker_zkvm/Cargo.toml` | ✅ | 新增 `blstrs = { workspace = true }` + `pairing = { workspace = true }` |
| `poker_zkvm/src/syscalls/mod.rs` | ✅ 部分 | SyscallId 枚举扩展到 26 个 variant（0x01-0x0F + 0x10-0x15 BLS + 0x20-0x21 GameState + 0x30-0x32 Game），含 `sparse_index()` 映射、Debug impl、`from_u32` 解析、`TOTAL_COUNT=26` |
| `poker_zkvm/src/syscalls/gas.rs` | ✅ | 11 个新 gas 常量 + `syscall_gas()` match 26 arm 完整 |
| `poker_zkvm/src/syscalls/host.rs` | ✅ 部分 | `read_vm_bytes` / `write_vm_bytes` 改为 `pub(crate)`；`create_full_registry()` 仅注册 10 个旧 syscall |
| `poker_zkvm/src/syscalls/bls12381.rs` | ⚠️ 文件已创建（812 行），但 **`pub mod bls12381;` 未在 mod.rs 声明**，导致编译器实际未引入；6 个 syscall struct + 测试代码全部沉睡 |

**验证**：`cargo check -p poker_zkvm` 当前通过（因为 bls12381.rs 未被引入，所以编译器看不到它的内容；一旦添加 `pub mod bls12381;`，可能暴露未发现的编译错误）。

### 1.2 未完成（需立即执行）

| Phase | 任务 | 文件 | 工作量 |
|-------|------|------|--------|
| 1.2 修复 | 在 mod.rs 添加 `pub mod bls12381;` 声明 | `poker_zkvm/src/syscalls/mod.rs` | 1 行 + 修复编译错误（若有） |
| 1.3 | 实现 game-specific syscall handlers | `poker_zkvm/src/syscalls/game.rs`（新建） | ~250 行 |
| 1.4 | 实现 GameState mock syscall | `poker_zkvm/src/syscalls/game_state.rs`（新建） | ~180 行 |
| 1.5 | 注册 11 个新 syscall 到 `create_full_registry()` | `poker_zkvm/src/syscalls/host.rs` 或 `mod.rs` | ~30 行 |
| 1.6 | 单元测试 + `cargo check --workspace` 验证 | 多文件 | 修复 + 测试 |
| 2 | texas_poker 合约 ELF 化 | 多文件 | ~2600 行 |
| 3 | zkvm 服务化（HTTP server + 缓存层） | 多文件 | ~1500 行 |
| 4 | 链上 LCCCS 分阶段提交 | 多文件 | ~1000 行 |
| 5 | 并行证明配置 + 性能测试 | 多文件 | ~600 行 |

---

## 2. 执行计划（5 个 Phase 续执行）

### Phase 1 续 — Syscall 扩展收尾（~500 行 + 验证）

#### 1.2 修复：注册 bls12381 模块
- **文件**：`poker_zkvm/src/syscalls/mod.rs`
- **改动**：在 `pub mod host;` 之后添加 `pub mod bls12381;` 声明，并补全模块文档
- **验证**：`cargo check -p poker_zkvm` 必须通过；若有编译错误，逐个修复（重点关注 `gas_cost` 方法签名、`SyscallContext` 字段访问、`VmState` 内存接口）
- **回退**：若 bls12381.rs 存在严重设计缺陷无法快速修复，将其内容用 `#[cfg(any(test, feature = "test-helpers"))]` 包裹暂时 gate 起来，不阻塞后续 Phase

#### 1.3 实现 game-specific syscall handlers（`game.rs`，~250 行）
- **文件**：`poker_zkvm/src/syscalls/game.rs`（新建）
- **实现 3 个 Syscall**：
  1. `CardEncodeSyscall (0x30)` — ABI: `(rank: u8, suit: u8, out_ptr)`, 输出 1 字节 `suit * 13 + (rank - 2)`，复用 `texas_poker/card.rs::Card::to_index` 逻辑
  2. `CardDecodeSyscall (0x31)` — ABI: `(byte: u8, out_rank_ptr, out_suit_ptr)`, 反向操作，复用 `Card::from_index`
  3. `ShuffleVerifySyscall (0x32)` — ABI: `(proof_ptr, proof_len) -> bool`, MVP 实现：校验 proof 长度 + 返回 true（完整 ZkShuffle 验证推迟到 Phase 2，因依赖 poker_protocol/zk_shuffle 完整管线）
- **依赖**：`poker_zkvm/src/syscalls/host.rs::read_vm_bytes/write_vm_bytes`、`poker_zkvm/src/syscalls/gas.rs::syscall_gas`
- **测试**：每个 syscall 至少 2 个测试（正常 + 边界）
- **MVP 决策**：`ShuffleVerifySyscall` 实现为校验 proof 非空 + 长度合理即返回 true，因为完整 ZkShuffle 验证需要链下 sigma proof 全套上下文，不在 syscall 范围内

#### 1.4 实现 GameState mock syscall（`game_state.rs`，~180 行）
- **文件**：`poker_zkvm/src/syscalls/game_state.rs`（新建）
- **实现 2 个 Syscall**：
  1. `GameStateReadSyscall (0x20)` — ABI: `(slot: u32, out_ptr, out_len) -> actual_len`
  2. `GameStateWriteSyscall (0x21)` — ABI: `(slot: u32, in_ptr, in_len)`
- **状态存储**：在 `SyscallContext` 新增 `game_state: HashMap<u32, Vec<u8>>` 字段（参考 `host_state: Box<dyn ZkvmHostState>` 模式）
  - 修改 `SyscallContext::new()` 初始化空 HashMap
  - 修改 `SyscallContext::Debug` impl 跳过 HashMap 详细打印（仅打印 len）
- **slot 白名单**：复用 `host.rs::is_whitelisted_slot`（SLOT_GAME_STATE / SLOT_PLAYER_HANDS / SLOT_POT_AMOUNT / SLOT_CURRENT_TURN / SLOT_ACK_CHAIN）
- **测试**：write→read 往返、白名单外 slot 拒绝、超过 out_len 截断

#### 1.5 注册 11 个新 syscall 到 `create_full_registry()`
- **文件**：`poker_zkvm/src/syscalls/host.rs::create_full_registry()`（line 539-552）
- **改动**：在 `ReadStateSyscall` 注册后追加：
  ```rust
  // BLS12-381 syscall（E2E Phase 1）
  registry.register(Box::new(bls12381::Bls12381HashToCurveSyscall)).unwrap();
  registry.register(Box::new(bls12381::Bls12381ScalarMulSyscall)).unwrap();
  registry.register(Box::new(bls12381::Bls12381G1AddSyscall)).unwrap();
  registry.register(Box::new(bls12381::Bls12381G1MulSyscall)).unwrap();
  registry.register(Box::new(bls12381::Bls12381PairingSyscall)).unwrap();
  registry.register(Box::new(bls12381::Bls12381HashToScalarSyscall)).unwrap();
  // GameState mock syscall（E2E Phase 1）
  registry.register(Box::new(game_state::GameStateReadSyscall)).unwrap();
  registry.register(Box::new(game_state::GameStateWriteSyscall)).unwrap();
  // Game-specific syscall（E2E Phase 1）
  registry.register(Box::new(game::CardEncodeSyscall)).unwrap();
  registry.register(Box::new(game::CardDecodeSyscall)).unwrap();
  registry.register(Box::new(game::ShuffleVerifySyscall)).unwrap();
  ```
- **mod.rs 声明**：添加 `pub mod game;` 和 `pub mod game_state;`

#### 1.6 单元测试 + workspace 验证
- **测试命令**：
  ```bash
  cargo test -p poker_zkvm --lib syscalls::bls12381
  cargo test -p poker_zkvm --lib syscalls::game
  cargo test -p poker_zkvm --lib syscalls::game_state
  cargo test -p poker_zkvm --lib syscalls::mod  # 含 registry 测试
  cargo check --workspace
  ```
- **通过标准**：所有测试 PASS，workspace 编译无新增 error（pre-existing warnings 可接受）

---

### Phase 2 — texas_poker 合约 ELF 化（~2600 行）

> 详见原计划 `/Users/mac/projects/zchain/.trae/documents/zkvm_e2e_full_test_plan.md` §Phase 2。本节仅记录执行顺序与关键决策。

#### 2.1 抽象 CryptoProvider / StateProvider trait
- **文件**：`poker_l1/src/vm/contracts/texas_poker/utils.rs`（修改）
- **新增 trait**：
  ```rust
  pub trait CryptoProvider {
      fn hash_to_curve(&self, msg: &[u8]) -> G1Projective;
      fn scalar_mul(&self, a: &BlsScalar, b: &BlsScalar) -> BlsScalar;
      fn g1_add(&self, a: &G1Projective, b: &G1Projective) -> G1Projective;
      fn g1_mul(&self, p: &G1Projective, s: &BlsScalar) -> G1Projective;
      fn pairing(&self, a_g1: &[u8], b_g2: &[u8], c_g1: &[u8], d_g2: &[u8]) -> bool;
      fn hash_to_scalar(&self, msg: &[u8]) -> BlsScalar;
  }
  pub trait StateProvider {
      fn read_state(&self, slot: u32) -> Vec<u8>;
      fn write_state(&mut self, slot: u32, data: &[u8]);
  }
  ```
- **NativeCryptoProvider**：直接调用现有 `utils.rs` 函数（保持原有行为）
- **测试**：所有原有测试通过 `NativeCryptoProvider + MockStateProvider` 跑通

#### 2.2 重构 state_machine.rs 使用 trait
- **文件**：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs`
- **改动量**：~800 行（2814 行中的部分函数签名修改 + 调用点替换）
- **保守策略**：每次只重构一个 method，立即跑原有测试验证不退化

#### 2.3 实现 ZkvmCryptoProvider / ZkvmStateProvider
- **文件**：`poker_l1/src/vm/contracts/texas_poker/zkvm_provider.rs`（新建，~400 行）
- **实现**：每个方法通过 RV32I `ecall` 指令触发对应 syscall
- **依赖**：Phase 1 的 11 个新 syscall

#### 2.4 构造完整一手牌 ELF
- **文件**：`poker_zkvm/src/test_helpers.rs`（扩展，~600 行新代码）
- **新增函数**：`build_texas_poker_full_hand_elf()`
- **覆盖流程**：init → start_hand → shuffle verify → reveal_token → reconstruct → 4 个下注轮（简化 check-call）→ showdown
- **实现方式**：手工 RV32I 汇编（复用 test_helpers.rs 现有 `addi/lw/sw/ecall` 编码函数）

#### 2.5 ELF 校验 + 加载测试
- **文件**：`poker_zkvm/tests/texas_poker_elf.rs`（新建，~200 行）
- **测试**：ELF validate → execute → trace 长度合理 → 所有 syscall 调用成功

**Phase 2 验证**：
```bash
cargo test -p poker_l1 --lib vm::contracts::texas_poker  # 原有测试不退化
cargo test -p poker_zkvm --lib test_helpers
cargo test -p poker_zkvm --test texas_poker_elf
```

---

### Phase 3 — zkvm 服务化（HTTP server + 缓存层，~1500 行）

#### 3.1 ProverService 实现
- **文件**：`poker_zkvm/src/service/mod.rs`（新建，~500 行）
- **关键设计**：
  - `ccs_registry: Arc<Vec<Ccs>>` — 启动时构造，所有请求复用
  - `ipa_pcs_cache: Arc<RwLock<HashMap<usize, IpaPcs>>>` — 按 `n_vars` 缓存
  - `prove()` 内部用 `tokio::task::spawn_blocking` 包装 `zkvm_prove`

#### 3.2 HTTP server 实现
- **文件**：`poker_zkvm/src/service/http.rs`（新建，~400 行）
- **依赖**：`axum` + `tokio` + `serde_json`
- **接口**：
  - `POST /prove` → `{ elf_hex, input_hex, config }` → `{ proof_hex, public_io, elapsed_ms }`
  - `POST /verify` → `{ proof_hex, public_io, ccs_registry_hash }` → `{ valid, elapsed_ms }`
  - `GET /health` → `{ status, uptime, request_count }`
  - `GET /stats` → `{ ccs_cache_size, ipa_pcs_cache_size, total_proofs, avg_latency_ms }`

#### 3.3-3.6 类型定义 / 客户端 SDK / 集成测试 / `zkvm-server` 子命令
- 详见原计划 §Phase 3.3-3.6
- 新增 `zchain zkvm-server --listen 127.0.0.1:9527` 子命令

**Phase 3 验证**：
```bash
cargo test -p poker_zkvm --lib service
cargo test -p poker_zkvm --test service_e2e
curl http://127.0.0.1:9527/health
```

---

### Phase 4 — 链上 LCCCS 分阶段提交（~1000 行）

#### 4.1 扩展 poker_zkvm 支持分阶段 prove
- **文件**：`poker_zkvm/src/prover/mod.rs`（修改，~300 行新代码）
- **新增类型**：
  ```rust
  pub struct PartialProveState {
      pub ccs_ref: Ccs,
      pub initial_lcccs: Lcccs,
      pub ccccs_instances: Vec<Ccccs>,
      pub folded_step_count: u32,
      pub intermediate_commitment: Hash,
      pub transcript: Transcript,
  }
  pub fn prove_partial_start(...) -> Result<PartialProveState, ZkvmError>;
  pub fn prove_partial_fold(state: &mut PartialProveState, steps: usize) -> Result<PartialProof, ZkvmError>;
  pub fn prove_final_fold(state: PartialProveState) -> Result<HypernovaProof, ZkvmError>;
  ```

#### 4.2-4.4 构造 PartialCheckinTx / 最终 CheckinTx / demo 集成
- **文件**：`src/poker_rpc_demo.rs`（扩展，~400 行）+ `src/poker_zkvm_demo.rs`（扩展，~400 行）
- **流程**：
  1. `prove_partial_start` → initial LCCCS
  2. 提交 `PartialCheckinTx #1`（folded_step_count=0, intermediate_commitment=initial）
  3. `prove_partial_fold` (fold 2 steps) → PartialProof
  4. 提交 `PartialCheckinTx #2`（folded_step_count=2）
  5. `prove_final_fold` → HypernovaProof
  6. 提交 `CheckinTx`（完整 proof）
  7. 验证链上 `last_partial_fold = None` + verify_proof_onchain 通过

#### 4.5 端到端测试
- **文件**：`poker_l1/tests/phase12_e2e_lcccs.rs`（新建，~200 行）

**Phase 4 验证**：
```bash
cargo test -p poker_l1 --test phase12_e2e_lcccs
zchain poker-zkvm-demo --rpc 127.0.0.1:8545 --log-file /tmp/zkvm_e2e.log
# 日志应含 "PartialCheckinTx #1 confirmed" / "#2 confirmed" / "CheckinTx confirmed"
```

---

### Phase 5 — 并行证明配置 + 性能测试（~600 行）

#### 5.1 启用 compile_trace_to_ccs 多 batch 并行
- **文件**：`poker_zkvm/src/constraints/mod.rs`（修改，~100 行改动）
- **改动**：batch 循环改为 `rayon::par_iter`

#### 5.2-5.3 RAYON_NUM_THREADS 配置 + ProverConfig 扩展
- **文件**：`poker_zkvm/src/service/mod.rs` + `poker_zkvm/src/prover/mod.rs`（~130 行）
- **新增字段**：`rayon_threads: Option<usize>`、`parallel_ccs_compile: bool`

#### 5.4 性能基准测试
- **文件**：`poker_zkvm/benches/prove_bench.rs`（新建，~200 行）
- **基准**：不同 batch_size / RAYON_NUM_THREADS / 缓存命中 vs 冷启动

#### 5.5-5.6 端到端性能日志 + 完整测试脚本
- **文件**：`src/poker_zkvm_demo.rs`（扩展，~150 行）+ `scripts/run_zkvm_e2e_full_test.sh`（新建，~100 行）

**Phase 5 验证**：
```bash
cargo bench -p poker_zkvm --bench prove_bench
bash scripts/run_zkvm_e2e_full_test.sh
# 日志含完整 4 阶段耗时 + 最低延迟配置
```

---

## 3. 关键决策与假设

### 3.1 关键决策（继承自原计划）
| 决策 | 选项 | 理由 |
|------|------|------|
| BLS12-381 实现 | `blstrs` crate | 生产级、与 poker_l1 一致 |
| HTTP 框架 | `axum` | tokio 生态主流 |
| ELF 构造方式 | 手工 RV32I 汇编 | 避免 RISC-V 工具链依赖 |
| 合约重构策略 | trait 抽象 + 双 provider | 单一代码库，trait 切换环境 |
| 并行策略 | rayon（CCS 编译 + sumcheck 内部） | 不改 fold_loop 顺序 |
| partial_checkin 次数 | 2 次 partial + 1 次 final | 平衡真实性与复杂度 |
| ShuffleVerify MVP | 校验长度非空即返回 true | 完整 ZkShuffle 需 sigma proof 上下文，不在 syscall 范围 |

### 3.2 关键假设
1. bls12381.rs 内容正确性待 1.2 修复后通过编译验证
2. 完整一手牌 ELF trace 预估 500-1000 步，对应 2-4 batch（batch_size=256）
3. zkvm server 单次 prove 延迟预估 5-15 秒（batch_size=256 + 8 线程）
4. 链上 partial_checkin 提交延迟预估 1.5s（3 个 block × 500ms）

### 3.3 风险与缓解
| 风险 | 缓解 |
|------|------|
| bls12381.rs 添加 `pub mod` 后暴露编译错误 | 逐个修复；若严重缺陷则 `#[cfg(test)]` gate |
| state_machine.rs 2814 行重构导致测试退化 | 保留 NativeCryptoProvider 跑原测试，每步重构后立即验证 |
| 手工汇编完整一手牌 ELF 工作量超预期 | 可降级为"最小完整流程"（init + 1 次 shuffle verify + showdown） |
| HTTP server 与 rayon 调度冲突 | 严格用 `spawn_blocking` 隔离 prove 调用 |
| PartialCheckinTx 链上验证失败 | 先在单元测试中验证签名/构造，再上链 |

---

## 4. 执行顺序

```
Phase 1 续（1.2 修复 → 1.3 → 1.4 → 1.5 → 1.6）  ← 立即执行
   ↓
Phase 2（trait 重构 → ZkvmProvider → ELF → 测试）
   ↓
Phase 3（ProverService → HTTP server → 客户端 → zkvm-server 子命令）
   ↓
Phase 4（PartialProveState → PartialCheckinTx → CheckinTx → demo 集成）
   ↓
Phase 5（并行 CCS → RAYON 配置 → benchmark → 端到端脚本）
```

**总剩余工作量**：~6350 行（Phase 1 续 ~500 + Phase 2 ~2600 + Phase 3 ~1500 + Phase 4 ~1000 + Phase 5 ~600 + 修复 buffer）

---

## 5. 关键文件清单

### 新建文件（剩余）
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

### 修改文件（剩余）
- `poker_zkvm/src/syscalls/mod.rs` — 添加 `pub mod bls12381;` + `pub mod game;` + `pub mod game_state;` + 模块文档更新
- `poker_zkvm/src/syscalls/host.rs` — `create_full_registry()` 注册 11 个新 syscall
- `poker_zkvm/src/syscalls/mod.rs` — `SyscallContext` 新增 `game_state: HashMap<u32, Vec<u8>>` 字段
- `poker_l1/src/vm/contracts/texas_poker/utils.rs` — CryptoProvider / StateProvider trait
- `poker_l1/src/vm/contracts/texas_poker/state_machine.rs` — 重构使用 trait
- `poker_zkvm/src/test_helpers.rs` — 新增 build_texas_poker_full_hand_elf
- `poker_zkvm/src/prover/mod.rs` — 新增 PartialProveState + prove_partial_*
- `poker_zkvm/src/constraints/mod.rs` — compile_trace_to_ccs 并行化
- `src/poker_zkvm_demo.rs` — 集成 Phase F (LCCCS 分阶段)
- `src/poker_rpc_demo.rs` — 新增 build_and_submit_partial_checkin / final_checkin
- `src/main.rs` — 新增 `zkvm-server` 子命令

---

## 6. 最终端到端验证

完整测试通过标准：
1. ✅ Phase 1：`cargo test -p poker_zkvm --lib syscalls` 全部通过（含 26 个 syscall handler）
2. ✅ Phase 2：`cargo test -p poker_zkvm --test texas_poker_elf` 通过（完整一手牌 ELF 执行）
3. ✅ Phase 3：`curl http://127.0.0.1:9527/health` 返回 200 + `service_e2e` 测试通过
4. ✅ Phase 4：`poker-zkvm-demo` 日志含 `PartialCheckinTx #1/#2 confirmed` + `CheckinTx confirmed` + 链上 verify 通过
5. ✅ Phase 5：`prove_bench` 输出 8 线程配置下最低延迟 + `run_zkvm_e2e_full_test.sh` 通过

---

## 7. 总结

本计划在原计划基础上，明确：
1. **当前已完成**：Phase 1.1（SyscallId 扩展）+ Phase 1.2 部分（bls12381.rs 文件已写但未注册）
2. **立即执行**：Phase 1 续（1.2 修复 + 1.3-1.6）— ~500 行 + 验证
3. **后续 Phase 2-5**：~5850 行新代码 + 大量改造
4. **执行原则**：每个子阶段独立可验证，前一个测试通过才进入下一个；遇到风险点立即评估是否需要降级方案（如 ShuffleVerify MVP、最小完整流程 ELF）
