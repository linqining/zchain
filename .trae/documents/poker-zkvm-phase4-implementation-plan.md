# poker_zkvm Phase 4 实现计划 — ZKVM Syscall 完整实现

> **范围**：Phase 4 — 10 个 ZKVM syscall 的完整框架（SyscallId 枚举 + Syscall trait + gas 计费 + 10 个 host 实现 + Poseidon 哈希 + executor 集成）
> **遵循**：spec.md L193-265 / L637-669（v1.4 FROZEN）、tasks.md L98-119、checklist.md L97-115
> **用户决策**：添加 `ark-crypto-primitives` 依赖实现 Poseidon；全部 10 个 syscall；定义 `ZkvmHostState` trait
> **TDD 严格模式**：从基础开始，每步测试通过 + clippy clean 才进入下一步

## 一、Context

Phase 3 完成了 ZKVM ISA 执行引擎（RV32I 解码/执行 + 内存模型 + execute_elf 循环 + 3 个最小 syscall）。Phase 3 的 `HostContext` 仅实现了 `read_input`(0x01) / `commit_output`(0x02) / `panic`(0x08) 三个 syscall，使用简化的 match 分派。

Phase 4 需要将 syscall 系统扩展为完整的 10 个，引入 `Syscall` trait 抽象、gas 计费、Poseidon 哈希、ECDSA 验证等能力。spec 明确要求 `SyscallId` 枚举 + `Syscall` trait（`id()` / `host_execute()` / `gas_cost()`）+ `ZKVM_ABI_VERSION = 1`。

**关键发现**：
- `poker_protocol::crypto::poseidon` 不存在 — 需引入 `ark-crypto-primitives` 0.6.0 自行实现
- `poker_protocol::vrf` 不存在 — `get_randomness` 的 seed 通过 `ZkvmExecutionConfig` 传入
- `PokerL1Context` 无 state slot 字段 — 定义 `ZkvmHostState` trait，Phase 4 提供 stub 实现
- `secp256k1` 已在 workspace deps 但未加入 poker_zkvm
- `sha2` 已在 poker_zkvm deps 中
- BN254 Fr 无内置 Poseidon 默认参数 — 用 `find_poseidon_ark_and_mds` 生成（alpha=5, rate=2, 8 full + 56 partial rounds）

## 二、Current State Analysis

### 已就绪产物

| 文件 | 状态 | 说明 |
|------|------|------|
| `poker_zkvm/src/syscalls/mod.rs` | 8 行注释桩 | Phase 4 主战场 |
| `poker_zkvm/src/isa/executor.rs` | ✅ Phase 3 完成 | `HostContext` 有 3 syscall match 分派，需迁移 |
| `poker_zkvm/src/isa/state.rs` | ✅ Phase 3 完成 | `VmState` 提供 `read/write_memory_byte/word` + `read/write_register` |
| `poker_zkvm/src/field.rs` | ✅ Phase 1 完成 | `ZkvmField` trait + `Bn254ScalarField`（基于 `ark_bn254::Fr`） |
| `poker_zkvm/src/error.rs` | ✅ FROZEN | 18 variants，Phase 4 可用：`InvalidSlot` / `Other` / `OutOfMemory` / `UninitializedRead` / `UnalignedAccess` |
| `poker_zkvm/Cargo.toml` | 需更新 | 添加 `ark-crypto-primitives` + `secp256k1` |

### 依赖关系

- `ark-crypto-primitives = { version = "0.6.0", default-features = false, features = ["crh", "std"] }` — Poseidon sponge
- `secp256k1 = { workspace = true }` — ECDSA 验证
- `sha2` — 已在 deps 中
- `ark-bn254` — 已在 deps 中（Fr 类型）

## 三、Proposed Changes

### 文件结构

```
poker_zkvm/src/syscalls/
├── mod.rs       — SyscallId, Syscall trait, SyscallContext, ZkvmHostState, ZKVM_ABI_VERSION, SyscallRegistry
├── gas.rs       — Gas 常量 + syscall_gas 函数
├── poseidon.rs  — Poseidon 哈希封装（BN254 Fr）
├── host.rs      — 10 个 Syscall struct 实现
└── state.rs     — ZkvmHostState trait + StubHostState 默认实现
```

---

### Step 0 — 添加依赖

**文件**：`poker_zkvm/Cargo.toml` + workspace `Cargo.toml`

- workspace `Cargo.toml` `[workspace.dependencies]` 添加：
  ```toml
  ark-crypto-primitives = { version = "0.6.0", default-features = false, features = ["crh", "std"] }
  ```
- `poker_zkvm/Cargo.toml` `[dependencies]` 添加：
  ```toml
  ark-crypto-primitives = { workspace = true }
  secp256k1 = { workspace = true }
  ```

**验证**：`cargo build -p poker_zkvm` 编译通过。

---

### Step 1 — SyscallId 枚举 + ZKVM_ABI_VERSION

**文件**：`poker_zkvm/src/syscalls/mod.rs`（重写注释桩）

```rust
/// ZKVM ABI 版本号（spec L210-215）。
pub const ZKVM_ABI_VERSION: u32 = 1;

/// Syscall ID 枚举（spec L196-206，10 个 syscall）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SyscallId {
    ReadInput = 0x01,
    CommitOutput = 0x02,
    Poseidon = 0x03,
    Sha256 = 0x04,
    EcdsaVerify = 0x05,
    EmitEvent = 0x06,
    Log = 0x07,
    Panic = 0x08,
    GetRandomness = 0x09,
    ReadState = 0x0A,
}

impl SyscallId {
    pub fn from_u32(id: u32) -> Result<Self, ZkvmError> { ... }
}
```

**测试**（~6 个）：
- `from_u32` 全部 10 个 ID 正确映射
- `from_u32` 非法 ID（0x00, 0x0B, 0xFF）返回 `Other`
- `ZKVM_ABI_VERSION == 1`
- `SyscallId::ReadInput as u32 == 0x01`
- 枚举 Debug/Clone/PartialEq/Eq 可用

---

### Step 2 — Gas 计费

**文件**：`poker_zkvm/src/syscalls/gas.rs`

```rust
// Gas 常量（spec L646/653/660/669 + 对齐 poker_l1 gas_table.rs）
pub const GAS_ZKVM_READ_INPUT_BASE: u64 = 10;
pub const GAS_ZKVM_COMMIT_OUTPUT_BASE: u64 = 10;
pub const GAS_ZKVM_POSEIDON_BASE: u64 = 100;
pub const GAS_ZKVM_POSEIDON_PER_BLOCK: u64 = 50;  // per 32-byte block
pub const GAS_ZKVM_SHA256_PER_BYTE: u64 = 1;
pub const GAS_ZKVM_ECDSA_VERIFY: u64 = 100_000;   // spec L660
pub const GAS_ZKVM_EMIT_EVENT_BASE: u64 = 10;
pub const GAS_ZKVM_EMIT_EVENT_PER_BYTE: u64 = 1;
pub const GAS_ZKVM_LOG_BASE: u64 = 10;
pub const GAS_ZKVM_LOG_PER_BYTE: u64 = 1;
pub const GAS_ZKVM_PANIC: u64 = 10;
pub const GAS_ZKVM_GET_RANDOMNESS: u64 = 100;
pub const GAS_ZKVM_READ_STATE_PER_SLOT: u64 = 50;

/// Syscall gas 参数（从寄存器读取后传入）。
pub struct SyscallGasArgs {
    pub input_len: u32,  // read_input / commit_output / poseidon / sha256 / emit_event / log / panic
    pub num_slots: u32,  // read_state
}

pub fn syscall_gas(id: SyscallId, args: &SyscallGasArgs) -> u64 { ... }
```

**测试**（~8 个）：
- 各 syscall gas 计算正确（含 PER_BYTE / PER_BLOCK 乘法）
- `GAS_ZKVM_ECDSA_VERIFY == 100_000`
- 边界：input_len=0

---

### Step 3 — Poseidon 哈希封装

**文件**：`poker_zkvm/src/syscalls/poseidon.rs`

使用 `ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds` 生成 BN254 Fr 参数（alpha=5, rate=2, full_rounds=8, partial_rounds=56），封装为：

```rust
/// Poseidon 哈希单次输出（BN254 Fr）。
pub fn poseidon_hash(inputs: &[Fr]) -> Fr { ... }

/// Poseidon 哈希任意长度字节输入 → Fr。
/// 将 bytes 按 31 字节分块转为 Fr 元素，absorb 后 squeeze 1 个 Fr。
pub fn poseidon_hash_bytes(input: &[u8]) -> Fr { ... }

/// Poseidon 2-to-1 压缩（Merkle tree 用）。
pub fn poseidon_compress(left: &Fr, right: &Fr) -> Fr { ... }
```

**设计要点**：
- `PoseidonConfig` 通过 `once_cell::sync::Lazy` 或函数内 `lazy` 初始化（避免每次调用重新生成参数）
- 无 `once_cell` 依赖时用 `std::sync::OnceLock`（std 1.70+）
- `poseidon_hash_bytes`：bytes → Fr chunks（每 31 字节一个 Fr，大端序），absorb 全部，squeeze 1 个 Fr

**测试**（~6 个）：
- `poseidon_hash(&[Fr::from(1u64), Fr::from(2u64)])` 确定性（相同输入相同输出）
- `poseidon_hash` 不同输入不同输出
- `poseidon_hash_bytes(b"hello")` 确定性
- `poseidon_hash_bytes(b"")` 不 panic
- `poseidon_compress` 确定性 + 交换律不成立（left≠right 时结果不同）
- 大输入（1000 字节）不 panic

---

### Step 4 — SyscallContext + ZkvmHostState + Syscall trait

**文件**：`poker_zkvm/src/syscalls/state.rs` + `poker_zkvm/src/syscalls/mod.rs`

#### ZkvmHostState trait（`syscalls/state.rs`）

```rust
/// Host 状态读取 trait（read_state syscall 用）。
pub trait ZkvmHostState: std::fmt::Debug {
    fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError>;
}

/// 默认 stub 实现（无状态源时返回 Other 错误）。
#[derive(Debug, Clone, Default)]
pub struct StubHostState;

impl ZkvmHostState for StubHostState {
    fn read_slot(&self, slot: u32) -> Result<Vec<u8>, ZkvmError> {
        Err(ZkvmError::Other(format!("read_state: stub host state, slot {slot} not available")))
    }
}
```

#### SyscallContext（`syscalls/mod.rs`）

```rust
/// Syscall 执行上下文 — 持有 host 侧状态。
pub struct SyscallContext {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub events: Vec<Fr>,           // event_hash 列表
    pub logs: Vec<Vec<u8>>,        // log 消息列表
    pub halted: bool,
    pub step_index: u64,           // 当前步序号（emit_event 绑定用）
    pub randomness_seed: Fr,       // get_randomness 派生用
    pub initial_commitment: Fr,    // get_randomness 派生用
    pub final_commitment: Fr,      // get_randomness 派生用
    pub randomness_counter: u64,   // get_randomness 调用计数器
    pub host_state: Box<dyn ZkvmHostState>,
}
```

#### Syscall trait（`syscalls/mod.rs`）

```rust
/// Syscall trait（spec Task 4.1.2）。
pub trait Syscall: std::fmt::Debug + Send + Sync {
    fn id(&self) -> SyscallId;
    fn host_execute(&self, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError>;
    fn gas_cost(&self, state: &VmState) -> u64;
}
```

#### SyscallRegistry（`syscalls/mod.rs`）

```rust
/// Syscall 注册表 — 按 SyscallId 分派到对应实现。
pub struct SyscallRegistry {
    syscalls: Vec<Box<dyn Syscall>>,  // index = SyscallId as usize - 1
}

impl SyscallRegistry {
    pub fn new() -> Self { ... }  // 注册全部 10 个 syscall
    pub fn dispatch(&self, id: u32, ctx: &mut SyscallContext, state: &mut VmState) -> Result<(), ZkvmError> { ... }
}
```

**测试**（~6 个）：
- `SyscallContext::new()` 默认值正确
- `StubHostState::read_slot` 返回错误
- `SyscallRegistry::new()` 注册 10 个 syscall
- `SyscallRegistry::dispatch` 非法 ID 返回错误
- `ZKVM_ABI_VERSION` 在 SyscallContext 中可访问

---

### Step 5 — 10 个 Host 实现（TDD）

**文件**：`poker_zkvm/src/syscalls/host.rs`

每个 syscall 为一个 struct，实现 `Syscall` trait。ABI：a0-a6 寄存器传参，a0 寄存器返回值。

#### 5.1 简单 syscall（4 个，已部分在 Phase 3 实现）

| Syscall | ABI (a7=ID) | 行为 | 测试数 |
|---------|-------------|------|--------|
| `ReadInput` (0x01) | a0=ptr, a1=len | 将 ctx.input 写入 VM 内存 [ptr, ptr+len)，设 a0=ptr, a1=actual_len | 3 |
| `CommitOutput` (0x02) | a0=ptr, a1=len | 从 VM 内存 [a0, a0+a1) 读入 ctx.output，halt=true | 3 |
| `Panic` (0x08) | a0=ptr, a1=len | 从 VM 内存读消息，返回 `Err(Other("zkvm_panic: {msg}"))` | 2 |
| `Log` (0x07) | a0=ptr, a1=len | 从 VM 内存读消息，存入 ctx.logs | 2 |

**Phase 3 → Phase 4 ABI 变更**：`ReadInput` 从"简化 ABI（不读 a0/a1，直接写 INPUT_BUFFER_ADDR）"升级为"标准 ABI（读 a0=ptr, a1=len，写入 [a0, a0+len)）"。向后兼容：若 a0=0 则用 INPUT_BUFFER_ADDR。

#### 5.2 哈希 syscall（2 个）

| Syscall | ABI | 行为 | 测试数 |
|---------|-----|------|--------|
| `Sha256` (0x04) | a0=ptr, a1=len, a2=out_ptr | SHA-256 哈希 [a0, a0+a1)，32 字节结果写入 [out_ptr, out_ptr+32) | 3 |
| `Poseidon` (0x03) | a0=ptr, a1=len, a2=out_ptr | Poseidon 哈希 [a0, a0+a1)，32 字节 Fr 序列化写入 [out_ptr, out_ptr+32) | 3 |

#### 5.3 复杂 syscall（4 个）

| Syscall | ABI | 行为 | 测试数 |
|---------|-----|------|--------|
| `EcdsaVerify` (0x05) | a0=msg_ptr, a1=msg_len, a2=sig_ptr, a3=pubkey_ptr | secp256k1 验证，a0=1(成功)/0(失败) | 4 |
| `EmitEvent` (0x06) | a0=ptr, a1=len | `event_hash = Poseidon(poseidon_hash_bytes(content) || Fr::from(step_index))`，存入 ctx.events | 3 |
| `GetRandomness` (0x09) | a0=out_ptr | `output = Poseidon(seed || initial_commitment || final_commitment || Fr::from(counter))`，32 字节写入 [out_ptr, out_ptr+32)，counter++ | 3 |
| `ReadState` (0x0A) | a0=slot, a1=out_ptr | 白名单校验（0x01-0x05），从 ctx.host_state.read_slot(slot) 读值写入 [out_ptr, out_ptr+len) | 4 |

**ECDSA 实现**：
- 消息：`[msg_ptr, msg_ptr+msg_len)` 字节
- 签名：64 字节 DER 或 64 字节 compact（r||s）— 使用 `secp256k1::Message::from_digest` + `Signature::from_compact`
- 公钥：33 字节 compressed 或 65 字节 uncompressed — 使用 `PublicKey::from_slice`
- 返回 `a0 = 1`（验证成功）或 `a0 = 0`（验证失败），**不返回错误**（spec 要求返回 bool）

**EmitEvent 实现**：
```rust
let content = read_vm_bytes(state, a0, a1)?;
let content_hash = poseidon_hash_bytes(&content);
let event_hash = poseidon_hash(&[content_hash, Fr::from(ctx.step_index)]);
ctx.events.push(event_hash);
```

**GetRandomness 实现**：
```rust
let output = poseidon_hash(&[
    ctx.randomness_seed,
    ctx.initial_commitment,
    ctx.final_commitment,
    Fr::from(ctx.randomness_counter),
]);
ctx.randomness_counter += 1;
write_vm_bytes(state, a0, &output.to_bytes())?;
```

**ReadState 实现**：
```rust
let slot = state.read_register(REG_A0);
let out_ptr = state.read_register(REG_A1);
if !is_whitelisted_slot(slot) {
    return Err(ZkvmError::InvalidSlot(slot));
}
let value = ctx.host_state.read_slot(slot)?;
write_vm_bytes(state, out_ptr, &value)?;
```

**slot 白名单常量**：
```rust
pub const SLOT_GAME_STATE: u32 = 0x01;
pub const SLOT_PLAYER_HANDS: u32 = 0x02;
pub const SLOT_POT_AMOUNT: u32 = 0x03;
pub const SLOT_CURRENT_TURN: u32 = 0x04;
pub const SLOT_ACK_CHAIN: u32 = 0x05;
```

**测试汇总**：~30 个测试（每个 syscall 2-4 个 + gas 计算覆盖）

---

### Step 6 — Executor 迁移 + execute_elf_with_config

**文件**：`poker_zkvm/src/isa/executor.rs`

#### 6.1 ZkvmExecutionConfig

```rust
pub struct ZkvmExecutionConfig {
    pub input: Vec<u8>,
    pub randomness_seed: Fr,
    pub initial_commitment: Fr,
    pub final_commitment: Fr,
    pub host_state: Box<dyn ZkvmHostState>,
}

impl Default for ZkvmExecutionConfig {
    fn default() -> Self {
        Self {
            input: Vec::new(),
            randomness_seed: Fr::zero(),
            initial_commitment: Fr::zero(),
            final_commitment: Fr::zero(),
            host_state: Box::new(StubHostState),
        }
    }
}
```

#### 6.2 迁移 HostContext → SyscallRegistry

- 删除 `HostContext` struct
- `execute_elf_with_limits` 改为接受 `ZkvmExecutionConfig`
- 循环中 ECALL 分派改为 `registry.dispatch(syscall_id, &mut ctx, &mut state)`
- `step_index` 在每步更新到 `ctx.step_index`
- `ExecuteResult` 新增 `events: Vec<Fr>` 和 `logs: Vec<Vec<u8>>` 字段

#### 6.3 API 变更

```rust
// 保留旧 API（向后兼容）
pub fn execute_elf(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError> {
    let config = ZkvmExecutionConfig { input: input.to_vec(), ..Default::default() };
    execute_elf_with_config(elf_bytes, config)
}

// 新 API
pub fn execute_elf_with_config(elf_bytes: &[u8], config: ZkvmExecutionConfig) -> Result<ExecuteResult, ZkvmError> {
    execute_elf_with_limits_and_config(elf_bytes, config, MAX_ZKVM_TRACE_STEPS, MAX_TRACE_HOST_MEMORY)
}

pub fn execute_elf_with_limits_and_config(
    elf_bytes: &[u8],
    config: ZkvmExecutionConfig,
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> { ... }
```

#### 6.4 更新现有 8 个 executor 测试

- `test_execute_elf_minimal_halt` — 适配新 ABI（ReadInput 标准化）
- `test_execute_elf_read_input_commit_output_echo` — 适配新 ABI
- 其余 6 个测试基本不变（不涉及 syscall ABI 变更的）

#### 6.5 更新 cargo-zkvm `cmd_run`

- 调用 `execute_elf`（旧 API 仍可用）
- 输出增加 events 数量

**验证**：
```bash
cargo test -p poker_zkvm --lib syscalls    # ~50 tests
cargo test -p poker_zkvm --lib isa::executor  # 8 existing + new
cargo test -p poker_zkvm                       # full crate ~296 tests
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

---

### Step 7 — 文档 + alternatives.md

**文件**：`poker_zkvm/docs/alternatives.md`

在 `## 待补充` 之前插入 Phase 4 章节，记录：
- Poseidon 实现（ark-crypto-primitives vs 自实现 vs stub）
- Syscall trait vs match 分派
- ZkvmHostState trait vs 扩展 PokerL1Context
- Gas 计费独立函数 vs trait 方法
- SyscallContext vs 散落参数
- ECDSA 签名格式（compact vs DER）
- 等 ~8 项决策

---

## 四、Assumptions & Decisions

1. **Poseidon 参数**：alpha=5（BN254 p-1 不被 5 整除），rate=2，capacity=1，8 full rounds + 56 partial rounds（对齐 BLS12-381 默认参数，field size 接近）
2. **Poseidon 参数生成**：用 `find_poseidon_ark_and_mds::<Fr>` 一次性生成，缓存在 `OnceLock<PoseidonConfig<Fr>>` 中
3. **ReadInput ABI 升级**：Phase 3 简化 ABI（不读 a0/a1）→ Phase 4 标准 ABI（a0=ptr, a1=len）。若 a0=0 则回退到 INPUT_BUFFER_ADDR（向后兼容）
4. **EcdsaVerify 返回值**：验证成功 a0=1，失败 a0=0（不返回 Err，spec 要求 bool 返回）
5. **ECDSA 签名格式**：64 字节 compact（r||s），pubkey 33 字节 compressed（与 poker_l1 对齐）
6. **GetRandomness seed 来源**：通过 `ZkvmExecutionConfig` 传入，Phase 4 不集成 VRF（VRF 模块不存在）
7. **ReadState Merkle 绑定**：Phase 4 仅实现 host 侧读取（slot 白名单 + 值返回），Merkle 证明验证是 Phase 5+ 电路侧职责
8. **gas_cost 是 trait 方法**：读寄存器估算 gas，但 executor 循环中不实际扣 gas（gas 计费是 on-chain 概念，host 执行不限制）
9. **`#![deny(missing_docs)]` + `#![deny(unsafe_code)]`**：所有公开项需 `///` doc，无 unsafe
10. **Step 5 分批实现**：5.1（4 简单）→ 5.2（2 哈希）→ 5.3（4 复杂），每批 TDD 验证

## 五、验证计划

### 每步完成后

```bash
cargo test -p poker_zkvm --lib syscalls     # syscalls 模块测试
cargo test -p poker_zkvm --lib isa::executor  # executor 不回归
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

### Phase 4 全部完成后

```bash
cargo test -p poker_zkvm                       # ~296 测试通过
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build --workspace
cargo build -p poker_zkvm --release
cargo build -p poker_zkvm --bin cargo-zkvm
```

### 测试覆盖汇总

| 步骤 | 预估测试数 | 累计 |
|------|-----------|------|
| Step 1（SyscallId） | +6 | ~252 |
| Step 2（Gas） | +8 | ~260 |
| Step 3（Poseidon） | +6 | ~266 |
| Step 4（Context+Trait） | +6 | ~272 |
| Step 5（10 Host 实现） | +30 | ~302 |
| Step 6（Executor 迁移） | +8（更新+新增） | ~310 |
| Step 7（文档） | 0 | ~310 |
| **合计** | **+64 新增** | **~246 → ~310** |

## 六、执行顺序（TDD 严格模式）

1. **Step 0**：添加依赖 → `cargo build` 通过
2. **Step 1**：SyscallId + ZKVM_ABI_VERSION → 6 测试通过
3. **Step 2**：Gas 常量 + syscall_gas → 8 测试通过
4. **Step 3**：Poseidon 封装 → 6 测试通过
5. **Step 4**：SyscallContext + ZkvmHostState + Syscall trait + SyscallRegistry → 6 测试通过
6. **Step 5.1**：ReadInput + CommitOutput + Panic + Log → ~10 测试通过
7. **Step 5.2**：Sha256 + Poseidon → ~6 测试通过
8. **Step 5.3**：EcdsaVerify + EmitEvent + GetRandomness + ReadState → ~14 测试通过
9. **Step 6**：Executor 迁移 + execute_elf_with_config + 更新现有测试 → 全部通过
10. **Step 7**：alternatives.md Phase 4 章节

每步必须通过全部测试 + clippy clean 才能进入下一步。

## 七、Phase 5 衔接

- **Phase 5（CCS）**：`compile_trace_to_ccs()` 消费 `Trace` + `ExecuteResult.events` — 每个 syscall 调用生成对应子电路约束（Poseidon 预编译电路、SHA-256 lookup table、ECDSA 预编译电路）
- **read_state Merkle 绑定**：Phase 5 电路侧校验 prover 提供的 Merkle 证明（slot 值在 `state_slot_root` 下）
- **跨 batch 一致性**：Phase 5 约束 `state_slot_root` 在所有 CCS 实例中相同
