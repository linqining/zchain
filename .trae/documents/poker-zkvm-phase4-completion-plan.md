# poker_zkvm Phase 4 收尾计划 — Step 5/6/7

> **范围**：完成 Phase 4 剩余三步 — Step 5（10 个 Host syscall 实现编译通过 + 测试）、Step 6（executor 迁移到 SyscallRegistry）、Step 7（alternatives.md 文档）
> **前置**：Step 0-4 已完成（依赖添加、SyscallId、gas、Poseidon、SyscallContext/Syscall trait/SyscallRegistry 全部测试通过）
> **TDD 严格模式**：每步测试通过 + clippy clean 才进入下一步

## 一、Current State Analysis

### Step 5 现状（IN PROGRESS — 文件已写但未编译/测试）

`poker_zkvm/src/syscalls/host.rs` 已写入全部 10 个 syscall 实现 + ~30 个测试，但存在以下已知 bug：

| # | 位置 | 问题 | 修复 |
|---|------|------|------|
| 1 | `mod.rs` L35 | `// pub mod host;` 被注释 | 取消注释 |
| 2 | `host.rs` L28 | `use crate::isa::state::{HeapStart, VmState}` — `HeapStart` 不存在 | 改为 `use crate::isa::state::{HEAP_START, VmState}` |
| 3 | `host.rs` L101 | `HeapStart::HEAP_START` | 改为 `HEAP_START` |
| 4 | `host.rs` L639, L642 | `HeapStart::HEAP_START`（测试中） | 改为 `HEAP_START` |
| 5 | `host.rs` L805, L831 | `hex::decode_to_slice(...)` — `hex` 不在 dev-deps | 在 `poker_zkvm/Cargo.toml` `[dev-dependencies]` 添加 `hex = { workspace = true }` |
| 6 | `host.rs` L24 | `use ark_ff::{One, Zero}` — 两者均未使用 | 删除整行 |
| 7 | `mod.rs` L332-336 | `SyscallRegistry::new()` 返回 `new_empty()` | 改为 `host::create_full_registry()` |

### Step 6 现状（未开始）

`poker_zkvm/src/isa/executor.rs` 使用 Phase 3 的 `HostContext`（3 syscall match 分派），需迁移到 `SyscallRegistry` + `SyscallContext`。

**现有 8 个 executor 测试中需要更新的**：

| 测试 | 问题 | 修复 |
|------|------|------|
| `test_execute_elf_read_input_commit_output_echo` | 新 ReadInput ABI 读 a1=len；a1=0 → 读 0 字节 → echo 失败 | 在 ECALL 前加 `ADDI a1, x0, 5` 指令 |
| `test_execute_elf_unknown_syscall` | syscall 3 现已注册为 Poseidon，不再返回错误 | 改用 `a7=0x0B`（11，未注册 ID） |
| `test_host_context_dispatch_direct` | 直接测试 `HostContext` — 将被删除 | 删除此测试（host.rs 已有等价覆盖） |

**不需修改的测试**：
- `test_execute_elf_minimal_halt` — commit_output(a0=0, a1=0) → 空 output → halt ✓
- `test_execute_elf_panic_terminates` — panic(a0=0, a1=0) → "zkvm_panic: " ✓
- `test_execute_elf_trace_too_long` — JAL 循环，无 syscall ✓
- `test_execute_elf_host_memory_exceeded` — JAL 循环 ✓
- `test_execute_elf_pc_out_of_bounds` — JAL 到未初始化 ✓

### Step 7 现状（未开始）

`poker_zkvm/docs/alternatives.md` 在 L243 `## 待补充` 之前插入 Phase 4 章节。

## 二、Proposed Changes

### Step 5 — 修复 host.rs 编译错误 + 运行测试

**文件**：`poker_zkvm/src/syscalls/mod.rs`、`poker_zkvm/src/syscalls/host.rs`、`poker_zkvm/Cargo.toml`

#### 5.1 取消注释 `pub mod host;`

`mod.rs` L34-35：
```rust
// Step 5 将实现 10 个 Syscall struct
// pub mod host;
```
→
```rust
/// 10 个 ZKVM Syscall 的 Host 实现（Task 4.2）。
pub mod host;
```

#### 5.2 更新 `SyscallRegistry::new()`

`mod.rs` L327-336：
```rust
pub fn new() -> Self {
    // Step 5 将注册全部 10 个 syscall
    // 当前返回空注册表，dispatch 全部走 fallback
    Self::new_empty()
}
```
→
```rust
pub fn new() -> Self {
    host::create_full_registry()
}
```

#### 5.3 修复 host.rs 导入

`host.rs` L24：
```rust
use ark_ff::{One, Zero};
```
→ 删除整行（未使用）

`host.rs` L28：
```rust
use crate::isa::state::{HeapStart, VmState};
```
→
```rust
use crate::isa::state::{HEAP_START, VmState};
```

#### 5.4 修复 HeapStart::HEAP_START → HEAP_START

`host.rs` L101：
```rust
let write_addr = if ptr == 0 { HeapStart::HEAP_START } else { ptr };
```
→
```rust
let write_addr = if ptr == 0 { HEAP_START } else { ptr };
```

`host.rs` L639, L642（测试 `test_read_input_backward_compat`）：
```rust
assert_eq!(state.read_register(REG_A0), HeapStart::HEAP_START);
// ...
assert_eq!(
    state.read_memory_byte(HeapStart::HEAP_START).unwrap(),
    0x42
);
```
→
```rust
assert_eq!(state.read_register(REG_A0), HEAP_START);
// ...
assert_eq!(
    state.read_memory_byte(HEAP_START).unwrap(),
    0x42
);
```

#### 5.5 添加 hex dev-dependency

`poker_zkvm/Cargo.toml` `[dev-dependencies]`：
```toml
[dev-dependencies]
proptest = { workspace = true }
criterion = { workspace = true }
hex = { workspace = true }
```

#### 5.6 验证

```bash
cargo test -p poker_zkvm --lib syscalls::host     # ~30 新测试
cargo test -p poker_zkvm --lib syscalls            # ~50 syscalls 测试
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

---

### Step 6 — Executor 迁移到 SyscallRegistry

**文件**：`poker_zkvm/src/isa/executor.rs`、`poker_zkvm/src/bin/cargo-zkvm.rs`

#### 6.1 新增 ZkvmExecutionConfig

```rust
use crate::syscalls::{SyscallContext, SyscallRegistry, ZkvmHostState, StubHostState};
use ark_bn254::Fr;
use ark_ff::Zero;

/// ZKVM 执行配置 — 持有 host 侧输入和 randomness 参数。
pub struct ZkvmExecutionConfig {
    /// 程序输入
    pub input: Vec<u8>,
    /// get_randomness 派生 seed
    pub randomness_seed: Fr,
    /// get_randomness 派生 initial_commitment
    pub initial_commitment: Fr,
    /// get_randomness 派生 final_commitment
    pub final_commitment: Fr,
    /// Host 状态读取实现
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

#### 6.2 更新 ExecuteResult

```rust
pub struct ExecuteResult {
    pub trace: Trace,
    pub output: Vec<u8>,
    /// emit_event 产生的事件哈希列表
    pub events: Vec<Fr>,
    /// log syscall 产生的日志列表
    pub logs: Vec<Vec<u8>>,
}
```

#### 6.3 删除 HostContext，迁移执行循环

删除：
- `HostContext` struct 及其所有方法
- `SYSCALL_READ_INPUT` / `SYSCALL_COMMIT_OUTPUT` / `SYSCALL_PANIC` 常量
- `INPUT_BUFFER_ADDR` 常量
- `REG_A0` / `REG_A1` / `REG_A7` 局部常量（用 `crate::syscalls::REG_*` 替代）

新执行循环核心：
```rust
pub fn execute_elf_with_limits_and_config(
    elf_bytes: &[u8],
    config: ZkvmExecutionConfig,
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> {
    let metadata = validate_elf(elf_bytes)?;
    let mut state = VmState::new();
    load_elf(&mut state, &metadata)?;

    let registry = SyscallRegistry::new();
    let mut ctx = SyscallContext::new(config.input)
        .with_randomness(config.randomness_seed, config.initial_commitment, config.final_commitment)
        .with_host_state(config.host_state);
    let mut trace = Trace::new();

    loop {
        if ctx.is_halted() { break; }
        if trace.len() >= step_limit { return Err(TraceTooLong); }
        if trace.host_memory_usage() > mem_limit { return Err(TraceHostMemoryExceeded); }

        let word = state.fetch_word()?;
        let insn = crate::isa::decode(word)?;
        ctx.step_index = trace.len() as u64;
        let log = crate::isa::execute(&mut state, insn.clone())?;

        if matches!(insn, crate::isa::Instruction::Ecall) {
            let syscall_id = state.read_register(crate::syscalls::REG_A7);
            registry.dispatch(syscall_id, &mut ctx, &mut state)?;
        }

        let step = Step::from_log(ctx.step_index, log);
        trace.push_step(step);
    }

    let events = std::mem::take(&mut ctx.events);
    let logs = std::mem::take(&mut ctx.logs);
    Ok(ExecuteResult {
        trace,
        output: ctx.into_output(),
        events,
        logs,
    })
}
```

#### 6.4 API 层级

```rust
// 旧 API（向后兼容）
pub fn execute_elf(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError> {
    let config = ZkvmExecutionConfig { input: input.to_vec(), ..Default::default() };
    execute_elf_with_limits_and_config(elf_bytes, config, MAX_ZKVM_TRACE_STEPS, MAX_TRACE_HOST_MEMORY)
}

// 新 API
pub fn execute_elf_with_config(elf_bytes: &[u8], config: ZkvmExecutionConfig) -> Result<ExecuteResult, ZkvmError> {
    execute_elf_with_limits_and_config(elf_bytes, config, MAX_ZKVM_TRACE_STEPS, MAX_TRACE_HOST_MEMORY)
}

// 保留旧名（测试用）
pub fn execute_elf_with_limits(elf_bytes, input, step_limit, mem_limit) -> Result<ExecuteResult, ZkvmError> {
    let config = ZkvmExecutionConfig { input: input.to_vec(), ..Default::default() };
    execute_elf_with_limits_and_config(elf_bytes, config, step_limit, mem_limit)
}
```

#### 6.5 更新 executor 测试（3 个修改 + 1 个删除）

**`test_execute_elf_read_input_commit_output_echo`**：
```rust
let text = encode_text(&[
    encode_i(0x13, 0, 17, 0, 1),  // ADDI a7, x0, 1 (read_input)
    encode_i(0x13, 0, 11, 0, 5),  // ADDI a1, x0, 5 (len=5)
    0x00000073,                    // ECALL
    encode_i(0x13, 0, 17, 0, 2),  // ADDI a7, x0, 2 (commit_output)
    0x00000073,                    // ECALL
]);
assert_eq!(result.trace.len(), 5, "5 instructions");
assert_eq!(result.output, b"hello");
```

**`test_execute_elf_unknown_syscall`**：
```rust
let text = encode_text(&[encode_i(0x13, 0, 17, 0, 0x0B), 0x00000073]);
let err = execute_elf(&elf, &[]).unwrap_err();
assert!(matches!(err, ZkvmError::Other(ref msg) if msg.contains("unknown syscall id: 0x0b")));
```

**删除 `test_host_context_dispatch_direct`** — HostContext 已移除，host.rs 已有等价测试覆盖。

**其余 5 个测试不需修改。**

#### 6.6 更新 cargo-zkvm cmd_run

```rust
Ok(format!(
    "Execution complete: {} steps, {} byte(s) output, {} event(s), {} log(s)",
    result.trace.len(),
    result.output.len(),
    result.events.len(),
    result.logs.len()
))
```

`test_run_executes_minimal_elf` 断言 `msg.contains("Execution complete") && msg.contains("2 steps")` → 仍然通过 ✓

#### 6.7 验证

```bash
cargo test -p poker_zkvm --lib isa::executor   # 7 测试（8-1删除）
cargo test -p poker_zkvm --lib                  # 全部 lib 测试
cargo test -p poker_zkvm --bin cargo-zkvm       # CLI 测试
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

---

### Step 7 — alternatives.md Phase 4 章节

**文件**：`poker_zkvm/docs/alternatives.md`

在 L243 `## 待补充` 之前插入 Phase 4 章节，记录 ~8 项设计决策：

1. **Poseidon 实现**：ark-crypto-primitives vs 自实现 vs stub → 选择 ark-crypto-primitives（未选择：自实现 Poseidon 电路、stub 占位）
2. **Syscall 分派**：Syscall trait + Registry vs match 分派 → 选择 trait 抽象（未选择：保持 match 分派、函数指针表）
3. **Host 状态读取**：ZkvmHostState trait vs 扩展 PokerL1Context → 选择 trait 抽象（未选择：直接依赖 PokerL1Context、硬编码状态）
4. **Gas 计费**：独立 syscall_gas 函数 vs Syscall::gas_cost trait 方法 → 两者皆用（trait 方法委托到 gas 模块）
5. **SyscallContext**：集中 struct vs 散落参数 → 选择集中 struct（未选择：每个 syscall 独立参数）
6. **ECDSA 签名格式**：64 字节 compact vs DER → 选择 compact（未选择：DER 格式、65 字节 recoverable）
7. **Poseidon 参数**：find_poseidon_ark_and_mds 生成 vs 硬编码 → 选择运行时生成 + OnceLock 缓存（未选择：编译期硬编码、BLS12-381 默认参数）
8. **ReadInput ABI 升级**：标准 ABI + a0=0 回退 vs 保持 Phase 3 简化 ABI → 选择标准 ABI + 回退（未选择：强制标准 ABI 不回退、保持简化 ABI）

## 三、验证计划

### Step 5 完成后
```bash
cargo test -p poker_zkvm --lib syscalls::host      # ~30 测试
cargo test -p poker_zkvm --lib syscalls             # ~50 测试
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

### Step 6 完成后
```bash
cargo test -p poker_zkvm --lib isa::executor        # 7 测试
cargo test -p poker_zkvm --lib                       # 全部 lib
cargo test -p poker_zkvm --bin cargo-zkvm            # CLI 测试
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

### Phase 4 全部完成
```bash
cargo test -p poker_zkvm                             # ~310 测试通过
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build --workspace
cargo build -p poker_zkvm --release
```

## 四、执行顺序

1. **Step 5.1-5.5**：修复 host.rs 编译错误 → `cargo test -p poker_zkvm --lib syscalls::host` 通过
2. **Step 5.6**：clippy clean
3. **Step 6.1-6.4**：executor 迁移 → `cargo test -p poker_zkvm --lib isa::executor` 通过
4. **Step 6.5-6.6**：更新测试 + cargo-zkvm → 全部测试通过
5. **Step 6.7**：clippy + build
6. **Step 7**：alternatives.md 文档

## 五、Assumptions & Decisions

1. `SyscallRegistry::new()` 委托到 `host::create_full_registry()` — `new_empty()` 仍保留用于测试
2. `execute_elf_with_limits` 保留旧签名（接受 `input: &[u8]`）向后兼容
3. `ExecuteResult` 新增 `events` / `logs` 字段 — 不影响现有测试断言
4. 删除 `test_host_context_dispatch_direct` 而非重写 — host.rs 的 30 个测试已充分覆盖
5. `hex` 加入 dev-dependencies（非正式 dependencies）— 仅测试用
6. `ReadInput` 向后兼容：a0=0 → HEAP_START，但 a1=0 → 读 0 字节（无回退）— 测试需显式设 a1
