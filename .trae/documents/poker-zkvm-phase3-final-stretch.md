# poker_zkvm Phase 3 收尾计划 — 验证 Step D + 实现 Step E + 集成 + 文档

> **范围**：Phase 3 剩余工作 — 验证 Step D（decode+execute）、实现 Step E（execute_elf+HostContext）、cargo-zkvm 集成、文档
> **依赖计划**：`.trae/documents/poker-zkvm-phase3-continuation.md`（已批准，含 Step 0/C/D/E 设计决策 D1-D8）
> **遵循**：spec.md L182-266（v1.4 FROZEN）、tasks.md L74-96、checklist.md L76-95
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多方案时选推荐方案，未选方案入文档

## 一、Summary

Phase 3 已完成 Step 0（trace 验证，15 测试）和 Step C（VmState+MemoryMap，10 测试）。Step D（decode+execute+48 测试）代码已写入 `isa/mod.rs` 但**尚未运行测试验证**。Step E（executor.rs）仍为 7 行注释桩。cargo-zkvm `cmd_run` 仍返回 stub 错误。alternatives.md 缺 Phase 3 章节。

本计划聚焦 4 项收尾工作，严格遵循 TDD：每步通过全部测试 + clippy clean 才能进入下一步。

## 二、Current State Analysis

### 已就绪产物（无需重做）

| 文件 | 步骤 | 状态 | 测试数 |
|------|------|------|--------|
| `poker_zkvm/src/trace/mod.rs` | Step 0/B | ✅ 已验证 | 15 |
| `poker_zkvm/src/isa/state.rs` | Step C | ✅ 已验证 | 10 |
| `poker_zkvm/src/isa/mod.rs` | Step D | ⏳ 代码已写，未验证 | 4(Step A) + 17(decode) + 27(execute) = 48 |
| `poker_zkvm/src/isa/executor.rs` | Step E | ❌ 7 行注释桩 | 0 |
| `poker_zkvm/src/bin/cargo-zkvm.rs` | 集成 | ❌ `cmd_run` 为 stub | 3(现有，需更新) |
| `poker_zkvm/docs/alternatives.md` | 文档 | ❌ 缺 Phase 3 章节 | — |

### 关键依赖关系

- Step E 依赖 Step D（`decode`/`execute`）+ Step C（`VmState`/`load_elf`）+ Step B（`Trace`/`Step`/`StepLog`）
- Step E 依赖 Phase 2 `compiler/elf_validator.rs`（`validate_elf` → `ElfMetadata`）
- 集成依赖 Step E（`execute_elf` 公开 API）
- `ZkvmError` 18 variants FROZEN，Step E 可用：`TraceTooLong` / `TraceHostMemoryExceeded` / `OutOfMemory` / `UninitializedRead` / `Other` / `UnsupportedInstruction`

### Step D 代码审查要点（待验证）

`isa/mod.rs` 中已实现的 `decode(word)` 和 `execute(state, insn)` 覆盖全部 RV32I 40 variants。关键实现点：
- 立即数解码：`sign_extend_12` + `decode_i/s/b/u/j_imm` 5 个辅助函数
- compressed 指令拒绝：`word & 0x3 != 0b11`
- execute 中 branch/jump 通过 `finalize_steplog()` 提前返回；非 branch 指令 fallthrough 到 `state.pc = pc.wrapping_add(4)`
- 有符号比较用 `as i32`；移位用 `& 0x1F` 取低 5 位
- `MemAccess` 记录读/写地址、值、size

**潜在风险点**（需测试验证）：
1. `unreachable!()` 在 OP-IMM funct3 match 的 `_` 分支 — clippy 可能建议改写
2. `#[allow(clippy::missing_errors_doc)]` 已加在 `decode`/`execute` 上
3. 测试辅助函数 `encode_r` 用于 SLLI/SRLI/SRAI 编码（bit 布局与 I-type shift 一致）

## 三、Proposed Changes

---

### Step 1：验证 Step D（decode + execute）

**文件**：`poker_zkvm/src/isa/mod.rs`（仅验证，不改动除非有 bug）

**动作**：运行测试 + clippy，确认 48 测试通过、零警告。若失败则修复后才能进入 Step 2。

**验证命令**：
```bash
cargo test -p poker_zkvm --lib isa          # Step A 4 + Step D 44 = 48 tests
cargo clippy -p poker_zkvm --lib -- -D warnings
cargo test -p poker_zkvm                     # 全 crate 不回归
```

**预期结果**：48 isa 测试 + 15 trace 测试 + 10 state 测试 + 已有 87 测试（error 18 + elf_validator 21 + compiler 12 + prelude 7 + cargo-zkvm 29）= ~160 测试通过，零 clippy 警告。

**可能需要的修复**（基于代码审查）：
- 若 clippy 报 `unreachable!` 相关 lint → 改为 `(0..=7)` 通配或保留 `_ => unreachable!()`
- 若 clippy 报 `unnecessary_wrapping` → 保留 `wrapping_add`/`wrapping_sub`（这是有意为之的 RV32I 语义）
- 若测试失败 → 检查立即数编码/解码是否对称

---

### Step 2 — SubTask 3.3.1-3.3.4：execute_elf 循环 + HostContext

**文件**：`poker_zkvm/src/isa/executor.rs`（完整重写 7 行注释桩）

**依赖**：Step A-D（`Instruction`/`decode`/`execute`/`VmState`/`load_elf`）+ Step B（`Trace`/`Step`/`StepLog`）+ Phase 2（`validate_elf`/`ElfMetadata`）

**设计决策**（继承已批准计划 D5/D8）：
- **D5**：`HostContext` 结构体，Phase 3 实现 3 个 syscall（read_input=0x01 / commit_output=0x02 / panic=0x08），其余返回 `Other("not implemented")`
- **D8**：`execute_elf` 内部调 `validate_elf` → `load_elf`，复用 Phase 2 校验
- **ECALL 分派时机**：executor 循环检测 `Instruction::Ecall` 后调 `host.dispatch`，`execute()` 仅 `pc+=4`（保持纯函数性）

#### 类型定义

```rust
use crate::error::ZkvmError;
use crate::isa::state::{VmState, load_elf, HEAP_START};
use crate::trace::{Trace, Step, MAX_TRACE_HOST_MEMORY};
use crate::compiler::elf_validator::validate_elf;

/// 最大 trace 步数（spec L257）。
pub const MAX_ZKVM_TRACE_STEPS: usize = 1_048_576;

/// input buffer 起始地址（= HEAP_START，spec L264）。
const INPUT_BUFFER_ADDR: u32 = HEAP_START;

/// syscall ID 常量（Phase 3 最小集）。
const SYSCALL_READ_INPUT: u32 = 0x01;
const SYSCALL_COMMIT_OUTPUT: u32 = 0x02;
const SYSCALL_PANIC: u32 = 0x08;

/// Host 上下文 — 管理 input/output/halted 状态 + syscall 分派。
pub struct HostContext {
    input: Vec<u8>,
    output: Vec<u8>,
    halted: bool,
}

/// 执行结果。
pub struct ExecuteResult {
    /// 执行轨迹
    pub trace: Trace,
    /// 程序输出（commit_output 写入）
    pub output: Vec<u8>,
}
```

#### 方法清单

| 方法 | 签名 | 行为 |
|------|------|------|
| `HostContext::new(input)` | `-> Self` | input=传入, output=空, halted=false |
| `HostContext::dispatch` | `(&mut self, state: &mut VmState, syscall_id: u32) -> Result<(), ZkvmError>` | 按 syscall_id 分派，读 a0/a1 寄存器 |
| `HostContext::is_halted` | `(&self) -> bool` | 返回 halted |
| `HostContext::into_output` | `(self) -> Vec<u8>` | 返回 output |
| `execute_elf` | `(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError>` | 默认上限执行 |
| `execute_elf_with_limits` | `(elf_bytes, input, step_limit, mem_limit) -> Result<ExecuteResult, ZkvmError>` | 可配置上限（测试用） |

#### syscall 分派表（Phase 3 最小集）

| syscall_id | 名称 | 寄存器约定 | 行为 |
|-----------|------|-----------|------|
| 0x01 | read_input | a0=buffer_addr, a1=buffer_len | 将 `self.input` 拷贝到 VM 内存 `[a0, a0+min(a1, input.len()))`，写实际长度到 a1，返回 a0=INPUT_BUFFER_ADDR |
| 0x02 | commit_output | a0=buffer_addr, a1=buffer_len | 从内存读 `[a0, a0+a1)` 存入 `self.output`，`halted=true` |
| 0x08 | panic | a0=msg_addr, a1=msg_len | 从内存读消息，返回 `Err(Other("zkvm_panic: {msg}"))` |
| 其余 | — | — | 返回 `Err(Other(format!("syscall {id} not implemented in Phase 3")))` |

**read_input 简化设计**（Phase 3 最小实现）：
- 不使用 a0/a1 作为参数（避免测试 ELF 需预设寄存器的复杂性）
- 直接将 `self.input` 写入 `INPUT_BUFFER_ADDR`，设 `a0 = INPUT_BUFFER_ADDR`，`a1 = input.len()`
- 后续 Phase 4 扩展为标准 ABI

#### `execute_elf_with_limits` 执行循环

```rust
pub fn execute_elf_with_limits(
    elf_bytes: &[u8],
    input: &[u8],
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> {
    // 1. 校验 + 加载 ELF
    let metadata = validate_elf(elf_bytes)?;
    let mut state = VmState::new();
    load_elf(&mut state, &metadata)?;

    // 2. 初始化 host + trace
    let mut host = HostContext::new(input.to_vec());
    let mut trace = Trace::new();

    // 3. 执行循环
    loop {
        // 检查 halt
        if host.is_halted() {
            break;
        }

        // 检查步数上限
        if trace.len() >= step_limit {
            return Err(ZkvmError::TraceTooLong {
                actual: trace.len() + 1,
                limit: step_limit,
            });
        }

        // 检查 host 内存上限
        let usage = trace.host_memory_usage();
        if usage > mem_limit {
            return Err(ZkvmError::TraceHostMemoryExceeded {
                actual: usage,
                limit: mem_limit,
            });
        }

        // fetch + decode + execute
        let word = state.fetch_word()?;
        let insn = crate::isa::decode(word)?;
        let step_index = trace.len() as u64;
        let log = crate::isa::execute(&mut state, insn.clone())?;

        // ECALL → syscall 分派
        if matches!(insn, crate::isa::Instruction::Ecall) {
            let syscall_id = state.read_register(17); // a7 = x17
            host.dispatch(&mut state, syscall_id)?;
        }

        // 组装 Step 并追加
        let step = Step::from_log(step_index, log);
        trace.push_step(step);
    }

    Ok(ExecuteResult {
        trace,
        output: host.into_output(),
    })
}
```

#### `execute_elf`（默认上限）

```rust
pub fn execute_elf(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError> {
    execute_elf_with_limits(
        elf_bytes,
        input,
        MAX_ZKVM_TRACE_STEPS,
        MAX_TRACE_HOST_MEMORY,
    )
}
```

#### 测试 ELF 构造辅助函数

复用 Phase 2 `elf_validator` 测试中的 `build_minimal_elf()` 模式，手工构造 ELF32 字节（52B header + 32B program header + .text 字节序列）。需构造的 ELF 含：
- 有效 ELF32 header（magic/class/endian/machine=0xF3 RISC-V/entry=0x1000）
- 1 个 PT_LOAD 段（vaddr=0x1000, .text 数据）
- .text 含预设的 RV32I 指令序列

#### TDD 测试计划（8 个测试）

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_execute_elf_minimal_halt` | 构造最小 ELF（commit_output syscall：LUI a0 + ADDI a1 + ECALL with a7=0x02）→ 执行 halted，output 非空 |
| 2 | `test_execute_elf_trace_too_long` | 用 step_limit=2 执行 3+ 步 ELF → `TraceTooLong` |
| 3 | `test_execute_elf_host_memory_exceeded` | 用 mem_limit=100 执行 → `TraceHostMemoryExceeded` |
| 4 | `test_execute_elf_read_input_commit_output_echo` | 完整 echo 闭环：read_input → 数据已在内存 → commit_output 输出 |
| 5 | `test_execute_elf_panic_terminates` | 触发 zkvm_panic（a7=0x08）→ `Other("zkvm_panic: ...")` |
| 6 | `test_execute_elf_unknown_syscall` | a7=0x03（Poseidon，Phase 4）→ `Other("syscall 3 not implemented")` |
| 7 | `test_execute_elf_pc_out_of_bounds` | ELF 入口指向未初始化内存（entry 超出段范围）→ `UninitializedRead` |
| 8 | `test_host_context_dispatch_direct` | 直接测 `HostContext::dispatch` read_input/commit_output/panic 分支 |

#### TDD 步骤

- **RED**：定义 `HostContext` / `ExecuteResult` + `execute_elf` / `execute_elf_with_limits` stub（返回 `Err(Other("Step E pending"))`）+ 8 测试（编译通过但失败）
- **GREEN**：
  1. 实现 `HostContext::new` / `is_halted` / `into_output`
  2. 实现 `HostContext::dispatch` 的 3 个 syscall 分支
  3. 实现 `execute_elf_with_limits` 循环
  4. 实现 `execute_elf` 默认上限包装
  5. 逐个让测试通过
- **REFACTOR**：`HostContext::dispatch` 的 match 分支提取为 `dispatch_read_input` / `dispatch_commit_output` / `dispatch_panic` 私有方法；所有公开项补 `///` doc

#### 验证

```bash
cargo test -p poker_zkvm --lib isa::executor   # 8 tests pass
cargo test -p poker_zkvm                        # 全 crate 不回归
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### Step 3 — 集成：cargo-zkvm `run` 子命令

**文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`（更新 `cmd_run`）

**当前状态**：`cmd_run` 为 stub，返回 `Err(format!("run not implemented (Phase 3...)"))`

**改动**：
- `cmd_run` 从 stub 改为：
  1. 读取 `--elf` 参数指向的文件字节
  2. 读取 `--input` 参数指向的文件字节（若未提供则空 `&[]`）
  3. 调用 `poker_zkvm::isa::executor::execute_elf(&elf_bytes, &input)`
  4. 输出：步数 + output 长度
  5. 可选 `--trace-out <PATH>` 写序列化 trace（二进制）
- 更新现有 3 个 `cmd_run` 测试：
  - `test_run_missing_elf_arg` — 保留（参数校验不变）
  - `test_run_missing_input_arg` — 保留（参数校验不变）
  - `test_run_returns_phase3_pending` — **改为** `test_run_nonexistent_elf_file`（验证文件不存在时返回 IO 错误，而非 "Phase 3" 错误）

**新增测试**（可选）：
- `test_run_executes_minimal_elf` — 构造临时最小 ELF 文件 + 空 input，执行成功，输出含步数

**验证**：
```bash
cargo test -p poker_zkvm --bin cargo-zkvm
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

---

### Step 4 — 文档：alternatives.md Phase 3 章节

**文件**：`poker_zkvm/docs/alternatives.md`（追加 Phase 3 章节）

**内容**：在 `## 待补充` 之前插入 Phase 3 章节，记录 D1-D8 + ECALL 分派时机共 9 项决策的备选方案。

| 决策 | 推荐方案（已实现） | 备选方案 | 否决理由 |
|------|-------------------|---------|---------|
| 内存模型（D1） | 分页 BTreeMap + 字节级 init 位图 | HashMap<u32,u8> / 稠密 Vec / 分段线性 | 离散地址无序 / 16MB 浪费 / 复杂度 |
| 内存对齐（D2） | 自然对齐（LW 4B / LH 2B / LB 1B） | 全部强制 4B 对齐 | 违反 RISC-V 语义，LB/SB 失效 |
| Instruction 枚举（D3） | 逐 variant + 预解码操作数 | 按 format 分组 / 存 raw word | execute 需间接分派 / 重复解码 |
| StepLog vs Step（D4） | 分离（execute 返回 StepLog，executor 组装 Step） | execute 直接返回 Step | 违反 execute 纯函数性 |
| HostContext（D5） | 结构体 + dispatch 方法 | Trait object / 全 defer 到 caller | 过度设计 / 无法测试闭环 |
| Trace 序列化（D6） | 自定义二进制（magic+version+steps） | serde+bincode / borsh / JSON | 无新依赖 / 流式 / 防 u64 溢出 |
| opcode 白名单（D7） | decode 自包含（内部 match） | 共享 RV32I_OPCODES 常量 | 跨模块耦合 / 职责不同 |
| load_elf 签名（D8） | 接受 `&ElfMetadata`（已校验） | 接受 raw bytes | TOCTOU 风险 |
| ECALL 分派时机 | executor 循环中检测 Ecall 后 dispatch | execute 内部分派 | 破坏 execute 纯函数性 + 难以测试 |

## 四、Assumptions & Decisions

1. **Step D 代码正确**：假设 `isa/mod.rs` 中 decode/execute 实现通过验证（Step 1 确认）。若发现 bug，修复后继续。
2. **read_input 简化 ABI**：Phase 3 的 `read_input` 不读 a0/a1 参数，直接将 input 写入 `INPUT_BUFFER_ADDR` 并设 a0/a1。Phase 4 扩展为标准 ABI。此决策降低测试 ELF 构造复杂度。
3. **EBREAK 不作为 halt 信号**：spec 未明确 EBREAK 语义，Phase 3 中 EBREAK 仅 `pc+=4`（与 ECALL 一致）。halt 仅由 `commit_output` syscall 触发。若程序无 halt 则跑到 `TraceTooLong`。
4. **测试 ELF 手工构造**：复用 Phase 2 `build_minimal_elf()` 模式，不依赖实际 rustc 交叉编译。
5. **`#![deny(missing_docs)]`**：所有新增公开项 + 枚举字段需 `///` doc comment。
6. **`#![deny(unsafe_code)]`**：无 unsafe。
7. **`extern crate alloc`**：`HostContext` 用 `Vec<u8>`（std 环境，无需 alloc）。

## 五、验证计划

### 每步完成后

```bash
cargo test -p poker_zkvm                          # 全部测试通过
cargo clippy -p poker_zkvm --all-targets -- -D warnings  # 零警告
```

### Phase 3 全部完成后

```bash
cargo build --workspace                            # workspace 集成
cargo test --workspace                             # workspace 全部测试
cargo build -p poker_zkvm --bin cargo-zkvm         # CLI 二进制可构建
cargo build -p poker_zkvm --release                # release build 成功
```

### 测试覆盖汇总

| 步骤 | SubTask | 预估测试数 | 累计 |
|------|---------|-----------|------|
| Step 0（已验证） | 3.4.1-3.4.5 | 15（已有） | ~160 |
| Step C（已验证） | 3.2.1-3.2.4 | 10（已有） | ~170 |
| Step 1（验证 Step D） | 3.1.2-3.1.4 | 48（已有） | ~218 |
| Step 2（Step E） | 3.3.1-3.3.4 | +8 新增 | ~226 |
| Step 3（集成） | — | ~3 更新 | ~226 |
| Step 4（文档） | — | 0 | ~226 |
| **合计** | | **+8 新增 + 3 更新** | **~218 → ~226** |

## 六、执行顺序（TDD 严格模式）

1. **Step 1**：运行 `cargo test -p poker_zkvm --lib isa` + `cargo clippy`，验证 Step D（48 测试）。若失败修复。
2. **Step 2**：RED（8 测试 + stub）→ GREEN（HostContext + execute_elf）→ REFACTOR → 验证
3. **Step 3**：更新 cargo-zkvm `cmd_run` → 更新测试 → 验证
4. **Step 4**：追加 alternatives.md Phase 3 章节

每步必须通过全部测试 + clippy clean 才能进入下一步。

## 七、Phase 4 衔接

- **Phase 4（Syscall）**：`HostContext` 迁移到 `syscalls/mod.rs`，扩展为 `SyscallId` 枚举 + `Syscall` trait + 10 个 host 实现。Phase 3 的 `dispatch()` match 分支成为兼容层。`read_input` 扩展为标准 ABI（读 a0/a1 参数）。
- **Phase 5（CCS）**：`compile_trace_to_ccs()` 消费 `Trace`——`Step.instruction` 选择子电路（a la carte），`Step.mem_access` 生成 byte-level permutation 约束，`Step.registers` 生成连续性约束。`MemAccess.size` 字段是 Phase 5 的关键。
