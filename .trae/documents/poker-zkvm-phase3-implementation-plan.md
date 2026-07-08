# poker_zkvm Phase 3 实现计划 — ZKVM ISA 执行引擎

> **范围**：Phase 3 全部 4 个 Task（3.1 / 3.2 / 3.3 / 3.4），按 TDD 严格模式顺序推进
> **依赖**：Phase 2 已完成（160 tests pass / clippy clean / release build / workspace build）
> **遵循**：spec.md L182-266（v1.4 FROZEN）、tasks.md L74-96、checklist.md L76-95
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多方案时选推荐方案，未选方案入文档

## 一、Context

Phase 3 实现 ZKVM ISA 执行引擎——将 Phase 2 产出的 RV32I ELF 加载到虚拟机内存，逐条解码并执行指令，产生 execution trace 供 Phase 5 CCS 约束编译器消费。这是 ZKVM 从"编译流水线"到"可执行虚拟机"的关键跃迁。

Phase 3 完成后，`cargo zkvm run --elf <path> --input <path>` 可端到端执行 ELF 并输出 trace 步数。Phase 4 将扩展 syscall 实现，Phase 5 将消费 trace 生成 CCS 实例。

## 二、Current State

### 已就绪（Phase 2 产物）
- `error.rs` — 18 个 FROZEN `ZkvmError` variants（Phase 3 用到 8 个：`UnsupportedInstruction` / `UnalignedAccess` / `UninitializedRead` / `TraceTooLong` / `TraceHostMemoryExceeded` / `OutOfMemory` / `InvalidSlot` / `Other`）
- `compiler/elf_validator.rs` — `validate_elf()` 返回 owned `ElfMetadata`（消除 TOCTOU）；`MAX_ZKVM_MEMORY = 16MB`；`RV32I_OPCODES` 私有常量（11 个 opcode）
- `lib.rs` — `#![deny(unsafe_code)]` + `#![deny(missing_docs)]` + `extern crate alloc`；声明 `pub mod isa; pub mod trace;`
- `Cargo.toml` — 已含 `serde` / `goblin` / `proptest` / `criterion`

### 待实现（4 个 stub 文件）
- `isa/mod.rs` — 10 行注释 stub，声明 `pub mod state; pub mod executor;`
- `isa/state.rs` — 6 行注释 stub
- `isa/executor.rs` — 7 行注释 stub
- `trace/mod.rs` — 6 行注释 stub

## 三、Task 执行顺序（解决 3.1 ↔ 3.4 循环依赖）

`Instruction`（3.1.1）被 `Step`（3.4.1）引用；`StepLog`（3.4）被 `execute()`（3.1.3）返回。拆分为 5 个顺序步骤：

| 步骤 | 对应 SubTask | 产出 | 依赖 |
|------|-------------|------|------|
| **Step A** | 3.1.1 | `Instruction` 枚举（40 variants，仅类型定义） | 无 |
| **Step B** | 3.4.1-3.4.5 | `Trace` / `Step` / `StepLog` / `MemAccess` / `MemOp` + 序列化 | Step A |
| **Step C** | 3.2.1-3.2.4 | `VmState` / `MemoryMap` / `load_elf` / `read_memory` / `write_memory` | `error.rs` + `elf_validator.rs`（已存在） |
| **Step D** | 3.1.2-3.1.4 | `decode(word)` + `execute(state, insn) -> StepLog` + 全 RV32I 测试 | Step A + B + C |
| **Step E** | 3.3.1-3.3.4 | `execute_elf()` 循环 + 步数/内存上限 + `HostContext` syscall 分派 | Step A-D |

## 四、关键设计决策

### D1：内存模型 — 分页 BTreeMap + 字节级初始化位图

```rust
const PAGE_SIZE: usize = 4096;

struct Page {
    data: [u8; PAGE_SIZE],
    init_mask: [u8; PAGE_SIZE / 8], // 1 bit/byte，标记已写入字节
}

pub struct MemoryMap {
    pages: alloc::collections::BTreeMap<u32, Box<Page>>, // key = 页基址
    total_allocated: usize, // 用于 16MB 上限检查
}
```

**理由**：16MB 在 4GB 地址空间中离散分布（STACK_TOP=0x80000000, HEAP_START=0x10000000），稠密 Vec 无法覆盖；BTreeMap 迭代有序满足 ZKVM 确定性；初始化位图支持 `UninitializedRead` 精确检测（Phase 3 + Phase 5 byte-level permutation 均需要）。

**否决方案**：`HashMap<u32,u8>`（1600 万 entry，开销过大且无序）/ 稠密 `Vec<u8>`（无法表示 0x80000000 栈地址）/ 分段 Vec（段边界管理复杂）

### D2：内存对齐 — 自然对齐（标准 RISC-V 语义）

- LW/SW → 4 字节对齐，LH/SH/LHU → 2 字节对齐，LB/SB/LBU → 1 字节（任意地址）
- 未对齐返回 `ZkvmError::UnalignedAccess { addr }`

**理由**：spec L265「4-byte word 对齐」指 word 级访问的对齐要求；`MemAccess.size` 字段（1/2/4）的存在要求支持子字访问；Phase 5 byte-level permutation（spec L292-294）明确处理混合尺寸访问（LW 4B + LB 1B）；`riscv32i-unknown-none-elf` ABI 使用自然对齐。

**否决方案**：全部强制 4 字节对齐（LB/SB 失效，违反 RISC-V 语义）

### D3：Instruction 枚举 — 逐 variant + 预解码操作数

40 个 variant（LUI/AUIPC/JAL/JALR + 6 Branch + 5 Load + 3 Store + 9 OP-IMM + 10 OP + FENCE/ECALL/EBREAK），每个携带预解码字段（`rd`/`rs1`/`rs2`/`imm`/`shamt`），`imm` 以 u32 存储符号扩展值，`shamt` 为 u8（0-31）。`#[derive(Clone, Debug, PartialEq, Eq)]`。

**理由**：预解码使 `execute()` 无需重复位操作；`imm` 用 u32 存符号扩展值简化 execute；`x0` 处理在 `execute()` 内部统一拦截（不特殊化枚举）。

**否决方案**：按 format 分组（`RType{rd,rs1,rs2,funct3,funct7}` — execute 需再次分派）/ 存 raw word（重复解码）

### D4：StepLog vs Step 分离

```rust
pub struct StepLog {           // execute() 返回值
    pub pc: u32,
    pub instruction: Instruction,
    pub registers: [u32; 32],  // 执行后快照
    pub mem_access: Vec<MemAccess>,
}

pub struct Step {              // Trace 中的条目
    pub step_index: u64,
    pub pc: u32,
    pub instruction: Instruction,
    pub registers: [u32; 32],
    pub mem_access: Vec<MemAccess>,
}
```

executor 负责组装 `Step::from_log(step_index, log)`。`execute()` 是纯单步函数，不感知全局 step_index。

### D5：Syscall 分派 — HostContext 结构体（Phase 3 最小集）

Phase 3 实现 3 个 syscall 供执行闭环测试，Phase 4 扩展其余 7 个：

```rust
pub struct HostContext {
    input: Vec<u8>,
    output: Vec<u8>,
    halted: bool,
}
```

ECALL 执行流程：`execute()` 处理 PC+4 → executor 循环检测 `insn == Ecall` → 调用 `host.dispatch(&mut state, a7, step_index)`。

| syscall_id | 名称 | Phase 3 行为 |
|-----------|------|-------------|
| 0x01 | read_input | 将 input 拷贝到 VM 内存（INPUT_BUFFER_ADDR=0x10000000），写长度到 a0 指向地址，返回 ptr 到 a0 |
| 0x02 | commit_output | 从内存读 [a0, a0+a1)，存入 output，设 halted=true |
| 0x08 | panic | 从内存读消息，返回 `Err(Other("zkvm_panic: {msg}"))` |
| 其余 | — | 返回 `Err(Other("syscall {id} not implemented in Phase 3"))` |

**否决方案**：Trait-based dispatch（Phase 3 过度设计）/ 全 defer 到 Phase 4（无法测试闭环）/ 在 execute() 内部分派（破坏纯函数性）

### D6：Trace 序列化 — 自定义二进制流式格式

```
[4B] magic "TRCE" | [4B] version=1 | [8B] num_steps
Per step: [8B step_index][4B pc][1B insn_tag][variable insn fields][128B registers][4B mem_count]
Per mem: [4B addr][1B op][4B value][1B size]
```

反序列化三步法（与 spec proof 反序列化一致）：magic 校验 → `num_steps.checked_mul(估算大小)` 防 u64 溢出 + 超 `MAX_TRACE_HOST_MEMORY` 早夭 → 逐 step 解析。

**否决方案**：serde+bincode（引入依赖 + 不默认防溢出）/ serde+borsh（enum 序列化不灵活）/ JSON（1M 步 ≈ 1GB 不可行）

### D7：opcode 白名单不共享

`decode()` 自包含——解码过程中自然拒绝非 RV32I opcode（不匹配任何已知 opcode/funct3/funct7 → `UnsupportedInstruction`）。`elf_validator::RV32I_OPCODES` 保持私有不变。两者职责不同：elf_validator 是编译时静态扫描，decode 是运行时动态解码。

### D8：load_elf 接受 ElfMetadata（消除 TOCTOU）

```rust
pub fn load_elf(state: &mut VmState, metadata: &ElfMetadata) -> Result<(), ZkvmError>
```

`execute_elf` 内部：`validate_elf(elf_bytes)?` → `load_elf(&mut state, &metadata)?`。复用 Phase 2 的校验产出，不再读文件。

## 五、逐步骤 TDD 计划

### Step A — SubTask 3.1.1：Instruction 枚举

**文件**：`poker_zkvm/src/isa/mod.rs`

**RED**：4 个测试——枚举构造 / Clone / Eq / variant 数量（断言 40 个 variant 覆盖全部 RV32I + ECALL/EBREAK/FENCE）

**GREEN**：定义 `Instruction` 枚举（40 variants，按 U-type/J-type/B-type/Load/Store/OP-IMM/OP/SYSTEM 分组注释），`#[derive(Clone, Debug, PartialEq, Eq)]`

**REFACTOR**：格式类型分组注释

### Step B — SubTask 3.4.1-3.4.5：Trace 数据结构

**文件**：`poker_zkvm/src/trace/mod.rs`

**依赖**：Step A 的 `Instruction`

**RED**（8 个测试）：
- `Trace::new()` 空构造 / `push_step()` + `step(i)` / `iter()`
- `MemAccess` 含 `size` 字段（防 LB/LW aliasing）
- `serialize()` → `deserialize()` 往返一致
- bad magic 拒绝 / `num_steps` 极大值返回 `TraceHostMemoryExceeded`
- `host_memory_usage()` 估算

**GREEN**：定义 `Trace`/`Step`/`StepLog`/`MemAccess`/`MemOp`（Read/Write），实现 `new`/`push_step`/`len`/`is_empty`/`step`/`iter`/`serialize`/`deserialize`/`host_memory_usage`。`deserialize` 用 `checked_mul` 防 u64 溢出。

**REFACTOR**：提取 `serialize_instruction()` / `deserialize_instruction()` 辅助函数

### Step C — SubTask 3.2.1-3.2.4：VmState + 内存模型

**文件**：`poker_zkvm/src/isa/state.rs`

**依赖**：`error.rs`、`compiler/elf_validator.rs`（`ElfMetadata` / `LoadedSegment` / `MAX_ZKVM_MEMORY`）

**RED**（10 个测试）：
- `VmState::new()` — pc=0, registers=0, sp=STACK_TOP
- `read_register(0)` / `write_register(0, v)` — x0 恒为 0
- `write_memory_word` / `read_memory_u32` — little-endian
- 未对齐 word/halfword 访问 → `UnalignedAccess`
- 字节访问任意对齐
- 未初始化读取 → `UninitializedRead`
- 16MB 上限 → 第 4097 页 `OutOfMemory`
- `load_elf(metadata)` — 段加载 + PC=entry
- `fetch_word()` — 从 PC 读指令（PC 对齐检查）

**GREEN**：实现 `VmState { pc, registers: [u32;32], memory: MemoryMap }` + `MemoryMap`（分页 BTreeMap + init_mask）+ `read_register`/`write_register`/`read_memory_byte`/`write_memory_byte`/`read_memory_halfword`/`write_memory_halfword`/`read_memory_word`/`write_memory_word`/`fetch_word`/`load_elf`。所有地址运算用 `checked_add`。

**REFACTOR**：提取 `Page::ensure_page()` / `Page::is_initialized()` 辅助方法

### Step D — SubTask 3.1.2-3.1.4：decode + execute

**文件**：`poker_zkvm/src/isa/mod.rs`

**依赖**：Step A（Instruction）+ Step B（StepLog/MemAccess）+ Step C（VmState）

#### SubTask 3.1.2：decode(word) — ~15 个测试

**RED**：每格式类型至少 1 个正例 + 负例（compressed / float opcode / atomics / CSR）。重点测试：LUI / AUIPC / JAL / JALR / BEQ / Branch 各类型 / LB/LW / ADDI（含负 imm）/ SLLI（shamt）/ SRAI（funct7=0x20）/ ECALL / FENCE

**GREEN**：实现 `decode(word: u32) -> Result<Instruction, ZkvmError>`：
1. `word & 0x3 != 0b11` → `UnsupportedInstruction("compressed")`
2. 提取 opcode → 按 opcode 分派提取 funct3/funct7/rd/rs1/rs2/imm/shamt
3. 立即数按 B/I/S/J-type 编码重组 + sign-extend to u32
4. 未知 opcode/funct3/funct7 → `UnsupportedInstruction`

**REFACTOR**：提取 `sign_extend_12()` / `decode_b_imm()` / `decode_j_imm()` 辅助函数

#### SubTask 3.1.3-3.1.4：execute + ~30 个测试

**RED**：每条 RV32I 指令至少 1 个 execute 测试 + 边界：
- ADDI / ADD（overflow wraps mod 2^32）/ SUB / SLT（有符号）/ SLTU（无符号）
- SRA（符号扩展）/ SRL（逻辑右移）/ SLL
- LW / LB（符号扩展）/ LBU（零扩展）/ SW / SB
- JAL（link=PC+4）/ JALR（目标 & !1）/ BEQ taken/not-taken
- LUI / AUIPC / FENCE（NOP）/ 写 x0 丢弃

**GREEN**：实现 `execute(state: &mut VmState, insn: Instruction) -> Result<StepLog, ZkvmError>`：
- 记录执行前 pc → 按 variant 执行 → 内存访问记入 `Vec<MemAccess>` → 非 branch/jump `pc += 4` → 返回 `StepLog`
- `x0` 写入统一通过 `write_register()` 拦截
- 移位量：R-type 用 `rs2 & 0x1F`，I-type 用 `shamt`
- 有符号比较：u32 as i32；无符号比较：直接 u32
- ECALL/EBREAK：仅 PC+4，syscall 分派由 executor 循环处理

**REFACTOR**：提取 `execute_alu()` / `execute_load()` / `execute_store()` / `execute_branch()` / `execute_jump()` 分组函数

### Step E — SubTask 3.3.1-3.3.4：execute_elf 循环

**文件**：`poker_zkvm/src/isa/executor.rs`

**依赖**：Step A-D + 新建 `HostContext`

**RED**（8 个测试）：
- 最小 halt 闭环（LUI + ECALL commit_output）
- `TraceTooLong`（用极小 step_limit 测试，避免跑 1M 步）
- `TraceHostMemoryExceeded`（用极小 mem_limit 测试）
- read_input + commit_output 完整 echo 闭环
- panic 终止执行
- 未知 syscall 返回 `Other("not implemented")`
- PC 越界（fetch 未初始化内存）→ `UninitializedRead`
- `HostContext::dispatch` 直接测试

**GREEN**：
- 常量：`MAX_ZKVM_TRACE_STEPS = 1_048_576`、`MAX_TRACE_HOST_MEMORY = 512MB`、`INPUT_BUFFER_ADDR = 0x10000000`
- `HostContext::new(input)` / `dispatch(&mut state, syscall_id, step_index) -> Result<(), ZkvmError>`
- `execute_elf(elf_bytes, input) -> Result<Trace, ZkvmError>`：
  1. `metadata = validate_elf(elf_bytes)?`
  2. `state = VmState::new()` + `state.load_elf(&metadata)?`
  3. `host = HostContext::new(input)` + `trace = Trace::new()`
  4. 循环：检查 halted → 检查 step_limit → 检查 mem_limit → `fetch_word` → `decode` → `execute` → 若 Ecall 调用 `host.dispatch` → `trace.push_step(Step::from_log(...))`
- 提供 `execute_elf_with_limits(elf_bytes, input, step_limit, mem_limit)` 供测试使用

**REFACTOR**：`HostContext::dispatch` 的 match 分支提取为独立方法

### 集成：cargo-zkvm `run` 子命令

Step E 完成后更新 `poker_zkvm/src/bin/cargo-zkvm.rs` 的 `cmd_run()`：从 stub 改为调用 `execute_elf`，更新现有测试（当前期望 "not implemented" 错误的 3 个测试需改为真实执行）。

## 六、测试覆盖汇总

| 步骤 | SubTask | 预估测试数 | 覆盖点 |
|------|---------|-----------|--------|
| Step A | 3.1.1 | 4 | 枚举构造 / Clone / Eq / variant 数量 |
| Step B | 3.4.1-3.4.5 | 8 | Trace CRUD / iter / serialize 往返 / bad magic / 溢出拒绝 / host_memory_usage |
| Step C | 3.2.1-3.2.4 | 10 | VmState 初始化 / x0 拦截 / 对齐检查 / 未初始化读取 / 16MB 上限 / load_elf / fetch_word |
| Step D (decode) | 3.1.2 | ~15 | 每格式类型 + 负例（compressed/float/atomics/CSR） |
| Step D (execute) | 3.1.3-3.1.4 | ~30 | 每条 RV32I + 边界（overflow/符号扩展/x0 丢弃） |
| Step E | 3.3.1-3.3.4 | 8 | halt 闭环 / TraceTooLong / TraceHostMemoryExceeded / echo / panic / 未知 syscall / PC 越界 / HostContext |
| **合计** | | **~75** | 从 160 → ~235 个测试 |

## 七、备选方案汇总（文档化到 alternatives.md）

| 决策 | 选择 | 否决方案 | 否决理由 |
|------|------|---------|---------|
| 内存模型 | 分页 BTreeMap + 位图 | HashMap<u32,u8> / 稠密 Vec / 分段 | 离散地址 / 16MB 限制 / 复杂度 |
| 内存对齐 | 自然对齐 | 全部强制 4B | 违反 RISC-V 语义，LB/SB 失效 |
| Instruction 枚举 | 逐 variant + 预解码 | 按 format 分组 / 存 raw word | execute 间接 / 重复解码 |
| StepLog vs Step | 分离 | execute 直接返回 Step | 违反纯函数性 |
| Syscall 分派 | HostContext 结构体 | Trait / 全 defer | 过度设计 / 无法测试闭环 |
| 序列化格式 | 自定义二进制 | serde+bincode / borsh / JSON | 无新依赖 / 流式 / 防溢出 |
| opcode 白名单 | decode 自包含 | 共享 RV32I_OPCODES | 跨模块耦合 / 职责不同 |
| load_elf 签名 | 接受 ElfMetadata | 接受 raw bytes | TOCTOU 消除 |
| ECALL 分派时机 | executor 循环中 | execute 内部 | 保持 execute 纯函数性 |

## 八、验证计划

每个 Step 完成后运行：
```bash
cargo test -p poker_zkvm                          # 全部测试通过
cargo clippy -p poker_zkvm --all-targets -- -D warnings  # 零警告
cargo build -p poker_zkvm --release               # release build 成功
```

全部 Step 完成后：
```bash
cargo build --workspace                            # workspace 集成
cargo test --workspace                             # workspace 全部测试
```

端到端验证（Step E 完成后）：
- `cargo zkvm run --elf <test_elf> --input <input>` 执行并输出步数
- 验证 trace serialize → deserialize 往返一致
- 验证 syscall 闭环（read_input → 计算 → commit_output）

## 九、Phase 4/5 衔接

- **Phase 4（Syscall）**：`HostContext` 将迁移到 `syscalls/mod.rs`，扩展为 `SyscallId` 枚举 + `Syscall` trait + 10 个 host 实现。Phase 3 的 `dispatch()` match 分支成为兼容层。
- **Phase 5（CCS）**：`compile_trace_to_ccs()` 消费 `Trace`——`Step.instruction` 选择子电路（a la carte），`Step.mem_access` 生成 byte-level permutation 约束，`Step.registers` 生成连续性约束。`MemAccess.size` 字段是 Phase 5 的关键。
