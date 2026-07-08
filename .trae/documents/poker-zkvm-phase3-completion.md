# poker_zkvm Phase 3 收尾计划 — 修复 Step E 编译错误 + 集成 + 文档

> **范围**：Phase 3 剩余收尾工作 — 修复 executor.rs 已知编译错误并验证、cargo-zkvm `run` 子命令集成、alternatives.md Phase 3 章节补全
> **依赖**：先前已批准的 `.trae/documents/poker-zkvm-phase3-final-stretch.md`（含 D1-D8 设计决策，Step 1 已完成）
> **遵循**：spec.md L182-266（v1.4 FROZEN）、tasks.md L74-96、checklist.md L76-95
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多方案时选推荐方案，未选方案入文档

## 一、Summary

Phase 3 已完成 Step 1（验证 Step D — 65 isa 测试通过、clippy clean、237 总测试通过）。Step E（executor.rs）代码已写入但**存在 1 处编译错误**：`HeapStart` 被当作类型导入，实际是 `pub const HEAP_START: u32`。Step 3（cargo-zkvm 集成）和 Step 4（alternatives.md 文档）尚未开始。

本计划聚焦 3 项收尾工作，严格遵循 TDD：每步通过全部测试 + clippy clean 才能进入下一步。

## 二、Current State Analysis

### 已就绪产物（无需重做）

| 文件 | 步骤 | 状态 | 测试数 |
|------|------|------|--------|
| `poker_zkvm/src/trace/mod.rs` | Step 0/B | ✅ 已验证 | 15 |
| `poker_zkvm/src/isa/state.rs` | Step C | ✅ 已验证 | 10 |
| `poker_zkvm/src/isa/mod.rs` | Step D | ✅ 已验证 | 4(Step A) + 17(decode) + 27(execute) = 48 |
| `poker_zkvm/src/isa/executor.rs` | Step E | ❌ 代码已写，有编译错误 | 8（未运行） |
| `poker_zkvm/src/bin/cargo-zkvm.rs` | 集成 | ❌ `cmd_run` 为 stub | 3（现有，待更新） |
| `poker_zkvm/docs/alternatives.md` | 文档 | ❌ 缺 Phase 3 章节 | — |

### Step E 已知编译错误（已通过代码审查确认）

**位置**：`poker_zkvm/src/isa/executor.rs` 第 17 行 + 第 24 行

**当前错误代码**：
```rust
// 第 17 行
use crate::isa::state::{load_elf, HeapStart as HeapStartAlias, VmState};
// 第 24 行
const INPUT_BUFFER_ADDR: u32 = HeapStartAlias::HEAP_START;
```

**根因**：`state.rs` 第 35 行定义为 `pub const HEAP_START: u32 = 0x1000_0000;`（常量，非类型/结构体/枚举），不存在 `HeapStart` 这个路径。

**修复**：
```rust
// 第 17 行改为
use crate::isa::state::{load_elf, VmState, HEAP_START};
// 第 24 行改为
const INPUT_BUFFER_ADDR: u32 = HEAP_START;
```

### 其他代码审查确认（无需修改）

- `Instruction` enum derives `Clone`（[executor.rs:228](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/executor.rs#L228) `insn.clone()` 合法）
- `Instruction::Ecall` variant 存在（[isa/mod.rs:395](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs#L395)）
- `execute()` 对 `Ecall` 仅 `pc += 4`，syscall 分派由 executor 循环处理（[isa/mod.rs:837-846](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs#L837-L846)）
- `Trace::new/len/push_step/host_memory_usage` 全部为 `pub`（[trace/mod.rs:185-230](file:///Users/mac/projects/zchain/poker_zkvm/src/trace/mod.rs#L185-L230)）
- `Step::from_log(step_index, log)` 为 `pub`（[trace/mod.rs:151](file:///Users/mac/projects/zchain/poker_zkvm/src/trace/mod.rs#L151)）
- `MAX_TRACE_HOST_MEMORY` 为 `pub const`（[trace/mod.rs:17](file:///Users/mac/projects/zchain/poker_zkvm/src/trace/mod.rs#L17)）
- `isa` 为 `pub mod`（[lib.rs:35](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs#L35)），`executor` 为 `pub mod`（[isa/mod.rs:12](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs#L12)）
- 调用路径：`poker_zkvm::isa::executor::execute_elf(&elf_bytes, &input)`

### cargo-zkvm 当前 cmd_run（[cargo-zkvm.rs:80-89](file:///Users/mac/projects/zchain/poker_zkvm/src/bin/cargo-zkvm.rs#L80-L89)）

返回 stub 错误 `Err(format!("run not implemented (Phase 3...)"))`，3 个测试：
- `test_run_missing_elf_arg` — 参数校验（保留）
- `test_run_missing_input_arg` — 参数校验（保留）
- `test_run_returns_phase3_pending` — **需改为** 验证文件不存在时返回 IO 错误

## 三、Proposed Changes

---

### Step 1 — 修复 Step E 编译错误 + 验证

**文件**：`poker_zkvm/src/isa/executor.rs`（仅改 2 行）

**改动**：
1. 第 17 行：`use crate::isa::state::{load_elf, HeapStart as HeapStartAlias, VmState};` → `use crate::isa::state::{load_elf, VmState, HEAP_START};`
2. 第 24 行：`const INPUT_BUFFER_ADDR: u32 = HeapStartAlias::HEAP_START;` → `const INPUT_BUFFER_ADDR: u32 = HEAP_START;`

**验证命令**：
```bash
cargo test -p poker_zkvm --lib isa::executor   # 8 tests
cargo clippy -p poker_zkvm --lib -- -D warnings
cargo test -p poker_zkvm                       # 全 crate 不回归（预期 ~245 测试）
```

**预期结果**：
- executor.rs 8 测试全部通过
- 零 clippy 警告
- 全 crate 测试从 237 → ~245（新增 8 executor 测试）

**若失败的处置**：
- 若 8 测试中有失败 → 检查测试 ELF 构造与 executor 循环逻辑，按 TDD 修复
- 若 clippy 报新警告 → 修复（如 `missing_errors_doc` 已用 `#[allow]` 标注）
- 若 `test_execute_elf_read_input_commit_output_echo` 失败 → 检查 read_input 是否正确写入 `INPUT_BUFFER_ADDR`、commit_output 是否从 `a0` 读

---

### Step 2 — 集成：cargo-zkvm `run` 子命令

**文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`（更新 `cmd_run` + 相关测试）

**改动**：

#### 2.1 更新 `cmd_run`（[cargo-zkvm.rs:80-89](file:///Users/mac/projects/zchain/poker_zkvm/src/bin/cargo-zkvm.rs#L80-L89)）

从 stub 改为真实调用：

```rust
/// `run` 子命令 — 执行 ELF 并输出步数 + output 长度。
fn cmd_run(args: &[String]) -> Result<String, String> {
    let elf_path = parse_arg(args, "--elf")?;
    let input_path = parse_arg(args, "--input")?;

    let elf_bytes = std::fs::read(&elf_path)
        .map_err(|e| format!("failed to read ELF {}: {e}", elf_path.display()))?;
    let input = std::fs::read(&input_path)
        .map_err(|e| format!("failed to read input {}: {e}", input_path.display()))?;

    let result = poker_zkvm::isa::executor::execute_elf(&elf_bytes, &input)
        .map_err(|e| format!("execution failed: {e}"))?;

    Ok(format!(
        "Execution complete: {} steps, {} byte(s) output",
        result.trace.len(),
        result.output.len()
    ))
}
```

#### 2.2 更新文件头注释

第 5 行 `run --elf <PATH> --input <PATH>` — 执行 ELF（Phase 3 未就绪，stub）` 改为 `run --elf <PATH> --input <PATH>` — 执行 ELF 并输出步数 + output 长度`

#### 2.3 更新测试

- 保留 `test_run_missing_elf_arg`（参数校验不变）
- 保留 `test_run_missing_input_arg`（参数校验不变）
- **改名** `test_run_returns_phase3_pending` → `test_run_nonexistent_elf_file`，验证 ELF 文件不存在时返回 IO 错误（含 "failed to read ELF"），而非 "Phase 3"
- **新增** `test_run_executes_minimal_elf` — 构造临时最小 ELF 文件（复用 executor.rs 的 `build_test_elf` 模式：52B header + 32B PH + 8B .text = ADDI a7,2 + ECALL）+ 空 input 文件，执行成功，输出含 "Execution complete" + "2 steps"

**验证命令**：
```bash
cargo test -p poker_zkvm --bin cargo-zkvm
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

**预期结果**：
- cargo-zkvm 测试从 29 → 30（改 1 + 新增 1）
- 零 clippy 警告
- `cargo-zkvm` 二进制可构建

---

### Step 3 — 文档：alternatives.md Phase 3 章节

**文件**：`poker_zkvm/docs/alternatives.md`（在 `## 待补充` 之前插入 Phase 3 章节）

**内容**：在 [alternatives.md:145](file:///Users/mac/projects/zchain/poker_zkvm/docs/alternatives.md#L145) `## 待补充` 之前插入 Phase 3 章节，记录 D1-D8 + ECALL 分派时机共 9 项决策的备选方案。

#### Phase 3 章节结构

```markdown
## Phase 3 — ZKVM ISA 执行引擎

### 推荐方案（已实现）

#### 3.1 内存模型（D1）
- 分页 BTreeMap<u32, Box<Page>> + 字节级初始化位图
- PAGE_SIZE = 4096，每页含 data[4096] + init_mask[512]（1 bit/byte）
- total_allocated 跟踪已分配内存，超 16MB 返回 OutOfMemory

#### 3.2 内存对齐（D2）
- 自然对齐（标准 RISC-V 语义）：LW/SW→4B，LH/SH/LHU→2B，LB/SB/LBU→1B
- 未对齐返回 UnalignedAccess

#### 3.3 Instruction 枚举（D3）
- 逐 variant + 预解码操作数（rd/rs1/rs2/imm/shamt 直接存入）
- imm 为 u32（已符号扩展），shamt 为 u8（0-31）

#### 3.4 StepLog vs Step 分离（D4）
- execute() 返回 StepLog（纯函数，不含 step_index）
- executor 组装 Step（含 step_index）追加到 Trace

#### 3.5 HostContext（D5）
- 结构体 + dispatch(state, syscall_id) 方法
- Phase 3 实现 3 个 syscall：read_input(0x01) / commit_output(0x02) / panic(0x08)
- 其余 syscall 返回 Other("syscall N not implemented in Phase 3")

#### 3.6 Trace 序列化（D6）
- 自定义二进制流式格式：magic "TRCE" + version(4B) + num_steps(8B) + steps
- deserialize 用 checked_mul 防 u64 溢出 + 超 MAX_TRACE_HOST_MEMORY 早夭

#### 3.7 opcode 白名单（D7）
- decode 内部自包含 match（不共享 elf_validator 的 RV32I_OPCODES 常量）
- 职责不同：elf_validator 校验段内所有指令，decode 解码单条指令

#### 3.8 load_elf 签名（D8）
- 接受 &ElfMetadata（已校验的 owned 数据），消除 TOCTOU
- validate_elf 返回 owned ElfMetadata（data: Vec<u8>），类型层保证校验后不可篡改

#### 3.9 ECALL 分派时机
- executor 循环检测 Instruction::Ecall 后调 host.dispatch
- execute() 仅 pc+=4，保持纯函数性

### 备选方案

#### A — HashMap<u32, u8> 内存模型（未选）
- 描述：使用 HashMap<u32, u8> 存储字节级数据
- 未选理由：离散地址无序迭代（BTreeMap 确定性迭代更利于电路约束）；HashMap 哈希碰撞非确定；每字节一个 entry 内存开销大（4-8 倍膨胀）

#### B — 稠密 Vec<u8> 内存模型（未选）
- 描述：预分配 16MB Vec<u8>，按地址直接索引
- 未选理由：16MB 浪费（多数程序仅用几 KB）；无法支持稀疏地址（栈顶 0x80000000 与堆 0x10000000 之间巨大空洞）

#### C — 全部强制 4B 对齐（未选）
- 描述：所有内存访问强制 4 字节对齐
- 未选理由：违反 RISC-V 语义（LB/SB/LH/SH 是合法指令）；spec 明确自然对齐

#### D — 按 format 分组 Instruction 枚举（未选）
- 描述：Instruction 按 R/I/S/B/U 格式分组（如 Instruction::RType { funct3, funct7, rd, rs1, rs2 }）
- 未选理由：execute 需间接分派（先 match format 再 match funct3/funct7）；重复解码；类型安全性弱（无法在类型层区分 ADD vs SUB）

#### E — 存 raw word 的 Instruction（未选）
- 描述：Instruction 仅存 raw u32 word，execute 时再解码
- 未选理由：重复解码（decode 后 execute 再解一次）；execute 性能差；StepLog.instruction 序列化需二次解码

#### F — execute 直接返回 Step（未选）
- 描述：execute(state, insn) -> Result<Step, ZkvmError>，内部含 step_index
- 未选理由：execute 需要知道 step_index（需传入或从 state 读），破坏纯函数性；step_index 是 executor 维护的状态，不应泄漏到 execute

#### G — HostContext 用 trait object（未选）
- 描述：定义 Syscall trait，HostContext 持有 Box<dyn Syscall>
- 未选理由：过度设计（Phase 3 仅 3 个 syscall）；trait object 动态分派开销；Phase 4 扩展为 10 个 syscall 时再考虑

#### H — execute 内部分派 syscall（未选）
- 描述：execute() 检测 Ecall 后直接调 syscall
- 未选理由：破坏 execute 纯函数性（syscall 有副作用：读 input / 写 output / halt）；execute 签名需变为 &mut HostContext，耦合 executor 与 host；难以单元测试 execute

#### I — serde + bincode 序列化（未选）
- 描述：使用 serde derive + bincode 二进制序列化
- 未选理由：引入 serde + bincode 两个新依赖（spec 要求最小依赖）；bincode 不支持流式消费（需先反序列化整个 Trace）；无法自定义 checked_mul 防 u64 溢出

#### J — 接受 raw bytes 的 load_elf（未选）
- 描述：load_elf(state, elf_bytes: &[u8])，内部调 validate_elf
- 未选理由：TOCTOU 风险（校验后、加载前 elf_bytes 可能被修改）；类型层无法保证已校验；当前设计 validate_elf 返回 owned ElfMetadata，load_elf 消费 &ElfMetadata，类型安全

### 实现期发现
- `extern crate alloc`：std 环境下使用 alloc::collections::BTreeMap 需在 crate root 显式声明
- `MemoryMap::get_page` 返回 `Option<&Page>` 需用 `.map(|v| &**v)` 解引用 Box
- clippy `manual_is_multiple_of`：Rust 1.81+ `% n != 0` → `!is_multiple_of(n)`
- read_input 简化 ABI（Phase 3）：不读 a0/a1 参数，直接将 input 写入 INPUT_BUFFER_ADDR 并设 a0/a1；Phase 4 扩展为标准 ABI
- EBREAK 不作为 halt 信号：Phase 3 中 EBREAK 仅 pc+=4（与 ECALL 一致），halt 仅由 commit_output syscall 触发
```

**验证**：人工审阅 markdown 格式 + 与代码实现一致性。

---

## 四、Assumptions & Decisions

1. **Step E 代码逻辑正确**：除 `HeapStart` 导入错误外，executor.rs 其余实现（HostContext / execute_elf / 8 测试）通过代码审查确认正确。Step 1 验证若发现其他 bug，按 TDD 修复。
2. **read_input 简化 ABI**：Phase 3 的 `read_input` 不读 a0/a1 参数，直接将 input 写入 `INPUT_BUFFER_ADDR` 并设 a0/a1。Phase 4 扩展为标准 ABI。此决策降低测试 ELF 构造复杂度。
3. **EBREAK 不作为 halt 信号**：spec 未明确 EBREAK 语义，Phase 3 中 EBREAK 仅 `pc+=4`（与 ECALL 一致）。halt 仅由 `commit_output` syscall 触发。若程序无 halt 则跑到 `TraceTooLong`。
4. **测试 ELF 手工构造**：复用 Phase 2 `build_minimal_elf()` 模式，不依赖实际 rustc 交叉编译。
5. **`#![deny(missing_docs)]`**：所有新增公开项 + 枚举字段需 `///` doc comment。
6. **`#![deny(unsafe_code)]`**：无 unsafe。
7. **不新增 `--trace-out` 选项**：cargo-zkvm `run` 子命令仅输出步数 + output 长度，不写 trace 文件（Phase 5 约束编译器直接消费内存中的 Trace，序列化仅用于跨进程传输，Phase 10 prover 才需要）。

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

| 步骤 | 预估测试数 | 累计 |
|------|-----------|------|
| Step 1（验证 Step E） | +8 新增 | ~245 |
| Step 2（集成） | +1 新增 + 1 改名 | ~246 |
| Step 3（文档） | 0 | ~246 |
| **合计** | **+9 新增 + 1 改名** | **~237 → ~246** |

## 六、执行顺序（TDD 严格模式）

1. **Step 1**：修复 executor.rs 第 17 + 24 行 → 运行 `cargo test -p poker_zkvm --lib isa::executor` + `cargo clippy` → 8 测试通过 + 零警告 → 全 crate 不回归
2. **Step 2**：更新 cargo-zkvm `cmd_run` + 改名 / 新增测试 → 运行 `cargo test -p poker_zkvm --bin cargo-zkvm` + `cargo clippy --all-targets` → 全部通过 + 二进制可构建
3. **Step 3**：在 alternatives.md `## 待补充` 之前插入 Phase 3 章节（9 项决策 + 10 个备选方案 + 实现期发现）

每步必须通过全部测试 + clippy clean 才能进入下一步。

## 七、Phase 4 衔接

- **Phase 4（Syscall）**：`HostContext` 迁移到 `syscalls/mod.rs`，扩展为 `SyscallId` 枚举 + `Syscall` trait + 10 个 host 实现。Phase 3 的 `dispatch()` match 分支成为兼容层。`read_input` 扩展为标准 ABI（读 a0/a1 参数）。
- **Phase 5（CCS）**：`compile_trace_to_ccs()` 消费 `Trace`——`Step.instruction` 选择子电路（a la carte），`Step.mem_access` 生成 byte-level permutation 约束，`Step.registers` 生成连续性约束。`MemAccess.size` 字段是 Phase 5 的关键。
