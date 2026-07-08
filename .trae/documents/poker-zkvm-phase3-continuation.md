# poker_zkvm Phase 3 续作计划 — 验证 Step B + 实现 Step C/D/E + 集成

> **范围**：Phase 3 剩余工作 — 验证 Step B、实现 Step C/D/E、cargo-zkvm 集成
> **依赖计划**：`.trae/documents/poker-zkvm-phase3-implementation-plan.md`（已批准，含 D1-D8 设计决策）
> **遵循**：spec.md L182-266（v1.4 FROZEN）、tasks.md L74-96、checklist.md L76-95
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多方案时选推荐方案，未选方案入文档

## 一、Summary

Phase 3 计划已在 `poker-zkvm-phase3-implementation-plan.md` 中批准，采用 5 步顺序（A→B→C→D→E）解决 Task 3.1↔3.4 循环依赖。当前状态：

- **Step A**（Task 3.1.1）— ✅ 已完成：`isa/mod.rs` 40-variant `Instruction` 枚举 + 4 测试通过 + clippy clean
- **Step B**（Task 3.4.1-3.4.5）— ⏳ 已编写未验证：`trace/mod.rs` 905 行完整实现 + 13 测试，**待 `cargo test` + `cargo clippy` 验证**
- **Step C**（Task 3.2.1-3.2.4）— ❌ 待实现：`isa/state.rs` 当前为最小桩
- **Step D**（Task 3.1.2-3.1.4）— ❌ 待实现：`decode`/`execute` 为 stub
- **Step E**（Task 3.3.1-3.3.4）— ❌ 待实现：`isa/executor.rs` 为 7 行注释桩
- **集成**（Task 3.4 末）— ❌ 待实现：`cargo-zkvm.rs` `cmd_run()` 为 stub

本计划聚焦剩余 5 项工作，严格遵循 TDD（RED→GREEN→REFACTOR），每步通过全部测试后才进入下一步。

## 二、Current State Analysis

### 已就绪产物（无需重做）

1. **`poker_zkvm/src/isa/mod.rs`**（Step A 完成）
   - 40-variant `Instruction` 枚举（U/J/B/Load/Store/OP-IMM/OP/SYSTEM 分组）
   - 每个字段含 `///` doc comment（满足 `#![deny(missing_docs)]`）
   - `decode(word: u32)` / `execute(state, insn)` 为 stub，返回 `Err(Other("Step D pending"))`
   - 4 测试通过：`test_instruction_lui_constructible` / `test_instruction_clone_eq` / `test_instruction_ecall_ebreak_fence_constructible` / `test_instruction_variant_count`

2. **`poker_zkvm/src/trace/mod.rs`**（Step B 已编写，待验证）
   - `MemOp`（Read/Write）+ `MemAccess`（addr/op/value/size）+ `StepLog` + `Step`（含 step_index）+ `Trace`
   - `Trace::serialize()` / `Trace::deserialize()` 自定义二进制格式（magic "TRCE" + version=1）
   - `serialize_instruction()` / `deserialize_instruction()` 覆盖 40 variants（tag 0-39）
   - `deserialize` 三步法：magic 校验 → `checked_mul` 防 u64 溢出 + `MAX_TRACE_HOST_MEMORY` 早夭 → 逐 step 解析
   - 13 测试：empty / push+step / iter / MemAccess.size / serialize 往返（simple/with_mem/multiple） / bad_magic / bad_version / step_overflow / host_memory_usage / Step::from_log / MemOp 往返
   - **关键常量**：`MAX_TRACE_HOST_MEMORY = 512 * 1024 * 1024`（512MB，spec L258）

3. **`poker_zkvm/src/error.rs`**（Phase 0 FROZEN，18 variants）
   - Phase 3 可用 variants：`UnsupportedInstruction(String)` / `UnalignedAccess { addr }` / `UninitializedRead { addr }` / `TraceTooLong { actual, limit }` / `TraceHostMemoryExceeded { actual, limit }` / `OutOfMemory` / `InvalidSlot(u32)` / `Other(String)`
   - 注：`InvalidZkProofFormat(String)` 也被 Step B 的反序列化复用（trace 格式错误）

4. **`poker_zkvm/src/compiler/elf_validator.rs`**（Phase 2 完成）
   - `validate_elf(elf_bytes) -> Result<ElfMetadata, ZkvmError>` — 11 项校验 + TOCTOU 消除
   - `ElfMetadata { entry: u32, segments: Vec<LoadedSegment>, text: Option<LoadedSegment> }`
   - `LoadedSegment { vaddr: u32, memsz: u32, data: Vec<u8>, flags: u32 }`（owned 数据）
   - `MAX_ZKVM_MEMORY = 16 * 1024 * 1024`（16MB）/ `MAX_TEXT_SIZE = 8 * 1024 * 1024`（8MB）

5. **`poker_zkvm/src/lib.rs`** — `#![deny(unsafe_code)]` + `#![deny(missing_docs)]` + `extern crate alloc`；声明 `pub mod isa; pub mod trace;`

### 待实现 stub

- **`poker_zkvm/src/isa/state.rs`** — 当前仅 `VmState { pc, registers: [u32; 32] }` + `load_elf` stub 返回 `Err`
- **`poker_zkvm/src/isa/executor.rs`** — 7 行注释
- **`poker_zkvm/src/isa/mod.rs`** 的 `decode` / `execute` — 返回 `Err(Other("Step D pending"))`
- **`poker_zkvm/src/bin/cargo-zkvm.rs`** 的 `cmd_run` — 返回 `Err(Other("phase X not implemented"))`

## 三、Proposed Changes

---

### Step 0：验证 Step B（Trace 数据结构）

**文件**：`poker_zkvm/src/trace/mod.rs`（已编写，仅验证）

**动作**：运行测试 + clippy，确认 13 测试通过、零警告。若失败则修复后才能进入 Step C。

**验证命令**：
```bash
cargo test -p poker_zkvm --lib trace
cargo clippy -p poker_zkvm --lib -- -D warnings
cargo test -p poker_zkvm  # 全 crate 不回归
```

**预期结果**：13 trace 测试 + 4 isa 测试 + 已有 160 测试 = 177 测试通过，零 clippy 警告。

---

### Step C — SubTask 3.2.1-3.2.4：VmState + 内存模型

**文件**：`poker_zkvm/src/isa/state.rs`（完整重写最小桩）

**依赖**：`error.rs`（`ZkvmError`）、`compiler/elf_validator.rs`（`ElfMetadata` / `LoadedSegment` / `MAX_ZKVM_MEMORY`）

**设计决策**（继承已批准计划 D1/D2/D8）：
- **D1**：分页 BTreeMap + 字节级初始化位图（`PAGE_SIZE=4096`，`Page { data, init_mask }`，`MemoryMap { pages: BTreeMap<u32, Box<Page>>, total_allocated }`）
- **D2**：自然对齐（LW/SW→4B，LH/SH/LHU→2B，LB/SB/LBU→1B），未对齐返回 `UnalignedAccess { addr }`
- **D8**：`load_elf(state, &ElfMetadata)` 接受已校验元数据，消除 TOCTOU

#### 类型定义

```rust
use alloc::collections::BTreeMap;

const PAGE_SIZE: usize = 4096;
const STACK_TOP: u32 = 0x8000_0000;  // spec L264
const HEAP_START: u32 = 0x1000_0000; // spec L264

struct Page {
    data: [u8; PAGE_SIZE],
    init_mask: [u8; PAGE_SIZE / 8], // 1 bit/byte
}

pub struct MemoryMap {
    pages: BTreeMap<u32, Box<Page>>, // key = 页基址（addr & !(PAGE_SIZE-1)）
    total_allocated: usize,          // 用于 16MB 上限检查
}

pub struct VmState {
    pub pc: u32,
    pub registers: [u32; 32],
    pub memory: MemoryMap,
}
```

#### 方法清单

| 方法 | 签名 | 行为 |
|------|------|------|
| `VmState::new()` | `-> Self` | pc=0, registers=[0;32], memory=空, **sp(x2)=STACK_TOP** |
| `read_register` | `(&self, idx: u8) -> u32` | idx==0 返回 0，否则 registers[idx] |
| `write_register` | `(&mut self, idx: u8, val: u32)` | idx==0 丢弃，否则写 |
| `read_memory_byte` | `(&self, addr: u32) -> Result<u8, ZkvmError>` | 检查 init_mask，未初始化 → `UninitializedRead` |
| `write_memory_byte` | `(&mut self, addr: u32, val: u8) -> Result<(), ZkvmError>` | 分配页（检查 16MB），设 init bit |
| `read_memory_halfword` | `(&self, addr: u32) -> Result<u16, ZkvmError>` | addr%2!=0 → `UnalignedAccess`；LE 拼接 2 字节 |
| `write_memory_halfword` | `(&mut self, addr: u32, val: u16) -> Result<(), ZkvmError>` | addr%2!=0 → `UnalignedAccess`；LE 写 2 字节 |
| `read_memory_word` | `(&self, addr: u32) -> Result<u32, ZkvmError>` | addr%4!=0 → `UnalignedAccess`；LE 拼接 4 字节 |
| `write_memory_word` | `(&mut self, addr: u32, val: u32) -> Result<(), ZkvmError>` | addr%4!=0 → `UnalignedAccess`；LE 写 4 字节 |
| `fetch_word` | `(&self) -> Result<u32, ZkvmError>` | 从 `self.pc` 读 4 字节（pc%4==0 检查），未初始化 → `UninitializedRead` |
| `load_elf` | `(&mut state, &ElfMetadata) -> Result<(), ZkvmError>` | 遍历 segments，逐字节 write_memory_byte（标记初始化），设 state.pc=entry |

#### 关键实现要点

- 所有地址运算用 `checked_add` 防 u32 溢出
- `write_memory_byte` 分配新页时检查 `total_allocated + PAGE_SIZE > MAX_ZKVM_MEMORY` → `OutOfMemory`
- `Page::ensure_page()` 辅助：`pages.entry(page_base).or_insert_with(|| { total_allocated += PAGE_SIZE; Box::new(Page::zeroed()) })`
- `Page::is_initialized(addr)` 辅助：检查 `init_mask[byte_offset / 8] & (1 << (byte_offset % 8))`
- `load_elf` 用 `write_memory_byte` 逐字节写入（自动标记 init + 16MB 检查），避免绕过 init_mask

#### TDD 测试计划（10 个测试）

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_vmstate_new_defaults` | pc=0, registers=[0;32], sp(x2)=STACK_TOP=0x80000000 |
| 2 | `test_read_write_register_x0` | write_register(0, 42) 后 read_register(0)==0（x0 恒 0） |
| 3 | `test_read_write_register_normal` | write_register(5, 0xABCD) 后 read_register(5)==0xABCD |
| 4 | `test_write_read_memory_word_aligned` | write_memory_word(0x1000, 0xDEADBEEF) → read_memory_word(0x1000)==0xDEADBEEF（LE） |
| 5 | `test_unaligned_word_access` | read_memory_word(0x1001) → `UnalignedAccess { addr: 0x1001 }`；write 同理 |
| 6 | `test_unaligned_halfword_access` | read_memory_halfword(0x1001) → `UnalignedAccess` |
| 7 | `test_byte_access_any_alignment` | write_memory_byte(0x1001, 0xAB) → read_memory_byte(0x1001)==0xAB（字节任意对齐） |
| 8 | `test_uninitialized_read` | read_memory_byte(0x2000)（未写入）→ `UninitializedRead { addr: 0x2000 }` |
| 9 | `test_memory_limit_16mb` | 写入第 4097 页（4096*4096=16MB）→ `OutOfMemory` |
| 10 | `test_load_elf_and_fetch_word` | 构造 ElfMetadata（entry=0x1000, segment vaddr=0x1000 data=[0x13,0x05,0x00,0x00] NOP），load_elf 后 pc==0x1000，fetch_word()==0x00000513 |

#### TDD 步骤

- **RED**：定义 `Page` / `MemoryMap` / 扩展 `VmState` + 10 测试（编译通过但失败）
- **GREEN**：按方法清单逐个实现，逐个让测试通过
- **REFACTOR**：提取 `Page::ensure_page` / `Page::is_initialized` / `Page::set_initialized` 辅助方法；所有 `missing_docs` 补全

#### 验证

```bash
cargo test -p poker_zkvm --lib isa::state  # 10 tests pass
cargo test -p poker_zkvm                    # 全 crate 不回归
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### Step D — SubTask 3.1.2-3.1.4：decode + execute

**文件**：`poker_zkvm/src/isa/mod.rs`（替换 `decode` / `execute` stub）

**依赖**：Step A（`Instruction`）+ Step B（`StepLog`/`MemAccess`/`MemOp`）+ Step C（`VmState` + 内存方法）

**设计决策**（继承 D3/D4/D7）：
- **D3**：`Instruction` 逐 variant + 预解码操作数（Step A 已实现）
- **D4**：`execute()` 返回 `StepLog`（不含 step_index），executor 组装 `Step`
- **D7**：`decode()` 自包含——解码过程中自然拒绝非 RV32I opcode

#### SubTask 3.1.2：`decode(word: u32) -> Result<Instruction, ZkvmError>`

**实现逻辑**：

1. `word & 0x3 != 0b11` → `UnsupportedInstruction("compressed instruction")`
2. 提取 `opcode = word & 0x7F`
3. 按 opcode 分派，提取 funct3/funct7/rd/rs1/rs2/imm/shamt
4. 立即数按 B/I/S/U/J-type 编码重组 + sign-extend to u32
5. 未知 opcode/funct3/funct7 → `UnsupportedInstruction(format!("..."))`

**opcode 分派表**：

| opcode | 指令 | funct3 | funct7 | 立即数类型 |
|--------|------|--------|--------|-----------|
| 0x37 | LUI | - | - | U-type |
| 0x17 | AUIPC | - | - | U-type |
| 0x6F | JAL | - | - | J-type |
| 0x67 | JALR | 0 | - | I-type |
| 0x63 | BEQ/BNE/BLT/BGE/BLTU/BGEU | 0/1/4/5/6/7 | - | B-type |
| 0x03 | LB/LH/LW/LBU/LHU | 0/1/2/4/5 | - | I-type |
| 0x23 | SB/SH/SW | 0/1/2 | - | S-type |
| 0x13 | ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI | 0/2/3/4/6/7/1/5/5 | -/0x20 for SRAI | I-type / shamt |
| 0x33 | ADD/SUB/SLL/SLT/SLTU/XOR/SRL/SRA/OR/AND | 0/1/2/3/4/6/5/5/6/7 | 0x00/0x20 for SUB/SRA | R-type |
| 0x0F | FENCE | 0 | - | - |
| 0x73 | ECALL/EBREAK | 0 | imm=0x000/0x001 | - |
| 其余 | - | - | - | → `UnsupportedInstruction` |

**立即数解码辅助函数**：

```rust
fn sign_extend_12(imm12: u32) -> u32 {
    if imm12 & 0x800 != 0 { imm12 | 0xFFFFF000 } else { imm12 }
}
fn decode_i_imm(word: u32) -> u32 { sign_extend_12((word >> 20) & 0xFFF) }
fn decode_s_imm(word: u32) -> u32 {
    let imm = ((word >> 25) << 5) | ((word >> 7) & 0x1F);
    sign_extend_12(imm)
}
fn decode_b_imm(word: u32) -> u32 {
    let imm = (((word >> 31) & 0x1) << 12)
            | (((word >> 7) & 0x1) << 11)
            | (((word >> 25) & 0x3F) << 5)
            | (((word >> 8) & 0xF) << 1);
    sign_extend_12(imm)
}
fn decode_u_imm(word: u32) -> u32 { word & 0xFFFFF000 } // 已左移 12 位
fn decode_j_imm(word: u32) -> u32 {
    let imm = (((word >> 31) & 0x1) << 20)
            | (((word >> 12) & 0xFF) << 12)
            | (((word >> 20) & 0x1) << 11)
            | (((word >> 21) & 0x3FF) << 1);
    if imm & 0x100000 != 0 { imm | 0xFFE00000 } else { imm }
}
```

**TDD 测试计划（decode，~15 个测试）**：

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_decode_lui` | LUI x1, 0x1000 → `Lui { rd:1, imm:0x1000000 }` |
| 2 | `test_decode_auipc` | AUIPC x2, 0x1000 → `Auipc { rd:2, imm:0x1000000 }` |
| 3 | `test_decode_jal` | JAL x1, 8 → `Jal { rd:1, imm:8 }` |
| 4 | `test_decode_jalr` | JALR x1, x2, 4 → `Jalr { rd:1, rs1:2, imm:4 }` |
| 5 | `test_decode_beq` | BEQ x1, x2, 8 → `Beq { rs1:1, rs2:2, imm:8 }` |
| 6 | `test_decode_branch_all_types` | 6 个 branch 指令均正确解码 |
| 7 | `test_decode_lw_lb_lbu` | LW/LB/LBU 正确解码 |
| 8 | `test_decode_sw_sb` | SW/SB 正确解码 |
| 9 | `test_decode_addi_negative_imm` | ADDI x1, x0, -1 → `Addi { rd:1, rs1:0, imm:0xFFFFFFFF }` |
| 10 | `test_decode_slli_shamt` | SLLI x1, x2, 5 → `Slli { rd:1, rs1:2, shamt:5 }` |
| 11 | `test_decode_srai_funct7` | SRAI（funct7=0x20）正确解码为 `Srai` |
| 12 | `test_decode_add_sub` | ADD（funct7=0x00）/ SUB（funct7=0x20）区分 |
| 13 | `test_decode_ecall_ebreak` | ECALL(imm=0x000) / EBREAK(imm=0x001) |
| 14 | `test_decode_fence` | FENCE（funct3=0） |
| 15 | `test_decode_reject_compressed` | word=0x00000001（bits[1:0]=01）→ `UnsupportedInstruction` |
| 16 | `test_decode_reject_float_opcode` | FLW（opcode=0x07）→ `UnsupportedInstruction` |
| 17 | `test_decode_reject_csr` | CSR（opcode=0x73, funct3=1）→ `UnsupportedInstruction` |

#### SubTask 3.1.3-3.1.4：`execute(state, insn) -> Result<StepLog, ZkvmError>`

**实现逻辑**：

1. 记录执行前 `pc = state.pc`
2. 按 `insn` variant 执行：
   - **ALU（U/I/R-type）**：读 rs1/rs2（via `read_register`），计算结果，`write_register(rd, result)`
   - **Load**：`addr = read_register(rs1).wrapping_add(imm)`，按 size 调 `read_memory_*`，符号/零扩展后 `write_register(rd, val)`，记 `MemAccess { op: Read, ... }`
   - **Store**：`addr = read_register(rs1).wrapping_add(imm)`，`val = read_register(rs2)`，按 size 调 `write_memory_*`，记 `MemAccess { op: Write, ... }`
   - **Branch**：比较 rs1/rs2，taken 则 `state.pc = pc.wrapping_add(imm)`，否则 `state.pc = pc + 4`
   - **JAL**：`write_register(rd, pc + 4)`，`state.pc = pc.wrapping_add(imm)`
   - **JALR**：`target = (read_register(rs1).wrapping_add(imm)) & !1`，`write_register(rd, pc + 4)`，`state.pc = target`
   - **FENCE**：NOP（无副作用）
   - **ECALL/EBREAK**：仅 `state.pc = pc + 4`（syscall 分派由 executor 循环处理）
3. 非 branch/jump 指令：`state.pc = pc + 4`
4. 收集 `mem_access: Vec<MemAccess>`（读在前、写在后）
5. 返回 `StepLog { pc, instruction: insn.clone(), registers: state.registers, mem_access }`

**关键语义**：

- **有符号比较**（SLT/BLT）：`read_register(x) as i32`
- **无符号比较**（SLTU/BLTU）：直接 `u32`
- **SRA/SRAI**：符号扩展右移 — `((read_register(rs1) as i32) >> shamt) as u32`
- **SRL/SRLI**：逻辑右移 — `read_register(rs1) >> shamt`
- **R-type 移位量**：`read_register(rs2) & 0x1F`
- **ADD/ADDI overflow**：`wrapping_add`（mod 2^32，标准 RISC-V 语义）
- **JALR 目标**：`(rs1 + imm) & !1`（清最低位，保证 2 字节对齐）

**TDD 测试计划（execute，~30 个测试）**：

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_execute_addi` | ADDI x1, x0, 42 → x1=42, pc+=4 |
| 2 | `test_execute_addi_overflow_wraps` | ADDI x1, x2, 1 (x2=0xFFFFFFFF) → x1=0（wrapping） |
| 3 | `test_execute_add` | ADD x1, x2, x3 |
| 4 | `test_execute_sub` | SUB x1, x2, x3 → x1=x2-x3（wrapping） |
| 5 | `test_execute_slt_signed` | SLT x1, x2, x3（x2=-1, x3=1）→ x1=1（-1 < 1） |
| 6 | `test_execute_sltu_unsigned` | SLTU x1, x2, x3（x2=0xFFFFFFFF, x3=1）→ x1=0 |
| 7 | `test_execute_sra_sign_extend` | SRA x1, x2, x3（x2=0x80000000, shamt=4）→ x1=0xF8000000 |
| 8 | `test_execute_srl_logical` | SRL x1, x2, x3（x2=0x80000000, shamt=4）→ x1=0x08000000 |
| 9 | `test_execute_sll` | SLL x1, x2, x3（x2=1, shamt=4）→ x1=0x10 |
| 10 | `test_execute_lui` | LUI x1, 0x1000 → x1=0x1000000 |
| 11 | `test_execute_auipc` | AUIPC x1, 0x1000 (pc=0x1000) → x1=0x1000+0x1000000 |
| 12 | `test_execute_jal_link` | JAL x1, 8 (pc=0x1000) → x1=0x1004, pc=0x1008 |
| 13 | `test_execute_jalr_target` | JALR x1, x2, 4 (x2=0x2000) → x1=0x1004, pc=0x2004 |
| 14 | `test_execute_jalr_clear_low_bit` | JALR x1, x2, 5 (x2=0x2000) → pc=0x2004（&!1） |
| 15 | `test_execute_beq_taken` | BEQ x1, x2, 8 (x1==x2) → pc+=8 |
| 16 | `test_execute_beq_not_taken` | BEQ x1, x2, 8 (x1!=x2) → pc+=4 |
| 17 | `test_execute_blt_signed` | BLT x1, x2, 8 (x1=-1, x2=1) → taken |
| 18 | `test_execute_bgeu_unsigned` | BGEU x1, x2, 8 (x1=2, x2=1) → taken |
| 19 | `test_execute_lw` | LW x1, 0(x2)（先 SW）→ x1=内存值 |
| 20 | `test_execute_lb_sign_extend` | LB x1, 0(x2)（内存=0xFF）→ x1=0xFFFFFFFF |
| 21 | `test_execute_lbu_zero_extend` | LBU x1, 0(x2)（内存=0xFF）→ x1=0x000000FF |
| 22 | `test_execute_sw` | SW x1, 0(x2) → 内存=寄存器值（LE） |
| 23 | `test_execute_sb` | SB x1, 0(x2) → 内存低字节=寄存器低字节 |
| 24 | `test_execute_lh_lhu` | LH 符号扩展 / LHU 零扩展 |
| 25 | `test_execute_unaligned_lw` | LW x1, 1(x2) → `UnalignedAccess` |
| 26 | `test_execute_uninitialized_lw` | LW x1, 0(x2)（未初始化）→ `UninitializedRead` |
| 27 | `test_execute_fence_nop` | FENCE → 无副作用，pc+=4 |
| 28 | `test_execute_ecall_pc_advance` | ECALL → pc+=4（不分派 syscall） |
| 29 | `test_execute_ebreak_pc_advance` | EBREAK → pc+=4 |
| 30 | `test_execute_write_x0_discarded` | ADDI x0, x1, 42 → x0 仍为 0 |
| 31 | `test_execute_steplog_contents` | 验证 StepLog.pc / .instruction / .registers / .mem_access 正确 |

#### TDD 步骤

- **RED**：实现 `decode` + `execute` 框架 + ~46 测试（编译通过但失败）
- **GREEN**：按 opcode 分组逐个实现 decode，逐个让 decode 测试通过；按指令类型分组逐个实现 execute，逐个让 execute 测试通过
- **REFACTOR**：提取 `sign_extend_12` / `decode_i_imm` / `decode_s_imm` / `decode_b_imm` / `decode_u_imm` / `decode_j_imm` 辅助函数；提取 `execute_alu` / `execute_load` / `execute_store` / `execute_branch` / `execute_jump` 分组函数

#### 验证

```bash
cargo test -p poker_zkvm --lib isa  # Step A 4 + Step D ~46 = ~50 tests pass
cargo test -p poker_zkvm            # 全 crate 不回归
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### Step E — SubTask 3.3.1-3.3.4：execute_elf 循环 + HostContext

**文件**：`poker_zkvm/src/isa/executor.rs`（完整重写 7 行注释桩）

**依赖**：Step A-D + 新建 `HostContext`

**设计决策**（继承 D5/D8）：
- **D5**：`HostContext` 结构体，Phase 3 实现 3 个 syscall（read_input/commit_output/panic），其余返回 `Other("not implemented")`
- **D8**：`execute_elf` 内部调 `validate_elf` → `load_elf`，复用 Phase 2 校验

#### 类型定义

```rust
pub const MAX_ZKVM_TRACE_STEPS: usize = 1_048_576; // spec L257
pub const INPUT_BUFFER_ADDR: u32 = 0x1000_0000;   // HEAP_START，spec L264

pub struct HostContext {
    input: Vec<u8>,
    output: Vec<u8>,
    halted: bool,
}

pub struct ExecuteResult {
    pub trace: Trace,
    pub output: Vec<u8>,
}
```

#### 方法清单

| 方法 | 签名 | 行为 |
|------|------|------|
| `HostContext::new(input)` | `-> Self` | input=传入, output=空, halted=false |
| `HostContext::dispatch` | `(&mut self, state: &mut VmState, syscall_id: u32, step_index: u64) -> Result<(), ZkvmError>` | 按 a7 分派 |
| `HostContext::is_halted` | `(&self) -> bool` | 返回 halted |
| `HostContext::into_output` | `(self) -> Vec<u8>` | 返回 output |
| `execute_elf` | `(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError>` | 默认上限执行 |
| `execute_elf_with_limits` | `(elf_bytes, input, step_limit, mem_limit) -> Result<ExecuteResult, ZkvmError>` | 可配置上限（测试用） |

#### syscall 分派表（Phase 3 最小集）

| syscall_id | 名称 | Phase 3 行为 |
|-----------|------|-------------|
| 0x01 | read_input | 将 input 拷贝到 VM 内存 INPUT_BUFFER_ADDR，写长度到 a0 指向地址，a0=INPUT_BUFFER_ADDR，a1=input.len() |
| 0x02 | commit_output | 从内存读 [a0, a0+a1) 存入 output，halted=true |
| 0x08 | panic | 从内存读 [a0, a0+a1) 消息，返回 `Err(Other("zkvm_panic: {msg}"))` |
| 其余 | — | 返回 `Err(Other(format!("syscall {id} not implemented in Phase 3")))` |

#### `execute_elf_with_limits` 执行循环

```rust
pub fn execute_elf_with_limits(
    elf_bytes: &[u8],
    input: &[u8],
    step_limit: usize,
    mem_limit: usize,
) -> Result<ExecuteResult, ZkvmError> {
    // 1. 校验 + 加载 ELF
    let metadata = crate::compiler::elf_validator::validate_elf(elf_bytes)?;
    let mut state = VmState::new();
    crate::isa::state::load_elf(&mut state, &metadata)?;

    // 2. 初始化 host + trace
    let mut host = HostContext::new(input.to_vec());
    let mut trace = Trace::new();

    // 3. 执行循环
    loop {
        // 检查 halt
        if host.is_halted() { break; }

        // 检查步数上限
        if trace.len() >= step_limit {
            return Err(ZkvmError::TraceTooLong { actual: trace.len() + 1, limit: step_limit });
        }

        // 检查 host 内存上限
        let usage = trace.host_memory_usage();
        if usage > mem_limit {
            return Err(ZkvmError::TraceHostMemoryExceeded { actual: usage, limit: mem_limit });
        }

        // fetch + decode + execute
        let word = state.fetch_word()?;
        let insn = crate::isa::decode(word)?;
        let step_index = trace.len() as u64;
        let log = crate::isa::execute(&mut state, insn.clone())?;

        // ECALL → syscall 分派
        if matches!(insn, crate::isa::Instruction::Ecall) {
            let syscall_id = state.read_register(17); // a7 = x17
            host.dispatch(&mut state, syscall_id, step_index)?;
        }

        // 组装 Step 并追加
        let step = Step::from_log(step_index, log);
        trace.push_step(step);
    }

    Ok(ExecuteResult { trace, output: host.into_output() })
}
```

#### `execute_elf`（默认上限）

```rust
pub fn execute_elf(elf_bytes: &[u8], input: &[u8]) -> Result<ExecuteResult, ZkvmError> {
    execute_elf_with_limits(
        elf_bytes,
        input,
        MAX_ZKVM_TRACE_STEPS,
        crate::trace::MAX_TRACE_HOST_MEMORY,
    )
}
```

#### TDD 测试计划（8 个测试）

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_execute_elf_minimal_halt` | 构造最小 ELF（LUI x1,0 + 准备 a7=0x02 commit_output + ECALL）→ 执行 halted，output 正确 |
| 2 | `test_execute_elf_trace_too_long` | 用 step_limit=2 执行无限循环 ELF → `TraceTooLong` |
| 3 | `test_execute_elf_host_memory_exceeded` | 用 mem_limit=100 执行 → `TraceHostMemoryExceeded` |
| 4 | `test_execute_elf_read_input_commit_output_echo` | 完整 echo 闭环：read_input → 复制 → commit_output |
| 5 | `test_execute_elf_panic_terminates` | 触发 zkvm_panic → `Other("zkvm_panic: ...")` |
| 6 | `test_execute_elf_unknown_syscall` | a7=0x03（Poseidon，Phase 4）→ `Other("syscall 3 not implemented")` |
| 7 | `test_execute_elf_pc_out_of_bounds` | ELF 入口指向未初始化内存 → `UninitializedRead` |
| 8 | `test_host_context_dispatch_direct` | 直接测 `HostContext::dispatch` read_input/commit_output/panic 分支 |

**测试 ELF 构造**：复用 Phase 2 `elf_validator` 测试中的 `build_minimal_elf()` 辅助函数模式，手工构造 ELF32 字节（52B header + 32B program header + .text 字节序列）。

#### TDD 步骤

- **RED**：定义 `HostContext` / `ExecuteResult` + `execute_elf` / `execute_elf_with_limits` stub + 8 测试
- **GREEN**：实现 `HostContext::dispatch` 3 个 syscall 分支 → 实现 `execute_elf_with_limits` 循环
- **REFACTOR**：`HostContext::dispatch` 的 match 分支提取为 `dispatch_read_input` / `dispatch_commit_output` / `dispatch_panic` 独立方法

#### 验证

```bash
cargo test -p poker_zkvm --lib isa::executor  # 8 tests pass
cargo test -p poker_zkvm                       # 全 crate 不回归
cargo clippy -p poker_zkvm --lib -- -D warnings
```

---

### 集成 — cargo-zkvm `run` 子命令

**文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`（更新 `cmd_run`）

**当前状态**：`cmd_run` 为 stub，返回 `Err(Other("phase X not implemented"))`

**改动**：
- `cmd_run` 从 stub 改为调用 `poker_zkvm::isa::executor::execute_elf(&elf_bytes, &input)`
- 读取 `--elf` 参数指向的文件字节
- 读取 `--input` 参数指向的文件字节（若未提供则空 `&[]`）
- 输出：步数 + output 长度（可选 `--trace-out` 写序列化 trace）
- 更新现有 3 个测试：当前期望 "not implemented" 错误的测试改为真实执行或调整

**验证**：
```bash
cargo test -p poker_zkvm --bin cargo-zkvm
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm
```

---

## 四、文档更新

**文件**：`poker_zkvm/docs/alternatives.md`（追加 Phase 3 未选方案）

已批准计划中 D1-D8 的否决方案汇总（9 项决策），追加到 alternatives.md：

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

## 五、Assumptions & Decisions

1. **Step B 已正确编写**：假设 `trace/mod.rs` 905 行实现通过验证（Step 0 确认）。若发现 bug，修复后继续。
2. **自然对齐（D2）**：spec L265「4-byte word 对齐」解读为 word 级访问的对齐要求；LB/SB 支持任意对齐是 RISC-V 标准语义。此决策已在批准计划中确认。
3. **ECALL 不在 execute 内分派**：`execute()` 仅 `pc+=4`，executor 循环检测 `Ecall` 后调 `host.dispatch`。保持 `execute` 纯函数性（D5）。
4. **Phase 3 仅 3 个 syscall**：read_input(0x01) / commit_output(0x02) / panic(0x08)，其余 7 个 defer 到 Phase 4，返回 `Other("not implemented")`。
5. **测试 ELF 手工构造**：复用 Phase 2 `build_minimal_elf()` 模式，不依赖实际 rustc 交叉编译（RISC-V target 可能未安装）。
6. **`#![deny(missing_docs)]`**：所有新增公开项 + 枚举字段需 `///` doc comment。
7. **`#![deny(unsafe_code)]`**：无 unsafe，所有内存操作通过安全 API。
8. **`extern crate alloc`**：`MemoryMap` 用 `alloc::collections::BTreeMap`（lib.rs 已声明）。

## 六、验证计划

### 每步完成后

```bash
cargo test -p poker_zkvm                          # 全部测试通过
cargo clippy -p poker_zkvm --all-targets -- -D warnings  # 零警告
cargo build -p poker_zkvm --release               # release build 成功
```

### Phase 3 全部完成后

```bash
cargo build --workspace                            # workspace 集成
cargo test --workspace                             # workspace 全部测试
cargo build -p poker_zkvm --bin cargo-zkvm         # CLI 二进制可构建
```

### 端到端验证（Step E + 集成完成后）

- `cargo zkvm run --elf <test_elf> --input <input>` 执行并输出步数
- 验证 trace serialize → deserialize 往返一致
- 验证 syscall 闭环（read_input → 计算 → commit_output）

### 测试覆盖汇总

| 步骤 | SubTask | 预估测试数 | 累计 |
|------|---------|-----------|------|
| Step 0（验证） | 3.4.1-3.4.5 | 13（已有） | 177 |
| Step C | 3.2.1-3.2.4 | 10 | 187 |
| Step D (decode) | 3.1.2 | ~17 | 204 |
| Step D (execute) | 3.1.3-3.1.4 | ~31 | 235 |
| Step E | 3.3.1-3.3.4 | 8 | 243 |
| 集成 | — | ~3（更新） | ~246 |
| **合计** | | **+86 新增** | **160 → ~246** |

## 七、执行顺序（TDD 严格模式）

1. **Step 0**：运行 `cargo test -p poker_zkvm --lib trace` + `cargo clippy`，验证 Step B（13 测试）。若失败修复。
2. **Step C**：RED（10 测试）→ GREEN（VmState + MemoryMap）→ REFACTOR → 验证
3. **Step D**：RED（~48 测试）→ GREEN（decode + execute）→ REFACTOR → 验证
4. **Step E**：RED（8 测试）→ GREEN（execute_elf + HostContext）→ REFACTOR → 验证
5. **集成**：更新 cargo-zkvm `cmd_run` → 更新测试 → 验证
6. **文档**：追加 alternatives.md Phase 3 未选方案

每步必须通过全部测试 + clippy clean 才能进入下一步。

## 八、Phase 4/5 衔接

- **Phase 4（Syscall）**：`HostContext` 迁移到 `syscalls/mod.rs`，扩展为 `SyscallId` 枚举 + `Syscall` trait + 10 个 host 实现。Phase 3 的 `dispatch()` match 分支成为兼容层。
- **Phase 5（CCS）**：`compile_trace_to_ccs()` 消费 `Trace`——`Step.instruction` 选择子电路（a la carte），`Step.mem_access` 生成 byte-level permutation 约束，`Step.registers` 生成连续性约束。`MemAccess.size` 字段是 Phase 5 的关键。
