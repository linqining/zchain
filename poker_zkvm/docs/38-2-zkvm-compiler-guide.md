# ZKVM 编译器使用指南

> 文档编号：38-2  
> 对应模块：`poker_zkvm::compiler`、`poker_zkvm::bin::cargo_zkvm`

## 1. 概述

poker_zkvm 编译器将 Rust crate 编译为 RV32I ELF32 二进制文件，供 ZKVM 执行引擎消费。编译器固定使用 `riscv32i-unknown-none-elf` target，禁用浮点 / atomics / SIMD / inline asm。

## 2. CLI 工具 — cargo-zkvm

`cargo-zkvm` 是 ZKVM 的命令行工具，可作为 cargo 子命令或独立二进制运行。

### 2.1 安装

```bash
# 编译 cargo-zkvm 二进制
cargo build -p poker_zkvm --bin cargo-zkvm

# 或通过 cargo 子命令自动调用
cargo zkvm <subcommand>
```

### 2.2 子命令

#### `build` — 编译 crate 为 RV32I ELF + 校验

```bash
cargo zkvm build
```

流程：
1. 调用 `compile_crate` 编译当前目录 crate
2. 读取编译产物 ELF
3. 调用 `validate_elf` 进行 11 项安全校验
4. 输出 entry 地址 / segment 数量 / text 大小

#### `run` — 执行 ELF

```bash
cargo zkvm run --elf <PATH> --input <PATH>
```

执行 ELF 并输出步数 + output 长度。

#### `prove` — 生成证明

```bash
cargo zkvm prove --elf <PATH> --input <PATH> --output <PATH>
```

生成 proof + public_io 文件。

#### `verify` — 验证证明

```bash
cargo zkvm verify --proof <PATH> --public-io <PATH>
```

验证 proof 文件。

#### `test` — 扫描测试

```bash
cargo zkvm test
```

扫描 `#[zkvm::test]` 标记函数（Phase 3 stub，暂未实现）。

## 3. Rust API

### 3.1 CompilerConfig

```rust
use poker_zkvm::compiler::CompilerConfig;

let config = CompilerConfig {
    target: "riscv32i-unknown-none-elf",
    opt_level: 3,
    panic: "abort",
};
```

| 字段 | 类型 | 固定值 | 说明 |
|------|------|--------|------|
| `target` | `&'static str` | `"riscv32i-unknown-none-elf"` | RISC-V 32 位整数基础 ISA |
| `opt_level` | `u32` | `3` | 优化级别 |
| `panic` | `&'static str` | `"abort"` | panic 策略（不 unwind） |

### 3.2 compile_crate

```rust
use poker_zkvm::compiler::{compile_crate, CompilerConfig};
use std::path::Path;

let crate_path = Path::new("./my_circuit");
let config = CompilerConfig::default();
let elf_path = compile_crate(crate_path, &config)?;
```

调用 `cargo build --target riscv32i-unknown-none-elf --release`，通过 `RUSTFLAGS` 传递 `-C panic=abort -C opt-level=3`。

输出路径：`<crate_path>/target/riscv32i-unknown-none-elf/release/<crate_name>`

#### 错误

| 错误 | 原因 |
|------|------|
| `ZkvmError::Other` | 路径不存在 |
| `ZkvmError::Other` | Cargo.toml 缺失或无法解析 crate name |
| `ZkvmError::Other` | cargo 调用失败（含 stderr） |
| `ZkvmError::Other` | 编译产物不存在 |

### 3.3 validate_elf

```rust
use poker_zkvm::compiler::elf_validator::validate_elf;

let metadata = validate_elf(&elf_bytes)?;
```

执行 11 项安全校验，返回 `ElfMetadata`（含 entry / segments / text 信息）。

## 4. ELF 校验规则

`validate_elf` 按 spec L151-189 执行 11 项校验：

### 4.1 Header 校验

| # | 校验项 | 失败错误 |
|---|--------|---------|
| 1 | Magic = `0x7f ELF` | `InvalidZkProofFormat("ELF magic")` |
| 2 | Class = ELF32（非 ELF64） | `InvalidZkProofFormat("ELF64")` |
| 3 | Data = Little-Endian | `InvalidZkProofFormat("endianness")` |
| 4 | Machine = EM_RISCV (0xF3) | `InvalidZkProofFormat("e_machine")` |
| 5 | 无 `PT_DYNAMIC` 段（禁止动态链接） | `InvalidZkProofFormat("PT_DYNAMIC")` |
| 6 | 无 `DT_NEEDED` 条目 | `InvalidZkProofFormat("DT_NEEDED")` |

### 4.2 段校验

| # | 校验项 | 失败错误 |
|---|--------|---------|
| 7 | 所有 `PT_LOAD` 段地址 + 大小 ≤ `MAX_ZKVM_MEMORY` (16MB) | `OutOfMemory` |
| 8 | 段间无重叠 | `InvalidZkProofFormat("segment overlap")` |
| 9 | Entry 地址在可执行段内 | `InvalidZkProofFormat("entry")` |

### 4.3 指令校验

| # | 校验项 | 失败错误 |
|---|--------|---------|
| 10 | 可执行段大小 ≤ 64KB | `InvalidZkProofFormat("text too large")` |
| 11 | 所有指令属于 RV32I 子集（无 M/A/F/D/C 扩展） | `UnsupportedInstruction` |

### 4.4 安全特性

- 所有地址计算使用 `checked_add` 防 32-bit wrap
- TOCTOU 消除：`validate_elf` 返回 metadata 后 `load_elf` 直接使用，不重新解析

## 5. 内存构造 ELF（无需 RISC-V target）

当 `riscv32i-unknown-none-elf` target 未安装时，可通过内存字节构造 ELF32。

### 5.1 test_helpers 模块

启用 `test-helpers` feature 后可用：

```rust
use poker_zkvm::test_helpers::{
    addi, add, sw, lb, beq, bne, lui, ecall, nop,
    encode_text, build_elf32, build_nop_elf,
};

// 构造指令序列
let text = vec![
    addi(1, 0, 0),       // x1 = 0
    addi(2, 0, 1),       // x2 = 1
    addi(17, 0, 2),      // a7 = 2 (commit_output)
    ecall(),             // ECALL
];
let text_bytes = encode_text(&text);

// 构造最小 ELF32
let elf = build_elf32(0x1000, 0x1000, &text_bytes);
```

### 5.2 ELF32 布局

`build_elf32(entry, text_vaddr, text_bytes)` 生成：

```
[52B ELF32 header] [32B PH (PT_LOAD)] [text_bytes]
```

- Entry = `entry`
- 单 PT_LOAD 段：vaddr = `text_vaddr`，flags = PF_R|PF_X，align = 0x1000
- 无 section headers

### 5.3 RV32I 指令编码器

| 函数 | 指令 | 编码类型 |
|------|------|---------|
| `nop()` | NOP | I-type (ADDI x0, x0, 0) |
| `addi(rd, rs1, imm)` | ADDI | I-type |
| `add(rd, rs1, rs2)` | ADD | R-type |
| `sub(rd, rs1, rs2)` | SUB | R-type |
| `sw(rs2, rs1, imm)` | SW | S-type |
| `lw(rd, rs1, imm)` | LW | I-type |
| `lb(rd, rs1, imm)` | LB | I-type |
| `beq(rs1, rs2, imm)` | BEQ | B-type |
| `bne(rs1, rs2, imm)` | BNE | B-type |
| `lui(rd, imm20)` | LUI | U-type |
| `ecall()` | ECALL | I-type (opcode=0x73) |

通用编码器：

```rust
encode_r(opcode, funct3, funct7, rd, rs1, rs2) -> u32
encode_i(opcode, funct3, rd, rs1, imm12) -> u32
encode_s(opcode, funct3, rs1, rs2, imm12) -> u32
encode_b(opcode, funct3, rs1, rs2, imm13) -> u32  // 13 位有符号偏移
encode_u(opcode, rd, imm20) -> u32
encode_j(opcode, rd, imm21) -> u32
```

### 5.4 BEQ/BNE 偏移计算

B-type 指令的偏移是相对于当前指令的 byte 偏移：

```
target_pc = current_pc + offset
offset = (target_instr_index - current_instr_index) * 4
```

示例：从 instr 3 跳转到 instr 9（6 条指令后）：
```rust
beq(4, 0, 24);  // offset = 6 * 4 = 24
```

从 instr 8 跳回 instr 3（5 条指令前）：
```rust
beq(0, 0, -20);  // offset = -5 * 4 = -20
```

## 6. 编写 ZKVM 电路

### 6.1 最小电路

```rust
// 读取输入并原样输出（echo）
let text = vec![
    addi(17, 0, 1),   // a7 = 1 (read_input)
    addi(11, 0, 5),   // a1 = 5 (len)
    ecall(),           // read_input(a0=0 → HEAP_START, a1=5)
    addi(17, 0, 2),   // a7 = 2 (commit_output)
    ecall(),           // commit_output(a0=HEAP_START, a1=5) → halt
];
```

### 6.2 循环结构 — While-loop

推荐使用 while-loop（循环顶部 BEQ 检查 + 底部无条件 BEQ 跳回），避免 do-while 在 N=0 时的无限循环：

```rust
// Init
addi(4, 0, n as i32),  // counter = N

// Loop check
beq(4, 0, +24),         // if counter==0 → skip (6 instr ahead)

// Loop body
addi(4, 4, -1),         // counter--

// Jump back
beq(0, 0, -12),         // unconditional → loop check

// Output
...
```

### 6.3 Syscall 调用

通过寄存器传参：
- `a7` (x17) = syscall ID
- `a0` (x10) = 第一个参数
- `a1` (x11) = 第二个参数
- `a2` (x12) = 第三个参数

```rust
// SHA-256 哈希
addi(10, 20, 0),   // a0 = input_ptr
addi(11, 0, 32),   // a1 = input_len
addi(12, 20, 0),   // a2 = output_ptr
addi(17, 0, 4),    // a7 = 4 (sha256)
ecall(),            // → 32B 哈希写入 output_ptr
```

详见 [Syscall 参考](38-3-zkvm-syscall-reference.md)。

## 7. prelude 模块

`poker_zkvm::compiler::prelude` 提供 ZKVM 电路开发常用 re-export 和宏：

```rust
use poker_zkvm::compiler::prelude::*;

// 包含 field / transcript / error / ccs 等常用类型的 re-export
```

## 8. 前置条件

### 8.1 安装 RISC-V target（可选）

如果使用 `compile_crate` 编译真实 Rust crate：

```bash
rustup target add riscv32i-unknown-none-elf
```

如果未安装，可使用 `test_helpers` 模块内存构造 ELF（见第 5 节）。

### 8.2 Cargo.toml 配置

用户 crate 的 `Cargo.toml` 须配置：

```toml
[profile.release]
panic = "abort"
opt-level = 3
```
