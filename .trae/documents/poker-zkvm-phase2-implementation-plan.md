# poker_zkvm Phase 2 实现计划 — 前端编译流水线

> **范围**：Phase 2 全部 4 个 Task（2.1 / 2.2 / 2.3 / 2.4），按 TDD 严格模式顺序推进
> **依赖**：Phase 1.5 已完成（91 tests pass / clippy clean / release build / workspace build）
> **遵循**：spec.md L141-181（v1.4 FROZEN）、tasks.md L45-73、checklist.md L51-75
> **用户要求**：从基础开始实现，测试通过后才进入下一步；多方案时选推荐方案，未选方案入文档

## 一、Summary

Phase 2 实现 ZKVM 前端编译流水线：将用户 Rust 代码编译为 RV32I ELF，经强化校验后供 ZKVM 加载执行。本计划按依赖顺序分 4 个 Task 推进，每个 Task 必须通过全部测试（`cargo test -p poker_zkvm` + `cargo clippy -p poker_zkvm --all-targets -- -D warnings`）才能进入下一个 Task。

**Task 执行顺序**（依赖关系：2.2 是安全基础 → 2.1 编译器 → 2.3 prelude → 2.4 CLI）：
1. **Task 2.2** — ELF 强化校验器（`elf_validator.rs`）— 11 项校验 + 21 测试
2. **Task 2.1** — 编译器入口（`compiler/mod.rs`）— `CompilerConfig` + `compile_crate` + `_start` trampoline
3. **Task 2.3** — prelude 模块（`prelude.rs`）— re-export + `zkvm::entry` / `zkvm::test` 宏
4. **Task 2.4** — cargo-zkvm 二进制（`bin/cargo-zkvm.rs`）— 5 子命令

## 二、Current State Analysis

### 已就绪（Phase 1.5 产物）
- `poker_zkvm/src/error.rs` — 18 个 `ZkvmError` variants（FROZEN，不可新增）
  - ELF 格式错误 → `Other(String)`
  - RV32I 非法指令 → `UnsupportedInstruction(String)`
- `poker_zkvm/Cargo.toml` — `goblin = { workspace = true }`（workspace: `goblin 0.8, default-features=false, features=["elf32"]`）
- `poker_zkvm/src/lib.rs` — `#![deny(unsafe_code)]` + `#![deny(missing_docs)]`，声明 `pub mod compiler;`
- `poker_zkvm/src/compiler/mod.rs` — 声明 `pub mod elf_validator; pub mod prelude;`
- goblin 0.8.2 API 已验证：
  - `Elf::parse(bytes) -> Result<Elf>`，`Elf` struct 含 `header`/`program_headers`/`section_headers`/`dynamic`/`entry`/`is_64`/`little_endian`/`libraries` 字段
  - `ProgramHeader` struct：`p_type`/`p_flags`/`p_offset`/`p_vaddr`/`p_paddr`/`p_filesz`/`p_memsz`/`p_align`（均为 `u64`）
  - 常量：`EM_RISCV=243`、`PT_LOAD=1`、`PT_DYNAMIC=2`、`DT_NEEDED=1`、`PF_X=1`、`PF_W=2`、`PF_R=4`

### 待实现（4 个 stub 文件）
- `poker_zkvm/src/compiler/elf_validator.rs` — 7 行注释 stub
- `poker_zkvm/src/compiler/mod.rs` — 仅模块声明，无 `CompilerConfig` / `compile_crate`
- `poker_zkvm/src/compiler/prelude.rs` — 5 行注释 stub
- `poker_zkvm/src/bin/cargo-zkvm.rs` — 不存在，需新建

## 三、Proposed Changes

---

### Task 2.2：ELF 强化校验器（`elf_validator.rs`）— 基础，先实现

**文件**：`poker_zkvm/src/compiler/elf_validator.rs`（完整重写 7 行 stub）

**目标**：实现 `validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>`，执行 spec L155-168 的 10 项校验 + TOCTOU 消除，覆盖 tasks.md SubTask 2.2.1-2.2.11。

#### 类型定义

```rust
pub const MAX_ZKVM_MEMORY: usize = 16 * 1024 * 1024; // 16MB
pub const MAX_TEXT_SIZE: usize = 8 * 1024 * 1024;    // 8MB

#[derive(Clone, Debug)]
pub struct LoadedSegment {
    pub vaddr: u32,
    pub memsz: u32,
    pub data: Vec<u8>,    // owned 拷贝，消除 TOCTOU
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct ElfMetadata {
    pub entry: u32,
    pub segments: Vec<LoadedSegment>,
    pub text: Option<LoadedSegment>,
}
```

#### `validate_elf` 11 项校验（按依赖顺序）

| # | 校验项 | spec 要求 | 错误映射 |
|---|--------|-----------|----------|
| 1 | ELF 解析 | `Elf::parse(bytes)` | `Other(String)` |
| 2 | Header | `is_64 == false` + `little_endian == true` + `e_machine == EM_RISCV` | `Other(String)` |
| 3 | Section table 溢出 | `e_shoff.checked_add(e_shnum.checked_mul(e_shentsize)?)` | `Other(String)` |
| 4 | 无 PT_DYNAMIC | 遍历 program_headers 拒绝 `p_type == PT_DYNAMIC` | `Other(String)` |
| 5 | 无 DT_NEEDED | `elf.libraries.is_empty()` | `Other(String)` |
| 6 | 段地址范围 | 每个 PT_LOAD：`vaddr.checked_add(memsz)? <= MAX_ZKVM_MEMORY` | `Other(String)` |
| 7 | 段无重叠 | 按 vaddr 排序，`end > next.start` 检测 | `Other(String)` |
| 8 | 总内存限制 | 累加各段 memsz 用 `checked_add`，≤ MAX_ZKVM_MEMORY | `Other(String)` |
| 9 | entry 在 .text 内 | `text.vaddr <= entry < text.vaddr + text.memsz` | `Other(String)` |
| 10 | .text 大小 | `text.data.len() <= MAX_TEXT_SIZE` | `Other(String)` |
| 11 | RV32I 指令子集 | 4 字节步进扫描 opcode 白名单 | `UnsupportedInstruction(String)` |

#### RV32I opcode 白名单（bits[6:0]）

允许：`0x37 LUI` / `0x17 AUIPC` / `0x6F JAL` / `0x67 JALR` / `0x63 Branch` / `0x03 Load` / `0x23 Store` / `0x13 OP-IMM` / `0x33 OP` / `0x0F FENCE` / `0x73 SYSTEM`

细查：
- **compressed 拒绝**：`bits[1:0] != 0b11`
- **FENCE**：`funct3 == 0` 允许（FENCE），`funct3 == 1` 拒绝（fence.i — Zifencei 扩展）
- **SYSTEM**：`funct3 == 0` 允许（ECALL imm=0x000 / EBREAK imm=0x001），`funct3 ∈ {1,2,3}` 拒绝（CSR — Zicsr 扩展）
- 拒绝浮点（`0x07 FLW/FLD` / `0x27 FSW/FSD` / `0x53 FP-OP`）、atomics（`0x2F`）

#### 测试策略（21 个单元测试）

在 `#[cfg(test)] mod tests` 内定义 `build_minimal_elf()` 辅助函数构造手工 ELF32 字节：
- 52 字节 ELF32 header（magic `\x7fELF`、class=1、data=1、machine=243）
- 32 字节 program header（PT_LOAD，vaddr=0x1000，filesz=8，memsz=8，flags=PF_R|PF_X）
- 8 字节 .text：`LUI x1, 0` (0x000000b7) + `ECALL` (0x00000073)
- entry=0x1000

负例通过 mutator 函数修改特定偏移：`set_machine` / `set_seg_vaddr` / `set_seg_memsz` / `add_pt_dynamic` / `set_shnum_overflow` / `inject_fence_i` / `inject_compressed` / `inject_float` / `add_overlapping_seg` / `set_entry_outside_text`

| # | 测试名 | 验证 |
|---|--------|------|
| 1 | `test_valid_minimal_elf` | 合法 ELF 通过 |
| 2 | `test_reject_bad_magic` | 错误 magic |
| 3 | `test_reject_elf64` | ELFCLASS64 |
| 4 | `test_reject_big_endian` | ELFDATA2MSB |
| 5 | `test_reject_wrong_machine` | 非 EM_RISCV |
| 6 | `test_reject_wrap_attack` | addr=0xFFFFFFF0 + size=0x20 |
| 7 | `test_reject_seg_out_of_range` | vaddr ≥ MAX_ZKVM_MEMORY |
| 8 | `test_reject_entry_outside_text` | entry 不在 .text |
| 9 | `test_reject_overlapping_segments` | 段重叠 |
| 10 | `test_reject_pt_dynamic` | PT_DYNAMIC 段 |
| 11 | `test_reject_dt_needed` | DT_NEEDED |
| 12 | `test_reject_section_header_overflow` | e_shoff+e_shnum*e_shentsize 溢出 |
| 13 | `test_reject_text_too_large` | .text > 8MB |
| 14 | `test_reject_total_memory_too_large` | 总内存 > 16MB |
| 15 | `test_reject_fence_i` | fence.i |
| 16 | `test_reject_compressed` | 压缩指令 |
| 17 | `test_reject_float_load` | FLW |
| 18 | `test_reject_atomics` | 原子 |
| 19 | `test_reject_csr` | CSR |
| 20 | `test_toctou_ownership` | ElfMetadata.data 为 owned Vec |
| 21 | `test_metadata_contains_segments` | ElfMetadata 段信息正确 |

#### TDD 步骤

- **Step 0（RED）**：定义常量 + 类型 + `validate_elf` stub（返回 `Err(Other("todo"))`）+ 21 测试（编译通过但失败）
- **Step 1（GREEN）**：按依赖顺序实现 11 项校验，逐项让对应测试通过
- **Step 2（REFACTOR）**：提取重复逻辑、补充 doc comment、clippy 清理

#### 验证

```bash
cargo test -p poker_zkvm compiler::elf_validator  # 21 tests pass
cargo test -p poker_zkvm                          # 全 crate 不回归
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

---

### Task 2.1：编译器入口（`compiler/mod.rs`）

**文件**：`poker_zkvm/src/compiler/mod.rs`（在现有模块声明后追加）

**目标**：实现 `CompilerConfig` + `compile_crate` + `_start` trampoline 生成，覆盖 tasks.md SubTask 2.1.1-2.1.3。

#### 类型与函数

```rust
/// 编译器配置（spec L143, L149）。
#[derive(Clone, Debug)]
pub struct CompilerConfig {
    /// 目标 triple（固定 `riscv32i-unknown-none-elf`）
    pub target: &'static str,
    /// 优化级别（固定 3）
    pub opt_level: u32,
    /// panic 策略（固定 abort）
    pub panic: &'static str,
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self { target: "riscv32i-unknown-none-elf", opt_level: 3, panic: "abort" }
    }
}

/// 编译用户 crate 为 RV32I ELF（spec L145-150）。
///
/// 调用 `rustc --target riscv32i-unknown-none-elf -- -C panic=abort -C opt-level=3`，
/// 输出到 `target/riscv32i-unknown-none-elf/release/<crate_name>.elf`。
pub fn compile_crate(crate_path: &std::path::Path, config: &CompilerConfig) -> Result<std::path::PathBuf, ZkvmError>;

/// 生成 `_start` trampoline（spec L173-174）。
///
/// 从 `zkvm_read_input` syscall 读输入 → 调用用户 `main` → `zkvm_commit_output` 提交输出。
/// panic 自动转 `zkvm_panic` syscall。
fn generate_start_trampoline() -> String;
```

#### 实现要点

- `compile_crate` 用 `std::process::Command::new("rustc")` 调 rustc
- `_start` trampoline 为预生成的 Rust 源码字符串（含 `#[no_mangle] pub extern "C" fn _start()` + `zkvm_read_input` / `zkvm_commit_output` / `zkvm_panic` extern 声明）
- 编译失败时返回 `ZkvmError::Other(String)`（含 stderr 输出）

#### 测试策略（约 5 个测试）

- `test_compiler_config_default` — Default 值正确
- `test_generate_start_trampoline_contains_read_input` — 含 `zkvm_read_input`
- `test_generate_start_trampoline_contains_commit_output` — 含 `zkvm_commit_output`
- `test_generate_start_trampoline_contains_panic` — 含 `zkvm_panic`
- `test_compile_crate_missing_path` — 不存在路径返回 `Other`

> **注**：`compile_crate` 实际调用 rustc 的端到端测试需 RISC-V target 已安装，放 Task 2.4 端到端测试中。本 Task 仅测配置与 trampoline 生成。

#### 验证

```bash
cargo test -p poker_zkvm compiler  # 含 elf_validator 21 + compiler 新测试
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

---

### Task 2.3：prelude 模块（`prelude.rs`）

**文件**：`poker_zkvm/src/compiler/prelude.rs`（完整重写 5 行 stub）

**目标**：re-export `alloc` 类型 + 定义 `zkvm::entry` / `zkvm::test` 宏，覆盖 tasks.md SubTask 2.3.1-2.3.3。

#### 内容

```rust
pub use alloc::boxed::Box;
pub use alloc::format;
pub use alloc::string::String;
pub use alloc::vec;
pub use alloc::vec::Vec;

/// 标记用户入口函数（spec L172-174）。
///
/// 生成 `_start` trampoline 调用被标记函数。
#[macro_export]
macro_rules! entry {
    ($item:item) => { $item };
}

/// 标记 ZKVM 测试函数（spec L72, SubTask 2.3.3）。
#[macro_export]
macro_rules! test {
    ($item:item) => { $item };
}
```

#### 设计决策

- 宏使用 `#[macro_export]` 使其在 `zkvm::entry` / `zkvm::test` 路径可用
- 当前为 pass-through（标记后原样输出），实际 trampoline 生成在 Task 2.1 `compile_crate` 中通过 AST 分析处理
- `alloc` 依赖：poker_zkvm 已是 std crate，但 prelude 为 no_std 用户代码设计，使用 `alloc` crate 路径（需在 Cargo.toml 确认 `alloc` 可用 — std 环境下 `extern crate alloc` 自动可用）

#### 测试策略（约 4 个测试）

- `test_prelude_reexports_vec` — `Vec::<u8>::new()` 可用
- `test_prelude_reexports_string` — `String::new()` 可用
- `test_entry_macro_pass_through` — `#[entry] fn main() {}` 编译通过
- `test_test_macro_pass_through` — `#[test] fn my_test() {}` 编译通过

#### 验证

```bash
cargo test -p poker_zkvm compiler::prelude
cargo clippy -p poker_zkvm --all-targets -- -D warnings
```

---

### Task 2.4：cargo-zkvm 二进制（`bin/cargo-zkvm.rs`）

**文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`（新建）

**目标**：实现 5 子命令 CLI，覆盖 tasks.md SubTask 2.4.1-2.4.5。

#### 子命令

| 子命令 | 功能 | spec |
|--------|------|------|
| `build` | 调 `compile_crate` + `validate_elf` | L145-150 |
| `run --elf <path> --input <path>` | 加载 ELF + 输入执行（Phase 3 `VmState` 未就绪，本 Task 仅 stub 执行并报 `Other`） | L188 |
| `prove --elf <path> --input <path> --output <path>` | run + 生成 proof（Phase 10 未就绪，stub 报 `Other`） | — |
| `verify --proof <path> --public-io <path>` | 验证 proof（Phase 11 未就绪，stub 报 `Other`） | — |
| `test` | 扫描 `#[zkvm::test]` 标记，自动 compile + run + prove + verify | L72 |

#### 实现要点

- 手写 `std::env::args()` 解析（不引入 clap 依赖 — spec 未要求，保持依赖最小）
- `build` 子命令：找 `Cargo.toml` → `compile_crate` → 读 ELF → `validate_elf` → 输出路径
- `run`/`prove`/`verify`：解析参数，因下游 Phase 未实现，返回 `Other("phase X not implemented")` 错误退出
- `test`：扫描 `src/` 下 `#[zkvm::test]` 标记，同样 stub

#### 测试策略（约 3 个测试）

- `test_build_missing_cargo_toml` — 无 Cargo.toml 目录报错
- `test_run_missing_elf_arg` — 缺 `--elf` 参数报错
- `test_verify_missing_proof_arg` — 缺 `--proof` 参数报错

> **注**：端到端 `build` 测试需 RISC-V target 已安装，作为手动验证项（checklist L75），不纳入自动测试。

#### 验证

```bash
cargo test -p poker_zkvm --bin cargo-zkvm
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo build -p poker_zkvm --bin cargo-zkvm  # 二进制可构建
```

---

## 四、Assumptions & Decisions

| # | 决策 | 选择 | 理由 | 未选方案 |
|---|------|------|------|----------|
| 1 | Task 执行顺序 | 2.2 → 2.1 → 2.3 → 2.4 | 2.2 是安全基础（ELF 校验），2.1 编译器依赖 2.2 校验输出，2.3 prelude 被 2.1 trampoline 引用，2.4 CLI 串联全部 | 按 tasks.md 编号顺序 2.1→2.2→2.3→2.4（但 2.1 编译后无法校验，安全基础缺失） |
| 2 | ELF 解析库 | goblin 0.8（已有依赖） | 纯 Rust、无 unsafe、elf32 feature 已启用 | `object` crate（更重）、手写 ELF 解析器（重复造轮子） |
| 3 | 错误映射 | `Other(String)` + `UnsupportedInstruction(String)` | spec v1.4 FROZEN 18 variants 不可新增 | 新增 `InvalidElfFormat` variant（违反 FROZEN） |
| 4 | TOCTOU 消除 | `validate_elf` 返回 owned `ElfMetadata`（`data: Vec<u8>`） | 类型层保证校验后数据不可篡改 | 返回引用 + 校验后加锁（运行时开销） |
| 5 | .text 识别 | section header 名称 `.text` | goblin 提供 `shdr_strtab` 查找 | 按 PT_LOAD flags PF_X 猜测（不可靠，多个可执行段） |
| 6 | RV32I 校验 | opcode 白名单 + FENCE/SYSTEM 细查 | 覆盖 spec 全部拒绝条件 | 正则匹配指令编码（可读性差） |
| 7 | 测试 ELF 构造 | 手工字节拼接 | 精确控制每个字段测试负例 | 用 `object` crate 写 ELF（无法构造非法字段） |
| 8 | CLI 参数解析 | 手写 `std::env::args()` | spec 未要求，保持依赖最小 | 引入 `clap`（增加依赖）、`structopt`（已 deprecated） |
| 9 | `_start` trampoline | 预生成 Rust 源码字符串 | 简单直接，用户可审阅 | 过程宏生成（复杂度高，Phase 2 不必要） |
| 10 | `entry`/`test` 宏 | `#[macro_export]` pass-through | 当前仅标记，实际处理在 `compile_crate` AST 分析 | 过程宏（需单独 crate，过度工程） |
| 11 | `run`/`prove`/`verify` 子命令 | stub 返回 `Other("phase X not implemented")` | 下游 Phase 3/10/11 未实现 | 等全部 Phase 完成再实现 CLI（阻塞 Phase 2 验收） |

## 五、未选方案归档

所有未选方案将归档至 `poker_zkvm/docs/alternatives.md`（Phase 1.5.2 已创建），新增 Phase 2 章节，记录：
- ELF 解析库选择（goblin vs object vs 手写）
- CLI 参数解析（手写 vs clap）
- `_start` trampoline 生成（字符串 vs 过程宏）
- `entry`/`test` 宏实现（`macro_export` vs 过程宏）

## 六、Verification Steps

每个 Task 完成后执行：

```bash
# 1. 单元测试
cargo test -p poker_zkvm <module_path>

# 2. 全 crate 不回归
cargo test -p poker_zkvm

# 3. clippy 无警告
cargo clippy -p poker_zkvm --all-targets -- -D warnings

# 4. release 构建
cargo build -p poker_zkvm --release
```

Phase 2 全部完成后额外验证：

```bash
# 5. workspace 构建
cargo build --workspace

# 6. cargo-zkvm 二进制可构建
cargo build -p poker_zkvm --bin cargo-zkvm

# 7. 手动端到端（需 RISC-V target，checklist L75）
# cargo zkvm build  # 在 examples/hello_world 目录
```

## 七、Phase 2 完成标准（checklist.md L51-75）

- [ ] Task 2.2：ELF 强化校验 11 项 + 21 测试 + TOCTOU 消除（先实现）
- [ ] Task 2.1：`CompilerConfig` + `compile_crate` + `_start` trampoline
- [ ] Task 2.3：`zkvm::prelude` re-export + `entry`/`test` 宏
- [ ] Task 2.4：`cargo-zkvm` 5 子命令（build/run/prove/verify/test）
- [ ] 全 crate 测试通过 + clippy clean + release build
- [ ] `cargo-zkvm` 二进制可构建
- [ ] alternatives.md 更新 Phase 2 未选方案

## 八、Phase 3 衔接

Phase 2 完成后，Phase 3（ZKVM ISA 执行引擎）将消费 `ElfMetadata`：
- `load_elf(metadata: &ElfMetadata, state: &mut VmState)` — 按 `metadata.segments` 加载段到 VM 内存
- `isa::decode(word: u32)` — RV32I 解码器（与 elf_validator 的 opcode 白名单共享常量）
- `isa::execute(state, insn)` — 单步执行，产生 `StepLog`
