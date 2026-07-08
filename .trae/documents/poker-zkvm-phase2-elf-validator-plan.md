# poker\_zkvm Phase 2 — ELF 校验器实现计划（Task 2.2）

> **范围**：Task 2.2（ELF 强化校验器）— Phase 2 的基础组件，后续 Task 2.1/2.3/2.4 依赖此模块
> **依赖**：Phase 1.5 已完成（`error.rs` 18 variants FROZEN + `goblin 0.8` 已在 Cargo.toml）
> **遵循**：TDD 严格模式（RED → GREEN → REFACTOR），spec.md L153-168（v1.4 FROZEN），tasks.md SubTask 2.2.1-2.2.11
> **用户要求**：从基础开始实现，测试通过后才进入下一步

## Context

Phase 2 实现前端编译流水线（Rust → RV32I ELF → ZKVM 加载）。ELF 校验器是安全基础——所有 ELF 输入须经过校验后才使用（spec L17）。spec v1.2 补充了 TOCTOU 消除、`checked_add` 防 wrap 攻击、`PT_DYNAMIC` 拒绝等强化要求。

当前 `poker_zkvm/src/compiler/elf_validator.rs` 仅为 7 行占位注释。本计划实现完整的 11 项校验 + 单元测试。

## 一、当前状态

* [x] `compiler/mod.rs` 声明 `pub mod elf_validator;`（已存在）

* [x] `goblin = { version = "0.8", features = ["elf32"] }` 已在 Cargo.toml

* [x] `ZkvmError` 18 variants FROZEN — 使用 `Other(String)` 映射 ELF 格式错误，`UnsupportedInstruction(String)` 映射 RV32I 非法指令

* [ ] `elf_validator.rs` — 仅占位注释，需完整实现

## 二、类型定义

```rust
/// ZKVM 最大可用内存（spec L164）。
pub const MAX_ZKVM_MEMORY: usize = 16 * 1024 * 1024; // 16MB
/// .text 段最大大小（spec L163）。
pub const MAX_TEXT_SIZE: usize = 8 * 1024 * 1024; // 8MB

/// 已校验的 ELF 加载段（owned 数据，消除 TOCTOU）。
#[derive(Clone, Debug)]
pub struct LoadedSegment {
    /// 虚拟地址
    pub vaddr: u32,
    /// 内存大小
    pub memsz: u32,
    /// 段数据（owned 拷贝自输入字节切片）
    pub data: Vec<u8>,
    /// 段标志（PF_R/PF_W/PF_X）
    pub flags: u32,
}

/// 已校验的 ELF 元数据（`validate_elf` 返回，`load_elf` 消费）。
#[derive(Clone, Debug)]
pub struct ElfMetadata {
    /// 入口地址
    pub entry: u32,
    /// 所有可加载段
    pub segments: Vec<LoadedSegment>,
    /// .text 段（若存在），用于后续指令执行
    pub text: Option<LoadedSegment>,
}
```

**TOCTOU 消除**：`data: Vec<u8>` 为 owned 拷贝，`validate_elf` 返回后调用方无法修改字节。`load_elf(metadata, state)` 接受 `&ElfMetadata` 而非文件路径（Phase 3 实现）。

## 三、函数签名

```rust
/// 校验 ELF 字节切片并返回已解析的元数据（spec L155，消除 TOCTOU）。
///
/// 执行 11 项校验，任一失败返回 `ZkvmError`：
/// - `Other(String)` — ELF 格式/结构错误
/// - `UnsupportedInstruction(String)` — RV32I 非法指令
pub fn validate_elf(elf_bytes: &[u8]) -> Result<ElfMetadata, ZkvmError>;
```

私有 helper（无 `missing_docs` 约束）：

* `check_header(elf: &Elf) -> Result<(), ZkvmError>` — magic/class/endian/machine

* `check_section_table_overflow(elf: &Elf) -> Result<(), ZkvmError>` — e\_shoff + e\_shnum \* e\_shentsize

* `check_segments(elf: &Elf, bytes: &[u8]) -> Result<Vec<LoadedSegment>, ZkvmError>` — 地址范围 + checked\_add + 无重叠 + 大小限制

* `check_no_dynamic(elf: &Elf) -> Result<(), ZkvmError>` — 拒绝 PT\_DYNAMIC + DT\_NEEDED

* `check_entry_in_text(entry: u32, text: &LoadedSegment) -> Result<(), ZkvmError>`

* `check_rv32i(text: &[u8]) -> Result<(), ZkvmError>` — RV32I 指令子集扫描

* `check_relocations(elf: &Elf, segments: &[LoadedSegment]) -> Result<(), ZkvmError>`

* `extract_text_segment(segments: &[LoadedSegment], elf: &Elf) -> Result<Option<LoadedSegment>, ZkvmError>` — 通过 section header 名称识别 .text

## 四、RV32I 指令校验（SubTask 2.2.6）

遍历 `.text` 段每 4 字节：

1. **对齐**：4 字节步进（.text 段大小必须 4 字节对齐）
2. **非压缩**：`bits[1:0] == 0b11`（否则为 compressed 指令，拒绝）
3. **opcode 白名单**（bits\[6:0]）：

   * `0x37` LUI / `0x17` AUIPC / `0x6F` JAL / `0x67` JALR

   * `0x63` Branch / `0x03` Load / `0x23` Store

   * `0x13` OP-IMM / `0x33` OP

   * `0x0F` FENCE / `0x73` SYSTEM
4. **FENCE 细查**：`funct3 == 0` 为 FENCE（允许），`funct3 == 1` 为 fence.i（拒绝，Zifencei 扩展）
5. **SYSTEM 细查**：仅 ECALL（imm=0x000）和 EBREAK（imm=0x001），拒绝 CSR 指令（Zicsr 扩展，funct3 ∈ {1,2,3}）

拒绝列表：fence.i / 浮点（opcode 0x07/0x27/0x53）/ atomics（0x2F）/ SIMD / compressed

## 五、测试策略

### 测试 ELF 构造辅助

在 `#[cfg(test)] mod tests` 内定义 `build_minimal_elf()` 函数：

* 52 字节 ELF32 header（magic `\x7fELF`、class=1、data=1、machine=243）

* 1 个 PT\_LOAD 程序头：vaddr=0x1000、filesz=8、memsz=8、flags=PF\_R|PF\_X

* .text 数据：`LUI x1, 0` (0x000000b7) + `ECALL` (0x00000073)

* entry=0x1000

负例通过 mutator 函数修改特定偏移：

* `set_machine(bytes, 0xFFFF)` — 错误 machine

* `set_seg_vaddr(bytes, 0xFFFFFFF0)` + `set_seg_memsz(bytes, 0x20)` — wrap 攻击

* `add_pt_dynamic(bytes)` — 添加 PT\_DYNAMIC 段

* `set_shnum_overflow(bytes)` — e\_shoff + e\_shnum \* e\_shentsize 溢出

* `inject_fence_i(bytes)` — 在 .text 中注入 fence.i (0x0000100f)

* `inject_compressed(bytes)` — 注入 2 字节压缩指令

* `inject_float(bytes)` — 注入浮点 load (FLW, opcode=0x07)

* `add_overlapping_seg(bytes)` — 添加重叠段

* `set_entry_outside_text(bytes)` — entry 指向 .text 之外

### 测试列表（SubTask 2.2.11）

| #  | 测试名                                   | 验证内容                                           |
| -- | ------------------------------------- | ---------------------------------------------- |
| 1  | `test_valid_minimal_elf`              | 最小合法 ELF 通过校验                                  |
| 2  | `test_reject_bad_magic`               | 错误 magic 被拒                                    |
| 3  | `test_reject_elf64`                   | ELFCLASS64 被拒                                  |
| 4  | `test_reject_big_endian`              | ELFDATA2MSB 被拒                                 |
| 5  | `test_reject_wrong_machine`           | 非 EM\_RISCV 被拒                                 |
| 6  | `test_reject_wrap_attack`             | addr=0xFFFFFFF0 + size=0x20 被拒                 |
| 7  | `test_reject_seg_out_of_range`        | vaddr >= MAX\_ZKVM\_MEMORY 被拒                  |
| 8  | `test_reject_entry_outside_text`      | entry 不在 .text 范围内                             |
| 9  | `test_reject_overlapping_segments`    | 段重叠被拒                                          |
| 10 | `test_reject_pt_dynamic`              | PT\_DYNAMIC 段被拒                                |
| 11 | `test_reject_dt_needed`               | DT\_NEEDED 入口被拒                                |
| 12 | `test_reject_section_header_overflow` | e\_shoff + e\_shnum \* e\_shentsize 溢出被拒       |
| 13 | `test_reject_text_too_large`          | .text > 8MB 被拒                                 |
| 14 | `test_reject_total_memory_too_large`  | 总加载内存 > 16MB 被拒                                |
| 15 | `test_reject_fence_i`                 | fence.i 指令被拒                                   |
| 16 | `test_reject_compressed`              | 压缩指令被拒                                         |
| 17 | `test_reject_float_load`              | 浮点 load 被拒                                     |
| 18 | `test_reject_atomics`                 | 原子指令被拒                                         |
| 19 | `test_reject_csr`                     | CSR 指令被拒                                       |
| 20 | `test_toctou_ownership`               | validate\_elf 返回 owned ElfMetadata（data 为 Vec） |
| 21 | `test_metadata_contains_segments`     | ElfMetadata 含正确段信息                             |

## 六、实现步骤（TDD）

### Step 0：类型定义 + stub

* 定义 `MAX_ZKVM_MEMORY`、`MAX_TEXT_SIZE` 常量

* 定义 `LoadedSegment`、`ElfMetadata` 结构

* 定义 `validate_elf` 函数签名（stub 返回 `Err(Other("todo"))`）

* 编写全部 21 个测试（RED — 编译通过但测试失败）

### Step 1：GREEN — 逐项实现校验

按依赖顺序实现 11 项校验：

1. `check_header` — goblin `Elf::parse` 已校 magic，补 `is_64 == false` + `little_endian == true` + `e_machine == EM_RISCV`
2. `check_section_table_overflow` — `e_shoff.checked_add(e_shnum.checked_mul(e_shentsize)?)`
3. `check_segments` — 遍历 PT\_LOAD 段，`vaddr.checked_add(memsz) <= MAX_ZKVM_MEMORY`，累加总大小 `checked_add`
4. `check_no_dynamic` — 拒绝 `PT_DYNAMIC` program header + `elf.libraries.is_empty()`
5. 段无重叠 — 按 vaddr 排序后 `end > next.start` 检测
6. `check_entry_in_text` — entry ∈ `[text.vaddr, text.vaddr + text.memsz)`
7. `check_rv32i` — 4 字节步进扫描 opcode
8. `check_relocations` — 每个 reloc 的 `r_offset` 在某段范围内
9. `.text` 大小校验 — ≤ MAX\_TEXT\_SIZE
10. 整合所有检查，构造 `ElfMetadata` 返回

### Step 2：REFACTOR

* 提取重复逻辑

* 补充 doc comment（所有 `pub` 项）

* 验证 clippy 无警告

### Step 3：全量验证

* `cargo test -p poker_zkvm compiler::elf_validator` — 21 测试通过

* `cargo test -p poker_zkvm` — 全 crate 测试通过

* `cargo clippy -p poker_zkvm --all-targets -- -D warnings` — 无警告

## 七、后续 Task 概要（测试通过后推进）

* **Task 2.1**（`compiler/mod.rs`）：`CompilerConfig`（target=riscv32i-unknown-none-elf, opt-level=3, panic=abort）；`compile_crate` 用 `std::process::Command` 调 rustc；`compile_std_bindings` 生成 `_start` trampoline

* **Task 2.3**（`prelude.rs`）：re-export `alloc::{Vec, Box, String}` + `format!`；`zkvm::entry`/`zkvm::test` 用 `macro_rules!`

* **Task 2.4**（`bin/cargo-zkvm.rs`）：手写 arg 解析，5 子命令 build/run/prove/verify/test

## 八、关键设计决策

| # | 决策        | 选择                                                 | 理由                                |
| - | --------- | -------------------------------------------------- | --------------------------------- |
| 1 | 错误映射      | `Other(String)` + `UnsupportedInstruction(String)` | spec v1.4 FROZEN 18 variants 不可新增 |
| 2 | ELF 解析库   | goblin 0.8（已有依赖）                                   | 纯 Rust、无 unsafe、elf32 feature     |
| 3 | TOCTOU 消除 | `validate_elf` 返回 owned `ElfMetadata`              | 类型层保证校验后数据不可篡改                    |
| 4 | .text 识别  | section header 名称 `.text`                          | goblin 提供 `shdr_strtab` 查找        |
| 5 | RV32I 校验  | opcode 白名单 + FENCE/SYSTEM 细查                       | 覆盖 spec 全部拒绝条件                    |
| 6 | 测试 ELF 构造 | 手工字节拼接                                             | 需精确控制每个字段测试负例                     |

