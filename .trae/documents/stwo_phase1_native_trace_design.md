# Phase 1 详细设计：Trace 重写 + 旧代码清理

> **版本**：1.0（2026-07-20）
> **所属迁移计划**：[hypernova_to_stwo_migration_plan_v2.md](file:///Users/mac/projects/zchain/.trae/documents/hypernova_to_stwo_migration_plan_v2.md)
> **工期**：2-3 周
> **前置条件**：v2 计划已获用户批准
> **后续阶段**：Phase 2（CPU AIR 重写）

***

## 1. 目标与范围

### 1.1 目标

1. **删除所有 Hypernova 相关代码**（~7,761 行），使 `poker_zkvm` 不再依赖 BN254 Fr 域转换
2. **重写 trace 生成**：emulator 执行后直接输出 `Vec<Vec<M31>>`（列主序），32-bit 值用 4×8-bit limb 表达
3. **设计新列布局**：参考 Nexus zkVM 0.3.6 `column.rs`，预计 60-80 列
4. **更新 `lib.rs`**：移除旧模块声明，保留与证明系统无关的基础模块

### 1.2 范围

**包含**：
- 代码删除（`ccs/`、`hypernova/`、`fold/`、`recursion/`、`pcs/ipa.rs`、`cyclic/`、`cyclegold.rs`、`stwo_backend/field.rs`、`stwo_backend/column_layout.rs`、`stwo_backend/air/cpu.rs`、`constraints/`）
- 新建 `stwo_backend/trace_native.rs`（原生 M31 trace 生成）
- 新建 `stwo_backend/column_layout_v2.rs`（4×8-bit limb 列布局）
- 更新 `lib.rs` 模块声明
- 更新 `Cargo.toml`（移除 BN254 相关依赖，保留 stwo 依赖）
- 单元测试

**不包含**：
- AIR 约束实现（Phase 2）
- 内存/syscall 约束（Phase 3）
- precompile 迁移（Phase 4）
- 递归证明（Phase 5）

***

## 2. 代码删除清单（精确到文件）

### 2.1 完整删除的文件/目录

| 路径 | 行数 | 说明 | 删除原因 |
|------|------|------|---------|
| `poker_zkvm/src/ccs/` | 565 | CCS 结构（SparseMatrix, Ccs, CcsInstance） | Stwo 用 AIR，不需要 CCS |
| `poker_zkvm/src/hypernova/` | ~1,200 | Hypernova fold/sumcheck/proof/verifier | 完全放弃 Hypernova |
| `poker_zkvm/src/fold/` | 4,776 | Hypernova fold loop（LCCCS/CCCCS/fold_step） | Stwo 无 fold |
| `poker_zkvm/src/recursion/` | 2,985 | 旧 CycleFold 电路（circuit_bn254/grumpkin） | 用 Stwo Verifier AIR 替代 |
| `poker_zkvm/src/pcs/ipa.rs` | ~200 | IPA PCS over BN254 | Stwo 用 FRI PCS |
| `poker_zkvm/src/cyclic/` | ~150 | CycleFold 辅助 | 不再需要 |
| `poker_zkvm/src/cyclegfold.rs` | ~56 | CycleFold 辅助 | 不再需要 |
| `poker_zkvm/src/stwo_backend/field.rs` | 134 | 域转换工具（`fr_to_m31_single`） | 原生 M31，不需要转换 |
| `poker_zkvm/src/stwo_backend/column_layout.rs` | ~400 | 旧 2×30-bit limb 布局 | 替换为 4×8-bit |
| `poker_zkvm/src/stwo_backend/air/cpu.rs` | ~1300 | 旧 CPU AIR（fold 改写版本） | 替换为 cpu_v2.rs |
| `poker_zkvm/src/stwo_backend/air/control_flow.rs` | - | 旧控制流 AIR | 合并到 cpu_v2.rs |
| `poker_zkvm/src/stwo_backend/air/memory.rs` | - | 旧内存 AIR | Phase 3 重写 |
| `poker_zkvm/src/stwo_backend/air/syscall.rs` | - | 旧 syscall AIR | Phase 3 重写 |
| `poker_zkvm/src/stwo_backend/air/opcode_table.rs` | - | 旧 opcode table | 合并到 cpu_v2.rs |
| `poker_zkvm/src/stwo_backend/trace.rs` | 40 | 旧 trace 转换 | 替换为 trace_native.rs |
| `poker_zkvm/src/constraints/` | ~1,200 | 旧 CCS 约束编译 | Stwo 用 AIR 约束 |
| `poker_zkvm/src/lookup/` | - | 旧 lookup 模块 | Stwo 用 LogupTraceGenerator |
| `poker_zkvm/src/prover/` | - | 旧 Hypernova prover | 替换为 stwo_backend/prover.rs |
| `poker_zkvm/src/verifier.rs` | - | 旧 Hypernova verifier | 替换为 stwo_backend/verifier.rs |
| `poker_zkvm/src/transcript.rs` | - | 旧 Fiat-Shamir transcript | Stwo 用 Blake2sChannel |
| `poker_zkvm/src/crypto_arkworks.rs` | - | arkworks BN254 绑定 | 不再需要 BN254 |

### 2.2 保留但需修改的文件

| 路径 | 修改内容 |
|------|---------|
| `poker_zkvm/src/lib.rs` | 移除已删除模块的 `pub mod` 声明，更新模块文档 |
| `poker_zkvm/src/error.rs` | 移除 Hypernova/CCS/IPA 相关错误变体，新增 Stwo 相关错误 |
| `poker_zkvm/src/field.rs` | 移除 BN254 Fr 相关代码（如不再被 isa/trace 引用），保留 M31 类型别名 |
| `poker_zkvm/src/trace/mod.rs` | 保留 Step/Trace 结构，新增 `to_m31_trace()` 方法 |
| `poker_zkvm/src/isa/` | 保留（与证明系统无关），移除对 Fr 的依赖 |
| `poker_zkvm/src/compiler/` | 保留（ELF 校验与证明无关） |
| `poker_zkvm/src/syscalls/` | 保留（host 函数定义） |
| `poker_zkvm/src/stwo_backend/mod.rs` | 更新子模块声明 |
| `poker_zkvm/src/stwo_backend/prover.rs` | 保留骨架，Phase 2 填充 |
| `poker_zkvm/src/stwo_backend/verifier.rs` | 保留骨架，Phase 5 填充 |
| `poker_zkvm/Cargo.toml` | 移除 ark-bn254/ark-ec 等依赖，保留 stwo 依赖 |

### 2.3 保留原样的文件

| 路径 | 说明 |
|------|------|
| `poker_zkvm/src/isa/mod.rs` | RISC-V Instruction enum 定义 |
| `poker_zkvm/src/isa/executor.rs` | RISC-V 执行器 |
| `poker_zkvm/src/isa/state.rs` | 执行状态 |
| `poker_zkvm/src/compiler/elf_validator.rs` | ELF 校验 |
| `poker_zkvm/src/compiler/mod.rs` | 编译器入口 |
| `poker_zkvm/src/compiler/prelude.rs` | 预定义常量 |
| `poker_zkvm/src/syscalls/*` | host 函数（poseidon/sha256/keccak/merkle/game/gas） |
| `poker_zkvm/src/precompiles/*` | precompile 逻辑（Phase 4 迁移到 AIR） |
| `poker_zkvm/src/test_helpers.rs` | 测试辅助 |

***

## 3. 新列布局设计（4×8-bit limb）

### 3.1 设计原则

参考 Nexus zkVM 0.3.6 `prover/src/column.rs`：

1. **32-bit 值用 4×8-bit limb**：每个 limb ∈ [0, 255] ⊂ [0, M31_MAX]，可直接 `M31::from(u8)`
2. **指令 indicator 每指令 1 列**：简化约束度数（`is_add * constraint` 度数 = 1 + constraint_degree）
3. **进位/借位只在 16-bit 边界**：4 limb 只需 2 个 carry（byte1→2, byte3→外）
4. **padding 用 IsPadding 列**：末尾填充行标记

### 3.2 列布局定义（v2）

```rust
// poker_zkvm/src/stwo_backend/column_layout_v2.rs

use stwo::core::fields::m31::M31;

/// 列布局常量（Phase 1，4×8-bit limb 方案）
///
/// 参考 Nexus zkVM 0.3.6 prover/src/column.rs
/// 32-bit 值用 4×8-bit limb，每个 limb < 256 < M31_MAX
pub const WORD_LIMB_COUNT: usize = 4;
pub const WORD_SIZE: usize = 4;

// ===== 主 trace 列索引 =====

// PC（4×8-bit limb）
pub const COL_PC_BASE: usize = 0;          // col 0-3
pub const COL_PC_NEXT_BASE: usize = 4;     // col 4-7
pub const COL_PC_NEXT_AUX_BASE: usize = 8; // col 8-11

// 操作数索引（1 列 each）
pub const COL_OP_A: usize = 12;
pub const COL_OP_B: usize = 13;
pub const COL_OP_C: usize = 14;

// 进位/借位标志（2 列 each，16-bit 边界）
pub const COL_CARRY_FLAG_BASE: usize = 15; // col 15-16
pub const COL_BORROW_FLAG_BASE: usize = 17;// col 17-18

// 立即数标志
pub const COL_IMM_C: usize = 19;

// 指令值（4×8-bit limb）
pub const COL_INSTR_VAL_BASE: usize = 20;  // col 20-23

// 操作数值（4×8-bit limb each）
pub const COL_VALUE_A_BASE: usize = 24;    // col 24-27
pub const COL_VALUE_A_EFF_BASE: usize = 28;// col 28-31
pub const COL_VALUE_B_BASE: usize = 32;    // col 32-35
pub const COL_VALUE_C_BASE: usize = 36;    // col 36-39

// 指令 indicator（每指令 1 列，共 35 个指令类别）
pub const COL_IS_BASE: usize = 40;         // col 40-74（35 列）
// 具体偏移：
pub const IS_LUI: usize = 40;
pub const IS_AUIPC: usize = 41;
pub const IS_JAL: usize = 42;
pub const IS_JALR: usize = 43;
pub const IS_BEQ: usize = 44;
pub const IS_BNE: usize = 45;
pub const IS_BLT: usize = 46;
pub const IS_BGE: usize = 47;
pub const IS_BLTU: usize = 48;
pub const IS_BGEU: usize = 49;
pub const IS_LOAD: usize = 50;             // LB/LH/LW/LBU/LHU 共用
pub const IS_STORE: usize = 51;            // SB/SH/SW 共用
pub const IS_ADDI: usize = 52;
pub const IS_SLTI: usize = 53;
pub const IS_SLTIU: usize = 54;
pub const IS_XORI: usize = 55;
pub const IS_ORI: usize = 56;
pub const IS_ANDI: usize = 57;
pub const IS_SLLI: usize = 58;
pub const IS_SRLI: usize = 59;
pub const IS_SRAI: usize = 60;
pub const IS_ADD: usize = 61;
pub const IS_SUB: usize = 62;
pub const IS_SLL: usize = 63;
pub const IS_SLT: usize = 64;
pub const IS_SLTU: usize = 65;
pub const IS_XOR: usize = 66;
pub const IS_SRL: usize = 67;
pub const IS_SRA: usize = 68;
pub const IS_OR: usize = 69;
pub const IS_AND: usize = 70;
pub const IS_FENCE: usize = 71;
pub const IS_ECALL: usize = 72;
pub const IS_EBREAK: usize = 73;
pub const IS_PADDING: usize = 74;

// 辅助变量（4×8-bit limb each，4 个 helper）
pub const COL_HELPER1_BASE: usize = 75;    // col 75-78
pub const COL_HELPER2_BASE: usize = 79;    // col 79-82
pub const COL_HELPER3_BASE: usize = 83;    // col 83-86
pub const COL_HELPER4_BASE: usize = 87;    // col 87-90

// 分支相关
pub const COL_TAKEN: usize = 91;           // 分支跳转标记
pub const COL_BRANCH_COND: usize = 92;     // 分支条件中间值
pub const COL_SHAMT: usize = 93;           // 移位量

// 符号位
pub const COL_SGN_A: usize = 94;
pub const COL_SGN_B: usize = 95;
pub const COL_SGN_C: usize = 96;

// 总列数
pub const NUM_COLUMNS: usize = 97;
```

### 3.3 与 Nexus 的差异

| 维度 | Nexus zkVM 0.3.6 | poker_zkvm v2 | 理由 |
|------|------------------|---------------|------|
| 总列数 | ~150 | 97 | poker_zkvm 指令集更小（无 M 扩展独立 chip） |
| M 扩展 | 独立 chip（MUL/MULH/DIV/REM） | 暂不含（Phase 2 后置） | poker_zkvm 当前无 M 扩展需求 |
| 内存列 | Ram1-4ValCur/Prev + TsPrev | Phase 3 添加 | Phase 1 仅 CPU trace |
| Range check | 独立 range8/16/32/128/256 | 暂不含 | Phase 2 用 LogUp 替代 |
| Helper | 4 个 × 4 limb | 4 个 × 4 limb | 相同 |

***

## 4. trace_native.rs 详细设计

### 4.1 核心数据结构

```rust
// poker_zkvm/src/stwo_backend/trace_native.rs

use stwo::core::fields::m31::M31;
use crate::trace::{Step, Trace};

/// 原生 M31 trace（列主序）
///
/// 参考 Nexus zkVM 0.3.6 TracesBuilder
/// 每列是一个 Vec<M31>，列数 = NUM_COLUMNS
#[derive(Debug, Clone)]
pub struct NativeTrace {
    /// 列主序存储：cols[col_idx][row_idx]
    pub cols: Vec<Vec<M31>>,
    /// log2(行数)
    pub log_size: u32,
}

impl NativeTrace {
    /// 创建指定 log_size 的空 trace（所有列初始化为 0）
    pub fn new(log_size: u32) -> Self {
        let num_rows = 1usize << log_size;
        Self {
            cols: vec![vec![M31::from(0u32); num_rows]; super::column_layout_v2::NUM_COLUMNS],
            log_size,
        }
    }

    /// 获取列数
    pub fn num_columns(&self) -> usize {
        self.cols.len()
    }

    /// 获取行数
    pub fn num_rows(&self) -> usize {
        1usize << self.log_size
    }

    /// 填充一行
    pub fn fill_row(&mut self, row: usize, values: &[M31]) {
        assert!(values.len() <= self.cols.len(), "values 超过列数");
        for (col, val) in values.iter().enumerate() {
            self.cols[col][row] = *val;
        }
    }

    /// 填充 32-bit 值到 4×8-bit limb 列
    pub fn fill_word(&mut self, row: usize, col_base: usize, value: u32) {
        let bytes = value.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            self.cols[col_base + i][row] = M31::from(byte as u32);
        }
    }
}
```

### 4.2 u32 ↔ M31 limb 转换

```rust
/// 将 u32 拆分为 4 个 M31 limb（little-endian 8-bit）
///
/// 参考 Nexus zkVM 0.3.6 prover/src/trace/utils.rs IntoBaseFields
/// 每个 limb ∈ [0, 255] ⊂ [0, M31_MAX]，无溢出风险
pub fn u32_to_m31_limbs(value: u32) -> [M31; 4] {
    let bytes = value.to_le_bytes();
    [
        M31::from(bytes[0] as u32),
        M31::from(bytes[1] as u32),
        M31::from(bytes[2] as u32),
        M31::from(bytes[3] as u32),
    ]
}

/// 将 4 个 M31 limb 重建为 u32（逆操作）
pub fn m31_limbs_to_u32(limbs: &[M31; 4]) -> u32 {
    let bytes = [
        limbs[0].0 as u8,
        limbs[1].0 as u8,
        limbs[2].0 as u8,
        limbs[3].0 as u8,
    ];
    u32::from_le_bytes(bytes)
}
```

### 4.3 从 Step 生成 trace 行

```rust
/// 将 emulator Step 转换为 trace 行（97 个 M31 值）
///
/// 参考 Nexus zkVM 0.3.6 fill_main_trace
pub fn step_to_m31_row(step: &Step, is_padding: bool) -> Vec<M31> {
    let mut row = vec![M31::from(0u32); super::column_layout_v2::NUM_COLUMNS];

    // PC（4×8-bit limb）
    let pc_limbs = u32_to_m31_limbs(step.pc);
    for (i, limb) in pc_limbs.iter().enumerate() {
        row[super::column_layout_v2::COL_PC_BASE + i] = *limb;
    }

    // next_pc（4×8-bit limb）
    let next_pc_limbs = u32_to_m31_limbs(step.next_pc);
    for (i, limb) in next_pc_limbs.iter().enumerate() {
        row[super::column_layout_v2::COL_PC_NEXT_BASE + i] = *limb;
    }

    // 指令值（4×8-bit limb）
    let instr_limbs = u32_to_m31_limbs(step.raw_instruction);
    for (i, limb) in instr_limbs.iter().enumerate() {
        row[super::column_layout_v2::COL_INSTR_VAL_BASE + i] = *limb;
    }

    // 操作数值（4×8-bit limb each）
    if let Some(result) = &step.result {
        // rs1_val, rs2_val, rd_val 从 result 提取
        // ... 具体字段取决于 Step 结构
    }

    // 指令 indicator（one-hot）
    let opcode = instruction_category(&step.instruction);
    let is_col = super::column_layout_v2::COL_IS_BASE + opcode;
    row[is_col] = M31::from(1u32);

    // padding 标记
    if is_padding {
        row[super::column_layout_v2::IS_PADDING] = M31::from(1u32);
    }

    row
}
```

### 4.4 TraceBuilder

```rust
/// Trace 构造器
pub struct TraceBuilder {
    trace: NativeTrace,
    next_row: usize,
}

impl TraceBuilder {
    pub fn new(log_size: u32) -> Self {
        Self {
            trace: NativeTrace::new(log_size),
            next_row: 0,
        }
    }

    /// 添加一个真实 step
    pub fn add_step(&mut self, step: &Step) {
        let row = self.next_row;
        let values = step_to_m31_row(step, false);
        self.trace.fill_row(row, &values);
        self.next_row += 1;
    }

    /// 填充 padding 行（用最后一个 step 的状态，IsPadding=1）
    pub fn fill_padding(&mut self, last_step: &Step) {
        let num_rows = self.trace.num_rows();
        while self.next_row < num_rows {
            let row = self.next_row;
            let mut values = step_to_m31_row(last_step, true);
            // padding 行：PC = last_step.next_pc，next_pc = last_step.next_pc
            // 所有 indicator 清零，IsPadding = 1
            for col in super::column_layout_v2::COL_IS_BASE..
                (super::column_layout_v2::COL_IS_BASE + 35) {
                values[col] = M31::from(0u32);
            }
            values[super::column_layout_v2::IS_PADDING] = M31::from(1u32);
            self.trace.fill_row(row, &values);
            self.next_row += 1;
        }
    }

    /// 计算 log_size（取 ≥ num_steps 的最小 2 的幂）
    pub fn compute_log_size(num_steps: usize) -> u32 {
        let mut log_size = 0u32;
        while (1usize << log_size) < num_steps {
            log_size += 1;
        }
        log_size.max(10) // 最小 log_size = 10（1024 行，SIMD 对齐）
    }

    /// finalize
    pub fn finalize(self) -> NativeTrace {
        assert_eq!(self.next_row, self.trace.num_rows(),
            "TraceBuilder: 必须先 fill_padding 再 finalize");
        self.trace
    }
}
```

### 4.5 从 emulator Trace 生成 NativeTrace

```rust
/// 从 emulator Trace 生成 NativeTrace
///
/// 主入口函数
pub fn trace_to_native(trace: &Trace) -> NativeTrace {
    let num_steps = trace.steps().len();
    let log_size = TraceBuilder::compute_log_size(num_steps);
    let mut builder = TraceBuilder::new(log_size);

    // 添加真实 steps
    for step in trace.steps() {
        builder.add_step(step);
    }

    // 填充 padding
    if let Some(last_step) = trace.steps().last() {
        builder.fill_padding(last_step);
    }

    builder.finalize()
}
```

***

## 5. lib.rs 更新

### 5.1 新的 lib.rs 结构

```rust
//! # poker_zkvm — Stwo Circle STARK 零知识虚拟机
//!
//! 基于 Stwo（Circle STARK + AIR + FRI on M31）的 RISC-V zkVM。
//! 完全放弃 Hypernova 兼容，trace 原生在 M31 中生成。
//!
//! ## 模块层次
//!
//! - **Layer 0**：[`error`] / [`field`] — 基础类型
//! - **Layer 1**：[`compiler`] / [`isa`] / [`trace`] / [`syscalls`] — 前端 + 执行
//! - **Layer 2**：[`stwo_backend`] — Stwo 证明后端（AIR + FRI）
//! - **Layer 3**：[`precompiles`] — Precompile 逻辑（Phase 4 迁移到 AIR）
//!
//! ## 安全约定
//!
//! - 全 crate `#![deny(unsafe_code)]`
//! - 全 crate `#![deny(missing_docs)]`
//! - 所有变长字段反序列化使用 `checked_add` / `checked_mul` 防 32-bit wrap
//! - 所有外部输入（ELF / proof / public_io）须经过校验后才使用

#![deny(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

// ===== Layer 0 — Foundation =====
pub mod error;
pub mod field;

// ===== Layer 1 — Frontend & Execution =====
pub mod compiler;
pub mod isa;
pub mod syscalls;
pub mod trace;

// ===== Layer 2 — Stwo Backend =====
pub mod stwo_backend;

// ===== Layer 3 — Precompile Logic（Phase 4 迁移到 AIR）=====
pub mod precompiles;

// ===== 测试辅助 =====
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

// ===== zkvm 服务化 =====
#[cfg(feature = "service")]
pub mod service;
```

### 5.2 删除的模块声明

- `pub mod transcript;` — Stwo 用 Blake2sChannel
- `pub mod pcs;` — Stwo 用 FRI PCS
- `pub mod ccs;` — Stwo 用 AIR
- `pub mod constraints;` — Stwo 用 AIR 约束
- `pub mod lookup;` — Stwo 用 LogupTraceGenerator
- `pub mod fold;` — Stwo 无 fold
- `pub mod cyclic;` — 不再需要
- `pub mod hypernova;` — 完全放弃
- `pub mod cyclegfold;` — 不再需要
- `pub mod recursion;` — 用 Stwo Verifier AIR 替代（Phase 5）
- `pub mod prover;` — 合并到 stwo_backend
- `pub mod verifier;` — 合并到 stwo_backend
- `pub mod crypto_arkworks;` — 不再需要 BN254

***

## 6. Cargo.toml 更新

### 6.1 移除的依赖

```toml
# 移除（BN254 / arkworks 相关）
ark-bn254 = "..."
ark-ec = "..."
ark-ff = "..."
ark-poly = "..."
ark-serialize = "..."
ark-groth16 = "..."  # 如果有
ark-r1cs-std = "..."  # 如果有
```

### 6.2 保留的依赖

```toml
# 保留
stwo = { workspace = true }
stwo-air-utils = { workspace = true }
stwo-air-utils-derive = { workspace = true }
stwo-constraint-framework = { workspace = true }
bincode = { workspace = true }
rayon = { workspace = true }
serde = { workspace = true }
sha2 = "..."
blake2 = "..."
# ... 其他与证明系统无关的依赖
```

***

## 7. 测试计划

### 7.1 单元测试

```rust
// poker_zkvm/src/stwo_backend/trace_native.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_to_m31_limbs_roundtrip() {
        // 边界值测试
        for &value in &[0u32, 1, 255, 256, 65535, 65536, 0xFFFFFF, 0xFFFFFFFF] {
            let limbs = u32_to_m31_limbs(value);
            assert_eq!(limbs.len(), 4);
            // 验证每个 limb ∈ [0, 255]
            for limb in &limbs {
                assert!(limb.0 < 256, "limb {} 超出 8-bit 范围", limb.0);
            }
            // roundtrip
            let reconstructed = m31_limbs_to_u32(&limbs);
            assert_eq!(reconstructed, value, "u32 roundtrip 失败: {}", value);
        }
    }

    #[test]
    fn test_native_trace_new() {
        let trace = NativeTrace::new(10);
        assert_eq!(trace.num_columns(), super::super::column_layout_v2::NUM_COLUMNS);
        assert_eq!(trace.num_rows(), 1024);
        // 所有列初始化为 0
        for col in &trace.cols {
            for val in col {
                assert_eq!(*val, M31::from(0u32));
            }
        }
    }

    #[test]
    fn test_fill_word() {
        let mut trace = NativeTrace::new(10);
        trace.fill_word(0, super::super::column_layout_v2::COL_PC_BASE, 0x12345678);
        // 验证 4 个 limb
        assert_eq!(trace.cols[0][0], M31::from(0x78u32)); // byte 0 (LE)
        assert_eq!(trace.cols[1][0], M31::from(0x56u32)); // byte 1
        assert_eq!(trace.cols[2][0], M31::from(0x34u32)); // byte 2
        assert_eq!(trace.cols[3][0], M31::from(0x12u32)); // byte 3
    }

    #[test]
    fn test_trace_builder_compute_log_size() {
        assert_eq!(TraceBuilder::compute_log_size(1), 10);  // 最小 10
        assert_eq!(TraceBuilder::compute_log_size(1024), 10);
        assert_eq!(TraceBuilder::compute_log_size(1025), 11);
        assert_eq!(TraceBuilder::compute_log_size(1_000_000), 20);
    }

    #[test]
    fn test_trace_builder_padding() {
        let log_size = 10; // 1024 行
        let mut builder = TraceBuilder::new(log_size);
        // 添加 100 个真实 step
        for _ in 0..100 {
            // builder.add_step(&mock_step);
        }
        // fill_padding
        // builder.fill_padding(&mock_last_step);
        // let trace = builder.finalize();
        // assert_eq!(trace.num_rows(), 1024);
        // 验证 padding 行的 IsPadding = 1
    }
}
```

### 7.2 列布局测试

```rust
// poker_zkvm/src/stwo_backend/column_layout_v2.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_columns() {
        assert_eq!(NUM_COLUMNS, 97, "Phase 1 列布局应为 97 列");
    }

    #[test]
    fn test_column_indices_distinct() {
        // 验证所有 COL_* 常量互不相同
        // ...
    }

    #[test]
    fn test_word_limb_count() {
        assert_eq!(WORD_LIMB_COUNT, 4);
        assert_eq!(WORD_SIZE, 4);
    }

    #[test]
    fn test_is_indicator_range() {
        // 验证 IS_* 常量在 [40, 74] 范围内
        for &is_col in &[IS_LUI, IS_AUIPC, IS_JAL, /* ... */ IS_PADDING] {
            assert!(is_col >= COL_IS_BASE && is_col < COL_IS_BASE + 35);
        }
    }
}
```

### 7.3 集成测试

```rust
// poker_zkvm/tests/phase1_trace_native.rs

use poker_zkvm::stwo_backend::trace_native::*;
use poker_zkvm::stwo_backend::column_layout_v2::*;

#[test]
fn test_trace_to_native_from_emulator() {
    // 1. 用 emulator 执行一个简单程序
    // 2. 调用 trace_to_native 生成 NativeTrace
    // 3. 验证列数、行数、padding
}

#[test]
fn test_cargo_build_no_hypernova() {
    // 验证 cargo build 不依赖 ark-bn254 等
    // 通过 cargo tree --no-default-features 检查
}
```

***

## 8. 实施步骤（有序）

### Step 1.1：备份当前代码（0.5 天）

```bash
cd /Users/mac/projects/zchain
git checkout -b backup/pre-stwo-v2-phase1
git commit -m "Backup before Stwo v2 Phase 1 (trace rewrite + Hypernova cleanup)"
```

### Step 1.2：删除旧代码（1 天）

按 2.1 清单逐个删除文件/目录：
1. `rm -rf poker_zkvm/src/ccs/ poker_zkvm/src/hypernova/ poker_zkvm/src/fold/ poker_zkvm/src/recursion/`
2. `rm -rf poker_zkvm/src/cyclic/ poker_zkvm/src/lookup/ poker_zkvm/src/constraints/`
3. `rm poker_zkvm/src/cyclegfold.rs poker_zkvm/src/crypto_arkworks.rs`
4. `rm poker_zkvm/src/pcs/ipa.rs poker_zkvm/src/transcript.rs`
5. `rm poker_zkvm/src/prover/mod.rs poker_zkvm/src/prover/partial.rs poker_zkvm/src/prover/groth16_compress.rs`
6. `rm poker_zkvm/src/verifier.rs`
7. `rm poker_zkvm/src/stwo_backend/field.rs poker_zkvm/src/stwo_backend/column_layout.rs`
8. `rm poker_zkvm/src/stwo_backend/trace.rs`
9. `rm poker_zkvm/src/stwo_backend/air/cpu.rs poker_zkvm/src/stwo_backend/air/control_flow.rs poker_zkvm/src/stwo_backend/air/memory.rs poker_zkvm/src/stwo_backend/air/syscall.rs poker_zkvm/src/stwo_backend/air/opcode_table.rs`

### Step 1.3：更新 lib.rs（0.5 天）

按 5.1 更新 `poker_zkvm/src/lib.rs`，移除已删除模块的 `pub mod` 声明。

### Step 1.4：更新 Cargo.toml（0.5 天）

按 6.1/6.2 更新 `poker_zkvm/Cargo.toml`，移除 BN254 相关依赖。

### Step 1.5：修复编译错误（1 天）

- 修复 `error.rs`：移除 Hypernova/CCS/IPA 相关错误变体
- 修复 `field.rs`：移除 BN254 Fr 相关代码（如不再被引用）
- 修复 `isa/`：移除对 Fr 的依赖（如果有）
- 修复 `trace/mod.rs`：移除对 ZkvmError 的 Hypernova 相关引用
- 修复 `stwo_backend/mod.rs`：更新子模块声明

**目标**：`cargo build -p poker_zkvm` 通过（允许 warning，但不能有 error）

### Step 1.6：新建 column_layout_v2.rs（0.5 天）

按 3.2 实现 `poker_zkvm/src/stwo_backend/column_layout_v2.rs`。

### Step 1.7：新建 trace_native.rs（1 天）

按 4 实现 `poker_zkvm/src/stwo_backend/trace_native.rs`，包含：
- `NativeTrace` 结构
- `u32_to_m31_limbs` / `m31_limbs_to_u32`
- `step_to_m31_row`
- `TraceBuilder`
- `trace_to_native`

### Step 1.8：编写测试（1 天）

按 7 编写单元测试 + 集成测试。

### Step 1.9：验证 cargo build + cargo test（0.5 天）

```bash
cargo build -p poker_zkvm
cargo test -p poker_zkvm --lib stwo_backend::trace_native
cargo test -p poker_zkvm --lib stwo_backend::column_layout_v2
cargo tree -p poker_zkvm | grep -i "ark-bn254\|ark-ec\|ark-ff"  # 应无输出
```

***

## 9. 完成标准

- [x] 所有 2.1 清单中的旧代码已删除
- [x] `cargo build -p poker_zkvm` 通过（无 error）
- [x] `cargo build --workspace` 通过（无 error）
- [x] `cargo test --workspace` 全部通过（poker_zkvm: 342 测试 / poker_l1: 1501 测试 / 集成测试全通过）
- [~] `cargo tree -p poker_zkvm` 不含 ark-bn254/ark-ec/ark-ff 依赖 — **保留偏差**：v2 计划保留 BN254 Fr 仅用于 Poseidon 哈希（poker game 事件哈希），Phase 3/4 可考虑迁移到 M31 Poseidon。已移除 ark-grumpkin / ark-groth16 / ark-r1cs-std / ark-relations / ark-snark / ark-poly / ark-ec 直接依赖（仅作为 ark-bn254 的传递依赖存在），并禁用 ark-bn254 的 `r1cs` feature
- [x] `column_layout_v2.rs` 实现，97 列布局
- [x] `trace_native.rs` 实现，包含 `NativeTrace`、`u32_to_m31_limbs`、`TraceBuilder`
- [x] `u32_to_m31_limbs` roundtrip 测试通过（0/1/255/256/65535/65536/0xFFFFFFFF）
- [x] `NativeTrace::new` 测试通过
- [x] `fill_word` 测试通过
- [x] `TraceBuilder::compute_log_size` 测试通过
- [x] padding 机制测试通过
- [x] `lib.rs` 模块声明更新完成（poker_zkvm / poker_l1 / zchain 三处）
- [x] zchain / poker_l1 中对已删除模块的所有引用已修复或替换为 StubVerifier
- [x] Hypernova Fr 非规范化测试（H5）已删除（Stwo M31 field 无此问题）

### 9.1 Phase 1 实施记录

**完成时间**：2026-07-20

**实际删除代码量**：~7,761+ 行（poker_zkvm 内 Hypernova 模块）+ ~2,000 行（poker_l1 offline 模块）+ zchain 根目录 demo/server 文件

**新增代码量**：
- `poker_zkvm/src/stwo_backend/column_layout_v2.rs` — 349 行，97 列 4×8-bit limb 布局
- `poker_zkvm/src/stwo_backend/trace_native.rs` — 622 行，NativeTrace + TraceBuilder
- `poker_l1/src/offline/zk_verifier.rs` — 新增公共 `StubVerifier` + 4 个 `register_*_stub_verifier` 函数（v2 过渡期占位）

**测试结果**：
- poker_zkvm 单元测试：342/342 通过
- poker_l1 单元测试：1501/1501 通过
- poker_l1 集成测试：全部通过
- zchain 集成测试：全部通过

**关键决策**：
1. 保留 BN254 Fr 用于 Poseidon 哈希（poker game 事件哈希），后续 Phase 3/4 可迁移到 M31 Poseidon
2. `poker_l1/src/offline/zk_verifier.rs` 新增公共 StubVerifier，Phase 5 由 Stwo Verifier AIR 替换
3. `poker_l1/src/offline/mod.rs` 保留 `MAX_FOLD_STEP_COUNT` 常量以兼容 `ZkPublicIo::validate`
4. `poker_l1/tests/soundness_tests.rs` H5 测试（Hypernova Fr 非规范化）已删除，Stwo M31 field 无此问题

***

## 10. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| 删除代码后编译错误过多 | 中 | Step 1.5 延期 | 分批删除，每批后 `cargo check` |
| `isa/` 或 `trace/` 隐式依赖 Fr | 中 | Step 1.5 阻塞 | 提前 grep `Fr::` 找出依赖 |
| Step 结构缺少必要字段 | 低 | Step 1.7 阻塞 | 先读 trace/mod.rs 确认字段 |
| Cargo.toml 依赖链断裂 | 低 | Step 1.4 阻塞 | 用 `cargo tree` 检查 |

***

## 11. 与 v2 计划的对应

| v2 计划 Phase 1 任务 | 本文档 Step |
|---------------------|------------|
| 删除旧代码（~7,761 行） | Step 1.2 |
| 重写 trace 生成 | Step 1.7 |
| 重写列布局 | Step 1.6 |
| 更新 lib.rs | Step 1.3 |
| `cargo build` 无 Hypernova 依赖 | Step 1.9 |
| `u32_to_m31_limbs` roundtrip 测试 | Step 1.8 |
| padding 机制测试 | Step 1.8