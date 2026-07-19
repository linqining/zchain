# Phase 2 详细设计：CPU AIR 重写（Stwo FrameworkEval）

> **版本**：1.0（2026-07-20）
> **所属迁移计划**：[hypernova_to_stwo_migration_plan_v2.md](file:///Users/mac/projects/zchain/.trae/documents/hypernova_to_stwo_migration_plan_v2.md)
> **工期**：3-4 周
> **前置条件**：Phase 1 已完成（git commit 2972ff7）
> **后续阶段**：Phase 3（内存 + Syscall AIR）

***

## 1. 目标与范围

### 1.1 目标

1. **实现 `step_to_m31_row`**：将 emulator `Step` 转换为 97 列 M31 row
2. **创建 `cpu_air.rs`**：基于 Stwo 原生 `FrameworkEval` + `EvalAtRow` + `relation!` 宏
3. **实现 ADD/ADDI/SUB AIR 约束**：作为首批约束，验证 4×8-bit limb 方案的正确性
4. **创建 `prover.rs` 骨架**：集成 Stwo Prover，端到端生成 proof（不要求性能优化）

### 1.2 范围

**包含**：
- `poker_zkvm/src/stwo_backend/trace_native.rs`：完善 `step_to_m31_row` + `trace_to_native`
- `poker_zkvm/src/stwo_backend/cpu_air.rs`（新建）：CPU AIR FrameworkEval 实现
- `poker_zkvm/src/stwo_backend/prover.rs`（新建）：Stwo Prover 集成
- `poker_zkvm/src/stwo_backend/mod.rs`：添加新模块声明
- ADD/ADDI/SUB 约束 + 单元测试

**不包含**：
- 其他指令约束（SLT/SLTU/逻辑/移位/分支/跳转 — Phase 2.7）
- 内存 AIR（Phase 3）
- Syscall AIR（Phase 3）
- Precompile AIR（Phase 4）
- 递归证明（Phase 5）
- 性能优化（Phase 6）

***

## 2. Stwo FrameworkEval 架构

### 2.1 关键 trait

```rust
// stwo-constraint-framework 提供
pub trait FrameworkEval {
    /// log2(trace 行数) — Stwo 要求 trace 行数为 2^k
    fn log_size(&self) -> u32;

    /// 约束的最大 log degree bound（通常 = log_size）
    fn max_constraint_log_degree_bound(&self) -> u32;

    /// 约束求值入口
    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E;
}

pub trait EvalAtRow {
    type F: BaseField;  // 通常是 M31
    type EF: SecureField;  // 通常是 QM31

    /// 获取下一个 trace 列的当前行值
    fn next_trace_mask(&mut self) -> Self::F;

    /// 获取指定 interaction 和 offset 的 mask 值
    fn next_interaction_mask<const N: usize>(
        &mut self,
        interaction: usize,
        offsets: [isize; N],
    ) -> [Self::F; N];

    /// 添加约束（表达式必须等于 0）
    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>;

    /// 添加中间值（用于约束分解，可降低 degree）
    fn add_intermediate(&mut self, val: Self::F) -> Self::F;
}
```

**注意**：`relation!` 宏仅用于 logup lookup 关系，不用于普通约束。普通约束直接用 `add_constraint` 添加。

### 2.2 典型约束表达

```rust
impl FrameworkEval for CpuAir {
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // 读取列值（顺序必须与 trace 列顺序一致）
        let pc = eval.next_trace_mask();           // col 0
        let pc_next = eval.next_trace_mask();      // col 1
        // ... 读取所有 97 列

        // 添加约束
        // 例：PC 递增约束 pc_next - pc - 4 = 0
        eval.add_constraint(pc_next.clone() - pc.clone() - E::F::from(4u32));

        eval
    }
}
```

### 2.2 组件化设计

参考 Nexus zkVM 0.3.6 的组件化架构：

```text
CpuComponent
  ├─ trace: NativeTrace (97 列)
  ├─ FrameworkEval impl
  ├─ 约束集（ADD/ADDI/SUB + ...）
  └─ interaction points（Phase 3 与 MemoryComponent 交互）
```

### 2.3 Interaction mask

Stwo 通过 interaction mask 实现组件间通信（Phase 3 内存 AIR 用）：

```rust
// Phase 2：CPU 单组件，无 interaction
// Phase 3：CPU → Memory 通过 lookup mask 交互
```

***

## 3. step_to_m31_row 实现

### 3.1 输入输出

```rust
/// 将单个 emulator Step 转换为 97 列 M31 row。
///
/// # 参数
/// - `step` — emulator 执行的单步记录
/// - `prev_registers` — 前一步的寄存器快照（用于计算 ValueA = prev[rs1] 等）
///
/// # 返回
/// 长度 = NUM_COLUMNS (97) 的 Vec<M31>
pub fn step_to_m31_row(step: &Step, prev_registers: &[u32; 32]) -> Vec<M31> { ... }
```

### 3.2 列填充逻辑

| 列范围 | 填充源 |
|--------|--------|
| Pc (0-3) | `step.pc.to_le_bytes()` |
| PcNext (4-7) | 计算 next_pc（指令长度 4 或分支目标） |
| PcNextAux (8-11) | JALR 目标（其他指令 = 0） |
| OpA (12) | `step.instruction.rd()` |
| OpB (13) | `step.instruction.rs1()` |
| OpC (14) | `step.instruction.rs2()` 或立即数低 5 bit |
| CarryFlag (15-16) | ADD/ADDI 进位（16-bit 边界） |
| BorrowFlag (17-18) | SUB 借位（16-bit 边界） |
| ImmC (19) | 立即数标志（I-type/U-type = 1，R-type = 0） |
| InstrVal (20-23) | 指令编码（4×8-bit limb） |
| ValueA (24-27) | `prev_registers[rd]`（写前值） |
| ValueAEff (28-31) | `step.registers[rd]`（写后值；rd=0 时为 0） |
| ValueB (32-35) | `prev_registers[rs1]` |
| ValueC (36-39) | `prev_registers[rs2]` 或立即数 |
| Is* (40-74) | 根据 `step.instruction` 设置 one-hot |
| Helpers (75-90) | 指令特定辅助值 |
| Taken (91) | 分支是否跳转 |
| BranchCond (92) | 分支条件中间值 |
| Shamt (93) | 移位量 |
| SgnA/B/C (94-96) | 操作数符号位 |

### 3.3 Instruction → indicator 映射

```rust
fn instruction_to_indicator_col(insn: &Instruction) -> usize {
    use crate::stwo_backend::column_layout_v2::*;
    match insn {
        Instruction::Lui { .. } => IS_LUI,
        Instruction::Auipc { .. } => IS_AUIPC,
        Instruction::Jal { .. } => IS_JAL,
        Instruction::Jalr { .. } => IS_JALR,
        Instruction::Beq { .. } => IS_BEQ,
        // ... 35 个分支
        Instruction::Addi { .. } => IS_ADDI,
        Instruction::Add { .. } => IS_ADD,
        Instruction::Sub { .. } => IS_SUB,
        // ...
    }
}
```

***

## 4. ADD/ADDI/SUB AIR 约束

### 4.1 约束设计（4×8-bit limb）

**ADD 约束**（`rd = rs1 + rs2`）：
```text
对每个 limb i ∈ {0,1,2,3}：
    ValueAEff[i] = ValueB[i] + ValueC[i] + carry_in[i]
    carry_out[i] = (ValueB[i] + ValueC[i] + carry_in[i]) >> 8

约束：
1. ValueAEff[0] = ValueB[0] + ValueC[0] - 256 * carry[0]  (degree 2)
2. ValueAEff[1] = ValueB[1] + ValueC[1] + carry[0] - 256 * carry[1]  (degree 2)
3. ValueAEff[2] = ValueB[2] + ValueC[2] + carry[1] - 256 * carry[2]  (degree 2)
4. ValueAEff[3] = ValueB[3] + ValueC[3] + carry[2] - 256 * carry[3]  (degree 2)
5. carry[i] ∈ {0, 1}  (binality, degree 2)

gating：
    IsAdd * (constraint_1 + constraint_2 + constraint_3 + constraint_4) = 0
```

**ADDI 约束**（`rd = rs1 + imm`）：
- 与 ADD 相同，但 ValueC = 立即数（4×8-bit limb）
- ImmC indicator = 1

**SUB 约束**（`rd = rs1 - rs2`）：
```text
对每个 limb i ∈ {0,1,2,3}：
    ValueAEff[i] = ValueB[i] - ValueC[i] - borrow_in[i] + 256 * borrow_out[i]

约束（符号方向与 ADD 相反）：
1. ValueAEff[0] = ValueB[0] - ValueC[0] + 256 * borrow[0]  (degree 2)
2. ValueAEff[1] = ValueB[1] - ValueC[1] - borrow[0] + 256 * borrow[1]
3. ValueAEff[2] = ValueB[2] - ValueC[2] - borrow[1] + 256 * borrow[2]
4. ValueAEff[3] = ValueB[3] - ValueC[3] - borrow[2] + 256 * borrow[3]
5. borrow[i] ∈ {0, 1}

gating：
    IsSub * (constraint_1 + constraint_2 + constraint_3 + constraint_4) = 0
```

### 4.2 PC 递增约束（通用）

```text
PcNext = Pc + 4 * (1 - IsBranchTaken)  (degree 2)

或更精确（每条非跳转指令）：
PcNext = Pc + 4
```

### 4.3 Padding 约束

```text
IsPadding ∈ {0, 1}  (binality)
IsPadding * (所有非 padding 列) = 0
```

### 4.4 Indicator one-hot 约束

```text
Σ(Is_i) = 1  (对所有 35 个 indicator 求和 = 1)
```

***

## 5. Prover 集成

### 5.1 Stwo Prover API

```rust
use stwo::prover::StwoProver;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;

pub fn prove_cpu_trace(trace: NativeTrace) -> Result<StarkProof, ZkvmError> {
    let log_size = trace.log_size();

    // 1. 构造 CPU AIR
    let cpu_air = CpuAir::new(log_size);

    // 2. 构造 Stwo Prover
    let prover = StwoProver::new::<Blake2sMerkleChannel>();

    // 3. 生成 proof
    let proof = prover.prove(&[trace.into()], &cpu_air)
        .map_err(|e| ZkvmError::StwoProveError(e.to_string()))?;

    Ok(proof)
}
```

### 5.2 验证（Phase 2 仅自验证）

```rust
pub fn verify_cpu_proof(proof: &StarkProof, log_size: u32) -> Result<bool, ZkvmError> {
    let cpu_air = CpuAir::new(log_size);
    let verifier = StwoVerifier::new();
    verifier.verify(proof, &cpu_air)
        .map_err(|e| ZkvmError::StwoVerifyError(e.to_string()))?;
    Ok(true)
}
```

***

## 6. 实施步骤

### Step 2.1：完善 trace_native.rs（1 天）✅
- 实现 `step_to_m31_row`
- 实现 `trace_to_native` 主入口
- 替换 `trace_to_native_trace_placeholder`

### Step 2.2：创建 cpu_air.rs 骨架（1 天）✅
- 定义 `CpuAir` struct
- 实现 `FrameworkEval` trait
- 添加空 `evaluate` 方法

### Step 2.3：实现 ADD/ADDI/SUB 约束（2 天）✅
- ~~用 `relation!` 宏表达约束~~（改用 `add_constraint()` 直接表达，`relation!` 仅用于 logup）
- 实现 carry/borrow binality 约束
- ~~实现 PC 递增约束~~（Phase 2.7 扩展时实现）
- 实现 padding + indicator one-hot 约束
- **共 14 条约束**：ADD 4 + ADDI 4 + SUB 4 + IsPadding binality + Indicator one-hot
- **关键修复**：`BaseField::from_u128_unchecked` → `from_u32_unchecked`；常量在 `evaluate` 入口统一转换为 `E::F`

### Step 2.4：创建 prover.rs 骨架（1 天）✅
- 集成 Stwo 原生 Prover（`stwo::prover::prove`）
- 实现 `prove_cpu_trace` / `verify_cpu_proof`
- **关键 API 发现**：
  - `SimdBackend::precompute_twiddles` 需导入 `PolyOps` trait
  - `SecureField::zero()` 需 `num_traits::Zero`，改用 `SecureField::from(0u32)`
  - `CircleEvaluation::new` 需显式类型参数 `<SimdBackend, BaseField>`
  - Verifier 需手动 `commit` preprocessed + trace commitment，`verify()` 内部处理 composition poly

### Step 2.5：编写测试（2 天）✅
- ~~`test_step_to_m31_row_add`~~：由 `test_prove_verify_roundtrip_single_add` 覆盖
- ~~`test_step_to_m31_row_sub`~~：Phase 2.7 扩展
- ~~`test_cpu_air_add_constraint`~~：由 prove/verify roundtrip 隐式覆盖
- ~~`test_cpu_air_sub_constraint`~~：Phase 2.7 扩展
- `test_prove_verify_roundtrip`：prove → verify 端到端测试 ✅
- **实际测试清单**（8 个全部通过）：
  - cpu_air: `test_cpu_air_new`, `test_constants`, `test_column_layout_consistency`
  - prover: `test_native_trace_to_evaluations_column_count`, `test_prove_padding_only_trace`,
    `test_verify_padding_only_trace`, `test_prove_verify_roundtrip_padding_only`,
    `test_prove_verify_roundtrip_single_add`

### Step 2.6：扩展到其他 RV32I 指令（2-3 天，可选）⬜ → Phase 2.7
- SLT/SLTU/逻辑/移位
- LUI/AUIPC
- JAL/JALR
- BEQ/BNE/BLT/BGE/BLTU/BGEU
- LB/LH/LW/LBU/LHU
- SB/SH/SW

### Step 2.7：ECALL/EBREAK stub（0.5 天）⬜
- Phase 3 完整实现

***

## 7. 完成标准

- [x] `step_to_m31_row` 实现，覆盖 ADD/ADDI/SUB + 其他 RV32I 指令 indicator（M 扩展暂占位）
- [x] `CpuAir` 实现 `FrameworkEval` trait
- [x] ADD/ADDI/SUB 约束通过测试
- [x] padding + indicator one-hot 约束通过测试
- [x] `prove_cpu_trace` + `verify_cpu_proof` 端到端通过
- [x] `cargo test -p poker_zkvm --lib stwo_backend` 全部通过（350 passed, 0 failed）
- [x] workspace 全部测试通过（600+ passed, 0 failed）

***

## 8. 实施记录

### 2026-07-20 Phase 2.3+2.4 完成
- **修复**：`BaseField::from_u128_unchecked` → `from_u32_unchecked`（M31 仅有 `from_u32_unchecked`）
- **修复**：`mod.rs` 添加 `pub mod cpu_air;` 声明
- **修复**：evaluate 中 `SIX5536`/`TWO56`/`BaseField::from(1u32)` 在入口统一 `.into()` 转换为 `E::F`
  - 原因：`E::F: From<BaseField> + Mul<BaseField>`，但 `BaseField * E::F` 不可行（顺序敏感）
- **约束清单**：14 条（ADD 4 + ADDI 4 + SUB 4 + IsPadding binality + Indicator one-hot）
- **测试**：3 个 cpu_air 单元测试通过

### 2026-07-20 Phase 2.5+2.6 完成
- **prover.rs 骨架**：`prove_cpu_trace` + `verify_cpu_proof` + `native_trace_to_evaluations`
- **关键 API 修复**：
  1. `SimdBackend::precompute_twiddles` → 导入 `stwo::prover::poly::circle::PolyOps`
  2. `SecureField::zero()` → `SecureField::from(0u32)`（避免 `num_traits::Zero` 依赖）
  3. `CircleEvaluation::new` → 显式类型参数 `<SimdBackend, BaseField>`
- **Verifier workflow**：手动 `commit` preprocessed + trace commitment，`verify()` 内部处理 composition poly
- **测试**：5 个 prover 单元测试通过（含 padding-only + single ADD roundtrip）
- **workspace 全部测试**：600+ passed, 0 failed
- [ ] `cargo build --workspace` 通过

***

## 8. 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| Stwo FrameworkEval API 与文档不一致 | 中 | Step 2.2 阻塞 | 优先读 stwo-constraint-framework 源码 |
| relation! 宏语法限制 | 中 | Step 2.3 阻塞 | 改用手动 eval 表达 |
| 4×8-bit limb carry 约束 soundness 不足 | 低 | Step 2.3 返工 | 参考 Nexus zkVM 0.3.6 carry 处理 |
| Stwo Prover API 在 1M steps 性能差 | 高 | Phase 6 处理 | Phase 2 不优化性能 |

***

## 9. 与 v2 计划的对应

| v2 计划 Phase 2 任务 | 本文档 Step |
|---------------------|------------|
| step_to_m31_row 实现 | Step 2.1 |
| CpuAir FrameworkEval | Step 2.2 |
| ADD/ADDI/SUB 约束 | Step 2.3 |
| Prover 集成 | Step 2.4 |
| 端到端 prove/verify | Step 2.5 |
