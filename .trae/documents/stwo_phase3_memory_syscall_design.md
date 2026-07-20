# Phase 3 详细设计：Memory AIR + Register AIR + Syscall AIR（多组件 logup）

> **版本**：1.0（2026-07-20）
> **所属迁移计划**：[hypernova_to_stwo_migration_plan_v2.md](file:///Users/mac/projects/zchain/.trae/documents/hypernova_to_stwo_migration_plan_v2.md)
> **工期**：2-3 周
> **前置条件**：Phase 2.7 已完成（git commit af91640）
> **后续阶段**：Phase 4（Precompile AIR）

***

## 1. 目标与范围

### 1.1 目标

1. **实现 Memory AIR 组件**：独立的内存访问一致性 AIR，通过 logup 与 CPU AIR 交互
2. **实现 Register AIR 组件**：寄存器文件一致性 AIR（证明 `ValueB = prev_registers[rs1]`）
3. **实现 Syscall AIR 组件**：ECALL/EBREAK + 自定义 syscall（poseidon/sha256/keccak/merkle）
4. **多组件 prove/verify 集成**：扩展 `prover.rs` 支持多组件 `FrameworkComponent` + `LogupTraceGenerator`
5. **填补 CPU AIR soundness 缺口**：Load/Store 约束 + 非代数运算 logup lookup（SLT/XOR/shift）

### 1.2 范围

**包含**：
- `poker_zkvm/src/stwo_backend/memory_air.rs`（新建）：Memory AIR FrameworkEval
- `poker_zkvm/src/stwo_backend/register_air.rs`（新建）：Register AIR FrameworkEval
- `poker_zkvm/src/stwo_backend/syscall_air.rs`（新建）：Syscall AIR FrameworkEval
- `poker_zkvm/src/stwo_backend/cpu_air.rs`（扩展）：Load/Store 约束 + logup claim 发送
- `poker_zkvm/src/stwo_backend/trace_native.rs`（扩展）：Memory/Register/Syscall trace 生成
- `poker_zkvm/src/stwo_backend/prover.rs`（扩展）：多组件 prove/verify + LogupTraceGenerator
- `poker_zkvm/src/stwo_backend/column_layout_v2.rs`（扩展）：Memory/Register 列布局常量

**不包含**：
- Precompile AIR（Poseidon/Sha256/Keccak/Merkle）— Phase 4
- 递归证明 — Phase 5
- 性能优化 — Phase 6

### 1.3 Soundness 缺口分析（Phase 2.7 遗留）

当前 CPU AIR 有 39 条约束，覆盖 ADD/ADDI/SUB/LUI/AUIPC/JAL/JALR/Branch。但以下 soundness 缺口仍存在：

| 缺口 | 严重性 | Phase 3 解决方案 |
|------|--------|-----------------|
| Load/Store 无约束（IsLoad/IsStore indicator 存在但无约束） | **CRITICAL** | Memory AIR + logup |
| Register consistency（ValueB != prev_registers[rs1] 风险） | **CRITICAL** | Register AIR + logup |
| SLT/SLTU/XOR/OR/AND/SLL/SRL/SRA 无约束 | HIGH | logup lookup table |
| 分支条件 soundness（BEQ taken iff rs1==rs2） | MEDIUM | CPU AIR 约束扩展 |
| ECALL/EBREAK 无约束 | MEDIUM | Syscall AIR |

***

## 2. Stwo 多组件 + Logup 架构

### 2.1 多组件 prove/verify 模式

Stwo 支持多个 `FrameworkComponent` 同时 prove，每个组件有独立的 trace 子树：

```rust
// Prover 侧
let mut allocator = TraceLocationAllocator::default();
let cpu_component = FrameworkComponent::new(&mut allocator, cpu_air, cpu_claimed_sum);
let mem_component = FrameworkComponent::new(&mut allocator, mem_air, mem_claimed_sum);
let reg_component = FrameworkComponent::new(&mut allocator, reg_air, reg_claimed_sum);

// 提交 4 棵树：
// tree 0: preprocessed (空或公共列)
// tree 1: CPU original trace (97 列)
// tree 2: Memory original trace (24 列)
// tree 3: Register original trace (16 列)
// tree 4: Interaction trace (logup cumulative sums，由 LogupTraceGenerator 生成)

prove(&[&cpu_component, &mem_component, &reg_component], &mut channel, commitment_scheme)
```

### 2.2 Logup Lookup 交互模式

使用 `relation!` 宏定义 lookup relation，CPU AIR 发送 claim（multiplicity +1），Memory/Register AIR yield（multiplicity -1）：

```rust
// 定义 lookup relation（9 个值：4 addr limbs + 4 value limbs + 1 op_flag）
relation!(MemoryLookup, 9);

// CPU AIR 侧（发送 claim，multiplicity = +1）
eval.add_to_relation(RelationEntry::new(
    &self.memory_lookup,
    SecureField::one().into(),  // +1
    &[addr_limb0, addr_limb1, addr_limb2, addr_limb3,
      val_limb0, val_limb1, val_limb2, val_limb3,
      is_store_flag],
));
eval.finalize_logup();

// Memory AIR 侧（yield，multiplicity = -1）
eval.add_to_relation(RelationEntry::new(
    &self.memory_lookup,
    SecureField::from(-1).into(),  // -1
    &[addr_limb0, addr_limb1, addr_limb2, addr_limb3,
      val_limb0, val_limb1, val_limb2, val_limb3,
      is_store_flag],
));
eval.finalize_logup();
```

### 2.3 Interaction Trace 生成

Prover 侧使用 `LogupTraceGenerator` 生成 interaction trace（tree 4）：

```rust
let mut logup_gen = LogupTraceGenerator::new(log_size);
// CPU 组件的 logup 列
let mut cpu_logup_col = logup_gen.new_col();
for row in 0..num_rows {
    let (num, denom) = compute_cpu_logup_frac(row, &lookup_elements);
    cpu_logup_col.write_frac(row, num, denom);
}
cpu_logup_col.finalize_col();
// Memory 组件的 logup 列（类似）
// ...
let (interaction_trace, claimed_sum) = logup_gen.finalize_last();
// 提交 interaction_trace 为 tree 4
```

### 2.4 关键 API（来自 stwo-constraint-framework-2.3.0）

- `relation!(Name, N)` — 定义 N 元 lookup relation（[logup.rs:64](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/logup.rs#L64)）
- `RelationEntry::new(relation, multiplicity, values)` — 创建 lookup entry（[lib.rs:295](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/lib.rs#L295)）
- `eval.add_to_relation(entry)` — 注册 lookup claim（[lib.rs:150](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/lib.rs#L150)）
- `eval.finalize_logup()` — 完成 logup 批次（[lib.rs:169](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/lib.rs#L169)）
- `LogupTraceGenerator::new(log_size)` — 创建 interaction trace 生成器（[prover/logup.rs:30](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/prover/logup.rs#L30)）
- `FrameworkComponent::new(allocator, eval, claimed_sum)` — 创建组件（[component.rs:124](file:///Users/mac/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-constraint-framework-2.3.0/src/component.rs#L124)）

***

## 3. Memory AIR 设计

### 3.1 设计参考

参考 Nexus zkVM 0.3.6 `memory_check/` 模块的 **sorted memory log** 模式：
- 每行记录一次内存访问
- 按 (addr, timestamp) 排序
- 连续行同 addr 时，`ValPrev == prev.ValCur` 且 `TsPrev == prev.TsCur`

### 3.2 Memory AIR Trace 列布局（24 列）

| 列范围 | 列名 | 说明 |
|--------|------|------|
| 0-3 | MemAddr (4×8-bit limb) | 内存地址 |
| 4-7 | MemValCur (4×8-bit limb) | 本次访问后的值 |
| 8-11 | MemValPrev (4×8-bit limb) | 本次访问前的值 |
| 12-15 | MemTsCur (4×8-bit limb) | 当前时间戳（= step_index） |
| 16-19 | MemTsPrev (4×8-bit limb) | 上次访问同 addr 的时间戳 |
| 20 | MemIsLoad | 1=Load，0=其他 |
| 21 | MemIsStore | 1=Store，0=其他 |
| 22 | MemSize | 访问尺寸（1/2/4 字节） |
| 23 | MemIsPadding | padding 行标记 |

**总列数**：`MEM_NUM_COLUMNS = 24`

### 3.3 Memory AIR 约束清单

| # | 约束 | 度 | gating | 说明 |
|---|------|----|--------|------|
| M1-M4 | Addr limb binality | 2 | 通用 | 每个 limb ∈ [0, 255]（确保 8-bit） |
| M5 | IsLoad binality | 2 | 通用 | IsLoad·(IsLoad−1) = 0 |
| M6 | IsStore binality | 2 | 通用 | IsStore·(IsStore−1) = 0 |
| M7 | IsPadding binality | 2 | 通用 | IsPadding·(IsPadding−1) = 0 |
| M8 | One-hot | 1 | 通用 | IsLoad + IsStore + IsPadding = 1 |
| M9 | Load 不改值 | 2 | IsLoad | IsLoad·(ValCur − ValPrev) = 0 |
| M10-M13 | TsCur 单调递增（per addr） | 2 | !IsPadding | TsPrev − prev.TsCur = 0（同 addr 时） |
| M14-M17 | ValPrev 连续性 | 2 | !IsPadding | ValPrev − prev.ValCur = 0（同 addr 时） |
| M18-M21 | 初始访问 TsPrev=0 | 2 | !IsPadding ∧ first_access | TsPrev = 0（首次访问 addr） |
| M22-M25 | 初始访问 ValPrev=0 | 2 | !IsPadding ∧ first_access | ValPrev = 0（首次访问 addr） |

**注**：约束 M10-M25 需要 "same addr" 和 "first access" 的 gating，这通过排序 + addr 差分实现：
- 同 addr 判定：`AddrDiff = (Addr - prev.Addr)`，若 `AddrDiff == 0` 则同 addr
- 首次访问判定：`IsFirstAccess = IsPadding + (1 - IsPadding) * (1 - IsSameAddr)`（简化）

### 3.4 Logup 交互

**MemoryLookup relation**（9 元组）：
```rust
relation!(MemoryLookup, 9);
// values = [addr_limb0, addr_limb1, addr_limb2, addr_limb3,
//           val_limb0, val_limb1, val_limb2, val_limb3,
//           is_store_flag]  // 1 for Store, 0 for Load
```

**CPU AIR 发送**（每条 Load/Store 指令）：
- multiplicity = +1
- values = (mem_addr, mem_value, is_store)

**Memory AIR yield**（每行）：
- multiplicity = -1
- values = (MemAddr, MemValCur, MemIsStore)

**约束**：Σ(CPU claims) = Σ(Memory yields)，即 logup sum = 0

### 3.5 Memory Trace 生成算法

```
输入：emulator Trace（N 步，每步含 mem_access: Vec<MemAccess>）
输出：sorted Memory trace（M 行，M = 总内存访问数，向上取整到 2^k）

1. 收集所有 MemAccess，附加 step_index 作为 TsCur：
   entries = []
   for step in trace.steps():
       for ma in step.mem_access:
           entries.append((ma.addr, ma.value, ma.op, ma.size, step.step_index))

2. 按 (addr, ts) 排序：
   entries.sort_by(|a, b| (a.0, a.4).cmp(&(b.0, b.4)))

3. 填充 trace：
   for (i, (addr, val, op, size, ts)) in entries.enumerate():
       if i > 0 and entries[i-1].addr == addr:
           // 同 addr 连续访问
           MemValPrev = entries[i-1].val
           MemTsPrev = entries[i-1].ts
       else:
           // 首次访问该 addr
           MemValPrev = 0
           MemTsPrev = 0
       MemAddr = addr
       MemValCur = val
       MemTsCur = ts
       MemIsLoad = (op == Read) ? 1 : 0
       MemIsStore = (op == Write) ? 1 : 0
       MemSize = size

4. Padding 到 2^log_size 行（IsPadding=1，其余=0）
```

***

## 4. Register AIR 设计

### 4.1 设计参考

类似 Memory AIR，但用于寄存器文件一致性。每行记录一次寄存器访问（读或写）。

### 4.2 Register AIR Trace 列布局（14 列）

| 列范围 | 列名 | 说明 |
|--------|------|------|
| 0 | RegIdx | 寄存器索引（0-31） |
| 1-4 | RegValCur (4×8-bit limb) | 本次访问后的值 |
| 5-8 | RegValPrev (4×8-bit limb) | 本次访问前的值 |
| 9-12 | RegTsCur (4×8-bit limb) | 当前时间戳 |
| 13 | RegIsWrite | 1=写，0=读 |

**注**：寄存器 AIR 不需要 IsPadding，因为读+写数量固定（每步 2 读 + 1 写）。

### 4.3 Register AIR 约束清单

| # | 约束 | 度 | 说明 |
|---|------|----|------|
| R1 | RegIdx 范围 | 2 | RegIdx < 32（通过 logup 或 binality） |
| R2 | TsCur 单调递增 | 2 | 同 RegIdx 时 TsPrev == prev.TsCur |
| R3 | ValPrev 连续性 | 2 | 同 RegIdx 时 ValPrev == prev.ValCur |
| R4 | 初始访问 ValPrev=0 | 2 | 首次访问 RegIdx 时 ValPrev = 0 |
| R5 | x0 永远为 0 | 2 | RegIdx==0 时 ValCur = 0 |

### 4.4 Logup 交互

**RegisterLookup relation**（6 元组）：
```rust
relation!(RegisterLookup, 6);
// values = [reg_idx, val_limb0, val_limb1, val_limb2, val_limb3, is_write]
```

**CPU AIR 发送**（每条指令的每个寄存器访问）：
- rs1 读：multiplicity = +1, values = (op_b, value_b, 0)
- rs2 读：multiplicity = +1, values = (op_c, value_c, 0)
- rd 写：multiplicity = +1, values = (op_a, value_a_eff, 1)

**Register AIR yield**（每行）：
- multiplicity = -1, values = (RegIdx, RegValCur, RegIsWrite)

***

## 5. Syscall AIR 设计

### 5.1 Syscall 列表

poker_zkvm 自定义 syscall：
- `poseidon_hash` — Poseidon 哈希（Phase 4 迁移到 AIR）
- `sha256` — SHA-256 哈希
- `keccak256` — Keccak-256 哈希
- `merkle_verify` — Merkle 路径验证

### 5.2 Syscall AIR Trace 列布局（简化，12 列）

| 列范围 | 列名 | 说明 |
|--------|------|------|
| 0-3 | SyscallId (4×8-bit limb) | syscall 编号 |
| 4-7 | SyscallInput (4×8-bit limb) | 输入参数 |
| 8-11 | SyscallOutput (4×8-bit limb) | 输出结果 |

### 5.3 Syscall AIR 约束

- ECALL 触发：`IsEcall * (SyscallId - expected_id) = 0`
- Syscall 输入/输出一致性：通过 logup 连接 precompile AIR（Phase 4）

**注**：Phase 3 仅实现 Syscall AIR 骨架，precompile 逻辑在 Phase 4 实现。

***

## 6. CPU AIR 扩展（Load/Store 约束 + Logup Claim）

### 6.1 新增 CPU AIR 约束（Phase 3）

| # | 约束 | 度 | gating | 说明 |
|---|------|----|--------|------|
| C40-C43 | Load addr 计算 | 2 | IsLoad | MemAddr[i] - (rs1[i] + imm[i]) = 0 |
| C44-C47 | Load 值匹配 | 2 | IsLoad | rd_eff[i] - MemValue[i] = 0 |
| C48-C51 | Store addr 计算 | 2 | IsStore | MemAddr[i] - (rs1[i] + imm[i]) = 0 |
| C52-C55 | Store 值匹配 | 2 | IsStore | MemValue[i] - rs2[i] = 0 |

### 6.2 Logup Claim 发送

CPU AIR `evaluate` 末尾添加：

```rust
// 对 Load/Store 指令发送 MemoryLookup claim
let is_load = col(IS_LOAD);
let is_store = col(IS_STORE);

// Load claim: (addr, rd_eff, is_store=0)
let load_claim_multiplicity = is_load.clone().into();  // EF type
eval.add_to_relation(RelationEntry::new(
    &self.memory_lookup,
    load_claim_multiplicity,
    &[
        col(COL_MEM_ADDR_BASE), col(COL_MEM_ADDR_BASE+1),
        col(COL_MEM_ADDR_BASE+2), col(COL_MEM_ADDR_BASE+3),
        col(COL_VALUE_A_EFF_BASE), col(COL_VALUE_A_EFF_BASE+1),
        col(COL_VALUE_A_EFF_BASE+2), col(COL_VALUE_A_EFF_BASE+3),
        BaseField::from(0u32).into(),  // is_store = 0
    ],
));

// Store claim: (addr, rs2_value, is_store=1)
let store_claim_multiplicity = is_store.clone().into();
eval.add_to_relation(RelationEntry::new(
    &self.memory_lookup,
    store_claim_multiplicity,
    &[
        col(COL_MEM_ADDR_BASE), col(COL_MEM_ADDR_BASE+1),
        col(COL_MEM_ADDR_BASE+2), col(COL_MEM_ADDR_BASE+3),
        col(COL_VALUE_C_BASE), col(COL_VALUE_C_BASE+1),
        col(COL_VALUE_C_BASE+2), col(COL_VALUE_C_BASE+3),
        BaseField::from(1u32).into(),  // is_store = 1
    ],
));

eval.finalize_logup();
```

### 6.3 CPU AIR 列布局扩展

需在 CPU AIR trace 中新增 MemAddr 列（4 列），用于记录 Load/Store 的地址。

**新增列**（在 97 列之后追加）：
| 列范围 | 列名 | 说明 |
|--------|------|------|
| 97-100 | MemAddr (4×8-bit limb) | Load/Store 地址（非 Load/Store 时为 0） |

**新 NUM_COLUMNS**：97 + 4 = 101

***

## 7. 实施步骤

### Step 3.1：扩展 column_layout_v2.rs（1 天）

- 新增 `COL_MEM_ADDR_BASE = 97`（CPU trace 中的 Load/Store 地址列）
- 更新 `NUM_COLUMNS = 101`
- 新增 Memory AIR 列布局常量（`MEM_COL_*`，共 24 列）
- 新增 Register AIR 列布局常量（`REG_COL_*`，共 14 列）

### Step 3.2：实现 memory_air.rs（2-3 天）

- 定义 `MemoryAir` struct + `FrameworkEval` impl
- 实现 25 条约束（M1-M25）
- 定义 `MemoryLookup` relation（`relation!` 宏）
- 实现 logup yield（multiplicity = -1）
- 单元测试：单行约束验证

### Step 3.3：扩展 trace_native.rs（2 天）

- 新增 `MemoryTrace` struct（sorted memory access log）
- 实现 `trace_to_memory_trace(trace: &Trace) -> MemoryTrace`
- 新增 `step_to_m31_row` 填充 `MemAddr` 列（97-100）
- 排序算法：按 (addr, ts) 排序

### Step 3.4：扩展 cpu_air.rs（1-2 天）

- 新增 16 条 Load/Store 约束（C40-C55）
- 新增 logup claim 发送（MemoryLookup + RegisterLookup）
- 更新 `max_constraint_log_degree_bound`

### Step 3.5：扩展 prover.rs（2-3 天）

- 新增 `prove_multi_component()` 函数
- 提交 5 棵树：preprocessed + CPU + Memory + Register + Interaction
- 集成 `LogupTraceGenerator`
- 新增 `verify_multi_component()` 函数

### Step 3.6：测试（2 天）

- `test_memory_air_single_load`：单条 Load 指令
- `test_memory_air_single_store`：单条 Store 指令
- `test_memory_air_load_after_store`：Store 后 Load 同地址
- `test_register_air_consistency`：寄存器读写一致
- `test_multi_component_prove_verify`：多组件联合 prove/verify
- `test_logup_memory_consistency`：logup 内存一致性

### Step 3.7：文档更新（0.5 天）

- 更新 `hypernova_to_stwo_migration_plan_v2.md` Phase 3 完成标准
- 更新 `project_memory.md`
- 更新 `topics.md`

***

## 8. 完成标准

- [x] `memory_air.rs` 实现并通过单元测试（3 个单元测试 + 5 个多组件集成测试）
- [ ] `register_air.rs` 实现并通过单元测试（**Phase 3.6 待补**：`RegisterLookup` 已定义但未接线）
- [ ] `syscall_air.rs` 骨架实现（**Phase 3.6 待补**）
- [x] `cpu_air.rs` Load/Store 约束 + logup claim 实现（C40-C55 约束 + `MemoryLookup` claim 发送）
- [x] `prover.rs` 多组件 prove/verify 集成（`prove_cpu_memory_trace` + `verify_cpu_memory_proof`）
- [x] `cargo test -p poker_zkvm --lib stwo_backend` 全绿（392 测试全部通过）
- [x] Memory consistency 测试通过（`test_prove_verify_multi_lw_sw_sequence` Store 后 Load 同地址）
- [ ] Register consistency 测试通过（**Phase 3.6 待补**）
- [x] workspace 全部测试通过

***

## 9. 风险与缓解

| 风险 | 概率 | 缓解 |
|------|------|------|
| Logup API 误用（multiplicity 符号） | MEDIUM | 先写最小 logup 测试验证 |
| 排序算法复杂度 | LOW | 使用 Rust 标准库 `sort_by` |
| 多组件 trace 大小不匹配 | MEDIUM | padding 到相同 log_size |
| Stwo interaction trace 提交错误 | HIGH | 参考 stwo-cairo 示例 |
| 约束度数超出 bound | LOW | 拆分为多约束降低度数 |

***

## 10. 实施记录

### 10.1 Phase 3.1 完成（2026-07-20）

- `column_layout_v2.rs` 新增 `COL_MEM_ADDR_BASE = 97`（CPU trace 中 Load/Store 地址列）
- `NUM_COLUMNS` 从 97 扩展到 101（4 个 MemAddr limb 列）
- 新增 Memory AIR 列布局常量（`MEM_COL_*`，共 25 列，详见 `memory_air.rs`）
- `RegisterLookup` relation 在 `lookups.rs` 中定义但暂标记 `#[allow(dead_code)]`，留待 Phase 3.6 接线

### 10.2 Phase 3.2 完成（2026-07-20）

- `memory_air.rs` 实现 `MemoryAir` struct + `FrameworkEval` impl
- 25 列布局：Addr×4 + ValCur×4 + ValPrev×4 + TsCur×4 + TsPrev×4 + IsLoad + IsStore + Size + IsPadding + IsFirstAccess
- 实现约束 M1-M33（binality + one-hot + 连续性 + 首次访问归零）
- `MemoryLookup` relation（9 元组）通过 `relation!` 宏定义
- logup yield：`multiplicity = -1 * (1 - IsPadding)`，padding 行不贡献 sum
- 3 个单元测试通过：`test_memory_air_new`、`test_mem_num_columns`、`test_column_layout_no_overlap`

### 10.3 Phase 3.3 完成（2026-07-20）

- `trace_native.rs` 新增 `MemoryTrace` struct（sorted memory access log）
- 实现 `trace_to_memory_trace(trace: &Trace) -> MemoryTrace`
- 排序算法：按 `(addr, ts)` 字典序排序，对 Load/Store 指令提取访问事件
- 内存访问事件类型：`(addr, val_cur, val_prev, ts_cur, ts_prev, is_load, is_store, size, is_first_access)`
- `is_first_access` 在排序后通过线性扫描预计算（同 addr 首次出现时为 1）

### 10.4 Phase 3.4 完成（2026-07-20）

- `cpu_air.rs` 新增 16 条 Load/Store 约束（C40-C55）：
  - C40-C43：MemAddr limb binality
  - C44-C47：MemAddr 等于 `op_b + imm`（4×8-bit limb）
  - C48-C51：Load 时 `rd_eff` 等于 `MemValCur`（4×8-bit limb）
  - C52-C55：Store 时 `rs2_value` 等于 `MemValCur`（4×8-bit limb）
- logup claim 发送：每条 Load/Store 指令发送 `MemoryLookup` claim
  - Load: `values = (mem_addr, loaded_value, 0)`，multiplicity = +1
  - Store: `values = (mem_addr, stored_value, 1)`，multiplicity = +1
- 通过 `is_load + is_store` 作为 multiplicity 实现统一 gating

### 10.5 Phase 3.5 完成（2026-07-20）✅

**多组件 prover + LogupTraceGenerator 集成完成。**

#### 实现内容

1. **`prover.rs` 新增 `CpuMemoryProof` 结构**：
   ```rust
   pub struct CpuMemoryProof {
       pub stark_proof: StarkProof<Blake2sMerkleHasher>,
       pub claimed_sum_cpu: SecureField,
       pub claimed_sum_mem: SecureField,
   }
   ```

2. **多组件 prove 主入口 `prove_cpu_memory_trace`**：
   - Tree 0：空 preprocessed
   - Tree 1：CPU original trace (101 列) + Memory original trace (25 列) = 126 列
   - 从 channel draw `MemoryLookup`
   - Tree 2：CPU interaction (4 列) + Memory interaction (4 列) = 8 列
   - Soundness check：`claimed_sum_cpu + claimed_sum_mem == 0`
   - `channel.mix_felts(&[sum_cpu, sum_mem])` 通信给 verifier
   - `prove(&[&cpu_component, &mem_component], &mut channel, commitment_scheme)`

3. **多组件 verify 主入口 `verify_cpu_memory_proof`**：
   - 镜像 prover 流程：commit Tree 0 → commit Tree 1 → draw lookup → soundness check → mix_felts → commit Tree 2 → `verify(&[&cpu, &mem], ...)`

4. **`gen_cpu_interaction_trace` 函数**：
   - 遍历 CPU trace 每个 SIMD vec_row
   - 构造 9 元 claim_values：`[MemAddr×4, is_load * rd_eff + is_store * rs2_value, IsStore]`
   - 计算 `denom = lookup.combine(&claim_values)`
   - 计算 `num = (is_load + is_store)` 作为 multiplicity
   - `col_gen.write_frac(vec_row, num, denom)`
   - `finalize_col() + finalize_last()` 返回 (4 个 CircleEvaluation, claimed_sum)

5. **`gen_mem_interaction_trace` 函数**：
   - 遍历 Memory trace 每个 SIMD vec_row
   - 构造 9 元 yield_values：`[MemAddr×4, MemValCur×4, MemIsStore]`
   - 计算 `denom = lookup.combine(&yield_values)`
   - 计算 `num = -1 * (1 - IsPadding)` 作为 multiplicity
   - padding 行 multiplicity = 0（不贡献 sum）
   - `finalize_col() + finalize_last()` 返回 (4 个 CircleEvaluation, claimed_sum)

#### 测试结果

5 个多组件测试全部通过：
- `test_prove_verify_multi_padding_only`：空 trace（仅 padding）→ 通过
- `test_prove_verify_multi_lw`：单条 LW 指令 → 通过
- `test_prove_verify_multi_sw`：单条 SW 指令 → 通过
- `test_prove_verify_multi_mixed_load_store_different_addrs`：不同地址 Load+Store 混合 → 通过
- `test_prove_verify_multi_lw_sw_sequence`：**同地址** SW+LW 序列（`is_continuation=1`）→ 通过

全部 392 个 poker_zkvm 测试通过（含 31 个 prover 测试 + 3 个 memory_air 测试）。

#### 关键 bug 修复：offset=-1 → offset=-2（**核心教训**）

**问题**：`test_prove_verify_multi_lw_sw_sequence` 报 `ConstraintsNotSatisfied`，其他 4 个多组件测试通过。

**根因**：在 SubDomain 评估模式下，eval_domain（2048 点）是 trace_domain（1024 点）的 2 倍。Stwo 的 `offset_bit_reversed_circle_domain_index` 计算 `step_size = offset * (1 << (eval_log_size - domain_log_size - 1))`：
- `offset=-1` → `step_size = -1`（**半个** trace 步，**不是** "previous row"）
- `offset=-2` → `step_size = -2`（**一个** trace 步 = 真正的 "previous row"）

**修复**：将 `memory_air.rs:166` 的 `next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -1])` 改为 `[0, -2]`，正确读取 Memory trace 的 previous row。

**影响范围**：
- `MemoryAir` 的连续性约束 M18-M25（ValPrev/TsPrev continuity）需要 `offset=-2`
- `CpuAir` 不受影响（所有约束在同行内，仅用 `next_trace_mask()`，offset=0）
- logup 的 `next_extension_interaction_mask([-1, 0])` 不受影响（cumsum 由 `inclusive_prefix_sum` 在 coset order 计算，机制与 original trace 读取不同）

#### 工程要点

- `LogupTraceGenerator::new(log_size)` → `new_col()` → `write_frac(vec_row, num, denom)` → `finalize_col()` → `finalize_last()` 返回 `(4 CircleEvaluation, claimed_sum)`
- `LogupTraceGenerator::finalize_last()` 在 `CanonicCoset::new(self.log_size).circle_domain()` 上创建 evaluation（trace domain，非 eval domain）
- `inclusive_prefix_sum` 在 **COSET order** 计算 prefix sum，结果存储在 **bit-reversed circle domain order**
- `FrameworkComponent::new(allocator, air, claimed_sum)` — 第三个参数为该组件的 logup sum
- `MemoryLookup::draw(&mut channel)` — 必须在 Tree 1 commit 之后、Tree 2 之前调用
- `channel.mix_felts(&[...])` — 通信 claimed_sums 给 verifier

### 10.6 Phase 3.6-3.7 待完成

- **Phase 3.6**：Register AIR 接线 + 边缘 case 测试
  - 新建 `register_air.rs` 实现 `RegisterAir` FrameworkEval
  - 接线 `RegisterLookup`（移除 `#[allow(dead_code)]`）
  - 扩展 `prover.rs` 支持 3 组件 prove（CPU + Memory + Register）
  - 边缘 case 测试：uninitialized register、register write back to x0、overlapping rs1=rd
- **Phase 3.7**：Syscall AIR 骨架 + 文档最终化
  - `syscall_air.rs` 骨架（ECALL/EBREAK binality + dispatch indicator）
  - 自定义 syscall（poseidon/sha256/keccak/merkle）接口预留，留待 Phase 4 实现

