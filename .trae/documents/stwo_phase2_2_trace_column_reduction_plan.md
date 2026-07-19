# Phase 2.2 — Trace 列数精简设计文档

> **⚠️ DEPRECATED（2026-07-20）**：本文档基于 v1 fold 改写路线（2×30-bit limb），已被 v2 路线（4×8-bit limb）取代。
> 详见 [hypernova_to_stwo_migration_plan_v2.md](hypernova_to_stwo_migration_plan_v2.md) 和 [stwo_phase1_native_trace_design.md](stwo_phase1_native_trace_design.md)。
> 本文档保留作为历史参考，不再作为实施依据。

**生成时间**：2026-07-19
**作者**：zchain agent
**关联文档**：
- `.trae/documents/hypernova_to_stwo_migration_plan.md`（总迁移计划，§Phase 2）
- `.trae/documents/stwo_poc_decision_report.md`（决策门报告，§6.2.1）
**依赖**：Phase 2.1d 已完成（真实 Group A 约束 + e2e 测试 3/3 通过）

---

## 1. 目标与范围

### 1.1 性能目标

| 指标 | Phase 2.1d 现状 | Phase 2.2 目标 | 决策门要求 |
|------|----------------|----------------|-----------|
| trace 列数 | 47 | 8-12（推荐 13，见 §3） | — |
| 1M 步 prove 耗时 | 62764ms（0.14×） | 6000-12000ms（0.7-1.5×） | ≤ 86.7ms（100×） |
| 1024 步 prove 耗时 | 96.47ms | 20-30ms | — |
| proof 大小 | 25869 bytes | 15000-20000 bytes | < 64KB |

**注**：Phase 2.2 单独无法达到 100× 决策门，需叠加 Phase 2.2.x（parallel feature）+ Phase 2.2.x（GPU backend）才能最终达标。Phase 2.2 是性能优化的**必经路径**，不是终点。

### 1.2 设计原则

1. **不破坏约束表达力**：列合并不得导致任何 Group A-F 约束无法表达。
2. **保持与 Hypernova `STEP_VARS` 的可映射性**：每个新列可由原 47 列计算得出，便于 `convert_trace_to_stwo` 适配。
3. **遵循 Stwo 最佳实践**：参考 RISC Zero（~16 列）、Nexus zkVM 3.0（~12 列）的列布局经验。
4. **保留 Phase 2.1d 修复成果**：`row_to_position` 索引语义、`is_last_row` preprocessed column、`max_constraint_log_degree_bound = log_size + 1` 等修复必须沿用。
5. **先行设计，分步实施**：本文档为设计阶段（Phase 2.2.1），实施分 4 个子任务（Phase 2.2.2-2.2.5）。

### 1.3 不在范围内

- **Group B-F 约束实现**：本文档仅设计列布局与约束重写方案，实际约束实现属于 Phase 2.3+。
- **parallel feature 启用**：属于 Phase 2.2.x（后续子阶段）。
- **GPU backend 探索**：属于 Phase 2.2.x（后续子阶段）。
- **递归聚合**：属于 Phase 5。

---

## 2. 现状分析

### 2.1 当前 47 列布局（Hypernova `STEP_VARS`）

来源：[poker_zkvm/src/constraints/mod.rs:57-86](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L57-L86)

| 列索引 | 列名 | 用途 | Group A 约束使用 |
|--------|------|------|------------------|
| 0 | `idx` | step_index | ✅ 当前 + 下一行 |
| 1 | `pc` | 当前 PC | ❌ |
| 2 | `next_pc` | 下一 PC（PC + 4 或分支目标） | ❌ |
| 3 | `rs1_val` | 源寄存器 1 值 | ❌ |
| 4 | `rs2_val` | 源寄存器 2 值 | ❌ |
| 5 | `rd_val` | 目标寄存器值 | ❌ |
| 6 | `imm` | 立即数 | ❌ |
| 7 | `carry` | 加法进位（SUB/SLT/SLTU） | ❌ |
| 8 | `taken` | 分支是否跳转（0/1） | ❌ |
| 9 | `shamt` | 移位量（SLL/SRL/SRA/SLLI/SRLI/SRAI） | ❌ |
| 10 | `branch_cond` | 分支条件中间值 | ❌ |
| 11 | `aux` | 辅助值（多 limb 运算中间值） | ❌ |
| 12-46 | `sel_0..sel_34` | 35 个 one-hot selector | ❌ |

### 2.2 35 个 selector 对应的指令类别

来源：[poker_zkvm/src/constraints/mod.rs:117-167](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L117-L167) `instruction_category`

| selector | 指令类别 | 共享 selector 的指令数 |
|----------|---------|----------------------|
| sel_0 | LUI | 1 |
| sel_1 | AUIPC | 1 |
| sel_2 | JAL | 1 |
| sel_3 | JALR | 1 |
| sel_4-sel_9 | BEQ/BNE/BLT/BGE/BLTU/BGEU | 6（各 1） |
| sel_10 | LB/LH/LW/LBU/LHU | 5（共享） |
| sel_11 | SB/SH/SW | 3（共享） |
| sel_12-sel_20 | ADDI/SLTI/SLTIU/XORI/ORI/ANDI/SLLI/SRLI/SRAI | 9（各 1） |
| sel_21-sel_30 | ADD/SUB/SLL/SLT/SLTU/XOR/SRL/SRA/OR/AND | 10（各 1） |
| sel_31 | MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU | 8（共享） |
| sel_32 | FENCE | 1 |
| sel_33 | ECALL | 1 |
| sel_34 | EBREAK | 1 |

**关键观察**：
- 35 个 selector 中，sel_10/sel_11/sel_31 共享给多个指令（load/store/mul-div 各类），需 sub-opcode 区分。
- 实际 RV32I + M 扩展共 ~40 条指令，但 `instruction_category` 归并为 35 类。
- one-hot selector 的优势：约束可写为 `sel_j * (constraint_j) == 0`，degree 仅 +1。
- one-hot selector 的劣势：35 列 × 1M 行 = 35M field elements，是性能瓶颈主因。

### 2.3 当前 Group A-F 约束结构

来源：[poker_zkvm/src/constraints/mod.rs:536-545](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L536-L545)

| Group | 约束 | 涉及列 | Stwo 实现状态 |
|-------|------|--------|--------------|
| A | step_index 连续性 `idx_{i+1} - idx_i - 1 = 0` | idx | ✅ Phase 2.1d |
| B | PC 连续性 `next_pc_i - pc_{i+1} = 0` | next_pc, pc | ❌ Phase 2.3 |
| C | selector one-hot `Σ_j sel_j(i) - 1 = 0` | sel_0..sel_34 | ❌ Phase 2.3 |
| D | selector 二值性 `sel_j(i)² - sel_j(i) = 0` | sel_0..sel_34 | ❌ Phase 2.3 |
| E | 算术/逻辑/移位语义（per-instruction） | rs1_val, rs2_val, rd_val, imm, carry, shamt | ❌ Phase 2.3 |
| F | carry 二值性 `carry(i)² - carry(i) = 0` | carry | ❌ Phase 2.3 |

### 2.4 性能瓶颈量化

- **47 列 × 1M 行 = 47M BaseField (M31, 4 bytes) = 188 MB** trace 数据
- Merkle commit：47 列各自构建 Merkle tree，每列 1M 叶子
- OODS 求值：47 列各自在 OODS point 求值
- FRI query：47 列各自 decommit

**列数精简到 13 列的理论加速比**：47/13 ≈ 3.6×（线性缩减假设下），实际因 FRI log 层数不变，加速比约 3-4×。

---

## 3. 推荐方案：opcode + 数据列（13 列）

### 3.1 新列布局

| 新列索引 | 列名 | 类型 | 来源（Hypernova 列） | 用途 |
|----------|------|------|---------------------|------|
| 0 | `idx` | u32 | idx | step_index（保留，Group A 用） |
| 1 | `pc` | u32 | pc | 当前 PC |
| 2 | `next_pc` | u32 | next_pc | 下一 PC（Group B 用） |
| 3 | `rs1_val` | u32 | rs1_val | 源寄存器 1 值 |
| 4 | `rs2_val` | u32 | rs2_val | 源寄存器 2 值 |
| 5 | `rd_val` | u32 | rd_val | 目标寄存器值 |
| 6 | `imm` | u32 | imm | 立即数 |
| 7 | `carry` | u8 (0/1) | carry | 加法进位（Group F 用） |
| 8 | `taken` | u8 (0/1) | taken | 分支跳转标记 |
| 9 | `shamt` | u8 (0-31) | shamt | 移位量 |
| 10 | `branch_cond` | u32 | branch_cond | 分支条件中间值 |
| 11 | `aux` | u32 | aux | 辅助值 |
| 12 | `opcode` | u8 (0-34) | argmax(sel_0..sel_34) | 指令类别（替代 35 列 selector） |

**总列数**：13（数据列 12 + opcode 1）

**列数缩减**：47 → 13，缩减比 3.6×

### 3.2 与 Hypernova `STEP_VARS` 的映射

**数据列（col 0-11）**：1:1 直接复制，无转换。

**opcode 列（col 12）**：
```rust
fn selector_to_opcode(sels: &[Fr; 35]) -> u8 {
    // argmax：找到 sel_j == 1 的 j
    (0..35).find(|&j| sels[j] == Fr::one()).unwrap() as u8
}
```

**反向映射（验证用）**：
```rust
fn opcode_to_selector(opcode: u8) -> [Fr; 35] {
    let mut sels = [Fr::zero(); 35];
    sels[opcode as usize] = Fr::one();
    sels
}
```

### 3.3 约束重写方案

#### 3.3.1 Group A：step_index 连续性（保持不变）

```
(idx_next - idx_cur - 1) * (1 - is_last_row) == 0
```

- 涉及列：`idx`（col 0）+ preprocessed `is_last_row`
- degree：2
- Phase 2.1d 已实现，**无需修改**

#### 3.3.2 Group B：PC 连续性（保持不变）

```
(pc_next - next_pc_cur) * (1 - is_last_row) == 0
```

- 涉及列：`pc`（col 1, next row）、`next_pc`（col 2, cur row）
- degree：2
- Phase 2.3 实现

#### 3.3.3 Group C：selector one-hot → opcode range check（重写）

**原约束**（35 列 selector）：
```
Σ_{j=0}^{34} sel_j - 1 == 0
```

**新约束**（opcode range check）：
- 通过 LogUp lookup 验证 `opcode ∈ {0, 1, ..., 34}`
- LogUp table：`lookup_table = [(j, 1) for j in 0..35]`
- LogUp lookup：每行 `(opcode, 1)` 在 table 中存在
- **不再需要 Group C 多项式约束**，由 LogUp 协议保证

#### 3.3.4 Group D：selector 二值性 → 自动满足（消除）

**原约束**（35 列 selector）：
```
sel_j² - sel_j == 0  (for each j)
```

**新约束**：无。opcode 是单值（u8），无二值性约束需求。LogUp 已保证 opcode ∈ [0, 34]。

**收益**：消除 35 个 degree-2 约束，composition polynomial 系数大幅减少。

#### 3.3.5 Group E：算术/逻辑/移位语义（重写为 opcode dispatch）

**原约束**（selector gating）：
```
sel_j * (constraint_j) == 0  (for each instruction j)
```

**新约束**（opcode dispatch，两种方案选一）：

**方案 E1：opcode equality gating（推荐，degree +1）**
```
∏_{k ≠ j} (opcode - k) * constraint_j == 0
```
- degree：`34 * 1 + constraint_j_degree`（过高，不可行）

**方案 E2：indicator function via lookup（推荐，degree 不变）**
- 预计算 35 个 indicator 多项式 `I_j(opcode)`，满足 `I_j(j) = 1, I_j(k) = 0 for k ≠ j`
- 通过 LogUp 或 preprocessed column 实现
- 约束形式：`I_j(opcode) * constraint_j == 0`（degree = 1 + constraint_j_degree）

**方案 E3：直接 opcode 比较（Stwo 原生支持）**
- 使用 Stwo `EvalAtRow` 的 condition pattern：
  ```rust
  let is_add = opcode.equals(21);  // 返回 0/1 BaseField
  eval.add_constraint(is_add * (rd_val - rs1_val - rs2_val));
  ```
- `equals` 通过 `(opcode - j)^{p-1}` 实现（Fermat 小定理，degree = p-1 = 2^31 - 2，过高）
- 实际 Stwo 使用 lookup 或多约束并联

**推荐方案**：E2（indicator via LogUp），与 Group C 共享 LogUp 基础设施。

#### 3.3.6 Group F：carry 二值性（保持不变）

```
carry² - carry == 0
```

- 涉及列：`carry`（col 7）
- degree：2
- 可选：通过 LogUp range check `carry ∈ {0, 1}` 替代（消除约束）

### 3.4 LogUp lookup 协议设计

#### 3.4.1 lookup table 定义

| Table 名称 | 列 | 行数 | 用途 |
|-----------|-----|------|------|
| `opcode_table` | `(opcode, 1)` | 35 | Group C: opcode range check |
| `carry_table` | `(carry, 1)` | 2 | Group F: carry 二值性 |
| `shamt_table` | `(shamt, 1)` | 32 | shamt range check（可选） |
| `indicator_table` | `(opcode, j, I_j)` | 35×35 | Group E: indicator function |

#### 3.4.2 LogUp 集成方式

参考 [Stwo book: Static Lookups](https://zksecurity.github.io/stwo-book/air-development/static-lookups/)：

```rust
// 在 CpuAirEval::evaluate 中
let opcode = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);
eval.add_lookup(
    LookupOp::Read(opcode, BaseField::from(1u32)),
    "opcode_table",
);
```

**Phase 2.2 实施范围**：仅设计 LogUp 接入点，实际 LogUp lookup 协议实现属于 Phase 2.3（与原迁移计划 §2.5 一致）。

### 3.5 preprocessed columns 清单

| preprocessed column | 用途 | 构造方式（prover.rs） |
|---------------------|------|----------------------|
| `cpu_is_last_row` | Group A cyclic 边界豁免 | Phase 2.1d 已实现（`row_to_position[br] == n_rows - 1`） |
| `cpu_opcode_table`（可选） | LogUp opcode table | Phase 2.3 实现 |
| `cpu_indicator_j`（可选） | Group E indicator functions | Phase 2.3 实现，35 列（仅 preprocessed，不计入 original trace） |

**注**：preprocessed columns 不计入 13 列 original trace，但计入总 commitment 开销。Phase 2.2 优先保持 1 个 preprocessed column（is_last_row），opcode_table/indicator 留待 Phase 2.3。

---

## 4. 备选方案对比

### 4.1 方案对比表

| 方案 | 列数 | 优点 | 缺点 | 推荐度 |
|------|------|------|------|--------|
| **A：opcode + 数据列（§3）** | 13 | 列数最少，约束清晰 | 需 LogUp 基础设施 | ⭐⭐⭐⭐⭐ |
| B：opcode + sub_opcode + 数据列 | 14 | 区分 load/store/mul 子类型 | 多 1 列，子类型可用 imm 低 bits 替代 | ⭐⭐⭐ |
| C：保留 one-hot + 合并数据列 | 38 | 约束形式不变 | 列数仍过多，性能收益有限 | ⭐ |
| D：完全 LogUp-based | 8 | 列数最少 | LogUp 开销大，约束表达力受限 | ⭐⭐ |
| E：保留 selector + LogUp range check | 48 | 渐进式改造 | 列数反增 1 | ⭐ |

### 4.2 推荐方案 A 的理由

1. **列数 13 接近 8-12 目标**，性能加速比 3.6×。
2. **opcode 列天然替代 35 列 selector**，消除 Group D 的 35 个约束。
3. **数据列保持 1:1 映射**，`convert_trace_to_stwo` 适配简单。
4. **LogUp 是 Stwo 原生支持**，与 Phase 2.3（原迁移计划 §2.5）复用。
5. **不破坏 Phase 2.1d 修复**：`idx` 列、`is_last_row`、`row_to_position` 索引语义全部保留。

### 4.3 未选择方案的理由

- **方案 B**：sub_opcode 可用 `imm` 列低 bits 编码（load 宽度 / store 宽度 / mul-div 子类型），无需独立列。
- **方案 C**：38 列仍远超 8-12 目标，性能收益不足以达标。
- **方案 D**：完全 LogUp 会导致 lookup 查询量爆炸（每行 ~10 次查询），LogUp 开销压倒列数收益。
- **方案 E**：列数反增，无性能收益。

---

## 5. 实施子任务（Phase 2.2.2-2.2.5）

### 5.1 Phase 2.2.2：StwoTraceTable 列定义重构

**目标**：新增 `StwoColumnLayout` 模块，定义 13 列布局常量与索引。

**修改文件**：
- 新增 `poker_zkvm/src/stwo_backend/column_layout.rs`
- 修改 `poker_zkvm/src/stwo_backend/mod.rs`（导出新模块）

**关键代码骨架**：
```rust
// poker_zkvm/src/stwo_backend/column_layout.rs
pub const NUM_COLUMNS: usize = 13;
pub const COL_IDX: usize = 0;
pub const COL_PC: usize = 1;
pub const COL_NEXT_PC: usize = 2;
pub const COL_RS1_VAL: usize = 3;
pub const COL_RS2_VAL: usize = 4;
pub const COL_RD_VAL: usize = 5;
pub const COL_IMM: usize = 6;
pub const COL_CARRY: usize = 7;
pub const COL_TAKEN: usize = 8;
pub const COL_SHAMT: usize = 9;
pub const COL_BRANCH_COND: usize = 10;
pub const COL_AUX: usize = 11;
pub const COL_OPCODE: usize = 12;

/// 将 Hypernova 47 列 witness 映射为 13 列 Stwo witness。
pub fn map_step_vars_to_stwo(
    step_vars: &[crate::ccs::Fr; crate::constraints::STEP_VARS],
) -> [M31; NUM_COLUMNS] {
    let mut result = [M31::from(0u32); NUM_COLUMNS];
    // 数据列 1:1 复制
    for i in 0..12 {
        result[i] = fr_to_m31_single(&step_vars[i]);
    }
    // opcode 列：argmax(sel_0..sel_34)
    let opcode = (0..35)
        .find(|&j| step_vars[12 + j] == crate::ccs::Fr::one())
        .unwrap_or(0) as u8;
    result[COL_OPCODE] = M31::from(opcode as u32);
    result
}
```

**验收测试**：
- `test_column_layout_num_columns`：`NUM_COLUMNS == 13`
- `test_map_step_vars_to_stwo_data_columns`：数据列 1:1 映射
- `test_map_step_vars_to_stwo_opcode`：opcode = argmax(selector)
- `test_map_step_vars_to_stwo_roundtrip`：selector → opcode → selector 一致

### 5.2 Phase 2.2.3：CpuAirEval 约束重写

**目标**：基于 13 列布局重写 `CpuAirEval::evaluate`，保留 Group A，预留 Group B-F 接口。

**修改文件**：
- `poker_zkvm/src/stwo_backend/air/cpu.rs`

**关键修改**：
```rust
fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
    let one: E::F = BaseField::from(1u32).into();

    // 注册 13 列 mask（按新布局）
    let [idx_cur, idx_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);  // col 0
    let [_pc_cur, _pc_next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);  // col 1
    let [next_pc_cur] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);            // col 2
    let [_rs1] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                   // col 3
    let [_rs2] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                   // col 4
    let [_rd] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                    // col 5
    let [_imm] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                   // col 6
    let [_carry] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                 // col 7
    let [_taken] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                 // col 8
    let [_shamt] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                 // col 9
    let [_branch_cond] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);           // col 10
    let [_aux] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                   // col 11
    let [_opcode] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0]);                // col 12

    let is_last_row = eval.get_preprocessed_column(PreProcessedColumnId {
        id: Self::IS_LAST_ROW_COL_ID.into(),
    });

    // Group A：step_index 连续性（保持不变）
    let diff = idx_next - idx_cur - one.clone();
    let mask = one - is_last_row;
    eval.add_constraint(diff * mask);

    // TODO(Phase 2.3): Group B-F 约束
    // - Group B: (pc_next - next_pc_cur) * (1 - is_last_row)
    // - Group C: opcode range check via LogUp
    // - Group D: 消除（opcode 是单值）
    // - Group E: opcode dispatch via indicator
    // - Group F: carry² - carry

    eval
}
```

**max_constraint_log_degree_bound**：保持 `log_size + 1`（Group A 仍为 degree 2）。

**验收测试**：
- 现有 8/8 单元测试全部通过（`build_group_a_circle_domain_trace` 适配 13 列）
- `test_cpu_air_eval_num_columns`：注册 13 列 mask
- `InfoEvaluator::n_constraints == 1`（仅 Group A）

### 5.3 Phase 2.2.4：convert_trace_to_stwo 适配

**目标**：修改 `convert_trace_to_stwo`，输出 13 列 `StwoTraceTable`。

**修改文件**：
- `poker_zkvm/src/stwo_backend/trace.rs`

**关键修改**：
```rust
pub fn convert_trace_to_stwo(trace: &Trace) -> Result<StwoTraceTable, ZkvmError> {
    // ...
    let num_columns = crate::stwo_backend::column_layout::NUM_COLUMNS;  // 13（原 STEP_VARS=47）
    let mut table = StwoTraceTable::new(num_columns, padded_rows);

    for i in 0..num_steps {
        let step = trace.step(i)?;
        let prev_step = if i > 0 { Some(trace.step(i - 1)?) } else { None };
        let next_step_pc = if i + 1 < num_steps { Some(trace.step(i + 1)?.pc) } else { None };
        let witness: Vec<ZkvmFr> = compile_step_witness(step, prev_step, next_step_pc);
        let mapped = crate::stwo_backend::column_layout::map_step_vars_to_stwo(&witness);
        for (col, m31_val) in mapped.iter().enumerate() {
            table.set(col, i, *m31_val);
        }
    }
    Ok(table)
}
```

**prover.rs 适配**：
- `trace_evals` 构造：idx 列（col 0）使用 `row_to_position[bit_reverse_index]`，其他 12 列直接复制（保持 Phase 2.1d Fix #4 逻辑）
- `is_last_row` 列构造：保持不变
- 删除 `for _ in 1..STEP_VARS` 循环，改为 13 列显式处理

**验收测试**：
- `test_convert_trace_num_columns_matches_layout`：列数 = 13
- `test_convert_trace_opcode_column`：opcode = argmax(selector)
- 现有 5/5 trace.rs 单元测试适配后通过

### 5.4 Phase 2.2.5：e2e 测试更新与性能基准

**目标**：更新 e2e 测试，重新采集性能基准，对比 Phase 2.1d。

**修改文件**：
- `poker_zkvm/tests/stwo_poc_e2e.rs`

**关键测试**：
- `test_stwo_poc_prove_minimal_trace`：1024 步，验证 proof 生成
- `test_stwo_poc_serialization_roundtrip`：序列化往返
- `test_stwo_poc_decision_gate_1m_steps`：1M 步，性能基准
- 新增 `test_stwo_poc_column_count_13`：断言 trace 列数 = 13

**性能基准采集项**：
| 指标 | Phase 2.1d | Phase 2.2.5 目标 |
|------|-----------|-----------------|
| 1024 步 prove 耗时 | 96.47ms | 20-30ms |
| 1M 步 prove 耗时 | 62764ms | 6000-12000ms |
| proof 大小（1024 步） | 8749 bytes | 5000-7000 bytes |
| proof 大小（1M 步） | 25869 bytes | 15000-20000 bytes |

**决策门更新**：
- 若 1M 步 prove 耗时降至 < 12000ms（0.14× → 0.7×+），Phase 2.2 成功，进入 Phase 2.2.x（parallel feature）
- 若未达标，分析瓶颈（LogUp 开销 / FRI 层数 / 其他），调整方案

---

## 6. 风险与缓解

### 6.1 已识别风险

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| LogUp 基础设施未实现 | Group C/E 无法表达 | Phase 2.2 仅实现 Group A（不依赖 LogUp），Group C/E 留待 Phase 2.3 |
| opcode dispatch 约束 degree 过高 | composition polynomial degree 爆炸 | 优先用 LogUp indicator（方案 E2），避免 Fermat 小定理 |
| `convert_trace_to_stwo` 适配引入 bug | trace 数据错位 | 保留 Phase 2.1d 的 `row_to_position` 测试，新增 opcode 列测试 |
| 列数变化破坏 Phase 2.1d 修复 | `ConstraintsNotSatisfied` 复发 | idx 列（col 0）处理逻辑保持不变，仅删除 col 13-46 的零列 |
| Hypernova `STEP_VARS` 仍被 CCS 使用 | 双轨维护成本 | Phase 2.2 仅影响 Stwo backend，Hypernova CCS 保持不变（Phase 5 废弃） |

### 6.2 回滚方案

若 Phase 2.2 实施后发现性能未达预期或约束表达力不足：
1. **回滚列布局**：恢复 `STEP_VARS = 47` 列，`convert_trace_to_stwo` 直接复制 47 列
2. **保留 column_layout 模块**：作为后续优化的基础，不删除
3. **Phase 2.2.x 备选**：直接启用 parallel feature（47 列 × rayon 并行），可能足够达标

### 6.3 验证检查点

| 检查点 | 验证方式 | 通过标准 |
|--------|---------|---------|
| Phase 2.2.2 完成 | 单元测试 | `NUM_COLUMNS == 13`，映射函数 roundtrip 一致 |
| Phase 2.2.3 完成 | 单元测试 | 8/8 + 新增测试通过，`n_constraints == 1` |
| Phase 2.2.4 完成 | 单元测试 + e2e 编译 | trace.rs 5/5 测试通过，e2e 测试编译通过 |
| Phase 2.2.5 完成 | e2e 测试 + 性能基准 | 3/3 e2e 通过，1M 步 prove < 12000ms |

---

## 7. 时间估算

| 子任务 | 估算工时 | 依赖 |
|--------|---------|------|
| Phase 2.2.1（本文档） | 已完成 | — |
| Phase 2.2.2（column_layout 模块） | 0.5 天 | — |
| Phase 2.2.3（CpuAirEval 重写） | 0.5 天 | 2.2.2 |
| Phase 2.2.4（convert_trace_to_stwo 适配） | 1 天 | 2.2.2, 2.2.3 |
| Phase 2.2.5（e2e 测试 + 基准） | 0.5 天 | 2.2.4 |
| **合计** | **2.5 天** | |

---

## 8. 后续阶段

### 8.1 Phase 2.2.x：parallel feature 启用（1 天）

- Cargo.toml 添加 `stwo = { version = "2.3", features = ["parallel"] }`
- 测试 rayon 列级并行加速比
- 预期 1M 步 prove 耗时降至 2000-4000ms（13 列 × rayon 4-8 线程）

### 8.2 Phase 2.3：Group B-F 约束实现（1-2 周）

- Group B（PC 连续性）：直接约束
- Group C（opcode range check）：LogUp lookup
- Group E（算术/逻辑/移位语义）：opcode dispatch via indicator
- Group F（carry 二值性）：LogUp 或多项式约束

### 8.3 Phase 2.2.x：GPU backend 探索（3-5 天）

- 评估 Stwo 2.3.0 GPU backend 成熟度
- 测试 CUDA/Metal 加速比
- 预期 1M 步 prove 耗时降至 500-1000ms

### 8.4 决策门最终评估

在 Phase 2.2 + 2.2.x（parallel）+ 2.3 完成后，重新评估 100× 决策门：
- 若 1M 步 prove ≤ 86.7ms（100×），进入 Phase 3-5
- 若 1M 步 prove 在 100-1000ms（10-100×），考虑 GPU backend 补强
- 若 1M 步 prove > 1000ms（< 10×），重新评估迁移可行性

---

## 9. 附录

### 9.1 关键文件清单

| 文件 | Phase 2.2 角色 |
|------|---------------|
| `poker_zkvm/src/constraints/mod.rs` | **只读参考**：`STEP_VARS = 47`、`instruction_category`、`compile_step_witness` |
| `poker_zkvm/src/stwo_backend/trace.rs` | **修改**：`StwoTraceTable`、`convert_trace_to_stwo` |
| `poker_zkvm/src/stwo_backend/air/cpu.rs` | **修改**：`CpuAirEval::evaluate`、测试 |
| `poker_zkvm/src/stwo_backend/prover.rs` | **修改**：`prove_internal` trace_evals 构造 |
| `poker_zkvm/src/stwo_backend/column_layout.rs` | **新增**：13 列布局定义、映射函数 |
| `poker_zkvm/tests/stwo_poc_e2e.rs` | **修改**：e2e 测试 + 性能基准 |

### 9.2 Stwo LogUp 参考文档

- [Stwo book: Static Lookups](https://zksecurity.github.io/stwo-book/air-development/static-lookups/)
- `stwo-constraint-framework-2.3.0/src/lookup.rs` — LogUp 实现参考
- `stwo-2.3.0/src/prover/lookups/` — LogUp prover 实现

### 9.3 参考 zkVM 列布局

| zkVM | trace 列数 | selector 方式 | 参考 |
|------|-----------|--------------|------|
| RISC Zero | ~16 | opcode + LogUp | [risc0](https://github.com/risc0/risc0) |
| Nexus zkVM 3.0 | ~12 | opcode + LogUp | [nexus](https://github.com/nexus-xyz/nexus-zkvm) |
| Stwo examples | 3-8 | 直接约束 | [stwo examples](https://github.com/starkware-libs/stwo) |
| **zchain Phase 2.1d（当前）** | 47 | one-hot selector | — |
| **zchain Phase 2.2（目标）** | 13 | opcode + LogUp | — |

---

**设计文档结束**
