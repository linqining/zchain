# Phase 2.3.4-b 设计文档：ADDI/ADD/SUB 算术约束 + Limb Decomposition

> **⚠️ DEPRECATED（2026-07-20）**：本文档基于 v1 fold 改写路线（2×30-bit limb + carry_low），已被 v2 路线（4×8-bit limb + 16-bit 边界 CarryFlag）取代。
> 详见 [hypernova_to_stwo_migration_plan_v2.md](hypernova_to_stwo_migration_plan_v2.md) 和 [stwo_phase1_native_trace_design.md](stwo_phase1_native_trace_design.md)。
> 本文档保留作为历史参考，不再作为实施依据。

**创建时间**：2026-07-20
**作者**：zchain agent
**关联文档**：
- `.trae/documents/hypernova_to_stwo_migration_plan.md`（总迁移计划）
- `.trae/documents/stwo_poc_decision_report.md`（决策门报告，Phase 2.3.4-a 已完成）
- `.trae/documents/stwo_phase2_2_trace_column_reduction_plan.md`（Phase 2.2 列数精简设计）

## 1. 背景与动机

### 1.1 Phase 2.3.4-a 完成状态

Phase 2.3.4-a 已完成 Group F carry 二值性约束 `carry * (carry - 1) == 0`（universal，无 indicator gating），约束总数 7→8，所有测试通过（cpu 21/21, stwo_backend 78/78, e2e 3/3 含 1M 步 38.24s, lib 1245/1245）。Group F 是 Phase 2.3.4-b 的前置依赖，保证 carry ∈ {0, 1}，防止攻击者构造 carry=2 使算术约束虚假满足。

### 1.2 Phase 2.3.4-b 目标

实现 ADDI/ADD/SUB 三条算术指令的 Stwo AIR 约束，对应 Hypernova Group E 的 cat=12, 21, 22：

| 指令 | cat | Hypernova 约束 | Stwo 约束（待实现） |
|------|-----|----------------|---------------------|
| ADDI | 12 | `sel_12 * (rs1 + imm - rd - 2^32*carry) = 0` | `is_addi * (rs1_low + imm_low - rd_low - 2^30*carry_low) + ... = 0`（limb decomposition） |
| ADD | 21 | `sel_21 * (rs1 + rs2 - rd - 2^32*carry) = 0` | `is_add * (rs1_low + rs2_low - rd_low - 2^30*carry_low) + ... = 0` |
| SUB | 22 | `sel_22 * (rd - rs1 + rs2 - 2^32*carry) = 0` | `is_sub * (rd_low - rs1_low + rs2_low - 2^30*carry_low) + ... = 0` |

## 2. M31 域中 u32 加法的挑战

### 2.1 M31 模数特性

M31 模数 P = 2^31 - 1（Mersenne 31-bit prime）：
- `2^31 mod P = 1`（因 2^31 = P + 1）
- `2^32 mod P = 2`（因 2^32 = 2 * 2^31 = 2 * (P + 1) = 2P + 2，模 P = 2）

**问题**：Hypernova ADD 约束 `a + b - result - 2^32 * carry = 0` 在 BN254 域中，`2^32` 是明确的常数。但在 M31 域中，`2^32 mod P = 2`，直接翻译会得到 `a_m31 + b_m31 - result_m31 - 2 * carry = 0`，这是**错误的**。

### 2.2 30-bit limb 丢失高 2 bit

当前 `fr_to_m31_single` 取 `v & 0x3FFFFFFF`（低 30 bit），u32 值的高 2 bit 丢失：
- 例如 `0xDeadBeef & 0x3FFFFFFF = 0x1EADBEEF`（高 2 bit `11` 丢失）
- u32 值 `v = v_low + 2^30 * v_high`，其中 `v_low = v & 0x3FFFFFFF`，`v_high = v >> 30`

**问题**：若直接用 `v_low` 替代 `v`，ADD 约束 `a_low + b_low - result_low - 2 * carry = 0` 不成立，因 `a + b ≠ a_low + b_low`（丢失高 2 bit）。

### 2.3 limb decomposition 必要性

为正确表达 u32 加法，必须将每个 u32 值拆分为 low 30-bit + high 2-bit 两个 M31 limb，分别约束。`split_u32_to_m31_limbs` 函数已存在于 [field.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/field.rs)，返回 `(low, high)` 两个 M31 值。

## 3. Limb Decomposition 方案

### 3.1 u32 值的 limb 分解

将 u32 值 `v` 拆分为：
- `v_low = v & 0x3FFFFFFF`（低 30 bit，∈ [0, 2^30 - 1]）
- `v_high = v >> 30`（高 2 bit，∈ [0, 3]）
- 重建：`v = v_low + 2^30 * v_high`

### 3.2 u32 加法的 limb 约束

ADD 语义 `a + b = result + 2^32 * carry`（carry ∈ {0, 1}）在 limb decomposition 下：

```
a_low + 2^30 * a_high + b_low + 2^30 * b_high = result_low + 2^30 * result_high + 2^32 * carry
```

拆分为两级约束（分别验证 low 和 high limb）：

**Low limb 约束**：
```
a_low + b_low = result_low + 2^30 * carry_low
```
- `a_low, b_low ∈ [0, 2^30 - 1]`，故 `a_low + b_low ∈ [0, 2^31 - 2]`
- `result_low ∈ [0, 2^30 - 1]`，故 `carry_low ∈ {0, 1}`（进位最多 1）
- 约束形式：`a_low + b_low - result_low - 2^30 * carry_low = 0`

**High limb 约束**：
```
a_high + b_high + carry_low = result_high + 2^2 * carry_high
```
- `a_high, b_high ∈ [0, 3]`，`carry_low ∈ {0, 1}`，故 `a_high + b_high + carry_low ∈ [0, 7]`
- `result_high ∈ [0, 3]`，故 `carry_high ∈ {0, 1}`（进位最多 1，因 7 = 3 + 2^2 * 1）
- 约束形式：`a_high + b_high + carry_low - result_high - 4 * carry_high = 0`

**最终 carry**：`carry = carry_high`（u32 加法的 overflow bit）

**Group F 扩展**：需对 `carry_low` 和 `carry_high` 分别二值性约束：
- `carry_low * (carry_low - 1) = 0`
- `carry_high * (carry_high - 1) = 0`

### 3.3 M31 域中 2^30 的表达

`2^30 mod P = 2^30`（因 2^30 < P = 2^31 - 1），可直接作为 M31 常数使用。

`2^2 = 4`，也可直接作为 M31 常数。

## 4. 列布局扩展

### 4.1 当前 13 列布局（Phase 2.2）

| col | 列名 | 用途 |
|-----|------|------|
| 0 | idx | step_index（Group A） |
| 1 | pc | 当前 PC（Group B, Group E AUIPC） |
| 2 | next_pc | 下一 PC（Group B） |
| 3 | rs1_val | 源寄存器 1 值 |
| 4 | rs2_val | 源寄存器 2 值 |
| 5 | rd_val | 目标寄存器值（Group E LUI/AUIPC/SLT/LogShift） |
| 6 | imm | 立即数（Group E LUI/AUIPC） |
| 7 | carry | 加法进位（Group F, Group E SLT） |
| 8 | taken | 分支跳转标记 |
| 9 | shamt | 移位量 |
| 10 | branch_cond | 分支条件中间值 |
| 11 | aux | 辅助值（Group E LogShift） |
| 12 | opcode | 指令类别（Group C LogUp） |

### 4.2 Phase 2.3.4-b 扩展布局（13→18 列）

**方案 A（推荐）**：新增 5 个 limb 列，保留原列兼容 Group E 现有约束

| col | 列名 | 用途 | 备注 |
|-----|------|------|------|
| 0 | idx | step_index | 不变 |
| 1 | pc | 当前 PC | 不变 |
| 2 | next_pc | 下一 PC | 不变 |
| 3 | rs1_val | 源寄存器 1 值（low 30 bit） | Group E 现有约束继续使用 |
| 4 | rs2_val | 源寄存器 2 值（low 30 bit） | Group E 现有约束继续使用 |
| 5 | rd_val | 目标寄存器值（low 30 bit） | Group E 现有约束继续使用 |
| 6 | imm | 立即数（low 30 bit） | Group E 现有约束继续使用 |
| 7 | carry | 加法进位（= carry_high，u32 overflow） | Group F, Group E SLT 继续使用 |
| 8 | taken | 分支跳转标记 | 不变 |
| 9 | shamt | 移位量 | 不变 |
| 10 | branch_cond | 分支条件中间值 | 不变 |
| 11 | aux | 辅助值 | Group E LogShift 继续使用 |
| 12 | opcode | 指令类别 | 不变 |
| **13** | **rs1_high** | rs1_val 高 2 bit | **新增**（Phase 2.3.4-b） |
| **14** | **rs2_high** | rs2_val 高 2 bit | **新增** |
| **15** | **rd_high** | rd_val 高 2 bit | **新增** |
| **16** | **imm_high** | imm 高 2 bit | **新增** |
| **17** | **carry_low** | low limb 进位位 | **新增**（carry = carry_high） |

**列数**：13 → 18（+5）

### 4.3 列布局扩展的兼容性

- **Group A/B/C**：不使用新增列，约束不变
- **Group E LUI/AUIPC**：使用原 rs1_val/rd_val/imm（low 30 bit），约束不变（LUI/AUIPC 的值通常 < 2^30，low limb 足够）
- **Group E SLT**：使用原 rd_val/carry，约束不变（SLT 的 rd_val ∈ {0, 1}，carry ∈ {0, 1}）
- **Group E LogShift**：使用原 rd_val/aux，约束不变
- **Group F**：原 carry 列仍用于 Group E SLT，新增 carry_low 用于 ADDI/ADD/SUB low limb 约束
- **Group F 扩展**：新增 carry_low 二值性约束 `carry_low * (carry_low - 1) = 0`

## 5. ADDI/ADD/SUB 约束形式

### 5.1 ADD 约束（cat=21）

```
is_add * (rs1_low + rs2_low - rd_val - 2^30 * carry_low) = 0          // Low limb
is_add * (rs1_high + rs2_high + carry_low - rd_high - 4 * carry) = 0  // High limb
```

其中 `carry = carry_high`（col 7），`carry_low`（col 17）。

**注意**：原 col 7 `carry` 现在表示 u32 加法的 overflow bit（= carry_high），与 Hypernova 语义一致。

### 5.2 ADDI 约束（cat=12）

```
is_addi * (rs1_low + imm - rd_val - 2^30 * carry_low) = 0          // Low limb
is_addi * (rs1_high + imm_high + carry_low - rd_high - 4 * carry) = 0  // High limb
```

### 5.3 SUB 约束（cat=22）

SUB 语义 `a - b = result`（borrow 语义：当 a < b 时 borrow=1，result = a - b + 2^32）：
```
a - b - result + 2^32 * borrow = 0
```

limb decomposition：
```
a_low - b_low - result_low + 2^30 * borrow_low = 0          // Low limb
a_high - b_high - result_high + borrow_low - 2^2 * borrow = 0  // High limb
```

**注意**：SUB 的 borrow 语义与 ADD 的 carry 语义方向相反（SUB 是 `+2^32 * borrow`，ADD 是 `-2^32 * carry`）。

Stwo 约束：
```
is_sub * (rs1_low - rs2_low - rd_val + 2^30 * carry_low) = 0          // Low limb（borrow_low = carry_low）
is_sub * (rs1_high - rs2_high - rd_high + carry_low - 4 * carry) = 0  // High limb
```

**关键**：SUB 中 `carry` 列表示 borrow bit（=1 表示借位），与 ADD 中 `carry` 列表示 overflow bit 语义不同，但 Group F 二值性约束对两者都适用。

### 5.4 Group F 扩展约束

```
carry_low * (carry_low - 1) = 0  // carry_low 二值性（新增）
carry * (carry - 1) = 0          // carry 二值性（Phase 2.3.4-a 已实现）
```

### 5.5 Indicator 方案

新增 3 个 preprocessed indicator：
- `is_addi`：opcode == 12
- `is_add`：opcode == 21
- `is_sub`：opcode == 22

preprocessed tree 从 5 列扩展为 8 列（is_last_row + is_lui + is_auipc + is_slt + is_logical_shift + is_addi + is_add + is_sub）。

## 6. 实现步骤

### 6.1 列布局更新（column_layout.rs）

1. 更新 `NUM_COLUMNS` 13 → 18
2. 新增列索引常量：`COL_RS1_HIGH = 13`, `COL_RS2_HIGH = 14`, `COL_RD_HIGH = 15`, `COL_IMM_HIGH = 16`, `COL_CARRY_LOW = 17`
3. 更新 `map_step_vars_to_stwo` 拆分 u32 值为 low + high limb

### 6.2 CpuAirEval 更新（cpu.rs）

1. 新增 3 个 indicator 常量：`IS_ADDI_COL_ID`, `IS_ADD_COL_ID`, `IS_SUB_COL_ID`
2. evaluate 函数：
   - 注册 5 个新列的 mask（col 13-17）
   - 读取 3 个新 indicator（is_addi, is_add, is_sub）
   - 添加 6 个新约束（ADDI/ADD/SUB 各 2 个 limb 约束）
   - 添加 1 个 Group F 扩展约束（carry_low 二值性）
3. `max_constraint_log_degree_bound` 注释更新（新增约束均为 degree 2，bound 不变）

### 6.3 Prover 更新（prover.rs）

1. `make_indicator` 闭包扩展支持 3 个新 indicator
2. preprocessed tree 从 5 列扩展为 8 列
3. trace 构造添加 5 个新列（low/high limb 拆分）

### 6.4 测试更新

1. InfoEvaluator 测试约束数 8 → 15（+6 ADDI/ADD/SUB 约束 + 1 carry_low 二值性）
2. `build_group_ab_circle_domain_trace` helper 返回值新增 5 个 limb 列 + 3 个 indicator 列
3. 现有测试更新解构与 preprocessed vec
4. 新增 9 个 Group E ADDI/ADD/SUB 专项测试（3 指令 × 正例 + 负例 + limb 边界）

### 6.5 实现顺序（渐进式）

**Step 1**：列布局扩展（column_layout.rs）+ `map_step_vars_to_stwo` 更新
**Step 2**：CpuAirEval 新增列 mask 注册 + Group F carry_low 二值性约束
**Step 3**：ADD 约束实现（先 ADD，因最简单，无 imm 符号问题）
**Step 4**：ADDI 约束实现（与 ADD 类似，imm 替代 rs2）
**Step 5**：SUB 约束实现（borrow 语义，符号方向相反）
**Step 6**：测试套件验证（cpu + stwo_backend + e2e + lib）

## 7. 性能预期

- 列数 13 → 18（+38%），预计 1M 步 prove 性能下降 ~10-15%（参考 Phase 2.2 经验：47→13 带来 2.57× 加速，13→18 预计 -10-15%）
- preprocessed 列 5 → 8（+60%），预计额外 -2-3%
- 约束数 8 → 15（+75%），预计额外 -3-5%
- **总体预期**：1M 步 prove 从 38240ms 增至 ~48000-52000ms（+25-35%）

## 8. 风险与缓解

### 8.1 列布局扩展的兼容性风险

**风险**：现有 Group E LUI/AUIPC/SLT/LogShift 约束使用原列（low 30 bit），若 ADDI/ADD/SUB 的 rd_val 需要完整 u32 值，可能与 Group E 约束冲突。

**缓解**：ADDI/ADD/SUB 的 rd_val 仍用原列（low 30 bit），新增 rd_high 列存储高 2 bit。Group E LUI/AUIPC/SLT/LogShift 约束不使用 rd_high，兼容性保持。

### 8.2 M31 域中 2^30 的溢出风险

**风险**：`a_low + b_low` 最大值 `2*(2^30-1) = 2^31 - 2`，在 M31 中 < P = 2^31 - 1，不溢出。但 `2^30 * carry_low` 在 M31 中 = 2^30（因 2^30 < P），正确。

**缓解**：所有 limb 运算均在 M31 范围内，无需额外模运算处理。

### 8.3 SUB 的 borrow 语义混淆

**风险**：SUB 中 `carry` 列表示 borrow bit（=1 表示借位），与 ADD 中 `carry` 列表示 overflow bit 语义不同。若 prover 错误设置 carry 值，可能导致约束虚假满足。

**缓解**：(1) Group F 二值性约束保证 carry ∈ {0, 1}；(2) ADDI/ADD/SUB 的 indicator gating 保证仅对应指令行检查算术约束；(3) 测试覆盖正例（carry=0/1）+ 负例（carry=2 违反 Group F，约束形式错误违反 ADDI/ADD/SUB）。

## 9. 测试策略

### 9.1 ADDI/ADD/SUB 专项测试（9 个）

- **ADD 正例**：`is_add=1`，构造 `rs1 + rs2 = rd + 2^32 * carry`，两级 limb 约束满足
- **ADD 负例**：`is_add=1`，构造 `rs1 + rs2 ≠ rd + 2^32 * carry`，约束失败 panic
- **ADD limb 边界**：`rs1_low + rs2_low` 溢出 2^30，carry_low=1，验证 low limb 约束
- **ADDI 正例**：`is_addi=1`，构造 `rs1 + imm = rd + 2^32 * carry`
- **ADDI 负例**：`is_addi=1`，构造 `rs1 + imm ≠ rd + 2^32 * carry`
- **SUB 正例**：`is_sub=1`，构造 `rs1 - rs2 = rd - 2^32 * borrow`（注意符号）
- **SUB 负例**：`is_sub=1`，构造 `rs1 - rs2 ≠ rd - 2^32 * borrow`
- **carry_low 二值性正例**：carry_low=0/1，Group F 扩展约束满足
- **carry_low 二值性负例**：carry_low=2，Group F 扩展约束失败 panic

### 9.2 现有测试回归

所有 Phase 2.3.4-a 及之前的测试应继续通过（列数变化但 Group A/B/C/E LUI/AUIPC/SLT/LogShift/F carry 约束形式不变）。

## 10. 完成标准

- [x] 列布局扩展 13→18（column_layout.rs）— 2026-07-20 完成
- [x] CpuAirEval 新增 6 个 ADDI/ADD/SUB 约束 + 1 个 carry_low 二值性约束 — 2026-07-20 完成
- [x] Prover preprocessed tree 5→8 列 — 2026-07-20 完成
- [x] InfoEvaluator 测试约束数 8→15 — 2026-07-20 完成
- [x] 新增 9 个 ADDI/ADD/SUB 专项测试 — 2026-07-20 完成
- [x] cpu 模块 21→30 测试通过 — 2026-07-20 完成
- [x] stwo_backend 模块 78→88 测试通过（设计文档预期 87，实际 88，含 column_layout 新增 1 个测试） — 2026-07-20 完成
- [x] e2e 3/3 通过（含 1M 步 44.91s） — 2026-07-20 完成
- [x] poker_proofs_integration 5/5 通过 — 2026-07-20 完成
- [x] 完整 lib 测试通过（1255/1255） — 2026-07-20 完成

## 11. 实施记录与设计文档修正

### 11.1 SUB high limb 约束符号修正

**设计文档原稿错误**（§5.3）：SUB high limb 约束写为：
```
is_sub * (rs1_high - rs2_high - rd_high + carry_low - 4 * carry) = 0
```
其中 `+ carry_low - 4 * carry` 与 ADD high limb 约束符号方向相同。

**数学推导证明错误**：
SUB 语义 `a - b = result`（borrow 语义：当 a < b 时 borrow=1，result = a - b + 2^32）：
```
a_low + 2^30 * a_high - b_low - 2^30 * b_high = result_low + 2^30 * result_high - 2^32 * borrow
```
拆分为两级：
- Low: `a_low - b_low - result_low + 2^30 * borrow_low = 0`（borrow_low = carry_low）
- High: `a_high - b_high - borrow_low - result_high + 4 * borrow = 0`（**`- borrow_low + 4 * borrow`**）

**修正后约束**：
```
is_sub * (rs1_high - rs2_high - carry_low - rd_high + 4 * carry) = 0
```
符号方向 `(- carry_low + 4 * carry)` 与 ADD 的 `(+ carry_low - 4 * carry)` 相反。

**验证**（SUB with borrow 测试，a=3, b=5, result=0xFFFFFFFE, carry=1, carry_low=1, rd_high=3）：
- Low: `3 - 5 - 0x3FFFFFFE + 2^30 * 1 = -2 - 0x3FFFFFFE + 0x40000000 = -2 + 2 = 0` ✓
- High: `0 - 0 - 1 - 3 + 4 * 1 = 0` ✓（用修正后的符号方向）
- 若用设计文档原稿符号（`+ 1 - 4 * 1`）：`0 - 0 + 1 - 3 - 4 = -6 ≠ 0` ✗

**教训**：设计文档中的符号方向必须通过数学推导验证，不能仅凭 ADD 约束形式类比。SUB 的 borrow 语义（`+2^32 * borrow`）与 ADD 的 carry 语义（`-2^32 * carry`）方向相反，limb decomposition 后 high limb 约束的 carry_low 与 carry 符号也相应相反。

### 11.2 性能基准对比

| 阶段 | 1M 步 prove | 列数（CPU） | 约束数 | preprocessed 列 | 性能变化 |
|------|------------|------------|--------|----------------|---------|
| Phase 2.3.4-a | 38240ms | 13 | 8 | 5 | 基准 |
| Phase 2.3.4-b（设计预测） | ~48000-52000ms | 18 | 15 | 8 | +25-35% |
| Phase 2.3.4-b（实际） | 44910ms | 18 | 15 | 8 | +17.4% |

**实际性能优于设计预测**：设计文档预测 +25-35%（基于列数 +38%、约束数 +88%、preprocessed 列 +60% 的线性叠加），实际仅 +17.4%。原因：FRI 固定开销在大规模下占比 >80%，列数与约束数变化对总耗时影响有限，非线性叠加效应显著。

### 11.3 完成时间

- 设计文档创建：2026-07-20
- 实现完成：2026-07-20
- 全部测试通过：2026-07-20
- 决策门报告更新：2026-07-20
