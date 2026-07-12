# Stage 2 实现计划：完整 RV32I 指令语义约束

## 概要

修复 C-1 健全性漏洞：当前 `compile_batch_to_ccs` 仅生成 step_index 连续性约束，恶意 prover 可执行错误指令而 CCS 仍通过。本 Stage 将 37 条 RV32I base 指令的语义约束接入 batch CCS，实现 selector-gated 约束框架。

**关键设计决策**：
- **One-hot selector 方案**：每步 34 个 binary selector（对应 34 个指令语义组），约束 `sel_C × semantic_C = 0`
- **Degree-2 CCS 适配**：分支条件 `taken × (rs1-rs2)` 超 degree-2，引入中间变量 `branch_cond`
- **可信寄存器值（MVP）**：rs1_val/rs2_val/rd_val 由 executor（可信）计算，CCS 验证指令语义但暂不验证寄存器连续性（留待 Phase 2e/Stage 3）
- **分 5 个 Phase 增量实现**，每 Phase 可独立测试

## 当前状态分析

### 现有代码（[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)）

`compile_batch_to_ccs`（L142-209）：
- witness 布局：`z = [1, idx_0, idx_1, ..., idx_{K-1}]`（长度 K+1）
- 约束：K-1 行 step_index 连续性（`idx_{i+1} - idx_i - 1 = 0`）
- 矩阵：3 个（M_plus, M_minus, M_const）
- Power-of-2 padding 已实现（num_vars, num_rows 均填充到 2 的幂）
- **无任何指令语义约束** → C-1 漏洞

### 现有子电路（独立 CCS，未集成）

- [algebra.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs)：AddCircuit, SubCircuit, AndCircuit, OrCircuit, XorCircuit（各自独立 CCS）
- [control_flow.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/control_flow.rs)：JalCircuit, BeqCircuit, LuiCircuit, AuipcCircuit（各自独立 CCS）
- [lookup.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs)：LogUp lookup（u8/u16 range, AND/OR/XOR 真值表），未集成到 batch CCS
- **问题**：Hypernova 折叠要求所有 batch 共享相同 CCS 结构，独立子电路无法直接拼接

### Step 结构（[trace/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/trace/mod.rs)）

```rust
pub struct Step {
    pub step_index: u64,
    pub pc: u32,           // 执行前 PC
    pub instruction: Instruction,
    pub registers: [u32; 32],  // 执行后寄存器快照
    pub mem_access: Vec<MemAccess>,
}
```
- **无执行前寄存器快照** → rs1_val/rs2_val 必须从前一步的 `registers` 数组中提取

### Instruction 枚举（[isa/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs)）

40 个 variant（37 base + ECALL/EBREAK/FENCE），按语义可分 34 组。

---

## 设计：统一 witness 布局 + selector-gated 约束

### Witness 布局（每步 46 变量）

```
z = [1,  // 常数项（offset 0）
     w_0[0..45], w_1[0..45], ..., w_{K-1}[0..45],  // 每步 46 变量
     padding...]

每步 w_i 的 46 个变量：
  offset 0:  idx_i          // step_index
  offset 1:  pc_i           // 执行前 PC
  offset 2:  next_pc_i      // 执行后 PC
  offset 3:  rs1_val_i      // rs1 值（执行前，从 prev step registers 提取）
  offset 4:  rs2_val_i      // rs2 值（执行前）
  offset 5:  rd_val_i       // rd 值（执行后）
  offset 6:  imm_i          // 立即数（符号扩展后的 u32）
  offset 7:  carry_i        // 溢出 carry bit
  offset 8:  taken_i        // 分支 taken flag
  offset 9:  shamt_i        // 移位量（0-31）
  offset 10: branch_cond_i  // 中间变量（degree-3 降阶用）
  offset 11: aux_i          // 辅助变量（比较结果等）
  offset 12..45: sel_0_i .. sel_33_i  // 34 个 one-hot selector
```

**维度计算**（K=256）：
- num_vars = 1 + 256×46 = 11,777 → padded to 16,384
- num_rows = 256×~70 = ~17,920 → padded to 32,768

### 34 个指令语义组

| 组 ID | 指令 | 语义约束要点 |
|-------|------|-------------|
| 0 | LUI | `rd_val = imm` |
| 1 | AUIPC | `rd_val = pc + imm`（含 carry） |
| 2 | JAL | `rd_val = pc + 4`, `next_pc = pc + imm`（含 carry） |
| 3 | JALR | `rd_val = pc + 4`, `next_pc = (rs1 + imm) & !1`（含 carry） |
| 4 | BEQ | `taken × (rs1 - rs2) = 0`, `next_pc = pc + taken×imm + (1-taken)×4` |
| 5 | BNE | `taken × (rs1 - rs2 - 1 + ...) = 0`（taken 蕴含 rs1≠rs2） |
| 6 | BLT | signed comparison |
| 7 | BGE | signed comparison |
| 8 | BLTU | unsigned comparison |
| 9 | BGEU | unsigned comparison |
| 10 | LB/LH/LW/LBU/LHU | `addr = rs1 + imm`（MVP：仅地址约束） |
| 11 | SB/SH/SW | `addr = rs1 + imm`（MVP） |
| 12 | ADDI | `rd_val = rs1_val + imm`（含 carry） |
| 13 | SLTI | `rd_val = (rs1 < imm) signed ? 1 : 0` |
| 14 | SLTIU | `rd_val = (rs1 < imm) unsigned ? 1 : 0` |
| 15 | XORI | `rd_val = rs1 ^ imm`（MVP：域级约束，LogUp deferred） |
| 16 | ORI | `rd_val = rs1 | imm`（MVP） |
| 17 | ANDI | `rd_val = rs1 & imm`（MVP） |
| 18 | SLLI | `rd_val = rs1 << shamt`（MVP：stub） |
| 19 | SRLI | `rd_val = rs1 >> shamt`（logical, MVP：stub） |
| 20 | SRAI | `rd_val = rs1 >> shamt`（arithmetic, MVP：stub） |
| 21 | ADD | `rd_val = rs1_val + rs2_val`（含 carry） |
| 22 | SUB | `rd_val = rs1_val - rs2_val`（含 borrow） |
| 23 | SLL | `rd_val = rs1 << (rs2 & 0x1F)`（MVP：stub） |
| 24 | SLT | signed comparison |
| 25 | SLTU | unsigned comparison |
| 26 | XOR | `rd_val = rs1 ^ rs2`（MVP） |
| 27 | SRL | logical shift（MVP：stub） |
| 28 | SRA | arithmetic shift（MVP：stub） |
| 29 | OR | `rd_val = rs1 | rs2`（MVP） |
| 30 | AND | `rd_val = rs1 & rs2`（MVP） |
| 31 | FENCE | NOP（无约束） |
| 32 | ECALL | MVP：无约束 |
| 33 | EBREAK | MVP：无约束 |

### Selector 有效性约束（每步）

1. **One-hot**：`Σ_{C=0}^{33} sel_C - 1 = 0`（1 行，线性）
2. **Binary**：`sel_C² - sel_C = 0` for each C（34 行，degree-2）

### 连续性约束（每步，与下一步关联）

1. **step_index 连续性**：`idx_{i+1} - idx_i - 1 = 0`（1 行，线性）
2. **PC 连续性**：`pc_{i+1} - next_pc_i = 0`（1 行，线性）

### 语义约束模板（每步，per category C）

**通用模式**：`sel_C × semantic_C = 0`（degree-2）

- 当 `sel_C = 1`（当前指令属于组 C）：`semantic_C = 0` 必须成立
- 当 `sel_C = 0`（其他指令）：`0 × semantic_C = 0` 平凡满足

**Degree-3 降阶**：分支指令 `taken × (rs1 - rs2) = 0` 是 degree-3（`sel × taken × (rs1-rs2)`）。
解决方案：引入中间变量 `branch_cond = taken × (rs1 - rs2)`（degree-2）+ `sel × branch_cond = 0`（degree-2）。

---

## 实现步骤（5 个 Phase）

### Phase 2a：Witness 布局 + 框架 + 连续性 + Selector 有效性

**文件**：[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)

**改动**：
1. 新增常量 `STEP_VARS: usize = 46`、`NUM_CATEGORIES: usize = 34`
2. 新增 `struct StepWitness`：封装每步 46 个变量的赋值逻辑
3. 新增 `fn compute_rs1_rs2_val(prev_step: &Step, cur_step: &Step) -> (u32, u32)`：从前一步 registers 提取 rs1/rs2 值
4. 新增 `fn assign_selectors(instruction: &Instruction) -> [Fr; 34]`：根据指令类型返回 one-hot selector 数组
5. 重构 `compile_batch_to_ccs`：
   - witness 布局改为 `[1, w_0, w_1, ..., w_{K-1}, padding]`
   - 约束矩阵扩展：连续性 + selector 有效性（无语义约束）
   - 新增 `compile_step_witness(step, prev_step) -> Vec<Fr>`：返回 46 个变量
   - 新增 `build_step_framework_matrices(k, padded_num_vars, padded_num_rows) -> Vec<SparseMatrix>`：构建连续性 + selector 矩阵
6. **保留**现有 `verify_batch_continuity` 函数（public_inputs 格式不变）

**测试**：
- `test_step_witness_layout`：验证 witness 布局正确
- `test_selector_one_hot`：验证每步恰好一个 selector = 1
- `test_selector_binary`：验证所有 selector ∈ {0, 1}
- `test_pc_continuity`：验证 `pc_{i+1} = next_pc_i`
- `test_step_index_continuity`：验证 `idx_{i+1} = idx_i + 1`
- `test_padding_power_of_two`：验证 padding 后 num_vars/num_rows 为 2 的幂
- **保留**所有现有测试（更新 witness 布局断言）

### Phase 2b：算术指令约束（ADD/ADDI/SUB/SLT/SLTI/SLTU/SLTIU/LUI/AUIPC）

**文件**：[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)（新增 `fn build_arithmetic_matrices` + `fn assign_arithmetic_witness`）

**约束实现**：

| 指令 | 约束行 | 语义 |
|------|--------|------|
| LUI (sel_0) | 1 行 | `sel_0 × (rd_val - imm) = 0` |
| AUIPC (sel_1) | 2 行 | `sel_1 × (rd_val - pc - imm - 2^32*carry) = 0` + `carry² - carry = 0` |
| ADDI (sel_12) | 2 行 | `sel_12 × (rs1_val + imm - rd_val - 2^32*carry) = 0` + `carry² - carry = 0` |
| ADD (sel_21) | 2 行 | `sel_21 × (rs1_val + rs2_val - rd_val - 2^32*carry) = 0` + `carry² - carry = 0` |
| SUB (sel_22) | 2 行 | `sel_22 × (rs1_val - rs2_val - rd_val + 2^32*carry) = 0` + `carry² - carry = 0` |
| SLTI (sel_13) | 3 行 | 比较约束（borrow-based） |
| SLTIU (sel_14) | 3 行 | unsigned 比较 |
| SLT (sel_24) | 3 行 | signed 比较 |
| SLTU (sel_25) | 3 行 | unsigned 比较 |

**比较指令约束**（SLT/SLTI/SLTU/SLTIU）：
- `aux = rs1 - operand`（含 borrow）
- `rd_val = aux_sign ? 1 : 0`（signed）或 `rd_val = borrow ? 1 : 0`（unsigned）
- `rd_val² - rd_val = 0`（binary check）

**测试**（每条指令 2 个）：
- 正例：正确执行 → CCS satisfied
- 负例：篡改 rd_val → CCS not satisfied
- 溢出测试：ADD 0xFFFFFFFF + 1 → carry=1

### Phase 2c：逻辑 + 移位指令约束

**文件**：[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)（新增 `fn build_logical_shift_matrices`）

**MVP 策略**：
- **逻辑指令**（XOR/XORI/OR/ORI/AND/ANDI）：域级约束 `sel × (rd_val - rs1 OP operand) = 0`，其中 OP 在域上计算。完整 soundness 需 LogUp 真值表（Phase 2e），但域级约束已能检测多数篡改。
- **移位指令**（SLL/SLLI/SRL/SRLI/SRA/SRAI）：MVP stub（`sel × (rd_val - computed_shift) = 0`，computed_shift 由 executor 计算）。完整实现需 bit decomposition + LogUp range check（Stage 3）。

**约束行**：
- XORI/ORI/ANDI：各 1 行 `sel × (rd_val - rs1 OP imm) = 0`
- XOR/OR/AND：各 1 行 `sel × (rd_val - rs1 OP rs2) = 0`
- SLLI/SRLI/SRAI：各 1 行 `sel × (rd_val - shift(rs1, shamt)) = 0`
- SLL/SRL/SRA：各 1 行 `sel × (rd_val - shift(rs1, rs2 & 0x1F)) = 0`

**测试**：
- 正例/负例 per 指令
- 边界：XOR 0xFFFFFFFF, AND 0x0, SLLI shamt=31

### Phase 2d：内存 + 分支 + 跳转 + 系统指令约束

**文件**：[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)（新增 `fn build_memory_branch_jump_matrices`）

**分支约束**（BEQ/BNE/BLT/BGE/BLTU/BGEU）：

```
// Degree-3 降阶：引入 branch_cond 中间变量
Row 0: sel_C × (branch_cond - taken × (rs1_val - rs2_val)) = 0  // degree-2: sel × branch_cond - sel × taken × (rs1-rs2)

// 实际拆为两行：
Row 0a: branch_cond - taken × (rs1_val - rs2_val) = 0   // degree-2, gated by sel_C via M_branch_cond
Row 0b: sel_C × branch_cond = 0                          // degree-2

// 更精确的实现：
// 引入 aux = (rs1_val - rs2_val) 作为线性组合
// branch_cond = taken × aux  (degree-2)
// sel × branch_cond = 0  (degree-2)

Row 1: taken² - taken = 0                    // binary check
Row 2: next_pc - pc - taken×imm - (1-taken)×4 - 2^32*carry = 0  // degree-2 (taken×imm is degree-2)
Row 3: carry² - carry = 0                    // binary check
```

**不同分支类型的条件**：
- BEQ: `taken = 1` 蕴含 `rs1 == rs2`，即 `taken × (rs1 - rs2) = 0`
- BNE: `taken = 1` 蕴含 `rs1 != rs2`，即 `taken × (rs1 - rs2) ≠ 0` → 需要不同约束
  - BNE 约束：`taken × (1 - (rs1-rs2)^(rs1-rs2))` ... 复杂
  - **MVP 方案**：BNE/BLT/BGE/BLTU/BGEU 使用 `aux` 变量由 executor 计算，CCS 约束 `sel × (taken - aux) = 0`（aux = 比较结果）

**跳转约束**（JAL/JALR）：
- JAL: `sel_2 × (rd_val - pc - 4 - 2^32*carry) = 0` + `sel_2 × (next_pc - pc - imm - 2^32*carry2) = 0` + carry bits
- JALR: `sel_3 × (rd_val - pc - 4 - 2^32*carry) = 0` + `sel_3 × (next_pc - (rs1+imm) - 2^32*carry2) = 0` + carry bits
  - JALR 的 `& !1`：MVP 中由 executor 处理，CCS 约束 next_pc = rs1+imm（模 2^32），`& !1` 差异留待 Stage 3

**内存约束**（LB/LH/LW/LBU/LHU/SB/SH/SW）：
- MVP：`sel_C × (addr - rs1_val - imm - 2^32*carry) = 0`（地址计算约束）
- 完整内存一致性：LogUp lookup（Phase 2e）

**系统指令**（FENCE/ECALL/EBREAK）：
- FENCE: 无约束（NOP）
- ECALL/EBREAK: MVP 无约束，Stage 3 补 syscall 分派

**测试**：
- 分支：taken/not-taken 正负例
- JAL/JALR：跳转目标正确/错误
- 内存：地址计算正确/错误
- 边界：BNE 不等时 taken=1，BEQ 不等时 taken=0

### Phase 2e：集成测试 + LogUp 集成 + Soundness 验证

**文件**：
- 新增 [tests/instruction_semantics_tests.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/instruction_semantics_tests.rs)
- 扩展 [tests/soundness_tests.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/soundness_tests.rs)（如存在）
- [src/constraints/lookup.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/lookup.rs)（集成到 batch CCS）

**LogUp 集成**（可选，可推迟到 Stage 3）：
- u5 range table（0-31）：移位量 range check
- 内存访问表：(addr, step, value) 三元组
- 逻辑运算真值表：AND/OR/XOR

**测试矩阵**：

| 测试类型 | 数量 | 内容 |
|---------|------|------|
| 单指令正例 | 40 | 每条指令正确执行 → CCS satisfied |
| 单指令负例 | 40 | 篡改 rd_val/pc → CCS not satisfied |
| 溢出测试 | 5 | ADD/SUB 边界（0xFFFFFFFF+1 等） |
| 分支测试 | 12 | 6 条分支 × taken/not-taken |
| 多步 trace | 3 | fibonacci/sha256_chain/poker_hand_eval |
| Soundness | 5 | 篡改任意 step → verify 拒绝 |
| E2E | 3 | 现有 e2e_fibonacci 等通过 |

---

## 假设与决策

### 关键设计决策

1. **One-hot selector（34 个）vs category ID（1 个 + range check）**：
   - 选择 one-hot：约束更简单（degree-2），witness 更大（46 vars/step vs ~20 vars/step）
   - 未选方案：category ID + Lagrange 插值（degree-33，超 CCS degree-2 限制，需大量中间变量）
   - 理由：CCS degree-2 限制下，one-hot 是最直接的方案

2. **可信寄存器值（MVP）vs 完整寄存器连续性**：
   - 选择 MVP：rs1_val/rs2_val/rd_val 由 executor 计算，CCS 验证指令语义
   - 未选方案：完整寄存器连续性（需 32 个 write flag + multiplexer 约束，~132 vars/step）
   - 理由：MVP 已能修复 C-1 的主要漏洞（防止执行错误指令），寄存器连续性留待 Stage 3
   - **限制**：恶意 prover 仍可伪造 rs1_val/rs2_val 使语义约束通过，但需同时伪造一致的 rd_val。完整修复需寄存器连续性。

3. **逻辑指令域级约束 vs LogUp 真值表**：
   - 选择域级约束（MVP）：`rd_val = rs1 OP operand` 在域上验证
   - 未选方案：LogUp 真值表（per-bit lookup，完整 soundness）
   - 理由：域级约束已能检测多数篡改，LogUp 集成可推迟到 Phase 2e/Stage 3

4. **移位指令 stub vs bit decomposition**：
   - 选择 stub（MVP）：`rd_val = shift(rs1, shamt)` 由 executor 计算，CCS 约束结果
   - 未选方案：bit decomposition + LogUp range check
   - 理由：bit decomposition 需 32 个中间变量/步，复杂度高，留待 Stage 3

### 向后兼容性

- `compile_trace_to_ccs` 签名不变（`trace: &Trace, batch_size: usize`）
- `verify_batch_continuity` 签名不变
- public_inputs 格式不变：`[batch_id, first_idx, last_idx]`
- 现有测试需更新 witness 布局断言（num_vars 从 K+1 变为 1+K×46 padded）

### CCS 结构一致性（Hypernova 折叠要求）

- 所有 batch 共享相同 CCS 结构（matrices, subsets, coefficients）
- 只有 witness 不同
- num_vars 和 num_rows 经 power-of-2 padding 后固定（K=256 → num_vars=16384, num_rows=32768）
- 部分 batch 步数 < K 时，padding 步的 selector 全为 0，约束平凡满足

---

## 验证步骤

### Phase 2a 完成后
```bash
cargo test -p poker_zkvm --lib constraints::mod::tests
# 验证：witness 布局、selector 有效性、连续性、padding
```

### Phase 2b-2d 完成后
```bash
cargo test -p poker_zkvm --lib constraints::mod::tests
# 验证：每条指令的语义约束正负例
```

### Phase 2e 完成后
```bash
cargo test -p poker_zkvm --features test-helpers --test instruction_semantics_tests
cargo test -p poker_zkvm --features test-helpers --test soundness_tests
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci
cargo test -p poker_zkvm  # 全量回归（777+ 测试）
cargo clippy -p poker_zkvm --all-targets -- -D warnings
cargo bench -p poker_zkvm --no-run  # 基准测试编译
```

### 通过标准
- 37 条 RV32I 指令均有正负测试
- 篡改任意 step 的 register/pc → CCS not satisfied
- 所有现有 E2E 测试通过
- cargo clippy 无 warning
- 基准测试编译成功
