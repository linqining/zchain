# Stage 2 续接计划 — Phase 2a 完成收尾 + Phase 2b 算术指令约束

## 摘要

Stage 2 修复 C-1 Soundness 漏洞：旧 `compile_batch_to_ccs` 仅生成 step_index 连续性约束，恶意 prover 可执行错误指令而 CCS 仍通过。Phase 2a 已建立 42-matrix selector-gated 框架。本计划完成 Phase 2a 测试收尾，并实现 Phase 2b 算术指令约束（ADD/ADDI/SUB/LUI/AUIPC/SLT/SLTI/SLTU/SLTIU 共 9 条）。

## 当前状态分析

### Phase 2a 已完成

- ✅ `constraints/mod.rs`：42-matrix CCS 结构（Group A/B/C/D），`compile_batch_to_ccs` 已重写
- ✅ Group D 行号 bug 已修复：`3 * k - 2 + i * NUM_CATEGORIES + j`
- ✅ `prover/mod.rs`：`pad_trace` PC 连续性 bug 已修复（pc=prev_pc+4）
- ✅ `generate_test_proof` / `generate_single_instance_test_proof`：已设 `proof_size_limit: MAX_PROOF_TOTAL_SIZE`（512KB）
- ✅ `e2e_fibonacci.rs` / `phase12_benchmarks.rs`：已使用 `MAX_PROOF_TOTAL_SIZE`
- ✅ 5 个现有测试已更新断言，7 个 Phase 2a 新测试已添加

### Phase 2a 待修复（3 个 prover 测试）

`prover/mod.rs` 中 3 个测试仍使用 `ProverConfig { batch_size: 3, ..Default::default() }`（默认 64KB proof_size_limit）：

| 行号 | 测试函数 | 需要修复 | 原因 |
|------|---------|---------|------|
| L1337 | `test_prove_invalid_elf_errors` | 否 | ELF 解析失败在 proof 生成前返回 |
| L1351 | `test_prove_empty_input_success` | **是** | 生成 proof >64KB，触发限制错误 |
| L1383 | `test_prove_returns_public_io_with_input` | **是** | 同上 |

### 现有 algebra.rs 子电路

`constraints/algebra.rs` 已有独立 CCS 子电路（AddCircuit/SubCircuit/AndCircuit/OrCircuit/XorCircuit），使用独立 witness `[1, a, b, result, flag]`。这些是 Phase 5 的独立测试电路，**不集成到统一 42-matrix CCS**。Phase 2b 需要在统一 CCS 中实现 selector-gated 算术约束。

## Phase 2b 设计方案

### 新增矩阵（6 个，索引 42..47）

| 矩阵 | 索引 | 用途 | 提取的 witness 列 |
|------|------|------|-------------------|
| M_E_RS1 | 42 | rs1_val | `1 + i*46 + 3` |
| M_E_RS2 | 43 | rs2_val | `1 + i*46 + 4` |
| M_E_RD | 44 | rd_val | `1 + i*46 + 5` |
| M_E_IMM | 45 | imm | `1 + i*46 + 6` |
| M_E_CARRY | 46 | carry/borrow | `1 + i*46 + 7` |
| M_E_PC | 47 | pc（AUIPC 用） | `1 + i*46 + 1` |

总矩阵数：42 + 6 = **48**

### Group E — 算术指令语义约束（行 37K-2 .. 46K-3，共 9K 行）

每步 9 行，对应 9 个算术指令类别。行布局：

```
E_base = 37K - 2
每步 i (0..K-1):
  Row E_base + i*9 + 0: LUI      → sel_lui * (rd - imm) = 0
  Row E_base + i*9 + 1: AUIPC    → sel_auipc * (rd - pc - imm) = 0
  Row E_base + i*9 + 2: ADDI     → sel_addi * (rs1 + imm - rd - 2^32*carry) = 0
  Row E_base + i*9 + 3: SLTI     → sel_slti * (rd - carry) = 0
  Row E_base + i*9 + 4: SLTIU    → sel_sltiu * (rd - carry) = 0
  Row E_base + i*9 + 5: ADD      → sel_add * (rs1 + rs2 - rd - 2^32*carry) = 0
  Row E_base + i*9 + 6: SUB      → sel_sub * (rd - rs1 + rs2 - 2^32*carry) = 0
  Row E_base + i*9 + 7: SLT      → sel_slt * (rd - carry) = 0
  Row E_base + i*9 + 8: SLTU     → sel_sltu * (rd - carry) = 0
```

算术类别索引映射（`instruction_category` 返回值 → Group E 行内偏移）：

```
ARITH_CATEGORIES = [0(LUI), 1(AUIPC), 12(ADDI), 13(SLTI), 14(SLTIU), 21(ADD), 22(SUB), 24(SLT), 25(SLTU)]
NUM_ARITH = 9
```

### Group F — carry/borrow 二值性（行 46K-2 .. 47K-3，共 K 行）

每步 1 行：`carry(i)² - carry(i) = 0`

利用 subset `{M_E_CARRY, M_E_CARRY}` 实现 carry²（同 Group D 的 `{40,40}` 模式）。

### 维度计算

- `raw_num_vars = 1 + K * 46`（不变）
- `raw_num_rows = 37K - 2 + 9K + K = 47K - 2`
- `padded_num_vars = raw_num_vars.next_power_of_two().max(2)`
- `padded_num_rows = raw_num_rows.max(1).next_power_of_two()`

**max_n_vars=20 验证**：
- K=256：num_vars=11777→16384=2^14，pcs_n_vars=14 ≤ 20 ✓
- K=3：num_vars=139→256=2^8，pcs_n_vars=8 ≤ 20 ✓
- K=1024：num_vars=47105→65536=2^16，pcs_n_vars=16 ≤ 20 ✓

### 新增 subsets（27 个）

Group E（25 个 degree-2 subsets）：

| 指令 | subsets | coefficients |
|------|---------|-------------|
| LUI | {M_C_0, M_E_RD}, {M_C_0, M_E_IMM} | 1, -1 |
| AUIPC | {M_C_1, M_E_RD}, {M_C_1, M_E_PC}, {M_C_1, M_E_IMM} | 1, -1, -1 |
| ADDI | {M_C_12, M_E_RS1}, {M_C_12, M_E_IMM}, {M_C_12, M_E_RD}, {M_C_12, M_E_CARRY} | 1, 1, -1, -2^32 |
| SLTI | {M_C_13, M_E_RD}, {M_C_13, M_E_CARRY} | 1, -1 |
| SLTIU | {M_C_14, M_E_RD}, {M_C_14, M_E_CARRY} | 1, -1 |
| ADD | {M_C_21, M_E_RS1}, {M_C_21, M_E_RS2}, {M_C_21, M_E_RD}, {M_C_21, M_E_CARRY} | 1, 1, -1, -2^32 |
| SUB | {M_C_22, M_E_RD}, {M_C_22, M_E_RS1}, {M_C_22, M_E_RS2}, {M_C_22, M_E_CARRY} | 1, -1, 1, -2^32 |
| SLT | {M_C_24, M_E_RD}, {M_C_24, M_E_CARRY} | 1, -1 |
| SLTU | {M_C_25, M_E_RD}, {M_C_25, M_E_CARRY} | 1, -1 |

Group F（2 个 subsets）：
- `{M_E_CARRY, M_E_CARRY}` → coeff 1
- `{M_E_CARRY}` → coeff -1

总 subsets：42 + 25 + 2 = **69**

### 矩阵条目规则

**Group E 行**（每步 i，每个算术类别 p）：

对于 `ARITH_CATEGORIES[p]` 对应的指令，在行 `E_base + i*9 + p`：
1. 选择器矩阵 `M_C_BASE + ARITH_CATEGORIES[p]`：添加 `(row, 1+i*46+12+ARITH_CATEGORIES[p], +1)`
2. 操作数矩阵（根据指令需要的操作数）：
   - 需要 rs1：`M_E_RS1` 添加 `(row, 1+i*46+3, +1)`
   - 需要 rs2：`M_E_RS2` 添加 `(row, 1+i*46+4, +1)`
   - 需要 rd：`M_E_RD` 添加 `(row, 1+i*46+5, +1)`
   - 需要 imm：`M_E_IMM` 添加 `(row, 1+i*46+6, +1)`
   - 需要 carry：`M_E_CARRY` 添加 `(row, 1+i*46+7, +1)`
   - 需要 pc：`M_E_PC` 添加 `(row, 1+i*46+1, +1)`

**Group F 行**（每步 i）：
- `M_E_CARRY` 添加 `(F_base + i, 1+i*46+7, +1)`

### `compile_step_witness` 更新

当前 carry 恒为 0。Phase 2b 根据 instruction 计算 carry/borrow：

```rust
let carry = match &step.instruction {
    Instruction::Add { rs1, rs2, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        let rs2_val = prev_step.map_or(0, |p| p.registers[*rs2 as usize]);
        if (rs1_val as u64) + (rs2_val as u64) >= (1u64 << 32) { 1 } else { 0 }
    }
    Instruction::Addi { rs1, imm, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        if (rs1_val as u64) + (imm as u64) >= (1u64 << 32) { 1 } else { 0 }
    }
    Instruction::Sub { rs1, rs2, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        let rs2_val = prev_step.map_or(0, |p| p.registers[*rs2 as usize]);
        if rs1_val < rs2_val { 1 } else { 0 }
    }
    Instruction::Slt { rs1, rs2, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        let rs2_val = prev_step.map_or(0, |p| p.registers[*rs2 as usize]);
        if (rs1_val as i32) < (rs2_val as i32) { 1 } else { 0 }
    }
    Instruction::Sltu { rs1, rs2, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        let rs2_val = prev_step.map_or(0, |p| p.registers[*rs2 as usize]);
        if rs1_val < rs2_val { 1 } else { 0 }
    }
    Instruction::Slti { rs1, imm, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        if (rs1_val as i32) < (*imm as i32) { 1 } else { 0 }
    }
    Instruction::Sltiu { rs1, imm, .. } => {
        let rs1_val = prev_step.map_or(0, |p| p.registers[*rs1 as usize]);
        if rs1_val < *imm { 1 } else { 0 }
    }
    _ => 0,
};
```

### Soundness 分析

| 指令 | 约束 | Soundness | 说明 |
|------|------|-----------|------|
| LUI | rd = imm | ✅ 完全 sound | 域元素直接相等 |
| AUIPC | rd = pc + imm | ✅ 完全 sound | pc < 2^32, imm < 2^32, 和 < 2^33 < p |
| ADD | rs1 + rs2 = rd + carry*2^32, carry∈{0,1} | ✅ 完全 sound | rs1+rs2 < 2^33 < p，carry 唯一确定 |
| ADDI | rs1 + imm = rd + carry*2^32, carry∈{0,1} | ✅ 完全 sound | 同 ADD |
| SUB | rd = rs1 - rs2 + carry*2^32, carry∈{0,1} | ✅ 完全 sound | carry=borrow 唯一确定 |
| SLT | rd = carry, carry∈{0,1} | ⚠️ 部分 sound | carry 值的正确性依赖 witness，未约束比较语义。Phase 2e LogUp 补全 |
| SLTU | rd = carry, carry∈{0,1} | ⚠️ 部分 sound | 同 SLT |
| SLTI | rd = carry, carry∈{0,1} | ⚠️ 部分 sound | 同 SLT |
| SLTIU | rd = carry, carry∈{0,1} | ⚠️ 部分 sound | 同 SLT |

**注意**：SLT/SLTU/SLTI/SLTIU 的 carry 虽然在 witness 中正确计算，但 CCS 未约束 carry = comparison(rs1, rs2)。恶意 prover 可设 carry 为任意二值。此漏洞在 Phase 2e 通过 LogUp range check 补全（约束 aux_diff = rs1 - rs2 + carry*2^32 ∈ [0, 2^32)）。

## 改动清单

### 改动 1：修复 Phase 2a 剩余 prover 测试

**文件**：`poker_zkvm/src/prover/mod.rs` L1364, L1394

将 2 处 `ProverConfig { batch_size: 3, ..Default::default() }` 改为：
```rust
let config = ProverConfig {
    batch_size: 3,
    proof_size_limit: MAX_PROOF_TOTAL_SIZE,
    ..Default::default()
};
```

### 改动 2：新增矩阵索引常量和算术类别映射

**文件**：`poker_zkvm/src/constraints/mod.rs` L83-93 之后

```rust
// Phase 2b — 算术指令约束矩阵（索引 42..47）
const M_E_RS1: usize = 42;
const M_E_RS2: usize = 43;
const M_E_RD: usize = 44;
const M_E_IMM: usize = 45;
const M_E_CARRY: usize = 46;
const M_E_PC: usize = 47;
const NUM_CCS_MATRICES_P2B: usize = 48;

/// 算术指令类别列表（对应 instruction_category 返回值）。
const ARITH_CATEGORIES: [usize; 9] = [0, 1, 12, 13, 14, 21, 22, 24, 25];
const NUM_ARITH: usize = 9;
```

### 改动 3：更新 `compile_step_witness` 计算 carry/borrow

**文件**：`poker_zkvm/src/constraints/mod.rs` L234-275

替换 `witness.push(Fr::zero()); // carry — Phase 2b 填充` 为上述 carry 计算逻辑。

### 改动 4：扩展 `compile_batch_to_ccs` 添加 Group E + F

**文件**：`poker_zkvm/src/constraints/mod.rs` L363-479

1. 更新 `NUM_CCS_MATRICES` → `NUM_CCS_MATRICES_P2B`（48）
2. 更新 `raw_num_rows = 47 * k - 2`
3. 添加 Group E 矩阵条目（9K 行）
4. 添加 Group F 矩阵条目（K 行）
5. 添加 25 个 Group E subsets + 2 个 Group F subsets
6. 更新现有测试中 `num_rows` 断言

### 改动 5：更新现有测试断言

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块

| 测试 | 旧 num_rows | 新 num_rows | 旧 num_matrices | 新 num_matrices |
|------|-------------|-------------|-----------------|-----------------|
| `test_compile_trace_single_batch` (K=5) | 256 | 256 (233→256) | 42 | 48 |
| `test_single_step_batch_no_continuity_constraint` (K=1) | 64 | 64 (45→64) | 42 | 48 |
| `test_large_batch_default_size` (K=1024) | 65536 | 65536 (48126→65536) | 42 | 48 |
| `test_42_matrix_ccs_structure` | 42 matrices, 42 subsets | 48 matrices, 69 subsets | — | — |

### 改动 6：新增 Phase 2b 测试

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块末尾

1. **`test_group_e_add_constraint`**：构造 ADD 步骤，验证 is_satisfied()=true；篡改 rd_val 验证 false
2. **`test_group_e_sub_constraint`**：构造 SUB 步骤（含 borrow），验证 true；篡改 carry 验证 false
3. **`test_group_e_lui_constraint`**：构造 LUI 步骤，验证 rd=imm
4. **`test_group_e_auipc_constraint`**：构造 AUIPC 步骤，验证 rd=pc+imm
5. **`test_group_e_addi_constraint`**：构造 ADDI 步骤（含 carry），验证 true
6. **`test_group_f_carry_binary`**：验证 carry∈{0,1} 约束；设 carry=2 验证 false
7. **`test_arith_soundness_wrong_instruction`**：构造 ADD 步骤但 selector 设为 SUB，验证约束失败
8. **`test_group_e_slt_constraint`**：构造 SLT 步骤，验证 rd=carry（部分 sound）
9. **`test_48_matrix_ccs_structure`**：验证 num_matrices=48, subsets=69, Group E/F 行布局

## 验证步骤

1. `cargo build` — 编译通过
2. `cargo clippy --all-targets --features test-helpers` — 无 warning
3. `cargo test --features test-helpers` — 全部测试通过
4. `cargo bench --no-run --features test-helpers` — 基准编译通过
5. 重点验证：
   - `test_soundness_trace_tampering_detected` 仍通过
   - `generate_test_proof` → `verify_production` 闭环通过
   - `test_prove_empty_input_success` 和 `test_prove_returns_public_io_with_input` 通过

## 假设与决策

1. **SLT 家族部分 soundness**：Phase 2b 仅约束 rd=carry + carry∈{0,1}，比较语义正确性留给 Phase 2e LogUp。这是已知技术债务，不引入新漏洞（旧代码无任何指令约束）。
2. **Group E/F 行增加**：raw_num_rows 从 37K-2 增至 47K-2，padding 后仍在 2 的幂范围内（K=256→16384, K=3→256）。
3. **48 矩阵 + 69 subsets**：Hypernova sumcheck 复杂度 O(num_subsets × num_rows)，69 subsets 在可接受范围内。
4. **carry 复用**：ADD overflow / SUB borrow / SLT 比较结果共用 witness offset 7（carry），由 selector one-hot 保证互斥。
5. **2^32 作为域元素**：`Fr::from_u64(1u64 << 32)` 在 BN254 标量域中精确表示（p >> 2^32）。

## Phase 2c-2e 大纲（后续）

- **Phase 2c**：逻辑 + 移位指令约束（XOR/OR/AND/XORI/ORI/ANDI/SLL/SRL/SRA/SLLI/SRLI/SRAI）— 需 bit decomposition 或 LogUp
- **Phase 2d**：内存 + 分支 + 跳转 + 系统约束（LB/LH/LW/LBU/LHU/SB/SH/SW/BEQ..BGEU/JAL/JALR/ECALL/EBREAK/FENCE）
- **Phase 2e**：LogUp lookup 集成 + SLT 比较语义补全 + range check + 集成测试 + soundness 验证
