# Stage 2 Phase 2b — 算术指令约束（修订版）

## 摘要

Phase 2b 在 Phase 2a 的 42-matrix selector-gated CCS 框架上增加算术指令约束（ADD/ADDI/SUB/LUI/AUIPC/SLT/SLTI/SLTU/SLTIU 共 9 条）。

原计划（`stage2_phase2b_arithmetic.md`）指定 9K Group E 行（每步 9 行，每类别 1 行），但实现过程中发现该设计会破坏 Group C 约束：在 Group E 行添加 M_C_j 条目而不添加 M_CONST_C 条目会导致 `Σ sel_j - 0 = 1 ≠ 0`。

本修订版改用 **K Group E 行**（每步 1 行，所有算术约束通过 selector gating 同时检查），并在每行添加 M_CONST_C +1 条目维持 Group C 约束。raw_num_rows 从原计划的 47K-2 降为 39K-2。

## 当前状态分析

### 已完成（本 session 前已落地）

- ✅ `constraints/mod.rs` L94-107：Phase 2b 常量已定义（M_E_RS1..M_E_PC, NUM_CCS_MATRICES=48, ARITH_CATEGORIES, NUM_ARITH）
- ✅ `constraints/mod.rs` L272-323：`compile_step_witness` 已实现 carry/borrow 计算（7 种算术指令）
- ✅ `prover/mod.rs`：全部 5 个测试配置已设 `proof_size_limit: MAX_PROOF_TOTAL_SIZE`
- ✅ Phase 2a 42-matrix 框架（Group A/B/C/D）已实现并通过测试

### 待完成（本计划范围）

1. `compile_batch_to_ccs` 扩展 Group E + F 矩阵条目和 subsets
2. 更新现有测试断言（42→48 矩阵，42→69 subsets）
3. 新增 9 个 Phase 2b 测试
4. 全量验证（build / clippy / test / bench --no-run）

## 修订设计：K Group E 行 + M_CONST_C +1

### 核心思路

每步仅 1 行 Group E 行，所有 9 个算术类别的约束通过 selector gating 同时在该行检查。由于 CCS 公式对所有行求和所有 subset，selector one-hot 保证只有活跃指令的约束项非零。

### Group C 约束兼容性

**问题**：在 Group E 行添加 M_C_j 条目（值 +1）后，Group C subset `{M_C_j}→1` 在该行贡献 `sel_j(i)`，而 `{M_CONST_C}→-1` 贡献 `-M_CONST_C·z[row]`。若 M_CONST_C 无条目，则 `Σ sel_j - 0 = 1 ≠ 0`。

**解决**：在每行 Group E 行为 M_CONST_C 添加 `(row, 0, +1)` 条目（注意：值 +1，与 Group C 行的 -1 不同）。此时：
- `M_CONST_C·z[row] = +1 * z[0] = +1 * 1 = 1`
- Group C 约束：`Σ_j sel_j(i)*1 + (-1)*1 = 1 - 1 = 0` ✓

### 行布局（K 步）

| 组 | 行范围 | 行数 | 约束 |
|----|--------|------|------|
| A | 0..K-2 | K-1 | `idx_{i+1} - idx_i - 1 = 0` |
| B | K-1..2K-3 | K-1 | `next_pc_i - pc_{i+1} = 0` |
| C | 2K-2..3K-3 | K | `Σ_j sel_j(i) - 1 = 0` |
| D | 3K-2..37K-3 | 34K | `sel_j(i)² - sel_j(i) = 0` |
| **E** | **37K-2..38K-3** | **K** | **算术语义 + carry² - carry = 0** |
| **F** | **38K-2..39K-3** | **K** | **carry(i)² - carry(i) = 0** |

总行数 = 39K - 2

### Padding 验证（padded_num_rows 不变）

| K | raw_num_rows (37K-2) | raw_num_rows (39K-2) | padded |
|---|----------------------|----------------------|--------|
| 1 | 35 | 37 | 64 |
| 3 | 109 | 115 | 128 |
| 5 | 183 | 193 | 256 |
| 256 | 9470 | 9982 | 16384 |
| 1024 | 37886 | 39934 | 65536 |

所有 K 值的 padded_num_rows 与 Phase 2a 相同，不影响 max_n_vars 验证。

### Group E 矩阵条目（每步 i，行 = 37K-2 + i）

```
对 ALL 34 j (0..33):
  M_C_BASE+j.add_entry(row, 1 + i*46 + 12 + j, +1)   // selector entry

M_CONST_C.add_entry(row, 0, +1)                        // 常量 +1（非 -1！）

M_E_RS1.add_entry(row, 1 + i*46 + 3, +1)               // rs1_val
M_E_RS2.add_entry(row, 1 + i*46 + 4, +1)               // rs2_val
M_E_RD.add_entry(row, 1 + i*46 + 5, +1)                // rd_val
M_E_IMM.add_entry(row, 1 + i*46 + 6, +1)               // imm
M_E_CARRY.add_entry(row, 1 + i*46 + 7, +1)             // carry
M_E_PC.add_entry(row, 1 + i*46 + 1, +1)                // pc
```

### Group F 矩阵条目（每步 i，行 = 38K-2 + i）

```
M_E_CARRY.add_entry(row, 1 + i*46 + 7, +1)             // carry
```

### 新增 subsets（27 个）

**Group E（25 个 degree-2 subsets）**：

| 指令 | cat | subsets | coefficients |
|------|-----|---------|-------------|
| LUI | 0 | {M_C_0, M_E_RD}, {M_C_0, M_E_IMM} | 1, -1 |
| AUIPC | 1 | {M_C_1, M_E_RD}, {M_C_1, M_E_PC}, {M_C_1, M_E_IMM} | 1, -1, -1 |
| ADDI | 12 | {M_C_12, M_E_RS1}, {M_C_12, M_E_IMM}, {M_C_12, M_E_RD}, {M_C_12, M_E_CARRY} | 1, 1, -1, -2^32 |
| SLTI | 13 | {M_C_13, M_E_RD}, {M_C_13, M_E_CARRY} | 1, -1 |
| SLTIU | 14 | {M_C_14, M_E_RD}, {M_C_14, M_E_CARRY} | 1, -1 |
| ADD | 21 | {M_C_21, M_E_RS1}, {M_C_21, M_E_RS2}, {M_C_21, M_E_RD}, {M_C_21, M_E_CARRY} | 1, 1, -1, -2^32 |
| SUB | 22 | {M_C_22, M_E_RD}, {M_C_22, M_E_RS1}, {M_C_22, M_E_RS2}, {M_C_22, M_E_CARRY} | 1, -1, 1, -2^32 |
| SLT | 24 | {M_C_24, M_E_RD}, {M_C_24, M_E_CARRY} | 1, -1 |
| SLTU | 25 | {M_C_25, M_E_RD}, {M_C_25, M_E_CARRY} | 1, -1 |

**Group F（2 个 subsets）**：
- `{M_E_CARRY, M_E_CARRY}` → coeff 1（carry²）
- `{M_E_CARRY}` → coeff -1（-carry）

总 subsets：42 + 25 + 2 = **69**

### 约束正确性验证

**Group E 行（步 i）**，CCS 公式对所有 subset 求和：

| 组 | 贡献 | 值 |
|----|------|----|
| A | 0（M_A_* 无 Group E 行条目） | 0 |
| B | 0（M_B_* 无 Group E 行条目） | 0 |
| C | `Σ_j sel_j(i)*1 + (-1)*(+1*z[0])` | `1 - 1 = 0` |
| D | 0（M_D_* 无 Group E 行条目） | 0 |
| E | `Σ_cat sel_cat(i) * operand_cat(i)` | `operand_active(i)` |
| F | `carry²(i) - carry(i)`（M_E_CARRY 有 Group E 行条目） | `carry² - carry` |

**总和** = `operand_active(i) + carry²(i) - carry(i) = 0`

- 正确 witness：`operand_active = 0`，`carry ∈ {0,1}` → `0 + 0 = 0` ✓
- 错误 operand：`operand_active ≠ 0`，`carry ∈ {0,1}` → `≠ 0` → 检测 ✓
- carry ∉ {0,1}：Group F 行独立检测 `carry² - carry ≠ 0` ✓

**Group F 行（步 i）**：

| 组 | 贡献 | 值 |
|----|------|----|
| A-D | 0（无 Group F 行条目） | 0 |
| E | 0（M_C_j 无 Group F 行条目 → 所有 {M_C_cat, M_E_*} 积 = 0） | 0 |
| F | `carry²(i) - carry(i)` | `carry² - carry` |

**总和** = `carry²(i) - carry(i) = 0` — 独立强制 carry ∈ {0,1} ✓

**安全性**：Group F 行独立约束 carry 二值性。恶意 prover 无法通过设 carry ∉ {0,1} 来补偿错误 operand，因为 Group F 行会检测到 carry 违规。

### Soundness 分析

| 指令 | 约束 | Soundness |
|------|------|-----------|
| LUI | rd = imm | ✅ 完全 sound |
| AUIPC | rd = pc + imm | ✅ 完全 sound |
| ADD | rs1 + rs2 = rd + carry*2^32, carry∈{0,1} | ✅ 完全 sound |
| ADDI | rs1 + imm = rd + carry*2^32, carry∈{0,1} | ✅ 完全 sound |
| SUB | rd = rs1 - rs2 + carry*2^32, carry∈{0,1} | ✅ 完全 sound |
| SLT | rd = carry, carry∈{0,1} | ⚠️ 部分 sound（carry 正确性依赖 witness，Phase 2e LogUp 补全） |
| SLTU | rd = carry, carry∈{0,1} | ⚠️ 部分 sound |
| SLTI | rd = carry, carry∈{0,1} | ⚠️ 部分 sound |
| SLTIU | rd = carry, carry∈{0,1} | ⚠️ 部分 sound |

## 改动清单

### 改动 1：扩展 `compile_batch_to_ccs` 添加 Group E + F

**文件**：`poker_zkvm/src/constraints/mod.rs` L408-547

1. 更新 doc comment：42→48 矩阵，添加 Group E/F 行描述
2. 更新 `raw_num_rows`：`37 * k - 2` → `39 * k - 2`
3. 添加 Group E 矩阵条目（K 行，37K-2..38K-3）：
   - 对每步 i：34 个 M_C_j 条目（+1）+ M_CONST_C 条目（+1）+ 6 个 M_E_* 条目（+1）
4. 添加 Group F 矩阵条目（K 行，38K-2..39K-3）：
   - 对每步 i：1 个 M_E_CARRY 条目（+1）
5. 添加 25 个 Group E subsets + 2 个 Group F subsets（含 `neg_two_pow_32` 系数）
6. 更新 subsets/coeffs Vec 容量：42 → 69

### 改动 2：更新现有测试断言

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块

| 测试 | 行号 | 旧值 | 新值 |
|------|------|------|------|
| `test_compile_trace_single_batch` | L624 | `num_matrices() == 42` | `== 48` |
| `test_compile_trace_single_batch` | L621 | 注释 `37*5-2=183` | `39*5-2=193` |
| `test_42_matrix_ccs_structure` | L1145 | 函数名 + 42/42 断言 | 重命名为 `test_48_matrix_ccs_structure`，48/69 断言 |
| `test_single_step_batch_no_continuity_constraint` | L754 | 注释 `37*1-2=35` | `39*1-2=37` |
| `test_large_batch_default_size` | L828 | 注释 `37*1024-2=37886` | `39*1024-2=39934` |

### 改动 3：新增 9 个 Phase 2b 测试

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块末尾（L1349 之后）

新增辅助函数 `make_step_with_insn`：构造指定指令和寄存器状态的 Step。

1. **`test_group_e_add_constraint`**：K=2 batch，步 0 设 registers[2]=100, [3]=200，步 1 为 ADD {rd:1, rs1:2, rs2:3}，registers[1]=300。验证 is_satisfied()=true。篡改 witness rd_val → false。

2. **`test_group_e_add_overflow_constraint`**：K=2，步 0 设 registers[2]=0xFFFFFFFF, [3]=1，步 1 为 ADD，registers[1]=0（wrapping）。carry=1。验证 true。

3. **`test_group_e_sub_constraint`**：K=2，步 0 设 registers[2]=100, [3]=200，步 1 为 SUB {rd:1, rs1:2, rs2:3}，registers[1]=0xFFFFFF9C。carry=1（borrow）。验证 true。篡改 carry → false。

4. **`test_group_e_lui_constraint`**：K=1，步 0 为 LUI {rd:1, imm:0x12340000}，registers[1]=0x12340000。验证 true。篡改 rd → false。

5. **`test_group_e_auipc_constraint`**：K=1，步 0 为 AUIPC {rd:1, imm:0x1000}，pc=0，registers[1]=0x1000。验证 true。

6. **`test_group_e_addi_constraint`**：K=2，步 0 设 registers[2]=100，步 1 为 ADDI {rd:1, rs1:2, imm:50}，registers[1]=150。carry=0。验证 true。

7. **`test_group_f_carry_binary`**：K=1 ECALL batch。编译后篡改 witness carry=2。验证 is_satisfied()=false（Group F 检测 carry²-carry=4-2=2≠0）。

8. **`test_arith_soundness_wrong_operand`**：K=2 ADD batch（registers[2]=100, [3]=200, [1]=300）。篡改 witness rd_val 为 301。验证 is_satisfied()=false。

9. **`test_48_matrix_ccs_structure`**（重命名）：验证 num_matrices=48, num_constraints=69。检查 subset[42]={5,44}（Group E LUI 第一个 subset），subset[67]={46,46}（Group F carry²）。

## 验证步骤

1. `cargo build` — 编译通过
2. `cargo clippy --all-targets --features test-helpers` — 无 warning（M_E_* 常量不再 dead code）
3. `cargo test --features test-helpers` — 全部测试通过
4. `cargo bench --no-run --features test-helpers` — 基准编译通过
5. 重点验证：
   - `test_48_matrix_ccs_structure` 通过
   - `test_group_e_add/sub/lui/auipc/addi_constraint` 通过
   - `test_group_f_carry_binary` 通过
   - `test_arith_soundness_wrong_operand` 通过
   - 现有 `test_group_a/b/c/d_*` 测试仍通过
   - `test_padding_power_of_two_invariant` 仍通过
   - `generate_test_proof` → `verify_production` 闭环通过（prover/mod.rs 测试）

## 假设与决策

1. **K Group E 行 vs 9K 行**：K 行设计更紧凑（raw_num_rows 39K-2 vs 47K-2），且通过 M_CONST_C +1 维持 Group C 约束。所有算术约束在单行通过 selector gating 同时检查，soundness 等价。
2. **Group E/F 约束耦合**：Group E 行包含 Group F subset 贡献（carry²-carry），但 Group F 行独立强制 carry∈{0,1}，因此耦合不引入漏洞。
3. **SLT 家族部分 soundness**：Phase 2b 仅约束 rd=carry + carry∈{0,1}，比较语义正确性留给 Phase 2e LogUp。已知技术债务。
4. **2^32 作为域元素**：`Fr::from_u64(1u64 << 32)` 在 BN254 标量域中精确表示（p >> 2^32）。
5. **carry 复用**：ADD overflow / SUB borrow / SLT 比较结果共用 witness offset 7（carry），由 selector one-hot 保证互斥。

## Phase 2c-2e 大纲（后续）

- **Phase 2c**：逻辑 + 移位指令约束（XOR/OR/AND/XORI/ORI/ANDI/SLL/SRL/SRA/SLLI/SRLI/SRAI）
- **Phase 2d**：内存 + 分支 + 跳转 + 系统约束（LB/LH/LW/LBU/LHU/SB/SH/SW/BEQ..BGEU/JAL/JALR/ECALL/EBREAK/FENCE）
- **Phase 2e**：LogUp lookup 集成 + SLT 比较语义补全 + range check + 集成测试
