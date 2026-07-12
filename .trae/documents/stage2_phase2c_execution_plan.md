# Stage 2 Phase 2c — 执行计划（逻辑 + 移位指令约束）

## 摘要

本计划推进 Stage 2 Phase 2c：在 Phase 2b 的 48-matrix CCS 框架上增加 12 条逻辑/移位指令（XOR/XORI/OR/ORI/AND/ANDI/SLL/SRL/SRA/SLLI/SRLI/SRAI）的结构性约束。

**执行顺序**：

1. **前置**：验证 Phase 2b bug fix（Group C M\_CONST\_C 双负号修复），移除 debug 测试
2. **Phase 2c 实现**：按已批准的 `stage2_phase2c_logical_shift.md` 设计执行 7 项改动
3. **全量验证**：build / clippy / test / bench --no-run

***

## 当前状态分析

### 已完成

* ✅ Phase 2a：42-matrix selector-gated CCS 框架（Group A/B/C/D）

* ✅ Phase 2b：48-matrix CCS，Group E（算术语义）+ Group F（carry 二值性），69 subsets

* ✅ Phase 2b bug fix：Group C M\_CONST\_C 条目值从 `-1` 改为 `+1`（[mod.rs L497](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L497)）

  * **根因**：矩阵条目值和 subset 系数均为 -1，导致 `(-1)×(-1)=+1` 而非预期的 -1

  * **修复**：矩阵条目值改为 +1，符号由 subset 系数 -1 提供

* ✅ Phase 2c 设计计划已批准（`stage2_phase2c_logical_shift.md`）

### 待处理

1. **Phase 2b 验证**：bug fix 已应用但测试未重新运行确认
2. **debug 测试**：`debug_ccs_row_failure`（[mod.rs L1662-1697](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs#L1662-L1697)）需移除
3. **Phase 2c 实现**：7 项改动（详见下文）

### 关键文件

| 文件                                                                                                        | 角色                              |
| --------------------------------------------------------------------------------------------------------- | ------------------------------- |
| [poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) | CCS 编译器主文件，所有改动集中于此             |
| [poker\_zkvm/src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs)                 | CCS 数据结构（`satisfied_by` 逐行校验逻辑） |

***

## 执行步骤

### Step 0：Phase 2b 验证（前置）

**目标**：确认 bug fix 解决所有 21 个测试失败，然后移除 debug 测试。

1. 运行 `cargo test -p poker_zkvm --lib constraints` 验证全部测试通过
2. 若全部通过，移除 `debug_ccs_row_failure` 测试（L1662-1697）
3. 再次运行测试确认移除后无回归

**通过标准**：全部 constraints 模块测试通过（含 Phase 2a/2b 测试），无 debug 测试残留。

### Step 1：新增 M\_E\_AUX 矩阵常量

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) L94-101

**改动**：

```rust
// Phase 2c — 逻辑/移位指令约束矩阵
const M_E_AUX: usize = 48;
const NUM_CCS_MATRICES: usize = 49;  // 原 48
```

移除 `OFF_AUX` 的 `#[allow(dead_code)]`（L79），因为本 Phase 开始使用。

### Step 2：计算 SLL/SRL/SRA 的 shamt

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) `compile_step_witness` 函数（\~L255）

**当前状态**：`extract_insn_fields` 对 SLL/SRL/SRA 返回 `shamt=0`（L203），因为 RISC-V 中寄存器移位的移位量来自 `rs2 & 0x1F`，而非指令编码。

**改动**：在 `rs2_val` 计算之后（L264 之后），添加 shamt 修正：

```rust
let (_, _, _, imm, extracted_shamt) = extract_insn_fields(&step.instruction);
// SLL/SRL/SRA 的移位量 = rs2 & 0x1F（RISC-V 规范）
let shamt = match &step.instruction {
    Instruction::Sll { .. } | Instruction::Srl { .. } | Instruction::Sra { .. } => {
        (rs2_val & 0x1F) as u8
    }
    _ => extracted_shamt,
};
```

### Step 3：计算 aux witness 值

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) `compile_step_witness` 函数（carry 计算之后，\~L325 之后）

**改动**：添加 aux 计算（12 条逻辑/移位指令）：

```rust
let aux: u32 = match &step.instruction {
    Instruction::Xori { .. } => rs1_val ^ imm,
    Instruction::Ori { .. } => rs1_val | imm,
    Instruction::Andi { .. } => rs1_val & imm,
    Instruction::Xor { .. } => rs1_val ^ rs2_val,
    Instruction::Or { .. } => rs1_val | rs2_val,
    Instruction::And { .. } => rs1_val & rs2_val,
    Instruction::Slli { .. } => rs1_val << shamt,
    Instruction::Srli { .. } => rs1_val >> shamt,
    Instruction::Srai { .. } => ((rs1_val as i32) >> shamt) as u32,
    Instruction::Sll { .. } => rs1_val << shamt,
    Instruction::Srl { .. } => rs1_val >> shamt,
    Instruction::Sra { .. } => ((rs1_val as i32) >> shamt) as u32,
    _ => 0,
};
```

修改 witness push（\~L339）：

```rust
witness.push(Fr::from_u32_with_wrap(aux));  // 原: Fr::zero()
```

### Step 4：Group E 行添加 M\_E\_AUX 条目

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) `compile_batch_to_ccs` Group E 循环（\~L528 之后）

**改动**：在现有 6 个 M\_E\_\* 条目后添加：

```rust
matrices[M_E_AUX].add_entry(row, base + OFF_AUX, Fr::one())?;
```

同时更新矩阵初始化：`vec![SparseMatrix::new(padded_num_rows, padded_num_vars); NUM_CCS_MATRICES]`（已使用常量，自动跟随）。

### Step 5：新增 24 个 subsets

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) subsets 段（Group E subsets 之后，Group F 之前，\~L625）

**改动**：添加 12 类 × 2 subset = 24 个 degree-2 subset，模式 `sel_cat × (rd - aux) = 0`：

```rust
// Phase 2c: 逻辑 + 移位指令约束（12 类 × 2 subset = 24）
// XORI(15), ORI(16), ANDI(17), SLLI(18), SRLI(19), SRAI(20),
// SLL(23), XOR(26), SRL(27), SRA(28), OR(29), AND(30)
for &cat in &[15, 16, 17, 18, 19, 20, 23, 26, 27, 28, 29, 30] {
    subsets.push(vec![M_C_BASE + cat, M_E_RD]);
    coeffs.push(Fr::one());
    subsets.push(vec![M_C_BASE + cat, M_E_AUX]);
    coeffs.push(neg_one);
}
```

更新 Vec 容量：`Vec::with_capacity(69)` → `Vec::with_capacity(93)`（subsets 和 coeffs 各一处）。

### Step 6：更新现有测试断言

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) 测试模块

| 测试                                 | 旧值                     | 新值                                          |
| ---------------------------------- | ---------------------- | ------------------------------------------- |
| `test_compile_trace_single_batch`  | `num_matrices() == 48` | `== 49`                                     |
| `test_48_matrix_ccs_structure`     | 函数名 + 48/69 断言         | 重命名 `test_49_matrix_ccs_structure`，49/93 断言 |
| `compile_batch_to_ccs` doc comment | 48 矩阵/69 subset        | 49 矩阵/93 subset                             |
| subsets Vec 容量注释                   | 69                     | 93                                          |

### Step 7：新增 14 个 Phase 2c 测试

**文件**：[poker\_zkvm/src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) 测试模块末尾（debug 测试移除后的位置）

复用 `make_step_with_insn`（L1474）和 `make_ecall_step_with_regs`（L1489）辅助函数。

#### 逻辑指令测试（6 个）

1. **`test_group_e_xor_constraint`**：K=2，步0 设 regs\[2]=0xF0, \[3]=0x0F，步1 XOR {rd:1,rs1:2,rs2:3} regs\[1]=0xFF。验证 true。篡改 rd→0xFE 验证 false。
2. **`test_group_e_or_constraint`**：K=2，步0 设 regs\[2]=0xF0, \[3]=0x0F，步1 OR regs\[1]=0xFF。验证 true。篡改 rd→0xF0 验证 false。
3. **`test_group_e_and_constraint`**：K=2，步0 设 regs\[2]=0xFF, \[3]=0x0F，步1 AND regs\[1]=0x0F。验证 true。篡改 rd→0xFF 验证 false。
4. **`test_group_e_xori_constraint`**：K=2，步0 设 regs\[2]=0xF0，步1 XORI {rd:1,rs1:2,imm:0x0F} regs\[1]=0xFF。验证 true。
5. **`test_group_e_ori_constraint`**：K=2，步0 设 regs\[2]=0xF0，步1 ORI {imm:0x0F} regs\[1]=0xFF。验证 true。
6. **`test_group_e_andi_constraint`**：K=2，步0 设 regs\[2]=0xFF，步1 ANDI {imm:0x0F} regs\[1]=0x0F。验证 true。

#### 移位指令测试（6 个）

1. **`test_group_e_slli_constraint`**：K=2，步0 设 regs\[2]=0x1，步1 SLLI {rd:1,rs1:2,shamt:4} regs\[1]=0x10。验证 true。篡改 rd→0x20 验证 false。
2. **`test_group_e_srli_constraint`**：K=2，步0 设 regs\[2]=0x80000000，步1 SRLI {shamt:1} regs\[1]=0x40000000。验证 true。
3. **`test_group_e_srai_constraint`**：K=2，步0 设 regs\[2]=0x80000000，步1 SRAI {shamt:1} regs\[1]=0xC0000000（算术右移）。验证 true。
4. **`test_group_e_sll_constraint`**：K=2，步0 设 regs\[2]=0x1, \[3]=4，步1 SLL {rd:1,rs1:2,rs2:3} regs\[1]=0x10。验证 true。验证 shamt = 4 & 0x1F = 4。
5. **`test_group_e_srl_constraint`**：K=2，步0 设 regs\[2]=0x80000000, \[3]=1，步1 SRL regs\[1]=0x40000000。验证 true。
6. **`test_group_e_sra_constraint`**：K=2，步0 设 regs\[2]=0x80000000, \[3]=1，步1 SRA regs\[1]=0xC0000000。验证 true。

#### 边界 + Soundness 测试（2 个）

1. **`test_shift_shamt_from_rs2_low_5_bits`**：K=2，步0 设 regs\[2]=0x1, \[3]=35（0b100011），步1 SLL {rd:1,rs1:2,rs2:3} regs\[1]=0x8（1 << (35&0x1F=3) = 8）。验证 true。确认 shamt = 3 而非 35。
2. **`test_logical_shift_soundness_wrong_operand`**：K=2 XOR batch，篡改 rd\_val → 验证 false。

### Step 8：全量验证

```bash
cargo build -p poker_zkvm
cargo clippy --all-targets --features test-helpers
cargo test --features test-helpers
cargo bench --no-run --features test-helpers
```

**通过标准**：

* 编译通过，clippy 无 warning（M\_E\_AUX、OFF\_AUX 不再 dead code）

* 全部测试通过（含 14 个新测试 + 全部 Phase 2a/2b 回归 + E2E）

* 基准测试编译通过

***

## 约束正确性验证

### Group E 行（步 i）新 subset 贡献

新增 subset `{M_C_cat, M_E_RD}→+1` 和 `{M_C_cat, M_E_AUX}→-1` 在各类行的贡献：

| 行类型         | M\_C\_cat·z | M\_E\_RD·z | M\_E\_AUX·z | 新 subset 贡献                   |
| ----------- | ----------- | ---------- | ----------- | ----------------------------- |
| Group A/B   | 0           | 0          | 0           | 0 ✓                           |
| Group C     | sel\_cat(i) | 0          | 0           | `+1·sel·0 + (-1)·sel·0 = 0` ✓ |
| Group D     | 0           | 0          | 0           | 0 ✓                           |
| **Group E** | sel\_cat(i) | rd\_val(i) | aux(i)      | `sel_cat·(rd - aux)`          |
| Group F     | 0           | 0          | 0           | 0 ✓                           |

由于 selector one-hot，同一步只有一个类别活跃。算术类别（0,1,12,13,14,21,22,24,25）和逻辑/移位类别（15,16,17,18,19,20,23,26,27,28,29,30）互斥。

### Padding 兼容性

padding 步为 `Addi { rd:0, rs1:0, imm:0 }`（category 12）：

* `aux = 0`（非逻辑/移位指令）

* 逻辑/移位 subset 贡献：`sel_12 · (rd - aux) = 0 · (0 - 0) = 0` ✓

***

## 假设与决策

1. **aux 为结构性约束**：验证 rd 与 executor 计算结果一致，但不验证逻辑/移位运算本身。完整 soundness 需 Phase 2e LogUp + Stage 3 bit decomposition。已知技术债务。
2. **shamt 不做 range check**：SLLI/SRLI/SRAI 的 shamt 来自指令解码（trusted ∈ \[0,31]），SLL/SRL/SRA 的 shamt = `rs2 & 0x1F`（自动 ∈ \[0,31]）。Phase 2e 添加 u5 range table。
3. **aux 复用 offset 11**：witness 布局已预留 `aux`（offset 11），无需扩展 STEP\_VARS。
4. **SRAI 算术右移**：使用 `(rs1_val as i32) >> shamt` 实现，Rust 的 `>>` 对 i32 是算术右移。✓
5. **24 个新 subset 用循环生成**：12 类 × 2 subset，用 `for &cat in &[...]` 循环简化代码，避免 24 行重复。

***

## 后续阶段（不在本计划范围）

* **Phase 2d**：内存 + 分支 + 跳转 + 系统约束（LB/LH/LW/LBU/LHU/SB/SH/SW/BEQ..BGEU/JAL/JALR/ECALL/EBREAK/FENCE）

* **Phase 2e**：LogUp lookup 集成 + SLT 比较语义补全 + u5 range check + 集成测试

