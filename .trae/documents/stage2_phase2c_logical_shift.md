# Stage 2 Phase 2c — 逻辑 + 移位指令约束

## 摘要

Phase 2c 在 Phase 2b 的 48-matrix CCS 框架上增加逻辑指令（XOR/XORI/OR/ORI/AND/ANDI，6 条）和移位指令（SLL/SRL/SRA/SLLI/SRLI/SRAI，6 条）的语义约束。

**核心设计**：引入 `aux` witness 变量（offset 11，已预留）存储 executor 计算的逻辑/移位结果，约束 `sel_cat × (rd_val - aux) = 0`（selector-gated degree-2）。

**Soundness 定位**：本 Phase 为 MVP 结构性约束——验证 rd 与 aux 一致，但不验证逻辑/移位运算本身的正确性（XOR/OR/AND 是逐位运算，无法用域算术表达；移位需 bit decomposition）。完整 soundness 推迟到 Phase 2e（LogUp 真值表）和 Stage 3（bit decomposition + range check）。

## 当前状态分析

### 已完成

- ✅ Phase 2a：42-matrix selector-gated CCS 框架（Group A/B/C/D）
- ✅ Phase 2b：48-matrix CCS，Group E（算术语义）+ Group F（carry 二值性），69 subsets
- ✅ `compile_step_witness` 已计算 carry/borrow（7 种算术指令）
- ✅ witness 布局含 `aux`（offset 11）和 `shamt`（offset 9），但当前 `aux=0`、SLL/SRL/SRA 的 `shamt=0`

### 待完成（本计划范围）

1. 新增 `M_E_AUX` 矩阵（索引 48），矩阵总数 48→49
2. `compile_step_witness` 中计算 `aux`（逻辑/移位结果）和 SLL/SRL/SRA 的 `shamt`（= `rs2_val & 0x1F`）
3. Group E 行添加 `M_E_AUX` 条目
4. 新增 24 个 subsets（12 类 × 2 subset/类）
5. 更新测试断言 + 新增 14 个 Phase 2c 测试
6. 全量验证

### 关键约束：Phase 2b 验证前置

Phase 2b 实现已完成但尚未运行验证（Task #36）。本 Phase 实现前须先确认 Phase 2b 编译和测试通过。若 Phase 2b 存在问题，先修复再推进 2c。

---

## 设计：aux-based 结构性约束

### 为什么不能用域算术验证 XOR/OR/AND

XOR/OR/AND 是**逐位运算**，无法表示为域元素间的代数关系 `f(rs1, rs2, rd) = 0`：

- **XOR**：`a XOR b = a + b - 2·(a AND b)`，但 AND 本身也是逐位运算
- **OR**：`a OR b = a + b - (a AND b)`，同样依赖 AND
- **AND**：`rd_bit = rs1_bit · rs2_bit`（per-bit 乘法），需 32 个 bit 变量

不引入 bit decomposition（96+ 额外 witness 变量/步），无法在 degree-2 CCS 中验证这些运算的正确性。

### MVP 方案：aux witness + selector gating

**Witness**：
- `aux`（offset 11）= executor 用原生 u32 算术计算的逻辑/移位结果
- 对非逻辑/移位指令，`aux = 0`

**约束**：对每个逻辑/移位类别 cat，添加 2 个 degree-2 subset：
- `{M_C_cat, M_E_RD} → +1`：贡献 `sel_cat(i) · rd_val(i)`
- `{M_C_cat, M_E_AUX} → -1`：贡献 `-sel_cat(i) · aux(i)`

合计：`sel_cat(i) · (rd_val(i) - aux(i)) = 0`

由于 selector one-hot，只有活跃指令的约束项非零。

### 为什么 aux 约束仍有价值

1. **结构一致性**：所有 34 个类别均有语义约束，CCS 结构统一
2. **检测不一致篡改**：篡改 rd 但不篡改 aux（或反之）会被检测
3. **为 Phase 2e 铺路**：LogUp 真值表将补充 `aux` 正确性验证，届时只需验证 `aux = rs1 OP rs2` 的 per-bit 关系

### 未选方案（文档记录）

| 方案 | 描述 | 未选原因 |
|------|------|----------|
| 纯 stub（无约束） | 逻辑/移位指令仅靠 selector one-hot | 结构不一致，无法检测任何 rd 篡改 |
| bit decomposition | 分解 rs1/rs2/rd 为 32 bit，per-bit 验证 | 需 96+ witness 变量/步，复杂度高，属 Stage 3 范围 |
| 代数恒等式 | `rs1+rs2-rd-2·aux_and=0`（XOR 恒等式） | aux_and 仍可任意取值，无额外 soundness |

---

## 改动清单

### 改动 1：新增 M_E_AUX 矩阵常量

**文件**：`poker_zkvm/src/constraints/mod.rs` L94-101

```rust
// Phase 2c — 逻辑/移位指令约束矩阵
const M_E_AUX: usize = 48;
const NUM_CCS_MATRICES: usize = 49;  // 原 48
```

### 改动 2：计算 SLL/SRL/SRA 的 shamt

**文件**：`poker_zkvm/src/constraints/mod.rs` `compile_step_witness` 函数（~L255）

当前 `extract_insn_fields` 对 SLL/SRL/SRA 返回 `shamt=0`。需改为 `rs2_val & 0x1F`：

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

### 改动 3：计算 aux witness 值

**文件**：`poker_zkvm/src/constraints/mod.rs` `compile_step_witness` 函数（carry 计算之后）

```rust
let aux: u32 = match &step.instruction {
    // 逻辑立即数
    Instruction::Xori { .. } => rs1_val ^ imm,
    Instruction::Ori { .. } => rs1_val | imm,
    Instruction::Andi { .. } => rs1_val & imm,
    // 逻辑寄存器
    Instruction::Xor { .. } => rs1_val ^ rs2_val,
    Instruction::Or { .. } => rs1_val | rs2_val,
    Instruction::And { .. } => rs1_val & rs2_val,
    // 移位立即数
    Instruction::Slli { .. } => rs1_val << shamt,
    Instruction::Srli { .. } => rs1_val >> shamt,
    Instruction::Srai { .. } => ((rs1_val as i32) >> shamt) as u32,
    // 移位寄存器
    Instruction::Sll { .. } => rs1_val << shamt,
    Instruction::Srl { .. } => rs1_val >> shamt,
    Instruction::Sra { .. } => ((rs1_val as i32) >> shamt) as u32,
    _ => 0,
};
```

然后修改 witness push（~L339）：
```rust
witness.push(Fr::from_u32_with_wrap(aux));  // 原: Fr::zero()
```

移除 `OFF_AUX` 的 `#[allow(dead_code)]`（L79），因为本 Phase 开始使用。

### 改动 4：Group E 行添加 M_E_AUX 条目

**文件**：`poker_zkvm/src/constraints/mod.rs` `compile_batch_to_ccs` Group E 循环（~L521-527）

在现有 6 个 M_E_* 条目后添加：
```rust
matrices[M_E_AUX].add_entry(row, base + OFF_AUX, Fr::one())?;
```

### 改动 5：新增 24 个 subsets

**文件**：`poker_zkvm/src/constraints/mod.rs` `compile_batch_to_ccs` subsets 段（Group E subsets 之后，Group F 之前）

```rust
// Phase 2c: 逻辑 + 移位指令约束（12 类 × 2 subset = 24）
// 模式：sel_cat × (rd - aux) = 0

// XORI (cat=15)
subsets.push(vec![M_C_BASE + 15, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 15, M_E_AUX]); coeffs.push(neg_one);
// ORI (cat=16)
subsets.push(vec![M_C_BASE + 16, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 16, M_E_AUX]); coeffs.push(neg_one);
// ANDI (cat=17)
subsets.push(vec![M_C_BASE + 17, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 17, M_E_AUX]); coeffs.push(neg_one);
// SLLI (cat=18)
subsets.push(vec![M_C_BASE + 18, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 18, M_E_AUX]); coeffs.push(neg_one);
// SRLI (cat=19)
subsets.push(vec![M_C_BASE + 19, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 19, M_E_AUX]); coeffs.push(neg_one);
// SRAI (cat=20)
subsets.push(vec![M_C_BASE + 20, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 20, M_E_AUX]); coeffs.push(neg_one);
// SLL (cat=23)
subsets.push(vec![M_C_BASE + 23, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 23, M_E_AUX]); coeffs.push(neg_one);
// SRL (cat=27)
subsets.push(vec![M_C_BASE + 27, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 27, M_E_AUX]); coeffs.push(neg_one);
// SRA (cat=28)
subsets.push(vec![M_C_BASE + 28, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 28, M_E_AUX]); coeffs.push(neg_one);
// XOR (cat=26)
subsets.push(vec![M_C_BASE + 26, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 26, M_E_AUX]); coeffs.push(neg_one);
// OR (cat=29)
subsets.push(vec![M_C_BASE + 29, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 29, M_E_AUX]); coeffs.push(neg_one);
// AND (cat=30)
subsets.push(vec![M_C_BASE + 30, M_E_RD]); coeffs.push(Fr::one());
subsets.push(vec![M_C_BASE + 30, M_E_AUX]); coeffs.push(neg_one);
```

同时更新 subsets/coeffs Vec 容量：`Vec::with_capacity(69)` → `Vec::with_capacity(93)`。

### 改动 6：更新现有测试断言

| 测试 | 旧值 | 新值 |
|------|------|------|
| `test_compile_trace_single_batch` | `num_matrices() == 48` | `== 49` |
| `test_48_matrix_ccs_structure` | 函数名 + 48/69 断言 | 重命名 `test_49_matrix_ccs_structure`，49/93 断言 |
| doc comment（`compile_batch_to_ccs`） | 48 矩阵/69 subset | 49 矩阵/93 subset |

### 改动 7：新增 14 个 Phase 2c 测试

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块末尾

复用 `make_step_with_insn` 和 `make_ecall_step_with_regs` 辅助函数。

#### 逻辑指令测试（6 个）

1. **`test_group_e_xor_constraint`**：K=2，步0 设 regs[2]=0xF0, [3]=0x0F，步1 XOR {rd:1,rs1:2,rs2:3} regs[1]=0xFF。验证 true。篡改 rd→0xFE 验证 false。

2. **`test_group_e_or_constraint`**：K=2，步0 设 regs[2]=0xF0, [3]=0x0F，步1 OR regs[1]=0xFF。验证 true。篡改 rd→0xF0 验证 false。

3. **`test_group_e_and_constraint`**：K=2，步0 设 regs[2]=0xFF, [3]=0x0F，步1 AND regs[1]=0x0F。验证 true。篡改 rd→0xFF 验证 false。

4. **`test_group_e_xori_constraint`**：K=2，步0 设 regs[2]=0xF0，步1 XORI {rd:1,rs1:2,imm:0x0F} regs[1]=0xFF。验证 true。

5. **`test_group_e_ori_constraint`**：K=2，步0 设 regs[2]=0xF0，步1 ORI {imm:0x0F} regs[1]=0xFF。验证 true。

6. **`test_group_e_andi_constraint`**：K=2，步0 设 regs[2]=0xFF，步1 ANDI {imm:0x0F} regs[1]=0x0F。验证 true。

#### 移位指令测试（6 个）

7. **`test_group_e_slli_constraint`**：K=2，步0 设 regs[2]=0x1，步1 SLLI {rd:1,rs1:2,shamt:4} regs[1]=0x10。验证 true。篡改 rd→0x20 验证 false。

8. **`test_group_e_srli_constraint`**：K=2，步0 设 regs[2]=0x80000000，步1 SRLI {shamt:1} regs[1]=0x40000000。验证 true。

9. **`test_group_e_srai_constraint`**：K=2，步0 设 regs[2]=0x80000000，步1 SRAI {shamt:1} regs[1]=0xC0000000（算术右移）。验证 true。

10. **`test_group_e_sll_constraint`**：K=2，步0 设 regs[2]=0x1, [3]=4，步1 SLL {rd:1,rs1:2,rs2:3} regs[1]=0x10。验证 true。验证 shamt = 4 & 0x1F = 4。

11. **`test_group_e_srl_constraint`**：K=2，步0 设 regs[2]=0x80000000, [3]=1，步1 SRL regs[1]=0x40000000。验证 true。

12. **`test_group_e_sra_constraint`**：K=2，步0 设 regs[2]=0x80000000, [3]=1，步1 SRA regs[1]=0xC0000000。验证 true。

#### 边界 + Soundness 测试（2 个）

13. **`test_shift_shamt_from_rs2_low_5_bits`**：K=2，步0 设 regs[2]=0x1, [3]=35（0b100011），步1 SLL {rd:1,rs1:2,rs2:3} regs[1]=0x8（1 << (35&0x1F=3) = 8）。验证 true。确认 shamt = 3 而非 35。

14. **`test_logical_shift_soundness_wrong_operand`**：K=2 XOR batch，篡改 rd_val → 验证 false。

---

## 约束正确性验证

### Group E 行（步 i）新 subset 贡献

新增 subset 在各类行的贡献：

| 行类型 | M_C_cat·z | M_E_RD·z | M_E_AUX·z | 新 subset 贡献 |
|--------|-----------|----------|-----------|---------------|
| Group A/B | 0 | 0 | 0 | 0 ✓ |
| Group C | sel_cat(i) | 0 | 0 | `sel_cat·0 - sel_cat·0 = 0` ✓ |
| Group D | 0 | 0 | 0 | 0 ✓ |
| **Group E** | sel_cat(i) | rd_val(i) | aux(i) | `sel_cat·(rd - aux)` |
| Group F | 0 | 0 | 0 | 0 ✓ |

**Group E 行总和**（含 Phase 2b 现有约束）：
- Phase 2b 算术：`operand_active(i)`（仅活跃算术类别非零）
- Phase 2c 逻辑/移位：`sel_cat·(rd - aux)`（仅活跃逻辑/移位类别非零）
- Group F carry：`carry²(i) - carry(i)`
- 合计 = `operand_active + sel_logical·(rd - aux) + carry² - carry = 0`

由于 selector one-hot，算术类别和逻辑/移位类别互斥，同一步只有一个非零。✓

### Padding 兼容性

padding 步为 `Addi { rd:0, rs1:0, imm:0 }`（category 12）：
- `aux = 0`（非逻辑/移位指令）
- 逻辑/移位 subset 贡献：`sel_12 · (rd - aux) = 0 · (0 - 0) = 0` ✓

### 跨 batch CCS 结构一致性

所有新矩阵条目和 subset 仅依赖 step 在 batch 内的位置 i，不依赖全局 step_index。所有同 K 的 batch 共享相同 CCS 结构。✓

---

## 假设与决策

1. **aux 为结构性约束**：验证 rd 与 executor 计算结果一致，但不验证逻辑/移位运算本身。完整 soundness 需 Phase 2e LogUp + Stage 3 bit decomposition。已知技术债务。
2. **shamt 不做 range check**：SLLI/SRLI/SRAI 的 shamt 来自指令解码（trusted ∈ [0,31]），SLL/SRL/SRA 的 shamt = `rs2 & 0x1F`（自动 ∈ [0,31]）。Phase 2e 添加 u5 range table。
3. **aux 复用 offset 11**：witness 布局已预留 `aux`（offset 11），无需扩展 STEP_VARS。
4. **SRAI 算术右移**：使用 `(rs1_val as i32) >> shamt` 实现，Rust 的 `>>` 对 i32 是算术右移。✓
5. **24 个新 subset**：12 类 × 2 subset（{M_C_cat, M_E_RD} + {M_C_cat, M_E_AUX}）。subset 总数 69→93，均为 degree-2。

## 验证步骤

### 前置：Phase 2b 验证

```bash
cargo build -p poker_zkvm
cargo test -p poker_zkvm --lib constraints::mod::tests
```
若失败，先修复 Phase 2b 再推进。

### Phase 2c 验证

1. `cargo build` — 编译通过
2. `cargo clippy --all-targets --features test-helpers` — 无 warning（M_E_AUX、OFF_AUX 不再 dead code）
3. `cargo test --features test-helpers` — 全部测试通过（含 14 个新测试 + 全部回归）
4. `cargo bench --no-run --features test-helpers` — 基准编译通过
5. 重点验证：
   - `test_49_matrix_ccs_structure` 通过（49 矩阵、93 subset）
   - 6 个逻辑指令测试通过（正例 + 负例）
   - 6 个移位指令测试通过（含 SRAI 算术右移）
   - `test_shift_shamt_from_rs2_low_5_bits` 通过（shamt = rs2 & 0x1F）
   - 全部 Phase 2b 测试仍通过
   - E2E 测试（e2e_fibonacci 等）仍通过

### 通过标准

- 12 条逻辑/移位指令均有正负测试
- SLL/SRL/SRA 正确使用 rs2 & 0x1F 作为移位量
- SRAI/SRA 正确实现算术右移
- 所有现有测试无回归
- clippy 无 warning
- 基准测试编译成功

## Phase 2d/2e 大纲（后续）

- **Phase 2d**：内存 + 分支 + 跳转 + 系统约束（LB/LH/LW/LBU/LHU/SB/SH/SW/BEQ..BGEU/JAL/JALR/ECALL/EBREAK/FENCE）
  - 分支：Degree-3 降阶引入 `branch_cond = taken × (rs1 - rs2)`（degree-2）+ `sel × branch_cond = 0`
  - 跳转：JAL/JALR 的 rd=pc+4 和 next_pc 约束
  - 内存：MVP 地址约束 `addr = rs1 + imm`
  - 系统：FENCE/ECALL/EBREAK 无约束（MVP）
- **Phase 2e**：LogUp lookup 集成 + SLT 比较语义补全 + u5 range check + 集成测试
