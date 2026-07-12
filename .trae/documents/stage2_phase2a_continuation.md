# Stage 2 Phase 2a — 42-matrix CCS 续接实现计划

## 摘要

Stage 2 目标：修复 C-1 Soundness 漏洞 — 当前 `compile_batch_to_ccs` 仅生成 step\_index 连续性约束，恶意 prover 可执行错误指令而 CCS 仍通过。Phase 2a 建立 **统一 witness 布局 + selector-gated 约束框架**（42 矩阵 CCS），为 Phase 2b-2e 的指令语义约束铺路。

**前置状态**：matrix 索引常量（M\_A\_NEXT..NUM\_CCS\_MATRICES）和辅助函数（`instruction_category`、`assign_selectors`、`extract_insn_fields`、`compute_taken`、`compute_next_pc`、`compile_step_witness`）已添加到 `constraints/mod.rs` L47-266。旧 3-matrix `compile_batch_to_ccs`（L364-431）仍存在，需替换。

## 当前状态分析

### 已完成

* `constraints/mod.rs` L47-84：常量 `STEP_VARS=46`、`NUM_CATEGORIES=34`、witness 偏移量、42 矩阵索引

* `constraints/mod.rs` L87-266：辅助函数（category 映射、selector 分配、字段提取、taken/next\_pc 计算、witness 编译）

* 编译器警告：矩阵常量未使用（将在此计划中使用）

### 待修改

1. **`compile_batch_to_ccs`**（L364-431）：旧 3-matrix 设计 → 新 42-matrix 设计
2. **`pad_trace`**（prover/mod.rs L897-929）：padding 步 `pc: 0` → `pc: prev_pc + 4`
3. **现有测试**（constraints/mod.rs L482-781）：6 个测试的断言需更新
4. **新增测试**：7 个 Phase 2a 专项测试

## 设计方案

### Witness 布局

```
z = [1, w_0[0..45], w_1[0..45], ..., w_{K-1}[0..45], 0, 0, ...]
     ^  ^--- step 0 ---  ^--- step 1 ---       ^--- step K-1 ---  ^- padding
     |
     z[0] = 1 (常数)
```

每步 46 个变量（`STEP_VARS=46`）：

| 偏移     | 字段              | 说明                        |
| ------ | --------------- | ------------------------- |
| 0      | idx             | step\_index               |
| 1      | pc              | 当前 PC                     |
| 2      | next\_pc        | 后继 PC                     |
| 3      | rs1\_val        | 源寄存器 1 值（来自前一步 registers） |
| 4      | rs2\_val        | 源寄存器 2 值                  |
| 5      | rd\_val         | 目的寄存器值（当前步 registers）     |
| 6      | imm             | 立即数                       |
| 7      | carry           | 进位（Phase 2b 填充）           |
| 8      | taken           | 分支 taken flag             |
| 9      | shamt           | 移位量                       |
| 10     | branch\_cond    | 分支条件中间变量（Phase 2d 填充）     |
| 11     | aux             | 辅助变量（Phase 2b 填充）         |
| 12..45 | sel\_0..sel\_33 | one-hot selector（34 个）    |

步 i 的 witness 起始列：`col_i = 1 + i * 46`

### 42 矩阵 CCS 结构

**4 个约束组**，所有组共享相同的 42 个 subset（每个 subset 对所有行求值，但矩阵仅在对应组行有非零条目，其余行隐式为 0）。

#### Group A — step\_index 连续性（行 0..K-2，共 K-1 行）

约束：`idx_{i+1} - idx_i - 1 = 0`

| 矩阵          | 索引 | 行 i 条目                     | subset | coeff |
| ----------- | -- | -------------------------- | ------ | ----- |
| M\_A\_NEXT  | 0  | col=`1+(i+1)*46+0`, val=+1 | {0}    | 1     |
| M\_A\_CUR   | 1  | col=`1+i*46+0`, val=-1     | {1}    | 1     |
| M\_CONST\_A | 2  | col=0, val=-1              | {2}    | 1     |

#### Group B — PC 连续性（行 K-1..2K-3，共 K-1 行）

约束：`next_pc_i - pc_{i+1} = 0`

| 矩阵         | 索引 | 行 (K-1+i) 条目               | subset | coeff |
| ---------- | -- | -------------------------- | ------ | ----- |
| M\_B\_NEXT | 3  | col=`1+i*46+2`, val=+1     | {3}    | 1     |
| M\_B\_CUR  | 4  | col=`1+(i+1)*46+1`, val=-1 | {4}    | 1     |

#### Group C — selector one-hot（行 2K-2..3K-3，共 K 行）

约束：`Σ_j sel_j(i) - 1 = 0`（对每步 i）

| 矩阵                | 索引    | 行 (2K-2+i) 条目             | subset | coeff   |
| ----------------- | ----- | ------------------------- | ------ | ------- |
| M\_C\_0..M\_C\_33 | 5..38 | col=`1+i*46+12+j`, val=+1 | {5+j}  | 1（每个 j） |
| M\_CONST\_C       | 39    | col=0, val=-1             | {39}   | -1      |

共 35 个 subset（34 selector + 1 constant）。

#### Group D — selector 二值性（行 3K-2..37K-3，共 34\*K 行）

约束：`sel_j(i)² - sel_j(i) = 0`（对每步 i 的每个 selector j）

| 矩阵        | 索引 | 行 (3K-2+i\*34+j) 条目       | subset   | coeff |
| --------- | -- | ------------------------- | -------- | ----- |
| M\_D\_SQ  | 40 | col=`1+i*46+12+j`, val=+1 | {40, 40} | 1     |
| M\_D\_LIN | 41 | col=`1+i*46+12+j`, val=+1 | {41}     | -1    |

subset `{40, 40}` 利用 CCS 允许重复索引的特性，计算 `row[40] * row[40] = sel²`（已验证 `ccs/mod.rs` L323-332）。

### 维度计算

* `raw_num_vars = 1 + K * 46`

* `raw_num_rows = 37 * K - 2`（K≥1；K=1 时 = 35）

* `padded_num_vars = raw_num_vars.next_power_of_two().max(2)`

* `padded_num_rows = raw_num_rows.max(1).next_power_of_two()`

* 矩阵数 = 42，subset 数 = 42

**max\_n\_vars=20 验证**：

* K=256：num\_vars=11777→16384=2^14，pcs\_n\_vars=14 ≤ 20 ✓

* K=1024：num\_vars=47105→65536=2^16，pcs\_n\_vars=16 ≤ 20 ✓

* K=3（generate\_test\_proof）：num\_vars=139→256=2^8，pcs\_n\_vars=8 ≤ 20 ✓

### `next_step_pc` 策略

对 batch 内步 i（i < K-1），传 `next_step_pc = None`，让 `compile_step_witness` 从指令计算 `next_pc`。Group B 约束 `next_pc_i - pc_{i+1} = 0` 检查计算值与实际下一步 PC 的一致性。对末步（i=K-1），同样传 `None`，next\_pc 计算但不被 Group B 约束。

**注意**：首步（i=0）的 rs1/rs2\_val=0（无 prev\_step），若首步为分支/JALR 指令，计算的 next\_pc 可能错误导致 Group B 失败。Phase 2a 测试用 ECALL/NOP（非分支），不受影响。此限制在 Phase 2d 解决。

## 改动清单

### 改动 1：重写 `compile_batch_to_ccs`

**文件**：`poker_zkvm/src/constraints/mod.rs` L364-431

替换为：

```rust
fn compile_batch_to_ccs(
    steps: &[&crate::trace::Step],
    batch_id: u64,
) -> Result<CcsInstance, ZkvmError> {
    let k = steps.len();
    if k == 0 {
        return Err(ZkvmError::Other("compile_batch_to_ccs: batch 为空".to_string()));
    }

    let raw_num_vars = 1 + k * STEP_VARS;
    let raw_num_rows = 37 * k - 2; // (K-1) + (K-1) + K + 34*K
    let padded_num_vars = raw_num_vars.next_power_of_two().max(2);
    let padded_num_rows = raw_num_rows.max(1).next_power_of_two();

    // --- Witness: [1, w_0, w_1, ..., w_{K-1}, padding] ---
    let mut witness = Vec::with_capacity(padded_num_vars);
    witness.push(Fr::one());
    for (i, step) in steps.iter().enumerate() {
        let prev_step = if i > 0 { Some(steps[i - 1]) } else { None };
        let step_witness = compile_step_witness(step, prev_step, None);
        witness.extend_from_slice(&step_witness);
    }
    witness.resize(padded_num_vars, Fr::zero());

    // --- 42 矩阵 ---
    let neg_one = Fr::zero().sub(&Fr::one());
    let mut matrices: Vec<SparseMatrix> = (0..NUM_CCS_MATRICES)
        .map(|_| SparseMatrix::new(padded_num_rows, padded_num_vars))
        .collect();

    // Group A: step_index continuity (rows 0..K-2)
    for i in 0..k.saturating_sub(1) {
        let row = i;
        let col_next = 1 + (i + 1) * STEP_VARS + OFF_IDX;
        let col_cur = 1 + i * STEP_VARS + OFF_IDX;
        matrices[M_A_NEXT].add_entry(row, col_next, Fr::one())?;
        matrices[M_A_CUR].add_entry(row, col_cur, neg_one)?;
        matrices[M_CONST_A].add_entry(row, 0, neg_one)?;
    }

    // Group B: PC continuity (rows K-1..2K-3)
    for i in 0..k.saturating_sub(1) {
        let row = (k - 1) + i;
        let col_next_pc = 1 + i * STEP_VARS + OFF_NEXT_PC;
        let col_next_step_pc = 1 + (i + 1) * STEP_VARS + OFF_PC;
        matrices[M_B_NEXT].add_entry(row, col_next_pc, Fr::one())?;
        matrices[M_B_CUR].add_entry(row, col_next_step_pc, neg_one)?;
    }

    // Group C: selector one-hot (rows 2K-2..3K-3)
    for i in 0..k {
        let row = 2 * (k - 1) + i; // 2K-2 + i
        for j in 0..NUM_CATEGORIES {
            let col = 1 + i * STEP_VARS + OFF_SEL_START + j;
            matrices[M_C_BASE + j].add_entry(row, col, Fr::one())?;
        }
        matrices[M_CONST_C].add_entry(row, 0, neg_one)?;
    }

    // Group D: selector binary (rows 3K-2..37K-3)
    for i in 0..k {
        for j in 0..NUM_CATEGORIES {
            let row = 3 * (k - 1) + k + i * NUM_CATEGORIES + j; // 3K-2 + i*34 + j
            // 等价: (k-1)+(k-1)+k + i*34 + j = 3k-2 + i*34 + j
            let col = 1 + i * STEP_VARS + OFF_SEL_START + j;
            matrices[M_D_SQ].add_entry(row, col, Fr::one())?;
            matrices[M_D_LIN].add_entry(row, col, Fr::one())?;
        }
    }

    // --- 42 subsets + coefficients ---
    let mut subsets: Vec<Vec<usize>> = Vec::with_capacity(NUM_CCS_MATRICES);
    let mut coeffs: Vec<Fr> = Vec::with_capacity(NUM_CCS_MATRICES);
    // Group A: {0}→1, {1}→1, {2}→1
    subsets.push(vec![M_A_NEXT]); coeffs.push(Fr::one());
    subsets.push(vec![M_A_CUR]); coeffs.push(Fr::one());
    subsets.push(vec![M_CONST_A]); coeffs.push(Fr::one());
    // Group B: {3}→1, {4}→1
    subsets.push(vec![M_B_NEXT]); coeffs.push(Fr::one());
    subsets.push(vec![M_B_CUR]); coeffs.push(Fr::one());
    // Group C: {5+j}→1 for j=0..33, {39}→-1
    for j in 0..NUM_CATEGORIES {
        subsets.push(vec![M_C_BASE + j]); coeffs.push(Fr::one());
    }
    subsets.push(vec![M_CONST_C]); coeffs.push(neg_one);
    // Group D: {40,40}→1, {41}→-1
    subsets.push(vec![M_D_SQ, M_D_SQ]); coeffs.push(Fr::one());
    subsets.push(vec![M_D_LIN]); coeffs.push(neg_one);

    let ccs = Ccs::new(padded_num_vars, matrices, subsets, coeffs)?;

    // public_inputs: [batch_id, first_idx, last_idx]
    let first_idx = steps.first().unwrap().step_index;
    let last_idx = steps.last().unwrap().step_index;
    let public_inputs = vec![
        Fr::from_u64(batch_id),
        Fr::from_u64(first_idx),
        Fr::from_u64(last_idx),
    ];

    CcsInstance::new(ccs, witness, public_inputs)
}
```

**行号计算验证**：

* Group A: 行 `0..K-2`（K-1 行）

* Group B: 行 `(K-1)..(2K-3)`（K-1 行）

* Group C: 行 `(2K-2)..(3K-3)`（K 行）

* Group D: 行 `(3K-2)..(37K-3)`（34K 行，3K-2+34K-1 = 37K-3）

* 总行数 = (K-1)+(K-1)+K+34K = 37K-2 ✓

### 改动 2：修复 `pad_trace` PC 连续性 bug

**文件**：`poker_zkvm/src/prover/mod.rs` L897-929

**问题**：padding 步 `pc: 0`，导致 Group B 约束 `next_pc_{last_real} - pc_{first_pad} = (last_real_pc+4) - 0 ≠ 0` 失败。

**修复**：padding 步 PC 从前一步 PC + 4 开始递增。

```rust
fn pad_trace(trace: &mut Trace, batch_size: usize) -> Result<(), ZkvmError> {
    if batch_size == 0 {
        return Err(ZkvmError::Other("pad_trace: batch_size 须 > 0".to_string()));
    }
    let len = trace.len();
    let remainder = len % batch_size;
    if remainder == 0 {
        return Ok(());
    }
    let pad_count = batch_size - remainder;
    let mut next_index = if len == 0 {
        0
    } else {
        trace.step(len - 1)?.step_index + 1
    };
    let mut next_pc = if len == 0 {
        0
    } else {
        trace.step(len - 1)?.pc.wrapping_add(4)
    };
    for _ in 0..pad_count {
        trace.push_step(Step {
            step_index: next_index,
            pc: next_pc,
            instruction: Instruction::Addi { rd: 0, rs1: 0, imm: 0 },
            registers: [0u32; 32],
            mem_access: vec![],
        });
        next_index += 1;
        next_pc = next_pc.wrapping_add(4);
    }
    Ok(())
}
```

### 改动 3：更新现有测试

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块（L456+）

| 测试                                                      | 旧断言                                       | 新断言                                                                      |
| ------------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------ |
| `test_compile_trace_single_batch` (K=5)                 | num\_vars=8, num\_rows=4, num\_matrices=3 | num\_vars=256(1+5\*46=231→256), num\_rows=256(183→256), num\_matrices=42 |
| `test_single_step_batch_no_continuity_constraint` (K=1) | num\_vars=2, num\_rows=1                  | num\_vars=64(47→64), num\_rows=64(35→64)                                 |
| `test_witness_layout` (K=3)                             | z\[0]=1, z\[1]=0, z\[2]=1, z\[3]=2        | z\[0]=1, z\[1]=0(idx\_0), z\[47]=1(idx\_1), z\[93]=2(idx\_2)             |
| `test_large_batch_default_size` (K=1024)                | num\_vars=2048, num\_rows=1024            | num\_vars=65536(47105→65536), num\_rows=65536(37886→65536)               |
| `test_padding_witness_zero_filled` (K=5)                | witness\[6]=0, witness\[7]=0              | witness\[231]=0, witness\[255]=0 (padding 区)                             |
| `test_continuity_constraint_violated_by_gap`            | `!is_satisfied()`                         | 不变（Group A 或 B 会失败）                                                      |

**不需要改动的测试**（14 个）：

* `test_compile_trace_empty_trace_errors`、`test_compile_trace_zero_batch_size_errors`：错误路径

* `test_compile_trace_multiple_batches`：仅检查 public\_inputs 和 is\_satisfied()

* `test_compile_trace_default_batch_size`：仅检查实例数

* `test_compile_trace_exceeds_fold_step_count`、`test_compile_trace_at_fold_step_limit`：错误路径

* `test_batch_continuity_constraint_satisfied`：仅检查 is\_satisfied() 和 batch 连续性

* `test_batch_continuity_between_batches_violated`：仅检查 batch 间连续性

* `test_batch_with_memory_access_steps`：仅检查 is\_satisfied()

* `test_padding_power_of_two_invariant`：检查 2 的幂不变量（仍成立）

* `test_compile_trace_returns_correct_instance_count`、`test_batch_id_monotonic`：仅检查实例数/batch\_id

* `test_public_inputs_contain_batch_metadata`：仅检查 public\_inputs

* Phase 5 集成测试：使用独立子电路 CCS

### 改动 4：新增 7 个 Phase 2a 测试

**文件**：`poker_zkvm/src/constraints/mod.rs` 测试模块末尾

1. **`test_42_matrix_ccs_structure`**：验证 num\_matrices=42, num\_constraints=42, subset\[39]={40,40}
2. **`test_group_a_step_index_continuity`**：构造 step\_index 连续 trace，验证 is\_satisfied()=true；构造跳跃 trace，验证 false
3. **`test_group_b_pc_continuity`**：构造 pc 连续 trace（pc=i\*4），验证 true；构造 pc 跳跃，验证 false
4. **`test_group_c_selector_one_hot`**：验证 ECALL 步的 selector one-hot（sel\_32=1，其余=0）
5. **`test_group_d_selector_binary`**：验证所有 selector 为 0 或 1（padding 区 selector=0 满足 0²-0=0）
6. **`test_compile_step_witness_layout`**：验证 46 变量布局（idx, pc, next\_pc, rs1\_val, ...）
7. **`test_instruction_category_coverage`**：验证所有 40 Instruction 变体映射到 0..33

## 假设与决策

1. **首步 rs1/rs2\_val=0**：Phase 2a 接受此限制（测试用非分支指令）。Phase 2d 解决跨 batch 寄存器传递。
2. **next\_step\_pc=None**：从指令计算 next\_pc，使 Group B 成为有意义的语义检查（而非 tautology）。
3. **42 矩阵 vs 43**：利用 subset `[40, 40]` 实现 sel²，避免第 43 个矩阵。
4. **Group C 用 35 个 size-1 subset**：保持 CCS degree=2（仅 Group D 的 {40,40} 为 degree 2），避免 degree-35 的 sumcheck 灾难。
5. **generate\_test\_proof（batch\_size=3）兼容**：K=3 → num\_vars=256, pcs\_n\_vars=8 ≤ 20。
6. **`default_ccs_whitelist`** **自动更新**：内部调用 `generate_test_proof()`，新 CCS commitment 会自动反映。

## 验证步骤

1. `cargo build` — 编译通过
2. `cargo clippy --all-targets` — 无 warning（矩阵常量被使用）
3. `cargo test` — 全部测试通过（716 unit + 31 integration + 17 E2E + 13 soundness）
4. `cargo bench --no-run` — 基准测试编译通过
5. 重点验证：

   * `test_soundness_trace_tampering_detected` 仍通过（使用独立 CCS）

   * `test_soundness_tampered_proof_byte_flip_fails` 仍通过（proof 结构不变）

   * `generate_test_proof` → `verify_production` 闭环通过

## Phase 2b-2e 大纲（后续）

* **Phase 2b**：算术指令约束（ADD/ADDI/SUB/SLT/SLTI/SLTU/SLTIU/LUI/AUIPC）— 在 Group D 后追加 Group E 语义约束行

* **Phase 2c**：逻辑 + 移位指令约束（XOR/OR/AND/XORI/ORI/ANDI/SLL/SRL/SRA/SLLI/SRLI/SRAI）

* **Phase 2d**：内存 + 分支 + 跳转 + 系统约束（LB/LH/LW/LBU/LHU/SB/SH/SW/BEQ/BNE/BLT/BGE/BLTU/BGEU/JAL/JALR/ECALL/EBREAK/FENCE）

* **Phase 2e**：集成测试 + soundness 验证 + LogUp lookup 集成

