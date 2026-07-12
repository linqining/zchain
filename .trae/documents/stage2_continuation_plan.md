# Stage 2 继续实现计划：完整 RV32I 指令语义约束

## 概要

继续推进 Stage 2（修复 C-1 健全性漏洞）。Phase 2a 的辅助函数已添加（[src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) L30-254），但 `compile_batch_to_ccs` 仍为旧的 3 矩阵设计（L352-419）。本计划完成 Phase 2a 并概述后续 Phase 2b-2e。

## 当前状态分析

### 已完成（Phase 2a 辅助函数）
- 常量：`STEP_VARS=46`、`NUM_CATEGORIES=34`、offset 常量 OFF_IDX..OFF_SEL_START（L47-72）
- `instruction_category(insn) -> usize`（L75-116）：40 variant → 34 组映射
- `assign_selectors(insn) -> [Fr; 34]`（L119-123）：one-hot selector
- `extract_insn_fields(insn) -> (Option<u8>, Option<u8>, Option<u8>, u32, u8)`（L128-171）
- `compute_taken(insn, rs1, rs2) -> bool`（L174-184）
- `compute_next_pc(pc, insn, rs1, rs2) -> u32`（L187-205）
- `compile_step_witness(step, prev_step, next_step_pc) -> Vec<Fr>`（L213-254）

### 待修改
- **`compile_batch_to_ccs`**（L352-419）：旧 3 矩阵设计 → 新 42 矩阵设计
- **`pad_trace`**（[src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) L897-929）：pc=0 → pc=prev_pc+4（修复 PC 连续性）
- **现有测试**（L444-770+）：witness 布局断言需更新

### 关键发现
1. **CCS 子集允许重复索引**：`Vec<Vec<usize>>` 可含 `[40, 40]`，使 `sel²` 可用单矩阵实现（验证于 [src/ccs/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/ccs/mod.rs) L321-332）
2. **`default_ccs_whitelist`** 运行时自动更新（[src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs) L1085-1088），CCS 结构变更后无需手动维护
3. **`max_n_vars=20`**（L87）：batch_size=256 → num_vars=1+256×46=11777 → padded 16384=2^14 ≤ 2^20 ✓
4. **Soundness test #4**（[tests/soundness_tests.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/soundness_tests.rs) L177-208）使用独立 CCS，不受影响
5. **`generate_test_proof`** 用 batch_size=3（L1003）：K=3 → num_vars=139→256, num_rows=109→128, pcs_n_vars=8 ≤ 20 ✓

---

## Phase 2a 实现：42 矩阵 CCS 框架

### 文件 1: [src/constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)

#### 改动 1：重写 `compile_batch_to_ccs`（替换 L352-419）

**Witness 布局**：
```
z = [1, w_0[0..45], w_1[0..45], ..., w_{K-1}[0..45], padding...]
```
- z[0] = 1（常数）
- 步 i 的变量 j 位于 z[1 + i*46 + j]
- 总长度 raw_num_vars = 1 + K×46，padding 到 2 的幂

**42 矩阵**（所有矩阵同高 padded_num_rows × padded_num_cols）：

| 索引 | 名称 | 用途 | 行组 |
|------|------|------|------|
| 0 | M_A_NEXT | 选 idx_{i+1} | A (0..K-2) |
| 1 | M_A_CUR | 选 idx_i | A |
| 2 | M_CONST_A | 选 z[0]=1 | A |
| 3 | M_B_NEXT | 选 pc_{i+1} | B (K-1..2K-3) |
| 4 | M_B_CUR | 选 next_pc_i | B |
| 5..38 | M_C_0..M_C_33 | 各选 sel_C | C (2K-2..3K-3) |
| 39 | M_CONST_C | 选 z[0]=1 | C |
| 40 | M_D_SQ | 选 sel_C（平方用） | D (3K-2..37K-3) |
| 41 | M_D_LIN | 选 sel_C（线性用） | D |

**42 子集 + 系数**：

| 子集 | 矩阵索引 | 系数 | 约束 |
|------|---------|------|------|
| S_0 | [0] | +1 | idx_{i+1} |
| S_1 | [1] | -1 | -idx_i |
| S_2 | [2] | -1 | -1 (常数) |
| S_3 | [3] | +1 | pc_{i+1} |
| S_4 | [4] | -1 | -next_pc_i |
| S_5..S_38 | [5]..[38] | +1 | sel_0..sel_33 |
| S_39 | [39] | -1 | -1 (常数) |
| S_40 | [40, 40] | +1 | sel_C² |
| S_41 | [41] | -1 | -sel_C |

**行布局**（K 步，总 37K-2 行）：
- Group A（step_index 连续性）：行 0..K-2（K-1 行）
  - 行 i：`idx_{i+1} - idx_i - 1 = 0`
- Group B（PC 连续性）：行 K-1..2K-3（K-1 行）
  - 行 K-1+i：`pc_{i+1} - next_pc_i = 0`
- Group C（selector one-hot）：行 2K-2..3K-3（K 行）
  - 行 2K-2+i：`Σ_{C=0}^{33} sel_C_i - 1 = 0`
- Group D（selector binary）：行 3K-2..37K-3（34K 行）
  - 行 3K-2+i×34+C：`sel_C_i² - sel_C_i = 0`

**矩阵条目填充**：

Group A（行 i = 0..K-2）：
- M_A_NEXT: (i, 1+(i+1)×46+OFF_IDX) = 1
- M_A_CUR: (i, 1+i×46+OFF_IDX) = 1
- M_CONST_A: (i, 0) = 1

Group B（行 r = K-1+i, i = 0..K-2）：
- M_B_NEXT: (r, 1+(i+1)×46+OFF_PC) = 1
- M_B_CUR: (r, 1+i×46+OFF_NEXT_PC) = 1

Group C（行 r = 2K-2+i, i = 0..K-1）：
- M_C_C: (r, 1+i×46+OFF_SEL_START+C) = 1, for C = 0..33
- M_CONST_C: (r, 0) = 1

Group D（行 r = 3K-2+i×34+C, i = 0..K-1, C = 0..33）：
- M_D_SQ: (r, 1+i×46+OFF_SEL_START+C) = 1
- M_D_LIN: (r, 1+i×46+OFF_SEL_START+C) = 1

**关键不变量**：每个矩阵仅在其行组内有条目，其他行组隐式为 0。对于不属于当前行组的子集，其矩阵-向量积为 0，乘积为 0，对约束和贡献为 0。

**实现逻辑**：
```rust
fn compile_batch_to_ccs(steps: &[&Step], batch_id: u64) -> Result<CcsInstance, ZkvmError> {
    let k = steps.len();
    // 1. 构建 witness: [1, w_0, ..., w_{K-1}, padding]
    let raw_num_vars = 1 + k * STEP_VARS;
    let padded_num_vars = raw_num_vars.next_power_of_two().max(2);
    let mut witness = Vec::with_capacity(padded_num_vars);
    witness.push(Fr::one());
    for (i, step) in steps.iter().enumerate() {
        let prev = if i > 0 { Some(steps[i - 1]) } else { None };
        let next_pc = if i + 1 < k { Some(steps[i + 1].pc) } else { None };
        witness.extend(compile_step_witness(step, prev, next_pc));
    }
    witness.resize(padded_num_vars, Fr::zero());

    // 2. 计算行数
    let raw_num_rows = 37 * k.saturating_sub(0) - 2; // 37K - 2 (K >= 1)
    // 实际: (K-1) + (K-1) + K + 34K = 37K - 2
    let raw_num_rows = if k >= 1 { 37 * k - 2 } else { 0 };
    let padded_num_rows = raw_num_rows.max(1).next_power_of_two();

    // 3. 构建 42 个矩阵（所有 padded_num_rows × padded_num_vars）
    let mut matrices = vec![SparseMatrix::new(padded_num_rows, padded_num_vars); 42];
    // 填充 Group A, B, C, D 条目（按上述规则）
    // ...

    // 4. 构建 42 个子集和系数
    let subsets = vec![
        vec![0], vec![1], vec![2],           // A: S_0, S_1, S_2
        vec![3], vec![4],                     // B: S_3, S_4
        vec![5], vec![6], ..., vec![38],      // C: S_5..S_38 (34 个)
        vec![39],                             // C: S_39 (常数)
        vec![40, 40],                         // D: S_40 (平方)
        vec![41],                             // D: S_41 (线性)
    ];
    let coeffs = vec![
        Fr::one(), neg_one, neg_one,          // A
        Fr::one(), neg_one,                    // B
        Fr::one(); 34,                         // C: sel_0..sel_33
        neg_one,                               // C: 常数
        Fr::one(), neg_one,                    // D
    ];

    // 5. public_inputs: [batch_id, first_idx, last_idx]（格式不变）
    // ...
    CcsInstance::new(ccs, witness, public_inputs)
}
```

#### 改动 2：更新测试（L444-770+）

需要更新的测试（witness 布局从 K+1 变为 1+K×46 padded）：

| 测试 | 旧断言 | 新断言 |
|------|--------|--------|
| `test_compile_trace_single_batch` | num_vars=8, num_rows=4, matrices=3 | K=5: num_vars=231→256, num_rows=183→256, matrices=42 |
| `test_witness_layout` | z[1]=idx_0, z[2]=idx_1 | z[1]=w_0[0]=idx_0, z[47]=w_1[0]=idx_1 |
| `test_padding_witness_zero_filled` | z[6..8]=0 | z[231..256]=0 (K=5) |
| `test_large_batch_default_size` | K=1024: num_vars=2048, num_rows=1024 | K=1024: num_vars=47105→65536, num_rows=37886→65536 |
| `test_single_step_batch_no_continuity_constraint` | K=1: num_vars=2, num_rows=1 | K=1: num_vars=47→64, num_rows=35→64 |
| `test_padding_power_of_two_invariant` | 不变（仅检查 2 的幂） | 不变 |

**保留不变**的测试（逻辑不依赖 witness 布局细节）：
- `test_compile_trace_empty_trace_errors`
- `test_compile_trace_zero_batch_size_errors`
- `test_compile_trace_multiple_batches`（public_inputs 格式不变）
- `test_compile_trace_default_batch_size`
- `test_compile_trace_exceeds_fold_step_count`
- `test_compile_trace_at_fold_step_limit`
- `test_batch_continuity_constraint_satisfied`
- `test_continuity_constraint_violated_by_gap`
- `test_batch_continuity_between_batches_violated`
- `test_public_inputs_contain_batch_metadata`
- `test_batch_with_memory_access_steps`
- `test_batch_id_monotonic`
- `test_compile_trace_returns_correct_instance_count`
- `test_phase5_integration_all_subcircuits_satisfied`（使用独立子电路）

**新增**测试：
- `test_step_witness_layout_46_vars`：验证 `compile_step_witness` 返回 46 个变量，布局正确
- `test_selector_one_hot`：验证每步恰好一个 selector = 1
- `test_selector_binary_all_zero_or_one`：验证所有 selector ∈ {0, 1}
- `test_pc_continuity_satisfied`：验证顺序执行时 `pc_{i+1} = next_pc_i`
- `test_pc_continuity_violated`：篡改 pc → CCS not satisfied
- `test_42_matrices_structure`：验证 num_matrices=42, num_subsets=42
- `test_group_d_selector_binary_violated`：selector=2 → `sel²-sel=4-2=2≠0` → CCS not satisfied

### 文件 2: [src/prover/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/mod.rs)

#### 改动 3：修复 `pad_trace`（L897-929）

**问题**：padding 步 pc=0，PC 连续性约束 `pc_{i+1} - next_pc_i = 0` 会失败（last real step 的 next_pc ≠ 0）。

**修复**：设置 padding 步的 `pc = prev_pc + 4`。

**理由**：
- padding 指令为 `Addi { rd:0, rs1:0, imm:0 }`，next_pc = pc + 4
- 真实程序末步通常为 ECALL（next_pc = pc + 4），故 first_padded_pc = last_real_pc + 4 = last_real_next_pc ✓
- 后续 padding 步：pc = prev_padded_pc + 4 = prev_next_pc ✓
- Addi 语义约束（Phase 2b）：rs1=0(x0), imm=0, rd=0(x0) → rd_val=0, rs1_val=0 → `0+0-0-0=0` ✓

```rust
fn pad_trace(trace: &mut Trace, batch_size: usize) -> Result<(), ZkvmError> {
    // ... (batch_size 检查不变)
    let mut next_index = if len == 0 { 0 } else { trace.step(len - 1)?.step_index + 1 };
    let mut next_pc = if len == 0 { 0 } else { trace.step(len - 1)?.pc.wrapping_add(4) };
    for _ in 0..pad_count {
        trace.push_step(Step {
            step_index: next_index,
            pc: next_pc,  // 原 pc: 0
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

---

## Phase 2b-2e 概述（后续实现）

### Phase 2b：算术指令约束（ADD/ADDI/SUB/SLT/SLTI/SLTU/SLTIU/LUI/AUIPC）

**矩阵扩展**：新增 34 个语义矩阵 `M_SEM_0..M_SEM_33`（每 category 一个），矩阵总数 42→76。每个语义矩阵在 Group E 行（语义约束行）有条目。

**约束模板**：`sel_C × semantic_C = 0`（degree-2，子集 {M_C_C, M_SEM_C}）

**关键约束**：
- LUI: `rd_val - imm = 0`
- ADDI/ADD: `rs1 + operand - rd_val - 2^32·carry = 0` + `carry² - carry = 0`
- SUB: `rs1 - rs2 - rd_val + 2^32·carry = 0` + `carry² - carry = 0`
- SLT/SLTI/SLTU/SLTIU: 比较约束（borrow-based）

### Phase 2c：逻辑 + 移位指令约束

**MVP 策略**：
- 逻辑指令（XOR/OR/AND 及 I 型）：域级约束 `rd_val = rs1 OP operand`（完整 soundness 需 LogUp，deferred）
- 移位指令：stub 约束 `rd_val = shift(rs1, shamt)`（executor 计算，bit decomposition 留待 Stage 3）

### Phase 2d：内存 + 分支 + 跳转 + 系统指令约束

**分支**：Degree-3 降阶 — 引入 `branch_cond = taken × (rs1 - rs2)`（degree-2）+ `sel × branch_cond = 0`（degree-2）
**跳转**：JAL/JALR 的 rd=pc+4 和 next_pc 约束
**内存**：MVP 地址约束 `addr = rs1 + imm`（LogUp 一致性留待 Phase 2e）
**系统**：FENCE/ECALL/EBREAK 无约束（MVP）

### Phase 2e：集成测试 + Soundness 验证

**新增文件**：[tests/instruction_semantics_tests.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/instruction_semantics_tests.rs)
- 40 正例 + 40 负例 + 5 溢出 + 12 分支 + 3 多步 trace + 5 soundness
- 扩展 [tests/soundness_tests.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/soundness_tests.rs)：篡改 trace → verify_production 拒绝

---

## 假设与决策

1. **42 矩阵设计**（非 43）：利用 CCS 子集 `Vec` 允许重复索引 `[40, 40]` 实现 `sel²`，省去一个矩阵
2. **pad_trace 用 Addi**（非 FENCE）：Addi 的语义约束在 Phase 2b 后自动满足（x0=0），且 selector one-hot 有效
3. **pad_trace pc = prev_pc + 4**：适用于程序以 ECALL/EBREAK/顺序指令结尾（实践中的所有情况）
4. **Phase 2a 无语义约束**：42 矩阵仅含连续性 + selector 有效性，语义约束在 Phase 2b-2d 扩展矩阵
5. **CCS 结构跨 batch 一致**：矩阵条目仅依赖 step 在 batch 内的位置 i（非全局 step_index），所有同 K 的 batch 共享相同 ccs_commitment
6. **public_inputs 格式不变**：`[batch_id, first_idx, last_idx]`，`verify_batch_continuity` 不需修改

## 验证步骤

### Phase 2a 完成后
```bash
# 1. 编译检查
cargo build -p poker_zkvm

# 2. clippy 检查（消除 unused 警告）
cargo clippy -p poker_zkvm --all-targets -- -D warnings

# 3. constraints 模块测试
cargo test -p poker_zkvm --lib constraints::mod::tests

# 4. 全量 lib 测试（验证无回归）
cargo test -p poker_zkvm --lib

# 5. soundness 测试（验证 #4 不受影响）
cargo test -p poker_zkvm --features test-helpers --test soundness_tests

# 6. E2E 测试（验证 prove/verify 端到端）
cargo test -p poker_zkvm --features test-helpers --test e2e_fibonacci
cargo test -p poker_zkvm --features test-helpers --test e2e_sha256_chain
cargo test -p poker_zkvm --features test-helpers --test e2e_poker_hand_eval

# 7. 基准测试编译
cargo bench -p poker_zkvm --no-run
```

**通过标准**：
- 全部测试通过（预计 777+ 测试）
- clippy 无 warning
- E2E 测试 prove → verify 闭环成功
- 基准测试编译成功
- CCS 结构：42 矩阵、42 子集、num_vars/num_rows 为 2 的幂
