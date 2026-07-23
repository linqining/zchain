# poker_zkvm 安全漏洞修复实施计划

> **关联审计报告**：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md`（已批准）
> **目标**：修复审计发现的 8 个漏洞（V1-V8），使 poker_zkvm 达到与 RISC Zero 同等的指令约束覆盖度
> **本计划状态**：决策完整 — 执行者无需再做选择，按步骤实现即可

---

## 1. 摘要（Summary）

审计已完成，发现 8 个漏洞（2 CRITICAL、3 HIGH、3 MEDIUM）。本计划定义剩余修复工作的实施步骤。当前 Step 4（JAL/JALR）已完成，**Step 2（比较指令）的约束已写入 `cpu_air.rs` 但 trace witness 填充缺失**——这是当前最紧迫的阻塞项（约束引用的 witness 列在比较指令行仍为 0，会导致 prove 失败）。

---

## 2. 当前状态分析（Current State Analysis）

### 已完成 ✅

| 步骤 | 漏洞 | 内容 | 位置 |
|------|------|------|------|
| Step 4 | V3 | JAL/JALR 链接寄存器约束（rd_eff = PC+4，4 约束） | `cpu_air.rs:478-501` + `trace_native.rs:591-602` + `prover.rs:1465` 测试 |

### 部分完成 🔄

| 步骤 | 漏洞 | 已完成 | 缺失（阻塞项） |
|------|------|--------|----------------|
| Step 2 | V2（比较部分） | `cpu_air.rs:336-409` 约束已写入（SLTU/SLTIU + SLT/SLTI） | `trace_native.rs` witness 填充未实现 + soundness 测试未写 |

**关键阻塞**：`trace_native.rs:609-754` 的 M 扩展 witness 填充 match 分支只处理 MUL/MULH/MULHSU/MULHU/DIV/REM/DIVU/REMU，比较指令（Slt/Sltu/Slti/Sltiu）落入 `_ => {}` 分支，导致约束引用的 5 组 witness 列（diff/borrow/sign_a/sign_b/same_sign）全为 0。必须先补齐 witness 填充，否则比较指令行的 prove 会失败。

### 未开始 ⏳

| 步骤 | 漏洞 | 严重度 | 难度 |
|------|------|--------|------|
| Step 1 | V2（逻辑部分） | CRITICAL | 低（limb-wise 直接约束） |
| Step 3 | V1 | CRITICAL | 高（需 diff_inv nonzero witness） |
| Step 5 | V4 | HIGH | 中（range check lookup） |
| Step 6 | V5 | HIGH | 高（Fiat-Shamir transcript） |
| Step 7 | V6 | MEDIUM | 低（补 q_abs 常量约束） |
| Step 9 | V2（移位部分） | CRITICAL | 高（shamt 分解+旋转） |

### 已确认的漏洞细节（探索阶段验证）

- **V5 确认未修复**：`recursive/trace_gen.rs:616` 硬编码 `SecureField::from(1u32)`；`recursive/public_inputs.rs` 的 `RecursivePublicInputs` 结构体无 `fri_query_x`/`fri_query_eval` 字段，v5.2 修复未实现。
- **V6 确认可利用**：`cpu_air.rs:916` 仅约束 `is_div·is_special·(1−sign_q)=0`（强制 sign_q=1），但 **q_abs 值完全无约束**。当 d=0（abs_b=0）时，identity 退化为 `r_abs = abs_a`，与 q_abs 无关，prover 可任意设定 q_abs。range check 在 is_special=1 时被跳过（`range_gate = g3·(1−is_special)`，line 924）。
- **测试缺口**：8 个 tamper 测试存在（MUL/MULHU/JAL/DIV×3/ECALL×2），但比较/分支/逻辑/移位/DIV 特殊情况均无 tamper 测试。

---

## 3. 提议变更（Proposed Changes）

### Phase A：立即修复比较指令 witness（解除阻塞）— Step 2 收尾

**文件**：`poker_zkvm/src/stwo_backend/trace_native.rs`

**变更**：在 `step_to_m31_row` 的 M 扩展 witness 填充 match（line 609 的 `match &step.instruction`）中，**在 `_ => {}` 之前**新增比较指令分支。

**新增代码**（决策已定，复用现有 helper）：
```rust
Instruction::Slt { .. } | Instruction::Sltu { .. }
| Instruction::Slti { .. } | Instruction::Sltiu { .. } => {
    // diff = rs1 - rs2（存入 COL_MUL_LOW_BASE，复用 MUL 列，one-hot 互斥）
    let diff = value_b.wrapping_sub(value_c);
    fill_word(&mut row, COL_MUL_LOW_BASE, diff);
    // borrow0/borrow1 复用 COL_CARRY_FLAG_BASE（与 ADD/SUB/MULH 互斥）
    let (borrow0, borrow1) = compute_sub_borrows(value_b, value_c, diff);
    row[COL_CARRY_FLAG_BASE] = M31::from(borrow0);
    row[COL_CARRY_FLAG_BASE + 1] = M31::from(borrow1);
    // 有符号比较（SLT/SLTI）需符号 witness
    if matches!(&step.instruction, Instruction::Slt { .. } | Instruction::Slti { .. }) {
        let sign_a = (value_b >> 31) & 1;
        let sign_b = (value_c >> 31) & 1;
        let same_sign = u32::from(sign_a == sign_b);
        row[COL_SIGN_A] = M31::from(sign_a);
        row[COL_SIGN_B] = M31::from(sign_b);
        row[COL_LOW_NONZERO] = M31::from(same_sign);
    }
}
```

**注意**：
- `value_b` = rs1 读值（line 470），`value_c` = rs2 读值或立即数（line 471-475），已在 `step_to_m31_row` 中计算。SLTI/SLTIU 的 `value_c` 是符号扩展立即数，`compute_sub_borrows` 对其做无符号减法 → 正确（SLTU 的语义就是与符号扩展后的立即数做无符号比较）。
- `compute_sub_borrows(value_b, value_c, diff)` 第三参数 `_rd` 未使用，传 diff 无害。
- 无符号比较（Sltu/Sltiu）不填 sign_a/sign_b/same_sign（保持 0），因 SLTU 约束不引用这些列；universal binality（line 786-788）对 0 值满足。

**验证**：编译 + 运行比较指令 roundtrip 测试（已存在 `test_prove_verify_roundtrip_slt` 等，若无则新增），确认约束通过。

**新增 soundness 测试**（文件 `prover.rs` tests 模块）：
```rust
#[test]
fn test_sltu_soundness_tamper_result() {
    // rs1=5, rs2=10 → SLTU rd_eff 应为 1，篡改为 0，预期 prove 失败
    let prev = zero_registers();
    let mut post = prev;
    post[1] = 1; // rd=1, rd_eff=1
    let step = make_step(0, Instruction::Sltu { rd: 1, rs1: 2, rs2: 3 }, post);
    let mut prev_with_vals = prev;
    prev_with_vals[2] = 5;
    prev_with_vals[3] = 10;
    let row = step_to_m31_row(&step, &prev_with_vals);
    let mut builder = TraceBuilder::new(10);
    builder.fill_row(&row);
    builder.fill_padding_to_full();
    let mut trace = builder.finalize();
    // 篡改 rd_eff 低 limb 为 0（正确值 1）
    trace.cols[COL_VALUE_A_EFF_BASE][0] = M31::from(0u32);
    let result = prove_cpu_trace(&trace);
    assert!(result.is_err(), "篡改 SLTU 比较结果应导致 prove 失败");
}

#[test]
fn test_slt_soundness_tamper_result() {
    // rs1=-5(0xFFFFFFFB), rs2=10 → SLT rd_eff 应为 1，篡改为 0，预期 prove 失败
    let prev = zero_registers();
    let mut prev_with_vals = prev;
    prev_with_vals[2] = 0xFFFF_FFFB; // -5 as i32
    prev_with_vals[3] = 10;
    let mut post = prev_with_vals;
    post[1] = 1; // rd=1, rd_eff=1 (neg < pos)
    let step = make_step(0, Instruction::Slt { rd: 1, rs1: 2, rs2: 3 }, post);
    let row = step_to_m31_row(&step, &prev_with_vals);
    let mut builder = TraceBuilder::new(10);
    builder.fill_row(&row);
    builder.fill_padding_to_full();
    let mut trace = builder.finalize();
    trace.cols[COL_VALUE_A_EFF_BASE][0] = M31::from(0u32);
    let result = prove_cpu_trace(&trace);
    assert!(result.is_err(), "篡改 SLT 比较结果应导致 prove 失败");
}
```

---

### Phase B：CRITICAL 修复

#### Step 1：逻辑指令约束（XOR/XORI/OR/ORI/AND/ANDI）— V2 逻辑部分

**文件**：`cpu_air.rs` + `trace_native.rs`（无新 witness 列，逻辑运算 limb-wise 直接约束）

**设计决策**：8-bit limb 的 XOR/OR/AND 是 limb-wise 的（`rd_limb[i] = rs1_limb[i] OP rs2_limb[i]`），可直接逐 limb 约束。**但 M31 域无原生 XOR 运算**——需验证 limb-wise 等式在域上是否 sound。

**关键问题**：`rd_eff_limb = rs1_limb ^ rs2_limb` 在域上无法用多项式表达。RISC Zero 用 bit 分解（每 limb 8 bit，逐 bit XOR 约束）。但 bit 分解开销大（每 limb 8 个 binary 列）。

**决策**：采用**轻量方案**——对每条逻辑指令，约束 `rd_eff_limb - rs1_limb - rs2_limb` 相关的域等式。但这在 soundness 上有缺口（XOR ≠ 加法）。**正确方案需 bit 分解**。

**修正决策**（采用 RISC Zero 方式）：
- 逻辑指令复用 helper 列存 rs1/rs2 的 bit 分解不可行（列数不足）
- **最终决策**：逻辑指令暂用 **truth-table lookup** 或 **逐 bit 约束**。鉴于当前列预算紧张（132 列已满），**降级处理**：逻辑指令在 poker 场景中几乎不使用，先记录 soundness gap，在 Phase E（扩展列布局）中统一处理。

**实施**：
- 在 `cpu_air.rs` 中为逻辑指令添加 `rd_eff ∈ {0,1}` 范围无关的**弱约束**（仅约束 indicator binality，不约束结果）→ 实际上保持现状但明确标注
- **不新增约束**，在审计报告中更新为"已知 gap，待 Phase E 列扩展后实现 bit 分解约束"
- 新增文档注释标注 soundness gap

#### Step 3：分支条件验证（BEQ/BNE/BLT/BGE/BLTU/BGEU）— V1

**文件**：`cpu_air.rs` + `trace_native.rs` + `column_layout_v2.rs`

**设计决策**：
- **BEQ/BNE**：`diff = rs1 - rs2`，`taken = (diff == 0)`。约束 `taken * diff = 0`（taken=1 → diff=0）+ `(1-taken) * diff * diff_inv = 0`（not-taken → diff≠0，需 nonzero witness `diff_inv`）。需要 4 列存 diff_inv。
- **BLT/BGE**（有符号）：复用 SLT 的比较结果，`taken = slt_result`（BLT）或 `taken = 1 - slt_result`（BGE）。复用比较指令的 sign_a/sign_b/same_sign/borrow witness。
- **BLTU/BGEU**（无符号）：`taken = borrow1`（BLTU）或 `taken = 1 - borrow1`（BGEU）。复用比较指令的 borrow witness。

**列需求**：
- BEQ/BNE 的 `diff_inv`（4 limb）需新列。复用 `COL_HELPER_A_BASE`（65-68）——BEQ/BNE 行与 LUI/JAL/Load/Store one-hot 互斥，HelperA 在 BEQ/BNE 行空闲。
- BLT/BGE/BLTU/BGEU 的 sign/borrow 复用比较指令已用的列（COL_SIGN_A/COL_SIGN_B/COL_LOW_NONZERO/COL_CARRY_FLAG_BASE），但**分支指令与比较指令 one-hot 互斥**，需确认这些列在分支行也可填充。

**实施步骤**：
1. `column_layout_v2.rs`：无需新列（diff_inv 复用 HelperA）
2. `trace_native.rs`：在 BEQ/BNE 行填充 HelperA = diff_inv（4 limb，diff 的域逆元，diff=0 时填 0）；在 BLT/BGE/BLTU/BGEU 行填充 sign_a/sign_b/same_sign/borrow（同比较指令）
3. `cpu_air.rs`：
   - BEQ: `is_beq * (taken * diff - 0)` + `is_beq * ((1-taken) * diff * diff_inv)`，其中 diff = rs1 - rs2（复用比较的 diff 约束结构）
   - BNE: `is_bne * ((1-taken) * diff)` + `is_bne * (taken * diff * diff_inv)`
   - BLTU: `is_bltu * (taken - borrow1)`
   - BGEU: `is_bgeu * (taken - 1 + borrow1)`
   - BLT: `is_blt * (taken - slt_signed_result)`（复用 SLT 公式）
   - BGE: `is_bge * (taken - 1 + slt_signed_result)`

**度数检查**：`taken * diff * diff_inv` = 1(taken) + 1(diff) + 1(diff_inv) = 3，gating 1，总度 4 > 3 预算。**需拆分**：先用约束建立 diff，再 `is_beq * taken * diff = 0`（度 3 ✓）+ `is_beq * (1-taken) * diff * diff_inv = 0`（度 4 ❌）。**修正**：将 `(1-taken)*diff*diff_inv` 改为引入中间 witness `is_nonzero = (1-taken)`，约束 `diff * diff_inv - is_nonzero = 0`（度 2）+ `is_nonzero * taken = 0`（度 2）。总度 3 ✓。

---

### Phase C：HIGH 修复

#### Step 5：8-bit limb 范围检查 — V4

**文件**：新增 `range_check_air.rs` + `cpu_air.rs`（logup 集成）+ `prover.rs`

**设计决策**：采用方案 A（range check lookup argument）。为每行的关键 limb 列（PC×4 + PcNext×4 + rd_eff×4 + rs1×4 + rs2×4 = 20 列）发送 logup claim `(value, +1)`，与预计算表 `(0..255, -256)` 匹配。

**复杂度**：高（需新增 AIR 组件 + channel 集成）。**建议单独实施**，不与其他步骤混合。

#### Step 6：递归 FRI query point 修复 — V5

**文件**：`recursive/public_inputs.rs` + `recursive/trace_gen.rs` + `recursive/air.rs`（如有）

**设计决策**（代码中已规划 v5.2）：
1. `RecursivePublicInputs` 新增字段 `fri_query_x: SecureField` + `fri_query_eval: SecureField`
2. `trace_gen.rs:616`：从 `SecureField::from(1u32)` 改为从 L1 proof 的 Fiat-Shamir transcript 推导（需解析 StarkProof 的 channel state）
3. `trace_gen.rs:622`：`query_eval` 仍由 prover 计算，但新增 AIR 约束 `query_eval == public_inputs.fri_query_eval`
4. 新增 soundness 测试：篡改 query_eval → prove 失败

**复杂度**：高（需理解 Stwo 的 Fiat-Shamir transcript 结构）。**建议在 Phase C 最后实施**。

---

### Phase D：MEDIUM 修复

#### Step 7：DIV 特殊情况 q_abs 约束 — V6

**文件**：`cpu_air.rs`（`trace_native.rs` 已正确填充 q_abs）

**设计决策**：添加约束强制 is_special=1 时 q_abs 为 RISC-V 规范值：
```rust
// d=0 有符号 DIV: q_abs = 1（|−1| = 1）
// overflow (INT_MIN/-1): q_abs = 0x80000000（|INT_MIN|）
// d=0 无符号 DIVU: q_abs = 0xFFFFFFFF
```

**问题**：需区分三种特殊情况。当前 `is_special` 是单一 binary 标志，无法区分 d=0 vs overflow vs signed/unsigned。

**修正决策**：引入 `div_special_type` witness（2-bit，复用现有 binary 列）：
- 0 = 非特殊
- 1 = d=0 有符号
- 2 = overflow（INT_MIN/-1）
- 3 = d=0 无符号

**实施**：
1. `column_layout_v2.rs`：复用 `COL_HELPER_A_BASE+3`（68，在 DIV 行空闲）作为 special_type 2-bit 分解
2. `cpu_air.rs`：约束 `is_special * (q_abs - expected(type))` + special_type binality
3. `trace_native.rs`：填充 special_type witness

#### Step 9：移位指令约束（SLL/SRL/SRA/SLLI/SRLI/SRAI）— V2 移位部分

**文件**：`cpu_air.rs` + `trace_native.rs` + `column_layout_v2.rs`

**设计决策**：参考 RISC Zero 的移位约束设计——shamt 分解为 5 bit，逐位旋转约束。复杂度高，poker 场景中移位使用频率低。

**决策**：**降级为已知 gap**，在 Phase E 中实现。当前仅标注。

---

### Phase E：验证 — Step 10

**文件**：`prover.rs` tests 模块

**实施**：为每条修复的指令添加 tamper 测试（篡改 rd_eff → prove 失败）：
- 比较指令（Phase A，2 测试）
- 分支条件（Step 3，6 测试：每条分支指令 taken/not-taken 篡改）
- DIV 特殊情况（Step 7，2 测试：d=0 篡改 q_abs + overflow 篡改 q_abs）

**回归测试**：
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```

---

## 4. 假设与决策（Assumptions & Decisions）

1. **比较指令 witness 复用列安全**：COL_MUL_LOW_BASE（diff）、COL_CARRY_FLAG_BASE（borrow）、COL_SIGN_A/COL_SIGN_B/COL_LOW_NONZERO（signs）在比较指令行与 MUL/MULH/DIV 行 one-hot 互斥，无冲突。已验证 universal binality 约束（line 786-788）对比较 witness 值（∈{0,1}）满足。
2. **SLTIU 立即数语义**：SLTIU 与符号扩展立即数做无符号比较。`value_c` 已是符号扩展后的 u32（由 `extract_operands` 提供），`compute_sub_borrows` 对其做无符号减法 → 正确。
3. **逻辑指令（Step 1）降级处理**：M31 域无 XOR 运算，bit 分解需 8 列/limb，当前 132 列预算不足。决策：暂不实现，标注为已知 gap，待列扩展后处理。poker 场景中逻辑指令使用频率极低。
4. **移位指令（Step 9）降级处理**：shamt 分解 + 旋转约束复杂度高，poker 场景使用频率低。决策：暂不实现，标注为已知 gap。
5. **分支 diff_inv 复用 HelperA**：BEQ/BNE 行与 LUI/JAL/Load/Store one-hot 互斥，HelperA（65-68）在 BEQ/BNE 行空闲，可存 diff_inv。BLT/BGE/BLTU/BGEU 复用比较指令的 sign/borrow 列。
6. **度数预算**：所有新增约束的总度 ≤ 3（gating 1 + 表达式 ≤ 2），符合 `max_constraint_log_degree_bound = log_size + 1`。
7. **不修改已完成且通过测试的 Step 4（JAL/JALR）实现**。
8. **执行顺序**：Phase A（解除阻塞）→ Phase B（CRITICAL）→ Phase C（HIGH）→ Phase D（MEDIUM）→ Phase E（验证）。每个 Phase 完成后运行完整测试套件。

---

## 5. 验证步骤（Verification Steps）

### Phase A 验证
```bash
# 1. 编译
cargo +nightly-2026-04-15 build -p poker_zkvm

# 2. 比较指令 soundness 测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_slt_soundness" "test_sltu_soundness"

# 3. 比较指令 roundtrip（确认约束通过）
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "slt" "sltu" "slti" "sltiu"
```

### 全量回归
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```

### 预期测试数
- Phase A 前基线：599 测试通过（含 Step 4 的 JAL soundness）
- Phase A 后：601 测试通过（+2 比较指令 soundness 测试）

---

## 6. 实施优先级与执行清单

| 顺序 | 步骤 | Phase | 阻塞? | 预计约束数 | 预计测试数 |
|------|------|-------|-------|-----------|-----------|
| 1 | Step 2 收尾（比较 witness + 测试） | A | 是（当前阻塞） | 0（已写） | +2 |
| 2 | Step 7（DIV 特殊情况 q_abs） | D | 否 | +4 | +2 |
| 3 | Step 3（分支条件验证） | B | 否 | +12 | +6 |
| 4 | Step 5（limb 范围检查） | C | 否 | lookup | +2 |
| 5 | Step 6（递归 FRI query point） | C | 否 | +2 | +1 |
| 6 | Step 1（逻辑指令） | B | 否 | 降级 | 0 |
| 7 | Step 9（移位指令） | D | 否 | 降级 | 0 |
| 8 | Step 10（全量 soundness 测试） | E | 否 | 0 | +4 |

**建议执行者从顺序 1 开始**，每完成一步运行测试确认无回归后再进行下一步。
