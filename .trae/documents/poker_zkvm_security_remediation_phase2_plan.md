# poker_zkvm 安全漏洞修复实施计划（Phase 2 — 剩余步骤）

> **关联文档**：
> - 审计报告：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md`
> - Phase 1 计划：`.trae/documents/poker_zkvm_security_remediation_plan.md`（已完成 Phase A + 部分 Step 7）
> **本计划状态**：决策完整 — 执行者无需再做选择，按步骤实现即可
> **用户决策**：覆盖全部剩余步骤（验证 V6 + Step 3 分支 + Step 5 范围检查 + Step 6 递归 FRI + Step 10 测试）；逻辑/移位指令保持降级为已知 gap

---

## 1. 摘要（Summary）

审计发现 8 个漏洞（2 CRITICAL、3 HIGH、3 MEDIUM）。Phase 1 已完成 Phase A（比较指令 witness + 约束 + 9 测试，609 测试通过）并写入 Step 7（V6 DIV 特殊情况 q_abs 约束 + 2 soundness 测试），**但 Step 7 尚未编译验证**。本计划定义剩余全部修复工作：先验证 Step 7，再实现 V1（分支条件 CRITICAL）、V4（范围检查 HIGH）、V5（递归 FRI HIGH），最后补齐全量 soundness 测试。

---

## 2. 当前状态分析（Current State Analysis）

### 已完成 ✅（已验证，代码在位）

| 内容 | 位置 | 状态 |
|------|------|------|
| 比较指令约束（SLTU/SLTIU + SLT/SLTI） | `cpu_air.rs:336-409` | ✅ 已写入 |
| 比较指令 witness 填充 | `trace_native.rs:753-780` | ✅ 已写入 |
| 比较指令 soundness 测试（3 个） | `prover.rs:1558-1634` | ✅ 已写入，609 测试通过 |
| JAL/JALR 链接寄存器约束 | `cpu_air.rs:478-501` | ✅ 已写入 |
| JAL/JALR PC carry witness | `trace_native.rs:591-602` | ✅ 已写入 |

### 已写入但未验证 🔄（Step 7 — 本计划首要任务）

| 内容 | 位置 | 状态 |
|------|------|------|
| V6 DIV 特殊情况 q_abs 约束（7 条） | `cpu_air.rs:918-963` | ⚠️ 已写入，未编译/未运行 |
| V6 DIV/DIVU d=0 soundness 测试（2 个） | `prover.rs:1695-1747` | ⚠️ 已写入，未编译/未运行 |
| `COL_DIV_QUOT_BASE` import | `prover.rs:929-930`（test 模块内） | ⚠️ 诊断告警 unused，需编译验证 |

**git status**：3 文件已修改未提交（`cpu_air.rs`、`prover.rs`、`trace_native.rs`）。

### 未开始 ⏳

| 步骤 | 漏洞 | 严重度 | 文件 |
|------|------|--------|------|
| Step 3 | V1 分支条件未验证（BEQ/BNE/BLT/BGE/BLTU/BGEU） | CRITICAL | `cpu_air.rs` + `trace_native.rs` |
| Step 5 | V4 缺少 8-bit limb 范围检查 | HIGH | 新建 `range_check_air.rs` + `cpu_air.rs` + `prover.rs` |
| Step 6 | V5 递归 FRI query point 硬编码为 1 | HIGH | `recursive/public_inputs.rs` + `recursive/trace_gen.rs` |
| Step 10 | 全量 soundness 测试补齐 + 回归 | — | `prover.rs` |

### 已确认的关键事实（Phase 1 探索验证）

1. **分支当前状态**：`cpu_air.rs:428-460` 的 PC 约束（约束 16-19）处理 PcNext，但分支的 `Taken` 标志**仅做 binality 约束**（约束 15，`Taken*(Taken-1)=0`），**未验证 Taken 与 rs1/rs2 比较结果一致**。恶意 prover 可任意设 Taken=1 让分支跳转，即使条件不满足 → V1 CRITICAL。
2. **V5 确认**：`recursive/trace_gen.rs:616` 硬编码 `query_x_qm31 = SecureField::from(1u32)`；`recursive/public_inputs.rs:20-56` 的 `RecursivePublicInputs` 结构体有 9 字段但**无 `fri_query_x`/`fri_query_eval`**。query_eval 在 `trace_gen.rs:622` 由 prover 计算但未受公开输入约束。
3. **列布局（132 列全满）**：`column_layout_v2.rs` 定义 132 列。关键复用机会（one-hot 互斥保证）：
   - `COL_HELPER_B_BASE`(69-72)：仅 Load/Store 使用 → **分支行空闲**，可存 diff_inv
   - `COL_MUL_LOW_BASE`(128-131)：仅 MUL/DIV/比较使用 → **分支行空闲**，可存 diff
   - `COL_CARRY_FLAG_BASE`(8-9)、`COL_SIGN_A`(114)、`COL_SIGN_B`(115)、`COL_LOW_NONZERO`(116)：ADD/SUB/MULH/比较使用 → **分支行空闲**
4. **度数预算**：`max_constraint_log_degree_bound = log_size + 1`（度 ≤ 3）。约束形式为 `indicator × expression`，故 expression 度 ≤ 2。
5. **lookup 基础设施**：`lookups.rs` 用 `relation!` 宏定义 N 元 lookup relation（MemoryLookup=9 元组、EcallLookup=1 元组）。`prover.rs:314-340` 的 `gen_cpu_interaction_trace` 展示了 logup trace 生成模式。

---

## 3. 提议变更（Proposed Changes）

### Phase 1：验证 Step 7（V6 DIV）— 解除未验证状态

**文件**：无代码变更（仅编译 + 运行测试）

**步骤**：
1. 编译：`cargo +nightly-2026-04-15 build -p poker_zkvm`
2. 运行 V6 soundness 测试：`cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "div_soundness_tamper_q_abs" "divu_soundness_tamper_q_abs"`
3. 全量回归：`cargo +nightly-2026-04-15 test -p poker_zkvm --lib`

**预期**：611 测试通过（609 基线 + 2 新 V6 测试），0 失败，0 回归。

**若 unused import 告警**：`prover.rs:929` 的 `COL_DIV_QUOT_BASE` import 在测试 `prover.rs:1713,1740` 中使用，编译后告警应消失。若仍告警，检查测试是否被正确编译。

**若 V6 测试失败**：分析失败原因。可能问题：
- `gate_d0 = is_special * (1 - abs_b_limb0)` 在 overflow（abs_b=1）时 gate=0，d=0（abs_b=0）时 gate=1 — 需确认 `compute_div_witness` 在 d=0 时填 abs_b=0
- `q_abs_limb0_expected = sign_q + 255*(1-sign_q)`：有符号 sign_q=1 → 1，无符号 sign_q=0 → 255 — 需确认 DIVU d=0 时 sign_q=0

---

### Phase 2：Step 3 — 分支条件验证（V1 CRITICAL）

**文件**：`cpu_air.rs` + `trace_native.rs`

**设计**（无新列，全部复用 one-hot 互斥的空闲列）：

#### 3.1 列复用方案（已验证 one-hot 互斥）

| witness | 列 | 分支行是否空闲 | 原使用者（互斥） |
|---------|-----|----------------|------------------|
| diff (4 limb) | `COL_MUL_LOW_BASE`(128-131) | ✅ 空闲 | MUL/DIV/SLT |
| borrow0, borrow1 | `COL_CARRY_FLAG_BASE`(8-9) | ✅ 空闲 | ADD/SUB/MULH/SLT |
| diff_inv (1 列) | `COL_HELPER_B_BASE`(69) | ✅ 空闲 | Load/Store |
| sign_a, sign_b | `COL_SIGN_A`(114), `COL_SIGN_B`(115) | ✅ 空闲 | MULH/SLT |
| same_sign | `COL_LOW_NONZERO`(116) | ✅ 空闲 | MULH/SLT |

**注意**：`COL_HELPER_A_BASE`(65-68) 在分支行**不空闲**（存分支目标 Pc+imm，见 `cpu_air.rs:466`），故 diff_inv 用 HelperB 而非 HelperA。diff_inv 是域逆元（单个 M31 列，非 4 limb）。

#### 3.2 约束设计（cpu_air.rs，在比较约束之后约 L410 插入）

**通用分支 diff 约束**（gated by `is_branch`，6 个分支共享）：
```rust
// diff = rs1 - rs2，存 COL_MUL_LOW_BASE，复用 SUB 结构
// low16: diff_low - rs1_low + rs2_low - 65536*borrow0 = 0
let br_diff_low = diff_low16 - rs1_low.clone() + rs2_low.clone()
    - six5536.clone() * carry0.clone();
eval.add_constraint(is_branch.clone() * br_diff_low);  // 度 2+1=3 ✓
// high16: diff_high - rs1_high + rs2_high + borrow0 - 65536*borrow1 = 0
let br_diff_high = diff_high16 - rs1_high.clone() + rs2_high.clone()
    + carry0.clone() - six5536.clone() * carry1.clone();
eval.add_constraint(is_branch.clone() * br_diff_high);  // 度 3 ✓
// borrow0/borrow1 binality（gated by is_branch）
eval.add_constraint(is_branch.clone() * carry0.clone() * (carry0.clone() - one.clone()));  // 度 3 ✓
eval.add_constraint(is_branch.clone() * carry1.clone() * (carry1.clone() - one.clone()));  // 度 3 ✓
```
其中 `diff_low16 = word_low16(COL_MUL_LOW_BASE)`，`diff_high16 = word_high16(COL_MUL_LOW_BASE)`，`diff_value = diff_low16 + 65536 * diff_high16`。

**BEQ 约束**（taken ⟺ diff==0）：
```rust
let diff_inv = col(COL_HELPER_B_BASE);  // 单列域逆元
// taken=1 → diff_value=0（度 3）
eval.add_constraint(is_beq.clone() * taken.clone() * diff_value.clone());
// diff * diff_inv = (1 - taken)（度 1+2=3 ✓）
eval.add_constraint(is_beq.clone() * (diff_value.clone() * diff_inv.clone() - (one.clone() - taken.clone())));
```

**BNE 约束**（taken ⟺ diff≠0）：
```rust
// not-taken → diff=0（度 3）
eval.add_constraint(is_bne.clone() * (one.clone() - taken.clone()) * diff_value.clone());
// diff * diff_inv = taken（度 3）
eval.add_constraint(is_bne.clone() * (diff_value.clone() * diff_inv.clone() - taken.clone()));
```

**BLTU/BGEU 约束**（无符号，taken = borrow1 / 1-borrow1）：
```rust
eval.add_constraint(is_bltu.clone() * (taken.clone() - carry1.clone()));         // 度 2 ✓
eval.add_constraint(is_bgeu.clone() * (taken.clone() - one.clone() + carry1.clone()));  // 度 2 ✓
```

**BLT/BGE 约束**（有符号，复用 SLT 公式）：
```rust
// same_sign 验证（witness 在 COL_LOW_NONZERO，度 3）
let same_sign = col(COL_LOW_NONZERO);
let sign_a_br = col(COL_SIGN_A);
let sign_b_br = col(COL_SIGN_B);
let is_signed_branch = is_blt.clone() + is_bge.clone();
eval.add_constraint(is_signed_branch.clone()
    * (same_sign.clone() - one.clone() + sign_a_br.clone() + sign_b_br.clone()
       - two.clone() * sign_a_br.clone() * sign_b_br.clone()));  // 度 3 ✓
// slt_result = sign_a*(1-sign_b) + same_sign*borrow1（度 2）
let slt_result = sign_a_br.clone() * (one.clone() - sign_b_br.clone())
    + same_sign.clone() * carry1.clone();
// BLT: taken = slt_result（度 3）
eval.add_constraint(is_blt.clone() * (taken.clone() - slt_result.clone()));
// BGE: taken = 1 - slt_result（度 3）
eval.add_constraint(is_bge.clone() * (taken.clone() - one.clone() + slt_result.clone()));
```

**约束总数**：~13 条，全部度 ≤ 3 ✓。

#### 3.3 witness 填充（trace_native.rs，在比较指令分支之前插入）

```rust
Instruction::Beq { .. } | Instruction::Bne { .. }
| Instruction::Blt { .. } | Instruction::Bge { .. }
| Instruction::Bltu { .. } | Instruction::Bgeu { .. } => {
    // diff = rs1 - rs2（存 COL_MUL_LOW_BASE，分支行与 MUL/DIV/SLT 互斥）
    let diff = value_b.wrapping_sub(value_c);
    fill_word(&mut row, COL_MUL_LOW_BASE, diff);
    let (borrow0, borrow1) = compute_sub_borrows(value_b, value_c, diff);
    row[COL_CARRY_FLAG_BASE] = M31::from(borrow0);
    row[COL_CARRY_FLAG_BASE + 1] = M31::from(borrow1);
    // BEQ/BNE 需 diff_inv（域逆元，存 HelperB[0]，分支行与 Load/Store 互斥）
    if matches!(&step.instruction, Instruction::Beq { .. } | Instruction::Bne { .. }) {
        let diff_inv = if diff == 0 { 0u32 } else {
            // M31 域逆元：diff^(p-2) mod p，p = 2^31 - 1
            m31_inverse(diff)
        };
        row[COL_HELPER_B_BASE] = M31::from(diff_inv);
    }
    // BLT/BGE 需符号 witness（BLTU/BGEU 不填，保持 0）
    if matches!(&step.instruction, Instruction::Blt { .. } | Instruction::Bge { .. }) {
        let sign_a = (value_b >> 31) & 1;
        let sign_b = (value_c >> 31) & 1;
        let same_sign = u32::from(sign_a == sign_b);
        row[COL_SIGN_A] = M31::from(sign_a);
        row[COL_SIGN_B] = M31::from(sign_b);
        row[COL_LOW_NONZERO] = M31::from(same_sign);
    }
}
```

**新增 helper**：`m31_inverse(x: u32) -> u32` — 计算 x 在 M31 域（p=2^31-1）的逆元，用快速幂 `x^(p-2) mod p`。放在 `trace_native.rs` helper 区。

#### 3.4 soundness 测试（prover.rs，6 个）

| 测试名 | 场景 | 篡改 | 预期 |
|--------|------|------|------|
| `test_beq_soundness_tamper_taken_false` | BEQ rs1==rs2, taken=0（应 taken=1） | 篡改 Taken=0 | prove 失败 |
| `test_bne_soundness_tamper_taken_true` | BNE rs1==rs2, taken=1（应 taken=0） | 篡改 Taken=1 | prove 失败 |
| `test_bltu_soundness_tamper_taken` | BLTU rs1>rs2, taken=1（应 taken=0） | 篡改 Taken=1 | prove 失败 |
| `test_bgeu_soundness_tamper_taken` | BGEU rs1<rs2, taken=1（应 taken=0） | 篡改 Taken=1 | prove 失败 |
| `test_blt_soundness_tamper_taken` | BLT rs1>rs2 正数, taken=1（应 taken=0） | 篡改 Taken=1 | prove 失败 |
| `test_bge_soundness_tamper_taken` | BGE rs1<rs2 正数, taken=1（应 taken=0） | 篡改 Taken=1 | prove 失败 |

---

### Phase 3：Step 5 — 8-bit limb 范围检查（V4 HIGH）

**文件**：新建 `range_check_air.rs` + `cpu_air.rs`（logup claim）+ `prover.rs`（多组件集成）+ `lookups.rs`（新 relation）

**设计**（logup lookup argument，复用现有 MemoryLookup 模式）：

#### 5.1 新 relation（lookups.rs）

```rust
/// RangeCheck lookup（1 元组：limb 值）
/// CPU 发送 claim (limb_value, +1)，RangeCheckAir 发送 yield (v, -multiplicity_v)
relation!(RangeCheckLookup, 1);
```

#### 5.2 新 AIR（range_check_air.rs）

`RangeCheckAir` — 256 行（log_size=8），每行 v ∈ [0, 255]：
- 列 0：value（= 行索引 v，prover 填充但约束为常量行索引）
- 列 1：multiplicity（prover 填充，= 该值在 CPU limb 中出现的次数）
- 发送 yield：(v, -multiplicity)

**关键约束**：value 列必须等于行索引（用 Stwo 的 `is_first`/row index 机制，或预计算表）。简化方案：value 由 prover 填充，约束 `value[row] = row`（通过递增约束 `value[row+1] = value[row] + 1`，首行 `value[0] = 0`）。

#### 5.3 CPU AIR claim（cpu_air.rs）

在 `evaluate` 中，对每行的关键 limb 列发送 range check claim（gated by `1 - is_padding`，即所有非 padding 行）：
- 候选 limb 列：PC(0-3) + PcNext(4-7) + ValueAEff(10-13) + ValueB(14-17) + ValueC(18-21) = 20 列
- 每行发送 20 个 claim，每个 (limb_value, +1)
- 通过 `eval.add_lookup`（若 Stwo 支持）或 logup interaction trace

**复杂度**：高。需新增 component + channel draw + soundness check（`claimed_sum_cpu + claimed_sum_range == 0`）。参考 `prover.rs:314-340` 的 `gen_cpu_interaction_trace` 和 `prover.rs:CpuMemoryProof` 多组件模式。

**实施步骤**：
1. `lookups.rs`：添加 `RangeCheckLookup` relation
2. `range_check_air.rs`：实现 `RangeCheckAir`（256 行，value + multiplicity 列，yield logup）
3. `cpu_air.rs`：添加 `range_lookup: Option<RangeCheckLookup>` 字段 + 在 evaluate 中发送 claim
4. `prover.rs`：扩展 `CpuMemoryProof` → `CpuMemRangeProof`（3 组件），新增 `gen_range_check_trace`
5. 测试：篡改 limb 为 256 → prove 失败

**降级备选**（若 logup 集成过于复杂）：对关键 limb 添加 2×4-bit 分解约束（lo4 ∈ [0,15], hi4 ∈ [0,15]），用 16 元 binality gate。每 limb 需 2 列（lo4, hi4）+ 范围约束。但 20 列 × 2 = 40 列超出预算，不可行。**故采用 logup 方案**。

---

### Phase 4：Step 6 — 递归 FRI query point 修复（V5 HIGH）

**文件**：`recursive/public_inputs.rs` + `recursive/trace_gen.rs` + `recursive/air.rs`（如有）

#### 6.1 公开输入扩展（public_inputs.rs）

`RecursivePublicInputs` 新增 2 字段：
```rust
/// L1 FRI 的 query point（从 L1 Fiat-Shamir transcript 推导，非硬编码）
pub fri_query_x: CirclePoint<SecureField>,
/// L1 FRI last layer 在 query_x 处的 claimed evaluation
pub fri_query_eval: SecureField,
```
同步更新 `new()`、`default()`、所有构造调用点。

#### 6.2 query point 推导（trace_gen.rs:614-616）

替换硬编码：
```rust
// 旧：let query_x_qm31 = SecureField::from(1u32);
// 新：从 public_inputs 读取（public_inputs 由调用者从 L1 transcript 提取）
let query_x_qm31 = public_inputs.fri_query_x;
```

#### 6.3 query point 提取（新增 helper）

新增函数 `extract_fri_query_point(l1_proof: &StarkProof, l1_public_inputs: &...) -> (CirclePoint<SecureField>, SecureField)`：
1. 重放 L1 channel：按 L1 verifier 流程 commit preprocessed → commit trace → draw OODS → commit FRI layers
2. 在 FRI query phase，调用 `channel.draw_fri_query_points()` 获取 query positions
3. 从 query position 计算 `query_x`（CirclePoint）和 `query_eval`（last_layer_poly.eval_at(query_x)）
4. 返回 (query_x, query_eval)

**复杂度**：高。需深入理解 Stwo 的 `Poseidon252Channel` 和 FRI verify 流程。参考 `stwo-2.3.0/src/core/verifier.rs::verify()`。

#### 6.4 AIR 约束（recursive/air.rs）

现有约束 `query_eval == last_layer_poly.eval_at(query_x)` 已存在（trace_gen.rs:622 计算 query_eval）。修复后 query_x 来自公开输入，prover 无法选择。新增约束将 query_x/query_eval 绑定到公开输入：
- `partial_eval` 的 Horner 递推用 `query_x` 作为系数 → query_x 已是 AIR 常量（从公开输入注入）
- 需确认 AIR 是否将 query_x 作为 public input 约束（而非自由值）

#### 6.5 soundness 测试

```rust
#[test]
fn test_recursive_fri_soundness_tamper_query_x() {
    // 构造合法 L1 proof → 提取真实 query_x
    // 篡改 public_inputs.fri_query_x 为 SecureField::from(2u32)
    // 预期：L2 prove 失败（query_eval ≠ last_layer_poly.eval_at(篡改后的 x)）
}
```

---

### Phase 5：Step 10 — 全量 soundness 测试 + 回归

**文件**：`prover.rs` tests 模块

#### 10.1 补齐 soundness 测试

| 指令类 | 测试数 | 说明 |
|--------|--------|------|
| 分支（Phase 2） | 6 | 见 3.4 |
| 范围检查（Phase 3） | 2 | 篡改 limb=256 / 篡改 multiplicity |
| 递归 FRI（Phase 4） | 1 | 篡改 query_x |
| **小计** | 9 | |

#### 10.2 全量回归测试

```bash
# 单元测试（lib）
cargo +nightly-2026-04-15 test -p poker_zkvm --lib

# 集成测试（e2e）
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture

# 递归路径测试（若 V5 修改影响）
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive"
```

**预期最终测试数**：~620（611 Phase 1 后 + 6 分支 + 2 范围 + 1 FRI），0 失败，0 回归。

---

## 4. 假设与决策（Assumptions & Decisions）

1. **分支 diff_inv 复用 HelperB[0]**：BEQ/BNE 行与 Load/Store one-hot 互斥，HelperB(69) 空闲。diff_inv 是单 M31 列（域逆元，非 4 limb）。已验证 HelperA(65) 在分支行被占用（存 Pc+imm 目标地址），故不用 HelperA。
2. **diff_value 度数**：`diff_value = limb0 + 256*limb1 + 65536*limb2 + 2^24*limb3`，是 4 列的线性组合（系数为常量），度数 = 1。故 `taken * diff_value` = 度 2，`diff_value * diff_inv` = 度 2，gating 后度 3 ✓。
3. **same_sign 作为 witness 列**：复用 `COL_LOW_NONZERO`(116) 存 same_sign（度 1），而非现场计算（度 2）。这样 `same_sign * borrow1` = 度 2，`is_blt * (taken - slt_result)` = 度 3 ✓。与现有 SLT 约束（cpu_air.rs:336-409）一致。
4. **逻辑/移位指令保持降级**：用户确认。XOR/OR/AND 需 bit 分解（每 limb 8 列），SLL/SRL/SRA 需 shamt 分解+旋转，132 列预算不足。标注为已知 gap，待列扩展（Phase E）后处理。poker 场景几乎不使用。
5. **范围检查用 logup**：唯一不超列预算的 sound 方案。20 个 limb 列 × 1 claim/行，与 256 行 RangeCheckAir 的 yield 配平。
6. **递归 FRI query point 推导**：从 L1 proof 的 Fiat-Shamir transcript 重放提取，而非硬编码。这是 V5 的核心修复，复杂度最高。
7. **执行顺序**：Phase 1（验证 V6）→ Phase 2（分支 CRITICAL）→ Phase 3（范围检查 HIGH）→ Phase 4（递归 FRI HIGH）→ Phase 5（测试）。每 Phase 完成后运行测试。
8. **不修改已完成且通过测试的 Phase A（比较指令）和 Step 4（JAL/JALR）实现**。

---

## 5. 验证步骤（Verification Steps）

### Phase 1 验证（V6）
```bash
cargo +nightly-2026-04-15 build -p poker_zkvm
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "div_soundness_tamper_q_abs" "divu_soundness_tamper_q_abs"
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```
预期：611 通过，0 失败。

### Phase 2 验证（分支）
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "beq_soundness" "bne_soundness" "bltu_soundness" "bgeu_soundness" "blt_soundness" "bge_soundness"
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "branch" "beq" "bne" "blt"  # roundtrip
```
预期：617 通过（+6），0 失败。

### Phase 3 验证（范围检查）
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"
```
预期：619 通过（+2），0 失败。

### Phase 4 验证（递归 FRI）
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive" "fri_soundness"
```
预期：620 通过（+1），0 失败。

### Phase 5 全量回归
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```
预期：~620 通过，0 失败，0 回归。

---

## 6. 实施优先级与执行清单

| 顺序 | Phase | 步骤 | 漏洞 | 严重度 | 预计约束 | 预计测试 | 阻塞? |
|------|-------|------|------|--------|----------|----------|-------|
| 1 | Phase 1 | 验证 Step 7（V6 DIV） | V6 | MEDIUM | 0（已写） | 0（已写） | 是（当前未验证） |
| 2 | Phase 2 | Step 3（分支条件验证） | V1 | CRITICAL | +13 | +6 | 否 |
| 3 | Phase 3 | Step 5（limb 范围检查） | V4 | HIGH | logup | +2 | 否 |
| 4 | Phase 4 | Step 6（递归 FRI query point） | V5 | HIGH | +2 | +1 | 否 |
| 5 | Phase 5 | Step 10（全量 soundness + 回归） | — | — | 0 | +9 | 否 |

**执行者从顺序 1 开始**，每完成一步运行测试确认无回归后再进行下一步。Phase 3/4 复杂度高，若遇到 Stwo API 障碍，可先完成 Phase 1+2+5（CRITICAL 修复 + 测试）并提交，再单独处理 Phase 3/4。
