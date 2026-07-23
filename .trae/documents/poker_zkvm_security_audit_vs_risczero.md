# poker_zkvm 安全审计报告：对比 RISC Zero

> **审计目标**：对比成熟 zkVM（RISC Zero），全面审计 poker_zkvm 代码，找出安全漏洞和逻辑错误
> **审计日期**：2026-07-23
> **审计范围**：`poker_zkvm/src/stwo_backend/`（CPU AIR + Memory AIR + Prover/Verifier + Recursive）
> **对比基准**：RISC Zero（riscv32im, FRI-STARK, BabyBear field, 生产级 zkVM）

---

## 1. 背景（Context）

poker_zkvm 是一个自研 riscv32im zkVM，使用 Stwo（M31 Circle STARK）后端。近期完成了 M 扩展算术约束（Steps 1-8，84 条新约束），但**原始 RV32I 指令集的约束完整性从未被系统审计**。本审计对比 RISC Zero 的成熟实现，逐指令检查约束覆盖度，识别 soundness 缺口。

**核心问题**：在 zkVM 中，AIR 约束必须验证每条指令的**结果正确性**（rd_eff = 正确计算值）。如果某指令仅有 indicator 但无结果约束，则 prover 可以将 rd_eff 设为**任意值**，完全破坏零知识证明的 soundness。

---

## 2. 审计方法论

1. **逐指令约束覆盖度检查**：对照 RV32I + M 扩展全部 42 个指令类别，检查每个是否有结果验证约束
2. **RISC Zero 对比**：RISC Zero 对每条指令都有完整约束（参考 risc0/risc0-vm `rzir` + `rv32im` AIR）
3. **Soundness 测试覆盖度**：检查哪些指令有 tamper 测试（篡改结果 → prove 失败）
4. **Witness 范围检查**：检查 8-bit limb 是否被约束到 [0, 255]
5. **递归层 soundness**：检查 recursive proof 的 FRI query point 绑定

---

## 3. 审计发现（按严重程度排序）

### 🔴 CRITICAL — V1：分支条件未验证（6 条分支指令）

**位置**：`cpu_air.rs:347-456`

**问题**：`taken` 标志仅约束 binality（`taken ∈ {0,1}`），但**未约束 taken 等于实际比较结果**。

```
当前约束：
  taken * (taken - 1) = 0          // binality ✓
  is_branch * (1-taken) * (PcNext = Pc+4)   // not-taken PC ✓
  is_branch * taken * (PcNext = Pc+imm)     // taken PC ✓

缺失约束：
  BEQ:  taken 应 = (rs1 == rs2)    // ❌ 未约束
  BNE:  taken 应 = (rs1 != rs2)    // ❌ 未约束
  BLT:  taken 应 = (rs1 < rs2 有符号)  // ❌ 未约束
  BGE:  taken 应 = (rs1 >= rs2 有符号) // ❌ 未约束
  BLTU: taken 应 = (rs1 < rs2 无符号)  // ❌ 未约束
  BGEU: taken 应 = (rs1 >= rs2 无符号) // ❌ 未约束
```

**影响**：恶意 prover 可对任意分支设置 `taken=1`（无论操作数是否满足条件），完全控制程序控制流。例如：BEQ x1,x2 中 x1≠x2，但 prover 设 taken=1 跳转到任意 PC。**这使 prover 可以伪造任意执行路径**。

**RISC Zero 对比**：RISC Zero 通过以下方式验证分支条件：
- BEQ: `(rs1 - rs2) * taken = 0`（若 taken=1 则 rs1=rs2）+ `(1-taken) * diff = 0`（若 taken=0 则 diff=rs1-rs2≠0，用 nonzero witness）
- BLT/BGE: 使用减法 + 符号位比较约束
- BLTU/BGEU: 使用减法 + borrow 约束

**修复方案**：
- 对 BEQ/BNE：引入 `diff = rs1 - rs2`（SUB 同结构），约束 `taken * diff = 0`（taken→diff=0）+ `(1-taken) * diff * diff_inv = 0`（not-taken→diff≠0，需 nonzero witness `diff_inv`）
- 对 BLT/BGE：使用 16-bit 减法 borrow chain，约束 `taken = 1 - borrow`（有符号）或 `taken = borrow`（无符号）
- 新增 witness 列：`diff_inv`（4 limb，非零逆元，复用现有 helper 列）

---

### 🔴 CRITICAL — V2：16 条逻辑/移位/比较指令结果未约束

**位置**：`cpu_air.rs` — 以下 indicator 从未用于任何 `add_constraint` 调用

| 指令 | 正确结果 | 约束状态 | 影响 |
|------|----------|----------|------|
| SLT | rd_eff = (rs1 < rs2 有符号) ? 1 : 0 | ❌ 无约束 | rd_eff 可为任意值 |
| SLTU | rd_eff = (rs1 < rs2 无符号) ? 1 : 0 | ❌ 无约束 | rd_eff 可为任意值 |
| SLTI | rd_eff = (rs1 < imm 有符号) ? 1 : 0 | ❌ 无约束 | rd_eff 可为任意值 |
| SLTIU | rd_eff = (rs1 < imm 无符号) ? 1 : 0 | ❌ 无约束 | rd_eff 可为任意值 |
| XOR | rd_eff = rs1 ^ rs2 | ❌ 无约束 | rd_eff 可为任意值 |
| XORI | rd_eff = rs1 ^ imm | ❌ 无约束 | rd_eff 可为任意值 |
| OR | rd_eff = rs1 \| rs2 | ❌ 无约束 | rd_eff 可为任意值 |
| ORI | rd_eff = rs1 \| imm | ❌ 无约束 | rd_eff 可为任意值 |
| AND | rd_eff = rs1 & rs2 | ❌ 无约束 | rd_eff 可为任意值 |
| ANDI | rd_eff = rs1 & imm | ❌ 无约束 | rd_eff 可为任意值 |
| SLL | rd_eff = rs1 << (rs2 & 0x1F) | ❌ 无约束 | rd_eff 可为任意值 |
| SLLI | rd_eff = rs1 << shamt | ❌ 无约束 | rd_eff 可为任意值 |
| SRL | rd_eff = rs1 >> (rs2 & 0x1F) | ❌ 无约束 | rd_eff 可为任意值 |
| SRLI | rd_eff = rs1 >> shamt | ❌ 无约束 | rd_eff 可为任意值 |
| SRA | rd_eff = (rs1 as i32) >> shamt | ❌ 无约束 | rd_eff 可为任意值 |
| SRAI | rd_eff = (rs1 as i32) >> shamt | ❌ 无约束 | rd_eff 可为任意值 |

**影响**：恶意 prover 可对这 16 条指令的 rd_eff 设置任意值。例如：`XOR x1, x2, x3` 中 prover 可将 x1 设为任意 32-bit 值（而非 rs1^rs2），后续依赖该寄存器的计算全部被污染。

**RISC Zero 对比**：RISC Zero 对所有这些指令都有完整约束：
- 逻辑运算（XOR/OR/AND）：bit-wise 约束，`rd[i] = rs1[i] OP rs2[i]`（每 bit 独立，度 1）
- 比较运算（SLT/SLTU）：结果约束为 {0,1} + 比较等式验证（同分支条件）
- 移位运算（SLL/SRL/SRA）：使用移位量分解（5-bit shamt），逐 limb 移位约束

**修复方案**：
- **逻辑运算**（XOR/XORI/OR/ORI/AND/ANDI）：直接 bit-wise 约束。`rd_eff[i] = rs1[i] OP rs2[i]` 对每个 limb。由于 8-bit limb 的 XOR/OR/AND 是 limb-wise 的，可直接约束 `rd_eff_limb[i] - rs1_limb[i] OP rs2_limb[i] = 0`，度 = indicator(1) × expr(1) = 2 ✓
- **比较运算**（SLT/SLTU/SLTI/SLTIU）：复用 SUB 的 borrow chain。`rd_eff ∈ {0,1}` binality + `taken = 1 - borrow`（SLT）或 `taken = borrow`（SLTU）。复用 ArithFlag 列（carry0/carry1 在比较行空闲，因 one-hot 与 SUB 互斥）
- **移位运算**（SLL/SRL/SRA/SLLI/SRLI/SRAI）：较复杂，需分解 shamt 为 5-bit，逐位旋转约束。参考 RISC Zero 的 shift 约束设计。**优先级可降低**（移位在 poker 场景中使用频率低）

---

### 🟠 HIGH — V3：JAL/JALR 链接寄存器未约束

**位置**：`cpu_air.rs:386-400`

**问题**：JAL/JALR 约束了 PC 跳转（PcNext = Pc+imm / PcNext = (rs1+imm)&!1），但**未约束 rd_eff = PC + 4**（返回地址）。

**影响**：恶意 prover 可将 JAL/JALR 的 rd_eff（链接寄存器/返回地址）设为任意值。后续 `RET`（JALR x0, x1, 0）跳转到该值时，prover 可控制返回目标。

**RISC Zero 对比**：RISC Zero 约束 `rd = PC + 4` for JAL/JALR，使用与 PC 递增相同的 16-bit carry 方案。

**修复方案**：
- 复用 PC carry（PcCarryFlag）列：JAL/JALR 行与 IsNonFlow 行互斥，PcCarryFlag 在 JAL/JALR 行空闲
- 约束：`is_jal * (rd_eff_low16 - pc_low16 - 4 + 65536*pc_carry0) = 0` + `is_jal * (rd_eff_high16 - pc_high16 - pc_carry0 + 65536*pc_carry1) = 0` + carry binality
- 同理 JALR。每条指令 4 约束，度 = 1×2 = 2 ✓（carry 在表达式内，度 1）

---

### 🟠 HIGH — V4：8-bit limb 缺少范围检查

**位置**：`cpu_air.rs` — 全文无 range check 约束

**问题**：所有 8-bit limb 值（PC、rd_eff、rs1、rs2、carry_lo 等）**未约束到 [0, 255]**。M31 域允许值到 2^31-2，恶意 prover 可在 limb 中放置 >255 的值。

**影响**：
- ADD 约束 `rd_eff_low = rs1_low + rs2_low - 65536*carry0` 可能被绕过（如 rs1_low=300, rs2_low=300, carry0=2, rd_eff_low=344 — 不是有效 limb 但约束满足）
- 乘法 carry chain 的部分积 `a_i * b_j` 可能溢出预期范围
- 所有依赖 limb 值 ∈ [0,255] 的约束均不 sound

**RISC Zero 对比**：RISC Zero 使用 range check lookup table，对每个 limb 约束 ∈ [0, 255]。通过 Logup argument 将所有 limb 值与预计算的 0-255 表匹配。

**修复方案**：
- **方案 A（推荐）**：添加 range check lookup argument。为每行的所有 limb 列（约 20 个：PC×4 + PcNext×4 + rd_eff×4 + rs1×4 + rs2×4 + carry_lo×7）发送 logup claim `(value, +1)`，与预计算表 `(0..255, -256)` 匹配
- **方案 B（轻量）**：对关键 limb（carry_lo, abs, div_quot, div_rem）添加 binary 分解约束（类似 carry hi0/hi1 的 8-bit 分解：`limb = bit0 + 2*bit1 + ... + 128*bit7`，8 个 binary 约束）。开销大但不依赖 lookup

---

### 🟠 HIGH — V5：递归层 FRI query point 为 placeholder

**位置**：`recursive/trace_gen.rs:583-616`

**问题**（已知 v5.1 soundness gap，代码中已标注）：
- FRI query point `x` 硬编码为 `SecureField::from(1u32)`（placeholder），未从 L1 proof 的 Fiat-Shamir transcript 推导
- `query_eval` 由 prover 计算并填入 trace，verifier 未独立验证

**影响**：递归证明中，prover 可伪造 query_eval（因为它不绑定到真实的 FRI query point），破坏递归证明的 soundness。

**RISC Zero 对比**：RISC Zero 的递归证明从 FRI transcript 中确定性推导 query point，verifier 重放相同推导。

**修复方案**（v5.2，代码中已规划）：
- 将 `query_x` 和 `query_eval` 添加到 `RecursivePublicInputs`
- L2 verifier 从 L1 proof 的 Fiat-Shamir transcript 重新推导 query point
- L2 AIR 约束 `query_eval == public_inputs.fri_query_eval`

---

### 🟡 MEDIUM — V6：DIV 特殊情况 q_abs 未完全约束

**位置**：`cpu_air.rs:807-815`

**问题**：当 `is_special=1`（d=0 或 INT_MIN/-1 溢出）时：
- 有符号 DIV：约束 `is_div * is_special * (1 - sign_q) = 0`（强制 sign_q=1）
- 但 `q_abs` 本身未约束（只约束了符号）
- 无符号 DIVU：d=0 时 q 应为 0xFFFFFFFF，但 `is_special` 仅约束存在性，不约束 q_abs 值

**影响**：d=0 时，prover 可将 q_abs 设为任意值（只要 sign_q=1）。虽然 RISC-V 规范定义 d=0 时结果为 all-ones，但 AIR 未强制此值。

**修复方案**：
- 添加约束：`is_special * (q_abs - expected_value) = 0`
  - d=0 有符号：`q_abs = 1`（|−1| = 1）
  - d=0 无符号：`q_abs = 0xFFFFFFFF`
  - 溢出（INT_MIN/-1）：`q_abs = 0x80000000`（|INT_MIN|）
- 或更简洁：约束 `is_special * (abs_b - 0) * (abs_b - 1)` ... 需要区分 d=0 vs overflow

---

### 🟡 MEDIUM — V7：Load 符号/零扩展未约束

**位置**：`cpu_air.rs:488-496`

**问题**：LB/LH 做符号扩展，LBU/LHU 做零扩展。AIR 约束 `rd_eff = HelperB(mem_value)`，但 mem_value 是**已扩展的 32-bit 值**（由 emulator 计算），AIR 未验证扩展正确性。

**影响**：LB x1, x2, 0 加载字节 0xFF → 应为 0xFFFFFFFF（符号扩展），但 prover 可放 0x000000FF（零扩展）或任意值到 mem_value（只要与 MemoryAir 一致）。由于 MemoryAir 存储的是 word，而 LB 读取 byte，存在粒度不匹配。

**RISC Zero 对比**：RISC Zero 的 memory model 是 byte-addressable，Load 指令的扩展逻辑由 AIR 显式约束（byte → word 的符号/零扩展）。

**修复方案**：
- 短期：确认 MemoryAir 的粒度（word vs byte）。若为 word，则 LB/LH 需额外约束从 word 中提取正确 byte 并扩展
- 长期：参考 RISC Zero 的 byte-level memory model

---

### 🟡 MEDIUM — V8：SHA-256 AIR 约束不完整

**位置**：`stwo_backend/sha256_air.rs:345, 395, 399, 403`

**问题**：SHA-256 AIR 有多个 TODO 标记，compression function 约束未完整实现。

**影响**：若 SHA-256 AIR 被用于证明路径（如 syscall 中的哈希验证），不完整约束可能导致 soundness 问题。需确认是否在当前 proof 路径中使用。

---

## 4. RISC Zero 对比总结

| 维度 | RISC Zero | poker_zkvm | 差距 |
|------|-----------|------------|------|
| 指令约束覆盖 | 42/42 指令完整约束 | 26/42 指令有约束 | ❌ 16 条无约束 |
| 分支条件验证 | ✅ 完整（比较+taken 绑定） | ❌ taken 仅 binality | 🔴 CRITICAL |
| Limb 范围检查 | ✅ range check lookup | ❌ 无 | 🟠 HIGH |
| JAL/JALR rd | ✅ rd = PC+4 | ❌ 未约束 | 🟠 HIGH |
| 移位指令 | ✅ shamt 分解 + 旋转约束 | ❌ 无约束 | 🔴 CRITICAL |
| 逻辑指令 | ✅ bit-wise limb 约束 | ❌ 无约束 | 🔴 CRITICAL |
| 比较指令 | ✅ 结果{0,1}+比较等式 | ❌ 无约束 | 🔴 CRITICAL |
| 内存一致性 | ✅ byte-level logup | ⚠️ word-level logup | 🟡 MEDIUM |
| 递归 FRI | ✅ transcript 推导 query | ❌ placeholder | 🟠 HIGH |
| 形式化验证 | ❌ | ❌ | 持平 |

---

## 5. 修复优先级与实施计划

### Phase 1：CRITICAL 修复（最高优先级）

**Step 1：逻辑指令约束**（XOR/XORI/OR/ORI/AND/ANDI）
- 难度：低（limb-wise 直接约束，度 2）
- 工作量：6 条指令 × 4 limb = 24 约束
- 文件：`cpu_air.rs`

**Step 2：比较指令约束**（SLT/SLTU/SLTI/SLTIU）
- 难度：中（复用 SUB borrow chain + 结果 binality）
- 工作量：4 条指令 × ~4 约束 = 16 约束
- 文件：`cpu_air.rs` + `trace_native.rs`（witness 填充）

**Step 3：分支条件验证**（BEQ/BNE/BLT/BGE/BLTU/BGEU）
- 难度：高（需要比较等式 + nonzero witness）
- 工作量：6 条指令 × ~4 约束 = 24 约束 + 新增 diff_inv witness 列
- 文件：`cpu_air.rs` + `trace_native.rs` + `column_layout_v2.rs`

### Phase 2：HIGH 修复

**Step 4：JAL/JALR 链接寄存器约束**
- 难度：低（复用 PC carry）
- 工作量：2 条指令 × 4 约束 = 8 约束

**Step 5：8-bit limb 范围检查**
- 难度：中（range check lookup argument）
- 工作量：新增 range check 组件 + logup 集成

**Step 6：递归 FRI query point 修复**（v5.2）
- 难度：高（Fiat-Shamir transcript 解析）
- 已有规划，按 v5.2 执行

### Phase 3：MEDIUM 修复

**Step 7：DIV 特殊情况 q_abs 约束**
**Step 8：Load 符号扩展约束**
**Step 9：移位指令约束**（SLL/SRL/SRA/SLLI/SRLI/SRAI）
- 难度：高（移位量分解 + 旋转约束）

### Phase 4：验证

**Step 10：Soundness 测试**
- 为每条修复的指令添加 tamper 测试（篡改 rd_eff → prove 失败）
- 参考已有 MUL/DIV soundness 测试模式
- 文件：`prover.rs` tests 模块

---

## 6. 验证方案

### 单元测试
```bash
# 逻辑指令约束
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_xor_soundness" "test_or_soundness" "test_and_soundness"

# 比较指令约束
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_slt_soundness" "test_sltu_soundness"

# 分支条件验证
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_branch_condition_soundness"

# JAL/JALR 链接寄存器
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_jal_link_soundness" "test_jalr_link_soundness"

# 范围检查
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "test_limb_range_check_soundness"
```

### 回归测试
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```

### E2E 测试
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```

---

## 7. 关键文件

| 文件 | 作用 | 修改内容 |
|------|------|----------|
| `stwo_backend/cpu_air.rs` | AIR 约束 | 新增 ~80 条约束（逻辑/比较/分支/JAL/范围检查） |
| `stwo_backend/trace_native.rs` | Trace 生成 | 新增 witness 填充（diff_inv, comparison borrow 等） |
| `stwo_backend/column_layout_v2.rs` | 列布局 | 新增 witness 列（diff_inv, range check witness） |
| `stwo_backend/prover.rs` | Prover/Verifier + 测试 | 新增 soundness 测试 |
| `stwo_backend/recursive/trace_gen.rs` | 递归 trace | v5.2 FRI query point 修复 |

---

## 8. 审计结论

poker_zkvm 的 M 扩展约束（Steps 1-8）实现完善，但**原始 RV32I 指令集存在严重 soundness 缺口**：16 条指令完全无结果约束，6 条分支指令条件未验证。这些漏洞允许恶意 prover 伪造任意计算结果和控制流，**当前不满足生产级 soundness 要求**。

对比 RISC Zero（42/42 指令完整约束 + range check + 形式化验证），poker_zkvm 需要补齐约 80 条约束才能达到同等 soundness 水平。建议按 Phase 1→4 顺序修复，每个 Phase 完成后运行完整测试套件确认无回归。
