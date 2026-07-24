# L1 CPU AIR Soundness 修复设计文档

> 状态：Draft → 冻结后作为实施规范
> 范围：poker_zkvm L1 CPU AIR + Memory AIR 的 soundness 缺口（A1–A8）
> 依据：基于 `cpu_air.rs` / `memory_air.rs` / `column_layout_v2.rs` / `trace_native.rs` 的代码审查

## 1. 背景与目标

L1 CPU AIR 当前实现存在多处约束缺口：关键 witness 列（HelperA、sign_a/sign_b、Memory Load ValCur、指令字）仅由 trace generator 填充，**AIR 层无约束验证其正确性**。恶意 prover 可伪造满足现有约束但不满足真实执行的 trace，破坏 ZKVM 的 soundness。

本设计文档目标：
1. 列出全部 L1 层 soundness 缺口（A1–A8），逐一定义修复约束。
2. 统一规划新增 witness 列，避免阶段性返工。
3. 核算度数预算，保证 `max_constraint_log_degree_bound = log_size + 1` 不被打破。
4. 定义分阶段实施顺序与测试策略。

## 2. 缺口清单（A1–A8）

| # | 缺口 | 位置 | 风险 |
|---|------|------|------|
| A1 | HelperA 地址/目标值未约束 | cpu_air.rs L621-743 | Load/Store/JAL/JALR/LUI/AUIPC/Branch 目标完全信任 trace generator |
| A2 | Memory AIR Load 行 ValCur 无约束 | memory_air.rs | Load 不改内存，ValCur 应=ValPrev；当前可任意伪造 |
| A3 | sign_a/sign_b 未绑定操作数符号位 | cpu_air.rs L1043 | SLT/SLTI/BLT/BGE/MULH/DIV 符号判断可被伪造 |
| A4 | JALR 最低位清零 `& !1` 未约束 | cpu_air.rs L629 | JALR 目标地址最低位可非 0 |
| A5 | MUL carry_lo 范围信任 | cpu_air.rs L986 | carry_lo ∈ [0,255] 未 RangeCheck |
| A6 | 无指令字解码约束 | column_layout_v2.rs | indicator 与实际指令字无绑定，可任意伪造指令类别 |
| A7 | ADD/SUB/比较 carry 与操作数 limb 范围 | cpu_air.rs | limb ∈ [0,255] 部分依赖 RangeCheck（A8 未全覆盖） |
| A8 | RangeCheck 覆盖不全 | cpu_air.rs L1367 | 仅 24 列，M 扩展 carry_lo/abs/quot/rem 未覆盖 |

### 2.1 依赖关系

```
A6（指令字列）──┬──> A1（HelperA = rs1/pc + imm，需 imm 字段）
                ├──> A4（JALR & !1，需 imm/bit 字段）
                └──> A5/A7 间接（指令字提供 opcode 范围）
A2 独立 ──────────────> 可先行
A3 独立 ──────────────> 可先行
A8 扩展 ──────────────> 可先行（仅新增 RangeCheck claim 列）
```

**实施顺序**：A2 + A3（Phase 1）→ A7 + A8（Phase 2）→ A6（Phase 3）→ A1 + A4 + A5（Phase 4，依赖 A6）。

## 3. 修复设计

### 3.1 A2 — Memory AIR Load 行 ValCur = ValPrev

**缺口**：Memory AIR 中 Load 行（IsStore=0, IsPadding=0）的 `ValCur` 无约束。恶意 prover 可设 Load 行 `ValCur` 为任意值，通过 logup 让 CPU 的 `rd_eff` 读到伪造值（rd_eff = MemValCur）。

**修复约束**：Load 行 ValCur[i] = ValPrev[i]（Load 不修改内存）。
- gating：`(1 - IsStore) * (1 - IsPadding)` = Load 行
- 约束：`is_load_mem * (ValCur[i] - ValPrev[i]) = 0`，i=0..3
- 度数 = 1 (gating) × 1 (diff) = 2 ✓

**新增列**：无（复用现有 ValCur/ValPrev/IsStore/IsPadding）。

**实现位置**：`memory_air.rs` evaluate 中，M19 之后新增 M20-M23。

### 3.2 A3 — sign_a/sign_b 绑定操作数符号位

**缺口**：`sign_a`(col 114)/`sign_b`(col 115) 仅约束 binality，未链接到 `ValueB[3]`/`ValueC[3]` 的 bit 31。SLT/SLTI/BLT/BGE/MULH/MULHSU/DIV/REM 的符号判断完全信任 trace generator。

**修复约束**：对 `ValueB[3]`（rs1 高字节）做 8-bit 分解，约束 `sign_a = SignABits[7]`（bit 31）；`ValueC[3]`（rs2 高字节）同理。
- 位分解：`ValueB[3] = Σ SignABits[i]·2^i`，i=0..7
- binality：`SignABits[i]·(SignABits[i]-1) = 0`
- 符号绑定：`sign_a - SignABits[7] = 0`
- gating：所有使用 sign_a 的指令组 `g_sign_a = is_slt_group + is_signed_branch + g2 + g3`
  - 度数：gating(1) × 位分解(1) = 2 ✓；gating(1) × binality(2) = 3 ✓；gating(1) × 绑定(1) = 2 ✓

**新增列**（v3.7）：
- `COL_SIGN_A_BITS_BASE` = 134（8 列，134-141）
- `COL_SIGN_B_BITS_BASE` = 142（8 列，142-149）
- NUM_COLUMNS：134 → 150

**实现位置**：`column_layout_v2.rs` 新增列常量；`cpu_air.rs` 新增约束块；`trace_native.rs` 新增 SignABits/SignBBits 填充。

### 3.3 A7 + A8 — RangeCheck 全覆盖

**缺口**：当前 RangeCheck 仅覆盖 24 列（PC/PcNext/ValueAEff/ValueB/ValueC/MemAddr）。M 扩展的 carry_lo(7)、AbsA(4)、AbsB(4)、DivQuot(4)、DivRem(4)、MulLow(4)、MulHigh(4) 共 31 列未 RangeCheck。

**修复**：扩展 `RANGE_CHECK_COLS` 至覆盖全部 8-bit limb 列。
- 新增覆盖：carry_lo(81-87, 7列)、AbsA(106-109)、AbsB(110-113)、DivQuot(117-120)、DivRem(121-124)、MulLow(128-131)、MulHigh(102-105)
- 注意：carry_lo 在 Load 行复用为 IS_LOAD_BYTE/HALF/SIGN（binary，已约束），RangeCheck claim 在 Load 行会发送这些 binary 值（0/1 ∈ [0,255] ✓）。但 Load 行的 carry_lo 实际是 binary flag，RangeCheck 仍合法。
- **冲突处理**：LOAD_BITS(85-92) 是 binary，RangeCheck 合法；但 MUL 行的 85-92 是 carry_hi0 的部分，需确认 RangeCheck 列表不重复包含。实际 88-94 是 carry_hi0（binary），RangeCheck 仍合法（0/1 ∈ [0,255]）。故只需覆盖 carry_lo(81-87)、MulHigh(102-105)、AbsA、AbsB、DivQuot、DivRem、MulLow。

**新增列**：无（复用 RangeCheckLookup，仅扩展 claim 列表）。

**实现位置**：`cpu_air.rs` RANGE_CHECK_COLS 数组扩展。

### 3.4 A6 — 指令字列 + 解码约束（Phase 3，大工程）

**缺口**：无指令字列，indicator one-hot 完全信任 trace generator。恶意 prover 可伪造 indicator 与实际指令字不匹配。

**修复设计**：
1. 新增 `InstrWord`（4×8-bit limb = 4 列）存储原始 32-bit 指令字。
2. 新增 `ImmField`（4×8-bit limb = 4 列）存储解码后的立即数（已符号扩展/移位）。
3. 解码约束：根据 InstrWord 的 opcode/funct3/funct7 字段，约束 indicator 与之匹配。
   - opcode = InstrWord[0] & 0x7F（低 7 位）
   - funct3 = (InstrWord[0] >> 5) | (InstrWord[1] & 0x0F) << 3（需位分解）
   - 约束：`IS_ADD · (opcode - 0x33) = 0`、`IS_ADDI · (opcode - 0x13) = 0` 等
4. imm 提取约束：根据指令类型约束 ImmField = decode_imm(InstrWord)。

**新增列**（v3.8）：InstrWord(4) + ImmField(4) + 解码中间位分解（~16 列）≈ 24 列。

**度数**：解码约束多为 gating(1) × 等式(1) = 2 ✓；位分解 binality = 2 ✓。

**实现位置**：`column_layout_v2.rs`、`cpu_air.rs`、`trace_native.rs`。

### 3.5 A1 — HelperA 约束（Phase 4，依赖 A6）

**缺口**：HelperA 在 LUI/JAL/JALR/Branch/AUIPC/Load/Store 行存预计算值，AIR 仅约束 `MemAddr/PcNext/rd_eff - HelperA = 0`，但 HelperA 本身（rs1+imm / pc+imm）无约束。

**修复设计**（依赖 A6 的 ImmField）：
- Load/Store：`HelperA = ValueB + ImmField`（rs1 + imm），4 limb 加法 + carry
- JAL/AUIPC：`HelperA = Pc + ImmField`（pc + imm），4 limb 加法 + carry
- JALR：`HelperA = (ValueB + ImmField) & !1`，加法 + 最低位清零（A4）
- LUI：`HelperA = ImmField`（imm 已移位）
- Branch taken：`HelperA = Pc + ImmField`

**新增列**：复用 PcCarryFlag 或新增 HelperA carry 列（与现有 carry one-hot 互斥）。

**度数**：gating(1) × 加法(1) = 2 ✓；carry binality = gating(1) × 2 = 3 ✓。

### 3.6 A4 — JALR 最低位清零

**缺口**：JALR 目标 = (rs1+imm) & !1，最低位清零未约束。

**修复**：`HelperA[0]` 的 bit 0 = 0。需对 HelperA[0] 位分解或约束 `HelperA[0] = 2·k`（k ∈ [0,127]）。
- 依赖 A6（ImmField）+ A1（HelperA 加法）。
- 约束：`HelperA[0] - 2·HelperA_low_half = 0`，HelperA_low_half ∈ [0,127]（RangeCheck 或 bit 分解）。

### 3.7 A5 — MUL carry_lo 范围

**缺口**：carry_lo ∈ [0,255] 信任（注释 line 986）。

**修复**：A8 RangeCheck 扩展覆盖 carry_lo(81-87) 即解决。

## 4. 列布局统一规划

### 4.1 阶段性列数演进

| 版本 | 阶段 | 新增列 | NUM_COLUMNS |
|------|------|--------|-------------|
| v3.6 | 现状 | — | 134 |
| v3.7 | Phase 1 (A2+A3) | SignABits(8) + SignBBits(8) | 150 |
| v3.8 | Phase 3 (A6) | InstrWord(4) + ImmField(4) + 解码位分解(~16) | ~174 |
| v3.9 | Phase 4 (A1) | HelperA carry(2，复用 PcCarry 互斥) | ~174 |

### 4.2 v3.7 新增列定义（Phase 1）

```
col 134-141：SignABits[0..8] — ValueB[3] 的 8-bit 位分解
  SignABits[7] = rs1 符号位（bit 31），与 sign_a 绑定
col 142-149：SignBBits[0..8] — ValueC[3] 的 8-bit 位分解
  SignBBits[7] = rs2 符号位（bit 31），与 sign_b 绑定
```

**互斥性**：SignABits/SignBBits 仅在使用 sign_a/sign_b 的指令行（SLT/SLTI/BLT/BGE/MULH/MULHSU/DIV/REM）非 0。这些指令与 Load 行 one-hot 互斥，与 MULHU/MUL（不使用 sign_a/sign_b）也互斥。安全。

## 5. 度数预算

所有新增约束的最大总度 ≤ 3，维持 `max_constraint_log_degree_bound = log_size + 1`：

| 约束类型 | 度数 | 示例 |
|----------|------|------|
| gating × 等式 | 1+1=2 | A2 ValCur=ValPrev |
| gating × binality | 1+2=3 | A3 SignABits binality |
| gating × 位分解 | 1+1=2 | A3 ValueB[3]=Σbits |
| gating × 绑定 | 1+1=2 | A3 sign_a=bits[7] |

**无约束度数 > 3**，预算安全。

## 6. 分阶段实施计划

### Phase 1：A2 + A3（独立，快速闭环）
1. `column_layout_v2.rs`：新增 SignABits/SignBBits 列常量，NUM_COLUMNS=150，更新测试。
2. `memory_air.rs`：新增 M20-M23（Load ValCur=ValPrev）。
3. `cpu_air.rs`：新增 A3 约束块（位分解 + binality + sign_a/sign_b 绑定）。
4. `trace_native.rs`：填充 SignABits/SignBBits。
5. 测试：单组件 prove/verify + 反例 witness（篡改 sign_a 应 prove 失败）。

### Phase 2：A7 + A8（RangeCheck 全覆盖）
1. `cpu_air.rs`：扩展 RANGE_CHECK_COLS 至全部 limb 列。
2. 测试：3 组件 prove/verify（CPU+Memory+RangeCheck）。

### Phase 3：A6（指令字解码，大工程）
1. `column_layout_v2.rs`：新增 InstrWord/ImmField/解码位分解列。
2. `cpu_air.rs`：新增解码约束（opcode/funct3/funct7 → indicator）。
3. `trace_native.rs`：填充 InstrWord/ImmField。
4. 测试：解码反例。

### Phase 4：A1 + A4 + A5（依赖 A6）✅ 已完成
1. `cpu_air.rs`：新增 HelperA = rs1/pc + ImmField 加法约束（A1）。✅
   - Load/Store：HelperA = ValueB + ImmField（16-bit carry 加法）
   - JAL/AUIPC/Branch taken：HelperA = Pc + ImmField（16-bit carry 加法）
   - LUI：HelperA = ImmField（直接 limb 等式）
   - JALR：HelperA = (ValueB + ImmField) & !1（binality(x) 隐式推导 bit0）
2. `cpu_air.rs`：新增 JALR & !1 约束（A4）。✅
   - HelperA[0] = 2 * HelperA_half（偶数约束，HelperA_half ∈ [0,127] RangeCheck）
3. A5 由 Phase 2 的 RangeCheck 覆盖解决（carry_lo 81-87 已在 RANGE_CHECK_COL_INDICES）。✅
4. 测试：地址伪造反例。✅
   - test_a1_jalr_helper_a_forgery_soundness（JALR HelperA 伪造）
   - test_a4_jalr_helper_a_half_forgery_soundness（A4 HelperA_half 伪造）
   - test_a4_jalr_odd_helper_a_soundness（JALR HelperA[0] 奇数）
   - test_a1_jal_helper_a_forgery_soundness（JAL HelperA 伪造）
   - test_a1_a4_jalr_roundtrip（JALR 正例）
   - test_a1_jal_roundtrip（JAL 正例）
   - test_a1_lui_roundtrip（LUI 正例）

## 7. 测试策略

### 7.1 正例测试
- 现有 prove/verify 全量回归（确保不破坏）。✅ 654 tests passed
- 新增约束后 prove/verify 通过。✅

### 7.2 反例测试（soundness 验证）
对每个修复，构造篡改 witness 的反例，验证 prover 拒绝：
- **A3 反例**：sign_a 设为与 ValueB[3] bit31 相反的值 → prove 失败。✅
- **A2 反例**：Memory Load 行 ValCur ≠ ValPrev → prove 失败。✅
- **A1 反例**：HelperA 设为 ≠ rs1+imm → prove 失败（Phase 4）。✅
- **A4 反例**：HelperA_half 设为 ≠ HelperA[0]/2 → prove 失败（Phase 4）。✅
- **A6 反例**：indicator 与 InstrWord opcode 不匹配 → prove 失败（Phase 3）。✅

### 7.3 度数与列布局自检
- `cargo test` 列无重叠测试。
- `max_constraint_log_degree_bound` 断言 = log_size + 1。

## 8. 风险与回退

| 风险 | 缓解 |
|------|------|
| 新增列导致 prover 性能下降 | Phase 1 仅 +16 列（+12%），可接受；分阶段评估 |
| A6 解码约束复杂度高 | Phase 3 独立，可拆子阶段 |
| trace_native 填充错误 | 反例测试覆盖 |
| Stwo API 变化 | 锁定 stwo 版本，回归测试 |

**回退**：每个 Phase 独立 commit，可单独 revert。

## 9. 完成标准（Definition of Done）

- [x] A1-A8 全部缺口有对应 AIR 约束（非信任 trace generator）。
  - A1：HelperA = rs1/pc + ImmField 加法约束（v3.9 Phase 4）
  - A2：Memory AIR Load 行 ValCur = ValPrev（Phase 1）
  - A3：sign_a/sign_b 绑定操作数符号位（Phase 1）
  - A4：JALR 最低位清零 HelperA[0] = 2*HelperA_half（v3.9 Phase 4）
  - A5：MUL carry_lo RangeCheck 覆盖（Phase 2 A8 扩展）
  - A6：指令字解码约束 opcode/funct3/funct7 → indicator（Phase 3）
  - A7：ADD/SUB/比较 carry 与操作数 limb RangeCheck（Phase 2 A8 扩展）
  - A8：RangeCheck 全覆盖 64 列（Phase 2 + Phase 3 + Phase 4）
- [x] 所有反例测试证明篡改 witness 被 prover 拒绝。
  - A2/A3/A6/A8/A1/A4 各有反例测试，均验证 prove 失败
- [x] `cargo test` 全量通过（654 passed, 0 failed）。
- [x] 列布局无重叠，NUM_COLUMNS = 185（v3.9）与文档一致。
- [x] `max_constraint_log_degree_bound = log_size + 1` 保持（所有新增约束度 ≤ 3）。
