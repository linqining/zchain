# M 扩展指令算术约束补充方案

> **目标**：参考成熟 ZKVM（RISC Zero / SP1 / OpenVM / Nexus）为 M 扩展 8 条指令（MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU）补充算术约束，闭合当前 soundness 缺口（目前仅有 indicator，无任何算术约束，prover 可"证明"任意错误结果）。

---

## 1. 现状分析

### 1.1 当前 soundness 缺口

M 扩展 8 条指令在 [cpu_air.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/cpu_air.rs) 中**仅定义了 indicator**（`IS_MUL`=56 … `IS_REMU`=63），`evaluate()` 函数中**无任何算术约束**。对比 ADD/SUB 有完整的 4-limb carry/borrow 约束，M 扩展指令的 `rd_eff`（结果列）完全不受约束——prover 可填充任意值并通过验证。

### 1.2 关键技术约束（来自 Phase 1 探索）

| 约束 | 值 | 影响 |
|------|----|------|
| M31 域 (BabyBear) | p = 2³¹−1 ≈ 2.147×10⁹ | 8-bit limb 乘积 255×255=65025 < p ✓；16-bit 半字乘积 65535²≈2³² > p ✗ → **必须用 8-bit limb 分解** |
| AIR 最大度 | 3 (`max_constraint_log_degree_bound = log_size + 1`) | 约束为 `indicator × expr`，expr 度 ≤ 2 |
| 现有 limb 信任模型 | ADD/SUB 不 range-check 每个 8-bit limb | 8-bit 部分沿用此信任；carry 的高位用 binary 分解强制约束 |

### 1.3 成熟 ZKVM 参考方案

| ZKVM | MUL 方案 | DIV 方案 | Range Check |
|------|----------|----------|-------------|
| **RISC Zero (Zirgen)** | 16-bit limb + carry chain | q·d+r=n | 专用 RangeCheck 组件 (logup) |
| **SP1 (Plonky3)** | 8/12-bit limb partial products | q·d+r=n + range lookup | lookup argument |
| **OpenVM** | 形式化验证 8-bit limb carry chain | q·d+r=n，Lean 证明 | range lookup |
| **Nexus zkVM** | limb 分解 + carry | — | range check |

**本方案选择**：8-bit limb 部分积 + carry chain（匹配 M31 域限制），carry 高位 binary 分解做轻量 range check（匹配现有 ADD/SUB 信任模型），DIV 用 `q·d+r=n` 恒等式。

---

## 2. 设计方案

### 2.1 MUL 系列：8-bit 部分积 carry chain

#### 2.1.1 核心算法（参考 RISC Zero / OpenVM）

将 32-bit 操作数 a, b 分解为 4×8-bit limb：`a = Σ aᵢ·256ⁱ`，`b = Σ bⱼ·256ʲ`。

64-bit 乘积 `P = a·b = Σ_{i,j} aᵢ·bⱼ·256^{i+j}`，按数位分组为 7 个部分和 S₀..S₆：

```
S₀ = a₀·b₀                                    (pos 0)
S₁ = a₀·b₁ + a₁·b₀                            (pos 1)
S₂ = a₀·b₂ + a₁·b₁ + a₂·b₀                    (pos 2)
S₃ = a₀·b₃ + a₁·b₂ + a₂·b₁ + a₃·b₀            (pos 3, 最大 = 4·65025 = 260100 < p ✓)
S₄ = a₁·b₃ + a₂·b₂ + a₃·b₁                    (pos 4)
S₅ = a₂·b₃ + a₃·b₂                            (pos 5)
S₆ = a₃·b₃                                    (pos 6)
```

每个 Sₖ 是 degree-2 表达式（trace 列乘积之和）。Carry chain 产生 8 个结果数字 c₀..c₇ + 7 个 carry：

```
S₀        = c₀ + 256·carry₀
S₁+carry₀ = c₁ + 256·carry₁
...
S₆+carry₅ = c₆ + 256·carry₆
carry₆    = c₇
```

结果：`P = Σ_{k=0}^{7} cₖ·256ᵏ`（64-bit）。
- **MUL**（低 32 位）：`rd_eff = c₀ + c₁·256 + c₂·65536 + c₃·16777216`，c₄..c₇ 丢弃
- **MULHU**（高 32 位）：`rd_eff = c₄ + c₅·256 + c₆·65536 + c₇·16777216`

#### 2.1.2 Carry range check（轻量方案）

carry 最大 ≈ 260100/256 ≈ 1020（10-bit）。无法用低度多项式约束 10-bit 范围。采用**二元分解**：

```
carryₖ = carry_loₖ + hi0ₖ·256 + hi1ₖ·512
```
- `carry_loₖ` ∈ [0,255]：信任（与 ADD/SUB 信任 limb 一致）
- `hi0ₖ, hi1ₖ` ∈ {0,1}：binality 约束 `x·(x−1)=0`（度 2，gated 度 3 ✓）

这限制 carry ∈ [0, 1023]（若 carry_lo ∈ [0,255]），覆盖实际范围。

#### 2.1.3 有符号处理（MULH / MULHSU）

参考 OpenVM 方案：
- **取绝对值**：`abs_a`（4×8-bit limb），`sign_a`（binary，= rs1 符号位）
- **约束**：`rs1 + sign_a·abs_a = sign_a·2³²`（即 abs_a = sign_a ? (2³²−rs1) : rs1，复用 SUB borrow 逻辑）
- **MULH**：a=|rs1|, b=|rs2|，结果符号 = sign_a ⊕ sign_b
- **MULHSU**：a=|rs1|, b=rs2（unsigned），结果符号 = sign_a
- **结果调整**：若结果为负，`rd_eff = 2³² − 1 − high32 − low_nonzero`（补码取反，需 `low_nonzero` flag 处理借位）

#### 2.1.4 操作数选择（避免度数超标）

因 indicator one-hot 互斥，按指令分组添加 carry chain 约束（共享 carry 列，操作数不同）：

| 分组 | 指令 | a 操作数 | b 操作数 | 约束数 |
|------|------|----------|----------|--------|
| G1 | MUL + MULHU | rs1 limbs | rs2 limbs | 8 |
| G2 | MULH | abs_a limbs | abs_b limbs | 8 |
| G3 | MULHSU | abs_a limbs | rs2 limbs | 8 |

每组 8 条 carry chain 约束，度 = indicator(1) × Sₖ(2) = 3 ✓。

### 2.2 DIV 系列：q·d+r=n 恒等式

#### 2.2.1 核心约束（参考 SP1 / OpenVM）

```
q·d + r = n   (quotient × divisor + remainder = dividend)
0 ≤ r < d     (remainder 范围)
```

- `q·d` 是 64-bit 乘积 → 复用 MUL carry chain（用 quotient, divisor 作为 a, b 操作数）
- 因 `q·d = n − r ≤ n < 2³²`，乘积高位 c₄..c₇ = 0（4 条约束）
- `0 ≤ r < d`：用 SUB borrow chain 验证 `d − r − 1 ≥ 0`（无借位），约 4 条约束

#### 2.2.2 特殊情况

| 情况 | RISC-V 规范 | 约束 |
|------|-------------|------|
| d = 0 (DIVU/DIV) | q = 0xFFFFFFFF, r = n | `is_special·(d−0) + (1−is_special)·(q·d+r−n) = 0` |
| INT_MIN / −1 (DIV) | q = INT_MIN, r = 0 | 同上 is_special 分支 |
| 正常 | q·d+r=n, 0≤r<d | `(1−is_special)·(q·d+r−n) = 0` |

`DIV_IS_SPECIAL`（binary）gate 两条分支。

#### 2.2.3 有符号 DIV/REM

- `DIV`：q 符号 = sign_a ⊕ sign_b，r 符号 = sign_a
- `REM`：r 符号 = sign_a，q = (n − r)/d
- 用 `DIV_SIGN_Q`, `DIV_SIGN_R`（binary）+ abs 值约束

### 2.3 列布局扩展（81 → 128，+47 新列）

新列追加在 col 80 之后：

| 范围 | 常量名 | 列数 | 用途 | 信任级别 |
|------|--------|------|------|----------|
| 81–87 | `COL_MUL_CARRY_LO[0..6]` | 7 | carry 低 8 位 | 信任（同 ADD limb） |
| 88–94 | `COL_MUL_CARRY_HI0[0..6]` | 7 | carry bit-8 | binary 约束 |
| 95–101 | `COL_MUL_CARRY_HI1[0..6]` | 7 | carry bit-9 | binary 约束 |
| 102–105 | `COL_MUL_HIGH[0..3]` | 4 | 乘积高 32 位 c₄..c₇ | 信任（8-bit） |
| 106–109 | `COL_ABS_A[0..3]` | 4 | \|rs1\| 的 4×8-bit limb | 信任（8-bit） |
| 110–113 | `COL_ABS_B[0..3]` | 4 | \|rs2\| 的 4×8-bit limb | 信任（8-bit） |
| 114 | `COL_SIGN_A` | 1 | rs1 符号位 | binary 约束 |
| 115 | `COL_SIGN_B` | 1 | rs2 符号位 | binary 约束 |
| 116 | `COL_LOW_NONZERO` | 1 | 乘积低 32 位 ≠ 0（补码借位） | binary 约束 |
| 117–120 | `COL_DIV_QUOT[0..3]` | 4 | 商 q 的 4×8-bit limb | 信任（8-bit） |
| 121–124 | `COL_DIV_REM[0..3]` | 4 | 余数 r 的 4×8-bit limb | 信任（8-bit） |
| 125 | `COL_DIV_IS_SPECIAL` | 1 | 除零/溢出标志 | binary 约束 |
| 126 | `COL_DIV_SIGN_Q` | 1 | 商符号（有符号 DIV/REM） | binary 约束 |
| 127 | `COL_DIV_SIGN_R` | 1 | 余数符号（有符号 DIV/REM） | binary 约束 |

**`NUM_COLUMNS: 81 → 128`**。MUL carry 列（81–101）被 MUL/DIV 共享（one-hot 互斥，同列存不同值）。

### 2.4 约束清单汇总

| 类别 | 约束组 | 条数 | 度 | 说明 |
|------|--------|------|----|------|
| **MUL carry chain** | G1(MUL+MULHU) | 8 | 3 | Sₖ(rs1,rs2) + carry chain |
| | G2(MULH) | 8 | 3 | Sₖ(abs_a,abs_b) + carry chain |
| | G3(MULHSU) | 8 | 3 | Sₖ(abs_a,rs2) + carry chain |
| **Carry range** | hi0 binality ×7 | 7 | 3 | hi0ₖ·(hi0ₖ−1)=0 |
| | hi1 binality ×7 | 7 | 3 | hi1ₖ·(hi1ₖ−1)=0 |
| **Carry 重建** | carryₖ=lo+hi0·256+hi1·512 ×7 | 7 | 2 | 度 2（无 indicator gating 也可，或 gated 度 3） |
| **MUL 结果** | MULHU: c₄..c₇=rd_eff | 4 | 2 | 高 32 位结果匹配 |
| | MUL: c₄..c₇ free | 0 | — | 低 32 位，高位丢弃 |
| **符号处理** | abs_a 重建 + abs_b 重建 | ~8 | 3 | sign_a·abs_a + rs1 = sign_a·2³² |
| | sign binality ×3 | 3 | 2 | sign_a,sign_b,low_nonzero |
| | 结果符号调整 | ~4 | 3 | rd_eff = sign ? neg(high) : high |
| **DIV 乘积** | q·d carry chain | 8 | 3 | 复用 carry 列，quot×divisor |
| | 高位 = 0 | 4 | 2 | c₄..c₇ = 0（乘积 ≤ 32 位） |
| **DIV 恒等式** | q·d+r=n (正常) | 4 | 3 | limb-wise + carry |
| | is_special 分支 | 4 | 3 | d=0 / overflow 特殊值 |
| | is_special binality | 1 | 2 | binary |
| **DIV 范围** | 0≤r<d | 4 | 3 | SUB borrow chain |
| | sign_q,sign_r binality | 2 | 2 | binary |
| **合计** | | **~83** | ≤3 | 全部在度 3 预算内 |

---

## 3. 实施步骤（8 步）

### Step 1: 扩展列布局 `column_layout_v2.rs`

**文件**：[column_layout_v2.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/column_layout_v2.rs)

- 追加 47 个列常量（col 81–127），更新 `NUM_COLUMNS = 128`
- 更新文件头文档表（81→128 列）
- 更新单元测试 `test_num_columns`（断言 128）、`test_column_ranges_no_overlap`（新增范围）
- 新增常量：`COL_MUL_CARRY_LO_BASE`, `COL_MUL_CARRY_HI0_BASE`, `COL_MUL_CARRY_HI1_BASE`, `COL_MUL_HIGH_BASE`, `COL_ABS_A_BASE`, `COL_ABS_B_BASE`, `COL_SIGN_A`, `COL_SIGN_B`, `COL_LOW_NONZERO`, `COL_DIV_QUOT_BASE`, `COL_DIV_REM_BASE`, `COL_DIV_IS_SPECIAL`, `COL_DIV_SIGN_Q`, `COL_DIV_SIGN_R`

### Step 2: 扩展 trace 生成 `trace_native.rs`

**文件**：[trace_native.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace_native.rs)

- 新增 `compute_mul_carries(rs1: u32, rs2: u32) -> [MulCarry; 7]`：计算 8-bit 部分积 carry chain，返回每个 carry 的 (lo, hi0, hi1) 分解
- 新增 `compute_abs_value(val: u32) -> (u32, u32)`：返回 (abs, sign)
- 新增 `compute_div_witness(n: u32, d: u32, signed: bool) -> DivWitness`：计算 q, r, is_special, sign_q, sign_r
- 在 `step_to_m31_row` 的 HelperA/HelperB match 中为 M 扩展指令填充新列：
  - MUL/MULHU/MULH/MULHSU：填充 carry 列（81–101）、high 列（102–105）、abs/sign 列（106–116）
  - DIV/DIVU/REM/REMU：填充 div 列（117–127），复用 carry 列（81–101）
- `needs_pc_carry` 已对 M 扩展返回 true，无需修改

### Step 3: 扩展 `cpu_air.rs` — MUL carry chain 约束

**文件**：[cpu_air.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/cpu_air.rs)

在 `evaluate()` 中 Store 约束（L510）之后、Memory logup（L512）之前插入：

- 读取 M 扩展 indicator：`is_mul`, `is_mulh`, `is_mulhsu`, `is_mulhu`, `is_div`, `is_divu`, `is_rem`, `is_remu`
- 定义 `is_unsigned_mul = is_mul + is_mulhu`，`is_mulh_group = is_mulh`，`is_mulhsu_group = is_mulhsu`
- 定义 partial sum 闭包 `S_k(a_base, b_base) -> E::F`（返回 degree-2 表达式）
- **G1 约束**（MUL+MULHU，8 条）：`is_unsigned_mul * (S_k(rs1_base, rs2_base) + carry_{k-1} - c_k - 256*carry_k) = 0`
- **G2 约束**（MULH，8 条）：`is_mulh * (S_k(abs_a_base, abs_b_base) + ...) = 0`
- **G3 约束**（MULHSU，8 条）：`is_mulhsu * (S_k(abs_a_base, rs2_base) + ...) = 0`
- 其中 c₀..c₃ = rd_eff limbs（col VALUE_A_EFF_BASE），c₄..c₇ = MUL_HIGH 列

### Step 4: 扩展 `cpu_air.rs` — Carry range check + 重建约束

- **Carry 重建**（7 条）：`is_mul_family * (carry_k - lo_k - hi0_k*256 - hi1_k*512) = 0`
- **hi0 binality**（7 条）：`is_mul_family * hi0_k * (hi0_k - 1) = 0`
- **hi1 binality**（7 条）：`is_mul_family * hi1_k * (hi1_k - 1) = 0`
- `is_mul_family = is_mul + is_mulh + is_mulhsu + is_mulhu + is_div + is_divu + is_rem + is_remu`

### Step 5: 扩展 `cpu_air.rs` — 符号处理 + MUL 结果约束

- **abs 重建**（~8 条）：`sign_a * abs_a_word + rs1_word = sign_a * 2^32`（16-bit half 方案，复用 SUB borrow 模式）
- **sign binality**（3 条）：sign_a, sign_b, low_nonzero
- **MULHU 结果**（4 条）：`is_mulhu * (MUL_HIGH[i] - rd_eff[i]) = 0`
- **MULH/MULHSU 结果调整**（~4 条）：`is_signed_mul * (rd_eff - sign_adjusted_high) = 0`

### Step 6: 扩展 `cpu_air.rs` — DIV 约束

- **q·d carry chain**（8 条）：`is_div_family * (S_k(quot_base, divisor_base) + ...) = 0`，复用 carry 列
- **高位 = 0**（4 条）：`is_div_family * MUL_HIGH[i] = 0`
- **恒等式**（4 条）：`(1-is_special) * (q*d_low + r_low - n_low + carry) = 0`
- **特殊分支**（4 条）：`is_special * (special_q - q) = 0` 等
- **is_special binality**（1 条）
- **r < d 范围**（4 条）：SUB borrow chain 验证 `d - r - 1 ≥ 0`
- **sign_q, sign_r binality**（2 条）

### Step 7: 更新 prover.rs 列数引用

**文件**：[prover.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs)

- `native_trace_to_evaluations`：assert `trace.cols.len() == NUM_COLUMNS`（已用常量，自动适配）
- `verify_cpu_proof`：`trace_log_sizes = vec![log_size; NUM_COLUMNS]`（已用常量，自动适配）
- 无需手动修改列数（全部引用 `NUM_COLUMNS` 常量），但需确认无硬编码 `81`

### Step 8: 测试

**文件**：[cpu_air.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/cpu_air.rs) 单元测试 + 新建 [tests/m_extension_constraints_e2e.rs](file:///Users/mac/projects/zchain/poker_zkvm/tests/m_extension_constraints_e2e.rs)

#### 单元测试（prove/verify roundtrip）
- `test_prove_verify_mul`：MUL x1, x2, x3 → 6×7=42
- `test_prove_verify_mul_large`：MUL 产生进位（0xFFFE × 0x10002）
- `test_prove_verify_mulhu`：MULHU 高 32 位
- `test_prove_verify_mulh_signed`：MULH 负×负=正
- `test_prove_verify_mulh_mixed_sign`：MULH 正×负=负
- `test_prove_verify_mulhsu`：MULHSU 有符号×无符号
- `test_prove_verify_div_normal`：DIV 100/7=14r2
- `test_prove_verify_divu`：DIVU 无符号
- `test_prove_verify_div_by_zero`：d=0 特殊情况
- `test_prove_verify_div_overflow`：INT_MIN/−1 溢出
- `test_prove_verify_rem`：REM 有符号取余

#### Soundness 测试（篡改应失败）
- `test_mul_soundness_wrong_result`：篡改 rd_eff → prove 失败
- `test_div_soundness_wrong_quotient`：篡改 q → prove 失败
- `test_div_soundness_wrong_remainder`：篡改 r 使 r≥d → prove 失败

#### E2E 测试
- 多指令序列（MUL → DIV → REM → MULHU）prove/verify roundtrip

---

## 4. 假设与决策

### 4.1 关键设计决策

| 决策 | 选择 | 理由 | 未选方案 |
|------|------|------|----------|
| limb 分解粒度 | 8-bit | M31 域限制：16-bit 乘积溢出 | 16-bit（溢出）/ 4-bit（列太多） |
| Carry range check | binary 分解 hi0/hi1（轻量） | 匹配 ADD/SUB 信任模型，度 ≤ 3 | 完整 RangeTable AIR（Phase 2 增强） |
| 有符号处理 | abs + sign flag + 补码调整 | 参考 OpenVM，清晰可验证 | 直接在有符号域计算（M31 无序） |
| DIV 约束 | q·d+r=n 恒等式 | 参考 SP1/OpenVM，标准方法 | 逐位除法（约束过多） |
| Carry 列共享 | MUL/DIV 共用 col 81–101 | one-hot 互斥，省列 | 独立列（浪费 21 列） |

### 4.2 Soundness 声明

**本方案实现的 soundness 级别**：
- ✅ 算术一致性完全约束（carry chain 验证乘法/除法正确性）
- ✅ Carry 高 2 位 binary 强制（限制 carry ∈ [0, 1023] 当 lo ∈ [0,255]）
- ⚠️ Carry 低 8 位 + 结果 limb 信任（与现有 ADD/SUB 一致，trace 生成保证）
- ⚠️ 不含完整 8-bit range check 组件

**未来增强（Phase 2，本文档不实现）**：
- 新增 `RangeLookup` relation（1-tuple）+ `RangeTableAir` 组件
- 对所有 carry_lo、abs limb、div limb 发送 8-bit range claim
- 实现完整 soundness（匹配 RISC Zero / SP1 级别）

### 4.3 度数预算验证

所有约束最大度 = 3（`indicator(1) × 表达式(≤2)`），符合 `max_constraint_log_degree_bound = log_size + 1`。关键验证：
- Carry chain：`is_mul(1) × Sₖ(2)` = 3 ✓
- Carry binality：`is_mul(1) × hi0(1) × (hi0−1)(1)` = 3 ✓
- Carry 重建：`is_mul(1) × (carry−lo−hi0·256−hi1·512)(1)` = 2 ✓
- DIV 恒等式：`is_div(1) × (q·d+r−n)(2)` = 3 ✓

---

## 5. 验证步骤

1. `cargo +nightly-2026-04-15 build -p poker_zkvm` — 编译通过
2. `cargo +nightly-2026-04-15 test -p poker_zkvm --lib` — 现有 568 测试 + 新增 M 扩展测试全通过
3. `cargo +nightly-2026-04-15 test -p poker_zkvm --test m_extension_constraints_e2e` — E2E 测试通过
4. `cargo +nightly-2026-04-15 test -p poker_zkvm --test texas_poker_guest_e2e` — 现有 E2E 不回归
5. `cargo +nightly-2026-04-15 test -p poker_zkvm --test texas_poker_guest_phase1` — Phase 1 不回归
6. Soundness 测试：篡改 M 扩展结果 → prove 必须失败

---

## 6. 文件修改清单

| 文件 | 操作 | 改动量 |
|------|------|--------|
| `src/stwo_backend/column_layout_v2.rs` | 修改 | +47 列常量，更新 NUM_COLUMNS/测试 |
| `src/stwo_backend/trace_native.rs` | 修改 | +3 helper 函数，step_to_m31_row 填充 M 扩展列 |
| `src/stwo_backend/cpu_air.rs` | 修改 | +~83 约束，+M 扩展 indicator 读取 |
| `src/stwo_backend/prover.rs` | 确认 | 无需改（用 NUM_COLUMNS 常量） |
| `tests/m_extension_constraints_e2e.rs` | 新建 | ~15 测试用例 |
