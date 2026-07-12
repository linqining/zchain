# Phase K: RV32IM M 扩展 — 约束层实现计划

## Summary

在已完成的 ISA 层（Instruction 枚举 + decode + execute + 测试，63 个 ISA 测试通过）基础上，
实现 M 扩展 8 条指令的约束层子电路（`algebra.rs`），包括：
- MUL/MULHU：无符号 64-bit 乘积分解（全约束，soundness 完整）
- MULH/MULHSU：有符号乘法 + 符号分解（全约束）
- DIV/DIVU/REM/REMU：MVP trust witness（soundness 依赖 witness 赋值，完整约束留给 Step 13 LogUp）

## Current State Analysis

### 已完成（ISA 层）
- [isa/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/isa/mod.rs)：Instruction 枚举 8 个 M 扩展 variant（L391-L463）、
  decode 0x33 funct7=0x01 的 8 个 arm（L655-L663）、execute 8 条指令语义含 RV32M 边界处理（L916-L972）
- [trace/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/trace/mod.rs)：M 扩展 tag 37-44 序列化/反序列化
- [constraints/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)：NUM_CATEGORIES=35、STEP_VARS=47、
  instruction_category M 扩展归入 category 31、extract_insn_fields M 扩展 variant

### 待实现（约束层）
- [constraints/algebra.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/algebra.rs)：当前 636 行，包含
  AddCircuit/SubCircuit/AndCircuit/OrCircuit/XorCircuit。需在 XorCircuit（L364）之后新增 8 个子电路。

### 关键设计约束
- **Fr = BN254 标量域**（~2^254 素数），64-bit 乘积在域中可直接表示，无溢出风险
- **CCS row-isolated 快速路径**：每个矩阵 ≤1 个 entry 时走 O(matrices + subsets) 快速路径
- **现有 witness 模式**：`[1, a, b, result, flag]`（5 var）或 `[1, a, b, result]`（4 var MVP trust witness）
- **AND/OR/XOR MVP 模式**：`build_ccs()` 返回 trivially satisfied 约束（result - result = 0），soundness 依赖 witness

## Proposed Changes

### 文件：`poker_zkvm/src/constraints/algebra.rs`

在 XorCircuit 之后（L364 附近，测试模块之前）新增以下 8 个子电路 + 辅助函数。

---

### Task #5: MUL / MULHU 子电路（无符号乘积分解）

**共用设计**：MUL 和 MULHU 共用 `build_ccs()` 和 `assign_witness()`，仅 `to_instance()` 的 public_inputs 不同。

**witness 布局**（6 变量）：
```
z = [1, a, b, product, hi, lo]
     0  1  2  3       4   5
```
- `product = (a as u64) * (b as u64)` — 64-bit 无符号乘积，Fr 中精确表示
- `hi = (product >> 32) as u32` — 高 32 位
- `lo = (product & 0xFFFFFFFF) as u32` — 低 32 位
- MUL: result = lo；MULHU: result = hi

**约束**（2 行）：
- Row 0: `a * b - product = 0`（乘法语义）
- Row 1: `product - hi * 2^32 - lo = 0`（64-bit 分解）

**矩阵**（6 个，每个 2×6，row-isolated）：
| 矩阵 | entry | 含义 |
|------|-------|------|
| M_a | (0, 1) = +1 | Row 0 选 a |
| M_b | (0, 2) = +1 | Row 0 选 b |
| M_prod_neg | (0, 3) = -1 | Row 0 选 -product |
| M_prod_pos | (1, 3) = +1 | Row 1 选 +product |
| M_hi | (1, 4) = -2^32 | Row 1 选 -2^32*hi |
| M_lo | (1, 5) = -1 | Row 1 选 -lo |

**子集**（5 个）：
| S_i | 矩阵索引 | c_i | 贡献行 | 语义 |
|-----|---------|-----|--------|------|
| S_0 | {0, 1} | +1 | Row 0 | +a*b |
| S_1 | {2} | +1 | Row 0 | -product |
| S_2 | {3} | +1 | Row 1 | +product |
| S_3 | {4} | +1 | Row 1 | -2^32*hi |
| S_4 | {5} | +1 | Row 1 | -lo |

**`MulCircuit::to_instance(a, b)`**：public_inputs = `[a, b, lo]`（MUL 结果 = lo）
**`MulhuCircuit::to_instance(a, b)`**：public_inputs = `[a, b, hi]`（MULHU 结果 = hi）

---

### Task #6: MULH / MULHSU 子电路（有符号乘法 + 符号分解）

#### MULH（有符号 × 有符号 → 高 32 位）

**witness 布局**（9 变量）：
```
z = [1, a, b, prod, hi, lo, a_sign, b_sign, neg_sign]
     0  1  2  3     4   5   6        7        8
```
- `a_sign = (a >> 31) & 1`，`b_sign = (b >> 31) & 1`
- `a_signed = a as i32 as i64`，`b_signed = b as i32 as i64`
- `product_signed = a_signed * b_signed`（i64，可负）
- `neg_sign = if product_signed < 0 { 1 } else { 0 }`
- `prod = product_signed as u64`（二补码 64-bit 表示）
- `hi = (prod >> 32) as u32`，`lo = (prod & 0xFFFFFFFF) as u32`
- MULH result = hi

**约束**（5 行）：
- Row 0: `a_sign² - a_sign = 0`（bit 检查）
- Row 1: `b_sign² - b_sign = 0`（bit 检查）
- Row 2: `neg_sign² - neg_sign = 0`（bit 检查）
- Row 3: `(a - 2^32*a_sign)*(b - 2^32*b_sign) - prod + 2^64*neg_sign = 0`
  - 展开后 6 个乘积项：`+a*b - 2^32*a*b_sign - 2^32*a_sign*b + 2^64*a_sign*b_sign - prod + 2^64*neg_sign`
- Row 4: `prod - hi*2^32 - lo = 0`（64-bit 分解）

**矩阵**（15 个，row-isolated）：
- Row 0（a_sign bit）：M_as_pos_r0 (0,6)=+1, M_as_neg_r0 (0,6)=-1
- Row 1（b_sign bit）：M_bs_pos_r1 (1,7)=+1, M_bs_neg_r1 (1,7)=-1
- Row 2（neg_sign bit）：M_ns_pos_r2 (2,8)=+1, M_ns_neg_r2 (2,8)=-1
- Row 3（乘积约束）：
  - M_a_r3 (3,1)=+1, M_b_r3 (3,2)=+1, M_as_r3 (3,6)=+1, M_bs_r3 (3,7)=+1
  - M_prod_neg_r3 (3,3)=-1, M_ns_r3 (3,8)=+1
- Row 4（分解）：M_prod_pos_r4 (4,3)=+1, M_hi_r4 (4,4)=-2^32, M_lo_r4 (4,5)=-1

**子集**（15 个）：
| S_i | 矩阵索引 | c_i | 行 | 语义 |
|-----|---------|-----|-----|------|
| S_0 | {0, 0} | +1 | 0 | +a_sign² |
| S_1 | {1} | +1 | 0 | -a_sign |
| S_2 | {2, 2} | +1 | 1 | +b_sign² |
| S_3 | {3} | +1 | 1 | -b_sign |
| S_4 | {4, 4} | +1 | 2 | +neg_sign² |
| S_5 | {5} | +1 | 2 | -neg_sign |
| S_6 | {6, 7} | +1 | 3 | +a*b |
| S_7 | {6, 8} | -2^32 | 3 | -2^32*a*b_sign |
| S_8 | {9, 7} | -2^32 | 3 | -2^32*a_sign*b |
| S_9 | {9, 8} | +2^64 | 3 | +2^64*a_sign*b_sign |
| S_10 | {10} | +1 | 3 | -prod |
| S_11 | {11} | +2^64 | 3 | +2^64*neg_sign |
| S_12 | {12} | +1 | 4 | +prod |
| S_13 | {13} | +1 | 4 | -2^32*hi |
| S_14 | {14} | +1 | 4 | -lo |

> 注意：S_0 = {0, 0} 表示矩阵 0 出现两次（平方项），与 AddCircuit 的 `vec![4, 4]` 模式一致。

#### MULHSU（有符号 × 无符号 → 高 32 位）

**witness 布局**（8 变量）：
```
z = [1, a, b, prod, hi, lo, a_sign, neg_sign]
     0  1  2  3     4   5   6        7
```
- `a_sign = (a >> 31) & 1`，`a_signed = a as i32 as i64`
- `b_unsigned = b as u64 as i64`（始终非负）
- `product_signed = a_signed * b_unsigned`（i64，可负）
- `neg_sign = if product_signed < 0 { 1 } else { 0 }`
- `prod = product_signed as u64`，`hi = (prod >> 32) as u32`，`lo = (prod & 0xFFFFFFFF) as u32`
- MULHSU result = hi

**约束**（4 行）：
- Row 0: `a_sign² - a_sign = 0`
- Row 1: `neg_sign² - neg_sign = 0`
- Row 2: `(a - 2^32*a_sign)*b - prod + 2^64*neg_sign = 0`
  - 展开后 4 项：`+a*b - 2^32*a_sign*b - prod + 2^64*neg_sign`
- Row 3: `prod - hi*2^32 - lo = 0`

**矩阵**（12 个，row-isolated）：
- Row 0: M_as_pos_r0 (0,6)=+1, M_as_neg_r0 (0,6)=-1
- Row 1: M_ns_pos_r1 (1,7)=+1, M_ns_neg_r1 (1,7)=-1
- Row 2: M_a_r2 (2,1)=+1, M_b_r2 (2,2)=+1, M_as_r2 (2,6)=+1, M_prod_neg_r2 (2,3)=-1, M_ns_r2 (2,7)=+1
- Row 3: M_prod_pos_r3 (3,3)=+1, M_hi_r3 (3,4)=-2^32, M_lo_r3 (3,5)=-1

**子集**（11 个）：
| S_i | 矩阵索引 | c_i | 行 | 语义 |
|-----|---------|-----|-----|------|
| S_0 | {0, 0} | +1 | 0 | +a_sign² |
| S_1 | {1} | +1 | 0 | -a_sign |
| S_2 | {2, 2} | +1 | 1 | +neg_sign² |
| S_3 | {3} | +1 | 1 | -neg_sign |
| S_4 | {4, 5} | +1 | 2 | +a*b |
| S_5 | {6, 5} | -2^32 | 2 | -2^32*a_sign*b |
| S_6 | {7} | +1 | 2 | -prod |
| S_7 | {8} | +2^64 | 2 | +2^64*neg_sign |
| S_8 | {9} | +1 | 3 | +prod |
| S_9 | {10} | +1 | 3 | -2^32*hi |
| S_10 | {11} | +1 | 3 | -lo |

---

### Task #7: DIV / DIVU / REM / REMU 子电路（MVP trust witness）

**设计**：与 AndCircuit/OrCircuit/XorCircuit 相同的 MVP trust witness 模式。
- `build_ccs()` 返回 trivially satisfied 约束（result - result = 0）
- `assign_witness()` 按 RV32M 语义计算 result（含边界处理）
- soundness 依赖 witness 赋值，完整约束留给 Step 13 LogUp

**witness 布局**（4 变量）：`z = [1, a, b, result]`

**约束**（1 行）：`result - result = 0`（trivially satisfied）

**矩阵**（2 个，1×4）：
- M_result_pos: (0, 3) = +1
- M_result_neg: (0, 3) = -1

**子集**：S_0 = {0}, c_0 = +1（+result）；S_1 = {1}, c_1 = +1（-result）

**assign_witness 语义**（RV32M 边界处理）：
| 指令 | b=0 | 溢出（a=INT_MIN, b=-1） | 正常 |
|------|-----|------------------------|------|
| DIV | result = -1 (0xFFFFFFFF) | result = INT_MIN (0x80000000) | a / b (signed) |
| DIVU | result = 0xFFFFFFFF | N/A | a / b (unsigned) |
| REM | result = a | result = 0 | a % b (signed) |
| REMU | result = a | N/A | a % b (unsigned) |

四个电路共用 `build_ccs()`（与 OrCircuit/XorCircuit 复用 AndCircuit::build_ccs 模式一致）。

---

### Task #8: 测试

在 `algebra.rs` 的 `#[cfg(test)] mod tests` 中新增测试，每个子电路覆盖：
1. **normal case**：正常输入，验证 `satisfied_by` 返回 true
2. **tampered witness**：篡改 result/关键变量，验证 `satisfied_by` 返回 false
3. **boundary cases**：RV32M 边界值（0、MAX、MIN、b=0、溢出）
4. **to_instance**：验证 public_inputs 正确

**测试清单**（约 40 个新测试）：

**MUL/MULHU**（~10 个）：
- `test_mul_basic`：7 * 6 = 42，lo=42, hi=0
- `test_mul_large`：0xFFFF * 0xFFFF = 0xFFFE0001，lo=0xFFFE0001, hi=0
- `test_mul_high_bits`：0x10000 * 0x10000 = 0x100000000，lo=0, hi=1
- `test_mul_zero`：0 * x = 0
- `test_mul_max`：0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
- `test_mulhu_basic`：验证 hi 为结果
- `test_mulhu_max`：0xFFFFFFFF * 0xFFFFFFFF → hi=0xFFFFFFFE
- `test_mul_soundness_tampered_lo`
- `test_mul_soundness_tampered_hi`
- `test_mul_to_instance`

**MULH/MULHSU**（~12 个）：
- `test_mulh_pos_pos`：2 * 3 = 6, hi=0
- `test_mulh_neg_neg`：(-1) * (-1) = 1, hi=0
- `test_mulh_neg_pos`：(-2) * 3 = -6, hi=0xFFFFFFFF
- `test_mulh_pos_neg`：3 * (-2) = -6, hi=0xFFFFFFFF
- `test_mulh_min_min`：INT_MIN * INT_MIN = 2^62, hi=0x40000000
- `test_mulh_overflow_div`：INT_MIN * (-1) = 2^31, hi=0
- `test_mulhsu_neg_unsigned`：(-1) * 0xFFFFFFFF = -(0xFFFFFFFF), hi=0xFFFFFFFF
- `test_mulhsu_pos_unsigned`：2 * 3 = 6, hi=0
- `test_mulhsu_min_unsigned`：INT_MIN * 0xFFFFFFFF
- `test_mulh_soundness_tampered_hi`
- `test_mulh_soundness_tampered_sign`
- `test_mulh_to_instance`

**DIV/DIVU/REM/REMU**（~16 个）：
- `test_div_basic`：100 / 7 = 14
- `test_div_by_zero`：100 / 0 = -1
- `test_div_overflow`：INT_MIN / -1 = INT_MIN
- `test_div_neg`：(-100) / 7 = -14
- `test_divu_basic`：100 / 7 = 14
- `test_divu_by_zero`：100 / 0 = 0xFFFFFFFF
- `test_rem_basic`：100 % 7 = 2
- `test_rem_by_zero`：100 % 0 = 100
- `test_rem_overflow`：INT_MIN % -1 = 0
- `test_rem_neg`：(-100) % 7 = -2
- `test_remu_basic`：100 % 7 = 2
- `test_remu_by_zero`：100 % 0 = 100
- `test_div_to_instance` / `test_divu_to_instance`
- `test_rem_to_instance` / `test_remu_to_instance`

---

### Task #9: 验证

1. `cargo build` 无 warning
2. `cargo test -p poker_zkvm --lib constraints::algebra` 全部通过
3. `cargo test -p poker_zkvm --lib isa` 回归通过（63 个测试）
4. `cargo clippy -p poker_zkvm --lib -- -D warnings` 无新 warning
5. 全量回归：`cargo test -p poker_zkvm` 全部通过

---

## Assumptions & Decisions

1. **Fr 域容量**：BN254 标量域 p ≈ 2^254 >> 2^64，所有 64-bit 乘积和 2^64 系数在 Fr 中精确表示，无模约简。
2. **2^64 辅助函数**：新增 `two_pow_64()` 返回 `two_pow_32().mul(&two_pow_32())`，因为 `1u64 << 64` 溢出 u64。
3. **MUL/MULHU 共用 CCS**：build_ccs 和 assign_witness 完全相同，仅 to_instance 的 public_inputs 不同（lo vs hi）。
   与 OrCircuit/XorCircuit 复用 AndCircuit::build_ccs 模式一致。
4. **MULH/MULHSU 全约束**：含符号分解（a_sign, b_sign, neg_sign）和 bit 检查，soundness 完整。
   hi/lo 的 u32 range check 留给 Step 13 LogUp（与 AddCircuit 的 result range check 策略一致）。
5. **DIV/DIVU/REM/REMU trust witness**：与 AND/OR/XOR 一致的 MVP 模式，约束 trivially satisfied。
   完整除法约束（a = q*b + r）和 range check 留给 Step 13。
6. **row-isolated 快速路径**：所有新矩阵均 ≤1 entry，走 `satisfied_by_row_isolated` 快速路径。
7. **平方项子集表示**：`vec![idx, idx]` 表示同一矩阵出现两次（平方），与 AddCircuit L80 `vec![4, 4]` 一致。

## Verification Steps

1. 编译：`cargo build -p poker_zkvm` 无错误无 warning
2. 约束测试：`cargo test -p poker_zkvm --lib constraints::algebra` — 预期 ~80+ 测试通过（现有 ~40 + 新增 ~40）
3. ISA 回归：`cargo test -p poker_zkvm --lib isa` — 预期 63 测试通过
4. Clippy：`cargo clippy -p poker_zkvm --lib -- -D warnings` 无新 warning
5. 全量回归：`cargo test -p poker_zkvm` 全部通过
