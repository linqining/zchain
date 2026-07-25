# V7 + V8 安全漏洞修复实施计划（byte-level 内存模型版）

> **关联文档**：
>
> * 审计报告：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md` §V7、§V8
>
> * 上一版计划：`.trae/documents/poker_zkvm_v7v8_fix_plan.md`（结构性约束版，已废弃）
>   **本计划状态**：待批准
>   **用户决策**：方案 C — 完整 byte-level 内存模型

***

## 1. Summary（摘要）

本计划用 **byte-level 内存模型**修复 V7（Load 符号/零扩展未约束），并用运行时 guard 修复 V8（SHA-256 AIR 约束不完整）。

**V7 核心改动**：将 emulator 的 `MemAccess.value` 从「扩展后值」改为「原始值（raw byte/halfword/word）」，使内存 logup 验证的是原始值而非扩展值；在 CPU AIR 中用约束从「验证后的原始值 + load subtype」**推导**出 rd\_eff，而非信任 prover 提供的扩展值。这同时修复了一个潜在的内存连续性 bug（LB 与 LBU 同址读取产生不同 MemValCur 会破坏 continuity）。

**V8 核心改动**：在 `Sha256Air::new()` 中加 panic guard 防误用，并文档化已知 gap。

**残留 gap（诚实声明）**：load subtype（LB/LBU/LH/LHU/LW）由 prover 设置，AIR 不验证其与实际指令一致。要完全闭合此 gap，需引入程序内存承诺（Merkle root 作为 public input）+ 指令 fetch/decoder 约束。这是独立的架构级功能（影响所有指令绑定，非 V7 专属），列为后续 Stage 2 工作。

***

## 2. Current State Analysis（现状分析）

### 2.1 当前 Load 数据流（V7 漏洞根源）

1. **Emulator**（`src/isa/mod.rs::execute` L827-881）：

   * LB: `val = read_memory_byte(addr) as i8 as i32 as u32` → **符号扩展值**存入 `MemAccess.value`

   * LBU: `val = read_memory_byte(addr) as u32` → 零扩展值

   * LH: `val = read_memory_halfword(addr) as i16 as i32 as u32` → 符号扩展值

   * LHU: `val = read_memory_halfword(addr) as u32` → 零扩展值

   * LW: `val = read_memory_word(addr)` → 原始 word

2. **Trace**（`src/trace/mod.rs` L73-83）：`MemAccess { addr, op, value, size }`，`value` = 扩展后值。

3. **CPU trace 填充**（`src/stwo_backend/trace_native.rs` L491-505）：`helper_b_value = extract_mem_value(...)` = `mem_access[0].value`（扩展后值），写入 `COL_HELPER_B_BASE`。

4. **Memory trace 填充**（`src/stwo_backend/trace_native.rs` L1648-1649）：`MemValCur = entry.value`（扩展后值）。

5. **CPU AIR 约束**（`src/stwo_backend/cpu_air.rs` L744-747）：`rd_eff[i] = HelperB[i]`（gated by IS\_LOAD）。

6. **Memory AIR logup**：链接 `(addr, value, is_store)` 于 CPU 与 Memory 之间——但两侧都用相同的扩展后值，故 logup 一致却可能都是错的。

### 2.2 V7 攻击面

恶意 prover 可将 LB 的符号扩展替换为零扩展（如 0xFF → 0x000000FF 而非 0xFFFFFFFF）。CPU 与 Memory 两侧一致（都用错误扩展值），logup 通过，但 rd\_eff 错误。

### 2.3 潜在的内存连续性 bug（附带修复）

若程序对同一字节地址先 LB（得 0xFFFFFFFF）后 LBU（得 0x000000FF），中间无写，则 MemoryAir 的 continuity 约束 `ValPrev = prev.ValCur` 会失败（0x000000FF ≠ 0xFFFFFFFF）。改为存储原始值后，两者均为 0xFF，连续性成立。

### 2.4 架构事实（影响修复范围）

* opcode/func3 **不在** trace 中（无指令字 witness 列）。

* 无程序内存承诺（无 Merkle root public input）。

* `instruction_to_indicator_col`（`trace_native.rs` L1404-1452）将 5 种 load 全部映射到单一 `IS_LOAD`（col 32）。

* M 扩展列（col 81-131）在 Load 行空闲（Load 与 MUL/DIV indicator one-hot 互斥）。

* `max_constraint_log_degree_bound = log_size + 1`，支持度 ≤ 3 的约束（见 `cpu_air.rs` L279-283）。

### 2.5 RISC Zero 参考（用户问「risc zero 怎么处理」的结论）

RISC Zero（Zirgen DSL，`risc0/zirgen` 仓库）：

1. **内存存原始 word**（word-level，`ValU32` 双 16 位），扩展在指令电路内做。
2. **LB**：用 `NondetBitReg` 见证符号位 + `NondetU8Reg`（翻倍技巧）见证低位，约束 `val = highBit*0x80 + low7x2/2`，结果 `ValU32(low8 + 0xff00*highBit, 0xffff*highBit)`。
3. **LBU**：直接 `ValU32(low8, 0)`，高位置 0，无需符号位见证。
4. **类型绑定**：`OneHot<8>(func3)` mux + 每个 OpXX 内 `VerifyOpcodeF3` 复核 opcode/func3——**这需要指令字在 trace 中**（poker\_zkvm 当前不具备）。

**结论**：poker\_zkvm 可复刻 RISC Zero 的「原始值 + 扩展约束」部分（V7 核心），但「类型绑定」部分需程序内存承诺（Stage 2）。

***

## 3. V7 修复设计（byte-level 内存模型）

### 3.1 核心思路

| 项目                        | 当前                     | 修复后                                                 |
| ------------------------- | ---------------------- | --------------------------------------------------- |
| `MemAccess.value`（Load）   | 扩展后值                   | **原始值**（raw byte/halfword/word）                     |
| `HelperB`（Load 行）         | 扩展后值                   | **原始值**                                             |
| `MemValCur`（Memory trace） | 扩展后值                   | **原始值**（logup 验证原始值）                                |
| Load 值约束                  | `rd_eff = HelperB`（信任） | **rd\_eff = extend(HelperB, load\_subtype)**（约束推导）  |
| Load subtype 区分           | 无（单一 IS\_LOAD）         | **IS\_LOAD\_BYTE/HALF/SIGN + LOAD\_BITS**（复用 M 扩展列） |

**安全收益**：原始值经 logup 验证（不可伪造），扩展由约束从原始值推导（不可自由选择）。prover 只能在「合法符号扩展」与「合法零扩展」间二选一，不能再选任意值。

### 3.2 Emulator 改动（`src/isa/mod.rs::execute`）

将 LB/LH 的 `MemAccess.value` 改为原始值，寄存器写入保持扩展值：

```rust
Instruction::Lb { rd, rs1, imm } => {
    let addr = state.read_register(rs1).wrapping_add(imm);
    let raw = state.read_memory_byte(addr)? as u32;          // 原始字节
    let val = raw as i8 as i32 as u32;                        // 扩展值（写入 rd）
    state.write_register(rd, val);
    mem_access.push(MemAccess { addr, op: MemOp::Read, value: raw, size: 1 });  // ← raw
}
Instruction::Lh { rd, rs1, imm } => {
    let addr = state.read_register(rs1).wrapping_add(imm);
    let raw = state.read_memory_halfword(addr)? as u32;       // 原始半字
    let val = raw as i16 as i32 as u32;                       // 扩展值
    state.write_register(rd, val);
    mem_access.push(MemAccess { addr, op: MemOp::Read, value: raw, size: 2 });  // ← raw
}
// LBU / LHU / LW：value 已经是原始值，无需改动
// LBU: value = read_memory_byte(addr) as u32        (已是 raw)
// LHU: value = read_memory_halfword(addr) as u32    (已是 raw)
// LW:  value = read_memory_word(addr)               (已是 raw)
// Store：value = rs2_value（保持不变）
```

**影响**：现有测试中检查 `mem_access[0].value` 的断言需更新（raw 而非扩展值）。

### 3.3 新增 witness 列（`src/stwo_backend/column_layout_v2.rs`）

复用 M 扩展列（81-91），Load 行与 MUL/DIV 互斥，安全复用：

| 复用列       | 新常量                  | 含义                                       |
| --------- | -------------------- | ---------------------------------------- |
| col 81    | `COL_IS_LOAD_BYTE`   | binary：1=LB/LBU（byte load）               |
| col 82    | `COL_IS_LOAD_HALF`   | binary：1=LH/LHU（halfword load）           |
| col 83    | `COL_IS_LOAD_SIGN`   | binary：1=LB/LH（sign-extend），0=LBU/LHU/LW |
| col 84    | `COL_SIGN_BIT`       | binary：原始值符号位（byte=bit7，halfword=bit15）  |
| col 85-92 | `COL_LOAD_BITS_BASE` | 8 binary：符号承载字节的位分解                      |

```rust
// 复用 M 扩展列（Load 行互斥），仅 Load 行非 0
pub const COL_IS_LOAD_BYTE: usize = 81;   // reuse COL_MUL_CARRY_LO_BASE + 0
pub const COL_IS_LOAD_HALF: usize = 82;   // reuse COL_MUL_CARRY_LO_BASE + 1
pub const COL_IS_LOAD_SIGN: usize = 83;   // reuse COL_MUL_CARRY_LO_BASE + 2
pub const COL_SIGN_BIT: usize = 84;       // reuse COL_MUL_CARRY_LO_BASE + 3
pub const COL_LOAD_BITS_BASE: usize = 85; // reuse COL_MUL_CARRY_LO_BASE + 4..6 + COL_MUL_CARRY_HI0_BASE + 0..4
pub const COL_LOAD_BITS_COUNT: usize = 8; // 8 个 binary bit
```

注：不改变 `NUM_COLUMNS`（仍 132），仅复用空闲列。

### 3.4 trace\_native.rs 改动（witness 填充）

在 `step_to_m31_row` 的 Load 分支中新增填充：

```rust
// ----- V7: Load subtype + bit 分解（复用 M 扩展列，仅 Load 行非 0）-----
let (is_load_byte, is_load_half, is_load_sign, sign_bit, load_bits_byte) = match &step.instruction {
    Instruction::Lb { .. } => {
        let raw_byte = (helper_b_value & 0xFF) as u8;       // HelperB[0] = raw byte
        (1, 0, 1, (raw_byte >> 7) & 1, raw_byte)
    }
    Instruction::Lbu { .. } => {
        let raw_byte = (helper_b_value & 0xFF) as u8;
        (1, 0, 0, (raw_byte >> 7) & 1, raw_byte)
    }
    Instruction::Lh { .. } => {
        let raw_hi_byte = ((helper_b_value >> 8) & 0xFF) as u8;  // HelperB[1] = 高字节（含 bit15）
        (0, 1, 1, (raw_hi_byte >> 7) & 1, raw_hi_byte)
    }
    Instruction::Lhu { .. } => {
        let raw_hi_byte = ((helper_b_value >> 8) & 0xFF) as u8;
        (0, 1, 0, (raw_hi_byte >> 7) & 1, raw_hi_byte)
    }
    Instruction::Lw { .. } => (0, 0, 0, 0, 0),
    _ => (0, 0, 0, 0, 0),
};
row[COL_IS_LOAD_BYTE] = M31::from(is_load_byte);
row[COL_IS_LOAD_HALF] = M31::from(is_load_half);
row[COL_IS_LOAD_SIGN] = M31::from(is_load_sign);
row[COL_SIGN_BIT] = M31::from(sign_bit);
for i in 0..8 {
    row[COL_LOAD_BITS_BASE + i] = M31::from((load_bits_byte >> i) & 1);
}
```

注意：`helper_b_value` 现在是**原始值**（因 emulator 改动），故位分解基于原始值。

### 3.5 cpu\_air.rs 改动（约束）

**删除**当前约束 44-47（`rd_eff[i] = HelperB[i]`，`cpu_air.rs` L744-747），**替换**为以下约束（均度 ≤ 3）：

#### (a) Load subtype binality + gating（度 2，共 8 条）

```
IS_LOAD_BYTE · (IS_LOAD_BYTE - 1) = 0
IS_LOAD_HALF · (IS_LOAD_HALF - 1) = 0
IS_LOAD_SIGN · (IS_LOAD_SIGN - 1) = 0
SIGN_BIT · (SIGN_BIT - 1) = 0
(1 - IS_LOAD) · IS_LOAD_BYTE = 0          // 非 Load 行 IS_LOAD_BYTE=0
(1 - IS_LOAD) · IS_LOAD_HALF = 0
(1 - IS_LOAD) · IS_LOAD_SIGN = 0
IS_LOAD_BYTE · IS_LOAD_HALF = 0            // byte/halfword 互斥
```

#### (b) LOAD\_BITS binality（度 2，8 条）

```
LOAD_BITS[i] · (LOAD_BITS[i] - 1) = 0    for i in 0..8
```

#### (c) 位分解正确性（度 2，2 条）

```
IS_LOAD_BYTE · (HelperB[0] - Σ LOAD_BITS[i]·2^i) = 0    // byte load: 分解 HelperB[0]
IS_LOAD_HALF · (HelperB[1] - Σ LOAD_BITS[i]·2^i) = 0    // halfword load: 分解 HelperB[1]（高字节）
```

#### (d) SIGN\_BIT 一致性（度 2，2 条）

```
IS_LOAD_BYTE · (SIGN_BIT - LOAD_BITS[7]) = 0
IS_LOAD_HALF · (SIGN_BIT - LOAD_BITS[7]) = 0
```

#### (e) 扩展结构约束（度 ≤ 3，14 条）

定义 gate：`is_lb = IS_LOAD_BYTE · IS_LOAD_SIGN`，`is_lbu = IS_LOAD_BYTE · (1 - IS_LOAD_SIGN)`，`is_lh = IS_LOAD_HALF · IS_LOAD_SIGN`，`is_lhu = IS_LOAD_HALF · (1 - IS_LOAD_SIGN)`，`is_lw = IS_LOAD · (1 - IS_LOAD_BYTE - IS_LOAD_HALF)`（度 2）。

**LB（符号扩展 byte）**：

```
is_lb · (rd_eff[0] - HelperB[0]) = 0          // 度 3
is_lb · (rd_eff[1] - SIGN_BIT · 0xFF) = 0    // 度 3
is_lb · (rd_eff[2] - SIGN_BIT · 0xFF) = 0
is_lb · (rd_eff[3] - SIGN_BIT · 0xFF) = 0
```

**LBU（零扩展 byte）**：

```
is_lbu · (rd_eff[0] - HelperB[0]) = 0        // 度 3
is_lbu · rd_eff[1] = 0                        // 度 3（upper bytes = 0）
is_lbu · rd_eff[2] = 0
is_lbu · rd_eff[3] = 0
```

**LH（符号扩展 halfword）**：

```
is_lh · (rd_eff[0] - HelperB[0]) = 0         // 度 3
is_lh · (rd_eff[1] - HelperB[1]) = 0
is_lh · (rd_eff[2] - SIGN_BIT · 0xFF) = 0
is_lh · (rd_eff[3] - SIGN_BIT · 0xFF) = 0
```

**LHU（零扩展 halfword）**：

```
is_lhu · (rd_eff[0] - HelperB[0]) = 0        // 度 3
is_lhu · (rd_eff[1] - HelperB[1]) = 0
is_lhu · rd_eff[2] = 0                        // 度 3
is_lhu · rd_eff[3] = 0
```

**LW（identity）**：

```
is_lw · (rd_eff[i] - HelperB[i]) = 0  for i in 0..4   // 度 3
```

注：`is_lw = IS_LOAD · (1 - IS_LOAD_BYTE - IS_LOAD_HALF)`，因 IS\_LOAD\_BYTE 与 IS\_LOAD\_HALF 互斥且非 Load 行为 0，故 `1 - sum` ∈ {0,1}，gate 度 2，约束度 3 ✓。

### 3.6 MemoryAir（无结构变更，语义变更）

MemoryAir **结构不变**（仍 17 列），但 `MemValCur` 语义从「扩展后值」变为「原始值」。此变更通过 emulator + trace\_native 的填充改动自动生效，**无需修改 memory\_air.rs 约束代码**。logup 仍链接 `(addr, value, is_store)`，现在 value = 原始值。

### 3.7 残留 gap 文档化

**残留攻击**：prover 可设置 `IS_LOAD_SIGN=0`（声称 LBU）执行 LB，对负字节使用零扩展。此攻击需篡改 witness（IS\_LOAD\_SIGN 等），且仅对 bit7=1 的字节有效。

**完全闭合需 Stage 2**：程序内存承诺（Merkle root 作为 public input）+ 指令 fetch 约束（PC → instruction word lookup）+ decoder 约束（instruction word → opcode/func3）。这是独立架构功能（影响所有指令绑定），超出 V7 MEDIUM 修复范围。

***

## 4. V8 修复设计（SHA-256 AIR 运行时 guard）

### 4.1 运行时 Guard（`src/stwo_backend/sha256_air.rs`）

将 `Sha256Air::new()` 改为 panic（注意：`new` 当前是 `const fn`，panic 在 const 上下文中需用 `panic!` 宏，Rust 1.57+ 支持 const panic）：

```rust
pub const fn new(log_size: u32, sha256_lookup: Sha256Lookup) -> Self {
    // V8 运行时 guard：约束未完成，禁止在任何 proof path 中使用
    panic!(
        "Sha256Air is INCOMPLETE (V8 known gap): \
         compression function / message schedule / round boundary \
         constraints not implemented. Do not use in any proof path \
         until Step 5.2 constraints are complete."
    );
}
```

若 `const fn` panic 导致编译期问题，改为非 const 的普通 `fn` + 运行时 `panic!`。

### 4.2 文档化（`sha256_air.rs` 模块注释）

更新模块注释 §「状态」，明确标注 V8 MEDIUM 已知 gap 与完整修复所需步骤。

### 4.3 测试（`sha256_air.rs`）

```rust
#[test]
#[should_panic(expected = "Sha256Air is INCOMPLETE")]
fn test_sha256_air_guard_panics() {
    let _ = Sha256Air::new(10, Sha256Lookup::dummy());
}
```

更新 `test_sha256_air_new` / `test_sha256_air_max_constraint_log_degree_bound`：这两个测试当前调用 `Sha256Air::new` 会触发 panic，需移除或改为 `#[should_panic]`。

***

## 5. 文件变更清单

| 文件                                     | 变更                                 | 说明                                                    |
| -------------------------------------- | ---------------------------------- | ----------------------------------------------------- |
| `src/isa/mod.rs`                       | 修改 LB/LH 的 `MemAccess.value` 为 raw | V7 核心：emulator 存原始值                                   |
| `src/stwo_backend/column_layout_v2.rs` | 新增 5 个列常量                          | IS\_LOAD\_BYTE/HALF/SIGN, SIGN\_BIT, LOAD\_BITS\_BASE |
| `src/stwo_backend/trace_native.rs`     | 填充 load subtype + bit 分解           | witness 填充                                            |
| `src/stwo_backend/cpu_air.rs`          | 删约束 44-47，加 \~34 条扩展约束             | V7 核心：约束推导扩展                                          |
| `src/stwo_backend/sha256_air.rs`       | new() panic guard + 注释 + 测试        | V8 防误用                                                |
| `src/stwo_backend/prover.rs`           | 更新 load 测试 + 新增 soundness 测试       | 验证修复                                                  |
| `src/isa/mod.rs` 测试                    | 更新 `mem_access.value` 断言           | raw 而非扩展值                                             |

***

## 6. 验证步骤

```bash
# 编译
cargo +nightly-2026-04-15 build -p poker_zkvm

# V7 单元测试（emulator raw value）
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "execute_lb" "execute_lh" "execute_lbu" "execute_lhu"

# V7 soundness 测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "load_sign_ext" "load_zero_ext" "load_soundness"

# V8 guard 测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "sha256_air_guard"

# 全量回归
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```

**预期**：全量通过（更新后的 load 测试 + 新增 V7 soundness + V8 guard），0 回归。

***

## 7. Soundness 测试设计（prover.rs）

| 测试名                                    | 场景                                  | 预期                                                                   |
| -------------------------------------- | ----------------------------------- | -------------------------------------------------------------------- |
| `test_load_sign_ext_byte_positive`     | LB 0x7F → rd\_eff=0x0000007F        | prove 成功                                                             |
| `test_load_sign_ext_byte_negative`     | LB 0xFF → rd\_eff=0xFFFFFFFF        | prove 成功                                                             |
| `test_load_zero_ext_byte`              | LBU 0xFF → rd\_eff=0x000000FF       | prove 成功                                                             |
| `test_load_sign_ext_halfword`          | LH 0xFF80 → rd\_eff=0xFFFFFF80      | prove 成功                                                             |
| `test_load_zero_ext_halfword`          | LHU 0xFFFF → rd\_eff=0x0000FFFF     | prove 成功                                                             |
| `test_load_word`                       | LW 0xDEADBEEF → rd\_eff=0xDEADBEEF  | prove 成功                                                             |
| `test_load_soundness_tamper_extension` | LB 0xFF 但篡改 rd\_eff=0x000000FF（零扩展） | prove 失败：约束 `is_lb·(rd_eff[1] - SIGN_BIT·0xFF) = 1·(0 - 1·0xFF) ≠ 0` |
| `test_load_soundness_tamper_raw_value` | LB 0xFF 但篡改 HelperB\[0]=0x7F（raw 值） | prove 失败：logup 不一致（memory 侧仍为 0xFF）                                  |

***

## 8. 实施顺序

1. **V7.1** — `column_layout_v2.rs`：新增列常量 + 单元测试
2. **V7.2** — `isa/mod.rs`：改 LB/LH 存 raw value + 更新 emulator 测试
3. **V7.3** — `trace_native.rs`：填充 load subtype + bit 分解 witness
4. **V7.4** — `cpu_air.rs`：删旧约束 44-47，加扩展约束
5. **V7.5** — `prover.rs`：更新 load 测试 + 新增 soundness 测试
6. **V8.1** — `sha256_air.rs`：guard + 注释 + 测试
7. **验证** — 编译 + V7 测试 + V8 测试 + 全量回归

***

## 9. Assumptions & Decisions（假设与决策）

1. **复用 M 扩展列**：Load 与 MUL/DIV indicator one-hot 互斥（同一行不可能既是 Load 又是 MUL），故 col 81-131 在 Load 行空闲，可安全复用。不改变 NUM\_COLUMNS。
2. **不引入 word-level 内存**：保持 byte-level 地址（addr 为字节地址），仅改变 `MemValCur` 语义为原始值。避免 SB/SH read-modify-write 的大改。功能上等价于 RISC Zero 的扩展验证。
3. **度 ≤ 3**：所有新约束度 ≤ 3，匹配现有 M 扩展约束，`max_constraint_log_degree_bound = log_size + 1` 已支持。
4. **load subtype 不绑定指令**：诚实承认残留 gap。Stage 2（程序内存承诺）为后续独立工作。
5. **V8 用 panic guard**：Sha256Air 未在任何 proof path 使用，panic guard 防未来误用，成本最低。

