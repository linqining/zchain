# V7 + V8 安全漏洞修复实施计划

> **关联文档**：
> - 审计报告：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md` §V7、§V8
> - 剩余修复计划：`.trae/documents/poker_zkvm_security_remaining_remediation_plan.md`
> **本计划状态**：待批准

---

## 1. Context（背景与问题）

### V7 — Load 符号/零扩展未约束（MEDIUM）

**问题**：LB/LH 做符号扩展，LBU/LHU 做零扩展。emulator 计算扩展后的 32-bit 值存入 `mem_access[0].value`，trace 写入 HelperB 列，AIR 约束 `rd_eff = HelperB`。但 AIR **不验证扩展正确性**——恶意 prover 可将 LB 的符号扩展替换为零扩展（如 0xFF → 0x000000FF 而非 0xFFFFFFFF），且 CPU/Memory logup 仍一致（两侧都用相同的错误值）。

**根因分析**：
- MemoryAir 存储 `MemValCur = mem_access[0].value = 扩展后值`（非原始 word）
- CPU 查找 claim 也用扩展后值（`mem_value = is_load * rd_eff`）
- 两侧一致但都可能是错误的扩展
- IS_LOAD（col 32）覆盖全部 5 种 load 类型，AIR 无法区分 LB/LBU

**V7 完整修复的限制**：完整修复需将 memory model 改为 byte-level（RISC Zero 方案），存储原始 word 并在 AIR 中约束 byte 提取 + 扩展。这是架构级变更，超出 MEDIUM 级修复范围。

**本计划方案（结构性约束 + 已知 gap 文档化）**：
- 添加扩展结构约束：upper bytes 必须 all-0 或 all-0xFF
- 添加 sign bit 一致性约束：upper=0xFF → byte bit7=1；upper=0x00 → byte bit7=0
- 添加 load size 约束（byte/halfword/word）
- **已知残留 gap**：prover 仍可选择零扩展代替符号扩展（零扩展结构合法）。完整修复需 byte-level memory model。

### V8 — SHA-256 AIR 约束不完整（MEDIUM）

**问题**：`sha256_air.rs` 有多处 TODO 标记（compression function 约束、message schedule、round boundary 等），`evaluate` 仅实现基本 binality 约束。

**关键发现**：Sha256Air **未在任何 proof path 中使用**——仅声明为 module（`mod.rs:45`），无任何 prover 函数调用它。不完整约束不影响当前任何证明。

**本计划方案**：添加运行时 guard 防止误用 + 文档化已知 gap。

---

## 2. V7 修复设计

### 2.1 新增 witness 列（复用 M 扩展列，Load 行互斥）

Load 指令与 MUL/DIV one-hot 互斥，M 扩展列（81-131）在 Load 行全部空闲。

| 复用列 | 新用途 | 说明 |
|--------|--------|------|
| col 81 | `IS_LOAD_BYTE` | binary：1=LB/LBU（byte load），0=其他 |
| col 82 | `IS_LOAD_HALF` | binary：1=LH/LHU（halfword load），0=其他 |
| col 83 | `IS_LOAD_SIGN` | binary：1=LB/LH（sign-extend），0=LBU/LHU/LW |
| col 84 | `SIGN_BIT` | binary：loaded value 的 sign bit |
| col 85-92 | `LOAD_BITS[0..7]` | 8 binary：rd_eff[0]（LB）或 rd_eff[1]（LH）的 bit 分解 |

新增列常量定义在 `column_layout_v2.rs`：
```rust
pub const COL_IS_LOAD_BYTE: usize = 81;   // reuse MulCarryLo[0]
pub const COL_IS_LOAD_HALF: usize = 82;   // reuse MulCarryLo[1]
pub const COL_IS_LOAD_SIGN: usize = 83;   // reuse MulCarryLo[2]
pub const COL_SIGN_BIT: usize = 84;       // reuse MulCarryLo[3]
pub const COL_LOAD_BITS_BASE: usize = 85; // reuse MulCarryLo[4..6]+MulCarryHi0[0..4], 8 cols
```

### 2.2 trace_native.rs — witness 填充

在 `fill_row` 函数 Load 分支中添加：

1. **确定 load subtype**（从 `step.instruction` 匹配）：
   - LB → IS_LOAD_BYTE=1, IS_LOAD_SIGN=1
   - LBU → IS_LOAD_BYTE=1, IS_LOAD_SIGN=0
   - LH → IS_LOAD_HALF=1, IS_LOAD_SIGN=1
   - LHU → IS_LOAD_HALF=1, IS_LOAD_SIGN=0
   - LW → all 0

2. **Bit 分解**：
   - LB：分解 `rd_eff[0]`（= helper_b_value 的 limb 0）为 8 bits
   - LH：分解 `rd_eff[1]`（= helper_b_value 的 limb 1）为 8 bits
   - 其他：bits = 0
   - SIGN_BIT = bits[7]

### 2.3 cpu_air.rs — 新增约束（~20 条，度 ≤ 3）

**binality + gating（度 2）**：
1. `IS_LOAD_BYTE * (IS_LOAD_BYTE - 1) = 0`
2. `IS_LOAD_HALF * (IS_LOAD_HALF - 1) = 0`
3. `IS_LOAD_SIGN * (IS_LOAD_SIGN - 1) = 0`
4. `SIGN_BIT * (SIGN_BIT - 1) = 0`
5. `(1 - IS_LOAD) * IS_LOAD_BYTE = 0`（仅 Load 行设置）
6. `(1 - IS_LOAD) * IS_LOAD_HALF = 0`
7. `(1 - IS_LOAD) * IS_LOAD_SIGN = 0`
8. `IS_LOAD_BYTE * IS_LOAD_HALF = 0`（byte/halfword 互斥）

**LOAD_BITS binality（8 条，度 2）**：
9-16. `LOAD_BITS[i] * (LOAD_BITS[i] - 1) = 0` for i in 0..8

**Bit 分解约束（度 3）**：
17. `IS_LOAD_BYTE * (rd_eff[0] - Σ(LOAD_BITS[i] * 2^i)) = 0`（byte load：rd_eff[0] = bit 分解）
18. `IS_LOAD_HALF * (rd_eff[1] - Σ(LOAD_BITS[i] * 2^i)) = 0`（halfword load：rd_eff[1] = bit 分解）

**Sign bit 一致性（度 2）**：
19. `IS_LOAD_BYTE * (SIGN_BIT - LOAD_BITS[7]) = 0`
20. `IS_LOAD_HALF * (SIGN_BIT - LOAD_BITS[7]) = 0`

**扩展结构约束（度 ≤ 3）**：
- **LB（sign-extend byte）**：`IS_LOAD_BYTE * IS_LOAD_SIGN` gating（度 2）
  21. `IS_LOAD_BYTE * IS_LOAD_SIGN * (rd_eff[1] - SIGN_BIT * 0xFF) = 0`（度 3）
  22. `IS_LOAD_BYTE * IS_LOAD_SIGN * (rd_eff[2] - SIGN_BIT * 0xFF) = 0`
  23. `IS_LOAD_BYTE * IS_LOAD_SIGN * (rd_eff[3] - SIGN_BIT * 0xFF) = 0`

- **LBU（zero-extend byte）**：`IS_LOAD_BYTE * (1 - IS_LOAD_SIGN)` gating
  24. `IS_LOAD_BYTE * (1 - IS_LOAD_SIGN) * rd_eff[1] = 0`（度 3）
  25. `IS_LOAD_BYTE * (1 - IS_LOAD_SIGN) * rd_eff[2] = 0`
  26. `IS_LOAD_BYTE * (1 - IS_LOAD_SIGN) * rd_eff[3] = 0`

- **LH（sign-extend halfword）**：`IS_LOAD_HALF * IS_LOAD_SIGN` gating
  27. `IS_LOAD_HALF * IS_LOAD_SIGN * (rd_eff[2] - SIGN_BIT * 0xFF) = 0`（度 3）
  28. `IS_LOAD_HALF * IS_LOAD_SIGN * (rd_eff[3] - SIGN_BIT * 0xFF) = 0`

- **LHU（zero-extend halfword）**：`IS_LOAD_HALF * (1 - IS_LOAD_SIGN)` gating
  29. `IS_LOAD_HALF * (1 - IS_LOAD_SIGN) * rd_eff[2] = 0`（度 3）
  30. `IS_LOAD_HALF * (1 - IS_LOAD_SIGN) * rd_eff[3] = 0`

### 2.4 Soundness 测试（prover.rs）

| 测试名 | 场景 | 预期 |
|--------|------|------|
| `test_load_sign_ext_byte_positive` | LB 0x7F → 0x0000007F | prove 成功 |
| `test_load_sign_ext_byte_negative` | LB 0xFF → 0xFFFFFFFF | prove 成功 |
| `test_load_zero_ext_byte` | LBU 0xFF → 0x000000FF | prove 成功 |
| `test_load_sign_ext_halfword` | LH 0xFF80 → 0xFFFFFF80 | prove 成功 |
| `test_load_soundness_tamper_extension` | LB 0xFF 但 rd_eff=0x000000FF（零扩展代替符号扩展） | prove 失败（结构约束捕获：SIGN_BIT=1 但 rd_eff[1]=0≠0xFF）|

**关键**：soundness 测试 5 验证——当 SIGN_BIT=1（byte bit7=1）时，若 prover 试图零扩展（rd_eff[1]=0），约束 21 `IS_LOAD_BYTE * IS_LOAD_SIGN * (rd_eff[1] - SIGN_BIT * 0xFF) = 1*1*(0 - 1*0xFF) ≠ 0` 会触发 ConstraintsNotSatisfied。

### 2.5 已知残留 gap（文档化）

完整修复需将 MemoryAir 改为 byte-level（存储原始 word 而非扩展值），并在 AIR 中约束 byte 提取。当前方案仅约束扩展结构，不验证 load type 与指令的绑定（IS_LOAD_SIGN/IS_LOAD_BYTE 由 prover 设置，AIR 不验证其与实际指令一致）。

**残留攻击**：prover 可设置 IS_LOAD_SIGN=0（声称 LBU）执行 LB，对负数 byte 使用零扩展。此攻击需修改 witness，且仅对 uninitialized memory 有效（已初始化 memory 的 continuity 约束可部分捕获）。

---

## 3. V8 修复设计

### 3.1 运行时 Guard（sha256_air.rs）

在 `Sha256Air::new()` 中添加 `panic!`，防止误用：

```rust
pub fn new(log_size: u32) -> Self {
    panic!(
        "Sha256Air is INCOMPLETE (V8 known gap): \
         compression function constraints not implemented. \
         Do not use in any proof path until constraints are complete."
    );
}
```

### 3.2 文档化（sha256_air.rs 模块注释）

更新模块注释，明确标注：
- V8 MEDIUM 已知 gap
- 完整修复需要的步骤（compression function, message schedule, round boundary）
- 当前不可用于任何 proof path

### 3.3 测试（sha256_air.rs）

添加测试验证 guard 生效：
```rust
#[test]
#[should_panic(expected = "Sha256Air is INCOMPLETE")]
fn test_sha256_air_guard_panics() {
    let _ = Sha256Air::new(10);
}
```

---

## 4. 文件变更清单

| 文件 | 变更 | 说明 |
|------|------|------|
| `column_layout_v2.rs` | 新增 5 个列常量 | IS_LOAD_BYTE/HALF/SIGN, SIGN_BIT, LOAD_BITS_BASE |
| `trace_native.rs` | 修改 `fill_row` Load 分支 | 填充 load subtype + bit 分解 witness |
| `cpu_air.rs` | 新增 ~30 条约束 | binality + bit 分解 + 扩展结构 |
| `prover.rs` | 新增 5 个 soundness 测试 | LB/LBU/LH/LHU + tamper |
| `sha256_air.rs` | new() panic guard + 注释 + 测试 | V8 防误用 |

---

## 5. 验证步骤

```bash
# 编译
cargo +nightly-2026-04-15 build -p poker_zkvm

# V7 测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "load_sign_ext" "load_zero_ext" "load_soundness"

# V8 测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "sha256_air_guard"

# 全量回归
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```

**预期**：~634 通过（629 + 5 V7 + 1 V8 guard），0 失败，0 回归。

---

## 6. 实施顺序

1. **V7.1** — `column_layout_v2.rs`：新增列常量
2. **V7.2** — `trace_native.rs`：witness 填充
3. **V7.3** — `cpu_air.rs`：约束实现
4. **V7.4** — `prover.rs`：soundness 测试
5. **V8.1** — `sha256_air.rs`：guard + 注释 + 测试
6. **验证** — 编译 + 测试 + 全量回归
