# 为 poker_zkvm 添加 riscv32im 支持 — 验证与收尾

## 当前状态（已验证）

### ✅ 代码变更（Steps 1-6，前序会话已完成并验证）

| 文件 | 变更 | 验证结果 |
|------|------|----------|
| `poker_zkvm/src/stwo_backend/column_layout_v2.rs` | 8 个 M 扩展 indicator (IS_MUL=56 … IS_REMU=63)，IS_PADDING→64，NUM_INSTRUCTION_CATEGORIES=43，NUM_COLUMNS=81 | ✅ 常量正确，测试断言已更新 |
| `poker_zkvm/src/stwo_backend/trace_native.rs` | `instruction_to_indicator_col` 占位映射修复：Mul→IS_MUL, …, Remu→IS_REMU | ✅ 映射正确（L966-974） |
| `poker_zkvm/src/stwo_backend/cpu_air.rs` | 测试硬编码列号断言更新 + test-only import IS_MUL/IS_REMU | ✅ 已验证 |
| `poker_zkvm/src/isa/mod.rs` | variant 计数测试 40→48，含 8 个 M 扩展 variant | ✅ 已验证 |
| `poker_zkvm/guests/texas_poker/.cargo/config.toml` | target = `riscv32im-unknown-none-elf` | ✅ 已验证 |
| `poker_zkvm/src/compiler/mod.rs` | CompilerConfig::default() target → riscv32im | ✅ 已验证 |
| 12+ 文件路径/注释引用 | riscv32i → riscv32im | ✅ `rg "riscv32i-unknown-none-elf"` 返回 0 结果 |

### ❌ 未完成项（本次需执行）

1. **riscv32im target 未安装**：`rustup +nightly-2026-04-15 target list --installed` 仅返回 `riscv32i-unknown-none-elf`，缺少 `riscv32im-unknown-none-elf`
2. **guest ELF 未重建为 riscv32im**：后台命令（job-e76739e20a524887812285950c75688d）已于 03:06 退出（exit_code=0），但它构建时 config.toml 仍为 riscv32i，产物在 `target/riscv32i-unknown-none-elf/release/`。`target/riscv32im-unknown-none-elf/` 不存在
3. **全量测试未执行**：lib / E2E / phase1 / bench 均未运行
4. **5 处 stale 注释**（column_layout_v2.rs，不影响功能，一并修复保持一致性）：
   - L17：`22-63` → `22-64`（indicator 范围含 IS_PADDING=64）
   - L32：`73 列` → `81 列`
   - L59：`35 列` → `43 列`
   - L60：`col 22-56，共 35 列` → `col 22-64，共 43 列`
   - L204：`0-34` → `0-42`

## 实施步骤

### Step 1：安装 riscv32im target

```bash
rustup +nightly-2026-04-15 target add riscv32im-unknown-none-elf
```

**Why**：config.toml 指定 `riscv32im-unknown-none-elf`，但该 target 未安装，build 会报错 `can't find crate for 'core'`。

### Step 2：修复 stale 注释（column_layout_v2.rs）

5 处 doc/section 注释更新（纯文档，不影响编译/测试）：
- L17 indicator 范围 `22-63` → `22-64`
- L32 `73 列` → `81 列`
- L59 `35 列` → `43 列`
- L60 `col 22-56，共 35 列` → `col 22-64，共 43 列`
- L204 `0-34` → `0-42`

### Step 3：重建 guest ELF（riscv32im）

```bash
cd /Users/mac/projects/zchain/poker_zkvm/guests/texas_poker && cargo +nightly-2026-04-15 build --release --target-dir target
```

**验证**：确认 `target/riscv32im-unknown-none-elf/release/texas_poker_guest` 存在。

### Step 4：poker_zkvm lib 单元测试

```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo +nightly-2026-04-15 test --lib
```

**重点**：列布局一致性（81 列）、indicator one-hot（43 类别）、M 扩展 decode/execute 边界、variant 计数（48）。

### Step 5：E2E 测试

```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo +nightly-2026-04-15 test --test texas_poker_guest_e2e
```

**重点**：riscv32im ELF 被正确加载执行，`prove_cpu_memory_trace` 通过。若 guest emit 了 MUL 指令，证明 M indicator 映射正确、proof 不因占位 ADD 约束失败。

### Step 6：phase1 测试

```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo +nightly-2026-04-15 test --test texas_poker_guest_phase1
```

### Step 7：性能基准（可选，验证 prove/verify 完整跑通）

```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo +nightly-2026-04-15 bench --bench texas_poker_guest_full_hand --features test-helpers
```

## 风险与回退

- **riscv32im target 不可用**：若 `rustup target add` 失败（网络/源问题），可临时回退 config.toml 为 riscv32i，但需同步回退 compiler/mod.rs 和路径引用（不推荐）
- **E2E 失败**：若 riscv32im 编译产生的 M 指令触发未覆盖的 code path（如 trace 中出现未处理的 M 指令），需检查 `instruction_to_indicator_col` 是否覆盖所有 M variant。当前已验证映射完整
- **Soundness**：M 扩展无算术约束（与 XOR/OR/AND 一致），prover 信任 executor。这是既定设计边界，非本次引入的回归

## 验证标准

全部测试通过即验证成功：
- lib 单元测试 0 failure
- E2E 测试 15/15 通过
- phase1 测试通过
- bench prove/verify 完整跑通（可选）
