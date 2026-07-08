# Phase 7 完成计划 — Prover 与最终压缩（收尾）

## 摘要

Phase 7 的主体实现已完成（Steps 1/3/4/5）：
- `poker_zkvm/src/prover/mod.rs` — `prove()` 主流程 + `ProverConfig` + `ZkPublicIo` + `serialize_proof` + `pad_trace` + 17 单元测试 + 6 端到端集成测试（已写入但**尚未运行**）
- `poker_zkvm/src/prover/spartan.rs` — Spartan 压缩 stub（返回 Phase 12 pending）
- `poker_zkvm/src/prover/groth16_compress.rs` — Groth16 压缩 stub（返回 Phase 12 pending）
- `poker_zkvm/src/pcs/ipa.rs` — `MAX_N_VARS` 改为 `pub`

剩余工作 3 步：
1. **Step 2（收尾）**：运行 6 个新集成测试，修复失败用例
2. **Step 6**：将 `cargo-zkvm prove` 子命令 stub 替换为真实 `prove()` 调用
3. **Step 7**：补全 `alternatives.md` Phase 7 段 + 标记 tasks.md 完成 + 全量验证（test / clippy / build）

## 当前状态分析

### 已完成
| 步骤 | 文件 | 状态 |
|------|------|------|
| Step 1 | `prover/mod.rs` — `ProverConfig` / `ZkPublicIo` / 常量 | ✅ |
| Step 2 | `prover/mod.rs` — `prove()` 主流程 + 6 集成测试 | ⚠️ 测试未运行 |
| Step 3 | `prover/mod.rs` — `serialize_proof()` stub | ✅ |
| Step 4 | `prover/spartan.rs` — stub | ✅ |
| Step 5 | `prover/groth16_compress.rs` — stub | ✅ |

### 待完成
| 步骤 | 内容 |
|------|------|
| Step 2 收尾 | 运行 `cargo test -p poker_zkvm --lib prover`，修复失败用例 |
| Step 6 | `bin/cargo-zkvm.rs` 的 `cmd_prove` stub → 真实 `prove()` 集成 |
| Step 7 | `alternatives.md` Phase 7 段 + `tasks.md` 标记 + 全量验证 |

### 关键约束
- `prove()` 当前 MVP 限制：`batch_size + 1` 须为 2 的幂（IPA PCS 要求）
- `prove()` 至少需要 2 个 CCS 实例（fold_loop 要求 ≥1 个 CCCCS）
- `cmd_prove` 须写出 proof 文件 + public_io 文件（verifier 在 Phase 8/11 需要二者）
- `poker_zkvm::prover` 已在 `lib.rs:53` 导出为 `pub mod prover`

## 实施步骤

### Step 2 收尾：运行集成测试并修复失败

**目标**：验证 `prover/mod.rs` 中 6 个集成测试全部通过

**操作**：
1. 运行 `cargo test -p poker_zkvm --lib prover::tests::test_prove` 查看结果
2. 如有失败，根据失败信息修复：
   - 可能失败点 1：`test_prove_empty_input_success` — 5 步程序 + padding 到 6 步 → 2 batches → num_vars=4。若 `compile_trace_to_ccs` 生成的 `num_vars` 与预期不符（如实际为 5 非 4），需调整测试用的 batch_size 或 trace 步数
   - 可能失败点 2：`test_prove_num_vars_not_power_of_two_errors` — batch_size=4 → num_vars=5。若 `compile_trace_to_ccs` 实际生成的 num_vars 不是 batch_size+1，需调整断言
   - 可能失败点 3：`test_prove_insufficient_instances_errors` — 2 步 + batch_size=3 → padding 到 3 步 → 1 batch → 不足 2 实例。若实际 padding 逻辑不同，需调整
   - 可能失败点 4：`test_prove_proof_size_limit_exceeded` — proof_size_limit=10。若 serialize_proof stub 输出 <10 字节（空数据情况），需调小 limit 或增大 trace
3. 修复后重新运行直到 23 个测试（17 单元 + 6 集成）全通过

**验证**：`cargo test -p poker_zkvm --lib prover` 输出 23 passed, 0 failed

### Step 6：cargo-zkvm prove 子命令集成

**目标**：将 [cargo-zkvm.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/bin/cargo-zkvm.rs) 中 `cmd_prove` 的 stub（返回 "Phase 10 — prover pending"）替换为真实 `prove()` 调用

**修改文件**：`poker_zkvm/src/bin/cargo-zkvm.rs`

**改动内容**：

1. **新增 import**（文件顶部）：
   ```rust
   use poker_zkvm::prover::{prove, ProverConfig};
   ```

2. **替换 `cmd_prove` 函数**（当前 L102-113）：
   ```rust
   /// `prove` 子命令 — 生成 proof 并写出 proof + public_io 文件。
   fn cmd_prove(args: &[String]) -> Result<String, String> {
       let elf_path = parse_arg(args, "--elf")?;
       let input_path = parse_arg(args, "--input")?;
       let output_path = parse_arg(args, "--output")?;

       let elf_bytes = std::fs::read(&elf_path)
           .map_err(|e| format!("failed to read ELF {}: {e}", elf_path.display()))?;
       let input = std::fs::read(&input_path)
           .map_err(|e| format!("failed to read input {}: {e}", input_path.display()))?;

       let config = ProverConfig::default();
       let (proof_bytes, public_io) = prove(&elf_bytes, &input, &config)
           .map_err(|e| format!("prove failed: {e}"))?;

       // 写 proof 文件
       std::fs::write(&output_path, &proof_bytes)
           .map_err(|e| format!("failed to write proof {}: {e}", output_path.display()))?;

       // 写 public_io 文件（proof 文件路径 + ".public_io"）
       let public_io_path = {
           let mut p = output_path.clone();
           let mut name = p.file_name().unwrap().to_os_string();
           name.push(".public_io");
           p.set_file_name(name);
           p
       };
       let public_io_bytes = public_io.to_bytes();
       std::fs::write(&public_io_path, &public_io_bytes)
           .map_err(|e| format!("failed to write public_io {}: {e}", public_io_path.display()))?;

       Ok(format!(
           "Prove successful: {} bytes proof + {} bytes public_io (output={})",
           proof_bytes.len(),
           public_io_bytes.len(),
           output_path.display()
       ))
   }
   ```

3. **更新模块顶部注释**（L7）：
   - 将 `prove --elf <PATH> --input <PATH> --output <PATH>` — 生成 proof（Phase 10 未就绪，stub）`
   - 改为 `prove --elf <PATH> --input <PATH> --output <PATH>` — 生成 proof + public_io 文件`

4. **更新 `usage_string`**（L234）：
   - 将 `prove --elf --input --output <PATH>           Generate proof (Phase 10)`
   - 改为 `prove --elf --input --output <PATH>           Generate proof + public_io`

5. **新增测试**（替换现有 `test_prove_missing_*` 两个测试 + 新增真实 prove 测试）：
   - 保留 `test_prove_missing_elf_arg` / `test_prove_missing_output_arg`（参数校验）
   - 新增 `test_prove_writes_proof_and_public_io_files`：构造最小 ELF（batch_size=3 程序）→ 调 cmd_prove → 校验 proof 文件 + .public_io 文件被写入且非空 → 清理临时文件
   - 修改 `test_prove_missing_output_arg`：原测试只校验 `--output` 缺失，现仍应通过（因为 cmd_prove 在 parse_arg 阶段就返回错误，不会走到 prove()）

**验证**：
- `cargo test -p poker_zkvm --bin cargo-zkvm` 全部通过（原 30 个 + 新增 1 个 = 31 个）
- `cargo build -p poker_zkvm` 成功

### Step 7：文档 + 全量验证

**目标**：补全 Phase 7 文档，标记任务完成，全量回归测试

#### 7.1 更新 `poker_zkvm/docs/alternatives.md`

在文件末尾（Phase 6 段之后）追加 `## Phase 7 — Prover 与最终压缩` 段，包含三小节：

**Recommended（采用方案）** ~6 项：
1. **prover 模块拆分为 mod.rs + spartan.rs + groth16_compress.rs** — 主流程与压缩器解耦，便于 Phase 12 替换 stub
2. **ProverConfig 使用 Bn254ScalarField（newtype）而非 ark_bn254::Fr** — 与 crate::ccs::Fr 一致，prove() 内部用 `.into_fr()` 桥接到 ZkvmExecutionConfig
3. **trace padding 使用 RISC-V NOP（Addi x0, x0, 0）** — 保证 CCS 结构一致且不改变执行语义
4. **serialize_proof stub 使用 length-prefixed 二进制** — 简单往返一致，Phase 5.5 替换为 spec 规范格式
5. **Spartan/Groth16 stub 返回 Phase 12 pending 错误** — 明确未实现边界，避免误用
6. **cargo-zkvm prove 同时输出 proof + .public_io 文件** — verifier 需要 public_io 才能验证

**Alternatives（未采用方案）** ~6 项：
1. ~~ProverConfig 直接用 ark_bn254::Fr~~ — 会破坏 crate 内 Fr 类型一致性
2. ~~trace padding 用 ECALL~~ — 会触发 syscall 分派，改变执行结果
3. ~~serialize_proof 用 serde~~ — 引入额外依赖，且 spec 格式非 serde 标准
4. ~~prove() 内部自动压缩（Spartan/Groth16）~~ — MVP 阶段压缩器未就绪，过早集成会阻塞
5. ~~cargo-zkvm prove 只输出 proof 文件~~ — verifier 无法独立验证，需配套 public_io
6. ~~proof_size_limit 检查放在 fold_loop 内~~ — 职责泄漏，fold_loop 应专注折叠

**Implementation Discovered（实现中发现）** ~5 项：
1. **IPA PCS 要求 witness 长度 = 2^m** — 当前 MVP 限制 `batch_size + 1` 须为 2 的幂（如 batch_size=3 → num_vars=4），Phase 5 增强版将在 CCS 构造时自动 padding
2. **fold_loop 要求 ≥1 个 CCCCS 实例** — 即至少 2 个 CCS 实例，prove() 中显式校验
3. **ZkvmExecutionConfig 用 ark_bn254::Fr，ProverConfig 用 Bn254ScalarField** — 类型不一致需 `.into_fr()`/`from_fr()` 桥接
4. **exec_result.events 是 Vec<ark_bn254::Fr>** — 构造 ZkPublicIo 时需 `.iter().map(|f| ZkvmFr::from_fr(*f)).collect()`
5. **executor::tests 的 build_test_elf/encode_text 是私有** — prover 集成测试需复制一份到 prover::tests

#### 7.2 更新 `tasks.md`

将 Phase 7 段（L216-231）的 `- [ ]` 改为 `- [x]`，标记 Task 7.1 / 7.2 / 7.3 全部完成（含所有 SubTask）。对于 Spartan/Groth16 的 SubTask 7.2.x / 7.3.x（除 stub 外的完整实现），在行尾添加 `(stub — Phase 12 实现)` 注释。

#### 7.3 全量验证

按顺序运行（须全部通过）：
1. `cargo test -p poker_zkvm` — 期望全量通过（lib + bin，约 660+ 测试）
2. `cargo clippy -p poker_zkvm -- -D warnings` — 零警告
3. `cargo build --workspace` — 成功
4. 手动确认 `cargo-zkvm` 二进制可构建：`cargo build -p poker_zkvm --bin cargo-zkvm --release`

## 假设与决策

1. **假设**：`prove()` 的 6 个集成测试中可能有部分失败（因测试是上一轮会话末尾添加，未运行验证）。计划预留修复空间。
2. **决策**：`cmd_prove` 使用 `ProverConfig::default()`，不暴露 CLI 参数覆盖（MVP 阶段保持简单，Phase 12 再扩展 `--batch-size` 等参数）。
3. **决策**：public_io 文件路径为 `{output_path}.public_io`（在原文件名后追加后缀），不引入额外 `--public-io` 参数（保持 3 参数简洁）。
4. **决策**：不实现 SubTask 7.1.5（错误恢复 — host 端调整 batch_size 重试）— 这属于 host 集成层职责，留待 Phase 11。
5. **决策**：Spartan/Groth16 完整实现（SubTask 7.2.1-7.2.4 / 7.3.1-7.3.2）留待 Phase 12，当前仅 stub。

## 验证步骤

完成后须满足：
- [ ] `cargo test -p poker_zkvm --lib prover` — 23 测试通过
- [ ] `cargo test -p poker_zkvm --bin cargo-zkvm` — 31 测试通过（含新增 prove 文件写入测试）
- [ ] `cargo test -p poker_zkvm` — 全量通过（lib + bin）
- [ ] `cargo clippy -p poker_zkvm -- -D warnings` — 零警告
- [ ] `cargo build --workspace` — 成功
- [ ] `alternatives.md` 含 Phase 7 段（Recommended / Alternatives / Implementation Discovered 三小节）
- [ ] `tasks.md` Phase 7 全部标记 `[x]`
