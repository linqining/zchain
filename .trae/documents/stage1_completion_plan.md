# Stage 1 完成计划 — batch_size=256 默认值 + proof size 常量 + 基准测试修复

## 概述

Stage 1（proof size 修复）已完成 1.1（CCS power-of-2 padding）和 1.2（单实例 proof 路径）。
本计划完成剩余 3 个子任务（1.3 / 1.4 / 1.5）+ 验证，使 Stage 1 完整收尾。

## 当前状态分析

### 已完成
- **Stage 1.1**：`compile_batch_to_ccs` 已实现 power-of-2 padding（`constraints/mod.rs` L156-158），`num_vars`/`num_rows` 自动填充到 2 的幂，不再需要 `batch_size + 1` 为 2 的幂。
- **Stage 1.2**：`fold_loop` 单实例路径已实现（`fold_loop.rs` L224-253），`verify_production` 单实例验证路径已实现（`verifier.rs` step 6.5），`generate_single_instance_test_proof()` 已添加（`prover/mod.rs` L1008），4 个相关测试全部通过。

### 待完成
- **Stage 1.3**：`ProverConfig::default().batch_size` 仍为 `3`（`prover/mod.rs` L85），需改为 `256`。字段注释（L59-62）已更新但 `Default` 实现（L81-85）仍是旧 MVP 注释 + 旧值。测试 `test_prover_config_default_valid`（L1093-1094）仍断言 `batch_size == 3`。
- **Stage 1.4**：`MAX_PROOF_TOTAL_SIZE` 注释（L253-257）描述过时（提及 "48KB" 但值为 512KB，提及 "M2-002 单项子分配" 但实际是 DoS 限制）。`MAX_ZKVM_PROOF_SIZE` 注释（L44-46）可补充 batch_size=256 的 proof 大小分析。
- **Stage 1.5**：基准测试文件（`benches/phase12_benchmarks.rs`）使用 `BATCH_SIZE = 3` + 旧 MVP 注释，且 `assert!(size <= MAX_ZKVM_PROOF_SIZE)`（L70）对多步 proof 会失败。需改为 `BATCH_SIZE = 256` + `proof_size_limit: MAX_PROOF_TOTAL_SIZE` + 修正断言。

## 修改计划

### Task 1: Stage 1.3 — `ProverConfig::default().batch_size` 改为 256

**文件**: `poker_zkvm/src/prover/mod.rs`

**修改 1a** — `Default` 实现（L78-94）：
- 将 `batch_size: 3` 改为 `batch_size: 256`
- 替换注释（L81-84）：
  ```rust
  // batch_size=256：Stage 1.1 padding 保证 num_vars/num_rows 为 2 的幂，
  // 不再需要 batch_size+1 为 2 的幂。
  // 单实例 proof（≤256 步）~48KB < 64KB 上链限制。
  // 多步 proof（如 1000 步→4 batches→3 fold steps）~245KB，需 CycleFold 压缩至 64KB（Stage 3）。
  ```

**修改 1b** — 测试 `test_prover_config_default_valid`（L1090-1098）：
- 将 `assert_eq!(config.batch_size, 3)` 改为 `assert_eq!(config.batch_size, 256)`
- 将注释 `// MVP 默认 batch_size = 3（...）` 改为 `// 默认 batch_size = 256（Stage 1.1 padding 后不再需要 2 的幂约束）`

**不受影响的测试**（均显式设置 batch_size，不依赖 default）：
- `generate_test_proof()`（L994）：`batch_size: 3` — 产生多步 proof 供 verifier 篡改测试，保持不变
- `generate_single_instance_test_proof()`（L1063）：`batch_size: 3` — 产生单实例 proof，保持不变
- `test_prove_invalid_elf_errors`（L1321）、`test_prove_empty_input_success`（L1347）等：均显式 `batch_size: 3`，保持不变
- E2E 测试（`tests/e2e_*.rs`）：均显式 `batch_size: 3` + `proof_size_limit: MAX_PROOF_TOTAL_SIZE`，保持不变
- Soundness 测试：使用 `generate_test_proof()`，保持不变

### Task 2: Stage 1.4 — proof size 常量注释更新

**文件**: `poker_zkvm/src/prover/mod.rs`

**修改 2a** — `MAX_ZKVM_PROOF_SIZE` 注释（L44-47）：
```rust
/// 上链 proof 字节数上限（spec L692 — 64KB）。
///
/// 超出此大小的 proof 须触发 CycleFold 递归压缩（Stage 3）。
/// batch_size=256 时单实例 proof（≤256 步）~48KB < 64KB，可直接上链。
pub const MAX_ZKVM_PROOF_SIZE: usize = 64 * 1024;
```

**修改 2b** — `MAX_PROOF_TOTAL_SIZE` 注释（L253-258）：
```rust
/// proof 反序列化/DoS 总长度上限（512KB）。
///
/// 用途：`deserialize_proof` 在分配内存前先校验总长度，防止 OOM DoS。
/// 与 [`MAX_ZKVM_PROOF_SIZE`]（64KB 上链限制）的区别：
/// - 本常量 = 压缩前 proof 的反序列化上限（含所有 fold 步骤数据）
/// - [`MAX_ZKVM_PROOF_SIZE`] = 压缩后上链 proof 上限
///
/// batch_size=256 时多步 proof 大小参考：
/// - 100 步 → 1 batch → 单实例 ~48KB
/// - 500 步 → 2 batches → 1 fold step ~80KB
/// - 1000 步 → 4 batches → 3 fold steps ~245KB
/// 均远小于 512KB 限制。CycleFold 压缩（Stage 3）后可恢复至 64KB 上链。
pub const MAX_PROOF_TOTAL_SIZE: usize = 512 * 1024;
```

### Task 3: Stage 1.5 — 基准测试修复

**文件**: `poker_zkvm/benches/phase12_benchmarks.rs`

**修改 3a** — 更新文件头注释（L1-10）：
```rust
//! Phase 12 性能基准 — prover 时间 / proof 大小 / verifier 时间 vs trace 步数。
//!
//! 基准维度：
//! - **prover_time**：`prove()` 端到端时间（ELF 校验 + 执行 + CCS 编译 + Hypernova 折叠 + 序列化）
//! - **proof_size**：序列化后的 proof 字节数
//! - **verifier_time**：`verify_production()` 验证时间
//!
//! 步数梯度：100 / 500 / 1000 步
//! - batch_size=256（Stage 1 默认值，Stage 1.1 padding 保证 num_vars/num_rows 为 2 的幂）
//! - 100 步 → 1 batch（单实例），500 步 → 2 batches（1 fold step），1000 步 → 4 batches（3 fold steps）
```

**修改 3b** — 更新 `BATCH_SIZE` 常量（L20-21）：
```rust
/// batch_size=256（Stage 1 默认值）
const BATCH_SIZE: usize = 256;
```

**修改 3c** — 三个 bench 函数中的 `ProverConfig` 构造（L31-34, L60-63, L93-96）：
将 `..Default::default()` 改为显式设置 `proof_size_limit`：
```rust
let config = ProverConfig {
    batch_size,
    proof_size_limit: MAX_PROOF_TOTAL_SIZE,
    ..Default::default()
};
```
原因：多步 proof（500/1000 步）超过 `MAX_ZKVM_PROOF_SIZE`（64KB），需用 512KB 限制。

**修改 3d** — `bench_proof_size` 中的断言（L70-71）：
```rust
// 多步 proof 超 64KB 上链限制，但须 < 512KB DoS 限制
assert!(size <= MAX_PROOF_TOTAL_SIZE, "proof 超 DoS 上限");
```
删除 `assert!(size <= MAX_ZKVM_PROOF_SIZE, "proof 过大")`，因为多步 proof 必然超 64KB。

**修改 3e** — `bench_proof_size` 的 println 输出（L77-80）：
```rust
println!(
    "  proof_size(steps={}) = {} bytes (on_chain_limit={}, dos_limit={}, batch_size={})",
    steps, size, MAX_ZKVM_PROOF_SIZE, MAX_PROOF_TOTAL_SIZE, batch_size
);
```

### Task 4: Stage 1 验证

**步骤 4a** — 编译检查：
```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo build --all-features
```

**步骤 4b** — Clippy 检查：
```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo clippy --all-features -- -D warnings
```

**步骤 4c** — 全量测试：
```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo test --all-features
```
预期：所有现有测试通过（766 项），包括：
- `test_prover_config_default_valid` 断言 `batch_size == 256`
- `test_verify_production_single_instance_proof_accepted` 通过
- `test_verify_production_rejects_empty_fold_steps` 通过
- `test_fold_loop_no_ccccs_instances` 通过

**步骤 4d** — 基准测试编译检查（不运行，仅编译）：
```bash
cd /Users/mac/projects/zchain/poker_zkvm && cargo bench --no-run
```
预期：基准测试编译通过，无断言错误。

## 假设与决策

1. **batch_size=256 选择理由**：单实例 proof ~48KB < 64KB 上链限制。1000 步→4 batches→3 fold steps，proof ~245KB < 512KB DoS 限制。虽非 1024（spec 上限）但实际可用，Stage 3 CycleFold 压缩后可恢复更大 batch_size。
2. **不修改 E2E/Soundness 测试**：这些测试显式设置 `batch_size: 3`，用于验证特定场景，不受 default 值变化影响。
3. **不修改 `generate_test_proof()` / `generate_single_instance_test_proof()`**：这些辅助函数显式设置 `batch_size: 3`，保持小 batch 产生可预测的 proof 结构供测试验证。
4. **基准测试使用 `proof_size_limit: MAX_PROOF_TOTAL_SIZE`**：多步 proof 超 64KB，需放宽至 512KB 才能成功 prove。
5. **`MAX_PROOF_TOTAL_SIZE` 值不变（512KB）**：仅更新注释，不改值。
