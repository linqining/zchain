# Phase 11.5 实施计划：治理参数与 gas 调整

> **change-id**：`build-hypernova-zkvm`
> **Phase**：11.5（v1.2 补 6 项 Proof 字段长度上限 + production_switch_height）
> **依赖**：Phase 11 Task 11.1（已完成 — stub fold 迁移到真实 Hypernova fold）
> **spec 参考**：`.trae/specs/build-hypernova-zkvm/tasks.md` L334-351 + `spec.md` L875-884

## 摘要

Phase 11.5 包含两个并行 Task：
- **Task 11.5.1**：调整 `poker_l1/src/vm/gas_table.rs` — `GAS_HYPERNOVA_VERIFY` 50000→300000，新增 ZKVM syscall gas 常量
- **Task 11.5.2**：扩展 `poker_l1/src/governance/mod.rs` — 新增 13 项敏感治理参数（含 5 项 Proof 字段长度上限），所有敏感参数 90% quorum + timelock

## 当前状态分析

### 已存在的常量（poker_zkvm 侧 — 单一事实源）

| 常量 | 值 | 位置 |
|------|-----|------|
| `MAX_ZKVM_TRACE_STEPS` | 1,048,576 | `poker_zkvm/src/isa/executor.rs:27` |
| `MAX_ZKVM_MEMORY` | 16MB | `poker_zkvm/src/compiler/elf_validator.rs:15` |
| `MAX_ZKVM_PROOF_SIZE` | 64KB | `poker_zkvm/src/prover/mod.rs:48` |
| `ZKVM_BATCH_SIZE` | 1024 | `poker_zkvm/src/constraints/mod.rs:39` |
| `MAX_RECURSION_DEPTH` | 16 | `poker_zkvm/src/prover/mod.rs:53` |
| `MAX_TRACE_HOST_MEMORY` | 512MB | `poker_zkvm/src/trace/mod.rs:17` |
| `GAS_ZKVM_POSEIDON_BASE` | 100 | `poker_zkvm/src/syscalls/gas.rs:24` |
| `GAS_ZKVM_POSEIDON_PER_BLOCK` | 50 | `poker_zkvm/src/syscalls/gas.rs:27` |
| `GAS_ZKVM_SHA256_PER_BYTE` | 1 | `poker_zkvm/src/syscalls/gas.rs:30` |
| `GAS_ZKVM_ECDSA_VERIFY` | 100,000 | `poker_zkvm/src/syscalls/gas.rs:33` |
| `GAS_ZKVM_READ_STATE_PER_SLOT` | 50 | `poker_zkvm/src/syscalls/gas.rs:54` |

### 已存在的常量（poker_l1 侧）

| 常量 | 值 | 位置 |
|------|-----|------|
| `PRODUCTION_GRACE_BLOCKS` | 7200 | `poker_l1/src/governance/mod.rs:119` |
| `MAX_FOLD_STEP_COUNT` | 1000 | `poker_l1/src/offline/mod.rs:53` |
| `GAS_HYPERNOVA_VERIFY` | 50000（须改 300000） | `poker_l1/src/vm/gas_table.rs:95` |
| `production_switch_height` 字段 | 已存在于 `GovernanceParams` | `poker_l1/src/governance/mod.rs:413` |

### 尚未定义的常量（spec L880-884 要求）

| 常量 | 默认值 | 说明 |
|------|--------|------|
| `MAX_PUBLIC_IO_SIZE` | 8KB | Proof 中 public_io 字段长度上限 |
| `MAX_FOLDED_INSTANCE_SIZE` | 8KB | Proof 中 folded_instance 字段长度上限 |
| `MAX_SUMCHECK_PROOF_SIZE` | 16KB | Proof 中 final_sumcheck 字段长度上限 |
| `MAX_PCS_OPENING_SIZE` | 8KB | Proof 中 pcs_opening 字段长度上限 |
| `MAX_EVENT_HASHES_COUNT` | 256 | Proof 中 event_hashes 数组长度上限 |

### 现有治理参数结构

- `ParamName` 枚举：41 个变体（含 `ProductionSwitchHeight`）
- `is_sensitive()`：18 个敏感参数（含 `ProductionSwitchHeight`）
- `GovernanceParams` 结构体：41 个字段
- `validate_param()`：边界校验，支持跨参数依赖（如 `bonding_period_blocks` 依赖 `epoch_length_blocks`）

## 提议变更

### Task 11.5.1：调整 `poker_l1/src/vm/gas_table.rs`

#### SubTask 11.5.1.1：`GAS_HYPERNOVA_VERIFY` 50000 → 300000

**文件**：`poker_l1/src/vm/gas_table.rs`

**变更点**：
1. L95：`pub const GAS_HYPERNOVA_VERIFY: u64 = 50000;` → `300000`
2. L100-106：`GAS_ZK_VERIFY` 默认 fallback 也从 50000 → 300000（保持与 Hypernova 一致）
3. L16 文档注释：`hypernova_verify = 50000` → `300000`
4. L103 文档注释：`Hypernova → GAS_HYPERNOVA_VERIFY = 50000` → `300000`
5. L182-185 `zk_verify_gas` 函数文档注释更新
6. L217 单元测试 `assert_eq!(GAS_HYPERNOVA_VERIFY, 50000);` → `300000`
7. L220 单元测试 `assert_eq!(GAS_ZK_VERIFY, 50000);` → `300000`

**理由**：覆盖 Spartan pairing + final exp + IPA verify log(N) 轮 MSM + 余量；本参数须在 Phase 12 性能基准实测后再次校准。

#### SubTask 11.5.1.2：新增 ZKVM syscall gas 常量

**文件**：`poker_l1/src/vm/gas_table.rs`

**变更点**：在 `GAS_VERIFY_FAILURE_PROOF` 之后、`// ===== gas limits =====` 之前新增 ZKVM gas 常量区块（re-export 自 `poker_zkvm::syscalls::gas`）：

```rust
// ===== ZKVM syscall gas（Phase 11.5 — re-export 自 poker_zkvm）=====
//
// 这些常量在 poker_zkvm 中定义（单一事实源），poker_l1 通过 re-export 复用。
// 治理调整时通过 GovernanceParams 的 zkvm_gas_* 字段覆盖（见 governance/mod.rs）。
pub use poker_zkvm::syscalls::gas::{
    GAS_ZKVM_POSEIDON_BASE, GAS_ZKVM_POSEIDON_PER_BLOCK,
    GAS_ZKVM_SHA256_PER_BYTE, GAS_ZKVM_ECDSA_VERIFY,
    GAS_ZKVM_READ_STATE_PER_SLOT,
};
```

**理由**：避免常量重复定义，保持 poker_zkvm 为单一事实源。poker_l1 仅 re-export，治理调整通过 `GovernanceParams` 的运行时字段实现（见 Task 11.5.2）。

**单元测试**：新增 `test_zkvm_gas_constants_reexport` 验证 re-export 常量值与 poker_zkvm 一致。

### Task 11.5.2：扩展治理敏感参数清单

**文件**：`poker_l1/src/governance/mod.rs`

#### SubTask 11.5.2.1-11.5.2.9：新增 13 项 `ParamName` 变体

在 `ParamName::ProductionSwitchHeight` 之后追加 13 个变体：

```rust
/// max_zkvm_trace_steps（敏感 90% quorum）
MaxZkvmTraceSteps,
/// max_zkvm_memory（敏感 90% quorum）
MaxZkvmMemory,
/// max_zkvm_proof_size（敏感 90% quorum）
MaxZkvmProofSize,
/// zkvm_batch_size（敏感 90% quorum；含一致性约束）
ZkvmBatchSize,
/// max_recursion_depth（敏感 90% quorum）
MaxRecursionDepth,
/// max_trace_host_memory（敏感 90% quorum）
MaxTraceHostMemory,
/// production_grace_blocks（敏感 90% quorum）
ProductionGraceBlocks,
/// gas_hypernova_verify（敏感 90% quorum）
GasHypernovaVerify,
/// max_public_io_size（敏感 90% quorum；v1.3 M2-002 子分配）
MaxPublicIoSize,
/// max_folded_instance_size（敏感 90% quorum；v1.3 M2-002 子分配）
MaxFoldedInstanceSize,
/// max_sumcheck_proof_size（敏感 90% quorum；v1.3 M2-002 子分配）
MaxSumcheckProofSize,
/// max_pcs_opening_size（敏感 90% quorum；v1.3 M2-002 子分配）
MaxPcsOpeningSize,
/// max_event_hashes_count（敏感 90% quorum；v1.3 M2-002 子分配）
MaxEventHashesCount,
```

#### SubTask 11.5.2.10：`production_switch_height` 已存在 — 无变更

`ParamName::ProductionSwitchHeight` 已在 L227 定义，`is_sensitive()` 已在 L315 包含，`GovernanceParams.production_switch_height` 字段已在 L413 定义。**无需变更**。

#### 更新 `as_str()` 方法

为 13 个新变体添加字符串映射：

```rust
Self::MaxZkvmTraceSteps => "max_zkvm_trace_steps",
Self::MaxZkvmMemory => "max_zkvm_memory",
Self::MaxZkvmProofSize => "max_zkvm_proof_size",
Self::ZkvmBatchSize => "zkvm_batch_size",
Self::MaxRecursionDepth => "max_recursion_depth",
Self::MaxTraceHostMemory => "max_trace_host_memory",
Self::ProductionGraceBlocks => "production_grace_blocks",
Self::GasHypernovaVerify => "gas_hypernova_verify",
Self::MaxPublicIoSize => "max_public_io_size",
Self::MaxFoldedInstanceSize => "max_folded_instance_size",
Self::MaxSumcheckProofSize => "max_sumcheck_proof_size",
Self::MaxPcsOpeningSize => "max_pcs_opening_size",
Self::MaxEventHashesCount => "max_event_hashes_count",
```

#### 更新 `is_sensitive()` 方法

在 `matches!` 宏中追加 13 个新变体（全部敏感）：

```rust
| Self::MaxZkvmTraceSteps
| Self::MaxZkvmMemory
| Self::MaxZkvmProofSize
| Self::ZkvmBatchSize
| Self::MaxRecursionDepth
| Self::MaxTraceHostMemory
| Self::ProductionGraceBlocks
| Self::GasHypernovaVerify
| Self::MaxPublicIoSize
| Self::MaxFoldedInstanceSize
| Self::MaxSumcheckProofSize
| Self::MaxPcsOpeningSize
| Self::MaxEventHashesCount
```

#### 新增默认值常量

在 `PRODUCTION_GRACE_BLOCKS` 常量之后追加（默认值与 poker_zkvm 编译时常量对齐）：

```rust
/// 默认 max_zkvm_trace_steps（与 poker_zkvm::isa::executor::MAX_ZKVM_TRACE_STEPS 对齐）。
pub const DEFAULT_MAX_ZKVM_TRACE_STEPS: u64 = 1_048_576;
/// 默认 max_zkvm_memory（16MB，与 poker_zkvm::compiler::elf_validator::MAX_ZKVM_MEMORY 对齐）。
pub const DEFAULT_MAX_ZKVM_MEMORY: u64 = 16 * 1024 * 1024;
/// 默认 max_zkvm_proof_size（64KB，与 poker_zkvm::prover::MAX_ZKVM_PROOF_SIZE 对齐）。
pub const DEFAULT_MAX_ZKVM_PROOF_SIZE: u64 = 64 * 1024;
/// 默认 zkvm_batch_size（1024，与 poker_zkvm::constraints::ZKVM_BATCH_SIZE 对齐）。
pub const DEFAULT_ZKVM_BATCH_SIZE: u64 = 1024;
/// 默认 max_recursion_depth（16，与 poker_zkvm::prover::MAX_RECURSION_DEPTH 对齐）。
pub const DEFAULT_MAX_RECURSION_DEPTH: u64 = 16;
/// 默认 max_trace_host_memory（512MB，与 poker_zkvm::trace::MAX_TRACE_HOST_MEMORY 对齐）。
pub const DEFAULT_MAX_TRACE_HOST_MEMORY: u64 = 512 * 1024 * 1024;
/// 默认 gas_hypernova_verify（300000，与 gas_table::GAS_HYPERNOVA_VERIFY 对齐）。
pub const DEFAULT_GAS_HYPERNOVA_VERIFY: u64 = 300_000;
/// 默认 max_public_io_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_PUBLIC_IO_SIZE: u64 = 8 * 1024;
/// 默认 max_folded_instance_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_FOLDED_INSTANCE_SIZE: u64 = 8 * 1024;
/// 默认 max_sumcheck_proof_size（16KB，v1.4 M3-001）。
pub const DEFAULT_MAX_SUMCHECK_PROOF_SIZE: u64 = 16 * 1024;
/// 默认 max_pcs_opening_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_PCS_OPENING_SIZE: u64 = 8 * 1024;
/// 默认 max_event_hashes_count（256，v1.4 M3-001）。
pub const DEFAULT_MAX_EVENT_HASHES_COUNT: u64 = 256;
```

**注**：`PRODUCTION_GRACE_BLOCKS = 7200` 已存在（L119），作为 `production_grace_blocks` 字段默认值。

#### 新增 `GovernanceParams` 字段

在 `production_switch_height` 字段之后追加 13 个字段：

```rust
/// max_zkvm_trace_steps ∈ [65536, 16_777_216]
pub max_zkvm_trace_steps: u64,
/// max_zkvm_memory ∈ [4MB, 64MB]
pub max_zkvm_memory: u64,
/// max_zkvm_proof_size ∈ [16KB, 256KB]
pub max_zkvm_proof_size: u64,
/// zkvm_batch_size ∈ [64, 8192]（含一致性约束：max_zkvm_trace_steps / zkvm_batch_size ≤ MAX_FOLD_STEP_COUNT=1000）
pub zkvm_batch_size: u64,
/// max_recursion_depth ∈ [4, 32]
pub max_recursion_depth: u64,
/// max_trace_host_memory ∈ [128MB, 2GB]
pub max_trace_host_memory: u64,
/// production_grace_blocks ∈ [720, 72000]
pub production_grace_blocks: u64,
/// gas_hypernova_verify ∈ [100000, 1000000]
pub gas_hypernova_verify: u64,
/// max_public_io_size ∈ [4KB, 32KB]（v1.3 M2-002 子分配）
pub max_public_io_size: u64,
/// max_folded_instance_size ∈ [4KB, 32KB]（v1.3 M2-002 子分配）
pub max_folded_instance_size: u64,
/// max_sumcheck_proof_size ∈ [8KB, 64KB]（v1.3 M2-002 子分配）
pub max_sumcheck_proof_size: u64,
/// max_pcs_opening_size ∈ [4KB, 32KB]（v1.3 M2-002 子分配）
pub max_pcs_opening_size: u64,
/// max_event_hashes_count ∈ [32, 1024]（v1.3 M2-002 子分配）
pub max_event_hashes_count: u64,
```

#### 更新 `default_values()`

追加 13 个默认值初始化（引用上面的 `DEFAULT_*` 常量）。

#### 更新 `get()` 方法

追加 13 个 match 分支。

#### 更新 `set()` 方法

追加 13 个 match 分支。

#### 更新 `validate_param()` — 含跨参数一致性约束

追加 13 个边界校验分支：

```rust
ParamName::MaxZkvmTraceSteps => (65_536, 16_777_216),
ParamName::MaxZkvmMemory => (4 * 1024 * 1024, 64 * 1024 * 1024),
ParamName::MaxZkvmProofSize => (16 * 1024, 256 * 1024),
ParamName::ZkvmBatchSize => (64, 8192),
ParamName::MaxRecursionDepth => (4, 32),
ParamName::MaxTraceHostMemory => (128 * 1024 * 1024, 2 * 1024 * 1024 * 1024),
ParamName::ProductionGraceBlocks => (720, 72_000),
ParamName::GasHypernovaVerify => (100_000, 1_000_000),
ParamName::MaxPublicIoSize => (4 * 1024, 32 * 1024),
ParamName::MaxFoldedInstanceSize => (4 * 1024, 32 * 1024),
ParamName::MaxSumcheckProofSize => (8 * 1024, 64 * 1024),
ParamName::MaxPcsOpeningSize => (4 * 1024, 32 * 1024),
ParamName::MaxEventHashesCount => (32, 1024),
```

**跨参数一致性约束**（`ZKVM_BATCH_SIZE` 调整后须满足 `max_zkvm_trace_steps / zkvm_batch_size ≤ MAX_FOLD_STEP_COUNT=1000`）：

在 `validate_param` 函数末尾的 `if value < min || value > max` 检查之后，追加一致性约束：

```rust
// ZKVM_BATCH_SIZE 一致性约束（SubTask 11.5.2.4）：
// max_zkvm_trace_steps / zkvm_batch_size ≤ MAX_FOLD_STEP_COUNT (1000)
if name == ParamName::ZkvmBatchSize && value > 0 {
    let max_fold_steps = params.max_zkvm_trace_steps / value;
    let limit = crate::offline::MAX_FOLD_STEP_COUNT as u64;
    if max_fold_steps > limit {
        return Err(PokerL1Error::ParamOutOfBounds {
            param: name.as_str(),
            value,
            min: params.max_zkvm_trace_steps / limit,  // 最小 batch_size 保证不超限
            max,
        });
    }
}
// 同理：MaxZkvmTraceSteps 调整后也须校验
if name == ParamName::MaxZkvmTraceSteps && params.zkvm_batch_size > 0 {
    let max_fold_steps = value / params.zkvm_batch_size;
    let limit = crate::offline::MAX_FOLD_STEP_COUNT as u64;
    if max_fold_steps > limit {
        return Err(PokerL1Error::ParamOutOfBounds {
            param: name.as_str(),
            value,
            min,
            max: params.zkvm_batch_size * limit,  // 最大 trace_steps 保证不超限
        });
    }
}
```

#### SubTask 11.5.2.11：单元测试

新增以下单元测试到 `governance/mod.rs` 的 `#[cfg(test)] mod tests` 模块：

1. **`test_new_sensitive_params_zkvm_limits`** — 验证 6 项 ZKVM 限制参数标记为敏感
2. **`test_new_sensitive_params_gas_and_grace`** — 验证 `GasHypernovaVerify` / `ProductionGraceBlocks` 标记为敏感
3. **`test_new_sensitive_params_proof_field_limits`** — 验证 5 项 Proof 字段长度参数标记为敏感
4. **`test_new_params_default_values`** — 验证 13 项新参数默认值正确
5. **`test_new_params_get_set`** — 验证 13 项新参数 get/set 正常
6. **`test_validate_new_params_in_bounds`** — 验证边界内值通过
7. **`test_validate_new_params_out_of_bounds`** — 验证越界值被拒
8. **`test_zkvm_batch_size_consistency_constraint`** — 验证 `ZKVM_BATCH_SIZE` 一致性约束：
   - `max_zkvm_trace_steps=1_048_576, zkvm_batch_size=1024` → 通过（1024 batches ≤ 1000? No, 1048576/1024=1024 > 1000 → 应失败）
   - **修正**：默认 `max_zkvm_trace_steps=1_048_576, zkvm_batch_size=1024` → 1024 batches > 1000 → 默认配置本身就违反约束？
   
   **重新审视**：spec L6 说 "N ≤ 1,024,000 ≈ MAX_ZKVM_TRACE_STEPS"，即 `1000 × 1024 = 1,024,000`。但 `MAX_ZKVM_TRACE_STEPS = 1,048,576 = 2^20`。`1_048_576 / 1024 = 1024 > 1000`。
   
   **决策**：默认配置下 `1_048_576 / 1024 = 1024 > 1000` 会违反约束。这表明：
   - 选项 A：将默认 `max_zkvm_trace_steps` 降至 `1_024_000`（= 1000 × 1024）
   - 选项 B：将约束改为 `ceil(max_zkvm_trace_steps / zkvm_batch_size) ≤ MAX_FOLD_STEP_COUNT`，并接受默认配置略超（1024 > 1000）
   - 选项 C：将默认 `zkvm_batch_size` 提升至 `2048`（使 `1_048_576 / 2048 = 512 ≤ 1000`）
   
   **采用选项 A**：默认 `max_zkvm_trace_steps = 1_024_000`（= 1000 × 1024，恰好满足约束）。这与 spec L6 "N ≤ 1,024,000" 一致。poker_zkvm 的 `MAX_ZKVM_TRACE_STEPS = 1_048_576` 是编译期硬上限（防 DoS），治理参数默认值取更保守的 `1_024_000`。
   
   **更新 `DEFAULT_MAX_ZKVM_TRACE_STEPS`**：`1_048_576` → `1_024_000`
   
   测试用例：
   - `max_zkvm_trace_steps=1_024_000, zkvm_batch_size=1024` → 通过（1000 batches = 1000 ≤ 1000）
   - `max_zkvm_trace_steps=1_024_000, zkvm_batch_size=512` → 失败（2000 batches > 1000）
   - `max_zkvm_trace_steps=512_000, zkvm_batch_size=512` → 通过（1000 batches = 1000 ≤ 1000）

9. **`test_production_grace_blocks_default`** — 验证 `production_grace_blocks` 默认值 = `PRODUCTION_GRACE_BLOCKS` 常量（7200）

### Task 11.5.3：集成测试更新

**文件**：`poker_l1/tests/phase5a_integration.rs`（如有引用 `GAS_HYPERNOVA_VERIFY` 的断言）

搜索并更新所有引用 `GAS_HYPERNOVA_VERIFY == 50000` 的测试断言。

### Task 11.5.4：全量验证

1. `cargo build -p poker_l1` — 编译通过
2. `cargo build -p poker_zkvm` — 编译通过
3. `cargo test -p poker_l1` — 全部测试通过
4. `cargo test -p poker_zkvm` — 全部测试通过（回归）
5. `cargo clippy -p poker_l1 -- -D warnings` — 0 warnings
6. `cargo clippy -p poker_zkvm -- -D warnings` — 0 warnings
7. `cargo fmt --all --check` — 0 diffs

## 假设与决策

### 决策 1：ZKVM gas 常量 re-export 而非重复定义
- **选择**：`pub use poker_zkvm::syscalls::gas::{...}` re-export
- **理由**：保持 poker_zkvm 为单一事实源，避免常量值漂移
- **影响**：治理调整通过 `GovernanceParams.gas_hypernova_verify` 运行时字段实现，不修改编译期常量

### 决策 2：`DEFAULT_MAX_ZKVM_TRACE_STEPS = 1_024_000`（非 `1_048_576`）
- **选择**：默认值 `1_024_000`（= 1000 × 1024）
- **理由**：满足 `max_zkvm_trace_steps / zkvm_batch_size ≤ MAX_FOLD_STEP_COUNT` 一致性约束
- **影响**：poker_zkvm 的 `MAX_ZKVM_TRACE_STEPS = 1_048_576` 仍是编译期硬上限（防 DoS），治理参数默认值更保守

### 决策 3：所有 13 项新参数标记为敏感（90% quorum）
- **选择**：全部敏感
- **理由**：spec L340-348 明确要求"到 90% quorum 敏感参数表"
- **影响**：调整须 90% validator 赞成 + timelock

### 决策 4：跨参数一致性约束在 `validate_param` 中实现
- **选择**：在 `validate_param` 末尾追加 `ZKVM_BATCH_SIZE` / `MaxZkvmTraceSteps` 双向校验
- **理由**：`validate_param` 已支持跨参数依赖（如 `bonding_period_blocks` 依赖 `epoch_length_blocks`）
- **影响**：调整任一参数时都会校验另一参数的当前值

### 假设 1：`production_switch_height` 已完整实现
- **依据**：`ParamName::ProductionSwitchHeight` 已在 L227 定义，`is_sensitive()` 已包含，`GovernanceParams.production_switch_height` 字段已在 L413 定义
- **结论**：SubTask 11.5.2.10 无需变更

### 假设 2：proof 字段长度常量尚未在 Rust 代码中定义
- **依据**：Grep 搜索 `pub const MAX_PUBLIC_IO_SIZE` 等在 poker_zkvm/src 中无匹配
- **结论**：这些常量仅作为治理参数存在于 `GovernanceParams` 中，poker_zkvm 反序列化逻辑未来可通过传入治理参数值使用（Phase 12+ 集成）

## 验证步骤

1. **编译验证**：`cargo build -p poker_l1 && cargo build -p poker_zkvm`
2. **单元测试**：`cargo test -p poker_l1 --lib governance && cargo test -p poker_l1 --lib gas_table`
3. **回归测试**：`cargo test -p poker_l1 && cargo test -p poker_zkvm`
4. **Clippy**：`cargo clippy -p poker_l1 -- -D warnings && cargo clippy -p poker_zkvm -- -D warnings`
5. **Fmt**：`cargo fmt --all --check`
6. **集成测试**：`cargo test -p poker_l1 --test phase5a_integration`

## 实施顺序

1. Task 11.5.1（gas_table.rs 调整）— 独立，无依赖
2. Task 11.5.2.1-11.5.2.9（ParamName 扩展）— 依赖 11.5.1 的 `GAS_HYPERNOVA_VERIFY = 300000`
3. Task 11.5.2.10（production_switch_height）— 无变更
4. Task 11.5.2.11（单元测试）— 依赖 11.5.2.1-9
5. Task 11.5.3（集成测试更新）— 依赖 11.5.1
6. Task 11.5.4（全量验证）— 依赖所有上述任务
