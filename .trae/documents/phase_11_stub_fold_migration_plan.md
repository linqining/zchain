# Phase 11 Task 11.1: poker_l1 stub fold → 真实 Hypernova 折叠迁移计划

## Summary

将 `poker_l1/src/offline/ccs.rs` 中的 MVP stub fold 实现（blake2b 哈希链冒充）替换为真实 Hypernova 折叠，通过 thin wrapper 委托到 `poker_zkvm::fold::fold_step::fold` 和 `poker_zkvm::fold::fold_loop::fold_loop`。这是一次 **BREAKING 迁移**：旧 hash-based `CcsInstance` / `CcsCircuit` trait / `fold_step` / `fold_loop` 签名变更为 Fr-based 新类型，既有调用方必须迁移。

## Current State Analysis

### 需要修改的核心文件

1. **`poker_l1/src/offline/ccs.rs`**（核心修改文件）
   - L33-44: 旧 `CcsInstance` struct（hash-based，5 个 `Hash` 字段）— **未标记 `#[deprecated]`**
   - L56-78: 旧 `CcsCircuit` trait — **已标记 `#[deprecated]`**
   - L101-168: 旧 `fold_step()` — MVP stub，使用 `blake2::Blake2bVar` 哈希链累计
   - L195-244: 旧 `fold_loop()` — 循环调用 `fold_step`，返回 `FoldLoopResult`
   - L260-331: 旧 `ZkShuffleCcsCircuit` — **已标记 `#[deprecated]`**，使用 blake2b 哈希
   - L334-493: 8 个单元测试覆盖旧 fold_step / fold_loop / ZkShuffleCcsCircuit

2. **`poker_l1/src/offline/hypernova.rs`**
   - L56-90: 旧 `FoldedInstance` / `WitnessCommitment` / `FinalSumcheck` / `HypernovaProof`（hash-based，被旧 `FoldLoopResult` 使用）
   - L537: `map_zkvm_error()` — **private fn**，需改为 `pub(crate)` 供 ccs.rs 新 wrapper 复用

3. **`poker_l1/tests/phase5a_integration.rs`**
   - L11-14: 导入旧 `fold_loop, fold_step, CcsCircuit, CcsInstance, ZkShuffleCcsCircuit`
   - L817-1032: SubTask 42.5 测试（6 个 test）使用旧 hash-based API

4. **`poker_l1/benches/task36_zk_verifier.rs`**
   - L20: 导入旧 `fold_loop, fold_step, CcsInstance`
   - L103-185: `bench_fold_step_single` + `bench_fold_loop` 基准测试使用旧 API

### 已就绪的 poker_zkvm 真实实现（无需修改，仅 re-export）

- `poker_zkvm/src/fold/fold_step.rs` L102-107: `fold(lcccs, witness_commitment_l, ccccs, transcript) -> FoldStepOutput`
- `poker_zkvm/src/fold/fold_loop.rs` L137-147: `fold_loop(ccs, initial_lcccs, initial_commitment, ccccs_instances, pcs, transcript, ccs_commitment, public_io_commitment, batch_public_inputs) -> HypernovaProof`
- `poker_zkvm/src/precompiles/mod.rs` L146-166: 新 `CcsCircuit` trait（Fr-based `to_ccs_instance`）
- `poker_zkvm/src/prover/mod.rs` L407: `serialize_proof(proof: &HypernovaProof) -> Vec<u8>`
- `poker_zkvm/src/fold/fold_loop.rs` L76-100: 新 `HypernovaProof`（含 fold_steps / final_sumcheck / pcs_opening 等）

## Proposed Changes

### Step 1: `poker_l1/src/offline/hypernova.rs` — 提升 `map_zkvm_error` 可见性

**What**: 将 L537 的 `fn map_zkvm_error` 从 `fn`（private）改为 `pub(crate) fn`

**Why**: 新 ccs.rs wrapper 需要复用此错误映射函数将 `ZkvmError` 转为 `PokerL1Error`

**How**:
```rust
// L537: 改
fn map_zkvm_error(e: poker_zkvm::error::ZkvmError) -> PokerL1Error {
// 为
pub(crate) fn map_zkvm_error(e: poker_zkvm::error::ZkvmError) -> PokerL1Error {
```

### Step 2: `poker_l1/src/offline/ccs.rs` — 标记旧 `CcsInstance` 为 deprecated

**What**: 在旧 `CcsInstance` struct 上添加 `#[deprecated]` 属性

**Why**: SubTask 11.1.1 要求标记旧 hash-based 类型为废弃，引导调用方迁移到 `poker_zkvm::ccs::CcsInstance`

**How**:
```rust
#[deprecated(
    since = "0.3.0",
    note = "Use `poker_zkvm::ccs::CcsInstance` (Fr-based) instead. Phase 11 BREAKING migration."
)]
#[derive(Debug, Clone)]
pub struct CcsInstance { ... }
```

同时对 `FoldStepResult` 和 `FoldLoopResult` 添加 `#[deprecated]`。

### Step 3: `poker_l1/src/offline/ccs.rs` — 实现 `LegacyCcsInstanceAdapter`

**What**: 新增 `LegacyCcsInstanceAdapter` struct，实现新 `CcsCircuit` trait，但 `to_ccs_instance()` 返回 `Err`

**Why**: SubTask 11.1.2 — 提供编译兼容性，使依赖旧 hash-based `CcsInstance` 的代码能编译通过，但运行时明确失败（hash 是单向的，无法恢复矩阵）

**How**:
```rust
/// 旧 hash-based CcsInstance 的编译兼容适配器（Phase 11 过渡）。
///
/// **v1.2 诚实声明**：仅用于过渡期编译兼容，`to_ccs_instance()` 运行时返回 Err。
/// hash 是单向的，无法恢复真实 CCS 矩阵 / witness / public_inputs。
/// 旧调用方在 Production 下会失败，必须重构以提供真实矩阵。
#[deprecated(since = "0.3.0", note = "Migrate to poker_zkvm::ccs::CcsInstance with real matrices")]
pub struct LegacyCcsInstanceAdapter {
    /// 旧 hash-based 实例
    pub legacy: CcsInstance,
}

impl CcsCircuit for LegacyCcsInstanceAdapter {
    fn name(&self) -> &str { "legacy_hash_based_adapter" }
    fn num_matrices(&self) -> usize { self.legacy.mat_commitments.len() }
    fn to_ccs_instance(&self, _witness: &[Fr], _public_inputs: &[Fr]) -> Result<CcsInstance, ZkvmError> {
        Err(ZkvmError::Other(
            "legacy hash-based instance cannot be really folded — hash is one-way, cannot recover matrices".to_string()
        ))
    }
}
```

### Step 4: `poker_l1/src/offline/ccs.rs` — 移除 blake2b 哈希链逻辑 + 替换 fold_step/fold_loop

**What**:
- 旧 `fold_step()` 函数体替换为 `Err(PokerL1Error::Other("Phase 11 BREAKING: use poker_zkvm::fold::fold_step::fold instead"))`
- 旧 `fold_loop()` 函数体替换为同样的 Err
- 移除 `use blake2::Blake2bVar` 等相关 import（如果该文件不再需要）
- 新增 thin wrapper 函数 `fold_step_real()` 和 `fold_loop_real()` 委托到 poker_zkvm

**Why**: SubTask 11.1.3/11.1.4/11.1.5 — 移除 blake2b 哈希链冒充逻辑，提供真实折叠入口

**How** — 新增 wrapper（保留旧函数名但加 `_real` 后缀避免冲突，或使用不同模块路径）：
```rust
/// 真实 Hypernova 单步折叠（委托到 poker_zkvm::fold::fold_step::fold）。
pub fn fold_step_real(
    lcccs: &poker_zkvm::fold::lcccs::Lcccs,
    witness_commitment_l: &poker_zkvm::pcs::ipa::IpaCommitment,
    ccccs: &poker_zkvm::fold::ccccs::Ccccs,
    transcript: &mut poker_zkvm::transcript::Transcript,
) -> Result<poker_zkvm::fold::fold_step::FoldStepOutput, PokerL1Error> {
    poker_zkvm::fold::fold_step::fold(lcccs, witness_commitment_l, ccccs, transcript)
        .map_err(super::hypernova::map_zkvm_error)
}

/// 真实 Hypernova 多步折叠循环（委托到 poker_zkvm::fold::fold_loop::fold_loop）。
#[allow(clippy::too_many_arguments)]
pub fn fold_loop_real(
    ccs: &poker_zkvm::ccs::Ccs,
    initial_lcccs: poker_zkvm::fold::lcccs::Lcccs,
    initial_commitment: poker_zkvm::pcs::ipa::IpaCommitment,
    ccccs_instances: &[poker_zkvm::fold::ccccs::Ccccs],
    pcs: &poker_zkvm::pcs::ipa::IpaPcs,
    transcript: &mut poker_zkvm::transcript::Transcript,
    ccs_commitment: [u8; 32],
    public_io_commitment: [u8; 32],
    batch_public_inputs: Vec<Vec<poker_zkvm::ccs::Fr>>,
) -> Result<poker_zkvm::fold::fold_loop::HypernovaProof, PokerL1Error> {
    poker_zkvm::fold::fold_loop::fold_loop(
        ccs, initial_lcccs, initial_commitment, ccccs_instances, pcs,
        transcript, ccs_commitment, public_io_commitment, batch_public_inputs,
    ).map_err(super::hypernova::map_zkvm_error)
}
```

旧函数体改为：
```rust
#[deprecated(since = "0.3.0", note = "Use fold_step_real / poker_zkvm::fold::fold_step::fold instead")]
pub fn fold_step(...) -> Result<FoldStepResult, PokerL1Error> {
    Err(PokerL1Error::Other(
        "Phase 11 BREAKING: fold_step stub removed. Use poker_zkvm::fold::fold_step::fold instead.".to_string()
    ))
}

#[deprecated(since = "0.3.0", note = "Use fold_loop_real / poker_zkvm::fold::fold_loop::fold_loop instead")]
pub fn fold_loop(...) -> Result<FoldLoopResult, PokerL1Error> {
    Err(PokerL1Error::Other(
        "Phase 11 BREAKING: fold_loop stub removed. Use poker_zkvm::fold::fold_loop::fold_loop instead.".to_string()
    ))
}
```

### Step 5: Re-export 新类型

**What**: 在 `poker_l1/src/offline/ccs.rs` 顶部添加 re-export

**Why**: SubTask 11.1.6 — `poker_l1` 通过 `pub use` re-export 新类型，调用方无需直接依赖 poker_zkvm

**How**:
```rust
// Re-export 新 Fr-based 类型（Phase 11 迁移目标）
pub use poker_zkvm::precompiles::CcsCircuit as NewCcsCircuit;
pub use poker_zkvm::ccs::{Ccs as NewCcs, CcsInstance as NewCcsInstance, Fr as ZkvmFr};
pub use poker_zkvm::fold::fold_step::{fold as fold_step_real_fn, FoldStepOutput};
pub use poker_zkvm::fold::fold_loop::{fold_loop as fold_loop_real_fn, HypernovaProof as ZkvmHypernovaProof};
pub use poker_zkvm::fold::lcccs::Lcccs;
pub use poker_zkvm::fold::ccccs::Ccccs;
pub use poker_zkvm::pcs::ipa::{IpaCommitment, IpaPcs};
pub use poker_zkvm::transcript::Transcript as ZkvmTranscript;
```

### Step 6: 更新 `poker_l1/tests/phase5a_integration.rs`

**What**: 将 SubTask 42.5 的 6 个测试迁移到新 API

**Why**: SubTask 11.1.7 — 旧测试使用 hash-based CcsInstance + stub fold_step/fold_loop，现在返回 Err，必须迁移

**How** — 测试改为使用 `poker_zkvm::fold::fold_step::fold` 和 `fold_loop::fold_loop` 的真实 API：

1. `subtask_42_5_fold_step_single` → 使用真实 `fold()` + 线性 CCS（参考 `poker_zkvm/src/fold/fold_step.rs` 测试中的 `make_linear_ccs`）
2. `subtask_42_5_fold_step_multi_increments_count` → 链式 fold 两步
3. `subtask_42_5_fold_loop_multi_step` → 使用真实 `fold_loop()` + 3 个 CCCCS 实例
4. `subtask_42_5_fold_loop_empty_rejected` → 仍测试空 instances 被拒绝（但用新 API）
5. `subtask_42_5_fold_loop_exceeds_max_steps_rejected` → 用新 API 测试 1001 步被拒
6. `subtask_42_5_fold_loop_max_boundary_accepted` → 用新 API 测试 1000 步边界
7. `subtask_42_5_zk_shuffle_ccs_circuit_trait` → 使用 `poker_zkvm::precompiles::zk_shuffle::ZkShuffleCcsCircuit`（已存在）
8. `subtask_42_5_zk_shuffle_circuit_consumed_by_fold_loop` → 端到端用新 fold_loop
9. `subtask_42_5_fold_loop_produces_valid_public_io_for_checkin` → 用新 fold_loop 产出 proof → serialize → CheckinTx

**注**: 真实 fold_loop 需要 `IpaPcs` 实例和完整 CCS 结构，测试 helper 需要构造真实 CCS（参考 `poker_zkvm/src/fold/fold_step.rs` tests 的 `make_linear_ccs`）。

### Step 7: 更新 `poker_l1/benches/task36_zk_verifier.rs`

**What**: 迁移 `bench_fold_step_single` 和 `bench_fold_loop` 到新 API

**Why**: 旧基准使用 hash-based CcsInstance + stub fold，现在返回 Err

**How**:
- `bench_fold_step_single` — 使用真实 `fold()` + 线性 CCS，测量单步折叠延迟
- `bench_fold_loop` — 使用真实 `fold_loop()` + 10/100/1000 个 CCCCS 实例，测量多步延迟
- 注：真实 fold_loop 涉及 IPA PCS + sumcheck，延迟远高于 stub，sample_size 可能需调小

### Step 8: 删除旧 ccs.rs 内的单元测试 + 新增迁移验证测试

**What**: 删除 `poker_l1/src/offline/ccs.rs` L333-493 的旧单元测试（8 个），新增少量验证 deprecated 函数返回 Err 的测试

**Why**: 旧测试断言 stub 行为（fold_step_count 递增 / cumulative hash 等），现在返回 Err，断言无效

**How**:
```rust
#[test]
#[allow(deprecated)]
fn test_deprecated_fold_step_returns_error() {
    let instance = CcsInstance {
        mat_commitments: vec![[0; 32]],
        public_input_hash: [0; 32],
        witness_commitment: [0; 32],
        state_delta_hash: [0; 32],
        ack_step_hash: [0; 32],
    };
    let result = fold_step(None, &instance, crate::DEFAULT_CHAIN_ID, &crate::object_model::ObjectID::new([0u8; 20], 0));
    assert!(matches!(result, Err(PokerL1Error::Other(_))));
}

#[test]
#[allow(deprecated)]
fn test_deprecated_fold_loop_returns_error() {
    let result = fold_loop(&[], [0; 32], [0; 32], [0; 32], 0, Vec::new());
    assert!(matches!(result, Err(PokerL1Error::Other(_))));
}
```

## Assumptions & Decisions

### A1: 旧 `HypernovaProof`（hash-based）保留不变
**理由**: 旧 `HypernovaProof` 在 `hypernova.rs` 中被 `HypernovaVerifier` 间接使用（通过 `to_bytes()` + `proof_hash()`），且 verifier 接口接受 `&[u8]` 而非 struct。保留旧 struct 不影响 verifier 功能，仅标注 deprecated。

### A2: 旧 `FoldStepResult` / `FoldLoopResult` 标记 deprecated 但保留
**理由**: 调用方可能引用这些类型名，保留 struct 定义（标注 deprecated）避免编译错误，但 `fold_step`/`fold_loop` 返回 Err。

### A3: 新 wrapper 使用 `_real` 后缀而非覆盖旧函数名
**理由**: Rust 不允许同名函数，且保留旧函数名（返回 Err）使依赖旧 API 的代码在编译时收到 deprecation warning 而非链接错误。新函数用 `fold_step_real` / `fold_loop_real` 明确区分。调用方也可直接使用 `poker_zkvm::fold::fold_step::fold`。

### A4: 测试迁移使用线性 CCS（而非 ZkShuffleCcsCircuit）验证 fold 语义
**理由**: 真实 `fold_loop` 需要 IPA PCS + 完整 CCS 结构。ZkShuffleCcsCircuit 构建复杂（~1.77M 约束），不适合快速单元测试。使用 `poker_zkvm/src/fold/fold_step.rs` 测试中的 `make_linear_ccs`（x - y = 0 约束）验证折叠语义即可。

### A5: `LegacyCcsInstanceAdapter` 实现新 `CcsCircuit` trait（非旧 trait）
**理由**: 旧 `CcsCircuit` trait 已 deprecated。`LegacyCcsInstanceAdapter` 实现新 trait 提供编译兼容，但运行时 Err，符合 SubTask 11.1.2 的"诚实声明"。

### A6: 基准测试 sample_size 调整
**理由**: 真实 fold_loop 涉及 IPA PCS opening + sumcheck，单次延迟可能从 µs 级升到 ms 级。`bench_fold_loop` 的 sample_size 从 20 调到 10，steps 从 [10, 100, 1000] 调到 [10, 50, 100]（1000 步真实折叠可能超时）。

## Verification Steps

1. **编译检查**: `cargo build -p poker_l1` 无错误（deprecation warnings 预期）
2. **Clippy**: `cargo clippy -p poker_l1 -- -D warnings` 无新增 warning
3. **格式化**: `cargo fmt -p poker_l1 -- --check` 无 diff
4. **单元测试**: `cargo test -p poker_l1` 全部通过（含迁移后的 ccs.rs 测试 + hypernova.rs 测试）
5. **集成测试**: `cargo test -p poker_l1 --test phase5a_integration` 全部通过
6. **基准测试编译**: `cargo bench -p poker_l1 --no-run` 编译通过（不要求运行）
7. **poker_zkvm 回归**: `cargo test -p poker_zkvm` 全部通过（确认无回归）

## Execution Order

1. Step 1: hypernova.rs `map_zkvm_error` → `pub(crate)`（前置依赖）
2. Step 5: ccs.rs re-export 新类型（基础设施）
3. Step 2: ccs.rs 旧 CcsInstance + FoldStepResult + FoldLoopResult 标记 deprecated
4. Step 3: ccs.rs 实现 LegacyCcsInstanceAdapter
5. Step 4: ccs.rs 替换 fold_step/fold_loop 函数体 + 新增 fold_step_real/fold_loop_real wrapper
6. Step 8: ccs.rs 删除旧单元测试 + 新增 deprecated 验证测试
7. Step 6: phase5a_integration.rs 迁移测试
8. Step 7: task36_zk_verifier.rs 迁移基准
9. 验证：cargo build + clippy + fmt + test 全套
