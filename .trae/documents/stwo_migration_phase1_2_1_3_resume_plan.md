# Stwo 迁移 Phase 1.2 + 1.3 续作实施计划

> **本文档为续作计划**。原计划位于 `.trae/documents/stwo_migration_phase1_2_1_3_plan.md`，已完成 Step 0/1/3（rust-toolchain.toml / CpuAirEval + FrameworkEval / constraints pub(crate)），但因会话上下文中断而停止。本文档专注于完成剩余 Step 2/4/5/6/7。
>
> **目标**：完成 POC 决策门（≥100× 加速 vs Hypernova 8670ms 基准），判定是否进入 Phase 2-5 全量迁移。

---

## 1. 当前状态分析

### 1.1 已完成（前一会话产物，已通过代码探索验证）

| 项 | 文件 | 状态 |
|---|---|---|
| rust-toolchain.toml | `/Users/mac/projects/zchain/rust-toolchain.toml` | ✅ nightly-2026-04-15 |
| Stwo 2.3.0 依赖 | workspace + poker_zkvm Cargo.toml | ✅ features = ["parallel", "prover"] |
| constraints 6 个函数 pub(crate) | `poker_zkvm/src/constraints/mod.rs:118/170/179/231/244/271` | ✅ 已暴露 |
| CpuAirEval + FrameworkEval | `poker_zkvm/src/stwo_backend/air/cpu.rs:97-134` | ✅ Group A 约束（idx 连续性） |
| StwoTraceTable 类型 | `poker_zkvm/src/stwo_backend/trace.rs:25-56` | ✅ 骨架（new/set/get） |
| StwoProverConfig + StwoProof + 序列化 | `poker_zkvm/src/stwo_backend/prover.rs` | ✅ 骨架（prove 主体未实现） |
| ZkvmField::to_u32() | `poker_zkvm/src/field.rs:133-137` | ✅ BN254 Fr 低 32 位 |
| field.rs 32-bit limb 工具 | `poker_zkvm/src/stwo_backend/field.rs` | ✅ split/merge/u32_to_m31 |
| nightly 工具链下载 | 后台任务 job-0d5b483a | ✅ exit code 0 |

### 1.2 待完成（本计划范围）

| Step | 任务 | 文件 | 优先级 |
|---|---|---|---|
| Step 2 | `convert_trace_to_stwo` 真实实现 + 4 个测试 | `stwo_backend/trace.rs` | 🔴 高 |
| Step 4 | `StwoProver::prove()` 接入 `stwo::prover::prove` | `stwo_backend/prover.rs` | 🔴 高 |
| Step 5 | POC 端到端测试 + 性能基准 | `poker_zkvm/tests/stwo_poc_e2e.rs` | 🔴 高 |
| Step 6 | `StwoProverConfig` 默认值调整 | `stwo_backend/prover.rs` | 🟡 中 |
| Step 7 | lib.rs 模块文档更新 | `poker_zkvm/src/lib.rs` | 🟡 中 |
| 验证 | cargo build + cargo test stwo_backend + 决策门报告 | — | 🔴 高 |

### 1.3 关键 API 调研结论（基于 Stwo 2.3.0 源码核实）

1. **`stwo::prover::prove` 签名**：
   ```rust
   pub fn prove<B: BackendForChannel<MC>, MC: MerkleChannel>(
       components: &[&dyn ComponentProver<B>],
       channel: &mut MC::C,
       commitment_scheme: CommitmentSchemeProver<'_, B, MC>,
   ) -> Result<StarkProof<MC::H>, ProvingError>
   ```
   - 选择 `B = SimdBackend`, `MC = Blake2sMerkleChannel`
   - `MC::C = Blake2sChannel`, `MC::H = Blake2sMerkleHasher`

2. **`StarkProof<H>` 序列化**：直接 `#[derive(Serialize, Deserialize)]`，但**无原生 `to_bytes/from_bytes`**。必须添加 `bincode = "1"` 依赖，用 `bincode::serialize(&proof)` / `bincode::deserialize(&bytes)`。

3. **`FrameworkComponent<E>`** 在 `E: FrameworkEval + Sync` 时**自动实现 `ComponentProver<SimdBackend>`**（源码位置：`stwo-constraint-framework-2.3.0/src/prover/component_prover.rs:116-214`），无需手写 6 个底层方法。

4. **trace 数据注入路径**：`Vec<M31>` → `CircleEvaluation::new(domain, vec.into_iter().collect())` → `.bit_reverse()` → `tree_builder.extend_evals(evals)` → `tree_builder.commit(&mut channel)`。

5. **空 preprocessed tree 必须先 commit**（`PREPROCESSED_TRACE_IDX = 0`），即使无 preprocessed columns，否则 `prove_ex` 内部 panic。

6. **约束满足性**：若 trace 上 `idx[i+1] - idx[i] != 1`，`prove` 返回 `ProvingError::ConstraintsNotSatisfied`。POC 测试必须保证 trace 的 idx 列严格连续递增。

7. **SimdBackend 最小 log_size**：`log_size >= 5`（32 行+），低于此 fall back 到 CpuBackend。zchain `air_log_size = 20`（1M step）远超阈值。

---

## 2. 实施步骤

### Step 2: 实现 `convert_trace_to_stwo`

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace.rs`

**改动**：

1. **新增导入**：
   ```rust
   use crate::ccs::Fr as ZkvmFr;
   use crate::constraints::compile_step_witness;
   use crate::field::ZkvmField;
   use super::field::{M31, M31_LIMB_MASK};
   ```

2. **替换 `convert_trace_to_stwo` 实现**（当前返回空表）：
   ```rust
   pub fn convert_trace_to_stwo(trace: &Trace) -> Result<StwoTraceTable, ZkvmError> {
       if trace.is_empty() {
           return Err(ZkvmError::Other("convert_trace_to_stwo: trace 为空".to_string()));
       }
       let num_steps = trace.len();
       // Stwo FRI 要求 trace 行数为 2 的幂；至少 2 行（log_size >= 1）。
       let padded_rows = num_steps.next_power_of_two().max(2);
       let num_columns = crate::constraints::STEP_VARS; // 47
       let mut table = StwoTraceTable::new(num_columns, padded_rows);

       for i in 0..num_steps {
           let step = trace.step(i)?;
           let prev_step = if i > 0 { Some(trace.step(i - 1)?) } else { None };
           let next_step_pc = if i + 1 < num_steps {
               Some(trace.step(i + 1)?.pc)
           } else {
               None
           };
           let witness: Vec<ZkvmFr> = compile_step_witness(step, prev_step, next_step_pc);
           // 编译期断言：witness 长度 == STEP_VARS
           debug_assert_eq!(
               witness.len(),
               num_columns,
               "compile_step_witness 返回 {} 个值，但 STEP_VARS = {}",
               witness.len(),
               num_columns
           );
           for (col, fr_val) in witness.iter().enumerate() {
               let m31_val = fr_to_m31_single(fr_val)?;
               table.set(col, i, m31_val);
           }
       }
       // padding 行保持 M31::from(0u32)（StwoTraceTable::new 已初始化为零）
       // Phase 1.2 POC：仅 Group A 约束（idx 连续性）需要 idx 列正确；
       // padding 行的 idx 列必须为 0 才能满足 idx[i+1] - idx[i] - 1 == 0 的"边界豁免"
       // （Stwo FrameworkEval 默认对 padding 行不加约束，故 idx=0 padding 不会触发约束失败）
       Ok(table)
   }
   ```

3. **新增 `fr_to_m31_single` 辅助函数**：
   ```rust
   /// 将单个 BN254 Fr 转换为 M31（取低 30 bit）。
   ///
   /// # 安全性
   /// - 30-bit limb 掩码避免 M31 模数陷阱（P = 2^31 - 1，`M31::from(P)` 归约为 0）
   /// - Phase 1.2 POC：仅用于 step_index（u64 < 2^30 实际值）等小数值
   /// - Phase 3.x：将替换为 9-limb 完整 Fr → M31 转换（见 `field.rs::fr_to_m31_limbs`）
   fn fr_to_m31_single(fr: &ZkvmFr) -> Result<M31, ZkvmError> {
       let v = fr.to_u32();
       Ok(M31::from(v & M31_LIMB_MASK))
   }
   ```

4. **新增 4 个单元测试**：
   - `test_convert_trace_empty_returns_error` — 空 trace 返回错误
   - `test_convert_trace_padding_to_power_of_two` — 5 步 trace 应 padding 到 8 行
   - `test_convert_trace_step_index_column` — idx 列（col 0）应严格递增 0,1,2,...
   - `test_convert_trace_num_columns_matches_step_vars` — 列数 == STEP_VARS（47）

5. **测试辅助函数**：因 `Trace::steps` 私有且无 `from_steps` 构造器，使用 `Trace::new()` + `push_step(Step::from_log(...))`。需构造最小可执行的 `Step`（`Instruction::Lui { rd: 0, imm: 0 }` + 全零 registers）。

**验证**：
```bash
cargo test -p poker_zkvm --lib stwo_backend::trace
```

---

### Step 4: 实现 `StwoProver::prove()` 接入 `stwo::prover::prove`

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs`

**前置依赖改动**：

1. `/Users/mac/projects/zchain/Cargo.toml` workspace 依赖添加：
   ```toml
   bincode = "1"
   ```
2. `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml` 添加：
   ```toml
   bincode = { workspace = true }
   ```

**改动**：

1. **新增导入**（prover.rs 顶部）：
   ```rust
   use stwo::core::channel::Blake2sChannel;
   use stwo::core::fields::qm31::SecureField;
   use stwo::core::pcs::PcsConfig;
   use stwo::core::poly::circle::CanonicCoset;
   use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
   use stwo::prover::backend::simd::SimdBackend;
   use stwo::prover::backend::BackendForChannel;
   use stwo::prover::pcs::CommitmentSchemeProver;
   use stwo::prover::poly::circle::CircleEvaluation;
   use stwo::prover::poly::BitReversedOrder;
   use stwo::prover::{prove as stwo_prove, ComponentProver};
   use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

   use crate::execute::execute_elf;
   use crate::stwo_backend::air::cpu::CpuAirEval;
   use crate::stwo_backend::trace::convert_trace_to_stwo;
   ```

2. **替换 `StwoProver::prove()` 主体**（当前返回 `ZkvmError::Other`）：
   ```rust
   pub fn prove(
       &self,
       elf_bytes: &[u8],
       input: &[u8],
       public_io: &ZkPublicIo,
   ) -> Result<StwoProof, ZkvmError> {
       // 1. 执行 ELF 生成 trace（复用既有 execute_elf）
       let trace = execute_elf(elf_bytes, input)?;
       let num_steps = trace.len();
       if num_steps == 0 {
           return Err(ZkvmError::Other("StwoProver::prove: trace 为空".to_string()));
       }

       // 2. trace → StwoTraceTable
       let stwo_trace = convert_trace_to_stwo(&trace)?;

       // 3. 计算 log_size（trace 行数 = 2^log_size）
       let log_size = stwo_trace.num_rows.trailing_zeros();
       if (1usize << log_size) != stwo_trace.num_rows {
           return Err(ZkvmError::Other(format!(
               "StwoProver::prove: num_rows {} 不是 2 的幂",
               stwo_trace.num_rows
           )));
       }
       if log_size < 5 {
           return Err(ZkvmError::Other(format!(
               "StwoProver::prove: log_size {} < 5 (SimdBackend 最小要求)",
               log_size
           )));
       }

       // 4. StwoTraceTable.columns → Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>
       let domain = CanonicCoset::new(log_size).circle_domain();
       let trace_evals: Vec<CircleEvaluation<SimdBackend, _, BitReversedOrder>> = stwo_trace
           .columns
           .iter()
           .map(|col| {
               CircleEvaluation::<SimdBackend, _, _>::new(
                   domain,
                   col.iter().copied().collect(),
               )
               .bit_reverse()
           })
           .collect();

       // 5. 构造 channel + PcsConfig + twiddles + CommitmentSchemeProver
       let mut channel = Blake2sChannel::default();
       let config = PcsConfig::default();
       let lifting_log_size = log_size + 1;
       let twiddles = SimdBackend::precompute_twiddles(
           CanonicCoset::new(lifting_log_size + config.fri_config.log_blowup_factor).half_coset(),
       );
       let mut commitment_scheme =
           CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

       // 6. commit preprocessed tree（空占位）+ original trace tree
       {
           // 空 preprocessed tree（PREPROCESSED_TRACE_IDX = 0）
           let mut pp_builder = commitment_scheme.tree_builder();
           pp_builder.commit(&mut channel);

           // original trace tree（ORIGINAL_TRACE_IDX = 1）
           let mut trace_builder = commitment_scheme.tree_builder();
           trace_builder.extend_evals(trace_evals);
           trace_builder.commit(&mut channel);
       }

       // 7. 构造 FrameworkComponent<CpuAirEval>
       let mut location_allocator = TraceLocationAllocator::default();
       let cpu_eval = CpuAirEval::new(log_size);
       let claimed_sum = SecureField::zero(); // Phase 1.2 无 claimed sum
       let component = FrameworkComponent::new(&mut location_allocator, cpu_eval, claimed_sum);

       // 8. 调用 stwo::prover::prove
       let components: &[&dyn ComponentProver<SimdBackend>] = &[&component];
       let stark_proof = stwo_prove::<SimdBackend, Blake2sMerkleChannel>(
           components,
           &mut channel,
           commitment_scheme,
       )
       .map_err(|e| ZkvmError::Other(format!("Stwo prove 失败: {e:?}")))?;

       // 9. 序列化 StarkProof → Vec<u8>
       let stwo_proof_bytes = bincode::serialize(&stark_proof)
           .map_err(|e| ZkvmError::Other(format!("StarkProof 序列化失败: {e}")))?;

       // 10. 校验 proof 大小
       if stwo_proof_bytes.len() > self.config.proof_size_limit {
           return Err(ZkvmError::Other(format!(
               "Stwo proof 大小 {} 超出限制 {}",
               stwo_proof_bytes.len(),
               self.config.proof_size_limit
           )));
       }

       // 11. 组装 StwoProof
       let public_io_commitment = hash_stwo_public_io(public_io)?;
       let proof = StwoProof {
           public_io_commitment,
           ccs_commitment: [0u8; 32], // Phase 1.3：暂不绑定 ccs_commitment
           stwo_proof: stwo_proof_bytes,
       };

       Ok(proof)
   }
   ```

3. **更新既有测试**：原 `test_stwo_prover_returns_unimplemented` 应改名为 `test_stwo_prover_returns_error_on_empty_elf`，断言 `prove(b"", b"", &ZkPublicIo::default())` 返回错误。

**验证**：
```bash
cargo build -p poker_zkvm
cargo test -p poker_zkvm --lib stwo_backend::prover
```

**风险与缓解**：

| 风险 | 缓解 |
|---|---|
| `execute_elf` 函数签名可能与假设不符 | 实施前先 `rg "pub fn execute_elf" poker_zkvm/src/` 确认 |
| `compile_step_witness` 返回的 witness 中 idx 列（col 0）值范围超 2^30 | POC 阶段 num_steps << 2^30，安全；若超需切 9-limb |
| `StarkProof` 序列化大小超 64KB（MAX_STWO_PROOF_SIZE） | 先跑 POC 测量；若超需调整 FriConfig（降 n_queries） |
| `ConstraintsNotSatisfied` 错误 | POC trace 必须保证 idx 列连续递增；padding 行 idx=0 |

---

### Step 5: 创建 POC 端到端测试 + 性能基准

**文件**：`/Users/mac/projects/zchain/poker_zkvm/tests/stwo_poc_e2e.rs`（新建）

**测试目标**：
1. **功能正确性**：构造小 trace（32 步，满足 Group A 约束），prove 成功，proof 大小合理
2. **约束失败检测**：构造 idx 不连续 trace，prove 返回 `ConstraintsNotSatisfied`
3. **性能基准**：测量 1K/10K/100K/1M 步 trace 的 prove 耗时，对比 Hypernova 8670ms 基准
4. **决策门判定**：≥100× 加速 = ≤86.7ms（对 1M step）

**测试代码骨架**：

```rust
//! Stwo POC 端到端测试 — Phase 1.3 决策门。
//!
//! 决策门：1M step trace 的 prove 耗时 ≤ 86.7ms（Hypernova 基准 8670ms / 100）

use std::time::Instant;
use poker_zkvm::stwo_backend::{StwoProver, StwoProverConfig};
use poker_zkvm::trace::{Trace, Step, StepLog, MemAccess, MemOp};
use poker_zkvm::isa::Instruction;
use poker_zkvm::public_io::ZkPublicIo;

/// 构造最小可执行 Step（Lui x0, 0 + 全零寄存器）。
fn make_minimal_step(step_index: u64) -> Step {
    Step::from_log(
        step_index,
        StepLog {
            pc: 0,
            instruction: Instruction::Lui { rd: 0, imm: 0 },
            registers: [0u32; 32],
            mem_access: vec![],
        },
    )
}

/// 构造指定步数的 trace（idx 列严格连续递增）。
fn make_sequential_trace(num_steps: usize) -> Trace {
    let mut trace = Trace::new();
    for i in 0..num_steps {
        trace.push_step(make_minimal_step(i as u64));
    }
    trace
}

#[test]
fn test_stwo_poc_prove_minimal_trace() {
    // 32 步 trace，满足 Group A 约束（idx = 0..31 连续递增）
    let _trace = make_sequential_trace(32);
    // 注：StwoProver::prove 需要 ELF 字节，但 POC 阶段可绕过 execute_elf
    // 直接调用 convert_trace_to_stwo + CpuAirEval + stwo::prover::prove
    // 若 StwoProver::prove 不便绕过 ELF，需暴露一个 prove_from_trace 内部 API
    // TODO: 根据 Step 4 实际实现决定测试路径
}

#[test]
fn test_stwo_poc_decision_gate_1m_steps() {
    let num_steps = 1_048_576; // 1M step = 2^20
    let trace = make_sequential_trace(num_steps);

    let start = Instant::now();
    // 调用 StwoProver::prove_from_trace(&trace) 或类似入口
    let _proof = call_stwo_prove(&trace).expect("prove should succeed");
    let elapsed = start.elapsed();

    println!("Stwo prove 1M step: {:?}", elapsed);
    println!("Hypernova baseline: 8670ms");
    println!("Speedup: {:.1}x", 8670.0 / elapsed.as_millis() as f64);
    println!("Decision gate (≥100x): {}",
        if elapsed.as_millis() <= 86 { "PASS" } else { "FAIL" });

    // 软断言（不 fail 测试，仅打印决策门结果）
    // 硬断言留待基准稳定后开启
}

fn call_stwo_prove(_trace: &Trace) -> Result<(), Box<dyn std::error::Error>> {
    // 实施时根据 Step 4 暴露的 API 决定：
    // 选项 A：StwoProver::prove(elf_bytes, input, public_io) — 需构造可执行 ELF
    // 选项 B：新增 StwoProver::prove_from_trace(&trace) — 直接绕过 execute_elf
    // 推荐选项 B（POC 阶段更简洁）
    unimplemented!("实施时填充")
}
```

**关键决策**：是否在 `StwoProver` 上新增 `pub(crate) fn prove_from_trace(&trace)` 方法？

**推荐**：是。原因：
- POC 阶段无需可执行 ELF（构造最小 ELF 复杂度高）
- `prove_from_trace` 内部复用 `prove` 的 Step 2-11，仅跳过 Step 1（execute_elf）
- 测试可注入任意 trace，便于构造"约束失败"场景

**Step 4 补充**：在 `prover.rs` 添加：
```rust
/// 仅用 trace 生成 proof（绕过 execute_elf）。
/// 仅供 POC 测试使用；生产环境应使用 `prove()`。
pub(crate) fn prove_from_trace(
    &self,
    trace: &Trace,
    public_io: &ZkPublicIo,
) -> Result<StwoProof, ZkvmError> {
    // 与 prove() 共享 Step 2-11 逻辑
    // 抽出私有函数 prove_internal(trace, public_io) 供两者调用
    self.prove_internal(trace, public_io)
}
```

并重构 `prove()` 为：
```rust
pub fn prove(&self, elf_bytes: &[u8], input: &[u8], public_io: &ZkPublicIo) -> Result<StwoProof, ZkvmError> {
    let trace = execute_elf(elf_bytes, input)?;
    self.prove_internal(&trace, public_io)
}

fn prove_internal(&self, trace: &Trace, public_io: &ZkPublicIo) -> Result<StwoProof, ZkvmError> {
    // Step 2-11 逻辑
    ...
}
```

**验证**：
```bash
cargo test -p poker_zkvm --test stwo_poc_e2e -- --nocapture
```

---

### Step 6: 调整 `StwoProverConfig` 默认值

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs`

**改动**：

1. **`air_log_size` 字段语义改为"上限"**（运行时根据 trace 步数动态计算实际 log_size）：
   ```rust
   #[derive(Clone, Debug)]
   pub struct StwoProverConfig {
       /// AIR trace log_size 上限（运行时实际 log_size = ceil(log2(num_steps)).max(5)）。
       /// 默认 20（1M step 上限）。
       pub air_log_size: u32,  // usize → u32（与 Stwo API 一致）
       /// proof 序列化后最大字节数。
       pub proof_size_limit: usize,
       /// prove 随机性种子（注入 Blake2sChannel）。
       pub randomness_seed: crate::ccs::Fr,
   }

   impl Default for StwoProverConfig {
       fn default() -> Self {
           Self {
               air_log_size: 20,
               proof_size_limit: MAX_STWO_PROOF_SIZE,
               randomness_seed: crate::ccs::Fr::zero(),
           }
       }
   }
   ```

2. **`validate()` 增加 log_size 上限校验**：
   ```rust
   pub fn validate(&self) -> Result<(), ZkvmError> {
       if self.air_log_size < 5 || self.air_log_size > 25 {
           return Err(ZkvmError::Other(format!(
               "air_log_size {} 不在 [5, 25] 范围",
               self.air_log_size
           )));
       }
       if self.proof_size_limit == 0 {
           return Err(ZkvmError::Other("proof_size_limit == 0".to_string()));
       }
       Ok(())
   }
   ```

3. **更新既有 `test_stwo_prover_config_validate` 测试**覆盖新边界。

**验证**：
```bash
cargo test -p poker_zkvm --lib stwo_backend::prover::tests::test_stwo_prover_config
```

---

### Step 7: 更新 lib.rs 模块文档

**文件**：`/Users/mac/projects/zchain/poker_zkvm/src/lib.rs`

**改动**（行 57-61 附近）：

```rust
// ===== Stwo 迁移后端（Phase 1.2-1.3 完成，POC 决策门待验证）=====
// 详见 .trae/documents/stwo_migration_phase1_2_1_3_resume_plan.md
// 全量替换 Hypernova + CCS + IPA → Stwo Circle STARK + AIR + FRI on M31
// Phase 1.2: CpuAirEval + FrameworkEval（Group A 约束）+ convert_trace_to_stwo
// Phase 1.3: StwoProver::prove 接入 stwo::prover::prove + POC 决策门
// POC 通过后进入 Phase 2-5（Group B-F 约束 / Memory / ControlFlow / Syscall / precompile 迁移）
pub mod stwo_backend;
```

**验证**：
```bash
cargo doc -p poker_zkvm --no-deps 2>&1 | grep -E "warning.*stwo_backend" | head
```

---

## 3. 验证步骤（最终）

```bash
# 1. 编译验证（必须 nightly）
rustc --version  # 应输出 nightly-2026-04-15
cargo build -p poker_zkvm 2>&1 | tee /tmp/stwo_build.log

# 2. 单元测试
cargo test -p poker_zkvm --lib stwo_backend 2>&1 | tee /tmp/stwo_unit.log

# 3. POC 端到端测试 + 性能基准
cargo test -p poker_zkvm --test stwo_poc_e2e -- --nocapture 2>&1 | tee /tmp/stwo_poc.log

# 4. 决策门报告（手动撰写到 .trae/documents/stwo_poc_decision_report.md）
# 内容：
#   - 1M step prove 耗时
#   - Hypernova 基准（8670ms）
#   - 加速比
#   - 决策门判定（≥100× 通过 / 失败）
#   - 后续建议（进入 Phase 2-5 / 调优 / 回退）
```

**通过标准**：
- ✅ `cargo build -p poker_zkvm` 零错误（warning 可接受）
- ✅ `cargo test -p poker_zkvm --lib stwo_backend` 全部通过
- ✅ `cargo test -p poker_zkvm --test stwo_poc_e2e` 功能测试通过
- ✅ 决策门报告：1M step prove ≤ 86.7ms（≥100× 加速）

---

## 4. 假设与决策

### 4.1 假设

1. **`compile_step_witness` 返回的 witness[0] 是 step_index**：基于 `constraints/mod.rs` 中 STEP_VARS 注释 `[idx, pc, next_pc, ...]`。实施前需 `rg "witness\[0\]|witness.push.*idx" poker_zkvm/src/constraints/mod.rs` 验证。

2. **`execute_elf` 存在且签名匹配**：基于项目惯例推断。实施前需 `rg "pub fn execute_elf" poker_zkvm/src/` 验证；若签名不同（如返回 `Result<(Trace, ZkPublicIo), ZkvmError>`），Step 4 代码需相应调整。

3. **nightly-2026-04-15 已就绪**：后台任务 job-0d5b483a exit code 0 确认。

4. **`StarkProof<Blake2sMerkleHasher>` 满足 `Send`**：`Blake2sMerkleHasher` 是 unit struct，无 `Rc`/`RefCell`，自动 `Send + Sync`。

5. **POC trace（1M step）host 内存可承受**：1M step × 160B/step ≈ 160MB，低于 `MAX_TRACE_HOST_MEMORY = 512MB`。

### 4.2 决策

| 决策 | 选项 | 理由 |
|---|---|---|
| 序列化后端 | bincode 1.x | 紧凑二进制，StarkProof 已 derive Serialize/Deserialize |
| MerkleChannel | Blake2sMerkleChannel | Stwo 默认，SimdBackend 已实现 BackendForChannel |
| Backend | SimdBackend | 性能最优，nightly required |
| PcsConfig | Default | pow_bits=10, FriConfig::new(0, 1, 3, 1)，POC 阶段足够 |
| prove 入口 | `prove()` + `prove_from_trace()` | 生产用前者，POC 用后者绕过 ELF 构造 |
| log_size 来源 | 运行时计算 | 从 trace.num_rows.trailing_zeros() 取，避免硬编码 |
| padding 策略 | 零填充至 2 的幂 | StwoTraceTable::new 已初始化零；Group A 约束对 padding 行豁免 |

### 4.3 未选择方案（备选）

1. **不用 bincode，用 postcard**：postcard 更紧凑但引入额外依赖；bincode 是 Rust 生态默认，且 poker_l1 可能已间接依赖（实施前 `rg "bincode" Cargo.lock` 确认）。

2. **不新增 `prove_from_trace`，构造最小 ELF**：复杂度高，需用 RISC-V 工具链编译空程序；POC 阶段不值。

3. **用 CpuBackend 替代 SimdBackend**：无需 nightly，但慢 10×，无法通过 ≥100× 决策门。

---

## 5. 工期估算

| Step | 估时 | 风险 |
|---|---|---|
| Step 2 | 0.5 天 | 低（设计已确定） |
| Step 4 | 1.5 天 | 中（Stwo API 集成，可能遇 borrow/move 问题） |
| Step 5 | 1 天 | 中（POC trace 构造 + 性能测量） |
| Step 6 | 0.25 天 | 低 |
| Step 7 | 0.25 天 | 低 |
| 验证 + 决策门报告 | 0.5 天 | 中（1M step prove 可能 OOM 或超时） |
| **合计** | **4 天** | — |

---

## 6. 后续工作（本计划范围外）

POC 决策门通过后，进入 Phase 2-5（另文细化）：

- **Phase 2**：CPU AIR Group B-F 完整约束（PC 连续性 / selector one-hot / selector 二值性 / 算术语义 / carry 二值性）
- **Phase 3**：Memory / ControlFlow / Syscall AIR 组件 + precompile 迁移（Poseidon / SHA-256 / Keccak）
- **Phase 4**：Stwo verifier 完整实现 + scheme_id=4 兼容
- **Phase 5**：Hypernova 模块删除 + poker_l1 集成切换

POC 决策门失败则回退：
- 评估 Stwo 性能瓶颈（FRI? commit? sumcheck?）
- 考虑替代方案（Plonky3 / RISC Zero STARK / 保留 Hypernova 优化）
