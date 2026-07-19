# Stwo 迁移 Phase 1.2 + 1.3 实施计划

> **目标**：完成 Stwo 迁移的 POC 决策门 — 实现真实 Stwo `FrameworkEval` + `stwo::prover::prove()` 接入，用 poker ELF 端到端验证 M31 field 实际加速比（≥100× 决策门）。
> **范围**：仅 Phase 1.2（CPU AIR Group A + trace 转换）+ Phase 1.3（POC 验证 + 性能基准）。Phase 2-5 留待 POC 通过后另文细化。
> **前置状态**：Phase 1.1 骨架已完成（25/25 测试通过，`cargo +nightly build -p poker_zkvm` 成功）。
> **决策依据**：用户明确选择①创建 `rust-toolchain.toml` 固定 nightly；②本次仅覆盖 Phase 1.2 + 1.3。

---

## Context（背景与动机）

### 已完成（Phase 1.1）

- `poker_zkvm/Cargo.toml` 添加 `stwo` / `stwo-air-utils` / `stwo-air-utils-derive` / `stwo-constraint-framework` 依赖
- `poker_zkvm/src/stwo_backend/` 模块骨架（10 文件）：`mod.rs` / `field.rs` / `prover.rs` / `verifier.rs` / `trace.rs` / `air/{mod,cpu,memory,control_flow,syscall}.rs`
- `StwoProverConfig` + STWO proof 序列化格式（`b"STWO"` magic + version + pio + ccs + stwo_proof）
- 30-bit limb M31 域转换工具（`split_u32_to_m31_limbs` / `merge_m31_limbs_to_u32`）— 已通过 roundtrip 测试
- `StwoProver::prove()` / `verify_stwo()` 返回 `ZkvmError::Other`（占位）

### 关键 Stwo API 发现（Phase 1 探索）

| Stwo API | 路径 | 用途 |
|----------|------|------|
| `FrameworkEval` trait | `stwo-constraint-framework::component` | **高层 AIR 抽象**，仅需实现 `log_size` / `max_constraint_log_degree_bound` / `evaluate<E: EvalAtRow>` 3 个方法 |
| `FrameworkComponent<E>` | 同上 | 自动为 `FrameworkEval` 实现 `Component` + `ComponentProver<SimdBackend>`，免手写 6 个底层方法 |
| `stwo::prover::prove` | `stwo::prover::mod` | 顶层 prove 入口：`prove(components: &[&dyn ComponentProver<B>], channel, commitment_scheme) -> StarkProof` |
| `assert_constraints_on_trace` | `stwo-constraint-framework::prover` | 测试工具：直接验证 trace 是否满足 `FrameworkEval` 约束 |
| `M31` / `QM31` | `stwo::core::fields::m31` / `qm31` | `M31(pub u32)` 内部字段 public，`QM31` = SecureField（4 个 M31） |

→ **关键简化**：无需手写 `Component` trait 的 6 个底层方法（`mask_points` / `evaluate_constraint_quotients_at_point` 等），仅需实现 `FrameworkEval` 的 3 个方法。

### Hypernova CCS 约束对应（参考）

[`poker_zkvm/src/constraints/mod.rs:540`](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) Group A-F：

| Group | 约束 | Phase 1.2 范围 |
|-------|------|---------------|
| A | `idx_{i+1} - idx_i - 1 = 0`（step_index 连续性） | ✅ 实现 |
| B | `next_pc_i - pc_{i+1} = 0`（PC 连续性） | ⏳ Phase 2.2 |
| C | `Σ_j sel_j(i) - 1 = 0`（selector one-hot） | ⏳ Phase 2.5 |
| D | `sel_j(i)² - sel_j(i) = 0`（selector 二值性） | ⏳ Phase 2.5 |
| E | 算术/逻辑/移位语义 | ⏳ Phase 2.1 |
| F | `carry(i)² - carry(i) = 0` | ⏳ Phase 2.1 |

**Phase 1.2 仅实现 Group A**，足以验证 M31 field 性能（prove 主要开销在 FRI + sumcheck，约束数量影响小）。

---

## Proposed Changes

### Step 0：创建 `rust-toolchain.toml`（用户决策①）

**文件**：`/Users/mac/projects/zchain/rust-toolchain.toml`（新建）

```toml
[toolchain]
channel = "nightly-2026-04-15"
components = ["rustfmt", "clippy"]
profile = "default"
```

**原因**：Stwo 2.3.0 `prover` feature 需要 `#![feature(iter_array_chunks, portable_simd, slice_ptr_get)]`，仅 nightly 可用。固定 nightly-2026-04-15（与 `rustc +nightly --version` 输出一致）保证 CI/本地构建一致。

**影响**：整个 workspace 默认使用 nightly。Stable Rust 1.97.0 代码兼容 nightly，故 `poker_l1` 等其他 crate 不受影响。Phase 5 删除 Hypernova 后可评估回退 stable。

**验证**：
```bash
rustc --version  # 应输出 nightly-2026-04-15
cargo build -p poker_zkvm  # 无需 +nightly 前缀
cargo test -p poker_zkvm stwo_backend::
```

---

### Step 1：实现 `CpuAirComponent` 的 `FrameworkEval`（Phase 1.2 核心）

**文件**：[`poker_zkvm/src/stwo_backend/air/cpu.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/air/cpu.rs)（修改）

**改造内容**：
1. **新增 `CpuAirEval` struct**（实现 `FrameworkEval`），与现有 `CpuAirComponent` 并存：
   ```rust
   use stwo_constraint_framework::{FrameworkEval, EvalAtRow};
   use stwo::core::fields::m31::M31;
   use stwo::core::fields::qm31::SecureField;

   /// CPU AIR 约束评估器（Phase 1.2：仅 Group A step_index 连续性）。
   ///
   /// 实现 `FrameworkEval`，由 `FrameworkComponent<CpuAirEval>` 自动生成
   /// `Component` + `ComponentProver<SimdBackend>` 实现。
   pub struct CpuAirEval {
       /// trace 行数的 log2（如 1024 行 → log_size = 10）。
       pub log_size: u32,
   }

   impl FrameworkEval for CpuAirEval {
       fn log_size(&self) -> u32 { self.log_size }

       fn max_constraint_log_degree_bound(&self) -> u32 {
           // Group A 约束度数 = 1（线性约束 idx[i+1] - idx[i] - 1）
           // bound = log_size + 1（标准 STARK 约束度上界）
           self.log_size + 1
       }

       fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
           // 列布局（与 compile_step_witness 一致，47 列）：
           // col 0 = idx (low 30-bit limb), col 47 = idx (high 2-bit limb)
           // 注意：u32 step_index 用 2 limb M31 表示（split_u32_to_m31_limbs）
           let idx_low_cur = eval.next_trace_mask();  // col 0
           // ... 跳过 col 1..46 ...
           let idx_high_cur = eval.next_trace_mask(); // col 47
           let idx_low_next = eval.next_trace_mask(); // col 48 (下一行 col 0)
           let idx_high_next = eval.next_trace_mask();// col 50 (下一行 col 47)

           // Group A: idx_next - idx_cur - 1 == 0
           // 由于 2-limb 表示，需分别约束 low/high limb 并处理进位
           // 简化方案（Phase 1.2）：假设 step_index < 2^30（trace 长度 < 1G step），
           // 仅用 low limb 约束，high limb 设为 0
           let one = M31::from(1u32);
           let constraint = idx_low_next - idx_low_cur - one;
           eval.add_constraint(constraint);

           eval
       }
   }
   ```

2. **保留现有 `CpuAirComponent` + `StwoAirComponent` trait impl**：作为高层 API 占位，Phase 2 重写时再决定是否替换为 `FrameworkEval`。当前测试不破坏。

3. **新增单元测试**：
   - `test_cpu_air_eval_log_size`：验证 `log_size()` 返回值
   - `test_cpu_air_eval_constraint_count`：用 `InfoEvaluator` 验证约束数为 1（仅 Group A）
   - `test_cpu_air_eval_satisfied_on_valid_trace`：构造连续 step_index trace，用 `assert_constraints_on_trace` 验证约束满足
   - `test_cpu_air_eval_violated_on_gap_trace`：构造 step_index 跳跃 trace，验证约束违反

**关键决策**：
- **2-limb vs 1-limb step_index**：Phase 1.2 假设 `step_index < 2^30`（实际 trace ≤ 1M step，远小于 2^30 = 1G），仅用 1 个 M31 表示。简化约束表达式，避免进位逻辑。若未来 trace 超过 2^30 步，扩展为 2-limb。
- **trace 列布局**：每行 47 个 M31 值（对应 `STEP_VARS`）。`compile_step_witness` 的 47 个 BN254 Fr 值逐一转换为 M31（u32 值 ≤ 2^31 - 1 直接 `M31::from`，> 2^31 - 1 用 2 limb）。

---

### Step 2：实现 `convert_trace_to_stwo`（Phase 1.2 trace 转换）

**文件**：[`poker_zkvm/src/stwo_backend/trace.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace.rs)（修改）

**改造内容**：将 `convert_trace_to_stwo()` 从骨架（返回空表）改为完整实现：

```rust
pub fn convert_trace_to_stwo(trace: &Trace) -> Result<StwoTraceTable, ZkvmError> {
    if trace.is_empty() {
        return Err(ZkvmError::Other("convert_trace_to_stwo: trace 为空".to_string()));
    }

    let num_steps = trace.len();
    // Stwo FRI 要求 trace 行数为 2 的幂。Padding 用零行（dummy step）。
    let padded_rows = num_steps.next_power_of_two().max(2);
    let log_size = padded_rows.trailing_zeros();

    let num_columns = crate::constraints::STEP_VARS; // 47
    let mut table = StwoTraceTable::new(num_columns, padded_rows);

    // 复用 compile_step_witness 生成每步 47 个 Fr 值
    for i in 0..num_steps {
        let step = trace.step(i)?;
        let prev_step = if i > 0 { Some(trace.step(i - 1)?) } else { None };
        let next_step_pc = if i + 1 < num_steps {
            Some(trace.step(i + 1)?.pc)
        } else {
            None
        };
        let witness: Vec<ZkvmFr> = compile_step_witness(step, prev_step, next_step_pc);

        // 域转换 Fr → M31（每步 47 列）
        for (col, fr_val) in witness.iter().enumerate() {
            let m31_val = fr_to_m31_single(fr_val)?;
            table.set(col, i, m31_val);
        }
    }
    // padding 行保持 M31::from(0u32)（StwoTraceTable::new 已初始化为零）

    Ok(table)
}

/// 单个 BN254 Fr → M31 转换（Phase 1.2 简化版）。
///
/// **关键限制**：当前仅正确处理 ≤ 2^31 - 1 的值（u32 范围内）。
/// 完整 254-bit Fr → 9 limb M31 转换留待 Phase 3.x precompile 迁移。
///
/// Phase 1.2 POC 中，compile_step_witness 产生的 47 个值均为 u32 派生
///（idx/pc/rs1_val/.../selectors），均 ≤ 2^31 - 1，故直接 M31::from(u32)。
fn fr_to_m31_single(fr: &ZkvmFr) -> Result<M31, ZkvmError> {
    // ZkvmFr::to_u32() — 需要确认 API 是否存在
    // 若 fr > M31_MAX，返回错误（Phase 1.2 POC 不应出现此情况）
    let bytes = fr.to_bytes(); // 32 字节 LE
    // 取低 4 字节作为 u32（假设值 ≤ 2^31 - 1）
    let low_u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if low_u32 > M31_MAX {
        return Err(ZkvmError::Other(format!(
            "fr_to_m31_single: 值 {} > M31_MAX {}（Phase 1.2 仅支持 ≤ 2^31-1）",
            low_u32, M31_MAX
        )));
    }
    Ok(M31::from(low_u32))
}
```

**新增测试**：
- `test_convert_trace_to_stwo_empty`：空 trace 返回错误
- `test_convert_trace_to_stwo_padding`：3 步 trace → padded 4 行（2 的幂）
- `test_convert_trace_to_stwo_step_index`：验证转换后 col 0 = step_index（0, 1, 2, ...）
- `test_convert_trace_to_stwo_columns`：验证列数 = 47

**依赖**：`compile_step_witness` 当前是 `constraints/mod.rs` 的私有函数。需将其改为 `pub(crate)` 或新增公开 wrapper。

---

### Step 3：暴露 `compile_step_witness` 为 `pub(crate)`

**文件**：[`poker_zkvm/src/constraints/mod.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs)（修改）

**改造**：将 `fn compile_step_witness(...)` 改为 `pub(crate) fn compile_step_witness(...)`。

**原因**：`stwo_backend::trace::convert_trace_to_stwo` 需复用此函数生成 witness 行，避免逻辑重复。`extract_insn_fields` / `assign_selectors` / `compute_taken` / `compute_next_pc` 同理需暴露（`compile_step_witness` 内部调用）。

**改动范围**：
- `compile_step_witness` → `pub(crate)`
- `extract_insn_fields` → `pub(crate)`（被 `compile_step_witness` 调用）
- `assign_selectors` → `pub(crate)`（同上）
- `compute_taken` → `pub(crate)`（同上）
- `compute_next_pc` → `pub(crate)`（同上）
- `instruction_category` → `pub(crate)`（被 `assign_selectors` 调用）

---

### Step 4：实现 `StwoProver::prove()` 真实接入（Phase 1.3）

**文件**：[`poker_zkvm/src/stwo_backend/prover.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs)（修改）

**改造内容**：将 `StwoProver::prove()` 从返回 `ZkvmError::Other` 改为真实 Stwo prove 调用：

```rust
use stwo::prover::{prove as stwo_prove, ComponentProver};
use stwo::prover::backend::{SimdBackend, Backend};
use stwo::prover::pcs::{CommitmentSchemeProver, DefaultCommitmentScheme};
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;

use super::trace::convert_trace_to_stwo;
use super::air::cpu::CpuAirEval;
use crate::compiler::elf_validator::validate_elf;
use crate::isa::executor::{execute_elf_with_config, ZkvmExecutionConfig};
use crate::prover::StubHostState;

impl StwoProver {
    pub fn prove(
        &self,
        elf_bytes: &[u8],
        input: &[u8],
        public_io: &ZkPublicIo,
    ) -> Result<StwoProof, ZkvmError> {
        self.config.validate()?;

        // 1. ELF 校验
        let _metadata = validate_elf(elf_bytes)?;

        // 2. 执行 ELF → trace
        let exec_config = ZkvmExecutionConfig {
            input: input.to_vec(),
            randomness_seed: self.config.randomness_seed.into_fr(),
            initial_commitment: crate::ccs::Fr::zero().into_fr(), // POC 简化
            final_commitment: crate::ccs::Fr::zero().into_fr(),
            host_state: Box::new(StubHostState),
        };
        let exec_result = execute_elf_with_config(elf_bytes, exec_config)?;

        // 3. trace → StwoTraceTable
        let trace_table = convert_trace_to_stwo(&exec_result.trace)?;
        let log_size = trace_table.num_rows.trailing_zeros();
        if log_size == 0 || log_size > 30 {
            return Err(ZkvmError::Other(format!(
                "StwoProver::prove: log_size {} 越界（须 1..=30）", log_size
            )));
        }

        // 4. 构造 FrameworkComponent<CpuAirEval>
        let cpu_eval = CpuAirEval { log_size };
        let mut location_allocator = TraceLocationAllocator::default();
        let claimed_sum = SecureField::zero(); // Group A 约束 sum = 0
        let cpu_component = FrameworkComponent::new(
            &mut location_allocator,
            cpu_eval,
            claimed_sum,
        );

        // 5. 构造 trace polynomials（列主序 → Poly）
        // StwoTraceTable.columns[col][row] → Vec<Poly>
        let trace_polys = build_trace_polys(&trace_table, log_size)?;

        // 6. 构造 CommitmentSchemeProver + Channel
        let config = stwo::prover::pcs::DefaultProverConfig::default();
        let commitment_scheme = CommitmentSchemeProver::new(
            &trace_polys,
            config,
        );
        let mut channel = Blake2sMerkleChannel::channel(); // 默认 Channel

        // 7. Stwo prove
        let components: &[&dyn ComponentProver<SimdBackend>] = &[&cpu_component];
        let stark_proof = stwo_prove::<SimdBackend, Blake2sMerkleChannel>(
            components,
            &mut channel,
            commitment_scheme,
        ).map_err(|e| ZkvmError::Other(format!("Stwo prove 失败: {e}")))?;

        // 8. 序列化 StarkProof → bytes（用 serde 或 bincode）
        let stwo_proof_bytes = serialize_stark_proof(&stark_proof)?;

        // 9. 构造 StwoProof
        let public_io_commitment = hash_public_io(public_io);
        let ccs_commitment = [0u8; 32]; // Phase 4.x 定义 AIR 结构 hash
        Ok(StwoProof {
            public_io_commitment,
            ccs_commitment,
            stwo_proof: stwo_proof_bytes,
        })
    }
}
```

**辅助函数 `build_trace_polys`**：
- 输入：`&StwoTraceTable`（列主序 `Vec<Vec<M31>>`）
- 输出：`Vec<Poly<SimdBackend>>`（Stwo trace 多项式）
- 算法：对每列调用 `CircleEvaluation::new` + FFT 得到 `Poly`

**辅助函数 `serialize_stark_proof`**：
- 输入：`&StarkProof<Blake2sMerkleChannel::Hash>`
- 输出：`Vec<u8>`
- 算法：用 `bincode` 或 Stwo 自带序列化（需检查 Stwo API）

**关键风险**：
- Stwo `CommitmentSchemeProver::new` / `Blake2sMerkleChannel::channel` 的确切构造 API 需在实现时验证（Phase 1 探索已确认入口存在，但具体参数需查 Stwo 源码）
- `StarkProof` 序列化格式需确认（可能需手动实现或用 serde derive）
- 若 API 不匹配，回退到 Stwo benches/ 示例代码作为参考

---

### Step 5：POC 测试 — poker ELF 端到端 prove + 性能基准（Phase 1.3）

**文件**：`/Users/mac/projects/zchain/poker_zkvm/tests/stwo_poc_e2e.rs`（新建）

**测试内容**：
```rust
use poker_zkvm::stwo_backend::{StwoProver, StwoProverConfig};
use poker_zkvm::test_helpers::build_texas_poker_full_hand_elf;
use poker_zkvm::prover::{ZkPublicIo, hash_public_io};
use std::time::Instant;

#[test]
fn test_stwo_poc_poker_elf_prove() {
    let elf = build_texas_poker_full_hand_elf();
    let prover = StwoProver::new(StwoProverConfig::default());

    let public_io = ZkPublicIo {
        input: vec![],
        output: vec![],
        randomness_seed: poker_zkvm::ccs::Fr::zero(),
        initial_commitment: poker_zkvm::ccs::Fr::zero(),
        final_commitment: poker_zkvm::ccs::Fr::zero(),
        event_hashes: vec![],
    };

    let start = Instant::now();
    let proof = prover.prove(&elf, b"", &public_io)
        .expect("Stwo prove 失败");
    let elapsed = start.elapsed();

    // 验证 proof 结构
    assert!(proof.stwo_proof.len() > 0);
    assert!(proof.stwo_proof.len() <= 64 * 1024);
    assert_eq!(proof.public_io_commitment, hash_public_io(&public_io));

    // 性能基准输出
    println!("\n=== Stwo POC 性能基准 ===");
    println!("ELF: build_texas_poker_full_hand_elf");
    println!("prove 延迟: {:.2?}（{}ms）", elapsed, elapsed.as_millis());
    println!("proof 大小: {} bytes", proof.stwo_proof.len());
    println!("对比 Hypernova 0-fold 基准: 8670ms");
    println!("加速比: {:.1}×", 8670.0 / elapsed.as_millis() as f64);
    println!("=========================\n");

    // 决策门：≥100× 加速
    let acceleration = 8670.0 / elapsed.as_millis() as f64;
    assert!(
        acceleration >= 100.0,
        "Stwo POC 加速比 {}× < 100× 决策门 — 需评估替代方案",
        acceleration
    );
}

#[test]
fn test_stwo_poc_poker_elf_prove_and_verify() {
    // 完整 prove + verify 闭环（Phase 4.1 verify_stwo 内部验证实现后）
    // Phase 1.3 暂仅验证 prove，verify 留待 Phase 4.1
    let elf = build_texas_poker_full_hand_elf();
    let prover = StwoProver::new(StwoProverConfig::default());
    let public_io = ZkPublicIo { /* ... */ };
    let proof = prover.prove(&elf, b"", &public_io).unwrap();
    let proof_bytes = poker_zkvm::stwo_backend::serialize_stwo_proof(&proof);
    // verify_stwo 暂返回未实现错误，仅验证反序列化 + public_io 绑定校验
    let result = poker_zkvm::stwo_backend::verify_stwo(&proof_bytes, &public_io);
    assert!(result.is_err()); // Phase 4.1 后改为 is_ok
}
```

**辅助基准**（可选，若 `test_stwo_poc_poker_elf_prove` 通过决策门则跳过）：
- `test_stwo_poc_nop_elf_prove`：`build_nop_elf(80)` 简单 80 步程序，对比 Hypernova 8.67s
- `test_stwo_poc_poker_hand_eval_elf_prove`：`build_poker_hand_eval_v2_elf()` 中等复杂度

---

### Step 6：更新 `StwoProverConfig` 默认值（Phase 1.3）

**文件**：[`poker_zkvm/src/stwo_backend/prover.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs)（修改）

**改造**：
- `air_log_size` 默认值从 20（1M step）改为 0（运行时根据 trace 长度计算）
- 新增 `log_size_override: Option<u32>` 字段（测试时强制指定 log_size）

**原因**：Phase 1.1 骨架假设 1M step，但 POC 中 trace 长度由 ELF 实际执行决定（poker full hand ~ 数千步）。`prove()` 内部用 `trace.num_rows.next_power_of_two().trailing_zeros()` 计算实际 log_size。

---

### Step 7：更新 `lib.rs` 模块文档（Phase 1.3 收尾）

**文件**：[`poker_zkvm/src/lib.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs)（修改）

**改造**：更新 stwo_backend 模块注释，反映 Phase 1.2-1.3 完成状态：
```rust
// ===== Stwo 迁移后端（Phase 1.2-1.3 完成）=====
// 详见 .trae/documents/hypernova_to_stwo_migration_plan.md
// 详见 .trae/documents/stwo_migration_phase1_2_1_3_plan.md
// 全量替换 Hypernova + CCS + IPA → Stwo Circle STARK + AIR + FRI on M31
// Phase 1.2：CpuAirEval (FrameworkEval) + Group A 约束 + trace 转换
// Phase 1.3：StwoProver::prove() 接入 stwo::prover::prove + POC 验证
// Phase 5 完成后将替代 Layer 1/3/3.5/4/6 的 Hypernova 相关模块
pub mod stwo_backend;
```

---

## Assumptions & Decisions

### 已确认决策（用户）

1. **Rust 工具链**：创建 `rust-toolchain.toml` 固定 nightly-2026-04-15（workspace-wide）
2. **计划范围**：仅 Phase 1.2 + 1.3（POC 决策门），Phase 2-5 留待 POC 通过后另文细化

### 技术决策（实施者）

3. **AIR 抽象层**：使用 `stwo-constraint-framework::FrameworkEval`（高层 API），不手写底层 `Component` trait。理由：免手写 6 个底层方法（`mask_points` / `evaluate_constraint_quotients_at_point` 等），Stwo 官方推荐路径。
4. **Group A only**：Phase 1.2 仅实现 step_index 连续性约束。理由：prove 开销主要由 FRI + sumcheck 决定，约束数量影响小；Group A 足以验证 M31 field 性能。
5. **step_index 单 limb 表示**：假设 `step_index < 2^30`（实际 trace ≤ 1M step），仅用 1 个 M31 表示。理由：简化约束表达式，避免 2-limb 进位逻辑。若未来 trace 超过 2^30 步，扩展为 2-limb。
6. **保留 `StwoAirComponent` trait**：与 `FrameworkEval` 并存。理由：不破坏现有 25 个测试；Memory/ControlFlow/Syscall 组件仍用 `StwoAirComponent` 占位，Phase 2 重写时统一。
7. **`compile_step_witness` 改为 `pub(crate)`**：而非复制逻辑。理由：避免逻辑重复，保持 witness 生成单一来源。
8. **Phase 1.3 不实现 verify_stwo 内部验证**：仅 prove 闭环。理由：verify 实现依赖 StarkProof 反序列化 + Stwo verifier API，属 Phase 4.1 范围；POC 决策门仅需 prove 性能达标。

### 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| Stwo `CommitmentSchemeProver::new` / `Blake2sMerkleChannel` API 不匹配 | 中 | 实现时查 Stwo 源码 `~/.cargo/registry/src/.../stwo-2.3.0/src/prover/`；回退参考 Stwo benches/ |
| `StarkProof` 序列化格式未公开 | 中 | 用 `bincode` + serde；或手动实现 magic+fields 序列化；最差情况用 `postcard` |
| POC 加速比 < 100× | 高 | 决策门失败 → 评估替代方案（plonky3 / 保留 Hypernova fallback）；记录详细 perf 数据 |
| M31 field 范围不足导致约束错误 | 低 | Phase 1.2 测试用 `assert_constraints_on_trace` 验证约束满足；trace 值均 ≤ 2^31-1 |
| `compile_step_witness` 改 `pub(crate)` 破坏其他调用 | 低 | grep 确认仅 `compile_batch_to_ccs` 调用；不破坏外部 API |

---

## Verification Steps

### Phase 1.2 验证

```bash
# 1. 编译通过
cargo build -p poker_zkvm

# 2. CPU AIR 单元测试通过
cargo test -p poker_zkvm --lib stwo_backend::air::cpu
# 期望：6 个测试通过（3 个原有 + 3 个新增 FrameworkEval 测试）

# 3. trace 转换单元测试通过
cargo test -p poker_zkvm --lib stwo_backend::trace
# 期望：5 个测试通过（1 个原有 + 4 个新增 convert_trace_to_stwo 测试）

# 4. 全部 stwo_backend 测试通过
cargo test -p poker_zkvm stwo_backend::
# 期望：≥30 个测试通过（Phase 1.1 的 25 个 + Phase 1.2 新增）
```

### Phase 1.3 验证

```bash
# 1. POC 端到端测试通过
cargo test -p poker_zkvm --test stwo_poc_e2e -- --nocapture
# 期望输出：
#   prove 延迟: <100ms（目标）
#   加速比: ≥100×
#   proof 大小: ≤64KB

# 2. 性能基准（若决策门通过）
cargo test -p poker_zkvm --test stwo_poc_e2e test_stwo_poc_poker_elf_prove -- --nocapture --test-threads=1
# 记录 prove 延迟、proof 大小、加速比

# 3. 回归测试（确认未破坏 Hypernova 路径）
cargo test -p poker_zkvm
# 期望：所有现有测试仍通过
```

### 决策门报告（Phase 1.3 输出）

实施完成后生成 `.trae/documents/stwo_poc_benchmark_report.md`，包含：
- poker ELF trace 长度
- Stwo prove 延迟（ms）
- Hypernova 0-fold 基准（8670ms）
- 加速比（×）
- proof 大小（bytes）
- 决策结论：≥100× 通过 → 进入 Phase 2；否则评估替代方案

---

## 文件改动清单

| 文件 | 改动类型 | 说明 |
|------|---------|------|
| `/Users/mac/projects/zchain/rust-toolchain.toml` | 新建 | 固定 nightly-2026-04-15 |
| [`poker_zkvm/src/stwo_backend/air/cpu.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/air/cpu.rs) | 修改 | 新增 `CpuAirEval` + `FrameworkEval` impl + 3 个测试 |
| [`poker_zkvm/src/stwo_backend/trace.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/trace.rs) | 修改 | 实现 `convert_trace_to_stwo` + `fr_to_m31_single` + 4 个测试 |
| [`poker_zkvm/src/stwo_backend/prover.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/stwo_backend/prover.rs) | 修改 | 实现 `StwoProver::prove()` 真实接入 + 辅助函数 + 更新测试 |
| [`poker_zkvm/src/constraints/mod.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/constraints/mod.rs) | 修改 | `compile_step_witness` 等 6 个函数改 `pub(crate)` |
| [`poker_zkvm/src/lib.rs`](file:///Users/mac/projects/zchain/poker_zkvm/src/lib.rs) | 修改 | 更新 stwo_backend 模块文档 |
| `/Users/mac/projects/zchain/poker_zkvm/tests/stwo_poc_e2e.rs` | 新建 | POC 端到端测试 + 性能基准 |
| `/Users/mac/projects/zchain/.trae/documents/stwo_poc_benchmark_report.md` | 新建（Phase 1.3 收尾） | 决策门基准报告 |

---

## 工期估算

| Step | 工作内容 | 工期 |
|------|---------|------|
| 0 | 创建 rust-toolchain.toml | 0.5 小时 |
| 1 | CpuAirEval + FrameworkEval impl + 测试 | 1-2 天 |
| 2 | convert_trace_to_stwo 实现 + 测试 | 1 天 |
| 3 | compile_step_witness pub(crate) | 0.5 小时 |
| 4 | StwoProver::prove() 真实接入 | 2-3 天（Stwo API 学习曲线） |
| 5 | POC 测试 + 性能基准 | 1 天 |
| 6 | StwoProverConfig 默认值调整 | 0.5 小时 |
| 7 | lib.rs 文档更新 | 0.5 小时 |
| **总计** | | **5-7 个工作日** |

---

## 后续（Phase 2-5 概要，POC 通过后另文细化）

- **Phase 2**（4-6 周）：CPU AIR 完整重写（Group B-F）+ Memory/ControlFlow/Syscall AIR + LogUp lookup
- **Phase 3**（2-3 周）：纯算术 precompile 迁移（Poseidon/SHA-256/Keccak/Merkle → AIR）
- **Phase 4**（3-4 周）：Stwo verifier 完整实现 + poker_zkvm prove() 重写 + poker_l1 集成
- **Phase 5**（2-3 周）：删除 Hypernova 模块 + E2E 测试 + 性能基准

详见 [`hypernova_to_stwo_migration_plan.md`](file:///Users/mac/projects/zchain/.trae/documents/hypernova_to_stwo_migration_plan.md)。
