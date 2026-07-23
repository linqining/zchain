# poker_zkvm Phase B/C/D 实施计划（剩余修复）

> **关联**：`.trae/documents/poker_zkvm_security_remaining_remediation_plan.md`（已批准总计划）
> **状态**：决策完整 — 执行者无需再做选择，按步骤实现即可
> **范围**：Phase A 已完成（617 测试通过）。本计划覆盖 Phase B 剩余（prover 侧）、Phase C（V5 递归 FRI）、Phase D（全量测试）。

---

## 1. 摘要（Summary）

- **Phase B（V4 范围检查）**：AIR 侧已完成（`RangeCheckAir` + `CpuAir` 24 个 claim + `RangeCheckLookup`）。**剩余**：prover 侧交互 trace 生成 + 3 组件 prover/verifier + 2 soundness 测试。
- **Phase C（V5 递归 FRI）**：`trace_gen.rs:616` 硬编码 `query_x=1`。修复：扩展 `RecursivePublicInputs` + 新增 `extract_fri_query_from_l1` transcript replay + prover 一致性检查 + 1 soundness 测试。
- **Phase D**：全量回归测试。

---

## 2. 当前状态分析（Current State Analysis）

### 已完成 ✅

| 内容 | 位置 | 验证 |
|------|------|------|
| Phase A：V1 分支条件约束 + witness + 6 测试 | `cpu_air.rs` + `trace_native.rs` + `prover.rs` | 617 测试通过 |
| `RangeCheckLookup` relation（1 元组） | `lookups.rs:188-216` | 已创建 |
| `RangeCheckAir`（4 列，6 约束，logup yield） | `range_check_air.rs` | 已创建 |
| `CpuAir.range_lookup` 字段 + `new_with_range_check` 构造器 + 24 claim | `cpu_air.rs:109-209, 1211-1248` | 已写入，未编译 |
| `prover.rs` 导入更新 | `prover.rs:53-67` | 已写入（当前 unused，待实现函数使用） |

### 未编译 ⚠️

Phase B 的 AIR 侧代码（`range_check_air.rs` + `cpu_air.rs` 的 range 部分 + `prover.rs` 导入）自写入后**未编译**。诊断显示 `prover.rs` 的 range_check 导入为 unused（因为 prover 函数尚未实现）。Phase B 第一步是确认 AIR 侧编译通过。

### 关键架构事实（已验证）

1. **Stwo logup 交互列映射**（`cpu_air.rs:1250-1259` 注释）：
   - 每个 `add_to_relation` 调用 = 1 个 frac = 1 个 interaction column（4 base field cols）
   - CpuAir 启用 memory + range（无 ecall）：1 + 24 = **25 interaction columns**（100 base cols）
   - MemoryAir：1 interaction column（4 base cols）
   - RangeCheckAir：1 interaction column（4 base cols）
   - **Tree 2 总计**：27 interaction columns = 108 base field cols

2. **交互列顺序**（由 `add_to_relation` 在 evaluate 中的顺序决定，`cpu_air.rs:1131-1248`）：
   - CPU：[memory_claim, range_claim_0, ..., range_claim_23]（25 列）
   - Memory：[memory_yield]（1 列）
   - RangeCheck：[range_yield]（1 列）
   - 顺序必须与 `prove(&[&cpu, &mem, &range], ...)` 的 component 顺序一致

3. **`combine` API**（1 元组）：`range_lookup.combine(&[limb_value])` — `&[PackedBaseField; 1]` 引用，与 9 元组 `lookup.combine(&[...9 values...])` 模式一致。

4. **RangeCheckAir 原始 trace**（4 列，Tree 1）：
   - value（col 0）：`next_interaction_mask(ORIGINAL_TRACE_IDX, [0, -2])` 读 cur+prev
   - multiplicity / is_padding / is_first：`next_trace_mask()` 读
   - 行布局：row 0..255 = real（value=row_idx），row 256..2^log_size = padding

---

## 3. 提议变更（Proposed Changes）

### Phase B 剩余：V4 范围检查 Prover 侧

#### B.1 新增 CpuAir 构造器（cpu_air.rs）

`new_with_range_check` 需要 ecall_lookup 参数。为 3 组件 prover 增加 memory+range（无 ecall）构造器，匹配现有 `prove_cpu_memory_trace`（无 ecall）模式。

在 `new_with_range_check` 之后新增：

```rust
/// 创建指定 log_size 的 CPU AIR（memory + range，无 ecall）。
/// 用于 V4 修复 3 组件 prover（CPU + Memory + RangeCheck）。
#[must_use]
pub const fn new_with_memory_and_range(
    log_size: u32,
    memory_lookup: MemoryLookup,
    range_lookup: RangeCheckLookup,
) -> Self {
    Self {
        log_size,
        memory_lookup: Some(memory_lookup),
        ecall_lookup: None,
        range_lookup: Some(range_lookup),
    }
}
```

#### B.2 新增 RangeCheckTrace 结构 + 生成函数（trace_native.rs）

在 `trace_native.rs` 中新增（仿照 `MemoryTrace` + `gen_poseidon_trace` 模式）：

```rust
/// RangeCheck 原始 trace（4 列 × 2^log_size 行）。
pub struct RangeCheckTrace {
    pub cols: Vec<Vec<M31>>,
    pub log_size: u32,
}

impl RangeCheckTrace {
    pub fn new(log_size: u32) -> Self { /* 4 列 × 2^log_size，全 0 */ }
    pub fn num_rows(&self) -> usize { 1 << self.log_size }
}

/// 将 RangeCheckTrace 转换为 Stwo CircleEvaluation 列（4 列）。
pub fn range_check_trace_to_evaluations(
    trace: &RangeCheckTrace,
) -> Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> { /* 同 memory_trace_to_evaluations */ }

/// 从 CPU trace 生成 RangeCheck 原始 trace。
///
/// # 算法
/// 1. 初始化 count[0..256] = 0
/// 2. 遍历 CPU trace 的所有非 padding 行（IS_PADDING col=0），对 24 个 limb 列读值 v，
///    若 v < 256 则 count[v] += 1（v ≥ 256 是 bug，不应出现；正常 trace 不会出现）
/// 3. 填充 4 列：
///    - row 0..256（real）：value=row_idx, multiplicity=-count[row_idx],
///      is_padding=0, is_first=(row_idx==0)
///    - row 256..2^log_size（padding）：value=0, multiplicity=0, is_padding=1, is_first=0
pub fn gen_range_check_air_trace(
    cpu_trace: &NativeTrace,
) -> RangeCheckTrace
```

**关键细节**：
- 24 limb 列索引（与 `cpu_air.rs:1225-1238` 的 `RANGE_CHECK_COLS` 一致）：
  `[0,1,2,3, 4,5,6,7, 10,11,12,13, 14,15,16,17, 18,19,20,21, 74,75,76,77]`
- IS_PADDING 列索引 = 64（`column_layout_v2.rs`）
- log_size 与 CPU trace 相同（`cpu_trace.log_size`），须 ≥ 8（256 real rows）

#### B.3 新增 CPU range claim 交互 trace（prover.rs）

新增函数（仿照 `gen_cpu_interaction_trace` 模式，但创建 24 列）：

```rust
/// 生成 CPU range check claim 交互 trace 列（24 列）。
///
/// # 算法
/// 对每个 vec_row（SIMD 向量行）：
///   对 24 个 limb 列中的每一个（独立 LogupTraceGenerator 列）：
///   1. 读取 limb 值（PackedBaseField）
///   2. denom = range_lookup.combine(&[limb_value])
///   3. num = PackedSecureField::from(1 - is_padding)（非 padding 行 = +1）
///   4. col_gen.write_frac(vec_row, num, denom)
///
/// # 返回
/// (96 CircleEvaluations, claimed_sum) — 24 列 × 4 base cols + 总 sum
fn gen_cpu_range_claim_interaction_trace(
    cpu_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    range_lookup: &RangeCheckLookup,
) -> (Vec<CircleEvaluation<...>>, SecureField) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut log_gen = LogupTraceGenerator::new(log_size);
    let one_packed = PackedBaseField::broadcast(BaseField::from(1u32));

    // 24 个 limb 列索引
    const RANGE_CHECK_COLS: [usize; 24] = [
        COL_PC_BASE, COL_PC_BASE+1, COL_PC_BASE+2, COL_PC_BASE+3,
        COL_PC_NEXT_BASE, COL_PC_NEXT_BASE+1, COL_PC_NEXT_BASE+2, COL_PC_NEXT_BASE+3,
        COL_VALUE_A_EFF_BASE, COL_VALUE_A_EFF_BASE+1, COL_VALUE_A_EFF_BASE+2, COL_VALUE_A_EFF_BASE+3,
        COL_VALUE_B_BASE, COL_VALUE_B_BASE+1, COL_VALUE_B_BASE+2, COL_VALUE_B_BASE+3,
        COL_VALUE_C_BASE, COL_VALUE_C_BASE+1, COL_VALUE_C_BASE+2, COL_VALUE_C_BASE+3,
        COL_MEM_ADDR_BASE, COL_MEM_ADDR_BASE+1, COL_MEM_ADDR_BASE+2, COL_MEM_ADDR_BASE+3,
    ];

    let mut col_gens: Vec<_> = (0..24).map(|_| log_gen.new_col()).collect();

    for vec_row in 0..n_vec_rows {
        let is_padding_packed = cpu_trace[IS_PADDING].values.data[vec_row];
        let is_non_padding = one_packed - is_padding_packed;
        let num = PackedSecureField::from(is_non_padding);

        for (i, &col_idx) in RANGE_CHECK_COLS.iter().enumerate() {
            let limb_val = cpu_trace[col_idx].values.data[vec_row];
            let denom = range_lookup.combine(&[limb_val]);
            col_gens[i].write_frac(vec_row, num.clone(), denom);
        }
    }

    for mut cg in col_gens { cg.finalize_col(); }
    log_gen.finalize_last()
}
```

#### B.4 新增 RangeCheckAir yield 交互 trace（prover.rs）

```rust
/// 生成 RangeCheckAir yield 交互 trace 列（1 列）。
///
/// # 算法
/// 对每个 vec_row：
///   1. 读取 value（col 0）和 multiplicity（col 1）
///   2. denom = range_lookup.combine(&[value])
///   3. num = multiplicity（已为负数，padding 行 = 0）
///   4. col_gen.write_frac(vec_row, num, denom)
fn gen_range_check_air_interaction_trace(
    rc_trace: &[CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>],
    log_size: u32,
    range_lookup: &RangeCheckLookup,
) -> (Vec<CircleEvaluation<...>>, SecureField) {
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut log_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = log_gen.new_col();

    for vec_row in 0..n_vec_rows {
        let value = rc_trace[RC_COL_VALUE].values.data[vec_row];
        let multiplicity_packed = rc_trace[RC_COL_MULTIPLICITY].values.data[vec_row];
        let denom = range_lookup.combine(&[value]);
        let num = PackedSecureField::from(multiplicity_packed);
        col_gen.write_frac(vec_row, num, denom);
    }

    col_gen.finalize_col();
    log_gen.finalize_last()
}
```

#### B.5 新增 3 组件 prover/verifier（prover.rs）

```rust
/// 3 组件 proof 结构：CPU + Memory + RangeCheck。
#[derive(Debug, Clone)]
pub struct CpuMemRangeProof {
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    pub claimed_sum_cpu: SecureField,
    pub claimed_sum_mem: SecureField,
    pub claimed_sum_range: SecureField,
}

/// 3 组件 prove 主入口。
///
/// # 流程（扩展 prove_cpu_memory_trace）
/// 1. PCS + twiddles + Channel + CommitmentSchemeProver
/// 2. Tree 0：空 preprocessed
/// 3. Tree 1：CPU(132) + Memory(17) + RangeCheck(4) = 153 cols
/// 4. draw MemoryLookup + draw RangeCheckLookup（顺序：memory 先，range 后）
/// 5. 生成 interaction traces：
///    a. CPU memory claim（gen_cpu_interaction_trace，1 列）→ sum_mem_claim
///    b. CPU range claims（gen_cpu_range_claim_interaction_trace，24 列）→ sum_range_claim
///    c. CPU claimed_sum = sum_mem_claim + sum_range_claim
///    d. Memory yield（gen_mem_interaction_trace，1 列）→ claimed_sum_mem
///    e. RangeCheck yield（gen_range_check_air_interaction_trace，1 列）→ claimed_sum_range
/// 6. Soundness：claimed_sum_cpu + claimed_sum_mem + claimed_sum_range == 0
/// 7. mix_felts(&[claimed_sum_cpu, claimed_sum_mem, claimed_sum_range])
/// 8. Tree 2：CPU(25×4=100) + Memory(4) + RangeCheck(4) = 108 cols
///    顺序：cpu_mem(4) + cpu_range(96) + mem_yield(4) + range_yield(4)
/// 9. components：CpuAir::new_with_memory_and_range + MemoryAir + RangeCheckAir
/// 10. prove(&[&cpu, &mem, &range], ...)
pub fn prove_cpu_mem_range_trace(
    cpu_trace: &NativeTrace,
    mem_trace: &MemoryTrace,
) -> Result<CpuMemRangeProof, ProvingError>

/// 3 组件 verify（镜像 prover）。
pub fn verify_cpu_mem_range_proof(
    proof: CpuMemRangeProof,
    log_size: u32,
) -> Result<(), VerificationError>
```

**Tree 1 列布局**（153 cols）：
```
extend_evals(cpu_evals.clone());       // 132 cols
extend_evals(mem_evals.clone());       // 17 cols
extend_evals(rc_evals.clone());        // 4 cols
```

**Tree 2 列布局**（108 base cols = 27 SecureField cols）：
```
extend_evals(cpu_mem_interaction_evals);    // 4 base cols (1 SecureField)
extend_evals(cpu_range_interaction_evals);  // 96 base cols (24 SecureField)
extend_evals(mem_interaction_evals);         // 4 base cols (1 SecureField)
extend_evals(rc_interaction_evals);          // 4 base cols (1 SecureField)
```

**Verifier 端 Tree 2 log_sizes**：`vec![log_size; 108]`（108 base cols）。

#### B.6 Soundness 测试（prover.rs tests 模块）

```rust
#[test]
fn test_range_check_soundness_tamper_limb() {
    // 构造 ADD 指令（合法 trace），prove 应成功
    // 篡改：将 PC limb[0] 设为 256（超出 [0,255] 范围）
    // 预期：prove_cpu_mem_range_trace 失败（soundness check：256 无对应 yield）
    //
    // 流程：
    // 1. make_step(0, Instruction::Add{rd:1,rs1:2,rs2:3}, post)
    // 2. trace_to_native → cpu_trace
    // 3. trace_to_memory_trace → mem_trace
    // 4. 篡改 cpu_trace.cols[COL_PC_BASE][0] = M31::from(256u32)
    // 5. prove_cpu_mem_range_trace(&cpu_trace, &mem_trace) → assert is_err
}

#[test]
fn test_range_check_soundness_tamper_multiplicity() {
    // 构造合法 trace，prove 应成功
    // 篡改：将 RangeCheckAir 的 multiplicity[0] 加 1（破坏 logup 平衡）
    // 预期：prove 失败（soundness check：sum != 0）
    //
    // 注：此测试需要先生成 RangeCheckTrace，篡改后重新生成 evaluations。
    // 因 gen_range_check_air_trace 内部调用，需在 prove 函数外构造。
    // 简化方案：直接篡改 CPU trace 的某个 limb 使其 != 真实值，
    // 使 count[v] 与 claim 不匹配（等效于篡改 multiplicity）。
    // 或：暴露 gen_range_check_air_trace 为 pub，测试中手动构造 + 篡改。
}
```

**测试 2 实现策略**：将 `gen_range_check_air_trace` 设为 `pub`，测试中：
1. 生成合法 `cpu_trace` + `mem_trace`
2. `let mut rc_trace = gen_range_check_air_trace(&cpu_trace);`
3. 篡改 `rc_trace.cols[RC_COL_MULTIPLICITY][0] += M31::from(1u32)`（破坏 count）
4. 手动调用 3 组件 prove 的内部步骤（或将 prove 重构为接受 rc_trace 参数的版本）

**简化备选**：测试 1 已覆盖核心 soundness（limb 超范围）。测试 2 可改为验证合法 trace prove 成功（roundtrip），作为正向测试。若篡改 multiplicity 测试实现复杂，先提交测试 1 + roundtrip 正向测试。

#### B.7 编译验证

```bash
cargo +nightly-2026-04-15 build -p poker_zkvm
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"
```

预期：AIR 侧 + prover 侧编译通过，range_check 测试通过。

---

### Phase C：V5 递归 FRI query point 修复

#### C.1 扩展 RecursivePublicInputs（recursive/public_inputs.rs）

在 `log_size` 字段后新增 2 字段：

```rust
/// L1 FRI 的 query point x 坐标（从 L1 transcript 提取，非硬编码）。
pub fri_query_x: SecureField,
/// L1 FRI last layer 在 query_x 的 claimed evaluation。
pub fri_query_eval: SecureField,
```

同步更新：
- `new()` 签名：新增 `fri_query_x: SecureField, fri_query_eval: SecureField`
- `Default`：`fri_query_x: SecureField::from(0u32), fri_query_eval: SecureField::from(0u32)`
- **10 处构造调用点**（实现时用 `rg "RecursivePublicInputs"` 定位全部，逐一更新）：
  - `recursion_prover.rs`（`make_test_public_inputs_from_l1` 等）
  - `trace_gen.rs`（`make_test_public_inputs` + FRI 测试）
  - `recursion_verifier.rs`
  - `e2e_test.rs`
  - `public_inputs.rs` 单元测试

#### C.2 新增 extract_fri_query_from_l1（trace_gen.rs 或 recursion_prover.rs）

```rust
/// 从 L1 proof 的 Fiat-Shamir transcript 提取 FRI query point。
///
/// # 算法
/// 1. 创建 fresh Poseidon252Channel（镜像 L1 verifier）
/// 2. 重放 L1 commit phase：
///    a. commit preprocessed（proof.commitments[0]，空）
///    b. commit trace（proof.commitments[1]，NUM_COLUMNS 列）
/// 3. draw random_coeff（channel.draw_secure_felt）
/// 4. read composition commitment（proof.commitments.last()）
/// 5. draw OODS point（CirclePoint::get_random_point(channel)）
/// 6. 构造 FriVerifier（从 proof.fri + config）
/// 7. sample_query_positions(channel) → Vec<usize>
/// 8. 用 FRI domain（CanonicCoset::new(log_size + blowup_log).circle_domain()）
///    将 position[0] 转为 CirclePoint → 取 x 坐标
/// 9. query_eval = last_layer_poly.eval_at_point(query_x)
/// 10. 返回 Some((query_x, query_eval))，失败返回 None
pub fn extract_fri_query_from_l1(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
    log_size: u32,
    last_layer_poly: &LinePoly,
) -> Option<(SecureField, SecureField)>
```

**实现风险**：`FriVerifier` 构造签名 + domain→point 转换 API 需在实现时查阅 Stwo 源码：
- `/Users/mac/.cargo/registry/src/index.crates.io-*/stwo-2.3.0/src/core/fri.rs`（`FriVerifier::new` + `sample_query_positions`）
- `/Users/mac/.cargo/registry/src/index.crates.io-*/stwo-2.3.0/src/core/pcs/verifier.rs`（`verify_values` 重放逻辑）

**降级备选**（若 FriVerifier 构造不可行）：`RecursivePublicInputs` 已有 `query_positions: Vec<usize>` 字段。改为：
1. 重放 channel 到 OODS point
2. 手动 draw query positions（按 Stwo `verify_values` 的逻辑）
3. 用 `CanonicCoset::new(log_size + blowup).circle_domain()` 构造 domain
4. 用 domain API 将 position 转 CirclePoint

#### C.3 修复 trace_gen.rs

`gen_fri_verifier_trace`（line 598-724）：

```rust
// 旧（line 616）：
// let query_x_qm31 = SecureField::from(1u32);

// 新：
let query_x_qm31 = public_inputs.fri_query_x;
let query_eval_qm31 = public_inputs.fri_query_eval;
// 删除 line 622 的 query_eval 计算（改用公开输入）
```

更新文档注释（lines 576-592 的 v5.1 placeholder → v5.2 已修复）。

#### C.4 prover 端一致性检查（recursion_prover.rs）

在 `prove_recursive_with_fri`（line 239）Step 1 之后新增：

```rust
let (real_query_x, real_query_eval) = extract_fri_query_from_l1(
    l1_proof, public_inputs.config, public_inputs.log_size,
    &public_inputs.fri_last_layer_poly,
).ok_or_else(|| RecursionProvingError::L1ProofStructureInvalid(
    "无法从 L1 proof 提取 FRI query point".to_string()
))?;

if real_query_x != public_inputs.fri_query_x
    || real_query_eval != public_inputs.fri_query_eval {
    return Err(RecursionProvingError::FriQueryMismatch {
        claimed_x: public_inputs.fri_query_x,
        derived_x: real_query_x,
    });
}
```

新增 `RecursionProvingError::FriQueryMismatch` 变体。

#### C.5 channel mix 扩展

`mix_public_inputs_into_channel`（recursion_prover.rs:372）+ verifier 端对应函数，新增：

```rust
channel.mix_felts(&[inputs.fri_query_x, inputs.fri_query_eval]);
```

#### C.6 Soundness 测试

```rust
#[test]
fn test_recursive_fri_soundness_tamper_query_x() {
    // 1. 构造合法 L1 proof
    // 2. extract_fri_query_from_l1 提取真实 (query_x, query_eval)
    // 3. 构造 RecursivePublicInputs（真实值）
    // 4. 篡改 fri_query_x = SecureField::from(2u32)
    // 5. 预期 prove_recursive_with_fri 失败（FriQueryMismatch）
}
```

---

### Phase D：全量测试

```bash
# Phase B 验证
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"

# Phase C 验证
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive" "fri_soundness"

# 全量回归
cargo +nightly-2026-04-15 test -p poker_zkvm --lib

# 集成测试
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```

**预期最终测试数**：~620（617 + 2 range + 1 FRI），0 失败，0 回归。

---

## 4. 假设与决策（Assumptions & Decisions）

1. **执行顺序**：Phase B（prover 侧 + 编译 + 测试）→ Phase C（递归 FRI）→ Phase D（全量回归）。每 Phase 完成后运行测试。

2. **Phase B 3 组件 prover 不含 ecall**：新增 `new_with_memory_and_range` 构造器（memory + range，ecall=None），匹配现有 `prove_cpu_memory_trace`（无 ecall）模式。避免引入无 yield 方的 eclaim 列。

3. **CPU 交互列 = 25 列**（1 memory + 24 range）：由 CpuAir::evaluate 的 `add_to_relation` 调用数决定。24 列因 24 个 limb 列各有独立 denominator。proof size 较大但 soundness 正确。

4. **CPU 交互列用两个 LogupTraceGenerator**：memory claim 用现有 `gen_cpu_interaction_trace`（1 列），range claims 用新 `gen_cpu_range_claim_interaction_trace`（24 列）。拼接为 `cpu_mem_evals ++ cpu_range_evals`，顺序与 evaluate 中 `add_to_relation` 顺序一致（memory 先，range 后）。

5. **RangeCheckAir multiplicity 计数**：遍历 CPU trace 非 padding 行的 24 limb 列，统计每个 v∈[0,255] 出现次数，multiplicity = -count。padding 行（v ≥ 256 不会出现在合法 trace；若出现则 count 跳过，logup 不平衡 → soundness 失败）。

6. **Phase C 降级备选**：若 `FriVerifier::new` 构造过于复杂，退化为手动重放 channel + 用 `query_positions` 字段 + domain API 转换。两种方案都需重放 channel。

7. **逻辑/移位指令保持降级**（用户已确认）：V2 不修复，132 列预算不足。

8. **每 Phase 完成后提交 git**，便于回溯。

---

## 5. 验证步骤（Verification Steps）

### Phase B 验证
```bash
cargo +nightly-2026-04-15 build -p poker_zkvm
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```
预期：619 通过（+2 range），0 失败，0 回归。

### Phase C 验证
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive" "fri_soundness"
```
预期：620 通过（+1 FRI），0 失败。

### Phase D 全量回归
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```
预期：~620 通过，0 失败，0 回归。

---

## 6. 实施优先级与执行清单

| 顺序 | Phase | 内容 | 预计测试 | 阻塞? |
|------|-------|------|----------|-------|
| 1 | B.1-B.6 | range check prover 侧 + 测试 | +2 | 否 |
| 2 | C.1-C.6 | 递归 FRI query point 修复 | +1 | 否（C.2 可能有 API 风险） |
| 3 | D | 全量回归 | 0 | 否 |

**执行者从顺序 1 开始**。Phase C 复杂度最高，若遇 Stwo FriVerifier API 障碍，可先完成 Phase B+D（HIGH range check + 测试）并提交，再单独处理 Phase C。
