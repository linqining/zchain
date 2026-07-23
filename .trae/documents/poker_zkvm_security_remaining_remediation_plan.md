# poker_zkvm 安全漏洞修复实施计划（剩余阶段）

> **关联文档**：
> - 审计报告：`.trae/documents/poker_zkvm_security_audit_vs_risczero.md`
> - Phase 2 计划（已批准）：`.trae/documents/poker_zkvm_security_remediation_phase2_plan.md`
> **本计划状态**：决策完整 — 执行者无需再做选择，按步骤实现即可
> **用户决策**：覆盖全部剩余步骤；逻辑/移位指令保持降级为已知 gap

---

## 1. 摘要（Summary）

审计发现 8 个漏洞（2 CRITICAL、3 HIGH、3 MEDIUM）。截至目前：
- **V6 DIV 特殊情况**（MEDIUM）— ✅ 已修复并验证，611 测试通过
- **V1 分支条件验证**（CRITICAL）— ✅ 代码已写入（约束 + witness + 6 soundness 测试），**待编译运行验证**
- **V4 8-bit limb 范围检查**（HIGH）— ⏳ 未开始
- **V5 递归 FRI query point 硬编码**（HIGH）— ⏳ 未开始
- **V2 逻辑/移位指令**（MEDIUM）— 降级为已知 gap（用户决策）

本计划定义剩余全部工作：先验证 V1（Phase A），再实现 V4（Phase B）、V5（Phase C），最后补齐全量测试（Phase D）。

---

## 2. 当前状态分析（Current State Analysis）

### 已完成 ✅（已验证，代码在位）

| 内容 | 位置 | 状态 |
|------|------|------|
| 比较指令约束（SLTU/SLTIU + SLT/SLTI） | `cpu_air.rs:336-409` | ✅ 609 测试通过 |
| JAL/JALR 链接寄存器约束 | `cpu_air.rs:478-501` | ✅ 通过 |
| V6 DIV 特殊情况 q_abs 约束（7 条） | `cpu_air.rs:918-963` | ✅ 611 测试通过 |
| V6 DIV/DIVU d=0 soundness 测试（2 个） | `prover.rs` | ✅ 通过 |

### 已写入待验证 🔄（Phase A — 本计划首要任务）

| 内容 | 位置 | 状态 |
|------|------|------|
| 分支条件约束（BEQ/BNE/BLT/BGE/BLTU/BGEU，~13 条） | `cpu_air.rs:411-482` | ⚠️ 已写入，未编译/未运行 |
| 分支 witness（diff/borrow/diff_inv/sign） | `trace_native.rs:757-794` | ⚠️ 已写入，未编译/未运行 |
| `m31_inverse` helper | `trace_native.rs:1151` | ⚠️ 已写入，未编译/未运行 |
| 分支 soundness 测试（6 个） | `prover.rs:1641-1794` | ⚠️ 已写入，未编译/未运行 |

**git status**：3 文件已修改未提交（`cpu_air.rs`、`prover.rs`、`trace_native.rs`）。

### 未开始 ⏳

| Phase | 漏洞 | 严重度 | 文件 |
|-------|------|--------|------|
| B | V4 缺少 8-bit limb 范围检查 | HIGH | 新建 `range_check_air.rs` + `lookups.rs` + `cpu_air.rs` + `prover.rs` |
| C | V5 递归 FRI query point 硬编码为 1 | HIGH | `recursive/public_inputs.rs` + `recursive/trace_gen.rs` + `recursion_prover.rs` |
| D | 全量 soundness 测试补齐 + 回归 | — | `prover.rs` |

### 已确认的关键事实（Phase 1 探索验证）

1. **V5 当前状态**：
   - `trace_gen.rs:616` 硬编码 `query_x_qm31 = SecureField::from(1u32)`
   - `RecursivePublicInputs`（`public_inputs.rs:20-56`）有 9 字段但无 `fri_query_x`/`fri_query_eval`
   - `mix_public_inputs_into_channel`（`recursion_prover.rs:372-391`）mix 了 config/max_log_degree_bound/composition_oods_eval/oods_point/fri_last_layer_poly，**未 mix `query_positions`**
   - `RecursivePublicInputs` 已有 `query_positions: Vec<usize>` 字段，但测试中为空 `Vec::new()`

2. **V5 修复路径（Stwo API 已验证）**：
   - Stwo `FriVerifier::sample_query_positions(channel)` (`fri.rs:294`) — 从 channel 抽取 FRI query positions
   - `pcs/verifier.rs:81` 展示了 L1 verifier 在 `verify_values` 中调用 `sample_query_positions`
   - `fri.rs:1135-1137` 展示了 `query_positions.iter().map(|p| polynomial.at(*p))` 将 position 转为求值
   - FRI domain 由 `CanonicCoset::new(log_size + blowup_log).circle_domain()` 构造（见 `fri.rs:117`）
   - **提取方案**：重放 L1 channel（commit preprocessed → commit trace → draw random_coeff → read composition commitment → draw OODS point）→ 构造 `FriVerifier` → `sample_query_positions` → 用 domain 将 position 转为 CirclePoint → 取 x 坐标

3. **V4 range check 基础设施**：
   - `lookups.rs` 用 `relation!` 宏定义 N 元 lookup relation（MemoryLookup=9 元组等）
   - `memory_air.rs` 是 AIR + logup yield 的模板（FrameworkEval + `eval.add_to_relation`）
   - `prover.rs:314-340` 的 `gen_cpu_interaction_trace` 展示 logup claim 生成模式
   - `prover.rs` 的 `CpuMemoryProof` + `prove_cpu_memory_trace` 展示多组件 prove 流程
   - `column_layout_v2.rs` 定义 132 列，需 range check 的 limb 列：PC(0-3) + PcNext(4-7) + ValueAEff(10-13) + ValueB(14-17) + ValueC(18-21) + MemAddr(22-25) = 24 limb/行

4. **度数预算**：`max_constraint_log_degree_bound = log_size + 1`（度 ≤ 3）。约束形式为 `indicator × expression`。

---

## 3. 提议变更（Proposed Changes）

### Phase A：验证 V1 分支条件修复（编译 + 测试）

**文件**：无代码变更（仅编译 + 运行测试）

**步骤**：
1. 编译：`cargo +nightly-2026-04-15 build -p poker_zkvm`
2. 运行分支 soundness 测试：
   ```
   cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "beq_soundness" "bne_soundness" "bltu_soundness" "bgeu_soundness" "blt_soundness" "bge_soundness"
   ```
3. 全量回归：`cargo +nightly-2026-04-15 test -p poker_zkvm --lib`

**预期**：617 测试通过（611 基线 + 6 分支 soundness），0 失败，0 回归。

**若编译失败**：诊断告警 `unused import: COL_TAKEN`（prover.rs:930）应为 stale（6 个测试使用 COL_TAKEN）。若真 unused，移除 import 或确认测试编译。若分支约束不满足（`ConstraintsNotSatisfied`），检查 witness 填充正确性——特别注意 B-type `extract_operands` 返回 `imm_c_flag=1` 导致 `value_c = imm`（非 rs2 值），分支 witness 已用 `prev_registers[op_c]` 覆盖 ValueC。

---

### Phase B：V4 — 8-bit limb 范围检查（HIGH）

**文件**：`lookups.rs` + 新建 `range_check_air.rs` + `cpu_air.rs` + `prover.rs`

**设计**（logup lookup argument，复用现有 MemoryLookup 多组件模式）：

#### B.1 新 relation（lookups.rs）

在 `lookups.rs` 末尾（`Sha256Lookup` 之后、tests 之前）添加：

```rust
/// RangeCheck lookup relation（1 元组：limb 值 v ∈ [0, 255]）。
///
/// CPU AIR 对每个非 padding 行的每个 limb 列发送 claim (v, +1)。
/// RangeCheckAir 对 v ∈ [0, 255] 发送 yield (v, -multiplicity_v)。
/// 一致性条件：Σ(CPU claims) + Σ(RangeCheck yields) == 0。
relation!(RangeCheckLookup, 1);
```

同步在 tests 模块添加 `test_range_check_lookup_dummy` + `test_range_check_lookup_size`（size=1）。

#### B.2 新 AIR（range_check_air.rs）

新建 `poker_zkvm/src/stwo_backend/range_check_air.rs`，仿照 `memory_air.rs` 结构：

```rust
/// RangeCheckAir — 256 行（log_size=8），每行 v ∈ [0, 255]。
///
/// 列布局（2 列）：
/// - col 0: value（= 行索引 v，约束为递增：value[0]=0, value[r+1]=value[r]+1）
/// - col 1: multiplicity（prover 填充，= 该值在 CPU limb 中出现次数的负数）
///
/// 发送 yield：(value, multiplicity)，multiplicity ≤ 0
pub struct RangeCheckAir {
    log_size: u32,  // = 8
    range_lookup: RangeCheckLookup,
}
```

**约束**：
1. `value[0] = 0`（首行，度 1）
2. `value[r+1] = value[r] + 1`（递增，度 2，gated by `1 - is_last`）
3. `value` 列的最后一行 = 255（隐含由递增 + 首行=0 + 256 行推导）
4. padding binality（RangeCheckAir 无 padding，256 行全用）

**logup yield**：每行调用 `eval.add_to_relation(RelationEntry::new(&range_lookup, multiplicity, &[value]))`

#### B.3 CPU AIR claim（cpu_air.rs）

在 `CpuAir` 添加 `range_lookup: Option<RangeCheckLookup>` 字段：
- 新增 `new_with_range_check(log_size, memory_lookup, ecall_lookup, range_lookup)` 构造器
- 在 `evaluate` 中，对每个非 padding 行的 24 个 limb 列发送 claim：
  - PC(0-3) + PcNext(4-7) + ValueAEff(10-13) + ValueB(14-17) + ValueC(18-21) + MemAddr(22-25)
  - gated by `(1 - is_padding)`，multiplicity = `+1`
  - 通过 `eval.add_to_relation(RelationEntry::new(&range_lookup, one, &[limb_value]))`

#### B.4 多组件集成（prover.rs）

扩展多组件 prover：
1. `CpuMemoryProof` → 新增 `claimed_sum_range: SecureField` 字段
2. 新增 `gen_range_check_interaction_trace(cpu_trace, log_size, range_lookup) -> (Vec<CircleEvaluation>, SecureField)`
   - 遍历 CPU trace 的 24 个 limb 列 × 所有非 padding 行
   - 对每个 limb 值发送 (value, +1) claim
3. `prove_cpu_memory_trace` 扩展为 3 组件：CPU + Memory + RangeCheck
4. soundness check：`claimed_sum_cpu + claimed_sum_mem + claimed_sum_range == 0`
5. `channel.draw(RangeCheckLookup::dummy())` 在 Tree 1 commit 之后

#### B.5 soundness 测试（prover.rs）

| 测试名 | 场景 | 篡改 | 预期 |
|--------|------|------|------|
| `test_range_check_soundness_tamper_limb` | 篡改 PC limb 为 256 | prove 失败 |
| `test_range_check_soundness_tamper_multiplicity` | 篡改 RangeCheckAir multiplicity | prove 失败 |

**复杂度评估**：中高。需要新文件 + 多组件集成。但模式与 MemoryAir 完全一致，有成熟模板。

**降级备选**（若 logup 集成遇阻）：先只 range check PC + PcNext（8 limb），减少 claim 数量。或用 per-limb binality gate（每 limb 8 列 × 2 bit decomposition = 16 列，仅对 PC+PcNext = 32 列，超预算，不可行）。**故采用 logup 方案**。

---

### Phase C：V5 — 递归 FRI query point 修复（HIGH）

**文件**：`recursive/public_inputs.rs` + `recursive/trace_gen.rs` + `recursive/recursion_prover.rs`

#### C.1 公开输入扩展（public_inputs.rs）

`RecursivePublicInputs` 新增 2 字段（在 `log_size` 之后）：

```rust
/// L1 FRI 的 query point x 坐标（从 L1 Fiat-Shamir transcript 提取，非硬编码）。
/// L2 FRI Verifier AIR 用此值计算 query_eval = last_layer_poly.eval_at_point(query_x)。
pub fri_query_x: SecureField,

/// L1 FRI last layer 在 query_x 处的 claimed evaluation。
/// = last_layer_poly.eval_at_point(fri_query_x)。
/// L2 AIR 约束 partial_eval[n] == fri_query_eval。
pub fri_query_eval: SecureField,
```

同步更新：
- `new()` 签名：新增 `fri_query_x: SecureField, fri_query_eval: SecureField` 参数
- `Default::default()`：`fri_query_x: SecureField::from(0u32), fri_query_eval: SecureField::from(0u32)`
- **所有构造调用点**（10 处）：
  - `recursion_prover.rs:470`（`make_test_public_inputs_from_l1`）
  - `recursion_prover.rs:661`（测试 helper）
  - `trace_gen.rs:916`（`make_test_public_inputs`）
  - `trace_gen.rs:1075, 1148, 1182`（FRI 测试）
  - `e2e_test.rs:61`
  - `recursion_verifier.rs:245, 321, 375`
  - `public_inputs.rs:115`（单元测试）

#### C.2 query point 提取 helper（trace_gen.rs 或 recursion_prover.rs）

新增函数 `extract_fri_query_from_l1`：

```rust
/// 从 L1 proof 的 Fiat-Shamir transcript 提取 FRI query point。
///
/// # 算法
/// 1. 创建 fresh Poseidon252Channel（镜像 L1 verifier）
/// 2. 重放 L1 commit phase：
///    a. commit preprocessed commitment（proof.commitments[0]，空）
///    b. commit trace commitment（proof.commitments[1]，NUM_COLUMNS 列）
/// 3. draw random_coeff（channel.draw_secure_felt()）
/// 4. read composition commitment（proof.commitments.last()）
/// 5. draw OODS point（CirclePoint::get_random_point(channel)）
/// 6. 构造 FriVerifier（从 proof 的 FRI layers + config）
/// 7. sample_query_positions(channel) → Vec<usize>
/// 8. 用 FRI domain 将 position[0] 转为 CirclePoint
/// 9. 返回 (query_x, query_eval)
///    query_eval = last_layer_poly.eval_at_point(query_x)
pub fn extract_fri_query_from_l1(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    config: PcsConfig,
    log_size: u32,
    last_layer_poly: &LinePoly,
) -> Option<(SecureField, SecureField)>
```

**关键 Stwo API**（已验证存在）：
- `FriVerifier::new(...)` — 从 proof + config 构造（见 `fri.rs`）
- `FriVerifier::sample_query_positions(channel)` (`fri.rs:294`) — 抽取 query positions
- `CanonicCoset::new(log_size + blowup_log).circle_domain()` — FRI domain
- `domain.at(position)` 或 `domain.half_coset` 相关 API — position → CirclePoint 转换

**实现风险**：FriVerifier 的构造签名和 domain→point 转换 API 需在实现时查阅 Stwo 源码 `fri.rs` 和 `pcs/verifier.rs`。若 FriVerifier 构造过于复杂，可退化为：重放 channel 到 OODS point 后，手动按 Stwo `verify_values` 的逻辑 draw query positions。

#### C.3 trace_gen.rs 修复

`gen_fri_verifier_trace`（line 598-724）：

```rust
// 旧（line 616）：
// let query_x_qm31 = SecureField::from(1u32);

// 新：
let query_x_qm31 = public_inputs.fri_query_x;
let query_eval_qm31 = public_inputs.fri_query_eval;
// 删除 line 622 的 query_eval 计算（改用公开输入）
```

同时更新文档注释（lines 576-592 的 v5.1 placeholder 说明改为 v5.2 已修复）。

#### C.4 prover 端一致性检查（recursion_prover.rs）

在 `prove_recursive_with_fri`（line 239）中，Step 1 之后新增：

```rust
// v5.2: 验证 public_inputs.fri_query_x 与 L1 proof 一致
let (real_query_x, real_query_eval) = extract_fri_query_from_l1(
    l1_proof,
    public_inputs.config,
    public_inputs.log_size,
    &public_inputs.fri_last_layer_poly,
).ok_or_else(|| RecursionProvingError::L1ProofStructureInvalid(
    "无法从 L1 proof 提取 FRI query point".to_string()
))?;

if real_query_x != public_inputs.fri_query_x || real_query_eval != public_inputs.fri_query_eval {
    return Err(RecursionProvingError::FriQueryMismatch {
        claimed_x: public_inputs.fri_query_x,
        derived_x: real_query_x,
    });
}
```

新增 `RecursionProvingError::FriQueryMismatch` 变体。

#### C.5 channel mix 扩展（recursion_prover.rs）

`mix_public_inputs_into_channel`（line 372）新增：

```rust
// 6. fri_query_x + fri_query_eval（v5.2 soundness fix）
channel.mix_felts(&[inputs.fri_query_x, inputs.fri_query_eval]);
```

同步更新 verifier 端 `mix_public_inputs_into_channel`（`recursion_verifier.rs` 中对应函数）。

#### C.6 soundness 测试

```rust
#[test]
fn test_recursive_fri_soundness_tamper_query_x() {
    // 1. 构造合法 L1 proof（make_l1_proof）
    // 2. 用 extract_fri_query_from_l1 提取真实 (query_x, query_eval)
    // 3. 构造 RecursivePublicInputs（真实值）
    // 4. 篡改 fri_query_x = SecureField::from(2u32)（非真实值）
    // 5. 预期：prove_recursive_with_fri 失败（FriQueryMismatch）
}
```

**复杂度评估**：高。是整个修复中最复杂的部分。核心难点在 `extract_fri_query_from_l1` 的 FriVerifier 构造和 domain→point 转换。

**降级备选**（若 FriVerifier 构造不可行）：将 `query_x` 改为从 `query_positions[0]` 推导（`RecursivePublicInputs` 已有 `query_positions` 字段）。需：
1. 确保 `query_positions` 被 mix 到 channel（当前未 mix）
2. 用 `CanonicCoset::new(log_size + blowup).circle_domain()` 构造 domain
3. 用 domain API 将 position 转为 CirclePoint
但这要求 `query_positions` 先被正确提取（同样需重放 channel），故不降低复杂度。

---

### Phase D：全量 soundness 测试 + 回归

**文件**：`prover.rs` tests 模块 + `recursive/` tests

#### D.1 补齐 soundness 测试

| 指令类 | 测试数 | 来源 Phase |
|--------|--------|------------|
| 分支（V1） | 6 | Phase A（已写） |
| 范围检查（V4） | 2 | Phase B |
| 递归 FRI（V5） | 1 | Phase C |
| **小计** | 9 | |

#### D.2 全量回归测试

```bash
# 单元测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib

# 集成测试
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture

# 递归路径测试
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive"
```

**预期最终测试数**：~620（611 Phase 1 后 + 6 分支 + 2 范围 + 1 FRI），0 失败，0 回归。

---

## 4. 假设与决策（Assumptions & Decisions）

1. **执行顺序**：Phase A（验证 V1）→ Phase B（范围检查 V4）→ Phase C（递归 FRI V5）→ Phase D（测试）。每 Phase 完成后运行测试确认无回归。
2. **Phase B range check 用 logup**：唯一不超列预算的 sound 方案。24 limb/行 × claim，与 256 行 RangeCheckAir 的 yield 配平。
3. **Phase C V5 修复用 transcript replay**：从 L1 proof 重放 channel 提取真实 query_x，而非硬编码。这是 V5 的核心修复。若 FriVerifier 构造遇阻，退化为从 query_positions 推导（但同样需重放 channel）。
4. **逻辑/移位指令保持降级**：用户确认。XOR/OR/AND 需 bit 分解，SLL/SRL/SRA 需 shamt 分解，132 列预算不足。
5. **不修改已完成且通过测试的 Phase 1 实现**（V6 DIV、比较指令、JAL/JALR）。
6. **Phase B/C 可独立并行**（触及不同文件），但为安全串行执行。
7. **每个 Phase 完成后提交 git**，便于回溯。

---

## 5. 验证步骤（Verification Steps）

### Phase A 验证（V1 分支）
```bash
cargo +nightly-2026-04-15 build -p poker_zkvm
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "beq_soundness" "bne_soundness" "bltu_soundness" "bgeu_soundness" "blt_soundness" "bge_soundness"
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
```
预期：617 通过，0 失败。

### Phase B 验证（V4 范围检查）
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "range_check"
```
预期：619 通过（+2），0 失败。

### Phase C 验证（V5 递归 FRI）
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib -- "recursive" "fri_soundness"
```
预期：620 通过（+1），0 失败。

### Phase D 全量回归
```bash
cargo +nightly-2026-04-15 test -p poker_zkvm --lib
cargo +nightly-2026-04-15 test -p poker_zkvm --features test-helpers --test texas_poker_guest_e2e -- --nocapture
```
预期：~620 通过，0 失败，0 回归。

---

## 6. 实施优先级与执行清单

| 顺序 | Phase | 漏洞 | 严重度 | 预计约束 | 预计测试 | 阻塞? |
|------|-------|------|--------|----------|----------|-------|
| 1 | A | 验证 V1 分支条件 | CRITICAL | 0（已写） | 0（已写） | 是（当前未验证） |
| 2 | B | V4 limb 范围检查 | HIGH | logup | +2 | 否 |
| 3 | C | V5 递归 FRI query point | HIGH | 0（改用公开输入） | +1 | 否 |
| 4 | D | 全量 soundness + 回归 | — | 0 | +9 | 否 |

**执行者从顺序 1 开始**，每完成一步运行测试确认无回归后再进行下一步。Phase C 复杂度最高，若遇到 Stwo FriVerifier API 障碍，可先完成 Phase A+B+D（CRITICAL + HIGH range check + 测试）并提交，再单独处理 Phase C。
