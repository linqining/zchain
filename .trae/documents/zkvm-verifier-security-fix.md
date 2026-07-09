# poker_zkvm Verifier 安全修复计划

## Context

poker_zkvm 核心安全模块审核发现 5 个安全漏洞（4 CRITICAL + 1 MAJOR），当前 verifier 不具备 soundness 保证。恶意 prover 可组合 CCS 注入 + 伪造 folded LCCCS + 替换 public_io，生成通过验证的 proof 而无需真实执行任何程序。

**根因**：verifier 被设计为"简化 verifier"（`fold_loop.rs:192-195` 明确承认），仅验证 final sumcheck + PCS opening，不重派生 fold challenge、不验证中间 sumcheck、不绑定 public_io、不校验 CCS 白名单、不检查 batch 连续性。

**目标**：实现完整 verifier，恢复 soundness 保证，使恶意 prover 无法伪造 proof。

## 修复方案

### 设计决策

选择**完整 verifier 方案**（保存所有中间 sumcheck proofs + fold 数据），而非 CycleFold 递归压缩（Phase 12 未来工作）。理由：
- 符合当前 MVP 阶段
- CycleFold 是优化，不应阻塞安全修复
- 保存所有中间 proofs 更直接，易于验证正确性

### Soundness 链

verifier 验证以下链式保证：
1. **CCS 白名单**：拒绝未注册的 CCS 结构
2. **public_io 绑定**：proof 与 public_io 哈希绑定，防重放
3. **fold challenge 重派生**：重放主 transcript，验证每步 r 来自正确 FS
4. **fold commitment 等式**：每步 `C' = C_L + r · C_C`（不需 witness）
5. **fold 实例等式**：每步 `x' = x_L + r · x_C`、`r_x' = r_x_L`、`u' = actual_u_prime`
6. **所有中间 sumcheck**：每步验证 `G(r_x_L) == actual_u_prime` + 内层 cross-language claim
7. **最终 PCS opening**：验证 `z'(r_y)` 的正确性

**v_l 正确性**：由 sumcheck 隐含验证（v_l 被 absorb 到下一步 transcript，绑定到 fold challenge；sumcheck 验证 z' 约束满足性；PCS opening 绑定实际 z'）。

## 实施步骤

### Step 1: 新增数据结构

**文件**：`src/fold/fold_loop.rs`

1. 新增 `FoldStepData` 结构，保存每步 fold 的 verifier 所需数据：
   ```rust
   pub struct FoldStepData {
       // CCCCS 字段（verifier 需用于 fold challenge 重派生 + folded 实例计算）
       pub ccccs_witness_commitment: IpaCommitment,
       pub ccccs_u_c: Fr,
       pub ccccs_x_c: Vec<Fr>,
       pub ccccs_trace_c: Vec<Fr>,    // 关键：verifier 需计算 v_C[j](r_x_L) 和 folded_trace
       // Sumcheck 证明 + 输出
       pub sumcheck_proof: sumcheck::SumcheckProof,
       pub z_at_r_y: Fr,              // 该步 sumcheck 的 z'(r_y)
       pub actual_u_prime: Fr,        // 该步的 actual_u_prime（非线性 CCS 修正）
       // Folded 输出（verifier 需验证 fold 等式一致性）
       pub folded_lcccs: Lcccs,       // u_l = actual_u_prime 修正后的 folded LCCCS
       pub folded_witness_commitment: IpaCommitment,
   }
   ```

   **ccccs_trace_c 的必要性**：verifier 需 `trace_c` 来计算：
   - `v_C[j](r_x_L) = compute_v_at(trace_c, r_x_l)` → 验证 `folded_v[j] = v_L[j] + r · v_C[j]`
   - `folded_trace = trace_L + r · trace_C` → 验证 folded LCCCS 的 trace_l 一致

2. 修改 `HypernovaProof` 结构（**BREAKING**）：
   ```rust
   pub struct HypernovaProof {
       pub abi_version: u8,
       pub ccs_commitment: [u8; 32],              // 新增：CCS 白名单校验
       pub public_io_commitment: [u8; 32],         // 新增：public_io 绑定
       pub batch_public_inputs: Vec<Vec<Fr>>,      // 新增：所有 batch 的 [batch_id, first_idx, last_idx]
       pub initial_lcccs: Lcccs,                   // 新增：初始 LCCCS
       pub initial_witness_commitment: IpaCommitment, // 新增
       pub fold_steps: Vec<FoldStepData>,          // 新增：所有 fold 步骤
       pub final_sumcheck: sumcheck::SumcheckProof, // 保留（= fold_steps 最后一步，用于 PCS transcript 链式）
       pub pcs_opening: IpaProof,
       pub r_y: Vec<Fr>,                           // 保留：最终 PCS opening 点（= 最后一步 sumcheck 的 r_y）
       pub z_at_point: Fr,                         // 保留：z'(r_y)
   }
   ```
   - 移除 `folded_instance` 和 `witness_commitment`（由 `fold_steps.last().folded_lcccs` 和 `folded_witness_commitment` 替代）
   - 保留 `final_sumcheck`、`pcs_opening`、`r_y`、`z_at_point` 用于最终 PCS opening 验证
   - `batch_public_inputs`：prover 在 `prove()` 中 absorb 所有 batch 的 public_inputs 到 transcript（prover/mod.rs:621-625），verifier 必须重放相同 absorb 序列才能正确派生 `r_x_l`

### Step 2: 修改 fold_loop（prover 侧）

**文件**：`src/fold/fold_loop.rs`

修改 `fold_loop` 函数：
1. **函数签名变更**：新增 `ccs_commitment: [u8; 32]` 和 `public_io_commitment: [u8; 32]` 参数（或从 transcript 状态隐式传递）
2. **在循环中收集 `FoldStepData`**（每步保存）：
   - `ccccs_witness_commitment`：从 `ccccs.witness_commitment_c` 提取
   - `ccccs_u_c`：从 `ccccs.u_c` 提取
   - `ccccs_x_c`：从 `ccccs.x_c` 提取
   - `ccccs_trace_c`：从 `ccccs.trace_c` 提取（关键：verifier 需此计算 v_C）
   - `sumcheck_proof`：从 `sumcheck_output.proof` 提取
   - `z_at_r_y`：从 `sumcheck_output.z_at_r_y` 提取
   - `actual_u_prime`：从 `sumcheck_output.actual_u_prime` 提取
   - `folded_lcccs`：修正后的 `corrected_lcccs`（u_l = actual_u_prime）
   - `folded_witness_commitment`：从 `fold_output.folded_commitment` 提取
3. **循环结束后构造 `HypernovaProof`**，填充：
   - `ccs_commitment`、`public_io_commitment`（从参数传入）
   - `initial_lcccs`、`initial_witness_commitment`（fold_loop 入参）
   - `fold_steps`（收集的 Vec<FoldStepData>）
   - `final_sumcheck` = `fold_steps.last().sumcheck_proof`（冗余但便于 PCS transcript 链式）
   - `r_y`、`z_at_point`（最后一步的 r_y 和 z_at_r_y）
   - `pcs_opening`（PCS opening proof）
   - `batch_public_inputs`：从外部传入或由 prove() 填充

### Step 3: 修改 prover（public_io + CCS 绑定）

**文件**：`src/prover/mod.rs`

修改 `prove` 函数：
1. **提前构造 ZkPublicIo**：当前 ZkPublicIo 在 prove() 末尾构造（prover/mod.rs:681-692），但需在 transcript 初始化前吸收其哈希。将 ZkPublicIo 构造移到 execute_elf_with_config 之后（line 571 之后），因所有字段（input/output/randomness_seed/initial_commitment/final_commitment/event_hashes）在执行后均已可用。
2. **计算 public_io_commitment**：`hash_public_io(&public_io)` = Blake2b(public_io.to_bytes())
3. **absorb public_io_commitment 到 transcript**（在 ccs_commitment absorb 之前）：
   - 当前代码（prover/mod.rs:620）：`transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &expected_commitment);`
   - 修改为：先 absorb `public_io_commitment`，再 absorb `expected_commitment`
   ```rust
   let public_io_commitment = hash_public_io(&public_io);
   transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
   transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &expected_commitment);
   ```
4. **收集 batch_public_inputs**：从 `ccs_instances` 提取每个实例的 `public_inputs`（Vec<Fr>）
5. **传递新参数给 fold_loop**：`ccs_commitment`（= expected_commitment）、`public_io_commitment`、`batch_public_inputs`
6. **填充 HypernovaProof 新字段**：由 fold_loop 构造（Step 2），prove() 仅传递参数

新增 `hash_public_io` 函数（pub，供 verifier 复用）：
```rust
pub fn hash_public_io(public_io: &ZkPublicIo) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
    hasher.update(b"poker_zkvm_public_io");
    hasher.update(&public_io.to_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("finalize");
    out
}
```

### Step 4: 修改 serialize/deserialize

**文件**：`src/prover/mod.rs`

更新 `serialize_proof` 和 `deserialize_proof`：
1. **PROOF_VERSION**：v2 → v3（BREAKING 格式变更）
2. **新增字段序列化**（在 magic + version + abi_version 之后）：
   - `ccs_commitment`（32B）
   - `public_io_commitment`（32B）
   - `batch_public_inputs`：count(4B LE) + 每组 [batch_id(32B), first_idx(32B), last_idx(32B)]
   - `initial_lcccs`：复用现有 Lcccs 序列化（ccs_ref + u_l + x_l + trace_l + r_x_l + v_l）
   - `initial_witness_commitment`：compressed G1 point
   - `fold_steps`：count(4B LE) + 每步含：
     - `ccccs_witness_commitment`（compressed G1）
     - `ccccs_u_c`（32B Fr）
     - `ccccs_x_c`（length-prefixed Fr 序列）
     - `ccccs_trace_c`（length-prefixed Fr 序列）
     - `sumcheck_proof`（outer_round_polys + v_pp + inner_round_polys）
     - `z_at_r_y`（32B Fr）
     - `actual_u_prime`（32B Fr）
     - `folded_lcccs`（ccs_ref + u_l + x_l + trace_l + r_x_l + v_l）
     - `folded_witness_commitment`（compressed G1）
   - 保留 `final_sumcheck`、`pcs_opening`、`r_y`、`z_at_point` 序列化
3. **移除旧字段**：`folded_instance`、`witness_commitment`（已移入 fold_steps.last()）
4. **更新 MAX_PROOF_TOTAL_SIZE**：每步含完整 Lcccs + sumcheck + ccccs_trace_c，约 ~2-3KB
   - MVP 限制 `fold_steps.len() ≤ 100`（proof ≤ ~300KB，临时调大 MAX_PROOF_TOTAL_SIZE）
   - 生产环境用 CycleFold 压缩（Phase 12）

### Step 5: 重写 verifier

**文件**：`src/verifier.rs`

重写 `verify_production` 函数，新签名：
```rust
pub fn verify_production(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_whitelist: &[[u8; 32]],  // CCS commitment 白名单
) -> Result<bool, ZkvmError>
```

验证流程：
1. **反序列化 + 总长度校验**
2. **CCS 白名单校验**：`ccs_whitelist.contains(&proof.ccs_commitment)`
3. **public_io 绑定校验**：`hash_public_io(public_io) == proof.public_io_commitment`
4. **重放主 transcript**（匹配 prover/mod.rs:618-638 顺序）：
   - `Transcript::with_domain(b"poker_zkvm_prover_v1")`
   - absorb `public_io_commitment`（32B，在 ccs_commitment 之前 — 匹配 Step 3 顺序）
   - absorb `ccs_commitment`（32B）
   - absorb 所有 batch public_inputs（每组 [batch_id, first_idx, last_idx]，从 `proof.batch_public_inputs` 读取）
   - 派生 `r_x_l`（`challenge_vec(HYPERNOVA_FOLD_DOMAIN_TAG, log2(num_rows))`），验证 == `proof.initial_lcccs.r_x_l`
5. **逐步验证 fold_steps**（完整 fold 等式验证）：
   - 对每步 `FoldStepData`（current_lcccs 从 initial_lcccs 开始，每步更新）：
     a. **重放 fold absorb**（匹配 fold_step.rs:133-157 顺序）：
        - absorb `ccs_commitment`（32B Blake2b）
        - absorb `current_witness_commitment`（compressed G1）
        - absorb `current.u_l` / `current.x_l` / `current.r_x_l` / `current.v_l`
        - absorb `step.ccccs_witness_commitment`（compressed G1）
        - absorb `step.ccccs_u_c` / `step.ccccs_x_c`
     b. **派生 fold challenge r**，验证 r 与 prover 使用的一致（隐式：后续等式验证）
     c. **计算 v_C[j](r_x_L)**：`ccs.compute_v_at(&step.ccccs_trace_c, &current.r_x_l)`
     d. **验证 fold 实例等式**（与 `step.folded_lcccs` 比对）：
        - `folded_u_spec = current.u_l + r · step.ccccs_u_c`（spec 值，非 actual_u_prime）
        - `folded_x = current.x_l + r · step.ccccs_x_c` → 验证 `== step.folded_lcccs.x_l`
        - `folded_trace = current.trace_l + r · step.ccccs_trace_c` → 验证 `== step.folded_lcccs.trace_l`
        - `folded_r_x = current.r_x_l` → 验证 `== step.folded_lcccs.r_x_l`
        - `folded_v[j] = current.v_l[j] + r · v_C[j]` → 验证 `== step.folded_lcccs.v_l`
        - `step.folded_lcccs.u_l == step.actual_u_prime`（u_l 修正，非 spec 值）
     e. **验证 fold commitment 等式**：`step.folded_witness_commitment == current_witness_commitment + r · step.ccccs_witness_commitment`（EC 点加法）
     f. **验证 sumcheck**（fresh transcript，匹配 prover 的 fresh transcript 策略）：
        - `sumcheck::verify(&step.sumcheck_proof, &ccs, &current.r_x_l, step.actual_u_prime, step.z_at_r_y, &mut fresh_transcript)`
        - claimed_sum = `step.actual_u_prime`（非 spec u'，因非线性 CCS 修正）
     g. **推进**：`current_lcccs = step.folded_lcccs`，`current_witness_commitment = step.folded_witness_commitment`
6. **batch 连续性校验**：验证所有 batch 的 `first_idx == prev_last_idx + 1`
7. **最终 PCS opening 验证**：
   - 重建 IpaPcs
   - fresh transcript（与 final sumcheck 链式）
   - `pcs.verify(final_commitment, r_y, z_at_point, pcs_opening)`

### Step 6: 提升 verify_batch_continuity 为生产代码

**文件**：`src/constraints/mod.rs`

1. 移除 `verify_batch_continuity` 的 `#[cfg(test)]` 门控
2. 修改签名使其可被 verifier 调用：
   ```rust
   pub fn verify_batch_continuity(public_inputs: &[Vec<Fr>]) -> bool
   ```
3. verifier 在 step 6 调用此函数

### Step 7: 更新测试

**文件**：`src/verifier.rs`、`src/fold/fold_loop.rs`、`src/prover/mod.rs`

1. 更新 `verify_production` 测试，传入 `ccs_whitelist` 参数
2. 新增测试：
   - `test_verify_production_rejects_unregistered_ccs` — CCS 不在白名单
   - `test_verify_production_rejects_mismatched_public_io` — public_io 不匹配
   - `test_verify_production_rejects_tampered_fold_challenge` — 篡改 fold 输入
   - `test_verify_production_rejects_tampered_intermediate_sumcheck` — 篡改中间 sumcheck
   - `test_verify_production_rejects_non_continuous_batch` — batch 不连续
   - `test_verify_production_rejects_tampered_fold_commitment` — 篡改 fold commitment
3. 更新 `fold_loop` 测试以适配新 `HypernovaProof` 结构
4. 更新 `serialize/deserialize` 往返测试

### Step 8: 更新 verify_hypernova

**文件**：`src/fold/fold_loop.rs`

更新 `verify_hypernova` 函数以匹配新 `HypernovaProof` 结构，或标记为 deprecated（推荐由 `verify_production` 替代）。

## 关键文件

| 文件 | 变更类型 |
|------|----------|
| `src/fold/fold_loop.rs` | HypernovaProof 结构变更 + fold_loop 修改 + FoldStepData 新增 |
| `src/verifier.rs` | 完全重写 verify_production |
| `src/prover/mod.rs` | prove 修改 + serialize/deserialize 更新 + hash_public_io 新增 |
| `src/constraints/mod.rs` | verify_batch_continuity 提升为生产代码 |
| `src/fold/fold_step.rs` | 无变更（fold 函数不变） |
| `src/fold/sumcheck.rs` | 无变更（prove/verify 不变） |

## 验证方案

1. **单元测试**：`cargo test --all-features -p poker_zkvm`
   - 所有现有测试需更新通过
   - 新增 6 个安全测试（CCS 白名单/public_io/fold challenge/中间 sumcheck/batch 连续性/fold commitment）
2. **Clippy**：`cargo clippy --all-features -p poker_zkvm -- -D warnings`
3. **集成测试**：`cargo test --all-features -p poker_l1`（确认 poker_l1 集成不破坏）
4. **Soundness 验证**：构造恶意 proof（篡改中间 sumcheck / 伪造 CCS / 替换 public_io），确认 verifier 拒绝

## 风险与缓解

| 风险 | 缓解 |
|------|------|
| HypernovaProof 结构 BREAKING 变更 | 更新所有调用方（poker_l1 集成） |
| proof 大小增长（每步 ~2KB） | MVP 限制 fold_steps ≤ 100；生产用 CycleFold |
| 序列化格式变更（v2 → v3） | 更新 PROOF_VERSION = 3，兼容性由 abi_version 管理 |
| verifier 性能（N 步验证） | MVP 可接受；生产用 CycleFold 压缩到 O(1) |
