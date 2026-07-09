# poker_zkvm Verifier 安全修复 — 续作计划

## Context

延续 `zkvm-verifier-security-fix.md` 的 8 步修复计划。前序会话已完成 Steps 1/2/3(部分)/8，但代码当前**无法编译**，因 `serialize_proof`/`deserialize_proof`/`verify_production` 仍引用已删除的旧字段 `proof.folded_instance` 和 `proof.witness_commitment`。

本计划完成剩余 Steps 4-7，恢复编译并补齐 soundness 保证。

## 当前状态盘点

### 已完成

| Step | 文件 | 状态 |
|------|------|------|
| 1 | `src/fold/fold_loop.rs` | ✓ `FoldStepData` + 新 `HypernovaProof` 结构 |
| 2 | `src/fold/fold_loop.rs` | ✓ `fold_loop` 新签名 + 循环中收集 `FoldStepData` |
| 3(部分) | `src/prover/mod.rs` | ✓ `hash_public_io` + `PROOF_VERSION=3` + `MAX_PROOF_TOTAL_SIZE=512KB` + `prove()` absorb 顺序 + `batch_public_inputs` |
| 8 | `src/fold/fold_loop.rs` | ✓ `verify_hypernova` 标记 `#[deprecated]` |

### 待完成

| Step | 文件 | 阻塞问题 |
|------|------|----------|
| 4 | `src/prover/mod.rs` | `serialize_proof` (L297,327) / `deserialize_proof` (L539-547) 引用旧字段 |
| 5 | `src/verifier.rs` | `verify_production` (L62,79-81,95) 引用旧字段；需重写为完整 verifier |
| 6 | `src/constraints/mod.rs` | `verify_batch_continuity` (L197) 在 `#[cfg(test)]` 下 |
| 7 | 多文件 | `fold_loop.rs` 测试 (L438,440,471,508,539,575,751,895,924,953,959-961,1003) 引用旧字段；`verifier.rs` 测试引用旧字段；外部调用方需适配 |

### 外部调用方影响（BREAKING）

`verify_production` 签名将新增 `ccs_whitelist: &[[u8; 32]]` 参数，以下调用方需同步更新：
- `poker_l1/src/offline/hypernova.rs:209`
- `poker_zkvm/tests/e2e_fibonacci.rs:13`
- `poker_zkvm/tests/e2e_sha256_chain.rs:13`
- `poker_zkvm/tests/e2e_poker_hand_eval.rs:14`
- `poker_zkvm/tests/soundness_tests.rs:22`
- `poker_zkvm/benches/phase12_benchmarks.rs:15`

## 实施步骤

### Step 4: 更新 serialize_proof / deserialize_proof

**文件**：`src/prover/mod.rs`

#### 4.1 重写 `serialize_proof` (L290-385)

新序列化格式（v3）：
```
magic(4B) + version(1B) + abi_version(1B)
+ ccs_commitment(32B)
+ public_io_commitment(32B)
+ batch_public_inputs: count(4B LE) + 每组 [count(4B LE) + Fr×count]
+ initial_lcccs: ccs_ref(len-prefixed) + u_l(32B) + x_l + trace_l + r_x_l + v_l
+ initial_witness_commitment(compressed G1, len-prefixed)
+ fold_steps: count(4B LE) + 每步:
    - ccccs_witness_commitment(compressed G1, len-prefixed)
    - ccccs_u_c(32B) + ccccs_x_c + ccccs_trace_c
    - sumcheck_proof(outer_round_polys + v_pp + inner_round_polys)
    - r_y + z_at_r_y(32B) + actual_u_prime(32B)
    - folded_lcccs(ccs_ref len-prefixed + u_l + x_l + trace_l + r_x_l + v_l)
    - folded_witness_commitment(compressed G1, len-prefixed)
+ final_sumcheck(outer_round_polys + v_pp + inner_round_polys)
+ pcs_opening(l_vec + r_vec + a_final)
+ r_y + z_at_point(32B)
```

**关键点**：
- 抽取辅助函数 `serialize_lcccs(lcccs, &mut out)` 和 `serialize_sumcheck(sc, &mut out)` 避免重复（initial_lcccs / folded_lcccs / final_sumcheck 复用）
- `batch_public_inputs` 每组是 `Vec<Fr>`（长度可变，非固定 3），用嵌套 length-prefix
- `fold_steps` 中每步的 `folded_lcccs.ccs_ref` 与 `initial_lcccs.ccs_ref` 相同（CCS 一致性已校验），但仍需完整序列化以支持反序列化时的 `Lcccs::new` 维度校验

#### 4.2 重写 `deserialize_proof` (L391-548)

镜像 4.1 格式反序列化：
- 抽取 `deserialize_lcccs(bytes, pos) -> Result<Lcccs, ZkvmError>` 和 `deserialize_sumcheck(bytes, pos) -> Result<SumcheckProof, ZkvmError>`
- 反序列化后构造新 `HypernovaProof`（含 `ccs_commitment` / `public_io_commitment` / `batch_public_inputs` / `initial_lcccs` / `initial_witness_commitment` / `fold_steps` / `final_sumcheck` / `pcs_opening` / `r_y` / `z_at_point`）
- 保留总长度优先校验 + magic/version 校验

#### 4.3 更新 doc comment

`serialize_proof` 的 doc（L278-289）当前描述 v2 格式，需更新为 v3 格式说明。

### Step 5: 重写 verify_production

**文件**：`src/verifier.rs`

#### 5.1 新签名

```rust
pub fn verify_production(
    proof_bytes: &[u8],
    public_io: &ZkPublicIo,
    ccs_whitelist: &[[u8; 32]],
) -> Result<bool, ZkvmError>
```

#### 5.2 验证流程

```
1. deserialize_proof(proof_bytes) → proof
2. CCS 白名单校验：ccs_whitelist.contains(&proof.ccs_commitment)
   - 否则返回 Err(ZkvmError::Other("CCS 不在白名单"))
3. public_io 绑定校验：hash_public_io(public_io) == proof.public_io_commitment
   - 否则返回 Err(ZkvmError::Other("public_io 不匹配"))
4. 重建 IpaPcs（基于 proof.initial_lcccs.ccs_ref.num_vars）
5. 重放主 transcript（匹配 prover/mod.rs:659-687 顺序）：
   a. Transcript::with_domain(b"poker_zkvm_prover_v1")
   b. absorb public_io_commitment (32B)
   c. absorb ccs_commitment (32B)
   d. absorb 所有 batch_public_inputs（每组逐 Fr absorb_field）
   e. 派生 r_x_l = challenge_vec(HYPERNOVA_FOLD_DOMAIN_TAG, log2(num_rows))
   f. 校验 r_x_l == proof.initial_lcccs.r_x_l
6. 逐步验证 fold_steps（current_lcccs 从 initial_lcccs 开始）：
   对每步 step:
   a. 重放 fold absorb（匹配 fold_step.rs:133-157 顺序）：
      - absorb ccs_commitment (32B)
      - absorb current_witness_commitment (compressed G1 bytes)
      - absorb current.u_l / x_l / r_x_l / v_l (field + field_slice×3)
      - absorb step.ccccs_witness_commitment (compressed G1 bytes)
      - absorb step.ccccs_u_c / step.ccccs_x_c
   b. 派生 fold challenge r = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG)
   c. 计算 v_C[j](r_x_L) = ccs.compute_v_at(&step.ccccs_trace_c, &current.r_x_l)
   d. 验证 fold 实例等式（与 step.folded_lcccs 比对）：
      - folded_x = current.x_l + r·step.ccccs_x_c  == step.folded_lcccs.x_l
      - folded_trace = current.trace_l + r·step.ccccs_trace_c  == step.folded_lcccs.trace_l
      - folded_r_x = current.r_x_l  == step.folded_lcccs.r_x_l
      - folded_v[j] = current.v_l[j] + r·v_C[j]  == step.folded_lcccs.v_l
      - step.folded_lcccs.u_l == step.actual_u_prime（u_l 修正校验）
      - (folded_u_spec = current.u_l + r·step.ccccs_u_c 不需校验，因 u_l 已被 actual_u_prime 覆盖)
   e. 验证 fold commitment 等式：
      - expected = current_witness_commitment + r·step.ccccs_witness_commitment (EC 点加法)
      - expected == step.folded_witness_commitment
   f. 验证 sumcheck（fresh transcript）：
      - fresh_t = Transcript::new()
      - sumcheck::verify(&step.sumcheck_proof, &ccs, &current.r_x_l, step.actual_u_prime, step.z_at_r_y, &mut fresh_t)?
   g. 推进：current_lcccs = step.folded_lcccs.clone(); current_witness_commitment = step.folded_witness_commitment.clone()
   - 保存最后一步的 fresh_t 用于 PCS opening 链式
7. batch 连续性校验：verify_batch_continuity(&proof.batch_public_inputs)
   - 否则返回 Err(ZkvmError::Other("batch 不连续"))
8. 最终 PCS opening 验证（使用最后一步的 fresh transcript，链式）：
   - pcs.verify(&current_witness_commitment, &proof.r_y, &IpaEval(proof.z_at_point), &proof.pcs_opening, &mut last_fresh_t)?
9. 返回 Ok(true) 若全部通过
```

#### 5.3 关键导入

```rust
use crate::ccs::Fr as ZkvmFr;
use crate::field::ZkvmField;
use crate::fold::fold_step;  // 复用 point_to_bytes 逻辑（或内联）
use crate::prover::hash_public_io;
use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};
use ark_ec::AffineRepr;  // EC 点加法
```

**注**：`point_to_bytes` 在 fold_step.rs 是私有的。verifier 需复用相同字节编码（compressed serialization）以匹配 transcript absorb。方案：在 verifier 中使用 `G1Affine::serialize_compressed` 得到字节再 absorb（与 fold_step.rs 的 `point_to_bytes` 实现一致——需确认 fold_step.rs 的 point_to_bytes 实现）。

### Step 6: 提升 verify_batch_continuity 为生产代码

**文件**：`src/constraints/mod.rs`

1. 移除 `#[cfg(test)]` 门控（L197）
2. 修改签名为 `pub fn verify_batch_continuity(public_inputs: &[Vec<Fr>]) -> bool`（接收 `Vec<Fr>` 切片而非 `CcsInstance` 切片，避免 verifier 依赖 CcsInstance）
3. 保留原有逻辑（`prev_last[2] + 1 == next_first[1]`）
4. 更新 doc comment（移除"用于测试验证"措辞）

### Step 7: 更新测试 + 外部调用方

#### 7.1 更新 `src/fold/fold_loop.rs` 测试

所有 `fold_loop` 调用需补 3 个新参数：
```rust
// 旧
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript)
// 新
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript,
          ccs.ccs_commitment(), [0u8; 32], vec![vec![]])
```
（测试场景 public_io_commitment 用 `[0u8;32]`，batch_public_inputs 用 `vec![vec![]]` 即可，因 fold_loop 内不校验这些）

所有 `proof.folded_instance.X` 替换为 `proof.fold_steps.last().unwrap().folded_lcccs.X`：
- L438,440,471,508,539,575,895,924: `proof.folded_instance.u_l` → `proof.fold_steps.last().unwrap().folded_lcccs.u_l`
- L751: `proof.folded_instance.u_l = f(99)` → `proof.fold_steps.last_mut().unwrap().folded_lcccs.u_l = f(99)`
- L953,959-961: `proof.folded_instance.trace_l/ccs_ref/r_x_l/u_l` → 对应 fold_steps.last()
- L1003: `proof.witness_commitment.0` → `proof.fold_steps.last().unwrap().folded_witness_commitment.0`

#### 7.2 更新 `src/verifier.rs` 测试

- `make_valid_proof_and_public_io` 需返回 ccs_whitelist（从 proof 提取）
- 所有 `verify_production(&proof_bytes, &public_io)` 调用改为 `verify_production(&proof_bytes, &public_io, &ccs_whitelist)`
- 现有篡改测试（folded_instance/witness_commitment）需适配新结构：
  - `proof.folded_instance.u_l` → `proof.fold_steps.last_mut().unwrap().folded_lcccs.u_l`
  - `proof.witness_commitment` → `proof.fold_steps.last_mut().unwrap().folded_witness_commitment`
- 新增 6 个安全测试：
  1. `test_verify_production_rejects_unregistered_ccs` — ccs_whitelist 不含 proof.ccs_commitment
  2. `test_verify_production_rejects_mismatched_public_io` — 传入不同 public_io
  3. `test_verify_production_rejects_tampered_fold_challenge` — 篡改 step.ccccs_u_c（fold challenge 重派生失败）
  4. `test_verify_production_rejects_tampered_intermediate_sumcheck` — 篡改非最后一步的 sumcheck_proof
  5. `test_verify_production_rejects_non_continuous_batch` — 篡改 batch_public_inputs 使不连续
  6. `test_verify_production_rejects_tampered_fold_commitment` — 篡改 step.folded_witness_commitment

#### 7.3 更新 `src/prover/mod.rs` 测试

- `test_deserialize_proof_roundtrip` (L1259) 应自动适配新 serialize/deserialize
- 其他 prove() 测试不直接访问 proof 结构，无需修改

#### 7.4 更新外部调用方

**`poker_l1/src/offline/hypernova.rs:209`**：
```rust
// 旧
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io) {
// 新
let ccs_whitelist = Self::get_ccs_whitelist();  // 需新增方法或常量
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_whitelist) {
```
**决策**：poker_l1 维护一个 CCS 白名单常量（或从配置读取）。MVP 阶段先用空切片 `&[]` 会导致所有 proof 被拒，故需提供至少一个有效 commitment。方案：在 poker_l1 中新增 `fn default_ccs_whitelist() -> Vec<[u8;32]>`，返回当前 MVP CCS 的 commitment（可从 generate_test_proof 提取，或硬编码）。

**`poker_zkvm/tests/*.rs` 和 `benches/phase12_benchmarks.rs`**：
- 调用方需构造 ccs_whitelist。方案：在 `test_helpers.rs` 新增 `pub fn default_ccs_whitelist() -> Vec<[u8;32]>`，内部调用 `generate_test_proof()` 提取 ccs_commitment（或直接从 prove 返回的 proof_bytes 反序列化提取）。
- **更简洁方案**：verify_production 提供 `verify_production_with_default_whitelist` 便捷函数，内部用 `generate_test_proof` 提取白名单。**不采用**——会引入循环依赖且生产不安全。
- **最终方案**：测试辅助函数 `default_ccs_whitelist()` 放入 `test_helpers.rs`，调用 `generate_test_proof()` → `deserialize_proof()` → 提取 `ccs_commitment`，返回 `vec![ccs_commitment]`。

## Assumptions & Decisions

1. **CCS 白名单来源**：verifier 不内建白名单，由调用方传入。MVP 阶段 poker_l1 和测试通过 `default_ccs_whitelist()` 辅助函数构造。生产环境应由链上治理配置。
2. **fold_steps 中的 folded_lcccs.ccs_ref 冗余**：每步序列化完整 ccs_ref（~数百字节），proof 增大但反序列化时能独立校验维度。MVP 可接受（fold_steps ≤ 100）。未来可用 ccs_ref 索引优化。
3. **fresh transcript for sumcheck**：每步 sumcheck 用 `Transcript::new()`（fresh），与 prover 的 `sumcheck::prove` 一致（fold_loop.rs:176）。最后一步的 fresh transcript 传给 PCS opening（链式）。
4. **point_to_bytes 复用**：fold_step.rs 的 `point_to_bytes` 是私有的。verifier 需用相同字节编码 absorb。方案：在 fold_step.rs 将 `point_to_bytes` 改为 `pub(crate)` 或在 verifier 内联相同逻辑（`G1Affine::serialize_compressed` → bytes）。**采用后者**（内联，避免暴露内部工具）。
5. **batch_public_inputs absorb 顺序**：prover 在 `prove()` 中对每个 ccs_instance 的 public_inputs 逐 Fr absorb（prover/mod.rs:670-674）。verifier 需镜像相同顺序：对 `proof.batch_public_inputs` 的每组，逐 Fr `absorb_field`。
6. **不修改 fold_step.rs / sumcheck.rs / lcccs.rs / ccccs.rs**：这些模块的协议逻辑不变，仅 verifier 侧重放验证。

## Verification Steps

1. **编译检查**：`cargo build --all-features -p poker_zkvm`
2. **单元测试**：`cargo test --all-features -p poker_zkvm`
   - 所有现有测试更新通过
   - 新增 6 个安全测试通过
3. **Clippy**：`cargo clippy --all-features -p poker_zkvm -- -D warnings`
4. **poker_l1 集成**：`cargo build --all-features -p poker_l1` + `cargo test --all-features -p poker_l1`
5. **E2E + Soundness**：`cargo test --all-features --test e2e_fibonacci --test e2e_sha256_chain --test e2e_poker_hand_eval --test soundness_tests`
6. **基准测试编译**：`cargo build --benches --all-features -p poker_zkvm`

## 关键文件

| 文件 | Step | 变更类型 |
|------|------|----------|
| `poker_zkvm/src/prover/mod.rs` | 4 | serialize_proof / deserialize_proof 重写 |
| `poker_zkvm/src/verifier.rs` | 5,7 | verify_production 重写 + 测试更新 |
| `poker_zkvm/src/constraints/mod.rs` | 6 | verify_batch_continuity 提升为 pub |
| `poker_zkvm/src/fold/fold_loop.rs` | 7 | 测试适配新结构 |
| `poker_zkvm/src/test_helpers.rs` | 7 | 新增 default_ccs_whitelist() |
| `poker_l1/src/offline/hypernova.rs` | 7 | verify_production 调用适配 |
| `poker_zkvm/tests/e2e_*.rs` | 7 | verify_production 调用适配 |
| `poker_zkvm/tests/soundness_tests.rs` | 7 | verify_production 调用适配 |
| `poker_zkvm/benches/phase12_benchmarks.rs` | 7 | verify_production 调用适配 |
