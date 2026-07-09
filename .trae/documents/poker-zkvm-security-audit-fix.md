# poker\_zkvm 安全审计 + 修复完成计划

## Summary

对 `/Users/mac/projects/zchain/poker_zkvm` 进行安全审核（参照 spec.md v1.4 FROZEN 与 Hypernova 原论文）。前序会话已修复 5 个安全漏洞（CCS 白名单 / public\_io 绑定 / fold challenge 重派生 / 中间 sumcheck / batch 连续性），但代码当前**无法编译**（fold\_loop 测试与 6 个外部调用方未适配新签名）。本次审核在已修复的 verifier 中又发现 **2 个新 CRITICAL 漏洞 + 1 个 MINOR 防御深度缺陷**，并制定完整修复 + 编译验证计划。

## Current State Analysis

### 已完成的修复（前序会话）

| 修复项                                      | 文件                      | 状态 |
| ---------------------------------------- | ----------------------- | -- |
| CCS 白名单校验                                | `verifier.rs` L73-79    | ✓  |
| public\_io 绑定                            | `verifier.rs` L81-87    | ✓  |
| fold challenge 重派生                       | `verifier.rs` L135-154  | ✓  |
| fold commitment 等式                       | `verifier.rs` L220-231  | ✓  |
| fold 实例等式                                | `verifier.rs` L159-218  | ✓  |
| 中间 sumcheck 验证                           | `verifier.rs` L233-245  | ✓  |
| batch 连续性                                | `verifier.rs` L253-258  | ✓  |
| `HypernovaProof` 新结构（含 fold\_steps）      | `fold_loop.rs` L44-101  | ✓  |
| `fold_loop` 8 参数签名                       | `fold_loop.rs` L137-147 | ✓  |
| `verify_hypernova` 标记 deprecated + 兼容新结构 | `fold_loop.rs` L278-314 | ✓  |
| `verify_production` 3 参数签名               | `verifier.rs` L65-69    | ✓  |
| verifier.rs 内部测试适配 3 参数                  | `verifier.rs` L277-609  | ✓  |

### 当前阻塞问题：代码无法编译

**根因**：fold\_loop 测试 + 外部调用方未适配新签名。具体断点：

1. **`src/fold/fold_loop.rs`** **测试**（\~18 处调用 + \~14 处旧字段引用）：

   * 所有 `fold_loop(...)` 调用缺少 3 个新参数：`ccs_commitment`, `public_io_commitment`, `batch_public_inputs`

   * 引用已删除字段 `proof.folded_instance.X`（应为 `proof.fold_steps.last().unwrap().folded_lcccs.X`）

   * 引用已删除字段 `proof.witness_commitment`（应为 `proof.fold_steps.last().unwrap().folded_witness_commitment`）

2. **`default_ccs_whitelist()`** **缺失**：外部调用方需要此函数构造白名单

3. **6 个外部调用方**（`verify_production` 2 参数 → 3 参数 BREAKING）：

   * `poker_l1/src/offline/hypernova.rs:209`

   * `poker_zkvm/tests/soundness_tests.rs:73,86,306,319`（4 处）

   * `poker_zkvm/tests/e2e_fibonacci.rs:34`

   * `poker_zkvm/tests/e2e_sha256_chain.rs:48`

   * `poker_zkvm/tests/e2e_poker_hand_eval.rs:38`

   * `poker_zkvm/benches/phase12_benchmarks.rs:107`

## Audit Findings

### 原有 5 个漏洞（已修复，本次审核确认正确）

| # | 严重性      | 漏洞                   | 修复位置                 | 状态    |
| - | -------- | -------------------- | -------------------- | ----- |
| 1 | CRITICAL | 无 CCS 白名单校验          | verifier.rs L73-79   | ✓ 已修复 |
| 2 | CRITICAL | 无 public\_io 绑定      | verifier.rs L81-87   | ✓ 已修复 |
| 3 | CRITICAL | 无 fold challenge 重派生 | verifier.rs L135-154 | ✓ 已修复 |
| 4 | CRITICAL | 无中间 sumcheck 验证      | verifier.rs L233-245 | ✓ 已修复 |
| 5 | MAJOR    | 无 batch 连续性校验        | verifier.rs L253-258 | ✓ 已修复 |

**审核确认**：prover 与 verifier 的 transcript absorb 顺序完全一致：

* 主 transcript：`public_io_commitment → ccs_commitment → batch_public_inputs(逐 Fr) → challenge×r_x_l_len`（prover/mod.rs:807-833 vs verifier.rs:103-128）✓

* fold transcript：`ccs_commitment → witness_commitment_L → u_l/x_l/r_x_l/v_l → witness_commitment_C → u_c/x_c → challenge r`（fold\_step.rs:133-160 vs verifier.rs:137-154）✓

* transcript domain：`b"poker_zkvm_prover_v1"`（prover/mod.rs:805 vs verifier.rs:101）✓

### 新发现漏洞（本次审核）

#### Finding A — CRITICAL：PCS opening 与 sumcheck 解耦

**位置**：`src/verifier.rs` L260-272

**问题**：verifier 在最终 PCS opening 验证时直接使用 `proof.r_y` 和 `proof.z_at_point`（顶层冗余字段），**未校验**它们等于 `fold_steps.last().r_y` 和 `fold_steps.last().z_at_r_y`。

**根因分析**：

* `proof.r_y` / `proof.z_at_point` 是 proof 中的独立冗余字段（合法 prover 中 = `fold_steps.last().r_y` / `.z_at_r_y`）

* sumcheck::verify 验证 `z'(step.r_y) = step.z_at_r_y`（使用 fold\_step 内的字段）

* PCS verify 验证 `z'(proof.r_y) = proof.z_at_point`（使用 proof 顶层字段）

* IPA verify 会 absorb `proof.r_y` 到 transcript（ipa.rs L392），但攻击者知道 `proof.r_y` 和 commitment 的 witness，可重新生成有效 IPA proof

**攻击路径**：

1. 攻击者选择白名单 CCS，构造任意 `initial_lcccs`
2. 对同一 CCS 运行合法 fold（使用满足约束的 witness w\_sat）→ 获得有效 sumcheck proof、r\_y\_sat、z\_at\_r\_y\_sat
3. 选择任意 w\_L、w\_C，计算 w' = w\_L + r·w\_C，承诺 C' = C\_L + r·C\_C
4. 设置 `step.sumcheck_proof` = 合法 proof，`step.r_y` = r\_y\_sat，`step.z_at_r_y` = z\_at\_r\_y\_sat
5. 线性 fold 方程 + fold commitment 等式可满足（攻击者自由选择字段）
6. PCS：设置 `proof.r_y` = r\_y\_new（≠ r\_y\_sat），`proof.z_at_point` = w'(r\_y\_new)，`proof.pcs_opening` = C' 在 r\_y\_new 处的有效 IPA opening

**结果**：verifier 接受 proof，但 sumcheck 验证的是 w\_sat（满足 CCS），PCS 验证的是 w'（不满足 CCS），二者完全解耦。

#### Finding B — CRITICAL：空 fold\_steps 未被拒绝

**位置**：`src/verifier.rs` L135（`for step in &proof.fold_steps` 循环）

**问题**：若 `proof.fold_steps` 为空，循环不执行，`last_sumcheck_transcript` 保持 `None`，PCS opening 使用 `Transcript::default()`。恶意 prover 构造空 fold\_steps 的 proof，仅需提供 `initial_witness_commitment` 的有效 IPA opening，完全绕过所有 fold/sumcheck 验证。

#### Finding C — MINOR：ccs\_commitment 一致性未显式校验

**位置**：`src/verifier.rs` L73-79, L90, L137

**问题**：

* verifier 用 `proof.ccs_commitment`（顶层字段）做白名单校验（L74）和 fold transcript absorb（L137）

* verifier 用 `proof.initial_lcccs.ccs_ref`（L90）做 `compute_v_at` 和 `sumcheck::verify`

* 未显式校验 `proof.ccs_commitment == proof.initial_lcccs.ccs_ref.ccs_commitment()`

* 当前间接被 fold 方程 + sumcheck 捕获，但缺乏防御深度

## Proposed Changes

### Step 1: 修复 Finding A + B（PCS-sumcheck 绑定 + 拒绝空 fold\_steps）

**文件**：`poker_zkvm/src/verifier.rs`

在 L258（batch 连续性校验之后、PCS opening 验证 L260 之前）插入：

```rust
// 7.5 PCS-sumcheck 绑定校验（Finding A + B）
let last_step = proof.fold_steps.last().ok_or_else(|| {
    ZkvmError::InvalidZkProofFormat("fold_steps 为空：无法链接 PCS opening".to_string())
})?;
if proof.r_y != last_step.r_y {
    return Err(ZkvmError::Other(
        "PCS opening 解耦：proof.r_y != fold_steps.last().r_y".to_string(),
    ));
}
if proof.z_at_point != last_step.z_at_r_y {
    return Err(ZkvmError::Other(
        "PCS opening 解耦：proof.z_at_point != fold_steps.last().z_at_r_y".to_string(),
    ));
}
```

### Step 2: 修复 Finding C（ccs\_commitment 显式一致性校验）

**文件**：`poker_zkvm/src/verifier.rs`

在 L98（`let pcs = IpaPcs::new(pcs_n_vars)?;` 之后）插入：

```rust
// 4.5 ccs_commitment 一致性校验（Finding C — 防御深度）
let initial_ccs_commit = ccs.ccs_commitment();
if proof.ccs_commitment != initial_ccs_commit {
    return Err(ZkvmError::Other(
        "ccs_commitment 不匹配：proof.ccs_commitment != initial_lcccs.ccs_ref.ccs_commitment()".to_string(),
    ));
}
```

### Step 3: 新增 `default_ccs_whitelist()` 到 `prover/mod.rs`

**文件**：`poker_zkvm/src/prover/mod.rs`

在 `generate_test_proof()` 附近（L930 后）新增。由于 `generate_test_proof()` 当前为 `#[cfg(any(test, feature = "test-helpers"))]`，`default_ccs_whitelist` 也需同样门控：

```rust
/// 构造默认 CCS 白名单（从 `generate_test_proof` 提取 ccs_commitment）。
///
/// **MVP 权宜之计**：仅供测试、基准测试和 MVP 生产调用方使用。
/// 生产环境应由链上治理配置白名单。
#[cfg(any(test, feature = "test-helpers"))]
pub fn default_ccs_whitelist() -> Vec<[u8; 32]> {
    let (proof_bytes, _) = generate_test_proof();
    let proof = deserialize_proof(&proof_bytes)
        .expect("deserialize generate_test_proof 应成功");
    vec![proof.ccs_commitment]
}
```

**前提确认**：`deserialize_proof` 已为 `pub`（verifier.rs L27 直接 `use`），`generate_test_proof` 已为 `pub`（L930），二者在同模块内可直接调用。

### Step 4: 更新 `poker_l1/Cargo.toml` 启用 test-helpers feature

**文件**：`poker_l1/Cargo.toml`

当前 `[dependencies]`（L11）为 `poker_zkvm = { workspace = true }`（无 test-helpers）。`default_ccs_whitelist` 在 `prover/mod.rs` 中被 `#[cfg(any(test, feature = "test-helpers"))]` 门控，poker\_l1 的**生产代码**（`src/offline/hypernova.rs`）需访问它，因此须在 `[dependencies]` 中启用：

```toml
[dependencies]
poker_zkvm = { workspace = true, features = ["test-helpers"] }
```

**注**：这是 MVP 权宜之计。生产环境实现治理白名单后，移除此 feature 依赖。

### Step 5: 更新 `fold_loop.rs` 测试

**文件**：`poker_zkvm/src/fold/fold_loop.rs`

#### 5.1 所有 `fold_loop` 调用补 3 个新参数（\~18 处）

所有形如：

```rust
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript)
```

改为：

```rust
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript,
          ccs.ccs_commitment(), [0u8; 32], vec![vec![]])
```

涉及行号（需逐一确认）：L424, L458, L497, L528, L563, L590, L613, L649, L679, L712, L740, L769, L798, L829, L884, L913, L941, L988

#### 5.2 替换旧字段引用（\~14 处）

| 旧引用                             | 新引用                                                          |
| ------------------------------- | ------------------------------------------------------------ |
| `proof.folded_instance.u_l`     | `proof.fold_steps.last().unwrap().folded_lcccs.u_l`          |
| `proof.folded_instance.trace_l` | `proof.fold_steps.last().unwrap().folded_lcccs.trace_l`      |
| `proof.folded_instance.ccs_ref` | `proof.fold_steps.last().unwrap().folded_lcccs.ccs_ref`      |
| `proof.folded_instance.r_x_l`   | `proof.fold_steps.last().unwrap().folded_lcccs.r_x_l`        |
| `proof.witness_commitment`      | `proof.fold_steps.last().unwrap().folded_witness_commitment` |

赋值场景（L751）：`proof.folded_instance.u_l = f(99)` → `proof.fold_steps.last_mut().unwrap().folded_lcccs.u_l = f(99)`

涉及行号：L438, L440, L471, L508, L539, L575, L751, L895, L924, L953, L959, L960, L961, L1003

### Step 6: 更新外部调用方（`verify_production` 3 参数签名）

#### 6.1 `poker_l1/src/offline/hypernova.rs:209`

```rust
// 旧
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io) {
// 新
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_whitelist) {
```

#### 6.2 `poker_zkvm/tests/soundness_tests.rs`（4 处：L73, L86, L306, L319）

```rust
// 旧
let result = verify_production(&proof_bytes, &public_io);
// 新
use poker_zkvm::prover::default_ccs_whitelist;
let ccs_whitelist = default_ccs_whitelist();
let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
```

**注**：`default_ccs_whitelist` 在 `prover` 模块，tests 默认启用 `test-helpers` feature（Cargo.toml `[dev-dependencies]` 或 `--all-features`），可访问。

#### 6.3 `poker_zkvm/tests/e2e_fibonacci.rs:34`

```rust
// 旧
let ok = verify_production(&proof_bytes, &public_io)
// 新
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
let ok = verify_production(&proof_bytes, &public_io, &ccs_whitelist)
```

#### 6.4 `poker_zkvm/tests/e2e_sha256_chain.rs:48` — 同 6.3

#### 6.5 `poker_zkvm/tests/e2e_poker_hand_eval.rs:38` — 同 6.3

#### 6.6 `poker_zkvm/benches/phase12_benchmarks.rs:107`

```rust
// 旧
let ok = verify_production(black_box(&proof_bytes), black_box(&public_io))
// 新
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
let ok = verify_production(black_box(&proof_bytes), black_box(&public_io), black_box(&ccs_whitelist))
```

### Step 7: 新增 Finding A + B 回归测试

**文件**：`poker_zkvm/src/verifier.rs`（测试模块末尾，L609 后）

```rust
#[test]
fn test_verify_production_rejects_pcs_sumcheck_decoupling() {
    let (proof_bytes, public_io) = make_valid_proof_and_public_io();
    let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
    let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
    // 篡改 proof.r_y（使其 != fold_steps.last().r_y）
    if !proof.r_y.is_empty() {
        let val = proof.r_y[0];
        proof.r_y[0] = val.add(&ZkvmFr::from_u32_with_wrap(1));
    }
    let tampered = serialize_proof(&proof).expect("serialize 应成功");
    let result = verify_production(&tampered, &public_io, &ccs_whitelist);
    assert!(
        matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("PCS opening 解耦")),
        "PCS-sumcheck 解耦应被拒绝，got: {result:?}"
    );
}

#[test]
fn test_verify_production_rejects_empty_fold_steps() {
    let (proof_bytes, public_io) = make_valid_proof_and_public_io();
    let ccs_whitelist = extract_ccs_whitelist(&proof_bytes);
    let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");
    // 清空 fold_steps
    proof.fold_steps.clear();
    let tampered = serialize_proof(&proof).expect("serialize 应成功");
    let result = verify_production(&tampered, &public_io, &ccs_whitelist);
    assert!(
        matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("fold_steps 为空")),
        "空 fold_steps 应被拒绝，got: {result:?}"
    );
}
```

### Step 8: 更新 README.md 示例

**文件**：`poker_zkvm/README.md` L63

```rust
// 旧
let ok = verify_production(&proof_bytes, &public_io)
// 新
let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
let ok = verify_production(&proof_bytes, &public_io, &ccs_whitelist)
```

## Assumptions & Decisions

1. **CCS 白名单来源**：verifier 不内建白名单，由调用方传入。MVP 阶段通过 `default_ccs_whitelist()` 构造（从 `generate_test_proof` 提取）。生产环境应由链上治理配置。

2. **poker\_l1 feature 依赖**：poker\_l1 的 `[dependencies]` 需启用 poker\_zkvm 的 `test-helpers` feature 才能访问 `default_ccs_whitelist()`。这是 MVP 权宜之计，生产环境实现治理白名单后移除。

3. **Finding A 修复不改变 proof 格式**：仅添加 verifier 端校验，proof 结构和序列化不变（`proof.r_y` / `proof.z_at_point` 字段保留，verifier 现在强制它们等于 `fold_steps.last()` 对应字段）。

4. **不修改 fold\_step.rs / sumcheck.rs / lcccs.rs / ccccs.rs / ipa.rs**：协议逻辑不变，仅 verifier 侧增加校验。

5. **fold\_loop.rs 测试参数**：测试场景中 `public_io_commitment` 用 `[0u8;32]`，`batch_public_inputs` 用 `vec![vec![]]`（fold\_loop 内不校验这些，仅存入 proof）。

6. **`verify_hypernova`** **deprecated 函数保留**：已兼容新 `fold_steps` 结构（L281-286），测试中仍可调用（产生 deprecation warning，不影响编译）。

## Verification Steps

1. **poker\_zkvm 编译**：`cargo build --all-features -p poker_zkvm`
2. **poker\_zkvm 单元测试**：`cargo test --all-features -p poker_zkvm`

   * fold\_loop 测试全部通过

   * verifier 新增 8 个安全测试通过（6 原有 + 2 新增 Finding A/B）
3. **poker\_zkvm Clippy**：`cargo clippy --all-features -p poker_zkvm -- -D warnings`
4. **poker\_l1 编译**：`cargo build --all-features -p poker_l1`
5. **poker\_l1 测试**：`cargo test --all-features -p poker_l1`
6. **E2E 测试**：`cargo test --all-features -p poker_zkvm --test e2e_fibonacci --test e2e_sha256_chain --test e2e_poker_hand_eval`
7. **Soundness 测试**：`cargo test --all-features -p poker_zkvm --test soundness_tests`
8. **基准测试编译**：`cargo build --benches --all-features -p poker_zkvm`

## 关键文件变更清单

| 文件                                         | 变更类型                                       |
| ------------------------------------------ | ------------------------------------------ |
| `poker_zkvm/src/verifier.rs`               | Finding A/B/C 修复 + 2 个新测试                  |
| `poker_zkvm/src/prover/mod.rs`             | 新增 `default_ccs_whitelist()`               |
| `poker_zkvm/src/fold/fold_loop.rs`         | 测试适配新签名 + 新字段引用                            |
| `poker_l1/Cargo.toml`                      | `[dependencies]` 启用 `test-helpers` feature |
| `poker_l1/src/offline/hypernova.rs`        | `verify_production` 3 参数适配                 |
| `poker_zkvm/tests/soundness_tests.rs`      | 4 处 3 参数适配                                 |
| `poker_zkvm/tests/e2e_fibonacci.rs`        | 3 参数适配                                     |
| `poker_zkvm/tests/e2e_sha256_chain.rs`     | 3 参数适配                                     |
| `poker_zkvm/tests/e2e_poker_hand_eval.rs`  | 3 参数适配                                     |
| `poker_zkvm/benches/phase12_benchmarks.rs` | 3 参数适配                                     |
| `poker_zkvm/README.md`                     | 示例代码 3 参数适配                                |

