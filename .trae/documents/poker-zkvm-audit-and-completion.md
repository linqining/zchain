# poker\_zkvm 审计报告 + 安全修复完成计划

## Summary

对 `/Users/mac/projects/zchain/poker_zkvm` 进行安全审核（参照 spec.md 与 poker\_l1 中的 stub 实现）。前序会话已识别 5 个安全漏洞（4 CRITICAL + 1 MAJOR）并实施修复（Steps 1-8），但代码当前**无法编译**（Step 7 测试/调用方更新未完成）。本次审核在已修复的 verifier 中又发现 **2 个新 CRITICAL 漏洞 + 1 个 MINOR 防御深度缺陷**，并制定完整修复 + 编译验证计划。

## Current State Analysis

### 已完成的修复（Steps 1-8，前序会话）

| Step | 文件                       | 内容                                                         | 状态 |
| ---- | ------------------------ | ---------------------------------------------------------- | -- |
| 1    | `src/fold/fold_loop.rs`  | `FoldStepData` + 新 `HypernovaProof` 结构                     | ✓  |
| 2    | `src/fold/fold_loop.rs`  | `fold_loop` 新签名 + 收集 `FoldStepData`                        | ✓  |
| 3    | `src/prover/mod.rs`      | `hash_public_io` + `PROOF_VERSION=3` + `prove()` absorb 顺序 | ✓  |
| 4    | `src/prover/mod.rs`      | `serialize_proof`/`deserialize_proof` 重写 v3 格式             | ✓  |
| 5    | `src/verifier.rs`        | `verify_production` 重写完整 verifier（3 参数签名）                  | ✓  |
| 6    | `src/constraints/mod.rs` | `verify_batch_continuity` 提升为 `pub`                        | ✓  |
| 8    | `src/fold/fold_loop.rs`  | `verify_hypernova` 标记 `#[deprecated]`                      | ✓  |

### 当前阻塞问题：代码无法编译

**根因**：Step 7（测试 + 外部调用方更新）未完成。具体断点：

1. **`src/fold/fold_loop.rs`** **测试（\~15 处调用 + \~12 处旧字段引用）**：

   * 所有 `fold_loop(...)` 调用缺少 3 个新参数：`ccs_commitment`, `public_io_commitment`, `batch_public_inputs`

   * 引用已删除字段 `proof.folded_instance.X`（应为 `proof.fold_steps.last().unwrap().folded_lcccs.X`）

   * 引用已删除字段 `proof.witness_commitment`（应为 `proof.fold_steps.last().unwrap().folded_witness_commitment`）

   * 涉及行号：L424-432, L438/440, L458-465, L470-473, L497-504, L508, L528-535, L539, L563-570, L575, L590, L613-620, L649-656, L679-686, L712-719, L740-747, L751, L769-776, L798-805, L829-836, L884-891, L895, L913-920, L924, L941-948, L953/959/960/961, L988-995, L1003

2. **`src/verifier.rs`** **测试**：已在 Step 5 中完成（含 6 个新安全测试 + `extract_ccs_whitelist` 辅助函数）✓

3. **`src/test_helpers.rs`**：缺少 `default_ccs_whitelist()` 函数

4. **外部调用方（`verify_production`** **2 参数 → 3 参数 BREAKING）**：

   * `poker_l1/src/offline/hypernova.rs:209` — `verify_production(proof, &zkvm_public_io)` 缺 `ccs_whitelist`

   * `poker_zkvm/tests/soundness_tests.rs:73,86,306,319` — 4 处 2 参数调用

   * `poker_zkvm/tests/e2e_fibonacci.rs:34` — 1 处

   * `poker_zkvm/tests/e2e_sha256_chain.rs:48` — 1 处

   * `poker_zkvm/tests/e2e_poker_hand_eval.rs:38` — 1 处

   * `poker_zkvm/benches/phase12_benchmarks.rs:107` — 1 处

## Audit Findings

### 原有 5 个漏洞（已修复，本次审核确认修复正确）

| # | 严重性      | 漏洞                   | 修复位置                 | 状态    |
| - | -------- | -------------------- | -------------------- | ----- |
| 1 | CRITICAL | 无 CCS 白名单校验          | verifier.rs L74      | ✓ 已修复 |
| 2 | CRITICAL | 无 public\_io 绑定      | verifier.rs L82-87   | ✓ 已修复 |
| 3 | CRITICAL | 无 fold challenge 重派生 | verifier.rs L137-154 | ✓ 已修复 |
| 4 | CRITICAL | 无中间 sumcheck 验证      | verifier.rs L233-245 | ✓ 已修复 |
| 5 | MAJOR    | 无 batch 连续性校验        | verifier.rs L253-258 | ✓ 已修复 |

**审核确认**：prover 与 verifier 的 transcript absorb 顺序完全一致：

* 主 transcript：`public_io_commitment → ccs_commitment → batch_public_inputs(逐 Fr) → challenge×r_x_l_len`（prover/mod.rs:807-833 vs verifier.rs:103-128）✓

* fold transcript：`ccs_commitment → witness_commitment_L → u_l/x_l/r_x_l/v_l → witness_commitment_C → u_c/x_c → challenge r`（fold\_step.rs:133-160 vs verifier.rs:137-154）✓

* transcript domain：`b"poker_zkvm_prover_v1"`（prover/mod.rs:805 vs verifier.rs:101）✓

### 新发现漏洞（本次审核）

#### Finding A — CRITICAL：PCS opening 与 sumcheck 解耦

**位置**：`src/verifier.rs` L260-272

**问题**：verifier 在最终 PCS opening 验证时直接使用 `proof.r_y` 和 `proof.z_at_point`，**未校验**它们等于 `fold_steps.last().r_y` 和 `fold_steps.last().z_at_r_y`。

**根因分析**：

* `proof.r_y` / `proof.z_at_point` 是 proof 中的独立冗余字段（= `fold_steps.last().r_y` / `.z_at_r_y`）

* 合法 prover 中二者相等（fold\_loop.rs L256-257），但 verifier 未强制此不变量

* sumcheck::verify 验证 `z'(step.r_y) = step.z_at_r_y`（使用 fold\_step 内的字段）

* PCS verify 验证 `z'(proof.r_y) = proof.z_at_point`（使用 proof 顶层字段）

* IPA verify 会 absorb `proof.r_y` 到 transcript（ipa.rs L392），但攻击者知道 `proof.r_y` 和 commitment 的 witness，可重新生成有效 IPA proof

**攻击路径**：

1. 攻击者选择一个白名单 CCS，构造任意 `initial_lcccs`（trace\_l 无需满足 CCS）
2. 对同一 CCS 运行合法 fold（使用满足约束的 witness w\_sat）→ 获得有效 sumcheck proof、r\_y\_sat、z\_at\_r\_y\_sat
3. 选择任意 w\_L、w\_C，计算 w' = w\_L + r·w\_C，承诺 C' = C\_L + r·C\_C
4. 设置 `step.sumcheck_proof` = 合法 proof，`step.r_y` = r\_y\_sat，`step.z_at_r_y` = z\_at\_r\_y\_sat
5. 线性 fold 方程可满足（攻击者自由选择 `folded_lcccs` 字段）
6. fold commitment 等式可满足（C' = C\_L + r·C\_C 是 EC 点加法）
7. PCS：设置 `proof.r_y` = r\_y\_new（≠ r\_y\_sat），`proof.z_at_point` = w'(r\_y\_new)，`proof.pcs_opening` = C' 在 r\_y\_new 处的有效 IPA opening

**结果**：verifier 接受 proof，但：

* sumcheck 验证的是 w\_sat（满足 CCS）

* PCS 验证的是 w'（不满足 CCS）

* 二者完全解耦，攻击者无需运行任何真实程序

**修复**：在 PCS opening 验证前添加一致性校验：

```rust
let last_step = proof.fold_steps.last().ok_or_else(|| {
    ZkvmError::InvalidZkProofFormat("fold_steps 为空：无法链接 PCS opening".to_string())
})?;
if proof.r_y != last_step.r_y {
    return Err(ZkvmError::Other(
        "PCS opening 解耦攻击：proof.r_y != fold_steps.last().r_y".to_string(),
    ));
}
if proof.z_at_point != last_step.z_at_r_y {
    return Err(ZkvmError::Other(
        "PCS opening 解耦攻击：proof.z_at_point != fold_steps.last().z_at_r_y".to_string(),
    ));
}
```

#### Finding B — CRITICAL：空 fold\_steps 未被拒绝

**位置**：`src/verifier.rs` L135（`for step in &proof.fold_steps` 循环）

**问题**：若 `proof.fold_steps` 为空，循环不执行，`last_sumcheck_transcript` 保持 `None`，PCS opening 使用 `Transcript::default()`（fresh）。

**攻击路径**：恶意 prover 构造空 fold\_steps 的 proof，仅需提供 `initial_witness_commitment` 的有效 IPA opening（prover 知道 witness），完全绕过所有 fold/sumcheck 验证。CCS 满足性零验证。

**修复**：Finding A 的修复中 `fold_steps.last()` 的 `ok_or_else` 已覆盖此情况（空 fold\_steps → 返回错误）。

#### Finding C — MINOR：ccs\_commitment 一致性未显式校验

**位置**：`src/verifier.rs` L90, L137

**问题**：

* verifier 用 `proof.ccs_commitment`（顶层字段）做 fold transcript absorb（L137）

* verifier 用 `proof.initial_lcccs.ccs_ref`（L90）做 `compute_v_at` 和 `sumcheck::verify`

* 未显式校验 `proof.ccs_commitment == proof.initial_lcccs.ccs_ref.ccs_commitment()`

* 未显式校验所有 `step.folded_lcccs.ccs_ref == initial_lcccs.ccs_ref`

**当前状态**：间接被 fold 方程 + sumcheck 捕获（CCS 不匹配 → sumcheck 失败），但缺乏防御深度。

**修复**：在 step 4（重建 IpaPcs）后添加显式校验：

```rust
let initial_ccs_commit = ccs.ccs_commitment();
if proof.ccs_commitment != initial_ccs_commit {
    return Err(ZkvmError::Other(
        "ccs_commitment 不匹配：proof.ccs_commitment != initial_lcccs.ccs_ref.ccs_commitment()".to_string(),
    ));
}
```

## Proposed Changes

### Step 1: 修复 Finding A + B（PCS-sumcheck 绑定 + 拒绝空 fold\_steps）

**文件**：`poker_zkvm/src/verifier.rs`

在 L253（batch 连续性校验之后、PCS opening 验证之前）插入：

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

### Step 3: 新增 `default_ccs_whitelist()` 到 test\_helpers

**文件**：`poker_zkvm/src/test_helpers.rs`

在文件末尾（测试模块之前）新增：

```rust
/// 构造默认 CCS 白名单（从 `generate_test_proof` 提取 ccs_commitment）。
///
/// 仅供测试和基准测试使用。生产环境应由链上治理配置白名单。
#[cfg(any(test, feature = "test-helpers"))]
pub fn default_ccs_whitelist() -> Vec<[u8; 32]> {
    let (proof_bytes, _) = crate::prover::generate_test_proof();
    let proof = crate::prover::deserialize_proof(&proof_bytes)
        .expect("deserialize generate_test_proof 应成功");
    vec![proof.ccs_commitment]
}
```

**注**：需确认 `deserialize_proof` 为 `pub`。若为 `pub(crate)`，需提升为 `pub`（在 `prover/mod.rs` 中）。

### Step 4: 更新 `fold_loop.rs` 测试

**文件**：`poker_zkvm/src/fold/fold_loop.rs`

#### 4.1 所有 `fold_loop` 调用补 3 个新参数

所有形如：

```rust
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript)
```

改为：

```rust
fold_loop(&ccs, lcccs, cmt, &[ccccs], &pcs, &mut transcript,
          ccs.ccs_commitment(), [0u8; 32], vec![vec![]])
```

涉及行号（\~15 处）：L424, L458, L497, L528, L563, L590, L613, L649, L679, L712, L740, L769, L798, L829, L884, L913, L941, L988

#### 4.2 替换旧字段引用

| 旧引用                             | 新引用                                                          |
| ------------------------------- | ------------------------------------------------------------ |
| `proof.folded_instance.u_l`     | `proof.fold_steps.last().unwrap().folded_lcccs.u_l`          |
| `proof.folded_instance.trace_l` | `proof.fold_steps.last().unwrap().folded_lcccs.trace_l`      |
| `proof.folded_instance.ccs_ref` | `proof.fold_steps.last().unwrap().folded_lcccs.ccs_ref`      |
| `proof.folded_instance.r_x_l`   | `proof.fold_steps.last().unwrap().folded_lcccs.r_x_l`        |
| `proof.witness_commitment`      | `proof.fold_steps.last().unwrap().folded_witness_commitment` |

赋值场景（L751）：`proof.folded_instance.u_l = f(99)` → `proof.fold_steps.last_mut().unwrap().folded_lcccs.u_l = f(99)`

涉及行号：L438, L440, L471, L508, L539, L575, L751, L895, L924, L953, L959, L960, L961, L1003

### Step 5: 更新外部调用方（`verify_production` 3 参数签名）

#### 5.1 `poker_l1/src/offline/hypernova.rs:209`

```rust
// 旧
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io) {
// 新
let ccs_whitelist = poker_zkvm::test_helpers::default_ccs_whitelist();
match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_whitelist) {
```

**决策**：MVP 阶段 poker\_l1 使用 `default_ccs_whitelist()`（从 `generate_test_proof` 提取）。生产环境应由链上治理配置白名单（未来工作）。

**前提**：poker\_l1 的 Cargo.toml 须启用 poker\_zkvm 的 `test-helpers` feature。需检查 poker\_l1 是否已启用；若未启用，需添加 `poker_zkvm = { path = "../poker_zkvm", features = ["test-helpers"] }`。

**注**：`default_ccs_whitelist` 名为 "test helpers" 但 MVP 生产调用方也使用。这是 MVP 权宜之计，生产环境需替换为治理配置。在函数 doc 中已标注此限制。

#### 5.2 `poker_zkvm/tests/soundness_tests.rs`（4 处）

```rust
// 旧
let result = verify_production(&proof_bytes, &public_io);
// 新
use poker_zkvm::test_helpers::default_ccs_whitelist;
let ccs_whitelist = default_ccs_whitelist();
let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
```

涉及行号：L73, L86, L306, L319

#### 5.3 `poker_zkvm/tests/e2e_fibonacci.rs:34`

```rust
// 旧
let ok = verify_production(&proof_bytes, &public_io)
// 新
let ccs_whitelist = poker_zkvm::test_helpers::default_ccs_whitelist();
let ok = verify_production(&proof_bytes, &public_io, &ccs_whitelist)
```

#### 5.4 `poker_zkvm/tests/e2e_sha256_chain.rs:48` — 同 5.3

#### 5.5 `poker_zkvm/tests/e2e_poker_hand_eval.rs:38` — 同 5.3

#### 5.6 `poker_zkvm/benches/phase12_benchmarks.rs:107`

```rust
// 旧
let ok = verify_production(black_box(&proof_bytes), black_box(&public_io))
// 新
let ccs_whitelist = poker_zkvm::test_helpers::default_ccs_whitelist();
let ok = verify_production(black_box(&proof_bytes), black_box(&public_io), black_box(&ccs_whitelist))
```

### Step 6: 新增 Finding A 回归测试

**文件**：`poker_zkvm/src/verifier.rs`（测试模块末尾）

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

### Step 7: 确认 `deserialize_proof` / `serialize_proof` 可见性

**文件**：`poker_zkvm/src/prover/mod.rs`

确认 `serialize_proof` 和 `deserialize_proof` 为 `pub`（供 test\_helpers 和 verifier 测试使用）。

* `serialize_proof` 当前应为 `pub(crate)` 或 `pub` — verifier.rs 测试已使用 `crate::prover::serialize_proof`

* `deserialize_proof` 当前为 `pub`（verifier.rs L27 `use crate::prover::{deserialize_proof, ...}`）

* `test_helpers::default_ccs_whitelist` 需跨 crate 访问 `deserialize_proof` → 须为 `pub`

若为 `pub(crate)`，改为 `pub`。

## Assumptions & Decisions

1. **CCS 白名单来源**：verifier 不内建白名单，由调用方传入。MVP 阶段通过 `test_helpers::default_ccs_whitelist()` 构造（从 `generate_test_proof` 提取）。生产环境应由链上治理配置。`default_ccs_whitelist` 虽在 `test_helpers` 模块，但 MVP 生产调用方（poker\_l1）也使用此函数 — 这是 MVP 权宜之计，函数 doc 已标注。

2. **poker\_l1 feature 依赖**：poker\_l1 需启用 poker\_zkvm 的 `test-helpers` feature 才能访问 `default_ccs_whitelist`。需检查并可能更新 poker\_l1 的 Cargo.toml。若不想在生产依赖 test-helpers feature，可将 `default_ccs_whitelist` 移至 `prover` 模块并改为 `pub`（无 feature 门控）。

3. **Finding A 修复不改变 proof 格式**：仅添加 verifier 端校验，proof 结构和序列化不变（`proof.r_y` / `proof.z_at_point` 字段保留，verifier 现在强制它们等于 `fold_steps.last()` 对应字段）。

4. **不修改 fold\_step.rs / sumcheck.rs / lcccs.rs / ccccs.rs / ipa.rs**：协议逻辑不变，仅 verifier 侧增加校验。

5. **fold\_loop.rs 测试参数**：测试场景中 `public_io_commitment` 用 `[0u8;32]`，`batch_public_inputs` 用 `vec![vec![]]`（fold\_loop 内不校验这些，仅存入 proof）。

## Verification Steps

1. **poker\_zkvm 编译**：`cargo build --all-features -p poker_zkvm`
2. **poker\_zkvm 单元测试**：`cargo test --all-features -p poker_zkvm`

   * 所有 fold\_loop 测试更新通过

   * verifier 新增 8 个安全测试通过（6 原有 + 2 新增 Finding A/B）
3. **poker\_zkvm Clippy**：`cargo clippy --all-features -p poker_zkvm -- -D warnings`
4. **poker\_l1 编译**：`cargo build --all-features -p poker_l1`
5. **poker\_l1 测试**：`cargo test --all-features -p poker_l1`
6. **E2E 测试**：`cargo test --all-features -p poker_zkvm --test e2e_fibonacci --test e2e_sha256_chain --test e2e_poker_hand_eval`
7. **Soundness 测试**：`cargo test --all-features -p poker_zkvm --test soundness_tests`
8. **基准测试编译**：`cargo build --benches --all-features -p poker_zkvm`

## 关键文件变更清单

| 文件                                         | 变更类型                                                  |
| ------------------------------------------ | ----------------------------------------------------- |
| `poker_zkvm/src/verifier.rs`               | Finding A/B/C 修复 + 2 个新测试                             |
| `poker_zkvm/src/test_helpers.rs`           | 新增 `default_ccs_whitelist()`                          |
| `poker_zkvm/src/prover/mod.rs`             | 确认 `serialize_proof`/`deserialize_proof` 为 `pub`（若需要） |
| `poker_zkvm/src/fold/fold_loop.rs`         | 测试适配新签名 + 新字段引用                                       |
| `poker_l1/src/offline/hypernova.rs`        | `verify_production` 3 参数适配                            |
| `poker_l1/Cargo.toml`                      | 启用 poker\_zkvm `test-helpers` feature（若未启用）           |
| `poker_zkvm/tests/soundness_tests.rs`      | 4 处 `verify_production` 3 参数适配                        |
| `poker_zkvm/tests/e2e_fibonacci.rs`        | `verify_production` 3 参数适配                            |
| `poker_zkvm/tests/e2e_sha256_chain.rs`     | `verify_production` 3 参数适配                            |
| `poker_zkvm/tests/e2e_poker_hand_eval.rs`  | `verify_production` 3 参数适配                            |
| `poker_zkvm/benches/phase12_benchmarks.rs` | `verify_production` 3 参数适配                            |

