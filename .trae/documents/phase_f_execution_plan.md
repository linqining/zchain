# Phase F 执行计划 — Groth16 真实 SNARK 压缩（更新版）

## 摘要

Phase F 目标：将 `groth16_compress` 从返回 `CompressedProof::Native`（仅原生约束验证）升级为返回 `CompressedProof::Groth16`（真实 Groth16 SNARK proof）。

当前状态：F-1 代码已写入但存在编译问题，F-2 到 F-5 未开始。本计划基于当前代码实际状态重新拆分执行步骤。

---

## 当前状态分析

### 已完成（代码已写入，待编译验证）

1. **`poker_zkvm/src/recursion/r1cs_gadgets_bn254.rs`** — 完全重写
   - 自定义 `G1VarBN254` 结构体（放弃 `ProjectiveVar` 因 trait 约束不兼容）
   - `FqVarEmulated = EmulatedFpVar<Fq, Fr>`、`FrVar = FpVar<Fr>` 类型别名
   - `point_double`、`add_incomplete`、`safe_add`、`scalar_mul_gadget_bn254`、`point_add_gadget_bn254`、`fold_commitment_check_bn254`
   - 6 个单元测试

2. **`poker_zkvm/src/recursion/hypernova_verifier_circuit.rs:L236-L359`** — `HypernovaVerifierCircuitBN254`
   - 实现 `ConstraintSynthesizer<Fr>`
   - `verify_native()` 方法
   - `public_inputs_to_fr()` 方法（F-1 核心，通过 `instance_assignment()` 提取公共输入）

3. **`poker_zkvm/src/recursion/mod.rs:L25`** — 模块声明已存在

### 已识别的编译问题（必须修复）

**问题 1：`Namespace` 未导入**
- **文件**：`r1cs_gadgets_bn254.rs:L72, L86`
- **症状**：`new_input` 和 `new_witness` 签名使用 `impl Into<Namespace<Fr>>`，但 `Namespace` 未导入
- **根因**：`ark_r1cs_std::prelude::*` 不导出 `Namespace`（见 `ark-r1cs-std-0.6.0/src/lib.rs:L100-L117`）；`Namespace` 定义在 `ark_relations::gr1cs::namespace`，通过 `ark_relations::gr1cs::Namespace` 访问（见 `ark-relations-0.6.0/src/gr1cs/mod.rs:L47`）
- **修复**：将 `use ark_relations::gr1cs::SynthesisError;` 改为 `use ark_relations::gr1cs::{Namespace, SynthesisError};`

**问题 2（潜在）：`CompressedProof::Groth16` 变体类型不匹配**
- **文件**：`groth16_compress.rs:L104`
- **当前**：`Groth16(Groth16Proof)` — 仅携带 proof，无 VK 和 public_inputs
- **需要**：改为 `Groth16(Groth16CompressedProof)` 携带 proof + VK + public_inputs + fold_step_count
- **影响**：`recursion/mod.rs:L76` 注释已预期 `CompressedProof::Groth16 含 Proof<Bn254> ~256B`，但实际 `Groth16CompressedProof` 会更大（VK ~1KB）

### 待完成（本计划范围）

- [ ] 修复 `r1cs_gadgets_bn254.rs` 的 `Namespace` 导入
- [ ] 编译验证 F-1 代码（`cargo check`）
- [ ] F-2: 扩展 `CompressedProof::Groth16` 变体 + 改造 `groth16_compress`
- [ ] F-3: 新增 `groth16_compress_verify`
- [ ] F-4: 确认 `tree_aggregate_recursive` 兼容性 + 更新测试断言
- [ ] F-5: 测试更新 + 全量回归

---

## 子任务详细设计

### F-1-fix: 修复 Namespace 导入 + 编译验证

**文件**：`poker_zkvm/src/recursion/r1cs_gadgets_bn254.rs`

**改动**：
```rust
// 原 L38:
use ark_relations::gr1cs::SynthesisError;
// 改为:
use ark_relations::gr1cs::{Namespace, SynthesisError};
```

**验证点**：
- `cargo check -p poker_zkvm` 编译通过
- `cargo test -p poker_zkvm --lib r1cs_gadgets_bn254` 6 个测试全绿
- `cargo test -p poker_zkvm --lib hypernova_verifier_circuit` 既有测试无回归

**风险**：编译可能暴露其他问题（如 `EmulatedFpVar` 方法签名不匹配）。若出现，逐个修复。

---

### F-2: 扩展 CompressedProof::Groth16 + 改造 groth16_compress

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

**改动 1：新增 `Groth16CompressedProof` 结构体**（在 `CompressedProof` enum 之前）

```rust
/// Groth16 压缩 proof — 含 proof + VK + 公共输入。
#[derive(Debug, Clone)]
pub struct Groth16CompressedProof {
    /// Groth16 SNARK proof（~200 字节）
    pub proof: Groth16Proof,
    /// Verifying key（setup 时生成，~1KB）
    pub verifying_key: Groth16VerifyingKey,
    /// 公共输入 Fr 值（initial + final commitment 的 limb 表示）
    pub public_inputs: Vec<Fr>,
    /// fold 步数（元数据）
    pub fold_step_count: usize,
}
```

**改动 2：更新 `CompressedProof` enum**（L98-L105）

```rust
#[derive(Debug, Clone)]
pub enum CompressedProof {
    Native(NativeCompressedProof),
    Groth16(Groth16CompressedProof),  // 原: Groth16(Groth16Proof)
}
```

**改动 3：改造 `groth16_compress` 函数**（L135-L164）

```rust
pub fn groth16_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        extract_fold_chain, HypernovaVerifierCircuitBN254,
    };

    // 1. 提取 fold chain
    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;

    // 2. 构造 Fr-based 电路
    let circuit = HypernovaVerifierCircuitBN254 {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };

    // 3. 原生约束满足性验证（前置检查，快速失败）
    let satisfied = circuit.verify_native()?;
    if !satisfied {
        return Err(ZkvmError::Other(
            "groth16_compress: fold commitment 链验证失败(约束不满足)".to_string(),
        ));
    }

    // 4. 提取公共输入 Fr 表示
    let public_inputs = circuit.public_inputs_to_fr()?;

    // 5. Groth16 setup + prove
    let (pk, vk) = groth16_setup(circuit.clone())?;
    let groth16_proof = groth16_prove(&pk, circuit)?;

    // 6. 返回 Groth16 压缩 proof
    Ok(CompressedProof::Groth16(Groth16CompressedProof {
        proof: groth16_proof,
        verifying_key: vk,
        public_inputs,
        fold_step_count: proof.fold_steps.len(),
    }))
}
```

**验证点**：
- `cargo check -p poker_zkvm` 编译通过
- `CompressedProof::Groth16` 变体携带完整验证所需数据

**注意**：`groth16_setup` 和 `groth16_prove` 对非原生约束电路（`EmulatedFpVar`）可能很慢。先用单步 fold 测试。

---

### F-3: 新增 groth16_compress_verify

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

**改动**：新增验证函数

```rust
/// 验证 Groth16 压缩 proof。
pub fn groth16_compress_verify(compressed: &CompressedProof) -> Result<bool, ZkvmError> {
    match compressed {
        CompressedProof::Native(_) => {
            // Native 模式：约束已由 groth16_compress 内部 verify_native 验证
            Ok(true)
        }
        CompressedProof::Groth16(groth16) => {
            groth16_verify(
                &groth16.verifying_key,
                &groth16.public_inputs,
                &groth16.proof,
            )
        }
    }
}
```

**验证点**：
- 合法 proof → `groth16_compress_verify` 返回 `true`
- 篡改 public_inputs → 返回 `false`

---

### F-4: tree_aggregate 集成 + 测试断言更新

**文件**：`poker_zkvm/src/recursion/mod.rs`

**改动 1：确认 `tree_aggregate_recursive` 兼容性**
- `L292`: `groth16_compress(&aggregated_proof).ok().map(Box::new)` — 调用点无需改动
- `CycleFoldNode::Node.compressed_proof` 类型为 `Option<Box<CompressedProof>>` — 兼容新变体

**改动 2：更新测试断言**（L684-L760）

`test_compressed_proof_in_internal_node`（L684-L702）：
```rust
// 原: 断言 Native 变体
match compressed {
    CompressedProof::Native(native) => { assert_eq!(native.fold_step_count, 1, ...); }
    CompressedProof::Groth16(_) => { panic!("Phase D 应返回 Native 变体"); }
}
// 改为: 断言 Groth16 变体
match compressed {
    CompressedProof::Groth16(groth16) => {
        assert_eq!(groth16.fold_step_count, 1, "fold_step_count 应 = 1");
        assert!(groth16_compress_verify(compressed).unwrap(), "Groth16 proof 应验证通过");
    }
    CompressedProof::Native(_) => { panic!("Phase F 应返回 Groth16 变体"); }
}
```

`test_compressed_proof_matches_direct_call`（L704-L733）：
```rust
// 原: 匹配双方均为 Native
// 改为: 匹配双方均为 Groth16，比较 fold_step_count 和 public_inputs
```

**验证点**：
- `cargo test -p poker_zkvm --lib recursion::tests::test_compressed_proof` 全绿
- 端到端：`groth16_compress` → `groth16_compress_verify` 闭环

---

### F-5: 测试更新 + 全量回归

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`（测试模块）

**改动 1：更新 `test_groth16_compress_valid_proof`**（L224-L315）
- 断言返回 `CompressedProof::Groth16(_)`
- 调用 `groth16_compress_verify` 验证闭环
- 断言 `fold_step_count == 1`

**改动 2：更新 `test_groth16_compress_tampered_commitment`**（L317-L401）
- 篡改 commitment → `groth16_compress` 返回错误（约束不满足，在 `verify_native` 阶段失败）

**改动 3：新增测试**
- `test_groth16_compress_verify_e2e` — 完整闭环：compress → verify → true
- `test_groth16_compress_tampered_public_input` — 篡改 public_inputs → verify → false
- `test_groth16_compress_proof_size` — 断言 Groth16 proof 序列化大小 < 1KB

**验证点**：
```bash
cargo test -p poker_zkvm --lib groth16 -- --nocapture
cargo test -p poker_zkvm --lib recursion -- --nocapture
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo test -p poker_zkvm --test e2e_poker_hand_eval
cargo test -p poker_zkvm --test soundness
cargo clippy -p poker_zkvm -- -D warnings
```

---

## 关键设计决策

### D-F-1: 公共输入提取方案
- **选择**：`ConstraintSystem::instance_assignment()`
- **理由**：简单、保证与电路 allocation 完全一致
- **API**：`ark-relations-0.6.0/src/gr1cs/constraint_system_ref.rs:L107-L111` 返回 `Vec<F>`

### D-F-2: CompressedProof::Groth16 携带 VK
- **选择**：`Groth16CompressedProof` 结构体含 `verifying_key` + `public_inputs`
- **理由**：`groth16_verify` 需要 VK 和 public_inputs；携带在 proof 中使 `groth16_compress_verify` 无需额外参数

### D-F-3: Native 验证作为前置检查
- **选择**：`groth16_compress` 先 `verify_native()`，通过后再 `groth16_setup + prove`
- **理由**：Native 验证快速失败，避免浪费 setup/prove 时间

### D-F-4: 保留 CompressedProof::Native 变体
- **选择**：保留 `Native` 变体（不删除）
- **理由**：向后兼容；未来可能用于 fallback 场景（Groth16 setup 失败时降级）

---

## 假设与前提

1. `ark-groth16 0.6.0` 的 `generate_random_parameters_with_reduction` 接受 `ConstraintSynthesizer<Fr>` — 已由现有 `TestCircuit` 测试验证
2. `HypernovaVerifierCircuitBN254::generate_constraints` 能正确分配所有变量 — 已由 Fq-based 版本的 8 个测试间接验证
3. Groth16 setup/prove 对 `EmulatedFpVar` 约束电路可行，但可能较慢（~700k 约束/步）— 先用单步 fold 测试
4. `CompressedProof::Groth16` 的 `Clone` 派生需 `Groth16CompressedProof` 实现 `Clone` — `Proof<Bn254>`、`VerifyingKey<Bn254>`、`Vec<Fr>` 均 `Clone`

---

## 执行顺序

```
F-1-fix (修复 Namespace 导入 + 编译验证)
  └─> F-2 (扩展 CompressedProof::Groth16 + 改造 groth16_compress)
        └─> F-3 (新增 groth16_compress_verify)
              └─> F-4 (tree_aggregate 测试断言更新)
                    └─> F-5 (测试更新 + 全量回归)
```

每个子任务完成后立即 `cargo check`，F-5 做全量回归。

---

## 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| `EmulatedFpVar` 约束数过大导致 Groth16 setup OOM | 中 | 阻塞 | 先用单步 fold；若失败考虑减少 limb 数 |
| `groth16_setup` 对 `EmulatedFpVar` 不兼容 | 低 | 阻塞 | `TestCircuit` 已验证基本流程；`EmulatedFpVar` 是标准 ark-r1cs-std 组件 |
| `instance_assignment()` 在 setup 模式返回空 | 低 | 阻塞 | 已确认 API 检查 `is_in_setup_mode()`，非 setup 模式正常返回 |
| Groth16 proof 序列化 > 1KB | 低 | 性能 | BN254 Groth16 proof = 3 G1/G2 元素 ≈ 200-300 字节 |
| 既有测试硬编码 `Native` 断言导致回归 | 高 | 测试失败 | F-4/F-5 系统性更新所有断言 |

---

## 后续阶段（Phase F 完成后）

- **Phase G**: LogUp 内存一致性
- **Phase H**: ECDSA 256-bit 标量
- **Phase I**: 预编译补齐
- **Phase J**: zkshuffle 真实电路
- **Phase K**: RV32IM M 扩展
- **Phase L**: Gas 模型 + STARK fallback + 形式化验证
