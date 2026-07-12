# Phase F 完成计划 — Groth16 真实 SNARK 压缩

## 摘要

Phase F 当前阻塞于公共输入提取问题。探索确认 `ark-relations 0.6.0` 的 `ConstraintSystem::instance_assignment()` 可提取所有 public input 的 `Fr` 值，解决了 `G1VarBN254::new_input`（`EmulatedFpVar<Fq, Fr>`）分解为多个 Fr limb 后如何传递给 `groth16_verify` 的问题。

本计划将 Phase F 剩余工作拆分为 5 个顺序子任务（F-1 ~ F-5），每个子任务有明确的文件改动、验证点和回归检查。

---

## 当前状态分析

### 已完成
- [x] `poker_zkvm/src/recursion/r1cs_gadgets_bn254.rs` — Fr-based gadget 库完整实现
  - `G1VarBN254`、`FqVarEmulated`、`FrVar` 类型别名
  - `point_add_gadget_bn254`、`scalar_mul_gadget_bn254`、`fold_commitment_check_bn254`
  - 4 个单元测试（scalar_mul_identity、scalar_mul_generator、fold_valid、fold_invalid）
- [x] `poker_zkvm/src/recursion/hypernova_verifier_circuit.rs:L236-L339` — `HypernovaVerifierCircuitBN254`
  - 实现 `ConstraintSynthesizer<Fr>`
  - 使用 `G1VarBN254::new_input` 分配公共输入
  - 复用 `fold_commitment_check_bn254` 生成约束
- [x] `poker_zkvm/src/recursion/mod.rs:L25` — 模块声明 `pub mod r1cs_gadgets_bn254;`

### 待完成（本计划范围）
- [ ] `groth16_compress` 改用 `HypernovaVerifierCircuitBN254`，返回 `CompressedProof::Groth16`
- [ ] 新增 `groth16_compress_verify` 端到端验证入口
- [ ] 集成到 `tree_aggregate_recursive`
- [ ] 测试更新 + 回归验证

### 核心阻塞点已解决

**问题**：`HypernovaVerifierCircuitBN254` 用 `G1VarBN254::new_input` 分配 G1 点作为公共输入。这通过 `EmulatedFpVar<Fq, Fr>` 分解为多个 Fr limb（见 `ark-r1cs-std-0.6.0/src/fields/emulated_fp/allocated_field_var.rs:L543-L572`）。`groth16_verify(vk, public_inputs: &[Fr], proof)` 需要 flat `&[Fr]` 切片。

**解决方案**（已验证 API 可用）：
- `ark-relations-0.6.0/src/gr1cs/constraint_system_ref.rs:L107-L111`：
  ```rust
  pub fn instance_assignment(&self) -> crate::gr1cs::Result<Vec<F>> {
      self.inner()
          .ok_or(SynthesisError::AssignmentMissing)
          .and_then(|cs| cs.borrow().instance_assignment().map(|v| v.to_vec()))
  }
  ```
- 流程：构造 CS → `generate_constraints` → `cs.instance_assignment()` → 得到 `Vec<Fr>`

**备选方案**（更高效但脆弱）：
- `AllocatedEmulatedFpVar::<Fq, Fr>::get_limbs_representations(&fq_elem, optimization_type)` 是 public API（`allocated_field_var.rs:L309-L314`），可直接计算 limb 值
- 风险：需匹配 `ShortWeierstrassProjectiveVar` 内部 allocation 顺序（x, y 坐标）

**决策**：采用主方案（`instance_assignment`），因其简单且保证与电路 allocation 完全一致。

---

## 子任务详细设计

### F-1: 公共输入提取 helper

**文件**：`poker_zkvm/src/recursion/hypernova_verifier_circuit.rs`

**改动**：在 `HypernovaVerifierCircuitBN254` impl 块新增方法

```rust
impl HypernovaVerifierCircuitBN254 {
    /// 提取公共输入的 Fr 表示（用于 groth16_verify）。
    ///
    /// 构造临时 ConstraintSystem<Fr>，运行 generate_constraints，
    /// 通过 instance_assignment() 提取所有 public input 的 Fr 值。
    ///
    /// 返回的 Vec<Fr> 顺序与 G1VarBN254::new_input 的 allocation 顺序一致：
    /// [initial_commitment_limbs..., final_commitment_limbs...]
    pub fn public_inputs_to_fr(&self) -> Result<Vec<Fr>, ZkvmError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone())
            .map_err(|e| ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: generate_constraints for public inputs failed: {e}"
            )))?;
        cs.instance_assignment()
            .map_err(|e| ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: instance_assignment failed: {e}"
            )))
    }
}
```

**验证点**：
- 编译通过
- 单元测试：构造合法 circuit，调用 `public_inputs_to_fr()`，断言返回非空 `Vec<Fr>`
- 长度一致性：相同 fold_steps 数量下，`public_inputs_to_fr()` 长度固定

---

### F-2: groth16_compress 改用 BN254 电路

**文件**：`poker_zkvm/src/prover/groth16_compress.rs:L135-L164`

**改动**：将 `groth16_compress` 从 Fq-based `HypernovaVerifierCircuit` 切换到 Fr-based `HypernovaVerifierCircuitBN254`，Native 验证通过后调用 `groth16_setup` + `groth16_prove`。

```rust
pub fn groth16_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        extract_fold_chain, HypernovaVerifierCircuitBN254,
    };

    // 1. 从 HypernovaProof 提取 fold chain
    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;

    // 2. 构造 Fr-based 电路
    let circuit = HypernovaVerifierCircuitBN254 {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };

    // 3. 原生约束满足性验证（前置检查）
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

    // 6. 返回 Groth16 压缩 proof（含 VK 供后续验证）
    Ok(CompressedProof::Groth16(Groth16CompressedProof {
        proof: groth16_proof,
        verifying_key: vk,
        public_inputs,
        fold_step_count: proof.fold_steps.len(),
    }))
}
```

**注意**：`CompressedProof::Groth16` 变体需扩展，携带 VK + public_inputs（供 verify 使用）。需同步更新 `CompressedProof` enum 定义（L98-L105）。

**新增结构**（在 `groth16_compress.rs`）：
```rust
/// Groth16 压缩 proof — 含 proof + VK + 公共输入。
#[derive(Debug, Clone)]
pub struct Groth16CompressedProof {
    /// Groth16 SNARK proof（~200 字节）
    pub proof: Groth16Proof,
    /// Verifying key（setup 时生成）
    pub verifying_key: Groth16VerifyingKey,
    /// 公共输入 Fr 值（initial + final commitment 的 limb 表示）
    pub public_inputs: Vec<Fr>,
    /// fold 步数（元数据）
    pub fold_step_count: usize,
}
```

**验证点**：
- 编译通过
- `CompressedProof::Groth16` 变体携带完整验证所需数据

---

### F-3: groth16_compress_verify 端到端验证入口

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

**改动**：新增验证函数

```rust
/// 验证 Groth16 压缩 proof。
///
/// 从 CompressedProof::Groth16 提取 proof + VK + public_inputs，
/// 调用 groth16_verify 进行 SNARK 验证。
pub fn groth16_compress_verify(compressed: &CompressedProof) -> Result<bool, ZkvmError> {
    match compressed {
        CompressedProof::Native(native) => {
            // Native 模式：无 SNARK proof，仅检查公共输入存在
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

### F-4: 集成到 tree_aggregate_recursive

**文件**：`poker_zkvm/src/recursion/mod.rs:L286-L299`

**改动**：`tree_aggregate_recursive` 中的 `compressed_proof` 已调用 `groth16_compress`，无需改动调用点。但需确认 `CycleFoldNode` 的 `compressed_proof` 字段类型兼容 `CompressedProof::Groth16`。

**检查项**：
- `CycleFoldNode` 枚举的 `compressed_proof` 字段类型为 `Option<Box<CompressedProof>>`（应已兼容）
- 测试 `test_tree_aggregate_compressed_proof`（L694-L732）需更新断言

**验证点**：
- `tree_aggregate_recursive` 调用后，节点 `compressed_proof` 为 `Some(CompressedProof::Groth16(_))`
- 端到端：`groth16_compress` → `groth16_compress_verify` 闭环

---

### F-5: 测试更新 + 回归验证

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`（测试模块）

**改动**：

1. **更新 `test_groth16_compress_valid_proof`**（L224-L315）：
   - 断言返回 `CompressedProof::Groth16(_)`（而非 `Native`）
   - 调用 `groth16_compress_verify` 验证闭环

2. **更新 `test_groth16_compress_tampered_commitment`**（L317+）：
   - 篡改 commitment → `groth16_compress` 返回错误（约束不满足）

3. **新增测试**：
   - `test_groth16_compress_verify_e2e` — 完整闭环：compress → verify → true
   - `test_groth16_compress_tampered_public_input` — 篡改 public_inputs → verify → false
   - `test_groth16_compress_proof_size` — 断言 Groth16 proof 序列化大小 < 1KB

4. **更新 `recursion/mod.rs` 测试**（L694-L732）：
   - `test_tree_aggregate_compressed_proof` 断言 `CompressedProof::Groth16`

**验证点**：
- `cargo test -p poker_zkvm --lib groth16` 全绿
- `cargo test -p poker_zkvm --lib recursion` 全绿
- `cargo test -p poker_zkvm --lib` 全量回归无破坏
- `cargo clippy -p poker_zkvm -- -D warnings` 无新警告

---

## 关键设计决策

### D-F-1: 公共输入提取方案
- **选择**：`ConstraintSystem::instance_assignment()`（主方案）
- **理由**：简单、保证与电路 allocation 完全一致
- **代价**：需运行 `generate_constraints` 两次（一次提取 public_inputs，一次在 `groth16_prove` 内部）
- **未选方案**：`get_limbs_representations` 直接计算（更高效但需匹配 `ShortWeierstrassProjectiveVar` 内部 allocation 顺序，脆弱）

### D-F-2: CompressedProof::Groth16 携带 VK
- **选择**：`Groth16CompressedProof` 结构体含 `verifying_key` + `public_inputs`
- **理由**：`groth16_verify` 需要 VK 和 public_inputs；携带在 proof 中使 `groth16_compress_verify` 无需额外参数
- **代价**：VK 较大（~1KB），但 proof 总大小仍 < 2KB
- **替代方案**：VK 全局缓存（复杂，且不同 circuit 的 VK 不同）

### D-F-3: Native 验证作为前置检查
- **选择**：`groth16_compress` 先 `verify_native()`，通过后再 `groth16_setup + prove`
- **理由**：Native 验证快速失败（约束不满足时立即返回错误），避免浪费 setup/prove 时间
- **代价**：多一次 `generate_constraints` 调用

---

## 假设与前提

1. **ark-groth16 0.6.0 的 `generate_random_parameters_with_reduction`** 接受 `ConstraintSynthesizer<Fr>` — 已由现有 `TestCircuit` 测试验证（L196-L207）
2. **`HypernovaVerifierCircuitBN254::generate_constraints`** 在非 setup 模式下能正确分配所有变量 — 已由 gadget 测试间接验证
3. **`EmulatedFpVar` limb 数量** 对 Fq（254-bit）在 Fr（254-bit）中约为 2-3 limbs/坐标 — 不影响正确性，仅影响 public_inputs 长度
4. **Groth16 proof 序列化大小** BN254 Groth16 proof = 3 G1/G2 元素 ≈ 200-300 字节 — 符合 < 1KB 目标

---

## 验证步骤

### 编译验证
```bash
cd /Users/mac/projects/zchain && cargo build -p poker_zkvm
```

### 单元测试
```bash
cargo test -p poker_zkvm --lib groth16 -- --nocapture
cargo test -p poker_zkvm --lib recursion -- --nocapture
```

### 全量回归
```bash
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo test -p poker_zkvm --test e2e_poker_hand_eval
cargo test -p poker_zkvm --test soundness
```

### Clippy 检查
```bash
cargo clippy -p poker_zkvm -- -D warnings 2>&1 | grep -c "warning:"
# 预期：≤ 2（预存的 constraints 模块警告）
```

### 证明大小验证
```bash
cargo test -p poker_zkvm --lib test_groth16_compress_proof_size -- --nocapture
# 预期：proof 序列化 < 1024 字节
```

---

## 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| `instance_assignment()` 在 setup 模式返回空 | 低 | 阻塞 | 已确认 API 检查 `is_in_setup_mode()`，非 setup 模式正常返回 |
| `groth16_setup` 对 `EmulatedFpVar` 约束数过大 | 中 | prover 慢 | 先用 1-2 步 fold chain 测试；约束数估算 ~33k/步 |
| `HypernovaVerifierCircuitBN254` 的 `clone()` 成本 | 低 | 性能 | `fold_steps: Vec` clone 是浅拷贝，`G1Projective` 是 Copy-like |
| Groth16 trusted setup 用 `test_rng()` | 已知 | 安全 | 文档标注，生产需 ceremony（Phase L 处理）|

---

## 执行顺序

```
F-1 (public_inputs_to_fr helper)
  └─> F-2 (groth16_compress 改造)
        └─> F-3 (groth16_compress_verify)
              └─> F-4 (tree_aggregate 集成)
                    └─> F-5 (测试 + 回归)
```

每个子任务完成后立即编译验证，F-5 做全量回归。

---

## 后续阶段（简述）

Phase F 完成后，按已批准的 7 阶段计划继续：
- **Phase G**: LogUp 内存一致性（复用 `constraints/lookup.rs:L247-L371`）
- **Phase H**: ECDSA 256-bit 标量（分段标量分解）
- **Phase I**: 预编译补齐（6 项）
- **Phase J**: zk_shuffle 真实电路（探索 spike 先行）
- **Phase K**: RV32IM M 扩展（8 条指令）
- **Phase L**: Gas 模型 + STARK fallback + 形式化验证

详见 `/Users/mac/projects/zchain/.trae/documents/stage4_market_alignment_phases.md`。
