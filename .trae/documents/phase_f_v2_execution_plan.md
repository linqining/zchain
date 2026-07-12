# Phase F v2 执行计划 — Groth16 真实 SNARK 压缩

## 摘要

Phase F 目标：将 `groth16_compress` 从返回 `CompressedProof::Native` 升级为返回 `CompressedProof::Groth16`（真实 Groth16 SNARK proof，~200B）。

**v2 更新原因**：原计划 F-1-fix Step 2 提出使用 `Reducer::<Fq, Fr>::reduce()` 修复 `add_incomplete`，但调查发现 `Reducer` 位于 `pub(crate) mod reduce`（`ark-r1cs-std-0.6.0/src/fields/emulated_fp/mod.rs:L145-L147`），不可从外部 crate 访问。v2 改用 public API 复制 `Reducer::reduce()` 内部逻辑。

---

## 当前状态分析

### 已完成

1. **`r1cs_gadgets_bn254.rs`** — 自定义 `G1VarBN254`（`EmulatedFpVar<Fq, Fr>`）
   - `point_double`（正确，测试通过）
   - `add_incomplete`（**结果值不正确** — 核心阻塞）
   - `safe_add`、`safe_double`、`scalar_mul_gadget_bn254`、`fold_commitment_check_bn254`
   - 6 个单元测试：4 通过，2 失败（`test_g1_point_add_bn254`、`test_fold_commitment_check_valid_bn254`）

2. **`hypernova_verifier_circuit.rs:L236-L359`** — `HypernovaVerifierCircuitBN254` 实现 `ConstraintSynthesizer<Fr>`

3. **`groth16_compress.rs`** — Groth16 API 可用；`CompressedProof` enum 已有 `Groth16(Groth16Proof)` 变体（需扩展为携带 VK + public_inputs）

### 核心阻塞根因（v2 更新）

**原假设**：`sub_without_reduce` 后 limbs 溢出 Fr 范围导致 `value()` 错误。

**v2 修正分析**：
- `sub_without_reduce` 产生的 limbs 虽然非归一化（limb 值可能 ≈ `2^(surfeit + bits_per_limb)` 而非 `< 2^bits_per_limb`），但 `limbs_to_value` 的数学推导在 `mod Fq` 下成立，`value()` 应返回正确值
- **真正问题**：非归一化 limbs 传给 `mul_without_reduce` 时，`pre_mul_reduce` 可能跳过 reduction（因 `bits_per_mulresult_limb < Fr::MODULUS_BIT_SIZE - 3`），但 `mul_without_reduce` 的乘法实现可能假设操作数 limb < `2^bits_per_limb`，导致乘法 witness 计算错误
- `point_double` 正确是因为其 sub 链较短（surfeit 累积较小）；`add_incomplete` 的链式 sub（`h = u2 - u1`，`r = s2 - s1`，`x3 = (r_sq - h_cu) - two_u1_h_sq`）导致 surfeit 累积，传给后续 `mul` 时产生错误

**修复方向**：在关键 sub 操作后强制归一化 limbs，确保传给 `mul` 的操作数是 normal form。

---

## 子任务详细设计

### F-1-fix: 修复 add_incomplete witness 值错误

**文件**：`poker_zkvm/src/recursion/r1cs_gadgets_bn254.rs`

#### Step 1: 添加调试输出，精确定位错误源

在 `add_incomplete` 中为每个中间变量添加 `eprintln!`，在 `test_g1_point_add_bn254` 中同时输出 ark-ec 原生计算的预期值，定位**第一个**出错的中间变量。

```rust
fn add_incomplete(a: &G1VarBN254, b: &G1VarBN254) -> G1VarBN254 {
    let z2_sq = &b.z * &b.z;
    let u1 = &a.x * &z2_sq;
    let z1_sq = &a.z * &a.z;
    let u2 = &b.x * &z1_sq;
    eprintln!("DEBUG u1 = {:?}", u1.value().unwrap());
    eprintln!("DEBUG u2 = {:?}", u2.value().unwrap());
    // ... 每个中间变量都输出 ...
    let h = &u2 - &u1;
    eprintln!("DEBUG h = {:?}", h.value().unwrap());
    // ... 后续 ...
}
```

运行 `cargo test -p poker_zkvm --lib r1cs_gadgets_bn254::tests::test_g1_point_add_bn254 -- --nocapture 2>&1 | grep DEBUG`，对比预期值定位第一个出错点。

#### Step 2: 实现 `reduce_fq_var` 辅助函数（复制 Reducer::reduce 逻辑）

`Reducer::reduce()` 的内部实现（`reduce.rs:L113-L121`）是：创建 `new_witness`（值 = `elem.value()`，limbs 为 normal form）+ `conditional_enforce_equal`。我们用 public API 复制此逻辑：

```rust
use ark_r1cs_std::fields::emulated_fp::AllocatedEmulatedFpVar;

/// 强制归一化 EmulatedFpVar 的 limbs（复制 Reducer::reduce 逻辑，用 public API）。
///
/// 创建新 witness（值相同，limbs 为 normal form），用 `enforce_equal` 约束相等。
/// 后续运算使用归一化后的变量，避免 `mul_without_reduce` 在非归一化操作数上出错。
fn reduce_fq_var(v: &FqVarEmulated) -> Result<FqVarEmulated, SynthesisError> {
    match v {
        FqVarEmulated::Var(allocated) => {
            let cs = allocated.cs();
            let val = allocated.value()?;
            let new_var = AllocatedEmulatedFpVar::<Fq, Fr>::new_witness(
                ark_relations::ns!(cs, "normal_form"),
                || Ok(val),
            )?;
            // EqGadget::enforce_equal 是 public trait 方法
            FqVarEmulated::Var(allocated.clone()).enforce_equal(&FqVarEmulated::Var(new_var.clone()))?;
            Ok(FqVarEmulated::Var(new_var))
        }
        FqVarEmulated::Constant(c) => Ok(FqVarEmulated::Constant(*c)),
    }
}
```

**为什么可行**：
- `AllocatedEmulatedFpVar::new_witness` 是 `pub`（通过 `AllocVar` trait）
- `EmulatedFpVar` 的 `enforce_equal` 来自 `EqGadget` trait，是 public
- `new_witness` 内部调用 `get_limbs_representations` 生成归一化 limbs（每个 limb < `2^bits_per_limb`）
- `enforce_equal` 内部调用 `conditional_enforce_equal`（`AllocatedEmulatedFpVar` 上是 `pub(crate)`，但通过 `EmulatedFpVar` 的 `EqGadget` impl 可公开调用）

#### Step 3: 在 add_incomplete 关键位置调用 reduce_fq_var

将 `add_incomplete` 签名改为返回 `Result<G1VarBN254, SynthesisError>`，在 sub 操作后强制归一化：

```rust
fn add_incomplete(a: &G1VarBN254, b: &G1VarBN254) -> Result<G1VarBN254, SynthesisError> {
    let z2_sq = &b.z * &b.z;
    let u1 = &a.x * &z2_sq;
    let z1_sq = &a.z * &a.z;
    let u2 = &b.x * &z1_sq;
    let z2_cu = &z2_sq * &b.z;
    let s1 = &a.y * &z2_cu;
    let z1_cu = &z1_sq * &a.z;
    let s2 = &b.y * &z1_cu;

    // sub 后强制归一化，防止非归一化 limbs 传入 mul
    let h = reduce_fq_var(&(&u2 - &u1))?;
    let r = reduce_fq_var(&(&s2 - &s1))?;

    let h_sq = &h * &h;
    let h_cu = &h_sq * &h;
    let u1_h_sq = &u1 * &h_sq;
    let r_sq = &r * &r;
    let two_u1_h_sq = &u1_h_sq + &u1_h_sq;

    // 链式 sub 也需归一化
    let r_sq_minus_h_cu = reduce_fq_var(&(&r_sq - &h_cu))?;
    let x3 = reduce_fq_var(&(&r_sq_minus_h_cu - &two_u1_h_sq))?;

    let inner = reduce_fq_var(&(&u1_h_sq - &x3))?;
    let s1_h_cu = &s1 * &h_cu;
    let r_inner = &r * &inner;
    let y3 = reduce_fq_var(&(&r_inner - &s1_h_cu))?;

    let z1_z2 = &a.z * &b.z;
    let z3 = &h * &z1_z2;

    Ok(G1VarBN254 { x: x3, y: y3, z: z3 })
}
```

**更新 `safe_add` 调用**：
```rust
fn safe_add(a: &G1VarBN254, b: &G1VarBN254) -> Result<G1VarBN254, SynthesisError> {
    let added = add_incomplete(a, b)?;  // 加 ?
    // ... 其余不变 ...
}
```

#### Step 4: 移除调试代码，验证测试

```bash
cargo test -p poker_zkvm --lib r1cs_gadgets_bn254 -- --nocapture
```

**验证点**：6 个测试全绿。

#### 备选方案（若 Step 3 无效）

- **备选 A**：在 mul 前也调用 `reduce_fq_var` 归一化乘法操作数（如 `h_sq = reduce_fq_var(&h)? * reduce_fq_var(&h)?`，但 `mul()` 已内置 reduce，所以这应该等效）
- **备选 B**：改用仿射坐标加法公式（需 1 次逆元，~250 次乘法约束，避免链式 sub）
- **备选 C**：电路外计算 `a + b`，电路内仅 `enforce_equal`（**注意**：此方案破坏 soundness — 攻击者可同时篡改 `c_c` 和 `c_prime` 使约束通过，故**不推荐**）

---

### F-2: 扩展 CompressedProof::Groth16 + 改造 groth16_compress

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

#### 改动 1：新增 `Groth16CompressedProof` 结构体（约 L97 前）

```rust
/// Groth16 压缩 proof — 含 proof + VK + 公共输入，支持独立验证。
#[derive(Debug, Clone)]
pub struct Groth16CompressedProof {
    pub proof: Groth16Proof,
    pub verifying_key: Groth16VerifyingKey,
    pub public_inputs: Vec<Fr>,
    pub fold_step_count: usize,
}
```

#### 改动 2：更新 `CompressedProof` enum（L98-L105）

```rust
pub enum CompressedProof {
    Native(NativeCompressedProof),
    Groth16(Groth16CompressedProof),  // 原: Groth16(Groth16Proof)
}
```

#### 改动 3：改造 `groth16_compress` 函数（L135-L164）

改用 `HypernovaVerifierCircuitBN254`（Fr-based），调用 `groth16_setup + groth16_prove`：

```rust
pub fn groth16_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        extract_fold_chain, HypernovaVerifierCircuitBN254,
    };

    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;
    let circuit = HypernovaVerifierCircuitBN254 {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };

    // 前置检查：原生约束满足性
    let satisfied = circuit.verify_native()?;
    if !satisfied {
        return Err(ZkvmError::Other(
            "groth16_compress: fold commitment 链验证失败(约束不满足)".to_string(),
        ));
    }

    // 提取公共输入 Fr 表示
    let public_inputs = circuit.public_inputs_to_fr()?;

    // Groth16 setup + prove
    let (pk, vk) = groth16_setup(circuit.clone())?;
    let groth16_proof = groth16_prove(&pk, circuit)?;

    Ok(CompressedProof::Groth16(Groth16CompressedProof {
        proof: groth16_proof,
        verifying_key: vk,
        public_inputs,
        fold_step_count: proof.fold_steps.len(),
    }))
}
```

**验证点**：`cargo check -p poker_zkvm` 编译通过。

---

### F-3: 新增 groth16_compress_verify

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

在 `groth16_compress` 之后新增：

```rust
/// 验证 Groth16 压缩 proof。
pub fn groth16_compress_verify(compressed: &CompressedProof) -> Result<bool, ZkvmError> {
    match compressed {
        CompressedProof::Native(_) => Ok(true),
        CompressedProof::Groth16(groth16) => {
            groth16_verify(&groth16.verifying_key, &groth16.public_inputs, &groth16.proof)
        }
    }
}
```

---

### F-4: tree_aggregate 集成 + 测试断言更新

**文件**：`poker_zkvm/src/recursion/mod.rs`

#### 改动 1：`tree_aggregate_recursive`（L292）

调用点 `groth16_compress(&aggregated_proof).ok().map(Box::new)` 签名不变，无需改动。

#### 改动 2：更新测试断言（L684-L733）

`test_compressed_proof_in_internal_node`（L684-L702）：
```rust
match compressed {
    CompressedProof::Groth16(groth16) => {
        assert_eq!(groth16.fold_step_count, 1, "fold_step_count 应 = 1");
        assert!(groth16_compress_verify(compressed).unwrap(), "Groth16 proof 应验证通过");
    }
    CompressedProof::Native(_) => { panic!("Phase F 应返回 Groth16 变体"); }
}
```

`test_compressed_proof_matches_direct_call`（L704-L733）：更新为匹配双方均为 `Groth16`，比较 `fold_step_count` 和 `public_inputs`。

---

### F-5: 测试更新 + 全量回归

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`（测试模块）

#### 改动 1：更新 `test_groth16_compress_valid_proof`（L224-L315）
- 断言返回 `CompressedProof::Groth16(_)`
- 调用 `groth16_compress_verify` 验证闭环
- 断言 `fold_step_count == 1`

#### 改动 2：更新 `test_groth16_compress_tampered_commitment`（L317-L401）
- 篡改 commitment → `groth16_compress` 在 `verify_native` 阶段失败

#### 改动 3：新增测试
- `test_groth16_compress_verify_e2e` — 完整闭环
- `test_groth16_compress_tampered_public_input` — 篡改 public_inputs → verify → false
- `test_groth16_compress_proof_size` — Groth16 proof 序列化 < 1KB

#### 全量回归

```bash
cargo test -p poker_zkvm --lib groth16 -- --nocapture
cargo test -p poker_zkvm --lib recursion -- --nocapture
cargo test -p poker_zkvm --lib r1cs_gadgets_bn254 -- --nocapture
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo test -p poker_zkvm --test e2e_poker_hand_eval
cargo test -p poker_zkvm --test soundness
cargo clippy -p poker_zkvm -- -D warnings 2>&1 | grep -c "warning"
```

---

## 关键设计决策

### D-F-1（v2 更新）: add_incomplete 修复方案
- **选择**：用 public API（`new_witness` + `enforce_equal`）复制 `Reducer::reduce()` 逻辑
- **理由**：`Reducer` 是 `pub(crate)` 不可外部访问；`EqGadget::enforce_equal` 是 public trait 方法
- **代价**：每次 reduce 新增 1 个 witness + `conditional_enforce_equal` 约束（~100 约束/次），`add_incomplete` 新增 ~5 次 reduce ≈ ~500 约束

### D-F-2: 公共输入提取
- `ConstraintSystem::instance_assignment()` 返回 `Vec<Fr>`

### D-F-3: CompressedProof::Groth16 携带 VK
- `Groth16CompressedProof` 含 `verifying_key` + `public_inputs` + `fold_step_count`，使 `groth16_compress_verify` 无需额外参数

### D-F-4: Native 验证作为前置检查
- `groth16_compress` 先 `verify_native()`，通过后再 `groth16_setup + prove`，快速失败

### D-F-5: 保留 Native 变体
- 向后兼容，未来可用于 fallback

---

## 执行顺序

```
F-1-fix (修复 add_incomplete)
  ├─ Step 1: 添加调试输出，定位错误源
  ├─ Step 2: 实现 reduce_fq_var
  ├─ Step 3: 在 add_incomplete 关键位置调用 reduce_fq_var
  └─ Step 4: 移除调试代码，验证 6 个测试全绿
      └─> F-2 (扩展 Groth16CompressedProof + 改造 groth16_compress)
            └─> F-3 (新增 groth16_compress_verify)
                  └─> F-4 (tree_aggregate 测试断言更新)
                        └─> F-5 (测试更新 + 全量回归)
```

每个子任务完成后 `cargo check`，F-5 做全量回归。

---

## 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| `reduce_fq_var` 无法修复（根因判断错误） | 中 | 阻塞 | Step 1 调试输出可重新定位；备选方案 A/B 已准备 |
| `enforce_equal` 内部调用 `pub(crate)` 方法失败 | 低 | 编译错误 | 已确认 `EqGadget` trait 方法是 public |
| Groth16 setup 对 `EmulatedFpVar` 电路 OOM | 中 | 阻塞 | 先用单步 fold；若失败考虑减少约束 |
| 既有测试硬编码 `Native` 断言 | 高 | 测试失败 | F-4/F-5 系统性更新 |
| Groth16 proof 序列化 > 1KB | 低 | 性能 | BN254 Groth16 proof ≈ 200-300 字节 |
