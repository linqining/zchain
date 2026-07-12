# Phase F 分阶段执行计划 — Groth16 真实 SNARK 压缩

## 摘要

Phase F 目标：将 `groth16_compress` 从返回 `CompressedProof::Native`（仅原生约束验证）升级为返回 `CompressedProof::Groth16`（真实 Groth16 SNARK proof），实现 ~200B 压缩 proof。

**当前阻塞**：F-1-fix 中 `add_incomplete` 函数的 `EmulatedFpVar<Fq, Fr>` 减法运算产生错误的 witness 值，导致 `test_g1_point_add_bn254` 和 `test_fold_commitment_check_valid_bn254` 两个测试失败。

---

## 当前状态分析

### 已完成

1. **`r1cs_gadgets_bn254.rs`** — 自定义 `G1VarBN254` 结构体，使用 `EmulatedFpVar<Fq, Fr>` 在 `ConstraintSystem<Fr>` 中表示 BN254 G1 点
   - `point_double`（正确，测试通过）
   - `add_incomplete`（**结果值不正确** — 核心阻塞）
   - `safe_add`、`safe_double`、`scalar_mul_gadget_bn254`、`point_add_gadget_bn254`、`fold_commitment_check_bn254`
   - 6 个单元测试：4 通过，2 失败
   - 编译通过（`Namespace`、`Borrow`、`AdditiveGroup` 导入已修复）

2. **`hypernova_verifier_circuit.rs:L236-L359`** — `HypernovaVerifierCircuitBN254` 实现 `ConstraintSynthesizer<Fr>`
   - `verify_native()` 方法
   - `public_inputs_to_fr()` 方法（通过 `instance_assignment()` 提取公共输入）

3. **`groth16_compress.rs`** — Groth16 API 完整可用（`groth16_setup/prove/verify`）
   - `CompressedProof` enum 已有 `Groth16(Groth16Proof)` 变体（需扩展为 `Groth16CompressedProof`）

### 核心阻塞分析

**现象**：`add_incomplete` 使用标准 EFD add-1998-cmo-2 投影坐标加法公式，数学公式经验证正确。`point_double` 使用相同的 `EmulatedFpVar` `+`/`-`/`*` 运算符但结果正确。`add_incomplete` 的 `value()` 返回的 Fq 值与 ark-ec 的 `a + b` 完全不同（交叉乘法验证 `X1*Z2 != X2*Z1` 且 `Y1*Z2 != Y2*Z1`）。

**根因分析**（基于 ark-r1cs-std 0.6.0 源码调查）：

- `EmulatedFpVar::sub()` 调用 `sub_without_reduce()` + `post_add_reduce()`
- `post_add_reduce()`（reduce.rs:L125-L138）仅在 `BaseF::MODULUS_BIT_SIZE > 2 * bits_per_limb + surfeit + 1` 时执行 `reduce()`
- 对于 `EmulatedFpVar<Fq, Fr>`：`Fr::MODULUS_BIT_SIZE = 254`，`bits_per_limb ≈ 88`，所以 `2*88 + surfeit + 1 = 177 + surfeit`。当 surfeit < 77 时，**reduction 被跳过**
- `sub_without_reduce()`（allocated_field_var.rs:L181-L257）在 limb 层执行 `this_limb + pad + pad_to_kp - other_limb`。当 `self` 来自前一次 sub（非 normal form，limbs 可能较大），再加 pad 可能导致单 limb 溢出 `BaseF (Fr)` 范围
- `mul()` 始终调用 `reduce()`，所以 `point_double` 中乘法后的值正确；`add_incomplete` 中 `x3 = (r_sq - h_cu) - two_u1_h_sq` 的链式 sub 是疑似溢出点

**修复方向**：在 `add_incomplete` 的关键 sub 操作后显式调用 `Reducer::<Fq, Fr>::reduce()` 归一化 limbs，防止溢出累积。

---

## 子任务详细设计

### F-1-fix: 修复 add_incomplete witness 值错误

**文件**：`poker_zkvm/src/recursion/r1cs_gadgets_bn254.rs`

#### Step 1: 精确定位错误源（添加临时调试代码）

在 `add_incomplete` 中为每个中间变量添加 `eprintln!` 调试输出：

```rust
fn add_incomplete(a: &G1VarBN254, b: &G1VarBN254) -> G1VarBN254 {
    let z2_sq = &b.z * &b.z;
    let u1 = &a.x * &z2_sq;
    let z1_sq = &a.z * &a.z;
    let u2 = &b.x * &z1_sq;
    // 调试：检查 u1, u2 值
    eprintln!("u1 = {:?}", u1.value().unwrap());
    eprintln!("u2 = {:?}", u2.value().unwrap());

    let z2_cu = &z2_sq * &b.z;
    let s1 = &a.y * &z2_cu;
    let z1_cu = &z1_sq * &a.z;
    let s2 = &b.y * &z1_cu;
    eprintln!("s1 = {:?}", s1.value().unwrap());
    eprintln!("s2 = {:?}", s2.value().unwrap());

    let h = &u2 - &u1;
    eprintln!("h = u2 - u1 = {:?}", h.value().unwrap());
    // 对比原生计算
    // (在测试中用 ark-ec 计算预期值)

    let r = &s2 - &s1;
    eprintln!("r = s2 - s1 = {:?}", r.value().unwrap());

    // ... 后续中间变量 ...
    let x3 = &(&r_sq - &h_cu) - &two_u1_h_sq;
    eprintln!("x3 = {:?}", x3.value().unwrap());
    // ...
}
```

在 `test_g1_point_add_bn254` 中同时输出 ark-ec 原生计算的中间值（需手动展开公式），定位**第一个**出错的中间变量。

#### Step 2: 应用修复 — 显式 reduce

根据 Step 1 的定位结果，在出错的 sub 操作后显式调用 `Reducer::reduce()`：

```rust
use ark_r1cs_std::fields::emulated_fp::AllocatedEmulatedFpVar;
use ark_r1cs_std::fields::emulated_fp::reduce::Reducer;

/// 辅助：显式归一化 EmulatedFpVar 的 limbs
fn reduce_fq_var(v: &FqVarEmulated) -> Result<FqVarEmulated, SynthesisError> {
    match v {
        FqVarEmulated::Var(allocated) => {
            let mut allocated = allocated.clone();
            Reducer::<Fq, Fr>::reduce(&mut allocated)
                .map_err(|e| SynthesisError::Other(format!("reduce failed: {e}")))?;
            Ok(FqVarEmulated::Var(allocated))
        }
        FqVarEmulated::Constant(c) => Ok(FqVarEmulated::Constant(*c)),
    }
}
```

然后在 `add_incomplete` 中对关键 sub 结果调用 `reduce_fq_var`：

```rust
fn add_incomplete(a: &G1VarBN254, b: &G1VarBN254) -> G1VarBN254 {
    let z2_sq = &b.z * &b.z;
    let u1 = &a.x * &z2_sq;
    let z1_sq = &a.z * &a.z;
    let u2 = &b.x * &z1_sq;
    let z2_cu = &z2_sq * &b.z;
    let s1 = &a.y * &z2_cu;
    let z1_cu = &z1_sq * &a.z;
    let s2 = &b.y * &z1_cu;

    // 关键修复：sub 后显式 reduce，防止 limb 溢出累积
    let h = reduce_fq_var(&(&u2 - &u1)).unwrap();
    let r = reduce_fq_var(&(&s2 - &s1)).unwrap();

    let h_sq = &h * &h;
    let h_cu = &h_sq * &h;
    let u1_h_sq = &u1 * &h_sq;
    let r_sq = &r * &r;
    let two_u1_h_sq = &u1_h_sq + &u1_h_sq;

    // 链式 sub 也需 reduce
    let r_sq_minus_h_cu = reduce_fq_var(&(&r_sq - &h_cu)).unwrap();
    let x3 = reduce_fq_var(&(&r_sq_minus_h_cu - &two_u1_h_sq)).unwrap();

    let inner = reduce_fq_var(&(&u1_h_sq - &x3)).unwrap();
    let y3 = reduce_fq_var(&(&(&r * &inner) - &(&s1 * &h_cu))).unwrap();

    let z1_z2 = &a.z * &b.z;
    let z3 = &h * &z1_z2;

    G1VarBN254 { x: x3, y: y3, z: z3 }
}
```

> **注意**：`reduce_fq_var` 返回 `Result`，但 `add_incomplete` 当前返回 `G1VarBN254`（非 Result）。需将 `add_incomplete` 改为返回 `Result<G1VarBN254, SynthesisError>`，并更新调用方 `safe_add`。或者使用 `.unwrap()`（因为 reduce 在 witness 模式下不应失败）。

#### Step 3: 移除调试代码，验证全部测试

```bash
cargo test -p poker_zkvm --lib r1cs_gadgets_bn254 -- --nocapture
```

**验证点**：
- 6 个测试全绿（`test_g1_scalar_mul_identity_bn254`、`test_g1_scalar_mul_generator_bn254`、`test_g1_scalar_mul_small_bn254`、`test_g1_point_add_bn254`、`test_fold_commitment_check_valid_bn254`、`test_fold_commitment_check_invalid_bn254`）
- `test_g1_point_add_bn254` 中的调试 `eprintln!` 全部移除
- `add_incomplete` 签名变更（若改为 Result）不影响 `safe_add` 调用

#### 备选方案（若 Step 2 无效）

若显式 `reduce()` 仍无法修复，考虑以下备选：

- **备选 A**：改用 `AllocatedEmulatedFpVar::sub()` 直接方法代替运算符，手动控制 surfeit
- **备选 B**：在 `add_incomplete` 中改用仿射坐标加法公式（需 1 次逆元，约 250 次乘法约束，但避免链式 sub）
- **备选 C**：完全避免在电路内做点加法 — 改为在电路外原生计算 `a + b`，电路内仅 enforce `result == expected`（牺牲通用性，但 fold commitment 验证场景中 `expected` 可在外部计算）

---

### F-2: 扩展 CompressedProof::Groth16 + 改造 groth16_compress

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

#### 改动 1：新增 `Groth16CompressedProof` 结构体

在 `CompressedProof` enum 之前（约 L97）新增：

```rust
/// Groth16 压缩 proof — 含 proof + VK + 公共输入，支持独立验证。
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

#### 改动 2：更新 `CompressedProof` enum（L98-L105）

```rust
#[derive(Debug, Clone)]
pub enum CompressedProof {
    Native(NativeCompressedProof),
    Groth16(Groth16CompressedProof),  // 原: Groth16(Groth16Proof)
}
```

#### 改动 3：改造 `groth16_compress` 函数（L135-L164）

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

**注意**：`groth16_setup` 和 `groth16_prove` 对 `EmulatedFpVar` 约束电路可能较慢（~700k 约束/步）。先用单步 fold 测试。

---

### F-3: 新增 groth16_compress_verify

**文件**：`poker_zkvm/src/prover/groth16_compress.rs`

在 `groth16_compress` 函数之后新增：

```rust
/// 验证 Groth16 压缩 proof。
///
/// 对 `CompressedProof::Groth16` 变体执行 Groth16 verify；
/// 对 `CompressedProof::Native` 变体直接返回 `true`（Native 的约束已在 `groth16_compress` 内验证）。
pub fn groth16_compress_verify(compressed: &CompressedProof) -> Result<bool, ZkvmError> {
    match compressed {
        CompressedProof::Native(_) => Ok(true),
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

#### 改动 1：确认 `tree_aggregate_recursive` 兼容性

- `L292`: `groth16_compress(&aggregated_proof).ok().map(Box::new)` — 调用点无需改动（`groth16_compress` 签名不变）
- `CycleFoldNode::Node.compressed_proof` 类型为 `Option<Box<CompressedProof>>` — 兼容新变体

#### 改动 2：更新测试断言（L684-L760）

`test_compressed_proof_in_internal_node`（约 L684-L702）：
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

`test_compressed_proof_matches_direct_call`（约 L704-L733）：
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

#### 改动 1：更新 `test_groth16_compress_valid_proof`（L224-L315）

- 断言返回 `CompressedProof::Groth16(_)`
- 调用 `groth16_compress_verify` 验证闭环
- 断言 `fold_step_count == 1`

#### 改动 2：更新 `test_groth16_compress_tampered_commitment`（L317-L401）

- 篡改 commitment → `groth16_compress` 返回错误（约束不满足，在 `verify_native` 阶段失败）

#### 改动 3：新增测试

- `test_groth16_compress_verify_e2e` — 完整闭环：compress → verify → true
- `test_groth16_compress_tampered_public_input` — 篡改 public_inputs → verify → false
- `test_groth16_compress_proof_size` — 断言 Groth16 proof 序列化大小 < 1KB

#### 全量回归

```bash
cargo test -p poker_zkvm --lib groth16 -- --nocapture
cargo test -p poker_zkvm --lib recursion -- --nocapture
cargo test -p poker_zkvm --lib
cargo test -p poker_l1 --lib
cargo test -p poker_zkvm --test e2e_poker_hand_eval
cargo test -p poker_zkvm --test soundness
cargo clippy -p poker_zkvm -- -D warnings 2>&1 | grep -c "warning"  # 应 ≤ 2（既有）
```

---

## 关键设计决策

### D-F-1: add_incomplete 修复方案
- **选择**：显式 `Reducer::reduce()` 归一化 limbs
- **理由**：`post_add_reduce` 在 surfeit 较小时跳过 reduction，导致 limbs 累积溢出；显式 reduce 强制归一化
- **代价**：每次 reduce 新增 1 个 witness 变量 + conditional_enforce_equal 约束（~100 约束/次），`add_incomplete` 新增 ~5 次 reduce ≈ ~500 约束

### D-F-2: 公共输入提取方案
- **选择**：`ConstraintSystem::instance_assignment()` 返回 `Vec<Fr>`
- **API**：`ark-relations-0.6.0/src/gr1cs/constraint_system_ref.rs` 的 `instance_assignment()` 方法

### D-F-3: CompressedProof::Groth16 携带 VK
- **选择**：`Groth16CompressedProof` 结构体含 `verifying_key` + `public_inputs` + `fold_step_count`
- **理由**：`groth16_verify` 需要 VK 和 public_inputs；携带在 proof 中使 `groth16_compress_verify` 无需额外参数

### D-F-4: Native 验证作为前置检查
- **选择**：`groth16_compress` 先 `verify_native()`，通过后再 `groth16_setup + prove`
- **理由**：Native 验证快速失败，避免浪费 setup/prove 时间

### D-F-5: 保留 CompressedProof::Native 变体
- **选择**：保留 `Native` 变体（不删除）
- **理由**：向后兼容；未来可能用于 fallback 场景

---

## 假设与前提

1. `ark-groth16 0.6.0` 的 `generate_random_parameters_with_reduction` 接受 `ConstraintSynthesizer<Fr>` — 已由现有 `TestCircuit` 测试验证
2. `Reducer::<Fq, Fr>::reduce()` 是公开方法 — 已确认在 `ark-r1cs-std-0.6.0/src/fields/emulated_fp/reduce.rs:L113` 为 `pub fn`
3. Groth16 setup/prove 对 `EmulatedFpVar` 约束电路可行，但可能较慢（~700k 约束/步）— 先用单步 fold 测试
4. `CompressedProof::Groth16` 的 `Clone` 派生需 `Groth16CompressedProof` 实现 `Clone` — `Proof<Bn254>`、`VerifyingKey<Bn254>`、`Vec<Fr>` 均 `Clone`

---

## 执行顺序

```
F-1-fix (修复 add_incomplete witness 值错误)
  ├─ Step 1: 添加调试输出，精确定位错误源
  ├─ Step 2: 应用显式 reduce 修复
  └─ Step 3: 移除调试代码，验证 6 个测试全绿
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
| 显式 `reduce()` 无法修复 `add_incomplete` | 低 | 阻塞 | 备选方案 A/B/C 已准备 |
| `Reducer::reduce` 非 public 或签名不匹配 | 低 | 阻塞 | 已确认 `pub fn reduce` 在 reduce.rs:L113 |
| `EmulatedFpVar` 约束数过大导致 Groth16 setup OOM | 中 | 阻塞 | 先用单步 fold；若失败考虑减少 limb 数 |
| `groth16_setup` 对 `EmulatedFpVar` 不兼容 | 低 | 阻塞 | `TestCircuit` 已验证基本流程 |
| 既有测试硬编码 `Native` 断言导致回归 | 高 | 测试失败 | F-4/F-5 系统性更新所有断言 |
| Groth16 proof 序列化 > 1KB | 低 | 性能 | BN254 Groth16 proof = 3 G1/G2 元素 ≈ 200-300 字节 |

---

## 后续阶段（Phase F 完成后）

- **Phase G**: LogUp 内存一致性
- **Phase H**: ECDSA 256-bit 标量
- **Phase I**: 预编译补齐
- **Phase J**: zkshuffle 真实电路
- **Phase K**: RV32IM M 扩展
- **Phase L**: Gas 模型 + STARK fallback + 形式化验证
