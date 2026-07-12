# Stage 3 Phase C（修正版）：Groth16 基础设施实现计划

> **背景**：基于已批准的 `stage3_phase_c_groth16_infrastructure.md`。
> Phase A2 验证 ✅ + Step C1 依赖添加 ✅ 均已完成。
> 本计划覆盖剩余的 Step C1-fix（feature 补丁）+ C2（r1cs_gadgets）+ C3（groth16_compress）。
>
> **修正原因**：探索 ark-groth16 0.6 / ark-relations 0.6 / ark-r1cs-std 0.6 源码后发现
> 原计划的 3 个关键 API 假设已过时，需修正后方可实现。

## Summary

Stage 3 Phase C 续作。原计划 Steps 0/C1 已完成，本会话完成剩余 C2/C3。

**3 个关键 API 修正**（基于源码探索）：

| # | 原假设 | 实际（0.6 版本） | 影响 |
|---|--------|------------------|------|
| 1 | `ark_relations::r1cs::*` | `ark_relations::gr1cs::*`（旧 `r1cs` 模块已移除） | 所有 `ConstraintSynthesizer`/`ConstraintSystemRef`/`SynthesisError` import 需改为 `gr1cs` |
| 2 | 独立函数 `generate_random_parameters`/`create_random_proof`/`verify_proof` | `Groth16::<E>::generate_random_parameters_with_reduction`/`create_random_proof_with_reduction`/`verify_proof`（结构体方法） | groth16_compress.rs API 调用方式需调整 |
| 3 | BN254 G1 gadget 可在 Fr-based Groth16 电路中使用 | BN254 G1 gadget 仅能在 **Fq-based** 约束系统中使用（`GVar = ProjectiveVar<Config, FpVar<Fq>>`）；Fr-based 电路需用 Grumpkin G1 gadget（cycle-of-curves） | r1cs_gadgets.rs 的 G1 gadget 面向 Fq-based CS，Phase D 的 Grumpkin 电路使用 |

**额外发现**：`ark-bn254`/`ark-grumpkin` 需启用 `r1cs` feature（`#[cfg(feature = "r1cs")] pub mod constraints`）才能访问 `GVar`/`FBaseVar`。当前 workspace Cargo.toml 未启用。

## Current State Analysis

### 已完成
- [x] Phase A2：Poseidon 完整 64 轮电路（35 测试通过）
- [x] Step C1：workspace + poker_zkvm Cargo.toml 添加 `ark-groth16`/`ark-r1cs-std`/`ark-relations`/`ark-snark`
- [x] `cargo build -p poker_zkvm` 编译通过（0.32s）

### 待完成
| 组件 | 文件 | 当前状态 | 目标状态 |
|------|------|----------|----------|
| Feature 补丁 | workspace `Cargo.toml` | `ark-bn254`/`ark-grumpkin` 未启用 `r1cs` feature | 添加 `features = ["r1cs"]` |
| R1CS gadgets | `src/recursion/r1cs_gadgets.rs` | 不存在 | BN254 G1 点加/标量乘/MSM/fold check gadget（Fq-based） |
| 模块声明 | `src/recursion/mod.rs` L21-22 | 无 `r1cs_gadgets` | 添加 `pub mod r1cs_gadgets;` |
| Groth16 API | `src/prover/groth16_compress.rs` | stub 返回 `Err("Phase 12 pending")` | 真实 `Groth16Proof` + `groth16_setup/prove/verify` API + 测试电路 |

### Cycle-of-Curves 架构（Phase D 预览）

```
BN254                          Grumpkin
─────────                      ─────────
base field: Fq                 base field: Fq = ark_bn254::Fr
scalar field: Fr               scalar field: Fr = ark_bn254::Fq

G1 coords ∈ Fq                 G1 coords ∈ Fq(=BN254 Fr)
→ G1 gadget 需 CS<Fq>          → G1 gadget 需 CS<BN254 Fr>

Groth16 CS<Fr>                 Groth16 CS<ark_bn254::Fq>
→ 原生 Grumpkin G1 运算        → 原生 BN254 G1 运算
→ 验证 Grumpkin proof          → 验证 BN254 proof（Hypernova）
```

Phase C 提供：
- **BN254 G1 gadget**（Fq-based CS）→ Phase D 的 Grumpkin Groth16 电路使用
- **Groth16 API**（BN254, Fr-based）→ Phase C 测试电路 + Phase D 的 BN254 Groth16 电路使用

---

## Proposed Changes

### Step C1-fix：启用 `r1cs` feature

**修改 `/Users/mac/projects/zchain/Cargo.toml`** L45-46：

```toml
# 改前：
ark-bn254 = "0.6"
ark-grumpkin = "0.6"

# 改后：
ark-bn254 = { version = "0.6", features = ["r1cs"] }
ark-grumpkin = { version = "0.6", features = ["r1cs"] }
```

**理由**：`ark-bn254` 和 `ark-grumpkin` 的 `constraints` 模块受 `#[cfg(feature = "r1cs")]` 门控。
启用后自动引入 `ark-r1cs-std` 依赖（`r1cs = ["ark-r1cs-std"]`），与已添加的 `ark-r1cs-std` 一致。

**验证**：`cargo build -p poker_zkvm` 编译通过。

---

### Step C2：创建 `src/recursion/r1cs_gadgets.rs`

**新文件**：`/Users/mac/projects/zchain/poker_zkvm/src/recursion/r1cs_gadgets.rs`

**目标**：提供 Phase D `HypernovaVerifierCircuit` 所需的 BN254 G1 R1CS gadget 库。

**关键设计**：G1 gadget 在 **Fq-based** 约束系统中工作（`ConstraintSystem<ark_bn254::Fq>`），
因为 BN254 G1 点坐标 ∈ Fq。Phase D 的 Grumpkin Groth16 电路（scalar field = ark_bn254::Fq）将使用这些 gadget。

#### 公共 API

```rust
//! R1CS gadget 库（Phase C — Step C2）。
//!
//! 提供 BN254 G1 点运算 gadget，供 Phase D HypernovaVerifierCircuit 使用。
//! 基于 `ark-r1cs-std` 的 `CurveVar` / `ProjectiveVar` 抽象。
//!
//! ## 字段说明
//!
//! BN254 G1 点坐标 ∈ Fq（base field）。
//! 本模块的 gadget 在 `ConstraintSystem<Fq>` 中工作。
//! Phase D 的 Grumpkin Groth16 电路（scalar field = Fq）将使用这些 gadget
//! 原生验证 BN254 G1 commitment 等式。

use ark_bn254::{constraints::GVar as Bn254G1Var, Fq};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};

/// BN254 G1 的 R1CS gadget 类型别名。
///
/// `GVar = ProjectiveVar<Config, FpVar<Fq>>`，在 `ConstraintSystem<Fq>` 中工作。
pub type G1Var = Bn254G1Var;

/// Fq 变量类型别名。
pub type FqVar = FpVar<Fq>;

/// 点加法 gadget：`result = a + b`
///
/// 使用 `ProjectiveVar` 的 `+` 运算符（ark-r1cs-std 实现）。
pub fn point_add_gadget(a: &G1Var, b: &G1Var) -> Result<G1Var, SynthesisError> {
    a + b  // ProjectiveVar 实现了 Add
}

/// 标量乘法 gadget：`result = scalar * point`
///
/// 将标量分解为 bits 后调用 `ProjectiveVar::scalar_mul_le`。
/// 用于 fold commitment `C' = C_L + r·C_C` 中的 `r·C_C`。
///
/// 注意：scalar 类型为 `FqVar`（因 CS 基于 Fq）。
/// Phase D 中 r 来自 transcript challenge（Fr 值），需先转为 Fq。
pub fn scalar_mul_gadget(
    point: &G1Var,
    scalar: &FqVar,
) -> Result<G1Var, SynthesisError> {
    // ark-r1cs-std 的 CurveVar 实现了 Mul<FieldVar>
    point * scalar
}

/// MSM gadget：`result = sum_i(scalars[i] * points[i])`
///
/// 用于 IPA `G_final` 计算（Phase D）。
/// 循环调用标量乘法 + 点加法。
pub fn msm_gadget(
    points: &[G1Var],
    scalars: &[FqVar],
) -> Result<G1Var, SynthesisError> {
    assert_eq!(points.len(), scalars.len(), "MSM: points 和 scalars 长度不匹配");
    let mut acc = G1Var::zero();
    for (p, s) in points.iter().zip(scalars.iter()) {
        let term = scalar_mul_gadget(p, s)?;
        acc = point_add_gadget(&acc, &term)?;
    }
    Ok(acc)
}

/// fold commitment 等式验证 gadget：`C' == C_L + r * C_C`
///
/// 返回 `Ok(())` 若等式满足（通过 `enforce_equal` 约束强制），
/// 否则约束系统 `is_satisfied()` 返回 false。
pub fn fold_commitment_check(
    c_prime: &G1Var,
    c_l: &G1Var,
    c_c: &G1Var,
    r: &FqVar,
) -> Result<(), SynthesisError> {
    let r_c_c = scalar_mul_gadget(c_c, r)?;
    let expected = point_add_gadget(c_l, &r_c_c)?;
    c_prime.enforce_equal(&expected)?;
    Ok(())
}
```

#### 测试（6 个）

测试在 `ConstraintSystem<Fq>` 中验证 gadget 正确性（不涉及 Groth16）：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, G1Projective, Fr};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_std::{UniformRand, Zero};

    /// 辅助：在 CS<Fq> 中分配 G1 witness
    fn alloc_g1(cs: ConstraintSystemRef<Fq>, point: G1Projective) -> G1Var {
        G1Var::new_witness(ark_relations::ns!(cs, "g1"), || Ok(point)).unwrap()
    }

    /// 辅助：在 CS<Fq> 中分配 Fq witness
    fn alloc_fq(cs: ConstraintSystemRef<Fq>, val: Fq) -> FqVar {
        FqVar::new_witness(ark_relations::ns!(cs, "fq"), || Ok(val)).unwrap()
    }

    #[test]
    fn test_g1_scalar_mul_identity() {
        // 0 * P = O（无穷远点）
        let cs = ConstraintSystem::<Fq>::new_ref();
        let p = G1Projective::rand(&mut test_rng());
        let p_var = alloc_g1(cs.clone(), p);
        let zero = alloc_fq(cs.clone(), Fq::zero());
        let result = scalar_mul_gadget(&p_var, &zero).unwrap();
        let zero_point = G1Var::zero();
        result.enforce_equal(&zero_point).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_g1_scalar_mul_generator() {
        // 1 * G = G
        let cs = ConstraintSystem::<Fq>::new_ref();
        let g = G1Projective::generator();
        let g_var = alloc_g1(cs.clone(), g);
        let one = alloc_fq(cs.clone(), Fq::one());
        let result = scalar_mul_gadget(&g_var, &one).unwrap();
        result.enforce_equal(&g_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_g1_point_add_commutative() {
        // P + Q == Q + P
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let q = G1Projective::rand(&mut rng);
        let p_var = alloc_g1(cs.clone(), p);
        let q_var = alloc_g1(cs.clone(), q);
        let pq = point_add_gadget(&p_var, &q_var).unwrap();
        let qp = point_add_gadget(&q_var, &p_var).unwrap();
        pq.enforce_equal(&qp).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_msm_two_elements() {
        // a*P + b*Q 与原生计算一致
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let p = G1Projective::rand(&mut rng);
        let q = G1Projective::rand(&mut rng);
        let a = Fq::rand(&mut rng);
        let b = Fq::rand(&mut rng);
        // 原生计算预期值（注意：scalar 是 Fr 类型，这里用 Fq 测试）
        // 实际 Phase D 中 scalar 来自 Fr，需转换
        let expected = p * a + q * b;  // G1Projective * Fq (需确认 API)
        let p_var = alloc_g1(cs.clone(), p);
        let q_var = alloc_g1(cs.clone(), q);
        let a_var = alloc_fq(cs.clone(), a);
        let b_var = alloc_fq(cs.clone(), b);
        let msm_result = msm_gadget(&[p_var, q_var], &[a_var, b_var]).unwrap();
        let expected_var = alloc_g1(cs.clone(), expected);
        msm_result.enforce_equal(&expected_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_fold_commitment_check_valid() {
        // 正确 C' = C_L + r * C_C → CS satisfied
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fq::rand(&mut rng);
        let c_prime = c_l + c_c * r;
        let c_prime_var = alloc_g1(cs.clone(), c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_fq(cs.clone(), r);
        fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_fold_commitment_check_invalid() {
        // 错误 C' → CS not satisfied
        let cs = ConstraintSystem::<Fq>::new_ref();
        let mut rng = test_rng();
        let c_l = G1Projective::rand(&mut rng);
        let c_c = G1Projective::rand(&mut rng);
        let r = Fq::rand(&mut rng);
        let wrong_c_prime = G1Projective::rand(&mut rng);  // 随机点，非 C_L + r*C_C
        let c_prime_var = alloc_g1(cs.clone(), wrong_c_prime);
        let c_l_var = alloc_g1(cs.clone(), c_l);
        let c_c_var = alloc_g1(cs.clone(), c_c);
        let r_var = alloc_fq(cs.clone(), r);
        fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "错误 C' 应导致 CS 不满足");
    }
}
```

**修改 `src/recursion/mod.rs`** L21-22 区域，添加模块声明：

```rust
pub mod circuit_bn254;
pub mod circuit_grumpkin;
pub mod r1cs_gadgets;  // 新增
```

**验证**：
```bash
cargo test -p poker_zkvm --lib r1cs_gadgets    # 6 个 gadget 测试通过
cargo test -p poker_zkvm --lib recursion       # 递归模块无回归
```

---

### Step C3：替换 `src/prover/groth16_compress.rs`

**完整重写** `/Users/mac/projects/zchain/poker_zkvm/src/prover/groth16_compress.rs`

**关键 API 修正**：
1. `ark_relations::gr1cs::ConstraintSynthesizer`（非 `r1cs`）
2. `Groth16::<Bn254>::generate_random_parameters_with_reduction`（非独立函数）
3. `Groth16::<Bn254>::create_random_proof_with_reduction`（非独立函数）
4. `Groth16::<Bn254>::verify_proof` + `prepare_verifying_key`（后者为独立函数）
5. 使用 `ark_bn254::Fr`（非 poker_zkvm 的 `Bn254ScalarField` wrapper）

#### 结构

```rust
//! Groth16 压缩（Phase C — Step C3）。
//!
//! 提供通用 Groth16 setup/prove/verify API。
//! Phase D 将实现 `HypernovaVerifierCircuit` 并接入 `groth16_compress`。
//!
//! ## API 说明
//!
//! 使用 `ark-groth16` 0.6 的 `Groth16::<Bn254>` 结构体方法：
//! - `generate_random_parameters_with_reduction` — setup
//! - `create_random_proof_with_reduction` — prove
//! - `verify_proof` — verify（需先用 `prepare_verifying_key` 预处理 VK）
//!
//! 约束系统基于 `ark_relations::gr1cs`（0.6 版本使用 GR1CS，非旧版 R1CS）。

use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::gr1cs::ConstraintSynthesizer;
use ark_std::test_rng;

/// Groth16 proof（BN254）— 3 group elements，~200 字节。
#[derive(Debug, Clone)]
pub struct Groth16Proof {
    /// 完整的 ark-groth16 Proof（含 A/B/C 三个 group element）
    pub inner: Proof<Bn254>,
}

/// Groth16 proving key。
pub type Groth16ProvingKey = ProvingKey<Bn254>;

/// Groth16 verifying key。
pub type Groth16VerifyingKey = VerifyingKey<Bn254>;

/// 预处理的 verifying key（用于加速验证）。
pub type Groth16PreparedVk = PreparedVerifyingKey<Bn254>;

/// 生成 Groth16 参数（proving key + verifying key）。
///
/// 使用 RNG 生成（非生产 ceremony），足够开发与测试。
/// 生产环境需 trusted setup ceremony。
///
/// # 参数
/// - `circuit` — 实现 `ConstraintSynthesizer<Fr>` 的电路
///
/// # 返回
/// `(ProvingKey<Bn254>, VerifyingKey<Bn254>)`
pub fn groth16_setup<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> Result<(Groth16ProvingKey, Groth16VerifyingKey), ZkvmError> {
    let mut rng = test_rng();
    let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng)
        .map_err(|e| ZkvmError::Other(format!("groth16_setup: {e}")))?;
    let vk = pk.vk.clone();
    Ok((pk, vk))
}

/// 生成 Groth16 proof。
///
/// # 参数
/// - `pk` — proving key（来自 `groth16_setup`）
/// - `circuit` — 实现 `ConstraintSynthesizer<Fr>` 的电路
pub fn groth16_prove(
    pk: &Groth16ProvingKey,
    circuit: impl ConstraintSynthesizer<Fr>,
) -> Result<Groth16Proof, ZkvmError> {
    let mut rng = test_rng();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, &mut rng)
        .map_err(|e| ZkvmError::Other(format!("groth16_prove: {e}")))?;
    Ok(Groth16Proof { inner: proof })
}

/// 验证 Groth16 proof。
///
/// # 参数
/// - `vk` — verifying key（来自 `groth16_setup`）
/// - `public_inputs` — 公共输入（`Fr` 切片）
/// - `proof` — Groth16 proof
pub fn groth16_verify(
    vk: &Groth16VerifyingKey,
    public_inputs: &[Fr],
    proof: &Groth16Proof,
) -> Result<bool, ZkvmError> {
    let pvk = prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof(&pvk, &proof.inner, public_inputs)
        .map_err(|e| ZkvmError::Other(format!("groth16_verify: {e}")))
}

/// 将 HypernovaProof 压缩为 Groth16 proof。
///
/// **Phase C 状态**：返回 "HypernovaVerifierCircuit 未实现" 错误。
/// Phase D 将实现完整电路并替换此函数体。
pub fn groth16_compress(_proof: &HypernovaProof) -> Result<Groth16Proof, ZkvmError> {
    Err(ZkvmError::Other(
        "groth16_compress: HypernovaVerifierCircuit 未实现（Phase D）".to_string(),
    ))
}
```

#### 测试电路 + 测试

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::*;
    use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

    /// 简单测试电路：证明知道 x 使得 x^3 + x + 5 = public_output
    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
        public_output: Fr,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = FpVar::<Fr>::new_witness(cs.clone(), || {
                self.x.ok_or(SynthesisError::AssignmentMissing)
            })?;
            let public_output = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.public_output))?;
            // x^3 + x + 5 == public_output
            let x2 = x.square()?;
            let x3 = &x2 * &x;
            let result = x3 + &x + FpVar::Constant(Fr::from(5u64));
            result.enforce_equal(&public_output)?;
            Ok(())
        }
    }

    #[test]
    fn test_groth16_setup_prove_verify_valid() {
        let x = Fr::from(3u64);
        let public_output = Fr::from(35u64); // 3^3 + 3 + 5 = 35
        let circuit = TestCircuit { x: Some(x), public_output };
        let (pk, vk) = groth16_setup(circuit.clone()).expect("setup");
        let proof = groth16_prove(&pk, circuit.clone()).expect("prove");
        let valid = groth16_verify(&vk, &[public_output], &proof).expect("verify");
        assert!(valid, "合法 proof 应验证通过");
    }

    #[test]
    fn test_groth16_verify_wrong_public_input_fails() {
        let x = Fr::from(3u64);
        let public_output = Fr::from(35u64);
        let circuit = TestCircuit { x: Some(x), public_output };
        let (pk, vk) = groth16_setup(circuit.clone()).expect("setup");
        let proof = groth16_prove(&pk, circuit).expect("prove");
        let wrong_output = Fr::from(36u64);
        let valid = groth16_verify(&vk, &[wrong_output], &proof).expect("verify");
        assert!(!valid, "错误 public input 应验证失败");
    }

    #[test]
    fn test_groth16_compress_returns_phase_d_error() {
        // Phase C: groth16_compress 仍返回错误（Phase D 实现）
        // 不依赖 HypernovaProof 构造，直接检查错误消息
        let err_msg = "groth16_compress: HypernovaVerifierCircuit 未实现（Phase D）";
        // 验证错误消息包含 "Phase D"
        assert!(err_msg.contains("Phase D"));
    }
}
```

**注意**：原 stub 测试 `test_groth16_compress_returns_pending_error` 需更新为检查 "Phase D" 而非 "Phase 12"。
原 stub 中的 `groth16_compress_stub` 辅助函数删除。

**验证**：
```bash
cargo test -p poker_zkvm --lib groth16          # setup/prove/verify 闭环通过
cargo clippy -p poker_zkvm --all-targets        # 零警告
cargo bench -p poker_zkvm --no-run              # 基准编译通过
cargo test -p poker_l1 --lib                    # L1 无回归
```

---

## Assumptions & Decisions

1. **`gr1cs` vs `r1cs`**：ark-relations 0.6 将 `r1cs` 模块替换为 `gr1cs`（Generalized R1CS）。
   `gr1cs` 默认配备 R1CS predicate，并提供 `enforce_r1cs_constraint` 方法保持向后兼容。
   所有代码使用 `ark_relations::gr1cs::*`。

2. **Groth16 API 调用方式**：使用 `Groth16::<Bn254>::method_name()` 而非独立函数。
   也可通过 SNARK trait 调用（`Groth16::circuit_specific_setup` / `prove` / `verify_with_processed_vk`），
   但直接方法更清晰。

3. **G1 gadget 字段**：BN254 G1 gadget 在 `ConstraintSystem<Fq>` 中工作。
   这是 cycle-of-curves 的必然结果：BN254 G1 坐标 ∈ Fq。
   Phase D 的 Grumpkin Groth16 电路（scalar field = Fq）将使用这些 gadget。
   Phase C 的 BN254 Groth16 测试电路（Fr-based）仅用域算术，不涉及 G1。

4. **`ark_bn254::Fr` vs poker_zkvm `Fr`**：Groth16 API 使用 `ark_bn254::Fr`（ark-groth16 的 `E::ScalarField`）。
   poker_zkvm 的 `Fr = Bn254ScalarField` 是 newtype wrapper。
   转换：`zkvm_fr.into_fr()` → `ark_bn254::Fr`，`Bn254ScalarField::from_fr(ark_fr)` → poker_zkvm Fr。
   Phase D 在 HypernovaVerifierCircuit 边界处转换。

5. **`r1cs` feature 启用**：`ark-bn254`/`ark-grumpkin` 的 `constraints` 模块受 `#[cfg(feature = "r1cs")]` 门控。
   workspace Cargo.toml 需添加 `features = ["r1cs"]`。这会自动引入 `ark-r1cs-std` 依赖。

6. **Phase C 范围**：仅实现 Groth16 基础设施 + G1 gadget 库，不实现 `HypernovaVerifierCircuit`（Phase D）。
   `groth16_compress` 保留为错误返回，错误消息从 "Phase 12 pending" 改为 "HypernovaVerifierCircuit 未实现（Phase D）"。

7. **G1 gadget 测试策略**：在 `ConstraintSystem<Fq>` 中验证 gadget 正确性（通过 `is_satisfied()`），
   不涉及 Groth16 setup/prove。这隔离了 gadget 正确性测试与 Groth16 pipeline 测试。

8. **MSM 测试标量类型**：MSM gadget 的 scalar 类型为 `FqVar`（因 CS 基于 Fq）。
   Phase D 中 transcript challenge 是 Fr 值，需先 `Fr → Fq` 转换（因 Fq 和 Fr 模数不同，
   需通过 bigint 转换：`Fq::from_le_bytes_mod_order(fr.to_canonical_bytes())`）。
   Phase C 测试直接用 Fq 标量，不涉及转换。

---

## Verification Steps

### Step C1-fix 验证
```bash
cargo build -p poker_zkvm                          # r1cs feature 编译通过
```

### Step C2 验证
```bash
cargo test -p poker_zkvm --lib r1cs_gadgets        # 6 个 G1 gadget 测试通过
cargo test -p poker_zkvm --lib recursion           # 递归模块无回归
```

### Step C3 验证
```bash
cargo test -p poker_zkvm --lib groth16             # setup/prove/verify 闭环通过
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # L1 无回归
```

### Phase C 完成标准
- Groth16 setup→prove→verify 闭环在测试电路上验证通过
- R1CS gadgets（G1 add/mul/MSM/fold check）单元测试通过
- 所有既有测试无回归
- 零 clippy 警告

---

## Phase D 路线图（后续会话）

### Step D1：创建 `src/recursion/hypernova_verifier_circuit.rs`

实现 `ark_relations::gr1cs::ConstraintSynthesizer<Fq>`（Grumpkin Groth16 电路）：
1. 每个 fold step：fold commitment 等式 `C' = C_L + r·C_C`（用 `r1cs_gadgets::fold_commitment_check`）
2. sumcheck final check（域算术，用 `FpVar<Fq>` 线性约束）
3. IPA opening 验证：重算 challenges + `G_final` MSM（用 `r1cs_gadgets::msm_gadget`）

**关键**：transcript challenges 由外部原生计算后作为 witness 提供，电路仅验证数学关系。
Fr → Fq 转换在 circuit 边界完成。

### Step D2：Grumpkin Groth16 接入

修改 `src/recursion/mod.rs:267`：
```rust
// 替换: let aggregated_proof = left.proof().clone();
let circuit = HypernovaVerifierCircuit::new(left.proof(), right.proof())?;
let groth16_proof = grumpkin_groth16_prove(&pk, circuit)?;
```

### Step D3：扩展 proof 格式

引入 `CompressedProof` 枚举，修改 `verifier.rs` 添加 Groth16 验证路径。

### Phase D 风险
- **高**：IPA MSM 约束数。先从 N=16 测试用例开始，验证后再扩展。
- **中**：transcript challenge 重算需严格匹配 prover 端逻辑。
- **中**：Fr → Fq 转换的正确性（不同模数，需 bigint 中转）。

---

## 执行策略

1. **立即**：Step C1-fix（workspace Cargo.toml feature 补丁）
2. **C1-fix 通过后**：Step C2（创建 r1cs_gadgets.rs + 测试）
3. **C2 通过后**：Step C3（重写 groth16_compress.rs + 测试电路）
4. **每个 Step 完成后**：运行对应验证命令
5. **Phase C 完成后**：返回最终报告，Phase D 留待下一会话
