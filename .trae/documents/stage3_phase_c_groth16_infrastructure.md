# Stage 3 Phase C：Groth16 基础设施实现计划

> **背景**：基于已批准的 `stage3_continuation_from_a2.md`（A2 → C → D → B → E 顺序）。
> Phase A2 代码已写入 `src/precompiles/poseidon.rs`，`cargo build -p poker_zkvm` 通过（1.29s），
> 但测试套件尚未运行。本计划覆盖 Phase A2 验证 + Phase C 完整实现。

## Summary

Stage 3 续作按已批准顺序推进。本会话目标：
1. **Phase A2 验证**（立即）：运行 Poseidon 完整模式的测试套件，确认无回归
2. **Phase C 实现**（主体）：Groth16 基础设施 — 依赖添加 + R1CS gadgets + Groth16 API wrapper + 测试电路
3. **Phase D 路线图**（高层）：Hypernova Verifier R1CS 电路 + CycleFold 真实压缩的后续步骤

Phase C 是 Phase D 的前置依赖：提供 Groth16 setup/prove/verify 通用 API 和 R1CS gadget 库，
Phase D 在此基础上实现 `HypernovaVerifierCircuit` 并接入 `recursion/mod.rs:267` 的 CycleFold 框架。

## Current State Analysis

### Phase A2 现状（已完成代码，待验证）

- [x] `src/precompiles/poseidon.rs` — 完整重写，支持 MVP + 完整 64 轮模式
  - `PoseidonCircuit::new_full()` 构造完整模式
  - `build_full_ccs()` 用 CcsBuilder 构建 435 约束、439 变量
  - `assign_full_witness()` 运行完整 permutation
  - 12 个新 full-mode 测试 + 11 个保留 MVP 测试
- [x] `cargo build -p poker_zkvm` 编译通过（1.29s，零警告）
- [ ] **测试套件尚未运行**（本计划第一步）

### Phase C 现状（待实现）

| 组件 | 文件 | 当前状态 | 目标状态 |
|------|------|----------|----------|
| 依赖 | workspace `Cargo.toml` + `poker_zkvm/Cargo.toml` | `ark-groth16` 已声明但未在 poker_zkvm 引用；缺 `ark-r1cs-std`/`ark-relations`/`ark-snark` | 全部依赖添加并在 poker_zkvm 引用 |
| Groth16 API | `src/prover/groth16_compress.rs` | stub 返回 `Err("Phase 12 pending")` | 真实 `Groth16Proof` 结构 + `groth16_setup/prove/verify` 通用 API |
| R1CS gadgets | `src/recursion/r1cs_gadgets.rs` | 不存在 | BN254 G1 点加法/标量乘法/MSM gadget |
| 模块声明 | `src/recursion/mod.rs` | 无 `r1cs_gadgets` 模块 | 添加 `pub mod r1cs_gadgets;` |

### 关键集成点（Phase D 预览）

- `src/recursion/mod.rs:267` — `let aggregated_proof = left.proof().clone();`（CycleFold stub）
- `src/recursion/circuit_bn254.rs:105-109` — `verify_native` 委托到 `verify_hypernova`（原生验证模拟）
- `src/verifier.rs:65-69` — `verify_production` 主入口（Phase D 需添加 CompressedProof 分派）
- `src/prover/mod.rs:402` — `serialize_proof` 二进制格式（Phase D 需扩展压缩 proof 格式）

### HypernovaProof 结构（Phase D 目标）

`src/fold/fold_loop.rs:76-100` 定义了 `HypernovaProof`，含 12 个字段：
- `abi_version: u8`、`ccs_commitment: [u8;32]`、`public_io_commitment: [u8;32]`
- `batch_public_inputs: Vec<Vec<Fr>>`、`initial_lcccs: Lcccs`、`initial_witness_commitment: IpaCommitment`
- `fold_steps: Vec<FoldStepData>`、`final_sumcheck: SumcheckProof`、`pcs_opening: IpaProof`
- `r_y: Vec<Fr>`、`z_at_point: Fr`

序列化格式（`prover/mod.rs:387-401`）：magic "HYPN"(4B) + version(1B) + abi_version(1B) + 各字段。
`MAX_ZKVM_PROOF_SIZE = 64KB`（`prover/mod.rs:48`），`MAX_RECURSION_DEPTH = 16`（L53）。

---

## Proposed Changes

### Step 0：Phase A2 验证（立即执行）

运行完整验证套件确认 Phase A2 无回归：

```bash
cd /Users/mac/projects/zchain
cargo test -p poker_zkvm --lib poseidon            # Poseidon 全部测试（MVP + full）
cargo test -p poker_zkvm --lib ccs_builder         # CcsBuilder 无回归
cargo test -p poker_zkvm --lib precompiles         # 预编译全部测试
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 基准编译通过
cargo test -p poker_l1 --lib                       # L1 无回归
```

**通过标准**：所有测试通过，零 clippy 警告，基准编译成功，L1 无回归。

若发现失败：定位并修复后再进入 Phase C。

---

### Step C1：添加 Groth16 依赖

**修改 `/Users/mac/projects/zchain/Cargo.toml`** `[workspace.dependencies]`（L47 区域）：

当前状态（L47）：
```toml
ark-groth16 = { version = "0.6", default-features = false }
```

改为（添加 std feature + 新增三个依赖）：
```toml
ark-groth16 = { version = "0.6", default-features = false, features = ["std"] }
ark-r1cs-std = { version = "0.6", default-features = false, features = ["std"] }
ark-relations = { version = "0.6", default-features = false, features = ["std"] }
ark-snark = { version = "0.6", default-features = false }
```

**理由**：
- `ark-groth16` 需 `std` feature 以启用 `generate_random_parameters` / `create_random_proof` 等 API
- `ark-r1cs-std` 提供 `FpVar`/`CurveVar`/`GroupVar` gadget 类型
- `ark-relations` 提供 `ConstraintSynthesizer`/`ConstraintSystem` trait
- `ark-snark` 提供 `SNARK` trait（Groth16 实现此 trait）

**修改 `/Users/mac/projects/zchain/poker_zkvm/Cargo.toml`** `[dependencies]`（L23 区域后插入）：

```toml
ark-groth16 = { workspace = true }
ark-r1cs-std = { workspace = true }
ark-relations = { workspace = true }
ark-snark = { workspace = true }
```

**验证**：`cargo build -p poker_zkvm` 编译通过，无版本冲突。

---

### Step C2：创建 `src/recursion/r1cs_gadgets.rs`

**新文件**：`/Users/mac/projects/zchain/poker_zkvm/src/recursion/r1cs_gadgets.rs`

**目标**：提供 Phase D `HypernovaVerifierCircuit` 所需的 R1CS gadget 库。

**依赖**：`ark-r1cs-std` 的 `FpVar<Fr>`、`ark_bn254::G1Var`（来自 `ark_bn254::constraints`）

#### 公共 API

```rust
//! R1CS gadget 库（Phase C — Step C2）。
//!
//! 提供 BN254 G1 点运算 + MSM gadget，供 Phase D HypernovaVerifierCircuit 使用。
//! 基于 `ark-r1cs-std` 的 `CurveVar` / `AllocVar` 抽象。

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::short_weierstrass::bls12::GVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::Zero;

/// BN254 G1 的 R1CS gadget 类型（ark-r1cs-std 提供）。
pub type G1Var = ark_bn254::constraints::G1Var;

/// 标量乘法 gadget：`result = scalar * point`
///
/// 封装 `G1Var::scalar_le_bits_mul` 或 `scalar_mul`（取决于 ark-r1cs-std API）。
/// 用于 IPA MSM 和 fold commitment 等式 `C' = C_L + r·C_C`。
pub fn scalar_mul_gadget(
    cs: ConstraintSystemRef<Fr>,
    point: &G1Var,
    scalar: &FpVar<Fr>,
) -> Result<G1Var, SynthesisError>;

/// 点加法 gadget：`result = a + b`
pub fn point_add_gadget(a: &G1Var, b: &G1Var) -> Result<G1Var, SynthesisError>;

/// MSM gadget：`result = sum_i(scalars[i] * points[i])`
///
/// 用于 IPA `G_final` 计算（Phase D）。
/// N=512 点时约 1.3M 约束（每点 ~2500 约束）。
pub fn msm_gadget(
    points: &[G1Affine],
    scalars: &[FpVar<Fr>],
) -> Result<G1Var, SynthesisError>;

/// fold commitment 等式验证 gadget：`C' == C_L + r * C_C`
///
/// 返回 BooleanVar 表示等式是否成立。
pub fn fold_commitment_check(
    c_prime: &G1Var,
    c_l: &G1Var,
    c_c: &G1Var,
    r: &FpVar<Fr>,
) -> Result<BooleanVar<Fr>, SynthesisError>;
```

#### 实现要点

1. **`G1Var` 类型**：`ark_bn254::constraints::G1Var` 已实现 `CurveVar` trait，原生支持点加法和标量乘法。无需从零实现。
2. **`scalar_mul_gadget`**：调用 `G1Var::scalar_mul_le` 或直接用 `*` 运算符（`ark-r1cs-std` 为 `CurveVar` 实现了 `Mul<Variable>`）。
3. **`msm_gadget`**：循环调用 `scalar_mul` + `point_add`，或用 `Variable::new_input` 批量处理。
4. **witness 分配**：gadget 函数接受 `Option<Fr>`/`Option<G1Affine>` 作为 witness 值（`ConstraintSynthesizer` 模式），`None` 时仅生成约束不赋值。

#### 测试（至少 4 个）

- `test_g1_scalar_mul_identity` — `0 * P = O`（无穷远点）
- `test_g1_scalar_mul_generator` — `1 * G = G`（生成元）
- `test_g1_point_add_commutative` — `P + Q == Q + P`
- `test_msm_two_elements` — `a*P + b*Q` 与原生计算一致
- `test_fold_commitment_check_valid` — 正确 `C' = C_L + r·C_C` 返回 true
- `test_fold_commitment_check_invalid` — 错误 `C'` 返回 false

**测试策略**：每个 gadget 用简单已知值验证，通过 `ConstraintSystem::is_satisfied` 判断。

**修改 `src/recursion/mod.rs`**（L21 区域）：
```rust
pub mod circuit_bn254;
pub mod circuit_grumpkin;
pub mod r1cs_gadgets;  // 新增
```

---

### Step C3：替换 `src/prover/groth16_compress.rs` stub

**修改文件**：`/Users/mac/projects/zchain/poker_zkvm/src/prover/groth16_compress.rs`（完整重写）

#### 目标

提供通用 Groth16 setup/prove/verify API，供 Phase D `HypernovaVerifierCircuit` 使用。
Phase C 阶段 `groth16_compress(proof: &HypernovaProof)` 仍返回 "circuit not yet implemented" 错误
（因 `HypernovaVerifierCircuit` 是 Phase D 的工作），但底层 API 完整可用并通过测试电路验证。

#### 结构

```rust
//! Groth16 压缩（Phase C — Step C3）。
//!
//! 提供通用 Groth16 setup/prove/verify API。
//! Phase D 将实现 `HypernovaVerifierCircuit` 并接入 `groth16_compress`。

use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key,
    verify_proof, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
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

/// 生成 Groth16 参数（proving key + verifying key）。
///
/// 使用 RNG 生成（非生产 ceremony），足够开发与测试。
/// 生产环境需 trusted setup ceremony。
pub fn groth16_setup<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> Result<(Groth16ProvingKey, Groth16VerifyingKey), ZkvmError> {
    let mut rng = test_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circuit, &mut rng)
        .map_err(|e| ZkvmError::Other(format!("groth16_setup: {e}")))?;
    let vk = params.vk.clone();
    Ok((params, vk))
}

/// 生成 Groth16 proof。
pub fn groth16_prove(
    pk: &Groth16ProvingKey,
    circuit: impl ConstraintSynthesizer<Fr>,
) -> Result<Groth16Proof, ZkvmError> {
    let mut rng = test_rng();
    let proof = create_random_proof(circuit, pk, &mut rng)
        .map_err(|e| ZkvmError::Other(format!("groth16_prove: {e}")))?;
    Ok(Groth16Proof { inner: proof })
}

/// 验证 Groth16 proof。
pub fn groth16_verify(
    vk: &Groth16VerifyingKey,
    public_inputs: &[Fr],
    proof: &Groth16Proof,
) -> Result<bool, ZkvmError> {
    let pvk = prepare_verifying_key(vk);
    let result = verify_proof(&pvk, &proof.inner, public_inputs)
        .map_err(|e| ZkvmError::Other(format!("groth16_verify: {e}")))?;
    Ok(result)
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

#### 测试电路（验证 Groth16 pipeline 闭环）

在 `groth16_compress.rs` 测试模块中定义一个简单电路验证 setup→prove→verify 闭环：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

    /// 简单测试电路：证明知道 x 使得 x^3 + x + 5 = public_output
    #[derive(Clone)]
    struct TestCircuit {
        x: Option<Fr>,
        public_output: Fr,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = FpVar::<Fr>::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let public_output = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.public_output))?;
            // x^3 + x + 5 == public_output
            let x3 = x.square()?;
            let x3 = x3.mul(&x)?;
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
        let result = groth16_compress_stub_check();
        assert!(result.is_err());
    }

    fn groth16_compress_stub_check() -> Result<Groth16Proof, ZkvmError> {
        Err(ZkvmError::Other(
            "groth16_compress: HypernovaVerifierCircuit 未实现（Phase D）".to_string(),
        ))
    }
}
```

**注意**：原 stub 测试 `test_groth16_compress_returns_pending_error` 需更新为检查 "Phase D" 而非 "Phase 12"。

---

## Assumptions & Decisions

1. **Phase C 范围**：仅实现 Groth16 基础设施（API + gadgets + 测试电路），不实现 `HypernovaVerifierCircuit`（Phase D）。
2. **`groth16_compress` 状态**：Phase C 保留为错误返回，但错误消息从 "Phase 12 pending" 改为 "HypernovaVerifierCircuit 未实现（Phase D）"。底层 `groth16_setup/prove/verify` API 完整可用。
3. **测试电路**：用 `x^3 + x + 5 = y` 简单电路验证 Groth16 pipeline 闭环，不依赖 HypernovaProof。
4. **R1CS gadgets 范围**：Phase C 实现 G1 点加法/标量乘法/MSM/fold commitment check。Poseidon hash gadget 推迟到 Phase D（因 Hypernova verifier 的 transcript challenge 由外部原生计算，电路仅需验证数学关系，不需在电路内重算 Poseidon）。
5. **依赖版本**：所有 ark-* 依赖统一 0.6 版本，与现有 `ark-bn254`/`ark-ff`/`ark-ec` 一致。
6. **`ark-groth16` std feature**：需启用 `std` 以获得 `generate_random_parameters`/`create_random_proof` API。
7. **向后兼容**：所有改动是增量式的，既有测试和 API 不受影响。原 `groth16_compress` stub 测试更新错误消息匹配。
8. **Phase D 渐进策略**（后续）：先 N=16（小规模 IPA）验证 R1CS 电路正确性，再扩展到 N=512（生产规模）。

## Verification Steps

### Step 0 验证（Phase A2）
```bash
cd /Users/mac/projects/zchain
cargo test -p poker_zkvm --lib poseidon            # MVP + full mode 全部通过
cargo test -p poker_zkvm --lib ccs_builder         # 无回归
cargo test -p poker_zkvm --lib precompiles         # 无回归
cargo clippy -p poker_zkvm --all-targets           # 零警告
cargo bench -p poker_zkvm --no-run                 # 编译通过
cargo test -p poker_l1 --lib                       # L1 无回归
```

### Step C1 验证（依赖）
```bash
cargo build -p poker_zkvm                          # 新依赖编译通过，无版本冲突
```

### Step C2 验证（R1CS gadgets）
```bash
cargo test -p poker_zkvm --lib r1cs_gadgets        # G1 运算 + MSM gadget 测试通过
cargo test -p poker_zkvm --lib recursion           # 递归模块无回归
```

### Step C3 验证（Groth16 API）
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

实现 `ark_relations::r1cs::ConstraintSynthesizer`，编码 Hypernova verifier 步骤：
1. 每个 fold step：fold commitment 等式 `C' = C_L + r·C_C`（用 `r1cs_gadgets::fold_commitment_check`）
2. sumcheck final check（域算术，用 `FpVar` 线性约束）
3. IPA opening 验证：重算 challenges + `G_final` MSM（用 `r1cs_gadgets::msm_gadget`，N=512 点，~1.3M 约束）

**关键优化**：transcript challenges 由外部原生计算后作为 witness 提供，电路仅验证数学关系。

### Step D2：接入 CycleFold 框架

修改 `src/recursion/mod.rs:267`：
```rust
// 替换: let aggregated_proof = left.proof().clone();
let circuit = HypernovaVerifierCircuit::new(left.proof(), right.proof())?;
let groth16_proof = groth16_prove(&pk, circuit)?;
```

### Step D3：扩展 proof 格式

引入 `CompressedProof` 枚举，修改 `verifier.rs` 添加 Groth16 验证路径。

### Phase D 风险

- **高**：IPA MSM 约束数 ~1.3M。先从 N=16 测试用例开始，验证后再扩展到 N=512。
- **中**：transcript challenge 重算需严格匹配 prover 端逻辑。
- **中**：CompressedProof 枚举需向后兼容既有 Hypernova proof 验证。

---

## 执行策略

1. **立即**：运行 Step 0（Phase A2 验证套件）
2. **A2 通过后**：依次执行 C1 → C2 → C3
3. **每个 Step 完成后**：运行对应验证命令
4. **Phase C 完成后**：返回最终报告，Phase D 留待下一会话
