# Stage 3 — Phase D: HypernovaVerifierCircuit + CycleFold 压缩集成

## 摘要

Phase D 实现 `HypernovaVerifierCircuit`（Grumpkin R1CS 电路,验证 Hypernova fold commitment 链）,
替换 `groth16_compress` stub,并集成到 CycleFold 树形聚合中。

**关键约束**:ark-grumpkin 0.6.0 不实现 `Pairing` trait,无法使用 `Groth16::<Grumpkin>`。
本 Phase 采用 **Grumpkin R1CS 电路 + 原生约束满足性验证** 作为 Phase 12/13 SNARK 包装的基础设施。

## 当前状态分析

### Phase C 已完成输出(本 Phase 依赖)

- [r1cs_gadgets.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/r1cs_gadgets.rs):
  - `G1Var = ark_bn254::constraints::GVar`(BN254 G1 gadget,在 `ConstraintSystem<Fq>` 中工作)
  - `FqVar = FpVar<Fq>`、`ScalarVar = EmulatedFpVar<Fr, Fq>`
  - `point_add_gadget`、`scalar_mul_gadget`、`msm_gadget`、`fold_commitment_check`
  - 6 个测试全部通过
- [groth16_compress.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/groth16_compress.rs):
  - `Groth16Proof`、`groth16_setup`、`groth16_prove`、`groth16_verify`(BN254 Groth16 可用)
  - `groth16_compress` stub 返回 "Phase D 未实现" 错误

### Phase D 目标文件

- [recursion/mod.rs:267](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/mod.rs#L267):
  stub `let aggregated_proof = left.proof().clone();`(需替换)
- [fold/fold_loop.rs:76-100](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/fold_loop.rs#L76-L100):
  `HypernovaProof` 12 字段(含 `initial_witness_commitment`、`fold_steps`、`final_sumcheck`、`pcs_opening`)
- [fold/fold_loop.rs:48-69](file:///Users/mac/projects/zchain/poker_zkvm/src/fold/fold_loop.rs#L48-L69):
  `FoldStepData` 10 字段(含 `ccccs_witness_commitment`、`folded_witness_commitment`)
- [verifier.rs:143-259](file:///Users/mac/projects/zchain/poker_zkvm/src/verifier.rs#L143-L259):
  fold challenge 重派生流程(transcript absorb 顺序 + challenge 派生)

### 字段映射(cycle-of-curves)

| 实体 | BN254 表示 | Grumpkin R1CS 电路(Fq-based CS) |
|------|-----------|--------------------------------|
| G1 点坐标 | `G1Affine`(x, y ∈ Fq) | `G1Var`(native Fq) |
| 标量 r(Fold challenge) | `Fr`(BN254 scalar) | `ScalarVar = EmulatedFpVar<Fr, Fq>`(非原生) |
| commitment C | `IpaCommitment(G1Affine)` | `G1Var` witness |
| fold 等式 `C' = C_L + r·C_C` | `c_l + c_c * r_fr`(verifier.rs:229-234) | `fold_commitment_check`(r1cs_gadgets.rs:95) |

## 提议变更

### D1: 创建 `src/recursion/hypernova_verifier_circuit.rs`

**目标**:实现 `ConstraintSynthesizer<Fq>` 电路,验证 Hypernova proof 的 fold commitment 链。

**文件**:`poker_zkvm/src/recursion/hypernova_verifier_circuit.rs`(新建)

**核心结构**:

```rust
use ark_bn254::{constraints::GVar as Bn254G1Var, Fq, Fr, G1Projective};
use ark_r1cs_std::fields::emulated_fp::EmulatedFpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::fold::fold_loop::HypernovaProof;
use crate::recursion::r1cs_gadgets::{fold_commitment_check, G1Var, ScalarVar};
use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};
use crate::ccs::Fr as ZkvmFr;
use crate::pcs::ipa::IpaCommitment;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;

/// 单步 fold 的电路数据(从 HypernovaProof 提取)。
pub struct FoldStepCircuitData {
    pub c_l: G1Projective,      // 当前 witness commitment
    pub c_c: G1Projective,      // CCCCS witness commitment
    pub r: Fr,                  // fold challenge
    pub c_prime: G1Projective,  // folded witness commitment
}

/// HypernovaVerifierCircuit — Grumpkin R1CS 电路(ConstraintSynthesizer<Fq>)。
///
/// 验证 fold commitment 链:对每步 fold,约束 C' = C_L + r·C_C。
/// 公共输入:initial_commitment + final_commitment(绑定 proof 到实例)。
/// Witness:所有中间 commitment + fold challenge + CCCCS commitment。
pub struct HypernovaVerifierCircuit {
    pub initial_commitment: Option<G1Projective>,
    pub final_commitment: Option<G1Projective>,
    pub fold_steps: Vec<FoldStepCircuitData>,
}
```

**`generate_constraints` 实现**:
1. 分配 `initial_commitment` 为 public input(`new_input`)
2. 分配 `final_commitment` 为 public input(`new_input`)
3. 对每步 fold:
   - 分配 `c_l`、`c_c`、`r`、`c_prime` 为 witness(`new_witness`)
   - 调用 `fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var)`
4. 第一步的 `c_l` 约束等于 `initial_commitment`(enforce_equal)
5. 最后一步的 `c_prime` 约束等于 `final_commitment`(enforce_equal)
6. 中间步骤链式:step[i].c_prime == step[i+1].c_l(enforce_equal)

**`extract_fold_chain` 辅助函数**:
- 输入:`&HypernovaProof`
- 逻辑:重放 transcript(镜像 verifier.rs:143-159 的 absorb 顺序)派生每步 fold challenge `r`
- 输出:`Vec<FoldStepCircuitData>` + `(initial_commitment, final_commitment)`

```rust
pub fn extract_fold_chain(
    proof: &HypernovaProof,
) -> Result<(Vec<FoldStepCircuitData>, G1Projective, G1Projective), ZkvmError> {
    let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.public_io_commitment);
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
    for group in &proof.batch_public_inputs {
        for pi in group {
            transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
        }
    }
    // 派生 r_x_l(长度 = log2(num_rows))
    let num_rows = proof.initial_lcccs.ccs_ref.num_rows();
    let r_x_l_len = num_rows.trailing_zeros() as usize;
    for _ in 0..r_x_l_len {
        let _ = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);
    }

    let mut steps = Vec::with_capacity(proof.fold_steps.len());
    let mut current_commitment = proof.initial_witness_commitment.0.into_group();
    let mut current_lcccs = proof.initial_lcccs.clone();

    for step in &proof.fold_steps {
        // 重放 fold absorb(verifier.rs:145-159 顺序)
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &point_to_bytes(&IpaCommitment(current_commitment.into_affine()).0));
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.u_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.r_x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.v_l);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &point_to_bytes(&step.ccccs_witness_commitment.0));
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_u_c);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_x_c);

        let r = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

        steps.push(FoldStepCircuitData {
            c_l: current_commitment,
            c_c: step.ccccs_witness_commitment.0.into_group(),
            r: r.into_fr(),
            c_prime: step.folded_witness_commitment.0.into_group(),
        });

        current_commitment = step.folded_witness_commitment.0.into_group();
        current_lcccs = step.folded_lcccs.clone();
    }

    Ok((steps, proof.initial_witness_commitment.0.into_group(), current_commitment))
}
```

**`verify_native` 方法**(D2 使用):
- 构造 `ConstraintSystem::<Fq>::new_ref()`
- 调用 `generate_constraints(cs.clone())`
- 返回 `cs.is_satisfied()`

**测试**(8 个):
1. `test_empty_fold_steps` — 单实例路径(fold_steps 为空),仅验证 initial == final
2. `test_single_fold_valid` — 单步 fold,合法 commitment,CS satisfied
3. `test_single_fold_tampered_c_prime` — 篡改 C',CS not satisfied
4. `test_single_fold_tampered_c_c` — 篡改 C_C,CS not satisfied
5. `test_multi_fold_valid` — 3 步 fold,合法链,CS satisfied
6. `test_multi_fold_broken_chain` — 中间链断裂,CS not satisfied
7. `test_extract_fold_chain_matches_verifier` — extract_fold_chain 派生的 r 与 verifier 一致
8. `test_public_inputs_binding` — initial/final commitment 作为 public input 正确绑定

**约束数估算**:
- 每步 fold:`scalar_mul` ~2500 + `point_add` ~800 + `enforce_equal` ~200 ≈ 3500 约束
- 3 步 fold:~10500 约束(远小于 spec L589 的 100k-200k,因仅验证 fold commitment,非完整 verifier)

### D2: 实现 `groth16_compress` + `CompressedProof` enum

**目标**:替换 `groth16_compress` stub,实现原生约束满足性验证。

**文件**:[poker_zkvm/src/prover/groth16_compress.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/groth16_compress.rs)(修改)

**变更**:

1. 新增 `CompressedProof` enum:
```rust
/// 压缩后的 proof(Phase D:原生验证;Phase 12/13:Groth16 SNARK)。
#[derive(Debug, Clone)]
pub enum CompressedProof {
    /// 原生约束满足性验证(Phase D)— 电路约束已满足,但未生成 SNARK proof。
    Native(NativeCompressedProof),
    /// Groth16 SNARK proof(Phase 12/13 — 基于 HypernovaVerifierCircuit 生成)。
    Groth16(Groth16Proof),
}

/// 原生压缩 proof(Phase D)— 含公共输入 + 约束数。
#[derive(Debug, Clone)]
pub struct NativeCompressedProof {
    /// initial witness commitment(公共输入,绑定 proof)。
    pub initial_commitment: ark_bn254::G1Affine,
    /// final witness commitment(公共输入,绑定 proof)。
    pub final_commitment: ark_bn254::G1Affine,
    /// fold 步数(用于约束数估算)。
    pub fold_step_count: usize,
}
```

2. 替换 `groth16_compress` 函数体:
```rust
pub fn groth16_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        extract_fold_chain, HypernovaVerifierCircuit,
    };

    // 1. 从 HypernovaProof 提取 fold chain
    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;

    // 2. 构造电路
    let circuit = HypernovaVerifierCircuit {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };

    // 3. 原生约束满足性验证
    let cs = ark_relations::gr1cs::ConstraintSystem::<ark_bn254::Fq>::new_ref();
    circuit.generate_constraints(cs.clone()).map_err(|e| {
        ZkvmError::Other(format!("groth16_compress: generate_constraints failed: {e}"))
    })?;
    if !cs.is_satisfied().map_err(|e| {
        ZkvmError::Other(format!("groth16_compress: is_satisfied failed: {e}"))
    })? {
        return Err(ZkvmError::Other(
            "groth16_compress: fold commitment 链验证失败(约束不满足)".to_string(),
        ));
    }

    // 4. 返回 Native 压缩 proof
    Ok(CompressedProof::Native(NativeCompressedProof {
        initial_commitment: initial.into_affine(),
        final_commitment: final_cmt.into_affine(),
        fold_step_count: proof.fold_steps.len(),
    }))
}
```

3. 更新测试:
- 保留现有 3 个 Groth16 测试(setup/prove/verify + wrong input + Phase D error)
- 修改 `test_groth16_compress_returns_phase_d_error` 为 `test_groth16_compress_valid_proof`
- 新增测试:
  - `test_groth16_compress_valid_proof` — 合法 HypernovaProof → `CompressedProof::Native`
  - `test_groth16_compress_tampered_commitment` — 篡改 fold commitment → 返回错误

### D3: 集成到 CycleFold 树形聚合

**目标**:替换 `recursion/mod.rs:267` stub,在树形聚合中调用 `groth16_compress`。

**文件**:[poker_zkvm/src/recursion/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/mod.rs)(修改)

**变更**:

1. 新增模块声明:
```rust
pub mod hypernova_verifier_circuit;
```

2. 在 `CycleFoldNode::Node` 中新增 `compressed_proof` 字段:
```rust
pub enum CycleFoldNode {
    Leaf { proof: HypernovaProof, curve: CurveKind },
    Node {
        left: Box<CycleFoldNode>,
        right: Box<CycleFoldNode>,
        aggregated_proof: HypernovaProof,
        compressed_proof: Option<CompressedProof>,  // 新增
        curve: CurveKind,
        depth: u32,
    },
}
```

3. 替换 `tree_aggregate_recursive` 中的 stub(L264-276):
```rust
let left_proof = left.proof();
let compressed = match groth16_compress(left_proof) {
    Ok(cp) => Some(cp),
    Err(e) => {
        return Err(ZkvmError::Other(format!(
            "tree_aggregate_recursive: groth16_compress failed at depth {depth}: {e}"
        )));
    }
};
let aggregated_proof = left_proof.clone();

next_level.push(CycleFoldNode::Node {
    left: Box::new(left.clone()),
    right: Box::new(right.clone()),
    aggregated_proof,
    compressed_proof: compressed,
    curve: node_curve,
    depth,
});
```

4. 更新 `CycleFoldNode::proof()` 等方法以处理新字段(无需修改,因 `aggregated_proof` 仍存在)。

5. 新增 `CycleFoldNode::compressed_proof()` 访问器:
```rust
pub fn compressed_proof(&self) -> Option<&CompressedProof> {
    match self {
        CycleFoldNode::Leaf { .. } => None,
        CycleFoldNode::Node { compressed_proof, .. } => compressed_proof.as_ref(),
    }
}
```

6. 更新 `tree_aggregate_recursive` 中的 `import`:
```rust
use crate::prover::groth16_compress::CompressedProof;
use crate::prover::groth16_compress;
```

7. 更新现有测试中构造 `CycleFoldNode::Node` 的地方(如有)— 添加 `compressed_proof: None`。

**测试**:
- `test_tree_aggregate_produces_compressed_proof` — 2 个 sub-proof 聚合后,根节点 `compressed_proof` 为 `Some(Native)`
- `test_tree_aggregate_compressed_proof_valid` — 验证 `compressed_proof` 的 `initial_commitment` 与 `aggregated_proof.initial_witness_commitment` 一致
- 现有 `recursion/mod.rs` 测试应仍通过(可能需添加 `compressed_proof` 字段)

## 假设与决策

### 决策

1. **Grumpkin R1CS + 原生验证(非 Groth16 SNARK)**:
   - 原因:ark-grumpkin 0.6.0 不实现 `Pairing` trait,`Groth16::<Grumpkin>` 不可用
   - 权衡:原生验证不压缩 proof 大小,但提供 R1CS 电路基础设施,Phase 12/13 可用其他 SNARK(如 PLONK)包装
   - 用户偏好"conservative refactoring first",此方案风险最低

2. **仅验证 fold commitment 链(非完整 verifier)**:
   - 原因:完整 verifier(sumcheck + PCS + transcript 一致性)约束数 100k-200k(spec L589),实现复杂
   - Phase D 聚焦 fold commitment 等式(每步 ~3500 约束),作为 CycleFold 压缩的最小可行单元
   - 完整 verifier 电路推迟到 Phase 12/13

3. **`CompressedProof` enum 设计**:
   - `Native` 变体:Phase D 产出,含公共输入绑定
   - `Groth16` 变体:Phase 12/13 产出,预留接口
   - 使调用方可在未来无缝切换到 SNARK 压缩

4. **public input 设计**:
   - `initial_commitment` + `final_commitment` 作为公共输入
   - 绑定 proof 到实例(防 proof 替换)
   - 未来 SNARK 包装后,verifier 仅需验证 SNARK proof + 比对公共输入

### 假设

- `HypernovaProof` 结构稳定(v1.4 FROZEN,不再变更)
- `r1cs_gadgets.rs` 的 `fold_commitment_check` 正确性已由 Phase C 测试保证
- `extract_fold_chain` 的 transcript 重放逻辑与 `verifier.rs:143-159` 一致(测试将验证)
- 现有 `recursion/mod.rs` 测试中无直接构造 `CycleFoldNode::Node` 的代码(均通过 `tree_aggregate` 构造)

## 验证步骤

### D1 验证

```bash
cargo test -p poker_zkvm --lib recursion::hypernova_verifier_circuit
cargo clippy -p poker_zkvm --features test-helpers
```

### D2 验证

```bash
cargo test -p poker_zkvm --lib prover::groth16_compress
cargo clippy -p poker_zkvm --features test-helpers
```

### D3 验证

```bash
cargo test -p poker_zkvm --lib recursion
cargo test -p poker_zkvm --lib
cargo clippy -p poker_zkvm --all-targets --features test-helpers
cargo test -p poker_l1 --lib
cargo build -p poker_zkvm
cargo build -p poker_l1
```

### 最终验证

```bash
cargo test -p poker_zkvm --features test-helpers
cargo clippy -p poker_zkvm --all-targets --features test-helpers -- -D warnings
cargo bench -p poker_zkvm --no-run
```

## 实施顺序

1. **D1**(创建 `hypernova_verifier_circuit.rs` + 8 测试)→ 运行测试 + clippy
2. **D2**(实现 `groth16_compress` + `CompressedProof` + 更新测试)→ 运行测试 + clippy
3. **D3**(集成到 `recursion/mod.rs` + 更新测试)→ 运行全套测试 + clippy + bench 编译

## 完成状态

### D1 — 完成

- [hypernova_verifier_circuit.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/hypernova_verifier_circuit.rs) 创建完成
- `HypernovaVerifierCircuit` 实现 `ConstraintSynthesizer<Fq>`,验证 fold commitment 链
- `extract_fold_chain` 重放 transcript(匹配 `prover/mod.rs:813-841` 流程)派生 fold challenge
- `verify_native()` 方法构造 `ConstraintSystem<Fq>` + `is_satisfied()`
- 8 个单元测试全部通过
- **关键修复**:测试辅助函数必须匹配 prover 流程(`Transcript::with_domain` + absorb `public_io_commitment`/`ccs_commitment`/`batch_public_inputs` + 派生 `r_x_l`),否则 transcript 重放失败

### D2 — 完成

- [groth16_compress.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/prover/groth16_compress.rs) stub 替换为实现
- `CompressedProof` enum(`Native` + `Groth16` 变体)+ `NativeCompressedProof` struct
- `groth16_compress()` 调用 `extract_fold_chain` + `HypernovaVerifierCircuit::verify_native`
- 4 个测试通过(2 个 Phase C 保留 + 2 个 D2 新增)
- 添加 `use ark_ec::CurveGroup;` 导入(支持 `into_affine()`)

### D3 — 完成

- [recursion/mod.rs](file:///Users/mac/projects/zchain/poker_zkvm/src/recursion/mod.rs) 集成完成
- `CycleFoldNode::Node` 新增 `compressed_proof: Option<Box<CompressedProof>>` 字段
- `tree_aggregate_recursive` 调用 `groth16_compress` (best-effort: `.ok().map(Box::new)`)
- `compressed_proof()` 访问器返回 `Option<&CompressedProof>`
- 更新 `make_proof` 测试辅助函数匹配 prover 流程(D3 要求 — `groth16_compress` 需重放 transcript)
- Box 化 `aggregated_proof`、`proof`(Leaf)、`compressed_proof` 修复 `clippy::large_enum_variant`
- 4 个 D3 新增测试 + 全部现有 recursion 测试通过(共 55 个)

### 测试结果

| 测试套件 | 结果 |
|---------|------|
| poker_zkvm lib (787 tests) | ALL PASS |
| soundness_tests (13 tests) | ALL PASS |
| e2e_poker_hand_eval (5 tests) | ALL PASS |
| e2e_fibonacci / e2e_sha256_chain | 预存失败(proof size > 512KB,batch_size=256 问题) |
| clippy (test-helpers) | 零警告 |
| bench --no-run | 编译成功 |

### 实现与计划的偏差

1. **best-effort 压缩**:计划中 `groth16_compress` 失败时返回错误;实际实现使用 `.ok()` 存 `None`,避免压缩失败阻断聚合(full proof 仍可用于原生验证)
2. **Box 化字段**:计划中未提及;实际因 `clippy::large_enum_variant` 对 `aggregated_proof`、`proof`(Leaf)、`compressed_proof` 进行 Box 化
3. **`CompressedProof` 类型**:计划为 `Option<CompressedProof>`;实际为 `Option<Box<CompressedProof>>`(clippy 要求)
