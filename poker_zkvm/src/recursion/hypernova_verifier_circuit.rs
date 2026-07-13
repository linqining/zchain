//! HypernovaVerifierCircuit — Grumpkin R1CS 电路(Phase D — Step D1)。
//!
//! 实现 `ConstraintSynthesizer<Fq>` 电路,验证 Hypernova proof 的 fold commitment 链。
//!
//! ## 设计原理
//!
//! ark-grumpkin 0.6.0 不实现 `Pairing` trait,无法使用 `Groth16::<Grumpkin>`。
//! 本电路采用 **Grumpkin R1CS 电路 + 原生约束满足性验证**:
//! - 在 `ConstraintSystem<Fq>` 中工作(Grumpkin 标量域 = BN254 基域)
//! - BN254 G1 点坐标 ∈ Fq → `G1Var` 原生表示
//! - BN254 标量 r ∈ Fr → `ScalarVar = EmulatedFpVar<Fr, Fq>` 非原生模拟
//! - 复用 Phase C 的 [`r1cs_gadgets::fold_commitment_check`]
//!
//! ## 验证范围
//!
//! Phase D 仅验证 **fold commitment 链**:对每步 fold,约束 `C' = C_L + r·C_C`。
//! 完整 verifier(sumcheck + PCS + transcript 一致性)推迟到 Phase 12/13。
//!
//! ## 约束数估算
//!
//! - 每步 fold:`scalar_mul` ~2500 + `point_add` ~800 + `enforce_equal` ~200 ≈ 3500 约束
//! - 典型 3 步 fold:~10500 约束(远小于 spec L589 的 100k-200k)

use ark_bn254::{Fq, Fr, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_r1cs_std::prelude::*;
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::CanonicalSerialize;

use crate::ccs::Fr as ZkvmFr;
use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;
use crate::pcs::ipa::IpaCommitment;
use crate::recursion::r1cs_gadgets::{G1Var, ScalarVar, fold_commitment_check};
use crate::transcript::{HYPERNOVA_FOLD_DOMAIN_TAG, Transcript};

/// 将 G1Affine 压缩序列化为字节(匹配 verifier.rs / fold_step.rs 的 point_to_bytes)。
fn point_to_bytes(p: &ark_bn254::G1Affine) -> Vec<u8> {
    let mut bytes = Vec::new();
    p.serialize_compressed(&mut bytes)
        .expect("G1Affine serialize_compressed 不应失败");
    bytes
}

/// 单步 fold 的电路数据(从 HypernovaProof 提取)。
///
/// 每步 fold 对应一个 `C' = C_L + r·C_C` 约束。
#[derive(Debug, Clone)]
pub struct FoldStepCircuitData {
    /// 当前 LCCCS 的 witness commitment `C_L`(projective 形式)。
    pub c_l: G1Projective,
    /// CCCCS 的 witness commitment `C_C`。
    pub c_c: G1Projective,
    /// fold challenge `r`(Fr 标量,在 Fq CS 中模拟)。
    pub r: Fr,
    /// folded witness commitment `C'`。
    pub c_prime: G1Projective,
}

/// HypernovaVerifierCircuit — Grumpkin R1CS 电路(`ConstraintSynthesizer<Fq>`)。
///
/// 验证 fold commitment 链:对每步 fold,约束 `C' = C_L + r·C_C`。
///
/// ## 公共输入
///
/// - `initial_commitment` — 初始 witness commitment(绑定 proof 到实例)
/// - `final_commitment` — 最终 folded witness commitment
///
/// ## Witness
///
/// 每步 fold 的 `c_l`、`c_c`、`r`、`c_prime`(除首步 `c_l` = initial,末步 `c_prime` = final)。
///
/// ## 链式约束
///
/// - step[0].c_l == initial_commitment
/// - step[i].c_prime == step[i+1].c_l(中间步骤链式)
/// - step[last].c_prime == final_commitment
#[derive(Debug, Clone)]
pub struct HypernovaVerifierCircuit {
    /// 初始 witness commitment(public input)。
    pub initial_commitment: Option<G1Projective>,
    /// 最终 witness commitment(public input)。
    pub final_commitment: Option<G1Projective>,
    /// fold 步骤数据(witness)。
    pub fold_steps: Vec<FoldStepCircuitData>,
}

impl HypernovaVerifierCircuit {
    /// 原生约束满足性验证(D2 的 `groth16_compress` 使用)。
    ///
    /// 构造 `ConstraintSystem<Fq>`,生成约束,返回 `is_satisfied()`。
    pub fn verify_native(&self) -> Result<bool, ZkvmError> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        self.clone().generate_constraints(cs.clone()).map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuit: generate_constraints failed: {e}"
            ))
        })?;
        cs.is_satisfied().map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuit: is_satisfied failed: {e}"
            ))
        })
    }
}

impl ConstraintSynthesizer<Fq> for HypernovaVerifierCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        // 1. 分配公共输入:initial_commitment + final_commitment
        let initial_var = G1Var::new_input(cs.clone(), || {
            self.initial_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let final_var = G1Var::new_input(cs.clone(), || {
            self.final_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. 单实例路径(fold_steps 为空):initial == final
        if self.fold_steps.is_empty() {
            initial_var.enforce_equal(&final_var)?;
            return Ok(());
        }

        // 3. 逐步验证 fold commitment 链
        let mut prev_c_prime_var: Option<G1Var> = None;

        for (i, step) in self.fold_steps.iter().enumerate() {
            // (a) 分配 witness:c_l, c_c, r, c_prime
            let c_l_var = G1Var::new_witness(cs.clone(), || Ok(step.c_l))?;
            let c_c_var = G1Var::new_witness(cs.clone(), || Ok(step.c_c))?;
            let r_var = ScalarVar::new_witness(cs.clone(), || Ok(step.r))?;
            let c_prime_var = G1Var::new_witness(cs.clone(), || Ok(step.c_prime))?;

            // (b) 链式约束:step[0].c_l == initial;step[i>0].c_l == prev.c_prime
            if i == 0 {
                c_l_var.enforce_equal(&initial_var)?;
            } else if let Some(prev) = &prev_c_prime_var {
                c_l_var.enforce_equal(prev)?;
            }

            // (c) fold commitment 等式:C' == C_L + r·C_C
            fold_commitment_check(&c_prime_var, &c_l_var, &c_c_var, &r_var)?;

            prev_c_prime_var = Some(c_prime_var);
        }

        // 4. 末步 c_prime == final_commitment
        if let Some(last_c_prime) = &prev_c_prime_var {
            last_c_prime.enforce_equal(&final_var)?;
        }

        Ok(())
    }
}

/// 从 HypernovaProof 提取 fold commitment 链数据。
///
/// 重放 transcript(镜像 [`verifier.rs:143-159`] 的 absorb 顺序)派生每步 fold challenge `r`,
/// 构造 `Vec<FoldStepCircuitData>` + 初始/最终 commitment。
///
/// # 参数
/// - `proof` — HypernovaProof
///
/// # 返回
/// `(fold_steps, initial_commitment, final_commitment)`
///
/// # 错误
/// - `num_rows` 非 2 的幂(transcript 派生失败)
pub fn extract_fold_chain(
    proof: &HypernovaProof,
) -> Result<(Vec<FoldStepCircuitData>, G1Projective, G1Projective), ZkvmError> {
    // 1. 重放主 transcript(匹配 verifier.rs:108-130 的 absorb 顺序)
    let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
    // (a) absorb public_io_commitment
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.public_io_commitment);
    // (b) absorb ccs_commitment
    transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
    // (c) absorb 所有 batch_public_inputs
    for group in &proof.batch_public_inputs {
        for pi in group {
            transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
        }
    }
    // (d) 派生 r_x_l(长度 = log2(num_rows))
    let num_rows = proof.initial_lcccs.ccs_ref.num_rows();
    if num_rows == 0 || !num_rows.is_power_of_two() {
        return Err(ZkvmError::Other(format!(
            "extract_fold_chain: num_rows = {num_rows} 非 2 的幂"
        )));
    }
    let r_x_l_len = num_rows.trailing_zeros() as usize;
    for _ in 0..r_x_l_len {
        let _ = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);
    }

    // 2. 逐步派生 fold challenge(匹配 verifier.rs:143-159 的 absorb 顺序)
    let mut steps = Vec::with_capacity(proof.fold_steps.len());
    let mut current_commitment = proof.initial_witness_commitment.0.into_group();
    let mut current_lcccs = proof.initial_lcccs.clone();

    for step in &proof.fold_steps {
        // (a) 重放 fold absorb
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&IpaCommitment(current_commitment.into_affine()).0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.u_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.r_x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &current_lcccs.v_l);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&step.ccccs_witness_commitment.0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_u_c);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_x_c);

        // (b) 派生 fold challenge r
        let r: ZkvmFr = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

        steps.push(FoldStepCircuitData {
            c_l: current_commitment,
            c_c: step.ccccs_witness_commitment.0.into_group(),
            r: r.into_fr(),
            c_prime: step.folded_witness_commitment.0.into_group(),
        });

        // (c) 推进
        current_commitment = step.folded_witness_commitment.0.into_group();
        current_lcccs = step.folded_lcccs.clone();
    }

    let initial = proof.initial_witness_commitment.0.into_group();
    let final_cmt = current_commitment;

    Ok((steps, initial, final_cmt))
}

/// HypernovaVerifierCircuitBN254 — BN254 R1CS 电路（`ConstraintSynthesizer<Fr>`）。
///
/// 与 [`HypernovaVerifierCircuit`]（Fq-based，用于 Grumpkin）对称，但在 BN254 标量域 Fr 中工作，
/// 可直接接入 `Groth16::<Bn254>` 生成真实 SNARK proof。
///
/// ## 设计原理
///
/// - 在 `ConstraintSystem<Fr>` 中工作
/// - BN254 G1 点坐标 ∈ Fq → 用 `G1VarBN254`（`EmulatedFpVar<Fq, Fr>`）非原生模拟
/// - BN254 标量 r ∈ Fr → 用 `FrVar`（`FpVar<Fr>`）原生表示
/// - 复用 [`extract_fold_chain`] 提取 fold 链数据
/// - 复用 [`r1cs_gadgets_bn254::fold_commitment_check_bn254`]
///
/// ## 约束数估算
///
/// 非原生点运算比 Fq-based 开销大（EmulatedFpVar 开销）：
/// - 每步 fold：~33000 约束（vs Fq-based ~3500）
/// - 典型 3 步 fold：~99000 约束
///
/// ## 公共输入
///
/// - `initial_commitment` — 初始 witness commitment
/// - `final_commitment` — 最终 folded witness commitment
#[derive(Debug, Clone)]
pub struct HypernovaVerifierCircuitBN254 {
    /// 初始 witness commitment（public input）。
    pub initial_commitment: Option<G1Projective>,
    /// 最终 witness commitment（public input）。
    pub final_commitment: Option<G1Projective>,
    /// fold 步骤数据（witness）。
    pub fold_steps: Vec<FoldStepCircuitData>,
}

impl HypernovaVerifierCircuitBN254 {
    /// 原生约束满足性验证。
    ///
    /// 构造 `ConstraintSystem<Fr>`，生成约束，返回 `is_satisfied()`。
    pub fn verify_native(&self) -> Result<bool, ZkvmError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone()).map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: generate_constraints failed: {e}"
            ))
        })?;
        cs.is_satisfied().map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: is_satisfied failed: {e}"
            ))
        })
    }

    /// 提取公共输入的 Fr 表示（用于 groth16_verify）。
    ///
    /// 构造临时 `ConstraintSystem<Fr>`，运行 `generate_constraints`，
    /// 通过 `instance_assignment()` 提取所有 public input 的 Fr 值。
    ///
    /// `instance_assignment()` 返回 `[Fr::one(), input1, input2, ...]`（首项为
    /// Groth16 常量项），但 `groth16_verify` 期望 public_inputs **不含**前导
    /// `Fr::one()`（`prepare_inputs` 内部会添加）。因此 `.skip(1)` 跳过常量项。
    ///
    /// 返回的 `Vec<Fr>` 顺序与 `G1VarBN254::new_input` 的 allocation 顺序一致：
    /// `[initial_commitment_limbs..., final_commitment_limbs...]`
    pub fn public_inputs_to_fr(&self) -> Result<Vec<Fr>, ZkvmError> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        self.clone().generate_constraints(cs.clone()).map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: generate_constraints for public inputs failed: {e}"
            ))
        })?;
        let full = cs.instance_assignment().map_err(|e| {
            ZkvmError::Other(format!(
                "HypernovaVerifierCircuitBN254: instance_assignment failed: {e}"
            ))
        })?;
        Ok(full.into_iter().skip(1).collect())
    }
}

impl ConstraintSynthesizer<Fr> for HypernovaVerifierCircuitBN254 {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use crate::recursion::r1cs_gadgets_bn254::{
            FrVar, G1VarBN254, fold_commitment_check_bn254,
        };

        // 1. 分配公共输入:initial_commitment + final_commitment
        let initial_var = G1VarBN254::new_input(cs.clone(), || {
            self.initial_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let final_var = G1VarBN254::new_input(cs.clone(), || {
            self.final_commitment
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. 单实例路径(fold_steps 为空):initial == final
        if self.fold_steps.is_empty() {
            initial_var.enforce_equal(&final_var)?;
            return Ok(());
        }

        // 3. 逐步验证 fold commitment 链
        let mut prev_c_prime_var: Option<G1VarBN254> = None;

        for (i, step) in self.fold_steps.iter().enumerate() {
            // (a) 分配 witness:c_l, c_c, r, c_prime
            let c_l_var = G1VarBN254::new_witness(cs.clone(), || Ok(step.c_l))?;
            let c_c_var = G1VarBN254::new_witness(cs.clone(), || Ok(step.c_c))?;
            let r_var = FrVar::new_witness(cs.clone(), || Ok(step.r))?;
            let c_prime_var = G1VarBN254::new_witness(cs.clone(), || Ok(step.c_prime))?;

            // (b) 链式约束:step[0].c_l == initial;step[i>0].c_l == prev.c_prime
            if i == 0 {
                c_l_var.enforce_equal(&initial_var)?;
            } else if let Some(prev) = &prev_c_prime_var {
                c_l_var.enforce_equal(prev)?;
            }

            // (c) fold commitment 等式:C' == C_L + r·C_C
            fold_commitment_check_bn254(&c_prime_var, &c_l_var, &c_c_var, &r_var)?;

            prev_c_prime_var = Some(c_prime_var);
        }

        // 4. 末步 c_prime == final_commitment
        if let Some(last_c_prime) = &prev_c_prime_var {
            last_c_prime.enforce_equal(&final_var)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::{Ccs, Fr, SparseMatrix};
    use crate::field::ZkvmField;
    use crate::fold::fold_loop::fold_loop;
    use crate::pcs::ipa::{IpaCommitment, IpaPcs};
    use crate::pcs::{MultilinearPoly, Pcs};
    use crate::transcript::Transcript;
    use ark_ec::CurveGroup;
    use ark_ff::One;
    use ark_std::{UniformRand, test_rng};

    /// 辅助:构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助:构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 使用 IPA 计算实际 witness commitment。
    fn commit_witness(pcs: &IpaPcs, z: &[Fr]) -> IpaCommitment {
        let poly = MultilinearPoly::from_evals(z.to_vec()).expect("MultilinearPoly 构造应成功");
        pcs.commit(&poly).expect("pcs.commit 应成功")
    }

    /// 构造线性 CCS — x - y = 0(1 row, 4 vars, 2 matrices)。
    fn make_linear_ccs() -> Ccs {
        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs 构造应成功")
    }

    /// 构造 IPA PCS(max_n_vars = 4)。
    fn make_ipa_pcs() -> IpaPcs {
        IpaPcs::new(4).expect("IpaPcs 构造应成功")
    }

    /// 生成单步 fold 的 HypernovaProof(使用真实 IPA commitment)。
    /// 匹配 prover/mod.rs:813-872 的 transcript 初始化流程。
    fn make_single_fold_proof(pcs: &IpaPcs, seed: u32) -> HypernovaProof {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(seed), f(seed), f(0)];
        let z_c = vec![f(1), f(seed + 1), f(seed + 1), f(0)];
        let cmt_l = commit_witness(pcs, &z_l);
        let cmt_c = commit_witness(pcs, &z_c);

        // 匹配 prover/mod.rs:813-841:transcript 初始化 + absorb + r_x_l 派生
        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<Fr>> = vec![vec![]];

        let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &ccs_commitment);
        for group in &batch_public_inputs {
            for pi in group {
                transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
            }
        }
        // 派生 r_x_l(长度 = log2(num_rows));num_rows=1 → r_x_l_len=0 → r_x_l 为空
        let num_rows = ccs.num_rows();
        let r_x_l_len = num_rows.trailing_zeros() as usize;
        let r_x_l: Vec<Fr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, r_x_l, cmt_c).expect("to_cccs");

        fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop 应成功")
    }

    /// 生成 3 步 fold 的 HypernovaProof。
    /// 匹配 prover/mod.rs:813-872 的 transcript 初始化流程。
    fn make_multi_fold_proof(pcs: &IpaPcs, seed: u32) -> HypernovaProof {
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(seed), f(seed), f(0)];
        let cmt_l = commit_witness(pcs, &z_l);

        // 匹配 prover/mod.rs:813-841:transcript 初始化 + absorb + r_x_l 派生
        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<Fr>> = vec![vec![]];

        let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &ccs_commitment);
        for group in &batch_public_inputs {
            for pi in group {
                transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
            }
        }
        let num_rows = ccs.num_rows();
        let r_x_l_len = num_rows.trailing_zeros() as usize;
        let r_x_l: Vec<Fr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");

        let mut ccccs_list = Vec::new();
        for i in 0..3u32 {
            let s = seed + i + 1;
            let z_c = vec![f(1), f(s), f(s), f(0)];
            let cmt_c = commit_witness(pcs, &z_c);
            let ccccs = ccs.to_cccs(&z_c, r_x_l.clone(), cmt_c).expect("to_cccs");
            ccccs_list.push(ccccs);
        }

        fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &ccccs_list,
            pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop 应成功")
    }

    // ===== 测试 1: 空fold_steps(单实例路径) =====

    #[test]
    fn test_empty_fold_steps() {
        // 构造单实例 proof(fold_steps 为空)
        let pcs = make_ipa_pcs();
        let ccs = make_linear_ccs();
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let cmt_l = commit_witness(&pcs, &z_l);

        // 匹配 prover/mod.rs:813-841 的 transcript 初始化流程
        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<Fr>> = vec![vec![]];

        let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &public_io_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &ccs_commitment);
        for group in &batch_public_inputs {
            for pi in group {
                transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
            }
        }
        let num_rows = ccs.num_rows();
        let r_x_l_len = num_rows.trailing_zeros() as usize;
        let r_x_l: Vec<Fr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");

        let proof = fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[],
            &pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop 应成功");

        assert!(proof.fold_steps.is_empty());

        // 电路:initial == final(单实例路径)
        let (steps, initial, final_cmt) = extract_fold_chain(&proof).expect("extract_fold_chain");
        assert!(steps.is_empty());
        assert_eq!(initial.into_affine(), final_cmt.into_affine());

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            circuit.verify_native().expect("verify_native 应成功"),
            "空 fold_steps(initial == final)应 satisfied"
        );
    }

    // ===== 测试 2: 单步fold合法 =====

    #[test]
    fn test_single_fold_valid() {
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);

        let (steps, initial, final_cmt) = extract_fold_chain(&proof).expect("extract_fold_chain");
        assert_eq!(steps.len(), 1);

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            circuit.verify_native().expect("verify_native 应成功"),
            "合法单步 fold 应 satisfied"
        );
    }

    // ===== 测试 3: 篡改C' =====

    #[test]
    fn test_single_fold_tampered_c_prime() {
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);

        let (mut steps, initial, final_cmt) =
            extract_fold_chain(&proof).expect("extract_fold_chain");
        // 篡改 c_prime:替换为随机点
        let mut rng = test_rng();
        steps[0].c_prime = G1Projective::rand(&mut rng);

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            !circuit.verify_native().expect("verify_native 应成功"),
            "篡改 C' 应导致 CS 不满足"
        );
    }

    // ===== 测试 4: 篡改C_C =====

    #[test]
    fn test_single_fold_tampered_c_c() {
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);

        let (mut steps, initial, final_cmt) =
            extract_fold_chain(&proof).expect("extract_fold_chain");
        // 篡改 c_c:替换为随机点
        let mut rng = test_rng();
        steps[0].c_c = G1Projective::rand(&mut rng);

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            !circuit.verify_native().expect("verify_native 应成功"),
            "篡改 C_C 应导致 CS 不满足"
        );
    }

    // ===== 测试 5: 多步fold合法 =====

    #[test]
    fn test_multi_fold_valid() {
        let pcs = make_ipa_pcs();
        let proof = make_multi_fold_proof(&pcs, 1);

        let (steps, initial, final_cmt) = extract_fold_chain(&proof).expect("extract_fold_chain");
        assert_eq!(steps.len(), 3);

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            circuit.verify_native().expect("verify_native 应成功"),
            "合法 3 步 fold 链应 satisfied"
        );
    }

    // ===== 测试 6: 多步fold链断裂 =====

    #[test]
    fn test_multi_fold_broken_chain() {
        let pcs = make_ipa_pcs();
        let proof = make_multi_fold_proof(&pcs, 1);

        let (mut steps, initial, final_cmt) =
            extract_fold_chain(&proof).expect("extract_fold_chain");
        assert_eq!(steps.len(), 3);
        // 破坏中间链:篡改 step[1].c_l(应等于 step[0].c_prime)
        let mut rng = test_rng();
        steps[1].c_l = G1Projective::rand(&mut rng);

        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            !circuit.verify_native().expect("verify_native 应成功"),
            "中间链断裂应导致 CS 不满足"
        );
    }

    // ===== 测试 7: extract_fold_chain 派生的 fold challenge 与 verifier 一致 =====

    #[test]
    fn test_extract_fold_chain_matches_verifier() {
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);

        let (steps, _, _) = extract_fold_chain(&proof).expect("extract_fold_chain");
        assert_eq!(steps.len(), 1);

        // 独立重放 transcript 派生 fold challenge(镜像 verifier.rs:143-162)
        let mut transcript = Transcript::with_domain(b"poker_zkvm_prover_v1");
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.public_io_commitment);
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
        for group in &proof.batch_public_inputs {
            for pi in group {
                transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, pi);
            }
        }
        let num_rows = proof.initial_lcccs.ccs_ref.num_rows();
        let r_x_l_len = num_rows.trailing_zeros() as usize;
        for _ in 0..r_x_l_len {
            let _ = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);
        }

        // 重放 step 0 的 fold absorb
        let step = &proof.fold_steps[0];
        transcript.absorb(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.ccs_commitment);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&proof.initial_witness_commitment.0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.initial_lcccs.u_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.initial_lcccs.x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.initial_lcccs.r_x_l);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &proof.initial_lcccs.v_l);
        transcript.absorb(
            HYPERNOVA_FOLD_DOMAIN_TAG,
            &point_to_bytes(&step.ccccs_witness_commitment.0),
        );
        transcript.absorb_field(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_u_c);
        transcript.absorb_field_slice(HYPERNOVA_FOLD_DOMAIN_TAG, &step.ccccs_x_c);

        let expected_r: ZkvmFr = transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG);

        // extract_fold_chain 派生的 r 应与独立重放一致
        assert_eq!(
            steps[0].r,
            expected_r.into_fr(),
            "extract_fold_chain 派生的 fold challenge 应与 verifier 一致"
        );
    }

    // ===== 测试 8: 公共输入绑定 =====

    #[test]
    fn test_public_inputs_binding() {
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);

        let (steps, initial, final_cmt) = extract_fold_chain(&proof).expect("extract_fold_chain");

        // 公共输入应与 proof 的 commitment 一致
        assert_eq!(
            initial.into_affine(),
            proof.initial_witness_commitment.0,
            "initial_commitment 应 = proof.initial_witness_commitment"
        );
        assert_eq!(
            final_cmt.into_affine(),
            proof.fold_steps[0].folded_witness_commitment.0,
            "final_commitment 应 = 最后一步的 folded_witness_commitment"
        );

        // 篡改公共输入(initial)应导致 CS 不满足
        let mut rng = test_rng();
        let wrong_initial = G1Projective::rand(&mut rng);
        let circuit = HypernovaVerifierCircuit {
            initial_commitment: Some(wrong_initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };
        assert!(
            !circuit.verify_native().expect("verify_native 应成功"),
            "篡改 initial_commitment 应导致 CS 不满足"
        );
    }

    // ===== 测试 9: public_inputs_to_fr 格式验证（F-2 修复）=====

    #[test]
    fn test_public_inputs_to_fr_skips_leading_one() {
        // 验证 public_inputs_to_fr() 不含前导 Fr::one()（Groth16 常量项）。
        // groth16_verify 的 prepare_inputs 内部会添加 Fr::one()，
        // 若 public_inputs 已含前导 one 会导致输入偏移、验证失败。
        let pcs = make_ipa_pcs();
        let proof = make_single_fold_proof(&pcs, 1);
        let (steps, initial, final_cmt) = extract_fold_chain(&proof).expect("extract_fold_chain");
        let circuit = HypernovaVerifierCircuitBN254 {
            initial_commitment: Some(initial),
            final_commitment: Some(final_cmt),
            fold_steps: steps,
        };

        // 构造 CS 获取 num_instance_variables（含前导 Fr::one()）
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit
            .clone()
            .generate_constraints(cs.clone())
            .expect("generate_constraints");
        let num_instance_vars = cs.num_instance_variables();

        // 约束数打印（用于性能分析）
        eprintln!("num_constraints = {}", cs.num_constraints());
        eprintln!(
            "num_instance_variables = {} (含前导 Fr::one())",
            num_instance_vars
        );

        let public_inputs = circuit.public_inputs_to_fr().expect("public_inputs_to_fr");

        // num_instance_variables 包含前导 Fr::one()（Groth16 常量项），
        // public_inputs_to_fr 已 skip(1)，所以长度应 = num_instance_vars - 1
        assert_eq!(
            public_inputs.len(),
            num_instance_vars - 1,
            "public_inputs_to_fr 长度应 = num_instance_variables - 1（skip 前导 Fr::one()）"
        );

        // 首元素不应是 Fr::one()（Groth16 常量项应被 skip）
        assert_ne!(
            public_inputs[0],
            ark_bn254::Fr::one(),
            "public_inputs 首元素不应是 Fr::one()（Groth16 常量项应被 skip）"
        );
    }
}
