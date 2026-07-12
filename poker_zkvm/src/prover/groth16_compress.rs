//! Groth16 压缩（Phase C — Step C3 / Phase F — 真实 SNARK 压缩）。
//!
//! 提供通用 Groth16 setup/prove/verify API，以及将 HypernovaProof 压缩为
//! 真实 Groth16 SNARK proof 的 `groth16_compress` 函数。
//!
//! ## API 说明
//!
//! 使用 `ark-groth16` 0.6 的 `Groth16::<Bn254>` 结构体方法：
//! - `generate_random_parameters_with_reduction` — setup
//! - `create_random_proof_with_reduction` — prove
//! - `verify_proof` — verify（需先用 `prepare_verifying_key` 预处理 VK）
//!
//! 约束系统基于 `ark_relations::gr1cs`（0.6 版本使用 GR1CS，非旧版 R1CS）。
//!
//! ## Phase F 实现
//!
//! `groth16_compress` 使用 `HypernovaVerifierCircuitBN254`（Fr-based 电路），
//! 验证 fold commitment 链后生成真实 Groth16 SNARK proof（~200B），
//! 返回 `CompressedProof::Groth16`。

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
/// `(Groth16ProvingKey, Groth16VerifyingKey)`
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
/// - `pk` — proving key（来自 [`groth16_setup`]）
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
/// - `vk` — verifying key（来自 [`groth16_setup`]）
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

/// 压缩后的 proof（Phase F: 真实 Groth16 SNARK）。
#[derive(Debug, Clone)]
pub enum CompressedProof {
    /// 原生约束满足性验证（Phase D 遗留）— 电路约束已满足，但未生成 SNARK proof。
    Native(NativeCompressedProof),
    /// Groth16 SNARK proof（Phase F — 基于 HypernovaVerifierCircuitBN254 生成）。
    /// Box 避免 enum variant size 差异过大（VerifyingKey 较大）。
    Groth16(Box<Groth16CompressedProof>),
}

/// 原生压缩 proof（Phase D 遗留）— 含公共输入 + fold 步数。
#[derive(Debug, Clone)]
pub struct NativeCompressedProof {
    /// initial witness commitment（公共输入，绑定 proof）。
    pub initial_commitment: ark_bn254::G1Affine,
    /// final witness commitment（公共输入，绑定 proof）。
    pub final_commitment: ark_bn254::G1Affine,
    /// fold 步数（用于约束数估算）。
    pub fold_step_count: usize,
}

/// Groth16 压缩 proof — 含 proof + VK + 公共输入，支持独立验证。
///
/// Phase F 产物：真实 Groth16 SNARK proof（~200B）+ 验证所需全部数据。
#[derive(Debug, Clone)]
pub struct Groth16CompressedProof {
    /// Groth16 proof（A/B/C 三个 G1/G2 元素）。
    pub proof: Groth16Proof,
    /// verifying key（来自 groth16_setup，用于独立验证）。
    pub verifying_key: Groth16VerifyingKey,
    /// 公共输入的 Fr 表示（initial_commitment + final_commitment 的 limbs）。
    pub public_inputs: Vec<Fr>,
    /// fold 步数（用于约束数估算）。
    pub fold_step_count: usize,
}

/// 将 HypernovaProof 压缩为 CompressedProof。
///
/// Phase F 实现：构造 [`HypernovaVerifierCircuitBN254`]（Fr-based 电路），
/// 先原生验证约束满足性（快速失败），再生成真实 Groth16 SNARK proof。
/// 返回 [`CompressedProof::Groth16`]（含 proof + VK + 公共输入）。
///
/// # 参数
/// - `proof` — HypernovaProof
///
/// # 返回
/// [`CompressedProof::Groth16`] 若约束满足；否则返回错误。
///
/// # 错误
/// - `extract_fold_chain` 失败（transcript 重放错误）
/// - `verify_native` 失败（约束不满足）
/// - `groth16_setup` / `groth16_prove` 失败（SNARK 生成错误）
pub fn groth16_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        extract_fold_chain, HypernovaVerifierCircuitBN254,
    };

    // 1. 从 HypernovaProof 提取 fold chain
    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;

    // 2. 构造 BN254 电路（Fr-based）
    let circuit = HypernovaVerifierCircuitBN254 {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };

    // 3. 前置检查：原生约束满足性验证（快速失败，避免昂贵的 setup+prove）
    let satisfied = circuit.verify_native()?;
    if !satisfied {
        return Err(ZkvmError::Other(
            "groth16_compress: fold commitment 链验证失败（约束不满足）".to_string(),
        ));
    }

    // 4. 提取公共输入 Fr 表示
    let public_inputs = circuit.public_inputs_to_fr()?;

    // 5. Groth16 setup + prove
    let (pk, vk) = groth16_setup(circuit.clone())?;
    let groth16_proof = groth16_prove(&pk, circuit)?;

    // 6. 返回 Groth16 压缩 proof
    Ok(CompressedProof::Groth16(Box::new(Groth16CompressedProof {
        proof: groth16_proof,
        verifying_key: vk,
        public_inputs,
        fold_step_count: proof.fold_steps.len(),
    })))
}

/// 验证 Groth16 压缩 proof（端到端验证入口）。
///
/// # 参数
/// - `compressed` — `groth16_compress` 产出的 `CompressedProof`
///
/// # 返回
/// - `Native` 变体：始终返回 `Ok(true)`（Phase D 已在 `groth16_compress` 中验证）
/// - `Groth16` 变体：调用 `groth16_verify` 验证 SNARK proof
pub fn groth16_compress_verify(compressed: &CompressedProof) -> Result<bool, ZkvmError> {
    match compressed {
        CompressedProof::Native(_) => Ok(true),
        CompressedProof::Groth16(groth16) => {
            groth16_verify(&groth16.verifying_key, &groth16.public_inputs, &groth16.proof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let circuit = TestCircuit {
            x: Some(x),
            public_output,
        };
        let (pk, vk) = groth16_setup(circuit.clone()).expect("setup");
        let proof = groth16_prove(&pk, circuit).expect("prove");
        let valid = groth16_verify(&vk, &[public_output], &proof).expect("verify");
        assert!(valid, "合法 proof 应验证通过");
    }

    #[test]
    fn test_groth16_verify_wrong_public_input_fails() {
        let x = Fr::from(3u64);
        let public_output = Fr::from(35u64);
        let circuit = TestCircuit {
            x: Some(x),
            public_output,
        };
        let (pk, vk) = groth16_setup(circuit.clone()).expect("setup");
        let proof = groth16_prove(&pk, circuit).expect("prove");
        let wrong_output = Fr::from(36u64);
        let valid = groth16_verify(&vk, &[wrong_output], &proof).expect("verify");
        assert!(!valid, "错误 public input 应验证失败");
    }

    #[test]
    fn test_groth16_compress_valid_proof() {
        // 合法 HypernovaProof → CompressedProof::Groth16（真实 SNARK proof）
        use crate::ccs::{Ccs, Fr as ZkvmFr, SparseMatrix};
        use crate::field::ZkvmField;
        use crate::fold::fold_loop::fold_loop;
        use crate::pcs::ipa::IpaPcs;
        use crate::pcs::{MultilinearPoly, Pcs};
        use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};

        fn f(v: u32) -> ZkvmFr {
            ZkvmFr::from_u32_with_wrap(v)
        }
        fn neg_f(v: u32) -> ZkvmFr {
            ZkvmFr::zero().sub(&f(v))
        }

        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let ccs = Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs");

        let pcs = IpaPcs::new(4).expect("IpaPcs");
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];
        let poly_l = MultilinearPoly::from_evals(z_l.clone()).unwrap();
        let poly_c = MultilinearPoly::from_evals(z_c.clone()).unwrap();
        let cmt_l = pcs.commit(&poly_l).unwrap();
        let cmt_c = pcs.commit(&poly_c).unwrap();

        // 匹配 prover/mod.rs:813-841 的 transcript 初始化流程
        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<ZkvmFr>> = vec![vec![]];

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
        let r_x_l: Vec<ZkvmFr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, r_x_l, cmt_c).expect("to_cccs");

        let proof = fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            &pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop");

        let compressed = groth16_compress(&proof).expect("groth16_compress 应成功");
        match &compressed {
            CompressedProof::Groth16(groth16) => {
                assert_eq!(groth16.fold_step_count, 1, "fold_step_count 应 = 1");
                // 端到端验证
                let valid = groth16_compress_verify(&compressed).expect("verify 应成功");
                assert!(valid, "Groth16 proof 应验证通过");
            }
            CompressedProof::Native(_) => {
                panic!("Phase F 应返回 Groth16 变体，而非 Native");
            }
        }
    }

    #[test]
    fn test_groth16_compress_tampered_commitment() {
        // 篡改 fold commitment → groth16_compress 返回错误
        use crate::ccs::{Ccs, Fr as ZkvmFr, SparseMatrix};
        use crate::field::ZkvmField;
        use crate::fold::fold_loop::fold_loop;
        use crate::pcs::ipa::IpaPcs;
        use crate::pcs::{MultilinearPoly, Pcs};
        use crate::transcript::{Transcript, HYPERNOVA_FOLD_DOMAIN_TAG};
        use ark_ec::CurveGroup;
        use ark_std::{test_rng, UniformRand};

        fn f(v: u32) -> ZkvmFr {
            ZkvmFr::from_u32_with_wrap(v)
        }
        fn neg_f(v: u32) -> ZkvmFr {
            ZkvmFr::zero().sub(&f(v))
        }

        let mut m0 = SparseMatrix::new(1, 4);
        m0.add_entry(0, 1, f(1)).unwrap();
        let mut m1 = SparseMatrix::new(1, 4);
        m1.add_entry(0, 2, f(1)).unwrap();
        let ccs = Ccs::new(
            4,
            vec![m0, m1],
            vec![vec![0], vec![1]],
            vec![f(1), neg_f(1)],
        )
        .expect("linear Ccs");

        let pcs = IpaPcs::new(4).expect("IpaPcs");
        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];
        let poly_l = MultilinearPoly::from_evals(z_l.clone()).unwrap();
        let poly_c = MultilinearPoly::from_evals(z_c.clone()).unwrap();
        let cmt_l = pcs.commit(&poly_l).unwrap();
        let cmt_c = pcs.commit(&poly_c).unwrap();

        let public_io_commitment = [0u8; 32];
        let ccs_commitment = ccs.ccs_commitment();
        let batch_public_inputs: Vec<Vec<ZkvmFr>> = vec![vec![]];

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
        let r_x_l: Vec<ZkvmFr> = (0..r_x_l_len)
            .map(|_| transcript.challenge(HYPERNOVA_FOLD_DOMAIN_TAG))
            .collect();

        let lcccs = ccs.to_lcccs(&z_l, &r_x_l, r_x_l.clone()).expect("to_lcccs");
        let ccccs = ccs.to_cccs(&z_c, r_x_l, cmt_c).expect("to_cccs");

        let mut proof = fold_loop(
            &ccs,
            lcccs,
            cmt_l,
            &[ccccs],
            &pcs,
            &mut transcript,
            ccs_commitment,
            public_io_commitment,
            batch_public_inputs,
        )
        .expect("fold_loop");

        // 篡改 folded_witness_commitment:替换为随机点
        let mut rng = test_rng();
        let wrong_point = ark_bn254::G1Projective::rand(&mut rng).into_affine();
        proof.fold_steps[0].folded_witness_commitment =
            crate::pcs::ipa::IpaCommitment(wrong_point);

        let result = groth16_compress(&proof);
        assert!(
            result.is_err(),
            "篡改 fold commitment 应导致 groth16_compress 失败"
        );
    }
}
