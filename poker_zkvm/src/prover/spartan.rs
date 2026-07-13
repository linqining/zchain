//! Spartan 压缩(Phase 7 — Task 7.2)。
//!
//! 将 HypernovaProof 压缩为更小的 Spartan SNARK proof(≤10KB)。
//!
//! ## 算法
//!
//! Spartan 是透明(无 trusted setup)的 ZK proof,利用 sumcheck + IPA 直接证明 CCS
//! 可满足性。HypernovaProof 已含 final sumcheck + PCS opening,Spartan 压缩提取
//! 这些材料 + 最终 LCCCS 公共数据,丢弃所有中间 fold_steps。
//!
//! 1. 原生验证 fold commitment 链(fast fail,与 groth16_compress 一致)
//! 2. 提取 final sumcheck + PCS opening + 最终 LCCCS 公共数据
//! 3. 返回 `CompressedProof::Spartan`
//!
//! ## 压缩效果
//!
//! - HypernovaProof:~2.4MB(N-1 个 fold_steps,每个含完整 sumcheck proof + CCCCS 数据)
//! - SpartanProof:~6-7KB(final sumcheck ~4KB + IPA opening ~1.3KB + LCCCS 公共数据 ~1KB)
//!
//! ## 信任模型
//!
//! - 压缩时:原生验证整个 fold commitment 链 → fast fail
//! - 压缩后:Spartan proof 密码学证明最终 LCCCS 满足(sumcheck + IPA verify)
//! - 与 Native variant 区别:Native 仅存 commitment(信任压缩时验证);
//!   Spartan 存 sumcheck + PCS proof(verifier 可密码学验证最终 LCCCS 满足)

use crate::ccs::{Ccs, Fr};
use crate::error::ZkvmError;
use crate::fold::fold_loop::HypernovaProof;
use crate::fold::sumcheck::{self, SumcheckProof};
use crate::pcs::Pcs;
use crate::pcs::ipa::{IpaCommitment, IpaEval, IpaPcs, IpaProof};
use crate::prover::groth16_compress::CompressedProof;
use crate::transcript::Transcript;

/// Spartan proof ABI 版本（写入 header）。
pub const SPARTAN_ABI_VERSION: u8 = 1;

/// Spartan 压缩 proof — 含 final sumcheck + PCS opening + 最终 LCCCS 公共数据。
///
/// verifier 通过 `spartan_verify` 重放 sumcheck + IPA verify 即可密码学验证
/// 最终 folded LCCCS 满足 relaxed CCS 约束,无需重新验证 fold 链。
///
/// **CCS 来源**：proof 仅含 `ccs_commitment`（32B），完整 CCS 结构由 verifier 从
/// `ccs_registry: &[Ccs]` 注册表按 commitment 查找（生产 CCS ~1.9MB，无法内嵌到 64KB proof）。
#[derive(Debug, Clone)]
pub struct SpartanCompressedProof {
    /// CCS 结构承诺(32B Blake2b),verifier 用于从 ccs_registry 查找 CCS。
    pub ccs_commitment: [u8; 32],
    /// public_io 承诺(32B Blake2b),verifier 用于 public_io 绑定校验。
    pub public_io_commitment: [u8; 32],
    /// 最终 folded witness commitment C'(PCS verify 用)。
    pub final_witness_commitment: IpaCommitment,
    /// 最终 LCCCS 的 u_l(= actual_u_prime,sumcheck claimed sum)。
    pub final_u_l: Fr,
    /// 最终 LCCCS 的 r_x_l(sumcheck verify 用)。
    pub final_r_x_l: Vec<Fr>,
    /// final sumcheck 证明(外层 + 内层)。
    pub final_sumcheck: SumcheckProof,
    /// PCS opening 证明(IPA 在 r_y 处打开 z')。
    pub pcs_opening: IpaProof,
    /// 内层 sumcheck 产生的 r_y(PCS opening 点)。
    pub r_y: Vec<Fr>,
    /// z'(r_y) — PCS opening 值。
    pub z_at_r_y: Fr,
    /// fold 步数(用于约束数估算)。
    pub fold_step_count: usize,
}

/// 将 HypernovaProof 压缩为 Spartan proof。
///
/// # 流程
/// 1. `extract_fold_chain` 提取 fold commitment 链
/// 2. `HypernovaVerifierCircuitBN254::verify_native` 原生验证(fast fail)
/// 3. 提取 final LCCCS + final sumcheck + PCS opening
/// 4. 返回 `CompressedProof::Spartan`
///
/// # 参数
/// - `proof` — HypernovaProof
///
/// # 返回
/// [`CompressedProof::Spartan`] 若 fold commitment 链验证通过;否则返回错误。
///
/// # 错误
/// - `extract_fold_chain` 失败(transcript 重放错误)
/// - `verify_native` 失败或返回 false(fold commitment 链不满足)
pub fn spartan_compress(proof: &HypernovaProof) -> Result<CompressedProof, ZkvmError> {
    use crate::recursion::hypernova_verifier_circuit::{
        HypernovaVerifierCircuitBN254, extract_fold_chain,
    };

    // 1. 提取 fold chain + 原生验证(fast fail,与 groth16_compress 一致)
    let (fold_steps, initial, final_cmt) = extract_fold_chain(proof)?;
    let circuit = HypernovaVerifierCircuitBN254 {
        initial_commitment: Some(initial),
        final_commitment: Some(final_cmt),
        fold_steps,
    };
    if !circuit.verify_native()? {
        return Err(ZkvmError::Other(
            "spartan_compress: fold commitment 链验证失败(约束不满足)".to_string(),
        ));
    }

    // 2. 提取最终 LCCCS + final sumcheck + PCS opening
    let (final_witness_commitment, final_u_l, final_r_x_l) = if proof.fold_steps.is_empty() {
        // 单实例路径:final = initial(fold_loop 已将 initial_lcccs.u_l 修正为 actual_u_prime)
        (
            proof.initial_witness_commitment.clone(),
            proof.initial_lcccs.u_l,
            proof.initial_lcccs.r_x_l.clone(),
        )
    } else {
        // 多实例路径:final = last fold step
        let last = proof.fold_steps.last().expect("fold_steps 非空(已校验)");
        (
            last.folded_witness_commitment.clone(),
            last.folded_lcccs.u_l,
            last.folded_lcccs.r_x_l.clone(),
        )
    };

    // 3. 构造 SpartanCompressedProof（不含 CCS — verifier 从 ccs_registry 查找）
    Ok(CompressedProof::Spartan(Box::new(SpartanCompressedProof {
        ccs_commitment: proof.ccs_commitment,
        public_io_commitment: proof.public_io_commitment,
        final_witness_commitment,
        final_u_l,
        final_r_x_l,
        final_sumcheck: proof.final_sumcheck.clone(),
        pcs_opening: proof.pcs_opening.clone(),
        r_y: proof.r_y.clone(),
        z_at_r_y: proof.z_at_point,
        fold_step_count: proof.fold_steps.len(),
    })))
}

/// 验证 Spartan 压缩 proof。
///
/// # 流程
/// 1. fresh `Transcript::new()`(与 fold_loop 的 sumcheck transcript 一致)
/// 2. `sumcheck::verify` 验证 final sumcheck
/// 3. `pcs.verify` 验证 PCS opening(同一 transcript,链式)
///
/// # 参数
/// - `proof` — SpartanCompressedProof
/// - `ccs` — CCS 结构(从 ccs_commitment 白名单查找)
/// - `pcs` — IPA PCS
///
/// # 返回
/// `true` 若 sumcheck + PCS opening 均验证通过。
pub fn spartan_verify(
    proof: &SpartanCompressedProof,
    ccs: &Ccs,
    pcs: &IpaPcs,
) -> Result<bool, ZkvmError> {
    // 1. fresh transcript(与 fold_loop 的 sumcheck transcript 和 verify_hypernova 一致)
    let mut transcript = Transcript::new();

    // 2. 验证 final sumcheck
    let sumcheck_valid = sumcheck::verify(
        &proof.final_sumcheck,
        ccs,
        &proof.final_r_x_l,
        proof.final_u_l,
        proof.z_at_r_y,
        &mut transcript,
    )?;
    if !sumcheck_valid {
        return Ok(false);
    }

    // 3. 验证 PCS opening(同一 transcript,链式 — 与 prover 的 PCS opening transcript 匹配)
    let pcs_eval = IpaEval(proof.z_at_r_y);
    let pcs_valid = pcs.verify(
        &proof.final_witness_commitment,
        &proof.r_y,
        &pcs_eval,
        &proof.pcs_opening,
        &mut transcript,
    )?;

    Ok(pcs_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccs::SparseMatrix;
    use crate::field::ZkvmField;
    use crate::fold::fold_loop::fold_loop;
    use crate::pcs::{MultilinearPoly, Pcs};
    use crate::transcript::{HYPERNOVA_FOLD_DOMAIN_TAG, Transcript};
    use ark_bn254::G1Affine;
    use ark_ec::AffineRepr;

    /// 辅助:构造 Fr。
    fn f(v: u32) -> Fr {
        Fr::from_u32_with_wrap(v)
    }

    /// 辅助:构造负 Fr。
    fn neg_f(v: u32) -> Fr {
        Fr::zero().sub(&f(v))
    }

    /// 构造线性 CCS — x - y = 0(1 row, 4 vars, 2 matrices)
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

    /// 构造合法 HypernovaProof(单实例 fold_loop,与 groth16_compress 测试一致)。
    fn make_valid_proof() -> (Ccs, HypernovaProof, IpaPcs) {
        let ccs = make_linear_ccs();
        let pcs = IpaPcs::new(4).expect("IpaPcs");

        let z_l = vec![f(1), f(5), f(5), f(0)];
        let z_c = vec![f(1), f(3), f(3), f(0)];
        let poly_l = MultilinearPoly::from_evals(z_l.clone()).unwrap();
        let poly_c = MultilinearPoly::from_evals(z_c.clone()).unwrap();
        let cmt_l = pcs.commit(&poly_l).unwrap();
        let cmt_c = pcs.commit(&poly_c).unwrap();

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

        (ccs, proof, pcs)
    }

    #[test]
    fn test_spartan_compress_valid_proof() {
        // 合法 HypernovaProof → Spartan 压缩 → 验证通过
        let (ccs, proof, pcs) = make_valid_proof();

        let compressed = spartan_compress(&proof).expect("spartan_compress 应成功");
        match &compressed {
            CompressedProof::Spartan(spartan) => {
                assert_eq!(spartan.fold_step_count, 1, "fold_step_count 应 = 1");
                assert_eq!(spartan.ccs_commitment, proof.ccs_commitment);
                assert_eq!(spartan.public_io_commitment, proof.public_io_commitment);

                // 端到端验证
                let valid = spartan_verify(spartan, &ccs, &pcs).expect("spartan_verify 应成功");
                assert!(valid, "Spartan proof 应验证通过");
            }
            _ => panic!("应返回 Spartan 变体"),
        }
    }

    #[test]
    fn test_spartan_compress_tampered_commitment() {
        // 篡改 fold commitment → spartan_compress 返回错误(fast fail)
        let (_ccs, mut proof, _pcs) = make_valid_proof();

        // 篡改 folded_witness_commitment:替换为 generator 点
        proof.fold_steps[0].folded_witness_commitment = IpaCommitment(G1Affine::generator());

        let result = spartan_compress(&proof);
        assert!(
            result.is_err(),
            "篡改 fold commitment 应导致 spartan_compress 失败"
        );
    }

    #[test]
    fn test_spartan_verify_tampered_sumcheck() {
        // 篡改 Spartan proof 的 sumcheck → spartan_verify 失败
        let (ccs, proof, pcs) = make_valid_proof();
        let compressed = spartan_compress(&proof).expect("spartan_compress 应成功");

        match &compressed {
            CompressedProof::Spartan(spartan) => {
                // 篡改 final_u_l(claimed sum)
                let mut tampered = spartan.clone();
                tampered.final_u_l = tampered.final_u_l.add(&Fr::one());

                let result = spartan_verify(&tampered, &ccs, &pcs).expect("verify 应执行");
                assert!(!result, "篡改 final_u_l 应验证失败");
            }
            _ => panic!("应返回 Spartan 变体"),
        }
    }

    #[test]
    fn test_spartan_proof_size_under_10kb() {
        // Spartan proof 序列化后 ≤ 10KB
        // 通过估算各组件大小验证(无需完整序列化实现)
        let (_ccs, proof, _pcs) = make_valid_proof();
        let compressed = spartan_compress(&proof).expect("spartan_compress 应成功");

        match &compressed {
            CompressedProof::Spartan(spartan) => {
                // 估算序列化大小:
                // - ccs_commitment: 32B
                // - public_io_commitment: 32B
                // - final_witness_commitment: 32B(compressed G1Affine)
                // - final_u_l: 32B
                // - final_r_x_l: len * 32B(len = log2(num_rows) = 0 for 1-row CCS)
                // - final_sumcheck: outer_round_polys + v_pp + inner_round_polys
                // - pcs_opening: l_vec + r_vec + a_final
                // - r_y: len * 32B
                // - z_at_r_y: 32B
                // - fold_step_count: 8B

                let mut size = 0usize;
                size += 32; // ccs_commitment
                size += 32; // public_io_commitment
                size += 32; // final_witness_commitment (compressed G1Affine)
                size += 32; // final_u_l
                size += spartan.final_r_x_l.len() * 32; // final_r_x_l
                // final_sumcheck: outer_round_polys (m rounds × (D+1) evals) + v_pp (t) + inner_round_polys (n rounds × 3)
                size += spartan
                    .final_sumcheck
                    .outer_round_polys
                    .iter()
                    .map(|r| r.len() * 32)
                    .sum::<usize>();
                size += spartan.final_sumcheck.v_pp.len() * 32;
                size += spartan
                    .final_sumcheck
                    .inner_round_polys
                    .iter()
                    .map(|r| r.len() * 32)
                    .sum::<usize>();
                // pcs_opening: l_vec + r_vec (each log2(N) G1Affine = 32B) + a_final (32B)
                size += spartan.pcs_opening.l_vec.len() * 32;
                size += spartan.pcs_opening.r_vec.len() * 32;
                size += 32; // a_final
                size += spartan.r_y.len() * 32; // r_y
                size += 32; // z_at_r_y
                size += 8; // fold_step_count

                // 对于 1-row CCS(num_rows=1, num_vars=4),proof 很小
                // 实际生产场景(num_rows=2^20, num_vars=2^20)约 6-7KB
                assert!(
                    size <= 10_000,
                    "Spartan proof 估算大小 {} 应 ≤ 10KB(10000B)",
                    size
                );
                eprintln!("Spartan proof 估算大小: {}B", size);
            }
            _ => panic!("应返回 Spartan 变体"),
        }
    }
}
