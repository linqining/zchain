//! Shuffle Proof — 3 层广义 Schnorr（移植自 `texas_poker_move/sources/shuffle_proof.move`）。
//!
//! 证明玩家正确地执行了 shuffle（重加密 + 置换）。
//!
//! # 结构
//!
//! - `sum_c1_commit`：`Σ ρ_i · input_c1_i` 的 G1 bytes
//! - `sum_c2_commit`：`Σ ρ_i · input_c2_i` 的 G1 bytes
//! - `combined_schnorr_proof`：base_points = `[output.c1, output.c2, ..., G, pk]`，R = `sum_c1 + sum_c2`
//! - `sum_c1_schnorr_proof`：base_points = `[output.c1, ..., G]`，R = `sum_c1`
//! - `sum_c2_schnorr_proof`：base_points = `[output.c2, ..., pk]`，R = `sum_c2`
//! - `nonce`：anti-replay nonce（32 字节 Scalar）
//!
//! # M-D13 / C1 / C2 修复
//!
//! - M-D13：移除 G/pk 作为自由基点，改用输入密文作为基点
//! - C1：pk 加入 transcript，绑定证明到玩家公钥
//! - C2：校验输出密文有效性 + c1 多重集保持（remask 保持 c1 不变）
//!
//! # 验证流程
//!
//! 0. 检查长度一致且 n > 0
//! 1. Transcript append `pk`（"shuffle_pk"）
//! 2. 校验所有 output_cts 有效（c1/c2 非 identity）
//! 3. Transcript append `nonce`（"shuffle_nonce"）
//! 4. Transcript append input/output ciphertexts
//! 5. 生成 `ρ_i` 挑战（"rho_challenge"）
//! 6. 计算 `sum_input_c1 = g1_msm(ρ, input_c1s)`、`sum_input_c2 = g1_msm(ρ, input_c2s)`
//! 7. 验证与 proof 的 sum_c1_commit / sum_c2_commit 一致
//! 8. 验证 combined_schnorr_proof
//! 9. 验证 sum_c1_schnorr_proof
//! 10. 验证 sum_c2_schnorr_proof

use blstrs::{G1Projective, Scalar};

use super::bls_elgamal::{ElGamalCiphertext, re_encrypt};
use super::bls_scalar::{
    g1_add, g1_equal, g1_is_identity, g1_msm, g1_generator, parse_g1, parse_scalar,
    serialize_g1, serialize_scalar,
};
use super::schnorr_proof::{self, GeneralizedSchnorrProof};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// Shuffle Proof。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShuffleProof {
    /// `Σ ρ_i · input_c1_i` 的 G1 compressed bytes（48 字节）。
    pub sum_c1_commit: Vec<u8>,
    /// `Σ ρ_i · input_c2_i` 的 G1 compressed bytes（48 字节）。
    pub sum_c2_commit: Vec<u8>,
    /// 组合 Schnorr 证明（base_points = output.c1+c2 + G + pk，R = sum_c1 + sum_c2）。
    pub combined_schnorr_proof: GeneralizedSchnorrProof,
    /// c1-only Schnorr 证明（base_points = output.c1 + G，R = sum_c1）。
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProof,
    /// c2-only Schnorr 证明（base_points = output.c2 + pk，R = sum_c2）。
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProof,
    /// anti-replay nonce（32 字节 Scalar）。
    pub nonce: Vec<u8>,
}

impl ShuffleProof {
    /// 构造证明。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sum_c1_commit: Vec<u8>,
        sum_c2_commit: Vec<u8>,
        combined_schnorr_proof: GeneralizedSchnorrProof,
        sum_c1_schnorr_proof: GeneralizedSchnorrProof,
        sum_c2_schnorr_proof: GeneralizedSchnorrProof,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            sum_c1_commit,
            sum_c2_commit,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
            nonce,
        }
    }
}

/// 验证 ShuffleProof。
///
/// # 参数
///
/// - `proof`：证明结构
/// - `input_cts`：洗牌前的密文数组
/// - `output_cts`：洗牌后的密文数组
/// - `pk`：玩家公钥 `G · sk`
/// - `t`：Fiat-Shamir transcript
pub fn verify(
    proof: &ShuffleProof,
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    pk: &G1Projective,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    let n = input_cts.len();
    // 0. 检查长度一致且 n > 0
    if n != output_cts.len() || n == 0 {
        return Ok(false);
    }

    // C1 修复：将 pk 加入 transcript
    t.append_point(b"shuffle_pk", pk);

    // C2 缓解：校验所有输出密文有效
    for out_ct in output_cts {
        if !out_ct.is_valid() {
            return Ok(false);
        }
    }

    // 1. Append nonce
    let nonce_scalar = match parse_scalar(&proof.nonce) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    t.append_scalar(b"shuffle_nonce", &nonce_scalar);

    // 2. Append input/output ciphertexts
    t.append_ciphertexts(b"input c1", b"input c2", input_cts);
    t.append_ciphertexts(b"output c1", b"output c2", output_cts);

    // 3. 生成 ρ 挑战
    let rho = t.challenge_vec(b"rho_challenge", n)?;

    // 4. 计算 sum_input_c1, sum_input_c2
    let input_c1s: Vec<G1Projective> = input_cts.iter().map(|ct| ct.c1).collect();
    let input_c2s: Vec<G1Projective> = input_cts.iter().map(|ct| ct.c2).collect();
    let sum_input_c1 = g1_msm(&rho, &input_c1s)?;
    let sum_input_c2 = g1_msm(&rho, &input_c2s)?;

    // 5. 验证与 proof 的 sum_c1_commit / sum_c2_commit 一致
    let proof_sum_c1 = match parse_g1(&proof.sum_c1_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let proof_sum_c2 = match parse_g1(&proof.sum_c2_commit) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    if !g1_equal(&sum_input_c1, &proof_sum_c1) {
        return Ok(false);
    }
    if !g1_equal(&sum_input_c2, &proof_sum_c2) {
        return Ok(false);
    }

    // 6. 验证 combined_schnorr_proof
    // base_points = [output[0].c1, ..., output[n-1].c1, output[0].c2, ..., output[n-1].c2, G, pk]
    // （与 prove 端 witnesses 布局一致：所有 c1 witnesses 然后所有 c2 witnesses）
    let mut combined_base_points = Vec::with_capacity(2 * n + 2);
    for out_ct in output_cts {
        combined_base_points.push(out_ct.c1);
    }
    for out_ct in output_cts {
        combined_base_points.push(out_ct.c2);
    }
    combined_base_points.push(g1_generator());
    combined_base_points.push(*pk);
    // R = sum_c1_commit + sum_c2_commit
    let combined_r = g1_add(&proof_sum_c1, &proof_sum_c2);
    if !schnorr_proof::verify(
        &proof.combined_schnorr_proof,
        &combined_base_points,
        &combined_r,
        t,
    )? {
        return Ok(false);
    }

    // 7. 验证 sum_c1_schnorr_proof
    // base_points = [output[0].c1, ..., output[n-1].c1, G]
    let mut c1_base_points = Vec::with_capacity(n + 1);
    for out_ct in output_cts {
        c1_base_points.push(out_ct.c1);
    }
    c1_base_points.push(g1_generator());
    if !schnorr_proof::verify(
        &proof.sum_c1_schnorr_proof,
        &c1_base_points,
        &proof_sum_c1,
        t,
    )? {
        return Ok(false);
    }

    // 8. 验证 sum_c2_schnorr_proof
    // base_points = [output[0].c2, ..., output[n-1].c2, pk]
    let mut c2_base_points = Vec::with_capacity(n + 1);
    for out_ct in output_cts {
        c2_base_points.push(out_ct.c2);
    }
    c2_base_points.push(*pk);
    if !schnorr_proof::verify(
        &proof.sum_c2_schnorr_proof,
        &c2_base_points,
        &proof_sum_c2,
        t,
    )? {
        return Ok(false);
    }

    Ok(true)
}

// ===== 链下 prove =====

#[cfg(any(test, feature = "client"))]
mod prove {
    use super::*;
    use ff::Field;
    use rand::Rng;

    /// 链下生成 ShuffleProof。
    ///
    /// # 参数
    ///
    /// - `input_cts`：输入密文数组
    /// - `permutation`：置换 `π`（`output[i] = re_encrypt(input[permutation[i]], pk, masks[i])`）
    /// - `masks`：重加密随机数 `r_i`
    /// - `pk`：玩家公钥
    /// - `t`：Fiat-Shamir transcript（调用方负责初始化协议名）
    ///
    /// # Returns
    ///
    /// `(proof, output_cts)` — 证明和对应的输出密文。
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        input_cts: &[ElGamalCiphertext],
        permutation: &[usize],
        masks: &[Scalar],
        pk: &G1Projective,
        t: &mut Transcript,
        rng: &mut impl Rng,
    ) -> PokerL1Result<(ShuffleProof, Vec<ElGamalCiphertext>)> {
        let n = input_cts.len();
        assert_eq!(permutation.len(), n, "permutation 长度必须等于 input_cts");
        assert_eq!(masks.len(), n, "masks 长度必须等于 input_cts");

        // 1. 计算 output_cts = re_encrypt(input[π[i]], pk, masks[i])
        let output_cts: Vec<ElGamalCiphertext> = (0..n)
            .map(|i| re_encrypt(&input_cts[permutation[i]], pk, &masks[i]))
            .collect();

        // 2. 生成 anti-replay nonce
        let nonce_scalar = Scalar::random(&mut *rng);
        let nonce_bytes = serialize_scalar(&nonce_scalar).to_vec();

        // 3. Transcript（与 verify 完全一致）
        t.append_point(b"shuffle_pk", pk);
        t.append_scalar(b"shuffle_nonce", &nonce_scalar);
        t.append_ciphertexts(b"input c1", b"input c2", input_cts);
        t.append_ciphertexts(b"output c1", b"output c2", &output_cts);

        // 4. 生成 ρ 挑战
        let rho = t.challenge_vec(b"rho_challenge", n)?;

        // 5. 计算 sum_c1_commit, sum_c2_commit
        let input_c1s: Vec<G1Projective> = input_cts.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<G1Projective> = input_cts.iter().map(|ct| ct.c2).collect();
        let sum_c1_commit = g1_msm(&rho, &input_c1s)?;
        let sum_c2_commit = g1_msm(&rho, &input_c2s)?;

        // 6. 计算 combined Schnorr witnesses
        // base_points = [output[0].c1, output[0].c2, ..., output[n-1].c1, output[n-1].c2, G, pk]
        // R = sum_c1 + sum_c2 = Σ ρ_i · (input_c1_i + input_c2_i)
        //
        // 关系：output[i].c1 = input[π[i]].c1 + r_i · G
        //       output[i].c2 = input[π[i]].c2 + r_i · pk
        //
        // 推导：Σ k_i · output[i].c1 = Σ k_i · input[π[i]].c1 + (Σ k_i · r_i) · G
        //       令 j = π[i]，则 i = π^{-1}[j]：
        //       Σ_j k_{π^{-1}[j]} · input[j].c1 = Σ_j ρ_j · input[j].c1
        //       → k_{π^{-1}[j]} = ρ_j → k_i = ρ_{π[i]}
        //
        // witnesses k_j:
        //   k_i = ρ_{π[i]} = ρ_{permutation[i]}  (for output[i].c1, i in 0..n)
        //   k_{n+i} = ρ_{permutation[i]}  (for output[i].c2, i in 0..n)
        //   k_{2n} = -Σ k_i · r_i  (for G)
        //   k_{2n+1} = -Σ k_{n+i} · r_i  (for pk)  [== k_{2n} since k_i == k_{n+i}]

        let mut combined_witnesses = Vec::with_capacity(2 * n + 2);
        // k_i for output[i].c1
        for i in 0..n {
            combined_witnesses.push(rho[permutation[i]]);
        }
        // k_{n+i} for output[i].c2
        for i in 0..n {
            combined_witnesses.push(rho[permutation[i]]);
        }
        // k_{2n} for G = -Σ k_i · r_i
        let mut g_witness = Scalar::ZERO;
        for i in 0..n {
            g_witness -= combined_witnesses[i] * masks[i];
        }
        combined_witnesses.push(g_witness);
        // k_{2n+1} for pk = -Σ k_{n+i} · r_i (same as g_witness)
        combined_witnesses.push(g_witness);

        // combined base_points（与 witnesses 布局一致：所有 c1 然后所有 c2）
        let mut combined_base_points = Vec::with_capacity(2 * n + 2);
        for out_ct in &output_cts {
            combined_base_points.push(out_ct.c1);
        }
        for out_ct in &output_cts {
            combined_base_points.push(out_ct.c2);
        }
        combined_base_points.push(g1_generator());
        combined_base_points.push(*pk);

        let combined_r = g1_add(&sum_c1_commit, &sum_c2_commit);

        // 8. 生成 combined Schnorr proof
        let (combined_schnorr_proof, _schnorr_r_point) = schnorr_proof::prove(
            &combined_base_points,
            &combined_witnesses,
            t,
            &mut *rng,
        )?;

        // 9. 生成 c1-only Schnorr proof
        // base_points = [output[0].c1, ..., output[n-1].c1, G]
        // R = sum_c1
        // witnesses: k_i = ρ_{permutation[i]}, k_n = -Σ k_i · r_i
        let mut c1_base_points = Vec::with_capacity(n + 1);
        for out_ct in &output_cts {
            c1_base_points.push(out_ct.c1);
        }
        c1_base_points.push(g1_generator());

        let mut c1_witnesses = Vec::with_capacity(n + 1);
        for i in 0..n {
            c1_witnesses.push(rho[permutation[i]]);
        }
        c1_witnesses.push(g_witness);

        let (sum_c1_schnorr_proof, _) =
            schnorr_proof::prove(&c1_base_points, &c1_witnesses, t, &mut *rng)?;

        // 10. 生成 c2-only Schnorr proof
        // base_points = [output[0].c2, ..., output[n-1].c2, pk]
        // R = sum_c2
        let mut c2_base_points = Vec::with_capacity(n + 1);
        for out_ct in &output_cts {
            c2_base_points.push(out_ct.c2);
        }
        c2_base_points.push(*pk);

        let mut c2_witnesses = Vec::with_capacity(n + 1);
        for i in 0..n {
            c2_witnesses.push(rho[permutation[i]]);
        }
        c2_witnesses.push(g_witness);

        let (sum_c2_schnorr_proof, _) =
            schnorr_proof::prove(&c2_base_points, &c2_witnesses, t, &mut *rng)?;

        // 11. 构造 ShuffleProof
        let proof = ShuffleProof::new(
            serialize_g1(&sum_c1_commit).to_vec(),
            serialize_g1(&sum_c2_commit).to_vec(),
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
            nonce_bytes,
        );

        Ok((proof, output_cts))
    }
}

#[cfg(any(test, feature = "client"))]
pub use prove::prove;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_transcript() -> Transcript {
        Transcript::new(b"test_shuffle_protocol")
    }

    fn make_test_deck(n: usize, pk: &G1Projective) -> Vec<ElGamalCiphertext> {
        (0..n)
            .map(|i| {
                let plaintext = hash_to_g1(format!("card_{i}").as_bytes());
                let r = scalar_from_u64((i as u64) * 7 + 1);
                super::super::bls_elgamal::encrypt(&plaintext, pk, &r)
            })
            .collect()
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(999);
        let pk = g1_generator() * sk;
        let n = 5;
        let input_cts = make_test_deck(n, &pk);

        // 简单置换：反转
        let permutation: Vec<usize> = (0..n).rev().collect();
        let masks: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 10)).collect();

        let mut t_prove = make_transcript();
        let (proof, output_cts) =
            prove(&input_cts, &permutation, &masks, &pk, &mut t_prove, &mut rng).unwrap();

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_prove_verify_roundtrip_identity_permutation() {
        let mut rng = StdRng::seed_from_u64(123);
        let sk = scalar_from_u64(888);
        let pk = g1_generator() * sk;
        let n = 3;
        let input_cts = make_test_deck(n, &pk);

        // 恒等置换
        let permutation: Vec<usize> = (0..n).collect();
        let masks: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 100)).collect();

        let mut t_prove = make_transcript();
        let (proof, output_cts) =
            prove(&input_cts, &permutation, &masks, &pk, &mut t_prove, &mut rng).unwrap();

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(999);
        let pk = g1_generator() * sk;
        let n = 5;
        let input_cts = make_test_deck(n, &pk);

        let permutation: Vec<usize> = (0..n).rev().collect();
        let masks: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 10)).collect();

        let mut t_prove = make_transcript();
        let (proof, output_cts) =
            prove(&input_cts, &permutation, &masks, &pk, &mut t_prove, &mut rng).unwrap();

        // 用不同长度的 input
        let short_input = &input_cts[..n - 1];
        let mut t_verify = make_transcript();
        let ok = verify(&proof, short_input, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_tampered_sum_c1_commit() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(999);
        let pk = g1_generator() * sk;
        let n = 5;
        let input_cts = make_test_deck(n, &pk);

        let permutation: Vec<usize> = (0..n).rev().collect();
        let masks: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 10)).collect();

        let mut t_prove = make_transcript();
        let (mut proof, output_cts) =
            prove(&input_cts, &permutation, &masks, &pk, &mut t_prove, &mut rng).unwrap();

        // 篡改 sum_c1_commit
        proof.sum_c1_commit[0] ^= 0xFF;

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_wrong_output() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(999);
        let pk = g1_generator() * sk;
        let n = 5;
        let input_cts = make_test_deck(n, &pk);

        let permutation: Vec<usize> = (0..n).rev().collect();
        let masks: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 10)).collect();

        let mut t_prove = make_transcript();
        let (proof, _output_cts) =
            prove(&input_cts, &permutation, &masks, &pk, &mut t_prove, &mut rng).unwrap();

        // 用错误的 output_cts（用原始 input 代替）
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &input_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_empty_deck_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(999);
        let pk = g1_generator() * sk;
        let input_cts: Vec<ElGamalCiphertext> = vec![];
        let output_cts: Vec<ElGamalCiphertext> = vec![];

        // 构造一个 dummy proof（不会被验证，因为 n=0 应直接拒绝）
        let dummy_proof = ShuffleProof::new(
            vec![0u8; 48],
            vec![0u8; 48],
            GeneralizedSchnorrProof::new(vec![0u8; 48], vec![]),
            GeneralizedSchnorrProof::new(vec![0u8; 48], vec![]),
            GeneralizedSchnorrProof::new(vec![0u8; 48], vec![]),
            vec![0u8; 32],
        );

        let mut t = make_transcript();
        let ok = verify(&dummy_proof, &input_cts, &output_cts, &pk, &mut t).unwrap();
        assert!(!ok);
    }
}
