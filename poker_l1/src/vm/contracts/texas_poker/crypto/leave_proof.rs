//! Leave Proof（移植自 `texas_poker_move/sources/leave_proof.move`）。
//!
//! 证明 leave 操作（`output.c2 = input.c2 - input.c1 · sk`）被正确执行，
//! 即证明知道 `sk` 使得 `pk = G · sk`，且对每张牌 `d2_i = input.c2 - output.c2 = c1_i · sk`。
//!
//! 与 RemaskProof 结构相同，但 d2 计算方向相反。
//!
//! # 结构
//!
//! - `per_card_commitments`：`A_i = input.c1_i · ω`（每个 48 字节 G1 compressed）
//! - `commitment_pk`：`B = G · ω`（48 字节 G1 compressed）
//! - `response`：`s = ω + c · sk`（32 字节 Scalar）
//! - `nonce`：anti-replay nonce（32 字节 Scalar）

use blstrs::{G1Projective, Scalar};

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::{
    g1_equal, g1_is_identity, g1_sub, g1_generator, parse_g1, parse_scalar, verify_dleq,
};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// Leave Proof。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveProof {
    /// `A_i = input.c1_i · ω`（每个 48 字节 G1 compressed）。
    pub per_card_commitments: Vec<Vec<u8>>,
    /// `B = G · ω`（48 字节 G1 compressed）。
    pub commitment_pk: Vec<u8>,
    /// `s = ω + c · sk`（32 字节 Scalar）。
    pub response: Vec<u8>,
    /// anti-replay nonce（32 字节 Scalar）。
    pub nonce: Vec<u8>,
}

impl LeaveProof {
    /// 构造证明。
    pub fn new(
        per_card_commitments: Vec<Vec<u8>>,
        commitment_pk: Vec<u8>,
        response: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
        }
    }
}

/// 验证 LeaveProof。
pub fn verify(
    proof: &LeaveProof,
    input_cts: &[ElGamalCiphertext],
    output_cts: &[ElGamalCiphertext],
    player_pk: &G1Projective,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    let n = proof.per_card_commitments.len();

    if n == 0 {
        return Ok(false);
    }
    if n != input_cts.len() || n != output_cts.len() {
        return Ok(false);
    }
    if g1_is_identity(player_pk) {
        return Ok(false);
    }

    // 检查 c1 不变性 + 密文有效性，计算 d2_i = input.c2 - output.c2（注意方向与 remask 相反）
    let mut d2s: Vec<G1Projective> = Vec::with_capacity(n);
    for i in 0..n {
        let input_ct = &input_cts[i];
        let output_ct = &output_cts[i];
        if !input_ct.is_valid() || !output_ct.is_valid() {
            return Ok(false);
        }
        if !g1_equal(&input_ct.c1, &output_ct.c1) {
            return Ok(false);
        }
        let d2_i = g1_sub(&input_ct.c2, &output_ct.c2);
        d2s.push(d2_i);
    }

    let comm_pk = match parse_g1(&proof.commitment_pk) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let s = match parse_scalar(&proof.response) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let nonce_scalar = match parse_scalar(&proof.nonce) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if g1_is_identity(&comm_pk) {
        return Ok(false);
    }

    // Transcript
    t.append_point(b"leave_pk", player_pk);
    t.append_ciphertexts(b"leave_input_c1", b"leave_input_c2", input_cts);
    t.append_ciphertexts(b"leave_output_c1", b"leave_output_c2", output_cts);

    let mut per_card_comm_points: Vec<G1Projective> = Vec::with_capacity(n);
    for i in 0..n {
        let comm_i = match parse_g1(&proof.per_card_commitments[i]) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        per_card_comm_points.push(comm_i);
        t.append_point(b"leave_per_card_commitment", &comm_i);
    }

    t.append_point(b"leave_commitment_pk", &comm_pk);
    t.append_points(b"leave_d2", &d2s);
    t.append_scalar(b"leave_nonce", &nonce_scalar);

    let c = t.challenge(b"leave_challenge")?;

    // 验证 pk DLEq: G · s == comm_pk + pk · c
    let g = g1_generator();
    if !verify_dleq(&g, player_pk, &comm_pk, &s, &c) {
        return Ok(false);
    }

    // 对每张牌验证 per-card DLEq: input.c1 · s == per_card_commitment[i] + d2_i · c
    for i in 0..n {
        let input_c1 = input_cts[i].c1;
        let d2_i = &d2s[i];
        let comm_i = &per_card_comm_points[i];
        if !verify_dleq(&input_c1, d2_i, comm_i, &s, &c) {
            return Ok(false);
        }
    }

    Ok(true)
}

// ===== 链下 prove =====

#[cfg(any(test, feature = "client"))]
mod prove {
    use super::*;
    use super::super::bls_scalar::{g1_add, g1_mul, serialize_g1};
    use ff::Field;
    use rand::Rng;

    /// 链下生成 LeaveProof。
    ///
    /// leave 操作：`output.c2 = input.c2 - input.c1 · sk`（c1 不变）。
    pub fn prove(
        input_cts: &[ElGamalCiphertext],
        sk: &Scalar,
        player_pk: &G1Projective,
        t: &mut Transcript,
        rng: &mut impl Rng,
    ) -> PokerL1Result<(LeaveProof, Vec<ElGamalCiphertext>)> {
        let n = input_cts.len();
        assert!(n > 0, "input_cts 不能为空");

        // output_cts[i] = (c1, c2 - c1*sk)
        let neg_sk = -*sk;
        let output_cts: Vec<ElGamalCiphertext> = input_cts
            .iter()
            .map(|ct| {
                let c1_sk_neg = g1_mul(&neg_sk, &ct.c1);
                ElGamalCiphertext::new(ct.c1, g1_add(&ct.c2, &c1_sk_neg))
            })
            .collect();

        let omega = Scalar::random(&mut *rng);
        let nonce_scalar = Scalar::random(&mut *rng);

        let per_card_comm_points: Vec<G1Projective> =
            input_cts.iter().map(|ct| ct.c1 * omega).collect();
        let comm_pk = g1_generator() * omega;

        // Transcript（与 verify 完全一致）
        t.append_point(b"leave_pk", player_pk);
        t.append_ciphertexts(b"leave_input_c1", b"leave_input_c2", input_cts);
        t.append_ciphertexts(b"leave_output_c1", b"leave_output_c2", &output_cts);
        for comm_i in &per_card_comm_points {
            t.append_point(b"leave_per_card_commitment", comm_i);
        }
        t.append_point(b"leave_commitment_pk", &comm_pk);

        let d2s: Vec<G1Projective> = (0..n)
            .map(|i| g1_sub(&input_cts[i].c2, &output_cts[i].c2))
            .collect();
        t.append_points(b"leave_d2", &d2s);
        t.append_scalar(b"leave_nonce", &nonce_scalar);

        let c = t.challenge(b"leave_challenge")?;

        let s = omega + c * sk;

        let per_card_commitments: Vec<Vec<u8>> = per_card_comm_points
            .iter()
            .map(|p| serialize_g1(p).to_vec())
            .collect();
        let commitment_pk = serialize_g1(&comm_pk).to_vec();
        let response = super::super::bls_scalar::serialize_scalar(&s).to_vec();
        let nonce = super::super::bls_scalar::serialize_scalar(&nonce_scalar).to_vec();

        let proof = LeaveProof::new(per_card_commitments, commitment_pk, response, nonce);
        Ok((proof, output_cts))
    }
}

#[cfg(any(test, feature = "client"))]
pub use prove::prove;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{
        g1_add, g1_generator, g1_mul, hash_to_g1, scalar_from_u64,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_transcript() -> Transcript {
        Transcript::new(b"test_leave_protocol")
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
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (proof, output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_empty_rejected() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let empty_proof = LeaveProof::new(vec![], vec![0u8; 48], vec![0u8; 32], vec![0u8; 32]);
        let mut t_verify = make_transcript();
        let ok = verify(&empty_proof, &[], &[], &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_length_mismatch_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (proof, output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        let shorter_input = &input_cts[..3];
        let mut t_verify = make_transcript();
        let ok = verify(&proof, shorter_input, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_identity_pk_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (proof, output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        let identity_pk = super::super::bls_scalar::g1_identity();
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &identity_pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_c1_modified_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (proof, mut output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        output_cts[0] = ElGamalCiphertext::new(hash_to_g1(b"tampered_c1"), output_cts[0].c2);
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_tampered_response_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (mut proof, output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        proof.response[0] ^= 0xFF;
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_wrong_output_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let input_cts = make_test_deck(5, &pk);

        let mut t_prove = make_transcript();
        let (proof, _output_cts) = prove(&input_cts, &sk, &pk, &mut t_prove, &mut rng).unwrap();

        // 用错误密钥生成不同的 output_cts
        let sk2 = scalar_from_u64(999_999);
        let neg_sk2 = -sk2;
        let wrong_output_cts: Vec<ElGamalCiphertext> = input_cts
            .iter()
            .map(|ct| {
                let c1_sk_neg = g1_mul(&neg_sk2, &ct.c1);
                ElGamalCiphertext::new(ct.c1, g1_add(&ct.c2, &c1_sk_neg))
            })
            .collect();

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &input_cts, &wrong_output_cts, &pk, &mut t_verify).unwrap();
        assert!(!ok);
    }
}