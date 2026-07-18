//! Reveal Token Proof（移植自 `texas_poker_move/sources/reveal_token_proof.move`）。
//!
//! Chaum-Pedersen DLEq 证明：`log_G(pk) == log_c1(reveal_token) == sk`，
//! 即证明持有者知道 `sk` 使得 `pk = G · sk` 且 `reveal_token = c1 · sk`。
//!
//! # 结构
//!
//! - `user_public_key`：pk bytes（48 字节 G1 compressed）
//! - `commitment_t1`：`T1 = G · ω`（48 字节）
//! - `commitment_t2`：`T2 = c1 · ω`（48 字节）
//! - `response_s`：`s = ω + c · sk`（32 字节 Scalar）
//! - `nonce`：anti-replay nonce（32 字节 Scalar）
//!
//! # 验证流程
//!
//! 0. 密文有效 + reveal_token 非 identity + proof.user_public_key == expected_pk
//! 1. 创建独立 transcript `reveal_token_proof_v3`
//! 2. 反序列化 t1、t2、s，校验非 identity
//! 3. Transcript：nonce → pk → c1 → c2 → reveal_token → t1 → t2
//! 4. 提取挑战 c
//! 5. 验证第一组 DLEq：`G · s == T1 + pk · c`
//! 6. 验证第二组 DLEq：`c1 · s == T2 + reveal_token · c`

use blstrs::{G1Projective, Scalar};

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::{
    g1_is_identity, g1_generator, parse_g1, parse_scalar, serialize_g1, verify_dleq,
};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// Reveal Token Proof。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealTokenProof {
    /// pk bytes（48 字节 G1 compressed）。
    pub user_public_key: Vec<u8>,
    /// `T1 = G · ω`（48 字节）。
    pub commitment_t1: Vec<u8>,
    /// `T2 = c1 · ω`（48 字节）。
    pub commitment_t2: Vec<u8>,
    /// `s = ω + c · sk`（32 字节 Scalar）。
    pub response_s: Vec<u8>,
    /// anti-replay nonce（32 字节 Scalar）。
    pub nonce: Vec<u8>,
}

impl RevealTokenProof {
    /// 构造证明。
    pub fn new(
        user_public_key: Vec<u8>,
        commitment_t1: Vec<u8>,
        commitment_t2: Vec<u8>,
        response_s: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Self {
        Self {
            user_public_key,
            commitment_t1,
            commitment_t2,
            response_s,
            nonce,
        }
    }
}

/// 验证 RevealTokenProof。
///
/// 注意：此验证使用独立 transcript `reveal_token_proof_v3`，
/// 不接收外部 transcript 参数（与 Move 端一致）。
pub fn verify(
    proof: &RevealTokenProof,
    encrypted_card: &ElGamalCiphertext,
    reveal_token: &G1Projective,
    expected_pk: &G1Projective,
) -> PokerL1Result<bool> {
    // 1. 检查密文有效
    if !encrypted_card.is_valid() {
        return Ok(false);
    }
    // 2. 检查 reveal_token 非 identity
    if g1_is_identity(reveal_token) {
        return Ok(false);
    }
    // 3. 检查 proof.user_public_key 与 expected_pk 一致
    let expected_pk_bytes = serialize_g1(expected_pk);
    if proof.user_public_key != expected_pk_bytes.as_slice() {
        return Ok(false);
    }

    // 4. 创建独立 transcript
    let mut t = Transcript::new(b"reveal_token_proof_v3");

    // M4: 追加 nonce 到 transcript
    t.append_message(b"reveal_token_nonce", &proof.nonce);

    // 反序列化证明元素
    let t1 = match parse_g1(&proof.commitment_t1) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let t2 = match parse_g1(&proof.commitment_t2) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let s = match parse_scalar(&proof.response_s) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    // M-P17: 校验承诺点非 identity
    if g1_is_identity(&t1) || g1_is_identity(&t2) {
        return Ok(false);
    }

    // 5. 追加到 transcript: pk, c1, c2, reveal_token, t1, t2
    t.append_point(b"pk", expected_pk);
    t.append_point(b"c1", &encrypted_card.c1);
    t.append_point(b"c2", &encrypted_card.c2);
    t.append_point(b"reveal_token", reveal_token);
    t.append_point(b"t1", &t1);
    t.append_point(b"t2", &t2);

    // 6. 提取挑战 c
    let c = t.challenge(b"challenge")?;

    // 7. 验证第一组 DLEq: G · s == T1 + pk · c
    let g = g1_generator();
    if !verify_dleq(&g, expected_pk, &t1, &s, &c) {
        return Ok(false);
    }

    // 8. 验证第二组 DLEq: c1 · s == T2 + reveal_token · c
    if !verify_dleq(&encrypted_card.c1, reveal_token, &t2, &s, &c) {
        return Ok(false);
    }

    Ok(true)
}

// ===== 链下 prove =====

#[cfg(any(test, feature = "client"))]
mod prove {
    use super::*;
    use super::super::bls_scalar::serialize_scalar;
    use ff::Field;
    use rand::Rng;

    /// 链下生成 RevealTokenProof。
    ///
    /// # 参数
    ///
    /// - `encrypted_card`：要揭示的密文
    /// - `sk`：用户私钥
    /// - `user_pk`：用户公钥 `G · sk`
    ///
    /// # Returns
    ///
    /// `(proof, reveal_token)` — 证明和对应的 reveal token `c1 · sk`。
    pub fn prove(
        encrypted_card: &ElGamalCiphertext,
        sk: &Scalar,
        user_pk: &G1Projective,
        rng: &mut impl Rng,
    ) -> PokerL1Result<(RevealTokenProof, G1Projective)> {
        // reveal_token = c1 * sk
        let reveal_token = encrypted_card.c1 * sk;

        // 随机 omega 与 nonce
        let omega = Scalar::random(&mut *rng);
        let nonce_scalar = Scalar::random(&mut *rng);

        // T1 = G * omega, T2 = c1 * omega
        let t1 = g1_generator() * omega;
        let t2 = encrypted_card.c1 * omega;

        // 独立 transcript（与 verify 完全一致）
        let mut t = Transcript::new(b"reveal_token_proof_v3");
        let nonce_bytes = serialize_scalar(&nonce_scalar).to_vec();
        t.append_message(b"reveal_token_nonce", &nonce_bytes);
        t.append_point(b"pk", user_pk);
        t.append_point(b"c1", &encrypted_card.c1);
        t.append_point(b"c2", &encrypted_card.c2);
        t.append_point(b"reveal_token", &reveal_token);
        t.append_point(b"t1", &t1);
        t.append_point(b"t2", &t2);

        let c = t.challenge(b"challenge")?;

        // response s = omega + c * sk
        let s = omega + c * sk;

        let proof = RevealTokenProof::new(
            serialize_g1(user_pk).to_vec(),
            serialize_g1(&t1).to_vec(),
            serialize_g1(&t2).to_vec(),
            serialize_scalar(&s).to_vec(),
            nonce_bytes,
        );
        Ok((proof, reveal_token))
    }
}

#[cfg(any(test, feature = "client"))]
pub use prove::prove;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, g1_identity, hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_test_ct(pk: &G1Projective) -> ElGamalCiphertext {
        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(7);
        super::super::bls_elgamal::encrypt(&plaintext, pk, &r)
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);

        let (proof, reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();
        let ok = verify(&proof, &ct, &reveal_token, &pk).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_invalid_ciphertext_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);
        let (proof, reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();

        // 用 placeholder（identity）密文
        let placeholder = ElGamalCiphertext::placeholder();
        let ok = verify(&proof, &placeholder, &reveal_token, &pk).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_identity_reveal_token_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);
        let (proof, _reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();

        let identity = g1_identity();
        let ok = verify(&proof, &ct, &identity, &pk).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_pk_mismatch_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);
        let (proof, reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();

        // 用不同的 pk
        let wrong_pk = g1_generator() * scalar_from_u64(999_999);
        let ok = verify(&proof, &ct, &reveal_token, &wrong_pk).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_tampered_response_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);
        let (mut proof, reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();

        proof.response_s[0] ^= 0xFF;
        let ok = verify(&proof, &ct, &reveal_token, &pk).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_wrong_reveal_token_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let ct = make_test_ct(&pk);
        let (proof, _reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();

        // 用错误的 reveal_token（不同 sk）
        let wrong_sk = scalar_from_u64(999_999);
        let wrong_reveal_token = ct.c1 * wrong_sk;
        let ok = verify(&proof, &ct, &wrong_reveal_token, &pk).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_reveal_token_correctness() {
        // reveal_token = c1 * sk 应能部分解密：c2 - reveal_token == plaintext
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_test");
        let r = scalar_from_u64(7);
        let ct = super::super::bls_elgamal::encrypt(&plaintext, &pk, &r);

        let (_proof, reveal_token) = prove(&ct, &sk, &pk, &mut rng).unwrap();
        let recovered = super::super::bls_scalar::g1_sub(&ct.c2, &reveal_token);
        assert!(super::super::bls_scalar::g1_equal(&plaintext, &recovered));
    }
}
