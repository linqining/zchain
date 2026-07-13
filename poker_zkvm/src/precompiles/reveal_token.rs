//! RevealTokenProof — Chaum-Pedersen DLEq 双基对证明（Phase M — M-10）。
//!
//! 完整移植 poker_protocol `reveal_token_proof.rs`，transcript 标签与协议完全一致。
//!
//! # 协议
//!
//! ElGamal 加密 `ct = (c1, c2) = (G·r, M + pk·r)`。
//! RevealToken `token = c1 · sk = G·r·sk = pk·r`（即 ElGamal 的 mask 部分），
//! 用于解密：`M = c2 - token`。
//!
//! RevealTokenProof 是 Chaum-Pedersen DLEq 双基对证明：
//! - Statement: `(G, c1) → (pk, token)` 两组离散对数相等
//! - Witness: `sk`（满足 `log_G(pk) == log_c1(token) == sk`）
//! - Commit: `T1 = G·ω, T2 = c1·ω`
//! - Challenge: `c = H(nonce ‖ pk ‖ c1 ‖ c2 ‖ token ‖ T1 ‖ T2)`
//! - Response: `s = ω + c·sk`
//! - Verify: `G·s == T1 + pk·c` AND `c1·s == T2 + token·c`
//!
//! # 序列化
//!
//! `RevealTokenProof`（163 字节）：
//! | 字段 | 偏移 | 长度 | 说明 |
//! |------|------|------|------|
//! | user_public_key | 0 | 33 | G1 压缩格式 |
//! | commitment_t1 | 33 | 33 | G1 压缩格式 |
//! | commitment_t2 | 66 | 33 | G1 压缩格式 |
//! | response_s | 99 | 32 | Fr little-endian |
//! | nonce | 131 | 32 | Fr little-endian |
//!
//! `RevealTokenAndProof`（196 字节）= `reveal_token`（33B）+ `proof`（163B）。
//!
//! # Transcript 标签（完全匹配 poker_protocol）
//!
//! `reveal_token_nonce` / `pk` / `c1` / `c2` / `reveal_token` / `t1` / `t2` / `challenge`

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

use crate::precompiles::elgamal::ElGamalCiphertext;
use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

/// Fiat-Shamir transcript domain tag。
///
/// 必须与 poker_protocol `REVEAL_TOKEN_PROOF_LABEL` 完全一致。
pub const REVEAL_TOKEN_PROOF_LABEL: &[u8] = b"reveal_token_proof_v3";

/// RevealTokenProof 序列化长度（固定 163 字节）。
pub const REVEAL_TOKEN_PROOF_BYTES: usize = 33 + 33 + 33 + 32 + 32;

/// RevealTokenAndProof 序列化长度（固定 196 字节）。
pub const REVEAL_TOKEN_AND_PROOF_BYTES: usize = 33 + REVEAL_TOKEN_PROOF_BYTES;

/// RevealTokenProof — 证明 `log_G(pk) == log_c1(reveal_token) == sk`。
#[derive(Debug, Clone, Copy)]
pub struct RevealTokenProof {
    /// 用户公钥 `pk = sk · G`。
    pub user_public_key: G1Affine,
    /// 承诺 `T1 = G · ω`。
    pub commitment_t1: G1Affine,
    /// 承诺 `T2 = c1 · ω`。
    pub commitment_t2: G1Affine,
    /// 响应 `s = ω + c · sk`。
    pub response_s: Fr,
    /// 防重放 nonce（参与 transcript）。
    pub nonce: Fr,
}

/// RevealTokenAndProof — reveal token 与对应 proof 的组合。
#[derive(Debug, Clone, Copy)]
pub struct RevealTokenAndProof {
    /// reveal token `= c1 · sk`（ElGamal mask 部分）。
    pub reveal_token: G1Affine,
    /// 对应的 DLEq proof。
    pub proof: RevealTokenProof,
}

impl RevealTokenProof {
    /// 从私钥和密文计算 reveal token：`token = c1 · sk`。
    pub fn compute_reveal_token(sk: &Fr, encrypted_card: &ElGamalCiphertext) -> G1Affine {
        (G1Projective::from(encrypted_card.c) * sk).into_affine()
    }

    /// 生成 RevealTokenProof。
    ///
    /// # 参数
    /// - `sk` — 用户私钥（witness）
    /// - `user_pk` — 用户公钥 `pk = sk · G`
    /// - `encrypted_card` — ElGamal 密文 `(c1, c2)`
    /// - `reveal_token` — `c1 · sk`
    /// - `transcript` — Fiat-Shamir transcript
    /// - `rng` — 随机数生成器
    ///
    /// # 返回
    /// 返回 `Option<Self>`，当输入非法（identity 点）时返回 `None`。
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        sk: &Fr,
        user_pk: &G1Affine,
        encrypted_card: &ElGamalCiphertext,
        reveal_token: &G1Affine,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        // 安全检查：拒绝 identity 点
        if user_pk.is_zero() || reveal_token.is_zero() {
            return None;
        }
        if !encrypted_card.is_valid() {
            return None;
        }

        let omega = Fr::rand(rng);
        let g = G1Projective::generator();
        let t1 = (g * omega).into_affine();
        let t2 = (G1Projective::from(encrypted_card.c) * omega).into_affine();

        // 安全检查：拒绝 identity 承诺点
        if t1.is_zero() || t2.is_zero() {
            return None;
        }

        let nonce = Fr::rand(rng);
        let challenge = Self::compute_challenge(
            user_pk,
            encrypted_card,
            reveal_token,
            &t1,
            &t2,
            &nonce,
            transcript,
        );

        let response_s = omega + challenge * sk;

        Some(Self {
            user_public_key: *user_pk,
            commitment_t1: t1,
            commitment_t2: t2,
            response_s,
            nonce,
        })
    }

    /// 验证 RevealTokenProof。
    ///
    /// # 参数
    /// - `&self` — proof
    /// - `encrypted_card` — ElGamal 密文
    /// - `reveal_token` — 待验证的 reveal token
    /// - `expected_pk` — 预期的用户公钥
    /// - `transcript` — Fiat-Shamir transcript
    ///
    /// # 返回
    /// `true` 表示 proof 有效。
    pub fn verify(
        &self,
        encrypted_card: &ElGamalCiphertext,
        reveal_token: &G1Affine,
        expected_pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        // 安全检查：拒绝 identity 密文
        if !encrypted_card.is_valid() {
            return false;
        }
        // 拒绝 identity reveal_token
        if reveal_token.is_zero() {
            return false;
        }
        // 校验 proof 中的 user_public_key 与预期公钥匹配
        if self.user_public_key != *expected_pk {
            return false;
        }
        // 拒绝 identity 承诺点
        if self.commitment_t1.is_zero() || self.commitment_t2.is_zero() {
            return false;
        }
        // 拒绝 identity expected_pk
        if expected_pk.is_zero() {
            return false;
        }

        let expected_c = Self::compute_challenge(
            &self.user_public_key,
            encrypted_card,
            reveal_token,
            &self.commitment_t1,
            &self.commitment_t2,
            &self.nonce,
            transcript,
        );

        // 校验第一组 DLEq: G·s == T1 + pk·c
        // MSM 优化: [s, -c] · [G, pk] == T1
        let neg_c = -expected_c;
        let lhs1: G1Projective = VariableBaseMSM::msm(
            &[
                G1Projective::generator().into_affine(),
                self.user_public_key,
            ],
            &[self.response_s, neg_c],
        )
        .unwrap_or(G1Affine::identity().into());
        if lhs1.into_affine() != self.commitment_t1 {
            return false;
        }

        // 校验第二组 DLEq: c1·s == T2 + token·c
        // MSM 优化: [s, -c] · [c1, token] == T2
        let lhs2: G1Projective = VariableBaseMSM::msm(
            &[encrypted_card.c, *reveal_token],
            &[self.response_s, neg_c],
        )
        .unwrap_or(G1Affine::identity().into());
        if lhs2.into_affine() != self.commitment_t2 {
            return false;
        }

        true
    }

    /// 计算 challenge 标量。
    ///
    /// Transcript 顺序（完全匹配 poker_protocol）：
    /// `nonce` → `pk` → `c1` → `c2` → `reveal_token` → `t1` → `t2` → `challenge`
    fn compute_challenge(
        pk: &G1Affine,
        encrypted_card: &ElGamalCiphertext,
        reveal_token: &G1Affine,
        t1: &G1Affine,
        t2: &G1Affine,
        nonce: &Fr,
        transcript: &mut PokerTranscript,
    ) -> Fr {
        transcript.append_scalar(b"reveal_token_nonce", nonce);
        transcript.append_point(b"pk", pk);
        transcript.append_point(b"c1", &encrypted_card.c);
        transcript.append_point(b"c2", &encrypted_card.d);
        transcript.append_point(b"reveal_token", reveal_token);
        transcript.append_point(b"t1", t1);
        transcript.append_point(b"t2", t2);
        transcript.challenge(b"challenge")
    }

    /// 序列化为 163 字节。
    pub fn to_bytes(&self) -> [u8; REVEAL_TOKEN_PROOF_BYTES] {
        let mut out = [0u8; REVEAL_TOKEN_PROOF_BYTES];
        let pk = compress_g1(&self.user_public_key);
        let t1 = compress_g1(&self.commitment_t1);
        let t2 = compress_g1(&self.commitment_t2);
        let s = fr_to_32bytes(&self.response_s);
        let n = fr_to_32bytes(&self.nonce);
        out[0..33].copy_from_slice(&pk);
        out[33..66].copy_from_slice(&t1);
        out[66..99].copy_from_slice(&t2);
        out[99..131].copy_from_slice(&s);
        out[131..163].copy_from_slice(&n);
        out
    }

    /// 从 163 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REVEAL_TOKEN_PROOF_BYTES {
            return None;
        }
        let mut pk_arr = [0u8; 33];
        pk_arr.copy_from_slice(&bytes[0..33]);
        let user_public_key = decompress_g1(&pk_arr)?;

        let mut t1_arr = [0u8; 33];
        t1_arr.copy_from_slice(&bytes[33..66]);
        let commitment_t1 = decompress_g1(&t1_arr)?;

        let mut t2_arr = [0u8; 33];
        t2_arr.copy_from_slice(&bytes[66..99]);
        let commitment_t2 = decompress_g1(&t2_arr)?;

        let response_s = fr_from_32bytes(&bytes[99..131])?;
        let nonce = fr_from_32bytes(&bytes[131..163])?;

        Some(Self {
            user_public_key,
            commitment_t1,
            commitment_t2,
            response_s,
            nonce,
        })
    }
}

impl RevealTokenAndProof {
    /// 生成 RevealTokenAndProof：从 sk 计算 reveal_token，再生成 proof。
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        sk: &Fr,
        user_pk: &G1Affine,
        encrypted_card: &ElGamalCiphertext,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        let reveal_token = RevealTokenProof::compute_reveal_token(sk, encrypted_card);
        let proof =
            RevealTokenProof::prove(sk, user_pk, encrypted_card, &reveal_token, transcript, rng)?;
        Some(Self {
            reveal_token,
            proof,
        })
    }

    /// 验证 RevealTokenAndProof。
    pub fn verify(
        &self,
        encrypted_card: &ElGamalCiphertext,
        expected_pk: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        self.proof
            .verify(encrypted_card, &self.reveal_token, expected_pk, transcript)
    }

    /// 序列化为 196 字节。
    pub fn to_bytes(&self) -> [u8; REVEAL_TOKEN_AND_PROOF_BYTES] {
        let mut out = [0u8; REVEAL_TOKEN_AND_PROOF_BYTES];
        let token = compress_g1(&self.reveal_token);
        out[0..33].copy_from_slice(&token);
        out[33..REVEAL_TOKEN_AND_PROOF_BYTES].copy_from_slice(&self.proof.to_bytes());
        out
    }

    /// 从 196 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REVEAL_TOKEN_AND_PROOF_BYTES {
            return None;
        }
        let mut token_arr = [0u8; 33];
        token_arr.copy_from_slice(&bytes[0..33]);
        let reveal_token = decompress_g1(&token_arr)?;
        let proof = RevealTokenProof::from_bytes(&bytes[33..REVEAL_TOKEN_AND_PROOF_BYTES])?;
        Some(Self {
            reveal_token,
            proof,
        })
    }
}

/// 字节导向的 RevealTokenProof 验证。
///
/// # 参数格式
/// - `encrypted_card_bytes`: 128 字节（c1‖c2，各 64B x‖y LE）
/// - `reveal_token_bytes`: 64 字节（x‖y LE）
/// - `expected_pk_bytes`: 64 字节（x‖y LE）
/// - `proof_bytes`: 163 字节 RevealTokenProof 序列化
#[must_use]
pub fn reveal_token_verify_bytes(
    encrypted_card_bytes: &[u8],
    reveal_token_bytes: &[u8],
    expected_pk_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::parse_g1_from_64bytes;

    if encrypted_card_bytes.len() != 128 {
        return false;
    }
    let c = match parse_g1_from_64bytes(&encrypted_card_bytes[0..64]) {
        Some(p) => p,
        None => return false,
    };
    let d = match parse_g1_from_64bytes(&encrypted_card_bytes[64..128]) {
        Some(p) => p,
        None => return false,
    };
    let encrypted_card = ElGamalCiphertext { c, d };

    let reveal_token = match parse_g1_from_64bytes(reveal_token_bytes) {
        Some(p) => p,
        None => return false,
    };
    let expected_pk = match parse_g1_from_64bytes(expected_pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match RevealTokenProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    proof.verify(&encrypted_card, &reveal_token, &expected_pk, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::elgamal::{ElGamalPublicKey, encrypt, keygen_from_secret};
    use crate::precompiles::poker_transcript::g1_to_64bytes;
    use ark_std::test_rng;

    /// 构造测试上下文：(sk, pk, plaintext, encrypted_card, reveal_token)。
    fn setup() -> (Fr, G1Affine, G1Affine, ElGamalCiphertext, G1Affine) {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = keygen_from_secret(&sk).pk;
        let plaintext = (G1Projective::generator() * Fr::from(42u64)).into_affine();
        let r = Fr::rand(&mut rng);
        let pk_obj = ElGamalPublicKey { pk };
        let encrypted_card = encrypt(&pk_obj, &plaintext, &r);
        let reveal_token = RevealTokenProof::compute_reveal_token(&sk, &encrypted_card);
        // 确保解密正确: M = c2 - token
        let decrypted =
            (G1Projective::from(encrypted_card.d) - G1Projective::from(reveal_token)).into_affine();
        assert_eq!(decrypted, plaintext, "reveal token 应正确解密");
        (sk, pk, plaintext, encrypted_card, reveal_token)
    }

    #[test]
    fn test_reveal_token_valid() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof.verify(&ct, &token, &pk, &mut ts2),
            "valid proof should pass"
        );
    }

    #[test]
    fn test_reveal_token_wrong_sk() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        // test_rng() 是确定性的，Fr::rand 会产生与 setup 相同序列；用 sk+1 保证不同
        let wrong_sk = sk + Fr::from(1u64);

        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        // 用错误的 sk 生成 proof（但 token 和 pk 是正确的）
        let proof = RevealTokenProof::prove(&wrong_sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !proof.verify(&ct, &token, &pk, &mut ts2),
            "wrong sk should fail"
        );
    }

    #[test]
    fn test_reveal_token_wrong_pk() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        // 使用不同的 sk 生成错误的 pk
        let wrong_sk = sk + Fr::from(1u64);
        let wrong_pk = keygen_from_secret(&wrong_sk).pk;

        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !proof.verify(&ct, &token, &wrong_pk, &mut ts2),
            "wrong expected_pk should fail"
        );
    }

    #[test]
    fn test_reveal_token_tampered_response() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let mut proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");
        proof.response_s += Fr::from(1u64);

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !proof.verify(&ct, &token, &pk, &mut ts2),
            "tampered response should fail"
        );
    }

    #[test]
    fn test_reveal_token_tampered_commitment() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let mut proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");
        // 篡改 commitment_t1
        proof.commitment_t1 = (G1Projective::generator() * Fr::from(999u64)).into_affine();

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !proof.verify(&ct, &token, &pk, &mut ts2),
            "tampered commitment should fail"
        );
    }

    #[test]
    fn test_reveal_token_identity_reveal_token() {
        let (sk, pk, _pt, ct, _token) = setup();
        let mut rng = test_rng();
        let id = G1Affine::identity();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        // identity reveal_token 应被 prove 拒绝
        assert!(
            RevealTokenProof::prove(&sk, &pk, &ct, &id, &mut ts, &mut rng).is_none(),
            "identity reveal_token should be rejected by prove"
        );

        // verify 时 identity reveal_token 也应失败
        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::prove(
            &sk,
            &pk,
            &ct,
            &(_token_from_sk(&sk, &ct)),
            &mut ts2,
            &mut rng,
        )
        .expect("prove should succeed");
        let mut ts3 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !proof.verify(&ct, &id, &pk, &mut ts3),
            "identity reveal_token should fail verify"
        );
    }

    /// 辅助：从 sk 计算 reveal_token（避免 setup 中变量名冲突）。
    fn _token_from_sk(sk: &Fr, ct: &ElGamalCiphertext) -> G1Affine {
        RevealTokenProof::compute_reveal_token(sk, ct)
    }

    #[test]
    fn test_reveal_token_serialization_roundtrip() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), REVEAL_TOKEN_PROOF_BYTES);
        let recovered = RevealTokenProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(recovered.verify(&ct, &token, &pk, &mut ts2));
    }

    #[test]
    fn test_reveal_token_byte_verify() {
        let (sk, pk, _pt, ct, token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &token, &mut ts, &mut rng)
            .expect("prove should succeed");
        let proof_bytes = proof.to_bytes();

        // 构造字节级输入
        let mut ct_bytes = [0u8; 128];
        ct_bytes[0..64].copy_from_slice(&g1_to_64bytes(&ct.c));
        ct_bytes[64..128].copy_from_slice(&g1_to_64bytes(&ct.d));
        let token_bytes = g1_to_64bytes(&token);
        let pk_bytes = g1_to_64bytes(&pk);

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(reveal_token_verify_bytes(
            &ct_bytes,
            &token_bytes,
            &pk_bytes,
            &proof_bytes,
            &mut ts2
        ));

        // 篡改检测
        let mut tampered = proof_bytes;
        tampered[99] ^= 0x01; // 篡改 response_s 第一字节
        let mut ts3 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            !reveal_token_verify_bytes(&ct_bytes, &token_bytes, &pk_bytes, &tampered, &mut ts3),
            "tampered proof should fail"
        );
    }

    #[test]
    fn test_reveal_token_and_proof_roundtrip() {
        let (sk, pk, _pt, ct, _token) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let rp = RevealTokenAndProof::prove(&sk, &pk, &ct, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(rp.verify(&ct, &pk, &mut ts2));

        // 序列化 roundtrip
        let bytes = rp.to_bytes();
        assert_eq!(bytes.len(), REVEAL_TOKEN_AND_PROOF_BYTES);
        let recovered = RevealTokenAndProof::from_bytes(&bytes).expect("from_bytes");
        let mut ts3 = PokerTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(recovered.verify(&ct, &pk, &mut ts3));
    }
}
