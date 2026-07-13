//! Generalized Schnorr proof（Phase M — M-4）。
//!
//! 证明点 R = Σ(k_i · g_i) 是基点 G_1..G_n 的线性组合，Prover 知道秘密标量 k_1..k_n。
//!
//! # 协议
//!
//! 1. Prover 选随机 r_1..r_n，计算承诺 T = Σ(r_i · g_i)
//! 2. Challenge c = H(n, G_1..G_n, R, T)（Fiat-Shamir，Blake2b256）
//! 3. Responses s_i = r_i + c · k_i
//! 4. Verifier 校验：MSM(s_i, g_i) == T + c · R
//!
//! # 序列化（变长）
//!
//! | 字段 | 长度 | 说明 |
//! |------|------|------|
//! | commitment | 33 | G1 压缩格式 |
//! | count | 2 | u16 LE，response 数量 |
//! | responses | count × 32 | Fr little-endian |
//!
//! 兼容 poker_protocol `GeneralizedSchnorrProof`，transcript 标签完全一致：
//! gen_schnorr_n / gen_schnorr_base / gen_schnorr_R / gen_schnorr_commitment / gen_schnorr_challenge

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

/// Generalized Schnorr proof。
#[derive(Debug, Clone)]
pub struct GeneralizedSchnorrProof {
    /// 承诺 T = Σ(r_i · g_i)
    pub commitment: G1Affine,
    /// Responses s_i = r_i + c · k_i
    pub responses: Vec<Fr>,
}

impl GeneralizedSchnorrProof {
    /// 证明 R = Σ(k_i · g_i)。
    ///
    /// 拒绝 identity 基点、identity R、identity 承诺（防止安全性削弱）。
    pub fn prove(
        base_points: &[G1Affine],
        secrets: &[Fr],
        r_point: &G1Affine,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        if base_points.len() != secrets.len() {
            return None;
        }
        if r_point.is_zero() {
            return None;
        }
        for g_i in base_points {
            if g_i.is_zero() {
                return None;
            }
        }

        let n = base_points.len();
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for g_i in base_points {
            transcript.append_point(b"gen_schnorr_base", g_i);
        }
        transcript.append_point(b"gen_schnorr_R", r_point);

        let r_vec: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        let commitment: G1Projective =
            VariableBaseMSM::msm(base_points, &r_vec).unwrap_or(G1Affine::identity().into());
        let commitment = commitment.into_affine();

        if commitment.is_zero() {
            return None;
        }

        transcript.append_point(b"gen_schnorr_commitment", &commitment);
        let c = transcript.challenge(b"gen_schnorr_challenge");

        let responses: Vec<Fr> = r_vec
            .iter()
            .zip(secrets.iter())
            .map(|(r_i, k_i)| *r_i + c * *k_i)
            .collect();

        Some(Self {
            commitment,
            responses,
        })
    }

    /// 验证 R = Σ(k_i · g_i)。
    ///
    /// 校验：MSM(responses, base_points) == commitment + c · R
    pub fn verify(
        &self,
        base_points: &[G1Affine],
        r_point: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        if self.responses.len() != base_points.len() {
            return false;
        }
        if r_point.is_zero() {
            return false;
        }
        for g_i in base_points {
            if g_i.is_zero() {
                return false;
            }
        }
        if self.commitment.is_zero() {
            return false;
        }

        let n = base_points.len();
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for g_i in base_points {
            transcript.append_point(b"gen_schnorr_base", g_i);
        }
        transcript.append_point(b"gen_schnorr_R", r_point);
        transcript.append_point(b"gen_schnorr_commitment", &self.commitment);

        let c = transcript.challenge(b"gen_schnorr_challenge");

        let lhs: G1Projective = VariableBaseMSM::msm(base_points, &self.responses)
            .unwrap_or(G1Affine::identity().into());
        let rhs: G1Projective =
            G1Projective::from(self.commitment) + G1Projective::from(*r_point) * c;

        lhs.into_affine() == rhs.into_affine()
    }

    /// 序列化为变长字节（33 + 2 + n*32）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33 + 2 + self.responses.len() * 32);
        out.extend_from_slice(&compress_g1(&self.commitment));
        let count = self.responses.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        for r in &self.responses {
            out.extend_from_slice(&fr_to_32bytes(r));
        }
        out
    }

    /// 从字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 35 {
            return None;
        }
        let mut a_arr = [0u8; 33];
        a_arr.copy_from_slice(&bytes[0..33]);
        let commitment = decompress_g1(&a_arr)?;

        let count = u16::from_le_bytes([bytes[33], bytes[34]]) as usize;
        let expected_len = 35 + count * 32;
        if bytes.len() != expected_len {
            return None;
        }

        let mut responses = Vec::with_capacity(count);
        for i in 0..count {
            let start = 35 + i * 32;
            let r = fr_from_32bytes(&bytes[start..start + 32])?;
            responses.push(r);
        }

        Some(Self {
            commitment,
            responses,
        })
    }
}

/// 字节导向的 Generalized Schnorr 验证。
///
/// # 参数格式
/// - `base_points_bytes`: n × 64 字节 (x||y, 32B LE each)
/// - `r_point_bytes`: 64 字节
/// - `proof_bytes`: 变长 GeneralizedSchnorrProof 序列化
#[must_use]
pub fn generalized_schnorr_verify_bytes(
    base_points_bytes: &[u8],
    r_point_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::parse_g1_from_64bytes;

    if !base_points_bytes.len().is_multiple_of(64) {
        return false;
    }
    let n = base_points_bytes.len() / 64;
    let base_points: Vec<G1Affine> = (0..n)
        .map(|i| parse_g1_from_64bytes(&base_points_bytes[i * 64..(i + 1) * 64]))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if base_points.len() != n {
        return false;
    }

    let r_point = match parse_g1_from_64bytes(r_point_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match GeneralizedSchnorrProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    proof.verify(&base_points, &r_point, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_std::test_rng;

    fn make_base_points(n: usize) -> Vec<G1Affine> {
        let g = G1Projective::generator();
        (0..n)
            .map(|i| (g * Fr::from((i as u64) + 2)).into_affine())
            .collect()
    }

    fn make_secrets_and_r(n: usize, rng: &mut impl Rng) -> (Vec<Fr>, G1Affine) {
        let base_points = make_base_points(n);
        let secrets: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        let r_point: G1Projective =
            VariableBaseMSM::msm(&base_points, &secrets).unwrap_or(G1Affine::identity().into());
        (secrets, r_point.into_affine())
    }

    #[test]
    fn test_schnorr_n1_roundtrip() {
        let mut rng = test_rng();
        let base_points = make_base_points(1);
        let (secrets, r_point) = make_secrets_and_r(1, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(proof.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_n3_roundtrip() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(proof.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_n10_roundtrip() {
        let mut rng = test_rng();
        let base_points = make_base_points(10);
        let (secrets, r_point) = make_secrets_and_r(10, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(proof.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_wrong_r() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);
        let wrong_r = (G1Projective::generator() * Fr::from(999u64)).into_affine();

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &wrong_r, &mut ts, &mut rng)
                .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(
            !proof.verify(&base_points, &r_point, &mut ts2),
            "应验证失败"
        );
    }

    #[test]
    fn test_schnorr_tampered_commitment() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let mut proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");
        proof.commitment = (G1Projective::generator() * Fr::from(42u64)).into_affine();

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(!proof.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_tampered_response() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let mut proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");
        proof.responses[0] += Fr::from(1u64);

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(!proof.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_reject_identity_base() {
        let mut rng = test_rng();
        let mut base_points = make_base_points(3);
        base_points[1] = G1Affine::identity();
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        assert!(
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .is_none(),
            "identity base point 应拒绝"
        );
    }

    #[test]
    fn test_schnorr_reject_identity_r() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, _) = make_secrets_and_r(3, &mut rng);
        let id = G1Affine::identity();

        let mut ts = PokerTranscript::new(b"test_gs");
        assert!(
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &id, &mut ts, &mut rng)
                .is_none(),
            "identity R 应拒绝"
        );
    }

    #[test]
    fn test_schnorr_serialization_roundtrip() {
        let mut rng = test_rng();
        let base_points = make_base_points(5);
        let (secrets, r_point) = make_secrets_and_r(5, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 33 + 2 + 5 * 32);
        let recovered = GeneralizedSchnorrProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(recovered.verify(&base_points, &r_point, &mut ts2));
    }

    #[test]
    fn test_schnorr_byte_verify() {
        let mut rng = test_rng();
        let base_points = make_base_points(3);
        let (secrets, r_point) = make_secrets_and_r(3, &mut rng);

        let mut ts = PokerTranscript::new(b"test_gs");
        let proof =
            GeneralizedSchnorrProof::prove(&base_points, &secrets, &r_point, &mut ts, &mut rng)
                .expect("prove should succeed");
        let proof_bytes = proof.to_bytes();

        use crate::precompiles::poker_transcript::g1_to_64bytes;
        let mut bp_bytes = Vec::new();
        for bp in &base_points {
            bp_bytes.extend_from_slice(&g1_to_64bytes(bp));
        }
        let r_bytes = g1_to_64bytes(&r_point);

        let mut ts2 = PokerTranscript::new(b"test_gs");
        assert!(generalized_schnorr_verify_bytes(
            &bp_bytes,
            &r_bytes,
            &proof_bytes,
            &mut ts2
        ));
    }
}
