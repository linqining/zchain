//! Chaum-Pedersen DLEQ proof（Phase M — M-3）。
//!
//! 证明 P1 = s·G1 且 P2 = s·G2 共享同一离散对数 s。
//!
//! # 协议
//!
//! 1. Prover 选随机 w，计算 A = w·G1, B = w·G2
//! 2. Challenge c = H(G1, G2, P1, P2, A, B)（Fiat-Shamir，Blake2b256）
//! 3. Response s = w + c·x（x 为秘密离散对数）
//! 4. Verifier 校验：G1·response == A + P1·c AND G2·response == B + P2·c
//!
//! # 序列化（98 字节）
//!
//! | 字段 | 偏移 | 长度 | 说明 |
//! |------|------|------|------|
//! | commitment_a | 0 | 33 | G1 压缩格式 (32B x LE + 1B flags) |
//! | commitment_b | 33 | 33 | G1 压缩格式 |
//! | response | 66 | 32 | Fr little-endian |
//!
//! 兼容 poker_protocol `ChaumPedersenDLEQProof`，transcript 标签完全一致：
//! cp_G1 / cp_G2 / cp_P1 / cp_P2 / cp_commitment_a / cp_commitment_b / cp_challenge

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;

use crate::precompiles::poker_transcript::{
    PokerTranscript, compress_g1, decompress_g1, fr_from_32bytes, fr_to_32bytes,
};

/// Chaum-Pedersen DLEQ proof。
#[derive(Debug, Clone, Copy)]
pub struct ChaumPedersenDLEQProof {
    /// A = w·G1
    pub commitment_a: G1Affine,
    /// B = w·G2
    pub commitment_b: G1Affine,
    /// response = w + c·x
    pub response: Fr,
}

impl ChaumPedersenDLEQProof {
    /// 证明 P1 = s·G1 且 P2 = s·G2。
    ///
    /// 拒绝 identity 基点 G1/G2 和 identity 公钥点 P1/P2（防止平凡攻击）。
    /// 拒绝 identity 承诺点（防止安全性削弱）。
    pub fn prove(
        g1: &G1Affine,
        g2: &G1Affine,
        s: &Fr,
        p1: &G1Affine,
        p2: &G1Affine,
        transcript: &mut PokerTranscript,
        rng: &mut impl Rng,
    ) -> Option<Self> {
        if g1.is_zero() || g2.is_zero() {
            return None;
        }
        if p1.is_zero() || p2.is_zero() {
            return None;
        }

        transcript.append_point(b"cp_G1", g1);
        transcript.append_point(b"cp_G2", g2);
        transcript.append_point(b"cp_P1", p1);
        transcript.append_point(b"cp_P2", p2);

        let w = Fr::rand(rng);

        let commitment_a = (G1Projective::from(*g1) * w).into_affine();
        let commitment_b = (G1Projective::from(*g2) * w).into_affine();

        if commitment_a.is_zero() || commitment_b.is_zero() {
            return None;
        }

        transcript.append_point(b"cp_commitment_a", &commitment_a);
        transcript.append_point(b"cp_commitment_b", &commitment_b);

        let c = transcript.challenge(b"cp_challenge");
        let response = w + c * s;

        Some(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }

    /// 验证 P1 = s·G1 且 P2 = s·G2。
    ///
    /// 校验等式（MSM 优化）：
    /// - `[response, -c] · [G1, P1] == A`
    /// - `[response, -c] · [G2, P2] == B`
    pub fn verify(
        &self,
        g1: &G1Affine,
        g2: &G1Affine,
        p1: &G1Affine,
        p2: &G1Affine,
        transcript: &mut PokerTranscript,
    ) -> bool {
        if g1.is_zero() || g2.is_zero() {
            return false;
        }
        if p1.is_zero() || p2.is_zero() {
            return false;
        }
        if self.commitment_a.is_zero() || self.commitment_b.is_zero() {
            return false;
        }

        transcript.append_point(b"cp_G1", g1);
        transcript.append_point(b"cp_G2", g2);
        transcript.append_point(b"cp_P1", p1);
        transcript.append_point(b"cp_P2", p2);
        transcript.append_point(b"cp_commitment_a", &self.commitment_a);
        transcript.append_point(b"cp_commitment_b", &self.commitment_b);

        let c = transcript.challenge(b"cp_challenge");
        let neg_c = -c;

        let lhs1: G1Projective = VariableBaseMSM::msm(&[*g1, *p1], &[self.response, neg_c])
            .unwrap_or(G1Affine::identity().into());
        if lhs1.into_affine() != self.commitment_a {
            return false;
        }

        let lhs2: G1Projective = VariableBaseMSM::msm(&[*g2, *p2], &[self.response, neg_c])
            .unwrap_or(G1Affine::identity().into());
        if lhs2.into_affine() != self.commitment_b {
            return false;
        }

        true
    }

    /// 序列化为 98 字节（33 + 33 + 32）。
    pub fn to_bytes(&self) -> [u8; 98] {
        let mut out = [0u8; 98];
        let a = compress_g1(&self.commitment_a);
        let b = compress_g1(&self.commitment_b);
        let r = fr_to_32bytes(&self.response);
        out[0..33].copy_from_slice(&a);
        out[33..66].copy_from_slice(&b);
        out[66..98].copy_from_slice(&r);
        out
    }

    /// 从 98 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 98 {
            return None;
        }
        let mut a_arr = [0u8; 33];
        a_arr.copy_from_slice(&bytes[0..33]);
        let commitment_a = decompress_g1(&a_arr)?;

        let mut b_arr = [0u8; 33];
        b_arr.copy_from_slice(&bytes[33..66]);
        let commitment_b = decompress_g1(&b_arr)?;

        let response = fr_from_32bytes(&bytes[66..98])?;

        Some(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }
}

/// 字节导向的 Chaum-Pedersen DLEQ 验证。
///
/// # 参数格式
/// - `g1_bytes`, `g2_bytes`, `p1_bytes`, `p2_bytes`: 各 64 字节 (x||y, 32B LE each)
/// - `proof_bytes`: 98 字节 ChaumPedersenDLEQProof 序列化
#[must_use]
pub fn chaum_pedersen_verify_bytes(
    g1_bytes: &[u8],
    g2_bytes: &[u8],
    p1_bytes: &[u8],
    p2_bytes: &[u8],
    proof_bytes: &[u8],
    transcript: &mut PokerTranscript,
) -> bool {
    use crate::precompiles::poker_transcript::parse_g1_from_64bytes;

    let g1 = match parse_g1_from_64bytes(g1_bytes) {
        Some(p) => p,
        None => return false,
    };
    let g2 = match parse_g1_from_64bytes(g2_bytes) {
        Some(p) => p,
        None => return false,
    };
    let p1 = match parse_g1_from_64bytes(p1_bytes) {
        Some(p) => p,
        None => return false,
    };
    let p2 = match parse_g1_from_64bytes(p2_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match ChaumPedersenDLEQProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    proof.verify(&g1, &g2, &p1, &p2, transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    fn setup() -> (G1Affine, G1Affine, Fr, G1Affine, G1Affine) {
        let mut rng = test_rng();
        let g1 = G1Projective::generator().into_affine();
        let g2 = (G1Projective::generator() * Fr::from(3u64)).into_affine();
        let s = Fr::rand(&mut rng);
        let p1 = (G1Projective::from(g1) * s).into_affine();
        let p2 = (G1Projective::from(g2) * s).into_affine();
        (g1, g2, s, p1, p2)
    }

    #[test]
    fn test_chaum_pedersen_roundtrip() {
        let (g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(b"test_cp");
        let proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &p2, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_cp");
        assert!(proof.verify(&g1, &g2, &p1, &p2, &mut ts2));
    }

    #[test]
    fn test_chaum_pedersen_wrong_p2() {
        let (g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        // Use a fixed wrong_s guaranteed different from s (test_rng is deterministic, so
        // Fr::rand would reproduce the same s; using s+1 guarantees difference)
        let wrong_s = s + Fr::from(1u64);
        let wrong_p2 = (G1Projective::from(g2) * wrong_s).into_affine();
        assert_ne!(wrong_p2, p2, "wrong_p2 must differ from p2");

        let mut ts = PokerTranscript::new(b"test_cp");
        let proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &wrong_p2, &mut ts, &mut rng)
            .expect("prove should succeed");

        let mut ts2 = PokerTranscript::new(b"test_cp");
        assert!(!proof.verify(&g1, &g2, &p1, &p2, &mut ts2), "应验证失败");
    }

    #[test]
    fn test_chaum_pedersen_tampered_response() {
        let (g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(b"test_cp");
        let mut proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &p2, &mut ts, &mut rng)
            .expect("prove should succeed");
        proof.response += Fr::from(1u64);

        let mut ts2 = PokerTranscript::new(b"test_cp");
        assert!(!proof.verify(&g1, &g2, &p1, &p2, &mut ts2));
    }

    #[test]
    fn test_chaum_pedersen_reject_identity_base() {
        let (_g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        let id = G1Affine::identity();
        let mut ts = PokerTranscript::new(b"test_cp");
        assert!(
            ChaumPedersenDLEQProof::prove(&id, &g2, &s, &p1, &p2, &mut ts, &mut rng).is_none(),
            "identity G1 应拒绝"
        );
    }

    #[test]
    fn test_chaum_pedersen_reject_identity_p() {
        let (g1, g2, s, _p1, p2) = setup();
        let mut rng = test_rng();
        let id = G1Affine::identity();
        let mut ts = PokerTranscript::new(b"test_cp");
        assert!(
            ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &id, &p2, &mut ts, &mut rng).is_none(),
            "identity P1 应拒绝"
        );
    }

    #[test]
    fn test_chaum_pedersen_serialization_roundtrip() {
        let (g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(b"test_cp");
        let proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &p2, &mut ts, &mut rng)
            .expect("prove should succeed");

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 98);
        let recovered = ChaumPedersenDLEQProof::from_bytes(&bytes).expect("from_bytes");

        let mut ts2 = PokerTranscript::new(b"test_cp");
        assert!(recovered.verify(&g1, &g2, &p1, &p2, &mut ts2));
    }

    #[test]
    fn test_chaum_pedersen_byte_verify() {
        let (g1, g2, s, p1, p2) = setup();
        let mut rng = test_rng();
        let mut ts = PokerTranscript::new(b"test_cp");
        let proof = ChaumPedersenDLEQProof::prove(&g1, &g2, &s, &p1, &p2, &mut ts, &mut rng)
            .expect("prove should succeed");
        let proof_bytes = proof.to_bytes();

        use crate::precompiles::poker_transcript::g1_to_64bytes;
        let g1_b = g1_to_64bytes(&g1);
        let g2_b = g1_to_64bytes(&g2);
        let p1_b = g1_to_64bytes(&p1);
        let p2_b = g1_to_64bytes(&p2);

        let mut ts2 = PokerTranscript::new(b"test_cp");
        assert!(chaum_pedersen_verify_bytes(
            &g1_b,
            &g2_b,
            &p1_b,
            &p2_b,
            &proof_bytes,
            &mut ts2
        ));
    }
}
