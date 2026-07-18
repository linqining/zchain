//! Chaum-Pedersen DLEq 证明（移植自 `texas_poker_move/sources/chaum_pedersen.move`）。
//!
//! 证明知道 `x` 使得 `p1 = g1 · x` 且 `p2 = g2 · x`，
//! 即 `log_{g1}(p1) == log_{g2}(p2)`。
//!
//! # 结构
//!
//! - `commitment_a`：`A = w · g1` 的 G1 compressed bytes（48 字节）
//! - `commitment_b`：`B = w · g2` 的 G1 compressed bytes（48 字节）
//! - `response`：`s = w + c · x` 的 Scalar bytes（32 字节）
//!
//! # 验证流程
//!
//! 1. 拒绝恒等元基点 `g1` / `g2`
//! 2. M5 修复：拒绝恒等元公钥点 `p1` / `p2`（否则 `x = 0` 平凡成立）
//! 3. 反序列化 `comm_a`、`comm_b`、`s`
//! 4. M-P17：拒绝恒等元承诺点
//! 5. Transcript 追加：`g1`、`g2`、`p1`、`p2`、`comm_a`、`comm_b`
//! 6. 提取挑战 `c`
//! 7. 验证 `g1 · s == comm_a + p1 · c`
//! 8. 验证 `g2 · s == comm_b + p2 · c`

use blstrs::{G1Projective, Scalar};

use super::bls_scalar::{g1_is_identity, parse_g1, parse_scalar, verify_dleq};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// Chaum-Pedersen DLEq 证明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaumPedersenProof {
    /// `A = w · g1` 的 G1 compressed bytes（48 字节）。
    pub commitment_a: Vec<u8>,
    /// `B = w · g2` 的 G1 compressed bytes（48 字节）。
    pub commitment_b: Vec<u8>,
    /// `s = w + c · x` 的 Scalar bytes（32 字节）。
    pub response: Vec<u8>,
}

impl ChaumPedersenProof {
    /// 构造证明。
    pub fn new(commitment_a: Vec<u8>, commitment_b: Vec<u8>, response: Vec<u8>) -> Self {
        Self {
            commitment_a,
            commitment_b,
            response,
        }
    }
}

/// 验证 Chaum-Pedersen DLEq 证明。
///
/// # 参数
///
/// - `proof`：证明结构
/// - `g1`、`g2`：基点
/// - `p1 = g1 · x`、`p2 = g2 · x`：公钥点
/// - `t`：Fiat-Shamir transcript
pub fn verify(
    proof: &ChaumPedersenProof,
    g1: &G1Projective,
    g2: &G1Projective,
    p1: &G1Projective,
    p2: &G1Projective,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    // 1. 拒绝恒等元基点
    if g1_is_identity(g1) || g1_is_identity(g2) {
        return Ok(false);
    }
    // M5：拒绝恒等元公钥点
    if g1_is_identity(p1) || g1_is_identity(p2) {
        return Ok(false);
    }

    // 2. 反序列化证明元素
    let comm_a = match parse_g1(&proof.commitment_a) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let comm_b = match parse_g1(&proof.commitment_b) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    let s = match parse_scalar(&proof.response) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    // M-P17：拒绝恒等元承诺点
    if g1_is_identity(&comm_a) || g1_is_identity(&comm_b) {
        return Ok(false);
    }

    // 3. Transcript 追加
    t.append_point(b"cp_G1", g1);
    t.append_point(b"cp_G2", g2);
    t.append_point(b"cp_P1", p1);
    t.append_point(b"cp_P2", p2);
    t.append_point(b"cp_commitment_a", &comm_a);
    t.append_point(b"cp_commitment_b", &comm_b);

    // 4. 提取挑战 c
    let c = t.challenge(b"cp_challenge")?;

    // 5. 验证两组 DLEq
    if !verify_dleq(g1, p1, &comm_a, &s, &c) {
        return Ok(false);
    }
    if !verify_dleq(g2, p2, &comm_b, &s, &c) {
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
    use super::super::bls_scalar::{g1_mul, serialize_g1, serialize_scalar};

    /// 链下生成 Chaum-Pedersen DLEq 证明。
    ///
    /// # 参数
    ///
    /// - `g1`、`g2`：基点
    /// - `x`：私钥（使得 `p1 = g1·x`、`p2 = g2·x`）
    /// - `t`：Fiat-Shamir transcript
    pub fn prove(
        g1: &G1Projective,
        g2: &G1Projective,
        x: &Scalar,
        t: &mut Transcript,
        rng: &mut impl Rng,
    ) -> PokerL1Result<ChaumPedersenProof> {
        // p1 = g1·x, p2 = g2·x
    let p1 = g1_mul(x, g1);
    let p2 = g1_mul(x, g2);

    // 随机 w
    let w = Scalar::random(rng);
    // comm_a = w·g1, comm_b = w·g2
    let comm_a = g1_mul(&w, g1);
    let comm_b = g1_mul(&w, g2);

    // Transcript（与 verify 完全一致）
    t.append_point(b"cp_G1", g1);
    t.append_point(b"cp_G2", g2);
    t.append_point(b"cp_P1", &p1);
    t.append_point(b"cp_P2", &p2);
    t.append_point(b"cp_commitment_a", &comm_a);
    t.append_point(b"cp_commitment_b", &comm_b);

    // 挑战 c
    let c = t.challenge(b"cp_challenge")?;

    // response s = w + c·x
    let s = w + c * x;

        Ok(ChaumPedersenProof::new(
            serialize_g1(&comm_a).to_vec(),
            serialize_g1(&comm_b).to_vec(),
            serialize_scalar(&s).to_vec(),
        ))
    }
}

#[cfg(any(test, feature = "client"))]
pub use prove::prove;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, hash_to_g1, scalar_from_u64};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn make_transcript() -> Transcript {
        Transcript::new(b"test_cp_protocol")
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();

        // 重算 p1, p2 用于 verify
        let p1 = g1 * x;
        let p2 = g2 * x;

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &g1, &g2, &p1, &p2, &mut t_verify).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_tampered_commitment_a() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let mut proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();
        proof.commitment_a[0] ^= 0xFF;

        let p1 = g1 * x;
        let p2 = g2 * x;
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &g1, &g2, &p1, &p2, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_tampered_response() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let mut proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();
        proof.response[0] ^= 0xFF;

        let p1 = g1 * x;
        let p2 = g2 * x;
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &g1, &g2, &p1, &p2, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_wrong_p2() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();

        let p1 = g1 * x;
        // 错误的 p2（用不同的 x）
        let wrong_p2 = g2 * scalar_from_u64(999);

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &g1, &g2, &p1, &wrong_p2, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_identity_base_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();

        let p1 = g1 * x;
        let p2 = g2 * x;
        // identity g1 应被拒绝
        let identity = super::super::bls_scalar::g1_identity();
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &identity, &g2, &p1, &p2, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_identity_pubkey_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"cp_base2");
        let x = scalar_from_u64(789);

        let mut t_prove = make_transcript();
        let proof = prove(&g1, &g2, &x, &mut t_prove, &mut rng).unwrap();

        let p1 = g1 * x;
        let p2 = g2 * x;
        // identity p1 应被拒绝（M5）
        let identity = super::super::bls_scalar::g1_identity();
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &g1, &g2, &identity, &p2, &mut t_verify).unwrap();
        assert!(!ok);
    }
}
