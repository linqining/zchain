//! 广义 Schnorr 证明（移植自 `texas_poker_move/sources/schnorr_proof.move`）。
//!
//! 证明知道 `k_1, ..., k_n` 使得 `R = Σ k_i · G_i`。
//!
//! # 结构
//!
//! - `commitment`：`T = Σ r_i · G_i` 的 G1 compressed bytes（48 字节）
//! - `responses`：`s_i = r_i + c · k_i` 的 Scalar bytes（每个 32 字节）
//!
//! # 验证流程
//!
//! 1. 检查 `responses.len() == base_points.len()`
//! 2. 检查 `R` 非 identity
//! 3. 检查所有 `base_points` 非 identity
//! 4. Transcript 追加：n（u64 LE 8 字节）、每个 base_point、R、commitment
//! 5. M-P17：校验 commitment 点非 identity
//! 6. 提取挑战 `c`
//! 7. LHS = `g1_msm(responses, base_points)`
//! 8. RHS = `commitment + c · R`
//! 9. LHS == RHS

use blstrs::{G1Projective, Scalar};

use super::bls_scalar::{
    g1_add, g1_equal, g1_is_identity, g1_mul, g1_msm, parse_g1, parse_scalar,
};
use super::transcript::Transcript;
use crate::error::PokerL1Result;

/// 广义 Schnorr 证明。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralizedSchnorrProof {
    /// `T = Σ r_i · G_i` 的 G1 compressed bytes（48 字节）。
    pub commitment: Vec<u8>,
    /// `s_i = r_i + c · k_i` 的 Scalar bytes（每个 32 字节）。
    pub responses: Vec<Vec<u8>>,
}

impl GeneralizedSchnorrProof {
    /// 构造证明。
    pub fn new(commitment: Vec<u8>, responses: Vec<Vec<u8>>) -> Self {
        Self {
            commitment,
            responses,
        }
    }
}

/// 验证广义 Schnorr 证明。
///
/// # 参数
///
/// - `proof`：证明结构
/// - `base_points`：基点数组 `G_1, ..., G_n`
/// - `r_point`：声称的线性组合点 `R = Σ k_i · G_i`
/// - `t`：Fiat-Shamir transcript（调用方负责初始化协议名）
pub fn verify(
    proof: &GeneralizedSchnorrProof,
    base_points: &[G1Projective],
    r_point: &G1Projective,
    t: &mut Transcript,
) -> PokerL1Result<bool> {
    let n = proof.responses.len();
    // 1. 检查长度一致
    if n != base_points.len() {
        return Ok(false);
    }
    // 2. 检查 R 非 identity
    if g1_is_identity(r_point) {
        return Ok(false);
    }
    // 3. 检查所有 base_points 非 identity
    for bp in base_points {
        if g1_is_identity(bp) {
            return Ok(false);
        }
    }

    // 4. Transcript 追加 n（u64 小端 8 字节）
    let n_bytes = (n as u64).to_le_bytes();
    t.append_message(b"gen_schnorr_n", &n_bytes);
    // 追加每个 base_point
    for bp in base_points {
        t.append_point(b"gen_schnorr_base", bp);
    }
    // 追加 R
    t.append_point(b"gen_schnorr_R", r_point);

    // 反序列化 commitment 点
    let commitment_point = match parse_g1(&proof.commitment) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    // M-P17：校验承诺点非 identity
    if g1_is_identity(&commitment_point) {
        return Ok(false);
    }
    t.append_point(b"gen_schnorr_commitment", &commitment_point);

    // 5. 提取挑战 c
    let c = t.challenge(b"gen_schnorr_challenge")?;

    // 6. 反序列化所有 responses
    let mut response_scalars = Vec::with_capacity(n);
    for r_bytes in &proof.responses {
        match parse_scalar(r_bytes) {
            Ok(s) => response_scalars.push(s),
            Err(_) => return Ok(false),
        }
    }
    // 7. LHS = g1_msm(responses, base_points)
    let lhs = g1_msm(&response_scalars, base_points)?;

    // 8. RHS = commitment + c * R
    let c_r = g1_mul(&c, r_point);
    let rhs = g1_add(&commitment_point, &c_r);

    // 9. LHS == RHS
    let eq = g1_equal(&lhs, &rhs);
    Ok(eq)
}

// ===== 链下 prove（仅测试 / client feature 启用时可用）=====

#[cfg(any(test, feature = "client"))]
mod prove {
    use super::*;
    use ff::Field;
    use rand::Rng;

    /// 链下生成广义 Schnorr 证明。
    ///
    /// # 参数
    ///
    /// - `base_points`：基点数组 `G_1, ..., G_n`
    /// - `witnesses`：私钥数组 `k_1, ..., k_n`
    /// - `t`：Fiat-Shamir transcript（调用方负责初始化协议名）
    ///
    /// # Returns
    ///
    /// `(proof, R)` 其中 `R = Σ k_i · G_i` 是公钥点。
    pub fn prove(
        base_points: &[G1Projective],
        witnesses: &[Scalar],
        t: &mut Transcript,
        rng: &mut impl Rng,
    ) -> PokerL1Result<(GeneralizedSchnorrProof, G1Projective)> {
        assert_eq!(
            base_points.len(),
            witnesses.len(),
            "base_points 和 witnesses 长度必须相同"
        );
        let n = base_points.len();

        // R = Σ k_i · G_i
        let r_point = g1_msm(witnesses, base_points)?;

        // 随机 r_i
        let mut randoms: Vec<Scalar> = Vec::with_capacity(n);
        for _ in 0..n {
            randoms.push(Scalar::random(&mut *rng));
        }
        // commitment T = Σ r_i · G_i
        let commitment_point = g1_msm(&randoms, base_points)?;

        // Transcript（与 verify 完全一致）
        let n_bytes = (n as u64).to_le_bytes();
        t.append_message(b"gen_schnorr_n", &n_bytes);
        for bp in base_points {
            t.append_point(b"gen_schnorr_base", bp);
        }
        t.append_point(b"gen_schnorr_R", &r_point);
        t.append_point(b"gen_schnorr_commitment", &commitment_point);

        // 挑战 c
        let c = t.challenge(b"gen_schnorr_challenge")?;

        // responses s_i = r_i + c * k_i
        let responses: Vec<Vec<u8>> = randoms
            .iter()
            .zip(witnesses.iter())
            .map(|(r_i, k_i)| {
                let s_i = r_i + c * k_i;
                s_i.to_bytes_be().to_vec()
            })
            .collect();

        let commitment_bytes = super::super::bls_scalar::serialize_g1(&commitment_point).to_vec();
        Ok((
            GeneralizedSchnorrProof::new(commitment_bytes, responses),
            r_point,
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
        Transcript::new(b"test_schnorr_protocol")
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let g1 = g1_generator();
        let g2 = hash_to_g1(b"base2");
        let base_points = vec![g1, g2];
        let witnesses = vec![scalar_from_u64(123), scalar_from_u64(456)];

        let mut t_prove = make_transcript();
        let (proof, r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &base_points, &r_point, &mut t_verify).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_verify_tampered_commitment() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator()];
        let witnesses = vec![scalar_from_u64(123)];

        let mut t_prove = make_transcript();
        let (mut proof, r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        // 篡改 commitment
        proof.commitment[0] ^= 0xFF;

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &base_points, &r_point, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_tampered_response() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator()];
        let witnesses = vec![scalar_from_u64(123)];

        let mut t_prove = make_transcript();
        let (mut proof, r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        // 篡改 response
        proof.responses[0][0] ^= 0xFF;

        let mut t_verify = make_transcript();
        let ok = verify(&proof, &base_points, &r_point, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_wrong_r_point() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator()];
        let witnesses = vec![scalar_from_u64(123)];

        let mut t_prove = make_transcript();
        let (proof, _r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        // 用错误的 R
        let wrong_r = hash_to_g1(b"wrong_r");
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &base_points, &wrong_r, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_identity_r_rejected() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator()];
        let witnesses = vec![scalar_from_u64(123)];

        let mut t_prove = make_transcript();
        let (proof, _r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        // R = identity 应被拒绝
        let identity_r = super::super::bls_scalar::g1_identity();
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &base_points, &identity_r, &mut t_verify).unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_verify_length_mismatch() {
        let mut rng = StdRng::seed_from_u64(42);
        let base_points = vec![g1_generator()];
        let witnesses = vec![scalar_from_u64(123)];

        let mut t_prove = make_transcript();
        let (proof, r_point) = prove(&base_points, &witnesses, &mut t_prove, &mut rng).unwrap();

        // base_points 长度与 proof.responses 不同
        let wrong_base_points = vec![g1_generator(), hash_to_g1(b"extra")];
        let mut t_verify = make_transcript();
        let ok = verify(&proof, &wrong_base_points, &r_point, &mut t_verify).unwrap();
        assert!(!ok);
    }
}
