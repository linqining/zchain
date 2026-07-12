//! Schnorr 批量 DLEq（Discrete Log Equality）proof（Phase J — J-8）。
//!
//! 证明 ΔC = g^R 和 ΔD = pk^R 共享同一离散对数 R，其中：
//! - ΔC = Σ λ_i · (c'_{σ(i)} - c_i) = Σ λ_i · g^{r_i} = g^{Σ λ_i · r_i} = g^R
//! - ΔD = Σ λ_i · (d'_{σ(i)} - d_i) = Σ λ_i · pk^{r_i} = pk^{Σ λ_i · r_i} = pk^R
//!
//! # Schnorr 协议
//!
//! 1. Prover 选随机 w，计算 A = g^w, B = pk^w
//! 2. Challenge c = H(g, pk, ΔC, ΔD, A, B)（Fiat-Shamir，Blake2bVar）
//! 3. Response z = w + c · R
//! 4. Verifier 校验：g^z == A · ΔC^c AND pk^z == B · ΔD^c
//!
//! # 序列化（97 字节）
//!
//! | 字段 | 偏移 | 长度 | 说明 |
//! |------|------|------|------|
//! | A.x | 0 | 32 | BN254 Fp little-endian |
//! | B.x | 32 | 32 | BN254 Fp little-endian |
//! | z | 64 | 32 | BN254 Fr little-endian |
//! | flags | 96 | 1 | bit 0: A.infinity, bit 1: B.infinity, bit 2: A.y parity, bit 3: B.y parity |

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_std::{UniformRand, rand::Rng};

/// DLEq proof（A, B, z）。
#[derive(Debug, Clone, Copy)]
pub struct DleqProof {
    /// A = g^w（commitment on g）
    pub a: G1Affine,
    /// B = pk^w（commitment on pk）
    pub b: G1Affine,
    /// z = w + c · R（response）
    pub z: Fr,
}

/// 批量 DLEq prove：证明 ΔC = g^R 且 ΔD = pk^R。
///
/// # 参数
/// - `g`: BN254 G1 生成元
/// - `pk`: ElGamal 公钥
/// - `delta_c`: Σ λ_i · Δc_i = g^R
/// - `delta_d`: Σ λ_i · Δd_i = pk^R
/// - `r_combined`: R = Σ λ_i · r_i
/// - `rng`: 随机数生成器
pub fn batch_dleq_prove(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    r_combined: &Fr,
    rng: &mut impl Rng,
) -> DleqProof {
    let w = Fr::rand(rng);
    let a = (G1Projective::from(*g) * w).into_affine();
    let b = (G1Projective::from(*pk) * w).into_affine();

    let c = fs_challenge(g, pk, delta_c, delta_d, &a, &b);
    let z = w + c * r_combined;

    DleqProof { a, b, z }
}

/// 批量 DLEq verify：校验 ΔC = g^R 且 ΔD = pk^R。
///
/// 校验等式（用 MSM 实现）：
/// - `[z, -c] · [g, ΔC] == A`
/// - `[z, -c] · [pk, ΔD] == B`
pub fn batch_dleq_verify(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    proof: &DleqProof,
) -> bool {
    let c = fs_challenge(g, pk, delta_c, delta_d, &proof.a, &proof.b);
    let neg_c = -c;

    let lhs1: G1Projective = VariableBaseMSM::msm(&[*g, *delta_c], &[proof.z, neg_c])
        .unwrap_or(G1Affine::identity().into());
    if lhs1.into_affine() != proof.a {
        return false;
    }

    let lhs2: G1Projective = VariableBaseMSM::msm(&[*pk, *delta_d], &[proof.z, neg_c])
        .unwrap_or(G1Affine::identity().into());
    if lhs2.into_affine() != proof.b {
        return false;
    }

    true
}

/// 字节导向的 DLEq 验证（供 poker_l1 等无 ark 依赖的 crate 使用）。
///
/// # 参数格式
/// - `g_bytes`, `pk_bytes`, `delta_c_bytes`, `delta_d_bytes`: 各 64 字节 (x||y, 32B LE each)
/// - `proof_bytes`: 97 字节 DleqProof 序列化
#[must_use]
pub fn batch_dleq_verify_bytes(
    g_bytes: &[u8],
    pk_bytes: &[u8],
    delta_c_bytes: &[u8],
    delta_d_bytes: &[u8],
    proof_bytes: &[u8],
) -> bool {
    let g = match parse_g1_from_bytes(g_bytes) {
        Some(p) => p,
        None => return false,
    };
    let pk = match parse_g1_from_bytes(pk_bytes) {
        Some(p) => p,
        None => return false,
    };
    let delta_c = match parse_g1_from_bytes(delta_c_bytes) {
        Some(p) => p,
        None => return false,
    };
    let delta_d = match parse_g1_from_bytes(delta_d_bytes) {
        Some(p) => p,
        None => return false,
    };
    let proof = match DleqProof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return false,
    };
    batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof)
}

/// BN254 G1 生成元的 64 字节表示 (x||y, 32B LE each)。
pub fn generator_bytes() -> [u8; 64] {
    use crate::precompiles::elgamal::{g1_to_u256, generator};
    let g = generator();
    let (x, y) = g1_to_u256(&g);
    let mut bytes = [0u8; 64];
    for k in 0..4 {
        bytes[k * 8..k * 8 + 8].copy_from_slice(&x[k].to_le_bytes());
        bytes[32 + k * 8..32 + k * 8 + 8].copy_from_slice(&y[k].to_le_bytes());
    }
    bytes
}

/// 从 64 字节 (x||y, 32B LE each) 解析 G1Affine，含 on-curve 校验。
fn parse_g1_from_bytes(bytes: &[u8]) -> Option<G1Affine> {
    if bytes.len() != 64 {
        return None;
    }
    let x_bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(&bytes[0..32]));
    let y_bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(&bytes[32..64]));
    let x_fq = Fq::from_bigint(x_bigint)?;
    let y_fq = Fq::from_bigint(y_bigint)?;

    if x_fq.is_zero() && y_fq.is_zero() {
        return Some(G1Affine::identity());
    }

    let y_sq = y_fq * y_fq;
    let x_cu = x_fq * x_fq * x_fq;
    let rhs = x_cu + Fq::from(3u64);
    if y_sq != rhs {
        return None;
    }
    Some(G1Affine::new(x_fq, y_fq))
}

/// Fiat-Shamir challenge: c = H(g, pk, ΔC, ΔD, A, B) → Fr
fn fs_challenge(
    g: &G1Affine,
    pk: &G1Affine,
    delta_c: &G1Affine,
    delta_d: &G1Affine,
    a: &G1Affine,
    b: &G1Affine,
) -> Fr {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
    hasher.update(b"poker_zkvm_dleq_v1");
    hasher.update(b"g");
    hasher.update(&g.x.into_bigint().to_bytes_le());
    hasher.update(&g.y.into_bigint().to_bytes_le());
    hasher.update(b"pk");
    hasher.update(&pk.x.into_bigint().to_bytes_le());
    hasher.update(&pk.y.into_bigint().to_bytes_le());
    hasher.update(b"dc");
    hasher.update(&delta_c.x.into_bigint().to_bytes_le());
    hasher.update(&delta_c.y.into_bigint().to_bytes_le());
    hasher.update(b"dd");
    hasher.update(&delta_d.x.into_bigint().to_bytes_le());
    hasher.update(&delta_d.y.into_bigint().to_bytes_le());
    hasher.update(b"a");
    hasher.update(&a.x.into_bigint().to_bytes_le());
    hasher.update(&a.y.into_bigint().to_bytes_le());
    hasher.update(b"b");
    hasher.update(&b.x.into_bigint().to_bytes_le());
    hasher.update(&b.y.into_bigint().to_bytes_le());

    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("finalize");
    Fr::from_le_bytes_mod_order(&out)
}

impl DleqProof {
    /// 序列化为 97 字节。
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        let mut flags = 0u8;

        if self.a.is_zero() {
            flags |= 1;
        } else {
            let a_x_bytes = self.a.x.into_bigint().to_bytes_le();
            out[0..32].copy_from_slice(&a_x_bytes);
            let a_y_bytes = self.a.y.into_bigint().to_bytes_le();
            if a_y_bytes[0] & 1 != 0 {
                flags |= 4;
            }
        }

        if self.b.is_zero() {
            flags |= 2;
        } else {
            let b_x_bytes = self.b.x.into_bigint().to_bytes_le();
            out[32..64].copy_from_slice(&b_x_bytes);
            let b_y_bytes = self.b.y.into_bigint().to_bytes_le();
            if b_y_bytes[0] & 1 != 0 {
                flags |= 8;
            }
        }

        let z_bytes = self.z.into_bigint().to_bytes_le();
        out[64..96].copy_from_slice(&z_bytes);
        out[96] = flags;
        out
    }

    /// 从 97 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 97 {
            return None;
        }
        let flags = bytes[96];
        let a = if flags & 1 != 0 {
            G1Affine::identity()
        } else {
            decompress_g1(&bytes[0..32], flags & 4 != 0)?
        };
        let b = if flags & 2 != 0 {
            G1Affine::identity()
        } else {
            decompress_g1(&bytes[32..64], flags & 8 != 0)?
        };
        let z_bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(&bytes[64..96]));
        let z = Fr::from_bigint(z_bigint)?;
        Some(Self { a, b, z })
    }
}

/// 从 32 字节 little-endian 还原 [u64; 4]。
fn bytes_le_to_u256(bytes: &[u8]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let start = k * 8;
        *limb = u64::from_le_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}

/// 从 x 坐标 + y parity 恢复 G1Affine。
fn decompress_g1(x_bytes: &[u8], y_odd: bool) -> Option<G1Affine> {
    let x_bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(x_bytes));
    let x_fq = Fq::from_bigint(x_bigint)?;
    let y_sq = x_fq * x_fq * x_fq + Fq::from(3u64);
    let y_fq = y_sq.sqrt()?;
    let y_bytes = y_fq.into_bigint().to_bytes_le();
    let y_is_odd = y_bytes[0] & 1 != 0;
    let y_fq = if y_is_odd == y_odd { y_fq } else { -y_fq };
    Some(G1Affine::new(x_fq, y_fq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_std::test_rng;

    #[test]
    fn test_dleq_prove_verify_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        assert!(batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_verify_invalid_proof() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let mut proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        proof.z += Fr::from(1u64);
        assert!(!batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_verify_wrong_delta_c() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        let wrong_dc = (G1Projective::generator() * Fr::from(12345u64)).into_affine();
        assert!(!batch_dleq_verify(&g, &pk, &wrong_dc, &delta_d, &proof));
    }

    #[test]
    fn test_dleq_serialization_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::generator() * sk).into_affine();
        let r = Fr::rand(&mut rng);
        let delta_c = (G1Projective::generator() * r).into_affine();
        let delta_d = (G1Projective::from(pk) * r).into_affine();

        let proof = batch_dleq_prove(&g, &pk, &delta_c, &delta_d, &r, &mut rng);
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 97);
        let recovered = DleqProof::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(recovered.a, proof.a);
        assert_eq!(recovered.b, proof.b);
        assert_eq!(recovered.z, proof.z);
        assert!(batch_dleq_verify(&g, &pk, &delta_c, &delta_d, &recovered));
    }
}
