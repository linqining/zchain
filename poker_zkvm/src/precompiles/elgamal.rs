//! ElGamal 交换加密（Phase J — J-2）。
//!
//! 基于 BN254 G1 群的 ElGamal 加密，用于 Mental Poker ZkShuffle 协议。
//!
//! # 密文格式
//!
//! 密文 `(c, d) = (g^r, m · pk^r)`，其中：
//! - `g` = BN254 G1 生成元
//! - `r` = 随机标量（BN254 Fr）
//! - `m` = 明文 G1 点（牌面 `card_id · G`）
//! - `pk` = 公钥 G1 点
//!
//! # 重加密
//!
//! `(c', d') = (c · g^{r'}, d · pk^{r'})`
//!
//! 重加密后密文解密得到相同明文，但密文不同（语义安全）。
//!
//! # 牌面编码
//!
//! `card_id ∈ [0, 51]` → G1 点 `card_id · G`（预计算）

#![allow(dead_code)]

use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::UniformRand;

use crate::precompiles::non_native::NonNativeElement;

// ===== Host-side 类型 =====

/// ElGamal 公钥。
#[derive(Debug, Clone, Copy)]
pub struct ElGamalPublicKey {
    /// 公钥 G1 点。
    pub pk: G1Affine,
}

/// ElGamal 私钥。
#[derive(Debug, Clone, Copy)]
pub struct ElGamalSecretKey {
    /// 私钥标量。
    pub sk: Fr,
}

/// ElGamal 密文 `(c, d)`。
#[derive(Debug, Clone, Copy)]
pub struct ElGamalCiphertext {
    /// 密文第一分量 `c = g^r`。
    pub c: G1Affine,
    /// 密文第二分量 `d = m · pk^r`。
    pub d: G1Affine,
}

// ===== Host-side 运算 =====

/// 获取 BN254 G1 生成元（affine）。
pub fn generator() -> G1Affine {
    G1Projective::generator().into_affine()
}

/// 从私钥派生公钥：`pk = sk · G`。
pub fn keygen_from_secret(sk: &Fr) -> ElGamalPublicKey {
    let g = G1Projective::generator();
    let pk_proj = g * sk;
    ElGamalPublicKey {
        pk: pk_proj.into_affine(),
    }
}

/// 随机生成密钥对。
pub fn keygen(rng: &mut impl ark_std::rand::Rng) -> (ElGamalPublicKey, ElGamalSecretKey) {
    let sk = Fr::rand(rng);
    let pk = keygen_from_secret(&sk);
    (pk, ElGamalSecretKey { sk })
}

/// ElGamal 加密：`(c, d) = (g^r, m · pk^r)`。
pub fn encrypt(pk: &ElGamalPublicKey, msg: &G1Affine, r: &Fr) -> ElGamalCiphertext {
    let g = G1Projective::generator();
    let pk_proj = G1Projective::from(pk.pk);
    let msg_proj = G1Projective::from(*msg);

    let c = (g * r).into_affine();
    let d = (msg_proj + pk_proj * r).into_affine();

    ElGamalCiphertext { c, d }
}

/// ElGamal 解密：`m = d · c^{-sk} = d - sk · c`。
pub fn decrypt(sk: &ElGamalSecretKey, ct: &ElGamalCiphertext) -> G1Affine {
    let c_proj = G1Projective::from(ct.c);
    let d_proj = G1Projective::from(ct.d);

    let m_proj = d_proj - c_proj * sk.sk;
    m_proj.into_affine()
}

/// ElGamal 重加密：`(c', d') = (c · g^{r'}, d · pk^{r'})`。
///
/// 解密结果不变，但密文不同。
pub fn reencrypt(pk: &ElGamalPublicKey, ct: &ElGamalCiphertext, r: &Fr) -> ElGamalCiphertext {
    let g = G1Projective::generator();
    let pk_proj = G1Projective::from(pk.pk);
    let c_proj = G1Projective::from(ct.c);
    let d_proj = G1Projective::from(ct.d);

    let c_new = (c_proj + g * r).into_affine();
    let d_new = (d_proj + pk_proj * r).into_affine();

    ElGamalCiphertext { c: c_new, d: d_new }
}

// ===== 牌面编码 =====

/// 将 card_id 映射为 G1 点：`card_id · G`。
pub fn card_to_point(card_id: u8) -> G1Affine {
    let g = G1Projective::generator();
    let scalar = Fr::from(card_id);
    (g * scalar).into_affine()
}

/// 预计算所有 52 张牌的 G1 点。
pub fn precompute_card_points() -> Vec<G1Affine> {
    (0..52u8).map(card_to_point).collect()
}

// ===== 转换辅助 =====

/// G1Affine → ([u64; 4], [u64; 4])（x, y 各 4 个 little-endian limb）。
pub fn g1_to_u256(point: &G1Affine) -> ([u64; 4], [u64; 4]) {
    let x_bigint = point.x.into_bigint();
    let y_bigint = point.y.into_bigint();
    let x_bytes = x_bigint.to_bytes_le();
    let y_bytes = y_bigint.to_bytes_le();
    (bytes_le_to_u256(&x_bytes), bytes_le_to_u256(&y_bytes))
}

/// [u8; 32] (little-endian) → [u64; 4] (little-endian limbs)。
fn bytes_le_to_u256(bytes: &[u8]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let start = k * 8;
        *limb = u64::from_le_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}

/// ([u64; 4], [u64; 4]) → G1Affine。
///
/// 返回 `None` 如果点不在曲线上或为无穷远点。
pub fn u256_to_g1(x: &[u64; 4], y: &[u64; 4]) -> Option<G1Affine> {
    let x_bigint = ark_ff::BigInt::<4>::new(*x);
    let y_bigint = ark_ff::BigInt::<4>::new(*y);
    let x_fq = Fq::from_bigint(x_bigint)?;
    let y_fq = Fq::from_bigint(y_bigint)?;

    // ark-ec 0.6 的 G1Affine::new 含 debug assertion 要求点在曲线上，
    // 因此先手动校验 y² == x³ + 3（BN254 b=3）。
    if x_fq.is_zero() && y_fq.is_zero() {
        return None; // 无穷远点（card_id=0 的编码），不作为合法 affine 点返回
    }
    let y_sq = y_fq * y_fq;
    let x_cu = x_fq * x_fq * x_fq;
    let rhs = x_cu + Fq::from(3u64);
    if y_sq != rhs {
        return None;
    }

    let point = G1Affine::new(x_fq, y_fq);
    Some(point)
}

// ===== CCS-side 类型 =====

/// CCS 中的 G1 点表示（affine x, y 各 4 limb）。
#[derive(Clone)]
pub(crate) struct CcsG1Point {
    /// x 坐标（4 limb）。
    pub(crate) x: NonNativeElement,
    /// y 坐标（4 limb）。
    pub(crate) y: NonNativeElement,
}

/// CCS 中的 ElGamal 密文表示（c, d 各 8 limb）。
#[derive(Clone)]
pub(crate) struct CcsCiphertext {
    /// 密文第一分量 c。
    pub(crate) c: CcsG1Point,
    /// 密文第二分量 d。
    pub(crate) d: CcsG1Point,
}

impl CcsG1Point {
    /// 从 host G1Affine 获取 ([u64;4], [u64;4]) 坐标。
    pub(crate) fn from_host(point: &G1Affine) -> ([u64; 4], [u64; 4]) {
        g1_to_u256(point)
    }

    /// 获取 host [u64; 4] 坐标。
    pub(crate) fn to_host(
        &self,
        builder: &crate::precompiles::non_native::NonNativeBuilder,
    ) -> ([u64; 4], [u64; 4]) {
        (
            builder.element_to_u256(&self.x),
            builder.element_to_u256(&self.y),
        )
    }
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompiles::bn254_ops::{BN254_G1_X, BN254_G1_Y};
    use ark_ec::AffineRepr;
    use ark_std::test_rng;

    #[test]
    fn test_keygen_and_decrypt() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let msg = card_to_point(5);
        let r = Fr::rand(&mut rng);
        let ct = encrypt(&pk, &msg, &r);

        let decrypted = decrypt(&sk, &ct);
        assert_eq!(decrypted, msg, "解密结果应与原文一致");
    }

    #[test]
    fn test_reencrypt_preserves_plaintext() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        let msg = card_to_point(10);
        let r1 = Fr::rand(&mut rng);
        let ct1 = encrypt(&pk, &msg, &r1);

        let r2 = Fr::rand(&mut rng);
        let ct2 = reencrypt(&pk, &ct1, &r2);

        let decrypted = decrypt(&sk, &ct2);
        assert_eq!(decrypted, msg, "重加密后解密结果应不变");

        // 密文应不同
        assert_ne!(ct1.c, ct2.c, "重加密后 c 应不同");
        assert_ne!(ct1.d, ct2.d, "重加密后 d 应不同");
    }

    #[test]
    fn test_card_to_point() {
        let g = generator();
        let card0 = card_to_point(0);
        assert!(card0.is_zero(), "card 0 = 0*G = infinity point");

        let card1 = card_to_point(1);
        assert_eq!(card1, g, "card 1 = 1*G = G");

        let card2 = card_to_point(2);
        let two_g = (G1Projective::generator() + G1Projective::generator()).into_affine();
        assert_eq!(card2, two_g, "card 2 = 2*G");
    }

    #[test]
    fn test_precompute_card_points() {
        let points = precompute_card_points();
        assert_eq!(points.len(), 52);
        assert!(points[0].is_zero(), "card 0 = infinity");
        assert_eq!(points[1], generator(), "card 1 = G");
    }

    #[test]
    fn test_g1_to_u256_roundtrip() {
        let point = card_to_point(7);
        let (x, y) = g1_to_u256(&point);
        let recovered = u256_to_g1(&x, &y).expect("应恢复 G1 点");
        assert_eq!(recovered, point, "roundtrip 应一致");
    }

    #[test]
    fn test_g1_to_u256_generator() {
        let g = generator();
        let (x, y) = g1_to_u256(&g);
        // BN254 G1 生成元 = (1, 2)
        assert_eq!(x, BN254_G1_X, "G.x = 1");
        assert_eq!(y, BN254_G1_Y, "G.y = 2");
    }

    #[test]
    fn test_u256_to_g1_invalid_point() {
        // (1, 3) 不在曲线上
        let result = u256_to_g1(&[1, 0, 0, 0], &[3, 0, 0, 0]);
        assert!(result.is_none(), "不在曲线上的点应返回 None");
    }

    #[test]
    fn test_multiple_cards_shuffle() {
        let mut rng = test_rng();
        let (pk, sk) = keygen(&mut rng);

        // 加密 5 张牌
        let cards: Vec<u8> = vec![0, 1, 2, 3, 4];
        let r: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let cts: Vec<ElGamalCiphertext> = cards
            .iter()
            .zip(&r)
            .map(|(&card, r)| encrypt(&pk, &card_to_point(card), r))
            .collect();

        // 重加密（shuffle）
        let r2: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let shuffled: Vec<ElGamalCiphertext> = cts
            .iter()
            .zip(&r2)
            .map(|(ct, r)| reencrypt(&pk, ct, r))
            .collect();

        // 解密后应得到原始牌组（顺序可能不同）
        let decrypted: Vec<u8> = shuffled
            .iter()
            .map(|ct| {
                let point = decrypt(&sk, ct);
                // 从 G1 点反查 card_id
                let g = G1Projective::generator();
                for card_id in 0u8..52 {
                    if (g * Fr::from(card_id)).into_affine() == point {
                        return card_id;
                    }
                }
                255u8
            })
            .collect();

        // 排序后比较
        let mut sorted_decrypted = decrypted.clone();
        sorted_decrypted.sort();
        assert_eq!(
            sorted_decrypted,
            vec![0, 1, 2, 3, 4],
            "解密结果应为原始牌组"
        );
    }
}
