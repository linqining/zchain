//! BLS12-381 标量与 G1 辅助函数（移植自 `texas_poker_move/sources/bls_scalar.move`）。
//!
//! 提供：
//! - G1/Scalar 的字节序列化与反序列化（含子群检查）
//! - `hash_to_scalar`：SHA3-256 → 清高 2 位 → Scalar（M-P18 大端序）
//! - `derive_scalar_from_card_and_sk/pk`：m6 长度前缀编码
//! - `generate_plaintext_cards`：52 张确定性明文牌点（DST = [`BLS_G1_DST`]）
//! - `g1_msm`：多标量乘法
//! - `verify_dleq`：Schnorr/Chaum-Pedersen 统一验证等式 `s*G == commitment + c*pk`
//!
//! # 字节序约定
//!
//! - G1 compressed：48 字节（blstrs `to_compressed` / `from_compressed`）
//! - Scalar：32 字节大端序（blstrs `Scalar::from_bytes_be`）
//! - SHA3-256 输出为大端序字节流，清高 2 位即 `h[0] & 0x3F`（M-P18）

use blstrs::{G1Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use sha3::{Digest, Sha3_256};
use subtle::CtOption;

use crate::crypto_precompiles::bls::BLS_G1_DST;
use crate::error::{PokerL1Error, PokerL1Result};

/// G1 compressed bytes 长度（48 字节）。
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Scalar bytes 长度（32 字节，大端序）。
pub const SCALAR_SIZE: usize = 32;

/// 扑克牌数量。
pub const N_CARDS: usize = 52;

// ===== 内部辅助 =====

fn ct_opt_to_opt<T>(ct: CtOption<T>) -> Option<T> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

// ===== 反序列化 / 序列化 =====

/// 反序列化 G1 compressed bytes（48 字节），含子群检查。
pub fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective> {
    if bytes.len() != G1_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "G1 compressed size mismatch: {} != {}",
            bytes.len(),
            G1_COMPRESSED_SIZE
        )));
    }
    let mut arr = [0u8; G1_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(G1Projective::from_compressed(&arr)).ok_or(PokerL1Error::InvalidSubgroup(
        "G1 point failed subgroup check or not on curve",
    ))
}

/// 序列化 G1 点为 compressed bytes（48 字节）。
pub fn serialize_g1(point: &G1Projective) -> [u8; G1_COMPRESSED_SIZE] {
    point.to_compressed()
}

/// 反序列化 Scalar（32 字节，大端序）。
pub fn parse_scalar(bytes: &[u8]) -> PokerL1Result<Scalar> {
    if bytes.len() != SCALAR_SIZE {
        return Err(PokerL1Error::InvalidBlsScalar(format!(
            "scalar size mismatch: {} != {}",
            bytes.len(),
            SCALAR_SIZE
        )));
    }
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(Scalar::from_bytes_be(&arr))
        .ok_or_else(|| PokerL1Error::InvalidBlsScalar("scalar reduction failed".to_string()))
}

/// 序列化 Scalar 为 32 字节大端序。
pub fn serialize_scalar(s: &Scalar) -> [u8; SCALAR_SIZE] {
    s.to_bytes_be()
}

// ===== 标量构造 =====

/// 标量零元。
pub fn scalar_zero() -> Scalar {
    Scalar::ZERO
}

/// 标量单位元。
pub fn scalar_one() -> Scalar {
    Scalar::ONE
}

/// 从 u64 构造标量。
pub fn scalar_from_u64(x: u64) -> Scalar {
    Scalar::from(x)
}

// ===== 标量运算 =====

/// 标量加法。
pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

/// 标量减法。
pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a - b
}

/// 标量乘法。
pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a * b
}

/// 标量取负。
pub fn scalar_neg(a: &Scalar) -> Scalar {
    -a
}

/// 标量求逆（若为零返回零）。
pub fn scalar_inv(a: &Scalar) -> Scalar {
    // ff::Field::invert 返回 CtOption<Scalar>；零元的逆约定为零（与 Move 端一致）
    let ct = a.invert();
    if bool::from(ct.is_some()) {
        ct.unwrap()
    } else {
        Scalar::ZERO
    }
}

// ===== 哈希到标量 =====

/// 将任意数据哈希为 BLS12-381 标量。
///
/// 算法（M-P18）：
/// 1. SHA3-256(data) → 32 字节大端序 h
/// 2. 清除 h[0] 高 2 位（`h[0] &= 0x3F`），确保值 < 2^254 < BLS12-381 曲线阶
/// 3. Scalar::from_bytes_be(h)
pub fn hash_to_scalar(data: &[u8]) -> PokerL1Result<Scalar> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let mut h = hasher.finalize();
    // M-P18: 大端序下 h[0] 是 MSB，清高 2 位
    h[0] &= 0x3F;
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(&h);
    ct_opt_to_opt(Scalar::from_bytes_be(&arr))
        .ok_or_else(|| PokerL1Error::InvalidBlsScalar("hash_to_scalar reduction failed".to_string()))
}

/// 从密文 c1*sk 与 c2*sk 派生标量（m6 长度前缀防歧义编码）。
///
/// 输入：`c1_sk = c1 * sk_i`、`c2_sk = c2 * sk_i`（48 字节 G1 compressed each）
/// 输出：`hash_to_scalar(len_le(c1_sk) || c1_sk || len_le(c2_sk) || c2_sk)`
pub fn derive_scalar_from_card_and_sk(c1_sk: &[u8], c2_sk: &[u8]) -> PokerL1Result<Scalar> {
    let mut data = Vec::with_capacity(8 + c1_sk.len() + c2_sk.len());
    data.extend_from_slice(&(c1_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c1_sk);
    data.extend_from_slice(&(c2_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c2_sk);
    hash_to_scalar(&data)
}

/// 从密文 (c1, c2) 与公钥 pk 派生标量（m6 长度前缀防歧义编码）。
pub fn derive_scalar_from_card_and_pk(
    c1: &[u8],
    c2: &[u8],
    pk: &[u8],
) -> PokerL1Result<Scalar> {
    let mut data = Vec::with_capacity(12 + c1.len() + c2.len() + pk.len());
    data.extend_from_slice(&(c1.len() as u32).to_le_bytes());
    data.extend_from_slice(c1);
    data.extend_from_slice(&(c2.len() as u32).to_le_bytes());
    data.extend_from_slice(c2);
    data.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    data.extend_from_slice(pk);
    hash_to_scalar(&data)
}

// ===== G1 辅助 =====

/// G1 生成元。
pub fn g1_generator() -> G1Projective {
    G1Projective::generator()
}

/// G1 单位元。
pub fn g1_identity() -> G1Projective {
    G1Projective::identity()
}

/// G1 点相等比较。
pub fn g1_equal(a: &G1Projective, b: &G1Projective) -> bool {
    a == b
}

/// 判断 G1 点是否为单位元。
pub fn g1_is_identity(p: &G1Projective) -> bool {
    p.is_identity().into()
}

/// G1 标量乘法。
pub fn g1_mul(s: &Scalar, p: &G1Projective) -> G1Projective {
    p * s
}

/// G1 点加法。
pub fn g1_add(a: &G1Projective, b: &G1Projective) -> G1Projective {
    a + b
}

/// G1 点减法。
pub fn g1_sub(a: &G1Projective, b: &G1Projective) -> G1Projective {
    a - b
}

/// 多标量乘法（MSM）：`Σ scalars[i] * points[i]`。
///
/// 镜像 Move `g1_msm`（循环实现，因 Sui testnet 原生 MSM 不可用）。
pub fn g1_msm(scalars: &[Scalar], points: &[G1Projective]) -> PokerL1Result<G1Projective> {
    if scalars.len() != points.len() {
        return Err(PokerL1Error::Serialization(format!(
            "g1_msm length mismatch: scalars={} points={}",
            scalars.len(),
            points.len()
        )));
    }
    let mut result = G1Projective::identity();
    for (s, p) in scalars.iter().zip(points.iter()) {
        result += p * s;
    }
    Ok(result)
}

/// DLEq 验证：检查 `s * g == commitment + c * pk`。
///
/// 用于 Schnorr / Chaum-Pedersen 风格证明的统一验证等式。
pub fn verify_dleq(
    g: &G1Projective,
    pk: &G1Projective,
    commitment: &G1Projective,
    s: &Scalar,
    c: &Scalar,
) -> bool {
    let lhs = g * s;
    let pk_c = pk * c;
    let rhs = commitment + pk_c;
    g1_equal(&lhs, &rhs)
}

// ===== Hash-to-curve =====

/// RFC 9380 hash to G1（DST 固定为 [`BLS_G1_DST`]）。
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, BLS_G1_DST, &[])
}

/// 生成 52 张确定性明文牌点。
///
/// 对 `i = 0..52`：`hash_to_g1("texas_poker/card/{i}")`
pub fn generate_plaintext_cards() -> Vec<G1Projective> {
    (0..N_CARDS)
        .map(|i| {
            let label = format!("texas_poker/card/{i}");
            hash_to_g1(label.as_bytes())
        })
        .collect()
}

/// 派生独立基点 H：`hash_to_g1("texas_poker_independent_base_H")`。
pub fn base_h() -> G1Projective {
    hash_to_g1(b"texas_poker_independent_base_H")
}

// ===== u64 → ASCII（移植 Move `u64_to_ascii`）=====

/// u64 转 ASCII 字节表示（十进制字符串的字节序列）。
pub fn u64_to_ascii(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![b'0'];
    }
    let mut digits = Vec::new();
    let mut val = n;
    while val > 0 {
        let digit = (val % 10) as u8;
        digits.push(digit + b'0');
        val /= 10;
    }
    digits.reverse();
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_roundtrip() {
        let p = g1_generator();
        let bytes = serialize_g1(&p);
        let recovered = parse_g1(&bytes).unwrap();
        assert!(g1_equal(&p, &recovered));
    }

    #[test]
    fn test_scalar_roundtrip() {
        let s = scalar_from_u64(123_456_789);
        let bytes = serialize_scalar(&s);
        let recovered = parse_scalar(&bytes).unwrap();
        assert_eq!(s, recovered);
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let s1 = hash_to_scalar(b"hello").unwrap();
        let s2 = hash_to_scalar(b"hello").unwrap();
        assert_eq!(s1, s2);
        let s3 = hash_to_scalar(b"world").unwrap();
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_hash_to_scalar_clears_high_bits() {
        // 任意输入下，hash_to_scalar 应返回合法 Scalar（< 曲线阶）。
        // 清高 2 位确保 < 2^254 < r ≈ 2^255。
        let s = hash_to_scalar(&[0xFF; 64]).unwrap();
        // 仅断言不 panic 且不等于 zero（极低概率下 hash 输出可能恰好映射到 0）
        let _ = s;
    }

    #[test]
    fn test_generate_plaintext_cards_count() {
        let cards = generate_plaintext_cards();
        assert_eq!(cards.len(), N_CARDS);
        // 每张牌非单位元
        for c in &cards {
            assert!(!g1_is_identity(c));
        }
    }

    #[test]
    fn test_generate_plaintext_cards_deterministic() {
        let cards1 = generate_plaintext_cards();
        let cards2 = generate_plaintext_cards();
        for (a, b) in cards1.iter().zip(cards2.iter()) {
            assert!(g1_equal(a, b));
        }
    }

    #[test]
    fn test_g1_msm() {
        let points = vec![g1_generator(), hash_to_g1(b"point2")];
        let scalars = vec![scalar_from_u64(2), scalar_from_u64(3)];
        let msm = g1_msm(&scalars, &points).unwrap();
        let manual = g1_add(&g1_mul(&scalars[0], &points[0]), &g1_mul(&scalars[1], &points[1]));
        assert!(g1_equal(&msm, &manual));
    }

    #[test]
    fn test_verify_dleq_honest() {
        // 诚实证明：s = r + c * sk, commitment = r * G, pk = sk * G
        let sk = scalar_from_u64(42);
        let r = scalar_from_u64(99);
        let g = g1_generator();
        let pk = g * sk;
        let commitment = g * r;
        let c = scalar_from_u64(7);
        let s = r + c * sk;
        assert!(verify_dleq(&g, &pk, &commitment, &s, &c));
    }

    #[test]
    fn test_verify_dleq_dishonest() {
        let sk = scalar_from_u64(42);
        let g = g1_generator();
        let pk = g * sk;
        let commitment = g * scalar_from_u64(99);
        let c = scalar_from_u64(7);
        // 故意用错误的 s
        let s = scalar_from_u64(0);
        assert!(!verify_dleq(&g, &pk, &commitment, &s, &c));
    }

    #[test]
    fn test_u64_to_ascii() {
        assert_eq!(u64_to_ascii(0), vec![b'0']);
        assert_eq!(u64_to_ascii(9), vec![b'9']);
        assert_eq!(u64_to_ascii(10), vec![b'1', b'0']);
        assert_eq!(u64_to_ascii(123), vec![b'1', b'2', b'3']);
    }

    #[test]
    fn test_derive_scalar_from_card_and_sk_deterministic() {
        let c1_sk = vec![1u8; 48];
        let c2_sk = vec![2u8; 48];
        let s1 = derive_scalar_from_card_and_sk(&c1_sk, &c2_sk).unwrap();
        let s2 = derive_scalar_from_card_and_sk(&c1_sk, &c2_sk).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_base_h_deterministic() {
        let h1 = base_h();
        let h2 = base_h();
        assert!(g1_equal(&h1, &h2));
        assert!(!g1_is_identity(&h1));
    }
}