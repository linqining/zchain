//! BLS12-381 ElGamal 加密（移植自 `texas_poker_move/sources/bls_elgamal.move`）。
//!
//! ElGamal 密文 `(c1, c2)`：
//! - `c1 = r · G`（临时公钥）
//! - `c2 = M + r · pk`（加密消息）
//!
//! 操作：
//! - `encrypt(M, pk, r)`：加密
//! - `re_encrypt(ct, pk, r)`：重加密（c1 += r·G, c2 += r·pk）
//! - `decrypt(ct, sk)`：解密 `M = c2 - sk·c1`
//! - `gen_reveal_token(ct, sk)`：`token = sk · c1`（部分解密）
//! - `remask(ct, sk)`：`c2 += sk · c1`（新玩家加入注入贡献）
//! - `add_pk_to_c2(ct, player_pk)`：`c2 += player_pk`（shuffle_v2 注入 pk）

use blstrs::{G1Projective, Scalar};

use super::bls_scalar::{
    g1_add, g1_equal, g1_identity, g1_is_identity, g1_mul, g1_generator, parse_g1, serialize_g1,
    G1_COMPRESSED_SIZE,
};
use crate::error::{PokerL1Error, PokerL1Result};

/// ElGamal 密文（crypto 视图，区别于 `types::ElGamalCiphertext` 的纯字节版）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub c1: G1Projective,
    pub c2: G1Projective,
}

impl ElGamalCiphertext {
    /// 构造密文。
    pub fn new(c1: G1Projective, c2: G1Projective) -> Self {
        Self { c1, c2 }
    }

    /// 占位牌（c1 = c2 = identity）。
    pub fn placeholder() -> Self {
        Self {
            c1: g1_identity(),
            c2: g1_identity(),
        }
    }

    /// 从 96 字节反序列化（c1 48 + c2 48）。
    pub fn from_bytes(bytes: &[u8]) -> PokerL1Result<Self> {
        if bytes.len() != 2 * G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::Serialization(format!(
                "ciphertext bytes must be exactly {} bytes, got {}",
                2 * G1_COMPRESSED_SIZE,
                bytes.len()
            )));
        }
        let c1 = parse_g1(&bytes[..G1_COMPRESSED_SIZE])?;
        let c2 = parse_g1(&bytes[G1_COMPRESSED_SIZE..])?;
        Ok(Self { c1, c2 })
    }

    /// 序列化为 96 字节（c1 48 + c2 48）。
    pub fn to_bytes(&self) -> [u8; 2 * G1_COMPRESSED_SIZE] {
        let mut out = [0u8; 2 * G1_COMPRESSED_SIZE];
        let c1_bytes = serialize_g1(&self.c1);
        let c2_bytes = serialize_g1(&self.c2);
        out[..G1_COMPRESSED_SIZE].copy_from_slice(&c1_bytes);
        out[G1_COMPRESSED_SIZE..].copy_from_slice(&c2_bytes);
        out
    }

    /// c1 字节（48 字节）。
    pub fn c1_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        serialize_g1(&self.c1)
    }

    /// c2 字节（48 字节）。
    pub fn c2_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        serialize_g1(&self.c2)
    }

    /// 验证密文有效（c1/c2 非 identity）。
    pub fn is_valid(&self) -> bool {
        !g1_is_identity(&self.c1) && !g1_is_identity(&self.c2)
    }
}

// ===== 加密操作 =====

/// ElGamal 加密：`c1 = r·G, c2 = M + r·pk`。
pub fn encrypt(plaintext: &G1Projective, pk: &G1Projective, r: &Scalar) -> ElGamalCiphertext {
    let g = g1_generator();
    let c1 = g1_mul(r, &g);
    let pk_r = g1_mul(r, pk);
    let c2 = g1_add(plaintext, &pk_r);
    ElGamalCiphertext::new(c1, c2)
}

/// 重加密：`c1 += r·G, c2 += r·pk`。
pub fn re_encrypt(ct: &ElGamalCiphertext, pk: &G1Projective, r: &Scalar) -> ElGamalCiphertext {
    let g = g1_generator();
    let g_r = g1_mul(r, &g);
    let pk_r = g1_mul(r, pk);
    ElGamalCiphertext::new(g1_add(&ct.c1, &g_r), g1_add(&ct.c2, &pk_r))
}

/// 解密：`M = c2 - sk·c1`。
pub fn decrypt(ct: &ElGamalCiphertext, sk: &Scalar) -> G1Projective {
    let c1_sk = g1_mul(sk, &ct.c1);
    g1_sub(&ct.c2, &c1_sk)
}

/// 生成揭牌令牌：`token = sk · c1`。
pub fn gen_reveal_token(ct: &ElGamalCiphertext, sk: &Scalar) -> G1Projective {
    g1_mul(sk, &ct.c1)
}

/// Remask：`c2 += sk · c1`（c1 不变）。c1 必须非 identity。
///
/// # Errors
/// 当 c1 为 identity 点时返回 `InvalidInput`。
pub fn remask(ct: &ElGamalCiphertext, sk: &Scalar) -> PokerL1Result<ElGamalCiphertext> {
    if g1_is_identity(&ct.c1) {
        return Err(PokerL1Error::Serialization(
            "c1 is identity point, cannot remask".to_string(),
        ));
    }
    let c1_sk = g1_mul(sk, &ct.c1);
    Ok(ElGamalCiphertext::new(ct.c1, g1_add(&ct.c2, &c1_sk)))
}

/// shuffle_v2 链上注入 player_pk 贡献：`c2 += player_pk`（c1 不变）。
///
/// 用于第二手及以后的 plain shuffle 流程，确保最终
/// `c2 = m + c1·Σsk` 解密不变量成立。
pub fn add_pk_to_c2(ct: &ElGamalCiphertext, player_pk: &G1Projective) -> ElGamalCiphertext {
    ElGamalCiphertext::new(ct.c1, g1_add(&ct.c2, player_pk))
}

// ===== G1 减法（re-export from bls_scalar）=====

/// G1 点减法（公开 re-export，供外部模块使用）。
pub fn g1_sub(a: &G1Projective, b: &G1Projective) -> G1Projective {
    super::bls_scalar::g1_sub(a, b)
}

// ===== 批量操作 =====

/// 批量加密：对每张明文用对应的随机数加密。
pub fn encrypt_batch(
    plaintexts: &[G1Projective],
    pk: &G1Projective,
    randoms: &[Scalar],
) -> Vec<ElGamalCiphertext> {
    plaintexts
        .iter()
        .zip(randoms.iter())
        .map(|(m, r)| encrypt(m, pk, r))
        .collect()
}

/// 批量 remask：每张密文都用同一个 sk remask。
pub fn remask_batch(
    ciphertexts: &[ElGamalCiphertext],
    sk: &Scalar,
) -> PokerL1Result<Vec<ElGamalCiphertext>> {
    ciphertexts.iter().map(|ct| remask(ct, sk)).collect()
}

/// 提取所有 c1 点。
pub fn extract_c1s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Projective> {
    ciphertexts.iter().map(|ct| ct.c1).collect()
}

/// 提取所有 c2 点。
pub fn extract_c2s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Projective> {
    ciphertexts.iter().map(|ct| ct.c2).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, hash_to_g1, scalar_from_u64};

    fn test_pk_sk() -> (G1Projective, Scalar) {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        (pk, sk)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (pk, sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(999);
        let ct = encrypt(&plaintext, &pk, &r);
        let recovered = decrypt(&ct, &sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_re_encrypt_preserves_decryption() {
        let (pk, sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_1");
        let r1 = scalar_from_u64(11);
        let r2 = scalar_from_u64(22);
        let ct1 = encrypt(&plaintext, &pk, &r1);
        let ct2 = re_encrypt(&ct1, &pk, &r2);
        // 用原 sk 仍能解密
        let recovered = decrypt(&ct2, &sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_reveal_token_partial_decrypt() {
        let (pk, sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_2");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        let token = gen_reveal_token(&ct, &sk);
        // c2 - token == plaintext（因为 token = sk*c1 = sk*r*G = r*pk）
        let recovered = g1_sub(&ct.c2, &token);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_remask_changes_ciphertext() {
        let (pk, sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_3");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        let sk2 = scalar_from_u64(555);
        let ct2 = remask(&ct, &sk2).unwrap();
        // c1 不变
        assert!(g1_equal(&ct.c1, &ct2.c1));
        // c2 变了
        assert!(!g1_equal(&ct.c2, &ct2.c2));
        // 用原 sk + 新 sk2 能解密（因为 c2 += sk2*c1，所以 M = c2 - (sk+sk2)*c1）
        let combined_sk = sk + sk2;
        let recovered = decrypt(&ct2, &combined_sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_remask_identity_c1_fails() {
        let ct = ElGamalCiphertext::placeholder();
        let sk = scalar_from_u64(1);
        assert!(remask(&ct, &sk).is_err());
    }

    #[test]
    fn test_add_pk_to_c2() {
        let (pk, sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_4");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        // player_pk = sk2 * G
        let sk2 = scalar_from_u64(888);
        let player_pk = g1_generator() * sk2;
        let ct2 = add_pk_to_c2(&ct, &player_pk);
        // c1 不变
        assert!(g1_equal(&ct.c1, &ct2.c1));
        // c2 变了
        assert!(!g1_equal(&ct.c2, &ct2.c2));
        // c2 - player_pk 应等于原 c2
        let recovered_c2 = g1_sub(&ct2.c2, &player_pk);
        assert!(g1_equal(&recovered_c2, &ct.c2));
    }

    #[test]
    fn test_ciphertext_bytes_roundtrip() {
        let (pk, _sk) = test_pk_sk();
        let plaintext = hash_to_g1(b"card_5");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), 96);
        let recovered = ElGamalCiphertext::from_bytes(&bytes).unwrap();
        assert!(g1_equal(&ct.c1, &recovered.c1));
        assert!(g1_equal(&ct.c2, &recovered.c2));
    }

    #[test]
    fn test_ciphertext_from_bytes_invalid_length() {
        let bytes = vec![0u8; 50];
        assert!(ElGamalCiphertext::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_placeholder() {
        let ct = ElGamalCiphertext::placeholder();
        assert!(!ct.is_valid());
    }

    #[test]
    fn test_encrypt_batch() {
        let (pk, _sk) = test_pk_sk();
        let plaintexts = vec![hash_to_g1(b"b0"), hash_to_g1(b"b1"), hash_to_g1(b"b2")];
        let randoms = vec![
            scalar_from_u64(1),
            scalar_from_u64(2),
            scalar_from_u64(3),
        ];
        let cts = encrypt_batch(&plaintexts, &pk, &randoms);
        assert_eq!(cts.len(), 3);
        for (ct, m) in cts.iter().zip(plaintexts.iter()) {
            // c1 = r*G != identity
            assert!(!g1_is_identity(&ct.c1));
            let _ = m;
        }
    }
}
