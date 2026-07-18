//! ArkworksCryptoProvider — 基于 ark-bn254 的 CryptoProvider 实现（poker_zkvm 侧）。
//!
//! # 设计
//!
//! - 哈希函数：使用 `sha2`/`sha3`/`blake2` crate（与 BlstrsCryptoProvider 一致，结果必然相同）
//! - ECDSA：使用 `secp256k1` crate（与 BlstrsCryptoProvider 一致）
//! - Ed25519：使用 `ed25519-dalek` crate（与 BlstrsCryptoProvider 一致）
//! - BLS12-381：全部返回 `None`/`false`（zkvm 不使用 BLS12-381，用 BN254）
//! - BN254：调用 `ark_bn254::Bn254::multi_pairing`（zkvm 用 BN254 曲线）
//!
//! # 一致性保证
//!
//! 哈希函数（sha256/keccak256/blake2b_256）与签名验证（ecdsa/ed25519）使用与
//! BlstrsCryptoProvider 相同的底层 crate，两个 provider 结果必然一致。
//! BLS12-381 vs BN254 是不同曲线，不做等价断言。
//!
//! # 范围说明
//!
//! Phase 3 仅建立 trait + 实现，**不改造现有 syscall 调用路径**。
//! zkvm 的 host syscall 仍直接调用 `syscalls/host.rs`，未来可改走本 provider。

use blake2::Blake2bVar;
use blake2::digest::VariableOutput;
use sha2::Sha256;
use sha3::Keccak256;
use sha2::Digest;

use vm_common::crypto::{
    BLS12_381_G1_COMPRESSED_SIZE, BLS12_381_G2_COMPRESSED_SIZE, BN254_G1_COMPRESSED_SIZE,
    BN254_G2_COMPRESSED_SIZE, CryptoProvider,
};

/// 基于 ark-bn254 的 CryptoProvider 实现。
///
/// 哈希/ECDSA/Ed25519 与 [`BlstrsCryptoProvider`](../../poker_l1/vm/crypto_blstrs/struct.BlstrsCryptoProvider.html)
/// 使用相同底层 crate，结果必然一致。BLS12-381 不支持（返回 None/false），
/// BN254 通过 ark-bn254 实现。
#[derive(Debug, Default, Clone, Copy)]
pub struct ArkworksCryptoProvider;

impl ArkworksCryptoProvider {
    /// 创建新 provider。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CryptoProvider for ArkworksCryptoProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    fn blake2b_256(&self, input: &[u8]) -> [u8; 32] {
        use blake2::digest::Update;
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        Update::update(&mut hasher, input);
        let mut result = [0u8; 32];
        hasher.finalize_variable(&mut result).expect("32 bytes output");
        result
    }

    fn ecdsa_verify_secp256k1(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8; 65],
        pubkey: &[u8; 33],
    ) -> bool {
        // 解析压缩公钥
        let Ok(pubkey_obj) = secp256k1::PublicKey::from_slice(pubkey) else {
            return false;
        };
        // 解析签名（r||s，65 字节含 v）— secp256k1 crate 接受 64 字节 r||s
        let Ok(sig_obj) = secp256k1::ecdsa::Signature::from_compact(&signature[..64]) else {
            return false;
        };
        // 验签（secp256k1 0.29: from_digest 直接返回 Message，非 Result）
        let msg = secp256k1::Message::from_digest(*msg_hash);
        secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(&msg, &sig_obj, &pubkey_obj)
            .is_ok()
    }

    fn ed25519_verify(&self, msg: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        // ed25519-dalek 2.1.1: Signature::from_bytes 不可失败（固定 64B 输入）
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        pk.verify_strict(msg, &sig).is_ok()
    }

    fn bls12_381_g1_add(
        &self,
        _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        _b: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        // zkvm 不使用 BLS12-381（用 BN254）
        None
    }

    fn bls12_381_g1_mul(
        &self,
        _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        _scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_g1_neg(
        &self,
        _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_g2_add(
        &self,
        _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        _b: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_g2_mul(
        &self,
        _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        _scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_g2_neg(
        &self,
        _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_pairing_check(
        &self,
        _pairs: &[(
            [u8; BLS12_381_G1_COMPRESSED_SIZE],
            [u8; BLS12_381_G2_COMPRESSED_SIZE],
        )],
    ) -> bool {
        false
    }

    fn bls12_381_hash_to_g1(
        &self,
        _msg: &[u8],
        _dst: &[u8],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_hash_to_g2(
        &self,
        _msg: &[u8],
        _dst: &[u8],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_aggregate_g1(
        &self,
        _points: &[[u8; BLS12_381_G1_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        None
    }

    fn bls12_381_aggregate_g2(
        &self,
        _points: &[[u8; BLS12_381_G2_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        None
    }

    fn bn254_pairing_check(
        &self,
        pairs: &[(
            [u8; BN254_G1_COMPRESSED_SIZE],
            [u8; BN254_G2_COMPRESSED_SIZE],
        )],
    ) -> bool {
        use ark_bn254::{Bn254, G1Affine, G2Affine};
        use ark_ec::pairing::Pairing;
        use ark_ff::One;
        use ark_serialize::CanonicalDeserialize;

        if pairs.is_empty() {
            return false; // 空配对不做验证
        }

        let mut g1_points = Vec::with_capacity(pairs.len());
        let mut g2_points = Vec::with_capacity(pairs.len());
        for (g1_bytes, g2_bytes) in pairs {
            let g1 = match G1Affine::deserialize_compressed(&g1_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };
            let g2 = match G2Affine::deserialize_compressed(&g2_bytes[..]) {
                Ok(p) => p,
                Err(_) => return false,
            };
            g1_points.push(g1);
            g2_points.push(g2);
        }
        let gt = Bn254::multi_pairing(&g1_points, &g2_points);
        // PairingOutput<E> 是 TargetField 的包装（pub 字段），比较内部值
        gt.0 == <Bn254 as Pairing>::TargetField::one()
    }

    fn name(&self) -> &'static str {
        "arkworks"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arkworks_provider_name() {
        let provider = ArkworksCryptoProvider::new();
        assert_eq!(provider.name(), "arkworks");
    }

    #[test]
    fn test_arkworks_sha256() {
        let provider = ArkworksCryptoProvider::new();
        let result = provider.sha256(b"hello");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let expected: [u8; 32] = hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_arkworks_keccak256() {
        let provider = ArkworksCryptoProvider::new();
        let result = provider.keccak256(b"");
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let expected: [u8; 32] = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_arkworks_blake2b_256() {
        let provider = ArkworksCryptoProvider::new();
        let result = provider.blake2b_256(b"hello");
        assert_eq!(result.len(), 32);
        // 验证非全零
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_arkworks_ecdsa_invalid_input() {
        let provider = ArkworksCryptoProvider::new();
        // 非法公钥应返回 false（不 panic）
        assert!(!provider.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]));
    }

    #[test]
    fn test_arkworks_ed25519_invalid_input() {
        let provider = ArkworksCryptoProvider::new();
        // 非法公钥应返回 false（不 panic）
        assert!(!provider.ed25519_verify(b"msg", &[0u8; 64], &[0u8; 32]));
    }

    #[test]
    fn test_arkworks_bls12_381_unsupported() {
        let provider = ArkworksCryptoProvider::new();
        // zkvm 不支持 BLS12-381，所有方法应返回 None 或 false
        assert!(provider.bls12_381_g1_add(&[0u8; 48], &[0u8; 48]).is_none());
        assert!(provider.bls12_381_g1_mul(&[0u8; 48], &[0u8; 32]).is_none());
        assert!(provider.bls12_381_g1_neg(&[0u8; 48]).is_none());
        assert!(provider.bls12_381_g2_add(&[0u8; 96], &[0u8; 96]).is_none());
        assert!(provider.bls12_381_g2_mul(&[0u8; 96], &[0u8; 32]).is_none());
        assert!(provider.bls12_381_g2_neg(&[0u8; 96]).is_none());
        assert!(!provider.bls12_381_pairing_check(&[]));
        assert!(provider.bls12_381_hash_to_g1(b"msg", b"dst").is_none());
        assert!(provider.bls12_381_hash_to_g2(b"msg", b"dst").is_none());
        assert!(provider.bls12_381_aggregate_g1(&[]).is_none());
        assert!(provider.bls12_381_aggregate_g2(&[]).is_none());
    }

    #[test]
    fn test_arkworks_bn254_invalid_input() {
        let provider = ArkworksCryptoProvider::new();
        // 非法输入应返回 false（不 panic）
        assert!(!provider.bn254_pairing_check(&[([0u8; 32], [0u8; 64])]));
    }

    #[test]
    fn test_arkworks_bn254_empty_pairs() {
        let provider = ArkworksCryptoProvider::new();
        // 空配对应返回 false
        assert!(!provider.bn254_pairing_check(&[]));
    }

    #[test]
    fn test_arkworks_aggregate_empty() {
        let provider = ArkworksCryptoProvider::new();
        // 空集合应返回 None（BLS12-381 不支持）
        assert!(provider.bls12_381_aggregate_g1(&[]).is_none());
        assert!(provider.bls12_381_aggregate_g2(&[]).is_none());
    }

    #[test]
    fn test_arkworks_trait_object() {
        let provider: Box<dyn CryptoProvider> = Box::new(ArkworksCryptoProvider::new());
        assert_eq!(provider.name(), "arkworks");
        assert_eq!(provider.sha256(b"test").len(), 32);
        assert!(provider.bls12_381_g1_add(&[0u8; 48], &[0u8; 48]).is_none());
    }
}
