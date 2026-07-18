//! Phase 3.6 — 跨 VM CryptoProvider 一致性测试。
//!
//! 验证 BlstrsCryptoProvider（poker_l1）与 ArkworksCryptoProvider（poker_zkvm）
//! 在哈希函数与签名验证上产生一致结果。
//!
//! 不测试 BLS12-381 vs BN254 等价（不同曲线，结果不可比）。

use poker_l1::vm::crypto_blstrs::BlstrsCryptoProvider;
use poker_zkvm::crypto_arkworks::ArkworksCryptoProvider;
use vm_common::crypto::CryptoProvider;

/// 测试输入向量。
const TEST_INPUTS: &[&[u8]] = &[
    b"",
    b"hello",
    b"test message",
    b"zchain vm unification",
    &[0u8; 1],
    &[0u8; 32],
    &[0xff; 64],
    &[0x42; 128],
];

#[test]
fn test_sha256_consistency() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    for input in TEST_INPUTS {
        let b = blstrs.sha256(input);
        let a = arkworks.sha256(input);
        assert_eq!(b, a, "sha256 mismatch for input len {}", input.len());
    }
}

#[test]
fn test_keccak256_consistency() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    for input in TEST_INPUTS {
        let b = blstrs.keccak256(input);
        let a = arkworks.keccak256(input);
        assert_eq!(b, a, "keccak256 mismatch for input len {}", input.len());
    }
}

#[test]
fn test_blake2b_256_consistency() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    for input in TEST_INPUTS {
        let b = blstrs.blake2b_256(input);
        let a = arkworks.blake2b_256(input);
        assert_eq!(b, a, "blake2b_256 mismatch for input len {}", input.len());
    }
}

#[test]
fn test_sha256_known_vector() {
    // 验证两个 provider 都产生 sha256("hello") 的已知值
    let expected: [u8; 32] = hex::decode(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    assert_eq!(blstrs.sha256(b"hello"), expected);
    assert_eq!(arkworks.sha256(b"hello"), expected);
}

#[test]
fn test_keccak256_known_vector() {
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    let expected: [u8; 32] = hex::decode(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    assert_eq!(blstrs.keccak256(b""), expected);
    assert_eq!(arkworks.keccak256(b""), expected);
}

#[test]
fn test_ecdsa_invalid_input_consistency() {
    // 两个 provider 对非法输入都应返回 false
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    let result_b = blstrs.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]);
    let result_a = arkworks.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]);
    assert_eq!(result_b, result_a, "ECDSA invalid input should both be false");
    assert!(!result_b, "ECDSA invalid input should be false");
}

#[test]
fn test_ed25519_invalid_input_consistency() {
    // 两个 provider 对非法输入都应返回 false
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    let result_b = blstrs.ed25519_verify(b"msg", &[0u8; 64], &[0u8; 32]);
    let result_a = arkworks.ed25519_verify(b"msg", &[0u8; 64], &[0u8; 32]);
    assert_eq!(result_b, result_a, "Ed25519 invalid input should both be false");
    assert!(!result_b, "Ed25519 invalid input should be false");
}

#[test]
fn test_provider_names_distinct() {
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();
    assert_eq!(blstrs.name(), "blstrs");
    assert_eq!(arkworks.name(), "arkworks");
    assert_ne!(blstrs.name(), arkworks.name());
}

#[test]
fn test_trait_object_collection() {
    // 两个 provider 可作为 trait object 共存于集合
    let providers: Vec<Box<dyn CryptoProvider>> = vec![
        Box::new(BlstrsCryptoProvider::new()),
        Box::new(ArkworksCryptoProvider::new()),
    ];
    assert_eq!(providers.len(), 2);
    assert_eq!(providers[0].name(), "blstrs");
    assert_eq!(providers[1].name(), "arkworks");

    // 通过 trait object 调用方法
    for p in &providers {
        let hash = p.sha256(b"consistency test");
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }
}

#[test]
fn test_bls12_381_vs_bn254_no_comparison() {
    // BLS12-381 与 BN254 是不同曲线，不做等价断言
    // 仅验证：blstrs 支持 BLS12-381（返回 Some/true 边界），arkworks 不支持（返回 None/false）
    let blstrs = BlstrsCryptoProvider::new();
    let arkworks = ArkworksCryptoProvider::new();

    // arkworks 对 BLS12-381 全部返回 None/false
    assert!(arkworks.bls12_381_g1_add(&[0u8; 48], &[0u8; 48]).is_none());
    assert!(!arkworks.bls12_381_pairing_check(&[]));

    // blstrs 对 BN254 返回 false
    assert!(!blstrs.bn254_pairing_check(&[]));

    // arkworks 对 BN254 可能返回 true 或 false（取决于输入），但不 panic
    assert!(!arkworks.bn254_pairing_check(&[([0u8; 32], [0u8; 64])]));
    assert!(!arkworks.bn254_pairing_check(&[]));
}