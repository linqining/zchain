//! Poseidon 哈希封装（Phase 4 — Task 4.2.3）。
//!
//! 使用 `ark-crypto-primitives` 0.6.0 的 `PoseidonSponge` 实现 BN254 Fr 上的 Poseidon 哈希。
//!
//! # 参数选择
//!
//! BN254 Fr 无内置默认 Poseidon 参数（不像 BLS12-381 Fr），
//! 需用 [`find_poseidon_ark_and_mds`] 生成：
//! - `alpha = 5`（BN254 p-1 不被 5 整除，安全）
//! - `rate = 2`，`capacity = 1`（state size = 3）
//! - `full_rounds = 8`，`partial_rounds = 56`（对齐 BLS12-381 rate=3 配置，field size 接近）
//! - `prime_bits = 254`（BN254 Fr 模数位长）
//!
//! # 缓存
//!
//! `PoseidonConfig` 生成耗时较长（~ms 级），通过 [`OnceLock`] 全局缓存，
//! 首次调用时生成，后续直接复用。

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};

/// Poseidon alpha（S-box 指数）。
const POSEIDON_ALPHA: u64 = 5;

/// Poseidon rate（吸收率）。
const POSEIDON_RATE: usize = 2;

/// Poseidon capacity（容量）。
const POSEIDON_CAPACITY: usize = 1;

/// Poseidon full rounds 数。
const POSEIDON_FULL_ROUNDS: u64 = 8;

/// Poseidon partial rounds 数。
const POSEIDON_PARTIAL_ROUNDS: u64 = 56;

/// BN254 Fr 模数位长。
const BN254_FR_MODULUS_BIT_SIZE: u64 = 254;

/// 全局 Poseidon 配置缓存。
static POSEIDON_CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();

/// 获取或初始化全局 Poseidon 配置。
///
/// 首次调用时通过 [`find_poseidon_ark_and_mds`] 生成参数，
/// 后续调用直接返回缓存。
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    POSEIDON_CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            BN254_FR_MODULUS_BIT_SIZE,
            POSEIDON_RATE,
            POSEIDON_FULL_ROUNDS,
            POSEIDON_PARTIAL_ROUNDS,
            0, // skip_matrices
        );
        PoseidonConfig {
            full_rounds: POSEIDON_FULL_ROUNDS as usize,
            partial_rounds: POSEIDON_PARTIAL_ROUNDS as usize,
            alpha: POSEIDON_ALPHA,
            ark,
            mds,
            rate: POSEIDON_RATE,
            capacity: POSEIDON_CAPACITY,
        }
    })
}

/// Poseidon 哈希 — 接受 Fr 切片，返回单个 Fr。
///
/// 创建临时 sponge，absorb 全部输入，squeeze 1 个 Fr。
///
/// # 空输入
///
/// 空输入仍然会执行 permutation 并返回一个有效 Fr（非零）。
#[must_use]
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    let config = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    if !inputs.is_empty() {
        sponge.absorb(&inputs.to_vec());
    }
    let outputs = sponge.squeeze_native_field_elements(1);
    outputs[0]
}

/// Poseidon 哈希 — 接受任意长度字节，返回单个 Fr。
///
/// 直接将字节 absorb 到 sponge（arkworks 内部会转为 Fr 元素），
/// squeeze 1 个 Fr。
///
/// # 空输入
///
/// 空输入仍然会执行 permutation 并返回一个有效 Fr。
#[must_use]
pub fn poseidon_hash_bytes(input: &[u8]) -> Fr {
    let config = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(config);
    if !input.is_empty() {
        sponge.absorb(&input.to_vec());
    }
    let outputs = sponge.squeeze_native_field_elements(1);
    outputs[0]
}

/// Poseidon 2-to-1 压缩 — 接受两个 Fr，返回单个 Fr。
///
/// 用于 Merkle tree 节点压缩：`parent = Poseidon(left || right)`。
#[must_use]
pub fn poseidon_compress(left: &Fr, right: &Fr) -> Fr {
    poseidon_hash(&[*left, *right])
}

/// 将 Fr 序列化为 32 字节 LE（用于写入 VM 内存）。
///
/// 与 [`crate::field::Bn254ScalarField::to_canonical_bytes`] 一致。
#[must_use]
pub fn fr_to_bytes_le(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let vec = bigint.to_bytes_le();
    let mut arr = [0u8; 32];
    let len = vec.len().min(32);
    arr[..len].copy_from_slice(&vec[..len]);
    arr
}

/// 从 32 字节 LE 反序列化为 Fr。
///
/// # Errors
/// - 输入长度不为 32 时返回 `ZkvmError::InvalidZkProofFormat`。
pub fn fr_from_bytes_le(bytes: &[u8]) -> Result<Fr, crate::error::ZkvmError> {
    if bytes.len() != 32 {
        return Err(crate::error::ZkvmError::InvalidZkProofFormat(format!(
            "Fr bytes 长度应为 32，实际 {}",
            bytes.len()
        )));
    }
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};

    // ===== poseidon_hash 测试 =====

    #[test]
    fn test_poseidon_hash_deterministic() {
        let inputs = vec![Fr::from(1u64), Fr::from(2u64)];
        let h1 = poseidon_hash(&inputs);
        let h2 = poseidon_hash(&inputs);
        assert_eq!(h1, h2, "相同输入应产生相同输出");
    }

    #[test]
    fn test_poseidon_hash_different_inputs() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(1u64), Fr::from(3u64)];
        assert_ne!(
            poseidon_hash(&a),
            poseidon_hash(&b),
            "不同输入应产生不同输出"
        );
    }

    // ===== poseidon_hash_bytes 测试 =====

    #[test]
    fn test_poseidon_hash_bytes_deterministic() {
        let h1 = poseidon_hash_bytes(b"hello");
        let h2 = poseidon_hash_bytes(b"hello");
        assert_eq!(h1, h2, "相同字节输入应产生相同输出");
    }

    #[test]
    fn test_poseidon_hash_bytes_empty() {
        // 空输入不应 panic，且应返回有效 Fr
        let h = poseidon_hash_bytes(b"");
        assert!(!h.is_zero(), "空输入的 Poseidon 哈希不应为零");
    }

    #[test]
    fn test_poseidon_hash_bytes_large_input() {
        // 1000 字节输入不应 panic
        let input = vec![42u8; 1000];
        let h = poseidon_hash_bytes(&input);
        assert!(!h.is_zero(), "大输入的 Poseidon 哈希不应为零");
    }

    // ===== poseidon_compress 测试 =====

    #[test]
    fn test_poseidon_compress_deterministic() {
        let left = Fr::from(1u64);
        let right = Fr::from(2u64);
        let h1 = poseidon_compress(&left, &right);
        let h2 = poseidon_compress(&left, &right);
        assert_eq!(h1, h2, "相同输入应产生相同输出");
    }

    #[test]
    fn test_poseidon_compress_non_commutative() {
        let left = Fr::from(1u64);
        let right = Fr::from(2u64);
        // Poseidon 是顺序敏感的：compress(a, b) != compress(b, a)
        assert_ne!(
            poseidon_compress(&left, &right),
            poseidon_compress(&right, &left),
            "Poseidon 压缩应非交换"
        );
    }

    // ===== fr_to_bytes_le / fr_from_bytes_le 测试 =====

    #[test]
    fn test_fr_bytes_roundtrip() {
        let vals = [Fr::zero(), Fr::one(), Fr::from(42u64), Fr::from(u64::MAX)];
        for v in vals {
            let bytes = fr_to_bytes_le(&v);
            assert_eq!(bytes.len(), 32, "Fr bytes 应为 32 字节");
            let v2 = fr_from_bytes_le(&bytes).unwrap();
            assert_eq!(v, v2, "roundtrip 应保持一致");
        }
    }

    #[test]
    fn test_fr_from_bytes_wrong_length() {
        let short = [0u8; 16];
        assert!(fr_from_bytes_le(&short).is_err());

        let long = [0u8; 64];
        assert!(fr_from_bytes_le(&long).is_err());
    }
}
