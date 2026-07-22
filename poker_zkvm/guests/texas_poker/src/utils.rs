//! crypto 适配层 —— ZKVM guest 版本（Phase 3.3）。
//!
//! 原 `poker_l1/src/vm/contracts/texas_poker/utils.rs` 的 no_std 移植。
//! 所有 BLS12-381 G1/Scalar 操作经 `guest_sdk::bls` syscall 完成。
//!
//! # 移植变更
//!
//! - **类型替换**：`blstrs::G1Projective` → `guest_sdk::bls::G1Point`，
//!   `blstrs::Scalar` → `guest_sdk::bls::Scalar`，
//!   `poker_protocol::crypto::types::ElGamalCiphertext` → `guest_sdk::bls::ElGamalCiphertext`
//! - **ElGamal 操作**：原依赖 `ElGamalCiphertextGeneric` 方法，guest 端自行实现
//!   （encrypt/re_encrypt/decrypt/gen_reveal_token/remask）
//! - **Transcript 工厂**：完全删除（proof 验证交给 host syscall）
//! - **verify_or_skip**：完全删除（guest 内永远不跳过 ZK 验证）
//! - **错误类型**：`PokerL1Error` → `UtilsError`（轻量枚举）
//!
//! # 字节序约定
//!
//! - G1 compressed：48 字节
//! - Scalar：32 字节大端序
//! - hash_to_scalar：SHA3-256 + 清高 2 位（M-P18），由 host syscall 0x15 完成

use alloc::format;
use alloc::vec::Vec;

use zkvm_guest_sdk::bls::{ElGamalCiphertext, G1Point, Scalar};

// ========== 错误类型 ==========

/// utils 模块错误类型（替代 `PokerL1Error`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtilsError {
    /// 非法 BLS G1 点（长度错误或不在子群内）。
    InvalidBlsPoint,
    /// 非法 BLS 标量（长度错误或归约失败）。
    InvalidBlsScalar,
    /// 序列化/反序列化错误。
    Serialization,
}

pub type UtilsResult<T> = Result<T, UtilsError>;

// ========== 常量 ==========

/// G1 compressed bytes 长度（48 字节）。
pub const G1_COMPRESSED_SIZE: usize = 48;

/// Scalar bytes 长度（32 字节，大端序）。
pub const SCALAR_SIZE: usize = 32;

/// 扑克牌数量。
pub const N_CARDS: usize = 52;

// ========== G1/Scalar 序列化与反序列化 ==========

/// 反序列化 G1 compressed bytes（48 字节）。
///
/// guest 端仅做字节拷贝（不含子群检查），子群检查由 host syscall 在执行时完成。
pub fn parse_g1(bytes: &[u8]) -> UtilsResult<G1Point> {
    G1Point::from_bytes(bytes).ok_or(UtilsError::InvalidBlsPoint)
}

/// 序列化 G1 点为 compressed bytes（48 字节）。
pub fn serialize_g1(point: &G1Point) -> [u8; G1_COMPRESSED_SIZE] {
    point.0
}

/// 反序列化 Scalar（32 字节，大端序）。
pub fn parse_scalar(bytes: &[u8]) -> UtilsResult<Scalar> {
    Scalar::from_bytes_be(bytes).ok_or(UtilsError::InvalidBlsScalar)
}

/// 序列化 Scalar 为 32 字节大端序。
pub fn serialize_scalar(s: &Scalar) -> [u8; SCALAR_SIZE] {
    s.0
}

// ========== 标量构造与运算 ==========

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
    Scalar::from_u64(x)
}

/// 标量加法 a+b mod p（syscall 0x16）。
pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a.add(b)
}

/// 标量减法 a-b mod p（syscall 0x17）。
pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a.sub(b)
}

/// 标量乘法 a*b mod p（syscall 0x11）。
pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a.mul(b)
}

/// 标量取负 -a mod p（syscall 0x18）。
pub fn scalar_neg(a: &Scalar) -> Scalar {
    a.neg()
}

/// 标量求逆 a^(-1) mod p（syscall 0x19）。a=0 时返回 0。
pub fn scalar_inv(a: &Scalar) -> Scalar {
    a.inv()
}

// ========== 哈希到标量 / Hash-to-curve ==========

/// 将任意数据哈希为 BLS12-381 标量（syscall 0x15，M-P18 算法）。
///
/// 算法：SHA3-256(data) → 清高 2 位 → reduce mod q。
/// 由 host syscall 完成，guest 端不会失败。
pub fn hash_to_scalar(data: &[u8]) -> UtilsResult<Scalar> {
    Ok(Scalar::hash_to_scalar(data))
}

/// RFC 9380 hash to G1（syscall 0x10，DST 固定）。
pub fn hash_to_g1(msg: &[u8]) -> G1Point {
    G1Point::hash_to_curve(msg)
}

/// 生成 52 张确定性明文牌点。
///
/// 对 `i = 0..52`：`hash_to_g1("texas_poker/card/{i}")`
pub fn generate_plaintext_cards() -> Vec<G1Point> {
    (0..N_CARDS)
        .map(|i| {
            let label = format!("texas_poker/card/{i}");
            hash_to_g1(label.as_bytes())
        })
        .collect()
}

/// 派生独立基点 H：`hash_to_g1("texas_poker_independent_base_H")`。
pub fn base_h() -> G1Point {
    hash_to_g1(b"texas_poker_independent_base_H")
}

/// 从密文 c1*sk 与 c2*sk 派生标量（m6 长度前缀防歧义编码）。
pub fn derive_scalar_from_card_and_sk(c1_sk: &[u8], c2_sk: &[u8]) -> UtilsResult<Scalar> {
    let mut data = Vec::with_capacity(8 + c1_sk.len() + c2_sk.len());
    data.extend_from_slice(&(c1_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c1_sk);
    data.extend_from_slice(&(c2_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c2_sk);
    hash_to_scalar(&data)
}

/// 从密文 (c1, c2) 与公钥 pk 派生标量（m6 长度前缀防歧义编码）。
pub fn derive_scalar_from_card_and_pk(c1: &[u8], c2: &[u8], pk: &[u8]) -> UtilsResult<Scalar> {
    let mut data = Vec::with_capacity(12 + c1.len() + c2.len() + pk.len());
    data.extend_from_slice(&(c1.len() as u32).to_le_bytes());
    data.extend_from_slice(c1);
    data.extend_from_slice(&(c2.len() as u32).to_le_bytes());
    data.extend_from_slice(c2);
    data.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    data.extend_from_slice(pk);
    hash_to_scalar(&data)
}

// ========== G1 辅助 ==========

/// G1 生成元（syscall 0x1B）。
pub fn g1_generator() -> G1Point {
    G1Point::generator()
}

/// G1 单位元。
pub fn g1_identity() -> G1Point {
    G1Point::identity()
}

/// G1 点相等比较。
pub fn g1_equal(a: &G1Point, b: &G1Point) -> bool {
    a.eq(b)
}

/// 判断 G1 点是否为单位元。
pub fn g1_is_identity(p: &G1Point) -> bool {
    p.is_identity()
}

/// G1 标量乘法 `s * p`。
///
/// 注意：与原 utils.rs 参数顺序一致（scalar 在前，point 在后）。
pub fn g1_mul(s: &Scalar, p: &G1Point) -> G1Point {
    p.mul(s)
}

/// G1 点加法。
pub fn g1_add(a: &G1Point, b: &G1Point) -> G1Point {
    a.add(b)
}

/// G1 点减法。
pub fn g1_sub(a: &G1Point, b: &G1Point) -> G1Point {
    a.sub(b)
}

/// 多标量乘法（MSM）：`Σ scalars[i] * points[i]`。
pub fn g1_msm(scalars: &[Scalar], points: &[G1Point]) -> UtilsResult<G1Point> {
    if scalars.len() != points.len() {
        return Err(UtilsError::Serialization);
    }
    let mut result = g1_identity();
    for (s, p) in scalars.iter().zip(points.iter()) {
        result = g1_add(&result, &g1_mul(s, p));
    }
    Ok(result)
}

/// DLEq 验证：检查 `s * g == commitment + c * pk`。
pub fn verify_dleq(
    g: &G1Point,
    pk: &G1Point,
    commitment: &G1Point,
    s: &Scalar,
    c: &Scalar,
) -> bool {
    let lhs = g1_mul(s, g);
    let pk_c = g1_mul(c, pk);
    let rhs = g1_add(commitment, &pk_c);
    g1_equal(&lhs, &rhs)
}

// ========== u64 → ASCII ==========

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

// ========== ElGamal 操作 ==========
//
// 原依赖 `poker_protocol::crypto::types::ElGamalCiphertext` 的方法，
// guest 端用 G1Point syscall 操作自行实现。
//
// ElGamal 语义：c1 = r·G, c2 = M + r·pk

/// ElGamal 加密：`c1 = r·G, c2 = M + r·pk`。
pub fn encrypt(plaintext: &G1Point, pk: &G1Point, r: &Scalar) -> ElGamalCiphertext {
    let g = g1_generator();
    let c1 = g1_mul(r, &g);
    let c2 = g1_add(plaintext, &g1_mul(r, pk));
    ElGamalCiphertext { c1, c2 }
}

/// 重加密：`c1 += r·G, c2 += r·pk`。
pub fn re_encrypt(ct: &ElGamalCiphertext, pk: &G1Point, r: &Scalar) -> ElGamalCiphertext {
    let g = g1_generator();
    let c1 = g1_add(&ct.c1, &g1_mul(r, &g));
    let c2 = g1_add(&ct.c2, &g1_mul(r, pk));
    ElGamalCiphertext { c1, c2 }
}

/// 解密：`M = c2 - sk·c1`。
pub fn decrypt(ct: &ElGamalCiphertext, sk: &Scalar) -> G1Point {
    g1_sub(&ct.c2, &g1_mul(sk, &ct.c1))
}

/// 生成揭牌令牌：`token = sk · c1`。
pub fn gen_reveal_token(ct: &ElGamalCiphertext, sk: &Scalar) -> G1Point {
    g1_mul(sk, &ct.c1)
}

/// Remask：`c2 += sk · c1`（c1 不变）。c1 必须非 identity。
///
/// # Errors
/// 当 c1 为 identity 点时返回 `Serialization` 错误。
pub fn remask(ct: &ElGamalCiphertext, sk: &Scalar) -> UtilsResult<ElGamalCiphertext> {
    if g1_is_identity(&ct.c1) {
        return Err(UtilsError::Serialization);
    }
    let c2 = g1_add(&ct.c2, &g1_mul(sk, &ct.c1));
    Ok(ElGamalCiphertext { c1: ct.c1, c2 })
}

/// shuffle_v2 链上注入 player_pk 贡献：`c2 += player_pk`（c1 不变）。
pub fn add_pk_to_c2(ct: &ElGamalCiphertext, player_pk: &G1Point) -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1: ct.c1,
        c2: g1_add(&ct.c2, player_pk),
    }
}

/// 批量加密：对每张明文用对应的随机数加密。
pub fn encrypt_batch(
    plaintexts: &[G1Point],
    pk: &G1Point,
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
) -> UtilsResult<Vec<ElGamalCiphertext>> {
    ciphertexts.iter().map(|ct| remask(ct, sk)).collect()
}

/// 提取所有 c1 点。
pub fn extract_c1s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Point> {
    ciphertexts.iter().map(|ct| ct.c1).collect()
}

/// 提取所有 c2 点。
pub fn extract_c2s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Point> {
    ciphertexts.iter().map(|ct| ct.c2).collect()
}

/// 占位牌（c1=c2=identity），用于未发牌状态。
pub fn new_placeholder_card() -> ElGamalCiphertext {
    let identity = g1_identity();
    ElGamalCiphertext {
        c1: identity,
        c2: identity,
    }
}

// ========== PK 所有权证明（80 字节 Schnorr，自定义格式保留） ==========

/// 验证 PK 所有权证明（Schnorr proof of knowledge of sk where pk = G · sk）。
///
/// `proof_bytes` 格式：commitment (48 bytes G1) + response (32 bytes scalar) = 80 bytes
///
/// 挑战派生：`challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)`
/// （M-D12 修复：使用 `hash_to_scalar` 替代原始 SHA2-256，清除高位确保 < 曲线阶）
///
/// 验证等式：`G · response == commitment + pk · challenge`
pub fn verify_pk_ownership(pk: &G1Point, proof_bytes: &[u8]) -> bool {
    // M-D11 修复：拒绝恒等元公钥
    if g1_is_identity(pk) {
        return false;
    }
    // 检查长度: 48 (commitment) + 32 (response) = 80
    if proof_bytes.len() != 80 {
        return false;
    }

    let g = g1_generator();
    let pk_bytes = serialize_g1(pk);
    let g_bytes = serialize_g1(&g);

    // 反序列化 commitment 和 response
    let commitment_bytes = &proof_bytes[0..48];
    let response_bytes = &proof_bytes[48..80];

    let commitment = match parse_g1(commitment_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let response = match parse_scalar(response_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 拒绝恒等元 commitment
    if g1_is_identity(&commitment) {
        return false;
    }

    // M-D12 修复：使用 hash_to_scalar 派生挑战
    let mut hash_input = Vec::with_capacity(g_bytes.len() + pk_bytes.len() + commitment_bytes.len());
    hash_input.extend_from_slice(&g_bytes);
    hash_input.extend_from_slice(&pk_bytes);
    hash_input.extend_from_slice(commitment_bytes);
    let challenge = match hash_to_scalar(&hash_input) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 验证: G * response == commitment + pk * challenge
    verify_dleq(&g, pk, &commitment, &response, &challenge)
}

// ========== 单元测试 ==========
//
// 测试策略：
// - 纯逻辑测试（u64_to_ascii）：无门控，std-test 下可运行
// - 序列化 round-trip 测试：用硬编码合法字节（不调 syscall），std-test 下可运行
// - crypto 操作测试（hash/encrypt 等）：需 syscall，仅在 riscv32 target 存在
//   （riscv32 不支持 cargo test，实际验证在 Phase 5 E2E 集成测试中完成）

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u64_to_ascii() {
        assert_eq!(u64_to_ascii(0), vec![b'0']);
        assert_eq!(u64_to_ascii(9), vec![b'9']);
        assert_eq!(u64_to_ascii(10), vec![b'1', b'0']);
        assert_eq!(u64_to_ascii(123), vec![b'1', b'2', b'3']);
        assert_eq!(u64_to_ascii(u64::MAX), b"18446744073709551615".to_vec());
    }

    #[test]
    fn test_parse_g1_wrong_length() {
        assert!(parse_g1(&[0u8; 47]).is_err());
        assert!(parse_g1(&[0u8; 49]).is_err());
    }

    #[test]
    fn test_parse_scalar_wrong_length() {
        assert!(parse_scalar(&[0u8; 31]).is_err());
        assert!(parse_scalar(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_serialize_g1_round_trip() {
        // 用任意非全零字节构造 G1Point（不验证子群，仅测字节往返）
        let bytes = [0x42u8; 48];
        let point = parse_g1(&bytes).unwrap();
        let recovered = serialize_g1(&point);
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn test_serialize_scalar_round_trip() {
        let bytes = [0xABu8; 32];
        let scalar = parse_scalar(&bytes).unwrap();
        let recovered = serialize_scalar(&scalar);
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn test_scalar_zero_one() {
        let zero = scalar_zero();
        let one = scalar_one();
        // 零标量的字节应全零
        assert_eq!(serialize_scalar(&zero), [0u8; 32]);
        // 单位标量的字节应只有最低字节为 1
        let one_bytes = serialize_scalar(&one);
        assert_eq!(one_bytes[31], 1);
        assert_eq!(one_bytes[0..31], [0u8; 31]);
    }

    #[test]
    fn test_scalar_from_u64() {
        let s = scalar_from_u64(0);
        assert_eq!(serialize_scalar(&s), [0u8; 32]);

        let s = scalar_from_u64(1);
        let bytes = serialize_scalar(&s);
        assert_eq!(bytes[31], 1);
        assert_eq!(bytes[0..31], [0u8; 31]);

        let s = scalar_from_u64(0xFFFF_FFFF_FFFF_FFFF);
        let bytes = serialize_scalar(&s);
        // u64::MAX 的大端 8 字节应放在 [24..32]
        assert_eq!(&bytes[24..32], &[0xFFu8; 8]);
        assert_eq!(&bytes[0..24], &[0u8; 24]);
    }

    #[test]
    fn test_utils_error_eq() {
        assert_eq!(UtilsError::InvalidBlsPoint, UtilsError::InvalidBlsPoint);
        assert_ne!(UtilsError::InvalidBlsPoint, UtilsError::InvalidBlsScalar);
    }

    // ===== crypto 操作测试（仅 riscv32 target，需 syscall）=====

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_new_placeholder_card() {
        let card = new_placeholder_card();
        // 占位牌的 c1 和 c2 都不是全零字节（identity 的 compressed 编码非全零）
        // 但它们应该相等（都是 identity）
        assert!(g1_equal(&card.c1, &card.c2));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_verify_pk_ownership_wrong_length_rejected() {
        // 构造一个非 identity 的 pk（任意非零字节，不调 syscall）
        let pk_bytes = [0x42u8; 48];
        let pk = parse_g1(&pk_bytes).unwrap();
        let short_proof = vec![0u8; 79];
        assert!(!verify_pk_ownership(&pk, &short_proof));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_hash_to_scalar_deterministic() {
        let s1 = hash_to_scalar(b"hello").unwrap();
        let s2 = hash_to_scalar(b"hello").unwrap();
        assert_eq!(serialize_scalar(&s1), serialize_scalar(&s2));
        let s3 = hash_to_scalar(b"world").unwrap();
        assert_ne!(serialize_scalar(&s1), serialize_scalar(&s3));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_g1_generator_and_identity() {
        let g = g1_generator();
        let id = g1_identity();
        assert!(!g1_equal(&g, &id));
        assert!(g1_is_identity(&id));
        assert!(!g1_is_identity(&g));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_mul(&sk, &g1_generator());
        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(999);
        let ct = encrypt(&plaintext, &pk, &r);
        let recovered = decrypt(&ct, &sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_verify_dleq_honest() {
        let sk = scalar_from_u64(42);
        let r = scalar_from_u64(99);
        let g = g1_generator();
        let pk = g1_mul(&sk, &g);
        let commitment = g1_mul(&r, &g);
        let c = scalar_from_u64(7);
        let s = scalar_add(&r, &scalar_mul(&c, &sk));
        assert!(verify_dleq(&g, &pk, &commitment, &s, &c));
    }
}
