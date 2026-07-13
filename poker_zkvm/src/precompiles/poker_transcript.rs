//! 共享 Fiat-Shamir Transcript（Phase M — M-1）。
//!
//! 基于 Blake2b256 的有状态 transcript，供 RemaskProof / LeaveProof /
//! ReconstructProof / ChaumPedersenDLEQProof / GeneralizedSchnorrProof 使用。
//!
//! # 设计
//!
//! - 状态机：`state = Blake2b256(state || len_label_le4 || label || len_msg_le4 || msg)`
//! - 每次 `append_*` 更新 state，保证 prove/verify 两端追加完全相同的字节序列
//! - `challenge(label)` 先追加 `b"challenge"` 再哈希 state 生成 Fr 标量
//! - `challenge_vec(label, n)` 使用子标签 `label + i.to_string()` 生成 n 个标量
//!
//! # 辅助函数
//!
//! 从 `dleq.rs` 提取为 pub，供所有 proof 模块共享：
//! - G1 点序列化/反序列化（33B 压缩格式 + 64B x||y 格式）
//! - Fr 标量序列化/反序列化（32B LE）
//! - `bytes_le_to_u256` 转换

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

// ===== PokerTranscript =====

/// 有状态 Fiat-Shamir Transcript（Blake2b256）。
///
/// 每次 `append_*` 调用更新内部 state，`challenge` 基于当前 state 生成标量。
/// prove 和 verify 必须按完全相同的顺序调用完全相同的 append/challenge 序列。
#[derive(Debug, Clone)]
pub struct PokerTranscript {
    /// 当前 transcript 状态（Blake2b256 输出，32 字节）。
    state: Vec<u8>,
}

impl PokerTranscript {
    /// 创建新 transcript，初始 state = Blake2b256(domain_tag)。
    pub fn new(domain_tag: &[u8]) -> Self {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
        hasher.update(domain_tag);
        let mut out = vec![0u8; 32];
        hasher.finalize_variable(&mut out).expect("finalize");
        Self { state: out }
    }

    /// 追加带标签的消息到 transcript。
    ///
    /// 状态更新：`state = Blake2b256(state || len_label_le4 || label || len_msg_le4 || msg)`
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut data = self.state.clone();
        let label_len = label.len() as u32;
        data.extend_from_slice(&label_len.to_le_bytes());
        data.extend_from_slice(label);
        let msg_len = message.len() as u32;
        data.extend_from_slice(&msg_len.to_le_bytes());
        data.extend_from_slice(message);

        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
        hasher.update(&data);
        self.state = vec![0u8; 32];
        hasher.finalize_variable(&mut self.state).expect("finalize");
    }

    /// 追加 G1 点到 transcript（64 字节 x||y LE 格式）。
    pub fn append_point(&mut self, label: &[u8], point: &G1Affine) {
        let bytes = g1_to_64bytes(point);
        self.append_message(label, &bytes);
    }

    /// 追加 Fr 标量到 transcript（32 字节 LE 格式）。
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let bytes = fr_to_32bytes(scalar);
        self.append_message(label, &bytes);
    }

    /// 从 transcript 生成 challenge 标量。
    ///
    /// 1. `append_message(label, b"challenge")`
    /// 2. `Fr::from_le_bytes_mod_order(state)`
    pub fn challenge(&mut self, label: &[u8]) -> Fr {
        self.append_message(label, b"challenge");
        Fr::from_le_bytes_mod_order(&self.state)
    }

    /// 批量生成 challenge 标量，使用带索引的子标签。
    ///
    /// 对每个 i，子标签 = `label + i.to_string()`，然后调用 `challenge`。
    pub fn challenge_vec(&mut self, label: &[u8], n: usize) -> Vec<Fr> {
        (0..n)
            .map(|i| {
                let mut sub_label = label.to_vec();
                sub_label.extend_from_slice(i.to_string().as_bytes());
                self.challenge(&sub_label)
            })
            .collect()
    }
}

// ===== G1 序列化辅助函数 =====

/// G1 点序列化为 64 字节 (x||y, 32B LE each)。
///
/// identity 点序列化为全零。
pub fn g1_to_64bytes(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if point.is_zero() {
        return out;
    }
    let x_bytes = point.x.into_bigint().to_bytes_le();
    let y_bytes = point.y.into_bigint().to_bytes_le();
    out[0..32].copy_from_slice(&x_bytes);
    out[32..64].copy_from_slice(&y_bytes);
    out
}

/// 从 64 字节 (x||y, 32B LE each) 解析 G1Affine，含 on-curve 校验。
///
/// 全零字节解析为 identity 点。
pub fn parse_g1_from_64bytes(bytes: &[u8]) -> Option<G1Affine> {
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

/// G1 点压缩为 33 字节 (32B x LE + 1B flags)。
///
/// flags: bit 0 = infinity, bit 1 = y parity。
pub fn compress_g1(point: &G1Affine) -> [u8; 33] {
    let mut out = [0u8; 33];
    let mut flags = 0u8;
    if point.is_zero() {
        flags |= 1;
    } else {
        let x_bytes = point.x.into_bigint().to_bytes_le();
        out[0..32].copy_from_slice(&x_bytes);
        let y_bytes = point.y.into_bigint().to_bytes_le();
        if y_bytes[0] & 1 != 0 {
            flags |= 2;
        }
    }
    out[32] = flags;
    out
}

/// 从 33 字节 (32B x LE + 1B flags) 解压 G1Affine。
///
/// flags: bit 0 = infinity, bit 1 = y parity。
pub fn decompress_g1(bytes: &[u8; 33]) -> Option<G1Affine> {
    let flags = bytes[32];
    if flags & 1 != 0 {
        return Some(G1Affine::identity());
    }
    let x_bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(&bytes[0..32]));
    let x_fq = Fq::from_bigint(x_bigint)?;
    let y_sq = x_fq * x_fq * x_fq + Fq::from(3u64);
    let y_fq = y_sq.sqrt()?;
    let y_bytes = y_fq.into_bigint().to_bytes_le();
    let y_is_odd = y_bytes[0] & 1 != 0;
    let want_odd = flags & 2 != 0;
    let y_fq = if y_is_odd == want_odd { y_fq } else { -y_fq };
    Some(G1Affine::new(x_fq, y_fq))
}

// ===== Fr 序列化辅助函数 =====

/// Fr 标量序列化为 32 字节 LE。
pub fn fr_to_32bytes(scalar: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = scalar.into_bigint().to_bytes_le();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

/// 从 32 字节 LE 解析 Fr 标量。
pub fn fr_from_32bytes(bytes: &[u8]) -> Option<Fr> {
    if bytes.len() != 32 {
        return None;
    }
    let bigint = ark_ff::BigInt::<4>::new(bytes_le_to_u256(bytes));
    Fr::from_bigint(bigint)
}

// ===== 通用辅助函数 =====

/// 从 32 字节 little-endian 还原 [u64; 4]。
pub fn bytes_le_to_u256(bytes: &[u8]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (k, limb) in limbs.iter_mut().enumerate() {
        let start = k * 8;
        *limb = u64::from_le_bytes(bytes[start..start + 8].try_into().expect("8 bytes"));
    }
    limbs
}

/// BN254 G1 生成元的 64 字节表示 (x||y, 32B LE each)。
pub fn generator_64bytes() -> [u8; 64] {
    use crate::precompiles::elgamal::generator;
    g1_to_64bytes(&generator())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::{CurveGroup, PrimeGroup};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_transcript_deterministic() {
        let g = G1Projective::generator().into_affine();
        let mut ts1 = PokerTranscript::new(b"test_domain");
        let mut ts2 = PokerTranscript::new(b"test_domain");

        ts1.append_point(b"pt", &g);
        ts2.append_point(b"pt", &g);

        let c1 = ts1.challenge(b"c");
        let c2 = ts2.challenge(b"c");
        assert_eq!(c1, c2, "相同输入序列应产生相同 challenge");
    }

    #[test]
    fn test_transcript_different_order() {
        let g = G1Projective::generator().into_affine();
        let s = Fr::from(42u64);

        let mut ts1 = PokerTranscript::new(b"test");
        ts1.append_point(b"a", &g);
        ts1.append_scalar(b"b", &s);

        let mut ts2 = PokerTranscript::new(b"test");
        ts2.append_scalar(b"b", &s);
        ts2.append_point(b"a", &g);

        let c1 = ts1.challenge(b"c");
        let c2 = ts2.challenge(b"c");
        assert_ne!(c1, c2, "不同追加顺序应产生不同 challenge");
    }

    #[test]
    fn test_transcript_different_domain() {
        let g = G1Projective::generator().into_affine();

        let mut ts1 = PokerTranscript::new(b"domain_a");
        ts1.append_point(b"pt", &g);

        let mut ts2 = PokerTranscript::new(b"domain_b");
        ts2.append_point(b"pt", &g);

        let c1 = ts1.challenge(b"c");
        let c2 = ts2.challenge(b"c");
        assert_ne!(c1, c2, "不同 domain tag 应产生不同 challenge");
    }

    #[test]
    fn test_challenge_vec_consistency() {
        let mut ts1 = PokerTranscript::new(b"test");
        let mut ts2 = PokerTranscript::new(b"test");

        let vec = ts1.challenge_vec(b"rho", 5);

        for (i, item) in vec.iter().enumerate() {
            let mut sub_label = b"rho".to_vec();
            sub_label.extend_from_slice(i.to_string().as_bytes());
            let single = ts2.challenge(&sub_label);
            assert_eq!(*item, single, "challenge_vec[{i}] 应与逐个 challenge 一致");
        }
    }

    #[test]
    fn test_challenge_advances_state() {
        let mut ts = PokerTranscript::new(b"test");
        let c1 = ts.challenge(b"c1");
        let c2 = ts.challenge(b"c2");
        assert_ne!(c1, c2, "连续 challenge 应产生不同值（state 前进）");
    }

    #[test]
    fn test_g1_64bytes_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let scalar = Fr::rand(&mut rng);
        let pt = (G1Projective::from(g) * scalar).into_affine();

        let bytes = g1_to_64bytes(&pt);
        let recovered = parse_g1_from_64bytes(&bytes).expect("roundtrip");
        assert_eq!(pt, recovered);
    }

    #[test]
    fn test_g1_64bytes_identity() {
        let id = G1Affine::identity();
        let bytes = g1_to_64bytes(&id);
        assert!(&bytes.iter().all(|&b| b == 0));
        let recovered = parse_g1_from_64bytes(&bytes).expect("identity roundtrip");
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_g1_64bytes_invalid_point() {
        let mut bytes = g1_to_64bytes(&G1Projective::generator().into_affine());
        bytes[0] ^= 0xFF;
        assert!(parse_g1_from_64bytes(&bytes).is_none(), "无效点应返回 None");
    }

    #[test]
    fn test_g1_compress_roundtrip() {
        let mut rng = test_rng();
        let g = G1Projective::generator().into_affine();
        let scalar = Fr::rand(&mut rng);
        let pt = (G1Projective::from(g) * scalar).into_affine();

        let bytes = compress_g1(&pt);
        let recovered = decompress_g1(&bytes).expect("roundtrip");
        assert_eq!(pt, recovered);
    }

    #[test]
    fn test_g1_compress_identity() {
        let id = G1Affine::identity();
        let bytes = compress_g1(&id);
        assert_eq!(bytes[32] & 1, 1, "identity flags bit 0 应为 1");
        let recovered = decompress_g1(&bytes).expect("identity roundtrip");
        assert_eq!(id, recovered);
    }

    #[test]
    fn test_fr_32bytes_roundtrip() {
        let mut rng = test_rng();
        let s = Fr::rand(&mut rng);
        let bytes = fr_to_32bytes(&s);
        let recovered = fr_from_32bytes(&bytes).expect("roundtrip");
        assert_eq!(s, recovered);
    }

    #[test]
    fn test_fr_32bytes_wrong_length() {
        let short = [0u8; 16];
        assert!(fr_from_32bytes(&short).is_none());
    }
}
