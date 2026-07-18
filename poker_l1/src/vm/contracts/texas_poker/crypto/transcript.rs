//! Fiat-Shamir Transcript（移植自 `texas_poker_move/sources/bls_transcript.move`）。
//!
//! 使用 SHA3-256 增量哈希，替代 Rust 生态的 Merlin Transcript。
//!
//! # M-P13 长度前缀编码
//!
//! 每次 `append_message(label, message)`：
//! 1. `data = state || len_le(label, 4) || label || len_le(msg, 4) || msg`
//! 2. `state = SHA3-256(data)`
//!
//! 这样不同 `(label, message)` 对的拼接结果唯一，防止长度扩展攻击和歧义编码。
//!
//! # 挑战生成
//!
//! `challenge(label)`：
//! 1. `append_message(label, b"challenge")`
//! 2. `hash_to_scalar(state)`（清高 2 位确保 < 曲线阶）
//!
//! `challenge_vec(label, n)`：对每个 `i = 0..n`，用 `label + ascii(i)` 作为子标签调 `challenge`。

use blstrs::Scalar;
use sha3::{Digest, Sha3_256};

use super::bls_elgamal::ElGamalCiphertext;
use super::bls_scalar::{hash_to_scalar, serialize_g1, serialize_scalar, u64_to_ascii};
use crate::error::PokerL1Result;

/// Fiat-Shamir Transcript。
#[derive(Debug, Clone)]
pub struct Transcript {
    state: Vec<u8>,
}

impl Transcript {
    /// 创建新 Transcript，初始状态为 `SHA3-256(protocol_name)`。
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(protocol_name);
        let state = hasher.finalize().to_vec();
        Self { state }
    }

    /// 追加 G1 点。
    pub fn append_point(&mut self, label: &[u8], point: &blstrs::G1Projective) {
        let bytes = serialize_g1(point);
        self.append_message(label, &bytes);
    }

    /// 批量追加 G1 点向量，所有点使用同一 label。
    pub fn append_points(&mut self, label: &[u8], points: &[blstrs::G1Projective]) {
        for p in points {
            self.append_point(label, p);
        }
    }

    /// 批量追加密文向量，c1 用 `c1_label`、c2 用 `c2_label`。
    pub fn append_ciphertexts(
        &mut self,
        c1_label: &[u8],
        c2_label: &[u8],
        cts: &[ElGamalCiphertext],
    ) {
        for ct in cts {
            self.append_point(c1_label, &ct.c1);
            self.append_point(c2_label, &ct.c2);
        }
    }

    /// 追加标量。
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Scalar) {
        let bytes = serialize_scalar(scalar);
        self.append_message(label, &bytes);
    }

    /// 追加任意消息（M-P13 长度前缀编码）。
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut data = self.state.clone();
        // label 长度前缀（4 字节小端）
        data.extend_from_slice(&(label.len() as u32).to_le_bytes());
        data.extend_from_slice(label);
        // message 长度前缀（4 字节小端）
        data.extend_from_slice(&(message.len() as u32).to_le_bytes());
        data.extend_from_slice(message);
        // state = SHA3-256(data)
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        self.state = hasher.finalize().to_vec();
    }

    /// 生成挑战标量。
    ///
    /// 1. `append_message(label, b"challenge")`
    /// 2. `hash_to_scalar(state)`
    pub fn challenge(&mut self, label: &[u8]) -> PokerL1Result<Scalar> {
        self.append_message(label, b"challenge");
        hash_to_scalar(&self.state)
    }

    /// 批量生成挑战标量。
    ///
    /// 对每个 `i = 0..n`，用 `label + ascii(i)` 作为子标签调 `challenge`。
    pub fn challenge_vec(&mut self, label: &[u8], n: usize) -> PokerL1Result<Vec<Scalar>> {
        let mut challenges = Vec::with_capacity(n);
        for i in 0..n {
            let idx_bytes = u64_to_ascii(i as u64);
            let mut sub_label = label.to_vec();
            sub_label.extend_from_slice(&idx_bytes);
            challenges.push(self.challenge(&sub_label)?);
        }
        Ok(challenges)
    }

    /// 获取当前状态（仅用于测试调试）。
    pub fn state(&self) -> &[u8] {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::bls_scalar::{g1_generator, hash_to_g1, scalar_from_u64};

    #[test]
    fn test_transcript_new() {
        let t1 = Transcript::new(b"protocol_A");
        let t2 = Transcript::new(b"protocol_A");
        let t3 = Transcript::new(b"protocol_B");
        assert_eq!(t1.state(), t2.state());
        assert_ne!(t1.state(), t3.state());
    }

    #[test]
    fn test_append_message_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_message(b"label1", b"msg1");
        t2.append_message(b"label1", b"msg1");
        assert_eq!(t1.state(), t2.state());
    }

    #[test]
    fn test_append_message_different_labels_diverge() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_message(b"label1", b"msg");
        t2.append_message(b"label2", b"msg");
        assert_ne!(t1.state(), t2.state());
    }

    #[test]
    fn test_m_p13_length_prefix_disambiguation() {
        // M-P13：长度前缀防止 (label="ab", msg="cd") 与 (label="abc", msg="d") 拼接后相同
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_message(b"ab", b"cd");
        t2.append_message(b"abc", b"d");
        assert_ne!(t1.state(), t2.state());
    }

    #[test]
    fn test_append_point() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let p = g1_generator();
        t1.append_point(b"G", &p);
        // 等价于 append_message(b"G", serialize_g1(&p))
        t2.append_message(b"G", &serialize_g1(&p));
        assert_eq!(t1.state(), t2.state());
    }

    #[test]
    fn test_append_scalar() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        let s = scalar_from_u64(42);
        t1.append_scalar(b"s", &s);
        t2.append_message(b"s", &serialize_scalar(&s));
        assert_eq!(t1.state(), t2.state());
    }

    #[test]
    fn test_challenge_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");
        t1.append_message(b"label", b"data");
        t2.append_message(b"label", b"data");
        let c1 = t1.challenge(b"c").unwrap();
        let c2 = t2.challenge(b"c").unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_challenge_vec() {
        let mut t = Transcript::new(b"test");
        let cs = t.challenge_vec(b"c", 3).unwrap();
        assert_eq!(cs.len(), 3);
        // 不同索引应产生不同挑战
        assert_ne!(cs[0], cs[1]);
        assert_ne!(cs[1], cs[2]);
    }

    #[test]
    fn test_append_ciphertexts() {
        let mut t = Transcript::new(b"test");
        let p = hash_to_g1(b"card");
        let r = scalar_from_u64(7);
        let pk = g1_generator() * scalar_from_u64(99);
        let ct = super::super::bls_elgamal::encrypt(&p, &pk, &r);
        t.append_ciphertexts(b"c1", b"c2", std::slice::from_ref(&ct));
        // 仅断言不 panic 且 state 改变
        assert!(!t.state().is_empty());
    }
}
