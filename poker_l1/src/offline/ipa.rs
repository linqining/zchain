//! IPA（Inner Product Argument）verifier（Task 25 — SubTask 25.1 / 25.2 / 25.3）。
//!
//! 严格遵循 spec.md L509–513（FROZEN 2026-06-27）：
//! - **SubTask 25.1**：`IpaProof` 结构
//! - **SubTask 25.2**：注册 `ipa_verify`
//! - **SubTask 25.3**：MVP — verifier stub
//!
//! ## IPA 算法
//!
//! spec.md L513：执行内积论证检查（Pedersen 承诺 + 折叠递归），返回布尔结果。
//!
//! 算法概要：
//! 1. prover 提交 commitment `C = <a, G> + <b, H> * <a, b> * U`
//! 2. 每轮 prover 发送 `L_i, R_i`（cross commitments）
//! 3. verifier 发送 challenge `x_i = Fiat-Shamir(transcript)`
//! 4. 折叠：`a' = a_L + x_i^{-1} * a_R`, `b' = b_R + x_i^{-1} * b_L`
//! 5. 最终轮：`a, b` 缩为标量，验证 `C == a * G_final + b * H_final + (a*b) * U`

use std::sync::Arc;

use crate::error::PokerL1Error;

use super::zk_verifier::{SCHEME_IPA, SchemeId, VerifierStatus, ZkVerifier};

/// IPA proof 最小字节数（MVP stub 下限）。
///
/// Production 实现须包含：
/// - `L_vec`: n 个 G1 compressed 点（每个 48 字节）
/// - `R_vec`: n 个 G1 compressed 点（每个 48 字节）
/// - `a_final`: 标量（32 字节）
/// - `b_final`: 标量（32 字节）
pub const IPA_PROOF_MIN_SIZE: usize = 32;

/// IPA proof 结构（SubTask 25.1）。
///
/// MVP 阶段仅作为类型定义，Production 阶段须实际反序列化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpaProof {
    /// 折叠轮次的 L 向量（每轮一个 G1 点）。
    pub l_vec: Vec<[u8; 48]>,
    /// 折叠轮次的 R 向量（每轮一个 G1 点）。
    pub r_vec: Vec<[u8; 48]>,
    /// 最终标量 a。
    pub a_final: [u8; 32],
    /// 最终标量 b。
    pub b_final: [u8; 32],
}

impl IpaProof {
    /// 序列化为字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.l_vec.len() as u32).to_be_bytes());
        for l in &self.l_vec {
            out.extend_from_slice(l);
        }
        out.extend_from_slice(&(self.r_vec.len() as u32).to_be_bytes());
        for r in &self.r_vec {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(&self.a_final);
        out.extend_from_slice(&self.b_final);
        out
    }
}

/// IPA verifier stub（SubTask 25.3）。
///
/// MVP 阶段：
/// - `Stub` 状态：仅校验 proof 格式（非空 + >= MIN_SIZE）
/// - `Production` 状态：MVP 未实现
#[derive(Debug, Default)]
pub struct IpaVerifier;

impl IpaVerifier {
    /// 创建 verifier 实例。
    pub const fn new() -> Self {
        Self
    }

    /// 包装为 `Arc<dyn ZkVerifier>` 以便注册到 ZkVerifierRegistry。
    pub fn into_registry_verifier() -> Arc<dyn ZkVerifier> {
        Arc::new(Self::new())
    }
}

impl ZkVerifier for IpaVerifier {
    fn scheme_id(&self) -> SchemeId {
        SCHEME_IPA
    }

    fn verify(
        &self,
        proof: &[u8],
        _public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        if status == VerifierStatus::Stub {
            self.validate_proof_format(proof)?;
            return Ok(true);
        }

        // Production 状态：MVP 未实现
        // TODO: 实现内积论证验证（Pedersen 承诺 + 折叠递归 + Fiat-Shamir challenge）
        Err(PokerL1Error::Other(
            "IPA Production verifier 尚未实现".to_string(),
        ))
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        if proof.is_empty() {
            return Err(PokerL1Error::InvalidZkProofFormat(
                "ipa proof 不能为空".to_string(),
            ));
        }
        if proof.len() < IPA_PROOF_MIN_SIZE {
            return Err(PokerL1Error::InvalidZkProofFormat(format!(
                "ipa proof 长度 {} < 最小要求 {}",
                proof.len(),
                IPA_PROOF_MIN_SIZE
            )));
        }
        Ok(())
    }
}

/// 便捷函数：注册 IPA verifier 到 ZkVerifierRegistry。
pub fn register_ipa_verifier(registry: &mut super::zk_verifier::ZkVerifierRegistry) {
    registry.register(IpaVerifier::into_registry_verifier());
}

#[cfg(test)]
mod tests {
    use super::super::zk_verifier::{ZkPublicIo, ZkVerifierRegistry};
    use super::*;

    fn make_public_io() -> ZkPublicIo {
        ZkPublicIo {
            initial_commitment: [0x01; 32],
            final_commitment: [0x02; 32],
            state_delta_hash: [0x03; 32],
            ack_chain_hash: [0x04; 32],
            fold_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        }
    }

    #[test]
    fn test_scheme_id() {
        let v = IpaVerifier::new();
        assert_eq!(v.scheme_id(), SCHEME_IPA);
    }

    #[test]
    fn test_validate_proof_format_empty() {
        let v = IpaVerifier::new();
        let result = v.validate_proof_format(&[]);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_validate_proof_format_too_short() {
        let v = IpaVerifier::new();
        let result = v.validate_proof_format(&[0x00; 10]);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_validate_proof_format_valid() {
        let v = IpaVerifier::new();
        let result = v.validate_proof_format(&[0x00; IPA_PROOF_MIN_SIZE]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_stub_success() {
        let v = IpaVerifier::new();
        let pi = make_public_io();
        let proof = vec![0xAA; IPA_PROOF_MIN_SIZE];
        let result = v
            .verify(&proof, &pi, VerifierStatus::Stub)
            .expect("stub verify 应成功");
        assert!(result);
    }

    #[test]
    fn test_verify_stub_rejects_empty() {
        let v = IpaVerifier::new();
        let pi = make_public_io();
        let result = v.verify(&[], &pi, VerifierStatus::Stub);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_verify_production_not_implemented() {
        let v = IpaVerifier::new();
        let pi = make_public_io();
        let proof = vec![0xAA; IPA_PROOF_MIN_SIZE];
        let result = v.verify(&proof, &pi, VerifierStatus::Production);
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_register_and_zk_verify() {
        let mut registry = ZkVerifierRegistry::new();
        register_ipa_verifier(&mut registry);

        let pi = make_public_io();
        let proof = vec![0xAA; IPA_PROOF_MIN_SIZE];
        let result = registry
            .zk_verify(crate::DEFAULT_CHAIN_ID, SCHEME_IPA, &proof, &pi, 3, 1000)
            .expect("zk_verify 应成功");
        assert!(result.verified);
        assert_eq!(result.scheme_id, SCHEME_IPA);
    }

    #[test]
    fn test_ipa_proof_to_bytes_roundtrip_format() {
        let proof = IpaProof {
            l_vec: vec![[0x01; 48], [0x02; 48]],
            r_vec: vec![[0x03; 48], [0x04; 48]],
            a_final: [0x05; 32],
            b_final: [0x06; 32],
        };
        let bytes = proof.to_bytes();
        // 4 (l_vec len) + 2*48 (l_vec) + 4 (r_vec len) + 2*48 (r_vec) + 32 + 32
        assert_eq!(bytes.len(), 4 + 2 * 48 + 4 + 2 * 48 + 32 + 32);
    }
}
