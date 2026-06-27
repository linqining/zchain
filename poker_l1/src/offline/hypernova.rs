//! Hypernova verifier（Task 23 — SubTask 23.1 / 23.2 / 23.3 / 23.4）。
//!
//! 严格遵循 spec.md L497–525 + L659–663（FROZEN 2026-06-27）：
//! - **SubTask 23.1**：Proof 结构（folded instance、witness commitment、final sumcheck）
//! - **SubTask 23.2**：public_io 边界（O15 修复）— initial_commitment / final_commitment / state_delta_hash / ack_chain_hash / fold_step_count（上限 1000）
//! - **SubTask 23.3**：注册 `hypernova_verify`，Fiat-Shamir challenge
//! - **SubTask 23.4**：MVP — verifier stub
//!
//! ## MVP 实现说明
//!
//! 当前为 stub（`VerifierStatus::Stub`），仅校验 proof 格式合法性。
//! Production 实现须：
//! 1. 反序列化 folded instance + witness commitment + final sumcheck
//! 2. 重新生成 Fiat-Shamir challenge（基于 public_io）
//! 3. 验证 final sumcheck 等式
//! 4. 验证 folded instance 的 cross-language claim

use std::sync::Arc;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::error::PokerL1Error;
use crate::Hash;

use super::zk_verifier::{SchemeId, VerifierStatus, ZkVerifier, SCHEME_HYPERNOVA};

/// Hypernova Proof 最小字节数（SubTask 23.1）。
///
/// MVP stub 仅要求 proof 非空且 >= 此下限。
/// Production 实现须解析具体字段。
pub const HYPERNOVA_PROOF_MIN_SIZE: usize = 64;

/// Hypernova folded instance 字段（SubTask 23.1）。
///
/// MVP 阶段仅作为类型定义，Production 阶段须实际反序列化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedInstance {
    /// 折叠后的 CCS instance commitment。
    pub instance_commitment: Hash,
    /// 折叠步数（== public_io.fold_step_count）。
    pub fold_step_count: u32,
}

/// Hypernova witness commitment（SubTask 23.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessCommitment {
    /// witness commitment hash。
    pub commitment: Hash,
}

/// Hypernova final sumcheck（SubTask 23.1 + 23.3）。
///
/// Fiat-Shamir challenge 由 public_io 派生（SubTask 23.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalSumcheck {
    /// Sumcheck 多项式求值序列。
    pub evaluations: Vec<Hash>,
    /// 最终求和值。
    pub final_sum: Hash,
}

/// Hypernova Proof 结构（SubTask 23.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypernovaProof {
    /// 折叠后的 CCS instance。
    pub folded_instance: FoldedInstance,
    /// witness commitment。
    pub witness_commitment: WitnessCommitment,
    /// final sumcheck（含 Fiat-Shamir challenge 派生的求值）。
    pub final_sumcheck: FinalSumcheck,
}

impl HypernovaProof {
    /// 序列化为字节（用于 proof hash 计算 / 链上存储）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.folded_instance.instance_commitment);
        out.extend_from_slice(&self.folded_instance.fold_step_count.to_be_bytes());
        out.extend_from_slice(&self.witness_commitment.commitment);
        for eval in &self.final_sumcheck.evaluations {
            out.extend_from_slice(eval);
        }
        out.extend_from_slice(&self.final_sumcheck.final_sum);
        out
    }

    /// 计算 proof hash（blake2b_256）。
    pub fn proof_hash(&self) -> Hash {
        let bytes = self.to_bytes();
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(&bytes);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// 由 public_io 派生 Fiat-Shamir challenge（SubTask 23.3）。
///
/// `challenge = blake2b_256("hypernova_fs" || public_io.to_bytes())`
pub fn fiat_shamir_challenge(public_io: &super::zk_verifier::ZkPublicIo) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(b"hypernova_fs");
    hasher.update(&public_io.to_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// Hypernova verifier stub（SubTask 23.4）。
///
/// MVP 阶段：
/// - `Stub` 状态：仅校验 proof 格式（非空 + >= MIN_SIZE）
/// - `Production` 状态：调用 `verify_production`（当前未实现，返回 `Other` 错误）
#[derive(Debug, Default)]
pub struct HypernovaVerifier;

impl HypernovaVerifier {
    /// 创建 verifier 实例。
    pub const fn new() -> Self {
        Self
    }

    /// 包装为 `Arc<dyn ZkVerifier>` 以便注册到 registry。
    pub fn into_registry_verifier() -> Arc<dyn ZkVerifier> {
        Arc::new(Self::new())
    }
}

impl ZkVerifier for HypernovaVerifier {
    fn scheme_id(&self) -> SchemeId {
        SCHEME_HYPERNOVA
    }

    fn verify(
        &self,
        proof: &[u8],
        public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        // Stub 状态：仅校验格式
        if status == VerifierStatus::Stub {
            self.validate_proof_format(proof)?;
            return Ok(true);
        }

        // Production 状态：MVP 未实现，返回错误
        // TODO: 实现 Production 验证（folded instance + witness commitment + final sumcheck）
        let _ = public_io;
        Err(PokerL1Error::Other(
            "Hypernova Production verifier 尚未实现".to_string(),
        ))
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        if proof.is_empty() {
            return Err(PokerL1Error::InvalidZkProofFormat(
                "hypernova proof 不能为空".to_string(),
            ));
        }
        if proof.len() < HYPERNOVA_PROOF_MIN_SIZE {
            return Err(PokerL1Error::InvalidZkProofFormat(format!(
                "hypernova proof 长度 {} < 最小要求 {}",
                proof.len(),
                HYPERNOVA_PROOF_MIN_SIZE
            )));
        }
        Ok(())
    }
}

/// 便捷函数：注册 Hypernova verifier 到 registry。
pub fn register_hypernova_verifier(
    registry: &mut super::zk_verifier::ZkVerifierRegistry,
) {
    registry.register(HypernovaVerifier::into_registry_verifier());
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::zk_verifier::{ZkPublicIo, ZkVerifierRegistry};

    fn make_public_io(fold_step_count: u32) -> ZkPublicIo {
        ZkPublicIo {
            initial_commitment: [0x01; 32],
            final_commitment: [0x02; 32],
            state_delta_hash: [0x03; 32],
            ack_chain_hash: [0x04; 32],
            fold_step_count,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        }
    }

    #[test]
    fn test_scheme_id() {
        let v = HypernovaVerifier::new();
        assert_eq!(v.scheme_id(), SCHEME_HYPERNOVA);
    }

    #[test]
    fn test_validate_proof_format_empty() {
        let v = HypernovaVerifier::new();
        let result = v.validate_proof_format(&[]);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_validate_proof_format_too_short() {
        let v = HypernovaVerifier::new();
        let result = v.validate_proof_format(&[0x00; 10]);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_validate_proof_format_valid() {
        let v = HypernovaVerifier::new();
        let result = v.validate_proof_format(&[0x00; HYPERNOVA_PROOF_MIN_SIZE]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_stub_returns_true() {
        let v = HypernovaVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0x00; HYPERNOVA_PROOF_MIN_SIZE];
        let result = v
            .verify(&proof, &public_io, VerifierStatus::Stub)
            .expect("stub verify 应成功");
        assert!(result);
    }

    #[test]
    fn test_verify_stub_rejects_empty_proof() {
        let v = HypernovaVerifier::new();
        let public_io = make_public_io(1);
        let result = v.verify(&[], &public_io, VerifierStatus::Stub);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_verify_production_not_implemented() {
        let v = HypernovaVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0x00; HYPERNOVA_PROOF_MIN_SIZE];
        let result = v.verify(&proof, &public_io, VerifierStatus::Production);
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_register_and_zk_verify() {
        let mut registry = ZkVerifierRegistry::new();
        register_hypernova_verifier(&mut registry);

        let public_io = make_public_io(5);
        let proof = vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE];
        let result = registry
            .zk_verify(crate::DEFAULT_CHAIN_ID, SCHEME_HYPERNOVA, &proof, &public_io, 3, 1000)
            .expect("zk_verify 应成功");
        assert!(result.verified);
        assert_eq!(result.verifier_status, VerifierStatus::Stub);
        assert_eq!(result.scheme_id, SCHEME_HYPERNOVA);
    }

    #[test]
    fn test_fiat_shamir_deterministic() {
        let pi1 = make_public_io(5);
        let pi2 = make_public_io(5);
        assert_eq!(fiat_shamir_challenge(&pi1), fiat_shamir_challenge(&pi2));

        let pi3 = make_public_io(6);
        assert_ne!(fiat_shamir_challenge(&pi1), fiat_shamir_challenge(&pi3));
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let proof1 = HypernovaProof {
            folded_instance: FoldedInstance {
                instance_commitment: [0x01; 32],
                fold_step_count: 5,
            },
            witness_commitment: WitnessCommitment {
                commitment: [0x02; 32],
            },
            final_sumcheck: FinalSumcheck {
                evaluations: vec![[0x03; 32], [0x04; 32]],
                final_sum: [0x05; 32],
            },
        };
        let proof2 = proof1.clone();
        assert_eq!(proof1.proof_hash(), proof2.proof_hash());

        let proof3 = HypernovaProof {
            folded_instance: FoldedInstance {
                instance_commitment: [0xFF; 32],
                ..proof1.clone().folded_instance
            },
            ..proof1.clone()
        };
        assert_ne!(proof1.proof_hash(), proof3.proof_hash());
    }
}
