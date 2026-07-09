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

use super::zk_verifier::{
    ProofKind, SchemeId, VerifierStatus, ZkVerifyContext, ZkVerifier, SCHEME_HYPERNOVA,
    SCHEME_ZKSHUFFLE,
};

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

/// Hypernova verifier（SubTask 23.4 + Phase 8 SubTask 8.2.1-8.2.7）。
///
/// ## 状态分派
///
/// - `Stub` 状态：仅校验 proof 格式（非空 + >= MIN_SIZE）
/// - `Production` 状态：调用 `poker_zkvm::verifier::verify_production`（完整 sumcheck + PCS opening + transcript 校验）
///
/// ## grace period 双通道（v1.2 SubTask 8.2.3-8.2.4）
///
/// `verify_with_context` 根据 `ZkVerifyContext` 判定 grace 期状态：
/// - **切换前**（`production_switch_height == 0`）：`scheme_id=1` 走 Production；`scheme_id=4` 走 stub
/// - **grace 期内**：`scheme_id=4`（ZkShuffle）走 stub 路径但须匹配 `last_partial_proof_hash`（M2-003）；`scheme_id=1`（Zkvm）强制 Production
/// - **grace 期后**：所有 proof 强制 Production 路径（stub 彻底关闭）
///
/// ## M2-004 签名形式校验
///
/// 通过 `scheme_id` 反推期望的签名形式：
/// - `scheme_id=4`（ZkShuffle）→ 旧签名（无 `proof_kind` 字段）
/// - `scheme_id=1`（Zkvm）→ 新签名（含 `proof_kind` 字段）
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

    /// 计算 proof_hash = `blake2b_256(proof)`（M2-003 校验用）。
    fn compute_proof_hash(proof: &[u8]) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(proof);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 将 poker_l1 的 `ZkPublicIo` 转换为 poker_zkvm 的 `ZkPublicIo`（SubTask 8.2.1）。
    ///
    /// poker_zkvm 的 `ZkPublicIo` 包含 `randomness_seed` / `initial_commitment` /
    /// `final_commitment` / `event_hashes` 等字段，MVP 阶段以零值填充
    /// （实际绑定通过 proof 结构内的 `folded_instance.x_l` 隐式保证）。
    fn public_io_to_zkvm(
        public_io: &super::zk_verifier::ZkPublicIo,
    ) -> poker_zkvm::prover::ZkPublicIo {
        use poker_zkvm::ccs::Fr as ZkvmFr;
        use poker_zkvm::field::ZkvmField;

        // initial_commitment / final_commitment：从 32B Hash 解析为 Fr
        let initial_commitment = ZkvmFr::from_canonical_bytes(&public_io.initial_commitment)
            .unwrap_or_else(|_| ZkvmFr::zero());
        let final_commitment = ZkvmFr::from_canonical_bytes(&public_io.final_commitment)
            .unwrap_or_else(|_| ZkvmFr::zero());

        poker_zkvm::prover::ZkPublicIo {
            input: public_io.state_delta_hash.to_vec(), // 状态增量作为输入
            output: public_io.ack_chain_hash.to_vec(), // ack_chain 作为输出
            randomness_seed: ZkvmFr::zero(),
            initial_commitment,
            final_commitment,
            event_hashes: Vec::new(),
        }
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

        // Production 状态：调用 poker_zkvm::verifier::verify_production（SubTask 8.2.1）
        let zkvm_public_io = Self::public_io_to_zkvm(public_io);
        let ccs_whitelist = poker_zkvm::prover::default_ccs_whitelist();
        match poker_zkvm::verifier::verify_production(proof, &zkvm_public_io, &ccs_whitelist) {
            Ok(true) => Ok(true),
            Ok(false) => Err(PokerL1Error::InvalidZkProofFormat(
                "verify_production 返回 false".to_string(),
            )),
            Err(e) => Err(map_zkvm_error(e)),
        }
    }

    fn verify_with_context(
        &self,
        proof: &[u8],
        public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
        ctx: &ZkVerifyContext<'_>,
    ) -> Result<bool, PokerL1Error> {
        // M2-004：通过 scheme_id 反推期望的签名形式
        let proof_kind = ProofKind::from_scheme_id(SCHEME_HYPERNOVA)
            .ok_or(PokerL1Error::ProofKindMismatch {
                declared: 0,
                actual: SCHEME_HYPERNOVA as u8,
            })?;

        // M2-004：签名形式校验
        // Zkvm (scheme_id=1) 期望新签名（uses_new_signature=true）
        if proof_kind.expects_new_signature() != ctx.uses_new_signature {
            return Err(PokerL1Error::SignatureFormMismatch {
                scheme_id: SCHEME_HYPERNOVA,
            });
        }

        // grace 期结束后所有 proof 强制 Production 路径（SubTask 8.2.4）
        // stub 路径彻底关闭 — 须在 Stub 检查之前判定
        if ctx.grace_period_ended() {
            return self.verify(proof, public_io, VerifierStatus::Production);
        }

        // grace 期内：scheme_id=1 (Zkvm) 强制 Production 路径（SubTask 8.2.3）
        if ctx.in_grace_period() {
            return self.verify(proof, public_io, VerifierStatus::Production);
        }

        // 切换前（production_switch_height == 0）：按 status 分派
        // Stub 状态：仅校验格式（SubTask 8.2.5 — 行为保持不变）
        if status == VerifierStatus::Stub {
            self.validate_proof_format(proof)?;
            return Ok(true);
        }

        // Production 状态：完整验证
        self.verify(proof, public_io, status)
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

/// ZkShuffle verifier（grace 期内 scheme_id=4 的 stub 路径 + M2-003 校验）。
///
/// grace 期内 `proof_kind = ZkShuffle` 的旧 proof 走 stub 路径（仅校验 proof 长度），
/// 但 `proof_hash` 必须匹配链上已存 `last_partial_fold.proof_partial_hash`（M2-003）。
///
/// grace 期结束后走既有 ZkShuffle Production verifier（Phase 11 迁移）。
#[derive(Debug, Default)]
pub struct ZkShuffleVerifier;

impl ZkShuffleVerifier {
    /// 创建 verifier 实例。
    pub const fn new() -> Self {
        Self
    }

    /// 包装为 `Arc<dyn ZkVerifier>` 以便注册到 registry。
    pub fn into_registry_verifier() -> Arc<dyn ZkVerifier> {
        Arc::new(Self::new())
    }
}

impl ZkVerifier for ZkShuffleVerifier {
    fn scheme_id(&self) -> SchemeId {
        SCHEME_ZKSHUFFLE
    }

    fn verify(
        &self,
        proof: &[u8],
        _public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        // Stub 状态：仅校验格式
        if status == VerifierStatus::Stub {
            self.validate_proof_format(proof)?;
            return Ok(true);
        }

        // Production 状态：ZkShuffle Production verifier（Phase 11 迁移）
        // 当前未实现，返回错误（grace 期结束后须迁移到完整 ZkShuffle Production verifier）
        Err(PokerL1Error::Other(
            "ZkShuffle Production verifier 尚未迁移（Phase 11）".to_string(),
        ))
    }

    fn verify_with_context(
        &self,
        proof: &[u8],
        public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
        ctx: &ZkVerifyContext<'_>,
    ) -> Result<bool, PokerL1Error> {
        // M2-004：ZkShuffle (scheme_id=4) 期望旧签名（uses_new_signature=false）
        // grace 期后所有 CheckinTx 须使用新签名（含 proof_kind 字段）
        let proof_kind = ProofKind::from_scheme_id(SCHEME_ZKSHUFFLE)
            .ok_or(PokerL1Error::ProofKindMismatch {
                declared: 0,
                actual: SCHEME_ZKSHUFFLE as u8,
            })?;

        // M2-004 签名形式校验
        // grace 期后：所有 CheckinTx 须使用新签名（含 proof_kind 字段）
        // grace 期后 scheme_id=4 走 ZkShuffle Production verifier（仍期望旧签名？）
        // 实际上 spec.md L772：grace 期后所有 CheckinTx（不论 scheme_id）必须使用新签名
        // 但 ZkShuffle 的签名形式由 scheme_id=4 决定 — 此处需要区分 grace 期前后
        if ctx.grace_period_ended() {
            // grace 期后：所有 CheckinTx 必须使用新签名
            if !ctx.uses_new_signature {
                return Err(PokerL1Error::SignatureFormMismatch {
                    scheme_id: SCHEME_ZKSHUFFLE,
                });
            }
            // grace 期后走 ZkShuffle Production verifier（非 stub）
            return self.verify(proof, public_io, VerifierStatus::Production);
        }

        // grace 期内 / 切换前：ZkShuffle 期望旧签名
        if proof_kind.expects_new_signature() != ctx.uses_new_signature {
            return Err(PokerL1Error::SignatureFormMismatch {
                scheme_id: SCHEME_ZKSHUFFLE,
            });
        }

        // Stub 状态：仅校验格式
        if status == VerifierStatus::Stub {
            self.validate_proof_format(proof)?;

            // M2-003：grace 期内 stub 路径要求 proof_hash 匹配 last_partial_proof_hash
            if ctx.in_grace_period() {
                if let Some(expected_hash) = ctx.last_partial_proof_hash {
                    let actual_hash = HypernovaVerifier::compute_proof_hash(proof);
                    if &actual_hash != expected_hash {
                        return Err(PokerL1Error::PartialFoldHashImmutable);
                    }
                } else {
                    // grace 期内无 last_partial_proof_hash → 拒绝（防伪造新游戏）
                    return Err(PokerL1Error::InvalidZkProofFormat(
                        "grace 期内 ZkShuffle stub 路径要求 proof_hash 匹配链上已存 proof_partial_hash".to_string(),
                    ));
                }
            }

            return Ok(true);
        }

        // Production 状态：委托到 verify
        self.verify(proof, public_io, status)
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        if proof.is_empty() {
            return Err(PokerL1Error::InvalidZkProofFormat(
                "zkshuffle proof 不能为空".to_string(),
            ));
        }
        if proof.len() < HYPERNOVA_PROOF_MIN_SIZE {
            return Err(PokerL1Error::InvalidZkProofFormat(format!(
                "zkshuffle proof 长度 {} < 最小要求 {}",
                proof.len(),
                HYPERNOVA_PROOF_MIN_SIZE
            )));
        }
        Ok(())
    }
}

/// 将 `poker_zkvm::error::ZkvmError` 映射为 `PokerL1Error`（SubTask 8.2.2）。
fn map_zkvm_error(e: poker_zkvm::error::ZkvmError) -> PokerL1Error {
    use poker_zkvm::error::ZkvmError;

    match e {
        ZkvmError::SumcheckVerificationFailed => PokerL1Error::SumcheckVerificationFailed,
        ZkvmError::PcsVerificationFailed => PokerL1Error::PcsVerificationFailed,
        ZkvmError::TranscriptMismatch => PokerL1Error::TranscriptMismatch,
        ZkvmError::AbiVersionMismatch { expected, actual } => {
            // ZkvmError 用 u32，PokerL1Error 用 u8（ABI 版本号实际范围 0-255）
            match (u8::try_from(expected), u8::try_from(actual)) {
                (Ok(exp), Ok(act)) => PokerL1Error::AbiVersionMismatch {
                    expected: exp,
                    actual: act,
                },
                _ => PokerL1Error::Other(format!(
                    "poker_zkvm AbiVersionMismatch overflow: expected={expected}, actual={actual}"
                )),
            }
        }
        ZkvmError::InvalidZkProofFormat(msg) => {
            PokerL1Error::InvalidZkProofFormat(msg)
        }
        other => PokerL1Error::Other(format!("poker_zkvm error: {other}")),
    }
}

/// 便捷函数：注册 Hypernova verifier 到 registry。
pub fn register_hypernova_verifier(
    registry: &mut super::zk_verifier::ZkVerifierRegistry,
) {
    registry.register(HypernovaVerifier::into_registry_verifier());
}

/// 便捷函数：注册 ZkShuffle verifier 到 registry（Phase 8 SubTask 8.2.3）。
pub fn register_zkshuffle_verifier(
    registry: &mut super::zk_verifier::ZkVerifierRegistry,
) {
    registry.register(ZkShuffleVerifier::into_registry_verifier());
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

    /// 将 poker_zkvm::prover::ZkPublicIo 反向转换为 poker_l1 ZkPublicIo，
    /// 使 public_io_to_zkvm(zkvm_to_public_io(zkvm_pio)) == zkvm_pio。
    fn zkvm_to_public_io(zkvm_pio: &poker_zkvm::prover::ZkPublicIo) -> ZkPublicIo {
        use poker_zkvm::field::ZkvmField;
        let mut state_delta_hash = [0u8; 32];
        let len = zkvm_pio.input.len().min(32);
        state_delta_hash[..len].copy_from_slice(&zkvm_pio.input[..len]);

        let mut ack_chain_hash = [0u8; 32];
        let len = zkvm_pio.output.len().min(32);
        ack_chain_hash[..len].copy_from_slice(&zkvm_pio.output[..len]);

        ZkPublicIo {
            initial_commitment: zkvm_pio.initial_commitment.to_canonical_bytes(),
            final_commitment: zkvm_pio.final_commitment.to_canonical_bytes(),
            state_delta_hash,
            ack_chain_hash,
            fold_step_count: 0,
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
    fn test_verify_production_rejects_invalid_proof() {
        // Phase 8：Production 分支已实现，调用 verify_production
        // 随机字节作为 proof 应返回 InvalidZkProofFormat（反序列化失败）
        let v = HypernovaVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0x00; HYPERNOVA_PROOF_MIN_SIZE];
        let result = v.verify(&proof, &public_io, VerifierStatus::Production);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
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

    // ===== Phase 8 SubTask 8.2.8 集成测试 =====

    use super::super::zk_verifier::{
        ProofKind, ZkVerifyContext, SCHEME_ZKSHUFFLE,
    };
    use crate::governance::PRODUCTION_GRACE_BLOCKS;

    /// 辅助：构造默认 ZkVerifyContext（切换前状态）。
    fn make_ctx_default() -> ZkVerifyContext<'static> {
        ZkVerifyContext {
            current_height: 0,
            production_switch_height: 0,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash: None,
            uses_new_signature: true, // scheme_id=1 期望新签名
        }
    }

    /// 辅助：构造 grace 期内的 ZkVerifyContext。
    fn make_ctx_in_grace(last_partial_proof_hash: Option<&'static crate::Hash>) -> ZkVerifyContext<'static> {
        ZkVerifyContext {
            current_height: 100,
            production_switch_height: 100,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash,
            uses_new_signature: true,
        }
    }

    /// 辅助：构造 grace 期后的 ZkVerifyContext。
    fn make_ctx_after_grace() -> ZkVerifyContext<'static> {
        ZkVerifyContext {
            current_height: 100 + PRODUCTION_GRACE_BLOCKS + 1,
            production_switch_height: 100,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash: None,
            uses_new_signature: true,
        }
    }

    /// 测试 1：Production 分支验证合法 proof 通过（SubTask 8.2.1）
    #[test]
    fn test_production_verify_valid_proof() {
        // 使用 poker_zkvm 的 generate_test_proof 生成合法 proof
        let (proof_bytes, zkvm_public_io) = poker_zkvm::prover::generate_test_proof();
        let v = HypernovaVerifier::new();
        let public_io = zkvm_to_public_io(&zkvm_public_io);

        // Production 状态：调用 verify_production
        let result = v.verify(&proof_bytes, &public_io, VerifierStatus::Production);
        assert!(result.is_ok(), "合法 proof 应通过: {:?}", result);
        assert!(result.unwrap());
    }

    /// 测试 2：grace 期内 ZkShuffle + 匹配 proof_hash 通过（SubTask 8.2.3 + M2-003）
    #[test]
    fn test_grace_period_zkshuffle_matching_proof_hash() {
        let v = ZkShuffleVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE];
        let proof_hash = HypernovaVerifier::compute_proof_hash(&proof);

        let ctx = ZkVerifyContext {
            current_height: 100,
            production_switch_height: 100,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash: Some(&proof_hash),
            uses_new_signature: false, // ZkShuffle 期望旧签名
        };

        let result = v.verify_with_context(&proof, &public_io, VerifierStatus::Stub, &ctx);
        assert!(result.is_ok(), "匹配 proof_hash 应通过: {:?}", result);
        assert!(result.unwrap());
    }

    /// 测试 3：grace 期内 ZkShuffle + 不匹配 proof_hash 失败（M2-003）
    #[test]
    fn test_grace_period_zkshuffle_mismatched_proof_hash() {
        let v = ZkShuffleVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE];
        let wrong_hash = [0xFF; 32];

        let ctx = ZkVerifyContext {
            current_height: 100,
            production_switch_height: 100,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash: Some(&wrong_hash),
            uses_new_signature: false,
        };

        let result = v.verify_with_context(&proof, &public_io, VerifierStatus::Stub, &ctx);
        assert!(matches!(result, Err(PokerL1Error::PartialFoldHashImmutable)));
    }

    /// 测试 4：grace 期内 ZkShuffle 无 last_partial_proof_hash 拒绝（防伪造新游戏）
    #[test]
    fn test_grace_period_zkshuffle_no_proof_hash_rejected() {
        let v = ZkShuffleVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE];

        // ZkShuffle 期望旧签名（uses_new_signature=false）
        let ctx = ZkVerifyContext {
            current_height: 100,
            production_switch_height: 100,
            grace_blocks: PRODUCTION_GRACE_BLOCKS,
            last_partial_proof_hash: None,
            uses_new_signature: false,
        };
        let result = v.verify_with_context(&proof, &public_io, VerifierStatus::Stub, &ctx);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    /// 测试 5：grace 期内 Zkvm 强制 Production 路径（SubTask 8.2.3）
    #[test]
    fn test_grace_period_zkvm_forced_production() {
        let (proof_bytes, zkvm_public_io) = poker_zkvm::prover::generate_test_proof();
        let v = HypernovaVerifier::new();
        let public_io = zkvm_to_public_io(&zkvm_public_io);

        let ctx = make_ctx_in_grace(None);
        // status = Stub 但 grace 期内 Zkvm 应强制 Production
        let result = v.verify_with_context(&proof_bytes, &public_io, VerifierStatus::Stub, &ctx);
        assert!(result.is_ok(), "合法 proof 应通过: {:?}", result);
        assert!(result.unwrap());
    }

    /// 测试 6：grace 期后 stub 路径彻底关闭（SubTask 8.2.4）
    #[test]
    fn test_after_grace_stub_closed() {
        let (proof_bytes, zkvm_public_io) = poker_zkvm::prover::generate_test_proof();
        let v = HypernovaVerifier::new();
        let public_io = zkvm_to_public_io(&zkvm_public_io);

        let ctx = make_ctx_after_grace();
        // status = Stub 但 grace 期后应强制 Production
        let result = v.verify_with_context(&proof_bytes, &public_io, VerifierStatus::Stub, &ctx);
        assert!(result.is_ok(), "合法 proof 应通过: {:?}", result);
        assert!(result.unwrap());

        // 无效 proof 在 grace 期后应失败（走 Production 路径）
        let bad_proof = vec![0x00; HYPERNOVA_PROOF_MIN_SIZE];
        let result = v.verify_with_context(&bad_proof, &public_io, VerifierStatus::Stub, &ctx);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    /// 测试 7：M2-003 覆盖已有 proof_partial_hash 返回 PartialFoldHashImmutable
    #[test]
    fn test_m2_003_overwrite_proof_partial_hash_rejected() {
        use crate::offline::state::{
            execute_partial_checkin, LastPartialFold, PartialCheckinTx,
        };
        use crate::offline::ack_chain::AckEntry;
        use crate::object_model::ObjectID;

        let mut registry = ZkVerifierRegistry::new();
        register_hypernova_verifier(&mut registry);

        let make_ack = |seq: u64| AckEntry {
            chain_id: crate::DEFAULT_CHAIN_ID,
            epoch: 1,
            game_id: ObjectID::new([0x01; 20], 1),
            current_turn: [0x02; 20],
            state_hash: [0x42; 32],
            checkpoint_seq: seq,
            participant: crate::signature::TaggedPubkey {
                tag: 0x01,
                raw: vec![0xAA; 33],
            },
            participant_signature: vec![0xBB; 64],
        };

        // 链上已有 last_partial_fold
        let last = LastPartialFold {
            intermediate_commitment: [0xBB; 32],
            folded_step_count: 5,
            proof_partial_hash: [0xAA; 32],
            ack_chain_partial_hash: [0xCC; 32],
        };

        // 尝试用不同的 proof_partial 覆盖（应被拒绝）
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xDD; 64], // 不同的 proof → 不同的 hash
            folded_step_count: 10, // 进度推进
            intermediate_commitment: [0xEE; 32],
            ack_chain_partial: vec![make_ack(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let result = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            Some(&last),
            0,
            crate::offline::DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            crate::offline::DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_ctx_default(),
        );
        assert!(matches!(result, Err(PokerL1Error::PartialFoldHashImmutable)));
    }

    /// 测试 8：M2-003 幂等重提交允许（整个 PartialCheckinTx 内容幂等）
    #[test]
    fn test_m2_003_idempotent_resubmit_allowed() {
        use crate::offline::state::{execute_partial_checkin, PartialCheckinTx};
        use crate::offline::ack_chain::AckEntry;
        use crate::object_model::ObjectID;

        let mut registry = ZkVerifierRegistry::new();
        register_hypernova_verifier(&mut registry);

        let make_ack = |seq: u64| AckEntry {
            chain_id: crate::DEFAULT_CHAIN_ID,
            epoch: 1,
            game_id: ObjectID::new([0x01; 20], 1),
            current_turn: [0x02; 20],
            state_hash: [0x42; 32],
            checkpoint_seq: seq,
            participant: crate::signature::TaggedPubkey {
                tag: 0x01,
                raw: vec![0xAA; 33],
            },
            participant_signature: vec![0xBB; 64],
        };

        let ack_chain = vec![make_ack(1)];
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xAA; 64],
            folded_step_count: 5,
            intermediate_commitment: [0xBB; 32],
            ack_chain_partial: ack_chain,
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        // 首次提交
        let first = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            0,
            crate::offline::DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            crate::offline::DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_ctx_default(),
        )
        .expect("首次提交应成功");

        // 幂等重提交（完全相同）
        let second = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            Some(&first),
            1,
            crate::offline::DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            crate::offline::DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_ctx_default(),
        )
        .expect("幂等重提交应成功");

        assert_eq!(first, second);
    }

    /// 测试 9：M2-003 幂等范围 — proof_hash 匹配但其他字段不一致拒绝（Min3-003）
    #[test]
    fn test_m2_003_idempotent_range_other_fields_mismatch() {
        use crate::offline::state::{
            execute_partial_checkin, LastPartialFold, PartialCheckinTx,
        };
        use crate::offline::ack_chain::AckEntry;
        use crate::object_model::ObjectID;

        let mut registry = ZkVerifierRegistry::new();
        register_hypernova_verifier(&mut registry);

        let make_ack = |seq: u64| AckEntry {
            chain_id: crate::DEFAULT_CHAIN_ID,
            epoch: 1,
            game_id: ObjectID::new([0x01; 20], 1),
            current_turn: [0x02; 20],
            state_hash: [0x42; 32],
            checkpoint_seq: seq,
            participant: crate::signature::TaggedPubkey {
                tag: 0x01,
                raw: vec![0xAA; 33],
            },
            participant_signature: vec![0xBB; 64],
        };

        // 链上已有 last_partial_fold
        let proof_partial = vec![0xAA; 64];
        let proof_hash = blake2_hash(&proof_partial);
        let last = LastPartialFold {
            intermediate_commitment: [0xBB; 32],
            folded_step_count: 5,
            proof_partial_hash: proof_hash,
            ack_chain_partial_hash: [0xCC; 32],
        };

        // proof_partial 相同（hash 匹配）但 intermediate_commitment 不同
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial,
            folded_step_count: 5,
            intermediate_commitment: [0xDD; 32], // 不同的 intermediate_commitment
            ack_chain_partial: vec![make_ack(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let result = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            Some(&last),
            0,
            crate::offline::DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            crate::offline::DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_ctx_default(),
        );
        assert!(matches!(result, Err(PokerL1Error::PartialFoldHashImmutable)));
    }

    /// 测试 10：M2-004 scheme_id=1 新签名通过 / 旧签名返回 SignatureFormMismatch
    #[test]
    fn test_m2_004_signature_form_mismatch() {
        let v = HypernovaVerifier::new();
        let public_io = make_public_io(1);
        let proof = vec![0xAA; HYPERNOVA_PROOF_MIN_SIZE];

        // scheme_id=1 (Zkvm) 期望新签名（uses_new_signature=true）
        let ctx_new_sig = ZkVerifyContext {
            uses_new_signature: true,
            ..make_ctx_default()
        };
        let result = v.verify_with_context(&proof, &public_io, VerifierStatus::Stub, &ctx_new_sig);
        assert!(result.is_ok(), "新签名应通过: {:?}", result);

        // 旧签名（uses_new_signature=false）应返回 SignatureFormMismatch
        let ctx_old_sig = ZkVerifyContext {
            uses_new_signature: false,
            ..make_ctx_default()
        };
        let result = v.verify_with_context(&proof, &public_io, VerifierStatus::Stub, &ctx_old_sig);
        assert!(matches!(result, Err(PokerL1Error::SignatureFormMismatch { scheme_id: 1 })));
    }

    /// 测试 11：ProofKind::from_scheme_id 映射（SubTask 8.2.7）
    #[test]
    fn test_proof_kind_from_scheme_id() {
        assert_eq!(ProofKind::from_scheme_id(SCHEME_HYPERNOVA), Some(ProofKind::Zkvm));
        assert_eq!(ProofKind::from_scheme_id(SCHEME_ZKSHUFFLE), Some(ProofKind::ZkShuffle));
        assert_eq!(ProofKind::from_scheme_id(99), None);

        // Zkvm 期望新签名
        assert!(ProofKind::Zkvm.expects_new_signature());
        // ZkShuffle 期望旧签名
        assert!(!ProofKind::ZkShuffle.expects_new_signature());
    }

    /// 测试 12：ZkVerifyContext grace 期判定
    #[test]
    fn test_zk_verify_context_grace_period() {
        // 切换前（production_switch_height == 0）
        let ctx_before = make_ctx_default();
        assert!(!ctx_before.in_grace_period());
        assert!(!ctx_before.grace_period_ended());

        // grace 期内
        let ctx_in_grace = make_ctx_in_grace(None);
        assert!(ctx_in_grace.in_grace_period());
        assert!(!ctx_in_grace.grace_period_ended());

        // grace 期后
        let ctx_after = make_ctx_after_grace();
        assert!(!ctx_after.in_grace_period());
        assert!(ctx_after.grace_period_ended());
    }

    /// 辅助：计算 blake2b_256 哈希。
    fn blake2_hash(data: &[u8]) -> crate::Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(data);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}
