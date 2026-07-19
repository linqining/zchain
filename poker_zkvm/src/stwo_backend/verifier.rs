//! # Stwo Verifier — Circle STARK 证明验证
//!
//! 严格遵循 `hypernova_to_stwo_migration_plan.md` §"Phase 4.1"：
//! - [`StwoVerifier`] — Stwo verifier 入口（替代 Hypernova verifier）
//! - [`verify_stwo`] — 顶层验证函数（对应 [`crate::verifier::verify_production`]）
//!
//! ## 验证流程（Phase 4.1 完整实现后）
//!
//! 1. 反序列化 STWO proof（[`super::prover::deserialize_stwo_proof`]）
//! 2. public_io 绑定校验（复用 `hash_public_io`）
//! 3. Stwo verifier 验证 proof（调用 `stwo::verifier::Verifier`）
//!
//! ## 当前状态（Phase 1.1）
//!
//! 仅提供类型定义与序列化骨架。`verify_stwo()` 返回 [`ZkvmError::Other`]，
//! 待 Phase 4.1 接入真实 Stwo verifier。

use crate::error::ZkvmError;
use crate::prover::ZkPublicIo;
use crate::prover::hash_public_io;

use super::prover::{deserialize_stwo_proof, StwoProof};

/// Stwo verifier 入口（替代 Hypernova verifier）。
///
/// Phase 4.1 将接入 `stwo::verifier::Verifier`，完整实现 `verify()` 方法。
#[derive(Clone, Debug, Default)]
pub struct StwoVerifier;

impl StwoVerifier {
    /// 创建新 verifier 实例。
    pub fn new() -> Self {
        Self
    }

    /// 验证 STWO proof。
    ///
    /// # 当前状态（Phase 1.1）
    ///
    /// 返回 `ZkvmError::Other`，待 Phase 4.1 接入真实 Stwo verifier。
    pub fn verify(&self, _proof_bytes: &[u8], _public_io: &ZkPublicIo) -> Result<bool, ZkvmError> {
        // TODO(Phase 4.1): 实现 Stwo verify
        Err(ZkvmError::Other(
            "StwoVerifier::verify 尚未实现 — Phase 4.1 将接入".to_string(),
        ))
    }
}

/// 顶层 Stwo proof 验证函数（对应 [`crate::verifier::verify_production`]）。
///
/// # 验证流程（Phase 4.1 完整实现后）
///
/// 1. 反序列化 STWO proof（magic / version / 长度校验）
/// 2. public_io 绑定校验（`hash_public_io(public_io) == proof.public_io_commitment`）
/// 3. Stwo verifier 验证 proof 内部结构
///
/// # 当前状态（Phase 1.1）
///
/// 仅完成反序列化 + public_io 绑定校验。Stwo proof 内部验证留待 Phase 4.1。
///
/// # 参数
/// - `proof_bytes` — 序列化的 STWO proof 字节
/// - `public_io` — 公共输入输出（与 proof 绑定校验）
///
/// # 返回
/// - `Ok(true)` — proof 验证通过
/// - `Err(...)` — 验证失败
pub fn verify_stwo(proof_bytes: &[u8], public_io: &ZkPublicIo) -> Result<bool, ZkvmError> {
    // 1. 反序列化（含 magic / version / 长度校验）
    let proof: StwoProof = deserialize_stwo_proof(proof_bytes)?;

    // 2. public_io 绑定校验（防重放攻击）
    let expected_pio = hash_public_io(public_io);
    if expected_pio != proof.public_io_commitment {
        return Err(ZkvmError::Other(
            "STWO proof: public_io 不匹配（hash_public_io(public_io) != proof.public_io_commitment）"
                .to_string(),
        ));
    }

    // 3. Stwo proof 内部验证
    // TODO(Phase 4.1): 调用 stwo::verifier::Verifier 验证 proof.stwo_proof
    // 当前 Phase 1.1 骨架阶段跳过此步骤，返回未实现错误
    Err(ZkvmError::Other(format!(
        "STWO proof 内部验证尚未实现 — Phase 4.1 将接入（stwo_proof len = {}）",
        proof.stwo_proof.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::prover::{serialize_stwo_proof, StwoProof, STWO_MAGIC, STWO_VERSION};
    // 测试代码使用 `Fr::zero()`，需 `ZkvmField` trait 在作用域内。
    use crate::field::ZkvmField;

    fn make_test_public_io() -> ZkPublicIo {
        ZkPublicIo {
            input: vec![],
            output: vec![],
            randomness_seed: crate::ccs::Fr::zero(),
            initial_commitment: crate::ccs::Fr::zero(),
            final_commitment: crate::ccs::Fr::zero(),
            event_hashes: vec![],
        }
    }

    #[test]
    fn test_verify_stwo_rejects_invalid_magic() {
        let public_io = make_test_public_io();
        // 构造一个 magic 错误的 proof
        let mut bad_bytes = vec![0u8; 73];
        bad_bytes[0..4].copy_from_slice(b"XXXX");
        bad_bytes[4] = STWO_VERSION;
        assert!(verify_stwo(&bad_bytes, &public_io).is_err());
    }

    #[test]
    fn test_verify_stwo_rejects_public_io_mismatch() {
        // 构造一个 public_io_commitment 不匹配的 proof
        let proof = StwoProof {
            public_io_commitment: [0xFF; 32], // 故意不匹配
            ccs_commitment: [0; 32],
            stwo_proof: vec![],
        };
        let bytes = serialize_stwo_proof(&proof);
        let public_io = make_test_public_io();
        let result = verify_stwo(&bytes, &public_io);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("public_io 不匹配"),
            "错误消息应包含 public_io 不匹配: {}",
            err_msg
        );
    }

    #[test]
    fn test_stwo_verifier_default() {
        let _verifier = StwoVerifier::default();
        let _verifier2 = StwoVerifier::new();
    }

    #[test]
    fn test_stwo_magic_constant() {
        assert_eq!(STWO_MAGIC, b"STWO");
    }
}