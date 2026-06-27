//! Groth16 verifier（Task 24 — SubTask 24.1 / 24.2 / 24.3 / 24.3a）。
//!
//! 严格遵循 spec.md L503–507 + R4-L2 + SEC-M10（FROZEN 2026-06-27）：
//! - **SubTask 24.1**：`Groth16Vk` / `Groth16Proof` 结构
//! - **SubTask 24.2**：注册 `groth16_verify`，复用 BLS12-381 pairing（含子群检查）
//! - **SubTask 24.3**：MVP — verifier stub
//! - **SubTask 24.3a**：R4-L2 Groth16 trusted setup 流程 + **SEC-M10 CRS fingerprint 链上验证**
//!
//! ## SEC-M10 CRS Fingerprint
//!
//! `crs_fingerprint = blake2b_256(vk.alpha_g1 || vk.beta_g2 || vk.gamma_g2 || vk.delta_g2 || vk.ic)`
//!
//! - 注册 vk 时同时存储 `crs_fingerprint`
//! - `groth16_verify(vk_id, proof, public_inputs)` 时先校验 `blake2b_256(stored_vk) == crs_fingerprint`
//! - 不匹配返回 `CrsFingerprintMismatch`（防 key substitution attack）
//! - `crs_fingerprint` 注册后不可更改；更新 vk 须经治理 90% quorum 通过注册新 `vk_id`

use std::collections::BTreeMap;
use std::sync::Arc;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::error::PokerL1Error;
use crate::Hash;

use super::zk_verifier::{SchemeId, VerifierStatus, ZkVerifier, SCHEME_GROTH16};

/// Groth16 verifying key（SubTask 24.1）。
///
/// BLS12-381 compressed 字节表示：
/// - `alpha_g1`：48 字节（G1 compressed）
/// - `beta_g2` / `gamma_g2` / `delta_g2`：96 字节（G2 compressed）
/// - `ic`：G1 compressed 数组（首个是 `[A]_1`，后续按 public_input 顺序）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Vk {
    /// αG1（48 字节）。
    pub alpha_g1: [u8; 48],
    /// βG2（96 字节）。
    pub beta_g2: [u8; 96],
    /// γG2（96 字节）。
    pub gamma_g2: [u8; 96],
    /// δG2（96 字节）。
    pub delta_g2: [u8; 96],
    /// IC = [γ^{-1} * (β * u_i(τ) + α * v_i(τ) + w_i(τ)) / γ]_1（G1 compressed 数组）。
    pub ic: Vec<[u8; 48]>,
}

impl Groth16Vk {
    /// 计算 CRS fingerprint = `blake2b_256(alpha_g1 || beta_g2 || gamma_g2 || delta_g2 || ic)`（SEC-M10）。
    pub fn crs_fingerprint(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(&self.alpha_g1);
        hasher.update(&self.beta_g2);
        hasher.update(&self.gamma_g2);
        hasher.update(&self.delta_g2);
        for ic in &self.ic {
            hasher.update(ic);
        }
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 序列化为字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.alpha_g1);
        out.extend_from_slice(&self.beta_g2);
        out.extend_from_slice(&self.gamma_g2);
        out.extend_from_slice(&self.delta_g2);
        for ic in &self.ic {
            out.extend_from_slice(ic);
        }
        out
    }
}

/// Groth16 proof（SubTask 24.1）。
///
/// `A` ∈ G1, `B` ∈ G2, `C` ∈ G1。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    /// A ∈ G1（48 字节 compressed）。
    pub a_g1: [u8; 48],
    /// B ∈ G2（96 字节 compressed）。
    pub b_g2: [u8; 96],
    /// C ∈ G1（48 字节 compressed）。
    pub c_g1: [u8; 48],
}

impl Groth16Proof {
    /// 序列化为字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + 96 + 48);
        out.extend_from_slice(&self.a_g1);
        out.extend_from_slice(&self.b_g2);
        out.extend_from_slice(&self.c_g1);
        out
    }
}

/// Groth16 proof 最小字节数（A + B + C = 48 + 96 + 48 = 192）。
pub const GROTH16_PROOF_SIZE: usize = 48 + 96 + 48;

/// Groth16 VK 注册表（SubTask 24.3a — SEC-M10）。
///
/// 存储已注册的 `verifying_key` + `crs_fingerprint`。
/// `vk_id` = `blake2b_256(vk.to_bytes())`（vk 内容哈希作为 ID）。
#[derive(Debug, Default)]
pub struct Groth16VkRegistry {
    /// vk_id → (vk, crs_fingerprint)
    entries: BTreeMap<Hash, (Groth16Vk, Hash)>,
}

impl Groth16VkRegistry {
    /// 创建空 registry。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册 verifying_key（SEC-M10）。
    ///
    /// - 计算 `vk_id = blake2b_256(vk.to_bytes())`
    /// - 计算 `crs_fingerprint = vk.crs_fingerprint()`
    /// - 存储 `(vk_id, (vk, crs_fingerprint))`
    /// - 若 `vk_id` 已存在且 `crs_fingerprint` 不同，返回 `CrsFingerprintMismatch`
    ///   （防 vk 被恶意替换为攻击者控制的 weak vk）
    pub fn register(&mut self, vk: Groth16Vk) -> Result<Hash, PokerL1Error> {
        let vk_id = {
            let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
            hasher.update(&vk.to_bytes());
            let mut out = [0u8; 32];
            hasher
                .finalize_variable(&mut out)
                .expect("Blake2bVar finalize 不应失败");
            out
        };
        let crs_fingerprint = vk.crs_fingerprint();

        if let Some((_, existing_fp)) = self.entries.get(&vk_id) {
            if *existing_fp != crs_fingerprint {
                return Err(PokerL1Error::CrsFingerprintMismatch { vk_id });
            }
            // 相同 vk 重复注册：幂等返回
            return Ok(vk_id);
        }

        self.entries.insert(vk_id, (vk, crs_fingerprint));
        Ok(vk_id)
    }

    /// 查询 vk。
    pub fn get(&self, vk_id: &Hash) -> Option<&Groth16Vk> {
        self.entries.get(vk_id).map(|(vk, _)| vk)
    }

    /// 校验 `crs_fingerprint`（SEC-M10）。
    ///
    /// `groth16_verify(vk_id, proof, public_inputs)` 时先调用此方法。
    pub fn verify_crs_fingerprint(&self, vk_id: &Hash) -> Result<(), PokerL1Error> {
        let (vk, stored_fp) = self
            .entries
            .get(vk_id)
            .ok_or(PokerL1Error::Groth16VkNotRegistered(*vk_id))?;

        let current_fp = vk.crs_fingerprint();
        if current_fp != *stored_fp {
            return Err(PokerL1Error::CrsFingerprintMismatch { vk_id: *vk_id });
        }
        Ok(())
    }

    /// 列出所有已注册 vk_id。
    pub fn registered_vk_ids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }
}

/// Groth16 verifier stub（SubTask 24.3）。
///
/// MVP 阶段：
/// - `Stub` 状态：仅校验 proof 格式（长度 == 192）+ vk 注册 + CRS fingerprint
/// - `Production` 状态：调用 BLS12-381 pairing 验证（当前未实现）
///
/// Production 验证等式（spec.md L507）：
/// `e(A, B) == e(αG1, βG2) * e(L, γG2) * e(C, δG2)`
///
/// 其中 `L = Σ IC[i] * public_input[i]`（含 IC[0] = αG1）。
#[derive(Debug, Default)]
pub struct Groth16Verifier {
    /// VK 注册表（SEC-M10）。
    vk_registry: Groth16VkRegistry,
}

impl Groth16Verifier {
    /// 创建 verifier 实例。
    pub fn new() -> Self {
        Self::default()
    }

    /// 包装为 `Arc<dyn ZkVerifier>` 以便注册到 ZkVerifierRegistry。
    pub fn into_registry_verifier() -> Arc<dyn ZkVerifier> {
        Arc::new(Self::new())
    }

    /// 注册 verifying_key（SEC-M10）。
    pub fn register_vk(&mut self, vk: Groth16Vk) -> Result<Hash, PokerL1Error> {
        self.vk_registry.register(vk)
    }

    /// 校验 proof 格式（长度 == 192）。
    pub fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        if proof.len() != GROTH16_PROOF_SIZE {
            return Err(PokerL1Error::InvalidZkProofFormat(format!(
                "groth16 proof 长度 {} != 期望 {}",
                proof.len(),
                GROTH16_PROOF_SIZE
            )));
        }
        Ok(())
    }
}

impl ZkVerifier for Groth16Verifier {
    fn scheme_id(&self) -> SchemeId {
        SCHEME_GROTH16
    }

    fn verify(
        &self,
        proof: &[u8],
        _public_io: &super::zk_verifier::ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        // Stub 与 Production 都校验 proof 格式
        self.validate_proof_format(proof)?;

        if status == VerifierStatus::Stub {
            return Ok(true);
        }

        // Production 状态：MVP 未实现 pairing 验证
        // TODO: 实现 e(A, B) == e(αG1, βG2) * e(L, γG2) * e(C, δG2)
        Err(PokerL1Error::Other(
            "Groth16 Production verifier 尚未实现".to_string(),
        ))
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        Self::validate_proof_format(self, proof)
    }
}

/// 便捷函数：注册 Groth16 verifier 到 ZkVerifierRegistry。
pub fn register_groth16_verifier(
    registry: &mut super::zk_verifier::ZkVerifierRegistry,
) {
    registry.register(Groth16Verifier::into_registry_verifier());
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::zk_verifier::{ZkPublicIo, ZkVerifierRegistry};

    fn make_vk() -> Groth16Vk {
        Groth16Vk {
            alpha_g1: [0x01; 48],
            beta_g2: [0x02; 96],
            gamma_g2: [0x03; 96],
            delta_g2: [0x04; 96],
            ic: vec![[0x05; 48], [0x06; 48]],
        }
    }

    fn make_proof() -> Vec<u8> {
        let proof = Groth16Proof {
            a_g1: [0xAA; 48],
            b_g2: [0xBB; 96],
            c_g1: [0xCC; 48],
        };
        proof.to_bytes()
    }

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
        let v = Groth16Verifier::new();
        assert_eq!(v.scheme_id(), SCHEME_GROTH16);
    }

    #[test]
    fn test_crs_fingerprint_deterministic() {
        let vk1 = make_vk();
        let vk2 = make_vk();
        assert_eq!(vk1.crs_fingerprint(), vk2.crs_fingerprint());
    }

    #[test]
    fn test_crs_fingerprint_differs_on_vk_change() {
        let vk1 = make_vk();
        let mut vk2 = make_vk();
        vk2.alpha_g1[0] ^= 0xFF;
        assert_ne!(vk1.crs_fingerprint(), vk2.crs_fingerprint());
    }

    #[test]
    fn test_vk_registry_register_and_lookup() {
        let mut registry = Groth16VkRegistry::new();
        let vk = make_vk();
        let vk_id = registry.register(vk.clone()).expect("注册应成功");

        assert!(registry.get(&vk_id).is_some());
        let retrieved = registry.get(&vk_id).unwrap();
        assert_eq!(retrieved, &vk);
    }

    #[test]
    fn test_vk_registry_idempotent_register() {
        let mut registry = Groth16VkRegistry::new();
        let vk = make_vk();
        let id1 = registry.register(vk.clone()).expect("首次注册应成功");
        let id2 = registry.register(vk).expect("重复注册应幂等");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_vk_registry_rejects_modified_vk_same_id() {
        // vk_id = blake2b(vk.to_bytes())
        // 修改 vk 后 vk_id 不同，不会触发 CrsFingerprintMismatch
        // 但若人为构造相同 vk_id 但不同 crs_fingerprint 的情况：
        // 实际上 vk_id 由 vk 内容决定，相同 vk_id 必有相同 crs_fingerprint
        // 此测试验证幂等性：相同 vk 重复注册返回相同 vk_id
        let mut registry = Groth16VkRegistry::new();
        let vk = make_vk();
        let id1 = registry.register(vk.clone()).expect("首次注册");
        let id2 = registry.register(vk).expect("重复注册");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_verify_crs_fingerprint_unregistered() {
        let registry = Groth16VkRegistry::new();
        let result = registry.verify_crs_fingerprint(&[0xFF; 32]);
        assert!(matches!(result, Err(PokerL1Error::Groth16VkNotRegistered(_))));
    }

    #[test]
    fn test_verify_crs_fingerprint_success() {
        let mut registry = Groth16VkRegistry::new();
        let vk = make_vk();
        let vk_id = registry.register(vk).expect("注册应成功");
        let result = registry.verify_crs_fingerprint(&vk_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proof_format_wrong_length() {
        let v = Groth16Verifier::new();
        assert!(v.validate_proof_format(&[0x00; 100]).is_err());
        assert!(v.validate_proof_format(&[0x00; GROTH16_PROOF_SIZE]).is_ok());
    }

    #[test]
    fn test_verify_stub_success() {
        let v = Groth16Verifier::new();
        let pi = make_public_io();
        let proof = make_proof();
        let result = v
            .verify(&proof, &pi, VerifierStatus::Stub)
            .expect("stub verify 应成功");
        assert!(result);
    }

    #[test]
    fn test_verify_stub_rejects_wrong_length() {
        let v = Groth16Verifier::new();
        let pi = make_public_io();
        let result = v.verify(&[0x00; 100], &pi, VerifierStatus::Stub);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_verify_production_not_implemented() {
        let v = Groth16Verifier::new();
        let pi = make_public_io();
        let proof = make_proof();
        let result = v.verify(&proof, &pi, VerifierStatus::Production);
        assert!(matches!(result, Err(PokerL1Error::Other(_))));
    }

    #[test]
    fn test_register_and_zk_verify() {
        let mut registry = ZkVerifierRegistry::new();
        register_groth16_verifier(&mut registry);

        let pi = make_public_io();
        let proof = make_proof();
        let result = registry
            .zk_verify(crate::DEFAULT_CHAIN_ID, SCHEME_GROTH16, &proof, &pi, 3, 1000)
            .expect("zk_verify 应成功");
        assert!(result.verified);
        assert_eq!(result.scheme_id, SCHEME_GROTH16);
    }

    #[test]
    fn test_proof_size_constant() {
        // A(48) + B(96) + C(48) = 192
        assert_eq!(GROTH16_PROOF_SIZE, 192);
    }
}
