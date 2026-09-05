//! # poker-appchain-texasair — 接入缝
//!
//! [`poker_appchain`] 结算证明管道（[`SettlementProver`] trait）与
//! [`poker_texas_air`](https://github.com/) 手写约束 AIR 栈（stwo
//! circle-STARK，独立验证器）之间的适配器。
//!
//! ## 为什么是独立 crate
//!
//! 外部 poker_texas_air 仓库携带自己的 `poker_l1`（同名不同源），与
//! zchain workspace 的 `poker_l1` 无法共存于同一依赖图（cargo lockfile
//! collision）。本 crate 自带 lockfile，把重型 stwo 栈隔离在接入缝内，
//! appchain 核心（账本/sequencer）保持零重依赖。
//!
//! ## prove 语义（TexasAirEngine）
//!
//! 1. `hand_proof` 必须存在（本引擎只证明带手牌证明绑定的结算）；
//! 2. 归档解析为 poker_texas_air 的 `ArchivedTaggedTexasProof`；
//! 3. 绑定检查：归档 `table_id` == 结算 `table_id`；归档终态承诺 ==
//!    声明 `post_state_commitment`（结算与**已证明的手牌终态**挂钩，
//!    host 不能跨手混装状态——plan B2 的承诺级绑定）；
//! 4. **完整 STARK 验证**：`verify_tagged_texas_proof`（手写约束 AIR
//!    的独立验证器，从公开范围验证，不信任 prover）；
//! 5. 结算关系校验 + attestor 签名（签名覆盖绑定 + 已验证终态承诺，
//!    [`TexasAirEngine::verify`] 可独立复验）。
//!
//! 剩余尾巴（plan-appchain BLOCKERS B2 末段）：pot 数值与终态状态镜像
//! 的逐字节绑定（需要 poker_texas_air 公开范围暴露 pot 或可复算的镜像
//! 哈希）。
#![deny(unsafe_code)]
#![deny(missing_docs)]

use poker_appchain::error::{AppchainError, AppchainResult};
use poker_appchain::pipeline::{ProofBundle, ProofJob, SettlementProver};

/// poker_texas_air 手写约束 AIR 证明引擎。
#[derive(Debug, Clone)]
pub struct TexasAirEngine {
    attestor: ed25519_dalek::SigningKey,
}

/// attestation 消息：绑定（引擎域, 结算绑定, **已验证的手牌终态承诺**）。
fn attestation_message(binding: &[u8], state_commitment: &[u8; 32]) -> [u8; 32] {
    poker_appchain::keys::blake2s32(&[
        b"poker-appchain.texas-air-v1",
        binding,
        state_commitment,
    ])
}

impl TexasAirEngine {
    /// 指定 attestor 密钥构造（生产：环境注入；不得入库）。
    #[must_use]
    pub fn new(attestor: ed25519_dalek::SigningKey) -> Self {
        Self { attestor }
    }

    /// attestor 公钥。
    #[must_use]
    pub fn attestor_public(&self) -> [u8; 32] {
        self.attestor.verifying_key().to_bytes()
    }

    /// 归档字节 → poker_texas_air 归档结构（borsh 编码）。
    ///
    /// # Errors
    /// 编码不合法 → [`AppchainError::Codec`]。
    pub fn parse_archive(
        archive_bytes: &[u8],
    ) -> AppchainResult<poker_texas_air::texas_tagged::ArchivedTaggedTexasProof> {
        use borsh::BorshDeserialize as _;
        poker_texas_air::texas_tagged::ArchivedTaggedTexasProof::try_from_slice(archive_bytes)
            .map_err(|e| AppchainError::Codec(format!("archive: {e}")))
    }
}

impl SettlementProver for TexasAirEngine {
    fn name(&self) -> &'static str {
        "texas-air-v1"
    }

    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
        // 1. 绑定必须存在
        let hp = job
            .record
            .hand_proof
            .as_ref()
            .ok_or(AppchainError::AdmissionRejected("hand proof required"))?;
        // 2. 归档解析（poker_texas_air 类型）
        let archive = Self::parse_archive(&hp.archive_bytes)?;
        // 3. 绑定检查
        if archive.table_id != job.record.table_id {
            return Err(AppchainError::AdmissionRejected("archive table mismatch"));
        }
        if archive.post_state_commitment != hp.post_state_commitment {
            return Err(AppchainError::AdmissionRejected(
                "archive state commitment mismatch",
            ));
        }
        // 4. 完整 STARK 验证（手写约束 AIR 验证器，fail-closed）
        poker_texas_air::texas_tagged::verify_tagged_texas_proof(&archive)
            .map_err(|_| AppchainError::AdmissionRejected("archive stark verify failed"))?;
        // 5. 结算关系校验 + attestation（签名覆盖绑定 + 已验证终态承诺）
        poker_appchain::settlement::validate_settlement(&job.record, &job.policy)?;
        let binding = hex::decode(&hex::encode(job.record.hand_binding))
            .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
        let msg = attestation_message(&binding, &archive.post_state_commitment);
        use ed25519_dalek::Signer as _;
        let mut payload = archive.post_state_commitment.to_vec();
        payload.extend_from_slice(&self.attestor.sign(&msg).to_bytes());
        Ok(ProofBundle {
            binding_hex: hex::encode(job.record.hand_binding),
            op_index: job.op_index,
            engine: self.name(),
            attestor_public: self.attestor_public(),
            payload,
        })
    }

    fn verify(&self, bundle: &ProofBundle) -> AppchainResult<()> {
        if bundle.engine != self.name() {
            return Err(AppchainError::AdmissionRejected("unknown engine"));
        }
        if bundle.payload.len() != 96 {
            return Err(AppchainError::AdmissionRejected("bad payload"));
        }
        let binding = hex::decode(&bundle.binding_hex)
            .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
        if binding.len() != 32 {
            return Err(AppchainError::AdmissionRejected("bad binding length"));
        }
        let mut state_commitment = [0u8; 32];
        state_commitment.copy_from_slice(&bundle.payload[..32]);
        let msg = attestation_message(&binding, &state_commitment);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bundle.payload[32..]);
        if !poker_appchain::keys::SequencerKey::verify(&bundle.attestor_public, &msg, &sig)
        {
            return Err(AppchainError::BadSignature);
        }
        Ok(())
    }
}
