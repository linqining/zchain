//! # poker-appchain-texasair — 接入缝
//!
//! [`poker_appchain`] 结算证明管道（[`SettlementProver`] trait）与
//! [`poker_texas_air`](https://github.com/) 手写约束 canonical AIR 栈
//! （stwo circle-STARK，独立验证器）之间的适配器。
//!
//! ## 为什么是独立 crate
//!
//! 外部 poker_texas_air 仓库携带自己的 `poker_l1`（同名不同源），与
//! zchain workspace 的 `poker_l1` 无法共存于同一依赖图（cargo lockfile
//! collision）。本 crate 自带 lockfile，把重型 stwo 栈隔离在接入缝内，
//! appchain 核心（账本/sequencer）保持零重依赖。
//!
//! ## prove 语义（TexasAirEngine，v2）
//!
//! 1. `hand_proof` 必须存在（本引擎只证明带手牌证明绑定的结算）；
//! 2. 归档解析为 poker_texas_air 的
//!    `texas_canonical_air::ArchivedCanonicalTaggedProof`（borsh 信封，
//!    STARK 证明本体在其内部为 bincode）；
//! 3. 绑定检查：归档 `table_id` == 结算 `table_id`；归档终态承诺
//!    （= 末张 state image 的 blake2b 承诺，32B）== 声明
//!    `post_state_commitment`（结算与**已证明的手牌终态**挂钩，host
//!    不能跨手混装状态——plan B2 的承诺级绑定）；
//! 4. **完整 STARK 验证**：`texas_canonical_air::verify_canonical_tagged_proof`
//!    （手写约束 canonical AIR 的独立验证器：归档 scope 与 state-image
//!    端点一致性 + stwo 验证器从公开范围复核全部约束，不信任 prover）；
//! 5. **完整结算关系校验（含 `hand_proof`，不再剥离）**：
//!    `poker_appchain::settlement::validate_settlement`——自 scope v2
//!    （canonical 布局镜像）落地后，appchain 侧可以逐字段解析 canonical
//!    归档：table/终态承诺/前后状态根/非空批绑定 + **gross_pot 与终态
//!    状态镜像中 `pot` 字段（偏移 74，8B LE）的逐字节绑定**在纯函数
//!    校验内 fail-closed 强制，旧的"清除 hand_proof 副本"补偿**移除**；
//! 6. attestor 签名（**attestation v2.1**：消息 = 结算绑定 + 已验证终态
//!    承诺 + **pre/post 状态根 + 已验证结算计划摘要**，域标签
//!    `poker-appchain.texas-air-v2` 不变、消息内容扩展——P0-3 四要素：
//!    verifier key 隐含于签名者、引擎版本=engine 名/域、pre/post 状态根、
//!    已验证计划摘要；[`TexasAirEngine::verify`] 可独立复验）；
//! 7. **verifier key 钉扎**（可选，生产注入）：[`TexasAirEngine::
//!    with_verifier_key`] 配置固定 attestor 公钥后，`verify` 对
//!    `bundle.attestor_public != 钉扎 key` 的 bundle 返回
//!    [`AppchainError::VerifierKeyMismatch`]（`StarkRequired` 生产语义的
//!    引擎侧强制，见 poker-appchain `real_policy`）。
#![deny(unsafe_code)]
#![deny(missing_docs)]

use poker_appchain::error::{AppchainError, AppchainResult};
use poker_appchain::pipeline::{ProofBundle, ProofJob, SettlementProver};

/// poker_texas_air 手写约束 canonical AIR 证明引擎。
#[derive(Debug, Clone)]
pub struct TexasAirEngine {
    attestor: ed25519_dalek::SigningKey,
    /// 钉扎的固定 attestor 公钥（生产注入）；Some 时 `verify` 强制一致。
    verifier_key: Option<[u8; 32]>,
}

/// attestation 消息（**v2.1**）：绑定（引擎域, 结算绑定, 已验证的手牌终态
/// 承诺, **已验证的 pre/post 状态根**, **已验证的结算计划摘要**）。
///
/// 域标签保持 `poker-appchain.texas-air-v2` 不变，消息内容相对 v2 **追加
/// `pre_state_root` 与 `plan_digest`**——跨版本不互通由消息形状保证（同域
/// 下 v2 签名对 v2.1 消息必然验证失败，且 payload 定长 128B ≠ 192B 先行
/// 拒绝）。四要素覆盖（P0-3）：签名者即 verifier key、域即引擎版本、
/// pre/post 状态根、计划摘要（计划经 `validate_settlement` 验证后取值）。
fn attestation_message(
    binding: &[u8],
    state_commitment: &[u8; 32],
    post_state_root: &[u8; 32],
    pre_state_root: &[u8; 32],
    plan_digest: &[u8; 32],
) -> [u8; 32] {
    poker_appchain::keys::blake2s32(&[
        b"poker-appchain.texas-air-v2",
        binding,
        state_commitment,
        post_state_root,
        pre_state_root,
        plan_digest,
    ])
}

/// attestation payload 定长（v2.1）：终态承诺(32) + 终态状态根(32) +
/// 首状态根(32) + 计划摘要(32) + ed25519 签名(64) = **192B**。
pub const ATTESTATION_PAYLOAD_BYTES: usize = 192;

impl TexasAirEngine {
    /// 指定 attestor 密钥构造（生产：环境注入；不得入库）。
    #[must_use]
    pub fn new(attestor: ed25519_dalek::SigningKey) -> Self {
        Self {
            attestor,
            verifier_key: None,
        }
    }

    /// 钉扎固定 attestor 公钥（生产注入）：`verify` 时
    /// `bundle.attestor_public` 必须一致，否则
    /// [`AppchainError::VerifierKeyMismatch`]（fail-closed，StarkRequired
    /// 生产语义的引擎侧强制）。
    #[must_use]
    pub fn with_verifier_key(mut self, key: [u8; 32]) -> Self {
        self.verifier_key = Some(key);
        self
    }

    /// attestor 公钥。
    #[must_use]
    pub fn attestor_public(&self) -> [u8; 32] {
        self.attestor.verifying_key().to_bytes()
    }

    /// 归档字节 → poker_texas_air canonical 归档结构（borsh 信封编码）。
    ///
    /// # Errors
    /// 编码不合法 → [`AppchainError::Codec`]。
    pub fn parse_archive(
        archive_bytes: &[u8],
    ) -> AppchainResult<poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof> {
        use borsh::BorshDeserialize as _;
        poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof::try_from_slice(
            archive_bytes,
        )
        .map_err(|e| AppchainError::Codec(format!("archive: {e}")))
    }
}

impl SettlementProver for TexasAirEngine {
    fn name(&self) -> &'static str {
        "texas-air-v2"
    }

    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
        // 1. 绑定必须存在
        let hp = job
            .record
            .hand_proof
            .as_ref()
            .ok_or(AppchainError::AdmissionRejected("hand proof required"))?;
        // 2. 归档解析（poker_texas_air canonical 类型）
        let archive = Self::parse_archive(&hp.archive_bytes)?;
        // 3. 绑定检查（[u8; 32] / u64 逐字段比较，数组 == 即逐字节相等）
        if archive.table_id != job.record.table_id {
            return Err(AppchainError::AdmissionRejected("archive table mismatch"));
        }
        if archive.post_state_commitment != hp.post_state_commitment {
            return Err(AppchainError::AdmissionRejected(
                "archive state commitment mismatch",
            ));
        }
        // 4. 完整 STARK 验证（手写约束 canonical AIR 验证器，fail-closed：
        //    归档形状 / reveal-cascade 调度 / 端点 state-image 绑定 /
        //    rake-blind opening 绑定 / stwo 验证器全约束复核，任一失败同拒）
        poker_texas_air::texas_canonical_air::verify_canonical_tagged_proof(&archive)
            .map_err(|_| AppchainError::AdmissionRejected("archive stark verify failed"))?;
        // 5. 完整结算关系校验（scope v2 落地后直接带 hand_proof 校验——
        //    归档 scope/状态根/镜像 pot 绑定全部在纯函数校验内 fail-closed）
        poker_appchain::settlement::validate_settlement(&job.record, &job.policy)?;
        // 6. attestation v2.1（签名覆盖绑定 + 已验证终态承诺 + 已验证
        //    pre/post 状态根 + 已验证结算计划摘要——P0-3 四要素）
        let binding = job.record.hand_binding.to_vec();
        let plan_digest = poker_appchain::settlement::plan_digest_bytes(&job.record.plan);
        let msg = attestation_message(
            &binding,
            &archive.post_state_commitment,
            &archive.post_state_root,
            &archive.pre_state_root,
            &plan_digest,
        );
        use ed25519_dalek::Signer as _;
        let mut payload = archive.post_state_commitment.to_vec();
        payload.extend_from_slice(&archive.post_state_root);
        payload.extend_from_slice(&archive.pre_state_root);
        payload.extend_from_slice(&plan_digest);
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
        if bundle.payload.len() != ATTESTATION_PAYLOAD_BYTES {
            return Err(AppchainError::AdmissionRejected("bad payload"));
        }
        // P0-3：钉扎的固定 attestor（StarkRequired 生产语义）——不一致即拒
        if let Some(key) = self.verifier_key {
            if bundle.attestor_public != key {
                return Err(AppchainError::VerifierKeyMismatch);
            }
        }
        let binding = hex::decode(&bundle.binding_hex)
            .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
        if binding.len() != 32 {
            return Err(AppchainError::AdmissionRejected("bad binding length"));
        }
        let mut state_commitment = [0u8; 32];
        state_commitment.copy_from_slice(&bundle.payload[..32]);
        let mut post_state_root = [0u8; 32];
        post_state_root.copy_from_slice(&bundle.payload[32..64]);
        let mut pre_state_root = [0u8; 32];
        pre_state_root.copy_from_slice(&bundle.payload[64..96]);
        let mut plan_digest = [0u8; 32];
        plan_digest.copy_from_slice(&bundle.payload[96..128]);
        let msg = attestation_message(
            &binding,
            &state_commitment,
            &post_state_root,
            &pre_state_root,
            &plan_digest,
        );
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bundle.payload[128..]);
        if !poker_appchain::keys::SequencerKey::verify(&bundle.attestor_public, &msg, &sig) {
            return Err(AppchainError::BadSignature);
        }
        Ok(())
    }
}
