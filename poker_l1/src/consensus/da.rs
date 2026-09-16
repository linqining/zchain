//! v1.5 DA 原语（plan §2-d，最小闭环原型）。
//!
//! # 语义
//!
//! **DA（Data Availability）问题**：执行层消费一条数据（tx / batch）前，需要
//! 确认该数据可被 quorum 获取 —— 即使原发布方（如 Sequencer）停机，数据也不
//! 会丢失。本模块给出最小闭环：
//!
//! 1. [`DaRequest`]：对某个数据摘要 `digest`（tx_hash 或 batch root）的可用性
//!    请求。digest 是请求的唯一键 —— DA 层不搬运数据本体，只对"数据已被
//!    validator 见证并可得"作签；
//! 2. [`DaReceipt`]：validator 对 `DA 签名对象` 的 BLS 签名回执 —— 语义是
//!    "本 validator 已持有/可在合理时间内提供 digest 对应的数据"；
//! 3. [`DaCertificate`]：≥2f+1 个回执的**聚合凭证**（复用 v1.5-c checkpoint
//!    的 BLS 聚合基建：G1 点加法聚合 + 单次配对验证）。凭证可独立于原数据
//!    持有方验证 —— M8-ACC-8（Sequencer 停机注入下 DA 凭证仍可验证）。
//!    P1 修复：聚合/验证均要求**签名者成员资格**（自声明公钥 ∈ 调用方传入
//!    的 validator BLS 公钥注册表，见 [`DaCertificate::verify_against_signers`]），
//!    防"自造 quorum(n) 全新 BLS 键伪造凭证"。
//!
//! # 命名与边界（如实）
//!
//! - 这**不是**完整 DA 层：没有擦除码（erasure coding）、没有随机采样
//!   （DAS）、没有批次分片、没有挑战/扣分游戏。"validator 签回执"的诚实性
//!   由签名者自律承担 —— 生产 DA 必须配合抽样验证或欺诈证明。
//! - 聚合凭证 = **2f+1 聚签**（聚合签名），非阈值签名（同 checkpoint 的
//!   命名纪律，见 `checkpoint` 模块头）。
//! - `digest` 的真实性（数据 ↔ 摘要绑定）由调用方保证：tx 场景即 tx_hash
//!   （签名交易内容寻址）；batch 场景应使用批次 Merkle root。
//!
//! # 与 checkpoint QC 的关系
//!
//! 签名/聚合/验证全部复用 `consensus::checkpoint` 的 BLS 函数
//! （`bls_derive_secret_key` / `bls_verify_single` / `bls_aggregate_g1` /
//! `bls_verify_aggregate_same_msg`），仅签名域不同（`0x44 'D'` vs `0x51 'Q'`），
//! 防跨域重放。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::consensus::Epoch;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::{BlockHeight, Hash};

/// DA 签名域分隔前缀（'D' for DA；与 checkpoint QC 0x51 区分）。
const DA_SIG_DOMAIN: u8 = 0x44;

/// DA 签名对象：`blake2b_256(0x44 || epoch || height || digest)`。
#[must_use]
pub fn da_signing_hash(epoch: Epoch, height: BlockHeight, digest: Hash) -> Hash {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[DA_SIG_DOMAIN]);
    h.update(&epoch.to_le_bytes());
    h.update(&height.to_le_bytes());
    h.update(&digest);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// DA 请求（对某数据摘要的可用性请求）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DaRequest {
    /// 数据摘要（tx_hash 或 batch root；DA 层不搬运数据本体）。
    pub digest: Hash,
    /// 请求时的 epoch（签名域分量）。
    pub epoch: Epoch,
    /// 请求时的链高（签名域分量）。
    pub height: BlockHeight,
    /// 请求发起方（客户端/Sequencer 的 tagged pubkey；仅记录，不参与签名域）。
    pub requester: crate::signature::TaggedPubkey,
}

/// validator 的 DA 签名回执（"已见证 digest 数据可得"）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DaReceipt {
    /// 数据摘要。
    pub digest: Hash,
    /// epoch。
    pub epoch: Epoch,
    /// 链高。
    pub height: BlockHeight,
    /// 签名对象（收集端一致性校验用）。
    pub signing_hash: Hash,
    /// 签名者 BLS 公钥（G2 compressed 96B）。
    pub signer_pubkey_g2: Vec<u8>,
    /// BLS 签名（G1 compressed 48B）。
    pub signature_g1: Vec<u8>,
}

impl DaReceipt {
    /// 签发一条 DA 回执。
    pub fn sign(
        digest: Hash,
        epoch: Epoch,
        height: BlockHeight,
        sk: &crate::consensus::checkpoint::BlsSecretKey,
    ) -> PokerL1Result<Self> {
        let signing_hash = da_signing_hash(epoch, height, digest);
        let signature_g1 = sk.sign(&signing_hash)?;
        Ok(Self {
            digest,
            epoch,
            height,
            signing_hash,
            signer_pubkey_g2: sk.pubkey_g2().to_vec(),
            signature_g1: signature_g1.to_vec(),
        })
    }

    /// 验证回执：签名对象一致 + 配对单签验证。
    pub fn verify(&self) -> PokerL1Result<()> {
        if self.signer_pubkey_g2.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "da receipt pubkey size {} != {}",
                self.signer_pubkey_g2.len(),
                crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
            )));
        }
        if self.signature_g1.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "da receipt signature size {} != {}",
                self.signature_g1.len(),
                crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
            )));
        }
        let expected = da_signing_hash(self.epoch, self.height, self.digest);
        if expected != self.signing_hash {
            return Err(PokerL1Error::Other(
                "da receipt signing_hash 与 (epoch, height, digest) 不一致".into(),
            ));
        }
        let ok = crate::consensus::checkpoint::bls_verify_single(
            &self.signer_pubkey_g2,
            &self.signature_g1,
            &self.signing_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "da receipt BLS signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// DA 聚合凭证（≥2f+1 聚签；复用 checkpoint QC 聚合基建）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DaCertificate {
    /// 数据摘要。
    pub digest: Hash,
    /// epoch。
    pub epoch: Epoch,
    /// 链高。
    pub height: BlockHeight,
    /// 聚合签名（G1 compressed 48B）。
    pub agg_signature_g1: Vec<u8>,
    /// 签名者 BLS 公钥集合（G2 compressed）。
    pub signer_pubkeys_g2: Vec<Vec<u8>>,
}

impl DaCertificate {
    /// 由回执集合聚合 DA 凭证（**签名者成员资格** + 逐回执验证 + 去重 +
    /// 2f+1 计数）。
    ///
    /// P1 修复：每份回执的 `signer_pubkey_g2` 必须 ∈ `allowed_g2`
    /// （validator BLS 公钥注册表）—— 防"自造 quorum(n) 全新 BLS 键拼出
    /// 密码学合法聚合签名"的凭证伪造；注册表为空 fail-closed 拒。
    ///
    /// # Errors
    /// 任一签名者非成员/注册表为空，或既有拒绝条件（位点异构/签名无效/
    /// 不足 quorum/聚合验证失败）。
    pub fn form_from_receipts(
        receipts: &[DaReceipt],
        allowed_g2: &std::collections::BTreeSet<[u8; 96]>,
        validator_count: usize,
    ) -> PokerL1Result<Self> {
        let Some(first) = receipts.first() else {
            return Err(PokerL1Error::Other("da certificate: 无回执".into()));
        };
        let (digest, epoch, height, signing_hash) =
            (first.digest, first.epoch, first.height, first.signing_hash);
        let mut pks: Vec<Vec<u8>> = Vec::new();
        let mut sigs: Vec<[u8; 48]> = Vec::new();
        for receipt in receipts {
            if receipt.digest != digest
                || receipt.epoch != epoch
                || receipt.height != height
                || receipt.signing_hash != signing_hash
            {
                return Err(PokerL1Error::Other(
                    "da certificate: 回执位点不一致（异构回执拒绝）".into(),
                ));
            }
            // 成员资格先行（集合查找，成本低于配对验证）
            crate::consensus::checkpoint::ensure_bls_signer_member(
                "da certificate",
                &receipt.signer_pubkey_g2,
                allowed_g2,
            )?;
            receipt.verify()?;
            if pks.iter().any(|pk| *pk == receipt.signer_pubkey_g2) {
                continue;
            }
            let mut sig = [0u8; 48];
            sig.copy_from_slice(&receipt.signature_g1);
            sigs.push(sig);
            pks.push(receipt.signer_pubkey_g2.clone());
        }
        let required = crate::consensus::required_quorum(validator_count);
        if pks.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: pks.len(),
                required,
            });
        }
        let agg_signature_g1 = crate::consensus::checkpoint::bls_aggregate_g1(&sigs)?;
        let agg_pk = crate::consensus::checkpoint::bls_aggregate_g2(
            &pks.iter()
                .map(|pk| {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(pk);
                    arr
                })
                .collect::<Vec<_>>(),
        )?;
        let ok =
            crate::consensus::checkpoint::bls_verify_aggregate_same_msg(&agg_signature_g1, &agg_pk, &signing_hash)?;
        if !ok {
            return Err(PokerL1Error::Other("da certificate: 聚合签名验证失败".into()));
        }
        Ok(Self {
            digest,
            epoch,
            height,
            agg_signature_g1: agg_signature_g1.to_vec(),
            signer_pubkeys_g2: pks,
        })
    }

    /// 验证 DA 凭证（**不含签名者成员资格**：聚合配对 + 2f+1 计数 + 去重）。
    ///
    /// # Safety-boundary（P1 修复后口径）
    ///
    /// 本方法不校验自声明 `signer_pubkeys_g2` 是否属于 validator 集 ——
    /// 生产路径必须用 [`Self::verify_against_signers`]；本方法仅供密码学
    /// 层单测（篡改/域分隔断言）。
    #[doc(hidden)]
    pub fn verify(&self, validator_count: usize) -> PokerL1Result<()> {
        if self.signer_pubkeys_g2.is_empty() {
            return Err(PokerL1Error::Other("da certificate: 签名者为空".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for pk in &self.signer_pubkeys_g2 {
            if !seen.insert(pk.clone()) {
                return Err(PokerL1Error::Other("da certificate: 重复签名者".into()));
            }
        }
        let required = crate::consensus::required_quorum(validator_count);
        if self.signer_pubkeys_g2.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_pubkeys_g2.len(),
                required,
            });
        }
        let signing_hash = da_signing_hash(self.epoch, self.height, self.digest);
        let agg_pk = crate::consensus::checkpoint::bls_aggregate_g2(
            &self
                .signer_pubkeys_g2
                .iter()
                .map(|pk| {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(pk);
                    arr
                })
                .collect::<Vec<_>>(),
        )?;
        let ok = crate::consensus::checkpoint::bls_verify_aggregate_same_msg(
            &self.agg_signature_g1,
            &agg_pk,
            &signing_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other("da certificate: 聚合签名验证失败".into()));
        }
        Ok(())
    }

    /// 验证 DA 凭证（P1 修复：**成员资格 + 密码学全量**）。
    ///
    /// 自声明 `signer_pubkeys_g2` 的每一项必须 ∈ `allowed_g2`（validator
    /// BLS 公钥注册表），叠加既有去重/quorum/聚合配对。注册表为空 →
    /// fail-closed 拒。
    ///
    /// # Errors
    /// 任一签名者非成员/注册表为空，或 [`Self::verify`] 的任一拒绝条件。
    pub fn verify_against_signers(
        &self,
        allowed_g2: &std::collections::BTreeSet<[u8; 96]>,
        validator_count: usize,
    ) -> PokerL1Result<()> {
        for pk in &self.signer_pubkeys_g2 {
            crate::consensus::checkpoint::ensure_bls_signer_member(
                "da certificate",
                pk,
                allowed_g2,
            )?;
        }
        self.verify(validator_count)
    }

    /// 签名者数量。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_pubkeys_g2.len()
    }
}


// ===== v1.5 DA v2 增补（da-selection.md §4.2 待办 #1/#3；additive） =====
//
// # object_type 进签名域（§4.2 #1：消除跨对象类型重放）
//
// v1 回执签名对象不含"被签对象是什么类型"——Batch 摘要与 Blob 摘要若
// 相同（理论可能：内容寻址碰撞面），Batch 回执可重放为 Blob 回执。v2
// 域把 [`DaObjectKind`] 判别值纳入签名对象；v1 类型与签名域**零变更**
// （既有回执/凭证继续验证），v2 回执只签 v2 域。
//
// # 挑战-应答（§4.2 #3：回执"凭证成立 ≠ 数据可取"缺口的机制面）
//
// 回执语义是"签名者声称持有数据"，凭证不证明数据真的可取。挑战-应答
// 给验证方一条**主动验证**路径：发布侧把 blob 按 [`DA_CHALLENGE_CHUNK`]
// 分块、对块哈希建 Merkle 树并公布 `chunk_root`（与 blob 摘要一起进
// DA 签名域的 `digest` 位）；验证方从**凭证签名对象 + 挑战 nonce** 确定性
// 派生随机块号（"receipt 后 N 块随机偏移取数挑战"的原语面），持有方
// 应答（块内容 + Merkle 路径），验证方本地核对包含关系——持有方若已
// 丢数据则无法应答任意挑战。本模块交付原语与负例矩阵；gossip 轮次/
// 罚没联动随 DA 层实现排期。

/// DA 对象类型（v2 签名域分量；判别值冻结）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum DaObjectKind {
    /// 批次数据（batch root 位）。
    Batch = 1,
    /// 任意 blob（tx 载荷/证明归档等）。
    Blob = 2,
}

impl DaObjectKind {
    /// ABI 判别值。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从判别值解析（未定义值拒，fail-closed）。
    ///
    /// # Errors
    /// 未定义判别值 → [`PokerL1Error::Other`]。
    pub fn from_u8(v: u8) -> PokerL1Result<Self> {
        match v {
            1 => Ok(Self::Batch),
            2 => Ok(Self::Blob),
            _ => Err(PokerL1Error::Other(format!(
                "da object kind: undefined discriminant {v}"
            ))),
        }
    }
}

/// DA v2 域版本字节（v1 域 `0x44 || ...`；v2 = `0x44 || 0x02 || kind ...`）。
const DA_SIG_DOMAIN_V2: u8 = 0x02;

/// DA v2 签名对象：`blake2b_256(0x44 || 0x02 || kind || epoch || height || digest)`。
#[must_use]
pub fn da_signing_hash_v2(
    kind: DaObjectKind,
    epoch: Epoch,
    height: BlockHeight,
    digest: Hash,
) -> Hash {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[DA_SIG_DOMAIN, DA_SIG_DOMAIN_V2, kind.as_u8()]);
    h.update(&epoch.to_le_bytes());
    h.update(&height.to_le_bytes());
    h.update(&digest);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// validator 的 DA v2 回执（v1 [`DaReceipt`] + `object_type`；签名域 v2）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DaReceiptV2 {
    /// 数据摘要。
    pub digest: Hash,
    /// 对象类型（进签名域，防跨类型重放）。
    pub object_type: DaObjectKind,
    /// epoch。
    pub epoch: Epoch,
    /// 链高。
    pub height: BlockHeight,
    /// 签名对象（收集端一致性校验用）。
    pub signing_hash: Hash,
    /// 签名者 BLS 公钥（G2 compressed 96B）。
    pub signer_pubkey_g2: Vec<u8>,
    /// BLS 签名（G1 compressed 48B）。
    pub signature_g1: Vec<u8>,
}

impl DaReceiptV2 {
    /// 签发一条 v2 回执。
    pub fn sign(
        digest: Hash,
        object_type: DaObjectKind,
        epoch: Epoch,
        height: BlockHeight,
        sk: &crate::consensus::checkpoint::BlsSecretKey,
    ) -> PokerL1Result<Self> {
        let signing_hash = da_signing_hash_v2(object_type, epoch, height, digest);
        let signature_g1 = sk.sign(&signing_hash)?;
        Ok(Self {
            digest,
            object_type,
            epoch,
            height,
            signing_hash,
            signer_pubkey_g2: sk.pubkey_g2().to_vec(),
            signature_g1: signature_g1.to_vec(),
        })
    }

    /// 验证回执（v2 域一致性 + 配对单签验证）。
    pub fn verify(&self) -> PokerL1Result<()> {
        if self.signer_pubkey_g2.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "da v2 receipt pubkey size {} != {}",
                self.signer_pubkey_g2.len(),
                crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
            )));
        }
        if self.signature_g1.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "da v2 receipt signature size {} != {}",
                self.signature_g1.len(),
                crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
            )));
        }
        let expected = da_signing_hash_v2(self.object_type, self.epoch, self.height, self.digest);
        if expected != self.signing_hash {
            return Err(PokerL1Error::Other(
                "da v2 receipt signing_hash 与 (kind, epoch, height, digest) 不一致".into(),
            ));
        }
        let ok = crate::consensus::checkpoint::bls_verify_single(
            &self.signer_pubkey_g2,
            &self.signature_g1,
            &self.signing_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "da v2 receipt BLS signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// DA v2 聚合凭证（≥2f+1 聚签；v2 签名域，复用 checkpoint 聚合基建）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct DaCertificateV2 {
    /// 数据摘要。
    pub digest: Hash,
    /// 对象类型（进签名域）。
    pub object_type: DaObjectKind,
    /// epoch。
    pub epoch: Epoch,
    /// 链高。
    pub height: BlockHeight,
    /// 聚合签名（G1 compressed 48B）。
    pub agg_signature_g1: Vec<u8>,
    /// 签名者 BLS 公钥集合（G2 compressed）。
    pub signer_pubkeys_g2: Vec<Vec<u8>>,
}

impl DaCertificateV2 {
    /// 由 v2 回执集合聚合凭证（**签名者成员资格** + 逐回执验证 + 去重 +
    /// 2f+1 计数）。
    ///
    /// P1 修复：每份回执的 `signer_pubkey_g2` 必须 ∈ `allowed_g2`
    /// （validator BLS 公钥注册表）；注册表为空 fail-closed 拒。
    ///
    /// # Errors
    /// 任一签名者非成员/注册表为空，或既有拒绝条件。
    pub fn form_from_receipts(
        receipts: &[DaReceiptV2],
        allowed_g2: &std::collections::BTreeSet<[u8; 96]>,
        validator_count: usize,
    ) -> PokerL1Result<Self> {
        let Some(first) = receipts.first() else {
            return Err(PokerL1Error::Other("da v2 certificate: 无回执".into()));
        };
        let (digest, object_type, epoch, height, signing_hash) = (
            first.digest,
            first.object_type,
            first.epoch,
            first.height,
            first.signing_hash,
        );
        let mut pks: Vec<Vec<u8>> = Vec::new();
        let mut sigs: Vec<[u8; 48]> = Vec::new();
        for receipt in receipts {
            if receipt.digest != digest
                || receipt.object_type != object_type
                || receipt.epoch != epoch
                || receipt.height != height
                || receipt.signing_hash != signing_hash
            {
                return Err(PokerL1Error::Other(
                    "da v2 certificate: 回执位点不一致（异构回执拒绝）".into(),
                ));
            }
            // 成员资格先行（集合查找，成本低于配对验证）
            crate::consensus::checkpoint::ensure_bls_signer_member(
                "da v2 certificate",
                &receipt.signer_pubkey_g2,
                allowed_g2,
            )?;
            receipt.verify()?;
            if pks.iter().any(|pk| *pk == receipt.signer_pubkey_g2) {
                continue;
            }
            let mut sig = [0u8; 48];
            sig.copy_from_slice(&receipt.signature_g1);
            sigs.push(sig);
            pks.push(receipt.signer_pubkey_g2.clone());
        }
        let required = crate::consensus::required_quorum(validator_count);
        if pks.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: pks.len(),
                required,
            });
        }
        let agg_signature_g1 = crate::consensus::checkpoint::bls_aggregate_g1(&sigs)?;
        let agg_pk = crate::consensus::checkpoint::bls_aggregate_g2(
            &pks.iter()
                .map(|pk| {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(pk);
                    arr
                })
                .collect::<Vec<_>>(),
        )?;
        let ok = crate::consensus::checkpoint::bls_verify_aggregate_same_msg(
            &agg_signature_g1,
            &agg_pk,
            &signing_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "da v2 certificate: 聚合签名验证失败".into(),
            ));
        }
        Ok(Self {
            digest,
            object_type,
            epoch,
            height,
            agg_signature_g1: agg_signature_g1.to_vec(),
            signer_pubkeys_g2: pks,
        })
    }

    /// 验证 DA v2 凭证（**不含签名者成员资格**）。
    ///
    /// # Safety-boundary（P1 修复后口径）
    ///
    /// 不校验签名者是否属于 validator 集 —— 生产路径必须用
    /// [`Self::verify_against_signers`]；本方法仅供密码学层单测。
    #[doc(hidden)]
    pub fn verify(&self, validator_count: usize) -> PokerL1Result<()> {
        if self.signer_pubkeys_g2.is_empty() {
            return Err(PokerL1Error::Other("da v2 certificate: 签名者为空".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for pk in &self.signer_pubkeys_g2 {
            if !seen.insert(pk.clone()) {
                return Err(PokerL1Error::Other("da v2 certificate: 重复签名者".into()));
            }
        }
        let required = crate::consensus::required_quorum(validator_count);
        if self.signer_pubkeys_g2.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_pubkeys_g2.len(),
                required,
            });
        }
        let signing_hash =
            da_signing_hash_v2(self.object_type, self.epoch, self.height, self.digest);
        let agg_pk = crate::consensus::checkpoint::bls_aggregate_g2(
            &self
                .signer_pubkeys_g2
                .iter()
                .map(|pk| {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(pk);
                    arr
                })
                .collect::<Vec<_>>(),
        )?;
        let ok = crate::consensus::checkpoint::bls_verify_aggregate_same_msg(
            &self.agg_signature_g1,
            &agg_pk,
            &signing_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "da v2 certificate: 聚合签名验证失败".into(),
            ));
        }
        Ok(())
    }

    /// 验证 DA v2 凭证（P1 修复：**成员资格 + 密码学全量**）。
    ///
    /// 自声明 `signer_pubkeys_g2` 的每一项必须 ∈ `allowed_g2`（validator
    /// BLS 公钥注册表），叠加既有去重/quorum/聚合配对。注册表为空 →
    /// fail-closed 拒。
    ///
    /// # Errors
    /// 任一签名者非成员/注册表为空，或 [`Self::verify`] 的任一拒绝条件。
    pub fn verify_against_signers(
        &self,
        allowed_g2: &std::collections::BTreeSet<[u8; 96]>,
        validator_count: usize,
    ) -> PokerL1Result<()> {
        for pk in &self.signer_pubkeys_g2 {
            crate::consensus::checkpoint::ensure_bls_signer_member(
                "da v2 certificate",
                pk,
                allowed_g2,
            )?;
        }
        self.verify(validator_count)
    }

    /// 签名者数量。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_pubkeys_g2.len()
    }

    /// 凭证签名对象（挑战派生输入）。
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        da_signing_hash_v2(self.object_type, self.epoch, self.height, self.digest)
    }
}

// ----- 挑战-应答原语（Merkle 分块） -----

/// 挑战域标签（块号派生；与签名域分离）。
const DA_CHALLENGE_DOMAIN: &[u8] = b"ZCHAIN_DA_CHALLENGE_V1";

/// blob 分块 → 块哈希表（`blake2b_256(chunk)`；末块不足整块按实际长度）。
#[must_use]
pub fn blob_chunk_digests(blob: &[u8], chunk_size: usize) -> Vec<Hash> {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    assert!(chunk_size > 0, "chunk size must be positive");
    blob.chunks(chunk_size)
        .map(|chunk| {
            let mut h = Blake2bVar::new(32).expect("32 <= 64");
            h.update(chunk);
            let mut out = [0u8; 32];
            h.finalize_variable(&mut out).expect("32 <= 64");
            out
        })
        .collect()
}

fn blake2b32(parts: &[&[u8]]) -> Hash {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 块哈希表 → Merkle 根（blake2b 二叉树；奇数层最后节点复制补齐——与
/// 路径生成同规则，负载非 2 的幂时确定）。
#[must_use]
pub fn chunk_merkle_root(leaf_digests: &[Hash]) -> Hash {
    assert!(!leaf_digests.is_empty(), "chunk merkle root of empty blob");
    let mut level = leaf_digests.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        level = level
            .chunks(2)
            .map(|pair| blake2b32(&[&pair[0], &pair[1]]))
            .collect();
    }
    level[0]
}

/// 块 `index` 的 Merkle 包含路径（自叶向根的兄弟哈希序列）。
#[must_use]
pub fn chunk_merkle_proof(leaf_digests: &[Hash], index: usize) -> Vec<Hash> {
    assert!(!leaf_digests.is_empty() && index < leaf_digests.len());
    let mut level = leaf_digests.to_vec();
    let mut idx = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(level[sibling]);
        level = level
            .chunks(2)
            .map(|pair| blake2b32(&[&pair[0], &pair[1]]))
            .collect();
        idx /= 2;
    }
    path
}

/// Merkle 包含验证（与 [`chunk_merkle_root`] 同折叠规则）。
#[must_use]
pub fn verify_chunk_inclusion(root: &Hash, leaf: &Hash, index: usize, path: &[Hash]) -> bool {
    let mut acc = *leaf;
    let mut idx = index;
    for &sibling in path {
        let pair = if idx % 2 == 0 {
            blake2b32(&[&acc, &sibling])
        } else {
            blake2b32(&[&sibling, &acc])
        };
        acc = pair;
        idx /= 2;
    }
    acc == *root
}

/// 挑战块号派生：`idx = blake2b(DOMAIN || cert_signing_hash || nonce) mod
/// chunk_count`（确定性——挑战方与应答方独立重算同号；nonce 递增即新
/// 挑战轮次）。
#[must_use]
pub fn challenge_chunk_index(chunk_count: usize, cert_signing_hash: &Hash, nonce: u64) -> usize {
    assert!(chunk_count > 0);
    let mut seed = blake2b32(&[DA_CHALLENGE_DOMAIN, cert_signing_hash, &nonce.to_le_bytes()]);
    // 取前 8 字节为 u64（大端）取模；模偏置对挑战选择无安全影响（nonce
    // 可无限轮换，非密钥面），诚实标注为均匀性近似。
    let pick = u64::from_be_bytes(seed[..8].try_into().expect("8B from 32B"));
    let _ = &mut seed;
    (pick % chunk_count as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::checkpoint::{BlsSecretKey, bls_derive_secret_key};

    fn bls_key(seed: u8) -> BlsSecretKey {
        bls_derive_secret_key(&[seed; 32])
    }

    /// 由种子集构造允许签名者注册表（P1 成员资格测试辅助）。
    fn allowed_from_seeds(seeds: &[u8]) -> std::collections::BTreeSet<[u8; 96]> {
        seeds.iter().map(|&s| bls_key(s).pubkey_g2()).collect()
    }

    fn receipts_for(digest: Hash, seeds: &[u8]) -> Vec<DaReceipt> {
        seeds
            .iter()
            .map(|&s| DaReceipt::sign(digest, 1, 42, &bls_key(s)).unwrap())
            .collect()
    }

    /// M8-ACC-8：Sequencer 停机注入下 DA 凭证仍可验证。
    ///
    /// 场景：Sequencer 持有 batch 数据并发起 DA 请求；7 validator 中 ≥2f+1（5）
    /// 从**自身已持有的副本**签回执；随后 Sequencer 停机（数据源消失）。
    /// 凭证的聚合与验证只消费 validator 侧回执 —— 与 Sequencer 是否存活无关。
    #[test]
    fn m8_acc_8_da_certificate_verifiable_after_sequencer_down() {
        let batch_root = [0xBAu8; 32];
        let allowed = allowed_from_seeds(&[0x10, 0x11, 0x12, 0x13, 0x14]);
        // Sequencer 停机前：5 个 validator 各自从本地副本签回执
        let receipts = receipts_for(batch_root, &[0x10, 0x11, 0x12, 0x13, 0x14]);
        // Sequencer 停机（此处无任何 Sequencer 依赖：不再触碰"数据源"）
        let cert = DaCertificate::form_from_receipts(&receipts, &allowed, 7)
            .expect("2f+1 回执必须成凭证");
        assert_eq!(cert.digest, batch_root);
        assert_eq!(cert.signer_count(), 5);
        // 第三方（无数据副本、无 Sequencer 连接）验证凭证
        cert.verify(7).expect("Sequencer 停机后凭证必须仍可验证");
        // digest 绑定：换摘要验证必失败
        let mut tampered = cert.clone();
        tampered.digest = [0x00u8; 32];
        assert!(tampered.verify(7).is_err(), "换 digest 必须验证失败");
    }

    #[test]
    fn da_receipt_sign_verify_and_domain_separation() {
        let digest = [1u8; 32];
        let receipt = DaReceipt::sign(digest, 1, 10, &bls_key(0x20)).unwrap();
        receipt.verify().expect("合法回执必须通过");
        // 篡改 height → 签名对象变化 → 拒
        let mut bad = receipt.clone();
        bad.height = 11;
        assert!(bad.verify().is_err());
        // 跨域：同位点用 checkpoint QC 域签的对象不能通过 DA 验证（域分隔）
        let qc_hash = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 10, digest);
        assert_ne!(qc_hash, da_signing_hash(1, 10, digest), "DA 与 QC 域必须不同");
    }

    #[test]
    fn da_certificate_rejects_insufficient_quorum() {
        let digest = [2u8; 32];
        let allowed = allowed_from_seeds(&[0x21, 0x22, 0x23, 0x24, 0x25, 0x26]);
        // 7 validator 需 5 回执，仅 4 → 拒
        let receipts = receipts_for(digest, &[0x21, 0x22, 0x23, 0x24]);
        let err = DaCertificate::form_from_receipts(&receipts, &allowed, 7).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientQuorum { actual: 4, required: 5 }));
        // 异构位点混入 → 拒
        let mut mixed = receipts_for(digest, &[0x21, 0x22, 0x23, 0x24, 0x25]);
        mixed.push(DaReceipt::sign([0xEEu8; 32], 1, 42, &bls_key(0x26)).unwrap());
        let err2 = DaCertificate::form_from_receipts(&mixed, &allowed, 7).unwrap_err();
        assert!(err2.to_string().contains("位点不一致"));
        // 重复签名者去重后不足 → 拒
        let single = DaReceipt::sign(digest, 1, 42, &bls_key(0x21)).unwrap();
        let dup = vec![single.clone(), single];
        assert!(matches!(
            DaCertificate::form_from_receipts(&dup, &allowed, 7).unwrap_err(),
            PokerL1Error::InsufficientQuorum { .. }
        ));
    }

    #[test]
    fn da_types_serialize_roundtrip() {
        let digest = [3u8; 32];
        let allowed = allowed_from_seeds(&[0x30, 0x31, 0x32, 0x33, 0x34]);
        let receipts = receipts_for(digest, &[0x30, 0x31, 0x32, 0x33, 0x34]);
        let cert = DaCertificate::form_from_receipts(&receipts, &allowed, 7).unwrap();
        // JSON（RPC/sidecar 友好）
        let json = serde_json::to_string(&cert).unwrap();
        let back: DaCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
        back.verify(7).unwrap();
        // BCS（P2P 载荷）
        let bytes = borsh::to_vec(&receipts[0]).unwrap();
        let receipt_back: DaReceipt = borsh::from_slice(&bytes).unwrap();
        assert_eq!(receipts[0], receipt_back);
        receipt_back.verify().unwrap();
    }

    // ===== v1.5 DA v2：object_type 域 + 挑战-应答 =====

    use super::{DaCertificateV2, DaObjectKind, DaReceiptV2};

    fn v2_receipts(digest: Hash, kind: DaObjectKind, seeds: &[u8]) -> Vec<DaReceiptV2> {
        seeds
            .iter()
            .map(|&s| DaReceiptV2::sign(digest, kind, 1, 42, &bls_key(s)).unwrap())
            .collect()
    }

    /// v2 object_type 进签名域：同摘要不同类型的回执互相不可重放（换类型
    /// 即签名对象变化 → 验证拒）；v2 与 v1 域分离（v1 回执不能过 v2 验证
    /// 面的位点一致性核对——域哈希不同必然 signing_hash 失配）。
    #[test]
    fn da_v2_object_type_binds_signature_domain() {
        let digest = [0xD2u8; 32];
        let batch = DaReceiptV2::sign(digest, DaObjectKind::Batch, 1, 42, &bls_key(0x30)).unwrap();
        batch.verify().expect("合法 v2 回执必须通过");
        // 类型互换重放：Batch 回执声明为 Blob → signing_hash 失配拒
        let mut replayed = batch.clone();
        replayed.object_type = DaObjectKind::Blob;
        assert!(replayed.verify().is_err(), "跨类型重放必须拒绝");
        // v2 域与 v1 域不同
        assert_ne!(
            da_signing_hash_v2(DaObjectKind::Batch, 1, 42, digest),
            da_signing_hash(1, 42, digest),
            "v1/v2 签名域必须分离"
        );
    }

    /// M8-ACC-8 的 v2 复验：凭证聚合/验证与 Sequencer 存活无关（对象类型
    /// 承载进凭证）。
    #[test]
    fn da_v2_certificate_form_and_verify() {
        let digest = [0xD3u8; 32];
        let allowed = allowed_from_seeds(&[0x40, 0x41, 0x42, 0x43, 0x44, 0x45]);
        let cert =
            DaCertificateV2::form_from_receipts(&v2_receipts(digest, DaObjectKind::Blob, &[0x40, 0x41, 0x42, 0x43, 0x44]), &allowed, 7)
                .expect("2f+1 v2 回执必须成凭证");
        assert_eq!(cert.signer_count(), 5);
        cert.verify(7).expect("v2 凭证必须可验证");
        // 篡改 object_type → 签名对象变化 → 拒
        let mut bad = cert.clone();
        bad.object_type = DaObjectKind::Batch;
        assert!(bad.verify(7).is_err());
        // 异构回执（类型不一致）聚合拒
        let mut mixed = v2_receipts(digest, DaObjectKind::Blob, &[0x40, 0x41, 0x42, 0x43]);
        mixed.push(DaReceiptV2::sign(digest, DaObjectKind::Batch, 1, 42, &bls_key(0x45)).unwrap());
        let err = DaCertificateV2::form_from_receipts(&mixed, &allowed, 7).unwrap_err();
        assert!(err.to_string().contains("位点不一致"));
    }

    /// P1（DA 凭证伪造）修复：签名者成员资格校验（v1 + v2 双变体）。
    ///
    /// 攻击场景：攻击者自造 quorum(n)=5 把全新非成员 BLS 键对某 digest 签
    /// 回执（每份签名密码学合法、聚合签名正确）——修复前 form/verify 只做
    /// possession + 计数，伪造凭证通过；修复后必须拒。成员键正例对照通过。
    #[test]
    fn da_certificate_membership_rejects_forged_non_member_signers() {
        let digest = [0xD5u8; 32];
        // 委员会（允许注册表）：7 把成员键 0x60..=0x66
        let allowed = allowed_from_seeds(&[0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]);

        // ---- v1 ----
        // (a) 非成员键的合法回执聚合 → form 拒
        let forged = receipts_for(digest, &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4]);
        let err = DaCertificate::form_from_receipts(&forged, &allowed, 7).unwrap_err();
        assert!(
            err.to_string().contains("非成员"),
            "v1 非成员回执必须被拒: {err:?}"
        );
        // (a') 手工构造的非成员凭证（自声明公钥 + 正确聚合签名）→ verify_against_signers 拒
        let member_receipts = receipts_for(digest, &[0x60, 0x61, 0x62, 0x63, 0x64]);
        let cert = DaCertificate::form_from_receipts(&member_receipts, &allowed, 7).unwrap();
        let mut forged_cert = cert.clone();
        // 用非成员键重签同位点并手工聚合（绕过 form 的成员检查）
        let sigs: Vec<[u8; 48]> = forged
            .iter()
            .map(|r| {
                let mut arr = [0u8; 48];
                arr.copy_from_slice(&r.signature_g1);
                arr
            })
            .collect();
        let pks: Vec<[u8; 96]> = forged
            .iter()
            .map(|r| {
                let mut arr = [0u8; 96];
                arr.copy_from_slice(&r.signer_pubkey_g2);
                arr
            })
            .collect();
        forged_cert.agg_signature_g1 =
            crate::consensus::checkpoint::bls_aggregate_g1(&sigs).unwrap().to_vec();
        forged_cert.signer_pubkeys_g2 = pks.iter().map(|p| p.to_vec()).collect();
        assert!(
            forged_cert.verify(7).is_ok(),
            "测试前提：伪造 v1 聚合签名本身密码学合法（旧口径会放过）"
        );
        let err2 = forged_cert.verify_against_signers(&allowed, 7).unwrap_err();
        assert!(err2.to_string().contains("非成员"), "v1 伪造凭证必须拒: {err2:?}");
        // (b) 成员键 → 通过
        cert.verify_against_signers(&allowed, 7)
            .expect("v1 成员凭证必须通过");
        // (d) 空注册表 → fail-closed
        assert!(cert.verify_against_signers(&allowed_from_seeds(&[]), 7).is_err());

        // ---- v2 ----
        // (a) 非成员键 v2 回执聚合 → form 拒
        let forged_v2 = v2_receipts(digest, DaObjectKind::Blob, &[0xF0, 0xF1, 0xF2, 0xF3, 0xF4]);
        let err3 = DaCertificateV2::form_from_receipts(&forged_v2, &allowed, 7).unwrap_err();
        assert!(err3.to_string().contains("非成员"), "v2 非成员回执必须被拒: {err3:?}");
        // (b) 成员键 v2 → form + verify_against_signers 通过
        let cert_v2 = DaCertificateV2::form_from_receipts(
            &v2_receipts(digest, DaObjectKind::Blob, &[0x60, 0x61, 0x62, 0x63, 0x64]),
            &allowed,
            7,
        )
        .expect("v2 成员凭证必须成立");
        cert_v2.verify_against_signers(&allowed, 7).unwrap();
        // (d) 空注册表 → fail-closed
        assert!(cert_v2.verify_against_signers(&allowed_from_seeds(&[]), 7).is_err());
    }

    /// 挑战-应答闭环：持有方应答任意挑战成功；丢数据方（错块/假块）失败。
    #[test]
    fn da_challenge_response_roundtrip_and_negatives() {
        // blob 分块（3 块）+ chunk root（发布侧与 digest 一起公布）
        let blob: Vec<u8> = (0..100u8).collect();
        let chunk_size = 40;
        let leaf_digests = blob_chunk_digests(&blob, chunk_size);
        assert_eq!(leaf_digests.len(), 3);
        let root = chunk_merkle_root(&leaf_digests);
        // 凭证（v2 域，digest 位即承诺位）
        let cert = DaCertificateV2::form_from_receipts(
            &v2_receipts(root, DaObjectKind::Blob, &[0x50, 0x51, 0x52, 0x53, 0x54]),
            &allowed_from_seeds(&[0x50, 0x51, 0x52, 0x53, 0x54]),
            7,
        )
        .unwrap();
        // 验证方（不持有 blob）从凭证派生挑战块号；持有方应答
        for nonce in 0..6u64 {
            let idx = challenge_chunk_index(leaf_digests.len(), &cert.signing_hash(), nonce);
            let proof = chunk_merkle_proof(&leaf_digests, idx);
            assert!(
                verify_chunk_inclusion(&root, &leaf_digests[idx], idx, &proof),
                "合法应答必须通过（nonce={nonce}）"
            );
        }
        // 丢数据方：应答错误块内容 → 块哈希失配
        let nonce = 0u64;
        let idx = challenge_chunk_index(leaf_digests.len(), &cert.signing_hash(), nonce);
        let proof = chunk_merkle_proof(&leaf_digests, idx);
        let fake_chunk_digest = blob_chunk_digests(&[0xFF; 40], chunk_size)[0];
        assert!(!verify_chunk_inclusion(&root, &fake_chunk_digest, idx, &proof));
        // 错位应答（真块 + 错索引）→ 路径验证失败
        let other = (idx + 1) % leaf_digests.len();
        assert!(!verify_chunk_inclusion(&root, &leaf_digests[other], idx, &proof));
        // 篡改路径任一节点 → 失败
        let mut tampered = proof.clone();
        tampered[0][0] ^= 0x01;
        assert!(!verify_chunk_inclusion(&root, &leaf_digests[idx], idx, &tampered));
    }

    /// 挑战派生确定性：同 (cert, nonce) 同号；换 nonce 换号（高概率）；
    /// 对象类型判别值冻结。
    #[test]
    fn da_challenge_derivation_deterministic() {
        let cert_hash = da_signing_hash_v2(DaObjectKind::Batch, 1, 42, [0xD4u8; 32]);
        assert_eq!(
            challenge_chunk_index(7, &cert_hash, 3),
            challenge_chunk_index(7, &cert_hash, 3)
        );
        assert!(matches!(DaObjectKind::from_u8(1), Ok(DaObjectKind::Batch)));
        assert!(matches!(DaObjectKind::from_u8(2), Ok(DaObjectKind::Blob)));
        assert!(DaObjectKind::from_u8(3).is_err());
        assert_eq!(DaObjectKind::Batch.as_u8(), 1);
    }

}
