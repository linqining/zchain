//! 检查点与归档（缺口 #9：Checkpoint & Archive）。
//!
//! 周期性生成不可逆检查点（finality gadget 保证），使新节点可从最近检查点
//! 而非 genesis 开始 Fast Sync；pruned 节点仅保留检查点之后的完整状态。
//!
//! # 检查点结构
//!
//! 检查点包含：`height` + `block_hash` + `state_root` + 2/3+ validator 签名。
//! 一旦 2/3+ validator 签名背书，该 height 之前的所有区块不可逆转（finalized）。
//!
//! # v1.5：BLS 聚合 QC（plan §2-c，原型口径）
//!
//! 本模块同时提供两层 checkpoint 机制：
//!
//! 1. [`CheckpointCertificate`]（既有，secp256k1 逐签名多签）；
//! 2. [`CheckpointQc`]（v1.5 新增）：**BLS12-381 聚合签 QC（2f+1 聚签，
//!    aggregate signatures）** —— 每个 validator 对 checkpoint 签名对象发布
//!    一个 G1 点签名（48B），收集方把 ≥2f+1 个签名点加总为一个聚合签名
//!    （仍 48B），用签名者公钥（G2 点）之和做一次配对验证。
//!
//! ## 命名与边界（如实：这是聚合签名，不是阈值签名）
//!
//! - 本实现是 **n-of-n / 2f+1 子集的线性聚合**：每位签名者持有完整私钥并
//!   发布完整签名；聚合只是 G1 点加法。
//! - **不是**阈值 BLS（t-of-n）：没有 DKG 密钥分片，没有 Lagrange 插值，
//!   单个签名者泄露即泄露完整密钥，聚合签名无法证明"恰好 t 人参与"
//!   （聚合 QC 的参与人数由显式 `signer_pubkeys_g2` 列表与 2f+1 计数约束）。
//! - **rogue-key 防护**：聚合前逐签名验证（[`CheckpointVote::verify`]，
//!   possession 证明）+ 签名者必须属于本地 validator 集；因此"伪造公钥
//!   抵消他人密钥"的 rogue-key 攻击在收集端被阻断。
//!
//! ## v1.5-e：阈值 QC 形态（真 t-of-n，additive；与聚合 QC 并存，零回退）
//!
//! [`CheckpointQc`] 现支持两种形态（additive 字段 [`CheckpointQc::threshold`]，
//! 聚合形态的字段与 JSON 格式不变）：
//!
//! 1. **聚合形态**（现状，`threshold == None`）：如上，2f+1 逐票聚签；
//! 2. **阈值形态**（`threshold == Some`）：密钥来自
//!    [`crate::consensus::dkg`]（deal-sum DKG 原型，无投诉轮——坏 dealer
//!    可被 Feldman 校验定位但重发机制属后续）。每位签名者只持群份额
//!    `x_i`（群私钥从不以明文存在），发布份额签名 `σ_i = x_i·H(m)`；
//!    收集 ≥t 个通过逐份配对校验的部分签名后，以 Lagrange 系数（at 0，
//!    见 [`crate::consensus::dkg::lagrange_coefficients_at_zero`]）为权重
//!    经 [`bls_aggregate_g1_weighted`]（v1.5 预留接入点）重构群签名
//!    `σ = s·H(m)`，验证端**单配对** `e(σ, G2gen) == e(H(m), Q)`（成本
//!    与参与人数无关；聚合形态的等价保证需 n 次逐票配对 + 1 次聚合
//!    配对）。QC ↔ keyset 绑定经 `group_key_digest`（内容摘要，不匹配
//!    即拒）。阈值形态的收集/签名分派在节点层：**无 GroupKeyset 的节点
//!    走聚合模式（零回退）**。
//!
//! ## 与 HotStuff-2 / Jolteon 的差距（如实）
//!
//! 本原型只是 **checkpoint QC 层**：周期性对已 commit 高度聚合 2f+1 背书并
//! 落盘/供 RPC 查询 + fork-anchor 滞后告警。它**不是**完整的 Jolteon/
//! HotStuff-2 流水线：没有 per-view 投票/超时轮换、没有 chain-QC 链式
//! 选举（commit QC 引用 prev QC）、没有 pacemaker。commit 安全性仍由
//! DAG Bullshark commit certificate 承担；checkpoint QC（聚合或阈值形态）
//! 是其上的检查点锚定层（轻客户端/快速同步/fork 检测消费），不改变
//! commit 语义。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::Hash;
use crate::consensus::Epoch;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;

/// 检查点生成间隔（每 10,000 区块生成一个检查点）。
pub const CHECKPOINT_INTERVAL: u64 = 10_000;

/// 检查点证书（缺口 #9）。
///
/// 由 ≥2/3 validator 签名背书的不可逆转检查点。一旦形成，该 height 之前的
/// 所有区块被视为 finalized，pruned 节点可安全丢弃更早的数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CheckpointCertificate {
    /// 检查点对应的区块高度。
    pub height: BlockHeight,
    /// 该高度的 block_hash。
    pub block_hash: Hash,
    /// 该高度的 state_root。
    pub state_root: Hash,
    /// 当前 epoch。
    pub epoch: Epoch,
    /// 参与签名的 validator pubkeys。
    pub signer_pubkeys: Vec<TaggedPubkey>,
    /// 对应的 secp256k1 签名列表。
    pub signatures: Vec<Vec<u8>>,
}

impl CheckpointCertificate {
    /// 计算检查点的签名对象哈希（所有 validator 对此哈希签名）。
    ///
    /// `blake2b_256(CHECKPOINT_DOMAIN || height || block_hash || state_root || epoch)`
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        use blake2::Blake2bVar;
        use blake2::digest::{Update, VariableOutput};
        const CHECKPOINT_DOMAIN: u8 = 0x43; // 'C' for Checkpoint
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[CHECKPOINT_DOMAIN]);
        h.update(&self.height.to_le_bytes());
        h.update(&self.block_hash);
        h.update(&self.state_root);
        h.update(&self.epoch.to_le_bytes());
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 签名者数量。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signatures.len()
    }

    /// 校验检查点证书（缺口 #9）。
    ///
    /// 校验项：
    /// 1. signer_pubkeys 与 signatures 长度一致
    /// 2. 签名者数量 ≥ required_quorum（2/3）
    /// 3. 每个签名对 `signing_hash` 有效（pubkey 验证）
    /// 4. 无重复签名者
    pub fn validate(&self, validator_count: usize) -> PokerL1Result<()> {
        // 1. 长度一致
        if self.signer_pubkeys.len() != self.signatures.len() {
            return Err(PokerL1Error::Other(format!(
                "checkpoint: signer_pubkeys len {} != signatures len {}",
                self.signer_pubkeys.len(),
                self.signatures.len()
            )));
        }
        // 2. quorum
        let required = crate::consensus::required_quorum(validator_count);
        if self.signer_count() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_count(),
                required,
            });
        }
        // 3 + 4. 逐签名验证 + 去重
        let msg_hash = self.signing_hash();
        let mut seen = std::collections::BTreeSet::new();
        for (pk, sig) in self.signer_pubkeys.iter().zip(self.signatures.iter()) {
            let pk_bytes = pk.to_bytes();
            if !seen.insert(pk_bytes.clone()) {
                return Err(PokerL1Error::Other(format!(
                    "checkpoint: duplicate signer {:?}",
                    pk
                )));
            }
            verify_signature(pk, sig, &msg_hash).map_err(|_| {
                PokerL1Error::Other("checkpoint: signature verification failed".to_string())
            })?;
        }
        Ok(())
    }
}

/// 判断给定高度是否应生成检查点（每 CHECKPOINT_INTERVAL 区块一次）。
#[must_use]
pub fn should_create_checkpoint(height: BlockHeight) -> bool {
    height > 0 && height % CHECKPOINT_INTERVAL == 0
}

/// 构造检查点证书的签名对象（供 validator 签名）。
///
/// 返回 `signing_hash`，validator 用 secp256k1 对此哈希签名后填入 `CheckpointCertificate.signatures`。
#[must_use]
pub fn checkpoint_signing_hash(
    height: BlockHeight,
    block_hash: Hash,
    state_root: Hash,
    epoch: Epoch,
) -> Hash {
    let cert = CheckpointCertificate {
        height,
        block_hash,
        state_root,
        epoch,
        signer_pubkeys: vec![],
        signatures: vec![],
    };
    cert.signing_hash()
}

// ===== v1.5：BLS12-381 聚合 QC（plan §2-c 原型） =====
//
// 命名纪律（见模块头）：以下全部是**聚合签名**（linear aggregation），
// 不是阈值签名（threshold BLS）。阈值接入点见 `bls_aggregate_g1_weighted`。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use blstrs::{Bls12, G1Projective, G2Projective, G2Prepared, Scalar};
use group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use subtle::CtOption;

/// Checkpoint QC 签名域分隔前缀（'Q' for QC；与 commit cert 的 0x43 区分）。
const CHECKPOINT_QC_DOMAIN: u8 = 0x51;

/// checkpoint 间隔的 v1.5 运行期默认值（块数；可经 `--checkpoint-interval` 覆盖）。
///
/// 注意：既有 [`CHECKPOINT_INTERVAL`]（10_000）是**审查检测窗口**的推导基准
/// （`DEFAULT_CENSORSHIP_WINDOW_BLOCKS = 2 * CHECKPOINT_INTERVAL`），语义不同，
/// 不随本值改变。
pub const DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 32;

/// fork-anchor 告警默认滞后阈值（commit tip 落后最后 QC checkpoint 超过
/// `2 * checkpoint_interval` 个高度 → 告警）。
pub const DEFAULT_FORK_ANCHOR_MAX_LAG_BLOCKS: u64 = 2 * DEFAULT_CHECKPOINT_INTERVAL_BLOCKS;

fn ct_opt_to_opt<T>(ct: CtOption<T>) -> Option<T> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// 解析 G1 compressed 点（48B；子群检查 fail-closed）。
///
/// # Errors
/// 长度非 48B，或非曲线点/未过子群检查。
pub fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective> {
    if bytes.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "checkpoint QC G1 compressed size mismatch: {} != {}",
            bytes.len(),
            crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
        )));
    }
    let mut arr = [0u8; crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(G1Projective::from_compressed(&arr)).ok_or(PokerL1Error::InvalidSubgroup(
        "checkpoint QC G1 point failed subgroup check or not on curve",
    ))
}

/// 解析 G2 compressed 点（96B；子群检查 fail-closed）。
///
/// # Errors
/// 长度非 96B，或非曲线点/未过子群检查。
pub fn parse_g2(bytes: &[u8]) -> PokerL1Result<G2Projective> {
    if bytes.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "checkpoint QC G2 compressed size mismatch: {} != {}",
            bytes.len(),
            crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
        )));
    }
    let mut arr = [0u8; crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(G2Projective::from_compressed(&arr)).ok_or(PokerL1Error::InvalidSubgroup(
        "checkpoint QC G2 point failed subgroup check or not on curve",
    ))
}

fn parse_scalar(bytes: &[u8]) -> PokerL1Result<Scalar> {
    if bytes.len() != crate::crypto_precompiles::bls::SCALAR_SIZE {
        return Err(PokerL1Error::InvalidBlsScalar(format!(
            "checkpoint QC scalar size mismatch: {} != {}",
            bytes.len(),
            crate::crypto_precompiles::bls::SCALAR_SIZE
        )));
    }
    let mut arr = [0u8; crate::crypto_precompiles::bls::SCALAR_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(Scalar::from_bytes_be(&arr))
        .ok_or_else(|| PokerL1Error::InvalidBlsScalar("scalar reduction failed".to_string()))
}

/// BLS 私钥（32 字节大端 Scalar）。v1.5 由 validator secp 私钥经域分隔哈希
/// 确定性派生（[`bls_derive_secret_key`]），零新密钥管理面；生产阈值方案
/// 应替换为 DKG 分片（见模块头阈值接入点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsSecretKey(#[serde(with = "base64_bytes")] pub [u8; 32]);

mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = Vec::<u8>::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("bls secret key must be 32 bytes"))
    }
}

/// 从任意 32 字节种子（validator secp 私钥字节）确定性派生 BLS 私钥。
///
/// `sk = blake2b_256("ZCHAIN_BLS_KEY_V1" || seed)`，域分隔防与其它密钥用途
/// 混淆。**边界（如实）**：派生意味着 secp 私钥泄露即 BLS 私钥泄露（无独立
/// HSM/分片保护）——这是 v1.5 原型口径，生产应独立生成或 DKG。
#[must_use]
pub fn bls_derive_secret_key(seed: &[u8; 32]) -> BlsSecretKey {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(b"ZCHAIN_BLS_KEY_V1");
    h.update(seed);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    // Scalar::from_bytes_be 对 >= r 的值返回 None（非规范），需重派生：
    // 用计数器后缀重哈希，循环期望次数 ~1（r ≈ 2^255）。
    let mut counter = 0u8;
    loop {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(b"ZCHAIN_BLS_KEY_REDUCE");
        h.update(&out);
        h.update(&[counter]);
        let mut cand = [0u8; 32];
        h.finalize_variable(&mut cand).expect("32 <= 64");
        if Scalar::from_bytes_be(&cand).is_some().into() {
            return BlsSecretKey(cand);
        }
        counter = counter.wrapping_add(1);
    }
}

impl BlsSecretKey {
    /// 对应 G2 公钥（96 字节 compressed）。
    #[must_use]
    pub fn pubkey_g2(&self) -> [u8; crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE] {
        let sk = parse_scalar(&self.0).expect("BlsSecretKey invariant: canonical scalar");
        let pk = G2Projective::generator() * sk;
        pk.to_compressed()
    }

    /// 对 32 字节消息哈希签名（G1 点，48 字节 compressed）。
    ///
    /// `sig = sk * H(msg, BLS_G1_DST)`（hash-to-curve 沿用 crypto_precompiles
    /// 的固定 DST，RFC 9380 SSWU-RO）。
    pub fn sign(
        &self,
        msg_hash: &Hash,
    ) -> PokerL1Result<[u8; crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE]> {
        let sk = parse_scalar(&self.0)?;
        let h_m = parse_g1(&crate::crypto_precompiles::bls::bls_hash_to_g1(msg_hash)?)?;
        let sig = h_m * sk;
        Ok(sig.to_compressed())
    }
}

/// 验证单枚 BLS 签名：`e(sig, G2gen) == e(H(m), pk)`。
pub fn bls_verify_single(
    pubkey_g2: &[u8],
    sig_g1: &[u8],
    msg_hash: &Hash,
) -> PokerL1Result<bool> {
    let pk = parse_g2(pubkey_g2)?;
    let sig = parse_g1(sig_g1)?;
    let h_m = parse_g1(&crate::crypto_precompiles::bls::bls_hash_to_g1(msg_hash)?)?;
    let g2 = G2Projective::generator();
    // e(sig, g2) * e(-h_m, pk) == identity  <=>  e(sig, g2) == e(h_m, pk)
    let ml = Bls12::multi_miller_loop(&[
        (&sig.to_affine(), &G2Prepared::from(g2.to_affine())),
        (&(-h_m).to_affine(), &G2Prepared::from(pk.to_affine())),
    ]);
    Ok(bool::from(ml.final_exponentiation().is_identity()))
}

/// G1 点聚合（点加法；**聚合签名核心**）。恒等点（全零/未签名占位）跳过；
/// 全部为恒等点时返回 Err（防 e(O,·) 恒等伪造，H3 同款防御）。
pub fn bls_aggregate_g1(sigs: &[[u8; 48]]) -> PokerL1Result<[u8; 48]> {
    let mut acc = G1Projective::identity();
    for bytes in sigs {
        let p = parse_g1(bytes)?;
        if !bool::from(p.is_identity()) {
            acc += p;
        }
    }
    if bool::from(acc.is_identity()) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "checkpoint QC: aggregate signature is identity (no valid contributor)".into(),
        ));
    }
    Ok(acc.to_compressed())
}

/// G2 公钥聚合（点加法）。全部为恒等点时返回 Err。
pub fn bls_aggregate_g2(pks: &[[u8; 96]]) -> PokerL1Result<[u8; 96]> {
    let mut acc = G2Projective::identity();
    for bytes in pks {
        let p = parse_g2(bytes)?;
        if !bool::from(p.is_identity()) {
            acc += p;
        }
    }
    if bool::from(acc.is_identity()) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "checkpoint QC: aggregate pubkey is identity (no valid contributor)".into(),
        ));
    }
    Ok(acc.to_compressed())
}

/// 权重聚合（线性组合 `sum(w_i * p_i)`）——**阈值 BLS 预留接入点**。
///
/// 权重为 32 字节大端域元素。v1.5 聚合 QC 不使用本函数（等权聚合 =
/// `bls_aggregate_g1`）；DKG 引入后，把 Lagrange 系数（域元素）作为权重传入
/// 即可升级为 t-of-n 阈值聚合，验证端公式不变。
pub fn bls_aggregate_g1_weighted(
    points: &[[u8; 48]],
    weights: &[[u8; 32]],
) -> PokerL1Result<[u8; 48]> {
    if points.len() != weights.len() || points.is_empty() {
        return Err(PokerL1Error::InvalidSyscallArgument(format!(
            "weighted aggregate length mismatch: points={}, weights={}",
            points.len(),
            weights.len()
        )));
    }
    let mut acc = G1Projective::identity();
    for (bytes, w) in points.iter().zip(weights.iter()) {
        let p = parse_g1(bytes)?;
        let s = parse_scalar(w)?;
        acc += p * s;
    }
    if bool::from(acc.is_identity()) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "checkpoint QC: weighted aggregate is identity".into(),
        ));
    }
    Ok(acc.to_compressed())
}

/// 同消息聚合验证：`e(agg_sig, G2gen) == e(H(m), agg_pk)`。
///
/// 这是 2f+1 聚合 QC 的验证核心（全部签名者对同一 checkpoint 签名对象签名）。
pub fn bls_verify_aggregate_same_msg(
    agg_sig_g1: &[u8],
    agg_pk_g2: &[u8],
    msg_hash: &Hash,
) -> PokerL1Result<bool> {
    let agg_sig = parse_g1(agg_sig_g1)?;
    let agg_pk = parse_g2(agg_pk_g2)?;
    let h_m = parse_g1(&crate::crypto_precompiles::bls::bls_hash_to_g1(msg_hash)?)?;
    let g2 = G2Projective::generator();
    let ml = Bls12::multi_miller_loop(&[
        (&agg_sig.to_affine(), &G2Prepared::from(g2.to_affine())),
        (&(-h_m).to_affine(), &G2Prepared::from(agg_pk.to_affine())),
    ]);
    Ok(bool::from(ml.final_exponentiation().is_identity()))
}

/// checkpoint QC 签名对象：`blake2b_256(0x51 || epoch || height || state_root)`。
///
/// v1.5 的 checkpoint 锚定 commit 高度（state_root 即该高度 block 的
/// state_root；批根摘要语义复用同一字段 —— 原型口径单一摘要位）。
#[must_use]
pub fn checkpoint_qc_signing_hash(epoch: Epoch, height: BlockHeight, state_root: Hash) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[CHECKPOINT_QC_DOMAIN]);
    h.update(&epoch.to_le_bytes());
    h.update(&height.to_le_bytes());
    h.update(&state_root);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 判断给定高度是否应产出 checkpoint（运行期可配间隔，`height % interval == 0`）。
#[must_use]
pub const fn should_create_checkpoint_at(height: BlockHeight, interval_blocks: u64) -> bool {
    interval_blocks > 0 && height > 0 && height % interval_blocks == 0
}

/// 单个 validator 的 checkpoint 投票（P2P gossip 载荷 / 收集端输入）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CheckpointVote {
    /// epoch。
    pub epoch: Epoch,
    /// 被 checkpoint 锚定的 commit 高度。
    pub height: BlockHeight,
    /// 该高度的 state_root（签名对象第三分量）。
    pub state_root: Hash,
    /// 签名对象（收集端一致性校验用；= `checkpoint_qc_signing_hash(..)`）。
    pub signing_hash: Hash,
    /// 签名者 BLS 公钥（G2 compressed 96B）。
    pub signer_pubkey_g2: Vec<u8>,
    /// BLS 签名（G1 compressed 48B）。
    pub signature_g1: Vec<u8>,
}

impl CheckpointVote {
    /// 签名一条 checkpoint 投票。
    pub fn sign(
        epoch: Epoch,
        height: BlockHeight,
        state_root: Hash,
        sk: &BlsSecretKey,
    ) -> PokerL1Result<Self> {
        let signing_hash = checkpoint_qc_signing_hash(epoch, height, state_root);
        let signature_g1 = sk.sign(&signing_hash)?;
        Ok(Self {
            epoch,
            height,
            state_root,
            signing_hash,
            signer_pubkey_g2: sk.pubkey_g2().to_vec(),
            signature_g1: signature_g1.to_vec(),
        })
    }

    /// 验证投票：签名对象一致性 + secp→BLS 域外的独立密码学验证（配对）。
    pub fn verify(&self) -> PokerL1Result<()> {
        if self.signer_pubkey_g2.len() != crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "checkpoint vote pubkey size {} != {}",
                self.signer_pubkey_g2.len(),
                crate::crypto_precompiles::bls::G2_COMPRESSED_SIZE
            )));
        }
        if self.signature_g1.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "checkpoint vote signature size {} != {}",
                self.signature_g1.len(),
                crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
            )));
        }
        let expected = checkpoint_qc_signing_hash(self.epoch, self.height, self.state_root);
        if expected != self.signing_hash {
            return Err(PokerL1Error::Other(
                "checkpoint vote signing_hash 与 (epoch, height, state_root) 不一致".into(),
            ));
        }
        let ok = bls_verify_single(&self.signer_pubkey_g2, &self.signature_g1, &self.signing_hash)?;
        if !ok {
            return Err(PokerL1Error::Other(
                "checkpoint vote BLS signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// BLS 聚合 QC（v1.5 原型：**2f+1 聚签**，聚合签名 —— 非阈值，见模块头）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CheckpointQc {
    /// epoch。
    pub epoch: Epoch,
    /// 被 checkpoint 锚定的 commit 高度。
    pub height: BlockHeight,
    /// 该高度 state_root（批根摘要位，原型口径单摘要）。
    pub state_root: Hash,
    /// 发起（首个被收集投票的）validator 的 BLS 公钥。
    pub proposer_g2: Vec<u8>,
    /// 聚合签名（G1 compressed 48B = 签名者 G1 签名点之和）。
    pub agg_signature_g1: Vec<u8>,
    /// 参与签名者的 BLS 公钥集合（G2 compressed，顺序即聚合顺序）。
    pub signer_pubkeys_g2: Vec<Vec<u8>>,
    /// v1.5-e additive：阈值形态载荷（真 t-of-n，见模块头与 [`ThresholdQc`]）。
    ///
    /// `None` = 聚合形态（既有字段与本结构的 JSON 输出完全不变：
    /// `skip_serializing_if` + `serde(default)` 保证旧 JSON 可解析）。
    /// `Some` = 阈值形态（此时聚合形态三字段为空——阈值签名者只持群份额，
    /// 无法产出完整签名的聚合；聚合形态验证路径对空集 fail-closed 拒）。
    /// borsh 面为尾部追加（与 `DagVertex::forced_tx_hashes` 同款 additive
    /// 约定：旧 payload 不可解析，属版本升级一次性切换）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ThresholdQc>,
}

impl CheckpointQc {
    /// 由投票集合聚合形成 QC。
    ///
    /// - 逐票验证（签名对象一致 + 单签名配对验证 —— rogue-key 防护点）；
    /// - 签名者去重（同公钥重复投票只计一次）；
    /// - 数量 ≥ `required_quorum(validator_count)`（2f+1）才成 QC。
    pub fn form_from_votes(
        votes: &[CheckpointVote],
        validator_count: usize,
    ) -> PokerL1Result<Self> {
        let Some(first) = votes.first() else {
            return Err(PokerL1Error::Other("checkpoint QC: 无投票".into()));
        };
        let (epoch, height, state_root, signing_hash) =
            (first.epoch, first.height, first.state_root, first.signing_hash);
        let mut pks: Vec<Vec<u8>> = Vec::new();
        let mut sigs: Vec<[u8; 48]> = Vec::new();
        for vote in votes {
            if vote.epoch != epoch || vote.height != height || vote.state_root != state_root {
                return Err(PokerL1Error::Other(
                    "checkpoint QC: 投票位点不一致（异构投票拒绝）".into(),
                ));
            }
            vote.verify()?;
            if pks.iter().any(|pk| *pk == vote.signer_pubkey_g2) {
                continue; // 去重：同签名者重复投票不重复计入聚合
            }
            let mut sig = [0u8; 48];
            sig.copy_from_slice(&vote.signature_g1);
            sigs.push(sig);
            pks.push(vote.signer_pubkey_g2.clone());
        }
        let required = crate::consensus::required_quorum(validator_count);
        if pks.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: pks.len(),
                required,
            });
        }
        let agg_signature_g1 = bls_aggregate_g1(&sigs)?;
        let agg_pk = bls_aggregate_g2(
            &pks.iter()
                .map(|pk| {
                    let mut arr = [0u8; 96];
                    arr.copy_from_slice(pk);
                    arr
                })
                .collect::<Vec<_>>(),
        )?;
        let ok = bls_verify_aggregate_same_msg(&agg_signature_g1, &agg_pk, &signing_hash)?;
        if !ok {
            return Err(PokerL1Error::Other(
                "checkpoint QC: 聚合签名验证失败".into(),
            ));
        }
        Ok(Self {
            epoch,
            height,
            state_root,
            proposer_g2: first.signer_pubkey_g2.clone(),
            agg_signature_g1: agg_signature_g1.to_vec(),
            signer_pubkeys_g2: pks,
            threshold: None,
        })
    }

    /// 验证 QC：聚合签名配对验证 + 2f+1 计数 + 签名者去重。
    pub fn verify(&self, validator_count: usize) -> PokerL1Result<()> {
        if self.signer_pubkeys_g2.is_empty() {
            return Err(PokerL1Error::Other("checkpoint QC: 签名者为空".into()));
        }
        let mut seen = std::collections::BTreeSet::new();
        for pk in &self.signer_pubkeys_g2 {
            if !seen.insert(pk.clone()) {
                return Err(PokerL1Error::Other("checkpoint QC: 重复签名者".into()));
            }
        }
        let required = crate::consensus::required_quorum(validator_count);
        if self.signer_pubkeys_g2.len() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_pubkeys_g2.len(),
                required,
            });
        }
        let signing_hash = checkpoint_qc_signing_hash(self.epoch, self.height, self.state_root);
        let agg_pk = bls_aggregate_g2(
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
        let ok =
            bls_verify_aggregate_same_msg(&self.agg_signature_g1, &agg_pk, &signing_hash)?;
        if !ok {
            return Err(PokerL1Error::Other(
                "checkpoint QC: 聚合签名验证失败".into(),
            ));
        }
        Ok(())
    }

    /// 签名者数量（形态感知：聚合形态 = 签名者公钥数；阈值形态 = signer
    /// bitmap 置位数）。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        match &self.threshold {
            Some(tqc) => tqc.signer_count(),
            None => self.signer_pubkeys_g2.len(),
        }
    }
}

// ===== v1.5-e：阈值 QC 形态（真 t-of-n，additive；密钥来自 consensus::dkg） =====
//
// 命名纪律（见模块头）：以下是**阈值签名**（threshold BLS）——每位签名者
// 只持 Shamir 群份额 `x_i`，任意 t 个份额签名经 Lagrange 系数加权聚合
// 恰等价于群签名 `σ = s·H(m)`；验证端单配对、成本与参与人数无关。
// 聚合接入点即 `bls_aggregate_g1_weighted`（权重 = Lagrange 系数 at 0，
// 见 `crate::consensus::dkg::lagrange_coefficients_at_zero`）。

use crate::consensus::dkg::GroupKeyset;

/// 阈值 QC 部分份额签名载荷（P2P gossip / 收集端输入形态）。
///
/// `σ_i = x_i·H(m)`，`H(m) = checkpoint_qc_signing_hash(epoch, height, state_root)`
/// ——与聚合 QC 同一签名对象（同一 checkpoint 位点可被两种形态背书）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ThresholdQcPartial {
    /// epoch。
    pub epoch: Epoch,
    /// 被 checkpoint 锚定的 commit 高度。
    pub height: BlockHeight,
    /// 该高度的 state_root。
    pub state_root: Hash,
    /// 参与者分片 id（1..=n；多项式求值点，见 `dkg::GroupKeyset`）。
    pub participant_id: u64,
    /// 份额签名（G1 compressed 48B）。
    pub sig_g1: Vec<u8>,
}

impl ThresholdQcPartial {
    /// 签名对象哈希（与聚合 QC 同域）。
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        checkpoint_qc_signing_hash(self.epoch, self.height, self.state_root)
    }

    /// 验证份额签名：对 `keyset.public_share(participant_id)` 做单签名配对
    /// 验证（逐份校验 —— 坏份额/伪造在聚合前拒，fail-closed）。
    ///
    /// # Errors
    /// id 越界（不在 1..=n）、签名尺寸非法、点非法或配对验证失败。
    pub fn verify(&self, keyset: &GroupKeyset) -> PokerL1Result<()> {
        if self.sig_g1.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "threshold QC partial signature size {} != {}",
                self.sig_g1.len(),
                crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
            )));
        }
        let pk_i = keyset.public_share(self.participant_id)?;
        let ok = bls_verify_single(&pk_i, &self.sig_g1, &self.signing_hash())?;
        if !ok {
            return Err(PokerL1Error::Other(format!(
                "threshold QC partial signature from participant {} failed verification",
                self.participant_id
            )));
        }
        Ok(())
    }
}

/// 阈值 QC 形态载荷（[`CheckpointQc::threshold`] 的 additive 字段值）。
///
/// 验证只依赖组公钥（单配对）；`signer_bitmap` 承担审计/计数职责，不参与
/// 密码学验证（与聚合形态的"公钥之和"验证相区分——阈值方案核心优势）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ThresholdQc {
    /// 群签名 `σ = s·H(m)`（G1 compressed 48B；Lagrange 加权重构结果）。
    pub sig_g1: Vec<u8>,
    /// 签名者 bitmap：bit `(id-1)` 置位表示分片 id 参与签名（popcount ≥ t）。
    pub signer_bitmap: Vec<u8>,
    /// 密钥集内容摘要（`dkg::GroupKeyset::group_key_digest`）——QC ↔ keyset
    /// 绑定位：验证端以本地 keyset 重算比对，不匹配即拒（防 QC 被挪到另一群）。
    pub group_key_digest: Hash,
    /// 签名/重建阈值 t（必须与绑定 keyset 的 t 一致）。
    pub t: u32,
}

impl ThresholdQc {
    /// bitmap 长度（字节）：`ceil(n/8)`。
    fn bitmap_len(n: u32) -> usize {
        (n as usize).div_ceil(8)
    }

    /// 由已验证的部分份额签名装配阈值 QC 形态（收集端核心）。
    ///
    /// 准入（全 fail-closed）：
    /// 1. 位点一致性（分片 id 越界/位点异构 → 拒）；
    /// 2. **逐份额签名验证**（单配对，坏份额在聚合前拒）；
    /// 3. 同分片重复提交去重（只计一次）；
    /// 4. 数量 ≥ `keyset.t` 才成 QC（`InsufficientQuorum`）；
    /// 5. Lagrange 系数（at 0）加权聚合 —— `bls_aggregate_g1_weighted`；
    /// 6. 聚合结果对组公钥终验（防御纵深：装配式错误在成型即拦截）。
    ///
    /// # Errors
    /// 任一份额验证失败、份额不足 t、位点异构、聚合/验证原语错误。
    pub fn assemble(
        partials: &[ThresholdQcPartial],
        keyset: &GroupKeyset,
        epoch: Epoch,
        height: BlockHeight,
        state_root: Hash,
    ) -> PokerL1Result<Self> {
        let msg = checkpoint_qc_signing_hash(epoch, height, state_root);
        let mut seen = std::collections::BTreeSet::new();
        let mut ids: Vec<u64> = Vec::new();
        let mut sigs: Vec<[u8; 48]> = Vec::new();
        for p in partials {
            if p.epoch != epoch || p.height != height || p.state_root != state_root {
                return Err(PokerL1Error::Other(
                    "threshold QC: partial 位点不一致（异构份额拒绝）".into(),
                ));
            }
            if !seen.insert(p.participant_id) {
                continue; // 同分片重复提交不重复计入
            }
            p.verify(keyset)?;
            let mut sig = [0u8; 48];
            sig.copy_from_slice(&p.sig_g1);
            ids.push(p.participant_id);
            sigs.push(sig);
        }
        if ids.len() < keyset.t as usize {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: ids.len(),
                required: keyset.t as usize,
            });
        }
        let lambdas = crate::consensus::dkg::lagrange_coefficients_at_zero(&ids)?;
        let weights: Vec<[u8; 32]> = lambdas
            .iter()
            .map(crate::consensus::dkg::scalar_to_bytes)
            .collect();
        let agg = bls_aggregate_g1_weighted(&sigs, &weights)?;
        let ok = bls_verify_single(&keyset.group_pubkey_g2, &agg, &msg)?;
        if !ok {
            return Err(PokerL1Error::Other(
                "threshold QC: Lagrange 重构签名未过组公钥验证（装配式错误）".into(),
            ));
        }
        Ok(Self {
            sig_g1: agg.to_vec(),
            signer_bitmap: Self::bitmap_from_ids(&ids, keyset.n),
            group_key_digest: keyset.group_key_digest(),
            t: keyset.t,
        })
    }

    /// 分片 id 集 → canonical bitmap（长度 `ceil(n/8)`，bit `(id-1)` 置位）。
    fn bitmap_from_ids(ids: &[u64], n: u32) -> Vec<u8> {
        let mut bitmap = vec![0u8; Self::bitmap_len(n)];
        for id in ids {
            let idx = (*id - 1) as usize;
            bitmap[idx / 8] |= 1 << (idx % 8);
        }
        bitmap
    }

    /// 签名者分片 id 升序序列（bitmap 解码；审计面）。
    #[must_use]
    pub fn signer_ids(&self) -> Vec<u64> {
        let mut ids = Vec::new();
        for (byte_idx, b) in self.signer_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (b >> bit) & 1 == 1 {
                    ids.push((byte_idx * 8 + bit + 1) as u64);
                }
            }
        }
        ids
    }

    /// 签名者数量（bitmap 置位数）。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// 验证阈值形态载荷（对本地 keyset；由
    /// [`CheckpointQc::verify_threshold`] 以 QC 位点构造签名对象后调用）。
    ///
    /// # Errors
    /// digest 与本地 keyset 不匹配（QC 被挪群）、t 不一致、bitmap 形状非法
    /// （长度 ≠ ceil(n/8) 或越界位置位）、数量 < t、签名尺寸/点非法或配对
    /// 验证失败。
    pub fn verify(&self, keyset: &GroupKeyset, msg_hash: &Hash) -> PokerL1Result<()> {
        if self.group_key_digest != keyset.group_key_digest() {
            return Err(PokerL1Error::Other(
                "threshold QC: group_key_digest 与本地 keyset 不匹配（QC 挪群拒）".into(),
            ));
        }
        if self.t != keyset.t {
            return Err(PokerL1Error::Other(format!(
                "threshold QC: t {} != keyset t {}",
                self.t, keyset.t
            )));
        }
        if self.signer_bitmap.len() != Self::bitmap_len(keyset.n) {
            return Err(PokerL1Error::Other(format!(
                "threshold QC: signer_bitmap len {} != ceil(n/8) = {}",
                self.signer_bitmap.len(),
                Self::bitmap_len(keyset.n)
            )));
        }
        // 越界位（> n 的 bit）必须为 0（canonical bitmap，fail-closed）
        let n = keyset.n as usize;
        for (byte_idx, b) in self.signer_bitmap.iter().enumerate() {
            let base = byte_idx * 8;
            for bit in 0..8 {
                let id = base + bit + 1;
                if id > n && (b >> bit) & 1 == 1 {
                    return Err(PokerL1Error::Other(format!(
                        "threshold QC: signer_bitmap bit for id {id} out of range 1..={n}"
                    )));
                }
            }
        }
        if self.signer_count() < keyset.t as usize {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_count(),
                required: keyset.t as usize,
            });
        }
        if self.sig_g1.len() != crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "threshold QC: aggregate signature size {} != {}",
                self.sig_g1.len(),
                crate::crypto_precompiles::bls::G1_COMPRESSED_SIZE
            )));
        }
        let ok = bls_verify_single(&keyset.group_pubkey_g2, &self.sig_g1, msg_hash)?;
        if !ok {
            return Err(PokerL1Error::Other(
                "threshold QC: 群签名配对验证失败".into(),
            ));
        }
        Ok(())
    }
}

impl CheckpointQc {
    /// 阈值形态 QC 装配入口（节点层收集端，v1.5-e）。
    ///
    /// 位点取第一条 partial 的 `(epoch, height, state_root)`；经
    /// [`ThresholdQc::assemble`] 的全 fail-closed 准入后包装为
    /// [`CheckpointQc`]（threshold = Some，聚合形态三字段为空 —— 阈值
    /// 签名者只持群份额，不产出完整签名聚合）。
    ///
    /// # Errors
    /// `partials` 为空，或 [`ThresholdQc::assemble`] 的任一拒绝条件。
    pub fn form_threshold_from_partials(
        partials: &[ThresholdQcPartial],
        keyset: &GroupKeyset,
    ) -> PokerL1Result<Self> {
        let Some(first) = partials.first() else {
            return Err(PokerL1Error::Other("threshold QC: 无部分份额签名".into()));
        };
        let (epoch, height, state_root) = (first.epoch, first.height, first.state_root);
        let threshold = ThresholdQc::assemble(partials, keyset, epoch, height, state_root)?;
        Ok(Self {
            epoch,
            height,
            state_root,
            // 阈值形态无 proposer/聚合签名/公钥列表（见字段文档）
            proposer_g2: Vec::new(),
            agg_signature_g1: Vec::new(),
            signer_pubkeys_g2: Vec::new(),
            threshold: Some(threshold),
        })
    }

    /// 验证阈值形态（v1.5-e）：以 QC 位点构造签名对象后对本地 keyset 验证
    /// （digest 绑定 + canonical bitmap ≥ t + 单配对）。
    ///
    /// # Errors
    /// `self.threshold == None`（本方法只验阈值形态），或
    /// [`ThresholdQc::verify`] 的任一拒绝条件。
    pub fn verify_threshold(&self, keyset: &GroupKeyset) -> PokerL1Result<()> {
        let Some(tqc) = self.threshold.as_ref() else {
            return Err(PokerL1Error::Other(
                "checkpoint QC: 阈值形态载荷缺失（聚合形态请走 verify）".into(),
            ));
        };
        let msg = checkpoint_qc_signing_hash(self.epoch, self.height, self.state_root);
        tqc.verify(keyset, &msg)
    }

    /// 双形态分派验证（v1.5-e；`get_latest_checkpoint` / fork-anchor 消费点）：
    ///
    /// - `threshold == Some` → 阈值形态验证（需本地 keyset；**无 keyset 节点
    ///   fail-closed 拒** —— 阈值 QC 无法退化为聚合验证，签名者无完整密钥）；
    /// - `threshold == None` → 既有聚合形态验证（零回退路径，keyset 缺席亦可验）。
    ///
    /// # Errors
    /// 分派后的对应验证错误。
    pub fn verify_any(
        &self,
        validator_count: usize,
        keyset: Option<&GroupKeyset>,
    ) -> PokerL1Result<()> {
        if self.threshold.is_some() {
            let Some(ks) = keyset else {
                return Err(PokerL1Error::Other(
                    "checkpoint QC: 阈值形态 QC 需要本地 GroupKeyset 验证（无 keyset 拒）".into(),
                ));
            };
            self.verify_threshold(ks)
        } else {
            self.verify(validator_count)
        }
    }
}

/// fork-anchor 检测三态（v1.5：commit 高度 vs 最后 QC checkpoint）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkAnchorStatus {
    /// commit tip 已 ≥ 最后 QC 高度（锚定正常）。
    Anchored,
    /// commit tip 落后最后 QC 高度但在容忍窗口内。
    Lagging,
    /// 落后超过容忍窗口 → 可能分叉/数据缺失，必须告警。
    Diverged,
}

/// fork-anchor 检测原语：commit tip 相对最后 QC checkpoint 的锚定状态。
///
/// `latest_qc_height == None`（尚无 QC）恒为 `Anchored`（无锚可对比，不告警）。
#[must_use]
pub fn check_fork_anchor(
    latest_qc_height: Option<BlockHeight>,
    commit_tip_height: BlockHeight,
    max_lag_blocks: u64,
) -> ForkAnchorStatus {
    let Some(qc_height) = latest_qc_height else {
        return ForkAnchorStatus::Anchored;
    };
    if commit_tip_height >= qc_height {
        ForkAnchorStatus::Anchored
    } else {
        let lag = qc_height - commit_tip_height;
        if lag > max_lag_blocks {
            ForkAnchorStatus::Diverged
        } else {
            ForkAnchorStatus::Lagging
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::ValidatorEntry;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_real_keypair(seed: u8) -> (secp256k1::SecretKey, TaggedPubkey) {
        let secp = secp256k1::Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        let secret = loop {
            match secp256k1::SecretKey::from_slice(&secret_bytes) {
                Ok(s) => break s,
                Err(_) => secret_bytes[31] = secret_bytes[31].wrapping_add(1),
            }
        };
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            crate::signature::CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .expect("tagged pubkey");
        (secret, tagged)
    }

    fn sign_hash(secret: &secp256k1::SecretKey, msg_hash: &[u8; 32]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut full = compact.to_vec();
        full.push(recovery_id.to_i32() as u8);
        full
    }

    #[test]
    fn checkpoint_interval_detection() {
        assert!(!should_create_checkpoint(0));
        assert!(!should_create_checkpoint(1));
        assert!(!should_create_checkpoint(9999));
        assert!(should_create_checkpoint(10000));
        assert!(should_create_checkpoint(20000));
        assert!(!should_create_checkpoint(15000));
    }

    #[test]
    fn checkpoint_validate_with_real_signatures() {
        // 3 validator，2/3 quorum = 3（required_quorum(3)=3），全签。
        let chain_epoch = 1u64;
        let block_hash = [0xAA; 32];
        let state_root = [0xBB; 32];
        let height = 10_000u64;
        let signing_hash = checkpoint_signing_hash(height, block_hash, state_root, chain_epoch);

        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x10 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();

        let cert = CheckpointCertificate {
            height,
            block_hash,
            state_root,
            epoch: chain_epoch,
            signer_pubkeys: pubkeys,
            signatures: sigs,
        };
        cert.validate(3).expect("3/3 签名应通过 validate");
    }

    #[test]
    fn checkpoint_rejects_insufficient_quorum() {
        // 5 validator，需 4 签名，仅给 3 → 拒绝。
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x20 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: pubkeys,
            signatures: sigs,
        };
        let err = cert.validate(5).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientQuorum { .. }));
    }

    #[test]
    fn checkpoint_rejects_duplicate_signer() {
        // 5 validator（required_quorum(5)=4），提供 4 个签名（其中 1 个重复）→
        // 通过 quorum 检查（4>=4），但在逐签名验证时检测到重复。
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x30 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        // 3 个不同 + 1 个重复（复制第 0 个）→ 共 4 个签名
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: {
                let mut p = pubkeys.clone();
                p.push(pubkeys[0].clone()); // 重复第 0 个
                p
            },
            signatures: {
                let mut s = sigs.clone();
                s.push(sigs[0].clone()); // 重复第 0 个签名
                s
            },
        };
        let err = cert.validate(5).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::Other(_)),
            "应检测到重复签名者: {err:?}"
        );
    }

    #[test]
    fn checkpoint_bcs_roundtrip() {
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let (sk, pk) = make_real_keypair(0x40);
        let sig = sign_hash(&sk, &signing_hash);
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: vec![pk],
            signatures: vec![sig],
        };
        let bytes = borsh::to_vec(&cert).unwrap();
        let recovered: CheckpointCertificate = borsh::from_slice(&bytes).unwrap();
        assert_eq!(cert, recovered);
    }

    // ===== v1.5：BLS 聚合 QC =====

    use super::{
        bls_aggregate_g1, bls_aggregate_g1_weighted, bls_aggregate_g2, bls_derive_secret_key,
        bls_verify_aggregate_same_msg, bls_verify_single, check_fork_anchor,
        checkpoint_qc_signing_hash, should_create_checkpoint_at, BlsSecretKey, CheckpointQc,
        CheckpointVote, ForkAnchorStatus,
    };

    fn bls_key(seed: u8) -> BlsSecretKey {
        bls_derive_secret_key(&[seed; 32])
    }

    fn qc_height_state() -> (u64, [u8; 32]) {
        (64, [0xCCu8; 32])
    }

    #[test]
    fn bls_keypair_derivation_is_deterministic_and_distinct() {
        let a = bls_key(0x10);
        let a2 = bls_key(0x10);
        assert_eq!(a, a2, "同种子必须派生同密钥");
        let b = bls_key(0x11);
        assert_ne!(a, b);
        assert_ne!(a.pubkey_g2(), b.pubkey_g2());
    }

    #[test]
    fn bls_single_sign_and_verify_roundtrip() {
        let sk = bls_key(0x21);
        let msg = checkpoint_qc_signing_hash(1, 32, [1u8; 32]);
        let sig = sk.sign(&msg).unwrap();
        assert!(
            bls_verify_single(&sk.pubkey_g2(), &sig, &msg).unwrap(),
            "合法单签名必须通过配对验证"
        );
        // 篡改消息 → 拒
        let other_msg = checkpoint_qc_signing_hash(1, 33, [1u8; 32]);
        assert!(!bls_verify_single(&sk.pubkey_g2(), &sig, &other_msg).unwrap());
        // 错误公钥 → 拒
        let other = bls_key(0x22);
        assert!(!bls_verify_single(&other.pubkey_g2(), &sig, &msg).unwrap());
    }

    #[test]
    fn qc_aggregate_two_f_plus_one_succeeds() {
        // 7 validator，quorum = 2*7/3+1 = 5（2f+1）
        let (height, state_root) = qc_height_state();
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x30 + i as u8)).unwrap())
            .collect();
        let qc = CheckpointQc::form_from_votes(&votes, 7).expect("5/7 签名必须达成 QC");
        assert_eq!(qc.signer_count(), 5);
        qc.verify(7).expect("QC 必须通过验证");
        // 全体 7 签也成立
        let votes7: Vec<CheckpointVote> = (0..7)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x30 + i as u8)).unwrap())
            .collect();
        CheckpointQc::form_from_votes(&votes7, 7).unwrap().verify(7).unwrap();
    }

    #[test]
    fn qc_aggregate_insufficient_quorum_rejected() {
        let (height, state_root) = qc_height_state();
        // 7 validator 需 5 签，仅 4 → InsufficientQuorum
        let votes: Vec<CheckpointVote> = (0..4)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x40 + i as u8)).unwrap())
            .collect();
        let err = CheckpointQc::form_from_votes(&votes, 7).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientQuorum { actual: 4, required: 5 }),
            "不足 2f+1 必须拒绝: {err:?}"
        );
    }

    #[test]
    fn qc_rejects_heterogeneous_votes_and_forged_signature() {
        let (height, state_root) = qc_height_state();
        let mut votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x50 + i as u8)).unwrap())
            .collect();
        // 异构位点：混入不同 state_root 的合法签名 → 拒
        let rogue = CheckpointVote::sign(1, height, [0xFFu8; 32], &bls_key(0x60)).unwrap();
        votes.push(rogue);
        let err = CheckpointQc::form_from_votes(&votes, 7).unwrap_err();
        assert!(err.to_string().contains("位点不一致"), "异构投票必须拒绝: {err:?}");

        // 伪签名：换掉最后一票的签名字节（合法公钥 + 无效签名）→ 单签验证拒
        // （全零 48B 不是曲线上的合法点，在反序列化/子群检查即拒 —— 同样是拒绝）。
        let mut votes2: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x50 + i as u8)).unwrap())
            .collect();
        votes2[4].signature_g1 = vec![0u8; 48];
        let err2 = CheckpointQc::form_from_votes(&votes2, 7).unwrap_err();
        let msg2 = err2.to_string();
        assert!(
            msg2.contains("signature") || msg2.contains("G1"),
            "伪签名必须拒绝: {err2:?}"
        );
        // 可解码但不匹配的伪签名：替换成另一消息上的合法签名 → 配对验证拒
        let wrong_msg_sig = bls_key(0x50 + 4)
            .sign(&checkpoint_qc_signing_hash(9, 999, [0xEAu8; 32]))
            .unwrap();
        let mut votes2b: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x50 + i as u8)).unwrap())
            .collect();
        votes2b[4].signature_g1 = wrong_msg_sig.to_vec();
        let err2b = CheckpointQc::form_from_votes(&votes2b, 7).unwrap_err();
        assert!(
            err2b.to_string().contains("signature verification failed"),
            "跨消息伪签名必须被配对验证拒绝: {err2b:?}"
        );

        // 重复签名者：同一票投两次 → 去重后不足 quorum → InsufficientQuorum
        let single = CheckpointVote::sign(1, height, state_root, &bls_key(0x51)).unwrap();
        let dup = vec![single.clone(), single];
        let err3 = CheckpointQc::form_from_votes(&dup, 7).unwrap_err();
        assert!(matches!(err3, PokerL1Error::InsufficientQuorum { .. }));
    }

    #[test]
    fn qc_verify_rejects_tampered_aggregate_and_wrong_state_root() {
        let (height, state_root) = qc_height_state();
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, height, state_root, &bls_key(0x70 + i as u8)).unwrap())
            .collect();
        let mut qc = CheckpointQc::form_from_votes(&votes, 7).unwrap();
        // 篡改聚合签名首字节 → 配对验证失败
        let mut bad_agg = qc.agg_signature_g1.clone();
        bad_agg[1] ^= 0x01;
        let saved_agg = std::mem::replace(&mut qc.agg_signature_g1, bad_agg);
        assert!(qc.verify(7).is_err(), "篡改聚合签名必须失败");
        qc.agg_signature_g1 = saved_agg;
        // 篡改 state_root → 签名对象变化 → 失败
        let saved_root = qc.state_root;
        qc.state_root = [0x99u8; 32];
        assert!(qc.verify(7).is_err(), "篡改 state_root 必须失败");
        qc.state_root = saved_root;
        // 签名者不足 → 拒
        let mut trimmed = qc.clone();
        trimmed.signer_pubkeys_g2.truncate(4);
        assert!(matches!(
            trimmed.verify(7).unwrap_err(),
            PokerL1Error::InsufficientQuorum { .. }
        ));
    }

    #[test]
    fn bls_aggregate_rejects_identity_and_verifies_subset_property() {
        // 恒等点聚合拒绝（H3 同款防御）
        let zero_g1 = [0u8; 48];
        assert!(bls_aggregate_g1(&[zero_g1]).is_err());
        let zero_g2 = [0u8; 96];
        assert!(bls_aggregate_g2(&[zero_g2]).is_err());
        // 聚合签名 != 单签名（2 人聚合 ≠ 1 人签名）
        let sk0 = bls_key(0x80);
        let sk1 = bls_key(0x81);
        let msg = checkpoint_qc_signing_hash(2, 64, [3u8; 32]);
        let s0 = sk0.sign(&msg).unwrap();
        let s1 = sk1.sign(&msg).unwrap();
        let agg = bls_aggregate_g1(&[s0, s1]).unwrap();
        let agg_pk = bls_aggregate_g2(&[sk0.pubkey_g2(), sk1.pubkey_g2()]).unwrap();
        assert!(bls_verify_aggregate_same_msg(&agg, &agg_pk, &msg).unwrap());
        // 用错（缺一人）的聚合公钥 → 失败
        assert!(!bls_verify_aggregate_same_msg(&agg, &sk0.pubkey_g2(), &msg).unwrap());
    }

    #[test]
    fn weighted_aggregate_supports_linear_combination() {
        // 权重语义：sum(w_i * p_i) —— 阈值 Lagrange 系数接入点。
        // w=(1,1) 等价普通聚合；w=(2,0) 等价单点自乘 2。
        let sk = bls_key(0x90);
        let msg = checkpoint_qc_signing_hash(3, 96, [4u8; 32]);
        let s = sk.sign(&msg).unwrap();
        let one = {
            let mut arr = [0u8; 32];
            arr[31] = 1;
            arr
        };
        let two = {
            let mut arr = [0u8; 32];
            arr[31] = 2;
            arr
        };
        let doubled = bls_aggregate_g1_weighted(&[s, s], &[two, [0u8; 32]]).unwrap();
        let via_sum = bls_aggregate_g1(&[s, s]).unwrap();
        assert_eq!(doubled, via_sum, "w=(2,0) 必须等于点自加");
        let single = bls_aggregate_g1_weighted(&[s], &[one]).unwrap();
        assert_eq!(single, s);
    }

    #[test]
    fn checkpoint_interval_configurable() {
        assert!(should_create_checkpoint_at(32, 32));
        assert!(should_create_checkpoint_at(64, 32));
        assert!(!should_create_checkpoint_at(31, 32));
        assert!(!should_create_checkpoint_at(0, 32));
        // interval=0 禁用
        assert!(!should_create_checkpoint_at(32, 0));
        // 旧常量语义不变
        assert!(super::should_create_checkpoint(10_000));
    }

    #[test]
    fn fork_anchor_status_three_states() {
        // 无 QC → Anchored（无锚可比）
        assert_eq!(check_fork_anchor(None, 0, 64), ForkAnchorStatus::Anchored);
        // tip >= QC → Anchored
        assert_eq!(check_fork_anchor(Some(64), 64, 64), ForkAnchorStatus::Anchored);
        assert_eq!(check_fork_anchor(Some(64), 100, 64), ForkAnchorStatus::Anchored);
        // 落后在窗口内 → Lagging
        assert_eq!(check_fork_anchor(Some(64), 20, 64), ForkAnchorStatus::Lagging);
        // 落后超窗口 → Diverged（告警）
        assert_eq!(check_fork_anchor(Some(64), 0, 63), ForkAnchorStatus::Diverged);
    }

    #[test]
    fn checkpoint_vote_jsonl_roundtrip() {
        let vote = CheckpointVote::sign(1, 32, [5u8; 32], &bls_key(0xA0)).unwrap();
        let json = serde_json::to_string(&vote).unwrap();
        let back: CheckpointVote = serde_json::from_str(&json).unwrap();
        assert_eq!(vote, back);
        back.verify().unwrap();
        // QC JSON 往返（sidecar JSONL 持久化格式）
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(1, 64, [6u8; 32], &bls_key(0xA1 + i as u8)).unwrap())
            .collect();
        let qc = CheckpointQc::form_from_votes(&votes, 7).unwrap();
        let qjson = serde_json::to_string(&qc).unwrap();
        let qback: CheckpointQc = serde_json::from_str(&qjson).unwrap();
        assert_eq!(qc, qback);
        qback.verify(7).unwrap();
    }

    // ===== v1.5-e：阈值 QC 形态（真 t-of-n，additive 双形态） =====

    use crate::consensus::dkg::{
        GroupKeyset, ParticipantShare, assemble_group_keyset, dealer_deal,
    };
    use crate::consensus::checkpoint::ThresholdQcPartial;

    /// deal-sum DKG 演练（n 个 dealer 单进程）。
    fn run_dkg(n: u32, t: u32, seed: u8) -> (GroupKeyset, Vec<ParticipantShare>) {
        let deals: Vec<_> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[seed; 32], j, n, t).expect("dealer deal"))
            .collect();
        assemble_group_keyset(&deals, n, t).expect("assemble")
    }

    fn threshold_partials(
        shares: &[ParticipantShare],
        ids: &[u64],
        epoch: Epoch,
        height: BlockHeight,
        state_root: Hash,
    ) -> Vec<ThresholdQcPartial> {
        let signing = checkpoint_qc_signing_hash(epoch, height, state_root);
        ids.iter()
            .map(|id| {
                let share = shares.iter().find(|s| s.id == *id).expect("share exists");
                ThresholdQcPartial {
                    epoch,
                    height,
                    state_root,
                    participant_id: share.id,
                    sig_g1: share.partial_sign(&signing).expect("partial sign").to_vec(),
                }
            })
            .collect()
    }

    /// 阈值 QC 装配/验证全链路（DKG 5-of-7 → ≥t 份额逐验 → Lagrange 加权重构
    /// → 单配对验证）；字段绑定：换位点半字/篡改签名/挪群 digest/t 不一致均拒。
    #[test]
    fn threshold_qc_assemble_verify_and_field_binding() {
        let (keyset, shares) = run_dkg(7, 5, 0x71);
        let (epoch, height, root) = (4u64, 96u64, [0x81u8; 32]);
        let ps = threshold_partials(&shares, &[2, 3, 4, 6, 7], epoch, height, root);
        // 逐份验证正例
        for p in &ps {
            p.verify(&keyset).expect("合法份额签名必须过逐份验证");
        }
        let qc = CheckpointQc::form_threshold_from_partials(&ps, &keyset)
            .expect("≥t 份额必须装配成阈值 QC");
        let tqc = qc.threshold.as_ref().expect("阈值形态载荷存在");
        assert_eq!(tqc.signer_count(), 5);
        assert_eq!(tqc.signer_ids(), vec![2, 3, 4, 6, 7]);
        assert_eq!(tqc.t, 5);
        assert_eq!(tqc.group_key_digest, keyset.group_key_digest());
        assert!(qc.proposer_g2.is_empty() && qc.signer_pubkeys_g2.is_empty());
        // 单配对验证通过（对组公钥）
        qc.verify_threshold(&keyset).expect("阈值 QC 必须通过组公钥验证");
        qc.verify_any(7, Some(&keyset)).expect("双形态分派：阈值形态走 keyset 验证");
        // 篡改聚合签名 → 拒
        let mut tampered = qc.clone();
        tampered.threshold.as_mut().unwrap().sig_g1[0] ^= 0x01;
        assert!(tampered.verify_threshold(&keyset).is_err());
        // 挪群：digest 与本地 keyset 不匹配 → 拒
        let (other_keyset, _) = run_dkg(7, 5, 0x72);
        assert!(qc.verify_threshold(&other_keyset).is_err(), "QC 挪到另一群必须拒");
        // t 不一致 → 拒
        let mut bad_t = qc.clone();
        bad_t.threshold.as_mut().unwrap().t = 3;
        assert!(bad_t.verify_threshold(&keyset).is_err());
        // QC 位点被改（签名对象变化）→ 拒
        let mut bad_site = qc.clone();
        bad_site.height = 97;
        assert!(bad_site.verify_threshold(&keyset).is_err());
        // bitmap 越界位置位 → 拒（canonical bitmap；bit 7 = id 8 > n=7）
        let mut bad_bitmap = qc.clone();
        bad_bitmap.threshold.as_mut().unwrap().signer_bitmap[0] |= 0x80;
        assert!(bad_bitmap.verify_threshold(&keyset).is_err());
        // 异构位点 partial → 装配拒
        let mut ps2 = ps.clone();
        ps2[0].state_root = [0xEEu8; 32];
        assert!(CheckpointQc::form_threshold_from_partials(&ps2, &keyset).is_err());
        // 伪造份额（拿 6 的签名贴 5）→ 逐份验证拒
        let mut ps3 = threshold_partials(&shares, &[1, 2, 3, 4, 5], epoch, height, root);
        ps3[4].sig_g1 = ps[3].sig_g1.clone();
        assert!(ps3[4].verify(&keyset).is_err());
    }

    /// <t 不产 QC（InsufficientQuorum）；重复份额去重后仍只计一次；同位点
    /// 两个不同 t-子集装配出可验证的等价 QC。
    #[test]
    fn threshold_qc_below_t_no_qc_and_dedupe() {
        let (keyset, shares) = run_dkg(7, 5, 0x73);
        let (epoch, height, root) = (1u64, 64u64, [0x83u8; 32]);
        // t-1 = 4 份 → InsufficientQuorum
        let ps4 = threshold_partials(&shares, &[1, 2, 3, 4], epoch, height, root);
        let err = CheckpointQc::form_threshold_from_partials(&ps4, &keyset).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientQuorum { actual: 4, required: 5 }),
            "<t 必须拒绝: {err:?}"
        );
        // 重复参与者：同一 partial 提交多次 → 去重后仍 1 人
        let single = threshold_partials(&shares, &[3], epoch, height, root);
        let dups = vec![
            single[0].clone(),
            single[0].clone(),
            single[0].clone(),
        ];
        let err2 = CheckpointQc::form_threshold_from_partials(&dups, &keyset).unwrap_err();
        assert!(matches!(err2, PokerL1Error::InsufficientQuorum { .. }));
        // 5 人含重复 → 去重后恰 t=5 → 成 QC
        let mut mixed = threshold_partials(&shares, &[1, 2, 3, 4, 5], epoch, height, root);
        mixed.push(mixed[0].clone());
        let qc = CheckpointQc::form_threshold_from_partials(&mixed, &keyset).unwrap();
        assert_eq!(qc.signer_count(), 5, "重复份额不得重复计入");
        qc.verify_threshold(&keyset).unwrap();
    }

    /// 双形态分派与 serde 兼容（零回退）：聚合 QC JSON 无 threshold 字段且
    /// 旧格式可解析；阈值 QC JSON 往返 + verify_any 分派；无 keyset 验阈值
    /// QC fail-closed 拒；聚合路径验阈值形态 QC 拒（空聚合集）。
    #[test]
    fn checkpoint_qc_dual_form_dispatch_and_serde_compat() {
        let (keyset, shares) = run_dkg(7, 5, 0x74);
        let (epoch, height, root) = (2u64, 64u64, [0x84u8; 32]);
        // 聚合形态（既有路径，threshold = None）
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(epoch, height, root, &bls_key(0xB0 + i as u8)).unwrap())
            .collect();
        let agg_qc = CheckpointQc::form_from_votes(&votes, 7).unwrap();
        assert!(agg_qc.threshold.is_none());
        agg_qc.verify(7).unwrap();
        agg_qc.verify_any(7, None).expect("聚合形态无 keyset 亦可验（零回退）");
        agg_qc.verify_any(7, Some(&keyset)).unwrap();
        // 聚合 QC JSON 不含 threshold 键（格式不变）且可解析
        let agg_json = serde_json::to_string(&agg_qc).unwrap();
        assert!(!agg_json.contains("threshold"), "聚合形态 JSON 格式必须不变");
        let agg_back: CheckpointQc = serde_json::from_str(&agg_json).unwrap();
        assert_eq!(agg_qc, agg_back);
        // 旧 v1.5-c JSON（无 threshold 字段）手写构造可解析（serde default）
        let legacy = format!(
            "{{\"epoch\":{},\"height\":{},\"state_root\":[{}],\"proposer_g2\":[],\"agg_signature_g1\":[],\"signer_pubkeys_g2\":[]}}",
            epoch,
            height,
            root.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        );
        let legacy_qc: CheckpointQc = serde_json::from_str(&legacy).unwrap();
        assert!(legacy_qc.threshold.is_none());
        // 阈值形态：JSON 往返（sidecar 落盘/重启恢复形态）+ 分派
        let ps = threshold_partials(&shares, &[1, 2, 4, 5, 6], epoch, height, root);
        let t_qc = CheckpointQc::form_threshold_from_partials(&ps, &keyset).unwrap();
        let t_json = serde_json::to_string(&t_qc).unwrap();
        assert!(t_json.contains("\"threshold\""));
        let t_back: CheckpointQc = serde_json::from_str(&t_json).unwrap();
        assert_eq!(t_qc, t_back, "阈值 QC JSON 往返必须一致（落盘/恢复）");
        t_back.verify_any(7, Some(&keyset)).unwrap();
        // 无 keyset 验阈值 QC → fail-closed 拒
        assert!(t_qc.verify_any(7, None).is_err());
        // 聚合路径（verify）验阈值形态 QC → 拒（聚合集为空）
        assert!(t_qc.verify(7).is_err());
        // 聚合形态走 verify_threshold → 拒（形态不符）
        assert!(agg_qc.verify_threshold(&keyset).is_err());
    }

    /// 性能对比（阈值单配对 vs 聚合逐票）：同一 7-validator 检查点位点，
    /// 测量（默认 release 口径，`--nocapture` 查看输出）：
    /// 1. 收集面：聚合 QC 成型（2f+1 逐票配对验证 + 点加聚合）vs
    ///    阈值 QC 装配（t 份逐份配对验证 + Lagrange 加权重构 + 终验）；
    /// 2. **独立重验面（核心差异）**：聚合 QC 完整重验需 n 次单签名配对
    ///    （对每位签名者公钥）+ 1 次聚合配对；阈值 QC 验证恒为 **1 次配对**
    ///    （对组公钥，成本与签名者数无关）。
    /// 断言只钉正确性，不钉速度（机器相关）；数字用于验收报告。
    #[test]
    fn perf_threshold_vs_aggregate_verification() {
        let (keyset, shares) = run_dkg(7, 5, 0x75);
        let (epoch, height, root) = (3u64, 64u64, [0x85u8; 32]);
        let ps = threshold_partials(&shares, &[1, 2, 3, 4, 5], epoch, height, root);
        let votes: Vec<CheckpointVote> = (0..5)
            .map(|i| CheckpointVote::sign(epoch, height, root, &bls_key(0xC0 + i as u8)).unwrap())
            .collect();

        const ITERS: u32 = 20;
        // ---- 收集面 ----
        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            let _qc = CheckpointQc::form_from_votes(&votes, 7).unwrap();
        }
        let agg_form_us = start.elapsed().as_micros() as f64 / ITERS as f64;
        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            let _qc = CheckpointQc::form_threshold_from_partials(&ps, &keyset).unwrap();
        }
        let thr_form_us = start.elapsed().as_micros() as f64 / ITERS as f64;

        // ---- 独立重验面 ----
        let agg_qc = CheckpointQc::form_from_votes(&votes, 7).unwrap();
        let thr_qc = CheckpointQc::form_threshold_from_partials(&ps, &keyset).unwrap();
        // 聚合完整重验：逐票单配对（n 次）+ 聚合配对（1 次）
        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            for v in &votes {
                v.verify().unwrap(); // 每票 1 次配对
            }
            agg_qc.verify(7).unwrap(); // + 1 次聚合配对
        }
        let agg_full_verify_us = start.elapsed().as_micros() as f64 / ITERS as f64;
        // 阈值重验：1 次配对（组公钥）+ bitmap/digest 检查（可忽略）
        let start = std::time::Instant::now();
        for _ in 0..ITERS {
            thr_qc.verify_threshold(&keyset).unwrap();
        }
        let thr_verify_us = start.elapsed().as_micros() as f64 / ITERS as f64;
        // 载荷对比（签名者证明材料）
        let agg_payload: usize = agg_qc
            .signer_pubkeys_g2
            .iter()
            .map(|pk| pk.len() + 48)
            .sum();
        let thr_payload: usize = 48 + thr_qc.threshold.as_ref().unwrap().signer_bitmap.len();

        println!(
            "PERF[n=7,t=5] 收集/成型: aggregate={agg_form_us:.0}us threshold={thr_form_us:.0}us"
        );
        println!(
            "PERF[n=7,t=5] 独立重验: aggregate(5 票逐配对+聚合)={agg_full_verify_us:.0}us threshold(单配对)={thr_verify_us:.0}us speedup={:.1}x",
            agg_full_verify_us / thr_verify_us
        );
        println!(
            "PERF[n=7,t=5] 签名者证明载荷: aggregate={agg_payload}B (5x96B pk + 5x48B sig) threshold={}B (48B sig + {}B bitmap)",
            48 + thr_qc.threshold.as_ref().unwrap().signer_bitmap.len(),
            thr_qc.threshold.as_ref().unwrap().signer_bitmap.len()
        );
        // 正确性断言（不钉速度）
        assert!(agg_form_us > 0.0 && thr_form_us > 0.0);
        assert!(agg_full_verify_us > thr_verify_us, "聚合逐票重验成本必须高于阈值单配对（配对次数 6 vs 1）");
        assert!(agg_payload > thr_payload, "聚合载荷（n 份公钥+签名）必须大于阈值载荷");
    }
}
