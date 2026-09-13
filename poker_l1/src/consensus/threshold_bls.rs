//! 阈值 BLS 聚合签名（真 t-of-n）——排期表 §2"阈值 BLS 聚合签名"行。
//!
//! # 与聚合 QC（[`crate::consensus::checkpoint::CheckpointQc`]）的边界（命名纪律）
//!
//! 聚合 QC 是**线性聚合**：每位签名者持完整私钥，聚合 = G1 点加法，验证
//! 需签名者公钥之和。本模块是**阈值签名**：私钥 `s` 从未在任何单点存在
//! （dealer 分片后即弃），每位签名者只持一个 Shamir 分片 `f(i)`；任意
//! `t` 个分片的**部分签名**经 Lagrange 插值系数加权聚合后，恰等价于
//! `s` 对消息的完整签名——验证端只需**一次配对**对**组公钥**验证（成本
//! 与参与人数无关），且 `t-1` 个分片无法伪造（门限性质，负例矩阵钉住）。
//!
//! # 方案（BLS12-381，零新依赖）
//!
//! 依赖结论（roadmap 出口分支"若现有依赖仅支持聚合签名，先出评估"）：
//! **`blstrs` 已足够**——Scalar 域运算（Shamir/Lagrange）、G1/G2 点运算、
//! 配对全部在库内，**无需依赖升级/替换**；加权聚合直接复用
//! [`crate::consensus::checkpoint::bls_aggregate_g1_weighted`]（v1.5 预留的阈值
//! 接入点，Lagrange 系数作为权重传入，验证端公式不变）。
//!
//! ```text
//! 分发（dealer）：f(x) = s + a1·x + … + a_{t-1}·x^{t-1}（mod r）
//!   share_i = f(i)，i ∈ 1..=n
//!   Feldman 承诺 C_j = a_j·G2（j ∈ 0..=t-1）→ 组公钥 pk = C_0 = s·G2
//!   任何持承诺集者可验任意分片：share_i·G2 == Σ_j C_j·i^j（VSS，防坏分片）
//! 签名：partial_i = share_i·H(m)（G1）
//! 聚合：σ = Σ_{i∈S} λ_i·partial_i，λ_i = Π_{j∈S, j≠i} x_j/(x_j−x_i)
//!       （S ⊆ 签名者集，|S| ≥ t）→ σ = f(0)·H(m) = s·H(m)
//! 验证：e(σ, G2gen) == e(H(m), pk)——与单签名同式，一次配对
//! ```
//!
//! # 边界（如实声明，不在此实现）
//!
//! - **dealer 模式，非 DKG**：`s` 在分发方进程内短暂完整存在。生产部署
//!   应替换为 DKG（各 validator 独立产承诺、Joint-Feldman 组合）——本模块
//!   的承诺集/分片/聚合/验证四层接口即 DKG 的接入面（只换 `deal_threshold`
//!   的来源，其余不变）。
//! - **签名者集动态性**：分片 id 与 validator 集的映射由部署层冻结（id
//!   ∈ 1..=n）；validator 集变更 = 重新分发（rekey），本原型不做
//!   proactive refresh。
//! - **共识路径接入现状**：[`ThresholdCheckpointQc`] 对
//!   [`crate::consensus::checkpoint::checkpoint_qc_signing_hash`] 签名对象出阈值
//!   QC，验证公式与节点 checkpoint 验证同层（一次配对、组公钥判定）；
//!   节点投票收集/gossip 面仍走聚合 QC（v1.5-c 既有管线），阈值 QC 的
//!   收集接线随 DKG 立项排期——本模块交付的是"阈值 QC 验证进共识路径"
//!   的验证侧与完整正负例矩阵。

use borsh::{BorshDeserialize, BorshSerialize};
use blstrs::{G2Projective, Scalar};
use group::Group;
use serde::{Deserialize, Serialize};
use subtle::CtOption;
use poker_protocol::crypto::curve::CurveScalar;

use crate::BlockHeight;
use crate::Hash;
use crate::consensus::Epoch;
use crate::crypto_precompiles::bls::{G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, SCALAR_SIZE};
use crate::error::{PokerL1Error, PokerL1Result};

/// 系数派生域标签（与 [`crate::consensus::checkpoint::bls_derive_secret_key`] 同纪律
/// 的域分离：本模块的 Shamir 系数不得与其它密钥用途共享派生空间）。
const THRESHOLD_COEFF_DOMAIN: &[u8] = b"ZCHAIN_THRESHOLD_BLS_COEFF_V1";

fn ct_opt<T>(ct: CtOption<T>) -> Option<T> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn parse_scalar(bytes: &[u8; 32]) -> PokerL1Result<Scalar> {
    ct_opt(Scalar::from_bytes_be(bytes))
        .ok_or_else(|| PokerL1Error::InvalidBlsScalar("threshold scalar not canonical".into()))
}

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes_be()
}

/// 从域标签 + 种子 + 计数器确定性派生规范 Scalar（拒绝重试至规范，循环
/// 期望次数 ~1；`bls_derive_secret_key` 同款约简）。
fn derive_scalar(domain: &[u8], seed: &[u8; 32], counter: u64) -> Scalar {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut nonce = 0u8;
    loop {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(domain);
        h.update(seed);
        h.update(&counter.to_le_bytes());
        h.update(&[nonce]);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        if let Some(s) = ct_opt(Scalar::from_bytes_be(&out)) {
            return s;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// `base^exp`（exp 为 u64，平方乘；指数规模 = t，无性能压力）。
fn scalar_pow(base: &Scalar, exp: u64) -> Scalar {
    let mut acc = Scalar::one();
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            acc *= b;
        }
        b *= b;
        e >>= 1;
    }
    acc
}

/// Lagrange 插值系数（在 0 点求值）：`λ_i = Π_{j∈S, j≠i} x_j/(x_j−x_i)`。
///
/// `ids` 即求值点集 S（分片 id，互异且 ≥ 1）；返回与 `ids` 对齐的系数
/// 序列。恒等式（测试钉住）：`Σ λ_i·f(x_i) == f(0)` 对任意次数 < |S|
/// 多项式成立——不同 t 子集插值出的组签名逐字节一致。
fn lagrange_coefficients(ids: &[u64]) -> PokerL1Result<Vec<Scalar>> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if ids.is_empty() || sorted.len() != ids.len() {
        return Err(PokerL1Error::Other(
            "threshold: Lagrange point set empty or has duplicates".into(),
        ));
    }
    if ids.iter().any(|x| *x == 0) {
        return Err(PokerL1Error::Other(
            "threshold: share ids are 1-based (0 is the polynomial constant point)".into(),
        ));
    }
    let x = |v: u64| Scalar::from(v);
    let mut out = Vec::with_capacity(ids.len());
    for &xi in ids {
        let mut num = Scalar::one();
        let mut den = Scalar::one();
        for &xj in ids {
            if xj == xi {
                continue;
            }
            num *= x(xj);
            den *= x(xj) - x(xi);
        }
        // CurveScalar::invert 语义：非零分母必可逆（ids 互异 ⇒ 分母非零）
        out.push(num * den.invert());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 密钥集（Feldman 承诺）与分片
// ---------------------------------------------------------------------------

/// 阈值密钥集（公开面：Feldman 承诺 + 组公钥；可分发/持久化）。
///
/// `t` 即重建/签名所需最小分片数（BFT 部署取 `required_quorum(n)`，
/// 见 [`bft_threshold`]）；承诺数 == `t`（j ∈ 0..=t-1）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ThresholdKeyset {
    /// 参与者总数（分片 id ∈ 1..=n）。
    pub n: u32,
    /// 签名/重建阈值（t-of-n 的 t）。
    pub t: u32,
    /// Feldman 承诺 `C_j = a_j·G2`（G2 compressed 96B 逐条，j = 0..=t-1；
    /// serde 面用 Vec<u8> —— serde 对 >32B 定长数组无实现）。
    pub commitments_g2: Vec<Vec<u8>>,
    /// 组公钥 `pk = s·G2`（== `C_0`，冗余字段供验证端一次读取；96B）。
    pub group_pubkey_g2: Vec<u8>,
}

impl ThresholdKeyset {
    /// 分片 id 的公开验证密钥：`pk_i = Σ_j C_j·i^j`（VSS 验证输入；
    /// 部分签名验证即对 `pk_i` 的单签名配对验证）。
    ///
    /// # Errors
    /// `id == 0` 或 `id > n`，或承诺点非法（非曲线点/未过子群检查）。
    pub fn public_share(&self, id: u64) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
        if id == 0 || u64::from(self.n) < id {
            return Err(PokerL1Error::Other(format!(
                "threshold: share id {id} out of range 1..={}",
                self.n
            )));
        }
        if self.commitments_g2.len() != self.t as usize {
            return Err(PokerL1Error::Other(
                "threshold: commitment count != t (keyset corrupt)".into(),
            ));
        }
        let x = Scalar::from(id);
        let mut acc = G2Projective::identity();
        for (j, c_bytes) in self.commitments_g2.iter().enumerate() {
            let arr: [u8; G2_COMPRESSED_SIZE] = c_bytes.as_slice().try_into().map_err(|_| {
                PokerL1Error::InvalidBlsPoint(format!(
                    "threshold: commitment {j} size {} != {G2_COMPRESSED_SIZE}",
                    c_bytes.len()
                ))
            })?;
            let c = crate::consensus::checkpoint::parse_g2(&arr)?;
            acc += c * scalar_pow(&x, j as u64);
        }
        Ok(acc.to_compressed())
    }

    /// 验证分片归属：`share_i·G2 == pk_i`（VSS；坏分片在准入即拒）。
    ///
    /// # Errors
    /// id 越界或点非法；返回 `Ok(false)` 表示分片与承诺不一致。
    pub fn verify_share(&self, share: &ThresholdShare) -> PokerL1Result<bool> {
        let pk = self.public_share(share.id)?;
        let sk = parse_scalar(&share.scalar)?;
        let derived = (G2Projective::generator() * sk).to_compressed();
        Ok(derived.as_slice() == pk.as_slice())
    }
}

/// BFT 阈值映射：`t = required_quorum(n)`（2f+1 of n）。
#[must_use]
pub fn bft_threshold(n: u32) -> u32 {
    u32::try_from(crate::consensus::required_quorum(n as usize)).unwrap_or(n)
}

/// 单个参与者的密钥分片（`share_i = f(i)`，32B 大端 Scalar）。
///
/// **秘密面**：只存在于各参与者本地；泄露 t 个分片即泄露组密钥（t-1 个
/// 在信息论上不泄露任何关于 `s` 的信息——Shamir 门限性质；本模块以
/// "t-1 个**合法**分片的插值不构成可验证组签名"为其可验证面，测试钉住）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ThresholdShare {
    /// 分片 id（1..=n；多项式求值点）。
    pub id: u64,
    /// 分片标量（32B 大端）。
    pub scalar: [u8; SCALAR_SIZE],
}

impl ThresholdShare {
    /// 部分签名：`partial_i = share_i·H(m)`（G1 compressed 48B）。
    ///
    /// # Errors
    /// 分片标量非规范（构造面已保证，防御性保留）或 hash-to-curve 失败。
    pub fn partial_sign(&self, msg_hash: &Hash) -> PokerL1Result<[u8; G1_COMPRESSED_SIZE]> {
        let sk = parse_scalar(&self.scalar)?;
        let h_m = crate::consensus::checkpoint::parse_g1(
            &crate::crypto_precompiles::bls::bls_hash_to_g1(msg_hash)?,
        )?;
        Ok((h_m * sk).to_compressed())
    }
}

/// dealer 式可信分发（原型口径；生产换 DKG，见模块头边界）。
///
/// 系数 `a_j` 由种子经域分隔哈希确定性派生（测试可重现；生产 dealer 应
/// 用 CSPRNG 并在分发后销毁种子与系数）。
///
/// # Errors
/// `n == 0` 或 `t == 0` 或 `t > n`。
pub fn deal_threshold(
    seed: &[u8; 32],
    n: u32,
    t: u32,
) -> PokerL1Result<(ThresholdKeyset, Vec<ThresholdShare>)> {
    if n == 0 || t == 0 || t > n {
        return Err(PokerL1Error::Other(format!(
            "threshold: invalid (n, t) = ({n}, {t}); require 1 <= t <= n, n >= 1"
        )));
    }
    let coeffs: Vec<Scalar> = (0..u64::from(t))
        .map(|j| derive_scalar(THRESHOLD_COEFF_DOMAIN, seed, j))
        .collect();
    let mut commitments_g2 = Vec::with_capacity(t as usize);
    for c in &coeffs {
        commitments_g2.push((G2Projective::generator() * c).to_compressed().to_vec());
    }
    let group_pubkey_g2 = commitments_g2[0].clone();
    let shares = (1..=u64::from(n))
        .map(|i| {
            let x = Scalar::from(i);
            let mut acc = Scalar::zero();
            for (j, c) in coeffs.iter().enumerate() {
                acc += c * scalar_pow(&x, j as u64);
            }
            ThresholdShare {
                id: i,
                scalar: scalar_to_bytes(&acc),
            }
        })
        .collect();
    Ok((
        ThresholdKeyset {
            n,
            t,
            commitments_g2,
            group_pubkey_g2,
        },
        shares,
    ))
}

// ---------------------------------------------------------------------------
// 阈值 QC（对 checkpoint 签名对象的 t-of-n 背书）
// ---------------------------------------------------------------------------

/// 单个参与者的 checkpoint 部分签名（P2P gossip 载荷形态）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ThresholdPartial {
    /// 分片 id（1..=n）。
    pub id: u64,
    /// 部分签名（G1 compressed 48B）。
    pub sig_g1: Vec<u8>,
}

/// 阈值 checkpoint QC：`t-of-n` 分片的部分签名经 Lagrange 插值聚合成的
/// 完整 BLS 签名（对 [`crate::consensus::checkpoint::checkpoint_qc_signing_hash`]
/// 签名对象）。
///
/// 验证端（[`Self::verify`]）只需组公钥 + 一次配对——签名者列表只承担
/// 审计/计数职责，不参与密码学验证（与聚合 QC 的"公钥之和"验证相区分，
/// 这是阈值方案的核心优势）。
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ThresholdCheckpointQc {
    /// epoch。
    pub epoch: Epoch,
    /// 被 checkpoint 锚定的 commit 高度。
    pub height: BlockHeight,
    /// 该高度 state_root。
    pub state_root: Hash,
    /// 参与签名的分片 id 集（审计面；聚合时已按 id 去重）。
    pub signer_ids: Vec<u64>,
    /// 聚合签名（G1 compressed 48B；== `s·H(m)`）。
    pub agg_signature_g1: Vec<u8>,
}

impl ThresholdCheckpointQc {
    /// 由部分签名聚合形成阈值 QC（对 (epoch, height, state_root) 的
    /// [`crate::consensus::checkpoint::checkpoint_qc_signing_hash`] 签名对象；
    /// 与聚合 QC 同一消息域——同一 checkpoint 位点可同时被两种 QC 背书）。
    ///
    /// 准入（全 fail-closed，见 [`Self::aggregate_partials`]）：
    /// 1. 分片 id 去重（重复部分签名只计一次）+ 越界拒（0 或 > n）；
    /// 2. **逐部分签名验证**：对 [`ThresholdKeyset::public_share`] 做单
    ///    签名配对验证（坏分片/伪造部分签名在此拒，不进聚合）；
    /// 3. 数量 ≥ `keyset.t` 才成 QC（`InsufficientQuorum`）；
    /// 4. Lagrange 加权聚合（复用聚合层预留的加权聚合原语）；
    /// 5. 聚合结果对组公钥做最终配对验证（防御纵深：聚合式错误在成型
    ///    即被拦截）。
    pub fn form_for_checkpoint(
        partials: &[ThresholdPartial],
        keyset: &ThresholdKeyset,
        epoch: Epoch,
        height: BlockHeight,
        state_root: Hash,
    ) -> PokerL1Result<Self> {
        let msg_hash =
            crate::consensus::checkpoint::checkpoint_qc_signing_hash(epoch, height, state_root);
        let (signer_ids, agg) = Self::aggregate_partials(partials, keyset, &msg_hash)?;
        Ok(Self {
            epoch,
            height,
            state_root,
            signer_ids,
            agg_signature_g1: agg.to_vec(),
        })
    }

    /// 聚合核心（消息层；`form_for_checkpoint` 的内部实现）：返回
    /// (去重后的分片 id 序列, 组签名)。
    fn aggregate_partials(
        partials: &[ThresholdPartial],
        keyset: &ThresholdKeyset,
        msg_hash: &Hash,
    ) -> PokerL1Result<(Vec<u64>, [u8; G1_COMPRESSED_SIZE])> {
        let mut seen = std::collections::BTreeSet::new();
        let mut ids: Vec<u64> = Vec::new();
        let mut sigs: Vec<[u8; G1_COMPRESSED_SIZE]> = Vec::new();
        for p in partials {
            if !seen.insert(p.id) {
                continue; // 同分片重复投票不重复计入
            }
            if p.id == 0 || u64::from(keyset.n) < p.id {
                return Err(PokerL1Error::Other(format!(
                    "threshold QC: share id {} out of range 1..={}",
                    p.id, keyset.n
                )));
            }
            if p.sig_g1.len() != G1_COMPRESSED_SIZE {
                return Err(PokerL1Error::InvalidBlsPoint(format!(
                    "threshold QC: partial signature size {} != {G1_COMPRESSED_SIZE}",
                    p.sig_g1.len()
                )));
            }
            let pk_i = keyset.public_share(p.id)?;
            let mut sig = [0u8; G1_COMPRESSED_SIZE];
            sig.copy_from_slice(&p.sig_g1);
            let ok = crate::consensus::checkpoint::bls_verify_single(&pk_i, &sig, msg_hash)?;
            if !ok {
                return Err(PokerL1Error::Other(format!(
                    "threshold QC: partial signature from share {} failed verification",
                    p.id
                )));
            }
            ids.push(p.id);
            sigs.push(sig);
        }
        if ids.len() < keyset.t as usize {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: ids.len(),
                required: keyset.t as usize,
            });
        }
        let lambdas = lagrange_coefficients(&ids)?;
        let weights: Vec<[u8; 32]> = lambdas.iter().map(scalar_to_bytes).collect();
        let agg = crate::consensus::checkpoint::bls_aggregate_g1_weighted(&sigs, &weights)?;
        let ok = crate::consensus::checkpoint::bls_verify_single(
            &keyset.group_pubkey_g2,
            &agg,
            msg_hash,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "threshold QC: aggregated signature failed group-key verification".into(),
            ));
        }
        Ok((ids, agg))
    }

    /// 验证阈值 QC（共识路径验证侧）：
    /// 1. `signer_ids` 去重 + 越界拒；
    /// 2. 数量 ≥ `keyset.t`；
    /// 3. **一次配对**：`e(agg_sig, G2gen) == e(H(m), group_pk)`——签名者
    ///    列表不参与密码学验证（成本 O(1)，与参与人数无关）。
    pub fn verify(&self, keyset: &ThresholdKeyset) -> PokerL1Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for id in &self.signer_ids {
            if *id == 0 || u64::from(keyset.n) < *id {
                return Err(PokerL1Error::Other(format!(
                    "threshold QC: signer id {id} out of range 1..={}",
                    keyset.n
                )));
            }
            if !seen.insert(*id) {
                return Err(PokerL1Error::Other("threshold QC: duplicate signer id".into()));
            }
        }
        if self.signer_ids.len() < keyset.t as usize {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_ids.len(),
                required: keyset.t as usize,
            });
        }
        if self.agg_signature_g1.len() != G1_COMPRESSED_SIZE {
            return Err(PokerL1Error::InvalidBlsPoint(format!(
                "threshold QC: aggregate signature size {} != {G1_COMPRESSED_SIZE}",
                self.agg_signature_g1.len()
            )));
        }
        let msg = crate::consensus::checkpoint::checkpoint_qc_signing_hash(
            self.epoch,
            self.height,
            self.state_root,
        );
        let ok = crate::consensus::checkpoint::bls_verify_single(
            &keyset.group_pubkey_g2,
            &self.agg_signature_g1,
            &msg,
        )?;
        if !ok {
            return Err(PokerL1Error::Other(
                "threshold QC: aggregate signature verification failed".into(),
            ));
        }
        Ok(())
    }

    /// 签名者数量。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_ids.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::checkpoint;

    fn keyset_5_of_7() -> (ThresholdKeyset, Vec<ThresholdShare>) {
        deal_threshold(&[0x71u8; 32], 7, bft_threshold(7)).expect("deal 5-of-7")
    }

    fn partials(shares: &[ThresholdShare], ids: &[u64], msg: &Hash) -> Vec<ThresholdPartial> {
        ids.iter()
            .map(|id| {
                let share = shares.iter().find(|s| s.id == *id).expect("share exists");
                ThresholdPartial {
                    id: share.id,
                    sig_g1: share.partial_sign(msg).unwrap().to_vec(),
                }
            })
            .collect()
    }

    /// 恒等式根基：任意两个 t 人子集对同一消息插值出的组签名逐字节一致
    /// （`Σ λ_i·f(x_i) == f(0) == s` 的签名面）。
    #[test]
    fn lagrange_reconstruction_is_subset_independent() {
        let (keyset, shares) = deal_threshold(&[9u8; 32], 5, 3).unwrap();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 32, [1u8; 32]);
        let qa = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[1, 3, 5], &m),
            &keyset,
            1,
            32,
            [1u8; 32],
        )
        .unwrap();
        let qb = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[2, 3, 4], &m),
            &keyset,
            1,
            32,
            [1u8; 32],
        )
        .unwrap();
        assert_eq!(
            qa.agg_signature_g1, qb.agg_signature_g1,
            "不同 t 子集插值必须得到同一个 s·H(m)"
        );
    }

    /// 5-of-7 正例：恰好 t=5（非前缀子集）成型 + 验证；超 t（6 人）同样
    /// 成立；组公钥 == C_0。
    #[test]
    fn threshold_qc_form_and_verify_positive() {
        let (keyset, shares) = keyset_5_of_7();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 64, [0xCCu8; 32]);
        let qc = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[2, 3, 4, 6, 7], &m),
            &keyset,
            1,
            64,
            [0xCCu8; 32],
        )
        .expect("t-of-n 部分签名必须成型");
        assert_eq!(qc.signer_count(), 5);
        qc.verify(&keyset).expect("阈值 QC 必须通过组公钥验证");
        let qc6 = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[1, 2, 3, 4, 6, 7], &m),
            &keyset,
            1,
            64,
            [0xCCu8; 32],
        )
        .unwrap();
        qc6.verify(&keyset).unwrap();
        assert_eq!(keyset.group_pubkey_g2, keyset.commitments_g2[0]);
    }

    /// checkpoint 形态便捷入口：对 (epoch, height, state_root) 出 QC 并
    /// 验证；换任一字段即失败（域绑定）。
    #[test]
    fn threshold_qc_binds_checkpoint_fields() {
        let (keyset, shares) = keyset_5_of_7();
        let (epoch, height, root) = (3u64, 96u64, [0xD1u8; 32]);
        let msg = crate::consensus::checkpoint::checkpoint_qc_signing_hash(epoch, height, root);
        let qc = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[1, 2, 3, 4, 5], &msg),
            &keyset,
            epoch,
            height,
            root,
        )
        .unwrap();
        qc.verify(&keyset).expect("合法 checkpoint 阈值 QC 必须通过");
        let mut bad = qc.clone();
        bad.height = 97;
        assert!(bad.verify(&keyset).is_err(), "篡改 height 必须失败");
        let mut bad2 = qc.clone();
        bad2.state_root = [0xE1u8; 32];
        assert!(bad2.verify(&keyset).is_err(), "篡改 state_root 必须失败");
    }

    /// t-1 分片无法成型（InsufficientQuorum）；重复分片去重后同样不足。
    #[test]
    fn threshold_below_t_rejected() {
        let (keyset, shares) = keyset_5_of_7();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 64, [2u8; 32]);
        let err = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[1, 2, 3, 4], &m),
            &keyset,
            1,
            64,
            [2u8; 32],
        )
        .unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientQuorum { actual: 4, required: 5 }),
            "t-1 分片必须拒绝: {err:?}"
        );
        let five_dups: Vec<ThresholdPartial> =
            std::iter::repeat(partials(&shares, &[3], &m)[0].clone())
                .take(5)
                .collect();
        let err2 =
            ThresholdCheckpointQc::form_for_checkpoint(&five_dups, &keyset, 1, 64, [2u8; 32])
                .unwrap_err();
        assert!(matches!(err2, PokerL1Error::InsufficientQuorum { .. }));
    }

    /// 坏分片/伪造部分签名在聚合前被逐验拒绝；越界 id 拒。
    #[test]
    fn threshold_partial_forgery_rejected_before_aggregation() {
        let (keyset, shares) = keyset_5_of_7();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 64, [3u8; 32]);
        // 用分片 6 的签名冒充分片 5（换 id 标签）→ 对 pk_5 验证失败
        let mut ps = partials(&shares, &[1, 2, 3, 4, 5], &m);
        let sig6 = shares
            .iter()
            .find(|s| s.id == 6)
            .unwrap()
            .partial_sign(&m)
            .unwrap();
        ps[4].sig_g1 = sig6.to_vec();
        let err = ThresholdCheckpointQc::form_for_checkpoint(&ps, &keyset, 1, 64, [3u8; 32])
            .unwrap_err();
        assert!(
            err.to_string().contains("share 5"),
            "冒名部分签名必须在逐验阶段拒绝: {err:?}"
        );
        // 篡改一条部分签名字节 → 同样拒绝
        let mut ps2 = partials(&shares, &[1, 2, 3, 4, 5], &m);
        ps2[2].sig_g1[0] ^= 0x01;
        assert!(ThresholdCheckpointQc::form_for_checkpoint(&ps2, &keyset, 1, 64, [3u8; 32]).is_err());
        // 越界 id
        let mut ps3 = partials(&shares, &[1, 2, 3, 4], &m);
        ps3.push(ThresholdPartial {
            id: 8,
            sig_g1: ps3[0].sig_g1.clone(),
        });
        let err3 = ThresholdCheckpointQc::form_for_checkpoint(&ps3, &keyset, 1, 64, [3u8; 32])
            .unwrap_err();
        assert!(err3.to_string().contains("out of range"));
    }

    /// 成型后篡改聚合签名 → 验证拒（配对层）；t-1 个**合法**分片的
    /// Lagrange 组合 ≠ 组签名（门限性质的可验证面）。
    #[test]
    fn threshold_qc_tamper_and_below_t_unforgeable() {
        let (keyset, shares) = keyset_5_of_7();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 64, [4u8; 32]);
        let mut qc = ThresholdCheckpointQc::form_for_checkpoint(
            &partials(&shares, &[1, 2, 3, 4, 5], &m),
            &keyset,
            1,
            64,
            [4u8; 32],
        )
        .unwrap();
        qc.agg_signature_g1[0] ^= 0x01;
        assert!(qc.verify(&keyset).is_err(), "篡改聚合签名必须失败");
        qc.agg_signature_g1[0] ^= 0x01;
        qc.verify(&keyset).unwrap();

        let ids = [1u64, 2, 3, 4];
        let ps = partials(&shares, &ids, &m);
        let lambdas = lagrange_coefficients(&ids).unwrap();
        let sigs: Vec<[u8; 48]> = ps
            .iter()
            .map(|p| {
                let mut a = [0u8; 48];
                a.copy_from_slice(&p.sig_g1);
                a
            })
            .collect();
        let weights: Vec<[u8; 32]> = lambdas.iter().map(scalar_to_bytes).collect();
        let forged =
            crate::consensus::checkpoint::bls_aggregate_g1_weighted(&sigs, &weights).unwrap();
        let forged_qc = ThresholdCheckpointQc {
            epoch: 1,
            height: 64,
            state_root: [4u8; 32],
            signer_ids: ids.to_vec(),
            agg_signature_g1: forged.to_vec(),
        };
        assert!(
            forged_qc.verify(&keyset).is_err(),
            "t-1 合法分片的插值不得通过组公钥验证"
        );
    }

    /// VSS：好分片过验证；坏分片（篡改标量）被拒；id 越界报错。
    #[test]
    fn vss_share_verification() {
        let (keyset, shares) = deal_threshold(&[7u8; 32], 5, 3).unwrap();
        for s in &shares {
            assert!(keyset.verify_share(s).unwrap(), "dealer 分片必须全部过 VSS");
        }
        let mut bad = shares[2];
        bad.scalar[0] ^= 0x01;
        assert!(!keyset.verify_share(&bad).unwrap(), "篡改分片必须被 VSS 拒");
        let oob = ThresholdShare {
            id: 6,
            scalar: shares[0].scalar,
        };
        assert!(keyset.verify_share(&oob).is_err(), "越界 id 必须报错");
    }

    /// 参数与形状：非法 (n, t) 拒；keyset borsh/JSON 往返；t=1 退化情形
    /// 成立（单分片即组签名）；BFT 阈值映射。
    #[test]
    fn params_shapes_and_degenerate_t1() {
        assert!(deal_threshold(&[1u8; 32], 0, 1).is_err());
        assert!(deal_threshold(&[1u8; 32], 5, 0).is_err());
        assert!(deal_threshold(&[1u8; 32], 5, 6).is_err());
        let (keyset, _shares) = deal_threshold(&[2u8; 32], 4, 2).unwrap();
        let bytes = borsh::to_vec(&keyset).unwrap();
        let back: ThresholdKeyset = borsh::from_slice(&bytes).unwrap();
        assert_eq!(keyset, back);
        let j = serde_json::to_string(&keyset).unwrap();
        let jback: ThresholdKeyset = serde_json::from_str(&j).unwrap();
        assert_eq!(keyset, jback);
        // t=1：任何单个分片即组签名
        let (k1, s1) = deal_threshold(&[3u8; 32], 3, 1).unwrap();
        let m = crate::consensus::checkpoint::checkpoint_qc_signing_hash(1, 8, [5u8; 32]);
        let qc = ThresholdCheckpointQc::form_for_checkpoint(&partials(&s1, &[2], &m), &k1, 1, 8, [5u8; 32])
            .unwrap();
        qc.verify(&k1).unwrap();
        // BFT 映射：required_quorum(7) == 5、required_quorum(4) == 3
        assert_eq!(bft_threshold(7), 5);
        assert_eq!(bft_threshold(4), 3);
    }
}
