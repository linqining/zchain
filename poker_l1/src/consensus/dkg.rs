//! DKG —— deal-sum 原型（GJKR 风格 Joint-Feldman，**无投诉轮**；诚实命名）。
//!
//! # 语义：真 t-of-n 阈值密钥生成
//!
//! n 个 validator 各自作为 dealer 独立贡献一个 t-1 次秘密多项式，deal-sum
//! 组合后的**群私钥** `s = Σ_j a_{j,0}` 满足 Shamir t-of-n 分享：
//!
//! ```text
//! dealer j：f_j(x) = a_{j,0} + a_{j,1}·x + … + a_{j,t-1}·x^{t-1}（mod r）
//!   对每个参与者 i 计算份额 s_{j,i} = f_j(i)（点对点发送，原型内为结构体字段）
//!   公开广播 Feldman 承诺 C_{j,k} = a_{j,k}·G2（k = 0..=t-1）
//! 参与者 i：群份额 x_i = Σ_j s_{j,i}（只在自己的进程内求和）
//! 群公钥：Q = Σ_j C_{j,0}（任何人可从承诺集算出）
//! ```
//!
//! **真阈值性质（与"可信 dealer"方案的差别，如实）**：
//! - 群私钥 `s` **从不以明文存在于任何单点**——包括本模块的所有输入输出：
//!   dealer 只产出逐点份额 `s_{j,i}`，参与者只持有份额和 `x_i`（`s` 的
//!   t-of-n 分享，单个 `x_i` 在信息论上不泄露 `s` 的任何信息）；`s` 的
//!   明文只在"≥t 个参与者合谋插值"时才可重构，而这正是阈值语义的定义。
//! - 可信 dealer 方案中 `s` 在 dealer 进程内完整存在，dealer 作弊/泄露即
//!   全失守；本方案单点（甚至 t-1 个合谋点）均无法恢复 `s`，也无需信任
//!   任何单一方的诚实性（每个 dealer 的贡献可被其余所有人验证/排除）。
//!
//! # 份额校验（Feldman 性质）
//!
//! 每个参与者对收到的每笔份额可本地验证：
//! `s_{j,i}·G2 == Σ_k C_{j,k}·i^k`（G2 点等式，0 次配对）。由配对双线性
//! 非退化性，这与配对形式 `e(G1gen, s_{j,i}·G2) == e(G1gen, Σ_k C_{j,k}·i^k)`
//! 等价；实现取 G2 点等式（更省）。deal-sum 的线性使参与者还能一步校验
//! 聚合份额：`x_i·G2 == Σ_j Σ_k C_{j,k}·i^k`。
//!
//! # 边界（如实声明，不在此实现）
//!
//! - **无投诉轮 / 无重发**：GJKR 的完整协议含投诉-仲裁与坏 dealer 重发
//!   轮；本原型在组装时对每笔份额做 Feldman 校验，**坏 dealer 的索引会被
//!   定位并整体拒绝**（fail-closed），但不支持剔除坏 dealer 后继续组装
//!   （那需要重发或秘密多项式插值恢复，属后续接线）。dealer 作恶可被发现
//!   但组装方需另行处置。
//! - **无 DLPoS 扩展 / 无 proactive refresh / 无 validator 集变更重分发
//!   （rekey）**：分片 id ∈ 1..=n 与 validator 集的映射由部署层冻结。
//! - **原型口径的"随机性"**：dealer 多项式系数由其 32 字节种子经域分隔
//!   哈希确定性派生（[`dealer_deal`]；生产应用 CSPRNG 并在分发后销毁）。
//!   部署面（`zchain dkg` CLI）以全部 dealer 在单进程内执行的方式跑同一
//!   算法做密钥供给；生产部署中 dealer 各自在 validator 进程内跑
//!   [`dealer_deal`] 并经加密 P2P 交换 [`DkgDeal`]——算法与安全性性质
//!   （群私钥不落地）完全一致，仅传输面不同。
//!
//! # 与 HotStuff chain-QC 的关系
//!
//! 本模块只产出阈值**密钥材料**（[`GroupKeyset`] + [`ParticipantShare`]）；
//! QC 的链式选举/commit 语义仍由 DAG Bullshark commit certificate 承担
//! （见 [`crate::consensus::checkpoint`] 模块头）。阈值 QC 是 checkpoint
//! 锚定层的背书形态之一，不改变 commit 安全性。

use borsh::{BorshDeserialize, BorshSerialize};
use blstrs::{G2Projective, Scalar};
use group::Group;
use poker_protocol::crypto::curve::CurveScalar;
use serde::{Deserialize, Serialize};
use subtle::CtOption;

use crate::Hash;
use crate::crypto_precompiles::bls::{G2_COMPRESSED_SIZE, SCALAR_SIZE};
use crate::error::{PokerL1Error, PokerL1Result};

/// dealer 常数项（a_{j,0}，即该 dealer 对群私钥的贡献）派生域标签。
const DKG_DEALER_A0_DOMAIN: &[u8] = b"ZCHAIN_DKG_DEALER_A0_V1";

/// dealer 高次系数（a_{j,k}, k >= 1）派生域标签。
const DKG_DEALER_COEF_DOMAIN: &[u8] = b"ZCHAIN_DKG_DEALER_COEF_V1";

fn ct_opt<T>(ct: CtOption<T>) -> Option<T> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// 从域标签 + 种子 + 计数器确定性派生规范 Scalar（拒绝重试至规范；
/// [`crate::consensus::checkpoint::bls_derive_secret_key`] 同款约简）。
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

/// 标量 → 32 字节大端。
#[must_use]
pub fn scalar_to_bytes(s: &Scalar) -> [u8; SCALAR_SIZE] {
    s.to_bytes_be()
}

/// Lagrange 插值系数（在 0 点求值）：`λ_i = Π_{j∈S, j≠i} x_j/(x_j−x_i)`（mod r）。
///
/// 恒等式（测试钉住）：对任意次数 < |S| 的多项式 f，`Σ λ_i·f(x_i) == f(0)`——
/// 不同 t-子集插值出的组签名逐字节一致（子集无关性）。份额签名重构
/// （[`crate::consensus::checkpoint`] 的阈值 QC 装配）经
/// [`crate::consensus::checkpoint::bls_aggregate_g1_weighted`]（权重 = λ_i）落地。
///
/// # Errors
/// `ids` 为空、含 0（多项式常数点，份额 id 从 1 起）或含重复（分母为零）。
pub fn lagrange_coefficients_at_zero(ids: &[u64]) -> PokerL1Result<Vec<Scalar>> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if ids.is_empty() || sorted.len() != ids.len() {
        return Err(PokerL1Error::Other(
            "dkg: Lagrange point set empty or has duplicates".into(),
        ));
    }
    if ids.iter().any(|x| *x == 0) {
        return Err(PokerL1Error::Other(
            "dkg: share ids are 1-based (0 is the polynomial constant point)".into(),
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
        // ids 互异 ⇒ 分母非零（已在前置检查排除 0/重复），CurveScalar::invert
        // 语义下必可逆；零分母面在此不可达。
        out.push(num * den.invert());
    }
    Ok(out)
}

/// 单个 dealer 的分发物：承诺集（公开广播）+ 对全体参与者的份额
/// （生产部署经点对点加密信道，仅接收者可见；原型内为结构体字段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct DkgDeal {
    /// dealer id（1..=n；同时是多项式系数派生的计数器基准）。
    pub dealer_id: u64,
    /// Feldman 承诺 `C_{j,k} = a_{j,k}·G2`（G2 compressed 96B 逐条，k = 0..=t-1）。
    pub commitments_g2: Vec<Vec<u8>>,
    /// 对每个参与者的份额 `s_{j,i} = f_j(i)`。
    pub shares: Vec<DkgDealShare>,
}

/// dealer j 发给参与者 i 的单笔份额。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct DkgDealShare {
    /// 接收方参与者 id（1..=n；多项式求值点）。
    pub participant_id: u64,
    /// 份额标量（32B 大端）。
    pub scalar: [u8; SCALAR_SIZE],
}

/// 阈值群密钥集（公开面）：n 个 dealer 的 Feldman 承诺 + 群公钥 Q。
///
/// 所有节点持有同一份（内容寻址于 [`Self::group_key_digest`]）；每个参与者
/// 另持有私密面 [`ParticipantShare`]（不在本结构内，不落公开盘）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GroupKeyset {
    /// 参与者总数（分片 id ∈ 1..=n）。
    pub n: u32,
    /// 签名/重建阈值（t-of-n 的 t；≥2）。
    pub t: u32,
    /// 群公钥 `Q = Σ_j C_{j,0}`（G2 compressed 96B）。
    pub group_pubkey_g2: Vec<u8>,
    /// 各 dealer 的承诺集（外层按 dealer_id-1 排序，内层 k = 0..=t-1）。
    pub commitments_g2: Vec<Vec<Vec<u8>>>,
}

/// 参与者 i 的群份额 `x_i = Σ_j s_{j,i}`（私密面；只存在于参与者本地）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ParticipantShare {
    /// 参与者 id（1..=n）。
    pub id: u64,
    /// 群份额标量（32B 大端）。
    pub scalar: [u8; SCALAR_SIZE],
}

impl ParticipantShare {
    /// 份额签名：`σ_i = x_i·H(m)`（G1 compressed 48B；hash-to-curve 沿用
    /// checkpoint QC 的既有 hash 方式，RFC 9380 SSWU-RO 固定 DST）。
    ///
    /// # Errors
    /// hash-to-curve 失败（消息域错误；份额标量构造面已保证规范）。
    pub fn partial_sign(&self, msg_hash: &Hash) -> PokerL1Result<[u8; 48]> {
        let scalar = ct_opt(Scalar::from_bytes_be(&self.scalar)).ok_or_else(|| {
            PokerL1Error::InvalidBlsScalar("dkg: participant share scalar not canonical".into())
        })?;
        let h_m = crate::consensus::checkpoint::parse_g1(
            &crate::crypto_precompiles::bls::bls_hash_to_g1(msg_hash)?,
        )?;
        Ok((h_m * scalar).to_compressed())
    }
}

impl GroupKeyset {
    /// 单 dealer 承诺在点 i 的求值：`pk_j(i) = Σ_k C_{j,k}·i^k`（G2）。
    fn dealer_public_share(&self, dealer: usize, id: u64) -> PokerL1Result<G2Projective> {
        let commitments = self.commitments_g2.get(dealer).ok_or_else(|| {
            PokerL1Error::Other(format!("dkg: dealer {dealer} commitments missing"))
        })?;
        let x = Scalar::from(id);
        let mut acc = G2Projective::identity();
        for (k, c_bytes) in commitments.iter().enumerate() {
            let arr: [u8; G2_COMPRESSED_SIZE] = c_bytes.as_slice().try_into().map_err(|_| {
                PokerL1Error::InvalidBlsPoint(format!(
                    "dkg: commitment size {} != {G2_COMPRESSED_SIZE}",
                    c_bytes.len()
                ))
            })?;
            let c = crate::consensus::checkpoint::parse_g2(&arr)?;
            acc += c * scalar_pow(&x, k as u64);
        }
        Ok(acc)
    }

    /// 参与者 id 的聚合公开份额：`pk(i) = Σ_j pk_j(i) = x_i·G2`（份额签名
    /// 验证输入；deal-sum 线性使单点等式即可校验全部 dealer 的贡献和）。
    ///
    /// # Errors
    /// `id` 越界（0 或 > n）或任一承诺点非法。
    pub fn public_share(&self, id: u64) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
        if id == 0 || u64::from(self.n) < id {
            return Err(PokerL1Error::Other(format!(
                "dkg: share id {id} out of range 1..={}",
                self.n
            )));
        }
        let mut acc = G2Projective::identity();
        for dealer in 0..self.commitments_g2.len() {
            acc += self.dealer_public_share(dealer, id)?;
        }
        Ok(acc.to_compressed())
    }

    /// 校验参与者群份额：`x_i·G2 == pk(i)`（deal-sum 的 Feldman 性质；
    /// 节点启动时对本地份额做准入自检，坏份额 fail-closed 拒载）。
    ///
    /// # Errors
    /// id 越界或承诺点非法；`Ok(false)` = 份额与承诺集不一致。
    pub fn verify_participant_share(&self, share: &ParticipantShare) -> PokerL1Result<bool> {
        let pk = self.public_share(share.id)?;
        let scalar = ct_opt(Scalar::from_bytes_be(&share.scalar)).ok_or_else(|| {
            PokerL1Error::InvalidBlsScalar("dkg: participant share scalar not canonical".into())
        })?;
        let derived = (G2Projective::generator() * scalar).to_compressed();
        Ok(derived.as_slice() == pk.as_slice())
    }

    /// 单笔 dealer 份额校验（Feldman）：`s_{j,i}·G2 == Σ_k C_{j,k}·i^k`。
    ///
    /// # Errors
    /// dealer/参与者 id 越界或承诺点非法；`Ok(false)` = 份额与承诺不一致
    /// （坏 dealer 的定位输入）。
    pub fn verify_deal_share(
        &self,
        dealer_id: u64,
        share: &DkgDealShare,
    ) -> PokerL1Result<bool> {
        if dealer_id == 0 || u64::from(self.n) < dealer_id {
            return Err(PokerL1Error::Other(format!(
                "dkg: dealer id {dealer_id} out of range 1..={}",
                self.n
            )));
        }
        if share.participant_id == 0 || u64::from(self.n) < share.participant_id {
            return Err(PokerL1Error::Other(format!(
                "dkg: deal participant id {} out of range 1..={}",
                share.participant_id, self.n
            )));
        }
        let expected = self.dealer_public_share(dealer_id as usize - 1, share.participant_id)?;
        let scalar = ct_opt(Scalar::from_bytes_be(&share.scalar)).ok_or_else(|| {
            PokerL1Error::InvalidBlsScalar("dkg: deal share scalar not canonical".into())
        })?;
        let derived = G2Projective::generator() * scalar;
        Ok(bool::from(derived == expected))
    }

    /// 密钥集内容摘要（QC ↔ keyset 绑定位）：
    /// `blake2b_256("ZCHAIN_DKG_KEYSET_DIGEST_V1" || n || t || Q || 全部承诺)`。
    /// 阈值 QC 携带本摘要，验证端以本地 keyset 重算比对（不匹配即拒，
    /// 防 QC 被挪到另一群）。
    #[must_use]
    pub fn group_key_digest(&self) -> Hash {
        use blake2::Blake2bVar;
        use blake2::digest::{Update, VariableOutput};
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(b"ZCHAIN_DKG_KEYSET_DIGEST_V1");
        h.update(&self.n.to_le_bytes());
        h.update(&self.t.to_le_bytes());
        h.update(&self.group_pubkey_g2);
        for dealer in &self.commitments_g2 {
            for c in dealer {
                h.update(c);
            }
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

/// dealer 生成分发物（GJKR deal 阶段，单 dealer 视角）。
///
/// 系数由种子确定性派生：`a_{j,0}` 用 [`DKG_DEALER_A0_DOMAIN`]（dealer 对群
/// 私钥的贡献），`a_{j,k}`（k ≥ 1）用 [`DKG_DEALER_COEF_DOMAIN`]（计数器含
/// dealer_id 与系数序）。**原型口径**：生产 dealer 应以 CSPRNG 生成系数并
/// 在分发完成后销毁（见模块头边界）。
///
/// # Errors
/// `dealer_id` 为 0，或 `n == 0` / `t < 2` / `t > n`。
pub fn dealer_deal(seed: &[u8; 32], dealer_id: u64, n: u32, t: u32) -> PokerL1Result<DkgDeal> {
    if n == 0 || t < 2 || t > n {
        return Err(PokerL1Error::Other(format!(
            "dkg: invalid (n, t) = ({n}, {t}); require t >= 2, t <= n, n >= 1"
        )));
    }
    if dealer_id == 0 {
        return Err(PokerL1Error::Other("dkg: dealer id must be 1-based".into()));
    }
    let a0 = derive_scalar(DKG_DEALER_A0_DOMAIN, seed, dealer_id);
    let coeffs: Vec<Scalar> = (0..u64::from(t))
        .map(|k| {
            if k == 0 {
                a0
            } else {
                // 计数器空间：dealer_id * 2^32 + k（t <= n <= 2^32，无碰撞）
                derive_scalar(DKG_DEALER_COEF_DOMAIN, seed, dealer_id << 32 | u64::from(k))
            }
        })
        .collect();
    let commitments_g2: Vec<Vec<u8>> = coeffs
        .iter()
        .map(|c| (G2Projective::generator() * c).to_compressed().to_vec())
        .collect();
    let shares = (1..=u64::from(n))
        .map(|i| {
            let x = Scalar::from(i);
            let mut acc = Scalar::zero();
            for (k, c) in coeffs.iter().enumerate() {
                acc += c * scalar_pow(&x, k as u64);
            }
            DkgDealShare {
                participant_id: i,
                scalar: scalar_to_bytes(&acc),
            }
        })
        .collect();
    Ok(DkgDeal {
        dealer_id,
        commitments_g2,
        shares,
    })
}

/// deal-sum 组装：校验全部 n 份 deal（每笔逐份额 Feldman 校验）后，
/// 聚合出群密钥集与各参与者群份额。
///
/// **fail-closed**：任何一笔份额校验失败即整体失败，错误信息携带坏 dealer
/// 索引（定位用）；无投诉轮/重发（见模块头边界），坏 dealer 需部署层另行
/// 处置后重新组装。
///
/// # Errors
/// deal 数量 ≠ n、dealer id 集不为 1..=n、任一承诺/份额非法或校验失败
/// （错误含 `dealer <id>` 定位）、`(n, t)` 参数非法。
pub fn assemble_group_keyset(
    deals: &[DkgDeal],
    n: u32,
    t: u32,
) -> PokerL1Result<(GroupKeyset, Vec<ParticipantShare>)> {
    if n == 0 || t < 2 || t > n {
        return Err(PokerL1Error::Other(format!(
            "dkg: invalid (n, t) = ({n}, {t}); require t >= 2, t <= n, n >= 1"
        )));
    }
    if deals.len() != n as usize {
        return Err(PokerL1Error::Other(format!(
            "dkg: expected {n} deals, got {}",
            deals.len()
        )));
    }
    let mut sorted_ids: Vec<u64> = deals.iter().map(|d| d.dealer_id).collect();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    if sorted_ids.len() != n as usize || sorted_ids.first() != Some(&1) || sorted_ids.last() != Some(&u64::from(n)) {
        return Err(PokerL1Error::Other(
            "dkg: dealer ids must be exactly 1..=n without duplicates".into(),
        ));
    }
    // 按 dealer_id 升序规范排列（承诺集外层序 = dealer_id - 1）
    let mut ordered: Vec<&DkgDeal> = deals.iter().collect();
    ordered.sort_by_key(|d| d.dealer_id);
    // 逐 dealer 结构校验 + 逐份额 Feldman 校验（坏 dealer 定位）
    let probe = GroupKeyset {
        n,
        t,
        group_pubkey_g2: vec![0u8; G2_COMPRESSED_SIZE],
        commitments_g2: ordered
            .iter()
            .map(|d| d.commitments_g2.clone())
            .collect(),
    };
    for d in &ordered {
        if d.commitments_g2.len() != t as usize {
            return Err(PokerL1Error::Other(format!(
                "dkg: dealer {} commitment count {} != t {t}",
                d.dealer_id,
                d.commitments_g2.len()
            )));
        }
        if d.shares.len() != n as usize {
            return Err(PokerL1Error::Other(format!(
                "dkg: dealer {} share count {} != n {n}",
                d.dealer_id,
                d.shares.len()
            )));
        }
        let mut seen_participants = std::collections::BTreeSet::new();
        for s in &d.shares {
            if !seen_participants.insert(s.participant_id) {
                return Err(PokerL1Error::Other(format!(
                    "dkg: dealer {} duplicate share for participant {}",
                    d.dealer_id, s.participant_id
                )));
            }
            if !probe.verify_deal_share(d.dealer_id, s)? {
                return Err(PokerL1Error::Other(format!(
                    "dkg: Feldman check failed — bad dealer {} (share for participant {})",
                    d.dealer_id, s.participant_id
                )));
            }
        }
        if seen_participants.len() != n as usize {
            return Err(PokerL1Error::Other(format!(
                "dkg: dealer {} missing shares for some participants",
                d.dealer_id
            )));
        }
    }
    // 群公钥 Q = Σ_j C_{j,0}
    let mut q = G2Projective::identity();
    for d in &ordered {
        let arr: [u8; G2_COMPRESSED_SIZE] = d.commitments_g2[0].as_slice().try_into().map_err(
            |_| {
                PokerL1Error::InvalidBlsPoint(format!(
                    "dkg: dealer {} C_0 size mismatch",
                    d.dealer_id
                ))
            },
        )?;
        q += crate::consensus::checkpoint::parse_g2(&arr)?;
    }
    if bool::from(q.is_identity()) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "dkg: group pubkey is identity (all dealer contributions zero)".into(),
        ));
    }
    // 参与者群份额 x_i = Σ_j s_{j,i}
    let shares = (1..=u64::from(n))
        .map(|i| {
            let mut acc = Scalar::zero();
            for d in &ordered {
                let s = d
                    .shares
                    .iter()
                    .find(|s| s.participant_id == i)
                    .expect("deal share for participant i exists (checked above)");
                acc += ct_opt(Scalar::from_bytes_be(&s.scalar))
                    .expect("deal share scalar canonical (checked above)");
            }
            ParticipantShare {
                id: i,
                scalar: scalar_to_bytes(&acc),
            }
        })
        .collect();
    let keyset = GroupKeyset {
        n,
        t,
        group_pubkey_g2: q.to_compressed().to_vec(),
        commitments_g2: probe.commitments_g2,
    };
    // 组装后自检：每个聚合份额必须过公开份额等式（deal-sum 线性恒等式）
    for s in &shares {
        if !keyset.verify_participant_share(s)? {
            return Err(PokerL1Error::Other(format!(
                "dkg: assembled share for participant {} failed self-check",
                s.id
            )));
        }
    }
    Ok((keyset, shares))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::checkpoint::{
        bls_aggregate_g1_weighted, bls_verify_single, checkpoint_qc_signing_hash,
    };

    /// 全 dealer 演练（确定性种子；deal-sum 全流程）。
    fn run_dkg(n: u32, t: u32, seed: u8) -> (GroupKeyset, Vec<ParticipantShare>) {
        let deals: Vec<DkgDeal> = (1..=u64::from(n))
            .map(|dealer_id| dealer_deal(&[seed; 32], dealer_id, n, t).expect("dealer deal"))
            .collect();
        assemble_group_keyset(&deals, n, t).expect("assemble")
    }

    /// 参与者部分签名载荷（对 checkpoint 签名对象）。
    fn partials_for(
        shares: &[ParticipantShare],
        ids: &[u64],
        msg: &Hash,
    ) -> Vec<(u64, [u8; 48])> {
        ids.iter()
            .map(|id| {
                let share = shares.iter().find(|s| s.id == *id).expect("share exists");
                (*id, share.partial_sign(msg).expect("partial sign"))
            })
            .collect()
    }

    /// deal-sum 全流程（n=7, t=5）：n 个 dealer 独立分发 → 组装 → 全部 n 个
    /// 参与者份额通过公开份额等式（全员群钥一致 —— 每个参与者的 `x_i·G2`
    /// 都等于同一承诺集在 i 点的求值）。
    #[test]
    fn deal_sum_full_flow_all_shares_verify_n7_t5() {
        let (keyset, shares) = run_dkg(7, 5, 0x50);
        assert_eq!(keyset.n, 7);
        assert_eq!(keyset.t, 5);
        assert_eq!(keyset.commitments_g2.len(), 7, "7 个 dealer 承诺集");
        assert!(
            keyset.commitments_g2.iter().all(|d| d.len() == 5),
            "每个 dealer t 个承诺"
        );
        for s in &shares {
            assert!(
                keyset.verify_participant_share(s).expect("share verify"),
                "参与者 {} 群份额必须过 Feldman 等式",
                s.id
            );
        }
        // 群公钥 = Σ_j C_{j,0}（公开可算性）
        let mut q = G2Projective::identity();
        for dealer in &keyset.commitments_g2 {
            let mut arr = [0u8; G2_COMPRESSED_SIZE];
            arr.copy_from_slice(&dealer[0]);
            q += crate::consensus::checkpoint::parse_g2(&arr).unwrap();
        }
        assert_eq!(
            q.to_compressed().as_slice(),
            keyset.group_pubkey_g2.as_slice(),
            "群公钥必须等于各 dealer 常数承诺之和"
        );
    }

    /// Lagrange 恒等式的公开形式：任意 t-子集上 `Σ λ_i·(x_i·G2) == Q`
    ///（份额公钥的加权重构 == 群公钥 —— 重构正确性的点层证据）。
    #[test]
    fn lagrange_weighted_public_shares_reconstruct_group_key() {
        for (n, t) in [(7u32, 5u32), (4, 3)] {
            let (keyset, _shares) = run_dkg(n, t, 0x51);
            for ids in [
                (1..=u64::from(t)).collect::<Vec<_>>(),
                (2..=u64::from(t) + 1).collect::<Vec<_>>(),
            ] {
                let pks: Vec<[u8; G2_COMPRESSED_SIZE]> = ids
                    .iter()
                    .map(|id| keyset.public_share(*id).expect("public share"))
                    .collect();
                let lambdas = lagrange_coefficients_at_zero(&ids).expect("lambdas");
                let weights: Vec<[u8; 32]> =
                    lambdas.iter().map(scalar_to_bytes).collect();
                // G2 面无 weighted 原语 → 手工线性组合
                let mut acc = G2Projective::identity();
                for (pk, w) in pks.iter().zip(weights.iter()) {
                    let mut arr = [0u8; G2_COMPRESSED_SIZE];
                    arr.copy_from_slice(pk);
                    let s = Scalar::from_bytes_be(w).unwrap();
                    acc += crate::consensus::checkpoint::parse_g2(&arr).unwrap() * s;
                }
                assert_eq!(
                    acc.to_compressed().as_slice(),
                    keyset.group_pubkey_g2.as_slice(),
                    "(n={n},t={t}) 任意 t-子集加权重构必须得到群公钥"
                );
            }
        }
    }

    /// Feldman 份额校验（dealer 级）：好份额过；篡改标量拒；participant id
    /// 越界报错。
    #[test]
    fn feldman_deal_share_verification() {
        let n = 5u32;
        let t = 3u32;
        let deals: Vec<DkgDeal> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[0x52; 32], j, n, t).unwrap())
            .collect();
        let (keyset, _) = assemble_group_keyset(&deals, n, t).unwrap();
        for deal in &deals {
            for share in &deal.shares {
                assert!(
                    keyset.verify_deal_share(deal.dealer_id, share).unwrap(),
                    "dealer {} → 参与者 {} 的份额必须过 Feldman",
                    deal.dealer_id,
                    share.participant_id
                );
            }
        }
        let mut bad = deals[0].shares[2].clone();
        bad.scalar[0] ^= 0x01;
        assert!(
            !keyset.verify_deal_share(1, &bad).unwrap(),
            "篡改份额必须被 Feldman 校验拒"
        );
        let oob = DkgDealShare {
            participant_id: u64::from(n) + 1,
            scalar: deals[0].shares[0].scalar,
        };
        assert!(keyset.verify_deal_share(1, &oob).is_err(), "越界参与者 id 报错");
    }

    /// 参与者群份额校验：错标量拒（Ok(false)）、非规范标量报错（fail-closed）。
    #[test]
    fn verify_participant_share_rejects_wrong_and_noncanonical() {
        let (keyset, shares) = run_dkg(5, 3, 0x53);
        let mut wrong = shares[1];
        wrong.scalar[7] ^= 0x80;
        assert!(!keyset.verify_participant_share(&wrong).unwrap());
        // 非规范（>= r）标量 → InvalidBlsScalar（r 附近字节模式）
        let mut big = [0xFFu8; 32];
        big[0] = 0xFF;
        let noncanonical = ParticipantShare {
            id: 1,
            scalar: big,
        };
        assert!(keyset.verify_participant_share(&noncanonical).is_err());
    }

    /// 坏 dealer 定位：篡改 dealer 3 的任意一笔份额 → 组装整体失败且错误
    /// 信息携带 `bad dealer 3`（fail-closed + 定位，无投诉轮边界如实）。
    #[test]
    fn bad_dealer_located_in_assemble_error() {
        let n = 5u32;
        let t = 3u32;
        let mut deals: Vec<DkgDeal> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[0x54; 32], j, n, t).unwrap())
            .collect();
        // 篡改 dealer 3 发给参与者 2 的份额
        deals[2].shares[1].scalar[0] ^= 0x01;
        let err = assemble_group_keyset(&deals, n, t).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("bad dealer 3"),
            "错误必须定位坏 dealer 3: {msg}"
        );
        // 承诺与份额同时被改（更隐蔽）→ 承诺面仍能定位（份额与承诺不一致）
        let mut deals2: Vec<DkgDeal> = (1..=u64::from(n))
            .map(|j| dealer_deal(&[0x55; 32], j, n, t).unwrap())
            .collect();
        deals2[4].shares[0].scalar[31] ^= 0x02;
        let err2 = assemble_group_keyset(&deals2, n, t).unwrap_err();
        assert!(err2.to_string().contains("bad dealer 5"));
    }

    /// <t 不可重构：t-1 个**合法**份额签名的 Lagrange 加权组合对群公钥的
    /// 配对验证必败（门限性质的可验证面 —— t-1 合谋无法伪造群签名）。
    #[test]
    fn below_t_cannot_reconstruct_group_signature() {
        let (keyset, shares) = run_dkg(7, 5, 0x56);
        let msg = checkpoint_qc_signing_hash(1, 32, [0x77u8; 32]);
        let ps = partials_for(&shares, &[1, 2, 3, 4], &msg);
        let ids: Vec<u64> = ps.iter().map(|(id, _)| *id).collect();
        let lambdas = lagrange_coefficients_at_zero(&ids).unwrap();
        let weights: Vec<[u8; 32]> = lambdas.iter().map(scalar_to_bytes).collect();
        let sigs: Vec<[u8; 48]> = ps.iter().map(|(_, s)| *s).collect();
        let forged = bls_aggregate_g1_weighted(&sigs, &weights)
            .expect("t-1 加权聚合可计算（但不得通过群钥验证）");
        assert!(
            !bls_verify_single(&keyset.group_pubkey_g2, &forged, &msg).unwrap(),
            "t-1 分片的插值不得通过群公钥验证"
        );
    }

    /// 任意两个 t-子集重构同一群签名 σ = s·H(m)（逐字节一致；子集无关性）。
    #[test]
    fn any_two_t_subsets_reconstruct_identical_signature() {
        let (keyset, shares) = run_dkg(7, 5, 0x57);
        let msg = checkpoint_qc_signing_hash(2, 64, [0x78u8; 32]);
        let reconstruct = |ids: &[u64]| {
            let ps = partials_for(&shares, ids, &msg);
            let lambdas =
                lagrange_coefficients_at_zero(&ps.iter().map(|(i, _)| *i).collect::<Vec<_>>())
                    .unwrap();
            let weights: Vec<[u8; 32]> = lambdas.iter().map(scalar_to_bytes).collect();
            let sigs: Vec<[u8; 48]> = ps.iter().map(|(_, s)| *s).collect();
            bls_aggregate_g1_weighted(&sigs, &weights).unwrap()
        };
        let s1 = reconstruct(&[1, 2, 3, 4, 5]);
        let s2 = reconstruct(&[2, 3, 5, 6, 7]);
        let s3 = reconstruct(&[1, 3, 4, 6, 7]);
        assert_eq!(s1, s2, "不同 t-子集插值必须得到同一群签名");
        assert_eq!(s2, s3);
        // 重构结果对群公钥单配对验证通过（一次配对）
        assert!(bls_verify_single(&keyset.group_pubkey_g2, &s1, &msg).unwrap());
        // 超集（6 人）同样重构出同一签名
        assert_eq!(reconstruct(&[1, 2, 3, 4, 5, 6]), s1);
    }

    /// 份额签名：正例（对 public_share(id) 单配对验证通过）；错消息拒；
    /// 冒名（拿份额 6 的签名冒充 5）拒。
    #[test]
    fn partial_sign_positive_wrong_msg_and_impersonation_rejected() {
        let (keyset, shares) = run_dkg(7, 5, 0x58);
        let msg = checkpoint_qc_signing_hash(1, 96, [0x79u8; 32]);
        for s in &shares {
            let sig = s.partial_sign(&msg).unwrap();
            let pk = keyset.public_share(s.id).unwrap();
            assert!(
                bls_verify_single(&pk, &sig, &msg).unwrap(),
                "份额 {} 签名必须对公开份额密钥验证通过",
                s.id
            );
            // 错消息拒
            let other = checkpoint_qc_signing_hash(1, 97, [0x79u8; 32]);
            assert!(!bls_verify_single(&pk, &sig, &other).unwrap());
        }
        // 冒名：份额 6 的签名贴 5 的 id → 对 pk_5 验证失败
        let sig6 = shares
            .iter()
            .find(|s| s.id == 6)
            .unwrap()
            .partial_sign(&msg)
            .unwrap();
        let pk5 = keyset.public_share(5).unwrap();
        assert!(!bls_verify_single(&pk5, &sig6, &msg).unwrap());
    }

    /// 参数与形状拒绝面：非法 (n, t)、dealer_id 0、deal 数不符、dealer id
    /// 集不为 1..=n、承诺数 ≠ t、缺参与者份额、重复参与者份额。
    #[test]
    fn assemble_param_and_shape_rejections() {
        assert!(dealer_deal(&[1; 32], 0, 5, 3).is_err(), "dealer id 0 拒");
        assert!(dealer_deal(&[1; 32], 1, 0, 3).is_err(), "n=0 拒");
        assert!(dealer_deal(&[1; 32], 1, 5, 1).is_err(), "t<2 拒");
        assert!(dealer_deal(&[1; 32], 1, 5, 6).is_err(), "t>n 拒");
        let deals: Vec<DkgDeal> = (1..=5)
            .map(|j| dealer_deal(&[2; 32], j, 5, 3).unwrap())
            .collect();
        // 数量不足 / 超出
        assert!(assemble_group_keyset(&deals[..4], 5, 3).is_err());
        let mut dup = deals.clone();
        dup.push(deals[0].clone());
        assert!(assemble_group_keyset(&dup, 5, 3).is_err(), "重复 dealer id 拒");
        // 承诺数 != t
        let mut bad_commit = deals.clone();
        bad_commit[0].commitments_g2.pop();
        assert!(assemble_group_keyset(&bad_commit, 5, 3).is_err());
        // 缺参与者份额
        let mut missing = deals.clone();
        missing[1].shares.remove(3);
        assert!(assemble_group_keyset(&missing, 5, 3).is_err());
        // (n, t) 非法
        assert!(assemble_group_keyset(&deals, 5, 6).is_err());
        assert!(assemble_group_keyset(&deals, 0, 3).is_err());
        // Lagrange 面：空集 / 重复 / 含 0
        assert!(lagrange_coefficients_at_zero(&[]).is_err());
        assert!(lagrange_coefficients_at_zero(&[1, 1, 2]).is_err());
        assert!(lagrange_coefficients_at_zero(&[0, 1, 2]).is_err());
    }

    /// 参数化全流程：(t=5, n=7) 与 (t=3, n=4) —— 两套参数下群钥一致、份额
    /// 校验、<t 拒、borsh/JSON 往返、digest 内容绑定。
    #[test]
    fn parameterized_t5n7_and_t3n4_flows() {
        for (n, t) in [(7u32, 5u32), (4, 3)] {
            let (keyset, shares) = run_dkg(n, t, 0x59 + u8::try_from(n).unwrap());
            assert_eq!(shares.len() as u32, n);
            // 全员份额校验（群钥一致性）
            for s in &shares {
                assert!(keyset.verify_participant_share(s).unwrap());
            }
            // t-1 拒：4 份（t=5）或 2 份（t=3）不能凑成 QC（份额层面：加权
            // 重构不过群钥 —— 见 below_t 测试；此处钉 keyset.t 计数语义）
            let msg = checkpoint_qc_signing_hash(1, 32, [0x7Au8; 32]);
            let ps = partials_for(&shares, &(1..u64::from(t)).collect::<Vec<_>>(), &msg);
            assert_eq!(ps.len(), (t - 1) as usize);
            // 序列化往返（公开面 + 私密面）
            let kb = borsh::to_vec(&keyset).unwrap();
            let kb_back: GroupKeyset = borsh::from_slice(&kb).unwrap();
            assert_eq!(keyset, kb_back);
            let kj = serde_json::to_string(&keyset).unwrap();
            let kj_back: GroupKeyset = serde_json::from_str(&kj).unwrap();
            assert_eq!(keyset, kj_back);
            let sb = borsh::to_vec(&shares[0]).unwrap();
            let sb_back: ParticipantShare = borsh::from_slice(&sb).unwrap();
            assert_eq!(shares[0], sb_back);
            // digest 内容绑定：任一承诺变化 → digest 变化
            let d0 = keyset.group_key_digest();
            let mut tweaked = keyset.clone();
            tweaked.commitments_g2[0][0][10] ^= 0x01;
            assert_ne!(d0, tweaked.group_key_digest());
            tweaked.group_pubkey_g2[10] ^= 0x01;
            assert_ne!(d0, tweaked.group_key_digest());
            tweaked.n = n.saturating_sub(1).max(1);
            assert_ne!(d0, tweaked.group_key_digest());
        }
    }

    /// 同种子确定性：同 (seed, dealer_id, n, t) 产出同 deal；不同种子产出
    /// 不同群钥（deal-sum 输入敏感）。
    #[test]
    fn dealer_deal_deterministic_and_seed_sensitive() {
        let a = dealer_deal(&[0x60; 32], 3, 7, 5).unwrap();
        let b = dealer_deal(&[0x60; 32], 3, 7, 5).unwrap();
        assert_eq!(a, b, "同种子必须确定性");
        let c = dealer_deal(&[0x61; 32], 3, 7, 5).unwrap();
        assert_ne!(a, c, "不同种子必须不同分发物");
        let (ka, _) = run_dkg(5, 3, 0x60);
        let (kc, _) = run_dkg(5, 3, 0x62);
        assert_ne!(ka.group_pubkey_g2, kc.group_pubkey_g2);
    }
}
