//! M8：watcher——等价性/分叉检测与链-证明注册表一致性审计。
//!
//! 软确认的信任支点是"sequencer 说话算数"（plan §安全五前提）：watcher
//! 独立验证 (a) 软确认链签名与接续，(b) 两条链导出的等价性（分叉定位），
//! (c) 每条 Settle 操作都有对应证明批次覆盖。任何玩家/第三方可运行。
//!
//! # 入金来源筛查（TEC-v1 §5 AML 落点）
//!
//! REAL 域入金的**来源筛查**（制裁名单 / 混合器 / 自排除等）按设计
//! "不在链上"——由 watcher 在确认外部支付时前置执行：命中或数据源不可用
//! → **不确认、不产生 deposit_id**，链上无该笔入金的任何痕迹。接口
//! fail-closed：[`confirm_deposit`] 未配置数据源时同样拒绝。sequencer 侧
//! 的市场/token/限额准入（[`crate::compliance`]）与本筛查互补而非重叠：
//! 前者管"谁能在本市场入多少"，本节管"这笔钱从哪来"。

use std::collections::{BTreeSet, HashSet};

use crate::error::AppchainError;
use crate::keys::blake2s32;
use crate::ops::Operation;
use crate::soft_confirm::SignedFrame;

/// 审计报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherReport {
    /// 检查帧数。
    pub frames_checked: usize,
    /// 分叉位置（两条链导出比较时）。
    pub fork_at: Option<u64>,
    /// 未被证明覆盖的结算绑定（活性问题信号）。
    pub uncovered_settlements: Vec<[u8; 32]>,
}

/// 验证单条链的完整性（签名 + 接续），返回 (首帧 index, 末帧 hash) 供比较。
///
/// # Errors
/// 链断裂/签名坏 → 对应错误。
pub fn audit_chain(
    frames: &[SignedFrame],
    sequencer_public: &[u8; 32],
) -> crate::error::AppchainResult<()> {
    crate::soft_confirm::verify_chain(frames, sequencer_public)
}

/// 两条链导出的等价性比较：返回首个分叉帧 index（None = 等价）。
///
/// 等价定义：相同 index 的帧哈希一致。攻击者（或被入侵的 sequencer）
/// 向不同受害者展示不同软确认历史时，两边导出在此处必然分裂。
#[must_use]
pub fn compare_chains(a: &[SignedFrame], b: &[SignedFrame]) -> Option<u64> {
    let n = a.len().min(b.len());
    for i in 0..n {
        let ha = a[i].hash().ok()?;
        let hb = b[i].hash().ok()?;
        if ha != hb {
            return Some(a[i].frame.index);
        }
    }
    // 前缀一致但长度不同：不算分叉（截断是活性问题，等价性仍成立）
    None
}

/// 审计结算覆盖：链内每个 Settle 操作的 hand_binding 必须出现在
/// 已证明绑定集合（证明注册表导出）中。
///
/// 缺失 = 证明积压（活性问题，非资金问题）；报告列出便于 SLA 追踪。
#[must_use]
pub fn audit_settlement_coverage(
    frames: &[SignedFrame],
    proven_bindings: &HashSet<[u8; 32]>,
) -> WatcherReport {
    let mut uncovered = Vec::new();
    for f in frames {
        if let Operation::Settle(record) = &f.frame.op {
            if !proven_bindings.contains(&record.hand_binding) {
                uncovered.push(record.hand_binding);
            }
        }
    }
    WatcherReport {
        frames_checked: frames.len(),
        fork_at: None,
        uncovered_settlements: uncovered,
    }
}

/// 分叉报告（M8-ACC-6）：比较 + 若分叉则立即返回错误语义的报告。
#[must_use]
pub fn fork_report(a: &[SignedFrame], b: &[SignedFrame]) -> WatcherReport {
    let fork_at = compare_chains(a, b);
    WatcherReport {
        frames_checked: a.len().max(b.len()),
        fork_at,
        uncovered_settlements: Vec::new(),
    }
}

/// 分叉即错误（供 CI/告警路径直接使用）。
///
/// # Errors
/// 分叉 → [`AppchainError::ForkDetected`]。
pub fn require_equivalent(a: &[SignedFrame], b: &[SignedFrame]) -> crate::error::AppchainResult<()> {
    match compare_chains(a, b) {
        Some(idx) => Err(AppchainError::ForkDetected(idx)),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// 入金来源筛查（TEC-v1 §5：watcher 入金前置，fail-closed，明确"不在链上"）
// ---------------------------------------------------------------------------

/// 入金来源筛查的域分离标签（deposit_id 派生）。
const DOMAIN_WATCHER_DEPOSIT: &[u8] = b"watcher.deposit.v1";

/// 入金来源描述：一笔外部链支付的唯一标识。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSource {
    /// 源链 id（口径由运营方约定；筛查数据源按此解释 address 编码）。
    pub chain_id: u64,
    /// 源地址原始字节（原链格式；数据源负责解码与归一化）。
    pub address: Vec<u8>,
    /// 源链支付 tx hash（混合器关联分析的关联键）。
    pub tx_hash: [u8; 32],
}

/// 筛查数据源不可用（网络/服务故障）。
///
/// fail-closed 语义：调用方收到 `Err` 时必须**拒绝**入金确认——
/// "查不到"与"查过了没问题"必须可区分。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreeningSourceError {
    /// 不可用原因（运营排障用；不进链）。
    pub reason: String,
}

/// 可插拔筛查数据源：制裁名单（OFAC 等）、混合器地址集、RG 自排除、
/// Chainalysis/TRM 类商业 API 适配器……
///
/// 实现契约（fail-closed 的关键）：
/// - `Ok(true)` = 命中拒绝；
/// - `Ok(false)` = 查询成功且未命中（放行）；
/// - `Err` = 数据源不可用（调用方拒绝入金确认，绝不放行）。
pub trait DepositScreeningSource: Send + Sync {
    /// 筛查一笔入金来源。
    ///
    /// # Errors
    /// 数据源不可用 → [`ScreeningSourceError`]（调用方 fail-closed）。
    fn screen(&self, source: &DepositSource) -> Result<bool, ScreeningSourceError>;
}

/// 静态拒绝名单（源地址 32B 键 = `blake2s32(b"watcher.deny.v1" || address)`；
/// RG 自排除 / 小型制裁集合；大型名单用外部数据源实现同一 trait）。
#[derive(Debug, Clone, Default)]
pub struct StaticDenylist {
    entries: BTreeSet<[u8; 32]>,
}

impl StaticDenylist {
    /// 地址原始字节 → 名单键。
    #[must_use]
    pub fn address_key(address: &[u8]) -> [u8; 32] {
        blake2s32(&[b"watcher.deny.v1", address])
    }

    /// 由地址迭代器构造名单。
    #[must_use]
    pub fn from_addresses<'a>(addresses: impl Iterator<Item = &'a [u8]>) -> Self {
        Self {
            entries: addresses.map(Self::address_key).collect(),
        }
    }
}

impl DepositScreeningSource for StaticDenylist {
    fn screen(&self, source: &DepositSource) -> Result<bool, ScreeningSourceError> {
        Ok(self.entries.contains(&Self::address_key(&source.address)))
    }
}

/// 始终不可用的数据源（fail-closed 语义的显式测试与降级演练用）。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableSource;

impl DepositScreeningSource for UnavailableSource {
    fn screen(&self, _source: &DepositSource) -> Result<bool, ScreeningSourceError> {
        Err(ScreeningSourceError {
            reason: "screening source unavailable (drill/stub)".into(),
        })
    }
}

/// 筛查裁决（Deny 的原因运营可观测，但一律不出现在链上）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreeningVerdict {
    /// 未命中且查询成功：放行。
    Allow,
    /// 拒绝确认入金。
    Deny(ScreeningDenyReason),
}

/// 拒绝原因（仅运营侧日志/指标；链上无痕）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreeningDenyReason {
    /// 未配置筛查数据源（部署错误：fail-closed 拒绝一切入金确认）。
    NoSourceConfigured,
    /// 数据源不可用（网络/服务故障：fail-closed）。
    SourceUnavailable,
    /// 命中名单（制裁/混合器/自排除）。
    SanctionHit,
}

/// fail-closed 筛查：数据源未配置 / 查询失败 / 命中 → [`Deny`]。
#[must_use]
pub fn screen_deposit(
    source: &DepositSource,
    screening: Option<&dyn DepositScreeningSource>,
) -> ScreeningVerdict {
    let Some(screening) = screening else {
        return ScreeningVerdict::Deny(ScreeningDenyReason::NoSourceConfigured);
    };
    match screening.screen(source) {
        Ok(true) => ScreeningVerdict::Deny(ScreeningDenyReason::SanctionHit),
        Ok(false) => ScreeningVerdict::Allow,
        Err(_) => ScreeningVerdict::Deny(ScreeningDenyReason::SourceUnavailable),
    }
}

/// watcher 入金确认：筛查放行才产生 deposit_id。
///
/// - `Some(id)`：确认入金。`id = blake2s32(DOMAIN || chain_id || address ||
///   tx_hash || owner)`——对同一 (来源, owner) 确定性幂等，可直接作为
///   [`Operation::Deposit`] / `DepositV2` 的 `deposit_id`。
/// - `None`：命中名单 / 数据源不可用 / 未配置数据源——**不确认、不产生
///   deposit_id**（TEC-v1 §5：链上无该笔入金任何痕迹；运营侧留
///   [`ScreeningDenyReason`] 日志即可）。
#[must_use]
pub fn confirm_deposit(
    source: &DepositSource,
    owner: &[u8],
    screening: Option<&dyn DepositScreeningSource>,
) -> Option<[u8; 32]> {
    match screen_deposit(source, screening) {
        ScreeningVerdict::Allow => Some(blake2s32(&[
            DOMAIN_WATCHER_DEPOSIT,
            &source.chain_id.to_be_bytes(),
            &source.address,
            &source.tx_hash,
            owner,
        ])),
        ScreeningVerdict::Deny(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee::FeePolicy;
    use crate::keys::SequencerKey;
    use crate::ops::Operation;
    use crate::soft_confirm::{genesis_prev_hash, SoftConfirmFrame};

    fn chain(key: &SequencerKey, n: u64, salt: u8) -> Vec<SignedFrame> {
        let mut out = Vec::new();
        let mut prev = genesis_prev_hash();
        for i in 0..n {
            let f = SignedFrame::sign(
                SoftConfirmFrame {
                    index: i,
                    prev_hash: prev,
                    op: Operation::OpenTable {
                        table_id: i + 1,
                        policy: FeePolicy::Zero,
                    },
                    state_root: [salt; 32],
                    ts_ms: 1_000 + i,
                },
                key,
            )
            .unwrap();
            prev = f.hash().unwrap();
            out.push(f);
        }
        out
    }

    #[test]
    fn equivalent_chains_pass() {
        let key = SequencerKey::from_seed(&[1; 32]);
        let c = chain(&key, 5, 1);
        assert!(require_equivalent(&c, &c).is_ok());
    }

    #[test]
    fn divergent_chains_detected_at_index() {
        let key = SequencerKey::from_seed(&[1; 32]);
        let a = chain(&key, 5, 1);
        let b = chain(&key, 5, 2); // 不同 state_root
        let r = fork_report(&a, &b);
        assert_eq!(r.fork_at, Some(0));
        assert!(require_equivalent(&a, &b).is_err());
    }

    #[test]
    fn prefix_chain_is_not_fork() {
        let key = SequencerKey::from_seed(&[1; 32]);
        let full = chain(&key, 5, 1);
        let truncated = full[..3].to_vec();
        assert!(require_equivalent(&full, &truncated).is_ok());
    }

    #[test]
    fn settlement_coverage_reported() {
        let key = SequencerKey::from_seed(&[1; 32]);
        let mut binding = [7u8; 32];
        let record = crate::settlement::SettlementRecord {
            table_id: 1,
            hand_binding: binding,
            policy_commitment: [0; 32],
            pot: 1,
            inputs: Vec::new(),
            payouts: Vec::new(),
            rake: crate::settlement::RakeSplitRecord {
                total: 0,
                treasury_out: None,
                operator_out: None,
            },
            plan: crate::settlement::flat_settlement_plan(1, 0b01, {
                let mut awards = [0u64; 9];
                awards[0] = 1;
                awards
            }),
            hand_proof: None,
        };
        let f = SignedFrame::sign(
            SoftConfirmFrame {
                index: 0,
                prev_hash: genesis_prev_hash(),
                op: Operation::Settle(Box::new(record)),
                state_root: [0; 32],
                ts_ms: 0,
            },
            &key,
        )
        .unwrap();
        let _ = &mut binding;
        let mut proven = HashSet::new();
        let r = audit_settlement_coverage(std::slice::from_ref(&f), &proven);
        assert_eq!(r.uncovered_settlements.len(), 1);
        proven.insert([7u8; 32]);
        let r = audit_settlement_coverage(std::slice::from_ref(&f), &proven);
        assert!(r.uncovered_settlements.is_empty());
    }
}
    // ===== 入金来源筛查（TEC-v1 §5：fail-closed，命中不产生 deposit_id）=====

    fn src_address(addr: u8) -> DepositSource {
        DepositSource {
            chain_id: 1,
            address: vec![addr; 20],
            tx_hash: [addr; 32],
        }
    }

    #[test]
    fn clean_source_produces_deterministic_deposit_id() {
        let deny = StaticDenylist::from_addresses(std::iter::once(&b"sanctioned"[..]));
        let s = src_address(0xAA);
        let id1 = confirm_deposit(&s, &[1u8; 32], Some(&deny));
        let id2 = confirm_deposit(&s, &[1u8; 32], Some(&deny));
        assert!(id1.is_some(), "干净来源必须可确认");
        assert_eq!(id1, id2, "deposit_id 对 (来源, owner) 确定性幂等");

        // owner 或 tx 不同 → id 不同（幂等键绑定完整上下文）
        assert_ne!(confirm_deposit(&s, &[2u8; 32], Some(&deny)), id1);
        let mut s2 = src_address(0xAA);
        s2.tx_hash = [0xBB; 32];
        assert_ne!(confirm_deposit(&s2, &[1u8; 32], Some(&deny)), id1);
    }

    #[test]
    fn sanctioned_source_produces_no_deposit_id() {
        let bad = vec![0xEEu8; 20];
        let deny = StaticDenylist::from_addresses(std::iter::once(bad.as_slice()));
        let mut s = src_address(0xEE);
        s.address = bad;
        // 同地址不同 tx 全部拒绝（名单按地址，不按单笔）
        s.tx_hash = [1; 32];
        assert_eq!(screen_deposit(&s, Some(&deny)), ScreeningVerdict::Deny(ScreeningDenyReason::SanctionHit));
        assert!(confirm_deposit(&s, &[1u8; 32], Some(&deny)).is_none(), "命中不得产生 deposit_id");
        s.tx_hash = [2; 32];
        assert!(confirm_deposit(&s, &[1u8; 32], Some(&deny)).is_none());
    }

    #[test]
    fn unavailable_source_fails_closed() {
        let s = src_address(0x11);
        assert_eq!(
            screen_deposit(&s, Some(&UnavailableSource)),
            ScreeningVerdict::Deny(ScreeningDenyReason::SourceUnavailable)
        );
        assert!(
            confirm_deposit(&s, &[1u8; 32], Some(&UnavailableSource)).is_none(),
            "数据源不可用必须 fail-closed（≠放行）"
        );
    }

    #[test]
    fn no_source_configured_fails_closed() {
        let s = src_address(0x22);
        assert_eq!(
            screen_deposit(&s, None),
            ScreeningVerdict::Deny(ScreeningDenyReason::NoSourceConfigured)
        );
        assert!(
            confirm_deposit(&s, &[1u8; 32], None).is_none(),
            "未接线筛查数据源的部署不得确认任何入金"
        );
    }

