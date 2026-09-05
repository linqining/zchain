//! M8：watcher——等价性/分叉检测与链-证明注册表一致性审计。
//!
//! 软确认的信任支点是"sequencer 说话算数"（plan §安全五前提）：watcher
//! 独立验证 (a) 软确认链签名与接续，(b) 两条链导出的等价性（分叉定位），
//! (c) 每条 Settle 操作都有对应证明批次覆盖。任何玩家/第三方可运行。

use std::collections::HashSet;

use crate::error::AppchainError;
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
