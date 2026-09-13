//! `display`：REAL/PLAY 展示门状态机（WALLET-ACC-6，纯逻辑）。
//!
//! - **REAL 页**：Vault/verifier/BFT 未就绪时隐藏 claim 操作并显示托管风险
//!   提示；就绪才出现 claim 按钮；
//! - **PLAY 页**：类型上不存在 REAL 余额/充值地址字段（[`PlayPageView`] 没有
//!   real 字段；序列化输出也不含 "real"）——隔离不是 UI 约定，是类型约定。
//!
//! UI 壳层（扩展/桌面/移动）消费本模块输出渲染，不得自行决定。

use serde::Serialize;

/// 平台就绪输入（Vault/verifier/BFT finality 是否可用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessFlags {
    /// Vault 在线（出入金通道可用）。
    pub vault_online: bool,
    /// verifier 就绪（本地证明验证可用）。
    pub verifier_ready: bool,
    /// BFT/锚定 finality 就绪（终态水位可跟随）。
    pub bft_finality_ready: bool,
}

impl ReadinessFlags {
    /// 全未就绪（冷启动默认）。
    #[must_use]
    pub const fn offline() -> Self {
        Self { vault_online: false, verifier_ready: false, bft_finality_ready: false }
    }

    /// 全就绪。
    #[must_use]
    pub const fn ready() -> Self {
        Self { vault_online: true, verifier_ready: true, bft_finality_ready: true }
    }
}

/// REAL 页视图（claim 门 + 托管风险提示）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealPageView {
    /// 是否显示 claim 操作（仅全就绪时 true）。
    pub show_claim: bool,
    /// claim 隐藏原因（就绪时 None）。
    pub claim_disabled_reason: Option<&'static str>,
    /// 托管风险提示文案 key（REAL 常显——v1 是托管模式，必须告知）。
    pub custody_risk_notice: Option<&'static str>,
    /// REAL 余额（自持 note 聚合）。
    pub balance: u128,
}

/// REAL 页视图构造（WALLET-ACC-6）。
///
/// claim 显示条件：`vault_online && verifier_ready && bft_finality_ready`；
/// 任一未就绪 → 隐藏 claim 并给原因 + 托管风险提示。
#[must_use]
pub fn real_page_view(flags: &ReadinessFlags, balance: u128) -> RealPageView {
    let all_ready = flags.vault_online && flags.verifier_ready && flags.bft_finality_ready;
    let reason = if all_ready {
        None
    } else if !flags.vault_online {
        Some("vault_offline")
    } else if !flags.verifier_ready {
        Some("verifier_not_ready")
    } else {
        Some("finality_not_ready")
    };
    RealPageView {
        show_claim: all_ready,
        claim_disabled_reason: reason,
        // REAL 余额可见性不受就绪态影响（隐藏余额不是安全边界），但托管
        // 风险提示在未全就绪时必须出现。
        custody_risk_notice: if all_ready { Some("real_is_custodial_v1") } else { Some("real_is_custodial_v1_offline") },
        balance,
    }
}

/// PLAY 页视图：**没有** REAL 余额/充值地址字段（类型级隔离）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PlayPageView {
    /// PLAY 余额。
    pub play_balance: u128,
    /// PLAY faucet 是否可用（休闲筹码无监管敞口，faucet 是运营功能）。
    pub faucet_available: bool,
}

/// PLAY 页视图构造（不含任何 REAL 信息；参数列表就是证明）。
#[must_use]
pub const fn play_page_view(play_balance: u128, faucet_available: bool) -> PlayPageView {
    PlayPageView { play_balance, faucet_available }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_gated_on_all_ready() {
        let v = real_page_view(&ReadinessFlags::offline(), 100);
        assert!(!v.show_claim);
        assert_eq!(v.claim_disabled_reason, Some("vault_offline"));
        assert!(v.custody_risk_notice.is_some());
        let v = real_page_view(&ReadinessFlags { vault_online: true, verifier_ready: true, bft_finality_ready: false }, 100);
        assert!(!v.show_claim);
        assert_eq!(v.claim_disabled_reason, Some("finality_not_ready"));
        let v = real_page_view(&ReadinessFlags::ready(), 100);
        assert!(v.show_claim);
        assert!(v.claim_disabled_reason.is_none());
    }

    #[test]
    fn play_page_has_no_real_field() {
        let v = play_page_view(55, true);
        let json = serde_json::to_string(&v).unwrap();
        assert!(!json.to_ascii_lowercase().contains("real"));
        // REAL 页始终带 REAL 字段（对照）
        let r = serde_json::to_string(&real_page_view(&ReadinessFlags::ready(), 1)).unwrap();
        assert!(r.contains("balance"));
    }
}
