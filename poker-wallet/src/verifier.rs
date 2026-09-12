//! `verifier`：本地验证即确认（plan §6.12.3 M6 客户端）。
//!
//! 接入 poker-appchain 的**既有校验面**（不重实现密码学/语义）：
//!
//! - [`verify_settlement`]：`poker_appchain::settlement::validate_settlement`
//!   全量校验（守恒 + 费率 + 分账 + P 层签名覆盖 + 手牌证明绑定），输出
//!   digest（结算绑定）与状态层级（本地可证 → soft；finality 需批次/BFT）；
//! - [`verify_soft_chain`]：`poker_appchain::soft_confirm::verify_chain`
//!   全量重验（ed25519 + 接续性），输出链头与层级；
//! - [`verify_batch_root`]：批次根 Poseidon 折叠**可复算**校验；
//! - [`batch_root_golden_ok`]：poker-appchain 冻结的 golden 向量在本 crate
//!   复算一致（防 Poseidon 参数/域标签无声更改）。
//!
//! 篡改输入一律拒绝并给出原因（M6-ACC-3）。

use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::settlement::{settlement_binding, validate_settlement, SettlementRecord};
use poker_appchain::soft_confirm::{chain_head, verify_chain, SignedFrame};

use crate::error::{WalletError, WalletResult};

/// verifier 名称。
pub const VERIFIER_NAME: &str = "wallet-core/verifier";

/// verifier 版本（跟随 crate 版本）。
pub const VERIFIER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 支持的 appchain Operation/帧 ABI 版本。
pub const SUPPORTED_APPCHAIN_ABI: u32 = 1;

/// verifier 元信息（UI 显示"验证器版本"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierMeta {
    /// 名称。
    pub name: &'static str,
    /// 版本。
    pub version: &'static str,
    /// 支持的 ABI 版本。
    pub abi_version: u32,
}

/// verifier 元信息。
#[must_use]
pub const fn meta() -> VerifierMeta {
    VerifierMeta { name: VERIFIER_NAME, version: VERIFIER_VERSION, abi_version: SUPPORTED_APPCHAIN_ABI }
}

/// 状态层级（soft → proven → finalized；客户端不伪造更高层级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum FinalityLevel {
    /// 仅本地结构校验通过。
    Local,
    /// 软确认帧已跟随（sequencer 承诺）。
    Soft,
    /// 已被证明批次覆盖。
    Proven,
    /// BFT/锚定终态。
    Finalized,
}

impl FinalityLevel {
    /// 状态名（预览/展示用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Soft => "soft",
            Self::Proven => "proven",
            Self::Finalized => "finalized",
        }
    }
}

/// settlement 校验结论。
#[derive(Debug, Clone)]
pub struct SettlementVerdict {
    /// 结算绑定摘要（32B；覆盖 pot/分配/全部输出，含 payout_root）。
    pub binding: [u8; 32],
    /// 状态层级（本地校验通过 → [`FinalityLevel::Soft`]；跨批/BFT 由上层推进）。
    pub level: FinalityLevel,
    /// 输入 note 数。
    pub inputs: usize,
    /// 赔付输出数。
    pub payouts: usize,
}

/// settlement 全量校验（接入 `validate_settlement`；篡改输入拒绝并给原因）。
///
/// # Errors
/// 任何账本校验失败 → [`WalletError::VerifierRejected`]（附账本原始原因）。
pub fn verify_settlement(record: &SettlementRecord, policy: &FeePolicy) -> WalletResult<SettlementVerdict> {
    validate_settlement(record, policy)
        .map_err(|e| WalletError::VerifierRejected(e.to_string()))?;
    Ok(SettlementVerdict {
        binding: felt_to_bytes32(&settlement_binding(record)),
        level: FinalityLevel::Soft,
        inputs: record.inputs.len(),
        payouts: record.payouts.len(),
    })
}

/// 软确认链校验结论。
#[derive(Debug, Clone)]
pub struct SoftChainVerdict {
    /// 链头哈希（空链 = 创世 prev）。
    pub head: [u8; 32],
    /// 已验证帧数。
    pub frames: usize,
    /// 状态层级。
    pub level: FinalityLevel,
}

/// 软确认链全量重验（接入 `verify_chain`；签名/接续失败拒绝并给原因）。
///
/// # Errors
/// 任何一帧验签/接续失败 → [`WalletError::VerifierRejected`]。
pub fn verify_soft_chain(
    frames: &[SignedFrame],
    sequencer_public: &[u8; 32],
) -> WalletResult<SoftChainVerdict> {
    verify_chain(frames, sequencer_public)
        .map_err(|e| WalletError::VerifierRejected(format!("soft confirm chain: {e}")))?;
    Ok(SoftChainVerdict {
        head: chain_head(frames)
            .map_err(|e| WalletError::Codec(e.to_string()))?,
        frames: frames.len(),
        level: FinalityLevel::Soft,
    })
}

/// 单帧验签（断点续传路径：只验证新帧对已知前驱的接续）。
///
/// # Errors
/// 签名/接续失败 → [`WalletError::VerifierRejected`]。
pub fn verify_soft_frame(
    frame: &SignedFrame,
    prev_hash: &[u8; 32],
    prev_index: u64,
    sequencer_public: &[u8; 32],
) -> WalletResult<[u8; 32]> {
    frame
        .verify_against(prev_hash, prev_index, sequencer_public)
        .map_err(|e| WalletError::VerifierRejected(format!("soft confirm frame: {e}")))?;
    frame.hash().map_err(|e| WalletError::Codec(e.to_string()))
}

/// 批次根复算校验（golden 可复算：绑定序确定性折叠）。
///
/// # Errors
/// 复算不一致 → [`WalletError::VerifierRejected`]。
pub fn verify_batch_root(bindings: &[[u8; 32]], claimed: &[u8; 32]) -> WalletResult<()> {
    let recomputed =
        poker_appchain::pipeline::batch_root(bindings).map_err(|e| WalletError::Codec(e.to_string()))?;
    let mut diff = 0u8;
    for (a, b) in recomputed.iter().zip(claimed.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(WalletError::VerifierRejected(format!(
            "batch root mismatch: claimed {}, recomputed {}",
            hex::encode(claimed),
            hex::encode(recomputed)
        )));
    }
    Ok(())
}

/// poker-appchain 冻结的批次根 golden 向量在本 crate 复算一致
/// （Poseidon 参数/域标签/编码纪律防无声更改）。
#[must_use]
pub fn batch_root_golden_ok() -> bool {
    let b1 = [0xAAu8; 32];
    let b2 = [0xBBu8; 32];
    match poker_appchain::pipeline::batch_root(&[b1, b2]) {
        Ok(root) => hex::encode(root) == "00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52",
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vector_recomputes() {
        assert!(batch_root_golden_ok());
    }

    #[test]
    fn batch_root_mismatch_rejected() {
        let b = [0x11u8; 32];
        let wrong = poker_appchain::pipeline::batch_root(&[b]).unwrap();
        let mut other = wrong;
        other[0] ^= 1;
        assert!(verify_batch_root(&[b], &wrong).is_ok());
        assert!(verify_batch_root(&[b], &other).is_err());
    }
}
