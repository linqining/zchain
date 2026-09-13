//! M3：软确认链（signed hash chain）。
//!
//! 每帧 = 一个已应用的操作 + 应用后状态根，sequencer 用 ed25519 签名。
//! 链是 sequencer 的**有约束力承诺**（v2 起周期锚定 L1，等价性欺诈可罚没）；
//! watcher 用它做分叉检测（M8-ACC-6）。

use crate::error::{AppchainError, AppchainResult};
use crate::keys::{blake2s32, SequencerKey};
use crate::ops::Operation;

/// 软确认帧（ABI v1）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SoftConfirmFrame {
    /// 链内序号（从 0 起，严格递增 +1）。
    pub index: u64,
    /// 前帧哈希（创世帧为全零）。
    pub prev_hash: [u8; 32],
    /// 已应用的操作。
    pub op: Operation,
    /// 应用后的账本状态根。
    pub state_root: [u8; 32],
    /// 序列器时钟（毫秒；单调性由 sequencer 保证）。
    pub ts_ms: u64,
}

/// 帧哈希（签名对象）：`blake2s(borsh(frame))`。
///
/// # Errors
/// borsh 序列化失败（实际不可达）→ [`AppchainError::Codec`]。
pub fn frame_hash(frame: &SoftConfirmFrame) -> AppchainResult<[u8; 32]> {
    let bytes =
        borsh::to_vec(frame).map_err(|e| AppchainError::Codec(e.to_string()))?;
    Ok(blake2s32(&[&bytes]))
}

/// 已签名帧。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SignedFrame {
    /// 帧。
    pub frame: SoftConfirmFrame,
    /// sequencer ed25519 签名（对 frame_hash）。
    pub sig: [u8; 64],
}

impl SignedFrame {
    /// 签名并封装。
    ///
    /// # Errors
    /// 序列化失败 → [`AppchainError::Codec`]。
    pub fn sign(
        frame: SoftConfirmFrame,
        key: &SequencerKey,
    ) -> AppchainResult<Self> {
        let h = frame_hash(&frame)?;
        let sig = key.sign(&h);
        Ok(Self { frame, sig })
    }

    /// 帧哈希。
    ///
    /// # Errors
    /// 序列化失败 → [`AppchainError::Codec`]。
    pub fn hash(&self) -> AppchainResult<[u8; 32]> {
        frame_hash(&self.frame)
    }

    /// 验签 + 接续性验证（prev_hash、index）。
    ///
    /// # Errors
    /// 签名坏 → [`AppchainError::BadFrameSignature`]；
    /// 接续坏 → [`AppchainError::ChainBroken`]。
    pub fn verify_against(
        &self,
        prev_hash: &[u8; 32],
        prev_index: u64,
        sequencer_public: &[u8; 32],
    ) -> AppchainResult<()> {
        let expected_index = prev_index.checked_add(1).ok_or(AppchainError::ChainBroken(u64::MAX))?;
        if self.frame.index != expected_index {
            return Err(AppchainError::ChainBroken(self.frame.index));
        }
        if &self.frame.prev_hash != prev_hash {
            return Err(AppchainError::ChainBroken(self.frame.index));
        }
        let h = self.hash()?;
        if !SequencerKey::verify(sequencer_public, &h, &self.sig) {
            return Err(AppchainError::BadFrameSignature);
        }
        Ok(())
    }
}

/// 创世帧构造（index = 0，prev = 全零，op = OpenTable 由调用方给）。
///
/// 注意：创世帧 index 是 0，verify_against 的 prev_index 传 `u64::MAX`？
/// 不——创世帧不由 [`SignedFrame::verify_against`] 校验接续，链重建时
/// 对 index 0 单独验签。
#[must_use]
pub fn genesis_prev_hash() -> [u8; 32] {
    [0u8; 32]
}

/// 校验一条完整链（fail-closed 全量重验）。
///
/// # Errors
/// 任何一帧验签/接续失败 → 对应错误。
pub fn verify_chain(
    frames: &[SignedFrame],
    sequencer_public: &[u8; 32],
) -> AppchainResult<()> {
    let mut prev = genesis_prev_hash();
    let mut prev_index: Option<u64> = None;
    for f in frames {
        match prev_index {
            None => {
                if f.frame.index != 0 || f.frame.prev_hash != genesis_prev_hash() {
                    return Err(AppchainError::ChainBroken(f.frame.index));
                }
                let h = f.hash()?;
                if !SequencerKey::verify(sequencer_public, &h, &f.sig) {
                    return Err(AppchainError::BadFrameSignature);
                }
            }
            Some(pi) => {
                f.verify_against(&prev, pi, sequencer_public)?;
            }
        }
        prev = f.hash()?;
        prev_index = Some(f.frame.index);
    }
    Ok(())
}

/// 链头哈希（空链 = 创世 prev）。
///
/// # Errors
/// 序列化失败 → [`AppchainError::Codec`]。
pub fn chain_head(frames: &[SignedFrame]) -> AppchainResult<[u8; 32]> {
    frames.last().map(|f| f.hash()).unwrap_or(Ok(genesis_prev_hash()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee::FeePolicy;

    fn frame(index: u64, prev: [u8; 32]) -> SoftConfirmFrame {
        SoftConfirmFrame {
            index,
            prev_hash: prev,
            op: Operation::OpenTable { table_id: index, policy: FeePolicy::Zero },
            state_root: [index as u8; 32],
            ts_ms: 1_000 + index,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = SequencerKey::from_seed(&[3u8; 32]);
        let f = SignedFrame::sign(frame(0, genesis_prev_hash()), &key).unwrap();
        // 创世帧（index 0）接续性由 verify_chain 特判，只验签。
        assert!(verify_chain(&[f.clone()], &key.public).is_ok());
        let f1 = SignedFrame::sign(frame(1, f.hash().unwrap()), &key).unwrap();
        assert!(verify_chain(&[f, f1], &key.public).is_ok());
    }

    #[test]
    fn tampered_payload_breaks_signature() {
        let key = SequencerKey::from_seed(&[4u8; 32]);
        let mut f = SignedFrame::sign(frame(0, genesis_prev_hash()), &key).unwrap();
        f.frame.ts_ms += 1;
        assert!(verify_chain(&[f], &key.public).is_err());
    }

    #[test]
    fn gap_breaks_chain() {
        let key = SequencerKey::from_seed(&[5u8; 32]);
        let f0 = SignedFrame::sign(frame(0, genesis_prev_hash()), &key).unwrap();
        let f2 = SignedFrame::sign(frame(2, f0.hash().unwrap()), &key).unwrap();
        assert!(verify_chain(&[f0, f2], &key.public).is_err());
    }
}
