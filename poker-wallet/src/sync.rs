//! `sync`：checkpoint / owner 索引同步（plan §6.12.3）。
//!
//! 真实网络不在本 crate（无网络 IO 纪律）：[`ChainSource`] 是接入缝，
//! sequencer/索引节点/RPC 适配器实现该 trait 即可接入；当前提供
//! [`InMemoryChainSource`]（软确认链 + note 事件的内存实现，测试/离线演练）。
//!
//! 语义：断点续传（checkpoint 单调推进、事件按 op_index 去重）、幂等
//! （重复同步同一区间无副作用）、重组检测（checkpoint 处帧哈希不接续 →
//! [`WalletError::ReorgDetected`]，由调用方决定回滚窗口）。

use poker_appchain::note::Note;
use poker_appchain::soft_confirm::{chain_head, SignedFrame};

use crate::error::{WalletError, WalletResult};
use crate::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};

/// 同步断点（持久化；恢复同步从该点续传）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SyncCheckpoint {
    /// 已消费到的软确认帧序号（op index 水位）。
    pub last_op_index: u64,
    /// 该序号帧的哈希（重组检测锚点）。
    pub head_hash: [u8; 32],
}

/// owner 名下的一条 note 更新（铸出/状态推进/花费）。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct OwnerNoteUpdate {
    /// note 内容。
    pub note: Note,
    /// spend secret（仅 owner 视图可见；真实网络路径由加密投递解出）。
    pub spend_secret: [u8; 32],
    /// 创建帧。
    pub origin: OriginFrame,
    /// 当前证明状态。
    pub proof: ProofState,
    /// 是否已被消费。
    pub spent: bool,
}

/// 链数据源接入缝（真实网络实现此 trait；本 crate 不做网络 IO）。
pub trait ChainSource {
    /// 当前链头（index + hash）。
    fn head(&self) -> SyncCheckpoint;
    /// 指定序号帧的哈希（重组检测用；越界返回 None）。
    fn frame_hash_at(&self, index: u64) -> Option<[u8; 32]>;
    /// 拉取 owner 名下 `op_index > after` 的更新（None = 全量首拉；
    /// 分页/断点续传由实现保证）。
    fn updates_since(&self, owner: &[u8; 33], after_op_index: Option<u64>) -> Vec<OwnerNoteUpdate>;
}

/// 内存链数据源（软确认链 + note 事件表）。
#[derive(Debug, Clone)]
pub struct InMemoryChainSource {
    sequencer_public: [u8; 32],
    frames: Vec<SignedFrame>,
    events: Vec<OwnerNoteUpdate>,
}

impl InMemoryChainSource {
    /// 新建（帧链必须能通过 [`poker_appchain::soft_confirm::verify_chain`]）。
    ///
    /// # Errors
    /// 帧链校验失败 → [`WalletError::VerifierRejected`]。
    pub fn new(
        frames: Vec<SignedFrame>,
        sequencer_public: [u8; 32],
    ) -> WalletResult<Self> {
        poker_appchain::soft_confirm::verify_chain(&frames, &sequencer_public)
            .map_err(|e| WalletError::VerifierRejected(format!("chain source: {e}")))?;
        Ok(Self { sequencer_public, frames, events: Vec::new() })
    }

    /// sequencer 公钥。
    #[must_use]
    pub fn sequencer_public(&self) -> &[u8; 32] {
        &self.sequencer_public
    }

    /// 追加 note 事件（按 origin.op_index 升序插入，保持拉取序确定）。
    pub fn push_event(&mut self, event: OwnerNoteUpdate) {
        self.events.push(event);
        self.events.sort_by_key(|e| e.origin.op_index);
    }

    /// 帧链可变访问（测试/后续追加；追加后须保持 verify_chain 可通过）。
    pub fn frames_mut(&mut self) -> &mut Vec<SignedFrame> {
        &mut self.frames
    }
}

impl ChainSource for InMemoryChainSource {
    fn head(&self) -> SyncCheckpoint {
        let last = self.frames.len();
        SyncCheckpoint {
            last_op_index: last.saturating_sub(1) as u64,
            head_hash: chain_head(&self.frames).unwrap_or(poker_appchain::soft_confirm::genesis_prev_hash()),
        }
    }

    fn frame_hash_at(&self, index: u64) -> Option<[u8; 32]> {
        self.frames
            .get(index as usize)
            .and_then(|f| f.hash().ok())
    }

    fn updates_since(&self, owner: &[u8; 33], after_op_index: Option<u64>) -> Vec<OwnerNoteUpdate> {
        self.events
            .iter()
            .filter(|e| {
                e.note.owner == *owner
                    && after_op_index.is_none_or(|after| e.origin.op_index > after)
            })
            .cloned()
            .collect()
    }
}

/// 单步同步结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// 无新内容（幂等）。
    UpToDate,
    /// 已应用 N 条更新（含状态推进）。
    Applied {
        /// 新 checkpoint。
        checkpoint: SyncCheckpoint,
        /// 应用的事件数。
        applied: usize,
    },
}

/// 单步同步：重组检测 → 拉取 → 入库（按承诺去重，状态只进不退）。
///
/// # Errors
/// checkpoint 处帧哈希不接续或水位回退 → [`WalletError::ReorgDetected`]。
pub fn sync_step(
    source: &dyn ChainSource,
    owner: &[u8; 33],
    checkpoint: Option<&SyncCheckpoint>,
    stores: &mut WalletStores,
) -> WalletResult<SyncOutcome> {
    if let Some(cp) = checkpoint {
        let local_hash = source.frame_hash_at(cp.last_op_index);
        match local_hash {
            None => {
                // 本地水位超过链长 → 分叉/回滚
                return Err(WalletError::ReorgDetected { index: cp.last_op_index });
            }
            Some(h) if h != cp.head_hash => {
                return Err(WalletError::ReorgDetected { index: cp.last_op_index });
            }
            Some(_) => {}
        }
    }
    let after = checkpoint.map(|c| c.last_op_index);
    let updates = source.updates_since(owner, after);
    if updates.is_empty() {
        return Ok(SyncOutcome::UpToDate);
    }
    let mut applied = 0usize;
    for u in &updates {
        let store = stores.store(u.note.asset_class);
        let commitment = u.note.commitment_bytes();
        match store.get_mut(&commitment) {
            Some(rec) => {
                // 幂等 + 状态只进不退（pending→soft→proven→finalized；spent 吸收）。
                rec.proof = advance(&rec.proof, &u.proof);
                if u.spent && rec.spent_by_op.is_none() {
                    rec.spent_by_op = Some(u.origin.op_index);
                }
            }
            None => {
                let record = NoteRecord::with_secret(u.note.clone(), u.spend_secret, u.origin.clone(), u.proof.clone());
                if u.spent {
                    let mut r = record;
                    r.spent_by_op = Some(u.origin.op_index);
                    store.insert(r)?;
                } else {
                    store.insert(record)?;
                }
            }
        }
        applied += 1;
    }
    let head = source.head();
    // 更新水位：取应用事件的最后一个 origin（不是链头——事件可能落后于链）。
    let new_index = updates
        .last()
        .map(|u| u.origin.op_index)
        .unwrap_or(after.unwrap_or(0));
    let head_hash = source
        .frame_hash_at(new_index)
        .unwrap_or(head.head_hash);
    Ok(SyncOutcome::Applied {
        checkpoint: SyncCheckpoint { last_op_index: new_index, head_hash },
        applied,
    })
}

/// proof 状态只进不退（pending < soft < proven < finalized）。
fn advance(current: &ProofState, incoming: &ProofState) -> ProofState {
    use ProofState::{Finalized, Pending, Proven, Soft};
    let rank = |p: &ProofState| match p {
        Pending => 0,
        Soft => 1,
        Proven { .. } => 2,
        Finalized => 3,
    };
    if rank(incoming) >= rank(current) {
        incoming.clone()
    } else {
        current.clone()
    }
}

/// 全量同步（循环到 [`SyncOutcome::UpToDate`]；返回最终 checkpoint）。
///
/// # Errors
/// 同 [`sync_step`]。
pub fn sync_all(
    source: &dyn ChainSource,
    owner: &[u8; 33],
    checkpoint: Option<&SyncCheckpoint>,
    stores: &mut WalletStores,
) -> WalletResult<SyncCheckpoint> {
    let mut current = checkpoint.cloned();
    loop {
        match sync_step(source, owner, current.as_ref(), stores)? {
            SyncOutcome::UpToDate => {
                return Ok(current.unwrap_or(SyncCheckpoint {
                    last_op_index: 0,
                    head_hash: poker_appchain::soft_confirm::genesis_prev_hash(),
                }));
            }
            SyncOutcome::Applied { checkpoint, .. } => current = Some(checkpoint),
        }
    }
}

/// 资产类重导出（sync 结果消费方免引 appchain）。
pub use poker_appchain::note::AssetClass as SyncAssetClass;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::OwnerKeyPair;
    use poker_appchain::note::AssetClass;
    use poker_appchain::keys::SequencerKey;
    use poker_appchain::ops::Operation;
    use poker_appchain::soft_confirm::{genesis_prev_hash, SoftConfirmFrame};

    #[test]
    fn resume_and_dedupe() {
        let seq = SequencerKey::from_seed(&[42; 32]);
        let mut frames = Vec::new();
        let f0 = SignedFrame::sign(SoftConfirmFrame {
            index: 0,
            prev_hash: genesis_prev_hash(),
            op: Operation::OpenTable { table_id: 1, policy: poker_appchain::fee::FeePolicy::Zero },
            state_root: [1; 32],
            ts_ms: 1,
        }, &seq).unwrap();
        frames.push(f0.clone());
        let mut source = InMemoryChainSource::new(frames, seq.public).unwrap();
        let owner = OwnerKeyPair::from_seed(&[7; 32]).unwrap();
        let note = Note::new(AssetClass::Play, 25, owner.public_bytes(), [1; 32], None).unwrap();
        source.push_event(OwnerNoteUpdate {
            note,
            spend_secret: [9; 32],
            origin: OriginFrame { op_index: 0, frame_hash: f0.hash().unwrap() },
            proof: ProofState::Soft,
            spent: false,
        });
        let mut stores = WalletStores::new();
        let cp = sync_all(&source, &owner.public_bytes(), None, &mut stores).unwrap();
        assert_eq!(stores.play().len(), 1);
        // 幂等：重复同步无变化
        assert_eq!(sync_step(&source, &owner.public_bytes(), Some(&cp), &mut stores).unwrap(), SyncOutcome::UpToDate);
        assert_eq!(stores.play().len(), 1);
    }

    #[test]
    fn reorg_detected() {
        let seq = SequencerKey::from_seed(&[43; 32]);
        let f0 = SignedFrame::sign(SoftConfirmFrame {
            index: 0,
            prev_hash: genesis_prev_hash(),
            op: Operation::OpenTable { table_id: 1, policy: poker_appchain::fee::FeePolicy::Zero },
            state_root: [1; 32],
            ts_ms: 1,
        }, &seq).unwrap();
        let h0 = f0.hash().unwrap();
        let source = InMemoryChainSource::new(vec![f0], seq.public).unwrap();
        let mut stores = WalletStores::new();
        let owner = [0u8; 33];
        // checkpoint 哈希与链不一致 → 重组拒绝
        let bad_cp = SyncCheckpoint { last_op_index: 0, head_hash: [9; 32] };
        assert!(matches!(
            sync_step(&source, &owner, Some(&bad_cp), &mut stores),
            Err(WalletError::ReorgDetected { index: 0 })
        ));
        // 好的 checkpoint 通过
        let good_cp = SyncCheckpoint { last_op_index: 0, head_hash: h0 };
        assert!(sync_step(&source, &owner, Some(&good_cp), &mut stores).is_ok());
        // 水位超前 → 重组拒绝
        let ahead = SyncCheckpoint { last_op_index: 5, head_hash: h0 };
        assert!(matches!(
            sync_step(&source, &owner, Some(&ahead), &mut stores),
            Err(WalletError::ReorgDetected { index: 5 })
        ));
    }
}
