//! 上锚提交器：批次根 / 聚合根 / checkpoint → Monad L1Inbox。
//!
//! 职责链（daemon 每轮驱动）：
//! 1. [`AnchorSubmitter::submit`]：按 key 幂等去重 → 签名广播（nonce 本地
//!    递增 + 失败重取，gas = gasPrice×1.1）；
//! 2. [`AnchorSubmitter::poll`]：回执确认（Submitted → Included）；
//! 3. [`AnchorSubmitter::poll`]：最终性推进（Included → Finalized，以
//!    `eth_getBlockByNumber("finalized")` 为不可逆基准）。
//!
//! 状态机：`Submitted{tx}` → `Included{tx, block}` → `Finalized{tx, block}`。
//! 状态可快照（daemon 持久化到 JSON 状态文件，重启不重放已上锚项）。

use std::collections::BTreeMap;

use crate::abi;
use crate::error::SettlementError;
use crate::keccak::keccak256;
use crate::l1::L1Rpc;
use crate::signer::{Credentials, LegacyTx};

/// 上锚数据类型（对应 L1Inbox 的三个入口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorKind {
    /// 批次根（`submitBatch`）。
    Batch,
    /// 聚合根（`submitAggregate`）。
    Aggregate,
    /// checkpoint（`submitCheckpoint`）。
    Checkpoint,
}

impl AnchorKind {
    /// key 前缀（去重键 = 前缀 + root hex）。
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Aggregate => "aggregate",
            Self::Checkpoint => "checkpoint",
        }
    }
}

/// 上锚状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorState {
    /// 已广播，未确认。
    Submitted {
        /// 交易哈希。
        tx_hash: [u8; 32],
    },
    /// 已打包，等最终性。
    Included {
        /// 交易哈希。
        tx_hash: [u8; 32],
        /// 打包高度。
        block: u64,
    },
    /// 已终结（不可逆）。
    Finalized {
        /// 交易哈希。
        tx_hash: [u8; 32],
        /// 打包高度。
        block: u64,
    },
}

impl AnchorState {
    /// tx hash（快照序列化用）。
    #[must_use]
    pub fn tx_hash(&self) -> [u8; 32] {
        match self {
            Self::Submitted { tx_hash }
            | Self::Included { tx_hash, .. }
            | Self::Finalized { tx_hash, .. } => *tx_hash,
        }
    }

    /// 打包高度（Submitted → None）。
    #[must_use]
    pub fn block(&self) -> Option<u64> {
        match self {
            Self::Submitted { .. } => None,
            Self::Included { block, .. } | Self::Finalized { block, .. } => Some(*block),
        }
    }

    /// 是否已终结。
    #[must_use]
    pub fn is_finalized(&self) -> bool {
        matches!(self, Self::Finalized { .. })
    }
}

/// 待提交任务（daemon 组装，submitter 不感知业务语义）。
#[derive(Debug, Clone)]
pub struct AnchorTask {
    /// 去重 key（幂等基准；建议 = kind.prefix() + root hex）。
    pub key: String,
    /// 合约 calldata（abi::encode_* 产物）。
    pub calldata: Vec<u8>,
    /// gas 上限（默认 300_000 足够三个入口）。
    pub gas_limit: u128,
}

impl AnchorTask {
    /// 快捷构造。
    #[must_use]
    pub fn new(key: String, calldata: Vec<u8>) -> Self {
        Self { key, calldata, gas_limit: 300_000 }
    }
}

/// 上锚提交器。
pub struct AnchorSubmitter {
    rpc: L1Rpc,
    creds: Credentials,
    /// L1Inbox 地址。
    inbox: [u8; 20],
    /// 期望 chainId（构造后 `ensure_chain_id` 校验一次）。
    expected_chain_id: u64,
    /// 本地 nonce（None = 待取）。
    nonce: Option<u64>,
    /// key → 状态。
    states: BTreeMap<String, AnchorState>,
}

impl std::fmt::Debug for AnchorSubmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorSubmitter")
            .field("inbox", &hex::encode(self.inbox))
            .field("expected_chain_id", &self.expected_chain_id)
            .field("pending", &self.pending_finality())
            .finish()
    }
}

impl AnchorSubmitter {
    /// 构造并做 chainId 闸门校验（错链即拒，fail-closed）。
    ///
    /// # Errors
    /// chainId 不符 / RPC 失败。
    pub fn connect(
        rpc: L1Rpc,
        creds: Credentials,
        inbox: [u8; 20],
        expected_chain_id: u64,
    ) -> Result<Self, SettlementError> {
        let actual = rpc.chain_id()?;
        if actual != expected_chain_id {
            return Err(SettlementError::ChainIdMismatch { expected: expected_chain_id, actual });
        }
        Ok(Self { rpc, creds, inbox, expected_chain_id, nonce: None, states: BTreeMap::new() })
    }

    /// 期望 chainId。
    #[must_use]
    pub fn expected_chain_id(&self) -> u64 {
        self.expected_chain_id
    }

    /// 提交任务（key 已存在 → 幂等跳过返回 None）。
    ///
    /// # Errors
    /// RPC / 签名失败。
    pub fn submit(&mut self, task: &AnchorTask) -> Result<Option<[u8; 32]>, SettlementError> {
        if self.states.contains_key(&task.key) {
            return Ok(None);
        }
        if self.nonce.is_none() {
            self.nonce = Some(self.rpc.transaction_count(&self.creds.address())?);
        }
        let gas_price = self.rpc.gas_price()?.saturating_mul(11) / 10;
        let tx = LegacyTx {
            nonce: self.nonce.expect("just filled"),
            gas_price,
            gas_limit: task.gas_limit,
            to: Some(self.inbox),
            value: 0,
            data: task.calldata.clone(),
        };
        let signed = self.creds.sign_eip155(&tx, self.expected_chain_id)?;
        let tx_hash = self.rpc.send_raw_transaction(&signed.raw)?;
        self.nonce = Some(tx.nonce + 1);
        self.states.insert(task.key.clone(), AnchorState::Submitted { tx_hash });
        Ok(Some(tx_hash))
    }

    /// 回执 + 最终性推进（一轮）。
    ///
    /// # Errors
    /// RPC 失败（单条失败不中断其余项的状态推进）。
    pub fn poll(&mut self) -> Result<(), SettlementError> {
        let finalized_height = self.rpc.finalized_block()?;
        let keys: Vec<String> = self.states.keys().cloned().collect();
        for key in keys {
            let state = self.states.get(&key).cloned();
            match state {
                Some(AnchorState::Submitted { tx_hash }) => {
                    if let Some(receipt) = self.rpc.transaction_receipt(&tx_hash)? {
                        if !receipt.success {
                            // 失败回执：删除状态（daemon 负责告警/重试决策）。
                            self.states.remove(&key);
                            continue;
                        }
                        self.states.insert(
                            key,
                            AnchorState::Included { tx_hash, block: receipt.block_number },
                        );
                    }
                }
                Some(AnchorState::Included { tx_hash, block }) => {
                    if block <= finalized_height {
                        self.states.insert(key, AnchorState::Finalized { tx_hash, block });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// 快照（daemon 持久化）。
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<String, AnchorState> {
        self.states.clone()
    }

    /// 恢复快照（重启续跑；已 Finalized 的项不再重复提交）。
    pub fn restore(&mut self, states: BTreeMap<String, AnchorState>) {
        self.states.extend(states);
    }

    /// 未终结项数量（daemon 退出条件/告警面）。
    #[must_use]
    pub fn pending_finality(&self) -> usize {
        self.states.values().filter(|s| !s.is_finalized()).count()
    }
}

/// checkpoint 上锚任务快捷构造（含 state root + 提现根）。
#[must_use]
pub fn checkpoint_task(l2_height: u64, state_root: [u8; 32], withdrawal_root: Option<([u8; 32], u64)>) -> AnchorTask {
    let (wr, leaf_count) = withdrawal_root.unwrap_or(([0u8; 32], 0));
    let key = format!("checkpoint:{}:{}", l2_height, hex::encode(wr));
    AnchorTask::new(key, abi::encode_submit_checkpoint(l2_height, state_root, wr, leaf_count))
}

/// 批次根上锚任务快捷构造。
#[must_use]
pub fn anchor_task(index: u64, root: [u8; 32], through_op: u64) -> AnchorTask {
    AnchorTask::new(
        format!("batch:{}:{}", index, hex::encode(root)),
        abi::encode_submit_batch(index, root, through_op),
    )
}

/// 聚合根上锚任务快捷构造。
#[must_use]
pub fn aggregate_task(index: u64, root: [u8; 32], through_op: u64, batch_count: u64) -> AnchorTask {
    AnchorTask::new(
        format!("aggregate:{}:{}", index, hex::encode(root)),
        abi::encode_submit_aggregate(index, root, through_op, batch_count),
    )
}

/// 领取 calldata 的 key 派生（daemon 不代领，此函数供集成测试/CLI 使用）。
#[must_use]
pub fn claim_task_key(leaf: &abi::ClaimLeaf) -> String {
    format!("claim:{}", hex::encode(keccak256(&crate::proof::leaf_borsh_bytes(leaf))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_prefixes_distinct() {
        let root = [1u8; 32];
        let b = anchor_task(0, root, 9);
        let a = aggregate_task(0, root, 9, 1);
        assert_ne!(b.key, a.key);
        assert!(b.key.starts_with("batch:"));
        assert!(a.key.starts_with("aggregate:"));
    }

    #[test]
    fn checkpoint_key_covers_withdrawal_root() {
        let t1 = checkpoint_task(7, [1u8; 32], None);
        let t2 = checkpoint_task(7, [1u8; 32], Some(([2u8; 32], 3)));
        assert_ne!(t1.key, t2.key);
    }
}
