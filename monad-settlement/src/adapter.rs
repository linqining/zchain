//! MonadAdapter — [`SettlementAdapter`] 的 Monad 实现（EVM 族第一个参考实现）。
//!
//! 组装：[`AnchorSubmitter`]（上锚状态机 + nonce + gas）+ [`DepositWatcher`]
//! （finalized 窗口入金）+ L1Outbox claim 编码。新增结算链时的参照物：
//! Solana 适配器（Anchor 程序）按本文件同形状实现即可，引擎零改动。

use settlement_adapter::{
    AdapterError, AnchorKind, AnchorTask, ClaimRequest, DepositRecord, ForcedOpRecord,
    SettlementAdapter, TxId,
};

use crate::abi::{encode_claim, ClaimLeaf};
use crate::anchor::AnchorSubmitter;
use crate::l1::L1Rpc;
use crate::watcher::DepositWatcher;

/// Monad（EVM 族）结算适配器。
pub struct MonadAdapter {
    submitter: AnchorSubmitter,
    watcher: Option<DepositWatcher>,
    bridge: [u8; 20],
    chain_id: u64,
    connected: bool,
}

impl std::fmt::Debug for MonadAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonadAdapter")
            .field("chain_id", &self.chain_id)
            .field("bridge", &hex::encode(self.bridge))
            .field("connected", &self.connected)
            .field("pending", &self.pending_finality())
            .finish()
    }
}

impl MonadAdapter {
    /// 构造（不连网；[`Self::connect`] 做链身份闸门）。
    ///
    /// # Errors
    /// URL 非法。
    pub fn new(
        l1_rpc_url: impl Into<String>,
        credentials: crate::Credentials,
        inbox: [u8; 20],
        bridge: [u8; 20],
        expected_chain_id: u64,
    ) -> Result<Self, crate::SettlementError> {
        let rpc = L1Rpc::new(l1_rpc_url)?;
        let submitter = AnchorSubmitter::connect(rpc, credentials, inbox, expected_chain_id)?;
        let watcher = DepositWatcher::new(
            L1Rpc::new(submitter.rpc_url())?,
            bridge,
            0,
        );
        Ok(Self { submitter, watcher: Some(watcher), bridge, chain_id: expected_chain_id, connected: false })
    }

    /// Bridge 地址（钱包买入面）。
    #[must_use]
    pub fn bridge(&self) -> [u8; 20] {
        self.bridge
    }
}

impl SettlementAdapter for MonadAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn host(&self) -> &'static str {
        "monad"
    }

    fn connect(&mut self) -> Result<(), AdapterError> {
        // chainId 闸门已在 AnchorSubmitter::connect 完成（错链即拒）；
        // 这里补一次在线探测（finalized 标签可用性）。
        let _ = self
            .watcher
            .as_mut()
            .ok_or_else(|| AdapterError::Other("watcher absent".into()))?
            .poll_once()
            .map_err(|e| AdapterError::Transport { method: "connect.finalized".into(), message: e.to_string() })?;
        self.connected = true;
        Ok(())
    }

    fn submit_anchor(&mut self, task: &AnchorTask) -> Result<Option<TxId>, AdapterError> {
        // settlement-adapter 的 AnchorTask.payload = 本链 calldata（不透明字节）。
        let inner = crate::anchor::AnchorTask::new(task.key.clone(), task.payload.clone());
        self.submitter
            .submit(&inner)
            .map_err(|e| AdapterError::Transport { method: "submit_anchor".into(), message: e.to_string() })
    }

    fn poll(&mut self) -> Result<(), AdapterError> {
        self.submitter
            .poll()
            .map_err(|e| AdapterError::Transport { method: "poll".into(), message: e.to_string() })
    }

    fn pending_finality(&self) -> usize {
        self.submitter.pending_finality()
    }

    fn snapshot(&self) -> serde_json::Value {
        let anchors: serde_json::Map<String, serde_json::Value> = self
            .submitter
            .snapshot()
            .into_iter()
            .map(|(k, v)| {
                let (tx, block, finalized) = match v {
                    crate::anchor::AnchorState::Submitted { tx_hash } => (hex::encode(tx_hash), None, false),
                    crate::anchor::AnchorState::Included { tx_hash, block } => (hex::encode(tx_hash), Some(block), false),
                    crate::anchor::AnchorState::Finalized { tx_hash, block } => (hex::encode(tx_hash), Some(block), true),
                };
                (
                    k,
                    serde_json::json!({ "tx": format!("0x{tx}"), "block": block, "finalized": finalized }),
                )
            })
            .collect();
        let deposit_next_block = self
            .watcher
            .as_ref()
            .map_or(0, crate::watcher::DepositWatcher::next_block);
        let forced_watermark = self
            .watcher
            .as_ref()
            .and_then(crate::watcher::DepositWatcher::forced_watermark);
        serde_json::json!({
            "kind": "monad",
            "chain_id": self.chain_id,
            "anchors": anchors,
            "deposit_next_block": deposit_next_block,
            "forced_watermark": forced_watermark,
        })
    }

    fn restore(&mut self, snapshot: &serde_json::Value) {
        if snapshot.get("kind").and_then(serde_json::Value::as_str) != Some("monad") {
            return; // 异族快照拒绝（幂等无操作）
        }
        let mut map = std::collections::BTreeMap::new();
        if let Some(entries) = snapshot.get("anchors").and_then(serde_json::Value::as_object) {
            for (key, entry) in entries {
                let tx = (|| {
                    let s = entry.get("tx").and_then(serde_json::Value::as_str)?;
                    let trimmed = s.strip_prefix("0x").unwrap_or(s);
                    let mut out = [0u8; 32];
                    hex::decode_to_slice(trimmed, &mut out).ok()?;
                    Some(out)
                })();
                let Some(tx) = tx else {
                    continue;
                };
                let block = entry.get("block").and_then(serde_json::Value::as_u64);
                let finalized = entry.get("finalized").and_then(serde_json::Value::as_bool).unwrap_or(false);
                let state = match (block, finalized) {
                    (None, _) => crate::anchor::AnchorState::Submitted { tx_hash: tx },
                    (Some(b), false) => crate::anchor::AnchorState::Included { tx_hash: tx, block: b },
                    (Some(b), true) => crate::anchor::AnchorState::Finalized { tx_hash: tx, block: b },
                };
                map.insert(key.clone(), state);
            }
        }
        self.submitter.restore(map);
        // 水位恢复（监听窗口 + 强制包含 seq）。
        if let (Some(w), Some(next)) = (
            self.watcher.as_mut(),
            snapshot.get("deposit_next_block").and_then(serde_json::Value::as_u64),
        ) {
            w.advance_to(next);
        }
        if let Some(w) = self.watcher.as_mut() {
            w.restore_forced_watermark(
                snapshot.get("forced_watermark").and_then(serde_json::Value::as_u64),
            );
        }
    }

    fn poll_deposits(&mut self) -> Result<Vec<DepositRecord>, AdapterError> {
        let watcher = self
            .watcher
            .as_mut()
            .ok_or_else(|| AdapterError::NotConfigured("deposit watcher".into()))?;
        let events = watcher
            .poll_once()
            .map_err(|e| AdapterError::Transport { method: "poll_deposits".into(), message: e.to_string() })?;
        Ok(events
            .into_iter()
            .map(|ev| {
                let mut token = [0u8; 32];
                token[12..].copy_from_slice(&ev.token);
                let mut recipient = [0u8; 32];
                recipient[12..].copy_from_slice(&ev.to);
                DepositRecord {
                    nonce: ev.nonce,
                    token,
                    recipient,
                    amount: ev.amount,
                    host_block: ev.host_block,
                }
            })
            .collect())
    }

    fn poll_forced_ops(&mut self) -> Result<Vec<ForcedOpRecord>, AdapterError> {
        let watcher = self
            .watcher
            .as_mut()
            .ok_or_else(|| AdapterError::NotConfigured("forced-op watcher".into()))?;
        let events = watcher
            .poll_forced_ops()
            .map_err(|e| AdapterError::Transport {
                method: "poll_forced_ops".into(),
                message: e.to_string(),
            })?;
        Ok(events
            .into_iter()
            .map(|ev| {
                let mut submitter = [0u8; 32];
                submitter[12..].copy_from_slice(&ev.submitter);
                ForcedOpRecord {
                    seq: ev.seq,
                    submitter,
                    payload: ev.payload,
                    host_block: 0, // 事件面未携带高度时由 seq 排序保证语义
                }
            })
            .collect())
    }

    fn claim_payload(&self, request: &ClaimRequest) -> Result<Vec<u8>, AdapterError> {
        // PLAY（tag 2）为 L2 内部筹码，不提供 L1 兑付（与 L1Outbox 合约一致 fail-closed）。
        if request.asset_tag == 2 {
            return Err(AdapterError::NotConfigured("PLAY not claimable on host".into()));
        }
        if !(1..=4).contains(&request.asset_tag) {
            return Err(AdapterError::NotConfigured(format!("unknown asset tag {}", request.asset_tag)));
        }
        let leaf = ClaimLeaf {
            request_id: request.request_id,
            external_recipient: request.recipient,
            asset_tag: request.asset_tag,
            amount: request.amount,
            burned_note_commitment: request.burned_note_commitment,
            checkpoint_height: request.checkpoint_height,
        };
        Ok(encode_claim(&leaf, request.withdrawal_root, request.leaf_count, request.leaf_index, &request.proof))
    }
}

/// AnchorKind（settlement-adapter）→ 无需转换：payload 已含类型语义，
/// kind 仅用于去重 key 前缀（daemon 组装时使用）。
#[must_use]
pub fn anchor_key(kind: AnchorKind, id: u64, root: &[u8; 32]) -> String {
    format!("{}:{}:{}", kind.prefix(), id, hex::encode(root))
}
