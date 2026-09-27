//! 入金监听：Monad `DepositInitiated` → L2 铸 note 触发源。
//!
//! 轮询窗口以 **finalized** 高度为右端（入金确认即不可逆，L2 侧无需二次
//! 防护）；nonce 去重（跨轮幂等），左侧水位持久化由 daemon 状态文件负责。

use std::collections::HashSet;

use crate::abi::{parse_deposit_log, deposit_initiated_topic0, DepositEvent};
use crate::error::SettlementError;
use crate::l1::L1Rpc;

/// 入金监听器。
pub struct DepositWatcher {
    rpc: L1Rpc,
    /// L1Bridge 地址。
    bridge: [u8; 20],
    /// 下一个待扫描高度（含）。
    next_block: u64,
    /// 已见 nonce（跨轮去重）。
    seen: HashSet<u64>,
}

impl DepositWatcher {
    /// 构造（`start_block` 建议 = Bridge 部署高度；daemon 可从状态文件恢复）。
    #[must_use]
    pub fn new(rpc: L1Rpc, bridge: [u8; 20], start_block: u64) -> Self {
        Self { rpc, bridge, next_block: start_block, seen: HashSet::new() }
    }

    /// 下一扫描高度（状态持久化面）。
    #[must_use]
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// 一轮拉取（扫描 (last_finalized, next_block] → 已终结的入金事件）。
    ///
    /// # Errors
    /// RPC 失败 / 事件解析失败（单个坏日志 → 整轮 Err，fail-closed）。
    pub fn poll_once(&mut self) -> Result<Vec<DepositEvent>, SettlementError> {
        let finalized = self.rpc.finalized_block()?;
        if finalized < self.next_block {
            return Ok(Vec::new());
        }
        let logs = self.rpc.get_logs(
            self.next_block,
            finalized,
            &[self.bridge],
            Some(deposit_initiated_topic0()),
        )?;
        let mut events = Vec::new();
        for log in logs {
            let mut event = parse_deposit_log(&log.topics, &log.data)?;
            event.host_block = log.block_number;
            if self.seen.insert(event.nonce) {
                events.push(event);
            }
        }
        self.next_block = finalized + 1;
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_block_advances_only_after_scan() {
        let rpc = L1Rpc::new("http://127.0.0.1:1").expect("url ok");
        let w = DepositWatcher::new(rpc, [1u8; 20], 100);
        assert_eq!(w.next_block(), 100);
    }
}
