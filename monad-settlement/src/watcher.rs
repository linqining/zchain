//! 入金监听：Monad `DepositInitiated` → L2 铸 note 触发源。
//!
//! 轮询窗口以 **finalized** 高度为右端（入金确认即不可逆，L2 侧无需二次
//! 防护）；nonce 去重（跨轮幂等），左侧水位持久化由 daemon 状态文件负责。

use std::collections::HashSet;

use crate::abi::{
    deposit_initiated_topic0, forced_op_topic0, parse_deposit_log, parse_forced_op_log,
    DepositEvent, ForcedOpEvent,
};
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
    /// 已见强制包含 seq（跨轮去重）。
    seen_forced: HashSet<u64>,
    /// 强制包含水位（已消费的最大 seq；`None` = 尚未消费任何——
    /// 注意 seq 从 0 起，用 Option 防"初始 0 吞掉首个事件"的 off-by-one）。
    forced_watermark: Option<u64>,
}

impl DepositWatcher {
    /// 构造（`start_block` 建议 = Bridge 部署高度；daemon 可从状态文件恢复）。
    #[must_use]
    pub fn new(rpc: L1Rpc, bridge: [u8; 20], start_block: u64) -> Self {
        Self {
            rpc,
            bridge,
            next_block: start_block,
            seen: HashSet::new(),
            seen_forced: HashSet::new(),
            forced_watermark: None,
        }
    }

    /// 下一扫描高度（状态持久化面）。
    #[must_use]
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// 恢复扫描水位（重启续跑；仅允许前进，回退 = 无操作防重放）。
    pub fn advance_to(&mut self, block: u64) {
        if block > self.next_block {
            self.next_block = block;
        }
    }

    /// 强制包含水位（已消费最大 seq；`None` = 未消费任何）。
    #[must_use]
    pub fn forced_watermark(&self) -> Option<u64> {
        self.forced_watermark
    }

    /// 恢复强制包含水位（重启续跑；仅允许前进）。
    pub fn restore_forced_watermark(&mut self, seq: Option<u64>) {
        match (self.forced_watermark, seq) {
            (_, None) => {}
            (None, Some(v)) => self.forced_watermark = Some(v),
            (Some(cur), Some(v)) if v > cur => self.forced_watermark = Some(v),
            _ => {}
        }
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

    /// 强制包含监听（escape channel）：与入金同一 finalized 窗口，seq 升序去重。
    ///
    /// # Errors
    /// RPC 失败 / 事件解析失败（fail-closed）。
    pub fn poll_forced_ops(&mut self) -> Result<Vec<ForcedOpEvent>, SettlementError> {
        let finalized = self.rpc.finalized_block()?;
        if finalized < self.next_block {
            return Ok(Vec::new());
        }
        let logs = self.rpc.get_logs(
            self.next_block,
            finalized,
            &[self.bridge],
            Some(forced_op_topic0()),
        )?;
        let mut events = Vec::new();
        for log in logs {
            let event = parse_forced_op_log(&log.topics, &log.data)?;
            // 水位纪律：只产出 seq > 已消费水位（重启后旧 seq 不重放）。
            if self.forced_watermark.is_some_and(|w| event.seq <= w)
                || !self.seen_forced.insert(event.seq)
            {
                continue;
            }
            self.forced_watermark =
                Some(self.forced_watermark.map_or(event.seq, |w: u64| w.max(event.seq)));
            events.push(event);
        }
        // 窗口推进（与 poll_once 同纪律）：不推进 → 窗口随高度无限增长，
        // 公共 RPC 100 块上限 → 413 永久失败（实测抓出）。
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
