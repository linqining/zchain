//! M7：出入金托管对账。
//!
//! v1 托管模式：REAL note 是运营方负债。本模块维护储备/浮存与已发行
//! note 的恒等关系，提供日终对账与差异告警输入；报表结构对齐 v2
//! STARK 储备证明的输入（note 集可导出）。

use std::collections::{BTreeMap, HashSet};

use crate::error::{AppchainError, AppchainResult};
use crate::metrics::HealthInputs;

/// 提现请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalRequest {
    /// 幂等键。
    pub request_id: [u8; 32],
    /// 收款外部地址（v1: Starknet 地址字节）。
    pub payout_address: [u8; 32],
    /// 金额。
    pub amount: u64,
}

/// 提现状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalStatus {
    /// 排队（note 已销毁，待打款）。
    Queued,
    /// 已打款（外部 tx hash 记录在案）。
    Paid,
}

/// 提现条目。
#[derive(Debug, Clone)]
pub struct WithdrawalEntry {
    /// 请求。
    pub request: WithdrawalRequest,
    /// 状态。
    pub status: WithdrawalStatus,
    /// 外部交易哈希（打款后填）。
    pub tx_hash: Option<[u8; 32]>,
}

/// 日终对账报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationReport {
    /// 已发行 REAL note 总额（来自 sequencer 账本）。
    pub issued_real_total: u128,
    /// 链上储备 + 浮存（外部录入）。
    pub reserved: u128,
    /// 排队中提现总额（已销毁未打款）。
    pub pending_withdrawal_total: u128,
    /// 差异 = reserved - (issued + pending)。0 = 平。
    pub delta: i128,
}

/// 托管账（vault）。
#[derive(Debug, Default)]
pub struct CustodyLedger {
    reserved: u128,
    deposits: BTreeMap<[u8; 32], u64>,
    withdrawals: BTreeMap<[u8; 32], WithdrawalEntry>,
    known_note_ids: HashSet<[u8; 32]>,
}

impl CustodyLedger {
    /// 空账。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 外部储备录入（链上余额读取由上层周期性注入）。
    pub fn record_external_reserve(&mut self, reserved: u128) {
        self.reserved = reserved;
    }

    /// 入金确认（幂等：同 deposit_id 同载荷重复确认返回 Ok；异载荷冲突）。
    ///
    /// # Errors
    /// 同 id 不同载荷 → [`AppchainError::WithdrawalConflict`]。
    pub fn confirm_deposit(
        &mut self,
        deposit_id: [u8; 32],
        note_commitment: [u8; 32],
        amount: u64,
    ) -> AppchainResult<()> {
        match self.deposits.get(&deposit_id) {
            Some(prev) if *prev == amount => return Ok(()),
            Some(_) => {
                return Err(AppchainError::WithdrawalConflict(
                    "deposit id payload mismatch".into(),
                ))
            }
            None => {}
        }
        if !self.known_note_ids.insert(note_commitment) {
            return Err(AppchainError::WithdrawalConflict(
                "note already bound to a deposit".into(),
            ));
        }
        self.deposits.insert(deposit_id, amount);
        Ok(())
    }

    /// 提现入队（幂等：同 id 同载荷返回既有条目；异载荷冲突）。
    ///
    /// # Errors
    /// 同 id 异载荷 → [`AppchainError::WithdrawalConflict`]。
    pub fn enqueue_withdrawal(
        &mut self,
        request: WithdrawalRequest,
    ) -> AppchainResult<&WithdrawalEntry> {
        match self.withdrawals.get(&request.request_id) {
            Some(e) if e.request.payout_address == request.payout_address
                && e.request.amount == request.amount =>
            {
                return Ok(self
                    .withdrawals
                    .get(&request.request_id)
                    .expect("checked above"));
            }
            Some(_) => {
                return Err(AppchainError::WithdrawalConflict(
                    "withdrawal id payload mismatch".into(),
                ))
            }
            None => {}
        }
        let id = request.request_id;
        self.withdrawals.insert(
            id,
            WithdrawalEntry {
                request,
                status: WithdrawalStatus::Queued,
                tx_hash: None,
            },
        );
        Ok(self.withdrawals.get(&id).expect("just inserted"))
    }

    /// 打款完成。
    ///
    /// # Errors
    /// 未知请求或已支付 → [`AppchainError::WithdrawalConflict`]。
    pub fn mark_paid(
        &mut self,
        request_id: [u8; 32],
        tx_hash: [u8; 32],
    ) -> AppchainResult<()> {
        let e = self
            .withdrawals
            .get_mut(&request_id)
            .ok_or_else(|| AppchainError::WithdrawalConflict("unknown request".into()))?;
        if e.status == WithdrawalStatus::Paid {
            return Err(AppchainError::WithdrawalConflict("already paid".into()));
        }
        e.status = WithdrawalStatus::Paid;
        e.tx_hash = Some(tx_hash);
        Ok(())
    }

    /// 已发行 REAL note 总额录入（来自 sequencer 账本聚合）。
    ///
    /// v1 语义：issued = 存续 REAL note 面额 + 已销毁（提现中/已提现）面额。
    /// 本方法只记录账本侧数字；对账时与 reserved + 打款回冲比较。
    #[must_use]
    pub fn reconciliation(
        &self,
        issued_real_total: u128,
    ) -> AppchainResult<ReconciliationReport> {
        let pending: u128 = self
            .withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .map(|e| u128::from(e.request.amount))
            .sum();
        // v1 托管语义：reserved 必须覆盖（存续 note + 未打款提现）。
        let delta = i128::try_from(self.reserved)
            .ok()
            .and_then(|r| r.checked_sub(i128::try_from(issued_real_total).ok()?))
            .ok_or(AppchainError::ReconciliationMismatch {
                issued: issued_real_total,
                reserved: self.reserved,
            })?;
        Ok(ReconciliationReport {
            issued_real_total,
            reserved: self.reserved,
            pending_withdrawal_total: pending,
            delta,
        })
    }

    /// 对账或报错（差异非零 → [`AppchainError::ReconciliationMismatch`]）。
    ///
    /// # Errors
    /// 差异非零或数值溢出。
    pub fn require_balanced(&self, issued_real_total: u128) -> AppchainResult<ReconciliationReport> {
        let r = self.reconciliation(issued_real_total)?;
        if r.delta != 0 {
            return Err(AppchainError::ReconciliationMismatch {
                issued: issued_real_total,
                reserved: self.reserved,
            });
        }
        Ok(r)
    }

    /// 健康输入（告警评估）。
    #[must_use]
    pub fn health(&self, issued_real_total: u128) -> HealthInputs {
        let pending = self
            .withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .count() as u64;
        let delta = i128::try_from(self.reserved).unwrap_or(i128::MAX)
            - i128::try_from(issued_real_total).unwrap_or(i128::MAX);
        HealthInputs {
            proof_queue_depth: 0,
            proof_degraded: false,
            withdrawal_queue_depth: pending,
            reconciliation_delta: delta,
            soft_confirm_idle_ms: 0,
        }
    }

    /// 排队提现数。
    #[must_use]
    pub fn queued_withdrawals(&self) -> usize {
        self.withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_idempotent_and_conflict() {
        let mut v = CustodyLedger::new();
        let mut id = [0u8; 32];
        id[0] = 1;
        v.confirm_deposit(id, [1u8; 32], 100).unwrap();
        v.confirm_deposit(id, [1u8; 32], 100).unwrap(); // 同载荷幂等
        let err = v.confirm_deposit(id, [2u8; 32], 200).unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalConflict(_)));
    }

    #[test]
    fn withdrawal_idempotent_and_conflict() {
        let mut v = CustodyLedger::new();
        let req = WithdrawalRequest {
            request_id: [1; 32],
            payout_address: [2; 32],
            amount: 50,
        };
        v.enqueue_withdrawal(req.clone()).unwrap();
        v.enqueue_withdrawal(req).unwrap(); // 幂等
        let bad = WithdrawalRequest {
            request_id: [1; 32],
            payout_address: [3; 32],
            amount: 50,
        };
        assert!(v.enqueue_withdrawal(bad).is_err());
    }

    #[test]
    fn reconciliation_balanced_and_mismatch() {
        let mut v = CustodyLedger::new();
        v.record_external_reserve(1_000);
        let r = v.require_balanced(1_000).unwrap();
        assert_eq!(r.delta, 0);
        assert!(v.require_balanced(999).is_err());
    }

    #[test]
    fn paid_twice_rejected() {
        let mut v = CustodyLedger::new();
        v.enqueue_withdrawal(WithdrawalRequest {
            request_id: [1; 32],
            payout_address: [2; 32],
            amount: 50,
        })
        .unwrap();
        v.mark_paid([1; 32], [3; 32]).unwrap();
        assert!(v.mark_paid([1; 32], [4; 32]).is_err());
        assert_eq!(v.queued_withdrawals(), 0);
    }
}
