//! M7：出入金托管对账。
//!
//! v1 托管模式：REAL note 是运营方负债。本模块维护储备/浮存与已发行
//! note 的恒等关系，提供日终对账与差异告警输入；报表结构对齐 v2
//! STARK 储备证明的输入（note 集可导出）。
//!
//! ## 提现 finality 门槛（§5.4 配套，P0-3 同批落地）
//!
//! REAL note 的提现申请（托管打款侧）必须过 v1 finality 门：
//!
//! 1. 来源 op 已证明——`proven_watermark >= op_index`（连续前缀语义下
//!    等价于"该 op 已证明"）；
//! 2. 该 op 所属批次根已被记录——`batch_covered_through >= op_index`
//!    （sequencer 侧 `record_batch_root` 快照）。
//!
//! 未满足 → [`AppchainError::WithdrawalNotFinalized`] 并计
//! `withdrawal_finality_rejected_total`。PLAY note 不做此要求（软确认即可
//! 提，§5.1 分层）。开关 [`CustodyLedger::without_finality_gate`] 为**显式
//! opt-out，仅限测试/开发，非生产配置**（见 docs/ABI.md §9）。
//! provenance 由调用方从 sequencer 导出（[`crate::real_policy::
//! WithdrawalProvenance`]，`LedgerState.note_origins`：note 承诺 → 铸出
//! op，消费后保留、WAL 重放重建），类型系统保证不可缺省——未知
//! provenance 无法绕过门槛。

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::error::{AppchainError, AppchainResult};
use crate::metrics::{HealthInputs, MetricsRegistry};
use crate::note::AssetClass;
use crate::real_policy::{FinalityEvidence, WithdrawalProvenance};

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
#[derive(Debug)]
pub struct CustodyLedger {
    reserved: u128,
    deposits: BTreeMap<[u8; 32], u64>,
    withdrawals: BTreeMap<[u8; 32], WithdrawalEntry>,
    known_note_ids: HashSet<[u8; 32]>,
    /// 提现 finality 门槛（默认开启；关闭 = 显式 opt-out，仅限非生产）。
    withdrawal_requires_finality: bool,
    /// 可选 metrics（finality 拒绝计数 `withdrawal_finality_rejected_total`）。
    metrics: Option<Arc<MetricsRegistry>>,
}

impl Default for CustodyLedger {
    /// 默认 = finality 门**开启**（fail-closed；生产语义）。
    fn default() -> Self {
        Self {
            reserved: 0,
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            known_note_ids: HashSet::new(),
            withdrawal_requires_finality: true,
            metrics: None,
        }
    }
}

impl CustodyLedger {
    /// 空账（提现 finality 门默认开启）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// **显式 opt-out**：关闭提现 finality 门。仅限测试/开发环境——放宽路径
    /// 必须显式构造，文档标注非生产（docs/ABI.md §9）。
    #[must_use]
    pub fn without_finality_gate(mut self) -> Self {
        self.withdrawal_requires_finality = false;
        self
    }

    /// 注入 metrics（finality 拒绝计数）。
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 提现 finality 门是否开启。
    #[must_use]
    pub fn finality_required(&self) -> bool {
        self.withdrawal_requires_finality
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
    /// §5.4 finality 门（默认开启，见 [`CustodyLedger::finality_required`]）：
    /// REAL note 的提现要求来源 op 已被证明水位覆盖 **且** 其所属批次根已
    /// 记录（幂等命中先行——已受理的重复申请不受门槛复审影响）；未满足 →
    /// [`AppchainError::WithdrawalNotFinalized`] 并计
    /// `withdrawal_finality_rejected_total`。PLAY note 不做此要求。
    ///
    /// # Errors
    /// 同 id 异载荷 → [`AppchainError::WithdrawalConflict`]；
    /// REAL note 未达 finality → [`AppchainError::WithdrawalNotFinalized`]。
    pub fn enqueue_withdrawal(
        &mut self,
        request: WithdrawalRequest,
        provenance: WithdrawalProvenance,
        finality: FinalityEvidence,
    ) -> AppchainResult<&WithdrawalEntry> {
        // 幂等语义保持：已受理的同 id 同载荷申请直接返回既有条目
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
        // §5.4：REAL note 提现的 v1 finality 门（水位覆盖 + 批次根覆盖；
        // PLAY 豁免——软确认即可提，§5.1 分层）
        if self.withdrawal_requires_finality
            && provenance.asset_class == AssetClass::Real
            && !finality.covers(provenance.source_op_index)
        {
            if let Some(m) = &self.metrics {
                m.inc("withdrawal_finality_rejected_total");
            }
            return Err(AppchainError::WithdrawalNotFinalized {
                op_index: provenance.source_op_index,
                watermark: finality.proven_watermark,
            });
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

    fn request(id_byte: u8, payout_byte: u8, amount: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            request_id: [id_byte; 32],
            payout_address: [payout_byte; 32],
            amount,
        }
    }

    /// PLAY provenance（finality 门豁免类）。
    fn play_prov() -> WithdrawalProvenance {
        WithdrawalProvenance {
            asset_class: AssetClass::Play,
            source_op_index: 3,
        }
    }

    /// REAL provenance（来源 op = 5）。
    fn real_prov() -> WithdrawalProvenance {
        WithdrawalProvenance {
            asset_class: AssetClass::Real,
            source_op_index: 5,
        }
    }

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
        let req = request(1, 2, 50);
        v.enqueue_withdrawal(req.clone(), play_prov(), FinalityEvidence::default())
            .unwrap();
        // 幂等：同 id 同载荷重复申请（finality 证据不同也不复审既有条目）
        v.enqueue_withdrawal(req, play_prov(), FinalityEvidence::default())
            .unwrap();
        let bad = WithdrawalRequest {
            request_id: [1; 32],
            payout_address: [3; 32],
            amount: 50,
        };
        assert!(v.enqueue_withdrawal(bad, play_prov(), FinalityEvidence::default()).is_err());
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
        v.enqueue_withdrawal(request(1, 2, 50), play_prov(), FinalityEvidence::default())
            .unwrap();
        v.mark_paid([1; 32], [3; 32]).unwrap();
        assert!(v.mark_paid([1; 32], [4; 32]).is_err());
        assert_eq!(v.queued_withdrawals(), 0);
    }

    /// §5.4 finality 门（REAL）：水位未覆盖 → 拒；水位覆盖但批次根未记录
    /// → 拒；两者齐备 → 成功。
    #[test]
    fn withdrawal_finality_gate_real_note() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mut v = CustodyLedger::new().with_metrics(Arc::clone(&metrics));
        assert!(v.finality_required(), "finality gate must default on");

        // 负例 A：水位未覆盖来源 op → WithdrawalNotFinalized
        let err = v
            .enqueue_withdrawal(
                request(1, 2, 50),
                real_prov(),
                FinalityEvidence {
                    proven_watermark: 4,
                    batch_covered_through: Some(4),
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AppchainError::WithdrawalNotFinalized {
                op_index: 5,
                watermark: 4
            }
        ));
        assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 1);

        // 负例 B：水位已覆盖但批次根未记录（mark_proven 直推无批次回调）→ 拒
        let err = v
            .enqueue_withdrawal(
                request(1, 2, 50),
                real_prov(),
                FinalityEvidence {
                    proven_watermark: 9,
                    batch_covered_through: None,
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AppchainError::WithdrawalNotFinalized { .. }
        ));
        assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 2);

        // 负例 C：op 0 与「尚无批次根」在水位侧不可区分——批次根为 None 时
        // 即便水位覆盖也不放行（fail-closed 的存在性判定）
        let err = v
            .enqueue_withdrawal(
                WithdrawalRequest {
                    request_id: [7; 32],
                    payout_address: [8; 32],
                    amount: 1,
                },
                WithdrawalProvenance {
                    asset_class: AssetClass::Real,
                    source_op_index: 0,
                },
                FinalityEvidence {
                    proven_watermark: 9,
                    batch_covered_through: None,
                },
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AppchainError::WithdrawalNotFinalized { op_index: 0, .. }
        ));
        assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 3);

        // 正例：水位 + 批次根都覆盖 → 入队成功
        let entry = v
            .enqueue_withdrawal(
                request(1, 2, 50),
                real_prov(),
                FinalityEvidence {
                    proven_watermark: 9,
                    batch_covered_through: Some(7),
                },
            )
            .unwrap();
        assert_eq!(entry.status, WithdrawalStatus::Queued);
        assert_eq!(metrics.counter("withdrawal_finality_rejected_total"), 3);

        // 幂等复审豁免：finality 证据回退（异常构造）也不影响既有条目
        v.enqueue_withdrawal(
            request(1, 2, 50),
            real_prov(),
            FinalityEvidence::default(),
        )
        .unwrap();
    }

    /// §5.4：PLAY note 不做 finality 要求（软确认即可提，§5.1 分层）。
    #[test]
    fn play_withdrawal_exempt_from_finality() {
        let mut v = CustodyLedger::new();
        let entry = v
            .enqueue_withdrawal(request(2, 3, 70), play_prov(), FinalityEvidence::default())
            .unwrap();
        assert_eq!(entry.status, WithdrawalStatus::Queued);
    }

    /// §5.4：finality 开关关闭 = 显式 opt-out——REAL 未证明也可提现。
    /// 该构造是显式的（`without_finality_gate`），仅限非生产。
    #[test]
    fn finality_opt_out_allows_unproven_real_withdrawal() {
        let v_builder = CustodyLedger::new().without_finality_gate();
        assert!(!v_builder.finality_required(), "opt-out must be explicit");
        let mut v = v_builder;
        let entry = v
            .enqueue_withdrawal(request(4, 5, 90), real_prov(), FinalityEvidence::default())
            .unwrap();
        assert_eq!(entry.status, WithdrawalStatus::Queued);
        // 默认构造仍是 fail-closed（同证据下拒绝）
        let mut strict = CustodyLedger::new();
        assert!(strict
            .enqueue_withdrawal(request(4, 5, 90), real_prov(), FinalityEvidence::default())
            .is_err());
    }
}
