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
//!
//! ## 提现费（M7，v1 托管侧定价）
//!
//! [`WithdrawalFeeConfig`]（v1：固定 flat 费，覆盖外部 gas；默认 0 = 免费）
//! 挂在 [`CustodyLedger`] 上。受理时从请求金额中扣减：
//! `fee = flat_fee`，打款净额 `payout_amount = amount − fee`；`fee > amount`
//! 直接拒绝（[`AppchainError::OutOfRange`]，计 `withdrawal_fee_rejected_total`
//! ）——不存在净额为 0/负的打款。对账恒等式保持：
//! `delta = reserved − issued` 不变（fee 从被提现余额内扣，链上销毁面额
//! 不变），浮存侧新增分解 `pending_withdrawal_total == pending_payout_total
//! + pending_fee_float`（排队额 = 对外应付净额 + 留存费用浮存）。
//!
//! ## 提现 SLA 计时器（M7-ACC-2 / M9）
//!
//! 每条提现记录受理时刻 `requested_at_ms`（注入时钟——生产默认
//! `SystemTime`，测试注入固定值，参照 sequencer 的 `now_ms` 参数模式）；
//! [`CustodyLedger::sla_report`] 输出排队数/越限数/等待 p95，越限首次
//! 发生计 `withdrawal_sla_breach_total`（同一请求不重复计数）。

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AppchainError, AppchainResult};
// TE-M2：多币托管资产身份（CustodyLedgerV2 按 AssetId 分账；v1 路径零变更）
use crate::asset_id::AssetId;
use crate::metrics::{HealthInputs, MetricsRegistry};
use crate::note::AssetClass;
use crate::real_policy::{FinalityEvidence, WithdrawalProvenance};
use crate::withdrawal_root::WithdrawalLeaf;

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

impl WithdrawalRequest {
    /// 受理载荷 ↔ 链上 op 一致性断言（审计 P1 修复配套，fail-closed）。
    ///
    /// `Operation::WithdrawRequest` 的效果摘要绑定 `payout_recipient` 并被
    /// owner 签名覆盖——托管受理侧必须核对受理载荷的收款地址/幂等键/金额
    /// 与签名 op 逐字段全等，否则操作方（或桥接环节）可在持签请求上偷换
    /// 收款人。任何失配 → [`AppchainError::WithdrawalConflict`]；op 不是
    /// v1 WithdrawRequest → [`AppchainError::AdmissionRejected`]。受理入口
    /// 见 [`CustodyLedger::enqueue_withdrawal_for_op`]。
    ///
    /// # Errors
    /// 载荷与 op 任何字段失配，或 op 变体不符。
    pub fn ensure_matches_op(
        &self,
        op: &crate::ops::Operation,
    ) -> AppchainResult<()> {
        match op {
            crate::ops::Operation::WithdrawRequest {
                request_id,
                note,
                payout_recipient,
                ..
            } => {
                if self.request_id != *request_id
                    || self.payout_address != *payout_recipient
                    || self.amount != note.amount
                {
                    return Err(AppchainError::WithdrawalConflict(
                        "withdrawal request does not match the signed op".into(),
                    ));
                }
                Ok(())
            }
            _ => Err(AppchainError::AdmissionRejected(
                "op is not a v1 WithdrawRequest",
            )),
        }
    }
}

/// 提现费配置（v1：固定 flat 费，覆盖外部 gas）。
///
/// 默认 0 = 免费（完全向后兼容：不配置即维持既有零费语义）。费从被提现
/// 余额内扣——链上销毁面额不变，托管打款净额 = `amount − flat_fee`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalFeeConfig {
    /// 每笔提现的固定费用。
    pub flat_fee: u64,
}

impl Default for WithdrawalFeeConfig {
    /// 默认免费（0）。
    fn default() -> Self {
        Self { flat_fee: 0 }
    }
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
    /// 受理时计提的提现费（`min(flat_fee, amount)`；负例在受理即拒）。
    pub fee: u64,
    /// 打款净额（`amount − fee`；打款执行侧按此数对外支付）。
    pub payout_amount: u64,
    /// 受理时刻（注入时钟，毫秒；SLA 计时起点）。
    pub requested_at_ms: u64,
    /// SLA 越限是否已计数（防重复计数）。
    sla_breach_counted: bool,
}

/// 提现 SLA 报告（M7-ACC-2：`sla_report` 输出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalSlaReport {
    /// 当前排队请求数。
    pub pending: u64,
    /// 等待超过阈值（`now − requested_at > threshold`）的排队数。
    pub breached_count: u64,
    /// 排队请求等待时长的 p95（无排队 → `null`）。
    pub p95_wait_ms: Option<u64>,
}

/// 排队提现的 leaf 投影（§5.4：`CustodyLedger::pending_withdrawal_leaves`
/// 输出；vault 队列侧可证字段）。
///
/// `payout_amount` 语义为**打款净额**——M7 提现费从请求金额内扣后的对外
/// 应付数，即 [`WithdrawalLeaf::amount`] 的取值（叶子承诺净额而非含费数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingWithdrawal {
    /// 提现请求幂等键（→ [`WithdrawalLeaf::request_id`]；claim 台账防重放
    /// 主键）。
    pub request_id: [u8; 32],
    /// 收款外部地址（→ [`WithdrawalLeaf::external_recipient`]）。
    pub external_recipient: [u8; 32],
    /// 打款净额 `amount − fee`（→ [`WithdrawalLeaf::amount`]）。
    pub payout_amount: u64,
}

impl PendingWithdrawal {
    /// 补齐队列外字段 → 完整 [`WithdrawalLeaf`]。
    ///
    /// `asset_class` 取 `note::AssetClass` 判别值（REAL=1 / PLAY=2）；
    /// `burned_note_commitment` 为被销毁 note 的承诺
    /// （`Operation::WithdrawRequest.spend.commitment`）。**诚实降级**：v1
    /// 提现队列不逐条保留这两个字段（provenance 在受理时消费、不入账），
    /// 由调用方从 sequencer 的 WithdrawRequest op 记录取——队列字段化属
    /// 后续；`checkpoint_height` 为目标窗口高度（队列条目**不携带**自身
    /// checkpoint 归属，见 [`CustodyLedger::pending_withdrawal_leaves`] 的
    /// 边界文档——调用方必须传**正被 finalize 的窗口**高度，不得把未
    /// finalize 窗口的高度折入已 finalized 的根）。
    #[must_use]
    pub fn into_leaf(
        self,
        asset_class: u8,
        burned_note_commitment: [u8; 32],
        checkpoint_height: u64,
    ) -> WithdrawalLeaf {
        WithdrawalLeaf {
            request_id: self.request_id,
            external_recipient: self.external_recipient,
            asset_class,
            amount: self.payout_amount,
            burned_note_commitment,
            checkpoint_height,
        }
    }
}

/// 日终对账报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationReport {
    /// 已发行 REAL note 总额（来自 sequencer 账本）。
    pub issued_real_total: u128,
    /// 链上储备 + 浮存（外部录入）。
    pub reserved: u128,
    /// 排队中提现总额（已销毁未打款；含费）。
    pub pending_withdrawal_total: u128,
    /// 排队中提现的对外应付净额（= pending_withdrawal_total −
    /// pending_fee_float；M7 提现费分解的浮存侧）。
    pub pending_payout_total: u128,
    /// 排队中提现的留存费用浮存（fee 从余额内扣、暂留托管侧）。
    pub pending_fee_float: u128,
    /// 差异 = reserved − issued。0 = 平（费从余额内扣，恒等式与零费时
    /// 完全一致——不引入第三条边）。
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
    /// 提现费配置（默认 0 = 免费；M7 v1 托管侧定价）。
    withdrawal_fee: WithdrawalFeeConfig,
    /// 可选 metrics（finality 拒绝 / SLA 越限 / 费用拒绝计数）。
    metrics: Option<Arc<MetricsRegistry>>,
}

impl Default for CustodyLedger {
    /// 默认 = finality 门**开启**（fail-closed；生产语义）+ 零费。
    fn default() -> Self {
        Self {
            reserved: 0,
            deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            known_note_ids: HashSet::new(),
            withdrawal_requires_finality: true,
            withdrawal_fee: WithdrawalFeeConfig::default(),
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

    /// 注入 metrics（finality 拒绝 / SLA 越限 / 费用拒绝计数）。
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 设置提现费配置（builder 风格；默认 0 = 免费）。
    #[must_use]
    pub fn with_withdrawal_fee(mut self, fee: WithdrawalFeeConfig) -> Self {
        self.withdrawal_fee = fee;
        self
    }

    /// 当前提现费配置。
    #[must_use]
    pub fn withdrawal_fee(&self) -> WithdrawalFeeConfig {
        self.withdrawal_fee
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
    /// 受理时刻取生产墙钟（[`wallclock_ms`]）；测试请用
    /// [`CustodyLedger::enqueue_withdrawal_at`] 注入时钟。
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
        let now_ms = wallclock_ms();
        self.enqueue_withdrawal_at(request, provenance, finality, now_ms)
    }

    /// 提现入队（**op 绑定受理入口**，审计 P1 修复配套；注入时钟版本）。
    ///
    /// 闸门 0 = [`WithdrawalRequest::ensure_matches_op`]：受理载荷的收款
    /// 地址/幂等键/金额必须与链上已受理的 v1 WithdrawRequest op（owner
    /// 签名覆盖 `payout_recipient`）逐字段全等——fail-closed，账本不可能
    /// 记入 owner 未签名的收款人。通过后语义与
    /// [`CustodyLedger::enqueue_withdrawal_at`] 完全一致（finality 门/
    /// 幂等/费用按原序复审）。
    ///
    /// # Errors
    /// 载荷与 op 失配 → [`AppchainError::WithdrawalConflict`]；其余见
    /// [`CustodyLedger::enqueue_withdrawal_at`]。
    pub fn enqueue_withdrawal_for_op(
        &mut self,
        request: WithdrawalRequest,
        op: &crate::ops::Operation,
        provenance: WithdrawalProvenance,
        finality: FinalityEvidence,
        now_ms: u64,
    ) -> AppchainResult<&WithdrawalEntry> {
        request.ensure_matches_op(op)?;
        self.enqueue_withdrawal_at(request, provenance, finality, now_ms)
    }

    /// 提现入队（注入时钟版本；`now_ms` 为受理时刻，SLA 计时起点）。
    ///
    /// 费用语义（[`WithdrawalFeeConfig`]）：`fee = flat_fee`，打款净额 =
    /// `amount − fee`；`fee > amount` → [`AppchainError::OutOfRange`] 并计
    /// `withdrawal_fee_rejected_total`（负例 fail-closed：不产生净额 ≤ 0 的
    /// 打款任务）。幂等命中仍先行——已受理条目按受理时的费配置保留。
    ///
    /// # Errors
    /// 同 id 异载荷 → [`AppchainError::WithdrawalConflict`]；
    /// REAL note 未达 finality → [`AppchainError::WithdrawalNotFinalized`]；
    /// 费用超过金额 → [`AppchainError::OutOfRange`]。
    pub fn enqueue_withdrawal_at(
        &mut self,
        request: WithdrawalRequest,
        provenance: WithdrawalProvenance,
        finality: FinalityEvidence,
        now_ms: u64,
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
        // M7 提现费：从余额内扣；费用超过金额即拒绝（fail-closed 负例）
        let fee = self.withdrawal_fee.flat_fee;
        if fee > request.amount {
            if let Some(m) = &self.metrics {
                m.inc("withdrawal_fee_rejected_total");
            }
            return Err(AppchainError::OutOfRange("withdrawal fee exceeds amount"));
        }
        let id = request.request_id;
        self.withdrawals.insert(
            id,
            WithdrawalEntry {
                payout_amount: request.amount - fee,
                fee,
                request,
                status: WithdrawalStatus::Queued,
                tx_hash: None,
                requested_at_ms: now_ms,
                sla_breach_counted: false,
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
    /// 本方法只记录账本侧数字；对账时与 reserved 比较（`delta = reserved −
    /// issued`；提现费从被提现余额内扣，销毁面额与恒等式均不变）。
    #[must_use]
    pub fn reconciliation(
        &self,
        issued_real_total: u128,
    ) -> AppchainResult<ReconciliationReport> {
        let mut pending: u128 = 0;
        let mut pending_payout: u128 = 0;
        let mut pending_fee: u128 = 0;
        for e in self
            .withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
        {
            pending = pending
                .checked_add(u128::from(e.request.amount))
                .ok_or(AppchainError::OutOfRange("pending withdrawal sum overflow"))?;
            pending_payout = pending_payout
                .checked_add(u128::from(e.payout_amount))
                .ok_or(AppchainError::OutOfRange("pending payout sum overflow"))?;
            pending_fee = pending_fee
                .checked_add(u128::from(e.fee))
                .ok_or(AppchainError::OutOfRange("pending fee sum overflow"))?;
        }
        // 浮存侧分解不变量：排队总额 = 对外应付净额 + 留存费用浮存。
        debug_assert_eq!(pending, pending_payout + pending_fee);
        // v1 托管语义：reserved 必须覆盖已发行 note（含存续与已销毁）。
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
            pending_payout_total: pending_payout,
            pending_fee_float: pending_fee,
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
            rate_limit_rejected_window: 0,
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

    /// 排队中提现请求的快照（打款执行侧轮询用；B7 事件桥——
    /// 托管打款执行器据此逐笔 `pay_withdrawal` → `mark_paid`）。
    #[must_use]
    pub fn queued_requests(&self) -> Vec<WithdrawalRequest> {
        self.withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .map(|e| e.request.clone())
            .collect()
    }

    /// 排队中提现的打款任务快照：(请求, 打款净额)。打款执行侧按净额对外
    /// 支付（费用已在受理时从余额内扣，不参与打款）。
    #[must_use]
    pub fn queued_payouts(&self) -> Vec<(WithdrawalRequest, u64)> {
        self.withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .map(|e| (e.request.clone(), e.payout_amount))
            .collect()
    }

    /// 排队提现 → [`WithdrawalLeaf`] 投影快照（§5.4 permissionless claim 的
    /// 输入侧；**不做自动触发**——由主控在 checkpoint BFT finalized 后拉取，
    /// 聚合为 withdrawal_root，见 [`crate::withdrawal_root`]）。
    ///
    /// 返回**全部**排队条目、按 `request_id` 字典序（BTreeMap 迭代序，聚合
    /// 确定性）；每条均在受理时过了 §5.4 finality 门（proven 水位 + 批次根）。
    ///
    /// **边界（审计 P2 修复：诚实签名）**：v1 队列不逐条记录 checkpoint
    /// 归属（checkpoint 携带 withdrawal_root 字段属后续集成，见
    /// `withdrawal_root` 模块文档），故本查询**无逐条窗口高度可过滤**——
    /// 刻意不收高度参数（旧签名的 `finalized_below_height` 从未生效，
    /// 保留即误导）。纪律：**必须由调用方保证仅已 finalize 的窗口入根**
    /// ——即只有当全部排队条目所属窗口已 BFT finalized 时才可聚合出根
    /// （与 [`crate::withdrawal_root::ClaimLedger`] 的根摘要重绑定配合：
    /// 未 finalized 的根不可 claim）。逐条 checkpoint 归属过滤待字段
    /// 集成后收紧（届时恢复高度过滤入参）。v2 侧
    /// [`CustodyLedgerV2::pending_withdrawals_v2`] 同纪律（无高度参数）。
    #[must_use]
    pub fn pending_withdrawal_leaves(&self) -> Vec<PendingWithdrawal> {
        self.withdrawals
            .values()
            .filter(|e| e.status == WithdrawalStatus::Queued)
            .map(|e| PendingWithdrawal {
                request_id: e.request.request_id,
                external_recipient: e.request.payout_address,
                payout_amount: e.payout_amount,
            })
            .collect()
    }

    /// 打款净额查询（打款执行侧按 request_id 取净额；未知 → `None`）。
    #[must_use]
    pub fn payout_amount_of(&self, request_id: &[u8; 32]) -> Option<u64> {
        self.withdrawals
            .get(request_id)
            .map(|e| e.payout_amount)
    }

    /// 提现 SLA 报告（M7-ACC-2 / M9）。
    ///
    /// 对全部排队请求计算等待 `wait = now_ms − requested_at_ms`；`wait >
    /// threshold_ms` 记越限。越限**首次发生**计
    /// `withdrawal_sla_breach_total`（条目内一次性标记，重复拉取报告不重复
    /// 计数）。需要 `&mut`：越限标记落条目。
    pub fn sla_report(&mut self, now_ms: u64, threshold_ms: u64) -> WithdrawalSlaReport {
        let mut waits: Vec<u64> = Vec::new();
        let mut breached = 0u64;
        for e in self
            .withdrawals
            .values_mut()
            .filter(|e| e.status == WithdrawalStatus::Queued)
        {
            let wait = now_ms.saturating_sub(e.requested_at_ms);
            waits.push(wait);
            if wait > threshold_ms {
                breached += 1;
                if !e.sla_breach_counted {
                    e.sla_breach_counted = true;
                    if let Some(m) = &self.metrics {
                        m.inc("withdrawal_sla_breach_total");
                    }
                }
            }
        }
        waits.sort_unstable();
        let p95_wait_ms = if waits.is_empty() {
            None
        } else {
            let idx = (((waits.len() as f64) - 1.0) * 0.95).round() as usize;
            Some(waits[idx.min(waits.len() - 1)])
        };
        WithdrawalSlaReport {
            pending: waits.len() as u64,
            breached_count: breached,
            p95_wait_ms,
        }
    }
}

/// 生产墙钟（毫秒；参照 sequencer 的可注入时钟模式——生产默认
/// `SystemTime`，测试走 `enqueue_withdrawal_at` 注入固定值）。
fn wallclock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ===========================================================================
// TE-M2：REAL 多币种托管（CustodyLedgerV2；排期表 §6 TE-M2 行，设计依据
// docs/plan-token-economy-v1.md §2.2/§2.3）
//
// v1 [`CustodyLedger`] 是单币标量账（冻结不动）；本段交付按 [`AssetId`]
// 独立分账的 v2 托管：
//
// - **独立托管/独立对账/独立提现通道**：每个 REAL 域 token 一本
//   [`TokenCustody`]（储备/入金幂等/提现队列/note 绑定互相不可见）；
// - **对账恒等式 per-token 成立**：`delta_token = reserved_token −
//   issued_token`，浮存分解 `pending_withdrawal_total[token] ==
//   pending_payout_total[token] + pending_fee_float[token]`；
// - **禁止跨币种轧差（INV-TE-2）**：本类型**不提供任何跨 token 汇总/
//   抵扣**——储备核验、对账、提现受理全部按 token 独立判定；USDT 短库
//   不能用 NATIVE 长库抵（`total_by_token()` 只按 token 输出，测试钉死
//   "USDT 短库 + NATIVE 长库 → USDT 提现仍拒"）；
// - **提现费 per-token 可配**（[`CustodyLedgerV2::with_token_fee`]，默认
//   沿用零费），费从该 token 被提现余额内扣（M7 语义按 token 复制）；
// - **finality 门按 domain 判**（TE-M1 冻结决策）：REAL 域任何 token 走
//   proven 水位 + 批次根双门；GAME 域资产拒入本托管（fail-closed——
//   GAME 赎回属 TE-M3+ 的独立通道）。
//
// 边界（如实声明）：本类型是 sequencer **外挂**托管账（与 v1 同架构，
// 不入状态根）——账本侧 v2 幂等集/销毁记录/来源映射由 WAL 重放恢复
// （`LedgerState` 扩展），托管队列由重放后按同一受理语义等价重建
// （`tests/te_m2.rs` 钉死）；链上实际打款（原生转账 / ERC20 transfer
// 分通道执行）属 TE-M4 后/部署阶段，本层只产出按 token 分道的打款任务
// 快照。
// ===========================================================================

/// TE-M2 提现 provenance：资产身份 + 铸出来源 op。
///
/// [`crate::real_policy::WithdrawalProvenance`]（v1，`AssetClass` 类型，
/// 冻结不动）的 AssetId 推广——finality 门判据从 `asset_class == Real`
/// 升级为 [`AssetId::is_real_domain`]（按 domain 不按 token，TE-M1 冻结
/// 决策）。来源 op 由调用方从 sequencer 导出
/// （`Sequencer::withdrawal_provenance_v2`：live 条目优先、销毁后回落
/// `note_origins_v2`，消费后保留——托管打款侧仍可查）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalProvenanceV2 {
    /// 被提现 note 的资产身份（finality 门按其 domain 判）。
    pub asset_id: AssetId,
    /// note 铸出时的帧链 op 序号。
    pub source_op_index: u64,
}

/// TE-M2 提现申请（托管受理侧载荷；`ops::WithdrawRequestV2Op` 的语义
/// 子集——验签/销毁已在 sequencer 准入完成，托管侧只做账务受理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalRequestV2 {
    /// 提现幂等键（per-token 查重）。
    pub request_id: [u8; 32],
    /// 提现资产（REAL 域 token）。
    pub asset_id: AssetId,
    /// 外部收款地址。
    pub external_recipient: [u8; 32],
    /// 提现总额（含费；打款净额 = gross − fee，费从余额内扣）。
    pub gross_amount: u64,
}

/// 单 token 托管摘要（[`CustodyLedgerV2::total_by_token`] 输出行）。
///
/// **刻意没有跨 token 合计类型**：任何把多行折叠成一个标量的路径都会
/// 重新引入轧差（INV-TE-2 禁止），故本类型只有 per-token 视图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCustodySummary {
    /// 外部储备快照（watcher 按币种注入）。
    pub reserved: u128,
    /// 排队提现总额（含费；已销毁未打款）。
    pub queued_withdrawal_total: u128,
    /// 排队提现对外应付净额。
    pub queued_payout_total: u128,
    /// 排队提现留存费用浮存。
    pub queued_fee_float: u128,
    /// 排队请求数。
    pub queued_count: u64,
}

/// 单 token 独立托管分账（私有；字段互相不可见 = 独立托管的结构表达）。
#[derive(Debug, Clone, Default)]
struct TokenCustody {
    /// 外部储备快照。
    reserved: u128,
    /// 入金确认记录（deposit_id → 面额；per-token 幂等）。
    deposits: BTreeMap<[u8; 32], u64>,    /// 提现队列（request_id → 条目；per-token 独立通道）。
    withdrawals: BTreeMap<[u8; 32], WithdrawalEntry>,
    /// note 承诺绑定集（per-token；一张 note 只能绑定一次入金）。
    known_note_ids: HashSet<[u8; 32]>,
}

impl TokenCustody {
    /// 浮存侧分解（排队总额 = 应付净额 + 费用浮存；per-token 恒等式，
    /// 溢出 fail-closed）。
    fn pending_breakdown(&self) -> AppchainResult<(u128, u128, u128)> {
        let mut gross = 0u128;
        let mut payout = 0u128;
        let mut fee = 0u128;
        for e in self.withdrawals.values().filter(|e| e.status == WithdrawalStatus::Queued) {
            gross = gross
                .checked_add(u128::from(e.request.amount))
                .ok_or(AppchainError::OutOfRange("pending withdrawal sum overflow"))?;
            payout = payout
                .checked_add(u128::from(e.payout_amount))
                .ok_or(AppchainError::OutOfRange("pending payout sum overflow"))?;
            fee = fee
                .checked_add(u128::from(e.fee))
                .ok_or(AppchainError::OutOfRange("pending fee sum overflow"))?;
        }
        debug_assert_eq!(gross, payout + fee, "per-token 浮存分解恒等式");
        Ok((gross, payout, fee))
    }
}

/// REAL 多币种托管账（TE-M2）。
///
/// 构造默认 fail-closed：提现 finality 门**开启**（生产语义）、全部
/// token 零费。逐 token 账在首次触及时惰性创建（`record_external_reserve`
/// / [`CustodyLedgerV2::confirm_deposit_v2`] / 受理提现），创建后互相
/// 完全隔离。
#[derive(Debug)]
pub struct CustodyLedgerV2 {
    /// per-token 独立分账（BTreeMap 序 = 输出确定性）。
    books: BTreeMap<AssetId, TokenCustody>,
    /// per-token 提现费配置（缺省 = 零费）。
    fees: BTreeMap<AssetId, WithdrawalFeeConfig>,
    /// 提现 finality 门槛（默认开启；关闭 = 显式 opt-out，仅限非生产）。
    withdrawal_requires_finality: bool,
    /// 可选 metrics（finality/费用/储备缺口拒绝计数）。
    metrics: Option<Arc<MetricsRegistry>>,
}

impl Default for CustodyLedgerV2 {
    /// 默认 = finality 门**开启**（fail-closed）+ 全 token 零费。
    fn default() -> Self {
        Self {
            books: BTreeMap::new(),
            fees: BTreeMap::new(),
            withdrawal_requires_finality: true,
            metrics: None,
        }
    }
}

impl CustodyLedgerV2 {
    /// 空账（提现 finality 门默认开启）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// **显式 opt-out**：关闭提现 finality 门。仅限测试/开发环境（与
    /// v1 [`CustodyLedger::without_finality_gate`] 同纪律，非生产配置）。
    #[must_use]
    pub fn without_finality_gate(mut self) -> Self {
        self.withdrawal_requires_finality = false;
        self
    }

    /// 注入 metrics（finality / 费用 / 储备缺口拒绝计数）。
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 设置某 token 的提现费配置（builder 风格；缺省零费——与 v1 默认
    /// 语义一致）。flat fee 以**该 token 计价**（外部 gas 成本结构不同，
    /// plan §2.2）。
    #[must_use]
    pub fn with_token_fee(mut self, asset: AssetId, fee: WithdrawalFeeConfig) -> Self {
        self.fees.insert(asset, fee);
        self
    }

    /// 某 token 的当前提现费配置（未配置 → 零费）。
    #[must_use]
    pub fn withdrawal_fee_of(&self, asset: AssetId) -> WithdrawalFeeConfig {
        self.fees.get(&asset).copied().unwrap_or_default()
    }

    /// 提现 finality 门是否开启。
    #[must_use]
    pub fn finality_required(&self) -> bool {
        self.withdrawal_requires_finality
    }

    /// 本托管已开账的 token 集（升序）。
    #[must_use]
    pub fn tokens(&self) -> Vec<AssetId> {
        self.books.keys().copied().collect()
    }

    /// REAL 域封闭枚举门（fail-closed 防线 0）：GAME 域任何 token 拒入
    /// 本托管（GAME 赎回属 TE-M3+ 独立通道）；REAL 域未注册 token 同拒
    /// （伪造载荷不因绕过构造器而被接受）。
    fn ensure_real_domain(asset: AssetId) -> AppchainResult<()> {
        if !asset.is_real_domain() || !asset.domain.is_registered_token(asset.token_id) {
            return Err(AppchainError::OutOfRange("custody accepts REAL domain registered tokens only"));
        }
        Ok(())
    }

    /// 惰性取账（不存在则建空账）。
    fn book_mut(&mut self, asset: AssetId) -> &mut TokenCustody {
        self.books.entry(asset).or_default()
    }

    /// 外部储备录入（**per-token**；watcher 按币种读链上余额后分别注入
    /// ——plan §2.2 `reserved[code]`）。
    ///
    /// # Errors
    /// GAME 域 / 未注册 token → [`AppchainError::OutOfRange`]。
    pub fn record_external_reserve(&mut self, asset: AssetId, reserved: u128) -> AppchainResult<()> {
        Self::ensure_real_domain(asset)?;
        self.book_mut(asset).reserved = reserved;
        Ok(())
    }

    /// 某 token 的储备快照（未开账 → 0）。
    #[must_use]
    pub fn reserved_of(&self, asset: AssetId) -> u128 {
        self.books.get(&asset).map_or(0, |b| b.reserved)
    }

    /// 入金确认（**per-token** 幂等；plan §2.2 `deposits[code]`）。
    ///
    /// 语义沿 v1 [`CustodyLedger::confirm_deposit`]：同 deposit_id 同载荷
    /// 重复确认返回 Ok（watcher 重试安全）；异载荷冲突；一张 note 承诺
    /// 只能绑定一次入金（per-token 查重）。
    ///
    /// # Errors
    /// GAME 域 / 未注册 token → [`AppchainError::OutOfRange`]；
    /// 同 id 异载荷 / note 重复绑定 → [`AppchainError::WithdrawalConflict`]。
    pub fn confirm_deposit_v2(
        &mut self,
        deposit_id: [u8; 32],
        asset: AssetId,
        note_commitment: [u8; 32],
        amount: u64,
    ) -> AppchainResult<()> {
        Self::ensure_real_domain(asset)?;
        let book = self.book_mut(asset);
        match book.deposits.get(&deposit_id) {
            Some(prev) if *prev == amount => return Ok(()),
            Some(_) => {
                return Err(AppchainError::WithdrawalConflict(
                    "deposit id payload mismatch".into(),
                ))
            }
            None => {}
        }
        if !book.known_note_ids.insert(note_commitment) {
            return Err(AppchainError::WithdrawalConflict(
                "note already bound to a deposit".into(),
            ));
        }
        book.deposits.insert(deposit_id, amount);
        Ok(())
    }

    /// 提现入队（**per-token** 独立通道；注入时钟版本——`now_ms` 为受理
    /// 时刻，生产取 `WithdrawRequestV2Op.created_at_ms`（帧链确定值），
    /// SLA 计时起点）。
    ///
    /// 受理闸门（顺序即实现，全 fail-closed）：
    /// 1. REAL 域封闭枚举门——GAME 域 / 未注册 token 拒（`OutOfRange`）；
    /// 2. 幂等先行——同 token 内同 request_id 同载荷直接返回既有条目
    ///    （不复审任何闸门；异载荷冲突）；
    /// 3. **finality 门按 domain**（TE-M1 冻结决策）：REAL 域任何 token
    ///    要求 proven 水位覆盖来源 op **且** 批次根覆盖（双门）——未满足
    ///    → [`AppchainError::WithdrawalNotFinalized`] 并计
    ///    `withdrawal_finality_rejected_total`；
    /// 4. **储备覆盖核验（禁止跨币轧差的强制点，INV-TE-2）**：本 token
    ///    储备必须覆盖本 token 已发行总额 `issued_token`（调用方从
    ///    sequencer 导出：live + 已销毁毛额；[plan §2.2]
    ///    `delta[code] = reserved[code] − issued[code]`）——不足 →
    ///    [`AppchainError::ReconciliationMismatch`] 并计
    ///    `withdrawal_reserve_short_rejected_total`。**判定只用本 token
    ///    的储备与发行**，其它 token 的富余在本函数内不可见（结构上
    ///    无法轧差）；
    /// 5. 提现费 per-token：`fee = fee_of(asset).flat_fee`，`fee > gross`
    ///    → [`AppchainError::OutOfRange`] 并计
    ///    `withdrawal_fee_rejected_total`（不存在净额 ≤ 0 的意外打款；
    ///    fee == gross 边界受理 = 全额抵费）。
    ///
    /// # Errors
    /// 见各闸门；同 id 异载荷 → [`AppchainError::WithdrawalConflict`]。
    pub fn enqueue_withdrawal_v2(
        &mut self,
        request: WithdrawalRequestV2,
        issued_token: u128,
        provenance: WithdrawalProvenanceV2,
        finality: crate::real_policy::FinalityEvidence,
        now_ms: u64,
    ) -> AppchainResult<&WithdrawalEntry> {
        // 1. REAL 域封闭枚举门（GAME 域拒入本托管）
        Self::ensure_real_domain(request.asset_id)?;
        let asset = request.asset_id;
        // 2. 幂等先行（per-token 查重；已受理条目不受后续闸门复审影响）
        enum Idempotent {
            Hit,
            Conflict,
            Miss,
        }
        let verdict = {
            match self
                .books
                .get(&asset)
                .and_then(|b| b.withdrawals.get(&request.request_id))
            {
                Some(e) if e.request.payout_address == request.external_recipient
                    && e.request.amount == request.gross_amount =>
                {
                    Idempotent::Hit
                }
                Some(_) => Idempotent::Conflict,
                None => Idempotent::Miss,
            }
        };
        match verdict {
            Idempotent::Conflict => {
                return Err(AppchainError::WithdrawalConflict(
                    "withdrawal id payload mismatch".into(),
                ))
            }
            Idempotent::Hit => {
                let book = self.books.get(&asset).expect("hit implies book exists");
                return Ok(book
                    .withdrawals
                    .get(&request.request_id)
                    .expect("hit implies entry"));
            }
            Idempotent::Miss => {}
        }
        // 3. finality 门按 domain（REAL 域任何 token 双门；此处必为 REAL
        //    域——第 1 步已拒 GAME——门条件即恒真，保留 domain 判据以钉
        //    TE-M1 冻结决策）
        if self.withdrawal_requires_finality
            && provenance.asset_id.is_real_domain()
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
        // 4. 储备覆盖核验（per-token；USDT 短库不能用 NATIVE 长库抵——
        //    判定只用本 token 储备，其它 token 富余在本函数不可见）
        if self.reserved_of(asset) < issued_token {
            if let Some(m) = &self.metrics {
                m.inc("withdrawal_reserve_short_rejected_total");
            }
            return Err(AppchainError::ReconciliationMismatch {
                issued: issued_token,
                reserved: self.reserved_of(asset),
            });
        }
        // 5. 提现费 per-token（从余额内扣；fail-closed 负例）
        let fee = self.withdrawal_fee_of(asset).flat_fee;
        if fee > request.gross_amount {
            if let Some(m) = &self.metrics {
                m.inc("withdrawal_fee_rejected_total");
            }
            return Err(AppchainError::OutOfRange("withdrawal fee exceeds amount"));
        }
        // ===== 变更段（以上全部通过；以下只入账，不再失败）=====
        let id = request.request_id;
        let gross = request.gross_amount;
        let book = self.book_mut(asset);
        book.withdrawals.insert(
            id,
            WithdrawalEntry {
                request: WithdrawalRequest {
                    request_id: id,
                    payout_address: request.external_recipient,
                    amount: gross,
                },
                payout_amount: gross - fee,
                fee,
                status: WithdrawalStatus::Queued,
                tx_hash: None,
                requested_at_ms: now_ms,
                sla_breach_counted: false,
            },
        );
        Ok(book.withdrawals.get(&id).expect("just inserted"))
    }

    /// 打款完成（**per-token** 通道）。
    ///
    /// # Errors
    /// 未知请求或已支付 → [`AppchainError::WithdrawalConflict`]。
    pub fn mark_paid(
        &mut self,
        asset: AssetId,
        request_id: [u8; 32],
        tx_hash: [u8; 32],
    ) -> AppchainResult<()> {
        let e = self
            .books
            .get_mut(&asset)
            .and_then(|b| b.withdrawals.get_mut(&request_id))
            .ok_or_else(|| AppchainError::WithdrawalConflict("unknown request".into()))?;
        if e.status == WithdrawalStatus::Paid {
            return Err(AppchainError::WithdrawalConflict("already paid".into()));
        }
        e.status = WithdrawalStatus::Paid;
        e.tx_hash = Some(tx_hash);
        Ok(())
    }

    /// 某 token 的打款净额查询（未知 → `None`）。
    #[must_use]
    pub fn payout_amount_of(&self, asset: AssetId, request_id: &[u8; 32]) -> Option<u64> {
        self.books
            .get(&asset)
            .and_then(|b| b.withdrawals.get(request_id))
            .map(|e| e.payout_amount)
    }

    /// 某 token 排队提现数。
    #[must_use]
    pub fn queued_withdrawals_of(&self, asset: AssetId) -> usize {
        self.books
            .get(&asset)
            .map_or(0, |b| b.withdrawals.values().filter(|e| e.status == WithdrawalStatus::Queued).count())
    }

    /// 全 token 排队提现打款任务快照（**按 token 分道**；plan §2.3 打款
    /// 执行器按币种分通道执行——原生转账 / ERC20 transfer，`mark_paid`
    /// 语义不变）。BTreeMap 序确定。
    #[must_use]
    pub fn queued_payouts_by_token(&self) -> BTreeMap<AssetId, Vec<(WithdrawalRequest, u64)>> {
        let mut out = BTreeMap::new();
        for (asset, book) in &self.books {
            let tasks: Vec<(WithdrawalRequest, u64)> = book
                .withdrawals
                .values()
                .filter(|e| e.status == WithdrawalStatus::Queued)
                .map(|e| (e.request.clone(), e.payout_amount))
                .collect();
            if !tasks.is_empty() {
                out.insert(*asset, tasks);
            }
        }
        out
    }

    /// 全 token 托管摘要（`total_by_token`；**只有 per-token 视图，无
    /// 跨 token 合计**——INV-TE-2）。每行满足浮存分解恒等式
    /// `queued_withdrawal_total == queued_payout_total + queued_fee_float`
    /// （构造处 debug_assert + 测试钉死）。
    #[must_use]
    pub fn total_by_token(&self) -> BTreeMap<AssetId, TokenCustodySummary> {
        self.books
            .iter()
            .map(|(asset, book)| {
                let (gross, payout, fee) = book
                    .pending_breakdown()
                    .expect("breakdown overflow is a programming error (u128 sums)");
                let queued_count = book
                    .withdrawals
                    .values()
                    .filter(|e| e.status == WithdrawalStatus::Queued)
                    .count() as u64;
                (*asset, TokenCustodySummary {
                    reserved: book.reserved,
                    queued_withdrawal_total: gross,
                    queued_payout_total: payout,
                    queued_fee_float: fee,
                    queued_count,
                })
            })
            .collect()
    }

    /// 日终对账（**per-token**；plan §2.2 对账恒等式的 v2 形态）。
    ///
    /// `issued_by_token`：调用方从 sequencer 导出的各 REAL token 已发行
    /// 总额（live + 已销毁毛额，`Sequencer::issued_v2_real_by_token`）。
    /// 只对给出的 token 出报告；**任何** token `delta != 0` 即整体
    /// [`AppchainError::ReconciliationMismatch`]（不允许跨币轧差——
    /// USDT 短库不能用 NATIVE 长库抵）。
    ///
    /// # Errors
    /// issued 给出未开账 token（托管无该 token 账本 = 未跟踪托管）→
    /// [`AppchainError::OutOfRange`]；数值溢出 → [`AppchainError::OutOfRange`]。
    pub fn reconciliation_by_token(
        &self,
        issued_by_token: &BTreeMap<AssetId, u128>,
    ) -> AppchainResult<BTreeMap<AssetId, ReconciliationReport>> {
        let mut out = BTreeMap::new();
        for (asset, issued) in issued_by_token {
            let book = self.books.get(asset).ok_or(AppchainError::OutOfRange(
                "issued token has no custody book (untracked custody)",
            ))?;
            let (pending, pending_payout, pending_fee) = book.pending_breakdown()?;
            let delta = i128::try_from(book.reserved)
                .ok()
                .and_then(|r| r.checked_sub(i128::try_from(*issued).ok()?))
                .ok_or(AppchainError::ReconciliationMismatch {
                    issued: *issued,
                    reserved: book.reserved,
                })?;
            out.insert(*asset, ReconciliationReport {
                issued_real_total: *issued,
                reserved: book.reserved,
                pending_withdrawal_total: pending,
                pending_payout_total: pending_payout,
                pending_fee_float: pending_fee,
                delta,
            });
        }
        Ok(out)
    }

    /// 对账或报错（**每个** token `delta` 都必须为 0，否则
    /// [`AppchainError::ReconciliationMismatch`]——逐 token 判定，无轧差；
    /// 错误载荷即首个失衡 token 的 (issued, reserved)）。
    ///
    /// # Errors
    /// 任一 token 差异非零 / 未开账 / 溢出。
    pub fn require_balanced_by_token(
        &self,
        issued_by_token: &BTreeMap<AssetId, u128>,
    ) -> AppchainResult<BTreeMap<AssetId, ReconciliationReport>> {
        let reports = self.reconciliation_by_token(issued_by_token)?;
        for r in reports.values() {
            if r.delta != 0 {
                return Err(AppchainError::ReconciliationMismatch {
                    issued: r.issued_real_total,
                    reserved: r.reserved,
                });
            }
        }
        Ok(reports)
    }

    /// 排队提现 → v2 leaf 投影快照（**per-token，含资产维度**；
    /// [`WithdrawalLeaf`] 的 `asset_class` 字节经
    /// [`crate::withdrawal_root::leaf_asset_tag_of`] 表达 token 判别）。
    ///
    /// 返回**全部** token 的排队条目，按 (asset_id, request_id) 字典序
    /// （BTreeMap 迭代序，聚合确定性）；每条均在受理时过了 finality 门
    /// 与储备核验。v2 队列同样不逐条记录 checkpoint 归属——与 v1
    /// [`CustodyLedger::pending_withdrawal_leaves`] 同纪律（无高度参数；
    /// 必须由调用方保证仅已 finalize 的窗口入根）。打款净额语义不变。
    #[must_use]
    pub fn pending_withdrawals_v2(&self) -> Vec<PendingWithdrawalV2> {
        let mut out: Vec<PendingWithdrawalV2> = self
            .books
            .iter()
            .flat_map(|(asset, book)| {
                book.withdrawals
                    .values()
                    .filter(|e| e.status == WithdrawalStatus::Queued)
                    .map(move |e| PendingWithdrawalV2 {
                        request_id: e.request.request_id,
                        asset_id: *asset,
                        external_recipient: e.request.payout_address,
                        payout_amount: e.payout_amount,
                    })
            })
            .collect();
        out.sort_by_key(|p| (p.asset_id, p.request_id));
        out
    }

    /// 提现 SLA 报告（**per-token** 独立通道；M7-ACC-2 语义按 token 复制，
    /// 越限计数不重复——条目内一次性标记）。
    pub fn sla_report_of(&mut self, asset: AssetId, now_ms: u64, threshold_ms: u64) -> WithdrawalSlaReport {
        let mut waits: Vec<u64> = Vec::new();
        let mut breached = 0u64;
        let Some(book) = self.books.get_mut(&asset) else {
            return WithdrawalSlaReport { pending: 0, breached_count: 0, p95_wait_ms: None };
        };
        for e in book
            .withdrawals
            .values_mut()
            .filter(|e| e.status == WithdrawalStatus::Queued)
        {
            let wait = now_ms.saturating_sub(e.requested_at_ms);
            waits.push(wait);
            if wait > threshold_ms {
                breached += 1;
                if !e.sla_breach_counted {
                    e.sla_breach_counted = true;
                    if let Some(m) = &self.metrics {
                        m.inc("withdrawal_sla_breach_total");
                    }
                }
            }
        }
        waits.sort_unstable();
        let p95_wait_ms = if waits.is_empty() {
            None
        } else {
            let idx = (((waits.len() as f64) - 1.0) * 0.95).round() as usize;
            Some(waits[idx.min(waits.len() - 1)])
        };
        WithdrawalSlaReport {
            pending: waits.len() as u64,
            breached_count: breached,
            p95_wait_ms,
        }
    }
}

/// TE-M2 排队提现的 v2 leaf 投影（含资产维度；vault 队列侧可证字段）。
///
/// `payout_amount` 语义为**打款净额**（M7 内扣后的对外应付数）；
/// [`PendingWithdrawalV2::into_leaf`] 经
/// [`crate::withdrawal_root::leaf_asset_tag_of`] 把资产身份折叠为
/// [`WithdrawalLeaf::asset_class`] 字节判别（TE-M2 语义扩展，编码冻结）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingWithdrawalV2 {
    /// 提现请求幂等键（→ [`WithdrawalLeaf::request_id`]）。
    pub request_id: [u8; 32],
    /// 提现资产（→ leaf 资产标签判别）。
    pub asset_id: AssetId,
    /// 外部收款地址（→ [`WithdrawalLeaf::external_recipient`]）。
    pub external_recipient: [u8; 32],
    /// 打款净额（→ [`WithdrawalLeaf::amount`]）。
    pub payout_amount: u64,
}

impl PendingWithdrawalV2 {
    /// 补齐队列外字段 → 完整 [`WithdrawalLeaf`]。
    ///
    /// # Errors
    /// 资产在 leaf 编码中无表示（GAME 域注册表 token，TE-M3 前不得出根）
    /// → [`AppchainError::OutOfRange`]（fail-closed）。
    pub fn into_leaf(
        self,
        burned_note_commitment: [u8; 32],
        checkpoint_height: u64,
    ) -> AppchainResult<WithdrawalLeaf> {
        let tag = crate::withdrawal_root::leaf_asset_tag_of(self.asset_id)
            .ok_or(AppchainError::OutOfRange("asset has no withdrawal leaf tag"))?;
        Ok(WithdrawalLeaf {
            request_id: self.request_id,
            external_recipient: self.external_recipient,
            asset_class: tag,
            amount: self.payout_amount,
            burned_note_commitment,
            checkpoint_height,
        })
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

    // ===== M7 提现费（WithdrawalFeeConfig）=====

    /// 定价生效：fee 从余额内扣，打款净额 = amount − fee；浮存侧分解
    /// （排队总额 = 净额 + 费用浮存）成立；对账恒等式 `delta = reserved −
    /// issued` 与零费时完全一致。
    #[test]
    fn withdrawal_fee_pricing_and_identity() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mut v = CustodyLedger::new()
            .with_withdrawal_fee(WithdrawalFeeConfig { flat_fee: 25 })
            .with_metrics(Arc::clone(&metrics));
        assert_eq!(v.withdrawal_fee().flat_fee, 25);

        let e = v
            .enqueue_withdrawal_at(request(1, 2, 100), play_prov(), FinalityEvidence::default(), 1_000)
            .unwrap();
        assert_eq!(e.fee, 25);
        assert_eq!(e.payout_amount, 75);
        assert_eq!(e.requested_at_ms, 1_000);
        assert_eq!(v.payout_amount_of(&[1; 32]), Some(75));

        // 第二笔（不同 id）
        v.enqueue_withdrawal_at(
            WithdrawalRequest { request_id: [2; 32], payout_address: [3; 32], amount: 50 },
            play_prov(),
            FinalityEvidence::default(),
            2_000,
        )
        .unwrap();

        // 浮存侧分解：pending 150 = payout 100 + fee 50
        let r = v.reconciliation(0).unwrap();
        assert_eq!(r.pending_withdrawal_total, 150);
        assert_eq!(r.pending_payout_total, 100);
        assert_eq!(r.pending_fee_float, 50);
        assert_eq!(r.pending_withdrawal_total, r.pending_payout_total + r.pending_fee_float);

        // 恒等式不变：fee 从余额内扣 → reserved == issued 仍为平
        v.record_external_reserve(1_000);
        let r = v.require_balanced(1_000).unwrap();
        assert_eq!(r.delta, 0);
        // 打款后：费用浮存随条目退出排队（pending 只剩未打款项）
        v.mark_paid([1; 32], [9; 32]).unwrap();
        let r = v.reconciliation(1_000).unwrap();
        assert_eq!(r.delta, 0, "打款不影响恒等式（费从余额内扣）");
        assert_eq!(r.pending_withdrawal_total, 50);
        assert_eq!(r.pending_payout_total, 25);
        assert_eq!(r.pending_fee_float, 25);

        // 打款任务快照带净额
        let tasks = v.queued_payouts();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].1, 25);
    }

    /// 0 免费回归：默认配置（不配置）下 fee == 0、净额 == 金额，
    /// 报告形状与既有语义一致。
    #[test]
    fn withdrawal_fee_zero_default_regression() {
        let mut v = CustodyLedger::new();
        assert_eq!(v.withdrawal_fee(), WithdrawalFeeConfig::default());
        let e = v
            .enqueue_withdrawal_at(request(1, 2, 70), play_prov(), FinalityEvidence::default(), 5)
            .unwrap();
        assert_eq!(e.fee, 0);
        assert_eq!(e.payout_amount, 70);
        let r = v.reconciliation(0).unwrap();
        assert_eq!(r.pending_withdrawal_total, 70);
        assert_eq!(r.pending_payout_total, 70);
        assert_eq!(r.pending_fee_float, 0);
    }

    /// 负例：费用 > 余额 → 拒绝（OutOfRange），条目不入账、计数 +1；
    /// 费用 == 金额的边界仍受理（净额 0 = 全额抵费，托管侧允许）。
    #[test]
    fn withdrawal_fee_exceeding_amount_rejected() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mut v = CustodyLedger::new()
            .with_withdrawal_fee(WithdrawalFeeConfig { flat_fee: 100 })
            .with_metrics(Arc::clone(&metrics));
        let err = v
            .enqueue_withdrawal_at(request(1, 2, 99), play_prov(), FinalityEvidence::default(), 1)
            .unwrap_err();
        assert!(matches!(err, AppchainError::OutOfRange("withdrawal fee exceeds amount")));
        assert_eq!(metrics.counter("withdrawal_fee_rejected_total"), 1);
        assert_eq!(v.queued_withdrawals(), 0, "拒绝的请求不入账");
        assert_eq!(v.payout_amount_of(&[1; 32]), None);

        // 边界：fee == amount → 净额 0，受理（金额内扣尽）
        let e = v
            .enqueue_withdrawal_at(request(3, 4, 100), play_prov(), FinalityEvidence::default(), 2)
            .unwrap();
        assert_eq!(e.fee, 100);
        assert_eq!(e.payout_amount, 0);
        assert_eq!(metrics.counter("withdrawal_fee_rejected_total"), 1);
    }

    /// 幂等命中保持受理时费配置（重放同 id 同载荷不重算费用/时刻）。
    #[test]
    fn withdrawal_fee_idempotent_hit_keeps_entry() {
        let mut v = CustodyLedger::new().with_withdrawal_fee(WithdrawalFeeConfig { flat_fee: 10 });
        let first = v
            .enqueue_withdrawal_at(request(1, 2, 60), play_prov(), FinalityEvidence::default(), 100)
            .unwrap()
            .clone();
        let again = v
            .enqueue_withdrawal_at(request(1, 2, 60), play_prov(), FinalityEvidence::default(), 9_999)
            .unwrap()
            .clone();
        assert_eq!(first.requested_at_ms, again.requested_at_ms);
        assert_eq!(again.fee, 10);
        assert_eq!(again.payout_amount, 50);
        assert_eq!(v.queued_withdrawals(), 1);
    }

    // ===== M7-ACC-2 / M9 提现 SLA 计时器 =====

    /// 注入时钟构造越阈值请求：breach 计数与报告逐一断言；重复拉取不重复
    /// 计数；p95 为等待时长的 95 分位。
    #[test]
    fn sla_report_breach_injected_clock() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mut v = CustodyLedger::new().with_metrics(Arc::clone(&metrics));

        // 请求 A：t=1_000 受理；请求 B：t=4_000 受理
        v.enqueue_withdrawal_at(request(1, 2, 10), play_prov(), FinalityEvidence::default(), 1_000)
            .unwrap();
        v.enqueue_withdrawal_at(request(3, 4, 10), play_prov(), FinalityEvidence::default(), 4_000)
            .unwrap();

        // t=2_500：A 等待 1_500（阈值 2_000 未越限）、B 等待 0（未受理后…实际
        // B 已受理，等待为 0）→ 无越限
        let r = v.sla_report(2_500, 2_000);
        assert_eq!(r.pending, 2);
        assert_eq!(r.breached_count, 0);
        assert_eq!(metrics.counter("withdrawal_sla_breach_total"), 0);
        assert_eq!(r.p95_wait_ms, Some(1_500));

        // t=3_100：A 等待 2_100 > 2_000 → A 越限一次
        let r = v.sla_report(3_100, 2_000);
        assert_eq!(r.breached_count, 1);
        assert_eq!(metrics.counter("withdrawal_sla_breach_total"), 1);

        // 重复拉取：A 已计数不重复（计数仍 1），B 到 t=6_100 也越限（第 2 次）
        let r = v.sla_report(3_200, 2_000);
        assert_eq!(r.breached_count, 1);
        assert_eq!(metrics.counter("withdrawal_sla_breach_total"), 1, "同一请求不重复计数");
        let r = v.sla_report(6_100, 2_000);
        assert_eq!(r.breached_count, 2);
        assert_eq!(metrics.counter("withdrawal_sla_breach_total"), 2);
        // p95：等待 {5_100(A), 2_100(B)} → 升序 [2100, 5100]，p95=idx1=5100
        assert_eq!(r.p95_wait_ms, Some(5_100));

        // 打款后退出 SLA 口径
        v.mark_paid([1; 32], [7; 32]).unwrap();
        let r = v.sla_report(9_999, 2_000);
        assert_eq!(r.pending, 1);
        assert_eq!(r.breached_count, 1, "只有 B 仍在排队");
    }

    /// 空队列 SLA 报告：pending 0、越限 0、p95 = null。
    #[test]
    fn sla_report_empty_queue_null_p95() {
        let mut v = CustodyLedger::new();
        let r = v.sla_report(1_000, 1_000);
        assert_eq!(r, WithdrawalSlaReport { pending: 0, breached_count: 0, p95_wait_ms: None });
    }
}

#[cfg(test)]
mod te_m2_tests {
    use super::*;

    /// 提现 provenance（USDT，来源 op = 5）。
    fn usdt_prov() -> WithdrawalProvenanceV2 {
        WithdrawalProvenanceV2 {
            asset_id: AssetId::REAL_USDT,
            source_op_index: 5,
        }
    }

    fn v2_request(id_byte: u8, asset: AssetId, recipient: u8, gross: u64) -> WithdrawalRequestV2 {
        WithdrawalRequestV2 {
            request_id: [id_byte; 32],
            asset_id: asset,
            external_recipient: [recipient; 32],
            gross_amount: gross,
        }
    }

    fn finality_ok() -> crate::real_policy::FinalityEvidence {
        crate::real_policy::FinalityEvidence {
            proven_watermark: 9,
            batch_covered_through: Some(7),
        }
    }

    /// 托管只收 REAL 域已注册 token（GAME 域 / 伪造 token 双向 fail-closed）。
    #[test]
    fn custody_accepts_real_domain_registered_tokens_only() {
        let mut v = CustodyLedgerV2::new();
        // GAME 域拒入（储备录入 / 入金 / 提现三口全拒）
        assert!(v.record_external_reserve(AssetId::GAME_PLAY, 100).is_err());
        assert!(v
            .confirm_deposit_v2([1; 32], AssetId::GAME_PLAY, [2; 32], 50)
            .is_err());
        let err = v
            .enqueue_withdrawal_v2(
                v2_request(1, AssetId::GAME_PLAY, 3, 50),
                0,
                WithdrawalProvenanceV2 { asset_id: AssetId::GAME_PLAY, source_op_index: 1 },
                crate::real_policy::FinalityEvidence::default(),
                1,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::OutOfRange(_)));
        // 伪造 REAL token（绕过 AssetId::real 构造器的载荷）同拒
        let forged = AssetId { domain: crate::asset_id::AssetDomain::Real, token_id: 999 };
        assert!(v.record_external_reserve(forged, 100).is_err());
        assert!(v.tokens().is_empty(), "拒绝路径不得开账");
    }

    /// per-token 入金幂等 + note 绑定隔离（同 deposit_id 异载荷冲突）。
    #[test]
    fn deposit_v2_idempotent_and_note_binding() {
        let mut v = CustodyLedgerV2::new();
        v.confirm_deposit_v2([1; 32], AssetId::REAL_USDT, [2; 32], 100).unwrap();
        // 同 id 同载荷幂等 Ok
        v.confirm_deposit_v2([1; 32], AssetId::REAL_USDT, [2; 32], 100).unwrap();
        // 同 id 异金额 → 冲突
        assert!(v.confirm_deposit_v2([1; 32], AssetId::REAL_USDT, [2; 32], 101).is_err());
        // note 承诺已被 USDT 账绑定：换 deposit_id 仍拒（per-token 绑定）
        assert!(v.confirm_deposit_v2([9; 32], AssetId::REAL_USDT, [2; 32], 1).is_err());
        // NATIVE 账独立：同 deposit_id / 同 note 承诺在别的 token 账互不可见
        v.confirm_deposit_v2([1; 32], AssetId::REAL_NATIVE, [3; 32], 70).unwrap();
        assert_eq!(v.tokens(), vec![AssetId::REAL_NATIVE, AssetId::REAL_USDT]);
    }

    /// 储备覆盖核验 per-token：USDT 短库拒、NATIVE 长库放行（同账本同调用）。
    #[test]
    fn reserve_coverage_is_per_token_no_netting() {
        let metrics = Arc::new(MetricsRegistry::new());
        let mut v = CustodyLedgerV2::new()
            .without_finality_gate()
            .with_metrics(Arc::clone(&metrics));
        v.record_external_reserve(AssetId::REAL_NATIVE, 1_000).unwrap();
        v.record_external_reserve(AssetId::REAL_USDT, 50).unwrap();
        // USDT：发行 100 > 储备 50 → 拒（ReconciliationMismatch）
        let err = v
            .enqueue_withdrawal_v2(
                v2_request(1, AssetId::REAL_USDT, 2, 100),
                100,
                usdt_prov(),
                finality_ok(),
                1,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::ReconciliationMismatch { issued: 100, reserved: 50 }));
        assert_eq!(v.queued_withdrawals_of(AssetId::REAL_USDT), 0);
        // NATIVE：储备覆盖 → 放行（同一时刻、同一托管账）
        v.enqueue_withdrawal_v2(
            v2_request(2, AssetId::REAL_NATIVE, 3, 100),
            100,
            WithdrawalProvenanceV2 { asset_id: AssetId::REAL_NATIVE, source_op_index: 5 },
            finality_ok(),
            1,
        )
        .unwrap();
        assert_eq!(v.queued_withdrawals_of(AssetId::REAL_NATIVE), 1);
        assert_eq!(
            metrics.counter("withdrawal_reserve_short_rejected_total"),
            1,
            "储备缺口拒绝计数（USDT）"
        );
    }

    /// per-token 浮存分解恒等式 + per-token 对账（total_by_token 无跨 token 合计）。
    #[test]
    fn per_token_identity_and_reconciliation() {
        let mut v = CustodyLedgerV2::new().without_finality_gate()
            .with_token_fee(AssetId::REAL_USDC, WithdrawalFeeConfig { flat_fee: 7 });
        v.record_external_reserve(AssetId::REAL_NATIVE, 1_000).unwrap();
        v.record_external_reserve(AssetId::REAL_USDC, 500).unwrap();
        v.enqueue_withdrawal_v2(
            v2_request(1, AssetId::REAL_NATIVE, 2, 100),
            1_000,
            WithdrawalProvenanceV2 { asset_id: AssetId::REAL_NATIVE, source_op_index: 5 },
            finality_ok(),
            10,
        )
        .unwrap();
        v.enqueue_withdrawal_v2(
            v2_request(3, AssetId::REAL_USDC, 4, 93),
            500,
            WithdrawalProvenanceV2 { asset_id: AssetId::REAL_USDC, source_op_index: 5 },
            finality_ok(),
            10,
        )
        .unwrap();

        let totals = v.total_by_token();
        assert_eq!(totals.len(), 2);
        for (asset, s) in &totals {
            assert_eq!(
                s.queued_withdrawal_total,
                s.queued_payout_total + s.queued_fee_float,
                "token {asset} 浮存分解恒等式"
            );
        }
        assert_eq!(totals[&AssetId::REAL_NATIVE].queued_fee_float, 0);
        assert_eq!(totals[&AssetId::REAL_USDC].queued_fee_float, 7);
        assert_eq!(totals[&AssetId::REAL_USDC].queued_payout_total, 86);

        // per-token 对账：逐 token delta == 0
        let mut issued = BTreeMap::new();
        issued.insert(AssetId::REAL_NATIVE, 1_000u128);
        issued.insert(AssetId::REAL_USDC, 500u128);
        let reports = v.require_balanced_by_token(&issued).unwrap();
        assert!(reports.values().all(|r| r.delta == 0));
        // 任一 token 短库 → 整体拒（即便另一 token 完全平衡）
        issued.insert(AssetId::REAL_USDC, 499);
        assert!(v.require_balanced_by_token(&issued).is_err());
    }

    /// per-token SLA：通道独立，A token 越限不影响 B token 报告。
    #[test]
    fn sla_report_per_token() {
        let mut v = CustodyLedgerV2::new().without_finality_gate();
        v.record_external_reserve(AssetId::REAL_USDT, 100).unwrap();
        v.enqueue_withdrawal_v2(
            v2_request(1, AssetId::REAL_USDT, 2, 10),
            100,
            usdt_prov(),
            finality_ok(),
            1_000,
        )
        .unwrap();
        let r = v.sla_report_of(AssetId::REAL_USDT, 3_000, 1_000);
        assert_eq!(r.pending, 1);
        assert_eq!(r.breached_count, 1);
        // 未开账 token → 空报告
        let r = v.sla_report_of(AssetId::REAL_NATIVE, 9_999, 1);
        assert_eq!(r, WithdrawalSlaReport { pending: 0, breached_count: 0, p95_wait_ms: None });
    }

    /// 打款闭环：按 token mark_paid → 任务退出该 token 通道。
    #[test]
    fn per_token_mark_paid_channel() {
        let mut v = CustodyLedgerV2::new().without_finality_gate();
        v.record_external_reserve(AssetId::REAL_USDT, 100).unwrap();
        v.enqueue_withdrawal_v2(
            v2_request(1, AssetId::REAL_USDT, 2, 60),
            100,
            usdt_prov(),
            finality_ok(),
            1,
        )
        .unwrap();
        assert_eq!(v.payout_amount_of(AssetId::REAL_USDT, &[1; 32]), Some(60));
        assert_eq!(v.payout_amount_of(AssetId::REAL_NATIVE, &[1; 32]), None, "跨 token 查询不可见");
        v.mark_paid(AssetId::REAL_USDT, [1; 32], [9; 32]).unwrap();
        assert!(v.mark_paid(AssetId::REAL_USDT, [1; 32], [8; 32]).is_err());
        assert_eq!(v.queued_withdrawals_of(AssetId::REAL_USDT), 0);
        assert!(v.queued_payouts_by_token().is_empty());
    }
}
