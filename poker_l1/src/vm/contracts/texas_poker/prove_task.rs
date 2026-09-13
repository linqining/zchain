//! L1 证明任务 — dispatch 层产出，Orchestrator（poker_texas_air）消费。
//!
//! ## 角色
//!
//! `dispatch` 主函数执行成功后，构造 [`L1ProveTask`]（含 pre/post table 快照 +
//! method 元数据），与 events 一起封装进 [`L1DispatchOutput`]，borsh 序列化
//! 为 `DispatchResult.return_value`。
//!
//! 链下 Orchestrator 从链层取回 return_value，反序列化为
//! `poker_texas_air::prove_task::DispatchOutput`（两者 borsh 二进制兼容），
//! 据此生成 method proof。
//!
//! ## borsh 兼容性
//!
//! 本模块的类型与 `poker_texas_air::prove_task` 的对应类型字段对齐：
//! - `TexasPokerTable` / `TexasPokerEvent` 都是 poker_l1 类型，两端可见同一类型
//! - `method_kind: u8` ↔ `poker_texas_air::MethodKind`（`use_discriminant=true`，
//!   单字节 borsh 布局一致）
//! - `method_kind + canonical_args` 是唯一持久化命令表示；selector 与 typed input
//!   均由该 tagged payload 确定性派生
//!
//! ## 与 poker_texas_air 的关系
//!
//! poker_l1 **不依赖** poker_texas_air（依赖方向是 air → l1）。本模块是 poker_l1
//! 侧的等价定义，通过 borsh 字节流与 Orchestrator 解耦。

use borsh::{BorshDeserialize, BorshSerialize};

// Transient decoded command view shared with the AIR crate. It is deliberately not a field of
// L1ProveTask; consumers derive it from `method_kind + canonical_args`.
pub use vm_common::prove_task::MethodInput;

use super::events::TexasPokerEvent;
use super::types::TexasPokerTable;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::vm::contracts::dispatch::DispatchContext;

/// 单次 method 调用的证明任务（L1 侧定义）。
///
/// borsh 布局与 `poker_texas_air::prove_task::ProveTask` 完全一致。
#[derive(Debug, Clone)]
pub struct L1ProveTask {
    /// 方法种类（u8 discriminant，与 poker_texas_air::MethodKind 兼容）。
    pub method_kind: u8,
    /// 执行该调用时经过交易层认证的完整 dispatch 上下文。
    pub context: DispatchContext,
    /// 规范化后的 Borsh command payload。
    ///
    /// `method_kind` 是 tag，本字段是唯一 payload。selector、typed input 和 dispatch digest
    /// 必须从二者派生，不能在 task 中保存第二份可错配表示。
    pub raw_args: Vec<u8>,
    /// 调用前表台快照。
    pub pre_table: TexasPokerTable,
    /// 调用后表台快照。
    pub post_table: TexasPokerTable,
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 方法调用序号。
    pub call_seq: u32,
}

impl L1ProveTask {
    /// 构造新的证明任务。
    #[must_use]
    pub fn new(
        method_kind: u8,
        context: DispatchContext,
        raw_args: Vec<u8>,
        pre_table: TexasPokerTable,
        post_table: TexasPokerTable,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        super::dispatch::derive_authenticated_method_input(
            method_kind,
            &raw_args,
            &context,
            &pre_table,
        )
        .expect("L1ProveTask requires a validated canonical command");
        super::dispatch::CanonicalCommand::from_u8(method_kind)
            .expect("L1ProveTask requires a known canonical command tag");
        Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        }
    }

    /// Selector deterministically derived from the canonical command tag.
    #[must_use]
    pub fn selector(&self) -> [u8; 32] {
        super::dispatch::CanonicalCommand::from_u8(self.method_kind)
            .expect("validated L1ProveTask command tag")
            .selector()
    }

    /// Decode the transient typed command view from the sole command payload.
    pub fn method_input(&self) -> crate::error::PokerL1Result<MethodInput> {
        super::dispatch::derive_authenticated_method_input(
            self.method_kind,
            &self.raw_args,
            &self.context,
            &self.pre_table,
        )
    }
}

impl BorshSerialize for L1ProveTask {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.method_kind.serialize(writer)?;
        self.context.serialize(writer)?;
        self.raw_args.serialize(writer)?;
        self.pre_table.serialize(writer)?;
        self.post_table.serialize(writer)?;
        self.table_id.serialize(writer)?;
        self.hand_id.serialize(writer)?;
        self.call_seq.serialize(writer)
    }
}

impl BorshDeserialize for L1ProveTask {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let method_kind = u8::deserialize_reader(reader)?;
        let context = DispatchContext::deserialize_reader(reader)?;
        let raw_args = Vec::<u8>::deserialize_reader(reader)?;
        let pre_table = TexasPokerTable::deserialize_reader(reader)?;
        let post_table = TexasPokerTable::deserialize_reader(reader)?;
        let table_id = u64::deserialize_reader(reader)?;
        let hand_id = u32::deserialize_reader(reader)?;
        let call_seq = u32::deserialize_reader(reader)?;
        super::dispatch::derive_authenticated_method_input(
            method_kind,
            &raw_args,
            &context,
            &pre_table,
        )
        .map_err(|error| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error.to_string())
        })?;
        super::dispatch::CanonicalCommand::from_u8(method_kind).ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                format!("unknown canonical Texas command tag {method_kind}"),
            )
        })?;
        Ok(Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        })
    }
}

/// dispatch 输出结构（return_value 的格式）。
///
/// borsh 布局与 `poker_texas_air::prove_task::DispatchOutput` 完全一致。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L1DispatchOutput {
    /// 事件日志。
    pub events: Vec<TexasPokerEvent>,
    /// 证明任务（None 表示此次 dispatch 无需证明）。
    pub prove_task: Option<L1ProveTask>,
}

/// Canonical Treasury transfer derived from one settlement in a dispatch output.
///
/// This is deliberately not serialized as a second wire fact. It is a fail-closed view of the
/// canonical settlement-plan and rake events already committed by the proof task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementTreasuryReceipt {
    /// Settled table.
    pub table_id: ObjectID,
    /// Canonical showdown plan digest, absent for an uncontested settlement.
    pub plan_digest: Option<[u8; 32]>,
    /// Pot before rake.
    pub gross_pot: u64,
    /// Treasury transfer amount.
    pub amount: u64,
    /// Pot awarded after rake.
    pub post_rake_pot: u64,
}

/// Canonical rake burn derived from one settlement in a dispatch output
/// (TE-M4: `RAKE_MODE_FIXED_RAKE_BURN` disposal view).
///
/// Burn-mode settlements deliberately produce **no** [`SettlementTreasuryReceipt`]:
/// the collected rake leaves the TableVault without any cash output (supply
/// contraction). This view is the matching fail-closed derivation of the same
/// committed events, so the precompile/economics assembly point can advance the
/// TreasuryCap burn counters from the dispatch output alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementRakeBurn {
    /// Settled table.
    pub table_id: ObjectID,
    /// Canonical showdown plan digest, absent for an uncontested settlement.
    pub plan_digest: Option<[u8; 32]>,
    /// Pot before rake.
    pub gross_pot: u64,
    /// Burned rake amount.
    pub amount: u64,
    /// Pot awarded after rake.
    pub post_rake_pot: u64,
}

/// One rake receipt resolved against its settlement anchor, with the
/// contract-side disposal verdict ([`rake_disposal`]) already applied.
struct ResolvedRake {
    table_id: ObjectID,
    plan_digest: Option<[u8; 32]>,
    gross_pot: u64,
    amount: u64,
    post_rake_pot: u64,
    disposal: super::settlement::RakeDisposal,
}

impl L1DispatchOutput {
    /// 仅含 events（无证明任务）的便捷构造。
    #[must_use]
    pub fn events_only(events: Vec<TexasPokerEvent>) -> Self {
        Self {
            events,
            prove_task: None,
        }
    }

    /// 含 events + 证明任务的构造。
    #[must_use]
    pub fn with_task(events: Vec<TexasPokerEvent>, prove_task: L1ProveTask) -> Self {
        Self {
            events,
            prove_task: Some(prove_task),
        }
    }

    /// Resolve the unique rake receipt against its settlement anchor (TE-M4).
    ///
    /// The `rake_mode` carried by `RakeCollected` decides the disposal:
    /// percentage (1) keeps the legacy Treasury-receipt semantics, burn (2)
    /// yields a [`SettlementRakeBurn`] instead, and unknown modes are rejected
    /// fail-closed ("不认识 ≠ 接受"). Every detachment/consistency check of the
    /// legacy view is preserved for all modes.
    fn resolve_rake(&self) -> PokerL1Result<Option<ResolvedRake>> {
        let mut plan = None;
        let mut uncontested_award = None;
        // (table_id, pot_before, rake_amount, pot_after, rake_mode)
        let mut rake_event: Option<(ObjectID, u64, u64, u64, u8)> = None;
        for event in &self.events {
            match event {
                TexasPokerEvent::SettlementPlanCommitted {
                    table_id,
                    plan_digest,
                    gross_pot,
                    rake,
                    total_awards,
                    ..
                } => {
                    if plan
                        .replace((*table_id, *plan_digest, *gross_pot, *rake, *total_awards))
                        .is_some()
                    {
                        return Err(PokerL1Error::Other(
                            "Texas dispatch contains multiple settlement plans".into(),
                        ));
                    }
                }
                TexasPokerEvent::RakeCollected {
                    table_id,
                    pot_before,
                    rake_amount,
                    pot_after,
                    rake_mode,
                } => {
                    if rake_event
                        .replace((*table_id, *pot_before, *rake_amount, *pot_after, *rake_mode))
                        .is_some()
                    {
                        return Err(PokerL1Error::Other(
                            "Texas dispatch contains multiple rake receipts".into(),
                        ));
                    }
                }
                TexasPokerEvent::HandEndedWithoutShowdown { table_id, pot, .. } => {
                    if uncontested_award.replace((*table_id, *pot)).is_some() {
                        return Err(PokerL1Error::Other(
                            "Texas dispatch contains multiple uncontested settlements".into(),
                        ));
                    }
                }
                _ => {}
            }
        }

        if plan.is_some() && uncontested_award.is_some() {
            return Err(PokerL1Error::Other(
                "Texas dispatch mixes showdown and uncontested settlement anchors".into(),
            ));
        }

        if let Some((table_id, award)) = uncontested_award {
            return match rake_event {
                None => Ok(None),
                Some((rake_table_id, gross_pot, rake, post_rake_pot, rake_mode)) => {
                    if rake_table_id != table_id
                        || post_rake_pot != award
                        || award.checked_add(rake) != Some(gross_pot)
                    {
                        return Err(PokerL1Error::Other(
                            "Texas rake receipt does not match its uncontested settlement".into(),
                        ));
                    }
                    Ok(Some(ResolvedRake {
                        table_id,
                        plan_digest: None,
                        gross_pot,
                        amount: rake,
                        post_rake_pot,
                        disposal: super::settlement::rake_disposal(rake_mode, rake)?,
                    }))
                }
            };
        }

        match (plan, rake_event) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(PokerL1Error::Other(
                "Texas rake receipt is detached from a settlement anchor".into(),
            )),
            (Some((_, _, gross_pot, rake, total_awards)), _)
                if total_awards.checked_add(rake) != Some(gross_pot) =>
            {
                Err(PokerL1Error::Other(
                    "Texas settlement plan violates gross = awards + rake".into(),
                ))
            }
            (Some((_, _, _, 0, _)), None) => Ok(None),
            (Some((_, _, _, 0, _)), Some(_)) => Err(PokerL1Error::Other(
                "Texas zero-rake settlement contains a rake receipt".into(),
            )),
            (Some((_, _, _, _, _)), None) => Err(PokerL1Error::Other(
                "Texas positive-rake settlement is missing its Treasury receipt".into(),
            )),
            (
                Some((table_id, plan_digest, gross_pot, rake, total_awards)),
                Some((rake_table_id, pot_before, rake_amount, pot_after, rake_mode)),
            ) => {
                if rake_table_id != table_id
                    || pot_before != gross_pot
                    || rake_amount != rake
                    || pot_after != total_awards
                {
                    return Err(PokerL1Error::Other(
                        "Texas rake receipt does not match its settlement plan".into(),
                    ));
                }
                Ok(Some(ResolvedRake {
                    table_id,
                    plan_digest: Some(plan_digest),
                    gross_pot,
                    amount: rake,
                    post_rake_pot: total_awards,
                    disposal: super::settlement::rake_disposal(rake_mode, rake)?,
                }))
            }
        }
    }

    /// Derive the unique Treasury receipt, rejecting duplicate or detached rake events.
    ///
    /// TE-M4: burn-mode (`RAKE_MODE_FIXED_RAKE_BURN`) settlements return `None`
    /// here — the collected rake must **not** become a Treasury-owned UTXO. The
    /// matching disposal is exposed by [`Self::settlement_rake_burn`].
    pub fn settlement_treasury_receipt(&self) -> PokerL1Result<Option<SettlementTreasuryReceipt>> {
        match self.resolve_rake()? {
            None => Ok(None),
            Some(rake) => match rake.disposal {
                super::settlement::RakeDisposal::TreasurySplit { .. } => {
                    Ok(Some(SettlementTreasuryReceipt {
                        table_id: rake.table_id,
                        plan_digest: rake.plan_digest,
                        gross_pot: rake.gross_pot,
                        amount: rake.amount,
                        post_rake_pot: rake.post_rake_pot,
                    }))
                }
                // 销毁处置：rake 不产生 Treasury 现金输出（一致性已由 resolve_rake 校验）
                super::settlement::RakeDisposal::Burn { .. }
                | super::settlement::RakeDisposal::None => Ok(None),
            },
        }
    }

    /// Derive the unique rake burn, rejecting duplicate or detached rake events
    /// (TE-M4). `None` unless the settled hand's rake mode is
    /// `RAKE_MODE_FIXED_RAKE_BURN` with a positive rake.
    pub fn settlement_rake_burn(&self) -> PokerL1Result<Option<SettlementRakeBurn>> {
        match self.resolve_rake()? {
            None => Ok(None),
            Some(rake) => match rake.disposal {
                super::settlement::RakeDisposal::Burn { amount } if amount > 0 => {
                    Ok(Some(SettlementRakeBurn {
                        table_id: rake.table_id,
                        plan_digest: rake.plan_digest,
                        gross_pot: rake.gross_pot,
                        amount,
                        post_rake_pot: rake.post_rake_pot,
                    }))
                }
                _ => Ok(None),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;

    fn dummy_table(name: &str) -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            name.into(),
            [0u8; 20],
            6,
            50,
            100,
        );
        table.seats[2].fixture_set_player([0xAA; 20]);
        table.seats[2].set_status(super::super::types::SeatStatus::Active);
        table
    }

    fn dummy_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0x11,
                raw: vec![0xBB; 32],
            },
            chain_id: 7,
            block_height: 11,
            block_timestamp: 13,
        }
    }

    #[test]
    fn l1_prove_task_borsh_roundtrip() {
        let task = L1ProveTask::new(
            6, // MethodKind::Fold = 6
            dummy_context(),
            vec![],
            dummy_table("pre"),
            dummy_table("post"),
            42,
            1,
            3,
        );
        let bytes = borsh::to_vec(&task).unwrap();
        let recovered: L1ProveTask = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.method_kind, 6);
        assert_eq!(recovered.table_id, 42);
        assert_eq!(recovered.context, dummy_context());
        assert!(recovered.raw_args.is_empty());
    }

    // ===== TE-M4：mode 感知的处置视图 =====

    fn showdown_events(rake_mode: u8) -> Vec<TexasPokerEvent> {
        use super::super::events::TexasPokerEvent;
        vec![
            TexasPokerEvent::SettlementPlanCommitted {
                table_id: dummy_table("t").id,
                plan_digest: [0x11; 32],
                runout_count: 1,
                gross_pot: 600,
                rake: 25,
                total_awards: 575,
            },
            TexasPokerEvent::RakeCollected {
                table_id: dummy_table("t").id,
                pot_before: 600,
                rake_amount: 25,
                pot_after: 575,
                rake_mode,
            },
        ]
    }

    /// mode 2 桌：无 Treasury receipt（不铸现金输出），burn 视图给出销毁额。
    #[test]
    fn burn_mode_yields_burn_view_and_no_treasury_receipt() {
        use super::super::constants::RAKE_MODE_FIXED_RAKE_BURN;
        let output = L1DispatchOutput::events_only(showdown_events(RAKE_MODE_FIXED_RAKE_BURN));

        let receipt = output.settlement_treasury_receipt().unwrap();
        assert!(receipt.is_none(), "burn 桌不得产生 Treasury 现金输出");

        let burn = output.settlement_rake_burn().unwrap().expect("burn view");
        assert_eq!(burn.table_id, dummy_table("t").id);
        assert_eq!(burn.amount, 25);
        assert_eq!(burn.gross_pot, 600);
        assert_eq!(burn.post_rake_pot, 575);
        assert_eq!(burn.plan_digest, Some([0x11; 32]));
    }

    /// mode 1 桌零回退：Treasury receipt 语义逐点不变，burn 视图恒 None。
    #[test]
    fn percentage_mode_keeps_treasury_receipt_and_no_burn_view() {
        use super::super::constants::RAKE_MODE_PERCENTAGE;
        let output = L1DispatchOutput::events_only(showdown_events(RAKE_MODE_PERCENTAGE));

        let receipt = output.settlement_treasury_receipt().unwrap().expect("receipt");
        assert_eq!(receipt.amount, 25);
        assert_eq!(receipt.plan_digest, Some([0x11; 32]));
        assert_eq!(receipt.gross_pot, 600);
        assert_eq!(receipt.post_rake_pot, 575);
        assert!(output.settlement_rake_burn().unwrap().is_none());
    }

    /// mode 0 桌：零 rake 无事件 → 两视图均 None；none 模式带正 rake 的
    /// receipt 是状态机 bug 信号（fail-closed）；未知 mode 同样 fail-closed。
    #[test]
    fn none_mode_is_quiet_and_inconsistent_or_unknown_modes_fail_closed() {
        use super::super::constants::RAKE_MODE_NONE;
        use super::super::events::TexasPokerEvent;
        // 正常 none 桌：零 rake 不发 RakeCollected（两视图均安静）
        let quiet = vec![TexasPokerEvent::SettlementPlanCommitted {
            table_id: dummy_table("t").id,
            plan_digest: [0x11; 32],
            runout_count: 1,
            gross_pot: 600,
            rake: 0,
            total_awards: 600,
        }];
        let output = L1DispatchOutput::events_only(quiet);
        assert!(output.settlement_treasury_receipt().unwrap().is_none());
        assert!(output.settlement_rake_burn().unwrap().is_none());

        // none 模式带正 rake：处置判定拒绝（状态机 bug 信号，不产出打款视图）
        let buggy = L1DispatchOutput::events_only(showdown_events(RAKE_MODE_NONE));
        assert!(buggy.settlement_treasury_receipt().is_err());
        assert!(buggy.settlement_rake_burn().is_err());

        // 未知 rake_mode：处置判定 fail-closed（此前该字段被忽略——mode 2 的
        // 引入使其成为承载处置语义的判别值，"不认识 ≠ 接受"）
        for unknown in [3u8, u8::MAX] {
            let output = L1DispatchOutput::events_only(showdown_events(unknown));
            assert!(output.settlement_treasury_receipt().is_err());
            assert!(output.settlement_rake_burn().is_err());
        }
    }

    /// burn 桌 uncontested（无 showdown plan）终局：burn 视图同样成立，
    /// 与 plan 锚的守恒检查保留。
    #[test]
    fn burn_mode_uncontested_settlement_burns_without_treasury_output() {
        use super::super::constants::RAKE_MODE_FIXED_RAKE_BURN;
        use super::super::events::TexasPokerEvent;
        let output = L1DispatchOutput::events_only(vec![
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id: dummy_table("t").id,
                winner_seat: 1,
                winner_player: [0xAB; 20],
                pot: 95,
            },
            TexasPokerEvent::RakeCollected {
                table_id: dummy_table("t").id,
                pot_before: 100,
                rake_amount: 5,
                pot_after: 95,
                rake_mode: RAKE_MODE_FIXED_RAKE_BURN,
            },
        ]);
        assert!(output.settlement_treasury_receipt().unwrap().is_none());
        let burn = output.settlement_rake_burn().unwrap().expect("burn view");
        assert_eq!(burn.amount, 5);
        assert_eq!(burn.plan_digest, None, "uncontested 终局无 plan 摘要");
    }
}
