//! 规范结算计划（`SettlementPlan`）——自 poker_l1
//! `settlement.rs` 搬运，borsh 编码与 digest 域标签**逐字节兼容**。
//!
//! Settlement is deliberately split into two phases:
//!
//! 1. [`crate::derive_settlement_plan`] is a pure function over an
//!    authenticated table snapshot and canonical runout boards.
//! 2. The state machine validates and applies the returned plan without
//!    re-running hand ranking, side-pot construction, rake allocation, or
//!    odd-chip selection while mutating balances.
//!
//! The normalized plan is bounded by the protocol constants (9 seats, 9 pots,
//! 2 runouts), has a canonical Borsh encoding, and can therefore be committed
//! by the host verifier and projected into AIR columns without depending on
//! event ordering or dynamic winner lists.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::SettlementError;
use crate::hand_rank::HandRank;

/// Canonical settlement-plan encoding version.
pub const SETTLEMENT_PLAN_VERSION: u8 = 2;
/// Maximum number of independent boards supported by the protocol.
pub const MAX_RUNOUTS: usize = 2;
/// Fixed number of award/rank slots in every plan (`MAX_PLAYERS`).
pub const SETTLEMENT_SEATS: usize = MAX_PLAYERS as usize;
/// 最多玩家数（与 poker_l1 `constants::MAX_PLAYERS` 一致）。
pub const MAX_PLAYERS: u8 = 9;
/// 总下注上界（与 poker_l1 `constants::MAX_TOTAL_BET` 一致）。
pub const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;

/// 摘要域标签（**冻结**：跨组件唯一事实源，字节兼容必须保留）。
pub const SETTLEMENT_PLAN_DIGEST_DOMAIN: &[u8] = b"zchain.texas_poker.settlement_plan.v2";

/// Street at which a two-runout schedule started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RitStartStreet {
    /// No public cards were exposed; both boards receive five independent cards.
    Preflop,
    /// The flop is shared; both boards receive an independent turn and river.
    Flop,
    /// Flop and turn are shared; both boards receive an independent river.
    Turn,
}

impl RitStartStreet {
    /// Number of first-board cards shared by both runouts.
    #[must_use]
    pub const fn shared_board_len(self) -> u8 {
        match self {
            Self::Preflop => 0,
            Self::Flop => 3,
            Self::Turn => 4,
        }
    }

    /// Recover the only canonical start street for a shared prefix length.
    ///
    /// # Errors
    /// 非规范共享前缀长度（2、>4 等）→ [`SettlementError`]。
    pub fn from_shared_board_len(shared_board_len: u8) -> Result<Self, SettlementError> {
        match shared_board_len {
            0 => Ok(Self::Preflop),
            3 => Ok(Self::Flop),
            4 => Ok(Self::Turn),
            value => Err(SettlementError::invalid(format!(
                "Texas RIT shared prefix {value} has no canonical start street"
            ))),
        }
    }
}

/// Canonical number and shared-prefix shape of a settlement's runouts.
///
/// The enum makes invalid pairs such as `(runout_count=1, shared_board_len=3)`
/// and non-street prefixes such as `2` unrepresentable in the normalized plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SettlementRunoutSchedule {
    /// One normal board with no duplicated runout suffix.
    Single,
    /// Two boards that diverge at a canonical Hold'em street boundary.
    Twice {
        /// Street at which both boards begin receiving independent cards.
        start: RitStartStreet,
    },
}

impl SettlementRunoutSchedule {
    /// Number of active boards.
    #[must_use]
    pub const fn count(self) -> u8 {
        match self {
            Self::Single => 1,
            Self::Twice { .. } => 2,
        }
    }

    /// Number of first-board cards shared by both runouts.
    #[must_use]
    pub const fn shared_board_len(self) -> u8 {
        match self {
            Self::Single => 0,
            Self::Twice { start } => start.shared_board_len(),
        }
    }
}

/// Settlement details for one pot on one runout.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct RunoutPotPlan {
    /// Amount of this pot assigned to the runout.
    pub amount: u64,
    /// Winning seats for this runout/pot.
    pub winner_mask: u16,
    /// Canonical best rank for every seat (`None` when ineligible).
    pub ranks: [Option<HandRank>; SETTLEMENT_SEATS],
    /// Award paid to every seat from this runout/pot.
    pub awards: [u64; SETTLEMENT_SEATS],
}

impl RunoutPotPlan {
    /// Canonical inactive runout slot (all-zero payload).
    #[must_use]
    pub fn inactive() -> Self {
        Self {
            amount: 0,
            winner_mask: 0,
            ranks: [None; SETTLEMENT_SEATS],
            awards: [0; SETTLEMENT_SEATS],
        }
    }

    /// Whether this fixed runout slot participates in settlement.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.winner_mask != 0
    }
}

impl BorshDeserialize for RunoutPotPlan {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let amount = u64::deserialize_reader(reader)?;
        let winner_mask = u16::deserialize_reader(reader)?;
        let ranks = <[Option<HandRank>; SETTLEMENT_SEATS]>::deserialize_reader(reader)?;
        let awards = <[u64; SETTLEMENT_SEATS]>::deserialize_reader(reader)?;
        let derived_active = winner_mask != 0;
        if !derived_active
            && (amount != 0 || ranks.iter().any(Option::is_some) || awards.iter().any(|v| *v != 0))
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "inactive settlement runout carries non-zero payload",
            ));
        }
        Ok(Self {
            amount,
            winner_mask,
            ranks,
            awards,
        })
    }
}

/// Canonical settlement details for one main/side-pot layer.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct SettlementPotPlan {
    /// Stable layer index (`0` is the main pot).
    pub pot_index: u8,
    /// Amount before rake.
    pub gross_amount: u64,
    /// Rake allocated to this layer.
    pub rake: u64,
    /// Amount after rake and before runout splitting.
    pub net_amount: u64,
    /// Seats eligible to win this layer.
    pub eligible_mask: u16,
    /// Fixed two-slot runout projection.
    pub runouts: [RunoutPotPlan; MAX_RUNOUTS],
}

impl SettlementPotPlan {
    /// Whether at least two seats are eligible to contest this layer.
    ///
    /// A one-seat outer layer is an uncalled return. It is never raked and is
    /// paid directly to that seat without depending on either runout board.
    #[must_use]
    pub const fn is_contested(&self) -> bool {
        self.eligible_mask.count_ones() >= 2
    }
}

impl BorshDeserialize for SettlementPotPlan {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let pot_index = u8::deserialize_reader(reader)?;
        let gross_amount = u64::deserialize_reader(reader)?;
        let rake = u64::deserialize_reader(reader)?;
        let net_amount = u64::deserialize_reader(reader)?;
        let eligible_mask = u16::deserialize_reader(reader)?;
        let runouts = <[RunoutPotPlan; MAX_RUNOUTS]>::deserialize_reader(reader)?;
        if eligible_mask == 0 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "settlement pot has no eligible seats",
            ));
        }
        Ok(Self {
            pot_index,
            gross_amount,
            rake,
            net_amount,
            eligible_mask,
            runouts,
        })
    }
}

/// Fully normalized settlement output.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementPlan {
    /// Encoding/domain version.
    pub version: u8,
    /// Typed single/twice schedule and canonical shared-prefix boundary.
    pub schedule: SettlementRunoutSchedule,
    /// Sum of all wager contributions before rake.
    pub gross_pot: u64,
    /// Total rake removed from table custody.
    pub rake: u64,
    /// Total paid to players.
    pub total_awards: u64,
    /// Winner union across every pot and runout.
    pub winner_mask: u16,
    /// Aggregate award paid to each seat.
    pub awards: [u64; SETTLEMENT_SEATS],
    /// Ordered main/side-pot layers (bounded by `MAX_PLAYERS`).
    pub pots: Vec<SettlementPotPlan>,
}

impl SettlementPlan {
    /// Rake billing basis: the sum of `gross_amount` over **contested**
    /// layers (`SettlementPotPlan::is_contested`, i.e. layers with ≥ 2
    /// eligible seats).
    ///
    /// Canonical rake semantics (poker_l1 `derive_settlement_plan`) only
    /// charge rake on contested gross: an uncontested layer is an uncalled
    /// return (or sole-survivor layer); it never carries rake (enforced by
    /// [`SettlementPlan::validate`]) and therefore never enters the billing
    /// basis. The appchain fee relation is
    /// `rake.total == plan.rake == policy.rake_of(plan.rake_base())`
    /// (ABI v1.2.2, BLOCKERS B9)。
    ///
    /// For a plan that passed [`SettlementPlan::validate`] the sum cannot
    /// overflow (Σ contested gross ≤ gross_pot); a hostile unvalidated plan
    /// saturates to `u64::MAX`, which can only over-state the base and thus
    /// fail the fee relation (fail-closed).
    #[must_use]
    pub fn rake_base(&self) -> u64 {
        self.pots
            .iter()
            .filter(|pot| pot.is_contested())
            .try_fold(0u64, |sum, pot| sum.checked_add(pot.gross_amount))
            .unwrap_or(u64::MAX)
    }

    /// Domain-separated digest of the canonical plan encoding.
    ///
    /// `blake2b-256("zchain.texas_poker.settlement_plan.v2" ‖ borsh(plan))`。
    /// 域标签**冻结**——本函数是跨组件（VM/appchain/verifier）plan 指纹的
    /// 唯一事实源，任何变更都是全协议版本升级。
    ///
    /// # Errors
    /// 编码失败（内存 plan 的 borsh 编码实际不可失败；保留 Result 以对齐
    /// poker_l1 既有签名，见 `PokerL1Error` 胶水）。
    pub fn digest(&self) -> Result<[u8; 32], SettlementError> {
        let encoded = borsh::to_vec(self)
            .map_err(|error| SettlementError::invalid(format!("settlement plan borsh: {error}")))?;
        let mut hasher = Blake2bVar::new(32).expect("32 <= Blake2b maximum output");
        hasher.update(SETTLEMENT_PLAN_DIGEST_DOMAIN);
        hasher.update(&encoded);
        let mut digest = [0u8; 32];
        hasher
            .finalize_variable(&mut digest)
            .expect("32 <= Blake2b maximum output");
        Ok(digest)
    }

    /// Recheck all internal conservation and shape invariants without
    /// recomputing poker logic.
    ///
    /// # Errors
    /// 版本不符、越界、守恒破裂、runout 投影非规范等（全部 fail-closed）。
    pub fn validate(&self, seat_count: usize) -> Result<(), SettlementError> {
        if self.version != SETTLEMENT_PLAN_VERSION {
            return Err(SettlementError::invalid(format!(
                "settlement: unsupported plan version {}",
                self.version
            )));
        }
        if seat_count > SETTLEMENT_SEATS || self.pots.len() > SETTLEMENT_SEATS {
            return Err(SettlementError::invalid(
                "settlement: plan exceeds fixed seat/pot bounds",
            ));
        }
        if self
            .gross_pot
            .checked_sub(self.rake)
            .filter(|net| *net == self.total_awards)
            .is_none()
        {
            return Err(SettlementError::invalid(
                "settlement: gross_pot != rake + total_awards",
            ));
        }

        let mut gross = 0u64;
        let mut rake = 0u64;
        let mut awards = [0u64; SETTLEMENT_SEATS];
        let mut winner_mask = 0u16;
        for (index, pot) in self.pots.iter().enumerate() {
            if usize::from(pot.pot_index) != index {
                return Err(SettlementError::invalid(
                    "settlement: non-canonical pot index",
                ));
            }
            if pot.gross_amount.checked_sub(pot.rake) != Some(pot.net_amount) {
                return Err(SettlementError::invalid(
                    "settlement: pot gross/rake/net mismatch",
                ));
            }
            let eligible_count = pot.eligible_mask.count_ones();
            if eligible_count == 0 {
                return Err(SettlementError::invalid(
                    "settlement: pot has no eligible seats",
                ));
            }
            let contested = pot.is_contested();
            if !contested && pot.rake != 0 {
                return Err(SettlementError::invalid(
                    "settlement: uncontested pot must not be raked",
                ));
            }
            gross = gross.checked_add(pot.gross_amount).ok_or_else(|| {
                SettlementError::invalid("settlement: gross pot sum overflow")
            })?;
            rake = rake.checked_add(pot.rake).ok_or_else(|| {
                SettlementError::invalid("settlement: rake sum overflow")
            })?;
            let mut runout_total = 0u64;
            let active_runouts = if contested {
                usize::from(self.schedule.count())
            } else {
                1
            };
            for (runout_index, runout) in pot.runouts.iter().enumerate() {
                if runout_index >= active_runouts {
                    if runout != &RunoutPotPlan::inactive() {
                        return Err(SettlementError::invalid(
                            "settlement: inactive runout slot is non-zero",
                        ));
                    }
                    continue;
                }
                if !runout.is_active() {
                    return Err(SettlementError::invalid(
                        "settlement: active runout has no winners",
                    ));
                }
                if runout.winner_mask & !pot.eligible_mask != 0 {
                    return Err(SettlementError::invalid(
                        "settlement: runout winner is not eligible for the pot",
                    ));
                }
                if !contested
                    && (runout.winner_mask != pot.eligible_mask
                        || runout.amount != pot.net_amount
                        || runout.ranks.iter().any(Option::is_some))
                {
                    return Err(SettlementError::invalid(
                        "settlement: uncontested pot projection is non-canonical",
                    ));
                }
                let runout_awards = runout.awards.iter().try_fold(0u64, |sum, amount| {
                    sum.checked_add(*amount).ok_or_else(|| {
                        SettlementError::invalid("settlement: runout award overflow")
                    })
                })?;
                if runout_awards != runout.amount {
                    return Err(SettlementError::invalid(
                        "settlement: runout amount != awards",
                    ));
                }
                runout_total = runout_total.checked_add(runout.amount).ok_or_else(|| {
                    SettlementError::invalid("settlement: runout total overflow")
                })?;
                winner_mask |= runout.winner_mask;
                for (seat, amount) in runout.awards.iter().enumerate() {
                    awards[seat] = awards[seat].checked_add(*amount).ok_or_else(|| {
                        SettlementError::invalid("settlement: seat award overflow")
                    })?;
                }
            }
            if runout_total != pot.net_amount {
                return Err(SettlementError::invalid(
                    "settlement: runout split does not equal pot net amount",
                ));
            }
        }
        if gross != self.gross_pot
            || rake != self.rake
            || awards != self.awards
            || winner_mask != self.winner_mask
        {
            return Err(SettlementError::invalid(
                "settlement: aggregate projection mismatch",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 单层 contested pot（`seats_mask.count_ones() >= 2`）计划。
    fn single_pot_plan(
        gross_amount: u64,
        rake: u64,
        eligible_mask: u16,
    ) -> SettlementPlan {
        let net_amount = gross_amount - rake;
        let mut awards = [0u64; SETTLEMENT_SEATS];
        awards[0] = net_amount;
        let mut runout = RunoutPotPlan::inactive();
        runout.amount = net_amount;
        runout.winner_mask = if eligible_mask == 0 { 0b01 } else { eligible_mask };
        runout.awards = awards;
        SettlementPlan {
            version: SETTLEMENT_PLAN_VERSION,
            schedule: SettlementRunoutSchedule::Single,
            gross_pot: gross_amount,
            rake,
            total_awards: net_amount,
            winner_mask: runout.winner_mask,
            awards,
            pots: vec![SettlementPotPlan {
                pot_index: 0,
                gross_amount,
                rake,
                net_amount,
                eligible_mask,
                runouts: [runout, RunoutPotPlan::inactive()],
            }],
        }
    }

    /// contested 层（双 eligible）gross 全额进入 rake 基数。
    #[test]
    fn rake_base_sums_contested_gross() {
        let plan = single_pot_plan(1_000, 50, 0b11);
        assert!(plan.pots[0].is_contested());
        assert_eq!(plan.rake_base(), 1_000);
    }

    /// uncontested 层（uncalled 返还/sole-survivor）gross 不进入 rake 基数；
    /// 且 validate 强制该层 rake 必须为 0（B9 语义约束，core 侧钉死）。
    #[test]
    fn rake_base_excludes_uncontested_layers_and_validate_rejects_rake_on_them() {
        let contested = single_pot_plan(1_000, 50, 0b11);
        // 追加一个 uncalled 返还层（seat1 独占，rake 0）
        let mut plan = contested;
        plan.gross_pot += 300;
        plan.total_awards += 300;
        plan.awards[1] += 300;
        plan.winner_mask |= 0b10;
        let mut runout = RunoutPotPlan::inactive();
        runout.amount = 300;
        runout.winner_mask = 0b10;
        runout.awards[1] = 300;
        plan.pots.push(SettlementPotPlan {
            pot_index: 1,
            gross_amount: 300,
            rake: 0,
            net_amount: 300,
            eligible_mask: 0b10,
            runouts: [runout, RunoutPotPlan::inactive()],
        });
        assert!(plan.pots[0].is_contested());
        assert!(!plan.pots[1].is_contested());
        assert_eq!(plan.rake_base(), 1_000, "uncalled 层不计入基数");
        assert_eq!(plan.rake, 50);
        plan.validate(2).unwrap();

        // 约束确认：uncontested 层携带非零 rake → validate 拒绝（fail-closed）
        let mut raked_return = plan.clone();
        raked_return.rake = 51; // 伪造者同步抬高 plan.rake
        raked_return.pots[1].rake = 1;
        raked_return.pots[1].net_amount = 299;
        raked_return.pots[1].runouts[0].amount = 299;
        raked_return.pots[1].runouts[0].awards[1] = 299;
        raked_return.awards[1] -= 1;
        raked_return.total_awards -= 1;
        let error = raked_return.validate(2).unwrap_err();
        assert!(
            error.to_string().contains("uncontested pot must not be raked"),
            "unexpected error: {error}"
        );
    }
}
