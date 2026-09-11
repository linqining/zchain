//! Deterministic Texas Hold'em settlement planning.
//!
//! Settlement is deliberately split into two phases:
//!
//! 1. [`derive_settlement_plan`] is a pure function over an authenticated table snapshot and
//!    canonical runout boards.
//! 2. The state machine validates and applies the returned plan without re-running hand ranking,
//!    side-pot construction, rake allocation, or odd-chip selection while mutating balances.
//!
//! The normalized plan is bounded by the protocol constants (9 seats, 9 pots, 2 runouts), has a
//! canonical Borsh encoding, and can therefore be committed by the host verifier and projected
//! into AIR columns without depending on event ordering or dynamic winner lists.
//!
//! # 单一事实源（plan-appchain §5.2-1，P0-1）
//!
//! 结算语义（[`SettlementPlan`] 及其派生/校验/摘要、side-pot、odd-chip、
//! run-it-twice）已整体搬运到共享 crate
//! [`poker_settlement_core`](poker_settlement_core)（牌以 u8 规范索引表示）。
//! 本模块只保留：
//!
//! - 类型**再导出**（`pub use`，路径不变，borsh/digest 字节兼容不变）；
//! - VM 集成胶水：`Card`/`TexasPokerTable` → core [`TableSnapshot`] 投影；
//! - `PokerL1Error` 错误映射（`From<SettlementError>`，见 `crate::error`）。
//!
//! 行为零变化：poker_l1 既有结算测试（本模块 tests、`texas_poker_unit`、
//! `state_machine`）是等价性裁判。

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};

use poker_settlement_core::{SettlementBoards as CoreBoards, TableSnapshot};

use super::card::Card;
use super::types::{Seat, TexasPokerTable};
use crate::error::{PokerL1Error, PokerL1Result};

// ===== 单一事实源再导出（borsh 编码与 digest 域标签逐字节兼容） =====
pub use poker_settlement_core::{
    calculate_side_pots, derive_settlement_plan as derive_plan_from_snapshot, evaluate_best,
    is_eligible, rake_for, split_among_winners, split_across_runouts, HandRank, RitStartStreet,
    RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule, SidePot,
    SidePotError, SidePotResult, RAKE_MODE_NONE, RAKE_MODE_PERCENTAGE, MAX_PLAYERS, MAX_RUNOUTS,
    MAX_TOTAL_BET, SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS,
};

/// Canonical board input used while deriving a settlement plan.
///
/// With two runouts, `shared_board_len` cards at the beginning of both boards must be identical.
/// Cards after that prefix must be distinct across both runouts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum SettlementBoards {
    /// One complete five-card board.
    Single {
        /// Canonical board.
        board: Vec<Card>,
    },
    /// Two complete boards with one shared prefix.
    Twice {
        /// Street at which the two-runout schedule started.
        start: RitStartStreet,
        /// First canonical board.
        board1: Vec<Card>,
        /// Second canonical board.
        board2: Vec<Card>,
    },
}

impl BorshDeserialize for SettlementBoards {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        let boards = match variant {
            0 => Self::Single {
                board: Vec::<Card>::deserialize_reader(reader)?,
            },
            1 => Self::Twice {
                start: RitStartStreet::deserialize_reader(reader)?,
                board1: Vec::<Card>::deserialize_reader(reader)?,
                board2: Vec::<Card>::deserialize_reader(reader)?,
            },
            _ => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "invalid settlement boards variant",
                ));
            }
        };
        boards.validate().map_err(|error| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error.to_string())
        })?;
        Ok(boards)
    }
}

impl SettlementBoards {
    /// Construct the normal single-board settlement input.
    #[must_use]
    pub fn single(board: Vec<Card>) -> Self {
        Self::Single { board }
    }

    /// Construct a two-runout settlement input.
    #[must_use]
    pub fn twice(start: RitStartStreet, board1: Vec<Card>, board2: Vec<Card>) -> Self {
        Self::Twice {
            start,
            board1,
            board2,
        }
    }

    #[must_use]
    const fn runout_count(&self) -> u8 {
        match self {
            Self::Single { .. } => 1,
            Self::Twice { .. } => 2,
        }
    }

    #[must_use]
    const fn shared_board_len(&self) -> u8 {
        match self {
            Self::Single { .. } => 0,
            Self::Twice { start, .. } => start.shared_board_len(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    const fn schedule(&self) -> SettlementRunoutSchedule {
        match self {
            Self::Single { .. } => SettlementRunoutSchedule::Single,
            Self::Twice { start, .. } => SettlementRunoutSchedule::Twice { start: *start },
        }
    }

    fn board1(&self) -> &[Card] {
        match self {
            Self::Single { board } => board,
            Self::Twice { board1, .. } => board1,
        }
    }

    fn board2(&self) -> &[Card] {
        match self {
            Self::Single { .. } => &[],
            Self::Twice { board2, .. } => board2,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn board(&self, runout_index: usize) -> &[Card] {
        if runout_index == 0 {
            self.board1()
        } else {
            self.board2()
        }
    }

    fn validate(&self) -> PokerL1Result<()> {
        if self.board1().len() != 5 {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: board 1 must contain exactly 5 cards, got {}",
                self.board1().len()
            )));
        }
        if let Self::Twice {
            start,
            board1,
            board2,
        } = self
        {
            if board2.len() != 5 {
                return Err(PokerL1Error::Serialization(format!(
                    "settlement: board 2 must contain exactly 5 cards, got {}",
                    board2.len()
                )));
            }
            let shared = usize::from(start.shared_board_len());
            if board1[..shared] != board2[..shared] {
                return Err(PokerL1Error::Serialization(
                    "settlement: runout boards disagree on their shared prefix".into(),
                ));
            }
        }
        if self
            .board1()
            .iter()
            .chain(self.board2())
            .any(|card| !card.is_valid())
        {
            return Err(PokerL1Error::Serialization(
                "settlement: runout contains an invalid card".into(),
            ));
        }

        let mut seen = HashSet::new();
        for card in self.board1() {
            if !seen.insert(card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: duplicate card within board 1".into(),
                ));
            }
        }
        if let Self::Twice { start, board2, .. } = self {
            let shared = usize::from(start.shared_board_len());
            for card in board2.iter().skip(shared) {
                if !seen.insert(card.to_index()) {
                    return Err(PokerL1Error::Serialization(
                        "settlement: duplicate non-shared card across runouts".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// 投影为 core 的 u8 索引板输入（字节等价：`Card` 内部即 u8 索引）。
    fn to_core(&self) -> CoreBoards {
        let to_idx = |cards: &[Card]| cards.iter().map(|c: &Card| c.to_index()).collect::<Vec<u8>>();
        match self {
            Self::Single { board } => CoreBoards::single(to_idx(board)),
            Self::Twice { start, board1, board2 } => {
                CoreBoards::twice(*start, to_idx(board1), to_idx(board2))
            }
        }
    }
}

/// Derive the normal one-board settlement plan from the table's community cards.
pub fn derive_settlement_plan(table: &TexasPokerTable) -> PokerL1Result<SettlementPlan> {
    derive_settlement_plan_for_boards(
        table,
        &SettlementBoards::single(table.community_cards.to_vec()),
    )
}

/// Derive a deterministic settlement plan for one or two canonical boards.
///
/// VM 集成胶水：把认证的 `TexasPokerTable` 投影为 core [`TableSnapshot`]
/// 后委托 [`poker_settlement_core::derive_settlement_plan`]；分层/odd-chip/
/// run-it-twice/rake 语义全部在 core（单一事实源）。
pub fn derive_settlement_plan_for_boards(
    table: &TexasPokerTable,
    boards: &SettlementBoards,
) -> PokerL1Result<SettlementPlan> {
    boards.validate()?;
    if table.seats.len() > SETTLEMENT_SEATS {
        return Err(PokerL1Error::Serialization(
            "settlement: table exceeds MAX_PLAYERS".into(),
        ));
    }
    validate_exposed_cards(table, boards)?;

    // 座位投影：inactive = 未入座 / folded / 离手（与原 validate_exposed_cards
    // 的跳过集合同一；未入座座位 bet 恒 0，不改变 side-pot 分层结果）。
    let inactive: Vec<bool> = table
        .seats
        .iter()
        .map(|seat| !seat.is_occupied() || seat.is_folded() || seat.has_left_hand())
        .collect();
    let all_in: Vec<bool> = table.seats.iter().map(Seat::is_all_in).collect();
    let total_bets: Vec<u64> = table.seats.iter().map(Seat::total_bet).collect();
    let hole_cards: Vec<Vec<u8>> = table
        .seats
        .iter()
        .map(|seat| {
            seat.hand()
                .map(|hand| hand.iter().map(|c| c.to_index()).collect::<Vec<u8>>())
                .unwrap_or_default()
        })
        .collect();
    let hole_refs: Vec<&[u8]> = hole_cards.iter().map(Vec::as_slice).collect();

    let snapshot = TableSnapshot {
        seat_count: table.seats.len(),
        button: table.button,
        total_bets: &total_bets,
        inactive: &inactive,
        all_in: &all_in,
        hole_cards: &hole_refs,
        rake_mode: table.rake_mode,
        rake_bps: table.rake_bps,
        rake_cap: table.rake_cap,
    };
    let plan = derive_plan_from_snapshot(&snapshot, &boards.to_core())?;
    // 与搬运前一致：贡献总额必须等于 table.pot（core 侧只查 MAX_TOTAL_BET）。
    if plan.gross_pot != table.pot {
        return Err(PokerL1Error::Serialization(format!(
            "settlement: contribution total {} does not match table pot {}",
            plan.gross_pot, table.pot
        )));
    }
    Ok(plan)
}

fn validate_exposed_cards(table: &TexasPokerTable, boards: &SettlementBoards) -> PokerL1Result<()> {
    let mut seen_hole_cards = HashSet::new();
    for (seat_index, seat) in table.seats.iter().enumerate() {
        if !seat.is_occupied() || seat.is_folded() || seat.has_left_hand() {
            continue;
        }
        let hand = seat.hand().ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} has no in-hand payload"
            ))
        })?;
        if hand.len() != 2 || hand.iter().any(|card| !card.is_valid()) {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} must expose exactly two valid cards"
            )));
        }
        for card in hand.iter() {
            if !seen_hole_cards.insert(card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: duplicate exposed hole card".into(),
                ));
            }
        }
    }
    for card in boards.board1() {
        if seen_hole_cards.contains(&card.to_index()) {
            return Err(PokerL1Error::Serialization(
                "settlement: board card duplicates an exposed hole card".into(),
            ));
        }
    }
    if boards.runout_count() == 2 {
        for card in boards
            .board2()
            .iter()
            .skip(usize::from(boards.shared_board_len()))
        {
            if seen_hole_cards.contains(&card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: second board duplicates an exposed hole card".into(),
                ));
            }
        }
    }
    Ok(())
}

// rake 模式常量在本模块保持可用（RAKE_MODE_NONE/PERCENTAGE 来自 core，
// 与 `constants.rs` 数值一致——跨 crate 一致性由下面的静态断言钉住）。
const _: () = {
    assert!(RAKE_MODE_NONE == super::constants::RAKE_MODE_NONE);
    assert!(RAKE_MODE_PERCENTAGE == super::constants::RAKE_MODE_PERCENTAGE);
    assert!(MAX_PLAYERS == super::constants::MAX_PLAYERS);
    assert!(MAX_TOTAL_BET == super::constants::MAX_TOTAL_BET);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::vm::contracts::texas_poker::types::SeatStatus;

    #[derive(BorshSerialize, Clone)]
    struct LegacyRunoutPotPlanV1 {
        active: bool,
        amount: u64,
        winner_mask: u16,
        ranks: [Option<HandRank>; SETTLEMENT_SEATS],
        awards: [u64; SETTLEMENT_SEATS],
    }

    #[derive(BorshSerialize)]
    struct LegacySettlementPotPlanV1 {
        pot_index: u8,
        contested: bool,
        gross_amount: u64,
        rake: u64,
        net_amount: u64,
        eligible_mask: u16,
        runouts: [LegacyRunoutPotPlanV1; MAX_RUNOUTS],
    }

    fn table() -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            "settlement".into(),
            [0xAA; 20],
            3,
            1,
            2,
        );
        for (index, stack) in [900u64, 800, 700].into_iter().enumerate() {
            table.seats[index].fixture_set_player([index as u8 + 1; 20]);
            table.seats[index].set_stack(stack).unwrap();
            table.seats[index].fixture_set_total_bet([100, 200, 300][index]);
            table.seats[index].set_status(SeatStatus::AllIn);
        }
        table.seats[0].fixture_set_hand([Card::new(0, 14), Card::new(1, 14)].into());
        table.seats[1].fixture_set_hand([Card::new(0, 13), Card::new(1, 13)].into());
        table.seats[2].fixture_set_hand([Card::new(0, 12), Card::new(1, 12)].into());
        table.pot = 600;
        table.chip_pool = 3_000;
        table.community_cards = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(3, 8),
            Card::new(2, 10),
        ]
        .try_into()
        .unwrap();
        table
    }

    #[test]
    fn settlement_pot_v2_omits_contested_and_rejects_v1_bytes() {
        let plan = derive_settlement_plan(&table()).unwrap();
        let pot = plan.pots[0].clone();
        let legacy = LegacySettlementPotPlanV1 {
            pot_index: pot.pot_index,
            contested: pot.is_contested(),
            gross_amount: pot.gross_amount,
            rake: pot.rake,
            net_amount: pot.net_amount,
            eligible_mask: pot.eligible_mask,
            runouts: std::array::from_fn(|index| {
                let runout = &pot.runouts[index];
                LegacyRunoutPotPlanV1 {
                    active: runout.is_active(),
                    amount: runout.amount,
                    winner_mask: runout.winner_mask,
                    ranks: runout.ranks,
                    awards: runout.awards,
                }
            }),
        };

        let canonical_bytes = borsh::to_vec(&pot).unwrap();
        let legacy_bytes = borsh::to_vec(&legacy).unwrap();
        assert_eq!(legacy_bytes.len(), canonical_bytes.len() + 3);
        let decoded: SettlementPotPlan = borsh::from_slice(&canonical_bytes).unwrap();
        assert_eq!(decoded, pot);
        assert!(
            borsh::from_slice::<SettlementPotPlan>(&legacy_bytes).is_err(),
            "v1 pot bytes with contested plus two nested active bits must fail closed"
        );
    }

    #[test]
    fn settlement_boards_and_plan_use_one_typed_runout_schedule() {
        let board = table().community_cards.to_vec();
        let boards = SettlementBoards::single(board.clone());
        let canonical_bytes = borsh::to_vec(&boards).unwrap();
        assert_eq!(
            borsh::from_slice::<SettlementBoards>(&canonical_bytes).unwrap(),
            boards
        );
        assert_eq!(boards.schedule(), SettlementRunoutSchedule::Single);
        assert!(RitStartStreet::from_shared_board_len(2).is_err());

        let twice = SettlementBoards::twice(RitStartStreet::Flop, board.clone(), board);
        assert_eq!(
            twice.schedule(),
            SettlementRunoutSchedule::Twice {
                start: RitStartStreet::Flop
            }
        );

        let mut mismatched_board = table().community_cards.to_vec();
        mismatched_board[0] = Card::new(0, 3);
        let malformed = SettlementBoards::twice(
            RitStartStreet::Flop,
            table().community_cards.to_vec(),
            mismatched_board,
        );
        assert!(
            borsh::from_slice::<SettlementBoards>(&borsh::to_vec(&malformed).unwrap()).is_err(),
            "typed tags still require both boards to agree on the street-derived shared prefix"
        );
    }

    #[test]
    fn settlement_runout_v2_omits_active_and_rejects_v1_bytes() {
        let plan = derive_settlement_plan(&table()).unwrap();
        let runout = plan.pots[0].runouts[0].clone();
        let legacy = LegacyRunoutPotPlanV1 {
            active: runout.is_active(),
            amount: runout.amount,
            winner_mask: runout.winner_mask,
            ranks: runout.ranks,
            awards: runout.awards,
        };

        let canonical_bytes = borsh::to_vec(&runout).unwrap();
        let legacy_bytes = borsh::to_vec(&legacy).unwrap();
        assert_eq!(legacy_bytes.len(), canonical_bytes.len() + 1);
        let decoded: RunoutPotPlan = borsh::from_slice(&canonical_bytes).unwrap();
        assert_eq!(decoded, runout);
        assert!(
            borsh::from_slice::<RunoutPotPlan>(&legacy_bytes).is_err(),
            "v1 runout bytes with the duplicated active bit must fail closed"
        );
    }

    #[test]
    fn single_runout_plan_is_canonical_and_conserves_funds() {
        let table = table();
        let plan = derive_settlement_plan(&table).expect("derive plan");
        assert_eq!(plan.schedule, SettlementRunoutSchedule::Single);
        assert_eq!(plan.gross_pot, 600);
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.total_awards, 600);
        assert_eq!(plan.pots.len(), 3);
        assert_eq!(plan.awards, [300, 200, 100, 0, 0, 0, 0, 0, 0]);
        assert_eq!(plan.digest().unwrap(), plan.clone().digest().unwrap());
        plan.validate(table.seats.len()).unwrap();

        let mut retired = plan;
        retired.version = 1;
        assert!(retired.validate(table.seats.len()).is_err());
    }

    #[test]
    fn two_runouts_split_each_side_pot_before_selecting_winners() {
        let table = table();
        let board1 = table.community_cards.to_vec();
        let board2 = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(2, 12),
            Card::new(3, 10),
        ];
        let boards = SettlementBoards::twice(RitStartStreet::Flop, board1, board2);
        let plan = derive_settlement_plan_for_boards(&table, &boards).expect("derive RIT plan");
        assert_eq!(
            plan.schedule,
            SettlementRunoutSchedule::Twice {
                start: RitStartStreet::Flop
            }
        );
        assert_eq!(plan.total_awards, 600);
        assert_eq!(plan.pots[0].runouts[0].amount, 150);
        assert_eq!(plan.pots[0].runouts[1].amount, 150);
        assert_eq!(plan.pots[0].runouts[0].winner_mask, 0b001);
        assert_eq!(plan.pots[0].runouts[1].winner_mask, 0b100);
    }

    #[test]
    fn odd_chip_order_starts_clockwise_after_button() {
        let awards = split_among_winners(5, 0b111, 0, 3).unwrap();
        assert_eq!(awards[..3], [1, 2, 2]);
    }

    #[test]
    fn duplicate_cross_runout_card_is_rejected() {
        let table = table();
        let board1 = table.community_cards.to_vec();
        let board2 = vec![board1[0], board1[1], board1[2], board1[3], Card::new(3, 10)];
        let error = derive_settlement_plan_for_boards(
            &table,
            &SettlementBoards::twice(RitStartStreet::Flop, board1, board2),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate non-shared card"));
    }

    #[test]
    fn uncalled_outer_layer_is_returned_without_rake_or_runout_dependency() {
        let mut table = table();
        table.seats[0].fixture_set_total_bet(50);
        table.seats[1].fixture_set_total_bet(100);
        table.seats[2] = super::super::types::Seat::empty();
        table.pot = 150;
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 1_000;
        table.rake_cap = u64::MAX;

        let board1 = table.community_cards.to_vec();
        let board2 = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(2, 11),
            Card::new(3, 12),
        ];
        let plan = derive_settlement_plan_for_boards(
            &table,
            &SettlementBoards::twice(RitStartStreet::Flop, board1, board2),
        )
        .unwrap();

        assert_eq!(plan.pots.len(), 2);
        assert!(plan.pots[0].is_contested());
        assert_eq!(plan.pots[0].gross_amount, 100);
        assert_eq!(plan.pots[0].rake, 10);
        assert!(!plan.pots[1].is_contested());
        assert_eq!(plan.pots[1].gross_amount, 50);
        assert_eq!(plan.pots[1].rake, 0);
        assert_eq!(plan.pots[1].runouts[0].amount, 50);
        assert_eq!(plan.pots[1].runouts[0].winner_mask, 0b010);
        assert_eq!(plan.pots[1].runouts[0].awards[1], 50);
        assert_eq!(plan.pots[1].runouts[1], RunoutPotPlan::inactive());
        assert_eq!(plan.rake, 10);
        assert_eq!(plan.total_awards, 140);
        plan.validate(table.seats.len()).unwrap();
    }

    #[test]
    fn multiway_rit_side_pots_ties_rake_and_odd_chips_are_canonical() {
        let mut table = table();
        table.button = 0;
        for (seat, bet) in table.seats.iter_mut().zip([101u64, 202, 303]) {
            seat.fixture_set_total_bet(bet);
        }
        table.pot = 606;
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500;
        table.rake_cap = 29;
        table.seats[0].fixture_set_hand([Card::new(0, 2), Card::new(1, 7)].into());
        table.seats[1].fixture_set_hand([Card::new(0, 3), Card::new(1, 8)].into());
        table.seats[2].fixture_set_hand([Card::new(0, 4), Card::new(1, 9)].into());

        // Both boards play entirely from the board, so every eligible seat ties. This makes the
        // button-relative odd-chip order observable at every side-pot depth.
        let boards = SettlementBoards::twice(
            RitStartStreet::Preflop,
            vec![
                Card::new(2, 10),
                Card::new(2, 11),
                Card::new(2, 12),
                Card::new(2, 13),
                Card::new(2, 14),
            ],
            vec![
                Card::new(3, 2),
                Card::new(3, 3),
                Card::new(3, 4),
                Card::new(3, 5),
                Card::new(3, 6),
            ],
        );
        let plan = derive_settlement_plan_for_boards(&table, &boards).unwrap();

        assert_eq!(plan.gross_pot, 606);
        // The final 101-chip layer is uncontested, so only 505 chips are rakeable.
        assert_eq!(plan.rake, 25);
        assert_eq!(plan.total_awards, 581);
        assert_eq!(plan.pots.len(), 3);
        assert!(plan.pots[0].is_contested());
        assert!(plan.pots[1].is_contested());
        assert!(!plan.pots[2].is_contested());
        assert_eq!(plan.pots[2].rake, 0);
        assert_eq!(plan.pots[2].runouts[0].awards[2], 101);
        assert!(!plan.pots[2].runouts[1].is_active());
        assert_eq!(plan.pots[0].runouts[0].winner_mask, 0b111);
        assert_eq!(plan.pots[0].runouts[1].winner_mask, 0b111);
        assert_eq!(plan.pots[1].runouts[0].winner_mask, 0b110);
        assert_eq!(plan.pots[1].runouts[1].winner_mask, 0b110);
        assert_eq!(plan.awards.iter().sum::<u64>(), 581);
        plan.validate(table.seats.len()).unwrap();
    }

    /// 跨 crate 一致性（P0-1）：同一 plan 经 core 派生与 VM 胶水派生必须
    /// 完全相等，digest 与 poker-settlement-core 单元 golden 一致。
    #[test]
    fn core_snapshot_derivation_matches_vm_glue_derivation() {
        let table = table();
        let boards = SettlementBoards::twice(
            RitStartStreet::Flop,
            table.community_cards.to_vec(),
            vec![
                Card::new(2, 2),
                Card::new(3, 4),
                Card::new(2, 6),
                Card::new(2, 12),
                Card::new(3, 10),
            ],
        );
        let glue = derive_settlement_plan_for_boards(&table, &boards).unwrap();

        let inactive: Vec<bool> = table
            .seats
            .iter()
            .map(|seat| !seat.is_occupied() || seat.is_folded() || seat.has_left_hand())
            .collect();
        let all_in: Vec<bool> = table.seats.iter().map(Seat::is_all_in).collect();
        let total_bets: Vec<u64> = table.seats.iter().map(Seat::total_bet).collect();
        let hole_cards: Vec<Vec<u8>> = table
            .seats
            .iter()
            .map(|seat| {
                seat.hand()
                    .map(|hand| hand.iter().map(|c| c.to_index()).collect::<Vec<u8>>())
                    .unwrap_or_default()
            })
            .collect();
        let hole_refs: Vec<&[u8]> = hole_cards.iter().map(Vec::as_slice).collect();
        let snapshot = TableSnapshot {
            seat_count: table.seats.len(),
            button: table.button,
            total_bets: &total_bets,
            inactive: &inactive,
            all_in: &all_in,
            hole_cards: &hole_refs,
            rake_mode: table.rake_mode,
            rake_bps: table.rake_bps,
            rake_cap: table.rake_cap,
        };
        let to_idx = |cards: &[Card]| cards.iter().map(|c: &Card| c.to_index()).collect::<Vec<u8>>();
        let core_plan = poker_settlement_core::derive_settlement_plan(
            &snapshot,
            &poker_settlement_core::SettlementBoards::twice(
                RitStartStreet::Flop,
                to_idx(boards.board1()),
                to_idx(boards.board2()),
            ),
        )
        .unwrap();
        assert_eq!(glue, core_plan);
        assert_eq!(
            glue.digest().unwrap(),
            poker_settlement_core::SettlementPlan::digest(&core_plan).unwrap()
        );
    }
}
