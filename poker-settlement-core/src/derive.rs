//! 结算计划派生（自 poker_l1 `settlement.rs:515` 起的纯函数搬运）。
//!
//! 牌一律用 u8 规范索引表示；poker_l1 侧在其 VM 集成层把 `Card`/
//! `TexasPokerTable` 投影为 [`TableSnapshot`] + [`SettlementBoards`] 后调用
//! [`derive_settlement_plan`]。所有分层/odd-chip/run-it-twice 语义与
//! poker_l1 搬运前逐字等价（golden digest 跨 crate 测试钉住）。

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::SettlementError;
use crate::hand_rank::{evaluate_best, HandRank};
use crate::plan::{
    RitStartStreet, RunoutPotPlan, SettlementPlan, SettlementPotPlan, SettlementRunoutSchedule,
    MAX_RUNOUTS, MAX_TOTAL_BET, SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS,
};
use crate::side_pot::{self, SidePot};
use crate::{RAKE_MODE_NONE, RAKE_MODE_PERCENTAGE};

/// Canonical board input used while deriving a settlement plan.
///
/// With two runouts, `shared_board_len` cards at the beginning of both boards
/// must be identical. Cards after that prefix must be distinct across both
/// runouts. 牌为 u8 规范索引（0..=51 合法）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum SettlementBoards {
    /// One complete five-card board.
    Single {
        /// Canonical board.
        board: Vec<u8>,
    },
    /// Two complete boards with one shared prefix.
    Twice {
        /// Street at which the two-runout schedule started.
        start: RitStartStreet,
        /// First canonical board.
        board1: Vec<u8>,
        /// Second canonical board.
        board2: Vec<u8>,
    },
}

impl BorshDeserialize for SettlementBoards {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        let boards = match variant {
            0 => Self::Single {
                board: Vec::<u8>::deserialize_reader(reader)?,
            },
            1 => Self::Twice {
                start: RitStartStreet::deserialize_reader(reader)?,
                board1: Vec::<u8>::deserialize_reader(reader)?,
                board2: Vec::<u8>::deserialize_reader(reader)?,
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
    pub fn single(board: Vec<u8>) -> Self {
        Self::Single { board }
    }

    /// Construct a two-runout settlement input.
    #[must_use]
    pub fn twice(start: RitStartStreet, board1: Vec<u8>, board2: Vec<u8>) -> Self {
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

    #[must_use]
    const fn schedule(&self) -> SettlementRunoutSchedule {
        match self {
            Self::Single { .. } => SettlementRunoutSchedule::Single,
            Self::Twice { start, .. } => SettlementRunoutSchedule::Twice { start: *start },
        }
    }

    fn board1(&self) -> &[u8] {
        match self {
            Self::Single { board } => board,
            Self::Twice { board1, .. } => board1,
        }
    }

    fn board2(&self) -> &[u8] {
        match self {
            Self::Single { .. } => &[],
            Self::Twice { board2, .. } => board2,
        }
    }

    fn board(&self, runout_index: usize) -> &[u8] {
        if runout_index == 0 {
            self.board1()
        } else {
            self.board2()
        }
    }

    fn validate(&self) -> Result<(), SettlementError> {
        if self.board1().len() != 5 {
            return Err(SettlementError::invalid(format!(
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
                return Err(SettlementError::invalid(format!(
                    "settlement: board 2 must contain exactly 5 cards, got {}",
                    board2.len()
                )));
            }
            let shared = usize::from(start.shared_board_len());
            if board1[..shared] != board2[..shared] {
                return Err(SettlementError::invalid(
                    "settlement: runout boards disagree on their shared prefix",
                ));
            }
        }
        if self
            .board1()
            .iter()
            .chain(self.board2())
            .any(|card| *card >= 52)
        {
            return Err(SettlementError::invalid(
                "settlement: runout contains an invalid card",
            ));
        }

        let mut seen = HashSet::new();
        for card in self.board1() {
            if !seen.insert(*card) {
                return Err(SettlementError::invalid(
                    "settlement: duplicate card within board 1",
                ));
            }
        }
        if let Self::Twice { start, board2, .. } = self {
            let shared = usize::from(start.shared_board_len());
            for card in board2.iter().skip(shared) {
                if !seen.insert(*card) {
                    return Err(SettlementError::invalid(
                        "settlement: duplicate non-shared card across runouts",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// 已认证桌面快照（poker_l1 `TexasPokerTable` 的结算投影）。
///
/// poker_l1 集成层负责从 table 提取：`total_bets`（`Seat::total_bet`）、
/// `inactive`（folded 或已离手）、`all_in`、各座位的底牌索引（未入座/未
/// 入手的座位为空切片）、rake 配置与按钮位。
#[derive(Debug, Clone)]
pub struct TableSnapshot<'a> {
    /// 座位总数（≤ [`MAX_PLAYERS`](crate::MAX_PLAYERS)）。
    pub seat_count: usize,
    /// 按钮位（odd-chip 分配的时钟起点）。
    pub button: u8,
    /// 每座位本手总下注。
    pub total_bets: &'a [u64],
    /// 每座位是否已退出本手争夺（folded 或 left hand）。
    pub inactive: &'a [bool],
    /// 每座位是否 all-in。
    pub all_in: &'a [bool],
    /// 每座位暴露的底牌索引（参与争夺的座位必须恰好 2 张）。
    pub hole_cards: &'a [&'a [u8]],
    /// rake 模式（`RAKE_MODE_NONE` / `RAKE_MODE_PERCENTAGE`）。
    pub rake_mode: u8,
    /// rake 比例（bps）。
    pub rake_bps: u16,
    /// rake 单手封顶（硬上限，与 poker_l1 `TableRules` 语义一致）。
    pub rake_cap: u64,
}

/// Derive a deterministic settlement plan for one or two canonical boards.
///
/// # Errors
/// 全部 fail-closed：板形状/重复牌、座位越界、底牌暴露违规、side-pot 失败、
/// 贡献总额越界、rake 模式不支持、守恒破裂（末次 [`SettlementPlan::validate`]）。
pub fn derive_settlement_plan(
    snapshot: &TableSnapshot,
    boards: &SettlementBoards,
) -> Result<SettlementPlan, SettlementError> {
    boards.validate()?;
    if snapshot.seat_count > SETTLEMENT_SEATS {
        return Err(SettlementError::invalid(
            "settlement: table exceeds MAX_PLAYERS",
        ));
    }
    if snapshot.seat_count != snapshot.total_bets.len()
        || snapshot.seat_count != snapshot.inactive.len()
        || snapshot.seat_count != snapshot.all_in.len()
        || snapshot.seat_count != snapshot.hole_cards.len()
    {
        return Err(SettlementError::invalid(
            "settlement: snapshot vectors must all have seat_count entries",
        ));
    }
    if usize::from(snapshot.button) >= snapshot.seat_count.max(1) {
        return Err(SettlementError::invalid(
            "settlement: button is outside the table",
        ));
    }
    validate_exposed_cards(snapshot, boards)?;

    let bets: Vec<u64> = snapshot.total_bets.to_vec();
    let folded: Vec<bool> = snapshot.inactive.to_vec();
    let all_in: Vec<bool> = snapshot.all_in.to_vec();
    let result = side_pot::calculate_side_pots(&bets, &folded, &all_in).map_err(|error| {
        SettlementError::invalid(format!("settlement: side-pot calculation failed: {error}"))
    })?;
    if result.pots.len() > SETTLEMENT_SEATS {
        return Err(SettlementError::invalid(
            "settlement: side-pot count exceeds MAX_PLAYERS",
        ));
    }
    let gross_pot = result.total();
    if gross_pot > MAX_TOTAL_BET {
        return Err(SettlementError::invalid(format!(
            "settlement: contribution total {gross_pot} exceeds MAX_TOTAL_BET"
        )));
    }
    let contested_gross = result.pots.iter().try_fold(0u64, |sum, pot| {
        if pot.eligible_seats.count_ones() >= 2 {
            sum.checked_add(pot.amount).ok_or_else(|| {
                SettlementError::invalid("settlement: contested pot sum overflow")
            })
        } else {
            Ok(sum)
        }
    })?;
    let rake = compute_rake(snapshot, contested_gross)?;
    let pot_rakes = allocate_rake(&result.pots, rake, contested_gross)?;

    let mut plan = SettlementPlan {
        version: SETTLEMENT_PLAN_VERSION,
        schedule: boards.schedule(),
        gross_pot,
        rake,
        total_awards: 0,
        winner_mask: 0,
        awards: [0; SETTLEMENT_SEATS],
        pots: Vec::with_capacity(result.pots.len()),
    };

    for (pot_index, side_pot) in result.pots.iter().enumerate() {
        if side_pot.amount == 0 || side_pot.eligible_seats == 0 {
            return Err(SettlementError::invalid(format!(
                "settlement: pot {pot_index} has zero amount or no eligible player"
            )));
        }
        let pot_rake = pot_rakes[pot_index];
        let net_amount = side_pot.amount.checked_sub(pot_rake).ok_or_else(|| {
            SettlementError::invalid("settlement: pot rake exceeds gross amount")
        })?;
        let contested = side_pot.eligible_seats.count_ones() >= 2;
        let mut runouts = [RunoutPotPlan::inactive(), RunoutPotPlan::inactive()];
        if contested {
            let runout_amounts = split_across_runouts(net_amount, boards.runout_count());
            for runout_index in 0..usize::from(boards.runout_count()) {
                let (winner_mask, ranks) =
                    find_winners(snapshot, side_pot.eligible_seats, boards.board(runout_index))?;
                let awards = split_among_winners(
                    runout_amounts[runout_index],
                    winner_mask,
                    snapshot.button,
                    snapshot.seat_count,
                )?;
                runouts[runout_index] = RunoutPotPlan {
                    amount: runout_amounts[runout_index],
                    winner_mask,
                    ranks,
                    awards,
                };
                plan.winner_mask |= winner_mask;
                for (seat, amount) in awards.iter().enumerate() {
                    plan.awards[seat] = plan.awards[seat].checked_add(*amount).ok_or_else(
                        || SettlementError::invalid("settlement: aggregate award overflow"),
                    )?;
                }
            }
        } else {
            let winner_mask = side_pot.eligible_seats;
            let awards =
                split_among_winners(net_amount, winner_mask, snapshot.button, snapshot.seat_count)?;
            runouts[0] = RunoutPotPlan {
                amount: net_amount,
                winner_mask,
                ranks: [None; SETTLEMENT_SEATS],
                awards,
            };
            plan.winner_mask |= winner_mask;
            for (seat, amount) in awards.iter().enumerate() {
                plan.awards[seat] = plan
                    .awards[seat]
                    .checked_add(*amount)
                    .ok_or_else(|| SettlementError::invalid("settlement: aggregate award overflow"))?;
            }
        }
        plan.pots.push(SettlementPotPlan {
            pot_index: u8::try_from(pot_index)
                .map_err(|_| SettlementError::invalid("settlement: pot index exceeds u8"))?,
            gross_amount: side_pot.amount,
            rake: pot_rake,
            net_amount,
            eligible_mask: side_pot.eligible_seats,
            runouts,
        });
    }
    plan.total_awards = plan.awards.iter().try_fold(0u64, |sum, amount| {
        sum.checked_add(*amount)
            .ok_or_else(|| SettlementError::invalid("settlement: total award overflow"))
    })?;
    plan.validate(snapshot.seat_count)?;
    Ok(plan)
}

fn validate_exposed_cards(
    snapshot: &TableSnapshot,
    boards: &SettlementBoards,
) -> Result<(), SettlementError> {
    let mut seen_hole_cards = HashSet::new();
    for (seat_index, hand) in snapshot.hole_cards.iter().enumerate() {
        if snapshot.inactive[seat_index] {
            continue;
        }
        if hand.len() != 2 || hand.iter().any(|card| *card >= 52) {
            return Err(SettlementError::invalid(format!(
                "settlement: eligible seat {seat_index} must expose exactly two valid cards"
            )));
        }
        for card in hand.iter() {
            if !seen_hole_cards.insert(*card) {
                return Err(SettlementError::invalid(
                    "settlement: duplicate exposed hole card",
                ));
            }
        }
    }
    for card in boards.board1() {
        if seen_hole_cards.contains(card) {
            return Err(SettlementError::invalid(
                "settlement: board card duplicates an exposed hole card",
            ));
        }
    }
    if boards.runout_count() == 2 {
        for card in boards
            .board2()
            .iter()
            .skip(usize::from(boards.shared_board_len()))
        {
            if seen_hole_cards.contains(card) {
                return Err(SettlementError::invalid(
                    "settlement: second board duplicates an exposed hole card",
                ));
            }
        }
    }
    Ok(())
}

fn compute_rake(snapshot: &TableSnapshot, gross_pot: u64) -> Result<u64, SettlementError> {
    match snapshot.rake_mode {
        RAKE_MODE_NONE => Ok(0),
        RAKE_MODE_PERCENTAGE => {
            let raw = crate::payout::rake_for(gross_pot, u64::from(snapshot.rake_bps), 10_000);
            Ok(raw
                .min(snapshot.rake_cap)
                .min(gross_pot))
        }
        mode => Err(SettlementError::invalid(format!(
            "settlement: unsupported rake mode {mode}"
        ))),
    }
}

fn allocate_rake(pots: &[SidePot], rake: u64, gross_pot: u64) -> Result<Vec<u64>, SettlementError> {
    if rake == 0 {
        return Ok(vec![0; pots.len()]);
    }
    if gross_pot == 0 || pots.is_empty() {
        return Err(SettlementError::invalid(
            "settlement: cannot allocate rake over an empty pot set",
        ));
    }
    let mut allocations = Vec::with_capacity(pots.len());
    let mut allocated = 0u64;
    for pot in pots {
        let share = if pot.eligible_seats.count_ones() >= 2 {
            (u128::from(pot.amount) * u128::from(rake) / u128::from(gross_pot)) as u64
        } else {
            0
        };
        allocations.push(share);
        allocated = allocated.checked_add(share).ok_or_else(|| {
            SettlementError::invalid("settlement: rake allocation overflow")
        })?;
    }
    let mut remainder = rake.checked_sub(allocated).ok_or_else(|| {
        SettlementError::invalid("settlement: proportional rake exceeds total rake")
    })?;
    for (pot, allocation) in pots.iter().zip(&mut allocations) {
        if remainder == 0 {
            break;
        }
        if pot.eligible_seats.count_ones() < 2 {
            continue;
        }
        let available = pot.amount.checked_sub(*allocation).ok_or_else(|| {
            SettlementError::invalid("settlement: pot rake allocation exceeds pot")
        })?;
        let take = remainder.min(available);
        *allocation += take;
        remainder -= take;
    }
    if remainder != 0 {
        return Err(SettlementError::invalid(
            "settlement: rake remainder exceeds available pots",
        ));
    }
    Ok(allocations)
}

/// Runout 之间的确定性切分：第一块板拿 deterministic odd chip。
#[must_use]
pub fn split_across_runouts(amount: u64, runout_count: u8) -> [u64; MAX_RUNOUTS] {
    if runout_count == 1 {
        [amount, 0]
    } else {
        // The first board receives the deterministic odd chip.
        [amount / 2 + amount % 2, amount / 2]
    }
}

fn find_winners(
    snapshot: &TableSnapshot,
    eligible_mask: u16,
    board: &[u8],
) -> Result<(u16, [Option<HandRank>; SETTLEMENT_SEATS]), SettlementError> {
    let mut ranks = [None; SETTLEMENT_SEATS];
    let mut best_rank = None;
    let mut winner_mask = 0u16;
    for seat_index in 0..snapshot.seat_count {
        if !side_pot::is_eligible(eligible_mask, seat_index as u8) {
            continue;
        }
        let hand = snapshot.hole_cards[seat_index];
        if hand.len() != 2 {
            return Err(SettlementError::invalid(format!(
                "settlement: eligible seat {seat_index} has no complete hand"
            )));
        }
        let mut cards = Vec::with_capacity(7);
        cards.extend_from_slice(hand);
        cards.extend_from_slice(board);
        let rank = evaluate_best(&cards);
        ranks[seat_index] = Some(rank);
        match best_rank {
            None => {
                best_rank = Some(rank);
                winner_mask = 1u16 << seat_index;
            }
            Some(best) if rank > best => {
                best_rank = Some(rank);
                winner_mask = 1u16 << seat_index;
            }
            Some(best) if rank == best => winner_mask |= 1u16 << seat_index,
            Some(_) => {}
        }
    }
    if winner_mask == 0 {
        return Err(SettlementError::invalid(
            "settlement: side pot has no ranked eligible winner",
        ));
    }
    Ok((winner_mask, ranks))
}

/// 按按钮顺时针序把金额分给赢家（odd chip 给按钮后第一位）。
///
/// # Errors
/// 赢家掩码为空或越界 → [`SettlementError`]。
pub fn split_among_winners(
    amount: u64,
    winner_mask: u16,
    button: u8,
    seat_count: usize,
) -> Result<[u64; SETTLEMENT_SEATS], SettlementError> {
    let mut ordered = Vec::new();
    for offset in 1..=seat_count {
        let seat = (usize::from(button) + offset) % seat_count;
        if winner_mask & (1u16 << seat) != 0 {
            ordered.push(seat);
        }
    }
    if ordered.is_empty() {
        return Err(SettlementError::invalid(
            "settlement: winner mask is empty or outside the table",
        ));
    }
    let winner_count = u64::try_from(ordered.len())
        .map_err(|_| SettlementError::invalid("settlement: winner count exceeds u64"))?;
    let share = amount / winner_count;
    let remainder = amount % winner_count;
    let mut awards = [0u64; SETTLEMENT_SEATS];
    for (position, seat) in ordered.into_iter().enumerate() {
        awards[seat] = share + u64::from((position as u64) < remainder);
    }
    Ok(awards)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 规范牌索引：i → (suit = i/13, rank = i%13+2)。
    // ♠A=12 ♠K=11 ♠Q=10 ♠J=9 ♠10=8 ♠9=7；♥2=13 ♥3=14 ♥4=15 ♥5=16 ♥6=17
    // ♥Q=23 ♥K=24 ♥A=25；♦2=26 ♦3=27 ♦8=33 ♦9=34 ♦Q=36
    const SEAT_A: [u8; 2] = [12, 11]; // ♠A ♠K
    const SEAT_B: [u8; 2] = [10, 9]; // ♠Q ♠J
    const SEAT_C: [u8; 2] = [8, 7]; // ♠10 ♠9

    /// 三座位快照（下注 `bets`、手牌 `hands`、全 all-in、按钮 0）。
    /// 测试脚手架用 `Box::leak` 获取 'static 借用（仅测试路径）。
    fn snapshot_rake(
        bets: [u64; 3],
        hands: [[u8; 2]; 3],
        rake_bps: u16,
        rake_cap: u64,
    ) -> TableSnapshot<'static> {
        let holes: Vec<&'static [u8]> = hands
            .iter()
            .map(|h| Box::leak(h.to_vec().into_boxed_slice()) as &'static [u8])
            .collect();
        TableSnapshot {
            seat_count: 3,
            button: 0,
            total_bets: Box::leak(bets.to_vec().into_boxed_slice()),
            inactive: Box::leak(vec![false; 3].into_boxed_slice()),
            all_in: Box::leak(vec![true; 3].into_boxed_slice()),
            hole_cards: Box::leak(holes.into_boxed_slice()),
            rake_mode: if rake_bps == 0 {
                crate::RAKE_MODE_NONE
            } else {
                crate::RAKE_MODE_PERCENTAGE
            },
            rake_bps,
            rake_cap,
        }
    }

    fn snapshot(bets: [u64; 3], hands: [[u8; 2]; 3]) -> TableSnapshot<'static> {
        snapshot_rake(bets, hands, 500, 29)
    }

    #[test]
    fn multiway_side_pots_rake_and_odd_chips_are_canonical() {
        // 两块板都是 2..6 连牌 → 全员打 board，每个 eligible 层都平分，
        // 让按钮相对的 odd-chip 顺序在每层都可观测（镜像 poker_l1 同名测试）。
        let board1: Vec<u8> = vec![13, 14, 15, 16, 17]; // ♥2..♥6
        let board2: Vec<u8> = vec![26, 27, 28, 29, 30]; // ♦2..♦6
        let snap = snapshot([101, 202, 303], [SEAT_A, SEAT_B, SEAT_C]);
        let boards = SettlementBoards::twice(RitStartStreet::Preflop, board1, board2);
        let plan = derive_settlement_plan(&snap, &boards).unwrap();

        assert_eq!(plan.gross_pot, 606);
        // 最外 101 层 uncontested 不抽水，只有 505 抽水：5% = 25（cap 29 不触发）
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
        plan.validate(3).unwrap();
    }

    /// B9 口径锚点（含 uncalled 返还层的手）：座0 加注全下 200、座1 覆盖
    /// 全下 500、座2 弃牌（50 死钱）。分层 = [150 contested, 300 contested,
    /// 300 uncontested uncalled 返还]；rake 只对 contested 基数 450 计费，
    /// 与 appchain 费率关系 `rake.total == policy.rake_of(plan.rake_base())`
    /// 同口径（ABI v1.2.2）。
    #[test]
    fn uncalled_return_layer_is_excluded_from_rake_base() {
        let board: Vec<u8> = vec![10, 9, 8, 13, 26]; // ♠Q ♠J ♠10 ♥2 ♦2
        let holes: Vec<&'static [u8]> = vec![
            Box::leak(vec![0u8, 1].into_boxed_slice()),     // ♠2 ♠3
            Box::leak(vec![12u8, 11].into_boxed_slice()),   // ♠A ♠K
            Box::leak(Vec::<u8>::new().into_boxed_slice()), // 弃牌无手牌
        ];
        let snap = TableSnapshot {
            seat_count: 3,
            button: 0,
            total_bets: Box::leak(vec![200u64, 500, 50].into_boxed_slice()),
            inactive: Box::leak(vec![false, false, true].into_boxed_slice()),
            all_in: Box::leak(vec![true, true, false].into_boxed_slice()),
            hole_cards: Box::leak(holes.into_boxed_slice()),
            rake_mode: crate::RAKE_MODE_PERCENTAGE,
            rake_bps: 500,
            rake_cap: 1_000,
        };
        let boards = SettlementBoards::single(board);
        let plan = derive_settlement_plan(&snap, &boards).unwrap();

        assert_eq!(plan.gross_pot, 750);
        // 分层：450 contested（座0/1 争夺 + 座2 的 50 死钱并入主层）+
        // 300 uncontested（座1 的 uncalled 加注差额返还）。
        assert_eq!(plan.pots.len(), 2);
        assert!(plan.pots[0].is_contested());
        assert!(!plan.pots[1].is_contested());
        assert_eq!(plan.pots[0].gross_amount, 450);
        assert_eq!(plan.pots[1].gross_amount, 300);
        assert_eq!(plan.rake_base(), 450, "uncalled 返还层不进入计费基数");
        // 5% 只作用于 contested 基数 450 → 22（uncalled 层 rake 0）
        assert_eq!(plan.rake, 22);
        assert_eq!(plan.pots[0].rake, 22);
        assert_eq!(plan.pots[1].rake, 0);
        assert_eq!(plan.pots[1].runouts[0].awards[1], 300, "uncalled 全额返还");
        assert_eq!(plan.total_awards, 728);
        assert_eq!(
            crate::payout::rake_for(plan.rake_base(), 500, 10_000),
            plan.rake
        );
        plan.validate(3).unwrap();
    }

    #[test]
    fn two_runouts_split_each_side_pot_before_selecting_winners() {
        // runout0（♥Q ♥K ♥A ♥2 ♥3）seat0 两对独大；runout1（♦2 ♦3 ♦8 ♦9 ♦Q）
        // seat2 一对 9 独大。先分层切分、再逐 runout 选赢家。
        // runout0（♥2 ♦3 ♥Q ♣K ♥A）seat0 两对独大；runout1（♦2 ♠3 ♦9 ♥J ♦10）
        // seat2 两对（10+9）独大。先分层切分、再逐 runout 选赢家。
        let board1: Vec<u8> = vec![13, 27, 23, 37, 25];
        let board2: Vec<u8> = vec![26, 40, 33, 21, 22];
        let snap = snapshot_rake([100, 200, 300], [SEAT_A, SEAT_B, SEAT_C], 0, 0);
        let boards = SettlementBoards::twice(RitStartStreet::Preflop, board1, board2);
        let plan = derive_settlement_plan(&snap, &boards).unwrap();
        assert_eq!(
            plan.schedule,
            SettlementRunoutSchedule::Twice {
                start: RitStartStreet::Preflop
            }
        );
        assert_eq!(plan.total_awards, 600);
        // 主池层 300（三人各 100）先切半再分赢
        assert_eq!(plan.pots[0].runouts[0].amount, 150);
        assert_eq!(plan.pots[0].runouts[1].amount, 150);
        assert_eq!(plan.pots[0].runouts[0].winner_mask, 0b001);
        assert_eq!(plan.pots[0].runouts[1].winner_mask, 0b100);
        assert_eq!(plan.pots[1].runouts[0].winner_mask, 0b010);
        assert_eq!(plan.pots[1].runouts[1].winner_mask, 0b100);
        plan.validate(3).unwrap();
    }

    #[test]
    fn odd_chip_order_starts_clockwise_after_button() {
        let awards = split_among_winners(5, 0b111, 0, 3).unwrap();
        assert_eq!(awards[..3], [1, 2, 2]);
        // 按钮转动改变 odd chip 归属：button=1 时顺时针序为 [2, 0, 1]
        let awards = split_among_winners(5, 0b111, 1, 3).unwrap();
        assert_eq!(awards[..3], [2, 1, 2]);
    }

    #[test]
    fn rit_odd_chip_goes_to_first_board() {
        assert_eq!(split_across_runouts(101, 2), [51, 50], "第一块板拿 odd chip");
        assert_eq!(split_across_runouts(100, 2), [50, 50]);
        assert_eq!(split_across_runouts(7, 1), [7, 0]);
    }

    #[test]
    fn duplicate_cross_runout_card_rejected() {
        let snap = snapshot([100, 200, 300], [SEAT_A, SEAT_B, SEAT_C]);
        let board1: Vec<u8> = vec![13, 14, 23, 24, 25];
        // 非共享后缀与 board1 重复（♥3 再次出现）
        let board2: Vec<u8> = vec![13, 14, 23, 24, 14];
        let error = derive_settlement_plan(
            &snap,
            &SettlementBoards::twice(RitStartStreet::Flop, board1, board2),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate non-shared card"));
    }

    #[test]
    fn boards_deserialize_fail_closed() {
        let boards = SettlementBoards::single(vec![13, 14, 23, 24, 25]);
        let bytes = borsh::to_vec(&boards).unwrap();
        assert_eq!(borsh::from_slice::<SettlementBoards>(&bytes).unwrap(), boards);
        // 板张数错误
        let bad = SettlementBoards::single(vec![13, 14, 23, 24]);
        assert!(borsh::from_slice::<SettlementBoards>(&borsh::to_vec(&bad).unwrap()).is_err());
        // 非法牌
        let bad = SettlementBoards::single(vec![13, 14, 23, 24, 99]);
        assert!(borsh::from_slice::<SettlementBoards>(&borsh::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn ineligible_hole_cards_are_not_required() {
        // seat2 已退出本手争夺（folded），无需暴露底牌
        let holes: Vec<&'static [u8]> = vec![
            Box::leak(SEAT_A.to_vec().into_boxed_slice()) as &'static [u8],
            Box::leak(SEAT_B.to_vec().into_boxed_slice()) as &'static [u8],
            &[],
        ];
        let snap = TableSnapshot {
            seat_count: 3,
            button: 0,
            total_bets: Box::leak(vec![100, 200, 300].into_boxed_slice()),
            inactive: Box::leak(vec![false, false, true].into_boxed_slice()),
            all_in: Box::leak(vec![true, true, true].into_boxed_slice()),
            hole_cards: Box::leak(holes.into_boxed_slice()),
            rake_mode: crate::RAKE_MODE_NONE,
            rake_bps: 0,
            rake_cap: 0,
        };
        let boards = SettlementBoards::single(vec![13, 14, 23, 24, 25]);
        let plan = derive_settlement_plan(&snap, &boards).unwrap();
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.gross_pot, 600);
        plan.validate(3).unwrap();
    }
}
