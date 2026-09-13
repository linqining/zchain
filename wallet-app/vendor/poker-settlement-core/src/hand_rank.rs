//! 手牌评估（7 选 5 最佳），从 poker_l1 `hand_evaluator.rs` 搬运。
//!
//! 牌用 u8 规范索引 `0..=51` 表示：`suit = idx / 13`、`rank = idx % 13 + 2`；
//! `52..=55` 是评估器瞬态占位（rank 视为 0），`>= 56` 一律 rank 0。与
//! poker_l1 `Card::to_index/rank/suit` 逐字一致。
//!
//! - [`HandRank`]：定长 `kickers: [u8; 5]`，borsh 编码 `category ‖ kickers`
//!   与 poker_l1 `hand_evaluator::HandRank` 逐字节一致；
//! - 直接实现 `Ord`（category 优先，kickers 字典序）；
//! - [`evaluate_best`] 枚举 C(n,5) 组合；<5 张先以瞬态占位牌补齐。

use borsh::{BorshDeserialize, BorshSerialize};

// ===== 牌型常量（与 poker_l1 hand_evaluator 一致） =====

/// 高牌。
pub const HIGH_CARD: u8 = 0;
/// 一对。
pub const ONE_PAIR: u8 = 1;
/// 两对。
pub const TWO_PAIR: u8 = 2;
/// 三条。
pub const THREE_OF_A_KIND: u8 = 3;
/// 顺子。
pub const STRAIGHT: u8 = 4;
/// 同花。
pub const FLUSH: u8 = 5;
/// 葫芦。
pub const FULL_HOUSE: u8 = 6;
/// 四条。
pub const FOUR_OF_A_KIND: u8 = 7;
/// 同花顺。
pub const STRAIGHT_FLUSH: u8 = 8;
/// 皇家同花顺。
pub const ROYAL_FLUSH: u8 = 9;

/// 牌索引 → 点数（`2..=14`；瞬态/占位索引为 0）。与 `Card::rank` 一致。
#[must_use]
pub const fn card_rank(index: u8) -> u8 {
    if index < 52 {
        (index % 13) + 2
    } else {
        0
    }
}

/// 牌索引 → 花色（`0..=3`；瞬态 `52..=55` 映射自身；非法为 `u8::MAX`）。
#[must_use]
pub const fn card_suit(index: u8) -> u8 {
    if index < 52 {
        index / 13
    } else if index < 56 {
        index - 52
    } else {
        u8::MAX
    }
}

/// 手牌评估结果。
///
/// - `category`: 牌型（0-9）
/// - `kickers`: tiebreaker 点数列表（定长 5，降序，不足位补 0）
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct HandRank {
    /// 牌型常量（[`HIGH_CARD`]..=[`ROYAL_FLUSH`]）。
    pub category: u8,
    /// 决胜点数（降序，不足补 0）。
    pub kickers: [u8; 5],
}

impl HandRank {
    /// 构造新 HandRank，kickers 不足 5 位用 0 填充。
    #[must_use]
    pub fn new(category: u8, kickers: &[u8]) -> Self {
        let mut k = [0u8; 5];
        for (i, &val) in kickers.iter().take(5).enumerate() {
            k[i] = val;
        }
        Self {
            category,
            kickers: k,
        }
    }

    /// 牌型名称。
    #[must_use]
    pub const fn category_name(&self) -> &'static str {
        match self.category {
            HIGH_CARD => "High Card",
            ONE_PAIR => "One Pair",
            TWO_PAIR => "Two Pair",
            THREE_OF_A_KIND => "Three of a Kind",
            STRAIGHT => "Straight",
            FLUSH => "Flush",
            FULL_HOUSE => "Full House",
            FOUR_OF_A_KIND => "Four of a Kind",
            STRAIGHT_FLUSH => "Straight Flush",
            ROYAL_FLUSH => "Royal Flush",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for HandRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.category_name())
    }
}

/// 直接字典序比较：category 优先，其次 kickers 降序逐位比较。
impl Ord for HandRank {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category
            .cmp(&other.category)
            .then_with(|| self.kickers.cmp(&other.kickers))
    }
}

impl PartialOrd for HandRank {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 从 n 张牌（5..=7）中选出最佳 5 张组合；<5 张时先 0 填充到 5 张再评估。
#[must_use]
pub fn evaluate_best(cards: &[u8]) -> HandRank {
    if cards.len() < 5 {
        // 不足 5 张：用 rank=0（不计入 counts）、花色递增的占位牌填充到 5 张。
        let mut padded = cards.to_vec();
        let mut next_suit = 0u8;
        while padded.len() < 5 {
            padded.push(52 + next_suit);
            next_suit = next_suit.wrapping_add(1);
        }
        return evaluate_five([padded[0], padded[1], padded[2], padded[3], padded[4]]);
    }
    let n = cards.len();
    let mut best = HandRank::new(HIGH_CARD, &[0; 5]);
    // 枚举所有 C(n,5) 组合。n==7 时为 21 组。
    for i in 0..n {
        for j in (i + 1)..n {
            for k in (j + 1)..n {
                for l in (k + 1)..n {
                    for m in (l + 1)..n {
                        let five = [cards[i], cards[j], cards[k], cards[l], cards[m]];
                        let rank = evaluate_five(five);
                        if rank > best {
                            best = rank;
                        }
                    }
                }
            }
        }
    }
    best
}

/// 评估 5 张牌（核心算法，poker_l1 `evaluate_five` 的逐字搬运）。
fn evaluate_five(cards: [u8; 5]) -> HandRank {
    let all = cards;

    // 1. counts[13]（索引 0=点数2, 12=点数14）
    let mut counts = [0u8; 13];
    for c in &all {
        let rank = card_rank(*c);
        if rank >= 2 && rank <= 14 {
            counts[usize::from(rank - 2)] += 1;
        }
    }

    // 2. 同花检测
    let is_flush = card_suit(cards[0]) == card_suit(cards[1])
        && card_suit(cards[1]) == card_suit(cards[2])
        && card_suit(cards[2]) == card_suit(cards[3])
        && card_suit(cards[3]) == card_suit(cards[4]);

    // 3. 点数降序排序
    let mut ranks = [
        card_rank(cards[0]),
        card_rank(cards[1]),
        card_rank(cards[2]),
        card_rank(cards[3]),
        card_rank(cards[4]),
    ];
    ranks.sort_unstable_by(|a, b| b.cmp(a));

    // 4. 顺子检测（返回顺子最高点数）
    let straight = straight_high(&ranks);

    // 5. 相同点数组（按 count 降序、rank 降序），末尾 (0,0) 占位到 5 个。
    let mut groups: Vec<(u8, u8)> = (0..13u8)
        .map(|i| (counts[usize::from(i)], i + 2))
        .filter(|(c, _)| *c > 0)
        .collect();
    groups.sort_unstable_by(|a, b| b.cmp(a));
    while groups.len() < 5 {
        groups.push((0, 0));
    }

    // 6. 优先级判断（从高到低）
    if is_flush {
        if let Some(high) = straight {
            if high == 14 {
                return HandRank::new(ROYAL_FLUSH, &[14]);
            }
            return HandRank::new(STRAIGHT_FLUSH, &[high]);
        }
    }

    if groups[0].0 == 4 {
        return HandRank::new(FOUR_OF_A_KIND, &[groups[0].1, groups[1].1]);
    }

    if groups[0].0 == 3 && groups[1].0 >= 2 {
        return HandRank::new(FULL_HOUSE, &[groups[0].1, groups[1].1]);
    }

    if is_flush {
        return HandRank::new(FLUSH, &ranks);
    }

    if let Some(high) = straight {
        return HandRank::new(STRAIGHT, &[high]);
    }

    if groups[0].0 == 3 {
        let k = [groups[0].1, groups[1].1, groups[2].1];
        return HandRank::new(THREE_OF_A_KIND, &k);
    }

    if groups[0].0 == 2 && groups[1].0 == 2 {
        let (hi, lo) = if groups[0].1 > groups[1].1 {
            (groups[0].1, groups[1].1)
        } else {
            (groups[1].1, groups[0].1)
        };
        return HandRank::new(TWO_PAIR, &[hi, lo, groups[2].1]);
    }

    if groups[0].0 == 2 {
        let k = [groups[0].1, groups[1].1, groups[2].1, groups[3].1];
        return HandRank::new(ONE_PAIR, &k);
    }

    HandRank::new(HIGH_CARD, &ranks)
}

/// 检测顺子，返回最高点数（A-2-3-4-5 wheel 返回 5）。非顺子返回 None。
fn straight_high(ranks_desc: &[u8; 5]) -> Option<u8> {
    if *ranks_desc == [14, 5, 4, 3, 2] {
        return Some(5);
    }
    let consecutive = (0..4).all(|i| ranks_desc[i] == ranks_desc[i + 1] + 1);
    if consecutive {
        Some(ranks_desc[0])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造规范牌索引（与 `Card::new(suit, rank)` 对齐）。
    const fn card(suit: u8, rank: u8) -> u8 {
        suit * 13 + (rank - 2)
    }

    #[test]
    fn card_index_views_match_poker_l1_card() {
        assert_eq!(card_rank(card(0, 14)), 14);
        assert_eq!(card_suit(card(3, 2)), 3);
        assert_eq!(card_rank(52), 0);
        assert_eq!(card_suit(53), 1);
        assert_eq!(card_rank(56), 0);
        assert_eq!(card_suit(56), u8::MAX);
    }

    #[test]
    fn royal_flush_and_wheel_straight() {
        let royal: Vec<u8> = (8..13).map(|i| card(0, i + 2)).collect();
        assert_eq!(evaluate_best(&royal).category, ROYAL_FLUSH);
        let wheel = [
            card(0, 14),
            card(1, 2),
            card(2, 3),
            card(3, 4),
            card(0, 5),
        ];
        let rank = evaluate_best(&wheel);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers[0], 5);
    }

    #[test]
    fn seven_card_selection_picks_best_five() {
        // 7 张：一对 K + 杂牌 → 一对，kickers 降序
        let cards = [
            card(0, 13),
            card(1, 13),
            card(2, 2),
            card(3, 5),
            card(0, 7),
            card(1, 9),
            card(2, 11),
        ];
        let rank = evaluate_best(&cards);
        assert_eq!(rank.category, ONE_PAIR);
        // ONE_PAIR 只取 pair + 前 3 个 kicker（k = [groups[0..4]]，补零）
        assert_eq!(rank.kickers, [13, 11, 9, 7, 0]);
    }

    #[test]
    fn flush_beats_straight_and_kickers_decide() {
        let flush = [
            card(0, 2),
            card(0, 5),
            card(0, 9),
            card(0, 11),
            card(0, 13),
        ];
        let straight = [
            card(1, 5),
            card(2, 6),
            card(3, 7),
            card(0, 8),
            card(1, 9),
        ];
        assert!(evaluate_best(&flush) > evaluate_best(&straight));
    }

    #[test]
    fn two_pair_tiebreakers_are_ordered() {
        let a = [
            card(0, 14),
            card(1, 14),
            card(2, 13),
            card(3, 13),
            card(0, 2),
        ];
        let b = [
            card(0, 13),
            card(1, 13),
            card(2, 2),
            card(3, 2),
            card(1, 14),
        ];
        let rank_a = evaluate_best(&a);
        let rank_b = evaluate_best(&b);
        assert_eq!(rank_a.category, TWO_PAIR);
        assert_eq!(rank_a.kickers[..3], [14, 13, 2]);
        assert!(rank_a > rank_b, "top-pair-first ordering must decide");
    }
}
