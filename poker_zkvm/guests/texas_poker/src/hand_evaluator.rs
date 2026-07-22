//! Texas Poker 手牌评估（移植自 `texas_poker_move/sources/hand_evaluator.move`）。
//!
//! 实现 7 选 5 最佳手牌评估：枚举 C(7,5)=21 种组合，取最大 HandRank。
//!
//! # 牌型常量
//!
//! 0=HIGH_CARD, 1=ONE_PAIR, 2=TWO_PAIR, 3=THREE_OF_A_KIND, 4=STRAIGHT,
//! 5=FLUSH, 6=FULL_HOUSE, 7=FOUR_OF_A_KIND, 8=STRAIGHT_FLUSH, 9=ROYAL_FLUSH

use alloc::vec::Vec;

use super::card::Card;

// ===== 牌型常量 =====

pub const HIGH_CARD: u8 = 0;
pub const ONE_PAIR: u8 = 1;
pub const TWO_PAIR: u8 = 2;
pub const THREE_OF_A_KIND: u8 = 3;
pub const STRAIGHT: u8 = 4;
pub const FLUSH: u8 = 5;
pub const FULL_HOUSE: u8 = 6;
pub const FOUR_OF_A_KIND: u8 = 7;
pub const STRAIGHT_FLUSH: u8 = 8;
pub const ROYAL_FLUSH: u8 = 9;

/// 手牌评估结果。
///
/// - `category`: 牌型（0-9）
/// - `kickers`: tiebreaker 点数列表（长度 1-5，降序）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HandRank {
    pub category: u8,
    pub kickers: Vec<u8>,
}

impl HandRank {
    /// 构造新 HandRank。
    #[must_use]
    pub fn new(category: u8, kickers: Vec<u8>) -> Self {
        Self { category, kickers }
    }

    /// 序列化为 u64（category 占 bits 0-7，kickers[i] 占 bits 8*(i+1)~+8）。
    #[must_use]
    pub fn to_u64(&self) -> u64 {
        let mut result = u64::from(self.category);
        for (i, &k) in self.kickers.iter().enumerate().take(5) {
            result |= u64::from(k) << (8 * (i + 1));
        }
        result
    }

    /// 牌型名称。
    #[must_use]
    pub fn category_name(&self) -> &'static str {
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

impl core::fmt::Display for HandRank {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.category_name())
    }
}

impl Ord for HandRank {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        compare(self, other).cmp(&1)
    }
}

impl PartialOrd for HandRank {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 比较两个 HandRank。
///
/// 返回值（与 Move `compare` 一致）：
/// - 0: a < b
/// - 1: a == b
/// - 2: a > b
#[must_use]
pub fn compare(a: &HandRank, b: &HandRank) -> u8 {
    if a.category != b.category {
        return if a.category > b.category { 2 } else { 0 };
    }
    compare_kickers(&a.kickers, &b.kickers)
}

/// 比较 kickers（按位降序比较）。
///
/// 当长度不同时（如初始 `best_rank` kickers 为空）：
/// - 空侧视为"最低"（初始哨兵）
/// - 同长度时按位比较
fn compare_kickers(a: &[u8], b: &[u8]) -> u8 {
    // 处理空 kickers（初始哨兵场景）
    if a.is_empty() && b.is_empty() {
        return 1; // 相等
    }
    if a.is_empty() {
        return 0; // a 为初始哨兵，b 更大
    }
    if b.is_empty() {
        return 2; // b 为初始哨兵，a 更大
    }
    // 同长度：按位降序比较
    debug_assert_eq!(
        a.len(),
        b.len(),
        "kickers 长度必须相同（同一 category，非初始哨兵）"
    );
    for i in 0..a.len() {
        if a[i] != b[i] {
            return if a[i] > b[i] { 2 } else { 0 };
        }
    }
    1 // 相等
}

/// 从 7 张牌中选出最佳 5 张组合。
///
/// 镜像 `hand_evaluator.move:92-120`：
/// 1. 断言 cards 长度为 7 且无重复
/// 2. 枚举 C(7,5)=21 种组合
/// 3. 对每种组合调用 `evaluate_five`，取最大
#[must_use]
pub fn best_hand(cards: &[Card]) -> HandRank {
    assert_eq!(
        cards.len(),
        7,
        "best_hand 要求 7 张牌，得到 {}",
        cards.len()
    );
    assert_no_duplicates(cards);

    let mut best = HandRank::new(HIGH_CARD, vec![]);
    // 枚举 C(7,5)=21 种组合
    let indices = [
        [0, 1, 2, 3, 4],
        [0, 1, 2, 3, 5],
        [0, 1, 2, 3, 6],
        [0, 1, 2, 4, 5],
        [0, 1, 2, 4, 6],
        [0, 1, 2, 5, 6],
        [0, 1, 3, 4, 5],
        [0, 1, 3, 4, 6],
        [0, 1, 3, 5, 6],
        [0, 1, 4, 5, 6],
        [0, 2, 3, 4, 5],
        [0, 2, 3, 4, 6],
        [0, 2, 3, 5, 6],
        [0, 2, 4, 5, 6],
        [0, 3, 4, 5, 6],
        [1, 2, 3, 4, 5],
        [1, 2, 3, 4, 6],
        [1, 2, 3, 5, 6],
        [1, 2, 4, 5, 6],
        [1, 3, 4, 5, 6],
        [2, 3, 4, 5, 6],
    ];
    for idx in &indices {
        let five = [
            cards[idx[0]],
            cards[idx[1]],
            cards[idx[2]],
            cards[idx[3]],
            cards[idx[4]],
        ];
        let rank = evaluate_five(&five);
        if compare(&rank, &best) == 2 {
            best = rank;
        }
    }
    best
}

/// 校验无重复牌。
///
/// 使用 O(n²) 双重循环替代 `std::collections::HashSet`（no_std 兼容，
/// 输入固定 7 张牌，性能可忽略）。
fn assert_no_duplicates(cards: &[Card]) {
    for i in 0..cards.len() {
        for j in (i + 1)..cards.len() {
            assert_ne!(
                (cards[i].suit, cards[i].rank),
                (cards[j].suit, cards[j].rank),
                "牌组中存在重复牌"
            );
        }
    }
}

/// 评估 5 张牌。
fn evaluate_five(cards: &[Card; 5]) -> HandRank {
    evaluate_five_impl(cards[0], cards[1], cards[2], cards[3], cards[4])
}

/// 评估 5 张牌（核心算法，镜像 `hand_evaluator.move:159-238`）。
fn evaluate_five_impl(c0: Card, c1: Card, c2: Card, c3: Card, c4: Card) -> HandRank {
    let cards = [c0, c1, c2, c3, c4];

    // 1. 构建 13 长度的 counts 数组（索引 0=点数2, 12=点数14）
    let mut counts = [0u8; 13];
    for c in &cards {
        counts[(c.rank - 2) as usize] += 1;
    }

    // 2. 同花检测：5 张花色全相同
    let is_flush = c0.suit == c1.suit
        && c1.suit == c2.suit
        && c2.suit == c3.suit
        && c3.suit == c4.suit;

    // 3. 排序点数降序
    let mut ranks: Vec<u8> = cards.iter().map(|c| c.rank).collect();
    ranks.sort_unstable_by(|a, b| b.cmp(a)); // 降序

    // 4. 检测顺子（含 A-2-3-4-5 wheel）
    let is_straight = is_straight_high(&ranks) || is_straight_wheel(&ranks);
    let straight_high = if is_straight_wheel(&ranks) {
        5 // A-2-3-4-5 的 high 是 5
    } else {
        ranks[0]
    };

    // 5. 收集相同点数的组（按 count 降序、rank 降序）
    let mut groups: Vec<(u8, u8)> = (0..13u8)
        .map(|i| (counts[i as usize], i + 2))
        .filter(|(c, _)| *c > 0)
        .collect();
    groups.sort_unstable_by(|a, b| b.cmp(a)); // (count, rank) 降序

    // 6. 优先级判断（从高到低）

    // 同花顺 / 皇家同花顺
    if is_flush && is_straight {
        if straight_high == 14 {
            return HandRank::new(ROYAL_FLUSH, vec![14]);
        }
        return HandRank::new(STRAIGHT_FLUSH, vec![straight_high]);
    }

    // 四条
    if groups[0].0 == 4 {
        let four_rank = groups[0].1;
        let kicker = groups[1].1;
        return HandRank::new(FOUR_OF_A_KIND, vec![four_rank, kicker]);
    }

    // 葫芦
    if groups[0].0 == 3 && groups[1].0 >= 2 {
        let three_rank = groups[0].1;
        let pair_rank = groups[1].1;
        return HandRank::new(FULL_HOUSE, vec![three_rank, pair_rank]);
    }

    // 同花
    if is_flush {
        return HandRank::new(FLUSH, ranks.clone());
    }

    // 顺子
    if is_straight {
        return HandRank::new(STRAIGHT, vec![straight_high]);
    }

    // 三条
    if groups[0].0 == 3 {
        let three_rank = groups[0].1;
        let mut kickers: Vec<u8> = groups[1..].iter().map(|(_, r)| *r).collect();
        kickers.sort_unstable_by(|a, b| b.cmp(a));
        return HandRank::new(THREE_OF_A_KIND, {
            let mut k = vec![three_rank];
            k.extend(kickers.into_iter().take(2));
            k
        });
    }

    // 两对
    if groups[0].0 == 2 && groups[1].0 == 2 {
        let mut pairs: Vec<u8> = vec![groups[0].1, groups[1].1];
        pairs.sort_unstable_by(|a, b| b.cmp(a));
        let kicker = groups[2].1;
        return HandRank::new(TWO_PAIR, {
            let mut k = pairs;
            k.push(kicker);
            k
        });
    }

    // 一对
    if groups[0].0 == 2 {
        let pair_rank = groups[0].1;
        let mut kickers: Vec<u8> = groups[1..].iter().map(|(_, r)| *r).collect();
        kickers.sort_unstable_by(|a, b| b.cmp(a));
        return HandRank::new(ONE_PAIR, {
            let mut k = vec![pair_rank];
            k.extend(kickers.into_iter().take(3));
            k
        });
    }

    // 高牌
    HandRank::new(HIGH_CARD, ranks.clone())
}

/// 检测普通顺子（不含 wheel）。
fn is_straight_high(ranks_desc: &[u8]) -> bool {
    // ranks_desc 已降序，检查 5 张连续递减
    for i in 0..4 {
        if ranks_desc[i] - 1 != ranks_desc[i + 1] {
            return false;
        }
    }
    true
}

/// 检测 A-2-3-4-5 wheel 顺子。
///
/// 排序后为 [14, 5, 4, 3, 2]。
fn is_straight_wheel(ranks_desc: &[u8]) -> bool {
    ranks_desc == [14, 5, 4, 3, 2]
}

/// 从多个玩家中找出赢家（返回 seat_index 列表，平局多人）。
///
/// `hands`: 每个 (seat_index, 7张牌) 对。
#[must_use]
pub fn find_winners(hands: &[(u8, Vec<Card>)]) -> Vec<u8> {
    assert!(!hands.is_empty(), "find_winners 要求至少 1 个玩家");
    let mut best_rank = HandRank::new(HIGH_CARD, vec![]);
    let mut best_seats: Vec<u8> = Vec::new();

    for (seat, cards) in hands {
        let rank = best_hand(cards);
        match compare(&rank, &best_rank) {
            2 => {
                // 新的最大
                best_rank = rank;
                best_seats.clear();
                best_seats.push(*seat);
            }
            1 => {
                // 平局
                best_seats.push(*seat);
            }
            // 0 = 更小，忽略；其他值（防御性）也忽略
            _ => {}
        }
    }
    best_seats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::*;

    fn card(suit: u8, rank: u8) -> Card {
        Card::new(suit, rank)
    }

    fn make_seven(cards: [Card; 7]) -> Vec<Card> {
        cards.to_vec()
    }

    #[test]
    fn test_royal_flush() {
        // A♠ K♠ Q♠ J♠ 10♠ + 2 张杂牌
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, QUEEN),
            card(SPADES, JACK),
            card(SPADES, TEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, ROYAL_FLUSH);
        assert_eq!(rank.kickers, vec![14]);
    }

    #[test]
    fn test_straight_flush_wheel() {
        // A-2-3-4-5 同花
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, TWO),
            card(SPADES, THREE),
            card(SPADES, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, STRAIGHT_FLUSH);
        assert_eq!(rank.kickers, vec![5]); // wheel high = 5
    }

    #[test]
    fn test_four_of_a_kind() {
        let seven = make_seven([
            card(SPADES, KING),
            card(HEARTS, KING),
            card(DIAMONDS, KING),
            card(CLUBS, KING),
            card(SPADES, TWO),
            card(HEARTS, THREE),
            card(CLUBS, FOUR),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, FOUR_OF_A_KIND);
        assert_eq!(rank.kickers, vec![13, 4]);
    }

    #[test]
    fn test_full_house() {
        let seven = make_seven([
            card(SPADES, QUEEN),
            card(HEARTS, QUEEN),
            card(DIAMONDS, QUEEN),
            card(CLUBS, JACK),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, FULL_HOUSE);
        assert_eq!(rank.kickers, vec![12, 11]);
    }

    #[test]
    fn test_flush() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, JACK),
            card(SPADES, NINE),
            card(SPADES, SEVEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, FLUSH);
    }

    #[test]
    fn test_straight() {
        let seven = make_seven([
            card(SPADES, TEN),
            card(HEARTS, NINE),
            card(DIAMONDS, EIGHT),
            card(CLUBS, SEVEN),
            card(SPADES, SIX),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, vec![10]);
    }

    #[test]
    fn test_straight_wheel() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(DIAMONDS, THREE),
            card(CLUBS, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, vec![5]);
    }

    #[test]
    fn test_three_of_a_kind() {
        let seven = make_seven([
            card(SPADES, SEVEN),
            card(HEARTS, SEVEN),
            card(DIAMONDS, SEVEN),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, THREE_OF_A_KIND);
        assert_eq!(rank.kickers, vec![7, 13, 12]);
    }

    #[test]
    fn test_two_pair() {
        let seven = make_seven([
            card(SPADES, JACK),
            card(HEARTS, JACK),
            card(DIAMONDS, FOUR),
            card(CLUBS, FOUR),
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, TWO_PAIR);
        assert_eq!(rank.kickers, vec![11, 4, 14]);
    }

    #[test]
    fn test_one_pair() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, ACE),
            card(DIAMONDS, KING),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, ONE_PAIR);
        assert_eq!(rank.kickers, vec![14, 13, 12, 11]);
    }

    #[test]
    fn test_high_card() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, JACK),
            card(CLUBS, NINE),
            card(SPADES, FIVE),
            card(HEARTS, THREE),
            card(CLUBS, TWO),
        ]);
        let rank = best_hand(&seven);
        assert_eq!(rank.category, HIGH_CARD);
    }

    #[test]
    fn test_compare() {
        let pair = HandRank::new(ONE_PAIR, vec![14, 13, 12, 11]);
        let two_pair = HandRank::new(TWO_PAIR, vec![11, 4, 14]);

        assert_eq!(compare(&two_pair, &pair), 2); // two_pair > pair
        assert_eq!(compare(&pair, &two_pair), 0); // pair < two_pair
        assert_eq!(compare(&pair, &pair), 1); // 相等

        // 同 category 比较 kickers
        let pair_high = HandRank::new(ONE_PAIR, vec![14, 13, 12, 11]);
        let pair_low = HandRank::new(ONE_PAIR, vec![13, 12, 11, 10]);
        assert_eq!(compare(&pair_high, &pair_low), 2);
    }

    #[test]
    fn test_find_winners_single() {
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(SPADES, KING),
                card(SPADES, QUEEN),
                card(SPADES, JACK),
                card(SPADES, TEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(HEARTS, TWO),
                card(HEARTS, THREE),
                card(HEARTS, FOUR),
                card(HEARTS, FIVE),
                card(HEARTS, SIX),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners, vec![0]); // 皇家同花顺 > 同花顺
    }

    #[test]
    fn test_find_winners_tie() {
        // 两个玩家都用公共牌组成相同牌型
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(HEARTS, ACE),
                card(DIAMONDS, KING),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(DIAMONDS, ACE),
                card(CLUBS, ACE),
                card(SPADES, KING),
                card(HEARTS, KING),
                card(DIAMONDS, QUEEN),
                card(CLUBS, TWO),
                card(SPADES, THREE),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners.len(), 2); // 平局
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
    }

    #[test]
    fn test_to_u64() {
        let rank = HandRank::new(ONE_PAIR, vec![14, 13, 12, 11]);
        let u = rank.to_u64();
        assert_eq!(u & 0xFF, 1); // category
        assert_eq!((u >> 8) & 0xFF, 14); // kicker[0]
        assert_eq!((u >> 16) & 0xFF, 13); // kicker[1]
    }
}
