//! Texas Poker 牌的数据结构（移植自 `texas_poker_move/sources/card.move`）。
//!
//! # 花色编码差异
//!
//! 注意：原 Move 合约存在两套花色编码：
//! - `Card`（table.move 用）：SPADES=0, HEARTS=1, DIAMONDS=2, CLUBS=3
//! - `PlayingCard`（Mental Poker 解密后映射用）：Club=0, Diamond=1, Heart=2, Spade=3
//!
//! 本模块同时提供两套常量，并在 `playing_card_to_card` 中处理映射。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

// ===== Card 花色常量（table.move 编码）=====

pub const SPADES: u8 = 0;
pub const HEARTS: u8 = 1;
pub const DIAMONDS: u8 = 2;
pub const CLUBS: u8 = 3;

// ===== Card 点数常量 =====

pub const TWO: u8 = 2;
pub const THREE: u8 = 3;
pub const FOUR: u8 = 4;
pub const FIVE: u8 = 5;
pub const SIX: u8 = 6;
pub const SEVEN: u8 = 7;
pub const EIGHT: u8 = 8;
pub const NINE: u8 = 9;
pub const TEN: u8 = 10;
pub const JACK: u8 = 11;
pub const QUEEN: u8 = 12;
pub const KING: u8 = 13;
pub const ACE: u8 = 14;

/// 主牌结构（table.move 编码：suit 0-3, rank 2-14）。
///
/// 与 Move `Card` struct 完全一致，使用 `copy + drop + store` 语义对应 Rust 的 `Copy + Clone`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Card {
    /// 花色：0=SPADES, 1=HEARTS, 2=DIAMONDS, 3=CLUBS。
    pub suit: u8,
    /// 点数：2..=14（2-10, 11=J, 12=Q, 13=K, 14=A）。
    pub rank: u8,
}

impl Card {
    /// 构造新牌。
    #[must_use]
    pub const fn new(suit: u8, rank: u8) -> Self {
        Self { suit, rank }
    }

    /// 校验牌的合法性。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.suit <= CLUBS && (TWO..=ACE).contains(&self.rank)
    }

    /// 转为 0..51 索引（suit * 13 + (rank - 2)）。
    #[must_use]
    pub fn to_index(&self) -> u8 {
        self.suit * 13 + (self.rank - TWO)
    }

    /// 从 0..51 索引构造牌。
    #[must_use]
    pub fn from_index(idx: u8) -> Self {
        debug_assert!(idx < 52);
        Self {
            suit: idx / 13,
            rank: (idx % 13) + TWO,
        }
    }

    /// 花色名称。
    #[must_use]
    pub fn suit_name(&self) -> &'static str {
        match self.suit {
            SPADES => "♠",
            HEARTS => "♥",
            DIAMONDS => "♦",
            CLUBS => "♣",
            _ => "?",
        }
    }

    /// 点数名称。
    #[must_use]
    pub fn rank_name(&self) -> &'static str {
        match self.rank {
            TWO => "2",
            THREE => "3",
            FOUR => "4",
            FIVE => "5",
            SIX => "6",
            SEVEN => "7",
            EIGHT => "8",
            NINE => "9",
            TEN => "10",
            JACK => "J",
            QUEEN => "Q",
            KING => "K",
            ACE => "A",
            _ => "?",
        }
    }

    /// 显示字符串（如 "A♠"）。
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}{}", self.rank_name(), self.suit_name())
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ===== PlayingCard（Mental Poker 解密后映射用）=====

/// Mental Poker 解密后的牌结构（花色编码与 `Card` 不同）。
///
/// 与 Move `PlayingCard` struct 一致：
/// - rank: 2-14
/// - suit: 0=Club, 1=Diamond, 2=Heart, 3=Spade
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct PlayingCard {
    pub rank: u8,
    pub suit: u8,
}

impl PlayingCard {
    /// 构造新 PlayingCard。
    #[must_use]
    pub const fn new(rank: u8, suit: u8) -> Self {
        Self { rank, suit }
    }

    /// 将 PlayingCard 转为 Card（处理花色编码差异）。
    ///
    /// 映射规则（与 table.move:254-262 一致）：
    /// - PlayingCard Club(0)    → Card CLUBS(3)
    /// - PlayingCard Diamond(1) → Card DIAMONDS(2)
    /// - PlayingCard Heart(2)   → Card HEARTS(1)
    /// - PlayingCard Spade(3)   → Card SPADES(0)
    #[must_use]
    pub fn to_card(&self) -> Card {
        let card_suit = match self.suit {
            0 => CLUBS,
            1 => DIAMONDS,
            2 => HEARTS,
            3 => SPADES,
            _ => CLUBS, // 不应发生
        };
        Card {
            suit: card_suit,
            rank: self.rank,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_valid() {
        assert!(Card::new(SPADES, ACE).is_valid());
        assert!(Card::new(CLUBS, TWO).is_valid());
        assert!(!Card::new(4, ACE).is_valid()); // 非法花色
        assert!(!Card::new(SPADES, 1).is_valid()); // 非法点数
        assert!(!Card::new(SPADES, 15).is_valid()); // 非法点数
    }

    #[test]
    fn test_card_index_roundtrip() {
        for idx in 0..52 {
            let card = Card::from_index(idx);
            assert_eq!(card.to_index(), idx);
            assert!(card.is_valid());
        }
    }

    #[test]
    fn test_card_display() {
        assert_eq!(Card::new(SPADES, ACE).display(), "A♠");
        assert_eq!(Card::new(HEARTS, KING).display(), "K♥");
        assert_eq!(Card::new(DIAMONDS, TEN).display(), "10♦");
        assert_eq!(Card::new(CLUBS, TWO).display(), "2♣");
    }

    #[test]
    fn test_playing_card_to_card_mapping() {
        // PlayingCard Club(0) → Card CLUBS(3)
        assert_eq!(PlayingCard::new(ACE, 0).to_card(), Card::new(CLUBS, ACE));
        // PlayingCard Diamond(1) → Card DIAMONDS(2)
        assert_eq!(
            PlayingCard::new(KING, 1).to_card(),
            Card::new(DIAMONDS, KING)
        );
        // PlayingCard Heart(2) → Card HEARTS(1)
        assert_eq!(
            PlayingCard::new(QUEEN, 2).to_card(),
            Card::new(HEARTS, QUEEN)
        );
        // PlayingCard Spade(3) → Card SPADES(0)
        assert_eq!(PlayingCard::new(JACK, 3).to_card(), Card::new(SPADES, JACK));
    }
}
