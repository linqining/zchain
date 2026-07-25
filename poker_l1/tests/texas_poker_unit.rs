//! Texas Poker 模块单元测试 — 覆盖核心游戏逻辑。

use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::texas_poker::{
    betting::{BettingRound, BettingError},
    card::{Card, PlayingCard, SPADES, HEARTS, DIAMONDS, CLUBS, TWO, ACE},
    constants::{
        ACTION_CHECK, ACTION_CALL, ACTION_FOLD, ACTION_RAISE,
        ROUND_WAITING, ROUND_PREFLOP, ROUND_FLOP, ROUND_TURN, ROUND_RIVER, ROUND_SHOWDOWN,
        MAX_PLAYERS, MIN_PLAYERS_TO_START, MAX_TOTAL_BET,
    },
    hand_evaluator::{
        HandRank, find_winners,
        HIGH_CARD, ONE_PAIR, TWO_PAIR, THREE_OF_A_KIND, STRAIGHT, FLUSH,
        FULL_HOUSE, FOUR_OF_A_KIND, STRAIGHT_FLUSH, ROYAL_FLUSH,
    },
    side_pot::{SidePot, SidePotResult, calculate_side_pots, SidePotError},
    types::{Seat, SeatStatus},
};

// ===========================================================================
// 1. card.rs — 扑克牌类型与操作
// ===========================================================================

#[test]
fn test_card_from_index_standard_range() {
    for i in 0..52 {
        let card = Card::from_index(i);
        assert_eq!(card.to_index(), i, "Card::from_index({i}) roundtrip failed");
    }
}

#[test]
fn test_card_from_index_boundary_zero() {
    let card = Card::from_index(0);
    assert_eq!(card.suit, SPADES);
    assert_eq!(card.rank, TWO);
    assert_eq!(card.to_index(), 0);
}

#[test]
fn test_card_from_index_boundary_max() {
    let card = Card::from_index(51);
    assert_eq!(card.suit, CLUBS);
    assert_eq!(card.rank, ACE);
    assert_eq!(card.to_index(), 51);
}

#[test]
fn test_card_is_valid() {
    assert!(Card::new(SPADES, ACE).is_valid());
    assert!(Card::new(CLUBS, TWO).is_valid());
    assert!(!Card::new(4, ACE).is_valid()); // 非法花色
    assert!(!Card::new(SPADES, 1).is_valid()); // 非法点数
    assert!(!Card::new(SPADES, 15).is_valid()); // 非法点数
}

#[test]
fn test_card_display_format() {
    assert_eq!(Card::new(SPADES, TWO).display(), "2♠");
    assert_eq!(Card::new(SPADES, ACE).display(), "A♠");
    assert_eq!(Card::new(DIAMONDS, TWO).display(), "2♦");
    assert_eq!(Card::new(HEARTS, ACE).display(), "A♥");
    assert_eq!(Card::new(CLUBS, TWO).display(), "2♣");
}

#[test]
fn test_card_borsh_roundtrip() {
    for i in 0..52 {
        let card = Card::from_index(i);
        let bytes = borsh::to_vec(&card).unwrap();
        let decoded = borsh::from_slice(&bytes).unwrap();
        assert_eq!(card, decoded);
    }
}

#[test]
fn test_playing_card_to_card_mapping() {
    // PlayingCard Club(0) → Card CLUBS(3)
    assert_eq!(PlayingCard::new(ACE, 0).to_card(), Card::new(CLUBS, ACE));
    // PlayingCard Diamond(1) → Card DIAMONDS(2)
    assert_eq!(PlayingCard::new(ACE, 1).to_card(), Card::new(DIAMONDS, ACE));
    // PlayingCard Heart(2) → Card HEARTS(1)
    assert_eq!(PlayingCard::new(ACE, 2).to_card(), Card::new(HEARTS, ACE));
    // PlayingCard Spade(3) → Card SPADES(0)
    assert_eq!(PlayingCard::new(ACE, 3).to_card(), Card::new(SPADES, ACE));
}

#[test]
fn test_playing_card_borsh_roundtrip() {
    let pc = PlayingCard::new(ACE, SPADES);
    let bytes = borsh::to_vec(&pc).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(pc, decoded);
}

// ===========================================================================
// 2. constants.rs — 常量与位掩码
// ===========================================================================

#[test]
fn test_constants_player_limits() {
    assert!(MIN_PLAYERS_TO_START >= 2);
    assert!(MAX_PLAYERS >= MIN_PLAYERS_TO_START);
}

#[test]
fn test_constants_action_masks_unique() {
    assert!((ACTION_FOLD & ACTION_CHECK) == 0);
    assert!((ACTION_FOLD & ACTION_CALL) == 0);
    assert!((ACTION_FOLD & ACTION_RAISE) == 0);
    assert!((ACTION_CHECK & ACTION_CALL) == 0);
    assert!((ACTION_CHECK & ACTION_RAISE) == 0);
    assert!((ACTION_CALL & ACTION_RAISE) == 0);
}

#[test]
fn test_constants_round_state_order() {
    assert!(ROUND_WAITING < ROUND_PREFLOP);
    assert!(ROUND_PREFLOP < ROUND_FLOP);
    assert!(ROUND_FLOP < ROUND_TURN);
    assert!(ROUND_TURN < ROUND_RIVER);
    assert!(ROUND_RIVER < ROUND_SHOWDOWN);
}

// ===========================================================================
// 3. types.rs — 核心类型
// ===========================================================================

#[test]
fn test_seat_status_default() {
    let status = SeatStatus::default();
    assert_eq!(status, SeatStatus::Empty);
}

// ===========================================================================
// 4. betting.rs — 下注轮状态与规则
// ===========================================================================

#[test]
fn test_betting_round_new_preflop() {
    let round = BettingRound::new(10, 10); // big_blind=10, current_bet=10
    assert_eq!(round.current_bet, 10);
    assert_eq!(round.min_raise, 10);
}

#[test]
fn test_betting_round_new_postflop() {
    let round = BettingRound::new(10, 0); // big_blind=10, current_bet=0
    assert_eq!(round.current_bet, 0);
    assert_eq!(round.min_raise, 10);
}

#[test]
fn test_betting_round_chips_to_call() {
    let round = BettingRound::new(10, 10);
    assert_eq!(round.chips_to_call(0), 10);
    assert_eq!(round.chips_to_call(5), 5);
    assert_eq!(round.chips_to_call(10), 0);
    assert_eq!(round.chips_to_call(20), 0);
}

#[test]
fn test_betting_round_can_check() {
    let round = BettingRound::new(10, 10);
    assert!(!round.can_check(0));
    assert!(round.can_check(10));
}

#[test]
fn test_betting_round_can_call() {
    let round = BettingRound::new(10, 10);
    assert!(round.can_call(0, 100)); // 需要跟注且有筹码
    assert!(!round.can_call(10, 100)); // 无需跟注
    assert!(!round.can_call(0, 0)); // 无筹码
}

#[test]
fn test_betting_round_can_raise() {
    let round = BettingRound::new(10, 10);
    assert!(round.can_raise(0, 100)); // stack > chips_to_call
    assert!(round.can_raise(0, 11)); // 刚好能加注
    assert!(!round.can_raise(0, 10)); // 只能 all-in call
    assert!(!round.can_raise(10, 0)); // 无筹码
}

#[test]
fn test_betting_round_available_actions() {
    let round = BettingRound::new(10, 10);
    
    // 需要跟注，有足够筹码
    let actions = round.available_actions(0, 100);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CALL != 0);
    assert!(actions & ACTION_RAISE != 0);
    assert!(actions & ACTION_CHECK == 0);
    
    // 已跟注，有筹码
    let actions = round.available_actions(10, 100);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CHECK != 0);
    assert!(actions & ACTION_RAISE != 0);
    assert!(actions & ACTION_CALL == 0);
    
    // 需要跟注，但筹码不够加注
    let actions = round.available_actions(0, 10);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CALL != 0);
    assert!(actions & ACTION_RAISE == 0);
    assert!(actions & ACTION_CHECK == 0);
}

#[test]
fn test_betting_round_process_call() {
    let round = BettingRound::new(10, 10);
    assert_eq!(round.process_call(0, 100), 10); // 正常跟注
    assert_eq!(round.process_call(0, 5), 5); // all-in 跟注
    assert_eq!(round.process_call(10, 100), 0); // 无需跟注
}

#[test]
fn test_betting_round_process_raise_normal() {
    let mut round = BettingRound::new(10, 10);
    let needed = round.process_raise(30, 0, 100).unwrap();
    assert_eq!(needed, 30);
    assert_eq!(round.current_bet, 30);
    assert_eq!(round.min_raise, 20); // 30-10=20
}

#[test]
fn test_betting_round_process_raise_all_in() {
    let mut round = BettingRound::new(10, 10);
    let needed = round.process_raise(30, 0, 30).unwrap();
    assert_eq!(needed, 30);
    assert_eq!(round.min_raise, 20);
}

#[test]
fn test_betting_round_process_raise_short_all_in() {
    let mut round = BettingRound::new(10, 10);
    round.process_raise(30, 0, 100).unwrap(); // min_raise = 20
    // 短 all-in：raise_amount=10 < min_raise=20
    let needed = round.process_raise(40, 0, 40).unwrap();
    assert_eq!(needed, 40);
    assert_eq!(round.min_raise, 20); // 不更新
    assert_eq!(round.current_bet, 40);
}

#[test]
fn test_betting_round_process_raise_below_min_rejected() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(15, 0, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_raise_below_current_bet_rejected() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(5, 0, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_raise_insufficient_stack() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(100, 0, 50),
        Err(BettingError::CannotRaise)
    ));
}

#[test]
fn test_betting_round_borsh_roundtrip() {
    let round = BettingRound::new(10, 10);
    let bytes = borsh::to_vec(&round).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(round, decoded);
}

// ===========================================================================
// 5. hand_evaluator.rs — 手牌评估
// ===========================================================================

fn make_cards(ints: &[u8]) -> Vec<Card> {
    ints.iter().map(|&i| Card::from_index(i)).collect()
}

#[test]
fn test_hand_rank_category_name() {
    let hr = HandRank::new(HIGH_CARD, &[]);
    assert_eq!(hr.category_name(), "High Card");
    let hr = HandRank::new(ONE_PAIR, &[]);
    assert_eq!(hr.category_name(), "One Pair");
    let hr = HandRank::new(TWO_PAIR, &[]);
    assert_eq!(hr.category_name(), "Two Pair");
    let hr = HandRank::new(THREE_OF_A_KIND, &[]);
    assert_eq!(hr.category_name(), "Three of a Kind");
    let hr = HandRank::new(STRAIGHT, &[]);
    assert_eq!(hr.category_name(), "Straight");
    let hr = HandRank::new(FLUSH, &[]);
    assert_eq!(hr.category_name(), "Flush");
    let hr = HandRank::new(FULL_HOUSE, &[]);
    assert_eq!(hr.category_name(), "Full House");
    let hr = HandRank::new(FOUR_OF_A_KIND, &[]);
    assert_eq!(hr.category_name(), "Four of a Kind");
    let hr = HandRank::new(STRAIGHT_FLUSH, &[]);
    assert_eq!(hr.category_name(), "Straight Flush");
    let hr = HandRank::new(ROYAL_FLUSH, &[]);
    assert_eq!(hr.category_name(), "Royal Flush");
}

#[test]
fn test_hand_rank_display() {
    let hr = HandRank::new(ROYAL_FLUSH, &[]);
    assert_eq!(format!("{}", hr), "Royal Flush");
}

#[test]
fn test_hand_rank_ordering() {
    let high_card = HandRank::new(HIGH_CARD, &[ACE]);
    let one_pair = HandRank::new(ONE_PAIR, &[ACE]);
    let two_pair = HandRank::new(TWO_PAIR, &[ACE]);
    let three_of_a_kind = HandRank::new(THREE_OF_A_KIND, &[ACE]);
    let straight = HandRank::new(STRAIGHT, &[ACE]);
    let flush = HandRank::new(FLUSH, &[ACE]);
    let full_house = HandRank::new(FULL_HOUSE, &[ACE]);
    let four_of_a_kind = HandRank::new(FOUR_OF_A_KIND, &[ACE]);
    let straight_flush = HandRank::new(STRAIGHT_FLUSH, &[ACE]);
    let royal_flush = HandRank::new(ROYAL_FLUSH, &[]);
    
    assert!(high_card < one_pair);
    assert!(one_pair < two_pair);
    assert!(two_pair < three_of_a_kind);
    assert!(three_of_a_kind < straight);
    assert!(straight < flush);
    assert!(flush < full_house);
    assert!(full_house < four_of_a_kind);
    assert!(four_of_a_kind < straight_flush);
    assert!(straight_flush < royal_flush);
}

#[test]
fn test_find_winners_two_players_tie() {
    let player1 = make_cards(&[0, 1]); // 2♠ 3♠
    let player2 = make_cards(&[13, 14]); // 2♦ 3♦
    
    let winners = find_winners(&[(0, player1), (1, player2)]);
    assert_eq!(winners.len(), 2);
    assert!(winners.contains(&0));
    assert!(winners.contains(&1));
}

#[test]
fn test_find_winners_two_players_one_wins() {
    let player1 = make_cards(&[12, 25]); // A♠ A♥ (一对A)
    let player2 = make_cards(&[0, 13]); // 2♠ 2♦ (一对2)
    
    let winners = find_winners(&[(0, player1), (1, player2)]);
    assert_eq!(winners.len(), 1);
    assert!(winners.contains(&0));
}

#[test]
fn test_find_winners_three_players_one_winner() {
    let player1 = make_cards(&[0, 1]); // 2♠ 3♠
    let player2 = make_cards(&[12, 25]); // A♠ A♥ (一对A)
    let player3 = make_cards(&[2, 3]); // 4♠ 5♠
    
    let winners = find_winners(&[(0, player1), (1, player2), (2, player3)]);
    assert_eq!(winners.len(), 1);
    assert!(winners.contains(&1));
}

// ===========================================================================
// 6. side_pot.rs — 边池结算
// ===========================================================================

#[test]
fn test_side_pot_new() {
    let pot = SidePot::new(100, 0b0011);
    assert_eq!(pot.amount, 100);
    assert_eq!(pot.eligible_seats, 0b0011);
}

#[test]
fn test_side_pot_is_eligible() {
    let pot = SidePot::new(100, 0b0101);
    assert!(pot.is_eligible(0));
    assert!(!pot.is_eligible(1));
    assert!(pot.is_eligible(2));
    assert!(!pot.is_eligible(3));
}

#[test]
fn test_side_pot_borsh_roundtrip() {
    let pot = SidePot::new(150, 0b1011);
    let bytes = borsh::to_vec(&pot).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(pot, decoded);
}

#[test]
fn test_calculate_side_pots_no_all_in() {
    let bets = vec![100, 100];
    let folded = vec![false, false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 200);
    assert_eq!(result.pots[0].eligible_seats, 0b0011);
    assert_eq!(result.total(), 200);
}

#[test]
fn test_calculate_side_pots_single_all_in() {
    let bets = vec![50, 100];
    let folded = vec![false, false];
    let all_in = vec![true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 2);
    assert_eq!(result.pots[0].amount, 100);
    assert_eq!(result.pots[0].eligible_seats, 0b0011);
    assert_eq!(result.pots[1].amount, 50);
    assert_eq!(result.pots[1].eligible_seats, 0b0010);
    assert_eq!(result.total(), 150);
}

#[test]
fn test_calculate_side_pots_three_players_two_all_in() {
    let bets = vec![50, 100, 100];
    let folded = vec![false, false, false];
    let all_in = vec![true, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 2);
    assert_eq!(result.pots[0].amount, 150);
    assert_eq!(result.pots[0].eligible_seats, 0b0111);
    assert_eq!(result.pots[1].amount, 100);
    assert_eq!(result.pots[1].eligible_seats, 0b0110);
    assert_eq!(result.total(), 250);
}

#[test]
fn test_calculate_side_pots_folded_player_ineligible() {
    let bets = vec![30, 100, 100];
    let folded = vec![true, false, false];
    let all_in = vec![false, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 230);
    assert_eq!(result.pots[0].eligible_seats, 0b0110);
}

#[test]
fn test_calculate_side_pots_all_folded() {
    let bets = vec![50, 100, 150];
    let folded = vec![true, true, true];
    let all_in = vec![false, false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 300);
    assert_eq!(result.pots[0].eligible_seats, 0);
}

#[test]
fn test_calculate_side_pots_empty_eligible_merge() {
    let bets = vec![50, 200, 200];
    let folded = vec![false, true, true];
    let all_in = vec![true, false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 450);
}

#[test]
fn test_calculate_side_pots_length_mismatch() {
    let bets = vec![100, 100];
    let folded = vec![false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in);
    assert!(matches!(result, Err(SidePotError::LengthMismatch)));
}

#[test]
fn test_calculate_side_pots_bet_overflow() {
    let bets = vec![MAX_TOTAL_BET, 1];
    let folded = vec![false, false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in);
    assert!(matches!(result, Err(SidePotError::BetOverflow)));
}

#[test]
fn test_calculate_side_pots_four_players_multiple_all_in() {
    let bets = vec![20, 50, 80, 100];
    let folded = vec![false, false, false, false];
    let all_in = vec![true, true, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    
    assert_eq!(result.pots.len(), 4);
    assert_eq!(result.pots[0].amount, 80);
    assert_eq!(result.pots[1].amount, 90);
    assert_eq!(result.pots[2].amount, 60);
    assert_eq!(result.pots[3].amount, 20);
    assert_eq!(result.total(), 250);
}

// ===========================================================================
// 7. state_machine.rs — 状态机与游戏逻辑
// ===========================================================================

use group::Group;
use blstrs::G1Projective;
use poker_protocol::crypto::types::ECPoint;
use poker_l1::vm::contracts::texas_poker::{
    state_machine,
    types::{TexasPokerTable, EMPTY_PLAYER},
    events::TexasPokerEvent,
};

fn dummy_table(name: &str, max_players: u8) -> TexasPokerTable {
    let id = poker_l1::object_model::ObjectID::new([0xFF; 20], 0);
    TexasPokerTable::new(id, name.into(), max_players, 50, 100)
}

fn occupy_seat(table: &mut TexasPokerTable, seat_idx: u8, player: [u8; 20], stack: u64) {
    table.seats[seat_idx as usize] = Seat {
        player,
        stack,
        hand: vec![],
        bet: 0,
        total_bet: 0,
        folded: false,
        all_in: false,
        acted_this_round: false,
        is_waiting: false,
        left_during_hand: false,
        pk: ECPoint(G1Projective::identity()),
        refunded: false,
        pending_addon: 0,
        time_bank_ms: 300_000,
    };
}

// ========== 状态谓词 ==========

#[test]
fn test_state_predicates_can_join_state() {
    let mut table = dummy_table("test", 6);
    assert!(state_machine::can_join_state(&table));
    
    table.round_state = ROUND_PREFLOP;
    assert!(!state_machine::can_join_state(&table));
}

#[test]
fn test_state_predicates_can_leave_state() {
    let mut table = dummy_table("test", 6);
    assert!(state_machine::can_leave_state(&table));
    
    table.round_state = ROUND_FLOP;
    assert!(!state_machine::can_leave_state(&table));
}

#[test]
fn test_state_predicates_is_betting_round() {
    let mut table = dummy_table("test", 6);
    assert!(!state_machine::is_betting_round(&table));
    
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    assert!(state_machine::is_betting_round(&table));
    
    table.round_state = ROUND_SHOWDOWN;
    assert!(!state_machine::is_betting_round(&table));
}

#[test]
fn test_state_predicates_is_playing() {
    let mut table = dummy_table("test", 6);
    assert!(!state_machine::is_playing(&table));
    
    table.round_state = ROUND_PREFLOP;
    assert!(state_machine::is_playing(&table));
}

#[test]
fn test_state_predicates_is_player_turn() {
    let mut table = dummy_table("test", 6);
    table.current_turn = Some(2);
    
    assert!(state_machine::is_player_turn(&table, 2));
    assert!(!state_machine::is_player_turn(&table, 3));
}

#[test]
fn test_state_predicates_is_in_list() {
    let list = vec![1, 3, 5];
    assert!(state_machine::is_in_list(&list, 3));
    assert!(!state_machine::is_in_list(&list, 2));
}

// ========== 座位辅助函数 ==========

#[test]
fn test_seat_helpers_count_active_players() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    
    assert_eq!(state_machine::count_active_players(&table.seats), 3);
    
    table.seats[1].folded = true;
    assert_eq!(state_machine::count_active_players(&table.seats), 2);
    
    table.seats[2].is_waiting = true;
    assert_eq!(state_machine::count_active_players(&table.seats), 1);
}

#[test]
fn test_seat_helpers_count_active_occupied() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    
    assert_eq!(state_machine::count_active_occupied(&table.seats), 2);
    
    table.seats[1].folded = true;
    assert_eq!(state_machine::count_active_occupied(&table.seats), 2);
    
    table.seats[1].is_waiting = true;
    assert_eq!(state_machine::count_active_occupied(&table.seats), 1);
}

#[test]
fn test_seat_helpers_get_active_seat_indices() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 2, [0x02; 20], 1000);
    
    let indices = state_machine::get_active_seat_indices(&table.seats);
    assert_eq!(indices, vec![0, 2]);
}

#[test]
fn test_seat_helpers_find_next_active_seat() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    table.seats[0].folded = true;
    
    // 环形查找：从 seat 0 开始找下一个，跳过 folded 的 seat 0，找到 seat 1
    assert_eq!(state_machine::find_next_active_seat(&table.seats, 0, 4), Some(1));
    // 从 seat 1 开始找下一个，找到 seat 2
    assert_eq!(state_machine::find_next_active_seat(&table.seats, 1, 4), Some(2));
    // 从 seat 2 开始找下一个，绕回找到 seat 1（seat 0 已 folded）
    assert_eq!(state_machine::find_next_active_seat(&table.seats, 2, 4), Some(1));
    
    // 所有玩家都 folded 时返回 None
    table.seats[1].folded = true;
    table.seats[2].folded = true;
    assert_eq!(state_machine::find_next_active_seat(&table.seats, 0, 4), None);
}

#[test]
fn test_seat_helpers_find_next_participating_seat() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 2, [0x02; 20], 1000);
    
    assert_eq!(state_machine::find_next_participating_seat(&table.seats, 0, 4), Some(2));
}

#[test]
fn test_seat_helpers_has_actionable_player() {
    let mut table = dummy_table("test", 4);
    assert!(!state_machine::has_actionable_player(&table.seats));
    
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    assert!(state_machine::has_actionable_player(&table.seats));
    
    table.seats[0].folded = true;
    assert!(!state_machine::has_actionable_player(&table.seats));
}

// ========== 下注动作 ==========

#[test]
fn test_apply_fold_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.round_state = ROUND_WAITING;
    
    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_fold_not_players_turn() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(1);
    
    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_fold_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert!(table.seats[0].folded);
}

#[test]
fn test_apply_check_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    
    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_check_bet_below_current() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_check_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_FLOP;
    table.betting_round = Some(BettingRound::new(100, 0));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert!(table.seats[0].acted_this_round);
    assert_eq!(table.current_turn, Some(1));
}

#[test]
fn test_apply_call_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    
    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_call_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet, 100);
    assert_eq!(table.seats[0].stack, 900);
}

#[test]
fn test_apply_call_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 50);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].stack, 0);
    assert!(table.seats[0].all_in);
}

#[test]
fn test_apply_raise_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    
    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 200, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_raise_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 300, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet, 300);
    assert_eq!(table.seats[0].stack, 700);
}

#[test]
fn test_apply_raise_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 500, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].stack, 0);
    assert!(table.seats[0].all_in);
}

#[test]
fn test_apply_raise_resets_other_players() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    table.seats[1].acted_this_round = true;
    
    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 300, &mut events);
    assert!(result.is_ok());
    assert!(!table.seats[1].acted_this_round);
}

// ========== 结算与重置 ==========

#[test]
fn test_reset_for_next_hand_clears_state() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    occupy_seat(&mut table, 1, [0x02; 20], 500);
    table.pot = 1000;
    table.community_cards = vec![Card::new(0, 14), Card::new(1, 13)];
    table.round_state = ROUND_SHOWDOWN;
    table.betting_round = Some(BettingRound::new(100, 0));
    
    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());
    
    assert_eq!(table.round_state, ROUND_WAITING);
    assert_eq!(table.pot, 0);
    assert!(table.community_cards.is_empty());
    assert!(table.betting_round.is_none());
    assert!(table.current_turn.is_none());
}

#[test]
fn test_reset_for_next_hand_merges_pending_addon() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.seats[0].pending_addon = 1000;
    
    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());
    
    assert_eq!(table.seats[0].stack, 1500);
    assert_eq!(table.seats[0].pending_addon, 0);
}

#[test]
fn test_reset_for_next_hand_refills_time_bank() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.seats[0].time_bank_ms = 0;
    
    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());
    
    assert!(table.seats[0].time_bank_ms > 0);
}

// ========== 盲注定位（通过 start_hand 间接测试） ==========

// ========== kick_player_internal ==========

#[test]
fn test_kick_player_internal_refunds_stack() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.chip_pool = 500;
    
    let mut events = vec![];
    state_machine::kick_player_internal(&mut table, 0, 0, &mut events);
    
    assert!(!table.seats[0].is_occupied());
    assert_eq!(table.chip_pool, 0);
}

// ===========================================================================
// 8. dispatch.rs — 路由与参数校验
// ===========================================================================

use poker_l1::vm::contracts::texas_poker::{
    dispatch,
    dispatch::{
        selectors,
        CreateTableArgs, JoinTableArgs, LeaveTableArgs, AddonArgs, RebuyArgs,
        SeatIndexArgs, RaiseArgs, BetArgs, TickArgs,
    },
};
use poker_l1::vm::contracts::dispatch::{DispatchContext, DispatchResult};

fn make_dispatch_context() -> DispatchContext {
    DispatchContext {
        caller: [0xAA; 20],
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xBB; 32],
        },
        chain_id: 1,
        block_height: 100,
        block_timestamp: 1_000_000,
    }
}

// ========== selector 测试 ==========

#[test]
fn test_dispatch_selectors_deterministic() {
    let h1 = selectors::create_table();
    let h2 = dispatch::compute_method_selector("create_table");
    assert_eq!(h1, h2);
}

#[test]
fn test_dispatch_selectors_all_unique() {
    let sels = selectors::all();
    assert_eq!(sels.len(), 21);
    for i in 0..sels.len() {
        for j in (i + 1)..sels.len() {
            assert_ne!(sels[i], sels[j]);
        }
    }
}

// ========== create_table 参数校验 ==========

#[test]
fn test_dispatch_create_table_rejects_zero_big_blind() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 6,
        small_blind: 50,
        big_blind: 0,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_create_table_rejects_small_blind_greater_than_big_blind() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 6,
        small_blind: 100,
        big_blind: 50,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_create_table_rejects_max_players_too_small() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 1,
        small_blind: 50,
        big_blind: 100,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

// ========== join_table 参数校验 ==========

#[test]
fn test_dispatch_join_table_rejects_non_waiting_state() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    table.round_state = ROUND_PREFLOP;
    
    let args = JoinTableArgs {
        player: [0x11; 20],
        buy_in: 1000,
        pk: ECPoint(G1Projective::identity()),
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_join_table_rejects_buy_in_less_than_big_blind() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    table.big_blind = 100;
    
    let args = JoinTableArgs {
        player: [0x11; 20],
        buy_in: 50,
        pk: ECPoint(G1Projective::identity()),
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_join_table_rejects_duplicate_pk() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    
    let args1 = JoinTableArgs {
        player: [0x11; 20],
        buy_in: 1000,
        pk: ECPoint(G1Projective::identity()),
    };
    dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &borsh::to_vec(&args1).unwrap()).unwrap();
    
    let args2 = JoinTableArgs {
        player: [0x22; 20],
        buy_in: 1000,
        pk: ECPoint(G1Projective::identity()),
    };
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &borsh::to_vec(&args2).unwrap());
    assert!(result.is_err());
}

// ========== leave_table 参数校验 ==========

#[test]
fn test_dispatch_leave_table_rejects_non_waiting_state() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    table.round_state = ROUND_PREFLOP;
    table.seats[0].player = [0x11; 20];
    table.seats[0].stack = 1000;
    
    let args = LeaveTableArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_leave_table_rejects_empty_seat() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    
    let args = LeaveTableArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_leave_table_rejects_invalid_seat_index() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    
    let args = LeaveTableArgs { seat_index: 10 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

// ========== addon/rebuy 测试 ==========

#[test]
fn test_dispatch_addon_accumulates_pending() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    
    let args = AddonArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::addon(), &args_bytes);
    assert!(result.is_ok());
    
    assert_eq!(table.seats[0].pending_addon, 1000);
    assert_eq!(table.seats[0].stack, 500);
}

#[test]
fn test_dispatch_addon_rejects_invalid_seat() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    
    let args = AddonArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::addon(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_rebuy_increases_stack_immediately() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    
    let args = RebuyArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::rebuy(), &args_bytes);
    assert!(result.is_ok());
    
    assert_eq!(table.seats[0].stack, 1500);
    assert_eq!(table.seats[0].pending_addon, 0);
}

#[test]
fn test_dispatch_rebuy_rejects_invalid_seat() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    
    let args = RebuyArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::rebuy(), &args_bytes);
    assert!(result.is_err());
}

// ========== 下注动作路由测试 ==========

#[test]
fn test_dispatch_fold_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::fold(), &args_bytes);
    assert!(result.is_ok());
    assert!(table.seats[0].folded);
}

#[test]
fn test_dispatch_check_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_FLOP;
    table.betting_round = Some(BettingRound::new(100, 0));
    table.current_turn = Some(0);
    
    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::check(), &args_bytes);
    assert!(result.is_ok());
}

#[test]
fn test_dispatch_call_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::call(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet, 100);
}

#[test]
fn test_dispatch_raise_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = Some(0);
    
    let args = RaiseArgs {
        seat_index: 0,
        total_bet: 300,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::raise(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet, 300);
}

#[test]
fn test_dispatch_bet_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.round_state = ROUND_FLOP;
    table.betting_round = Some(BettingRound::new(100, 0));
    table.current_turn = Some(0);
    
    let args = BetArgs {
        seat_index: 0,
        amount: 200,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::bet(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet, 200);
}

// ========== 未知方法测试 ==========

#[test]
fn test_dispatch_unknown_method() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let unknown_selector = [0xFE; 32];
    let result = dispatch::dispatch(&ctx, &mut table, &unknown_selector, &[]);
    assert!(matches!(result, Err(poker_l1::error::PokerL1Error::UnknownContractMethod { .. })));
}