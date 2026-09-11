//! Texas Poker 边池分层算法。
//!
//! # 单一事实源（plan-appchain §5.2-1，P0-1）
//!
//! 分层算法（[`SidePot`] / [`calculate_side_pots`] / 位掩码工具）已整体
//! 搬运到共享 crate [`poker_settlement_core`]，本模块只做**再导出**（路径
//! 不变，行为零变化），使 `super::side_pot::X` 调用点继续可用。
//! 既有测试保留在本文件作为跨 crate 等价性见证。

pub use poker_settlement_core::{
    calculate_side_pots, is_eligible, seat_bit, SidePot, SidePotError, SidePotResult,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contracts::texas_poker::constants::MAX_TOTAL_BET;

    fn eligible_vec(mask: u16) -> Vec<u8> {
        (0..16).filter(|&j| is_eligible(mask, j)).collect()
    }

    #[test]
    fn test_no_all_in_single_pot() {
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 1);
        assert_eq!(result.pots[0].amount, 200);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1]);
        assert_eq!(result.total(), 200);
    }

    #[test]
    fn test_single_all_in_two_pots() {
        // P0 all-in 50，P1 call 100 → pots[0] 100（eligible [0,1]），pots[1] 50（eligible [1]）
        let bets = vec![50, 100];
        let folded = vec![false, false];
        let all_in = vec![true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 2);
        assert_eq!(result.pots[0].amount, 100);
        assert_eq!(result.pots[1].amount, 50);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![1]);
        assert_eq!(result.total(), 150);
    }

    #[test]
    fn test_three_players_two_all_in_levels() {
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 2);
        assert_eq!(result.pots[0].amount, 150);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1, 2]);
        assert_eq!(result.pots[1].amount, 100);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![1, 2]);
        assert_eq!(result.total(), 250);
    }

    #[test]
    fn test_folded_player_contributes_but_ineligible() {
        // P0 fold 已下注 30，P1 all-in 100，P2 call 100
        let bets = vec![30, 100, 100];
        let folded = vec![true, false, false];
        let all_in = vec![false, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 1);
        assert_eq!(result.pots[0].amount, 230);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![1, 2]);
        assert_eq!(result.total(), 230);
    }

    #[test]
    fn test_empty_eligible_merge() {
        // 所有超额贡献者都 fold：P0 all-in 50（未 fold），P1/P2 fold 已下注 200
        // level=50: pot 150，eligible [0]
        // outer: P1+P2 各贡献 150 = 300，eligible [] → 合并到 pots[0] → 450
        let bets = vec![50, 200, 200];
        let folded = vec![false, true, true];
        let all_in = vec![true, false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 1);
        assert_eq!(result.pots[0].amount, 450);
        assert_eq!(result.total(), 450);
    }

    #[test]
    fn test_all_in_bets_same_level() {
        // 两玩家 all-in 相同金额 → 同一 level（循环内 level<=prev_level 跳过重复）
        let bets = vec![100, 100, 200];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 2);
        assert_eq!(result.pots[0].amount, 300);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1, 2]);
        assert_eq!(result.pots[1].amount, 100);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![2]);
    }

    #[test]
    fn test_length_mismatch_rejected() {
        let bets = vec![100, 100];
        let folded = vec![false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in),
            Err(SidePotError::LengthMismatch)
        );
    }

    #[test]
    fn test_bet_overflow_detected() {
        let bets = vec![MAX_TOTAL_BET, 1];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in),
            Err(SidePotError::BetOverflow)
        );
    }

    #[test]
    fn test_side_pot_borsh_roundtrip() {
        let pot = SidePot::new(150, seat_bit(0) | seat_bit(2) | seat_bit(3));
        let bytes = borsh::to_vec(&pot).unwrap();
        let recovered: SidePot = borsh::from_slice(&bytes).unwrap();
        assert_eq!(pot, recovered);
    }

    #[test]
    fn test_seat_bit_and_is_eligible() {
        assert!(is_eligible(seat_bit(0), 0));
        assert!(is_eligible(seat_bit(5), 5));
        assert!(!is_eligible(seat_bit(0), 1));
        assert!(!is_eligible(0, 0)); // 空掩码无人 eligible
    }
}
