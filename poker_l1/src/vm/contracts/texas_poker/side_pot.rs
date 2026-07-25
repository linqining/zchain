//! Texas Poker 边池分层（移植自 `texas_poker_move/sources/side_pot.move`）。
//!
//! 算法逐层切片 all-in 玩家的 bet 水位，构造多个 SidePot。
//! 关键修复点（与 Move 端一致）：
//! - M-P9: 升序排序（Rust 用 `sort_unstable`）
//! - M-P10: 溢出保护——单局总下注上限 10^18
//! - m4: 三个输入向量长度一致性校验
//! - m5: pop_back 后 side_pots 为空时将 merge_amount 重新放回，避免金额丢失
//! - M-A3: 最外层 side_pot 的 eligible 为空时合并到上一个有 eligible 的层级

use serde::{Deserialize, Serialize};
use borsh::{BorshSerialize, BorshDeserialize};

use super::constants::MAX_TOTAL_BET;

/// 边池（eligible_seats 升序，便于 BTreeSet 去重与确定性序列化）。
///
/// 对应 Move `SidePot { amount: u64, eligible_seats: vector<u64> }`。
/// 使用 `Vec<u8>` 而非 `BTreeSet<u8>`：保留与 Move 端完全一致的顺序语义
/// （调用方传入顺序即保存顺序），避免 Borsh 序列化差异。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SidePot {
    /// 该层 pot 总金额。
    pub amount: u64,
    /// 有资格争夺该层 pot 的座位索引列表。
    pub eligible_seats: Vec<u8>,
}

impl SidePot {
    /// 构造新 SidePot。
    #[must_use]
    pub fn new(amount: u64, eligible_seats: Vec<u8>) -> Self {
        Self {
            amount,
            eligible_seats,
        }
    }
}

/// 边池计算错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidePotError {
    /// 总下注超过 MAX_TOTAL_BET（M-P10 溢出保护）。
    #[error("total bets exceed MAX_TOTAL_BET, possible overflow")]
    BetOverflow,
    /// bets/folded/all_in 三个向量长度不一致（m4 修复）。
    #[error("bets/folded/all_in vectors must have same length")]
    LengthMismatch,
}

/// 边池计算结果（main_pot 与 side_pots 分离，对应 Move 返回 `(u64, vector<SidePot>)`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidePotResult {
    /// 主池金额（= side_pots[0].amount，单独返回便于调用方直接使用）。
    pub main_pot: u64,
    /// 边池列表（不含主池；若全员未 all-in 则为空）。
    pub side_pots: Vec<SidePot>,
}

impl SidePotResult {
    /// 返回所有 pot（main + sides）的总额。
    #[must_use]
    pub fn total(&self) -> u64 {
        let side_total: u64 = self.side_pots.iter().map(|p| p.amount).sum();
        self.main_pot
            .checked_add(side_total)
            .expect("pot total 溢出（应在 M-P10 上限内）")
    }
}

/// 计算边池分层（镜像 `side_pot.move::calculate_side_pots`）。
///
/// # 参数
/// - `bets`：每个座位的总下注
/// - `folded`：每个座位是否已 fold
/// - `all_in`：每个座位是否 all-in
///
/// # 算法
/// 1. 校验三个向量长度一致（m4）
/// 2. 计算总下注 `total_pot`（含 M-P10 溢出保护）
/// 3. 收集所有 all-in 玩家的 bet（去重）
/// 4. 升序排序后，逐层切片构造 SidePot（eligible = 未 fold 且 bet > prev_level 的座位）
/// 5. 最外层（超出最大 all-in 的部分）单独构造一层
/// 6. **M-A3 修复**：最外层 eligible 为空时，金额合并到上一个有 eligible 的层级
/// 7. 主池 = side_pots[0].amount，其余为 side_pots
///
/// # Errors
/// - `SidePotError::LengthMismatch`：三个向量长度不一致
/// - `SidePotError::BetOverflow`：总下注超过 MAX_TOTAL_BET
pub fn calculate_side_pots(
    bets: &[u64],
    folded: &[bool],
    all_in: &[bool],
) -> Result<SidePotResult, SidePotError> {
    let n = bets.len();
    // m4 修复：校验三个向量长度一致
    if folded.len() != n || all_in.len() != n {
        return Err(SidePotError::LengthMismatch);
    }

    let total_pot = sum_bets(bets)?;

    // 收集所有 all-in 玩家的 bet（去重）
    let mut all_in_bets = collect_all_in_bets(bets, all_in);

    if all_in_bets.is_empty() {
        // 无人 all-in：全部筹码归入主池，无 side pot
        return Ok(SidePotResult {
            main_pot: total_pot,
            side_pots: vec![],
        });
    }

    // M-P9: 升序排序
    all_in_bets.sort_unstable();

    let mut side_pots: Vec<SidePot> = vec![];
    let mut prev_level: u64 = 0;

    for &level in &all_in_bets {
        if level <= prev_level {
            continue;
        }

        let mut pot_amount: u64 = 0;
        let mut eligible: Vec<u8> = vec![];

        for j in 0..n {
            let bet = bets[j];
            if bet > prev_level {
                // M-P10: 单层 pot_amount 累加溢出检查
                let contribution = if bet < level {
                    bet - prev_level
                } else {
                    level - prev_level
                };
                pot_amount = pot_amount
                    .checked_add(contribution)
                    .ok_or(SidePotError::BetOverflow)?;
                if !folded[j] {
                    eligible.push(u8::try_from(j).expect("座位数 <= 255"));
                }
            }
        }

        if pot_amount > 0 {
            side_pots.push(SidePot::new(pot_amount, eligible));
        }

        prev_level = level;
    }

    // 最外层（超出最大 all-in 的部分）
    let mut outer_amount: u64 = 0;
    let mut outer_eligible: Vec<u8> = vec![];
    for k in 0..n {
        let bet = bets[k];
        if bet > prev_level {
            outer_amount = outer_amount
                .checked_add(bet - prev_level)
                .ok_or(SidePotError::BetOverflow)?;
            if !folded[k] {
                outer_eligible.push(u8::try_from(k).expect("座位数 <= 255"));
            }
        }
    }

    if outer_amount > 0 {
        side_pots.push(SidePot::new(outer_amount, outer_eligible));
    }

    // M-A3 修复：最外层 eligible 为空时合并到上一个有 eligible 的层级
    if !side_pots.is_empty() {
        let last_idx = side_pots.len() - 1;
        let last_eligible_empty = side_pots[last_idx].eligible_seats.is_empty();
        let last_amount = side_pots[last_idx].amount;
        if last_eligible_empty && last_amount > 0 {
            let merge_amount = last_amount;
            side_pots.pop();
            if !side_pots.is_empty() {
                // 从后往前找第一个有 eligible 的层级
                let mut merge_idx = 0;
                for k in (0..side_pots.len()).rev() {
                    if !side_pots[k].eligible_seats.is_empty() {
                        merge_idx = k;
                        break;
                    }
                }
                side_pots[merge_idx].amount = side_pots[merge_idx]
                    .amount
                    .checked_add(merge_amount)
                    .ok_or(SidePotError::BetOverflow)?;
            } else {
                // m5 修复：pop_back 后 side_pots 为空（原本仅一个 pot 且 eligible 为空），
                // 将 merge_amount 重新放回，避免金额丢失。此时 eligible 为空，
                // 由调用方处理（通常归还给唯一未弃牌玩家或主池）。
                side_pots.push(SidePot::new(merge_amount, vec![]));
            }
        }
    }

    // 主池 = 第一个 side_pot；其余为 side_pots
    if side_pots.is_empty() {
        Ok(SidePotResult {
            main_pot: total_pot,
            side_pots: vec![],
        })
    } else {
        let main_pot = side_pots[0].amount;
        let rest = side_pots[1..].to_vec();
        Ok(SidePotResult {
            main_pot,
            side_pots: rest,
        })
    }
}

/// 计算总下注（含 M-P10 溢出保护）。
fn sum_bets(bets: &[u64]) -> Result<u64, SidePotError> {
    let mut total: u64 = 0;
    for &bet in bets {
        total = total
            .checked_add(bet)
            .ok_or(SidePotError::BetOverflow)?;
        if total > MAX_TOTAL_BET {
            return Err(SidePotError::BetOverflow);
        }
    }
    Ok(total)
}

/// 收集所有 all-in 玩家的 bet（去重）。
fn collect_all_in_bets(bets: &[u64], all_in: &[bool]) -> Vec<u64> {
    let mut result: Vec<u64> = vec![];
    for i in 0..bets.len() {
        if all_in[i] && bets[i] > 0 && !result.contains(&bets[i]) {
            result.push(bets[i]);
        }
    }
    result
}

/// 按 pot 分配奖金给赢家（更新赢家 stack）。
///
/// # 参数
/// - `stacks`：每个座位的筹码栈（可变引用，分配时累加）
/// - `main_pot`：主池金额
/// - `main_eligible`：主池 eligible 座位
/// - `side_pots`：边池列表
/// - `main_winners`：主池赢家座位列表（平局时多人）
/// - `side_winners`：每个边池对应的赢家座位列表（与 side_pots 等长）
///
/// # 返回
/// 实际分配的总金额（应等于 main_pot + Σ side_pots.amount）。
///
/// # Panics
/// - `side_winners.len() != side_pots.len()`：编程错误
pub fn distribute_pots(
    stacks: &mut [u64],
    main_pot: u64,
    main_eligible: &[u8],
    side_pots: &[SidePot],
    main_winners: &[u8],
    side_winners: &[Vec<u8>],
) -> u64 {
    assert_eq!(
        side_winners.len(),
        side_pots.len(),
        "side_winners 与 side_pots 长度不一致"
    );

    let mut distributed: u64 = 0;

    // 主池分配（平局时均分，截断取整，余数归第一个赢家）。
    // P2-6 修复：与边池对称地校验 winner 是否都在 main_eligible 内，
    // 防御性避免调用方误传不在 eligible 列表中的 seat 导致主池被错误分配。
    let main_all_eligible = main_winners
        .iter()
        .all(|w| main_eligible.contains(w));
    if !main_winners.is_empty() && main_pot > 0 && main_all_eligible {
        let share = main_pot / main_winners.len() as u64;
        let remainder = main_pot % main_winners.len() as u64;
        for (idx, &winner) in main_winners.iter().enumerate() {
            let amount = if idx == 0 {
                share + remainder
            } else {
                share
            };
            stacks[winner as usize] += amount;
            distributed += amount;
        }
    }

    // 标记 main_eligible 已被使用（校验逻辑已消费），避免未使用变量警告。
    let _ = main_eligible;

    // 边池分配
    for (pot_idx, pot) in side_pots.iter().enumerate() {
        let winners = &side_winners[pot_idx];
        if winners.is_empty() || pot.amount == 0 {
            continue;
        }
        // 校验赢家都在 eligible 列表内（防御性，不满足则跳过）
        let all_eligible = winners
            .iter()
            .all(|w| pot.eligible_seats.contains(w));
        if !all_eligible {
            continue;
        }
        let share = pot.amount / winners.len() as u64;
        let remainder = pot.amount % winners.len() as u64;
        for (idx, &winner) in winners.iter().enumerate() {
            let amount = if idx == 0 {
                share + remainder
            } else {
                share
            };
            stacks[winner as usize] += amount;
            distributed += amount;
        }
    }

    distributed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_all_in_single_pot() {
        // 2 玩家各下注 100，无人 all-in → 主池 200，无 side pot
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.main_pot, 200);
        assert!(result.side_pots.is_empty());
        assert_eq!(result.total(), 200);
    }

    #[test]
    fn test_single_all_in_two_pots() {
        // P0 all-in 50，P1 call 100 → main pot 100（P0+P1 各贡献 50），
        // side pot 50（仅 P1 贡献的超额部分，eligible 仅 P1）
        let bets = vec![50, 100];
        let folded = vec![false, false];
        let all_in = vec![true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.main_pot, 100);
        assert_eq!(result.side_pots.len(), 1);
        assert_eq!(result.side_pots[0].amount, 50);
        assert_eq!(result.side_pots[0].eligible_seats, vec![1]);
        assert_eq!(result.total(), 150);
    }

    #[test]
    fn test_three_players_two_all_in_levels() {
        // P0 all-in 50，P1 all-in 100，P2 call 100
        // 期望：
        // - main pot (level=50): P0/P1/P2 各贡献 50 → 150，eligible [0,1,2]
        // - side pot 1 (level=100): P1/P2 各贡献 50 → 100，eligible [1,2]
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.main_pot, 150);
        assert_eq!(result.side_pots.len(), 1);
        assert_eq!(result.side_pots[0].amount, 100);
        assert_eq!(result.side_pots[0].eligible_seats, vec![1, 2]);
        assert_eq!(result.total(), 250);
    }

    #[test]
    fn test_folded_player_contributes_but_ineligible() {
        // P0 fold 但已下注 30，P1 all-in 100，P2 call 100
        // main pot (level=100): P0 30 + P1 100 + P2 100 = 230，eligible [1,2]（P0 fold）
        let bets = vec![30, 100, 100];
        let folded = vec![true, false, false];
        let all_in = vec![false, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.main_pot, 230);
        assert!(result.side_pots.is_empty());
        assert_eq!(result.total(), 230);
    }

    #[test]
    fn test_m_a3_empty_eligible_merge() {
        // M-A3 场景：所有超额贡献者都 fold，最外层 eligible 为空
        // P0 all-in 50（未 fold），P1 fold 但已下注 200，P2 fold 但已下注 200
        // level=50: main pot = 50+50+50 = 150，eligible [0]
        // outer level: P1 贡献 150 + P2 贡献 150 = 300，eligible []（都 fold）
        // M-A3 修复：outer 300 合并到 main pot → main pot = 450
        let bets = vec![50, 200, 200];
        let folded = vec![false, true, true];
        let all_in = vec![true, false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        // main pot 应被合并为 150 + 300 = 450
        assert_eq!(result.main_pot, 450);
        // side_pots 为空（M-A3 合并后仅剩一个 pot）
        assert!(result.side_pots.is_empty() || result.side_pots.iter().all(|p| p.amount == 0));
        // 总额必须保持 = 50+200+200 = 450
        assert_eq!(result.total(), 450);
    }

    #[test]
    fn test_m_a3_single_pot_empty_eligible() {
        // m5 修复场景：原本仅一个 pot 且 eligible 为空
        // P0 fold 已下注 100，无 all-in 玩家
        // 由于无人 all-in，走 `all_in_bets.is_empty()` 分支，直接返回主池
        let bets = vec![100, 0];
        let folded = vec![true, false];
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.main_pot, 100);
        assert!(result.side_pots.is_empty());
    }

    #[test]
    fn test_all_in_bets_deduplicated() {
        // 两个玩家 all-in 相同金额 → 只生成一个 level
        let bets = vec![100, 100, 200];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        // level=100: main pot = 100+100+100 = 300，eligible [0,1,2]
        // outer: P2 贡献 100，eligible [2]
        assert_eq!(result.main_pot, 300);
        assert_eq!(result.side_pots.len(), 1);
        assert_eq!(result.side_pots[0].amount, 100);
        assert_eq!(result.side_pots[0].eligible_seats, vec![2]);
    }

    #[test]
    fn test_length_mismatch_rejected() {
        let bets = vec![100, 100];
        let folded = vec![false]; // 长度不一致
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in);
        assert_eq!(result, Err(SidePotError::LengthMismatch));
    }

    #[test]
    fn test_bet_overflow_detected() {
        // 总下注超过 MAX_TOTAL_BET (10^18)
        let bets = vec![MAX_TOTAL_BET, 1];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in);
        assert_eq!(result, Err(SidePotError::BetOverflow));
    }

    #[test]
    fn test_distribute_single_winner() {
        // 主池 200，P0 赢 → P0 stack += 200
        let mut stacks = vec![1000, 1000];
        let main_pot = 200;
        let main_eligible = vec![0, 1];
        let side_pots: Vec<SidePot> = vec![];
        let main_winners = vec![0];
        let side_winners: Vec<Vec<u8>> = vec![];

        let distributed =
            distribute_pots(&mut stacks, main_pot, &main_eligible, &side_pots, &main_winners, &side_winners);
        assert_eq!(distributed, 200);
        assert_eq!(stacks, vec![1200, 1000]);
    }

    #[test]
    fn test_distribute_split_pot() {
        // 主池 200，P0 和 P1 平局 → 各 100
        let mut stacks = vec![1000, 1000];
        let main_pot = 200;
        let main_eligible = vec![0, 1];
        let side_pots: Vec<SidePot> = vec![];
        let main_winners = vec![0, 1];
        let side_winners: Vec<Vec<u8>> = vec![];

        let distributed =
            distribute_pots(&mut stacks, main_pot, &main_eligible, &side_pots, &main_winners, &side_winners);
        assert_eq!(distributed, 200);
        assert_eq!(stacks, vec![1100, 1100]);
    }

    #[test]
    fn test_distribute_split_with_remainder() {
        // 主池 201，P0 和 P1 平局 → P0 得 101（含余数 1），P1 得 100
        let mut stacks = vec![1000, 1000];
        let main_pot = 201;
        let main_eligible = vec![0, 1];
        let side_pots: Vec<SidePot> = vec![];
        let main_winners = vec![0, 1];
        let side_winners: Vec<Vec<u8>> = vec![];

        let distributed =
            distribute_pots(&mut stacks, main_pot, &main_eligible, &side_pots, &main_winners, &side_winners);
        assert_eq!(distributed, 201);
        assert_eq!(stacks, vec![1101, 1100]);
    }

    #[test]
    fn test_distribute_with_side_pot() {
        // 主池 100（P0/P1 eligible），side pot 50（仅 P1 eligible）
        // P0 赢主池，P1 赢 side pot
        let mut stacks = vec![1000, 1000];
        let main_pot = 100;
        let main_eligible = vec![0, 1];
        let side_pots = vec![SidePot::new(50, vec![1])];
        let main_winners = vec![0];
        let side_winners = vec![vec![1]];

        let distributed =
            distribute_pots(&mut stacks, main_pot, &main_eligible, &side_pots, &main_winners, &side_winners);
        assert_eq!(distributed, 150);
        assert_eq!(stacks, vec![1100, 1050]);
    }

    #[test]
    fn test_distribute_rejects_ineligible_winner() {
        // P0 不在 side pot eligible 列表，但被错误地标记为 side winner → 跳过该 pot
        let mut stacks = vec![1000, 1000];
        let main_pot = 0;
        let main_eligible = vec![];
        let side_pots = vec![SidePot::new(100, vec![1])]; // 仅 P1 eligible
        let main_winners: Vec<u8> = vec![];
        let side_winners = vec![vec![0]]; // 错误：P0 不 eligible

        let distributed =
            distribute_pots(&mut stacks, main_pot, &main_eligible, &side_pots, &main_winners, &side_winners);
        assert_eq!(distributed, 0); // 被跳过
        assert_eq!(stacks, vec![1000, 1000]);
    }

    #[test]
    fn test_side_pot_borsh_roundtrip() {
        let pot = SidePot::new(150, vec![0, 2, 3]);
        let bytes = borsh::to_vec(&pot).unwrap();
        let recovered: SidePot = borsh::from_slice(&bytes).unwrap();
        assert_eq!(pot, recovered);
    }
}
