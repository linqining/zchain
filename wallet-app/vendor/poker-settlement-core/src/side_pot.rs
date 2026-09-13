//! Texas Poker 边池分层算法（自 poker_l1 `side_pot.rs` 逐字搬运，行为等价）。
//!
//! 逐层切片 all-in 玩家的 bet 水位，构造多个 [`SidePot`]。
//!
//! # 电路友好设计
//!
//! - `eligible_seats` 用 `u16` 位掩码（MAX_PLAYERS=9，9 bit 足够），第 j 位为 1
//!   表示 seat j eligible。定长、无动态分配、无 panic 路径。
//! - [`SidePotResult::pots`] 统一为单一 vec（含主池作为 `pots[0]`）。
//! - 无单层溢出保护（`sum_bets` 已做全局上界校验，单层 pot 必然 <= total）。

use borsh::{BorshDeserialize, BorshSerialize};

use crate::plan::{MAX_PLAYERS, MAX_TOTAL_BET};

// ========== 位掩码辅助 ==========

/// 构造 eligible 位掩码：第 j 位置 1。
#[must_use]
pub const fn seat_bit(j: u8) -> u16 {
    1u16 << j
}

/// 位掩码工具：测试第 j 位是否置 1。
#[must_use]
pub const fn is_eligible(mask: u16, seat: u8) -> bool {
    (mask & seat_bit(seat)) != 0
}

// ========== 数据结构 ==========

/// 单层 pot（主池或边池）。
///
/// `eligible_seats` 为 `u16` 位掩码：第 j 位为 1 表示 seat j 有资格争夺该层。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SidePot {
    /// 该层 pot 总金额。
    pub amount: u64,
    /// 有资格争夺该层 pot 的座位位掩码（bit j = 1 → seat j eligible）。
    pub eligible_seats: u16,
}

impl SidePot {
    /// 构造新 SidePot。
    #[must_use]
    pub const fn new(amount: u64, eligible_seats: u16) -> Self {
        Self {
            amount,
            eligible_seats,
        }
    }

    /// 判断指定座位是否 eligible。
    #[must_use]
    pub const fn is_eligible(&self, seat: u8) -> bool {
        is_eligible(self.eligible_seats, seat)
    }
}

/// 边池计算错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SidePotError {
    /// 总下注超过 MAX_TOTAL_BET（溢出保护）。
    #[error("total bets exceed MAX_TOTAL_BET, possible overflow")]
    BetOverflow,
    /// bets/folded/all_in 三个向量长度不一致。
    #[error("bets/folded/all_in vectors must have same length")]
    LengthMismatch,
}

/// 边池计算结果。
///
/// `pots` 始终包含主池作为 `pots[0]`（即使无人 all-in 也返回单元素 vec），
/// 消除 main/side 不对称。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidePotResult {
    /// 所有 pot 层（含主池 pots[0]）。
    pub pots: Vec<SidePot>,
}

impl SidePotResult {
    /// 返回所有 pot 层的总额。
    #[must_use]
    pub fn total(&self) -> u64 {
        self.pots.iter().map(|p| p.amount).sum()
    }
}

// ========== 核心算法 ==========

/// 计算边池分层（与 poker_l1 `calculate_side_pots` 行为逐字等价）。
///
/// # 参数
/// - `bets`：每个座位的总下注
/// - `folded`：每个座位是否已 fold
/// - `all_in`：每个座位是否 all-in
///
/// # Errors
/// - [`SidePotError::LengthMismatch`]：向量长度不一致或超过座位容量
/// - [`SidePotError::BetOverflow`]：总下注超过 [`MAX_TOTAL_BET`]
pub fn calculate_side_pots(
    bets: &[u64],
    folded: &[bool],
    all_in: &[bool],
) -> Result<SidePotResult, SidePotError> {
    let n = bets.len();
    if folded.len() != n || all_in.len() != n {
        return Err(SidePotError::LengthMismatch);
    }
    // 运行时座位数不应超过 MAX_PLAYERS（位掩码容量）。
    if n > MAX_PLAYERS as usize {
        return Err(SidePotError::LengthMismatch);
    }

    let total_pot = sum_bets(bets)?;

    // 收集 all-in 水位并升序排序（不去重，循环内 level<=prev_level 自然跳过）。
    let mut levels: Vec<u64> = (0..n)
        .filter(|&j| all_in[j] && bets[j] > 0)
        .map(|j| bets[j])
        .collect();
    levels.sort_unstable();

    let mut pots: Vec<SidePot> = Vec::new();
    let mut prev_level: u64 = 0;

    // 逐层切片（含最外层：levels 末尾之后的超额部分由最后的 push 兜底）。
    for &level in &levels {
        if level <= prev_level {
            continue;
        }
        let (amount, eligible) = slice_layer(bets, folded, prev_level, level, n);
        push_or_merge(&mut pots, amount, eligible);
        prev_level = level;
    }

    // 最外层：超出最大 all-in 水位的贡献。
    if prev_level < total_pot {
        let (amount, eligible) = slice_layer(bets, folded, prev_level, u64::MAX, n);
        push_or_merge(&mut pots, amount, eligible);
    }

    // 若所有层 eligible 都为空（全员 fold 的极端情况），仍保留一个 pot 持有总额。
    if pots.is_empty() {
        pots.push(SidePot::new(total_pot, 0));
    }

    Ok(SidePotResult { pots })
}

/// 切片单层：计算 [prev_level, level) 区间内各座位的贡献总额与 eligible 位掩码。
///
/// `level = u64::MAX` 表示最外层（取全部超额部分）。
fn slice_layer(bets: &[u64], folded: &[bool], prev_level: u64, level: u64, n: usize) -> (u64, u16) {
    let mut amount: u64 = 0;
    let mut eligible: u16 = 0;
    for j in 0..n {
        let bet = bets[j];
        if bet > prev_level {
            // contribution = min(bet, level) - prev_level（bet > prev_level 保证不下溢）
            let cap = if bet < level { bet } else { level };
            amount += cap - prev_level;
            if !folded[j] {
                eligible |= seat_bit(j as u8);
            }
        }
    }
    (amount, eligible)
}

/// push 前判断：若 eligible 为空且 pots 非空，金额累加到最后一层。
fn push_or_merge(pots: &mut Vec<SidePot>, amount: u64, eligible: u16) {
    if amount == 0 {
        return;
    }
    if eligible == 0 && !pots.is_empty() {
        // 所有贡献者都 fold：金额并入最后一层。
        pots.last_mut().expect("pots 非空").amount += amount;
    } else {
        pots.push(SidePot::new(amount, eligible));
    }
}

/// 计算总下注（含上界校验）。
fn sum_bets(bets: &[u64]) -> Result<u64, SidePotError> {
    let mut total: u64 = 0;
    for &bet in bets {
        total = total.checked_add(bet).ok_or(SidePotError::BetOverflow)?;
        if total > MAX_TOTAL_BET {
            return Err(SidePotError::BetOverflow);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eligible_vec(mask: u16) -> Vec<u8> {
        (0..16).filter(|&j| is_eligible(mask, j)).collect()
    }

    #[test]
    fn no_all_in_single_pot() {
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
    fn single_all_in_two_pots() {
        let bets = vec![50, 100];
        let folded = vec![false, false];
        let all_in = vec![true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 2);
        assert_eq!(result.pots[0].amount, 100);
        assert_eq!(result.pots[1].amount, 50);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![1]);
    }

    #[test]
    fn multi_level_all_in_with_folded_contributor() {
        // P0 fold 已下注 30，P1 all-in 100，P2 call 100 → 单层 230，eligible [1,2]
        let bets = vec![30, 100, 100];
        let folded = vec![true, false, false];
        let all_in = vec![false, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 1);
        assert_eq!(result.pots[0].amount, 230);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![1, 2]);
    }

    #[test]
    fn empty_eligible_layer_merges_into_last() {
        let bets = vec![50, 200, 200];
        let folded = vec![false, true, true];
        let all_in = vec![true, false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(result.pots.len(), 1);
        assert_eq!(result.pots[0].amount, 450);
    }

    #[test]
    fn all_in_bets_same_level_collapse() {
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
    fn length_mismatch_and_overflow_rejected() {
        let bets = vec![100, 100];
        assert_eq!(
            calculate_side_pots(&bets, &[false], &[false, false]),
            Err(SidePotError::LengthMismatch)
        );
        assert_eq!(
            calculate_side_pots(&[MAX_TOTAL_BET, 1], &[false, false], &[false, false]),
            Err(SidePotError::BetOverflow)
        );
    }

    #[test]
    fn side_pot_borsh_roundtrip() {
        let pot = SidePot::new(150, seat_bit(0) | seat_bit(2) | seat_bit(3));
        let bytes = borsh::to_vec(&pot).unwrap();
        let recovered: SidePot = borsh::from_slice(&bytes).unwrap();
        assert_eq!(pot, recovered);
    }
}
