//! 差分对拍向量生成器（方案 C，`.trae/documents/rust-to-lean-proof-schemes.md`）。
//!
//! 用确定性 PRNG 生成随机输入，运行**真实 Rust 实现**得到期望输出，写入
//! `$ZCHAIN_DIFF_DIR`（默认 `/tmp/zchain_diff`）下的 `cases.txt` / `expected.txt`。
//! Lean 侧 runner（`poker_lean/Differential/Main.lean`）读取同一份 `cases.txt`，
//! 用 `PokerLean.State` 模型求值并与 `expected.txt` 逐行比对。
//!
//! 覆盖域（与 Lean 镜像的纯算法层一致）：
//! - `B`  ：BettingRound 全部 7 个方法（chips_to_call / can_* / available_actions
//!          / process_call / process_raise 成功与错误分支）
//! - `SP` ：calculate_side_pots（poker_settlement_core 单一事实源；
//!          仅生成模型内输入：等长、Σbets ≤ MAX_TOTAL_BET）
//! - `EB` ：evaluate_best 5..=7 张（含部分重复牌）
//! - `EBP`：evaluate_best < 5 张的 0 填充路径（已知 Lean 镜像花色不循环，探针）
//! - `W`  ：find_winners
//!
//! 运行：`cargo test -p poker_l1 --lib differential -- --nocapture`

use crate::vm::contracts::texas_poker::betting::BettingRound;
use crate::vm::contracts::texas_poker::card::Card;
use crate::vm::contracts::texas_poker::hand_evaluator::{evaluate_best, find_winners};
use crate::vm::contracts::texas_poker::side_pot::{calculate_side_pots, SidePotError};

use std::fmt::Write as _;

/// xorshift64* 确定性 PRNG：固定种子，CI 可复现，无外部依赖。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `[0, n)` 均匀取值（要求 n > 0）。
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
/// 与 constants.rs MAX_TOTAL_BET 一致；SP 用例总下注保持 ≤ 此值（模型内输入）。
const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;
/// SP 用例单注上界：9 座 × 此值 < MAX_TOTAL_BET，保证 Σbets 恒在模型内。
const SP_BET_CAP: u64 = 100_000_000_000_000_000;

/// 混合取值池：边界小额 + 随机中额 + 贴近 10^18 的大额。
fn mixed_amount(rng: &mut Rng, bet_cap: u64) -> u64 {
    match rng.below(4) {
        0 => [0u64, 1, 2, 25, 50, 99, 100, 101, 9900, 10000, 10001][rng.below(11) as usize],
        1 => rng.below(1_000),
        2 => bet_cap - rng.below(10),
        _ => rng.below(bet_cap / 4 + 1),
    }
}

fn diff_dir() -> std::path::PathBuf {
    std::env::var_os("ZCHAIN_DIFF_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("zchain_diff"))
}

#[test]
fn generate_differential_vectors() {
    let dir = diff_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let cases_path = dir.join("cases.txt");
    let expected_path = dir.join("expected.txt");

    let mut rng = Rng::new(SEED);
    let mut cases = String::new();
    let mut expected = String::new();

    let (n_b, n_sp, n_eb, n_w) = (3000usize, 2000, 6000, 1000);

    // ===== B：betting 全方法 =====
    for _ in 0..n_b {
        let cb = mixed_amount(&mut rng, MAX_TOTAL_BET);
        let mr = mixed_amount(&mut rng, MAX_TOTAL_BET);
        let sb = mixed_amount(&mut rng, MAX_TOTAL_BET);
        let stack = mixed_amount(&mut rng, MAX_TOTAL_BET);
        // total_bet 围绕 cb / sb / (sb+stack) 边界扰动 + 纯随机
        let tb = match rng.below(4) {
            0 => cb + rng.below(3),
            1 => sb + rng.below(3),
            2 => sb + stack + rng.below(3),
            _ => mixed_amount(&mut rng, MAX_TOTAL_BET),
        };
        writeln!(cases, "B {cb} {mr} {sb} {stack} {tb}").unwrap();

        let r = BettingRound {
            current_bet: cb,
            min_raise: mr,
        };
        let ctc = r.chips_to_call(sb);
        let cc = r.can_check(sb) as u8;
        let cl = r.can_call(sb, stack) as u8;
        let cr = r.can_raise(sb, stack) as u8;
        let aa = r.available_actions(sb, stack);
        let pc = r.process_call(sb, stack);
        let mut rr = r;
        let (rok, rcb, rmr, rneeded) = match rr.process_raise(tb, sb, stack) {
            Ok(needed) => (1, rr.current_bet, rr.min_raise, needed),
            Err(_) => (0, 0, 0, 0),
        };
        writeln!(expected, "{ctc} {cc} {cl} {cr} {aa} {pc} {rok} {rcb} {rmr} {rneeded}").unwrap();
    }

    // ===== SP：calculate_side_pots（模型内输入）=====
    for _ in 0..n_sp {
        let n = rng.below(10) as usize; // 0..=9
        // 10% 注入全同额（触发重复 level 路径），10% 高度不均
        let bets: Vec<u64> = if n >= 2 && rng.below(10) == 0 {
            let v = rng.below(SP_BET_CAP / n as u64 + 1);
            vec![v; n]
        } else {
            (0..n).map(|_| mixed_amount(&mut rng, SP_BET_CAP)).collect()
        };
        let folded: Vec<bool> = (0..n).map(|_| rng.coin()).collect();
        let all_in: Vec<bool> = (0..n).map(|_| rng.coin()).collect();

        let mut line = format!("SP {n}");
        for b in &bets {
            write!(line, " {b}").unwrap();
        }
        for f in &folded {
            write!(line, " {}", *f as u8).unwrap();
        }
        for a in &all_in {
            write!(line, " {}", *a as u8).unwrap();
        }
        writeln!(cases, "{line}").unwrap();

        let out = match calculate_side_pots(&bets, &folded, &all_in) {
            Ok(res) => {
                let mut s = format!("1 {}", res.pots.len());
                for p in &res.pots {
                    write!(s, " {} {}", p.amount, p.eligible_seats).unwrap();
                }
                s
            }
            Err(SidePotError::LengthMismatch) => "0 1".to_string(),
            Err(SidePotError::BetOverflow) => "0 2".to_string(),
        };
        writeln!(expected, "{out}").unwrap();
    }

    // ===== EB / EBP：evaluate_best（0..=7 张，含少量重复牌）=====
    for case_i in 0..n_eb {
        let n = if case_i % 6 == 0 {
            rng.below(5) as usize // EBP：<5 张填充路径
        } else {
            5 + rng.below(3) as usize // EB：5..=7
        };
        let tag = if n < 5 { "EBP" } else { "EB" };
        let mut cards: Vec<Card> = Vec::with_capacity(n);
        for _ in 0..n {
            cards.push(Card::from_index(rng.below(52) as u8));
        }
        // 20% 注入一张重复牌（非法局面但函数是全函数，镜像必须一致）
        if n >= 2 && rng.below(5) == 0 {
            let i = rng.below(n as u64) as usize;
            let j = rng.below(n as u64) as usize;
            cards[i] = cards[j];
        }

        let mut line = format!("{tag} {n}");
        for c in &cards {
            write!(line, " {}", c.to_index()).unwrap();
        }
        writeln!(cases, "{line}").unwrap();

        let hr = evaluate_best(&cards);
        let k = &hr.kickers;
        writeln!(
            expected,
            "{} {} {} {} {} {}",
            hr.category, k[0], k[1], k[2], k[3], k[4]
        )
        .unwrap();
    }

    // ===== W：find_winners =====
    for _ in 0..n_w {
        let m = 1 + rng.below(9) as usize; // 1..=9
        let mut hands: Vec<(u8, Vec<Card>)> = Vec::with_capacity(m);
        let mut line = format!("W {m}");
        for (seat, i) in (0..m).enumerate() {
            // 多数 7 张（真实 showdown），少数 5..=6 / <5
            let k = if rng.below(4) == 0 {
                rng.below(7) as usize
            } else {
                7
            };
            let cards: Vec<Card> = (0..k).map(|_| Card::from_index(rng.below(52) as u8)).collect();
            write!(line, " {i} {k}").unwrap();
            for c in &cards {
                write!(line, " {}", c.to_index()).unwrap();
            }
            hands.push((seat as u8, cards));
        }
        writeln!(cases, "{line}").unwrap();

        let winners = find_winners(&hands);
        let mut out = format!("{}", winners.len());
        for w in &winners {
            write!(out, " {w}").unwrap();
        }
        writeln!(expected, "{out}").unwrap();
    }

    std::fs::write(&cases_path, &cases).unwrap();
    std::fs::write(&expected_path, &expected).unwrap();
    println!("differential vectors: {} cases -> {}", n_b + n_sp + n_eb + n_w, dir.display());
    println!("  cases:   {}", cases_path.display());
    println!("  expected: {}", expected_path.display());
}
