//! Texas Poker 状态机推进（移植自 `texas_poker_move/sources/table.move` 内部函数）。
//!
//! 本模块实现桌台状态机的所有状态转换逻辑，包括：
//! - 洗牌协议（join_and_shuffle / submit_shuffle_v2 / advance_shuffle）
//! - 揭示协议（start_*_reveal_phase / check_reveal_phase_complete）
//! - 重构协议（start_reconstruct / on_complete_reconstruct）
//! - 下注流程（post_blinds / start_betting_round / advance_turn / advance_round）
//! - 玩家动作（fold / check / call / raise / leave_with_proof）
//! - 结算与重置（settle_hand / end_without_showdown / reset_for_next_hand）
//! - 超时驱动（tick / on_*_timeout）
//!
//! # ZK 验证策略（Phase 4 移植）
//!
//! 所有 proof verify 经 host syscall 完成（`zkvm_guest_sdk::syscalls::verify_*`）。
//! guest 端将 proof + inputs 序列化为 length-prefixed buffer，调用 syscall 委托验证。
//! skip 标志保留（dev chain 可跳过），mainnet 由 governance 强制 false。
//!
//! # 调用约定
//!
//! 所有公开函数签名：
//! ```text
//! fn apply_xxx(table: &mut TexasPokerTable, ..., events: &mut Vec<TexasPokerEvent>) -> StateMachineResult<T>
//! ```
//! - `events` 由调用方（dispatch.rs）创建并传入，函数内通过 `events::emit_event` 追加
//! - 任何状态变更后调用 `table.bump_version()`
//! - 错误用 `StateMachineError::Serialization` 包裹（带上下文 message）

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use zkvm_guest_sdk::bls::{ElGamalCiphertext, G1Point, Scalar};
use zkvm_guest_sdk::syscalls;

use super::betting::{BettingError, BettingRound};
use super::card::{Card, PlayingCard};
use super::constants::*;
use super::events::{
    self, TexasPokerEvent, DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE,
    DECK_REBUILT_REASON_SHUFFLE_TIMEOUT, POT_TYPE_MAIN, POT_TYPE_SIDE, TRIGGER_ACTION_CALL_ALL_IN,
    TRIGGER_ACTION_RAISE_ALL_IN,
};
use super::side_pot;
use super::types::{
    Address, DecryptedCard, ECPoint, ECScalar, ObjectID, ReconstructPlayerDeck, RevealAssignment,
    RevealTokenData, Seat, TexasPokerTable, OWNER_SEAT_PUBLIC,
};
use super::utils::{
    self, g1_add, g1_equal, g1_generator, g1_identity, g1_is_identity, g1_mul, g1_sub,
    generate_plaintext_cards, hash_to_scalar, scalar_from_u64, serialize_g1,
};

// ========== 错误类型 ==========

/// 状态机错误类型（替代 `PokerL1Error`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateMachineError {
    /// 序列化/反序列化或状态校验错误。
    Serialization(String),
    /// 下注逻辑错误。
    Betting(BettingError),
}

impl From<BettingError> for StateMachineError {
    fn from(e: BettingError) -> Self {
        Self::Betting(e)
    }
}

pub type StateMachineResult<T> = Result<T, StateMachineError>;

// ========== Proof 序列化辅助（Phase 4） ==========

/// 追加 length-prefixed bytes 到 buffer。
fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// 追加 Borsh 序列化的 ciphertexts 到 buffer。
fn push_ciphertexts(buf: &mut Vec<u8>, cts: &[ElGamalCiphertext]) {
    let bytes = borsh::to_vec(cts).unwrap_or_default();
    push_len_prefixed(buf, &bytes);
}

/// 追加 Borsh 序列化的 G1 points 到 buffer。
fn push_g1_points(buf: &mut Vec<u8>, points: &[G1Point]) {
    let serialized: Vec<[u8; 48]> = points.iter().map(|p| serialize_g1(p)).collect();
    let bytes = borsh::to_vec(&serialized).unwrap_or_default();
    push_len_prefixed(buf, &bytes);
}

/// 追加单个 G1 compressed bytes 到 buffer（无长度前缀，固定 48B）。
fn push_g1(buf: &mut Vec<u8>, p: &G1Point) {
    buf.extend_from_slice(&serialize_g1(p));
}

// ========== 工具：bytes↔G1 转换（typed 化后大部分不再需要） ==========

// 注：types.rs 字段已 typed 化为 G1Point / ElGamalCiphertext，
// 原 `bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1` 已删除。
// 残余 RPC 边界转换直接使用 `utils::parse_g1` / `utils::serialize_g1`。

// ========== 状态谓词 ==========

/// 是否处于 ROUND_WAITING（允许 join/leave）。
#[must_use]
pub fn can_join_state(table: &TexasPokerTable) -> bool {
    table.round_state == ROUND_WAITING
}

/// `can_leave_state` 与 `can_join_state` 同义。
#[must_use]
pub fn can_leave_state(table: &TexasPokerTable) -> bool {
    can_join_state(table)
}

/// 是否处于下注轮（betting_round.is_some() 且 round 在 preflop..=river）。
#[must_use]
pub fn is_betting_round(table: &TexasPokerTable) -> bool {
    table.betting_round.is_some()
        && matches!(
            table.round_state,
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
        )
}

/// 是否处于"游戏中"（非 WAITING 或任一协议 phase != NONE）。
#[must_use]
pub fn is_playing(table: &TexasPokerTable) -> bool {
    table.round_state != ROUND_WAITING
        || table.shuffle_state.phase != SHUFFLE_PHASE_NONE
        || table.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE
        || table.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE
}

/// 当前是否轮到指定座位行动。
#[must_use]
pub fn is_player_turn(table: &TexasPokerTable, seat_index: u8) -> bool {
    table.current_turn == Some(seat_index)
}

/// 是否在列表中。
#[must_use]
pub fn is_in_list(list: &[u8], value: u8) -> bool {
    list.iter().any(|&v| v == value)
}

/// 是否已注册 pk（occupied 且 pk 匹配）。
#[must_use]
pub fn is_pk_registered(seats: &[Seat], pk: &G1Point) -> bool {
    seats
        .iter()
        .any(|s| s.is_occupied() && &s.pk == pk)
}

// ========== 座位/玩家辅助 ==========

/// 统计活跃玩家数（occupied && !folded && !is_waiting）。
#[must_use]
pub fn count_active_players(seats: &[Seat]) -> u8 {
    seats
        .iter()
        .filter(|s| s.is_occupied() && !s.folded && !s.is_waiting)
        .count() as u8
}

/// 统计活跃占用座位数（occupied && !is_waiting，含 folded）。
#[must_use]
pub fn count_active_occupied(seats: &[Seat]) -> u8 {
    seats
        .iter()
        .filter(|s| s.is_occupied() && !s.is_waiting)
        .count() as u8
}

/// 取所有 occupied && !is_waiting 的座位索引。
#[must_use]
pub fn get_active_seat_indices(seats: &[Seat]) -> Vec<u8> {
    seats
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_occupied() && !s.is_waiting)
        .map(|(i, _)| i as u8)
        .collect()
}

/// 取 occupied && !is_waiting && !in completed 的座位索引（待洗牌者）。
#[must_use]
pub fn get_pending_seat_indices(completed: &[u8], seats: &[Seat]) -> Vec<u8> {
    seats
        .iter()
        .enumerate()
        .filter(|(i, s)| {
            s.is_occupied() && !s.is_waiting && !is_in_list(completed, *i as u8)
        })
        .map(|(i, _)| i as u8)
        .collect()
}

/// 环形查找下一个可行动座位（occupied && !folded && !all_in && !waiting）。
#[must_use]
pub fn find_next_active_seat(seats: &[Seat], from: u8, max: u8) -> Option<u8> {
    let n = seats.len() as u8;
    for offset in 1..=n {
        let idx = (from + offset) % max.min(n);
        let s = &seats[idx as usize];
        if s.is_occupied() && !s.folded && !s.all_in && !s.is_waiting {
            return Some(idx);
        }
    }
    None
}

/// 是否存在可行动玩家（occupied && !folded && !all_in && !waiting）。
#[must_use]
pub fn has_actionable_player(seats: &[Seat]) -> bool {
    seats
        .iter()
        .any(|s| s.is_occupied() && !s.folded && !s.all_in && !s.is_waiting)
}

/// 从 list 中移除首个匹配项（不报错）。
pub fn remove_from_pending(list: &mut Vec<u8>, value: u8) {
    if let Some(pos) = list.iter().position(|&v| v == value) {
        list.swap_remove(pos);
    }
}

// ========== PK 聚合 ==========

/// 将 pk 加入聚合 pk：None + pk = Some(pk)；Some(old) + pk = Some(old + pk)。
///
/// typed 化后 `aggregated_pk: Option<G1Point>`，不再使用字节表示。
fn add_pk_to_aggregated(old: Option<&G1Point>, new_pk: &G1Point) -> Option<G1Point> {
    match old {
        None => Some(*new_pk),
        Some(old_pt) => Some(g1_add(old_pt, new_pk)),
    }
}

/// 从聚合 pk 移除 pk：None 直接返回 None；Some(old) - pk 返回 Some(old - pk) 或 None（若为单位元）。
///
/// 若结果为单位元，返回 None（与 Move 端"空 Vec"语义一致）。
fn remove_pk_from_aggregated(old: Option<&G1Point>, pk: &G1Point) -> Option<G1Point> {
    let old_pt = old?;
    let diff = g1_sub(old_pt, pk);
    if g1_is_identity(&diff) {
        None
    } else {
        Some(diff)
    }
}

// ========== 牌组管理 ==========

/// 初始化加密牌组：每张牌密文 = (G, plaintext_i)，相当于 sk=0 加密。
///
/// 镜像 `table.move::set_initial_encrypted_deck`（line 1121-1142）。
/// 仅覆写 `deck_state.encrypted` 和 `deck_state.plaintext`。
pub fn set_initial_encrypted_deck(table: &mut TexasPokerTable) -> StateMachineResult<()> {
    let plaintexts = generate_plaintext_cards(); // 52 个 G1
    let g = g1_generator();

    table.deck_state.encrypted = plaintexts
        .iter()
        .map(|m| {
            // c1 = G, c2 = m
            ElGamalCiphertext { c1: g, c2: *m }
        })
        .collect();
    // Vec<G1Point> → Vec<ECPoint>（types.rs 字段使用 ECPoint newtype 以支持 Borsh）
    table.deck_state.plaintext = plaintexts.into_iter().map(ECPoint::from).collect();
    table.deck_state.cards_dealt = 0;
    table.deck_state.decrypted_cards.clear();
    Ok(())
}

/// 从 reconstruct 玩家提交的 deck 重建新 deck（累加所有 player_decks）。
///
/// 算法（`table.move::rebuild_deck_from_reconstruct_deck` line 1144-1198）：
/// - 初始 `new_cts[j] = (G, plaintext_j)`
/// - 对每个 player_deck p：`new_cts[j].c1 += p.c1[j]`, `new_cts[j].c2 += p.c2[j] - plaintext_j`
fn rebuild_deck_from_reconstruct_deck(table: &mut TexasPokerTable) -> StateMachineResult<()> {
    let n = table.deck_state.plaintext.len();
    if n == 0 {
        return Err(StateMachineError::Serialization(
            "rebuild_deck: plaintext 为空".into(),
        ));
    }

    // 初始 (G, plaintext_j)
    let g = g1_generator();
    let mut new_cts: Vec<ElGamalCiphertext> = (0..n)
        .map(|j| {
            // ECPoint → G1Point（Deref 后 copy）
            let m: G1Point = table.deck_state.plaintext[j].into();
            Ok::<_, StateMachineError>(ElGamalCiphertext { c1: g, c2: m })
        })
        .collect::<StateMachineResult<_>>()?;

    // 累加每个 player_deck
    for deck in &table.reconstruct_state.player_decks {
        for j in 0..n {
            let p_ct = &deck.output_cts[j];
            new_cts[j] = ElGamalCiphertext {
                c1: g1_add(&new_cts[j].c1, &p_ct.c1),
                c2: g1_add(&new_cts[j].c2, &p_ct.c2),
            };
        }
    }

    // 减去 plaintext_j（恢复正确语义）
    for j in 0..n {
        let m: G1Point = table.deck_state.plaintext[j].into();
        new_cts[j] = ElGamalCiphertext {
            c1: new_cts[j].c1,
            c2: g1_sub(&new_cts[j].c2, &m),
        };
    }

    table.deck_state.encrypted = new_cts;
    table.deck_state.cards_dealt = 0;
    table.deck_state.decrypted_cards.clear();
    Ok(())
}

// ========== 庄家位与盲注 ==========

/// 移动庄家位到下一 occupied seat。
fn move_button(table: &mut TexasPokerTable) {
    let n = table.max_players;
    for offset in 1..=n {
        let idx = (table.button + offset) % n;
        if table.seats[idx as usize].is_occupied() {
            table.button = idx;
            return;
        }
    }
}

/// 投盲注，返回 (sb_seat, bb_seat, first_to_act)。
///
/// 镜像 `table.move::post_blinds`（line 2672-2710）：
/// - heads-up（2 人）：SB=button, BB=button+1, first_to_act=BB
/// - 否则：SB=button+1, BB=SB+1, first_to_act=BB+1
fn post_blinds(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) -> (u8, u8, u8) {
    let n = table.max_players;
    let active = count_active_occupied(&table.seats);
    let (sb_seat, bb_seat, first_to_act) = if active == 2 {
        // heads-up: SB=button, BB=next
        let sb = table.button;
        let bb = (sb + 1) % n;
        (sb, bb, bb) // BB 先行动
    } else {
        let sb = (table.button + 1) % n;
        let bb = (sb + 1) % n;
        let first = (bb + 1) % n;
        (sb, bb, first)
    };

    let sb_amt = table.small_blind.min(table.seats[sb_seat as usize].stack);
    let bb_amt = table.big_blind.min(table.seats[bb_seat as usize].stack);

    let sb_seat_idx = sb_seat as usize;
    let bb_seat_idx = bb_seat as usize;
    table.seats[sb_seat_idx].stack -= sb_amt;
    table.seats[sb_seat_idx].bet = sb_amt;
    table.seats[sb_seat_idx].total_bet += sb_amt;
    if table.seats[sb_seat_idx].stack == 0 {
        table.seats[sb_seat_idx].all_in = true;
    }

    table.seats[bb_seat_idx].stack -= bb_amt;
    table.seats[bb_seat_idx].bet = bb_amt;
    table.seats[bb_seat_idx].total_bet += bb_amt;
    if table.seats[bb_seat_idx].stack == 0 {
        table.seats[bb_seat_idx].all_in = true;
    }

    events::emit_event(
        events,
        TexasPokerEvent::BlindsPosted {
            table_id: table.id,
            sb_seat,
            bb_seat,
            sb_amount: sb_amt,
            bb_amount: bb_amt,
            first_to_act: first_to_act,
        },
    );
    (sb_seat, bb_seat, first_to_act)
}

/// 启动下注轮。
///
/// 镜像 `table.move::start_betting_round`（line 2715-2762）。
fn start_betting_round(
    table: &mut TexasPokerTable,
    is_preflop: bool,
    events: &mut Vec<TexasPokerEvent>,
) {
    let bb = table.big_blind;
    let round = if is_preflop {
        BettingRound::new_preflop(bb)
    } else {
        // postflop 清零 seat.bet
        for s in &mut table.seats {
            s.bet = 0;
        }
        BettingRound::new_postflop(bb)
    };
    table.betting_round = Some(round);

    // 关键修复：每个新下注轮开始时重置所有座位的 acted_this_round 标记。
    // 否则上一轮的 acted 标记会泄漏到下一轮，导致 is_betting_complete 误判
    // （例如 preflop raise 后 Alice.acted=true，flop 开始时未重置，
    //  Bob check 后 is_betting_complete 检测到 Alice 已 acted 且 bet 匹配，
    //  错误地认为本轮下注完成并提前 advance_round）。
    for s in &mut table.seats {
        s.acted_this_round = false;
    }

    // 选第一个可行动玩家作为 current_turn（preflop=first_to_act 即 button 后第三个位置）
    let start_seat = if is_preflop {
        // first_to_act 已在 post_blinds 中确定，用 button+2 后第一个可行动
        let n = table.max_players;
        let candidate = if count_active_occupied(&table.seats) == 2 {
            // heads-up preflop: button(SB) 先行动
            table.button
        } else {
            (table.button + 3) % n
        };
        Some(candidate)
    } else {
        // postflop: button 后第一个可行动玩家
        find_next_active_seat(&table.seats, table.button, table.max_players)
    };

    set_current_turn(table, start_seat, events);

    // 检查全员 all-in 死锁（无可行动玩家）
    if !has_actionable_player(&table.seats) {
        collect_bets_to_pot(table, events);
        advance_round(table, events);
        return;
    }

    events::emit_event(
        events,
        TexasPokerEvent::BettingRoundStarted {
            table_id: table.id,
            round_state: table.round_state,
            current_bet: table.betting_round.as_ref().map_or(0, |b| b.current_bet),
            min_raise: bb,
            first_to_act: start_seat.unwrap_or(0),
            pot_before: table.pot,
        },
    );
}

// ========== 行动轮换 ==========

/// 设置当前行动玩家。
fn set_current_turn(
    table: &mut TexasPokerTable,
    turn: Option<u8>,
    events: &mut Vec<TexasPokerEvent>,
) {
    let old = table.current_turn;
    table.current_turn = turn;
    table.timestamps.betting_started_at = 0; // 清零，由 tick 重新设置
    events::emit_event(
        events,
        TexasPokerEvent::CurrentTurnChanged {
            table_id: table.id,
            old_turn: old,
            new_turn: turn,
            round_state: table.round_state,
        },
    );
}

/// 检查下注轮是否完成。
///
/// 所有可行动玩家（occupied && !folded && !all_in && !waiting）都已 acted 且 bet == current_bet。
fn is_betting_complete(table: &TexasPokerTable) -> bool {
    let cb = match &table.betting_round {
        Some(b) => b.current_bet,
        None => return true,
    };
    for s in &table.seats {
        if s.is_occupied() && !s.folded && !s.all_in && !s.is_waiting {
            if !s.acted_this_round || s.bet != cb {
                return false;
            }
        }
    }
    true
}

/// 推进到下一行动玩家，若下注完成则 collect + advance_round。
fn advance_turn(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    if is_betting_complete(table) {
        collect_bets_to_pot(table, events);
        advance_round(table, events);
        return;
    }
    let cur = table.current_turn.unwrap_or(0);
    let next = find_next_active_seat(&table.seats, cur, table.max_players);
    set_current_turn(table, next, events);
}

/// 收集本轮 bet 到 pot。
fn collect_bets_to_pot(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let mut collected_seats = Vec::new();
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.bet > 0 {
            table.pot += s.bet;
            s.bet = 0;
            collected_seats.push(i as u8);
        }
    }
    if !collected_seats.is_empty() {
        events::emit_event(
            events,
            TexasPokerEvent::PotCollected {
                table_id: table.id,
                round_state: table.round_state,
                pot_after: table.pot,
                collected_from_seats: collected_seats,
            },
        );
    }
}

/// 推进到下一轮（preflop→flop→turn→river→showdown）。
///
/// 镜像 `table.move::advance_round`（line 2855-2886）。
fn advance_round(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let from = table.round_state;
    let to = match from {
        ROUND_PREFLOP => {
            table.round_state = ROUND_FLOP;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 3, REVEAL_PHASE_FLOP, events);
            ROUND_FLOP
        }
        ROUND_FLOP => {
            table.round_state = ROUND_TURN;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 1, REVEAL_PHASE_TURN, events);
            ROUND_TURN
        }
        ROUND_TURN => {
            table.round_state = ROUND_RIVER;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 1, REVEAL_PHASE_RIVER, events);
            ROUND_RIVER
        }
        ROUND_RIVER => {
            table.round_state = ROUND_SHOWDOWN;
            table.timestamps.showdown_at = 0;
            start_showdown_reveal_phase(table, events);
            ROUND_SHOWDOWN
        }
        _ => return, // 不该到达
    };

    // 清空 betting_round
    table.betting_round = None;
    set_current_turn(table, None, events);

    events::emit_event(
        events,
        TexasPokerEvent::RoundAdvanced {
            table_id: table.id,
            from_round: from,
            to_round: to,
            pot: table.pot,
            community_cards_count: table.community_cards.len() as u64,
        },
    );
}

// ========== 洗牌协议 ==========

/// 推进洗牌流程：选下一洗牌者，或完成洗牌进入下一阶段。
///
/// 镜像 `table.move::advance_shuffle`（line 2920-2970）。
fn advance_shuffle(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let phase = table.shuffle_state.phase;
    if phase != SHUFFLE_PHASE_RECONSTRUCT && phase != SHUFFLE_PHASE_BEFORE_PREFLOP {
        return;
    }

    if table.shuffle_state.pending_players.is_empty() {
        // 洗牌完成
        let completed_count = table.shuffle_state.completed_players.len() as u64;
        let deck_size = table.deck_state.encrypted.len() as u64;
        events::emit_event(
            events,
            TexasPokerEvent::ShuffleComplete {
                table_id: table.id,
                phase,
                participant_count: completed_count,
                deck_size,
            },
        );
        table.shuffle_state = super::types::ShuffleState::default();
        table.timestamps.shuffle_started_at = 0;

        match phase {
            SHUFFLE_PHASE_BEFORE_PREFLOP => {
                table.timestamps.reveal_started_at = 0;
                table.round_state = ROUND_PREFLOP;
                start_preflop_reveal_phase(table, events);
            }
            SHUFFLE_PHASE_RECONSTRUCT => {
                // reconstruct 后按当前 round_state 重启对应 reveal phase
                table.reconstruct_state = super::types::ReconstructState::default();
                table.reveal_token_state = super::types::RevealTokenState::default();
                restart_reveal_after_reconstruct(table, events);
            }
            _ => {}
        }
        return;
    }

    // 选下一洗牌者
    let next = table.shuffle_state.pending_players[0];
    table.shuffle_state.current_shuffler = Some(next);
    table.timestamps.shuffle_started_at = 0;
    events::emit_event(
        events,
        TexasPokerEvent::ShuffleTurn {
            table_id: table.id,
            seat_index: next,
            pending_count: table.shuffle_state.pending_players.len() as u64,
            completed_count: table.shuffle_state.completed_players.len() as u64,
        },
    );
}

/// reconstruct 后根据当前 round_state 重启对应 reveal phase。
fn restart_reveal_after_reconstruct(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    match table.round_state {
        ROUND_PREFLOP => start_preflop_reveal_phase(table, events),
        ROUND_FLOP => {
            let pending = count_pending_community_cards(table);
            if pending < 3 {
                start_community_reveal_phase(table, 3 - pending, REVEAL_PHASE_FLOP, events);
            }
        }
        ROUND_TURN => {
            let pending = count_pending_community_cards(table);
            if pending < 4 {
                start_community_reveal_phase(table, 4 - pending, REVEAL_PHASE_TURN, events);
            }
        }
        ROUND_RIVER => {
            let pending = count_pending_community_cards(table);
            if pending < 5 {
                start_community_reveal_phase(table, 5 - pending, REVEAL_PHASE_RIVER, events);
            }
        }
        ROUND_SHOWDOWN => start_showdown_reveal_phase(table, events),
        _ => {}
    }
}

/// 超时后重建牌组并重启洗牌。
fn rebuild_deck_and_shuffle_on_timeout(
    table: &mut TexasPokerTable,
    phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    set_initial_encrypted_deck(table)?;
    let active = get_active_seat_indices(&table.seats);
    table.shuffle_state = super::types::ShuffleState {
        phase,
        current_shuffler: None,
        pending_players: active,
        completed_players: vec![],
    };
    events::emit_event(
        events,
        TexasPokerEvent::DeckRebuilt {
            table_id: table.id,
            reason: DECK_REBUILT_REASON_SHUFFLE_TIMEOUT,
            deck_size: table.deck_state.encrypted.len() as u64,
        },
    );
    Ok(())
}

// ========== Reveal 协议 ==========

/// 启动 preflop reveal phase：给每个活跃玩家发 2 张手牌。
///
/// 镜像 `table.move::start_preflop_reveal_phase`（line 2974-3017）。
fn start_preflop_reveal_phase(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let active_seats = get_active_seat_indices(&table.seats);
    let mut assignments = Vec::new();
    let mut card_idx = table.deck_state.cards_dealt;

    for &seat in &active_seats {
        for _ in 0..CARDS_PER_PLAYER {
            // pending_players = 除牌主外的所有活跃玩家（牌主不为自己提交 reveal token）
            let pending: Vec<u8> = active_seats.iter().copied().filter(|&s| s != seat).collect();
            assignments.push(RevealAssignment {
                encrypted_card_index: card_idx,
                pending_players: pending,
                reveal_tokens: vec![],
                decrypted: false,
            });
            card_idx += 1;
        }
    }

    table.deck_state.cards_dealt = card_idx;
    table.reveal_token_state = super::types::RevealTokenState {
        reveal_phase: REVEAL_PHASE_PREFLOP,
        assignments,
    };
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase: REVEAL_PHASE_PREFLOP,
        },
    );
}

/// 启动公共牌 reveal phase（flop=3, turn=1, river=1）。
///
/// 镜像 `table.move::start_community_reveal_phase`（line 3019-3044）。
fn start_community_reveal_phase(
    table: &mut TexasPokerTable,
    count: u8,
    phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) {
    let active_seats = get_active_seat_indices(&table.seats);
    let mut assignments = Vec::new();
    let mut card_idx = table.deck_state.cards_dealt;

    for _ in 0..count {
        // 所有活跃玩家都要为公共牌提交 token
        let pending: Vec<u8> = active_seats.clone();
        assignments.push(RevealAssignment {
            encrypted_card_index: card_idx,
            pending_players: pending,
            reveal_tokens: vec![],
            decrypted: false,
        });
        card_idx += 1;
    }

    table.deck_state.cards_dealt = card_idx;
    table.reveal_token_state = super::types::RevealTokenState {
        reveal_phase: phase,
        assignments,
    };
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase,
        },
    );
}

/// 启动 showdown reveal phase：每个未 fold 玩家提交自己手牌的 reveal token。
///
/// 镜像 `table.move::start_showdown_reveal_phase`（line 3046-3080）。
fn start_showdown_reveal_phase(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let mut assignments = Vec::new();
    let active_seats = get_active_seat_indices(&table.seats);

    for &seat in &active_seats {
        // 在 decrypted_cards 中找属于该玩家且 ciphertext 仍存在的部分解密手牌
        for dc in &table.deck_state.decrypted_cards {
            // typed 化后 ciphertext 是 Option<ElGamalCiphertext>；is_some 等价于旧的 !is_empty()。
            if dc.owner_seat_index == seat && dc.ciphertext.is_some() {
                // pending = [seat]（只牌主自己提交）
                assignments.push(RevealAssignment {
                    encrypted_card_index: dc.encrypted_card_index,
                    pending_players: vec![seat],
                    reveal_tokens: vec![],
                    decrypted: false,
                });
            }
        }
    }

    table.reveal_token_state = super::types::RevealTokenState {
        reveal_phase: REVEAL_PHASE_SHOWDOWN,
        assignments,
    };
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase: REVEAL_PHASE_SHOWDOWN,
        },
    );
}

/// 统计已解密但未写入 community 的公共牌数。
fn count_pending_community_cards(table: &TexasPokerTable) -> u8 {
    table
        .deck_state
        .decrypted_cards
        .iter()
        .filter(|dc| {
            // typed 化后 plaintext 是 Option<G1Point>；is_some 等价于旧的 !is_empty()。
            dc.owner_seat_index == OWNER_SEAT_PUBLIC && dc.plaintext.is_some()
        })
        .count() as u8
}

/// 检查 reveal phase 是否完成，并推进状态。
///
/// 镜像 `table.move::check_reveal_phase_complete`（line 3106-3156）。
fn check_reveal_phase_complete(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    // 检查所有 assignments 是否已解密
    let all_decrypted = table
        .reveal_token_state
        .assignments
        .iter()
        .all(|a| a.decrypted);
    if !all_decrypted {
        return;
    }

    let phase = table.reveal_token_state.reveal_phase;
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhaseComplete {
            table_id: table.id,
            phase,
        },
    );

    // 先清空 reveal_token_state
    table.reveal_token_state = super::types::RevealTokenState::default();

    match phase {
        REVEAL_PHASE_PREFLOP => {
            table.timestamps.betting_started_at = 0;
            // 投盲注并启动 preflop 下注轮
            let _ = post_blinds(table, events);
            start_betting_round(table, true, events);
        }
        REVEAL_PHASE_FLOP | REVEAL_PHASE_TURN | REVEAL_PHASE_RIVER => {
            write_decrypted_cards_to_community(table, events);
            start_betting_round(table, false, events);
        }
        REVEAL_PHASE_SHOWDOWN => {
            write_decrypted_cards_to_hands(table, events);
            table.timestamps.showdown_at = 0;
            settle_hand(table, events);
        }
        _ => {}
    }
}

/// 将解密的公共牌写入 community_cards。
fn write_decrypted_cards_to_community(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let mut indices = Vec::new();
    let mut ranks = Vec::new();
    let mut suits = Vec::new();

    for dc in &mut table.deck_state.decrypted_cards {
        // typed 化后 plaintext 是 Option<G1Point>；is_some 等价于旧的 !is_empty()。
        if dc.owner_seat_index == OWNER_SEAT_PUBLIC && dc.plaintext.is_some() {
            // 直接通过 encrypted_card_index 反查 Card（plaintext G1 点不可逆）。
            let card = card_from_encrypted_index(dc.encrypted_card_index);
            table.community_cards.push(card);
            indices.push(dc.encrypted_card_index);
            ranks.push(card.rank);
            suits.push(card.suit);
            dc.plaintext = None; // 防重复
        }
    }

    if !indices.is_empty() {
        events::emit_event(
            events,
            TexasPokerEvent::CommunityCardRevealed {
                table_id: table.id,
                phase: table.reveal_token_state.reveal_phase,
                card_indices: indices,
                card_ranks: ranks,
                card_suits: suits,
            },
        );
    }
}

/// 将解密的手牌写入 seat.hand。
fn write_decrypted_cards_to_hands(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    for dc in table.deck_state.decrypted_cards.clone().iter() {
        if dc.owner_seat_index != OWNER_SEAT_PUBLIC
            && dc.plaintext.is_some()
            && (dc.owner_seat_index as usize) < table.seats.len()
        {
            let card = card_from_encrypted_index(dc.encrypted_card_index);
            let seat_idx = dc.owner_seat_index as usize;
            table.seats[seat_idx].hand.push(card);

            if !table.seats[seat_idx].folded {
                events::emit_event(
                    events,
                    TexasPokerEvent::ShowdownHoleCardsRevealed {
                        table_id: table.id,
                        seat_index: dc.owner_seat_index,
                        player: table.seats[seat_idx].player,
                        card_indices: vec![dc.encrypted_card_index],
                        card_ranks: vec![card.rank],
                        card_suits: vec![card.suit],
                    },
                );
            }
        }
    }
}

/// 根据 encrypted_card_index 反查 Card。
///
/// typed 化后 `DecryptedCard` 携带 `encrypted_card_index`，可通过 `% 52` 直接得到 Card。
/// 原 `plaintext_bytes_to_card` 桩函数已删除（G1 点不可逆）。
fn card_from_encrypted_index(idx: u8) -> Card {
    Card::from_index(idx % 52)
}

// ========== 部分解密 ==========

/// 部分解密 c2：`result = c2 - Σ token_point`。
///
/// typed 化后直接接收/返回 G1Point，无需 bytes 转换。
fn partial_decrypt_c2(c2: &G1Point, tokens: &[G1Point]) -> G1Point {
    let mut result = *c2;
    for t in tokens {
        result = g1_sub(&result, t);
    }
    result
}

/// 根据 encrypted_card_index 反查明文 G1 点。
#[allow(dead_code)] // 保留供 future RPC / 测试使用。
fn plaintext_point_by_index(table: &TexasPokerTable, idx: u8) -> StateMachineResult<G1Point> {
    if (idx as usize) >= table.deck_state.plaintext.len() {
        return Err(StateMachineError::Serialization(format!(
            "plaintext index {} out of range {}",
            idx,
            table.deck_state.plaintext.len()
        )));
    }
    Ok(table.deck_state.plaintext[idx as usize].into())
}

// ========== Reconstruct 协议 ==========

/// 启动 reconstruct 流程（玩家超时未提交 reveal token 时触发）。
///
/// 镜像 `table.move::start_reconstruct`（line 1357-1390）。
fn start_reconstruct(table: &mut TexasPokerTable, now_ms: u64, events: &mut Vec<TexasPokerEvent>) {
    let active_seats = get_active_seat_indices(&table.seats);
    // 生成 coefficient = hash_to_scalar("reconstruct_coefficient/" || table_id_bytes || timestamp_ascii)
    let mut input = b"reconstruct_coefficient/".to_vec();
    input.extend_from_slice(&table.id);
    input.extend_from_slice(&utils::u64_to_ascii(now_ms));
    // typed 化后 coefficient 直接存 BlsScalar（Option<BlsScalar>）。
    let coefficient = match hash_to_scalar(&input) {
        Ok(s) => Some(s),
        Err(_) => Some(utils::scalar_one()),
    };

    table.reconstruct_state = super::types::ReconstructState {
        phase: RECONSTRUCT_PHASE_COLLECTING,
        pending_players: active_seats.clone(),
        // BlsScalar → ECScalar（types.rs 字段使用 ECScalar newtype 以支持 Borsh）
        coefficient: coefficient.map(ECScalar::from),
        player_decks: vec![],
    };
    table.timestamps.reconstruct_started_at = now_ms;

    events::emit_event(
        events,
        TexasPokerEvent::ReconstructInitiated {
            table_id: table.id,
            expected_players: active_seats,
            round_state: table.round_state,
        },
    );
}

/// 所有玩家提交 reconstruct deck 完成后的处理。
///
/// 镜像 `table.move::on_complete_reconstruct`（line 1199-1211）。
fn on_complete_reconstruct(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    rebuild_deck_from_reconstruct_deck(table)?;
    table.reconstruct_state = super::types::ReconstructState::default();

    events::emit_event(
        events,
        TexasPokerEvent::ReconstructComplete { table_id: table.id },
    );
    events::emit_event(
        events,
        TexasPokerEvent::DeckRebuilt {
            table_id: table.id,
            reason: DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE,
            deck_size: table.deck_state.encrypted.len() as u64,
        },
    );

    // 重新洗牌（RECONSTRUCT phase）
    let active = get_active_seat_indices(&table.seats);
    table.shuffle_state = super::types::ShuffleState {
        phase: SHUFFLE_PHASE_RECONSTRUCT,
        current_shuffler: None,
        pending_players: active,
        completed_players: vec![],
    };
    advance_shuffle(table, events);
    Ok(())
}

/// reconstruct 超时处理：踢未提交者，按情况推进。
fn on_reconstruct_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    let pending = table.reconstruct_state.pending_players.clone();
    events::emit_event(
        events,
        TexasPokerEvent::ReconstructTimeout {
            table_id: table.id,
            pending_players: pending.clone(),
        },
    );

    for &seat in &pending {
        kick_player_internal(table, seat, KICK_REASON_RECONSTRUCT_TIMEOUT, events);
    }

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events);
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events);
        return Ok(());
    }
    if !table.reconstruct_state.player_decks.is_empty() {
        on_complete_reconstruct(table, events)?;
    } else {
        refund_all_bets(table, events);
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_RECONSTRUCT_FAIL,
                round_state: table.round_state,
            },
        );
    }
    let _ = now_ms;
    Ok(())
}

// ========== 玩家入口动作 ==========

/// 玩家加入并提交首洗（或后续 remask+shuffle）。
///
/// 镜像 `table.move::join_and_shuffle`（line 774-851）。
#[allow(clippy::too_many_arguments)]
pub fn apply_join_and_shuffle(
    table: &mut TexasPokerTable,
    seat_index: u8,
    player: Address,
    buy_in: u64,
    pk: G1Point,
    _pk_ownership_proof: Vec<u8>,
    mask_cards: Vec<ElGamalCiphertext>,
    output_cards: Vec<ElGamalCiphertext>,
    remask_proof: Vec<u8>,
    shuffle_proof: Vec<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if seat_index >= table.max_players {
        return Err(StateMachineError::Serialization(format!(
            "seat_index {seat_index} >= max_players {}",
            table.max_players
        )));
    }
    if table.seats[seat_index as usize].is_occupied() {
        return Err(StateMachineError::Serialization("seat already occupied".into()));
    }
    if !can_join_state(table) {
        return Err(StateMachineError::Serialization(
            "not in WAITING state, cannot join".into(),
        ));
    }
    if table.find_seat(&player).is_some() {
        return Err(StateMachineError::Serialization("player already seated".into()));
    }
    if is_pk_registered(&table.seats, &pk) {
        return Err(StateMachineError::Serialization("pk already registered".into()));
    }
    if buy_in == 0 {
        return Err(StateMachineError::Serialization("buy_in must be > 0".into()));
    }

    let pk_pt = pk;

    // 是否首玩家（deck 为空或全为单位元 placeholder）
    let is_first_player = table.deck_state.encrypted.is_empty()
        || table
            .deck_state
            .encrypted
            .iter()
            .all(|ct| g1_is_identity(&ct.c1) && g1_is_identity(&ct.c2));

    // ZK 验证：pk_ownership（首玩家以外）—— guest 内直接验证（不经 syscall）
    if !is_first_player && !table.config.skip_shuffle() {
        if !utils::verify_pk_ownership(&pk_pt, &_pk_ownership_proof) {
            return Err(StateMachineError::Serialization("pk_ownership failed".into()));
        }
    }

    // typed 化后无需反序列化：Args 字段已是 Vec<ElGamalCiphertext> / DLEqProof / ZKShuffleProof
    let mask_cts = mask_cards;
    let output_cts = output_cards;

    // 首玩家：input = (G, plaintext_i)；后续：input = 当前 deck
    let input_cts: Vec<ElGamalCiphertext> = if is_first_player {
        let g = g1_generator();
        table
            .deck_state
            .plaintext
            .iter()
            .map(|m| ElGamalCiphertext { c1: g, c2: *m })
            .collect()
    } else {
        table.deck_state.encrypted.clone()
    };

    // ZK verify remask (input → mask_cts) — syscall 0x34 kind=0
    if !table.config.skip_remask() {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, &remask_proof);
        push_ciphertexts(&mut buf, &input_cts);
        push_ciphertexts(&mut buf, &mask_cts);
        push_g1(&mut buf, &pk_pt);
        if !syscalls::verify_dleq_proof(0, &buf) {
            return Err(StateMachineError::Serialization("remask proof failed".into()));
        }
    }

    // ZK verify shuffle (mask_cts → output_cts) — syscall 0x34 kind=2，用 new_agg_pk
    // ECPoint → G1Point（types.rs 字段为 Option<ECPoint>，add_pk_to_aggregated 接受 Option<&G1Point>）
    let agg_pk_pt: Option<G1Point> =
        table.deck_state.aggregated_pk.as_ref().map(|p| *p);
    let new_agg_pk = add_pk_to_aggregated(agg_pk_pt.as_ref(), &pk_pt);
    let new_agg_pk_pt = new_agg_pk.unwrap_or(g1_identity());
    if !table.config.skip_shuffle() {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, &shuffle_proof);
        push_ciphertexts(&mut buf, &mask_cts);
        push_ciphertexts(&mut buf, &output_cts);
        push_g1(&mut buf, &new_agg_pk_pt);
        if !syscalls::verify_dleq_proof(2, &buf) {
            return Err(StateMachineError::Serialization("shuffle proof failed".into()));
        }
    }

    // 应用状态变更
    // G1Point → ECPoint（types.rs 字段为 Option<ECPoint>）
    table.deck_state.aggregated_pk = new_agg_pk.map(ECPoint::from);
    table.deck_state.encrypted = output_cts;

    // 初始化座位
    table.seats[seat_index as usize] = Seat {
        player,
        stack: buy_in,
        hand: vec![],
        bet: 0,
        total_bet: 0,
        folded: false,
        all_in: false,
        acted_this_round: false,
        is_waiting: false,
        left_during_hand: false,
        pk: ECPoint::from(pk),
        refunded: false,
    };
    table.chip_pool = table.chip_pool.checked_add(buy_in).ok_or_else(|| {
        StateMachineError::Serialization("chip_pool overflow on join".into())
    })?;

    table.shuffle_state.completed_players.push(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    let active_after = count_active_occupied(&table.seats);
    events::emit_event(
        events,
        TexasPokerEvent::PlayerJoined {
            table_id: table.id,
            seat_index,
            player,
            buy_in,
            is_waiting: false,
            active_count_after: active_after as u64,
        },
    );
    table.bump_version();
    Ok(())
}

/// 后续玩家提交 shuffle（V2：链上注入 c2 += player_pk）。
///
/// 镜像 `table.move::submit_shuffle_v2`（line 1790-1845）。
pub fn apply_submit_shuffle_v2(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    shuffle_proof: Vec<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if table.shuffle_state.phase == SHUFFLE_PHASE_NONE {
        return Err(StateMachineError::Serialization("shuffle phase is NONE".into()));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(StateMachineError::Serialization("seat not occupied".into()));
    }
    if table.shuffle_state.current_shuffler != Some(seat_index) {
        return Err(StateMachineError::Serialization(format!(
            "not shuffler's turn: expected {:?}, got {seat_index}",
            table.shuffle_state.current_shuffler
        )));
    }
    if is_in_list(&table.shuffle_state.completed_players, seat_index) {
        return Err(StateMachineError::Serialization("already completed shuffle".into()));
    }

    // typed 化后无需反序列化
    let output_cts = output_cards;

    // input_cts = 当前 deck（已是 Vec<ElGamalCiphertext>）
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.clone();

    // ECPoint → G1Point（aggregated_pk 字段为 Option<ECPoint>）
    let agg_pk_pt: G1Point = table
        .deck_state
        .aggregated_pk
        .as_ref()
        .map(|p| *p)
        .unwrap_or(g1_identity());
    // ZK verify shuffle — syscall 0x34 kind=2
    if !table.config.skip_shuffle() {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, &shuffle_proof);
        push_ciphertexts(&mut buf, &input_cts);
        push_ciphertexts(&mut buf, &output_cts);
        push_g1(&mut buf, &agg_pk_pt);
        if !syscalls::verify_dleq_proof(2, &buf) {
            return Err(StateMachineError::Serialization("shuffle proof failed".into()));
        }
    }

    // 链上注入：new_cts[i] = add_pk_to_c2(output_cts[i], player_pk)
    // ECPoint → G1Point（Seat.pk 字段为 ECPoint）
    let player_pk: G1Point = table.seats[seat_index as usize].pk.into();
    let new_cts: Vec<ElGamalCiphertext> = output_cts
        .iter()
        .map(|ct| utils::add_pk_to_c2(ct, &player_pk))
        .collect();
    table.deck_state.encrypted = new_cts;

    table.shuffle_state.completed_players.push(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    events::emit_event(
        events,
        TexasPokerEvent::ShuffleVerified {
            table_id: table.id,
            seat_index,
            player: table.seats[seat_index as usize].player,
        },
    );

    advance_shuffle(table, events);
    table.bump_version();
    Ok(())
}

/// 玩家提交 reveal token（批量）。
///
/// 镜像 `table.move::submit_player_reveal_tokens`（line 1900-2064）。
#[allow(clippy::too_many_arguments)]
pub fn apply_submit_player_reveal_tokens(
    table: &mut TexasPokerTable,
    seat_index: u8,
    assignment_indices: Vec<u8>,
    reveal_tokens: Vec<G1Point>,
    proofs: Vec<Vec<u8>>,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if table.reveal_token_state.reveal_phase == REVEAL_PHASE_NONE {
        return Err(StateMachineError::Serialization("reveal phase is NONE".into()));
    }
    if assignment_indices.len() != reveal_tokens.len()
        || assignment_indices.len() != proofs.len()
    {
        return Err(StateMachineError::Serialization(
            "assignment_indices/reveal_tokens/proofs length mismatch".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(StateMachineError::Serialization("seat not occupied".into()));
    }

    let phase = table.reveal_token_state.reveal_phase;
    // ECPoint → G1Point（Seat.pk 字段为 ECPoint）
    let expected_pk: G1Point = table.seats[seat_index as usize].pk.into();

    for k in 0..assignment_indices.len() {
        let ai = assignment_indices[k] as usize;
        if ai >= table.reveal_token_state.assignments.len() {
            return Err(StateMachineError::Serialization(format!(
                "assignment_index {ai} out of range"
            )));
        }
        // 取 assignment 的可变引用前先检查
        {
            let assignment = &table.reveal_token_state.assignments[ai];
            if assignment.decrypted {
                return Err(StateMachineError::Serialization(format!(
                    "assignment {ai} already decrypted"
                )));
            }
            if !is_in_list(&assignment.pending_players, seat_index) {
                return Err(StateMachineError::Serialization(format!(
                    "seat {seat_index} not in pending for assignment {ai}"
                )));
            }
        }

        let card_index = table.reveal_token_state.assignments[ai].encrypted_card_index;
        if card_index as usize >= table.deck_state.encrypted.len() {
            return Err(StateMachineError::Serialization(format!(
                "card_index {card_index} out of range"
            )));
        }

        let encrypted_card = table.deck_state.encrypted[card_index as usize];
        let token = reveal_tokens[k];
        let proof = &proofs[k];

        let token_pt = token;
        // ZK verify reveal token — syscall 0x36
        if !table.config.skip_reveal() {
            let mut buf = Vec::new();
            push_len_prefixed(&mut buf, proof);
            // enc_card: c1||c2（固定 96B）
            buf.extend_from_slice(&serialize_g1(&encrypted_card.c1));
            buf.extend_from_slice(&serialize_g1(&encrypted_card.c2));
            push_g1(&mut buf, &token_pt);
            push_g1(&mut buf, &expected_pk);
            if !syscalls::verify_reveal_token_proof(&buf) {
                return Err(StateMachineError::Serialization("reveal token proof failed".into()));
            }
        }

        // 追加 token + 移除 pending
        {
            let assignment = &mut table.reveal_token_state.assignments[ai];
            // G1Point → ECPoint（RevealTokenData.token 字段为 ECPoint）
            assignment.reveal_tokens.push(RevealTokenData {
                seat_index,
                token: ECPoint::from(token),
            });
            remove_from_pending(&mut assignment.pending_players, seat_index);
        }

        events::emit_event(
            events,
            TexasPokerEvent::RevealTokenSubmitted {
                table_id: table.id,
                seat_index,
                card_index,
                phase,
            },
        );

        // 若 pending 为空，执行链上解密
        let pending_empty = table.reveal_token_state.assignments[ai].pending_players.is_empty();
        if pending_empty {
            let tokens: Vec<G1Point> = table.reveal_token_state.assignments[ai]
                .reveal_tokens
                .iter()
                .map(|d| d.token)
                .collect();
            let c2 = table.deck_state.encrypted[card_index as usize].c2;
            let decrypted_c2 = partial_decrypt_c2(&c2, &tokens);

            if phase == REVEAL_PHASE_SHOWDOWN {
                // 升级已存在的 partial decrypted_card 为 plaintext
                for dc in &mut table.deck_state.decrypted_cards {
                    if dc.encrypted_card_index == card_index && dc.ciphertext.is_some() {
                        let existing_c2 = dc.ciphertext.as_ref().unwrap().c2;
                        let p = g1_sub(&existing_c2, &decrypted_c2);
                        dc.plaintext = Some(ECPoint::from(p));
                        dc.ciphertext = None;
                        break;
                    }
                }
            } else if phase == REVEAL_PHASE_PREFLOP {
                // 部分解密：ciphertext = Some(ElGamalCiphertext { c1, c2: partial })，plaintext = None
                let c1 = table.deck_state.encrypted[card_index as usize].c1;
                let owner = find_hand_card_owner(table, card_index).unwrap_or(OWNER_SEAT_PUBLIC);
                table.deck_state.decrypted_cards.push(DecryptedCard {
                    encrypted_card_index: card_index,
                    owner_seat_index: owner,
                    ciphertext: Some(ElGamalCiphertext {
                        c1,
                        c2: decrypted_c2,
                    }),
                    plaintext: None,
                });
            } else {
                // 公共牌：完全解密
                table.deck_state.decrypted_cards.push(DecryptedCard {
                    encrypted_card_index: card_index,
                    owner_seat_index: OWNER_SEAT_PUBLIC,
                    ciphertext: None,
                    plaintext: Some(ECPoint::from(decrypted_c2)),
                });
            }

            table.reveal_token_state.assignments[ai].decrypted = true;
        }
    }

    check_reveal_phase_complete(table, events);
    table.bump_version();
    Ok(())
}

/// 查找手牌归属（preflop 按 active_seats 顺序）。
fn find_hand_card_owner(table: &TexasPokerTable, card_index: u8) -> Option<u8> {
    let active = get_active_seat_indices(&table.seats);
    // 简化：每次新局从 cards_dealt=0 开始；preflop 发 2*n 张
    let hole_cards_start = 0u8;
    if card_index < hole_cards_start {
        return None;
    }
    let offset = (card_index - hole_cards_start) / CARDS_PER_PLAYER;
    if (offset as usize) < active.len() {
        Some(active[offset as usize])
    } else {
        None
    }
}

/// 玩家提交 reconstruct deck。
///
/// 镜像 `table.move::submit_reconstruct_deck`（line 2218-2275）。
#[allow(clippy::too_many_arguments)]
pub fn apply_submit_reconstruct_deck(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    swap_cards: Vec<ElGamalCiphertext>,
    user_readable_cards: Vec<ElGamalCiphertext>,
    proof: Vec<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if table.reconstruct_state.phase != RECONSTRUCT_PHASE_COLLECTING {
        return Err(StateMachineError::Serialization(
            "reconstruct not in COLLECTING phase".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(StateMachineError::Serialization("seat not occupied".into()));
    }
    if !is_in_list(&table.reconstruct_state.pending_players, seat_index) {
        return Err(StateMachineError::Serialization(
            "seat not in reconstruct pending".into(),
        ));
    }

    // typed 化后无需反序列化：output_cards / swap_cards / user_readable_cards 已是
    // Vec<ElGamalCiphertext>，proof 已是 ReconstructProof<DefaultCurve>。
    let output_cts = output_cards;
    let swap_cts = swap_cards;
    let readable_cts = user_readable_cards;

    let user_pk: G1Point = table.seats[seat_index as usize].pk;
    // ECPoint → G1Point：types.rs 字段已改为 Vec<ECPoint>，需提取内部 G1Point。
    let card_points: Vec<G1Point> = table.deck_state.plaintext.iter().map(|p| *p).collect();

    // ZK verify reconstruct — syscall 0x35
    if !table.config.skip_reconstruct() {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, &proof);
        push_g1_points(&mut buf, &card_points);
        push_ciphertexts(&mut buf, &output_cts);
        push_ciphertexts(&mut buf, &swap_cts);
        push_ciphertexts(&mut buf, &readable_cts);
        push_g1(&mut buf, &user_pk);
        if !syscalls::verify_reconstruct_proof(&buf) {
            return Err(StateMachineError::Serialization("reconstruct proof failed".into()));
        }
    }

    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    table
        .reconstruct_state
        .player_decks
        .push(ReconstructPlayerDeck {
            seat_index,
            output_cts,
        });

    events::emit_event(
        events,
        TexasPokerEvent::ReconstructDeckSubmitted {
            table_id: table.id,
            seat_index,
        },
    );

    if table.reconstruct_state.pending_players.is_empty() {
        on_complete_reconstruct(table, events)?;
    }
    table.bump_version();
    Ok(())
}

/// 玩家离场（带 leave_proof）。
///
/// 镜像 `table.move::leave_with_proof`（line 903-948）。
pub fn apply_leave_with_proof(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    leave_proof: Vec<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if seat_index >= table.max_players {
        return Err(StateMachineError::Serialization("seat_index out of range".into()));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(StateMachineError::Serialization("seat not occupied".into()));
    }
    if !can_leave_state(table) {
        return Err(StateMachineError::Serialization("not in WAITING state".into()));
    }
    if !is_in_list(&table.shuffle_state.completed_players, seat_index) {
        return Err(StateMachineError::Serialization(
            "player must have completed shuffle before leave".into(),
        ));
    }

    // typed 化后无需反序列化。
    let output_cts = output_cards;
    // input_cts = 当前 deck（已是 Vec<ElGamalCiphertext>）。
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.clone();
    let player_pk = table.seats[seat_index as usize].pk;
    // ZK verify leave — syscall 0x34 kind=1
    if !table.config.skip_remask() {
        let mut buf = Vec::new();
        push_len_prefixed(&mut buf, &leave_proof);
        push_ciphertexts(&mut buf, &input_cts);
        push_ciphertexts(&mut buf, &output_cts);
        push_g1(&mut buf, &player_pk);
        if !syscalls::verify_dleq_proof(1, &buf) {
            return Err(StateMachineError::Serialization("leave proof verify failed".into()));
        }
    }

    // remove_pk_from_aggregated 已返回 Option<G1Point>（None 表示结果为单位元/空）。
    let new_agg = remove_pk_from_aggregated(table.deck_state.aggregated_pk.as_ref(), &player_pk);
    table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
    table.deck_state.encrypted = output_cts;

    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);

    let refund = table.seats[seat_index as usize].stack;
    if refund > 0 {
        table.seats[seat_index as usize].stack = 0;
        events::emit_event(
            events,
            TexasPokerEvent::PlayerRefund {
                table_id: table.id,
                seat_index,
                player: table.seats[seat_index as usize].player,
                amount: refund,
                refund_type: REFUND_TYPE_STACK_ONLY,
            },
        );
    }

    let player_addr = table.seats[seat_index as usize].player;
    table.seats[seat_index as usize] = Seat::empty();
    events::emit_event(
        events,
        TexasPokerEvent::PlayerLeft {
            table_id: table.id,
            seat_index,
            player: player_addr,
        },
    );
    table.bump_version();
    Ok(())
}

// ========== 下注动作 ==========

/// 玩家弃牌。
pub fn apply_fold(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    apply_fold_internal(table, seat_index, FOLD_REASON_MANUAL, events)
}

/// 内部 fold 实现（被 apply_fold / on_betting_timeout 共用）。
///
/// 暴露为 pub 供 dispatch.rs 的 auto_fold / force_fold 复用（带不同 reason）。
pub fn apply_fold_internal(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if !is_betting_round(table) {
        return Err(StateMachineError::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(StateMachineError::Serialization("not player's turn".into()));
    }
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded {
        return Err(StateMachineError::Serialization("already folded".into()));
    }

    seat.folded = true;
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerFolded {
            table_id: table.id,
            seat_index,
            reason,
            round_state: table.round_state,
        },
    );

    if count_active_players(&table.seats) <= 1 {
        end_without_showdown(table, events);
        return Ok(());
    }
    advance_turn(table, events);
    table.bump_version();
    Ok(())
}

/// 玩家过牌。
pub fn apply_check(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if !is_betting_round(table) {
        return Err(StateMachineError::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(StateMachineError::Serialization("not player's turn".into()));
    }
    let cb = table.betting_round.as_ref().expect("checked above").current_bet;
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded || seat.all_in {
        return Err(StateMachineError::Serialization("player inactive".into()));
    }
    if seat.bet < cb {
        return Err(StateMachineError::Serialization(
            "cannot check: bet < current_bet".into(),
        ));
    }

    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerChecked {
            table_id: table.id,
            seat_index,
            round_state: table.round_state,
        },
    );

    advance_turn(table, events);
    table.bump_version();
    Ok(())
}

/// 玩家跟注。
pub fn apply_call(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if !is_betting_round(table) {
        return Err(StateMachineError::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(StateMachineError::Serialization("not player's turn".into()));
    }
    let round = table.betting_round.as_ref().expect("checked above").clone();
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded || seat.all_in {
        return Err(StateMachineError::Serialization("player inactive".into()));
    }

    let call_amt = round.process_call(seat.bet, seat.stack);
    seat.stack = seat
        .stack
        .checked_sub(call_amt)
        .ok_or_else(|| StateMachineError::Serialization("stack underflow on call".into()))?;
    seat.bet += call_amt;
    seat.total_bet = seat
        .total_bet
        .checked_add(call_amt)
        .ok_or_else(|| StateMachineError::Serialization("total_bet overflow on call".into()))?;
    let is_all_in = seat.stack == 0 && call_amt > 0;
    if is_all_in {
        seat.all_in = true;
    }
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerCalled {
            table_id: table.id,
            seat_index,
            call_delta: call_amt,
            round_state: table.round_state,
        },
    );
    if is_all_in {
        events::emit_event(
            events,
            TexasPokerEvent::PlayerAllIn {
                table_id: table.id,
                seat_index,
                trigger_action: TRIGGER_ACTION_CALL_ALL_IN,
                amount: call_amt,
                round_state: table.round_state,
            },
        );
    }

    advance_turn(table, events);
    table.bump_version();
    Ok(())
}

/// 玩家加注到 total_bet。
pub fn apply_raise(
    table: &mut TexasPokerTable,
    seat_index: u8,
    total_bet: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if !is_betting_round(table) {
        return Err(StateMachineError::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(StateMachineError::Serialization("not player's turn".into()));
    }
    let seat_bet = table.seats[seat_index as usize].bet;
    let seat_stack = table.seats[seat_index as usize].stack;
    let round = table.betting_round.as_mut().expect("checked above");
    let needed = round.process_raise(total_bet, seat_index, seat_bet, seat_stack)?;

    let seat = &mut table.seats[seat_index as usize];
    seat.stack = seat
        .stack
        .checked_sub(needed)
        .ok_or_else(|| StateMachineError::Serialization("stack underflow on raise".into()))?;
    seat.bet = total_bet;
    seat.total_bet = seat
        .total_bet
        .checked_add(needed)
        .ok_or_else(|| StateMachineError::Serialization("total_bet overflow on raise".into()))?;
    let is_all_in = seat.stack == 0;
    if is_all_in {
        seat.all_in = true;
    }
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    // raise 重置其他可行动玩家
    for (i, s) in table.seats.iter_mut().enumerate() {
        if i as u8 != seat_index
            && s.is_occupied()
            && !s.folded
            && !s.all_in
            && !s.is_waiting
        {
            s.acted_this_round = false;
        }
    }

    events::emit_event(
        events,
        TexasPokerEvent::PlayerRaised {
            table_id: table.id,
            seat_index,
            raise_delta: needed,
            total_bet,
            round_state: table.round_state,
        },
    );
    if is_all_in {
        events::emit_event(
            events,
            TexasPokerEvent::PlayerAllIn {
                table_id: table.id,
                seat_index,
                trigger_action: TRIGGER_ACTION_RAISE_ALL_IN,
                amount: needed,
                round_state: table.round_state,
            },
        );
    }

    advance_turn(table, events);
    table.bump_version();
    Ok(())
}

// ========== 开局 / 超时 / 结算 ==========

/// 开局：投盲注 + 进入 SHUFFLE_PHASE_BEFORE_PREFLOP + 设置 pending_players。
///
/// 镜像 `table.move::start_hand / do_start_hand`（line 1061-1100）。
pub fn start_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    if table.round_state != ROUND_WAITING {
        return Err(StateMachineError::Serialization(format!(
            "not in WAITING state: round_state={}",
            table.round_state
        )));
    }
    if count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START {
        return Err(StateMachineError::Serialization(format!(
            "active players {} < MIN_PLAYERS_TO_START {}",
            count_active_occupied(&table.seats),
            MIN_PLAYERS_TO_START
        )));
    }

    move_button(table);
    set_initial_encrypted_deck(table)?;
    table.timestamps.shuffle_started_at = 0;

    let pending = get_pending_seat_indices(&table.shuffle_state.completed_players, &table.seats);
    table.shuffle_state = super::types::ShuffleState {
        phase: SHUFFLE_PHASE_BEFORE_PREFLOP,
        current_shuffler: None,
        pending_players: pending.clone(),
        completed_players: table.shuffle_state.completed_players.clone(),
    };

    let active = get_active_seat_indices(&table.seats);
    events::emit_event(
        events,
        TexasPokerEvent::HandStarted {
            table_id: table.id,
            button: table.button,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            participants: active,
        },
    );

    advance_shuffle(table, events);
    table.bump_version();
    Ok(())
}

/// 超时驱动（permissionless）。
///
/// 镜像 `table.move::tick`（line 1560-1669）。严格优先级：
/// reconstruct > shuffle > reveal > 正常逻辑 > fallback。
pub fn tick(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    // 1. Reconstruct 优先
    if table.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE {
        let started = table.timestamps.reconstruct_started_at;
        if started > 0 && now_ms >= started + table.timeout_config.reconstruct_timeout_ms {
            on_reconstruct_timeout(table, now_ms, events)?;
        }
        return Ok(());
    }

    // 2. Shuffle 阶段
    let sp = table.shuffle_state.phase;
    if sp == SHUFFLE_PHASE_RECONSTRUCT || sp == SHUFFLE_PHASE_BEFORE_PREFLOP {
        if table.shuffle_state.pending_players.is_empty() {
            advance_shuffle(table, events);
            return Ok(());
        }
        if table.shuffle_state.current_shuffler.is_none() {
            advance_shuffle(table, events);
            return Ok(());
        }
        let started = table.timestamps.shuffle_started_at;
        if started == 0 {
            table.timestamps.shuffle_started_at = now_ms;
            return Ok(());
        }
        if now_ms >= started + table.timeout_config.shuffle_timeout_ms {
            on_shuffle_timeout(table, now_ms, events)?;
        }
        return Ok(());
    }

    // 3. Reveal 阶段
    if table.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE {
        let all_complete = table
            .reveal_token_state
            .assignments
            .iter()
            .all(|a| a.pending_players.is_empty());
        if all_complete {
            check_reveal_phase_complete(table, events);
            return Ok(());
        }
        let started = table.timestamps.reveal_started_at;
        if started == 0 {
            table.timestamps.reveal_started_at = now_ms;
            return Ok(());
        }
        if now_ms >= started + table.timeout_config.reveal_timeout_ms {
            on_reveal_timeout(table, now_ms, events)?;
        }
        return Ok(());
    }

    // 4. 正常逻辑
    if table.round_state == ROUND_WAITING {
        if count_active_occupied(&table.seats) >= MIN_PLAYERS_TO_START {
            start_hand(table, events)?;
        }
        return Ok(());
    }

    if is_betting_round(table) {
        if table.current_turn.is_none() {
            collect_bets_to_pot(table, events);
            advance_round(table, events);
            return Ok(());
        }
        let started = table.timestamps.betting_started_at;
        if started == 0 {
            table.timestamps.betting_started_at = now_ms;
            return Ok(());
        }
        if now_ms >= started + table.timeout_config.betting_timeout_ms {
            on_betting_timeout(table, events)?;
        }
        return Ok(());
    }

    if table.round_state == ROUND_SHOWDOWN {
        if table.timestamps.showdown_at == 0 {
            table.timestamps.showdown_at = now_ms + table.timeout_config.showdown_display_ms;
        } else if now_ms >= table.timestamps.showdown_at {
            settle_hand(table, events);
        }
        return Ok(());
    }

    // 5. Fallback：状态不一致
    if matches!(
        table.round_state,
        ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
    ) && !is_betting_round(table)
    {
        refund_all_bets(table, events);
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_STATE_INCONSISTENT,
                round_state: table.round_state,
            },
        );
    }
    Ok(())
}

/// shuffle 超时处理。
fn on_shuffle_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    let seat = table.shuffle_state.current_shuffler.unwrap_or(0);
    let phase = table.shuffle_state.phase;
    events::emit_event(
        events,
        TexasPokerEvent::ShuffleTimeout {
            table_id: table.id,
            seat_index: seat,
            phase,
            started_at: table.timestamps.shuffle_started_at,
            timeout_ms: table.timeout_config.shuffle_timeout_ms,
        },
    );

    kick_player_internal(table, seat, KICK_REASON_TIMEOUT, events);

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events);
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events);
        return Ok(());
    }
    if table.shuffle_state.phase == SHUFFLE_PHASE_NONE {
        return Ok(());
    }

    rebuild_deck_and_shuffle_on_timeout(table, phase, events)?;
    advance_shuffle(table, events);
    let _ = now_ms;
    Ok(())
}

/// reveal 超时处理：preflop 退款重置；其他阶段启动 reconstruct。
fn on_reveal_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    let phase = table.reveal_token_state.reveal_phase;
    let pending: Vec<u8> = table
        .reveal_token_state
        .assignments
        .iter()
        .flat_map(|a| a.pending_players.iter().copied())
        .collect::<alloc::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    events::emit_event(
        events,
        TexasPokerEvent::RevealTimeout {
            table_id: table.id,
            phase,
            pending_players: pending.clone(),
        },
    );

    for &seat in &pending {
        kick_player_internal(table, seat, KICK_REASON_TIMEOUT, events);
    }

    let active = count_active_players(&table.seats);
    if phase == REVEAL_PHASE_PREFLOP {
        refund_all_bets(table, events);
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_TIMEOUT,
                round_state: table.round_state,
            },
        );
        return Ok(());
    }
    if active <= 1 {
        end_without_showdown(table, events);
        return Ok(());
    }
    start_reconstruct(table, now_ms, events);
    Ok(())
}

/// betting 超时处理：自动 fold。
fn on_betting_timeout(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    let seat = table.current_turn.unwrap_or(0);
    apply_fold_internal(table, seat, FOLD_REASON_AUTO_TIMEOUT, events)
}

/// 单人获胜（无摊牌）。
fn end_without_showdown(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    let winner = table
        .seats
        .iter()
        .enumerate()
        .find(|(_, s)| s.is_occupied() && !s.folded && !s.is_waiting)
        .map(|(i, _)| i as u8);

    if let Some(winner_seat) = winner {
        let pot = table.pot;
        table.seats[winner_seat as usize].stack += pot;
        table.pot = 0;

        events::emit_event(
            events,
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id: table.id,
                winner_seat,
                winner_player: table.seats[winner_seat as usize].player,
                pot,
            },
        );
    }

    let _ = reset_for_next_hand(table, events);
}

/// 摊牌结算。
///
/// 镜像 `table.move::settle_hand`（line 2440-2510）。
fn settle_hand(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    if table.round_state != ROUND_SHOWDOWN {
        return;
    }
    if table.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE {
        return;
    }

    let n = table.seats.len();
    let bets: Vec<u64> = table.seats.iter().map(|s| s.total_bet).collect();
    let folded: Vec<bool> = table.seats.iter().map(|s| s.folded || s.left_during_hand).collect();
    let all_in: Vec<bool> = table.seats.iter().map(|s| s.all_in).collect();

    let result = match side_pot::calculate_side_pots(&bets, &folded, &all_in) {
        Ok(r) => r,
        Err(e) => {
            // guest no_std 无 tracing，静默降级（refund + reset）
            let _ = e;
            refund_all_bets(table, events);
            let _ = reset_for_next_hand(table, events);
            return;
        }
    };

    let main_eligible: Vec<u8> = (0..n as u8)
        .filter(|&i| {
            table.seats[i as usize].is_occupied()
                && !table.seats[i as usize].folded
                && !table.seats[i as usize].is_waiting
        })
        .collect();
    let main_winners = find_winners_in_seats(table, &main_eligible);
    distribute_pot_to_winners(table, result.main_pot, &main_winners, POT_TYPE_MAIN, events);

    let mut all_winners: Vec<u8> = main_winners.clone();
    for sp in &result.side_pots {
        let winners = find_winners_in_seats(table, &sp.eligible_seats);
        distribute_pot_to_winners(table, sp.amount, &winners, POT_TYPE_SIDE, events);
        all_winners.extend(&winners);
    }

    events::emit_event(
        events,
        TexasPokerEvent::HandSettled {
            table_id: table.id,
            pot: result.total(),
            winners: all_winners,
        },
    );

    let _ = reset_for_next_hand(table, events);
}

/// 在指定 eligible seats 中找最佳手牌持有者。
fn find_winners_in_seats(table: &TexasPokerTable, eligible: &[u8]) -> Vec<u8> {
    if eligible.is_empty() {
        return vec![];
    }
    let mut best_rank: Option<super::hand_evaluator::HandRank> = None;
    let mut winners: Vec<u8> = vec![];

    for &seat in eligible {
        let s = &table.seats[seat as usize];
        if s.hand.is_empty() {
            continue;
        }
        let mut cards = s.hand.clone();
        cards.extend_from_slice(&table.community_cards);
        if cards.len() < 7 {
            if winners.is_empty() {
                winners.push(seat);
            }
            continue;
        }
        let rank = super::hand_evaluator::best_hand(&cards);
        match &best_rank {
            None => {
                best_rank = Some(rank.clone());
                winners = vec![seat];
            }
            Some(b) => {
                let cmp = super::hand_evaluator::compare(&rank, b);
                if cmp == 2 {
                    best_rank = Some(rank);
                    winners = vec![seat];
                } else if cmp == 1 {
                    winners.push(seat);
                }
            }
        }
    }
    if winners.is_empty() {
        winners.push(eligible[0]);
    }
    winners
}

/// 将 pot 分配给赢家列表（平局均分，余数给 winners[0]）。
fn distribute_pot_to_winners(
    table: &mut TexasPokerTable,
    pot: u64,
    winners: &[u8],
    pot_type: u8,
    events: &mut Vec<TexasPokerEvent>,
) {
    if winners.is_empty() || pot == 0 {
        return;
    }
    let share = pot / winners.len() as u64;
    let remainder = pot % winners.len() as u64;
    for (idx, &winner) in winners.iter().enumerate() {
        let amount = if idx == 0 { share + remainder } else { share };
        table.seats[winner as usize].stack += amount;
        events::emit_event(
            events,
            TexasPokerEvent::WinnerAwarded {
                table_id: table.id,
                seat_index: winner,
                player: table.seats[winner as usize].player,
                amount,
                pot_type,
                hand_rank: None,
            },
        );
    }
}

/// 退还所有下注（异常路径）。
fn refund_all_bets(table: &mut TexasPokerTable, events: &mut Vec<TexasPokerEvent>) {
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.is_occupied() && !s.folded && !s.left_during_hand && s.total_bet > 0 && !s.refunded {
            s.stack += s.total_bet;
            s.refunded = true;
            events::emit_event(
                events,
                TexasPokerEvent::PlayerRefund {
                    table_id: table.id,
                    seat_index: i as u8,
                    player: s.player,
                    amount: s.total_bet,
                    refund_type: REFUND_TYPE_BET_ONLY,
                },
            );
        }
        s.bet = 0;
        s.total_bet = 0;
    }
    table.pot = 0;
    table.side_pots.clear();
}

/// 重置进入下一局。
///
/// 镜像 `table.move::reset_for_next_hand`（line 3550-3621）。
///
/// 暴露为 pub 供 dispatch 层 `reset_for_next_hand` selector 直接调用，
/// 用于管理员/测试场景下显式重置桌台到 WAITING 状态（正常对局流程中
/// 由 `settle_hand` / `end_without_showdown` / 超时路径内部调用）。
pub fn reset_for_next_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> StateMachineResult<()> {
    // 第一轮：重置 seat 字段；waiting 玩家 pk 加入 aggregated_pk
    for s in &mut table.seats {
        s.hand.clear();
        s.bet = 0;
        s.total_bet = 0;
        s.folded = false;
        s.all_in = false;
        s.acted_this_round = false;
        // typed 化后 pk 是 G1Point；用 is_identity 判断未设置。
        if s.is_waiting && !g1_is_identity(&s.pk) {
            // add_pk_to_aggregated 接受 Option<&G1Point>，返回 Option<G1Point>。
            let new_agg = add_pk_to_aggregated(table.deck_state.aggregated_pk.as_ref(), &s.pk);
            table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
        }
        s.is_waiting = false;
        s.left_during_hand = false;
    }

    // 第二轮：清理 stack==0 的 occupied seat
    let mut to_remove: Vec<u8> = vec![];
    for (i, s) in table.seats.iter().enumerate() {
        if s.is_occupied() && s.stack == 0 {
            to_remove.push(i as u8);
        }
    }
    for &i in &to_remove {
        // G1Point 是 Copy，直接拷贝。
        let pk = table.seats[i as usize].pk;
        let player = table.seats[i as usize].player;
        if !g1_is_identity(&pk) {
            let new_agg =
                remove_pk_from_aggregated(table.deck_state.aggregated_pk.as_ref(), &pk);
            table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
        }
        table.seats[i as usize] = Seat::empty();
        events::emit_event(
            events,
            TexasPokerEvent::PlayerLeft {
                table_id: table.id,
                seat_index: i,
                player,
            },
        );
    }

    if count_active_occupied(&table.seats) == 0 {
        // typed 化后 aggregated_pk 是 Option<G1Point>；用 None 表示空。
        table.deck_state.aggregated_pk = None;
    }

    table.pot = 0;
    table.side_pots.clear();
    table.community_cards.clear();
    table.betting_round = None;
    table.current_turn = None;
    table.round_state = ROUND_WAITING;
    table.deck_state.encrypted.clear();
    table.deck_state.cards_dealt = 0;
    table.deck_state.decrypted_cards.clear();
    table.shuffle_state = super::types::ShuffleState::default();
    table.reveal_token_state = super::types::RevealTokenState::default();
    table.reconstruct_state = super::types::ReconstructState::default();
    table.timestamps = super::types::Timestamps::default();

    set_initial_encrypted_deck(table)?;
    table.bump_version();
    Ok(())
}

/// 踢人内部实现（被 dispatch::kick_player / on_*_timeout 共用）。
///
/// 镜像 `table.move::kick_player_internal`（line 3625-3702）。
/// 暴露为 pub 供 dispatch.rs 直接调用。
pub fn kick_player_internal(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: u8,
    events: &mut Vec<TexasPokerEvent>,
) {
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return;
    }

    let refund_amt = seat.stack;
    let was_waiting = seat.is_waiting;
    // G1Point 是 Copy，无需 clone。
    let pk = seat.pk;
    let player = seat.player;

    table.pot += seat.bet;
    seat.bet = 0;
    seat.stack = 0;
    seat.hand.clear();
    seat.left_during_hand = true;
    seat.folded = true;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.is_waiting = false;
    // typed 化后 pk 是 G1Point；用 identity 表示空。
    seat.pk = g1_identity();

    if !g1_is_identity(&pk) && !was_waiting {
        let new_agg = remove_pk_from_aggregated(table.deck_state.aggregated_pk.as_ref(), &pk);
        table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
    }

    if refund_amt > 0 {
        events::emit_event(
            events,
            TexasPokerEvent::PlayerRefund {
                table_id: table.id,
                seat_index,
                player,
                amount: refund_amt,
                refund_type: REFUND_TYPE_STACK_ONLY,
            },
        );
    }

    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    for a in &mut table.reveal_token_state.assignments {
        remove_from_pending(&mut a.pending_players, seat_index);
    }

    events::emit_event(
        events,
        TexasPokerEvent::PlayerKicked {
            table_id: table.id,
            seat_index,
            player,
            reason,
        },
    );

    let _ = reason;
    if table.shuffle_state.current_shuffler == Some(seat_index) {
        table.shuffle_state.current_shuffler = None;
        let mut tmp_events = Vec::new();
        advance_shuffle(table, &mut tmp_events);
        events.extend(tmp_events);
    }
    if table.current_turn == Some(seat_index) && is_betting_round(table) {
        let active = count_active_players(&table.seats);
        if active <= 1 {
            end_without_showdown(table, events);
        } else {
            advance_turn(table, events);
        }
    }

    if count_active_players(&table.seats) < MIN_PLAYERS_TO_START {
        let _ = reset_for_next_hand(table, events);
    }
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_id() -> ObjectID {
        [0xFF; 32]
    }

    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new(dummy_id(), "test".into(), 4, 50, 100)
    }

    #[test]
    fn test_can_join_state_initial() {
        let table = make_table();
        assert!(can_join_state(&table));
        assert!(can_leave_state(&table));
        assert!(!is_playing(&table));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_set_initial_encrypted_deck() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        assert_eq!(table.deck_state.encrypted.len(), 52);
        assert_eq!(table.deck_state.plaintext.len(), 52);
        for ct in &table.deck_state.encrypted {
            // c1 = G（generator，非 identity）；c2 = plaintext_i（非 identity）。
            assert!(!g1_is_identity(&ct.c1));
            assert!(!g1_is_identity(&ct.c2));
        }
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_is_pk_registered() {
        let mut table = make_table();
        let g = g1_generator();
        let pk = g1_mul(&scalar_from_u64(0xAB), &g);
        assert!(!is_pk_registered(&table.seats, &pk));
        table.seats[0].player = [0x01; 20];
        table.seats[0].pk = ECPoint::from(pk);
        assert!(is_pk_registered(&table.seats, &pk));
        let other_pk = g1_mul(&scalar_from_u64(0xCD), &g);
        assert!(!is_pk_registered(&table.seats, &other_pk));
    }

    #[test]
    fn test_count_active_players() {
        let mut table = make_table();
        assert_eq!(count_active_players(&table.seats), 0);

        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];
        assert_eq!(count_active_players(&table.seats), 2);

        table.seats[0].folded = true;
        assert_eq!(count_active_players(&table.seats), 1);

        table.seats[1].is_waiting = true;
        assert_eq!(count_active_players(&table.seats), 0);
    }

    #[test]
    fn test_get_active_seat_indices() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[2].player = [0x03; 20];
        let active = get_active_seat_indices(&table.seats);
        assert_eq!(active, vec![0, 2]);
    }

    #[test]
    fn test_find_next_active_seat() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[1].player = [0x02; 20];
        table.seats[1].folded = true;
        table.seats[2].player = [0x03; 20];
        let next = find_next_active_seat(&table.seats, 0, 4);
        assert_eq!(next, Some(2));
    }

    #[test]
    fn test_remove_from_pending() {
        let mut list = vec![1, 3, 5, 7];
        remove_from_pending(&mut list, 3);
        assert_eq!(list, vec![1, 7, 5]);
        remove_from_pending(&mut list, 99);
        assert_eq!(list, vec![1, 7, 5]);
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_add_remove_pk_aggregated() {
        let g = g1_generator();
        let pk1 = g1_mul(&scalar_from_u64(111), &g);
        let pk2 = g1_mul(&scalar_from_u64(222), &g);

        // typed 化后 add/remove_pk_to/from_aggregated 接受 Option<&G1Point>，
        // 返回 Option<G1Point>（None = 空/单位元）。
        let agg1 = add_pk_to_aggregated(None, &pk1);
        assert_eq!(agg1, Some(pk1));

        let agg2 = add_pk_to_aggregated(agg1.as_ref(), &pk2);
        let expected = g1_add(&pk1, &pk2);
        assert_eq!(agg2, Some(expected));

        let agg3 = remove_pk_from_aggregated(agg2.as_ref(), &pk1);
        assert_eq!(agg3, Some(pk2));

        let agg4 = remove_pk_from_aggregated(agg3.as_ref(), &pk2);
        assert_eq!(agg4, None);
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_start_hand_requires_min_players() {
        let mut table = make_table();
        let mut events = vec![];
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_err());

        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_err());

        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_ok());
        assert_eq!(table.shuffle_state.phase, SHUFFLE_PHASE_BEFORE_PREFLOP);
        assert!(!table.shuffle_state.pending_players.is_empty());
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_start_hand_initializes_deck() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let mut events = vec![];
        start_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.deck_state.encrypted.len(), 52);
        assert_eq!(table.deck_state.plaintext.len(), 52);
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::HandStarted { .. })));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_tick_advances_shuffle_on_first_call() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let mut events = vec![];
        // 第一次 tick：从 WAITING 触发 start_hand（内部 advance_shuffle 设置
        // current_shuffler，但 shuffle_started_at 被重置为 0）。
        tick(&mut table, 1000, &mut events).unwrap();
        assert_eq!(table.shuffle_state.phase, SHUFFLE_PHASE_BEFORE_PREFLOP);
        assert!(table.shuffle_state.current_shuffler.is_some());
        assert_eq!(table.timestamps.shuffle_started_at, 0);
        // 第二次 tick：进入 shuffle 分支，started_at==0 → 设为 now_ms。
        tick(&mut table, 1000, &mut events).unwrap();
        assert_eq!(table.timestamps.shuffle_started_at, 1000);
    }

    #[test]
    fn test_post_blinds_heads_up() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.button = 0;
        let mut events = vec![];
        let (sb, bb, first) = post_blinds(&mut table, &mut events);
        assert_eq!(sb, 0);
        assert_eq!(bb, 1);
        assert_eq!(first, 1);
        assert_eq!(table.seats[0].bet, 50);
        assert_eq!(table.seats[1].bet, 100);
        assert_eq!(table.seats[0].stack, 950);
        assert_eq!(table.seats[1].stack, 900);
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::BlindsPosted { .. })));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_apply_fold_ends_without_showdown() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new_preflop(100));
        table.current_turn = Some(0);
        table.pot = 200;
        let mut events = vec![];

        apply_fold(&mut table, 0, &mut events).unwrap();
        // fold 后只剩 1 名活跃玩家 → end_without_showdown → reset_for_next_hand
        // 会清掉 folded 标记，故此处仅断言事件与筹码分配。
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::PlayerFolded { .. })));
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::HandEndedWithoutShowdown { .. })));
        assert_eq!(table.seats[1].stack, 1200);
    }

    #[test]
    fn test_apply_call_deducts_stack() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[0].bet = 0;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.seats[1].bet = 100;
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new_preflop(100));
        table.current_turn = Some(0);
        let mut events = vec![];

        apply_call(&mut table, 0, &mut events).unwrap();
        assert_eq!(table.seats[0].stack, 900);
        assert_eq!(table.seats[0].bet, 100);
        assert!(table.seats[0].acted_this_round);
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::PlayerCalled { .. })));
    }

    #[test]
    fn test_apply_raise_resets_others_acted() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.seats[1].bet = 100;
        table.seats[1].acted_this_round = true;
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new_preflop(100));
        table.current_turn = Some(0);
        let mut events = vec![];

        apply_raise(&mut table, 0, 300, &mut events).unwrap();
        assert_eq!(table.seats[0].bet, 300);
        assert_eq!(table.seats[0].stack, 700);
        assert!(!table.seats[1].acted_this_round);
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_reset_for_next_hand_clears_state() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[0].bet = 100;
        table.seats[0].total_bet = 250;
        table.seats[0].folded = true;
        table.pot = 500;
        table.round_state = ROUND_FLOP;
        let mut events = vec![];

        reset_for_next_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.round_state, ROUND_WAITING);
        assert_eq!(table.pot, 0);
        assert_eq!(table.seats[0].bet, 0);
        assert_eq!(table.seats[0].total_bet, 0);
        assert!(!table.seats[0].folded);
        assert!(table.community_cards.is_empty());
        assert_eq!(table.deck_state.encrypted.len(), 52);
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_kick_player_internal_removes_pk() {
        let mut table = make_table();
        let g = g1_generator();
        // 3 个玩家，pk = sk_i * G；aggregated_pk = pk0 + pk1 + pk2。
        let pk0 = g1_mul(&scalar_from_u64(42), &g);
        let pk1 = g1_mul(&scalar_from_u64(43), &g);
        let pk2 = g1_mul(&scalar_from_u64(44), &g);
        let agg = g1_add(&g1_add(&pk0, &pk1), &pk2);

        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;
        table.seats[0].pk = ECPoint::from(pk0);
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 500;
        table.seats[1].pk = ECPoint::from(pk1);
        table.seats[2].player = [0x03; 20];
        table.seats[2].stack = 500;
        table.seats[2].pk = ECPoint::from(pk2);
        table.deck_state.aggregated_pk = Some(ECPoint::from(agg));
        // 用一个非 NONE 的 round_state，使 reset_for_next_hand 不会被触发
        // （count_active_players 在 kick 后仍 >= MIN_PLAYERS_TO_START）。
        table.round_state = ROUND_PREFLOP;
        let mut events = vec![];

        kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events);
        // kick 后 active=2（seat1+seat2），不会触发 reset_for_next_hand。
        assert!(table.seats[0].left_during_hand);
        assert!(table.seats[0].folded);
        assert_eq!(table.seats[0].stack, 0);
        // Seat::empty() 后 pk 为 g1_identity()（默认值）。
        assert!(g1_is_identity(&table.seats[0].pk));
        // aggregated_pk 应 = pk1 + pk2（移除 pk0）。
        let new_agg = table.deck_state.aggregated_pk.unwrap();
        let expected = g1_add(&pk1, &pk2);
        assert!(g1_equal(&new_agg, &expected));
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::PlayerKicked { .. })));
        assert!(events
            .iter()
            .any(|e| matches!(e, TexasPokerEvent::PlayerRefund { .. })));
    }

    #[cfg(target_arch = "riscv32")]
    #[test]
    fn test_partial_decrypt_c2_subtracts_tokens() {
        let g = g1_generator();
        let sk = scalar_from_u64(42);
        let pk = g1_mul(&sk, &g);
        let plaintext = utils::hash_to_g1(b"test_card");
        let r = scalar_from_u64(7);
        let ct = utils::encrypt(&plaintext, &pk, &r);
        let token = utils::gen_reveal_token(&ct, &sk);

        // typed 化后 partial_decrypt_c2 直接接受 G1Point，返回 G1Point。
        let result = partial_decrypt_c2(&ct.c2, &[token]);
        assert!(g1_equal(&result, &plaintext));
    }

    #[test]
    fn test_is_betting_complete() {
        let mut table = make_table();
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new_preflop(100));
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[0].bet = 100;
        table.seats[0].acted_this_round = true;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.seats[1].bet = 100;
        table.seats[1].acted_this_round = true;
        assert!(is_betting_complete(&table));

        table.seats[1].acted_this_round = false;
        assert!(!is_betting_complete(&table));
    }
}
