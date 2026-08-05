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
//! # ZK 验证策略
//!
//! 所有 verify 调用经 `utils::verify_or_skip(table.config.skip_*(), ...)`
//! 包装。dev chain 默认全部 skip，mainnet 由 governance 强制 false。
//!
//! # 调用约定
//!
//! 所有公开函数签名：
//! ```text
//! fn apply_xxx(table: &mut TexasPokerTable, ..., events: &mut Vec<TexasPokerEvent>) -> PokerL1Result<T>
//! ```
//! - `events` 由调用方（dispatch.rs）创建并传入，函数内通过 `events::emit_event` 追加
//! - 任何状态变更后调用 `table.bump_version()`
//! - 错误用 `PokerL1Error::Serialization` 包裹（带上下文 message）

use blstrs::G1Projective;
use group::Group;

use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ECScalar, ElGamalCiphertext};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use poker_protocol::zk_shuffle::reconstruction::{
    ReconstructProofV3, ReconstructionV3Statement, apply_reconstruction_contributions,
    canonical_base_deck,
};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};

use super::betting::{BettingError, BettingRound};
use super::card::{Card, PlayingCard};
use super::constants::*;
use super::events::{
    self, DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE, DECK_REBUILT_REASON_SHUFFLE_TIMEOUT,
    POT_TYPE_MAIN, POT_TYPE_SIDE, TRIGGER_ACTION_CALL_ALL_IN, TRIGGER_ACTION_RAISE_ALL_IN,
    TexasPokerEvent,
};
use super::side_pot;
use super::types::{
    DecryptedCard, EMPTY_PLAYER, OWNER_SEAT_PUBLIC, ReconstructPlayerDeck, RevealAssignment,
    RevealTokenData, Seat, TexasPokerTable,
};
// 适配层（保留原 crypto/ 的自由函数 API：g1_add/g1_equal/verify_or_skip/...）。
// typed 化后字段已是 G1Projective / ElGamalCiphertext，parse_g1/serialize_g1 仅在 RPC 边界使用。
use super::utils::{
    self, g1_add, g1_equal, g1_generator, g1_is_identity, g1_sub, generate_plaintext_cards,
    hash_to_scalar, scalar_from_u64,
};
use crate::error::{PokerL1Error, PokerL1Result};

// ========== 工具：bytes↔G1 转换（typed 化后大部分不再需要） ==========

// 注：types.rs 字段已 typed 化为 G1Projective / ElGamalCiphertext，
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

/// Reconcile the embedded TableVault against every canonical custody bucket.
///
/// `total_bet`, `ante_collected`, `addon_pool` and `side_pots` are accounting views, not
/// additional assets. The actual locked value is represented exactly once by seat stacks,
/// pending addons, current-round bets and the collected pot. `rake_collected` is a transient
/// settlement receipt: its matching value has already left `chip_pool` for the Treasury output
/// and it must be cleared by `reset_for_next_hand` before the table is persisted.
pub fn reconcile_table_vault(table: &TexasPokerTable) -> PokerL1Result<u64> {
    let mut stacks = 0u64;
    let mut pending_addons = 0u64;
    let mut current_bets = 0u64;
    let mut total_bets = 0u64;
    for (index, seat) in table.seats.iter().enumerate() {
        if seat.player == EMPTY_PLAYER
            && (seat.stack != 0 || seat.bet != 0 || seat.total_bet != 0 || seat.pending_addon != 0)
        {
            return Err(PokerL1Error::Other(format!(
                "Texas TableVault has monetary value in empty seat {index}"
            )));
        }
        stacks = stacks
            .checked_add(seat.stack)
            .ok_or_else(|| PokerL1Error::Other("Texas seat stack sum overflow".into()))?;
        pending_addons = pending_addons
            .checked_add(seat.pending_addon)
            .ok_or_else(|| PokerL1Error::Other("Texas pending addon sum overflow".into()))?;
        current_bets = current_bets
            .checked_add(seat.bet)
            .ok_or_else(|| PokerL1Error::Other("Texas current bet sum overflow".into()))?;
        total_bets = total_bets
            .checked_add(seat.total_bet)
            .ok_or_else(|| PokerL1Error::Other("Texas total bet sum overflow".into()))?;
    }
    if pending_addons != table.addon_pool {
        return Err(PokerL1Error::Other(format!(
            "Texas addon ledger mismatch: seats={pending_addons}, addon_pool={}",
            table.addon_pool
        )));
    }

    let wagers_in_custody = table
        .pot
        .checked_add(current_bets)
        .ok_or_else(|| PokerL1Error::Other("Texas wager custody sum overflow".into()))?;
    if wagers_in_custody != total_bets {
        return Err(PokerL1Error::Other(format!(
            "Texas wager ledger mismatch: pot={} current_bets={current_bets}, total_bets={total_bets}",
            table.pot
        )));
    }
    if table.ante_collected > table.pot {
        return Err(PokerL1Error::Other(format!(
            "Texas ante ledger {} exceeds collected pot {}",
            table.ante_collected, table.pot
        )));
    }

    let accounted = stacks
        .checked_add(pending_addons)
        .and_then(|value| value.checked_add(wagers_in_custody))
        .ok_or_else(|| PokerL1Error::Other("Texas TableVault accounting overflow".into()))?;
    if accounted != table.chip_pool {
        return Err(PokerL1Error::Other(format!(
            "Texas TableVault invariant violated: stacks={stacks}, pending_addons={pending_addons}, pot={}, current_bets={current_bets}, accounted={accounted}, chip_pool={}",
            table.pot, table.chip_pool
        )));
    }
    Ok(accounted)
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
pub fn is_pk_registered(seats: &[Seat], pk: &G1Projective) -> bool {
    seats.iter().any(|s| s.is_occupied() && &s.pk.0 == pk)
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
        .filter(|(i, s)| s.is_occupied() && !s.is_waiting && !is_in_list(completed, *i as u8))
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

/// 环形查找下一个参与本局的座位（occupied && !is_waiting）。
///
/// 与 [`find_next_active_seat`] 的区别：**不过滤 folded / all_in**。
/// 用于盲注定位（SB/BB）——盲注阶段所有参与本局的玩家都要投盲注，
/// 即使某玩家理论上已 all-in（实际盲注是第一步，不会有 folded/all_in，
/// 但保持语义清晰：只要参与本局就应被考虑为盲注候选）。
///
/// 这是 P0 修复的核心辅助：传统德州扑克的 SB/BB/UTG 必须顺时针跳过空座位
/// 找下一个参与本局的玩家，不能简单 `(button+k) % n` 取模。
#[must_use]
pub fn find_next_participating_seat(seats: &[Seat], from: u8, max: u8) -> Option<u8> {
    let n = seats.len() as u8;
    for offset in 1..=n {
        let idx = (from + offset) % max.min(n);
        let s = &seats[idx as usize];
        if s.is_occupied() && !s.is_waiting {
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
/// typed 化后 `aggregated_pk: Option<G1Projective>`，不再使用字节表示。
fn add_pk_to_aggregated(old: Option<&G1Projective>, new_pk: &G1Projective) -> Option<G1Projective> {
    match old {
        None => Some(*new_pk),
        Some(old_pt) => Some(g1_add(old_pt, new_pk)),
    }
}

/// 从聚合 pk 移除 pk：None 直接返回 None；Some(old) - pk 返回 Some(old - pk) 或 None（若为单位元）。
///
/// 若结果为单位元，返回 None（与 Move 端"空 Vec"语义一致）。
fn remove_pk_from_aggregated(
    old: Option<&G1Projective>,
    pk: &G1Projective,
) -> Option<G1Projective> {
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
pub fn set_initial_encrypted_deck(table: &mut TexasPokerTable) -> PokerL1Result<()> {
    let plaintexts = generate_plaintext_cards(); // 52 个 G1
    let g = g1_generator();

    table.deck_state.encrypted = plaintexts
        .iter()
        .map(|m| {
            // c1 = G, c2 = m
            ElGamalCiphertext { c1: g, c2: *m }
        })
        .collect();
    // Vec<G1Projective> → Vec<ECPoint>（types.rs 字段使用 ECPoint newtype 以支持 Borsh）
    table.deck_state.plaintext = plaintexts.into_iter().map(ECPoint::from).collect();
    table.deck_state.cards_dealt = 0;
    table.deck_state.decrypted_cards.clear();
    Ok(())
}

/// Rebuild a fresh aggregate-key deck from verified V3 contributions.
///
/// The base is the deterministic canonical encryption of every public card
/// under the table aggregate key. Each player contributes one canonical-slot
/// vector whose plaintexts are proven to be either zero or `-card[i]`.
fn rebuild_deck_from_reconstruct_deck(table: &mut TexasPokerTable) -> PokerL1Result<()> {
    let aggregate_pk = table.deck_state.aggregated_pk.as_ref().ok_or_else(|| {
        PokerL1Error::Serialization("rebuild_deck V3 requires aggregate public key".into())
    })?;
    let cards = table
        .deck_state
        .plaintext
        .iter()
        .map(|card| card.0)
        .collect::<Vec<_>>();
    let mut new_cts = canonical_base_deck::<DefaultCurve>(&cards, &aggregate_pk.0)
        .map_err(|error| PokerL1Error::Serialization(format!("rebuild_deck V3 base: {error}")))?;
    for deck in &table.reconstruct_state.player_decks {
        new_cts = apply_reconstruction_contributions::<DefaultCurve>(&new_cts, &deck.output_cts)
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "rebuild_deck V3 contribution for seat {}: {error}",
                    deck.seat_index
                ))
            })?;
    }

    table.deck_state.encrypted = new_cts;
    // reconstruct 重建的是一副全新牌组，与旧 deck 的 index 空间无关。
    // 新 deck 必须从 index=0 开始顺序发牌（见 restart_reveal_after_reconstruct
    // 的注释），因此重置 cards_dealt=0。
    //
    // 已发出的旧牌不依赖新 deck 的 index：
    // - 已解出的公共牌明文存于 community_cards（不依赖 index）
    // - 已部分解密的手牌记录（decrypted_cards 中 ciphertext.is_some() 者）
    //   自包含 partial c2，showdown 解密时不访问 deck_state.encrypted（见
    //   apply_submit_player_reveal_tokens 的 showdown 分支）
    // 因此保留 decrypted_cards（不清空），仅重置 cards_dealt。
    table.deck_state.cards_dealt = 0;
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
/// 镜像 `table.move::post_blinds`（line 2672-2710），并修正座位定位（P0-1）：
/// - **heads-up（2 人）**：SB=button，BB=顺时针下一个参与本局的座位，
///   first_to_act=BB（heads-up preflop BB 先行动）。
/// - **非 heads-up**：SB=顺时针下一个参与本局的座位，BB=SB 之后的下一个，
///   first_to_act 返回 BB 之后的参考座位（实际 first-to-act 由
///   `start_betting_round` 用 `find_next_active_seat(seats, bb, n)` 精确定位）。
///
/// # P0-1 修复
///
/// 原实现用 `(button+k) % n` 直接取模定位 SB/BB，不跳过空座位。
/// 当 button 与 BB 之间存在空座位时，盲注会落到空座位（stack=0，盲注失效）。
/// 现统一用 `find_next_participating_seat` 顺时针跳过空座位定位。
fn post_blinds(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<(u8, u8, u8)> {
    let n = table.max_players;
    let active = count_active_occupied(&table.seats);
    let (sb_seat, bb_seat) = if active == 2 {
        // heads-up: SB=button, BB=顺时针下一个参与本局的座位
        let sb = table.button;
        let bb = find_next_participating_seat(&table.seats, sb, n).unwrap_or(sb);
        (sb, bb)
    } else {
        // 非 heads-up: SB=button 之后第一个参与本局的座位，BB=SB 之后下一个
        let sb =
            find_next_participating_seat(&table.seats, table.button, n).unwrap_or(table.button);
        let bb = find_next_participating_seat(&table.seats, sb, n).unwrap_or(sb);
        (sb, bb)
    };
    // first_to_act 仅作事件参考，实际由 start_betting_round 基于 BB 精确定位。
    let first_to_act = bb_seat;

    let sb_amt = table.small_blind.min(table.seats[sb_seat as usize].stack);
    let bb_amt = table.big_blind.min(table.seats[bb_seat as usize].stack);

    let sb_seat_idx = sb_seat as usize;
    let bb_seat_idx = bb_seat as usize;
    table.seats[sb_seat_idx].stack = table.seats[sb_seat_idx]
        .stack
        .checked_sub(sb_amt)
        .ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: sb stack -= sb_amt underflow".into())
        })?;
    table.seats[sb_seat_idx].bet = sb_amt;
    table.seats[sb_seat_idx].total_bet = table.seats[sb_seat_idx]
        .total_bet
        .checked_add(sb_amt)
        .ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: sb total_bet += sb_amt overflow".into())
        })?;
    if table.seats[sb_seat_idx].stack == 0 {
        table.seats[sb_seat_idx].all_in = true;
    }

    table.seats[bb_seat_idx].stack = table.seats[bb_seat_idx]
        .stack
        .checked_sub(bb_amt)
        .ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: bb stack -= bb_amt underflow".into())
        })?;
    table.seats[bb_seat_idx].bet = bb_amt;
    table.seats[bb_seat_idx].total_bet = table.seats[bb_seat_idx]
        .total_bet
        .checked_add(bb_amt)
        .ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: bb total_bet += bb_amt overflow".into())
        })?;
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
    Ok((sb_seat, bb_seat, first_to_act))
}

/// 启动下注轮。
///
/// 镜像 `table.move::start_betting_round`（line 2715-2762），并修正 first-to-act 定位（P0-2/P0-3）。
///
/// # 参数
/// - `is_preflop`: 是否 preflop（决定 current_bet 初始化与 first-to-act 规则）。
/// - `bb_seat`: preflop 时传入大盲位座位（用于定位 UTG = BB 之后第一个可行动玩家）；
///   postflop 传 `None`。
///
/// # first-to-act 规则（P0-2/P0-3 修复）
/// - **preflop 非 heads-up**：UTG = BB 之后第一个可行动座位
///   （`find_next_active_seat(seats, bb_seat, n)`），跳过空/folded/all_in 座位。
///   原实现硬编码 `button+3`，不跳过空座位。
/// - **preflop heads-up**：SB(button) 先行动。
/// - **postflop 非 heads-up**：button 之后第一个可行动座位。
/// - **postflop heads-up**：SB(button) 先行动（heads-up postflop 由 button 先行动）。
///   原实现未区分 heads-up，导致 heads-up postflop 行动权反转。
fn start_betting_round(
    table: &mut TexasPokerTable,
    is_preflop: bool,
    bb_seat: Option<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let bb = table.big_blind;
    let round = if is_preflop {
        // Ante goes directly to the pot and does not buy down the amount to call. Only blinds
        // and voluntary wagers participate in the current betting-round price.
        let max_bet = table
            .seats
            .iter()
            .map(|s| s.bet)
            .max()
            .unwrap_or(bb)
            .max(bb);
        let mut r = BettingRound::new(bb, bb);
        r.current_bet = max_bet;
        r
    } else {
        // postflop 清零 seat.bet
        for s in &mut table.seats {
            s.bet = 0;
        }
        BettingRound::new(bb, 0)
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

    let is_heads_up = count_active_occupied(&table.seats) == 2;
    let n = table.max_players;
    // 选第一个可行动玩家作为 current_turn。
    let start_seat = if is_preflop {
        if is_heads_up {
            // heads-up preflop: SB(button) 先行动
            Some(table.button)
        } else {
            // 非 heads-up preflop: UTG = BB 之后第一个可行动座位
            bb_seat
                .filter(|_| !is_heads_up)
                .and_then(|bb| find_next_active_seat(&table.seats, bb, n))
        }
    } else if is_heads_up {
        // heads-up postflop: button(SB) 先行动
        Some(table.button)
    } else {
        // 非 heads-up postflop: button 之后第一个可行动座位
        find_next_active_seat(&table.seats, table.button, n)
    };

    set_current_turn(table, start_seat, events);

    // 检查全员 all-in 死锁（无可行动玩家）
    if !has_actionable_player(&table.seats) {
        collect_bets_to_pot(table, events)?;
        advance_round(table, events)?;
        return Ok(());
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
    Ok(())
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
fn advance_turn(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if is_betting_complete(table) {
        collect_bets_to_pot(table, events)?;
        advance_round(table, events)?;
        return Ok(());
    }
    let cur = table.current_turn.unwrap_or(0);
    let next = find_next_active_seat(&table.seats, cur, table.max_players);
    set_current_turn(table, next, events);
    Ok(())
}

/// 收集本轮 bet 到 pot。
fn collect_bets_to_pot(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let mut collected_seats = Vec::new();
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.bet > 0 {
            table.pot = table.pot.checked_add(s.bet).ok_or_else(|| {
                PokerL1Error::Serialization("collect_bets_to_pot: pot += bet overflow".into())
            })?;
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
    Ok(())
}

/// 推进到下一轮（preflop→flop→turn→river→showdown）。
///
/// 镜像 `table.move::advance_round`（line 2855-2886）。
fn advance_round(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // P1-8 修复：若只剩一名未 fold 玩家（其他人全 fold），无需继续发牌到 showdown，
    // 直接 end_without_showdown 结算。覆盖 advance_round 路径上的"剩一人"场景
    // （fold 路径已在 apply_fold_internal 处理，此处兜底 all-in/advance 后的情形）。
    if count_active_players(&table.seats) <= 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    let from = table.round_state;
    let to = match from {
        ROUND_PREFLOP => {
            table.round_state = ROUND_FLOP;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 3, REVEAL_PHASE_FLOP, events)?;
            ROUND_FLOP
        }
        ROUND_FLOP => {
            table.round_state = ROUND_TURN;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 1, REVEAL_PHASE_TURN, events)?;
            ROUND_TURN
        }
        ROUND_TURN => {
            table.round_state = ROUND_RIVER;
            table.timestamps.reveal_started_at = 0;
            start_community_reveal_phase(table, 1, REVEAL_PHASE_RIVER, events)?;
            ROUND_RIVER
        }
        ROUND_RIVER => {
            table.round_state = ROUND_SHOWDOWN;
            table.timestamps.showdown_at = 0;
            start_showdown_reveal_phase(table, events)?;
            ROUND_SHOWDOWN
        }
        _ => return Ok(()), // 不该到达
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
    Ok(())
}

// ========== 洗牌协议 ==========

/// 推进洗牌流程：选下一洗牌者，或完成洗牌进入下一阶段。
///
/// 镜像 `table.move::advance_shuffle`（line 2920-2970）。
fn advance_shuffle(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let phase = table.shuffle_state.phase;
    if phase != SHUFFLE_PHASE_RECONSTRUCT && phase != SHUFFLE_PHASE_BEFORE_PREFLOP {
        return Ok(());
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
                start_preflop_reveal_phase(table, events)?;
            }
            SHUFFLE_PHASE_RECONSTRUCT => {
                // reconstruct 后按当前 round_state 重启对应 reveal phase
                table.reconstruct_state = super::types::ReconstructState::default();
                table.reveal_token_state = super::types::RevealTokenState::default();
                restart_reveal_after_reconstruct(table, events)?;
            }
            _ => {}
        }
        return Ok(());
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
    Ok(())
}

/// reconstruct 后根据当前 round_state 重启对应 reveal phase。
///
/// # 设计要点
///
/// reconstruct 在某轮 reveal 超时（玩家未提交 reveal token）后触发，由剩余玩家
/// 重新构建牌组（`rebuild_deck_from_reconstruct_deck` 生成全新加密 deck，`cards_dealt`
/// 重置为 0）让牌局继续。重启 reveal phase 的原则：
///
/// 1. **已解出的牌不动**：已写入 `community_cards` 的公共牌、已部分解密存于
///    `decrypted_cards`（`ciphertext.is_some()`）的手牌，都不依赖新 deck 的 index，
///    原样保留。手牌的 partial 记录自包含 c2，showdown 时牌主公开 token 即可解开。
/// 2. **补发缺失的牌**：以 `community_cards.len()` 为基准补齐到当前轮次所需张数，
///    新发的牌从新 deck 的 index=0 开始顺序发出（`cards_dealt` 已被 rebuild 重置）。
///
/// # 各轮次处理
///
/// - PREFLOP：正常流程下 preflop 超时走 refund+reset（见 `on_reveal_timeout`），
///   不会进 reconstruct；此分支为防御性兜底。若走到这里，说明手牌从未成功发出，
///   需清空 `decrypted_cards` 中残留的旧 partial 手牌记录后从新 deck 重发。
/// - FLOP/TURN/RIVER：按 `community_cards.len()` 补发缺失的公共牌。
/// - SHOWDOWN：不补发新牌，直接让各牌主从 `decrypted_cards` 的 partial 记录解手牌。
fn restart_reveal_after_reconstruct(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    match table.round_state {
        ROUND_PREFLOP => {
            // 防御性：清空残留的旧 partial 手牌记录，避免 showdown 时新旧记录并存。
            table.deck_state.decrypted_cards.clear();
            start_preflop_reveal_phase(table, events)?;
        }
        ROUND_FLOP => {
            let have = table.community_cards.len() as u8;
            if have < 3 {
                start_community_reveal_phase(table, 3 - have, REVEAL_PHASE_FLOP, events)?;
            }
        }
        ROUND_TURN => {
            let have = table.community_cards.len() as u8;
            if have < 4 {
                start_community_reveal_phase(table, 4 - have, REVEAL_PHASE_TURN, events)?;
            }
        }
        ROUND_RIVER => {
            let have = table.community_cards.len() as u8;
            if have < 5 {
                start_community_reveal_phase(table, 5 - have, REVEAL_PHASE_RIVER, events)?;
            }
        }
        ROUND_SHOWDOWN => start_showdown_reveal_phase(table, events)?,
        _ => {}
    }
    Ok(())
}

/// 超时后重建牌组并重启洗牌。
fn rebuild_deck_and_shuffle_on_timeout(
    table: &mut TexasPokerTable,
    phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
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
fn start_preflop_reveal_phase(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let active_seats = get_active_seat_indices(&table.seats);
    let mut assignments = Vec::new();
    let mut card_idx = table.deck_state.cards_dealt;

    for &seat in &active_seats {
        for _ in 0..CARDS_PER_PLAYER {
            // pending_players = 除牌主外的所有活跃玩家（牌主不为自己提交 reveal token）
            let pending: Vec<u8> = active_seats
                .iter()
                .copied()
                .filter(|&s| s != seat)
                .collect();
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
    Ok(())
}

/// 启动公共牌 reveal phase（flop=3, turn=1, river=1）。
///
/// 镜像 `table.move::start_community_reveal_phase`（line 3019-3044）。
fn start_community_reveal_phase(
    table: &mut TexasPokerTable,
    count: u8,
    phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
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
    Ok(())
}

/// 启动 showdown reveal phase：每个未 fold 玩家提交自己手牌的 reveal token。
///
/// 镜像 `table.move::start_showdown_reveal_phase`（line 3046-3080）。
fn start_showdown_reveal_phase(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
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
    Ok(())
}

/// 统计已解密但未写入 community 的公共牌数。
#[allow(dead_code)] // P1-7 重构后重启逻辑改为完整重发，此函数暂无调用方，保留供未来增量补发使用。
fn count_pending_community_cards(table: &TexasPokerTable) -> u8 {
    table
        .deck_state
        .decrypted_cards
        .iter()
        .filter(|dc| {
            // typed 化后 plaintext 是 Option<G1Projective>；is_some 等价于旧的 !is_empty()。
            dc.owner_seat_index == OWNER_SEAT_PUBLIC && dc.plaintext.is_some()
        })
        .count() as u8
}

/// 检查 reveal phase 是否完成，并推进状态。
///
/// 镜像 `table.move::check_reveal_phase_complete`（line 3106-3156）。
fn check_reveal_phase_complete(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // 检查所有 assignments 是否已解密
    let all_decrypted = table
        .reveal_token_state
        .assignments
        .iter()
        .all(|a| a.decrypted);
    if !all_decrypted {
        return Ok(());
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
            let (_, bb_seat, _) = post_blinds(table, events)?;
            // 投 ante（若配置）— 在盲注之后、下注轮启动之前
            collect_ante(table, bb_seat, events)?;
            start_betting_round(table, true, Some(bb_seat), events)?;
        }
        REVEAL_PHASE_FLOP | REVEAL_PHASE_TURN | REVEAL_PHASE_RIVER => {
            write_decrypted_cards_to_community(table, phase, events)?;
            start_betting_round(table, false, None, events)?;
        }
        REVEAL_PHASE_SHOWDOWN => {
            write_decrypted_cards_to_hands(table, events)?;
            table.timestamps.showdown_at = 0;
            settle_hand(table, events)?;
        }
        _ => {}
    }
    Ok(())
}

/// 将解密的公共牌写入 community_cards。
fn write_decrypted_cards_to_community(
    table: &mut TexasPokerTable,
    reveal_phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let canonical_cards = generate_plaintext_cards();
    let mut seen = exposed_card_ids(table)?;
    let mut pending = Vec::new();

    for (decrypted_index, dc) in table.deck_state.decrypted_cards.iter().enumerate() {
        if dc.owner_seat_index != OWNER_SEAT_PUBLIC {
            continue;
        }
        let Some(plaintext) = &dc.plaintext else {
            continue;
        };
        let (card_id, card) = card_from_plaintext(&plaintext.0, &canonical_cards)?;
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "duplicate decrypted card id {card_id} while writing community cards"
            )));
        }
        pending.push((decrypted_index, dc.encrypted_card_index, card));
    }

    let mut indices = Vec::new();
    let mut ranks = Vec::new();
    let mut suits = Vec::new();
    for (decrypted_index, encrypted_card_index, card) in pending {
        table.deck_state.decrypted_cards[decrypted_index].plaintext = None;
        table.community_cards.push(card);
        indices.push(encrypted_card_index);
        ranks.push(card.rank);
        suits.push(card.suit);
    }

    if !indices.is_empty() {
        events::emit_event(
            events,
            TexasPokerEvent::CommunityCardRevealed {
                table_id: table.id,
                phase: reveal_phase,
                card_indices: indices,
                card_ranks: ranks,
                card_suits: suits,
            },
        );
    }
    Ok(())
}

/// 将解密的手牌写入 seat.hand。
fn write_decrypted_cards_to_hands(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let canonical_cards = generate_plaintext_cards();
    let mut seen = exposed_card_ids(table)?;
    let mut pending = Vec::new();

    for (decrypted_index, dc) in table.deck_state.decrypted_cards.iter().enumerate() {
        if dc.owner_seat_index == OWNER_SEAT_PUBLIC {
            continue;
        }
        let Some(plaintext) = &dc.plaintext else {
            continue;
        };
        let seat_index = usize::from(dc.owner_seat_index);
        let seat = table.seats.get(seat_index).ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "decrypted hole card owner seat {} is out of range",
                dc.owner_seat_index
            ))
        })?;
        if !seat.is_occupied() {
            return Err(PokerL1Error::Serialization(format!(
                "decrypted hole card owner seat {} is not occupied",
                dc.owner_seat_index
            )));
        }
        let (card_id, card) = card_from_plaintext(&plaintext.0, &canonical_cards)?;
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "duplicate decrypted card id {card_id} while writing hole cards"
            )));
        }
        pending.push((
            decrypted_index,
            dc.owner_seat_index,
            dc.encrypted_card_index,
            card,
        ));
    }

    for (decrypted_index, owner_seat_index, encrypted_card_index, card) in pending {
        table.deck_state.decrypted_cards[decrypted_index].plaintext = None;
        let seat_index = usize::from(owner_seat_index);
        table.seats[seat_index].hand.push(card);
        if !table.seats[seat_index].folded {
            events::emit_event(
                events,
                TexasPokerEvent::ShowdownHoleCardsRevealed {
                    table_id: table.id,
                    seat_index: owner_seat_index,
                    player: table.seats[seat_index].player,
                    card_indices: vec![encrypted_card_index],
                    card_ranks: vec![card.rank],
                    card_suits: vec![card.suit],
                },
            );
        }
    }
    Ok(())
}

/// Match a decrypted plaintext point against the protocol's canonical 52-card domain.
fn card_from_plaintext(
    plaintext: &G1Projective,
    canonical_cards: &[G1Projective],
) -> PokerL1Result<(u8, Card)> {
    let card_id = canonical_cards
        .iter()
        .position(|candidate| g1_equal(candidate, plaintext))
        .ok_or_else(|| {
            PokerL1Error::Serialization(
                "decrypted plaintext is not a canonical Texas Poker card".into(),
            )
        })?;
    let card_id = u8::try_from(card_id)
        .map_err(|_| PokerL1Error::Serialization("canonical card id exceeds u8".into()))?;
    Ok((card_id, Card::from_index(card_id)))
}

/// Collect all already exposed card identities and reject corrupt duplicate state.
fn exposed_card_ids(table: &TexasPokerTable) -> PokerL1Result<std::collections::HashSet<u8>> {
    let mut seen = std::collections::HashSet::new();
    for card in table
        .community_cards
        .iter()
        .chain(table.seats.iter().flat_map(|seat| seat.hand.iter()))
    {
        if !card.is_valid() {
            return Err(PokerL1Error::Serialization(format!(
                "table contains invalid exposed card suit={} rank={}",
                card.suit, card.rank
            )));
        }
        let card_id = card.to_index();
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "table contains duplicate exposed card id {card_id}"
            )));
        }
    }
    Ok(seen)
}

// ========== 部分解密 ==========

/// 部分解密 c2：`result = c2 - Σ token_point`。
///
/// typed 化后直接接收/返回 G1Projective，无需 bytes 转换。
fn partial_decrypt_c2(c2: &G1Projective, tokens: &[G1Projective]) -> G1Projective {
    let mut result = *c2;
    for t in tokens {
        result = g1_sub(&result, t);
    }
    result
}

/// 根据 encrypted_card_index 反查明文 G1 点。
#[allow(dead_code)] // 保留供 future RPC / 测试使用。
fn plaintext_point_by_index(table: &TexasPokerTable, idx: u8) -> PokerL1Result<G1Projective> {
    if (idx as usize) >= table.deck_state.plaintext.len() {
        return Err(PokerL1Error::Serialization(format!(
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
    input.extend_from_slice(&table.id.to_bytes());
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
) -> PokerL1Result<()> {
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
    advance_shuffle(table, events)?;
    Ok(())
}

/// reconstruct 超时处理：踢未提交者，按情况推进。
fn on_reconstruct_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let pending = table.reconstruct_state.pending_players.clone();
    events::emit_event(
        events,
        TexasPokerEvent::ReconstructTimeout {
            table_id: table.id,
            pending_players: pending.clone(),
        },
    );

    for &seat in &pending {
        kick_player_internal(table, seat, KICK_REASON_RECONSTRUCT_TIMEOUT, events)?;
    }

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    if !table.reconstruct_state.player_decks.is_empty() {
        on_complete_reconstruct(table, events)?;
    } else {
        refund_all_bets(table, events)?;
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
    player: crate::Address,
    buy_in: u64,
    pk: G1Projective,
    _pk_ownership_proof: Vec<u8>,
    mask_cards: Vec<ElGamalCiphertext>,
    output_cards: Vec<ElGamalCiphertext>,
    remask_proof: DLEqProof<DefaultCurve, RemaskKind>,
    shuffle_proof: ShuffleProof,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "seat_index {seat_index} >= max_players {}",
            table.max_players
        )));
    }
    if table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat already occupied".into()));
    }
    if !can_join_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot join".into(),
        ));
    }
    if table.find_seat(&player).is_some() {
        return Err(PokerL1Error::Serialization("player already seated".into()));
    }
    if is_pk_registered(&table.seats, &pk) {
        return Err(PokerL1Error::Serialization("pk already registered".into()));
    }
    if buy_in == 0 {
        return Err(PokerL1Error::Serialization("buy_in must be > 0".into()));
    }

    let pk_pt = pk;

    // 是否首玩家（deck 为空或全为单位元 placeholder）
    let is_first_player = table.deck_state.encrypted.is_empty()
        || table
            .deck_state
            .encrypted
            .iter()
            .all(|ct| g1_is_identity(&ct.c1) && g1_is_identity(&ct.c2));

    // ZK 验证：pk_ownership（首玩家以外）
    if !is_first_player {
        let _ = utils::verify_or_skip(table.config.skip_shuffle(), || {
            if !utils::verify_pk_ownership(&pk_pt, &_pk_ownership_proof) {
                return Err(PokerL1Error::Serialization("pk_ownership failed".into()));
            }
            Ok(true)
        })?;
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
            .map(|m| ElGamalCiphertext { c1: g, c2: m.0 })
            .collect()
    } else {
        table.deck_state.encrypted.clone()
    };

    // ZK verify remask (input → mask_cts)
    let _ = utils::verify_or_skip(table.config.skip_remask(), || {
        let mut t = utils::new_mask_shuffle_transcript();
        let ok = DLEqProof::<DefaultCurve, RemaskKind>::verify(
            &remask_proof,
            &input_cts,
            &mask_cts,
            &pk_pt,
            &mut t,
        );
        if ok {
            Ok(true)
        } else {
            Err(PokerL1Error::Serialization("remask proof failed".into()))
        }
    })?;

    // ZK verify shuffle (mask_cts → output_cts)，用 new_agg_pk
    // ECPoint → G1Projective（types.rs 字段为 Option<ECPoint>，add_pk_to_aggregated 接受 Option<&G1Projective>）
    let agg_pk_pt: Option<G1Projective> = table.deck_state.aggregated_pk.as_ref().map(|p| p.0);
    let new_agg_pk = add_pk_to_aggregated(agg_pk_pt.as_ref(), &pk_pt);
    let new_agg_pk_pt = new_agg_pk.unwrap_or(G1Projective::identity());
    let _ = utils::verify_or_skip(table.config.skip_shuffle(), || {
        let mut t = utils::new_mask_shuffle_transcript();
        shuffle_proof
            .verify(&mask_cts, &output_cts, &new_agg_pk_pt, &mut t)
            .map_err(|e| PokerL1Error::Serialization(format!("shuffle proof: {e}")))?;
        Ok(true)
    })?;

    // 应用状态变更
    // G1Projective → ECPoint（types.rs 字段为 Option<ECPoint>）
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
        pending_addon: 0,
        time_bank_ms: super::constants::DEFAULT_TIME_BANK_MS,
        want_leave: false,
    };
    // 全局上界检查：与 addon/rebuy 一致，确保系统总筹码不超过 MAX_TOTAL_BET。
    // 在累加之前检查，避免检查失败后状态已被修改。
    let total_chips = table
        .chip_pool
        .checked_add(buy_in)
        .ok_or_else(|| PokerL1Error::Serialization("join: total chips overflow".into()))?;
    if total_chips > super::constants::MAX_TOTAL_BET {
        return Err(PokerL1Error::Serialization(format!(
            "join: total chips {total_chips} exceeds MAX_TOTAL_BET {}",
            super::constants::MAX_TOTAL_BET
        )));
    }
    table.chip_pool = table
        .chip_pool
        .checked_add(buy_in)
        .ok_or_else(|| PokerL1Error::Serialization("chip_pool overflow on join".into()))?;

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
    shuffle_proof: ShuffleProof,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.shuffle_state.phase == SHUFFLE_PHASE_NONE {
        return Err(PokerL1Error::Serialization("shuffle phase is NONE".into()));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }
    if table.shuffle_state.current_shuffler != Some(seat_index) {
        return Err(PokerL1Error::Serialization(format!(
            "not shuffler's turn: expected {:?}, got {seat_index}",
            table.shuffle_state.current_shuffler
        )));
    }
    if is_in_list(&table.shuffle_state.completed_players, seat_index) {
        return Err(PokerL1Error::Serialization(
            "already completed shuffle".into(),
        ));
    }

    // typed 化后无需反序列化
    let output_cts = output_cards;

    // input_cts = 当前 deck（已是 Vec<ElGamalCiphertext>）
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.clone();

    // ECPoint → G1Projective（aggregated_pk 字段为 Option<ECPoint>）
    let agg_pk_pt: G1Projective = table
        .deck_state
        .aggregated_pk
        .as_ref()
        .map(|p| **p)
        .unwrap_or(G1Projective::identity());
    let _ = utils::verify_or_skip(table.config.skip_shuffle(), || {
        let mut t = utils::new_shuffle_transcript();
        shuffle_proof
            .verify(&input_cts, &output_cts, &agg_pk_pt, &mut t)
            .map_err(|e| PokerL1Error::Serialization(format!("shuffle proof: {e}")))?;
        Ok(true)
    })?;

    // 链上注入：new_cts[i] = add_pk_to_c2(output_cts[i], player_pk)
    // ECPoint → G1Projective（Seat.pk 字段为 ECPoint）
    let player_pk: G1Projective = table.seats[seat_index as usize].pk.into();
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

    advance_shuffle(table, events)?;
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
    reveal_tokens: Vec<G1Projective>,
    proofs: Vec<RevealTokenProof<DefaultCurve>>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.reveal_token_state.reveal_phase == REVEAL_PHASE_NONE {
        return Err(PokerL1Error::Serialization("reveal phase is NONE".into()));
    }
    if assignment_indices.len() != reveal_tokens.len() || assignment_indices.len() != proofs.len() {
        return Err(PokerL1Error::Serialization(
            "assignment_indices/reveal_tokens/proofs length mismatch".into(),
        ));
    }
    if assignment_indices.is_empty() {
        return Err(PokerL1Error::Serialization(
            "reveal token submission must not be empty".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }

    let phase = table.reveal_token_state.reveal_phase;
    // ECPoint → G1Projective（Seat.pk 字段为 ECPoint）
    let expected_pk: G1Projective = table.seats[seat_index as usize].pk.into();

    for k in 0..assignment_indices.len() {
        let ai = assignment_indices[k] as usize;
        if ai >= table.reveal_token_state.assignments.len() {
            return Err(PokerL1Error::Serialization(format!(
                "assignment_index {ai} out of range"
            )));
        }
        // 取 assignment 的可变引用前先检查
        {
            let assignment = &table.reveal_token_state.assignments[ai];
            if assignment.decrypted {
                return Err(PokerL1Error::Serialization(format!(
                    "assignment {ai} already decrypted"
                )));
            }
            if !is_in_list(&assignment.pending_players, seat_index) {
                return Err(PokerL1Error::Serialization(format!(
                    "seat {seat_index} not in pending for assignment {ai}"
                )));
            }
        }

        let card_index = table.reveal_token_state.assignments[ai].encrypted_card_index;

        // 取用于 proof 验证的密文。
        // - showdown：手牌已部分解密，密文存于 decrypted_cards 的 ciphertext 字段
        //   （自包含，与 deck_state.encrypted 解耦）。这点对 reconstruct 后的场景
        //   至关重要：rebuild 后 deck_state.encrypted 是全新 deck，旧 card_index 在
        //   其中指向不同密文，但 partial 记录自包含，proof 验证仍基于原 partial 密文。
        // - 其他阶段（preflop/公共牌）：直接用当前 deck 的密文。
        let encrypted_card = if phase == REVEAL_PHASE_SHOWDOWN {
            table
                .deck_state
                .decrypted_cards
                .iter()
                .find(|dc| dc.encrypted_card_index == card_index && dc.ciphertext.is_some())
                .map(|dc| dc.ciphertext.clone().unwrap())
                .unwrap_or_else(|| table.deck_state.encrypted[card_index as usize])
        } else {
            if card_index as usize >= table.deck_state.encrypted.len() {
                return Err(PokerL1Error::Serialization(format!(
                    "card_index {card_index} out of range"
                )));
            }
            table.deck_state.encrypted[card_index as usize]
        };
        let token = reveal_tokens[k];
        let proof = &proofs[k];

        let token_pt = token;
        let _ = utils::verify_or_skip(table.config.skip_reveal(), || {
            RevealTokenProof::verify(
                proof,
                &encrypted_card,
                &token_pt,
                &expected_pk,
                &mut MerlinTranscript::new(b"reveal_token_proof_v3"),
            )
            .map_err(|e| PokerL1Error::Serialization(format!("reveal token proof: {e:?}")))?;
            Ok(true)
        })?;

        // 追加 token + 移除 pending
        {
            let assignment = &mut table.reveal_token_state.assignments[ai];
            // G1Projective → ECPoint（RevealTokenData.token 字段为 ECPoint）
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
        let pending_empty = table.reveal_token_state.assignments[ai]
            .pending_players
            .is_empty();
        if pending_empty {
            let tokens: Vec<G1Projective> = table.reveal_token_state.assignments[ai]
                .reveal_tokens
                .iter()
                .map(|d| d.token.0)
                .collect();

            if phase == REVEAL_PHASE_SHOWDOWN {
                // 升级已存在的 partial decrypted_card 为 plaintext。
                //
                // 关键（P1-7 续）：partial 手牌记录自包含 `ciphertext.c2`（preflop 时已扣除
                // 其他玩家的 reveal token），showdown 只需在此基础上减去本轮 token
                // （牌主自己的 token）即可得明文：
                //   plaintext = partial_c2 - Σ(本轮 token)
                //             = (原始c2 - Σ(他人 preflop token)) - 牌主 token
                // 因此**不依赖** `deck_state.encrypted[card_index]`。这点对 reconstruct
                // 后的场景至关重要：reconstruct 重建了整个 deck，旧 card_index 在新 deck
                // 中指向不同的 c2，但 partial 记录自包含，旧手牌依然能由牌主自己解开。
                for dc in &mut table.deck_state.decrypted_cards {
                    if dc.encrypted_card_index == card_index && dc.ciphertext.is_some() {
                        let partial_c2 = dc.ciphertext.as_ref().unwrap().c2;
                        let p = partial_decrypt_c2(&partial_c2, &tokens);
                        dc.plaintext = Some(ECPoint::from(p));
                        dc.ciphertext = None;
                        break;
                    }
                }
            } else {
                // preflop / 公共牌：从当前 deck_state.encrypted 取 c2 做部分/完全解密。
                let c2 = table.deck_state.encrypted[card_index as usize].c2;
                let decrypted_c2 = partial_decrypt_c2(&c2, &tokens);

                if phase == REVEAL_PHASE_PREFLOP {
                    // 部分解密：ciphertext = Some(ElGamalCiphertext { c1, c2: partial })，plaintext = None
                    let c1 = table.deck_state.encrypted[card_index as usize].c1;
                    let owner =
                        find_hand_card_owner(table, card_index).unwrap_or(OWNER_SEAT_PUBLIC);
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
            } // 闭合非 showdown 的 else 块

            table.reveal_token_state.assignments[ai].decrypted = true;
        }
    }

    check_reveal_phase_complete(table, events)?;
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
    statement: ReconstructionV3Statement<DefaultCurve>,
    proof: ReconstructProofV3<DefaultCurve>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.reconstruct_state.phase != RECONSTRUCT_PHASE_COLLECTING {
        return Err(PokerL1Error::Serialization(
            "reconstruct not in COLLECTING phase".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }
    if !is_in_list(&table.reconstruct_state.pending_players, seat_index) {
        return Err(PokerL1Error::Serialization(
            "seat not in reconstruct pending".into(),
        ));
    }

    let aggregate_pk = table.deck_state.aggregated_pk.as_ref().ok_or_else(|| {
        PokerL1Error::Serialization("reconstruction V3 requires aggregate public key".into())
    })?;
    let expected_owner_pk = table.seats[seat_index as usize].pk.0;
    let expected_cards: Vec<G1Projective> = table
        .deck_state
        .plaintext
        .iter()
        .map(|point| point.0)
        .collect();
    let expected_readable = utils::reconstruction_v3_user_readable_cards(table, seat_index);
    let expected_context_digest = utils::reconstruction_v3_context_digest(table);
    let expected_prior_state_digest =
        utils::reconstruction_v3_prior_state_digest(table, seat_index)?;
    let expected_epoch = table.timestamps.reconstruct_started_at;
    if statement.aggregate_pk != aggregate_pk.0
        || statement.owner_pk != expected_owner_pk
        || statement.cards != expected_cards
        || statement.user_readable_cards != expected_readable
        || statement.context_digest != expected_context_digest
        || statement.prior_state_digest != expected_prior_state_digest
        || statement.reconstruction_epoch != expected_epoch
    {
        return Err(PokerL1Error::Serialization(
            "reconstruction V3 statement does not match authenticated table state".into(),
        ));
    }
    let contributions = statement.contributions.clone();

    let _ = utils::verify_or_skip(table.config.skip_reconstruct(), || {
        let mut transcript = utils::new_reconstruct_v3_transcript();
        proof.verify(&statement, &mut transcript).map_err(|error| {
            PokerL1Error::Serialization(format!("reconstruction V3 proof: {error}"))
        })?;
        Ok(true)
    })?;

    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    table
        .reconstruct_state
        .player_decks
        .push(ReconstructPlayerDeck {
            seat_index,
            output_cts: contributions,
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
    leave_proof: DLEqProof<DefaultCurve, LeaveKind>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(
            "seat_index out of range".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }
    if !can_leave_state(table) {
        return Err(PokerL1Error::Serialization("not in WAITING state".into()));
    }
    if !is_in_list(&table.shuffle_state.completed_players, seat_index) {
        return Err(PokerL1Error::Serialization(
            "player must have completed shuffle before leave".into(),
        ));
    }

    // 先计算完整资金转移，再修改牌组/公钥/座位状态。
    // 这与 leave_table 的 checked-u64 语义一致，避免 saturating
    // arithmetic 在账户池不足时静默造币，也避免报错时留下部分状态变更。
    let stack_refund = table.seats[seat_index as usize].stack;
    let pending_refund = table.seats[seat_index as usize].pending_addon;
    let refund = stack_refund
        .checked_add(pending_refund)
        .ok_or_else(|| PokerL1Error::Serialization("leave_with_proof: refund overflow".into()))?;
    let post_chip_pool = table.chip_pool.checked_sub(refund).ok_or_else(|| {
        PokerL1Error::Serialization("leave_with_proof: chip_pool underflow".into())
    })?;
    let post_addon_pool = table
        .addon_pool
        .checked_sub(pending_refund)
        .ok_or_else(|| {
            PokerL1Error::Serialization("leave_with_proof: addon_pool underflow".into())
        })?;

    // typed 化后无需反序列化。
    let output_cts = output_cards;
    // input_cts = 当前 deck（已是 Vec<ElGamalCiphertext>）。
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.clone();
    let player_pk = table.seats[seat_index as usize].pk;
    let _ = utils::verify_or_skip(table.config.skip_remask(), || {
        let mut t = utils::new_leave_transcript();
        let ok = DLEqProof::<DefaultCurve, LeaveKind>::verify(
            &leave_proof,
            &input_cts,
            &output_cts,
            &player_pk,
            &mut t,
        );
        if ok {
            Ok(true)
        } else {
            Err(PokerL1Error::Serialization(
                "leave proof verify failed".into(),
            ))
        }
    })?;

    // remove_pk_from_aggregated 已返回 Option<G1Projective>（None 表示结果为单位元/空）。
    let new_agg = remove_pk_from_aggregated(
        table.deck_state.aggregated_pk.as_ref().map(|p| &p.0),
        &player_pk,
    );
    table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
    table.deck_state.encrypted = output_cts;

    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);

    // P1-9 修复：退还 stack + 未入账的 pending_addon（与 dispatch_leave_table 一致），
    // 并同步扣减 chip_pool（join 时 buy_in 计入）与 addon_pool（addon 时计入）。
    if refund > 0 {
        table.seats[seat_index as usize].stack = 0;
        table.seats[seat_index as usize].pending_addon = 0;
        table.chip_pool = post_chip_pool;
        table.addon_pool = post_addon_pool;
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

/// 玩家 fold 并提交 fold proof（剥离自己的加密层 + 退出后续 reveal 协议）。
///
/// `apply_leave_with_proof` 的「对局中」版本：
/// - `leave_with_proof` 仅在 WAITING 状态可用（局间离场）；
/// - `fold_with_proof` 在**下注轮**可用（局中弃牌 + 退出协议）。
///
/// 业务语义（结合 fold 与 leave）：
/// 1. 验证 DLEqProof<LeaveKind>（与 leave 同 transcript `b"zk_leave_proof_v1"`）：
///    证明玩家剥离了自己对整个牌组的加密层（`output.c2 = input.c2 - c1*sk`）。
/// 2. 从 `aggregated_pk` 移除玩家 pk，把 `deck_state.encrypted` 替换为 output_cards。
///    c1 不变（DLEq verify 强制）→ 已收集的 reveal tokens 仍然有效。
/// 3. Scrub 玩家在所有协议 pending 列表中的痕迹（shuffle / reconstruct /
///    reveal assignments），让**后续解牌不需要该玩家参加**。
/// 4. 标记 `seat.folded = true`（保留 seat.pk / total_bet / bet，不设
///    left_during_hand）—— 玩家仍参与 side-pot 记账，只是已弃牌 + 退出协议。
///
/// # 与普通 fold 的区别
///
/// - 普通 `apply_fold`：仅置 `folded=true`，玩家 pk 仍在 aggregated_pk 中，
///   仍需为后续公共牌提交 reveal token（或被超时踢出）。
/// - `apply_fold_with_proof`：玩家立即从协议中「物理退出」，剥离加密层，
///   后续 reveal 不再需要他（也不会被超时罚）。
///
/// # Errors
///
/// - 非下注轮（WAITING / reveal phase / showdown）
/// - 非该玩家行动轮
/// - `seat_index` 越界 / 座位未占用 / 已 folded
/// - fold proof 验证失败（skip_remask=false 时）
pub fn apply_fold_with_proof(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    fold_proof: DLEqProof<DefaultCurve, LeaveKind>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // 1. Guards（对齐 apply_fold_internal）
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization(
            "fold_with_proof: not in betting round".into(),
        ));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: not seat {seat_index}'s turn (current_turn={:?})",
            table.current_turn
        )));
    }
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat {seat_index} not occupied"
        )));
    }
    if seat.folded {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat {seat_index} already folded"
        )));
    }

    // 2. 验证 DLEq proof（复制 apply_leave_with_proof 1696-1710）
    // typed 化后无需反序列化。
    let output_cts = output_cards;
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.clone();
    let player_pk = table.seats[seat_index as usize].pk;
    let _ = utils::verify_or_skip(table.config.skip_remask(), || {
        let mut t = utils::new_leave_transcript();
        let ok = DLEqProof::<DefaultCurve, LeaveKind>::verify(
            &fold_proof,
            &input_cts,
            &output_cts,
            &player_pk,
            &mut t,
        );
        if ok {
            Ok(true)
        } else {
            Err(PokerL1Error::Serialization(
                "fold_with_proof: proof verify failed".into(),
            ))
        }
    })?;

    // 3. 剥离 pk + 替换 deck（复制 apply_leave_with_proof 1712-1715）
    // remove_pk_from_aggregated 返回 Option<G1Projective>（None 表示结果为单位元/空）。
    let new_agg = remove_pk_from_aggregated(
        table.deck_state.aggregated_pk.as_ref().map(|p| &p.0),
        &player_pk,
    );
    table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
    table.deck_state.encrypted = output_cts;

    // 4. Scrub 协议 pending 列表（复制 kick_player_internal 2785-2790）
    //    关键：让玩家退出后续 reveal 协议，后续解牌不需要该玩家参加。
    //    下注轮调用时 reveal_token_state.assignments 为空（reveal phase 在
    //    check_reveal_phase_complete 后已重置），循环无操作；保留以备防御性。
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    for a in &mut table.reveal_token_state.assignments {
        remove_from_pending(&mut a.pending_players, seat_index);
    }

    // 5. 标记 fold（对齐 apply_fold_internal 1787-1788）
    //    保留 seat.pk / total_bet / bet / stack；不设 left_during_hand。
    let seat = &mut table.seats[seat_index as usize];
    seat.folded = true;
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerFolded {
            table_id: table.id,
            seat_index,
            reason: FOLD_REASON_MANUAL,
            round_state: table.round_state,
        },
    );

    // 6. 推进轮次（复制 apply_fold_internal 1800-1807）
    if count_active_players(&table.seats) <= 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    advance_turn(table, events)?;
    table.bump_version();
    Ok(())
}

// ========== 下注动作 ==========

/// 玩家弃牌。
pub fn apply_fold(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
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
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("not player's turn".into()));
    }
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded {
        return Err(PokerL1Error::Serialization("already folded".into()));
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
        end_without_showdown(table, events)?;
        return Ok(());
    }
    advance_turn(table, events)?;
    table.bump_version();
    Ok(())
}

/// 玩家过牌。
pub fn apply_check(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("not player's turn".into()));
    }
    let cb = table
        .betting_round
        .as_ref()
        .expect("checked above")
        .current_bet;
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded || seat.all_in {
        return Err(PokerL1Error::Serialization("player inactive".into()));
    }
    if seat.bet < cb {
        return Err(PokerL1Error::Serialization(
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

    advance_turn(table, events)?;
    table.bump_version();
    Ok(())
}

/// 玩家跟注。
pub fn apply_call(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("not player's turn".into()));
    }
    let round = table.betting_round.as_ref().expect("checked above").clone();
    let seat = &mut table.seats[seat_index as usize];
    if seat.folded || seat.all_in {
        return Err(PokerL1Error::Serialization("player inactive".into()));
    }

    let call_amt = round.process_call(seat.bet, seat.stack);
    seat.stack = seat
        .stack
        .checked_sub(call_amt)
        .ok_or_else(|| PokerL1Error::Serialization("stack underflow on call".into()))?;
    seat.bet = seat
        .bet
        .checked_add(call_amt)
        .ok_or_else(|| PokerL1Error::Serialization("bet overflow on call".into()))?;
    seat.total_bet = seat
        .total_bet
        .checked_add(call_amt)
        .ok_or_else(|| PokerL1Error::Serialization("total_bet overflow on call".into()))?;
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

    advance_turn(table, events)?;
    table.bump_version();
    Ok(())
}

/// 玩家加注到 total_bet。
pub fn apply_raise(
    table: &mut TexasPokerTable,
    seat_index: u8,
    total_bet: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("not player's turn".into()));
    }
    let seat_bet = table.seats[seat_index as usize].bet;
    let seat_stack = table.seats[seat_index as usize].stack;
    let round = table.betting_round.as_mut().expect("checked above");
    let needed = round.process_raise(total_bet, seat_bet, seat_stack)?;

    let seat = &mut table.seats[seat_index as usize];
    seat.stack = seat
        .stack
        .checked_sub(needed)
        .ok_or_else(|| PokerL1Error::Serialization("stack underflow on raise".into()))?;
    seat.bet = total_bet;
    seat.total_bet = seat
        .total_bet
        .checked_add(needed)
        .ok_or_else(|| PokerL1Error::Serialization("total_bet overflow on raise".into()))?;
    let is_all_in = seat.stack == 0;
    if is_all_in {
        seat.all_in = true;
    }
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;

    // raise 重置其他可行动玩家
    for (i, s) in table.seats.iter_mut().enumerate() {
        if i as u8 != seat_index && s.is_occupied() && !s.folded && !s.all_in && !s.is_waiting {
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

    advance_turn(table, events)?;
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
) -> PokerL1Result<()> {
    if table.round_state != ROUND_WAITING {
        return Err(PokerL1Error::Serialization(format!(
            "not in WAITING state: round_state={}",
            table.round_state
        )));
    }
    if count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START {
        return Err(PokerL1Error::Serialization(format!(
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

    advance_shuffle(table, events)?;
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
) -> PokerL1Result<()> {
    // 1. Reconstruct 优先
    if table.reconstruct_state.phase != RECONSTRUCT_PHASE_NONE {
        let started = table.timestamps.reconstruct_started_at;
        if started > 0
            && now_ms >= started.saturating_add(table.timeout_config.reconstruct_timeout_ms)
        {
            on_reconstruct_timeout(table, now_ms, events)?;
        }
        return Ok(());
    }

    // 2. Shuffle 阶段
    let sp = table.shuffle_state.phase;
    if sp == SHUFFLE_PHASE_RECONSTRUCT || sp == SHUFFLE_PHASE_BEFORE_PREFLOP {
        if table.shuffle_state.pending_players.is_empty() {
            advance_shuffle(table, events)?;
            return Ok(());
        }
        if table.shuffle_state.current_shuffler.is_none() {
            advance_shuffle(table, events)?;
            return Ok(());
        }
        let started = table.timestamps.shuffle_started_at;
        if started == 0 {
            if now_ms != 0 {
                table.timestamps.shuffle_started_at = now_ms;
                table.bump_version();
            }
            return Ok(());
        }
        if now_ms >= started.saturating_add(table.timeout_config.shuffle_timeout_ms) {
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
            check_reveal_phase_complete(table, events)?;
            return Ok(());
        }
        let started = table.timestamps.reveal_started_at;
        if started == 0 {
            if now_ms != 0 {
                table.timestamps.reveal_started_at = now_ms;
                table.bump_version();
            }
            return Ok(());
        }
        if now_ms >= started.saturating_add(table.timeout_config.reveal_timeout_ms) {
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
            collect_bets_to_pot(table, events)?;
            advance_round(table, events)?;
            return Ok(());
        }
        let started = table.timestamps.betting_started_at;
        if started == 0 {
            if now_ms != 0 {
                table.timestamps.betting_started_at = now_ms;
                table.bump_version();
            }
            return Ok(());
        }
        if now_ms >= started.saturating_add(table.timeout_config.betting_timeout_ms) {
            // Time Bank：超时前检查当前玩家是否还有 time_bank 额度。
            // 若有，则消耗等量时间延长 betting_started_at，而非立即 auto_fold。
            let seat = table.current_turn.unwrap_or(0);
            let tb = table.seats[seat as usize].time_bank_ms;
            if tb > 0 {
                // 消耗 time_bank（最多覆盖一个 betting_timeout 周期）
                let consume = tb.min(table.timeout_config.betting_timeout_ms);
                consume_time_bank(table, seat, consume, events)?;
                // 延长截止时间：betting_started_at += consume
                table.timestamps.betting_started_at =
                    table.timestamps.betting_started_at.saturating_add(consume);
            } else {
                on_betting_timeout(table, events)?;
            }
        }
        return Ok(());
    }

    if table.round_state == ROUND_SHOWDOWN {
        if table.timestamps.showdown_at == 0 {
            table.timestamps.showdown_at =
                now_ms.saturating_add(table.timeout_config.showdown_display_ms);
        } else if now_ms >= table.timestamps.showdown_at {
            settle_hand(table, events)?;
        }
        return Ok(());
    }

    // 5. Fallback：状态不一致
    if matches!(
        table.round_state,
        ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
    ) && !is_betting_round(table)
    {
        refund_all_bets(table, events)?;
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
) -> PokerL1Result<()> {
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

    kick_player_internal(table, seat, KICK_REASON_TIMEOUT, events)?;

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    if table.shuffle_state.phase == SHUFFLE_PHASE_NONE {
        return Ok(());
    }

    rebuild_deck_and_shuffle_on_timeout(table, phase, events)?;
    advance_shuffle(table, events)?;
    let _ = now_ms;
    Ok(())
}

/// reveal 超时处理：移除超时玩家，按轮次选择 reset 或 reconstruct。
///
/// # 流程
/// 1. 收集所有未提交 reveal token 的 pending 玩家，逐个踢出（`kick_player_internal`）。
/// 2. 若踢出后无人活跃（active==0）→ refund + reset（异常收场）。
/// 3. 若仅剩 1 人 → `end_without_showdown`（该玩家独得 pot）。
/// 4. 否则按轮次分支：
///    - **preflop**：直接 reset。此时一张牌都未解出（preflop reveal 完成才会
///      post_blinds 进入下注），reset 后桌台回到 WAITING，下次 tick 会自动
///      `start_hand`（重新 shuffle + 发牌）。比 reconstruct（重建牌组）简单得多——
///      reconstruct 的语义是"已有牌解出、剩余牌无法继续解密时重建牌组继续"，
///      preflop 没有已解出的牌，无需重建。
///    - **其他轮次**（flop/turn/river/showdown）：已有牌解出，走 `start_reconstruct`
///      重建牌组让剩余玩家补发缺失的牌继续。
fn on_reveal_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let phase = table.reveal_token_state.reveal_phase;
    let pending: Vec<u8> = table
        .reveal_token_state
        .assignments
        .iter()
        .flat_map(|a| a.pending_players.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
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
        kick_player_internal(table, seat, KICK_REASON_TIMEOUT, events)?;
    }

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
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
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }

    if phase == REVEAL_PHASE_PREFLOP {
        // preflop 未解出任何牌，直接 reset 回 WAITING；
        // 下次 tick 检测到 active >= MIN_PLAYERS_TO_START 会自动 start_hand 重新洗牌发牌。
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

    // flop/turn/river/showdown：已有牌解出，走 reconstruct 重建牌组继续。
    start_reconstruct(table, now_ms, events);
    Ok(())
}

/// betting 超时处理：自动 fold。
fn on_betting_timeout(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let seat = table.current_turn.unwrap_or(0);
    apply_fold_internal(table, seat, FOLD_REASON_AUTO_TIMEOUT, events)
}

/// 单人获胜（无摊牌）。
fn end_without_showdown(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let winner = table
        .seats
        .iter()
        .enumerate()
        .find(|(_, s)| s.is_occupied() && !s.folded && !s.is_waiting)
        .map(|(i, _)| i as u8);

    if let Some(winner_seat) = winner {
        // 抽水（在分配奖金之前）
        let pot_before = table.pot;
        let rake = collect_rake(table)?;
        if rake > 0 {
            events::emit_event(
                events,
                TexasPokerEvent::RakeCollected {
                    table_id: table.id,
                    pot_before,
                    rake_amount: rake,
                    pot_after: table.pot,
                    rake_mode: table.rake_mode,
                },
            );
        }
        let pot = table.pot;
        table.seats[winner_seat as usize].stack = table.seats[winner_seat as usize]
            .stack
            .checked_add(pot)
            .ok_or_else(|| {
                PokerL1Error::Serialization(
                    "end_without_showdown: winner stack += pot overflow".into(),
                )
            })?;
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

    reset_for_next_hand(table, events)?;
    Ok(())
}

/// 摊牌结算。
///
/// 镜像 `table.move::settle_hand`（line 2440-2510）。
fn settle_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.round_state != ROUND_SHOWDOWN {
        return Ok(());
    }
    if table.reveal_token_state.reveal_phase != REVEAL_PHASE_NONE {
        return Ok(());
    }

    // 先 side pot 分层，再基于分层总额算 rake，按比例从各 pot 扣除（守恒）。
    let bets: Vec<u64> = table.seats.iter().map(|s| s.total_bet).collect();
    let folded: Vec<bool> = table
        .seats
        .iter()
        .map(|s| s.folded || s.left_during_hand)
        .collect();
    let all_in: Vec<bool> = table.seats.iter().map(|s| s.all_in).collect();

    let mut result = match side_pot::calculate_side_pots(&bets, &folded, &all_in) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("settle_hand: side_pot 计算失败: {e:?}");
            refund_all_bets(table, events)?;
            reset_for_next_hand(table, events)?;
            return Ok(());
        }
    };

    // 基于分层总额计算 rake，按各 pot 占比扣除（余数归 pots[0]，守恒）。
    let total_before_rake = result.total();
    let rake = compute_rake_amount(table, total_before_rake)?;
    if rake > 0 {
        // The rake is not table-owned escrow. Reserve its deterministic Treasury output before
        // paying winners, so the post-state root already matches the table that the precompile
        // persists and the proof task replays. `reset_for_next_hand` clears this receipt after
        // the `RakeCollected` event has made the payout amount explicit.
        let post_rake_collected = table
            .rake_collected
            .checked_add(rake)
            .ok_or_else(|| PokerL1Error::Serialization("rake receipt overflow".into()))?;
        let post_chip_pool = table
            .chip_pool
            .checked_sub(rake)
            .ok_or_else(|| PokerL1Error::Serialization("rake exceeds TableVault".into()))?;
        apply_rake_to_pots(&mut result, rake)?;
        table.rake_collected = post_rake_collected;
        table.chip_pool = post_chip_pool;
        events::emit_event(
            events,
            TexasPokerEvent::RakeCollected {
                table_id: table.id,
                pot_before: total_before_rake,
                rake_amount: rake,
                pot_after: result.total(),
                rake_mode: table.rake_mode,
            },
        );
    }

    // 逐层分配：pots[0] 是主池，pots[1..] 是边池。eligible 取分层算法结果（同源）。
    let mut all_winners: Vec<u8> = Vec::new();
    for (idx, sp) in result.pots.iter().enumerate() {
        let pot_type = if idx == 0 {
            POT_TYPE_MAIN
        } else {
            POT_TYPE_SIDE
        };
        let winners = find_winners_in_seats(table, sp.eligible_seats);
        distribute_pot_to_winners(table, sp.amount, &winners, pot_type, events)?;
        all_winners.extend(&winners);
    }

    events::emit_event(
        events,
        TexasPokerEvent::HandSettled {
            table_id: table.id,
            pot: result.total() + rake,
            winners: all_winners,
        },
    );

    // pot 已全部分配给赢家（含 rake 扣除），清零。
    table.pot = 0;
    reset_for_next_hand(table, events)?;
    Ok(())
}

/// 计算 rake 金额（不修改状态），供 settle_hand 在分层后使用。
fn compute_rake_amount(table: &TexasPokerTable, pot: u64) -> PokerL1Result<u64> {
    if table.rake_mode == super::constants::RAKE_MODE_NONE {
        return Ok(0);
    }
    let raw_rake = u128::from(pot)
        .checked_mul(u128::from(table.rake_bps))
        .ok_or_else(|| PokerL1Error::Serialization("rake multiplication overflow".into()))?
        / 10_000;
    Ok(raw_rake
        .min(u128::from(table.rake_cap))
        .min(u128::from(pot)) as u64)
}

/// 按各 pot 占比扣除 rake，再按固定 pot 顺序扣除整除尾差（守恒）。
///
/// 扣除后 `result.total()` 恰好减少 `rake`。
fn apply_rake_to_pots(result: &mut side_pot::SidePotResult, rake: u64) -> PokerL1Result<()> {
    let total = result.total();
    if total == 0 || rake == 0 || result.pots.is_empty() {
        return Ok(());
    }
    let mut remaining = rake;
    // Use the original amount in each independent proportional calculation. The floor shares can
    // leave at most a small deterministic remainder, which is consumed in the second pass.
    for sp in &mut result.pots {
        let this_rake = (sp.amount as u128 * rake as u128 / total as u128) as u64;
        sp.amount = sp.amount.checked_sub(this_rake).ok_or_else(|| {
            PokerL1Error::Serialization("side-pot rake exceeds pot amount".into())
        })?;
        remaining = remaining.checked_sub(this_rake).ok_or_else(|| {
            PokerL1Error::Serialization("side-pot proportional rake exceeds total rake".into())
        })?;
    }
    for sp in &mut result.pots {
        if remaining == 0 {
            break;
        }
        let take = remaining.min(sp.amount);
        sp.amount -= take;
        remaining -= take;
    }
    if remaining != 0 {
        return Err(PokerL1Error::Serialization(
            "side-pot rake remainder exceeds available pots".into(),
        ));
    }
    Ok(())
}

/// 在指定 eligible seats（位掩码）中找最佳手牌持有者。
///
/// 用 `evaluate_best` 评估手牌+公共牌（统一处理 5..=7 张及不足 5 张的 0 填充），
/// 取最大 HandRank 的玩家；平局返回多人。
fn find_winners_in_seats(table: &TexasPokerTable, eligible_mask: u16) -> Vec<u8> {
    if eligible_mask == 0 {
        return vec![];
    }
    let mut best_rank: Option<super::hand_evaluator::HandRank> = None;
    let mut winners: Vec<u8> = vec![];

    for seat in 0..table.seats.len() as u8 {
        if !side_pot::is_eligible(eligible_mask, seat) {
            continue;
        }
        let s = &table.seats[seat as usize];
        if s.hand.is_empty() {
            continue;
        }
        let mut cards = s.hand.clone();
        cards.extend_from_slice(&table.community_cards);

        let rank = super::hand_evaluator::evaluate_best(&cards);
        match &best_rank {
            None => {
                best_rank = Some(rank);
                winners = vec![seat];
            }
            Some(b) => {
                use std::cmp::Ordering;
                match rank.cmp(b) {
                    Ordering::Greater => {
                        best_rank = Some(rank);
                        winners = vec![seat];
                    }
                    Ordering::Equal => {
                        winners.push(seat);
                    }
                    Ordering::Less => {}
                }
            }
        }
    }
    if winners.is_empty() {
        // 所有 eligible 玩家都无手牌（异常），回退到最低位 eligible 座位。
        winners.push(eligible_mask.trailing_zeros() as u8);
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
) -> PokerL1Result<()> {
    if winners.is_empty() || pot == 0 {
        return Ok(());
    }
    let share = pot / winners.len() as u64;
    let remainder = pot % winners.len() as u64;
    for (idx, &winner) in winners.iter().enumerate() {
        let amount = if idx == 0 { share + remainder } else { share };
        table.seats[winner as usize].stack = table.seats[winner as usize]
            .stack
            .checked_add(amount)
            .ok_or_else(|| {
                PokerL1Error::Serialization(
                    "distribute_pot_to_winners: winner stack += amount overflow".into(),
                )
            })?;
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
    Ok(())
}

/// 退还所有下注（异常路径）。
fn refund_all_bets(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.is_occupied() && !s.folded && !s.left_during_hand && s.total_bet > 0 && !s.refunded {
            s.stack = s.stack.checked_add(s.total_bet).ok_or_else(|| {
                PokerL1Error::Serialization("refund_all_bets: stack += total_bet overflow".into())
            })?;
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
    Ok(())
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
) -> PokerL1Result<()> {
    // Preflight the complete addon merge before changing any seat or emitting events. This keeps
    // a corrupt pool/overflow failure atomic instead of crediting an earlier seat partially.
    let mut total_pending_addon = 0u64;
    let mut to_remove_leave: Vec<u8> = vec![];
    let mut total_leave_refund = 0u64;
    for (i, s) in table.seats.iter().enumerate() {
        if s.pending_addon > 0 && s.is_occupied() {
            s.stack.checked_add(s.pending_addon).ok_or_else(|| {
                PokerL1Error::Serialization(
                    "reset_for_next_hand: stack += pending_addon overflow".into(),
                )
            })?;
            total_pending_addon = total_pending_addon
                .checked_add(s.pending_addon)
                .ok_or_else(|| {
                    PokerL1Error::Serialization(
                        "reset_for_next_hand: total pending addon overflow".into(),
                    )
                })?;
        }
        if s.is_occupied() && s.want_leave {
            let refund = s.stack.checked_add(s.pending_addon).ok_or_else(|| {
                PokerL1Error::Serialization("reset_for_next_hand: leave refund overflow".into())
            })?;
            total_leave_refund = total_leave_refund.checked_add(refund).ok_or_else(|| {
                PokerL1Error::Serialization(
                    "reset_for_next_hand: total leave refund overflow".into(),
                )
            })?;
            to_remove_leave.push(i as u8);
        }
    }
    let post_addon_pool = table
        .addon_pool
        .checked_sub(total_pending_addon)
        .ok_or_else(|| {
            PokerL1Error::Serialization("reset_for_next_hand: pending addon pool underflow".into())
        })?;
    let post_leave_chip_pool =
        table
            .chip_pool
            .checked_sub(total_leave_refund)
            .ok_or_else(|| {
                PokerL1Error::Serialization("reset_for_next_hand: leave chip_pool underflow".into())
            })?;

    // 第一阶段：合并 pending_addon 到 stack（在清理 stack==0 之前）
    //
    // 关键不变量：addon 在下一手生效，合并发生在任何清理之前，
    // 确保 addon 后玩家不会被误踢（即使上一手结束时 stack==0）。
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.pending_addon > 0 && s.is_occupied() {
            let player = s.player;
            let amount = s.pending_addon;
            s.stack += amount;
            s.pending_addon = 0;
            events::emit_event(
                events,
                TexasPokerEvent::AddonCredited {
                    table_id: table.id,
                    seat_index: i as u8,
                    player,
                    amount,
                    stack_after: s.stack,
                },
            );
        }
    }
    table.addon_pool = post_addon_pool;

    // P2-11 修复：每手开始时补充 Time Bank（按 TIME_BANK_REFILL_PER_HAND_MS，
    // 上限 DEFAULT_TIME_BANK_MS）。此前 constants 定义了 refill 常量但 reset
    // 未实现补充逻辑，导致 time_bank 仅会单调下降，无法跨手恢复。
    let refill = super::constants::TIME_BANK_REFILL_PER_HAND_MS;
    let cap = super::constants::DEFAULT_TIME_BANK_MS;
    for s in &mut table.seats {
        if s.is_occupied() {
            s.time_bank_ms = s.time_bank_ms.saturating_add(refill).min(cap);
        }
    }

    // 第二阶段：重置 seat 字段；waiting 玩家 pk 加入 aggregated_pk
    for s in &mut table.seats {
        s.hand.clear();
        s.bet = 0;
        s.total_bet = 0;
        s.folded = false;
        s.all_in = false;
        s.acted_this_round = false;
        // typed 化后 pk 是 G1Projective；用 is_identity 判断未设置。
        if s.is_waiting && !g1_is_identity(&s.pk) {
            // add_pk_to_aggregated 接受 Option<&G1Projective>，返回 Option<G1Projective>。
            let new_agg =
                add_pk_to_aggregated(table.deck_state.aggregated_pk.as_ref().map(|p| &p.0), &s.pk);
            table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
        }
        s.is_waiting = false;
        s.left_during_hand = false;
    }

    // 第二阶段（b）：强制踢出 `want_leave=true` 的 occupied seat。
    //
    // 这是 `request_leave_after_hand`（sit out next hand）的执行点：玩家在
    // 对局中预约离场后，下一手 reset 时强制踢出并退款。资金账对齐
    // `kick_player_internal` / `dispatch_leave_table`：
    // - 退 stack + pending_addon（refund_amt）
    // - 同步扣 chip_pool（join 时 buy_in 计入）与 addon_pool（addon 时计入）
    // - 从 aggregated_pk 移除该 pk（若非 identity）
    // - 清空座位 + 发 PlayerRefund + PlayerLeft 事件
    //
    // 时机说明：必须在第二阶段（重置 seat 字段）之后、第三阶段（清理 stack==0）
    // 之前。理由：第二阶段已把 pending_addon 合并到 stack（退款金额正确），
    // 第三阶段的 stack==0 判定不会误清已退款的座位。
    for &i in &to_remove_leave {
        let stack_refund = table.seats[i as usize].stack;
        let pending_refund = table.seats[i as usize].pending_addon;
        let refund = stack_refund + pending_refund;
        let pk = table.seats[i as usize].pk;
        let player = table.seats[i as usize].player;
        if refund > 0 {
            table.seats[i as usize].stack = 0;
            table.seats[i as usize].pending_addon = 0;
            events::emit_event(
                events,
                TexasPokerEvent::PlayerRefund {
                    table_id: table.id,
                    seat_index: i,
                    player,
                    amount: refund,
                    refund_type: REFUND_TYPE_STACK_ONLY,
                },
            );
        }
        if !g1_is_identity(&pk) {
            let new_agg = remove_pk_from_aggregated(
                table.deck_state.aggregated_pk.as_ref().map(|p| &p.0),
                &pk,
            );
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
    table.chip_pool = post_leave_chip_pool;

    // 第三阶段：清理 stack==0 的 occupied seat
    let mut to_remove: Vec<u8> = vec![];
    for (i, s) in table.seats.iter().enumerate() {
        if s.is_occupied() && s.stack == 0 {
            to_remove.push(i as u8);
        }
    }
    for &i in &to_remove {
        // G1Projective 是 Copy，直接拷贝。
        let pk = table.seats[i as usize].pk;
        let player = table.seats[i as usize].player;
        if !g1_is_identity(&pk) {
            let new_agg = remove_pk_from_aggregated(
                table.deck_state.aggregated_pk.as_ref().map(|p| &p.0),
                &pk,
            );
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
        // typed 化后 aggregated_pk 是 Option<G1Projective>；用 None 表示空。
        table.deck_state.aggregated_pk = None;
    }

    table.pot = 0;
    // `rake_collected` is only a same-dispatch receipt for the Treasury UTXO. No persisted
    // table may retain it as unclaimed money.
    table.rake_collected = 0;
    table.side_pots.clear();
    table.ante_collected = 0;
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
) -> PokerL1Result<()> {
    // A kick can cascade into end_without_showdown/settlement and finally reset_for_next_hand.
    // Execute the whole cascade on a candidate table so a late reset failure cannot leave a
    // partially refunded seat or a partially collected pot in the caller's state.
    let mut candidate = table.clone();
    let mut candidate_events = Vec::new();
    kick_player_internal_in_place(&mut candidate, seat_index, reason, &mut candidate_events)?;
    *table = candidate;
    events.extend(candidate_events);
    Ok(())
}

fn kick_player_internal_in_place(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // P0-1 修复：seat_index 越界校验（原先直接索引会 panic）。
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "kick_player: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        // 座位空闲视为无操作成功（幂等），但区分于越界错误。
        return Ok(());
    }

    let stack_refund = seat.stack;
    let pending_refund = seat.pending_addon;
    let refund_amt = stack_refund
        .checked_add(pending_refund)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: refund overflow".into()))?;
    let was_waiting = seat.is_waiting;
    // G1Projective 是 Copy，无需 clone。
    let pk = seat.pk;
    let player = seat.player;

    // Preflight every fallible monetary transition before mutating the seat, pot or aggregate key.
    let post_pot = table
        .pot
        .checked_add(seat.bet)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: pot overflow".into()))?;
    let post_chip_pool = table
        .chip_pool
        .checked_sub(refund_amt)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: chip_pool underflow".into()))?;
    let post_addon_pool = table
        .addon_pool
        .checked_sub(pending_refund)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: addon_pool underflow".into()))?;

    // P1-2 语义说明：被踢玩家的 bet 立即并入 pot（区别于 fold/auto_fold/force_fold，
    // 后者保留 seat.bet，等下注轮结束由 collect_bets_to_pot 统一收集）。
    // 这是 kick 的特殊路径：被踢玩家立即离开，其本轮已下注金额不参与后续轮次，
    // 故提前单独收集。资金账安全：collect_bets_to_pot 后续不会再收（seat.bet 已为 0）；
    // side_pot 分层依据 total_bet（不受 bet 清零影响）。
    table.pot = post_pot;
    seat.bet = 0;
    seat.stack = 0;
    seat.hand.clear();
    seat.left_during_hand = true;
    seat.folded = true;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.is_waiting = false;
    // typed 化后 pk 是 G1Projective；用 identity 表示空。
    seat.pk = ECPoint(G1Projective::identity());

    if !g1_is_identity(&pk) && !was_waiting {
        let new_agg =
            remove_pk_from_aggregated(table.deck_state.aggregated_pk.as_ref().map(|p| &p.0), &pk);
        table.deck_state.aggregated_pk = new_agg.map(ECPoint::from);
    }

    if refund_amt > 0 {
        // chip_pool 是完整 TableVault 锁仓；pending addon 同时是 addon_pool 子集。
        table.chip_pool = post_chip_pool;
        table.addon_pool = post_addon_pool;
        table.seats[seat_index as usize].pending_addon = 0;
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
        advance_shuffle(table, &mut tmp_events)?;
        events.extend(tmp_events);
    }
    if table.current_turn == Some(seat_index) && is_betting_round(table) {
        let active = count_active_players(&table.seats);
        if active <= 1 {
            end_without_showdown(table, events)?;
        } else {
            advance_turn(table, events)?;
        }
    }

    if count_active_players(&table.seats) < MIN_PLAYERS_TO_START {
        reset_for_next_hand(table, events)?;
    }
    Ok(())
}

// ========== Addon / Rebuy ==========

/// `addon` — 玩家追加筹码，**下一手生效**。
///
/// 业务语义：玩家可在任意时刻（包括牌局进行中）追加筹码，但追加金额
/// **不影响当前手牌**，只累加 `seat.pending_addon`，在下一手
/// [`reset_for_next_hand`] 第一阶段合并到 `seat.stack`。
///
/// 这样设计的关键不变量：
/// - 不破坏当前 `side_pot` 分层（all-in 后的钱不能凭空增加）
/// - 不允许玩家利用 addon 在 all-in 后"加码"破坏结算
/// - addon 只影响 `stack`，不动 `bet/total_bet`
///
/// # 参数
/// - `table`: 桌台状态
/// - `seat_index`: 目标座位
/// - `amount`: 追加金额（必须 > 0）
/// - `events`: 事件日志
///
/// # Errors
///
/// - `seat_index` 越界
/// - 座位未被占用
/// - `amount == 0`
pub fn apply_addon(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "addon: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if amount == 0 {
        return Err(PokerL1Error::Serialization("addon: amount must > 0".into()));
    }

    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "addon: seat {seat_index} not occupied"
        )));
    }

    // chip_pool 是真实锁仓总额；addon_pool 只是其中尚未并入 stack 的子集，不能重复相加。
    let total_chips = table
        .chip_pool
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("addon: total chips overflow".into()))?;
    if total_chips > super::constants::MAX_TOTAL_BET {
        return Err(PokerL1Error::Serialization(format!(
            "addon: total chips {total_chips} exceeds MAX_TOTAL_BET {}",
            super::constants::MAX_TOTAL_BET
        )));
    }

    // 关键：只累加 pending_addon，不动 stack（不影响当前 pot）
    seat.pending_addon = seat
        .pending_addon
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("addon: pending_addon overflow".into()))?;
    table.addon_pool = table
        .addon_pool
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("addon: addon_pool overflow".into()))?;
    table.chip_pool = total_chips;

    let player = seat.player;
    let pending_after = seat.pending_addon;
    events::emit_event(
        events,
        TexasPokerEvent::AddonRequested {
            table_id: table.id,
            seat_index,
            player,
            amount,
            pending_after,
        },
    );
    table.bump_version();
    Ok(())
}

/// `rebuy` — 玩家重购，**立即生效**（仅 MTT 早期或特殊规则用）。
///
/// 与 `addon` 的关键区别：
/// - `addon` 下一手生效，只改 `pending_addon`，不影响当前 pot
/// - `rebuy` 立即生效，直接改 `stack`，可用于玩家筹码不足时继续游戏
///
/// 业务约束（调用方负责）：
/// - MTT 中通常要求 `seat.stack < big_blind` 才允许 rebuy
/// - 现金桌通常不使用 rebuy，而用 addon
/// - 通常在 rebuy 期内（盲注升阶到某级别前）才允许
///
/// # 参数
/// - `table`: 桌台状态
/// - `seat_index`: 目标座位
/// - `amount`: 重购金额（必须 > 0）
/// - `events`: 事件日志
///
/// # Errors
///
/// - `seat_index` 越界
/// - 座位未被占用
/// - `amount == 0`
pub fn apply_rebuy(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "rebuy: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if amount == 0 {
        return Err(PokerL1Error::Serialization("rebuy: amount must > 0".into()));
    }

    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "rebuy: seat {seat_index} not occupied"
        )));
    }

    // chip_pool 是真实锁仓总额；rebuy 立即进入 stack，因此不进入 pending addon_pool。
    let total_chips = table
        .chip_pool
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("rebuy: total chips overflow".into()))?;
    if total_chips > super::constants::MAX_TOTAL_BET {
        return Err(PokerL1Error::Serialization(format!(
            "rebuy: total chips {total_chips} exceeds MAX_TOTAL_BET {}",
            super::constants::MAX_TOTAL_BET
        )));
    }

    // 立即入账：直接改 stack
    seat.stack = seat
        .stack
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("rebuy: stack overflow".into()))?;
    table.chip_pool = total_chips;

    let player = seat.player;
    let stack_after = seat.stack;
    events::emit_event(
        events,
        TexasPokerEvent::RebuyProcessed {
            table_id: table.id,
            seat_index,
            player,
            amount,
            stack_after,
        },
    );
    table.bump_version();
    Ok(())
}

// ========== Request Leave After Hand（sit out next hand） ==========

/// `request_leave_after_hand` — 玩家请求「下局开始前离场」（toggle）。
///
/// 业务语义（在线扑克 "sit out next hand / stand up next hand" 标准模式）：
/// 玩家可在**任意时刻**（含对局进行中的 shuffle / reveal / betting / showdown）
/// 调用此方法切换 `seat.want_leave` 标志。下一手在 [`reset_for_next_hand`]（由
/// settle_hand / end_without_showdown / 超时路径触发）时，所有 `want_leave=true`
/// 的 occupied seat 会被强制踢出并退还 stack + pending_addon。
///
/// 解决的问题：`leave_table` 仅在 WAITING 状态可用，而 creator / `tick`
/// 可能在 settle 后立即 `start_hand`，玩家来不及离场。此方法让玩家在对局中
/// 即可预约离场，由 reset 强制执行。
///
/// # Toggle 语义
///
/// 每次调用翻转 `want_leave` 标志：false→true（预约离场）/ true→false（取消）。
/// `LeaveRequested` 事件携带切换后的新值，便于链下索引。
///
/// # 权限
///
/// dispatch 层校验 `caller == seat.player`（与 leave_table / addon 一致）。
///
/// # Errors
///
/// - `seat_index` 越界
/// - 座位未被占用
pub fn apply_request_leave(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "request_leave_after_hand: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "request_leave_after_hand: seat {seat_index} not occupied"
        )));
    }

    seat.want_leave = !seat.want_leave;
    let player = seat.player;
    let want_leave = seat.want_leave;

    events::emit_event(
        events,
        TexasPokerEvent::LeaveRequested {
            table_id: table.id,
            seat_index,
            player,
            want_leave,
        },
    );
    table.bump_version();
    Ok(())
}

// ========== Bet / Time Bank / Ante / Rake / Run It Twice ==========

/// `bet` — 玩家主动下注（postflop 第一个下注者）。
///
/// 与 `raise` 的区别：
/// - `raise` 用于已有下注时加注（preflop BB 已存在，或有人 bet 后）
/// - `bet` 用于 postflop 当前 pot 无下注时主动开注
///
/// 实现上 `bet` 等价于 `raise(total_bet = amount)`（因为 round 开注后 min_raise = amount）。
/// 分离为独立方法仅为语义清晰。
pub fn apply_bet(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization(
            "bet: not in betting round".into(),
        ));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("bet: not player's turn".into()));
    }
    if amount == 0 {
        return Err(PokerL1Error::Serialization("bet: amount must > 0".into()));
    }
    // P2-5 修复：preflop 已有强制下注（盲注构成 current_bet），不应使用 bet
    // （开注动作应叫 raise）。bet 仅用于 postflop 当前轮无下注时主动开注。
    if table.round_state == ROUND_PREFLOP {
        return Err(PokerL1Error::Serialization(
            "bet: not allowed in preflop, use raise instead".into(),
        ));
    }
    // 验证当前轮无已有下注（bet 只能在 current_bet == seat.bet 时使用）
    let round = table.betting_round.as_ref().expect("checked above");
    let current_bet = round.current_bet;
    let seat_bet = table.seats[seat_index as usize].bet;
    if current_bet > seat_bet {
        return Err(PokerL1Error::Serialization(format!(
            "bet: current_bet {current_bet} > seat_bet {seat_bet}, 应使用 call/raise"
        )));
    }

    // 复用 raise 逻辑（total_bet = seat_bet + amount）
    let total_bet = seat_bet
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("bet: total_bet overflow".into()))?;
    apply_raise(table, seat_index, total_bet, events)?;
    // raise 已 emit PlayerRaised，额外 emit PlayerBet 以保留语义
    events::emit_event(
        events,
        TexasPokerEvent::PlayerBet {
            table_id: table.id,
            seat_index,
            amount,
            round_state: table.round_state,
        },
    );
    Ok(())
}

/// `consume_time_bank` — 玩家 Time Bank 被消耗（超时续命）。
///
/// 通常由 `tick` 在玩家 betting 超时且 time_bank_ms > 0 时自动调用。
/// 消耗指定毫秒数，若剩余不足以覆盖则返回错误（调用方应改用 auto_fold）。
pub fn consume_time_bank(
    table: &mut TexasPokerTable,
    seat_index: u8,
    consumed_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: seat_index {seat_index} out of range"
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: seat {seat_index} not occupied"
        )));
    }
    if seat.time_bank_ms < consumed_ms {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: time_bank_ms {} < consumed_ms {}",
            seat.time_bank_ms, consumed_ms
        )));
    }
    seat.time_bank_ms -= consumed_ms;
    let remaining_ms = seat.time_bank_ms;
    events::emit_event(
        events,
        TexasPokerEvent::TimeBankConsumed {
            table_id: table.id,
            seat_index,
            consumed_ms,
            remaining_ms,
        },
    );
    table.bump_version();
    Ok(())
}

/// `collect_ante` — 在 `start_hand` 中按 `ante_mode` 投 ante。
///
/// 此函数由 `start_hand` 内部调用，不作为独立 dispatch method。
/// 投注规则：
/// - `ANTE_MODE_NORMAL`：每个活跃玩家投 `ante_amount`
/// - `ANTE_MODE_BBA`：仅大盲位投 `ante_amount`
/// - `ANTE_MODE_NONE`：不做任何操作
///
/// 投注的 ante 累积到 `table.ante_collected`，并直接加入 `table.pot`。
pub fn collect_ante(
    table: &mut TexasPokerTable,
    bb_seat: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.ante_mode == super::constants::ANTE_MODE_NONE || table.ante_amount == 0 {
        return Ok(());
    }
    let amount = table.ante_amount;
    let mode = table.ante_mode;

    let seats_to_ante: Vec<u8> = if mode == super::constants::ANTE_MODE_BBA {
        vec![bb_seat]
    } else {
        // NORMAL: 所有活跃玩家
        table
            .seats
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_occupied() && !s.is_waiting)
            .map(|(i, _)| i as u8)
            .collect()
    };

    let antes = seats_to_ante
        .iter()
        .map(|seat_idx| (*seat_idx, amount.min(table.seats[*seat_idx as usize].stack)))
        .collect::<Vec<_>>();
    let total_ante = antes.iter().try_fold(0u64, |total, (_, actual)| {
        total
            .checked_add(*actual)
            .ok_or_else(|| PokerL1Error::Serialization("collect_ante: total overflow".into()))
    })?;
    table
        .ante_collected
        .checked_add(total_ante)
        .ok_or_else(|| PokerL1Error::Serialization("collect_ante: ante ledger overflow".into()))?;
    table
        .pot
        .checked_add(total_ante)
        .ok_or_else(|| PokerL1Error::Serialization("collect_ante: pot overflow".into()))?;
    for (seat_idx, actual) in &antes {
        table.seats[*seat_idx as usize]
            .total_bet
            .checked_add(*actual)
            .ok_or_else(|| {
                PokerL1Error::Serialization("collect_ante: total_bet overflow".into())
            })?;
    }

    table.ante_collected += total_ante;
    table.pot += total_ante;
    for (seat_idx, actual) in antes {
        let seat = &mut table.seats[seat_idx as usize];
        seat.stack -= actual;
        // An ante is dead money: it contributes to side-pot eligibility through total_bet and is
        // held directly by the pot, but it must not reduce the price of a call via seat.bet.
        seat.total_bet += actual;
        if seat.stack == 0 {
            seat.all_in = true;
        }
        events::emit_event(
            events,
            TexasPokerEvent::AntePosted {
                table_id: table.id,
                seat_index: seat_idx,
                amount: actual,
                ante_mode: mode,
            },
        );
    }
    Ok(())
}

/// `collect_rake` — 在 `settle_hand` 中按 `rake_mode` 抽水。
///
/// 此函数由 `settle_hand` / `end_without_showdown` 内部调用。
/// 抽水规则：
/// - `RAKE_MODE_NONE`：不抽水
/// - `RAKE_MODE_PERCENTAGE`：`rake = min(pot * rake_bps / 10000, rake_cap)`
///
/// 抽水后：
/// - `table.rake_collected += rake`（本次 dispatch 的 Treasury 出金收据）
/// - `table.pot -= rake`（从奖池中扣除）
/// - `table.chip_pool -= rake`（资金已离开桌台，预编译将创建 Treasury Coin 输出）
///
/// 返回实际抽水金额（调用方用于 emit RakeCollected 事件）。
pub fn collect_rake(table: &mut TexasPokerTable) -> PokerL1Result<u64> {
    if table.rake_mode == super::constants::RAKE_MODE_NONE {
        return Ok(0);
    }
    let pot = table.pot;
    let rake = compute_rake_amount(table, pot)?;
    let post_rake_receipt = table
        .rake_collected
        .checked_add(rake)
        .ok_or_else(|| PokerL1Error::Serialization("collect_rake: rake receipt overflow".into()))?;
    let post_pot = table
        .pot
        .checked_sub(rake)
        .ok_or_else(|| PokerL1Error::Serialization("collect_rake: pot -= rake underflow".into()))?;
    let post_chip_pool = table.chip_pool.checked_sub(rake).ok_or_else(|| {
        PokerL1Error::Serialization("collect_rake: rake exceeds TableVault".into())
    })?;
    table.rake_collected = post_rake_receipt;
    table.pot = post_pot;
    table.chip_pool = post_chip_pool;
    Ok(rake)
}

/// `trigger_run_it_twice` — 标记本手将执行 Run It Twice（all-in 后）。
///
/// ## v2 PoC 范围
///
/// 当前实现：仅设置标记并 emit 事件。
///
/// ## 完整实现路线图
///
/// 完整 RIT 流程需要扩展 Mental Poker 协议层：
///
/// 1. **双 board 发牌**：all-in 后，从剩余牌组发两套公共牌（各 5 张），
///    需要扩展 `submit_player_reveal_tokens` 以支持两个 board 的独立 reveal phase
/// 2. **双 board settlement**：分别评估两套 board 的胜者，pot 对半分
/// 3. **AIR 影响**：需要扩展 `submit_player_reveal_tokens` AIR 约束以验证两套 board
///    的 reveal 一致性；settlement AIR 需约束双 pot 分配
///
/// ## AIR 约束策略
///
/// RIT AIR 约束嵌入 `submit_player_reveal_tokens` AIR 和 settlement 流程：
/// - Board 1 reveal tokens 与 Board 2 reveal tokens 独立约束
/// - Pot split 不变量：`pot_after = pot_before`（总额不变，只是分配方式改变）
/// - 双 board 使用的牌不重叠（range check on deck indices）
///
/// 此 PoC 仅标记状态，完整流程待 Mental Poker V3 实现。
pub fn trigger_run_it_twice(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.rit_mode == super::constants::RIT_MODE_DISABLED {
        return Ok(());
    }
    if table.rit_mode != super::constants::RIT_MODE_TWICE {
        return Err(PokerL1Error::Serialization(format!(
            "trigger_run_it_twice: unsupported rit_mode {}",
            table.rit_mode
        )));
    }
    // PoC: 仅 emit 事件，标记本手为 RIT 模式
    events::emit_event(
        events,
        TexasPokerEvent::RunItTwiceTriggered {
            table_id: table.id,
            board1_cards: 5, // 完整 board
            board2_cards: 5,
        },
    );
    table.bump_version();
    Ok(())
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn dummy_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new(dummy_id(), "test".into(), EMPTY_PLAYER, 4, 50, 100)
    }

    #[test]
    fn test_can_join_state_initial() {
        let table = make_table();
        assert!(can_join_state(&table));
        assert!(can_leave_state(&table));
        assert!(!is_playing(&table));
    }

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

    #[test]
    fn test_community_reveal_uses_plaintext_identity_not_encrypted_index() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        let plaintext_id = 3u8;
        let encrypted_card_index = 41u8;
        table.deck_state.decrypted_cards.push(DecryptedCard {
            encrypted_card_index,
            owner_seat_index: OWNER_SEAT_PUBLIC,
            ciphertext: None,
            plaintext: Some(table.deck_state.plaintext[usize::from(plaintext_id)]),
        });
        let mut events = vec![];

        write_decrypted_cards_to_community(&mut table, REVEAL_PHASE_TURN, &mut events).unwrap();

        assert_eq!(table.community_cards, vec![Card::from_index(plaintext_id)]);
        assert_ne!(
            table.community_cards[0],
            Card::from_index(encrypted_card_index)
        );
        assert!(matches!(
            events.as_slice(),
            [TexasPokerEvent::CommunityCardRevealed { phase, card_indices, card_ranks, card_suits, .. }]
                if *phase == REVEAL_PHASE_TURN
                    && card_indices == &vec![encrypted_card_index]
                    && card_ranks == &vec![Card::from_index(plaintext_id).rank]
                    && card_suits == &vec![Card::from_index(plaintext_id).suit]
        ));
    }

    #[test]
    fn test_unknown_community_plaintext_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.decrypted_cards.push(DecryptedCard {
            encrypted_card_index: 7,
            owner_seat_index: OWNER_SEAT_PUBLIC,
            ciphertext: None,
            plaintext: Some(ECPoint::from(utils::hash_to_g1(b"not-a-canonical-card"))),
        });
        let before = table.clone();
        let mut events = vec![];

        let error = write_decrypted_cards_to_community(&mut table, REVEAL_PHASE_FLOP, &mut events)
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("not a canonical Texas Poker card")
        );
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_duplicate_community_plaintext_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        let plaintext = table.deck_state.plaintext[9];
        for encrypted_card_index in [2u8, 38u8] {
            table.deck_state.decrypted_cards.push(DecryptedCard {
                encrypted_card_index,
                owner_seat_index: OWNER_SEAT_PUBLIC,
                ciphertext: None,
                plaintext: Some(plaintext),
            });
        }
        let before = table.clone();
        let mut events = vec![];

        let error = write_decrypted_cards_to_community(&mut table, REVEAL_PHASE_FLOP, &mut events)
            .unwrap_err();

        assert!(error.to_string().contains("duplicate decrypted card id 9"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_hole_card_duplicate_with_community_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.seats[0].player = [1; 20];
        let duplicate_id = 12u8;
        table.community_cards.push(Card::from_index(duplicate_id));
        table.deck_state.decrypted_cards.push(DecryptedCard {
            encrypted_card_index: 44,
            owner_seat_index: 0,
            ciphertext: None,
            plaintext: Some(table.deck_state.plaintext[usize::from(duplicate_id)]),
        });
        let before = table.clone();
        let mut events = vec![];

        let error = write_decrypted_cards_to_hands(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("duplicate decrypted card id 12"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_reconstruction_v3_two_players_rebuilds_canonical_deck() {
        let mut table = make_table();
        let generator = g1_generator();
        let owner_secrets = [scalar_from_u64(101), scalar_from_u64(202)];
        let owner_public_keys = [generator * owner_secrets[0], generator * owner_secrets[1]];
        let aggregate_pk = owner_public_keys[0] + owner_public_keys[1];

        for (seat_index, owner_pk) in owner_public_keys.iter().enumerate() {
            table.seats[seat_index].player = [(seat_index as u8) + 1; 20];
            table.seats[seat_index].stack = 1_000;
            table.seats[seat_index].pk = ECPoint::from(*owner_pk);
        }
        set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.aggregated_pk = Some(ECPoint::from(aggregate_pk));
        table.hand_id = 7;
        table.round_state = ROUND_FLOP;
        table.timestamps.reconstruct_started_at = 9_000;
        table.reconstruct_state = super::super::types::ReconstructState {
            phase: RECONSTRUCT_PHASE_COLLECTING,
            pending_players: vec![0, 1],
            coefficient: Some(ECScalar::from(scalar_from_u64(1))),
            player_decks: vec![],
        };

        // These ciphertexts model the authenticated, still-encrypted owner-readable
        // cards retained from the previous round. Their plaintexts are canonical
        // init-deck card points, but their readable-list order does not reveal the
        // hidden canonical slots used by the V3 Bayer--Groth witness.
        let readable_card_indices = [[17usize, 3usize], [41usize, 9usize]];
        for (seat_index, indices) in readable_card_indices.iter().enumerate() {
            for (record_index, card_index) in indices.iter().enumerate() {
                let plaintext = table.deck_state.plaintext[*card_index].0;
                let randomness =
                    scalar_from_u64(1_000 + (seat_index as u64) * 10 + record_index as u64);
                table.deck_state.decrypted_cards.push(DecryptedCard {
                    encrypted_card_index: (20 + seat_index * 2 + record_index) as u8,
                    owner_seat_index: seat_index as u8,
                    ciphertext: Some(ElGamalCiphertext::encrypt(
                        &plaintext,
                        &owner_public_keys[seat_index],
                        &randomness,
                    )),
                    plaintext: None,
                });
            }
        }

        let canonical_cards = table
            .deck_state
            .plaintext
            .iter()
            .map(|point| point.0)
            .collect::<Vec<_>>();
        let preserved_readable_cards = table.deck_state.decrypted_cards.clone();
        let mut expected_deck =
            canonical_base_deck::<DefaultCurve>(&canonical_cards, &aggregate_pk)
                .expect("canonical aggregate-key base deck");
        let mut events = vec![];

        for seat_index in 0..2usize {
            let context_digest = utils::reconstruction_v3_context_digest(&table);
            let prior_state_digest =
                utils::reconstruction_v3_prior_state_digest(&table, seat_index as u8).unwrap();
            let readable_cards =
                utils::reconstruction_v3_user_readable_cards(&table, seat_index as u8);
            let mut transcript = utils::new_reconstruct_v3_transcript();
            let mut rng = StdRng::seed_from_u64(0xC0DE_0000 + seat_index as u64);
            let (statement, proof) = ReconstructProofV3::prove(
                context_digest,
                table.timestamps.reconstruct_started_at,
                prior_state_digest,
                canonical_cards.clone(),
                readable_cards,
                &owner_secrets[seat_index],
                &owner_public_keys[seat_index],
                &aggregate_pk,
                &mut rng,
                &mut transcript,
            )
            .expect("honest reconstruction V3 proof");

            expected_deck = apply_reconstruction_contributions::<DefaultCurve>(
                &expected_deck,
                &statement.contributions,
            )
            .expect("apply verified contribution vector");
            apply_submit_reconstruct_deck(
                &mut table,
                seat_index as u8,
                statement,
                proof,
                &mut events,
            )
            .expect("state machine accepts honest reconstruction V3 submission");
        }

        assert_eq!(table.deck_state.encrypted, expected_deck);
        assert_eq!(table.deck_state.cards_dealt, 0);
        assert_eq!(table.deck_state.decrypted_cards, preserved_readable_cards);
        assert_eq!(
            table.reconstruct_state,
            super::super::types::ReconstructState::default()
        );
        assert_eq!(table.shuffle_state.phase, SHUFFLE_PHASE_RECONSTRUCT);
        assert_eq!(table.shuffle_state.current_shuffler, Some(0));
        assert_eq!(table.shuffle_state.pending_players, vec![0, 1]);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::ReconstructComplete { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::DeckRebuilt { .. }))
        );
    }

    #[test]
    fn test_is_pk_registered() {
        let mut table = make_table();
        let g = g1_generator();
        let pk = g * scalar_from_u64(0xAB);
        assert!(!is_pk_registered(&table.seats, &pk));
        table.seats[0].player = [0x01; 20];
        table.seats[0].pk = ECPoint::from(pk);
        assert!(is_pk_registered(&table.seats, &pk));
        let other_pk = g * scalar_from_u64(0xCD);
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

    #[test]
    fn test_add_remove_pk_aggregated() {
        let g = g1_generator();
        let pk1 = g * scalar_from_u64(111);
        let pk2 = g * scalar_from_u64(222);

        // typed 化后 add/remove_pk_to/from_aggregated 接受 Option<&G1Projective>，
        // 返回 Option<G1Projective>（None = 空/单位元）。
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
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::HandStarted { .. }))
        );
    }

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
        let (sb, bb, first) = post_blinds(&mut table, &mut events).unwrap();
        assert_eq!(sb, 0);
        assert_eq!(bb, 1);
        assert_eq!(first, 1);
        assert_eq!(table.seats[0].bet, 50);
        assert_eq!(table.seats[1].bet, 100);
        assert_eq!(table.seats[0].stack, 950);
        assert_eq!(table.seats[1].stack, 900);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::BlindsPosted { .. }))
        );
    }

    #[test]
    fn test_apply_fold_ends_without_showdown() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new(100, 100));
        table.current_turn = Some(0);
        table.pot = 200;
        let mut events = vec![];

        apply_fold(&mut table, 0, &mut events).unwrap();
        // fold 后只剩 1 名活跃玩家 → end_without_showdown → reset_for_next_hand
        // 会清掉 folded 标记，故此处仅断言事件与筹码分配。
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerFolded { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::HandEndedWithoutShowdown { .. }))
        );
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
        table.betting_round = Some(BettingRound::new(100, 100));
        table.current_turn = Some(0);
        let mut events = vec![];

        apply_call(&mut table, 0, &mut events).unwrap();
        assert_eq!(table.seats[0].stack, 900);
        assert_eq!(table.seats[0].bet, 100);
        assert!(table.seats[0].acted_this_round);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerCalled { .. }))
        );
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
        table.betting_round = Some(BettingRound::new(100, 100));
        table.current_turn = Some(0);
        let mut events = vec![];

        apply_raise(&mut table, 0, 300, &mut events).unwrap();
        assert_eq!(table.seats[0].bet, 300);
        assert_eq!(table.seats[0].stack, 700);
        assert!(!table.seats[1].acted_this_round);
    }

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

    #[test]
    fn test_kick_player_internal_removes_pk() {
        let mut table = make_table();
        let g = g1_generator();
        // 3 个玩家，pk = sk_i * G；aggregated_pk = pk0 + pk1 + pk2。
        let pk0 = g * scalar_from_u64(42);
        let pk1 = g * scalar_from_u64(43);
        let pk2 = g * scalar_from_u64(44);
        let agg = pk0 + pk1 + pk2;

        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;
        table.seats[0].pk = ECPoint::from(pk0);
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 500;
        table.seats[1].pk = ECPoint::from(pk1);
        table.seats[2].player = [0x03; 20];
        table.seats[2].stack = 500;
        table.chip_pool = 1_500;
        table.seats[2].pk = ECPoint::from(pk2);
        table.deck_state.aggregated_pk = Some(ECPoint::from(agg));
        // 用一个非 NONE 的 round_state，使 reset_for_next_hand 不会被触发
        // （count_active_players 在 kick 后仍 >= MIN_PLAYERS_TO_START）。
        table.round_state = ROUND_PREFLOP;
        let mut events = vec![];

        kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events).unwrap();
        // kick 后 active=2（seat1+seat2），不会触发 reset_for_next_hand。
        assert!(table.seats[0].left_during_hand);
        assert!(table.seats[0].folded);
        assert_eq!(table.seats[0].stack, 0);
        // Seat::empty() 后 pk 为 G1Projective::identity()（默认值）。
        assert!(g1_is_identity(&table.seats[0].pk));
        // aggregated_pk 应 = pk1 + pk2（移除 pk0）。
        let new_agg = table.deck_state.aggregated_pk.unwrap();
        let expected = pk1 + pk2;
        assert!(g1_equal(&new_agg, &expected));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerKicked { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerRefund { .. }))
        );
    }

    #[test]
    fn test_kick_player_pool_underflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 10;
        table.chip_pool = 9;
        let before = table.clone();
        let mut events = vec![];

        let error =
            kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events).unwrap_err();

        assert!(error.to_string().contains("chip_pool underflow"));
        assert_eq!(table, before, "failed kick refund must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_kick_player_nested_reset_failure_is_atomic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 10;
        // A waiting seat is not counted as active, so kicking seat 0 triggers reset. Keep the
        // addon pool deliberately inconsistent so reset fails after the kick candidate mutates.
        table.seats[1].player = [0x02; 20];
        table.seats[1].is_waiting = true;
        table.seats[1].pending_addon = 5;
        table.chip_pool = 10;
        table.addon_pool = 4;
        let before = table.clone();
        let mut events = vec![];

        let error = kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events)
            .expect_err("nested reset failure must propagate");

        assert!(error.to_string().contains("pending addon pool underflow"));
        assert_eq!(
            table, before,
            "nested reset failure must not commit the kick"
        );
        assert!(
            events.is_empty(),
            "failed kick must not emit partial events"
        );
    }

    #[test]
    fn test_partial_decrypt_c2_subtracts_tokens() {
        let g = g1_generator();
        let sk = scalar_from_u64(42);
        let pk = g * sk;
        let plaintext = utils::hash_to_g1(b"test_card");
        let r = scalar_from_u64(7);
        let ct = ElGamalCiphertext::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);

        // typed 化后 partial_decrypt_c2 直接接受 G1Projective，返回 G1Projective。
        let result = partial_decrypt_c2(&ct.c2, &[token]);
        assert!(g1_equal(&result, &plaintext));
    }

    #[test]
    fn test_is_betting_complete() {
        let mut table = make_table();
        table.round_state = ROUND_PREFLOP;
        table.betting_round = Some(BettingRound::new(100, 100));
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

    // ========== Addon / Rebuy 单元测试 ==========

    #[test]
    fn test_apply_addon_basic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;
        let mut events = vec![];

        apply_addon(&mut table, 0, 200, &mut events).unwrap();
        // 关键不变量：stack 不变（不影响当前手牌）
        assert_eq!(table.seats[0].stack, 500);
        assert_eq!(table.seats[0].pending_addon, 200);
        assert_eq!(table.addon_pool, 200);
        assert_eq!(table.version, 1);
        // 事件
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::AddonRequested { amount: 200, .. }))
        );
    }

    #[test]
    fn test_apply_addon_accumulates() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;

        apply_addon(&mut table, 0, 100, &mut vec![]).unwrap();
        apply_addon(&mut table, 0, 50, &mut vec![]).unwrap();
        assert_eq!(table.seats[0].pending_addon, 150);
        assert_eq!(table.addon_pool, 150);
        assert_eq!(table.seats[0].stack, 500); // 仍不变
    }

    #[test]
    fn test_apply_addon_invalid_seat() {
        let mut table = make_table();
        // 越界
        let err = apply_addon(&mut table, 99, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat_index 99 out of range"));
        // amount == 0
        table.seats[0].player = [0x01; 20];
        let err = apply_addon(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
        // 未占用座位
        let err = apply_addon(&mut table, 1, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat 1 not occupied"));
    }

    #[test]
    fn test_reset_for_next_hand_merges_addon() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 0; // stack==0 触发清理
        table.seats[0].pending_addon = 500; // 但有 addon
        table.chip_pool = 500;
        table.addon_pool = 500;

        let mut events = vec![];
        reset_for_next_hand(&mut table, &mut events).unwrap();

        // addon 合并后 stack > 0，玩家不应被踢
        assert_eq!(table.seats[0].stack, 500);
        assert_eq!(table.seats[0].pending_addon, 0);
        assert_eq!(table.seats[0].player, [0x01; 20]);
        // AddonCredited 事件应触发
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::AddonCredited {
                amount: 500,
                stack_after: 500,
                ..
            }
        )));
    }

    #[test]
    fn test_reset_for_next_hand_pool_underflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].pending_addon = 5;
        table.chip_pool = 5;
        table.addon_pool = 4;
        let before = table.clone();
        let mut events = vec![];

        let error = reset_for_next_hand(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("pending addon pool underflow"));
        assert_eq!(table, before, "failed addon merge must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_reset_for_next_hand_leave_underflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 10;
        table.seats[0].want_leave = true;
        table.chip_pool = 9;
        let before = table.clone();
        let mut events = vec![];

        let error = reset_for_next_hand(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("leave chip_pool underflow"));
        assert_eq!(table, before, "failed leave refund must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_reset_for_next_hand_addon_then_cleanup() {
        // addon=0 且 stack=0 的玩家应被清理（不能误保留）
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 0;
        table.seats[0].pending_addon = 0;

        let mut events = vec![];
        reset_for_next_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.seats[0].player, [0u8; 20]); // EMPTY_PLAYER
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerLeft { seat_index: 0, .. }))
        );
    }

    #[test]
    fn test_apply_rebuy_immediate() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 100;
        table.chip_pool = 100;

        let mut events = vec![];
        apply_rebuy(&mut table, 0, 500, &mut events).unwrap();
        // 立即生效
        assert_eq!(table.seats[0].stack, 600);
        assert_eq!(table.chip_pool, 600);
        assert_eq!(table.addon_pool, 0);
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::RebuyProcessed {
                amount: 500,
                stack_after: 600,
                ..
            }
        )));
    }

    #[test]
    fn test_apply_rebuy_invalid() {
        let mut table = make_table();
        // amount == 0
        table.seats[0].player = [0x01; 20];
        let err = apply_rebuy(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
        // 未占用
        let err = apply_rebuy(&mut table, 1, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat 1 not occupied"));
    }

    fn empty_leave_proof() -> DLEqProof<DefaultCurve, LeaveKind> {
        let zero = utils::scalar_zero();
        DLEqProof::from_parts(vec![], G1Projective::identity(), zero, zero)
    }

    fn make_leave_with_proof_table(stack: u64, pending_addon: u64) -> TexasPokerTable {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = stack;
        table.seats[0].pending_addon = pending_addon;
        table.shuffle_state.completed_players = vec![0];
        table
    }

    #[test]
    fn test_leave_with_proof_rejects_refund_overflow_without_mutation() {
        let mut table = make_leave_with_proof_table(u64::MAX, 1);
        table.chip_pool = u64::MAX;
        table.addon_pool = 1;
        let before = table.clone();
        let mut events = vec![];

        let error = apply_leave_with_proof(&mut table, 0, vec![], empty_leave_proof(), &mut events)
            .unwrap_err();

        assert!(error.to_string().contains("refund overflow"));
        assert_eq!(table, before, "failed refund must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_leave_with_proof_rejects_pool_underflow_without_mutation() {
        let mut table = make_leave_with_proof_table(10, 5);
        table.chip_pool = 15;
        table.addon_pool = 4;
        let before = table.clone();
        let mut events = vec![];

        let error = apply_leave_with_proof(&mut table, 0, vec![], empty_leave_proof(), &mut events)
            .unwrap_err();

        assert!(error.to_string().contains("addon_pool underflow"));
        assert_eq!(table, before, "failed refund must be atomic");
        assert!(events.is_empty());
    }

    // ========== Bet 动作测试 ==========

    #[test]
    fn test_apply_bet_postflop() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[0].bet = 0; // postflop bet=0
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        table.round_state = ROUND_FLOP;
        table.betting_round = Some(BettingRound::new(100, 0));
        table.current_turn = Some(0);
        let mut events = vec![];

        apply_bet(&mut table, 0, 200, &mut events).unwrap();
        assert_eq!(table.seats[0].bet, 200);
        assert_eq!(table.seats[0].stack, 800);
        assert!(table.seats[0].acted_this_round);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerBet { amount: 200, .. }))
        );
    }

    #[test]
    fn test_apply_bet_rejects_when_current_bet_exists() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[0].bet = 50;
        table.round_state = ROUND_FLOP;
        table.betting_round = Some(BettingRound::new(100, 0));
        // 模拟已有下注：current_bet = 100 > seat.bet = 50
        table.betting_round.as_mut().unwrap().current_bet = 100;
        table.current_turn = Some(0);

        let err = apply_bet(&mut table, 0, 200, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("current_bet 100 > seat_bet 50"));
    }

    #[test]
    fn test_apply_bet_rejects_zero_amount() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.round_state = ROUND_FLOP;
        table.betting_round = Some(BettingRound::new(100, 0));
        table.current_turn = Some(0);

        let err = apply_bet(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
    }

    // ========== Time Bank 测试 ==========

    #[test]
    fn test_consume_time_bank_basic() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].time_bank_ms = 30_000;
        let mut events = vec![];

        consume_time_bank(&mut table, 0, 10_000, &mut events).unwrap();
        assert_eq!(table.seats[0].time_bank_ms, 20_000);
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::TimeBankConsumed {
                consumed_ms: 10_000,
                remaining_ms: 20_000,
                ..
            }
        )));
    }

    #[test]
    fn test_consume_time_bank_insufficient() {
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].time_bank_ms = 5_000;
        let err = consume_time_bank(&mut table, 0, 10_000, &mut vec![]).unwrap_err();
        assert!(
            err.to_string()
                .contains("time_bank_ms 5000 < consumed_ms 10000")
        );
    }

    // ========== Ante 测试 ==========

    #[test]
    fn test_collect_ante_normal_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NORMAL;
        table.ante_amount = 10;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let mut events = vec![];

        collect_ante(&mut table, 1, &mut events).unwrap();
        assert_eq!(table.ante_collected, 20); // 2 个玩家各投 10
        assert_eq!(table.pot, 20);
        assert_eq!(table.seats[0].stack, 990);
        assert_eq!(table.seats[1].stack, 990);
        assert_eq!(table.seats[0].bet, 0);
        assert_eq!(table.seats[1].bet, 0);
        assert_eq!(table.seats[0].total_bet, 10);
        assert_eq!(table.seats[1].total_bet, 10);
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TexasPokerEvent::AntePosted { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn test_ante_does_not_buy_down_call_and_table_vault_reconciles() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NORMAL;
        table.ante_amount = 10;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1_000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1_000;
        table.chip_pool = 2_000;
        let mut events = vec![];

        let (_, bb_seat, _) = post_blinds(&mut table, &mut events).unwrap();
        collect_ante(&mut table, bb_seat, &mut events).unwrap();
        start_betting_round(&mut table, true, Some(bb_seat), &mut events).unwrap();

        assert_eq!(table.betting_round.unwrap().current_bet, table.big_blind);
        assert_eq!(table.pot, 20);
        assert_eq!(table.seats.iter().map(|seat| seat.bet).sum::<u64>(), 150);
        assert_eq!(reconcile_table_vault(&table).unwrap(), 2_000);
    }

    #[test]
    fn test_collect_ante_bba_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_BBA;
        table.ante_amount = 20;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let mut events = vec![];

        // BBA 模式：仅 bb_seat=1 投 ante
        collect_ante(&mut table, 1, &mut events).unwrap();
        assert_eq!(table.ante_collected, 20);
        assert_eq!(table.seats[0].stack, 1000); // SB 不投 ante
        assert_eq!(table.seats[1].stack, 980); // BB 投 ante
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TexasPokerEvent::AntePosted { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn test_collect_ante_none_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NONE;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        let mut events = vec![];

        collect_ante(&mut table, 0, &mut events).unwrap();
        assert_eq!(table.ante_collected, 0);
        assert!(events.is_empty());
    }

    // ========== Rake 测试 ==========

    #[test]
    fn test_collect_rake_percentage() {
        let mut table = make_table();
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500; // 5%
        table.rake_cap = 100;
        table.pot = 1000;
        table.chip_pool = 1000;

        let pot_before = table.pot;
        let rake = collect_rake(&mut table).unwrap();
        assert_eq!(rake, 50); // 1000 * 5% = 50
        assert_eq!(table.pot, 950);
        assert_eq!(table.chip_pool, 950);
        assert_eq!(table.rake_collected, 50);
        assert_eq!(pot_before, 1000);
    }

    #[test]
    fn test_collect_rake_capped() {
        let mut table = make_table();
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500; // 5%
        table.rake_cap = 30;
        table.pot = 1000;
        table.chip_pool = 1000;

        let rake = collect_rake(&mut table).unwrap();
        // raw_rake = 50，但 cap = 30
        assert_eq!(rake, 30);
        assert_eq!(table.pot, 970);
    }

    #[test]
    fn test_collect_rake_uses_full_width_multiplication() {
        let mut table = make_table();
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = u64::MAX;
        table.rake_cap = u64::MAX;
        table.pot = u64::MAX;
        table.chip_pool = u64::MAX;

        let rake = collect_rake(&mut table).unwrap();
        assert_eq!(rake, u64::MAX);
        assert_eq!(table.pot, 0);
        assert_eq!(table.chip_pool, 0);
        assert_eq!(table.rake_collected, u64::MAX);
    }

    #[test]
    fn test_side_pot_rake_remainder_never_overdraws_small_main_pot() {
        let mut result = side_pot::SidePotResult {
            pots: vec![
                side_pot::SidePot::new(1, 0b111),
                side_pot::SidePot::new(1, 0b110),
                side_pot::SidePot::new(1, 0b100),
            ],
        };

        apply_rake_to_pots(&mut result, 2).unwrap();
        assert_eq!(result.total(), 1);
    }

    #[test]
    fn test_collect_rake_none_mode() {
        let mut table = make_table();
        table.rake_mode = RAKE_MODE_NONE;
        table.pot = 1000;

        let rake = collect_rake(&mut table).unwrap();
        assert_eq!(rake, 0);
        assert_eq!(table.pot, 1000);
    }

    // ========== Run It Twice 测试 ==========

    #[test]
    fn test_trigger_run_it_twice_enabled() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_TWICE;
        let mut events = vec![];

        trigger_run_it_twice(&mut table, &mut events).unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::RunItTwiceTriggered {
                board1_cards: 5,
                board2_cards: 5,
                ..
            }
        )));
    }

    #[test]
    fn test_trigger_run_it_twice_disabled() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_DISABLED;
        let mut events = vec![];

        trigger_run_it_twice(&mut table, &mut events).unwrap();
        // DISABLED 模式下不 emit 事件
        assert!(events.is_empty());
    }
}
