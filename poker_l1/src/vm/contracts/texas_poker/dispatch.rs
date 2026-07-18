//! Texas Poker 合约 dispatch 路由（17 method selector）。
//!
//! 严格对齐 `texas_poker_move/sources/table.move` 的 public entry function 清单：
//! - 表台生命周期：create_table / join_table / leave_table / start_hand / tick
//! - 玩家动作：fold / check / call / raise / auto_fold / force_fold / kick_player
//! - Mental Poker 协议：join_and_shuffle / leave_with_proof / submit_shuffle_v2
//!   / submit_player_reveal_tokens / submit_reconstruct_deck
//!
//! # Selector 计算
//!
//! `blake2b_256(method_name)[0..32]`，与 `contracts/dispatch.rs` 保持一致。
//!
//! # Args 编码
//!
//! 每个 method 对应一个 `*Args` 结构体，使用 BCS 序列化。
//!
//! # Events 处理
//!
//! state_machine 函数会通过 `events: &mut Vec<TexasPokerEvent>` 收集事件。
//! dispatch 层目前仅记录日志（tracing::debug!）并丢弃，后续 Precompile
//! 实现可在 Phase 3.3 / Phase 4 中扩展 DispatchResult 携带 events 字段。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use super::constants::{FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN, KICK_REASON_ADMIN};
use super::events::TexasPokerEvent;
use super::state_machine;
use super::types::TexasPokerTable;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::vm::contracts::dispatch::{DispatchContext, DispatchResult};
use crate::{Address, BlockHeight, ChainId};

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// 与 `contracts::dispatch::compute_method_selector` 算法一致，
/// 但独立定义以避免循环依赖（texas_poker 不应被父 dispatch 模块引用）。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    let mut h = Blake2bVar::new(METHOD_SELECTOR_LEN).expect("32 <= 64");
    h.update(method_name.as_bytes());
    let mut out = [0u8; METHOD_SELECTOR_LEN];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 17 个方法选择器常量。
///
/// 所有方法名使用 snake_case，与 Move 端 entry function 名一一对应。
pub mod selectors {
    use super::compute_method_selector;

    /// `create_table` — 创建新桌台。
    pub fn create_table() -> [u8; 32] {
        compute_method_selector("create_table")
    }

    /// `join_and_shuffle` — 玩家加入并完成首洗牌（含 remask + shuffle proof）。
    pub fn join_and_shuffle() -> [u8; 32] {
        compute_method_selector("join_and_shuffle")
    }

    /// `leave_with_proof` — 玩家带 proof 离场（保留手牌贡献）。
    pub fn leave_with_proof() -> [u8; 32] {
        compute_method_selector("leave_with_proof")
    }

    /// `join_table` — 简单入座（不参与本局，等下一局）。
    pub fn join_table() -> [u8; 32] {
        compute_method_selector("join_table")
    }

    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    pub fn leave_table() -> [u8; 32] {
        compute_method_selector("leave_table")
    }

    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    pub fn start_hand() -> [u8; 32] {
        compute_method_selector("start_hand")
    }

    /// `tick` — 超时驱动（permissionless）。
    pub fn tick() -> [u8; 32] {
        compute_method_selector("tick")
    }

    /// `auto_fold` — 玩家超时自动 fold。
    pub fn auto_fold() -> [u8; 32] {
        compute_method_selector("auto_fold")
    }

    /// `force_fold` — 管理员强制 fold 玩家。
    pub fn force_fold() -> [u8; 32] {
        compute_method_selector("force_fold")
    }

    /// `kick_player` — 踢出玩家（管理员操作）。
    pub fn kick_player() -> [u8; 32] {
        compute_method_selector("kick_player")
    }

    /// `submit_shuffle_v2` — 玩家提交洗牌结果（第二手及以后）。
    pub fn submit_shuffle_v2() -> [u8; 32] {
        compute_method_selector("submit_shuffle_v2")
    }

    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    pub fn submit_player_reveal_tokens() -> [u8; 32] {
        compute_method_selector("submit_player_reveal_tokens")
    }

    /// `submit_reconstruct_deck` — 提交重构牌组。
    pub fn submit_reconstruct_deck() -> [u8; 32] {
        compute_method_selector("submit_reconstruct_deck")
    }

    /// `fold` — 玩家主动 fold。
    pub fn fold() -> [u8; 32] {
        compute_method_selector("fold")
    }

    /// `check` — 玩家过牌。
    pub fn check() -> [u8; 32] {
        compute_method_selector("check")
    }

    /// `call` — 玩家跟注。
    pub fn call() -> [u8; 32] {
        compute_method_selector("call")
    }

    /// `raise` — 玩家加注。
    pub fn raise() -> [u8; 32] {
        compute_method_selector("raise")
    }

    /// 返回所有 17 个 selector，供 `supports_selector` 等使用。
    #[must_use]
    pub fn all() -> Vec<[u8; 32]> {
        vec![
            create_table(),
            join_and_shuffle(),
            leave_with_proof(),
            join_table(),
            leave_table(),
            start_hand(),
            tick(),
            auto_fold(),
            force_fold(),
            kick_player(),
            submit_shuffle_v2(),
            submit_player_reveal_tokens(),
            submit_reconstruct_deck(),
            fold(),
            check(),
            call(),
            raise(),
        ]
    }
}

// ========== Args 结构体（BCS 序列化）==========

/// `create_table` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateTableArgs {
    /// 桌台名称。
    pub name: String,
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注金额。
    pub small_blind: u64,
    /// 大盲注金额。
    pub big_blind: u64,
}

/// `join_and_shuffle` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinAndShuffleArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家公钥（G1 compressed 48 字节）。
    pub pk: Vec<u8>,
    /// pk 所有权证明（暂时未强制验证，保留字段）。
    pub pk_ownership_proof: Vec<u8>,
    /// remask 后的牌组掩码（c1 拼接，48*N 字节）。
    pub mask_cards: Vec<u8>,
    /// shuffle 输出牌组（c1||c2 拼接，96*N 字节）。
    pub output_cards: Vec<u8>,
    /// remask proof 字节。
    pub remask_proof: Vec<u8>,
    /// shuffle proof 字节。
    pub shuffle_proof: Vec<u8>,
}

/// `leave_with_proof` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaveWithProofArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 离场时的牌组输出（用于验证贡献连续性）。
    pub output_cards: Vec<u8>,
    /// leave proof 字节。
    pub leave_proof: Vec<u8>,
}

/// `join_table` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JoinTableArgs {
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家公钥（G1 compressed 48 字节）。
    pub pk: Vec<u8>,
}

/// `leave_table` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaveTableArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `tick` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TickArgs {
    /// 当前时间戳（毫秒）。
    pub now_ms: u64,
}

/// `auto_fold` / `force_fold` / `fold` / `check` / `call` 参数（仅 seat_index）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeatIndexArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `kick_player` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KickPlayerArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 踢出原因（KICK_REASON_*）。
    pub reason: u8,
}

/// `submit_shuffle_v2` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitShuffleV2Args {
    /// 座位索引。
    pub seat_index: u8,
    /// shuffle 输出牌组（c1||c2 拼接，96*N 字节）。
    pub output_cards: Vec<u8>,
    /// shuffle proof 字节。
    pub shuffle_proof: Vec<u8>,
}

/// `submit_player_reveal_tokens` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitRevealTokensArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 揭牌分配索引列表（每张待揭示牌在 deck 中的位置）。
    pub assignment_indices: Vec<u8>,
    /// 揭牌令牌列表（每个 = 48 字节 G1 compressed）。
    pub reveal_tokens: Vec<Vec<u8>>,
    /// 揭牌 proof 列表（与 reveal_tokens 一一对应）。
    pub proofs: Vec<Vec<u8>>,
}

/// `submit_reconstruct_deck` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubmitReconstructDeckArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 重构输出牌组（c1||c2 拼接，96*N 字节）。
    pub output_cards: Vec<u8>,
    /// swap 牌组（暂时未用，保留）。
    pub swap_cards: Vec<u8>,
    /// user_readable 牌组（暂时未用，保留）。
    pub user_readable_cards: Vec<u8>,
    /// reconstruct proof 字节。
    pub proof: Vec<u8>,
}

/// `raise` 参数。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaiseArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 加注后该玩家本轮总下注额（不是加注增量）。
    pub total_bet: u64,
}

// ========== Dispatch 路由入口 ==========

/// Dispatch 路由入口。
///
/// 将 ContractCall 路由到对应的 Texas Poker 合约方法。
///
/// 参数：
/// - `context`：执行上下文（调用者、block 信息等）
/// - `table`：可变的 `TexasPokerTable` 引用（状态变更目标）
/// - `selector`：方法选择器（32 字节）
/// - `args`：调用参数（BCS 编码）
///
/// 返回：`DispatchResult` 包含状态变更信息。
///
/// 失败时返回 `PokerL1Error::UnknownContractMethod`（未知方法）或各业务方法的具体错误。
pub fn dispatch(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let mut events: Vec<TexasPokerEvent> = Vec::new();
    let result = match selector {
        s if s == &selectors::create_table() => dispatch_create_table(table, args, &mut events),
        s if s == &selectors::join_and_shuffle() => {
            dispatch_join_and_shuffle(context, table, args, &mut events)
        }
        s if s == &selectors::leave_with_proof() => {
            dispatch_leave_with_proof(table, args, &mut events)
        }
        s if s == &selectors::join_table() => dispatch_join_table(context, table, args, &mut events),
        s if s == &selectors::leave_table() => dispatch_leave_table(table, args, &mut events),
        s if s == &selectors::start_hand() => dispatch_start_hand(table, args, &mut events),
        s if s == &selectors::tick() => dispatch_tick(table, args, &mut events),
        s if s == &selectors::auto_fold() => dispatch_auto_fold(table, args, &mut events),
        s if s == &selectors::force_fold() => dispatch_force_fold(table, args, &mut events),
        s if s == &selectors::kick_player() => dispatch_kick_player(table, args, &mut events),
        s if s == &selectors::submit_shuffle_v2() => {
            dispatch_submit_shuffle_v2(table, args, &mut events)
        }
        s if s == &selectors::submit_player_reveal_tokens() => {
            dispatch_submit_player_reveal_tokens(table, args, &mut events)
        }
        s if s == &selectors::submit_reconstruct_deck() => {
            dispatch_submit_reconstruct_deck(table, args, &mut events)
        }
        s if s == &selectors::fold() => dispatch_fold(table, args, &mut events),
        s if s == &selectors::check() => dispatch_check(table, args, &mut events),
        s if s == &selectors::call() => dispatch_call(table, args, &mut events),
        s if s == &selectors::raise() => dispatch_raise(table, args, &mut events),
        _ => {
            return Err(PokerL1Error::UnknownContractMethod {
                selector: *selector,
            })
        }
    };
    result?;
    log_events(&events);
    Ok(DispatchResult {
        created_objects: vec![],
        modified_objects: vec![table.id],
        return_value: vec![],
    })
}

/// 将 events 列表以 debug 级别记录到 tracing。
fn log_events(events: &[TexasPokerEvent]) {
    if events.is_empty() {
        return;
    }
    tracing::debug!("texas_poker dispatch emitted {} events", events.len());
}

/// BCS 反序列化辅助。
fn decode_args<T: serde::de::DeserializeOwned>(args: &[u8], method: &str) -> PokerL1Result<T> {
    bcs::from_bytes(args)
        .map_err(|e| PokerL1Error::Serialization(format!("{method} args BCS: {e}")))
}

// ========== 17 个 dispatch_* 子函数 ==========

/// `create_table` — 初始化桌台（覆写默认空桌台）。
fn dispatch_create_table(
    table: &mut TexasPokerTable,
    args: &[u8],
    _events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: CreateTableArgs = decode_args(args, "create_table")?;
    if !(2..=9).contains(&input.max_players) {
        return Err(PokerL1Error::Serialization(format!(
            "max_players {} out of range [2, 9]",
            input.max_players
        )));
    }
    if input.big_blind == 0 {
        return Err(PokerL1Error::Serialization("big_blind must > 0".into()));
    }
    if input.small_blind > input.big_blind {
        return Err(PokerL1Error::Serialization(
            "small_blind must <= big_blind".into(),
        ));
    }
    let id = table.id;
    *table = TexasPokerTable::new(
        id,
        input.name,
        input.max_players,
        input.small_blind,
        input.big_blind,
    );
    table.bump_version();
    Ok(())
}

/// `join_and_shuffle` — 玩家加入并完成首洗牌。
fn dispatch_join_and_shuffle(
    _context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: JoinAndShuffleArgs = decode_args(args, "join_and_shuffle")?;
    state_machine::apply_join_and_shuffle(
        table,
        input.seat_index,
        input.player,
        input.buy_in,
        input.pk,
        input.pk_ownership_proof,
        input.mask_cards,
        input.output_cards,
        input.remask_proof,
        input.shuffle_proof,
        events,
    )
}

/// `leave_with_proof` — 带 proof 离场。
fn dispatch_leave_with_proof(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: LeaveWithProofArgs = decode_args(args, "leave_with_proof")?;
    state_machine::apply_leave_with_proof(
        table,
        input.seat_index,
        input.output_cards,
        input.leave_proof,
        events,
    )
}

/// `join_table` — 简单入座（不参与本局，标记 is_waiting=true）。
///
/// 仅在 WAITING 状态允许；占第一个空座位；玩家不能已在桌台。
fn dispatch_join_table(
    _context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: JoinTableArgs = decode_args(args, "join_table")?;
    if !state_machine::can_join_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot join_table".into(),
        ));
    }
    if state_machine::is_pk_registered(&table.seats, &input.pk) {
        return Err(PokerL1Error::Serialization(
            "pk already registered at this table".into(),
        ));
    }
    if input.buy_in < table.big_blind {
        return Err(PokerL1Error::Serialization(format!(
            "buy_in {} < big_blind {}",
            input.buy_in, table.big_blind
        )));
    }
    let seat_idx = table.find_empty_seat().ok_or_else(|| {
        PokerL1Error::Serialization("no empty seat available".into())
    })?;
    let seat = &mut table.seats[seat_idx as usize];
    seat.player = input.player;
    seat.stack = input.buy_in;
    seat.pk = input.pk;
    seat.is_waiting = false; // WAITING 状态加入，立即参与下一局
    seat.folded = false;
    seat.left_during_hand = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.bet = 0;
    seat.total_bet = 0;
    seat.hand.clear();

    let active_count_after = (state_machine::count_active_occupied(&table.seats) as u64) + 1;
    events.push(TexasPokerEvent::PlayerJoined {
        table_id: table.id,
        seat_index: seat_idx,
        player: input.player,
        buy_in: input.buy_in,
        is_waiting: false,
        active_count_after,
    });
    table.bump_version();
    Ok(())
}

/// `leave_table` — 简单离座（仅 WAITING 状态）。
fn dispatch_leave_table(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: LeaveTableArgs = decode_args(args, "leave_table")?;
    if !state_machine::can_leave_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot leave_table".into(),
        ));
    }
    if input.seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "seat_index {} out of range",
            input.seat_index
        )));
    }
    let seat = &mut table.seats[input.seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(
            "seat not occupied, cannot leave".into(),
        ));
    }
    let refund_amt = seat.stack;
    let player = seat.player;
    *seat = super::types::Seat::empty();

    if refund_amt > 0 {
        events.push(TexasPokerEvent::PlayerRefund {
            table_id: table.id,
            seat_index: input.seat_index,
            player,
            amount: refund_amt,
            refund_type: super::constants::REFUND_TYPE_STACK_ONLY,
        });
    }
    events.push(TexasPokerEvent::PlayerLeft {
        table_id: table.id,
        seat_index: input.seat_index,
        player,
    });
    table.bump_version();
    Ok(())
}

/// `start_hand` — 开始新一局。
fn dispatch_start_hand(
    table: &mut TexasPokerTable,
    _args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    state_machine::start_hand(table, events)
}

/// `tick` — 超时驱动。
fn dispatch_tick(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // 允许空 args（兼容无参调用）；非空则解析为 TickArgs
    let now_ms = if args.is_empty() {
        // 无 args 时使用 0（仅推进状态机，超时不触发）
        0u64
    } else {
        decode_args::<TickArgs>(args, "tick")?.now_ms
    };
    state_machine::tick(table, now_ms, events)
}

/// `auto_fold` — 玩家超时自动 fold。
fn dispatch_auto_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "auto_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_AUTO_TIMEOUT, events)
}

/// `force_fold` — 管理员强制 fold。
fn dispatch_force_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "force_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_FORCE_ADMIN, events)
}

/// `kick_player` — 踢出玩家。
fn dispatch_kick_player(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: KickPlayerArgs = decode_args(args, "kick_player")?;
    let reason = if input.reason == 0 {
        KICK_REASON_ADMIN
    } else {
        input.reason
    };
    state_machine::kick_player_internal(table, input.seat_index, reason, events);
    table.bump_version();
    Ok(())
}

/// `submit_shuffle_v2` — 提交洗牌结果。
fn dispatch_submit_shuffle_v2(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2")?;
    state_machine::apply_submit_shuffle_v2(
        table,
        input.seat_index,
        input.output_cards,
        input.shuffle_proof,
        events,
    )
}

/// `submit_player_reveal_tokens` — 提交揭牌令牌。
fn dispatch_submit_player_reveal_tokens(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitRevealTokensArgs = decode_args(args, "submit_player_reveal_tokens")?;
    state_machine::apply_submit_player_reveal_tokens(
        table,
        input.seat_index,
        input.assignment_indices,
        input.reveal_tokens,
        input.proofs,
        events,
    )
}

/// `submit_reconstruct_deck` — 提交重构牌组。
fn dispatch_submit_reconstruct_deck(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck")?;
    state_machine::apply_submit_reconstruct_deck(
        table,
        input.seat_index,
        input.output_cards,
        input.swap_cards,
        input.user_readable_cards,
        input.proof,
        events,
    )
}

/// `fold` — 玩家主动 fold。
fn dispatch_fold(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "fold")?;
    state_machine::apply_fold(table, input.seat_index, events)
}

/// `check` — 玩家过牌。
fn dispatch_check(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "check")?;
    state_machine::apply_check(table, input.seat_index, events)
}

/// `call` — 玩家跟注。
fn dispatch_call(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "call")?;
    state_machine::apply_call(table, input.seat_index, events)
}

/// `raise` — 玩家加注。
fn dispatch_raise(
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RaiseArgs = decode_args(args, "raise")?;
    state_machine::apply_raise(table, input.seat_index, input.total_bet, events)
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;

    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            "test".to_string(),
            6,
            50,
            100,
        )
    }

    fn make_context() -> DispatchContext {
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

    #[test]
    fn selector_deterministic() {
        let h1 = selectors::create_table();
        let h2 = compute_method_selector("create_table");
        assert_eq!(h1, h2);
    }

    #[test]
    fn all_selectors_unique() {
        let sels = selectors::all();
        assert_eq!(sels.len(), 17, "应有 17 个 selector");
        for i in 0..sels.len() {
            for j in (i + 1)..sels.len() {
                assert_ne!(sels[i], sels[j], "selector[{i}] == selector[{j}] 不应相等");
            }
        }
    }

    #[test]
    fn dispatch_unknown_method_returns_error() {
        let ctx = make_context();
        let mut table = make_table();
        let unknown = [0xFE; 32];
        let result = dispatch(&ctx, &mut table, &unknown, &[]);
        assert!(matches!(result, Err(PokerL1Error::UnknownContractMethod { .. })));
    }

    #[test]
    fn dispatch_create_table_initializes() {
        let ctx = make_context();
        let mut table = make_table();
        // 把 table 改成非初始状态，验证 create_table 会覆写
        table.pot = 999;

        let args = CreateTableArgs {
            name: "new_game".into(),
            max_players: 9,
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = bcs::to_bytes(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes).unwrap();

        assert_eq!(table.name, "new_game");
        assert_eq!(table.max_players, 9);
        assert_eq!(table.small_blind, 25);
        assert_eq!(table.big_blind, 50);
        assert_eq!(table.pot, 0, "create_table 应覆写为初始状态");
        assert!(!result.modified_objects.is_empty());
    }

    #[test]
    fn dispatch_create_table_rejects_invalid_max_players() {
        let ctx = make_context();
        let mut table = make_table();
        let args = CreateTableArgs {
            name: "bad".into(),
            max_players: 10, // 越界
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = bcs::to_bytes(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_join_table_then_leave_table() {
        let ctx = make_context();
        let mut table = make_table();
        // WAITING 状态允许 join_table
        let join_args = JoinTableArgs {
            player: [0x11; 20],
            buy_in: 1000,
            pk: vec![0xCD; 48],
        };
        let join_bytes = bcs::to_bytes(&join_args).unwrap();
        dispatch(&ctx, &mut table, &selectors::join_table(), &join_bytes).unwrap();
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].stack, 1000);

        // leave_table
        let leave_args = LeaveTableArgs { seat_index: 0 };
        let leave_bytes = bcs::to_bytes(&leave_args).unwrap();
        dispatch(&ctx, &mut table, &selectors::leave_table(), &leave_bytes).unwrap();
        assert_eq!(table.occupied_count(), 0);
    }

    #[test]
    fn dispatch_kick_player_marks_seat() {
        let ctx = make_context();
        let mut table = make_table();
        // 设置 3 个玩家，确保 kick 后不触发 reset_for_next_hand
        table.round_state = super::super::constants::ROUND_PREFLOP;
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 500;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 500;
        table.seats[2].player = [0x03; 20];
        table.seats[2].stack = 500;

        let args = KickPlayerArgs {
            seat_index: 0,
            reason: 0,
        };
        let args_bytes = bcs::to_bytes(&args).unwrap();
        dispatch(&ctx, &mut table, &selectors::kick_player(), &args_bytes).unwrap();
        assert!(table.seats[0].folded);
        assert!(table.seats[0].left_during_hand);
        assert_eq!(table.seats[0].stack, 0);
    }

    #[test]
    fn dispatch_tick_with_empty_args_uses_zero() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        // 空 args 调用 tick：等价于 now_ms=0，触发 start_hand
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &[]);
        assert!(result.is_ok());
        assert_eq!(
            table.shuffle_state.phase,
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP
        );
    }

    #[test]
    fn dispatch_tick_with_args_uses_provided_timestamp() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].player = [0x01; 20];
        table.seats[0].stack = 1000;
        table.seats[1].player = [0x02; 20];
        table.seats[1].stack = 1000;
        let args = TickArgs { now_ms: 5_000_000 };
        let args_bytes = bcs::to_bytes(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::tick(), &args_bytes);
        assert!(result.is_ok());
    }
}
