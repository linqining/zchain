//! `tick` AIR — 超时驱动（permissionless）。
//!
//! ## 业务规约
//! 1. 根据当前 `round_state` 和超时配置触发状态转换
//! 2. 严格优先级：reconstruct > shuffle > reveal > 正常逻辑 > fallback
//! 3. **Time Bank**：下注超时时若 `time_bank_ms > 0`，消耗等量时间延长截止
//! 4. **Rake**：reveal 阶段完成触发 settle_hand 时抽水（`pot_after = pot_before - rake`）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{
    COMMON_NUM_COLUMNS, CommonConstraints, CommonRow, ZERO, u64_to_m31_limbs,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

use poker_l1::vm::contracts::texas_poker::constants::{
    RECONSTRUCT_PHASE_NONE, REVEAL_PHASE_NONE, ROUND_SHOWDOWN, SHUFFLE_PHASE_BEFORE_PREFLOP,
    SHUFFLE_PHASE_RECONSTRUCT,
};
use poker_l1::vm::contracts::texas_poker::events::TexasPokerEvent;
use poker_l1::vm::contracts::texas_poker::state_machine;
use poker_l1::vm::contracts::texas_poker::types::{NO_SEAT, TexasPokerTable};

/// `timeout_kind` values used in the tick statement.  The value denotes the
/// highest-priority timer family visible in the pre-state; `5` is a non-timer
/// tick transition such as waiting/start-hand, showdown, or the consistency
/// fallback.  Zero is deliberately invalid so the AIR has no all-zero
/// "timeout happened" witness.
pub const TICK_KIND_SHUFFLE: u8 = 1;
/// The canonical tick branch is governed by the reveal timer.
pub const TICK_KIND_REVEAL: u8 = 2;
/// The canonical tick branch is governed by the reconstruction timer.
pub const TICK_KIND_RECONSTRUCT: u8 = 3;
/// The canonical tick branch is governed by the betting-turn timer.
pub const TICK_KIND_BETTING: u8 = 4;
/// The canonical tick branch has no timer predicate (e.g. hand start/reset).
pub const TICK_KIND_NON_TIMER: u8 = 5;

/// Canonical Tick lifecycle receipt ABI.
pub const TICK_LIFECYCLE_ABI_VERSION: u8 = 1;
/// Reserved legacy ABI value. Schema v15 never commits an active phase with
/// an unset deadline, so canonical Tick receipts must never issue this branch.
pub const TICK_BRANCH_TIMER_STARTED: u8 = 1;
/// Tick started a new hand from WAITING.
pub const TICK_BRANCH_HAND_STARTED: u8 = 2;
/// Tick advanced the shuffle protocol without a timeout.
pub const TICK_BRANCH_SHUFFLE_ADVANCED: u8 = 3;
/// Tick handled a shuffle timeout.
pub const TICK_BRANCH_SHUFFLE_TIMEOUT: u8 = 4;
/// Tick completed or advanced a reveal phase without a timeout.
pub const TICK_BRANCH_REVEAL_ADVANCED: u8 = 5;
/// Tick handled a reveal timeout or its reconstruct/reset cascade.
pub const TICK_BRANCH_REVEAL_TIMEOUT: u8 = 6;
/// Tick handled a reconstruction timeout.
pub const TICK_BRANCH_RECONSTRUCT_TIMEOUT: u8 = 7;
/// Tick collected bets and advanced a completed betting round.
pub const TICK_BRANCH_BETTING_ROUND_ADVANCED: u8 = 8;
/// Tick consumed the current actor's time bank.
pub const TICK_BRANCH_TIME_BANK_CONSUMED: u8 = 9;
/// Tick auto-folded the current actor after a betting timeout.
pub const TICK_BRANCH_BETTING_TIMEOUT: u8 = 10;
/// Tick settled/reset a completed showdown display period.
pub const TICK_BRANCH_SHOWDOWN_SETTLED: u8 = 11;
/// Tick repaired an inconsistent non-WAITING table by refunding/resetting it.
pub const TICK_BRANCH_INCONSISTENT_RESET: u8 = 12;

/// AIR projection of a verifier-issued canonical Tick lifecycle receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickLifecycleAirBinding {
    /// Lifecycle receipt ABI version.
    pub abi_version: u8,
    /// Exact canonical lifecycle branch.
    pub branch_kind: u8,
    /// Digest of the complete canonical lifecycle request.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Digest of the verifier-issued successful receipt.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

impl TickLifecycleAirBinding {
    const fn zero() -> Self {
        Self {
            abi_version: 0,
            branch_kind: 0,
            request_digest: [ZERO; DIGEST_LIMBS],
            receipt_digest: [ZERO; DIGEST_LIMBS],
        }
    }
}

/// `tick` 业务特定列布局。
pub mod cols {
    use super::COMMON_NUM_COLUMNS;
    /// `INPUT_CURRENT_TIME` 起始列（4 limb）。
    pub const INPUT_CURRENT_TIME_BASE: usize = COMMON_NUM_COLUMNS + 0;
    /// `INPUT_TIMEOUT_KIND` 列（0=shuffle, 1=reveal, 2=reconstruct, 3=betting）。
    pub const INPUT_TIMEOUT_KIND: usize = COMMON_NUM_COLUMNS + 4;
    /// `OUTPUT_NEW_ROUND_STATE` 列。
    pub const OUTPUT_NEW_ROUND_STATE: usize = COMMON_NUM_COLUMNS + 5;
    /// `TIME_BANK_CONSUMED` 起始列（完整 64-bit 消耗量）。
    pub const TIME_BANK_CONSUMED_BASE: usize = COMMON_NUM_COLUMNS + 6;
    /// `TIME_BANK_POST` 起始列（完整 64-bit 剩余 time bank）。
    pub const TIME_BANK_POST_BASE: usize = COMMON_NUM_COLUMNS + 10;
    /// `RAKE_MODE` 列（0=NONE, 1=PERCENTAGE）。
    pub const RAKE_MODE: usize = COMMON_NUM_COLUMNS + 14;
    /// `RAKE_AMOUNT` 起始列（完整 4×16-bit u64）。
    pub const RAKE_AMOUNT_BASE: usize = COMMON_NUM_COLUMNS + 15;
    /// `INPUT_TIMEOUT_KIND_INV` invertibility witness（Gap 5）：timeout_kind 的乘法逆元，
    /// 约束 `timeout_kind * inv == 1` 证明 timeout_kind ≠ 0（即存在真实超时）。
    pub const INPUT_TIMEOUT_KIND_INV: usize = COMMON_NUM_COLUMNS + 19;
    /// 当前 betting actor 调用前完整 time bank（仅 betting 分支有意义）。
    pub const PRE_TIME_BANK_BASE: usize = COMMON_NUM_COLUMNS + 20;
    /// 触发的 timer 开始时间（完整 64-bit）。
    pub const TIMEOUT_STARTED_AT_BASE: usize = COMMON_NUM_COLUMNS + 24;
    /// 触发的 timer 配置（完整 64-bit）。
    pub const TIMEOUT_MS_BASE: usize = COMMON_NUM_COLUMNS + 28;
    /// `started_at + timeout_ms` 的模 2^64 加法结果。
    pub const DEADLINE_SUM_BASE: usize = COMMON_NUM_COLUMNS + 32;
    /// Rust `saturating_add` 后的 deadline。
    pub const DEADLINE_BASE: usize = COMMON_NUM_COLUMNS + 36;
    /// deadline 加法的 3 个 limb carry。
    pub const DEADLINE_ADD_CARRY_BASE: usize = COMMON_NUM_COLUMNS + 40;
    /// deadline 加法的最终 overflow witness。
    pub const DEADLINE_ADD_OVERFLOW: usize = COMMON_NUM_COLUMNS + 43;
    /// `current_time - deadline` 的完整 64-bit 差。
    pub const TIME_ELAPSED_BASE: usize = COMMON_NUM_COLUMNS + 44;
    /// 上述减法的 4 个 borrow witness。
    pub const TIME_SUB_BORROW_BASE: usize = COMMON_NUM_COLUMNS + 48;
    /// `timeout_started_at != 0` 的非零 inverse witness。
    pub const TIMEOUT_STARTED_AT_INV: usize = COMMON_NUM_COLUMNS + 52;
    /// Tick lifecycle receipt ABI version.
    pub const LIFECYCLE_ABI_VERSION: usize = COMMON_NUM_COLUMNS + 53;
    /// Canonical Tick lifecycle branch kind.
    pub const LIFECYCLE_BRANCH_KIND: usize = COMMON_NUM_COLUMNS + 54;
    /// Complete lifecycle request digest.
    pub const LIFECYCLE_REQUEST_DIGEST_BASE: usize = COMMON_NUM_COLUMNS + 55;
    /// Complete lifecycle receipt digest.
    pub const LIFECYCLE_RECEIPT_DIGEST_BASE: usize =
        LIFECYCLE_REQUEST_DIGEST_BASE + super::DIGEST_LIMBS;
    /// 总列数。
    pub const NUM_COLUMNS: usize = LIFECYCLE_RECEIPT_DIGEST_BASE + super::DIGEST_LIMBS;
}

/// `tick` 输入参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickInput {
    /// 当前时间戳。
    pub current_time: u64,
    /// 超时类型。
    pub timeout_kind: u8,
    /// Whether the selected branch requires `current_time >= started + timeout`.
    /// This is a verifier-reconstructed AIR constant, not a prover witness.
    pub timeout_required: bool,
    /// Timer start timestamp selected by the canonical tick branch.
    pub timeout_started_at: u64,
    /// Timeout configuration selected by the canonical tick branch.
    pub timeout_ms: u64,
    /// Time Bank 消耗量（毫秒，0 = 未消耗）。
    pub time_bank_consumed: u64,
    /// Time Bank 消耗后余额（毫秒）。
    pub time_bank_post: u64,
    /// Current betting actor's pre-transition Time Bank.  It is zero outside
    /// an active betting-turn branch.
    pub pre_time_bank: u64,
    /// Rake 模式（0=NONE, 1=PERCENTAGE）。
    pub rake_mode: u8,
    /// Rake 抽水金额。
    pub rake_amount: u64,
    /// Exact native `bump_version` count for this tick transition.  Some tick
    /// helpers alter state without bumping the table version, so treating every
    /// tick as `+1` was an invalid proof precondition.
    pub version_increment: u8,
    /// Verifier-issued receipt for the exact lifecycle branch executed by Tick.
    pub lifecycle: TickLifecycleAirBinding,
}

impl Default for TickInput {
    fn default() -> Self {
        Self {
            current_time: 0,
            timeout_kind: TICK_KIND_NON_TIMER,
            timeout_required: false,
            timeout_started_at: 0,
            timeout_ms: 0,
            time_bank_consumed: 0,
            time_bank_post: 0,
            pre_time_bank: 0,
            rake_mode: 0,
            rake_amount: 0,
            version_increment: 1,
            lifecycle: TickLifecycleAirBinding::zero(),
        }
    }
}

/// Canonically reconstruct all business constants for a state-changing `tick`.
///
/// The native VM deliberately has several `tick` branches that are not timer
/// expirations (advance a completed protocol phase, start a hand, or repair an
/// inconsistent table). This helper follows the same
/// priority order as [`state_machine::tick`], replays it, and derives the
/// input constants from the resulting VM events and post-state.  It is shared
/// by the prover and production verifier so no Tick witness is selected by the
/// prover.
pub fn canonical_input(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    current_time: u64,
) -> TexasAirResult<TickInput> {
    let (timeout_kind, timeout_started_at, timeout_ms, timer_is_pending, actor) =
        select_tick_timer(pre)?;
    let timeout_required = timer_is_pending
        && timeout_started_at != 0
        && current_time >= timeout_started_at.saturating_add(timeout_ms);

    let pre_time_bank = actor
        .map(|seat| seat_time_bank(pre, seat, "pre"))
        .transpose()?
        .unwrap_or(0);
    let post_time_bank = actor
        .map(|seat| seat_time_bank(post, seat, "post"))
        .transpose()?
        .unwrap_or(0);

    let mut replay = pre.clone();
    let mut events = Vec::new();
    state_machine::tick(&mut replay, current_time, &mut events).map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "tick: canonical state-machine replay failed: {error}"
        ))
    })?;
    if replay == *pre {
        return Err(TexasAirError::SpecViolation(
            "tick: canonical replay made no state change, so dispatch must not issue a proof task"
                .into(),
        ));
    }

    replay.call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation("tick: call_seq overflow during canonical replay".into())
    })?;
    if events
        .iter()
        .any(|event| matches!(event, TexasPokerEvent::HandStarted { .. }))
    {
        replay.hand_id = pre.hand_id.checked_add(1).ok_or_else(|| {
            TexasAirError::SpecViolation("tick: hand_id overflow during canonical replay".into())
        })?;
    } else {
        replay.hand_id = pre.hand_id;
    }
    if replay != *post {
        return Err(TexasAirError::SpecViolation(
            "tick: canonical post-table differs from VM replay".into(),
        ));
    }

    let mut time_bank_consumed = 0u64;
    let mut event_post_time_bank = None;
    let mut rake_amount = 0u64;
    let mut rake_mode = pre.rake_mode;
    for event in &events {
        match event {
            TexasPokerEvent::TimeBankConsumed {
                table_id,
                seat_index,
                consumed_ms,
                remaining_ms,
            } => {
                if *table_id != pre.id {
                    return Err(TexasAirError::SpecViolation(
                        "tick: TimeBankConsumed event references another table".into(),
                    ));
                }
                if Some(*seat_index) != actor || event_post_time_bank.is_some() {
                    return Err(TexasAirError::SpecViolation(
                        "tick: invalid TimeBankConsumed event for the selected betting actor"
                            .into(),
                    ));
                }
                time_bank_consumed = *consumed_ms;
                event_post_time_bank = Some(*remaining_ms);
            }
            TexasPokerEvent::RakeCollected {
                table_id,
                rake_amount: amount,
                rake_mode: mode,
                ..
            } => {
                if *table_id != pre.id {
                    return Err(TexasAirError::SpecViolation(
                        "tick: RakeCollected event references another table".into(),
                    ));
                }
                rake_amount = rake_amount.checked_add(*amount).ok_or_else(|| {
                    TexasAirError::SpecViolation("tick: rake event sum overflow".into())
                })?;
                rake_mode = *mode;
            }
            _ => {}
        }
    }
    if let Some(remaining) = event_post_time_bank {
        if pre_time_bank
            .checked_sub(time_bank_consumed)
            .ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "tick: Time Bank consumption exceeds pre balance".into(),
                )
            })?
            != remaining
            || post_time_bank != remaining
        {
            return Err(TexasAirError::SpecViolation(
                "tick: Time Bank event is inconsistent with canonical table balances".into(),
            ));
        }
    } else if time_bank_consumed != 0 {
        return Err(TexasAirError::SpecViolation(
            "tick: non-zero Time Bank consumption lacks a canonical event".into(),
        ));
    }

    let expected_version = u64::from(pre.call_seq)
        .checked_add(1)
        .ok_or_else(|| TexasAirError::SpecViolation("tick: pre-call-seq overflow".into()))?;
    if u64::from(post.call_seq) != expected_version {
        return Err(TexasAirError::SpecViolation(
            "tick: a committed external command must increment call_seq exactly once".into(),
        ));
    }
    let version_increment = 1;
    let lifecycle = issue_lifecycle_binding(pre, post, current_time, &events)?;

    Ok(TickInput {
        current_time,
        timeout_kind,
        timeout_required,
        timeout_started_at,
        timeout_ms,
        time_bank_consumed,
        time_bank_post: post_time_bank,
        pre_time_bank,
        rake_mode,
        rake_amount,
        version_increment,
        lifecycle,
    })
}

fn issue_lifecycle_binding(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    current_time: u64,
    events: &[TexasPokerEvent],
) -> TexasAirResult<TickLifecycleAirBinding> {
    use poker_l1::vm::contracts::texas_poker::constants::{
        FOLD_REASON_AUTO_TIMEOUT, RESET_REASON_STATE_INCONSISTENT,
    };

    let has = |predicate: fn(&TexasPokerEvent) -> bool| events.iter().any(predicate);
    let pre_reveal = pre.reveal_token_state();
    let branch_kind = if has(|event| matches!(event, TexasPokerEvent::ReconstructTimeout { .. })) {
        TICK_BRANCH_RECONSTRUCT_TIMEOUT
    } else if has(|event| matches!(event, TexasPokerEvent::ShuffleTimeout { .. })) {
        TICK_BRANCH_SHUFFLE_TIMEOUT
    } else if has(|event| matches!(event, TexasPokerEvent::RevealTimeout { .. })) {
        TICK_BRANCH_REVEAL_TIMEOUT
    } else if has(|event| matches!(event, TexasPokerEvent::TimeBankConsumed { .. })) {
        TICK_BRANCH_TIME_BANK_CONSUMED
    } else if events.iter().any(|event| {
        matches!(
            event,
            TexasPokerEvent::PlayerFolded {
                reason: FOLD_REASON_AUTO_TIMEOUT,
                ..
            }
        )
    }) {
        TICK_BRANCH_BETTING_TIMEOUT
    } else if has(|event| matches!(event, TexasPokerEvent::HandStarted { .. })) {
        TICK_BRANCH_HAND_STARTED
    } else if events.iter().any(|event| {
        matches!(
            event,
            TexasPokerEvent::HandReset {
                reason: RESET_REASON_STATE_INCONSISTENT,
                ..
            }
        )
    }) {
        TICK_BRANCH_INCONSISTENT_RESET
    } else if pre.round_state() == ROUND_SHOWDOWN
        && (has(|event| matches!(event, TexasPokerEvent::SettlementPlanCommitted { .. }))
            || has(|event| matches!(event, TexasPokerEvent::HandEndedWithoutShowdown { .. })))
    {
        TICK_BRANCH_SHOWDOWN_SETTLED
    } else if matches!(
        pre.shuffle_phase(),
        SHUFFLE_PHASE_RECONSTRUCT | SHUFFLE_PHASE_BEFORE_PREFLOP
    ) {
        TICK_BRANCH_SHUFFLE_ADVANCED
    } else if pre_reveal.reveal_phase != REVEAL_PHASE_NONE {
        TICK_BRANCH_REVEAL_ADVANCED
    } else if state_machine::is_betting_round(pre) && pre.current_turn() == NO_SEAT {
        TICK_BRANCH_BETTING_ROUND_ADVANCED
    } else {
        return Err(TexasAirError::SpecViolation(
            "tick: state-changing canonical replay has no supported lifecycle branch".into(),
        ));
    };

    let payload = borsh::to_vec(&(
        TICK_LIFECYCLE_ABI_VERSION,
        branch_kind,
        current_time,
        pre,
        post,
        events,
    ))
    .map_err(|error| {
        TexasAirError::SerializationError(format!(
            "tick: lifecycle request borsh encoding failed: {error}"
        ))
    })?;
    let request_digest = tick_lifecycle_hash(b"zchain.texas.tick.lifecycle.request.v1", &payload);
    let mut receipt = Vec::with_capacity(4 + request_digest.len());
    receipt.extend_from_slice(&[
        TICK_LIFECYCLE_ABI_VERSION,
        branch_kind,
        1, // canonical native Tick replay backend
        1, // verified-success result
    ]);
    receipt.extend_from_slice(&request_digest);
    let receipt_digest = tick_lifecycle_hash(b"zchain.texas.tick.lifecycle.receipt.v1", &receipt);
    Ok(TickLifecycleAirBinding {
        abi_version: TICK_LIFECYCLE_ABI_VERSION,
        branch_kind,
        request_digest: digest_to_m31_limbs(request_digest),
        receipt_digest: digest_to_m31_limbs(receipt_digest),
    })
}

fn tick_lifecycle_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

/// Return the canonical timer family that has priority in the pre-state.
fn select_tick_timer(table: &TexasPokerTable) -> TexasAirResult<(u8, u64, u64, bool, Option<u8>)> {
    let shuffle = table.shuffle_state();
    let reveal = table.reveal_token_state();
    let timestamps = table.timestamps();
    if table.reconstruct_phase() != RECONSTRUCT_PHASE_NONE {
        return Ok((
            TICK_KIND_RECONSTRUCT,
            timestamps.reconstruct_started_at,
            u64::from(table.timeout_config.reconstruct_timeout_ms),
            true,
            None,
        ));
    }
    if matches!(
        table.shuffle_phase(),
        SHUFFLE_PHASE_RECONSTRUCT | SHUFFLE_PHASE_BEFORE_PREFLOP
    ) {
        let pending = shuffle.pending_mask != 0 && shuffle.derived_current_shuffler() != NO_SEAT;
        return Ok((
            TICK_KIND_SHUFFLE,
            timestamps.shuffle_started_at,
            u64::from(table.timeout_config.shuffle_timeout_ms),
            pending,
            None,
        ));
    }
    if reveal.reveal_phase != REVEAL_PHASE_NONE {
        let pending = !reveal
            .assignments
            .iter()
            .all(|assignment| assignment.pending_mask() == 0);
        return Ok((
            TICK_KIND_REVEAL,
            timestamps.reveal_started_at,
            u64::from(table.timeout_config.reveal_timeout_ms),
            pending,
            None,
        ));
    }
    if state_machine::is_betting_round(table) {
        if table.current_turn() != NO_SEAT {
            let seat = table.current_turn();
            // Validate this now rather than letting an out-of-range index reach
            // the native state machine's indexing path later.
            let _ = seat_time_bank(table, seat, "pre")?;
            return Ok((
                TICK_KIND_BETTING,
                timestamps.betting_started_at,
                u64::from(table.timeout_config.betting_timeout_ms),
                true,
                Some(seat),
            ));
        }
    }
    if table.round_state() == ROUND_SHOWDOWN {
        // `showdown_at` is already a deadline in the native VM. Model it as
        // `started_at + 0` so the common 64-bit comparison AIR remains exact.
        return Ok((
            TICK_KIND_NON_TIMER,
            timestamps.showdown_at,
            0,
            timestamps.showdown_at != 0,
            None,
        ));
    }
    Ok((TICK_KIND_NON_TIMER, 0, 0, false, None))
}

fn seat_time_bank(table: &TexasPokerTable, seat: u8, label: &str) -> TexasAirResult<u64> {
    table
        .seats
        .get(usize::from(seat))
        .map(|entry| u64::from(entry.time_bank_ms))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(format!(
                "tick: {label}-state current_turn {seat} is outside the table seats"
            ))
        })
}

/// `tick` AIR。
#[derive(Debug, Clone)]
pub struct TickAir {
    /// log2(行数)。
    pub log_size: u32,
    /// 输入参数。
    pub input: TickInput,
    /// 调用前 state_root。
    pub pre_state_root: [M31; 4],
    /// 调用后 state_root。
    pub post_state_root: [M31; 4],
    /// 表台 ID。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 调用序号。
    pub call_seq: u32,
    /// 调用前 version。
    pub pre_version: u64,
    /// 调用后 version。
    pub post_version: u64,
}

impl TickAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for TickAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let statement = crate::airs::TexasAir::statement(self);
        let common = CommonConstraints::write_with_version_increment(
            &mut eval,
            &statement,
            u64::from(self.input.version_increment),
        );
        let is_active = common.is_active.clone();

        let input_current_time = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let input_timeout_kind = eval.next_trace_mask();
        let output_new_round_state = eval.next_trace_mask();
        let time_bank_consumed = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let time_bank_post = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let rake_mode = eval.next_trace_mask();
        let rake_amount = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        // Gap 5 invertibility witness（timeout_kind ≠ 0）。
        let input_timeout_kind_inv = eval.next_trace_mask();
        let pre_time_bank = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let timeout_started_at = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let timeout_ms = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_sum = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let deadline_add_overflow = eval.next_trace_mask();
        let time_elapsed = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let time_sub_borrow = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let timeout_started_at_inv = eval.next_trace_mask();
        let lifecycle_abi_version = eval.next_trace_mask();
        let lifecycle_branch_kind = eval.next_trace_mask();
        let lifecycle_request_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let lifecycle_receipt_digest: Vec<_> =
            (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        // 约束 1：完整 consensus timestamp 必须与 trusted AIR statement
        // 一致。只读而不绑定这些 limb 会允许证明与不同区块时间脱钩。
        let expected_current_time = crate::airs::common::u64_to_m31_limbs(self.input.current_time);
        for i in 0..4 {
            let expected_time: E::F = expected_current_time[i].into();
            eval.add_constraint(
                is_active.clone() * (input_current_time[i].clone() - expected_time),
            );
        }

        // 约束 2：timeout_kind == input.timeout_kind
        let expected: E::F = M31::from(u32::from(self.input.timeout_kind)).into();
        eval.add_constraint(is_active.clone() * (input_timeout_kind.clone() - expected));

        // 约束 3（Time Bank）：所有 64-bit limb 都必须绑定，不能让高 limb
        // 成为 prover 可选 witness。对于 betting timer 分支还证明
        // pre_time_bank = consumed + post_time_bank。
        let expected_tb_consumed = u64_to_m31_limbs(self.input.time_bank_consumed);
        let expected_tb_post = u64_to_m31_limbs(self.input.time_bank_post);
        let expected_pre_tb = u64_to_m31_limbs(self.input.pre_time_bank);
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone()
                    * (time_bank_consumed[i].clone() - expected_tb_consumed[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (time_bank_post[i].clone() - expected_tb_post[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (pre_time_bank[i].clone() - expected_pre_tb[i].into()),
            );
        }

        // 约束 5（Rake）：rake_mode == input.rake_mode
        let expected_rake_mode: E::F = M31::from(u32::from(self.input.rake_mode)).into();
        eval.add_constraint(is_active.clone() * (rake_mode - expected_rake_mode));

        // 约束 6（Rake）：完整 64-bit rake amount 与 canonical replay 一致。
        let expected_rake_amt = u64_to_m31_limbs(self.input.rake_amount);
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone() * (rake_amount[i].clone() - expected_rake_amt[i].into()),
            );
        }

        // The business-row output must agree with the common post-state value.
        eval.add_constraint(
            is_active.clone() * (output_new_round_state - common.post_round_state.clone()),
        );

        // 注：tick 会驱动状态机阶段转换（SHUFFLE→DEAL→BETTING 等），
        // round_state 可合法变化，故不施加 round_state 不变约束。
        // tick 的 Lean 反例「version 不递增」已由通用层 version+=1 约束消除。
        // 约束 7（Gap 5，degree-2）：timeout_kind * inv == 1 — 证明 timeout_kind ≠ 0
        // （即存在真实超时）。诚实 host 必须 timeout_kind > 0 才存在逆元。
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(
            is_active.clone() * (input_timeout_kind * input_timeout_kind_inv - one.clone()),
        );

        let expected_started_at = u64_to_m31_limbs(self.input.timeout_started_at);
        let expected_timeout_ms = u64_to_m31_limbs(self.input.timeout_ms);
        for i in 0..4 {
            eval.add_constraint(
                is_active.clone() * (timeout_started_at[i].clone() - expected_started_at[i].into()),
            );
            eval.add_constraint(
                is_active.clone() * (timeout_ms[i].clone() - expected_timeout_ms[i].into()),
            );
        }

        // Timeout branches prove Rust's exact `saturating_add` deadline and
        // unsigned `current_time >= deadline` comparison.  Non-timeout tick
        // branches intentionally do not claim a timeout predicate.
        if self.input.timeout_required {
            let started_sum = timeout_started_at[0].clone()
                + timeout_started_at[1].clone()
                + timeout_started_at[2].clone()
                + timeout_started_at[3].clone();
            eval.add_constraint(
                is_active.clone() * (started_sum * timeout_started_at_inv - one.clone()),
            );

            let limb_base: E::F = M31::from(1u32 << 16).into();
            for carry in deadline_add_carry.iter() {
                eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
            }
            eval.add_constraint(
                deadline_add_overflow.clone() * (deadline_add_overflow.clone() - one.clone()),
            );
            eval.add_constraint(
                timeout_started_at[0].clone() + timeout_ms[0].clone()
                    - deadline_sum[0].clone()
                    - limb_base.clone() * deadline_add_carry[0].clone(),
            );
            for i in 1..3 {
                eval.add_constraint(
                    timeout_started_at[i].clone()
                        + timeout_ms[i].clone()
                        + deadline_add_carry[i - 1].clone()
                        - deadline_sum[i].clone()
                        - limb_base.clone() * deadline_add_carry[i].clone(),
                );
            }
            eval.add_constraint(
                timeout_started_at[3].clone()
                    + timeout_ms[3].clone()
                    + deadline_add_carry[2].clone()
                    - deadline_sum[3].clone()
                    - limb_base.clone() * deadline_add_overflow.clone(),
            );
            let limb_max: E::F = M31::from(0xFFFFu32).into();
            for i in 0..4 {
                eval.add_constraint(
                    deadline[i].clone()
                        - deadline_sum[i].clone()
                        - deadline_add_overflow.clone()
                            * (limb_max.clone() - deadline_sum[i].clone()),
                );
            }

            for borrow in time_sub_borrow.iter() {
                eval.add_constraint(borrow.clone() * (borrow.clone() - one.clone()));
            }
            eval.add_constraint(
                input_current_time[0].clone() - deadline[0].clone()
                    + limb_base.clone() * time_sub_borrow[0].clone()
                    - time_elapsed[0].clone(),
            );
            for i in 1..4 {
                eval.add_constraint(
                    input_current_time[i].clone()
                        - deadline[i].clone()
                        - time_sub_borrow[i - 1].clone()
                        + limb_base.clone() * time_sub_borrow[i].clone()
                        - time_elapsed[i].clone(),
                );
            }
            eval.add_constraint(time_sub_borrow[3].clone());
        }

        let expected_lifecycle_abi: E::F =
            M31::from(u32::from(self.input.lifecycle.abi_version)).into();
        let expected_branch: E::F = M31::from(u32::from(self.input.lifecycle.branch_kind)).into();
        eval.add_constraint(is_active.clone() * (lifecycle_abi_version - expected_lifecycle_abi));
        eval.add_constraint(is_active.clone() * (lifecycle_branch_kind - expected_branch));
        for limb in 0..DIGEST_LIMBS {
            eval.add_constraint(
                is_active.clone()
                    * (lifecycle_request_digest[limb].clone()
                        - E::F::from(self.input.lifecycle.request_digest[limb])),
            );
            eval.add_constraint(
                is_active.clone()
                    * (lifecycle_receipt_digest[limb].clone()
                        - E::F::from(self.input.lifecycle.receipt_digest[limb])),
            );
        }

        eval
    }
}

/// `tick` trace 行。
#[derive(Debug, Clone)]
pub struct TickRow {
    /// 通用列。
    pub common: CommonRow,
    /// 当前时间。
    pub input_current_time: [M31; 4],
    /// 超时类型。
    pub input_timeout_kind: M31,
    /// 新 round_state。
    pub output_new_round_state: M31,
    /// Time Bank 消耗量（4×16-bit limb）。
    pub time_bank_consumed: [M31; 4],
    /// Time Bank 剩余余额（4×16-bit limb）。
    pub time_bank_post: [M31; 4],
    /// Rake 模式。
    pub rake_mode: M31,
    /// Rake 金额（4×16-bit limb）。
    pub rake_amount: [M31; 4],
    /// `INPUT_TIMEOUT_KIND_INV` invertibility witness（Gap 5）。
    pub input_timeout_kind_inv: M31,
    /// 当前 betting actor 的调用前 Time Bank。
    pub pre_time_bank: [M31; 4],
    /// 所选 timer 的开始时间。
    pub timeout_started_at: [M31; 4],
    /// 所选 timer 的超时配置。
    pub timeout_ms: [M31; 4],
    /// `started_at + timeout_ms` 的 wrapping 结果。
    pub deadline_sum: [M31; 4],
    /// Rust `saturating_add` 后的 deadline。
    pub deadline: [M31; 4],
    /// 加法过程的 3 个跨 limb 进位。
    pub deadline_add_carry: [M31; 3],
    /// 加法是否溢出 64 位。
    pub deadline_add_overflow: M31,
    /// `current_time - deadline` 的 4×16-bit 差。
    pub time_elapsed: [M31; 4],
    /// 上述减法的 4 个 borrow witness。
    pub time_sub_borrow: [M31; 4],
    /// `timeout_started_at` 非零性 witness。
    pub timeout_started_at_inv: M31,
    /// Verifier-issued canonical lifecycle branch receipt.
    pub lifecycle: TickLifecycleAirBinding,
}

impl TickRow {
    /// active 行。
    #[must_use]
    pub fn active(
        input: &TickInput,
        pre_state_root: [M31; 4],
        post_state_root: [M31; 4],
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre_version: u64,
        post_version: u64,
        pre_round_state: u8,
        post_round_state: u8,
    ) -> Self {
        use crate::airs::common::u64_to_m31_limbs;
        // timeout_kind is non-zero by construction and therefore has a field
        // inverse used by the AIR's non-zero constraint.
        let kind_m31 = M31::from(u32::from(input.timeout_kind));
        let input_timeout_kind_inv = kind_m31.inverse();
        let time_bank_consumed = u64_to_m31_limbs(input.time_bank_consumed);
        let time_bank_post = u64_to_m31_limbs(input.time_bank_post);
        let pre_time_bank = u64_to_m31_limbs(input.pre_time_bank);
        let timeout_started_at = u64_to_m31_limbs(input.timeout_started_at);
        let timeout_ms = u64_to_m31_limbs(input.timeout_ms);
        let (deadline_sum_u64, deadline_overflow) =
            input.timeout_started_at.overflowing_add(input.timeout_ms);
        let deadline_sum = u64_to_m31_limbs(deadline_sum_u64);
        let deadline = u64_to_m31_limbs(input.timeout_started_at.saturating_add(input.timeout_ms));
        let mut carry = 0u32;
        let mut deadline_add_carry = [ZERO; 3];
        for i in 0..3 {
            let sum = timeout_started_at[i].0 + timeout_ms[i].0 + carry;
            carry = sum >> 16;
            deadline_add_carry[i] = M31::from(carry);
        }
        let current_time = u64_to_m31_limbs(input.current_time);
        let mut time_elapsed = [ZERO; 4];
        let mut time_sub_borrow = [ZERO; 4];
        let mut borrow = 0i64;
        for i in 0..4 {
            let difference = i64::from(current_time[i].0) - i64::from(deadline[i].0) - borrow;
            if difference < 0 {
                time_elapsed[i] = M31::from((difference + (1_i64 << 16)) as u32);
                borrow = 1;
            } else {
                time_elapsed[i] = M31::from(difference as u32);
                borrow = 0;
            }
            time_sub_borrow[i] = M31::from(borrow as u32);
        }
        let timeout_started_at_sum = timeout_started_at
            .iter()
            .fold(ZERO, |sum, limb| sum + *limb);
        let timeout_started_at_inv = if timeout_started_at_sum == ZERO {
            ZERO
        } else {
            timeout_started_at_sum.inverse()
        };
        Self {
            common: CommonRow::active(
                MethodKind::Tick,
                pre_state_root,
                post_state_root,
                table_id,
                hand_id,
                call_seq,
                pre_version,
                post_version,
                pre_round_state,
                post_round_state,
                0,
                0,
                0,
                0,
            ),
            input_current_time: current_time,
            input_timeout_kind: kind_m31,
            output_new_round_state: M31::from(u32::from(post_round_state)),
            time_bank_consumed,
            time_bank_post,
            rake_mode: M31::from(u32::from(input.rake_mode)),
            rake_amount: u64_to_m31_limbs(input.rake_amount),
            input_timeout_kind_inv,
            pre_time_bank,
            timeout_started_at,
            timeout_ms,
            deadline_sum,
            deadline,
            deadline_add_carry,
            deadline_add_overflow: M31::from(u32::from(deadline_overflow)),
            time_elapsed,
            time_sub_borrow,
            timeout_started_at_inv,
            lifecycle: input.lifecycle,
        }
    }
    /// padding 行。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            common: CommonRow::padding(),
            input_current_time: [ZERO; 4],
            input_timeout_kind: ZERO,
            output_new_round_state: ZERO,
            time_bank_consumed: [ZERO; 4],
            time_bank_post: [ZERO; 4],
            rake_mode: ZERO,
            rake_amount: [ZERO; 4],
            input_timeout_kind_inv: ZERO,
            pre_time_bank: [ZERO; 4],
            timeout_started_at: [ZERO; 4],
            timeout_ms: [ZERO; 4],
            deadline_sum: [ZERO; 4],
            deadline: [ZERO; 4],
            deadline_add_carry: [ZERO; 3],
            deadline_add_overflow: ZERO,
            time_elapsed: [ZERO; 4],
            time_sub_borrow: [ZERO; 4],
            timeout_started_at_inv: ZERO,
            lifecycle: TickLifecycleAirBinding::zero(),
        }
    }
    /// 转列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = self.common.to_vec();
        v.extend_from_slice(&self.input_current_time);
        v.push(self.input_timeout_kind);
        v.push(self.output_new_round_state);
        v.extend_from_slice(&self.time_bank_consumed);
        v.extend_from_slice(&self.time_bank_post);
        v.push(self.rake_mode);
        v.extend_from_slice(&self.rake_amount);
        v.push(self.input_timeout_kind_inv);
        v.extend_from_slice(&self.pre_time_bank);
        v.extend_from_slice(&self.timeout_started_at);
        v.extend_from_slice(&self.timeout_ms);
        v.extend_from_slice(&self.deadline_sum);
        v.extend_from_slice(&self.deadline);
        v.extend_from_slice(&self.deadline_add_carry);
        v.push(self.deadline_add_overflow);
        v.extend_from_slice(&self.time_elapsed);
        v.extend_from_slice(&self.time_sub_borrow);
        v.push(self.timeout_started_at_inv);
        v.push(M31::from(u32::from(self.lifecycle.abi_version)));
        v.push(M31::from(u32::from(self.lifecycle.branch_kind)));
        v.extend_from_slice(&self.lifecycle.request_digest);
        v.extend_from_slice(&self.lifecycle.receipt_digest);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// Reconstruct the canonical native Tick transition and its complete AIR row.
///
/// This closes the gap between the trace's Tick business columns and the
/// public table images.  A verifier now rejects a proof whose timer family,
/// Time Bank accounting, rake receipt, version delta, or trusted trace row was
/// not derived from the same VM transition as the committed pre/post tables.
pub fn validate_public_inputs(
    air: &TickAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    if public_inputs.kind != MethodKind::Tick {
        return Err(TexasAirError::SpecViolation(
            "tick: public-input method kind mismatch".into(),
        ));
    }
    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if pre.id != post.id
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.pre_version != u64::from(pre.call_seq)
        || public_inputs.post_version != u64::from(post.call_seq)
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
    {
        return Err(TexasAirError::SpecViolation(
            "tick: public metadata does not match canonical pre/post tables".into(),
        ));
    }

    let expected_input = canonical_input(&pre, &post, air.input.current_time)?;
    if air.input != expected_input {
        return Err(TexasAirError::SpecViolation(
            "tick: AIR constants do not match the canonical VM transition".into(),
        ));
    }
    let mut expected_row = TickRow::active(
        &expected_input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
        pre.round_state(),
        post.round_state(),
    );
    expected_row.common.pre_pot = u64_to_m31_limbs(pre.pot);
    expected_row.common.post_pot = u64_to_m31_limbs(post.pot);
    let expected_row = expected_row.to_vec();
    let trusted_row = public_inputs.require_expected_trace_row(expected_row.len())?;
    if trusted_row != expected_row {
        return Err(TexasAirError::SpecViolation(
            "tick: trusted trace row was not reconstructed from canonical public inputs".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        TICK_BRANCH_BETTING_TIMEOUT, TICK_BRANCH_TIME_BANK_CONSUMED, TICK_KIND_BETTING,
        canonical_input,
    };
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::{
        betting::BettingRound,
        constants::{FOLD_REASON_AUTO_TIMEOUT, RAKE_MODE_PERCENTAGE, ROUND_PREFLOP},
        events::TexasPokerEvent,
        state_machine,
        types::{SeatStatus, TexasPokerTable},
    };

    fn table() -> TexasPokerTable {
        TexasPokerTable::new(
            ObjectID::new([0xA1; 20], 42),
            "canonical-tick".into(),
            [0xB2; 20],
            4,
            50,
            100,
        )
    }

    fn occupy(table: &mut TexasPokerTable, index: usize, player: u8, stack: u64) {
        table.set_seat_acted_this_round(index as u8, false);
        let seat = &mut table.seats[index];
        seat.player = [player; 20];
        seat.stack = stack;
        seat.set_status(SeatStatus::Active);
        seat.bet = 0;
        seat.total_bet = 0;
        seat.pending_addon = 0;
    }

    /// The state machine owns call/hand sequence maintenance at the dispatch
    /// layer.  Mirror that small dispatch step so `canonical_input` receives
    /// the exact pre/post tables used by a real prove task.
    fn execute_tick(pre: &TexasPokerTable, now_ms: u64) -> (TexasPokerTable, Vec<TexasPokerEvent>) {
        let mut post = pre.clone();
        let mut events = Vec::new();
        state_machine::tick(&mut post, now_ms, &mut events).expect("fixture tick must succeed");
        assert_ne!(post, *pre, "fixture tick must change the table");
        post.call_seq = pre.call_seq.checked_add(1).expect("fixture call sequence");
        post.hand_id = if events
            .iter()
            .any(|event| matches!(event, TexasPokerEvent::HandStarted { .. }))
        {
            pre.hand_id.checked_add(1).expect("fixture hand sequence")
        } else {
            pre.hand_id
        };
        (post, events)
    }

    fn betting_table(time_bank_ms: u32) -> TexasPokerTable {
        let mut table = table();
        occupy(&mut table, 0, 1, 1_000);
        occupy(&mut table, 1, 2, 1_000);
        occupy(&mut table, 2, 3, 1_000);
        table.timeout_config.betting_timeout_ms = 30_000;
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 1_000_000)
            .unwrap();
        table.seats[0].time_bank_ms = time_bank_ms;
        table.chip_pool = 3_000;
        table.hand_id = 7;
        table.call_seq = 11;
        table
    }

    #[test]
    fn canonical_input_binds_betting_time_bank_at_maximum_legal_deadline() {
        let mut pre = betting_table(10);
        pre.timeout_config.betting_timeout_ms = 10;
        pre.enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, u64::MAX - 20)
            .unwrap();
        let now_ms = u64::MAX - 10;
        let (post, events) = execute_tick(&pre, now_ms);

        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::TimeBankConsumed {
                consumed_ms: 10,
                remaining_ms: 0,
                ..
            }
        )));
        assert_eq!(post.timestamps().betting_started_at, now_ms);
        assert!(!post.seats[0].is_folded());

        let input = canonical_input(&pre, &post, now_ms).expect("canonical betting tick");
        assert_eq!(input.timeout_kind, TICK_KIND_BETTING);
        assert!(input.timeout_required);
        assert_eq!(input.timeout_started_at, u64::MAX - 20);
        assert_eq!(input.timeout_ms, 10);
        assert_eq!(input.pre_time_bank, 10);
        assert_eq!(input.time_bank_consumed, 10);
        assert_eq!(input.time_bank_post, 0);
        assert_eq!(input.rake_amount, 0);
        assert_eq!(input.version_increment, 1);
        assert_eq!(input.lifecycle.branch_kind, TICK_BRANCH_TIME_BANK_CONSUMED);
    }

    #[test]
    fn canonical_input_binds_rake_event_from_betting_timeout_settlement() {
        let mut pre = betting_table(0);
        // Model an already-collected 100-chip wager from each player.  The
        // table vault is therefore stacks (1,800) + pot (200) = 2,000.
        pre.seats.truncate(2);
        pre.max_players = 2;
        pre.seats[0].stack = 900;
        pre.seats[1].stack = 900;
        pre.seats[0].total_bet = 100;
        pre.seats[1].total_bet = 100;
        pre.pot = 200;
        pre.chip_pool = 2_000;
        pre.rake_mode = RAKE_MODE_PERCENTAGE;
        pre.rake_bps = 500;
        pre.rake_cap = 20;

        let now_ms = 1_030_001;
        let (post, events) = execute_tick(&pre, now_ms);
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::RakeCollected {
                rake_amount: 10,
                rake_mode: RAKE_MODE_PERCENTAGE,
                ..
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::PlayerFolded {
                seat_index: 0,
                reason: FOLD_REASON_AUTO_TIMEOUT,
                ..
            }
        )));

        let input = canonical_input(&pre, &post, now_ms).expect("canonical rake tick");
        assert_eq!(input.timeout_kind, TICK_KIND_BETTING);
        assert!(input.timeout_required);
        assert_eq!(input.time_bank_consumed, 0);
        assert_eq!(input.rake_mode, RAKE_MODE_PERCENTAGE);
        assert_eq!(input.rake_amount, 10);
        assert_eq!(input.lifecycle.branch_kind, TICK_BRANCH_BETTING_TIMEOUT);
    }

    #[test]
    fn canonical_input_rejects_waiting_noop_tick() {
        let mut pre = table();
        occupy(&mut pre, 0, 1, 1_000);
        occupy(&mut pre, 1, 2, 1_000);
        pre.chip_pool = 2_000;
        pre.hand_id = 9;
        pre.call_seq = 13;

        let mut post = pre.clone();
        let mut events = Vec::new();
        state_machine::tick(&mut post, 2_000_000, &mut events).expect("waiting tick");
        assert_eq!(post, pre);
        assert!(events.is_empty());
        assert!(canonical_input(&pre, &post, 2_000_000).is_err());
    }

    #[test]
    fn canonical_input_rejects_post_state_not_produced_by_native_tick() {
        let pre = betting_table(30_000);
        let (mut post, _) = execute_tick(&pre, 1_030_000);
        post.enter_betting(
            ROUND_PREFLOP,
            post.betting_round().unwrap(),
            post.current_turn(),
            123,
        )
        .unwrap();

        assert!(canonical_input(&pre, &post, 1_030_000).is_err());
    }
}
