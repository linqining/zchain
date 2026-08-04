//! Production verifier-side reconstruction for betting action AIRs.
//!
//! The state roots and a complete trace row are Fiat-Shamir bound, but that is
//! insufficient if both are supplied independently: a malicious prover could
//! commit to real table roots and a different, self-consistent action row. This
//! module decodes the canonical table preimages, replays the native VM action,
//! and reconstructs the exact AIR row before Stwo verification.

use poker_l1::vm::contracts::texas_poker::constants::{
    FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN,
};
use poker_l1::vm::contracts::texas_poker::state_machine;
use poker_l1::vm::contracts::texas_poker::types::{Seat, TexasPokerTable};
use stwo::core::fields::m31::M31;

use super::auto_fold::{AutoFoldAir, AutoFoldRow};
use super::bet::{BetAir, BetRow};
use super::call::{CallAir, CallRow};
use super::check::{CheckAir, CheckRow, NO_CURRENT_TURN};
use super::fold::{FoldAir, FoldRow};
use super::force_fold::{ForceFoldAir, ForceFoldRow};
use super::raise::{RaiseAir, RaiseRow};
use super::request_leave_after_hand::{RequestLeaveAfterHandAir, RequestLeaveAfterHandRow};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

#[derive(Debug, Clone, Copy)]
enum NativeAction {
    Fold { seat_index: u8 },
    Check { seat_index: u8 },
    Call { seat_index: u8 },
    Raise { seat_index: u8, total_bet: u64 },
    Bet { seat_index: u8, amount: u64 },
    AutoFold { seat_index: u8 },
    ForceFold { seat_index: u8 },
}

impl NativeAction {
    const fn name(self) -> &'static str {
        match self {
            Self::Fold { .. } => "fold",
            Self::Check { .. } => "check",
            Self::Call { .. } => "call",
            Self::Raise { .. } => "raise",
            Self::Bet { .. } => "bet",
            Self::AutoFold { .. } => "auto_fold",
            Self::ForceFold { .. } => "force_fold",
        }
    }
}

struct ValidatedTables {
    pre: TexasPokerTable,
    post: TexasPokerTable,
}

fn validate_native_mid_round(
    public_inputs: &TexasPublicInputs,
    expected_kind: MethodKind,
    action: NativeAction,
    allow_round_completion: bool,
) -> TexasAirResult<ValidatedTables> {
    let method = action.name();
    if public_inputs.kind != expected_kind {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public-input method kind mismatch"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if public_inputs.pre_version != pre.version
        || public_inputs.post_version != post.version
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
        || pre.hand_id != post.hand_id
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public metadata does not match canonical pre/post tables"
        )));
    }

    let expected_call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{method}: call_seq overflow during VM replay"))
    })?;
    if post.call_seq != expected_call_seq {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: post call_seq must equal pre call_seq + 1"
        )));
    }

    let mut replay = pre.clone();
    let mut events = Vec::new();
    let result = match action {
        NativeAction::Fold { seat_index } => {
            state_machine::apply_fold(&mut replay, seat_index, &mut events)
        }
        NativeAction::Check { seat_index } => {
            state_machine::apply_check(&mut replay, seat_index, &mut events)
        }
        NativeAction::Call { seat_index } => {
            state_machine::apply_call(&mut replay, seat_index, &mut events)
        }
        NativeAction::Raise {
            seat_index,
            total_bet,
        } => state_machine::apply_raise(&mut replay, seat_index, total_bet, &mut events),
        NativeAction::Bet { seat_index, amount } => {
            state_machine::apply_bet(&mut replay, seat_index, amount, &mut events)
        }
        NativeAction::AutoFold { seat_index } => state_machine::apply_fold_internal(
            &mut replay,
            seat_index,
            FOLD_REASON_AUTO_TIMEOUT,
            &mut events,
        ),
        NativeAction::ForceFold { seat_index } => state_machine::apply_fold_internal(
            &mut replay,
            seat_index,
            FOLD_REASON_FORCE_ADMIN,
            &mut events,
        ),
    };
    result.map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "{method}: canonical pre-state cannot execute native VM action: {error}"
        ))
    })?;

    // dispatch() advances sequence metadata outside the state-machine helper.
    replay.call_seq = expected_call_seq;
    replay.hand_id = pre.hand_id;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: canonical post-table differs from native VM replay"
        )));
    }

    let completes_betting_round =
        post.round_state != pre.round_state || post.betting_round.is_none() || post.pot != pre.pot;
    if pre.betting_round.is_none() || (completes_betting_round && !allow_round_completion) {
        return Err(TexasAirError::UnsupportedBettingTransition(format!(
            "{method} triggered collect_bets_to_pot / advance_round / settlement; current AIR proves only same-round transitions with unchanged pot and Some(current_turn)"
        )));
    }

    Ok(ValidatedTables { pre, post })
}

fn seat<'a>(table: &'a TexasPokerTable, seat_index: u8, method: &str) -> TexasAirResult<&'a Seat> {
    table.seats.get(usize::from(seat_index)).ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{method}: seat_index {seat_index} is outside canonical table"
        ))
    })
}

fn validate_row(
    public_inputs: &TexasPublicInputs,
    expected_row: &[M31],
    method: &str,
) -> TexasAirResult<()> {
    let trusted_row = public_inputs.require_expected_trace_row(expected_row.len())?;
    if trusted_row != expected_row {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: trusted trace row was not reconstructed from canonical public inputs"
        )));
    }
    Ok(())
}

pub(crate) fn validate_fold(
    air: &FoldAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Fold,
        NativeAction::Fold {
            seat_index: air.input.seat_index,
        },
        false,
    )?;
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    if air.input.post_current_turn != post_turn {
        return Err(TexasAirError::SpecViolation(
            "fold: AIR input does not match canonical post current_turn".into(),
        ));
    }
    let row = FoldRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
    );
    validate_row(public_inputs, &row.to_vec(), "fold")
}

pub(crate) fn validate_check(
    air: &CheckAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Check,
        NativeAction::Check {
            seat_index: air.input.seat_index,
        },
        true,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "check")?;
    let pre_round = tables
        .pre
        .betting_round
        .as_ref()
        .expect("mid-round checked");
    let post_turn = tables.post.current_turn.unwrap_or(NO_CURRENT_TURN);
    let completes_betting_round = tables.post.round_state != tables.pre.round_state
        || tables.post.betting_round.is_none()
        || tables.post.pot != tables.pre.pot;
    if air.input.current_bet != pre_round.current_bet
        || air.input.seat_bet != pre_seat.bet
        || air.input.post_current_turn != post_turn
        || air.input.completes_betting_round != completes_betting_round
        || air.input.post_round_state != tables.post.round_state
        || air.input.post_pot != tables.post.pot
    {
        return Err(TexasAirError::SpecViolation(
            "check: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = CheckRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
        tables.pre.pot,
        tables.post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), "check")
}

pub(crate) fn validate_call(
    air: &CallAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Call,
        NativeAction::Call {
            seat_index: air.input.seat_index,
        },
        false,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "call")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "call")?;
    let pre_round = tables
        .pre
        .betting_round
        .as_ref()
        .expect("mid-round checked");
    let call_amount = pre_round.process_call(pre_seat.bet, pre_seat.stack);
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    if air.input.call_amount != call_amount
        || air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_seat_bet != pre_seat.bet
        || air.input.pre_seat_stack != pre_seat.stack
        || air.input.pre_seat_total_bet != pre_seat.total_bet
        || air.input.post_current_turn != post_turn
    {
        return Err(TexasAirError::SpecViolation(
            "call: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = CallRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
        tables.pre.pot,
        tables.post.pot,
        post_seat.stack,
        post_seat.bet,
        post_seat.all_in,
        pre_seat.bet,
        pre_seat.stack,
        post_seat.total_bet,
        pre_seat.total_bet,
    );
    validate_row(public_inputs, &row.to_vec(), "call")
}

pub(crate) fn validate_raise(
    air: &RaiseAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Raise,
        NativeAction::Raise {
            seat_index: air.input.seat_index,
            total_bet: air.input.raise_to,
        },
        false,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "raise")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "raise")?;
    let pre_round = tables
        .pre
        .betting_round
        .as_ref()
        .expect("mid-round checked");
    let post_round = tables
        .post
        .betting_round
        .as_ref()
        .expect("mid-round checked");
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    if air.input.raise_to != post_seat.bet
        || air.input.raise_to != post_round.current_bet
        || air.input.min_raise != pre_round.min_raise
        || air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_seat_stack != pre_seat.stack
        || air.input.pre_seat_bet != pre_seat.bet
        || air.input.pre_seat_total_bet != pre_seat.total_bet
        || air.input.post_current_turn != post_turn
    {
        return Err(TexasAirError::SpecViolation(
            "raise: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = RaiseRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
        tables.pre.pot,
        tables.post.pot,
        pre_seat.stack,
        pre_seat.bet,
        pre_seat.total_bet,
        post_seat.stack,
        post_seat.bet,
        post_seat.total_bet,
        post_round.current_bet,
        post_round.min_raise,
        post_seat.all_in,
    );
    validate_row(public_inputs, &row.to_vec(), "raise")
}

pub(crate) fn validate_bet(air: &BetAir, public_inputs: &TexasPublicInputs) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::Bet,
        NativeAction::Bet {
            seat_index: air.input.seat_index,
            amount: air.input.amount,
        },
        false,
    )?;
    let pre_seat = seat(&tables.pre, air.input.seat_index, "bet")?;
    let post_seat = seat(&tables.post, air.input.seat_index, "bet")?;
    let pre_round = tables
        .pre
        .betting_round
        .as_ref()
        .expect("mid-round checked");
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    let amount = post_seat.bet.checked_sub(pre_seat.bet).ok_or_else(|| {
        TexasAirError::SpecViolation("bet: canonical post seat.bet decreased".into())
    })?;
    if air.input.amount != amount
        || air.input.pre_current_bet != pre_round.current_bet
        || air.input.pre_min_raise != pre_round.min_raise
        || air.input.pre_seat_bet != pre_seat.bet
        || air.input.pre_seat_stack != pre_seat.stack
        || air.input.pre_seat_total_bet != pre_seat.total_bet
        || air.input.post_current_turn != post_turn
    {
        return Err(TexasAirError::SpecViolation(
            "bet: AIR input does not match canonical table fields".into(),
        ));
    }
    let row = BetRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
        tables.pre.pot,
        tables.post.pot,
        post_seat.bet,
        pre_seat.bet,
        pre_seat.stack,
        post_seat.stack,
        pre_seat.total_bet,
        post_seat.total_bet,
    );
    validate_row(public_inputs, &row.to_vec(), "bet")
}

pub(crate) fn validate_auto_fold(
    air: &AutoFoldAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::AutoFold,
        NativeAction::AutoFold {
            seat_index: air.input.seat_index,
        },
        false,
    )?;
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    let pre_seat = seat(&tables.pre, air.input.seat_index, "auto_fold")?;
    let deadline = tables
        .pre
        .timestamps
        .betting_started_at
        .saturating_add(tables.pre.timeout_config.betting_timeout_ms);
    if air.input.pre_betting_started_at != tables.pre.timestamps.betting_started_at
        || air.input.betting_timeout_ms != tables.pre.timeout_config.betting_timeout_ms
        || air.input.pre_time_bank_ms != pre_seat.time_bank_ms
        || air.input.pre_betting_started_at == 0
        || air.input.pre_time_bank_ms != 0
        || air.input.current_time < deadline
        || air.input.post_current_turn != post_turn
    {
        return Err(TexasAirError::SpecViolation(
            "auto_fold: AIR timeout inputs do not match the canonical table transition".into(),
        ));
    }
    let row = AutoFoldRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
    );
    validate_row(public_inputs, &row.to_vec(), "auto_fold")
}

pub(crate) fn validate_force_fold(
    air: &ForceFoldAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let tables = validate_native_mid_round(
        public_inputs,
        MethodKind::ForceFold,
        NativeAction::ForceFold {
            seat_index: air.input.seat_index,
        },
        false,
    )?;
    let post_turn = tables.post.current_turn.expect("mid-round checked");
    if air.input.post_current_turn != post_turn {
        return Err(TexasAirError::SpecViolation(
            "force_fold: AIR input does not match canonical post current_turn".into(),
        ));
    }
    let row = ForceFoldRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        tables.pre.version,
        tables.post.version,
        tables.pre.round_state,
        tables.post.round_state,
    );
    validate_row(public_inputs, &row.to_vec(), "force_fold")
}

/// Reconstruct and bind the complete single-seat toggle performed by
/// `request_leave_after_hand`.
///
/// The method is valid in every table phase, but must leave every table-level
/// field unchanged apart from the selected occupied seat's `want_leave`, the
/// normal version bump, and dispatch's call sequence bump. Permission is
/// checked by the full dispatch replay in the Orchestrator; the raw state
/// preimages here provide the same canonical-row protection used by betting
/// actions for direct verifier callers.
pub(crate) fn validate_request_leave_after_hand(
    air: &RequestLeaveAfterHandAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "request_leave_after_hand";
    if public_inputs.kind != MethodKind::RequestLeaveAfterHand {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: public-input method kind mismatch"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if public_inputs.pre_version != pre.version
        || public_inputs.post_version != post.version
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.hand_id != pre.hand_id
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: public metadata does not match canonical pre/post tables"
        )));
    }

    let expected_call_seq = pre.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("{METHOD}: call_seq overflow during VM replay"))
    })?;
    if post.call_seq != expected_call_seq {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: post call_seq must equal pre call_seq + 1"
        )));
    }
    if pre.hand_id != post.hand_id {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: hand_id must remain unchanged"
        )));
    }

    let pre_seat = seat(&pre, air.input.seat_index, METHOD)?;
    if !pre_seat.is_occupied() {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: target seat is not occupied"
        )));
    }
    let mut replay = pre.clone();
    let mut events = Vec::new();
    state_machine::apply_request_leave(&mut replay, air.input.seat_index, &mut events).map_err(
        |error| TexasAirError::SpecViolation(format!("{METHOD}: native VM replay failed: {error}")),
    )?;
    replay.call_seq = expected_call_seq;
    replay.hand_id = pre.hand_id;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: canonical post-table differs from native VM replay"
        )));
    }

    let post_seat = seat(&post, air.input.seat_index, METHOD)?;
    if air.input.pre_want_leave != pre_seat.want_leave
        || air.input.post_want_leave != post_seat.want_leave
        || air.input.post_want_leave == air.input.pre_want_leave
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{METHOD}: AIR input does not match canonical want_leave toggle"
        )));
    }

    let row = RequestLeaveAfterHandRow::active(
        &air.input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        pre.version,
        post.version,
        pre.round_state,
        post.round_state,
        pre.pot,
        post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}
