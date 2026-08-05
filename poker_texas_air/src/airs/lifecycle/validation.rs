//! Production verifier-side reconstruction for lifecycle AIRs.
//!
//! Lifecycle statements bind full table roots and a replicated business row,
//! but roots and rows must also describe the exact authenticated VM call.  The
//! helpers here verify the dispatch-call preimage against its transcript-bound
//! digest, replay native Texas Poker dispatch, compare the complete post table,
//! and finally rebuild the row accepted by each AIR.

use poker_l1::vm::contracts::texas_poker::dispatch::{
    JoinTableArgs, LeaveTableArgs, dispatch,
};
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
use stwo::core::fields::m31::M31;

use super::join_table::{JoinTableAir, JoinTableInput, JoinTableRow};
use super::leave_table::{LeaveTableAir, LeaveTableInput, LeaveTableRow};
use super::reset_for_next_hand::{
    ResetForNextHandAir, ResetForNextHandInput, ResetForNextHandRow,
};
use super::start_hand::{StartHandAir, StartHandInput, StartHandRow};
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prove_task::{DispatchOutput, MethodInput, ProveTask};
use crate::public_inputs::{DispatchCallPublicInput, TexasPublicInputs};
use crate::state_root::{state_root_to_air_limbs, table_from_state_preimage};

struct CanonicalDispatch {
    pre: TexasPokerTable,
    post: TexasPokerTable,
    call: DispatchCallPublicInput,
    task: ProveTask,
}

fn validate_canonical_dispatch(
    public_inputs: &TexasPublicInputs,
    expected_kind: MethodKind,
) -> TexasAirResult<CanonicalDispatch> {
    let method = expected_kind.method_name();
    if public_inputs.kind != expected_kind {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: public-input method kind mismatch"
        )));
    }

    let call = public_inputs.require_dispatch_call()?.clone();
    if call.selector != expected_kind.selector() {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: dispatch selector does not match method kind"
        )));
    }

    let pre = table_from_state_preimage(&public_inputs.pre_image)?;
    let post = table_from_state_preimage(&public_inputs.post_image)?;
    if pre.id != post.id
        || public_inputs.table_id != pre.id.creation_nonce
        || public_inputs.table_id != post.id.creation_nonce
        || public_inputs.pre_version != pre.version
        || public_inputs.post_version != post.version
        || public_inputs.hand_id != post.hand_id
        || public_inputs.call_seq != post.call_seq
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
    let result = dispatch(&call.context, &mut replay, &call.selector, &call.raw_args).map_err(
        |error| {
            TexasAirError::SpecViolation(format!(
                "{method}: canonical pre-state cannot execute native VM dispatch: {error}"
            ))
        },
    )?;
    if replay != post {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: canonical post-table differs from native VM dispatch replay"
        )));
    }

    let output: DispatchOutput = borsh::from_slice(&result.return_value).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "{method}: replayed dispatch output borsh: {error}"
        ))
    })?;
    let task = output.prove_task.ok_or_else(|| {
        TexasAirError::SpecViolation(format!(
            "{method}: replayed state-changing dispatch produced no prove task"
        ))
    })?;
    if task.method_kind != expected_kind
        || task.context != call.context
        || task.selector != call.selector
        || task.raw_args != call.raw_args
        || task.pre_table != pre
        || task.post_table != post
        || task.table_id != public_inputs.table_id
        || task.hand_id != public_inputs.hand_id
        || task.call_seq != public_inputs.call_seq
    {
        return Err(TexasAirError::SpecViolation(format!(
            "{method}: replayed prove task does not match verifier public inputs"
        )));
    }

    Ok(CanonicalDispatch {
        pre,
        post,
        call,
        task,
    })
}

/// Replay canonical `start_hand` and reconstruct its complete trusted row.
pub(crate) fn validate_start_hand(
    air: &StartHandAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "start_hand";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::StartHand)?;
    if !matches!(canonical.task.method_input, MethodInput::Empty) {
        return Err(TexasAirError::SpecViolation(
            "start_hand: replayed task has the wrong MethodInput variant".into(),
        ));
    }

    let active_count = u8::try_from(
        canonical
            .pre
            .seats
            .iter()
            .filter(|seat| seat.is_occupied())
            .count(),
    )
    .map_err(|_| TexasAirError::SpecViolation("start_hand: active count exceeds u8".into()))?;
    let input = StartHandInput {
        active_count,
        new_button: canonical.post.button,
        ante_mode: canonical.post.ante_mode,
        ante_amount: canonical.post.ante_amount,
        ante_collected: canonical.post.ante_collected,
    };
    if air.input.active_count != input.active_count
        || air.input.new_button != input.new_button
        || air.input.ante_mode != input.ante_mode
        || air.input.ante_amount != input.ante_amount
        || air.input.ante_collected != input.ante_collected
    {
        return Err(TexasAirError::SpecViolation(
            "start_hand: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let count = M31::from(u32::from(active_count));
    let count_product = count * (count - M31::from(1u32));
    let row = StartHandRow::active(
        &input,
        count_product.inverse(),
        count_product,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Replay canonical `reset_for_next_hand` and reconstruct its complete trusted row.
pub(crate) fn validate_reset_for_next_hand(
    air: &ResetForNextHandAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "reset_for_next_hand";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::ResetForNextHand)?;
    if !matches!(canonical.task.method_input, MethodInput::Empty) {
        return Err(TexasAirError::SpecViolation(
            "reset_for_next_hand: replayed task has the wrong MethodInput variant".into(),
        ));
    }

    let input = ResetForNextHandInput {
        shuffle_phase: canonical.pre.shuffle_state.phase,
    };
    if air.input.shuffle_phase != input.shuffle_phase {
        return Err(TexasAirError::SpecViolation(
            "reset_for_next_hand: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let row = ResetForNextHandRow::active(
        &input,
        0,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        canonical.pre.round_state,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
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

/// Replay canonical `join_table` and reconstruct its complete trusted row.
pub(crate) fn validate_join_table(
    air: &JoinTableAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "join_table";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::JoinTable)?;
    let args: JoinTableArgs = borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::Join { player, buy_in } = canonical.task.method_input else {
        return Err(TexasAirError::SpecViolation(
            "join_table: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if player != args.player || buy_in != args.buy_in {
        return Err(TexasAirError::SpecViolation(
            "join_table: replayed MethodInput does not match raw args".into(),
        ));
    }

    let seat_index = canonical.pre.find_empty_seat().ok_or_else(|| {
        TexasAirError::SpecViolation("join_table: canonical pre-table has no empty seat".into())
    })?;
    if air.input.seat_index != seat_index
        || air.input.player_addr != args.player
        || air.input.buy_in != args.buy_in
    {
        return Err(TexasAirError::SpecViolation(
            "join_table: AIR input does not match the canonical dispatch".into(),
        ));
    }
    let post_seat = canonical
        .post
        .seats
        .get(usize::from(seat_index))
        .ok_or_else(|| TexasAirError::SpecViolation("join_table: post seat missing".into()))?;
    if post_seat.player != args.player || post_seat.stack != args.buy_in {
        return Err(TexasAirError::SpecViolation(
            "join_table: canonical post seat does not match the dispatch args".into(),
        ));
    }

    let input = JoinTableInput {
        seat_index,
        buy_in: args.buy_in,
        player_addr: args.player,
    };
    let row = JoinTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        canonical.pre.big_blind,
        canonical.pre.chip_pool,
        canonical.pre.addon_pool,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Replay canonical `leave_table` and reconstruct its complete trusted row.
pub(crate) fn validate_leave_table(
    air: &LeaveTableAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "leave_table";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::LeaveTable)?;
    let args: LeaveTableArgs = borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::SeatOnly { seat_index } = canonical.task.method_input else {
        return Err(TexasAirError::SpecViolation(
            "leave_table: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if seat_index != args.seat_index || air.input.seat_index != args.seat_index {
        return Err(TexasAirError::SpecViolation(
            "leave_table: AIR/task seat index does not match raw args".into(),
        ));
    }
    let pre_seat = canonical
        .pre
        .seats
        .get(usize::from(args.seat_index))
        .ok_or_else(|| TexasAirError::SpecViolation("leave_table: pre seat missing".into()))?;

    let input = LeaveTableInput {
        seat_index: args.seat_index,
    };
    let row = LeaveTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        pre_seat.stack,
        pre_seat.pending_addon,
        canonical.pre.chip_pool,
        canonical.post.chip_pool,
        canonical.pre.addon_pool,
        canonical.post.addon_pool,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}
