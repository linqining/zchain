//! Canonical verifier-side reconstruction for crypto protocol AIR rows.
//!
//! These validators close the state-root/business-row detachment gap by
//! replaying the complete native dispatch and rebuilding the exact row accepted
//! by each AIR.  They do not turn the current protocol-state AIRs into embedded
//! DLEq or reveal-token verifiers; that separate cryptographic closure remains
//! explicit in the individual AIR modules.

use poker_l1::vm::contracts::texas_poker::constants::{
    REVEAL_PHASE_NONE, REVEAL_PHASE_SHOWDOWN, ROUND_SHOWDOWN, ROUND_WAITING,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    FoldWithProofArgs, JoinAndShuffleArgs, LeaveWithProofArgs, SubmitReconstructDeckArgs,
    SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;

use super::fold_with_proof::{FoldWithProofAir, FoldWithProofInput, FoldWithProofRow};
use super::join_and_shuffle::{JoinAndShuffleAir, JoinAndShuffleInput, JoinAndShuffleRow};
use super::leave_with_proof::{LeaveWithProofAir, LeaveWithProofInput, LeaveWithProofRow};
use super::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use super::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use super::submit_shuffle_v2::{SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row};
use crate::airs::validation::{validate_canonical_dispatch, validate_row};
use crate::deck_commitment::deck_commitment;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::{
    JoinAndShuffleVerifyRequest, LeaveDleqVerifyRequest, PokerPrecompileId,
    RevealTokenVerifyRequest, precompile_call_context,
};
use crate::prove_task::MethodInput;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::state_root_to_air_limbs;

/// Reject compound `fold_with_proof` transitions that require collection,
/// round advancement, settlement, or reset AIRs.
pub(crate) fn ensure_fold_with_proof_mid_round(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
) -> TexasAirResult<u8> {
    let expected_version = pre
        .version
        .checked_add(1)
        .ok_or_else(|| TexasAirError::SpecViolation("fold_with_proof version overflow".into()))?;
    if post.version != expected_version
        || pre.betting_round.is_none()
        || post.betting_round.is_none()
        || pre.round_state != post.round_state
        || pre.pot != post.pot
    {
        return Err(TexasAirError::UnsupportedBettingTransition(
            "fold_with_proof triggered collect_bets_to_pot / round advance / settlement; the current AIR covers only a single-version same-round transition with unchanged pot"
                .into(),
        ));
    }
    post.current_turn.ok_or_else(|| {
        TexasAirError::UnsupportedBettingTransition(
            "fold_with_proof produced no next current_turn; terminal settlement remains fail-closed"
                .into(),
        )
    })
}

/// Bind a non-terminal `fold_with_proof` transition to its exact dispatch and
/// verifier-issued leave-layer DLEq receipt.
pub(crate) fn validate_fold_with_proof(
    air: &FoldWithProofAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "fold_with_proof";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::FoldWithProof)?;
    let args: FoldWithProofArgs = borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
        TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
    })?;
    let MethodInput::FoldWithProof {
        seat_index,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index || raw_args != &canonical.call.raw_args {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: replayed MethodInput does not match raw args".into(),
        ));
    }
    let post_current_turn = ensure_fold_with_proof_mid_round(&canonical.pre, &canonical.post)?;

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "fold_with_proof requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::DleqLeave {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof received the wrong precompile receipt type".into(),
        ));
    }
    let player_pk = canonical
        .pre
        .seats
        .get(usize::from(args.seat_index))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "fold_with_proof seat is outside the canonical pre-table".into(),
            )
        })?
        .pk;
    let expected_context = precompile_call_context(
        MethodKind::FoldWithProof,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request = LeaveDleqVerifyRequest::new(
        expected_context,
        canonical.pre.deck_state.encrypted.clone(),
        args.output_cards,
        player_pk,
        args.fold_proof,
    );
    if binding.request_bytes() != expected_request.encode()? {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof precompile request does not match canonical dispatch".into(),
        ));
    }
    binding.validate_issued()?;

    let input = FoldWithProofInput {
        seat_index: args.seat_index,
        post_current_turn,
        old_deck_commitment: deck_commitment(&canonical.pre),
        new_deck_commitment: deck_commitment(&canonical.post),
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.post_current_turn != input.post_current_turn
        || air.input.old_deck_commitment != input.old_deck_commitment
        || air.input.new_deck_commitment != input.new_deck_commitment
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "fold_with_proof: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let row = FoldWithProofRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        canonical.pre.round_state,
        canonical.post.round_state,
        canonical.pre.pot,
        canonical.post.pot,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind `join_and_shuffle` to its exact authenticated dispatch and post table.
pub(crate) fn validate_join_and_shuffle(
    air: &JoinAndShuffleAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "join_and_shuffle";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::JoinAndShuffle)?;
    let args: JoinAndShuffleArgs =
        borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::JoinAndShuffle {
        seat_index,
        player,
        buy_in,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "join_and_shuffle: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index
        || *player != args.player
        || *buy_in != args.buy_in
        || raw_args != &canonical.call.raw_args
    {
        return Err(TexasAirError::SpecViolation(
            "join_and_shuffle: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "join_and_shuffle requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::JoinAndShuffle {
        return Err(TexasAirError::SpecViolation(
            "join_and_shuffle received the wrong precompile receipt type".into(),
        ));
    }
    binding.validate_issued()?;
    let call_context = precompile_call_context(
        MethodKind::JoinAndShuffle,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request =
        JoinAndShuffleVerifyRequest::from_dispatch(call_context, &canonical.pre, &args)?;
    if expected_request.encode()? != binding.request_bytes() {
        return Err(TexasAirError::SpecViolation(
            "join_and_shuffle precompile request does not match canonical dispatch".into(),
        ));
    }

    let input = JoinAndShuffleInput {
        seat_index: args.seat_index,
        old_deck_commitment: deck_commitment(&canonical.pre),
        new_deck_commitment: deck_commitment(&canonical.post),
        shuffle_phase: canonical.pre.shuffle_state.phase,
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.old_deck_commitment != input.old_deck_commitment
        || air.input.new_deck_commitment != input.new_deck_commitment
        || air.input.shuffle_phase != input.shuffle_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "join_and_shuffle: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let pre_completed_count = count_as_u8(
        canonical.pre.shuffle_state.completed_players.len(),
        METHOD,
        "pre completed player",
    )?;
    let post_completed_count = count_as_u8(
        canonical.post.shuffle_state.completed_players.len(),
        METHOD,
        "post completed player",
    )?;
    let row = JoinAndShuffleRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        pre_completed_count,
        post_completed_count,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind `leave_with_proof` to its exact authenticated dispatch and post table.
pub(crate) fn validate_leave_with_proof(
    air: &LeaveWithProofAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "leave_with_proof";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::LeaveWithProof)?;
    let args: LeaveWithProofArgs =
        borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::LeaveWithProof {
        seat_index,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "leave_with_proof: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index || raw_args != &canonical.call.raw_args {
        return Err(TexasAirError::SpecViolation(
            "leave_with_proof: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "leave_with_proof requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::DleqLeave {
        return Err(TexasAirError::SpecViolation(
            "leave_with_proof received the wrong precompile receipt type".into(),
        ));
    }
    let player_pk = canonical
        .pre
        .seats
        .get(usize::from(args.seat_index))
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "leave_with_proof seat is outside the canonical pre-table".into(),
            )
        })?
        .pk;
    let expected_context = precompile_call_context(
        MethodKind::LeaveWithProof,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request = LeaveDleqVerifyRequest::new(
        expected_context,
        canonical.pre.deck_state.encrypted.clone(),
        args.output_cards.clone(),
        player_pk,
        args.leave_proof.clone(),
    );
    if binding.request_bytes() != expected_request.encode()? {
        return Err(TexasAirError::SpecViolation(
            "leave_with_proof precompile request does not match the canonical dispatch".into(),
        ));
    }
    binding.validate_issued()?;

    let input = LeaveWithProofInput {
        seat_index: args.seat_index,
        // `LeaveKind` is the proof marker type, not a runtime enum. The current
        // row keeps its historical zero discriminator until the DLEq verifier
        // AIR replaces this placeholder column.
        leave_kind: 0,
        shuffle_phase: canonical.pre.shuffle_state.phase,
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.leave_kind != input.leave_kind
        || air.input.shuffle_phase != input.shuffle_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "leave_with_proof: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_completed_count = count_as_u8(
        canonical.post.shuffle_state.completed_players.len(),
        METHOD,
        "post completed player",
    )?;
    let row = LeaveWithProofRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        post_completed_count,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind reveal-token submission to its exact authenticated dispatch and post table.
pub(crate) fn validate_submit_player_reveal_tokens(
    air: &SubmitPlayerRevealTokensAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_player_reveal_tokens";
    let canonical =
        validate_canonical_dispatch(public_inputs, MethodKind::SubmitPlayerRevealTokens)?;
    let args: SubmitRevealTokensArgs =
        borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::SubmitPlayerRevealTokens {
        seat_index,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index || raw_args != &canonical.call.raw_args {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_player_reveal_tokens requires a verifier-issued precompile binding".into(),
        )
    })?;
    if binding.precompile_id() != PokerPrecompileId::RevealToken {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens received the wrong precompile receipt type".into(),
        ));
    }
    let expected_context = precompile_call_context(
        MethodKind::SubmitPlayerRevealTokens,
        args.seat_index,
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let expected_request =
        RevealTokenVerifyRequest::from_dispatch(expected_context, &canonical.pre, &args)?;
    if binding.request_bytes() != expected_request.encode()? {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens precompile request does not match the canonical dispatch"
                .into(),
        ));
    }
    binding.validate_issued()?;

    let input = SubmitPlayerRevealTokensInput {
        seat_index: args.seat_index,
        reveal_phase: canonical.pre.reveal_token_state.reveal_phase,
        version_increment: reveal_version_increment(&canonical.pre, &canonical.post)?,
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.reveal_phase != input.reveal_phase
        || air.input.version_increment != input.version_increment
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "submit_player_reveal_tokens: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_revealed_count = count_as_u8(
        canonical.post.reveal_token_state.assignments.len(),
        METHOD,
        "post reveal assignment",
    )?;
    let row = SubmitPlayerRevealTokensRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        post_revealed_count,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)
}

/// Bind a verifier-issued shuffle receipt to the exact VM dispatch and row.
pub(crate) fn validate_submit_shuffle_v2(
    air: &SubmitShuffleV2Air,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_shuffle_v2";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::SubmitShuffleV2)?;
    let args: SubmitShuffleV2Args =
        borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::SubmitShuffleV2 {
        seat_index,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index || raw_args != &canonical.call.raw_args {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_shuffle_v2 requires a verifier-issued precompile binding".into(),
        )
    })?;
    let input = SubmitShuffleV2Input {
        seat_index: args.seat_index,
        new_deck_commitment: deck_commitment(&canonical.post),
        shuffle_phase: canonical.pre.shuffle_state.phase,
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.new_deck_commitment != input.new_deck_commitment
        || air.input.shuffle_phase != input.shuffle_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "submit_shuffle_v2: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_completed_count = count_as_u8(
        canonical.post.shuffle_state.completed_players.len(),
        METHOD,
        "post completed player",
    )?;
    let row = SubmitShuffleV2Row::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        post_completed_count,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)?;
    super::submit_shuffle_v2::validate_public_inputs(air, public_inputs)
}

/// Bind a verifier-issued reconstruction receipt to the exact VM dispatch and row.
pub(crate) fn validate_submit_reconstruct_deck(
    air: &SubmitReconstructDeckAir,
    public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()> {
    const METHOD: &str = "submit_reconstruct_deck";
    let canonical = validate_canonical_dispatch(public_inputs, MethodKind::SubmitReconstructDeck)?;
    let args: SubmitReconstructDeckArgs =
        borsh::from_slice(&canonical.call.raw_args).map_err(|error| {
            TexasAirError::SerializationError(format!("{METHOD}: raw args borsh: {error}"))
        })?;
    let MethodInput::SubmitReconstructDeck {
        seat_index,
        raw_args,
    } = &canonical.task.method_input
    else {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: replayed task has the wrong MethodInput variant".into(),
        ));
    };
    if *seat_index != args.seat_index || raw_args != &canonical.call.raw_args {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: replayed MethodInput does not match raw args".into(),
        ));
    }

    let binding = public_inputs.precompile_binding.as_ref().ok_or_else(|| {
        TexasAirError::SpecViolation(
            "submit_reconstruct_deck requires a verifier-issued precompile binding".into(),
        )
    })?;
    let input = SubmitReconstructDeckInput {
        seat_index: args.seat_index,
        reconstruct_phase: canonical.pre.reconstruct_state.phase,
        precompile: binding.air_binding(),
    };
    if air.input.seat_index != input.seat_index
        || air.input.reconstruct_phase != input.reconstruct_phase
        || air.input.precompile != input.precompile
    {
        return Err(TexasAirError::SpecViolation(
            "submit_reconstruct_deck: AIR input does not match the canonical dispatch".into(),
        ));
    }

    let post_submitted_count = count_as_u8(
        canonical.post.reconstruct_state.player_decks.len(),
        METHOD,
        "post submitted deck",
    )?;
    let row = SubmitReconstructDeckRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        canonical.pre.version,
        canonical.post.version,
        post_submitted_count,
    );
    validate_row(public_inputs, &row.to_vec(), METHOD)?;
    super::submit_reconstruct_deck::validate_public_inputs(air, public_inputs)
}

fn reveal_version_increment(
    pre: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    post: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
) -> TexasAirResult<u8> {
    let completed_showdown = post.round_state == ROUND_WAITING
        && post.reveal_token_state.reveal_phase == REVEAL_PHASE_NONE
        && post.pot == 0;
    let increment = if completed_showdown {
        if pre.round_state != ROUND_SHOWDOWN
            || pre.reveal_token_state.reveal_phase != REVEAL_PHASE_SHOWDOWN
        {
            return Err(TexasAirError::UnsupportedBettingTransition(
                "submit_player_reveal_tokens reset without a showdown reveal pre-state".into(),
            ));
        }
        2
    } else {
        1
    };

    let expected_post_version = pre.version.saturating_add(u64::from(increment));
    if post.version != expected_post_version {
        return Err(TexasAirError::SpecViolation(format!(
            "submit_player_reveal_tokens: expected version {expected_post_version} after {increment} native bump(s), got {}",
            post.version
        )));
    }
    Ok(increment)
}

fn count_as_u8(count: usize, method: &str, field: &str) -> TexasAirResult<u8> {
    u8::try_from(count).map_err(|_| {
        TexasAirError::SpecViolation(format!("{method}: {field} count {count} exceeds u8"))
    })
}
