//! Versioned persisted-state codec for Texas Poker tables.
//!
//! The live persisted table type is schema v15. Schemas v2-v14 are decoded into exact legacy
//! mirrors and migrated with fail-closed validation for every removed or compacted field.

use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ElGamalCiphertext};
use poker_protocol::zk_shuffle::reconstruction::{
    apply_reconstruction_contributions, canonical_base_deck,
};
use std::io::{self, Read, Write};

use super::TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION;
use super::betting::BettingRound;
use super::card::{BoardCards, Card, HoleCards};
use super::side_pot::SidePot;
use super::types::{
    DeckState, EMPTY_PLAYER, HandPhase, NO_SEAT, ReconstructState, RevealAssignment,
    RevealProgress, RevealTarget, RevealTokenState, RitStartStreet, RunItTwiceState, Seat,
    SeatMask, SeatStatus, ShuffleState, ShufflingPhase, ShufflingPurpose, TexasPokerTable,
    TimeoutConfig, Timestamps, seat_mask_contains, seat_mask_from_indices,
};
use super::utils::generate_plaintext_cards;
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;

const LEGACY_V2_SCHEMA_VERSION: u8 = 2;
const LEGACY_V3_SCHEMA_VERSION: u8 = 3;
const LEGACY_V4_SCHEMA_VERSION: u8 = 4;
const LEGACY_V5_SCHEMA_VERSION: u8 = 5;
const LEGACY_V6_SCHEMA_VERSION: u8 = 6;
const LEGACY_V7_SCHEMA_VERSION: u8 = 7;
const LEGACY_V8_SCHEMA_VERSION: u8 = 8;
const LEGACY_V9_SCHEMA_VERSION: u8 = 9;
const LEGACY_V10_SCHEMA_VERSION: u8 = 10;
const LEGACY_V11_SCHEMA_VERSION: u8 = 11;
const LEGACY_V12_SCHEMA_VERSION: u8 = 12;
const LEGACY_V13_SCHEMA_VERSION: u8 = 13;
const LEGACY_V14_SCHEMA_VERSION: u8 = 14;

fn time_bank_u32(value: u64, label: &str) -> PokerL1Result<u32> {
    u32::try_from(value).map_err(|_| {
        PokerL1Error::Serialization(format!(
            "Texas {label} time bank {value} exceeds canonical u32 range"
        ))
    })
}

fn rake_bps_u16(value: u64, label: &str) -> PokerL1Result<u16> {
    u16::try_from(value).map_err(|_| {
        PokerL1Error::Serialization(format!(
            "Texas {label} rake bps {value} exceeds canonical u16 range"
        ))
    })
}

/// Exact two-byte card layout used by table schemas v2-v5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct LegacyCardV5 {
    suit: u8,
    rank: u8,
}

impl TryFrom<LegacyCardV5> for Card {
    type Error = PokerL1Error;

    fn try_from(value: LegacyCardV5) -> Result<Self, Self::Error> {
        let card = Card::new(value.suit, value.rank);
        if card.is_valid() {
            Ok(card)
        } else {
            Err(PokerL1Error::Serialization(format!(
                "legacy Texas card has invalid suit/rank {}/{}",
                value.suit, value.rank
            )))
        }
    }
}

impl From<Card> for LegacyCardV5 {
    fn from(value: Card) -> Self {
        Self {
            suit: value.suit(),
            rank: value.rank(),
        }
    }
}

fn migrate_hole_cards(cards: Vec<LegacyCardV5>, label: &str) -> PokerL1Result<HoleCards> {
    let cards = cards
        .into_iter()
        .map(Card::try_from)
        .collect::<PokerL1Result<Vec<_>>>()?;
    HoleCards::try_from(cards)
        .map_err(|error| PokerL1Error::Serialization(format!("{label}: {error}")))
}

fn migrate_board_cards(cards: Vec<LegacyCardV5>, label: &str) -> PokerL1Result<BoardCards> {
    let cards = cards
        .into_iter()
        .map(Card::try_from)
        .collect::<PokerL1Result<Vec<_>>>()?;
    BoardCards::try_from(cards)
        .map_err(|error| PokerL1Error::Serialization(format!("{label}: {error}")))
}

#[cfg(test)]
fn legacy_cards(cards: &[Card]) -> Vec<LegacyCardV5> {
    cards.iter().copied().map(LegacyCardV5::from).collect()
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyShuffleStateV4 {
    phase: u8,
    current_shuffler: Option<u8>,
    pending_players: Vec<u8>,
    completed_players: Vec<u8>,
}

/// Exact shuffle payload used by schemas v5-v10 before the actor became mask-derived.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyShuffleStateV10 {
    phase: u8,
    current_shuffler: u8,
    pending_mask: SeatMask,
    completed_mask: SeatMask,
}

/// Exact schema-v11 shuffle payload before purpose moved to the outer tagged union.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyShuffleStateV11 {
    phase: u8,
    pending_mask: SeatMask,
    completed_mask: SeatMask,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealTokenDataV4 {
    seat_index: u8,
    token: ECPoint,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealAssignmentV4 {
    encrypted_card_index: u8,
    runout_index: u8,
    board_position: u8,
    pending_players: Vec<u8>,
    reveal_tokens: Vec<LegacyRevealTokenDataV4>,
    decrypted: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealTokenStateV4 {
    reveal_phase: u8,
    assignments: Vec<LegacyRevealAssignmentV4>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyReconstructPlayerDeckV4 {
    seat_index: u8,
    output_cts: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyReconstructStateV4 {
    phase: u8,
    pending_players: Vec<u8>,
    coefficient: Option<poker_protocol::crypto::types::ECScalar>,
    player_decks: Vec<LegacyReconstructPlayerDeckV4>,
}

/// Exact v5/v6 reconstruct layout before verified decks were folded into one accumulator.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyReconstructStateV6 {
    phase: u8,
    pending_mask: SeatMask,
    coefficient: Option<poker_protocol::crypto::types::ECScalar>,
    player_decks: Vec<LegacyReconstructPlayerDeckV4>,
}

/// Exact schema-v7..v11 reconstruction payload before redundant phase/coefficient removal.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyReconstructStateV11 {
    phase: u8,
    pending_mask: SeatMask,
    coefficient: Option<poker_protocol::crypto::types::ECScalar>,
    accumulated_deck: Option<Vec<ElGamalCiphertext>>,
}

fn legacy_ordered_mask(indices: &[u8], max_players: u8, label: &str) -> PokerL1Result<SeatMask> {
    if indices.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: legacy seat order is not strictly increasing"
        )));
    }
    seat_mask_from_indices(indices, max_players, label)
}

fn migrate_shuffle_state(
    value: LegacyShuffleStateV4,
    max_players: u8,
) -> PokerL1Result<(u8, ShuffleState)> {
    let pending_mask = legacy_ordered_mask(
        &value.pending_players,
        max_players,
        "legacy shuffle pending players",
    )?;
    let completed_mask = seat_mask_from_indices(
        &value.completed_players,
        max_players,
        "legacy shuffle completed players",
    )?;
    if pending_mask & completed_mask != 0 {
        return Err(PokerL1Error::Serialization(
            "legacy shuffle pending/completed players overlap".into(),
        ));
    }
    let current_shuffler = value.current_shuffler.unwrap_or(NO_SEAT);
    let expected_shuffler = value.pending_players.first().copied().unwrap_or(NO_SEAT);
    if current_shuffler != expected_shuffler {
        return Err(PokerL1Error::Serialization(
            "legacy current shuffler is not the canonical first pending seat".into(),
        ));
    }
    Ok((
        value.phase,
        ShuffleState {
            pending_mask,
            completed_mask,
        },
    ))
}

fn migrate_shuffle_state_v10(
    value: LegacyShuffleStateV10,
    max_players: u8,
) -> PokerL1Result<(u8, ShuffleState)> {
    if !super::types::seat_mask_is_canonical(value.pending_mask, max_players)
        || !super::types::seat_mask_is_canonical(value.completed_mask, max_players)
    {
        return Err(PokerL1Error::Serialization(
            "legacy shuffle mask contains out-of-range seat bits".into(),
        ));
    }
    if value.pending_mask & value.completed_mask != 0 {
        return Err(PokerL1Error::Serialization(
            "legacy shuffle pending/completed masks overlap".into(),
        ));
    }
    let expected_shuffler = super::types::seat_mask_first(value.pending_mask).unwrap_or(NO_SEAT);
    if value.current_shuffler != expected_shuffler {
        return Err(PokerL1Error::Serialization(format!(
            "legacy current shuffler {} is not canonical; expected {expected_shuffler}",
            value.current_shuffler
        )));
    }
    Ok((
        value.phase,
        ShuffleState {
            pending_mask: value.pending_mask,
            completed_mask: value.completed_mask,
        },
    ))
}

fn migrate_shuffle_state_v11(
    value: LegacyShuffleStateV11,
    max_players: u8,
) -> PokerL1Result<(u8, ShuffleState)> {
    if !super::types::seat_mask_is_canonical(value.pending_mask, max_players)
        || !super::types::seat_mask_is_canonical(value.completed_mask, max_players)
        || value.pending_mask & value.completed_mask != 0
    {
        return Err(PokerL1Error::Serialization(
            "legacy v11 shuffle masks are non-canonical".into(),
        ));
    }
    Ok((
        value.phase,
        ShuffleState {
            pending_mask: value.pending_mask,
            completed_mask: value.completed_mask,
        },
    ))
}

fn migrate_shuffling_purpose(
    phase: u8,
    street: u8,
    has_suspended_reveal: bool,
) -> PokerL1Result<ShufflingPurpose> {
    match phase {
        super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP
            if street == super::constants::ROUND_WAITING && !has_suspended_reveal =>
        {
            Ok(ShufflingPurpose::Initial)
        }
        super::constants::SHUFFLE_PHASE_RECONSTRUCT
            if matches!(
                street,
                super::constants::ROUND_PREFLOP
                    | super::constants::ROUND_FLOP
                    | super::constants::ROUND_TURN
                    | super::constants::ROUND_RIVER
                    | super::constants::ROUND_SHOWDOWN
            ) && has_suspended_reveal =>
        {
            Ok(ShufflingPurpose::Reconstruct)
        }
        _ => Err(PokerL1Error::Serialization(format!(
            "legacy shuffle phase {phase} has invalid street/reveal combination"
        ))),
    }
}

fn migrate_shuffling_phase(
    purpose: ShufflingPurpose,
    street: u8,
    state: ShuffleState,
    suspended_reveal: Option<RevealTokenState>,
    deadline_ms: u64,
) -> PokerL1Result<HandPhase> {
    let phase = match (purpose, suspended_reveal) {
        (ShufflingPurpose::Initial, None) if street == super::constants::ROUND_WAITING => {
            ShufflingPhase::Initial { state, deadline_ms }
        }
        (ShufflingPurpose::Reconstruct, Some(suspended_reveal))
            if matches!(
                street,
                super::constants::ROUND_PREFLOP
                    | super::constants::ROUND_FLOP
                    | super::constants::ROUND_TURN
                    | super::constants::ROUND_RIVER
                    | super::constants::ROUND_SHOWDOWN
            ) =>
        {
            ShufflingPhase::Reconstruct {
                street,
                state,
                suspended_reveal,
                deadline_ms,
            }
        }
        _ => {
            return Err(PokerL1Error::Serialization(
                "legacy shuffle has an invalid purpose/street/reveal combination".into(),
            ));
        }
    };
    Ok(HandPhase::Shuffling { phase })
}

fn migrate_reveal_state(
    value: LegacyRevealTokenStateV4,
    max_players: u8,
) -> PokerL1Result<RevealTokenState> {
    let assignments = value
        .assignments
        .into_iter()
        .enumerate()
        .map(|(index, assignment)| {
            let pending_mask = seat_mask_from_indices(
                    &assignment.pending_players,
                    max_players,
                    &format!("legacy reveal assignment {index} pending players"),
                )?;
            let mut submitted_mask = 0;
            let mut reveal_tokens = Vec::with_capacity(assignment.reveal_tokens.len());
            for token in assignment.reveal_tokens {
                if token.seat_index >= max_players {
                    return Err(PokerL1Error::Serialization(format!(
                        "legacy reveal assignment {index} token seat {} is out of range",
                        token.seat_index
                    )));
                }
                let bit = 1u16 << token.seat_index;
                if submitted_mask & bit != 0 || pending_mask & bit == 0 {
                    return Err(PokerL1Error::Serialization(format!(
                        "legacy reveal assignment {index} token seat {} is duplicate or not submitted",
                        token.seat_index
                    )));
                }
                submitted_mask |= bit;
                reveal_tokens.push((token.seat_index, token.token));
            }
            reveal_tokens.sort_by_key(|(seat, _)| *seat);
            let tokens = reveal_tokens.into_iter().map(|(_, token)| token).collect();
            let target = if assignment.board_position == u8::MAX {
                RevealTarget::Hole {
                    // v4 did not persist the owner. The dealing order and card index remain the
                    // authoritative owner mapping; the runtime resolves it when starting showdown.
                    seat_index: NO_SEAT,
                    card_slot: assignment.encrypted_card_index % 2,
                }
            } else {
                RevealTarget::Board {
                    runout_index: assignment.runout_index,
                    board_position: assignment.board_position,
                }
            };
            Ok(RevealAssignment {
                encrypted_card_index: assignment.encrypted_card_index,
                target,
                progress: RevealProgress::Collecting {
                    pending_mask: if assignment.decrypted { 0 } else { pending_mask },
                    submitted_mask,
                    reveal_tokens: tokens,
                },
            })
        })
        .collect::<PokerL1Result<Vec<_>>>()?;
    Ok(RevealTokenState {
        reveal_phase: value.reveal_phase,
        assignments,
    })
}

fn migrate_reveal_state_v7(
    value: LegacyRevealTokenStateV7,
    max_players: u8,
) -> PokerL1Result<RevealTokenState> {
    if max_players > super::types::MAX_SEATS {
        return Err(PokerL1Error::Serialization(format!(
            "legacy v7 reveal max_players {max_players} exceeds mask capacity"
        )));
    }
    let assignments = value
        .assignments
        .into_iter()
        .enumerate()
        .map(|(index, assignment)| {
            if !super::types::seat_mask_is_canonical(assignment.pending_mask, max_players) {
                return Err(PokerL1Error::Serialization(format!(
                    "legacy v7 reveal assignment {index} has out-of-range pending bits"
                )));
            }
            let mut submitted_mask = 0;
            let mut tokens = Vec::with_capacity(assignment.reveal_tokens.len());
            for token in assignment.reveal_tokens {
                if token.seat_index >= max_players {
                    return Err(PokerL1Error::Serialization(format!(
                        "legacy v7 reveal assignment {index} token seat {} is out of range",
                        token.seat_index
                    )));
                }
                let bit = 1u16 << token.seat_index;
                if submitted_mask & bit != 0 || assignment.pending_mask & bit != 0 {
                    return Err(PokerL1Error::Serialization(format!(
                        "legacy v7 reveal assignment {index} token seat {} is duplicate or still pending",
                        token.seat_index
                    )));
                }
                submitted_mask |= bit;
                tokens.push((token.seat_index, token.token));
            }
            tokens.sort_by_key(|(seat, _)| *seat);
            let target = if assignment.board_position == u8::MAX {
                RevealTarget::Hole {
                    seat_index: NO_SEAT,
                    card_slot: assignment.encrypted_card_index % 2,
                }
            } else {
                RevealTarget::Board {
                    runout_index: assignment.runout_index,
                    board_position: assignment.board_position,
                }
            };
            Ok(RevealAssignment {
                encrypted_card_index: assignment.encrypted_card_index,
                target,
                progress: RevealProgress::Collecting {
                    pending_mask: if assignment.decrypted {
                        0
                    } else {
                        assignment.pending_mask
                    },
                    submitted_mask,
                    reveal_tokens: tokens.into_iter().map(|(_, token)| token).collect(),
                },
            })
        })
        .collect::<PokerL1Result<Vec<_>>>()?;
    Ok(RevealTokenState {
        reveal_phase: value.reveal_phase,
        assignments,
    })
}

fn migrate_hand_phase_v11(phase: LegacyHandPhaseV11, max_players: u8) -> PokerL1Result<HandPhase> {
    Ok(match phase {
        LegacyHandPhaseV11::Waiting => HandPhase::Waiting,
        LegacyHandPhaseV11::Shuffling {
            street,
            state,
            suspended_reveal,
            deadline_ms,
        } => {
            let (phase, state) = migrate_shuffle_state_v11(state, max_players)?;
            let purpose = migrate_shuffling_purpose(phase, street, suspended_reveal.is_some())?;
            migrate_shuffling_phase(purpose, street, state, suspended_reveal, deadline_ms)?
        }
        LegacyHandPhaseV11::Revealing {
            street,
            state,
            deadline_ms,
        } => HandPhase::Revealing {
            street,
            state,
            deadline_ms,
        },
        LegacyHandPhaseV11::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        } => {
            let (phase, state) = migrate_reconstruct_state_v11(state, max_players)?;
            validate_active_reconstruct_state(phase, &state)?;
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            }
        }
        LegacyHandPhaseV11::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        } => HandPhase::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        },
        LegacyHandPhaseV11::ShowdownDisplay { deadline_ms } => {
            HandPhase::ShowdownDisplay { deadline_ms }
        }
    })
}

fn migrate_hand_phase_v13(phase: LegacyHandPhaseV13) -> PokerL1Result<HandPhase> {
    Ok(match phase {
        LegacyHandPhaseV13::Waiting => HandPhase::Waiting,
        LegacyHandPhaseV13::Shuffling {
            purpose,
            street,
            state,
            suspended_reveal,
            deadline_ms,
        } => migrate_shuffling_phase(purpose, street, state, suspended_reveal, deadline_ms)?,
        LegacyHandPhaseV13::Revealing {
            street,
            state,
            deadline_ms,
        } => HandPhase::Revealing {
            street,
            state,
            deadline_ms,
        },
        LegacyHandPhaseV13::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        } => HandPhase::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        },
        LegacyHandPhaseV13::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        } => HandPhase::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        },
        LegacyHandPhaseV13::ShowdownDisplay { deadline_ms } => {
            HandPhase::ShowdownDisplay { deadline_ms }
        }
    })
}

fn migrate_hand_phase_v10(phase: LegacyHandPhaseV10, max_players: u8) -> PokerL1Result<HandPhase> {
    Ok(match phase {
        LegacyHandPhaseV10::Waiting => HandPhase::Waiting,
        LegacyHandPhaseV10::Shuffling {
            street,
            state,
            suspended_reveal,
            deadline_ms,
        } => {
            let (phase, state) = migrate_shuffle_state_v10(state, max_players)?;
            let purpose = migrate_shuffling_purpose(phase, street, suspended_reveal.is_some())?;
            migrate_shuffling_phase(purpose, street, state, suspended_reveal, deadline_ms)?
        }
        LegacyHandPhaseV10::Revealing {
            street,
            state,
            deadline_ms,
        } => HandPhase::Revealing {
            street,
            state,
            deadline_ms,
        },
        LegacyHandPhaseV10::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        } => {
            let (phase, state) = migrate_reconstruct_state_v11(state, max_players)?;
            validate_active_reconstruct_state(phase, &state)?;
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            }
        }
        LegacyHandPhaseV10::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        } => HandPhase::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        },
        LegacyHandPhaseV10::ShowdownDisplay { deadline_ms } => {
            HandPhase::ShowdownDisplay { deadline_ms }
        }
    })
}

fn migrate_hand_phase_v7(phase: LegacyHandPhaseV7, max_players: u8) -> PokerL1Result<HandPhase> {
    Ok(match phase {
        LegacyHandPhaseV7::Waiting => HandPhase::Waiting,
        LegacyHandPhaseV7::Shuffling {
            street,
            state,
            suspended_reveal,
            deadline_ms,
        } => {
            let suspended_reveal = suspended_reveal
                .map(|reveal| migrate_reveal_state_v7(reveal, max_players))
                .transpose()?;
            let (phase, state) = migrate_shuffle_state_v10(state, max_players)?;
            let purpose = migrate_shuffling_purpose(phase, street, suspended_reveal.is_some())?;
            migrate_shuffling_phase(purpose, street, state, suspended_reveal, deadline_ms)?
        }
        LegacyHandPhaseV7::Revealing {
            street,
            state,
            deadline_ms,
        } => HandPhase::Revealing {
            street,
            state: migrate_reveal_state_v7(state, max_players)?,
            deadline_ms,
        },
        LegacyHandPhaseV7::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        } => {
            let (phase, state) = migrate_reconstruct_state_v11(state, max_players)?;
            validate_active_reconstruct_state(phase, &state)?;
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal: migrate_reveal_state_v7(suspended_reveal, max_players)?,
                epoch_ms,
                deadline_ms,
            }
        }
        LegacyHandPhaseV7::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        } => HandPhase::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        },
        LegacyHandPhaseV7::ShowdownDisplay { deadline_ms } => {
            HandPhase::ShowdownDisplay { deadline_ms }
        }
    })
}

fn migrate_reconstruct_state(
    value: LegacyReconstructStateV4,
    max_players: u8,
    deck_state: &DeckState,
) -> PokerL1Result<(u8, ReconstructState)> {
    migrate_reconstruct_accumulator(
        LegacyReconstructStateV6 {
            phase: value.phase,
            pending_mask: seat_mask_from_indices(
                &value.pending_players,
                max_players,
                "legacy reconstruct pending players",
            )?,
            coefficient: value.coefficient,
            player_decks: value.player_decks,
        },
        max_players,
        deck_state,
    )
}

fn migrate_reconstruct_accumulator(
    value: LegacyReconstructStateV6,
    max_players: u8,
    deck_state: &DeckState,
) -> PokerL1Result<(u8, ReconstructState)> {
    let mut seen_mask = 0u16;
    let mut accumulated_deck = None;
    if !value.player_decks.is_empty() {
        let aggregate_pk = deck_state.aggregated_pk.as_ref().ok_or_else(|| {
            PokerL1Error::Serialization(
                "legacy reconstruct contributions require aggregate public key".into(),
            )
        })?;
        let cards = generate_plaintext_cards();
        let mut accumulator = canonical_base_deck::<DefaultCurve>(&cards, &aggregate_pk.0)
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "legacy reconstruct canonical base deck: {error}"
                ))
            })?;
        for deck in &value.player_decks {
            if deck.seat_index >= max_players {
                return Err(PokerL1Error::Serialization(format!(
                    "legacy reconstruct contributor seat {} is outside max_players {}",
                    deck.seat_index, max_players
                )));
            }
            let bit = 1u16 << deck.seat_index;
            if seen_mask & bit != 0 || value.pending_mask & bit != 0 {
                return Err(PokerL1Error::Serialization(format!(
                    "legacy reconstruct contributor seat {} is duplicate or still pending",
                    deck.seat_index
                )));
            }
            seen_mask |= bit;
            accumulator =
                apply_reconstruction_contributions::<DefaultCurve>(&accumulator, &deck.output_cts)
                    .map_err(|error| {
                        PokerL1Error::Serialization(format!(
                            "legacy reconstruct contribution for seat {}: {error}",
                            deck.seat_index
                        ))
                    })?;
        }
        accumulated_deck = Some(accumulator);
    }

    Ok((
        value.phase,
        ReconstructState {
            pending_mask: value.pending_mask,
            accumulated_deck,
        },
    ))
}

fn migrate_reconstruct_state_v11(
    value: LegacyReconstructStateV11,
    max_players: u8,
) -> PokerL1Result<(u8, ReconstructState)> {
    if !super::types::seat_mask_is_canonical(value.pending_mask, max_players) {
        return Err(PokerL1Error::Serialization(
            "legacy reconstruct mask contains out-of-range seat bits".into(),
        ));
    }
    if let Some(deck) = &value.accumulated_deck
        && deck.len() != poker_protocol::crypto::types::N_CARDS
    {
        return Err(PokerL1Error::Serialization(format!(
            "legacy reconstruct accumulator has {} cards, expected {}",
            deck.len(),
            poker_protocol::crypto::types::N_CARDS
        )));
    }
    // The coefficient belonged to the retired reconstruction-v1 transcript and is not consumed
    // by V3 verification. Decode it exactly, then deliberately discard it.
    let _ = value.coefficient;
    Ok((
        value.phase,
        ReconstructState {
            pending_mask: value.pending_mask,
            accumulated_deck: value.accumulated_deck,
        },
    ))
}

fn validate_active_reconstruct_state(phase: u8, state: &ReconstructState) -> PokerL1Result<()> {
    match phase {
        super::constants::RECONSTRUCT_PHASE_COLLECTING => Ok(()),
        super::constants::RECONSTRUCT_PHASE_COMPLETE
            if state.pending_mask == 0 && state.accumulated_deck.is_some() =>
        {
            Ok(())
        }
        _ => Err(PokerL1Error::Serialization(format!(
            "legacy active reconstruct phase {phase} is inconsistent with its payload"
        ))),
    }
}

/// Exact v2 mirror of the state-carried unit-test crypto bypass flags.
///
/// They are decoded solely to preserve the old byte layout and intentionally discarded during
/// migration. Production execution never honored them, so they are not consensus game state.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
struct LegacyTableConfigV2 {
    zk_skip_enabled: bool,
    zk_skip_shuffle: bool,
    zk_skip_reveal: bool,
    zk_skip_reconstruct: bool,
    zk_skip_remask: bool,
}

impl Default for LegacyTableConfigV2 {
    fn default() -> Self {
        Self {
            zk_skip_enabled: true,
            zk_skip_shuffle: true,
            zk_skip_reveal: true,
            zk_skip_reconstruct: true,
            zk_skip_remask: true,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacySeatV2 {
    player: Address,
    stack: u64,
    hand: Vec<LegacyCardV5>,
    bet: u64,
    total_bet: u64,
    folded: bool,
    all_in: bool,
    acted_this_round: bool,
    is_waiting: bool,
    left_during_hand: bool,
    pk: ECPoint,
    refunded: bool,
    pending_addon: u64,
    time_bank_ms: u64,
    want_leave: bool,
}

/// Exact schema-v3 seat layout, before lifecycle booleans were normalized into status + flags.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacySeatV3 {
    player: Address,
    stack: u64,
    hand: Vec<LegacyCardV5>,
    bet: u64,
    total_bet: u64,
    folded: bool,
    all_in: bool,
    acted_this_round: bool,
    is_waiting: bool,
    left_during_hand: bool,
    pk: ECPoint,
    pending_addon: u64,
    time_bank_ms: u64,
    want_leave: bool,
}

impl From<LegacySeatV3> for LegacySeatV2 {
    fn from(value: LegacySeatV3) -> Self {
        Self {
            player: value.player,
            stack: value.stack,
            hand: value.hand,
            bet: value.bet,
            total_bet: value.total_bet,
            folded: value.folded,
            all_in: value.all_in,
            acted_this_round: value.acted_this_round,
            is_waiting: value.is_waiting,
            left_during_hand: value.left_during_hand,
            pk: value.pk,
            refunded: false,
            pending_addon: value.pending_addon,
            time_bank_ms: value.time_bank_ms,
            want_leave: value.want_leave,
        }
    }
}

impl TryFrom<LegacySeatV2> for Seat {
    type Error = PokerL1Error;

    fn try_from(value: LegacySeatV2) -> Result<Self, Self::Error> {
        if value.refunded && value.total_bet != 0 {
            return Err(PokerL1Error::Serialization(
                "Texas v2 migration found an in-flight refunded wager".into(),
            ));
        }
        let lifecycle_bits = u8::from(value.is_waiting)
            + u8::from(value.left_during_hand)
            + u8::from(value.folded && !value.left_during_hand)
            + u8::from(value.all_in);
        if value.player == EMPTY_PLAYER {
            if lifecycle_bits != 0 || value.acted_this_round || value.want_leave {
                return Err(PokerL1Error::Serialization(
                    "Texas v2 migration found live state on an empty seat".into(),
                ));
            }
        } else if lifecycle_bits > 1 {
            return Err(PokerL1Error::Serialization(
                "Texas v2 migration found conflicting seat lifecycle flags".into(),
            ));
        }

        // Legacy kick encoded Out redundantly as left_during_hand=true + folded=true. Preserve that
        // one known pair, but reject every other mutually-exclusive combination above.
        let status = if value.player == EMPTY_PLAYER {
            SeatStatus::Empty
        } else if value.left_during_hand {
            SeatStatus::Out
        } else if value.is_waiting {
            SeatStatus::Waiting
        } else if value.folded {
            SeatStatus::Folded
        } else if value.all_in {
            SeatStatus::AllIn
        } else {
            SeatStatus::Active
        };
        let seat = Self {
            player: value.player,
            stack: value.stack,
            hand: migrate_hole_cards(value.hand, "Texas v2/v3 seat hand")?,
            bet: value.bet,
            total_bet: value.total_bet,
            status,
            pk: value.pk,
            pending_addon: value.pending_addon,
            time_bank_ms: time_bank_u32(value.time_bank_ms, "v4 seat")?,
        };
        seat.validate_canonical()?;
        Ok(seat)
    }
}

#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
struct LegacySeatFlagsV4(u8);

impl LegacySeatFlagsV4 {
    const ACTED_THIS_ROUND: u8 = 1 << 0;
    const WANT_LEAVE: u8 = 1 << 1;
    const KNOWN_BITS: u8 = Self::ACTED_THIS_ROUND | Self::WANT_LEAVE;

    fn validate(self) -> PokerL1Result<()> {
        if self.0 & !Self::KNOWN_BITS == 0 {
            Ok(())
        } else {
            Err(PokerL1Error::Serialization(
                "Texas v4 migration found unknown seat flag bits".into(),
            ))
        }
    }

    const fn acted(self) -> bool {
        self.0 & Self::ACTED_THIS_ROUND != 0
    }

    const fn wants_leave(self) -> bool {
        self.0 & Self::WANT_LEAVE != 0
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacySeatV4 {
    player: Address,
    stack: u64,
    hand: Vec<LegacyCardV5>,
    bet: u64,
    total_bet: u64,
    status: SeatStatus,
    flags: LegacySeatFlagsV4,
    pk: ECPoint,
    pending_addon: u64,
    time_bank_ms: u64,
}

impl TryFrom<LegacySeatV4> for Seat {
    type Error = PokerL1Error;

    fn try_from(value: LegacySeatV4) -> Result<Self, Self::Error> {
        value.flags.validate()?;
        if (value.player == EMPTY_PLAYER) != (value.status == SeatStatus::Empty) {
            return Err(PokerL1Error::Serialization(
                "Texas v4 migration found player/status mismatch".into(),
            ));
        }
        if value.status == SeatStatus::Empty && value.flags.0 != 0 {
            return Err(PokerL1Error::Serialization(
                "Texas v4 migration found live flags on an empty seat".into(),
            ));
        }
        let seat = Seat {
            player: value.player,
            stack: value.stack,
            hand: migrate_hole_cards(value.hand, "Texas v4 seat hand")?,
            bet: value.bet,
            total_bet: value.total_bet,
            status: value.status,
            pk: value.pk,
            pending_addon: value.pending_addon,
            time_bank_ms: time_bank_u32(value.time_bank_ms, "v5 seat")?,
        };
        seat.validate_canonical()?;
        Ok(seat)
    }
}

/// Exact schema-v5 seat layout before fixed-capacity hole cards.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacySeatV5 {
    player: Address,
    stack: u64,
    hand: Vec<LegacyCardV5>,
    bet: u64,
    total_bet: u64,
    status: SeatStatus,
    pk: ECPoint,
    pending_addon: u64,
    time_bank_ms: u64,
}

impl TryFrom<LegacySeatV5> for Seat {
    type Error = PokerL1Error;

    fn try_from(value: LegacySeatV5) -> Result<Self, Self::Error> {
        let seat = Seat {
            player: value.player,
            stack: value.stack,
            hand: migrate_hole_cards(value.hand, "Texas v5 seat hand")?,
            bet: value.bet,
            total_bet: value.total_bet,
            status: value.status,
            pk: value.pk,
            pending_addon: value.pending_addon,
            time_bank_ms: time_bank_u32(value.time_bank_ms, "v5 seat")?,
        };
        seat.validate_canonical()?;
        Ok(seat)
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRunItTwiceStateV2 {
    active: bool,
    trigger_round: u8,
    shared_board_len: u8,
    second_board_cards: Vec<LegacyCardV5>,
}

/// Exact schema-v3-v5 RIT layout, including a duplicated shared board prefix.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRunItTwiceStateV5 {
    active: bool,
    shared_board_len: u8,
    second_board_cards: Vec<LegacyCardV5>,
}

/// Exact schema-v6-v12 seat layout before the bounded time bank moved to `u32`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacySeatV12 {
    player: Address,
    stack: u64,
    hand: HoleCards,
    bet: u64,
    total_bet: u64,
    status: SeatStatus,
    pk: ECPoint,
    pending_addon: u64,
    time_bank_ms: u64,
}

impl TryFrom<LegacySeatV12> for Seat {
    type Error = PokerL1Error;

    fn try_from(value: LegacySeatV12) -> Result<Self, Self::Error> {
        let seat = Seat {
            player: value.player,
            stack: value.stack,
            hand: value.hand,
            bet: value.bet,
            total_bet: value.total_bet,
            status: value.status,
            pk: value.pk,
            pending_addon: value.pending_addon,
            time_bank_ms: time_bank_u32(value.time_bank_ms, "v6-v12 seat")?,
        };
        seat.validate_canonical()?;
        Ok(seat)
    }
}

impl From<&Seat> for LegacySeatV12 {
    fn from(value: &Seat) -> Self {
        Self {
            player: value.player,
            stack: value.stack,
            hand: value.hand.clone(),
            bet: value.bet,
            total_bet: value.total_bet,
            status: value.status,
            pk: value.pk,
            pending_addon: value.pending_addon,
            time_bank_ms: u64::from(value.time_bank_ms),
        }
    }
}

#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
enum LegacyRunoutModeV12 {
    Single,
    Twice,
}

/// Exact schema-v6-v12 RIT layout before it became a payload-bearing enum.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRunItTwiceStateV12 {
    mode: LegacyRunoutModeV12,
    shared_board_len: u8,
    second_board_suffix: BoardCards,
}

impl LegacyRunItTwiceStateV12 {
    fn migrate(self, first_board: &BoardCards) -> PokerL1Result<RunItTwiceState> {
        let result = match self.mode {
            LegacyRunoutModeV12::Single => {
                if self.shared_board_len != 0 || !self.second_board_suffix.is_empty() {
                    return Err(PokerL1Error::Serialization(
                        "legacy single runout carries RIT payload".into(),
                    ));
                }
                RunItTwiceState::Single
            }
            LegacyRunoutModeV12::Twice => RunItTwiceState::Twice {
                start: RitStartStreet::from_shared_board_len(self.shared_board_len)?,
                second_board_suffix: self.second_board_suffix,
            },
        };
        result.validate_canonical(first_board)?;
        Ok(result)
    }
}

impl From<&RunItTwiceState> for LegacyRunItTwiceStateV12 {
    fn from(value: &RunItTwiceState) -> Self {
        match value {
            RunItTwiceState::Single => Self {
                mode: LegacyRunoutModeV12::Single,
                shared_board_len: 0,
                second_board_suffix: BoardCards::empty(),
            },
            RunItTwiceState::Twice {
                start,
                second_board_suffix,
            } => Self {
                mode: LegacyRunoutModeV12::Twice,
                shared_board_len: start.shared_board_len(),
                second_board_suffix: second_board_suffix.clone(),
            },
        }
    }
}

struct MigratedLegacyRunout {
    active: bool,
    shared_board_len: u8,
    second_board_cards: Vec<Card>,
}

fn migrate_legacy_runout(
    active: bool,
    shared_board_len: u8,
    second_board_cards: Vec<LegacyCardV5>,
) -> PokerL1Result<MigratedLegacyRunout> {
    let second_board_cards = second_board_cards
        .into_iter()
        .map(Card::try_from)
        .collect::<PokerL1Result<Vec<_>>>()?;
    if !active && (shared_board_len != 0 || !second_board_cards.is_empty()) {
        return Err(PokerL1Error::Serialization(
            "legacy inactive RIT state carries board data".into(),
        ));
    }
    if active
        && (!matches!(shared_board_len, 0 | 3 | 4)
            || second_board_cards.len() > 5
            || second_board_cards.len() < usize::from(shared_board_len))
    {
        return Err(PokerL1Error::Serialization(
            "legacy active RIT state has non-canonical board bounds".into(),
        ));
    }
    Ok(MigratedLegacyRunout {
        active,
        shared_board_len,
        second_board_cards,
    })
}

fn finalize_legacy_runout(
    value: MigratedLegacyRunout,
    first_board: &BoardCards,
) -> PokerL1Result<RunItTwiceState> {
    if !value.active {
        return Ok(RunItTwiceState::default());
    }
    let shared = usize::from(value.shared_board_len);
    if first_board.len() < shared || value.second_board_cards[..shared] != first_board[..shared] {
        return Err(PokerL1Error::Serialization(
            "legacy RIT boards disagree on their shared prefix".into(),
        ));
    }
    let suffix =
        BoardCards::try_from(value.second_board_cards[shared..].to_vec()).map_err(|error| {
            PokerL1Error::Serialization(format!("legacy RIT second-board suffix: {error}"))
        })?;
    let result = RunItTwiceState::Twice {
        start: RitStartStreet::from_shared_board_len(value.shared_board_len)?,
        second_board_suffix: suffix,
    };
    result.validate_canonical(first_board)?;
    Ok(result)
}

impl LegacyRunItTwiceStateV2 {
    fn migrate(self) -> PokerL1Result<MigratedLegacyRunout> {
        use super::constants::{ROUND_FLOP, ROUND_PREFLOP, ROUND_TURN, ROUND_WAITING};

        let valid = if self.active {
            matches!(
                (self.trigger_round, self.shared_board_len),
                (ROUND_PREFLOP, 0) | (ROUND_FLOP, 3) | (ROUND_TURN, 4)
            )
        } else {
            self.trigger_round == ROUND_WAITING
                && self.shared_board_len == 0
                && self.second_board_cards.is_empty()
        };
        if !valid {
            return Err(PokerL1Error::Serialization(
                "Texas v2 migration found a non-canonical RIT trigger".into(),
            ));
        }
        migrate_legacy_runout(self.active, self.shared_board_len, self.second_board_cards)
    }
}

impl LegacyRunItTwiceStateV5 {
    fn migrate(self) -> PokerL1Result<MigratedLegacyRunout> {
        migrate_legacy_runout(self.active, self.shared_board_len, self.second_board_cards)
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTimestampsV2 {
    ready_at: u64,
    shuffle_started_at: u64,
    reveal_started_at: u64,
    betting_started_at: u64,
    reconstruct_started_at: u64,
    showdown_at: u64,
    hand_complete_at: u64,
}

impl From<LegacyTimestampsV2> for Timestamps {
    fn from(value: LegacyTimestampsV2) -> Self {
        Self {
            shuffle_started_at: value.shuffle_started_at,
            reveal_started_at: value.reveal_started_at,
            betting_started_at: value.betting_started_at,
            reconstruct_started_at: value.reconstruct_started_at,
            showdown_at: value.showdown_at,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyDecryptedCardV8 {
    encrypted_card_index: u8,
    owner_seat_index: u8,
    ciphertext: Option<ElGamalCiphertext>,
    plaintext: Option<ECPoint>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyDeckStateV8 {
    encrypted: Vec<ElGamalCiphertext>,
    aggregated_pk: Option<ECPoint>,
    cards_dealt: u8,
    decrypted_cards: Vec<LegacyDecryptedCardV8>,
}

/// Exact schema-v9 deck layout: typed reveal ledger, but no contributor lineage yet.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyDeckStateV9 {
    encrypted: Vec<ElGamalCiphertext>,
    aggregated_pk: Option<ECPoint>,
    cards_dealt: u8,
    decrypted_cards: Vec<super::types::DecryptedCard>,
}

/// Canonical schema-v10 deck encoding. The aggregate key is derived after decode.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct PersistedDeckStateV10 {
    encrypted: Vec<ElGamalCiphertext>,
    contributor_mask: SeatMask,
    cards_dealt: u8,
    decrypted_cards: Vec<super::types::DecryptedCard>,
}

fn migrate_deck_state(value: LegacyDeckStateV8, max_players: u8) -> PokerL1Result<DeckState> {
    if max_players > super::types::MAX_SEATS {
        return Err(PokerL1Error::Serialization(
            "Texas legacy deck max_players exceeds mask capacity".into(),
        ));
    }
    let mut decrypted_cards = Vec::with_capacity(value.decrypted_cards.len());
    for record in value.decrypted_cards {
        if record.encrypted_card_index >= 52 {
            return Err(PokerL1Error::Serialization(format!(
                "Texas legacy reveal ledger deck index {} is out of range",
                record.encrypted_card_index
            )));
        }
        if record.owner_seat_index != super::types::OWNER_SEAT_PUBLIC
            && record.owner_seat_index >= max_players
        {
            return Err(PokerL1Error::Serialization(format!(
                "Texas legacy reveal ledger owner {} is out of range",
                record.owner_seat_index
            )));
        }
        let state = match (record.ciphertext, record.plaintext) {
            (Some(ciphertext), None) => super::types::DecryptedCardState::Partial { ciphertext },
            (None, Some(plaintext)) => super::types::DecryptedCardState::Plaintext { plaintext },
            (None, None) => continue,
            (Some(_), Some(_)) => {
                return Err(PokerL1Error::Serialization(
                    "Texas legacy reveal ledger contains ciphertext and plaintext together".into(),
                ));
            }
        };
        if decrypted_cards
            .iter()
            .any(|prior: &super::types::DecryptedCard| {
                prior.encrypted_card_index == record.encrypted_card_index
                    && prior.owner_seat_index == record.owner_seat_index
            })
        {
            return Err(PokerL1Error::Serialization(
                "Texas legacy reveal ledger contains duplicate lineage".into(),
            ));
        }
        decrypted_cards.push(super::types::DecryptedCard {
            encrypted_card_index: record.encrypted_card_index,
            owner_seat_index: record.owner_seat_index,
            state,
        });
    }
    Ok(DeckState {
        encrypted: value.encrypted,
        aggregated_pk: value.aggregated_pk,
        contributor_mask: 0,
        cards_dealt: value.cards_dealt,
        decrypted_cards,
    })
}

fn aggregate_pk_for_mask(
    seats: &[Seat],
    max_players: u8,
    mask: SeatMask,
) -> PokerL1Result<Option<ECPoint>> {
    if !super::types::seat_mask_is_canonical(mask, max_players)
        || seats.len() != usize::from(max_players)
    {
        return Err(PokerL1Error::Serialization(
            "Texas contributor mask/seat layout is not canonical".into(),
        ));
    }
    let mut aggregate: Option<ECPoint> = None;
    for seat_index in 0..max_players {
        if !seat_mask_contains(mask, seat_index) {
            continue;
        }
        let seat = &seats[usize::from(seat_index)];
        if !seat.is_occupied() || super::utils::g1_is_identity(&seat.pk.0) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas contributor seat {seat_index} is not a live non-identity key"
            )));
        }
        aggregate = Some(match aggregate {
            None => seat.pk,
            Some(current) => ECPoint::from(super::utils::g1_add(&current.0, &seat.pk.0)),
        });
    }
    if aggregate
        .as_ref()
        .is_some_and(|point| super::utils::g1_is_identity(&point.0))
    {
        return Err(PokerL1Error::Serialization(
            "Texas contributor aggregate cannot be identity".into(),
        ));
    }
    Ok(aggregate)
}

fn infer_legacy_contributor_mask(
    aggregated_pk: Option<ECPoint>,
    seats: &[Seat],
    max_players: u8,
) -> PokerL1Result<SeatMask> {
    let Some(target) = aggregated_pk else {
        return Ok(0);
    };
    if super::utils::g1_is_identity(&target.0) {
        return Err(PokerL1Error::Serialization(
            "Texas legacy aggregate pk is identity".into(),
        ));
    }
    let limit = 1u16 << max_players;
    let mut matched = None;
    for mask in 1..limit {
        let Ok(candidate) = aggregate_pk_for_mask(seats, max_players, mask) else {
            continue;
        };
        if candidate.as_ref().is_some_and(|point| point == &target) {
            if matched.is_some() {
                return Err(PokerL1Error::Serialization(
                    "Texas legacy aggregate pk has ambiguous contributor lineage".into(),
                ));
            }
            matched = Some(mask);
        }
    }
    matched.ok_or_else(|| {
        PokerL1Error::Serialization(
            "Texas legacy aggregate pk cannot be derived from occupied seat keys".into(),
        )
    })
}

fn attach_legacy_contributor_mask(
    deck_state: &mut DeckState,
    seats: &[Seat],
    max_players: u8,
) -> PokerL1Result<()> {
    deck_state.contributor_mask =
        infer_legacy_contributor_mask(deck_state.aggregated_pk, seats, max_players)?;
    Ok(())
}

fn restore_deck_state_v10(
    value: PersistedDeckStateV10,
    seats: &[Seat],
    max_players: u8,
) -> PokerL1Result<DeckState> {
    let aggregated_pk = aggregate_pk_for_mask(seats, max_players, value.contributor_mask)?;
    Ok(DeckState {
        encrypted: value.encrypted,
        aggregated_pk,
        contributor_mask: value.contributor_mask,
        cards_dealt: value.cards_dealt,
        decrypted_cards: value.decrypted_cards,
    })
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyDeckStateV2 {
    encrypted: Vec<ElGamalCiphertext>,
    aggregated_pk: Option<ECPoint>,
    plaintext: Vec<ECPoint>,
    cards_dealt: u8,
    decrypted_cards: Vec<LegacyDecryptedCardV8>,
}

impl TryFrom<LegacyDeckStateV2> for DeckState {
    type Error = PokerL1Error;

    fn try_from(value: LegacyDeckStateV2) -> Result<Self, Self::Error> {
        let canonical = generate_plaintext_cards();
        if value.plaintext.len() != canonical.len()
            || value
                .plaintext
                .iter()
                .zip(canonical)
                .any(|(stored, expected)| stored.0 != expected)
        {
            return Err(PokerL1Error::Serialization(
                "Texas v2 migration found a non-canonical plaintext deck".into(),
            ));
        }
        migrate_deck_state(
            LegacyDeckStateV8 {
                encrypted: value.encrypted,
                aggregated_pk: value.aggregated_pk,
                cards_dealt: value.cards_dealt,
                decrypted_cards: value.decrypted_cards,
            },
            super::types::MAX_SEATS,
        )
    }
}

fn migrate_bool_seats(
    seats: Vec<LegacySeatV2>,
    max_players: u8,
) -> PokerL1Result<(Vec<Seat>, SeatMask, SeatMask)> {
    if seats.len() != usize::from(max_players) {
        return Err(PokerL1Error::Serialization(format!(
            "legacy Texas seat length {} does not match max_players {max_players}",
            seats.len()
        )));
    }
    let mut acted_mask = 0;
    let mut leave_after_hand_mask = 0;
    let mut migrated = Vec::with_capacity(seats.len());
    for (index, seat) in seats.into_iter().enumerate() {
        if seat.acted_this_round {
            acted_mask |= 1u16 << index;
        }
        if seat.want_leave {
            leave_after_hand_mask |= 1u16 << index;
        }
        migrated.push(Seat::try_from(seat)?);
    }
    Ok((migrated, acted_mask, leave_after_hand_mask))
}

fn migrate_v4_seats(
    seats: Vec<LegacySeatV4>,
    max_players: u8,
) -> PokerL1Result<(Vec<Seat>, SeatMask, SeatMask)> {
    if seats.len() != usize::from(max_players) {
        return Err(PokerL1Error::Serialization(format!(
            "Texas v4 seat length {} does not match max_players {max_players}",
            seats.len()
        )));
    }
    let mut acted_mask = 0;
    let mut leave_after_hand_mask = 0;
    let mut migrated = Vec::with_capacity(seats.len());
    for (index, seat) in seats.into_iter().enumerate() {
        if seat.flags.acted() {
            acted_mask |= 1u16 << index;
        }
        if seat.flags.wants_leave() {
            leave_after_hand_mask |= 1u16 << index;
        }
        migrated.push(Seat::try_from(seat)?);
    }
    Ok((migrated, acted_mask, leave_after_hand_mask))
}

fn migrate_current_turn(
    current_turn: Option<u8>,
    max_players: u8,
    label: &str,
) -> PokerL1Result<u8> {
    match current_turn {
        Some(seat) if seat >= max_players => Err(PokerL1Error::Serialization(format!(
            "{label}: current turn {seat} outside max_players {max_players}"
        ))),
        Some(seat) => Ok(seat),
        None => Ok(NO_SEAT),
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTexasPokerTableV2 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV2>,
    button: u8,
    pot: u64,
    side_pots: Vec<SidePot>,
    community_cards: Vec<LegacyCardV5>,
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: Option<u8>,
    deck_state: LegacyDeckStateV2,
    shuffle_state: LegacyShuffleStateV4,
    reveal_token_state: LegacyRevealTokenStateV4,
    reconstruct_state: LegacyReconstructStateV4,
    timeout_config: LegacyTimeoutConfigV6,
    timestamps: LegacyTimestampsV2,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV2,
    config: LegacyTableConfigV2,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v3 table layout. Only `Seat` changed between v3 and v4.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTexasPokerTableV3 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV3>,
    button: u8,
    pot: u64,
    community_cards: Vec<LegacyCardV5>,
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: Option<u8>,
    deck_state: LegacyDeckStateV8,
    shuffle_state: LegacyShuffleStateV4,
    reveal_token_state: LegacyRevealTokenStateV4,
    reconstruct_state: LegacyReconstructStateV4,
    timeout_config: LegacyTimeoutConfigV6,
    timestamps: Timestamps,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV5,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v4 layout, before seat flags and protocol seat vectors moved to table masks.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTexasPokerTableV4 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV4>,
    button: u8,
    pot: u64,
    community_cards: Vec<LegacyCardV5>,
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: Option<u8>,
    deck_state: LegacyDeckStateV8,
    shuffle_state: LegacyShuffleStateV4,
    reveal_token_state: LegacyRevealTokenStateV4,
    reconstruct_state: LegacyReconstructStateV4,
    timeout_config: LegacyTimeoutConfigV6,
    timestamps: Timestamps,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV5,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v5 layout before canonical CardId/fixed-card containers/RIT suffix storage.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTexasPokerTableV5 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV5>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: Vec<LegacyCardV5>,
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: u8,
    deck_state: LegacyDeckStateV8,
    shuffle_state: LegacyShuffleStateV11,
    reveal_token_state: RevealTokenState,
    reconstruct_state: LegacyReconstructStateV6,
    timeout_config: LegacyTimeoutConfigV6,
    timestamps: Timestamps,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV5,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v6 layout before phase/timestamp state moved into a persisted tagged union.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyTexasPokerTableV6 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: u8,
    deck_state: LegacyDeckStateV8,
    shuffle_state: LegacyShuffleStateV11,
    reveal_token_state: RevealTokenState,
    reconstruct_state: LegacyReconstructStateV6,
    timeout_config: LegacyTimeoutConfigV6,
    timestamps: Timestamps,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Canonical timeout rules. Ready/hand-complete timers were never read by production.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
struct PersistedTimeoutConfigV7 {
    shuffle_timeout_ms: u32,
    reveal_timeout_ms: u32,
    betting_timeout_ms: u32,
    reconstruct_timeout_ms: u32,
    showdown_display_ms: u32,
}

/// Exact timeout layout persisted by schemas v2-v6.
#[derive(Debug, Clone, Copy, BorshSerialize, BorshDeserialize)]
struct LegacyTimeoutConfigV6 {
    shuffle_timeout_ms: u64,
    reveal_timeout_ms: u64,
    betting_timeout_ms: u64,
    reconstruct_timeout_ms: u64,
    showdown_display_ms: u64,
    hand_complete_wait_ms: u64,
    ready_wait_ms: u64,
}

/// Canonical schema-v14 table encoding.
///
/// The runtime table temporarily retains schema-v6 phase fields as compatibility caches while
/// call sites are migrated. They are deliberately absent here: persisted state, state roots and
/// nested prove tasks bind only this single tagged phase representation.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct PersistedTexasPokerTableV14 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<Seat>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: HandPhase,
    deck_state: PersistedDeckStateV10,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u16,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: RunItTwiceState,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v13 hand phase before shuffle purpose became a second-level tagged union.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LegacyHandPhaseV13 {
    Waiting,
    Shuffling {
        purpose: ShufflingPurpose,
        street: u8,
        state: ShuffleState,
        suspended_reveal: Option<RevealTokenState>,
        deadline_ms: u64,
    },
    Revealing {
        street: u8,
        state: RevealTokenState,
        deadline_ms: u64,
    },
    Reconstructing {
        street: u8,
        state: ReconstructState,
        suspended_reveal: RevealTokenState,
        epoch_ms: u64,
        deadline_ms: u64,
    },
    Betting {
        street: u8,
        round: BettingRound,
        current_turn: u8,
        deadline_ms: u64,
    },
    ShowdownDisplay {
        deadline_ms: u64,
    },
}

/// Exact schema-v13 table before the type-safe shuffle sub-union.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV13 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<Seat>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV13,
    deck_state: PersistedDeckStateV10,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u16,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: RunItTwiceState,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v12 table before bounded seat time banks, bounded rake bps and tagged RIT.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV12 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV13,
    deck_state: PersistedDeckStateV10,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v11 outer table before shuffle purpose moved into the outer union and the
/// reconstruction-v1 phase/coefficient fields were removed.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV11 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV11,
    deck_state: PersistedDeckStateV10,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

// Schema v7 persisted the same outer table shape, but its `HandPhase` carried the old flattened
// reveal assignment (`runout_index`, `board_position`, `pending_mask`, token seat tags and a
// `decrypted` bool). Keep an exact mirror so a v7 object can never be decoded as v8 by accident.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealTokenDataV7 {
    seat_index: u8,
    token: ECPoint,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealAssignmentV7 {
    encrypted_card_index: u8,
    runout_index: u8,
    board_position: u8,
    pending_mask: SeatMask,
    reveal_tokens: Vec<LegacyRevealTokenDataV7>,
    decrypted: bool,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyRevealTokenStateV7 {
    reveal_phase: u8,
    assignments: Vec<LegacyRevealAssignmentV7>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LegacyHandPhaseV11 {
    Waiting,
    Shuffling {
        street: u8,
        state: LegacyShuffleStateV11,
        suspended_reveal: Option<RevealTokenState>,
        deadline_ms: u64,
    },
    Revealing {
        street: u8,
        state: RevealTokenState,
        deadline_ms: u64,
    },
    Reconstructing {
        street: u8,
        state: LegacyReconstructStateV11,
        suspended_reveal: RevealTokenState,
        epoch_ms: u64,
        deadline_ms: u64,
    },
    Betting {
        street: u8,
        round: BettingRound,
        current_turn: u8,
        deadline_ms: u64,
    },
    ShowdownDisplay {
        deadline_ms: u64,
    },
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LegacyHandPhaseV10 {
    Waiting,
    Shuffling {
        street: u8,
        state: LegacyShuffleStateV10,
        suspended_reveal: Option<RevealTokenState>,
        deadline_ms: u64,
    },
    Revealing {
        street: u8,
        state: RevealTokenState,
        deadline_ms: u64,
    },
    Reconstructing {
        street: u8,
        state: LegacyReconstructStateV11,
        suspended_reveal: RevealTokenState,
        epoch_ms: u64,
        deadline_ms: u64,
    },
    Betting {
        street: u8,
        round: BettingRound,
        current_turn: u8,
        deadline_ms: u64,
    },
    ShowdownDisplay {
        deadline_ms: u64,
    },
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LegacyHandPhaseV7 {
    Waiting,
    Shuffling {
        street: u8,
        state: LegacyShuffleStateV10,
        suspended_reveal: Option<LegacyRevealTokenStateV7>,
        deadline_ms: u64,
    },
    Revealing {
        street: u8,
        state: LegacyRevealTokenStateV7,
        deadline_ms: u64,
    },
    Reconstructing {
        street: u8,
        state: LegacyReconstructStateV11,
        suspended_reveal: LegacyRevealTokenStateV7,
        epoch_ms: u64,
        deadline_ms: u64,
    },
    Betting {
        street: u8,
        round: BettingRound,
        current_turn: u8,
        deadline_ms: u64,
    },
    ShowdownDisplay {
        deadline_ms: u64,
    },
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV7 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV7,
    deck_state: LegacyDeckStateV8,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

// Kept as a source-compatible name for older codec fixtures. It denotes the current canonical
// encoding; actual schema-v7 bytes use `LegacyPersistedTexasPokerTableV7` above.
#[cfg(test)]
type PersistedTexasPokerTableV7 = PersistedTexasPokerTableV14;

/// Exact schema-v10 mirror. It is identical to v11 except the shuffle actor was persisted.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV10 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV10,
    deck_state: PersistedDeckStateV10,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v8 mirror. Its deck ledger still used two independent `Option` payloads.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV8 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV10,
    deck_state: LegacyDeckStateV8,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

/// Exact schema-v9 mirror. The reveal ledger was typed, but aggregate lineage was implicit.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct LegacyPersistedTexasPokerTableV9 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    seats: Vec<LegacySeatV12>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: LegacyHandPhaseV10,
    deck_state: LegacyDeckStateV9,
    timeout_config: PersistedTimeoutConfigV7,
    chip_pool: u64,
    addon_pool: u64,
    ante_mode: u8,
    ante_amount: u64,
    ante_collected: u64,
    rake_mode: u8,
    rake_bps: u64,
    rake_cap: u64,
    rake_collected: u64,
    rit_mode: u8,
    run_it_twice_state: LegacyRunItTwiceStateV12,
    hand_id: u32,
    call_seq: u32,
    version: u64,
}

fn timeout_u32(value: u64, label: &str) -> PokerL1Result<u32> {
    u32::try_from(value).map_err(|_| {
        PokerL1Error::Serialization(format!(
            "Texas {label} timeout {value} exceeds canonical u32 range"
        ))
    })
}

impl TryFrom<TimeoutConfig> for PersistedTimeoutConfigV7 {
    type Error = PokerL1Error;

    fn try_from(value: TimeoutConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            shuffle_timeout_ms: value.shuffle_timeout_ms,
            reveal_timeout_ms: value.reveal_timeout_ms,
            betting_timeout_ms: value.betting_timeout_ms,
            reconstruct_timeout_ms: value.reconstruct_timeout_ms,
            showdown_display_ms: value.showdown_display_ms,
        })
    }
}

impl From<PersistedTimeoutConfigV7> for TimeoutConfig {
    fn from(value: PersistedTimeoutConfigV7) -> Self {
        Self {
            shuffle_timeout_ms: value.shuffle_timeout_ms,
            reveal_timeout_ms: value.reveal_timeout_ms,
            betting_timeout_ms: value.betting_timeout_ms,
            reconstruct_timeout_ms: value.reconstruct_timeout_ms,
            showdown_display_ms: value.showdown_display_ms,
        }
    }
}

impl TryFrom<LegacyTimeoutConfigV6> for TimeoutConfig {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTimeoutConfigV6) -> Result<Self, Self::Error> {
        Ok(Self {
            shuffle_timeout_ms: timeout_u32(value.shuffle_timeout_ms, "shuffle")?,
            reveal_timeout_ms: timeout_u32(value.reveal_timeout_ms, "reveal")?,
            betting_timeout_ms: timeout_u32(value.betting_timeout_ms, "betting")?,
            reconstruct_timeout_ms: timeout_u32(value.reconstruct_timeout_ms, "reconstruct")?,
            showdown_display_ms: timeout_u32(value.showdown_display_ms, "showdown display")?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn collapse_legacy_hand_phase(
    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: u8,
    shuffle_state: (u8, ShuffleState),
    reveal_token_state: RevealTokenState,
    reconstruct_state: (u8, ReconstructState),
    timeout: TimeoutConfig,
    timestamps: Timestamps,
) -> PokerL1Result<HandPhase> {
    let deadline_from_started_at = |started_at: u64, timeout_ms: u32, label: &str| {
        if started_at == 0 {
            Ok(0)
        } else {
            started_at
                .checked_add(u64::from(timeout_ms))
                .ok_or_else(|| {
                    PokerL1Error::Serialization(format!(
                        "Texas legacy {label} start plus timeout overflows u64"
                    ))
                })
        }
    };
    let (shuffle_phase, shuffle_state) = shuffle_state;
    let (reconstruct_phase, reconstruct_state) = reconstruct_state;
    let reconstruct_active = reconstruct_phase != super::constants::RECONSTRUCT_PHASE_NONE;
    let shuffle_active = shuffle_phase != super::constants::SHUFFLE_PHASE_NONE;
    let reveal_active = reveal_token_state.reveal_phase != super::constants::REVEAL_PHASE_NONE;
    let betting_active = betting_round.is_some();

    if reconstruct_active {
        validate_active_reconstruct_state(reconstruct_phase, &reconstruct_state)?;
        if shuffle_active || betting_active || !reveal_active {
            return Err(PokerL1Error::Serialization(
                "Texas legacy reconstruct phase has an invalid active-phase combination".into(),
            ));
        }
        let epoch_ms = timestamps.reconstruct_started_at;
        return Ok(HandPhase::Reconstructing {
            street: round_state,
            state: reconstruct_state,
            suspended_reveal: reveal_token_state,
            epoch_ms,
            deadline_ms: deadline_from_started_at(
                epoch_ms,
                timeout.reconstruct_timeout_ms,
                "reconstruct",
            )?,
        });
    }
    if shuffle_active {
        if betting_active
            || (reveal_active && shuffle_phase != super::constants::SHUFFLE_PHASE_RECONSTRUCT)
        {
            return Err(PokerL1Error::Serialization(
                "Texas legacy shuffle phase has an invalid active-phase combination".into(),
            ));
        }
        let purpose = migrate_shuffling_purpose(shuffle_phase, round_state, reveal_active)?;
        return migrate_shuffling_phase(
            purpose,
            round_state,
            shuffle_state,
            reveal_active.then_some(reveal_token_state),
            deadline_from_started_at(
                timestamps.shuffle_started_at,
                timeout.shuffle_timeout_ms,
                "shuffle",
            )?,
        );
    }
    if reveal_active {
        if betting_active {
            return Err(PokerL1Error::Serialization(
                "Texas legacy reveal and betting phases overlap".into(),
            ));
        }
        return Ok(HandPhase::Revealing {
            street: round_state,
            state: reveal_token_state,
            deadline_ms: deadline_from_started_at(
                timestamps.reveal_started_at,
                timeout.reveal_timeout_ms,
                "reveal",
            )?,
        });
    }
    if let Some(round) = betting_round {
        return Ok(HandPhase::Betting {
            street: round_state,
            round,
            current_turn,
            deadline_ms: deadline_from_started_at(
                timestamps.betting_started_at,
                timeout.betting_timeout_ms,
                "betting",
            )?,
        });
    }
    match round_state {
        super::constants::ROUND_WAITING => Ok(HandPhase::Waiting),
        super::constants::ROUND_SHOWDOWN => Ok(HandPhase::ShowdownDisplay {
            deadline_ms: timestamps.showdown_at,
        }),
        round => Err(PokerL1Error::Serialization(format!(
            "Texas legacy live/unknown round {round} has no active phase"
        ))),
    }
}

impl TryFrom<&TexasPokerTable> for PersistedTexasPokerTableV14 {
    type Error = PokerL1Error;

    fn try_from(value: &TexasPokerTable) -> Result<Self, Self::Error> {
        value.validate_state_schema()?;
        Ok(Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name.clone(),
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats: value.seats.clone(),
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards.clone(),
            hand_phase: value.canonical_hand_phase()?,
            deck_state: PersistedDeckStateV10 {
                encrypted: value.deck_state.encrypted.clone(),
                contributor_mask: value.deck_state.contributor_mask,
                cards_dealt: value.deck_state.cards_dealt,
                decrypted_cards: value.deck_state.decrypted_cards.clone(),
            },
            timeout_config: value.timeout_config.try_into()?,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: value.rake_bps,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state: value.run_it_twice_state.clone(),
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        })
    }
}

impl TryFrom<PersistedTexasPokerTableV14> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: PersistedTexasPokerTableV14) -> Result<Self, Self::Error> {
        if value.state_schema_version != TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported canonical Texas schema {}",
                value.state_schema_version
            )));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let deck_state = restore_deck_state_v10(value.deck_state, &value.seats, value.max_players)?;
        let hand_phase = value.hand_phase;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats: value.seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: value.rake_bps,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state: value.run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV13> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV13) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V13_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let deck_state = restore_deck_state_v10(value.deck_state, &value.seats, value.max_players)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats: value.seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase: migrate_hand_phase_v13(value.hand_phase)?,
            deck_state,
            timeout_config: value.timeout_config.into(),
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: value.rake_bps,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state: value.run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

fn migrate_legacy_seats_v12(values: Vec<LegacySeatV12>) -> PokerL1Result<Vec<Seat>> {
    values.into_iter().map(Seat::try_from).collect()
}

impl TryFrom<LegacyPersistedTexasPokerTableV12> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV12) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V12_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let seats = migrate_legacy_seats_v12(value.seats)?;
        let deck_state = restore_deck_state_v10(value.deck_state, &seats, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase: migrate_hand_phase_v13(value.hand_phase)?,
            deck_state,
            timeout_config: value.timeout_config.into(),
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v12")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV11> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV11) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V11_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let seats = migrate_legacy_seats_v12(value.seats)?;
        let deck_state = restore_deck_state_v10(value.deck_state, &seats, value.max_players)?;
        let hand_phase = migrate_hand_phase_v11(value.hand_phase, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v11")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV10> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV10) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V10_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let seats = migrate_legacy_seats_v12(value.seats)?;
        let deck_state = restore_deck_state_v10(value.deck_state, &seats, value.max_players)?;
        let hand_phase = migrate_hand_phase_v10(value.hand_phase, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v10")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV7> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV7) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V7_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        if value.max_players > super::types::MAX_SEATS
            || value.seats.len() != usize::from(value.max_players)
        {
            return Err(PokerL1Error::Serialization(
                "Texas v7 seat capacity/length is not canonical".into(),
            ));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let hand_phase = migrate_hand_phase_v7(value.hand_phase, value.max_players)?;
        let mut deck_state = migrate_deck_state(value.deck_state, value.max_players)?;
        let seats = migrate_legacy_seats_v12(value.seats)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v7")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV9> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV9) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V9_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let mut deck_state = DeckState {
            encrypted: value.deck_state.encrypted,
            aggregated_pk: value.deck_state.aggregated_pk,
            contributor_mask: 0,
            cards_dealt: value.deck_state.cards_dealt,
            decrypted_cards: value.deck_state.decrypted_cards,
        };
        let seats = migrate_legacy_seats_v12(value.seats)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, value.max_players)?;
        let hand_phase = migrate_hand_phase_v10(value.hand_phase, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v9")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyPersistedTexasPokerTableV8> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyPersistedTexasPokerTableV8) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V8_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let timeout_config: TimeoutConfig = value.timeout_config.into();
        let mut deck_state = migrate_deck_state(value.deck_state, value.max_players)?;
        let seats = migrate_legacy_seats_v12(value.seats)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, value.max_players)?;
        let hand_phase = migrate_hand_phase_v10(value.hand_phase, value.max_players)?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v8")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl BorshSerialize for TexasPokerTable {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let persisted = PersistedTexasPokerTableV14::try_from(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        persisted.serialize(writer)
    }
}

impl BorshDeserialize for TexasPokerTable {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let persisted = PersistedTexasPokerTableV14::deserialize_reader(reader)?;
        persisted.try_into().map_err(|error: PokerL1Error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })
    }
}

impl TryFrom<LegacyTexasPokerTableV6> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTexasPokerTableV6) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V6_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        // Canonicalize legacy timeout state immediately. Schema v7 persists only the five
        // production timers as u32 values; the unused ready/hand-complete timers must not leak
        // into the migrated runtime object before its first re-serialization.
        let timeout_config = TimeoutConfig::try_from(value.timeout_config)?;
        let mut deck_state = migrate_deck_state(value.deck_state, value.max_players)?;
        let seats = migrate_legacy_seats_v12(value.seats)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, value.max_players)?;
        let reconstruct_state = migrate_reconstruct_accumulator(
            value.reconstruct_state.clone(),
            value.max_players,
            &deck_state,
        )?;
        let hand_phase = collapse_legacy_hand_phase(
            value.round_state,
            value.betting_round,
            value.current_turn,
            migrate_shuffle_state_v11(value.shuffle_state, value.max_players)?,
            value.reveal_token_state,
            reconstruct_state,
            timeout_config,
            value.timestamps,
        )?;
        let run_it_twice_state = value.run_it_twice_state.migrate(&value.community_cards)?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v6")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyTexasPokerTableV5> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTexasPokerTableV5) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V5_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        if value.seats.len() != usize::from(value.max_players) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas v5 seat length {} does not match max_players {}",
                value.seats.len(),
                value.max_players
            )));
        }
        let community_cards = migrate_board_cards(value.community_cards, "Texas v5 first board")?;
        let run_it_twice_state =
            finalize_legacy_runout(value.run_it_twice_state.migrate()?, &community_cards)?;
        let seats = value
            .seats
            .into_iter()
            .map(Seat::try_from)
            .collect::<PokerL1Result<Vec<_>>>()?;
        let mut deck_state = migrate_deck_state(value.deck_state, value.max_players)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, value.max_players)?;
        let reconstruct_state = migrate_reconstruct_accumulator(
            value.reconstruct_state.clone(),
            value.max_players,
            &deck_state,
        )?;
        let timeout_config = TimeoutConfig::try_from(value.timeout_config)?;
        let hand_phase = collapse_legacy_hand_phase(
            value.round_state,
            value.betting_round,
            value.current_turn,
            migrate_shuffle_state_v11(value.shuffle_state, value.max_players)?,
            value.reveal_token_state,
            reconstruct_state,
            timeout_config,
            value.timestamps,
        )?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v5")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyTexasPokerTableV4> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTexasPokerTableV4) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V4_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let max_players = value.max_players;
        let (seats, acted_mask, leave_after_hand_mask) =
            migrate_v4_seats(value.seats, max_players)?;
        let current_turn =
            migrate_current_turn(value.current_turn, max_players, "Texas v4 migration")?;
        let shuffle_state = migrate_shuffle_state(value.shuffle_state, max_players)?;
        let reveal_token_state = migrate_reveal_state(value.reveal_token_state, max_players)?;
        let mut deck_state = migrate_deck_state(value.deck_state, max_players)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, max_players)?;
        let reconstruct_state =
            migrate_reconstruct_state(value.reconstruct_state, max_players, &deck_state)?;
        let community_cards = migrate_board_cards(value.community_cards, "Texas v4 first board")?;
        let run_it_twice_state =
            finalize_legacy_runout(value.run_it_twice_state.migrate()?, &community_cards)?;
        let timeout_config = TimeoutConfig::try_from(value.timeout_config)?;
        let hand_phase = collapse_legacy_hand_phase(
            value.round_state,
            value.betting_round,
            current_turn,
            shuffle_state,
            reveal_token_state,
            reconstruct_state,
            timeout_config,
            value.timestamps,
        )?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask,
            leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v4")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyTexasPokerTableV3> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTexasPokerTableV3) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V3_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let max_players = value.max_players;
        let legacy_seats = value.seats.into_iter().map(LegacySeatV2::from).collect();
        let (seats, acted_mask, leave_after_hand_mask) =
            migrate_bool_seats(legacy_seats, max_players)?;
        let current_turn =
            migrate_current_turn(value.current_turn, max_players, "Texas v3 migration")?;
        let shuffle_state = migrate_shuffle_state(value.shuffle_state, max_players)?;
        let reveal_token_state = migrate_reveal_state(value.reveal_token_state, max_players)?;
        let mut deck_state = migrate_deck_state(value.deck_state, max_players)?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, max_players)?;
        let reconstruct_state =
            migrate_reconstruct_state(value.reconstruct_state, max_players, &deck_state)?;
        let community_cards = migrate_board_cards(value.community_cards, "Texas v3 first board")?;
        let run_it_twice_state =
            finalize_legacy_runout(value.run_it_twice_state.migrate()?, &community_cards)?;
        let timeout_config = TimeoutConfig::try_from(value.timeout_config)?;
        let hand_phase = collapse_legacy_hand_phase(
            value.round_state,
            value.betting_round,
            current_turn,
            shuffle_state,
            reveal_token_state,
            reconstruct_state,
            timeout_config,
            value.timestamps,
        )?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask,
            leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v3")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

impl TryFrom<LegacyTexasPokerTableV2> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: LegacyTexasPokerTableV2) -> Result<Self, Self::Error> {
        if value.state_schema_version != LEGACY_V2_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported legacy Texas schema {}",
                value.state_schema_version
            )));
        }
        let max_players = value.max_players;
        let (seats, acted_mask, leave_after_hand_mask) =
            migrate_bool_seats(value.seats, max_players)?;
        let current_turn =
            migrate_current_turn(value.current_turn, max_players, "Texas v2 migration")?;
        let shuffle_state = migrate_shuffle_state(value.shuffle_state, max_players)?;
        let reveal_token_state = migrate_reveal_state(value.reveal_token_state, max_players)?;
        let mut deck_state: DeckState = value.deck_state.try_into()?;
        attach_legacy_contributor_mask(&mut deck_state, &seats, max_players)?;
        let reconstruct_state =
            migrate_reconstruct_state(value.reconstruct_state, max_players, &deck_state)?;
        let community_cards = migrate_board_cards(value.community_cards, "Texas v2 first board")?;
        let run_it_twice_state =
            finalize_legacy_runout(value.run_it_twice_state.migrate()?, &community_cards)?;
        let timeout_config = TimeoutConfig::try_from(value.timeout_config)?;
        let timestamps: Timestamps = value.timestamps.into();
        let hand_phase = collapse_legacy_hand_phase(
            value.round_state,
            value.betting_round,
            current_turn,
            shuffle_state,
            reveal_token_state,
            reconstruct_state,
            timeout_config,
            timestamps,
        )?;
        let table = Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name,
            creator: value.creator,
            max_players: value.max_players,
            small_blind: value.small_blind,
            big_blind: value.big_blind,
            seats,
            acted_mask,
            leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards,
            hand_phase,
            deck_state,
            timeout_config,
            chip_pool: value.chip_pool,
            addon_pool: value.addon_pool,
            ante_mode: value.ante_mode,
            ante_amount: value.ante_amount,
            ante_collected: value.ante_collected,
            rake_mode: value.rake_mode,
            rake_bps: rake_bps_u16(value.rake_bps, "v2")?,
            rake_cap: value.rake_cap,
            rake_collected: value.rake_collected,
            rit_mode: value.rit_mode,
            run_it_twice_state,
            hand_id: value.hand_id,
            call_seq: value.call_seq,
            version: value.version,
        };
        table.validate_state_schema()?;
        Ok(table)
    }
}

/// Encode the current canonical persisted table state.
pub fn encode_table_state(table: &TexasPokerTable) -> PokerL1Result<Vec<u8>> {
    table.validate_state_schema()?;
    borsh::to_vec(table)
        .map_err(|error| PokerL1Error::Serialization(format!("TexasPokerTable borsh: {error}")))
}

/// Decode current v15 bytes or migrate exact v2-v14 bytes into the canonical v15 model.
pub fn decode_table_state(bytes: &[u8]) -> PokerL1Result<TexasPokerTable> {
    if let Ok(table) = TexasPokerTable::try_from_slice(bytes) {
        if table.state_schema_version == TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION {
            table.validate_state_schema()?;
            return Ok(table);
        }
    }

    // Schema v15 keeps the v14 physical layout but strengthens the invariant: every active
    // phase must already carry a non-zero authenticated deadline. A v14 active table whose timer
    // was never armed has no trustworthy timestamp from which to reconstruct one, so migration
    // rejects it instead of silently choosing a new timeout origin.
    if let Ok(mut legacy) = PersistedTexasPokerTableV14::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V14_SCHEMA_VERSION {
            legacy.state_schema_version = TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION;
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV13::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V13_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV12::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V12_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV11::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V11_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV10::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V10_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV9::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V9_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV8::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V8_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyPersistedTexasPokerTableV7::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V7_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyTexasPokerTableV6::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V6_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyTexasPokerTableV5::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V5_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyTexasPokerTableV4::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V4_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    if let Ok(legacy) = LegacyTexasPokerTableV3::try_from_slice(bytes) {
        if legacy.state_schema_version == LEGACY_V3_SCHEMA_VERSION {
            return legacy.try_into();
        }
    }

    let legacy = LegacyTexasPokerTableV2::try_from_slice(bytes).map_err(|error| {
        PokerL1Error::Serialization(format!(
            "TexasPokerTable is neither canonical v15 nor migratable v2-v14: {error}"
        ))
    })?;
    legacy.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contracts::texas_poker::card::Card;
    use crate::vm::contracts::texas_poker::constants::{
        RECONSTRUCT_PHASE_COLLECTING, RECONSTRUCT_PHASE_COMPLETE, RECONSTRUCT_PHASE_NONE,
        REVEAL_PHASE_FLOP, REVEAL_PHASE_TURN, ROUND_FLOP, ROUND_PREFLOP, ROUND_TURN, ROUND_WAITING,
        SHUFFLE_PHASE_BEFORE_PREFLOP, SHUFFLE_PHASE_RECONSTRUCT,
    };
    use crate::vm::contracts::texas_poker::types::{EMPTY_PLAYER, seat_mask_to_indices};

    fn legacy_current_turn(table: &TexasPokerTable) -> Option<u8> {
        table.current_turn_option()
    }

    fn legacy_shuffle(table: &TexasPokerTable) -> LegacyShuffleStateV4 {
        let shuffle_state = table.shuffle_state();
        let current_shuffler = shuffle_state.derived_current_shuffler();
        LegacyShuffleStateV4 {
            phase: table.shuffle_phase(),
            current_shuffler: (current_shuffler != NO_SEAT).then_some(current_shuffler),
            pending_players: seat_mask_to_indices(shuffle_state.pending_mask, table.max_players),
            completed_players: seat_mask_to_indices(
                shuffle_state.completed_mask,
                table.max_players,
            ),
        }
    }

    fn legacy_shuffle_phase_parts(
        phase: ShufflingPhase,
    ) -> (
        ShufflingPurpose,
        u8,
        ShuffleState,
        Option<RevealTokenState>,
        u64,
    ) {
        match phase {
            ShufflingPhase::Initial { state, deadline_ms } => (
                ShufflingPurpose::Initial,
                ROUND_WAITING,
                state,
                None,
                deadline_ms,
            ),
            ShufflingPhase::Reconstruct {
                street,
                state,
                suspended_reveal,
                deadline_ms,
            } => (
                ShufflingPurpose::Reconstruct,
                street,
                state,
                Some(suspended_reveal),
                deadline_ms,
            ),
        }
    }

    fn legacy_hand_phase_v10(phase: HandPhase) -> LegacyHandPhaseV10 {
        match phase {
            HandPhase::Waiting => LegacyHandPhaseV10::Waiting,
            HandPhase::Shuffling { phase } => {
                let (purpose, street, state, suspended_reveal, deadline_ms) =
                    legacy_shuffle_phase_parts(phase);
                LegacyHandPhaseV10::Shuffling {
                    street,
                    state: LegacyShuffleStateV10 {
                        phase: purpose.legacy_phase(),
                        current_shuffler: state.derived_current_shuffler(),
                        pending_mask: state.pending_mask,
                        completed_mask: state.completed_mask,
                    },
                    suspended_reveal,
                    deadline_ms,
                }
            }
            HandPhase::Revealing {
                street,
                state,
                deadline_ms,
            } => LegacyHandPhaseV10::Revealing {
                street,
                state,
                deadline_ms,
            },
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            } => LegacyHandPhaseV10::Reconstructing {
                street,
                state: LegacyReconstructStateV11 {
                    phase: RECONSTRUCT_PHASE_COLLECTING,
                    pending_mask: state.pending_mask,
                    coefficient: None,
                    accumulated_deck: state.accumulated_deck,
                },
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            },
            HandPhase::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            } => LegacyHandPhaseV10::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            },
            HandPhase::ShowdownDisplay { deadline_ms } => {
                LegacyHandPhaseV10::ShowdownDisplay { deadline_ms }
            }
        }
    }

    fn legacy_hand_phase_v11(phase: HandPhase) -> LegacyHandPhaseV11 {
        match phase {
            HandPhase::Waiting => LegacyHandPhaseV11::Waiting,
            HandPhase::Shuffling { phase } => {
                let (purpose, street, state, suspended_reveal, deadline_ms) =
                    legacy_shuffle_phase_parts(phase);
                LegacyHandPhaseV11::Shuffling {
                    street,
                    state: LegacyShuffleStateV11 {
                        phase: purpose.legacy_phase(),
                        pending_mask: state.pending_mask,
                        completed_mask: state.completed_mask,
                    },
                    suspended_reveal,
                    deadline_ms,
                }
            }
            HandPhase::Revealing {
                street,
                state,
                deadline_ms,
            } => LegacyHandPhaseV11::Revealing {
                street,
                state,
                deadline_ms,
            },
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            } => LegacyHandPhaseV11::Reconstructing {
                street,
                state: LegacyReconstructStateV11 {
                    phase: RECONSTRUCT_PHASE_COLLECTING,
                    pending_mask: state.pending_mask,
                    coefficient: None,
                    accumulated_deck: state.accumulated_deck,
                },
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            },
            HandPhase::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            } => LegacyHandPhaseV11::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            },
            HandPhase::ShowdownDisplay { deadline_ms } => {
                LegacyHandPhaseV11::ShowdownDisplay { deadline_ms }
            }
        }
    }

    fn legacy_hand_phase_v13(phase: HandPhase) -> LegacyHandPhaseV13 {
        match phase {
            HandPhase::Waiting => LegacyHandPhaseV13::Waiting,
            HandPhase::Shuffling { phase } => {
                let (purpose, street, state, suspended_reveal, deadline_ms) =
                    legacy_shuffle_phase_parts(phase);
                LegacyHandPhaseV13::Shuffling {
                    purpose,
                    street,
                    state,
                    suspended_reveal,
                    deadline_ms,
                }
            }
            HandPhase::Revealing {
                street,
                state,
                deadline_ms,
            } => LegacyHandPhaseV13::Revealing {
                street,
                state,
                deadline_ms,
            },
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            } => LegacyHandPhaseV13::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            },
            HandPhase::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            } => LegacyHandPhaseV13::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            },
            HandPhase::ShowdownDisplay { deadline_ms } => {
                LegacyHandPhaseV13::ShowdownDisplay { deadline_ms }
            }
        }
    }

    fn legacy_reveal(table: &TexasPokerTable) -> LegacyRevealTokenStateV4 {
        let reveal_state = table.reveal_token_state();
        LegacyRevealTokenStateV4 {
            reveal_phase: reveal_state.reveal_phase,
            assignments: reveal_state
                .assignments
                .iter()
                .map(|assignment| LegacyRevealAssignmentV4 {
                    encrypted_card_index: assignment.encrypted_card_index,
                    runout_index: match assignment.target {
                        RevealTarget::Hole { .. } => 0,
                        RevealTarget::Board { runout_index, .. } => runout_index,
                    },
                    board_position: match assignment.target {
                        RevealTarget::Hole { .. } => u8::MAX,
                        RevealTarget::Board { board_position, .. } => board_position,
                    },
                    pending_players: seat_mask_to_indices(
                        assignment.pending_mask(),
                        table.max_players,
                    ),
                    reveal_tokens: match &assignment.progress {
                        RevealProgress::Collecting {
                            submitted_mask,
                            reveal_tokens,
                            ..
                        } => seat_mask_to_indices(*submitted_mask, table.max_players)
                            .into_iter()
                            .zip(reveal_tokens.iter())
                            .map(|(seat_index, token)| LegacyRevealTokenDataV4 {
                                seat_index,
                                token: *token,
                            })
                            .collect(),
                        RevealProgress::ReadyPartial { .. } | RevealProgress::ReadyCard { .. } => {
                            Vec::new()
                        }
                    },
                    decrypted: assignment.is_ready(),
                })
                .collect(),
        }
    }

    fn legacy_reconstruct(table: &TexasPokerTable) -> LegacyReconstructStateV4 {
        let reconstruct_state = table.reconstruct_state();
        assert!(reconstruct_state.accumulated_deck.is_none());
        LegacyReconstructStateV4 {
            phase: table.reconstruct_phase(),
            pending_players: seat_mask_to_indices(
                reconstruct_state.pending_mask,
                table.max_players,
            ),
            coefficient: None,
            player_decks: vec![],
        }
    }

    fn legacy_reconstruct_v6(table: &TexasPokerTable) -> LegacyReconstructStateV6 {
        let reconstruct_state = table.reconstruct_state();
        assert!(reconstruct_state.accumulated_deck.is_none());
        LegacyReconstructStateV6 {
            phase: table.reconstruct_phase(),
            pending_mask: reconstruct_state.pending_mask,
            coefficient: None,
            player_decks: vec![],
        }
    }

    fn legacy_deck(table: &TexasPokerTable) -> LegacyDeckStateV8 {
        LegacyDeckStateV8 {
            encrypted: table.deck_state.encrypted.clone(),
            aggregated_pk: table.deck_state.aggregated_pk,
            cards_dealt: table.deck_state.cards_dealt,
            decrypted_cards: table
                .deck_state
                .decrypted_cards
                .iter()
                .map(|record| {
                    let (ciphertext, plaintext) = match &record.state {
                        super::super::types::DecryptedCardState::Partial { ciphertext } => {
                            (Some(*ciphertext), None)
                        }
                        super::super::types::DecryptedCardState::Plaintext { plaintext } => {
                            (None, Some(*plaintext))
                        }
                    };
                    LegacyDecryptedCardV8 {
                        encrypted_card_index: record.encrypted_card_index,
                        owner_seat_index: record.owner_seat_index,
                        ciphertext,
                        plaintext,
                    }
                })
                .collect(),
        }
    }

    fn legacy_runout_v5(table: &TexasPokerTable) -> LegacyRunItTwiceStateV5 {
        LegacyRunItTwiceStateV5 {
            active: table.run_it_twice_state.is_active(),
            shared_board_len: table.run_it_twice_state.shared_board_len(),
            second_board_cards: if table.run_it_twice_state.is_active() {
                legacy_cards(
                    &table
                        .run_it_twice_state
                        .full_second_board(&table.community_cards)
                        .unwrap(),
                )
            } else {
                vec![]
            },
        }
    }

    fn legacy_seats_v12(table: &TexasPokerTable) -> Vec<LegacySeatV12> {
        table.seats.iter().map(LegacySeatV12::from).collect()
    }

    fn legacy_runout_v12(table: &TexasPokerTable) -> LegacyRunItTwiceStateV12 {
        LegacyRunItTwiceStateV12::from(&table.run_it_twice_state)
    }

    fn legacy_v8(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV8 {
        LegacyPersistedTexasPokerTableV8 {
            id: table.id,
            state_schema_version: LEGACY_V8_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v10(table.canonical_hand_phase().unwrap()),
            deck_state: legacy_deck(table),
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v9(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV9 {
        LegacyPersistedTexasPokerTableV9 {
            id: table.id,
            state_schema_version: LEGACY_V9_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v10(table.canonical_hand_phase().unwrap()),
            deck_state: LegacyDeckStateV9 {
                encrypted: table.deck_state.encrypted.clone(),
                aggregated_pk: table.deck_state.aggregated_pk,
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table.deck_state.decrypted_cards.clone(),
            },
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v10(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV10 {
        LegacyPersistedTexasPokerTableV10 {
            id: table.id,
            state_schema_version: LEGACY_V10_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v10(table.canonical_hand_phase().unwrap()),
            deck_state: PersistedDeckStateV10 {
                encrypted: table.deck_state.encrypted.clone(),
                contributor_mask: table.deck_state.contributor_mask,
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table.deck_state.decrypted_cards.clone(),
            },
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v11(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV11 {
        LegacyPersistedTexasPokerTableV11 {
            id: table.id,
            state_schema_version: LEGACY_V11_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v11(table.canonical_hand_phase().unwrap()),
            deck_state: PersistedDeckStateV10 {
                encrypted: table.deck_state.encrypted.clone(),
                contributor_mask: table.deck_state.contributor_mask,
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table.deck_state.decrypted_cards.clone(),
            },
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v13(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV13 {
        LegacyPersistedTexasPokerTableV13 {
            id: table.id,
            state_schema_version: LEGACY_V13_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: table.seats.clone(),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v13(table.canonical_hand_phase().unwrap()),
            deck_state: PersistedDeckStateV10 {
                encrypted: table.deck_state.encrypted.clone(),
                contributor_mask: table.deck_state.contributor_mask,
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table.deck_state.decrypted_cards.clone(),
            },
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: table.rake_bps,
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: table.run_it_twice_state.clone(),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v12(table: &TexasPokerTable) -> LegacyPersistedTexasPokerTableV12 {
        LegacyPersistedTexasPokerTableV12 {
            id: table.id,
            state_schema_version: LEGACY_V12_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: legacy_hand_phase_v13(table.canonical_hand_phase().unwrap()),
            deck_state: PersistedDeckStateV10 {
                encrypted: table.deck_state.encrypted.clone(),
                contributor_mask: table.deck_state.contributor_mask,
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table.deck_state.decrypted_cards.clone(),
            },
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_timeout_v6(timeout: TimeoutConfig) -> LegacyTimeoutConfigV6 {
        LegacyTimeoutConfigV6 {
            shuffle_timeout_ms: u64::from(timeout.shuffle_timeout_ms),
            reveal_timeout_ms: u64::from(timeout.reveal_timeout_ms),
            betting_timeout_ms: u64::from(timeout.betting_timeout_ms),
            reconstruct_timeout_ms: u64::from(timeout.reconstruct_timeout_ms),
            showdown_display_ms: u64::from(timeout.showdown_display_ms),
            hand_complete_wait_ms: 5_000,
            ready_wait_ms: 5_000,
        }
    }

    fn legacy_v2(table: &TexasPokerTable) -> LegacyTexasPokerTableV2 {
        LegacyTexasPokerTableV2 {
            id: table.id,
            state_schema_version: LEGACY_V2_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: table
                .seats
                .iter()
                .enumerate()
                .map(|(index, seat)| LegacySeatV2 {
                    player: seat.player,
                    stack: seat.stack,
                    hand: legacy_cards(&seat.hand),
                    bet: seat.bet,
                    total_bet: seat.total_bet,
                    folded: seat.is_folded() || seat.has_left_hand(),
                    all_in: seat.is_all_in(),
                    acted_this_round: table.seat_acted_this_round(index as u8),
                    is_waiting: seat.is_waiting(),
                    left_during_hand: seat.has_left_hand(),
                    pk: seat.pk,
                    refunded: false,
                    pending_addon: seat.pending_addon,
                    time_bank_ms: u64::from(seat.time_bank_ms),
                    want_leave: table.seat_wants_leave(index as u8),
                })
                .collect(),
            button: table.button,
            pot: table.pot,
            side_pots: vec![],
            community_cards: legacy_cards(&table.community_cards),
            round_state: table.round_state(),
            betting_round: table.betting_round(),
            current_turn: legacy_current_turn(table),
            deck_state: LegacyDeckStateV2 {
                encrypted: table.deck_state.encrypted.clone(),
                aggregated_pk: table.deck_state.aggregated_pk,
                plaintext: generate_plaintext_cards()
                    .into_iter()
                    .map(ECPoint)
                    .collect(),
                cards_dealt: table.deck_state.cards_dealt,
                decrypted_cards: table
                    .deck_state
                    .decrypted_cards
                    .iter()
                    .map(|record| {
                        let (ciphertext, plaintext) = match &record.state {
                            super::super::types::DecryptedCardState::Partial { ciphertext } => {
                                (Some(*ciphertext), None)
                            }
                            super::super::types::DecryptedCardState::Plaintext { plaintext } => {
                                (None, Some(*plaintext))
                            }
                        };
                        LegacyDecryptedCardV8 {
                            encrypted_card_index: record.encrypted_card_index,
                            owner_seat_index: record.owner_seat_index,
                            ciphertext,
                            plaintext,
                        }
                    })
                    .collect(),
            },
            shuffle_state: legacy_shuffle(table),
            reveal_token_state: legacy_reveal(table),
            reconstruct_state: legacy_reconstruct(table),
            timeout_config: legacy_timeout_v6(table.timeout_config),
            timestamps: LegacyTimestampsV2 {
                ready_at: 7,
                shuffle_started_at: table.timestamps().shuffle_started_at,
                reveal_started_at: table.timestamps().reveal_started_at,
                betting_started_at: table.timestamps().betting_started_at,
                reconstruct_started_at: table.timestamps().reconstruct_started_at,
                showdown_at: table.timestamps().showdown_at,
                hand_complete_at: 9,
            },
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: LegacyRunItTwiceStateV2 {
                active: table.run_it_twice_state.is_active(),
                trigger_round: if table.run_it_twice_state.is_active() {
                    match table.run_it_twice_state.shared_board_len() {
                        0 => ROUND_PREFLOP,
                        3 => ROUND_FLOP,
                        4 => ROUND_TURN,
                        other => panic!("non-canonical test RIT shared prefix {other}"),
                    }
                } else {
                    ROUND_WAITING
                },
                shared_board_len: table.run_it_twice_state.shared_board_len(),
                second_board_cards: legacy_runout_v5(table).second_board_cards,
            },
            config: LegacyTableConfigV2::default(),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v3(table: &TexasPokerTable) -> LegacyTexasPokerTableV3 {
        LegacyTexasPokerTableV3 {
            id: table.id,
            state_schema_version: LEGACY_V3_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: table
                .seats
                .iter()
                .enumerate()
                .map(|(index, seat)| LegacySeatV3 {
                    player: seat.player,
                    stack: seat.stack,
                    hand: legacy_cards(&seat.hand),
                    bet: seat.bet,
                    total_bet: seat.total_bet,
                    folded: seat.is_folded() || seat.has_left_hand(),
                    all_in: seat.is_all_in(),
                    acted_this_round: table.seat_acted_this_round(index as u8),
                    is_waiting: seat.is_waiting(),
                    left_during_hand: seat.has_left_hand(),
                    pk: seat.pk,
                    pending_addon: seat.pending_addon,
                    time_bank_ms: u64::from(seat.time_bank_ms),
                    want_leave: table.seat_wants_leave(index as u8),
                })
                .collect(),
            button: table.button,
            pot: table.pot,
            community_cards: legacy_cards(&table.community_cards),
            round_state: table.round_state(),
            betting_round: table.betting_round(),
            current_turn: legacy_current_turn(table),
            deck_state: legacy_deck(&table),
            shuffle_state: legacy_shuffle(table),
            reveal_token_state: legacy_reveal(table),
            reconstruct_state: legacy_reconstruct(table),
            timeout_config: legacy_timeout_v6(table.timeout_config),
            timestamps: *table.timestamps(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v5(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v4(table: &TexasPokerTable) -> LegacyTexasPokerTableV4 {
        LegacyTexasPokerTableV4 {
            id: table.id,
            state_schema_version: LEGACY_V4_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: table
                .seats
                .iter()
                .enumerate()
                .map(|(index, seat)| LegacySeatV4 {
                    player: seat.player,
                    stack: seat.stack,
                    hand: legacy_cards(&seat.hand),
                    bet: seat.bet,
                    total_bet: seat.total_bet,
                    status: seat.status,
                    flags: LegacySeatFlagsV4(
                        u8::from(table.seat_acted_this_round(index as u8))
                            | (u8::from(table.seat_wants_leave(index as u8)) << 1),
                    ),
                    pk: seat.pk,
                    pending_addon: seat.pending_addon,
                    time_bank_ms: u64::from(seat.time_bank_ms),
                })
                .collect(),
            button: table.button,
            pot: table.pot,
            community_cards: legacy_cards(&table.community_cards),
            round_state: table.round_state(),
            betting_round: table.betting_round(),
            current_turn: legacy_current_turn(table),
            deck_state: legacy_deck(table),
            shuffle_state: legacy_shuffle(table),
            reveal_token_state: legacy_reveal(table),
            reconstruct_state: legacy_reconstruct(table),
            timeout_config: legacy_timeout_v6(table.timeout_config),
            timestamps: *table.timestamps(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v5(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v5(table: &TexasPokerTable) -> LegacyTexasPokerTableV5 {
        LegacyTexasPokerTableV5 {
            id: table.id,
            state_schema_version: LEGACY_V5_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: table
                .seats
                .iter()
                .map(|seat| LegacySeatV5 {
                    player: seat.player,
                    stack: seat.stack,
                    hand: legacy_cards(&seat.hand),
                    bet: seat.bet,
                    total_bet: seat.total_bet,
                    status: seat.status,
                    pk: seat.pk,
                    pending_addon: seat.pending_addon,
                    time_bank_ms: u64::from(seat.time_bank_ms),
                })
                .collect(),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: legacy_cards(&table.community_cards),
            round_state: table.round_state(),
            betting_round: table.betting_round(),
            current_turn: table.current_turn(),
            deck_state: legacy_deck(table),
            shuffle_state: LegacyShuffleStateV11 {
                phase: table.shuffle_phase(),
                pending_mask: table.shuffle_state().pending_mask,
                completed_mask: table.shuffle_state().completed_mask,
            },
            reveal_token_state: table.reveal_token_state().into_owned(),
            reconstruct_state: legacy_reconstruct_v6(table),
            timeout_config: legacy_timeout_v6(table.timeout_config),
            timestamps: *table.timestamps(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v5(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    fn legacy_v6(table: &TexasPokerTable) -> LegacyTexasPokerTableV6 {
        LegacyTexasPokerTableV6 {
            id: table.id,
            state_schema_version: LEGACY_V6_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            round_state: table.round_state(),
            betting_round: table.betting_round(),
            current_turn: table.current_turn(),
            deck_state: legacy_deck(table),
            shuffle_state: LegacyShuffleStateV11 {
                phase: table.shuffle_phase(),
                pending_mask: table.shuffle_state().pending_mask,
                completed_mask: table.shuffle_state().completed_mask,
            },
            reveal_token_state: table.reveal_token_state().into_owned(),
            reconstruct_state: legacy_reconstruct_v6(table),
            timeout_config: legacy_timeout_v6(table.timeout_config),
            timestamps: *table.timestamps(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        }
    }

    #[test]
    fn v7_roundtrip_uses_canonical_phase_codec() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xAA; 20], 3),
            "v7".into(),
            EMPTY_PLAYER,
            6,
            50,
            100,
        );
        let bytes = encode_table_state(&table).unwrap();
        let persisted = PersistedTexasPokerTableV7::try_from_slice(&bytes).unwrap();
        assert_eq!(
            persisted.state_schema_version,
            TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        );
        assert_eq!(persisted.hand_phase, HandPhase::Waiting);
        assert_eq!(bytes, borsh::to_vec(&persisted).unwrap());
        assert_eq!(decode_table_state(&bytes).unwrap(), table);
    }

    #[test]
    fn schema_v14_waiting_and_armed_active_states_migrate_to_v15() {
        let waiting = TexasPokerTable::new(
            ObjectID::new([0xE0; 20], 14),
            "v14-waiting".into(),
            [0x14; 20],
            2,
            5,
            10,
        );
        let mut waiting_v14 = PersistedTexasPokerTableV14::try_from(&waiting).unwrap();
        waiting_v14.state_schema_version = LEGACY_V14_SCHEMA_VERSION;
        assert_eq!(
            decode_table_state(&borsh::to_vec(&waiting_v14).unwrap()).unwrap(),
            waiting
        );

        let mut shuffling = waiting.clone();
        shuffling
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();
        let mut shuffling_v14 = PersistedTexasPokerTableV14::try_from(&shuffling).unwrap();
        shuffling_v14.state_schema_version = LEGACY_V14_SCHEMA_VERSION;
        assert_eq!(
            decode_table_state(&borsh::to_vec(&shuffling_v14).unwrap()).unwrap(),
            shuffling
        );
    }

    #[test]
    fn schema_v14_zero_active_deadline_fails_closed() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xE1; 20], 14),
            "v14-zero-deadline".into(),
            [0x14; 20],
            2,
            5,
            10,
        );
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();
        let mut legacy = PersistedTexasPokerTableV14::try_from(&table).unwrap();
        legacy.state_schema_version = LEGACY_V14_SCHEMA_VERSION;
        let HandPhase::Shuffling { phase } = &mut legacy.hand_phase else {
            panic!("expected shuffling phase");
        };
        *phase.deadline_ms_mut() = 0;
        assert!(decode_table_state(&borsh::to_vec(&legacy).unwrap()).is_err());
    }

    #[test]
    fn schema_v14_partial_reconstruct_deadline_pair_fails_closed() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xE2; 20], 14),
            "v14-reconstruct-pair".into(),
            [0x14; 20],
            2,
            5,
            10,
        );
        table
            .enter_reconstructing(
                ROUND_TURN,
                ReconstructState {
                    pending_mask: 0b11,
                    accumulated_deck: None,
                },
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                1_000,
            )
            .unwrap();

        for clear_epoch in [true, false] {
            let mut legacy = PersistedTexasPokerTableV14::try_from(&table).unwrap();
            legacy.state_schema_version = LEGACY_V14_SCHEMA_VERSION;
            let HandPhase::Reconstructing {
                epoch_ms,
                deadline_ms,
                ..
            } = &mut legacy.hand_phase
            else {
                panic!("expected reconstructing phase");
            };
            if clear_epoch {
                *epoch_ms = 0;
            } else {
                *deadline_ms = 0;
            }
            assert!(decode_table_state(&borsh::to_vec(&legacy).unwrap()).is_err());
        }
    }

    #[test]
    fn schema_v15_roundtrip_and_zero_deadline_encoding_are_fail_closed() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xE3; 20], 15),
            "v15-roundtrip".into(),
            [0x15; 20],
            2,
            5,
            10,
        );
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();
        let bytes = encode_table_state(&table).unwrap();
        assert_eq!(decode_table_state(&bytes).unwrap(), table);

        let mut invalid = table;
        let HandPhase::Shuffling { phase } = &mut invalid.hand_phase else {
            panic!("expected shuffling phase");
        };
        *phase.deadline_ms_mut() = 0;
        assert!(encode_table_state(&invalid).is_err());
    }

    #[test]
    fn legacy_v13_shuffle_subtypes_migrate_to_v14_and_new_bytes_do_not_alias() {
        let mut initial = TexasPokerTable::new(
            ObjectID::new([0xC0; 20], 13),
            "legacy-v13-initial".into(),
            [0x13; 20],
            2,
            5,
            10,
        );
        initial
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();

        let initial_bytes = borsh::to_vec(&legacy_v13(&initial)).unwrap();
        assert!(TexasPokerTable::try_from_slice(&initial_bytes).is_err());
        assert_eq!(decode_table_state(&initial_bytes).unwrap(), initial);

        let mut reconstruct = initial.clone();
        reconstruct
            .enter_reconstruct_shuffling(
                ROUND_TURN,
                ShuffleState {
                    pending_mask: 0b10,
                    completed_mask: 0b01,
                },
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                2_000,
            )
            .unwrap();
        let reconstruct_bytes = borsh::to_vec(&legacy_v13(&reconstruct)).unwrap();
        assert_eq!(decode_table_state(&reconstruct_bytes).unwrap(), reconstruct);

        let canonical = encode_table_state(&reconstruct).unwrap();
        assert!(PersistedTexasPokerTableV14::try_from_slice(&canonical).is_ok());
        assert!(LegacyPersistedTexasPokerTableV13::try_from_slice(&canonical).is_err());
    }

    #[test]
    fn legacy_v13_invalid_shuffle_combinations_fail_closed() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xCF; 20], 13),
            "legacy-v13-invalid".into(),
            [0x13; 20],
            2,
            5,
            10,
        );
        let state = ShuffleState {
            pending_mask: 0b11,
            completed_mask: 0,
        };
        let reveal = RevealTokenState {
            reveal_phase: REVEAL_PHASE_TURN,
            assignments: vec![],
        };

        let mut initial_with_reveal = legacy_v13(&table);
        initial_with_reveal.hand_phase = LegacyHandPhaseV13::Shuffling {
            purpose: ShufflingPurpose::Initial,
            street: ROUND_WAITING,
            state: state.clone(),
            suspended_reveal: Some(reveal.clone()),
            deadline_ms: 10_000,
        };
        assert!(decode_table_state(&borsh::to_vec(&initial_with_reveal).unwrap()).is_err());

        let mut reconstruct_without_reveal = legacy_v13(&table);
        reconstruct_without_reveal.hand_phase = LegacyHandPhaseV13::Shuffling {
            purpose: ShufflingPurpose::Reconstruct,
            street: ROUND_TURN,
            state,
            suspended_reveal: None,
            deadline_ms: 10_000,
        };
        assert!(decode_table_state(&borsh::to_vec(&reconstruct_without_reveal).unwrap()).is_err());
    }

    #[test]
    fn legacy_v12_migrates_bounded_fields_and_tagged_rit() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xC1; 20], 12),
            "legacy-v12".into(),
            [0x12; 20],
            2,
            5,
            10,
        );
        table.rake_mode = super::super::constants::RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500;
        table.rit_mode = super::super::constants::RIT_MODE_TWICE;
        table.community_cards =
            BoardCards::try_from((0..4).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        table.run_it_twice_state = RunItTwiceState::Twice {
            start: RitStartStreet::Flop,
            second_board_suffix: BoardCards::try_from(vec![Card::from_index(4)]).unwrap(),
        };
        table.validate_state_schema().unwrap();

        let legacy_bytes = borsh::to_vec(&legacy_v12(&table)).unwrap();
        assert!(TexasPokerTable::try_from_slice(&legacy_bytes).is_err());
        let migrated = decode_table_state(&legacy_bytes).unwrap();
        assert_eq!(migrated, table);

        let canonical = encode_table_state(&migrated).unwrap();
        assert!(PersistedTexasPokerTableV14::try_from_slice(&canonical).is_ok());
        assert!(LegacyPersistedTexasPokerTableV12::try_from_slice(&canonical).is_err());
    }

    #[test]
    fn legacy_v12_bounded_fields_and_rit_are_fail_closed() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xC2; 20], 12),
            "legacy-v12-invalid".into(),
            [0x12; 20],
            2,
            5,
            10,
        );

        let mut excessive_time_bank = legacy_v12(&table);
        excessive_time_bank.seats[0].time_bank_ms = u64::from(u32::MAX) + 1;
        assert!(decode_table_state(&borsh::to_vec(&excessive_time_bank).unwrap()).is_err());

        let mut excessive_rake = legacy_v12(&table);
        excessive_rake.rake_mode = super::super::constants::RAKE_MODE_PERCENTAGE;
        excessive_rake.rake_bps = 10_001;
        assert!(decode_table_state(&borsh::to_vec(&excessive_rake).unwrap()).is_err());

        let mut invalid_twice = legacy_v12(&table);
        invalid_twice.run_it_twice_state = LegacyRunItTwiceStateV12 {
            mode: LegacyRunoutModeV12::Twice,
            shared_board_len: 2,
            second_board_suffix: BoardCards::empty(),
        };
        assert!(decode_table_state(&borsh::to_vec(&invalid_twice).unwrap()).is_err());

        let mut invalid_single = legacy_v12(&table);
        invalid_single.run_it_twice_state = LegacyRunItTwiceStateV12 {
            mode: LegacyRunoutModeV12::Single,
            shared_board_len: 0,
            second_board_suffix: BoardCards::try_from(vec![Card::from_index(0)]).unwrap(),
        };
        assert!(decode_table_state(&borsh::to_vec(&invalid_single).unwrap()).is_err());
    }

    #[test]
    fn legacy_v8_decrypted_card_options_migrate_fail_closed() {
        let ciphertext = ElGamalCiphertext::new_placeholder_card();
        let plaintext = ECPoint(super::super::utils::g1_generator());
        let migrated = migrate_deck_state(
            LegacyDeckStateV8 {
                encrypted: vec![],
                aggregated_pk: None,
                cards_dealt: 0,
                decrypted_cards: vec![
                    LegacyDecryptedCardV8 {
                        encrypted_card_index: 1,
                        owner_seat_index: 0,
                        ciphertext: Some(ciphertext),
                        plaintext: None,
                    },
                    LegacyDecryptedCardV8 {
                        encrypted_card_index: 2,
                        owner_seat_index: 1,
                        ciphertext: None,
                        plaintext: Some(plaintext),
                    },
                    LegacyDecryptedCardV8 {
                        encrypted_card_index: 3,
                        owner_seat_index: 1,
                        ciphertext: None,
                        plaintext: None,
                    },
                ],
            },
            2,
        )
        .unwrap();
        assert_eq!(migrated.decrypted_cards.len(), 2);
        assert!(matches!(
            migrated.decrypted_cards[0].state,
            super::super::types::DecryptedCardState::Partial { .. }
        ));
        assert!(matches!(
            migrated.decrypted_cards[1].state,
            super::super::types::DecryptedCardState::Plaintext { .. }
        ));

        let invalid = LegacyDeckStateV8 {
            encrypted: vec![],
            aggregated_pk: None,
            cards_dealt: 0,
            decrypted_cards: vec![LegacyDecryptedCardV8 {
                encrypted_card_index: 4,
                owner_seat_index: 0,
                ciphertext: Some(ElGamalCiphertext::new_placeholder_card()),
                plaintext: Some(plaintext),
            }],
        };
        assert!(migrate_deck_state(invalid, 2).is_err());
    }

    #[test]
    fn legacy_v8_table_migrates_tombstone_and_v9_bytes_do_not_parse_as_v8() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA9; 20], 9),
            "legacy-v8-ledger".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table
            .deck_state
            .decrypted_cards
            .push(super::super::types::DecryptedCard::partial(
                1,
                0,
                ElGamalCiphertext::new_placeholder_card(),
            ));

        let mut legacy = legacy_v8(&table);
        legacy
            .deck_state
            .decrypted_cards
            .push(LegacyDecryptedCardV8 {
                encrypted_card_index: 2,
                owner_seat_index: 1,
                ciphertext: None,
                plaintext: None,
            });
        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(
            migrated.state_schema_version,
            TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        );
        assert_eq!(migrated.deck_state.decrypted_cards.len(), 1);

        let canonical_bytes = encode_table_state(&table).unwrap();
        assert!(LegacyPersistedTexasPokerTableV8::try_from_slice(&canonical_bytes).is_err());
    }

    #[test]
    fn legacy_v9_migration_derives_unique_contributor_lineage() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB0; 20], 10),
            "legacy-v9-lineage".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].pk = ECPoint::from(super::super::utils::g1_generator());
        table.deck_state.contributor_mask = 1;
        table.sync_aggregated_pk().unwrap();

        let migrated = decode_table_state(&borsh::to_vec(&legacy_v9(&table)).unwrap()).unwrap();
        assert_eq!(migrated.deck_state.contributor_mask, 1);
        assert_eq!(migrated.deck_state.aggregated_pk, Some(table.seats[0].pk));
    }

    #[test]
    fn legacy_v10_migration_derives_shuffle_actor_and_rejects_mismatch() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB2; 20], 12),
            "legacy-v10-shuffler".into(),
            [0x11; 20],
            3,
            5,
            10,
        );
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b110,
                    completed_mask: 0b001,
                },
                1,
            )
            .unwrap();

        let legacy = legacy_v10(&table);
        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(migrated.shuffle_state().derived_current_shuffler(), 1);
        assert_eq!(migrated.shuffle_state().pending_mask, 0b110);

        let mut invalid = legacy_v10(&table);
        let LegacyHandPhaseV10::Shuffling { state, .. } = &mut invalid.hand_phase else {
            panic!("expected shuffling phase");
        };
        state.current_shuffler = 2;
        assert!(decode_table_state(&borsh::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn legacy_v11_migrates_to_v13_and_discards_retired_coefficient() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB3; 20], 13),
            "legacy-v11-reconstruct".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table
            .enter_reconstructing(
                ROUND_TURN,
                ReconstructState {
                    pending_mask: 0b11,
                    accumulated_deck: None,
                },
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                1_000,
            )
            .unwrap();

        let mut legacy = legacy_v11(&table);
        let LegacyHandPhaseV11::Reconstructing { state, .. } = &mut legacy.hand_phase else {
            panic!("expected reconstructing phase");
        };
        state.coefficient = Some(poker_protocol::crypto::types::ECScalar(
            super::super::utils::scalar_from_u64(7),
        ));
        let bytes = borsh::to_vec(&legacy).unwrap();

        // V11 bytes must take the explicit migration path, never the canonical V12 parser.
        assert!(TexasPokerTable::try_from_slice(&bytes).is_err());
        let migrated = decode_table_state(&bytes).unwrap();
        assert_eq!(migrated, table);
        assert_eq!(
            migrated.state_schema_version,
            TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        );

        let canonical = encode_table_state(&migrated).unwrap();
        assert!(PersistedTexasPokerTableV14::try_from_slice(&canonical).is_ok());
        assert!(LegacyPersistedTexasPokerTableV11::try_from_slice(&canonical).is_err());
    }

    #[test]
    fn legacy_v11_shuffle_purpose_migration_is_fail_closed() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xB4; 20], 14),
            "legacy-v11-shuffle-purpose".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        let shuffle = |phase, street, suspended_reveal| LegacyHandPhaseV11::Shuffling {
            street,
            state: LegacyShuffleStateV11 {
                phase,
                pending_mask: 0b11,
                completed_mask: 0,
            },
            suspended_reveal,
            deadline_ms: u64::from(table.timeout_config.shuffle_timeout_ms),
        };

        let mut valid = legacy_v11(&table);
        valid.hand_phase = shuffle(SHUFFLE_PHASE_BEFORE_PREFLOP, ROUND_WAITING, None);
        let migrated = decode_table_state(&borsh::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(
            migrated.shuffling_purpose(),
            Some(ShufflingPurpose::Initial)
        );

        let mut bad_initial_street = legacy_v11(&table);
        bad_initial_street.hand_phase = shuffle(SHUFFLE_PHASE_BEFORE_PREFLOP, ROUND_FLOP, None);
        assert!(decode_table_state(&borsh::to_vec(&bad_initial_street).unwrap()).is_err());

        let mut bad_reconstruct_without_reveal = legacy_v11(&table);
        bad_reconstruct_without_reveal.hand_phase =
            shuffle(SHUFFLE_PHASE_RECONSTRUCT, ROUND_TURN, None);
        assert!(
            decode_table_state(&borsh::to_vec(&bad_reconstruct_without_reveal).unwrap()).is_err()
        );

        let mut bad_initial_with_reveal = legacy_v11(&table);
        bad_initial_with_reveal.hand_phase = shuffle(
            SHUFFLE_PHASE_BEFORE_PREFLOP,
            ROUND_WAITING,
            Some(RevealTokenState {
                reveal_phase: REVEAL_PHASE_TURN,
                assignments: vec![],
            }),
        );
        assert!(decode_table_state(&borsh::to_vec(&bad_initial_with_reveal).unwrap()).is_err());
    }

    #[test]
    fn legacy_v11_active_reconstruct_phase_is_fail_closed() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xB5; 20], 15),
            "legacy-v11-reconstruct-phase".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        let reconstruct =
            |phase, pending_mask, accumulated_deck| LegacyHandPhaseV11::Reconstructing {
                street: ROUND_TURN,
                state: LegacyReconstructStateV11 {
                    phase,
                    pending_mask,
                    coefficient: None,
                    accumulated_deck,
                },
                suspended_reveal: RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                epoch_ms: 1_000,
                deadline_ms: 1_000 + u64::from(table.timeout_config.reconstruct_timeout_ms),
            };

        let mut none = legacy_v11(&table);
        none.hand_phase = reconstruct(RECONSTRUCT_PHASE_NONE, 0b11, None);
        assert!(decode_table_state(&borsh::to_vec(&none).unwrap()).is_err());

        let mut inconsistent_complete = legacy_v11(&table);
        inconsistent_complete.hand_phase = reconstruct(
            RECONSTRUCT_PHASE_COMPLETE,
            0b01,
            Some(vec![ElGamalCiphertext::new_placeholder_card(); 52]),
        );
        assert!(decode_table_state(&borsh::to_vec(&inconsistent_complete).unwrap()).is_err());
    }

    #[test]
    fn legacy_v9_migration_rejects_unmatched_ambiguous_and_identity_aggregates() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB1; 20], 11),
            "legacy-v9-invalid-lineage".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        let generator = super::super::utils::g1_generator();
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].pk = ECPoint::from(generator);

        let mut unmatched = legacy_v9(&table);
        unmatched.deck_state.aggregated_pk = Some(ECPoint::from(super::super::utils::g1_mul(
            &super::super::utils::scalar_from_u64(2),
            &generator,
        )));
        assert!(decode_table_state(&borsh::to_vec(&unmatched).unwrap()).is_err());

        table.seats[1].player = [0x33; 20];
        table.seats[1].set_status(SeatStatus::Active);
        table.seats[1].pk = ECPoint::from(generator);
        let mut ambiguous = legacy_v9(&table);
        ambiguous.deck_state.aggregated_pk = Some(ECPoint::from(generator));
        assert!(decode_table_state(&borsh::to_vec(&ambiguous).unwrap()).is_err());

        let mut identity = legacy_v9(&table);
        identity.deck_state.aggregated_pk = Some(ECPoint::from(super::super::utils::g1_identity()));
        assert!(decode_table_state(&borsh::to_vec(&identity).unwrap()).is_err());
    }

    #[test]
    fn canonical_v10_persists_lineage_and_restores_aggregate_cache() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xB2; 20], 12),
            "canonical-v10-lineage".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].pk = ECPoint::from(super::super::utils::g1_generator());
        table.deck_state.contributor_mask = 1;
        table.sync_aggregated_pk().unwrap();

        let bytes = encode_table_state(&table).unwrap();
        let persisted = PersistedTexasPokerTableV14::try_from_slice(&bytes).unwrap();
        assert_eq!(persisted.deck_state.contributor_mask, 1);
        assert!(LegacyPersistedTexasPokerTableV9::try_from_slice(&bytes).is_err());

        let restored = decode_table_state(&bytes).unwrap();
        assert_eq!(restored.deck_state.contributor_mask, 1);
        assert_eq!(restored.deck_state.aggregated_pk, Some(table.seats[0].pk));
    }

    #[test]
    fn legacy_v7_flattened_phase_migrates_to_canonical_v9() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xA8; 20], 8),
            "legacy-v7".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        let legacy = LegacyPersistedTexasPokerTableV7 {
            id: table.id,
            state_schema_version: LEGACY_V7_SCHEMA_VERSION,
            name: table.name.clone(),
            creator: table.creator,
            max_players: table.max_players,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            seats: legacy_seats_v12(&table),
            acted_mask: table.acted_mask,
            leave_after_hand_mask: table.leave_after_hand_mask,
            button: table.button,
            pot: table.pot,
            community_cards: table.community_cards.clone(),
            hand_phase: LegacyHandPhaseV7::Waiting,
            deck_state: legacy_deck(&table),
            timeout_config: table.timeout_config.try_into().unwrap(),
            chip_pool: table.chip_pool,
            addon_pool: table.addon_pool,
            ante_mode: table.ante_mode,
            ante_amount: table.ante_amount,
            ante_collected: table.ante_collected,
            rake_mode: table.rake_mode,
            rake_bps: u64::from(table.rake_bps),
            rake_cap: table.rake_cap,
            rake_collected: table.rake_collected,
            rit_mode: table.rit_mode,
            run_it_twice_state: legacy_runout_v12(&table),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
            version: table.version,
        };
        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(
            migrated.state_schema_version,
            TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        );
        assert_eq!(migrated.canonical_hand_phase().unwrap(), HandPhase::Waiting);
        assert_eq!(migrated.id, table.id);
        assert_eq!(migrated.seats, table.seats);
    }

    #[test]
    fn v6_migration_preserves_all_canonical_hand_phases() {
        let base = || {
            TexasPokerTable::new(
                ObjectID::new([0xA7; 20], 7),
                "v6-all-phases".into(),
                [0x11; 20],
                2,
                5,
                10,
            )
        };

        let waiting = base();

        let mut shuffling = base();
        shuffling
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 1,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();

        let mut revealing = base();
        revealing
            .enter_revealing(
                ROUND_FLOP,
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_FLOP,
                    assignments: vec![],
                },
                2_000,
            )
            .unwrap();

        let mut reconstructing = base();
        reconstructing
            .enter_reconstructing(
                ROUND_TURN,
                ReconstructState {
                    pending_mask: 0b11,
                    ..ReconstructState::default()
                },
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                3_000,
            )
            .unwrap();

        let mut betting = base();
        // A consumed time bank is represented by moving the effective start forward. The v7
        // union must preserve the resulting absolute deadline, not the historical raw start.
        betting
            .enter_betting(ROUND_PREFLOP, BettingRound::new(10, 10), 0, 4_000 + 7_500)
            .unwrap();

        let mut showdown = base();
        showdown.enter_showdown_display(99_000);

        for table in [
            waiting,
            shuffling,
            revealing,
            reconstructing,
            betting,
            showdown,
        ] {
            let expected_phase = table.canonical_hand_phase().unwrap();
            let migrated = decode_table_state(&borsh::to_vec(&legacy_v6(&table)).unwrap()).unwrap();
            assert_eq!(migrated.canonical_hand_phase().unwrap(), expected_phase);

            let canonical_bytes = encode_table_state(&migrated).unwrap();
            let persisted = PersistedTexasPokerTableV7::try_from_slice(&canonical_bytes).unwrap();
            assert_eq!(persisted.hand_phase, expected_phase);
        }
    }

    #[test]
    fn v7_decode_rejects_deadline_smaller_than_timeout() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xD1; 20], 1),
            "bad-deadline".into(),
            EMPTY_PLAYER,
            2,
            5,
            10,
        );
        let mut persisted = PersistedTexasPokerTableV7::try_from(&table).unwrap();
        persisted.hand_phase = HandPhase::Shuffling {
            phase: ShufflingPhase::Initial {
                state: ShuffleState {
                    pending_mask: 1,
                    completed_mask: 0,
                },
                deadline_ms: u64::from(persisted.timeout_config.shuffle_timeout_ms) - 1,
            },
        };

        assert!(decode_table_state(&borsh::to_vec(&persisted).unwrap()).is_err());
    }

    #[test]
    fn v7_decode_rejects_reconstruct_epoch_overflow() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xD2; 20], 2),
            "bad-reconstruct-epoch".into(),
            EMPTY_PLAYER,
            2,
            5,
            10,
        );
        let mut persisted = PersistedTexasPokerTableV7::try_from(&table).unwrap();
        persisted.hand_phase = HandPhase::Reconstructing {
            street: ROUND_TURN,
            state: ReconstructState {
                pending_mask: 0b11,
                accumulated_deck: None,
            },
            suspended_reveal: RevealTokenState {
                reveal_phase: REVEAL_PHASE_TURN,
                assignments: vec![],
            },
            epoch_ms: u64::MAX,
            deadline_ms: u64::MAX,
        };

        assert!(decode_table_state(&borsh::to_vec(&persisted).unwrap()).is_err());
    }

    #[test]
    fn v6_migration_rejects_timeout_outside_u32_range() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xD3; 20], 3),
            "wide-timeout".into(),
            EMPTY_PLAYER,
            2,
            5,
            10,
        );
        let mut legacy = legacy_v6(&table);
        legacy.timeout_config.betting_timeout_ms = u64::from(u32::MAX) + 1;

        assert!(decode_table_state(&borsh::to_vec(&legacy).unwrap()).is_err());
    }

    #[test]
    fn v6_migration_preserves_betting_deadline_and_discards_dead_timers() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA6; 20], 6),
            "v6-migration".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(10, 10), 0, 7_000)
            .unwrap();
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);

        let mut legacy = legacy_v6(&table);
        legacy.timeout_config.ready_wait_ms = 123;
        legacy.timeout_config.hand_complete_wait_ms = 456;
        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();

        assert_eq!(migrated.round_state(), ROUND_PREFLOP);
        assert_eq!(migrated.betting_round(), table.betting_round());
        assert_eq!(migrated.current_turn(), 0);
        assert_eq!(migrated.timestamps().betting_started_at, 7_000);
        assert_eq!(migrated.timeout_config, table.timeout_config);
        assert_eq!(
            borsh::to_vec(&migrated).unwrap(),
            encode_table_state(&migrated).unwrap()
        );
    }

    #[test]
    fn v6_migration_folds_reconstruct_player_decks_into_one_accumulator() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA8; 20], 8),
            "v6-reconstruct-stream".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table
            .enter_revealing(
                ROUND_TURN,
                RevealTokenState {
                    reveal_phase: REVEAL_PHASE_TURN,
                    assignments: vec![],
                },
                0,
            )
            .unwrap();
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].pk = ECPoint::from(super::super::utils::g1_generator());
        table.deck_state.contributor_mask = 1;
        table.sync_aggregated_pk().unwrap();

        let mut legacy = legacy_v6(&table);
        legacy.timestamps.reconstruct_started_at = 8_000;
        legacy.reconstruct_state = LegacyReconstructStateV6 {
            phase: RECONSTRUCT_PHASE_COLLECTING,
            pending_mask: 0b10,
            coefficient: None,
            player_decks: vec![LegacyReconstructPlayerDeckV4 {
                seat_index: 0,
                output_cts: vec![ElGamalCiphertext::new_placeholder_card(); 52],
            }],
        };

        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(migrated.reconstruct_state().pending_mask, 0b10);
        assert_eq!(
            migrated
                .reconstruct_state()
                .accumulated_deck
                .as_ref()
                .unwrap()
                .len(),
            52
        );
        assert!(encode_table_state(&migrated).is_ok());
    }

    #[test]
    fn v5_migration_compacts_cards_and_rit_prefix() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA5; 20], 5),
            "v5-migration".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x22; 20];
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].hand = [Card::from_index(20), Card::from_index(21)].into();
        table.community_cards =
            BoardCards::try_from((0..4).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        table.run_it_twice_state = RunItTwiceState::Twice {
            start: RitStartStreet::Flop,
            second_board_suffix: BoardCards::try_from(vec![Card::from_index(4)]).unwrap(),
        };
        let legacy = legacy_v5(&table);
        assert_eq!(legacy.run_it_twice_state.second_board_cards.len(), 4);
        let migrated = decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(migrated, table);
        assert_eq!(migrated.run_it_twice_state.second_board_suffix().len(), 1);
    }

    #[test]
    fn v2_migration_preserves_live_game_fields() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xBB; 20], 4),
            "legacy".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x22; 20];
        table.seats[0].stack = 900;
        table.seats[0].set_status(SeatStatus::Active);
        table.hand_id = 8;
        table.call_seq = 13;
        let bytes = borsh::to_vec(&legacy_v2(&table)).unwrap();
        assert_eq!(decode_table_state(&bytes).unwrap(), table);
    }

    #[test]
    fn v3_migration_normalizes_seat_status_and_flags() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xBC; 20], 5),
            "legacy-v3".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x33; 20];
        table.seats[0].stack = 700;
        table.seats[0].set_status(SeatStatus::AllIn);
        table.set_seat_acted_this_round(0, true);
        table.set_seat_wants_leave(0, true);
        let bytes = borsh::to_vec(&legacy_v3(&table)).unwrap();
        assert_eq!(decode_table_state(&bytes).unwrap(), table);
    }

    #[test]
    fn v4_migration_moves_seat_vectors_and_flags_to_masks() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xC4; 20], 5),
            "legacy-v4".into(),
            [0x11; 20],
            3,
            5,
            10,
        );
        for index in 0..3 {
            table.seats[index].player = [0x40 + index as u8; 20];
            table.seats[index].set_status(SeatStatus::Active);
        }
        table.set_seat_acted_this_round(1, true);
        table.set_seat_wants_leave(2, true);
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b011,
                    completed_mask: 0b100,
                },
                1,
            )
            .unwrap();
        let bytes = borsh::to_vec(&legacy_v4(&table)).unwrap();
        assert_eq!(decode_table_state(&bytes).unwrap(), table);
    }

    #[test]
    fn v3_migration_rejects_conflicting_lifecycle_flags() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xBD; 20], 6),
            "legacy-v3-conflict".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x44; 20];
        table.seats[0].set_status(SeatStatus::Active);
        let mut legacy = legacy_v3(&table);
        legacy.seats[0].folded = true;
        legacy.seats[0].all_in = true;
        assert!(decode_table_state(&borsh::to_vec(&legacy).unwrap()).is_err());
    }

    #[test]
    fn v3_migration_accepts_legacy_kick_pair_as_out() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xBE; 20], 7),
            "legacy-v3-kick".into(),
            [0x11; 20],
            2,
            5,
            10,
        );
        table.seats[0].player = [0x55; 20];
        table.seats[0].set_status(SeatStatus::Out);
        let legacy = legacy_v3(&table);
        assert!(legacy.seats[0].folded && legacy.seats[0].left_during_hand);
        assert_eq!(
            decode_table_state(&borsh::to_vec(&legacy).unwrap()).unwrap(),
            table
        );
    }

    #[test]
    fn v2_migration_accepts_canonical_active_rit_boundaries() {
        for (round, shared, board) in [
            (ROUND_PREFLOP, 0, vec![]),
            (
                ROUND_FLOP,
                3,
                vec![Card::new(0, 2), Card::new(1, 3), Card::new(2, 4)],
            ),
            (
                ROUND_TURN,
                4,
                vec![
                    Card::new(0, 2),
                    Card::new(1, 3),
                    Card::new(2, 4),
                    Card::new(3, 5),
                ],
            ),
        ] {
            let mut table = TexasPokerTable::new(
                ObjectID::new([round; 20], u64::from(shared)),
                "rit-migration".into(),
                EMPTY_PLAYER,
                2,
                5,
                10,
            );
            table
                .enter_betting(round, BettingRound::new(10, 10), NO_SEAT, 1)
                .unwrap();
            table.community_cards = BoardCards::try_from(board.clone()).unwrap();
            table.run_it_twice_state = RunItTwiceState::Twice {
                start: RitStartStreet::from_shared_board_len(shared).unwrap(),
                second_board_suffix: BoardCards::empty(),
            };

            let bytes = borsh::to_vec(&legacy_v2(&table)).unwrap();
            assert_eq!(decode_table_state(&bytes).unwrap(), table);
        }
    }

    #[test]
    fn v7_state_is_materially_smaller_and_discards_test_flags() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xDD; 20], 6),
            "size-regression".into(),
            EMPTY_PLAYER,
            9,
            50,
            100,
        );
        let current = encode_table_state(&table).unwrap();
        let mut legacy = legacy_v2(&table);
        legacy.config = LegacyTableConfigV2 {
            zk_skip_enabled: false,
            zk_skip_shuffle: true,
            zk_skip_reveal: false,
            zk_skip_reconstruct: true,
            zk_skip_remask: false,
        };
        let old = borsh::to_vec(&legacy).unwrap();
        assert!(
            old.len() >= current.len() + 2_500,
            "expected canonical state compaction to save at least 2.5KB: v2={}, v7={}",
            old.len(),
            current.len()
        );
        assert_eq!(decode_table_state(&old).unwrap(), table);
    }

    #[test]
    fn v2_migration_rejects_noncanonical_plaintext() {
        let table = TexasPokerTable::new(
            ObjectID::new([0xCC; 20], 5),
            "bad-deck".into(),
            EMPTY_PLAYER,
            2,
            5,
            10,
        );
        let mut legacy = legacy_v2(&table);
        legacy.deck_state.plaintext.clear();
        let bytes = borsh::to_vec(&legacy).unwrap();
        assert!(decode_table_state(&bytes).is_err());
    }
}
