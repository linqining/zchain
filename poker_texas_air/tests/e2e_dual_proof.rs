//! Stage-3 two-part proof package tests.

use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
use poker_l1::vm::contracts::texas_poker::constants::{
    RECONSTRUCT_PHASE_COLLECTING, REVEAL_PHASE_PREFLOP, REVEAL_PHASE_TURN, ROUND_PREFLOP,
    ROUND_TURN, SHUFFLE_PHASE_WAITING,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    self as texas_dispatch, FoldWithProofArgs, JoinAndShuffleArgs, LeaveWithProofArgs,
    SubmitReconstructDeckArgs, SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::types::{
    DecryptedCard, ReconstructState, RevealAssignment, RevealProgress, RevealTarget,
    RevealTokenState, SeatStatus, ShuffleState, TexasPokerTable,
};
use poker_l1::vm::contracts::texas_poker::utils;
use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::types::ECPoint;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use poker_protocol::zk_shuffle::reconstruction::{
    RECONSTRUCTION_V3_PROOF_LABEL, ReconstructProofV3,
};
use poker_protocol::zk_shuffle::reveal_token_proof::{REVEAL_TOKEN_PROOF_LABEL, RevealTokenProof};
use poker_protocol::zk_shuffle::transcript_ext::{
    CryptoTranscript, FiatShamirTranscript, MerlinTranscript,
};
use poker_texas_air::dual_proof::{
    DUAL_PROOF_MAGIC, DUAL_PROOF_VERSION, DualProofBundle, dual_proof_from_archived,
    prove_dual_proof, verify_dual_proof,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
use rand::rngs::OsRng;

const HEADER_LEN: usize = 20;

fn context(caller: poker_l1::Address) -> DispatchContext {
    DispatchContext {
        caller,
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xA7; 32],
        },
        chain_id: 377,
        block_height: 9_001,
        block_timestamp: 1_900_000,
    }
}

fn dispatch_task(
    pre_table: TexasPokerTable,
    caller: poker_l1::Address,
    selector: [u8; 32],
    raw_args: Vec<u8>,
) -> ProveTask {
    let mut post_table = pre_table;
    let result = texas_dispatch::dispatch(&context(caller), &mut post_table, &selector, &raw_args)
        .expect("valid crypto dispatch should succeed");
    let output: DispatchOutput =
        borsh::from_slice(&result.return_value).expect("dispatch output should decode");
    output.prove_task.expect("state change should emit task")
}

fn shuffle_task(nonce: u64, call_seq: u32) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let input_cards: Vec<_> = (0..8)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(
                format!("dual-proof/shuffle/{nonce}/card/{i}").as_bytes(),
            );
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let permutation = [3, 0, 7, 1, 6, 2, 5, 4];
    let rerandomizers: Vec<_> = (0..input_cards.len())
        .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let output_cards: Vec<_> = (0..input_cards.len())
        .map(|i| input_cards[permutation[i]].re_encrypt(&public_key, &rerandomizers[i]))
        .collect();
    let shuffle_proof = ShuffleProof::prove(
        &input_cards,
        &output_cards,
        &permutation,
        &rerandomizers,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(b"zk_shuffle_proof_v2"),
    )
    .expect("shuffle proof should build");

    let player = [0x31; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xD3; 20], nonce),
        format!("shuffle-{nonce}"),
        [0xC0; 20],
        2,
        50,
        100,
    );
    table.call_seq = call_seq;
    table.hand_id = 7;
    table.version = u64::from(call_seq) + 10;
    table.seats[0].player = player;
    table.seats[0].set_status(SeatStatus::Active);
    table.seats[0].stack = 1_000;
    table.seats[0].pk = ECPoint(public_key);
    table.deck_state.encrypted = input_cards;
    table.deck_state.contributor_mask = 1;
    table.sync_aggregated_pk().unwrap();
    table.shuffle_state = ShuffleState {
        phase: SHUFFLE_PHASE_WAITING,
        current_shuffler: 0,
        pending_mask: (1u16 << (0)),
        completed_mask: 0,
    };
    let raw_args = borsh::to_vec(&SubmitShuffleV2Args {
        seat_index: 0,
        output_cards,
        shuffle_proof,
    })
    .expect("shuffle args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_shuffle_v2(),
        raw_args,
    )
}

fn join_task(nonce: u64, call_seq: u32) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let plaintext_cards = utils::generate_plaintext_cards();
    let input_cards: Vec<_> = plaintext_cards
        .iter()
        .map(|plaintext| ElGamalCiphertextGeneric {
            c1: <Bls12381Curve as Curve>::base_g(),
            c2: *plaintext,
        })
        .collect();
    let mask_cards: Vec<_> = input_cards
        .iter()
        .map(|card| card.remask(&secret_key))
        .collect();
    let remask_proof = DLEqProof::<Bls12381Curve, RemaskKind>::prove(
        &input_cards,
        &mask_cards,
        &secret_key,
        &public_key,
        &mut utils::new_mask_shuffle_transcript(),
    );
    let permutation: Vec<_> = (0..mask_cards.len()).rev().collect();
    let rerandomizers: Vec<_> = (0..mask_cards.len())
        .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let output_cards: Vec<_> = (0..mask_cards.len())
        .map(|index| mask_cards[permutation[index]].re_encrypt(&public_key, &rerandomizers[index]))
        .collect();
    let shuffle_proof = ShuffleProof::prove(
        &mask_cards,
        &output_cards,
        &permutation,
        &rerandomizers,
        &public_key,
        &mut OsRng,
        &mut utils::new_mask_shuffle_transcript(),
    )
    .expect("join shuffle proof should build");

    let player = [0x41; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xC4; 20], nonce),
        format!("join-{nonce}"),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = call_seq;
    table.hand_id = 6;
    table.version = u64::from(call_seq) + 20;
    table.shuffle_state = ShuffleState {
        phase: SHUFFLE_PHASE_WAITING,
        current_shuffler: u8::MAX,
        pending_mask: 0,
        completed_mask: 0,
    };
    let raw_args = borsh::to_vec(&JoinAndShuffleArgs {
        seat_index: 1,
        player,
        buy_in: 2_000,
        pk: ECPoint(public_key),
        pk_ownership_proof: vec![],
        mask_cards,
        output_cards,
        remask_proof,
        shuffle_proof,
    })
    .expect("join args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::join_and_shuffle(),
        raw_args,
    )
}

fn reconstruction_task(nonce: u64) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let cards = utils::generate_plaintext_cards();
    let readable_cards: Vec<_> = [2usize, 5]
        .iter()
        .map(|&i| {
            ElGamalCiphertextGeneric::encrypt(
                &cards[i],
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let player = [0x51; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xE4; 20], nonce),
        format!("reconstruct-{nonce}"),
        [0xC0; 20],
        2,
        50,
        100,
    );
    table.call_seq = 12;
    table.hand_id = 8;
    table.version = 44;
    table.seats[0].player = player;
    table.seats[0].set_status(SeatStatus::Active);
    table.seats[0].stack = 1_000;
    table.seats[0].pk = ECPoint(public_key);
    table.seats[1].player = [0x52; 20];
    table.seats[1].set_status(SeatStatus::Active);
    table.seats[1].stack = 1_000;
    table.deck_state.contributor_mask = 1;
    table.sync_aggregated_pk().unwrap();
    table.deck_state.decrypted_cards = readable_cards
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, ciphertext)| DecryptedCard::partial(index as u8, 0, ciphertext))
        .collect();
    table.round_state = ROUND_TURN;
    table.reveal_token_state.reveal_phase = REVEAL_PHASE_TURN;
    table.timestamps.reconstruct_started_at = 7_000 + nonce;
    table.reconstruct_state = ReconstructState {
        phase: RECONSTRUCT_PHASE_COLLECTING,
        pending_mask: (1u16 << (0)) | (1u16 << (1)),
        coefficient: None,
        accumulated_deck: None,
    };
    let context_digest = utils::reconstruction_v3_context_digest(&table);
    let prior_state_digest = utils::reconstruction_v3_prior_state_digest(&table, 0).unwrap();
    let (statement, proof) = ReconstructProofV3::prove(
        context_digest,
        table.timestamps.reconstruct_started_at,
        prior_state_digest,
        cards,
        readable_cards,
        &secret_key,
        &public_key,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
    )
    .expect("reconstruction V3 proof should build");
    let raw_args = borsh::to_vec(&SubmitReconstructDeckArgs {
        seat_index: 0,
        statement,
        proof,
    })
    .expect("reconstruction args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_reconstruct_deck(),
        raw_args,
    )
}

fn leave_task(nonce: u64) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let input_cards: Vec<_> = (0..52)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(
                format!("dual-proof/leave/{nonce}/card/{i}").as_bytes(),
            );
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let output_cards: Vec<_> = input_cards
        .iter()
        .map(|ciphertext| ElGamalCiphertextGeneric {
            c1: ciphertext.c1,
            c2: ciphertext.decrypt(&secret_key),
        })
        .collect();
    let leave_proof = DLEqProof::<Bls12381Curve, LeaveKind>::prove(
        &input_cards,
        &output_cards,
        &secret_key,
        &public_key,
        &mut utils::new_leave_transcript(),
    );
    let player = [0x61; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xF5; 20], nonce),
        format!("leave-{nonce}"),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = 4;
    table.hand_id = 9;
    table.version = 21;
    table.seats[1].player = player;
    table.seats[1].set_status(SeatStatus::Active);
    table.seats[1].pk = ECPoint(public_key);
    table.deck_state.encrypted = input_cards;
    table.deck_state.contributor_mask = 1u16 << 1;
    table.sync_aggregated_pk().unwrap();
    table.shuffle_state = ShuffleState {
        phase: SHUFFLE_PHASE_WAITING,
        current_shuffler: u8::MAX,
        pending_mask: 0,
        completed_mask: (1u16 << (1)),
    };
    let raw_args = borsh::to_vec(&LeaveWithProofArgs {
        seat_index: 1,
        output_cards,
        leave_proof,
    })
    .expect("leave args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::leave_with_proof(),
        raw_args,
    )
}

fn fold_with_proof_task(nonce: u64, active_players: u8, compound_reset: bool) -> ProveTask {
    assert!((2..=3).contains(&active_players));
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let input_cards: Vec<_> = (0..52)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(
                format!("dual-proof/fold/{nonce}/card/{i}").as_bytes(),
            );
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let output_cards: Vec<_> = input_cards
        .iter()
        .map(|ciphertext| ElGamalCiphertextGeneric {
            c1: ciphertext.c1,
            c2: ciphertext.decrypt(&secret_key),
        })
        .collect();
    let fold_proof = DLEqProof::<Bls12381Curve, LeaveKind>::prove(
        &input_cards,
        &output_cards,
        &secret_key,
        &public_key,
        &mut utils::new_leave_transcript(),
    );
    let player = [0x81; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xD5; 20], nonce),
        format!("fold-{nonce}"),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = 12;
    table.hand_id = 14;
    table.version = 40;
    table.round_state = ROUND_PREFLOP;
    table.betting_round = Some(BettingRound::new(100, 100));
    table.current_turn = 0;
    for index in 0..active_players {
        table.seats[usize::from(index)].player = if index == 0 {
            player
        } else {
            [0x81 + index; 20]
        };
        table.seats[usize::from(index)].set_status(SeatStatus::Active);
        table.seats[usize::from(index)].stack = 1_000;
    }
    if active_players == 2 {
        table.pot = 200;
        table.seats[0].bet = 25;
        table.seats[0].total_bet = 25;
        table.seats[1].bet = 75;
        table.seats[1].total_bet = 75;
    }
    if compound_reset {
        assert_eq!(active_players, 2);
        table.seats[1].pending_addon = 20;
        table.addon_pool = 20;
    }
    table.seats[0].pk = ECPoint(public_key);
    table.deck_state.encrypted = input_cards;
    table.deck_state.contributor_mask = 1;
    table.sync_aggregated_pk().unwrap();
    let raw_args = borsh::to_vec(&FoldWithProofArgs {
        seat_index: 0,
        output_cards,
        fold_proof,
    })
    .expect("fold_with_proof args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::fold_with_proof(),
        raw_args,
    )
}

fn reveal_task(nonce: u64) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let encrypted_cards: Vec<_> = (0..2)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(
                format!("dual-proof/reveal/{nonce}/card/{i}").as_bytes(),
            );
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let reveal_token = encrypted_cards[0].c1 * secret_key;
    let proof = RevealTokenProof::prove(
        &secret_key,
        &public_key,
        &encrypted_cards[0],
        &reveal_token,
        &mut OsRng,
        &mut MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL),
    );
    let player = [0x71; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xA6; 20], nonce),
        format!("reveal-{nonce}"),
        [0xC0; 20],
        3,
        50,
        100,
    );
    table.call_seq = 7;
    table.hand_id = 11;
    table.version = 31;
    table.seats[1].player = player;
    table.seats[1].set_status(SeatStatus::Active);
    table.seats[1].stack = 1_000;
    table.seats[1].pk = ECPoint(public_key);
    table.deck_state.encrypted = encrypted_cards;
    table.deck_state.contributor_mask = 1u16 << 1;
    table.sync_aggregated_pk().unwrap();
    table.reveal_token_state = RevealTokenState {
        reveal_phase: REVEAL_PHASE_PREFLOP,
        assignments: vec![
            RevealAssignment {
                encrypted_card_index: 0,
                target: RevealTarget::Hole {
                    seat_index: 0,
                    card_slot: 0,
                },
                progress: RevealProgress::Collecting {
                    pending_mask: 1u16 << 1,
                    submitted_mask: 0,
                    reveal_tokens: vec![],
                },
            },
            RevealAssignment {
                encrypted_card_index: 1,
                target: RevealTarget::Hole {
                    seat_index: 1,
                    card_slot: 0,
                },
                progress: RevealProgress::Collecting {
                    pending_mask: 1u16,
                    submitted_mask: 0,
                    reveal_tokens: vec![],
                },
            },
        ],
    };
    let raw_args = borsh::to_vec(&SubmitRevealTokensArgs {
        seat_index: 1,
        assignment_indices: vec![0],
        reveal_tokens: vec![ECPoint(reveal_token)],
        proofs: vec![proof],
    })
    .expect("reveal args should encode");
    dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_player_reveal_tokens(),
        raw_args,
    )
}

fn rebuild_wire(template: &DualProofBundle, proof_bytes: &[u8], request_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&DUAL_PROOF_MAGIC);
    bytes.extend_from_slice(&[
        DUAL_PROOF_VERSION,
        template.method_kind() as u8,
        template.precompile_id() as u8,
        template.abi_version(),
    ]);
    bytes.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(request_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(proof_bytes);
    bytes.extend_from_slice(request_bytes);
    bytes
}

#[test]
fn shuffle_dual_package_is_bound_and_not_spliceable_or_replayable() {
    let task_a = shuffle_task(101, 3);
    let task_b = shuffle_task(202, 9);
    let bundle_a = prove_dual_proof(&task_a).expect("shuffle package A should prove");
    let bundle_b = prove_dual_proof(&task_b).expect("shuffle package B should prove");

    let encoded = bundle_a.encode().expect("bundle should encode");
    let decoded = DualProofBundle::decode(&encoded).expect("bundle should strictly decode");
    let accepted = verify_dual_proof(&task_a, &decoded).expect("honest package should verify");
    assert_eq!(accepted.receipt().kind(), MethodKind::SubmitShuffleV2);
    assert_eq!(
        accepted.precompile_binding().request_bytes(),
        decoded.crypto_request_bytes()
    );

    // A legal request from another package cannot replace the crypto half.
    let swapped_request = rebuild_wire(
        &bundle_a,
        bundle_a.stark_proof_bytes(),
        bundle_b.crypto_request_bytes(),
    );
    let swapped_request = DualProofBundle::decode(&swapped_request).unwrap();
    assert!(verify_dual_proof(&task_a, &swapped_request).is_err());

    // A legal Stwo proof from another package cannot replace the method half.
    let swapped_stark = rebuild_wire(
        &bundle_a,
        bundle_b.stark_proof_bytes(),
        bundle_a.crypto_request_bytes(),
    );
    let swapped_stark = DualProofBundle::decode(&swapped_stark).unwrap();
    assert!(verify_dual_proof(&task_a, &swapped_stark).is_err());

    // The complete package cannot be replayed in a different table/call scope.
    assert!(verify_dual_proof(&task_b, &bundle_a).is_err());

    // A one-byte request mutation fails before any package-carried statement is trusted.
    let mut bad_request = bundle_a.crypto_request_bytes().to_vec();
    let last = bad_request.len() - 1;
    bad_request[last] ^= 1;
    let bad_request = rebuild_wire(&bundle_a, bundle_a.stark_proof_bytes(), &bad_request);
    let bad_request = DualProofBundle::decode(&bad_request).unwrap();
    assert!(verify_dual_proof(&task_a, &bad_request).is_err());

    // Trailing data in either the envelope or the inner bincode proof is rejected.
    let mut trailing_envelope = encoded.clone();
    trailing_envelope.push(0);
    assert!(DualProofBundle::decode(&trailing_envelope).is_err());
    let mut trailing_stark = bundle_a.stark_proof_bytes().to_vec();
    trailing_stark.push(0);
    let trailing_stark = rebuild_wire(&bundle_a, &trailing_stark, bundle_a.crypto_request_bytes());
    let trailing_stark = DualProofBundle::decode(&trailing_stark).unwrap();
    assert!(verify_dual_proof(&task_a, &trailing_stark).is_err());
}

#[test]
fn reconstruction_dual_package_roundtrips_and_verifies() {
    let task = reconstruction_task(303);
    let bundle = prove_dual_proof(&task).expect("reconstruction package should prove");
    let encoded = bundle
        .encode()
        .expect("reconstruction package should encode");
    let decoded = DualProofBundle::decode(&encoded).expect("package should decode");
    let accepted = verify_dual_proof(&task, &decoded).expect("both halves should verify");
    assert_eq!(accepted.receipt().kind(), MethodKind::SubmitReconstructDeck);
}

#[test]
fn leave_and_reveal_dual_packages_roundtrip_and_verify() {
    for (task, expected_kind) in [
        (leave_task(305), MethodKind::LeaveWithProof),
        (reveal_task(306), MethodKind::SubmitPlayerRevealTokens),
    ] {
        let bundle = prove_dual_proof(&task).expect("crypto package should prove");
        let encoded = bundle.encode().expect("crypto package should encode");
        let decoded = DualProofBundle::decode(&encoded).expect("crypto package should decode");
        let accepted = verify_dual_proof(&task, &decoded).expect("both proof halves should verify");
        assert_eq!(accepted.receipt().kind(), expected_kind);

        let archived = Orchestrator::new()
            .prove_verify_and_archive_task(&task)
            .expect("crypto method proof should archive");
        let restored_bundle = dual_proof_from_archived(&task, &archived.archive)
            .expect("archive should repackage as a dual proof");
        let restored = verify_dual_proof(&task, &restored_bundle)
            .expect("archive-derived dual proof should verify");
        assert_eq!(restored.receipt().kind(), expected_kind);
    }
}

#[test]
fn fold_with_proof_dual_package_roundtrips_archives_and_rejects_replay() {
    let task = fold_with_proof_task(309, 3, false);
    let bundle = prove_dual_proof(&task).expect("mid-round fold package should prove");
    let encoded = bundle.encode().expect("fold package should encode");
    let decoded = DualProofBundle::decode(&encoded).expect("fold package should decode");
    let accepted =
        verify_dual_proof(&task, &decoded).expect("fold method and DLEq proof should verify");
    assert_eq!(accepted.receipt().kind(), MethodKind::FoldWithProof);

    let archived = Orchestrator::new()
        .prove_verify_and_archive_task(&task)
        .expect("fold method proof should archive");
    let restored_bundle = dual_proof_from_archived(&task, &archived.archive)
        .expect("fold archive should repackage as a dual proof");
    let restored = verify_dual_proof(&task, &restored_bundle)
        .expect("archive-derived fold dual proof should verify");
    assert_eq!(restored.receipt().kind(), MethodKind::FoldWithProof);

    let replay_task = fold_with_proof_task(310, 3, false);
    assert!(verify_dual_proof(&replay_task, &bundle).is_err());
}

#[test]
fn terminal_fold_with_proof_proves_clean_and_compound_settlement() {
    let task = fold_with_proof_task(311, 2, false);
    assert_eq!(task.pre_table.pot, 200);
    assert_eq!(task.post_table.pot, 0);
    assert_eq!(task.post_table.seats[1].stack, 1_300);

    let bundle = prove_dual_proof(&task).expect("terminal fold package should prove");
    let accepted = verify_dual_proof(&task, &bundle)
        .expect("terminal fold method and DLEq proof should verify");
    assert_eq!(accepted.receipt().kind(), MethodKind::FoldWithProof);

    let archived = Orchestrator::new()
        .prove_verify_and_archive_task(&task)
        .expect("terminal fold method proof should archive");
    let restored_bundle = dual_proof_from_archived(&task, &archived.archive)
        .expect("terminal fold archive should repackage as a dual proof");
    verify_dual_proof(&task, &restored_bundle)
        .expect("archive-derived terminal fold dual proof should verify");

    let compound = fold_with_proof_task(312, 2, true);
    let compound_bundle =
        prove_dual_proof(&compound).expect("terminal fold with pending addon should prove");
    verify_dual_proof(&compound, &compound_bundle)
        .expect("compound terminal fold method and DLEq proof should verify");
    let compound_archived = Orchestrator::new()
        .prove_verify_and_archive_task(&compound)
        .expect("compound terminal fold should archive all four component proofs");
    assert!(compound_archived.composition_archive.is_some());
    Orchestrator::verify_archived_proven_task(&compound, &compound_archived)
        .expect("full compound archive should verify method and component proofs");
}

#[test]
fn join_dual_package_roundtrips_archives_and_rejects_replay_or_request_tamper() {
    let task = join_task(307, 5);
    let bundle = prove_dual_proof(&task).expect("join package should prove");
    let encoded = bundle.encode().expect("join package should encode");
    let decoded = DualProofBundle::decode(&encoded).expect("join package should decode");
    let accepted = verify_dual_proof(&task, &decoded).expect("both proof halves should verify");
    assert_eq!(accepted.receipt().kind(), MethodKind::JoinAndShuffle);

    let archived = Orchestrator::new()
        .prove_verify_and_archive_task(&task)
        .expect("join method proof should archive");
    let restored_bundle = dual_proof_from_archived(&task, &archived.archive)
        .expect("join archive should repackage as a dual proof");
    let restored = verify_dual_proof(&task, &restored_bundle)
        .expect("archive-derived join dual proof should verify");
    assert_eq!(restored.receipt().kind(), MethodKind::JoinAndShuffle);

    let replay_task = join_task(308, 8);
    assert!(verify_dual_proof(&replay_task, &bundle).is_err());

    let mut bad_request = bundle.crypto_request_bytes().to_vec();
    let last = bad_request.len() - 1;
    bad_request[last] ^= 1;
    let bad_request = rebuild_wire(&bundle, bundle.stark_proof_bytes(), &bad_request);
    let bad_request = DualProofBundle::decode(&bad_request).unwrap();
    assert!(verify_dual_proof(&task, &bad_request).is_err());
}

#[test]
fn reconstruction_v3_rejects_prior_state_or_readable_hand_substitution() {
    let task = reconstruction_task(304);

    let mut changed_digest = task.clone();
    let mut args: SubmitReconstructDeckArgs = borsh::from_slice(&changed_digest.raw_args).unwrap();
    args.statement.prior_state_digest[0] ^= 1;
    let raw_args = borsh::to_vec(&args).unwrap();
    changed_digest.raw_args = raw_args.clone();
    changed_digest.method_input = poker_texas_air::prove_task::MethodInput::SubmitReconstructDeck {
        seat_index: args.seat_index,
        raw_args,
    };
    assert!(prove_dual_proof(&changed_digest).is_err());

    let mut changed_hand = task;
    let mut args: SubmitReconstructDeckArgs = borsh::from_slice(&changed_hand.raw_args).unwrap();
    args.statement.user_readable_cards.swap(0, 1);
    let raw_args = borsh::to_vec(&args).unwrap();
    changed_hand.raw_args = raw_args.clone();
    changed_hand.method_input = poker_texas_air::prove_task::MethodInput::SubmitReconstructDeck {
        seat_index: args.seat_index,
        raw_args,
    };
    assert!(prove_dual_proof(&changed_hand).is_err());
}

#[test]
fn strict_envelope_rejects_unknown_routes_missing_halves_and_bad_lengths() {
    let task = shuffle_task(404, 1);
    let bundle = prove_dual_proof(&task).expect("fixture should prove");
    let encoded = bundle.encode().unwrap();
    assert_eq!(
        encoded.len(),
        HEADER_LEN + bundle.stark_proof_bytes().len() + bundle.crypto_request_bytes().len()
    );

    let mut unknown_version = encoded.clone();
    unknown_version[8] = DUAL_PROOF_VERSION + 1;
    assert!(DualProofBundle::decode(&unknown_version).is_err());

    let mut wrong_method = encoded.clone();
    wrong_method[9] = MethodKind::SubmitReconstructDeck as u8;
    assert!(DualProofBundle::decode(&wrong_method).is_err());

    let mut wrong_precompile = encoded.clone();
    wrong_precompile[10] = 2;
    assert!(DualProofBundle::decode(&wrong_precompile).is_err());

    let mut wrong_abi = encoded.clone();
    wrong_abi[11] = wrong_abi[11].wrapping_add(1);
    assert!(DualProofBundle::decode(&wrong_abi).is_err());

    let missing_stark = rebuild_wire(&bundle, &[], bundle.crypto_request_bytes());
    assert!(DualProofBundle::decode(&missing_stark).is_err());
    let missing_crypto = rebuild_wire(&bundle, bundle.stark_proof_bytes(), &[]);
    assert!(DualProofBundle::decode(&missing_crypto).is_err());

    let mut oversized = encoded;
    oversized[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(DualProofBundle::decode(&oversized).is_err());
}
