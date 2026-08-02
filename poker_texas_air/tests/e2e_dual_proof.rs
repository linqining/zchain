//! Stage-3 two-part proof package tests.

use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::constants::{
    RECONSTRUCT_PHASE_COLLECTING, SHUFFLE_PHASE_WAITING,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    self as texas_dispatch, SubmitReconstructDeckArgs, SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::types::{
    DecryptedCard, ReconstructState, ShuffleState, TexasPokerTable,
};
use poker_l1::vm::contracts::texas_poker::utils;
use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::types::ECPoint;
use poker_protocol::zk_shuffle::reconstruction::{
    ReconstructProofV3, RECONSTRUCTION_V3_PROOF_LABEL,
};
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_texas_air::dual_proof::{
    prove_dual_proof, verify_dual_proof, DualProofBundle, DUAL_PROOF_MAGIC, DUAL_PROOF_VERSION,
};
use poker_texas_air::method_kind::MethodKind;
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
    table.seats[0].stack = 1_000;
    table.seats[0].pk = ECPoint(public_key);
    table.deck_state.encrypted = input_cards;
    table.deck_state.aggregated_pk = Some(ECPoint(public_key));
    table.shuffle_state = ShuffleState {
        phase: SHUFFLE_PHASE_WAITING,
        current_shuffler: Some(0),
        pending_players: vec![0],
        completed_players: vec![],
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

fn reconstruction_task(nonce: u64) -> ProveTask {
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let cards: Vec<_> = (0..8)
        .map(|i| {
            Bls12381Curve::hash_to_curve(
                format!("dual-proof/reconstruct/{nonce}/card/{i}").as_bytes(),
            )
        })
        .collect();
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
    table.seats[0].stack = 1_000;
    table.seats[0].pk = ECPoint(public_key);
    table.seats[1].player = [0x52; 20];
    table.seats[1].stack = 1_000;
    table.deck_state.plaintext = cards.iter().copied().map(ECPoint).collect();
    table.deck_state.aggregated_pk = Some(ECPoint(public_key));
    table.deck_state.decrypted_cards = readable_cards
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, ciphertext)| DecryptedCard {
            encrypted_card_index: index as u8,
            owner_seat_index: 0,
            ciphertext: Some(ciphertext),
            plaintext: None,
        })
        .collect();
    table.timestamps.reconstruct_started_at = 7_000 + nonce;
    table.reconstruct_state = ReconstructState {
        phase: RECONSTRUCT_PHASE_COLLECTING,
        pending_players: vec![0, 1],
        coefficient: None,
        player_decks: vec![],
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
