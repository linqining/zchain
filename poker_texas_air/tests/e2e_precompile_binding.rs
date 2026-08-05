//! Production-path tests for shuffle precompile request/receipt binding.

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
use poker_protocol::precompile::{
    build_bls12381_reconstruction_v3_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::TranscriptId;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::reconstruction::{
    RECONSTRUCTION_V3_PROOF_LABEL, ReconstructProofV3,
};
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_texas_air::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use poker_texas_air::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::precompile_binding::{PrecompileCallBinding, precompile_call_context};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
use poker_texas_air::prover::{MethodProof, prove_method};
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::state_root_to_air_limbs;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method_against;
use rand::rngs::OsRng;

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

fn canonical_public_inputs(task: &ProveTask) -> TexasPublicInputs {
    let mut public_inputs = TexasPublicInputs::from_tables(
        &task.pre_table,
        &task.post_table,
        task.method_kind,
        task.table_id,
        task.hand_id,
        task.call_seq,
    )
    .expect("canonical public inputs should build");
    public_inputs
        .bind_dispatch_call(task.context.clone(), task.selector, task.raw_args.clone())
        .expect("dispatch call should bind");
    public_inputs
}

fn fixture(
    statement_call_seq: u32,
    request_scope_call_seq: u32,
) -> (
    MethodProof<SubmitShuffleV2Air>,
    SubmitShuffleV2Air,
    TexasPublicInputs,
) {
    let table_id = 42;
    let hand_id = 7;
    let seat_index = 2;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let input_cards: Vec<_> = (0..8)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(format!("air-binding/card/{i}").as_bytes());
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
    let transcript_context = b"zk_shuffle_proof_v2";
    let shuffle_proof = ShuffleProof::prove(
        &input_cards,
        &output_cards,
        &permutation,
        &rerandomizers,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(transcript_context),
    )
    .unwrap();

    let player = [0x31; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xD3; 20], table_id),
        "precompile-binding-shuffle".into(),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = statement_call_seq
        .checked_sub(1)
        .expect("statement call sequence must be non-zero");
    table.hand_id = hand_id;
    table.version = 10;
    table.seats[usize::from(seat_index)].player = player;
    table.seats[usize::from(seat_index)].stack = 1_000;
    table.seats[usize::from(seat_index)].pk = ECPoint(public_key);
    table.deck_state.encrypted = input_cards.clone();
    table.deck_state.aggregated_pk = Some(ECPoint(public_key));
    table.shuffle_state = ShuffleState {
        phase: SHUFFLE_PHASE_WAITING,
        current_shuffler: Some(seat_index),
        pending_players: vec![seat_index],
        completed_players: vec![],
    };
    let raw_args = borsh::to_vec(&SubmitShuffleV2Args {
        seat_index,
        output_cards: output_cards.clone(),
        shuffle_proof: shuffle_proof.clone(),
    })
    .expect("shuffle args should encode");
    let task = dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_shuffle_v2(),
        raw_args,
    );
    assert_eq!(task.call_seq, statement_call_seq);
    let mut public_inputs = canonical_public_inputs(&task);

    let call_context = precompile_call_context(
        MethodKind::SubmitShuffleV2,
        seat_index,
        table_id,
        hand_id,
        request_scope_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let request = build_bls12381_shuffle_request(
        transcript_context,
        &call_context,
        TranscriptId::FiatShamirSha3,
        &public_key,
        &input_cards,
        &output_cards,
        &shuffle_proof,
    )
    .unwrap();
    let binding = PrecompileCallBinding::verify_shuffle(&request).unwrap();
    let input = SubmitShuffleV2Input {
        seat_index,
        new_deck_commitment: task.post_table.deck_state.encrypted.len() as u64,
        shuffle_phase: task.pre_table.shuffle_state.phase,
        precompile: binding.air_binding(),
    };
    let pre_root = state_root_to_air_limbs(public_inputs.pre_state_root);
    let post_root = state_root_to_air_limbs(public_inputs.post_state_root);
    let row = SubmitShuffleV2Row::active(
        &input,
        pre_root,
        post_root,
        table_id,
        hand_id,
        statement_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        u8::try_from(task.post_table.shuffle_state.completed_players.len())
            .expect("completed player count should fit u8"),
    );
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .unwrap();
    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: pre_root,
        post_state_root: post_root,
        table_id,
        hand_id,
        call_seq: statement_call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    public_inputs.precompile_binding = Some(binding);
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let proof = prove_method(
        &trace,
        air.clone(),
        SubmitShuffleV2Air::num_columns(),
        public_inputs.clone(),
    )
    .unwrap();
    (proof, air, public_inputs)
}

#[test]
fn honest_verified_request_and_receipt_are_bound_to_the_air() {
    let (proof, air, public_inputs) = fixture(3, 3);
    verify_method_against(proof, air, &public_inputs).unwrap();
}

#[test]
fn bare_air_success_without_a_verifier_binding_fails_closed() {
    let (proof, air, mut public_inputs) = fixture(3, 3);
    public_inputs.precompile_binding = None;
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn valid_crypto_receipt_cannot_be_replayed_at_another_call_sequence() {
    let (proof, air, public_inputs) = fixture(3, 4);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn changing_a_receipt_digest_limb_invalidates_the_statement() {
    let (proof, mut air, public_inputs) = fixture(3, 3);
    air.input.precompile.receipt_digest[15] += stwo::core::fields::m31::M31::from(1u32);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn changing_a_request_digest_limb_invalidates_the_statement() {
    let (proof, mut air, public_inputs) = fixture(3, 3);
    air.input.precompile.request_digest[0] += stwo::core::fields::m31::M31::from(1u32);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn honest_reconstruction_v3_receipt_is_bound_to_the_air() {
    let table_id = 51;
    let hand_id = 8;
    let call_seq = 6;
    let seat_index = 1;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let cards: Vec<_> = (0..8)
        .map(|i| Bls12381Curve::hash_to_curve(format!("air-reconstruct/card/{i}").as_bytes()))
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
        ObjectID::new([0xE4; 20], table_id),
        "precompile-binding-reconstruct".into(),
        [0xC0; 20],
        2,
        50,
        100,
    );
    table.call_seq = call_seq - 1;
    table.hand_id = hand_id;
    table.version = 44;
    table.seats[0].player = [0x52; 20];
    table.seats[0].stack = 1_000;
    table.seats[1].player = player;
    table.seats[1].stack = 1_000;
    table.seats[1].pk = ECPoint(public_key);
    table.deck_state.plaintext = cards.iter().copied().map(ECPoint).collect();
    table.deck_state.aggregated_pk = Some(ECPoint(public_key));
    table.deck_state.decrypted_cards = readable_cards
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, ciphertext)| DecryptedCard {
            encrypted_card_index: index as u8,
            owner_seat_index: seat_index,
            ciphertext: Some(ciphertext),
            plaintext: None,
        })
        .collect();
    table.timestamps.reconstruct_started_at = 9;
    table.reconstruct_state = ReconstructState {
        phase: RECONSTRUCT_PHASE_COLLECTING,
        pending_players: vec![0, seat_index],
        coefficient: None,
        player_decks: vec![],
    };
    let context_digest = utils::reconstruction_v3_context_digest(&table);
    let prior_state_digest =
        utils::reconstruction_v3_prior_state_digest(&table, seat_index).unwrap();
    let (statement, reconstruction_proof) = ReconstructProofV3::prove(
        context_digest,
        table.timestamps.reconstruct_started_at,
        prior_state_digest,
        cards.clone(),
        readable_cards.clone(),
        &secret_key,
        &public_key,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
    )
    .unwrap();
    let raw_args = borsh::to_vec(&SubmitReconstructDeckArgs {
        seat_index,
        statement: statement.clone(),
        proof: reconstruction_proof.clone(),
    })
    .expect("reconstruction args should encode");
    let task = dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_reconstruct_deck(),
        raw_args,
    );
    assert_eq!(task.call_seq, call_seq);
    let mut public_inputs = canonical_public_inputs(&task);

    let call_context = precompile_call_context(
        MethodKind::SubmitReconstructDeck,
        seat_index,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let request = build_bls12381_reconstruction_v3_request(
        RECONSTRUCTION_V3_PROOF_LABEL,
        &call_context,
        TranscriptId::FiatShamirSha3,
        &statement,
        &reconstruction_proof,
    )
    .unwrap();
    let binding = PrecompileCallBinding::verify_reconstruction_v3(&request).unwrap();
    let input = SubmitReconstructDeckInput {
        seat_index,
        reconstruct_phase: task.pre_table.reconstruct_state.phase,
        precompile: binding.air_binding(),
    };
    let pre_root = state_root_to_air_limbs(public_inputs.pre_state_root);
    let post_root = state_root_to_air_limbs(public_inputs.post_state_root);
    let row = SubmitReconstructDeckRow::active(
        &input,
        pre_root,
        post_root,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        u8::try_from(task.post_table.reconstruct_state.player_decks.len())
            .expect("submitted deck count should fit u8"),
    );
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .unwrap();
    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: pre_root,
        post_state_root: post_root,
        table_id,
        hand_id,
        call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    public_inputs.precompile_binding = Some(binding);
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let proof = prove_method(
        &trace,
        air.clone(),
        SubmitReconstructDeckAir::num_columns(),
        public_inputs.clone(),
    )
    .unwrap();
    verify_method_against(proof, air, &public_inputs).unwrap();
}
