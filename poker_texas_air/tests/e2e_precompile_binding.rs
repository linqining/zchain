//! Production-path tests for shuffle precompile request/receipt binding.

use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::precompile::{
    build_bls12381_reconstruction_v3_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::TranscriptId;
use poker_protocol::zk_shuffle::reconstruction::{
    ReconstructProofV3, RECONSTRUCTION_V3_PROOF_LABEL,
};
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_texas_air::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use poker_texas_air::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::precompile_binding::{precompile_call_context, PrecompileCallBinding};
use poker_texas_air::prover::{prove_method, MethodProof};
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::state_root_to_air_limbs;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method_against;
use rand::rngs::OsRng;

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
    let mut public_inputs = TexasPublicInputs::synthetic_for_test(
        MethodKind::SubmitShuffleV2,
        table_id,
        hand_id,
        statement_call_seq,
    );
    public_inputs.dispatch_call_digest = [0xA5; 32];

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
        new_deck_commitment: output_cards.len() as u64,
        shuffle_phase: 1,
        precompile: binding.air_binding(),
    };
    let roots = state_root_to_air_limbs(public_inputs.pre_state_root);
    let row = SubmitShuffleV2Row::active(
        &input,
        roots,
        roots,
        table_id,
        hand_id,
        statement_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        1,
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
        pre_state_root: roots,
        post_state_root: roots,
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
    let mut public_inputs = TexasPublicInputs::synthetic_for_test(
        MethodKind::SubmitReconstructDeck,
        table_id,
        hand_id,
        call_seq,
    );
    public_inputs.dispatch_call_digest = [0x5A; 32];

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
    let (statement, reconstruction_proof) = ReconstructProofV3::prove(
        [0x11; 32],
        9,
        [0x22; 32],
        cards,
        readable_cards,
        &secret_key,
        &public_key,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
    )
    .unwrap();
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
        reconstruct_phase: 1,
        precompile: binding.air_binding(),
    };
    let roots = state_root_to_air_limbs(public_inputs.pre_state_root);
    let row = SubmitReconstructDeckRow::active(
        &input,
        roots,
        roots,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        1,
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
        pre_state_root: roots,
        post_state_root: roots,
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
