//! Audit regression for recursive public-input Fiat–Shamir binding.
//!
//! Every field advertised as part of the L1 recursive statement must affect the
//! L2 transcript. A proof created for one statement must not verify after any
//! commitment, query position, or trace-size field is replaced.

use poker_zkvm::stwo_backend::prover::prove_cpu_trace;
use poker_zkvm::stwo_backend::recursive::public_inputs::RecursivePublicInputs;
use poker_zkvm::stwo_backend::recursive::recursion_prover::prove_recursive_with_fri;
use poker_zkvm::stwo_backend::recursive::recursion_verifier::verify_recursive_with_fri;
use poker_zkvm::stwo_backend::recursive::trace_gen::{
    extract_composition_oods_eval_from_l1, extract_fri_query_from_l1,
};
use poker_zkvm::stwo_backend::trace_native::TraceBuilder;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;

const TEST_OODS_POINT: CirclePoint<SecureField> = CirclePoint {
    x: SecureField::from_u32_unchecked(1, 0, 0, 0),
    y: SecureField::from_u32_unchecked(0, 1, 0, 0),
};

#[test]
fn recursive_verifier_rejects_tampered_commitments_and_queries() {
    let log_size = 8;
    let mut builder = TraceBuilder::new(log_size);
    builder.fill_padding_to_full();
    let l1_proof = prove_cpu_trace(&builder.finalize()).expect("L1 prove should succeed");

    let composition_oods_eval =
        extract_composition_oods_eval_from_l1(&l1_proof, TEST_OODS_POINT, log_size)
            .expect("composition OODS extraction should succeed");
    let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
    let (fri_query_x, fri_query_eval) =
        extract_fri_query_from_l1(&l1_proof, PcsConfig::default(), log_size, &last_layer_poly)
            .expect("FRI query extraction should succeed");

    // This mirrors the recursive backend's own E2E setup: no commitments or
    // query positions are supplied, so its Merkle component is an all-zero
    // placeholder trace.
    let public_inputs = RecursivePublicInputs::new(
        Vec::new(),
        TEST_OODS_POINT,
        composition_oods_eval,
        FieldElement252::ZERO,
        last_layer_poly,
        log_size,
        PcsConfig::default(),
        Vec::new(),
        log_size,
        fri_query_x,
        fri_query_eval,
    );

    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs)
        .expect("recursive PoC prove should succeed");
    verify_recursive_with_fri(&l2_proof, &public_inputs)
        .expect("baseline recursive PoC proof should verify");

    let mut changed_l1_commitments = public_inputs.clone();
    changed_l1_commitments.l1_commitments = vec![FieldElement252::ONE];
    let mut changed_fri_commitment = public_inputs.clone();
    changed_fri_commitment.fri_first_layer_commitment = FieldElement252::ONE;
    let mut changed_queries = public_inputs.clone();
    changed_queries.query_positions = vec![1, 3, 7, 15];
    let mut changed_log_size = public_inputs.clone();
    changed_log_size.log_size = log_size + 7;

    for (name, tampered) in [
        ("l1_commitments", changed_l1_commitments),
        ("fri_first_layer_commitment", changed_fri_commitment),
        ("query_positions", changed_queries),
        ("log_size", changed_log_size),
    ] {
        assert!(
            verify_recursive_with_fri(&l2_proof, &tampered).is_err(),
            "recursive verifier accepted proof after tampering {name}"
        );
    }
}
