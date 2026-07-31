//! Audit regression for the experimental recursive backend production gate.
//!
//! Transcript binding prevents an existing proof from being relabelled, but the
//! current verifier AIR still does not fully constrain the L1 Merkle/FRI proof.
//! Cross-crate callers must therefore fail closed instead of accepting the PoC.

use poker_zkvm::stwo_backend::prover::prove_cpu_trace;
use poker_zkvm::stwo_backend::recursive::public_inputs::RecursivePublicInputs;
use poker_zkvm::stwo_backend::recursive::recursion_prover::{
    RecursionProvingError, prove_recursive_with_fri,
};
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
fn recursive_backend_is_disabled_for_cross_crate_callers() {
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

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(matches!(
        result,
        Err(RecursionProvingError::UnsoundBackendDisabled)
    ));
}
