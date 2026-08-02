//! Texas method-proof adaptation for the generic Stwo recursive verifier.
//!
//! This module keeps the dependency direction `poker_texas_air -> poker_zkvm`: it constructs the
//! fixed Texas component and records the exact application transcript, while the lower-level
//! recursive crate remains unaware of poker table types.

#[cfg(not(feature = "recursive-prover"))]
use poker_zkvm::stwo_backend::recursive::recursion_prover::RecursiveProof;
#[cfg(feature = "recursive-prover")]
use poker_zkvm::stwo_backend::recursive::recursion_prover::{
    RecursiveProof, prove_recursive_with_fri,
};
use poker_zkvm::stwo_backend::recursive::{
    RecursivePublicInputs, RecursiveStatementRecorder, RecursiveVerifierProgram,
    build_replicated_row_recursive_public_inputs, verify_replicated_row_with_component,
};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::airs::TexasAir;
use crate::airs::bound::BoundAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::prover::MethodProof;
use crate::public_inputs::TexasPublicInputs;

/// Verify a Texas method proof natively, then derive the complete public statement consumed by
/// the replicated-row recursive verifier program.
///
/// Both `expected_air` and `expected_public_inputs` must be reconstructed from trusted L1 task
/// data. Proof-carried metadata is never used as the source of truth. The returned statement
/// contains the exact `TexasPublicInputs::mix_into` operation sequence, so a later recursive
/// verifier can require byte-for-byte equality with independently reconstructed application data.
///
/// # Errors
///
/// Returns an error if native Texas verification fails, the trusted row is absent/malformed, or
/// the proof does not have the fixed single-component/no-interaction Stwo layout.
pub fn build_method_recursive_public_inputs<A>(
    proof: &MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<RecursivePublicInputs>
where
    A: TexasAir,
{
    crate::verifier::verify_method_against(
        proof.clone(),
        expected_air.clone(),
        expected_public_inputs,
    )?;

    let expected_trace_row =
        expected_public_inputs.require_expected_trace_row(expected_air.trace_num_columns())?;
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        BoundAir::new(expected_air, expected_trace_row),
        SecureField::from(0u32),
    );
    let mut statement_recorder = RecursiveStatementRecorder::default();
    expected_public_inputs.mix_into(&mut statement_recorder);

    build_replicated_row_recursive_public_inputs(
        &proof.stark_proof,
        &component,
        statement_recorder.into_operations(),
    )
    .map_err(|error| TexasAirError::RecursionError(error.to_string()))
}

/// Produce a recursive Stwo proof for one verifier-trusted Texas method statement.
///
/// The returned proof is self-contained with respect to the inner proof: a final verifier only
/// needs this recursive proof, the returned recursive public inputs, and independently
/// reconstructed Texas AIR/public inputs.  The inner [`MethodProof`] is consumed only by the
/// recursive prover.
///
/// # Errors
///
/// Returns an error when native method verification, recursive statement construction, or the
/// recursive Stwo prover fails.
#[cfg(feature = "recursive-prover")]
pub fn prove_method_recursive<A>(
    proof: &MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<(RecursiveProof, RecursivePublicInputs)>
where
    A: TexasAir,
{
    let recursive_inputs =
        build_method_recursive_public_inputs(proof, expected_air, expected_public_inputs)?;
    let recursive_proof = prove_recursive_with_fri(&proof.stark_proof, &recursive_inputs)
        .map_err(|error| TexasAirError::RecursionError(error.to_string()))?;
    Ok((recursive_proof, recursive_inputs))
}

/// Directly verify a recursive Stwo proof against an independently reconstructed Texas method.
///
/// This function deliberately does **not** accept the inner method proof.  It rebuilds the roots,
/// canonical method statement, trusted replicated row, application component, and exact
/// `TexasPublicInputs::mix_into` transcript from verifier-owned data.  The generic recursive
/// verifier then verifies the outer Stwo proof and evaluates the Texas AIR composition claim from
/// the L1 samples bound inside that proof.
///
/// Consensus/task provenance is still an external input: callers must derive `expected_air` and
/// `expected_public_inputs` from an authenticated L1 task or state transition, never from fields
/// supplied by the prover.
///
/// # Errors
///
/// Returns an error if the trusted Texas statement is malformed, differs from the statement bound
/// by the recursive proof, or the recursive Stwo proof fails verification.
pub fn verify_method_recursive_proof<A>(
    recursive_proof: &RecursiveProof,
    recursive_inputs: &RecursivePublicInputs,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<()>
where
    A: TexasAir,
{
    let statement = expected_air.statement();
    if !statement.kind.is_production_air_enabled() {
        return Err(TexasAirError::NotImplemented(format!(
            "{} is a registered selector without an enabled production AIR",
            statement.kind.method_name()
        )));
    }
    expected_public_inputs.verify_roots()?;
    expected_public_inputs.verify_air_statement(&statement)?;
    expected_air.validate_public_inputs(expected_public_inputs)?;

    let expected_trace_row =
        expected_public_inputs.require_expected_trace_row(expected_air.trace_num_columns())?;
    let mut statement_recorder = RecursiveStatementRecorder::default();
    expected_public_inputs.mix_into(&mut statement_recorder);
    if recursive_inputs.verifier_program != RecursiveVerifierProgram::ReplicatedRowV1
        || recursive_inputs.statement_transcript != statement_recorder.into_operations()
    {
        return Err(TexasAirError::RecursionError(
            "recursive statement transcript does not match verifier-trusted Texas inputs".into(),
        ));
    }

    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        BoundAir::new(expected_air, expected_trace_row),
        SecureField::from(0u32),
    );
    verify_replicated_row_with_component(recursive_proof, recursive_inputs, &component)
        .map_err(|error| TexasAirError::RecursionError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::M31;
    use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

    use super::*;
    use crate::airs::AirStatement;
    use crate::method_kind::MethodKind;
    use crate::prover::prove_method;
    use crate::trace_gen::MethodTrace;

    #[derive(Debug, Clone)]
    struct TestAir {
        statement: AirStatement,
        log_size: u32,
    }

    impl FrameworkEval for TestAir {
        fn log_size(&self) -> u32 {
            self.log_size
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            self.log_size + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let left = eval.next_trace_mask();
            let right = eval.next_trace_mask();
            eval.add_constraint(left - right);
            eval
        }
    }

    impl TexasAir for TestAir {
        fn statement(&self) -> AirStatement {
            self.statement.clone()
        }

        fn trace_num_columns(&self) -> usize {
            2
        }
    }

    #[test]
    fn texas_statement_builds_replicated_row_recursive_inputs() {
        let log_size = 8;
        let mut public_inputs = TexasPublicInputs::synthetic_for_test(MethodKind::Fold, 42, 3, 9);
        public_inputs.pre_version = 7;
        public_inputs.post_version = 8;
        let (pre_state_root, post_state_root) =
            TexasPublicInputs::synthetic_air_roots(MethodKind::Fold);
        let air = TestAir {
            statement: AirStatement {
                kind: MethodKind::Fold,
                pre_state_root,
                post_state_root,
                table_id: 42,
                hand_id: 3,
                call_seq: 9,
                pre_version: 7,
                post_version: 8,
            },
            log_size,
        };
        let row = [M31::from(11u32), M31::from(11u32)];
        public_inputs.bind_expected_trace_row(&row).unwrap();
        let mut trace = MethodTrace::new(log_size, 2);
        trace
            .write_active_with_padding(&row, &[M31::from(0u32); 2])
            .unwrap();
        let proof = prove_method(&trace, air.clone(), 2, public_inputs.clone()).unwrap();

        let recursive_inputs =
            build_method_recursive_public_inputs(&proof, air, &public_inputs).unwrap();

        assert_eq!(
            recursive_inputs.verifier_program,
            poker_zkvm::stwo_backend::recursive::RecursiveVerifierProgram::ReplicatedRowV1
        );
        assert!(!recursive_inputs.statement_transcript.is_empty());
        assert_eq!(
            recursive_inputs.l1_tree_metadata[1].column_log_sizes.len(),
            2
        );
    }

    #[cfg(feature = "recursive-prover")]
    #[test]
    #[ignore = "recursive Stwo proving is intentionally expensive"]
    fn texas_recursive_proof_verifies_without_inner_proof_and_rejects_relabeling() {
        let log_size = 8;
        let mut public_inputs = TexasPublicInputs::synthetic_for_test(MethodKind::Fold, 42, 3, 9);
        public_inputs.pre_version = 7;
        public_inputs.post_version = 8;
        public_inputs.dispatch_call_digest = [0x5a; 32];
        let (pre_state_root, post_state_root) =
            TexasPublicInputs::synthetic_air_roots(MethodKind::Fold);
        let air = TestAir {
            statement: AirStatement {
                kind: MethodKind::Fold,
                pre_state_root,
                post_state_root,
                table_id: 42,
                hand_id: 3,
                call_seq: 9,
                pre_version: 7,
                post_version: 8,
            },
            log_size,
        };
        let row = [M31::from(11u32), M31::from(11u32)];
        public_inputs.bind_expected_trace_row(&row).unwrap();
        let mut trace = MethodTrace::new(log_size, 2);
        trace
            .write_active_with_padding(&row, &[M31::from(0u32); 2])
            .unwrap();
        let method_proof = prove_method(&trace, air.clone(), 2, public_inputs.clone()).unwrap();

        let (recursive_proof, recursive_inputs) =
            prove_method_recursive(&method_proof, air.clone(), &public_inputs).unwrap();
        drop(method_proof);

        verify_method_recursive_proof(
            &recursive_proof,
            &recursive_inputs,
            air.clone(),
            &public_inputs,
        )
        .expect("recursive proof must verify without the inner method proof");

        let mut relabeled_statement = public_inputs.clone();
        relabeled_statement.dispatch_call_digest[0] ^= 1;
        assert!(
            verify_method_recursive_proof(
                &recursive_proof,
                &recursive_inputs,
                air.clone(),
                &relabeled_statement,
            )
            .is_err(),
            "a different trusted Texas transcript must be rejected"
        );

        let mut relabeled_recursive_inputs = recursive_inputs.clone();
        relabeled_recursive_inputs.verifier_program = RecursiveVerifierProgram::CpuV1;
        assert!(
            verify_method_recursive_proof(
                &recursive_proof,
                &relabeled_recursive_inputs,
                air,
                &public_inputs,
            )
            .is_err(),
            "a different recursive verifier program must be rejected"
        );
    }
}
