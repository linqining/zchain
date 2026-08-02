//! L1 registry adapter for Texas recursive STWO proofs.
//!
//! This module lives in `poker_texas_air` (which already depends on `poker_l1`) to avoid a Cargo
//! dependency cycle. A node binary can register [`TexasStwoRecursiveVerifier`] in the L1 registry;
//! registration replaces the generic scheme-1 fail-closed placeholder with the application-aware
//! verifier.

use std::sync::Arc;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use poker_l1::error::PokerL1Error;
use poker_l1::offline::zk_verifier::{
    SCHEME_STWO, SchemeId, VerifierStatus, ZkPublicIo, ZkVerifier, ZkVerifierRegistry,
    ZkVerifyResult,
};

use crate::orchestrator::Orchestrator;
use crate::prove_task::{ProveTask, dispatch_call_digest};
use crate::recursive_envelope::TexasRecursiveProofEnvelope;
use crate::state_root::compute_state_root;
use crate::verified_chain::ExpectedChainAnchor;

/// Application-aware scheme-1 verifier for one Texas method recursive proof.
#[derive(Debug, Default)]
pub struct TexasStwoRecursiveVerifier;

impl TexasStwoRecursiveVerifier {
    /// Construct the stateless verifier adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ZkVerifier for TexasStwoRecursiveVerifier {
    fn scheme_id(&self) -> SchemeId {
        SCHEME_STWO
    }

    fn verify(
        &self,
        proof: &[u8],
        public_io: &ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        let envelope = decode_envelope(proof)?;
        if status == VerifierStatus::Stub {
            return Ok(true);
        }

        let expected_public_io = texas_recursive_public_io(envelope.task()).map_err(|error| {
            PokerL1Error::InvalidZkPublicIo(format!(
                "cannot reconstruct Texas recursive public I/O: {error}"
            ))
        })?;
        if &expected_public_io != public_io {
            return Ok(false);
        }

        Ok(Orchestrator::verify_recursive_task(
            envelope.task(),
            envelope.recursive_proof(),
            envelope.recursive_inputs(),
        )
        .is_ok())
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        let envelope = decode_envelope(proof)?;
        if !envelope.task().method_kind.is_production_air_enabled() {
            return Err(PokerL1Error::InvalidZkProofFormat(format!(
                "Texas selector {} has no enabled production AIR",
                envelope.task().method_kind.method_name()
            )));
        }
        if envelope.recursive_inputs().verifier_program
            != poker_zkvm::stwo_backend::recursive::RecursiveVerifierProgram::ReplicatedRowV1
        {
            return Err(PokerL1Error::InvalidZkProofFormat(
                "Texas recursive envelope must use ReplicatedRowV1".into(),
            ));
        }
        Ok(())
    }
}

/// Replace the generic scheme-1 placeholder with the Texas application-aware verifier.
///
/// # Errors
///
/// Returns [`PokerL1Error::ZkVerifierCapabilityDisabled`] when this crate was built without the
/// `recursive-verifier` capability. This prevents a node from silently registering an adapter
/// whose lower-level recursive verifier is compile-time disabled.
pub fn register_texas_stwo_recursive_verifier(
    registry: &mut ZkVerifierRegistry,
) -> Result<(), PokerL1Error> {
    if !cfg!(feature = "recursive-verifier") {
        return Err(PokerL1Error::ZkVerifierCapabilityDisabled {
            scheme_id: SCHEME_STWO,
            capability: "recursive-verifier",
        });
    }
    registry.register(Arc::new(TexasStwoRecursiveVerifier::new()));
    Ok(())
}

/// Verify an envelope against a Texas transition obtained from an authenticated L1 dispatch.
///
/// Unlike the generic RPC/syscall primitive, this boundary does not accept caller-selected public
/// I/O. The caller supplies the task recovered from consensus execution, this function requires
/// the envelope to carry that exact task, derives public I/O from the authenticated task, and then
/// invokes the registered Production verifier. Stub mode is rejected instead of treating format
/// validation as proof acceptance.
///
/// # Errors
///
/// Returns an error if the verifier is not in Production, the envelope and authenticated task do
/// not match byte-for-byte, public I/O reconstruction fails, or registry verification fails.
pub fn verify_authenticated_texas_recursive_transition(
    registry: &ZkVerifierRegistry,
    chain_id: poker_l1::ChainId,
    encoded_envelope: &[u8],
    authenticated_task: &ProveTask,
) -> Result<ZkVerifyResult, PokerL1Error> {
    if registry.verifier_status(chain_id) != VerifierStatus::Production {
        return Err(PokerL1Error::ZkVerifierNotProduction {
            chain_id,
            scheme_id: SCHEME_STWO,
        });
    }

    let envelope = decode_envelope(encoded_envelope)?;
    let envelope_task = borsh::to_vec(envelope.task()).map_err(|error| {
        PokerL1Error::InvalidZkProofFormat(format!(
            "encode envelope Texas task for authenticated comparison: {error}"
        ))
    })?;
    let trusted_task = borsh::to_vec(authenticated_task).map_err(|error| {
        PokerL1Error::InvalidZkPublicIo(format!(
            "encode authenticated Texas task for comparison: {error}"
        ))
    })?;
    if envelope_task != trusted_task {
        return Err(PokerL1Error::InvalidZkPublicIo(
            "recursive envelope task does not match the authenticated L1 dispatch task".into(),
        ));
    }

    let public_io = texas_recursive_public_io(authenticated_task).map_err(|error| {
        PokerL1Error::InvalidZkPublicIo(format!(
            "cannot reconstruct authenticated Texas recursive public I/O: {error}"
        ))
    })?;
    registry.zk_verify(chain_id, SCHEME_STWO, encoded_envelope, &public_io, 0, 1)
}

/// Verify one recursive proof against a cryptographically authenticated consensus anchor.
///
/// The anchor is expected to come from [`crate::consensus_anchor::build_anchor_from_consensus`].
/// It must describe exactly one Texas dispatch; all endpoint roots, versions, method sequence,
/// table/hand identifiers, and the transaction-derived dispatch digest are checked before proof
/// verification.
///
/// # Errors
///
/// Returns an error when the task is not the exact single transition authenticated by `anchor`,
/// or when the lower-level authenticated transition verifier fails.
pub fn verify_consensus_anchored_texas_recursive_transition(
    registry: &ZkVerifierRegistry,
    chain_id: poker_l1::ChainId,
    encoded_envelope: &[u8],
    authenticated_task: &ProveTask,
    anchor: &ExpectedChainAnchor,
) -> Result<ZkVerifyResult, PokerL1Error> {
    validate_task_against_single_step_anchor(authenticated_task, anchor)?;
    verify_authenticated_texas_recursive_transition(
        registry,
        chain_id,
        encoded_envelope,
        authenticated_task,
    )
}

fn validate_task_against_single_step_anchor(
    task: &ProveTask,
    anchor: &ExpectedChainAnchor,
) -> Result<(), PokerL1Error> {
    let pre_root = compute_state_root(&task.pre_table).map_err(|error| {
        PokerL1Error::InvalidZkPublicIo(format!("compute anchored Texas pre-state root: {error}"))
    })?;
    let post_root = compute_state_root(&task.post_table).map_err(|error| {
        PokerL1Error::InvalidZkPublicIo(format!("compute anchored Texas post-state root: {error}"))
    })?;
    let digest =
        dispatch_call_digest(&task.context, &task.selector, &task.raw_args).map_err(|error| {
            PokerL1Error::InvalidZkPublicIo(format!(
                "compute anchored Texas dispatch digest: {error}"
            ))
        })?;
    let matches = anchor.dispatch_call_digests() == [digest]
        && anchor.table_id() == task.table_id
        && anchor.hand_id() == task.hand_id
        && anchor.first_call_seq() == task.call_seq
        && anchor.last_call_seq_public() == task.call_seq
        && anchor.pre_state_root() == pre_root
        && anchor.post_state_root() == post_root
        && anchor.pre_version() == task.pre_table.version
        && anchor.post_version() == task.post_table.version;
    if !matches {
        return Err(PokerL1Error::InvalidZkPublicIo(
            "Texas recursive task does not match the authenticated single-step consensus anchor"
                .into(),
        ));
    }
    Ok(())
}

/// Reconstruct the exact L1 public-I/O boundary for one Texas method task.
///
/// Production callers must source this value from authenticated L1 state/transaction data. The
/// verifier independently recomputes the same value from the envelope task only for equality
/// checking; accepting a `ZkPublicIo` copied from an unauthenticated envelope would forfeit the
/// intended trust boundary.
///
/// Mapping:
/// - initial/final commitments = full-width Poseidon252 table roots;
/// - state-delta hash = exact dispatch context/selector/args digest;
/// - ack-chain hash = domain-separated Texas method metadata commitment;
/// - one recursive envelope proves exactly one method step, with no skipped/continuity segments.
///
/// # Errors
///
/// Returns an error when table roots or the dispatch digest cannot be reconstructed.
pub fn texas_recursive_public_io(task: &ProveTask) -> crate::error::TexasAirResult<ZkPublicIo> {
    let pre_root = compute_state_root(&task.pre_table)?;
    let post_root = compute_state_root(&task.post_table)?;
    let call_digest = dispatch_call_digest(&task.context, &task.selector, &task.raw_args)?;

    let mut metadata = Vec::with_capacity(64);
    metadata.extend_from_slice(b"zchain.texas_poker.recursive_public_io.v1");
    metadata.push(task.method_kind as u8);
    metadata.extend_from_slice(&task.table_id.to_be_bytes());
    metadata.extend_from_slice(&task.hand_id.to_be_bytes());
    metadata.extend_from_slice(&task.call_seq.to_be_bytes());
    metadata.extend_from_slice(&task.pre_table.version.to_be_bytes());
    metadata.extend_from_slice(&task.post_table.version.to_be_bytes());
    metadata.extend_from_slice(&task.selector);
    let ack_chain_hash = blake2b_256(&metadata);

    Ok(ZkPublicIo {
        initial_commitment: pre_root.field().to_bytes_be(),
        final_commitment: post_root.field().to_bytes_be(),
        state_delta_hash: call_digest,
        ack_chain_hash,
        fold_step_count: 1,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    })
}

fn decode_envelope(proof: &[u8]) -> Result<TexasRecursiveProofEnvelope, PokerL1Error> {
    TexasRecursiveProofEnvelope::decode(proof).map_err(|error| {
        PokerL1Error::InvalidZkProofFormat(format!("decode Texas recursive STWO envelope: {error}"))
    })
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(input);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_kind::MethodKind;
    use poker_l1::object_model::ObjectID;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::vm::contracts::dispatch::DispatchContext;
    use poker_l1::vm::contracts::texas_poker::dispatch::{SeatIndexArgs, selectors};
    use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
    use vm_common::prove_task::MethodInput;

    fn fold_task() -> ProveTask {
        let mut pre = TexasPokerTable::new(
            ObjectID::new([0x11; 20], 7),
            "recursive-io".into(),
            EMPTY_PLAYER,
            2,
            50,
            100,
        );
        pre.version = 4;
        pre.hand_id = 3;
        pre.call_seq = 8;
        let mut post = pre.clone();
        post.version = 5;
        post.call_seq = 9;
        let context = DispatchContext {
            caller: [0x22; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0x33; 33],
            },
            chain_id: 1,
            block_height: 12,
            block_timestamp: 34,
        };
        ProveTask::new(
            MethodKind::Fold,
            MethodInput::SeatOnly { seat_index: 0 },
            context,
            selectors::fold(),
            borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap(),
            pre,
            post,
            7,
            3,
            9,
        )
    }

    #[cfg(not(feature = "recursive-verifier"))]
    #[test]
    fn registration_rejects_a_build_without_recursive_verifier_capability() {
        let mut registry = ZkVerifierRegistry::new();
        assert!(matches!(
            register_texas_stwo_recursive_verifier(&mut registry),
            Err(PokerL1Error::ZkVerifierCapabilityDisabled { .. })
        ));
        assert!(!registry.registered_schemes().contains(&SCHEME_STWO));
    }

    #[cfg(feature = "recursive-verifier")]
    #[test]
    fn registration_succeeds_when_recursive_verifier_capability_is_compiled() {
        let mut registry = ZkVerifierRegistry::new();
        register_texas_stwo_recursive_verifier(&mut registry).unwrap();
        assert!(registry.registered_schemes().contains(&SCHEME_STWO));
    }

    #[test]
    fn texas_public_io_binds_roots_dispatch_and_metadata() {
        let task = fold_task();
        let baseline = texas_recursive_public_io(&task).unwrap();

        let mut changed_call = task.clone();
        changed_call.raw_args.push(0);
        assert_ne!(
            baseline.state_delta_hash,
            texas_recursive_public_io(&changed_call)
                .unwrap()
                .state_delta_hash
        );

        let mut changed_metadata = task;
        changed_metadata.call_seq += 1;
        assert_ne!(
            baseline.ack_chain_hash,
            texas_recursive_public_io(&changed_metadata)
                .unwrap()
                .ack_chain_hash
        );
    }
}
