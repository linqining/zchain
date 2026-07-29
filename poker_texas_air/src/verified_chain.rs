//! Host-side verification receipts for method-proof chains.
//!
//! This module deliberately does **not** claim recursive proof compression.  It
//! records that the native verifier accepted each method proof, then checks the
//! business metadata and state-root continuity before a caller treats the
//! sequence as a verified host-side chain.
//!
//! A [`VerifiedChain`] is therefore an acceptance artifact for a trusted host
//! process.  It is not transferable evidence that an Aggregator STARK verified
//! its children; the current recursive backend does not provide that circuit.

use starknet_ff::FieldElement;

use crate::airs::TexasAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prover::MethodProof;
use crate::public_inputs::TexasPublicInputs;
use crate::state_root::StateRoot;

/// Receipt issued only after the native method-proof verifier succeeds.
///
/// The fields are intentionally private so downstream code cannot construct a
/// receipt from descriptor data alone. Receipt issuance is crate-private and
/// reachable in production only from the Orchestrator after full VM replay.
#[derive(Debug, Clone)]
pub struct VerificationReceipt {
    kind: MethodKind,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    pre_version: u64,
    post_version: u64,
    dispatch_call_digest: [u8; 32],
    proof_commitments: Vec<FieldElement>,
    log_size: u32,
    num_columns: usize,
}

impl VerificationReceipt {
    /// Method kind authenticated by the verified proof's public inputs.
    #[must_use]
    pub const fn kind(&self) -> MethodKind {
        self.kind
    }

    /// State root before the method call.
    #[must_use]
    pub const fn pre_state_root(&self) -> StateRoot {
        self.pre_state_root
    }

    /// State root after the method call.
    #[must_use]
    pub const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    /// Table identifier.
    #[must_use]
    pub const fn table_id(&self) -> u64 {
        self.table_id
    }

    /// Hand identifier.
    #[must_use]
    pub const fn hand_id(&self) -> u32 {
        self.hand_id
    }

    /// Method-call sequence number.
    #[must_use]
    pub const fn call_seq(&self) -> u32 {
        self.call_seq
    }

    /// State version before the verified method execution.
    #[must_use]
    pub const fn pre_version(&self) -> u64 {
        self.pre_version
    }

    /// State version after the verified method execution.
    #[must_use]
    pub const fn post_version(&self) -> u64 {
        self.post_version
    }

    /// Digest of the exact authenticated VM dispatch call accepted by the host.
    #[must_use]
    pub const fn dispatch_call_digest(&self) -> [u8; 32] {
        self.dispatch_call_digest
    }

    /// Commitment roots of the method proof accepted by the native verifier.
    #[must_use]
    pub fn proof_commitments(&self) -> &[FieldElement] {
        &self.proof_commitments
    }

    /// Trace log size used by the verified method proof.
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Number of original-trace columns used by the verified method proof.
    #[must_use]
    pub const fn num_columns(&self) -> usize {
        self.num_columns
    }
}

/// Verify one method proof natively and issue a non-forgeable-in-safe-Rust receipt.
///
/// The expected AIR and public inputs must be reconstructed independently by
/// the verifier. This host step does not turn the result into a recursively
/// verifiable proof.
///
/// # Errors
///
/// Returns an error when the native Stwo verifier rejects the proof.
pub(crate) fn verify_method_against_and_issue_receipt<A>(
    proof: MethodProof<A>,
    expected_air: A,
    expected_public_inputs: &TexasPublicInputs,
) -> TexasAirResult<VerificationReceipt>
where
    A: TexasAir,
{
    let proof_commitments = proof.stark_proof.commitments.to_vec();
    let log_size = expected_air.log_size();
    let num_columns = expected_air.trace_num_columns();

    crate::verifier::verify_method_against(proof, expected_air, expected_public_inputs)?;

    Ok(VerificationReceipt {
        kind: expected_public_inputs.kind,
        pre_state_root: expected_public_inputs.pre_state_root,
        post_state_root: expected_public_inputs.post_state_root,
        table_id: expected_public_inputs.table_id,
        hand_id: expected_public_inputs.hand_id,
        call_seq: expected_public_inputs.call_seq,
        pre_version: expected_public_inputs.pre_version,
        post_version: expected_public_inputs.post_version,
        dispatch_call_digest: expected_public_inputs.dispatch_call_digest,
        proof_commitments,
        log_size,
        num_columns,
    })
}

/// A sequence of natively verified method proofs with checked metadata continuity.
///
/// Construction validates that all receipts belong to the same table and hand,
/// call sequences are consecutive, and every previous post-state root equals
/// the next pre-state root.
///
/// Descriptor-only summaries are intentionally not accepted by this API:
///
/// ```compile_fail
/// use poker_texas_air::aggregator_air::ChildDescriptor;
/// use poker_texas_air::verified_chain::VerifiedChain;
///
/// let descriptor: ChildDescriptor = todo!();
/// let _ = VerifiedChain::try_from_receipts(vec![descriptor]);
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    receipts: Vec<VerificationReceipt>,
}

impl VerifiedChain {
    /// Build a verified chain from receipts issued by the native verifier.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty chain, mixed table/hand identifiers,
    /// non-consecutive call sequences, or a broken state-root link.
    pub(crate) fn try_from_receipts(receipts: Vec<VerificationReceipt>) -> TexasAirResult<Self> {
        validate_receipt_chain(&receipts)?;
        Ok(Self { receipts })
    }

    /// Receipts in verified execution order.
    #[must_use]
    pub fn receipts(&self) -> &[VerificationReceipt] {
        &self.receipts
    }

    /// Number of verified method proofs in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the chain contains no receipts.
    ///
    /// A successfully constructed chain is never empty; this method is
    /// provided for normal collection-style inspection.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Common table identifier for the chain.
    #[must_use]
    pub fn table_id(&self) -> u64 {
        self.receipts[0].table_id
    }

    /// Common hand identifier for the chain.
    #[must_use]
    pub fn hand_id(&self) -> u32 {
        self.receipts[0].hand_id
    }
}

/// Incremental host-side verifier for heterogeneous method AIR proof types.
///
/// Each call to [`push`](Self::push) is generic, so one builder can accept the
/// different concrete AIR types used by successive poker methods.
#[derive(Debug, Default, Clone)]
pub(crate) struct VerifiedChainBuilder {
    receipts: Vec<VerificationReceipt>,
}

impl VerifiedChainBuilder {
    /// Create an empty host-side chain verifier.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            receipts: Vec::new(),
        }
    }

    /// Append a receipt previously issued by the native verifier.
    ///
    /// This accepts only [`VerificationReceipt`], whose fields are private and
    /// which safe external code can obtain only from a successful native
    /// verification. Descriptor-only summaries therefore cannot enter the
    /// trusted chain through this path.
    ///
    /// # Errors
    ///
    /// Returns an error if the receipt does not continue the existing
    /// table/hand/state/sequence/version chain.
    pub(crate) fn push_receipt(&mut self, receipt: VerificationReceipt) -> TexasAirResult<()> {
        if let Some(previous) = self.receipts.last() {
            validate_adjacent_receipts(previous, &receipt)?;
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// Snapshot the currently accumulated host-verified chain.
    ///
    /// # Errors
    ///
    /// Returns an error if no verified receipts have been added.
    pub(crate) fn snapshot(&self) -> TexasAirResult<VerifiedChain> {
        VerifiedChain::try_from_receipts(self.receipts.clone())
    }

    /// Finish the host-side batch and return a checked chain.
    ///
    /// # Errors
    ///
    /// Returns an error if no verified proofs were added.
    pub(crate) fn finish(self) -> TexasAirResult<VerifiedChain> {
        VerifiedChain::try_from_receipts(self.receipts)
    }
}

fn validate_receipt_chain(receipts: &[VerificationReceipt]) -> TexasAirResult<()> {
    if receipts.is_empty() {
        return Err(TexasAirError::RecursionError(
            "verified chain must contain at least one method proof".into(),
        ));
    }
    for pair in receipts.windows(2) {
        validate_adjacent_receipts(&pair[0], &pair[1])?;
    }
    Ok(())
}

fn validate_adjacent_receipts(
    left: &VerificationReceipt,
    right: &VerificationReceipt,
) -> TexasAirResult<()> {
    if left.table_id != right.table_id {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain crosses tables: {} -> {}",
            left.table_id, right.table_id
        )));
    }
    if left.hand_id != right.hand_id {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain crosses hands: {} -> {}",
            left.hand_id, right.hand_id
        )));
    }
    let expected_seq = left
        .call_seq
        .checked_add(1)
        .ok_or_else(|| TexasAirError::RecursionError("verified chain call_seq overflow".into()))?;
    if right.call_seq != expected_seq {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain call_seq is not consecutive: expected {}, got {}",
            expected_seq, right.call_seq
        )));
    }
    if left.post_state_root != right.pre_state_root {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain state root is discontinuous at call_seq {} -> {}",
            left.call_seq, right.call_seq
        )));
    }
    if left.post_version != right.pre_version {
        return Err(TexasAirError::RecursionError(format!(
            "verified chain state version is discontinuous at call_seq {} -> {}",
            left.call_seq, right.call_seq
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
        pre: u64,
        post: u64,
    ) -> VerificationReceipt {
        VerificationReceipt {
            kind: MethodKind::Check,
            pre_state_root: StateRoot::from_field(FieldElement::from(pre)),
            post_state_root: StateRoot::from_field(FieldElement::from(post)),
            table_id,
            hand_id,
            call_seq,
            pre_version: u64::from(call_seq),
            post_version: u64::from(call_seq) + 1,
            dispatch_call_digest: [call_seq as u8; 32],
            proof_commitments: vec![FieldElement::from(call_seq as u64 + 1)],
            log_size: 10,
            num_columns: 1,
        }
    }

    #[test]
    fn builds_contiguous_host_verified_chain() {
        let chain = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 101, 102),
        ])
        .expect("contiguous receipts should form a chain");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.table_id(), 7);
        assert_eq!(chain.hand_id(), 3);
    }

    #[test]
    fn rejects_cross_table_receipts() {
        let result = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(8, 3, 11, 101, 102),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_cross_hand_receipts() {
        let result = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 4, 11, 101, 102),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_consecutive_or_broken_state_chain() {
        let bad_seq = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 12, 101, 102),
        ]);
        assert!(bad_seq.is_err());

        let bad_root = VerifiedChain::try_from_receipts(vec![
            receipt(7, 3, 10, 100, 101),
            receipt(7, 3, 11, 999, 102),
        ]);
        assert!(bad_root.is_err());
    }

    #[test]
    fn rejects_broken_version_chain() {
        let mut second = receipt(7, 3, 11, 101, 102);
        second.pre_version = 99;
        let result = VerifiedChain::try_from_receipts(vec![receipt(7, 3, 10, 100, 101), second]);
        assert!(result.is_err());
    }
}
