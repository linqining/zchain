//! Restart-safe proving-service package for one Texas transition proof set.
//!
//! The package stores the complete canonical task beside the bounded Stwo
//! method archive and, for composite methods, the required four-stage component
//! archive. Verification never trusts proof-carried AIR metadata: it replays the
//! task through [`poker_texas_air::orchestrator::Orchestrator`] and reconstructs
//! every trusted statement before decoding the proofs.

use borsh::{BorshDeserialize, BorshSerialize};
use poker_texas_air::airs::composition::{
    ArchivedCompositionProofBundle, supports_composite_proof,
};
use poker_texas_air::proof_archive::ArchivedMethodProof;
use poker_texas_air::prove_task::ProveTask;

use crate::repository::StoredProofMetadata;
use crate::{ServiceError, ServiceResult};

/// Current proving-service proof package schema.
pub const SERVICE_PROOF_PACKAGE_VERSION: u8 = 2;
/// Maximum accepted task-plus-proof package size.
pub const MAX_SERVICE_PROOF_PACKAGE_BYTES: usize = 128 * 1024 * 1024;

/// Durable package required to reverify one completed proving job.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ServiceProofPackage {
    version: u8,
    task: ProveTask,
    archive: ArchivedMethodProof,
    composition_archive: Option<ArchivedCompositionProofBundle>,
}

impl ServiceProofPackage {
    /// Construct a package from the exact replayed task and verified proof archive.
    ///
    /// # Errors
    ///
    /// Returns an error when archive validation fails.
    pub fn new(
        task: ProveTask,
        archive: ArchivedMethodProof,
        composition_archive: Option<ArchivedCompositionProofBundle>,
    ) -> ServiceResult<Self> {
        let package = Self {
            version: SERVICE_PROOF_PACKAGE_VERSION,
            task,
            archive,
            composition_archive,
        };
        package.validate()?;
        Ok(package)
    }

    /// Strictly decode one complete Borsh package.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/oversized input, trailing bytes, an unsupported
    /// version, or an invalid embedded archive.
    pub fn from_bytes(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "invalid proving-service proof package length".into(),
            ));
        }
        let package = Self::try_from_slice(bytes).map_err(|error| {
            ServiceError::Prover(format!("decode proving-service proof package: {error}"))
        })?;
        package.validate()?;
        Ok(package)
    }

    /// Encode this package as canonical Borsh bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or encoding fails, or the encoded value
    /// exceeds the service package limit.
    pub fn to_bytes(&self) -> ServiceResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            ServiceError::Prover(format!("encode proving-service proof package: {error}"))
        })?;
        if bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "proving-service proof package exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Exact canonical task that defines the proof statement.
    #[must_use]
    pub const fn task(&self) -> &ProveTask {
        &self.task
    }

    /// Bounded Stwo method-proof archive.
    #[must_use]
    pub const fn archive(&self) -> &ArchivedMethodProof {
        &self.archive
    }

    /// Optional four-stage component-proof bundle required by composite methods.
    #[must_use]
    pub const fn composition_archive(&self) -> Option<&ArchivedCompositionProofBundle> {
        self.composition_archive.as_ref()
    }

    /// Consume the package into its task and archive.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProveTask,
        ArchivedMethodProof,
        Option<ArchivedCompositionProofBundle>,
    ) {
        (self.task, self.archive, self.composition_archive)
    }

    fn validate(&self) -> ServiceResult<()> {
        if self.version != SERVICE_PROOF_PACKAGE_VERSION {
            return Err(ServiceError::Prover(format!(
                "unsupported proving-service proof package version {}",
                self.version
            )));
        }
        self.archive
            .validate()
            .map_err(|error| ServiceError::Prover(error.to_string()))?;
        if self.task.method_kind != self.archive.method_kind() {
            return Err(ServiceError::Prover(
                "proof package task/archive method mismatch".into(),
            ));
        }
        match (
            supports_composite_proof(self.task.method_kind),
            self.composition_archive.as_ref(),
        ) {
            (true, Some(bundle)) => bundle
                .validate()
                .map_err(|error| ServiceError::Prover(error.to_string()))?,
            (true, None) => {
                return Err(ServiceError::Prover(
                    "composite proof package is missing its four-stage STARK proof bundle".into(),
                ));
            }
            (false, None) => {}
            (false, Some(_)) => {
                return Err(ServiceError::Prover(
                    "non-composite proof package carries an unexpected component bundle".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Reconstruct the compact journal metadata for a canonical proof task.
pub(crate) fn stored_proof_metadata(task: &ProveTask) -> ServiceResult<StoredProofMetadata> {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let task_bytes = borsh::to_vec(task)
        .map_err(|error| ServiceError::Prover(format!("encode proved task: {error}")))?;
    let pre_state_root = poker_texas_air::state_root::compute_state_root(&task.pre_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    let post_state_root = poker_texas_air::state_root::compute_state_root(&task.post_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.proving_service.task.v1");
    hasher.update(&task_bytes);
    let mut task_digest = [0u8; 32];
    hasher
        .finalize_variable(&mut task_digest)
        .expect("32 <= 64");
    Ok(StoredProofMetadata {
        task_digest,
        pre_state_root: pre_state_root.field().to_bytes_be(),
        post_state_root: post_state_root.field().to_bytes_be(),
    })
}
