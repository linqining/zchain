//! Restart-safe proving-service package for one Texas proof set.
//!
//! A strict payload tag separates legacy single-task archives from the shared
//! two-proof tagged batch package. Verification never trusts proof-carried AIR
//! metadata: it replays the canonical task or continuous command stream and
//! reconstructs every trusted statement before decoding the proofs.

use borsh::{BorshDeserialize, BorshSerialize};
use poker_texas_air::airs::composition::{
    ArchivedCompositionProofBundle, supports_composite_proof,
};
use poker_texas_air::proof_archive::ArchivedMethodProof;
use poker_texas_air::prove_task::ProveTask;
use poker_texas_air::tagged_method::ArchivedTaggedBatchProofPackage;

use crate::repository::StoredProofMetadata;
use crate::{ServiceError, ServiceResult};

/// Current proving-service proof package schema.
pub const SERVICE_PROOF_PACKAGE_VERSION: u8 = 5;
/// Maximum accepted task-plus-proof package size.
pub const MAX_SERVICE_PROOF_PACKAGE_BYTES: usize = 128 * 1024 * 1024;

/// Durable package required to reverify one job or a shared batch of jobs.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct ServiceProofPackage {
    version: u8,
    payload: ServiceProofPayload,
}

/// Canonically decoded package together with the tasks reconstructed during validation.
///
/// Tagged packages otherwise replay their embedded command stream each time callers ask for a
/// row count or task. Keeping the replay result beside the immutable package lets service-level
/// verification bind many jobs to one sidecar without repeating native VM execution.
#[derive(Debug, Clone)]
pub struct DecodedServiceProofPackage {
    package: ServiceProofPackage,
    tasks: Vec<ProveTask>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum ServiceProofPayload {
    Single {
        task: ProveTask,
        archive: ArchivedMethodProof,
        composition_archive: Option<ArchivedCompositionProofBundle>,
    },
    Tagged(ArchivedTaggedBatchProofPackage),
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
            payload: ServiceProofPayload::Single {
                task,
                archive,
                composition_archive,
            },
        };
        package.validate()?;
        Ok(package)
    }

    /// Construct one shared two-proof package for a contiguous tagged batch.
    pub fn new_tagged(package: ArchivedTaggedBatchProofPackage) -> ServiceResult<Self> {
        let package = Self {
            version: SERVICE_PROOF_PACKAGE_VERSION,
            payload: ServiceProofPayload::Tagged(package),
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
        Ok(Self::decode_bytes(bytes)?.package)
    }

    /// Strictly decode a package and retain the canonical tasks produced by validation.
    pub fn decode_bytes(bytes: &[u8]) -> ServiceResult<DecodedServiceProofPackage> {
        if bytes.is_empty() || bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "invalid proving-service proof package length".into(),
            ));
        }
        let version = bytes[0];
        if version != SERVICE_PROOF_PACKAGE_VERSION {
            return Err(ServiceError::Prover(format!(
                "unsupported proving-service proof package version {version}"
            )));
        }
        let package = Self::try_from_slice(bytes).map_err(|error| {
            ServiceError::Prover(format!("decode proving-service proof package: {error}"))
        })?;
        let tasks = package.validate_and_replay_tasks()?;
        Ok(DecodedServiceProofPackage { package, tasks })
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

    /// Replay or borrow all canonical tasks committed by this package.
    pub fn tasks(&self) -> ServiceResult<Vec<ProveTask>> {
        match &self.payload {
            ServiceProofPayload::Single { task, .. } => Ok(vec![task.clone()]),
            ServiceProofPayload::Tagged(package) => package
                .replay_tasks()
                .map_err(|error| ServiceError::Prover(error.to_string())),
        }
    }

    /// Exact canonical task for one zero-based package row.
    pub fn task_at(&self, row_index: u16) -> ServiceResult<ProveTask> {
        self.tasks()?
            .into_iter()
            .nth(usize::from(row_index))
            .ok_or_else(|| ServiceError::Prover("proof package row index is out of range".into()))
    }

    /// Number of method rows committed by this package.
    pub fn row_count(&self) -> ServiceResult<u16> {
        u16::try_from(self.tasks()?.len())
            .map_err(|_| ServiceError::Prover("proof package row count exceeds u16".into()))
    }

    /// Shared tagged-batch identifier, absent for a single-task package.
    #[must_use]
    pub fn batch_id(&self) -> Option<[u8; 32]> {
        match &self.payload {
            ServiceProofPayload::Single { .. } => None,
            ServiceProofPayload::Tagged(package) => Some(package.method().batch_id()),
        }
    }

    /// Borrow the legacy single-task parts when this is not a tagged package.
    #[must_use]
    pub const fn single_parts(
        &self,
    ) -> Option<(
        &ProveTask,
        &ArchivedMethodProof,
        Option<&ArchivedCompositionProofBundle>,
    )> {
        match &self.payload {
            ServiceProofPayload::Single {
                task,
                archive,
                composition_archive,
            } => Some((task, archive, composition_archive.as_ref())),
            ServiceProofPayload::Tagged(_) => None,
        }
    }

    /// Borrow the self-contained two-proof tagged package.
    #[must_use]
    pub const fn tagged(&self) -> Option<&ArchivedTaggedBatchProofPackage> {
        match &self.payload {
            ServiceProofPayload::Single { .. } => None,
            ServiceProofPayload::Tagged(package) => Some(package),
        }
    }

    fn validate(&self) -> ServiceResult<()> {
        self.validate_and_replay_tasks().map(drop)
    }

    fn validate_and_replay_tasks(&self) -> ServiceResult<Vec<ProveTask>> {
        if self.version != SERVICE_PROOF_PACKAGE_VERSION {
            return Err(ServiceError::Prover(format!(
                "unsupported proving-service proof package version {}",
                self.version
            )));
        }
        match &self.payload {
            ServiceProofPayload::Single {
                task,
                archive,
                composition_archive,
            } => {
                archive
                    .validate()
                    .map_err(|error| ServiceError::Prover(error.to_string()))?;
                if task.method_kind != archive.method_kind() {
                    return Err(ServiceError::Prover(
                        "proof package task/archive method mismatch".into(),
                    ));
                }
                match (
                    supports_composite_proof(task.method_kind),
                    composition_archive.as_ref(),
                ) {
                    (true, Some(bundle)) => bundle
                        .validate()
                        .map_err(|error| ServiceError::Prover(error.to_string()))?,
                    (true, None) => {
                        return Err(ServiceError::Prover(
                            "composite proof package is missing its four-stage STARK proof bundle"
                                .into(),
                        ));
                    }
                    (false, None) => {}
                    (false, Some(_)) => {
                        return Err(ServiceError::Prover(
                            "non-composite proof package carries an unexpected component bundle"
                                .into(),
                        ));
                    }
                }
                Ok(vec![task.clone()])
            }
            ServiceProofPayload::Tagged(package) => package
                .validate_and_replay_tasks()
                .map_err(|error| ServiceError::Prover(error.to_string())),
        }
    }
}

impl DecodedServiceProofPackage {
    /// Construct a decoded tagged service package from tasks already replayed by the live prover.
    ///
    /// The caller must only use this after the package's two proofs have verified. This method
    /// validates the immutable package scopes against the supplied canonical tasks without
    /// replaying their command stream again.
    pub(crate) fn new_verified_tagged(
        package: ArchivedTaggedBatchProofPackage,
        tasks: Vec<ProveTask>,
    ) -> ServiceResult<Self> {
        package
            .validate_with_replayed_tasks(&tasks)
            .map_err(|error| ServiceError::Prover(error.to_string()))?;
        Ok(Self {
            package: ServiceProofPackage {
                version: SERVICE_PROOF_PACKAGE_VERSION,
                payload: ServiceProofPayload::Tagged(package),
            },
            tasks,
        })
    }

    /// Immutable decoded service package.
    #[must_use]
    pub const fn package(&self) -> &ServiceProofPackage {
        &self.package
    }

    /// Canonical tasks replayed exactly once while decoding the package.
    #[must_use]
    pub fn tasks(&self) -> &[ProveTask] {
        &self.tasks
    }

    /// Exact canonical task for one zero-based package row.
    pub fn task_at(&self, row_index: u16) -> ServiceResult<&ProveTask> {
        self.tasks
            .get(usize::from(row_index))
            .ok_or_else(|| ServiceError::Prover("proof package row index is out of range".into()))
    }

    /// Number of method rows committed by this package.
    pub fn row_count(&self) -> ServiceResult<u16> {
        u16::try_from(self.tasks.len())
            .map_err(|_| ServiceError::Prover("proof package row count exceeds u16".into()))
    }

    /// Encode a package whose envelope and canonical tasks were already validated together.
    pub(crate) fn to_bytes(&self) -> ServiceResult<Vec<u8>> {
        let bytes = borsh::to_vec(&self.package).map_err(|error| {
            ServiceError::Prover(format!("encode proving-service proof package: {error}"))
        })?;
        if bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(ServiceError::Prover(
                "proving-service proof package exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }
}

/// Content identity used by the process-local validated-package cache.
#[must_use]
pub(crate) fn proof_package_digest(bytes: &[u8]) -> [u8; 32] {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.proving_service.validated_package.v1");
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
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
    hasher.update(b"zchain.proving_service.task.v2");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_service_packages_are_rejected() {
        assert!(ServiceProofPackage::from_bytes(&[2]).is_err());
        assert!(ServiceProofPackage::from_bytes(&[3]).is_err());
        assert!(ServiceProofPackage::from_bytes(&[4]).is_err());
    }
}
