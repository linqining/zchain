//! Durable, single-process repository for Texas proving jobs and proof archives.
//!
//! The service intentionally keeps the storage format small and explicit: one
//! Borsh snapshot contains all table snapshots and dispatch job records.  A
//! write is staged to a sibling temporary file and renamed only after it has
//! been flushed, so a failed write never makes the in-memory state authoritative.
//! Complete proof packages are stored as atomic sidecars before the job journal
//! can mark the corresponding transition completed. Tagged jobs share one
//! sidecar by batch ID; tentative rows remain explicit `PendingProof` records.
//! This remains a local service repository, not a consensus database.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::Address;
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
use poker_texas_air::prove_task::ProveTask;

use crate::proof_package::MAX_SERVICE_PROOF_PACKAGE_BYTES;
use crate::{ServiceError, ServiceResult};

const SCHEMA_VERSION: u32 = 6;

/// A table state that can be rehydrated into a `TexasPokerPlugin` after a restart.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredTable {
    pub table_id: u64,
    pub table: TexasPokerTable,
    pub dispatch_count: u64,
    pub prove_count: u64,
}

/// Metadata retained in the journal for an accepted native proof.
///
/// The complete task and Stwo archive live in the referenced proof sidecar. These
/// compact fields bind that sidecar to the completed journal record and support
/// inexpensive job listing without loading a potentially large proof package.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredProofMetadata {
    pub task_digest: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
}

/// Durable location of one job's proof inside either a private or shared sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum StoredProofReference {
    /// One legacy method archive owned only by this job.
    Single { package_id: [u8; 32] },
    /// One row in a shared tagged method + Stage package.
    Tagged {
        batch_id: [u8; 32],
        row_index: u16,
        row_count: u16,
    },
}

impl StoredProofReference {
    #[must_use]
    pub const fn package_id(self) -> [u8; 32] {
        match self {
            Self::Single { package_id } => package_id,
            Self::Tagged { batch_id, .. } => batch_id,
        }
    }

    #[must_use]
    pub const fn row_index(self) -> u16 {
        match self {
            Self::Single { .. } => 0,
            Self::Tagged { row_index, .. } => row_index,
        }
    }
}

/// JSON-independent response data stored with a completed job.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredDispatchResult {
    pub had_prove_task: bool,
    pub proof_verified: bool,
    pub events_count: u64,
    pub dispatch_count: u64,
    pub prove_count: u64,
    pub chain_length: u64,
    pub table_version: u64,
    pub hand_id: u32,
    pub call_seq: u32,
}

/// Lifecycle status of one idempotent dispatch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum StoredJobStatus {
    /// Persisted before dispatch/proving.  It is safe to replay from the durable
    /// table snapshot after a process interruption because the table transition
    /// has not been committed yet.
    Running,
    /// The VM transition is durable and may feed later transitions, but its
    /// receipt is withheld until the shared tagged package verifies.
    PendingProof,
    Completed,
    Failed,
}

/// Durable dispatch-job record.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredDispatchJob {
    pub job_id: [u8; 32],
    pub table_id: u64,
    pub idempotency_key: Option<String>,
    pub request_digest: [u8; 32],
    pub caller: Address,
    pub selector: [u8; 32],
    pub args: Vec<u8>,
    pub status: StoredJobStatus,
    pub attempts: u32,
    pub result: Option<StoredDispatchResult>,
    pub proof: Option<StoredProofMetadata>,
    pub proof_reference: Option<StoredProofReference>,
    pub error: Option<String>,
}

impl StoredDispatchJob {
    #[must_use]
    pub const fn job_id(&self) -> [u8; 32] {
        self.job_id
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct RepositorySnapshot {
    schema_version: u32,
    next_job_nonce: u64,
    tables: Vec<StoredTable>,
    jobs: Vec<StoredDispatchJob>,
    pending_tagged_batches: Vec<StoredPendingTaggedBatch>,
}

/// Canonical tasks retained only until one shared tagged package becomes durable.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredPendingTaggedBatch {
    pub table_id: u64,
    pub tasks: Vec<ProveTask>,
    pub job_ids: Vec<[u8; 32]>,
}

impl Default for RepositorySnapshot {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            next_job_nonce: 0,
            tables: Vec::new(),
            jobs: Vec::new(),
            pending_tagged_batches: Vec::new(),
        }
    }
}

/// Result of reserving a request's idempotency slot.
#[derive(Debug, Clone)]
pub enum JobReservation {
    /// A prior pending, completed, or failed request has an immutable result.
    Existing(StoredDispatchJob),
    /// The request should be processed.  A stale `Running` record was resumed,
    /// or this is a newly persisted job.
    Execute(StoredDispatchJob),
}

/// Errors specific to durable repository semantics.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("unsupported proving-service repository schema {0}")]
    UnsupportedSchema(u32),
    #[error("idempotency key is already associated with a different request")]
    IdempotencyConflict,
    #[error("repository corruption: {0}")]
    Corruption(String),
    #[error("repository I/O: {0}")]
    Io(String),
}

impl From<RepositoryError> for ServiceError {
    fn from(error: RepositoryError) -> Self {
        Self::Runner(error.to_string())
    }
}

/// Repository backed either by an atomic on-disk snapshot or by memory for tests.
#[derive(Debug, Clone)]
pub struct ServiceRepository {
    path: Option<PathBuf>,
    snapshot: RepositorySnapshot,
    in_memory_proofs: BTreeMap<[u8; 32], Vec<u8>>,
}

impl ServiceRepository {
    /// Construct an empty in-memory repository.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            snapshot: RepositorySnapshot::default(),
            in_memory_proofs: BTreeMap::new(),
        }
    }

    /// Open an on-disk repository, recovering its last complete snapshot.
    pub fn open(path: impl AsRef<Path>) -> ServiceResult<Self> {
        let path = path.as_ref().to_path_buf();
        let snapshot = match fs::read(&path) {
            Ok(bytes) => {
                let snapshot = RepositorySnapshot::try_from_slice(&bytes).map_err(|error| {
                    RepositoryError::Corruption(format!("{}: {error}", path.display()))
                })?;
                if snapshot.schema_version != SCHEMA_VERSION {
                    return Err(RepositoryError::UnsupportedSchema(snapshot.schema_version).into());
                }
                snapshot
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                RepositorySnapshot::default()
            }
            Err(error) => {
                return Err(RepositoryError::Io(format!("{}: {error}", path.display())).into());
            }
        };
        Ok(Self {
            path: Some(path),
            snapshot,
            in_memory_proofs: BTreeMap::new(),
        })
    }

    /// All durable table states in deterministic insertion order.
    #[must_use]
    pub fn tables(&self) -> &[StoredTable] {
        &self.snapshot.tables
    }

    #[must_use]
    pub fn table(&self, table_id: u64) -> Option<&StoredTable> {
        self.snapshot
            .tables
            .iter()
            .find(|table| table.table_id == table_id)
    }

    #[must_use]
    pub fn job(&self, job_id: [u8; 32]) -> Option<&StoredDispatchJob> {
        self.snapshot.jobs.iter().find(|job| job.job_id == job_id)
    }

    #[must_use]
    pub fn jobs(&self) -> &[StoredDispatchJob] {
        &self.snapshot.jobs
    }

    #[must_use]
    pub fn pending_tagged_batch(&self, table_id: u64) -> Option<&StoredPendingTaggedBatch> {
        self.snapshot
            .pending_tagged_batches
            .iter()
            .find(|batch| batch.table_id == table_id)
    }

    #[must_use]
    pub fn pending_tagged_batches(&self) -> &[StoredPendingTaggedBatch] {
        &self.snapshot.pending_tagged_batches
    }

    /// Persist the complete proof package before marking its job completed.
    ///
    /// Disk repositories use one atomic sidecar per single job or tagged batch. An orphan sidecar is
    /// acceptable after a later journal failure, but a completed job must never
    /// be committed before its proof is durable.
    pub fn store_proof_package(&mut self, package_id: [u8; 32], bytes: &[u8]) -> ServiceResult<()> {
        if bytes.is_empty() || bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
            return Err(RepositoryError::Corruption("invalid proof package length".into()).into());
        }
        if let Some(path) = self.proof_path(package_id) {
            write_atomic(&path, bytes)?;
        } else {
            self.in_memory_proofs.insert(package_id, bytes.to_vec());
        }
        Ok(())
    }

    /// Load the complete proof package for a job, if present.
    pub fn load_proof_package(&self, package_id: [u8; 32]) -> ServiceResult<Option<Vec<u8>>> {
        if let Some(path) = self.proof_path(package_id) {
            return match fs::read(&path) {
                Ok(bytes) => {
                    if bytes.is_empty() || bytes.len() > MAX_SERVICE_PROOF_PACKAGE_BYTES {
                        Err(RepositoryError::Corruption(format!(
                            "invalid proof package length: {}",
                            path.display()
                        ))
                        .into())
                    } else {
                        Ok(Some(bytes))
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => {
                    Err(RepositoryError::Io(format!("{}: {error}", path.display())).into())
                }
            };
        }
        Ok(self.in_memory_proofs.get(&package_id).cloned())
    }

    /// Whether a complete proof package is available for the job.
    pub fn has_proof_package(&self, package_id: [u8; 32]) -> ServiceResult<bool> {
        if let Some(path) = self.proof_path(package_id) {
            return match fs::metadata(&path) {
                Ok(metadata) => Ok(metadata.is_file()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => {
                    Err(RepositoryError::Io(format!("{}: {error}", path.display())).into())
                }
            };
        }
        Ok(self.in_memory_proofs.contains_key(&package_id))
    }

    /// Resolve and load the package referenced by a completed job.
    pub fn load_job_proof_package(
        &self,
        job: &StoredDispatchJob,
    ) -> ServiceResult<Option<Vec<u8>>> {
        let Some(reference) = job.proof_reference else {
            return Ok(None);
        };
        self.load_proof_package(reference.package_id())
    }

    /// Whether the package referenced by a completed job is durable.
    pub fn has_job_proof_package(&self, job: &StoredDispatchJob) -> ServiceResult<bool> {
        let Some(reference) = job.proof_reference else {
            return Ok(false);
        };
        self.has_proof_package(reference.package_id())
    }

    /// Persist a table only after it has a fully verified transition to commit.
    pub fn store_table(&mut self, table: StoredTable) -> ServiceResult<()> {
        let mut candidate = self.snapshot.clone();
        if let Some(existing) = candidate
            .tables
            .iter_mut()
            .find(|existing| existing.table_id == table.table_id)
        {
            *existing = table;
        } else {
            candidate.tables.push(table);
        }
        self.commit(candidate)
    }

    /// Reserve an idempotent job before any transition is executed.
    pub fn reserve_job(
        &mut self,
        mut job: StoredDispatchJob,
    ) -> Result<JobReservation, RepositoryError> {
        if let Some(key) = &job.idempotency_key {
            if let Some(existing) = self.snapshot.jobs.iter().find(|existing| {
                existing.table_id == job.table_id
                    && existing.idempotency_key.as_deref() == Some(key.as_str())
            }) {
                if existing.request_digest != job.request_digest {
                    return Err(RepositoryError::IdempotencyConflict);
                }
                return match existing.status {
                    StoredJobStatus::PendingProof
                    | StoredJobStatus::Completed
                    | StoredJobStatus::Failed => Ok(JobReservation::Existing(existing.clone())),
                    StoredJobStatus::Running => {
                        let mut candidate = self.snapshot.clone();
                        let resumed = candidate
                            .jobs
                            .iter_mut()
                            .find(|candidate| candidate.job_id == existing.job_id)
                            .expect("job found in cloned repository");
                        resumed.attempts = resumed.attempts.saturating_add(1);
                        job = resumed.clone();
                        self.commit_repository(candidate)?;
                        Ok(JobReservation::Execute(job))
                    }
                };
            }
        }

        let mut candidate = self.snapshot.clone();
        job.status = StoredJobStatus::Running;
        job.attempts = 1;
        candidate.jobs.push(job.clone());
        self.commit_repository(candidate)?;
        Ok(JobReservation::Execute(job))
    }

    /// Atomically commit a verified table transition and its completed job.
    pub fn complete_job(
        &mut self,
        table: StoredTable,
        mut job: StoredDispatchJob,
        result: StoredDispatchResult,
        proof: Option<StoredProofMetadata>,
        proof_reference: Option<StoredProofReference>,
    ) -> ServiceResult<()> {
        if proof.is_some() != proof_reference.is_some() {
            return Err(RepositoryError::Corruption(
                "completed proof metadata/reference presence differs".into(),
            )
            .into());
        }
        if let Some(reference) = proof_reference
            && !self.has_proof_package(reference.package_id())?
        {
            return Err(RepositoryError::Corruption(
                "cannot complete a proof job before its archive is durable".into(),
            )
            .into());
        }
        let mut candidate = self.snapshot.clone();
        let target = candidate
            .jobs
            .iter_mut()
            .find(|candidate| candidate.job_id == job.job_id)
            .ok_or_else(|| {
                RepositoryError::Corruption("completed job is missing from repository".into())
            })?;
        job.status = StoredJobStatus::Completed;
        job.result = Some(result);
        job.proof = proof;
        job.proof_reference = proof_reference;
        job.error = None;
        *target = job;
        if let Some(existing) = candidate
            .tables
            .iter_mut()
            .find(|existing| existing.table_id == table.table_id)
        {
            *existing = table;
        } else {
            candidate.tables.push(table);
        }
        self.commit(candidate)
    }

    /// Atomically persist one tentative same-hand transition and append it to
    /// the table's open tagged batch. Methods outside the Stage pipeline are
    /// represented by zero-Stage tagged rows.
    pub fn queue_pending_tagged_job(
        &mut self,
        table: StoredTable,
        mut job: StoredDispatchJob,
        result: StoredDispatchResult,
        proof: StoredProofMetadata,
        task: ProveTask,
    ) -> ServiceResult<()> {
        let mut candidate = self.snapshot.clone();
        let target = candidate
            .jobs
            .iter_mut()
            .find(|candidate| candidate.job_id == job.job_id)
            .ok_or_else(|| RepositoryError::Corruption("pending job is missing".into()))?;
        job.status = StoredJobStatus::PendingProof;
        job.result = Some(result);
        job.proof = Some(proof);
        job.proof_reference = None;
        job.error = None;
        *target = job.clone();

        if let Some(batch) = candidate
            .pending_tagged_batches
            .iter_mut()
            .find(|batch| batch.table_id == table.table_id)
        {
            if batch.job_ids.contains(&job.job_id) {
                return Err(RepositoryError::Corruption(
                    "pending tagged job was inserted twice".into(),
                )
                .into());
            }
            batch.tasks.push(task);
            batch.job_ids.push(job.job_id);
        } else {
            candidate
                .pending_tagged_batches
                .push(StoredPendingTaggedBatch {
                    table_id: table.table_id,
                    tasks: vec![task],
                    job_ids: vec![job.job_id],
                });
        }
        upsert_table(&mut candidate.tables, table);
        self.commit(candidate)
    }

    /// Bind every pending job row to one durable shared tagged package and
    /// atomically advance the verified table counters.
    pub fn complete_pending_tagged_batch(
        &mut self,
        table: StoredTable,
        batch_id: [u8; 32],
        row_count: u16,
        chain_length: u64,
    ) -> ServiceResult<Vec<StoredDispatchJob>> {
        if !self.has_proof_package(batch_id)? {
            return Err(RepositoryError::Corruption(
                "cannot complete tagged jobs before the shared package is durable".into(),
            )
            .into());
        }
        let mut candidate = self.snapshot.clone();
        let batch_index = candidate
            .pending_tagged_batches
            .iter()
            .position(|batch| batch.table_id == table.table_id)
            .ok_or_else(|| RepositoryError::Corruption("pending tagged batch is missing".into()))?;
        let batch = candidate.pending_tagged_batches.remove(batch_index);
        if batch.tasks.len() != batch.job_ids.len() || usize::from(row_count) != batch.job_ids.len()
        {
            return Err(RepositoryError::Corruption(
                "pending tagged batch row count mismatch".into(),
            )
            .into());
        }
        let first_job_id = *batch
            .job_ids
            .first()
            .ok_or_else(|| RepositoryError::Corruption("pending tagged batch is empty".into()))?;
        let first_result = candidate
            .jobs
            .iter()
            .find(|job| job.job_id == first_job_id)
            .and_then(|job| job.result.as_ref())
            .ok_or_else(|| {
                RepositoryError::Corruption("first pending tagged result is missing".into())
            })?;
        let base_prove_count = first_result.prove_count;
        let base_chain_length = first_result.chain_length;
        let row_count_u64 = u64::from(row_count);
        if table.prove_count
            != base_prove_count.checked_add(row_count_u64).ok_or_else(|| {
                RepositoryError::Corruption("tagged prove counter overflow".into())
            })?
            || chain_length
                != base_chain_length
                    .checked_add(row_count_u64)
                    .ok_or_else(|| {
                        RepositoryError::Corruption("tagged chain counter overflow".into())
                    })?
            || candidate
                .tables
                .iter()
                .find(|stored| stored.table_id == table.table_id)
                .is_none_or(|stored| stored.prove_count != base_prove_count)
        {
            return Err(RepositoryError::Corruption(
                "tagged batch counters do not advance exactly once per row".into(),
            )
            .into());
        }
        let mut completed = Vec::with_capacity(batch.job_ids.len());
        for (row_index, job_id) in batch.job_ids.into_iter().enumerate() {
            let job = candidate
                .jobs
                .iter_mut()
                .find(|job| job.job_id == job_id)
                .ok_or_else(|| RepositoryError::Corruption("pending row job is missing".into()))?;
            if job.status != StoredJobStatus::PendingProof
                || job.proof.is_none()
                || job.proof_reference.is_some()
            {
                return Err(RepositoryError::Corruption(
                    "pending tagged job has inconsistent proof state".into(),
                )
                .into());
            }
            let row_index = u16::try_from(row_index).map_err(|_| {
                RepositoryError::Corruption("pending tagged row index exceeds u16".into())
            })?;
            job.status = StoredJobStatus::Completed;
            job.proof_reference = Some(StoredProofReference::Tagged {
                batch_id,
                row_index,
                row_count,
            });
            let result = job.result.as_mut().ok_or_else(|| {
                RepositoryError::Corruption("pending tagged job result is missing".into())
            })?;
            if result.proof_verified
                || result.prove_count != base_prove_count
                || result.chain_length != base_chain_length
            {
                return Err(RepositoryError::Corruption(
                    "pending tagged rows do not share the same verified-history base".into(),
                )
                .into());
            }
            let completed_rows = u64::from(row_index)
                .checked_add(1)
                .ok_or_else(|| RepositoryError::Corruption("tagged row counter overflow".into()))?;
            result.proof_verified = true;
            result.prove_count = base_prove_count
                .checked_add(completed_rows)
                .ok_or_else(|| {
                    RepositoryError::Corruption("tagged prove counter overflow".into())
                })?;
            result.chain_length =
                base_chain_length
                    .checked_add(completed_rows)
                    .ok_or_else(|| {
                        RepositoryError::Corruption("tagged chain counter overflow".into())
                    })?;
            completed.push(job.clone());
        }
        upsert_table(&mut candidate.tables, table);
        self.commit(candidate)?;
        Ok(completed)
    }

    /// Persist a proof/dispatch failure without changing the table snapshot.
    pub fn fail_job(
        &mut self,
        job_id: [u8; 32],
        error: String,
    ) -> ServiceResult<StoredDispatchJob> {
        let mut candidate = self.snapshot.clone();
        let job = candidate
            .jobs
            .iter_mut()
            .find(|candidate| candidate.job_id == job_id)
            .ok_or_else(|| {
                RepositoryError::Corruption("failed job is missing from repository".into())
            })?;
        job.status = StoredJobStatus::Failed;
        job.error = Some(error);
        job.result = None;
        job.proof = None;
        job.proof_reference = None;
        let result = job.clone();
        self.commit(candidate)?;
        Ok(result)
    }

    /// Allocate a durable monotonic nonce for non-idempotent requests.
    pub fn next_job_nonce(&mut self) -> ServiceResult<u64> {
        let nonce = self.snapshot.next_job_nonce;
        let mut candidate = self.snapshot.clone();
        candidate.next_job_nonce = candidate.next_job_nonce.checked_add(1).ok_or_else(|| {
            RepositoryError::Corruption("proving-service job nonce overflow".into())
        })?;
        self.commit(candidate)?;
        Ok(nonce)
    }

    fn commit(&mut self, candidate: RepositorySnapshot) -> ServiceResult<()> {
        self.commit_repository(candidate).map_err(Into::into)
    }

    fn commit_repository(&mut self, candidate: RepositorySnapshot) -> Result<(), RepositoryError> {
        if let Some(path) = &self.path {
            let bytes = borsh::to_vec(&candidate).map_err(|error| {
                RepositoryError::Corruption(format!("repository encode: {error}"))
            })?;
            write_atomic(path, &bytes)?;
        }
        self.snapshot = candidate;
        Ok(())
    }

    fn proof_path(&self, package_id: [u8; 32]) -> Option<PathBuf> {
        self.path.as_ref().map(|repository_path| {
            repository_path
                .with_extension("proofs")
                .join(format!("{}.proof", hex::encode(package_id)))
        })
    }
}

fn upsert_table(tables: &mut Vec<StoredTable>, table: StoredTable) {
    if let Some(existing) = tables
        .iter_mut()
        .find(|existing| existing.table_id == table.table_id)
    {
        *existing = table;
    } else {
        tables.push(table);
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RepositoryError> {
    // A bare filename has an empty parent component.  Persist it in the current
    // directory, which is the documented default service-state location.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", parent.display())))?;
    let tmp = path.with_extension("tmp");
    let mut file = File::create(&tmp)
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", tmp.display())))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| RepositoryError::Io(format!("{}: {error}", tmp.display())))?;
    fs::rename(&tmp, path).map_err(|error| {
        RepositoryError::Io(format!("{} -> {}: {error}", tmp.display(), path.display()))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_repository_schema_is_rejected() {
        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_repo_schema_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("service.borsh");
        let mut snapshot = RepositorySnapshot::default();
        snapshot.schema_version = 3;
        write_atomic(&path, &borsh::to_vec(&snapshot).unwrap()).unwrap();

        let error = ServiceRepository::open(&path).unwrap_err().to_string();
        assert!(error.contains("unsupported proving-service repository schema 3"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn idempotency_conflict_is_persisted_across_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_repo_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("service.borsh");
        let mut repo = ServiceRepository::open(&path).unwrap();
        let job = StoredDispatchJob {
            job_id: [1; 32],
            table_id: 9,
            idempotency_key: Some("request-1".into()),
            request_digest: [2; 32],
            caller: [3; 20],
            selector: [4; 32],
            args: vec![5],
            status: StoredJobStatus::Running,
            attempts: 0,
            result: None,
            proof: None,
            proof_reference: None,
            error: None,
        };
        assert!(matches!(
            repo.reserve_job(job.clone()).unwrap(),
            JobReservation::Execute(_)
        ));
        drop(repo);

        let mut reopened = ServiceRepository::open(&path).unwrap();
        let mut conflicting = job;
        conflicting.request_digest = [9; 32];
        assert!(matches!(
            reopened.reserve_job(conflicting),
            Err(RepositoryError::IdempotencyConflict)
        ));
        let _ = fs::remove_dir_all(dir);
    }
}
