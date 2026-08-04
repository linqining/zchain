//! Durable, single-process repository for Texas proving jobs.
//!
//! The service intentionally keeps the storage format small and explicit: one
//! Borsh snapshot contains all table snapshots and dispatch job records.  A
//! write is staged to a sibling temporary file and renamed only after it has
//! been flushed, so a failed write never makes the in-memory state authoritative.
//! It is a durable job journal, not a consensus database or proof archive.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::Address;
use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;

use crate::{ServiceError, ServiceResult};

const SCHEMA_VERSION: u32 = 1;

/// A table state that can be rehydrated into a `TexasPokerPlugin` after a restart.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredTable {
    pub table_id: u64,
    pub table: TexasPokerTable,
    pub dispatch_count: u64,
    pub prove_count: u64,
}

/// Metadata retained for an accepted native proof.
///
/// The current Stwo proof object is process-local and deliberately not encoded
/// here.  The durable record instead identifies the exact replayed task and its
/// full-width state-root endpoints, allowing an auditor to retrieve/reprove the
/// task from its consensus source.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct StoredProofMetadata {
    pub task_digest: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
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
}

impl Default for RepositorySnapshot {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            next_job_nonce: 0,
            tables: Vec::new(),
            jobs: Vec::new(),
        }
    }
}

/// Result of reserving a request's idempotency slot.
#[derive(Debug, Clone)]
pub enum JobReservation {
    /// A prior completed or failed request has an immutable result.
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
}

impl ServiceRepository {
    /// Construct an empty in-memory repository.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            snapshot: RepositorySnapshot::default(),
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
                    StoredJobStatus::Completed | StoredJobStatus::Failed => {
                        Ok(JobReservation::Existing(existing.clone()))
                    }
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
    ) -> ServiceResult<()> {
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
