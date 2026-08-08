//! Durable, local-only HTTP proving service.
//!
//! `POST /tables/:table_id/dispatch` is deliberately restricted to loopback
//! addresses.  It is a development harness that replays unanchored candidate
//! transitions, not a network authority: its request format carries no block
//! inclusion proof, and callers must not mistake a local receipt for consensus
//! finality.  A production-facing service must instead accept authenticated
//! consensus material and build an anchor with
//! `poker_texas_air::consensus_anchor::build_anchor_from_consensus` before it
//! persists an externally usable receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::contracts::TexasPokerPlugin;
use crate::full_hand::{FullHandReport, FullHandRunner};
use crate::plugin::ContractPlugin;
use crate::proof_package::{
    DecodedServiceProofPackage, ServiceProofPackage, proof_package_digest, stored_proof_metadata,
};
use crate::repository::{
    JobReservation, RepositoryError, ServiceRepository, StoredDispatchJob, StoredDispatchResult,
    StoredJobStatus, StoredProofReference, StoredTable,
};
use crate::runner::HandRunner;
use crate::{ServiceError, ServiceResult};
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_texas_air::airs::composition::supports_composite_proof;
use poker_texas_air::consensus_anchor::ConsensusAnchorMaterial;
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::prove_task::MAX_METHOD_BATCH_ROWS;

const LEGACY_TABLE_ID: u64 = 0;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
/// Bound the decoded Borsh package before it reaches certificate/SMT verification.
const MAX_CONSENSUS_ANCHOR_BYTES: usize = 16 * 1024 * 1024;
/// Bound retained decoded proof material independently from the durable repository.
const MAX_VALIDATED_PACKAGE_CACHE_BYTES: usize = 256 * 1024 * 1024;
const MAX_VALIDATED_PACKAGE_CACHE_ENTRIES: usize = 64;

type HttpError = (axum::http::StatusCode, String);

/// HTTP service state.  A global runtime lock makes dispatch and repository
/// commits serializable; tables are nevertheless independent plugin instances.
#[derive(Clone)]
struct ServerState {
    runtime: Arc<Mutex<ServiceRuntime>>,
    last_report: Arc<Mutex<Option<HandReportJson>>>,
    last_full_report: Arc<Mutex<Option<FullHandReportJson>>>,
}

struct ServiceRuntime {
    repository: ServiceRepository,
    plugins: BTreeMap<u64, TexasPokerPlugin>,
    validated_packages: ValidatedPackageCache,
}

#[derive(Debug, Clone)]
struct CachedValidatedPackage {
    decoded: Arc<DecodedServiceProofPackage>,
    encoded_len: usize,
    last_used: u64,
}

#[derive(Debug, Default)]
struct ValidatedPackageCache {
    entries: BTreeMap<[u8; 32], CachedValidatedPackage>,
    encoded_bytes: usize,
    clock: u64,
    #[cfg(test)]
    hits: u64,
    #[cfg(test)]
    misses: u64,
}

impl ValidatedPackageCache {
    fn get(&mut self, digest: [u8; 32]) -> Option<Arc<DecodedServiceProofPackage>> {
        self.clock = self.clock.wrapping_add(1);
        let Some(entry) = self.entries.get_mut(&digest) else {
            #[cfg(test)]
            {
                self.misses = self.misses.saturating_add(1);
            }
            return None;
        };
        entry.last_used = self.clock;
        #[cfg(test)]
        {
            self.hits = self.hits.saturating_add(1);
        }
        Some(entry.decoded.clone())
    }

    fn insert(
        &mut self,
        digest: [u8; 32],
        encoded_len: usize,
        decoded: Arc<DecodedServiceProofPackage>,
    ) {
        if encoded_len > MAX_VALIDATED_PACKAGE_CACHE_BYTES {
            return;
        }
        self.clock = self.clock.wrapping_add(1);
        if let Some(previous) = self.entries.remove(&digest) {
            self.encoded_bytes = self.encoded_bytes.saturating_sub(previous.encoded_len);
        }
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_VALIDATED_PACKAGE_CACHE_ENTRIES
                || self.encoded_bytes.saturating_add(encoded_len)
                    > MAX_VALIDATED_PACKAGE_CACHE_BYTES)
        {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(digest, _)| *digest)
            else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&oldest) {
                self.encoded_bytes = self.encoded_bytes.saturating_sub(evicted.encoded_len);
            }
        }
        self.encoded_bytes = self.encoded_bytes.saturating_add(encoded_len);
        self.entries.insert(
            digest,
            CachedValidatedPackage {
                decoded,
                encoded_len,
                last_used: self.clock,
            },
        );
    }
}

impl ServiceRuntime {
    fn new(repository: ServiceRepository) -> ServiceResult<Self> {
        let mut plugins: BTreeMap<u64, TexasPokerPlugin> = repository
            .tables()
            .iter()
            .map(|stored| {
                (
                    stored.table_id,
                    TexasPokerPlugin::from_persisted_state(
                        stored.table.clone(),
                        stored.dispatch_count,
                        stored.prove_count,
                    ),
                )
            })
            .collect();

        // Rebuild every table's verifier-issued receipt history from durable
        // proof sidecars in the same serialized order in which jobs committed.
        // Completed proof metadata is authoritative: a missing or invalid
        // sidecar makes startup fail closed instead of silently shortening the
        // chain that a later consensus anchor would inspect.
        let jobs = repository.jobs().to_vec();
        let mut restored_tagged = BTreeSet::new();
        let mut validated_packages = ValidatedPackageCache::default();
        for job in &jobs {
            let Some(result) = job.result.as_ref() else {
                if job.status == StoredJobStatus::Completed {
                    return Err(ServiceError::Runner(format!(
                        "completed job {} is missing result metadata",
                        hex::encode(job.job_id())
                    )));
                }
                continue;
            };
            if job.status != StoredJobStatus::Completed {
                continue;
            }
            if !result.had_prove_task && !result.proof_verified && job.proof.is_none() {
                continue;
            }
            if !result.had_prove_task || !result.proof_verified {
                return Err(ServiceError::Runner(format!(
                    "completed job {} has inconsistent proof flags",
                    hex::encode(job.job_id())
                )));
            }
            let stored_metadata = job.proof.as_ref().ok_or_else(|| {
                ServiceError::Runner(format!(
                    "completed proof job {} is missing proof metadata",
                    hex::encode(job.job_id())
                ))
            })?;
            let reference = job.proof_reference.ok_or_else(|| {
                ServiceError::Runner(format!(
                    "completed proof job {} is missing its package reference",
                    hex::encode(job.job_id())
                ))
            })?;
            if matches!(
                reference,
                StoredProofReference::Tagged { batch_id, .. }
                    if restored_tagged.contains(&batch_id)
            ) {
                // The first row validated the complete ordered job set and restored every receipt.
                // Later rows still passed lifecycle/metadata-presence checks above, but need not
                // reload, decode or replay the same shared sidecar.
                continue;
            }
            let bytes = repository.load_job_proof_package(job)?.ok_or_else(|| {
                ServiceError::Runner(format!(
                    "completed proof job {} is missing its durable proof package",
                    hex::encode(job.job_id())
                ))
            })?;
            let package_digest = proof_package_digest(&bytes);
            let decoded = Arc::new(ServiceProofPackage::decode_bytes(&bytes)?);
            let package = decoded.package();
            let task = decoded.task_at(reference.row_index())?;
            validate_job_task(job, result, stored_metadata, &task)?;
            let plugin = plugins.get_mut(&job.table_id).ok_or_else(|| {
                ServiceError::Runner(format!(
                    "completed proof job {} references missing table {}",
                    hex::encode(job.job_id()),
                    job.table_id
                ))
            })?;
            match reference {
                StoredProofReference::Single { package_id } => {
                    if package_id != job.job_id || decoded.row_count()? != 1 {
                        return Err(ServiceError::Prover(
                            "single proof reference does not own exactly one package row".into(),
                        ));
                    }
                    let (task, archive, composition) = package.single_parts().ok_or_else(|| {
                        ServiceError::Prover(
                            "single proof reference targets a tagged package".into(),
                        )
                    })?;
                    plugin.restore_archived_task(task, archive, composition)?;
                    validated_packages.insert(package_digest, bytes.len(), decoded);
                }
                StoredProofReference::Tagged {
                    batch_id,
                    row_index,
                    row_count,
                } => {
                    if package.batch_id() != Some(batch_id) || decoded.row_count()? != row_count {
                        return Err(ServiceError::Prover(
                            "tagged proof reference scope differs from shared package".into(),
                        ));
                    }
                    if row_index != 0 {
                        return Err(ServiceError::Prover(
                            "first journal reference to a tagged package is not row zero".into(),
                        ));
                    }
                    validate_complete_tagged_job_set(&jobs, batch_id, &decoded)?;
                    plugin.restore_tagged_batch_with_replayed_tasks(
                        decoded.tasks(),
                        package.tagged().ok_or_else(|| {
                            ServiceError::Prover(
                                "tagged proof reference targets a single package".into(),
                            )
                        })?,
                    )?;
                    restored_tagged.insert(batch_id);
                    validated_packages.insert(package_digest, bytes.len(), decoded);
                }
            }
        }

        for stored in repository.tables() {
            let plugin = plugins
                .get(&stored.table_id)
                .expect("plugin was constructed for every stored table");
            let restored = u64::try_from(plugin.proven().len()).map_err(|_| {
                ServiceError::Runner("restored proof count does not fit u64".into())
            })?;
            if restored != stored.prove_count {
                return Err(ServiceError::Runner(format!(
                    "table {} restored {restored} proofs but journal expects {}",
                    stored.table_id, stored.prove_count
                )));
            }
        }

        // Tentative composite streams survive restart but remain excluded from
        // the verified receipt chain until explicit or automatic finalization.
        for pending in repository.pending_tagged_batches() {
            let plugin = plugins.get_mut(&pending.table_id).ok_or_else(|| {
                ServiceError::Runner(format!(
                    "pending tagged batch references missing table {}",
                    pending.table_id
                ))
            })?;
            if pending.tasks.len() != pending.job_ids.len() || pending.tasks.is_empty() {
                return Err(ServiceError::Runner(
                    "pending tagged batch has inconsistent row storage".into(),
                ));
            }
            for (job_id, task) in pending.job_ids.iter().zip(&pending.tasks) {
                let job = repository.job(*job_id).ok_or_else(|| {
                    ServiceError::Runner("pending tagged row references a missing job".into())
                })?;
                let result = job.result.as_ref().ok_or_else(|| {
                    ServiceError::Runner("pending tagged job is missing result metadata".into())
                })?;
                let metadata = job.proof.as_ref().ok_or_else(|| {
                    ServiceError::Runner("pending tagged job is missing proof metadata".into())
                })?;
                if job.status != StoredJobStatus::PendingProof
                    || job.proof_reference.is_some()
                    || !result.had_prove_task
                    || result.proof_verified
                {
                    return Err(ServiceError::Runner(
                        "pending tagged job has inconsistent lifecycle flags".into(),
                    ));
                }
                validate_job_task(job, result, metadata, task)?;
                plugin.queue_tagged_batch_task(task)?;
            }
        }

        Ok(Self {
            repository,
            plugins,
            validated_packages,
        })
    }

    fn staged_plugin(&mut self, table_id: u64) -> TexasPokerPlugin {
        self.plugins
            .entry(table_id)
            .or_insert_with(|| new_service_plugin(table_id))
            .clone()
    }
}

fn validate_job_task(
    job: &StoredDispatchJob,
    result: &StoredDispatchResult,
    stored: &crate::repository::StoredProofMetadata,
    task: &poker_texas_air::prove_task::ProveTask,
) -> ServiceResult<()> {
    let expected = stored_proof_metadata(task)?;
    if stored.task_digest != expected.task_digest
        || stored.pre_state_root != expected.pre_state_root
        || stored.post_state_root != expected.post_state_root
        || task.table_id != job.table_id
        || task.hand_id != result.hand_id
        || task.call_seq != result.call_seq
        || u64::from(task.post_table.call_seq) != result.table_version
    {
        return Err(ServiceError::Prover(format!(
            "durable proof row for job {} does not match journal metadata",
            hex::encode(job.job_id())
        )));
    }
    Ok(())
}

fn validate_complete_tagged_job_set(
    jobs: &[StoredDispatchJob],
    batch_id: [u8; 32],
    package: &DecodedServiceProofPackage,
) -> ServiceResult<()> {
    let tasks = package.tasks();
    let batch_jobs = jobs
        .iter()
        .filter(|job| {
            matches!(
                job.proof_reference,
                Some(StoredProofReference::Tagged { batch_id: id, .. }) if id == batch_id
            )
        })
        .collect::<Vec<_>>();
    if batch_jobs.len() != tasks.len() {
        return Err(ServiceError::Prover(
            "shared tagged package does not have exactly one journal job per row".into(),
        ));
    }
    let mut base_prove_count = None;
    let mut base_chain_length = None;
    for (expected_index, (job, task)) in batch_jobs.iter().zip(tasks).enumerate() {
        let Some(StoredProofReference::Tagged {
            row_index,
            row_count,
            ..
        }) = job.proof_reference
        else {
            unreachable!("batch_jobs contains only tagged references")
        };
        if usize::from(row_index) != expected_index || usize::from(row_count) != tasks.len() {
            return Err(ServiceError::Prover(
                "tagged package journal rows are reordered, duplicated, or incomplete".into(),
            ));
        }
        let result = job.result.as_ref().ok_or_else(|| {
            ServiceError::Runner("completed tagged job is missing result metadata".into())
        })?;
        let metadata = job.proof.as_ref().ok_or_else(|| {
            ServiceError::Runner("completed tagged job is missing proof metadata".into())
        })?;
        if job.status != StoredJobStatus::Completed
            || !result.had_prove_task
            || !result.proof_verified
        {
            return Err(ServiceError::Runner(
                "tagged package job set has inconsistent lifecycle flags".into(),
            ));
        }
        let completed_rows = u64::try_from(expected_index + 1)
            .map_err(|_| ServiceError::Runner("tagged row index does not fit u64".into()))?;
        let prove_base = match base_prove_count {
            Some(base) => base,
            None => {
                let base = result
                    .prove_count
                    .checked_sub(completed_rows)
                    .ok_or_else(|| ServiceError::Runner("tagged prove counter underflow".into()))?;
                base_prove_count = Some(base);
                base
            }
        };
        let chain_base = match base_chain_length {
            Some(base) => base,
            None => {
                let base = result
                    .chain_length
                    .checked_sub(completed_rows)
                    .ok_or_else(|| ServiceError::Runner("tagged chain counter underflow".into()))?;
                base_chain_length = Some(base);
                base
            }
        };
        if result.prove_count
            != prove_base
                .checked_add(completed_rows)
                .ok_or_else(|| ServiceError::Runner("tagged prove counter overflow".into()))?
            || result.chain_length
                != chain_base
                    .checked_add(completed_rows)
                    .ok_or_else(|| ServiceError::Runner("tagged chain counter overflow".into()))?
        {
            return Err(ServiceError::Runner(
                "tagged package job counters are not exact per-row history positions".into(),
            ));
        }
        validate_job_task(job, result, metadata, task)?;
    }
    Ok(())
}

impl ServerState {
    fn from_repository(repository: ServiceRepository) -> ServiceResult<Self> {
        Ok(Self {
            runtime: Arc::new(Mutex::new(ServiceRuntime::new(repository)?)),
            last_report: Arc::new(Mutex::new(None)),
            last_full_report: Arc::new(Mutex::new(None)),
        })
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::from_repository(ServiceRepository::in_memory())
            .expect("empty in-memory proving repository must recover")
    }
}

/// HandReport JSON serialization.
#[derive(Debug, Clone, Serialize)]
pub struct HandReportJson {
    pub steps: Vec<(String, bool)>,
    pub chain_ok: bool,
    /// `false` means descriptor-only aggregation was rejected as expected.
    pub aggregate_ok: Option<bool>,
    pub dispatch_count: u64,
    pub prove_count: u64,
    pub chain_length: usize,
}

impl HandReportJson {
    fn from_report(r: &crate::runner::HandReport) -> Self {
        Self {
            steps: r
                .steps
                .iter()
                .map(|(name, ok)| ((*name).to_string(), *ok))
                .collect(),
            chain_ok: r.chain_ok,
            aggregate_ok: r.aggregate_ok,
            dispatch_count: r.stats.dispatch_count,
            prove_count: r.stats.prove_count,
            chain_length: r.stats.chain_length,
        }
    }
}

/// JSON representation of one full-hand dispatch/prove step.
#[derive(Debug, Clone, Serialize)]
pub struct FullHandStepJson {
    pub method: String,
    pub dispatch_micros: u64,
    pub prove_verify_micros: u64,
    pub ok: bool,
}

/// JSON representation of the complete 32-transition Texas proving run plus batch finalization.
#[derive(Debug, Clone, Serialize)]
pub struct FullHandReportJson {
    pub steps: Vec<FullHandStepJson>,
    pub total_micros: u64,
    pub chain_ok: bool,
    pub dispatch_count: u64,
    pub prove_count: u64,
    pub chain_length: usize,
    pub winner_seat: Option<u8>,
    pub stopped_at: Option<String>,
}

impl FullHandReportJson {
    fn from_report(report: &FullHandReport) -> Self {
        Self {
            steps: report
                .steps
                .iter()
                .map(|step| FullHandStepJson {
                    method: step.method.clone(),
                    dispatch_micros: duration_micros(step.dispatch),
                    prove_verify_micros: duration_micros(step.prove),
                    ok: step.ok,
                })
                .collect(),
            total_micros: duration_micros(report.total),
            chain_ok: report.chain_ok,
            dispatch_count: report.stats.dispatch_count,
            prove_count: report.stats.prove_count,
            chain_length: report.stats.chain_length,
            winner_seat: report.winner_seat,
            stopped_at: report.stopped_at.clone(),
        }
    }
}

fn duration_micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Dispatch request.  Supplying `idempotency_key` makes retries safe across a
/// service restart.  Requests without it remain supported but are intentionally
/// treated as new dispatches.
#[derive(Debug, Deserialize)]
pub struct DispatchRequest {
    /// Caller address (20-byte hexadecimal).
    pub caller_hex: String,
    /// Optional tagged caller public key (`tag || raw`, hexadecimal).  When
    /// supplied it must derive `caller_hex`, and its exact bytes are committed
    /// to the generated receipt.  Supplying it is required for a later
    /// `/verify-chain-consensus` success path because consensus reconstruction
    /// derives the dispatch context from the transaction's tagged public key.
    #[serde(default)]
    pub caller_pubkey_hex: Option<String>,
    /// Chain identifier used by the consensus transaction that will later
    /// authenticate this dispatch.  This field, `block_height`, and
    /// `block_timestamp_ms` must either all be supplied with
    /// `caller_pubkey_hex`, or all be omitted for the compatibility-only local
    /// development path.
    #[serde(default)]
    pub chain_id: Option<u64>,
    /// Height of the block whose execution context produced this transition.
    #[serde(default)]
    pub block_height: Option<u64>,
    /// Timestamp of the block whose execution context produced this transition.
    #[serde(default)]
    pub block_timestamp_ms: Option<u64>,
    /// Method selector (32-byte hexadecimal).
    pub selector_hex: String,
    /// Borsh method arguments (hexadecimal).
    pub args_hex: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// Authenticated consensus material submitted to verify a live receipt range.
///
/// The package is Borsh-encoded [`ConsensusAnchorMaterial`] represented as hex.
/// It contains block headers, certificates and SMT inclusion paths; the service
/// verifies all of them before accepting an anchor.  This route deliberately
/// verifies only the current in-memory receipt segment, because the local job
/// journal is not a STARK proof archive.
#[derive(Debug, Deserialize)]
pub struct ConsensusAnchorRequest {
    /// Hexadecimal Borsh encoding of `ConsensusAnchorMaterial`.
    pub material_borsh_hex: String,
}

/// A completed dispatch result.
#[derive(Debug, Clone, Serialize)]
pub struct DispatchResponse {
    pub job_id: String,
    pub table_id: u64,
    /// True only when this exact idempotent request was served from durable state.
    pub replayed: bool,
    pub had_prove_task: bool,
    /// True only when a generated task completed native prove and verify.
    pub proof_verified: bool,
    pub events_count: usize,
    pub dispatch_count: u64,
    pub prove_count: u64,
    /// Receipts in the current process segment.  Restarting begins a new host
    /// segment; use stored job metadata plus a consensus anchor for audit.
    pub chain_length: usize,
    pub table_version: u64,
    pub hand_id: u32,
    pub call_seq: u32,
}

/// Read-only job representation for `/jobs/:job_id`.
#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub job_id: String,
    pub table_id: u64,
    pub status: &'static str,
    pub attempts: u32,
    pub result: Option<DispatchResponse>,
    pub task_digest_hex: Option<String>,
    pub pre_state_root_hex: Option<String>,
    pub post_state_root_hex: Option<String>,
    pub proof_package_id_hex: Option<String>,
    pub proof_row_index: Option<u16>,
    pub proof_row_count: Option<u16>,
    pub proof_archive_available: bool,
    pub error: Option<String>,
}

/// Result of reverifying a durable proof package after service restart.
#[derive(Debug, Serialize)]
pub struct ProofVerificationResponse {
    pub job_id: String,
    pub verified: bool,
    pub method: &'static str,
    pub table_id: u64,
    pub hand_id: u32,
    pub call_seq: u32,
    pub pre_state_root_hex: String,
    pub post_state_root_hex: String,
}

/// Result of explicitly flushing one table's pending tagged rows.
#[derive(Debug, Serialize)]
pub struct FinalizeProofsResponse {
    pub table_id: u64,
    pub finalized_rows: usize,
    pub batch_id_hex: Option<String>,
    pub prove_count: u64,
    pub chain_length: usize,
}

/// Result of anchoring the current live receipt segment to authenticated consensus data.
#[derive(Debug, Serialize)]
pub struct ConsensusAnchorResponse {
    /// Table whose receipts and table snapshots were authenticated.
    pub table_id: u64,
    /// Hand shared by every receipt in the verified range.
    pub hand_id: u32,
    /// First authenticated call sequence, inclusive.
    pub first_call_seq: u32,
    /// Last authenticated call sequence, inclusive.
    pub last_call_seq: u32,
    /// Exact number of authenticated dispatch calls/receipts.
    pub call_count: usize,
}

/// Start the loopback-only development proving service.
///
/// Override the state file with `ZCHAIN_PROVING_SERVICE_STATE` when running
/// more than one local instance.  Binding the unanchored dispatch harness to a
/// non-loopback address is rejected; it has no request authentication or
/// consensus-inclusion verification.
pub async fn serve(addr: SocketAddr) -> ServiceResult<()> {
    let state_path = std::env::var_os("ZCHAIN_PROVING_SERVICE_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("proving_service_state.borsh"));
    serve_with_repository_path(addr, state_path).await
}

/// Start the loopback-only development service with an explicit repository.
///
/// The durable repository makes retries crash-safe, but it does not make its
/// local dispatches consensus-authenticated.  See [`serve`] for the binding
/// restriction.
pub async fn serve_with_repository_path(
    addr: SocketAddr,
    repository_path: impl AsRef<Path>,
) -> ServiceResult<()> {
    ensure_loopback_bind(addr)?;
    let state = ServerState::from_repository(ServiceRepository::open(repository_path)?)?;
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| ServiceError::Runner(format!("bind {addr}: {error}")))?;
    tracing::info!("proving_service listening on {addr}");
    axum::serve(listener, app)
        .await
        .map_err(|error| ServiceError::Runner(format!("serve: {error}")))?;
    Ok(())
}

/// Construct the HTTP application for the loopback development service.
///
/// Keeping route assembly separate lets integration tests exercise the same
/// JSON/path routing stack as a real listener without exposing an unanchored
/// mutation endpoint on a non-loopback address.
fn router(state: ServerState) -> axum::Router {
    axum::Router::new()
        // Legacy single-table compatibility route.
        .route("/dispatch", post(dispatch_legacy))
        .route("/tables/:table_id/dispatch", post(dispatch_table))
        .route(
            "/tables/:table_id/finalize-proofs",
            post(finalize_table_proofs),
        )
        .route(
            "/tables/:table_id/verify-chain-consensus",
            post(verify_table_chain_consensus),
        )
        .route("/jobs/:job_id", get(get_job))
        .route("/jobs/:job_id/proof", get(get_job_proof))
        .route("/jobs/:job_id/verify-proof", post(verify_job_proof))
        .route("/hands/run", post(run_hand))
        .route("/hands/run-full", post(run_full_hand))
        .route("/plugins", get(list_plugins))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

/// Reject exposing the unanchored state-mutating harness over the network.
fn ensure_loopback_bind(addr: SocketAddr) -> ServiceResult<()> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    Err(ServiceError::Runner(format!(
        "refusing to bind unanchored proving dispatch service to {addr}; use a consensus-anchored adapter for non-loopback deployment"
    )))
}

async fn run_hand(State(state): State<ServerState>) -> Result<Json<HandReportJson>, HttpError> {
    let (_plugin, report) = tokio::task::spawn_blocking(|| HandRunner::new().run())
        .await
        .map_err(|error| internal_error(format!("hand runner task failed: {error}")))?
        .map_err(|error| internal_error(error.to_string()))?;
    let json = HandReportJson::from_report(&report);
    *state.last_report.lock().await = Some(json.clone());
    Ok(Json(json))
}

async fn run_full_hand(
    State(state): State<ServerState>,
) -> Result<Json<FullHandReportJson>, HttpError> {
    let (_plugin, report) = tokio::task::spawn_blocking(|| FullHandRunner::new().run())
        .await
        .map_err(|error| internal_error(format!("full-hand runner task failed: {error}")))?;
    let json = FullHandReportJson::from_report(&report);
    *state.last_full_report.lock().await = Some(json.clone());
    Ok(Json(json))
}

async fn dispatch_legacy(
    State(state): State<ServerState>,
    Json(request): Json<DispatchRequest>,
) -> Result<Json<DispatchResponse>, HttpError> {
    dispatch_for_table(state, LEGACY_TABLE_ID, request).await
}

async fn dispatch_table(
    State(state): State<ServerState>,
    AxumPath(table_id): AxumPath<u64>,
    Json(request): Json<DispatchRequest>,
) -> Result<Json<DispatchResponse>, HttpError> {
    dispatch_for_table(state, table_id, request).await
}

async fn dispatch_for_table(
    state: ServerState,
    table_id: u64,
    request: DispatchRequest,
) -> Result<Json<DispatchResponse>, HttpError> {
    let caller = decode_fixed_hex::<20>(&request.caller_hex, "caller_hex")?;
    let caller_pubkey = request
        .caller_pubkey_hex
        .as_deref()
        .map(|encoded| {
            let bytes = hex::decode(encoded).map_err(|error| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("caller_pubkey_hex must be hexadecimal: {error}"),
                )
            })?;
            poker_l1::signature::TaggedPubkey::from_bytes(&bytes).map_err(|error| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("caller_pubkey_hex is not a valid tagged public key: {error}"),
                )
            })
        })
        .transpose()?;
    if let Some(pubkey) = &caller_pubkey
        && poker_l1::account::derive_address(pubkey) != caller
    {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "caller_hex does not match caller_pubkey_hex-derived address".into(),
        ));
    }
    let selector = decode_fixed_hex::<32>(&request.selector_hex, "selector_hex")?;
    let args = hex::decode(&request.args_hex).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("args_hex must be hexadecimal: {error}"),
        )
    })?;
    let idempotency_key = normalize_idempotency_key(request.idempotency_key)?;
    let consensus_context = match (
        request.chain_id,
        request.block_height,
        request.block_timestamp_ms,
    ) {
        (None, None, None) => None,
        (Some(chain_id), Some(block_height), Some(block_timestamp_ms)) => {
            Some((chain_id, block_height, block_timestamp_ms))
        }
        _ => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                "chain_id, block_height and block_timestamp_ms must be supplied together".into(),
            ));
        }
    };
    if caller_pubkey.is_some() != consensus_context.is_some() {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "caller_pubkey_hex and the complete consensus execution context must be supplied together"
                .into(),
        ));
    }
    let request_digest = digest_request(
        table_id,
        &idempotency_key,
        caller,
        caller_pubkey.as_ref(),
        consensus_context,
        selector,
        &args,
    );

    // Proving is CPU-bound and deliberately serialized with repository writes.
    // The staged clone means dispatch/prove errors cannot mutate the committed
    // table, while `complete_job` persists both job and table before memory is
    // updated.
    let mut runtime = state.runtime.lock().await;
    let nonce = if idempotency_key.is_none() {
        Some(
            runtime
                .repository
                .next_job_nonce()
                .map_err(|error| internal_error(error.to_string()))?,
        )
    } else {
        None
    };
    let job = StoredDispatchJob {
        job_id: digest_job_id(table_id, request_digest, nonce),
        table_id,
        idempotency_key,
        request_digest,
        caller,
        selector,
        args: args.clone(),
        status: StoredJobStatus::Running,
        attempts: 0,
        result: None,
        proof: None,
        proof_reference: None,
        error: None,
    };
    let job = match runtime.repository.reserve_job(job) {
        Ok(JobReservation::Existing(job)) => return completed_job_response(job, true),
        Ok(JobReservation::Execute(job)) => job,
        Err(RepositoryError::IdempotencyConflict) => {
            return Err((
                axum::http::StatusCode::CONFLICT,
                "idempotency key has already been used for a different dispatch".into(),
            ));
        }
        Err(error) => return Err(internal_error(error.to_string())),
    };

    let selector_is_tagged = MethodKind::all()
        .into_iter()
        .find(|kind| kind.selector() == selector)
        .is_some_and(supports_composite_proof);
    let pending_rows = runtime
        .repository
        .pending_tagged_batch(table_id)
        .map_or(0, |batch| batch.tasks.len());
    if pending_rows != 0
        && (!selector_is_tagged || pending_rows >= MAX_METHOD_BATCH_ROWS)
        && let Err(error) = finalize_pending_tagged_batch(&mut runtime, table_id)
    {
        return fail_reserved_job(&mut runtime, job, error.to_string());
    }

    let mut staged = runtime.staged_plugin(table_id);
    let context = match (caller_pubkey, consensus_context) {
        (None, None) => DispatchContext {
            caller,
            // Compatibility-only development mode.  A receipt from this path
            // cannot match an authenticated transaction unless the caller
            // supplies the exact public key and consensus context above.
            caller_pubkey: poker_l1::signature::TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            block_height: 100,
            block_timestamp: 1_000_000,
        },
        (Some(caller_pubkey), Some((chain_id, block_height, block_timestamp))) => DispatchContext {
            caller,
            caller_pubkey,
            chain_id,
            block_height,
            block_timestamp,
        },
        _ => unreachable!("public key/context pairing was validated above"),
    };
    let outcome = match staged.dispatch_with_context(&context, &selector, &args) {
        Ok(outcome) => outcome,
        Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
    };
    let had_prove_task = outcome.prove_task.is_some();
    if let Some(task) = &outcome.prove_task
        && supports_composite_proof(task.method_kind)
    {
        if let Err(error) = staged.queue_tagged_batch_task(task) {
            return fail_reserved_job(&mut runtime, job, error.to_string());
        }
        let metadata = match stored_proof_metadata(task) {
            Ok(proof) => proof,
            Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
        };
        let stats = staged.stats();
        let table = staged.table();
        let result = StoredDispatchResult {
            had_prove_task: true,
            proof_verified: false,
            events_count: u64::try_from(outcome.output.events.len())
                .map_err(|_| internal_error("events count does not fit u64".into()))?,
            dispatch_count: stats.dispatch_count,
            prove_count: stats.prove_count,
            chain_length: u64::try_from(stats.chain_length)
                .map_err(|_| internal_error("chain length does not fit u64".into()))?,
            table_version: u64::from(table.call_seq),
            hand_id: table.hand_id,
            call_seq: table.call_seq,
        };
        let stored_table = StoredTable {
            table_id,
            table: table.clone(),
            dispatch_count: stats.dispatch_count,
            prove_count: stats.prove_count,
        };
        runtime
            .repository
            .queue_pending_tagged_job(
                stored_table,
                job.clone(),
                result.clone(),
                metadata,
                task.clone(),
            )
            .map_err(|error| internal_error(error.to_string()))?;
        runtime.plugins.insert(table_id, staged);
        return Ok(Json(response_from_result(
            job.job_id(),
            table_id,
            result,
            false,
        )?));
    }
    let (proof, proof_package) = if let Some(task) = &outcome.prove_task {
        let archived = match staged.prove_task_archived(task) {
            Ok(archived) => archived,
            Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
        };
        let metadata = match stored_proof_metadata(task) {
            Ok(proof) => proof,
            Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
        };
        let package = match ServiceProofPackage::new(
            task.clone(),
            archived.archive,
            archived.composition_archive,
        )
        .and_then(|package| package.to_bytes())
        {
            Ok(package) => package,
            Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
        };
        (Some(metadata), Some(package))
    } else {
        (None, None)
    };

    let stats = staged.stats();
    let table = staged.table();
    let result = StoredDispatchResult {
        had_prove_task,
        proof_verified: had_prove_task,
        events_count: u64::try_from(outcome.output.events.len())
            .map_err(|_| internal_error("events count does not fit u64".into()))?,
        dispatch_count: stats.dispatch_count,
        prove_count: stats.prove_count,
        chain_length: u64::try_from(stats.chain_length)
            .map_err(|_| internal_error("chain length does not fit u64".into()))?,
        // Legacy response/journal field retained for schema-v1 compatibility. Texas schema v17
        // has no table-local version, so this alias is derived from the sole command sequence.
        table_version: u64::from(table.call_seq),
        hand_id: table.hand_id,
        call_seq: table.call_seq,
    };
    let stored_table = StoredTable {
        table_id,
        table: table.clone(),
        dispatch_count: stats.dispatch_count,
        prove_count: stats.prove_count,
    };
    if let Some(package) = &proof_package {
        runtime
            .repository
            .store_proof_package(job.job_id(), package)
            .map_err(|error| internal_error(error.to_string()))?;
    }
    let proof_reference = proof.as_ref().map(|_| StoredProofReference::Single {
        package_id: job.job_id(),
    });
    runtime
        .repository
        .complete_job(
            stored_table,
            job.clone(),
            result.clone(),
            proof,
            proof_reference,
        )
        .map_err(|error| internal_error(error.to_string()))?;
    runtime.plugins.insert(table_id, staged);
    Ok(Json(response_from_result(
        job.job_id(),
        table_id,
        result,
        false,
    )?))
}

async fn finalize_table_proofs(
    State(state): State<ServerState>,
    AxumPath(table_id): AxumPath<u64>,
) -> Result<Json<FinalizeProofsResponse>, HttpError> {
    let mut runtime = state.runtime.lock().await;
    let finalized = finalize_pending_tagged_batch(&mut runtime, table_id)
        .map_err(|error| unprocessable(error.to_string()))?;
    let plugin = runtime.plugins.get(&table_id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            "table was not found".to_string(),
        )
    })?;
    let stats = plugin.stats();
    Ok(Json(FinalizeProofsResponse {
        table_id,
        finalized_rows: finalized.as_ref().map_or(0, |result| result.1),
        batch_id_hex: finalized.map(|result| hex::encode(result.0)),
        prove_count: stats.prove_count,
        chain_length: stats.chain_length,
    }))
}

fn finalize_pending_tagged_batch(
    runtime: &mut ServiceRuntime,
    table_id: u64,
) -> ServiceResult<Option<([u8; 32], usize)>> {
    let Some(pending) = runtime.repository.pending_tagged_batch(table_id).cloned() else {
        return Ok(None);
    };
    if pending.tasks.is_empty()
        || pending.tasks.len() > MAX_METHOD_BATCH_ROWS
        || pending.tasks.len() != pending.job_ids.len()
    {
        return Err(ServiceError::Runner(
            "pending tagged batch has an invalid row set".into(),
        ));
    }
    let mut staged = runtime.staged_plugin(table_id);
    let runtime_pending = borsh::to_vec(staged.pending_tagged_tasks())
        .map_err(|error| ServiceError::Runner(format!("encode runtime pending rows: {error}")))?;
    let durable_pending = borsh::to_vec(&pending.tasks)
        .map_err(|error| ServiceError::Runner(format!("encode durable pending rows: {error}")))?;
    if runtime_pending != durable_pending {
        return Err(ServiceError::Runner(
            "runtime and repository pending tagged rows differ".into(),
        ));
    }
    let previous_packages = staged.tagged_batches().len();
    let package_count = staged.finalize_tagged_batches()?;
    if package_count != 1 || staged.tagged_batches().len() != previous_packages + 1 {
        return Err(ServiceError::Runner(
            "one bounded pending stream did not produce exactly one tagged package".into(),
        ));
    }
    let package = staged
        .tagged_batches()
        .last()
        .expect("one finalized package was appended")
        .clone();
    let batch_id = package.method().batch_id();
    let row_count = package.method().row_count();
    if usize::from(row_count) != pending.tasks.len() {
        return Err(ServiceError::Runner(
            "tagged package row count differs from pending journal".into(),
        ));
    }
    let decoded = Arc::new(DecodedServiceProofPackage::new_verified_tagged(
        package,
        pending.tasks.clone(),
    )?);
    let bytes = decoded.to_bytes()?;
    runtime.repository.store_proof_package(batch_id, &bytes)?;

    let stats = staged.stats();
    let stored_table = StoredTable {
        table_id,
        table: staged.table().clone(),
        dispatch_count: stats.dispatch_count,
        prove_count: stats.prove_count,
    };
    runtime.repository.complete_pending_tagged_batch(
        stored_table,
        batch_id,
        row_count,
        u64::try_from(stats.chain_length)
            .map_err(|_| ServiceError::Runner("chain length does not fit u64".into()))?,
    )?;
    runtime
        .validated_packages
        .insert(proof_package_digest(&bytes), bytes.len(), decoded);
    runtime.plugins.insert(table_id, staged);
    Ok(Some((batch_id, pending.tasks.len())))
}

fn fail_reserved_job(
    runtime: &mut ServiceRuntime,
    job: StoredDispatchJob,
    error: String,
) -> Result<Json<DispatchResponse>, HttpError> {
    runtime
        .repository
        .fail_job(job.job_id(), error.clone())
        .map_err(|persistence_error| internal_error(persistence_error.to_string()))?;
    Err((axum::http::StatusCode::UNPROCESSABLE_ENTITY, error))
}

async fn get_job(
    State(state): State<ServerState>,
    AxumPath(job_hex): AxumPath<String>,
) -> Result<Json<JobResponse>, HttpError> {
    let job_id = decode_fixed_hex::<32>(&job_hex, "job_id")?;
    let runtime = state.runtime.lock().await;
    let job = runtime.repository.job(job_id).cloned().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            "proving job was not found".to_string(),
        )
    })?;
    let archive_available = runtime
        .repository
        .has_job_proof_package(&job)
        .map_err(|error| internal_error(error.to_string()))?;
    Ok(Json(job_response(job, archive_available)?))
}

async fn get_job_proof(
    State(state): State<ServerState>,
    AxumPath(job_hex): AxumPath<String>,
) -> Result<Response, HttpError> {
    let job_id = decode_fixed_hex::<32>(&job_hex, "job_id")?;
    let runtime = state.runtime.lock().await;
    let (_job, bytes) = completed_job_proof(&runtime.repository, job_id)?;
    Ok(([(CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn verify_job_proof(
    State(state): State<ServerState>,
    AxumPath(job_hex): AxumPath<String>,
) -> Result<Json<ProofVerificationResponse>, HttpError> {
    let job_id = decode_fixed_hex::<32>(&job_hex, "job_id")?;
    let mut runtime = state.runtime.lock().await;
    let (job, bytes) = completed_job_proof(&runtime.repository, job_id)?;
    let package_digest = proof_package_digest(&bytes);
    let (decoded, already_verified) = match runtime.validated_packages.get(package_digest) {
        Some(decoded) => (decoded, true),
        None => (
            Arc::new(
                ServiceProofPackage::decode_bytes(&bytes)
                    .map_err(|error| unprocessable(error.to_string()))?,
            ),
            false,
        ),
    };
    let package = decoded.package();
    let reference = job
        .proof_reference
        .ok_or_else(|| internal_error("completed proof job is missing reference".into()))?;
    let task = decoded
        .task_at(reference.row_index())
        .map_err(|error| unprocessable(error.to_string()))?;
    let expected_metadata =
        stored_proof_metadata(&task).map_err(|error| unprocessable(error.to_string()))?;
    let stored_metadata = job
        .proof
        .as_ref()
        .ok_or_else(|| internal_error("completed proof job is missing metadata".into()))?;
    if stored_metadata.task_digest != expected_metadata.task_digest
        || stored_metadata.pre_state_root != expected_metadata.pre_state_root
        || stored_metadata.post_state_root != expected_metadata.post_state_root
    {
        return Err(unprocessable(
            "stored proof package does not match completed job metadata".into(),
        ));
    }
    match reference {
        StoredProofReference::Single { package_id } => {
            if package_id != job.job_id || decoded.row_count().ok() != Some(1) {
                return Err(unprocessable(
                    "single proof reference differs from owned package".into(),
                ));
            }
            let (single_task, archive, composition) = package.single_parts().ok_or_else(|| {
                unprocessable("single proof reference targets a tagged package".into())
            })?;
            if !already_verified {
                Orchestrator::verify_archived_task_parts(single_task, archive, composition)
                    .map_err(|error| unprocessable(error.to_string()))?;
            }
        }
        StoredProofReference::Tagged {
            batch_id,
            row_count,
            ..
        } => {
            if package.batch_id() != Some(batch_id) || decoded.row_count().ok() != Some(row_count) {
                return Err(unprocessable(
                    "tagged proof reference differs from shared package".into(),
                ));
            }
            let tagged = package.tagged().ok_or_else(|| {
                unprocessable("tagged proof reference targets a single package".into())
            })?;
            if !already_verified {
                Orchestrator::verify_tagged_package_with_replayed_tasks(decoded.tasks(), tagged)
                    .map_err(|error| unprocessable(error.to_string()))?;
            }
        }
    }
    if !already_verified {
        runtime
            .validated_packages
            .insert(package_digest, bytes.len(), decoded.clone());
    }
    let pre_state_root = poker_texas_air::state_root::compute_state_root(&task.pre_table)
        .map_err(|error| unprocessable(error.to_string()))?;
    let post_state_root = poker_texas_air::state_root::compute_state_root(&task.post_table)
        .map_err(|error| unprocessable(error.to_string()))?;
    Ok(Json(ProofVerificationResponse {
        job_id: hex::encode(job_id),
        verified: true,
        method: task.method_kind.method_name(),
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        pre_state_root_hex: hex::encode(pre_state_root.field().to_bytes_be()),
        post_state_root_hex: hex::encode(post_state_root.field().to_bytes_be()),
    }))
}

/// Verify the current process-local receipt segment against authenticated consensus material.
///
/// A service restart intentionally clears the process-local receipt segment. Individual durable
/// proof packages remain re-verifiable through `/jobs/:job_id/verify-proof`, but callers must
/// rebuild the exact ordered receipt range before anchoring a multi-call chain here.
async fn verify_table_chain_consensus(
    State(state): State<ServerState>,
    AxumPath(table_id): AxumPath<u64>,
    Json(request): Json<ConsensusAnchorRequest>,
) -> Result<Json<ConsensusAnchorResponse>, HttpError> {
    if request.material_borsh_hex.len() > MAX_CONSENSUS_ANCHOR_BYTES * 2 {
        return Err((
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "consensus anchor hex material exceeds {} character limit",
                MAX_CONSENSUS_ANCHOR_BYTES * 2
            ),
        ));
    }
    let material_bytes = hex::decode(&request.material_borsh_hex).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("material_borsh_hex must be hexadecimal: {error}"),
        )
    })?;
    if material_bytes.len() > MAX_CONSENSUS_ANCHOR_BYTES {
        return Err((
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            format!("consensus anchor material exceeds {MAX_CONSENSUS_ANCHOR_BYTES} byte limit"),
        ));
    }
    let material = ConsensusAnchorMaterial::try_from_slice(&material_bytes).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("invalid consensus anchor Borsh material: {error}"),
        )
    })?;

    let runtime = state.runtime.lock().await;
    let plugin = runtime.plugins.get(&table_id).ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            format!("Texas Poker table {table_id} is not loaded"),
        )
    })?;
    let anchor = plugin
        .verify_chain_from_consensus_material(&material)
        .map_err(|error| {
            (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                error.to_string(),
            )
        })?;
    if anchor.table_id() != table_id {
        return Err((
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "authenticated anchor targets table {}, not requested table {table_id}",
                anchor.table_id()
            ),
        ));
    }

    Ok(Json(ConsensusAnchorResponse {
        table_id: anchor.table_id(),
        hand_id: anchor.hand_id(),
        first_call_seq: anchor.first_call_seq(),
        last_call_seq: anchor.last_call_seq_public(),
        call_count: anchor.dispatch_call_digests().len(),
    }))
}

async fn list_plugins(State(state): State<ServerState>) -> impl IntoResponse {
    let last_report = state.last_report.lock().await.clone();
    let last_full_report = state.last_full_report.lock().await.clone();
    let runtime = state.runtime.lock().await;
    let tables: Vec<_> = runtime
        .repository
        .tables()
        .iter()
        .map(|table| {
            serde_json::json!({
                "table_id": table.table_id,
                "dispatch_count": table.dispatch_count,
                "prove_count": table.prove_count,
                "call_seq": table.table.call_seq,
                "hand_id": table.table.hand_id,
            })
        })
        .collect();
    Json(serde_json::json!({
        "plugins": ["texas_poker"],
        "tables": tables,
        "job_count": runtime.repository.jobs().len(),
        "last_report": last_report.map(|report| serde_json::json!({
            "chain_ok": report.chain_ok,
            "aggregate_ok": report.aggregate_ok,
            "dispatch_count": report.dispatch_count,
            "prove_count": report.prove_count,
            "chain_length": report.chain_length,
        })),
        "last_full_report": last_full_report.map(|report| serde_json::json!({
            "chain_ok": report.chain_ok,
            "dispatch_count": report.dispatch_count,
            "prove_count": report.prove_count,
            "chain_length": report.chain_length,
            "winner_seat": report.winner_seat,
            "stopped_at": report.stopped_at,
            "total_micros": report.total_micros,
        })),
    }))
}

fn completed_job_response(
    job: StoredDispatchJob,
    replayed: bool,
) -> Result<Json<DispatchResponse>, HttpError> {
    match job.status {
        StoredJobStatus::PendingProof | StoredJobStatus::Completed => {
            Ok(Json(response_from_result(
                job.job_id,
                job.table_id,
                job.result
                    .ok_or_else(|| internal_error("completed job is missing its result".into()))?,
                replayed,
            )?))
        }
        StoredJobStatus::Failed => Err((
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            job.error
                .unwrap_or_else(|| "previous dispatch failed without an error message".into()),
        )),
        StoredJobStatus::Running => Err(internal_error(
            "running job cannot be returned as completed".into(),
        )),
    }
}

fn job_response(
    job: StoredDispatchJob,
    proof_archive_available: bool,
) -> Result<JobResponse, HttpError> {
    let status = match job.status {
        StoredJobStatus::Running => "running",
        StoredJobStatus::PendingProof => "pending_proof",
        StoredJobStatus::Completed => "completed",
        StoredJobStatus::Failed => "failed",
    };
    let result = job
        .result
        .clone()
        .map(|result| response_from_result(job.job_id, job.table_id, result, true))
        .transpose()?;
    let (task_digest_hex, pre_state_root_hex, post_state_root_hex) = match job.proof {
        Some(proof) => (
            Some(hex::encode(proof.task_digest)),
            Some(hex::encode(proof.pre_state_root)),
            Some(hex::encode(proof.post_state_root)),
        ),
        None => (None, None, None),
    };
    let (proof_package_id_hex, proof_row_index, proof_row_count) = match job.proof_reference {
        Some(StoredProofReference::Single { package_id }) => {
            (Some(hex::encode(package_id)), Some(0), Some(1))
        }
        Some(StoredProofReference::Tagged {
            batch_id,
            row_index,
            row_count,
        }) => (
            Some(hex::encode(batch_id)),
            Some(row_index),
            Some(row_count),
        ),
        None => (None, None, None),
    };
    Ok(JobResponse {
        job_id: hex::encode(job.job_id),
        table_id: job.table_id,
        status,
        attempts: job.attempts,
        result,
        task_digest_hex,
        pre_state_root_hex,
        post_state_root_hex,
        proof_package_id_hex,
        proof_row_index,
        proof_row_count,
        proof_archive_available,
        error: job.error,
    })
}

fn completed_job_proof(
    repository: &ServiceRepository,
    job_id: [u8; 32],
) -> Result<(StoredDispatchJob, Vec<u8>), HttpError> {
    let job = repository.job(job_id).cloned().ok_or_else(|| {
        (
            axum::http::StatusCode::NOT_FOUND,
            "proving job was not found".to_string(),
        )
    })?;
    if job.status != StoredJobStatus::Completed || job.proof.is_none() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "completed job has no proof archive".into(),
        ));
    }
    let bytes = repository
        .load_job_proof_package(&job)
        .map_err(|error| internal_error(error.to_string()))?
        .ok_or_else(|| internal_error("completed job is missing its proof archive".into()))?;
    Ok((job, bytes))
}

fn response_from_result(
    job_id: [u8; 32],
    table_id: u64,
    result: StoredDispatchResult,
    replayed: bool,
) -> Result<DispatchResponse, HttpError> {
    Ok(DispatchResponse {
        job_id: hex::encode(job_id),
        table_id,
        replayed,
        had_prove_task: result.had_prove_task,
        proof_verified: result.proof_verified,
        events_count: usize::try_from(result.events_count)
            .map_err(|_| internal_error("persisted events count does not fit usize".into()))?,
        dispatch_count: result.dispatch_count,
        prove_count: result.prove_count,
        chain_length: usize::try_from(result.chain_length)
            .map_err(|_| internal_error("persisted chain length does not fit usize".into()))?,
        table_version: result.table_version,
        hand_id: result.hand_id,
        call_seq: result.call_seq,
    })
}

fn normalize_idempotency_key(key: Option<String>) -> Result<Option<String>, HttpError> {
    let Some(key) = key else {
        return Ok(None);
    };
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!("idempotency_key must contain 1..={MAX_IDEMPOTENCY_KEY_BYTES} bytes"),
        ));
    }
    Ok(Some(key))
}

fn digest_request(
    table_id: u64,
    idempotency_key: &Option<String>,
    caller: [u8; 20],
    caller_pubkey: Option<&poker_l1::signature::TaggedPubkey>,
    consensus_context: Option<(u64, u64, u64)>,
    selector: [u8; 32],
    args: &[u8],
) -> [u8; 32] {
    let key = idempotency_key.as_deref().unwrap_or("");
    let caller_pubkey_bytes = caller_pubkey.map(poker_l1::signature::TaggedPubkey::to_bytes);
    let mut material = Vec::with_capacity(
        8 + 20
            + 1
            + caller_pubkey_bytes.as_ref().map_or(0, Vec::len)
            + 32
            + 8
            + args.len()
            + key.len(),
    );
    material.extend_from_slice(&table_id.to_le_bytes());
    material.extend_from_slice(&caller);
    match caller_pubkey_bytes {
        Some(bytes) => {
            material.push(1);
            material.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            material.extend_from_slice(&bytes);
        }
        None => material.push(0),
    }
    let digest_domain =
        if let Some((chain_id, block_height, block_timestamp_ms)) = consensus_context {
            // Context-aware requests use a new domain and explicitly commit the
            // consensus execution tuple. Context-free development requests retain
            // the exact v1 preimage/domain so idempotent jobs persisted by an older
            // service binary remain replayable after upgrade.
            material.push(1);
            material.extend_from_slice(&chain_id.to_le_bytes());
            material.extend_from_slice(&block_height.to_le_bytes());
            material.extend_from_slice(&block_timestamp_ms.to_le_bytes());
            b"zchain.proving_service.request.v2".as_slice()
        } else {
            b"zchain.proving_service.request.v1".as_slice()
        };
    material.extend_from_slice(&selector);
    material.extend_from_slice(&(key.len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_bytes());
    material.extend_from_slice(&(args.len() as u64).to_le_bytes());
    material.extend_from_slice(args);
    blake2b_256(digest_domain, &material)
}

fn digest_job_id(table_id: u64, request_digest: [u8; 32], nonce: Option<u64>) -> [u8; 32] {
    let mut material = Vec::with_capacity(8 + 32 + 9);
    material.extend_from_slice(&table_id.to_le_bytes());
    material.extend_from_slice(&request_digest);
    match nonce {
        Some(nonce) => {
            material.push(1);
            material.extend_from_slice(&nonce.to_le_bytes());
        }
        None => material.push(0),
    }
    blake2b_256(b"zchain.proving_service.job.v1", &material)
}

fn blake2b_256(domain: &[u8], material: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(material);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

fn decode_fixed_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], HttpError> {
    let bytes = hex::decode(value).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("{name} must be hexadecimal: {error}"),
        )
    })?;
    bytes.try_into().map_err(|_: Vec<u8>| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("{name} must encode exactly {N} bytes"),
        )
    })
}

fn new_service_plugin(table_id: u64) -> TexasPokerPlugin {
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};

    let table = TexasPokerTable::new(
        ObjectID::new([0xFF; 20], table_id),
        String::new(),
        EMPTY_PLAYER,
        2,
        1,
        1,
    );
    TexasPokerPlugin::new(table)
}

fn internal_error(message: String) -> HttpError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message)
}

fn unprocessable(message: String) -> HttpError {
    (axum::http::StatusCode::UNPROCESSABLE_ENTITY, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{Body, to_bytes};
    use poker_l1::account::derive_address;
    use poker_l1::block::BlockHeader;
    use poker_l1::consensus::ValidatorEntry;
    use poker_l1::consensus::bullshark::assemble_commit_certificate;
    use poker_l1::network::InMemoryTransport;
    use poker_l1::object_model::{ObjectStore, SparseMerkleTree};
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
    use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
    use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
    use poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
    use poker_l1::vm::contracts::texas_poker::dispatch::{
        CreateTableArgs, JoinTableArgs, SeatIndexArgs, selectors,
    };
    use poker_l1::vm::contracts::texas_poker::types::TexasPokerTable;
    use poker_l1::vm::contracts::texas_poker::utils;
    use poker_texas_air::consensus_anchor::{
        AuthenticatedObjectSnapshot, ConsensusDispatchCall, TableSnapshot,
    };
    use secp256k1::{Message, Secp256k1, SecretKey};
    use tower::ServiceExt;

    #[tokio::test]
    async fn composite_jobs_share_one_tagged_package_and_recover_pending_rows() {
        use blstrs::G1Projective;
        use group::Group;
        use poker_l1::object_model::ObjectID;
        use poker_l1::vm::contracts::texas_poker::types::{Seat, SeatStatus};
        use poker_protocol::crypto::types::ECPoint;

        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_service_tagged_proof_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("state.borsh");
        let table_id = 808;
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xFF; 20], table_id),
            "tagged-http".into(),
            [0xA0; 20],
            6,
            50,
            100,
        );
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 1_000_000)
            .unwrap();
        for index in 0..3 {
            table.seats[index] = Seat::occupied(
                [u8::try_from(index + 1).unwrap(); 20],
                1_000,
                ECPoint(G1Projective::generator()),
                SeatStatus::Active,
            )
            .unwrap();
            table.seats[index].set_bet(100).unwrap();
        }
        let mut repository = ServiceRepository::open(&path).unwrap();
        repository
            .store_table(StoredTable {
                table_id,
                table,
                dispatch_count: 0,
                prove_count: 0,
            })
            .unwrap();
        let state = ServerState::from_repository(repository).unwrap();

        let check_request = |seat_index: u8, key: &str, caller: [u8; 20]| DispatchRequest {
            caller_hex: hex::encode(caller),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::check()),
            args_hex: hex::encode(borsh::to_vec(&SeatIndexArgs { seat_index }).unwrap()),
            idempotency_key: Some(key.into()),
        };
        let first = dispatch_for_table(
            state.clone(),
            table_id,
            check_request(0, "check-0", [1; 20]),
        )
        .await
        .unwrap()
        .0;
        assert!(!first.proof_verified);

        // A restart must recover the tentative table and exact pending command
        // stream without manufacturing a receipt.
        let recovered_repository = state.runtime.lock().await.repository.clone();
        let recovered = ServerState::from_repository(recovered_repository).unwrap();
        assert_eq!(
            recovered
                .runtime
                .lock()
                .await
                .plugins
                .get(&table_id)
                .unwrap()
                .pending_tagged_tasks()
                .len(),
            1
        );
        let second = dispatch_for_table(
            recovered.clone(),
            table_id,
            check_request(1, "check-1", [2; 20]),
        )
        .await
        .unwrap()
        .0;
        assert!(!second.proof_verified);

        let finalized = finalize_table_proofs(State(recovered.clone()), AxumPath(table_id))
            .await
            .unwrap()
            .0;
        assert_eq!(finalized.finalized_rows, 2);
        assert!(finalized.batch_id_hex.is_some());

        {
            let mut runtime = recovered.runtime.lock().await;
            assert_eq!(runtime.validated_packages.entries.len(), 1);
            runtime.validated_packages = ValidatedPackageCache::default();
        }

        let first_verification =
            verify_job_proof(State(recovered.clone()), AxumPath(first.job_id.clone()))
                .await
                .expect("first tagged row should verify and populate the package cache")
                .0;
        let second_verification =
            verify_job_proof(State(recovered.clone()), AxumPath(second.job_id.clone()))
                .await
                .expect("second tagged row should reuse the validated shared package")
                .0;
        assert!(first_verification.verified);
        assert!(second_verification.verified);

        let runtime = recovered.runtime.lock().await;
        assert_eq!(runtime.validated_packages.entries.len(), 1);
        assert_eq!(runtime.validated_packages.misses, 1);
        assert_eq!(runtime.validated_packages.hits, 1);
        let first_id = decode_fixed_hex::<32>(&first.job_id, "job_id").unwrap();
        let second_id = decode_fixed_hex::<32>(&second.job_id, "job_id").unwrap();
        let first_job = runtime.repository.job(first_id).unwrap();
        let second_job = runtime.repository.job(second_id).unwrap();
        assert_eq!(first_job.status, StoredJobStatus::Completed);
        assert_eq!(second_job.status, StoredJobStatus::Completed);
        assert_eq!(first_job.result.as_ref().unwrap().prove_count, 1);
        assert_eq!(first_job.result.as_ref().unwrap().chain_length, 1);
        assert_eq!(second_job.result.as_ref().unwrap().prove_count, 2);
        assert_eq!(second_job.result.as_ref().unwrap().chain_length, 2);
        let Some(StoredProofReference::Tagged {
            batch_id: first_batch,
            row_index: 0,
            row_count: 2,
        }) = first_job.proof_reference
        else {
            panic!("first job must reference tagged row zero")
        };
        let Some(StoredProofReference::Tagged {
            batch_id: second_batch,
            row_index: 1,
            row_count: 2,
        }) = second_job.proof_reference
        else {
            panic!("second job must reference tagged row one")
        };
        assert_eq!(first_batch, second_batch);
        let shared_package = runtime
            .repository
            .load_job_proof_package(first_job)
            .unwrap()
            .unwrap();
        assert_eq!(
            Some(shared_package.clone()),
            runtime
                .repository
                .load_job_proof_package(second_job)
                .unwrap()
        );
        drop(runtime);

        // Cache identity is the exact sidecar content, not the durable batch ID. Replacing the
        // sidecar under the same path must miss the cache and fail closed.
        let mut corrupted_package = shared_package.clone();
        *corrupted_package
            .first_mut()
            .expect("shared proof package should not be empty") ^= 0x01;
        recovered
            .runtime
            .lock()
            .await
            .repository
            .store_proof_package(first_batch, &corrupted_package)
            .unwrap();
        assert!(
            verify_job_proof(State(recovered.clone()), AxumPath(first.job_id.clone()),)
                .await
                .is_err(),
            "changed sidecar bytes must not reuse a prior validated cache entry"
        );
        let mut runtime = recovered.runtime.lock().await;
        runtime
            .repository
            .store_proof_package(first_batch, &shared_package)
            .unwrap();
        let durable = runtime.repository.clone();
        drop(runtime);

        let restarted = ServiceRuntime::new(durable).unwrap();
        assert_eq!(restarted.plugins.get(&table_id).unwrap().proven().len(), 2);
        assert_eq!(restarted.validated_packages.entries.len(), 1);
        assert!(
            restarted
                .plugins
                .get(&table_id)
                .unwrap()
                .pending_tagged_tasks()
                .is_empty()
        );

        // A peer may serve the same shared package under either job ID. Repairing
        // from row one must restore the batch-ID sidecar used by both jobs.
        let transport = InMemoryTransport::new();
        transport
            .inject_proof_package(second_id, shared_package)
            .expect("remote peer should retain the shared tagged package");
        let proof_path = path
            .with_extension("proofs")
            .join(format!("{}.proof", hex::encode(first_batch)));
        std::fs::remove_file(&proof_path).expect("test should remove shared batch sidecar");
        assert!(
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).is_err(),
            "startup must fail closed while a completed tagged sidecar is missing"
        );

        let mut repository = ServiceRepository::open(&path).unwrap();
        let report = crate::proof_sync::sync_proof_package(&mut repository, &transport, second_id)
            .expect("P2P sync from any tagged row should repair the shared sidecar");
        assert_eq!(report.job_id, second_id);
        assert_eq!(report.table_id, table_id);
        assert_eq!(report.call_seq, 2);
        let first_job = repository.job(first_id).unwrap();
        let second_job = repository.job(second_id).unwrap();
        assert!(repository.has_job_proof_package(first_job).unwrap());
        assert!(repository.has_job_proof_package(second_job).unwrap());

        let repaired = ServiceRuntime::new(repository).unwrap();
        assert_eq!(repaired.plugins.get(&table_id).unwrap().proven().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn full_hand_http_route_proves_and_reports_all_transitions() {
        let response = router(ServerState::default())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/hands/run-full")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("full-hand route must return a response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("full-hand response body must be readable");
        let report: serde_json::Value =
            serde_json::from_slice(&body).expect("full-hand response must be JSON");
        let steps = report["steps"]
            .as_array()
            .expect("full-hand response must carry step records");
        assert_eq!(steps.len(), 25);
        assert!(
            steps
                .last()
                .and_then(|step| step["method"].as_str())
                .is_some_and(|method| method.starts_with("tagged_batch[1 packages/2 proofs each/"))
        );
        assert_eq!(report["chain_ok"], true);
        assert_eq!(report["dispatch_count"], 24);
        assert_eq!(report["prove_count"], 24);
        assert_eq!(report["chain_length"], 24);
        assert!(report["stopped_at"].is_null());
    }

    fn test_tagged_pubkey(secret: &SecretKey) -> TaggedPubkey {
        let secp = Secp256k1::new();
        let public = secp256k1::PublicKey::from_secret_key(&secp, secret);
        TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .expect("secp256k1 public key has canonical tagged encoding")
    }

    fn test_validators() -> (Vec<ValidatorEntry>, Vec<SecretKey>) {
        let secrets: Vec<_> = (1u8..=5)
            .map(|byte| SecretKey::from_slice(&[byte; 32]).expect("fixed secret scalar is valid"))
            .collect();
        let validators = secrets
            .iter()
            .map(|secret| ValidatorEntry::new(test_tagged_pubkey(secret), [0; 33], 1_000, 0))
            .collect();
        (validators, secrets)
    }

    fn sign_certificate(
        validators: &[ValidatorEntry],
        secrets: &[SecretKey],
        roots: ([u8; 32], [u8; 32], [u8; 32]),
    ) -> poker_l1::consensus::DagCommitCertificate {
        let placeholder = assemble_commit_certificate(
            1,
            1,
            [0; 32],
            vec![],
            vec![],
            roots.0,
            roots.1,
            roots.2,
            &[],
            validators.len(),
        )
        .expect("certificate placeholder must assemble");
        let message = Message::from_digest(placeholder.signing_hash(poker_l1::DEFAULT_CHAIN_ID));
        let secp = Secp256k1::new();
        let signatures: Vec<_> = secrets
            .iter()
            .take(validators.len() * 2 / 3 + 1)
            .enumerate()
            .map(|(index, secret)| {
                let signature = secp.sign_ecdsa_recoverable(&message, secret);
                let (recovery_id, compact) = signature.serialize_compact();
                let mut bytes = compact.to_vec();
                bytes.push(recovery_id.to_i32() as u8);
                (index, bytes)
            })
            .collect();
        assemble_commit_certificate(
            1,
            1,
            [0; 32],
            vec![],
            vec![],
            roots.0,
            roots.1,
            roots.2,
            &signatures,
            validators.len(),
        )
        .expect("signed certificate must assemble")
    }

    fn tx_smt(tx: &Transaction) -> ([u8; 32], poker_l1::object_model::MerklePath) {
        let mut smt = SparseMerkleTree::new();
        let tx_hash = tx.tx_hash();
        let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2 output is supported");
        hasher.update(&tx_hash);
        let mut key = [0; 32];
        hasher
            .finalize_variable(&mut key)
            .expect("32-byte Blake2 output is supported");
        smt.upsert(key, &tx_hash);
        (smt.root(), smt.prove(&key))
    }

    fn snapshot(
        table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    ) -> ([u8; 32], TableSnapshot) {
        let [hot_table, metadata, rules, governance] =
            poker_l1::vm::contracts::texas_poker::state_codec::table_storage_objects(table)
                .expect("table storage objects must encode");
        let mut store = ObjectStore::new();
        for object in [&hot_table, &metadata, &rules, &governance] {
            store
                .create(object.clone())
                .expect("table object must store");
        }
        let authenticated = |object: poker_l1::object_model::Object| AuthenticatedObjectSnapshot {
            inclusion_path: store
                .prove(&object.id)
                .expect("stored object has inclusion proof"),
            object,
        };
        (
            store.state_root(),
            TableSnapshot {
                hot_table: authenticated(hot_table),
                metadata: authenticated(metadata),
                rules: authenticated(rules),
                governance: authenticated(governance),
            },
        )
    }

    fn consensus_material_for_create(
        pre_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        post_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        sender_secret: &SecretKey,
        selector: [u8; 32],
        args: Vec<u8>,
        block_height: u64,
        block_timestamp_ms: u64,
    ) -> ConsensusAnchorMaterial {
        let (validators, validator_secrets) = test_validators();
        let (pre_state_root, pre_snapshot) = snapshot(pre_table);
        let (post_state_root, post_snapshot) = snapshot(post_table);
        let sender = test_tagged_pubkey(sender_secret);
        let mut tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: Some(ContractCall {
                contract_id: poker_l1::vm::precompile::reserved::texas_poker_contract_id(),
                method_selector: selector,
                args,
            }),
            tagged_pubkey: sender,
            signature: vec![],
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let secp = Secp256k1::new();
        let signature =
            secp.sign_ecdsa_recoverable(&Message::from_digest(tx.signing_hash()), sender_secret);
        let (recovery_id, compact) = signature.serialize_compact();
        tx.signature = compact.to_vec();
        tx.signature.push(recovery_id.to_i32() as u8);
        let (public_tx_root, tx_path) = tx_smt(&tx);
        let empty_tx_root = SparseMerkleTree::new().root();
        let pre_certificate = sign_certificate(
            &validators,
            &validator_secrets,
            (pre_state_root, public_tx_root, empty_tx_root),
        );
        let post_certificate = sign_certificate(
            &validators,
            &validator_secrets,
            (post_state_root, public_tx_root, empty_tx_root),
        );
        let pre_block_header = BlockHeader {
            height: block_height,
            timestamp_ms: block_timestamp_ms,
            prev_hash: [0; 32],
            state_root: pre_state_root,
            public_tx_root,
            gameturn_tx_root: empty_tx_root,
            dag_commit_certificate: pre_certificate.clone(),
        };
        let post_block_header = BlockHeader {
            state_root: post_state_root,
            dag_commit_certificate: post_certificate,
            ..pre_block_header.clone()
        };
        ConsensusAnchorMaterial {
            pre_block_header,
            pre_snapshot,
            pre_certificate,
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            validators,
            post_block_header,
            post_snapshot,
            calls: vec![ConsensusDispatchCall {
                tx,
                lane: TxLane::Public,
                inclusion_path: tx_path,
            }],
        }
    }

    #[test]
    fn unanchored_dispatch_service_is_loopback_only() {
        let loopback_v4 = "127.0.0.1:7878".parse().unwrap();
        let loopback_v6 = "[::1]:7878".parse().unwrap();
        let wildcard = "0.0.0.0:7878".parse().unwrap();
        let remote = "192.0.2.1:7878".parse().unwrap();

        assert!(ensure_loopback_bind(loopback_v4).is_ok());
        assert!(ensure_loopback_bind(loopback_v6).is_ok());
        assert!(ensure_loopback_bind(wildcard).is_err());
        assert!(ensure_loopback_bind(remote).is_err());
    }

    fn create_request(creator: [u8; 20], key: &str) -> DispatchRequest {
        DispatchRequest {
            caller_hex: hex::encode(creator),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::create_table()),
            args_hex: hex::encode(
                borsh::to_vec(&CreateTableArgs {
                    name: "service_table".into(),
                    max_players: 2,
                    small_blind: 50,
                    big_blind: 100,
                })
                .unwrap(),
            ),
            idempotency_key: Some(key.into()),
        }
    }

    #[test]
    fn context_free_request_digest_retains_the_v1_wire_value() {
        let digest = digest_request(
            7,
            &Some("legacy".into()),
            [0xAA; 20],
            None,
            None,
            selectors::create_table(),
            &[1, 2, 3],
        );
        assert_eq!(
            hex::encode(digest),
            "ec1d127b8dc1b6354159ecf2f6cf63827af73513c08da4423e22bb5a44cbae17"
        );
    }

    #[tokio::test]
    async fn dispatch_requires_public_key_and_complete_consensus_context_together() {
        let state = ServerState::default();
        let sender_secret =
            SecretKey::from_slice(&[11; 32]).expect("fixed sender secret scalar is valid");
        let sender = test_tagged_pubkey(&sender_secret);
        let caller = derive_address(&sender);
        let sender_hex = hex::encode(sender.to_bytes());

        let mut missing_context = create_request(caller, "missing-context");
        missing_context.caller_pubkey_hex = Some(sender_hex.clone());
        let error = dispatch_for_table(state.clone(), 70, missing_context)
            .await
            .expect_err("a public key without consensus context must be rejected");
        assert_eq!(error.0, axum::http::StatusCode::BAD_REQUEST);
        assert!(error.1.contains("complete consensus execution context"));

        let mut partial_context = create_request(caller, "partial-context");
        partial_context.caller_pubkey_hex = Some(sender_hex);
        partial_context.chain_id = Some(poker_l1::DEFAULT_CHAIN_ID);
        let error = dispatch_for_table(state.clone(), 70, partial_context)
            .await
            .expect_err("a partial consensus context must be rejected");
        assert_eq!(error.0, axum::http::StatusCode::BAD_REQUEST);
        assert!(error.1.contains("must be supplied together"));

        let mut missing_public_key = create_request(caller, "missing-public-key");
        missing_public_key.chain_id = Some(poker_l1::DEFAULT_CHAIN_ID);
        missing_public_key.block_height = Some(100);
        missing_public_key.block_timestamp_ms = Some(1_000_000);
        let error = dispatch_for_table(state, 70, missing_public_key)
            .await
            .expect_err("consensus context without a public key must be rejected");
        assert_eq!(error.0, axum::http::StatusCode::BAD_REQUEST);
        assert!(error.1.contains("complete consensus execution context"));
    }

    #[tokio::test]
    async fn idempotency_key_conflicts_when_consensus_context_changes() {
        let state = ServerState::default();
        let sender_secret =
            SecretKey::from_slice(&[12; 32]).expect("fixed sender secret scalar is valid");
        let sender = test_tagged_pubkey(&sender_secret);
        let caller = derive_address(&sender);

        let mut first = create_request(caller, "context-bound-create");
        first.caller_pubkey_hex = Some(hex::encode(sender.to_bytes()));
        first.chain_id = Some(poker_l1::DEFAULT_CHAIN_ID);
        first.block_height = Some(777);
        first.block_timestamp_ms = Some(9_876_543);
        let _ = dispatch_for_table(state.clone(), 71, first)
            .await
            .expect("the first context-bound request must prove");

        let mut changed = create_request(caller, "context-bound-create");
        changed.caller_pubkey_hex = Some(hex::encode(sender.to_bytes()));
        changed.chain_id = Some(poker_l1::DEFAULT_CHAIN_ID);
        changed.block_height = Some(778);
        changed.block_timestamp_ms = Some(9_876_543);
        let error = dispatch_for_table(state, 71, changed)
            .await
            .expect_err("the same idempotency key must not cross execution contexts");
        assert_eq!(error.0, axum::http::StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn table_dispatch_is_idempotent_and_isolated() {
        let state = ServerState::default();
        let creator = [0xAA; 20];
        let first = dispatch_for_table(state.clone(), 7, create_request(creator, "create-7"))
            .await
            .unwrap()
            .0;
        assert_eq!(first.table_id, 7);
        assert_eq!(first.call_seq, 1);
        assert!(!first.replayed);

        let replay = dispatch_for_table(state.clone(), 7, create_request(creator, "create-7"))
            .await
            .unwrap()
            .0;
        assert!(replay.replayed);
        assert_eq!(replay.job_id, first.job_id);
        assert_eq!(replay.call_seq, 1);

        let conflict = dispatch_for_table(
            state.clone(),
            7,
            DispatchRequest {
                caller_hex: hex::encode(creator),
                caller_pubkey_hex: None,
                chain_id: None,
                block_height: None,
                block_timestamp_ms: None,
                selector_hex: hex::encode(selectors::create_table()),
                args_hex: hex::encode(
                    borsh::to_vec(&CreateTableArgs {
                        name: "different".into(),
                        max_players: 2,
                        small_blind: 50,
                        big_blind: 100,
                    })
                    .unwrap(),
                ),
                idempotency_key: Some("create-7".into()),
            },
        )
        .await;
        assert_eq!(conflict.unwrap_err().0, axum::http::StatusCode::CONFLICT);

        let second_table =
            dispatch_for_table(state.clone(), 8, create_request(creator, "create-8"))
                .await
                .unwrap()
                .0;
        assert_eq!(second_table.call_seq, 1);
        let runtime = state.runtime.lock().await;
        assert_eq!(runtime.plugins.get(&7).unwrap().table().call_seq, 1);
        assert_eq!(runtime.plugins.get(&8).unwrap().table().call_seq, 1);
    }

    #[tokio::test]
    async fn durable_table_state_survives_restart() {
        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_service_server_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("state.borsh");
        let creator = [0xAA; 20];
        let state = ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        let create = dispatch_for_table(state, 42, create_request(creator, "create"))
            .await
            .unwrap()
            .0;
        assert_eq!(create.call_seq, 1);

        let recovered =
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        {
            let runtime = recovered.runtime.lock().await;
            let plugin = runtime.plugins.get(&42).expect("table must recover");
            assert_eq!(plugin.stats().chain_length, 1);
            plugin
                .verify_chain()
                .expect("restart must rebuild the verified receipt chain");
        }
        let player = [0x10; 20];
        let join = DispatchRequest {
            caller_hex: hex::encode(player),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::join_table()),
            args_hex: hex::encode(
                borsh::to_vec(
                    &JoinTableArgs::with_key(
                        player,
                        1_000,
                        utils::scalar_from_u64(1),
                        utils::scalar_from_u64(901),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            idempotency_key: Some("join".into()),
        };
        let response = dispatch_for_table(recovered.clone(), 42, join)
            .await
            .unwrap()
            .0;
        assert_eq!(response.call_seq, 2);
        let job = get_job(State(recovered), AxumPath(response.job_id))
            .await
            .unwrap()
            .0;
        assert_eq!(job.status, "completed");
        assert!(job.task_digest_hex.is_some());
        assert!(job.proof_archive_available);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn durable_proof_archive_survives_restart_and_rejects_tampering() {
        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_service_proof_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("state.borsh");
        let creator = [0xAA; 20];
        let initial =
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        let created = dispatch_for_table(initial, 91, create_request(creator, "archive-create"))
            .await
            .expect("create proof should complete")
            .0;

        let recovered =
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        let job = get_job(State(recovered.clone()), AxumPath(created.job_id.clone()))
            .await
            .expect("completed job should reload")
            .0;
        assert!(job.proof_archive_available);

        let proof_response =
            get_job_proof(State(recovered.clone()), AxumPath(created.job_id.clone()))
                .await
                .expect("proof download should succeed");
        let downloaded = axum::body::to_bytes(
            proof_response.into_body(),
            crate::proof_package::MAX_SERVICE_PROOF_PACKAGE_BYTES,
        )
        .await
        .expect("proof response body should decode");
        ServiceProofPackage::from_bytes(&downloaded)
            .expect("downloaded proof package should be canonical");
        let mut trailing = downloaded.to_vec();
        trailing.push(0);
        assert!(ServiceProofPackage::from_bytes(&trailing).is_err());

        let verified = verify_job_proof(State(recovered.clone()), AxumPath(created.job_id.clone()))
            .await
            .expect("fresh service should reverify archived proof")
            .0;
        assert!(verified.verified);
        assert_eq!(verified.table_id, 91);
        assert_eq!(verified.call_seq, 1);
        let job_id = decode_fixed_hex::<32>(&created.job_id, "job_id").unwrap();
        let transport = InMemoryTransport::new();
        transport
            .inject_proof_package(job_id, downloaded.to_vec())
            .expect("remote peer should retain canonical proof package");
        drop(recovered);

        let proof_path = path
            .with_extension("proofs")
            .join(format!("{}.proof", created.job_id));
        std::fs::remove_file(&proof_path).expect("test should remove local proof sidecar");
        assert!(
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).is_err(),
            "startup must fail closed while a completed proof sidecar is missing"
        );
        let mut repository = ServiceRepository::open(&path).unwrap();
        assert!(!repository.has_proof_package(job_id).unwrap());
        let report = crate::proof_sync::sync_proof_package(&mut repository, &transport, job_id)
            .expect("P2P sync should reverify and repair the missing sidecar");
        assert_eq!(report.job_id, job_id);
        assert_eq!(report.table_id, 91);
        assert_eq!(report.call_seq, 1);
        assert!(repository.has_proof_package(job_id).unwrap());
        drop(repository);

        let repaired =
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        let verified = verify_job_proof(State(repaired), AxumPath(created.job_id.clone()))
            .await
            .expect("repaired proof sidecar should remain re-verifiable")
            .0;
        assert!(verified.verified);

        let mut tampered = std::fs::read(&proof_path).expect("proof sidecar should exist");
        *tampered
            .last_mut()
            .expect("proof package should not be empty") ^= 0x01;
        std::fs::write(&proof_path, tampered).expect("test should replace proof sidecar");

        assert!(
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).is_err(),
            "tampered durable proof must be rejected during startup recovery"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn legacy_route_still_commits_only_a_proven_transition() {
        let state = ServerState::default();
        let creator = [0xAA; 20];
        let create = dispatch_legacy(
            State(state.clone()),
            Json(create_request(creator, "create")),
        )
        .await
        .unwrap()
        .0;
        assert!(create.had_prove_task);
        assert!(create.proof_verified);

        let player = [0x10; 20];
        let join = DispatchRequest {
            caller_hex: hex::encode(player),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::join_table()),
            args_hex: hex::encode(
                borsh::to_vec(
                    &JoinTableArgs::with_key(
                        player,
                        1_000,
                        utils::scalar_from_u64(1),
                        utils::scalar_from_u64(902),
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            idempotency_key: Some("join".into()),
        };
        let join = dispatch_legacy(State(state.clone()), Json(join))
            .await
            .unwrap()
            .0;
        assert_eq!(join.call_seq, 2);

        let leave = DispatchRequest {
            caller_hex: hex::encode(player),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::request_leave_after_hand()),
            args_hex: hex::encode(borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap()),
            idempotency_key: Some("leave".into()),
        };
        let leave = dispatch_legacy(State(state.clone()), Json(leave))
            .await
            .unwrap()
            .0;
        assert_eq!(leave.call_seq, 3);
        let runtime = state.runtime.lock().await;
        assert!(
            runtime
                .plugins
                .get(&LEGACY_TABLE_ID)
                .unwrap()
                .table()
                .seat_wants_leave(0)
        );
    }

    #[tokio::test]
    async fn consensus_anchor_route_rejects_malformed_material_before_chain_access() {
        let result = verify_table_chain_consensus(
            State(ServerState::default()),
            AxumPath(LEGACY_TABLE_ID),
            Json(ConsensusAnchorRequest {
                material_borsh_hex: "not-hex".into(),
            }),
        )
        .await;

        match result {
            Err((status, message)) => {
                assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
                assert!(message.contains("hexadecimal"));
            }
            Ok(_) => panic!("malformed consensus material must be rejected"),
        }
    }

    #[tokio::test]
    async fn consensus_anchor_http_route_accepts_recovered_receipt_chain() {
        let dir = std::env::temp_dir().join(format!(
            "zchain_proving_service_anchor_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let path = dir.join("state.borsh");
        let table_id = 91;
        let sender_secret =
            SecretKey::from_slice(&[9; 32]).expect("fixed sender secret scalar is valid");
        let sender = test_tagged_pubkey(&sender_secret);
        let caller = derive_address(&sender);
        let pre_table = TexasPokerTable::new(
            poker_l1::object_model::ObjectID::new([0xFF; 20], table_id),
            "anchored-table".into(),
            [0xA0; 20],
            2,
            50,
            100,
        );
        let mut repository = ServiceRepository::open(&path).unwrap();
        repository
            .store_table(StoredTable {
                table_id,
                table: pre_table.clone(),
                dispatch_count: 0,
                prove_count: 0,
            })
            .unwrap();
        let initial = ServerState::from_repository(repository).unwrap();
        let join_args = borsh::to_vec(
            &JoinTableArgs::with_key(
                caller,
                1_000,
                utils::scalar_from_u64(1),
                utils::scalar_from_u64(777),
            )
            .unwrap(),
        )
        .unwrap();
        let selector = selectors::join_table();
        let join = DispatchRequest {
            caller_hex: hex::encode(caller),
            caller_pubkey_hex: Some(hex::encode(sender.to_bytes())),
            chain_id: Some(poker_l1::DEFAULT_CHAIN_ID),
            block_height: Some(777),
            block_timestamp_ms: Some(9_876_543),
            selector_hex: hex::encode(selector),
            args_hex: hex::encode(&join_args),
            idempotency_key: Some("anchored-join".into()),
        };

        let response = dispatch_for_table(initial.clone(), table_id, join)
            .await
            .expect("dispatch with an address-bound public key must prove")
            .0;
        assert!(response.proof_verified);

        let post_table = {
            let runtime = initial.runtime.lock().await;
            runtime
                .plugins
                .get(&table_id)
                .expect("dispatched table is loaded")
                .table()
                .clone()
        };
        drop(initial);
        let recovered =
            ServerState::from_repository(ServiceRepository::open(&path).unwrap()).unwrap();
        let material = consensus_material_for_create(
            &pre_table,
            &post_table,
            &sender_secret,
            selector,
            join_args,
            777,
            9_876_543,
        );
        let body = serde_json::json!({
            "material_borsh_hex": hex::encode(
                borsh::to_vec(&material).expect("authenticated material must serialize")
            ),
        });
        let app = router(recovered);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/tables/{table_id}/verify-chain-consensus"))
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("HTTP request must build");

        let response = app
            .oneshot(request)
            .await
            .expect("router must return a response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let response_body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body must be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&response_body).expect("response must be valid JSON");
        assert_eq!(json["table_id"], table_id);
        assert_eq!(json["hand_id"], 0);
        assert_eq!(json["first_call_seq"], 1);
        assert_eq!(json["last_call_seq"], 1);
        assert_eq!(json["call_count"], 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
