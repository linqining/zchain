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

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::contracts::TexasPokerPlugin;
use crate::full_hand::{FullHandReport, FullHandRunner};
use crate::plugin::ContractPlugin;
use crate::repository::{
    JobReservation, RepositoryError, ServiceRepository, StoredDispatchJob, StoredDispatchResult,
    StoredJobStatus, StoredProofMetadata, StoredTable,
};
use crate::runner::HandRunner;
use crate::{ServiceError, ServiceResult};
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_texas_air::consensus_anchor::ConsensusAnchorMaterial;

const LEGACY_TABLE_ID: u64 = 0;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
/// Bound the decoded Borsh package before it reaches certificate/SMT verification.
const MAX_CONSENSUS_ANCHOR_BYTES: usize = 16 * 1024 * 1024;

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
}

impl ServiceRuntime {
    fn new(repository: ServiceRepository) -> Self {
        let plugins = repository
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
        Self {
            repository,
            plugins,
        }
    }

    fn staged_plugin(&mut self, table_id: u64) -> TexasPokerPlugin {
        self.plugins
            .entry(table_id)
            .or_insert_with(|| new_service_plugin(table_id))
            .clone()
    }
}

impl ServerState {
    fn from_repository(repository: ServiceRepository) -> Self {
        Self {
            runtime: Arc::new(Mutex::new(ServiceRuntime::new(repository))),
            last_report: Arc::new(Mutex::new(None)),
            last_full_report: Arc::new(Mutex::new(None)),
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::from_repository(ServiceRepository::in_memory())
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

/// JSON representation of the complete 32-transition Texas proving run.
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
    pub error: Option<String>,
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
    let state = ServerState::from_repository(ServiceRepository::open(repository_path)?);
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
            "/tables/:table_id/verify-chain-consensus",
            post(verify_table_chain_consensus),
        )
        .route("/jobs/:job_id", get(get_job))
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
    let proof = if let Some(task) = &outcome.prove_task {
        if let Err(error) = staged.prove_task(task) {
            return fail_reserved_job(&mut runtime, job, error.to_string());
        }
        match proof_metadata(task) {
            Ok(proof) => Some(proof),
            Err(error) => return fail_reserved_job(&mut runtime, job, error.to_string()),
        }
    } else {
        None
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
        table_version: table.version,
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
        .complete_job(stored_table, job.clone(), result.clone(), proof)
        .map_err(|error| internal_error(error.to_string()))?;
    runtime.plugins.insert(table_id, staged);
    Ok(Json(response_from_result(
        job.job_id(),
        table_id,
        result,
        false,
    )?))
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
    Ok(Json(job_response(job)?))
}

/// Verify the current process-local receipt segment against authenticated consensus material.
///
/// A service restart intentionally clears the process-local receipt segment, so callers must
/// first retrieve/reprove the relevant tasks from consensus rather than treating durable job
/// metadata as a portable STARK archive.
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
        StoredJobStatus::Completed => Ok(Json(response_from_result(
            job.job_id,
            job.table_id,
            job.result
                .ok_or_else(|| internal_error("completed job is missing its result".into()))?,
            replayed,
        )?)),
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

fn job_response(job: StoredDispatchJob) -> Result<JobResponse, HttpError> {
    let status = match job.status {
        StoredJobStatus::Running => "running",
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
    Ok(JobResponse {
        job_id: hex::encode(job.job_id),
        table_id: job.table_id,
        status,
        attempts: job.attempts,
        result,
        task_digest_hex,
        pre_state_root_hex,
        post_state_root_hex,
        error: job.error,
    })
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

fn proof_metadata(
    task: &poker_texas_air::prove_task::ProveTask,
) -> ServiceResult<StoredProofMetadata> {
    let task_bytes = borsh::to_vec(task)
        .map_err(|error| ServiceError::Prover(format!("encode proved task: {error}")))?;
    let pre_state_root = poker_texas_air::state_root::compute_state_root(&task.pre_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    let post_state_root = poker_texas_air::state_root::compute_state_root(&task.post_table)
        .map_err(|error| ServiceError::Prover(error.to_string()))?;
    Ok(StoredProofMetadata {
        task_digest: blake2b_256(b"zchain.proving_service.task.v1", &task_bytes),
        pre_state_root: pre_state_root.field().to_bytes_be(),
        post_state_root: post_state_root.field().to_bytes_be(),
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
    use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TableConfig, TexasPokerTable};

    let mut table = TexasPokerTable::new(
        ObjectID::new([0xFF; 20], table_id),
        "service_placeholder".into(),
        EMPTY_PLAYER,
        6,
        50,
        100,
    );
    table.config = TableConfig::default();
    TexasPokerPlugin::new(table)
}

fn internal_error(message: String) -> HttpError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::{Body, to_bytes};
    use blstrs::G1Projective;
    use group::Group;
    use poker_l1::account::derive_address;
    use poker_l1::block::BlockHeader;
    use poker_l1::consensus::ValidatorEntry;
    use poker_l1::consensus::bullshark::assemble_commit_certificate;
    use poker_l1::object_model::{Object, ObjectStore, Ownership, SparseMerkleTree};
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
    use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
    use poker_l1::vm::contracts::texas_poker::dispatch::{
        CreateTableArgs, JoinTableArgs, SeatIndexArgs, selectors,
    };
    use poker_protocol::crypto::types::ECPoint;
    use poker_texas_air::consensus_anchor::{ConsensusDispatchCall, TableSnapshot};
    use secp256k1::{Message, Secp256k1, SecretKey};
    use tower::ServiceExt;

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
        assert_eq!(report["steps"].as_array().map(Vec::len), Some(32));
        assert_eq!(report["chain_ok"], true);
        assert_eq!(report["dispatch_count"], 32);
        assert_eq!(report["prove_count"], 32);
        assert_eq!(report["chain_length"], 32);
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
        let object = Object::new(
            table.id,
            Ownership::Shared,
            "TexasPokerTable",
            borsh::to_vec(table).expect("table must serialize"),
            None,
        );
        let mut store = ObjectStore::new();
        store
            .create(object.clone())
            .expect("table object must store");
        (
            store.state_root(),
            TableSnapshot {
                object,
                inclusion_path: store
                    .prove(&table.id)
                    .expect("stored object has inclusion proof"),
            },
        )
    }

    fn consensus_material_for_create(
        pre_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        post_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
        sender: TaggedPubkey,
        selector: [u8; 32],
        args: Vec<u8>,
        block_height: u64,
        block_timestamp_ms: u64,
    ) -> ConsensusAnchorMaterial {
        let (validators, validator_secrets) = test_validators();
        let (pre_state_root, pre_snapshot) = snapshot(pre_table);
        let (post_state_root, post_snapshot) = snapshot(post_table);
        let signing_secret =
            SecretKey::from_slice(&[42; 32]).expect("fixed secret scalar is valid");
        let secp = Secp256k1::new();
        let signature =
            secp.sign_ecdsa_recoverable(&Message::from_digest([0xA5; 32]), &signing_secret);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut tx_signature = compact.to_vec();
        tx_signature.push(recovery_id.to_i32() as u8);
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: Some(ContractCall {
                contract_id: poker_l1::vm::precompile::reserved::texas_poker_contract_id(),
                method_selector: selector,
                args,
            }),
            tagged_pubkey: sender,
            signature: tx_signature,
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
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
        let state = ServerState::from_repository(ServiceRepository::open(&path).unwrap());
        let create = dispatch_for_table(state, 42, create_request(creator, "create"))
            .await
            .unwrap()
            .0;
        assert_eq!(create.call_seq, 1);

        let recovered = ServerState::from_repository(ServiceRepository::open(&path).unwrap());
        let player = [0x10; 20];
        let join = DispatchRequest {
            caller_hex: hex::encode(player),
            caller_pubkey_hex: None,
            chain_id: None,
            block_height: None,
            block_timestamp_ms: None,
            selector_hex: hex::encode(selectors::join_table()),
            args_hex: hex::encode(
                borsh::to_vec(&JoinTableArgs {
                    player,
                    buy_in: 1_000,
                    pk: ECPoint(G1Projective::generator()),
                })
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
                borsh::to_vec(&JoinTableArgs {
                    player,
                    buy_in: 1_000,
                    pk: ECPoint(G1Projective::generator()),
                })
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
        assert!(runtime.plugins.get(&LEGACY_TABLE_ID).unwrap().table().seats[0].want_leave);
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
    async fn consensus_anchor_http_route_accepts_certificate_smt_and_receipt_chain() {
        let state = ServerState::default();
        let table_id = 91;
        let sender_secret =
            SecretKey::from_slice(&[9; 32]).expect("fixed sender secret scalar is valid");
        let sender = test_tagged_pubkey(&sender_secret);
        let caller = derive_address(&sender);
        let mut create = create_request(caller, "anchored-create");
        create.caller_pubkey_hex = Some(hex::encode(sender.to_bytes()));
        create.chain_id = Some(poker_l1::DEFAULT_CHAIN_ID);
        create.block_height = Some(777);
        create.block_timestamp_ms = Some(9_876_543);
        let create_args = hex::decode(&create.args_hex).expect("create args are hex");
        let selector = selectors::create_table();

        let response = dispatch_for_table(state.clone(), table_id, create)
            .await
            .expect("dispatch with an address-bound public key must prove")
            .0;
        assert!(response.proof_verified);

        let (pre_table, post_table) = {
            let runtime = state.runtime.lock().await;
            let pre_table = new_service_plugin(table_id).table().clone();
            let post_table = runtime
                .plugins
                .get(&table_id)
                .expect("dispatched table is loaded")
                .table()
                .clone();
            (pre_table, post_table)
        };
        let material = consensus_material_for_create(
            &pre_table,
            &post_table,
            sender,
            selector,
            create_args,
            777,
            9_876_543,
        );
        let body = serde_json::json!({
            "material_borsh_hex": hex::encode(
                borsh::to_vec(&material).expect("authenticated material must serialize")
            ),
        });
        let app = router(state);
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
    }
}
