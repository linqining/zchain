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
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::contracts::TexasPokerPlugin;
use crate::plugin::ContractPlugin;
use crate::repository::{
    JobReservation, RepositoryError, ServiceRepository, StoredDispatchJob, StoredDispatchResult,
    StoredJobStatus, StoredProofMetadata, StoredTable,
};
use crate::runner::HandRunner;
use crate::{ServiceError, ServiceResult};

const LEGACY_TABLE_ID: u64 = 0;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

type HttpError = (axum::http::StatusCode, String);

/// HTTP service state.  A global runtime lock makes dispatch and repository
/// commits serializable; tables are nevertheless independent plugin instances.
#[derive(Clone)]
struct ServerState {
    runtime: Arc<Mutex<ServiceRuntime>>,
    last_report: Arc<Mutex<Option<HandReportJson>>>,
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

/// Dispatch request.  Supplying `idempotency_key` makes retries safe across a
/// service restart.  Requests without it remain supported but are intentionally
/// treated as new dispatches.
#[derive(Debug, Deserialize)]
pub struct DispatchRequest {
    /// Caller address (20-byte hexadecimal).
    pub caller_hex: String,
    /// Method selector (32-byte hexadecimal).
    pub selector_hex: String,
    /// Borsh method arguments (hexadecimal).
    pub args_hex: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
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
    let app = axum::Router::new()
        // Legacy single-table compatibility route.
        .route("/dispatch", post(dispatch_legacy))
        .route("/tables/:table_id/dispatch", post(dispatch_table))
        .route("/jobs/:job_id", get(get_job))
        .route("/hands/run", post(run_hand))
        .route("/plugins", get(list_plugins))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| ServiceError::Runner(format!("bind {addr}: {error}")))?;
    tracing::info!("proving_service listening on {addr}");
    axum::serve(listener, app)
        .await
        .map_err(|error| ServiceError::Runner(format!("serve: {error}")))?;
    Ok(())
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
    let (_plugin, report) = HandRunner::new()
        .run()
        .map_err(|error| internal_error(error.to_string()))?;
    let json = HandReportJson::from_report(&report);
    *state.last_report.lock().await = Some(json.clone());
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
    let selector = decode_fixed_hex::<32>(&request.selector_hex, "selector_hex")?;
    let args = hex::decode(&request.args_hex).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("args_hex must be hexadecimal: {error}"),
        )
    })?;
    let idempotency_key = normalize_idempotency_key(request.idempotency_key)?;
    let request_digest = digest_request(table_id, &idempotency_key, caller, selector, &args);

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
    let outcome = match staged.dispatch(caller, &selector, &args) {
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

async fn list_plugins(State(state): State<ServerState>) -> impl IntoResponse {
    let last_report = state.last_report.lock().await.clone();
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
    selector: [u8; 32],
    args: &[u8],
) -> [u8; 32] {
    let key = idempotency_key.as_deref().unwrap_or("");
    let mut material = Vec::with_capacity(8 + 20 + 32 + 8 + args.len() + key.len());
    material.extend_from_slice(&table_id.to_le_bytes());
    material.extend_from_slice(&caller);
    material.extend_from_slice(&selector);
    material.extend_from_slice(&(key.len() as u64).to_le_bytes());
    material.extend_from_slice(key.as_bytes());
    material.extend_from_slice(&(args.len() as u64).to_le_bytes());
    material.extend_from_slice(args);
    blake2b_256(b"zchain.proving_service.request.v1", &material)
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

    use blstrs::G1Projective;
    use group::Group;
    use poker_l1::vm::contracts::texas_poker::dispatch::{
        CreateTableArgs, JoinTableArgs, SeatIndexArgs, selectors,
    };
    use poker_protocol::crypto::types::ECPoint;

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
}
