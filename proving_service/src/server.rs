//! axum HTTP 服务：暴露 dispatch / 覆盖片段编排 / 插件查询端点。
//!
//! 端点：
//! - `POST /hands/run`：历史路径名；触发 6 步 WAITING 覆盖片段（HandRunner），
//!   返回 HandReport，不代表完整牌局或共识锚定。
//! - `POST /dispatch`：在服务进程内维护单桌插件状态，执行真实 dispatch，并在有
//!   `ProveTask` 时同步 prove + verify。任一环节失败都不会提交状态变更。
//! - `GET /plugins`：列出已加载合约插件统计。
//!
//! 注：当前为单插件、单桌的进程内服务；状态不会跨进程重启持久化，也不声称共识锚定。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::contracts::TexasPokerPlugin;
use crate::plugin::ContractPlugin;
use crate::runner::HandRunner;
use crate::{ServiceError, ServiceResult};

/// HTTP 服务共享状态。
///
/// `plugin` serializes one table's stateful dispatches. Each request works on a clone and only
/// replaces this value after the optional proof has verified, so an unsupported or invalid AIR
/// transition cannot leave a state change without its receipt.
#[derive(Clone)]
struct ServerState {
    plugin: Arc<Mutex<TexasPokerPlugin>>,
    last_report: Arc<Mutex<Option<HandReportJson>>>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            plugin: Arc::new(Mutex::new(new_service_plugin())),
            last_report: Arc::new(Mutex::new(None)),
        }
    }
}

/// HandReport 的 JSON 序列化形式。
#[derive(Debug, Clone, Serialize)]
pub struct HandReportJson {
    pub steps: Vec<(String, bool)>,
    pub chain_ok: bool,
    /// `false` means the descriptor-only production Aggregator was attempted and
    /// rejected as expected; it is not a failed recursive proof verification.
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
                .map(|(n, ok)| ((*n).to_string(), *ok))
                .collect(),
            chain_ok: r.chain_ok,
            aggregate_ok: r.aggregate_ok,
            dispatch_count: r.stats.dispatch_count,
            prove_count: r.stats.prove_count,
            chain_length: r.stats.chain_length,
        }
    }
}

/// `/dispatch` 请求体。
#[derive(Debug, Deserialize)]
pub struct DispatchRequest {
    /// 调用者地址（20 字节 hex）。
    pub caller_hex: String,
    /// 方法选择器（32 字节 hex）。
    pub selector_hex: String,
    /// 方法参数（borsh 编码 hex）。
    pub args_hex: String,
}

/// `/dispatch` 响应体。
#[derive(Debug, Serialize)]
pub struct DispatchResponse {
    pub had_prove_task: bool,
    /// `true` only when a generated task has completed native prove + verify.
    pub proof_verified: bool,
    pub events_count: usize,
    /// Cumulative service-local plugin statistics after the committed transition.
    pub dispatch_count: u64,
    pub prove_count: u64,
    pub chain_length: usize,
    /// Version and ordering fields let the caller detect the committed table revision.
    pub table_version: u64,
    pub hand_id: u32,
    pub call_seq: u32,
}

/// 启动 HTTP 服务。
///
/// # Errors
///
/// 绑定 / serve 失败时返回错误。
pub async fn serve(addr: SocketAddr) -> ServiceResult<()> {
    let state = ServerState::default();
    let app = axum::Router::new()
        .route("/hands/run", post(run_hand))
        .route("/dispatch", post(dispatch))
        .route("/plugins", get(list_plugins))
        .route("/health", get(|| async { "ok" }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServiceError::Runner(format!("bind {addr}: {e}")))?;
    tracing::info!("proving_service listening on {addr}");
    axum::serve(listener, app)
        .await
        .map_err(|e| ServiceError::Runner(format!("serve: {e}")))?;
    Ok(())
}

async fn run_hand(
    State(state): State<ServerState>,
) -> Result<Json<HandReportJson>, (axum::http::StatusCode, String)> {
    let (_plugin, report) = HandRunner::new()
        .run()
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let json = HandReportJson::from_report(&report);
    *state.last_report.lock().await = Some(json.clone());
    Ok(Json(json))
}

async fn dispatch(
    State(state): State<ServerState>,
    Json(req): Json<DispatchRequest>,
) -> Result<Json<DispatchResponse>, (axum::http::StatusCode, String)> {
    let caller = decode_fixed_hex::<20>(&req.caller_hex, "caller_hex")?;
    let selector = decode_fixed_hex::<32>(&req.selector_hex, "selector_hex")?;
    let args = hex::decode(&req.args_hex).map_err(|error| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("args_hex must be hexadecimal: {error}"),
        )
    })?;

    // Keep the lock over CPU work deliberately: this is a single-table service and serializing
    // requests is required for call_seq/state-root continuity. The staged clone gives the entire
    // dispatch+prove operation all-or-nothing semantics.
    let mut committed = state.plugin.lock().await;
    let mut staged = committed.clone();
    let outcome = staged
        .dispatch(caller, &selector, &args)
        .map_err(service_failure)?;
    let had_prove_task = outcome.prove_task.is_some();
    if let Some(task) = &outcome.prove_task {
        staged.prove_task(task).map_err(service_failure)?;
    }

    let stats = staged.stats();
    let table = staged.table();
    let response = DispatchResponse {
        had_prove_task,
        proof_verified: had_prove_task,
        events_count: outcome.output.events.len(),
        dispatch_count: stats.dispatch_count,
        prove_count: stats.prove_count,
        chain_length: stats.chain_length,
        table_version: table.version,
        hand_id: table.hand_id,
        call_seq: table.call_seq,
    };
    *committed = staged;

    Ok(Json(response))
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    name: &str,
) -> Result<[u8; N], (axum::http::StatusCode, String)> {
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

fn service_failure(error: crate::PluginError) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        error.to_string(),
    )
}

fn new_service_plugin() -> TexasPokerPlugin {
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TableConfig, TexasPokerTable};

    let mut table = TexasPokerTable::new(
        ObjectID::new([0xFF; 20], 0),
        "service_placeholder".into(),
        EMPTY_PLAYER,
        6,
        50,
        100,
    );
    // `create_table` overwrites this placeholder and captures its caller as the real creator.
    // Keeping the default config permits the documented non-crypto AIR coverage methods.
    table.config = TableConfig::default();
    TexasPokerPlugin::new(table)
}

async fn list_plugins(State(state): State<ServerState>) -> impl IntoResponse {
    let guard = state.last_report.lock().await;
    Json(serde_json::json!({
        "plugins": ["texas_poker"],
        "last_report": guard.as_ref().map(|r| serde_json::json!({
            "chain_ok": r.chain_ok,
            "aggregate_ok": r.aggregate_ok,
            "dispatch_count": r.dispatch_count,
            "prove_count": r.prove_count,
            "chain_length": r.chain_length,
        })),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatch_endpoint_commits_only_a_proven_transition() {
        use blstrs::G1Projective;
        use group::Group;
        use poker_l1::vm::contracts::texas_poker::dispatch::{
            CreateTableArgs, JoinTableArgs, SeatIndexArgs, selectors,
        };
        use poker_protocol::crypto::types::ECPoint;

        let state = ServerState::default();
        let creator = [0xAA; 20];
        let create = DispatchRequest {
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
        };
        let create_response = dispatch(State(state.clone()), Json(create))
            .await
            .unwrap()
            .0;
        assert!(create_response.had_prove_task);
        assert!(create_response.proof_verified);
        assert_eq!(create_response.call_seq, 1);

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
        };
        let join_response = dispatch(State(state.clone()), Json(join)).await.unwrap().0;
        assert_eq!(join_response.call_seq, 2);

        let request_leave = DispatchRequest {
            caller_hex: hex::encode(player),
            selector_hex: hex::encode(selectors::request_leave_after_hand()),
            args_hex: hex::encode(borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap()),
        };
        let leave_response = dispatch(State(state.clone()), Json(request_leave))
            .await
            .unwrap()
            .0;
        assert!(leave_response.had_prove_task);
        assert!(leave_response.proof_verified);
        assert_eq!(leave_response.call_seq, 3);
        assert_eq!(leave_response.dispatch_count, 3);
        assert_eq!(leave_response.prove_count, 3);
        assert_eq!(leave_response.chain_length, 3);

        let plugin = state.plugin.lock().await;
        assert_eq!(plugin.table().call_seq, 3);
        assert!(plugin.table().seats[0].want_leave);
    }
}
