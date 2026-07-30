//! axum HTTP 服务：暴露 dispatch / 覆盖片段编排 / 插件查询端点。
//!
//! 端点：
//! - `POST /hands/run`：历史路径名；触发 6 步 WAITING 覆盖片段（HandRunner），
//!   返回 HandReport，不代表完整牌局或共识锚定。
//! - `POST /dispatch`：当前显式返回 501；持久化插件状态与单步证明尚未接线，不能返回
//!   看似成功的占位结果。
//! - `GET /plugins`：列出已加载合约插件统计。
//!
//! 注：当前为单插件（texas_poker）演示；每次 `/hands/run` 构造新插件实例。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::runner::HandRunner;
use crate::{ServiceError, ServiceResult};

/// HTTP 服务共享状态：当前插件统计（每次 run 更新）。
#[derive(Clone, Default)]
struct ServerState {
    last_report: Arc<Mutex<Option<HandReportJson>>>,
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
    pub events_count: usize,
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
    State(_state): State<ServerState>,
    Json(_req): Json<DispatchRequest>,
) -> Result<Json<DispatchResponse>, (axum::http::StatusCode, String)> {
    Err((
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "stateful POST /dispatch is disabled until persistent plugin state and prove/verify are wired; use POST /hands/run for the documented coverage fragment".into(),
    ))
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
    async fn dispatch_endpoint_fails_closed_until_stateful_execution_is_wired() {
        let result = dispatch(
            State(ServerState::default()),
            Json(DispatchRequest {
                caller_hex: "00".repeat(20),
                selector_hex: "00".repeat(32),
                args_hex: String::new(),
            }),
        )
        .await;

        let (status, message) = result.expect_err("placeholder dispatch must not return success");
        assert_eq!(status, axum::http::StatusCode::NOT_IMPLEMENTED);
        assert!(message.contains("disabled"));
    }
}
