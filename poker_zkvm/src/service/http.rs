//! Phase 3.2 — zkvm 服务化 HTTP server（axum 0.7）。
//!
//! 提供 5 个 REST 端点：
//!
//! | 方法 | 路径 | 说明 |
//! |------|------|------|
//! | POST | `/prove` | 提交 ELF+input，返回 proof+public_io |
//! | POST | `/verify` | 提交 proof+public_io，返回 valid |
//! | GET  | `/health` | 健康检查 |
//! | GET  | `/stats` | 详细统计 |
//! | POST | `/shutdown` | 触发优雅关闭 |
//!
//! ## 优雅关闭
//!
//! 监听 SIGINT/SIGTERM，drain in-flight 请求后退出。
//! `/shutdown` 端点也会触发同样流程。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::types::{
    ErrorResponse, HealthResponse, ProveRequest, ProveResponse, ShutdownResponse, StatsResponse,
    VerifyRequest, VerifyResponse, from_hex,
};
use super::{ProverService, ProverServiceConfig};
use crate::error::ZkvmError;
use crate::prover::ZkPublicIo;

// ===========================================================================
// AppState
// ===========================================================================

/// HTTP server 共享状态。
pub struct AppState {
    /// ProverService 实例。
    pub service: Arc<ProverService>,
    /// 关闭信号（true = 正在关闭）。
    pub shutdown_flag: Arc<AtomicBool>,
    /// 触发 shutdown 端点时的 oneshot 信号。
    pub shutdown_tx: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
}

// ===========================================================================
// 路由
// ===========================================================================

/// 构造 axum Router。
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/prove", post(handle_prove))
        .route("/verify", post(handle_verify))
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .route("/shutdown", post(handle_shutdown))
        .with_state(state)
}

// ===========================================================================
// 端点处理器
// ===========================================================================

/// POST /prove
async fn handle_prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, Json<ErrorResponse>)> {
    if state.shutdown_flag.load(Ordering::Relaxed) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new("服务正在关闭")),
        ));
    }

    let elf = from_hex(&req.elf_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("elf_hex 解码失败: {e}")))))?;
    let input = from_hex(&req.input_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("input_hex 解码失败: {e}")))))?;

    match state.service.prove(&elf, &input).await {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => {
            tracing::warn!("prove 失败: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(format!("prove 失败: {e}"))),
            ))
        }
    }
}

/// POST /verify
async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    if state.shutdown_flag.load(Ordering::Relaxed) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse::new("服务正在关闭")),
        ));
    }

    let proof = from_hex(&req.proof_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("proof_hex 解码失败: {e}")))))?;
    let public_io_bytes = from_hex(&req.public_io_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ErrorResponse::new(format!("public_io_hex 解码失败: {e}")))))?;
    let public_io = ZkPublicIo::from_bytes(&public_io_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(format!("public_io 反序列化失败: {e}"))),
        )
    })?;

    match state.service.verify(&proof, &public_io).await {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => {
            tracing::warn!("verify 失败: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(format!("verify 失败: {e}"))),
            ))
        }
    }
}

/// GET /health
async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let stats = state.service.stats();
    let status = if state.shutdown_flag.load(Ordering::Relaxed) {
        "shutting_down"
    } else {
        "ok"
    };
    Json(HealthResponse {
        status: status.to_string(),
        uptime_s: stats.uptime_s,
        request_count: stats.prove_count + stats.verify_count,
        proofs_generated: stats.proofs_generated,
    })
}

/// GET /stats
async fn handle_stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let stats = state.service.stats();
    let prove_count = stats.prove_count;
    let verify_count = stats.verify_count;
    let avg_prove = if prove_count > 0 {
        stats.prove_total_ms as f64 / prove_count as f64
    } else {
        0.0
    };
    let avg_verify = if verify_count > 0 {
        stats.verify_total_ms as f64 / verify_count as f64
    } else {
        0.0
    };
    Json(StatsResponse {
        ccs_registry_size: state.service.ccs_registry_size(),
        ipa_pcs_cache_size: 0, // Phase 5 启用
        proof_cache_size: state.service.proof_cache_size(),
        total_proofs: stats.proofs_generated,
        total_verifies: verify_count,
        avg_prove_latency_ms: avg_prove,
        avg_verify_latency_ms: avg_verify,
    })
}

/// POST /shutdown
async fn handle_shutdown(State(state): State<Arc<AppState>>) -> Json<ShutdownResponse> {
    tracing::info!("收到 /shutdown 请求，开始优雅关闭");
    state.shutdown_flag.store(true, Ordering::Relaxed);
    let mut tx_guard = state.shutdown_tx.lock().await;
    if let Some(tx) = tx_guard.take() {
        let _ = tx.send(());
    }
    Json(ShutdownResponse {
        status: "shutting_down".to_string(),
    })
}

// ===========================================================================
// 启动 server
// ===========================================================================

/// 启动 HTTP server。
///
/// # 参数
/// - `listen_addr` — 监听地址（如 "127.0.0.1:9527"）
/// - `config` — ProverService 配置
///
/// # Errors
/// - `ZkvmError::Other` — 端口绑定失败 / ProverService 构造失败
pub async fn run_server(
    listen_addr: &str,
    config: ProverServiceConfig,
) -> Result<(), ZkvmError> {
    let service = Arc::new(ProverService::new(config)?);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let state = Arc::new(AppState {
        service: service.clone(),
        shutdown_flag: shutdown_flag.clone(),
        shutdown_tx: tokio::sync::Mutex::new(Some(shutdown_tx)),
    });

    let app = build_router(state);
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| ZkvmError::Other(format!("非法 listen_addr '{listen_addr}': {e}")))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| ZkvmError::Other(format!("bind {listen_addr} 失败: {e}")))?;

    tracing::info!("zkvm-server 监听 http://{addr}");

    // 优雅关闭：SIGINT / SIGTERM / shutdown_rx 任一触发则停止
    let sig_shutdown_flag = shutdown_flag.clone();
    let ctrl_c_task = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            if let (Ok(mut sigint), Ok(mut sigterm)) = (
                signal(SignalKind::interrupt()),
                signal(SignalKind::terminate()),
            ) {
                tokio::select! {
                    _ = sigint.recv() => tracing::info!("收到 SIGINT"),
                    _ = sigterm.recv() => tracing::info!("收到 SIGTERM"),
                }
            } else {
                // fallback: ctrl_c
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("收到 Ctrl-C");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("收到 Ctrl-C");
        }
        sig_shutdown_flag.store(true, Ordering::Relaxed);
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
            tracing::info!("graceful shutdown 已触发");
        })
        .await
        .map_err(|e| ZkvmError::Other(format!("axum::serve 失败: {e}")))?;

    ctrl_c_task.abort();
    tracing::info!("zkvm-server 已退出");
    Ok(())
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::to_hex;
    use crate::test_helpers::{build_nop_elf, build_texas_poker_full_hand_elf, make_full_hand_input};

    /// 启动一个测试用 server，返回其监听地址与 shutdown 信号发送端。
    async fn start_test_server() -> (String, Arc<ProverService>, Arc<AtomicBool>) {
        let service = Arc::new(ProverService::new(ProverServiceConfig::default()).unwrap());
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let state = Arc::new(AppState {
            service: service.clone(),
            shutdown_flag: shutdown_flag.clone(),
            shutdown_tx: tokio::sync::Mutex::new(Some(shutdown_tx)),
        });
        let app = build_router(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let addr_str = format!("http://{addr}");

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        (addr_str, service, shutdown_flag)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let (addr, _service, _flag) = start_test_server().await;
        let resp = reqwest::get(format!("{addr}/health"))
            .await
            .expect("GET /health");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: HealthResponse = resp.json().await.expect("parse health");
        assert_eq!(body.status, "ok");
        assert_eq!(body.request_count, 0);
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let (addr, _service, _flag) = start_test_server().await;
        let resp = reqwest::get(format!("{addr}/stats"))
            .await
            .expect("GET /stats");
        assert_eq!(resp.status(), StatusCode::OK);
        let body: StatsResponse = resp.json().await.expect("parse stats");
        assert!(body.ccs_registry_size > 0);
        assert_eq!(body.proof_cache_size, 0);
    }

    #[tokio::test]
    async fn test_prove_verify_roundtrip() {
        let (addr, _service, _flag) = start_test_server().await;

        // prove
        let elf = build_texas_poker_full_hand_elf();
        let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);
        let prove_req = ProveRequest {
            elf_hex: to_hex(&elf),
            input_hex: to_hex(&input),
        };
        let prove_resp: ProveResponse = reqwest::Client::new()
            .post(format!("{addr}/prove"))
            .json(&prove_req)
            .send()
            .await
            .expect("POST /prove")
            .json()
            .await
            .expect("parse prove response");
        assert!(prove_resp.proof_size > 0);
        assert!(!prove_resp.cache_hit);

        // verify
        let verify_req = VerifyRequest {
            proof_hex: prove_resp.proof_hex.clone(),
            public_io_hex: prove_resp.public_io_hex.clone(),
        };
        let verify_resp: VerifyResponse = reqwest::Client::new()
            .post(format!("{addr}/verify"))
            .json(&verify_req)
            .send()
            .await
            .expect("POST /verify")
            .json()
            .await
            .expect("parse verify response");
        assert!(verify_resp.valid);
    }

    #[tokio::test]
    async fn test_prove_cache_hit() {
        let (addr, _service, _flag) = start_test_server().await;
        let elf = build_nop_elf(10);
        let input: Vec<u8> = vec![];
        let prove_req = ProveRequest {
            elf_hex: to_hex(&elf),
            input_hex: to_hex(&input),
        };

        let client = reqwest::Client::new();
        let resp1: ProveResponse = client
            .post(format!("{addr}/prove"))
            .json(&prove_req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(!resp1.cache_hit);

        let resp2: ProveResponse = client
            .post(format!("{addr}/prove"))
            .json(&prove_req)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(resp2.cache_hit, "二次 prove 应命中 cache");
        assert_eq!(resp1.proof_hex, resp2.proof_hex);
    }

    #[tokio::test]
    async fn test_prove_invalid_hex() {
        let (addr, _service, _flag) = start_test_server().await;
        let prove_req = ProveRequest {
            elf_hex: "not_hex!".to_string(),
            input_hex: "00".to_string(),
        };
        let resp = reqwest::Client::new()
            .post(format!("{addr}/prove"))
            .json(&prove_req)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_shutdown_endpoint() {
        let (addr, _service, shutdown_flag) = start_test_server().await;
        let resp: ShutdownResponse = reqwest::Client::new()
            .post(format!("{addr}/shutdown"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp.status, "shutting_down");
        // shutdown_flag 应被设置
        assert!(shutdown_flag.load(Ordering::Relaxed));
    }
}