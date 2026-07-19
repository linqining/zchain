//! Phase 3.4 — zkvm 服务化客户端 SDK（reqwest 0.12）。
//!
//! 提供与 `service::http` 服务端对话的异步客户端。
//!
//! ## 使用示例
//!
//! ```no_run
//! use poker_zkvm::service::client::ZkvmClient;
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ZkvmClient::new("http://127.0.0.1:9527")?;
//! let elf_hex = poker_zkvm::service::to_hex(b"...");
//! let input_hex = poker_zkvm::service::to_hex(b"...");
//! let resp = client.prove(&elf_hex, &input_hex).await?;
//! println!("proof size: {} bytes", resp.proof_size);
//! # Ok(())
//! # }
//! ```

use crate::error::ZkvmError;
use crate::service::types::{
    ErrorResponse, HealthResponse, ProveRequest, ProveResponse, ShutdownResponse, StatsResponse,
    VerifyRequest, VerifyResponse,
};

/// zkvm HTTP 客户端。
pub struct ZkvmClient {
    /// 服务端 base URL（如 "http://127.0.0.1:9527"）。
    pub base_url: String,
    /// 内部 reqwest client。
    client: reqwest::Client,
}

impl ZkvmClient {
    /// 创建新客户端。
    ///
    /// # Errors
    /// - `reqwest::Client::new()` 失败（极少见）
    pub fn new(base_url: &str) -> Result<Self, ZkvmError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| ZkvmError::Other(format!("reqwest::Client 构造失败: {e}")))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// POST /prove
    pub async fn prove(&self, elf_hex: &str, input_hex: &str) -> Result<ProveResponse, ZkvmError> {
        let req = ProveRequest {
            elf_hex: elf_hex.to_string(),
            input_hex: input_hex.to_string(),
        };
        let resp = self
            .client
            .post(format!("{}/prove", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| ZkvmError::Other(format!("prove 请求失败: {e}")))?;
        Self::parse_response(resp).await
    }

    /// POST /verify
    pub async fn verify(
        &self,
        proof_hex: &str,
        public_io_hex: &str,
    ) -> Result<VerifyResponse, ZkvmError> {
        let req = VerifyRequest {
            proof_hex: proof_hex.to_string(),
            public_io_hex: public_io_hex.to_string(),
        };
        let resp = self
            .client
            .post(format!("{}/verify", self.base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| ZkvmError::Other(format!("verify 请求失败: {e}")))?;
        Self::parse_response(resp).await
    }

    /// GET /health
    pub async fn health(&self) -> Result<HealthResponse, ZkvmError> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|e| ZkvmError::Other(format!("health 请求失败: {e}")))?;
        Self::parse_response(resp).await
    }

    /// GET /stats
    pub async fn stats(&self) -> Result<StatsResponse, ZkvmError> {
        let resp = self
            .client
            .get(format!("{}/stats", self.base_url))
            .send()
            .await
            .map_err(|e| ZkvmError::Other(format!("stats 请求失败: {e}")))?;
        Self::parse_response(resp).await
    }

    /// POST /shutdown
    pub async fn shutdown(&self) -> Result<ShutdownResponse, ZkvmError> {
        let resp = self
            .client
            .post(format!("{}/shutdown", self.base_url))
            .send()
            .await
            .map_err(|e| ZkvmError::Other(format!("shutdown 请求失败: {e}")))?;
        Self::parse_response(resp).await
    }

    /// 便捷方法：直接用字节提交 prove。
    pub async fn prove_bytes(&self, elf: &[u8], input: &[u8]) -> Result<ProveResponse, ZkvmError> {
        let elf_hex = crate::service::to_hex(elf);
        let input_hex = crate::service::to_hex(input);
        self.prove(&elf_hex, &input_hex).await
    }

    /// 解析响应：2xx → 反序列化为 T；非 2xx → 解析 ErrorResponse 为错误。
    async fn parse_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, ZkvmError> {
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| ZkvmError::Other(format!("响应反序列化失败: {e}")))
        } else {
            let err: ErrorResponse = resp
                .json()
                .await
                .map_err(|e| ZkvmError::Other(format!("错误响应反序列化失败: {e}")))?;
            Err(ZkvmError::Other(format!(
                "HTTP {status}: {}",
                err.error
            )))
        }
    }
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::http;
    use crate::service::{ProverService, ProverServiceConfig};
    use crate::test_helpers::{build_nop_elf, build_texas_poker_full_hand_elf, make_full_hand_input};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// 启动测试 server 并返回 (base_url, client, shutdown_flag)。
    async fn start_server_and_client() -> (ZkvmClient, Arc<AtomicBool>) {
        let service = Arc::new(ProverService::new(ProverServiceConfig::default()).unwrap());
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let state = Arc::new(http::AppState {
            service: service.clone(),
            shutdown_flag: shutdown_flag.clone(),
            shutdown_tx: tokio::sync::Mutex::new(Some(shutdown_tx)),
        });
        let app = http::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");

        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let client = ZkvmClient::new(&base_url).unwrap();
        (client, shutdown_flag)
    }

    #[tokio::test]
    async fn test_client_health() {
        let (client, _flag) = start_server_and_client().await;
        let health = client.health().await.expect("health");
        assert_eq!(health.status, "ok");
    }

    #[tokio::test]
    async fn test_client_stats() {
        let (client, _flag) = start_server_and_client().await;
        let stats = client.stats().await.expect("stats");
        assert!(stats.ccs_registry_size > 0);
    }

    #[tokio::test]
    async fn test_client_prove_verify_roundtrip() {
        let (client, _flag) = start_server_and_client().await;
        let elf = build_texas_poker_full_hand_elf();
        let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);

        let prove_resp = client.prove_bytes(&elf, &input).await.expect("prove");
        assert!(prove_resp.proof_size > 0);

        let verify_resp = client
            .verify(&prove_resp.proof_hex, &prove_resp.public_io_hex)
            .await
            .expect("verify");
        assert!(verify_resp.valid);
    }

    #[tokio::test]
    async fn test_client_cache_hit() {
        let (client, _flag) = start_server_and_client().await;
        let elf = build_nop_elf(10);
        let input: Vec<u8> = vec![];

        let resp1 = client.prove_bytes(&elf, &input).await.expect("prove #1");
        assert!(!resp1.cache_hit);

        let resp2 = client.prove_bytes(&elf, &input).await.expect("prove #2");
        assert!(resp2.cache_hit);
    }

    #[tokio::test]
    async fn test_client_shutdown() {
        let (client, flag) = start_server_and_client().await;
        let resp = client.shutdown().await.expect("shutdown");
        assert_eq!(resp.status, "shutting_down");
        assert!(flag.load(Ordering::Relaxed));
    }
}