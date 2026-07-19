//! Phase 3.6 — zkvm 服务化端到端集成测试。
//!
//! 启动真实 HTTP server，通过 `ZkvmClient` 客户端 SDK 验证完整流程：
//! 1. 健康检查端点
//! 2. prove → verify roundtrip
//! 3. proof_cache 命中
//! 4. 非法 ELF 错误处理
//! 5. stats 端点字段完整性
//! 6. shutdown 端点
//!
//! ## 运行
//!
//! ```bash
//! cargo test -p poker_zkvm --features service --test service_e2e
//! ```

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use poker_zkvm::service::client::ZkvmClient;
use poker_zkvm::service::http;
use poker_zkvm::service::{ProverService, ProverServiceConfig, to_hex};
use poker_zkvm::test_helpers::{build_nop_elf, build_texas_poker_full_hand_elf, make_full_hand_input};
use tokio::sync::oneshot;

/// 启动测试 server 并返回 (base_url, client, shutdown_flag)。
async fn start_server() -> (String, ZkvmClient, Arc<AtomicBool>) {
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

    let client = ZkvmClient::new(&base_url).expect("ZkvmClient::new");
    (base_url, client, shutdown_flag)
}

#[tokio::test]
async fn test_health() {
    let (_base, client, _flag) = start_server().await;
    let health = client.health().await.expect("health");
    assert_eq!(health.status, "ok");
    assert_eq!(health.request_count, 0, "初始 request_count 应为 0");
    assert_eq!(health.proofs_generated, 0, "初始 proofs_generated 应为 0");
}

#[tokio::test]
async fn test_prove_verify_roundtrip() {
    let (_base, client, _flag) = start_server().await;
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);

    // prove
    let prove_resp = client.prove_bytes(&elf, &input).await.expect("prove");
    assert!(prove_resp.proof_size > 0, "proof 不应为空");
    assert!(prove_resp.proof_size <= 64 * 1024, "proof 应在 64KB 上链限制内");
    assert!(!prove_resp.cache_hit, "首次 prove 不应命中 cache");
    assert!(prove_resp.elapsed_ms > 0, "prove 耗时应 > 0");

    // verify
    let verify_resp = client
        .verify(&prove_resp.proof_hex, &prove_resp.public_io_hex)
        .await
        .expect("verify");
    assert!(verify_resp.valid, "verify 应通过");
}

#[tokio::test]
async fn test_proof_cache_hit() {
    let (_base, client, _flag) = start_server().await;
    let elf = build_nop_elf(10);
    let input: Vec<u8> = vec![];

    // 首次 prove
    let resp1 = client.prove_bytes(&elf, &input).await.expect("prove #1");
    assert!(!resp1.cache_hit, "首次 prove 不应命中 cache");

    // 二次 prove 同一 elf+input → cache hit
    let resp2 = client.prove_bytes(&elf, &input).await.expect("prove #2");
    assert!(resp2.cache_hit, "二次 prove 应命中 cache");
    assert_eq!(
        resp1.proof_hex, resp2.proof_hex,
        "cache 命中应返回相同 proof"
    );
    // cache hit 的 elapsed_ms 应远小于首次
    assert!(
        resp2.elapsed_ms <= resp1.elapsed_ms,
        "cache hit 应更快 ({} <= {})",
        resp2.elapsed_ms,
        resp1.elapsed_ms
    );
}

#[tokio::test]
async fn test_invalid_elf() {
    let (_base, client, _flag) = start_server().await;
    // 非法 ELF 字节
    let bad_elf = b"not an elf";
    let input = b"";
    let result = client.prove_bytes(bad_elf, input).await;
    assert!(
        result.is_err(),
        "非法 ELF 应返回错误，实际: {:?}",
        result
    );
}

#[tokio::test]
async fn test_stats() {
    let (_base, client, _flag) = start_server().await;
    let stats = client.stats().await.expect("stats");
    assert!(stats.ccs_registry_size > 0, "CCS registry 不应为空");
    assert_eq!(stats.ipa_pcs_cache_size, 0, "Phase 5 启用 IPA PCS cache");
    assert_eq!(stats.proof_cache_size, 0, "初始 cache 应为空");
    assert_eq!(stats.total_proofs, 0, "初始 total_proofs 应为 0");
    assert_eq!(stats.total_verifies, 0, "初始 total_verifies 应为 0");

    // 执行一次 prove + verify 后再查 stats
    let elf = build_nop_elf(10);
    let input: Vec<u8> = vec![];
    let prove_resp = client.prove_bytes(&elf, &input).await.expect("prove");
    let _ = client
        .verify(&prove_resp.proof_hex, &prove_resp.public_io_hex)
        .await
        .expect("verify");

    let stats2 = client.stats().await.expect("stats #2");
    assert_eq!(stats2.total_proofs, 1, "prove 后 total_proofs 应为 1");
    assert_eq!(stats2.total_verifies, 1, "verify 后 total_verifies 应为 1");
    assert!(stats2.avg_prove_latency_ms > 0.0, "平均延迟应 > 0");
}

#[tokio::test]
async fn test_shutdown() {
    let (_base, client, flag) = start_server().await;
    let resp = client.shutdown().await.expect("shutdown");
    assert_eq!(resp.status, "shutting_down");
    // shutdown_flag 应被设置
    assert!(
        flag.load(Ordering::Relaxed),
        "shutdown_flag 应被设置为 true"
    );
}

#[tokio::test]
async fn test_texas_poker_full_hand_e2e() {
    // 完整端到端：texas_poker ELF → HTTP /prove → HTTP /verify → 校验 winner
    let (_base, client, _flag) = start_server().await;
    let elf = build_texas_poker_full_hand_elf();
    let input = make_full_hand_input([14, 13, 12, 11, 10], [2, 2, 3, 4, 5]);

    let prove_resp = client.prove_bytes(&elf, &input).await.expect("prove");
    assert!(prove_resp.proof_size > 0);

    // 反序列化 public_io 检查 winner
    let public_io_bytes =
        poker_zkvm::service::from_hex(&prove_resp.public_io_hex).expect("decode public_io hex");
    let public_io = poker_zkvm::prover::ZkPublicIo::from_bytes(&public_io_bytes)
        .expect("deserialize public_io");
    assert_eq!(public_io.output.len(), 1, "texas_poker 输出应为 1 字节 winner");
    assert_eq!(public_io.output[0], 1, "P1 (straight A K Q J 10) 应胜 P2 (pair 2s)");

    // verify
    let verify_resp = client
        .verify(&prove_resp.proof_hex, &prove_resp.public_io_hex)
        .await
        .expect("verify");
    assert!(verify_resp.valid, "verify 应通过");
}

#[tokio::test]
async fn test_raw_hex_api() {
    // 测试 raw hex 接口（不通过 prove_bytes 便捷方法）
    let (_base, client, _flag) = start_server().await;
    let elf = build_nop_elf(10);
    let input: Vec<u8> = vec![];
    let elf_hex = to_hex(&elf);
    let input_hex = to_hex(&input);

    let resp = client.prove(&elf_hex, &input_hex).await.expect("prove");
    assert!(resp.proof_size > 0);
    assert!(!resp.proof_hex.is_empty());
    assert!(!resp.public_io_hex.is_empty());
}