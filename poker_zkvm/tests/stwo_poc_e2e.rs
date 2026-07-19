//! Stwo POC 端到端测试 — Phase 1.5 决策门。
//!
//! 决策门：1M step trace 的 prove 耗时 ≤ 86.7ms（Hypernova 基准 8670ms / 100）。
//!
//! 测试覆盖：
//! 1. 功能正确性 — 1024 步 trace prove 成功，proof 大小合理
//! 2. 序列化往返 — StwoProof serialize/deserialize roundtrip
//! 3. 性能基准 — 1M 步 trace prove 耗时测量 + 决策门判定（软断言）

use std::time::Instant;
use poker_zkvm::stwo_backend::{
    StwoProver, deserialize_stwo_proof, serialize_stwo_proof,
};
use poker_zkvm::field::ZkvmField;
use poker_zkvm::prover::ZkPublicIo;
use poker_zkvm::test_helpers::make_sequential_trace;

/// 构造空 ZkPublicIo（POC 阶段不绑定 public_io）。
fn empty_public_io() -> ZkPublicIo {
    ZkPublicIo {
        input: vec![],
        output: vec![],
        randomness_seed: poker_zkvm::ccs::Fr::zero(),
        initial_commitment: poker_zkvm::ccs::Fr::zero(),
        final_commitment: poker_zkvm::ccs::Fr::zero(),
        event_hashes: vec![],
    }
}

#[test]
fn test_stwo_poc_prove_minimal_trace() {
    // 1024 步 trace（log_size=10，SimdBackend 最小要求）
    let trace = make_sequential_trace(1024);
    let prover = StwoProver::default();
    let public_io = empty_public_io();

    let start = Instant::now();
    let proof = prover
        .prove_from_trace(&trace, &public_io)
        .expect("1024 步 trace prove 应成功");
    let elapsed = start.elapsed();

    println!("Stwo prove 1024 step: {:?}", elapsed);
    println!("Proof size: {} bytes", proof.stwo_proof.len());

    // proof 大小应 < 64KB（MAX_STWO_PROOF_SIZE）
    assert!(
        proof.stwo_proof.len() < 64 * 1024,
        "proof 大小 {} 应 < 64KB",
        proof.stwo_proof.len()
    );
    // proof 非空
    assert!(!proof.stwo_proof.is_empty(), "proof 不应为空");
}

#[test]
fn test_stwo_poc_serialization_roundtrip() {
    let trace = make_sequential_trace(1024);
    let prover = StwoProver::default();
    let public_io = empty_public_io();

    let proof = prover
        .prove_from_trace(&trace, &public_io)
        .expect("prove 应成功");

    // 序列化往返
    let bytes = serialize_stwo_proof(&proof);
    let restored = deserialize_stwo_proof(&bytes).expect("deserialize 应成功");
    assert_eq!(restored, proof, "serialize/deserialize 往返应保持一致");
}

#[test]
fn test_stwo_poc_decision_gate_1m_steps() {
    // 1M step = 2^20，log_size=20，与 StwoProverConfig::default().air_log_size 一致
    let num_steps = 1 << 20; // 1_048_576
    let trace = make_sequential_trace(num_steps);
    let prover = StwoProver::default();
    let public_io = empty_public_io();

    println!("=== Stwo POC 决策门测试 ===");
    println!("Hypernova baseline: 8670ms");
    println!("Decision gate: <= 86.7ms (>=100x speedup)");
    println!("Trace steps: {}", num_steps);
    println!();

    let start = Instant::now();
    let proof = prover
        .prove_from_trace(&trace, &public_io)
        .expect("1M step trace prove 应成功");
    let elapsed = start.elapsed();

    let elapsed_ms = elapsed.as_millis() as f64;
    let speedup = 8670.0 / elapsed_ms;
    let decision_gate_pass = elapsed_ms <= 86.7;

    println!("Stwo prove 1M step: {:.2}ms", elapsed_ms);
    println!("Speedup vs Hypernova: {:.1}x", speedup);
    println!("Proof size: {} bytes", proof.stwo_proof.len());
    println!(
        "Decision gate (>=100x): {}",
        if decision_gate_pass { "PASS" } else { "FAIL" }
    );

    // 软断言（不 fail 测试，仅打印决策门结果）
    // 硬断言留待基准稳定后开启
    assert!(!proof.stwo_proof.is_empty(), "proof 不应为空");
}
