//! Phase 12 端到端集成测试 — Fibonacci 电路。
//!
//! 测试流程：构建 ELF → prove() → verify_production() → 验证输出 → proof 大小检查
//!
//! # 电路说明
//!
//! 计算 Fibonacci(N) mod 2^32，N 次迭代后通过 commit_output 输出 4 字节结果。

mod common;

use common::{build_fibonacci_elf, fibonacci_expected};
use poker_zkvm::prover::{MAX_PROOF_TOTAL_SIZE, ProverConfig, default_ccs_registry, prove};
use poker_zkvm::verifier::verify_production;

/// 构造 Fibonacci prove 配置。
fn fib_config() -> ProverConfig {
    ProverConfig {
        batch_size: 3,
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    }
}

/// 验证 Fibonacci(N) 的完整 prove→verify 流程。
fn run_fibonacci_e2e(n: u32) {
    let elf = build_fibonacci_elf(n);
    let input: Vec<u8> = Vec::new();
    let config = fib_config();

    // 1. prove
    let (proof_bytes, public_io) =
        prove(&elf, &input, &config).unwrap_or_else(|e| panic!("prove 失败: {e:?}"));

    // 2. verify
    let ccs_registry = default_ccs_registry();
    let ok = verify_production(&proof_bytes, &public_io, &ccs_registry)
        .unwrap_or_else(|e| panic!("verify_production 错误: {e:?}"));
    assert!(ok, "verify_production 应返回 true");

    // 3. 输出正确性
    assert_eq!(
        public_io.output.len(),
        4,
        "Fibonacci 输出应为 4 字节（u32）"
    );
    let got = u32::from_le_bytes(public_io.output[..4].try_into().expect("输出至少 4 字节"));
    let expected = fibonacci_expected(n);
    assert_eq!(
        got, expected,
        "Fibonacci({n}) 输出不符: got={got}, expected={expected}"
    );

    // 4. proof 大小检查（MVP 阶段 CycleFold 未实现，放宽到 MAX_PROOF_TOTAL_SIZE）
    assert!(
        proof_bytes.len() <= MAX_PROOF_TOTAL_SIZE,
        "proof 超 M2-002 总长度上限: {} > {MAX_PROOF_TOTAL_SIZE}",
        proof_bytes.len()
    );
}

#[test]
fn test_fibonacci_n0() {
    run_fibonacci_e2e(0);
}

#[test]
fn test_fibonacci_n1() {
    run_fibonacci_e2e(1);
}

#[test]
fn test_fibonacci_n5() {
    run_fibonacci_e2e(5);
}

#[test]
fn test_fibonacci_n10() {
    run_fibonacci_e2e(10);
}

#[test]
fn test_fibonacci_n50() {
    // N=50 → 6*50+9=309 步，batch_size=3 → 103 batches
    run_fibonacci_e2e(50);
}

#[test]
fn test_fibonacci_n100() {
    // N=100 → 6*100+9=609 步，batch_size=3 → 203 batches
    run_fibonacci_e2e(100);
}

#[test]
fn test_fibonacci_proof_size_bound() {
    // 单独检查 proof 大小，便于调试
    let elf = build_fibonacci_elf(20);
    let (proof_bytes, _public_io) = prove(&elf, &[], &fib_config()).expect("prove 应成功");
    println!(
        "Fibonacci(20) proof size = {} bytes (limit = {})",
        proof_bytes.len(),
        MAX_PROOF_TOTAL_SIZE
    );
    assert!(proof_bytes.len() <= MAX_PROOF_TOTAL_SIZE);
}
