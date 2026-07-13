//! Phase 12 端到端集成测试 — SHA-256 哈希链电路。
//!
//! 测试流程：构建 ELF → prove() → verify_production() → 验证输出 → proof 大小检查
//!
//! # 电路说明
//!
//! 读取 32 字节输入，迭代 N 次 SHA-256（in-place），最后通过 commit_output 输出 32 字节哈希。

mod common;

use common::build_sha256_chain_elf;
use poker_zkvm::prover::{MAX_PROOF_TOTAL_SIZE, ProverConfig, default_ccs_registry, prove};
use poker_zkvm::verifier::verify_production;
use sha2::{Digest, Sha256};

/// 构造 SHA-256 哈希链 prove 配置。
fn sha_config() -> ProverConfig {
    ProverConfig {
        proof_size_limit: MAX_PROOF_TOTAL_SIZE,
        ..Default::default()
    }
}

/// 主机端参考实现：迭代 N 次 SHA-256。
fn sha256_chain_expected(input: &[u8], iterations: u32) -> Vec<u8> {
    assert_eq!(input.len(), 32, "输入须为 32 字节");
    let mut state = [0u8; 32];
    state.copy_from_slice(input);
    for _ in 0..iterations {
        let mut hasher = Sha256::new();
        hasher.update(state);
        state = hasher.finalize().into();
    }
    state.to_vec()
}

/// 验证 SHA-256 哈希链的完整 prove→verify 流程。
fn run_sha256_chain_e2e(iterations: u32, input: &[u8]) {
    assert_eq!(input.len(), 32, "测试输入须为 32 字节");
    let elf = build_sha256_chain_elf(iterations);
    let config = sha_config();

    // 1. prove
    let (proof_bytes, public_io) =
        prove(&elf, input, &config).unwrap_or_else(|e| panic!("prove 失败: {e:?}"));

    // 2. verify
    let ccs_registry = default_ccs_registry();
    let ok = verify_production(&proof_bytes, &public_io, &ccs_registry)
        .unwrap_or_else(|e| panic!("verify_production 错误: {e:?}"));
    assert!(ok, "verify_production 应返回 true");

    // 3. 输出正确性
    assert_eq!(public_io.output.len(), 32, "SHA-256 输出应为 32 字节");
    let expected = sha256_chain_expected(input, iterations);
    assert_eq!(
        public_io.output, expected,
        "SHA-256 chain({iterations}) 输出不符"
    );

    // 4. proof 大小检查（MVP 阶段 CycleFold 未实现，放宽到 MAX_PROOF_TOTAL_SIZE）
    assert!(
        proof_bytes.len() <= MAX_PROOF_TOTAL_SIZE,
        "proof 超 M2-002 总长度上限: {} > {MAX_PROOF_TOTAL_SIZE}",
        proof_bytes.len()
    );
}

#[test]
fn test_sha256_chain_n1_zeros() {
    // N=1 → 7*1+11=18 步，batch_size=256 → 1 batch
    let input = [0u8; 32];
    run_sha256_chain_e2e(1, &input);
}

#[test]
fn test_sha256_chain_n5_zeros() {
    // N=5 → 7*5+11=46 步
    let input = [0u8; 32];
    run_sha256_chain_e2e(5, &input);
}

#[test]
fn test_sha256_chain_n10_zeros() {
    // N=10 → 7*10+11=81 步，batch_size=256 → 1 batch
    let input = [0u8; 32];
    run_sha256_chain_e2e(10, &input);
}

#[test]
fn test_sha256_chain_n1_custom_input() {
    // 自定义输入（SHA-256("zchain") 衍生）
    let mut input = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(b"zchain");
    let h = hasher.finalize();
    input[..h.len()].copy_from_slice(&h);
    run_sha256_chain_e2e(1, &input);
}

#[test]
fn test_sha256_chain_n3_custom_input() {
    let mut input = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(b"phase12-e2e");
    let h = hasher.finalize();
    input[..h.len()].copy_from_slice(&h);
    run_sha256_chain_e2e(3, &input);
}
