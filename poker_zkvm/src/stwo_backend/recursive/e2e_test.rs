//! # Phase 6 E2E 集成测试 — Stwo 递归证明完整流程
//!
//! 验证完整流程：L1 proof → L2 proof → L2 verify
//!
//! ## 测试结构
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    E2E 集成测试流程                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  1. 生成 L1 trace（CPU padding trace）                               │
//! │  2. 生成 L1 proof（Poseidon252MerkleChannel）                       │
//! │  3. 提取 public_inputs（composition_oods_eval + fri_last_layer_poly）│
//! │  4. 生成 L2 proof（OODS + FRI Verifier AIR）                        │
//! │  5. 验证 L2 proof（OODS + FRI Verifier AIR）                        │
//! │  6. 验证 L2 proof 大小（目标 < 20KB）                               │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

use super::public_inputs::RecursivePublicInputs;
use super::recursion_prover::{prove_recursive_with_fri, RecursiveProof};
use super::recursion_verifier::verify_recursive_with_fri;
use super::trace_gen::{extract_composition_oods_eval_from_l1, compute_fri_trace_log_size};
use crate::stwo_backend::prover::prove_cpu_trace;
use crate::stwo_backend::trace_native::TraceBuilder;
use ark_ff::Zero;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::PcsConfig;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

const TEST_OODS_POINT: CirclePoint<SecureField> = CirclePoint {
    x: SecureField::from_u32_unchecked(1, 0, 0, 0),
    y: SecureField::from_u32_unchecked(0, 1, 0, 0),
};

const TEST_MAX_LOG_DEGREE_BOUND: u32 = 10;

/// 生成真实 L1 proof。
fn make_l1_proof(log_size: u32) -> StarkProof<Poseidon252MerkleHasher> {
    let mut builder = TraceBuilder::new(log_size);
    builder.fill_padding_to_full();
    let trace = builder.finalize();
    prove_cpu_trace(&trace).expect("L1 prove 应成功")
}

/// 从 L1 proof 创建测试用 RecursivePublicInputs。
fn make_recursive_public_inputs(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    log_size: u32,
) -> RecursivePublicInputs {
    let composition_oods_eval = extract_composition_oods_eval_from_l1(
        l1_proof,
        TEST_OODS_POINT,
        TEST_MAX_LOG_DEGREE_BOUND,
    )
    .expect("提取 composition_oods_eval 应成功");
    let last_layer_poly = l1_proof.0.fri_proof.last_layer_poly.clone();
    RecursivePublicInputs::new(
        Vec::new(),
        TEST_OODS_POINT,
        composition_oods_eval,
        FieldElement252::ZERO,
        last_layer_poly,
        TEST_MAX_LOG_DEGREE_BOUND,
        PcsConfig::default(),
        Vec::new(),
        log_size,
    )
}

#[test]
fn test_e2e_l1_to_l2_prove_verify() {
    let log_size = 10;

    println!("=== Phase 6 E2E 集成测试 ===");
    println!("步骤 1: 生成 L1 trace（log_size={log_size}）");
    let l1_proof = make_l1_proof(log_size);
    println!("步骤 2: L1 proof 生成完成，commitments={}", l1_proof.0.commitments.len());

    println!("步骤 3: 提取 public_inputs");
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    let fri_log_size = compute_fri_trace_log_size(&public_inputs.fri_last_layer_poly);
    println!("  - FRI trace log_size={fri_log_size}");

    println!("步骤 4: 生成 L2 proof（OODS + FRI Verifier AIR）");
    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs)
        .expect("L2 prove 应成功");
    println!("  - L2 proof commitments={}", l2_proof.0.commitments.len());

    println!("步骤 5: 验证 L2 proof");
    let verify_result = verify_recursive_with_fri(&l2_proof, &public_inputs);
    assert!(verify_result.is_ok(), "L2 verify 应成功: {:?}", verify_result.err());
    println!("  - ✅ L2 verify 通过");

    println!("步骤 6: 验证 L2 proof 大小");
    let proof_bytes = bincode::serialize(&l2_proof.0).expect("序列化 L2 proof 应成功");
    let proof_kb = proof_bytes.len() as f64 / 1024.0;
    println!("  - L2 proof 大小: {proof_kb:.2} KB");
    assert!(
        proof_bytes.len() < 20 * 1024,
        "L2 proof 应 < 20KB，实际 {} KB",
        proof_kb
    );
    println!("  - ✅ L2 proof 大小符合要求");

    println!("=== Phase 6 E2E 集成测试通过 ===");
}

#[test]
fn test_e2e_l2_proof_size_with_different_l1_sizes() {
    let log_sizes = [8, 10, 12];

    for &log_size in &log_sizes {
        println!("=== 测试 L1 log_size={log_size} ===");
        let l1_proof = make_l1_proof(log_size);
        let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

        let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs)
            .expect("L2 prove 应成功");

        let proof_bytes = bincode::serialize(&l2_proof.0).expect("序列化 L2 proof 应成功");
        let proof_kb = proof_bytes.len() as f64 / 1024.0;
        println!("  - L2 proof 大小: {proof_kb:.2} KB");

        assert!(
            proof_bytes.len() < 20 * 1024,
            "L2 proof 应 < 20KB，实际 {} KB",
            proof_kb
        );
    }
}

#[test]
fn test_e2e_l1_proof_tampering_detected() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let mut public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    public_inputs.composition_oods_eval = public_inputs.composition_oods_eval + SecureField::from(1u32);

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(result.is_err(), "篡改 public_inputs 应导致 L2 prove 失败");
    println!("✅ 篡改 L1 proof public_inputs 被检测到");
}

#[test]
fn test_e2e_l2_proof_tampering_detected() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs)
        .expect("L2 prove 应成功");

    let mut tampered_inputs = public_inputs.clone();
    tampered_inputs.oods_point = CirclePoint {
        x: SecureField::from_u32_unchecked(2, 0, 0, 0),
        y: SecureField::from_u32_unchecked(0, 2, 0, 0),
    };

    let result = verify_recursive_with_fri(&l2_proof, &tampered_inputs);
    assert!(result.is_err(), "篡改 L2 public_inputs 应导致 verify 失败");
    println!("✅ 篡改 L2 public_inputs 被检测到");
}
