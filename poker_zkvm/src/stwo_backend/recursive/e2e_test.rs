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
//! │  6. 验证 L2 proof 大小处于 STWO recursive proof 的合理范围           │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

use super::public_inputs::RecursivePublicInputs;
use super::recursion_prover::{RecursionProvingError, prove_recursive_with_fri};
use super::recursion_verifier::{RecursionVerificationError, verify_recursive_with_fri};
use super::trace_gen::compute_fri_trace_log_size;
use super::verifier_program::build_cpu_recursive_public_inputs;
use crate::stwo_backend::prover::prove_cpu_trace;
use crate::stwo_backend::trace_native::TraceBuilder;
use starknet_ff::FieldElement as FieldElement252;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

/// 生成真实 L1 proof。
fn make_l1_proof(log_size: u32) -> StarkProof<Poseidon252MerkleHasher> {
    let mut builder = TraceBuilder::new(log_size);
    builder.fill_padding_to_full();
    let trace = builder.finalize();
    prove_cpu_trace(&trace).expect("L1 prove 应成功")
}

/// 从 L1 proof 创建测试用 RecursivePublicInputs。
///
/// 注意：`max_log_degree_bound` 必须等于 L1 proof 的 trace `log_size`。
/// Stwo 的 `prove_ex` 计算 `max_log_degree_bound = lifting_log_size - log_blowup_factor`，
/// 其中 `lifting_log_size = split_composition_log_size = log_size + blowup`（默认 config），
/// 因此 `max_log_degree_bound = log_size`。
fn make_recursive_public_inputs(
    l1_proof: &StarkProof<Poseidon252MerkleHasher>,
    log_size: u32,
) -> RecursivePublicInputs {
    build_cpu_recursive_public_inputs(l1_proof, log_size)
        .expect("固定 CpuV1 verifier statement 构造应成功")
}

#[test]
#[ignore = "expensive recursive STWO end-to-end test"]
fn test_e2e_l1_to_l2_prove_verify() {
    let log_size = 10;

    println!("=== Phase 6 E2E 集成测试 ===");
    println!("步骤 1: 生成 L1 trace（log_size={log_size}）");
    let l1_proof = make_l1_proof(log_size);
    println!(
        "步骤 2: L1 proof 生成完成，commitments={}",
        l1_proof.0.commitments.len()
    );

    println!("步骤 3: 提取 public_inputs");
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    let fri_log_size = compute_fri_trace_log_size(&public_inputs.fri_last_layer_poly);
    println!("  - FRI trace log_size={fri_log_size}");

    println!("步骤 4: 生成 L2 proof（OODS + FRI Verifier AIR）");
    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs).expect("L2 prove 应成功");
    println!("  - L2 proof commitments={}", l2_proof.0.commitments.len());

    println!("步骤 5: 验证 L2 proof");
    let verify_result = verify_recursive_with_fri(&l2_proof, &public_inputs);
    assert!(
        verify_result.is_ok(),
        "L2 verify 应成功: {:?}",
        verify_result.err()
    );
    println!("  - ✅ L2 verify 通过");

    println!("步骤 6: 验证 L2 proof 大小");
    let proof_bytes = bincode::serialize(&l2_proof.0).expect("序列化 L2 proof 应成功");
    let proof_kb = proof_bytes.len() as f64 / 1024.0;
    println!("  - L2 proof 大小: {proof_kb:.2} KB");
    assert!(!proof_bytes.is_empty(), "L2 proof 序列化结果不应为空");
    assert!(
        proof_bytes.len() < 512 * 1024,
        "recursive STWO proof 应小于 512KiB，实际 {proof_kb:.2} KiB"
    );
    println!("  - ✅ L2 proof 大小符合要求");

    println!("=== Phase 6 E2E 集成测试通过 ===");
}

#[test]
#[ignore = "expensive recursive STWO proof-size stability test"]
fn test_e2e_l2_proof_size_with_different_l1_sizes() {
    let log_sizes = [8, 10, 12];
    let mut proof_sizes = Vec::with_capacity(log_sizes.len());

    for &log_size in &log_sizes {
        println!("=== 测试 L1 log_size={log_size} ===");
        let l1_proof = make_l1_proof(log_size);
        let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

        let l2_proof =
            prove_recursive_with_fri(&l1_proof, &public_inputs).expect("L2 prove 应成功");

        let proof_bytes = bincode::serialize(&l2_proof.0).expect("序列化 L2 proof 应成功");
        let proof_kb = proof_bytes.len() as f64 / 1024.0;
        println!("  - L2 proof 大小: {proof_kb:.2} KB");

        assert!(!proof_bytes.is_empty(), "L2 proof 序列化结果不应为空");
        assert!(
            proof_bytes.len() < 512 * 1024,
            "recursive STWO proof 应小于 512KiB，实际 {proof_kb:.2} KiB"
        );
        proof_sizes.push(proof_bytes.len());
    }

    let min_size = *proof_sizes.iter().min().expect("至少应生成一个 proof");
    let max_size = *proof_sizes.iter().max().expect("至少应生成一个 proof");
    assert!(
        max_size - min_size < 64 * 1024,
        "固定 recursive verifier 的 proof 大小不应随 L1 trace 大幅增长: min={min_size}, max={max_size}"
    );
}

#[test]
fn test_e2e_l1_proof_tampering_detected() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let mut public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    public_inputs.composition_oods_eval =
        public_inputs.composition_oods_eval + SecureField::from(1u32);

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(result.is_err(), "篡改 public_inputs 应导致 L2 prove 失败");
    println!("✅ 篡改 L1 proof public_inputs 被检测到");
}

#[test]
#[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
fn test_e2e_l2_proof_tampering_detected() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs).expect("L2 prove 应成功");

    let mut tampered_inputs = public_inputs.clone();
    tampered_inputs.oods_point = CirclePoint {
        x: SecureField::from_u32_unchecked(2, 0, 0, 0),
        y: SecureField::from_u32_unchecked(0, 2, 0, 0),
    };

    let result = verify_recursive_with_fri(&l2_proof, &tampered_inputs);
    assert!(result.is_err(), "篡改 L2 public_inputs 应导致 verify 失败");
    println!("✅ 篡改 L2 public_inputs 被检测到");
}

// ===========================================================================
// P05-R gap #1 soundness 回归
// ===========================================================================

/// 空 `l1_commitments` 必须被 prover 入口显式拒绝（`L1CommitmentsMissing`）。
///
/// 此前 PoC 调用方可传空 commitments，使 Merkle Path AIR 的 final-root 检查绑定到
/// 零 root，L2 proof 在不触及任何 L1 Merkle decommitment 的情况下通过。
#[test]
fn recursive_prover_rejects_empty_commitments() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let mut public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    public_inputs.l1_commitments.clear();

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(
        matches!(result, Err(RecursionProvingError::L1CommitmentsMissing)),
        "空 l1_commitments 应被拒绝，实际: {result:?}"
    );
    println!("✅ 空 l1_commitments 被 prover 拒绝");
}

/// 空 `query_positions` 必须被 prover 入口显式拒绝（`QueryPositionsMissing`）。
#[test]
fn recursive_prover_rejects_empty_query_positions() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let mut public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    public_inputs.query_positions.clear();

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(
        matches!(result, Err(RecursionProvingError::QueryPositionsMissing)),
        "空 query_positions 应被拒绝，实际: {result:?}"
    );
    println!("✅ 空 query_positions 被 prover 拒绝");
}

/// `log_size == 0` 必须被 prover 入口显式拒绝（`InvalidLogSize`）。
#[test]
fn recursive_prover_rejects_zero_log_size() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let mut public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    public_inputs.log_size = 0;

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    assert!(
        matches!(result, Err(RecursionProvingError::InvalidLogSize)),
        "log_size == 0 应被拒绝，实际: {result:?}"
    );
    println!("✅ log_size == 0 被 prover 拒绝");
}

/// 非空真实输入路径仍闭合：prove → verify 全通过，证明 gap #1 守卫未误伤合法路径。
#[test]
#[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
fn recursive_sound_e2e_nonempty_inputs() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    // 守卫的前置条件：真实 L1 proof 提取出非空 commitments/query。
    assert!(!public_inputs.l1_commitments.is_empty());
    assert!(!public_inputs.query_positions.is_empty());
    assert_ne!(public_inputs.log_size, 0);

    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs)
        .expect("非空真实输入的 L2 prove 应成功");
    verify_recursive_with_fri(&l2_proof, &public_inputs).expect("非空真实输入的 L2 verify 应成功");
    println!("✅ 非空真实输入 prove→verify 全程闭合");
}

/// Feature gate 回归：默认测试构建保持 fail-closed；显式启用
/// `recursive-prover` 后，真实 L1 proof 必须能够完成递归证明。
#[test]
fn gap3b_incomplete_merkle_air_is_explicitly_disabled() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);

    let result = prove_recursive_with_fri(&l1_proof, &public_inputs);
    if cfg!(feature = "recursive-prover") {
        assert!(
            result.is_ok(),
            "显式启用 recursive-prover 后应完成证明，实际: {result:?}"
        );
    } else {
        assert!(
            matches!(
                result,
                Err(RecursionProvingError::IncompleteMerkleVerifierAir)
            ),
            "默认构建应由不完整 AIR gate 显式 fail-closed，实际: {result:?}"
        );
    }
}

/// 篡改 `l1_commitments[0]`（声称的 Merkle root）必须导致 verify 失败：
/// 证明 transcript binding 把公开承诺绑定到 L2 Fiat-Shamir transcript，
/// root 被改后 channel 状态与 proof 不一致。
#[test]
#[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
fn tampered_commitment_fails_verify() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs).expect("L2 prove 应成功");

    let mut tampered = public_inputs.clone();
    // 改掉第一个 commitment（即 PoC 假设的 Merkle root）。
    tampered.l1_commitments[0] = tampered.l1_commitments[0] + FieldElement252::from(1u32);

    let result = verify_recursive_with_fri(&l2_proof, &tampered);
    assert!(
        result.is_err(),
        "篡改 l1_commitments[0] 应导致 verify 失败，实际: {result:?}"
    );
    println!("✅ 篡改 l1_commitments[0] 被 verify 检测到");
}

/// 空-input L2 proof 必须被 verifier 侧对称守卫拒绝（`L1CommitmentsMissing`），
/// 即便有人手工伪造了一个 Stwo-verify 能通过的空 proof。
#[test]
#[ignore = "P05-R gap #3-B: _with_fri 显式 fail-closed"]
fn recursive_verifier_rejects_empty_commitments() {
    let log_size = 10;
    let l1_proof = make_l1_proof(log_size);
    let public_inputs = make_recursive_public_inputs(&l1_proof, log_size);
    let l2_proof = prove_recursive_with_fri(&l1_proof, &public_inputs).expect("L2 prove 应成功");

    let mut tampered = public_inputs.clone();
    tampered.l1_commitments.clear();

    let result = verify_recursive_with_fri(&l2_proof, &tampered);
    assert!(
        matches!(
            result,
            Err(RecursionVerificationError::L1CommitmentsMissing)
        ),
        "空 l1_commitments 应被 verifier 拒绝，实际: {result:?}"
    );
    println!("✅ 空 l1_commitments 被 verifier 拒绝");
}
