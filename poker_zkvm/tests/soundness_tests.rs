//! Phase 12 Soundness 负向测试 — 验证 ZKVM 安全边界。
//!
//! 6 项测试覆盖：
//! 1. 恶意 ELF — `validate_elf` 拒绝篡改的 ELF 字节
//! 2. Proof 字节篡改 — `verify_production` 拒绝篡改的 proof
//! 3. Multiplicity 伪造 — `LogUpProof::verify` 拒绝错误的 multiplicity
//! 4. Trace 篡改 — `Ccs::satisfied_by` 拒绝不满足约束的 witness
//! 5. 非白名单 slot — `execute_elf` 拒绝访问非法 slot
//! 6. Witness 篡改（folded instance）— `verify_production` 拒绝篡改的 folded instance

mod common;

use common::build_minimal_valid_elf;
use poker_zkvm::ccs::{Ccs, Fr, SparseMatrix};
use poker_zkvm::compiler::elf_validator::validate_elf;
use poker_zkvm::constraints::lookup::{LogUpCommitments, LogUpProof};
use poker_zkvm::error::ZkvmError;
use poker_zkvm::field::ZkvmField;
use poker_zkvm::isa::executor::execute_elf;
use poker_zkvm::prover::{
    default_ccs_whitelist, deserialize_proof, generate_test_proof, serialize_proof,
};
use poker_zkvm::test_helpers::{addi, build_elf32, ecall, encode_text};
use poker_zkvm::verifier::verify_production;

// ===========================================================================
// 1. 恶意 ELF — validate_elf 拒绝篡改的 ELF
// ===========================================================================

#[test]
fn test_soundness_malicious_elf_tampered_magic() {
    let mut elf = build_minimal_valid_elf();
    // 篡改 ELF magic
    elf[0] = 0x00;
    let result = validate_elf(&elf);
    assert!(result.is_err(), "篡改 magic 的 ELF 应被拒绝");
}

#[test]
fn test_soundness_malicious_elf_truncated() {
    let elf = build_minimal_valid_elf();
    // 截断 ELF（仅保留 10 字节，不足以包含完整 header）
    let truncated = &elf[..10];
    let result = validate_elf(truncated);
    assert!(result.is_err(), "截断的 ELF 应被拒绝");
}

#[test]
fn test_soundness_malicious_elf_tampered_machine_type() {
    let mut elf = build_minimal_valid_elf();
    // 篡改 e_machine（offset 18-19），从 EM_RISCV (0xF3) 改为 EM_386 (0x03)
    elf[18] = 0x03;
    elf[19] = 0x00;
    let result = validate_elf(&elf);
    assert!(result.is_err(), "篡改 e_machine 的 ELF 应被拒绝");
}

// ===========================================================================
// 2. Proof 字节篡改 — verify_production 拒绝篡改的 proof
// ===========================================================================

#[test]
fn test_soundness_tampered_proof_magic_fails() {
    let (mut proof_bytes, public_io) = generate_test_proof();
    proof_bytes[0] = b'X'; // 篡改 magic
    let ccs_whitelist = default_ccs_whitelist();
    let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
    assert!(
        matches!(result, Err(ZkvmError::InvalidZkProofFormat(ref m)) if m.contains("magic")),
        "篡改 magic 应返回 InvalidZkProofFormat，got: {result:?}"
    );
}

#[test]
fn test_soundness_tampered_proof_byte_flip_fails() {
    let (mut proof_bytes, public_io) = generate_test_proof();
    // 翻转最后一个字节（不影响 header，但破坏 payload）
    let last = proof_bytes.len() - 1;
    proof_bytes[last] ^= 0xFF;
    let ccs_whitelist = default_ccs_whitelist();
    let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
    assert!(
        result.is_err(),
        "篡改 proof payload 应导致验证失败，got: {result:?}"
    );
}

// ===========================================================================
// 3. Multiplicity 伪造 — LogUpProof::verify 拒绝错误的 multiplicity
// ===========================================================================

#[test]
fn test_soundness_multiplicity_forgery_detected() {
    // 构造合法 LogUp proof：table=[1,2,3], witness=[1,2], multiplicity=[1,1,0]
    let table = vec![
        Fr::from_u32_with_wrap(1),
        Fr::from_u32_with_wrap(2),
        Fr::from_u32_with_wrap(3),
    ];
    let witness = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
    let multiplicity = vec![
        Fr::from_u32_with_wrap(1),
        Fr::from_u32_with_wrap(1),
        Fr::from_u32_with_wrap(0),
    ];

    let (proof, commits) = LogUpProof::create(table.clone(), witness.clone(), multiplicity.clone())
        .expect("合法 LogUp proof 应创建成功");
    assert!(
        proof.verify(&commits).unwrap_or(false),
        "合法 proof 应通过验证"
    );

    // 伪造 multiplicity：将 m[0] 从 1 改为 2（多算一次）
    let forged_multiplicity = vec![
        Fr::from_u32_with_wrap(2),
        Fr::from_u32_with_wrap(1),
        Fr::from_u32_with_wrap(0),
    ];
    let (forged_proof, forged_commits) = LogUpProof::create(table, witness, forged_multiplicity)
        .expect("伪造 proof 应能创建（create 不校验等式）");

    // verify 应返回 false（等式不成立）
    let result = forged_proof.verify(&forged_commits);
    assert!(result.is_ok(), "verify 不应返回 Err，got: {result:?}");
    assert!(
        !result.unwrap(),
        "伪造 multiplicity 的 proof 应验证失败（等式不成立）"
    );
}

#[test]
fn test_soundness_logup_tampered_commitment_detected() {
    // 合法 proof
    let table = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(2)];
    let witness = vec![Fr::from_u32_with_wrap(1)];
    let multiplicity = vec![Fr::from_u32_with_wrap(1), Fr::from_u32_with_wrap(0)];

    let (proof, commits) = LogUpProof::create(table, witness, multiplicity).expect("创建应成功");

    // 篡改承诺：将 c_t 改为不同的值
    let tampered_commits = LogUpCommitments {
        c_t: Fr::from_u32_with_wrap(999),
        c_f: commits.c_f,
        c_m: commits.c_m,
    };

    // verify 应返回 false（承诺不匹配 → β 不匹配 或 承诺校验失败）
    let result = proof.verify(&tampered_commits);
    assert!(result.is_ok(), "verify 不应返回 Err");
    assert!(!result.unwrap(), "篡改承诺的 proof 应验证失败");
}

// ===========================================================================
// 4. Trace 篡改 — Ccs::satisfied_by 拒绝不满足约束的 witness
// ===========================================================================

#[test]
fn test_soundness_trace_tampering_detected() {
    // 构造简单 CCS：约束 z[1] - z[2] = 0（即 z[1] == z[2]）
    let mut m_a = SparseMatrix::new(1, 3);
    m_a.add_entry(0, 1, Fr::one()).unwrap();
    let mut m_b = SparseMatrix::new(1, 3);
    m_b.add_entry(0, 2, Fr::one()).unwrap();

    let ccs = Ccs::new(
        3,
        vec![m_a, m_b],
        vec![vec![0], vec![1]],
        vec![Fr::one(), Fr::zero().sub(&Fr::one())], // c_0=1, c_1=-1
    )
    .expect("CCS 构造应成功");

    // 合法 witness：z = [1, 5, 5] → 5 - 5 = 0 ✓
    let valid_witness = vec![
        Fr::one(),
        Fr::from_u32_with_wrap(5),
        Fr::from_u32_with_wrap(5),
    ];
    assert!(
        ccs.satisfied_by(&valid_witness).unwrap_or(false),
        "合法 witness 应满足约束"
    );

    // 篡改 witness：z = [1, 5, 6] → 5 - 6 = -1 ≠ 0 ✗
    let tampered_witness = vec![
        Fr::one(),
        Fr::from_u32_with_wrap(5),
        Fr::from_u32_with_wrap(6),
    ];
    let result = ccs.satisfied_by(&tampered_witness);
    assert!(result.is_ok(), "satisfied_by 不应返回 Err");
    assert!(!result.unwrap(), "篡改 witness 应不满足约束");
}

#[test]
fn test_soundness_ccs_wrong_witness_length() {
    let mut m = SparseMatrix::new(1, 3);
    m.add_entry(0, 1, Fr::one()).unwrap();
    let ccs = Ccs::new(3, vec![m], vec![vec![0]], vec![Fr::one()]).expect("CCS 构造应成功");

    // 长度不匹配的 witness
    let wrong_len_witness = vec![Fr::one(), Fr::one()];
    let result = ccs.satisfied_by(&wrong_len_witness);
    assert!(
        matches!(result, Err(ZkvmError::Other(ref m)) if m.contains("num_vars")),
        "长度不匹配应返回 Other 错误，got: {result:?}"
    );
}

// ===========================================================================
// 5. 非白名单 slot — execute_elf 拒绝访问非法 slot
// ===========================================================================

#[test]
fn test_soundness_invalid_slot_rejected() {
    // 构造 ELF：调用 read_state(slot=0x06) — 非白名单
    // read_state ABI: a7=0x0A, a0=slot, a1=out_ptr
    // 使用 LUI 设置 out_ptr=0x2000，ADDI 设置 slot=6
    let text = encode_text(&[
        addi(10, 0, 6),      // a0 = 6 (non-whitelisted slot)
        addi(11, 0, 0x2000), // a1 = out_ptr (simplified, low bits only)
        addi(17, 0, 0x0A),   // a7 = 0x0A (read_state)
        ecall(),             // ECALL → should fail with InvalidSlot
    ]);
    let elf = build_elf32(0x1000, 0x1000, &text);

    let result = execute_elf(&elf, &[]);
    assert!(result.is_err(), "非白名单 slot 应导致执行失败");
    let err = result.unwrap_err();
    assert!(
        matches!(err, ZkvmError::InvalidSlot(slot) if slot == 6),
        "应返回 InvalidSlot(6)，got: {err:?}"
    );
}

#[test]
fn test_soundness_whitelisted_slot_accepted() {
    // 构造 ELF：调用 read_state(slot=0x01) — 白名单内
    // 注意：StubHostState::read_slot 返回 Err，但 slot 本身通过白名单检查
    // 所以错误应是 host_state 错误而非 InvalidSlot
    let text = encode_text(&[
        addi(10, 0, 1),      // a0 = 1 (whitelisted slot: SLOT_GAME_STATE)
        addi(11, 0, 0x2000), // a1 = out_ptr
        addi(17, 0, 0x0A),   // a7 = 0x0A (read_state)
        ecall(),             // ECALL
    ]);
    let elf = build_elf32(0x1000, 0x1000, &text);

    let result = execute_elf(&elf, &[]);
    // StubHostState 返回 Other 错误（slot not available），但不是 InvalidSlot
    assert!(result.is_err(), "StubHostState 应返回错误（slot 不可用）");
    let err = result.unwrap_err();
    assert!(
        !matches!(err, ZkvmError::InvalidSlot(_)),
        "白名单 slot 不应返回 InvalidSlot，got: {err:?}"
    );
}

// ===========================================================================
// 6. Witness 篡改（proof payload）— verify_production 拒绝篡改的 payload
// ===========================================================================

#[test]
fn test_soundness_tampered_proof_payload_fails() {
    let (proof_bytes, public_io) = generate_test_proof();
    let mut proof = deserialize_proof(&proof_bytes).expect("deserialize 应成功");

    // 篡改 initial_lcccs.u_l（LCCCS 的 relaxed 标量，sumcheck 直接校验）
    if proof.initial_lcccs.u_l == Fr::zero() {
        proof.initial_lcccs.u_l = Fr::from_u32_with_wrap(1);
    } else {
        proof.initial_lcccs.u_l = Fr::zero();
    }

    let tampered = serialize_proof(&proof).expect("serialize 应成功");
    let ccs_whitelist = default_ccs_whitelist();
    let result = verify_production(&tampered, &public_io, &ccs_whitelist);
    assert!(result.is_err(), "篡改 u_l 应导致验证失败，got: {result:?}");
}

#[test]
fn test_soundness_tampered_proof_z_at_point_fails() {
    let (mut proof_bytes, public_io) = generate_test_proof();
    // 篡改 proof 最后 32 字节中的 1 字节（z_at_point 是最后 32 字节 Fr）
    let last_fr_offset = proof_bytes.len() - 16;
    proof_bytes[last_fr_offset] ^= 0xFF;
    let ccs_whitelist = default_ccs_whitelist();
    let result = verify_production(&proof_bytes, &public_io, &ccs_whitelist);
    assert!(
        result.is_err(),
        "篡改 z_at_point 区域应导致验证失败，got: {result:?}"
    );
}
