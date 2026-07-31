//! E2E 测试 — crypto 模块（Mental Poker 协议方法）prove + verify + soundness。
//!
//! 覆盖 5 个 crypto 协议方法：
//! - `join_and_shuffle`
//! - `leave_with_proof`
//! - `submit_shuffle_v2`
//! - `submit_player_reveal_tokens`
//! - `submit_reconstruct_deck`
//!
//! 阶段 4 PoC：crypto AIR 只验证协议级状态变更（seat_index / commitment / phase
//! 一致性），完整密码学约束（DLEq / ZKShuffle / RevealToken / Reconstruct proof）
//! 留待阶段 5 嵌入 Verifier AIR。
//!
//! 验证流程：
//! 1. 构造 method AIR 的 active row + padding row
//! 2. 调用 `gen_method_trace` 生成 trace
//! 3. 调用 `prove_method` 生成 Stwo proof
//! 4. 调用 `verify_method` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败

use stwo::core::fields::m31::M31;

use poker_texas_air::airs::common::ZERO;
use poker_texas_air::airs::crypto::join_and_shuffle::{
    JoinAndShuffleAir, JoinAndShuffleInput, JoinAndShuffleRow,
};
use poker_texas_air::airs::crypto::leave_with_proof::{
    LeaveWithProofAir, LeaveWithProofInput, LeaveWithProofRow,
};
use poker_texas_air::airs::crypto::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use poker_texas_air::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use poker_texas_air::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::prover::prove_method;
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method;

/// 构造 4 个 state_root limb（测试用，全 0）。
fn zero_root() -> [M31; 4] {
    // 与 synthetic_placeholder 的 pre_state_root 一致（AIR statement 绑定）
    poker_texas_air::public_inputs::TexasPublicInputs::synthetic_air_roots(
        poker_texas_air::method_kind::MethodKind::Fold,
    )
    .0
}

/// 构造 4 个 state_root limb（测试用，全 1）。
fn one_root() -> [M31; 4] {
    // 与 synthetic_placeholder 的 post_state_root 一致（AIR statement 绑定）
    poker_texas_air::public_inputs::TexasPublicInputs::synthetic_air_roots(
        poker_texas_air::method_kind::MethodKind::Fold,
    )
    .1
}

// ========== join_and_shuffle AIR ==========

/// E2E: join_and_shuffle → trace → prove → verify（happy path）。
#[test]
fn test_e2e_join_and_shuffle_prove_verify() {
    let input = JoinAndShuffleInput {
        seat_index: 0,
        new_deck_commitment: 0xABCD_1234,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = JoinAndShuffleRow::active(
        &input,
        zero_root(),
        one_root(),
        42, // table_id
        1,  // hand_id
        1,  // call_seq
        0,  // pre_version
        1,  // post_version
        0,  // pre_completed_count（占位）
        1,  // post_completed_count
    );
    let trace = gen_method_trace(
        JoinAndShuffleAir::num_columns(),
        &row.to_vec(),
        &JoinAndShuffleRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = JoinAndShuffleAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        JoinAndShuffleAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinAndShuffle, 42, 1, 1),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 join_and_shuffle 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_join_and_shuffle_tampered_seat() {
    let input = JoinAndShuffleInput {
        seat_index: 0,
        new_deck_commitment: 0xABCD_1234,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = JoinAndShuffleRow::active(&input, zero_root(), one_root(), 42, 1, 1, 0, 1, 0, 1);
    let trace = gen_method_trace(
        JoinAndShuffleAir::num_columns(),
        &row.to_vec(),
        &JoinAndShuffleRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = JoinAndShuffleAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        JoinAndShuffleAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinAndShuffle, 42, 1, 1),
    )
    .expect("prove 失败");

    // 篡改 seat_index：trace 中是 0，AIR 声明 5
    proof.air = JoinAndShuffleAir {
        input: JoinAndShuffleInput {
            seat_index: 5, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 seat_index 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 join_and_shuffle 的 `new_deck_commitment` 公开输入后，verify 应失败。
#[test]
fn test_soundness_join_and_shuffle_tampered_commitment() {
    let input = JoinAndShuffleInput {
        seat_index: 0,
        new_deck_commitment: 0xABCD_1234,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = JoinAndShuffleRow::active(&input, zero_root(), one_root(), 42, 1, 1, 0, 1, 0, 1);
    let trace = gen_method_trace(
        JoinAndShuffleAir::num_columns(),
        &row.to_vec(),
        &JoinAndShuffleRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = JoinAndShuffleAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        JoinAndShuffleAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinAndShuffle, 42, 1, 1),
    )
    .expect("prove 失败");

    // 篡改 new_deck_commitment：trace 中是 0xABCD_1234，AIR 声明 0xFFFF_FFFF
    proof.air = JoinAndShuffleAir {
        input: JoinAndShuffleInput {
            new_deck_commitment: 0xFFFF_FFFF, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 new_deck_commitment 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== leave_with_proof AIR ==========

/// E2E: leave_with_proof → trace → prove → verify（happy path）。
#[test]
fn test_e2e_leave_with_proof_prove_verify() {
    let input = LeaveWithProofInput {
        seat_index: 1,
        leave_kind: 0,    // LeaveKind::Normal
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = LeaveWithProofRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        2,
        0,
        1,
        0, // post_completed_count（玩家离场后）
    );
    let trace = gen_method_trace(
        LeaveWithProofAir::num_columns(),
        &row.to_vec(),
        &LeaveWithProofRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = LeaveWithProofAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        LeaveWithProofAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::LeaveWithProof, 42, 1, 2),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 leave_with_proof 的 `leave_kind` 公开输入后，verify 应失败。
#[test]
fn test_soundness_leave_with_proof_tampered_kind() {
    let input = LeaveWithProofInput {
        seat_index: 1,
        leave_kind: 0,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = LeaveWithProofRow::active(&input, zero_root(), one_root(), 42, 1, 2, 0, 1, 0);
    let trace = gen_method_trace(
        LeaveWithProofAir::num_columns(),
        &row.to_vec(),
        &LeaveWithProofRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = LeaveWithProofAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        LeaveWithProofAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::LeaveWithProof, 42, 1, 2),
    )
    .expect("prove 失败");

    // 篡改 leave_kind：trace 中是 0，AIR 声明 2
    proof.air = LeaveWithProofAir {
        input: LeaveWithProofInput {
            leave_kind: 2, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 leave_kind 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== submit_shuffle_v2 AIR ==========

/// E2E: submit_shuffle_v2 → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_shuffle_v2_prove_verify() {
    let input = SubmitShuffleV2Input {
        seat_index: 2,
        new_deck_commitment: 0xDEAD_BEEF,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = SubmitShuffleV2Row::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        3,
        0,
        1,
        2, // post_completed_count
    );
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitShuffleV2Air::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitShuffleV2, 42, 1, 3),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 submit_shuffle_v2 的 `new_deck_commitment` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_shuffle_v2_tampered_commitment() {
    let input = SubmitShuffleV2Input {
        seat_index: 2,
        new_deck_commitment: 0xDEAD_BEEF,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
    };
    let row = SubmitShuffleV2Row::active(&input, zero_root(), one_root(), 42, 1, 3, 0, 1, 2);
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitShuffleV2Air::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitShuffleV2, 42, 1, 3),
    )
    .expect("prove 失败");

    // 篡改 new_deck_commitment：trace 中是 0xDEAD_BEEF，AIR 声明 0x1234_5678
    proof.air = SubmitShuffleV2Air {
        input: SubmitShuffleV2Input {
            new_deck_commitment: 0x1234_5678, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 new_deck_commitment 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== submit_player_reveal_tokens AIR ==========

/// E2E: submit_player_reveal_tokens → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_player_reveal_tokens_prove_verify() {
    let input = SubmitPlayerRevealTokensInput {
        seat_index: 0,
        reveal_phase: 1, // RevealPhase::HoleCards
    };
    let row = SubmitPlayerRevealTokensRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        4,
        0,
        1,
        1, // post_revealed_count
    );
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitPlayerRevealTokensAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 4),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 submit_player_reveal_tokens 的 `reveal_phase` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_player_reveal_tokens_tampered_phase() {
    let input = SubmitPlayerRevealTokensInput {
        seat_index: 0,
        reveal_phase: 1,
    };
    let row =
        SubmitPlayerRevealTokensRow::active(&input, zero_root(), one_root(), 42, 1, 4, 0, 1, 1);
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitPlayerRevealTokensAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 4),
    )
    .expect("prove 失败");

    // 篡改 reveal_phase：trace 中是 1，AIR 声明 3
    proof.air = SubmitPlayerRevealTokensAir {
        input: SubmitPlayerRevealTokensInput {
            reveal_phase: 3, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 reveal_phase 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== submit_reconstruct_deck AIR ==========

/// E2E: submit_reconstruct_deck → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_reconstruct_deck_prove_verify() {
    let input = SubmitReconstructDeckInput {
        seat_index: 3,
        reconstruct_phase: 1, // ReconstructPhase::Started
    };
    let row = SubmitReconstructDeckRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        5,
        0,
        1,
        1, // post_submitted_count
    );
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitReconstructDeckAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitReconstructDeck, 42, 1, 5),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 submit_reconstruct_deck 的 `reconstruct_phase` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_reconstruct_deck_tampered_phase() {
    let input = SubmitReconstructDeckInput {
        seat_index: 3,
        reconstruct_phase: 1,
    };
    let row = SubmitReconstructDeckRow::active(&input, zero_root(), one_root(), 42, 1, 5, 0, 1, 1);
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitReconstructDeckAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitReconstructDeck, 42, 1, 5),
    )
    .expect("prove 失败");

    // 篡改 reconstruct_phase：trace 中是 1，AIR 声明 0
    proof.air = SubmitReconstructDeckAir {
        input: SubmitReconstructDeckInput {
            reconstruct_phase: 0, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 reconstruct_phase 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== 列数一致性 ==========

/// 单元测试：所有 crypto AIR 的列数与常量声明一致。
#[test]
fn test_crypto_air_column_consistency() {
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    use poker_texas_air::airs::crypto::{
        join_and_shuffle, leave_with_proof, submit_player_reveal_tokens, submit_reconstruct_deck,
        submit_shuffle_v2,
    };

    // join_and_shuffle: 通用 + 16 业务（含 Gap 6 shuffle_phase + q witness）= 53
    assert_eq!(join_and_shuffle::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 16);
    assert_eq!(
        JoinAndShuffleAir::num_columns(),
        join_and_shuffle::cols::NUM_COLUMNS
    );

    // leave_with_proof: 通用 + 5 业务（含 Gap 6 shuffle_phase + q witness）= 42
    assert_eq!(leave_with_proof::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 5);
    assert_eq!(
        LeaveWithProofAir::num_columns(),
        leave_with_proof::cols::NUM_COLUMNS
    );

    // submit_shuffle_v2: 通用 + 8 业务（含 Gap 6 shuffle_phase + q witness）= 45
    assert_eq!(submit_shuffle_v2::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 8);
    assert_eq!(
        SubmitShuffleV2Air::num_columns(),
        submit_shuffle_v2::cols::NUM_COLUMNS
    );

    // submit_player_reveal_tokens: 通用 + 5 业务 = 42（含 Gap 7 witness q1/q2）
    assert_eq!(
        submit_player_reveal_tokens::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 5
    );
    assert_eq!(
        SubmitPlayerRevealTokensAir::num_columns(),
        submit_player_reveal_tokens::cols::NUM_COLUMNS
    );

    // submit_reconstruct_deck: 通用 + 3 业务 = 40
    assert_eq!(
        submit_reconstruct_deck::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 3
    );
    assert_eq!(
        SubmitReconstructDeckAir::num_columns(),
        submit_reconstruct_deck::cols::NUM_COLUMNS
    );
}

/// 单元测试：MethodKind 的 crypto 档位分类正确。
#[test]
fn test_crypto_method_kinds() {
    use poker_texas_air::method_kind::{MethodKind, MethodTier};

    assert_eq!(MethodKind::JoinAndShuffle.tier(), MethodTier::Crypto);
    assert_eq!(MethodKind::LeaveWithProof.tier(), MethodTier::Crypto);
    assert_eq!(MethodKind::SubmitShuffleV2.tier(), MethodTier::Crypto);
    assert_eq!(
        MethodKind::SubmitPlayerRevealTokens.tier(),
        MethodTier::Crypto
    );
    assert_eq!(MethodKind::SubmitReconstructDeck.tier(), MethodTier::Crypto);
}
