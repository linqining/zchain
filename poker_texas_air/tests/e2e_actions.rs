//! E2E 测试 — actions 模块（fold/check/call）prove + verify + soundness。
//!
//! 验证流程：
//! 1. 构造 method AIR 的 active row + padding row
//! 2. 调用 `gen_method_trace` 生成 trace
//! 3. 调用 `prove_method` 生成 Stwo proof
//! 4. 调用 `verify_method` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败

use stwo::core::fields::m31::M31;

use poker_texas_air::airs::actions::call::{CallAir, CallInput, CallRow};
use poker_texas_air::airs::actions::check::{CheckAir, CheckInput, CheckRow};
use poker_texas_air::airs::actions::fold::{FoldAir, FoldInput, FoldRow};
use poker_texas_air::airs::actions::raise::RaiseAir;
use poker_texas_air::airs::common::ZERO;
use poker_texas_air::prover::prove_method;
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method;

/// 构造 4 个 state_root limb（测试用，全 0）。
fn zero_root() -> [M31; 4] {
    [ZERO; 4]
}

/// 构造 4 个 state_root limb（测试用，全 1）。
fn one_root() -> [M31; 4] {
    [M31::from(1u32); 4]
}

// ========== fold AIR ==========

/// E2E: fold → trace → prove → verify（happy path）。
#[test]
fn test_e2e_fold_prove_verify() {
    let input = FoldInput { seat_index: 3 };
    let row = FoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,   // table_id
        0,    // hand_id
        1,    // call_seq
        0,    // pre_version
        1,    // post_version
        4,    // pre_round_state (PREFLOP)
        4,    // post_round_state (PREFLOP)
    );
    let trace = gen_method_trace(FoldAir::num_columns(), &row.to_vec(), &FoldRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = FoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, FoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Fold)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 fold 的 `seat_index` 公开输入后，verify 应失败。
///
/// 流程：用正确 AIR 生成 proof → 篡改 proof.air.input.seat_index → verify 应失败。
#[test]
fn test_soundness_fold_tampered_seat() {
    let input = FoldInput { seat_index: 3 };
    let row = FoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        1,
        0,
        1,
        4,
        4,
    );
    let trace = gen_method_trace(FoldAir::num_columns(), &row.to_vec(), &FoldRow::padding().to_vec())
        .expect("trace 生成失败");

    // 用正确的 AIR 生成 proof
    let air = FoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, FoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Fold)).expect("prove 失败");

    // 篡改 proof.air.input.seat_index：trace 中是 3，但 AIR 声明 5
    proof.air = FoldAir {
        input: FoldInput { seat_index: 5 }, // 篡改！
        ..proof.air.clone()
    };

    // verify 应失败（约束 is_active * (input_seat_index - expected_seat) ≠ 0）
    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 seat_index 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness 回归：version 不递增（Lean 审计 C2 反例）。
///
/// 构造 `pre_version=0, post_version=0`（未递增）的 fold trace，prove 应失败。
/// 验证通用层 `post_version = pre_version + 1` 约束有效。
#[test]
fn test_soundness_fold_version_not_incremented() {
    let input = FoldInput { seat_index: 3 };
    let row = FoldRow::active(
        &input, zero_root(), one_root(), 42, 0, 1,
        0, // pre_version
        0, // post_version（未递增！应为 1）
        4, 4, // round_state 不变
    );
    let trace = gen_method_trace(FoldAir::num_columns(), &row.to_vec(), &FoldRow::padding().to_vec())
        .expect("trace 生成失败");
    let air = FoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 0, // 与 trace 一致地未递增
    };
    let result = prove_method(&trace, air, FoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Fold));
    assert!(
        result.is_err(),
        "version 未递增时 prove 应失败（version+=1 约束应捕获）"
    );
}

/// Soundness 回归：fold 改变 pot（Lean 审计 fold「pot 不变」缺失）。
///
/// 构造合法 fold trace，再篡改 POST_POT limb0 → prove 应失败。
#[test]
fn test_soundness_fold_pot_changed() {
    use poker_texas_air::airs::common::{COL_POST_POT_BASE, COL_PRE_POT_BASE};
    let input = FoldInput { seat_index: 3 };
    let row = FoldRow::active(
        &input, zero_root(), one_root(), 42, 0, 1,
        0, 1, // version 正确递增
        4, 4, // round_state 不变
    );
    let mut trace_vec = row.to_vec();
    // 篡改：post_pot limb0 = 100（fold 不应改变 pot，pre=0）。
    trace_vec[COL_PRE_POT_BASE] = ZERO;
    trace_vec[COL_POST_POT_BASE] = M31::from(100u32);
    let trace = gen_method_trace(FoldAir::num_columns(), &trace_vec, &FoldRow::padding().to_vec())
        .expect("trace 生成失败");
    let air = FoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let result = prove_method(&trace, air, FoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Fold));
    assert!(
        result.is_err(),
        "fold 改变 pot 时 prove 应失败（pot 不变约束应捕获）"
    );
}

// ========== check AIR ==========

/// E2E: check → trace → prove → verify（happy path）。
#[test]
fn test_e2e_check_prove_verify() {
    let input = CheckInput {
        seat_index: 1,
        current_bet: 20,
        seat_bet: 20, // 守卫：seat.bet == current_bet
    };
    let row = CheckRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        4, // pre = PREFLOP
        4, // post = PREFLOP
        100, // pre_pot
        100, // post_pot（check 不改变 pot）
    );
    let trace = gen_method_trace(CheckAir::num_columns(), &row.to_vec(), &CheckRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = CheckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, CheckAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Check)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 check 的 `current_bet` 公开输入后，verify 应失败。
///
/// 流程：用正确 AIR 生成 proof → 篡改 proof.air.input.current_bet → verify 应失败。
#[test]
fn test_soundness_check_tampered_bet() {
    let input = CheckInput {
        seat_index: 1,
        current_bet: 20,
        seat_bet: 20,
    };
    let row = CheckRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        4,
        4,
        100,
        100,
    );
    let trace = gen_method_trace(CheckAir::num_columns(), &row.to_vec(), &CheckRow::padding().to_vec())
        .expect("trace 生成失败");

    // 用正确的 AIR 生成 proof
    let air = CheckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, CheckAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Check)).expect("prove 失败");

    // 篡改 proof.air.input.current_bet：trace 中是 20，但 AIR 声明 99
    proof.air = CheckAir {
        input: CheckInput {
            current_bet: 99, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 current_bet 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== call AIR ==========

/// E2E: call → trace → prove → verify（happy path）。
#[test]
fn test_e2e_call_prove_verify() {
    let input = CallInput {
        seat_index: 2,
        call_amount: 20,
    };
    let row = CallRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
        4,    // pre = PREFLOP
        4,    // post = PREFLOP
        100,  // pre_pot
        120,  // post_pot（pot += call_amount）
        80,   // post_seat_stack（原 100 - 20）
        20,   // post_seat_bet
        false, // is_all_in
        0,    // pre_seat_bet（post_seat_bet - call_amount = 20 - 20）
        100,  // pre_seat_stack（阶段3：原 100，call 后 stack=80）
        20,   // post_seat_total_bet（= post_seat_bet，首次下注）
        0,    // pre_seat_total_bet（原 0）
    );
    let trace = gen_method_trace(CallAir::num_columns(), &row.to_vec(), &CallRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = CallAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, CallAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Call)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 call 的 `call_amount` 公开输入后，verify 应失败。
///
/// 流程：用正确 AIR 生成 proof → 篡改 `proof.air.input.call_amount` → verify 应失败。
#[test]
fn test_soundness_call_tampered_amount() {
    let input = CallInput {
        seat_index: 2,
        call_amount: 20,
    };
    let row = CallRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
        4,
        4,
        100,
        120,
        80,
        20,
        false,
        0,    // pre_seat_bet（post_seat_bet - call_amount = 20 - 20）
        100,  // pre_seat_stack（阶段3：原 100，call 后 stack=80）
        20,   // post_seat_total_bet（= post_seat_bet，首次下注）
        0,    // pre_seat_total_bet（原 0）
    );
    let trace = gen_method_trace(CallAir::num_columns(), &row.to_vec(), &CallRow::padding().to_vec())
        .expect("trace 生成失败");

    // 用正确的 AIR 生成 proof
    let air = CallAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, CallAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Call)).expect("prove 失败");

    // 篡改 proof.air.input.call_amount：trace 中是 20，但 AIR 声明 999
    proof.air = CallAir {
        input: CallInput {
            call_amount: 999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    // verify 应失败（约束 is_active * (input_call_amount_0 - expected_amt_0) ≠ 0）
    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 call_amount 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== raise AIR ==========

/// E2E: raise → trace → prove → verify（happy path）。
#[test]
fn test_e2e_raise_prove_verify() {
    use poker_texas_air::airs::actions::raise::{RaiseAir, RaiseInput, RaiseRow};

    let input = RaiseInput {
        seat_index: 4,
        raise_to: 80,
        min_raise: 20,
    };
    let row = RaiseRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        4,
        0,
        1,
        4, // PREFLOP
        4,
        100,
        160, // pot += 60（raise_to - pre_bet = 80 - 20）
        80,  // pre_seat_stack
        20,  // pre_seat_bet
        20,  // pre_seat_total_bet
        20,  // post_seat_stack（原 80 - 60）
        80,  // post_seat_bet = raise_to
        80,  // post_seat_total_bet = 20 + 60
        80,  // post_current_bet = raise_to
        80,  // post_min_raise = raise_to（pre.current_bet = 0）
        false,
    );
    let trace = gen_method_trace(RaiseAir::num_columns(), &row.to_vec(), &RaiseRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = RaiseAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, RaiseAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Raise)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 raise 的 `raise_to` 公开输入后，verify 应失败。
#[test]
fn test_soundness_raise_tampered_raise_to() {
    use poker_texas_air::airs::actions::raise::{RaiseAir, RaiseInput, RaiseRow};

    let input = RaiseInput {
        seat_index: 4,
        raise_to: 80,
        min_raise: 20,
    };
    let row = RaiseRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        4,
        0,
        1,
        4,
        4,
        100,
        160,
        80,  // pre_seat_stack
        20,  // pre_seat_bet
        20,  // pre_seat_total_bet
        20,  // post_seat_stack
        80,  // post_seat_bet = raise_to
        80,  // post_seat_total_bet
        80,  // post_current_bet
        80,  // post_min_raise
        false,
    );
    let trace = gen_method_trace(RaiseAir::num_columns(), &row.to_vec(), &RaiseRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = RaiseAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, RaiseAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Raise)).expect("prove 失败");

    // 篡改 raise_to：trace 中是 80，但 AIR 声明 200
    proof.air = RaiseAir {
        input: RaiseInput {
            raise_to: 200, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 raise_to 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== auto_fold AIR ==========

/// E2E: auto_fold → trace → prove → verify（happy path）。
#[test]
fn test_e2e_auto_fold_prove_verify() {
    use poker_texas_air::airs::actions::auto_fold::{AutoFoldAir, AutoFoldInput, AutoFoldRow};

    let input = AutoFoldInput {
        seat_index: 1,
        current_time: 1_700_000_000,
    };
    let row = AutoFoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        5,
        0,
        1,
        4, // PREFLOP
        4,
    );
    let trace = gen_method_trace(
        AutoFoldAir::num_columns(),
        &row.to_vec(),
        &AutoFoldRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = AutoFoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, AutoFoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::AutoFold)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 auto_fold 的 `current_time` 公开输入后，verify 应失败。
#[test]
fn test_soundness_auto_fold_tampered_time() {
    use poker_texas_air::airs::actions::auto_fold::{AutoFoldAir, AutoFoldInput, AutoFoldRow};

    let input = AutoFoldInput {
        seat_index: 1,
        current_time: 1_700_000_000,
    };
    let row = AutoFoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        5,
        0,
        1,
        4,
        4,
    );
    let trace = gen_method_trace(
        AutoFoldAir::num_columns(),
        &row.to_vec(),
        &AutoFoldRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = AutoFoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, AutoFoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::AutoFold)).expect("prove 失败");

    // 篡改 current_time：trace 中是 1_700_000_000，AIR 声明 0
    proof.air = AutoFoldAir {
        input: AutoFoldInput {
            current_time: 0, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 current_time 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== force_fold AIR ==========

/// E2E: force_fold → trace → prove → verify（happy path）。
#[test]
fn test_e2e_force_fold_prove_verify() {
    use poker_texas_air::airs::actions::force_fold::{ForceFoldAir, ForceFoldInput, ForceFoldRow};

    let input = ForceFoldInput { seat_index: 5 };
    let row = ForceFoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        6,
        0,
        1,
        4, // PREFLOP
        4,
    );
    let trace = gen_method_trace(
        ForceFoldAir::num_columns(),
        &row.to_vec(),
        &ForceFoldRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = ForceFoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 6,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, ForceFoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::ForceFold)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 force_fold 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_force_fold_tampered_seat() {
    use poker_texas_air::airs::actions::force_fold::{ForceFoldAir, ForceFoldInput, ForceFoldRow};

    let input = ForceFoldInput { seat_index: 5 };
    let row = ForceFoldRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        6,
        0,
        1,
        4,
        4,
    );
    let trace = gen_method_trace(
        ForceFoldAir::num_columns(),
        &row.to_vec(),
        &ForceFoldRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = ForceFoldAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 6,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, ForceFoldAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::ForceFold)).expect("prove 失败");

    // 篡改 seat_index：trace 中是 5，AIR 声明 0
    proof.air = ForceFoldAir {
        input: ForceFoldInput { seat_index: 0 }, // 篡改！
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 seat_index 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== kick_player AIR ==========

/// E2E: kick_player → trace → prove → verify（happy path）。
#[test]
fn test_e2e_kick_player_prove_verify() {
    use poker_texas_air::airs::actions::kick_player::{
        KickPlayerAir, KickPlayerInput, KickPlayerRow,
    };

    let input = KickPlayerInput {
        seat_index: 2,
        refund: 500,
        kicked_bet: 50,
    };
    let row = KickPlayerRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        7,
        0,
        1,
        4, // PREFLOP
        4,
        100, // pre_pot
        150, // post_pot = pre_pot + kicked_bet (100 + 50)
    );
    let trace = gen_method_trace(
        KickPlayerAir::num_columns(),
        &row.to_vec(),
        &KickPlayerRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = KickPlayerAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 7,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, KickPlayerAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::KickPlayer)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 kick_player 的 `refund` 公开输入后，verify 应失败。
#[test]
fn test_soundness_kick_player_tampered_refund() {
    use poker_texas_air::airs::actions::kick_player::{
        KickPlayerAir, KickPlayerInput, KickPlayerRow,
    };

    let input = KickPlayerInput {
        seat_index: 2,
        refund: 500,
        kicked_bet: 50,
    };
    let row = KickPlayerRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        7,
        0,
        1,
        4,
        4,
        100, // pre_pot
        150, // post_pot = pre_pot + kicked_bet
    );
    let trace = gen_method_trace(
        KickPlayerAir::num_columns(),
        &row.to_vec(),
        &KickPlayerRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = KickPlayerAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 7,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, KickPlayerAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::KickPlayer)).expect("prove 失败");

    // 篡改 refund：trace 中是 500，AIR 声明 9999
    proof.air = KickPlayerAir {
        input: KickPlayerInput {
            refund: 9999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 refund 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== 列数一致性 ==========

/// 单元测试：所有 action AIR 的列数与常量声明一致。
#[test]
fn test_action_air_column_consistency() {
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    use poker_texas_air::airs::actions::{
        auto_fold, bet, call, check, fold, force_fold, kick_player, raise,
    };

    // fold: 通用 + 4 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    assert_eq!(fold::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 4);
    assert_eq!(FoldAir::num_columns(), fold::cols::NUM_COLUMNS);

    // check: 通用 + 8 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    assert_eq!(check::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 8);
    assert_eq!(CheckAir::num_columns(), check::cols::NUM_COLUMNS);

    // call: 通用 + 33 业务（阶段 3 soundness 升级：全 4-limb delta）
    // 业务列：seat_index/current_turn(2) + call_amount/stack/bet(12) + all_in/acted(2)
    // + pre_round_state_q(1) + pre_seat_bet/stack(8) + pre/post_total_bet(8) = 33
    assert_eq!(call::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 33);
    assert_eq!(CallAir::num_columns(), call::cols::NUM_COLUMNS);

    // raise: 通用 + 46 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    // 业务列：seat_index/current_turn/seat_occupied(3) + raise_to(4)
    // + pre_seat_stack/bet/total_bet(12) + call_delta(4)
    // + post_seat_stack/bet/total_bet(12) + post_current_bet/min_raise(8)
    // + output_all_in/acted(2) + pre_round_state_q(1) = 46
    assert_eq!(raise::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 46);
    assert_eq!(RaiseAir::num_columns(), raise::cols::NUM_COLUMNS);

    // bet: 通用 + 12 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    assert_eq!(bet::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 33);

    // auto_fold: 通用 + 8 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    assert_eq!(auto_fold::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 8);

    // force_fold: 通用 + 4 业务（含 Gap 1 witness + INPUT_CURRENT_TURN witness）
    assert_eq!(force_fold::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 4);

    // kick_player: 通用 + 11 业务（含 KICKED_BET 4 limb + Gap 3 INPUT_SEAT_OCCUPIED boolean witness）
    assert_eq!(kick_player::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 11);
}

/// 单元测试：MethodKind 的 actions 档位分类正确。
#[test]
fn test_action_method_kinds() {
    use poker_texas_air::method_kind::{MethodKind, MethodTier};

    assert_eq!(MethodKind::Fold.tier(), MethodTier::Action);
    assert_eq!(MethodKind::Check.tier(), MethodTier::Action);
    assert_eq!(MethodKind::Call.tier(), MethodTier::Action);
    assert_eq!(MethodKind::Raise.tier(), MethodTier::Action);
    assert_eq!(MethodKind::Bet.tier(), MethodTier::Action);
    assert_eq!(MethodKind::AutoFold.tier(), MethodTier::Action);
    assert_eq!(MethodKind::ForceFold.tier(), MethodTier::Action);
    assert_eq!(MethodKind::KickPlayer.tier(), MethodTier::Action);
}

// ========== bet AIR ==========

/// E2E: bet → trace → prove → verify（happy path）。
///
/// 场景：postflop 玩家 bet 50，原 seat.bet = 0，结果 seat.bet = 50。
#[test]
fn test_e2e_bet_prove_verify() {
    use poker_texas_air::airs::actions::bet::{BetAir, BetInput, BetRow};

    let input = BetInput {
        seat_index: 1,
        amount: 50,
    };
    let row = BetRow::active(
        &input,
        zero_root(),
        one_root(),
        42, // table_id
        0,  // hand_id
        8,  // call_seq
        0,  // pre_version
        1,  // post_version
        5,  // pre = FLOP（postflop bet）
        5,  // post = FLOP
        0,  // pre_pot
        50, // post_pot（pot += amount）
        50, // post_seat_bet
        0,   // pre_seat_bet（阶段3）
        100, // pre_seat_stack
        50,  // post_seat_stack（stack -= amount）
        0,   // pre_seat_total_bet
        50,  // post_seat_total_bet
    );
    let trace = gen_method_trace(BetAir::num_columns(), &row.to_vec(), &BetRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = BetAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 8,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(&trace, air, BetAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Bet)).expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 bet 的 `amount` 公开输入后，verify 应失败。
#[test]
fn test_soundness_bet_tampered_amount() {
    use poker_texas_air::airs::actions::bet::{BetAir, BetInput, BetRow};

    let input = BetInput {
        seat_index: 1,
        amount: 50,
    };
    let row = BetRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        8,
        0,
        1,
        5,
        5,
        0,
        50,
        50,
        0,   // pre_seat_bet
        100, // pre_seat_stack
        50,  // post_seat_stack
        0,   // pre_seat_total_bet
        50,  // post_seat_total_bet
    );
    let trace = gen_method_trace(BetAir::num_columns(), &row.to_vec(), &BetRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = BetAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 8,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, BetAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Bet)).expect("prove 失败");

    // 篡改 amount：trace 中是 50，但 AIR 声明 999
    proof.air = BetAir {
        input: BetInput {
            amount: 999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 amount 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 bet 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_bet_tampered_seat() {
    use poker_texas_air::airs::actions::bet::{BetAir, BetInput, BetRow};

    let input = BetInput {
        seat_index: 1,
        amount: 50,
    };
    let row = BetRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        8,
        0,
        1,
        5,
        5,
        0,
        50,
        50,
        0,   // pre_seat_bet
        100, // pre_seat_stack
        50,  // post_seat_stack
        0,   // pre_seat_total_bet
        50,  // post_seat_total_bet
    );
    let trace = gen_method_trace(BetAir::num_columns(), &row.to_vec(), &BetRow::padding().to_vec())
        .expect("trace 生成失败");

    let air = BetAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 8,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(&trace, air, BetAir::num_columns(), TexasPublicInputs::synthetic_placeholder(MethodKind::Bet)).expect("prove 失败");

    // 篡改 seat_index：trace 中是 1，但 AIR 声明 6
    proof.air = BetAir {
        input: BetInput {
            seat_index: 6, // 篡改！
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
