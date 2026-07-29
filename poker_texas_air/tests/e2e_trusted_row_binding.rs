//! Regression tests for verifier-trusted complete business-row binding.

use poker_l1::object_model::ObjectID;
use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
use poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
use poker_l1::vm::contracts::texas_poker::state_machine;
use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
use poker_texas_air::airs::actions::call::{CallAir, CallInput, CallRow};
use poker_texas_air::airs::lifecycle::create_table::CreateTableInput;
use poker_texas_air::airs::{AirStatement, TexasAir};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::prover::{prove_create_table, prove_method};
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::state_root_to_air_limbs;
use poker_texas_air::trace_gen::create_table_trace::gen_create_table_trace;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::{verify_create_table_against, verify_method_against};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

/// Minimal AIR with a deliberately unconstrained second business column.
/// `BoundAir` must still bind that column to the trusted row.
#[derive(Debug, Clone)]
struct PartiallyConstrainedAir {
    statement: AirStatement,
}

impl FrameworkEval for PartiallyConstrainedAir {
    fn log_size(&self) -> u32 {
        10
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        11
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let first = eval.next_trace_mask();
        let seven: E::F = M31::from(7u32).into();
        eval.add_constraint(first - seven);
        // Column 1 is intentionally unread/unconstrained by this inner AIR.
        eval
    }
}

impl TexasAir for PartiallyConstrainedAir {
    fn statement(&self) -> AirStatement {
        self.statement.clone()
    }

    fn trace_num_columns(&self) -> usize {
        2
    }
}

fn generic_fixture() -> (
    poker_texas_air::prover::MethodProof<PartiallyConstrainedAir>,
    PartiallyConstrainedAir,
    TexasPublicInputs,
) {
    let mut public_inputs = TexasPublicInputs::synthetic_for_test(MethodKind::Fold, 42, 3, 9);
    let row = [M31::from(7u32), M31::from(42u32)];
    public_inputs
        .bind_expected_trace_row(&row)
        .expect("trusted row should bind");
    let trace =
        gen_method_trace(2, &row, &[M31::from(0u32); 2]).expect("trace should be generated");
    let air = PartiallyConstrainedAir {
        statement: AirStatement {
            kind: MethodKind::Fold,
            pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
            post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
            table_id: 42,
            hand_id: 3,
            call_seq: 9,
            pre_version: 0,
            post_version: 1,
        },
    };
    let proof = prove_method(&trace, air.clone(), 2, public_inputs.clone())
        .expect("bound generic proof should be generated");
    (proof, air, public_inputs)
}

#[test]
fn generic_verifier_accepts_the_independently_supplied_complete_row() {
    let (proof, air, public_inputs) = generic_fixture();
    verify_method_against(proof, air, &public_inputs)
        .expect("the independently reconstructed row should verify");
}

#[test]
fn generic_verifier_rejects_a_changed_unconstrained_business_column() {
    let (proof, air, mut public_inputs) = generic_fixture();
    public_inputs.expected_trace_row.as_mut().unwrap()[1] = 43;
    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "an inner-AIR-unconstrained column must still be bound by BoundAir"
    );
}

#[test]
fn generic_verifier_does_not_fallback_to_the_proof_carried_row() {
    let (proof, air, mut public_inputs) = generic_fixture();
    assert!(proof.public_inputs.expected_trace_row.is_some());
    public_inputs.expected_trace_row = None;
    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verification must fail closed when its trusted row is absent"
    );
}

fn make_create_tables() -> (TexasPokerTable, TexasPokerTable) {
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0u8; 20], 0),
        "pre_placeholder".to_owned(),
        EMPTY_PLAYER,
        2,
        1,
        2,
    );
    pre.version = 0;
    let mut post = TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 1),
        "test_table".to_owned(),
        EMPTY_PLAYER,
        6,
        10,
        20,
    );
    post.version = 1;
    (pre, post)
}

#[test]
fn create_table_verifier_requires_and_binds_the_complete_row() {
    let (pre, post) = make_create_tables();
    let trace = gen_create_table_trace(
        CreateTableInput {
            name: "test_table".to_owned(),
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
        },
        &pre,
        &post,
        42,
        0,
        1,
    )
    .expect("create-table trace should be generated");
    let mut public_inputs =
        TexasPublicInputs::from_tables(&pre, &post, MethodKind::CreateTable, 42, 0, 1)
            .expect("public inputs should be generated");
    public_inputs
        .bind_expected_trace_row(&trace.trace.first_row().unwrap())
        .expect("trusted create-table row should bind");
    let proof = prove_create_table(&trace, public_inputs.clone())
        .expect("bound create-table proof should be generated");

    verify_create_table_against(proof.clone(), trace.air.clone(), &public_inputs)
        .expect("trusted create-table row should verify");

    let mut changed = public_inputs.clone();
    let last = changed
        .expected_trace_row
        .as_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    *last = (*last + 1) % (stwo::core::fields::m31::P - 1);
    assert!(
        verify_create_table_against(proof.clone(), trace.air.clone(), &changed).is_err(),
        "changing any create-table business column must invalidate verification"
    );

    let mut missing = public_inputs;
    missing.expected_trace_row = None;
    assert!(
        verify_create_table_against(proof, trace.air, &missing).is_err(),
        "create-table verification must fail closed without a trusted row"
    );
}

#[test]
fn production_verifier_rejects_action_row_not_reconstructed_from_canonical_tables() {
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xCC; 20], 7),
        "canonical-call".to_owned(),
        EMPTY_PLAYER,
        6,
        50,
        100,
    );
    pre.round_state = ROUND_PREFLOP;
    pre.betting_round = Some(BettingRound::new(100, 100));
    pre.current_turn = Some(0);
    pre.pot = 25;
    pre.hand_id = 5;
    pre.call_seq = 8;
    for i in 0..3 {
        pre.seats[i].player = [u8::try_from(i + 1).unwrap(); 20];
        pre.seats[i].stack = 1_000;
    }
    pre.seats[0].bet = 50;
    pre.seats[0].total_bet = 50;
    pre.seats[1].bet = 100;
    pre.seats[1].total_bet = 100;
    pre.seats[2].bet = 100;
    pre.seats[2].total_bet = 100;

    let mut post = pre.clone();
    state_machine::apply_call(&mut post, 0, &mut vec![]).unwrap();
    post.call_seq = pre.call_seq + 1;
    assert_eq!(post.seats[0].bet, 100);
    assert_eq!(post.current_turn, Some(1));

    // This row is internally valid for a fictitious current_bet=70/call=20,
    // but the canonical pre/post tables commit to current_bet=100/call=50.
    // Before verifier-side table decoding, such a proof could verify because
    // roots and business row were transcript-bound but unrelated.
    let fake_input = CallInput {
        seat_index: 0,
        call_amount: 20,
        pre_current_bet: 70,
        pre_seat_bet: 50,
        pre_seat_stack: 1_000,
        pre_seat_total_bet: 50,
        post_current_turn: 1,
    };
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &post,
        MethodKind::Call,
        42,
        post.hand_id,
        post.call_seq,
    )
    .expect("canonical public inputs should be generated");
    let fake_row = CallRow::active(
        &fake_input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        pre.version,
        post.version,
        pre.round_state,
        post.round_state,
        pre.pot,
        post.pot,
        980,
        70,
        false,
        50,
        1_000,
        70,
        50,
    );
    public_inputs
        .bind_expected_trace_row(&fake_row.to_vec())
        .expect("fictitious row should bind at construction time");
    let trace = gen_method_trace(
        CallAir::num_columns(),
        &fake_row.to_vec(),
        &CallRow::padding().to_vec(),
    )
    .expect("fictitious but AIR-consistent trace should be generated");
    let air = CallAir {
        log_size: trace.log_size,
        input: fake_input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        CallAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("the fictitious row is intentionally AIR-consistent");

    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verifier must derive action semantics from canonical table images"
    );
}
