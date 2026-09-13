//! Path A 原生出证：真实 canonical 证明（poker_texas_air prove 路径）落盘。
//!
//! witness 构造镜像 poker-appchain-texasair/tests/perf_baseline.rs 的
//! `full_hand_witnesses`（已证模式：Raise/Raise/Fold/Call/AdvanceRound 五行
//! 单批，构造即 host 侧 validate_shape 自检）。每桌独立 table_id → 批次
//! scope 互异 → 3 份互不相同的真实证明。
//!
//! 输出（默认 ../proofs/，即 stwo-wasm-verify/proofs/）：
//!   canonical_table<T>.bin   — borsh 归档字节（wasm 验证输入）
//!   canonical_proofs.json    — 元数据清单（字节数/摘要/耗时）
//! 另对每份归档跑一次 native `verify_canonical_tagged_proof` 作为真值基线。
//!
//! 用法（repo 内）：cargo run --release -p gen-canonical -- [输出目录]

use std::time::Instant;

use poker_texas_air::canonical_rake_opening::{CanonicalBlindOpening, CanonicalRakeOpening};
use poker_texas_air::texas_canonical::{
    CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

const BUY_IN: u64 = 500;
const FOLDER_NOTE: u64 = 50;
const GROSS_POT: u64 = BUY_IN * 2 + FOLDER_NOTE;
/// 三张不同桌（批次 scope 互异）。
const TABLE_IDS: [u64; 3] = [9101, 9102, 9103];

fn active_seat(stack: u64, bet: u64, total_bet: u64, index: usize) -> CanonicalSeat {
    CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted: false,
        stack,
        bet,
        total_bet,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [70 + index as u8; 32],
        key_commitment: [80 + index as u8; 32],
        hole_cards_commitment: [90 + index as u8; 32],
    }
}

fn hand_start_image(table_id: u64) -> CanonicalStateImage {
    let mut image = CanonicalStateImage {
        abi_version: CANONICAL_ABI_VERSION,
        table_id,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Betting,
        phase_subtag: 1,
        street: 1,
        current_turn: 0,
        deadline_ms: 42_500,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 3_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 50,
        min_raise: 50,
        chip_pool: BUY_IN * 3,
        pot: 0,
        button: 0,
        max_players: 3,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [1; 32],
        deck_commitment: [2; 32],
        reveal_commitment: [3; 32],
        reconstruction_commitment: [4; 32],
        run_it_twice_commitment: [5; 32],
        rules_commitment: [6; 32],
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
    };
    image.seats[0] = active_seat(BUY_IN, 0, 0, 0);
    image.seats[1] = active_seat(BUY_IN - 25, 25, 25, 1);
    image.seats[2] = active_seat(BUY_IN - 50, 50, 50, 2);
    image
}

/// 完整一手牌 witness 序列（镜像 perf_baseline::full_hand_witnesses）。
fn full_hand_witnesses(table_id: u64) -> Vec<CanonicalTransitionWitness> {
    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut CanonicalStateImage)| {
        let pre = rows
            .last()
            .map(|r| r.post.clone())
            .unwrap_or_else(|| hand_start_image(table_id));
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: CanonicalRakeOpening::ZERO,
            blind_opening: CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
            .validate_shape()
            .unwrap_or_else(|e| panic!("witness {seq} ({kind:?}) shape invalid: {e}"));
        rows.push(witness);
    };

    step(
        CanonicalTransitionKind::Raise,
        [70; 32],
        0,
        200,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 1;
            post.current_bet = 200;
            post.min_raise = 150;
            post.acted_mask = 0b001;
            post.seats[0].acted = true;
            post.seats[0].stack = BUY_IN - 200;
            post.seats[0].bet = 200;
            post.seats[0].total_bet = 200;
        },
    );
    step(
        CanonicalTransitionKind::Raise,
        [71; 32],
        1,
        500,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 2;
            post.current_bet = 500;
            post.min_raise = 300;
            post.acted_mask = 0b010;
            post.seats[1].acted = true;
            post.seats[1].status = CanonicalSeatStatus::AllIn;
            post.seats[1].stack = 0;
            post.seats[1].bet = 500;
            post.seats[1].total_bet = 500;
            post.seats[0].acted = false;
        },
    );
    step(
        CanonicalTransitionKind::Fold,
        [72; 32],
        2,
        0,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 0;
            post.acted_mask = 0b110;
            post.seats[2].status = CanonicalSeatStatus::Folded;
            post.seats[2].acted = true;
        },
    );
    step(
        CanonicalTransitionKind::Call,
        [70; 32],
        0,
        300,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = NO_CANONICAL_SEAT;
            post.acted_mask = 0b111;
            post.seats[0].acted = true;
            post.seats[0].status = CanonicalSeatStatus::AllIn;
            post.seats[0].stack = 0;
            post.seats[0].bet = 500;
            post.seats[0].total_bet = 500;
        },
    );

    let advance_pre = rows.last().expect("pre-advance row").post.clone();
    let mut advance_post = advance_pre.clone();
    advance_post.call_seq = 5;
    advance_post.phase = CanonicalPhase::Revealing;
    advance_post.phase_subtag = 2;
    advance_post.street = 2;
    advance_post.deadline_ms = 45_000;
    advance_post.current_turn = NO_CANONICAL_SEAT;
    advance_post.current_bet = 0;
    advance_post.min_raise = 0;
    advance_post.pot = GROSS_POT;
    advance_post.protocol_pending_mask = 0b111;
    for seat in &mut advance_post.seats {
        seat.bet = 0;
    }
    let mut advance = CanonicalTransitionWitness {
        pre: advance_pre,
        post: advance_post,
        kind: CanonicalTransitionKind::AdvanceRound,
        actor: [0; 32],
        action: CanonicalActionPayload {
            seat: NO_CANONICAL_SEAT,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening {
            pre_cards_dealt: 6,
            post_cards_dealt: 9,
            pre_board_len: 0,
            post_board_len: 0,
            pre_second_board_len: 0,
            post_second_board_len: 0,
            run_it_twice: false,
            reveal_purpose: 2,
            assignment_count: 3,
            assignments: {
                let mut slots =
                    [CanonicalBoardRevealAssignment::EMPTY; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS];
                for (position, slot) in slots.iter_mut().take(3).enumerate() {
                    *slot = CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 6 + position as u8,
                        runout_index: 0,
                        board_position: position as u8,
                        pending_mask: 0b111,
                        submitted_mask: 0,
                    };
                }
                slots
            },
        },
        protocol_completion: Default::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        blind_opening: CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    advance.seal();
    advance.validate_shape().expect("advance opening shape");
    rows.push(advance);
    rows
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("proofs"));
    std::fs::create_dir_all(&out_dir).expect("create output dir");

    let mut entries = Vec::new();
    for table_id in TABLE_IDS {
        let witnesses = full_hand_witnesses(table_id);
        assert_eq!(witnesses.len(), 5);
        let t0 = Instant::now();
        let archive = prove_canonical_tagged_batch(&witnesses)
            .unwrap_or_else(|e| panic!("table {table_id} prove failed: {e}"));
        let prove_ms = t0.elapsed().as_secs_f64() * 1e3;

        // native 真值基线：本机 verify 一次（对照 texasair perf_baseline p50 188.7ms 口径）。
        let t1 = Instant::now();
        verify_canonical_tagged_proof(&archive)
            .unwrap_or_else(|e| panic!("table {table_id} native verify failed: {e}"));
        let native_verify_ms = t1.elapsed().as_secs_f64() * 1e3;

        let bytes = borsh::to_vec(&archive).expect("archive borsh serialize");
        let file = format!("canonical_table{table_id}.bin");
        let path = std::path::Path::new(&out_dir).join(&file);
        std::fs::write(&path, &bytes).expect("write archive");
        println!(
            "GEN table={table_id} file={} bytes={} prove_ms={prove_ms:.1} native_verify_ms={native_verify_ms:.1} \
             log_size={} transition_count={} batch_digest={}",
            path.display(),
            bytes.len(),
            archive.log_size,
            archive.transition_count,
            archive
                .batch_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        entries.push(format!(
            "{{\"table_id\":{table_id},\"file\":\"{file}\",\"bytes\":{},\
             \"prove_ms\":{prove_ms:.1},\"native_verify_ms\":{native_verify_ms:.1},\
             \"log_size\":{},\"transition_count\":{},\"batch_digest\":\"{}\"}}",
            bytes.len(),
            archive.log_size,
            archive.transition_count,
            archive
                .batch_digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        ));
    }

    let manifest = format!(
        "{{\"generated_by\":\"gen-canonical (poker_texas_air prove_canonical_tagged_batch)\",\
         \"format\":\"borsh ArchivedCanonicalTaggedProof\",\"count\":{},\"proofs\":[{}]}}\n",
        entries.len(),
        entries.join(",")
    );
    std::fs::write(
        std::path::Path::new(&out_dir).join("canonical_proofs.json"),
        manifest,
    )
    .expect("write manifest");
    println!("GEN manifest written to {out_dir}/canonical_proofs.json");
}
