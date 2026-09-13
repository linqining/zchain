//! 洗牌/发牌证明链——**上游 stage0 真实产出 → zchain 消费侧**对齐验收
//! （SHUFFLE_CONSUME.md §3 排队清单收口：deck 链摘要两侧对照 + 真实归档
//! 消费侧钉扎 + REAL × 协议行 fail-closed 证据）。
//!
//! 本测试用**上游真实密码学栈**（`poker_texas_air::canonical_shuffle_chain`
//! 的 `ShuffleChainBuilder` + Bayer–Groth V2 + reveal-token DLEq，Stark 曲线
//! + Poseidon 生产域）产出一手**单批全链**（SubmitShuffle×4 →
//! SubmitReveal×4 → Call×3 → Check → AdvanceRound，13 行），经
//! `prove_canonical_reveal_completion_batch` 出证后：
//!
//! 1. **deck 链摘要裁决对照（交付 1）**：上游 receipt 的
//!    `deck_chain_digest`（poseidon 折叠，域
//!    `zchain.texas.canonical-shuffle-chain.v1`）vs 消费侧
//!    `poker_settlement_core::deck_chain_digest`（裁决后同源实现）对同一
//!    链锚序列**逐位一致**；golden 十六进制钉扎回归。
//! 2. **真实归档消费侧钉扎（交付 2）**：真实 archive borsh 字节 →
//!    `parse_archive_scope` 逐字段比对（table/kind/计数/批摘要/blind
//!    opening/镜像 pot@74 与 deck@122/reveal@154/reconstruction@186 锚）
//!    ——镜像偏移对**真实归档**成立（此前只有手写编码器钉扎）。
//! 3. **消费侧正例 + 负例**：`validate_settlement` 对真实归档 v2 绑定
//!    PLAY 类结算接受；REAL 类结算被 11b-f fail-closed 拒绝（精确消息）。
//! 4. **夹具导出**：archive 字节 + 元数据 JSON 只读复制到
//!    `../poker-appchain/tests/fixtures/`，供 poker-appchain 侧独立
//!    钉扎测试（`tests/shuffle_chain_real_archive.rs`）消费。
//!
//! 纪律：不修改上游仓库（poker_texas_air 只读）；确定性种子 → 归档与
//! 摘要逐位可重现。

use std::path::PathBuf;

use poker_texas_air::canonical_rake_opening::canonical_rules_commitment;
use poker_texas_air::canonical_shuffle_chain::{
    verify_canonical_batch_with_shuffle_chain, PlayerKeys, ShuffleChainBuilder,
};
use poker_texas_air::texas_canonical::{
    CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    prove_canonical_reveal_completion_batch, verify_canonical_tagged_proof,
};

// 上游 stage0 夹具同款参数（SEATS/盲注/买入与
// poker_texas_air/tests/canonical_shuffle_chain_stage0.rs 对齐）。
const SEATS: u8 = 4;
const BUY_IN: u64 = 10_000;
const SB: u64 = 50;
const BB: u64 = 100;
const TABLE_ID: u64 = 7;
const TERMINAL_TIME_BANK_MS: u32 = 30_000;
const GROSS_POT: u64 = 400; // SB 50 + BB 100 + Call 100 ×2 + BB 既有 100（见下）

fn table_rules() -> poker_l1::contracts::texas_poker::types::TableRules {
    poker_l1::contracts::texas_poker::types::TableRules {
        max_players: SEATS,
        small_blind: SB,
        big_blind: BB,
        timeout_config: Default::default(),
        ante_mode: 0,
        ante_amount: 0,
        rake_mode: 0,
        rake_bps: 0,
        rake_cap: 0,
        rit_mode: 0,
    }
}

fn base_image(rules_commitment: [u8; 32], deck_commitment: [u8; 32]) -> CanonicalStateImage {
    CanonicalStateImage {
        abi_version: poker_texas_air::texas_canonical::CANONICAL_ABI_VERSION,
        table_id: TABLE_ID,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Waiting,
        phase_subtag: 0,
        street: 0,
        current_turn: NO_CANONICAL_SEAT,
        deadline_ms: 0,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 10_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 0,
        min_raise: 0,
        chip_pool: 0,
        pot: 0,
        button: 0,
        max_players: SEATS,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
        board_cards_commitment: [0; 32],
        deck_commitment,
        reveal_commitment: [0; 32],
        reconstruction_commitment: [0; 32],
        run_it_twice_commitment: [0; 32],
        rules_commitment,
        governance_commitment: [7; 32],
        settlement_commitment: [8; 32],
        custody_commitment: [9; 32],
        lifecycle_root: [10; 32],
        overlay_root: [11; 32],
        state_root: [12; 32],
        seats: [CanonicalSeat::EMPTY; poker_texas_air::texas_canonical::MAX_CANONICAL_SEATS],
    }
}

fn empty_row(
    pre: CanonicalStateImage,
    post: CanonicalStateImage,
    kind: CanonicalTransitionKind,
    seat: u8,
    actor: [u8; 32],
    amount: u64,
    proof_commitment: [u8; 32],
) -> CanonicalTransitionWitness {
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
            proof_commitment,
        },
        round_advance: CanonicalRoundAdvanceOpening::default(),
        protocol_completion: Default::default(),
        rake_opening: poker_texas_air::canonical_rake_opening::CanonicalRakeOpening::ZERO,
        blind_opening: poker_texas_air::canonical_rake_opening::CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    witness.seal();
    witness
}

fn identity_of(pre: &CanonicalStateImage, seat: u8) -> [u8; 32] {
    pre.seats[usize::from(seat)].identity_commitment
}

fn join_row(pre: CanonicalStateImage, seat: u8, actor_seed: u8) -> CanonicalTransitionWitness {
    let mut post = pre.clone();
    post.call_seq = pre.call_seq + 1;
    post.chip_pool = pre.chip_pool + BUY_IN;
    post.seats[usize::from(seat)] = CanonicalSeat {
        status: CanonicalSeatStatus::Waiting,
        acted: false,
        stack: BUY_IN,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
        time_bank_ms: TERMINAL_TIME_BANK_MS,
        identity_commitment: [actor_seed; 32],
        key_commitment: [actor_seed + 10; 32],
        hole_cards_commitment: [0; 32],
    };
    empty_row(pre, post, CanonicalTransitionKind::JoinTable, seat, [actor_seed; 32], BUY_IN, [0; 32])
}

/// hand-start 投影（street_fix = stage-0 桥接：StartHand 钉 street 0 而洗牌
/// 完成钉 street 不变、reveal 完成要求 street 1——生产者以 street=1 投影
/// 作为全链批起点，见 SHUFFLE_STAGE0.md §4.1）。
fn hand_start_projection(pre: &CanonicalStateImage, hand_id: u32) -> CanonicalStateImage {
    let mut post = pre.clone();
    post.call_seq = 0;
    post.hand_id = hand_id;
    let max = usize::from(pre.max_players);
    post.button = (1..=max)
        .map(|offset| (usize::from(pre.button) + offset) % max)
        .find(|&index| pre.seats[index].status != CanonicalSeatStatus::Empty)
        .map(|index| index as u8)
        .unwrap_or(pre.button);
    post.phase = CanonicalPhase::Shuffling;
    post.phase_subtag = 1;
    post.street = 1;
    post.deadline_ms = 100;
    post.acted_mask = 0;
    post.current_turn = NO_CANONICAL_SEAT;
    post.protocol_pending_mask = (0..usize::from(SEATS))
        .filter(|&index| {
            matches!(
                pre.seats[index].status,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::Waiting
            )
        })
        .fold(0u16, |mask, index| mask | (1u16 << index));
    for (pre_seat, post_seat) in pre.seats.iter().zip(post.seats.iter_mut()) {
        if pre_seat.status == CanonicalSeatStatus::Waiting {
            post_seat.status = CanonicalSeatStatus::Active;
        }
    }
    post
}

fn next_seat(from: u8, step: usize) -> u8 {
    ((usize::from(from) + step) % usize::from(SEATS)) as u8
}

fn deterministic_permutation(n: usize, seed: u64) -> (Vec<usize>, Vec<<poker_protocol::crypto::types::DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar>) {
    use poker_protocol::crypto::curve::CurveScalar;
    use poker_protocol::crypto::types::Scalar;
    use rand::SeedableRng;
    let mut permutation: Vec<usize> = (0..n).collect();
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    for index in (1..permutation.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        permutation.swap(index, (state % (index as u64 + 1)) as usize);
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(state);
    let rerandomizers: Vec<Scalar> = (0..n)
        .map(|_| <poker_protocol::crypto::types::DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar::random(&mut rng))
        .collect();
    (permutation, rerandomizers)
}

/// RevealComplete 后的下注段：Call×3 + BB Check → AdvanceRound（收池入
/// `pot`，街 1 → 街 2 揭示相位开台；批终 = AdvanceRound（结算语义末 kind）。
/// 桌面几何（button=1 ⇒ sb=2 / bb=3 / utg=0）与上游 stage0 夹具一致。
fn betting_to_advance_round(pre: CanonicalStateImage) -> Vec<CanonicalTransitionWitness> {
    let mut witnesses = Vec::new();
    let mut current = pre;
    let button = current.button;
    let bb = next_seat(button, 2);
    let utg = next_seat(bb, 1);

    // Call ×3（utg → button → sb），BB Check 收口。
    for step in 0..4usize {
        let seat = next_seat(utg, step);
        let mut post = current.clone();
        post.call_seq += 1;
        if step == 3 {
            // BB check：注码已匹配，无资金移动。
            post.current_turn = NO_CANONICAL_SEAT;
            post.acted_mask |= 1u16 << seat;
            post.seats[usize::from(seat)].acted = true;
            witnesses.push(empty_row(
                current.clone(),
                post,
                CanonicalTransitionKind::Check,
                seat,
                identity_of(&current, seat),
                0,
                [0; 32],
            ));
        } else {
            let owed = current.current_bet - current.seats[usize::from(seat)].bet;
            post.current_turn = next_seat(seat, 1);
            post.acted_mask |= 1u16 << seat;
            let seat_state = &mut post.seats[usize::from(seat)];
            seat_state.stack -= owed;
            seat_state.bet = current.current_bet;
            seat_state.total_bet += owed;
            seat_state.acted = true;
            witnesses.push(empty_row(
                current.clone(),
                post,
                CanonicalTransitionKind::Call,
                seat,
                identity_of(&current, seat),
                owed,
                [0; 32],
            ));
        }
        current = witnesses.last().expect("rows").post.clone();
    }

    // AdvanceRound：把 Σbet 收进 pot，开街 2 板牌揭示相位（上游 stage0
    // segment-B1 同款 opening）。
    let mut post = current.clone();
    post.call_seq += 1;
    post.phase = CanonicalPhase::Revealing;
    post.phase_subtag = 2;
    post.street = 2;
    post.current_turn = NO_CANONICAL_SEAT;
    post.deadline_ms = 32_000;
    post.protocol_pending_mask = 0b1111;
    post.current_bet = 0;
    post.min_raise = 0;
    post.pot = current.pot + current.seats.iter().map(|seat| seat.bet).sum::<u64>();
    for seat in post.seats.iter_mut() {
        seat.bet = 0;
    }
    let assignments = {
        let mut slots = [CanonicalBoardRevealAssignment::EMPTY; 6];
        for (slot, assignment) in slots.iter_mut().take(3).enumerate() {
            *assignment = CanonicalBoardRevealAssignment {
                present: true,
                encrypted_card_index: 8 + slot as u8,
                runout_index: 0,
                board_position: slot as u8,
                pending_mask: 0b1111,
                submitted_mask: 0,
            };
        }
        slots
    };
    let mut witness = empty_row(
        current.clone(),
        post,
        CanonicalTransitionKind::AdvanceRound,
        NO_CANONICAL_SEAT,
        [0; 32],
        0,
        [0; 32],
    );
    witness.round_advance = CanonicalRoundAdvanceOpening {
        pre_cards_dealt: 8,
        post_cards_dealt: 11,
        pre_board_len: 0,
        post_board_len: 0,
        reveal_purpose: 2,
        assignment_count: 3,
        assignments,
        ..Default::default()
    };
    witness.seal();
    witnesses.push(witness);
    witnesses
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 上游 stage0 真实产出的一手单批全链（确定性种子）：
/// 返回（witnesses, archive, receipt, deck 链锚序列）。
fn proven_full_chain()
-> (
    Vec<CanonicalTransitionWitness>,
    poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof,
    poker_texas_air::canonical_shuffle_chain::ShuffleChainReceipt,
    Vec<[u8; 32]>,
) {
    use poker_protocol::crypto::curve::{Curve, CurveScalar};
    use poker_protocol::crypto::types::{DefaultCurve, Scalar};
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ACE_0001);
    let rules_commitment = canonical_rules_commitment(&table_rules()).expect("rules commitment");
    let players: Vec<PlayerKeys> = (0..SEATS)
        .map(|seat| {
            let secret = Scalar::random(&mut rng);
            PlayerKeys {
                seat,
                public: DefaultCurve::base_g() * secret,
                secret,
            }
        })
        .collect();
    let mut builder = ShuffleChainBuilder::new(players).expect("builder");

    // 桌务（JoinTable×4）在批外：全链批起点 = hand-start 投影。
    let mut waiting = base_image(rules_commitment, builder.initial_deck_commitment());
    for seat in 0..SEATS {
        waiting = join_row(waiting, seat, 30 + seat).post;
    }
    let mut current = hand_start_projection(&waiting, 2);

    // 协议段：SubmitShuffle×4（真实 BG V2）→ SubmitReveal×4（真实 DLEq，
    // 末行 RevealComplete 盲注实投）。
    let mut witnesses = Vec::new();
    for index in 0..usize::from(SEATS) {
        let row = builder
            .produce_shuffle_row(current.clone(), &mut rng, |n| {
                deterministic_permutation(n, 700 + index as u64)
            })
            .expect("shuffle row");
        current = row.post.clone();
        witnesses.push(row);
    }
    builder.set_reveal_completion_blinds(SB, BB);
    let hole_set: Vec<usize> = (0..2 * usize::from(SEATS)).collect();
    for seat in 0..SEATS {
        let row = builder
            .produce_reveal_row(current.clone(), seat, &hole_set, &mut rng)
            .expect("reveal row");
        current = row.post.clone();
        witnesses.push(row);
    }

    // 下注段：Call×3 + Check → AdvanceRound（收池；批终 = 结算语义末 kind）。
    witnesses.extend(betting_to_advance_round(current));
    assert_eq!(witnesses.len(), 13);

    // 出证（reveal-completion 通道：绑定 blind opening + 桌规则）+ STARK 验证
    // + 路线 A 原生验证（含承诺链重导）→ 路线 B receipt。
    let archive = prove_canonical_reveal_completion_batch(&witnesses, &table_rules())
        .expect("full-chain single-batch proof");
    verify_canonical_tagged_proof(&archive).expect("STARK verify");
    let mut sidecar = builder.into_sidecar();
    let receipt = verify_canonical_batch_with_shuffle_chain(&archive, &witnesses, &mut sidecar)
        .expect("native BG/DLEq shuffle-chain verification");

    // 上游 receipt 的 deck 链锚 = 每个 SubmitShuffle 行的 post.deck_commitment
    // （`verify_canonical_batch_with_shuffle_chain` 逐行 push，见其实现）。
    let deck_chain: Vec<[u8; 32]> = witnesses
        .iter()
        .filter(|w| w.kind == CanonicalTransitionKind::SubmitShuffle)
        .map(|w| w.post.deck_commitment)
        .collect();
    (witnesses, archive, receipt, deck_chain)
}

/// **交付 1 主证据**：上游真实 `ShuffleChainReceipt.deck_chain_digest` vs
/// 消费侧 `poker_settlement_core::deck_chain_digest` —— 同一链锚序列输入
/// 下**逐位一致**（裁决：消费侧冻结为上游 poseidon 折叠，与生产者同源）。
#[test]
fn deck_chain_digest_consumer_rederives_upstream_bit_for_bit() {
    let (_witnesses, archive, receipt, deck_chain) = proven_full_chain();

    assert_eq!(deck_chain.len(), 4, "one anchor per SubmitShuffle row");
    assert_eq!(receipt.batch_digest, archive.batch_digest);

    // 逐位一致（裁决对照）：消费侧重导 == 上游 receipt 值。
    let consumer = poker_settlement_core::deck_chain_digest(&deck_chain)
        .expect("4-anchor chain within DECK_CHAIN_MAX");
    assert_eq!(
        consumer, receipt.deck_chain_digest,
        "consumer deck_chain_digest must re-derive the upstream receipt bit-for-bit"
    );

    // golden 钉扎（确定性种子 → 稳定值；源 = 上游真实出证 receipt）。
    assert_eq!(
        hex(&receipt.deck_chain_digest),
        "073c5e280d7d548111384f60c97f1b492af20b5d1ef4c242497b55605265e66a",
        "upstream deck-chain digest golden drifted"
    );
    assert_eq!(
        hex(&receipt.engine_receipt_digest),
        "0174ced8f6aec0d3fe2f1941e2c95fd65f34980e4e80ed34c6e31299c47550aa",
        "upstream engine receipt digest golden drifted"
    );
    assert_eq!(receipt.statement_digests.len(), 8, "4 shuffle + 4 reveal statements");

    println!("[stage0-consume] deck chain anchors: {}", deck_chain.len());
    println!("[stage0-consume] deck_chain_digest: {}", hex(&receipt.deck_chain_digest));
    println!("[stage0-consume] engine_receipt_digest: {}", hex(&receipt.engine_receipt_digest));
}

/// **交付 2**：真实归档 → 消费侧 `parse_archive_scope` 逐字段钉扎 +
/// `validate_settlement` 正例（PLAY）与 11b-f fail-closed 负例（REAL），
/// 并把真实归档字节/元数据导出到 poker-appchain fixtures。
#[test]
fn real_archive_scope_pinning_and_consumer_validation() {
    use poker_appchain::error::AppchainError;
    use poker_appchain::fee::FeePolicy;
    use poker_appchain::note::AssetClass;
    use poker_appchain::settlement::{
        archive_has_protocol_rows, classify_hand_binding, hand_binding_v2, parse_archive_scope,
        validate_settlement, HandBindingFormat, STATE_IMAGE_DECK_COMMITMENT_OFFSET,
        STATE_IMAGE_POT_OFFSET, STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
    };

    let (_witnesses, archive, receipt, deck_chain) = proven_full_chain();
    let archive_bytes = borsh::to_vec(&archive).expect("archive borsh");

    // ===== (1) 真实归档 → scope 逐字段钉扎（排队清单 §3-2 收口）=====
    let scope = parse_archive_scope(&archive_bytes).expect("real archive parses as scope prefix");
    assert_eq!(scope.table_id, TABLE_ID);
    assert_eq!(scope.transition_count, 13);
    assert_eq!(scope.first_transition_kind, 7, "SubmitShuffle opens the chain");
    assert_eq!(scope.last_transition_kind, 19, "AdvanceRound settles the segment");
    assert_eq!(scope.batch_digest, receipt.batch_digest);
    let blind = scope.blind_opening.expect("RevealComplete posts the blind opening");
    assert_eq!((blind.small_blind, blind.big_blind, blind.ante_mode, blind.ante_amount), (SB, BB, 0, 0));
    assert!(scope.rake_opening.is_none(), "no raked-award terminal in this batch");
    assert_eq!(
        scope.log_size, 8,
        "full-chain single hand stays inside the log-8 domain"
    );
    // 镜像锚（真实归档字节上的偏移钉扎）：
    let post_pot = u64::from_le_bytes(
        scope.post_state_image_bytes[STATE_IMAGE_POT_OFFSET..][..8].try_into().unwrap(),
    );
    assert_eq!(post_pot, GROSS_POT, "terminal image pot == collected wagers");
    let pre_deck: [u8; 32] = scope.pre_state_image_bytes
        [STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32]
        .try_into()
        .unwrap();
    let post_deck: [u8; 32] = scope.post_state_image_bytes
        [STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32]
        .try_into()
        .unwrap();
    assert_ne!(pre_deck, post_deck, "batch contains shuffle rotations");
    assert_eq!(
        post_deck,
        deck_chain[deck_chain.len() - 1],
        "terminal deck anchor == last chain entry"
    );
    assert_ne!(
        &scope.post_state_image_bytes[STATE_IMAGE_REVEAL_COMMITMENT_OFFSET..][..32],
        &[0u8; 32][..],
        "reveal ledger is live at the AdvanceRound terminal"
    );
    // 端点镜像承诺读回与上游 witness 端点一致（镜像 v5 布局的真实归档证据）
    assert_eq!(scope.pre_state_image_bytes.len(), 1_680);
    assert_eq!(scope.post_state_image_bytes.len(), 1_680);

    // ===== (2) 消费侧正例（PLAY）+ (3) 11b-f fail-closed 负例（REAL）=====
    let binding_v2 = hand_binding_v2(&scope).unwrap();
    assert_eq!(
        classify_hand_binding(&consumer_record(AssetClass::Play, binding_v2, &archive_bytes, &scope), &scope)
            .unwrap(),
        HandBindingFormat::HandBindingV2
    );
    let play_record = consumer_record(AssetClass::Play, binding_v2, &archive_bytes, &scope);
    validate_settlement(&play_record, &FeePolicy::Zero)
        .expect("real-archive-backed PLAY full-chain settlement must be accepted");

    // REAL × 协议行 → 11b-f fail-closed（阶段 0 负面发现的链侧执行）。
    let real_record = consumer_record(AssetClass::Real, binding_v2, &archive_bytes, &scope);
    assert!(archive_has_protocol_rows(&scope).unwrap(), "this archive carries protocol rows");
    let err = validate_settlement(&real_record, &FeePolicy::Zero).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)"
            )
        ),
        "11b-f got {err:?}"
    );

    // ===== (4) 导出夹具（只读复制到 poker-appchain/tests/fixtures/）=====
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../poker-appchain/tests/fixtures");
    std::fs::create_dir_all(&fixtures).expect("fixtures dir");
    std::fs::write(fixtures.join("stage0_full_chain.archive.bin"), &archive_bytes)
        .expect("archive fixture write");
    let mut meta = String::new();
    meta.push_str("{\n");
    meta.push_str(&format!("  \"batch_digest\": \"{}\",\n", hex(&archive.batch_digest)));
    meta.push_str(&format!("  \"deck_chain_digest\": \"{}\",\n", hex(&receipt.deck_chain_digest)));
    meta.push_str(&format!("  \"engine_receipt_digest\": \"{}\",\n", hex(&receipt.engine_receipt_digest)));
    meta.push_str(&format!("  \"reveal_chain_digest\": \"{}\",\n", hex(&receipt.reveal_chain_digest)));
    meta.push_str(&format!("  \"reconstruct_chain_digest\": \"{}\",\n", hex(&receipt.reconstruct_chain_digest)));
    meta.push_str(&format!("  \"statement_count\": {},\n", receipt.statement_digests.len()));
    meta.push_str(&format!("  \"table_id\": {TABLE_ID},\n"));
    meta.push_str(&format!("  \"transition_count\": {},\n", scope.transition_count));
    meta.push_str(&format!("  \"first_transition_kind\": {},\n", scope.first_transition_kind));
    meta.push_str(&format!("  \"last_transition_kind\": {},\n", scope.last_transition_kind));
    meta.push_str(&format!("  \"pot\": {GROSS_POT},\n"));
    meta.push_str(&format!("  \"log_size\": {},\n", scope.log_size));
    meta.push_str(&format!("  \"post_state_commitment\": \"{}\",\n", hex(&scope.post_state_commitment)));
    meta.push_str(&format!("  \"pre_state_root\": \"{}\",\n", hex(&scope.pre_state_root)));
    meta.push_str(&format!("  \"post_state_root\": \"{}\",\n", hex(&scope.post_state_root)));
    meta.push_str("  \"deck_chain\": [\n");
    for (index, anchor) in deck_chain.iter().enumerate() {
        let comma = if index + 1 == deck_chain.len() { "" } else { "," };
        meta.push_str(&format!("    \"{}\"{comma}\n", hex(anchor)));
    }
    meta.push_str("  ]\n}\n");
    std::fs::write(fixtures.join("stage0_full_chain.json"), meta).expect("meta fixture write");
    println!("[stage0-consume] fixtures exported to {}", fixtures.display());
}

/// 消费侧结算记录构造（真实归档绑定）：2 输入 seat note（100 + 300 =
/// GROSS_POT）→ 单赢家 payout；hand_binding 由调用方给定（v2 / 其他），
/// hand_proof 绑定真实归档字节与声明根；签名按 settle_effect 全量重签
/// （settle_effect 覆盖 hand_binding 字节 → 换绑定必然重签）。
fn consumer_record(
    class: poker_appchain::note::AssetClass,
    hand_binding: [u8; 32],
    archive_bytes: &[u8],
    scope: &poker_appchain::settlement::TexasArchiveScope,
) -> poker_appchain::settlement::SettlementRecord {
    use poker_appchain::fee::FeePolicy;
    use poker_appchain::keys::{spend_digest, EcdsaSig, OwnerKey};
    use poker_appchain::note::{Note, NoteSpec};
    use poker_appchain::settlement::{
        flat_settlement_plan, settle_effect, settle_spend_scope, HandProofBinding, RakeSplitRecord,
        SettleInput, SettlementRecord, SpendAuth,
    };

    const GROSS_POT: u64 = 400;
    let policy = FeePolicy::Zero;
    let key_a = OwnerKey::from_seed(&[0xA1; 32]).unwrap();
    let key_b = OwnerKey::from_seed(&[0xB2; 32]).unwrap();
    let keys = [key_a, key_b];
    let secrets: [[u8; 32]; 2] = [[0xA1; 32], [0xB2; 32]];
    let amounts = [100u64, 300u64];
    let nonces = [[0xE1; 32], [0xE2; 32]];

    let mut record = SettlementRecord {
        table_id: TABLE_ID,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot: GROSS_POT,
        inputs: Vec::with_capacity(2),
        payouts: vec![NoteSpec {
            asset_class: class,
            amount: GROSS_POT,
            owner: keys[0].public_bytes(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        }],
        rake: RakeSplitRecord { total: 0, treasury_out: None, operator_out: None },
        plan: flat_settlement_plan(GROSS_POT, 0b11, {
            let mut awards = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
            awards[0] = GROSS_POT;
            awards
        }),
        hand_proof: Some(HandProofBinding {
            archive_bytes: archive_bytes.to_vec(),
            post_state_commitment: scope.post_state_commitment,
            pre_state_root: scope.pre_state_root,
            post_state_root: scope.post_state_root,
        }),
    };
    for index in 0..2 {
        let note = Note::new(class, amounts[index], keys[index].public_bytes(), nonces[index], Some(TABLE_ID))
            .unwrap();
        let commitment = note.commitment_bytes();
        let nf = poker_appchain::felt::felt_to_bytes32(&note.nullifier(&secrets[index]));
        record.inputs.push(SettleInput {
            note,
            spend: SpendAuth { commitment, nullifier: nf, sig: EcdsaSig { bytes: [0; 64] } },
        });
    }
    let effect = settle_effect(&record);
    for (input, key) in record.inputs.iter_mut().zip(keys.iter()) {
        let d = spend_digest(
            &input.spend.commitment,
            &input.spend.nullifier,
            &settle_spend_scope(&record.hand_binding),
            &effect,
        );
        input.spend.sig = key.sign(&d);
    }
    record
}
