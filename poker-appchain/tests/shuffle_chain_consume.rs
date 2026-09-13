//! 洗牌/发牌证明链**消费侧**验收（ABI v1.3，设计文档
//! `docs/shuffle-deal-proof-design.md` §5-C2/C3 + 路线 A/B 消费半边）。
//!
//! 本文件的用例**不触碰进程级开关**（迁移窗 / receipt 门默认关——既有
//! v1 流量零回退的双轨迁移期语义）；开关矩阵见
//! `shuffle_chain_gate.rs`（独立测试二进制，避免原子量竞态）。
//!
//! 负例矩阵（≥8 类，全部断言**精确拒绝消息**）：
//! | # | 类别 | 拒绝点 |
//! |---|---|---|
//! | N1 | 首 kind 不符（非链入口） | 11b-a |
//! | N2 | 末 kind 不符（非结算语义） | 11b-b |
//! | N3 | blind_opening 缺失 | 11b-c |
//! | N4 | blind_opening ante_mode 越界 | 11b-c |
//! | N5 | blind_opening 全零（空洞 opening） | 11b-c |
//! | N6 | pre 镜像 deck 锚为零（S1 缺失） | 11b-d |
//! | N7 | 终态 reveal 承诺为零（发牌未覆盖） | 11b-e |
//! | N8 | receipt 集缺回执 | 覆盖记账 |
//! | N9 | receipt 集含未知语句 | 覆盖记账 |
//! | N10 | receipt 集重复语句 / 零 digest / 数额不符 | 覆盖记账 |
//! | N11 | deck 锚断裂（换锚后 v2 绑定失配，分类降级） | 11a 分类 |
//! | N12 | REAL 类 + 含协议行归档（无路线 A 原生校验凭据） | 11b-f（阶段 0
//!   负面发现的 fail-closed 执行，SHUFFLE_STAGE0.md §3.4-2） |

#![allow(clippy::too_many_arguments)]

mod common;

use common::{rake_policy, two_player_settlement, TestUser};
use poker_appchain::error::AppchainError;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::settlement::{
    classify_hand_binding, crypto_statement_digest, expected_crypto_statements,
    hand_binding_v2, parse_archive_scope, validate_settlement, verify_receipt_set,
    BlindOpeningScope, CryptoVerifierReceipt, HandBindingFormat, HandProofBinding,
    RakeOpeningScope, SettlementRecord, TexasArchiveScope, CANONICAL_STATE_IMAGE_BORSH_BYTES,
    KIND_ADVANCE_ROUND, KIND_AUTO_FOLD, KIND_JOIN_TABLE, KIND_RAISE,
    KIND_REVEAL_TIMEOUT_RAKED_AWARD, KIND_SUBMIT_SHUFFLE, SETTLEMENT_TERMINAL_KINDS,
    STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET, STATE_IMAGE_DECK_COMMITMENT_OFFSET,
    STATE_IMAGE_POT_OFFSET, STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET,
    STATE_IMAGE_REVEAL_COMMITMENT_OFFSET, STATEMENT_KIND_REVEAL, STATEMENT_KIND_SHUFFLE,
};
use poker_settlement_core::DECK_CHAIN_DIGEST_DOMAIN;

// ===== scope 夹具 =====

/// 归档 scope 规格（消费校验的全部判据面）。
struct ScopeSpec {
    first_kind: u8,
    last_kind: u8,
    transition_count: u16,
    pre_deck: [u8; 32],
    post_deck: [u8; 32],
    /// 起始帧 reveal 承诺（真实续批批段承继上一批终态；默认零 = hand-start）。
    pre_reveal: [u8; 32],
    post_reveal: [u8; 32],
    post_reconstruct: [u8; 32],
    blind: Option<BlindOpeningScope>,
    rake: Option<RakeOpeningScope>,
    pot: u64,
    batch_digest: [u8; 32],
    pre_root: [u8; 32],
    post_root: [u8; 32],
}

/// 全链批正例规格：JoinTable → … → AdvanceRound（批内含洗牌段：
/// pre.deck ≠ post.deck），blind opening 在位，reveal 承诺非零。
fn full_chain_spec() -> ScopeSpec {
    ScopeSpec {
        first_kind: KIND_JOIN_TABLE,
        last_kind: KIND_ADVANCE_ROUND,
        transition_count: 12,
        pre_deck: [0xAA; 32],
        post_deck: [0xBB; 32],
        pre_reveal: [0; 32],
        post_reveal: [0xCC; 32],
        post_reconstruct: [0; 32],
        blind: Some(BlindOpeningScope {
            small_blind: 50,
            big_blind: 100,
            ante_mode: 0,
            ante_amount: 0,
        }),
        rake: None,
        pot: 3_000,
        batch_digest: [0x42; 32],
        pre_root: [0x11; 32],
        post_root: [0x22; 32],
    }
}

/// 按规格构造归档字节（canonical 布局 scope v2 前缀 + 定宽镜像）。
fn scope_bytes(spec: &ScopeSpec) -> Vec<u8> {
    let mut pre = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
    let mut post = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
    for (image, deck) in [(&mut pre, spec.pre_deck), (&mut post, spec.post_deck)] {
        image[STATE_IMAGE_POT_OFFSET..][..8].copy_from_slice(&spec.pot.to_le_bytes());
        image[STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32].copy_from_slice(&deck);
    }
    pre[STATE_IMAGE_REVEAL_COMMITMENT_OFFSET..][..32].copy_from_slice(&spec.pre_reveal);
    post[STATE_IMAGE_REVEAL_COMMITMENT_OFFSET..][..32]
        .copy_from_slice(&spec.post_reveal);
    post[STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET..][..32]
        .copy_from_slice(&spec.post_reconstruct);
    let scope = TexasArchiveScope {
        log_size: 9,
        num_columns: 1_574,
        table_id: 1,
        first_hand_id: 1,
        last_hand_id: 1,
        first_call_seq: 0,
        last_call_seq: 11,
        transition_count: spec.transition_count,
        first_transition_kind: spec.first_kind,
        last_transition_kind: spec.last_kind,
        reveal_timeout_cascade_count: 0,
        reveal_timeout_cascade_schedule: [u8::MAX; 9],
        batch_digest: spec.batch_digest,
        pre_state_commitment: [3; 32],
        post_state_commitment: [4; 32],
        pre_state_root: spec.pre_root,
        post_state_root: spec.post_root,
        pre_lifecycle_root: [0; 32],
        post_lifecycle_root: [0; 32],
        pre_overlay_root: [0; 32],
        post_overlay_root: [0; 32],
        pre_settlement_commitment: [0; 32],
        post_settlement_commitment: [0; 32],
        pre_custody_commitment: [0; 32],
        post_custody_commitment: [0; 32],
        pre_state_image_bytes: pre,
        post_state_image_bytes: post,
        range_claimed_sum: [0; 4],
        rake_opening: spec.rake,
        blind_opening: spec.blind,
    };
    borsh::to_vec(&scope).unwrap()
}

fn binding_for(spec: &ScopeSpec) -> [u8; 32] {
    let bytes = scope_bytes(spec);
    let scope = parse_archive_scope(&bytes).unwrap();
    hand_binding_v2(&scope).unwrap()
}

/// 结算记录 + 归档绑定的完整构造：hand_binding 升域为 v2 并对效果重签
/// （settle_effect 覆盖 hand_binding 字节——升域必然重签）。
fn v2_record_bound_to(
    spec: &ScopeSpec,
    a: &TestUser,
    b: &TestUser,
    seat_a: &Note,
    seat_b: &Note,
    policy: &poker_appchain::fee::FeePolicy,
) -> SettlementRecord {
    let mut record =
        two_player_settlement(1, a, b, seat_a, seat_b, 3_000, 500, 2_350, policy, 0x56);
    record.hand_binding = binding_for(spec);
    record.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(spec),
        post_state_commitment: [4; 32],
        pre_state_root: spec.pre_root,
        post_state_root: spec.post_root,
    });
    record.inputs[0].spend = a.settle_auth(seat_a, &record);
    record.inputs[1].spend = b.settle_auth(seat_b, &record);
    record
}

fn seats() -> (TestUser, TestUser, Note, Note) {
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let seat_a = Note::new(AssetClass::Real, 1_000, a.pk(), [0x71; 32], Some(1)).unwrap();
    let seat_b = Note::new(AssetClass::Real, 2_000, b.pk(), [0x72; 32], Some(1)).unwrap();
    (a, b, seat_a, seat_b)
}

/// PLAY 类座位（娱乐筹码）：11b-f（REAL × 协议行 fail-closed）只约束 REAL
/// 类——v2 绑定/布局语义正例用本构造承载（REAL 侧正例 = 无协议行批段，
/// 见 `real_no_protocol_rows_v2_accepted`）。
fn seats_play() -> (TestUser, TestUser, Note, Note) {
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let seat_a = Note::new(AssetClass::Play, 1_000, a.pk(), [0x71; 32], Some(1)).unwrap();
    let seat_b = Note::new(AssetClass::Play, 2_000, b.pk(), [0x72; 32], Some(1)).unwrap();
    (a, b, seat_a, seat_b)
}

// ===== 布局钉扎 =====

/// 镜像偏移回归钉：按 ABI.md 记录的 `CanonicalStateImage` v5 字段序
/// （独立手写编码器）播种可识别字节，断言本 crate 常量读回一致。
/// 真实归档（poker_texas_air 编码器输出）的逐字段钉扎属适配器测试
/// 职责（排队清单见 docs/SHUFFLE_CONSUME.md）。
#[test]
fn state_image_commitment_offsets_match_documented_layout() {
    // 独立编码器：字段序 = abi_version u16, table_id u64, hand_id u32,
    // call_seq u32, phase u8, phase_subtag u8, street u8, current_turn u8,
    // deadline u64, 5×timeout u32, current_bet u64, min_raise u64,
    // chip_pool u64, pot u64, button u8, max_players u8, acted u16,
    // leave u16, pending u16, board/deck/reveal/reconstruction [u8;32]×4, …
    let mut image = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
    let put = |img: &mut Vec<u8>, off: usize, bytes: &[u8]| {
        img[off..off + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut image, 0, &5u16.to_le_bytes()); // abi_version
    put(&mut image, 2, &7u64.to_le_bytes()); // table_id
    put(&mut image, 10, &1u32.to_le_bytes()); // hand_id
    put(&mut image, 14, &9u32.to_le_bytes()); // call_seq
    image[18] = 4; // phase（枚举判别值不影响后续定宽标量偏移）
    image[19] = 1; // phase_subtag
    image[20] = 2; // street
    image[21] = 3; // current_turn
    put(&mut image, 22, &99u64.to_le_bytes()); // deadline_ms
    for (i, off) in [30usize, 34, 38, 42, 46].into_iter().enumerate() {
        put(&mut image, off, &(100 + i as u64).to_le_bytes()); // timeouts
    }
    put(&mut image, 50, &200u64.to_le_bytes()); // current_bet
    put(&mut image, 58, &201u64.to_le_bytes()); // min_raise
    put(&mut image, 66, &202u64.to_le_bytes()); // chip_pool（既有锚）
    put(&mut image, 74, &203u64.to_le_bytes()); // pot（既有锚）
    image[82] = 0; // button
    image[83] = 9; // max_players
    put(&mut image, 84, &0x0102u16.to_le_bytes()); // acted_mask
    put(&mut image, 86, &0x0304u16.to_le_bytes()); // leave_after_hand_mask
    put(&mut image, 88, &0x0506u16.to_le_bytes()); // protocol_pending_mask
    put(&mut image, STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET, &[0xB0; 32]);
    put(&mut image, STATE_IMAGE_DECK_COMMITMENT_OFFSET, &[0xD1; 32]);
    put(&mut image, STATE_IMAGE_REVEAL_COMMITMENT_OFFSET, &[0xE1; 32]);
    put(&mut image, STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET, &[0xF1; 32]);

    let read32 = |off: usize| -> [u8; 32] {
        image[off..off + 32].try_into().unwrap()
    };
    assert_eq!(
        u64::from_le_bytes(image[66..74].try_into().unwrap()),
        202,
        "chip_pool anchor drifted"
    );
    assert_eq!(
        u64::from_le_bytes(image[74..82].try_into().unwrap()),
        203,
        "pot anchor drifted"
    );
    assert_eq!(read32(STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET), [0xB0; 32]);
    assert_eq!(read32(STATE_IMAGE_DECK_COMMITMENT_OFFSET), [0xD1; 32]);
    assert_eq!(read32(STATE_IMAGE_REVEAL_COMMITMENT_OFFSET), [0xE1; 32]);
    assert_eq!(read32(STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET), [0xF1; 32]);
    // 座位区预算：1_680 − 474（前缀+承诺区）= 1_206 = 9 × 134
    // （reconstruction 之后还有 8 个 32B 承诺字段：run_it_twice / rules /
    // governance / settlement / custody / lifecycle_root / overlay_root /
    // state_root）
    assert_eq!(
        CANONICAL_STATE_IMAGE_BORSH_BYTES
            - (STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET + 32 + 32 * 8),
        1_206,
        "seat-area budget drifted (9 seats × 134B)"
    );
}

// ===== 正例 =====

/// 含 deck 链的全链批结算被接受（路线 A 消费半边主正例）：v2 绑定 +
/// JoinTable→AdvanceRound + blind opening + deck/reveal 锚齐备。PLAY 类
/// （REAL × 协议行的 fail-closed 见 N12——本正例证明的是绑定/布局语义，
/// 不受资产类约束）。
#[test]
fn v2_full_chain_settlement_accepted() {
    let (a, b, seat_a, seat_b) = seats_play();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);

    // 分类判定：v2 优先
    let scope = parse_archive_scope(&record.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(classify_hand_binding(&record, &scope).unwrap(), HandBindingFormat::HandBindingV2);
    validate_settlement(&record, &policy).expect("full-chain v2 settlement must be accepted");
}

/// 链语义正例边界：批内无洗牌（pre.deck == post.deck，betting 段批）+
/// reveal 在位 → 单元素链，v2 绑定同样成立。
#[test]
fn v2_betting_segment_batch_with_reveal_accepted() {
    let (a, b, seat_a, seat_b) = seats_play();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.pre_deck = spec.post_deck;
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    validate_settlement(&record, &policy).expect("betting-segment v2 batch must be accepted");
}

// ===== 负例矩阵（常开部分：v2 分类成立 → 严格校验 fail-closed）=====
//
// 每个负例：篡改 scope 的**非绑定哈希覆盖面**（kind/blind 形状）时保持
// 原绑定不重算也可判 V2 吗？——不能：绑定覆盖 batch_digest/deck/reveal，
// 不覆盖 kind/blind。为使严格分支真实触发，所有负例都对篡改后 scope
// **重导 v2 绑定并重签**（记录诚实地声明"我绑定这个归档"，归档违反
// 全链语义 → 11b 拒绝）。deck/reveal 面的负例（N6/N7）同理。

/// N1：首 kind 非链入口（Raise 起批冒充全链批）。
#[test]
fn n1_first_kind_not_chain_entry_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.first_kind = KIND_RAISE; // 下注段起批 ≠ {JoinTable, StartHand, SubmitShuffle}
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "full-chain archive first transition kind is not a chain-entry kind"
            )
        ),
        "N1 got {err:?}"
    );
}

/// N2：末 kind 非结算语义（AutoFold 收尾——未收池/未分派）。
#[test]
fn n2_last_kind_not_settlement_terminal_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.last_kind = KIND_AUTO_FOLD;
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "full-chain archive last transition kind is not settlement-terminal"
            )
        ),
        "N2 got {err:?}"
    );
}

/// N2b：末 kind 集冻结边界——带 rake 超时终局在结算语义集内（正例向），
/// 而 ResetOnly(22) 不在（此处以 AutoFold 代表性覆盖；集合成员回归）。
#[test]
fn n2b_terminal_kind_set_membership_frozen() {
    assert!(SETTLEMENT_TERMINAL_KINDS.contains(&KIND_ADVANCE_ROUND));
    assert!(SETTLEMENT_TERMINAL_KINDS.contains(&KIND_REVEAL_TIMEOUT_RAKED_AWARD));
    assert!(!SETTLEMENT_TERMINAL_KINDS.contains(&22u8), "ResetOnly must stay excluded");
    assert!(!SETTLEMENT_TERMINAL_KINDS.contains(&KIND_SUBMIT_SHUFFLE));
}

/// N3：blind_opening 缺失（批含末个 SubmitReveal 却无盲注投影 →
/// 全链批冒充）。
#[test]
fn n3_missing_blind_opening_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.blind = None;
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected("full-chain archive is missing the blind opening")
        ),
        "N3 got {err:?}"
    );
}

/// N4：blind_opening ante_mode 越界（>2，未冻结判别值）。
#[test]
fn n4_blind_opening_unsupported_ante_mode_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.blind = Some(BlindOpeningScope {
        small_blind: 50,
        big_blind: 100,
        ante_mode: 3,
        ante_amount: 10,
    });
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected("blind opening has unsupported ante mode")
        ),
        "N4 got {err:?}"
    );
}

/// N5：blind_opening 全零（空洞 opening 冒充在位）。
#[test]
fn n5_vacuous_blind_opening_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.blind = Some(BlindOpeningScope {
        small_blind: 0,
        big_blind: 0,
        ante_mode: 0,
        ante_amount: 0,
    });
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected("blind opening is vacuous (all-zero blinds and ante)")
        ),
        "N5 got {err:?}"
    );
}

/// N6：pre 镜像 deck 锚为零（S1 初始牌堆绑定缺失）。
#[test]
fn n6_zero_pre_deck_commitment_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.pre_deck = [0; 32];
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "archive pre-state deck commitment is zero (S1 anchor missing)"
            )
        ),
        "N6 got {err:?}"
    );
}

/// N7：终态 reveal 承诺为零（发牌段未覆盖却声明全链结算）。
#[test]
fn n7_zero_terminal_reveal_commitment_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    spec.post_reveal = [0; 32];
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "archive terminal reveal commitment is zero (deal not covered)"
            )
        ),
        "N7 got {err:?}"
    );
}

// ===== N12 + REAL 边界：阶段 0 负面发现的消费侧 fail-closed（11b-f）=====
//
// 上游 stage0 实测（SHUFFLE_STAGE0.md §3.4-2）：canonical AIR 对非末段
// shuffle 行 deck 承诺篡改照常出证（只冻结锚，不重算密文哈希）——含协议行
// 的 REAL 结算必须经路线 A 原生校验（引擎侧），结算纯函数层不可自证 ⇒
// 直接拒绝该批（无开关；引擎 receipt 归责接线后升级为回执集验证）。

/// N12：REAL 类 + 含协议行归档（批内 deck 轮转 = 协议行在批）→ fail-closed
/// 拒绝（精确消息）。
#[test]
fn n12_real_settlement_with_protocol_rows_rejected() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec(); // pre.deck ≠ post.deck ⇒ 协议行在批
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let err = validate_settlement(&record, &policy).unwrap_err();
    assert!(
        matches!(
            err,
            AppchainError::AdmissionRejected(
                "REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)"
            )
        ),
        "N12 got {err:?}"
    );
}

/// N12 控制面：同批形状的 PLAY 类不受 11b-f 约束（布局/绑定语义正例照旧）。
#[test]
fn play_settlement_with_protocol_rows_still_accepted() {
    let (a, b, seat_a, seat_b) = seats_play();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    validate_settlement(&record, &policy).expect("PLAY class is out of 11b-f scope");
}

/// REAL 正例边界：**无协议行**的 REAL 批段（reveal 承诺承继上一批终态、
/// 批内零轮转、kind 全下注）照常接受——11b-f 只拦协议行批，不拦 REAL。
#[test]
fn real_no_protocol_rows_v2_accepted() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let mut spec = full_chain_spec();
    // 起批保持 JoinTable（11b-a 链入口集内）；批内形状 = 纯下注批
    // （11b-a/b/c/d 全过），仅靠 11b-e 要求终态 reveal 非零 ⇒ 承继上一批。
    spec.pre_deck = spec.post_deck; // 批内无洗牌
    spec.pre_reveal = [0xCC; 32]; // reveal 承诺承继上一批终态（批内零轮转）
    spec.post_reveal = [0xCC; 32];
    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    let scope = parse_archive_scope(&record.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert!(
        !poker_appchain::settlement::archive_has_protocol_rows(&scope).unwrap(),
        "fixture must be protocol-free"
    );
    validate_settlement(&record, &policy)
        .expect("REAL settlement of a protocol-free batch must be accepted");
}

/// 迁移窗诚实边界：REAL + 协议行 + **Legacy** 绑定在窗内仍接受（v1 双轨
/// 语义，本就允许绑定与归档无关系；窗关闭后拒绝 = G3/G4 路径）。此处
/// 钉住"11b-f 不扩大化到旧格式"的冻结边界。
#[test]
fn real_protocol_rows_legacy_binding_still_window_accepted() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let mut record =
        two_player_settlement(1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, 0x77);
    record.hand_binding = spec.batch_digest;
    record.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(&spec),
        post_state_commitment: [4; 32],
        pre_state_root: spec.pre_root,
        post_state_root: spec.post_root,
    });
    record.inputs[0].spend = a.settle_auth(&seat_a, &record);
    record.inputs[1].spend = b.settle_auth(&seat_b, &record);
    let scope = parse_archive_scope(&record.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(classify_hand_binding(&record, &scope).unwrap(), HandBindingFormat::LegacyBatchDigest);
    validate_settlement(&record, &policy)
        .expect("11b-f is v2-scoped; legacy stays on migration-window semantics");
}

// ===== 11a 双轨：迁移期旧格式接受并计数（不触碰开关的默认态）=====

/// Legacy 形态（hand_binding == batch_digest，v1 e2e 形态）迁移期接受，
/// 计数器前进（告警口径①）。
#[test]
fn legacy_batch_digest_binding_accepted_and_counted() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let mut record =
        two_player_settlement(1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, 0x77);
    record.hand_binding = spec.batch_digest;
    record.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(&spec),
        post_state_commitment: [4; 32],
        pre_state_root: spec.pre_root,
        post_state_root: spec.post_root,
    });
    record.inputs[0].spend = a.settle_auth(&seat_a, &record);
    record.inputs[1].spend = b.settle_auth(&seat_b, &record);
    let scope = parse_archive_scope(&record.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(
        classify_hand_binding(&record, &scope).unwrap(),
        HandBindingFormat::LegacyBatchDigest
    );
    let before = poker_appchain::settlement::legacy_binding_accept_count();
    validate_settlement(&record, &policy)
        .expect("legacy batch-digest binding must be accepted in the migration window");
    assert!(
        poker_appchain::settlement::legacy_binding_accept_count() >= before + 1,
        "legacy acceptance counter must advance"
    );
}

/// Unbound 形态（绑定与归档无关系，v1 语义遗留）迁移期接受并计数
/// （告警口径②）。deck 锚断裂攻击在此窗内**只会降级分类、不会拒绝**——
/// 迁移窗关闭后拒绝，见 shuffle_chain_gate.rs（诚实边界，SHUFFLE_CONSUME.md）。
#[test]
fn unbound_binding_accepted_and_counted_during_migration() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let mut record =
        two_player_settlement(1, &a, &b, &seat_a, &seat_b, 3_000, 500, 2_350, &policy, 0x88);
    // hand_binding = [0x88;32]（two_player_settlement 默认）≠ batch_digest ≠ v2
    record.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(&spec),
        post_state_commitment: [4; 32],
        pre_state_root: spec.pre_root,
        post_state_root: spec.post_root,
    });
    record.inputs[0].spend = a.settle_auth(&seat_a, &record);
    record.inputs[1].spend = b.settle_auth(&seat_b, &record);
    let scope = parse_archive_scope(&record.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(classify_hand_binding(&record, &scope).unwrap(), HandBindingFormat::Unbound);
    let before = poker_appchain::settlement::unbound_binding_accept_count();
    validate_settlement(&record, &policy)
        .expect("unbound legacy record must be accepted during the migration window");
    assert!(
        poker_appchain::settlement::unbound_binding_accept_count() >= before + 1,
        "unbound acceptance counter must advance"
    );
}

// ===== N11 + 路线 A 敏感性：deck 锚断裂改变 v2 绑定 =====

/// N11：换锚（post.deck 篡改）→ v2 绑定失配（分类降级 Unbound）。
/// v2 绑定对 deck 链的密码学敏感性是"结算 hand 续自 deck 承诺链"的
/// 判定前提；迁移窗内的接受语义与关闭后拒绝见 gate 文件。
#[test]
fn n11_deck_anchor_break_shifts_classification() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let mut tampered = full_chain_spec();
    tampered.post_deck = [0xFF; 32]; // 断链：承诺链末端被换
    assert_ne!(binding_for(&spec), binding_for(&tampered), "v2 binding must be deck-anchor sensitive");

    let record = v2_record_bound_to(&spec, &a, &b, &seat_a, &seat_b, &policy);
    // 记录按 A 归档绑定，但出示 B 归档（换锚归档）
    let mut record_b = record.clone();
    record_b.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(&tampered),
        post_state_commitment: [4; 32],
        pre_state_root: tampered.pre_root,
        post_state_root: tampered.post_root,
    });
    let scope_b =
        parse_archive_scope(&record_b.hand_proof.as_ref().unwrap().archive_bytes).unwrap();
    assert_eq!(
        classify_hand_binding(&record_b, &scope_b).unwrap(),
        HandBindingFormat::Unbound,
        "cross-archive deck-anchor assembly must not classify as v2"
    );
}

/// hand_binding v2 与 v1 值域分离：v2(scope) ≠ batch_digest（同 scope），
/// 且与上游 Poseidon 域标签无碰撞面（域标签独立冻结）。
#[test]
fn v2_binding_is_domain_separated_from_legacy_values() {
    let spec = full_chain_spec();
    let scope = parse_archive_scope(&scope_bytes(&spec)).unwrap();
    let v2 = hand_binding_v2(&scope).unwrap();
    assert_ne!(v2, scope.batch_digest);
    // 链摘要域独立于 payout/side_pot/plan 域（settlement-core 冻结表）
    assert_ne!(DECK_CHAIN_DIGEST_DOMAIN, b"zchain.settlement.payout_root.v1");
    assert_ne!(DECK_CHAIN_DIGEST_DOMAIN, b"zchain.settlement.side_pot_root.v1");
}

// ===== 路线 B：语句面 + receipt 覆盖记账（占位结构，无密码学验证）=====

/// 语句面推导：洗牌段批（pre≠post deck + reveal 非零）→ {shuffle, reveal}
/// 两条；betting 段批（pre==post deck、reveal 零）→ 空集。
#[test]
fn expected_statements_follow_protocol_coverage() {
    let full = parse_archive_scope(&scope_bytes(&full_chain_spec())).unwrap();
    let stmts = expected_crypto_statements(&full).unwrap();
    assert_eq!(stmts.len(), 2, "shuffle + reveal statements expected");
    assert_eq!(
        stmts[0],
        crypto_statement_digest(STATEMENT_KIND_SHUFFLE, &[[0xAA; 32], [0xBB; 32]]),
    );
    assert_eq!(
        stmts[1],
        crypto_statement_digest(STATEMENT_KIND_REVEAL, &[[0xBB; 32], [0xCC; 32]]),
    );

    let mut betting = full_chain_spec();
    betting.pre_deck = betting.post_deck;
    betting.post_reveal = [0; 32];
    let empty = parse_archive_scope(&scope_bytes(&betting)).unwrap();
    assert!(expected_crypto_statements(&empty).unwrap().is_empty());
}

/// N8–N10：覆盖记账负例矩阵（缺回执/未知语句/重复/零 digest/数额不符）。
#[test]
fn receipt_set_coverage_matrix() {
    let stmts = [
        crypto_statement_digest(STATEMENT_KIND_SHUFFLE, &[[0xAA; 32], [0xBB; 32]]),
        crypto_statement_digest(STATEMENT_KIND_REVEAL, &[[0xBB; 32], [0xCC; 32]]),
    ];
    let receipt = |statement: [u8; 32], receipt_digest: [u8; 32]| CryptoVerifierReceipt {
        statement_digest: statement,
        receipt_digest,
    };
    let good = [
        receipt(stmts[0], [1; 32]),
        receipt(stmts[1], [2; 32]),
    ];
    verify_receipt_set(&stmts, &good).expect("complete receipt set must pass");

    // N8：缺回执（数额不符形态；含未知回执的换包按 N9 优先诊断）
    let err = verify_receipt_set(&stmts, &good[..1]).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("crypto receipt count does not match expected statement count")
    ));

    // N9：未知语句（换包/多余回执——先于数额与缺失诊断）
    let unknown = [receipt(stmts[0], [1; 32]), receipt([0xAD; 32], [2; 32])];
    let err = verify_receipt_set(&stmts, &unknown).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("crypto receipt set contains an unknown statement")
    ));

    // N10a：重复语句
    let dup = [receipt(stmts[0], [1; 32]), receipt(stmts[0], [3; 32])];
    let err = verify_receipt_set(&[stmts[0]], &dup).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("crypto receipt set contains duplicate statements")
    ));

    // N10b：零 receipt digest
    let zero = [receipt(stmts[0], [0; 32])];
    let err = verify_receipt_set(&[stmts[0]], &zero).unwrap_err();
    assert!(matches!(
        err,
        AppchainError::AdmissionRejected("crypto receipt digest is zero")
    ));
}
