//! 洗牌/发牌证明链消费侧——**进程级开关矩阵**（迁移窗 / receipt 门）。
//!
//! 开关是进程级原子量（`settlement::set_full_chain_enforcement` /
//! `set_crypto_receipt_enforcement`）。本文件是**独立测试二进制**，内部
//! 只有一个按序执行的用例（避免同进程并行测试的开关竞态），结束时经
//! Drop 守卫复原默认态（关）。
//!
//! 矩阵：
//! | # | 迁移窗 | receipt 门 | 记录形态 | 期望 |
//! |---|---|---|---|---|
//! | G1 | 关 | 关 | Legacy / Unbound | 接受（双轨迁移，默认零回退） |
//! | G2 | 关 | 关 | v2 | 接受 + 全链强制 |
//! | G3 | 开 | 关 | Legacy | **拒绝**（迁移窗关闭） |
//! | G4 | 开 | 关 | Unbound | **拒绝** |
//! | G5 | 开 | 关 | v2 | 接受 |
//! | G6 | 开 | 关 | v2 绑定 + 换锚归档（deck 断链拼装） | **拒绝** |
//! | G7 | 关 | 开 | v2 | **拒绝**（receipt 集成待上游 stage0——不许假验证） |
//! | G8 | 关 | 开 | Legacy | 接受（门只作用于声明 deck 链的 v2 记录） |

mod common;

use common::{rake_policy, two_player_settlement, TestUser};
use poker_appchain::error::AppchainError;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::settlement::{
    classify_hand_binding, crypto_receipt_enforcement, full_chain_enforcement, hand_binding_v2,
    parse_archive_scope, set_crypto_receipt_enforcement, set_full_chain_enforcement,
    validate_settlement,
    BlindOpeningScope, HandBindingFormat, HandProofBinding, TexasArchiveScope,
    CANONICAL_STATE_IMAGE_BORSH_BYTES, KIND_ADVANCE_ROUND, KIND_JOIN_TABLE,
    STATE_IMAGE_DECK_COMMITMENT_OFFSET, STATE_IMAGE_POT_OFFSET,
    STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
};

/// 进程级开关复原守卫（drop 时一律关闭，保证测试失败也不污染后续）。
struct GatesOpen;
impl GatesOpen {
    fn both() -> Self {
        set_full_chain_enforcement(true);
        set_crypto_receipt_enforcement(true);
        Self
    }
    fn migration_only() -> Self {
        set_full_chain_enforcement(true);
        set_crypto_receipt_enforcement(false);
        Self
    }
    fn receipt_only() -> Self {
        set_full_chain_enforcement(false);
        set_crypto_receipt_enforcement(true);
        Self
    }
}
impl Drop for GatesOpen {
    fn drop(&mut self) {
        set_full_chain_enforcement(false);
        set_crypto_receipt_enforcement(false);
    }
}

struct Spec {
    post_deck: [u8; 32],
    batch_digest: [u8; 32],
}

fn full_chain_spec() -> Spec {
    Spec { post_deck: [0xBB; 32], batch_digest: [0x42; 32] }
}

fn scope_bytes(spec: &Spec) -> Vec<u8> {
    let mut pre = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
    let mut post = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
    for (image, deck) in [(&mut pre, [0xAAu8; 32]), (&mut post, spec.post_deck)] {
        image[STATE_IMAGE_POT_OFFSET..][..8].copy_from_slice(&3_000u64.to_le_bytes());
        image[STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32].copy_from_slice(&deck);
    }
    post[STATE_IMAGE_REVEAL_COMMITMENT_OFFSET..][..32].copy_from_slice(&[0xCC; 32]);
    let scope = TexasArchiveScope {
        log_size: 9,
        num_columns: 1_574,
        table_id: 1,
        first_hand_id: 1,
        last_hand_id: 1,
        first_call_seq: 0,
        last_call_seq: 11,
        transition_count: 12,
        first_transition_kind: KIND_JOIN_TABLE,
        last_transition_kind: KIND_ADVANCE_ROUND,
        reveal_timeout_cascade_count: 0,
        reveal_timeout_cascade_schedule: [u8::MAX; 9],
        batch_digest: spec.batch_digest,
        pre_state_commitment: [3; 32],
        post_state_commitment: [4; 32],
        pre_state_root: [0x11; 32],
        post_state_root: [0x22; 32],
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
        rake_opening: None,
        blind_opening: Some(BlindOpeningScope {
            small_blind: 50,
            big_blind: 100,
            ante_mode: 0,
            ante_amount: 0,
        }),
    };
    borsh::to_vec(&scope).unwrap()
}

fn scope_of(spec: &Spec) -> TexasArchiveScope {
    parse_archive_scope(&scope_bytes(spec)).unwrap()
}

/// 构造（记录, seat notes, 策略）：`mode` 决定 hand_binding 形态。
enum Mode {
    /// hand_binding = v2(spec)
    V2,
    /// hand_binding = batch_digest（v1 e2e 形态）
    Legacy,
    /// hand_binding 与归档无关系（v1 语义遗留）
    Unbound,
}

fn record_in_mode(
    mode: &Mode,
    spec: &Spec,
    a: &TestUser,
    b: &TestUser,
    seat_a: &Note,
    seat_b: &Note,
    policy: &poker_appchain::fee::FeePolicy,
) -> poker_appchain::settlement::SettlementRecord {
    let mut record =
        two_player_settlement(1, a, b, seat_a, seat_b, 3_000, 500, 2_350, policy, 0x56);
    record.hand_binding = match mode {
        Mode::V2 => hand_binding_v2(&scope_of(spec)).unwrap(),
        Mode::Legacy => spec.batch_digest,
        Mode::Unbound => [0x56; 32],
    };
    record.hand_proof = Some(HandProofBinding {
        archive_bytes: scope_bytes(spec),
        post_state_commitment: [4; 32],
        pre_state_root: [0x11; 32],
        post_state_root: [0x22; 32],
    });
    record.inputs[0].spend = a.settle_auth(seat_a, &record);
    record.inputs[1].spend = b.settle_auth(seat_b, &record);
    record
}

fn seats() -> (TestUser, TestUser, Note, Note) {
    // PLAY 类座位：本矩阵验证的是**开关语义**（迁移窗/receipt 门）；本批
    // 形状含协议行（deck 锚 [0xAA]→[0xBB] 轮转），REAL 类会先命中 11b-f
    // （REAL × 协议行 fail-closed，无开关、与门矩阵无关）污染矩阵语义。
    // 11b-f 自身的 REAL 矩阵见 shuffle_chain_consume.rs（N12 及边界）。
    let a = TestUser::new(1);
    let b = TestUser::new(2);
    let seat_a = Note::new(AssetClass::Play, 1_000, a.pk(), [0x71; 32], Some(1)).unwrap();
    let seat_b = Note::new(AssetClass::Play, 2_000, b.pk(), [0x72; 32], Some(1)).unwrap();
    (a, b, seat_a, seat_b)
}

/// 按序执行 G1..G8（同进程唯一用例——开关竞态隔离）。
#[test]
fn migration_and_receipt_gate_matrix() {
    let (a, b, seat_a, seat_b) = seats();
    let policy = rake_policy(&TestUser::new(7), &TestUser::new(8));
    let spec = full_chain_spec();
    let v2 = record_in_mode(&Mode::V2, &spec, &a, &b, &seat_a, &seat_b, &policy);
    let legacy = record_in_mode(&Mode::Legacy, &spec, &a, &b, &seat_a, &seat_b, &policy);
    let unbound = record_in_mode(&Mode::Unbound, &spec, &a, &b, &seat_a, &seat_b, &policy);
    let scope = scope_of(&spec);
    assert_eq!(classify_hand_binding(&v2, &scope).unwrap(), HandBindingFormat::HandBindingV2);
    assert_eq!(
        classify_hand_binding(&legacy, &scope).unwrap(),
        HandBindingFormat::LegacyBatchDigest
    );
    assert_eq!(classify_hand_binding(&unbound, &scope).unwrap(), HandBindingFormat::Unbound);

    // ===== G1/G2：默认双轨（全部接受）=====
    set_full_chain_enforcement(false);
    set_crypto_receipt_enforcement(false);
    assert!(!full_chain_enforcement());
    validate_settlement(&legacy, &policy).expect("G1 legacy accepted (migration window open)");
    validate_settlement(&unbound, &policy).expect("G1 unbound accepted (migration window open)");
    validate_settlement(&v2, &policy).expect("G2 v2 accepted with full-chain enforcement");

    // ===== G3/G4/G5：迁移窗关闭 =====
    {
        let _gates = GatesOpen::migration_only();
        let err = validate_settlement(&legacy, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                AppchainError::AdmissionRejected(
                    "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)"
                )
            ),
            "G3 got {err:?}"
        );
        let err = validate_settlement(&unbound, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                AppchainError::AdmissionRejected(
                    "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)"
                )
            ),
            "G4 got {err:?}"
        );
        validate_settlement(&v2, &policy).expect("G5 v2 still accepted after migration closes");

        // ===== G6：deck 锚断裂拼装（换锚归档 + 原绑定）→ 迁移窗关闭后拒绝 =====
        let mut broken = full_chain_spec();
        broken.post_deck = [0xFF; 32];
        let mut spliced = v2.clone();
        spliced.hand_proof = Some(HandProofBinding {
            archive_bytes: scope_bytes(&broken),
            post_state_commitment: [4; 32],
            pre_state_root: [0x11; 32],
            post_state_root: [0x22; 32],
        });
        let broken_scope = scope_of(&broken);
        assert_eq!(
            classify_hand_binding(&spliced, &broken_scope).unwrap(),
            HandBindingFormat::Unbound,
            "deck-anchor splice must declassify from v2"
        );
        let err = validate_settlement(&spliced, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                AppchainError::AdmissionRejected(
                    "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)"
                )
            ),
            "G6 got {err:?}"
        );
    }

    // ===== G7/G8：receipt 门（默认关；开启即要求引擎集成，v2 fail-closed）=====
    {
        let _gates = GatesOpen::receipt_only();
        let err = validate_settlement(&v2, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                AppchainError::AdmissionRejected(
                    "crypto receipt enforcement is enabled but engine receipt integration is pending upstream stage0"
                )
            ),
            "G7 got {err:?}"
        );
        validate_settlement(&legacy, &policy)
            .expect("G8 legacy traffic unaffected by the v2-only receipt gate");
    }

    // ===== 运营面接线（ABI v1.3 排队项收口）：SequencerConfig → 进程级门 =====
    // 配置字段 → apply_settlement_gates 刻入原子量 → validate_settlement
    // 行为随之翻转；重放面（replay/build_index）禁止调用的纪律见字段文档
    // （重放确定性）。测试尾部即刻复原默认态（关）。
    {
        let config = poker_appchain::sequencer::SequencerConfig {
            full_chain_enforcement: true,
            crypto_receipt_enforcement: false,
            ..poker_appchain::sequencer::SequencerConfig::default()
        };
        config.apply_settlement_gates();
        assert!(full_chain_enforcement(), "config must drive the migration window");
        assert!(!crypto_receipt_enforcement(), "receipt gate stays as configured");
        let err = validate_settlement(&legacy, &policy).unwrap_err();
        assert!(
            matches!(
                err,
                AppchainError::AdmissionRejected(
                    "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)"
                )
            ),
            "config-applied window close must reject legacy, got {err:?}"
        );
        validate_settlement(&v2, &policy).expect("v2 unaffected by window close (receipt gate off)");
    }

    // 复原默认态后全部恢复接受（守卫 drop 的语义回归）
    poker_appchain::sequencer::SequencerConfig::default().apply_settlement_gates();
    assert!(!full_chain_enforcement() && !crypto_receipt_enforcement(), "gates restored");
    validate_settlement(&legacy, &policy).expect("post-reset legacy accepted");
    validate_settlement(&v2, &policy).expect("post-reset v2 accepted");
}
