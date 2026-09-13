//! 洗牌/发牌证明链——**真实 stage0 归档**的消费侧钉扎测试（fixture 消费端）。
//!
//! 夹具 = 上游真实密码学栈产出的单批全链归档（SubmitShuffle×4（真实
//! Bayer–Groth V2）→ SubmitReveal×4（真实 DLEq，末行 RevealComplete 盲注
//! 实投）→ Call×3 → Check → AdvanceRound，13 行，log 8；STARK 出证 +
//! 路线 A 原生验证通过后导出）。生产端（导出）见
//! `poker-appchain-texasair/tests/shuffle_stage0_consume.rs`；本文件**只用
//! 导出的字节/JSON**（无上游依赖），证明消费侧校验对真实归档成立：
//!
//! 1. `parse_archive_scope` 前缀消费真实归档 borsh（字段序/镜像偏移钉扎，
//!    收口 SHUFFLE_CONSUME.md §3-2 排队项）；
//! 2. `hand_binding_v2` 重导 + `validate_settlement` **正例**（PLAY，全链
//!    11b 判据全过）；
//! 3. **11b-f fail-closed 负例**（REAL × 协议行，精确拒绝消息）；
//! 4. deck 锚篡改敏感性：翻转终态镜像 deck 承诺一位 → v2 绑定失配
//!    （分类降级 Unbound）。
//!
//! 夹具缺失 → panic（fail-closed：导出端一次性生成、随仓维护）。

mod common;

use common::{two_player_settlement, TestUser};
use poker_appchain::fee::FeePolicy;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::settlement::{
    archive_has_protocol_rows, classify_hand_binding, hand_binding_v2, parse_archive_scope,
    validate_settlement, HandBindingFormat, HandProofBinding, STATE_IMAGE_DECK_COMMITMENT_OFFSET,
    STATE_IMAGE_POT_OFFSET,
};

const ARCHIVE: &str = "tests/fixtures/stage0_full_chain.archive.bin";
const META: &str = "tests/fixtures/stage0_full_chain.json";

struct Fixture {
    archive_bytes: Vec<u8>,
    batch_digest: [u8; 32],
    deck_chain: Vec<[u8; 32]>,
    deck_chain_digest_hex: String,
    pot: u64,
    table_id: u64,
}

fn load_fixture() -> Fixture {
    let archive_bytes = std::fs::read(ARCHIVE)
        .expect("fixture archive missing — run poker-appchain-texasair tests/shuffle_stage0_consume.rs export first");
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(META).expect("fixture meta missing"),
    )
    .expect("fixture meta json");
    let hex32 = |s: &str| -> [u8; 32] {
        let bytes = hex::decode(s).expect("hex");
        bytes.try_into().expect("32 bytes")
    };
    let batch_digest = hex32(meta["batch_digest"].as_str().unwrap());
    let deck_chain = meta["deck_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex32(v.as_str().unwrap()))
        .collect();
    Fixture {
        archive_bytes,
        batch_digest,
        deck_chain,
        deck_chain_digest_hex: meta["deck_chain_digest"].as_str().unwrap().to_owned(),
        pot: meta["pot"].as_u64().unwrap(),
        table_id: meta["table_id"].as_u64().unwrap(),
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 真实归档 → scope 钉扎 + v2 绑定正例（PLAY）+ 11b-f 负例（REAL）。
#[test]
fn real_stage0_archive_scope_binding_and_consumer_rules() {
    let fx = load_fixture();
    let scope = parse_archive_scope(&fx.archive_bytes).expect("real archive parses as scope");
    // 元数据 ↔ scope 交叉核对（导出端与消费端独立来源一致）
    assert_eq!(scope.table_id, fx.table_id);
    assert_eq!(scope.batch_digest, fx.batch_digest);
    assert_eq!(scope.first_transition_kind, 7, "SubmitShuffle chain entry");
    assert_eq!(scope.last_transition_kind, 19, "AdvanceRound settlement terminal");
    // 镜像锚（真实归档字节偏移）：
    let pot = u64::from_le_bytes(
        scope.post_state_image_bytes[STATE_IMAGE_POT_OFFSET..][..8].try_into().unwrap(),
    );
    assert_eq!(pot, fx.pot);
    let post_deck: [u8; 32] = scope.post_state_image_bytes
        [STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32]
        .try_into()
        .unwrap();
    assert_eq!(post_deck, *fx.deck_chain.last().unwrap(), "terminal deck anchor == chain tail");
    assert!(
        archive_has_protocol_rows(&scope).unwrap(),
        "fixture archive carries protocol rows"
    );
    // deck 链摘要 golden（消费侧 = 上游 receipt 逐位一致；算法裁决证据的
    // fixture 侧复核——完整对照在 texasair 两侧测试）。
    let digest = poker_settlement_core::deck_chain_digest(&fx.deck_chain)
        .expect("chain within DECK_CHAIN_MAX");
    assert_eq!(hex_of(&digest), fx.deck_chain_digest_hex);

    // ===== 消费正例（PLAY）=====
    let a = TestUser::new(0x91);
    let b = TestUser::new(0x92);
    let policy = FeePolicy::Zero;
    let mk = |class, binding: [u8; 32]| {
        let seat_a = Note::new(class, 100, a.pk(), [0x81; 32], Some(fx.table_id)).unwrap();
        let seat_b = Note::new(class, 300, b.pk(), [0x82; 32], Some(fx.table_id)).unwrap();
        let mut record = two_player_settlement(
            fx.table_id, &a, &b, &seat_a, &seat_b, fx.pot, 150, 250, &policy, 0x5A,
        );
        record.hand_binding = binding;
        record.hand_proof = Some(HandProofBinding {
            archive_bytes: fx.archive_bytes.clone(),
            post_state_commitment: scope.post_state_commitment,
            pre_state_root: scope.pre_state_root,
            post_state_root: scope.post_state_root,
        });
        record.inputs[0].spend = a.settle_auth(&seat_a, &record);
        record.inputs[1].spend = b.settle_auth(&seat_b, &record);
        record
    };

    let binding_v2 = hand_binding_v2(&scope).unwrap();
    assert_eq!(
        classify_hand_binding(&mk(AssetClass::Play, binding_v2), &scope).unwrap(),
        HandBindingFormat::HandBindingV2
    );
    validate_settlement(&mk(AssetClass::Play, binding_v2), &policy)
        .expect("real-archive v2 PLAY settlement must be accepted");

    // ===== 11b-f：REAL × 协议行 fail-closed =====
    let err = validate_settlement(&mk(AssetClass::Real, binding_v2), &policy).unwrap_err();
    assert!(
        matches!(
            err,
            poker_appchain::error::AppchainError::AdmissionRejected(
                "REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)"
            )
        ),
        "REAL × protocol rows got {err:?}"
    );

    // ===== deck 锚篡改敏感性（真实归档上的 N11）=====
    let mut tampered = fx.archive_bytes.clone();
    // post_state_image_bytes 的 deck 承诺末字节翻位（scope 内该值仅出现一次
    // ——镜像承诺区 [0x00..0xFF] 随机密码空间保证）。
    let anchor = fx.deck_chain.last().unwrap().clone();
    let pos = fx
        .archive_bytes
        .windows(32)
        .position(|w| w == anchor.as_slice())
        .expect("terminal deck anchor appears in the archive bytes");
    tampered[pos + 31] ^= 0x01;
    let tampered_scope = parse_archive_scope(&tampered).unwrap();
    assert_eq!(
        classify_hand_binding(&mk(AssetClass::Play, binding_v2), &tampered_scope).unwrap(),
        HandBindingFormat::Unbound,
        "deck-anchor tamper must declassify the v2 binding"
    );
}
