//! archive_index v2 op 解析收口（TE-M5 发现的 pre-existing 缺口）：
//! `--write-index` 此前对 v2 WAL 报 `unknown kind "DepositV2"`——
//! `parse_frame_line` 的 known 集不识别 v2 追加变体。
//!
//! 覆盖：
//! 1. **v2 WAL 端到端**（真实 sequencer 产链：OpenTable(v1) +
//!    RegisterGameToken×2 + DepositV2 + IssueGameToken + FaucetMint +
//!    BindGasPolicy + BuyGasCredits + WithdrawRequestV2）→ `build_index`
//!    成功 → `load_index` 帧等价 + `v2` 子对象逐字段核对；
//! 2. **MigrateNote / SettleV2 行的装载契约**（构造索引行级覆盖——这两类
//!    op 的合法 WAL 产链需要 owner 信封/混合结算全套签名夹具，行级契约
//!    与 build 端产出同构即可判定装载面）；
//! 3. **unknown kind 仍拒** + v2 行缺 `v2` 对象/缺必填键拒（fail-closed）。
//!
//! 纪律：零新依赖（serde_json/hex 均为既有依赖）；索引契约见
//! `src/archive_index.rs` 模块文档（v2 kind + `v2` 子对象 additive 扩展、
//! 格式标签保持 `.v1` 的裁决记录）。

use std::path::PathBuf;
use std::sync::Arc;

use poker_appchain::asset_id::AssetId;
use poker_appchain::archive_index::{build_index, load_index};
use poker_appchain::fee::FeePolicy;
use poker_appchain::game_token::{FaucetPolicy, GameTokenSpec, GasPolicy, IssuanceMode};
use poker_appchain::keys::{OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note_v2::{default_network_id, NoteV2};
use poker_appchain::ops::{
    scope, BindGasPolicyOp, BuyGasCreditsOp, DepositV2Op, FaucetMintOp, IssueGameTokenOp,
    Operation, RegisterGameTokenOp, WithdrawRequestV2Op,
};
use poker_appchain::owner_v2::{
    legacy_account_id, v2_spend_digest, OwnerRef, SignatureEnvelope, SignatureScheme,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::wal::WalWriter;

const T0: u64 = 1_000;
const EXPIRY: u64 = 10_000;

fn id32(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

struct V2User {
    key: OwnerKey,
    secret: [u8; 32],
    owner: OwnerRef,
}

impl V2User {
    fn new(seed: u8) -> Self {
        let key = OwnerKey::from_seed(&[seed; 32]).unwrap();
        let owner = OwnerRef {
            scheme: SignatureScheme::LegacySecp256k1,
            account_id: legacy_account_id(&key.public_bytes()),
            key_version: 0,
            binding_id: None,
        };
        Self { key, secret: [seed; 32], owner }
    }
}

fn register_paid_op(token_id: u32, max_supply: u64) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Paid { anchor: AssetId::REAL_USDT, rate: 1_000_000 };
    let digest = GameTokenSpec::genesis_digest_of(token_id, &issuer, &mode, max_supply);
    Operation::RegisterGameToken(Box::new(RegisterGameTokenOp {
        token_id,
        issuer,
        mode,
        max_supply,
        genesis_digest: digest,
    }))
}

fn register_free_op(token_id: u32, single_max: u64, lifetime_max: u64) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Free {
        faucet: FaucetPolicy { single_max, player_lifetime_max: lifetime_max },
    };
    let digest = GameTokenSpec::genesis_digest_of(token_id, &issuer, &mode, 0);
    Operation::RegisterGameToken(Box::new(RegisterGameTokenOp {
        token_id,
        issuer,
        mode,
        max_supply: 0,
        genesis_digest: digest,
    }))
}

fn withdraw_scope(network_id: &[u8; 32]) -> Vec<u8> {
    poker_appchain::note_v2::spend_scope(network_id, OWNER_V2_ABI_VERSION, scope::WITHDRAW_V2)
}

/// 已签名的 WithdrawRequestV2（与 tests/te_m2.rs 同构造）。
fn signed_withdraw(
    user: &V2User,
    note: &NoteV2,
    request_id_byte: u8,
    nonce: u64,
    network_id: &[u8; 32],
) -> Operation {
    let nullifier = note.nullifier(&user.secret, &withdraw_scope(network_id));
    let mut op = WithdrawRequestV2Op {
        request_id: id32(request_id_byte),
        owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: user.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce,
            expiry: EXPIRY,
        },
        asset_id: note.asset_id,
        gross_amount: note.amount,
        external_recipient: [0x77; 32],
        created_at_ms: T0 + 1_000,
        note: note.clone(),
        nullifier,
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: user.key.public_bytes(),
        },
    };
    let effect = Operation::WithdrawRequestV2(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        &op.nullifier,
        &withdraw_scope(network_id),
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::WithdrawRequestV2(Box::new(op))
}

fn note_of(seq: &Sequencer, owner: &OwnerRef, asset: AssetId) -> NoteV2 {
    seq.state()
        .note_entries_v2_of(owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == asset)
        .expect("live v2 note")
}

/// fixture：一串合法 v2 帧的 WAL。返回 (sequencer_public, wal 路径, 期望
/// kind 序列)。
fn build_v2_wal(dir: &std::path::Path) -> ([u8; 32], PathBuf, Vec<&'static str>) {
    let key = SequencerKey::from_seed(&[0x2A; 32]);
    let mut seq = Sequencer::new(
        key.clone(),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    );

    // v1 帧照常入索引（既有行为不回退）
    seq.submit(
        Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
        T0,
    )
    .unwrap();
    // GTS 注册：Paid(1) + Free(2)
    seq.submit(register_paid_op(1, 10_000_000), T0 + 1).unwrap();
    seq.submit(register_free_op(2, 500, 5_000), T0 + 2).unwrap();

    let alice = V2User::new(0xB1);
    // REAL 多币种入金 + GAME 发行 + faucet + gas 绑定 + credit + 提现
    seq.submit(
        Operation::DepositV2(Box::new(DepositV2Op {
            deposit_id: id32(0xD1),
            owner: alice.owner.clone(),
            asset_id: AssetId::REAL_USDT,
            amount: 100,
        })),
        T0 + 3,
    )
    .unwrap();
    seq.submit(
        Operation::IssueGameToken(Box::new(IssueGameTokenOp {
            issue_id: id32(0xD2),
            token_id: 1,
            buyer: alice.owner.clone(),
            // Paid 计价 1e18 wei 刻度：R = 1e6 ⇒ 5e12 wei 铸 5 GAME
            //（floor(5e12 · 1e6 / 1e18)；低于 1 币的尘埃支付准入拒绝）。
            pay_amount: 5_000_000_000_000,
        })),
        T0 + 4,
    )
    .unwrap();
    seq.submit(
        Operation::FaucetMint(Box::new(FaucetMintOp {
            claim_id: id32(0xD3),
            token_id: 2,
            owner: alice.owner.clone(),
            amount: 400,
        })),
        T0 + 5,
    )
    .unwrap();
    seq.submit(
        Operation::BindGasPolicy(Box::new(BindGasPolicyOp {
            table_id: 1,
            token_id: 2,
            policy: GasPolicy::new(3, AssetId::REAL_USDT, 3).unwrap(),
        })),
        T0 + 6,
    )
    .unwrap();
    seq.submit(
        Operation::BuyGasCredits(Box::new(BuyGasCreditsOp {
            pay_digest: id32(0xD4),
            payer: alice.owner.clone(),
            pricing_asset_id: AssetId::REAL_NATIVE,
            pay_amount: 25,
        })),
        T0 + 7,
    )
    .unwrap();
    let usdt_note = note_of(&seq, &alice.owner, AssetId::REAL_USDT);
    seq.submit(
        signed_withdraw(&alice, &usdt_note, 0xD5, 1, &default_network_id()),
        T0 + 8,
    )
    .unwrap();

    let wal_path = dir.join("v2.wal");
    let mut wal = WalWriter::create(&wal_path).unwrap().with_fsync(false);
    for frame in seq.export_chain() {
        wal.append(&frame).unwrap();
    }
    wal.sync().unwrap();
    let kinds = vec![
        "OpenTable",
        "RegisterGameToken",
        "RegisterGameToken",
        "DepositV2",
        "IssueGameToken",
        "FaucetMint",
        "BindGasPolicy",
        "BuyGasCredits",
        "WithdrawRequestV2",
    ];
    (key.public, wal_path, kinds)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "archive-index-v2-tests-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// v2 WAL → build_index → load_index 查询等价 + `v2` 子对象逐字段核对。
#[test]
fn v2_wal_build_load_query_equivalence() {
    let dir = temp_dir("v2-wal");
    let (public, wal, kinds) = build_v2_wal(&dir);
    let index_path = dir.join("v2.index.jsonl");

    // TE-M5 缺口收口断言：此前这里报 `unknown kind "DepositV2"`。
    let index = build_index(&wal, public, None, &index_path).expect("v2 WAL must index");
    assert_eq!(index.header().frame_count, kinds.len() as u64);
    assert_eq!(index.header().settlement_count, 0, "no v1 Settle in this WAL");
    let loaded = load_index(&index_path).expect("built index must reload");
    assert_eq!(loaded.header(), index.header());
    assert_eq!(loaded.frames(), index.frames(), "build/load frames bit-equal");
    assert_eq!(
        loaded.frames().iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
        kinds,
        "frame kind sequence"
    );
    // 查询等价：时间窗全命中；无 v1 结算账收录
    assert_eq!(loaded.frames_by_time_window(0, u64::MAX).len(), kinds.len());
    assert!(loaded.settlement_by_binding(&[1; 32]).is_none());

    // v2 子对象逐字段核对（等价键/金额摘要）
    let v2_of = |i: usize| loaded.frames()[i].v2.as_ref().expect("v2 summary");
    let deposit = v2_of(3);
    assert_eq!(deposit.key.as_ref().unwrap(), &id32(0xD1), "deposit_id equivalent key");
    assert_eq!(deposit.amount, Some(100));
    assert_eq!(deposit.asset.as_deref(), Some("real:usdt"));
    let issue = v2_of(4);
    assert_eq!(issue.key.as_ref().unwrap(), &id32(0xD2));
    assert_eq!(issue.token_id, Some(1));
    assert_eq!(issue.amount, Some(5_000_000_000_000));
    let faucet = v2_of(5);
    assert_eq!(faucet.key.as_ref().unwrap(), &id32(0xD3));
    assert_eq!(faucet.token_id, Some(2));
    assert_eq!(faucet.amount, Some(400));
    let bind = v2_of(6);
    assert_eq!(bind.table_id, Some(1));
    assert_eq!(bind.token_id, Some(2));
    assert!(bind.key.is_none(), "BindGasPolicy has no idempotency key");
    let credits = v2_of(7);
    assert_eq!(credits.key.as_ref().unwrap(), &id32(0xD4));
    assert_eq!(credits.asset.as_deref(), Some("real:native"));
    assert_eq!(credits.amount, Some(25));
    let withdraw = v2_of(8);
    assert_eq!(withdraw.key.as_ref().unwrap(), &id32(0xD5));
    assert_eq!(withdraw.asset.as_deref(), Some("real:usdt"));
    assert_eq!(withdraw.amount, Some(100));
    let register = v2_of(1);
    assert_eq!(register.token_id, Some(1));
    assert_eq!(register.secondary_amount, Some(10_000_000), "max supply summary");
    // v1 帧无 v2 摘要
    assert!(loaded.frames()[0].v2.is_none(), "v1 OpenTable carries no v2 summary");
}

/// MigrateNote / SettleV2 的装载契约（行级覆盖）：构造含两类行的完整
/// 索引文件（digest 按同一契约重算）→ load_index 解析 `v2` 子对象。
#[test]
fn migrate_note_and_settle_v2_rows_load() {
    use poker_appchain::keys::blake2s32;

    let dir = temp_dir("rows");
    let public = SequencerKey::from_seed(&[0x2B; 32]).public;
    let lines = vec![
        serde_json::json!({
            "kind": "MigrateNote", "index": 0, "ts_ms": 1,
            "state_root": hex::encode([2; 32]), "hash": hex::encode([3; 32]),
            "offset": 0,
            "v2": {
                "key_hex": hex::encode(id32(0xE1)),
                "amount": 250,
                "asset": "real:usdt",
            },
        })
        .to_string(),
        serde_json::json!({
            "kind": "SettleV2", "index": 1, "ts_ms": 2,
            "state_root": hex::encode([4; 32]), "hash": hex::encode([5; 32]),
            "offset": 96,
            "v2": {
                "binding_hex": hex::encode(id32(0xE2)),
                "table_id": 7,
                "amount": 400,
                "secondary_amount": 0,
            },
        })
        .to_string(),
    ];
    let blob = format!("{}\n", lines.join("\n"));
    let digest = blake2s32(&[blob.as_bytes()]);
    let header = serde_json::json!({
        "format": poker_appchain::archive_index::FORMAT_TAG,
        "sequencer_public": hex::encode(public),
        "chain_head": {
            "index": 1,
            "hash": hex::encode([5; 32]),
            "state_root": hex::encode([4; 32]),
        },
        "frame_count": 2,
        "settlement_count": 0,
        "proof_count": 0,
        "digest": hex::encode(digest),
    })
    .to_string();
    let path = dir.join("crafted.jsonl");
    std::fs::write(&path, format!("{header}\n{blob}")).unwrap();

    let loaded = load_index(&path).expect("crafted v2-row index must load");
    assert_eq!(loaded.frames().len(), 2);
    let migrate = loaded.frames()[0].v2.as_ref().unwrap();
    assert_eq!(migrate.key.as_ref().unwrap(), &id32(0xE1), "migration_nonce equivalent key");
    assert_eq!(migrate.amount, Some(250));
    let settle = loaded.frames()[1].v2.as_ref().unwrap();
    assert_eq!(settle.binding.as_ref().unwrap(), &id32(0xE2));
    assert_eq!(settle.table_id, Some(7));
    assert_eq!(settle.amount, Some(400), "pot summary");
    assert_eq!(settle.secondary_amount, Some(0), "rake summary");
    // SettleV2 不进 v1 结算查询账（两模式对等口径，模块文档裁决）
    assert!(loaded.settlement_by_binding(&id32(0xE2)).is_none());
}

/// unknown kind 仍拒 + v2 行缺 `v2` 对象/缺必填键拒（fail-closed 不回退）。
#[test]
fn unknown_kind_and_broken_v2_contract_rejected() {
    use poker_appchain::keys::blake2s32;

    let dir = temp_dir("neg");
    let public = SequencerKey::from_seed(&[0x2C; 32]).public;
    let write_and_load = |lines: Vec<serde_json::Value>| -> Result<
        poker_appchain::archive_index::ArchiveIndex,
        poker_appchain::error::AppchainError,
    > {
        let text_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
        let blob = format!("{}\n", text_lines.join("\n"));
        let digest = blake2s32(&[blob.as_bytes()]);
        let header = serde_json::json!({
            "format": poker_appchain::archive_index::FORMAT_TAG,
            "sequencer_public": hex::encode(public),
            "chain_head": {"index": 0, "hash": hex::encode([0; 32]), "state_root": hex::encode([0; 32])},
            "frame_count": lines.len() as u64,
            "settlement_count": 0,
            "proof_count": 0,
            "digest": hex::encode(digest),
        })
        .to_string();
        let path = dir.join(format!("case-{}.jsonl", lines.len()));
        std::fs::write(&path, format!("{header}\n{blob}")).unwrap();
        load_index(&path)
    };
    let base = |kind: &str, v2: serde_json::Value| {
        let mut line = serde_json::json!({
            "kind": kind, "index": 0, "ts_ms": 1,
            "state_root": hex::encode([2; 32]), "hash": hex::encode([3; 32]),
            "offset": 0,
        });
        if !v2.is_null() {
            line["v2"] = v2;
        }
        line
    };

    // 未知 kind 仍拒（既有 fail-closed 不回退）
    assert!(write_and_load(vec![base("Bogus", serde_json::Value::Null)]).is_err());
    // v2 kind 缺 `v2` 对象 → 拒
    assert!(write_and_load(vec![base("DepositV2", serde_json::Value::Null)]).is_err());
    // v2 kind 缺必填键 → 拒
    assert!(write_and_load(vec![base("DepositV2", serde_json::json!({"amount": 1}))]).is_err());
    // SettleV2 缺 binding_hex → 拒
    assert!(
        write_and_load(vec![base("SettleV2", serde_json::json!({"table_id": 1, "amount": 1, "secondary_amount": 0}))])
            .is_err()
    );
}
