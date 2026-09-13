//! TE-M5（排期表 §6）：UI/explorer 呈现——explorer_gateway 的资产维度
//! 数据面测试。
//!
//! 覆盖（对应交付清单 §1/§4）：
//! 1. `/api/v1/status.assets` 资产摘要（replay 模式）：REAL 域封闭枚举
//!    三 token 的 issued/burned/outstanding（链上可见面）+ GAME 域供给
//!    对账（`outstanding = Σminted − Σburned`）+ 注册表规格展示；
//! 2. index 模式 `assets` 恒 null（token 聚合账是 WAL 重放重建态，不入
//!    索引——如实呈现，不从 v1 计数伪造）；
//! 3. `/api/v1/settlement/{binding}` 明细逐项带 `asset_id`（domain 判别
//!    值/名称 + token 编号/名称 + 规范字符串；v1 记录经冻结映射 of_v1）；
//! 4. 名称解析拼写钉住（`asset_id_json` 与 `AssetId::to_string` 同源）。
//!
//! 边界（如实声明，不在此测试）：
//! - 托管侧储备（CustodyLedgerV2 reserved/浮存/提现队列）网关不可达，
//!   资产摘要只覆盖链上可见面（`assets.source` 如实标注）；
//! - settlements 列表端点本轮仍以 v1 Settle 为准（index 模式同语义，
//!   两数据面逐字段一致纪律）；SettleV2（GAME 桌）在 frames 端点以
//!   kind 呈现，其资产维度经 status.assets 的 GAME 域对账闭合。

#[path = "../src/bin/explorer_gateway/aggregate_log.rs"]
mod aggregate_log;
#[path = "../src/bin/explorer_gateway/api.rs"]
mod api;
#[path = "../src/bin/explorer_gateway/http.rs"]
mod http;
#[path = "../src/bin/explorer_gateway/l1.rs"]
mod l1;
#[path = "../src/bin/explorer_gateway/proven_log.rs"]
mod proven_log;
#[path = "../src/bin/explorer_gateway/rate_limit.rs"]
mod rate_limit;
#[path = "../src/bin/explorer_gateway/server.rs"]
mod server;
#[path = "../src/bin/explorer_gateway/state.rs"]
mod state;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use poker_appchain::asset_id::{AssetId, TOKEN_NATIVE, TOKEN_USDC, TOKEN_USDT};
use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::game_token::{GameTokenSpec, IssuanceMode};
use poker_appchain::keys::{spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::note_v2::{default_network_id, spend_scope, NoteV2};
use poker_appchain::ops::{
    scope, BurnGameTokenOp, DepositV2Op, IssueGameTokenOp, Operation, RegisterGameTokenOp,
    WithdrawRequestV2Op,
};
use poker_appchain::owner_v2::{
    legacy_account_id, v2_spend_digest, OwnerRef, SignatureEnvelope, SignatureScheme,
    VerifierMaterial, OWNER_V2_ABI_VERSION,
};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    flat_settlement_plan, settle_effect, settle_spend_scope, RakeSplitRecord, SettleInput,
    SettlementRecord, SpendAuth,
};
use poker_appchain::wal::WalWriter;

// ---------------------------------------------------------------------------
// v2 夹具（镜像 tests/te_m2.rs / tests/game_token.rs 的构造纪律）
// ---------------------------------------------------------------------------

/// 测试时钟（帧时间戳 ms）。
const T0: u64 = 1_100;
/// 信封有效期（unix 秒；远晚于测试时钟）。
const EXPIRY: u64 = 100_000;

/// 单字节前缀 32B id。
fn id32(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

/// v2 测试用户：secp256k1 密钥 + LegacySecp256k1 [`OwnerRef`]。
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
        Self {
            key,
            secret: [seed; 32],
            owner,
        }
    }
}

/// 某 owner 名下指定资产的 live v2 note（账本扫描）。
fn note_of(seq: &Sequencer, owner: &OwnerRef, asset: AssetId) -> NoteV2 {
    seq.state()
        .note_entries_v2_of(owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == asset)
        .unwrap_or_else(|| panic!("no live v2 note for {asset}"))
}

/// DepositV2 op 构造。
fn deposit_v2(id_byte: u8, owner: &OwnerRef, asset: AssetId, amount: u64) -> Operation {
    Operation::DepositV2(Box::new(DepositV2Op {
        deposit_id: id32(id_byte),
        owner: owner.clone(),
        asset_id: asset,
        amount,
    }))
}

/// 构造**已签名**的 WithdrawRequestV2 op（镜像 tests/te_m2.rs 纪律）。
fn signed_withdraw(
    user: &V2User,
    note: &NoteV2,
    request_id_byte: u8,
    nonce: u64,
) -> Operation {
    let network_id = default_network_id();
    let scope_tag = spend_scope(&network_id, OWNER_V2_ABI_VERSION, scope::WITHDRAW_V2);
    let nullifier = note.nullifier(&user.secret, &scope_tag);
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
        external_recipient: [0xB0; 32],
        created_at_ms: T0 + 500,
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
        &scope_tag,
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::WithdrawRequestV2(Box::new(op))
}

/// RegisterGameToken op（Paid：anchor USDT、R = 1e6、不限供给）。
fn register_op(token_id: u32) -> Operation {
    let issuer = [0x02u8; 33];
    let mode = IssuanceMode::Paid {
        anchor: AssetId::REAL_USDT,
        rate: 1_000_000,
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

/// IssueGameToken op（`millions_e18` × 1e18 wei anchor → 等比百万币）。
fn issue_op(id_byte: u8, token_id: u32, buyer: &OwnerRef, millions_e18: u64) -> Operation {
    Operation::IssueGameToken(Box::new(IssueGameTokenOp {
        issue_id: id32(id_byte),
        token_id,
        buyer: buyer.clone(),
        pay_amount: millions_e18 * 1_000_000_000_000_000_000,
    }))
}

/// 构造**已签名**的 BurnGameToken op（镜像 tests/game_token.rs 纪律）。
fn signed_burn(user: &V2User, note: &NoteV2, burn_id_byte: u8, nonce: u64) -> Operation {
    let network_id = default_network_id();
    let scope_tag = spend_scope(&network_id, OWNER_V2_ABI_VERSION, scope::BURN_GAME);
    let nullifier = note.nullifier(&user.secret, &scope_tag);
    let mut op = BurnGameTokenOp {
        burn_id: id32(burn_id_byte),
        token_id: note.asset_id.token_id,
        note: note.clone(),
        nullifier,
        owner_sig: SignatureEnvelope {
            scheme: SignatureScheme::LegacySecp256k1,
            signer_ref: user.owner.clone(),
            typed_data_digest: [0u8; 32],
            signature: [0u8; 64],
            nonce,
            expiry: EXPIRY,
        },
        material: VerifierMaterial::LegacySecp256k1 {
            presented_public: user.key.public_bytes(),
        },
    };
    let effect = Operation::BurnGameToken(Box::new(op.clone())).effect_digest();
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        &nullifier,
        &scope_tag,
        &effect,
    );
    op.owner_sig.typed_data_digest = digest;
    op.owner_sig.signature = user.key.sign(&digest).bytes;
    Operation::BurnGameToken(Box::new(op))
}

/// 生成 v2 资产链 fixture（三币种存/提 + GAME 注册/发行/销毁），WAL 落盘。
///
/// 链内容（8 帧）：
/// `DepositV2(NATIVE 1000) / DepositV2(USDT 500) / DepositV2(USDC 250) /
/// WithdrawRequestV2(销毁 USDT 500) / RegisterGameToken(token 1) /
/// IssueGameToken(1e18 → 100 万) / IssueGameToken(2e18 → 200 万) /
/// BurnGameToken(销毁 100 万)`。
fn build_v2_wal(dir: &Path, seed: u8) -> [u8; 32] {
    let seq_key = SequencerKey::from_seed(&[seed; 32]);
    let public = seq_key.public;
    let mut seq = Sequencer::new(
        seq_key,
        SequencerConfig {
            ops_per_min: u32::MAX,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    let alice = V2User::new(seed.wrapping_add(1));

    let native = AssetId::real(TOKEN_NATIVE).unwrap();
    let usdt = AssetId::real(TOKEN_USDT).unwrap();
    let usdc = AssetId::real(TOKEN_USDC).unwrap();

    seq.submit(deposit_v2(0x01, &alice.owner, native, 1_000), T0)
        .unwrap();
    seq.submit(deposit_v2(0x02, &alice.owner, usdt, 500), T0 + 10)
        .unwrap();
    seq.submit(deposit_v2(0x03, &alice.owner, usdc, 250), T0 + 20)
        .unwrap();
    let usdt_note = note_of(&seq, &alice.owner, usdt);
    seq.submit(signed_withdraw(&alice, &usdt_note, 0x04, 1), T0 + 30)
        .unwrap();
    seq.submit(register_op(1), T0 + 40).unwrap();
    seq.submit(issue_op(0x05, 1, &alice.owner, 1), T0 + 50).unwrap();
    seq.submit(issue_op(0x06, 1, &alice.owner, 2), T0 + 60).unwrap();
    let game_note = seq
        .state()
        .note_entries_v2_of(&alice.owner)
        .into_iter()
        .map(|e| e.note.clone())
        .find(|n| n.asset_id == AssetId::game(1) && n.amount == 1_000_000)
        .expect("first issue note (1e18 × 1e6 / 1e18)");
    assert_eq!(game_note.amount, 1_000_000);
    seq.submit(signed_burn(&alice, &game_note, 0x07, 2), T0 + 70)
        .unwrap();

    let wal_path = dir.join("appchain.wal");
    let mut wal = WalWriter::create(&wal_path)
        .map(|w| w.with_fsync(false))
        .unwrap();
    for f in seq.export_chain() {
        wal.append(&f).unwrap();
    }
    wal.sync().unwrap();
    // 落盘 sequencer public（供网关 replay 演示/ops 接线；与 fixture 同源）。
    std::fs::write(dir.join("sequencer_public.hex"), hex::encode(public)).unwrap();
    public
}

// ---------------------------------------------------------------------------
// v1 夹具（REAL 结算——镜像 tests/explorer_gateway.rs，资产换 Real）
// ---------------------------------------------------------------------------

const TABLE_ID: u64 = 1;
const BUY_IN: u64 = 1_000;

struct Player {
    key: OwnerKey,
    secret: [u8; 32],
}

impl Player {
    fn new(seed: u8) -> Self {
        Self {
            key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
            secret: [seed; 32],
        }
    }

    fn buyin_auth(&self, note: &Note, effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            scope::BUYIN,
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }

    fn settle_auth(&self, note: &Note, binding: &[u8; 32], effect: &[u8; 32]) -> SpendAuth {
        let nf = note.nullifier(&self.secret);
        let d = spend_digest(
            &note.commitment_bytes(),
            &felt_to_bytes32(&nf),
            &settle_spend_scope(binding),
            effect,
        );
        SpendAuth {
            commitment: note.commitment_bytes(),
            nullifier: felt_to_bytes32(&nf),
            sig: self.key.sign(&d),
        }
    }
}

/// 生成 v1 REAL 结算 fixture（1 桌 2 人 1 手；REAL 域 NATIVE 入金/结算）。
fn build_v1_real_wal(dir: &Path, seed: u8) -> ([u8; 32], Vec<[u8; 32]>) {
    let seq_public = SequencerKey::from_seed(&[seed; 32]).public;
    let mut seq = Sequencer::new(
        SequencerKey::from_seed(&[seed; 32]),
        SequencerConfig {
            ops_per_min: u32::MAX,
            open_table_per_min: u32::MAX,
            ..SequencerConfig::default()
        },
        Arc::new(MetricsRegistry::new()),
    );
    let players: Vec<Player> = (0..2u8)
        .map(|i| Player::new(seed.wrapping_add(10 + i)))
        .collect();

    seq.submit(
        Operation::OpenTable {
            table_id: TABLE_ID,
            policy: FeePolicy::Zero,
        },
        T0,
    )
    .unwrap();

    let mut binding32 = [0u8; 32];
    binding32[..8].copy_from_slice(&1u64.to_be_bytes());

    for (pi, p) in players.iter().enumerate() {
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = TABLE_ID as u8;
        deposit_id[1] = pi as u8;
        seq.submit(
            Operation::Deposit {
                deposit_id,
                owner: p.key.public_bytes(),
                asset_class: AssetClass::Real,
                amount: BUY_IN,
            },
            T0 + 10,
        )
        .unwrap();
    }
    seq.mark_proven_through(seq.state().seq);

    for p in &players {
        let note = find_proven_note(&seq, &p.key.public_bytes());
        let effect = Operation::BuyIn {
            table_id: TABLE_ID,
            spends: vec![],
            notes: vec![],
            seat_owner: p.key.public_bytes(),
        }
        .effect_digest();
        seq.submit(
            Operation::BuyIn {
                table_id: TABLE_ID,
                spends: vec![p.buyin_auth(&note, &effect)],
                notes: vec![note],
                seat_owner: p.key.public_bytes(),
            },
            T0 + 20,
        )
        .unwrap();
    }

    let seats: Vec<Note> = players
        .iter()
        .map(|p| {
            seq.state()
                .note_entries_of(&p.key.public_bytes())
                .into_iter()
                .find(|e| e.note.table_id == Some(TABLE_ID))
                .map(|e| e.note.clone())
                .expect("one seat note per player")
        })
        .collect();
    let pot = BUY_IN * seats.len() as u64;
    let mask = (1u16 << seats.len()) - 1;
    let mut awards = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
    for a in awards.iter_mut().take(seats.len()) {
        *a = BUY_IN;
    }
    let mut record = SettlementRecord {
        table_id: TABLE_ID,
        hand_binding: binding32,
        policy_commitment: FeePolicy::Zero.commitment_bytes(),
        pot,
        inputs: seats
            .iter()
            .map(|n| SettleInput {
                note: n.clone(),
                spend: SpendAuth {
                    commitment: n.commitment_bytes(),
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            })
            .collect(),
        payouts: seats
            .iter()
            .map(|n| poker_appchain::note::NoteSpec {
                asset_class: AssetClass::Real,
                amount: n.amount,
                owner: n.owner,
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            })
            .collect(),
        rake: RakeSplitRecord {
            total: 0,
            treasury_out: None,
            operator_out: None,
        },
        plan: flat_settlement_plan(pot, mask, awards),
        hand_proof: None,
    };
    let effect = settle_effect(&record);
    for (i, n) in seats.iter().enumerate() {
        let p = players
            .iter()
            .find(|p| p.key.public_bytes() == n.owner)
            .unwrap();
        record.inputs[i].spend = p.settle_auth(n, &binding32, &effect);
    }
    seq.submit(Operation::Settle(Box::new(record)), T0 + 30).unwrap();

    let wal_path = dir.join("appchain.wal");
    let mut wal = WalWriter::create(&wal_path)
        .map(|w| w.with_fsync(false))
        .unwrap();
    for f in seq.export_chain() {
        wal.append(&f).unwrap();
    }
    wal.sync().unwrap();
    std::fs::write(dir.join("sequencer_public.hex"), hex::encode(seq_public)).unwrap();
    (seq_public, vec![binding32])
}

fn find_proven_note(seq: &Sequencer, owner: &[u8; 33]) -> Note {
    seq.state()
        .note_entries_of(owner)
        .into_iter()
        .find(|e| {
            e.note.amount == BUY_IN && e.note.table_id.is_none() && e.status == NoteStatus::Proven
        })
        .map(|e| e.note.clone())
        .unwrap_or_else(|| panic!("no proven {BUY_IN}-note for owner"))
}

// ---------------------------------------------------------------------------
// HTTP 客户端（极简；一请求一连接）
// ---------------------------------------------------------------------------

struct ServerHandle {
    addr: SocketAddr,
}

fn start_replay_server(wal: &Path, public: [u8; 32]) -> ServerHandle {
    let state = Arc::new(
        state::load(wal, public, None, None, None).expect("gateway state loads from fixture"),
    );
    let listener = server::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    let _join = server::spawn(
        listener,
        state,
        server::ServerOptions {
            public: false,
            rate_per_sec: 1_000,
            burst: 1_000,
            l1: None,
        },
    );
    ServerHandle { addr }
}

fn start_index_server(wal: &Path, index: &Path, public: [u8; 32]) -> ServerHandle {
    let state = Arc::new(
        state::load_with_index(index, wal, public, None, None, None)
            .expect("gateway index state loads"),
    );
    let listener = server::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    let _join = server::spawn(
        listener,
        state,
        server::ServerOptions {
            public: false,
            rate_per_sec: 1_000,
            burst: 1_000,
            l1: None,
        },
    );
    ServerHandle { addr }
}

fn request(addr: SocketAddr, target: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("client connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("client read");
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
    let status = head
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("response body is json")
}

fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "te-m5-tests-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

/// status.assets：REAL 域三 token（issued/burned/outstanding，链上可见面）+
/// GAME 域供给对账（恒等式闭合 + 注册表规格）。
#[test]
fn status_assets_summary_real_and_game_domains() {
    let dir = fixture_dir("assets");
    let public = build_v2_wal(&dir, 0x51);
    let srv = start_replay_server(&dir.join("appchain.wal"), public);

    let (status, body) = request(srv.addr, "/api/v1/status");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["data_source"], "replay");
    let assets = &v["assets"];
    assert!(
        assets["source"].as_str().unwrap().contains("chain-visible"),
        "assets.source must honestly label the chain-visible face"
    );

    // REAL 域：封闭枚举三 token， issued = 存续 + 已销毁毛额
    let real = assets["real"]["tokens"].as_array().unwrap();
    assert_eq!(real.len(), 3, "REAL domain closed enum: NATIVE/USDT/USDC");
    assert_eq!(real[0]["token_id"], TOKEN_NATIVE);
    assert_eq!(real[0]["token"], "native");
    assert_eq!(real[0]["asset"], "real:native");
    assert_eq!(real[0]["issued"], "1000");
    assert_eq!(real[0]["burned"], "0");
    assert_eq!(real[0]["outstanding"], "1000", "outstanding = issued − burned");
    assert_eq!(real[1]["token_id"], TOKEN_USDT);
    assert_eq!(real[1]["token"], "usdt");
    assert_eq!(real[1]["issued"], "500");
    assert_eq!(real[1]["burned"], "500", "WithdrawRequestV2 gross burned");
    assert_eq!(real[1]["outstanding"], "0");
    assert_eq!(real[2]["token_id"], TOKEN_USDC);
    assert_eq!(real[2]["token"], "usdc");
    assert_eq!(real[2]["issued"], "250");
    assert_eq!(real[2]["outstanding"], "250");

    // GAME 域：供给对账（Σminted − Σburned == outstanding == live note）
    let game = assets["game"]["tokens"].as_array().unwrap();
    assert_eq!(game.len(), 1, "only registered GTS token 1 (no PLAY note ever existed)");
    let g = &game[0];
    assert_eq!(g["token_id"], 1);
    assert_eq!(g["asset"], "game:1");
    assert_eq!(g["registered"], true);
    assert_eq!(g["mode"], "paid");
    assert_eq!(g["anchor"], "real:usdt", "anchor resolves to REAL domain token");
    assert_eq!(g["rate"], "1000000");
    assert_eq!(g["max_supply"], "0");
    assert_eq!(g["minted_total"], "3000000", "1e18 + 2e18 wei anchor at R=1e6");
    assert_eq!(g["burned_total"], "1000000");
    assert_eq!(g["outstanding"], "2000000");
    assert_eq!(g["live_note_sum"], "2000000");
    assert_eq!(g["consistent"], true);
    assert_eq!(assets["game"]["all_consistent"], true);
}

/// index 模式：`assets` 恒 null（token 聚合账不入索引——如实呈现）。
///
/// fixture 用 v1 链：archive index 的 kind 词表当前不解析 v2 op 行
/// （pre-existing 边界，非本轮文件）；断言只依赖"index 模式下 assets
/// 为 null + 冻结契约字段不变"，与链内容无关。
#[test]
fn status_assets_null_in_index_mode() {
    let dir = fixture_dir("assets-index");
    let (public, _) = build_v1_real_wal(&dir, 0x52);
    let wal = dir.join("appchain.wal");
    let index_path = dir.join("archive_index.jsonl");
    poker_appchain::archive_index::build_index(&wal, public, None, &index_path)
        .expect("index builds from fixture wal");
    let srv = start_index_server(&wal, &index_path, public);

    let (status, body) = request(srv.addr, "/api/v1/status");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["data_source"], "index");
    assert_eq!(
        v["assets"],
        serde_json::Value::Null,
        "token aggregates are replay-rebuilt, not indexed — honest null"
    );
    // 冻结契约字段不受影响
    assert!(v["frame_count"].is_u64());
}

/// settlement 明细：inputs/payouts 逐项带 asset_id（v1 REAL 记录经冻结
/// 映射 of_v1 → real:native）。
#[test]
fn settlement_detail_carries_asset_id() {
    let dir = fixture_dir("detail-asset");
    let (public, bindings) = build_v1_real_wal(&dir, 0x53);
    let srv = start_replay_server(&dir.join("appchain.wal"), public);

    let target = format!("/api/v1/settlement/{}", hex::encode(bindings[0]));
    let (status, body) = request(srv.addr, &target);
    assert_eq!(status, 200);
    let v = json(&body);
    let expect = serde_json::json!({
        "domain": 1,
        "domain_name": "REAL",
        "token_id": 0,
        "token": "native",
        "asset": "real:native",
    });
    for i in v["inputs"].as_array().unwrap() {
        assert_eq!(i["asset_id"], expect, "input asset_id via frozen of_v1 mapping");
        assert_eq!(i["asset_class"], "REAL");
    }
    for p in v["payouts"].as_array().unwrap() {
        assert_eq!(p["asset_id"], expect, "payout asset_id via frozen of_v1 mapping");
        assert_eq!(p["asset_class"], "REAL");
    }
}

/// 名称解析拼写钉住：`asset_id_json` 与 `AssetId::to_string` 同源；
/// v1 双资产冻结映射（Real → real:native / Play → game:play(legacy)）+
/// REAL 多币种（USDT/USDC）+ GAME 未注册 token 如实给编号。
#[test]
fn asset_id_display_names_are_pinned() {
    use poker_appchain::note::AssetClass as AC;
    assert_eq!(
        api::asset_id_json(&AssetId::of_v1(AC::Real)),
        serde_json::json!({
            "domain": 1, "domain_name": "REAL", "token_id": 0,
            "token": "native", "asset": "real:native",
        })
    );
    assert_eq!(
        api::asset_id_json(&AssetId::of_v1(AC::Play)),
        serde_json::json!({
            "domain": 2, "domain_name": "GAME", "token_id": 0,
            "token": "play(legacy)", "asset": "game:play(legacy)",
        })
    );
    assert_eq!(
        api::asset_id_json(&AssetId::REAL_USDT)["asset"],
        "real:usdt"
    );
    assert_eq!(api::asset_id_json(&AssetId::REAL_USDC)["token"], "usdc");
    assert_eq!(api::asset_id_json(&AssetId::game(7))["token"], "7");
    assert_eq!(
        api::asset_id_json(&AssetId::game(7))["domain_name"],
        "GAME"
    );
    // 展示名与 Display 同源（token 段逐点一致）
    for a in [AssetId::REAL_NATIVE, AssetId::REAL_USDT, AssetId::REAL_USDC, AssetId::GAME_PLAY] {
        let j = api::asset_id_json(&a);
        let asset = j["asset"].as_str().unwrap();
        let token = j["token"].as_str().unwrap();
        assert_eq!(
            asset.strip_prefix(&format!("{}:", j["domain_name"].as_str().unwrap().to_ascii_lowercase())),
            Some(token),
            "Display token segment == token field for {asset}"
        );
    }
}
