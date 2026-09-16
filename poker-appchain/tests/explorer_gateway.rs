//! explorer gateway 集成测试（E1 只读实时数据面 + E2 领域查询验收）。
//!
//! 网关 bin 的模块经 `#[path]` 挂载进本测试 crate，**进程内**起 server 于
//! `127.0.0.1:0`（临时端口）；fixture WAL 由测试内代码生成（loadtest.rs
//! 最小流：OpenTable → Deposit → mark_proven_through → BuyIn（真实 spend
//! 签名）→ Settle（真实 settle_effect 签名）×2 手），WAL 用
//! `WalWriter::create` + `with_fsync(false)` 落盘。
//!
//! 覆盖：status 字段/水位缺失语义、frames 分页与上限、settlements 分页
//! 与 table_id 过滤、settlement 明细命中/404/坏 hex 400、伪造 WAL 重放
//! 失败、限流 429、未知路径 404、POST 405、超长请求行 400、proven log
//! 恢复水位 + 撕裂尾行容错、L1 代理（含 zchain newline-RPC 回落）、
//! 快照导出。

#[path = "../src/bin/explorer_gateway/aggregate_log.rs"]
mod aggregate_log;
#[path = "../src/bin/explorer_gateway/api.rs"]
mod api;
#[path = "../src/bin/explorer_gateway/fixture.rs"]
mod fixture;
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
#[path = "../src/bin/explorer_gateway/snapshot.rs"]
mod snapshot;
#[path = "../src/bin/explorer_gateway/state.rs"]
mod state;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use poker_appchain::fee::FeePolicy;
use poker_appchain::felt::felt_to_bytes32;
use poker_appchain::keys::{spend_digest, OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::ops::{scope, Operation};
use poker_appchain::sequencer::{NoteStatus, Sequencer, SequencerConfig};
use poker_appchain::settlement::{
    flat_settlement_plan, settle_effect, settle_spend_scope, RakeSplitRecord, SettleInput,
    SettlementRecord, SpendAuth,
};
use poker_appchain::wal::WalWriter;

// ===== fixture 生成（loadtest.rs 最小流）=====

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

/// fixture 目录（每测试独立，避免并行互踩）。
fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "explorer-gateway-tests-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 生成最小合法 appchain：1 桌 2 人 2 手；返回 (sequencer public, 手绑定列表)。
fn build_wal(dir: &Path, seed: u8) -> ([u8; 32], Vec<[u8; 32]>) {
    let seq_public = SequencerKey::from_seed(&[seed; 32]).public;
    let seq_key = SequencerKey::from_seed(&[seed; 32]);
    let mut seq = Sequencer::new(
        seq_key,
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
        1_100,
    )
    .unwrap();

    let mut bindings = Vec::new();
    for hand in 0..2u64 {
        let mut binding32 = [0u8; 32];
        binding32[..8].copy_from_slice(&(hand + 1).to_be_bytes());
        bindings.push(binding32);

        if hand == 0 {
            for (pi, p) in players.iter().enumerate() {
                let mut deposit_id = [0u8; 32];
                deposit_id[0] = TABLE_ID as u8;
                deposit_id[1] = pi as u8;
                deposit_id[2..10].copy_from_slice(&(hand + 1).to_be_bytes());
                seq.submit(
                    Operation::Deposit {
                        deposit_id,
                        owner: p.key.public_bytes(),
                        asset_class: AssetClass::Play,
                        amount: BUY_IN,
                    },
                    1_500,
                )
                .unwrap();
            }
            seq.mark_proven_through(seq.state().seq);
        }

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
                1_600,
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
                    asset_class: AssetClass::Play,
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
        seq.submit(Operation::Settle(Box::new(record)), 2_000).unwrap();

        // 第二手买入需要 proven note：第一手结算后推水位（赔付 note
        // 由此转 proven；与 gen-fixture 语义一致）。
        if hand == 0 {
            seq.mark_proven_through(seq.state().seq);
        }
    }

    // WAL 落盘：create + with_fsync(false)（任务契约）。
    let wal_path = dir.join("appchain.wal");
    let mut wal = WalWriter::create(&wal_path)
        .map(|w| w.with_fsync(false))
        .unwrap();
    for f in seq.export_chain() {
        wal.append(&f).unwrap();
    }
    wal.sync().unwrap();
    (seq_public, bindings)
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

// ===== server 启动与 HTTP 客户端 =====

struct ServerHandle {
    addr: SocketAddr,
}

/// 启动网关（全量参数：proven log / proof registry / aggregate log）。
#[allow(clippy::too_many_arguments)]
fn start_server_full(
    wal: &Path,
    public: [u8; 32],
    proven_log: Option<&Path>,
    proof_registry: Option<&Path>,
    aggregate_log: Option<&Path>,
    rate_per_sec: u32,
    burst: u32,
    l1_url: Option<String>,
) -> ServerHandle {
    let state = Arc::new(
        state::load(wal, public, proven_log, proof_registry, aggregate_log)
            .expect("gateway state loads from fixture"),
    );
    let listener = server::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    let l1 = l1_url.map(|u| l1::L1Client::from_url(&u).expect("valid l1 url"));
    let _join = server::spawn(
        listener,
        state,
        server::ServerOptions {
            public: false,
            rate_per_sec,
            burst,
            l1,
        },
    );
    ServerHandle { addr }
}

/// 兼容既有用例的最小启动（无 sidecar、宽松限流）。
fn start_server(
    wal: &Path,
    public: [u8; 32],
    proven_log: Option<&Path>,
    rate_per_sec: u32,
    burst: u32,
    l1_url: Option<String>,
) -> ServerHandle {
    start_server_full(
        wal,
        public,
        proven_log,
        None,
        None,
        rate_per_sec,
        burst,
        l1_url,
    )
}

/// 极简 HTTP/1.1 客户端（一请求一连接，Connection: close）。
fn request(addr: SocketAddr, method: &str, target: &str) -> (u16, Vec<(String, String)>, String) {
    let raw = raw_request(addr, &format!(
        "{method} {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    ));
    parse_response(&raw)
}

fn raw_request(addr: SocketAddr, payload: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).expect("client connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(payload.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).expect("client read");
    buf
}

fn parse_response(raw: &[u8]) -> (u16, Vec<(String, String)>, String) {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap_or((l, ""));
            (k.trim().to_ascii_lowercase(), v.trim().to_string())
        })
        .collect();
    (status, headers, body.to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("response body is json")
}

// ===== 测试 =====

#[test]
fn status_without_proven_log_reports_null_watermark() {
    let dir = fixture_dir("status-null");
    let (public, _) = build_wal(&dir, 0x21);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    let (status, headers, body) = request(srv.addr, "GET", "/api/v1/status");
    assert_eq!(status, 200);
    assert_eq!(
        headers.iter().any(|(k, v)| k == "x-zchain-gateway" && v == "replay-v1"),
        true,
        "all responses carry X-Zchain-Gateway: replay-v1"
    );
    assert_eq!(
        headers.iter().any(|(k, v)| k == "cache-control" && v == "max-age=5"),
        true,
        "status carries Cache-Control: max-age=5"
    );
    let v = json(&body);
    assert_eq!(v["env"], "devnet");
    assert_eq!(v["chain_head"]["index"], 8, "9 frames → head index 8");
    assert_eq!(
        v["chain_head"]["hash"].as_str().map(str::len),
        Some(64),
        "head hash 64hex"
    );
    assert_eq!(
        v["chain_head"]["state_root"].as_str().map(str::len),
        Some(64)
    );
    // 头哈希与 lib 侧 chain_head 一致（重放即恢复的强断言）。
    let frames = poker_appchain::wal::read_all(&dir.join("appchain.wal")).unwrap();
    let expect_head = hex::encode(poker_appchain::soft_confirm::chain_head(&frames).unwrap());
    assert_eq!(v["chain_head"]["hash"], expect_head);
    assert_eq!(v["sequencer_public"], hex::encode(public));
    assert_eq!(v["frame_count"], 9);
    assert_eq!(v["settlement_count"], 2);
    assert_eq!(v["watermark"], serde_json::Value::Null);
    assert_eq!(v["watermark_source"], "none");
    assert_eq!(v["batch_covered_through"], serde_json::Value::Null);
    assert_eq!(v["latest_batch_root"], serde_json::Value::Null);
}

#[test]
fn frames_pagination_caps_and_summaries() {
    let dir = fixture_dir("frames");
    let (public, _) = build_wal(&dir, 0x22);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    // 正常分页
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/frames?offset=2&limit=3");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["total"], 9);
    let page = v["frames"].as_array().unwrap();
    assert_eq!(page.len(), 3);
    assert_eq!(page[0]["index"], 2);
    assert_eq!(page[2]["index"], 4);
    for f in page {
        assert!(f["ts_ms"].is_u64());
        assert_eq!(f["state_root"].as_str().map(str::len), Some(64));
        // 摘要只含 op 类型名，不内联 op 细节
        assert!(matches!(
            f["op"].as_str(),
            Some("OpenTable" | "Deposit" | "BuyIn" | "Settle")
        ));
        assert!(f.get("op_detail").is_none());
    }

    // limit 上限 200（截断并回显生效值）
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/frames?limit=1000");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["limit"], 200);
    assert_eq!(v["frames"].as_array().unwrap().len(), 9);

    // offset 越界 → 空页
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/frames?offset=100");
    assert_eq!(status, 200);
    assert_eq!(json(&body)["frames"].as_array().unwrap().len(), 0);

    // 参数解析失败 → 400
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/frames?offset=abc");
    assert_eq!(status, 400);
    assert!(json(&body)["error"].is_string());
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/frames?limit=-1");
    assert_eq!(status, 400);
}

#[test]
fn settlements_pagination_and_table_filter() {
    let dir = fixture_dir("settlements");
    let (public, _) = build_wal(&dir, 0x23);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    let (status, _, body) = request(srv.addr, "GET", "/api/v1/settlements");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["total"], 2);
    let items = v["settlements"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for s in items {
        assert_eq!(s["table_id"], 1);
        assert_eq!(s["hand_binding"].as_str().map(str::len), Some(64));
        assert_eq!(s["pot"], 2_000);
        assert_eq!(s["rake_base"], 2_000);
        assert_eq!(s["rake_total"], 0);
        // payout 摘要：owner 缩写（非全量 hex）+ amount
        let payouts = s["payouts"].as_array().unwrap();
        assert_eq!(payouts.len(), 2);
        for p in payouts {
            let short = p["owner_short"].as_str().unwrap();
            assert!(short.len() < 66 && short.contains('…'), "abbreviated owner: {short}");
            assert_eq!(p["amount"], 1_000);
        }
        // 无 proven log → 全部 soft_accepted
        assert_eq!(s["level"], "soft_accepted");
    }

    // table_id 过滤
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/settlements?table_id=1");
    assert_eq!(status, 200);
    assert_eq!(json(&body)["total"], 2);
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/settlements?table_id=99");
    assert_eq!(status, 200);
    assert_eq!(json(&body)["total"], 0);
    // 坏 table_id → 400
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/settlements?table_id=zz");
    assert_eq!(status, 400);

    // 分页
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/settlements?offset=1&limit=1");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["total"], 2);
    assert_eq!(v["settlements"].as_array().unwrap().len(), 1);
    assert_eq!(v["settlements"][0]["frame_index"], 8);
}

#[test]
fn settlement_detail_hit_miss_and_bad_hex() {
    let dir = fixture_dir("detail");
    let (public, bindings) = build_wal(&dir, 0x24);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    // 命中：全量明细
    let target = format!("/api/v1/settlement/{}", hex::encode(bindings[0]));
    let (status, _, body) = request(srv.addr, "GET", &target);
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["table_id"], 1);
    assert_eq!(v["hand_binding"], hex::encode(bindings[0]));
    assert_eq!(v["pot"], 2_000);
    assert_eq!(v["policy_commitment"].as_str().map(str::len), Some(64));
    assert_eq!(v["inputs"].as_array().unwrap().len(), 2);
    for i in v["inputs"].as_array().unwrap() {
        assert_eq!(i["commitment"].as_str().map(str::len), Some(64));
        // nullifier/owner 与列表端点同款缩写（short_hex 摘要，非全量 hex）
        let nf = i["nullifier"].as_str().unwrap();
        assert!(nf.len() < 64 && nf.contains('…'), "abbreviated nullifier: {nf}");
        let owner = i["owner"].as_str().unwrap();
        assert!(owner.len() < 66 && owner.contains('…'), "abbreviated owner: {owner}");
    }
    assert_eq!(v["payouts"].as_array().unwrap().len(), 2);
    for p in v["payouts"].as_array().unwrap() {
        let owner = p["owner"].as_str().unwrap();
        assert!(owner.len() < 66 && owner.contains('…'), "abbreviated owner: {owner}");
    }
    assert_eq!(v["rake"]["total"], 0);
    assert_eq!(v["rake"]["treasury_out"], serde_json::Value::Null);
    assert_eq!(v["plan"]["gross_pot"], 2_000);
    assert_eq!(v["plan"]["schedule"], "Single");
    assert_eq!(v["hand_proof"], serde_json::Value::Null);

    // 格式合法但不存在 → 404
    let miss = format!("/api/v1/settlement/{}", "d".repeat(64));
    let (status, _, body) = request(srv.addr, "GET", &miss);
    assert_eq!(status, 404);
    assert!(json(&body)["error"].is_string());

    // 坏 hex → 400
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/settlement/deadbeef");
    assert_eq!(status, 400);
}

#[test]
fn tampered_wal_replay_fails() {
    let dir = fixture_dir("tamper");
    let (public, _) = build_wal(&dir, 0x25);
    let wal_path = dir.join("appchain.wal");

    // 伪造：改一帧载荷（不重签）→ 验签必败
    let mut frames = poker_appchain::wal::read_all(&wal_path).unwrap();
    assert!(frames.len() >= 4);
    frames[3].frame.ts_ms += 1;
    let tampered = dir.join("tampered.wal");
    let mut w = WalWriter::create(&tampered)
        .map(|w| w.with_fsync(false))
        .unwrap();
    for f in &frames {
        w.append(f).unwrap();
    }
    w.sync().unwrap();

    let config = SequencerConfig::default();
    let result = Sequencer::replay(
        &tampered,
        public,
        config,
        Arc::new(MetricsRegistry::new()),
    );
    assert!(result.is_err(), "tampered WAL must fail replay");
}

#[test]
fn rate_limit_returns_429() {
    let dir = fixture_dir("ratelimit");
    let (public, _) = build_wal(&dir, 0x26);
    // 1 req/s、突发 2：第 3 个起（毫秒内连发）必 429
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1, 2, None);

    let mut got_429 = 0;
    let mut first_status = 0;
    for (i, status) in (0..6).map(|i| {
        let (status, _, _) = request(srv.addr, "GET", "/api/v1/status");
        (i, status)
    }) {
        if i == 0 {
            first_status = status;
        }
        if status == 429 {
            got_429 += 1;
        }
        assert_ne!(status, 500);
    }
    assert_eq!(first_status, 200, "burst 内首个请求放行");
    assert!(got_429 >= 3, "超突发后必须 429（got {got_429}/5）");
}

#[test]
fn unknown_path_post_and_oversized_request() {
    let dir = fixture_dir("routing");
    let (public, _) = build_wal(&dir, 0x27);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    // 白名单路由：未知路径 404
    let (status, _, body) = request(srv.addr, "GET", "/nope");
    assert_eq!(status, 404);
    assert!(json(&body)["error"].is_string());
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/unknown");
    assert_eq!(status, 404);

    // 非 GET → 405 + Allow: GET
    let (status, headers, body) = request(srv.addr, "POST", "/api/v1/status");
    assert_eq!(status, 405);
    assert!(headers.iter().any(|(k, v)| k == "allow" && v == "GET"));
    assert!(json(&body)["error"].is_string());

    // 超长请求行 → 400（头/行长度上限）
    let long = format!("/api/v1/frames?pad={}", "a".repeat(20_000));
    let (status, _, _) = request(srv.addr, "GET", &long);
    assert_eq!(status, 400);
}

#[test]
fn proven_log_restores_watermark_and_batch_roots() {
    let dir = fixture_dir("proven");
    let (public, _) = build_wal(&dir, 0x28);
    let log_path = dir.join("proven.log");
    // 手写契约 JSONL（两行，带换行）
    std::fs::write(
        &log_path,
        format!(
            "{{\"op_index\":3,\"batch_root\":\"{}\",\"ts_ms\":111}}\n{{\"op_index\":6,\"batch_root\":\"{}\",\"ts_ms\":222}}\n",
            hex::encode([0xAA; 32]),
            hex::encode([0xBB; 32]),
        ),
    )
    .unwrap();

    let srv = start_server(&dir.join("appchain.wal"), public, Some(&log_path), 1_000, 1_000, None);

    let (status, _, body) = request(srv.addr, "GET", "/api/v1/status");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["watermark"], 6, "watermark = 最后一条 op_index");
    assert_eq!(v["watermark_source"], "proven_log");
    assert_eq!(v["batch_covered_through"], 6);
    assert_eq!(v["latest_batch_root"], hex::encode([0xBB; 32]));

    // batch_roots 端点：两行全部列出
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/batch_roots");
    assert_eq!(status, 200);
    let roots = json(&body)["batch_roots"].as_array().unwrap().clone();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0]["op_index"], 3);
    assert_eq!(roots[0]["batch_root"], hex::encode([0xAA; 32]));
    assert_eq!(roots[1]["op_index"], 6);

    // 层级：settle1（frame 5 ≤ 6）proven；settle2（frame 8 > 6）soft_accepted
    let (_, _, body) = request(srv.addr, "GET", "/api/v1/settlements");
    let items = json(&body)["settlements"].as_array().unwrap().clone();
    assert_eq!(items[0]["frame_index"], 5);
    assert_eq!(items[0]["level"], "proven");
    assert_eq!(items[1]["frame_index"], 8);
    assert_eq!(items[1]["level"], "soft_accepted");
}

#[test]
fn proven_log_torn_final_line_is_ignored_with_warning() {
    let dir = fixture_dir("proven-torn");
    let (public, _) = build_wal(&dir, 0x29);
    let log_path = dir.join("proven.log");
    // 第二行无换行（撕裂写）→ 忽略残行，水位回落到最后一条完整记录
    std::fs::write(
        &log_path,
        format!(
            "{{\"op_index\":3,\"batch_root\":\"{}\",\"ts_ms\":111}}\n{{\"op_index\":6,\"batch_r",
            hex::encode([0xAA; 32]),
        ),
    )
    .unwrap();

    let srv = start_server(&dir.join("appchain.wal"), public, Some(&log_path), 1_000, 1_000, None);
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/status");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["watermark"], 3, "torn final line ignored → watermark = 3");
    assert_eq!(v["watermark_source"], "proven_log");
    assert_eq!(v["latest_batch_root"], hex::encode([0xAA; 32]));
}

#[test]
fn l1_proxy_newline_fallback_and_validation() {
    let dir = fixture_dir("l1");
    let (public, _) = build_wal(&dir, 0x2A);

    // 假 zchain 节点：newline-delimited JSON-RPC（与 src/main.rs 同协议）
    let node = TcpListener::bind("127.0.0.1:0").unwrap();
    let node_addr = node.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in node.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                use std::io::BufRead as _;
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let resp = if line.contains("\"get_metrics\"") {
                        r#"{"jsonrpc":"2.0","id":1,"result":{"metrics":"l1_height 42\n"}}"#
                    } else if line.contains("\"get_block\"") {
                        r#"{"jsonrpc":"2.0","id":1,"result":{"height":7,"hash":[1,2]}}"#
                    } else if line.contains("\"get_tx\"") {
                        r#"{"jsonrpc":"2.0","id":1,"result":null}"#
                    } else {
                        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#
                    };
                    stream
                        .write_all(resp.as_bytes())
                        .and_then(|_| stream.write_all(b"\n"))
                        .unwrap();
                    line.clear();
                }
            });
        }
    });

    let srv = start_server(
        &dir.join("appchain.wal"),
        public,
        None,
        1_000,
        1_000,
        Some(format!("http://{node_addr}")),
    );

    // metrics（HTTP POST 到 newline 节点 → 回落路径命中）
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/l1/metrics");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["ok"], true);
    assert_eq!(v["method"], "get_metrics");
    assert_eq!(v["result"]["metrics"], "l1_height 42\n");

    // block?height=
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/l1/block?height=7");
    assert_eq!(status, 200);
    assert_eq!(json(&body)["result"]["height"], 7);

    // tx?hash=（64hex → 32B 数组参数）
    let (status, _, body) = request(srv.addr, "GET", &format!("/api/v1/l1/tx?hash={}", hex::encode([7u8; 32])));
    assert_eq!(status, 200);
    assert_eq!(json(&body)["method"], "get_tx");

    // 参数校验：坏 hash → 400；缺 height → 400
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/l1/tx?hash=zz");
    assert_eq!(status, 400);
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/l1/block");
    assert_eq!(status, 400);
}

#[test]
fn snapshot_writes_explorer_json() {
    let dir = fixture_dir("snapshot");
    let (public, _) = build_wal(&dir, 0x2B);
    let state = Arc::new(
        state::load(&dir.join("appchain.wal"), public, None, None, None).expect("state loads"),
    );
    let out = dir.join("snap");
    snapshot::write_to(&out, &state).expect("snapshot writes");
    let text = std::fs::read_to_string(out.join("explorer.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["mode"], "replay");
    assert_eq!(v["status"]["frame_count"], 9);
    assert_eq!(v["status"]["watermark_source"], "none");
    assert_eq!(v["frames"].as_array().unwrap().len(), 9);
    assert_eq!(v["settlements"].as_array().unwrap().len(), 2);
    assert_eq!(v["batch_roots"].as_array().unwrap().len(), 0);
    assert!(v["generated_unix_ms"].is_u64());
}

// ===== E2：proof 归档注册表 + 下载端点（v1.2.3）=====

/// 写一条合法 proof 注册表条目（binding 参数化）。
fn write_proof_registry(path: &Path, binding: [u8; 32], op_index: u64) {
    let _ = std::fs::remove_file(path);
    let mut w = poker_appchain::proof_registry::ProofRegistryWriter::open(path).unwrap();
    w.with_fsync(false);
    w.append(&poker_appchain::proof_registry::ProofRegistryEntry {
        binding_hex: hex::encode(binding),
        op_index,
        engine: "host-validate-v2".to_string(),
        attestor_public: [0x55; 32],
        payload: vec![0xABu8; 64],
    })
    .unwrap();
}

#[test]
fn proof_endpoints_hit_miss_bad_hex_and_settlement_link() {
    let dir = fixture_dir("proof-endpoints");
    let (public, bindings) = build_wal(&dir, 0x2C);
    let reg = dir.join("proof_registry.jsonl");
    write_proof_registry(&reg, bindings[0], 3);

    let srv = start_server_full(
        &dir.join("appchain.wal"),
        public,
        None,
        Some(&reg),
        None,
        1_000,
        1_000,
        None,
    );

    // 列表端点：元数据形态（binding/op_index/engine/payload 字节数），无 payload 内联
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/proofs");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["total"], 1);
    let items = v["proofs"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["binding_hex"], hex::encode(bindings[0]));
    assert_eq!(items[0]["op_index"], 3);
    assert_eq!(items[0]["engine"], "host-validate-v2");
    assert_eq!(items[0]["payload_bytes"], 64);
    assert!(items[0].get("payload_b64").is_none(), "list must not inline payload");
    // 分页与坏参数
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/proofs?offset=1");
    assert_eq!(status, 200);
    assert_eq!(json(&body)["proofs"].as_array().unwrap().len(), 0);
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/proofs?limit=zz");
    assert_eq!(status, 400);

    // 下载端点：200 + X-Zchain-Engine + payload_b64 可解码
    let target = format!("/api/v1/proof/{}", hex::encode(bindings[0]));
    let (status, headers, body) = request(srv.addr, "GET", &target);
    assert_eq!(status, 200);
    assert!(
        headers.iter().any(|(k, val)| k == "x-zchain-engine" && val == "host-validate-v2"),
        "download must carry X-Zchain-Engine"
    );
    let v = json(&body);
    assert_eq!(v["binding_hex"], hex::encode(bindings[0]));
    assert_eq!(v["op_index"], 3);
    assert_eq!(v["payload_len"], 64);
    let decoded = poker_appchain::proof_registry::b64_decode(v["payload_b64"].as_str().unwrap())
        .expect("payload_b64 decodes");
    assert_eq!(decoded.len(), 64);
    assert_eq!(decoded, vec![0xABu8; 64]);

    // 未命中（格式合法）→ 404 JSON
    let miss = format!("/api/v1/proof/{}", "e".repeat(64));
    let (status, _, body) = request(srv.addr, "GET", &miss);
    assert_eq!(status, 404);
    assert!(json(&body)["error"].is_string());
    // 坏 hex → 400
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/proof/deadbeef");
    assert_eq!(status, 400);

    // settlement 明细：payout_root 非零 + proof 链接（命中时带 engine）
    let detail = format!("/api/v1/settlement/{}", hex::encode(bindings[0]));
    let (status, _, body) = request(srv.addr, "GET", &detail);
    assert_eq!(status, 200);
    let v = json(&body);
    let payout_root = v["payout_root"].as_str().expect("payout_root present");
    assert_eq!(payout_root.len(), 64);
    assert_ne!(payout_root, "0".repeat(64), "payout_root must be non-zero");
    assert_eq!(v["proof"]["href"], format!("/api/v1/proof/{}", hex::encode(bindings[0])));
    assert_eq!(v["proof"]["engine"], "host-validate-v2");

    // 无注册表命中的结算（第二手）→ proof.engine = null（链接仍给出）
    let detail2 = format!("/api/v1/settlement/{}", hex::encode(bindings[1]));
    let (_, _, body) = request(srv.addr, "GET", &detail2);
    let v = json(&body);
    assert_eq!(v["proof"]["engine"], serde_json::Value::Null);
    assert_eq!(v["proof"]["href"], format!("/api/v1/proof/{}", hex::encode(bindings[1])));
}

#[test]
fn aggregates_endpoint_and_status_fields() {
    let dir = fixture_dir("aggregates");
    let (public, _) = build_wal(&dir, 0x2D);
    // 手写契约 aggregate log（两行，index 连续 / through_op 递增）
    let alog = dir.join("aggregate.log");
    let line = |index: u64, through_op: u64, root: [u8; 32], batch_count: u64| {
        format!(
            "{{\"index\":{index},\"through_op\":{through_op},\"root\":\"{}\",\"ts_ms\":1000,\"batch_count\":{batch_count}}}\n",
            hex::encode(root)
        )
    };
    let r0 = poker_appchain::aggregate::aggregate_roots(&[[0xAA; 32]]).unwrap();
    let r1 = poker_appchain::aggregate::aggregate_roots(&[[0xAA; 32], [0xBB; 32]]).unwrap();
    std::fs::write(
        &alog,
        format!(
            "{}{}",
            line(0, 3, r0, 1),
            line(1, 6, r1, 2),
        ),
    )
    .unwrap();

    let srv = start_server_full(
        &dir.join("appchain.wal"),
        public,
        None,
        None,
        Some(&alog),
        1_000,
        1_000,
        None,
    );

    let (status, _, body) = request(srv.addr, "GET", "/api/v1/aggregates");
    assert_eq!(status, 200);
    let items = json(&body)["aggregates"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["index"], 0);
    assert_eq!(items[0]["through_op"], 3);
    assert_eq!(items[0]["root"], hex::encode(r0));
    assert_eq!(items[0]["batch_count"], 1);
    assert_eq!(items[1]["index"], 1);
    assert_eq!(items[1]["root"], hex::encode(r1));

    // status 增字段：latest_aggregate_root / latest_aggregate_through_op
    let (status, _, body) = request(srv.addr, "GET", "/api/v1/status");
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["latest_aggregate_root"], hex::encode(r1));
    assert_eq!(v["latest_aggregate_through_op"], 6);

    // 无 aggregate log：两字段 = null
    let srv2 = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);
    let (_, _, body) = request(srv2.addr, "GET", "/api/v1/status");
    let v = json(&body);
    assert_eq!(v["latest_aggregate_root"], serde_json::Value::Null);
    assert_eq!(v["latest_aggregate_through_op"], serde_json::Value::Null);
    let (_, _, body) = request(srv2.addr, "GET", "/api/v1/aggregates");
    assert_eq!(json(&body)["aggregates"].as_array().unwrap().len(), 0);
}

#[test]
fn corrupt_aggregate_log_fails_gateway_startup() {
    let dir = fixture_dir("agg-corrupt");
    let (public, _) = build_wal(&dir, 0x2E);
    let alog = dir.join("aggregate.log");
    // 中间行损坏（撕裂尾行合法，但完整坏行必须拒绝）
    std::fs::write(&alog, "{\"index\":0,\"through_op\":3,\"root\":\"zz\",\"ts_ms\":1,\"batch_count\":1}\n").unwrap();
    let result = state::load(
        &dir.join("appchain.wal"),
        public,
        None,
        None,
        Some(&alog),
    );
    assert!(result.is_err(), "corrupt aggregate log must fail startup");

    // 撕裂尾行：忽略 + 恢复成功
    std::fs::write(
        &alog,
        format!(
            "{{\"index\":0,\"through_op\":3,\"root\":\"{}\",\"ts_ms\":1,\"batch_count\":1}}\n{{\"index\":1,\"thro",
            hex::encode([0x11; 32]),
        ),
    )
    .unwrap();
    let state = state::load(&dir.join("appchain.wal"), public, None, None, Some(&alog))
        .expect("torn tail ignored");
    assert_eq!(state.aggregates.len(), 1);
}

/// E2 验收闭环（①.5）：fixture 全量重放 → settlements → settlement 明细
/// （payout_root 非零）→ /api/v1/proof/{binding} 归档下载（payload_b64
/// 解码 > 0、binding/op_index 一致）→ 未命中 404 → 坏 hex 400。
#[test]
fn e2e_fixture_settlement_to_proof_download() {
    let dir = fixture_dir("e2e");
    let public = fixture::generate(&dir).expect("fixture generates");
    assert!(dir.join("proof_registry.jsonl").exists());
    assert!(dir.join("aggregate.log").exists());

    let srv = start_server_full(
        &dir.join("appchain.wal"),
        public,
        Some(&dir.join("proven.log")),
        Some(&dir.join("proof_registry.jsonl")),
        Some(&dir.join("aggregate.log")),
        1_000,
        1_000,
        None,
    );

    // (1) settlements 列表 → 选 proven 层的第一手
    let (_, _, body) = request(srv.addr, "GET", "/api/v1/settlements");
    let items = json(&body)["settlements"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["level"], "proven");
    let binding = items[0]["hand_binding"].as_str().unwrap().to_string();

    // (2) settlement 明细：payout_root 非零 + proof 链接命中引擎
    let (_, _, body) = request(srv.addr, "GET", &format!("/api/v1/settlement/{binding}"));
    let v = json(&body);
    let payout_root = v["payout_root"].as_str().expect("payout_root present");
    assert_eq!(payout_root.len(), 64);
    assert_ne!(payout_root, "0".repeat(64));
    assert_eq!(v["proof"]["engine"], "host-validate-v2");

    // (3) 归档下载：payload_b64 解码 > 0，binding/op_index 一致
    let (status, headers, body) = request(srv.addr, "GET", &format!("/api/v1/proof/{binding}"));
    assert_eq!(status, 200);
    let v = json(&body);
    assert_eq!(v["binding_hex"], binding.as_str());
    assert_eq!(v["op_index"], 6, "第一手结算 op 的 bundle");
    assert_eq!(v["engine"], "host-validate-v2");
    let payload = poker_appchain::proof_registry::b64_decode(v["payload_b64"].as_str().unwrap())
        .expect("payload_b64 decodes");
    assert!(!payload.is_empty(), "payload must decode to non-empty bytes");
    assert_eq!(payload.len(), v["payload_len"].as_u64().unwrap() as usize);
    // 64B attestation 签名可被独立验证（真 bundle，非伪记录）
    let bundle_ok = {
        use poker_appchain::pipeline::{ProofBundle, SettlementProver};
        let engine = poker_appchain::pipeline::ValidationEngine::default();
        engine
            .verify(&ProofBundle {
                binding_hex: binding.clone(),
                op_index: 6,
                engine: "host-validate-v2",
                attestor_public: hex::decode(v["attestor_public"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                payload: payload.clone(),
            })
            .is_ok()
    };
    assert!(bundle_ok, "archived payload must verify against the engine");
    assert!(
        headers.iter().any(|(k, val)| k == "x-zchain-engine" && val == "host-validate-v2"),
        "download carries X-Zchain-Engine"
    );

    // (4) 未命中 → 404；坏 hex → 400
    let (status, _, body) = request(srv.addr, "GET", &format!("/api/v1/proof/{}", "f".repeat(64)));
    assert_eq!(status, 404);
    assert!(json(&body)["error"].is_string());
    let (status, _, _) = request(srv.addr, "GET", "/api/v1/proof/nothex");
    assert_eq!(status, 400);

    // (5) aggregates 端点 + status 最新聚合（fixture 产一条）
    let (_, _, body) = request(srv.addr, "GET", "/api/v1/aggregates");
    let aggs = json(&body)["aggregates"].as_array().unwrap().clone();
    assert_eq!(aggs.len(), 1);
    assert_eq!(aggs[0]["index"], 0);
    assert_eq!(aggs[0]["batch_count"], 1);
    assert_eq!(aggs[0]["through_op"], 6);
    let (_, _, body) = request(srv.addr, "GET", "/api/v1/status");
    let v = json(&body);
    assert_eq!(v["latest_aggregate_root"], aggs[0]["root"]);
    assert_eq!(v["latest_aggregate_through_op"], 6);
}

/// 审计修复 4b：并发连接硬上限——占满上限的静默连接（连而不发，占住
/// 每连接线程直至读超时）之后，新连接被拒（最小 503；竞态下也可能以
/// RST/空响应丢弃——过载丢弃语义，见 server.rs 注释）；holder 释放后
/// 计数守卫递减、服务恢复（计数不泄漏）。
#[test]
fn connection_cap_rejects_with_503_and_recovers() {
    // RST 容忍探针：过载丢弃既可能是可读的最小 503，也可能是 RST/空
    // 响应（返回 0）；硬边界是绝不返回 200。
    let probe_status = |addr: SocketAddr| -> u16 {
        let mut s = TcpStream::connect(addr).expect("probe connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        match s.read_to_end(&mut buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return 0,
            Err(e) => panic!("probe read: {e}"),
        }
        if buf.is_empty() {
            return 0;
        }
        parse_response(&buf).0
    };

    let dir = fixture_dir("conncap");
    let (public, _) = build_wal(&dir, 0x2F);
    let srv = start_server(&dir.join("appchain.wal"), public, None, 1_000, 1_000, None);

    // 占满上限：N 个"连而不发"的 holder（服务端 read_request 阻塞到
    // 5s 读超时，连接槽位一直被占）。
    let mut holders: Vec<TcpStream> = Vec::new();
    for _ in 0..server::MAX_CONCURRENT_CONNECTIONS {
        let s = TcpStream::connect(srv.addr).expect("holder connect");
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        holders.push(s);
    }

    // 超限连接：被拒——0（RST/空丢弃）或最小 503，绝不被服务成 200。
    let status = probe_status(srv.addr);
    assert_ne!(status, 200, "over-cap connection must not be served");
    assert!(
        status == 0 || status == 503,
        "readable over-cap rejection must be minimal 503, got {status}"
    );

    // holder 全部关闭 → 守卫递减 → 服务恢复（读超时 5s + 余量上界）。
    drop(holders);
    let mut recovered = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        let status = probe_status(srv.addr);
        if status == 200 {
            recovered = true;
            break;
        }
        assert!(
            status == 0 || status == 503,
            "recovery window: expected 503/reset, got {status}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(recovered, "service must recover after holders close (guard decrements)");
}
