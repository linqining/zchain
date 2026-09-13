//! M4/E2：archive 持久化索引的集成测试。
//!
//! 覆盖：
//! 1. `build_index` → `load_index` 等价查询（binding / 时间窗 / 桌）；
//! 2. 索引文件 digest 篡改 / 行数篡改 → 装载 Err（fail-closed）；
//! 3. 网关双数据面等价：replay 路径（`state::load`）与 index 路径
//!    （`state::load_with_index`）的 `/api/v1/frames`、`/api/v1/settlements`
//!    查询结果逐字节一致；status 链头/计数一致；settlement 明细一致；
//!    索引与 sequencer 公钥不匹配 → 启动拒绝。
//!
//! 网关 bin 的模块经 `#[path]` 挂载进本测试 crate（与
//! tests/explorer_gateway.rs 同范式）；fixture WAL 测试内生成（真实
//! spend/settle 签名，`WalWriter::with_fsync(false)` 落盘）。

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
#[path = "../src/bin/explorer_gateway/state.rs"]
mod state;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use poker_appchain::archive_index::load_index;
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

    fn pk(&self) -> [u8; 33] {
        self.key.public_bytes()
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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "archive-index-tests-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// fixture：2 桌 × 3 手（每手 ts 间隔 60s，便于时间窗过滤断言）。
/// 返回 (public, wal 路径, bindings, 每手 ts)。
fn build_fixture(dir: &Path, seed: u8) -> ([u8; 32], PathBuf, Vec<[u8; 32]>, Vec<u64>) {
    let public = SequencerKey::from_seed(&[seed; 32]).public;
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

    for table in [1u64, 2u64] {
        seq.submit(
            Operation::OpenTable {
                table_id: table,
                policy: FeePolicy::Zero,
            },
            1_000 + table,
        )
        .unwrap();
    }

    let mut bindings = Vec::new();
    let mut ts_list = Vec::new();
    let mut hand_ts = 1_700_000_100_000u64;
    for hand in 0..3u64 {
        // 手按桌轮转：hand0 → 桌1、hand1 → 桌2、hand2 → 桌1
        let table = if hand % 2 == 0 { 1 } else { 2 };
        let mut binding32 = [0u8; 32];
        binding32[..8].copy_from_slice(&(hand + 1).to_be_bytes());
        bindings.push(binding32);
        ts_list.push(hand_ts);

        // 每手各入金 1_000 → 推水位 → 买入
        for (pi, p) in players.iter().enumerate() {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = table as u8;
            deposit_id[1] = pi as u8;
            deposit_id[2..10].copy_from_slice(&(hand + 1).to_be_bytes());
            seq.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: p.key.public_bytes(),
                    asset_class: AssetClass::Play,
                    amount: BUY_IN,
                },
                hand_ts,
            )
            .unwrap();
        }
        seq.mark_proven_through(seq.state().seq);
        for p in &players {
            let note = seq
                .state()
                .note_entries_of(&p.key.public_bytes())
                .into_iter()
                .find(|e| {
                    e.note.amount == BUY_IN
                        && e.note.table_id.is_none()
                        && e.status == NoteStatus::Proven
                })
                .map(|e| e.note.clone())
                .expect("proven note");
            let effect = Operation::BuyIn {
                table_id: table,
                spends: vec![],
                notes: vec![],
                seat_owner: p.key.public_bytes(),
            }
            .effect_digest();
            seq.submit(
                Operation::BuyIn {
                    table_id: table,
                    spends: vec![p.buyin_auth(&note, &effect)],
                    notes: vec![note],
                    seat_owner: p.key.public_bytes(),
                },
                hand_ts + 100,
            )
            .unwrap();
        }
        let seats: Vec<Note> = players
            .iter()
            .map(|p| {
                seq.state()
                    .note_entries_of(&p.key.public_bytes())
                    .into_iter()
                    .find(|e| e.note.table_id == Some(table))
                    .map(|e| e.note.clone())
                    .expect("seat note")
            })
            .collect();
        let pot = BUY_IN * seats.len() as u64;
        let mask = (1u16 << seats.len()) - 1;
        let mut awards = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
        for a in awards.iter_mut().take(seats.len()) {
            *a = BUY_IN;
        }
        let mut record = SettlementRecord {
            table_id: table,
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
        seq.submit(Operation::Settle(Box::new(record)), hand_ts + 200)
            .unwrap();
        hand_ts += 60_000;
    }

    let wal_path = dir.join("appchain.wal");
    let mut wal = WalWriter::create(&wal_path).unwrap().with_fsync(false);
    for f in seq.export_chain() {
        wal.append(&f).unwrap();
    }
    wal.sync().unwrap();
    (public, wal_path, bindings, ts_list)
}

fn get(path: &str, query: &[(&str, &str)]) -> http::Request {
    http::Request {
        method: "GET".to_owned(),
        path: path.to_owned(),
        query: query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
    }
}

fn body(resp: &http::Response) -> serde_json::Value {
    serde_json::from_str(&resp.body).expect("valid json body")
}

#[test]
fn build_load_query_and_tamper_negatives() {
    let dir = temp_dir("build-load");
    let (public, wal, bindings, ts_list) = build_fixture(&dir, 0x21);
    let index_path = dir.join("appchain.index.jsonl");

    let index = poker_appchain::archive_index::build_index(
        &wal,
        public,
        None,
        &index_path,
    )
    .unwrap();
    // 帧计数：2 开桌 + 3 手 × (2 入金 + 2 买入 + 1 结算) = 17
    assert_eq!(index.header().frame_count, 17);
    assert_eq!(index.header().settlement_count, 3);
    assert_eq!(index.header().proof_count, 0);
    assert_eq!(index.header().sequencer_public, public);

    let loaded = load_index(&index_path).unwrap();
    assert_eq!(loaded.header(), index.header());
    assert_eq!(loaded.frames().len(), 17);

    // binding 查询：帧序号/桌/pot 与 fixture 对齐
    for (i, binding) in bindings.iter().enumerate() {
        let hit = loaded.settlement_by_binding(binding).expect("binding hit");
        let s = hit.settle.as_ref().unwrap();
        let want_table = if i % 2 == 0 { 1 } else { 2 };
        assert_eq!(s.table_id, want_table);
        assert_eq!(s.pot, 2_000);
        assert_eq!(s.rake_base, 2_000);
        assert_eq!(s.rake_total, 0);
        assert_eq!(hit.ts_ms, ts_list[i] + 200);
    }
    assert!(loaded
        .settlement_by_binding(&[0u8; 32])
        .is_none(), "零绑定不命中");

    // 时间窗（双闭区间）：只含第 2 手（ts = base + 60_000 + 200）
    let mid = ts_list[1] + 200;
    let window = loaded.frames_by_time_window(ts_list[1], mid);
    assert!(window.iter().all(|f| f.ts_ms >= ts_list[1] && f.ts_ms <= mid));
    assert!(window
        .iter()
        .any(|f| f.settle.is_some() && f.settle.as_ref().unwrap().binding == bindings[1]));
    let all = loaded.frames_by_time_window(0, u64::MAX);
    assert_eq!(all.len(), 17);
    assert!(loaded.frames_by_time_window(u64::MAX, u64::MAX).is_empty());

    // 桌过滤：桌 1 有手 0/2，桌 2 有手 1
    let t1 = loaded.frames_by_table(1);
    assert_eq!(t1.len(), 2);
    assert_eq!(t1.iter().all(|f| f.settle.as_ref().unwrap().table_id == 1), true);
    let t2 = loaded.frames_by_table(2);
    assert_eq!(t2.len(), 1);
    assert_eq!(loaded.frames_by_table(9).len(), 0);

    // ===== 负例 1：篡改 digest（翻转头部 digest 一个字符）=====
    let raw = std::fs::read_to_string(&index_path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(|l| l.to_owned()).collect();
    let head = lines[0].clone();
    let flipped = format!(
        "{}{}",
        &head[..head.len() - 2],
        if head.ends_with("aa") { "bb" } else { "aa" }
    );
    lines[0] = flipped;
    std::fs::write(dir.join("tampered_digest.jsonl"), lines.join("\n") + "\n").unwrap();
    assert!(load_index(&dir.join("tampered_digest.jsonl")).is_err(), "digest 篡改必须 Err");

    // ===== 负例 2：删一行帧（行数与头部计数不符 / digest 不符）=====
    let mut lines: Vec<String> = raw.lines().map(|l| l.to_owned()).collect();
    lines.remove(3);
    std::fs::write(dir.join("tampered_missing.jsonl"), lines.join("\n") + "\n").unwrap();
    assert!(load_index(&dir.join("tampered_missing.jsonl")).is_err());

    // ===== 负例 3：改一帧的 offset（digest 不符）=====
    let mut lines: Vec<String> = raw.lines().map(|l| l.to_owned()).collect();
    lines[2] = lines[2].replace("\"offset\":", "\"offset\":9");
    std::fs::write(dir.join("tampered_offset.jsonl"), lines.join("\n") + "\n").unwrap();
    assert!(load_index(&dir.join("tampered_offset.jsonl")).is_err());

    // ===== 负例 4：format 标签错 =====
    let mut lines: Vec<String> = raw.lines().map(|l| l.to_owned()).collect();
    lines[0] = lines[0].replace("archive_index.v1", "archive_index.v2");
    std::fs::write(dir.join("tampered_format.jsonl"), lines.join("\n") + "\n").unwrap();
    assert!(load_index(&dir.join("tampered_format.jsonl")).is_err());

    // ===== 负例 5：垃圾文件 =====
    std::fs::write(dir.join("garbage.jsonl"), b"not json\nat all\n").unwrap();
    assert!(load_index(&dir.join("garbage.jsonl")).is_err());
}

#[test]
fn gateway_replay_and_index_modes_agree() {
    let dir = temp_dir("dual-mode");
    let (public, wal, bindings, _ts) = build_fixture(&dir, 0x22);
    let index_path = dir.join("appchain.index.jsonl");
    poker_appchain::archive_index::build_index(&wal, public, None, &index_path).unwrap();

    let replay = Arc::new(state::load(&wal, public, None, None, None).expect("replay state"));
    let index = Arc::new(
        state::load_with_index(&index_path, &wal, public, None, None, None)
            .expect("index state"),
    );
    assert_eq!(replay.data_source, "replay");
    assert_eq!(index.data_source, "index");

    // frames：两模式响应逐字节一致
    let fr_replay = api::route(&replay, &get("/api/v1/frames", &[("limit", "200")]), None);
    let fr_index = api::route(&index, &get("/api/v1/frames", &[("limit", "200")]), None);
    assert_eq!(fr_replay.status, 200);
    assert_eq!(fr_index.status, 200);
    assert_eq!(fr_replay.body, fr_index.body, "frames 两模式一致");

    // 分页一致性（offset 越页）
    let fr_replay = api::route(&replay, &get("/api/v1/frames", &[("offset", "5"), ("limit", "3")]), None);
    let fr_index = api::route(&index, &get("/api/v1/frames", &[("offset", "5"), ("limit", "3")]), None);
    assert_eq!(fr_replay.body, fr_index.body);

    // settlements：两模式响应逐字节一致（含 table_id 过滤）
    let s_replay = api::route(&replay, &get("/api/v1/settlements", &[]), None);
    let s_index = api::route(&index, &get("/api/v1/settlements", &[]), None);
    assert_eq!(s_replay.status, 200);
    assert_eq!(s_index.status, 200);
    assert_eq!(s_replay.body, s_index.body, "settlements 两模式一致");
    let f_replay = api::route(&replay, &get("/api/v1/settlements", &[("table_id", "2")]), None);
    let f_index = api::route(&index, &get("/api/v1/settlements", &[("table_id", "2")]), None);
    assert_eq!(f_replay.body, f_index.body);

    // status：链头 / 帧计数 / 结算计数一致（data_source 语义化差异）
    let st_replay = body(&api::route(&replay, &get("/api/v1/status", &[]), None));
    let st_index = body(&api::route(&index, &get("/api/v1/status", &[]), None));
    assert_eq!(st_replay["chain_head"], st_index["chain_head"]);
    assert_eq!(st_replay["frame_count"], st_index["frame_count"]);
    assert_eq!(st_replay["settlement_count"], st_index["settlement_count"]);
    assert_eq!(st_replay["sequencer_public"], st_index["sequencer_public"]);
    assert_eq!(st_index["data_source"], "index");
    assert_eq!(st_replay["data_source"], "replay");

    // settlement 明细：两模式逐字节一致（index 模式走定向读帧 + 完整性校验）
    let binding_hex = hex::encode(bindings[2]);
    let p = format!("/api/v1/settlement/{binding_hex}");
    let d_replay = api::route(&replay, &get(&p, &[]), None);
    let d_index = api::route(&index, &get(&p, &[]), None);
    assert_eq!(d_replay.status, 200, "replay 命中");
    assert_eq!(d_index.status, 200, "index 模式定向读帧命中");
    assert_eq!(d_replay.body, d_index.body, "settlement 明细两模式一致");

    // 明细 404 / 坏 hex 一致
    let miss = format!("/api/v1/settlement/{}", "d".repeat(64));
    assert_eq!(
        api::route(&replay, &get(&miss, &[]), None).status,
        404
    );
    assert_eq!(
        api::route(&index, &get(&miss, &[]), None).status,
        404
    );
    assert_eq!(
        api::route(&index, &get("/api/v1/settlement/deadbeef", &[]), None).status,
        400
    );

    // metrics 端点回显数据面标签
    let m_index = body(&api::route(&index, &get("/api/v1/metrics", &[]), None));
    assert_eq!(m_index["mode"], "index");
    let m_replay = body(&api::route(&replay, &get("/api/v1/metrics", &[]), None));
    assert_eq!(m_replay["mode"], "replay");
}

#[test]
fn index_mode_rejects_wrong_sequencer() {
    let dir = temp_dir("wrong-key");
    let (public, wal, _b, _t) = build_fixture(&dir, 0x23);
    let index_path = dir.join("appchain.index.jsonl");
    poker_appchain::archive_index::build_index(&wal, public, None, &index_path).unwrap();

    let other = SequencerKey::from_seed(&[0xFE; 32]).public;
    let err = match state::load_with_index(&index_path, &wal, other, None, None, None) {
        Err(e) => e,
        Ok(_) => panic!("索引发错链必须拒绝装载"),
    };
    assert!(err.contains("sequencer"), "错误信息应指出公钥不匹配: {err}");
}
