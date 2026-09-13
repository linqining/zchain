//! M8：appchain_watcher 独立进程集成测试（真实二进制、真实退出码）。
//!
//! 覆盖：
//! - 好链（WAL + proven log + checkpoint 全给）→ 退出 0；
//! - 篡改一帧 → 退出 1，finding 指明链完整性类别；
//! - 换一个 batch_root → 退出 1，finding 指明 proven log 类别；
//! - 伪造 checkpoint → 退出 1，finding 指明 checkpoint 类别；
//! - 双链分叉 → 退出 1，报告首个分歧 frame index。

#![allow(clippy::too_many_arguments)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::{deposit_and_find, find_note, TestUser};
use poker_appchain::checkpoint::export_checkpoint;
use poker_appchain::keys::SequencerKey;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::batch_root;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::settlement::RakeSplitRecord;
use std::sync::Arc;

/// 每个用例独立的临时目录。
fn fixture_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("poker-appchain-watcher-it").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 构造一条真实好链（含两次结算、两个批次根），返回全部工件路径。
///
/// 帧：0 depA / 1 depB / 2 OpenTable(1, Zero) / 3 BuyInA / 4 BuyInB /
/// 5 Settle1 / 6 BuyInA2 / 7 BuyInB2 / 8 Settle2。
/// 批次：root1 = batch_root([b1]) 覆盖 op 0..=5；root2 = batch_root([b2])
/// 覆盖 op 6..=8。
struct Fixture {
    wal: PathBuf,
    proven_log: PathBuf,
    checkpoint: PathBuf,
    public_hex: String,
}

fn build_good_chain(tag: &str) -> Fixture {
    let dir = fixture_dir(tag);
    let wal = dir.join("chain.wal");
    let proven_log = dir.join("proven.jsonl");
    let checkpoint = dir.join("checkpoint.json");
    let key = SequencerKey::from_seed(&[0xA0u8; 32]);
    let mut seq = Sequencer::new(
        key.clone(),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    );
    seq.attach_wal(&wal).unwrap();
    seq.attach_proven_log(&proven_log).unwrap();

    let alice = TestUser::new(101);
    let bob = TestUser::new(102);
    let deposit_id = |b: u8| {
        let mut d = [0u8; 32];
        d[0] = b;
        d
    };

    // op 0/1：入金
    let note_a = deposit_and_find(&mut seq, &alice, 1_000, AssetClass::Play, 1);
    let note_b = deposit_and_find(&mut seq, &bob, 2_000, AssetClass::Play, 2);
    // 入金 note 翻 proven（否则桌准入拦截 BuyIn；直推不落 sidecar）
    seq.mark_proven_through(1);
    // op 2：开桌（零费）
    seq.submit(
        Operation::OpenTable {
            table_id: 1,
            policy: poker_appchain::fee::FeePolicy::Zero,
        },
        3_000,
    )
    .unwrap();
    // op 3/4：买入 seat
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![alice.buyin_auth(&note_a, 1, alice.pk())],
            notes: vec![note_a],
            seat_owner: alice.pk(),
        },
        3_100,
    )
    .unwrap();
    let seat_a = find_note(&seq, &alice, 1_000);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![bob.buyin_auth(&note_b, 1, bob.pk())],
            notes: vec![note_b],
            seat_owner: bob.pk(),
        },
        3_200,
    )
    .unwrap();
    let seat_b = find_note(&seq, &bob, 2_000);

    // op 5：Settle1（pot 3000 → 1500/1500）
    let record1 = common::two_player_settlement(
        1, &alice, &bob, &seat_a, &seat_b, 3_000, 1_500, 1_500,
        &poker_appchain::fee::FeePolicy::Zero, 0xB1,
    );
    seq.submit(Operation::Settle(Box::new(record1)), 4_000)
        .unwrap();
    let root1 = batch_root(&[[0xB1u8; 32]]).unwrap();
    seq.mark_proven_through_with_root(5, root1);

    // op 6/7：再买入（用上一手的 payout note）
    let payout_a = find_note(&seq, &alice, 1_500);
    let payout_b = find_note(&seq, &bob, 1_500);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![alice.buyin_auth(&payout_a, 1, alice.pk())],
            notes: vec![payout_a],
            seat_owner: alice.pk(),
        },
        4_100,
    )
    .unwrap();
    let seat_a2 = find_note(&seq, &alice, 1_500);
    seq.submit(
        Operation::BuyIn {
            table_id: 1,
            spends: vec![bob.buyin_auth(&payout_b, 1, bob.pk())],
            notes: vec![payout_b],
            seat_owner: bob.pk(),
        },
        4_200,
    )
    .unwrap();
    let seat_b2 = find_note(&seq, &bob, 1_500);

    // op 8：Settle2（pot 3000 → 2000/1000）
    let record2 = common::two_player_settlement(
        1, &alice, &bob, &seat_a2, &seat_b2, 3_000, 2_000, 1_000,
        &poker_appchain::fee::FeePolicy::Zero, 0xB2,
    );
    seq.submit(Operation::Settle(Box::new(record2)), 5_000)
        .unwrap();
    let root2 = batch_root(&[[0xB2u8; 32]]).unwrap();
    seq.mark_proven_through_with_root(8, root2);

    assert_eq!(seq.chain().len(), 9);
    assert_eq!(seq.proven_watermark(), 8);
    assert_eq!(seq.batch_roots().len(), 2);
    export_checkpoint(&seq, &checkpoint).unwrap();
    drop(seq);

    // sidecar 应有两行（冻结契约）
    let plog_text = std::fs::read_to_string(&proven_log).unwrap();
    assert_eq!(plog_text.lines().count(), 2);

    Fixture {
        wal,
        proven_log,
        checkpoint,
        public_hex: hex::encode(key.public),
    }
}

fn watcher_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_appchain_watcher"))
}

struct Run {
    code: i32,
    stdout: String,
}

fn run_watcher(extra_args: &[&str]) -> Run {
    let out = watcher_cmd().args(extra_args).output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
    }
}

/// 伪造/篡改产出的 JSON 改写辅助。
fn rewrite_json(path: &std::path::Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    edit(&mut v);
    std::fs::write(path, serde_json::to_string(&v).unwrap()).unwrap();
}

#[test]
fn good_chain_exits_zero() {
    let f = build_good_chain("good");
    let json_out = f.wal.parent().unwrap().join("report.json");
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--proven-log", f.proven_log.to_str().unwrap(),
        "--checkpoint", f.checkpoint.to_str().unwrap(),
        "--json-out", json_out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}", r.stdout);
    assert!(r.stdout.contains("CONSISTENT"), "stdout:\n{}", r.stdout);
    // JSON 结构化 findings
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json_out).unwrap()).unwrap();
    assert_eq!(doc["consistent"], serde_json::Value::Bool(true));
    assert_eq!(doc["frames_checked"], serde_json::Value::from(9));
    assert_eq!(doc["proven_entries"], serde_json::Value::from(2));
}

/// 篡改一帧（字节翻转）→ 退出 1，类别指明链完整性/状态重放。
#[test]
fn tampered_frame_exits_one_with_chain_finding() {
    let f = build_good_chain("tamper");
    // 翻转第一帧体内一个字节（前 4 字节是 u32 长度头，避开）
    let mut bytes = std::fs::read(&f.wal).unwrap();
    assert!(bytes.len() > 12);
    bytes[12] ^= 0x01;
    let bad_wal = f.wal.parent().unwrap().join("tampered.wal");
    std::fs::write(&bad_wal, bytes).unwrap();
    let r = run_watcher(&[
        "--appchain-wal", bad_wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("chain_integrity") || r.stdout.contains("state_replay"),
        "finding must name the chain category; stdout:\n{}",
        r.stdout
    );
    assert!(r.stdout.contains("INCONSISTENT"));
}

/// 换一个 batch_root → 退出 1，finding 指明 proven log 类别。
#[test]
fn wrong_batch_root_exits_one_with_proven_log_finding() {
    let f = build_good_chain("badroot");
    // 改写 proven log 第二行的 batch_root（合法 hex，但与重算不符）
    let text = std::fs::read_to_string(&f.proven_log).unwrap();
    let forged: String = text
        .lines()
        .map(|line| {
            if line.contains("\"op_index\":8") {
                format!(
                    "{{\"op_index\":8,\"batch_root\":\"{}\",\"ts_ms\":{}}}",
                    hex::encode([0xEEu8; 32]),
                    line.split("\"ts_ms\":").nth(1).unwrap().trim_end_matches('}').trim()
                )
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&f.proven_log, format!("{forged}\n")).unwrap();
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--proven-log", f.proven_log.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("proven_log_root_mismatch"),
        "finding must name proven log root category; stdout:\n{}",
        r.stdout
    );
}

/// 伪造 checkpoint（改水位且重签 digest，仍与重放状态不符）→ 退出 1。
#[test]
fn forged_checkpoint_exits_one() {
    let f = build_good_chain("badckpt");
    // (1) 改字段不改 digest
    let forged = f.checkpoint.parent().unwrap().join("forged1.json");
    std::fs::copy(&f.checkpoint, &forged).unwrap();
    rewrite_json(&forged, |v| {
        v["watermark"] = serde_json::Value::from(99);
    });
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--checkpoint", forged.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(r.stdout.contains("checkpoint_mismatch"));

    // (2) 连 digest 一起重算的"自洽"伪造（watermark=99，digest 按规范字节
    //     重签）→ 字段对拍挡住（digest 对但与重放状态不符）
    let forged2 = f.checkpoint.parent().unwrap().join("forged2.json");
    std::fs::copy(&f.checkpoint, &forged2).unwrap();
    rewrite_json(&forged2, |v| {
        v["watermark"] = serde_json::Value::from(99);
        let mut payload: Vec<u8> = b"zchain.appchain.checkpoint.v1.payload".to_vec();
        payload.extend_from_slice(&v["head_index"].as_u64().unwrap().to_be_bytes());
        payload.extend_from_slice(&hex::decode(v["head_hash"].as_str().unwrap()).unwrap());
        payload.extend_from_slice(&v["frame_count"].as_u64().unwrap().to_be_bytes());
        payload.extend_from_slice(&hex::decode(v["state_root"].as_str().unwrap()).unwrap());
        payload.extend_from_slice(&v["watermark"].as_u64().unwrap().to_be_bytes());
        for b in v["batch_roots"].as_array().unwrap() {
            payload.extend_from_slice(&b["op_index"].as_u64().unwrap().to_be_bytes());
            payload.extend_from_slice(&hex::decode(b["root"].as_str().unwrap()).unwrap());
        }
        v["payload_digest"] =
            serde_json::Value::from(hex::encode(poker_appchain::keys::blake2s32(&[&payload])));
    });
    let r2 = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--checkpoint", forged2.to_str().unwrap(),
    ]);
    assert_eq!(r2.code, 1, "stdout:\n{}", r2.stdout);
    assert!(r2.stdout.contains("checkpoint_mismatch"));
    assert!(r2.stdout.contains("watermark mismatch") || r2.stdout.contains("digest mismatch"));
}

/// 双链分叉：--wal-b 喂入不同历史 → 退出 1，报告首个分歧 index 0。
#[test]
fn fork_detected_with_divergence_index() {
    let f = build_good_chain("fork");
    // 链 B：不同金额的入金历史（op 0 即分叉）
    let wal_b = f.wal.parent().unwrap().join("chain_b.wal");
    let key = SequencerKey::from_seed(&[0xA0u8; 32]);
    let mut seq = Sequencer::new(
        key.clone(),
        SequencerConfig::default(),
        Arc::new(MetricsRegistry::new()),
    );
    seq.attach_wal(&wal_b).unwrap();
    let alice = TestUser::new(201);
    seq.submit(
        Operation::Deposit {
            deposit_id: [7u8; 32],
            owner: alice.pk(),
            asset_class: AssetClass::Play,
            amount: 999, // 与链 A 的 1_000 不同
        },
        1_000,
    )
    .unwrap();
    drop(seq);

    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--wal-b", wal_b.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(r.stdout.contains("fork_detected"), "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("diverge at frame index 0"),
        "must report first divergence index; stdout:\n{}",
        r.stdout
    );
}

/// 无人提及的回归锚：RakeSplitRecord 在固定记录中保持零抽取
/// （Zero 桌 watcher 语义检查路径的守门样本）。
#[test]
fn zero_policy_records_carry_zero_rake() {
    let r = RakeSplitRecord {
        total: 0,
        treasury_out: None,
        operator_out: None,
    };
    assert_eq!(r.total, 0);
}

// ===== (c2) aggregate log 一致性（v1.2.3）=====

/// 手写一条契约格式 aggregate log 行。
fn aggregate_line(index: u64, through_op: u64, root: [u8; 32], batch_count: u64) -> String {
    format!(
        "{{\"index\":{},\"through_op\":{},\"root\":\"{}\",\"ts_ms\":{},\"batch_count\":{}}}\n",
        index,
        through_op,
        hex::encode(root),
        1_700_000_000_000i64 + i64::try_from(index).unwrap(),
        batch_count
    )
}

/// 好链 + 与 proven log 一致的 aggregate log → 退出 0（含 aggregate_entries 计数）。
#[test]
fn good_chain_with_aggregate_log_exits_zero() {
    let f = build_good_chain("agg-good");
    // 窗口 (0, 8] 内的批次根 = root1@5, root2@8
    let root1 = batch_root(&[[0xB1u8; 32]]).unwrap();
    let root2 = batch_root(&[[0xB2u8; 32]]).unwrap();
    let agg_root = poker_appchain::aggregate::aggregate_roots(&[root1, root2]).unwrap();
    let alog = f.wal.parent().unwrap().join("aggregate.jsonl");
    std::fs::write(&alog, aggregate_line(0, 8, agg_root, 2)).unwrap();

    let json_out = f.wal.parent().unwrap().join("agg-report.json");
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--proven-log", f.proven_log.to_str().unwrap(),
        "--aggregate-log", alog.to_str().unwrap(),
        "--json-out", json_out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stdout:\n{}", r.stdout);
    assert!(r.stdout.contains("CONSISTENT"), "stdout:\n{}", r.stdout);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json_out).unwrap()).unwrap();
    assert_eq!(doc["aggregate_entries"], serde_json::Value::from(1));
    assert_eq!(doc["consistent"], serde_json::Value::Bool(true));
}

/// 换一个聚合根 → 退出 1，finding 指明 aggregate_mismatch。
#[test]
fn swapped_aggregate_root_exits_one() {
    let f = build_good_chain("agg-swap");
    let forged_root = hex::encode([0xEEu8; 32]);
    let alog = f.wal.parent().unwrap().join("aggregate.jsonl");
    std::fs::write(
        &alog,
        format!(
            "{{\"index\":0,\"through_op\":8,\"root\":\"{forged_root}\",\"ts_ms\":1700000000000,\"batch_count\":2}}\n"
        ),
    )
    .unwrap();
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--proven-log", f.proven_log.to_str().unwrap(),
        "--aggregate-log", alog.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("aggregate_mismatch"),
        "finding must name aggregate_mismatch; stdout:\n{}",
        r.stdout
    );
    assert!(r.stdout.contains("INCONSISTENT"));
}

/// index 跳号 → 退出 1（aggregate_range finding）。
#[test]
fn aggregate_skipped_index_exits_one() {
    let f = build_good_chain("agg-gap");
    let root1 = batch_root(&[[0xB1u8; 32]]).unwrap();
    let root2 = batch_root(&[[0xB2u8; 32]]).unwrap();
    let agg_root = poker_appchain::aggregate::aggregate_roots(&[root1, root2]).unwrap();
    let alog = f.wal.parent().unwrap().join("aggregate.jsonl");
    // index 0 → 2（跳过 1）
    std::fs::write(
        &alog,
        format!(
            "{}{}",
            aggregate_line(0, 5, agg_root, 1),
            aggregate_line(2, 8, agg_root, 1),
        ),
    )
    .unwrap();
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--proven-log", f.proven_log.to_str().unwrap(),
        "--aggregate-log", alog.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(
        r.stdout.contains("aggregate_range"),
        "finding must name aggregate_range; stdout:\n{}",
        r.stdout
    );
}

/// aggregate log 无 proven log 基准 → 无法独立重算，fail-closed 退出 1。
#[test]
fn aggregate_log_without_proven_log_exits_one() {
    let f = build_good_chain("agg-noproven");
    let alog = f.wal.parent().unwrap().join("aggregate.jsonl");
    std::fs::write(&alog, aggregate_line(0, 8, [0x11u8; 32], 1)).unwrap();
    let r = run_watcher(&[
        "--appchain-wal", f.wal.to_str().unwrap(),
        "--sequencer-public", &f.public_hex,
        "--aggregate-log", alog.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1, "stdout:\n{}", r.stdout);
    assert!(r.stdout.contains("aggregate_mismatch"));
}
