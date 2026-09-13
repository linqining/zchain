//! M5-ACC-3（v1）：rake_audit 工具的端到端验收测试。
//!
//! 覆盖：export → verify 零差异正例；四类篡改负例（rake.total / 分账额 /
//! 层 contested 标记 / 删明细破坏汇总）全部退出码 1；ZERO 桌 rake=0 可验；
//! uncalled 返还层不计费断言（rake_base 只含 contested gross）。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 集成测试直接调用同包 bin（cargo 注入路径）。
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rake_audit")
}

/// 每个测试独立临时目录（进程号 + 用例名区分）。
fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rake_audit-tests-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Selftest {
    wal: PathBuf,
    public: String,
    head: String,
    hands: u64,
}

fn run_selftest(dir: &Path) -> Selftest {
    let out = Command::new(bin())
        .arg("selftest")
        .arg("--dir")
        .arg(dir)
        .output()
        .expect("spawn selftest");
    assert!(
        out.status.success(),
        "selftest 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |tag: &str| -> String {
        stdout
            .lines()
            .find(|l| l.starts_with(tag))
            .map(|l| l[tag.len()..].to_owned())
            .unwrap_or_else(|| panic!("selftest stdout 缺 {tag} 行: {stdout}"))
    };
    Selftest {
        wal: PathBuf::from(field("WAL=")),
        public: field("SEQUENCER_PUBLIC="),
        head: field("WAL_HEAD_HASH="),
        hands: field("HANDS=").parse().unwrap(),
    }
}

fn run_export(dir: &Path, st: &Selftest, out_name: &str) -> Output {
    Command::new(bin())
        .arg("export")
        .arg("--appchain-wal")
        .arg(&st.wal)
        .arg("--sequencer-public")
        .arg(&st.public)
        .arg("--from-ts")
        .arg("0")
        .arg("--to-ts")
        .arg("99999999999999")
        .arg("--out")
        .arg(dir.join(out_name))
        .output()
        .expect("spawn export")
}

fn run_verify(audit: &Path) -> Output {
    Command::new(bin())
        .arg("verify")
        .arg("--audit")
        .arg(audit)
        .output()
        .expect("spawn verify")
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, v: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// selftest → export 一条龙，返回 (目录, Selftest, audit.json 路径)。
fn setup_audit(name: &str) -> (PathBuf, Selftest, PathBuf) {
    let dir = test_dir(name);
    let st = run_selftest(&dir);
    let out = run_export(&dir, &st, "audit.json");
    assert!(out.status.success(), "export 失败: {}", String::from_utf8_lossy(&out.stderr));
    let audit = dir.join("audit.json");
    (dir, st, audit)
}

/// 正例：export 头部字段正确（head hash 与 selftest 一致、Σrake=150）、
/// verify 零差异（退出码 0）。
#[test]
fn export_verify_roundtrip_zero_diff() {
    let (_dir, st, audit) = setup_audit("roundtrip");
    let doc = read_json(&audit);
    assert_eq!(doc["format"], "zchain.rake_audit.v1");
    assert_eq!(doc["header"]["wal_head_hash"], st.head.as_str());
    assert_eq!(doc["header"]["rake_total"], 150, "Σrake = 100 + 50 + 0");
    assert_eq!(doc["records"].as_array().unwrap().len(), st.hands as usize);
    // 策略生成清单：raked 桌（mode 1, 5%, treasury 20%）+ ZERO 桌（mode 0）
    let policies = doc["header"]["policy_commitments"].as_array().unwrap();
    assert_eq!(policies.len(), 2);
    assert!(policies
        .iter()
        .any(|p| p["mode"] == 1 && p["rate_bps"] == 500 && p["treasury_bps"] == 2_000));
    assert!(policies.iter().any(|p| p["mode"] == 0));
    // 复验零差异
    let v = run_verify(&audit);
    assert_eq!(v.status.code(), Some(0), "stdout: {}", String::from_utf8_lossy(&v.stdout));
    assert!(String::from_utf8_lossy(&v.stdout).contains("零差异"));
}

/// 篡改负例 1：改单条 rake.total → 独立重算不符 + 汇总不符，退出码 1。
#[test]
fn tamper_rake_total_detected() {
    let (dir, _st, audit) = setup_audit("t-rake-total");
    let mut doc = read_json(&audit);
    let orig = doc["records"][0]["rake_total"].as_u64().unwrap();
    doc["records"][0]["rake_total"] = serde_json::json!(orig + 1);
    let path = dir.join("tampered.json");
    write_json(&path, &doc);
    assert_eq!(run_verify(&path).status.code(), Some(1));
}

/// 篡改负例 2：改分账额（treasury_out.amount）→ 退出码 1。
#[test]
fn tamper_split_amount_detected() {
    let (dir, _st, audit) = setup_audit("t-split");
    let mut doc = read_json(&audit);
    let idx = doc["records"]
        .as_array()
        .unwrap()
        .iter()
        .position(|r| r["treasury_out"].is_object())
        .expect("至少一条 raked 记录带 treasury_out");
    let orig = doc["records"][idx]["treasury_out"]["amount"].as_u64().unwrap();
    doc["records"][idx]["treasury_out"]["amount"] = serde_json::json!(orig - 1);
    let path = dir.join("tampered.json");
    write_json(&path, &doc);
    let out = run_verify(&path);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("treasury_out.amount"));
}

/// 篡改负例 3：翻转某层 contested 标记 → 与 eligible_seats 矛盾 + 基数重算
/// 不符，退出码 1。
#[test]
fn tamper_contested_flag_detected() {
    let (dir, _st, audit) = setup_audit("t-contested");
    let mut doc = read_json(&audit);
    // 找到 contested=true 的层并翻转为 false
    let mut flipped = false;
    for rec in doc["records"].as_array_mut().unwrap() {
        for pot in rec["pots"].as_array_mut().unwrap() {
            if pot["contested"] == serde_json::json!(true) {
                pot["contested"] = serde_json::json!(false);
                flipped = true;
                break;
            }
        }
        if flipped {
            break;
        }
    }
    assert!(flipped, "demo WAL 至少含一个 contested 层");
    let path = dir.join("tampered.json");
    write_json(&path, &doc);
    let out = run_verify(&path);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("contested 标志"),
        "应报 contested 标志矛盾: {stdout}"
    );
}

/// 篡改负例 4：删一条明细 → 明细和 ≠ 头部汇总，退出码 1。
#[test]
fn tamper_delete_record_breaks_summary() {
    let (dir, _st, audit) = setup_audit("t-delete");
    let mut doc = read_json(&audit);
    let records = doc["records"].as_array_mut().unwrap();
    assert!(records.len() >= 2);
    records.remove(0);
    let path = dir.join("tampered.json");
    write_json(&path, &doc);
    let out = run_verify(&path);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("汇总不一致"));
}

/// ZERO 桌：rake=0、无分账输出，且该记录复验通过（零费口径可证明）。
#[test]
fn zero_table_rake_is_zero_and_verifies() {
    let (_dir, _st, audit) = setup_audit("zero-table");
    let doc = read_json(&audit);
    let zero = doc["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["table_id"] == 2)
        .expect("demo WAL 含 ZERO 桌记录");
    assert_eq!(zero["rake_total"], 0);
    assert_eq!(zero["rake_base"], 2_000, "ZERO 桌基数照常导出，抽取恒 0");
    assert!(zero["treasury_out"].is_null());
    assert!(zero["operator_out"].is_null());
    assert_eq!(zero["conservation"]["inputs_sum"], zero["conservation"]["payouts_sum"]);
}

/// uncalled 返还层不计费：含双层 pot 的记录，rake_base 只含 contested 层
/// gross（1_000 而非 2_000），rake = floor(1_000×5%) = 50；uncontested 层
/// rake == 0（B9 contested-only 口径）。
#[test]
fn uncalled_return_layer_not_billed() {
    let (_dir, _st, audit) = setup_audit("uncalled");
    let doc = read_json(&audit);
    let rec = doc["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["pots"].as_array().unwrap().len() == 2)
        .expect("demo WAL 含 uncalled 返还层记录");
    let pots = rec["pots"].as_array().unwrap();
    let contested_gross: u64 = pots
        .iter()
        .filter(|p| p["contested"] == serde_json::json!(true))
        .map(|p| p["gross_amount"].as_u64().unwrap())
        .sum();
    let uncontested = pots
        .iter()
        .find(|p| p["contested"] == serde_json::json!(false))
        .expect("含 uncontested 返还层");
    assert_eq!(contested_gross, 1_000);
    assert_eq!(rec["rake_base"], contested_gross, "rake_base 只含 contested gross");
    assert_ne!(rec["rake_base"], rec["conservation"]["inputs_sum"], "基数 ≠ 全额 gross");
    assert_eq!(uncontested["rake"], 0, "uncalled 层 rake 必须为 0");
    // 5% × 1_000 = 50（若误按全额 gross 2_000 计费会是 100）
    assert_eq!(rec["rake_total"], 50);
}

/// 输入错误路径：verify 一个不存在的文件 → 退出码 2（不是差异 1）。
#[test]
fn verify_missing_file_is_input_error() {
    let dir = test_dir("missing");
    let out = run_verify(&dir.join("no-such-file.json"));
    assert_eq!(out.status.code(), Some(2));
}

/// 输入错误路径：结构损坏（format 不认识 / 缺字段）→ 退出码 2。
#[test]
fn verify_malformed_json_is_input_error() {
    let (dir, _st, audit) = setup_audit("malformed");
    let mut doc = read_json(&audit);
    doc["format"] = serde_json::json!("some.other.format");
    let path = dir.join("bad-format.json");
    write_json(&path, &doc);
    assert_eq!(run_verify(&path).status.code(), Some(2));

    let mut doc = read_json(&audit);
    doc.as_object_mut().unwrap().remove("header");
    let path = dir.join("no-header.json");
    write_json(&path, &doc);
    assert_eq!(run_verify(&path).status.code(), Some(2));
}
