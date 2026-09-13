//! KeyProvider 集成测试（外部评审建议 4 的验收面）：
//!
//! - 三实现正例（env / file / remote mock 端点）；
//! - fail-closed 负例：env 缺失、文件缺失、文件权限过宽（Unix）、远程
//!   超时 / 非 2xx / 坏响应体 / https 拒绝、工厂未知/未配置；
//! - "无固定种子回退"的 grep 级 + 行为级断言；
//! - 生产装配路径行为回归：provider 产物喂 `Sequencer::new` +
//!   `ValidationEngine::new`，提交-验签-replay 全链零回退。

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::key_provider::{
    EnvKeyProvider, FileKeyProvider, KeyProvider, RemoteKeyProvider, SequencerKeyExt, from_config,
};
use poker_appchain::keys::SequencerKey;
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::{PipelineConfig, ProofPipeline, ValidationEngine};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::soft_confirm::verify_chain;

const SEED: [u8; 32] = [0x5Eu8; 32];
const HEX: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

/// 每测试唯一 env 变量名（并行测试无竞态：变量名含测试 tag + 进程 id）。
fn unique_env(tag: &str) -> String {
    format!("KP_TEST_{tag}_{}", std::process::id())
}

/// SAFETY 前提：变量名经 [`unique_env`] 保证本测试进程内唯一，并行测试
/// 互不覆写；进程退出即整体清理。
unsafe fn set_env(var: &str, value: &str) {
    // SAFETY: unique per-test variable name (see unique_env), single-writer.
    unsafe { std::env::set_var(var, value) }
}

/// SAFETY 前提：同 [`set_env`]。
unsafe fn unset_env(var: &str) {
    // SAFETY: unique per-test variable name (see unique_env).
    unsafe { std::env::remove_var(var) }
}

/// 唯一临时目录（手动清理 best-effort）。
fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "kp_test_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("temp dir create");
    d
}

fn write_key_file(dir: &std::path::Path, name: &str, content: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).expect("write key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))
            .expect("chmod key file");
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    p
}

// ===== mock KMS（std TcpListener 最小 HTTP 服务）=====

/// 起一个一次性 mock 端点：接受一个连接，读完请求头+body，按 `respond`
/// 生成响应后关闭。返回地址。
fn spawn_mock_kms(respond: impl FnOnce(Vec<u8>) -> Vec<u8> + Send + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock kms bind");
    let addr = listener.local_addr().expect("mock kms addr");
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("mock kms accept");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        // 读到头结束，再按 Content-Length 补齐 body。
        let body_len = loop {
            let text = std::str::from_utf8(&raw).unwrap_or("");
            if let Some(pos) = text.find("\r\n\r\n") {
                let cl = text
                    .lines()
                    .find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if raw.len() >= pos + 4 + cl {
                    break pos + 4 + cl;
                }
            }
            let n = sock.read(&mut chunk).expect("mock kms read");
            assert!(n > 0, "mock kms: client closed early");
            raw.extend_from_slice(&chunk[..n]);
        };
        let _ = body_len;
        let reply = respond(raw);
        sock.write_all(&reply).expect("mock kms write");
        let _ = sock.flush();
        // drop sock → close
    });
    addr
}

fn http_reply(status: &str, body: &str) -> Vec<u8> {
    format!(
        "{status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn remote_provider(addr: SocketAddr) -> RemoteKeyProvider {
    RemoteKeyProvider::new(
        &format!("http://{addr}/keys"),
        Duration::from_secs(5),
        "seq-key-v2",
        "attestor-key-v2",
    )
    .expect("http endpoint accepted")
}

// ===== 1. EnvKeyProvider =====

#[test]
fn env_provider_positive_sequencer_and_attestor() {
    let seq_var = unique_env("env_pos_seq");
    let att_var = unique_env("env_pos_att");
    unsafe { set_env(&seq_var, HEX) };
    unsafe { set_env(&att_var, HEX) };

    let p = EnvKeyProvider::with_vars(seq_var.clone(), att_var.clone());
    let k = p
        .sequencer_key()
        .expect("env provider must yield sequencer key");
    assert_eq!(k.public, SequencerKey::from_seed(&SEED).public);

    let a = p
        .attestor_signing_key()
        .expect("env provider must yield attestor key");
    use ed25519_dalek::Signer as _;
    // 与直接构造逐位一致；签名往返可用。
    let sig = a.sign(b"msg");
    assert!(SequencerKey::verify(
        &a.verifying_key().to_bytes(),
        b"msg",
        &sig.to_bytes()
    ));

    unsafe { unset_env(&seq_var) };
    unsafe { unset_env(&att_var) };
}

/// fail-closed：变量缺失 → Err，且错误消息点名变量（运维可定位）。
#[test]
fn env_provider_missing_fail_closed() {
    let never = unique_env("env_never_set");
    let p = EnvKeyProvider::with_vars(never.clone(), never.clone());
    let e = p.sequencer_key().expect_err("missing env must fail");
    assert!(
        e.to_string().contains(&never),
        "error must name the variable: {e}"
    );
    assert!(p.attestor_signing_key().is_err());
}

#[test]
fn env_provider_bad_content_fail_closed() {
    for bad in ["zz-not-hex", &"ab".repeat(8)[..], &"0".repeat(64)] {
        let v = unique_env("env_bad");
        unsafe { set_env(&v, bad) };
        let p = EnvKeyProvider::with_vars(v.clone(), v.clone());
        assert!(
            p.sequencer_key().is_err(),
            "bad env content {bad:?} must be rejected"
        );
        unsafe { unset_env(&v) };
    }
}

// ===== 2. FileKeyProvider =====

#[test]
#[cfg(unix)]
fn file_provider_positive_hex_and_keygen_json() {
    let dir = temp_dir("file_pos");
    // 形态 1：裸 32B hex（0600）
    let hex_path = write_key_file(&dir, "seq.key", HEX, 0o600);
    // 形态 2：zchain keygen JSON（0400 更紧也合法）
    let json = format!("{{\"scheme\":\"ed25519\",\"secret_key_hex\":\"{HEX}\"}}");
    let json_path = write_key_file(&dir, "attestor.key.json", &json, 0o400);

    let p = FileKeyProvider::new(hex_path.clone(), json_path.clone());
    let k = p.sequencer_key().expect("hex key file must load");
    assert_eq!(k.public, SequencerKey::from_seed(&SEED).public);
    let a = p.attestor_signing_key().expect("keygen json must load");
    assert_eq!(
        a.verifying_key().to_bytes(),
        SequencerKey::from_seed(&SEED).public
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(unix)]
fn file_provider_too_wide_permissions_rejected_with_chmod_hint() {
    let dir = temp_dir("file_perm");
    // 0644：group/other 可读 → 拒绝（fail-closed）。
    let wide = write_key_file(&dir, "seq.key", HEX, 0o644);
    let tight = write_key_file(&dir, "att.key", HEX, 0o600);
    let p = FileKeyProvider::new(wide.clone(), tight);
    let e = p
        .sequencer_key()
        .expect_err("0644 key file must be rejected");
    let msg = e.to_string();
    assert!(msg.contains("chmod 600"), "must suggest chmod: {msg}");
    assert!(msg.contains(&wide.display().to_string()));
    // 0660（group 可读）同样拒绝。
    let group_readable = write_key_file(&dir, "seq2.key", HEX, 0o660);
    let p2 = FileKeyProvider::new(group_readable, wide);
    assert!(
        p2.sequencer_key().is_err(),
        "0660 key file must be rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_provider_missing_fail_closed() {
    let dir = temp_dir("file_missing");
    let missing = dir.join("does-not-exist.key");
    let p = FileKeyProvider::new(missing, dir.join("also-missing.key"));
    assert!(p.sequencer_key().is_err());
    assert!(p.attestor_signing_key().is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

// ===== 3. RemoteKeyProvider（本地 mock 端点）=====

#[test]
fn remote_provider_positive_hex_body() {
    let addr = spawn_mock_kms(|req| {
        // 请求契约自检：POST + JSON body 带 key_id。
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("POST /keys HTTP/1.1"));
        assert!(text.contains("\"key_id\":\"seq-key-v2\""));
        http_reply("HTTP/1.1 200 OK", HEX)
    });
    let p = remote_provider(addr);
    let k = p.sequencer_key().expect("mock kms must serve hex body");
    assert_eq!(k.public, SequencerKey::from_seed(&SEED).public);
}

#[test]
fn remote_provider_positive_base64_body() {
    // 0x5e × 32 的标准 base64。
    let b64 = "Xl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl4=";
    let addr = spawn_mock_kms(|_| http_reply("HTTP/1.1 200 OK", b64));
    let p = remote_provider(addr);
    let a = p
        .attestor_signing_key()
        .expect("mock kms must serve base64 body");
    assert_eq!(
        a.verifying_key().to_bytes(),
        SequencerKey::from_seed(&SEED).public
    );
}

#[test]
fn remote_provider_non_2xx_rejected() {
    let addr = spawn_mock_kms(|_| http_reply("HTTP/1.1 403 Forbidden", "denied"));
    let p = remote_provider(addr);
    let e = p.sequencer_key().expect_err("403 must be rejected");
    assert!(
        e.to_string().contains("403"),
        "error must carry status: {e}"
    );
}

#[test]
fn remote_provider_bad_body_rejected() {
    for bad in [
        "not-a-key-at-all",
        &"ab".repeat(4)[..],
        &"ff".repeat(33)[..],
    ] {
        let addr = spawn_mock_kms({
            let bad = bad.to_string();
            move |_| http_reply("HTTP/1.1 200 OK", &bad)
        });
        let p = remote_provider(addr);
        assert!(
            p.sequencer_key().is_err(),
            "bad body {bad:?} must be rejected"
        );
    }
}

/// 远程端点接受连接但永不响应 → 读超时拒绝（fail-closed）。
#[test]
fn remote_provider_timeout_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    // 接受但不读不写（持有连接直至客户端超时）；线程分离，进程退出即回收。
    let handle = std::thread::spawn(move || {
        let (_sock, _) = listener.accept().expect("accept");
        std::thread::sleep(Duration::from_millis(1_500));
    });
    let p = RemoteKeyProvider::new(
        &format!("http://{addr}/keys"),
        Duration::from_millis(200),
        "s",
        "a",
    )
    .expect("http endpoint accepted");
    let e = p
        .sequencer_key()
        .expect_err("silent endpoint must time out");
    assert!(
        e.to_string().contains("timed out"),
        "error must say timeout: {e}"
    );
    handle.join().expect("hang thread joins");
}

/// https 端点构造即拒绝（std 接缝无 TLS，无法校验证书就不假装安全）。
#[test]
fn remote_provider_https_rejected() {
    let e = RemoteKeyProvider::new(
        "https://kms.example.com/keys",
        Duration::from_secs(1),
        "s",
        "a",
    )
    .expect_err("https must be rejected");
    assert!(
        e.to_string().contains("TLS"),
        "error must explain TLS seam: {e}"
    );
}

// ===== 4. 工厂 from_config：fail-closed（无默认）=====

#[test]
fn from_config_unconfigured_rejected() {
    let prefix = unique_env("factory_never");
    let e = match from_config(&prefix) {
        Err(e) => e,
        Ok(_) => panic!("unconfigured factory must fail (no default provider)"),
    };
    assert!(
        e.to_string().contains("refusing to fall back"),
        "error must state no-fallback policy: {e}"
    );
}

/// 行为级"无开发默认回退"断言：显式要求 dev/default 一律拒绝。
#[test]
fn from_config_dev_kind_rejected() {
    let prefix = unique_env("factory_dev");
    let kind_var = format!("{prefix}_KEY_PROVIDER");
    unsafe { set_env(&kind_var, "dev-seed") };
    let e = match from_config(&prefix) {
        Err(e) => e,
        Ok(_) => panic!("dev provider must not exist (no dev/default provider)"),
    };
    assert!(
        e.to_string().contains("no dev/test/default provider"),
        "{e}"
    );
    unsafe { unset_env(&kind_var) };
}

#[test]
fn from_config_env_kind_wires_env_provider() {
    let prefix = unique_env("factory_env");
    let kind_var = format!("{prefix}_KEY_PROVIDER");
    let seq_var = format!("{prefix}_SEQUENCER_KEY_HEX");
    let att_var = format!("{prefix}_ATTESTOR_KEY_HEX");
    unsafe { set_env(&kind_var, "env") };
    // env 种类但变量缺失 → Err（工厂选型成功 ≠ 取钥成功；fail-closed 仍在）。
    assert!(
        from_config(&prefix)
            .expect("factory selects env")
            .sequencer_key()
            .is_err()
    );
    unsafe { set_env(&seq_var, HEX) };
    unsafe { set_env(&att_var, HEX) };
    let k = from_config(&prefix)
        .expect("factory selects env")
        .sequencer_key()
        .expect("configured env key must load");
    assert_eq!(k.public, SequencerKey::from_seed(&SEED).public);
    unsafe { unset_env(&kind_var) };
    unsafe { unset_env(&seq_var) };
    unsafe { unset_env(&att_var) };
}

#[test]
fn from_config_file_kind_requires_paths() {
    let prefix = unique_env("factory_file");
    let kind_var = format!("{prefix}_KEY_PROVIDER");
    unsafe { set_env(&kind_var, "file") };
    assert!(
        from_config(&prefix).is_err(),
        "file kind without paths must fail"
    );
    unsafe { unset_env(&kind_var) };
}

// ===== 5. 无固定种子回退：grep 级断言（源码扫描钉住）=====

#[test]
fn no_fixed_seed_fallback_grep_level() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    // 本模块：生产取钥代码不得出现任何 from_seed 字面量种子。
    let kp = std::fs::read_to_string(format!("{manifest}/src/key_provider.rs"))
        .expect("read key_provider.rs");
    assert!(
        !kp.contains("from_seed(&["),
        "key_provider.rs must not construct keys from literal seeds"
    );
    // 轮换工具：provider 通道已接入。
    let rot = std::fs::read_to_string(format!("{manifest}/src/bin/seq_key_rotate.rs"))
        .expect("read seq_key_rotate.rs");
    assert!(
        rot.contains("--provider"),
        "rotation tool must expose --provider"
    );

    // sequencer.rs 生产区（`mod tests` 之前）唯一允许的 from_seed 是
    // replay 占位（重放只验签不签名，纯公钥 API 语义冻结——非回退路径）。
    let seq =
        std::fs::read_to_string(format!("{manifest}/src/sequencer.rs")).expect("read sequencer.rs");
    let prod = seq
        .split("mod tests")
        .next()
        .expect("sequencer.rs has a test module");
    let occurrences: Vec<&str> = prod.matches("from_seed(&[").collect();
    assert_eq!(
        occurrences.len(),
        1,
        "sequencer production region must contain exactly the documented replay placeholder"
    );
    assert!(
        prod.contains("from_seed(&[0u8; 32])"),
        "the single production from_seed must be the replay placeholder"
    );
}

// ===== 6. 生产装配路径行为回归：provider 产物 → Sequencer/ValidationEngine =====

#[test]
fn production_assembly_via_provider_end_to_end() {
    let seq_var = unique_env("e2e_seq");
    let att_var = unique_env("e2e_att");
    unsafe { set_env(&seq_var, HEX) };
    unsafe { set_env(&att_var, HEX) };
    let provider = EnvKeyProvider::with_vars(seq_var.clone(), att_var.clone());

    // 生产装配（Sequencer 签名未变，密钥来自 provider）：
    let seq_key = SequencerKey::from_provider(&provider).expect("provider key");
    let attestor = provider.attestor_signing_key().expect("attestor key");
    let metrics = Arc::new(MetricsRegistry::new());
    let mut seq = Sequencer::new(
        seq_key.clone(),
        SequencerConfig::default(),
        Arc::clone(&metrics),
    );

    // provider 产物喂 ValidationEngine（attestor 注入点；attestor 公钥
    // 必须就是 provider 里 attestor 种子的公钥）。
    let engine = Arc::new(ValidationEngine::new(attestor));
    assert_eq!(engine.attestor_public(), seq_key.public);
    let _pipeline = ProofPipeline::new(PipelineConfig::default(), engine, Arc::clone(&metrics));

    // 提交一笔开桌（用 provider 密钥签帧）。
    let frame = seq
        .submit(
            Operation::OpenTable {
                table_id: 1,
                policy: FeePolicy::FixedRake {
                    rate_bps: 500,
                    cap: 0,
                    split: FeeSplit {
                        treasury_bps: 2_000,
                        treasury: [1u8; 33],
                        operator: [2u8; 33],
                    },
                },
            },
            1_700_000_000_000,
        )
        .expect("open table via provider-keyed sequencer");
    // 帧验签：公钥 + 帧哈希 + 签名逐位可验。
    let h = frame.hash().expect("frame hash");
    assert!(SequencerKey::verify(&seq_key.public, &h, &frame.sig));

    // replay 等价的纯公钥校验（零回退：不接触 provider / 私钥）。
    verify_chain(seq.chain(), &seq_key.public)
        .expect("provider-keyed chain verifies by public key alone");

    unsafe { unset_env(&seq_var) };
    unsafe { unset_env(&att_var) };
}
