//! M8：seq_key_rotate——sequencer 密钥**停机轮换**清单工具。
//!
//! 语义见 `poker_appchain::rotation`：本工具只生成/校验"旧钥授权换新钥"
//! 的签名记录（runbook 归档件）；**帧链中途热换签是 v1.5**，v1 轮换必须
//! 在停机窗口配合 runbook 执行。
//!
//! 旧钥来源（二选一，fail-closed——不给就报用法错误，无默认）：
//!
//! 1. `--old-key-file <p>`：密钥文件，兼容两种形态——
//!    a. `zchain keygen` 输出的 JSON（取 `secret_key_hex` 字段，32B hex）；
//!    b. 纯 32 字节 hex 的裸文件（64 个 hex 字符，空白容忍）。
//! 2. `--provider <env|file|remote>`（+ 可选 `--provider-prefix <p>`，默认
//!    `ZCHAIN`）：经 `poker_appchain::key_provider::from_config` 取钥——
//!    与生产装配同一条 KeyProvider 通道（env 变量 / 密钥文件（含 Unix
//!    权限校验）/ KMS 端点接缝）；取钥失败即失败，**无默认种子回退**。
//!
//! 文档注明：私钥只在本进程内存短暂存在，用于签名，不落任何输出。
//!
//! 用法：
//!
//! ```text
//! seq_key_rotate generate --old-key-file <p> --new-public <64hex> --out <p>
//! seq_key_rotate generate --provider env --new-public <64hex> --out <p>
//! seq_key_rotate verify --in <p>
//! ```
//!
//! 退出码：0 = 成功（generate 写出 / verify 通过）；1 = verify 拒绝或
//! 文件/解析/取钥错误；2 = 用法错误。

use std::path::PathBuf;

use poker_appchain::key_provider::{SequencerKeyExt, from_config};
use poker_appchain::keys::SequencerKey;
use poker_appchain::rotation::{self, KeyRotationRecord};

const USAGE: &str = "usage:\n  seq_key_rotate generate --old-key-file <path> | --provider <env|file|remote> [--provider-prefix <prefix>] --new-public <64hex> --out <path>\n  seq_key_rotate verify --in <path>\n\n  old key source is one of --old-key-file or --provider (mutually exclusive, no default);\n  --provider uses key_provider::from_config with env config vars:\n    <prefix>_KEY_PROVIDER, <prefix>_SEQUENCER_KEY_HEX (env),\n    <prefix>_SEQUENCER_KEY_FILE (file), <prefix>_KMS_ENDPOINT + key ids (remote)";

/// 旧钥来源（--old-key-file 与 --provider 二选一）。
enum OldKeySource {
    /// 密钥文件路径（既有行为，向后兼容）。
    File(PathBuf),
    /// KeyProvider 工厂 + 配置前缀（生产同源通道）。
    Provider(String),
}

/// 读旧钥文件：zchain keygen JSON（secret_key_hex）或裸 32B hex。
fn read_secret_key_file(path: &std::path::Path) -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("key file unreadable: {e}"))?;
    let trimmed = text.trim();
    // 形态 1：keygen JSON（含 secret_key_hex 字段）
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(Some(sk)) = v.get("secret_key_hex").map(serde_json::Value::as_str) {
            return parse_seed(sk)
                .ok_or_else(|| "key file secret_key_hex is not 32 bytes of hex".to_string());
        }
    }
    // 形态 2：裸 32B hex
    parse_seed(trimmed).ok_or_else(|| "key file is neither keygen JSON nor 32-byte hex".to_string())
}

fn parse_seed(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return 2;
    }
    match args[0].as_str() {
        "generate" => {
            let mut old_key_source: Option<OldKeySource> = None;
            let mut new_public = None;
            let mut out = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--old-key-file" => match args.get(i + 1) {
                        Some(v) => {
                            if old_key_source.is_some() {
                                return usage_err(
                                    "--old-key-file and --provider are mutually exclusive",
                                );
                            }
                            old_key_source = Some(OldKeySource::File(PathBuf::from(v)));
                            i += 1;
                        }
                        None => return usage_err("--old-key-file needs a value"),
                    },
                    "--provider" => match args.get(i + 1) {
                        Some(v) => {
                            if old_key_source.is_some() {
                                return usage_err(
                                    "--old-key-file and --provider are mutually exclusive",
                                );
                            }
                            match v.as_str() {
                                "env" | "file" | "remote" => {}
                                other => {
                                    return usage_err(&format!(
                                        "--provider expects env|file|remote, got {other:?}"
                                    ));
                                }
                            }
                            old_key_source = Some(OldKeySource::Provider("ZCHAIN".to_string()));
                            i += 1;
                        }
                        None => return usage_err("--provider needs a value"),
                    },
                    "--provider-prefix" => match (args.get(i + 1), &old_key_source) {
                        (Some(v), Some(OldKeySource::Provider(_))) => {
                            old_key_source = Some(OldKeySource::Provider(v.clone()));
                            i += 1;
                        }
                        (Some(_), _) => {
                            return usage_err(
                                "--provider-prefix requires --provider (and must come with it)",
                            );
                        }
                        (None, _) => return usage_err("--provider-prefix needs a value"),
                    },
                    "--new-public" => match args.get(i + 1) {
                        Some(v) => match hex::decode(v) {
                            Ok(bytes) => match bytes.try_into() {
                                Ok(pk) => {
                                    new_public = Some(pk);
                                    i += 1;
                                }
                                Err(_) => return usage_err("--new-public expects 64 hex chars"),
                            },
                            Err(_) => return usage_err("--new-public expects 64 hex chars"),
                        },
                        None => return usage_err("--new-public needs a value"),
                    },
                    "--out" => match args.get(i + 1) {
                        Some(v) => {
                            out = Some(PathBuf::from(v));
                            i += 1;
                        }
                        None => return usage_err("--out needs a value"),
                    },
                    other => return usage_err(&format!("unknown argument {other:?}")),
                }
                i += 1;
            }
            let (old_key_source, new_public, out) = match (old_key_source, new_public, out) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => {
                    return usage_err(
                        "generate requires --new-public, --out, and one old-key source \
                     (--old-key-file or --provider)",
                    );
                }
            };
            let old: SequencerKey = match &old_key_source {
                OldKeySource::File(path) => {
                    let seed = match read_secret_key_file(path) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("error: {e}");
                            return 1;
                        }
                    };
                    SequencerKey::from_seed(&seed)
                }
                OldKeySource::Provider(prefix) => {
                    // 生产同源取钥通道（KeyProvider）：失败即失败——
                    // 无默认种子回退（fail-closed，外部评审建议 4）。
                    match from_config(prefix).and_then(|p| SequencerKey::from_provider(p.as_ref()))
                    {
                        Ok(k) => k,
                        Err(e) => {
                            eprintln!("error: provider key load failed: {e}");
                            return 1;
                        }
                    }
                }
            };
            let ts_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            let record = rotation::generate(&old, new_public, ts_ms);
            let json = match rotation::json::to_string_pretty(&record) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("error: encode failed: {e}");
                    return 1;
                }
            };
            if let Err(e) = std::fs::write(&out, json) {
                eprintln!("error: write {out:?} failed: {e}");
                return 1;
            }
            println!(
                "rotation record written: {} -> {} at ts_ms {}",
                hex::encode(record.old_public),
                hex::encode(record.new_public),
                record.ts_ms
            );
            println!(
                "note: this is a STOPPED-STATE rotation checklist record; \
                      hot re-key mid-chain is v1.5"
            );
            0
        }
        "verify" => {
            let mut input = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--in" => match args.get(i + 1) {
                        Some(v) => {
                            input = Some(PathBuf::from(v));
                            i += 1;
                        }
                        None => return usage_err("--in needs a value"),
                    },
                    other => return usage_err(&format!("unknown argument {other:?}")),
                }
                i += 1;
            }
            let input = match input {
                Some(p) => p,
                None => return usage_err("verify requires --in <path>"),
            };
            let text = match std::fs::read_to_string(&input) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: read {input:?} failed: {e}");
                    return 1;
                }
            };
            let record: KeyRotationRecord = match rotation::json::from_str(&text) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: parse failed: {e}");
                    return 1;
                }
            };
            if rotation::verify(&record) {
                println!(
                    "VALID: old {} authorizes rotation to {} at ts_ms {}",
                    hex::encode(record.old_public),
                    hex::encode(record.new_public),
                    record.ts_ms
                );
                0
            } else {
                eprintln!("INVALID: signature does not verify against old_public");
                1
            }
        }
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            0
        }
        other => usage_err(&format!("unknown subcommand {other:?}")),
    }
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("error: {msg}");
    eprintln!("{USAGE}");
    2
}

fn main() {
    std::process::exit(real_main());
}
