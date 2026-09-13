//! M5-ACC-3（v1）：rake 独立审计导出工具。
//!
//! ```text
//! rake_audit export  --appchain-wal <path> --sequencer-public <64hex>
//!                    --from-ts <ms> --to-ts <ms> [--table-id N] --out <file.json>
//! rake_audit verify  --audit <file.json>
//! rake_audit selftest --dir <dir> [--hands N]
//! ```
//!
//! - `export`：从 WAL 重放（`Sequencer::replay`，全量验签 + 状态根重验），
//!   抽出全部 Settle 记录并导出为 `zchain.rake_audit.v1` JSON；
//! - `verify`：**独立代码路径**复验（只用 serde_json，不 import
//!   `poker_appchain` 的校验器/费率模块；见 verify.rs 头注释），
//!   退出码 0 = 零差异 / 1 = 差异 / 2 = 输入错误；
//! - `selftest`：生成 demo WAL——默认 3 手（标准计费手、含 uncalled 返还
//!   层的手、ZERO 桌手）；`--hands N` 生成 N 手混合桌批量口径（5% 无封顶
//!   + uncalled 层手 / 10% 封顶 30 / ZERO 轮转），供 M5-ACC-3 外部独立
//!   复验（tools_external/，独立语言独立代码路径）使用。
//!
//! 独立性现状（如实标注）：verify 是与链内校验器不共享代码的**第二条实现
//! 路径**；M5-ACC-3 的最终形态要求"外部工具（独立仓库）复验"，本工具同仓
//! 独立路径是通往该形态的 v1 步骤（见 docs/runbook.md §工具页）。
//! `tools_external/rake_audit_verify.py`（纯 Python 标准库，从 ABI.md 公式
//! 规范独立重实现）是外部独立复验工具，与本 bin 无任何共享代码。

use std::path::PathBuf;
use std::process::ExitCode;

mod export;
mod selftest;
mod verify;

/// verify/export 共用退出码语义：0 成功 / 1 差异 / 2 输入错误。
pub const EXIT_OK: u8 = 0;
pub const EXIT_DIFF: u8 = 1;
pub const EXIT_INPUT: u8 = 2;

/// 审计文件格式标识（verify 端独立声明同一常量——刻意不从 export 共享，
/// 保持两条路径各自成立）。
pub const FORMAT_TAG: &str = "zchain.rake_audit.v1";

fn usage() -> String {
    format!(
        "rake_audit — rake 独立审计导出与复验（{FORMAT_TAG}）\n\
         \n\
         用法：\n\
         \x20 rake_audit export --appchain-wal <path> --sequencer-public <64hex>\n\
         \x20                    --from-ts <ms> --to-ts <ms> [--table-id N] --out <file.json>\n\
         \x20 rake_audit verify --audit <file.json>\n\
         \x20 rake_audit selftest --dir <dir> [--hands N]\n\
         \n\
         退出码：0 = 成功（零差异）/ 1 = 复验差异 / 2 = 输入错误"
    )
}

/// 解析 `--name value` 形式的必选参数。
fn take_arg(args: &[String], name: &str) -> Result<String, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .ok_or_else(|| format!("缺少参数 {name}"))
}

/// 解析 `--name value` 形式的可选参数。
fn take_opt_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn parse_u64(s: &str, what: &str) -> Result<u64, String> {
    s.parse::<u64>().map_err(|_| format!("{what} 非法：{s:?}（应为非负整数）"))
}

fn parse_pubkey_hex(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "sequencer-public 不是合法 hex".to_owned())?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("sequencer-public 必须是 64 位 hex（32 字节），得到 {len} 字节"))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        eprintln!("{}", usage());
        return ExitCode::from(EXIT_INPUT);
    };
    let res = match cmd.as_str() {
        "export" => cmd_export(&argv[1..]),
        "verify" => cmd_verify(&argv[1..]),
        "selftest" => cmd_selftest(&argv[1..]),
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            return ExitCode::from(EXIT_OK);
        }
        other => Err(CliError::Input(format!(
            "未知子命令 {other:?}（见 --help）"
        ))),
    };
    match res {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(CliError::Input(msg)) => {
            eprintln!("错误（输入）：{msg}");
            eprintln!("{}", usage());
            ExitCode::from(EXIT_INPUT)
        }
        Err(CliError::Diff(msg)) => {
            eprintln!("差异：{msg}");
            ExitCode::from(EXIT_DIFF)
        }
    }
}

/// 命令级错误：Input → 退出码 2；Diff → 退出码 1。
enum CliError {
    Input(String),
    Diff(String),
}

fn cmd_export(args: &[String]) -> Result<(), CliError> {
    let wal = PathBuf::from(take_arg(args, "--appchain-wal").map_err(CliError::Input)?);
    let public = parse_pubkey_hex(&take_arg(args, "--sequencer-public").map_err(CliError::Input)?)
        .map_err(CliError::Input)?;
    let from_ts = parse_u64(&take_arg(args, "--from-ts").map_err(CliError::Input)?, "--from-ts")
        .map_err(CliError::Input)?;
    let to_ts = parse_u64(&take_arg(args, "--to-ts").map_err(CliError::Input)?, "--to-ts")
        .map_err(CliError::Input)?;
    let table_id = match take_opt_arg(args, "--table-id") {
        Some(s) => Some(parse_u64(&s, "--table-id").map_err(CliError::Input)?),
        None => None,
    };
    let out = PathBuf::from(take_arg(args, "--out").map_err(CliError::Input)?);
    if from_ts > to_ts {
        return Err(CliError::Input("--from-ts 不得大于 --to-ts".into()));
    }
    export::run(&export::ExportArgs {
        wal,
        public,
        from_ts,
        to_ts,
        table_id,
        out,
    })
    .map_err(CliError::Input)
}

fn cmd_verify(args: &[String]) -> Result<(), CliError> {
    let audit = PathBuf::from(take_arg(args, "--audit").map_err(CliError::Input)?);
    match verify::run(&audit) {
        Ok(diffs) => {
            if diffs.is_empty() {
                println!("OK: 复验零差异");
                Ok(())
            } else {
                for d in &diffs {
                    println!("DIFF: {d}");
                }
                println!("共 {} 处差异", diffs.len());
                Err(CliError::Diff(format!("{} 处差异", diffs.len())))
            }
        }
        Err(msg) => Err(CliError::Input(msg)),
    }
}

fn cmd_selftest(args: &[String]) -> Result<(), CliError> {
    let dir = PathBuf::from(take_arg(args, "--dir").map_err(CliError::Input)?);
    let hands = match take_opt_arg(args, "--hands") {
        Some(s) => Some(
            parse_u64(&s, "--hands")
                .map_err(CliError::Input)?
                .min(usize::MAX as u64) as usize,
        ),
        None => None,
    };
    selftest::run_with_hands(&dir, hands)
        .map(|_| ())
        .map_err(CliError::Input)
}
