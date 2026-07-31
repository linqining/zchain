//! proving_service 二进制入口。
//!
//! 两种模式：
//! - `proving_service serve [addr]`：启动 axum HTTP 服务（默认 `127.0.0.1:7878`）。
//! - `proving_service --once`：同步跑 6 步 WAITING 覆盖片段到 stdout（不启服务）。

use std::net::SocketAddr;
use std::process::ExitCode;

use proving_service::HandRunner;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--once") => run_once(),
        Some("serve") => {
            let addr: SocketAddr = args
                .get(2)
                .map(|s| s.parse().expect("invalid addr"))
                .unwrap_or_else(|| "127.0.0.1:7878".parse().unwrap());
            // tokio runtime
            let rt = tokio::runtime::Runtime::new().expect("build runtime");
            match rt.block_on(proving_service::server::serve(addr)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("server error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "usage:\n  proving_service --once       跑 6 步 WAITING 覆盖片段到 stdout\n  proving_service serve [addr]  启动 HTTP 服务（默认 127.0.0.1:7878）"
            );
            ExitCode::FAILURE
        }
    }
}

/// 同步跑 VM→AIR→host verifier 覆盖片段，打印报告。
fn run_once() -> ExitCode {
    match HandRunner::new().run() {
        Ok((_plugin, report)) => {
            println!("===== VM→AIR→host verifier 覆盖片段报告 =====");
            for (name, ok) in &report.steps {
                println!(
                    "  {name:<22} {}",
                    if *ok {
                        "✓ proved+verified"
                    } else {
                        "✗ failed"
                    }
                );
            }
            println!("-----");
            println!(
                "  state_root 链校验: {}",
                if report.chain_ok {
                    "✓ 通过"
                } else {
                    "✗ 失败"
                }
            );
            if let Some(agg) = report.aggregate_ok {
                println!(
                    "  descriptor 聚合入口: {}",
                    if agg {
                        "✗ 意外成功（不可信）"
                    } else {
                        "✓ 已按预期拒绝"
                    }
                );
            }
            println!(
                "  dispatch {} 次 / prove {} 次 / 链长 {}",
                report.stats.dispatch_count, report.stats.prove_count, report.stats.chain_length
            );
            if report.chain_ok
                && report.steps.iter().all(|(_, ok)| *ok)
                && report.aggregate_ok != Some(true)
            {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("coverage fragment failed: {e}");
            ExitCode::FAILURE
        }
    }
}
