//! proving_service 二进制入口。
//!
//! 两种模式：
//! - `proving_service serve [addr]`：启动 axum HTTP 服务（默认 `127.0.0.1:7878`）。
//! - `proving_service --once`：同步跑一手牌到 stdout（不启服务）。

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
            eprintln!("usage:\n  proving_service --once       跑一手牌到 stdout\n  proving_service serve [addr]  启动 HTTP 服务（默认 127.0.0.1:7878）");
            ExitCode::FAILURE
        }
    }
}

/// 同步跑一手牌，打印报告。
fn run_once() -> ExitCode {
    match HandRunner::new().run() {
        Ok((_plugin, report)) => {
            println!("===== HandRunner 报告 =====");
            for (name, ok) in &report.steps {
                println!("  {name:<22} {}", if *ok { "✓ proved+verified" } else { "✗ failed" });
            }
            println!("-----");
            println!("  state_root 链校验: {}", if report.chain_ok { "✓ 通过" } else { "✗ 失败" });
            if let Some(agg) = report.aggregate_ok {
                println!("  聚合证明:          {}", if agg { "✓ verify 通过" } else { "✗ 失败" });
            }
            println!(
                "  dispatch {} 次 / prove {} 次 / 链长 {}",
                report.stats.dispatch_count, report.stats.prove_count, report.stats.chain_length
            );
            if report.chain_ok && report.steps.iter().all(|(_, ok)| *ok) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("hand run failed: {e}");
            ExitCode::FAILURE
        }
    }
}
