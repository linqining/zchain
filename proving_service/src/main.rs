//! proving_service 二进制入口。
//!
//! 两种模式：
//! - `proving_service serve [addr]`：启动 axum HTTP 服务（默认 `127.0.0.1:7878`）。
//! - `proving_service --once`：同步跑 6 步 WAITING 覆盖片段到 stdout（不启服务）。

use std::net::SocketAddr;
use std::process::ExitCode;

use proving_service::full_hand::FullHandRunner;
use proving_service::HandRunner;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--once") => run_once(),
        Some("--full-hand") => run_full_hand(),
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
                "usage:\n  proving_service --once        跑 6 步 WAITING 覆盖片段到 stdout\n  proving_service --full-hand   跑一局完整 Texas Hold'em 牌局 + 性能报告\n  proving_service serve [addr]  启动 HTTP 服务（默认 127.0.0.1:7878）"
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

/// 跑一局完整 Texas Hold'em 牌局（含 crypto 洗牌 + 全部下注轮 + 摊牌结算），
/// 打印每步 dispatch / prove 耗时与总体性能报告。
fn run_full_hand() -> ExitCode {
    let (_plugin, report) = FullHandRunner::new().run();
    println!("===== 完整牌局 VM→AIR→host verifier 报告 =====");
    println!(
        "  {:<26} {:>10} {:>14}  结果",
        "method", "dispatch", "prove+verify"
    );
    println!("  {:-<70}", "");
    for s in &report.steps {
        println!(
            "  {:<26} {:>8.2}ms {:>12.2}ms  {}",
            s.method,
            s.dispatch.as_secs_f64() * 1000.0,
            s.prove.as_secs_f64() * 1000.0,
            if s.ok { "✓" } else { "✗" }
        );
    }
    println!("  {:-<70}", "");
    let dispatch_total: f64 =
        report.steps.iter().map(|s| s.dispatch.as_secs_f64()).sum::<f64>() * 1000.0;
    let prove_total: f64 =
        report.steps.iter().map(|s| s.prove.as_secs_f64()).sum::<f64>() * 1000.0;
    println!("  dispatch 合计: {:.2}ms", dispatch_total);
    println!("  prove+verify 合计: {:.2}ms", prove_total);
    println!("  总耗时: {:.2}ms", report.total.as_secs_f64() * 1000.0);
    println!("  -----");
    println!(
        "  state_root 链校验: {}",
        if report.chain_ok {
            "✓ 通过"
        } else {
            "✗ 失败/部分（见 stopped_at）"
        }
    );
    println!(
        "  dispatch {} 次 / prove {} 次 / 链长 {}",
        report.stats.dispatch_count, report.stats.prove_count, report.stats.chain_length
    );
    if let Some(w) = report.winner_seat {
        println!("  赢家: seat {w}");
    } else {
        println!("  赢家: 未结算（见 stopped_at）");
    }
    if let Some(reason) = &report.stopped_at {
        println!("  ⚠ 提前停止: {reason}");
        println!(
            "  注：crypto AIR Gap-6 约束 (shuffle_phase ∈ {{1,2,3}}) 会拒绝终结洗牌者的 submit_shuffle_v2，"
        );
        println!("     详见 AIR_GAP.md；其前各步均可正常 prove+verify。");
    }
    let all_ok = report.steps.iter().all(|s| s.ok) && report.stopped_at.is_none();
    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
