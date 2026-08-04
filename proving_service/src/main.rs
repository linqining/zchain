//! proving_service 二进制入口。
//!
//! 两种模式：
//! - `proving_service serve [addr]`：启动仅限 loopback 的本地 axum 开发服务
//!   （默认 `127.0.0.1:7878`）。
//! - `proving_service --once`：同步跑 6 步 WAITING 覆盖片段到 stdout（不启服务）。

use std::net::SocketAddr;
use std::process::ExitCode;

use proving_service::HandRunner;
use proving_service::full_hand::FullHandRunner;
use proving_service::proof_sync::{TcpProofPackagePeer, sync_proof_package};
use proving_service::repository::ServiceRepository;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--once") => run_once(),
        Some("--full-hand") => run_full_hand(),
        Some("sync-proof") => sync_proof(&args[2..]),
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
                "usage:\n  proving_service --once        跑 6 步 WAITING 覆盖片段到 stdout\n  proving_service --full-hand   跑一局完整 Texas Hold'em 牌局 + 性能报告\n  proving_service serve [addr]  启动 loopback 本地开发服务（默认 127.0.0.1:7878）\n  proving_service sync-proof <state-path> <job-id-hex> <peer> [peer...]"
            );
            ExitCode::FAILURE
        }
    }
}

/// Repair a missing/corrupt local proof sidecar from bounded zchain P2P peers.
fn sync_proof(args: &[String]) -> ExitCode {
    if args.len() < 3 {
        eprintln!(
            "usage: proving_service sync-proof <state-path> <job-id-hex> <peer> [peer...]"
        );
        return ExitCode::FAILURE;
    }
    let job_bytes = match hex::decode(&args[1]) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(bytes) => {
            eprintln!("job id must be 32 bytes, got {}", bytes.len());
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("invalid job id hex: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut job_id = [0u8; 32];
    job_id.copy_from_slice(&job_bytes);
    let peers = match args[2..]
        .iter()
        .map(|peer| peer.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(peers) => peers,
        Err(error) => {
            eprintln!("invalid peer address: {error}");
            return ExitCode::FAILURE;
        }
    };
    let peer = match TcpProofPackagePeer::new(peers) {
        Ok(peer) => peer,
        Err(error) => {
            eprintln!("proof sync setup failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut repository = match ServiceRepository::open(&args[0]) {
        Ok(repository) => repository,
        Err(error) => {
            eprintln!("open repository failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    match sync_proof_package(&mut repository, &peer, job_id) {
        Ok(report) => {
            println!(
                "synced proof package job={} method={} table={} hand={} call_seq={} bytes={} chunks={} hash={}",
                hex::encode(report.job_id),
                report.method,
                report.table_id,
                report.hand_id,
                report.call_seq,
                report.total_len,
                report.chunk_count,
                hex::encode(report.package_hash)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("proof sync failed: {error}");
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
    let dispatch_total: f64 = report
        .steps
        .iter()
        .map(|s| s.dispatch.as_secs_f64())
        .sum::<f64>()
        * 1000.0;
    let prove_total: f64 = report
        .steps
        .iter()
        .map(|s| s.prove.as_secs_f64())
        .sum::<f64>()
        * 1000.0;
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
    } else if report.stopped_at.is_none() {
        println!("  赢家: 平局或无法由最终 stack 唯一判定");
    } else {
        println!("  赢家: 未结算（见 stopped_at）");
    }
    if let Some(reason) = &report.stopped_at {
        println!("  ⚠ 提前停止: {reason}");
    }
    let all_ok = report.steps.iter().all(|s| s.ok) && report.stopped_at.is_none();
    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
