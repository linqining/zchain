//! zchain zkvm-server 子命令 — 启动 zkvm HTTP 证明服务。
//!
//! 严格遵循 zkvm E2E Phase 3.5（执行就绪计划 §3.5）：
//! - 解析 CLI 参数（`--listen`、`--batch-size`、`--parallel-threads`）
//! - 构造 `ProverServiceConfig` 并调用 `poker_zkvm::service::http::run_server`
//! - 优雅关闭：SIGINT/SIGTERM 触发 drain in-flight 请求后退出
//!
//! ## 用法
//!
//! ```text
//! zchain zkvm-server --listen 127.0.0.1:9527 --batch-size 256
//! ```
//!
//! ## 端点
//!
//! | 方法 | 路径 | 说明 |
//! |------|------|------|
//! | POST | /prove    | 提交 ELF+input → 返回 proof+public_io |
//! | POST | /verify   | 提交 proof+public_io → 返回 valid |
//! | GET  | /health   | 健康检查 |
//! | GET  | /stats    | 详细统计 |
//! | POST | /shutdown | 触发优雅关闭 |

use poker_zkvm::service::{ProverServiceConfig, http::run_server};

/// zkvm-server 子命令入口。
///
/// # Errors
/// - 参数解析失败
/// - 服务启动失败（端口占用等）
pub fn run(args: &[String]) -> Result<(), String> {
    let mut listen_addr = "127.0.0.1:9527".to_string();
    let mut batch_size: usize = 256;
    let mut max_n_vars: usize = 20;
    let mut proof_cache_capacity: usize = 16;
    // Phase 5.6 — 服务端并行线程配置（透传给底层 ProverConfig）
    let mut parallel_threads: Option<usize> = None;
    let mut parallel_ccs_compile: bool = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen_addr = args
                    .get(i)
                    .ok_or("--listen 缺少参数")?
                    .clone();
            }
            "--batch-size" => {
                i += 1;
                let v = args.get(i).ok_or("--batch-size 缺少参数")?;
                batch_size = v
                    .parse::<usize>()
                    .map_err(|e| format!("--batch-size 解析失败: {e}"))?;
            }
            "--max-n-vars" => {
                i += 1;
                let v = args.get(i).ok_or("--max-n-vars 缺少参数")?;
                max_n_vars = v
                    .parse::<usize>()
                    .map_err(|e| format!("--max-n-vars 解析失败: {e}"))?;
            }
            "--proof-cache-capacity" => {
                i += 1;
                let v = args.get(i).ok_or("--proof-cache-capacity 缺少参数")?;
                proof_cache_capacity = v
                    .parse::<usize>()
                    .map_err(|e| format!("--proof-cache-capacity 解析失败: {e}"))?;
            }
            "--parallel-threads" => {
                i += 1;
                let v = args.get(i).ok_or("--parallel-threads 缺少参数")?;
                let n = v
                    .parse::<usize>()
                    .map_err(|e| format!("--parallel-threads 解析失败: {e}"))?;
                if n == 0 {
                    return Err("--parallel-threads 须 >= 1".to_string());
                }
                parallel_threads = Some(n);
            }
            "--sequential-ccs-compile" => {
                parallel_ccs_compile = false;
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => {
                return Err(format!("未知参数: {other}"));
            }
        }
        i += 1;
    }

    let config = ProverServiceConfig {
        batch_size,
        max_n_vars,
        proof_cache_capacity,
        parallel_ccs_compile,
        rayon_threads: parallel_threads,
        ..Default::default()
    };

    tracing::info!(
        "zkvm-server 启动配置: listen={}, batch_size={}, max_n_vars={}, proof_cache_capacity={}, parallel_ccs_compile={}, rayon_threads={:?}",
        listen_addr,
        config.batch_size,
        config.max_n_vars,
        config.proof_cache_capacity,
        config.parallel_ccs_compile,
        config.rayon_threads,
    );

    // tokio runtime — 多线程，支持 spawn_blocking
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime 构造失败: {e}"))?;

    runtime.block_on(async move {
        if let Err(e) = run_server(&listen_addr, config).await {
            tracing::error!("zkvm-server 运行失败: {e}");
            return Err(format!("zkvm-server 运行失败: {e}"));
        }
        Ok(())
    })
}

/// 打印用法。
fn print_usage() {
    eprintln!("zchain zkvm-server — 启动 zkvm HTTP 证明服务");
    eprintln!();
    eprintln!("用法：");
    eprintln!("  zchain zkvm-server [options]");
    eprintln!();
    eprintln!("选项：");
    eprintln!("  --listen <addr>                监听地址（默认 127.0.0.1:9527）");
    eprintln!("  --batch-size <n>               每 batch 步数（默认 256）");
    eprintln!("  --max-n-vars <n>               IPA PCS 最大变量数（默认 20）");
    eprintln!("  --proof-cache-capacity <n>     proof_cache 容量（默认 16，LRU 淘汰）");
    eprintln!("  --parallel-threads <n>         rayon 线程池线程数（默认 None = 全局 RAYON_NUM_THREADS）");
    eprintln!("  --sequential-ccs-compile       禁用并行 CCS 编译（默认启用）");
    eprintln!("  --help, -h                     打印此帮助");
    eprintln!();
    eprintln!("环境变量：");
    eprintln!("  RUST_LOG                       tracing 日志级别（默认 info）");
    eprintln!();
    eprintln!("端点：");
    eprintln!("  POST /prove     提交 ELF+input，返回 proof+public_io");
    eprintln!("  POST /verify    提交 proof+public_io，返回 valid");
    eprintln!("  GET  /health    健康检查");
    eprintln!("  GET  /stats     详细统计");
    eprintln!("  POST /shutdown  触发优雅关闭");
    eprintln!();
    eprintln!("示例：");
    eprintln!("  zchain zkvm-server --listen 127.0.0.1:9527 --batch-size 256");
    eprintln!("  zchain zkvm-server --listen 127.0.0.1:9527 --parallel-threads 8");
}
