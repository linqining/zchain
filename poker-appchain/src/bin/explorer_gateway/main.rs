//! explorer_gateway — poker-appchain 区块链浏览器**只读**网关（计划内
//! E1 只读实时数据面 + E2 appchain 领域查询的 v1 落地）。
//!
//! 数据面（二选一）：
//!
//! - **replay**（默认）：从 appchain WAL 全量重放（验签 + 逐帧状态根重验，
//!   fail-closed——任何损坏即退出非零），可选 proven log 恢复证明水位
//!   与批次根；
//! - **index**（`--index-file`）：跳过全量 replay，直接装载持久化索引
//!   （`zchain.appchain.archive_index.v1`，digest/契约 fail-closed 校验），
//!   帧/结算/状态查询由索引服务；单笔结算明细按索引记录的 WAL 字节偏移
//!   定向读单帧（验签 + 与索引行交叉核对，fail-closed）。
//!
//! 运行期不接收任何写路径、不提交任何操作。
//!
//! # 用法
//!
//! ```text
//! explorer_gateway --appchain-wal <path> --sequencer-public <64hex>
//!                  [--index-file <path>] [--proven-log <path>]
//!                  [--proof-registry <path>] [--aggregate-log <path>]
//!                  [--l1-rpc <http://host:port>]
//!                  [--listen 127.0.0.1:8900] [--snapshot-out <dir>]
//!                  [--snapshot-interval-secs N] [--public]
//! explorer_gateway --write-index <path> --appchain-wal <path>
//!                  --sequencer-public <64hex> [--proof-registry <path>]
//! explorer_gateway --gen-fixture <dir>
//! ```
//!
//! # 纪律（fail-closed）
//!
//! - **默认只绑回环**；非回环监听地址必须 `--public` 显式开启，且启动时
//!   打印"非生产配置"警告；
//! - 每 IP 令牌桶限流（10 req/s，突发 20），超限 429；
//! - 只读 GET 白名单路由：未知路径 404、非 GET 405、参数坏 400；
//! - 全部响应带 `X-Zchain-Gateway: replay-v1`；`--public` 时附
//!   `Access-Control-Allow-Origin: *`。

mod aggregate_log;
mod api;
mod fixture;
mod http;
mod l1;
mod proven_log;
mod rate_limit;
mod server;
mod snapshot;
mod state;

use std::path::PathBuf;
use std::time::Duration;

use l1::L1Client;

/// 默认限流速率（req/s，每 IP）。
const DEFAULT_RATE: u32 = 10;
/// 默认令牌桶容量（突发）。
const DEFAULT_BURST: u32 = 20;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // 隐藏子命令：演示数据生成（smoke 脚本与本地调试用）。
    if let Some(pos) = position(&args, "--gen-fixture") {
        let Some(dir) = args.get(pos + 1) else {
            eprintln!("--gen-fixture 缺少目录参数");
            return usage(2);
        };
        return match fixture::generate(&PathBuf::from(dir)) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[explorer_gateway] fixture 生成失败: {e}");
                1
            }
        };
    }

    // 隐藏子命令：archive 索引构建（E2 indexer：回放时同步构建并落盘）。
    if let Some(pos) = position(&args, "--write-index") {
        return cmd_write_index(&args, pos);
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        return usage(0);
    }

    // ===== 必选参数 =====
    let Some(wal) = str_arg(&args, "--appchain-wal") else {
        eprintln!("缺少 --appchain-wal <path>");
        return usage(2);
    };
    let Some(pub_hex) = str_arg(&args, "--sequencer-public") else {
        eprintln!("缺少 --sequencer-public <64hex>");
        return usage(2);
    };
    let sequencer_public = match decode_public(&pub_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("--sequencer-public 无效: {e}");
            return 2;
        }
    };

    // ===== 可选参数 =====
    let proven_log = str_arg(&args, "--proven-log").map(PathBuf::from);
    let proof_registry = str_arg(&args, "--proof-registry").map(PathBuf::from);
    let aggregate_log = str_arg(&args, "--aggregate-log").map(PathBuf::from);
    let index_file = str_arg(&args, "--index-file").map(PathBuf::from);
    let listen = str_arg(&args, "--listen").unwrap_or_else(|| "127.0.0.1:8900".to_string());
    let snapshot_out = str_arg(&args, "--snapshot-out").map(PathBuf::from);
    let snapshot_interval_secs = match opt_u64(&args, "--snapshot-interval-secs") {
        Ok(v) => v,
        Err(()) => {
            eprintln!("--snapshot-interval-secs 需要非负整数");
            return 2;
        }
    };
    let public = args.iter().any(|a| a == "--public");
    let l1_url = str_arg(&args, "--l1-rpc");

    // ===== fail-closed：非回环监听必须 --public 显式开启 =====
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("--listen 无效（形如 127.0.0.1:8900）: {e}");
            return 2;
        }
    };
    if !addr.ip().is_loopback() && !public {
        eprintln!(
            "拒绝启动：监听地址 {addr} 非回环。只读网关默认只服务本机；\
             对外暴露必须显式传 --public（并自担暴露面评审）"
        );
        return 2;
    }
    if public && !addr.ip().is_loopback() {
        eprintln!(
            "[explorer_gateway] WARNING: 非生产配置——网关以 --public 绑定 {addr}，\
             将对网络暴露只读查询面（含 CORS *）；生产部署前必须补反代/鉴权/审计"
        );
    }

    // ===== 装配网关态（双数据面：index 直连或 WAL 全量重放，均 fail-closed）=====
    let wal_path = std::path::Path::new(&wal);
    let state = if let Some(index_path) = &index_file {
        match state::load_with_index(
            index_path,
            wal_path,
            sequencer_public,
            proven_log.as_deref(),
            proof_registry.as_deref(),
            aggregate_log.as_deref(),
        ) {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                eprintln!("[explorer_gateway] 启动失败: {e}");
                return 1;
            }
        }
    } else {
        match state::load(
            wal_path,
            sequencer_public,
            proven_log.as_deref(),
            proof_registry.as_deref(),
            aggregate_log.as_deref(),
        ) {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                eprintln!("[explorer_gateway] 启动失败: {e}");
                return 1;
            }
        }
    };
    let (frame_count, settlement_count) = if let Some(seq) = &state.seq {
        let seq = seq.lock().expect("gateway seq lock");
        (seq.chain().len(), api::settlement_frames(&seq).len())
    } else if let Some(index) = &state.index {
        let h = index.header();
        (
            usize::try_from(h.frame_count).unwrap_or(usize::MAX),
            usize::try_from(h.settlement_count).unwrap_or(usize::MAX),
        )
    } else {
        (0, 0)
    };
    eprintln!(
        "[explorer_gateway] {} 完成：{frame_count} 帧 / {settlement_count} settlements / watermark {:?}（{}）/ proofs {} / aggregates {}",
        state.data_source,
        state.watermark,
        state.watermark_source,
        state.proofs.len(),
        state.aggregates.len(),
    );

    // ===== L1 代理客户端（可选）=====
    let l1 = match &l1_url {
        Some(url) => match L1Client::from_url(url) {
            Ok(c) => {
                eprintln!("[explorer_gateway] L1 代理目标: {}", c.target());
                Some(c)
            }
            Err(e) => {
                eprintln!("[explorer_gateway] --l1-rpc 无效: {e}");
                return 2;
            }
        },
        None => None,
    };

    // ===== 绑定 + 服务 =====
    let listener = match server::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[explorer_gateway] 绑定 {listen} 失败: {e}");
            return 1;
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| listen.clone());
    let handle = server::spawn(
        listener,
        std::sync::Arc::clone(&state),
        server::ServerOptions {
            public,
            rate_per_sec: DEFAULT_RATE,
            burst: DEFAULT_BURST,
            l1,
        },
    );
    println!(
        "[explorer_gateway] listening on http://{local} (mode={})",
        state.data_source
    );

    // ===== 静态快照 =====
    if let Some(dir) = snapshot_out {
        if let Err(e) = snapshot::write_to(&dir, &state) {
            eprintln!("[explorer_gateway] 快照写入失败: {e}");
            return 1;
        }
        eprintln!(
            "[explorer_gateway] 快照已写: {}/explorer.json",
            dir.display()
        );
        if snapshot_interval_secs > 0 {
            let interval = Duration::from_secs(snapshot_interval_secs);
            std::thread::spawn(move || loop {
                std::thread::sleep(interval);
                if let Err(e) = snapshot::write_to(&dir, &state) {
                    eprintln!("[explorer_gateway] 快照周期写入失败: {e}");
                }
            });
        }
    }

    // accept 线程永不返回（服务器语义）；Ctrl-C 结束进程。
    let _ = handle.join();
    0
}

// ===== CLI 辅助 =====

/// `--write-index <out>`：回放构建 archive 索引并落盘（E2 indexer；
/// 需要 `--appchain-wal` + `--sequencer-public`，可选 `--proof-registry`）。
fn cmd_write_index(args: &[String], pos: usize) -> i32 {
    let Some(out) = args.get(pos + 1) else {
        eprintln!("--write-index 缺少输出路径参数");
        return usage(2);
    };
    let Some(wal) = str_arg(args, "--appchain-wal") else {
        eprintln!("--write-index 需要 --appchain-wal <path>");
        return usage(2);
    };
    let Some(pub_hex) = str_arg(args, "--sequencer-public") else {
        eprintln!("--write-index 需要 --sequencer-public <64hex>");
        return usage(2);
    };
    let public = match decode_public(&pub_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("--sequencer-public 无效: {e}");
            return 2;
        }
    };
    let registry = str_arg(args, "--proof-registry").map(PathBuf::from);
    let t0 = std::time::Instant::now();
    match poker_appchain::archive_index::build_index(
        std::path::Path::new(&wal),
        public,
        registry.as_deref(),
        std::path::Path::new(out),
    ) {
        Ok(index) => {
            let h = index.header();
            println!("INDEX_WRITTEN={out}");
            println!(
                "INDEX_FRAMES={} INDEX_SETTLEMENTS={} INDEX_PROOFS={}",
                h.frame_count, h.settlement_count, h.proof_count
            );
            println!("INDEX_DIGEST={}", hex::encode(h.digest));
            println!("INDEX_HEAD_INDEX={}", h.chain_head_index);
            eprintln!(
                "[explorer_gateway] index built in {:.1?}",
                t0.elapsed()
            );
            0
        }
        Err(e) => {
            eprintln!("[explorer_gateway] 索引构建失败: {e}");
            1
        }
    }
}

fn usage(code: i32) -> i32 {
    eprintln!(
        "用法:\n  \
         explorer_gateway --appchain-wal <path> --sequencer-public <64hex> \
         [--index-file <path>] [--proven-log <path>] [--proof-registry <path>] \
         [--aggregate-log <path>] [--l1-rpc <http://host:port>] \
         [--listen 127.0.0.1:8900] [--snapshot-out <dir>] \
         [--snapshot-interval-secs N] [--public]\n  \
         explorer_gateway --write-index <out> --appchain-wal <path> \
         --sequencer-public <64hex> [--proof-registry <path>]\n  \
         explorer_gateway --gen-fixture <dir>"
    );
    code
}

fn position(args: &[String], flag: &str) -> Option<usize> {
    args.iter().position(|a| a == flag)
}

fn str_arg(args: &[String], flag: &str) -> Option<String> {
    position(args, flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn opt_u64(args: &[String], flag: &str) -> Result<u64, ()> {
    match str_arg(args, flag) {
        None => Ok(0),
        Some(v) => v.parse::<u64>().map_err(|_| ()),
    }
}

fn decode_public(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|_| "need 64 hex chars".to_string())?;
    bytes.try_into().map_err(|_| "need 32 bytes".to_string())
}
