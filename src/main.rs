//! zchain — Poker L1 节点二进制入口。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 32.5**：CLI 工具（keygen / node 启动 / 节点查询）
//! - **Task 31**：JSON-RPC 2.0 over TCP（newline-delimited）
//!
//! 实现说明：
//! - 不引入额外 HTTP 框架（axum / hyper），使用 std::net::TcpListener +
//!   std::thread::scope 实现 newline-delimited JSON-RPC over TCP
//! - 节点角色（validator / full / archive / light）通过 CLI 参数选择
//! - validator 私钥优先从 `--validator-key-file <path>` 或 `ZCHAIN_VALIDATOR_KEY`
//!   环境变量读取；`--validator-key <hex>` 仍可用但会通过 ps aux 泄露，不推荐
//! - 支持 Ctrl+C / SIGTERM 优雅关闭（non-blocking accept + AtomicBool 轮询）
//! - 支持 `--max-connections` 限制并发连接数（默认 128）
//!
//! 用法示例：
//! ```text
//! zchain keygen --scheme secp256k1
//! zchain node --role full --data-dir ./data --rpc-listen 127.0.0.1:8545
//! zchain node --role validator --data-dir ./data --validator-key-file /run/secrets/validator.key
//! ZCHAIN_VALIDATOR_KEY=<hex> zchain node --role validator --data-dir ./data
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use poker_l1::node::{Node, NodeConfig, NodeRole, NodeRpcBackend, ValidatorKey};
use poker_l1::rpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcHandler};
use poker_l1::signature::tagged_pubkey::SignatureScheme;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// 程序版本。
const VERSION: &str = "0.1.0";

/// 默认最大并发连接数。
const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// 优雅关闭轮询间隔（accept non-blocking 后 sleep）。
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 程序入口。
fn main() {
    // 初始化 tracing：默认 INFO 级别，可通过 RUST_LOG 环境变量覆盖
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    let subcommand = args[1].as_str();
    let rest = &args[2..];
    match subcommand {
        "node" => {
            if let Err(e) = run_node(rest) {
                error!("node 启动失败：{e}");
                std::process::exit(1);
            }
        }
        "keygen" => {
            if let Err(e) = run_keygen(rest) {
                error!("keygen 失败：{e}");
                std::process::exit(1);
            }
        }
        "version" | "--version" | "-V" => {
            println!("zchain {VERSION}");
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        other => {
            error!("未知子命令：{other}");
            print_usage();
            std::process::exit(1);
        }
    }
}

/// 打印用法。
fn print_usage() {
    eprintln!("zchain {VERSION} — Poker L1 节点二进制");
    eprintln!();
    eprintln!("用法：");
    eprintln!("  zchain <subcommand> [options]");
    eprintln!();
    eprintln!("子命令：");
    eprintln!("  node      启动节点（运行 JSON-RPC server）");
    eprintln!("  keygen    生成密钥对（secp256k1 / ed25519）");
    eprintln!("  version   打印版本号");
    eprintln!("  help      打印此帮助");
    eprintln!();
    eprintln!("`node` 选项：");
    eprintln!("  --role <validator|full|archive|light>   节点角色（默认 full）");
    eprintln!("  --data-dir <path>                       数据目录（默认 ./data）");
    eprintln!("  --rpc-listen <addr>                     RPC 监听地址（默认 127.0.0.1:8545）");
    eprintln!("  --p2p-listen <addr>                     P2P 监听地址（默认 127.0.0.1:9000）");
    eprintln!("  --max-connections <n>                   最大并发连接数（默认 128）");
    eprintln!("  --validator-key-file <path>             validator 私钥文件（32B hex，推荐）");
    eprintln!(
        "  --validator-key <hex>                   validator 私钥（32B hex，不推荐：ps 可见）"
    );
    eprintln!();
    eprintln!("环境变量：");
    eprintln!(
        "  ZCHAIN_VALIDATOR_KEY                    validator 私钥（32B hex，优先级低于 --validator-key-file）"
    );
    eprintln!("  RUST_LOG                                tracing 日志级别（默认 info）");
    eprintln!();
    eprintln!("`keygen` 选项：");
    eprintln!("  --scheme <secp256k1|ed25519>            签名方案（默认 secp256k1）");
    eprintln!();
    eprintln!("示例：");
    eprintln!("  zchain keygen --scheme secp256k1");
    eprintln!("  zchain node --role full --data-dir ./data");
    eprintln!("  zchain node --role validator --validator-key-file /run/secrets/validator.key");
    eprintln!("  ZCHAIN_VALIDATOR_KEY=<hex> zchain node --role validator --data-dir ./data");
}

// ===== node 子命令 =====

/// 启动节点。
fn run_node(args: &[String]) -> Result<(), String> {
    let mut role: NodeRole = NodeRole::Full;
    let mut data_dir = PathBuf::from("./data");
    let mut rpc_listen = "127.0.0.1:8545".to_string();
    let mut p2p_listen = "127.0.0.1:9000".to_string();
    let mut max_connections: usize = DEFAULT_MAX_CONNECTIONS;
    let mut validator_key_hex: Option<String> = None;
    let mut validator_key_file: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--role" => {
                i += 1;
                let v = args.get(i).ok_or("--role 缺少参数")?;
                role = match v.as_str() {
                    "validator" => NodeRole::Validator,
                    "full" => NodeRole::Full,
                    "archive" => NodeRole::Archive,
                    "light" => NodeRole::Light,
                    other => {
                        return Err(format!(
                            "未知 role：{other}（应为 validator/full/archive/light）"
                        ));
                    }
                };
            }
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(args.get(i).ok_or("--data-dir 缺少参数")?);
            }
            "--rpc-listen" => {
                i += 1;
                rpc_listen = args.get(i).ok_or("--rpc-listen 缺少参数")?.clone();
            }
            "--p2p-listen" => {
                i += 1;
                p2p_listen = args.get(i).ok_or("--p2p-listen 缺少参数")?.clone();
            }
            "--max-connections" => {
                i += 1;
                let v = args.get(i).ok_or("--max-connections 缺少参数")?;
                max_connections = v
                    .parse::<usize>()
                    .map_err(|e| format!("--max-connections 解析失败：{e}"))?;
                if max_connections == 0 {
                    return Err("--max-connections 必须 > 0".to_string());
                }
            }
            "--validator-key-file" => {
                i += 1;
                validator_key_file = Some(PathBuf::from(
                    args.get(i).ok_or("--validator-key-file 缺少参数")?,
                ));
            }
            "--validator-key" => {
                i += 1;
                validator_key_hex = Some(args.get(i).ok_or("--validator-key 缺少参数")?.clone());
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }

    // 构建 NodeConfig
    let mut config = match role {
        NodeRole::Validator => {
            let key_hex = resolve_validator_key(validator_key_file, validator_key_hex)?;
            let key_bytes =
                hex::decode(key_hex.trim()).map_err(|e| format!("私钥 hex 解码失败：{e}"))?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "validator 私钥必须为 32 字节，得到 {} 字节",
                    key_bytes.len()
                ));
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&key_bytes);
            let vkey = ValidatorKey::from_secret_bytes(sk).map_err(|e| format!("私钥无效：{e}"))?;
            NodeConfig::validator(data_dir.clone(), vkey)
        }
        NodeRole::Full => NodeConfig::default_full(data_dir.clone()),
        NodeRole::Archive => NodeConfig::archive(data_dir.clone()),
        NodeRole::Light => NodeConfig::light(data_dir.clone()),
    };
    config.rpc_listen = rpc_listen.clone();
    config.p2p_listen = p2p_listen.clone();

    // 打印启动信息
    info!("zchain {VERSION} — Poker L1 节点启动中");
    info!("role        : {role:?}");
    info!("chain_id    : 0x{:08X}", config.chain_id);
    info!("data_dir    : {}", config.data_dir.display());
    info!("rpc_listen  : {}", config.rpc_listen);
    info!("p2p_listen  : {}", config.p2p_listen);
    info!("max_conn    : {max_connections}");
    if role.is_validator()
        && let Some(vk) = &config.validator_key
    {
        info!("validator   : {}", hex::encode(&vk.tagged_pubkey.raw));
    }

    // 打开节点
    let node = Node::open(config).map_err(|e| format!("Node::open 失败：{e}"))?;
    let node_arc = Arc::new(node);
    let backend = Arc::new(NodeRpcBackend::new(node_arc));

    // 绑定 TCP listener
    let listener = TcpListener::bind(&rpc_listen)
        .map_err(|e| format!("RPC 监听绑定 {rpc_listen} 失败：{e}"))?;
    // 设置 non-blocking 以支持优雅关闭轮询
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking 失败：{e}"))?;
    info!("JSON-RPC server 监听 {rpc_listen}（newline-delimited TCP）");

    // 优雅关闭：tokio runtime 监听 SIGINT / SIGTERM，设置 AtomicBool
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_flag_clone = Arc::clone(&shutdown_flag);
    let signal_thread = std::thread::Builder::new()
        .name("signal-handler".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime build failed");
            rt.block_on(async move {
                let ctrl_c = async {
                    tokio::signal::ctrl_c()
                        .await
                        .expect("ctrl_c signal handler failed");
                };

                #[cfg(unix)]
                let terminate = async {
                    use tokio::signal::unix::{SignalKind, signal};
                    signal(SignalKind::terminate())
                        .expect("SIGTERM signal handler failed")
                        .recv()
                        .await;
                };
                #[cfg(not(unix))]
                let terminate = std::future::pending::<()>();

                tokio::select! {
                    _ = ctrl_c => info!("收到 SIGINT，开始优雅关闭..."),
                    _ = terminate => info!("收到 SIGTERM，开始优雅关闭..."),
                }
                shutdown_flag_clone.store(true, Ordering::SeqCst);
            });
        })
        .map_err(|e| format!("signal handler 线程启动失败：{e}"))?;

    // 连接计数器（用于 --max-connections 限制）
    let active_connections = Arc::new(AtomicUsize::new(0));

    info!("按 Ctrl+C 退出");

    // 接受连接循环（scoped threads 共享 &backend）
    std::thread::scope(|s| {
        loop {
            // 检查关闭信号
            if shutdown_flag.load(Ordering::SeqCst) {
                info!("关闭信号已触发，停止接受新连接");
                break;
            }

            // non-blocking accept
            match listener.accept() {
                Ok((stream, _addr)) => {
                    // 恢复 blocking 模式给 handler 使用
                    let _ = stream.set_nonblocking(false);

                    // 连接数限制
                    let current = active_connections.load(Ordering::SeqCst);
                    if current >= max_connections {
                        warn!("连接数已达上限 {max_connections}，拒绝新连接（peer={_addr}）");
                        drop(stream);
                        continue;
                    }
                    active_connections.fetch_add(1, Ordering::SeqCst);

                    let peer = stream.peer_addr().ok();
                    let backend_clone = Arc::clone(&backend);
                    let conn_counter = Arc::clone(&active_connections);
                    s.spawn(move || {
                        if let Err(e) = handle_connection(stream, &backend_clone) {
                            warn!("连接处理错误（peer={peer:?}）：{e}");
                        }
                        conn_counter.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // 无新连接，短暂 sleep 后重试（同时检查 shutdown）
                    std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
                Err(e) => {
                    warn!("accept 失败：{e}");
                    std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                }
            }
        }
    });

    // 等待 signal handler 线程结束（它已经在设置 flag 后退出）
    let _ = signal_thread.join();

    info!("节点已关闭");
    Ok(())
}

/// 解析 validator 私钥来源。
///
/// 优先级：`--validator-key-file` > `ZCHAIN_VALIDATOR_KEY` 环境变量 > `--validator-key`（不推荐）。
///
/// # Errors
/// - validator 角色未提供任何私钥来源
/// - 文件读取失败
/// - 环境变量或 CLI 参数为空
fn resolve_validator_key(
    key_file: Option<PathBuf>,
    key_hex_cli: Option<String>,
) -> Result<String, String> {
    // 优先级 1：文件
    if let Some(path) = key_file {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取 validator-key-file {} 失败：{e}", path.display()))?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(format!("validator-key-file {} 内容为空", path.display()));
        }
        return Ok(trimmed.to_string());
    }

    // 优先级 2：环境变量
    if let Ok(env_key) = std::env::var("ZCHAIN_VALIDATOR_KEY") {
        let trimmed = env_key.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    // 优先级 3：CLI 参数（不推荐，ps aux 可见）
    if let Some(hex) = key_hex_cli {
        warn!(
            "使用 --validator-key CLI 参数传递私钥不安全（ps aux 可见），建议改用 --validator-key-file 或 ZCHAIN_VALIDATOR_KEY 环境变量"
        );
        return Ok(hex);
    }

    Err("validator 角色必须提供私钥：使用 --validator-key-file <path>、ZCHAIN_VALIDATOR_KEY 环境变量、或 --validator-key <hex>（不推荐）".to_string())
}

/// 处理单条 TCP 连接（newline-delimited JSON-RPC）。
fn handle_connection(stream: std::net::TcpStream, backend: &NodeRpcBackend) -> Result<(), String> {
    let handler = RpcHandler::new(backend);
    // TcpStream 在 BufReader / 写引用之间拆分
    let reader_stream = stream.try_clone().map_err(|e| e.to_string())?;
    let reader = BufReader::new(reader_stream);
    let mut writer = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => return Err(format!("读取行失败：{e}")),
        };
        if line.trim().is_empty() {
            continue;
        }
        // 解析 JSON-RPC 请求
        let resp: JsonRpcResponse = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(req) => handler.handle(&req),
            Err(e) => JsonRpcResponse::error(
                JsonRpcError::new(JsonRpcError::PARSE_ERROR, format!("parse error: {e}")),
                serde_json::Value::Null,
            ),
        };
        let resp_bytes = serde_json::to_vec(&resp).map_err(|e| e.to_string())?;
        writer.write_all(&resp_bytes).map_err(|e| e.to_string())?;
        writer.write_all(b"\n").map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ===== keygen 子命令 =====

/// 运行 keygen。
fn run_keygen(args: &[String]) -> Result<(), String> {
    let mut scheme = SignatureScheme::Secp256k1;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--scheme" => {
                i += 1;
                let v = args.get(i).ok_or("--scheme 缺少参数")?;
                scheme = match v.as_str() {
                    "secp256k1" => SignatureScheme::Secp256k1,
                    "ed25519" => SignatureScheme::Ed25519,
                    other => {
                        return Err(format!("未知 scheme：{other}（应为 secp256k1 / ed25519）"));
                    }
                };
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }

    let result = poker_l1::node::keygen(scheme).map_err(|e| e.to_string())?;
    // 输出 JSON（secret_key 以 hex 编码便于直接使用）
    let scheme_str = match result.scheme {
        SignatureScheme::Secp256k1 => "secp256k1",
        SignatureScheme::Ed25519 => "ed25519",
    };
    let output = serde_json::json!({
        "scheme": scheme_str,
        "secret_key_hex": hex::encode(&result.secret_key_bytes),
        "tagged_pubkey": {
            "tag": hex::encode([result.tagged_pubkey.tag]),
            "raw_hex": hex::encode(&result.tagged_pubkey.raw),
        },
        "address_hex": hex::encode(result.address),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}
