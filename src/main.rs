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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use poker_l1::node::{Node, NodeConfig, NodeRole, NodeRpcBackend, ValidatorKey};
use poker_l1::account::derive_address;
use poker_l1::block::validator::{validate_tx_chain_id, validate_tx_nonce, validate_tx_signature};
use poker_l1::block::{Block, BlockHeader, compute_tx_merkle_root};
use poker_l1::executor::ExecutionEnvironment;
use poker_l1::consensus::{
    Dag, DagCommitCertificate, DagVertex, VertexBuilder, detect_commit_leader,
};
use poker_l1::error::PokerL1Result;
use poker_l1::network::{GossipTopic, NetworkMessage, NetworkTransport, PeerInfo};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane, validate_tx_limits};
use poker_l1::{Address, Hash};
use poker_l1::rpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcClientInfo, RpcGuard, RpcHandler,
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

mod poker_demo;

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
        "test-e2e" => {
            if let Err(e) = run_test_e2e(rest) {
                error!("test-e2e 失败：{e}");
                std::process::exit(1);
            }
        }
        "poker-demo" => {
            if let Err(e) = poker_demo::run(rest) {
                error!("poker-demo 失败：{e}");
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
    eprintln!("  test-e2e  端到端链路测试（构造交易→签名→提交→出块→查询）");
    eprintln!("  poker-demo  运行 Texas Poker 完整牌局演示（in-process，绕过 RPC）");
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
    eprintln!(
        "  --block-interval-ms <ms>                出块间隔毫秒（默认 1000，仅 validator）"
    );
    eprintln!(
        "  --peer <addr>                           P2P peer 地址（可重复，如 127.0.0.1:9001）"
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
    let mut block_interval_ms: u64 = DEFAULT_BLOCK_INTERVAL_MS;
    let mut peers: Vec<String> = Vec::new();

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
            "--block-interval-ms" => {
                i += 1;
                let v = args.get(i).ok_or("--block-interval-ms 缺少参数")?;
                block_interval_ms = v
                    .parse::<u64>()
                    .map_err(|e| format!("--block-interval-ms 解析失败：{e}"))?;
                if block_interval_ms == 0 {
                    return Err("--block-interval-ms 必须 > 0".to_string());
                }
            }
            "--peer" => {
                i += 1;
                let addr = args.get(i).ok_or("--peer 缺少参数")?.clone();
                peers.push(addr);
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
            let mut key_bytes =
                hex::decode(key_hex.trim()).map_err(|e| format!("私钥 hex 解码失败：{e}"))?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "validator 私钥必须为 32 字节，得到 {} 字节",
                    key_bytes.len()
                ));
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&key_bytes);
            // 安全擦除含私钥明文的中间变量（ValidatorKey 内部有独立副本并实现 Drop zeroize）
            key_bytes.fill(0);
            let vkey = ValidatorKey::from_secret_bytes(sk).map_err(|e| format!("私钥无效：{e}"))?;
            sk.fill(0);
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
    let backend = Arc::new(NodeRpcBackend::new(Arc::clone(&node_arc)));

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

    // H-1 修复：创建 RPC 安全守卫（限流 + 认证，所有连接共享同一窗口）
    let guard = Arc::new(RpcGuard::default_config());
    info!("RPC 安全守卫已启用（限流: read 100rps / write 10rps / crypto 5rps）");

    info!("按 Ctrl+C 退出");

    // === P2P 传输层 ===
    let transport = Arc::new(TcpTransport::new());

    // 绑定 P2P listener
    let p2p_listener = TcpListener::bind(&p2p_listen)
        .map_err(|e| format!("P2P 监听绑定 {p2p_listen} 失败：{e}"))?;
    p2p_listener
        .set_nonblocking(true)
        .map_err(|e| format!("P2P set_nonblocking 失败：{e}"))?;
    info!("P2P server 监听 {p2p_listen}（length-prefixed BCS）");

    // 主动连接 --peer 列表
    for peer_addr in &peers {
        if let Err(e) = transport.connect_peer(peer_addr) {
            warn!("初始连接 peer {peer_addr} 失败：{e}（后续可重试）");
        }
    }
    info!("P2P 已连接 {} 个 peer", transport.peer_count());

    // === P2P accept loop 线程 ===
    let p2p_node = Arc::clone(&node_arc);
    let p2p_transport = Arc::clone(&transport);
    let p2p_shutdown = Arc::clone(&shutdown_flag);
    let p2p_thread = std::thread::Builder::new()
        .name("p2p-accept".to_string())
        .spawn(move || {
            loop {
                if p2p_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                match p2p_listener.accept() {
                    Ok((stream, addr)) => {
                        let _ = stream.set_nonblocking(false);
                        info!("P2P 接入连接：{addr}");
                        let node = Arc::clone(&p2p_node);
                        let transport = Arc::clone(&p2p_transport);
                        std::thread::spawn(move || {
                            handle_p2p_connection(stream, node, transport);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                    }
                    Err(e) => {
                        warn!("P2P accept 失败：{e}");
                        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                    }
                }
            }
        })
        .map_err(|e| format!("P2P accept 线程启动失败：{e}"))?;

    // === validator 产块循环线程（仅 validator 角色）===
    // 注意：config 已 move 进 Node::open，需从 node_arc.config() 获取 validator_key
    let validator_thread = if role.is_validator() {
        let vkey = node_arc
            .config()
            .validator_key
            .clone()
            .ok_or("validator 角色缺少 validator_key")?;
        let chain_id = node_arc.chain_id();
        let dag = Arc::new(Mutex::new(Dag::new()));
        let v_transport = Arc::clone(&transport);
        let v_shutdown = Arc::clone(&shutdown_flag);
        let v_node = Arc::clone(&node_arc);
        let interval = Duration::from_millis(block_interval_ms);
        Some(
            std::thread::Builder::new()
                .name("validator-loop".to_string())
                .spawn(move || {
                    run_validator_loop(v_node, vkey, chain_id, dag, v_transport, interval, v_shutdown);
                })
                .map_err(|e| format!("validator loop 线程启动失败：{e}"))?,
        )
    } else {
        info!("非 validator 角色，跳过产块循环");
        None
    };

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
                    let guard_clone = Arc::clone(&guard);
                    s.spawn(move || {
                        if let Err(e) = handle_connection(stream, &backend_clone, &guard_clone) {
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
    let _ = p2p_thread.join();
    if let Some(vt) = validator_thread {
        let _ = vt.join();
    }

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
///
/// H-1 修复：提取客户端 IP 作为 client_id，经 RpcGuard 执行限流 + 认证。
fn handle_connection(
    stream: std::net::TcpStream,
    backend: &NodeRpcBackend,
    guard: &Arc<RpcGuard>,
) -> Result<(), String> {
    let client = RpcClientInfo {
        client_id: stream.peer_addr().ok().map(|a| a.to_string()),
        api_key: None,
    };
    let handler = RpcHandler::with_guard(backend, Arc::clone(guard));
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
            Ok(req) => handler.handle_with_client(&req, &client),
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

// ===== P2P TCP 传输层 =====

/// 默认出块间隔（毫秒）。
const DEFAULT_BLOCK_INTERVAL_MS: u64 = 1000;

/// P2P 消息最大长度（16MB，防止恶意大消息 OOM）。
const MAX_P2P_MSG_SIZE: usize = 16 * 1024 * 1024;

/// 默认 P2P 请求-响应超时（秒）。
const P2P_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// tokio TCP 轻量 P2P 传输层。
///
/// 实现 [`NetworkTransport`] trait，用 4 字节 length-prefix + BCS 序列化消息。
/// 不引入 libp2p，避免 musl 静态编译问题。
///
/// 重构2：维护 peer 地址列表（`peer_addrs`）以支持定向通信（send_to / request_*）。
/// - `peers` 仅用于 `gossip_broadcast`（持久写入 stream）
/// - `peer_addrs` 用于 `send_to` / `request_blocks_by_range` / `request_vertices_by_range`
///   —— 通过创建临时连接发送，避免与持久读取循环冲突
struct TcpTransport {
    /// 已连接的 peer streams（仅用于 gossip_broadcast）。
    peers: Arc<Mutex<Vec<TcpStream>>>,
    /// 已连接 peer 的地址信息（用于定向通信）。
    peer_addrs: Arc<Mutex<Vec<PeerInfo>>>,
}

impl TcpTransport {
    /// 创建空传输层。
    fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(Vec::new())),
            peer_addrs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 添加已连接的 peer stream（仅加入广播列表）。
    fn add_peer(&self, stream: TcpStream) {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(stream);
    }

    /// 注册 peer 地址信息（用于定向通信）。
    /// 去重以避免同一地址多次注册。
    fn register_peer_info(&self, peer_info: PeerInfo) {
        let mut addrs = self.peer_addrs.lock().unwrap_or_else(|e| e.into_inner());
        if !addrs.iter().any(|p| p.address == peer_info.address) {
            addrs.push(peer_info);
        }
    }

    /// 主动连接到 peer。
    ///
    /// 连接成功后：stream 加入广播列表，PeerInfo 加入定向通信列表。
    fn connect_peer(&self, addr: &str) -> Result<(), String> {
        let stream = TcpStream::connect(addr).map_err(|e| format!("连接 peer {addr} 失败：{e}"))?;
        info!("已连接 peer：{addr}");
        self.add_peer(stream);
        self.register_peer_info(PeerInfo {
            peer_id: addr.to_string(),
            address: addr.to_string(),
            validator_pubkey: None,
        });
        Ok(())
    }

    /// 获取当前 peer 数量（按地址计数）。
    fn peer_count(&self) -> usize {
        self.peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl NetworkTransport for TcpTransport {
    fn gossip_broadcast(
        &self,
        _topic: GossipTopic,
        message: &NetworkMessage,
    ) -> PokerL1Result<()> {
        let bytes = borsh::to_vec(message)?;
        let len = bytes.len() as u32;
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);

        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let mut failed = Vec::new();
        for (i, stream) in peers.iter_mut().enumerate() {
            if let Err(e) = stream.write_all(&frame).and_then(|_| stream.flush()) {
                warn!("广播消息到 peer {i} 失败：{e}，移除连接");
                failed.push(i);
            }
        }
        // 从后往前移除失败的 peer
        for i in failed.into_iter().rev() {
            peers.remove(i);
        }
        Ok(())
    }

    fn send_to(&self, peer: &PeerInfo, message: &NetworkMessage) -> PokerL1Result<()> {
        // 重构2：通过临时连接定向发送，避免与持久读取循环冲突
        let mut stream = TcpStream::connect(&peer.address).map_err(|e| {
            poker_l1::error::PokerL1Error::Other(format!(
                "send_to: 连接 {} 失败：{e}",
                peer.address
            ))
        })?;
        stream
            .set_write_timeout(Some(P2P_REQUEST_TIMEOUT))
            .map_err(|e| {
                poker_l1::error::PokerL1Error::Other(format!("set_write_timeout 失败：{e}"))
            })?;
        send_p2p_message(&mut stream, message).map_err(|e| {
            poker_l1::error::PokerL1Error::Other(format!("send_to: 发送失败：{e}"))
        })?;
        debug!("send_to: 已发送消息到 peer={}", peer.address);
        Ok(())
    }

    fn discover_peers(&self) -> PokerL1Result<Vec<PeerInfo>> {
        Ok(self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn request_blocks_by_range(
        &self,
        start: poker_l1::BlockHeight,
        end: poker_l1::BlockHeight,
    ) -> PokerL1Result<Vec<Block>> {
        let peers = self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if peers.is_empty() {
            return Err(poker_l1::error::PokerL1Error::Other(
                "request_blocks_by_range: 无可用 peer".to_string(),
            ));
        }
        let req = NetworkMessage::RequestBlocksByRange(start, end);
        for peer in &peers {
            match send_request_and_recv(&peer.address, &req) {
                Ok(NetworkMessage::ResponseBlocks(blocks)) => {
                    debug!(
                        "request_blocks_by_range: 从 peer {} 获取 {} 个 block",
                        peer.address,
                        blocks.len()
                    );
                    return Ok(blocks);
                }
                Ok(other) => warn!(
                    "request_blocks_by_range: peer {} 返回非预期消息类型：{other:?}",
                    peer.address
                ),
                Err(e) => warn!("request_blocks_by_range: peer {} 失败：{e}", peer.address),
            }
        }
        Err(poker_l1::error::PokerL1Error::Other(
            "request_blocks_by_range: 所有 peer 请求失败".to_string(),
        ))
    }

    fn request_vertices_by_range(
        &self,
        start_round: u64,
        end_round: u64,
    ) -> PokerL1Result<Vec<DagVertex>> {
        let peers = self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if peers.is_empty() {
            return Err(poker_l1::error::PokerL1Error::Other(
                "request_vertices_by_range: 无可用 peer".to_string(),
            ));
        }
        let req = NetworkMessage::RequestVerticesByRange(start_round, end_round);
        for peer in &peers {
            match send_request_and_recv(&peer.address, &req) {
                Ok(NetworkMessage::ResponseVertices(vertices)) => {
                    debug!(
                        "request_vertices_by_range: 从 peer {} 获取 {} 个 vertex",
                        peer.address,
                        vertices.len()
                    );
                    return Ok(vertices);
                }
                Ok(other) => warn!(
                    "request_vertices_by_range: peer {} 返回非预期消息类型：{other:?}",
                    peer.address
                ),
                Err(e) => warn!("request_vertices_by_range: peer {} 失败：{e}", peer.address),
            }
        }
        Err(poker_l1::error::PokerL1Error::Other(
            "request_vertices_by_range: 所有 peer 请求失败".to_string(),
        ))
    }

    fn subscribe_light_headers(
        &self,
    ) -> PokerL1Result<Vec<poker_l1::network::LightClientHeader>> {
        // 轻客户端 header 订阅依赖 validator 多签协议，超出本次重构范围
        Ok(Vec::new())
    }
}

/// 向 peer 发送请求并接收响应（临时连接，含超时）。
///
/// 用于 `request_blocks_by_range` / `request_vertices_by_range` 等请求-响应协议。
/// 创建独立连接以避免与持久 P2P 读取循环冲突。
fn send_request_and_recv(
    peer_addr: &str,
    req: &NetworkMessage,
) -> Result<NetworkMessage, String> {
    let mut stream =
        TcpStream::connect(peer_addr).map_err(|e| format!("连接 {peer_addr} 失败：{e}"))?;
    stream
        .set_read_timeout(Some(P2P_REQUEST_TIMEOUT))
        .map_err(|e| format!("set_read_timeout 失败：{e}"))?;
    stream
        .set_write_timeout(Some(P2P_REQUEST_TIMEOUT))
        .map_err(|e| format!("set_write_timeout 失败：{e}"))?;
    send_p2p_message(&mut stream, req)?;
    match recv_p2p_message(&mut stream)? {
        Some(msg) => Ok(msg),
        None => Err("连接在响应前关闭".to_string()),
    }
}

/// 发送一条 length-prefixed BCS 消息到 stream。
#[allow(dead_code)]
fn send_p2p_message(stream: &mut TcpStream, msg: &NetworkMessage) -> Result<(), String> {
    let bytes = borsh::to_vec(msg).map_err(|e| format!("BCS 序列化失败：{e}"))?;
    if bytes.len() > MAX_P2P_MSG_SIZE {
        return Err(format!("消息过大：{} bytes", bytes.len()));
    }
    let len = bytes.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| format!("写入 length 失败：{e}"))?;
    stream
        .write_all(&bytes)
        .map_err(|e| format!("写入 body 失败：{e}"))?;
    stream.flush().map_err(|e| format!("flush 失败：{e}"))?;
    Ok(())
}

/// 接收一条 length-prefixed BCS 消息。
///
/// 返回 `Ok(None)` 表示连接已关闭（EOF）。
fn recv_p2p_message(stream: &mut TcpStream) -> Result<Option<NetworkMessage>, String> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("读取 length 失败：{e}")),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_P2P_MSG_SIZE {
        return Err(format!("消息过大：{len} bytes（上限 {MAX_P2P_MSG_SIZE}）"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("读取 body 失败：{e}"))?;
    let msg = borsh::from_slice(&buf).map_err(|e| format!("BCS 反序列化失败：{e}"))?;
    Ok(Some(msg))
}

/// 处理 P2P 连接（接收端）。
///
/// 接收消息并分发处理：
/// - `DagVertex` → `node.put_vertex`
/// - `Transaction` → `node.submit_tx`（含完整验证链）
/// - `ResponseBlocks` → 逐个 `node.put_block`
/// - `RequestBlocksByRange` → 查询本地并回送 `ResponseBlocks`
/// - `RequestVerticesByRange` → 暂返回空（需 epoch 上下文，超出本次重构范围）
fn handle_p2p_connection(
    mut stream: TcpStream,
    node: Arc<Node>,
    transport: Arc<TcpTransport>,
) {
    let peer_addr = stream.peer_addr().ok();
    // 重构2：注册接入 peer 的地址信息（用于定向通信）
    if let Some(addr) = peer_addr {
        transport.register_peer_info(PeerInfo {
            peer_id: addr.to_string(),
            address: addr.to_string(),
            validator_pubkey: None,
        });
    }
    loop {
        match recv_p2p_message(&mut stream) {
            Ok(Some(msg)) => {
                match msg {
                    NetworkMessage::DagVertex(vertex) => {
                        if let Err(e) = node.put_vertex(&vertex) {
                            warn!("P2P put_vertex 失败：{e}");
                        }
                    }
                    NetworkMessage::Transaction(tx) => {
                        // C-1 安全修复：P2P 路径必须与 RPC 路径执行一致的验证链，
                        // 防止恶意节点注入未签名/跨链重放/超大交易进入 pending_tx。
                        let chain_id = node.chain_id();
                        if let Err(e) = validate_tx_limits(&tx) {
                            warn!("P2P 交易拒绝（limits）：{e}");
                            continue;
                        }
                        if let Err(e) = validate_tx_chain_id(&tx, chain_id) {
                            warn!("P2P 交易拒绝（chain_id）：{e}");
                            continue;
                        }
                        if let Err(e) = validate_tx_signature(&tx) {
                            warn!("P2P 交易拒绝（签名无效）：{e}");
                            continue;
                        }
                        // nonce 校验：Public/ForceSync/CheckpointAnchor 用 account nonce；
                        // GameTurn 的 game_player_nonce 需游戏状态，留待 block 验证。
                        let caller_address = derive_address(&tx.tagged_pubkey);
                        let account_nonce = node
                            .get_account(&caller_address)
                            .ok()
                            .flatten()
                            .map(|a| a.nonce)
                            .unwrap_or(0);
                        if let Err(e) = validate_tx_nonce(&tx, account_nonce, None) {
                            warn!("P2P 交易拒绝（nonce）：{e}");
                            continue;
                        }
                        if let Err(e) = node.submit_tx(tx) {
                            warn!("P2P submit_tx 失败：{e}");
                        }
                    }
                    NetworkMessage::ResponseBlocks(blocks) => {
                        for block in blocks {
                            if let Err(e) = node.put_block(&block) {
                                warn!("P2P put_block 失败：{e}");
                            }
                        }
                    }
                    NetworkMessage::ResponseVertices(vertices) => {
                        for vertex in vertices {
                            if let Err(e) = node.put_vertex(&vertex) {
                                warn!("P2P put_vertex 失败：{e}");
                            }
                        }
                    }
                    NetworkMessage::RequestBlocksByRange(start, end) => {
                        // 重构2：响应 block range 请求
                        let blocks = collect_blocks_by_range(&node, start, end);
                        if let Err(e) =
                            send_p2p_message(&mut stream, &NetworkMessage::ResponseBlocks(blocks))
                        {
                            warn!("P2P 回送 ResponseBlocks 失败：{e}");
                        }
                    }
                    NetworkMessage::RequestVerticesByRange(_start_round, _end_round) => {
                        // 需 epoch 上下文才能查询 vertex_store.get_by_round(epoch, round)，
                        // 当前请求未携带 epoch，暂返回空 Vec。
                        // TODO: 协议升级后补充 epoch 字段。
                        debug!("收到 RequestVerticesByRange（暂不支持，需 epoch）");
                        if let Err(e) = send_p2p_message(
                            &mut stream,
                            &NetworkMessage::ResponseVertices(Vec::new()),
                        ) {
                            warn!("P2P 回送 ResponseVertices 失败：{e}");
                        }
                    }
                    NetworkMessage::CompactVertex(compact) => {
                        // 简化：compact vertex 需要从本地 tx_cache 重建，暂不支持
                        let _ = compact;
                        debug!("收到 CompactVertex（暂不支持重建）");
                    }
                    other => {
                        debug!("收到未处理的 P2P 消息类型：{other:?}");
                    }
                }
            }
            Ok(None) => {
                info!("P2P 连接关闭（peer={peer_addr:?}）");
                break;
            }
            Err(e) => {
                warn!("P2P 接收错误（peer={peer_addr:?}）：{e}");
                break;
            }
        }
    }
}

/// 收集指定 height 范围内的 blocks（用于响应 RequestBlocksByRange）。
///
/// `start` / `end` 均为闭区间。单个 height 查询失败不影响其他。
fn collect_blocks_by_range(
    node: &Node,
    start: poker_l1::BlockHeight,
    end: poker_l1::BlockHeight,
) -> Vec<Block> {
    let mut blocks = Vec::new();
    for height in start..=end {
        match node.get_block_by_height(height) {
            Ok(Some(block)) => blocks.push(block),
            Ok(None) => debug!("collect_blocks: height {height} 无 block"),
            Err(e) => warn!("collect_blocks: 查询 height {height} 失败：{e}"),
        }
        // 防止单次请求扫表过大（DoS 防护）
        if blocks.len() >= 512 {
            debug!("collect_blocks: 达到 512 上限，截断");
            break;
        }
    }
    blocks
}

// ===== validator 产块循环 =====

/// 用 secp256k1 签名 32 字节哈希，返回 65 字节 recoverable 签名（64B compact + 1B recovery_id）。
fn secp256k1_sign_hash(secret_key: &secp256k1::SecretKey, msg_hash: &Hash) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let msg = secp256k1::Message::from_digest(*msg_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut full_sig = compact.to_vec();
    full_sig.push(recovery_id.to_i32() as u8);
    full_sig
}

/// 从单个 vertex 构造 block（单 validator 简化模式）。
///
/// 单 validator 自闭环模式下，每轮 vertex 直接对应一个 block。
/// 不调用 `project_block_from_commit`（其 `collect_ancestors` 会包含历史 vertex 的 tx 导致重复），
/// 而是直接从当前 vertex 的 tx_list 构造 block。
///
/// tx 执行引擎接入：caller 传入 `node` + `prev_state_root`，本函数：
/// 1. 对 vertex 的 txs 执行 S9 排序
/// 2. 调用 `node.execute_block_on_state` 执行全部 txs（含 public + gameturn）
/// 3. 取 `outcome.state_root` 作为新 block header 的 state_root
/// 4. 按 public / gameturn 拆分 txs 用于 merkle root 计算 + block body
///
/// `prev_state_root` 仅用于日志对比（检测执行引擎是否真正推进了状态）。
fn build_block_from_vertex(
    vertex: &DagVertex,
    chain_id: poker_l1::ChainId,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    node: &Node,
    prev_state_root: Hash,
    secret_key: &secp256k1::SecretKey,
) -> Result<Block, String> {
    // 1. S9 排序：GameTurn/CheckpointAnchor 优先，Public 中间，ForceSync 后置
    let sorted_txs = poker_l1::consensus::sort_vertex_txs_s9(vertex.tx_list.clone());

    // 2. 拆分 public / gameturn（用于 merkle root + block body）
    let mut public_txs = Vec::new();
    let mut gameturn_txs = Vec::new();
    for tx in &sorted_txs {
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn_txs.push(tx.clone()),
            _ => public_txs.push(tx.clone()),
        }
    }

    // 3. 计算 timestamp（提前到执行之前，供 ExecutionEnvironment 使用）
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // 4. 执行 txs，得到新 state_root
    //
    // execute_block 内部已处理失败 tx（返回失败回执，不阻断 block），
    // 故此处仅在底层错误（锁中毒 / RocksDB 写失败）时返回 Err。
    let env = ExecutionEnvironment::new(chain_id, height, timestamp_ms)
        .with_precompile_registry_arc(node.precompile_registry());
    let outcome = node
        .execute_block_on_state(&env, &sorted_txs)
        .map_err(|e| format!("execute_block failed: {e}"))?;
    let state_root = outcome.state_root;
    if state_root == prev_state_root && !sorted_txs.is_empty() {
        warn!(
            "执行 {} 笔 tx 后 state_root 未变化（可能全部失败或为无状态 tx）",
            sorted_txs.len()
        );
    }

    // 5. 计算 roots
    let public_tx_root = compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = compute_tx_merkle_root(&gameturn_txs);

    // 6. 构造 commit certificate（先不含签名）
    let vertex_hash = vertex.vertex_hash();
    let cert = DagCommitCertificate {
        epoch: vertex.epoch,
        commit_round,
        prev_commit_hash,
        vertex_hash_list: vec![vertex_hash],
        round_attendance_bitmap: vec![0xFF],
        state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![],
        signer_bitmap: vec![0x00],
    };

    // 7. 签名 cert
    let cert_signing_hash = cert.signing_hash(chain_id);
    let cert_sig = secp256k1_sign_hash(secret_key, &cert_signing_hash);

    // 8. 填入签名（validator index = 0，signer_bitmap bit 0 = 1）
    let cert = DagCommitCertificate {
        signature_list: vec![cert_sig],
        signer_bitmap: vec![0x01],
        ..cert
    };

    // 9. 构造 block header
    let header = BlockHeader {
        height,
        timestamp_ms,
        prev_hash: prev_block_hash,
        state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };

    Ok(Block::new(header, public_txs, gameturn_txs))
}

/// validator 产块循环（后台线程）。
///
/// 单 validator 自闭环模式：
/// 1. 每 `block_interval` 从 `pending_tx` 取 tx 组装 vertex
/// 2. secp256k1 签名 vertex → `dag.insert` + `node.put_vertex` + P2P 广播
/// 3. 从第 2 轮起，当前 vertex 引用上一轮 vertex → 自动满足 quorum(1) → commit
/// 4. 构造 block → `node.put_block` + P2P 广播
fn run_validator_loop(
    node: Arc<Node>,
    validator_key: ValidatorKey,
    chain_id: poker_l1::ChainId,
    dag: Arc<Mutex<Dag>>,
    transport: Arc<TcpTransport>,
    block_interval: Duration,
    shutdown: Arc<AtomicBool>,
) {
    // 从 ValidatorKey 提取 secp256k1 SecretKey
    let secret_key = match secp256k1::SecretKey::from_slice(&validator_key.secret_key_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            error!("validator 私钥无效：{e}");
            return;
        }
    };
    let author_pubkey = validator_key.tagged_pubkey.clone();

    let epoch: u64 = 1;
    let mut round: u64 = 1;
    let mut commit_round: u64 = 1;
    let mut prev_commit_hash: Hash = [0u8; 32];
    let mut prev_block_hash: Hash = [0u8; 32];
    // 存完整 vertex（非仅 hash），以便 commit 时从上一个 vertex 构造 block
    let mut last_vertex: Option<DagVertex> = None;

    info!(
        "validator 产块循环已启动（混合模式，间隔={}ms，pubkey={})",
        block_interval.as_millis(),
        hex::encode(&author_pubkey.raw)
    );

    while !shutdown.load(Ordering::SeqCst) {
        // 混合模式核心：等待 tx 或超时
        // - 有 tx 时被 submit_tx 的 notify_one 立即唤醒 → 零延迟出 vertex
        // - 超时返回 false → 检查是否需要出空 vertex 推进 commit
        let _has_tx = node.wait_for_pending_tx(block_interval);
        let txs = node.drain_pending_tx();

        // 决定是否产出 vertex：
        // - 有 tx → 立即出 vertex
        // - 无 tx 但上一个 vertex 有未 commit 的 tx → 出空 vertex 推进 commit
        // - 无 tx 且无未 commit 的 tx-vertex → 跳过，继续等待
        let last_has_txs = last_vertex
            .as_ref()
            .map(|v| !v.tx_list.is_empty())
            .unwrap_or(false);
        if txs.is_empty() && !last_has_txs {
            continue;
        }

        // 构造 vertex
        let parent_hashes = last_vertex
            .as_ref()
            .map(|v| vec![v.vertex_hash()])
            .unwrap_or_default();
        let mut builder = VertexBuilder::new(epoch, round, author_pubkey.clone());
        for tx in txs {
            builder.push_tx(tx);
        }
        let builder = builder.with_parents(parent_hashes);

        // 创世轮（round 1）跳过 validate_parents（无 parent）
        if round > 1 {
            if let Err(e) = builder.validate_parents(1) {
                warn!("vertex parent 校验失败：{e}");
            }
        }
        if let Err(e) = builder.validate_size() {
            warn!("vertex 大小校验失败：{e}");
            continue;
        }

        // 签名 vertex
        let unsigned = builder.build(vec![]);
        let vertex_signing_hash = unsigned.signing_hash(chain_id);
        let vertex_sig = secp256k1_sign_hash(&secret_key, &vertex_signing_hash);
        let vertex = DagVertex {
            author_sig: vertex_sig,
            ..unsigned
        };

        // 插入 Dag + 持久化 + 广播
        let vertex_hash = {
            let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
            dag_guard.insert(vertex.clone())
        };
        if let Err(e) = node.put_vertex(&vertex) {
            // put_vertex 持久化失败：跳过本轮 commit 与广播，避免基于未持久化 vertex 出块。
            warn!("put_vertex 失败，跳过本轮 commit：{e}");
            last_vertex = Some(vertex);
            round += 1;
            continue;
        }
        let _ = transport.gossip_broadcast(
            GossipTopic::DagVertex,
            &NetworkMessage::DagVertex(vertex.clone()),
        );

        info!(
            "vertex 已产出 round={} tx_count={} hash={}",
            round,
            vertex.tx_list.len(),
            hex::encode(vertex_hash)
        );

        // 从第 2 轮起，检测 commit 并产出 block
        if let Some(prev_vertex) = &last_vertex {
            let prev_hash = prev_vertex.vertex_hash();
            match detect_commit_leader(&dag.lock().unwrap_or_else(|e| e.into_inner()), &prev_hash, 1) {
                Ok(Some(_leader)) => {
                    // 从上一个 vertex（被 commit 的）构造 block
                    // 这样 block 包含的是被 commit 的 tx，而非当前 vertex 的 tx
                    match build_block_from_vertex(
                        prev_vertex,
                        chain_id,
                        commit_round,
                        prev_commit_hash,
                        prev_block_hash,
                        node.block_store()
                            .get_tip_height()
                            .ok()
                            .flatten()
                            .map(|h| h + 1)
                            .unwrap_or(1),
                        &node,
                        node.state_root(),
                        &secret_key,
                    ) {
                        Ok(block) => {
                            let block_hash = block.header.block_hash(chain_id);
                            match node.put_block(&block) {
                                Ok(_) => {
                                    info!(
                                        "✅ 出块成功 height={} hash={} public_txs={} gameturn_txs={} commit_round={}",
                                        block.header.height,
                                        hex::encode(block_hash),
                                        block.public_txs.len(),
                                        block.gameturn_txs.len(),
                                        commit_round
                                    );

                                    let _ = transport.gossip_broadcast(
                                        GossipTopic::DagVertex,
                                        &NetworkMessage::ResponseBlocks(vec![block.clone()]),
                                    );

                                    commit_round += 1;
                                    prev_commit_hash = block
                                        .header
                                        .dag_commit_certificate
                                        .cert_hash(chain_id);
                                    prev_block_hash = block_hash;

                                    // 清空 Dag，只保留当前 vertex
                                    let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                                    *dag_guard = Dag::new();
                                    dag_guard.insert(vertex.clone());
                                }
                                Err(e) => {
                                    error!("put_block 失败：{e}");
                                }
                            }
                        }
                        Err(e) => {
                            error!("build_block_from_vertex 失败：{e}");
                        }
                    }
                }
                Ok(None) => {
                    warn!("detect_commit_leader 返回 None（不应发生）");
                }
                Err(e) => {
                    warn!("detect_commit_leader 错误：{e}");
                }
            }
        }

        last_vertex = Some(vertex);
        round += 1;
    }

    info!("validator 产块循环已停止（共产出 {} 轮 vertex）", round - 1);
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

// ===== test-e2e 子命令 =====

/// 端到端链路测试：构造交易 → 签名 → 提交 → 出块 → 查询验证。
///
/// 在单进程内以 validator 模式打开 Node，完成完整链路测试。
/// 使用独立 data-dir（默认 /tmp/zchain-e2e），不影响正在运行的节点。
fn run_test_e2e(args: &[String]) -> Result<(), String> {
    use secp256k1::{Message, Secp256k1};
    use secp256k1::rand::rngs::OsRng;

    let mut data_dir = PathBuf::from("/tmp/zchain-e2e");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                data_dir = PathBuf::from(args.get(i).ok_or("--data-dir 缺少参数")?);
            }
            "--help" | "-h" => {
                eprintln!("用法: zchain test-e2e [--data-dir <path>]");
                eprintln!("  在单进程内完成 交易构造→签名→提交→出块→查询 的端到端测试。");
                eprintln!("  默认 data-dir: /tmp/zchain-e2e（独立目录，不影响运行中的节点）");
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }

    info!("===== zchain 端到端链路测试 =====");
    info!("data-dir: {}", data_dir.display());

    // 1. 生成 secp256k1 密钥对
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged_pubkey =
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, compressed.to_vec())
            .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    let address: Address = poker_l1::account::derive_address(&tagged_pubkey);
    info!("1. 密钥对生成完成");
    info!("   tagged_pubkey tag=0x{:02x} raw={}B", tagged_pubkey.tag, tagged_pubkey.raw.len());
    info!("   address={}", hex::encode(address));

    // 2. 构造 ValidatorKey 并以 validator 模式打开 Node
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&secret_key.secret_bytes()[..]);
    let vkey = ValidatorKey::from_secret_bytes(sk_bytes)
        .map_err(|e| format!("构造 ValidatorKey 失败：{e}"))?;
    let config = NodeConfig::validator(data_dir.clone(), vkey);
    let node = Node::open(config).map_err(|e| format!("Node::open 失败：{e}"))?;
    info!("2. Validator 节点已打开（chain_id=0x{:08x}）", node.chain_id());

    // 3. 构造交易（Public 通道，空 inputs/outputs，nonce=0）
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: tagged_pubkey.clone(),
        signature: vec![], // 稍后填入
        gas: Gas::zero(),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: node.chain_id(),
        nonce: 0,
        gameturn_nonce: None,
        is_fallback: false,
    };

    // 4. 计算签名哈希并签名
    let signing_hash = tx.signing_hash();
    let msg = Message::from_digest(signing_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let (recovery_id, compact) = sig.serialize_compact();
    let v = recovery_id.to_i32() as u8;
    let mut full_sig = compact.to_vec();
    full_sig.push(v);
    let mut tx = tx;
    tx.signature = full_sig;
    let tx_hash = tx.tx_hash();
    info!("3. 交易构造与签名完成");
    info!("   tx_hash={}", hex::encode(tx_hash));
    info!("   lane=Public nonce=0 inputs=0 outputs=0 sig={}B", tx.signature.len());

    // 5. 提交交易到 Node
    let returned_hash = node
        .submit_tx(tx.clone())
        .map_err(|e| format!("submit_tx 失败：{e}"))?;
    if returned_hash != tx_hash {
        return Err(format!(
            "tx_hash 不匹配: expected {} got {}",
            hex::encode(tx_hash),
            hex::encode(returned_hash)
        ));
    }
    info!("4. 交易提交成功（tx_hash 匹配）");

    // 6. drain pending_tx（validator 应缓冲了交易）
    let pending = node.drain_pending_tx();
    info!("5. drain_pending_tx: {} 笔交易", pending.len());
    if pending.is_empty() {
        return Err("validator 未缓冲交易，pending_tx 为空".to_string());
    }
    if pending[0].tx_hash() != tx_hash {
        return Err("pending_tx 中的交易 hash 不匹配".to_string());
    }

    // 7. 获取当前 tip
    let tip_height = node
        .block_store()
        .get_tip_height()
        .map_err(|e| format!("get_tip_height 失败：{e}"))?;
    let tip_hash = node
        .block_store()
        .get_tip_hash()
        .map_err(|e| format!("get_tip_hash 失败：{e}"))?;
    let (block_height, prev_hash) = match (tip_height, tip_hash) {
        (Some(h), Some(hh)) => (h + 1, hh),
        _ => (1, [0u8; 32]),
    };
    info!(
        "6. 当前 tip: height={:?} → 新区块 height={}",
        tip_height, block_height
    );

    // 8. 构造区块（包含提交的交易）
    let public_txs = vec![pending[0].clone()];
    let public_tx_root = compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = compute_tx_merkle_root(&[]);
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let cert = DagCommitCertificate {
        epoch: 1,
        commit_round: 1,
        prev_commit_hash: [0u8; 32],
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0xFF],
        state_root: [0u8; 32],
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![vec![0u8; 65]],
        signer_bitmap: vec![0xFF],
    };
    let header = BlockHeader {
        height: block_height,
        timestamp_ms,
        prev_hash,
        state_root: [0u8; 32],
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };
    let block = Block::new(header, public_txs, vec![]);
    let block_hash = block.header.block_hash(node.chain_id());
    info!("7. 区块构造完成");
    info!("   height={} block_hash={}", block_height, hex::encode(block_hash));
    info!("   public_txs=1 gameturn_txs=0");

    // 9. 写入区块
    let put_hash = node
        .put_block(&block)
        .map_err(|e| format!("put_block 失败：{e}"))?;
    if put_hash != block_hash {
        return Err(format!(
            "block_hash 不匹配: expected {} got {}",
            hex::encode(block_hash),
            hex::encode(put_hash)
        ));
    }
    info!("8. 区块写入成功（block_hash 匹配）");

    // 10. 查询验证
    let fetched_block = node
        .get_block_by_height(block_height)
        .map_err(|e| format!("get_block_by_height 失败：{e}"))?
        .ok_or("查询区块返回 None")?;
    if fetched_block.header.block_hash(node.chain_id()) != block_hash {
        return Err("查询到的区块 hash 不匹配".to_string());
    }
    if fetched_block.public_txs.len() != 1 {
        return Err(format!(
            "区块中交易数不匹配: expected 1 got {}",
            fetched_block.public_txs.len()
        ));
    }
    if fetched_block.public_txs[0].tx_hash() != tx_hash {
        return Err("区块中交易 hash 不匹配".to_string());
    }
    info!("9. 区块查询验证通过（height/hash/tx 均匹配）");

    let fetched_tx = node
        .get_tx(&tx_hash)
        .map_err(|e| format!("get_tx 失败：{e}"))?
        .ok_or("查询交易返回 None")?;
    if fetched_tx.tx_hash() != tx_hash {
        return Err("查询到的交易 hash 不匹配".to_string());
    }
    info!("10. 交易查询验证通过（tx_hash 匹配）");

    // 11. 验证 tip 已更新
    let new_tip_height = node
        .block_store()
        .get_tip_height()
        .map_err(|e| format!("get_tip_height 失败：{e}"))?;
    let new_tip_hash = node
        .block_store()
        .get_tip_hash()
        .map_err(|e| format!("get_tip_hash 失败：{e}"))?;
    if new_tip_height != Some(block_height) {
        return Err(format!(
            "tip_height 未更新: expected {} got {:?}",
            block_height, new_tip_height
        ));
    }
    if new_tip_hash != Some(block_hash) {
        return Err(format!(
            "tip_hash 未更新: expected {} got {:?}",
            hex::encode(block_hash),
            new_tip_hash.map(hex::encode)
        ));
    }
    info!("11. tip 已更新: height={} hash={}", block_height, hex::encode(block_hash));

    info!("===== 端到端链路测试全部通过 =====");
    info!("  密钥生成 → 交易构造 → 签名 → 提交 → 缓冲 → 出块 → 写入 → 查询 → tip 更新");
    println!("\n✅ E2E 测试通过: block#{} 包含 1 笔交易, tx_hash={}", block_height, hex::encode(tx_hash));
    Ok(())
}
