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
//! - validator 角色需提供 32 字节 secp256k1 私钥（hex 编码）
//!
//! 用法示例：
//! ```text
//! zchain keygen --scheme secp256k1
//! zchain node --role full --data-dir ./data --rpc-listen 127.0.0.1:8545
//! zchain node --role validator --data-dir ./data --validator-key <hex>
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use poker_l1::node::{Node, NodeConfig, NodeRole, NodeRpcBackend, ValidatorKey};
use poker_l1::rpc::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcHandler};
use poker_l1::signature::tagged_pubkey::SignatureScheme;

/// 程序版本。
const VERSION: &str = "0.1.0";

/// 程序入口。
fn main() {
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
                eprintln!("[ERROR] node 启动失败：{}", e);
                std::process::exit(1);
            }
        }
        "keygen" => {
            if let Err(e) = run_keygen(rest) {
                eprintln!("[ERROR] keygen 失败：{}", e);
                std::process::exit(1);
            }
        }
        "version" | "--version" | "-V" => {
            println!("zchain {}", VERSION);
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        other => {
            eprintln!("未知子命令：{}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

/// 打印用法。
fn print_usage() {
    eprintln!("zchain {} — Poker L1 节点二进制", VERSION);
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
    eprintln!("  --validator-key <hex>                   validator 私钥（32B hex，仅 validator 角色）");
    eprintln!();
    eprintln!("`keygen` 选项：");
    eprintln!("  --scheme <secp256k1|ed25519>            签名方案（默认 secp256k1）");
    eprintln!();
    eprintln!("示例：");
    eprintln!("  zchain keygen --scheme secp256k1");
    eprintln!("  zchain node --role full --data-dir ./data");
    eprintln!("  zchain node --role validator --validator-key <hex>");
}

// ===== node 子命令 =====

/// 启动节点。
fn run_node(args: &[String]) -> Result<(), String> {
    let mut role: NodeRole = NodeRole::Full;
    let mut data_dir = PathBuf::from("./data");
    let mut rpc_listen = "127.0.0.1:8545".to_string();
    let mut p2p_listen = "127.0.0.1:9000".to_string();
    let mut validator_key_hex: Option<String> = None;

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
                    other => return Err(format!("未知 role：{}（应为 validator/full/archive/light）", other)),
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
            "--validator-key" => {
                i += 1;
                validator_key_hex = Some(args.get(i).ok_or("--validator-key 缺少参数")?.clone());
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("未知参数：{}", other)),
        }
        i += 1;
    }

    // 构建 NodeConfig
    let mut config = match role {
        NodeRole::Validator => {
            let key_hex = validator_key_hex
                .ok_or("validator 角色必须提供 --validator-key <hex>（32 字节 secp256k1 私钥）")?;
            let key_bytes = hex::decode(key_hex.trim()).map_err(|e| format!("私钥 hex 解码失败：{}", e))?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "validator 私钥必须为 32 字节，得到 {} 字节",
                    key_bytes.len()
                ));
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&key_bytes);
            let vkey = ValidatorKey::from_secret_bytes(sk).map_err(|e| format!("私钥无效：{}", e))?;
            NodeConfig::validator(data_dir.clone(), vkey)
        }
        NodeRole::Full => NodeConfig::default_full(data_dir.clone()),
        NodeRole::Archive => NodeConfig::archive(data_dir.clone()),
        NodeRole::Light => NodeConfig::light(data_dir.clone()),
    };
    config.rpc_listen = rpc_listen.clone();
    config.p2p_listen = p2p_listen.clone();

    // 打印启动信息
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║  zchain {} — Poker L1 节点启动中                          ║", VERSION);
    eprintln!("╠══════════════════════════════════════════════════════════╣");
    eprintln!("║  role        : {:?}", role);
    eprintln!("║  chain_id    : 0x{:08X}", config.chain_id);
    eprintln!("║  data_dir    : {}", config.data_dir.display());
    eprintln!("║  rpc_listen  : {}", config.rpc_listen);
    eprintln!("║  p2p_listen  : {}", config.p2p_listen);
    if role.is_validator()
        && let Some(vk) = &config.validator_key
    {
        eprintln!("║  validator   : {}", hex::encode(&vk.tagged_pubkey.raw));
    }
    eprintln!("╚══════════════════════════════════════════════════════════╝");

    // 打开节点
    let node = Node::open(config).map_err(|e| format!("Node::open 失败：{}", e))?;
    let node_arc = Arc::new(node);
    let backend = Arc::new(NodeRpcBackend::new(node_arc));

    // 绑定 TCP listener
    let listener = TcpListener::bind(&rpc_listen)
        .map_err(|e| format!("RPC 监听绑定 {} 失败：{}", rpc_listen, e))?;
    eprintln!("[INFO] JSON-RPC server 监听 {}（newline-delimited TCP）", rpc_listen);
    eprintln!("[INFO] 按 Ctrl+C 退出");

    // 接受连接循环（scoped threads 共享 &backend）
    std::thread::scope(|s| {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[WARN] accept 失败：{}", e);
                    continue;
                }
            };
            let peer = stream.peer_addr().ok();
            let backend_clone = Arc::clone(&backend);
            s.spawn(move || {
                if let Err(e) = handle_connection(stream, &backend_clone) {
                    eprintln!("[WARN] 连接处理错误（peer={:?}）：{}", peer, e);
                }
            });
        }
    });

    Ok(())
}

/// 处理单条 TCP 连接（newline-delimited JSON-RPC）。
fn handle_connection(
    stream: std::net::TcpStream,
    backend: &NodeRpcBackend,
) -> Result<(), String> {
    let handler = RpcHandler::new(backend);
    // TcpStream 在 BufReader / 写引用之间拆分
    let reader_stream = stream.try_clone().map_err(|e| e.to_string())?;
    let reader = BufReader::new(reader_stream);
    let mut writer = stream;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => return Err(format!("读取行失败：{}", e)),
        };
        if line.trim().is_empty() {
            continue;
        }
        // 解析 JSON-RPC 请求
        let resp: JsonRpcResponse = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(req) => handler.handle(&req),
            Err(e) => JsonRpcResponse::error(
                JsonRpcError::new(JsonRpcError::PARSE_ERROR, format!("parse error: {}", e)),
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
                    other => return Err(format!("未知 scheme：{}（应为 secp256k1 / ed25519）", other)),
                };
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("未知参数：{}", other)),
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
    println!("{}", serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?);
    Ok(())
}
