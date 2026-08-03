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

use poker_l1::account::derive_address;
use poker_l1::block::validator::{validate_tx_chain_id, validate_tx_nonce, validate_tx_signature};
use poker_l1::block::{Block, BlockHeader, compute_tx_merkle_root};
use poker_l1::consensus::{
    Dag, DagCommitCertificate, DagVertex, MAX_VERTEX_SIZE, VertexBuilder, detect_commit_leader,
    required_quorum, assemble_commit_certificate,
};
use poker_l1::error::PokerL1Result;
use poker_l1::network::{CommitVote, GossipTopic, NetworkMessage, NetworkTransport, PeerInfo};
use poker_l1::node::{Node, NodeConfig, NodeRole, NodeRpcBackend, ValidatorKey};
use poker_l1::rpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcClientInfo, RpcGuard, RpcHandler,
};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey, verify_signature};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane, validate_tx_limits};
use poker_l1::{Address, Hash};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use std::collections::BTreeSet;

mod poker_demo;

/// 程序版本。
const VERSION: &str = "0.1.0";

/// 默认最大并发连接数。
const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// 优雅关闭轮询间隔（accept non-blocking 后 sleep）。
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Deterministic logical-time increment used for a committed block.
///
/// Header time is a soft reference, but it is part of the execution environment.  Validators
/// must therefore never derive it independently from wall-clock time while signing the same
/// certificate; doing so can produce distinct state roots for a single DAG leader.
const CONSENSUS_TIMESTAMP_STEP_MS: u64 = 1_000;

/// Bound a vertex range response by both rounds scanned and vertices returned.
const MAX_VERTEX_RANGE_ROUNDS: u64 = 512;
const MAX_VERTEX_RANGE_RESPONSE: usize = 512;

/// Derive the execution timestamp from already-finalized chain state rather than the local clock.
///
/// This preserves the header's monotonic soft-time invariant and is identical for every validator
/// which has the same parent.  The genesis fallback is also deterministic for integration tests
/// and a freshly initialized chain.
fn consensus_block_timestamp(node: &Node, height: u64) -> Result<u64, String> {
    let previous = height
        .checked_sub(1)
        .and_then(|previous_height| {
            node.block_store()
                .get_by_height(previous_height)
                .ok()
                .map(|block| block.header.timestamp_ms)
        });
    match previous {
        Some(timestamp) => timestamp
            .checked_add(CONSENSUS_TIMESTAMP_STEP_MS)
            .ok_or_else(|| "block timestamp overflow".to_string()),
        None => height
            .checked_mul(CONSENSUS_TIMESTAMP_STEP_MS)
            .ok_or_else(|| "genesis block timestamp overflow".to_string()),
    }
}

fn open_node_with_application_verifiers(config: NodeConfig) -> PokerL1Result<Node> {
    // The standard binary deliberately does not expose the experimental zkVM recursive verifier.
    // Texas proof work continues through the custom AIR/proving-service path until the recursive
    // verifier has its own completed soundness review and an explicit re-enable decision.
    Node::open(config)
}

/// commit certificate 投票累加器（缺口 #3：多 validator 2/3 多签闭环）。
///
/// 跨线程共享（P2P handler 写入收集到的 peer 投票，validator loop 读取凑 quorum）。
/// 按 `(epoch, commit_round, cert_signing_hash)` 索引收集投票；validator loop 凑齐
/// ≥2/3 后用 [`poker_l1::consensus::bullshark::assemble_commit_certificate`] 组装 cert。
#[derive(Debug, Default)]
struct VoteCollector {
    /// key = (epoch, commit_round, cert_signing_hash) → 去重的投票列表。
    votes: std::sync::Mutex<Vec<CommitVote>>,
}

impl VoteCollector {
    fn new() -> Self {
        Self {
            votes: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// 收集一笔投票（去重：同一 signer_pubkey 对同一 cert_signing_hash 仅计一次）。
    fn add_vote(&self, vote: CommitVote) {
        let mut votes = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        let exists = votes.iter().any(|v| {
            v.signer_pubkey == vote.signer_pubkey
                && v.cert_signing_hash == vote.cert_signing_hash
        });
        if !exists {
            votes.push(vote);
        }
    }

    /// 取出针对指定 cert_signing_hash 的全部已收集投票（清空该 key 对应的投票）。
    fn drain_for_hash(&self, cert_signing_hash: &poker_l1::Hash) -> Vec<CommitVote> {
        let mut votes = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        let (matched, rest): (Vec<_>, Vec<_>) =
            votes.drain(..).partition(|v| v.cert_signing_hash == *cert_signing_hash);
        *votes = rest;
        matched
    }

    /// 非破坏性地查看针对指定 cert_signing_hash 的全部已收集投票（缺口 #3 活性修复）。
    ///
    /// 与 [`drain_for_hash`] 的区别：不删除投票，供跨轮次重试 commit（投票可能跨进程
    /// 延迟到达，须保留直到成功组装 cert 后才 drain）。
    fn peek_for_hash(&self, cert_signing_hash: &poker_l1::Hash) -> Vec<CommitVote> {
        let votes = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        votes
            .iter()
            .filter(|v| v.cert_signing_hash == *cert_signing_hash)
            .cloned()
            .collect()
    }
}


/// 程序入口。
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    let subcommand = args[1].as_str();
    let rest = &args[2..];

    // poker-demo 自带 tracing 双写初始化（stderr + 文件），跳过全局 init
    if subcommand != "poker-demo" {
        // 初始化 tracing：默认 INFO 级别，可通过 RUST_LOG 环境变量覆盖
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }
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
    eprintln!("  --block-interval-ms <ms>                出块间隔毫秒（默认 1000，仅 validator）");
    eprintln!(
        "  --peer <addr>                           P2P peer 地址（可重复，如 127.0.0.1:9001）"
    );
    eprintln!(
        "  --genesis-validators <file>             genesis validator set JSON 文件（多 validator 共识所需，所有节点须一致）"
    );
    eprintln!(
        "  --vrf-key-file <path>                   VRF 私钥文件（32B hex，ECVRF-secp256k1，用于 epoch_randomness）"
    );
    eprintln!(
        "  --genesis-alloc <file>                  genesis 余额分配 JSON（初始代币发行，[{{pubkey_hex, balance}}]）"
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

/// genesis validator JSON 条目（缺口 #3：`--genesis-validators` 文件格式）。
#[derive(serde::Deserialize)]
struct GenesisValidatorEntry {
    /// secp256k1 pubkey（33 字节 compressed，hex）。
    pubkey_hex: String,
    /// VRF pubkey（33 字节 compressed，hex）。
    vrf_pubkey_hex: String,
    /// 质押金额。
    stake: u64,
}

/// 从 JSON 文件加载 genesis validator set（缺口 #3）。
///
/// 文件格式：`[{"pubkey_hex": "..", "vrf_pubkey_hex": "..", "stake": N}, ...]`。
/// 所有节点须用相同文件（signer_bitmap index 基准 = `active_validator_pubkeys_sorted()`）。
fn load_genesis_validators(path: &std::path::Path) -> Result<Vec<poker_l1::consensus::ValidatorEntry>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取 genesis validators 文件失败：{e}"))?;
    let entries: Vec<GenesisValidatorEntry> = serde_json::from_str(&content)
        .map_err(|e| format!("解析 genesis validators JSON 失败：{e}"))?;
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let pubkey_bytes = hex::decode(&e.pubkey_hex)
            .map_err(|e| format!("validator#{i} pubkey_hex 解码失败：{e}"))?;
        let tagged = poker_l1::signature::TaggedPubkey::new(
            poker_l1::signature::SignatureScheme::Secp256k1,
            poker_l1::signature::CURRENT_VERSION,
            pubkey_bytes,
        )
        .map_err(|e| format!("validator#{i} TaggedPubkey 构造失败：{e}"))?;
        let vrf_pubkey_bytes = hex::decode(&e.vrf_pubkey_hex)
            .map_err(|e| format!("validator#{i} vrf_pubkey_hex 解码失败：{e}"))?;
        if vrf_pubkey_bytes.len() != 33 {
            return Err(format!(
                "validator#{i} vrf_pubkey 必须为 33 字节，得到 {}",
                vrf_pubkey_bytes.len()
            ));
        }
        let mut vrf_pk = [0u8; 33];
        vrf_pk.copy_from_slice(&vrf_pubkey_bytes);
        // 缺口 #3：genesis validator 立即 Active（无 bonding 期），使其能参与共识。
        // ValidatorEntry::new 默认 Bonding，此处转为 Active。
        let mut entry =
            poker_l1::consensus::ValidatorEntry::new(tagged, vrf_pk, e.stake, 0);
        entry.status = poker_l1::consensus::ValidatorStatus::Active;
        out.push(entry);
    }
    Ok(out)
}

/// genesis 余额分配 JSON 条目（缺口 #4-M1：`--genesis-alloc` 文件格式）。
#[derive(serde::Deserialize)]
struct GenesisAllocEntry {
    /// secp256k1 pubkey（33 字节 compressed，hex）。
    pubkey_hex: String,
    /// 初始余额。
    balance: u64,
}

/// 从 JSON 文件加载 genesis 余额分配（缺口 #4-M1）。
///
/// 文件格式：`[{"pubkey_hex": "..", "balance": N}, ...]`。
/// 返回 `(TaggedPubkey, balance)` 列表供 [`Node::apply_genesis_alloc`] 应用。
fn load_genesis_alloc(
    path: &std::path::Path,
) -> Result<Vec<(poker_l1::signature::TaggedPubkey, u64)>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取 genesis alloc 文件失败：{e}"))?;
    let entries: Vec<GenesisAllocEntry> = serde_json::from_str(&content)
        .map_err(|e| format!("解析 genesis alloc JSON 失败：{e}"))?;
    let mut out = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        let pubkey_bytes = hex::decode(&e.pubkey_hex)
            .map_err(|err| format!("alloc#{i} pubkey_hex 解码失败：{err}"))?;
        let tagged = poker_l1::signature::TaggedPubkey::new(
            poker_l1::signature::SignatureScheme::Secp256k1,
            poker_l1::signature::CURRENT_VERSION,
            pubkey_bytes,
        )
        .map_err(|err| format!("alloc#{i} TaggedPubkey 构造失败：{err}"))?;
        out.push((tagged, e.balance));
    }
    Ok(out)
}

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
    // 缺口 #3：genesis validator set 文件（多 validator 共识所需，所有节点须一致）。
    let mut genesis_validators_file: Option<PathBuf> = None;
    // 缺口 #3 §3.6：VRF 私钥文件（32B hex，ECVRF-secp256k1，用于 epoch_randomness 派生）。
    let mut vrf_key_file: Option<PathBuf> = None;
    // 缺口 #4-M1：genesis 余额分配文件（初始代币发行）。
    let mut genesis_alloc_file: Option<PathBuf> = None;

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
            "--genesis-validators" => {
                i += 1;
                genesis_validators_file = Some(PathBuf::from(
                    args.get(i).ok_or("--genesis-validators 缺少参数")?,
                ));
            }
            "--vrf-key-file" => {
                i += 1;
                vrf_key_file = Some(PathBuf::from(
                    args.get(i).ok_or("--vrf-key-file 缺少参数")?,
                ));
            }
            "--genesis-alloc" => {
                i += 1;
                genesis_alloc_file = Some(PathBuf::from(
                    args.get(i).ok_or("--genesis-alloc 缺少参数")?,
                ));
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
            // 缺口 #3 §3.6：加载 VRF 私钥（可选，用于 epoch_randomness 真实 ECVRF 派生）。
            let vkey = if let Some(vrf_path) = &vrf_key_file {
                let vrf_hex = std::fs::read_to_string(vrf_path)
                    .map_err(|e| format!("读取 vrf-key-file {} 失败：{e}", vrf_path.display()))?;
                let mut vrf_bytes = hex::decode(vrf_hex.trim())
                    .map_err(|e| format!("VRF 私钥 hex 解码失败：{e}"))?;
                if vrf_bytes.len() != 32 {
                    return Err(format!(
                        "VRF 私钥必须为 32 字节，得到 {} 字节",
                        vrf_bytes.len()
                    ));
                }
                let mut vrf_sk = [0u8; 32];
                vrf_sk.copy_from_slice(&vrf_bytes);
                vrf_bytes.fill(0);
                info!("已加载 VRF 私钥（用于 epoch_randomness ECVRF 派生）");
                vkey.with_vrf_secret(vrf_sk)
            } else {
                warn!("未配置 VRF 私钥（--vrf-key-file），epoch_randomness 将走 fallback");
                vkey
            };
            NodeConfig::validator(data_dir.clone(), vkey)
        }
        NodeRole::Full => NodeConfig::default_full(data_dir.clone()),
        NodeRole::Archive => NodeConfig::archive(data_dir.clone()),
        NodeRole::Light => NodeConfig::light(data_dir.clone()),
    };
    config.rpc_listen = rpc_listen.clone();
    config.p2p_listen = p2p_listen.clone();
    // 缺口 #3：加载 genesis validator set（多 validator 共识的 signer_bitmap index 基准）。
    if let Some(gv_path) = &genesis_validators_file {
        let entries = load_genesis_validators(gv_path)?;
        info!("已加载 {} 个 genesis validator", entries.len());
        config = config.with_genesis_validators(entries);
    }

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
    let node = open_node_with_application_verifiers(config)
        .map_err(|e| format!("Node::open 失败：{e}"))?;
    // Apply the canonical native-coin genesis allocation (idempotent across restarts).
    if let Some(alloc_path) = &genesis_alloc_file {
        let allocs = load_genesis_alloc(alloc_path)?;
        let created = node
            .apply_genesis_alloc(allocs)
            .map_err(|e| format!("genesis alloc 应用失败：{e}"))?;
        info!("已应用 genesis UTXO 分配：新铸 {} 个 coin outputs", created);
    }
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

    // 缺口 #3：共享的 DAG + 投票累加器（P2P handler 与 validator loop 跨线程共享）。
    // peer vertex 经 handle_p2p_connection 写入此 Dag（+ node.vertex_store），
    // validator loop 从此 Dag 调 detect_commit_leader；否则 quorum 永远无法凑齐。
    let shared_dag: Arc<Mutex<Dag>> = Arc::new(Mutex::new(Dag::new()));
    let vote_collector: Arc<VoteCollector> = Arc::new(VoteCollector::new());

    // === P2P accept loop 线程 ===
    let p2p_node = Arc::clone(&node_arc);
    let p2p_transport = Arc::clone(&transport);
    let p2p_shutdown = Arc::clone(&shutdown_flag);
    let p2p_dag = Arc::clone(&shared_dag);
    let p2p_votes = Arc::clone(&vote_collector);
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
                        let dag = Arc::clone(&p2p_dag);
                        let votes = Arc::clone(&p2p_votes);
                        std::thread::spawn(move || {
                            handle_p2p_connection(stream, node, transport, dag, votes);
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
        // 缺口 #3：复用 shared_dag（与 P2P handler 共享，使 peer vertex 进入此 Dag）。
        let dag = Arc::clone(&shared_dag);
        let votes = Arc::clone(&vote_collector);
        let v_transport = Arc::clone(&transport);
        let v_shutdown = Arc::clone(&shutdown_flag);
        let v_node = Arc::clone(&node_arc);
        let interval = Duration::from_millis(block_interval_ms);
        Some(
            std::thread::Builder::new()
                .name("validator-loop".to_string())
                .spawn(move || {
                    run_validator_loop(
                        v_node,
                        vkey,
                        chain_id,
                        dag,
                        votes,
                        v_transport,
                        interval,
                        v_shutdown,
                    );
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

    /// 缺口 #5：Peer Exchange（PEX）—— 广播本节点已知 peer 列表给所有已连接 peer。
    fn broadcast_peer_exchange(&self) -> Result<(), String> {
        let peers: Vec<PeerInfo> = self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if peers.is_empty() {
            return Ok(());
        }
        self.gossip_broadcast(
            GossipTopic::DagVertex,
            &NetworkMessage::PeerExchange(peers),
        )
        .map_err(|e| e.to_string())
    }

    /// 缺口 #5：合并 PEX 发现的新 peer 地址（去重）。
    fn merge_discovered_peers(&self, new_peers: &[PeerInfo]) {
        let mut addrs = self.peer_addrs.lock().unwrap_or_else(|e| e.into_inner());
        for peer in new_peers {
            if !addrs.iter().any(|p| p.address == peer.address) {
                addrs.push(peer.clone());
            }
        }
    }
}

impl NetworkTransport for TcpTransport {
    fn gossip_broadcast(&self, _topic: GossipTopic, message: &NetworkMessage) -> PokerL1Result<()> {
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
        send_p2p_message(&mut stream, message)
            .map_err(|e| poker_l1::error::PokerL1Error::Other(format!("send_to: 发送失败：{e}")))?;
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

    fn subscribe_light_headers(&self) -> PokerL1Result<Vec<poker_l1::network::LightClientHeader>> {
        // 返回 Node 缓存的 LightClientHeader（validator 多签背书）。
        // TcpTransport 不直接持有 header 缓存——此方法在 handle_p2p_connection 中
        // 通过 node.get_light_headers() 获取。
        // 注意：NetworkTransport trait 方法无法访问 Node，故此处返回空；
        // 实际 light header 分发经 P2P handler 的 NetworkMessage::LightClientHeader。
        Ok(Vec::new())
    }
}

/// 向 peer 发送请求并接收响应（临时连接，含超时）。
///
/// 用于 `request_blocks_by_range` / `request_vertices_by_range` 等请求-响应协议。
/// 创建独立连接以避免与持久 P2P 读取循环冲突。
fn send_request_and_recv(peer_addr: &str, req: &NetworkMessage) -> Result<NetworkMessage, String> {
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
    dag: Arc<Mutex<Dag>>,
    votes: Arc<VoteCollector>,
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
    // 缺口 #3 活性修复：把入站连接的 stream clone 加入广播列表，使本节点能通过
    // 此连接向对方广播（双向通信）。此前入站连接只能读不能写 → 对方收不到本节点的
    // vertex/vote，多 validator 共识无法形成。
    if let Ok(write_stream) = stream.try_clone() {
        transport.add_peer(write_stream);
    }
    loop {
        match recv_p2p_message(&mut stream) {
            Ok(Some(msg)) => {
                match msg {
                    NetworkMessage::DagVertex(vertex) => {
                        // 缺口 #3：peer vertex 同时写入共享 Dag（供 detect_commit_leader）
                        // 与 node.vertex_store（持久化）。
                        {
                            let mut dag_guard =
                                dag.lock().unwrap_or_else(|e| e.into_inner());
                            dag_guard.insert(vertex.clone());
                        }
                        if let Err(e) = node.put_vertex(&vertex) {
                            warn!("P2P put_vertex 失败：{e}");
                        }
                    }
                    NetworkMessage::CommitVote(vote) => {
                        // A vote is useful only if its signer is an active validator and its
                        // signature is valid for this exact certificate statement.  Otherwise an
                        // attacker could fill the collector with junk that later consumes a
                        // quorum attempt and causes valid votes to be discarded.
                        let active_validators = node.active_validator_pubkeys_sorted();
                        if !active_validators.iter().any(|pk| pk == &vote.signer_pubkey) {
                            warn!("P2P commit vote rejected: signer is not an active validator");
                            continue;
                        }
                        if !matches!(
                            vote.signer_pubkey.scheme(),
                            Ok(SignatureScheme::Secp256k1)
                        )
                            || verify_signature(
                                &vote.signer_pubkey,
                                &vote.signature,
                                &vote.cert_signing_hash,
                            )
                            .is_err()
                        {
                            warn!("P2P commit vote rejected: invalid secp256k1 signature");
                            continue;
                        }
                        votes.add_vote(vote);
                    }
                    NetworkMessage::PeerExchange(peers) => {
                        // 缺口 #5：Peer Discovery / PEX —— 合并发现的 peer。
                        transport.merge_discovered_peers(&peers);
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
                        if tx.lane_hint != TxLane::GameTurn {
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
                            {
                                let mut dag_guard =
                                    dag.lock().unwrap_or_else(|e| e.into_inner());
                                dag_guard.insert(vertex.clone());
                            }
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
                    NetworkMessage::RequestVerticesByRange(start_round, end_round) => {
                        let vertices = collect_vertices_by_round(&dag, start_round, end_round);
                        if let Err(e) = send_p2p_message(
                            &mut stream,
                            &NetworkMessage::ResponseVertices(vertices),
                        ) {
                            warn!("P2P 回送 ResponseVertices 失败：{e}");
                        }
                    }
                    NetworkMessage::CompactVertex(compact) => {
                        // 简化：compact vertex 需要从本地 tx_cache 重建，暂不支持
                        let _ = compact;
                        debug!("收到 CompactVertex（暂不支持重建）");
                    }
                    NetworkMessage::LightClientHeader(header) => {
                        // 收到 peer 的 light client header（validator 多签背书），
                        // 合并到本地缓存（多 validator 签名合并）。
                        node.merge_light_header(header);
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

/// Collect the current DAG's full vertices for an inclusive round range.
///
/// `RequestVerticesByRange` has no epoch field.  The in-memory DAG is intentionally scoped to
/// the active epoch and is reset after commit, so it is the authoritative answer for this wire
/// request.  A bounded scan prevents a peer from turning a sparse, enormous range into CPU work.
fn collect_vertices_by_round(dag: &Arc<Mutex<Dag>>, start_round: u64, end_round: u64) -> Vec<DagVertex> {
    if start_round > end_round {
        return Vec::new();
    }
    let capped_end = end_round.min(start_round.saturating_add(MAX_VERTEX_RANGE_ROUNDS - 1));
    let dag = dag.lock().unwrap_or_else(|e| e.into_inner());
    let mut vertices = Vec::new();
    for round in start_round..=capped_end {
        for hash in dag.round_vertices(round) {
            if let Some(vertex) = dag.get(hash) {
                vertices.push(vertex.clone());
                if vertices.len() == MAX_VERTEX_RANGE_RESPONSE {
                    return vertices;
                }
            }
        }
    }
    vertices
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

/// 把待出 vertex 的 tx 列表切分为多个不超 `max_size` 的 batch。
///
/// 修复一个活性/数据丢失 bug：原先 `drain_pending_tx()` 取出的 tx 一次性塞进单个
/// `VertexBuilder`，若累计体积超过 `MAX_VERTEX_SIZE`，`validate_size()` 失败后直接
/// `continue` —— 由于 tx 已从 `pending_tx` 中 `drain(..)` 移除，整批 tx 被静默丢弃，
/// 既不打包也不回绝客户端。对照 Narwhal（Sui）"超限即切多个 batch、不丢 tx" 的做法，
/// 这里改为按精确 BCS 体积累计切片。
///
/// 切片规则（贪心，保持 arrival 顺序）：
/// - 逐笔累加 `tx.to_bcs()` 体积；加入后若超过 `max_size`，封包当前 batch，该 tx 开启新 batch。
/// - 单笔 tx 自身序列化体积 > `max_size`（异常：`submit_tx` 的 `validate_tx_limits`
///   本应早已拦截）→ 单独成 batch，返回时由调用方 `validate_size`/`put_vertex` 再次拒绝，
///   记日志后跳过该笔，**不影响其余 tx**。
///
/// `max_size` 取 `MAX_VERTEX_SIZE`，已包含 vertex 头部与 parent_hashes 的余量预算
/// （`VertexBuilder::estimate_size` 中 epoch+round+pubkey+parents 约 100B 量级，
/// 相对 256KB 上限可忽略；切片仅按 tx 体积累加，留出头部空间由 `validate_size` 兜底）。
///
/// 参数：
/// - `txs`：drain 出的待出 tx（按 arrival 顺序）
/// - `max_size`：单 vertex 字节上限（应等于 `MAX_VERTEX_SIZE`）
///
/// 返回非空 batch 列表；输入为空时返回空 `Vec`（由调用方决定是否产出空 vertex）。
fn split_txs_into_batches(txs: Vec<Transaction>, max_size: usize) -> Vec<Vec<Transaction>> {
    // 为 vertex 头部（epoch+round+pubkey+parent_hashes len+author_sig）预留预算，
    // 使切片结果更贴近实际 vertex 序列化体积，减少 put_vertex 处的二次拒绝。
    // 取一个保守常量：≈ 1 + 1 + (1+33) + 8 + (8+65) ≈ 120B 量级，向上取 256B。
    const VERTEX_HEADER_BUDGET: usize = 256;

    let limit = max_size.saturating_sub(VERTEX_HEADER_BUDGET);
    let mut batches: Vec<Vec<Transaction>> = Vec::new();
    let mut current: Vec<Transaction> = Vec::new();
    let mut current_size: usize = 0;

    for tx in txs {
        let tx_size = tx.to_bcs().map(|b| b.len()).unwrap_or(usize::MAX);

        if !current.is_empty() && current_size.saturating_add(tx_size) > limit {
            // 当前 batch 装不下这笔 tx → 封包
            batches.push(std::mem::take(&mut current));
            current_size = 0;
        }

        // 单笔超限（tx_size > limit）：单独成 batch，后续 validate_size/put_vertex 拒绝并记日志。
        current.push(tx);
        current_size = current_size.saturating_add(tx_size);
    }

    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// 计算待出块 commit certificate 的 `signing_hash`（缺口 #3：多 validator 投票对象）。
///
/// 确定性执行 prev_vertex 的 txs 得到 state_root，按与 [`build_block_from_vertex`]
/// 完全一致的 cert 字段构造一个**不含签名**的 cert 模板，返回其 `signing_hash`。
/// 各 validator 对同一 (prev_vertex, epoch, commit_round, prev_commit_hash, state) 得到
/// 相同的 signing_hash → 可对其签名并互验（CommitVote）。
///
/// 注意：state_root 由确定性执行得出，所有诚实 validator 对相同输入得到相同结果。
fn compute_cert_signing_hash(
    vertex: &DagVertex,
    chain_id: poker_l1::ChainId,
    epoch: u64,
    commit_round: u64,
    prev_commit_hash: Hash,
    node: &Node,
    height: u64,
) -> Result<Hash, String> {
    let sorted_txs = poker_l1::consensus::sort_vertex_txs_s9(vertex.tx_list.clone());
    let mut public_txs = Vec::new();
    let mut gameturn_txs = Vec::new();
    for tx in &sorted_txs {
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn_txs.push(tx.clone()),
            _ => public_txs.push(tx.clone()),
        }
    }
    let timestamp_ms = consensus_block_timestamp(node, height)?;
    let env = node.execution_environment(height, timestamp_ms);
    // 缺口 #4-M1：proposer = vertex author（出块 validator）。
    let env = env.with_proposer(poker_l1::account::derive_address(&vertex.author_pubkey));
    let outcome = node
        .simulate_block_execution(&env, &sorted_txs)
        .map_err(|e| format!("execute_block failed: {e}"))?;
    let public_tx_root = poker_l1::block::compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = poker_l1::block::compute_tx_merkle_root(&gameturn_txs);
    let vertex_hash = vertex.vertex_hash();
    let cert = DagCommitCertificate {
        epoch,
        commit_round,
        prev_commit_hash,
        vertex_hash_list: vec![vertex_hash],
        round_attendance_bitmap: vec![0xFF],
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![],
        signer_bitmap: vec![0x00],
    };
    Ok(cert.signing_hash(chain_id))
}

/// 单 validator 引导期：从 vertex 构造 block、自签 cert、入链、广播、推进状态。
///
/// 封装原 `build_block_from_vertex` + put_block + 广播 + Dag 清空 的流程，
/// 供单 validator 路径复用。
#[allow(clippy::too_many_arguments)]
fn commit_and_finalize_block(
    prev_vertex: &DagVertex,
    node: &Node,
    secret_key: &secp256k1::SecretKey,
    chain_id: poker_l1::ChainId,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    transport: &TcpTransport,
    dag: &Arc<Mutex<Dag>>,
    vertex: &DagVertex,
    commit_round_out: &mut u64,
    prev_commit_hash_out: &mut Hash,
    prev_block_hash_out: &mut Hash,
) {
    match build_block_from_vertex(
        prev_vertex,
        chain_id,
        commit_round,
        prev_commit_hash,
        prev_block_hash,
        height,
        node,
        node.state_root(),
        secret_key,
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
                    *commit_round_out += 1;
                    *prev_commit_hash_out =
                        block.header.dag_commit_certificate.cert_hash(chain_id);
                    *prev_block_hash_out = block_hash;
                    let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                    *dag_guard = Dag::new();
                    dag_guard.insert(vertex.clone());
                }
                Err(e) => error!("put_block 失败：{e}"),
            }
        }
        Err(e) => error!("build_block_from_vertex 失败：{e}"),
    }
}

/// 多 validator：用收集到的 ≥2/3 签名组装 cert，构造 block、入链、广播、推进状态。
#[allow(clippy::too_many_arguments)]
fn commit_and_finalize_block_multi(
    prev_vertex: &DagVertex,
    node: &Node,
    chain_id: poker_l1::ChainId,
    epoch: u64,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    sig_pairs: &[(usize, Vec<u8>)],
    validator_count: usize,
    transport: &TcpTransport,
    dag: &Arc<Mutex<Dag>>,
    vertex: &DagVertex,
    commit_round_out: &mut u64,
    prev_commit_hash_out: &mut Hash,
    prev_block_hash_out: &mut Hash,
) {
    // 确定性执行得到 state_root + tx roots。
    let sorted_txs = poker_l1::consensus::sort_vertex_txs_s9(prev_vertex.tx_list.clone());
    let mut public_txs = Vec::new();
    let mut gameturn_txs = Vec::new();
    for tx in &sorted_txs {
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn_txs.push(tx.clone()),
            _ => public_txs.push(tx.clone()),
        }
    }
    let timestamp_ms = match consensus_block_timestamp(node, height) {
        Ok(timestamp) => timestamp,
        Err(error) => {
            error!("multi: derive deterministic block timestamp failed: {error}");
            return;
        }
    };
    let env = node.execution_environment(height, timestamp_ms);
    // 缺口 #4-M1：proposer = prev_vertex author（leader / 出块 validator）。
    let env = env.with_proposer(poker_l1::account::derive_address(
        &prev_vertex.author_pubkey,
    ));
    let outcome = match node.simulate_block_execution(&env, &sorted_txs) {
        Ok(o) => o,
        Err(e) => {
            error!("multi: execute_block 失败：{e}");
            return;
        }
    };
    let public_tx_root = poker_l1::block::compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = poker_l1::block::compute_tx_merkle_root(&gameturn_txs);
    let vertex_hash = prev_vertex.vertex_hash();
    // 组装含 2/3 多签的 cert。
    let cert = match assemble_commit_certificate(
        epoch,
        commit_round,
        prev_commit_hash,
        vec![vertex_hash],
        vec![0xFF],
        outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        sig_pairs,
        validator_count,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("assemble_commit_certificate 失败：{e}");
            return;
        }
    };
    let header = poker_l1::block::BlockHeader {
        height,
        timestamp_ms,
        prev_hash: prev_block_hash,
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };
    let block = poker_l1::block::Block::new(header, public_txs, gameturn_txs);
    let block_hash = block.header.block_hash(chain_id);
    match node.put_block(&block) {
        Ok(_) => {
            info!(
                "✅ 出块成功(多签 {} 票) height={} hash={} commit_round={}",
                sig_pairs.len(),
                block.header.height,
                hex::encode(block_hash),
                commit_round
            );
            let _ = transport.gossip_broadcast(
                GossipTopic::DagVertex,
                &NetworkMessage::ResponseBlocks(vec![block.clone()]),
            );
            *commit_round_out += 1;
            *prev_commit_hash_out = block.header.dag_commit_certificate.cert_hash(chain_id);
            *prev_block_hash_out = block_hash;
            let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
            *dag_guard = Dag::new();
            dag_guard.insert(vertex.clone());
        }
        Err(e) => error!("multi: put_block 失败：{e}"),
    }
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
    let env = node.execution_environment(height, timestamp_ms);
    let outcome = node
        .simulate_block_execution(&env, &sorted_txs)
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
    votes: Arc<VoteCollector>,
    transport: Arc<TcpTransport>,
    block_interval: Duration,
    shutdown: Arc<AtomicBool>,
) {
    // 缺口 #3 §3.6：提取 VRF 私钥（若配置），用于 epoch_randomness 派生。
    let vrf_secret: Option<[u8; 32]> = validator_key.vrf_secret;
    // 从 ValidatorKey 提取 secp256k1 SecretKey
    let secret_key = match secp256k1::SecretKey::from_slice(&validator_key.secret_key_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            error!("validator 私钥无效：{e}");
            return;
        }
    };
    let author_pubkey = validator_key.tagged_pubkey.clone();

    let mut epoch: u64 = 1;
    let mut round: u64 = 1;
    let mut commit_round: u64 = 1;
    let mut prev_commit_hash: Hash = [0u8; 32];
    let mut prev_block_hash: Hash = [0u8; 32];
    // 存完整 vertex（非仅 hash），以便 commit 时从上一个 vertex 构造 block
    let mut last_vertex: Option<DagVertex> = None;
    // 缺口 #3 §3.6：epoch 推进周期（每 EPOCH_LENGTH 个 commit 推进一次 epoch）。
    const EPOCH_LENGTH: u64 = 10;

    info!(
        "validator 产块循环已启动（混合模式，间隔={}ms，pubkey={})",
        block_interval.as_millis(),
        hex::encode(&author_pubkey.raw)
    );

    while !shutdown.load(Ordering::SeqCst) {
        // 混合模式核心：等待 tx 或超时
        // - 有 tx 时被 submit_tx 的 notify_one 立即唤醒 → 零延迟出 vertex
        // - 超时返回 false → 检查是否需要出空 vertex 推进 commit
        // info!("[validator-loop] round={} 进入 wait_for_pending_tx", round);
        let _has_tx = node.wait_for_pending_tx(block_interval);
        // info!(
        //     "[validator-loop] round={} wait_for_pending_tx 返回 has_tx={}",
        //     round, _has_tx
        // );
        let txs = node.drain_pending_tx();

        if !txs.is_empty() {
            info!(
                "[validator-loop] round={} drained {} tx(s) has_tx={} shutdown={}",
                round,
                txs.len(),
                _has_tx,
                shutdown.load(Ordering::SeqCst)
            );
        }

        // 决定是否产出 vertex：
        // - 有 tx → 立即出 vertex
        // - 无 tx 但上一个 vertex 有未 commit 的 tx → 出空 vertex 推进 commit
        // - 缺口 #3 多 validator 活性：无 tx 时，多 validator 节点仍须定期出空 vertex
        //   推进 DAG（Bullshark 活性要求 validator 持续产出 vertex 以形成 2/3 引用），
        //   否则 DAG 停滞、永不 commit。由 block_interval 节流（每轮 wait_for_pending_tx
        //   超时即产空 vertex）。
        // - 无 tx 且（单 validator 且无未 commit 的 tx-vertex）→ 跳过
        let last_has_txs = last_vertex
            .as_ref()
            .map(|v| !v.tx_list.is_empty())
            .unwrap_or(false);
        let is_multi_validator = node.active_validator_count() > 1;
        if txs.is_empty() && !last_has_txs && !is_multi_validator {
            continue;
        }

        // 切片为多个不超 MAX_VERTEX_SIZE 的 batch（修复溢出整批丢弃的活性 bug）。
        // 每来一笔 tx 累计其精确 BCS 体积，超限即封包进入下一个 vertex。
        // 单笔 tx 自身超限（异常，submit_tx 本应拦截）→ 单独记日志丢弃，不影响其他 tx。
        // 无 tx 但需推进 commit（last_has_txs）→ 一个空 batch，产出空 vertex。
        let batches = if txs.is_empty() {
            vec![Vec::new()]
        } else {
            let batches = split_txs_into_batches(txs, MAX_VERTEX_SIZE);
            if batches.is_empty() {
                vec![Vec::new()]
            } else {
                batches
            }
        };
        let batch_count = batches.len();

        for (batch_idx, batch) in batches.into_iter().enumerate() {
            let batch_tx_count = batch.len();

            // 构造 vertex 的 parent_hashes。
            // 缺口 #3 多 validator 活性修复：多 validator 时，round 同步到全局 Dag 的
            // max_round+1，parent 引用 max_round 轮的所有不同 author vertex（含自身），
            // 形成 Bullshark 所需的跨 validator 引用扇形。这使各 validator 的 round
            // 对齐到同一全局轮次（而非各自独立计数），detect_commit_leader 才能凑齐
            // 2/3 distinct-author 引用。
            // 单 validator（vc<=1）仍用自身 last_vertex 作为 parent（兼容引导期）。
            let vc = node.active_validator_count();
            let parent_hashes: Vec<Hash> = if vc <= 1 {
                // 单 validator：引用自身 last_vertex。
                last_vertex
                    .as_ref()
                    .map(|v| vec![v.vertex_hash()])
                    .unwrap_or_default()
            } else {
                // 多 validator：round 同步到 dag.max_round()+1。
                let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                match dag_guard.max_round() {
                    None => Vec::new(), // Dag 空（创世）
                    Some(max_r) => {
                        // 引用 max_r 轮的所有不同 author vertex（含自身）。
                        let mut seen_authors: BTreeSet<Vec<u8>> = BTreeSet::new();
                        let mut parents: Vec<Hash> = Vec::new();
                        for vh in dag_guard.round_vertices(max_r) {
                            if let Some(v) = dag_guard.get(vh) {
                                if seen_authors.insert(v.author_pubkey.to_bytes()) {
                                    parents.push(*vh);
                                }
                            }
                        }
                        // 同步本地 round 到 max_r+1（使后续 vertex 的 round 与全局对齐）。
                        round = max_r + 1;
                        parents
                    }
                }
            };
            let mut builder = VertexBuilder::new(epoch, round, author_pubkey.clone());
            for tx in batch {
                builder.push_tx(tx);
            }
            let builder = builder.with_parents(parent_hashes);

            // 创世轮（round 1）跳过 validate_parents（无 parent）
            // 缺口 #3：parent quorum 用真实 validator 数（而非硬编码 1）。
            // 单 validator 引导期（active=0/1）允许 1 个 parent；多 validator 时需 ≥2/3。
            // 注意：多 validator 时若 peer vertex 未及时到达，parent 数可能 < quorum，
            // 此处仅 warn 不阻断（活性优先；validate_parents 在 vc<=1 时才强制）。
            if round > 1 {
                let vc_check = node.active_validator_count().max(1);
                if vc_check > 1 {
                    // 多 validator：parent 不足仅 warn（peer 可能未到达），不阻断出 vertex。
                    if let Err(e) = builder.validate_parents(vc_check) {
                        warn!("vertex parent 校验（多 validator，非阻断）：{e}");
                    }
                } else if let Err(e) = builder.validate_parents(vc_check) {
                    warn!("vertex parent 校验失败：{e}");
                }
            }
            // validate_size 为粗估；put_vertex 内部用精确 BCS 再校验一次，此处仅作提前拒绝。
            if let Err(e) = builder.validate_size() {
                warn!("vertex 大小校验失败（batch_idx={}）：{e}", batch_idx);
                round += 1;
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
                // put_vertex 持久化失败：跳过本 vertex 的 commit 与广播，避免基于未持久化 vertex 出块。
                warn!(
                    "put_vertex 失败（batch_idx={}），跳过 commit：{e}",
                    batch_idx
                );
                last_vertex = Some(vertex);
                round += 1;
                continue;
            }
            let _ = transport.gossip_broadcast(
                GossipTopic::DagVertex,
                &NetworkMessage::DagVertex(vertex.clone()),
            );

            info!(
                "vertex 已产出 round={} batch_idx={}/{} tx_count={} hash={}",
                round,
                batch_idx,
                batch_count,
                vertex.tx_list.len(),
                hex::encode(vertex_hash)
            );

            // 从第 2 轮起，检测 commit 并产出 block（缺口 #3：真实 2/3 多签闭环）。
            //
            // 多 validator 活性修复：不只检查 last_vertex，而是扫描最近几轮（max_round-4
            // 到 max_round-1）的所有 vertex 作为候选 commit leader。这些较旧 vertex 有
            // 足够时间积累 2/3 distinct-author 引用。首个满足 quorum 的候选即提交。
            // 单 validator（vc<=1）仍直接用 last_vertex 自签出块。
            {
                let vc = node.active_validator_count().max(1);
                // 收集候选 leader：单 validator 用 last_vertex；多 validator 扫描旧轮。
                let candidate_leaders: Vec<Hash> = if vc <= 1 {
                    last_vertex.as_ref().map(|v| vec![v.vertex_hash()]).unwrap_or_default()
                } else {
                    let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                    let max_r = match dag_guard.max_round() {
                        Some(m) if m >= 2 => m,
                        _ => {
                            // max_round < 2，不足以 commit（至少需 2 轮：leader + 引用轮）。
                            last_vertex = Some(vertex);
                            round += 1;
                            let _ = batch_tx_count;
                            continue;
                        }
                    };
                    // 扫描 max_r-4 到 max_r-1 轮的所有 vertex（去重）作为候选。
                    let scan_start = max_r.saturating_sub(4).max(1);
                    let mut cands: Vec<Hash> = Vec::new();
                    for r in scan_start..max_r {
                        for vh in dag_guard.round_vertices(r) {
                            cands.push(*vh);
                        }
                    }
                    cands
                };

                // 对每个候选 leader 调 detect_commit_leader，首个满足 quorum 的提交。
                let mut committed = false;
                for leader_hash in &candidate_leaders {
                    let commit_result = {
                        let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                        detect_commit_leader(&dag_guard, leader_hash, vc)
                    };
                    if let Ok(Some(_leader)) = commit_result {
                        // 找到可 commit 的 leader。取该 leader vertex 构造 block。
                        let leader_vertex = {
                            let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                            dag_guard.get(leader_hash).cloned()
                        };
                        if let Some(leader_vertex) = leader_vertex {
                            let height = node
                                .block_store()
                                .get_tip_height()
                                .ok()
                                .flatten()
                                .map(|h| h + 1)
                                .unwrap_or(1);

                            if vc <= 1 {
                                // 单 validator：自签出块。
                                commit_and_finalize_block(
                                    &leader_vertex,
                                    &node,
                                    &secret_key,
                                    chain_id,
                                    commit_round,
                                    prev_commit_hash,
                                    prev_block_hash,
                                    height,
                                    &transport,
                                    &dag,
                                    &vertex,
                                    &mut commit_round,
                                    &mut prev_commit_hash,
                                    &mut prev_block_hash,
                                );
                            } else {
                                // 多 validator：DAG 的 2/3 引用与 certificate 的 2/3 签名
                                // 都是 finality 条件。后者不能降级为“仅审计”，否则本节点会
                                // 自产随后被严格 block validation 拒绝的区块。
                                let cert_signing_hash = match compute_cert_signing_hash(
                                    &leader_vertex,
                                    chain_id,
                                    epoch,
                                    commit_round,
                                    prev_commit_hash,
                                    &node,
                                    height,
                                ) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        error!("compute_cert_signing_hash 失败：{e}");
                                        break;
                                    }
                                };
                                let self_sig = secp256k1_sign_hash(&secret_key, &cert_signing_hash);
                                let self_vote = CommitVote {
                                    epoch,
                                    commit_round,
                                    cert_signing_hash,
                                    signer_pubkey: author_pubkey.clone(),
                                    signature: self_sig,
                                };
                                votes.add_vote(self_vote.clone());
                                let _ = transport.gossip_broadcast(
                                    GossipTopic::CommitVote,
                                    &NetworkMessage::CommitVote(self_vote),
                                );
                                // 收集已到达的投票（本节点 + peer）。不足 quorum 时保留它们，
                                // 让后续轮次继续累积，而不是出一个必然无效的 block。
                                let collected = votes.peek_for_hash(&cert_signing_hash);
                                let active_pubkeys = node.active_validator_pubkeys_sorted();
                                let mut sig_pairs: Vec<(usize, Vec<u8>)> = collected
                                    .iter()
                                    .filter_map(|vote| {
                                        active_pubkeys
                                            .iter()
                                            .position(|pk| *pk == vote.signer_pubkey)
                                            .map(|idx| (idx, vote.signature.clone()))
                                    })
                                    .collect();
                                // 确保本节点签名在列（防御性）。
                                if !sig_pairs.iter().any(|(idx, _)| {
                                    active_pubkeys.get(*idx) == Some(&author_pubkey)
                                }) {
                                    if let Some(idx) = active_pubkeys.iter().position(|pk| *pk == author_pubkey) {
                                        sig_pairs.push((idx, secp256k1_sign_hash(&secret_key, &cert_signing_hash)));
                                    }
                                }
                                let quorum = required_quorum(vc);
                                if sig_pairs.len() < quorum {
                                    debug!(
                                        commit_round,
                                        votes = sig_pairs.len(),
                                        quorum,
                                        "waiting for commit certificate quorum"
                                    );
                                    continue;
                                }
                                // Only discard votes after enough signer positions were collected.
                                let _ = votes.drain_for_hash(&cert_signing_hash);
                                commit_and_finalize_block_multi(
                                    &leader_vertex,
                                    &node,
                                    chain_id,
                                    epoch,
                                    commit_round,
                                    prev_commit_hash,
                                    prev_block_hash,
                                    height,
                                    &sig_pairs,
                                    vc,
                                    &transport,
                                    &dag,
                                    &vertex,
                                    &mut commit_round,
                                    &mut prev_commit_hash,
                                    &mut prev_block_hash,
                                );
                                committed = true;
                            }
                            if committed || vc <= 1 {
                                break;
                            }
                        }
                    }
                }
            }

            // 缺口 #3 §3.6：epoch 推进触发（每 EPOCH_LENGTH 个 commit 推进一次 epoch，
            // 并用 VRF 派生新 epoch_randomness）。仅在发生 commit 时计数。
            if commit_round > 1 && (commit_round - 1) % EPOCH_LENGTH == 0 && round > 1 {
                let new_epoch = epoch + 1;
                node.advance_epoch_with_vrf(new_epoch, vrf_secret.as_ref());
                epoch = new_epoch;
                info!(
                    "[validator-loop] epoch 推进至 {}（commit_round={}，VRF={}）",
                    epoch,
                    commit_round,
                    vrf_secret.is_some()
                );
            }

            last_vertex = Some(vertex);
            round += 1;
            // batch_tx_count 仅供本作用域日志/调试上下文，显式标记避免未使用告警。
            let _ = batch_tx_count;
        }
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
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

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
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )
    .map_err(|e| format!("构造 tagged_pubkey 失败：{e}"))?;
    let address: Address = poker_l1::account::derive_address(&tagged_pubkey);
    info!("1. 密钥对生成完成");
    info!(
        "   tagged_pubkey tag=0x{:02x} raw={}B",
        tagged_pubkey.tag,
        tagged_pubkey.raw.len()
    );
    info!("   address={}", hex::encode(address));

    // 2. 构造 ValidatorKey 并以 validator 模式打开 Node
    let mut sk_bytes = [0u8; 32];
    sk_bytes.copy_from_slice(&secret_key.secret_bytes()[..]);
    let vkey = ValidatorKey::from_secret_bytes(sk_bytes)
        .map_err(|e| format!("构造 ValidatorKey 失败：{e}"))?;
    let config = NodeConfig::validator(data_dir.clone(), vkey);
    let node = open_node_with_application_verifiers(config)
        .map_err(|e| format!("Node::open 失败：{e}"))?;
    info!(
        "2. Validator 节点已打开（chain_id=0x{:08x}）",
        node.chain_id()
    );

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
    info!(
        "   lane=Public nonce=0 inputs=0 outputs=0 sig={}B",
        tx.signature.len()
    );

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
    info!(
        "   height={} block_hash={}",
        block_height,
        hex::encode(block_hash)
    );
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
    info!(
        "11. tip 已更新: height={} hash={}",
        block_height,
        hex::encode(block_hash)
    );

    info!("===== 端到端链路测试全部通过 =====");
    info!("  密钥生成 → 交易构造 → 签名 → 提交 → 缓冲 → 出块 → 写入 → 查询 → tip 更新");
    println!(
        "\n✅ E2E 测试通过: block#{} 包含 1 笔交易, tx_hash={}",
        block_height,
        hex::encode(tx_hash)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_l1::signature::tagged_pubkey::encode_tag;

    /// 构造一条可控大小的 Transaction：用 `signature` 字段填充指定字节数来调控 BCS 体积。
    fn make_sized_tx(sig_bytes: usize) -> Transaction {
        let scheme = SignatureScheme::Secp256k1;
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: TaggedPubkey {
                tag: encode_tag(scheme, 1),
                raw: vec![0u8; scheme.raw_pubkey_len()],
            },
            signature: vec![0u8; sig_bytes],
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: 1,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn split_batches_empty_input_returns_empty() {
        let batches = split_txs_into_batches(Vec::new(), MAX_VERTEX_SIZE);
        assert!(batches.is_empty(), "空输入应返回空 Vec");
    }

    #[test]
    fn split_batches_all_small_fit_single_batch() {
        // 10 笔小 tx（每笔 ~1KB）应全部装入一个 batch
        let txs: Vec<Transaction> = (0..10).map(|_| make_sized_tx(1000)).collect();
        let batches = split_txs_into_batches(txs, MAX_VERTEX_SIZE);
        assert_eq!(batches.len(), 1, "10 笔 1KB tx 应装入 1 个 batch");
        assert_eq!(batches[0].len(), 10, "batch 内应有 10 笔 tx");
    }

    #[test]
    fn split_batches_overflow_splits_into_multiple() {
        // 关键回归测试：超 MAX_VERTEX_SIZE 时切片为多 batch，而非整批丢弃。
        // 每笔 ~100KB，3 笔 ≈ 300KB > 256KB（含头部预算）→ 至少 2 个 batch。
        let txs: Vec<Transaction> = (0..3).map(|_| make_sized_tx(100_000)).collect();
        let batches = split_txs_into_batches(txs, MAX_VERTEX_SIZE);
        assert!(
            batches.len() >= 2,
            "3 笔 100KB tx 应切分为 ≥2 个 batch，实际 {}",
            batches.len()
        );
        // 所有 tx 都被保留（不丢失）
        let total: usize = batches.iter().map(|b| b.len()).sum();
        assert_eq!(total, 3, "所有 tx 必须被保留，不得丢失");
    }

    #[test]
    fn split_batches_single_oversized_tx_alone() {
        // 单笔 tx 自身超限：应单独成 batch（交由 validate_size/put_vertex 拒绝），
        // 不影响后续 tx。
        let big = make_sized_tx(MAX_VERTEX_SIZE + 1000);
        let small = make_sized_tx(100);
        let batches = split_txs_into_batches(vec![big, small], MAX_VERTEX_SIZE);
        // 第一笔单独一个 batch，第二笔另一个 batch
        assert_eq!(batches.len(), 2, "超大 tx 单独成 batch，其余 tx 不受影响");
        assert_eq!(batches[1].len(), 1, "第二笔小 tx 应在第二个 batch");
    }

    #[test]
    fn split_batches_each_batch_within_size_limit() {
        // 每个 batch 的累计 tx BCS 体积（加头部预算）应 ≤ MAX_VERTEX_SIZE
        let txs: Vec<Transaction> = (0..20).map(|_| make_sized_tx(40_000)).collect();
        let batches = split_txs_into_batches(txs, MAX_VERTEX_SIZE);
        const HEADER_BUDGET: usize = 256;
        for (i, batch) in batches.iter().enumerate() {
            let size: usize = batch.iter().map(|tx| tx.to_bcs().unwrap().len()).sum();
            assert!(
                size + HEADER_BUDGET <= MAX_VERTEX_SIZE || batch.len() == 1,
                "batch#{} 体积 {} + 头部 {} 超过 {} 且非单笔超大 tx",
                i,
                size,
                HEADER_BUDGET,
                MAX_VERTEX_SIZE
            );
        }
    }

    // ===== 缺口 #3：VoteCollector 测试 =====

    fn make_vote(signer_byte: u8, cert_hash_byte: u8) -> CommitVote {
        CommitVote {
            epoch: 1,
            commit_round: 5,
            cert_signing_hash: [cert_hash_byte; 32],
            signer_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![signer_byte; 33],
            },
            signature: vec![0u8; 65],
        }
    }

    fn make_vertex(round: u64, author_byte: u8) -> DagVertex {
        DagVertex {
            epoch: 1,
            round,
            author_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![author_byte; 33],
            },
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![],
        }
    }

    #[test]
    fn vertex_range_response_returns_only_requested_rounds() {
        let mut dag = Dag::new();
        dag.insert(make_vertex(1, 0x01));
        dag.insert(make_vertex(1, 0x02));
        dag.insert(make_vertex(2, 0x03));
        let dag = Arc::new(Mutex::new(dag));

        let first_round = collect_vertices_by_round(&dag, 1, 1);
        assert_eq!(first_round.len(), 2);
        assert!(first_round.iter().all(|vertex| vertex.round == 1));
        assert!(collect_vertices_by_round(&dag, 3, 2).is_empty());
    }

    #[test]
    fn vote_collector_dedups_same_signer_same_hash() {
        let vc = VoteCollector::new();
        let vote = make_vote(0x10, 0xAA);
        vc.add_vote(vote.clone());
        vc.add_vote(vote.clone()); // 重复 → 去重
        let collected = vc.drain_for_hash(&[0xAA; 32]);
        assert_eq!(collected.len(), 1, "同一 signer + 同一 hash 应去重为 1 票");
    }

    #[test]
    fn vote_collector_collects_distinct_signers() {
        let vc = VoteCollector::new();
        vc.add_vote(make_vote(0x10, 0xAA));
        vc.add_vote(make_vote(0x20, 0xAA)); // 不同 signer → 计入
        vc.add_vote(make_vote(0x30, 0xAA)); // 不同 signer → 计入
        let collected = vc.drain_for_hash(&[0xAA; 32]);
        assert_eq!(collected.len(), 3, "3 个不同 signer 应收集 3 票");
    }

    #[test]
    fn vote_collector_drain_isolates_by_hash() {
        let vc = VoteCollector::new();
        vc.add_vote(make_vote(0x10, 0xAA));
        vc.add_vote(make_vote(0x20, 0xBB)); // 不同 cert hash
        let collected_aa = vc.drain_for_hash(&[0xAA; 32]);
        assert_eq!(collected_aa.len(), 1, "仅 drain hash=AA 的投票");
        // BB 投票仍保留
        let collected_bb = vc.drain_for_hash(&[0xBB; 32]);
        assert_eq!(collected_bb.len(), 1, "BB 投票应保留");
    }

    #[test]
    fn vote_collector_drain_clears_returned_votes() {
        // drain 后再次 drain 同 hash 应为空。
        let vc = VoteCollector::new();
        vc.add_vote(make_vote(0x10, 0xAA));
        let _ = vc.drain_for_hash(&[0xAA; 32]);
        let again = vc.drain_for_hash(&[0xAA; 32]);
        assert!(again.is_empty(), "drain 后该 hash 的投票应清空");
    }
}
