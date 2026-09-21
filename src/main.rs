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
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use poker_l1::account::derive_address;
use poker_l1::block::validator::{validate_tx_chain_id, validate_tx_nonce, validate_tx_signature};
use poker_l1::block::{Block, BlockHeader, compute_tx_merkle_root};
use poker_l1::consensus::{
    Dag, DagCommitCertificate, DagVertex, MAX_VERTEX_SIZE, VertexBuilder,
    assemble_commit_certificate, attempt_commit_projection, detect_commit_leader,
    evaluate_leader_wave, find_missing_parent_vertices, required_quorum, round_leader_index,
    sort_commit_txs_r4m4_with_force_include, WaveOutcome, COMMIT_ABSENCE_ROUNDS,
};
use poker_l1::error::PokerL1Result;
use poker_l1::network::{
    CommitVote, GossipManager, GossipTopic, LightClientHeader, MAX_PROOF_PACKAGE_BYTES,
    NetworkMessage, NetworkTransport, PeerInfo, ProofPackageChunk, ProofPackageManifest,
    build_proof_package_chunk, build_proof_package_manifest,
};
use poker_l1::node::{Node, NodeConfig, NodeRole, NodeRpcBackend, ValidatorKey};
use poker_l1::rpc::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RpcClientInfo, RpcGuard, RpcHandler,
};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey, verify_signature};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane, validate_tx_limits};
use poker_l1::{Address, Hash};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
/// Bound block range scans by requested heights, including sparse/missing heights.
const MAX_BLOCK_RANGE_HEIGHTS: u64 = 512;
/// Bound untrusted peer-exchange payloads before they become dial targets.
const MAX_DISCOVERED_PEERS: usize = 256;

/// 出站 peer 重连的初始退避间隔（缺口：初始 --peer 连接失败无重试）。
const PEER_DIAL_INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// 出站 peer 重连的最大退避间隔（指数退避封顶）。
const PEER_DIAL_MAX_BACKOFF: Duration = Duration::from_secs(15);

/// catch-up 轮询间隔（启动 / 落后期间向 peer 请求缺失区块的周期）。
const CATCH_UP_INTERVAL: Duration = Duration::from_secs(2);

/// 单次 catch-up 请求覆盖的 height 数（<= MAX_BLOCK_RANGE_HEIGHTS）。
const CATCH_UP_CHUNK: u64 = 64;

/// 单个 catch-up 周期内最多连续导入的批次数（防止长时间独占 block 锁）。
const MAX_CATCH_UP_BATCHES_PER_TICK: u64 = 16;

/// shutdown 感知 sleep 的分片粒度。
const SLEEP_POLL_CHUNK: Duration = Duration::from_millis(250);

/// 在 `duration` 内睡眠，但每 [`SLEEP_POLL_CHUNK`] 检查一次 shutdown 标志。
///
/// 返回是否完整睡满（false 表示 shutdown 触发提前返回）。
fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) -> bool {
    let mut remaining = duration;
    while !shutdown.load(Ordering::SeqCst) {
        if remaining.is_zero() {
            return true;
        }
        let chunk = remaining.min(SLEEP_POLL_CHUNK);
        std::thread::sleep(chunk);
        remaining = remaining.saturating_sub(chunk);
    }
    false
}

/// Bidirectional stream used by the persistent P2P connection handler.
///
/// Production connections use [`TcpStream`]. Keeping the handler generic over
/// this narrow boundary lets protocol tests use an already-connected local
/// socket pair without opening a listening port.
trait P2pIo: Read + Write + Send {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn P2pIo>>;
    fn peer_socket_addr(&self) -> Option<SocketAddr>;
    /// 广播写超时（半开死连接的 write 阻塞防线；不支持者 no-op）。
    fn set_broadcast_write_timeout(&self) {}
}

impl P2pIo for TcpStream {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn P2pIo>> {
        self.try_clone()
            .map(|stream| Box::new(stream) as Box<dyn P2pIo>)
    }

    fn peer_socket_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }

    fn set_broadcast_write_timeout(&self) {
        let _ = self.set_write_timeout(Some(P2P_BROADCAST_WRITE_TIMEOUT));
    }
}

#[cfg(all(test, unix))]
impl P2pIo for std::os::unix::net::UnixStream {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn P2pIo>> {
        self.try_clone()
            .map(|stream| Box::new(stream) as Box<dyn P2pIo>)
    }

    fn peer_socket_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Derive the execution timestamp from already-finalized chain state rather than the local clock.
///
/// This preserves the header's monotonic soft-time invariant and is identical for every validator
/// which has the same parent.  The genesis fallback is also deterministic for integration tests
/// and a freshly initialized chain.
/// put_block 同高冲突后的权威块拉取退避窗口。
const BLOCK_CONFLICT_REQUEST_BACKOFF: std::time::Duration = std::time::Duration::from_millis(2_000);

/// epoch 推进周期（每 EPOCH_LENGTH 个 commit 推进一次 epoch）。
pub const EPOCH_LENGTH: u64 = 100_000;

/// 落后检测阈值：本地 tip 落后 peer 投票高度即触发 catch-up（=1）。
/// 网络抖动丢失 1-2 个块时若不补，tip cert_round 分裂会让各节点的
/// epoch 推进判定错位（本地 tip % EPOCH_LENGTH 各异）→ DAG 清空时机
/// 分裂 → 拓扑级分叉（实测 tip 分裂 170/171/172 后全网 commit 停滞）。
const CATCHUP_LAG_THRESHOLD: u64 = 1;

fn consensus_block_timestamp(node: &Node, height: u64) -> Result<u64, String> {
    let previous = height.checked_sub(1).and_then(|previous_height| {
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

/// commit certificate 投票累加器（多 validator 2/3 多签闭环）。
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
    /// 投票上限：不同 (cert_signing_hash) 的过期投票在 tip 前进后永不 commit，
    /// 无上限会随运行时间无界增长。
    const MAX_VOTES: usize = 8192;

    fn new() -> Self {
        Self {
            votes: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// 收集一笔投票（同一 (epoch, commit_round, signer) 仅保留最新一张）。
    ///
    /// 恰 quorum 修复：旧实现按 (signer, cert_hash) 去重 —— 同一 signer 对同一
    /// 高度先后为两个不同 cert 签票时，两张票**同时**留在池中，旧票会继续为
    /// 已被放弃的 cert 凑 quorum，配合视图收敛后的重票可令两个 cert 各自凑齐
    /// quorum，形成同高度分叉。改为 last-write-wins：signer 的重票**替换**其
    /// 旧票，任何时刻池内总票数 ≤ validator 数，两个 5 票 quorum 在 n=7 下
    /// 不可能同时成立（5+5 > 7）。
    fn add_vote(&self, vote: CommitVote) {
        let mut votes = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        let same_signer_at_height = |v: &CommitVote| {
            // 分叉根因修复：按 (signer, height) 去重。视图切换会让
            // commit_round 前进而 height 不动——按 round 去重时同一 signer
            // 对同一 height 的不同 cert 票共存，双 quorum 同高度分叉。
            v.epoch == vote.epoch
                && v.height == vote.height
                && v.signer_pubkey == vote.signer_pubkey
        };
        if votes.iter().any(|v| {
            same_signer_at_height(v) && v.cert_signing_hash == vote.cert_signing_hash
        }) {
            return;
        }
        if votes.len() >= Self::MAX_VOTES {
            // FIFO 淘汰最旧投票（活跃 cert 的投票会在下轮重新广播/重签）。
            let drop_count = votes.len() / 4 + 1;
            votes.drain(0..drop_count);
        }
        // 替换该 signer 在同一高度的旧票（若有不同 hash 的旧票）。
        votes.retain(|v| !same_signer_at_height(v));
        votes.push(vote);
    }

    /// 取出针对指定 cert_signing_hash 的全部已收集投票（清空该 key 对应的投票）。
    fn drain_for_hash(&self, cert_signing_hash: &poker_l1::Hash) -> Vec<CommitVote> {
        let mut votes = self.votes.lock().unwrap_or_else(|e| e.into_inner());
        let (matched, rest): (Vec<_>, Vec<_>) = votes
            .drain(..)
            .partition(|v| v.cert_signing_hash == *cert_signing_hash);
        *votes = rest;
        matched
    }

    /// 非破坏性地查看针对指定 cert_signing_hash 的全部已收集投票。
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

    // 初始化 tracing：默认 INFO 级别，可通过 RUST_LOG 环境变量覆盖
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match subcommand {
        "node" => {
            if let Err(e) = run_node(rest) {
                error!("node 启动失败：{e}");
                std::process::exit(1);
            }
        }
        "tx" => {
            if let Err(e) = run_tx(rest) {
                error!("tx 构造失败：{e}");
                std::process::exit(1);
            }
        }
        "keygen" => {
            if let Err(e) = run_keygen(rest) {
                error!("keygen 失败：{e}");
                std::process::exit(1);
            }
        }
        "dkg" => {
            if let Err(e) = run_dkg(rest) {
                error!("dkg 失败：{e}");
                std::process::exit(1);
            }
        }
        "test-e2e" => {
            if let Err(e) = run_test_e2e(rest) {
                error!("test-e2e 失败：{e}");
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
    eprintln!("  dkg       deal-sum DKG 密钥供给（全部 dealer 单进程执行，v1.5-e 原型部署面）");
    eprintln!("  tx        构造并签名 Public tx，输出 submit_tx 参数 JSON（v1.5 演练工具）");
    eprintln!("  test-e2e  端到端链路测试（构造交易→签名→提交→出块→查询）");
    eprintln!("  version   打印版本号");
    eprintln!("  help      打印此帮助");
    eprintln!();
    eprintln!("`node` 选项：");
    eprintln!("  --role <validator|full|archive|light>   节点角色（默认 full）");
    eprintln!("  --data-dir <path>                       数据目录（默认 ./data）");
    eprintln!("  --rpc-listen <addr>                     RPC 监听地址（默认 127.0.0.1:8545）");
    eprintln!("  --p2p-listen <addr>                     P2P 监听地址（默认 127.0.0.1:9000）");
    eprintln!(
        "  --proof-package-dir <path>               向 P2P peers 提供 proving_service .proof sidecars"
    );
    eprintln!("  --max-connections <n>                   最大并发连接数（默认 128）");
    eprintln!("  --validator-key-file <path>             validator 私钥文件（32B hex，推荐）");
    eprintln!(
        "  --validator-key <hex>                   validator 私钥（32B hex，不推荐：ps 可见）"
    );
    eprintln!("  --block-interval-ms <ms>                出块间隔毫秒（默认 1000，仅 validator）");
    eprintln!(
        "  --inclusion-deadline-ms <ms>            ForceInclude 强制包含期限毫秒（M3-ACC-6，默认 10000；0 = 禁用）"
    );
    eprintln!(
        "  --checkpoint-interval <n>               checkpoint 产出间隔（块数，v1.5-c 默认 32；0 = 禁用）"
    );
    eprintln!(
        "  --qc-threshold-t <t>                    checkpoint QC 阈值 t（v1.5-e 真 t-of-n 阈值 BLS；默认 0 = 聚合模式零回退）"
    );
    eprintln!(
        "  --dkg-keyset <path>                     DKG 群密钥集 JSON（`zchain dkg` 产出；qc-threshold-t > 0 必填）"
    );
    eprintln!(
        "  --dkg-share <path>                      本节点 DKG 群份额 JSON（`zchain dkg` 产出；qc-threshold-t > 0 必填）"
    );
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
    eprintln!("`dkg` 选项：");
    eprintln!("  --n <n>                                 参与者总数 n");
    eprintln!("  --t <t>                                 签名/重建阈值 t（2 <= t <= n）");
    eprintln!("  --out-dir <path>                        输出目录（keyset.json + share-<id>.json）");
    eprintln!("  --seed <hex>                            可选 32B hex 种子（默认 CSPRNG；原型口径，生产 dealer 应各自执行并销毁种子）");
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
fn load_genesis_validators(
    path: &std::path::Path,
) -> Result<Vec<poker_l1::consensus::ValidatorEntry>, String> {
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
        let mut entry = poker_l1::consensus::ValidatorEntry::new(tagged, vrf_pk, e.stake, 0);
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
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("读取 genesis alloc 文件失败：{e}"))?;
    let entries: Vec<GenesisAllocEntry> =
        serde_json::from_str(&content).map_err(|e| format!("解析 genesis alloc JSON 失败：{e}"))?;
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
    let mut proof_package_dir: Option<PathBuf> = None;
    let mut max_connections: usize = DEFAULT_MAX_CONNECTIONS;
    let mut validator_key_hex: Option<String> = None;
    let mut validator_key_file: Option<PathBuf> = None;
    let mut block_interval_ms: u64 = DEFAULT_BLOCK_INTERVAL_MS;
    // M3-ACC-6：强制包含期限（毫秒，默认 10000；0 = 禁用强制包含路径）。
    let mut inclusion_deadline_ms: u64 = poker_l1::force_include::DEFAULT_INCLUSION_DEADLINE_MS;
    // v1.5-c：checkpoint 产出间隔（块数；0 = 禁用）。
    let mut checkpoint_interval: u64 =
        poker_l1::consensus::checkpoint::DEFAULT_CHECKPOINT_INTERVAL_BLOCKS;
    // v1.5-e：阈值 QC 阈值 t（0 = 聚合模式）+ DKG 密钥材料路径。
    let mut qc_threshold_t: u32 = 0;
    let mut dkg_keyset_path: Option<PathBuf> = None;
    let mut dkg_share_path: Option<PathBuf> = None;
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
            "--proof-package-dir" => {
                i += 1;
                proof_package_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--proof-package-dir 缺少参数")?,
                ));
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
            "--inclusion-deadline-ms" => {
                i += 1;
                let v = args.get(i).ok_or("--inclusion-deadline-ms 缺少参数")?;
                inclusion_deadline_ms = v
                    .parse::<u64>()
                    .map_err(|e| format!("--inclusion-deadline-ms 解析失败：{e}"))?;
            }
            "--checkpoint-interval" => {
                i += 1;
                let v = args.get(i).ok_or("--checkpoint-interval 缺少参数")?;
                checkpoint_interval = v
                    .parse::<u64>()
                    .map_err(|e| format!("--checkpoint-interval 解析失败：{e}"))?;
            }
            // v1.5-e：checkpoint QC 阈值 t（0 = 聚合模式零回退；> 0 = 真 t-of-n）。
            "--qc-threshold-t" => {
                i += 1;
                let v = args.get(i).ok_or("--qc-threshold-t 缺少参数")?;
                qc_threshold_t = v
                    .parse::<u32>()
                    .map_err(|e| format!("--qc-threshold-t 解析失败：{e}"))?;
            }
            "--dkg-keyset" => {
                i += 1;
                dkg_keyset_path =
                    Some(PathBuf::from(args.get(i).ok_or("--dkg-keyset 缺少参数")?));
            }
            "--dkg-share" => {
                i += 1;
                dkg_share_path = Some(PathBuf::from(args.get(i).ok_or("--dkg-share 缺少参数")?));
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
                vrf_key_file = Some(PathBuf::from(args.get(i).ok_or("--vrf-key-file 缺少参数")?));
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
    // M3-ACC-6：强制包含期限（0 = 禁用，行为与历史版本一致）。
    config.inclusion_deadline_ms = inclusion_deadline_ms;
    if inclusion_deadline_ms == 0 {
        info!("inclusion_deadline: 强制包含路径已禁用（--inclusion-deadline-ms 0）");
    } else {
        info!("inclusion_deadline: {inclusion_deadline_ms}ms");
    }
    // v1.5-c：checkpoint 间隔（0 = 禁用）。
    config.checkpoint_interval_blocks = checkpoint_interval;
    if checkpoint_interval == 0 {
        info!("checkpoint: 已禁用（--checkpoint-interval 0）");
    } else if qc_threshold_t > 0 {
        info!("checkpoint: 每 {checkpoint_interval} 个高度产出一次（真 t-of-n 阈值 QC，t={qc_threshold_t}）");
    } else {
        info!("checkpoint: 每 {checkpoint_interval} 个高度产出一次（2f+1 BLS 聚签 QC）");
    }
    // v1.5-e：阈值 QC 配置（0 = 聚合模式零回退；> 0 = 阈值形态 + DKG 材料）。
    config.qc_threshold_t = qc_threshold_t;
    config.dkg_keyset_path = dkg_keyset_path;
    config.dkg_share_path = dkg_share_path;
    if qc_threshold_t == 0 {
        info!("qc-threshold: 关闭（聚合模式，零回退）");
    } else {
        info!("qc-threshold: t={qc_threshold_t}（真 t-of-n 阈值 BLS，密钥来自 deal-sum DKG）");
    }
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
    node.ensure_consensus_ready().map_err(|error| {
        format!(
            "节点拒绝以空 ValidatorSet 启动共识/RPC/P2P；请提供 --genesis-validators 或恢复已持久化集合：{error}"
        )
    })?;
    // Apply the canonical native-coin genesis allocation (idempotent across restarts).
    // Even a zero-allocation chain creates and permanently closes TreasuryCap before
    // networking starts, so every production block commit is covered by supply reconciliation.
    let genesis_allocs = genesis_alloc_file
        .as_deref()
        .map(load_genesis_alloc)
        .transpose()?
        .unwrap_or_default();
    let created = node
        .apply_genesis_alloc(genesis_allocs)
        .map_err(|e| format!("genesis alloc 应用失败：{e}"))?;
    info!("已应用 genesis UTXO 分配：新铸 {} 个 coin outputs", created);
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
    if let Some(directory) = &proof_package_dir {
        let loaded = load_proof_packages_from_dir(&transport, directory)?;
        info!(
            directory = %directory.display(),
            loaded,
            "loaded proof packages for P2P serving"
        );
    }
    // Compact vertex recovery needs one shared, bounded tx/short-id cache on
    // every P2P handler and the validator loop.
    let gossip = Arc::new(GossipManager::new());
    // Shared by inbound and outbound P2P readers as well as the validator
    // loop. A remotely accepted vertex reaches this DAG only after the node's
    // persistent validation succeeds.
    let shared_dag: Arc<Mutex<Dag>> = Arc::new(Mutex::new(Dag::new()));
    let vote_collector: Arc<VoteCollector> = Arc::new(VoteCollector::new());

    // 绑定 P2P listener
    let p2p_listener = TcpListener::bind(&p2p_listen)
        .map_err(|e| format!("P2P 监听绑定 {p2p_listen} 失败：{e}"))?;
    transport.set_self_addr(p2p_listen.clone());
    p2p_listener
        .set_nonblocking(true)
        .map_err(|e| format!("P2P set_nonblocking 失败：{e}"))?;
    info!("P2P server 监听 {p2p_listen}（length-prefixed BCS）");

    // 出站连接管理器：--peer 与 PEX 学到的地址都经它维持持久广播连接
    //（断线指数退避重连；自身监听地址跳过，避免 PEX 自拨回环）。
    let supervisor = Arc::new(ConnectionSupervisor::new(
        Arc::clone(&transport),
        p2p_listen.clone(),
        Arc::clone(&shutdown_flag),
    ));

    // 主动连接 --peer 列表：每条地址交给 supervisor 的持久 dialer 线程
    //（连接失败/断开按指数退避自动重连，修复原先只 warn 一次的缺口）。
    for peer_addr in &peers {
        let started = supervisor.ensure_dialing(
            peer_addr.clone(),
            &node_arc,
            &shared_dag,
            &vote_collector,
            &gossip,
        );
        if !started {
            info!("peer {peer_addr} 已有 dialer 或为本机地址，跳过重复拨号");
        }
    }
    info!("P2P peer 地址 {} 个（dialer 已启动）", transport.peer_count());
    if let Err(error) = transport.broadcast_peer_exchange() {
        warn!("初始 PEX 广播失败：{error}");
    }

    // === 启动 catch-up 线程（light 角色不存全量区块，跳过）===
    let catch_up_thread = if role != NodeRole::Light {
        let c_node = Arc::clone(&node_arc);
        let c_transport = Arc::clone(&transport);
        let c_shutdown = Arc::clone(&shutdown_flag);
        Some(
            std::thread::Builder::new()
                .name("catch-up".to_string())
                .spawn(move || run_catch_up_loop(c_node, c_transport, c_shutdown))
                .map_err(|e| format!("catch-up 线程启动失败：{e}"))?,
        )
    } else {
        None
    };

    // === P2P accept loop 线程 ===
    let p2p_node = Arc::clone(&node_arc);
    let p2p_transport = Arc::clone(&transport);
    let p2p_shutdown = Arc::clone(&shutdown_flag);
    let p2p_dag = Arc::clone(&shared_dag);
    let p2p_votes = Arc::clone(&vote_collector);
    let p2p_gossip = Arc::clone(&gossip);
    let p2p_supervisor = Arc::clone(&supervisor);
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
                        let gossip = Arc::clone(&p2p_gossip);
                        let supervisor = Arc::clone(&p2p_supervisor);
                        std::thread::spawn(move || {
                            handle_p2p_connection(
                                stream,
                                node,
                                transport,
                                dag,
                                votes,
                                gossip,
                                Some(&supervisor),
                            );
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
        let v_gossip = Arc::clone(&gossip);
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
                        v_gossip,
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
    if let Some(ct) = catch_up_thread {
        let _ = ct.join();
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
const MAX_P2P_MSG_SIZE: usize = poker_l1::network::MAX_P2P_MESSAGE_BYTES;

/// 默认 P2P 请求-响应超时（秒）。
const P2P_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// gossip 广播的 per-stream 写超时：半开死连接的 write 阻塞（TCP 重传
/// 超时可达 15 分钟+）会持 per-stream 写锁，令所有广播线程排队、validator
/// loop 停产。超时需长于同机 debug 构建的极端写延迟（实测 2s 会误杀
/// CPU 争用下的活连接 → 连接churn → vertex 丢失），又须远小于 TCP
/// 默认阻塞，10s 平衡。
const P2P_BROADCAST_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// 本节点 P2P 监听地址（自连过滤：PEX 会把自己广播给所有节点，
    /// 不过滤则节点持续自拨/自连，连接churn 且 catch-up 轮询先在
    /// 自连接上空耗 30s 超时）。
    self_addr: std::sync::Mutex<Option<String>>,
    /// 已连接 peer 的共享写端（仅用于 gossip_broadcast）。
    ///
    /// 同一连接还会由其接收循环发送 Response*/fallback 消息。每个写端单独
    /// 加锁，保证两类 writer 不会把 length-prefixed frame 交错写入 TCP 字节流。
    peers: Arc<Mutex<Vec<Arc<Mutex<Box<dyn P2pIo>>>>>>,
    /// 已连接 peer 的地址信息（用于定向通信）。
    peer_addrs: Arc<Mutex<Vec<PeerInfo>>>,
    /// 已收到或本地生成的轻客户端 headers。
    ///
    /// 该缓存属于传输层，令 `NetworkTransport::subscribe_light_headers` 不再是空
    /// 实现；`Node` 仍是 header 签名和合并的权威来源。
    light_headers: Arc<Mutex<Vec<LightClientHeader>>>,
    /// Bounded opaque proof packages available to peers on this transport.
    ///
    /// The node binary does not interpret these bytes. A proving-service adapter
    /// must canonical-decode and reverify every downloaded package before adding
    /// it to its durable repository.
    proof_packages: Arc<Mutex<BTreeMap<Hash, Vec<u8>>>>,
}

impl TcpTransport {
    /// 创建空传输层。
    fn new() -> Self {
        Self {
            self_addr: std::sync::Mutex::new(None),
            peers: Arc::new(Mutex::new(Vec::new())),
            peer_addrs: Arc::new(Mutex::new(Vec::new())),
            light_headers: Arc::new(Mutex::new(Vec::new())),
            proof_packages: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// 注册本节点 P2P 监听地址（自连过滤基准）。
    fn set_self_addr(&self, addr: String) {
        *self.self_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
    }

    /// 地址是否为本节点自身（规范化比较）。
    fn is_self_addr(&self, addr: &str) -> bool {
        match self.self_addr.lock() {
            Ok(guard) => guard.as_deref() == Some(addr),
            Err(_) => false,
        }
    }

    /// Register one already-canonical package for bounded P2P serving.
    fn register_proof_package(&self, job_id: Hash, bytes: Vec<u8>) -> Result<(), String> {
        build_proof_package_manifest(job_id, &bytes).map_err(|error| error.to_string())?;
        self.proof_packages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job_id, bytes);
        Ok(())
    }

    /// 添加已连接 peer 的共享写端（仅加入广播列表）。
    fn add_peer(&self, stream: Arc<Mutex<Box<dyn P2pIo>>>) {
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

    /// 主动连接到 peer，返回由调用方交给 P2P 接收循环的 stream。
    ///
    /// `handle_p2p_connection` 会在读取端启动后克隆该 stream 并加入广播
    /// 列表。这样主动连接与入站连接都具备双向收发能力，而不会留下一个只写
    /// 不读的 socket。
    fn connect_peer(&self, addr: &str) -> Result<TcpStream, String> {
        if self.is_self_addr(addr) {
            return Err(format!("跳过自身地址 {addr}（自连过滤）"));
        }
        let stream = TcpStream::connect(addr).map_err(|e| format!("连接 peer {addr} 失败：{e}"))?;
        info!("已连接 peer：{addr}");
        self.register_peer_info(PeerInfo {
            peer_id: addr.to_string(),
            address: addr.to_string(),
            validator_pubkey: None,
        });
        Ok(stream)
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
        self.gossip_broadcast(GossipTopic::DagVertex, &NetworkMessage::PeerExchange(peers))
            .map_err(|e| e.to_string())
    }

    /// 缺口 #5：合并 PEX 发现的新 peer 地址（去重）。
    ///
    /// 返回本次新加入的规范化地址列表（调用方据此升级为持久拨号连接）。
    fn merge_discovered_peers(&self, new_peers: &[PeerInfo]) -> Vec<String> {
        let mut addrs = self.peer_addrs.lock().unwrap_or_else(|e| e.into_inner());
        let mut added = Vec::new();
        for peer in new_peers.iter().take(MAX_DISCOVERED_PEERS) {
            // PEX 是不可信网络输入。仅保留可拨号 socket 地址，避免随后同步请求
            // 把任意字符串变成连接目标；同时限制总条目数，防止地址表无界增长。
            let Ok(address) = peer.address.parse::<SocketAddr>() else {
                debug!(peer = %peer.address, "忽略 PEX 中的非 socket 地址");
                continue;
            };
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                debug!(peer = %peer.address, "忽略 PEX 中不可拨号的地址");
                continue;
            }
            if addrs.len() >= MAX_DISCOVERED_PEERS {
                warn!(
                    limit = MAX_DISCOVERED_PEERS,
                    "PEX peer 地址表已满，忽略后续发现结果"
                );
                break;
            }
            if !addrs.iter().any(|p| p.address == address.to_string()) {
                let mut peer = peer.clone();
                peer.address = address.to_string();
                addrs.push(peer);
                added.push(address.to_string());
            }
        }
        added
    }

    /// Merge one light-client header and report whether it added new material.
    ///
    /// Header signatures are intentionally deduplicated by validator key.  The
    /// cache is bounded just like `Node`'s cache so a remote peer cannot retain
    /// an unbounded historical stream in this transport object.
    fn merge_light_header(&self, header: LightClientHeader) -> bool {
        const MAX_LIGHT_HEADERS: usize = 1_000;

        let mut headers = self.light_headers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = headers
            .iter_mut()
            .find(|existing| existing.header_bytes == header.header_bytes)
        {
            let mut changed = false;
            for signature in header.signatures {
                if !existing
                    .signatures
                    .iter()
                    .any(|known| known.validator == signature.validator)
                {
                    existing.signatures.push(signature);
                    changed = true;
                }
            }
            if existing.signer_bitmap != header.signer_bitmap && !header.signer_bitmap.is_empty() {
                existing.signer_bitmap = header.signer_bitmap;
                changed = true;
            }
            return changed;
        }

        headers.push(header);
        if headers.len() > MAX_LIGHT_HEADERS {
            headers.remove(0);
        }
        true
    }

    /// Cache and gossip any locally generated headers that were not previously
    /// announced on this transport.
    fn publish_light_headers_from_node(&self, node: &Node) {
        for header in node.get_light_headers() {
            if self.merge_light_header(header.clone()) {
                if let Err(error) = self.gossip_broadcast(
                    GossipTopic::DagVertex,
                    &NetworkMessage::LightClientHeader(header),
                ) {
                    warn!("P2P 广播 LightClientHeader 失败：{error}");
                }
            }
        }
    }
}

/// 出站连接管理器：为每个已知 peer 地址维持一条持久广播连接。
///
/// 覆盖三个组网鲁棒性缺口：
/// 1. 配置的 `--peer` 地址在连接失败/断开后按指数退避（2s 起、15s 封顶）持续重拨，
///    节点存活期间不放弃（原先只 warn 一次）。
/// 2. PEX 学到的新地址自动升级为同样的持久拨号连接（原先只进临时请求地址表）。
/// 3. 以地址为粒度去重（同一地址只保留一个 dialer 线程），不与已有连接重复拨号。
struct ConnectionSupervisor {
    transport: Arc<TcpTransport>,
    /// 已有 dialer 线程的目标地址集合（去重）。
    dialing: Mutex<BTreeSet<String>>,
    /// 本节点 P2P 监听地址（跳过自拨，避免 PEX 回环）。
    own_addr: String,
    shutdown: Arc<AtomicBool>,
}

impl ConnectionSupervisor {
    fn new(transport: Arc<TcpTransport>, own_addr: String, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            transport,
            dialing: Mutex::new(BTreeSet::new()),
            own_addr,
            shutdown,
        }
    }

    /// 若 `addr` 尚无 dialer 线程，则启动一个持久拨号线程。返回是否新启动。
    ///
    /// `self` 必须位于 [`Arc`] 中：dialer 线程持有同一个 supervisor 引用，
    /// 退出时从去重集合摘除自己的地址。自身监听地址与重复地址直接跳过；
    /// dialer 总数受 [`MAX_DISCOVERED_PEERS`] 约束，防止恶意 PEX 把线程数
    /// 变成无界资源。
    fn ensure_dialing(
        self: &Arc<Self>,
        addr: String,
        node: &Arc<Node>,
        dag: &Arc<Mutex<Dag>>,
        votes: &Arc<VoteCollector>,
        gossip: &Arc<GossipManager>,
    ) -> bool {
        if addr == self.own_addr || addr.is_empty() {
            return false;
        }
        {
            let mut dialing = self.dialing.lock().unwrap_or_else(|e| e.into_inner());
            if dialing.contains(&addr) || dialing.len() >= MAX_DISCOVERED_PEERS {
                return false;
            }
            dialing.insert(addr.clone());
        }

        let supervisor = Arc::clone(self);
        let node = Arc::clone(node);
        let dag = Arc::clone(dag);
        let votes = Arc::clone(votes);
        let gossip = Arc::clone(gossip);
        let spawned = std::thread::Builder::new()
            .name("p2p-dialer".to_string())
            .spawn({
                let addr = addr.clone();
                move || {
                    run_outbound_dialer(
                        &addr,
                        Arc::clone(&supervisor.transport),
                        node,
                        dag,
                        votes,
                        gossip,
                        &supervisor,
                    );
                    // 线程退出（shutdown）：释放去重槽位。
                    supervisor
                        .dialing
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&addr);
                }
            });
        if spawned.is_err() {
            // 线程启动失败：释放去重槽位，下次仍可重试。
            self.dialing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&addr);
            return false;
        }
        true
    }
}

/// 单个出站地址的持久拨号循环（缺口：连接失败/断开无重连）。
///
/// - 连接成功后运行 [`handle_p2p_connection`] 读取循环（该函数同时把写端注册进
///   广播列表），直到连接关闭。
/// - 连接失败或关闭后按指数退避重拨（[`PEER_DIAL_INITIAL_BACKOFF`] 起、
///   [`PEER_DIAL_MAX_BACKOFF`] 封顶）；一次连接存活超过初始退避时长才重置退避，
///   避免对端立即拒绝对应的忙轮询。
fn run_outbound_dialer(
    addr: &str,
    transport: Arc<TcpTransport>,
    node: Arc<Node>,
    dag: Arc<Mutex<Dag>>,
    votes: Arc<VoteCollector>,
    gossip: Arc<GossipManager>,
    supervisor: &Arc<ConnectionSupervisor>,
) {
    let mut backoff = PEER_DIAL_INITIAL_BACKOFF;
    while !supervisor.shutdown.load(Ordering::SeqCst) {
        match transport.connect_peer(addr) {
            Ok(stream) => {
                let connected_at = std::time::Instant::now();
                info!("outbound peer {addr} 已连接，进入读取循环");
                // 阻塞直到连接关闭；handle_p2p_connection 内部已注册广播写端，
                // 并可通过 supervisor 把 PEX 学到的新地址升级为持久拨号。
                handle_p2p_connection(
                    stream,
                    Arc::clone(&node),
                    Arc::clone(&transport),
                    Arc::clone(&dag),
                    Arc::clone(&votes),
                    Arc::clone(&gossip),
                    Some(supervisor),
                );
                if connected_at.elapsed() >= PEER_DIAL_INITIAL_BACKOFF {
                    backoff = PEER_DIAL_INITIAL_BACKOFF;
                }
                info!("outbound peer {addr} 连接关闭，{backoff:?} 后重连");
            }
            Err(error) => {
                warn!("outbound peer {addr} 连接失败：{error}（{backoff:?} 后重试）");
            }
        }
        if !sleep_interruptible(backoff, &supervisor.shutdown) {
            break;
        }
        backoff = backoff.saturating_mul(2).min(PEER_DIAL_MAX_BACKOFF);
    }
}

/// 启动 / 落后 catch-up 循环（缺口：bin 从不调用 `request_blocks_by_range`，
/// 重启或落后的节点无法追上网络高度）。
///
/// 周期性行为（仅当存在已注册 peer 地址时）：
/// 1. 取本地 tip height，向任一 peer 请求 `(tip+1, tip+CHUNK]` 缺失区间；
/// 2. 收到的每个 block 都走完整 `Node::put_block` 验证（结构 + prev_hash + cert
///    验证 + 执行重放 + state_root 比对）后才入库 —— 不绕过任何共识校验；
/// 3. peer 返回空区间说明其对端不高于本节点，结束本轮。
///
/// 注意 `put_block` 严格要求 tip+1 顺序导入，gossip 乱序到达的区块会被拒绝并
/// 由下一轮 catch-up 按序补齐，因此该循环同时充当乱序区块的修复路径。
fn run_catch_up_loop(node: Arc<Node>, transport: Arc<TcpTransport>, shutdown: Arc<AtomicBool>) {
    info!("catch-up 循环已启动（间隔={}ms）", CATCH_UP_INTERVAL.as_millis());
    while !shutdown.load(Ordering::SeqCst) {
        if !sleep_interruptible(CATCH_UP_INTERVAL, &shutdown) {
            break;
        }
        if transport.peer_count() == 0 {
            continue;
        }
        for _ in 0..MAX_CATCH_UP_BATCHES_PER_TICK {
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
            let tip = node
                .block_store()
                .get_tip_height()
                .ok()
                .flatten()
                .unwrap_or(0);
            let start = tip.saturating_add(1);
            let end = start.saturating_add(CATCH_UP_CHUNK.saturating_sub(1));
            match transport.request_blocks_by_range(start, end) {
                Ok(blocks) => {
                    if blocks.is_empty() {
                        // 加入门闩置位（join-race 根治）：区间返回空 = 已追平
                        // 主网链头（或本机即创世首节点），此刻起产块不会与
                        // 主链分叉。同步中途不放行——否则 fresh 节点会在导入
                        // 主链区块的半途产出自己的 block 1，形成不可追赶的分
                        // 叉（实测每次节点重启都以该竞态孤立）。
                        CATCHUP_FIRST_ROUND.store(true, Ordering::SeqCst);
                        break;
                    }
                    let mut imported = 0usize;
                    for block in &blocks {
                        match node.put_block(block) {
                            Ok(_) => {
                                imported += 1;
                                // epoch 跟随（catch-up 版，2026-09-15）：tip cert
                                // 过 EPOCH_LENGTH 边界即推进 node epoch，否则
                                // 后续块的 cert/vertex 全被 epoch 检查拒绝、
                                // catch-up 永久卡住（实测 node1 卡 11）。
                                let tip_cert_round = block
                                    .header
                                    .dag_commit_certificate
                                    .commit_round;
                                let expected_epoch = tip_cert_round.saturating_add(EPOCH_LENGTH - 1)
                                    / EPOCH_LENGTH;
                                while node.current_epoch() < expected_epoch {
                                    let next = node.current_epoch() + 1;
                                    let vrf = VRF_SECRET.get().and_then(|v| v.as_ref());
                                    if let Err(error) =
                                        node.advance_epoch_with_vrf(next, vrf)
                                    {
                                        warn!("catch-up epoch 推进到 {next} 失败：{error}");
                                        break;
                                    }
                                }
                            }
                            Err(error) => {
                                // 典型原因：peer 返回区间稀疏导致缺父块。留给下一轮。
                                warn!(
                                    height = block.header.height,
                                    "catch-up put_block 拒绝：{error}"
                                );
                                break;
                            }
                        }
                    }
                    if imported == 0 {
                        break;
                    }
                    info!(
                        "catch-up: 从网络导入 {imported} 个区块（本地 tip {tip} → {}）",
                        node
                            .block_store()
                            .get_tip_height()
                            .ok()
                            .flatten()
                            .unwrap_or(tip)
                    );
                }
                Err(error) => {
                    debug!("catch-up 请求失败（下轮重试）：{error}");
                    break;
                }
            }
        }
    }
    info!("catch-up 循环已停止");
}

/// Load canonical proving-service sidecars named `<64-hex-job-id>.proof`.
///
/// Directory entries are untrusted local input: non-files and unrelated names
/// are ignored, while a file that claims the canonical sidecar name but is
/// oversized or malformed aborts startup rather than being served to peers.
fn load_proof_packages_from_dir(
    transport: &TcpTransport,
    directory: &std::path::Path,
) -> Result<usize, String> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        format!(
            "读取 proof package 目录 {} 失败：{error}",
            directory.display()
        )
    })?;
    let mut loaded = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "读取 proof package 目录项 {} 失败：{error}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("读取 {} 类型失败：{error}", path.display()))?;
        if !file_type.is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("proof")
        {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let job_bytes = match hex::decode(stem) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            _ => continue,
        };
        let metadata = entry
            .metadata()
            .map_err(|error| format!("读取 {} 元数据失败：{error}", path.display()))?;
        if metadata.len() == 0 || metadata.len() > MAX_PROOF_PACKAGE_BYTES as u64 {
            return Err(format!(
                "proof package {} 长度 {} 超出 1..={} 范围",
                path.display(),
                metadata.len(),
                MAX_PROOF_PACKAGE_BYTES
            ));
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("读取 {} 失败：{error}", path.display()))?;
        let mut job_id = [0u8; 32];
        job_id.copy_from_slice(&job_bytes);
        transport.register_proof_package(job_id, bytes)?;
        loaded += 1;
    }
    Ok(loaded)
}

impl NetworkTransport for TcpTransport {
    fn gossip_broadcast(&self, _topic: GossipTopic, message: &NetworkMessage) -> PokerL1Result<()> {
        let bytes = borsh::to_vec(message)?;
        let len = bytes.len() as u32;
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);

        // Do not retain the peer-list mutex while writing to the network.  A
        // slow peer then blocks only its own per-connection writer, while
        // request/response code for other connections remains live.
        let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut failed = Vec::new();
        for (i, stream) in peers.iter().enumerate() {
            let mut stream = stream.lock().unwrap_or_else(|e| e.into_inner());
            // 写超时防线（346 停滞根因）：半开/死连接的 write_all 会阻塞到
            // TCP 重传超时（可达 15 分钟+），期间持有 per-stream 写锁——
            // validator loop 的所有广播在 stream.lock() 排队，vertex 停产。
            // 超时即按失败移除，与读侧的 read timeout 对称。
            stream.set_broadcast_write_timeout();
            if let Err(e) = stream.write_all(&frame).and_then(|_| stream.flush()) {
                warn!("广播消息到 peer {i} 失败：{e}，移除连接");
                failed.push(Arc::clone(&peers[i]));
            }
        }
        if !failed.is_empty() {
            let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            peers.retain(|candidate| {
                !failed
                    .iter()
                    .any(|failed_writer| Arc::ptr_eq(candidate, failed_writer))
            });
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
            // 临时连接 + 带谓词读循环：该连接同时会收到 gossip 混流
            //（CommitVote / 出块成功时广播的最新单块 ResponseBlocks 等），
            // 一律跳过，直到读到**首块高度 == start** 的区间响应
            //（2026-09-14 346 停滞修复：此前首条非公告消息即返回，
            // gossip 单块被误当响应 → 跳跃 put_block 拒绝 → 永追不上）。
            let stream = TcpStream::connect(&peer.address);
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("request_blocks_by_range: 连接 {} 失败：{e}", peer.address);
                    continue;
                }
            };
            let _ = stream.set_read_timeout(Some(P2P_REQUEST_TIMEOUT));
            let _ = stream.set_write_timeout(Some(P2P_REQUEST_TIMEOUT));
            if let Err(e) = send_p2p_message(&mut stream, &req) {
                warn!("request_blocks_by_range: 发送失败：{e}");
                continue;
            }
            warn!(
                "request_blocks_by_range: 向 {} 请求区间 ({start},{end})",
                peer.address
            );
            let deadline = std::time::Instant::now() + P2P_REQUEST_TIMEOUT;
            let mut got_response = false;
            loop {
                if std::time::Instant::now() >= deadline {
                    warn!(
                        "request_blocks_by_range: peer {} 响应超时（30s 未收到首块={start} 的区间）",
                        peer.address
                    );
                    break;
                }
                match recv_p2p_message(&mut stream) {
                    Err(e) => {
                        warn!("request_blocks_by_range: 读取失败：{e}");
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(NetworkMessage::ResponseBlocks(mut blocks))) => {
                        warn!(
                            "request_blocks_by_range: 收到 {} 块（首块 {:?}）",
                            blocks.len(),
                            blocks.first().map(|b| b.header.height)
                        );
                        // 区间过滤：只接受首块 == start 的连续区间
                        blocks.retain(|block| {
                            block.header.height >= start && block.header.height <= end
                        });
                        blocks.sort_by_key(|block| block.header.height);
                        if blocks.first().map(|b| b.header.height) != Some(start) {
                            warn!(
                                "request_blocks_by_range: gossip 混流（首块 {:?}≠{start}），继续等",
                                blocks.first().map(|b| b.header.height)
                            );
                            continue; // gossip 单块污染 → 继续等真响应
                        }
                        debug!(
                            "request_blocks_by_range: 从 peer {} 获取 {} 个 block",
                            peer.address,
                            blocks.len()
                        );
                        return Ok(blocks);
                    }
                    Ok(Some(_)) => continue, // gossip 混流一律跳过
                }
            }
            let _ = got_response;
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
        // 恰 quorum 存活修复：合并**所有** peer 的响应（按轮升序去重），而不是取
        // 首个非空 —— 某个 peer 的 vertex 可能因作者已被罚没等原因在本地不可准入
        //（作者失格 → put_vertex 拒绝），若只取它的响应，有效 peer 的数据永远
        // 得不到补充。合并后按 (round, author, hash) 排序保证 parent 先于 child
        // 被 admission 校验。空响应的 peer（自身落后）自然贡献 0 条。
        let mut merged: Vec<DagVertex> = Vec::new();
        let mut seen: BTreeSet<Hash> = BTreeSet::new();
        let mut ok_peers = 0usize;
        for peer in &peers {
            match send_request_and_recv(&peer.address, &req) {
                Ok(NetworkMessage::ResponseVertices(vertices)) => {
                    debug!(
                        "request_vertices_by_range: 从 peer {} 获取 {} 个 vertex",
                        peer.address,
                        vertices.len()
                    );
                    ok_peers += 1;
                    for vertex in vertices {
                        let hash = vertex.vertex_hash();
                        if seen.insert(hash) {
                            merged.push(vertex);
                        }
                    }
                }
                Ok(other) => warn!(
                    "request_vertices_by_range: peer {} 返回非预期消息类型：{other:?}",
                    peer.address
                ),
                Err(e) => warn!("request_vertices_by_range: peer {} 失败：{e}", peer.address),
            }
        }
        if ok_peers == 0 {
            return Err(poker_l1::error::PokerL1Error::Other(
                "request_vertices_by_range: 所有 peer 请求失败".to_string(),
            ));
        }
        merged.sort_by(|a, b| {
            a.round
                .cmp(&b.round)
                .then_with(|| a.author_pubkey.to_bytes().cmp(&b.author_pubkey.to_bytes()))
                .then_with(|| a.vertex_hash().cmp(&b.vertex_hash()))
        });
        Ok(merged)
    }

    fn request_proof_package_manifest(
        &self,
        job_id: Hash,
    ) -> PokerL1Result<Option<ProofPackageManifest>> {
        let peers = self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if peers.is_empty() {
            return Err(poker_l1::error::PokerL1Error::Other(
                "request_proof_package_manifest: no available peer".to_string(),
            ));
        }
        let request = NetworkMessage::RequestProofPackageManifest(job_id);
        for peer in &peers {
            match send_request_and_recv(&peer.address, &request) {
                Ok(NetworkMessage::ResponseProofPackageManifest(manifest)) => {
                    if let Some(manifest) = &manifest {
                        manifest.validate()?;
                        if manifest.job_id != job_id {
                            warn!(peer = %peer.address, "proof package manifest job mismatch");
                            continue;
                        }
                    }
                    return Ok(manifest);
                }
                Ok(other) => warn!(
                    peer = %peer.address,
                    "unexpected proof package manifest response: {other:?}"
                ),
                Err(error) => warn!(
                    peer = %peer.address,
                    "proof package manifest request failed: {error}"
                ),
            }
        }
        Err(poker_l1::error::PokerL1Error::Other(
            "request_proof_package_manifest: all peers failed".to_string(),
        ))
    }

    fn request_proof_package_chunk(
        &self,
        job_id: Hash,
        package_hash: Hash,
        index: u32,
    ) -> PokerL1Result<Option<ProofPackageChunk>> {
        let peers = self
            .peer_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if peers.is_empty() {
            return Err(poker_l1::error::PokerL1Error::Other(
                "request_proof_package_chunk: no available peer".to_string(),
            ));
        }
        let request = NetworkMessage::RequestProofPackageChunk {
            job_id,
            package_hash,
            index,
        };
        for peer in &peers {
            match send_request_and_recv(&peer.address, &request) {
                Ok(NetworkMessage::ResponseProofPackageChunk(chunk)) => {
                    if let Some(chunk) = &chunk
                        && (chunk.job_id != job_id
                            || chunk.package_hash != package_hash
                            || chunk.index != index)
                    {
                        warn!(peer = %peer.address, "proof package chunk identity mismatch");
                        continue;
                    }
                    return Ok(chunk);
                }
                Ok(other) => warn!(
                    peer = %peer.address,
                    "unexpected proof package chunk response: {other:?}"
                ),
                Err(error) => warn!(
                    peer = %peer.address,
                    "proof package chunk request failed: {error}"
                ),
            }
        }
        Err(poker_l1::error::PokerL1Error::Other(
            "request_proof_package_chunk: all peers failed".to_string(),
        ))
    }

    fn subscribe_light_headers(&self) -> PokerL1Result<Vec<poker_l1::network::LightClientHeader>> {
        Ok(self
            .light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

/// 向 peer 发送请求并接收响应（临时连接，含超时）。
///
/// 用于 `request_blocks_by_range` / `request_vertices_by_range` 等请求-响应协议。
/// 创建独立连接以避免与持久 P2P 读取循环冲突。
///
/// 接收端在每条新入站连接上会立即广播 PeerExchange / LightClientHeader 公告，
/// 临时请求连接因此可能先读到无请求公告：本函数持续读取直至真正的响应，
/// 公告直接丢弃（无响应时由 socket read timeout / EOF 兜底报错）。
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
    loop {
        match recv_p2p_message(&mut stream)? {
            Some(msg) => {
                if matches!(
                    msg,
                    NetworkMessage::PeerExchange(_) | NetworkMessage::LightClientHeader(_)
                ) {
                    // 接收端在每条新入站连接上立即广播 PEX / light header 公告；
                    // 临时请求连接可能先读到公告。丢弃公告直至真正响应。
                    debug!("send_request_and_recv: 跳过无请求公告（{peer_addr}）");
                    continue;
                }
                return Ok(msg);
            }
            None => return Err("连接在响应前关闭".to_string()),
        }
    }
}

/// 发送一条 length-prefixed BCS 消息到 stream。
#[allow(dead_code)]
fn send_p2p_message<S: Write + ?Sized>(stream: &mut S, msg: &NetworkMessage) -> Result<(), String> {
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

/// Write one framed P2P message through a connection's shared write half.
///
/// The P2P handler owns the read half independently, but all messages in the
/// other direction (gossip plus request/response) pass through this lock so a
/// frame length and its payload cannot be interleaved on TCP.
fn send_p2p_message_locked(
    writer: &Arc<Mutex<Box<dyn P2pIo>>>,
    msg: &NetworkMessage,
) -> Result<(), String> {
    let mut stream = writer.lock().unwrap_or_else(|e| e.into_inner());
    send_p2p_message(&mut **stream, msg)
}

/// 接收一条 length-prefixed BCS 消息。
///
/// 返回 `Ok(None)` 表示连接已关闭（EOF）。
fn recv_p2p_message(stream: &mut impl Read) -> Result<Option<NetworkMessage>, String> {
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

/// Validate, persist, and only then expose a remotely supplied vertex to the
/// in-memory DAG used by the validator loop.
///
/// Keeping the insertion order this way is material: an invalid compact/full
/// vertex must not influence leader detection merely because it arrived before
/// its signature, parents, or transactions were checked.
/// 返回值 = 缺失的 parent hash 列表（非空 ⟺ 因缺 parent 被拒）。
///
/// 调用方（持有连接写端）应向发送方逐个请求这些 parent 的 full vertex，
/// 形成「child 被拒 → 回源拉 parent → 递归补链」的闭环——parent 到位后
/// child 由生产者的周期重播再次送入即可通过。此前缺 parent 一律直接丢弃
/// 且无人重发 child，vertex 只活在生产者本地 DAG，quorum 永远收不齐，
/// 链只能出空块（实测 tx 全部滞留）。
fn accept_p2p_vertex(node: &Node, dag: &Arc<Mutex<Dag>>, vertex: DagVertex, source: &str) -> Vec<Hash> {
    // 先自检 parent 完整性，一次性收集全部缺口（put_vertex 只报第一个）。
    let missing: Vec<Hash> = {
        let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
        vertex
            .parent_hashes
            .iter()
            .filter(|h| {
                dag_guard.get(h).is_none()
                    && node.vertex_store().get_by_hash(h).is_err()
            })
            .copied()
            .collect()
    };
    if !missing.is_empty() {
        warn!(
            "P2P {source} vertex 拒绝：缺 {} 个 parent（已回源请求补链）",
            missing.len()
        );
        return missing;
    }
    match node.put_vertex(&vertex) {
        Ok(_) => {
            let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
            dag_guard.insert(vertex);
            Vec::new()
        }
        Err(poker_l1::error::PokerL1Error::InvalidVertexEpoch {
            actual, expected,
        }) if actual > expected => {
            // epoch 跟随多数派（346 停滞修复）：本地 epoch 落后于全网（其它
            // 节点已推进并清空旧 DAG，本地缺的 parent vertex 全网不复存在，
            // vertex/commit 全部被 epoch 检查拒绝 → 永久隔离）。连续推进本地
            // epoch 到 actual 后重试准入；validator loop 检测 node epoch 变化
            // 自行清 DAG/重置 round。
            //
            // P0 加固：epoch 声明来自远端 vertex，跟随前必须先认证（author
            // 活跃 + 签名），并限制单次跟随跳变上限——否则一条未签名的
            // `epoch = u64::MAX` 消息即可驱动无界推进循环卡死节点。
            const MAX_EPOCH_FOLLOW_JUMP: u64 = 8;
            if actual - expected > MAX_EPOCH_FOLLOW_JUMP {
                warn!(
                    "P2P {source} epoch 跟随拒绝：跳变 {} 超过上限 {MAX_EPOCH_FOLLOW_JUMP}",
                    actual - expected
                );
                return Vec::new();
            }
            if !node.vertex_authentic(&vertex) {
                warn!("P2P {source} epoch 跟随拒绝：vertex 未通过认证（author/签名）");
                return Vec::new();
            }
            for next in expected + 1..=actual {
                let vrf = VRF_SECRET.get().and_then(|v| v.as_ref());
                if let Err(error) = node.advance_epoch_with_vrf(next, vrf) {
                    warn!("P2P {source} epoch 跟随推进到 {next} 失败：{error}");
                    return Vec::new();
                }
            }
            match node.put_vertex(&vertex) {
                Ok(_) => {
                    let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                    dag_guard.insert(vertex);
                }
                Err(error) => warn!("P2P {source} vertex 拒绝（epoch 跟随后）：{error}"),
            }
            Vec::new()
        }
        Err(error) => {
            warn!("P2P {source} vertex 拒绝：{error}");
            Vec::new()
        }
    }
}

/// Validate a P2P transaction through the same admission path used by the
/// previous full-transaction branch, then retain it in the bounded compact
/// relay cache only after node admission succeeds.
fn accept_p2p_transaction(node: &Node, gossip: &GossipManager, tx: Transaction, source: &str) {
    let chain_id = node.chain_id();
    if let Err(error) = validate_tx_limits(&tx) {
        warn!("P2P {source} 交易拒绝（limits）：{error}");
        return;
    }
    if let Err(error) = validate_tx_chain_id(&tx, chain_id) {
        warn!("P2P {source} 交易拒绝（chain_id）：{error}");
        return;
    }
        if let Err(error) = validate_tx_signature(&tx) {
        warn!("P2P {source} 交易拒绝（签名无效）：{error}");
        return;
    }
    // gossip 回声抑制：已见过的 tx（本地已提交/接收过）直接丢弃。vertex
    // 生产的 tx 重广播 + 对端 drain 后队列为空的组合会让同一批 tx 无限回
    // 声入池（RBF 彼时无从拦截），pending 被打到上限、出块载荷全是副本。
    if node.has_seen_tx(&tx.tx_hash()) {
        return;
    }
    // Public/ForceSync/CheckpointAnchor use the account nonce. GameTurn's
    // nonce depends on game state and remains verified during block execution.
    if tx.lane_hint != TxLane::GameTurn {
        let caller_address = derive_address(&tx.tagged_pubkey);
        let account_nonce = node
            .get_account(&caller_address)
            .ok()
            .flatten()
            .map(|account| account.nonce)
            .unwrap_or(0);
        if let Err(error) = validate_tx_nonce(&tx, account_nonce, None) {
            warn!("P2P {source} 交易拒绝（nonce）：{error}");
            return;
        }
    }

    match node.submit_tx(tx.clone()) {
        Ok(_) => {
            if let Err(error) = gossip.receive_tx(tx) {
                warn!("P2P {source} transaction 已入节点但未进入 compact-relay 缓存：{error}");
            }
        }
        Err(error) => warn!("P2P {source} submit_tx 失败：{error}"),
    }
}

/// Rebuild a full vertex from a compact relay message and the bounded local tx
/// cache. The compact-provided content hash is checked before the normal node
/// vertex validation path handles the author signature and parents.
fn reconstruct_compact_vertex(
    compact: &poker_l1::network::CompactVertex,
    gossip: &GossipManager,
) -> Result<DagVertex, String> {
    let (tx_hashes, missing) = gossip
        .receive_compact_vertex(compact)
        .map_err(|error| error.to_string())?;
    if !missing.is_empty() {
        return Err(format!(
            "{} 个 short ID 未在本地 tx cache 命中",
            missing.len()
        ));
    }
    if tx_hashes.len() != compact.tx_short_ids.len() {
        return Err("compact vertex 的已匹配 tx 数量不完整".into());
    }
    let tx_list = gossip.cached_transactions(&tx_hashes);
    if tx_list.len() != tx_hashes.len() {
        return Err("compact vertex 的 tx cache 在重建期间发生缺失".into());
    }

    let vertex = DagVertex {
        epoch: compact.epoch,
        round: compact.round,
        author_pubkey: compact.author_pubkey.clone(),
        tx_list,
        parent_hashes: compact.parent_hashes.clone(),
        author_sig: compact.author_sig.clone(),
        forced_tx_hashes: compact.forced_tx_hashes.clone(),
    };
    if vertex.vertex_hash() != compact.vertex_hash {
        return Err("compact vertex hash 与重建内容不匹配".into());
    }
    Ok(vertex)
}

/// 处理 P2P 连接（接收端）。
///
/// All compact-relay fallback messages are handled on the same connection: a
/// cache miss asks for the authenticated full vertex rather than admitting an
/// incomplete descriptor.
fn handle_p2p_connection<S: P2pIo + 'static>(
    mut stream: S,
    node: Arc<Node>,
    transport: Arc<TcpTransport>,
    dag: Arc<Mutex<Dag>>,
    votes: Arc<VoteCollector>,
    gossip: Arc<GossipManager>,
    supervisor: Option<&Arc<ConnectionSupervisor>>,
) {
    let peer_addr = stream.peer_socket_addr();
    // The read loop owns `stream`; every write path shares this cloned writer.
    // Without the shared mutex, a concurrent gossip broadcast and a direct
    // Response*/fallback reply can interleave their length-prefix frames.
    let writer = match stream.try_clone_box() {
        Ok(write_stream) => Arc::new(Mutex::new(write_stream)),
        Err(error) => {
            warn!("P2P 无法克隆写端（peer={peer_addr:?}）：{error}");
            return;
        }
    };
    transport.add_peer(Arc::clone(&writer));
    if let Err(error) = transport.broadcast_peer_exchange() {
        warn!("P2P 接入后的 PEX 广播失败：{error}");
    }
    loop {
        match recv_p2p_message(&mut stream) {
            Ok(Some(msg)) => {
                match msg {
                    NetworkMessage::DagVertex(vertex) => {
                        for missing in accept_p2p_vertex(&node, &dag, vertex, "full") {
                            // 缺 parent → 回源请求（补链闭环，见函数注释）
                            if let Err(e) = send_p2p_message_locked(
                                &writer,
                                &NetworkMessage::RequestFullVertex(missing),
                            ) {
                                warn!("P2P 请求缺失 parent 失败：{e}");
                            }
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
                        if !matches!(vote.signer_pubkey.scheme(), Ok(SignatureScheme::Secp256k1))
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
                        let vote_height = vote.height;
                        votes.add_vote(vote);
                        // 落后检测：投票携带目标 height（修复 1）。peer 投票
                        // 的 height 显著高于本地 tip → 触发区间 catch-up，
                        // 解除「epoch 落后 → vertex 被拒 → parent quorum 不足
                        // → tip 永不前进」的隔离死锁（服务器实测 node0 卡
                        // epoch 31/tip 320，其余节点 epoch 41/411）。
                        let local_tip = node
                            .block_store()
                            .get_tip_height()
                            .ok()
                            .flatten()
                            .unwrap_or(0);
                        if vote_height > local_tip + CATCHUP_LAG_THRESHOLD {
                            request_catchup_range(&transport, local_tip, vote_height);
                        }
                    }
                    NetworkMessage::CheckpointVote(vote) => {
                        // v1.5-c：checkpoint 投票（BLS 聚签）。签名有效性与
                        // **签名者成员资格**（P1：必须 ∈ 节点 BLS 注册表，防
                        // 自造全新键拼 QC）均在 record 内验证（possession +
                        // 位点一致 + 成员资格）；凑齐 2f+1 即聚合 QC 并落盘
                        // sidecar。
                        match node.record_checkpoint_vote(vote) {
                            Ok((_count, Some(qc))) => {
                                info!(
                                    "CHECKPOINT QC FORMED (peer votes) epoch={} height={} signers={}",
                                    qc.epoch,
                                    qc.height,
                                    qc.signer_count()
                                );
                            }
                            Ok((_count, None)) => {}
                            Err(e) => {
                                warn!("checkpoint vote rejected: {e}");
                            }
                        }
                    }
                    NetworkMessage::CheckpointThresholdPartial(partial) => {
                        // v1.5-e：阈值部分份额签名。验证在 record 内逐份进行
                        //（对 keyset.public_share(id) 单配对 —— 成员资格由
                        // group_key_digest ↔ 本地活跃 keyset 绑定）；凑齐 t 即
                        // Lagrange 重构装配阈值 QC 并落盘 sidecar（装配失败时
                        // 后续份额会重试，P2）。无 keyset 的节点拒绝
                        //（fail-closed；聚合模式走 CheckpointVote 路径）。
                        match node.record_threshold_partial(partial) {
                            Ok((_count, Some(qc))) => {
                                info!(
                                    "THRESHOLD QC FORMED (peer partials) epoch={} height={} mode=threshold signers={}",
                                    qc.epoch,
                                    qc.height,
                                    qc.signer_count()
                                );
                            }
                            Ok((_count, None)) => {}
                            Err(e) => {
                                warn!("threshold partial rejected: {e}");
                            }
                        }
                    }
                    NetworkMessage::DaReceipt(receipt) => {
                        // v1.5-d：DA 回执（validator 侧可用性签名）。签名有效
                        // 性与**签名者成员资格**（P1：必须 ∈ 节点 BLS 注册表，
                        // 防自造全新键拼凭证）均在 record 内验证。
                        if let Err(e) = node.record_da_receipt(receipt) {
                            warn!("da receipt rejected: {e}");
                        }
                    }
                    NetworkMessage::PeerExchange(peers) => {
                        // 缺口 #5：Peer Discovery / PEX —— 合并发现的 peer。
                        let new_addresses = transport.merge_discovered_peers(&peers);
                        // 缺口：PEX 学到的地址不再只用于临时请求 —— 自动升级为
                        // 持久广播连接（supervisor 以地址去重，已拨号的跳过）。
                        if let Some(supervisor) = supervisor {
                            for addr in &new_addresses {
                                supervisor.ensure_dialing(
                                    addr.clone(),
                                    &node,
                                    &dag,
                                    &votes,
                                    &gossip,
                                );
                            }
                        }
                        // 仅在学到新地址时转发，避免 PEX 回声风暴（与原行为一致）。
                        if !new_addresses.is_empty()
                            && let Err(error) = transport.broadcast_peer_exchange()
                        {
                            warn!("P2P 转发新增 PEX 结果失败：{error}");
                        }
                    }
                    NetworkMessage::Transaction(tx) => {
                        accept_p2p_transaction(&node, &gossip, tx, "transaction");
                    }
                    NetworkMessage::ResponseBlocks(blocks) => {
                        for block in blocks {
                            if let Err(e) = node.put_block(&block) {
                                warn!("P2P put_block 失败：{e}");
                            } else {
                                transport.publish_light_headers_from_node(&node);
                            }
                        }
                    }
                    NetworkMessage::ResponseVertices(vertices) => {
                        for vertex in vertices {
                            for missing in
                                accept_p2p_vertex(&node, &dag, vertex, "range-response")
                            {
                                if let Err(e) = send_p2p_message_locked(
                                    &writer,
                                    &NetworkMessage::RequestFullVertex(missing),
                                ) {
                                    warn!("P2P 请求缺失 parent 失败：{e}");
                                }
                            }
                        }
                    }
                    NetworkMessage::RequestBlocksByRange(start, end) => {
                        info!("收到 RequestBlocksByRange({}, {}) — 回送区间", start, end);
                        // 重构2：响应 block range 请求
                        let blocks = collect_blocks_by_range(&node, start, end);
                        info!("回送 ResponseBlocks {} 块", blocks.len());
                        if let Err(e) = send_p2p_message_locked(
                            &writer,
                            &NetworkMessage::ResponseBlocks(blocks),
                        ) {
                            warn!("P2P 回送 ResponseBlocks 失败：{e}");
                        }
                    }
                    NetworkMessage::RequestVerticesByRange(start_round, end_round) => {
                        let vertices = collect_vertices_by_round(&dag, start_round, end_round);
                        if let Err(e) = send_p2p_message_locked(
                            &writer,
                            &NetworkMessage::ResponseVertices(vertices),
                        ) {
                            warn!("P2P 回送 ResponseVertices 失败：{e}");
                        }
                    }
                    NetworkMessage::RequestProofPackageManifest(job_id) => {
                        let bytes = transport
                            .proof_packages
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&job_id)
                            .cloned();
                        let manifest = bytes.as_deref().and_then(|bytes| {
                            match build_proof_package_manifest(job_id, bytes) {
                                Ok(manifest) => Some(manifest),
                                Err(error) => {
                                    warn!("local proof package rejected before serving: {error}");
                                    None
                                }
                            }
                        });
                        if let Err(error) = send_p2p_message_locked(
                            &writer,
                            &NetworkMessage::ResponseProofPackageManifest(manifest),
                        ) {
                            warn!("P2P proof package manifest response failed: {error}");
                        }
                    }
                    NetworkMessage::RequestProofPackageChunk {
                        job_id,
                        package_hash,
                        index,
                    } => {
                        let bytes = transport
                            .proof_packages
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(&job_id)
                            .cloned();
                        let chunk = bytes.as_deref().and_then(|bytes| {
                            let manifest = match build_proof_package_manifest(job_id, bytes) {
                                Ok(manifest) => manifest,
                                Err(error) => {
                                    warn!("local proof package rejected before serving: {error}");
                                    return None;
                                }
                            };
                            if manifest.package_hash != package_hash {
                                return None;
                            }
                            match build_proof_package_chunk(&manifest, bytes, index) {
                                Ok(chunk) => Some(chunk),
                                Err(error) => {
                                    debug!("proof package chunk unavailable: {error}");
                                    None
                                }
                            }
                        });
                        if let Err(error) = send_p2p_message_locked(
                            &writer,
                            &NetworkMessage::ResponseProofPackageChunk(chunk),
                        ) {
                            warn!("P2P proof package chunk response failed: {error}");
                        }
                    }
                    NetworkMessage::ResponseProofPackageManifest(_)
                    | NetworkMessage::ResponseProofPackageChunk(_) => {
                        debug!("unsolicited proof package response ignored");
                    }
                    NetworkMessage::CompactVertex(compact) => {
                        match reconstruct_compact_vertex(&compact, &gossip) {
                            Ok(vertex) => {
                                for missing in accept_p2p_vertex(&node, &dag, vertex, "compact") {
                                if let Err(e) = send_p2p_message_locked(
                                    &writer,
                                    &NetworkMessage::RequestFullVertex(missing),
                                ) {
                                    warn!("P2P 请求缺失 parent 失败：{e}");
                                }
                            }
                            }
                            Err(error) => {
                                // A cache miss or a short-id collision never creates a partial
                                // vertex. Ask the sender for the signed full fallback instead.
                                debug!("CompactVertex 重建失败（请求 full fallback）：{error}");
                                if let Err(send_error) = send_p2p_message_locked(
                                    &writer,
                                    &NetworkMessage::RequestFullVertex(compact.vertex_hash),
                                ) {
                                    warn!(
                                        "P2P 请求 CompactVertex full fallback 失败：{send_error}"
                                    );
                                }
                            }
                        }
                    }
                    NetworkMessage::RequestTx(hashes) => {
                        let transactions = gossip.cached_transactions(&hashes);
                        if let Err(error) = send_p2p_message_locked(
                            &writer,
                            &NetworkMessage::ResponseTx(transactions),
                        ) {
                            warn!("P2P 回送 ResponseTx 失败：{error}");
                        }
                    }
                    NetworkMessage::ResponseTx(transactions) => {
                        for transaction in transactions {
                            accept_p2p_transaction(&node, &gossip, transaction, "response-tx");
                        }
                    }
                    NetworkMessage::RequestFullVertex(vertex_hash) => {
                        let vertex = {
                            let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                            dag_guard.get(&vertex_hash).cloned()
                        }
                        .or_else(|| node.vertex_store().get_by_hash(&vertex_hash).ok());
                        if let Some(vertex) = vertex {
                            if let Err(error) = send_p2p_message_locked(
                                &writer,
                                &NetworkMessage::ResponseFullVertex(vertex),
                            ) {
                                warn!("P2P 回送 ResponseFullVertex 失败：{error}");
                            }
                        } else {
                            debug!(hash = %hex::encode(vertex_hash), "请求的 full vertex 不在本地");
                        }
                    }
                    NetworkMessage::ResponseFullVertex(vertex) => {
                        for missing in accept_p2p_vertex(&node, &dag, vertex, "full-fallback") {
                            if let Err(e) = send_p2p_message_locked(
                                &writer,
                                &NetworkMessage::RequestFullVertex(missing),
                            ) {
                                warn!("P2P 请求缺失 parent 失败：{e}");
                            }
                        }
                    }
                    NetworkMessage::LightClientHeader(header) => {
                        // 收到 peer 的 light client header（validator 多签背书），
                        // 合并到本地缓存（多 validator 签名合并）。
                        let changed = transport.merge_light_header(header.clone());
                        node.merge_light_header(header.clone());
                        // Forward only newly learned signatures, avoiding P2P echo loops while
                        // letting a multi-hop light client collect the complete quorum.
                        if changed
                            && let Err(error) = transport.gossip_broadcast(
                                GossipTopic::DagVertex,
                                &NetworkMessage::LightClientHeader(header),
                            )
                        {
                            warn!("P2P 转发 LightClientHeader 失败：{error}");
                        }
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
    if start > end {
        return Vec::new();
    }
    let capped_end = end.min(start.saturating_add(MAX_BLOCK_RANGE_HEIGHTS - 1));
    let mut blocks = Vec::new();
    for height in start..=capped_end {
        match node.get_block_by_height(height) {
            Ok(Some(block)) => blocks.push(block),
            Ok(None) => debug!("collect_blocks: height {height} 无 block"),
            Err(e) => warn!("collect_blocks: 查询 height {height} 失败：{e}"),
        }
    }
    blocks
}

/// Collect the current DAG's full vertices for an inclusive round range.
///
/// `RequestVerticesByRange` has no epoch field.  The in-memory DAG is intentionally scoped to
/// the active epoch and is reset after commit, so it is the authoritative answer for this wire
/// request.  A bounded scan prevents a peer from turning a sparse, enormous range into CPU work.
fn collect_vertices_by_round(
    dag: &Arc<Mutex<Dag>>,
    start_round: u64,
    end_round: u64,
) -> Vec<DagVertex> {
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

/// 恰 quorum 存活修复：投影结果三分支。
enum CommitProjectionOutcome {
    /// 投影就绪：(规范未提交序, 投影顶点)。
    Ready(Vec<Hash>, Vec<DagVertex>),
    /// 本地缺失未提交祖先 —— 携带需要定向补洞的轮次区间（min_round, max_round）。
    MissingVertices(u64, u64),
    /// leader 的全部祖先均已提交 → 无可投影内容（空投影，弃权）。
    Empty,
}

/// Resolve one Bullshark leader into the canonical, not-yet-committed projection.
///
/// Committed vertices remain in the in-memory DAG because later rounds reference them.  The
/// committed frontier therefore has to be applied before building a block, otherwise an old
/// ancestor's transactions would be replayed in every later commit.
///
/// 恰 quorum 存活修复：投影遍历不降入已提交 vertex（committed 集祖先封闭），
/// 本地 DAG 缺历史 round 不再导致永久投影失败；未提交区缺口经
/// [`CommitProjectionOutcome::MissingVertices`] 上报，由调用方定向补洞
/// （RequestVerticesByRange）后收敛，而非签出分裂票或永久弃权。
fn canonical_commit_projection(
    dag: &Dag,
    leader: &poker_l1::consensus::CommitLeader,
    committed_vertices: &BTreeSet<Hash>,
) -> CommitProjectionOutcome {
    let attempt = attempt_commit_projection(
        dag,
        &leader.referencing_hashes,
        committed_vertices,
        leader.leader_round.saturating_add(1),
    );
    if !attempt.missing.is_empty() {
        let min_round = attempt.missing.iter().map(|(_, round)| *round).min().unwrap_or(1);
        let max_round = attempt.missing.iter().map(|(_, round)| *round).max().unwrap_or(1);
        return CommitProjectionOutcome::MissingVertices(min_round, max_round);
    }
    let ordered_hashes = attempt.ordered_hashes;
    if ordered_hashes.is_empty() {
        return CommitProjectionOutcome::Empty;
    }
    let mut vertices = Vec::with_capacity(ordered_hashes.len());
    for hash in &ordered_hashes {
        match dag.get(hash) {
            Some(vertex) => vertices.push(vertex.clone()),
            None => return CommitProjectionOutcome::Empty,
        }
    }
    CommitProjectionOutcome::Ready(ordered_hashes, vertices)
}

/// 收集 `ref_round` 轮全部不同 author 的 vertex 作为 parents（含自身 author），
/// 并检测该轮预定 leader（wave-3 轮转）是否在场。
fn collect_round_parents_with_leader(
    dag_guard: &Dag,
    node: &Node,
    ref_round: u64,
) -> (Vec<Hash>, bool) {
    let mut seen_authors: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut parents: Vec<Hash> = Vec::new();
    let mut leader_included = false;
    let sorted_v = node.active_validator_pubkeys_sorted();
    let leader_bytes = sorted_v
        .get(round_leader_index(ref_round, sorted_v.len().max(1)))
        .map(|pk| pk.to_bytes());
    for vh in dag_guard.round_vertices(ref_round) {
        if let Some(v) = dag_guard.get(vh) {
            let author_bytes = v.author_pubkey.to_bytes();
            if node.is_active_validator(&v.author_pubkey)
                && seen_authors.insert(author_bytes.clone())
            {
                if Some(&author_bytes) == leader_bytes.as_ref() {
                    leader_included = true;
                }
                parents.push(*vh);
            }
        }
    }
    (parents, leader_included)
}

/// 恰 quorum 修复 · 定向补洞：向 peer 请求 [min_round, max_round] 轮的 vertex，
/// 经完整 admission 校验（put_vertex）后补入本地 live DAG。500ms 限频。
fn repair_missing_vertices(
    transport: &TcpTransport,
    dag: &Arc<Mutex<Dag>>,
    node: &Node,
    min_round: u64,
    max_round: u64,
    last_repair: &mut Option<std::time::Instant>,
) {
    let now = std::time::Instant::now();
    if let Some(previous) = last_repair {
        if now.duration_since(*previous) < Duration::from_millis(500) {
            return;
        }
    }
    *last_repair = Some(now);
    match transport.request_vertices_by_range(min_round, max_round) {
        Ok(vertices) => {
            let mut accepted = 0usize;
            for vertex in vertices {
                // accept_p2p_vertex：validate + persist + 写入 live DAG。
                let hash = vertex.vertex_hash();
                match node.put_vertex(&vertex) {
                    Ok(_) => {
                        let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                        dag_guard.insert(vertex);
                        accepted += 1;
                    }
                    Err(error) => {
                        // 恰 quorum 修复 · 可观测性：补洞被拒即视角无法收敛的根因信号
                        //（作者失格 / parent 缺失 / epoch 不合），必须可见。
                        warn!(
                            vertex = %hex::encode(hash),
                            round = vertex.round,
                            "vertex 定向补洞被拒：{error}"
                        );
                    }
                }
            }
            info!(
                min_round,
                max_round,
                accepted,
                "vertex 定向补洞完成（commit 投影缺口修复）"
            );
        }
        Err(error) => warn!("vertex 定向补洞请求失败：{error}"),
    }
}

/// Derive the canonical execution result shared by commit votes and final block construction.
///
/// The two transaction lanes are storage commitments only; execution always replays the single
/// R4-M4 ordered sequence.  This function is deliberately the only producer-side path used to
/// compute the certificate roots and state root.
fn derive_commit_execution(
    vertices: &[DagVertex],
    leader: &DagVertex,
    node: &Node,
    height: u64,
) -> Result<
    (
        Vec<Transaction>,
        Vec<Transaction>,
        poker_l1::executor::BlockExecutionOutcome,
        u64,
    ),
    String,
> {
    if vertices.is_empty() {
        return Err("cannot execute an empty Bullshark projection".into());
    }
    if vertices.iter().any(|vertex| vertex.epoch != leader.epoch) {
        return Err("Bullshark projection crosses an epoch boundary".into());
    }
    // v1.5-a2：forced 集以 commit 投影内 vertex 载荷的并集为准（共识数据），
    // 不再读出块节点本地 force_include 状态 —— 所有 validator 对同一投影
    // 推导出同一 forced 集，消除本地状态不一致导致的排序分叉。
    let forced_hashes = poker_l1::consensus::commit_forced_union(vertices);
    if !forced_hashes.is_empty() {
        info!(
            "commit_forced_union: {} 个 forced hash 来自 vertex 载荷（{} 个 vertex，共识数据而非节点本地状态）",
            forced_hashes.len(),
            vertices.len()
        );
    }
    let vertex_txs: Vec<Vec<Transaction>> = vertices
        .iter()
        .map(|vertex| vertex.tx_list.clone())
        .collect();
    let sorted_txs = sort_commit_txs_r4m4_with_force_include(vertex_txs, &forced_hashes);
    let mut public_txs = Vec::new();
    let mut gameturn_txs = Vec::new();
    for tx in &sorted_txs {
        match tx.lane_hint {
            TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn_txs.push(tx.clone()),
            _ => public_txs.push(tx.clone()),
        }
    }
    let timestamp_ms = consensus_block_timestamp(node, height)?;
    let proposer = vertices
        .first()
        .map(|vertex| poker_l1::account::derive_address(&vertex.author_pubkey))
        .ok_or_else(|| "cannot derive proposer for an empty projection".to_string())?;
    let env = node
        .execution_environment(height, timestamp_ms)
        .with_proposer(proposer);
    let outcome = node
        .simulate_block_execution(&env, &sorted_txs)
        .map_err(|e| format!("execute_block failed: {e}"))?;
    Ok((public_txs, gameturn_txs, outcome, timestamp_ms))
}

/// 计算待出块 commit certificate 的 `signing_hash`（缺口 #3：多 validator 投票对象）。
///
/// Votes commit to the complete canonical projection, not merely the leader vertex.  Every
/// honest validator therefore signs the same vertex list, lane roots, and post-state root.
fn compute_cert_signing_hash(
    vertices: &[DagVertex],
    ordered_hashes: &[Hash],
    leader: &DagVertex,
    chain_id: poker_l1::ChainId,
    epoch: u64,
    commit_round: u64,
    prev_commit_hash: Hash,
    node: &Node,
    height: u64,
) -> Result<Hash, String> {
    let (public_txs, gameturn_txs, outcome, _) =
        derive_commit_execution(vertices, leader, node, height)?;
    let public_tx_root = poker_l1::block::compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = poker_l1::block::compute_tx_merkle_root(&gameturn_txs);
    let cert = DagCommitCertificate {
        epoch,
        commit_round,
        prev_commit_hash,
        vertex_hash_list: ordered_hashes.to_vec(),
        round_attendance_bitmap: vec![0xFF],
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        signature_list: vec![],
        signer_bitmap: vec![0x00],
    };
    Ok(cert.signing_hash(chain_id))
}

/// 单 validator 引导期：从完整 Bullshark 投影构造 block、自签 cert、入链并广播。
#[allow(clippy::too_many_arguments)]
fn commit_and_finalize_block(
    commit_vertices: &[DagVertex],
    ordered_hashes: &[Hash],
    leader: &DagVertex,
    node: &Node,
    secret_key: &secp256k1::SecretKey,
    chain_id: poker_l1::ChainId,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    transport: &TcpTransport,
    dag: &Arc<Mutex<Dag>>,
    committed_vertices: &mut BTreeSet<Hash>,
    commit_round_out: &mut u64,
    prev_commit_hash_out: &mut Hash,
    prev_block_hash_out: &mut Hash,
) -> bool {
    match build_block_from_commit_projection(
        commit_vertices,
        ordered_hashes,
        leader,
        chain_id,
        commit_round,
        prev_commit_hash,
        prev_block_hash,
        height,
        node,
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
                    transport.publish_light_headers_from_node(node);
                    *commit_round_out += 1;
                    *prev_commit_hash_out = block.header.dag_commit_certificate.signing_hash(chain_id);
                    *prev_block_hash_out = block_hash;
                    committed_vertices.extend(ordered_hashes.iter().copied());
                    let _ = dag;
                    true
                }
                Err(e) => {
                    error!("put_block 失败：{e}");
                    false
                }
            }
        }
        Err(e) => {
            error!("build_block_from_commit_projection 失败：{e}");
            false
        }
    }
}

/// 多 validator：用收集到的 ≥2/3 签名组装完整投影的 cert 并入链。
#[allow(clippy::too_many_arguments)]
fn commit_and_finalize_block_multi(
    commit_vertices: &[DagVertex],
    ordered_hashes: &[Hash],
    leader: &DagVertex,
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
    committed_vertices: &mut BTreeSet<Hash>,
    commit_round_out: &mut u64,
    prev_commit_hash_out: &mut Hash,
    prev_block_hash_out: &mut Hash,
) -> bool {
    let (public_txs, gameturn_txs, outcome, timestamp_ms) =
        match derive_commit_execution(commit_vertices, leader, node, height) {
            Ok(result) => result,
            Err(e) => {
                error!("multi: execute_block 失败：{e}");
                return false;
            }
        };
    let public_tx_root = poker_l1::block::compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = poker_l1::block::compute_tx_merkle_root(&gameturn_txs);
    // 组装含 2/3 多签的 cert。
    let cert = match assemble_commit_certificate(
        epoch,
        commit_round,
        prev_commit_hash,
        ordered_hashes.to_vec(),
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
            return false;
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
            transport.publish_light_headers_from_node(node);
            *commit_round_out += 1;
            *prev_commit_hash_out = block.header.dag_commit_certificate.signing_hash(chain_id);
            *prev_block_hash_out = block_hash;
            committed_vertices.extend(ordered_hashes.iter().copied());
            let _ = dag;
            true
        }
        Err(e) => {
            error!("multi: put_block 失败：{e}");
            if e.to_string().contains("already committed") {
                request_authoritative_block(transport, block.header.height);
            }
            false
        }
    }
}

/// put_block 同高度冲突后的恢复：向全网广播 `RequestBlocksByRange(h, h)`
/// 拉取已提交的权威块（提交成功方会广播 ResponseBlocks / 响应范围请求）。
/// 同一 height 的请求按退避限频，避免装配重试期间的请求风暴。
/// 落后节点 catch-up：本地 tip 落后 peer 广播的 vote.height 超过阈值时，
/// 拉取 (tip, observed] 的区块区间（ResponseBlocks 经 put_block 幂等接受：
/// 多签 cert 验证 + 状态重放）。tip 推进后 epoch 推进条件自然满足，
/// 解除「epoch 落后 → vertex 被拒 → parent quorum 不够 → tip 永不前进」
/// 的隔离死锁。按 end 高度退避限频。
fn request_catchup_range(transport: &TcpTransport, start: u64, end: u64) {
    static LAST: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    let map = LAST.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let now = std::time::Instant::now();
    let should = {
        let mut guard = match map.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match guard.get(&end) {
            Some(at) if now.duration_since(*at) < BLOCK_CONFLICT_REQUEST_BACKOFF => false,
            _ => {
                guard.insert(end, now);
                true
            }
        }
    };
    if should {
        warn!(
            "本地 tip 落后 peer 投票高度 {end} — 广播 RequestBlocksByRange({},{end}) catch-up",
            start + 1
        );
        if let Err(e) = transport.gossip_broadcast(
            GossipTopic::DagVertex,
            &NetworkMessage::RequestBlocksByRange(start + 1, end),
        ) {
            warn!("catch-up RequestBlocksByRange 广播失败：{e}");
        }
    }
}

fn request_authoritative_block(transport: &TcpTransport, height: u64) {
    static LAST_REQUEST: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<u64, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    let map = LAST_REQUEST.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let now = std::time::Instant::now();
    let should_request = {
        let mut guard = match map.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match guard.get(&height) {
            Some(at) if now.duration_since(*at) < BLOCK_CONFLICT_REQUEST_BACKOFF => false,
            _ => {
                guard.insert(height, now);
                true
            }
        }
    };
    if should_request {
        warn!(
            "height {height} 与本地已提交块冲突 — 广播 RequestBlocksByRange 拉取权威块（catch-up）"
        );
        if let Err(e) = transport.gossip_broadcast(
            GossipTopic::DagVertex,
            &NetworkMessage::RequestBlocksByRange(height, height),
        ) {
            warn!("RequestBlocksByRange 广播失败：{e}");
        }
    }
}

/// 从完整 Bullshark commit projection 构造 block。
fn build_block_from_commit_projection(
    vertices: &[DagVertex],
    ordered_hashes: &[Hash],
    leader: &DagVertex,
    chain_id: poker_l1::ChainId,
    commit_round: u64,
    prev_commit_hash: Hash,
    prev_block_hash: Hash,
    height: u64,
    node: &Node,
    secret_key: &secp256k1::SecretKey,
) -> Result<Block, String> {
    if vertices.is_empty() || vertices.len() != ordered_hashes.len() {
        return Err("commit projection vertices and hashes have different lengths".into());
    }
    for (vertex, hash) in vertices.iter().zip(ordered_hashes) {
        if vertex.vertex_hash() != *hash {
            return Err("commit projection hash does not match vertex contents".into());
        }
    }
    let previous_state_root = node.state_root();
    let (public_txs, gameturn_txs, outcome, timestamp_ms) =
        derive_commit_execution(vertices, leader, node, height)?;
    if outcome.state_root == previous_state_root
        && !(public_txs.is_empty() && gameturn_txs.is_empty())
    {
        warn!(
            "执行 {} 笔 tx 后 state_root 未变化（可能全部失败或为无状态 tx）",
            public_txs.len() + gameturn_txs.len()
        );
    }
    let public_tx_root = compute_tx_merkle_root(&public_txs);
    let gameturn_tx_root = compute_tx_merkle_root(&gameturn_txs);
    let cert = DagCommitCertificate {
        epoch: leader.epoch,
        commit_round,
        prev_commit_hash,
        vertex_hash_list: ordered_hashes.to_vec(),
        round_attendance_bitmap: vec![0xFF],
        state_root: outcome.state_root,
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
        state_root: outcome.state_root,
        public_tx_root,
        gameturn_tx_root,
        dag_commit_certificate: cert,
    };

    Ok(Block::new(header, public_txs, gameturn_txs))
}

/// 把 `(last_folded_height, tip]` 区间内每个区块 cert 的 `vertex_hash_list` 并入
/// committed 集合。
///
/// 区块无论来自本地 commit 还是从 peer gossip / catch-up 导入，tip 前进后都必须把
/// cert 覆盖的 vertex 标记为已提交；否则 Bullshark 投影会把它们再次纳入 commit，
/// 造成重复执行 / 各节点 cert hash 不一致（投票永远凑不齐 quorum）。
/// 每次调用有界处理，避免长时间阻塞产出循环。
fn fold_committed_vertices(
    node: &Node,
    committed_vertices: &mut BTreeSet<Hash>,
    last_folded_height: &mut u64,
) {
    const MAX_FOLD_PER_CALL: u64 = 256;
    let tip = match node.block_store().get_tip_height() {
        Ok(Some(tip)) => tip,
        _ => return,
    };
    let mut processed = 0u64;
    while *last_folded_height < tip && processed < MAX_FOLD_PER_CALL {
        let next = *last_folded_height + 1;
        match node.block_store().get_by_height(next) {
            Ok(block) => {
                committed_vertices.extend(
                    block
                        .header
                        .dag_commit_certificate
                        .vertex_hash_list
                        .iter()
                        .copied(),
                );
                *last_folded_height = next;
            }
            Err(_) => break, // 稀缺缺口留给下一轮（put_block 保证 tip 连续，正常不发生）
        }
        processed += 1;
    }
}

/// validator 产块循环（后台线程）。
///
/// 单 validator 自闭环模式：
/// 1. 每 `block_interval` 从 `pending_tx` 取 tx 组装 vertex
/// 2. secp256k1 签名 vertex → `dag.insert` + `node.put_vertex` + P2P 广播
/// 3. 从第 2 轮起，当前 vertex 引用上一轮 vertex → 自动满足 quorum(1) → commit
/// 4. 构造 block → `node.put_block` + P2P 广播
/// v1.5-c：checkpoint 间隔触发 —— validator 对 tip 签发 BLS checkpoint 投票，
/// 本地记录并 gossip（各节点独立收集 2f+1 后聚合 QC 并落盘 sidecar）。
fn maybe_sign_and_gossip_checkpoint(
    node: &Node,
    bls_sk: &poker_l1::consensus::checkpoint::BlsSecretKey,
    transport: &TcpTransport,
    signed_checkpoints: &mut BTreeSet<(u64, u64)>,
) {
    use poker_l1::consensus::checkpoint::CheckpointVote;
    let Some((epoch, height, state_root)) = node.checkpoint_target() else {
        return;
    };
    // 本节点已签过该位点 → 不重复签发/广播
    if signed_checkpoints.contains(&(epoch, height)) {
        return;
    }
    let vote = match CheckpointVote::sign(epoch, height, state_root, bls_sk) {
        Ok(v) => v,
        Err(e) => {
            warn!("checkpoint vote 签名失败（epoch={epoch} height={height}）：{e}");
            return;
        }
    };
    signed_checkpoints.insert((epoch, height));
    match node.record_checkpoint_vote(vote.clone()) {
        Ok((_count, Some(qc))) => {
            info!(
                "CHECKPOINT QC FORMED epoch={} height={} signers={} agg_sig={} — 已落盘 checkpoints.jsonl",
                qc.epoch,
                qc.height,
                qc.signer_count(),
                hex::encode(&qc.agg_signature_g1)
            );
        }
        Ok((count, None)) => {
            debug!(
                "checkpoint vote 已记录 epoch={epoch} height={height} collected={count}"
            );
        }
        Err(e) => {
            warn!("checkpoint vote 记录失败（epoch={epoch} height={height}）：{e}");
            return;
        }
    }
    if let Err(e) = transport.gossip_broadcast(
        GossipTopic::Checkpoint,
        &NetworkMessage::CheckpointVote(vote),
    ) {
        warn!("checkpoint vote 广播失败：{e}");
    }
}

/// v1.5-e：阈值形态 checkpoint 触发 —— validator 对 tip 已覆盖的最新间隔边界
/// 用 DKG 群份额签发部分签名 `σ_i = x_i·H(m)`，本地记录并 gossip（各节点独立
/// 收集 ≥ t 份后经 Lagrange 重构装配阈值 QC 并落盘 sidecar）。
///
/// 与聚合路径（[`maybe_sign_and_gossip_checkpoint`]）二选一：由节点
/// `qc_threshold_t` 配置分派（0 = 聚合零回退；> 0 = 阈值）。
fn maybe_sign_and_gossip_checkpoint_threshold(
    node: &Node,
    transport: &TcpTransport,
    signed_sites: &mut BTreeSet<(u64, u64)>,
) {
    use poker_l1::consensus::checkpoint::ThresholdQcPartial;
    let Some((epoch, height, state_root)) = node.checkpoint_target() else {
        return;
    };
    // 本节点已签过该位点 → 不重复签发/广播
    if signed_sites.contains(&(epoch, height)) {
        return;
    }
    let Some(dkg_share) = node.dkg_share() else {
        return; // 无群份额（非阈值参与者）→ 只收集不签发
    };
    let signing_hash = poker_l1::consensus::checkpoint::checkpoint_qc_signing_hash(
        epoch, height, state_root,
    );
    let sig = match dkg_share.partial_sign(&signing_hash) {
        Ok(s) => s,
        Err(e) => {
            warn!("threshold partial 签名失败（epoch={epoch} height={height}）：{e}");
            return;
        }
    };
    let partial = ThresholdQcPartial {
        epoch,
        height,
        state_root,
        participant_id: dkg_share.id,
        sig_g1: sig.to_vec(),
    };
    signed_sites.insert((epoch, height));
    match node.record_threshold_partial(partial.clone()) {
        Ok((_count, Some(qc))) => {
            info!(
                "THRESHOLD QC FORMED epoch={} height={} mode=threshold signers={} t={} group_digest=0x{} — 已落盘 checkpoints.jsonl",
                qc.epoch,
                qc.height,
                qc.signer_count(),
                node.qc_threshold_t(),
                qc.threshold
                    .as_ref()
                    .map(|t| hex::encode(t.group_key_digest))
                    .unwrap_or_default(),
            );
        }
        Ok((count, None)) => {
            debug!(
                "threshold partial 已记录 epoch={epoch} height={height} collected={count}/{}",
                node.qc_threshold_t()
            );
        }
        Err(e) => {
            warn!("threshold partial 记录失败（epoch={epoch} height={height}）：{e}");
            return;
        }
    }
    if let Err(e) = transport.gossip_broadcast(
        GossipTopic::Checkpoint,
        &NetworkMessage::CheckpointThresholdPartial(partial),
    ) {
        warn!("threshold partial 广播失败：{e}");
    }
}

/// v1.5-c：fork-anchor 检测 —— commit tip 落后最后 QC checkpoint 超过
/// `max_lag_blocks` 时告警（分叉/数据缺失原语，watcher 精神的接线点）。
fn maybe_warn_fork_anchor(node: &Node, max_lag_blocks: u64) {
    use poker_l1::consensus::checkpoint::{ForkAnchorStatus, check_fork_anchor};
    let qc_height = node.latest_checkpoint_qc().map(|qc| qc.height);
    let tip = node
        .block_store()
        .get_tip_height()
        .ok()
        .flatten()
        .unwrap_or(0);
    match check_fork_anchor(qc_height, tip, max_lag_blocks) {
        ForkAnchorStatus::Anchored => {}
        ForkAnchorStatus::Lagging => debug!(
            "fork-anchor: commit tip {tip} 落后 checkpoint 高度 {}（窗口内，容忍）",
            qc_height.unwrap_or(0)
        ),
        ForkAnchorStatus::Diverged => warn!(
            "FORK ANCHOR WARNING: commit tip {tip} 落后最后 checkpoint QC 高度 {} 超过 {max_lag_blocks} 块 — 可能分叉或数据缺失",
            qc_height.unwrap_or(0)
        ),
    }
}

/// validator VRF 私钥的进程级共享：epoch 跟随（accept 线程推进 epoch）与
/// validator loop 都需要它（advance_epoch_with_vrf 的 randomness 派生）。
static VRF_SECRET: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();
/// 加入门闩（join-race 根治）：catch-up 循环完成至少一次成功 peer 请求后
/// 置位。validator 产块循环启动前等待它（有 peers 时）——否则 fresh 节点
/// 会在同步到主链之前就产出自己的 block 1，形成无法追赶的分叉（实测每次
/// 节点重启都以该竞态孤立）。
static CATCHUP_FIRST_ROUND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn run_validator_loop(
    node: Arc<Node>,
    validator_key: ValidatorKey,
    chain_id: poker_l1::ChainId,
    dag: Arc<Mutex<Dag>>,
    votes: Arc<VoteCollector>,
    transport: Arc<TcpTransport>,
    gossip: Arc<GossipManager>,
    block_interval: Duration,
    shutdown: Arc<AtomicBool>,
) {
    // 缺口 #3 §3.6：提取 VRF 私钥（若配置），用于 epoch_randomness 派生。
    let vrf_secret: Option<[u8; 32]> = validator_key.vrf_secret;
    let _ = VRF_SECRET.set(vrf_secret);
    // 从 ValidatorKey 提取 secp256k1 SecretKey
    let secret_key = match secp256k1::SecretKey::from_slice(&validator_key.secret_key_bytes) {
        Ok(sk) => sk,
        Err(e) => {
            error!("validator 私钥无效：{e}");
            return;
        }
    };
    let author_pubkey = validator_key.tagged_pubkey.clone();

    // v1.5-c：BLS 密钥由 validator secp 私钥域分隔派生（原型口径；阈值/DKG
    // 接入点见 consensus::checkpoint 模块头）。
    let bls_sk = poker_l1::consensus::checkpoint::bls_derive_secret_key(
        &validator_key.secret_key_bytes,
    );
    // 本节点已签署的 checkpoint 位点（(epoch, height)；防同一 tick 重复签发/广播）
    let mut signed_checkpoints: BTreeSet<(u64, u64)> = BTreeSet::new();
    // v1.5-e：阈值形态同款去重集（阈值模式 t>0 时使用）
    let mut signed_threshold_sites: BTreeSet<(u64, u64)> = BTreeSet::new();

    let mut epoch = node.current_epoch();
    // 重启恢复：round 必须越过本节点重启前已产出的最高 DAG round——
    // 否则重启后同 author 同 round 重产 vertex 触发 equivocation，节点
    // 永久无法产出（数据保留重启路径实测）。内存 DAG 重启后为空，因此
    // 从**持久 vertex 存储**按作者取历史最高 round。
    let mut round: u64 = {
        let history = node
            .vertex_store()
            .get_by_author(&author_pubkey)
            .unwrap_or_default();
        history
            .iter()
            .map(|v| v.round)
            .max()
            .map(|r| r.saturating_add(1))
            .unwrap_or(1)
    };
    let (mut commit_round, mut prev_commit_hash, mut prev_block_hash) = node
        .block_store()
        .get_tip_height()
        .ok()
        .flatten()
        .and_then(|height| node.block_store().get_by_height(height).ok())
        .map_or((1, [0u8; 32], [0u8; 32]), |tip| {
            let next_round = tip
                .header
                .dag_commit_certificate
                .commit_round
                .checked_add(1)
                .unwrap_or(u64::MAX);
            (
                next_round,
                tip.header.dag_commit_certificate.signing_hash(chain_id),
                tip.block_hash(chain_id),
            )
        });
    // 存完整 vertex（非仅 hash），以便 commit 时从上一个 vertex 构造 block
    let mut last_vertex: Option<DagVertex> = None;
    // Keep committed frontier vertices in the live DAG for ancestry traversal, but filter them
    // out of later block projections so their transactions cannot execute twice.
    //
    // 启动时从链上重建（重启后必须知道历史 cert 覆盖了哪些 vertex），运行期间每个
    // tick 增量折叠 tip 新增区块（含 gossip/catch-up 导入的 peer 区块）。
    let mut committed_vertices: BTreeSet<Hash> = BTreeSet::new();
    let mut last_folded_height: u64 = 0;
    // wave-3 固定 leader 扫描游标（Mysticeti 对齐，取代 L4 意图稳定门）：
    // 下一待评估 leader 轮。波评估是 (DAG, committed) 的稳定纯函数，语句天然
    // 收敛，无需连续两周期确认意图；已决策轮（committed 闭包覆盖 / 投影为空 /
    // Skip）游标自愈推进，epoch 重置归 1。
    let mut scan_from: u64 = 1;
    // 恰 quorum 存活修复 · L5 投票钉扎：(epoch, commit_round) → (cert hash, 首票
    // 时刻)。同一高度一旦签票，钉扎期内拒绝为不同 cert 再签（fail-closed 防双票
    // 等价错误）；超时未决策才释放重投（视图长期分歧的逃生口）。已决策高度
    // （commit_round ≤ tip）的 pin 定期清理。
    let mut commit_vote_pins: HashMap<(u64, u64), (Hash, std::time::Instant)> = HashMap::new();
    // 恰 quorum 存活修复 · 定向补洞限频：上次向 peer 请求缺失 vertex 的时刻。
    let mut last_vertex_repair: Option<std::time::Instant> = None;
    // 传播丢失修复：上次重播未提交自家 vertex 的时刻。compact vertex 只广播
    // 一次，接收方缺 parent 拒收后再无人重发——该 vertex 只留在生产者本地
    // DAG，quorum 永远收不齐它（链只出空块、tx 不上链的根因）。周期性重播
    // 幂等（接收方按 hash 去重），仅在 vertex 尚未被 commit 引用时进行。
    let mut last_vertex_replay: Option<std::time::Instant> = None;
    // 未提交自家 vertex 近期窗口（传播丢失根修）：只重播 last vertex 时，
    // 连续多轮生产（peer 断连窗口内产出的 R、R+1…）会永久丢失中间轮——
    // peer DAG 留洞、quorum 长期只有 2 author、tx vertex 无法 commit
    // （空块/锚定饥饿的多 validator 根因）。全窗口重播使传播最终必然完备：
    // 每个未 commit 的自家 vertex 周期性重发，接收方按 hash 幂等去重。
    let mut recent_own_vertices: std::collections::VecDeque<DagVertex> =
        std::collections::VecDeque::new();
    const RECENT_OWN_VERTEX_WINDOW: usize = 64;
    // 多 validator 空产出配速基准（见生产 skip 处注释）
    let mut last_production_at: Option<std::time::Instant> = None;
    loop {
        let before = last_folded_height;
        fold_committed_vertices(&node, &mut committed_vertices, &mut last_folded_height);
        // 窗口维护：已 commit 的自家 vertex 停止重播
        recent_own_vertices
            .retain(|v| !committed_vertices.contains(&v.vertex_hash()));
        if last_folded_height == before {
            break;
        }
    }
    // 缺口 #3 §3.6：epoch 推进周期（每 EPOCH_LENGTH 个 commit 推进一次 epoch）。
    // 使用模块级 EPOCH_LENGTH（曾在此处重复定义为局部常量 10 并遮蔽模块值，
    // 导致模块级调整失效——实测 epoch 仍每 10 轮翻转、DAG 反复清空引发
    // 传播丢失级联与 commit 停摆）。
    // 恰 quorum 修复 · L5 投票钉扎释放窗口：钉扎超过该时长仍未见该高度决策
    // （tip 未推进过钉扎的 commit_round），允许为不同 cert 重投（视图长期分歧
    // 的活性逃生口）。窗口内拒绝双票（fail-closed）。取 5s：健康路径上 quorum
    // 在数百 ms 内决策，5s 足够覆盖启动/epoch 切换期的视图churn，把「同一节点
    // 先后为两个 cert 签票」压缩到极端分区场景。
    const COMMIT_VOTE_PIN_RELEASE: Duration = Duration::from_secs(5);

    info!(
        "validator 产块循环已启动（混合模式，间隔={}ms，pubkey={})",
        block_interval.as_millis(),
        hex::encode(&author_pubkey.raw)
    );

    // 加入门闩：配置了 peers 时，等待 catch-up 完成首轮成功请求（拿到主链
    // 高度或确认自己就是链头）再开始产块；上限 15s（peers 不可达 = 单机
    // bootstrap 场景，直接放行）。根除「fresh validator 先产块 1 后同步」
    // 的分叉竞态。
    if transport.peer_count() > 0 {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !CATCHUP_FIRST_ROUND.load(Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                warn!("加入门闩：15s 内 catch-up 未完成首轮（peers 不可达？），放行产块");
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
            if shutdown.load(Ordering::SeqCst) {
                return;
            }
        }
        info!("加入门闩放行：catch-up 首轮已完成，开始产块");
    }

    while !shutdown.load(Ordering::SeqCst) {
        // 折叠 tip 新增区块的 cert vertex（本地 commit / peer gossip / catch-up 导入
        // 都汇入 block_store），保持 committed 投影过滤集合与链一致。
        fold_committed_vertices(&node, &mut committed_vertices, &mut last_folded_height);
        // v1.5-c：checkpoint 间隔触发（签名/收集/聚合/落盘）+ fork-anchor 检测。
        // v1.5-e：阈值模式（t>0）签份额签名（Lagrange 重构装配阈值 QC）；
        // 聚合模式（t=0）维持既有 2f+1 聚签路径（零回退）。
        if node.qc_threshold_t() > 0 {
            maybe_sign_and_gossip_checkpoint_threshold(
                &node,
                &transport,
                &mut signed_threshold_sites,
            );
        } else {
            maybe_sign_and_gossip_checkpoint(&node, &bls_sk, &transport, &mut signed_checkpoints);
        }
        maybe_warn_fork_anchor(&node, 2 * node.checkpoint_interval_blocks().max(1));
        // v1.5-d：DA 回执 outbox 广播（da_request RPC 签发的本地回执）。
        for receipt in node.drain_da_outbox() {
            if let Err(e) = transport.gossip_broadcast(
                GossipTopic::Checkpoint,
                &NetworkMessage::DaReceipt(receipt),
            ) {
                warn!("da receipt 广播失败：{e}");
            }
        }
        // epoch 跟随检测（346 停滞修复）：accept 线程可能已把 node epoch
        // 推进到多数派位置——loop 同步局部 epoch 并按推进语义清 DAG/round，
        // 使本节点立即参与新 epoch 的 vertex/commit 生产。
        if node.current_epoch() != epoch {
            while epoch < node.current_epoch() {
                epoch += 1;
            }
            // epoch 边界 tx 蒸发修复：清 DAG 会丢弃未 commit 的 vertex，
            // 其承载的 tx 已从 pending drain——不回收则永久丢失（多
            // validator 下 epoch 高频推进 = tx 持续蒸发，锚定饥饿的直
            // 接根因）。回收进 pending 由新 epoch 重新打包。
            {
                let mut rescued = Vec::new();
                for v in &recent_own_vertices {
                    if !committed_vertices.contains(&v.vertex_hash()) {
                        rescued.extend(v.tx_list.iter().cloned());
                    }
                }
                if !rescued.is_empty() {
                    node.requeue_pending_txs(rescued);
                }
            }
            round = 1;
            last_vertex = None;
            committed_vertices.clear();
            // 旧 epoch 的 vertex 永不可 commit，重播只会被全网按 epoch
            // 检查拒绝（实测 7 万条拒绝风暴）——窗口必须一并清空。
            recent_own_vertices.clear();
            scan_from = 1;
            *dag.lock().unwrap_or_else(|e| e.into_inner()) = Dag::new();
            info!(
                "[validator-loop] epoch 跟随多数派至 {}（DAG round 已重置，未提交 tx 已回收）",
                epoch
            );
        }
        // 混合模式核心：等待 tx 或超时
        // - 有 tx 时被 submit_tx 的 notify_one 立即唤醒 → 零延迟出 vertex
        // - 超时返回 false → 检查是否需要出空 vertex 推进 commit
        // info!("[validator-loop] round={} 进入 wait_for_pending_tx", round);
        let mut leader_gate_skip: u64 = 0;
        let _has_tx = node.wait_for_pending_tx(block_interval);
        // commit 语句四元组快照：fold 与 tip 必须同代——cycle 中途 gossip 到达
        // 的新块会推进 block_store 的 tip，而 committed 集只在 fold 时跟进。
        // 混用两代会签出「旧投影 × 新 tip」的杂交语句（实测：scan 后 68ms
        // 新块到达，全网对同一高度出现两种 cert hash，票数 1/2 分裂卡死）。
        // 此处二次 fold 把等待期间到达的块一并吸收，快照后到达的块一律
        // 下周期生效。
        fold_committed_vertices(&node, &mut committed_vertices, &mut last_folded_height);
        let (tip_height, tip_commit_round, tip_prev_commit_hash, tip_prev_block_hash) = {
            match node
                .block_store()
                .get_tip_height()
                .ok()
                .flatten()
                .and_then(|h| node.block_store().get_by_height(h).ok())
            {
                Some(tip) => (
                    tip.header.height,
                    tip.header
                        .dag_commit_certificate
                        .commit_round
                        .checked_add(1)
                        .unwrap_or(u64::MAX),
                    tip.header.dag_commit_certificate.signing_hash(chain_id),
                    tip.block_hash(chain_id),
                ),
                None => (0, 1, [0u8; 32], [0u8; 32]),
            }
        };
        // 传播丢失修复：每 5s 重播最近一个未提交的自家 vertex（含其承载的
        // tx 不重发——tx 已随首播 gossip，缺 tx 的 peer 会走 full-vertex
        // fallback）。已被 commit 引用的 vertex 停止重播。
        if last_vertex_replay
            .map(|t| std::time::Instant::now() >= t)
            .unwrap_or(true)
        {
            last_vertex_replay = Some(std::time::Instant::now() + Duration::from_secs(2));
            // 全窗口重播（按生产顺序 = parent 先于 child，接收方可顺序准入）
            for vertex in &recent_own_vertices {
                let vh = vertex.vertex_hash();
                if committed_vertices.contains(&vh) || vertex.epoch != epoch {
                    continue;
                }
                if let Err(error) = gossip.broadcast_compact_vertex(vertex, transport.as_ref()) {
                    warn!("P2P 重播 CompactVertex 失败：{error}");
                }
            }
        }
        // info!(
        //     "[validator-loop] round={} wait_for_pending_tx 返回 has_tx={}",
        //     round, _has_tx
        // );
        // v1.5-a2：drain 同时返回本轮 forced 集，写入 vertex 载荷（共识承诺）。
        let (txs, drain_forced_hashes) = node.drain_pending_tx_for_block_with_forced();

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
        // 多 validator 空产出闸门（frontier-commit 竞速根修）：commit 节奏被
        // L2 成熟度门 + 投票往返压到 ~0.1/s，空 vertex 生产若按 block_interval
        //（1/s）推进，frontier 无界竞跑 cert，canonical 最老优先的候选序把
        // tx vertex 压在队尾（实测 frontier 819 vs cert 264）。改为仅当
        // frontier 领先 cert 不足 EMPTY_RUNWAY_ROUNDS 轮时才产空 vertex——
        // 生产严格跟随 commit 消化速度（commit 的投影按祖先闭包批量消化
        // 积压轮次，cert 单块可前跳多轮）。tx 唤醒的生产不受闸门（tx 直接
        // 排在队首附近）。纯本地产速策略，共识语义零改动。
        if is_multi_validator && txs.is_empty() {
            // 配速 1s：生产率须与 commit 消费率（投票微等待 + 多提交排水）匹配
            // ——生产过快则 frontier-commit 轮差累积成 tx 确认时延，过慢则波
            // 成熟（L+1/L+2 轮产出）拖长 tx 时延。1s = block_interval，与周期
            // 同拍。
            const EMPTY_VERTEX_PACE: Duration = Duration::from_secs(1);
            let paced_out = last_production_at
                .map(|t| std::time::Instant::now().duration_since(t) < EMPTY_VERTEX_PACE)
                .unwrap_or(false);
            if paced_out {
                continue;
            }
        }
        // （背压机制已移除 2026-09-21：三版实测各致新病——全停 = 候选引用
        // 饥饿死锁（NO candidates 卡死）；心跳 = 4 节点合计仍竞跑 frontier；
        // commit-only = 同死锁 + 自旋。frontier-commit 竞速的正确解法是空产出
        // 配速（见上方 EMPTY_VERTEX_PACE）让生产节奏对齐 commit 节奏。）

        // 切片为多个不超 MAX_VERTEX_SIZE 的 batch（修复溢出整批丢弃的活性 bug）。
        // 每来一笔 tx 累计其精确 BCS 体积，超限即封包进入下一个 vertex。
        // 单笔 tx 自身超限（异常，submit_tx 本应拦截）→ 单独记日志丢弃，不影响其他 tx。
        // 无 tx 但需推进 commit（last_has_txs）→ 一个空 batch，产出空 vertex。
        let batches = if txs.is_empty() {
            vec![Vec::new()]
        } else {
            let batches = split_txs_into_batches(txs.clone(), MAX_VERTEX_SIZE);
        // （txs 已在背压分支 requeue；clone 仅为切片——数量恒小，代价可忽略）
            if batches.is_empty() {
                vec![Vec::new()]
            } else {
                batches
            }
        };
        let batch_count = batches.len();
        let mut batches = batches.into_iter().enumerate().peekable();
        // 本 batch 成功产出的 vertex（推进在 commit 检测之后执行，见上）
        let mut produced_vertex_this_batch: Option<DagVertex> = None;

        while let Some((batch_idx, batch)) = batches.next() {
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
                    // 多 validator：parent 引用「本节点自身最新 vertex 所在轮」的全部不同
                    // author vertex（含自身），新 vertex 放在该轮 +1。
                    //
                    // 不能直接用 dag.max_round() 作为引用轮：
                    // (1) peer 在 round R 的 vertex 先于本节点自身的 R 轮 vertex 到达时，
                    //     max_round 已被推到 R，而 put_vertex 要求所有 parent 恰好位于
                    //     round-1 —— 本节点只能出 R+1，R 轮将永远凑不齐 required 个
                    //     distinct author，全网活性死锁。以自身 last_vertex.round 为基准
                    //     使落后节点能在 R 轮继续补充 author。
                    // (2) 本节点从未产出过 vertex（启动 / 新 epoch）时必须引导为
                    //     round 1 无 parent：validate_vertex 对 round=1 仅要求无 parent，
                    //     允许任意时刻加入。若以 max_r 为基准，先启动节点的 vertex 会把
                    //     后启动节点直接卡死在 max_r+1。
                    let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                    match last_vertex.as_ref() {
                        None => {
                            // 引导（含 Dag 为空的创世情形）。
                            round = 1;
                            Vec::new()
                        }
                        Some(own) => {
                            let max_r = dag_guard.max_round().unwrap_or(own.round);
                            // 引用轮基准：自身 last vertex 所在轮；越界（DAG 被重置等
                            // 异常）时回退 max_r。
                            let mut ref_round = if own.round <= max_r { own.round } else { max_r };
                            // Straggler 追赶（多 validator 活性根修）：round 只按自身
                            // 产出推进，一旦本节点停顿（GC/阻塞/临时 quorum 失败），
                            // own.round 与 DAG frontier 的差距永远无法收敛——后续
                            // vertex 全部产在过时轮次，永远进不了 frontier 领导者的
                            // causal history（其承载的 tx 永不执行；实测 node 停顿
                            // 4 分钟后落后 270 轮，该分片锚定全部停滞）。落后超过
                            // 2 轮即跳到 frontier-1 重新入场；parents 数量不足时
                            // validate_parents 会跳过本轮，无风险。
                            if max_r > ref_round.saturating_add(2) {
                                ref_round = max_r - 1;
                            }
                            // 引用 ref_round 轮的所有不同 author vertex（含自身），
                            // 并检测该轮预定 leader 是否在场。
                            let (mut parents, leader_included) =
                                collect_round_parents_with_leader(&dag_guard, &node, ref_round);
                            // wave-3 配套（Bullshark PartiallySynchronous proposer /
                            // Mysticeti ready_new_block 对齐）：引用轮的预定 leader
                            // vertex 尚未到达时，仅在前沿处短暂等待其投递再产出——
                            // 未等待就产出等于投下一张永久的非支持票（blame），会
                            // 触发全网一致的伪 skip、拉高提交时延。落后轮不等待
                            //（leader 早已该到，缺席即真实缺席）。睡眠绝不在持锁下
                            // 发生（P2P accept 线程要拿同一把锁）。
                            if is_multi_validator
                                && !leader_included
                                && ref_round >= max_r
                            {
                                const PROD_LEADER_WAIT: Duration = Duration::from_millis(800);
                                drop(dag_guard);
                                let deadline = std::time::Instant::now() + PROD_LEADER_WAIT;
                                while std::time::Instant::now() < deadline {
                                    std::thread::sleep(Duration::from_millis(100));
                                    let g2 = dag.lock().unwrap_or_else(|e| e.into_inner());
                                    let (p2, l2) =
                                        collect_round_parents_with_leader(&g2, &node, ref_round);
                                    drop(g2);
                                    if l2 {
                                        parents = p2;
                                        break;
                                    }
                                    if shutdown.load(Ordering::SeqCst) {
                                        break;
                                    }
                                }
                            }
                            // 同步本地 round 到 ref_round+1（使后续 vertex 的 round 连续）。
                            round = ref_round + 1;
                            parents
                        }
                    }
                };
                let mut builder = VertexBuilder::new(epoch, round, author_pubkey.clone());
                for tx in batch {
                    builder.push_tx(tx);
                }
                // v1.5-a2：本 vertex 实际携带的 forced 集 = 本轮 drain forced 集
                // ∩ 本 batch tx 集（forced hash 只承诺真实进入本 vertex 的交易）。
                if !drain_forced_hashes.is_empty() {
                    let batch_hashes: std::collections::BTreeSet<Hash> =
                        builder.tx_list.iter().map(|tx| tx.tx_hash()).collect();
                    let batch_forced: Vec<Hash> = drain_forced_hashes
                        .iter()
                        .copied()
                        .filter(|h| batch_hashes.contains(h))
                        .collect();
                    if !batch_forced.is_empty() {
                        builder = builder.with_forced_tx_hashes(batch_forced);
                    }
                }
                let builder = builder.with_parents(parent_hashes);

                // 创世轮（round 1）无 parent。其余轮次必须先凑齐真实 validator quorum；
                // 不足时把本批及尚未处理的批次放回 mempool，等待 peer vertex，而不是产出一个
                // 接收侧必然拒绝的弱 vertex 或静默丢失已经 drain 的交易。
                if round > 1 {
                    let vc_check = node.active_validator_count().max(1);
                    if let Err(e) = builder.validate_parents(vc_check) {
                        let mut deferred = builder.tx_list;
                        for (_, remaining_batch) in batches {
                            deferred.extend(remaining_batch);
                        }
                        let deferred_count = deferred.len();
                        node.requeue_pending_txs(deferred);
                        warn!(
                            "vertex parent quorum 未就绪，跳过本轮并回排 {} 笔交易：{e}",
                            deferred_count
                        );
                        // 恰 quorum 存活修复 · 生产侧补洞：parent 缺口多为「vertex 一次性
                        // gossip 在断连/启动竞态中丢失」所致，而 vertex 不会重播 —— 不主动
                        // 补齐则节点永久卡在本轮（恰 quorum 时少一个生产者即全网停滞）。
                        // 丢失常是**连续多轮**（断连窗口内的所有 vertex），且补入的 vertex
                        // 其 parent 也必须在本地，故请求范围向前覆盖 8 轮；限频执行。
                        {
                            let parent_round = round.saturating_sub(1).max(1);
                            let window_start = parent_round.saturating_sub(8).max(1);
                            repair_missing_vertices(
                                &transport,
                                &dag,
                                &node,
                                window_start,
                                parent_round,
                                &mut last_vertex_repair,
                            );
                        }
                        std::thread::sleep(block_interval.min(Duration::from_secs(1)));
                        break;
                    }
                }
                // validate_size 为粗估；put_vertex 内部用精确 BCS 再校验一次，此处仅作提前拒绝。
                if let Err(e) = builder.validate_size() {
                    warn!("vertex 大小校验失败（batch_idx={}）：{e}", batch_idx);
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

                // 先通过完整验证并持久化，再让 vertex 进入 live DAG。反过来的顺序会在
                // put_vertex 失败时污染 parent 选择和 commit leader 检测。
                let vertex_hash = match node.put_vertex(&vertex) {
                    Ok(hash) => hash,
                    Err(e) => {
                        let mut deferred = vertex.tx_list.clone();
                        for (_, remaining_batch) in batches {
                            deferred.extend(remaining_batch);
                        }
                        let deferred_count = deferred.len();
                        node.requeue_pending_txs(deferred);
                        warn!(
                            "put_vertex 失败（batch_idx={}），未写入 DAG/广播并回排 {} 笔交易：{e}",
                            batch_idx, deferred_count
                        );
                        std::thread::sleep(block_interval.min(Duration::from_secs(1)));
                        break;
                    }
                };
                {
                    let mut dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                    let live_hash = dag_guard.insert(vertex.clone());
                    debug_assert_eq!(live_hash, vertex_hash);
                }
                // Feed the bounded cache and gossip each transaction before the
                // compact vertex. Peers that already saw the tx can reconstruct
                // the vertex from short IDs; peers that missed one safely request
                // the full vertex fallback below.
                for tx in &vertex.tx_list {
                    if let Err(error) = gossip.receive_tx(tx.clone()) {
                        warn!("本地 vertex tx 未进入 compact-relay 缓存：{error}");
                    }
                    if let Err(error) = transport.gossip_broadcast(
                        GossipTopic::Transaction,
                        &NetworkMessage::Transaction(tx.clone()),
                    ) {
                        warn!("P2P 广播 transaction 失败：{error}");
                    }
                }
                if let Err(error) = gossip.broadcast_compact_vertex(&vertex, transport.as_ref()) {
                    warn!("P2P 广播 CompactVertex 失败：{error}");
                }

                info!(
                    "vertex 已产出 round={} batch_idx={}/{} tx_count={} hash={}",
                    round,
                    batch_idx,
                    batch_count,
                    vertex.tx_list.len(),
                    hex::encode(vertex_hash)
                );

                // 记录本 batch 产出（推进在 batch 体末尾、commit 检测之后执行：
                // 单 validator 的 commit 候选 = last_vertex，提前推进会令候选
                // 永远指向刚产出、尚无引用的新 vertex → commit 永不成立）。
                produced_vertex_this_batch = Some(vertex.clone());


            // 从第 2 轮起，检测 commit 并产出 block（缺口 #3：真实 2/3 多签闭环）。
            //
            // 恰 quorum 存活 commit 停滞根因修复（详见
            // poker_l1/src/consensus/bullshark.rs 模块头「canonical leader 候选序」）：
            // 旧实现扫本地 `max_r-4..max_r-1` 滑窗 + DAG 插入序取首个满足 quorum 的候选。
            // 窗口边界随各节点生产节奏错位（本节点刚出 vertex 则 max_r 已 +1，peer 未同步
            // 则 -1），同轮候选又按各自到达序排列 —— 不同节点对同一 DAG 推断出不同的首候选
            // leader，对不同 cert_signing_hash 签票（实测票数 2/4/1 分裂），恰 quorum 存活
            // （7 杀 2 余 5，quorum=5）时任何单个 cert 永远凑不齐 5 票：DAG 平面健康推进
            // 而 chain tip 停滞。现改为全量未提交 vertex 的规范化全序
            // (round, author, hash) + 廉价 quorum 预检：候选序是 (DAG, committed) 的纯
            // 函数且单调稳定，投票跨节点单调汇聚。单 validator（vc<=1）仍直接用
            // last_vertex 自签出块。
            {
                let vc = node.active_validator_count().max(1);
                // L5 pin 清理：commit_round ≤ 当前 tip 的高度已经决策，钉扎不再需要。
                {
                    let tip_now = node
                        .block_store()
                        .get_tip_height()
                        .ok()
                        .flatten()
                        .unwrap_or(0);
                    commit_vote_pins.retain(|(pin_epoch, pin_cr), _| {
                        *pin_epoch == epoch && *pin_cr > tip_now
                    });
                }
                // 收集候选 leader：单 validator 用 last_vertex；多 validator 走
                // wave-3 固定 leader 轮序扫描（Mysticeti 对齐；调研与安全性论证见
                // docs/test-records/2026-09-21-consensus-reference-research.md）。
                // 取代旧「canonical 候选序 + L2 成熟度门 + L4 意图稳定门」三件套：
                // 预定 leader（轮转纯函数）+ 有界波（票只数 L+1、certificate 只数
                // L+2）使「投给谁、投什么语句」成为 (DAG, committed) 的稳定纯
                // 函数，各节点语句天然一致，投票必然汇聚。
                // 多提交排水（见下方扫描内说明）。
                const MAX_WAVE_PICKS_PER_CYCLE: usize = 8;
                let mut wave_picks: Vec<(DagVertex, Vec<Hash>, Vec<DagVertex>)> = Vec::new();
                let mut wave_repair: Option<(u64, u64)> = None;
                let mut first_pick_round: Option<u64> = None;
                let candidate_leaders: Vec<Hash> = if vc <= 1 {
                    last_vertex
                        .as_ref()
                        .map(|v| vec![v.vertex_hash()])
                        .unwrap_or_default()
                } else {
                    let sorted_validators = node.active_validator_pubkeys_sorted();
                    if sorted_validators.is_empty() {
                        Vec::new()
                    } else {
                        let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                        let max_r = dag_guard.max_round().unwrap_or(0);
                        let mut r = scan_from.max(1);
                        // 本周期已拾取投影的增量集：后续 pick 的祖先闭包排除它们
                        //（与「已提交」同义，块落地后由 fold 正式并入）。多提交
                        // 排水：单周期拾取最多 MAX_WAVE_PICKS_PER_CYCLE 个可提交
                        // leader，连续出块消化 frontier-commit 轮差（lag 直接构成
                        // tx 确认时延，实测 lag~15 轮 × 3s/块 = 60s/笔）。
                        let mut scan_committed = committed_vertices.clone();
                        let mut actionable: Vec<Hash> = Vec::new();
                        while r <= max_r {
                            let leader_pk =
                                &sorted_validators[round_leader_index(r, sorted_validators.len())];
                            let leader_hash = dag_guard
                                .round_vertices(r)
                                .iter()
                                .find(|vh| {
                                    dag_guard
                                        .get(vh)
                                        .is_some_and(|v| &v.author_pubkey == leader_pk)
                                })
                                .copied();
                            match leader_hash {
                                // leader 已随先前块的投影闭包入库 → 该轮已消化，
                                // 游标自愈推进（兼容 gossip 导入的 peer 块）。
                                Some(lh) if committed_vertices.contains(&lh) => {
                                    r += 1;
                                }
                                Some(lh) => match evaluate_leader_wave(&dag_guard, &lh, r, vc) {
                                    WaveOutcome::Commit { votes, certs } => {
                                        info!(
                                            round = r,
                                            leader = %hex::encode(&lh[..8]),
                                            votes = votes.len(),
                                            certs = certs.len(),
                                            "[wave] COMMIT（L+1 票 / L+2 certificate 双 quorum）"
                                        );
                                        // 投影 = leader 祖先闭包（fail-closed），
                                        // 排除集含本周期先前 pick 的投影。
                                        let attempt = attempt_commit_projection(
                                            &dag_guard,
                                            std::slice::from_ref(&lh),
                                            &scan_committed,
                                            r,
                                        );
                                        if !attempt.missing.is_empty() {
                                            let min_round = attempt
                                                .missing
                                                .iter()
                                                .map(|(_, round)| *round)
                                                .min()
                                                .unwrap_or(1);
                                            let max_round = attempt
                                                .missing
                                                .iter()
                                                .map(|(_, round)| *round)
                                                .max()
                                                .unwrap_or(1);
                                            wave_repair = Some((min_round, max_round));
                                            break;
                                        }
                                        if attempt.ordered_hashes.is_empty() {
                                            // leader 闭包已全部提交 → 该轮已消化
                                            r += 1;
                                            continue;
                                        }
                                        let mut commit_vertices =
                                            Vec::with_capacity(attempt.ordered_hashes.len());
                                        let mut complete = true;
                                        for hash in &attempt.ordered_hashes {
                                            match dag_guard.get(hash) {
                                                Some(vertex) => {
                                                    commit_vertices.push(vertex.clone())
                                                }
                                                None => {
                                                    complete = false;
                                                    break;
                                                }
                                            }
                                        }
                                        if !complete {
                                            wave_repair = Some((r.saturating_sub(1), r));
                                            break;
                                        }
                                        // leader vertex 必在场（上方 find 已确认）
                                        let leader_vertex =
                                            dag_guard.get(&lh).expect("leader vertex 已确认在场");
                                        wave_picks.push((
                                            leader_vertex.clone(),
                                            attempt.ordered_hashes.clone(),
                                            commit_vertices,
                                        ));
                                        scan_committed.extend(attempt.ordered_hashes.iter().copied());
                                        first_pick_round.get_or_insert(r);
                                        actionable.push(lh);
                                        if actionable.len() >= MAX_WAVE_PICKS_PER_CYCLE {
                                            break;
                                        }
                                        r += 1;
                                    }
                                    WaveOutcome::Skip => {
                                        info!(
                                            round = r,
                                            "[wave] SKIP（blame quorum，leader 未获支持，内容由后续 leader 闭包兜底）"
                                        );
                                        r += 1;
                                    }
                                    WaveOutcome::Undecided => {
                                        // 前缀规则：未决轮阻断扫描（不能直接跳过
                                        // ——别处视角下它可能 Commit，跳过=分叉）。
                                        // 但 2/2 分票（votes、blame 均 < quorum）的
                                        // 未决是**终态**，会永久卡死扫描。Mysticeti
                                        // 间接裁决的本地等价形式：若更晚的波已可
                                        // 提交（r2 ≥ r+3），用 r2 的祖先闭包裁决 r——
                                        // leader ∈ 闭包 → 内容随 r2 的块消化；否则
                                        // skip。闭包成员资格是 DAG 纯函数，视角
                                        // 收敛后各节点裁决一致。
                                        let mut later: Option<(Hash, u64)> = None;
                                        let mut r2 = r.saturating_add(3);
                                        while r2 <= max_r {
                                            let lpk2 = &sorted_validators[round_leader_index(
                                                r2,
                                                sorted_validators.len(),
                                            )];
                                            if let Some(lh2) = dag_guard
                                                .round_vertices(r2)
                                                .iter()
                                                .find(|vh| {
                                                    dag_guard.get(vh).is_some_and(|v| {
                                                        &v.author_pubkey == lpk2
                                                    })
                                                })
                                                .copied()
                                                && matches!(
                                                    evaluate_leader_wave(
                                                        &dag_guard,
                                                        &lh2,
                                                        r2,
                                                        vc
                                                    ),
                                                    WaveOutcome::Commit { .. }
                                                )
                                            {
                                                later = Some((lh2, r2));
                                                break;
                                            }
                                            r2 += 1;
                                        }
                                        match later {
                                            Some((lh2, r2)) => {
                                                let attempt2 = attempt_commit_projection(
                                                    &dag_guard,
                                                    std::slice::from_ref(&lh2),
                                                    &committed_vertices,
                                                    r2,
                                                );
                                                if !attempt2.missing.is_empty() {
                                                    // r2 投影有缺口：fail-closed，
                                                    // 按缺口轮区间补洞（下周期重扫）。
                                                    let min_round = attempt2
                                                        .missing
                                                        .iter()
                                                        .map(|(_, rd)| *rd)
                                                        .min()
                                                        .unwrap_or(r);
                                                    let max_round = attempt2
                                                        .missing
                                                        .iter()
                                                        .map(|(_, rd)| *rd)
                                                        .max()
                                                        .unwrap_or(r2);
                                                    wave_repair = Some((min_round, max_round));
                                                    break;
                                                }
                                                if attempt2
                                                    .ordered_hashes
                                                    .contains(&lh)
                                                {
                                                    info!(
                                                        round = r,
                                                        anchor = r2,
                                                        "[wave] ABSORB（未决轮由更晚可提交波的闭包消化）"
                                                    );
                                                } else {
                                                    info!(
                                                        round = r,
                                                        anchor = r2,
                                                        "[wave] SKIP-INDIRECT（未决轮不在更晚可提交波闭包内）"
                                                    );
                                                }
                                                r += 1;
                                            }
                                            None => {
                                                // 无更晚可提交波。波已陈旧仍无法
                                                // 裁决 = 本地视角缺洞（票/blame 计
                                                // 不满），触发补洞；波仍在形成则
                                                // 静默等待。
                                                if max_r.saturating_sub(r)
                                                    >= COMMIT_ABSENCE_ROUNDS.saturating_add(2)
                                                {
                                                    wave_repair = Some((r, r.saturating_add(2)));
                                                }
                                                break;
                                            }
                                        }
                                    }
                                },
                                None => {
                                    // leader vertex 本地缺失：生产是前向-only 的，
                                    // 波龄超限后 L+1/L+2 引用位已定型，迟到也改变
                                    // 不了该波——跳过；波龄内先补洞等待。
                                    let wave_age = max_r.saturating_sub(r);
                                    if wave_age >= COMMIT_ABSENCE_ROUNDS.saturating_add(2) {
                                        info!(
                                            round = r,
                                            wave_age,
                                            "[wave] SKIP（leader vertex 缺失且波龄超限）"
                                        );
                                        r += 1;
                                    } else {
                                        wave_repair = Some((r, r.saturating_add(2)));
                                        break;
                                    }
                                }
                            }
                        }
                        // 游标：有 pick 时钉在首个 pick 的轮上（vote 路径按实际
                        // 落块推进；中途 WAITING 退出也不越过未提交轮——否则下
                        // 周期会对不同高度绑定的语句分叉）。无 pick 时用扫描
                        // 游标（Skip/Empty/ABSORB 已自愈推进）。
                        scan_from = first_pick_round.unwrap_or(r).max(scan_from);
                        actionable
                    }
                };

                // 对候选 leader 提交（多 validator 的 quorum 判定由上方 wave 评估
                // 完成，detect_commit_leader 仅服务单 validator 路径）。
                // 投影缺口触发定向补洞后整体弃权，下一个生产周期以补齐的视角
                // 重新参与投票。
                let mut committed;
                let mut repair_plan: Option<(u64, u64)> = None;
                if let Some((min_r, max_r)) = wave_repair {
                    repair_plan = Some((min_r, max_r));
                }
                for (pick_idx, leader_hash) in candidate_leaders.iter().enumerate() {
                    let commit_result = if vc <= 1 {
                        let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                        detect_commit_leader(&dag_guard, leader_hash, vc)
                    } else {
                        Ok(None)
                    };
                    if vc > 1 || matches!(&commit_result, Ok(Some(_))) {
                        // 找到可 commit 的 leader，并 resolve the same canonical projection
                        // that will be committed in the certificate and block body.
                        let projection_pick: Option<(
                            DagVertex,
                            Vec<Hash>,
                            Vec<DagVertex>,
                        )> = 'pick: {
                            if vc > 1 {
                                // wave 扫描已产出确定性投影（含 fail-closed 缺口
                                // 处理与 Empty 游标推进），按 pick 序取用。
                                break 'pick wave_picks.get(pick_idx).cloned();
                            }
                            let dag_guard = dag.lock().unwrap_or_else(|e| e.into_inner());
                            let Some(leader_vertex) = dag_guard.get(leader_hash).cloned() else {
                                break 'pick None;
                            };
                            if committed_vertices.contains(leader_hash) {
                                break 'pick None;
                            }
                            let commit_leader = match commit_result.as_ref() {
                                Ok(Some(commit_leader)) => commit_leader,
                                _ => break 'pick None,
                            };
                            match canonical_commit_projection(
                                &dag_guard,
                                commit_leader,
                                &committed_vertices,
                            ) {
                                CommitProjectionOutcome::Ready(ordered_hashes, commit_vertices) => {
                                    // 引用轮闭合检查：round-(r+1) 的作者集必须覆盖
                                    // round-r 的作者集（每 (author, round) 至多一个
                                    // vertex）。不满足 = 本地还缺 r+1 的 vertex，引用集
                                    // （进而投影）仍会增长 → 弃权并定向补洞，防止对
                                    // 「半熟引用集」的投影签票。
                                    let ref_round = commit_leader.leader_round.saturating_add(1);
                                    let authors_of = |dag: &Dag, round: u64| -> BTreeSet<Vec<u8>> {
                                        dag.round_vertices(round)
                                            .iter()
                                            .filter_map(|hash| dag.get(hash))
                                            .map(|vertex| vertex.author_pubkey.to_bytes())
                                            .collect()
                                    };
                                    let authors_leader = authors_of(&dag_guard, commit_leader.leader_round);
                                    let authors_referencing = authors_of(&dag_guard, ref_round);
                                    // 恰 quorum 存活修复 · 前沿缺席分类：掉线 validator 的
                                    // round-(r+1) vertex 永远不会到来。闭合检查原样把「永久
                                    // 缺席」当「gossip 在途」无限等待，而候选按 (round asc)
                                    // 序最老者优先 —— 含缺席作者的老候选每个生产周期都触发
                                    // 整体弃权，恰 quorum 存活（kill-2 后存活恰 = quorum）时
                                    // 全网 commit 冻死（7 节点演练实测：vertex 平面持续推进
                                    // 而 tip 停滞）。前沿已前移 COMMIT_ABSENCE_ROUNDS 轮且
                                    // 作者自 ref_round 起无任何 vertex → 按离线处理，引用集
                                    // 视为已冻结。分类是 DAG 内容的纯函数（同视图必同分类，
                                    // 无新 cert 分裂源；收敛窗口由 L4 意图稳定门兜底）。
                                    // finality 口径不变：cert 2/3 签名与引用 quorum 仍按
                                    // 全集 validator 数执行。
                                    let missing_authors: Vec<Vec<u8>> = authors_leader
                                        .difference(&authors_referencing)
                                        .cloned()
                                        .collect();
                                    // 引用波冻结判定（轮龄口径）：生产是前向-only 的
                                    //（round = 自身 last+1 或 straggler 跳至 frontier，
                                    // 永不回填旧轮），前沿越过 ref_round 达
                                    // COMMIT_ABSENCE_ROUNDS 后，该轮引用集不可能再
                                    // 增长——无论缺席作者在线与否。原「缺席作者此后
                                    // 从未产出」口径只覆盖离线作者（kill-2 演练），
                                    // 对「跳过了该轮但活跃」的作者（跳跃/配速下的
                                    // 常态）判成"仍会补产"→ 永久弃权（实测 round-42
                                    // 缺 1 作者、quorum 3/4 已满足仍卡死）。
                                    // 确定性：轮龄是 DAG 内容的纯函数，与
                                    // author_has_vertex_since 同为视图函数，收敛窗口
                                    // 由 L4 意图稳定门 + L5 钉扎吸收；quorum 引用
                                    //（detect 硬性 2/3）与 cert 签名 quorum 不变。
                                    let authors_settled = missing_authors.is_empty()
                                        || dag_guard
                                            .max_round()
                                            .unwrap_or(0)
                                            .saturating_sub(ref_round)
                                            >= COMMIT_ABSENCE_ROUNDS;
                                    if !authors_settled {
                                        repair_plan = Some((ref_round, ref_round));
                                        debug!(
                                            leader = %hex::encode(leader_hash),
                                            leader_round = commit_leader.leader_round,
                                            ref_round,
                                            missing = missing_authors.len(),
                                            "引用轮作者集不完整（引用集仍会增长），定向补洞后下周期再投票"
                                        );
                                        break 'pick None;
                                    }
                                    // 引用叶缺口扫描：缺失的 round-(r+1) 引用叶不出现在
                                    // 任何祖先路径上（投影/预检均不报错），但会令不同节点
                                    // 的引用集不同 → 投影不同 → cert 分裂。经由其在
                                    // leader.round+2 轮的子顶点 parent 指针定位并补洞。
                                    let leaf_round =
                                        commit_leader.leader_round.saturating_add(2);
                                    let missing_leaves = find_missing_parent_vertices(
                                        &dag_guard,
                                        leaf_round,
                                        leaf_round,
                                    );
                                    if !missing_leaves.is_empty() {
                                        info!(
                                            "GAP-LEAVES round={} missing={} hashes={}",
                                            leaf_round,
                                            missing_leaves.len(),
                                            missing_leaves
                                                .iter()
                                                .take(4)
                                                .map(|(h, _)| hex::encode(&h[..6]))
                                                .collect::<Vec<_>>()
                                                .join(",")
                                        );
                                        let min_round = missing_leaves
                                            .iter()
                                            .map(|(_, round)| *round)
                                            .min()
                                            .unwrap_or(leaf_round);
                                        let max_round = missing_leaves
                                            .iter()
                                            .map(|(_, round)| *round)
                                            .max()
                                            .unwrap_or(leaf_round);
                                        repair_plan = Some((min_round, max_round));
                                        debug!(
                                            leader = %hex::encode(leader_hash),
                                            missing_leaves = missing_leaves.len(),
                                            min_round,
                                            max_round,
                                            "引用叶缺失，定向补洞后下周期再投票"
                                        );
                                        break 'pick None;
                                    }
                                    Some((leader_vertex, ordered_hashes, commit_vertices))
                                }
                                CommitProjectionOutcome::MissingVertices(min_round, max_round) => {
                                    repair_plan = Some((min_round, max_round));
                                    debug!(
                                        leader = %hex::encode(leader_hash),
                                        min_round,
                                        max_round,
                                        "commit 投影缺失未提交祖先，定向补洞后下周期再投票"
                                    );
                                    break 'pick None;
                                }
                                CommitProjectionOutcome::Empty => {
                                    debug!(
                                        leader = %hex::encode(leader_hash),
                                        "commit 投影为空（leader 全部祖先已提交），弃权"
                                    );
                                    break 'pick None;
                                }
                            }
                        };
                        let Some((leader_vertex, ordered_hashes, commit_vertices)) = projection_pick
                        else {
                            // 触发了补洞或无需投票：跳出候选循环（本周期弃权）。
                            // （曾试改为 continue 跳过缺口候选——投票分散更糟：
                            // 各节点缺口不同 → 候选选择不同 → 4 张票各投不同
                            // cert，quorum 永不成立。确定性候选序是投票汇聚的
                            // 前提，缺口必须靠补洞治愈而非绕过。）
                            break;
                        };
                        // commit 语句四元组：首个 pick 用周期顶部快照（fold 后
                        // 立即读取）；同周期第 k>1 个 pick 之前一个 pick 已本地
                        // 出块，重新 fold + 取新 tip——投影的 committed 过滤集与
                        // tip 绑定信息必须出自同一代，杜绝「旧投影 × 新 tip」的
                        // 杂交语句。
                        let (height, tip_commit_round, tip_prev_commit_hash, tip_prev_block_hash) =
                            if pick_idx == 0 {
                                (
                                    tip_height + 1,
                                    tip_commit_round,
                                    tip_prev_commit_hash,
                                    tip_prev_block_hash,
                                )
                            } else {
                                fold_committed_vertices(
                                    &node,
                                    &mut committed_vertices,
                                    &mut last_folded_height,
                                );
                                match node
                                    .block_store()
                                    .get_tip_height()
                                    .ok()
                                    .flatten()
                                    .and_then(|h| node.block_store().get_by_height(h).ok())
                                {
                                    Some(tip) => (
                                        tip.header.height + 1,
                                        tip.header
                                            .dag_commit_certificate
                                            .commit_round
                                            .checked_add(1)
                                            .unwrap_or(u64::MAX),
                                        tip.header.dag_commit_certificate.signing_hash(chain_id),
                                        tip.block_hash(chain_id),
                                    ),
                                    None => (1, 1, [0u8; 32], [0u8; 32]),
                                }
                            };
                        // 多提交游标钉位：本 pick 未落块前，游标停在该轮。
                        scan_from = leader_vertex.round;

                        if vc <= 1 {
                            // 单 validator：自签出块。
                            committed = commit_and_finalize_block(
                                &commit_vertices,
                                &ordered_hashes,
                                &leader_vertex,
                                &node,
                                &secret_key,
                                chain_id,
                                tip_commit_round,
                                tip_prev_commit_hash,
                                tip_prev_block_hash,
                                height,
                                &transport,
                                &dag,
                                &mut committed_vertices,
                                &mut commit_round,
                                &mut prev_commit_hash,
                                &mut prev_block_hash,
                            );
                        } else {
                            // 多 validator：DAG 的 2/3 引用与 certificate 的 2/3 签名
                            // 都是 finality 条件。后者不能降级为“仅审计”，否则本节点会
                            // 自产随后被严格 block validation 拒绝的区块。
                            let cert_signing_hash = match compute_cert_signing_hash(
                                &commit_vertices,
                                &ordered_hashes,
                                &leader_vertex,
                                chain_id,
                                epoch,
                                tip_commit_round,
                                tip_prev_commit_hash,
                                &node,
                                height,
                            ) {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("compute_cert_signing_hash 失败：{e}");
                                    continue;
                                }
                            };
                            // 恰 quorum 修复 · L5 投票钉扎：同一 (epoch, commit_round)
                            // 已为不同 cert 签过票且未超时 → 拒绝再签（fail-closed 防
                            // 双票等价错误，双票曾致同高度两个 cert 各自凑齐 quorum）。
                            {
                                let pin_key = (epoch, tip_commit_round);
                                let now = std::time::Instant::now();
                                match commit_vote_pins.get(&pin_key) {
                                    Some((pinned_hash, pinned_at))
                                        if *pinned_hash != cert_signing_hash =>
                                    {
                                        if now.duration_since(*pinned_at) < COMMIT_VOTE_PIN_RELEASE
                                        {
                                            debug!(
                                                commit_round = tip_commit_round,
                                                pinned = %hex::encode(pinned_hash),
                                                new = %hex::encode(cert_signing_hash),
                                                "同高度已钉扎到不同 cert，拒绝双票"
                                            );
                                            break;
                                        }
                                        warn!(
                                            commit_round = tip_commit_round,
                                            from = %hex::encode(pinned_hash),
                                            to = %hex::encode(cert_signing_hash),
                                            "commit 投票钉扎超时释放（该高度长期未决策），按当前意图重投"
                                        );
                                        commit_vote_pins.insert(pin_key, (cert_signing_hash, now));
                                    }
                                    Some(_) => {}
                                    None => {
                                        commit_vote_pins.insert(pin_key, (cert_signing_hash, now));
                                    }
                                }
                            }
                            let self_sig = secp256k1_sign_hash(&secret_key, &cert_signing_hash);
                            let self_vote = CommitVote {
                                epoch,
                                commit_round: tip_commit_round,
                                height,
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
                            // 恰 quorum 修复：移除旧的「防御性自签」。旧逻辑在池中票数
                            // 差一票时用本地签名补足 —— 节点可能从未广播过对该 cert 的
                            // 投票（其真实投票在另一 cert 上），却在 cert 上留下自己的
                            // 签名：同一高度两个不同 cert 各自被不同节点用防御性自签
                            // 凑满 quorum 并落块（实测 h6/h11 相隔 2ms 双出块分叉）。
                            // 现在只能用真实收集到的投票（含自己已广播的那张）凑 quorum；
                            // 凑不齐就等待，绝不代签。
                            let quorum = required_quorum(vc);
                            let mut sig_pairs: Vec<(usize, Vec<u8>)> = sig_pairs;
                            // 投票微等待（提交流水线压测瓶颈根修）：无等待时每块
                            // 都要跨周期往返一轮投票（他人下周期签票 → 本节点再
                            // 下周期装配），块率被压到 ~0.5 块/s，frontier-commit
                            // 轮差随之累积成 tx 确认时延。当周期内短轮询凑票
                            //（票经 P2P 线程实时入池），凑齐即装配，流水线深度
                            // 从 2-3 周期压到 ~1 周期。
                            {
                                const VOTE_MICRO_WAIT: Duration = Duration::from_millis(800);
                                let vote_deadline = std::time::Instant::now() + VOTE_MICRO_WAIT;
                                while sig_pairs.len() < quorum
                                    && std::time::Instant::now() < vote_deadline
                                {
                                    std::thread::sleep(Duration::from_millis(150));
                                    let collected = votes.peek_for_hash(&cert_signing_hash);
                                    sig_pairs = collected
                                        .iter()
                                        .filter_map(|vote| {
                                            active_pubkeys
                                                .iter()
                                                .position(|pk| *pk == vote.signer_pubkey)
                                                .map(|idx| (idx, vote.signature.clone()))
                                        })
                                        .collect();
                                }
                            }
                            if sig_pairs.len() < quorum {
                                info!(
                                    commit_round = tip_commit_round,
                                    votes = sig_pairs.len(),
                                    quorum,
                                    leader = %hex::encode(&leader_hash[..8]),
                                    "WAITING-VOTES"
                                );
                                // 恰 quorum 修复：本周期已为本 cert 投票并广播，绝不
                                // 再为同高度的其他候选投票（防双票等价错误）。票数由
                                // gossip 持续累积，下一生产周期重试同一 intent。
                                break;
                            }
                            // 方案 A（leader-only 装配，2026-09-15）：块字节含签名
                            // 子集——各 validator 独立装配会产出同语句不同字节的
                            // 块（prev_hash 链互不承认 → epoch 边界 tip 分裂卡死，
                            // 实测 330/331）。只有 commit leader 装配并广播完整块，
                            // 其余 validator 通过 gossip ResponseBlocks 分支走完整
                            // put_block 验证接受（cert 多签 + 重放 + state_root），
                            // 块字节全网唯一。leader 缺席时该轮无块，活性由 leader
                            // 轮换保证（Bullshark 语义）。
                            // leader 超时兜底：leader（本轮装配者）在
                            // COMMIT_VOTE_PIN_RELEASE 内未出块 → 距投票时间最久的
                            // follower 兜底装配。兜底块与 leader 块同语句
                            //（signing_hash 相同），put_block 的语句级去重保证
                            // 只有一份入库，无分叉风险。
                            let pinned_at_ref = commit_vote_pins
                                .get(&(epoch, tip_commit_round))
                                .map(|(_, at)| *at);
                            let leader_timed_out = pinned_at_ref
                                .map(|at| {
                                    std::time::Instant::now().duration_since(at)
                                        >= COMMIT_VOTE_PIN_RELEASE
                                })
                                .unwrap_or(false);
                            let this_node_is_leader =
                                leader_vertex.author_pubkey == author_pubkey;
                            if !this_node_is_leader && !leader_timed_out {
                                leader_gate_skip += 1;
                                if leader_gate_skip % 50 == 1 {
                                    info!(
                                        commit_round = tip_commit_round,
                                        height,
                                        skips = leader_gate_skip,
                                        "非 commit leader，等待 leader 广播块"
                                    );
                                }
                                break;
                            }
                            // 修复：verify 端（validate_commit_certificate_signatures）按
                            // bitmap 置位升序枚举并与 signature_list 位置一一对应，因此
                            // 必须按 idx 升序排列签名（否则自投非最小 idx 的节点组装的
                            // cert 永远验证失败 —— 既往「只有一个节点能出块」的根因）。
                            sig_pairs.sort_by_key(|(idx, _)| *idx);
                            // Only discard votes after the block is accepted; a failed put_block
                            // must leave the certificate material available for retry.
                            committed = commit_and_finalize_block_multi(
                                &commit_vertices,
                                &ordered_hashes,
                                &leader_vertex,
                                &node,
                                chain_id,
                                epoch,
                                tip_commit_round,
                                tip_prev_commit_hash,
                                tip_prev_block_hash,
                                height,
                                &sig_pairs,
                                vc,
                                &transport,
                                &dag,
                                &mut committed_vertices,
                                &mut commit_round,
                                &mut prev_commit_hash,
                                &mut prev_block_hash,
                            );
                            if committed {
                                let _ = votes.drain_for_hash(&cert_signing_hash);
                                // wave 游标推进（防漏：下一周期折叠自愈也会推）。
                                scan_from = leader_vertex.round.saturating_add(1);
                            }
                        }
                        if committed {
                            // 多提交排水：本 pick 已落块，继续处理下一个 pick
                            //（vote 路径会用刷新后的 tip 绑定下一高度）。
                            continue;
                        }
                    }
                }
                // 恰 quorum 修复 · 定向补洞执行点：dag_guard 已释放，可安全加锁。
                if let Some((min_round, max_round)) = repair_plan {
                    repair_missing_vertices(
                        &transport,
                        &dag,
                        &node,
                        min_round,
                        max_round,
                        &mut last_vertex_repair,
                    );
                }
            }

            // 缺口 #3 §3.6：epoch 推进触发（每 EPOCH_LENGTH 个 commit 推进一次 epoch，
            // 并用 VRF 派生新 epoch_randomness）。
            //
            // 触发基准必须取自 tip cert（epoch, commit_round），不能只用本地缓存：
            // gossip / catch-up 导入的 peer 区块同样推进链高度 —— 只看「自己 commit」
            // 会让主要导入区块的节点错过 epoch 边界，全网 epoch 分叉，vertex 互相被
            // InvalidVertexEpoch 拒绝。
            let tip_state = node
                .block_store()
                .get_tip_height()
                .ok()
                .flatten()
                .and_then(|h| node.block_store().get_by_height(h).ok())
                .map(|tip_block| {
                    let cert = &tip_block.header.dag_commit_certificate;
                    (cert.epoch, cert.commit_round)
                });
            let crossed_boundary = matches!(tip_state, Some((cert_epoch, cert_commit_round))
                if cert_epoch == epoch
                    && cert_commit_round > 1
                    && (cert_commit_round - 1) % EPOCH_LENGTH == 0);
            let chain_epoch_ahead = matches!(tip_state, Some((cert_epoch, _)) if cert_epoch > epoch);
            if crossed_boundary || chain_epoch_ahead {
                let target_epoch = if chain_epoch_ahead {
                    tip_state.map(|(cert_epoch, _)| cert_epoch).unwrap_or(epoch)
                } else {
                    epoch + 1
                };
                'epoch_advance: while epoch < target_epoch {
                    let new_epoch = epoch + 1;
                    if let Err(error) = node.advance_epoch_with_vrf(new_epoch, vrf_secret.as_ref()) {
                        error!("[validator-loop] epoch 状态持久化失败：{error}");
                        break 'epoch_advance;
                    }
                    epoch = new_epoch;
                    // DAG parents are epoch-local. Start the new epoch from a parentless round 1
                    // and discard the old-epoch live DAG so the next vertex cannot accidentally
                    // reference a parent which admission must reject. Certificate commit rounds are
                    // chain-global and must remain continuous across the epoch boundary: resetting
                    // them here would make the next locally produced block fail Node's prev+1 check.
                    // epoch 边界 tx 蒸发修复（同跟随路径）：未 commit 的
                    // 自家 vertex tx 回收进 pending，重播窗口清空。
                    {
                        let mut rescued = Vec::new();
                        for v in &recent_own_vertices {
                            if !committed_vertices.contains(&v.vertex_hash()) {
                                rescued.extend(v.tx_list.iter().cloned());
                            }
                        }
                        if !rescued.is_empty() {
                            node.requeue_pending_txs(rescued);
                        }
                    }
                    round = 1;
                    last_vertex = None;
                    committed_vertices.clear();
                    recent_own_vertices.clear();
                    scan_from = 1;
                    *dag.lock().unwrap_or_else(|e| e.into_inner()) = Dag::new();
                    info!(
                        "[validator-loop] epoch 推进至 {}（DAG round 已重置，未提交 tx 已回收，tip commit_round={}，VRF={}）",
                        epoch,
                        tip_state.map(|(_, r)| r).unwrap_or(0),
                        vrf_secret.is_some()
                    );
                }
            }
            // 产出推进（commit 检测之后）：失败路径 produced 为 None 不推进
            // （旧外层推进会把未持久化失败 vertex 记为 last_vertex = 毒药循环）。
            if let Some(produced) = produced_vertex_this_batch.take() {
                last_production_at = Some(std::time::Instant::now());
                last_vertex = Some(produced.clone());
                round += 1;
                recent_own_vertices.push_back(produced);
                while recent_own_vertices.len() > RECENT_OWN_VERTEX_WINDOW {
                    recent_own_vertices.pop_front();
                }
            }
            // batch_tx_count 仅供本作用域日志/调试上下文，显式标记避免未使用告警。
            let _ = batch_tx_count;
        }
    }

    info!("validator 产块循环已停止（共产出 {} 轮 vertex）", round - 1);
}

// ===== tx 子命令（v1.5 演练工具：构造 + 签名 Public tx，输出 submit_tx 参数） =====

/// 构造并签名一笔 Public 通道 tx，输出可直接用于 JSON-RPC `submit_tx` 的参数。
///
/// 输出（单行 JSON）：
/// `{"tx_hash_hex": "..64hex..", "tx_bytes": [b0, b1, ...], "nonce": N}`
///
/// tx 形状与 `test-e2e` 同款（空 inputs/outputs、Gas::zero、AnyValidator 路由），
/// 签名为 secp256k1 recoverable（65B r||s||v）。演练脚本用 `tx_bytes` 数组直接
/// 拼 `{"method":"submit_tx","params":{"tx_bytes":[..]}}`。
fn run_tx(args: &[String]) -> Result<(), String> {
    let mut secret_hex: Option<String> = None;
    let mut payload = b"tx".to_vec();
    let mut nonce: u64 = 0;
    let mut chain_id = poker_l1::DEFAULT_CHAIN_ID;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret-key-hex" | "--secret-key-file" => {
                i += 1;
                let v = args.get(i).ok_or("--secret-key-* 缺少参数")?;
                secret_hex = Some(if args[i - 1] == "--secret-key-file" {
                    std::fs::read_to_string(v)
                        .map_err(|e| format!("读取私钥文件失败：{e}"))?
                        .trim()
                        .to_string()
                } else {
                    v.clone()
                });
            }
            "--payload" => {
                i += 1;
                let v = args.get(i).ok_or("--payload 缺少参数")?;
                payload = v.as_bytes().to_vec();
            }
            "--nonce" => {
                i += 1;
                let v = args.get(i).ok_or("--nonce 缺少参数")?;
                nonce = v.parse::<u64>().map_err(|e| format!("--nonce 解析失败：{e}"))?;
            }
            "--chain-id" => {
                i += 1;
                let v = args.get(i).ok_or("--chain-id 缺少参数")?;
                chain_id = u64::from_str_radix(v.trim_start_matches("0x"), 16)
                    .map_err(|e| format!("--chain-id 解析失败：{e}"))?;
            }
            "--help" | "-h" => {
                eprintln!("用法: zchain tx --secret-key-hex <hex>|--secret-key-file <path> [--payload <ascii>] [--nonce <n>] [--chain-id <hex>]");
                eprintln!("  构造并签名 Public tx，输出 submit_tx 参数 JSON（单行）。");
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }
    let secret_hex = secret_hex.ok_or("必须提供 --secret-key-hex 或 --secret-key-file")?;
    let secret_bytes = hex::decode(secret_hex.trim()).map_err(|e| format!("私钥 hex 解码失败：{e}"))?;
    if secret_bytes.len() != 32 {
        return Err(format!("私钥必须为 32 字节，得到 {}", secret_bytes.len()));
    }
    let secp = secp256k1::Secp256k1::new();
    let secret_key =
        secp256k1::SecretKey::from_slice(&secret_bytes).map_err(|e| format!("私钥无效：{e}"))?;
    let public = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        public.serialize().to_vec(),
    )
    .map_err(|e| format!("tagged_pubkey 构造失败：{e}"))?;

    let unsigned = Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey,
        signature: vec![],
        gas: Gas::zero(),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    };
    // 签名对象须含 payload 语义：复用 outputs content 参与签名？否 —— v1 tx 签名
    // 只覆盖 signing_hash（结构域）。payload 写入 outputs.data 以保证不同
    // --payload 产出不同 tx_hash：改用单 output 携带 payload 字节。
    let mut tx = unsigned;
    if !payload.is_empty() {
        tx.outputs = vec![poker_l1::object_model::Object::new(
            poker_l1::object_model::ObjectID::new(derive_address(&tx.tagged_pubkey), nonce + 1),
            poker_l1::object_model::Ownership::Shared,
            "DrillPayload",
            payload,
            None,
        )];
    }
    let signing_hash = tx.signing_hash();
    let msg = secp256k1::Message::from_digest(signing_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut full_sig = compact.to_vec();
    full_sig.push(recovery_id.to_i32() as u8);
    tx.signature = full_sig;

    let tx_bytes = tx.to_bcs().map_err(|e| format!("tx BCS 序列化失败：{e}"))?;
    let bytes_json: Vec<String> = tx_bytes.iter().map(|b| b.to_string()).collect();
    println!(
        "{{\"tx_hash_hex\":\"{}\",\"tx_bytes\":[{}],\"nonce\":{}}}",
        hex::encode(tx.tx_hash()),
        bytes_json.join(","),
        nonce
    );
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

// ===== dkg 子命令 =====

/// 运行 deal-sum DKG 密钥供给（v1.5-e 原型部署面）。
///
/// 语义（见 `poker_l1::consensus::dkg` 模块头）：n 个 dealer **在本单进程内**
/// 各自执行 [`dealer_deal`]（真 t-of-n：群私钥从不以明文存在于任何单点——
/// 每个 dealer 只产出逐点份额），逐份额 Feldman 校验后 deal-sum 组装
/// `keyset.json`（公开面，全体节点共用）与 `share-<id>.json`（私密面，分发
/// 至对应参与者节点 `--dkg-share`）。生产部署中 dealer 应各自在 validator
/// 进程内执行并经加密 P2P 交换 DkgDeal——算法与安全性性质一致，仅传输面不同。
fn run_dkg(args: &[String]) -> Result<(), String> {
    let mut n: u32 = 0;
    let mut t: u32 = 0;
    let mut out_dir = PathBuf::from("./dkg-out");
    let mut seed_hex: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => {
                i += 1;
                let v = args.get(i).ok_or("--n 缺少参数")?;
                n = v.parse::<u32>().map_err(|e| format!("--n 解析失败：{e}"))?;
            }
            "--t" => {
                i += 1;
                let v = args.get(i).ok_or("--t 缺少参数")?;
                t = v.parse::<u32>().map_err(|e| format!("--t 解析失败：{e}"))?;
            }
            "--out-dir" => {
                i += 1;
                out_dir = PathBuf::from(args.get(i).ok_or("--out-dir 缺少参数")?);
            }
            "--seed" => {
                i += 1;
                seed_hex = Some(args.get(i).ok_or("--seed 缺少参数")?.clone());
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other => return Err(format!("未知参数：{other}")),
        }
        i += 1;
    }
    if n == 0 || t == 0 {
        return Err("dkg 需要 --n <n> 与 --t <t>（2 <= t <= n）".to_string());
    }
    // 种子：显式提供（演练可重现）或 CSPRNG（生产口径）。
    let master_seed: [u8; 32] = match seed_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())
                .map_err(|e| format!("--seed hex 解码失败：{e}"))?;
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "--seed 必须为 32 字节 hex".to_string())?
        }
        None => {
            use rand::rngs::OsRng;
            use rand::RngCore;
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s
        }
    };
    let deals: Vec<poker_l1::consensus::dkg::DkgDeal> = (1..=u64::from(n))
        .map(|dealer_id| {
            // 每个 dealer 独立域派生种子（同 master 种子下的确定性演练口径）
            let mut dealer_seed = [0u8; 32];
            let mut h = blake2::Blake2bVar::new(32).map_err(|e| e.to_string())?;
            use blake2::digest::{Update, VariableOutput};
            h.update(b"ZCHAIN_DKG_CLI_DEALER_SEED_V1");
            h.update(&master_seed);
            h.update(&dealer_id.to_le_bytes());
            let mut out = [0u8; 32];
            h.finalize_variable(&mut out).map_err(|e| e.to_string())?;
            dealer_seed = out;
            poker_l1::consensus::dkg::dealer_deal(&dealer_seed, dealer_id, n, t)
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, String>>()?;
    let (keyset, shares) =
        poker_l1::consensus::dkg::assemble_group_keyset(&deals, n, t).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("创建输出目录失败：{e}"))?;
    let keyset_json = poker_l1::node::dkg_keyset_to_json(&keyset).map_err(|e| e.to_string())?;
    let keyset_path = out_dir.join("keyset.json");
    std::fs::write(&keyset_path, keyset_json)
        .map_err(|e| format!("写 keyset.json 失败：{e}"))?;
    for share in &shares {
        let share_json = poker_l1::node::dkg_share_to_json(share).map_err(|e| e.to_string())?;
        let path = out_dir.join(format!("share-{}.json", share.id));
        std::fs::write(&path, share_json).map_err(|e| format!("写 {} 失败：{e}", path.display()))?;
    }
    println!(
        "{}",
        serde_json::json!({
            "n": n,
            "t": t,
            "group_key_digest": format!("0x{}", hex::encode(keyset.group_key_digest())),
            "keyset_file": keyset_path.display().to_string(),
            "share_files": (1..=n).map(|id| out_dir.join(format!("share-{id}.json")).display().to_string()).collect::<Vec<_>>(),
        })
        .to_string()
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
    // genesis validator set：本测试是单 validator 夹具——把自己的 key 以
    // Active 状态（stake=0，genesis 无背书记账）注入 genesis 集，否则
    // put_block 的"空 active 集拒绝 + 证书 quorum 验签"两道生产闸都会
    // （正确地）拒绝夹具区块。
    let mut genesis_entry = poker_l1::consensus::validator_set::ValidatorEntry::new(
        vkey.tagged_pubkey.clone(),
        [0u8; 33],
        0,
        0,
    );
    genesis_entry.status = poker_l1::consensus::validator_set::ValidatorStatus::Active;
    let config = NodeConfig::validator(data_dir.clone(), vkey)
        .with_genesis_validators(vec![genesis_entry]);
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
    // 真实 state root：与生产路径同款——先在执行环境模拟区块执行，
    // put_block 的"header.state_root == 执行后状态根"闸要求两者一致。
    let proposer = poker_l1::account::derive_address(&tagged_pubkey);
    let env = node
        .execution_environment(block_height, timestamp_ms)
        .with_proposer(proposer);
    let outcome = node
        .simulate_block_execution(&env, &public_txs)
        .map_err(|e| format!("simulate_block_execution 失败：{e}"))?;
    let cert = {
        // 首块证书：epoch 必须等于 validator set 当前 epoch（0）——
        // put_block 校验"首个证书 epoch == validator_set epoch"（node/mod.rs）；
        // 签名必须对本 validator 私钥真实可恢复（证书 quorum 验签闸）。
        let mut c = DagCommitCertificate {
            epoch: 0,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            // 单 validator 夹具：bit 0 置位（bitmap 语义 = validator 索引位）
            round_attendance_bitmap: vec![0x01],
            state_root: outcome.state_root,
            public_tx_root,
            gameturn_tx_root,
            signature_list: vec![],
            signer_bitmap: vec![0x01],
        };
        let msg = Message::from_digest(c.signing_hash(node.chain_id()));
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut sig65 = compact.to_vec();
        sig65.push(recovery_id.to_i32() as u8);
        c.signature_list = vec![sig65];
        c
    };
    let header = BlockHeader {
        height: block_height,
        timestamp_ms,
        prev_hash,
        state_root: outcome.state_root,
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
    fn tcp_transport_subscribes_to_deduplicated_light_headers() {
        let transport = TcpTransport::new();
        let header = LightClientHeader {
            header_bytes: vec![0xA5; 16],
            signatures: vec![],
            signer_bitmap: vec![],
        };

        assert!(transport.merge_light_header(header.clone()));
        assert!(!transport.merge_light_header(header.clone()));
        assert_eq!(
            transport.subscribe_light_headers().unwrap(),
            vec![header],
            "transport subscription must expose the cached header exactly once"
        );
    }

    #[test]
    fn tcp_transport_pex_rejects_non_dialable_addresses_and_deduplicates() {
        let transport = TcpTransport::new();
        let valid = PeerInfo {
            peer_id: "valid".into(),
            address: "127.0.0.1:9001".into(),
            validator_pubkey: None,
        };
        let invalid = PeerInfo {
            peer_id: "invalid".into(),
            address: "not-a-socket-address".into(),
            validator_pubkey: None,
        };

        assert_eq!(
            transport.merge_discovered_peers(&[valid.clone(), invalid]),
            vec!["127.0.0.1:9001".to_string()],
            "合法地址应被加入并返回为新增地址"
        );
        assert!(
            transport.merge_discovered_peers(&[valid]).is_empty(),
            "重复地址不应再次返回"
        );
        let peers = transport.discover_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "127.0.0.1:9001");
    }

    #[test]
    fn sleep_interruptible_returns_early_on_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let killer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        assert!(!sleep_interruptible(Duration::from_secs(5), &shutdown));
        assert!(started.elapsed() < Duration::from_secs(1));
        killer.join().unwrap();

        // shutdown 未触发的全新标志下应睡满并返回 true。
        let fresh = Arc::new(AtomicBool::new(false));
        let started = std::time::Instant::now();
        assert!(sleep_interruptible(Duration::from_millis(100), &fresh));
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn connection_supervisor_dedups_and_skips_own_address() {
        let transport = Arc::new(TcpTransport::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let supervisor = Arc::new(ConnectionSupervisor::new(
            Arc::clone(&transport),
            "127.0.0.1:9999".to_string(),
            Arc::clone(&shutdown),
        ));
        let node = Arc::new(Node::open_inmemory(NodeRole::Full, poker_l1::DEFAULT_CHAIN_ID).unwrap());
        let dag = Arc::new(Mutex::new(Dag::new()));
        let votes = Arc::new(VoteCollector::new());
        let gossip = Arc::new(GossipManager::new());

        // 自身监听地址永不拨号。
        assert!(!supervisor.ensure_dialing(
            "127.0.0.1:9999".to_string(),
            &node,
            &dag,
            &votes,
            &gossip
        ));
        // 同一地址只启动一个 dialer。
        assert!(supervisor.ensure_dialing(
            "127.0.0.1:19001".to_string(),
            &node,
            &dag,
            &votes,
            &gossip
        ));
        assert!(!supervisor.ensure_dialing(
            "127.0.0.1:19001".to_string(),
            &node,
            &dag,
            &votes,
            &gossip
        ));
        assert_eq!(supervisor.dialing.lock().unwrap_or_else(|e| e.into_inner()).len(), 1);
        // shutdown 后 dialer 退出并释放去重槽位。
        shutdown.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !supervisor
            .dialing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "dialer 线程应在 shutdown 后释放去重槽位"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn tcp_transport_serializes_concurrent_gossip_and_response_frames() {
        // The persistent broadcast path and a request/response reply share a
        // single TCP write half.  This loopback test is deliberately at the
        // framing boundary: receiving two independently framed messages proves
        // that the length prefix of one was not interleaved with the other's
        // payload.
        let (mut read_stream, write_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        read_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let receiver = std::thread::spawn(move || {
            vec![
                recv_p2p_message(&mut read_stream).unwrap().unwrap(),
                recv_p2p_message(&mut read_stream).unwrap().unwrap(),
            ]
        });

        let writer: Arc<Mutex<Box<dyn P2pIo>>> = Arc::new(Mutex::new(Box::new(write_stream)));
        let transport = Arc::new(TcpTransport::new());
        transport.add_peer(Arc::clone(&writer));

        let broadcast_transport = Arc::clone(&transport);
        let broadcast = std::thread::spawn(move || {
            broadcast_transport
                .gossip_broadcast(
                    GossipTopic::DagVertex,
                    &NetworkMessage::LightClientHeader(LightClientHeader {
                        header_bytes: vec![0xA5; 32 * 1024],
                        signatures: vec![],
                        signer_bitmap: vec![],
                    }),
                )
                .unwrap();
        });
        let response_writer = Arc::clone(&writer);
        let response = std::thread::spawn(move || {
            send_p2p_message_locked(
                &response_writer,
                &NetworkMessage::PeerExchange(vec![PeerInfo {
                    peer_id: "response".into(),
                    address: "127.0.0.1:9001".into(),
                    validator_pubkey: None,
                }]),
            )
            .unwrap();
        });

        broadcast.join().unwrap();
        response.join().unwrap();
        let messages = receiver.join().unwrap();
        assert!(
            messages
                .iter()
                .any(|message| matches!(message, NetworkMessage::LightClientHeader(_))),
            "gossip frame must remain parseable"
        );
        assert!(
            messages
                .iter()
                .any(|message| matches!(message, NetworkMessage::PeerExchange(_))),
            "response frame must remain parseable"
        );
    }

    #[test]
    fn compact_vertex_cache_miss_falls_back_to_full_vertex_and_persists() {
        let secret_key = secp256k1::SecretKey::from_slice(&[0x37; 32]).unwrap();
        let public_key =
            secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret_key);
        let author_pubkey = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public_key.serialize().to_vec(),
        )
        .unwrap();

        // The receiver deliberately does not cache this transaction. Its first
        // attempt to reconstruct the compact vertex must therefore request the
        // authenticated full vertex from the sender.
        let mut tx = make_sized_tx(64);
        tx.chain_id = poker_l1::DEFAULT_CHAIN_ID;
        tx.tagged_pubkey = author_pubkey.clone();
        tx.signature = secp256k1_sign_hash(&secret_key, &tx.signing_hash());
        let mut vertex = DagVertex {
            epoch: 1,
            round: 1,
            author_pubkey,
            tx_list: vec![tx],
            parent_hashes: vec![],
            author_sig: vec![],
            forced_tx_hashes: Vec::new(),
        };
        vertex.author_sig = secp256k1_sign_hash(
            &secret_key,
            &vertex.signing_hash(poker_l1::DEFAULT_CHAIN_ID),
        );
        let vertex_hash = vertex.vertex_hash();

        let sender_node =
            Arc::new(Node::open_inmemory(NodeRole::Full, poker_l1::DEFAULT_CHAIN_ID).unwrap());
        sender_node.put_vertex(&vertex).unwrap();
        let receiver_node =
            Arc::new(Node::open_inmemory(NodeRole::Full, poker_l1::DEFAULT_CHAIN_ID).unwrap());

        let (sender_stream, receiver_stream) = std::os::unix::net::UnixStream::pair().unwrap();
        sender_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        receiver_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let sender_transport = Arc::new(TcpTransport::new());
        let receiver_transport = Arc::new(TcpTransport::new());
        let sender_dag = Arc::new(Mutex::new(Dag::new()));
        let receiver_dag = Arc::new(Mutex::new(Dag::new()));
        let sender_gossip = Arc::new(GossipManager::new());
        let receiver_gossip = Arc::new(GossipManager::new());

        let sender_handler = {
            let node = Arc::clone(&sender_node);
            let transport = Arc::clone(&sender_transport);
            let dag = Arc::clone(&sender_dag);
            let gossip = Arc::clone(&sender_gossip);
            std::thread::spawn(move || {
                handle_p2p_connection(
                    sender_stream,
                    node,
                    transport,
                    dag,
                    Arc::new(VoteCollector::new()),
                    gossip,
                    None,
                );
            })
        };
        let receiver_handler = {
            let node = Arc::clone(&receiver_node);
            let transport = Arc::clone(&receiver_transport);
            let dag = Arc::clone(&receiver_dag);
            let gossip = Arc::clone(&receiver_gossip);
            std::thread::spawn(move || {
                handle_p2p_connection(
                    receiver_stream,
                    node,
                    transport,
                    dag,
                    Arc::new(VoteCollector::new()),
                    gossip,
                    None,
                );
            })
        };

        let connected_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while sender_transport
            .peers
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < connected_deadline,
                "sender handler did not register its shared writer"
            );
            std::thread::yield_now();
        }

        sender_gossip
            .broadcast_compact_vertex(&vertex, sender_transport.as_ref())
            .unwrap();

        let persistence_deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if receiver_node
                .vertex_store()
                .get_by_hash(&vertex_hash)
                .is_ok()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < persistence_deadline,
                "receiver did not persist the full-vertex fallback"
            );
            std::thread::yield_now();
        }

        assert_eq!(
            receiver_node
                .vertex_store()
                .get_by_hash(&vertex_hash)
                .unwrap(),
            vertex
        );
        assert!(
            receiver_dag
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .get(&vertex_hash)
                .is_some(),
            "validated fallback vertex must also enter the live DAG"
        );

        sender_handler.join().unwrap();
        receiver_handler.join().unwrap();
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
            height: 10,
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
            forced_tx_hashes: Vec::new(),
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
    fn block_range_scan_is_bounded_even_when_range_is_huge_and_sparse() {
        let node = Node::open_inmemory(NodeRole::Full, poker_l1::DEFAULT_CHAIN_ID).unwrap();

        assert!(collect_blocks_by_range(&node, 10, 9).is_empty());
        assert!(collect_blocks_by_range(&node, 1, u64::MAX).is_empty());
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
