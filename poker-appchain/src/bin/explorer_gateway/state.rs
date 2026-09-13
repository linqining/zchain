//! explorer gateway — 网关态装配（WAL 全量重放 + proven log 水位恢复 +
//! proof 注册表 / aggregate log 装载 + **archive 索引直连模式**）。
//!
//! 网关是**只读**进程，两种数据面：
//!
//! - **replay 模式**（默认，`load`）：启动时从 WAL 全量重放（验签 + 逐帧
//!   状态根重验，fail-closed——任何损坏直接退出非零），再把 proven log 的
//!   水位/批次根经 sequencer 公开 API（`mark_proven_through_with_root`）
//!   恢复进内存；
//! - **index 模式**（`--index-file`，`load_with_index`）：跳过全量 replay，
//!   直接装载持久化索引（`archive_index::load_index`，digest/契约 fail-closed
//!   校验），帧/结算/状态查询由索引服务；单笔结算明细按索引记录的 WAL
//!   字节偏移**定向读单帧**并做完整性校验（签名 + 哈希 + 状态根与索引行
//!   交叉核对）。
//!
//! proof 归档注册表与 aggregate log 为只读装载（两模式同语义）；proven
//! log 在 index 模式只恢复水位数值（无 sequencer 实例可回填）。运行期
//! 不接受任何写路径。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use poker_appchain::archive_index::{self, ArchiveIndex};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::proof_registry::{self, ProofRegistryEntry};
use poker_appchain::sequencer::{Sequencer, SequencerConfig};

use super::aggregate_log::{self, AggregateEntry};
use super::proven_log::{self, ProvenEntry};

/// 网关内存态（启动后跨线程共享）。
///
/// `seq` 以 `Option<Mutex<Sequencer>>` 表达数据面：replay 模式 `Some`，
/// index 模式 `None`（此时 `index` 必为 `Some`）。运行期 replay 模式的
/// `wal` 恒为 `None`（replay 不挂 WAL），类型层面仍须互斥——`Sequencer`
/// 因 `WalWriter` 内含非 `Sync` 的 sink trait object 而不可直接 `Arc` 共享。
pub struct GatewayState {
    /// replay 数据面（重放重建的 sequencer；只读使用：`chain()` / `state()`）。
    pub seq: Option<Mutex<Sequencer>>,
    /// index 数据面（`--index-file` 时为 `Some`）。
    pub index: Option<ArchiveIndex>,
    /// WAL 路径（index 模式定向读帧用；replay 模式 `None`）。
    pub wal_path: Option<PathBuf>,
    /// 数据面标签：`"replay"` 或 `"index"`（status/metrics/快照回显）。
    pub data_source: &'static str,
    /// sequencer 公钥（32B，创世参数；index 模式同时是定向读帧的验签判据）。
    pub sequencer_public: [u8; 32],
    /// 水位（proven log 恢复；None = 无 proven log，全部软确认层）。
    pub watermark: Option<u64>,
    /// 水位来源标签：`"proven_log"` 或 `"none"`。
    pub watermark_source: &'static str,
    /// proven log 条目（batch_roots 端点数据源，按追加序）。
    pub proven: Vec<ProvenEntry>,
    /// proof 归档注册表条目（proofs/proof 端点数据源；未挂
    /// `--proof-registry` 时为空）。
    pub proofs: Vec<ProofRegistryEntry>,
    /// aggregate log 条目（aggregates 端点数据源；未挂
    /// `--aggregate-log` 时为空）。
    pub aggregates: Vec<AggregateEntry>,
    /// 指标注册表（replay 期间写入；`/api/v1/metrics` 导出其静态快照）。
    pub metrics: Arc<MetricsRegistry>,
}

/// 从 WAL + 可选 sidecar 装配网关态（replay 模式）。
///
/// # Errors
/// WAL 重放失败（链断裂/签名坏/状态根分叉/文件不可读）或任一 sidecar
/// 损坏 → Err（描述性消息；调用方必须退出非零）。
pub fn load(
    wal_path: &Path,
    sequencer_public: [u8; 32],
    proven_log_path: Option<&Path>,
    proof_registry_path: Option<&Path>,
    aggregate_log_path: Option<&Path>,
) -> Result<GatewayState, String> {
    let metrics = Arc::new(MetricsRegistry::new());
    let config = SequencerConfig {
        // 网关只读：限流参数不影响重放（replay 不走在线准入）。
        ops_per_min: u32::MAX,
        open_table_per_min: u32::MAX,
        ..SequencerConfig::default()
    };
    let mut seq = Sequencer::replay(
        wal_path,
        sequencer_public,
        config,
        Arc::clone(&metrics),
    )
    .map_err(|e| format!("WAL replay failed: {e}"))?;

    let (proven, watermark) = load_proven(proven_log_path)?;
    // 恢复 sequencer 内存态（水位 + §5.4 批次根证据）。
    for entry in &proven {
        seq.mark_proven_through_with_root(entry.op_index, entry.batch_root);
    }
    let proofs = load_proofs(proof_registry_path)?;
    let aggregates = load_aggregates(aggregate_log_path)?;

    Ok(GatewayState {
        seq: Some(Mutex::new(seq)),
        index: None,
        wal_path: None,
        data_source: "replay",
        sequencer_public,
        watermark,
        watermark_source: if watermark.is_some() { "proven_log" } else { "none" },
        proven,
        proofs,
        aggregates,
        metrics,
    })
}

/// 从持久化索引 + 可选 sidecar 装配网关态（index 模式；免全量 replay）。
///
/// fail-closed：索引文件 digest/契约/行数任何校验失败 → Err；索引头部的
/// sequencer 公钥与 `--sequencer-public` 不一致 → Err（索引发错链防线）。
///
/// # Errors
/// 索引装载失败或任一 sidecar 损坏 → Err（描述性消息；调用方必须退出非零）。
pub fn load_with_index(
    index_path: &Path,
    wal_path: &Path,
    sequencer_public: [u8; 32],
    proven_log_path: Option<&Path>,
    proof_registry_path: Option<&Path>,
    aggregate_log_path: Option<&Path>,
) -> Result<GatewayState, String> {
    let index = archive_index::load_index(index_path)
        .map_err(|e| format!("archive index load failed: {e}"))?;
    if index.header().sequencer_public != sequencer_public {
        return Err(format!(
            "archive index belongs to sequencer {} but gateway started with {} (fail-closed)",
            hex::encode(index.header().sequencer_public),
            hex::encode(sequencer_public),
        ));
    }
    let (proven, watermark) = load_proven(proven_log_path)?;
    let proofs = load_proofs(proof_registry_path)?;
    let aggregates = load_aggregates(aggregate_log_path)?;
    Ok(GatewayState {
        seq: None,
        index: Some(index),
        wal_path: Some(wal_path.to_path_buf()),
        data_source: "index",
        sequencer_public,
        watermark,
        watermark_source: if watermark.is_some() { "proven_log" } else { "none" },
        proven,
        proofs,
        aggregates,
        metrics: Arc::new(MetricsRegistry::new()),
    })
}

/// proven log 装载（两模式共用；撕裂尾行容错语义与 replay 模式一致）。
fn load_proven(
    proven_log_path: Option<&Path>,
) -> Result<(Vec<ProvenEntry>, Option<u64>), String> {
    let mut warnings = Vec::new();
    let proven = match proven_log_path {
        Some(p) => {
            let log = proven_log::read(p)?;
            warnings.extend(log.warnings);
            log.entries
        }
        None => Vec::new(),
    };
    for w in &warnings {
        eprintln!("[explorer_gateway] warning: {w}");
    }
    let watermark = proven.last().map(|e| e.op_index);
    Ok((proven, watermark))
}

/// proof 归档注册表装载（只读；容错语义与 proven log 一致）。
fn load_proofs(proof_registry_path: Option<&Path>) -> Result<Vec<ProofRegistryEntry>, String> {
    match proof_registry_path {
        Some(p) => proof_registry::read_registry(p).map_err(|e| format!("proof registry: {e}")),
        None => Ok(Vec::new()),
    }
}

/// aggregate log 装载（只读）。
fn load_aggregates(aggregate_log_path: Option<&Path>) -> Result<Vec<AggregateEntry>, String> {
    match aggregate_log_path {
        Some(p) => {
            let log = aggregate_log::read(p)?;
            for w in &log.warnings {
                eprintln!("[explorer_gateway] warning: {w}");
            }
            Ok(log.entries)
        }
        None => Ok(Vec::new()),
    }
}
