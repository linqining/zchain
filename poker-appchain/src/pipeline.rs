//! M4：证明管道——任务队列、worker 池、批次聚合、积压降级。
//!
//! 证明引擎抽象为 [`SettlementProver`] trait：v1 落地 [`ValidationEngine`]
//! （host 侧关系校验引擎，attestation 模式——与主仓库 Phase 1 姿态一致）；
//! stwo 真引擎通过实现同 trait 接入，管道机制不变。
//!
//! ## 语义
//!
//! - submit → 入队（有界，背压 = 阻塞）
//! - worker 并行 prove → 完成回调标记 proven + 入批次；**prove 失败/panic
//!   的任务带尝试计数回队有界重试**（[`MAX_PROVE_RETRIES`] 次，超限后留在
//!   队列并暴露 `prove_retry_exhausted_total` 告警计数，绝不丢弃）
//! - 批次：只从「最早的未批次化任务」起收集已完成任务的**连续前缀**，遇
//!   空洞（失败/未完成）即停——批次不越过未证明操作；验证失败不丢
//!   completion（可重新组批）；批次根 = Poseidon 确定性折叠（[`batch_root`]）
//! - 批次验证通过 → [`ProofPipeline::set_on_batch_proven`] 回调（生产装配点
//!   接线 `sequencer::Sequencer::mark_proven_through` 推进证明水位）
//! - REAL 结算出证策略（P0-3）：[`RealSettlementPolicy`] 三层门——引擎层
//!   （host 引擎对 REAL 一律 [`AppchainError::RealRequiresStarkProof`]）、
//!   提交层（模式/引擎能力/verifier key 钉扎/hand_proof 准入，拒绝尽早）、
//!   批次层（允许集 + attestor 钉扎复查——违反则该 op 不标记已证明、水位
//!   不推进，并计 `real_settlement_rejected_total` 告警）
//! - 积压降级：inflight 超高水位 → degraded（告警 + 建议稀疏批次档）

use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::aggregate::{aggregate_roots, AggregateRecord};
use crate::error::{AppchainError, AppchainResult};
use crate::fee::FeePolicy;
use crate::felt::{bytes32_to_felts, domain_felt, felt_to_bytes32, DOMAIN_BATCH_ROOT};
use crate::metrics::{evaluate_alerts, Alert, HealthInputs, MetricsRegistry};
use crate::proof_registry::{ProofRegistryEntry, ProofRegistryWriter};
use crate::real_policy::{is_real_settlement, RealMode, RealSettlementPolicy, STARK_ENGINE_PREFIX};
use crate::settlement::SettlementRecord;

/// 优先级：real 桌 > play 桌（plan §M4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// 休闲桌。
    Play,
    /// 真金桌。
    Real,
}

/// 证明任务。
#[derive(Debug, Clone)]
pub struct ProofJob {
    /// 帧链序号（proven 水位的推进依据）。
    pub op_index: u64,
    /// 桌 ID。
    pub table_id: u64,
    /// 结算记录。
    pub record: Arc<SettlementRecord>,
    /// 桌绑定策略。
    pub policy: FeePolicy,
    /// 优先级。
    pub priority: Priority,
}

/// 证明产物（v1 attestation 形态；stwo 引擎接入后携带归档证明字节）。
#[derive(Debug, Clone)]
pub struct ProofBundle {
    /// 对应任务的结算绑定（hex 编码 32B）。
    pub binding_hex: String,
    /// 帧链序号。
    pub op_index: u64,
    /// 引擎标识（版本化，如 "host-validate-v2"）。
    pub engine: &'static str,
    /// attestation 签名公钥（32B ed25519）。
    pub attestor_public: [u8; 32],
    /// 证明载荷（v1 = attestation 签名 64B；v2 = stwo proof archive）。
    pub payload: Vec<u8>,
}

/// 证明引擎 seam。
pub trait SettlementProver: Send + Sync {
    /// 引擎标识。
    fn name(&self) -> &'static str;
    /// 生成证明。
    ///
    /// # Errors
    /// 关系校验失败或引擎内部错误。
    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle>;
    /// 验证证明（独立代码路径，与 prove 不共享中间态）。
    ///
    /// # Errors
    /// 证明无效。
    fn verify(&self, bundle: &ProofBundle) -> AppchainResult<()>;
}

fn attestation_message(binding_hex: &str) -> AppchainResult<Vec<u8>> {
    let binding = hex::decode(binding_hex)
        .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
    if binding.len() != 32 {
        return Err(AppchainError::AdmissionRejected("bad binding length"));
    }
    Ok(crate::keys::blake2s32(&[b"host-validate-v2", &binding]).to_vec())
}

/// v1 host 校验引擎：prove = 关系纯函数校验 + **attestor 签名**。
///
/// 与主仓库 Phase 1 姿态一致（host 验证 + 浏览器可复验）；审计 C3 修复：
/// attestation 载荷由 attestor 密钥签名（可归属、不可伪造），不再是
/// 任何人可算的摘要。stwo 引擎接入是 `texas-air` feature 适配器
/// （`texas_air_engine`）。
#[derive(Debug, Clone)]
pub struct ValidationEngine {
    attestor: ed25519_dalek::SigningKey,
}

impl ValidationEngine {
    /// 指定 attestor 密钥构造（生产：环境注入；不得入库）。
    #[must_use]
    pub fn new(attestor: ed25519_dalek::SigningKey) -> Self {
        Self { attestor }
    }

    /// attestor 公钥。
    #[must_use]
    pub fn attestor_public(&self) -> [u8; 32] {
        self.attestor.verifying_key().to_bytes()
    }
}

impl Default for ValidationEngine {
    /// 默认构造：**确定性开发密钥，仅限测试**（生产必须 [`ValidationEngine::new`]）。
    fn default() -> Self {
        Self::new(ed25519_dalek::SigningKey::from_bytes(&[
            0x50, 0x4f, 0x4b, 0x45, 0x52, 0x2d, 0x41, 0x50, 0x50, 0x43, 0x48, 0x41,
            0x49, 0x4e, 0x2d, 0x44, 0x45, 0x56, 0x2d, 0x4b, 0x45, 0x59, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
        ]))
    }
}

impl SettlementProver for ValidationEngine {
    fn name(&self) -> &'static str {
        "host-validate-v2"
    }

    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
        // P0-3 引擎层门（fail-closed）：host 签名引擎天然不能给 REAL 出证
        // ——与管道模式无关，REAL 结算在此一律拒绝（真实证明必须走
        // texas-air-* STARK 引擎的 stwo 验证路径）。
        if is_real_settlement(&job.record) {
            return Err(AppchainError::RealRequiresStarkProof);
        }
        crate::settlement::validate_settlement(&job.record, &job.policy)?;
        let binding_hex = hex::encode(job.record.hand_binding);
        let msg = attestation_message(&binding_hex)?;
        use ed25519_dalek::Signer as _;
        let payload = self.attestor.sign(&msg).to_bytes().to_vec();
        Ok(ProofBundle {
            binding_hex,
            op_index: job.op_index,
            engine: self.name(),
            attestor_public: self.attestor_public(),
            payload,
        })
    }

    fn verify(&self, bundle: &ProofBundle) -> AppchainResult<()> {
        if bundle.engine != self.name() {
            return Err(AppchainError::AdmissionRejected("unknown engine"));
        }
        if bundle.payload.len() != 64 {
            return Err(AppchainError::AdmissionRejected("bad payload"));
        }
        let msg = attestation_message(&bundle.binding_hex)?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bundle.payload);
        if !crate::keys::SequencerKey::verify(&bundle.attestor_public, &msg, &sig) {
            return Err(AppchainError::BadSignature);
        }
        Ok(())
    }
}

/// 批次根域折叠 + 域分隔（P0-6：统一为 crate 内既有 Poseidon；与
/// docs/ABI.md §「批次根」逐字一致）：
///
/// ```text
/// fold_0 = 0
/// fold_i = poseidon_hash_many([fold_{i-1}, hi_i, lo_i])  // binding 32B → hi/lo 无损拆分
/// root   = felt_to_bytes32(poseidon_hash_many([D, fold_n]))
/// D      = domain_felt("poker-appchain.batch_root.v1")   // felt::DOMAIN_BATCH_ROOT
/// ```
///
/// 审计修复：旧实现误用 `keys::blake2s32`，现与全链状态根/nullifier 折叠
/// 同一 Poseidon 实现与编码纪律（任意 32B 入域一律 hi/lo 拆分）。
///
/// # Errors
/// 本函数总成功（输入已是定长字节；保留 Result 以对齐 ABI 演进空间）。
pub fn batch_root(bindings: &[[u8; 32]]) -> AppchainResult<[u8; 32]> {
    let mut fold = FieldElement::ZERO;
    for b in bindings {
        let (hi, lo) = bytes32_to_felts(b);
        fold = poseidon_hash_many(&[fold, hi, lo]);
    }
    Ok(felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_BATCH_ROOT),
        fold,
    ])))
}

/// 批次根（绑定序确定性折叠，算法见 [`batch_root`] 与 docs/ABI.md
/// §「批次根」）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRoot {
    /// 批次序号。
    pub index: u64,
    /// 批次根（32B）。
    pub root: [u8; 32],
    /// 覆盖的结算数。
    pub count: usize,
    /// 覆盖的最大帧序号（proven 水位推进依据）。
    pub through_op: u64,
}

/// 管道配置。
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// worker 数。
    pub workers: usize,
    /// 有界队列深度（背压点）。
    pub queue_bound: usize,
    /// 高水位（超过则降级）。
    pub high_watermark: usize,
    /// 批次大小（帧数触发）。
    pub batch_size: usize,
    /// 批次时间窗（毫秒触发）。
    pub batch_interval_ms: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            queue_bound: 4_096,
            high_watermark: 3_000,
            batch_size: 64,
            batch_interval_ms: 5_000,
        }
    }
}

/// 单个 prove 失败的最大重试次数（P0-5 有界重试）；超限后任务**留在队列**
/// 并暴露 `prove_retry_exhausted_total` 告警计数（不丢，等瞬态恢复或人工处置）。
pub const MAX_PROVE_RETRIES: u32 = 3;

/// 重试退避（毫秒）：防毒任务热循环。
const PROVE_RETRY_BACKOFF_MS: u64 = 5;

/// 待处理任务 + 已失败尝试计数。
#[derive(Debug, Clone)]
struct PendingJob {
    job: ProofJob,
    attempts: u32,
    /// 入队时刻（M9-ACC-4 `proof_ready_ms` 起点：结算任务提交进管道 →
    /// 证明完成；重试路径原样携带，保证延迟覆盖含重试的全程）。
    enqueued_at: std::time::Instant,
}

/// 批次验证通过回调类型（参数 = 批次 through_op；见
/// [`ProofPipeline::set_on_batch_proven`]）。
pub type ProvenCallback = Arc<dyn Fn(u64) + Send + Sync>;

/// 聚合游标（[`ProofPipeline::aggregate_due`] 的推进水位）：
/// 已折叠进聚合的批次数量、下一个聚合序号、上次聚合时刻。
#[derive(Debug, Default, Clone, Copy)]
struct AggregateCursor {
    /// 已消费（折叠过）的产出批次数量。
    consumed: usize,
    /// 下一个 AggregateRecord 的 index。
    next_index: u64,
    /// 上次聚合触发的 now_ms（首次聚合基准 = 0，now ≥ interval 即触发）。
    last_ms: u64,
}

/// 证明管道（v1 串行提交 + rayon 并行 prove + 完成通道收集）。
pub struct ProofPipeline {
    config: PipelineConfig,
    engine: Arc<dyn SettlementProver>,
    metrics: Arc<MetricsRegistry>,
    inflight: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    completions: Mutex<Vec<ProofBundle>>,
    /// 已提交未批次化的 op_index 集合（P0-5 连续区间组批的空洞依据）。
    outstanding: Arc<Mutex<BTreeSet<u64>>>,
    pending: Arc<Mutex<Vec<PendingJob>>>,
    batch_index: AtomicU64,
    /// 批次验证通过回调（P0-5 接线：生产装配点接 sequencer 水位推进）。
    on_batch_proven: Mutex<Option<ProvenCallback>>,
    rx: Mutex<Option<Receiver<ProofBundle>>>,
    tx: SyncSender<ProofBundle>,
    /// REAL 结算出证策略（P0-3；默认 = fail-closed 的 StarkRequired 未钉 key）。
    real_policy: RealSettlementPolicy,
    /// 已准入的 REAL 结算 op（批次/水位门的判定集合）。
    real_ops: Arc<Mutex<HashSet<u64>>>,
    /// 已产出批次根日志（产出序；M4 outer aggregate [`Self::aggregate_due`]
    /// 的折叠窗口来源）。
    produced_batches: Mutex<Vec<BatchRoot>>,
    /// 聚合游标（同一 root 不重复聚合的推进依据）。
    aggregate_cursor: Mutex<AggregateCursor>,
    /// proof 归档注册表写端（None = 未挂载，纯内存语义不变；E2 闭环）。
    proof_registry: Mutex<Option<ProofRegistryWriter>>,
}

impl ProofPipeline {
    /// 构造：启动 worker 池（rayon 并行执行 prove，完成结果进通道）。
    ///
    /// REAL 出证策略取 fail-closed 默认（[`RealSettlementPolicy::default`] =
    /// StarkRequired + 未钉 verifier key → REAL 结算全部拒绝）；生产装配用
    /// [`ProofPipeline::with_real_policy`]。
    #[must_use]
    pub fn new(
        config: PipelineConfig,
        engine: Arc<dyn SettlementProver>,
        metrics: Arc<MetricsRegistry>,
    ) -> Arc<Self> {
        Self::with_real_policy(config, engine, metrics, RealSettlementPolicy::default())
    }

    /// 指定 REAL 出证策略构造（生产：`StarkRequired` + 固定 verifier key）。
    #[must_use]
    pub fn with_real_policy(
        config: PipelineConfig,
        engine: Arc<dyn SettlementProver>,
        metrics: Arc<MetricsRegistry>,
        real_policy: RealSettlementPolicy,
    ) -> Arc<Self> {
        let (tx, rx) = sync_channel::<ProofBundle>(config.queue_bound);
        let pipeline = Arc::new(Self {
            inflight: Arc::new(AtomicU64::new(0)),
            completed: Arc::new(AtomicU64::new(0)),
            completions: Mutex::new(Vec::new()),
            outstanding: Arc::new(Mutex::new(BTreeSet::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
            batch_index: AtomicU64::new(0),
            on_batch_proven: Mutex::new(None),
            rx: Mutex::new(Some(rx)),
            tx,
            config,
            engine,
            metrics,
            real_policy,
            real_ops: Arc::new(Mutex::new(HashSet::new())),
            produced_batches: Mutex::new(Vec::new()),
            aggregate_cursor: Mutex::new(AggregateCursor::default()),
            proof_registry: Mutex::new(None),
        });
        // worker：从 pending 队列取任务（优先级排序），rayon 并行 prove
        for _ in 0..pipeline.config.workers.max(1) {
            let p = Arc::clone(&pipeline);
            std::thread::spawn(move || loop {
                let job = {
                    let mut q = p.pending.lock().expect("pending lock");
                    if q.is_empty() {
                        drop(q);
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    // 稳定取最高优先级（Real > Play）；同级优先取**未失败过**
                    // 的新鲜任务（防重试任务饿死队列——重试任务只在无新鲜
                    // 任务时兜底，超限任务靠退避 + 告警计数暴露）
                    let best = q.iter().enumerate().max_by_key(|(_, pj)| {
                        (pj.job.priority, pj.attempts == 0, std::cmp::Reverse(pj.job.op_index))
                    });
                    let (idx, _) = best.expect("non-empty checked");
                    q.remove(idx)
                };
                let t0 = std::time::Instant::now();
                // P0-5：worker 崩溃（prove panic）不杀 worker、不丢任务——
                // 与 prove 失败同等对待，带计数回队重试
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    p.engine.prove(&job.job)
                }));
                p.metrics.observe(
                    "prove_us",
                    u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
                );
                match res {
                    Ok(Ok(bundle)) => {
                        // M9-ACC-4：证明就绪延迟 = 任务入队 → 证明完成（含
                        // 排队与重试全程），完成路径统一观测
                        p.metrics.observe(
                            "proof_ready_ms",
                            u64::try_from(job.enqueued_at.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                        );
                        // 先发送后计数：completed==N 保证 N 个 bundle 已可收割
                        let _ = p.tx.send(bundle);
                        p.completed.fetch_add(1, Ordering::Relaxed);
                    }
                    res => {
                        if res.is_err() {
                            p.metrics.inc("prove_panicked_total");
                        }
                        p.metrics.inc("prove_failed_total");
                        // P0-3：REAL 被引擎层拒绝（host 引擎不能给 REAL 出证）
                        // 单独计告警——配置错误（模式/引擎组合）在这里显形
                        if matches!(&res, Ok(Err(AppchainError::RealRequiresStarkProof))) {
                            p.metrics.inc("real_settlement_rejected_total");
                        }
                        let attempts = job.attempts + 1;
                        if attempts == MAX_PROVE_RETRIES {
                            p.metrics.inc("prove_retry_exhausted_total");
                        }
                        // 有界重试，超限仍留队列（不丢任务；见 MAX_PROVE_RETRIES）。
                        // enqueued_at 原样携带：proof_ready_ms 覆盖含重试全程
                        p.pending.lock().expect("pending lock").push(PendingJob {
                            job: job.job,
                            attempts,
                            enqueued_at: job.enqueued_at,
                        });
                        std::thread::sleep(Duration::from_millis(PROVE_RETRY_BACKOFF_MS));
                    }
                }
                p.inflight.fetch_sub(1, Ordering::Relaxed);
            });
        }
        pipeline
    }

    /// 设置批次验证通过回调（P0-5 水位接线）：每出一个批次以
    /// `through_op` 调用一次；生产装配点接
    /// `sequencer::Sequencer::mark_proven_through`。
    pub fn set_on_batch_proven(&self, cb: ProvenCallback) {
        *self.on_batch_proven.lock().expect("callback lock") = Some(cb);
    }

    /// 挂载 proof 归档注册表 sidecar（E2 闭环）：此后每次
    /// [`Self::drain_completions`] 收割完成的 bundle 时逐条追加一行冻结
    /// 契约 JSONL（`proof_registry.rs` 模块文档）。
    ///
    /// sidecar 语义（文档化取舍）：归档是**旁路优化**，写失败**不吞完成
    /// 项**——bundle 照常进入 completions（可组批、可推进水位），只计
    /// `proof_registry_write_failed_total` 告警计数 + warn，且本实例此后
    /// 不再追加（`ProofRegistryWriter::failed` 置位，避免日志与内存无界
    /// 漂移）。这与 proven log 的"fail-closed 挂起水位"不同：证明产物的
    /// 权威载体是批次验证回调（`set_on_batch_proven` → 水位），注册表只
    /// 服务 explorer 下载端点。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_proof_registry(&self, path: &Path) -> AppchainResult<()> {
        *self.proof_registry.lock().expect("proof registry lock") =
            Some(ProofRegistryWriter::open(path)?);
        Ok(())
    }

    /// proof 注册表 fsync 开关（builder 风格）：`true` = 每行追加后
    /// `sync_all` 真落盘；`false`（默认）= 只做用户态 flush。未挂载
    /// sidecar 时为无操作。
    pub fn with_registry_fsync(&self, enabled: bool) -> &Self {
        if let Some(w) = self.proof_registry.lock().expect("proof registry lock").as_mut() {
            w.with_fsync(enabled);
        }
        self
    }

    /// 归档单个 bundle 到已挂载的 proof 注册表（sidecar 语义：失败不吞
    /// 完成项，只计告警 + warn）。
    fn archive_bundle(&self, bundle: &ProofBundle) {
        let mut guard = self.proof_registry.lock().expect("proof registry lock");
        let Some(w) = guard.as_mut() else { return };
        if w.failed {
            return; // 已失败：不再追加（见 attach_proof_registry 文档）
        }
        let entry = ProofRegistryEntry {
            binding_hex: bundle.binding_hex.clone(),
            op_index: bundle.op_index,
            engine: bundle.engine.to_string(),
            attestor_public: bundle.attestor_public,
            payload: bundle.payload.clone(),
        };
        if let Err(e) = w.append(&entry) {
            w.failed = true;
            self.metrics.inc("proof_registry_write_failed_total");
            eprintln!(
                "[poker-appchain::pipeline] warning: proof registry write failed \
                 (op {} archived = false, further writes suspended): {e}",
                bundle.op_index
            );
        }
    }

    /// 提交任务（有界背压：队列满时短暂阻塞重试）。
    ///
    /// P0-3 提交准入：REAL 结算 op 在此即做策略检查（单实例单引擎 →
    /// 拒绝路径尽早，不进队列、不烧重试预算），见 [`Self::admit_real_job`]。
    ///
    /// # Errors
    /// 提交超时（1s × 60 次）→ [`AppchainError::AdmissionRejected("pipeline saturated")`]；
    /// REAL 结算不满足出证策略 → [`AppchainError::RealRequiresStarkProof`]。
    pub fn submit(&self, job: ProofJob) -> AppchainResult<()> {
        if is_real_settlement(&job.record) {
            self.admit_real_job(&job)?;
        }
        for _ in 0..60 {
            let depth = self.inflight.load(Ordering::Relaxed);
            self.metrics.set_gauge("proof_queue_depth", depth);
            if depth < u64::try_from(self.config.queue_bound).unwrap_or(u64::MAX) {
                self.inflight.fetch_add(1, Ordering::Relaxed);
                self.outstanding
                    .lock()
                    .expect("outstanding lock")
                    .insert(job.op_index);
                self.pending
                    .lock()
                    .expect("pending lock")
                    .push(PendingJob {
                        job,
                        attempts: 0,
                        enqueued_at: std::time::Instant::now(),
                    });
                self.metrics.inc("proof_submitted_total");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(16));
        }
        Err(AppchainError::AdmissionRejected("pipeline saturated"))
    }

    /// P0-3 REAL 结算提交准入（fail-closed；拒绝路径尽早）：
    ///
    /// 1. 模式不允许当前引擎（Disabled / 引擎不在允许集）→
    ///    [`AppchainError::RealRequiresStarkProof`]；
    /// 2. 当前引擎不具备 REAL 出证能力（非 [`STARK_ENGINE_PREFIX`] 前缀的
    ///    STARK 引擎——host 签名引擎在引擎层已无条件拒绝 REAL，这里提交时
    ///    同步拒绝，避免注定失败的任务空耗重试预算）→ 同上；
    /// 3. `StarkRequired` 未配置 verifier key（出证前提不完备）→ 同上；
    /// 4. 缺 `hand_proof`（REAL 结算必须绑定已验证的手牌批次证明）→
    ///    [`AppchainError::AdmissionRejected`]。
    ///
    /// 全部通过后把 op 记入 REAL 集合，供批次/水位门（[`Self::try_build_batch`]）
    /// 复查 bundle 的引擎与 attestor 钉扎。
    fn admit_real_job(&self, job: &ProofJob) -> AppchainResult<()> {
        let engine = self.engine.name();
        if self.real_policy.mode == RealMode::Disabled
            || !self.real_policy.engine_allowed(engine)
            || !engine.starts_with(STARK_ENGINE_PREFIX)
            || !self.real_policy.config_complete()
        {
            self.metrics.inc("real_settlement_rejected_total");
            return Err(AppchainError::RealRequiresStarkProof);
        }
        if job.record.hand_proof.is_none() {
            self.metrics.inc("real_settlement_rejected_total");
            return Err(AppchainError::AdmissionRejected(
                "real settlement requires hand proof",
            ));
        }
        self.real_ops
            .lock()
            .expect("real ops lock")
            .insert(job.op_index);
        Ok(())
    }

    /// 收割完成结果（非阻塞），返回本轮收集的 bundle 数。
    ///
    /// E2 挂账：已挂载 proof 注册表时，每个收割的 bundle 逐条追加归档
    /// （[`Self::archive_bundle`]）——写失败不吞完成项、不改本方法签名
    /// （sidecar 语义，见 [`Self::attach_proof_registry`]）。
    pub fn drain_completions(&self) -> usize {
        let rx_opt = {
            let mut guard = self.rx.lock().expect("rx lock");
            guard.take()
        };
        let mut n = 0;
        if let Some(rx) = rx_opt {
            loop {
                match rx.try_recv() {
                    Ok(b) => {
                        self.archive_bundle(&b);
                        self.completions
                            .lock()
                            .expect("completions lock")
                            .push(b);
                        n += 1;
                    }
                    Err(_) => break,
                }
            }
            *self.rx.lock().expect("rx lock") = Some(rx);
        }
        self.metrics
            .set_gauge("proof_completed_total", self.completed.load(Ordering::Relaxed));
        n
    }

    /// 当前是否降级（inflight 超高水位）。
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.inflight.load(Ordering::Relaxed)
            > u64::try_from(self.config.high_watermark).unwrap_or(u64::MAX)
    }

    /// 已完成证明数（观测/测试用）。
    #[must_use]
    pub fn completed_count(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    /// 当前 inflight（观测/测试用）。
    #[must_use]
    pub fn inflight_count(&self) -> u64 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// 已完成但尚未组批出队的 bundle 数（观测/测试用；P0-5：批次验证失败
    /// 后此数不减少——completion 未丢，可重新组批）。
    #[must_use]
    pub fn pending_completion_count(&self) -> usize {
        self.completions.lock().expect("completions lock").len()
    }

    /// 从已收集 bundle 构造批次（凑满 batch_size 时触发；返回批次根）。
    ///
    /// P0-5 语义：
    /// - 只从「最早的未批次化任务」起收集已完成任务的**连续前缀**，遇空洞
    ///   （失败/未完成的更早任务）即停——批次绝不越过未证明操作；
    /// - bundle 验证在出队**之前**：验证失败时不修改 completions/未批次化
    ///   集合（整个批次的 completion 原地保留，可重新组批）。
    ///
    /// # Errors
    /// bundle 验证失败 → 对应错误（fail-closed：坏证明不进批次）；
    /// REAL op 的 bundle 不在出证策略允许集 / attestor 未钉扎 →
    /// [`AppchainError::RealRequiresStarkProof`] / [`AppchainError::VerifierKeyMismatch`]
    /// （completion 原地保留，op 不标记已证明）。
    pub fn try_build_batch(&self) -> AppchainResult<Option<BatchRoot>> {
        self.drain_completions();
        let mut c = self.completions.lock().expect("completions lock");
        let mut out = self.outstanding.lock().expect("outstanding lock");
        if c.len() < self.config.batch_size {
            return Ok(None);
        }
        // 连续前缀：按 op_index 升序走未批次化集合，completion 缺席即停
        let done: HashSet<u64> = c.iter().map(|b| b.op_index).collect();
        let mut run: Vec<u64> = Vec::with_capacity(self.config.batch_size);
        for &idx in out.iter() {
            if !done.contains(&idx) {
                break;
            }
            run.push(idx);
        }
        if run.len() < self.config.batch_size {
            return Ok(None);
        }
        run.truncate(self.config.batch_size);
        let take: Vec<ProofBundle> = run
            .iter()
            .map(|idx| {
                c.iter()
                    .find(|b| b.op_index == *idx)
                    .expect("completion present")
                    .clone()
            })
            .collect();
        // 绑定解码 + 验证全部在出队之前（失败 → c/out 未动，可重新组批）
        let mut bindings = Vec::with_capacity(take.len());
        for b in &take {
            let bytes = hex::decode(&b.binding_hex)
                .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
            if bytes.len() != 32 {
                return Err(AppchainError::AdmissionRejected("bad binding length"));
            }
            let mut binding = [0u8; 32];
            binding.copy_from_slice(&bytes);
            bindings.push(binding);
        }
        for b in &take {
            // P0-3 批次/水位门：REAL op 的证明必须来自当前策略允许集
            // （引擎 + StarkRequired attestor 钉扎）。违反时 completion
            // 原地保留——该 op 不标记已证明、批次不出队、水位不推进，
            // 并计 `real_settlement_rejected_total` 告警。
            if self
                .real_ops
                .lock()
                .expect("real ops lock")
                .contains(&b.op_index)
            {
                if !self.real_policy.engine_allowed(b.engine) {
                    self.metrics.inc("real_settlement_rejected_total");
                    return Err(AppchainError::RealRequiresStarkProof);
                }
                if !self.real_policy.attestor_pinned(&b.attestor_public) {
                    self.metrics.inc("real_settlement_rejected_total");
                    return Err(AppchainError::VerifierKeyMismatch);
                }
            }
            if let Err(e) = self.engine.verify(b) {
                self.metrics.inc("batch_verify_failed_total");
                return Err(e);
            }
        }
        // ===== 出队段（以上全部通过）=====
        for idx in &run {
            let pos = c
                .iter()
                .position(|b| b.op_index == *idx)
                .expect("completion present");
            c.remove(pos);
            out.remove(idx);
            self.real_ops.lock().expect("real ops lock").remove(idx);
        }
        let root = batch_root(&bindings)?;
        let index = self.batch_index.fetch_add(1, Ordering::Relaxed);
        let through_op = *run.last().expect("non-empty run");
        self.metrics.inc("batch_total");
        // P0-5 接线：批次验证通过 → 通知上层推进 sequencer 证明水位
        if let Some(cb) = self.on_batch_proven.lock().expect("callback lock").as_ref() {
            cb(through_op);
        }
        // M4 outer aggregate：登记产出批次根（aggregate_due 的折叠窗口来源；
        // 先于返回值，保证聚合游标之后的可见性）
        self.produced_batches
            .lock()
            .expect("produced batches lock")
            .push(BatchRoot {
                index,
                root,
                count: take.len(),
                through_op,
            });
        Ok(Some(BatchRoot {
            index,
            root,
            count: take.len(),
            through_op,
        }))
    }

    /// M4 outer aggregate：到期触发一次批次根二级聚合。
    ///
    /// 触发条件（同时满足）：
    /// - 自上次聚合以来已产出的批次根（[`Self::try_build_batch`] 登记的
    ///   `BatchRoot` 序列的未消费后缀）**非空**；
    /// - `now_ms ≥ 上次聚合时刻 + interval_ms`（首次聚合基准 = 0，即
    ///   `now ≥ interval` 即可触发）。
    ///
    /// 满足则把窗口内全部批次根按产出序折叠（[`aggregate_roots`]）产出
    /// [`AggregateRecord`] 并**原子推进内部游标**（同一 root 不重复聚合；
    /// 空窗口返回 `Ok(None)`，不推进任何水位）。并发安全：窗口切片与游标
    /// 在同一把锁序内读取推进（produced_batches → aggregate_cursor，两把
    /// 锁均只在方法内短暂持有，与现有锁风格一致）。
    ///
    /// # Errors
    /// 聚合折叠失败 → 对应 [`AppchainError`]（游标不推进，可重试）。
    pub fn aggregate_due(
        &self,
        now_ms: u64,
        interval_ms: u64,
    ) -> AppchainResult<Option<AggregateRecord>> {
        let batches = self.produced_batches.lock().expect("produced batches lock");
        let mut cursor = self.aggregate_cursor.lock().expect("aggregate cursor lock");
        // 空窗口：没有未聚合的批次根 → 无操作
        if cursor.consumed >= batches.len() {
            return Ok(None);
        }
        // 时间窗未到
        if now_ms < cursor.last_ms.saturating_add(interval_ms) {
            return Ok(None);
        }
        let window: Vec<[u8; 32]> = batches[cursor.consumed..].iter().map(|b| b.root).collect();
        let batch_count = u64::try_from(window.len()).unwrap_or(u64::MAX);
        let root = aggregate_roots(&window)?;
        let through_op = batches
            .last()
            .map(|b| b.through_op)
            .expect("non-empty window checked");
        let rec = AggregateRecord {
            index: cursor.next_index,
            through_op,
            root,
            ts_ms: now_ms,
            batch_count,
        };
        // 推进游标（同一 root 不重复聚合）
        cursor.consumed = batches.len();
        cursor.next_index = cursor.next_index.wrapping_add(1);
        cursor.last_ms = now_ms;
        Ok(Some(rec))
    }

    /// 已产出但尚未聚合的批次根数量（观测/测试用）。
    #[must_use]
    pub fn pending_aggregate_count(&self) -> usize {
        let batches = self.produced_batches.lock().expect("produced batches lock");
        let cursor = self.aggregate_cursor.lock().expect("aggregate cursor lock");
        batches.len().saturating_sub(cursor.consumed)
    }

    /// 健康输入（M9 告警评估）。
    #[must_use]
    pub fn health(&self) -> HealthInputs {
        HealthInputs {
            proof_queue_depth: self.inflight.load(Ordering::Relaxed),
            proof_degraded: self.degraded(),
            withdrawal_queue_depth: 0,
            reconciliation_delta: 0,
            soft_confirm_idle_ms: 0,
            rate_limit_rejected_window: 0,
        }
    }

    /// 当前告警。
    #[must_use]
    pub fn alerts(&self) -> Vec<Alert> {
        evaluate_alerts(&self.health())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32};

    use crate::fee::FeePolicy;
    use crate::keys::EcdsaSig;
    use crate::note::{AssetClass, NoteSpec};
    use crate::real_policy::RealMode;
    use crate::sequencer::{Sequencer, SequencerConfig};
    use crate::settlement::{
        HandProofBinding, RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
    };

    /// 构造单个输入 note 的合法结算记录（签名完整；class 参数化供 REAL 门测试）。
    fn signed_record(binding_byte: u8, class: AssetClass) -> SettlementRecord {
        let k = crate::keys::OwnerKey::from_seed(&[binding_byte; 32]).unwrap();
        let note = crate::note::Note::new(
            class,
            100,
            k.public_bytes(),
            [binding_byte; 32],
            Some(1),
        )
        .unwrap();
        let note_commitment_bytes = note.commitment_bytes();
        let nf = note.nullifier(&[binding_byte; 32]);
        let scope = crate::settlement::settle_spend_scope(&[binding_byte; 32]);
        let mut record = SettlementRecord {
            table_id: 1,
            hand_binding: [binding_byte; 32],
            policy_commitment: FeePolicy::Zero.commitment_bytes(),
            pot: 100,
            inputs: vec![SettleInput {
                note,
                spend: SpendAuth {
                    commitment: note_commitment_bytes,
                    nullifier: crate::felt::felt_to_bytes32(&nf),
                    sig: EcdsaSig { bytes: [0; 64] },
                },
            }],
            payouts: vec![NoteSpec {
                asset_class: class,
                amount: 100,
                owner: k.public_bytes(),
                table_id: None,
                pot_index: 0,
                runout_index: 0,
            }],
            rake: RakeSplitRecord {
                total: 0,
                treasury_out: None,
                operator_out: None,
            },
            plan: crate::settlement::flat_settlement_plan(100, 0b01, {
                let mut awards = [0u64; 9];
                awards[0] = 100;
                awards
            }),
            hand_proof: None,
        };
        // S1：签名覆盖结算效果摘要（在记录完整后计算）
        let effect = crate::settlement::settle_effect(&record);
        let d = crate::keys::spend_digest(
            &record.inputs[0].spend.commitment,
            &record.inputs[0].spend.nullifier,
            &scope,
            &effect,
        );
        record.inputs[0].spend.sig = k.sign(&d);
        record
    }

    fn dummy_record(binding_byte: u8) -> SettlementRecord {
        signed_record(binding_byte, AssetClass::Play)
    }

    /// REAL 结算记录（可选 hand_proof 绑定——内容仅供引擎层形状判定）。
    fn real_record(binding_byte: u8, with_hand_proof: bool) -> SettlementRecord {
        let mut record = signed_record(binding_byte, AssetClass::Real);
        if with_hand_proof {
            record.hand_proof = Some(HandProofBinding {
                archive_bytes: Vec::new(),
                post_state_commitment: [binding_byte; 32],
                pre_state_root: [0; 32],
                post_state_root: [0; 32],
            });
        }
        record
    }

    /// 可编程故障测试引擎：prove 失败/panic（worker 崩溃模拟）与 verify
    /// 失败均可注入。
    struct TestEngine {
        /// op_index == 1 时 prove 失败（置 false 后重试成功）。
        fail_op1: AtomicBool,
        /// op_index == 1 时 prove panic 的剩余次数（模拟 worker 崩溃）。
        panic_op1_budget: AtomicU32,
        /// verify 一律失败开关。
        fail_verify: AtomicBool,
    }

    impl SettlementProver for TestEngine {
        fn name(&self) -> &'static str {
            "test-engine-v1"
        }

        fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
            if job.op_index == 1 {
                if self.panic_op1_budget.load(Ordering::Relaxed) > 0 {
                    self.panic_op1_budget.fetch_sub(1, Ordering::Relaxed);
                    panic!("injected worker crash");
                }
                if self.fail_op1.load(Ordering::Relaxed) {
                    return Err(AppchainError::AdmissionRejected("injected prove failure"));
                }
            }
            Ok(ProofBundle {
                binding_hex: hex::encode(job.record.hand_binding),
                op_index: job.op_index,
                engine: self.name(),
                attestor_public: [7u8; 32],
                payload: vec![0u8; 64],
            })
        }

        fn verify(&self, _bundle: &ProofBundle) -> AppchainResult<()> {
            if self.fail_verify.load(Ordering::Relaxed) {
                return Err(AppchainError::BadSignature);
            }
            Ok(())
        }
    }

    fn test_engine(
        fail_op1: bool,
        panic_op1_budget: u32,
        fail_verify: bool,
    ) -> Arc<TestEngine> {
        Arc::new(TestEngine {
            fail_op1: AtomicBool::new(fail_op1),
            panic_op1_budget: AtomicU32::new(panic_op1_budget),
            fail_verify: AtomicBool::new(fail_verify),
        })
    }

    fn poll_until(f: impl Fn() -> bool) {
        // 5s 预算：容忍并行测试下的编译/CPU 争用
        for _ in 0..1_000 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("condition not reached within timeout");
    }


    /// M4-ACC-4 端到端注入：灌入超容量任务 → 降级档触发（degraded + 告警
    /// 规则命中）→ 放行后积压清空、降级解除（恢复面）。
    #[test]
    fn backlog_degraded_end_to_end_injection_and_recovery() {
        // 门控引擎：gate 关闭时 worker 阻塞（模拟 prove 停滞 → 积压真实堆积）
        struct GateEngine {
            open: std::sync::atomic::AtomicBool,
        }
        impl SettlementProver for GateEngine {
            fn name(&self) -> &'static str {
                "gate-engine-v1"
            }
            fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
                while !self.open.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(ProofBundle {
                    binding_hex: hex::encode(job.record.hand_binding),
                    op_index: job.op_index,
                    engine: self.name(),
                    attestor_public: [7u8; 32],
                    payload: vec![0u8; 64],
                })
            }
            fn verify(&self, _bundle: &ProofBundle) -> AppchainResult<()> {
                Ok(())
            }
        }

        let metrics = Arc::new(MetricsRegistry::new());
        let gate = Arc::new(GateEngine {
            open: std::sync::atomic::AtomicBool::new(false),
        });
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 4,
                queue_bound: 64,
                // 高水位 4：灌 12 个任务（8 inflight > 4）必降级
                high_watermark: 4,
                batch_interval_ms: 1_000,
            },
            gate.clone(),
            metrics,
        );
        // 灌入 12 个任务（queue_bound=64 足够容纳）
        for i in 0..12u64 {
            let seed = u8::try_from(i + 1).unwrap_or(u8::MAX);
            p.submit(ProofJob {
                op_index: i,
                table_id: 1,
                record: Arc::new(dummy_record(seed)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        // 等待 worker 取走第一批（inflight 计入 worker 手中），门关闭 →
        // 其余滞留 pending/inflight，降级必须触发
        poll_until(|| p.inflight_count() >= 5);
        assert!(
            p.degraded(),
            "inflight {} 必须超过高水位 4 触发降级",
            p.inflight_count()
        );
        // 告警规则联动（M4-ACC-4 的"告警"面）
        let alerts = crate::metrics::evaluate_alerts(&p.health());
        assert!(
            alerts.iter().any(|a| a.rule == "proof_backlog_degraded"),
            "降级档必须触发 proof_backlog_degraded 告警"
        );
        // 放行：积压应被清空（12 个全部完成）
        gate.open.store(true, Ordering::Relaxed);
        poll_until(|| p.completed_count() >= 12);
        assert_eq!(p.drain_completions(), 12);
        poll_until(|| !p.degraded());
        assert!(
            !p.degraded(),
            "积压清空后降级必须解除（恢复面）"
        );
        assert!(crate::metrics::evaluate_alerts(&p.health()).is_empty());
    }

    // ===== M4 outer aggregate：定期批次聚合触发 =====

    /// aggregate_due：时间窗触发、空窗口 None、同一 root 不重复聚合。
    #[test]
    fn aggregate_due_time_window_and_no_duplicate() {
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 2,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            Arc::new(ValidationEngine::default()),
            metrics,
        );
        // 尚无批次：时间窗再长也 None（空窗口优先）
        assert!(p.aggregate_due(10_000, 1_000).unwrap().is_none());

        // 产出一个批次（2 帧）
        for i in 0..2u8 {
            p.submit(ProofJob {
                op_index: u64::from(i),
                table_id: 1,
                record: Arc::new(dummy_record(i + 1)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        poll_until(|| p.completed_count() >= 2);
        let b1 = p.try_build_batch().unwrap().expect("batch 1");
        assert_eq!(p.pending_aggregate_count(), 1);

        // 时间窗未到（now < 0 + interval）→ None，不消费窗口
        assert!(p.aggregate_due(500, 1_000).unwrap().is_none());
        assert_eq!(p.pending_aggregate_count(), 1);

        // 到期 → Some；聚合根 = 窗口批次根的独立域折叠；through_op 对齐
        let rec1 = p.aggregate_due(1_000, 1_000).unwrap().expect("first aggregate");
        assert_eq!(rec1.index, 0);
        assert_eq!(rec1.batch_count, 1);
        assert_eq!(rec1.through_op, b1.through_op);
        assert_eq!(rec1.root, aggregate_roots(&[b1.root]).unwrap());
        assert_eq!(rec1.ts_ms, 1_000);
        assert_eq!(p.pending_aggregate_count(), 0);

        // 同一 root 不重复聚合：窗口空 → None
        assert!(p.aggregate_due(2_000, 1_000).unwrap().is_none());

        // 再出一个批次，下一个时间窗 → index 递进，聚合第二窗口的根
        for i in 2..4u8 {
            p.submit(ProofJob {
                op_index: u64::from(i),
                table_id: 1,
                record: Arc::new(dummy_record(i + 1)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        poll_until(|| p.completed_count() >= 4);
        let b2 = p.try_build_batch().unwrap().expect("batch 2");
        let rec2 = p.aggregate_due(2_500, 500).unwrap().expect("second aggregate");
        assert_eq!(rec2.index, 1);
        assert_eq!(rec2.batch_count, 1);
        assert_eq!(rec2.through_op, b2.through_op);
        assert_eq!(rec2.root, aggregate_roots(&[b2.root]).unwrap());
        assert!(p.aggregate_due(9_999, 1_000).unwrap().is_none());
    }

    /// E2 挂账：挂载 proof 注册表后 drain_completions 逐条归档；
    /// 注册表内容与批次内 bundle 一致（binding/op_index/engine/payload）。
    #[test]
    fn proof_registry_archives_drained_bundles() {
        let dir = std::env::temp_dir().join("poker-appchain-pipeline-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof_registry.jsonl");
        let _ = std::fs::remove_file(&path);

        let metrics = Arc::new(MetricsRegistry::new());
        let engine = Arc::new(ValidationEngine::default());
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 2,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            engine.clone(),
            Arc::clone(&metrics),
        );
        p.attach_proof_registry(&path).unwrap();
        p.with_registry_fsync(false);
        for i in 0..2u8 {
            p.submit(ProofJob {
                op_index: u64::from(i),
                table_id: 1,
                record: Arc::new(dummy_record(i + 1)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        poll_until(|| p.completed_count() >= 2);
        let batch = p.try_build_batch().unwrap().expect("batch built");
        // try_build_batch 内部 drain → 两个 bundle 已归档
        assert_eq!(metrics.counter("proof_registry_write_failed_total"), 0);
        let entries = crate::proof_registry::read_registry(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].binding_hex, hex::encode([1u8; 32]));
        assert_eq!(entries[0].op_index, 0);
        assert_eq!(entries[0].engine, "host-validate-v2");
        assert_eq!(entries[0].payload.len(), 64);
        assert_eq!(entries[1].op_index, 1);
        // attestor 公钥与引擎一致（可验证 attestation 回路）
        let bundle = crate::pipeline::ProofBundle {
            binding_hex: entries[0].binding_hex.clone(),
            op_index: entries[0].op_index,
            engine: "host-validate-v2",
            attestor_public: entries[0].attestor_public,
            payload: entries[0].payload.clone(),
        };
        assert!(engine.verify(&bundle).is_ok(), "archived payload verifies");
        let _ = batch;
    }

    #[test]
    fn pipeline_end_to_end_batch() {
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 2,
                batch_size: 8,
                queue_bound: 64,
                high_watermark: 64,
                batch_interval_ms: 1_000,
            },
            Arc::new(ValidationEngine::default()),
            metrics,
        );
        for i in 0..8u8 {
            p.submit(ProofJob {
                op_index: u64::from(i),
                table_id: 1,
                record: Arc::new(dummy_record(i + 1)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        poll_until(|| p.completed.load(Ordering::Relaxed) >= 8);
        let batch = p.try_build_batch().unwrap().expect("batch ready");
        assert_eq!(batch.count, 8);
        assert_eq!(batch.through_op, 7); // op_index 0..=7
        assert_ne!(batch.root, [0u8; 32]);
        // P0-6：批次根为 Poseidon 折叠（与 batch_root 函数一致）
        let bindings: Vec<[u8; 32]> = (1..=8u8).map(|i| [i; 32]).collect();
        assert_eq!(batch.root, batch_root(&bindings).unwrap());
    }

    #[test]
    fn invalid_job_never_completes() {
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 1,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            Arc::new(ValidationEngine::default()),
            Arc::clone(&metrics),
        );
        let mut rec = dummy_record(5);
        rec.payouts[0].amount = 99; // 破坏守恒
        p.submit(ProofJob {
            op_index: 1,
            table_id: 1,
            record: Arc::new(rec),
            policy: FeePolicy::Zero,
            priority: Priority::Play,
        })
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        p.drain_completions();
        assert!(p.try_build_batch().unwrap().is_none());
        // P0-5：失败任务不再丢弃——至少失败一次，且留在队列持续重试
        assert!(metrics.counter("prove_failed_total") >= 1);
        assert_eq!(p.pending_completion_count(), 0);
    }

    /// P0-5 (a)(b)：op 1 失败时缺口挡住水位（op 2/3 完成也不推进）；
    /// 故障解除重试成功后，连续前缀组批并推进水位到 3。
    #[test]
    fn watermark_blocks_on_hole_then_advances() {
        let metrics = Arc::new(MetricsRegistry::new());
        let engine = test_engine(true, 0, false);
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 3,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            engine.clone(),
            Arc::clone(&metrics),
        );
        let seq = Arc::new(Mutex::new(Sequencer::new(
            crate::keys::SequencerKey::from_seed(&[3u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )));
        // P0-5 接线：批次验证通过 → sequencer.mark_proven_through
        p.set_on_batch_proven({
            let seq = Arc::clone(&seq);
            Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
        });
        for i in 1..=3u64 {
            p.submit(ProofJob {
                op_index: i,
                table_id: 1,
                record: Arc::new(dummy_record(u8::try_from(i).unwrap() + 1)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        // (a) op 2/3 已完成、op 1 持续失败：组批被缺口挡住，水位停在 0
        poll_until(|| p.completed_count() >= 2);
        assert!(p.try_build_batch().unwrap().is_none(), "hole must block batch");
        assert_eq!(seq.lock().unwrap().proven_watermark(), 0);
        // (b) 故障解除 → op 1 重试成功 → 连续区间组批，水位推进到 3
        engine.fail_op1.store(false, Ordering::Relaxed);
        poll_until(|| p.completed_count() >= 3);
        let batch = p.try_build_batch().unwrap().expect("contiguous batch");
        assert_eq!(batch.through_op, 3);
        assert_eq!(seq.lock().unwrap().proven_watermark(), 3);
        assert!(metrics.counter("prove_failed_total") >= 1);
    }

    /// P0-5 (c)：批次验证失败后 completion 不丢，可重新组批成功。
    #[test]
    fn batch_verify_failure_keeps_completions() {
        let metrics = Arc::new(MetricsRegistry::new());
        let engine = test_engine(false, 0, true);
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 1,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            engine.clone(),
            Arc::clone(&metrics),
        );
        p.submit(ProofJob {
            op_index: 7,
            table_id: 1,
            record: Arc::new(dummy_record(9)),
            policy: FeePolicy::Zero,
            priority: Priority::Play,
        })
        .unwrap();
        poll_until(|| p.completed_count() >= 1);
        // 验证失败：返回 Err 且 completion 原地保留
        assert!(p.try_build_batch().is_err());
        assert_eq!(p.pending_completion_count(), 1);
        assert_eq!(metrics.counter("batch_verify_failed_total"), 1);
        // 故障解除 → 同一批 completion 重新组批成功
        engine.fail_verify.store(false, Ordering::Relaxed);
        let batch = p.try_build_batch().unwrap().expect("rebuilt batch");
        assert_eq!(batch.count, 1);
        assert_eq!(batch.through_op, 7);
        assert_eq!(p.pending_completion_count(), 0);
    }

    /// P0-5 (d)：worker 崩溃（prove panic）不杀 worker、不丢任务——
    /// panic 任务回队重试成功。
    #[test]
    fn worker_crash_does_not_lose_jobs() {
        let metrics = Arc::new(MetricsRegistry::new());
        let engine = test_engine(false, 1, false);
        let p = ProofPipeline::new(
            PipelineConfig {
                workers: 1,
                batch_size: 2,
                queue_bound: 16,
                high_watermark: 16,
                batch_interval_ms: 1_000,
            },
            engine.clone(),
            Arc::clone(&metrics),
        );
        for i in 1..=2u64 {
            p.submit(ProofJob {
                op_index: i,
                table_id: 1,
                record: Arc::new(dummy_record(u8::try_from(i).unwrap() + 20)),
                policy: FeePolicy::Zero,
                priority: Priority::Play,
            })
            .unwrap();
        }
        poll_until(|| p.completed_count() >= 2);
        let batch = p.try_build_batch().unwrap().expect("batch after crash retry");
        assert_eq!(batch.through_op, 2);
        assert_eq!(metrics.counter("prove_panicked_total"), 1);
        // panic 与 prove 失败同路径计数，重试后不再增长
        assert_eq!(metrics.counter("prove_failed_total"), 1);
    }

    /// P0-6 golden vector：固定两帧 binding，手工按 docs/ABI.md §「批次根」
    /// 算法计算期望值（不经 batch_root 代码路径），并冻结十六进制常量。
    #[test]
    fn batch_root_golden_vector() {
        let b1 = [0xAAu8; 32];
        let b2 = [0xBBu8; 32];
        // 手工展开文档算法：
        // fold_i = poseidon(fold_{i-1}, hi_i, lo_i)；root = poseidon(D, fold_2)
        let (h1, l1) = bytes32_to_felts(&b1);
        let (h2, l2) = bytes32_to_felts(&b2);
        let fold1 = poseidon_hash_many(&[FieldElement::ZERO, h1, l1]);
        let fold2 = poseidon_hash_many(&[fold1, h2, l2]);
        let d = domain_felt(DOMAIN_BATCH_ROOT);
        let expect = felt_to_bytes32(&poseidon_hash_many(&[d, fold2]));
        assert_eq!(batch_root(&[b1, b2]).unwrap(), expect);
        // 冻结 golden 常量：防 Poseidon 参数/域标签/编码被无声更改
        assert_eq!(
            hex::encode(batch_root(&[b1, b2]).unwrap()),
            "00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52"
        );
        // 绑定序敏感（折叠序 = 帧序）
        assert_ne!(batch_root(&[b1, b2]).unwrap(), batch_root(&[b2, b1]).unwrap());
    }

    // ===== P0-3：REAL 结算出证策略门 =====

    /// 名字/attestor 可配置的 mock STARK 引擎（texas-air-* 前缀可进入 REAL
    /// 允许集；证明内容不真实——真实 stwo 路径的正例回归在
    /// poker-appchain-texasair 适配器测试）。
    struct NamedMockEngine {
        name: &'static str,
        attestor_public: [u8; 32],
    }

    impl SettlementProver for NamedMockEngine {
        fn name(&self) -> &'static str {
            self.name
        }

        fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
            Ok(ProofBundle {
                binding_hex: hex::encode(job.record.hand_binding),
                op_index: job.op_index,
                engine: self.name,
                attestor_public: self.attestor_public,
                payload: vec![0u8; 64],
            })
        }

        fn verify(&self, _bundle: &ProofBundle) -> AppchainResult<()> {
            Ok(())
        }
    }

    fn gate_pipeline_config() -> PipelineConfig {
        PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 16,
            high_watermark: 16,
            batch_interval_ms: 1_000,
        }
    }

    /// P0-3 (a) 引擎层门：REAL 结算经 host 签名引擎 → RealRequiresStarkProof
    ///（与管道模式无关）；PLAY 对照照常出证。
    #[test]
    fn real_settlement_rejected_by_host_engine() {
        let engine = ValidationEngine::default();
        let real_job = ProofJob {
            op_index: 0,
            table_id: 1,
            record: Arc::new(real_record(0x91, false)),
            policy: FeePolicy::Zero,
            priority: Priority::Real,
        };
        assert!(matches!(
            engine.prove(&real_job).unwrap_err(),
            AppchainError::RealRequiresStarkProof
        ));
        // PLAY 对照：同一引擎照常出证
        let play_job = ProofJob {
            record: Arc::new(signed_record(0x92, AssetClass::Play)),
            ..real_job
        };
        assert!(engine.prove(&play_job).is_ok());
    }

    /// P0-3 (b) 提交准入矩阵（拒绝路径尽早：不进队列）：
    /// Disabled / 非 STARK 引擎 / StarkRequired 未钉 key / 缺 hand_proof。
    #[test]
    fn real_submit_gate_matrix() {
        let stark_mock: Arc<dyn SettlementProver> = Arc::new(NamedMockEngine {
            name: "texas-air-mock-v1",
            attestor_public: [7u8; 32],
        });
        let real_job = |hand_proof: bool| ProofJob {
            op_index: 1,
            table_id: 1,
            record: Arc::new(real_record(0x93, hand_proof)),
            policy: FeePolicy::Zero,
            priority: Priority::Real,
        };

        // 1. Disabled：即便 STARK 引擎在位，REAL 一律拒
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::with_real_policy(
            gate_pipeline_config(),
            Arc::clone(&stark_mock),
            Arc::clone(&metrics),
            RealSettlementPolicy {
                mode: RealMode::Disabled,
                verifier_key: Some([9u8; 32]),
            },
        );
        assert!(matches!(
            p.submit(real_job(true)).unwrap_err(),
            AppchainError::RealRequiresStarkProof
        ));
        assert_eq!(metrics.counter("real_settlement_rejected_total"), 1);
        assert_eq!(p.inflight_count(), 0, "rejected job must not enter queue");

        // 2. HostAttestation + host 签名引擎：引擎对 REAL 无出证能力 → 提交即拒
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::with_real_policy(
            gate_pipeline_config(),
            Arc::new(ValidationEngine::default()),
            Arc::clone(&metrics),
            RealSettlementPolicy::host_attestation(),
        );
        assert!(matches!(
            p.submit(real_job(true)).unwrap_err(),
            AppchainError::RealRequiresStarkProof
        ));

        // 3. StarkRequired 默认（未钉 verifier key）：出证前提不完备 → 拒
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::new(
            gate_pipeline_config(),
            Arc::clone(&stark_mock),
            Arc::clone(&metrics),
        );
        assert!(matches!(
            p.submit(real_job(true)).unwrap_err(),
            AppchainError::RealRequiresStarkProof
        ));

        // 4. StarkRequired + 钉 key，但缺 hand_proof → AdmissionRejected
        let metrics = Arc::new(MetricsRegistry::new());
        let p = ProofPipeline::with_real_policy(
            gate_pipeline_config(),
            Arc::clone(&stark_mock),
            Arc::clone(&metrics),
            RealSettlementPolicy::stark_required([9u8; 32]),
        );
        assert!(matches!(
            p.submit(real_job(false)).unwrap_err(),
            AppchainError::AdmissionRejected("real settlement requires hand proof")
        ));

        // 5. 全部前提满足 → 准入；钉扎匹配的引擎 bundle 正常出批
        let metrics = Arc::new(MetricsRegistry::new());
        let pinned_mock = Arc::new(NamedMockEngine {
            name: "texas-air-mock-v1",
            attestor_public: [9u8; 32],
        });
        let p = ProofPipeline::with_real_policy(
            gate_pipeline_config(),
            pinned_mock,
            Arc::clone(&metrics),
            RealSettlementPolicy::stark_required([9u8; 32]),
        );
        assert!(p.submit(real_job(true)).is_ok());
        poll_until(|| p.completed_count() >= 1);
        let batch = p.try_build_batch().unwrap().expect("pinned batch");
        assert_eq!(batch.through_op, 1);
    }

    /// P0-3 (b) 批次/水位门：REAL op 的 bundle attestor 未钉扎 →
    /// VerifierKeyMismatch，completion 原地保留，水位不推进，告警计数；
    /// 后续 PLAY op 被连续前缀语义一并挡住（绝不越过未证明的 REAL op）。
    #[test]
    fn real_batch_pin_mismatch_blocks_watermark() {
        let metrics = Arc::new(MetricsRegistry::new());
        // 引擎 attestor [7;32] ≠ 钉扎 key [9;32]
        let engine = Arc::new(NamedMockEngine {
            name: "texas-air-mock-v1",
            attestor_public: [7u8; 32],
        });
        let p = ProofPipeline::with_real_policy(
            gate_pipeline_config(),
            engine,
            Arc::clone(&metrics),
            RealSettlementPolicy::stark_required([9u8; 32]),
        );
        let seq = Arc::new(Mutex::new(Sequencer::new(
            crate::keys::SequencerKey::from_seed(&[3u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )));
        p.set_on_batch_proven({
            let seq = Arc::clone(&seq);
            Arc::new(move |through| seq.lock().unwrap().mark_proven_through(through))
        });
        p.submit(ProofJob {
            op_index: 1,
            table_id: 1,
            record: Arc::new(real_record(0x94, true)),
            policy: FeePolicy::Zero,
            priority: Priority::Real,
        })
        .expect("admission prerequisites met");
        poll_until(|| p.completed_count() >= 1);
        // 钉扎不匹配：批次拒出，completion 保留，水位不动
        assert!(matches!(
            p.try_build_batch().unwrap_err(),
            AppchainError::VerifierKeyMismatch
        ));
        assert_eq!(p.pending_completion_count(), 1);
        assert_eq!(seq.lock().unwrap().proven_watermark(), 0);
        assert_eq!(metrics.counter("real_settlement_rejected_total"), 1);
        // 后续 PLAY op 完成也不推进（连续前缀：REAL op 仍是未证明缺口，
        // 且每次组批重触同一拒绝）
        p.submit(ProofJob {
            op_index: 2,
            table_id: 1,
            record: Arc::new(signed_record(0x95, AssetClass::Play)),
            policy: FeePolicy::Zero,
            priority: Priority::Play,
        })
        .unwrap();
        poll_until(|| p.completed_count() >= 2);
        assert!(p.try_build_batch().is_err());
        assert_eq!(seq.lock().unwrap().proven_watermark(), 0);
        assert_eq!(metrics.counter("real_settlement_rejected_total"), 2);
    }
}
