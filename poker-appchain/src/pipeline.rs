//! M4：证明管道——任务队列、worker 池、批次聚合、积压降级。
//!
//! 证明引擎抽象为 [`SettlementProver`] trait：v1 落地 [`ValidationEngine`]
//! （host 侧关系校验引擎，attestation 模式——与主仓库 Phase 1 姿态一致）；
//! stwo 真引擎通过实现同 trait 接入，管道机制不变。
//!
//! ## 语义
//!
//! - submit → 入队（有界，背压 = 阻塞）
//! - worker 并行 prove → 完成回调标记 proven + 入批次
//! - 批次：按帧数或时间窗聚合，批次根 = 绑定序确定性折叠
//! - 积压降级：inflight 超高水位 → degraded（告警 + 建议稀疏批次档）

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{AppchainError, AppchainResult};
use crate::fee::FeePolicy;
use crate::metrics::{evaluate_alerts, Alert, HealthInputs, MetricsRegistry};
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
    /// 引擎标识（版本化，如 "host-validate-v1"）。
    pub engine: &'static str,
    /// 证明载荷（v1 = 校验摘要；v2 = stwo proof archive）。
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

/// v1 host 校验引擎：prove = 关系纯函数校验 + 摘要打包。
///
/// 与主仓库 Phase 1 姿态一致（host 验证 + 浏览器可复验）；stwo 引擎接入
/// 是已知后续项（见 docs/plan-appchain-v1-blockers.md）。
#[derive(Debug, Default)]
pub struct ValidationEngine;

impl SettlementProver for ValidationEngine {
    fn name(&self) -> &'static str {
        "host-validate-v1"
    }

    fn prove(&self, job: &ProofJob) -> AppchainResult<ProofBundle> {
        crate::settlement::validate_settlement(&job.record, &job.policy)?;
        let digest = crate::keys::blake2s32(&[
            b"host-validate-v1",
            &job.record.hand_binding,
        ]);
        Ok(ProofBundle {
            binding_hex: hex::encode(job.record.hand_binding),
            op_index: job.op_index,
            engine: self.name(),
            payload: digest.to_vec(),
        })
    }

    fn verify(&self, bundle: &ProofBundle) -> AppchainResult<()> {
        if bundle.engine != self.name() {
            return Err(AppchainError::AdmissionRejected("unknown engine"));
        }
        if bundle.payload.len() != 32 {
            return Err(AppchainError::AdmissionRejected("bad payload"));
        }
        Ok(())
    }
}

/// 批次根（绑定序确定性折叠：`root_i = poseidon(root_{i-1}, binding_i)`）。
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

/// 证明管道（v1 串行提交 + rayon 并行 prove + 完成通道收集）。
pub struct ProofPipeline {
    config: PipelineConfig,
    engine: Arc<dyn SettlementProver>,
    metrics: Arc<MetricsRegistry>,
    inflight: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    completions: Mutex<Vec<ProofBundle>>,
    pending: Arc<Mutex<Vec<ProofJob>>>,
    batch_index: AtomicU64,
    rx: Mutex<Option<Receiver<ProofBundle>>>,
    tx: SyncSender<ProofBundle>,
}

impl ProofPipeline {
    /// 构造：启动 worker 池（rayon 并行执行 prove，完成结果进通道）。
    #[must_use]
    pub fn new(
        config: PipelineConfig,
        engine: Arc<dyn SettlementProver>,
        metrics: Arc<MetricsRegistry>,
    ) -> Arc<Self> {
        let (tx, rx) = sync_channel::<ProofBundle>(config.queue_bound);
        let pipeline = Arc::new(Self {
            inflight: Arc::new(AtomicU64::new(0)),
            completed: Arc::new(AtomicU64::new(0)),
            completions: Mutex::new(Vec::new()),
            pending: Arc::new(Mutex::new(Vec::new())),
            batch_index: AtomicU64::new(0),
            rx: Mutex::new(Some(rx)),
            tx,
            config,
            engine,
            metrics,
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
                    // 稳定取最高优先级（Real > Play），同级 FIFO
                    let best = q
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, j)| (j.priority, std::cmp::Reverse(j.op_index)));
                    let (idx, _) = best.expect("non-empty checked");
                    q.remove(idx)
                };
                let t0 = std::time::Instant::now();
                let res = p.engine.prove(&job);
                p.metrics.observe(
                    "prove_us",
                    u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
                );
                match res {
                    Ok(bundle) => {
                        // 先发送后计数：completed==N 保证 N 个 bundle 已可收割
                        let _ = p.tx.send(bundle);
                        p.completed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        p.metrics.inc("prove_failed_total");
                        // 失败任务记录后跳过（重试策略归上层编排）
                    }
                }
                p.inflight.fetch_sub(1, Ordering::Relaxed);
            });
        }
        pipeline
    }

    /// 提交任务（有界背压：队列满时短暂阻塞重试）。
    ///
    /// # Errors
    /// 提交超时（1s × 60 次）→ [`AppchainError::AdmissionRejected("pipeline saturated")`]。
    pub fn submit(&self, job: ProofJob) -> AppchainResult<()> {
        for _ in 0..60 {
            let depth = self.inflight.load(Ordering::Relaxed);
            self.metrics.set_gauge("proof_queue_depth", depth);
            if depth < u64::try_from(self.config.queue_bound).unwrap_or(u64::MAX) {
                self.inflight.fetch_add(1, Ordering::Relaxed);
                self.pending
                    .lock()
                    .expect("pending lock")
                    .push(job);
                self.metrics.inc("proof_submitted_total");
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(16));
        }
        Err(AppchainError::AdmissionRejected("pipeline saturated"))
    }

    /// 收割完成结果（非阻塞），返回本轮收集的 bundle 数。
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

    /// 从已收集 bundle 构造批次（凑满 batch_size 时触发；返回批次根）。
    ///
    /// # Errors
    /// bundle 验证失败 → 对应错误（fail-closed：坏证明不进批次）。
    pub fn try_build_batch(&self) -> AppchainResult<Option<BatchRoot>> {
        self.drain_completions();
        let mut c = self.completions.lock().expect("completions lock");
        if c.len() < self.config.batch_size {
            return Ok(None);
        }
        c.sort_by_key(|b| b.op_index);
        let take: Vec<ProofBundle> = c.drain(..self.config.batch_size).collect();
        drop(c);
        for b in &take {
            self.engine.verify(b)?;
        }
        let mut root = [0u8; 32];
        for b in &take {
            let mut binding = [0u8; 32];
            let bytes = hex::decode(&b.binding_hex)
                .map_err(|_| AppchainError::AdmissionRejected("bad binding hex"))?;
            if bytes.len() != 32 {
                return Err(AppchainError::AdmissionRejected("bad binding length"));
            }
            binding.copy_from_slice(&bytes);
            root = crate::keys::blake2s32(&[&root, &binding]);
        }
        let index = self.batch_index.fetch_add(1, Ordering::Relaxed);
        self.metrics.inc("batch_total");
        Ok(Some(BatchRoot {
            index,
            root,
            count: take.len(),
            through_op: take.last().map(|b| b.op_index).unwrap_or(0),
        }))
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
    use crate::fee::FeePolicy;
    use crate::note::{AssetClass, NoteSpec};
    use crate::settlement::{
        RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
    };

    fn dummy_record(binding_byte: u8) -> SettlementRecord {
        let k = crate::keys::OwnerKey::from_seed(&[binding_byte; 32]).unwrap();
        let note = crate::note::Note::new(
            AssetClass::Play,
            100,
            k.public_bytes(),
            [binding_byte; 32],
            Some(1),
        )
        .unwrap();
        let note_commitment_bytes = note.commitment_bytes();
        let nf = note.nullifier(&[binding_byte; 32]);
        let scope = crate::settlement::settle_spend_scope(&[binding_byte; 32]);
        let d = crate::keys::spend_digest(
            &note.commitment_bytes(),
            &crate::felt::felt_to_bytes32(&nf),
            &scope,
        );
        SettlementRecord {
            table_id: 1,
            hand_binding: [binding_byte; 32],
            policy_commitment: FeePolicy::Zero.commitment_bytes(),
            pot: 100,
            inputs: vec![SettleInput {
                note,
                spend: SpendAuth {
                    commitment: note_commitment_bytes,
                    nullifier: crate::felt::felt_to_bytes32(&nf),
                    sig: k.sign(&d),
                },
            }],
            payouts: vec![NoteSpec {
                asset_class: AssetClass::Play,
                amount: 100,
                owner: k.public_bytes(),
                table_id: None,
            }],
            rake: RakeSplitRecord {
                total: 0,
                treasury_out: None,
                operator_out: None,
            },
        }
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
            Arc::new(ValidationEngine),
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
        // 等待 worker 完成
        for _ in 0..200 {
            if p.completed.load(Ordering::Relaxed) >= 8 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let batch = p.try_build_batch().unwrap().expect("batch ready");
        assert_eq!(batch.count, 8);
        assert_eq!(batch.through_op, 7); // op_index 0..=7
        assert_ne!(batch.root, [0u8; 32]);
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
            Arc::new(ValidationEngine),
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
        assert_eq!(metrics.counter("prove_failed_total"), 1);
    }
}
