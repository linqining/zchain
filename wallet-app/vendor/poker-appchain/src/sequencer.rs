//! M3：Sequencer——软确认应用引擎。
//!
//! 构造性无冲突（桌与桌 note 集合不相交）：**不需要 Block-STM**，只需要
//! nullifier 查重 + 桌级互斥（BTreeMap 天然互斥）。单 sequencer 串行应用，
//! 软确认 = 签名帧落 WAL + 内存状态更新，毫秒级。
//!
//! ## 应用管线（每笔操作，P0-4 原子提交）
//!
//! ```text
//! 限流 → 语义校验 + 试算（克隆态上 apply，真实状态零接触）
//!      → 帧签名 → WAL append + fsync（承诺点）→ 内存态原子换入
//! ```
//!
//! write-ahead 顺序：**先 WAL 后内存应用**。任何一步失败 = 整笔拒绝
//! （fail-closed）：试算失败则真实状态从未被接触；WAL 写/fsync 失败则
//! 试算态被丢弃，内存态/链/时间戳全部未动（内存与 WAL 不可能分叉）。
//! 重启后从 WAL 全量重放恢复。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use starknet_crypto::poseidon_hash_many;

use crate::error::{AppchainError, AppchainResult};
use crate::fee::{FeePolicy, FeeRegistry};
use crate::felt::{felt_from_u64, felt_to_bytes32};
use crate::keys::{blake2s32, spend_digest, SequencerKey};
use crate::merkle::PoseidonMerkleTree;
use crate::metrics::MetricsRegistry;
use crate::note::Note;
use crate::nullifier_set::NullifierSet;
use crate::ops::{scope, Operation};
use crate::real_policy::{FinalityEvidence, WithdrawalProvenance};
use crate::settlement::validate_settlement;
use crate::soft_confirm::{chain_head, SignedFrame, SoftConfirmFrame};
use crate::wal::WalWriter;

/// sequencer 配置。
#[derive(Debug, Clone)]
pub struct SequencerConfig {
    /// 桌准入只收 proven note（M8 污染防御；plan §M3）。
    pub admission_proven_only: bool,
    /// 每 principal 每分钟操作数（burst 同值）。
    pub ops_per_min: u32,
    /// 每 principal 每分钟开桌数（burst 同值）。
    pub open_table_per_min: u32,
    /// 单桌最大 seat note 数（容量限制）。
    pub max_seats: usize,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            admission_proven_only: true,
            ops_per_min: 600,
            open_table_per_min: 30,
            max_seats: 10,
        }
    }
}

/// note 状态：pending（软确认未证明）→ proven（批次已落证明）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteStatus {
    /// 已软确认，等待证明覆盖。
    Pending,
    /// 已被证明批次覆盖。
    Proven,
}

/// 账本中的 note 条目。
#[derive(Debug, Clone)]
pub struct NoteEntry {
    /// note 全量内容。
    pub note: Note,
    /// 承诺树叶索引。
    pub leaf_index: u64,
    /// 创建时的操作序号（= 帧链 index）。
    pub created_at_op: u64,
    /// 证明状态。
    pub status: NoteStatus,
}

/// 桌状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableState {
    /// 开放中。
    pub open: bool,
    /// 当前 seat note 数。
    pub seats: usize,
}

/// 令牌桶（每 principal）。
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_ms: u64,
}

/// 限流器。
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: HashMap<[u8; 32], TokenBucket>,
}

impl RateLimiter {
    /// 判定并扣减一个令牌（不足则拒绝且不扣）。
    pub fn allow(&mut self, principal: &[u8; 32], now_ms: u64, rate_per_min: u32) -> bool {
        let rate = f64::from(rate_per_min);
        let b = self.buckets.entry(*principal).or_insert_with(|| TokenBucket {
            tokens: rate,
            last_ms: now_ms,
        });
        let elapsed_ms = now_ms.saturating_sub(b.last_ms);
        b.tokens = (b.tokens + elapsed_ms as f64 / 60_000.0 * rate).min(rate);
        b.last_ms = now_ms;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

    /// 账本状态（可重放重建；Clone 供提交路径克隆态试算，P0-4）。
    #[derive(Debug, Clone, Default)]
    pub struct LedgerState {
        /// notes：承诺字节 → 条目。
        pub notes: HashMap<[u8; 32], NoteEntry>,
        /// owner 二级索引（B5）：owner 压缩公钥 → 该 owner 名下 **live**
        /// note 承诺集合。纯性能结构（**不入状态根**，行为等价由
        /// `tests/proptests.rs::owner_index_matches_full_scan` 属性测试
        /// 钉住）：mint/consume 全路径（deposit/buy-in/settle payout+
        /// rake/transfer 输出/withdraw 销毁）经 [`Sequencer::mint_note`]/
        /// [`Sequencer::consume_note`] 同步维护，消费即移除（集合空则连
        /// owner 键一并删除，索引语义 == 对 `notes` 的全量扫描）。WAL 重放
        /// 复用同一 `apply_op` → mint/consume 路径，重启自然重建。
        pub owner_index: HashMap<[u8; 33], HashSet<[u8; 32]>>,
        /// note 承诺 → 铸出来源 op（§5.4 provenance 映射）。与
        /// [`NoteEntry::created_at_op`] 同源（`mint_note` 写入），但**消费后
        /// 不删除**——提现销毁后托管打款侧仍需查来源 op 过 finality 门；
        /// WAL 重放重建。
        pub note_origins: HashMap<[u8; 32], u64>,
        /// 承诺树。
        pub tree: PoseidonMerkleTree,
        /// nullifier 集。
        pub nullifiers: NullifierSet,
        /// 桌状态。
        pub tables: BTreeMap<u64, TableState>,
        /// 费率注册表（开桌冻结）。
        pub registry: FeeRegistry,
        /// 已结算 hand_binding。
        pub settled_bindings: HashSet<[u8; 32]>,
        /// 已处理充值幂等键。
        pub deposit_ids: HashSet<[u8; 32]>,
        /// 已接受提现幂等键。
        pub withdrawal_ids: HashSet<[u8; 32]>,
        /// 被销毁（提现）note 记录：(request_id, 面额)。
        pub burned: Vec<([u8; 32], u64)>,
        /// 已应用操作数（= 帧链 index 的下一个）。
        pub seq: u64,
        /// 证明水位：op index ≤ watermark 的产出 note 已被证明覆盖。只按**最大
        /// 连续前缀**推进（见 [`Sequencer::mark_proven`]）；不在 WAL 重放路径上
        /// ——崩溃重启后保守归零（note 回 Pending，桌准入重新拦截），由证明
        /// 管道对已验证批次重新回调恢复。
        pub proven_watermark: u64,
    }

impl LedgerState {
    /// 账本状态根：`poseidon` 折叠（树根、nullifier 根、注册表根、桌折叠、序号）。
    ///
    /// **不含** `proven_watermark`：水位是证明管道的恢复态元数据（不入 WAL，
    /// 崩溃后由批次回调重放恢复），不是帧链承诺的账本状态——否则两次帧间
    /// 的水位推进会嵌入后续帧的 `state_root`，使 WAL 重放（重放从零水位
    /// 开始）必然分叉，破坏 P0-4"重启后从 WAL 全量重放恢复"。
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut acc = self.tree.root();
        acc = poseidon_hash_many(&[acc, self.nullifiers.root()]);
        acc = poseidon_hash_many(&[acc, self.registry.root()]);
        for (table_id, ts) in &self.tables {
            acc = poseidon_hash_many(&[
                acc,
                felt_from_u64(*table_id),
                felt_from_u64(u64::from(ts.open)),
                felt_from_u64(ts.seats as u64),
            ]);
        }
        acc = poseidon_hash_many(&[
            acc,
            felt_from_u64(self.seq),
            felt_from_u64(self.nullifiers.spent_count),
        ]);
        felt_to_bytes32(&acc)
    }

    /// 某 owner 名下的全部 live note 承诺（B5：O(1) 索引命中；承诺集引用，
    /// 零拷贝）。
    #[must_use]
    pub fn commitments_of(&self, owner: &[u8; 33]) -> Option<&HashSet<[u8; 32]>> {
        self.owner_index.get(owner)
    }

    /// 某 owner 名下的全部 live note（B5：走 owner_index，O(1) 定位 +
    /// k 次查表，不再全账本线性扫描）。
    #[must_use]
    pub fn notes_of(&self, owner: &[u8; 33]) -> Vec<Note> {
        self.note_entries_of(owner).into_iter().map(|e| e.note.clone()).collect()
    }

    /// 某 owner 名下的全部 live 条目（含 leaf_index/status 等账本元数据；
    /// B5 索引路径）。顺序不保证（HashSet 迭代序）。
    #[must_use]
    pub fn note_entries_of(&self, owner: &[u8; 33]) -> Vec<&NoteEntry> {
        match self.owner_index.get(owner) {
            Some(set) => set
                .iter()
                .filter_map(|c| self.notes.get(c))
                .collect(),
            None => Vec::new(),
        }
    }

    /// 某 owner 的余额聚合（(REAL, PLAY)）。B5：走 owner_index，与全量
    /// 扫描等价（`owner_index_matches_full_scan` 属性测试钉住）。
    #[must_use]
    pub fn balances_of(&self, owner: &[u8; 33]) -> (u128, u128) {
        let mut real = 0u128;
        let mut play = 0u128;
        if let Some(set) = self.owner_index.get(owner) {
            for c in set {
                if let Some(e) = self.notes.get(c) {
                    match e.note.asset_class {
                        crate::note::AssetClass::Real => real += u128::from(e.note.amount),
                        crate::note::AssetClass::Play => play += u128::from(e.note.amount),
                    }
                }
            }
        }
        (real, play)
    }
}

/// Sequencer。
pub struct Sequencer {
    config: SequencerConfig,
    key: SequencerKey,
    state: LedgerState,
    rate: RateLimiter,
    wal: Option<WalWriter>,
    metrics: Arc<MetricsRegistry>,
    last_ts_ms: u64,
    chain: Vec<SignedFrame>,
    /// 水位之上的单点证明完成集合（P0-5 连续前缀语义的"缺口"记录）；
    /// 不入状态根——崩溃重启后由证明管道重新回调恢复。
    proven_marks: HashSet<u64>,
    /// 已记录批次根：through_op → batch_root（§5.4 finality 证据）。
    /// 内存态，与证明水位同生命周期——重启后由证明管道对已验证批次
    /// 重新回调恢复（[`Sequencer::record_batch_root`]）。
    batch_roots: BTreeMap<u64, [u8; 32]>,
}

impl Sequencer {
    /// 新建（内存模式，无 WAL）。
    #[must_use]
    pub fn new(
        key: SequencerKey,
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            config,
            key,
            state: LedgerState::default(),
            rate: RateLimiter::default(),
            wal: None,
            metrics,
            last_ts_ms: 0,
            chain: Vec::new(),
            proven_marks: HashSet::new(),
            batch_roots: BTreeMap::new(),
        }
    }

    /// 挂载 WAL（追加模式；调用方负责先 [`Sequencer::replay`] 恢复）。
    ///
    /// fsync 默认开启（每次提交 [`WalWriter::sync`] 真落盘）；测试提速可用
    /// [`WalWriter::with_fsync(false)`] 构造后经 `attach_wal_writer` 注入。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_wal(&mut self, path: &Path) -> AppchainResult<()> {
        self.wal = Some(WalWriter::open_append(path)?);
        Ok(())
    }

    /// 注入已构造的 WAL writer（测试故障注入用；生产路径走 [`Sequencer::attach_wal`]）。
    #[cfg(test)]
    pub(crate) fn attach_wal_writer(&mut self, w: WalWriter) {
        self.wal = Some(w);
    }

    /// 从 WAL 全量重放（fail-closed：链签名、每帧状态根都重验）。
    ///
    /// # Errors
    /// 链断裂/签名坏/状态根分叉 → 对应错误。
    pub fn replay(
        path: &Path,
        key_public: [u8; 32],
        config: SequencerConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> AppchainResult<Self> {
        let frames = crate::wal::read_all(path)?;
        crate::soft_confirm::verify_chain(&frames, &key_public)?;
        // 证明水位不入 WAL（崩溃重启后保守归零）。历史帧在提交时已通过
        // 全部在线准入（含"桌准入只收 proven note"），重放是**重建已承诺
        // 状态**而非新准入——若按原配置重放，任何含成功 BuyIn 的 WAL 都会
        // 因水位丢失而无法恢复（破坏 P0-4"重启后从 WAL 全量重放恢复"的
        // 承诺点语义）。恢复期覆盖该单项，重放完成后恢复原始配置——
        // 重启后的**新**提交仍受完整在线准入约束（M8 污染防御不变）。
        let recovery_config = SequencerConfig {
            admission_proven_only: false,
            ..config.clone()
        };
        let mut seq = Self::new(
            SequencerKey::from_seed(&[0u8; 32]),
            recovery_config,
            metrics,
        );
        seq.chain = Vec::with_capacity(frames.len());
        for f in &frames {
            let expect_root = f.frame.state_root;
            let ts = f.frame.ts_ms;
            // 关联字段分离借用（config/metrics 共享、state 可变），不走 &self
            Self::apply_op(&seq.config, &seq.metrics, &mut seq.state, &f.frame.op)?;
            let got = seq.state.root();
            if got != expect_root {
                return Err(AppchainError::WalCorrupted("state root divergence on replay"));
            }
            seq.last_ts_ms = ts;
            seq.chain.push(f.clone());
        }
        seq.config = config;
        Ok(seq)
    }

    /// 账本状态引用。
    #[must_use]
    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// 软确认链引用。
    #[must_use]
    pub fn chain(&self) -> &[SignedFrame] {
        &self.chain
    }

    /// 链头哈希。
    ///
    /// # Errors
    /// 序列化失败 → Codec。
    pub fn head_hash(&self) -> AppchainResult<[u8; 32]> {
        chain_head(&self.chain)
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &SequencerConfig {
        &self.config
    }

    /// 证明水位只读访问器（管道/观测用）。
    #[must_use]
    pub fn proven_watermark(&self) -> u64 {
        self.state.proven_watermark
    }

    /// 标记单个 op_index 证明完成（P0-5 连续前缀语义）：内部只把
    /// `proven_watermark` 推进到**最大连续前缀**——存在失败/未完成的缺口
    /// 时水位停住，绝不越过未证明操作。
    ///
    /// 持久化语义（P0-4 复核）：水位是唯一不走 WAL 的状态变更——内存态可
    /// 由证明管道从批次重放恢复（崩溃后保守归零），无需独立持久化。
    pub fn mark_proven(&mut self, op_index: u64) {
        if op_index <= self.state.proven_watermark || !self.proven_marks.insert(op_index) {
            return; // 已被水位覆盖或重复标记
        }
        let mut w = self.state.proven_watermark;
        while self.proven_marks.remove(&(w + 1)) {
            w += 1;
        }
        if w > self.state.proven_watermark {
            self.state.proven_watermark = w;
            for e in self.state.notes.values_mut() {
                if e.created_at_op <= w {
                    e.status = NoteStatus::Proven;
                }
            }
            self.metrics.set_gauge("proven_watermark", w);
        }
    }

    /// 证明水位推进（pipeline 批次回调）：标记 `0..=n` 全部已证明（批次
    /// 覆盖到 through_op，其间所有操作一并视为已证明），内部同一连续前缀
    /// 语义（这里前缀天然连续，直接推进）。
    pub fn mark_proven_through(&mut self, op_index: u64) {
        if op_index <= self.state.proven_watermark {
            return;
        }
        self.proven_marks.retain(|&g| g > op_index);
        self.state.proven_watermark = op_index;
        for e in self.state.notes.values_mut() {
            if e.created_at_op <= op_index {
                e.status = NoteStatus::Proven;
            }
        }
        self.metrics.set_gauge("proven_watermark", op_index);
    }

    /// 批次根记录（§5.4 finality 证据）：批次回调带 root 时快照
    /// `through_op → root`。内存态——重启后由证明管道对已验证批次重新
    /// 回调恢复（与证明水位同生命周期）。
    pub fn record_batch_root(&mut self, through_op: u64, root: [u8; 32]) {
        self.batch_roots.insert(through_op, root);
    }

    /// 水位推进 + 批次根记录（生产装配点：pipeline 批次回调一次调用完成
    /// 证明水位与 §5.4 finality 证据的同步推进）。
    pub fn mark_proven_through_with_root(&mut self, op_index: u64, root: [u8; 32]) {
        self.record_batch_root(op_index, root);
        self.mark_proven_through(op_index);
    }

    /// 已记录批次根覆盖到的最大 op（None = 尚无批次根记录）。
    #[must_use]
    pub fn batch_covered_through(&self) -> Option<u64> {
        self.batch_roots.keys().next_back().copied()
    }

    /// 已记录批次根查询（观测/审计用）。
    #[must_use]
    pub fn batch_root_at(&self, through_op: u64) -> Option<[u8; 32]> {
        self.batch_roots.get(&through_op).copied()
    }

    /// 提现 provenance 导出（§5.4 配套）：note 铸出来源 op
    /// （`LedgerState.note_origins`，消费后保留——提现销毁后托管侧仍可查；
    /// WAL 重放重建）。
    #[must_use]
    pub fn withdrawal_provenance(&self, note: &Note) -> Option<WithdrawalProvenance> {
        let c = felt_to_bytes32(&note.commitment());
        // 优先查 live 条目（created_at_op），销毁后回落到 origins 映射——
        // 两者同源同值
        let op = self
            .state
            .notes
            .get(&c)
            .map(|e| e.created_at_op)
            .or_else(|| self.state.note_origins.get(&c).copied())?;
        let asset_class = self
            .state
            .notes
            .get(&c)
            .map(|e| e.note.asset_class)
            .unwrap_or(note.asset_class);
        Some(WithdrawalProvenance {
            asset_class,
            source_op_index: op,
        })
    }

    /// finality 证据快照（托管账提现申请的判定输入）。
    #[must_use]
    pub fn finality_evidence(&self) -> FinalityEvidence {
        FinalityEvidence {
            proven_watermark: self.state.proven_watermark,
            batch_covered_through: self.batch_covered_through(),
        }
    }

    /// 提交一笔操作：软确认全管线，成功返回已签名帧。
    ///
    /// # Errors
    /// 见 [`AppchainError`] 全部变体——每个拒绝路径唯一。
    pub fn submit(
        &mut self,
        op: Operation,
        now_ms: u64,
    ) -> AppchainResult<SignedFrame> {
        let t0 = Instant::now();
        let principal = self.principal_of(&op);
        // 限流（开桌单独配额）
        let is_table_op = matches!(op, Operation::OpenTable { .. });
        let rate = if is_table_op {
            self.config.open_table_per_min
        } else {
            self.config.ops_per_min
        };
        if !self.rate.allow(&principal, now_ms, rate) {
            self.metrics.inc("ops_rejected_total");
            return Err(AppchainError::RateLimited(principal));
        }

        let op_index = self.state.seq; // 本操作位置（apply 成功后 = seq-1 不变式）
        let ts = now_ms.max(self.last_ts_ms);
        let prev = self.head_hash()?;

        // P0-4 原子提交，两段式（试算 → 持久化承诺 → 生效）：
        // - 持久模式（挂 WAL）：在**克隆态**上试算（语义失败在此返回，真实
        //   状态零接触），帧携带试算后的状态根；WAL append + sync（fsync 承诺
        //   点）成功后才把试算态原子换入——WAL 写/fsync 失败时内存态、链、
        //   时间戳全部未动（内存与 WAL 不可能分叉）。试算阶段的 metrics 观测
        //   可能包含最终被 WAL 拒绝的操作（仅影响观测，不影响共识态）。
        // - 内存模式（无 WAL，测试/压测）：直接原地应用，免克隆开销。
        // 失败路径共同点：限流令牌已扣（DoS 防御从宽，可接受）。
        let signed = if self.wal.is_some() {
            let mut staged = self.state.clone();
            Self::apply_op(&self.config, &self.metrics, &mut staged, &op)?;
            let frame = SoftConfirmFrame {
                index: op_index,
                prev_hash: prev,
                op,
                state_root: staged.root(),
                ts_ms: ts,
            };
            let signed = SignedFrame::sign(frame, &self.key)?;
            // write-ahead：先持久化后生效
            let w = self.wal.as_mut().expect("wal presence checked");
            w.append(&signed)?;
            w.sync()?;
            self.state = staged;
            signed
        } else {
            Self::apply_op(&self.config, &self.metrics, &mut self.state, &op)?;
            let frame = SoftConfirmFrame {
                index: op_index,
                prev_hash: prev,
                op,
                state_root: self.state.root(),
                ts_ms: ts,
            };
            SignedFrame::sign(frame, &self.key)?
        };
        self.last_ts_ms = ts;
        self.chain.push(signed.clone());
        self.metrics.inc("ops_total");
        self.metrics.observe(
            "soft_confirm_us",
            u64::try_from(t0.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        Ok(signed)
    }

    fn principal_of(&self, op: &Operation) -> [u8; 32] {
        let owner32 = |pk: &[u8; 33]| -> [u8; 32] {
            let mut h = [0u8; 32];
            h.copy_from_slice(&pk[1..33]);
            h
        };
        match op {
            Operation::OpenTable { .. } | Operation::CloseTable { .. }
            | Operation::Deposit { .. } => [0u8; 32], // operator
            Operation::WithdrawRequest { note, .. } => owner32(&note.owner),
            Operation::BuyIn { notes, .. } | Operation::Transfer { notes, .. } => {
                notes.first().map(|n| owner32(&n.owner)).unwrap_or([0u8; 32])
            }
            Operation::Settle(r) => r
                .inputs
                .first()
                .map(|i| owner32(&i.note.owner))
                .unwrap_or([0u8; 32]),
        }
    }

    // ===== 语义应用（全部检查先行，应用段零失败）=====
    //
    // P0-4：应用逻辑与 Sequencer 实例解耦（state 显式传参），使提交路径能
    // 在克隆态上试算、WAL 承诺后才换入真实状态。注意：试算阶段 metrics 观测
    // 可能包含最终被 WAL 拒绝的操作（仅影响观测，不影响共识态）。

    fn apply_op(
        config: &SequencerConfig,
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        op: &Operation,
    ) -> AppchainResult<()> {
        // 效果摘要（审计 S1）：绑定操作全部语义载荷，纳入花费签名验证
        let effect = op.effect_digest();
        let res = match op {
            Operation::OpenTable { table_id, policy } => {
                Self::apply_open_table(state, *table_id, policy)
            }
            Operation::CloseTable { table_id } => Self::apply_close_table(state, *table_id),
            Operation::Deposit { deposit_id, owner, asset_class, amount } => {
                Self::apply_deposit(state, deposit_id, owner, *asset_class, *amount)
            }
            Operation::WithdrawRequest { spend, note, request_id } => {
                Self::apply_withdraw(state, spend, note, request_id, &effect)
            }
            Operation::Transfer { spends, notes, outputs } => {
                Self::apply_transfer(state, spends, notes, outputs, &effect)
            }
            Operation::BuyIn { table_id, spends, notes, seat_owner } => {
                Self::apply_buy_in(config, state, *table_id, spends, notes, seat_owner, &effect)
            }
            Operation::Settle(record) => Self::apply_settle(metrics, state, record),
        };
        if res.is_ok() {
            // 成功才推进序号（失败路径零状态变更）
            state.seq += 1;
        }
        res
    }

    fn apply_open_table(
        state: &mut LedgerState,
        table_id: u64,
        policy: &FeePolicy,
    ) -> AppchainResult<()> {
        if state.tables.contains_key(&table_id) {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        state.registry.bind(table_id, *policy)?;
        state.tables.insert(
            table_id,
            TableState {
                open: true,
                seats: 0,
            },
        );
        Ok(())
    }

    fn apply_close_table(state: &mut LedgerState, table_id: u64) -> AppchainResult<()> {
        match state.tables.get_mut(&table_id) {
            Some(ts) if ts.open => {
                ts.open = false;
                Ok(())
            }
            _ => Err(AppchainError::TableNotOpen(table_id)),
        }
    }

    fn apply_deposit(
        state: &mut LedgerState,
        deposit_id: &[u8; 32],
        owner: &[u8; 33],
        asset_class: crate::note::AssetClass,
        amount: u64,
    ) -> AppchainResult<()> {
        // C1：先完成全部可失败检查，幂等键最后插入（失败零状态变更）
        let nonce = Self::mint_nonce(state.seq, b"deposit", deposit_id);
        let note = Note::new(asset_class, amount, *owner, nonce, None)?;
        let c = felt_to_bytes32(&note.commitment());
        if state.notes.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        if !state.deposit_ids.insert(*deposit_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate deposit id".into()));
        }
        Self::mint_note(state, note)
    }

    fn apply_withdraw(
        state: &mut LedgerState,
        spend: &crate::settlement::SpendAuth,
        note: &Note,
        request_id: &[u8; 32],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        // C1：签名/note/账本校验全部先行，幂等键销毁在变更段
        let c = felt_to_bytes32(&note.commitment());
        if c != spend.commitment || !state.notes.contains_key(&c) {
            return Err(AppchainError::NoteNotFound);
        }
        let d = spend_digest(&spend.commitment, &spend.nullifier, scope::WITHDRAW, effect);
        crate::keys::verify_ecsdsa(&note.owner, &d, &spend.sig)?;
        if !state.withdrawal_ids.insert(*request_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate request id".into()));
        }
        Self::consume_note(state, note, &spend.nullifier)?;
        state.burned.push((*request_id, note.amount));
        Ok(())
    }

    fn apply_transfer(
        state: &mut LedgerState,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        outputs: &[crate::note::NoteSpec],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        if spends.len() != notes.len() || notes.is_empty() || outputs.is_empty() {
            return Err(AppchainError::AdmissionRejected("transfer arity"));
        }
        let class = notes[0].asset_class;
        let mut input_sum = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::TRANSFER, effect);
            crate::keys::verify_ecsdsa(&n.owner, &d, &s.sig)?;
            if n.asset_class != class {
                return Err(AppchainError::AssetClassMismatch(
                    class.name(),
                    n.asset_class.name(),
                ));
            }
            input_sum += u128::from(n.amount);
        }
        crate::settlement::assert_single_class(class, outputs)?;
        let mut output_sum = 0u128;
        for o in outputs {
            output_sum += u128::from(o.amount);
        }
        if input_sum != output_sum {
            return Err(AppchainError::ConservationViolated {
                inputs: input_sum,
                outputs: output_sum,
                rake: 0,
            });
        }
        for (s, n) in spends.iter().zip(notes.iter()) {
            Self::consume_note(state, n, &s.nullifier)?;
        }
        for (i, o) in outputs.iter().enumerate() {
            let payload = blake2s32(&[
                b"transfer-out",
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = Self::mint_nonce(state.seq, b"transfer", &payload);
            Self::mint_note(state, o.clone().mint(nonce)?)?;
        }
        Ok(())
    }

    fn apply_buy_in(
        config: &SequencerConfig,
        state: &mut LedgerState,
        table_id: u64,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        seat_owner: &[u8; 33],
        effect: &[u8; 32],
    ) -> AppchainResult<()> {
        let ts = state
            .tables
            .get(&table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        if ts.seats + notes.len() > config.max_seats {
            return Err(AppchainError::AdmissionRejected("table full"));
        }
        if notes.is_empty() {
            return Err(AppchainError::AdmissionRejected("empty buy-in"));
        }
        let class = notes[0].asset_class;
        let mut total = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::BUYIN, effect);
            crate::keys::verify_ecsdsa(&n.owner, &d, &s.sig)?;
            if n.asset_class != class {
                return Err(AppchainError::AssetClassMismatch(
                    class.name(),
                    n.asset_class.name(),
                ));
            }
            // 桌准入：只收 proven note（M8 污染防御）
            if config.admission_proven_only {
                let key = felt_to_bytes32(&n.commitment());
                let e = state
                    .notes
                    .get(&key)
                    .ok_or(AppchainError::NoteNotFound)?;
                if e.status != NoteStatus::Proven {
                    return Err(AppchainError::AdmissionRejected("note not proven"));
                }
            }
            total += u128::from(n.amount);
        }
        let amount = u64::try_from(total).map_err(|_| AppchainError::InvalidAmount(u64::MAX))?;
        for (s, n) in spends.iter().zip(notes.iter()) {
            Self::consume_note(state, n, &s.nullifier)?;
        }
        let payload = blake2s32(&[b"buyin", &felt_to_bytes32(&felt_from_u64(table_id))]);
        let nonce = Self::mint_nonce(state.seq, b"buyin", &payload);
        let seat = Note::new(
            class,
            amount,
            *seat_owner,
            nonce,
            Some(table_id),
        )?;
        Self::mint_note(state, seat)?;
        if let Some(t) = state.tables.get_mut(&table_id) {
            t.seats += 1;
        }
        Ok(())
    }

    fn apply_settle(
        metrics: &MetricsRegistry,
        state: &mut LedgerState,
        record: &crate::settlement::SettlementRecord,
    ) -> AppchainResult<()> {
        let ts = state
            .tables
            .get(&record.table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(record.table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(record.table_id));
        }
        // C1：replay 检查只读；hand_binding 的销毁移到全部校验通过之后——
        // 校验失败的结算不得烧掉绑定（否则合法修正版会被误判重放）
        if state.settled_bindings.contains(&record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        let policy = *state.registry.require(record.table_id)?;
        validate_settlement(record, &policy)?;
        // 账本核对：输入 note 存在且内容一致
        for input in &record.inputs {
            let key = felt_to_bytes32(&input.note.commitment());
            let e = state
                .notes
                .get(&key)
                .ok_or(AppchainError::NoteNotFound)?;
            if e.note != input.note {
                return Err(AppchainError::AdmissionRejected("input note mismatch"));
            }
        }
        // ===== 变更段（以上全部通过，以下不再失败）=====
        if !state.settled_bindings.insert(record.hand_binding) {
            return Err(AppchainError::SettlementReplay);
        }
        // 消费 + 铸造（已通过纯函数校验，守恒有保证）
        for input in &record.inputs {
            Self::consume_note(state, &input.note, &input.spend.nullifier)?;
        }
        for (i, o) in record.payouts.iter().enumerate() {
            let payload = blake2s32(&[
                b"settle-out",
                record.hand_binding.as_slice(),
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = Self::mint_nonce(state.seq, b"settle", &payload);
            Self::mint_note(state, o.clone().mint(nonce)?)?;
        }
        if record.rake.total > 0 {
            let (t_spec, o_spec) = crate::settlement::rake_outputs(record, &policy);
            if let Some(spec) = t_spec {
                let nonce = Self::mint_nonce(state.seq, b"rake-t", &record.hand_binding);
                Self::mint_note(state, spec.mint(nonce)?)?;
            }
            if let Some(spec) = o_spec {
                let nonce = Self::mint_nonce(state.seq, b"rake-o", &record.hand_binding);
                Self::mint_note(state, spec.mint(nonce)?)?;
            }
        }
        // 结算释放全部被消费的 seat
        if let Some(t) = state.tables.get_mut(&record.table_id) {
            t.seats = t.seats.saturating_sub(record.inputs.len());
        }
        metrics.add("rake_total", u64::from(record.rake.total));
        Ok(())
    }

    // ===== 账本原语 =====

    /// 铸造 nonce：`blake2s(domain || seq_be || payload)`——seq 单调保证唯一。
    fn mint_nonce(seq: u64, domain: &[u8], payload: &[u8; 32]) -> [u8; 32] {
        blake2s32(&[domain, &seq.to_be_bytes(), payload])
    }

    fn mint_note(state: &mut LedgerState, note: Note) -> AppchainResult<()> {
        let cfelt = note.commitment();
        let c = felt_to_bytes32(&cfelt);
        if state.notes.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        let leaf = state.tree.append(cfelt)?;
        let created = state.seq;
        // §5.4 provenance：铸出即记录来源 op；消费后保留（提现打款侧
        // finality 判据），WAL 重放重建
        state.note_origins.insert(c, created);
        // B5：owner 二级索引同步维护（铸入即登记；全部铸造路径——deposit/
        // buy-in seat/transfer 输出/settle payout/rake note——都经此原语）
        state.owner_index.entry(note.owner).or_default().insert(c);
        state.notes.insert(
            c,
            NoteEntry {
                note,
                leaf_index: leaf,
                created_at_op: created,
                status: NoteStatus::Pending,
            },
        );
        Ok(())
    }

    fn consume_note(
        state: &mut LedgerState,
        note: &Note,
        nullifier: &[u8; 32],
    ) -> AppchainResult<()> {
        let c = felt_to_bytes32(&note.commitment());
        if state.notes.remove(&c).is_none() {
            return Err(AppchainError::NoteNotFound);
        }
        // B5：与 notes.remove 同步（索引语义 == 全量扫描，即便后续
        // nullifier 步骤失败也不漂移）
        if let Some(set) = state.owner_index.get_mut(&note.owner) {
            set.remove(&c);
            if set.is_empty() {
                state.owner_index.remove(&note.owner);
            }
        }
        let nf = crate::felt::felt_from_bytes32_exact(nullifier)?;
        state.nullifiers.try_consume(nf)?;
        Ok(())
    }

    /// 导出全链（watcher/锚定用）。
    #[must_use]
    pub fn export_chain(&self) -> Vec<SignedFrame> {
        self.chain.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::OwnerKey;
    use crate::note::{AssetClass, NoteSpec};
    use crate::ops::scope;
    use crate::settlement::SpendAuth;

    /// 测试用户：密钥与 spend secret 成对（生产中 secret 由客户端派生）。
    struct TestUser {
        key: OwnerKey,
        secret: [u8; 32],
    }

    impl TestUser {
        fn new(seed: u8) -> Self {
            Self {
                key: OwnerKey::from_seed(&[seed; 32]).unwrap(),
                secret: [seed; 32],
            }
        }

        fn pk(&self) -> [u8; 33] {
            self.key.public_bytes()
        }

        fn note(&self, amount: u64, class: AssetClass, nonce_byte: u8) -> Note {
            let mut nonce = [0u8; 32];
            nonce[0] = nonce_byte;
            Note::new(class, amount, self.pk(), nonce, None).unwrap()
        }

        fn auth(&self, note: &Note, scope_tag: &[u8], effect: &[u8; 32]) -> SpendAuth {
            let nf = note.nullifier(&self.secret);
            let d = spend_digest(
                &note.commitment_bytes(),
                &felt_to_bytes32(&nf),
                scope_tag,
                effect,
            );
            SpendAuth {
                commitment: felt_to_bytes32(&note.commitment()),
                nullifier: felt_to_bytes32(&nf),
                sig: self.key.sign(&d),
            }
        }
    }

    fn new_sequencer() -> Sequencer {
        Sequencer::new(
            SequencerKey::from_seed(&[11u8; 32]),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
    }

    #[test]
    fn deposit_transfer_flow() {
        let mut s = new_sequencer();
        let alice = TestUser::new(1);
        let bob = TestUser::new(2);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: alice.pk(),
                asset_class: AssetClass::Play,
                amount: 1_000,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == alice.pk())
            .unwrap()
            .note
            .clone();
        let out = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 400,
            owner: bob.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let out2 = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 600,
            owner: alice.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let effect = Operation::Transfer {
            spends: vec![],
            notes: vec![],
            outputs: vec![out.clone(), out2.clone()],
        }
        .effect_digest();
        s.submit(
            Operation::Transfer {
                spends: vec![alice.auth(&note, scope::TRANSFER, &effect)],
                notes: vec![note],
                outputs: vec![out, out2],
            },
            2_000,
        )
        .unwrap();
        let (real, play) = s.state().balances_of(&bob.pk());
        assert_eq!((real, play), (0, 400));
    }

    #[test]
    fn double_spend_rejected() {
        let mut s = new_sequencer();
        let alice = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: alice.pk(),
                asset_class: AssetClass::Play,
                amount: 500,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == alice.pk())
            .unwrap()
            .note
            .clone();
        let out = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 500,
            owner: alice.pk(),
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let effect = Operation::Transfer {
            spends: vec![],
            notes: vec![],
            outputs: vec![out.clone()],
        }
        .effect_digest();
        let op = Operation::Transfer {
            spends: vec![alice.auth(&note, scope::TRANSFER, &effect)],
            notes: vec![note],
            outputs: vec![out],
        };
        s.submit(op.clone(), 2_000).unwrap();
        let err = s.submit(op, 3_000).unwrap_err();
        assert!(matches!(err, AppchainError::DoubleSpend | AppchainError::NoteNotFound));
    }

    #[test]
    fn replay_roundtrip_with_wal() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seq.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[21u8; 32]);
        let mut s = Sequencer::new(
            key,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        s.attach_wal(&path).unwrap();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 9;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Play,
                amount: 777,
            },
            1_000,
        )
        .unwrap();
        // P0-4：先落盘后生效——提交成功即内存态已推进，WAL 可重放出同一状态
        let root_before = s.state().root();
        drop(s);
        let s2 = Sequencer::replay(
            &path,
            SequencerKey::from_seed(&[21u8; 32]).public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        let (real, play) = s2.state().balances_of(&a.pk());
        assert_eq!((real, play), (0, 777));
        assert_eq!(s2.state().root(), root_before, "replay must reconstruct identical state");
    }

    /// P0-4 (a)：WAL 写失败（磁盘满模拟）→ 提交被拒、内存态零变更、
    /// 重放不含该帧。
    #[test]
    fn wal_write_failure_keeps_state_untouched() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("walfail.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[22u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // 预算 0 字节：append 第一个字节就失败（模拟磁盘满）
        s.attach_wal_writer(WalWriter::from_sink(
            path.clone(),
            Box::new(crate::wal::BudgetSink::new(file, 0)),
            true,
        ));
        let a = TestUser::new(3);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        let err = s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 500,
                },
                1_000,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::WalCorrupted("write failed")));
        // 内存状态未被修改：序号、账本、链、水位全部原地
        assert_eq!(s.state().seq, 0);
        assert!(s.state().notes.is_empty());
        assert_eq!(s.chain().len(), 0);
        assert_eq!(s.proven_watermark(), 0);
        drop(s);
        // 后续重放不含该帧（WAL 为空，重放出空账本）
        assert!(crate::wal::read_all(&path).unwrap().is_empty());
        let s2 = Sequencer::replay(
            &path,
            key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .unwrap();
        assert_eq!(s2.state().seq, 0);
        assert_eq!(s2.state().balances_of(&a.pk()), (0, 0));
    }

    /// P0-4 (a) 补充：半帧落盘（长度头已写、帧体失败）→ 重放 fail-closed。
    #[test]
    fn wal_partial_frame_fails_replay() {
        let dir = std::env::temp_dir().join("poker-appchain-seq-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("walpartial.wal");
        let _ = std::fs::remove_file(&path);
        let key = SequencerKey::from_seed(&[23u8; 32]);
        let mut s = Sequencer::new(
            key.clone(),
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        );
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // 预算 4 字节：恰好够 u32 长度头，帧体必失败
        s.attach_wal_writer(WalWriter::from_sink(
            path.clone(),
            Box::new(crate::wal::BudgetSink::new(file, 4)),
            true,
        ));
        let a = TestUser::new(4);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 2;
        assert!(s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 100,
                },
                1_000,
            )
            .is_err());
        assert_eq!(s.state().seq, 0);
        drop(s);
        // 半帧不可解析 → 重放拒绝（fail-closed，绝不静默丢帧）
        assert!(matches!(
            crate::wal::read_all(&path),
            Err(AppchainError::WalCorrupted("truncated frame"))
        ));
        assert!(Sequencer::replay(
            &path,
            key.public,
            SequencerConfig::default(),
            Arc::new(MetricsRegistry::new()),
        )
        .is_err());
    }

    /// P0-5：mark_proven 只推进最大连续前缀，缺口（失败/未完成）挡住水位。
    #[test]
    fn proven_watermark_advances_only_contiguous_prefix() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Play,
                amount: 100,
            },
            1_000,
        )
        .unwrap();
        let commitment = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .map(|e| e.note.commitment_bytes())
            .unwrap();
        // op 0 产出 note 处于 Pending
        assert_eq!(s.state().seq, 1);
        assert_eq!(s.proven_watermark(), 0);
        // op 2、op 3 先完成：缺口 op 1 挡住水位
        s.mark_proven(2);
        assert_eq!(s.proven_watermark(), 0);
        s.mark_proven(3);
        assert_eq!(s.proven_watermark(), 0);
        let e = s.state().notes.get(&commitment).unwrap();
        assert_eq!(e.status, NoteStatus::Pending);
        // 补上 op 1 → 连续前缀一次推进到 3，note 翻 Proven
        s.mark_proven(1);
        assert_eq!(s.proven_watermark(), 3);
        let e = s.state().notes.get(&commitment).unwrap();
        assert_eq!(e.status, NoteStatus::Proven);
        // mark_proven_through：0..=n 全部标记，只进不退，幂等
        s.mark_proven_through(5);
        assert_eq!(s.proven_watermark(), 5);
        s.mark_proven_through(4);
        assert_eq!(s.proven_watermark(), 5);
    }

    #[test]
    fn rate_limit_fires() {
        let mut s = Sequencer::new(
            SequencerKey::from_seed(&[31u8; 32]),
            SequencerConfig {
                ops_per_min: 2,
                open_table_per_min: 2,
                ..SequencerConfig::default()
            },
            Arc::new(MetricsRegistry::new()),
        );
        let a = TestUser::new(1);
        for i in 0..2u8 {
            let mut deposit_id = [0u8; 32];
            deposit_id[0] = i;
            s.submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 1,
                },
                1_000,
            )
            .unwrap();
        }
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 99;
        let err = s
            .submit(
                Operation::Deposit {
                    deposit_id,
                    owner: a.pk(),
                    asset_class: AssetClass::Play,
                    amount: 1,
                },
                1_100,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::RateLimited(_)));
    }

    #[test]
    fn proven_only_admission_blocks_pending_buyin() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Real,
                amount: 1_000,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .unwrap()
            .note
            .clone();
        s.submit(
            Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
            1_100,
        )
        .unwrap();
        let buyin_effect = |table_id: u64, seat_owner: [u8; 33]| {
            Operation::BuyIn {
                table_id,
                spends: vec![],
                notes: vec![],
                seat_owner,
            }
            .effect_digest()
        };
        let err = s
            .submit(
                Operation::BuyIn {
                    table_id: 1,
                    spends: vec![a.auth(&note, scope::BUYIN, &buyin_effect(1, a.pk()))],
                    notes: vec![note],
                    seat_owner: a.pk(),
                },
                1_200,
            )
            .unwrap_err();
        assert!(matches!(err, AppchainError::AdmissionRejected("note not proven")));
        // 推进水位后通过
        s.mark_proven_through(s.state().seq);
        s.submit(
            Operation::BuyIn {
                table_id: 1,
                spends: vec![a.auth(
                    &s.state()
                        .notes
                        .values()
                        .find(|e| e.note.owner == a.pk())
                        .unwrap()
                        .note,
                    scope::BUYIN,
                    &buyin_effect(1, a.pk()),
                )],
                notes: vec![s
                    .state()
                    .notes
                    .values()
                    .find(|e| e.note.owner == a.pk())
                    .unwrap()
                    .note
                    .clone()],
                seat_owner: a.pk(),
            },
            1_300,
        )
        .unwrap();
    }

    /// §5.4 配套：note provenance（created_at_op）与批次根证据的导出。
    /// mark_proven_through 直推只动水位；批次回调（root + through_op）
    /// 才同时补齐 finality 证据。
    #[test]
    fn finality_evidence_tracks_provenance_and_batch_roots() {
        let mut s = new_sequencer();
        let a = TestUser::new(1);
        let mut deposit_id = [0u8; 32];
        deposit_id[0] = 1;
        s.submit(
            Operation::Deposit {
                deposit_id,
                owner: a.pk(),
                asset_class: AssetClass::Real,
                amount: 100,
            },
            1_000,
        )
        .unwrap();
        let note = s
            .state()
            .notes
            .values()
            .find(|e| e.note.owner == a.pk())
            .unwrap()
            .note
            .clone();
        // provenance：note 承诺 → 来源 op 0（REAL 类）
        let prov = s.withdrawal_provenance(&note).expect("note in ledger");
        assert_eq!(prov.asset_class, AssetClass::Real);
        assert_eq!(prov.source_op_index, 0);
        // 初始：无水位、无批次根
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 0,
                batch_covered_through: None
            }
        );
        // mark_proven_through 直推（无批次根）：水位动、批次覆盖不动
        s.mark_proven_through(2);
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 2,
                batch_covered_through: None
            }
        );
        // 批次回调（root + through_op）：finality 证据齐备
        let root = [0xAB; 32];
        s.mark_proven_through_with_root(4, root);
        assert_eq!(
            s.finality_evidence(),
            FinalityEvidence {
                proven_watermark: 4,
                batch_covered_through: Some(4)
            }
        );
        assert_eq!(s.batch_root_at(4), Some(root));
        assert_eq!(s.batch_covered_through(), Some(4));
        // 未知 note → None（provenance 不可伪造）
        let alien = Note::new(AssetClass::Real, 1, a.pk(), [0xFF; 32], None).unwrap();
        assert!(s.withdrawal_provenance(&alien).is_none());
        // 销毁后 provenance 保留（托管打款侧仍可过 finality 门）
        burn_test_note(&mut s, &a, &note, [9; 32]);
        assert_eq!(
            s.withdrawal_provenance(&note).expect("origin survives burn"),
            prov
        );
    }

    /// 测试脚手架：软确认一笔提现销毁（花费授权按 effect 摘要签名）。
    fn burn_test_note(s: &mut Sequencer, a: &TestUser, note: &Note, request_id: [u8; 32]) {
        let effect = Operation::WithdrawRequest {
            spend: SpendAuth {
                commitment: [0; 32],
                nullifier: [0; 32],
                sig: crate::keys::EcdsaSig { bytes: [0; 64] },
            },
            note: note.clone(),
            request_id,
        }
        .effect_digest();
        let nf = felt_to_bytes32(&note.nullifier(&a.secret));
        let d = spend_digest(&note.commitment_bytes(), &nf, scope::WITHDRAW, &effect);
        s.submit(
            Operation::WithdrawRequest {
                spend: SpendAuth {
                    commitment: note.commitment_bytes(),
                    nullifier: nf,
                    sig: a.key.sign(&d),
                },
                note: note.clone(),
                request_id,
            },
            3_000,
        )
        .unwrap();
    }
}
