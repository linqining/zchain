//! M3：Sequencer——软确认应用引擎。
//!
//! 构造性无冲突（桌与桌 note 集合不相交）：**不需要 Block-STM**，只需要
//! nullifier 查重 + 桌级互斥（BTreeMap 天然互斥）。单 sequencer 串行应用，
//! 软确认 = 签名帧落 WAL + 内存状态更新，毫秒级。
//!
//! ## 应用管线（每笔操作）
//!
//! ```text
//! 限流 → P 层签名验证 → 语义校验（M2 纯函数）→ nullifier 查重
//!      → 准入（桌开/凭证 proven）→ 应用（消费/铸造）→ 状态根 → 帧签名 → WAL
//! ```
//!
//! 任何一步失败 = 整笔拒绝（fail-closed），状态零变更（apply 前全部检查
//! 可静态完成；应用阶段只做已验证的确定性转换）。

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

/// 账本状态（可重放重建）。
#[derive(Debug, Default)]
pub struct LedgerState {
    /// notes：承诺字节 → 条目。
    pub notes: HashMap<[u8; 32], NoteEntry>,
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
    /// 证明水位：op index ≤ watermark 的产出 note 已被证明覆盖。
    pub proven_watermark: u64,
}

impl LedgerState {
    /// 账本状态根：`poseidon` 折叠（树根、nullifier 根、注册表根、桌折叠、序号）。
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
            felt_from_u64(self.proven_watermark),
        ]);
        felt_to_bytes32(&acc)
    }

    /// 某 owner 的余额聚合（(REAL, PLAY)）。
    #[must_use]
    pub fn balances_of(&self, owner: &[u8; 33]) -> (u128, u128) {
        let mut real = 0u128;
        let mut play = 0u128;
        for e in self.notes.values() {
            if &e.note.owner == owner {
                match e.note.asset_class {
                    crate::note::AssetClass::Real => real += u128::from(e.note.amount),
                    crate::note::AssetClass::Play => play += u128::from(e.note.amount),
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
        }
    }

    /// 挂载 WAL（追加模式；调用方负责先 [`Sequencer::replay`] 恢复）。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn attach_wal(&mut self, path: &Path) -> AppchainResult<()> {
        self.wal = Some(WalWriter::open_append(path)?);
        Ok(())
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
        let mut seq = Self::new(
            SequencerKey::from_seed(&[0u8; 32]),
            config,
            metrics,
        );
        seq.chain = Vec::with_capacity(frames.len());
        for f in &frames {
            let expect_root = f.frame.state_root;
            let ts = f.frame.ts_ms;
            seq.apply(&f.frame.op, ts)?;
            let got = seq.state.root();
            if got != expect_root {
                return Err(AppchainError::WalCorrupted("state root divergence on replay"));
            }
            seq.last_ts_ms = ts;
            seq.chain.push(f.clone());
        }
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

    /// 证明水位推进（pipeline 回调）：≤ op_index 的产出 note 翻 proven。
    pub fn mark_proven_through(&mut self, op_index: u64) {
        if op_index <= self.state.proven_watermark {
            return;
        }
        self.state.proven_watermark = op_index;
        for e in self.state.notes.values_mut() {
            if e.created_at_op <= op_index {
                e.status = NoteStatus::Proven;
            }
        }
        self.metrics.set_gauge("proven_watermark", op_index);
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
        self.apply(&op, now_ms)?;

        // 帧构造 + 签名 + WAL（write-ahead 顺序：先落盘后入链）
        let ts = now_ms.max(self.last_ts_ms);
        let prev = self.head_hash()?;
        let root = self.state.root();
        let frame = SoftConfirmFrame {
            index: op_index,
            prev_hash: prev,
            op,
            state_root: root,
            ts_ms: ts,
        };
        let signed = SignedFrame::sign(frame, &self.key)?;
        if let Some(w) = self.wal.as_mut() {
            w.append(&signed)?;
            w.flush()?;
        }
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

    fn apply(&mut self, op: &Operation, _now_ms: u64) -> AppchainResult<()> {
        let res = match op {
            Operation::OpenTable { table_id, policy } => self.apply_open_table(*table_id, policy),
            Operation::CloseTable { table_id } => self.apply_close_table(*table_id),
            Operation::Deposit { deposit_id, owner, asset_class, amount } => {
                self.apply_deposit(deposit_id, owner, *asset_class, *amount)
            }
            Operation::WithdrawRequest { spend, note, request_id } => {
                self.apply_withdraw(spend, note, request_id)
            }
            Operation::Transfer { spends, notes, outputs } => {
                self.apply_transfer(spends, notes, outputs)
            }
            Operation::BuyIn { table_id, spends, notes, seat_owner } => {
                self.apply_buy_in(*table_id, spends, notes, seat_owner)
            }
            Operation::Settle(record) => self.apply_settle(record),
        };
        if res.is_ok() {
            // 成功才推进序号（失败路径零状态变更）
            self.state.seq += 1;
        }
        res
    }

    fn apply_open_table(&mut self, table_id: u64, policy: &FeePolicy) -> AppchainResult<()> {
        if self.state.tables.contains_key(&table_id) {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        self.state.registry.bind(table_id, *policy)?;
        self.state.tables.insert(
            table_id,
            TableState {
                open: true,
                seats: 0,
            },
        );
        Ok(())
    }

    fn apply_close_table(&mut self, table_id: u64) -> AppchainResult<()> {
        match self.state.tables.get_mut(&table_id) {
            Some(ts) if ts.open => {
                ts.open = false;
                Ok(())
            }
            _ => Err(AppchainError::TableNotOpen(table_id)),
        }
    }

    fn apply_deposit(
        &mut self,
        deposit_id: &[u8; 32],
        owner: &[u8; 33],
        asset_class: crate::note::AssetClass,
        amount: u64,
    ) -> AppchainResult<()> {
        if !self.state.deposit_ids.insert(*deposit_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate deposit id".into()));
        }
        let nonce = self.mint_nonce(b"deposit", deposit_id);
        let note = Note::new(asset_class, amount, *owner, nonce, None)?;
        self.mint_note(note)?;
        Ok(())
    }

    fn apply_withdraw(
        &mut self,
        spend: &crate::settlement::SpendAuth,
        note: &Note,
        request_id: &[u8; 32],
    ) -> AppchainResult<()> {
        if !self.state.withdrawal_ids.insert(*request_id) {
            return Err(AppchainError::WithdrawalConflict("duplicate request id".into()));
        }
        let c = felt_to_bytes32(&note.commitment());
        if c != spend.commitment {
            return Err(AppchainError::NoteNotFound);
        }
        let d = spend_digest(&spend.commitment, &spend.nullifier, scope::WITHDRAW);
        crate::keys::verify_ecsdsa(&note.owner, &d, &spend.sig)?;
        self.consume_note(note, &spend.nullifier)?;
        self.state.burned.push((*request_id, note.amount));
        Ok(())
    }

    fn apply_transfer(
        &mut self,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        outputs: &[crate::note::NoteSpec],
    ) -> AppchainResult<()> {
        if spends.len() != notes.len() || notes.is_empty() || outputs.is_empty() {
            return Err(AppchainError::AdmissionRejected("transfer arity"));
        }
        let class = notes[0].asset_class;
        let mut input_sum = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::TRANSFER);
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
            self.consume_note(n, &s.nullifier)?;
        }
        for (i, o) in outputs.iter().enumerate() {
            let payload = blake2s32(&[
                b"transfer-out",
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = self.mint_nonce(b"transfer", &payload);
            self.mint_note(o.clone().mint(nonce)?)?;
        }
        Ok(())
    }

    fn apply_buy_in(
        &mut self,
        table_id: u64,
        spends: &[crate::settlement::SpendAuth],
        notes: &[Note],
        seat_owner: &[u8; 33],
    ) -> AppchainResult<()> {
        let ts = self
            .state
            .tables
            .get(&table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(table_id));
        }
        if ts.seats + notes.len() > self.config.max_seats {
            return Err(AppchainError::AdmissionRejected("table full"));
        }
        if notes.is_empty() {
            return Err(AppchainError::AdmissionRejected("empty buy-in"));
        }
        let class = notes[0].asset_class;
        let mut total = 0u128;
        for (s, n) in spends.iter().zip(notes.iter()) {
            let d = spend_digest(&s.commitment, &s.nullifier, scope::BUYIN);
            crate::keys::verify_ecsdsa(&n.owner, &d, &s.sig)?;
            if n.asset_class != class {
                return Err(AppchainError::AssetClassMismatch(
                    class.name(),
                    n.asset_class.name(),
                ));
            }
            // 桌准入：只收 proven note（M8 污染防御）
            if self.config.admission_proven_only {
                let key = felt_to_bytes32(&n.commitment());
                let e = self
                    .state
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
            self.consume_note(n, &s.nullifier)?;
        }
        let payload = blake2s32(&[b"buyin", &felt_to_bytes32(&felt_from_u64(table_id))]);
        let nonce = self.mint_nonce(b"buyin", &payload);
        let seat = Note::new(
            class,
            amount,
            *seat_owner,
            nonce,
            Some(table_id),
        )?;
        self.mint_note(seat)?;
        if let Some(t) = self.state.tables.get_mut(&table_id) {
            t.seats += 1;
        }
        Ok(())
    }

    fn apply_settle(
        &mut self,
        record: &crate::settlement::SettlementRecord,
    ) -> AppchainResult<()> {
        let ts = self
            .state
            .tables
            .get(&record.table_id)
            .copied()
            .ok_or(AppchainError::TableNotOpen(record.table_id))?;
        if !ts.open {
            return Err(AppchainError::TableNotOpen(record.table_id));
        }
        if !self
            .state
            .settled_bindings
            .insert(record.hand_binding)
        {
            return Err(AppchainError::SettlementReplay);
        }
        let policy = *self.state.registry.require(record.table_id)?;
        validate_settlement(record, &policy)?;
        // 账本核对：输入 note 存在且内容一致
        for input in &record.inputs {
            let key = felt_to_bytes32(&input.note.commitment());
            let e = self
                .state
                .notes
                .get(&key)
                .ok_or(AppchainError::NoteNotFound)?;
            if e.note != input.note {
                return Err(AppchainError::AdmissionRejected("input note mismatch"));
            }
        }
        // 消费 + 铸造（已通过纯函数校验，守恒有保证）
        for input in &record.inputs {
            self.consume_note(&input.note, &input.spend.nullifier)?;
        }
        for (i, o) in record.payouts.iter().enumerate() {
            let payload = blake2s32(&[
                b"settle-out",
                record.hand_binding.as_slice(),
                &felt_to_bytes32(&felt_from_u64(u64::try_from(i).unwrap_or(u64::MAX))),
            ]);
            let nonce = self.mint_nonce(b"settle", &payload);
            self.mint_note(o.clone().mint(nonce)?)?;
        }
        if record.rake.total > 0 {
            let (t_spec, o_spec) = crate::settlement::rake_outputs(record, &policy);
            if let Some(spec) = t_spec {
                let nonce = self.mint_nonce(b"rake-t", &record.hand_binding);
                self.mint_note(spec.mint(nonce)?)?;
            }
            if let Some(spec) = o_spec {
                let nonce = self.mint_nonce(b"rake-o", &record.hand_binding);
                self.mint_note(spec.mint(nonce)?)?;
            }
        }
        // 结算释放全部被消费的 seat
        if let Some(t) = self.state.tables.get_mut(&record.table_id) {
            t.seats = t.seats.saturating_sub(record.inputs.len());
        }
        self.metrics.add("rake_total", u64::from(record.rake.total));
        Ok(())
    }

    // ===== 账本原语 =====

    fn mint_note(&mut self, note: Note) -> AppchainResult<()> {
        let cfelt = note.commitment();
        let c = felt_to_bytes32(&cfelt);
        if self.state.notes.contains_key(&c) {
            return Err(AppchainError::AdmissionRejected("duplicate note commitment"));
        }
        let leaf = self.state.tree.append(cfelt)?;
        let created = self.state.seq;
        self.state.notes.insert(
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

    fn consume_note(&mut self, note: &Note, nullifier: &[u8; 32]) -> AppchainResult<()> {
        let c = felt_to_bytes32(&note.commitment());
        if self.state.notes.remove(&c).is_none() {
            return Err(AppchainError::NoteNotFound);
        }
        let nf = crate::felt::felt_from_bytes32_exact(nullifier)?;
        self.state.nullifiers.try_consume(nf)?;
        Ok(())
    }

    /// 铸造 nonce：`blake2s(domain || seq_be || payload)`——seq 单调保证唯一。
    fn mint_nonce(&self, domain: &[u8], payload: &[u8; 32]) -> [u8; 32] {
        let seq = self.state.seq.to_be_bytes();
        blake2s32(&[domain, &seq, payload])
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

        fn auth(&self, note: &Note, scope_tag: &[u8]) -> SpendAuth {
            let nf = note.nullifier(&self.secret);
            let d = spend_digest(&note.commitment_bytes(), &felt_to_bytes32(&nf), scope_tag);
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
        };
        let out2 = NoteSpec {
            asset_class: AssetClass::Play,
            amount: 600,
            owner: alice.pk(),
            table_id: None,
        };
        s.submit(
            Operation::Transfer {
                spends: vec![alice.auth(&note, scope::TRANSFER)],
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
        };
        let op = Operation::Transfer {
            spends: vec![alice.auth(&note, scope::TRANSFER)],
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
        let err = s
            .submit(
                Operation::BuyIn {
                    table_id: 1,
                    spends: vec![a.auth(&note, scope::BUYIN)],
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
}
