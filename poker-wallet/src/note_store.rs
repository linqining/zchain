//! `note_store`：note + spend secret + nullifier + 创建帧 + proof 状态的
//! 加密存储（plan §6.12.3）。
//!
//! ## REAL/PLAY 物理分库
//!
//! 一个 [`NoteStore`] 实例只承载一个资产类：插入时强制类检查（fail-closed），
//! 静态快照的 AEAD AAD 钉住资产类（REAL 文件永远不可能被当作 PLAY 打开）。
//! [`WalletStores`] 是"两个独立实例"的组合视图，余额按资产类聚合。
//!
//! ## 加密存储
//!
//! 静态快照 = 对整库 borsh 序列化做 AEAD（DEK 派生自 keystore），AAD =
//! `domain || class`；note/spend secret/nullifier/创建帧/proof 状态全部在
//! 密文内。内存态不落盘。

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use poker_appchain::note::{AssetClass, Note};
use rand::RngCore;

use crate::error::{WalletError, WalletResult};
use crate::key_manager::SecretBytes;

/// note store 快照域标签（AAD 组成部分）。
pub const DOMAIN_NOTE_STORE: &[u8] = b"zchain.note_store.v1";

/// note 的铸出来源帧（创建帧：软确认链上的 op 序号 + 帧哈希）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct OriginFrame {
    /// 创建本 note 的操作在软确认链上的序号。
    pub op_index: u64,
    /// 创建帧哈希（重组检测锚点）。
    pub frame_hash: [u8; 32],
}

/// 证明状态层级（与 verifier 的状态层级对齐：soft/proven/finalized）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ProofState {
    /// 已提交、帧未跟随（客户端未知）。
    Pending,
    /// 软确认帧已跟随（sequencer 承诺）。
    Soft,
    /// 已被证明批次覆盖（附批次根与批次序号）。
    Proven {
        /// 批次根（Poseidon 折叠，可复算校验）。
        batch_root: [u8; 32],
        /// 批次序号。
        batch_index: u64,
    },
    /// BFT/锚定终态。
    Finalized,
}

/// 一张钱包持有的 note 记录。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct NoteRecord {
    /// note 内容（与账本 ABI 一致）。
    pub note: Note,
    /// spend secret（owner 派生 nullifier 用；zeroize on drop）。
    pub spend_secret: SecretBytes,
    /// 铸出来源帧。
    pub origin: OriginFrame,
    /// 证明状态。
    pub proof: ProofState,
    /// 已被哪个操作消费（op 序号；None = 未花费）。
    pub spent_by_op: Option<u64>,
    /// 展示占位标记：非本钱包持有的输入（结算预览用；不参与任何签名）。
    pub is_external_stub: bool,
}

impl NoteRecord {
    /// 构造（自动生成随机 spend secret；测试可用 [`NoteRecord::with_secret`]）。
    #[must_use]
    pub fn new(note: Note, origin: OriginFrame, proof: ProofState) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self::with_secret(note, secret, origin, proof)
    }

    /// 指定 spend secret 构造（导入/测试路径）。
    #[must_use]
    pub fn with_secret(
        note: Note,
        spend_secret: [u8; 32],
        origin: OriginFrame,
        proof: ProofState,
    ) -> Self {
        Self {
            note,
            spend_secret: SecretBytes::new(spend_secret),
            origin,
            proof,
            spent_by_op: None,
            is_external_stub: false,
        }
    }

    /// 预览占位（非本钱包持有的输入；仅用于 proof 状态展示）。
    #[must_use]
    pub fn external_proof_stub() -> Self {
        Self {
            note: Note::new(AssetClass::Play, 1, [0; 33], [0; 32], None)
                .expect("stub note is valid"),
            spend_secret: SecretBytes::new([0; 32]),
            origin: OriginFrame { op_index: 0, frame_hash: [0; 32] },
            proof: ProofState::Pending,
            spent_by_op: None,
            is_external_stub: true,
        }
    }

    /// 承诺（32B 规范编码）。
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        self.note.commitment_bytes()
    }

    /// nullifier（32B 规范编码；由 spend secret 派生）。
    #[must_use]
    pub fn nullifier(&self) -> [u8; 32] {
        poker_appchain::felt::felt_to_bytes32(&self.note.nullifier(self.spend_secret.expose()))
    }

    /// 是否可花费（未花费且非桌内 seat）。
    #[must_use]
    pub fn spendable(&self) -> bool {
        self.spent_by_op.is_none() && self.note.table_id.is_none()
    }
}

/// 单资产类 note 库（物理分库单元）。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct NoteStore {
    class: AssetClass,
    /// commitment → record（BTreeMap 保证序列化确定性）。
    records: std::collections::BTreeMap<[u8; 32], NoteRecord>,
    /// nullifier → commitment 反查索引（恢复后重建并自检）。
    nullifiers: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
}

impl NoteStore {
    /// 新建空库（绑定资产类）。
    #[must_use]
    pub fn new(class: AssetClass) -> Self {
        Self {
            class,
            records: std::collections::BTreeMap::new(),
            nullifiers: std::collections::BTreeMap::new(),
        }
    }

    /// 本库资产类。
    #[must_use]
    pub fn class(&self) -> AssetClass {
        self.class
    }

    /// 记录数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 插入 note 记录（资产类强制检查 + 承诺/nullifier 去重，fail-closed）。
    ///
    /// # Errors
    /// 类不匹配 → [`WalletError::AssetClassMismatch`]；重复承诺/nullifier 冲突
    /// → [`WalletError::InvalidArgument`]。
    pub fn insert(&mut self, record: NoteRecord) -> WalletResult<[u8; 32]> {
        if record.note.asset_class != self.class {
            return Err(WalletError::AssetClassMismatch(format!(
                "store holds {}, got {}",
                self.class.name(),
                record.note.asset_class.name()
            )));
        }
        let commitment = record.commitment();
        if self.records.contains_key(&commitment) {
            return Err(WalletError::InvalidArgument("duplicate note commitment"));
        }
        let nullifier = record.nullifier();
        if let Some(prev) = self.nullifiers.get(&nullifier) {
            if *prev != commitment {
                return Err(WalletError::InvalidArgument("nullifier collision"));
            }
        }
        self.nullifiers.insert(nullifier, commitment);
        self.records.insert(commitment, record);
        Ok(commitment)
    }

    /// 按承诺查找。
    #[must_use]
    pub fn get(&self, commitment: &[u8; 32]) -> Option<&NoteRecord> {
        self.records.get(commitment)
    }

    /// 按承诺可变查找。
    pub fn get_mut(&mut self, commitment: &[u8; 32]) -> Option<&mut NoteRecord> {
        self.records.get_mut(commitment)
    }

    /// 按 nullifier 反查承诺。
    #[must_use]
    pub fn commitment_by_nullifier(&self, nullifier: &[u8; 32]) -> Option<[u8; 32]> {
        self.nullifiers.get(nullifier).copied()
    }

    /// 标记已花费。
    pub fn mark_spent(&mut self, commitment: &[u8; 32], op_index: u64) {
        if let Some(r) = self.records.get_mut(commitment) {
            r.spent_by_op = Some(op_index);
        }
    }

    /// 更新证明状态。
    pub fn set_proof(&mut self, commitment: &[u8; 32], proof: ProofState) {
        if let Some(r) = self.records.get_mut(commitment) {
            r.proof = proof;
        }
    }

    /// 自由余额（未花费、非桌内）按 u128 聚合（不溢出）。
    #[must_use]
    pub fn free_balance(&self) -> u128 {
        self.records
            .values()
            .filter(|r| r.spendable())
            .map(|r| u128::from(r.note.amount))
            .sum()
    }

    /// 桌内锁定余额（seat note）。
    #[must_use]
    pub fn table_locked_balance(&self) -> u128 {
        self.records
            .values()
            .filter(|r| r.spent_by_op.is_none() && r.note.table_id.is_some())
            .map(|r| u128::from(r.note.amount))
            .sum()
    }

    /// 全部记录（稳定序）。
    #[must_use]
    pub fn records(&self) -> impl Iterator<Item = (&[u8; 32], &NoteRecord)> {
        self.records.iter().map(|(k, v)| (k, v))
    }

    /// 全部 nullifier（稳定序；索引自检/备份索引用）。
    #[must_use]
    pub fn nullifiers(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.nullifiers.keys().copied()
    }

    /// 重建反查索引并断言与记录一致（恢复自检原语）。
    ///
    /// # Errors
    /// 索引不一致 → [`WalletError::Tampered`]。
    pub fn rebuild_and_verify_index(&mut self) -> WalletResult<()> {
        let mut rebuilt = std::collections::BTreeMap::new();
        for (commitment, record) in &self.records {
            rebuilt.insert(record.nullifier(), *commitment);
        }
        if rebuilt != self.nullifiers {
            return Err(WalletError::Tampered("nullifier index"));
        }
        self.nullifiers = rebuilt;
        Ok(())
    }

    /// 全库静态快照加密（DEK AEAD；AAD 钉住域标签 + 资产类——跨类换皮必失败）。
    ///
    /// # Errors
    /// AEAD 内部失败（实际不可达）→ [`WalletError::Codec`]。
    pub fn seal(&self, dek: &SecretBytes) -> WalletResult<Vec<u8>> {
        let plain = borsh::to_vec(self)
            .map_err(|e| WalletError::Codec(format!("note store borsh: {e}")))?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.expose()));
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &self.aad() })
            .map_err(|_| WalletError::Codec("note store seal".into()))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 从静态快照恢复（AAD 资产类不符 → [`WalletError::Tampered`]；口令根
    /// DEK 错 → [`WalletError::BadPassword`]）。
    ///
    /// # Errors
    /// 见上。
    pub fn open(dek: &SecretBytes, class: AssetClass, blob: &[u8]) -> WalletResult<Self> {
        if blob.len() < 12 {
            return Err(WalletError::Tampered("note store blob"));
        }
        let (nonce, ct) = blob.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(dek.expose()));
        let aad = note_store_aad(class);
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| WalletError::BadPassword)?;
        let mut store: Self = borsh::from_slice(&plain)
            .map_err(|_| WalletError::Tampered("note store payload"))?;
        if store.class != class {
            return Err(WalletError::AssetClassMismatch(format!(
                "expected {}, sealed {}",
                class.name(),
                store.class.name()
            )));
        }
        store.rebuild_and_verify_index()?;
        Ok(store)
    }

    fn aad(&self) -> Vec<u8> {
        note_store_aad(self.class)
    }
}

/// note store 快照 AAD：域标签 + 资产类字节 + 格式版本。
#[must_use]
pub fn note_store_aad(class: AssetClass) -> Vec<u8> {
    let mut a = DOMAIN_NOTE_STORE.to_vec();
    a.push(class.as_u8());
    a.push(1); // 快照格式版本
    a
}

/// REAL/PLAY 物理分库组合：两个独立 [`NoteStore`] 实例。
///
/// 跨库访问不可达：类字段是构造时固定的，路由只能走 [`WalletStores::store`]。
#[derive(Debug, Clone)]
pub struct WalletStores {
    real: NoteStore,
    play: NoteStore,
}

/// 按资产类聚合的余额视图。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BalancesView {
    /// REAL 自由余额。
    pub real_free: u128,
    /// REAL 桌内锁定。
    pub real_locked: u128,
    /// PLAY 自由余额。
    pub play_free: u128,
    /// PLAY 桌内锁定。
    pub play_locked: u128,
}

impl WalletStores {
    /// 新建分库组合。
    #[must_use]
    pub fn new() -> Self {
        Self {
            real: NoteStore::new(AssetClass::Real),
            play: NoteStore::new(AssetClass::Play),
        }
    }

    /// 按资产类路由（唯一入口：物理分库语义）。
    #[must_use]
    pub fn store(&mut self, class: AssetClass) -> &mut NoteStore {
        match class {
            AssetClass::Real => &mut self.real,
            AssetClass::Play => &mut self.play,
        }
    }

    /// REAL 库只读。
    #[must_use]
    pub fn real(&self) -> &NoteStore {
        &self.real
    }

    /// 替换 REAL 库（恢复流程用；恢复后必须跑 [`WalletStores::verify_indexes`]）。
    pub fn set_real(&mut self, store: NoteStore) {
        assert_eq!(store.class(), AssetClass::Real, "physical split violated");
        self.real = store;
    }

    /// 替换 PLAY 库（恢复流程用）。
    pub fn set_play(&mut self, store: NoteStore) {
        assert_eq!(store.class(), AssetClass::Play, "physical split violated");
        self.play = store;
    }

    /// PLAY 库只读。
    #[must_use]
    pub fn play(&self) -> &NoteStore {
        &self.play
    }

    /// 余额聚合视图（按资产类）。
    #[must_use]
    pub fn balances(&self) -> BalancesView {
        BalancesView {
            real_free: self.real.free_balance(),
            real_locked: self.real.table_locked_balance(),
            play_free: self.play.free_balance(),
            play_locked: self.play.table_locked_balance(),
        }
    }

    /// 全库自检：两个库各自 nullifier 索引一致，且互不越类。
    ///
    /// # Errors
    /// 索引不一致 → [`WalletError::Tampered`]。
    pub fn verify_indexes(&mut self) -> WalletResult<()> {
        self.real.rebuild_and_verify_index()?;
        self.play.rebuild_and_verify_index()
    }
}

impl Default for WalletStores {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(seed: u8) -> [u8; 33] {
        crate::key_manager::OwnerKeyPair::from_seed(&[seed; 32])
            .unwrap()
            .public_bytes()
    }

    #[test]
    fn physical_split_is_enforced() {
        let mut stores = WalletStores::new();
        let real_note = Note::new(AssetClass::Real, 100, owner(1), [1u8; 32], None).unwrap();
        let rec = NoteRecord::with_secret(real_note, [7u8; 32],
            OriginFrame { op_index: 0, frame_hash: [0; 32] }, ProofState::Soft);
        let c = stores.store(AssetClass::Real).insert(rec).unwrap();
        // REAL 库确实持有该承诺
        assert!(stores.real().get(&c).is_some());
        // REAL 库拒绝 PLAY note 插入（跨类 fail-closed）
        let play_note = Note::new(AssetClass::Play, 100, owner(1), [2u8; 32], None).unwrap();
        let bad = NoteRecord::with_secret(play_note, [7u8; 32],
            OriginFrame { op_index: 1, frame_hash: [0; 32] }, ProofState::Soft);
        assert!(matches!(
            stores.store(AssetClass::Real).insert(bad),
            Err(WalletError::AssetClassMismatch(_))
        ));
        // PLAY 库看不到 REAL 的承诺
        assert!(stores.play().get(&c).is_none());
        assert!(stores.play().is_empty());
        let b = stores.balances();
        assert_eq!(b.real_free, 100);
        assert_eq!(b.play_free, 0);
    }

    #[test]
    fn sealed_snapshot_is_class_pinned() {
        let mut stores = WalletStores::new();
        let note = Note::new(AssetClass::Real, 50, owner(2), [3u8; 32], None).unwrap();
        stores
            .store(AssetClass::Real)
            .insert(NoteRecord::with_secret(note, [8u8; 32],
                OriginFrame { op_index: 0, frame_hash: [0; 32] }, ProofState::Pending))
            .unwrap();
        let dek = SecretBytes::new([42u8; 32]);
        let blob = stores.real().seal(&dek).unwrap();
        // 用 PLAY 类打开 REAL 快照 → AAD 不符 → 拒绝
        assert!(matches!(
            NoteStore::open(&dek, AssetClass::Play, &blob),
            Err(WalletError::BadPassword)
        ));
        let back = NoteStore::open(&dek, AssetClass::Real, &blob).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.free_balance(), 50);
        // 篡改一个字节 → 拒绝
        let mut tampered = blob.clone();
        let i = tampered.len() - 1;
        tampered[i] ^= 0x01;
        assert!(NoteStore::open(&dek, AssetClass::Real, &tampered).is_err());
    }

    #[test]
    fn index_self_check_detects_drift() {
        let mut store = NoteStore::new(AssetClass::Play);
        let note = Note::new(AssetClass::Play, 5, owner(3), [4u8; 32], None).unwrap();
        store
            .insert(NoteRecord::with_secret(note, [9u8; 32],
                OriginFrame { op_index: 0, frame_hash: [0; 32] }, ProofState::Soft))
            .unwrap();
        assert!(store.rebuild_and_verify_index().is_ok());
        assert_eq!(store.nullifiers().count(), 1);
    }
}
