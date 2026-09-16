//! BlockStore（SubTask 4.1 — 区块持久化存储）
//!
//! 功能：
//! - 按 `block_hash` 存取完整 `Block`（BCS 序列化）
//! - 按 `height` 索引到 `block_hash`（双向查询）
//! - 提供 tip 跟踪（最高 block 的 height / hash）
//! - WriteBatch 保证 block + height 索引原子写入
//!
//! RocksDB 列族：
//! - `blocks`：key = `block_hash`（32 字节） → value = `BCS(Block)`
//! - `height_index`：key = `height_be`（8 字节 **big-endian**，数值序 = 字节序）
//!   → value = `block_hash`（32 字节）
//!
//! 历史迁移（P2 审计修复 2026-09）：commit 993029c 之前高度键为 LE 编码，
//! 现由 [`BlockStore::open`] 启动时清扫存量 LE 键并校验/重建索引（见
//! `migrate_height_index_le_to_be`），原地升级节点的 tip/range 查询不再被
//! 旧键污染。

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options, WriteBatch};

use crate::block::Block;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::{BlockHeight, ChainId, Hash};

/// `blocks` 列族名。
const BLOCKS_CF: &str = "blocks";
/// `height_index` 列族名。
const HEIGHT_INDEX_CF: &str = "height_index";

/// 区块存储（RocksDB 后端）。
///
/// 按 `block_hash` 与 `height` 双向索引；启动时无需全量加载，按需查询。
/// DB 句柄通过 `Arc<DB>` 共享，可被多线程并发访问。
pub struct BlockStore {
    /// RocksDB 句柄（包含 `blocks` + `height_index` 两个 CF）。
    db: Arc<DB>,
    /// Serialize check-and-insert so a competing local writer cannot replace a height between
    /// the conflict check and the atomic RocksDB batch.
    write_lock: std::sync::Mutex<()>,
}

impl BlockStore {
    /// 打开（或创建）指定路径下的 BlockStore。
    ///
    /// 若目录不存在会自动创建（`create_if_missing` + `create_missing_column_families`）。
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let blocks_cf = ColumnFamilyDescriptor::new(BLOCKS_CF, Options::default());
        let height_cf = ColumnFamilyDescriptor::new(HEIGHT_INDEX_CF, Options::default());

        let db = DB::open_cf_descriptors(&db_opts, path, vec![blocks_cf, height_cf])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;

        let store = Self {
            db: Arc::new(db),
            write_lock: std::sync::Mutex::new(()),
        };
        // P2 审计修复 2026-09：清扫 legacy LE 高度键并校验索引一致性
        //（新库为无操作；仅持久化路径有历史数据，临时目录天然干净）。
        store.migrate_height_index_le_to_be()?;
        Ok(store)
    }

    /// 打开一个临时目录下的 BlockStore（用于测试 / 开发）。
    ///
    /// 实现说明：使用 `std::env::temp_dir()` + 随机后缀生成唯一路径，
    /// 避免对 `tempfile` crate 的非测试依赖；进程退出后由 OS 清理 `/tmp`。
    pub fn open_inmemory() -> PokerL1Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_blockstore_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self::open(path)
    }

    /// 获取 `blocks` CF 句柄。
    fn blocks_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(BLOCKS_CF)
            .expect("blocks CF 必须存在（由 open 创建）")
    }

    /// 获取 `height_index` CF 句柄。
    fn height_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(HEIGHT_INDEX_CF)
            .expect("height_index CF 必须存在（由 open 创建）")
    }

    /// height_index LE→BE 一次性迁移（P2 审计修复 2026-09），`open` 时执行。
    ///
    /// commit 993029c 之前高度键为 `to_le_bytes()`：legacy LE 键中高度 ≥ 256
    /// 的首字节非零，字节序排在**所有** BE 键之后，`get_tip_height`（End
    /// 迭代）与 `get_range`（字节序比较）从此被永久污染。规则：
    ///
    /// - `len != 8` 的键 → 删除；
    /// - 前 4 字节非零的键 → 不是规范 BE 键（现实高度 < 2^32，BE 键前 4 字节
    ///   必为 0）→ 按 legacy LE 键处理：就地把 `LE(h)→hash` 转写为
    ///   `BE(h)→hash`（该高度已有 BE 键时 BE 胜出，LE 键直接删除）。
    ///   唯一自碰撞是 `LE(0) == BE(0)`（全零），无需特判；
    /// - 值长度 ≠ 32 / 同一高度多个 hash / 条目指向缺失或高度不符的 block /
    ///   索引条目数 ≠ blocks 数 → 数据不可信：**整体重建**——清空
    ///   height_index，从 `blocks` CF（唯一权威）按 `header.height` 全量
    ///   重索引。fail-closed：宁可重建也不返回可疑 tip。
    ///
    /// 干净库（无 legacy 痕迹且计数一致）零写入返回；启动成本为两个 CF 的
    /// 顺序迭代（devnet 规模可忽略）。
    fn migrate_height_index_le_to_be(&self) -> PokerL1Result<()> {
        let mut to_delete: Vec<Vec<u8>> = Vec::new();
        // 就地转写的 (height, hash)
        let mut converted: Vec<(BlockHeight, Hash)> = Vec::new();
        let mut canonical: Vec<(BlockHeight, Hash)> = Vec::new();
        // legacy LE 条目：(LE 解码高度, hash, 原始键)
        let mut legacy: Vec<(BlockHeight, Hash, [u8; 8])> = Vec::new();
        let mut needs_rebuild = false;
        let mut saw_trace = false;

        for item in self.db.iterator_cf(self.height_cf(), IteratorMode::Start) {
            let (key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            if key.len() != 8 {
                saw_trace = true;
                to_delete.push(key.to_vec());
                continue;
            }
            let bytes: [u8; 8] = key.as_ref().try_into().expect("length checked above");
            let value_ok = value.len() == 32;
            let mut hash = [0u8; 32];
            if value_ok {
                hash.copy_from_slice(&value);
            }
            if bytes[0..4] != [0u8, 0, 0, 0] {
                // 非 BE 形态：legacy LE 键（或不现实高度的 BE 键，随 legacy 一并转写/淘汰）
                saw_trace = true;
                if value_ok {
                    legacy.push((u64::from_le_bytes(bytes), hash, bytes));
                } else {
                    needs_rebuild = true;
                }
            } else if value_ok {
                canonical.push((u64::from_be_bytes(bytes), hash));
            } else {
                saw_trace = true;
                needs_rebuild = true;
            }
        }

        canonical.sort_unstable_by_key(|(height, _)| *height);
        if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            needs_rebuild = true;
        }

        // legacy LE 键就地转写：该高度无 BE 键时转写为 BE，且必须指向
        // 真实存在、高度一致的 block；任何失联即整体重建。
        if !needs_rebuild {
            for (height, hash, raw_key) in legacy {
                if canonical.binary_search_by_key(&height, |(h, _)| *h).is_ok() {
                    // 同高度已有 BE 键：新代码的冲突检查只看 BE 键，BE 胜出
                    to_delete.push(raw_key.to_vec());
                    continue;
                }
                match self.db.get_cf(self.blocks_cf(), hash) {
                    Ok(Some(block_bytes)) => {
                        let block: Block = borsh::from_slice(&block_bytes)?;
                        if block.header.height != height {
                            needs_rebuild = true;
                            break;
                        }
                        to_delete.push(raw_key.to_vec());
                        converted.push((height, hash));
                    }
                    Ok(None) => {
                        needs_rebuild = true;
                        break;
                    }
                    Err(e) => return Err(PokerL1Error::Rocksdb(e.to_string())),
                }
            }
        }

        // 干净库快路径：无任何痕迹且索引条目数 == blocks 数
        if !needs_rebuild && !saw_trace {
            if canonical.len() == self.len()? {
                return Ok(());
            }
            needs_rebuild = true; // 无 legacy 痕迹但计数失配（如索引被外部清空）
        }

        // 有迁移痕迹：对保留的 BE 条目做一次性深度校验（悬空引用检测）
        if !needs_rebuild {
            for (_, hash) in &canonical {
                match self.db.get_cf(self.blocks_cf(), hash) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        needs_rebuild = true;
                        break;
                    }
                    Err(e) => return Err(PokerL1Error::Rocksdb(e.to_string())),
                }
            }
            if !needs_rebuild && canonical.len() + converted.len() != self.len()? {
                needs_rebuild = true; // 存在无索引对应的 block
            }
        }

        let mut batch = WriteBatch::default();
        if needs_rebuild {
            tracing::warn!(
                "height_index 检测到不可信状态：清空并从 blocks CF 全量重建（P2 审计修复 2026-09：LE→BE 迁移）"
            );
            let mut wipe_keys: Vec<Vec<u8>> = Vec::new();
            for item in self.db.iterator_cf(self.height_cf(), IteratorMode::Start) {
                let (key, _) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
                wipe_keys.push(key.to_vec());
            }
            for key in &wipe_keys {
                batch.delete_cf(self.height_cf(), key);
            }
            for item in self.db.iterator_cf(self.blocks_cf(), IteratorMode::Start) {
                let (key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
                if key.len() != 32 {
                    tracing::warn!(
                        "blocks CF 存在 {} 字节的非法键，重建索引时跳过",
                        key.len()
                    );
                    continue;
                }
                // fail-closed：坏块直接报错，宁可启动失败也不带病运行
                let block: Block = borsh::from_slice(&value)?;
                batch.put_cf(self.height_cf(), block.header.height.to_be_bytes(), key.as_ref());
            }
        } else {
            for key in &to_delete {
                batch.delete_cf(self.height_cf(), key);
            }
            for (height, hash) in &converted {
                batch.put_cf(self.height_cf(), height.to_be_bytes(), hash);
            }
            if !batch.is_empty() {
                tracing::warn!(
                    deleted = to_delete.len(),
                    converted = converted.len(),
                    "height_index LE→BE 迁移完成（P2 审计修复 2026-09）"
                );
            }
        }
        if !batch.is_empty() {
            self.db
                .write(batch)
                .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
        }
        Ok(())
    }

    /// 写入区块。原子地写入 `blocks` 与 `height_index`（WriteBatch）。
    ///
    /// 返回该区块的 `block_hash`。重复写入同一 hash 是幂等的（覆盖写）。
    ///
    /// 同一 `height` 仅接受同一 block hash 的幂等重放；不同 hash 会被拒绝，不能覆盖
    /// canonical height index。
    pub fn put(&self, block: &Block, chain_id: ChainId) -> PokerL1Result<Hash> {
        let hash = block.block_hash(chain_id);
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // 幂等优化：已存在则直接返回
        if self.exists(&hash)? {
            return Ok(hash);
        }
        // height_index key 必须 big-endian：RocksDB 按**字节序**迭代/比较，
        // LE 编码下 256(00 01..) 字节序小于 255(FF 00..)——get_tip_height 的
        // End 迭代与 get_range 的字节序比较在高度 255→256 处全部断裂
        //（链卡 256、FORK ANCHOR WARNING、catch-up range 拿不到块的根因）。
        // BE 编码下数值序 = 字节序，全部迭代/比较自然正确。
        let height_key = block.header.height.to_be_bytes();
        if let Some(existing_hash) = self
            .db
            .get_cf(self.height_cf(), height_key)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
        {
            if existing_hash.as_ref() != hash {
                return Err(PokerL1Error::Other(format!(
                    "block height {} is already bound to a different hash",
                    block.header.height
                )));
            }
        }
        let value = borsh::to_vec(block)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.blocks_cf(), hash, &value);
        batch.put_cf(self.height_cf(), height_key, hash);
        self.db
            .write(batch)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;

        Ok(hash)
    }

    /// 按 `block_hash` 查询完整区块。不存在返回 `BlockNotFound`。
    pub fn get_by_hash(&self, hash: &Hash) -> PokerL1Result<Block> {
        let bytes = self
            .db
            .get_cf(self.blocks_cf(), hash)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .ok_or(PokerL1Error::BlockNotFound)?;
        let block: Block = borsh::from_slice(&bytes)?;
        Ok(block)
    }

    /// 按 `height` 查询完整区块（先查 `height_index` 得到 hash，再查 `blocks`）。
    /// 不存在返回 `BlockNotFound`。
    pub fn get_by_height(&self, height: BlockHeight) -> PokerL1Result<Block> {
        let hash_bytes = self
            .db
            .get_cf(self.height_cf(), height.to_be_bytes())
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .ok_or(PokerL1Error::BlockNotFound)?;
        if hash_bytes.len() != 32 {
            return Err(PokerL1Error::Serialization(format!(
                "height_index value 长度异常：{} != 32",
                hash_bytes.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);
        self.get_by_hash(&hash)
    }

    /// 判断指定 `block_hash` 是否已存在。
    pub fn exists(&self, hash: &Hash) -> PokerL1Result<bool> {
        // get_cf 返回 None 表示 key 不存在
        self.db
            .get_cf(self.blocks_cf(), hash)
            .map(|v| v.is_some())
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))
    }

    /// 裁剪旧区块 body（缺口 #4：State Pruning）。
    ///
    /// 删除 height < `prune_below` 的 block body（`blocks` CF）+ height index（`height_index` CF）。
    /// Archive 节点不调用此方法（保留全量历史）。
    ///
    /// 返回裁剪的区块数量。
    pub fn prune_old_blocks(&self, prune_below: BlockHeight) -> PokerL1Result<usize> {
        let mut count = 0usize;
        // 遍历 height_index，删除 height < prune_below 的条目 + 对应 block body。
        let iter = self.db.iterator_cf(self.height_cf(), IteratorMode::Start);
        let mut to_delete: Vec<([u8; 8], Hash)> = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            if key.len() == 8 && value.len() == 32 {
                let height = u64::from_be_bytes(key.as_ref().try_into().unwrap());
                if height < prune_below {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&value);
                    to_delete.push((key.as_ref().try_into().unwrap(), hash));
                }
            }
        }
        if !to_delete.is_empty() {
            let mut batch = WriteBatch::default();
            for (height_key, hash) in &to_delete {
                batch.delete_cf(self.blocks_cf(), hash);
                batch.delete_cf(self.height_cf(), height_key);
            }
            self.db
                .write(batch)
                .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            count = to_delete.len();
        }
        Ok(count)
    }

    /// 当前存储的区块数量（遍历 `blocks` CF 计数）。
    pub fn len(&self) -> PokerL1Result<usize> {
        let iter = self.db.iterator_cf(self.blocks_cf(), IteratorMode::Start);
        let mut count = 0usize;
        for item in iter {
            item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }

    /// 是否为空。
    pub fn is_empty(&self) -> PokerL1Result<bool> {
        Ok(self.len()? == 0)
    }

    /// 获取最高 block 的 height。空库返回 `None`。
    ///
    /// 实现：以 `IteratorMode::End` 反向遍历 `height_index`，取首条（最大 height）。
    pub fn get_tip_height(&self) -> PokerL1Result<Option<BlockHeight>> {
        let mut iter = self.db.iterator_cf(self.height_cf(), IteratorMode::End);
        match iter.next() {
            None => Ok(None),
            Some(Err(e)) => Err(PokerL1Error::Rocksdb(e.to_string())),
            Some(Ok((key, _))) => {
                if key.len() != 8 {
                    return Err(PokerL1Error::Serialization(format!(
                        "height_index key 长度异常：{} != 8",
                        key.len()
                    )));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&key);
                Ok(Some(u64::from_be_bytes(bytes)))
            }
        }
    }

    /// 获取最高 block 的 hash。空库返回 `None`。
    pub fn get_tip_hash(&self) -> PokerL1Result<Option<Hash>> {
        match self.get_tip_height()? {
            None => Ok(None),
            Some(height) => {
                let hash_bytes = self
                    .db
                    .get_cf(self.height_cf(), height.to_be_bytes())
                    .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
                    .ok_or(PokerL1Error::BlockNotFound)?;
                if hash_bytes.len() != 32 {
                    return Err(PokerL1Error::Serialization(format!(
                        "height_index value 长度异常：{} != 32",
                        hash_bytes.len()
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                Ok(Some(hash))
            }
        }
    }

    /// 按 height 范围批量查询区块（SubTask 38.4 — range scan）。
    ///
    /// 返回 `[start, end]` 闭区间内所有区块，按 height 升序排列。
    /// 若某 height 不存在则跳过（不报错）；空范围返回空 Vec。
    ///
    /// 实现：以 `IteratorMode::From(start_be, Forward)` 正向遍历 `height_index`，
    /// 直到 key > end_be 停止。
    pub fn get_range(&self, start: BlockHeight, end: BlockHeight) -> PokerL1Result<Vec<Block>> {
        if start > end {
            return Ok(Vec::new());
        }
        let start_key = start.to_be_bytes();
        let end_key = end.to_be_bytes();
        let iter = self.db.iterator_cf(
            self.height_cf(),
            IteratorMode::From(&start_key, Direction::Forward),
        );

        let mut blocks = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            // key 超过 end → 停止
            if key.as_ref() > end_key.as_ref() {
                break;
            }
            if value.len() != 32 {
                return Err(PokerL1Error::Serialization(format!(
                    "height_index value 长度异常：{} != 32",
                    value.len()
                )));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&value);
            blocks.push(self.get_by_hash(&hash)?);
        }
        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::consensus::DagCommitCertificate;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxLane};

    fn dummy_tagged_pubkey() -> crate::signature::TaggedPubkey {
        crate::signature::TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    fn dummy_commit_cert() -> DagCommitCertificate {
        DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![vec![0u8; 65]],
            signer_bitmap: vec![0xFF],
        }
    }

    fn dummy_tx(nonce: u64) -> crate::transaction::Transaction {
        crate::transaction::Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    fn dummy_header(height: BlockHeight, prev_hash: Hash) -> BlockHeader {
        BlockHeader {
            height,
            timestamp_ms: height * 1000,
            prev_hash,
            state_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(),
        }
    }

    fn dummy_block(height: BlockHeight, prev_hash: Hash) -> Block {
        Block::new(
            dummy_header(height, prev_hash),
            vec![dummy_tx(height)],
            vec![],
        )
    }

    #[test]
    fn open_creates_cfs() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        // CF 句柄必须存在
        assert!(store.db.cf_handle(BLOCKS_CF).is_some());
        assert!(store.db.cf_handle(HEIGHT_INDEX_CF).is_some());
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn put_and_get_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let block = dummy_block(1, [0u8; 32]);
        let hash = store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();

        let recovered = store.get_by_hash(&hash).unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn put_and_get_by_height() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let block = dummy_block(7, [0u8; 32]);
        store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();

        let recovered = store.get_by_height(7).unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn get_missing_hash_returns_block_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let err = store.get_by_hash(&[0xAAu8; 32]).unwrap_err();
        assert!(matches!(err, PokerL1Error::BlockNotFound));
    }

    #[test]
    fn get_missing_height_returns_block_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let err = store.get_by_height(42).unwrap_err();
        assert!(matches!(err, PokerL1Error::BlockNotFound));
    }

    #[test]
    fn exists_returns_true_after_put() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let block = dummy_block(1, [0u8; 32]);
        let hash = store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();

        assert!(store.exists(&hash).unwrap());
        assert!(!store.exists(&[0xBBu8; 32]).unwrap());
    }

    #[test]
    fn tip_tracking_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.get_tip_height().unwrap(), None);
        assert_eq!(store.get_tip_hash().unwrap(), None);
    }

    #[test]
    fn tip_tracking_after_chain_of_puts() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        let b0 = dummy_block(0, [0u8; 32]);
        let h0 = store.put(&b0, chain_id).unwrap();
        let b1 = dummy_block(1, h0);
        let h1 = store.put(&b1, chain_id).unwrap();
        let b2 = dummy_block(2, h1);
        let h2 = store.put(&b2, chain_id).unwrap();

        assert_eq!(store.get_tip_height().unwrap(), Some(2));
        assert_eq!(store.get_tip_hash().unwrap(), Some(h2));
        assert_eq!(store.len().unwrap(), 3);
    }

    #[test]
    fn len_counts_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.len().unwrap(), 0);
        assert!(store.is_empty().unwrap());

        store
            .put(&dummy_block(0, [0u8; 32]), crate::DEFAULT_CHAIN_ID)
            .unwrap();
        assert_eq!(store.len().unwrap(), 1);

        store
            .put(&dummy_block(1, [0u8; 32]), crate::DEFAULT_CHAIN_ID)
            .unwrap();
        store
            .put(&dummy_block(2, [0u8; 32]), crate::DEFAULT_CHAIN_ID)
            .unwrap();
        assert_eq!(store.len().unwrap(), 3);
    }

    #[test]
    fn put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let block = dummy_block(5, [0u8; 32]);

        let h1 = store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let h2 = store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.len().unwrap(), 1, "幂等写入不应增加计数");
    }

    #[test]
    fn put_rejects_a_different_block_at_an_existing_height() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let first = dummy_block(5, [0u8; 32]);
        let first_hash = store.put(&first, crate::DEFAULT_CHAIN_ID).unwrap();

        let mut conflicting = dummy_block(5, [0u8; 32]);
        conflicting.header.timestamp_ms += 1;
        let error = store
            .put(&conflicting, crate::DEFAULT_CHAIN_ID)
            .unwrap_err();
        assert!(error.to_string().contains("already bound"));
        assert_eq!(
            store
                .get_by_height(5)
                .unwrap()
                .block_hash(crate::DEFAULT_CHAIN_ID),
            first_hash
        );
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn put_chain_all_retrievable() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        let mut prev = [0u8; 32];
        let mut hashes = Vec::new();
        for h in 0..5u64 {
            let b = dummy_block(h, prev);
            let hash = store.put(&b, chain_id).unwrap();
            hashes.push(hash);
            prev = hash;
        }

        for (i, h) in hashes.iter().enumerate() {
            let b = store.get_by_hash(h).unwrap();
            assert_eq!(b.header.height, i as u64);
            let b2 = store.get_by_height(i as u64).unwrap();
            assert_eq!(b2.header.height, i as u64);
        }
    }

    #[test]
    fn open_inmemory_works() {
        let store = BlockStore::open_inmemory().unwrap();
        let block = dummy_block(1, [0u8; 32]);
        let hash = store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let recovered = store.get_by_hash(&hash).unwrap();
        assert_eq!(recovered, block);
    }

    #[test]
    fn persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let block = dummy_block(3, [0u8; 32]);
        let hash = {
            let store = BlockStore::open(dir.path()).unwrap();
            store.put(&block, chain_id).unwrap()
        };
        // 重新打开同一目录
        let store2 = BlockStore::open(dir.path()).unwrap();
        let recovered = store2.get_by_hash(&hash).unwrap();
        assert_eq!(recovered, block);
        assert_eq!(store2.get_by_height(3).unwrap(), block);
        assert_eq!(store2.len().unwrap(), 1);
        assert_eq!(store2.get_tip_height().unwrap(), Some(3));
    }

    #[test]
    fn large_batch_chain_persists() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        let mut prev = [0u8; 32];
        for h in 0..50u64 {
            let b = dummy_block(h, prev);
            let hash = store.put(&b, chain_id).unwrap();
            prev = hash;
        }
        assert_eq!(store.len().unwrap(), 50);
        assert_eq!(store.get_tip_height().unwrap(), Some(49));
    }

    #[test]
    fn get_range_returns_blocks_in_closed_interval() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        let mut prev = [0u8; 32];
        for h in 0..10u64 {
            let b = dummy_block(h, prev);
            let hash = store.put(&b, chain_id).unwrap();
            prev = hash;
        }
        // 查 [3, 7] 闭区间
        let range = store.get_range(3, 7).unwrap();
        assert_eq!(range.len(), 5);
        for (i, b) in range.iter().enumerate() {
            assert_eq!(b.header.height, 3 + i as u64);
        }
    }

    #[test]
    fn get_range_full_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        let mut prev = [0u8; 32];
        for h in 0..5u64 {
            let b = dummy_block(h, prev);
            let hash = store.put(&b, chain_id).unwrap();
            prev = hash;
        }
        let range = store.get_range(0, 4).unwrap();
        assert_eq!(range.len(), 5);
    }

    #[test]
    fn get_range_empty_when_start_gt_end() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let range = store.get_range(5, 3).unwrap();
        assert!(range.is_empty());
    }

    #[test]
    fn get_range_empty_store_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let range = store.get_range(0, 10).unwrap();
        assert!(range.is_empty());
    }

    #[test]
    fn get_range_skips_missing_heights() {
        // 只写入 height 0, 2, 4（跳过 1, 3），range [0, 4] 应返回 3 个
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;

        for h in [0u64, 2, 4] {
            let b = dummy_block(h, [0u8; 32]);
            store.put(&b, chain_id).unwrap();
        }
        let range = store.get_range(0, 4).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].header.height, 0);
        assert_eq!(range[1].header.height, 2);
        assert_eq!(range[2].header.height, 4);
    }

    #[test]
    fn prune_old_blocks_deletes_below_threshold() {
        // 缺口 #4：裁剪 height < threshold 的区块。
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        // 插入 height 0..4
        let mut prev = [0u8; 32];
        for h in 0u64..5 {
            let blk = dummy_block(h, prev);
            prev = blk.header.block_hash(chain_id);
            store.put(&blk, chain_id).unwrap();
        }
        assert_eq!(store.len().unwrap(), 5);
        // 裁剪 height < 3（删除 0,1,2）
        let pruned = store.prune_old_blocks(3).unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(store.len().unwrap(), 2, "应保留 height 3,4");
        // 验证保留的区块可查
        assert!(store.get_by_height(3).is_ok());
        assert!(store.get_by_height(4).is_ok());
        // 裁剪的区块不存在
        assert!(store.get_by_height(0).is_err());
        assert!(store.get_by_height(2).is_err());
    }

    #[test]
    fn prune_old_blocks_noop_when_all_above_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlockStore::open(dir.path()).unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let mut prev = [0u8; 32];
        // 插入 height 10,11,12
        for h in 10u64..13 {
            let blk = dummy_block(h, prev);
            prev = blk.header.block_hash(chain_id);
            store.put(&blk, chain_id).unwrap();
        }
        // threshold=10，全部 >= 10 → 不裁剪
        let pruned = store.prune_old_blocks(10).unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(store.len().unwrap(), 3);
    }

    // ============================================================
    // P2 审计修复 2026-09：height_index LE→BE 启动迁移
    // ============================================================

    /// 直接向 height_index 写原始键（绕过 put，模拟旧版本二进制写下的数据）。
    fn raw_put_height_entry(store: &BlockStore, key: &[u8], hash: [u8; 32]) {
        let mut batch = WriteBatch::default();
        batch.put_cf(store.height_cf(), key, hash);
        store.db.write(batch).unwrap();
    }

    /// 直接向 blocks CF 写块（不带索引），模拟旧版本二进制存下的块数据。
    fn raw_put_block(store: &BlockStore, block: &Block, chain_id: ChainId) -> Hash {
        let hash = block.block_hash(chain_id);
        let mut batch = WriteBatch::default();
        batch.put_cf(store.blocks_cf(), hash, borsh::to_vec(block).unwrap());
        store.db.write(batch).unwrap();
        hash
    }

    /// 场景一（就地转写）：BE 规范链 + legacy LE 键指向真实块（含 300 这类
    /// LE 首字节非零、字节序排在全部 BE 键之后的"隐形毒键"）+ 非法长度键。
    /// 重开后 LE 键被转写为 BE，非法键删除，tip/range 恢复正确。
    #[test]
    fn height_index_legacy_le_keys_migrated_in_place_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        // 规范链：height 0..=5（BE 键）
        let mut prev = [0u8; 32];
        {
            let store = BlockStore::open(dir.path()).unwrap();
            for h in 0..=5u64 {
                let b = dummy_block(h, prev);
                prev = b.header.block_hash(chain_id);
                store.put(&b, chain_id).unwrap();
            }
            // 旧版本节点写下的块 + LE 索引键：height 10 与 300
            let b10 = dummy_block(10, prev);
            let h10 = raw_put_block(&store, &b10, chain_id);
            let b300 = dummy_block(300, h10);
            let h300 = raw_put_block(&store, &b300, chain_id);
            raw_put_height_entry(&store, &10u64.to_le_bytes(), h10);
            raw_put_height_entry(&store, &300u64.to_le_bytes(), h300);
            // 非法长度键
            raw_put_height_entry(&store, &[0u8; 7], h10);
            // 注入后（未迁移）：tip 被 LE(300) 污染——LE(300) 首字节 0x2C 非零，
            // 字节序排在全部 BE 键之后，以 BE 解读为天文数字
            let poisoned_tip = store.get_tip_height().unwrap().unwrap();
            assert_eq!(
                poisoned_tip,
                u64::from_be_bytes(300u64.to_le_bytes()),
                "LE 键未迁移时以 BE 解读出错误 tip（复现审计缺陷）"
            );
        }
        // 重开 → 迁移：LE(10)/LE(300) 转写为 BE，非法键删除
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.get_tip_height().unwrap(), Some(300), "tip 必须恢复为真实最高高度");
        assert_eq!(store.len().unwrap(), 8);
        let range = store.get_range(0, 300).unwrap();
        assert_eq!(range.len(), 8, "range 覆盖全部块（0..5 + 10 + 300）");
        assert_eq!(range[6].header.height, 10);
        assert_eq!(range[7].header.height, 300);
        assert_eq!(store.get_by_height(10).unwrap().header.height, 10);
        assert_eq!(store.get_by_height(300).unwrap().header.height, 300);
    }

    /// 场景二（整体重建）：索引含悬空引用（BE/LE 形态键指向不存在的块）时，
    /// 迁移清空索引并从 blocks CF 全量重建，恢复一致视图。
    #[test]
    fn height_index_rebuilt_from_blocks_when_index_untrusted() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let mut prev = [0u8; 32];
        {
            let store = BlockStore::open(dir.path()).unwrap();
            for h in 0..=4u64 {
                let b = dummy_block(h, prev);
                prev = b.header.block_hash(chain_id);
                store.put(&b, chain_id).unwrap();
            }
            // 悬空 BE 键：高度 9 指向不存在的块
            raw_put_height_entry(&store, &9u64.to_be_bytes(), [0xEE; 32]);
            // 悬空 LE 键：高度 777 指向不存在的块
            raw_put_height_entry(&store, &777u64.to_le_bytes(), [0xDD; 32]);
        }
        // 重开 → 检测到不可信 → 从 blocks CF 重建
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.get_tip_height().unwrap(), Some(4), "重建后 tip 恢复");
        assert_eq!(store.len().unwrap(), 5);
        assert_eq!(store.get_range(0, 100).unwrap().len(), 5);
        assert!(store.get_by_hash(&[0xEE; 32]).is_err());
        assert!(store.get_by_hash(&[0xDD; 32]).is_err());
        for h in 0..=4u64 {
            assert_eq!(store.get_by_height(h).unwrap().header.height, h);
        }
    }

    /// 场景三（BE 胜出）：legacy LE 键与规范 BE 键绑定同一高度但不同 hash
    /// 时，保留 BE 键（新代码 put 的冲突检查只看 BE 键），LE 键删除。
    #[test]
    fn height_index_be_key_wins_over_conflicting_legacy_le_key() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let block = dummy_block(3, [0u8; 32]);
        let conflict = dummy_block(8, [0u8; 32]);
        let (real_hash, conflict_hash) = {
            let store = BlockStore::open(dir.path()).unwrap();
            let h3 = store.put(&block, chain_id).unwrap();
            let h8 = store.put(&conflict, chain_id).unwrap();
            // 旧链分叉残留：LE(3) 指向另一高度的块；BE(3) 已存在 → BE 胜出
            raw_put_height_entry(&store, &3u64.to_le_bytes(), h8);
            (h3, h8)
        };
        let store = BlockStore::open(dir.path()).unwrap();
        assert_eq!(store.get_tip_height().unwrap(), Some(8));
        assert_eq!(
            store.get_by_height(3).unwrap().block_hash(chain_id),
            real_hash,
            "BE 键胜出：高度 3 仍指向规范块"
        );
        assert_ne!(
            store.get_by_height(3).unwrap().block_hash(chain_id),
            conflict_hash
        );
        assert_eq!(store.len().unwrap(), 2);
        // height_index 中仅剩规范 BE 键（3 与 8），LE(3) 已删除
        let mut keys = Vec::new();
        for item in store.db.iterator_cf(store.height_cf(), IteratorMode::Start) {
            let (key, _) = item.unwrap();
            keys.push(key.to_vec());
        }
        keys.sort();
        assert_eq!(
            keys,
            vec![3u64.to_be_bytes().to_vec(), 8u64.to_be_bytes().to_vec()],
            "仅保留规范 BE 键"
        );
    }

    /// 场景四（幂等/零开销）：干净库重复重开不做任何写、行为不变。
    #[test]
    fn height_index_migration_idempotent_on_clean_store() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        {
            let store = BlockStore::open(dir.path()).unwrap();
            let mut prev = [0u8; 32];
            for h in 0..=3u64 {
                let b = dummy_block(h, prev);
                prev = b.header.block_hash(chain_id);
                store.put(&b, chain_id).unwrap();
            }
        }
        for _ in 0..3 {
            let store = BlockStore::open(dir.path()).unwrap();
            assert_eq!(store.get_tip_height().unwrap(), Some(3));
            assert_eq!(store.len().unwrap(), 4);
            assert_eq!(store.get_range(0, 3).unwrap().len(), 4);
        }
    }
}
