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
//! - `height_index`：key = `height_le`（8 字节 LE） → value = `block_hash`（32 字节）

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, DB, Direction, IteratorMode, Options, WriteBatch};

use crate::block::Block;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::{ChainId, BlockHeight, Hash};

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

        Ok(Self { db: Arc::new(db) })
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

    /// 写入区块。原子地写入 `blocks` 与 `height_index`（WriteBatch）。
    ///
    /// 返回该区块的 `block_hash`。重复写入同一 hash 是幂等的（覆盖写）。
    ///
    /// 注意：调用方负责保证同一 `height` 不会被不同 block 覆盖（链式增长约束）。
    pub fn put(&self, block: &Block, chain_id: ChainId) -> PokerL1Result<Hash> {
        let hash = block.block_hash(chain_id);
        // 幂等优化：已存在则直接返回
        if self.exists(&hash)? {
            return Ok(hash);
        }
        let height_le = block.header.height.to_le_bytes();
        let value = bcs::to_bytes(block)?;

        let mut batch = WriteBatch::default();
        batch.put_cf(self.blocks_cf(), hash, &value);
        batch.put_cf(self.height_cf(), height_le, hash);
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
        let block: Block = bcs::from_bytes(&bytes)?;
        Ok(block)
    }

    /// 按 `height` 查询完整区块（先查 `height_index` 得到 hash，再查 `blocks`）。
    /// 不存在返回 `BlockNotFound`。
    pub fn get_by_height(&self, height: BlockHeight) -> PokerL1Result<Block> {
        let hash_bytes = self
            .db
            .get_cf(self.height_cf(), height.to_le_bytes())
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
                Ok(Some(u64::from_le_bytes(bytes)))
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
                    .get_cf(self.height_cf(), height.to_le_bytes())
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
    /// 实现：以 `IteratorMode::From(start_le, Forward)` 正向遍历 `height_index`，
    /// 直到 key > end_le 停止。
    pub fn get_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<Block>> {
        if start > end {
            return Ok(Vec::new());
        }
        let start_key = start.to_le_bytes();
        let end_key = end.to_le_bytes();
        let iter = self
            .db
            .iterator_cf(self.height_cf(), IteratorMode::From(&start_key, Direction::Forward));

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
    use crate::signature::tagged_pubkey::{encode_tag, SignatureScheme};
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
        Block::new(dummy_header(height, prev_hash), vec![dummy_tx(height)], vec![])
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

        store.put(&dummy_block(0, [0u8; 32]), crate::DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(store.len().unwrap(), 1);

        store.put(&dummy_block(1, [0u8; 32]), crate::DEFAULT_CHAIN_ID).unwrap();
        store.put(&dummy_block(2, [0u8; 32]), crate::DEFAULT_CHAIN_ID).unwrap();
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
}
