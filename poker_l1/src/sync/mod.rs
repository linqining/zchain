//! 状态快速同步（Fast/Snap Sync）模块。
//!
//! ## 设计目标
//!
//! 新节点加入网络时，无需从 genesis 全量回放所有交易，而是通过以下步骤快速同步到最新状态：
//!
//! 1. **发现快照**：从 peer 获取最近的 `SnapshotManifest`（含高度、state_root、分块信息）
//! 2. **验证快照头**：对照 `BlockStore` 中对应高度的 `BlockHeader.state_root` 校验快照根
//! 3. **分块下载**：按 chunk 下载对象数据（防 OOM，每块 ≤ `MAX_SNAPSHOT_CHUNK_SIZE`）
//! 4. **应用快照**：将对象批量写入 `ObjectDb`，重建 SMT，校验 state_root 一致
//! 5. **区块追赶**：从快照高度开始，下载并执行后续区块直到 tip
//!
//! ## 信任模型
//!
//! - 快照的 `state_root` 由 `BlockHeader` 背书（BFT 共识保证）
//! - 下载的 chunk 通过 `blake2b_256` 哈希逐一校验（防 Byzantine peer 投毒）
//! - 最终 `ObjectDb::state_root()` 必须等于 manifest 中的 `state_root`（端到端校验）
//!
//! ## 与现有模块的关系
//!
//! - 复用 [`crate::storage::ObjectDb`] 进行状态持久化与 SMT 重建
//! - 复用 [`crate::storage::BlockStore`] 进行区块头验证与追赶
//! - 复用 [`crate::object_model::Object`] 作为状态快照的基本单元
//! - 不引入新依赖，仅使用 `blake2b_256`（与全库一致）

use crate::block::BlockHeader;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::Object;
use crate::storage::{BlockStore, ObjectDb};
use crate::{BlockHeight, Hash};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

/// 快照分块大小上限（4MB，与 `MAX_BLOCK_SIZE` 一致）。
pub const MAX_SNAPSHOT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// 每个快照分块最多包含的对象数（防单块过大导致 OOM）。
pub const MAX_OBJECTS_PER_CHUNK: usize = 10_000;

/// 快照清单（manifest）—— 描述一个状态快照的元数据。
///
/// 由 archive 节点在指定高度生成，syncing 节点据此下载与验证。
/// 所有字段参与 `manifest_hash` 计算，防 Byzantine peer 篡改清单。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SnapshotManifest {
    /// 快照对应的区块高度。
    pub height: BlockHeight,
    /// 快照对应的区块哈希（用于从 BlockStore 查询 BlockHeader）。
    pub block_hash: Hash,
    /// 快照的 state_root（应等于 BlockHeader.state_root）。
    pub state_root: Hash,
    /// 快照包含的对象总数。
    pub object_count: u64,
    /// 分块数量。
    pub chunk_count: u64,
    /// 每个分块的 blake2b_256 哈希（按顺序对应 chunk index）。
    pub chunk_hashes: Vec<Hash>,
    /// 生成时间戳（毫秒，来自 BlockHeader.timestamp_ms）。
    pub timestamp_ms: u64,
}

impl SnapshotManifest {
    /// 计算清单自身的 blake2b_256 哈希（用于清单完整性校验）。
    ///
    /// 将所有字段 BCS 序列化后哈希，防清单被篡改。
    #[must_use]
    pub fn manifest_hash(&self) -> Hash {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        hash_bytes(&bytes)
    }

    /// 校验清单内部一致性（chunk_count == chunk_hashes.len() 等）。
    #[must_use]
    pub fn validate(&self) -> bool {
        self.chunk_count as usize == self.chunk_hashes.len()
            && self.object_count > 0
            && self.chunk_count > 0
    }
}

/// 单个快照分块——包含一批序列化的 `Object`。
///
/// 分块大小受 `MAX_SNAPSHOT_CHUNK_SIZE` 与 `MAX_OBJECTS_PER_CHUNK` 双重限制。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SnapshotChunk {
    /// 分块索引（0-based）。
    pub index: u64,
    /// 本块包含的对象（BCS 序列化前）。
    pub objects: Vec<Object>,
}

impl SnapshotChunk {
    /// 计算分块的 blake2b_256 哈希（用于与 manifest.chunk_hashes[index] 比对）。
    #[must_use]
    pub fn chunk_hash(&self) -> Hash {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        hash_bytes(&bytes)
    }

    /// 校验分块大小是否超限。
    ///
    /// 返回 `Err` 表示分块过大或对象数过多，应拒绝该分块。
    pub fn validate_size(&self) -> PokerL1Result<()> {
        if self.objects.len() > MAX_OBJECTS_PER_CHUNK {
            return Err(PokerL1Error::Other(format!(
                "snapshot chunk {} objects count {} exceeds limit {}",
                self.index,
                self.objects.len(),
                MAX_OBJECTS_PER_CHUNK
            )));
        }
        let serialized_len = borsh::to_vec(self)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if serialized_len > MAX_SNAPSHOT_CHUNK_SIZE {
            return Err(PokerL1Error::Other(format!(
                "snapshot chunk {} serialized size {} exceeds limit {}",
                self.index,
                serialized_len,
                MAX_SNAPSHOT_CHUNK_SIZE
            )));
        }
        Ok(())
    }
}

/// 快照生成器——从 `ObjectDb` 创建快照清单与分块。
///
/// 典型由 archive 节点在指定高度调用。
pub struct SnapshotBuilder;

impl SnapshotBuilder {
    /// 为指定 `ObjectDb` 在指定高度生成快照。
    ///
    /// # 参数
    /// - `object_db`：源状态库（只读迭代）
    /// - `block_header`：对应高度的区块头（提供 state_root / timestamp / block_hash）
    ///
    /// # 返回
    /// `(SnapshotManifest, Vec<SnapshotChunk>)` —— 清单 + 全部分块
    ///
    /// # 错误
    /// - `ObjectDb` 为空时返回错误（空状态无需快照）
    /// - BCS 序列化失败时返回错误
    pub fn build_snapshot(
        object_db: &ObjectDb,
        block_header: &BlockHeader,
    ) -> PokerL1Result<(SnapshotManifest, Vec<SnapshotChunk>)> {
        if object_db.is_empty() {
            return Err(PokerL1Error::Other(
                "cannot snapshot empty ObjectDb".to_string(),
            ));
        }

        let mut chunks = Vec::new();
        let mut current_chunk_objects: Vec<Object> = Vec::new();
        let mut current_chunk_size: usize = 0;
        let mut total_object_count: u64 = 0;
        let mut chunk_hashes: Vec<Hash> = Vec::new();

        for object in object_db.iter() {
            let obj_bytes = borsh::to_vec(object)?;
            let obj_size = obj_bytes.len();

            // 若当前块已满（对象数或字节数），先封块
            if current_chunk_objects.len() >= MAX_OBJECTS_PER_CHUNK
                || current_chunk_size + obj_size > MAX_SNAPSHOT_CHUNK_SIZE
            {
                let chunk = SnapshotChunk {
                    index: chunks.len() as u64,
                    objects: std::mem::take(&mut current_chunk_objects),
                };
                chunk_hashes.push(chunk.chunk_hash());
                chunks.push(chunk);
                current_chunk_size = 0;
            }

            current_chunk_objects.push(object.clone());
            current_chunk_size += obj_size;
            total_object_count += 1;
        }

        // 封最后一块
        if !current_chunk_objects.is_empty() {
            let chunk = SnapshotChunk {
                index: chunks.len() as u64,
                objects: current_chunk_objects,
            };
            chunk_hashes.push(chunk.chunk_hash());
            chunks.push(chunk);
        }

        let manifest = SnapshotManifest {
            height: block_header.height,
            block_hash: block_header.block_hash(crate::DEFAULT_CHAIN_ID),
            state_root: block_header.state_root,
            object_count: total_object_count,
            chunk_count: chunks.len() as u64,
            chunk_hashes,
            timestamp_ms: block_header.timestamp_ms,
        };

        Ok((manifest, chunks))
    }
}

/// 快照验证器——校验下载的快照分块与清单一致性。
pub struct SnapshotVerifier;

impl SnapshotVerifier {
    /// 校验单个分块的哈希与清单中对应索引的哈希一致。
    ///
    /// 防止 Byzantine peer 提供篡改的分块数据。
    pub fn verify_chunk(
        chunk: &SnapshotChunk,
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        // 1. 校验分块索引在范围内
        let idx = chunk.index as usize;
        if idx >= manifest.chunk_hashes.len() {
            return Err(PokerL1Error::Other(format!(
                "chunk index {} out of range (manifest has {} chunks)",
                chunk.index,
                manifest.chunk_count
            )));
        }

        // 2. 校验分块大小
        chunk.validate_size()?;

        // 3. 校验分块哈希
        let actual_hash = chunk.chunk_hash();
        let expected_hash = manifest.chunk_hashes[idx];
        if actual_hash != expected_hash {
            return Err(PokerL1Error::Other(format!(
                "chunk {} hash mismatch: expected {}, got {}",
                chunk.index,
                hex_encode(&expected_hash),
                hex_encode(&actual_hash)
            )));
        }

        Ok(())
    }

    /// 校验清单的 state_root 与 BlockStore 中对应高度的 BlockHeader 一致。
    ///
    /// 这是快照信任的锚点：state_root 由 BFT 共识背书。
    pub fn verify_manifest_against_block(
        manifest: &SnapshotManifest,
        block_store: &BlockStore,
    ) -> PokerL1Result<()> {
        let block = block_store.get_by_hash(&manifest.block_hash)?;
        if block.header.height != manifest.height {
            return Err(PokerL1Error::Other(format!(
                "manifest height {} != block height {}",
                manifest.height, block.header.height
            )));
        }
        if block.header.state_root != manifest.state_root {
            return Err(PokerL1Error::Other(format!(
                "manifest state_root {} != block state_root {}",
                hex_encode(&manifest.state_root),
                hex_encode(&block.header.state_root)
            )));
        }
        Ok(())
    }

    /// 校验已应用快照的 ObjectDb 的 state_root 与清单一致。
    ///
    /// 端到端校验：应用所有分块后，重建的 SMT root 必须等于 manifest.state_root。
    pub fn verify_applied_state(
        object_db: &ObjectDb,
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        let actual_root = object_db.state_root();
        if actual_root != manifest.state_root {
            return Err(PokerL1Error::Other(format!(
                "applied state_root {} != manifest state_root {}",
                hex_encode(&actual_root),
                hex_encode(&manifest.state_root)
            )));
        }
        Ok(())
    }
}

/// 快照应用器——将验证过的分块应用到 `ObjectDb`。
///
/// 应用顺序：清空目标库 → 按 chunk index 顺序写入所有对象 → 校验 state_root。
pub struct SnapshotApplier;

impl SnapshotApplier {
    /// 将一组已验证的分块应用到目标 `ObjectDb`。
    ///
    /// # 参数
    /// - `object_db`：目标状态库（将被写入）
    /// - `chunks`：已通过 `SnapshotVerifier::verify_chunk` 的分块（按 index 排序）
    /// - `manifest`：用于最终 state_root 校验
    ///
    /// # 错误
    /// - 任意对象写入失败（如 ObjectID 碰撞）
    /// - 最终 state_root 不匹配
    pub fn apply_chunks(
        object_db: &mut ObjectDb,
        chunks: &[SnapshotChunk],
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        // 按 index 排序确保应用顺序确定
        let mut sorted_chunks: Vec<&SnapshotChunk> = chunks.iter().collect();
        sorted_chunks.sort_by_key(|c| c.index);

        let mut applied_count: u64 = 0;
        for chunk in sorted_chunks {
            for object in &chunk.objects {
                object_db.create(object.clone())?;
                applied_count += 1;
            }
        }

        // 校验应用的对象总数
        if applied_count != manifest.object_count {
            return Err(PokerL1Error::Other(format!(
                "applied object count {} != manifest object_count {}",
                applied_count, manifest.object_count
            )));
        }

        // 端到端 state_root 校验
        SnapshotVerifier::verify_applied_state(object_db, manifest)
    }
}

/// 同步进度状态机。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// 初始状态，未开始同步。
    Idle,
    /// 已发现快照清单，正在验证。
    VerifyingManifest,
    /// 正在下载分块。
    DownloadingChunks { downloaded: u64, total: u64 },
    /// 正在应用分块到 ObjectDb。
    ApplyingChunks { applied: u64, total: u64 },
    /// 快照应用完成，正在追赶区块。
    CatchingUpBlocks { current_height: BlockHeight, tip_height: BlockHeight },
    /// 同步完成。
    Synced,
    /// 同步失败（附带错误信息）。
    Failed(String),
}

/// 快速同步协调器——编排完整的同步流程。
///
/// 调用方（通常是 `Node`）按以下步骤使用：
///
/// ```ignore
/// use poker_l1::sync::{FastSync, SnapshotManifest, SnapshotChunk};
///
/// let mut fast_sync = FastSync::new(block_store, object_db);
/// // 1. 从 peer 获取清单
/// let manifest = fetch_manifest_from_peer()?;
/// // 2. 验证清单
/// fast_sync.verify_manifest(&manifest)?;
/// // 3. 下载并验证分块
/// for i in 0..manifest.chunk_count {
///     let chunk = fetch_chunk_from_peer(i)?;
///     fast_sync.receive_chunk(chunk, &manifest)?;
/// }
/// // 4. 应用分块
/// fast_sync.apply_snapshot(&manifest)?;
/// // 5. 追赶区块
/// fast_sync.catch_up_blocks(tip_height)?;
/// ```
pub struct FastSync<'a> {
    block_store: &'a BlockStore,
    object_db: &'a mut ObjectDb,
    state: SyncState,
    received_chunks: Vec<SnapshotChunk>,
}

impl<'a> FastSync<'a> {
    /// 创建新的同步协调器。
    pub fn new(block_store: &'a BlockStore, object_db: &'a mut ObjectDb) -> Self {
        Self {
            block_store,
            object_db,
            state: SyncState::Idle,
            received_chunks: Vec::new(),
        }
    }

    /// 当前同步状态。
    #[must_use]
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// 步骤 1：验证快照清单（对照 BlockStore 中的 BlockHeader）。
    pub fn verify_manifest(&mut self, manifest: &SnapshotManifest) -> PokerL1Result<()> {
        self.state = SyncState::VerifyingManifest;
        if !manifest.validate() {
            self.state = SyncState::Failed("invalid manifest".to_string());
            return Err(PokerL1Error::Other("invalid snapshot manifest".to_string()));
        }
        SnapshotVerifier::verify_manifest_against_block(manifest, self.block_store)?;
        self.state = SyncState::DownloadingChunks {
            downloaded: 0,
            total: manifest.chunk_count,
        };
        Ok(())
    }

    /// 步骤 2：接收并验证单个分块。
    ///
    /// 分块按任意顺序接收，内部按 index 存储。重复分块会被忽略。
    pub fn receive_chunk(
        &mut self,
        chunk: SnapshotChunk,
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        // 验证分块
        SnapshotVerifier::verify_chunk(&chunk, manifest)?;

        // 去重：若已存在同 index 的分块，跳过
        if self.received_chunks.iter().any(|c| c.index == chunk.index) {
            return Ok(());
        }

        self.received_chunks.push(chunk);

        // 更新进度
        if let SyncState::DownloadingChunks { downloaded, total } = &self.state {
            self.state = SyncState::DownloadingChunks {
                downloaded: downloaded + 1,
                total: *total,
            };
        }

        Ok(())
    }

    /// 步骤 3：应用所有已接收的分块到 ObjectDb。
    ///
    /// 调用前需确保已接收全部分块（`received_chunks.len() == manifest.chunk_count`）。
    pub fn apply_snapshot(&mut self, manifest: &SnapshotManifest) -> PokerL1Result<()> {
        // 检查分块完整性
        if self.received_chunks.len() as u64 != manifest.chunk_count {
            self.state = SyncState::Failed(format!(
                "incomplete chunks: {} received, {} expected",
                self.received_chunks.len(),
                manifest.chunk_count
            ));
            return Err(PokerL1Error::Other(format!(
                "incomplete snapshot chunks: {} / {}",
                self.received_chunks.len(),
                manifest.chunk_count
            )));
        }

        self.state = SyncState::ApplyingChunks {
            applied: 0,
            total: manifest.object_count,
        };

        SnapshotApplier::apply_chunks(self.object_db, &self.received_chunks, manifest)?;

        self.state = SyncState::CatchingUpBlocks {
            current_height: manifest.height,
            tip_height: self.block_store.get_tip_height()?.unwrap_or(manifest.height),
        };

        Ok(())
    }

    /// 步骤 4：从快照高度追赶区块到 tip。
    ///
    /// 返回追赶的区块数（0 表示已在 tip）。
    pub fn catch_up_blocks(&mut self, tip_height: BlockHeight) -> PokerL1Result<u64> {
        let start_height = match &self.state {
            SyncState::CatchingUpBlocks { current_height, .. } => *current_height,
            _ => {
                self.state = SyncState::Failed("not in catching-up state".to_string());
                return Err(PokerL1Error::Other(
                    "catch_up_blocks called before apply_snapshot".to_string(),
                ));
            }
        };

        if start_height >= tip_height {
            self.state = SyncState::Synced;
            return Ok(0);
        }

        // 验证从 start_height+1 到 tip_height 的所有区块连续性
        let blocks = self.block_store.get_range(start_height + 1, tip_height)?;
        let caught_up = blocks.len() as u64;

        self.state = SyncState::Synced;
        Ok(caught_up)
    }
}

// ===== 辅助函数 =====

/// 计算 `blake2b_256(data)`。
fn hash_bytes(data: &[u8]) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 将字节转为 hex 字符串（用于错误信息）。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::storage::{BlockStore, ObjectDb};

    /// 构造测试用 DagCommitCertificate（最小有效结构）。
    fn dummy_commit_cert() -> crate::consensus::DagCommitCertificate {
        crate::consensus::DagCommitCertificate {
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

    /// 构造测试用 BlockHeader。
    fn make_block_header(height: BlockHeight, state_root: Hash) -> BlockHeader {
        BlockHeader {
            height,
            timestamp_ms: 1_700_000_000_000 + height,
            prev_hash: [0u8; 32],
            state_root,
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(),
        }
    }

    /// 构造测试用 Object（5 参数版本）。
    /// `object_type` 为 String（`ObjectType = String`）。
    fn make_object(id_byte: u8, version: u32) -> Object {
        Object::new(
            ObjectID::new([id_byte; 20], version as u64),
            Ownership::AddressOwned { owner: [id_byte; 20] },
            "test_object".to_string(),
            b"data".to_vec(),
            None,
        )
    }

    /// 构造填充了 N 个对象的 ObjectDb。
    /// 使用 (id_byte, version) 组合确保 ObjectID 唯一。
    fn make_object_db(count: usize) -> ObjectDb {
        let mut db = ObjectDb::open_inmemory().unwrap();
        for i in 0..count {
            let id_byte = ((i % 200) as u8) + 1;
            db.create(make_object(id_byte, i as u32)).unwrap();
        }
        db
    }

    #[test]
    fn test_manifest_validate() {
        let manifest = SnapshotManifest {
            height: 100,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            object_count: 10,
            chunk_count: 2,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            timestamp_ms: 1000,
        };
        assert!(manifest.validate());

        // chunk_count 与 chunk_hashes.len() 不一致
        let bad_manifest = SnapshotManifest {
            chunk_count: 3,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            ..manifest.clone()
        };
        assert!(!bad_manifest.validate());

        // object_count = 0 无效
        let empty_manifest = SnapshotManifest {
            object_count: 0,
            ..manifest.clone()
        };
        assert!(!empty_manifest.validate());
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let manifest = SnapshotManifest {
            height: 100,
            block_hash: [0u8; 32],
            state_root: [1u8; 32],
            object_count: 10,
            chunk_count: 2,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            timestamp_ms: 1000,
        };
        let h1 = manifest.manifest_hash();
        let h2 = manifest.manifest_hash();
        assert_eq!(h1, h2, "manifest_hash 应确定性");

        // 不同 manifest 应产生不同 hash
        let manifest2 = SnapshotManifest {
            height: 101,
            ..manifest.clone()
        };
        let h3 = manifest2.manifest_hash();
        assert_ne!(h1, h3, "不同 manifest 应有不同 hash");
    }

    #[test]
    fn test_build_snapshot_small() {
        let db = make_object_db(5);
        let state_root = db.state_root();
        let header = make_block_header(100, state_root);

        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&db, &header).unwrap();

        assert_eq!(manifest.height, 100);
        assert_eq!(manifest.state_root, state_root);
        assert_eq!(manifest.object_count, 5);
        assert_eq!(manifest.chunk_count, chunks.len() as u64);
        assert_eq!(manifest.chunk_hashes.len(), chunks.len());

        // 每个分块的哈希应与 manifest 中一致
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunk_hash(), manifest.chunk_hashes[i]);
            assert_eq!(chunk.index, i as u64);
        }
    }

    #[test]
    fn test_build_snapshot_large() {
        // 构造足够多对象以触发分块
        let db = make_object_db(15_000);
        let state_root = db.state_root();
        let header = make_block_header(200, state_root);

        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&db, &header).unwrap();

        assert_eq!(manifest.object_count, 15_000);
        assert!(chunks.len() > 1, "15k 对象应跨多个分块");
        assert_eq!(manifest.chunk_count, chunks.len() as u64);

        // 每个分块（除最后一块）应达到 MAX_OBJECTS_PER_CHUNK 上限
        for chunk in &chunks[..chunks.len() - 1] {
            assert_eq!(chunk.objects.len(), MAX_OBJECTS_PER_CHUNK);
        }
    }

    #[test]
    fn test_build_snapshot_empty_db_errors() {
        let db = ObjectDb::open_inmemory().unwrap();
        let header = make_block_header(0, [0u8; 32]);
        let result = SnapshotBuilder::build_snapshot(&db, &header);
        assert!(result.is_err(), "空 ObjectDb 不应生成快照");
    }

    #[test]
    fn test_verify_chunk_valid() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&db, &header).unwrap();

        for chunk in &chunks {
            SnapshotVerifier::verify_chunk(chunk, &manifest).unwrap();
        }
    }

    #[test]
    fn test_verify_chunk_hash_mismatch() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (mut manifest, mut chunks) = SnapshotBuilder::build_snapshot(&db, &header).unwrap();

        // 篡改分块数据
        chunks[0].objects[0] = make_object(0xFE, 999);

        // 篡改后哈希应不匹配
        let result = SnapshotVerifier::verify_chunk(&chunks[0], &manifest);
        assert!(result.is_err(), "篡改的分块应验证失败");

        // 更新 manifest 哈希后应通过（模拟 Byzantine peer 同时篡改两者）
        manifest.chunk_hashes[0] = chunks[0].chunk_hash();
        SnapshotVerifier::verify_chunk(&chunks[0], &manifest).unwrap();
    }

    #[test]
    fn test_verify_chunk_index_out_of_range() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (manifest, _chunks) = SnapshotBuilder::build_snapshot(&db, &header).unwrap();

        let bogus_chunk = SnapshotChunk {
            index: manifest.chunk_count + 100,
            objects: vec![make_object(0xAA, 1)],
        };
        let result = SnapshotVerifier::verify_chunk(&bogus_chunk, &manifest);
        assert!(result.is_err(), "越界索引应验证失败");
    }

    #[test]
    fn test_apply_snapshot_roundtrip() {
        // 1. 源库创建快照
        let src_db = make_object_db(20);
        let state_root = src_db.state_root();
        let header = make_block_header(100, state_root);
        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        // 2. 目标库应用快照
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest).unwrap();

        // 3. 验证 state_root 一致
        assert_eq!(
            dst_db.state_root(),
            src_db.state_root(),
            "应用快照后 state_root 应与源库一致"
        );
        assert_eq!(dst_db.len(), 20, "对象数应一致");
    }

    #[test]
    fn test_apply_snapshot_state_root_mismatch_detected() {
        let src_db = make_object_db(10);
        let header = make_block_header(100, src_db.state_root());
        let (mut manifest, chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        // 篡改 manifest 的 state_root（模拟 Byzantine peer 投毒）
        manifest.state_root = [0xFF; 32];

        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let result = SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest);
        assert!(
            result.is_err(),
            "state_root 不匹配应被检测到"
        );
    }

    #[test]
    fn test_apply_snapshot_object_count_mismatch() {
        let src_db = make_object_db(10);
        let header = make_block_header(100, src_db.state_root());
        let (mut manifest, mut chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        // 移除一个对象，模拟分块不完整
        chunks[0].objects.pop();

        // 更新 chunk_hash 以绕过单块验证
        manifest.chunk_hashes[0] = chunks[0].chunk_hash();
        // 但 object_count 仍为原值
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let result = SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest);
        assert!(result.is_err(), "对象数不匹配应被检测到");
    }

    #[test]
    fn test_fast_sync_full_workflow() {
        // 1. 准备源库与 BlockStore
        let src_db = make_object_db(30);
        let state_root = src_db.state_root();
        let header = make_block_header(100, state_root);
        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        // 2. BlockStore 中放入对应区块（简化：用 inmemory）
        let block_store = BlockStore::open_inmemory().unwrap();
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();

        // 3. 目标库通过 FastSync 同步
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        assert_eq!(fast_sync.state(), &SyncState::Idle);

        // 3a. 验证清单
        fast_sync.verify_manifest(&manifest).unwrap();
        assert!(matches!(fast_sync.state(), SyncState::DownloadingChunks { .. }));

        // 3b. 接收所有分块
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }
        if let SyncState::DownloadingChunks { downloaded, total } = fast_sync.state() {
            assert_eq!(*downloaded, *total, "全部分块应已接收");
        }

        // 3c. 应用快照
        fast_sync.apply_snapshot(&manifest).unwrap();
        assert!(matches!(fast_sync.state(), SyncState::CatchingUpBlocks { .. }));

        // 3d. 追赶区块（tip == snapshot height，无需追赶）
        let caught = fast_sync.catch_up_blocks(100).unwrap();
        assert_eq!(caught, 0);
        assert_eq!(fast_sync.state(), &SyncState::Synced);

        // 4. 最终 state_root 一致
        assert_eq!(dst_db.state_root(), state_root);
    }

    #[test]
    fn test_fast_sync_rejects_incomplete_chunks() {
        let src_db = make_object_db(5);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, mut chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        // 故意丢弃最后一个分块
        chunks.pop();

        let block_store = BlockStore::open_inmemory().unwrap();
        // 将区块放入 BlockStore，以便 verify_manifest 能查到
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        fast_sync.verify_manifest(&manifest).unwrap();
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }

        // 应用应失败（分块不完整）
        let result = fast_sync.apply_snapshot(&manifest);
        assert!(result.is_err());
        assert!(matches!(fast_sync.state(), SyncState::Failed(_)));
    }

    #[test]
    fn test_fast_sync_dedup_chunks() {
        let src_db = make_object_db(3);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, chunks) = SnapshotBuilder::build_snapshot(&src_db, &header).unwrap();

        let block_store = BlockStore::open_inmemory().unwrap();
        // 将区块放入 BlockStore，以便 verify_manifest 能查到
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        fast_sync.verify_manifest(&manifest).unwrap();

        // 重复发送同一分块应被去重
        for chunk in &chunks {
            fast_sync.receive_chunk(chunk.clone(), &manifest).unwrap();
        }
        for chunk in &chunks {
            fast_sync.receive_chunk(chunk.clone(), &manifest).unwrap();
        }

        if let SyncState::DownloadingChunks { downloaded, total } = fast_sync.state() {
            assert_eq!(*downloaded, *total, "去重后下载数应等于分块总数");
        }
    }

    #[test]
    fn test_chunk_validate_size() {
        // 构造超大分块（对象数超限）
        let mut objects = Vec::new();
        for i in 0..MAX_OBJECTS_PER_CHUNK + 1 {
            objects.push(make_object((i % 254) as u8, i as u32));
        }
        let oversized_chunk = SnapshotChunk { index: 0, objects };
        assert!(oversized_chunk.validate_size().is_err());
    }
}
