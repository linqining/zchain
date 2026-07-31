//! BridgeRegistry nonce 持久化（缺口 #9 / Q24：防重启重放铸币的安全刚需）。
//!
//! [`crate::bridge::BridgeRegistry`] 的 `consumed_nonces` / `consumed_burn_nonces`
//! 若仅存内存，节点重启后 nonce 状态丢失 → 同一笔 deposit 可被再次 `bridge_verify`
//! 通过并重复铸币。本模块把这两个 nonce 集合持久化到 RocksDB，重启时全量加载回内存。
//!
//! 设计与 [`crate::account::AccountStore`]（缺口 #8）一致：内存 `BridgeRegistry` 为
//! 权威态 + 同步写 DB；nonce 是 16 字节 key（chain_id_le(8) || nonce_le(8)），
//! value 为空（仅需 key 存在性判断）。

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rocksdb::{ColumnFamilyDescriptor, DB, Options};

use crate::bridge::BridgeRegistry;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::ChainId;

/// `deposit_nonces` 列族名（bridge deposit 防重放）。
const DEPOSIT_NONCES_CF: &str = "bridge_deposit_nonces";
/// `burn_nonces` 列族名（bridge burn 防重放）。
const BURN_NONCES_CF: &str = "bridge_burn_nonces";

/// 把 `(chain_id, nonce)` 编码为 16 字节 key（little-endian 拼接）。
fn nonce_key(chain_id: ChainId, nonce: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&chain_id.to_le_bytes());
    key[8..16].copy_from_slice(&nonce.to_le_bytes());
    key
}

/// 持久化的 BridgeRegistry 包装（缺口 #9 / Q24）。
///
/// 内存 [`BridgeRegistry`] 为权威态（供 `bridge_verify` / `burn_on_source` 直接使用）；
/// 每次消费 nonce 后同步落盘，重启时从 DB 全量重建内存态。
///
/// 内部用 `Mutex<BridgeRegistry>` 保护（bridge_verify 需 `&mut`），DB 句柄 `Arc<DB>` 共享。
pub struct BridgeRegistryStore {
    /// 内存权威态（供 bridge 验证逻辑使用）。
    registry: Mutex<BridgeRegistry>,
    /// RocksDB 后端（持久化 consumed nonces）。
    db: Arc<DB>,
}

impl std::fmt::Debug for BridgeRegistryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeRegistryStore").finish_non_exhaustive()
    }
}

impl BridgeRegistryStore {
    /// 打开（或创建）持久化的 BridgeRegistryStore。
    ///
    /// 启动时全量加载已消费的 deposit/burn nonces 到内存 `BridgeRegistry`。
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let deposit_cf = ColumnFamilyDescriptor::new(DEPOSIT_NONCES_CF, Options::default());
        let burn_cf = ColumnFamilyDescriptor::new(BURN_NONCES_CF, Options::default());
        let db = DB::open_cf_descriptors(&db_opts, path, vec![deposit_cf, burn_cf])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
        let db = Arc::new(db);

        // 全量加载已消费 nonces 到内存 registry。
        let mut registry = BridgeRegistry::new();
        let deposit_cf_handle = db
            .cf_handle(DEPOSIT_NONCES_CF)
            .expect("bridge_deposit_nonces CF 必须存在");
        for item in db.iterator_cf(deposit_cf_handle, rocksdb::IteratorMode::Start) {
            let (key, _) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            if key.len() == 16 {
                let chain_id = ChainId::from_le_bytes(key[0..8].try_into().unwrap());
                let nonce = u64::from_le_bytes(key[8..16].try_into().unwrap());
                registry.consume_nonce(chain_id, nonce);
            }
        }
        let burn_cf_handle = db
            .cf_handle(BURN_NONCES_CF)
            .expect("bridge_burn_nonces CF 必须存在");
        for item in db.iterator_cf(burn_cf_handle, rocksdb::IteratorMode::Start) {
            let (key, _) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            if key.len() == 16 {
                let chain_id = ChainId::from_le_bytes(key[0..8].try_into().unwrap());
                let nonce = u64::from_le_bytes(key[8..16].try_into().unwrap());
                registry.consume_burn_nonce(chain_id, nonce);
            }
        }

        Ok(Self {
            registry: Mutex::new(registry),
            db,
        })
    }

    /// 打开一个临时目录下的持久化 store（用于测试 / 开发）。
    pub fn open_inmemory() -> PokerL1Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_bridge_registry_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self::open(path)
    }

    /// 持久化一个已消费的 deposit nonce（bridge_verify 成功后调用）。
    ///
    /// 同时更新内存 registry 与 DB。幂等：重复写入同一 key 无副作用。
    pub fn persist_deposit_nonce(&self, source_chain_id: ChainId, nonce: u64) -> PokerL1Result<()> {
        let cf = self
            .db
            .cf_handle(DEPOSIT_NONCES_CF)
            .expect("bridge_deposit_nonces CF 必须存在");
        let key = nonce_key(source_chain_id, nonce);
        self.db
            .put_cf(cf, key, [])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
        // 内存态已在 bridge_verify 内 consume_nonce；此处防御性同步（幂等）。
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        reg.consume_nonce(source_chain_id, nonce);
        Ok(())
    }

    /// 持久化一个已消费的 burn nonce（burn_on_source 成功后调用）。
    pub fn persist_burn_nonce(&self, dest_chain_id: ChainId, burn_nonce: u64) -> PokerL1Result<()> {
        let cf = self
            .db
            .cf_handle(BURN_NONCES_CF)
            .expect("bridge_burn_nonces CF 必须存在");
        let key = nonce_key(dest_chain_id, burn_nonce);
        self.db
            .put_cf(cf, key, [])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        reg.consume_burn_nonce(dest_chain_id, burn_nonce);
        Ok(())
    }

    /// 获取内存 registry 的锁（供 `bridge_verify` / `burn_on_source` 使用）。
    ///
    /// 返回 `MutexGuard`，调用方在 guard 上调用 bridge 验证逻辑；验证成功后
    /// 调用 [`Self::persist_deposit_nonce`] / [`Self::persist_burn_nonce`] 落盘。
    pub fn registry(&self) -> std::sync::MutexGuard<'_, BridgeRegistry> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 仅用于测试：从 DB 直接读取已持久化的 deposit nonce 集合（验证持久化生效）。
#[cfg(test)]
pub(crate) fn dump_persisted_deposit_nonces(store: &BridgeRegistryStore) -> BTreeSet<(ChainId, u64)> {
    let mut out = BTreeSet::new();
    let cf = store
        .db
        .cf_handle(DEPOSIT_NONCES_CF)
        .expect("CF 必须存在");
    for item in store.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, _) = item.expect("iter");
        if key.len() == 16 {
            let chain_id = ChainId::from_le_bytes(key[0..8].try_into().unwrap());
            let nonce = u64::from_le_bytes(key[8..16].try_into().unwrap());
            out.insert((chain_id, nonce));
        }
    }
    out
}

/// 仅用于测试：从 DB 直接读取已持久化的 burn nonce 集合。
#[cfg(test)]
pub(crate) fn dump_persisted_burn_nonces(store: &BridgeRegistryStore) -> BTreeSet<(ChainId, u64)> {
    let mut out = BTreeSet::new();
    let cf = store
        .db
        .cf_handle(BURN_NONCES_CF)
        .expect("CF 必须存在");
    for item in store.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
        let (key, _) = item.expect("iter");
        if key.len() == 16 {
            let chain_id = ChainId::from_le_bytes(key[0..8].try_into().unwrap());
            let nonce = u64::from_le_bytes(key[8..16].try_into().unwrap());
            out.insert((chain_id, nonce));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_nonce_survives_reopen() {
        // 消费一个 deposit nonce → 重启 → nonce 仍在（防重启重放铸币）。
        let path = std::env::temp_dir().join(format!(
            "poker_l1_bridge_test_dep_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        {
            let store = BridgeRegistryStore::open(&path).expect("open");
            store
                .persist_deposit_nonce(0xAAAA_BBBB, 42)
                .expect("persist");
            assert!(
                store.registry().is_nonce_consumed(0xAAAA_BBBB, 42),
                "内存态应标记已消费"
            );
        }
        // 重启：重新 open 同路径
        {
            let store = BridgeRegistryStore::open(&path).expect("reopen");
            assert!(
                store.registry().is_nonce_consumed(0xAAAA_BBBB, 42),
                "重启后 deposit nonce 必须仍标记已消费（防重放）"
            );
            // DB 层面也应持久化
            let persisted = dump_persisted_deposit_nonces(&store);
            assert!(persisted.contains(&(0xAAAA_BBBB, 42)));
        }
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn burn_nonce_survives_reopen() {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_bridge_test_burn_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        {
            let store = BridgeRegistryStore::open(&path).expect("open");
            store
                .persist_burn_nonce(0xCCCC_DDDD, 7)
                .expect("persist");
        }
        {
            let store = BridgeRegistryStore::open(&path).expect("reopen");
            assert!(
                store.registry().is_burn_nonce_consumed(0xCCCC_DDDD, 7),
                "重启后 burn nonce 必须仍标记已消费"
            );
        }
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn persist_is_idempotent() {
        // 重复持久化同一 nonce 无副作用（不报错、不重复）。
        let path = std::env::temp_dir().join(format!(
            "poker_l1_bridge_test_idem_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = BridgeRegistryStore::open(&path).expect("open");
        store.persist_deposit_nonce(1, 100).expect("first");
        store.persist_deposit_nonce(1, 100).expect("second (idempotent)");
        let persisted = dump_persisted_deposit_nonces(&store);
        assert_eq!(persisted.iter().filter(|(_, n)| *n == 100).count(), 1);
        let _ = std::fs::remove_dir_all(&path);
    }
}
