//! ObjectStore（SubTask 2.3 — 内存版 + Sparse Merkle Tree backing）
//!
//! 功能：
//! - create / read / update / delete / version 查询
//! - 创建时校验 ObjectID 不存在，冲突返回 `ObjectIDCollision`（NEW-L4）
//! - Sparse Merkle Root 计算（IMPL-SEC-3）— keyed by blake2b_256(ObjectID)
//! - 批量写入接口

use super::id::ObjectID;
use super::object::Object;
use super::smt::SparseMerkleTree;
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use std::collections::HashMap;

/// 内存版 ObjectStore + SMT backing。
///
/// Phase 1 内存实现；Phase 4 扩展 rocksdb 后端。
pub struct ObjectStore {
    /// ObjectID -> Object
    objects: HashMap<ObjectID, Object>,
    /// Sparse Merkle Tree，key = blake2b_256(ObjectID)，value = BCS(Object)
    smt: SparseMerkleTree,
}

impl ObjectStore {
    /// 创建空 store。
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            smt: SparseMerkleTree::new(),
        }
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    pub const fn state_root(&self) -> crate::Hash {
        self.smt.root()
    }

    /// 创建对象。ObjectID 冲突返回 `ObjectIDCollision`（NEW-L4）。
    pub fn create(&mut self, object: Object) -> PokerL1Result<()> {
        if self.objects.contains_key(&object.id) {
            return Err(PokerL1Error::ObjectIDCollision(object.id));
        }
        let key = object.id.merkle_key();
        let value = bcs::to_bytes(&object)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        self.objects.insert(object.id, object);
        Ok(())
    }

    /// 读取对象。
    pub fn read(&self, id: &ObjectID) -> PokerL1Result<&Object> {
        self.objects
            .get(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))
    }

    /// 查询对象版本号。
    pub fn version_of(&self, id: &ObjectID) -> PokerL1Result<super::object::Version> {
        Ok(self.read(id)?.version)
    }

    /// 更新对象。校验：对象存在、可写（非 Immutable）、actor 有写权。
    /// 成功后 version += 1，SMT 同步更新。
    pub fn update(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_data: Vec<u8>,
    ) -> PokerL1Result<()> {
        let obj = self
            .objects
            .get_mut(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;

        if !obj.can_write(actor) {
            return if obj.owner.is_immutable() {
                Err(PokerL1Error::ObjectImmutable(*id))
            } else {
                Err(PokerL1Error::NotOwner(*id))
            };
        }

        obj.data = new_data;
        obj.bump_version();

        // SMT 同步：用新 BCS(Object) 覆盖
        let key = obj.id.merkle_key();
        let value = bcs::to_bytes(obj)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        Ok(())
    }

    /// 转移所有权（仅 AddressOwned 对象可转移）。
    pub fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        let obj = self
            .objects
            .get_mut(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;

        if !obj.owner.is_transferable() {
            return Err(PokerL1Error::ObjectImmutable(*id));
        }
        if !obj.can_write(actor) {
            return Err(PokerL1Error::NotOwner(*id));
        }

        obj.owner = crate::object_model::Ownership::AddressOwned { owner: new_owner };
        obj.bump_version();

        let key = obj.id.merkle_key();
        let value = bcs::to_bytes(obj)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        Ok(())
    }

    /// 删除对象（从 SMT 移除，状态根同步更新）。
    pub fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        let obj = self
            .objects
            .remove(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;
        let key = id.merkle_key();
        self.smt.remove(&key);
        Ok(obj)
    }

    /// 批量写入（原子语义：全部成功或全部失败回滚）。
    ///
    /// 注意：当前实现先预检所有 ObjectID 不冲突，再依次插入。若中途 BCS 序列化失败，
    /// 已插入的对象会保留（部分写入）—— Phase 1 内存版可接受；Phase 4 rocksdb 将用 WriteBatch。
    pub fn batch_create(&mut self, objects: Vec<Object>) -> PokerL1Result<()> {
        // 预检：所有 ObjectID 互不冲突且与现有 store 不冲突
        let mut seen = std::collections::HashSet::new();
        for o in &objects {
            if self.objects.contains_key(&o.id) || !seen.insert(o.id) {
                return Err(PokerL1Error::ObjectIDCollision(o.id));
            }
        }
        // 依次插入
        for o in objects {
            self.create(o)?;
        }
        Ok(())
    }

    /// 当前 live 对象数量。
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// 生成对象的 Merkle 包含证明（供轻客户端验证，R5-M8）。
    pub fn prove(&self, id: &ObjectID) -> PokerL1Result<super::smt::MerklePath> {
        if !self.objects.contains_key(id) {
            return Err(PokerL1Error::ObjectNotFound(*id));
        }
        Ok(self.smt.prove(&id.merkle_key()))
    }

    /// 生成非包含证明（证明某 ObjectID 不存在）。
    pub fn prove_nonexistence(&self, id: &ObjectID) -> super::smt::MerklePath {
        self.smt.prove(&id.merkle_key())
    }

    /// 迭代所有 live 对象。
    pub fn iter(&self) -> impl Iterator<Item = &Object> {
        self.objects.values()
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::Ownership;

    fn make_obj(creator: Address, nonce: u64, owner: Address) -> Object {
        Object::new(
            ObjectID::new(creator, nonce),
            Ownership::AddressOwned { owner },
            "Test",
            format!("data-{nonce}").into_bytes(),
            None,
        )
    }

    #[test]
    fn create_and_read() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let read = s.read(&o.id).unwrap();
        assert_eq!(read, &o);
    }

    #[test]
    fn create_collision_returns_error() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let err = s.create(o).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
    }

    #[test]
    fn update_bumps_version_and_state_root() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let root_before = s.state_root();

        s.update(&o.id, &[1u8; 20], b"new data".to_vec()).unwrap();

        assert_eq!(s.version_of(&o.id).unwrap(), 1);
        let root_after = s.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn update_by_non_owner_fails() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let o = make_obj([1u8; 20], 1, owner);
        s.create(o.clone()).unwrap();

        let err = s.update(&o.id, &other, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotOwner(_)));
    }

    #[test]
    fn update_immutable_fails() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let mut o = make_obj([1u8; 20], 1, owner);
        o.owner = Ownership::Immutable;
        s.create(o.clone()).unwrap();

        let err = s.update(&o.id, &owner, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectImmutable(_)));
    }

    #[test]
    fn transfer_changes_owner() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let new_owner = [2u8; 20];
        let o = make_obj([1u8; 20], 1, owner);
        s.create(o.clone()).unwrap();

        s.transfer(&o.id, &owner, new_owner).unwrap();
        assert!(s.read(&o.id).unwrap().can_write(&new_owner));
        assert!(!s.read(&o.id).unwrap().can_write(&owner));
    }

    #[test]
    fn delete_restores_state_root() {
        let mut s = ObjectStore::new();
        let empty_root = s.state_root();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        assert_ne!(s.state_root(), empty_root);
        s.delete(&o.id).unwrap();
        assert_eq!(s.state_root(), empty_root, "删除后状态根应恢复");
    }

    #[test]
    fn batch_create_atomic_collision() {
        let mut s = ObjectStore::new();
        let o1 = make_obj([1u8; 20], 1, [1u8; 20]);
        let o2 = make_obj([2u8; 20], 1, [2u8; 20]);
        // o3 与 o1 同 ID（冲突）
        let o3 = make_obj([1u8; 20], 1, [3u8; 20]);

        let err = s.batch_create(vec![o1, o2, o3]).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
        // 冲突时整个批次都不写入
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn prove_inclusion_verifies() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();

        let path = s.prove(&o.id).unwrap();
        let value_bytes = bcs::to_bytes(&o).unwrap();
        assert!(super::super::smt::SparseMerkleTree::verify(
            &s.state_root(),
            &o.id.merkle_key(),
            Some(&value_bytes),
            &path,
        ));
    }

    #[test]
    fn prove_nonexistence_verifies() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o).unwrap();

        let absent_id = ObjectID::new([9u8; 20], 999);
        let path = s.prove_nonexistence(&absent_id);
        assert!(path.is_empty_leaf);
        assert!(super::super::smt::SparseMerkleTree::verify(
            &s.state_root(),
            &absent_id.merkle_key(),
            None,
            &path,
        ));
    }
}
