//! `backup`：全库加密备份导出/导入（plan §6.12.3 + M6-ACC-2/8、WALLET-ACC-5）。
//!
//! 格式：`magic("ZCBK") + version + KDF 参数 + AEAD(payload)`；AAD 覆盖整个
//! 明文头（版本改一个字节即认证失败——**未来版本**在 AEAD 之前先行拒绝，
//! 保证 fail-closed 与前向隔离）。
//!
//! payload 含 note 双库快照（REAL/PLAY 物理分库各自密文）、keystore 信封
//! （owner key + DEK）、binding 登记表、同步 checkpoint 与**声明索引**
//! （commitment/nullifier/spent 清单）。导入后重建索引并与声明索引自检，
//! 不一致即篡改（M6-ACC-8/WALLET-ACC-5：恢复后 commitment/nullifier 索引
//! 与链上视图一致）。
//!
//! 版本迁移点：[`migrate_payload`] 当前只接受 v1；更高版本一律
//! [`WalletError::UnsupportedVersion`]（旧版本迁移接口留缝）。

use crate::account_binding::BindingRegistry;
use crate::error::{WalletError, WalletResult};
use crate::keystore::{KdfParams, SealedEnvelope, KEYSTORE_VERSION};
use crate::note_store::WalletStores;
use crate::sync::SyncCheckpoint;

/// 备份格式版本（只升不降）。
pub const BACKUP_VERSION: u16 = 1;

/// 备份魔数。
pub const BACKUP_MAGIC: &[u8; 4] = b"ZCBK";

/// 备份域标签（AAD）。
pub const DOMAIN_BACKUP: &[u8] = b"zchain.backup.v1";

/// 备份声明的全库索引（恢复自检基准）。
#[derive(Debug, Clone, Default, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BackupIndexes {
    /// 全部 note 承诺（REAL+PLAY）。
    pub commitments: Vec<[u8; 32]>,
    /// 全部 nullifier。
    pub nullifiers: Vec<[u8; 32]>,
    /// 已花费承诺。
    pub spent: Vec<[u8; 32]>,
}

/// 备份 payload v1（AEAD 明文结构）。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BackupPayloadV1 {
    /// keystore 信封（owner key；口令加密层）。
    pub keystore: Option<SealedEnvelope>,
    /// DEK 信封（库快照加密根；同一口令独立信封）。
    pub dek_envelope: Option<SealedEnvelope>,
    /// REAL 库快照（DEK 加密层，见 [`crate::note_store::NoteStore::seal`]）。
    pub real_store: Option<Vec<u8>>,
    /// PLAY 库快照。
    pub play_store: Option<Vec<u8>>,
    /// 会话 binding 登记表。
    pub bindings: BindingRegistry,
    /// 同步 checkpoint。
    pub checkpoint: Option<SyncCheckpoint>,
    /// 声明索引（恢复自检）。
    pub indexes: BackupIndexes,
    /// 创建时间（unix 秒；审计信息）。
    pub created_unix: u64,
}

/// 加密备份文件结构。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct EncryptedBackup {
    /// 魔数 `ZCBK`。
    pub magic: [u8; 4],
    /// 备份格式版本。
    pub version: u16,
    /// KDF 参数。
    pub kdf: KdfParams,
    /// AEAD nonce。
    pub nonce: [u8; 12],
    /// 密文（含 Poly1305 tag；明文 = borsh(payload)）。
    pub ciphertext: Vec<u8>,
}

impl EncryptedBackup {
    /// 文件字节（borsh）。
    ///
    /// # Errors
    /// 不可达（纯内存结构）→ [`WalletError::Codec`]。
    pub fn to_bytes(&self) -> WalletResult<Vec<u8>> {
        borsh::to_vec(self).map_err(|e| WalletError::Codec(format!("backup encode: {e}")))
    }

    /// 从文件字节解析（只做结构解析，不解密）。
    ///
    /// # Errors
    /// 长度/魔数非法 → [`WalletError::Tampered`]；未来版本 →
    /// [`WalletError::UnsupportedVersion`]。
    pub fn from_bytes(bytes: &[u8]) -> WalletResult<Self> {
        let backup: Self = borsh::from_slice(bytes)
            .map_err(|_| WalletError::Tampered("backup structure"))?;
        backup.validate_header()?;
        Ok(backup)
    }

    /// 头部校验（魔数 + 版本；在解密前执行——未来版本 fail-closed）。
    ///
    /// # Errors
    /// 见 [`EncryptedBackup::from_bytes`]。
    pub fn validate_header(&self) -> WalletResult<()> {
        if &self.magic != BACKUP_MAGIC {
            return Err(WalletError::Tampered("backup magic"));
        }
        if self.version > BACKUP_VERSION {
            return Err(WalletError::UnsupportedVersion {
                found: self.version,
                max_supported: BACKUP_VERSION,
            });
        }
        Ok(())
    }
}

/// 全库加密导出。
///
/// `keystore`/库快照由调用方给出（钱包解锁态持有 DEK）；口令 → KEK 直接
/// 加密整个 payload（AES 级 AEAD，密文自带完整性）。
///
/// # Errors
/// 编码失败（实际不可达）→ [`WalletError::Codec`]。
pub fn export_backup(
    payload: &BackupPayloadV1,
    password: &[u8],
    params: (u32, u32, u32),
) -> WalletResult<EncryptedBackup> {
    let plain = borsh::to_vec(payload)
        .map_err(|e| WalletError::Codec(format!("backup payload: {e}")))?;
    // seal() 内部使用 DOMAIN_KEYSTORE；备份用自己的域标签防跨用途移植。
    let mut env = crate::keystore::SealedEnvelope {
        version: KEYSTORE_VERSION,
        kdf: KdfParams { salt: [0; 16], m_cost_kib: params.0, t_cost: params.1, p_cost: params.2 },
        nonce: [0; 12],
        ciphertext: Vec::new(),
    };
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(&mut env.kdf.salt);
    rand::rngs::OsRng.fill_bytes(&mut env.nonce);
    let kek = crate::keystore::derive_key(password, &env.kdf);
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey};
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(kek.as_ref()));
    let header = borsh::to_vec(&(&env.kdf, env.version))
        .map_err(|e| WalletError::Codec(e.to_string()))?;
    env.ciphertext = cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(&env.nonce),
            Payload { msg: &plain, aad: &header },
        )
        .map_err(|_| WalletError::Codec("backup seal".into()))?;
    Ok(EncryptedBackup {
        magic: *BACKUP_MAGIC,
        version: BACKUP_VERSION,
        kdf: env.kdf,
        nonce: env.nonce,
        ciphertext: env.ciphertext,
    })
}

/// 版本迁移点：`version ≤ BACKUP_VERSION` 的旧 payload 迁移到当前结构。
/// 当前只支持 v1（未来版本在 [`EncryptedBackup::validate_header`] 已拒）。
///
/// # Errors
/// 不支持的版本 → [`WalletError::UnsupportedVersion`]。
pub fn migrate_payload(version: u16, plain: &[u8]) -> WalletResult<BackupPayloadV1> {
    match version {
        1 => borsh::from_slice(plain).map_err(|_| WalletError::Tampered("backup payload")),
        v => Err(WalletError::UnsupportedVersion { found: v, max_supported: BACKUP_VERSION }),
    }
}

/// 解密 + 解析 + **恢复自检**（M6-ACC-8/WALLET-ACC-5）。
///
/// 拒绝面：魔数/结构篡改、未来版本、错误口令（AEAD 认证失败）、payload
/// 畸形、**重建索引与声明索引不一致**（库快照存在时走全链路：口令 →
/// keystore 信封 → DEK → 解密双库 → 重建索引 → 与声明索引比对）。
///
/// # Errors
/// 见上（全部 fail-closed）。
pub fn import_backup(backup: &EncryptedBackup, password: &[u8]) -> WalletResult<BackupPayloadV1> {
    backup.validate_header()?;
    let kek = crate::keystore::derive_key(password, &backup.kdf);
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey};
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(kek.as_ref()));
    let header = borsh::to_vec(&(&backup.kdf, backup.version))
        .map_err(|e| WalletError::Codec(e.to_string()))?;
    let plain = cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(&backup.nonce),
            Payload { msg: &backup.ciphertext, aad: &header },
        )
        .map_err(|_| WalletError::BadPassword)?;
    let payload = migrate_payload(backup.version, &plain)?;
    // 库快照存在时执行全链路恢复自检（DEK 层解密 + 索引重建比对）。
    if payload.real_store.is_some() || payload.play_store.is_some() {
        let dek_env = payload
            .dek_envelope
            .as_ref()
            .ok_or(WalletError::Tampered("backup missing dek envelope"))?;
        let dek = crate::keystore::open_dek(dek_env, password)?;
        let mut stores = crate::note_store::WalletStores::new();
        if let Some(blob) = &payload.real_store {
            stores.set_real(crate::note_store::NoteStore::open(
                &dek,
                poker_appchain::note::AssetClass::Real,
                blob,
            )?);
        }
        if let Some(blob) = &payload.play_store {
            stores.set_play(crate::note_store::NoteStore::open(
                &dek,
                poker_appchain::note::AssetClass::Play,
                blob,
            )?);
        }
        verify_stores_against_indexes(&mut stores, &payload.indexes)?;
    }
    Ok(payload)
}

/// 用恢复出的库实例校验声明索引（导入流程的最后一步；M6-ACC-8）。
///
/// # Errors
/// 索引不一致 → [`WalletError::Tampered`]。
pub fn verify_stores_against_indexes(
    stores: &mut WalletStores,
    indexes: &BackupIndexes,
) -> WalletResult<()> {
    stores.verify_indexes()?;
    let mut rebuilt = BackupIndexes::default();
    for store in [stores.real(), stores.play()] {
        for (commitment, record) in store.records() {
            rebuilt.commitments.push(*commitment);
            rebuilt.nullifiers.push(record.nullifier());
            if record.spent_by_op.is_some() {
                rebuilt.spent.push(*commitment);
            }
        }
    }
    rebuilt.commitments.sort_unstable();
    rebuilt.nullifiers.sort_unstable();
    rebuilt.spent.sort_unstable();
    let mut declared = indexes.clone();
    declared.commitments.sort_unstable();
    declared.nullifiers.sort_unstable();
    declared.spent.sort_unstable();
    if rebuilt.commitments != declared.commitments
        || rebuilt.nullifiers != declared.nullifiers
        || rebuilt.spent != declared.spent
    {
        return Err(WalletError::Tampered("restored index mismatch"));
    }
    Ok(())
}

/// 便捷：从 payload 声明导出当前库的索引（导出侧使用）。
#[must_use]
pub fn collect_indexes(stores: &WalletStores) -> BackupIndexes {
    let mut idx = BackupIndexes::default();
    for store in [stores.real(), stores.play()] {
        for (commitment, record) in store.records() {
            idx.commitments.push(*commitment);
            idx.nullifiers.push(record.nullifier());
            if record.spent_by_op.is_some() {
                idx.spent.push(*commitment);
            }
        }
    }
    idx
}

/// 生产参数预设重导出（CLI 用）。
pub use crate::keystore::params_interactive as default_params;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_binding::SessionBinding;
    use crate::key_manager::{OwnerKeyPair, Scope, SecretBytes, SessionConstraints};
    use crate::note_store::{NoteRecord, OriginFrame, ProofState};
    use poker_appchain::note::{AssetClass, Note};

    fn owner(seed: u8) -> [u8; 33] {
        OwnerKeyPair::from_seed(&[seed; 32]).unwrap().public_bytes()
    }

    fn populated_stores() -> WalletStores {
        let mut stores = WalletStores::new();
        let real = Note::new(AssetClass::Real, 70, owner(1), [1u8; 32], None).unwrap();
        let mut rec = NoteRecord::with_secret(real, [0xAA; 32],
            OriginFrame { op_index: 3, frame_hash: [5; 32] }, ProofState::Proven {
                batch_root: [7; 32], batch_index: 2 });
        rec.spent_by_op = Some(9);
        stores.store(AssetClass::Real).insert(rec).unwrap();
        let play = Note::new(AssetClass::Play, 33, owner(1), [2u8; 32], None).unwrap();
        stores
            .store(AssetClass::Play)
            .insert(NoteRecord::with_secret(play, [0xBB; 32],
                OriginFrame { op_index: 4, frame_hash: [6; 32] }, ProofState::Soft))
            .unwrap();
        stores
    }

    fn payload(stores: &WalletStores) -> BackupPayloadV1 {
        let mut registry = BindingRegistry::new();
        registry.authorize(SessionBinding::new(SessionConstraints {
            binding_id: [1; 32],
            chain_id: "zchain-devnet-1".into(),
            account_address: [2; 32],
            delegated_public: owner(2),
            allowed_scopes: vec![Scope::Play],
            per_tx_limit: None,
            daily_limit: None,
            table_allowlist: None,
            valid_after: 0,
            valid_until: u64::MAX,
            nonce: 1,
        }));
        BackupPayloadV1 {
            keystore: None,
            dek_envelope: None,
            real_store: None,
            play_store: None,
            bindings: registry,
            checkpoint: Some(SyncCheckpoint { last_op_index: 9, head_hash: [3; 32] }),
            indexes: collect_indexes(stores),
            created_unix: 1_700_000_000,
        }
    }

    #[test]
    fn roundtrip_and_fail_closed_paths() {
        let stores = populated_stores();
        let payload = payload(&stores);
        let backup = export_backup(&payload, b"pass phrase", crate::keystore::params_test()).unwrap();

        // 正确口令导入
        let restored = import_backup(&backup, b"pass phrase").unwrap();
        assert_eq!(restored.indexes, payload.indexes);
        assert_eq!(restored.bindings.get(&[1; 32]).map(|b| b.revoked), Some(false));

        // 错误口令
        assert!(matches!(import_backup(&backup, b"wrong"), Err(WalletError::BadPassword)));

        // 篡改一个密文字节
        let mut bytes = backup.to_bytes().unwrap();
        let i = bytes.len() - 1;
        bytes[i] ^= 0x01;
        let tampered = EncryptedBackup::from_bytes(&bytes).unwrap();
        assert!(matches!(import_backup(&tampered, b"pass phrase"), Err(WalletError::BadPassword)));

        // 未来版本（在解密之前拒绝）
        let mut future = backup.clone();
        future.version = 99;
        assert!(matches!(
            import_backup(&future, b"pass phrase"),
            Err(WalletError::UnsupportedVersion { found: 99, max_supported: 1 })
        ));
    }

    #[test]
    fn index_self_check_detects_tampering() {
        let stores = populated_stores();
        let mut declared = payload(&stores);
        // 声明索引少一条 nullifier → 恢复自检必须拒绝
        declared.indexes.nullifiers.pop();
        let backup = export_backup(&declared, b"pw", crate::keystore::params_test()).unwrap();
        let restored = import_backup(&backup, b"pw").unwrap();
        let mut stores2 = populated_stores();
        assert!(matches!(
            verify_stores_against_indexes(&mut stores2, &restored.indexes),
            Err(WalletError::Tampered("restored index mismatch"))
        ));
        // 一致索引通过
        let payload_ok = payload(&stores);
        let mut stores_ok = populated_stores();
        assert!(verify_stores_against_indexes(&mut stores_ok, &payload_ok.indexes).is_ok());
        // 库快照 + keystore 齐备时，导入路径内部即执行全链路自检
        let dek = SecretBytes::new([0x42; 32]);
        let mut full = payload(&stores);
        full.real_store = Some(stores.real().seal(&dek).unwrap());
        full.play_store = Some(stores.play().seal(&dek).unwrap());
        full.dek_envelope = Some(crate::keystore::seal_dek(&dek, b"pw3", crate::keystore::params_test()).unwrap());
        full.indexes.nullifiers.clear();
        let bad_backup = export_backup(&full, b"pw3", crate::keystore::params_test()).unwrap();
        assert!(matches!(
            import_backup(&bad_backup, b"pw3"),
            Err(WalletError::Tampered("restored index mismatch"))
        ));
    }

    #[test]
    fn sealed_stores_roundtrip_through_backup_payload() {
        let stores = populated_stores();
        let dek = SecretBytes::new([0x42; 32]);
        let mut payload = payload(&stores);
        payload.real_store = Some(stores.real().seal(&dek).unwrap());
        payload.play_store = Some(stores.play().seal(&dek).unwrap());
        payload.dek_envelope =
            Some(crate::keystore::seal_dek(&dek, b"pw2", crate::keystore::params_test()).unwrap());
        let backup = export_backup(&payload, b"pw2", crate::keystore::params_test()).unwrap();
        let restored = import_backup(&backup, b"pw2").unwrap();
        let real = crate::note_store::NoteStore::open(&dek, AssetClass::Real,
            restored.real_store.as_ref().unwrap()).unwrap();
        let play = crate::note_store::NoteStore::open(&dek, AssetClass::Play,
            restored.play_store.as_ref().unwrap()).unwrap();
        assert_eq!(real.len(), 1);
        assert_eq!(play.len(), 1);
        // REAL 库里那张是已花费（spent 状态恢复）
        assert!(real.records().all(|(_, r)| r.spent_by_op == Some(9)));
        assert!(matches!(real.records().next().unwrap().1.proof, ProofState::Proven { .. }));
    }
}
