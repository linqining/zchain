//! # zwallet — ZChain 桌面钱包 MVP 接线层（plan §6.12.5）
//!
//! [`Wallet`] 是 wallet-core（`poker-wallet`，plan §6.12.3）之上的薄壳：
//! 状态机（未初始化/锁定/解锁 + 自动锁屏）+ 数据目录持久化（与 poker-wallet
//! CLI **同格式**，可互读）+ serde DTO。**本 crate 不实现任何密码学/Note/
//! 签名/备份逻辑**——全部委托 wallet-core：
//!
//! - 创建/导入账户 → [`wallet_core::key_manager::OwnerKeyPair`] +
//!   [`wallet_core::keystore`]（Argon2id + ChaCha20-Poly1305 信封）
//! - PLAY note 列表/余额 → [`wallet_core::note_store`]（REAL/PLAY 物理分库）
//! - 逐字段签名确认 → [`wallet_core::operation_signer::Signer`]（只接受
//!   结构化请求；`sign_raw_bytes` 恒拒绝）
//! - 备份导出/导入 → [`wallet_core::backup`]（错误口令 fail-closed + 恢复自检）
//! - REAL/PLAY 展示门 → [`wallet_core::display`]（壳层不得自行决定）
//!
//! ## MVP 网络边界（如实标注）
//!
//! 本 crate 不做任何网络 IO。devnet（`zchain-devnet-1`）为固定本地环境；
//! PLAY note 的"faucet"是**本地演示铸造**（明示 demo，不伪造链上余额）。

#![deny(unsafe_code)]

pub mod dto;
pub mod persist;

/// 重导出：签名预览（壳层确认页逐字段展示的直接数据源；serde JSON）。
pub use wallet_core::operation_signer::SigningPreview;

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use borsh::BorshDeserialize as _;
use dto::{
    BackupInfoDto, BalancesDto, NoteDto, NotesPageDto, SignRequestDto, StatusDto, SignedDto,
    ABI_VERSION, CHAIN_ID, DEFAULT_AUTO_LOCK_SECS, DOMAIN, REQUEST_TTL_SECS,
};
use persist::{Settings, WalletPaths};
use poker_appchain::note::{AssetClass, Note};
use poker_appchain::soft_confirm::genesis_prev_hash;
use wallet_core::account_binding::BindingRegistry;
use wallet_core::backup::{
    collect_indexes, export_backup, import_backup, BackupPayloadV1, EncryptedBackup,
};
use wallet_core::display::{play_page_view, real_page_view, ReadinessFlags};
use wallet_core::error::{WalletError, WalletResult};
use wallet_core::key_manager::{OwnerKeyPair, SecretBytes};
use wallet_core::keystore::{
    generate_dek, open_dek, open_owner_key, params_interactive, seal_dek, seal_owner_key,
};
use wallet_core::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};
use wallet_core::operation_signer::{
    parse_domain, NetworkCtx, NonceTracker, OutputSpec, RequestContext, Signer, SigningRequest,
};
use wallet_core::sync::SyncCheckpoint;

/// 壳层错误：wallet-core 错误原样透传（fail-closed 语义不变），另加壳层状态错误。
#[derive(Debug, thiserror::Error)]
pub enum ZWalletError {
    /// 钱包处于锁定态（手动或自动锁屏触发）。
    #[error("wallet is locked ({0})")]
    Locked(String),
    /// 数据目录未初始化（先创建/导入钱包）。
    #[error("wallet not initialized (create or restore first)")]
    NotInitialized,
    /// 数据目录已有钱包（避免覆盖）。
    #[error("wallet already initialized in this data dir")]
    AlreadyInitialized,
    /// 口令过短（MVP 策略：≥ 8 字节）。
    #[error("password must be at least 8 characters")]
    PasswordTooShort,
    /// 文件 IO 失败。
    #[error("io error: {0}")]
    Io(String),
    /// wallet-core 错误（原样透传，不吞不改）。
    #[error(transparent)]
    Core(#[from] WalletError),
}

/// 壳层 Result 别名。
pub type ZResult<T> = Result<T, ZWalletError>;

/// KDF 参数元组（wallet-core `params_interactive`/`params_test` 的形状）。
pub type Params = (u32, u32, u32);

/// 当前 unix 秒。
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 解锁后的内存态（secret 均为 wallet-core zeroize 容器；drop 即清零）。
struct UnlockedWallet {
    owner: OwnerKeyPair,
    dek: SecretBytes,
    stores: WalletStores,
    registry: BindingRegistry,
    checkpoint: Option<SyncCheckpoint>,
    nonces: NonceTracker,
}

/// 钱包状态机：未初始化 → 锁定 ⇄ 解锁（自动锁屏从解锁回到锁定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletState {
    /// 数据目录无 keystore。
    Uninitialized,
    /// 已初始化但锁定。
    Locked,
    /// 解锁态。
    Unlocked,
}

/// 桌面钱包实例（壳层持有一个互斥实例；所有入口都先过自动锁屏检查）。
pub struct Wallet {
    paths: WalletPaths,
    state: WalletState,
    unlocked: Option<UnlockedWallet>,
    auto_lock_secs: u64,
    last_activity: Instant,
}

impl Wallet {
    /// 打开数据目录（不创建；不触碰任何敏感数据）。加载壳层设置。
    ///
    /// # Errors
    /// 设置文件损坏 → [`ZWalletError::Core`]（[`WalletError::Codec`]）。
    pub fn open(dir: impl AsRef<Path>) -> ZResult<Self> {
        let paths = WalletPaths::new(dir.as_ref().to_path_buf());
        let auto_lock_secs = match paths.read_blob::<Settings>(&paths.settings())? {
            Some(s) => s.auto_lock_secs,
            None => DEFAULT_AUTO_LOCK_SECS,
        };
        let state = if paths.is_initialized() { WalletState::Locked } else { WalletState::Uninitialized };
        Ok(Self {
            paths,
            state,
            unlocked: None,
            auto_lock_secs,
            last_activity: Instant::now(),
        })
    }

    // ===== 状态机 =====

    /// 自动锁屏检查：解锁态且空闲超时 → 立即回锁（fail-closed：先锁再报错）。
    fn auto_lock_check(&mut self) {
        if self.state == WalletState::Unlocked
            && self.last_activity.elapsed().as_secs() >= self.auto_lock_secs
        {
            self.lock();
        }
    }

    /// 记录活动时间（每次成功访问解锁态后调用）。
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// 取解锁态（先过自动锁屏；锁定/未初始化一律拒绝）。
    fn unlocked_mut(&mut self) -> ZResult<&mut UnlockedWallet> {
        self.auto_lock_check();
        match (&mut self.unlocked, self.state) {
            (Some(w), WalletState::Unlocked) => Ok(w),
            (_, WalletState::Uninitialized) => Err(ZWalletError::NotInitialized),
            (_, WalletState::Locked) => Err(ZWalletError::Locked("locked".into())),
            (None, WalletState::Unlocked) => unreachable!("state/unlocked desync"),
        }
    }

    /// 手动锁定（立即丢弃全部 secret——zeroize on drop）。
    pub fn lock(&mut self) {
        self.unlocked = None;
        self.state = if self.paths.is_initialized() { WalletState::Locked } else { WalletState::Uninitialized };
    }

    /// 设置自动锁屏秒数并持久化（settings.json）。
    ///
    /// # Errors
    /// 写盘失败 → [`ZWalletError::Io`]。
    pub fn set_auto_lock_secs(&mut self, secs: u64) -> ZResult<()> {
        self.auto_lock_secs = secs;
        self.paths
            .write_blob(&self.paths.settings(), &Settings { auto_lock_secs: secs })
            .map_err(|e| ZWalletError::Core(e))?;
        self.touch();
        Ok(())
    }

    /// 当前自动锁屏秒数。
    #[must_use]
    pub fn auto_lock_secs(&self) -> u64 {
        self.auto_lock_secs
    }

    /// 数据目录。
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.paths.dir
    }

    // ===== 创建 / 解锁 =====

    /// 创建钱包（或经 `secret_hex` 导入 32B owner 私钥）。生产 KDF 参数。
    ///
    /// # Errors
    /// 已初始化 / 口令过短 / 私钥字节非法 / 写盘失败。
    pub fn create_wallet(&mut self, password: &str, secret_hex: Option<&str>) -> ZResult<StatusDto> {
        self.create_wallet_with_params(password, secret_hex, params_interactive())
    }

    /// 同 [`Wallet::create_wallet`]，可指定 KDF 参数（测试用轻量参数）。
    ///
    /// # Errors
    /// 同 [`Wallet::create_wallet`]。
    pub fn create_wallet_with_params(
        &mut self,
        password: &str,
        secret_hex: Option<&str>,
        params: Params,
    ) -> ZResult<StatusDto> {
        if self.paths.is_initialized() {
            return Err(ZWalletError::AlreadyInitialized);
        }
        if password.len() < 8 {
            return Err(ZWalletError::PasswordTooShort);
        }
        let owner = match secret_hex {
            Some(hex_str) => {
                let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                    .map_err(|_| WalletError::BadKeyMaterial("secret hex"))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| WalletError::BadKeyMaterial("secret must be 32 bytes"))?;
                OwnerKeyPair::from_secret_bytes(&arr)?
            }
            None => OwnerKeyPair::generate(),
        };
        let dek = generate_dek();
        let keystore_env = seal_owner_key(&owner, password.as_bytes(), params)?;
        let dek_env = seal_dek(&dek, password.as_bytes(), params)?;
        self.paths.write_envelope(&self.paths.keystore(), &keystore_env)?;
        self.paths.write_envelope(&self.paths.dek(), &dek_env)?;

        let w = UnlockedWallet {
            owner,
            dek,
            stores: WalletStores::new(),
            registry: BindingRegistry::new(),
            checkpoint: Some(SyncCheckpoint { last_op_index: 0, head_hash: genesis_prev_hash() }),
            nonces: NonceTracker::new(),
        };
        self.state = WalletState::Unlocked;
        self.unlocked = Some(w);
        self.persist()?;
        self.touch();
        Ok(self.status())
    }

    /// 口令解锁（口令错 → wallet-core `BadPassword`，fail-closed）。
    ///
    /// # Errors
    /// 未初始化 / 口令错 / 库快照损坏。
    pub fn unlock(&mut self, password: &str) -> ZResult<StatusDto> {
        self.auto_lock_check();
        if !self.paths.is_initialized() {
            return Err(ZWalletError::NotInitialized);
        }
        let keystore_env = self
            .paths
            .read_envelope(&self.paths.keystore())?
            .ok_or(ZWalletError::NotInitialized)?;
        let dek_env = self
            .paths
            .read_envelope(&self.paths.dek())?
            .ok_or(WalletError::Tampered("missing dek envelope"))?;
        // 口令错 → BadPassword（wallet-core 信封 canary + AEAD 认证）。
        let owner = open_owner_key(&keystore_env, password.as_bytes())?;
        let dek = open_dek(&dek_env, password.as_bytes())?;
        let mut stores = WalletStores::new();
        for class in [AssetClass::Real, AssetClass::Play] {
            if let Some(blob) = self.paths.read_blob::<persist::HexBlob>(&self.paths.stores(class))? {
                let store = wallet_core::note_store::NoteStore::open(&dek, class, &blob.data)?;
                match class {
                    AssetClass::Real => stores.set_real(store),
                    AssetClass::Play => stores.set_play(store),
                }
            }
        }
        let registry = self
            .paths
            .read_blob::<persist::HexBlob>(&self.paths.sessions())?
            .map(|b| BindingRegistry::try_from_slice(&b.data))
            .transpose()
            .map_err(|e| WalletError::Codec(e.to_string()))?
            .unwrap_or_default();
        let checkpoint = self
            .paths
            .read_blob::<persist::HexBlob>(&self.paths.checkpoint())?
            .map(|b| SyncCheckpoint::try_from_slice(&b.data))
            .transpose()
            .map_err(|e| WalletError::Codec(e.to_string()))?;
        let nonces = self
            .paths
            .read_blob::<std::collections::BTreeMap<String, Vec<u64>>>(&self.paths.nonces())?
            .map(NonceTracker::from_used)
            .unwrap_or_default();

        self.state = WalletState::Unlocked;
        self.unlocked = Some(UnlockedWallet { owner, dek, stores, registry, checkpoint, nonces });
        self.touch();
        Ok(self.status())
    }

    // ===== 持久化 =====

    /// 全量持久化（库快照 AAD 钉资产类；与 CLI `persist` 等价）。
    fn persist(&self) -> ZResult<()> {
        let Some(w) = &self.unlocked else {
            return Ok(());
        };
        for class in [AssetClass::Real, AssetClass::Play] {
            let sealed = match class {
                AssetClass::Real => w.stores.real().seal(&w.dek),
                AssetClass::Play => w.stores.play().seal(&w.dek),
            }?;
            self.paths.write_blob(&self.paths.stores(class), &persist::HexBlob { data: sealed })?;
        }
        let reg_bytes = borsh::to_vec(&w.registry).map_err(|e| WalletError::Codec(e.to_string()))?;
        self.paths.write_blob(&self.paths.sessions(), &persist::HexBlob { data: reg_bytes })?;
        if let Some(cp) = &w.checkpoint {
            let cp_bytes = borsh::to_vec(cp).map_err(|e| WalletError::Codec(e.to_string()))?;
            self.paths.write_blob(&self.paths.checkpoint(), &persist::HexBlob { data: cp_bytes })?;
        }
        self.paths.write_blob(&self.paths.nonces(), &w.nonces.used_map())?;
        Ok(())
    }

    // ===== 视图 =====

    /// 钱包状态视图（状态栏/锁屏/账户页）。
    #[must_use]
    pub fn status(&mut self) -> StatusDto {
        self.auto_lock_check();
        let initialized = self.paths.is_initialized();
        let unlocked = self.state == WalletState::Unlocked && self.unlocked.is_some();
        let balances = if unlocked {
            let w = self.unlocked.as_ref().expect("checked unlocked");
            Some(self.balances_dto(w))
        } else {
            None
        };
        let remaining = if unlocked {
            self.auto_lock_secs.saturating_sub(self.last_activity.elapsed().as_secs())
        } else {
            0
        };
        StatusDto {
            initialized,
            locked: !unlocked,
            chain_id: CHAIN_ID.into(),
            domain: DOMAIN.into(),
            abi_version: ABI_VERSION,
            network_label: "ZChain devnet（本地 · 未连网）".into(),
            owner_public_hex: unlocked
                .then(|| {
                    hex::encode(
                        self.unlocked.as_ref().expect("checked unlocked").owner.public_bytes(),
                    )
                }),
            balances,
            auto_lock_secs: self.auto_lock_secs,
            lock_remaining_secs: remaining,
            data_dir: self.paths.dir.display().to_string(),
            environment_badge: environment_badge(),
        }
    }

    /// 余额视图（REAL 页展示门由 wallet-core `display` 决定：离线 → 无 claim/提现入口）。
    fn balances_dto(&self, w: &UnlockedWallet) -> BalancesDto {
        let b = w.stores.balances();
        // devnet MVP：vault/verifier/finality 全部未就绪（如实离线）。
        BalancesDto {
            play_free: b.play_free.to_string(),
            play_locked: b.play_locked.to_string(),
            real_free: b.real_free.to_string(),
            real_locked: b.real_locked.to_string(),
            play_view: play_page_view(b.play_free, true),
            real_view: real_page_view(&ReadinessFlags::offline(), b.real_free),
        }
    }

    /// PLAY note 列表页。
    ///
    /// # Errors
    /// 锁定 / 未初始化。
    pub fn play_notes(&mut self) -> ZResult<NotesPageDto> {
        let w = self.unlocked_mut()?;
        let b = w.stores.balances();
        let play: Vec<NoteDto> = w
            .stores
            .play()
            .records()
            .map(|(c, r)| note_dto(c, r, true))
            .collect();
        self.touch();
        Ok(NotesPageDto {
            play,
            play_free: b.play_free.to_string(),
            play_locked: b.play_locked.to_string(),
            play_view: play_page_view(b.play_free, true),
            data_source_notice:
                "本地演示数据：note 由本机 faucet 生成，未连任何链上网络，不代表链上余额"
                    .to_string(),
        })
    }

    /// 本地演示 faucet：铸造一张 PLAY note（**本地演示数据**，不联网、不伪造链上余额）。
    ///
    /// # Errors
    /// 锁定 / 金额为 0 / note 构造失败。
    pub fn demo_faucet(&mut self, amount: u64) -> ZResult<NoteDto> {
        if amount == 0 {
            return Err(WalletError::InvalidArgument("amount must be > 0").into());
        }
        let w = self.unlocked_mut()?;
        let mut nonce = [0u8; 32];
        let tick = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nonce[..8].copy_from_slice(&tick.to_be_bytes());
        let note = Note::new(AssetClass::Play, amount, w.owner.public_bytes(), nonce, None)
            .map_err(|e| WalletError::Codec(e.to_string()))?;
        let rec = NoteRecord::new(
            note,
            OriginFrame {
                op_index: w.checkpoint.as_ref().map(|c| c.last_op_index + 1).unwrap_or(0),
                frame_hash: genesis_prev_hash(),
            },
            ProofState::Soft,
        );
        let commitment = w.stores.store(AssetClass::Play).insert(rec)?;
        let stored = w
            .stores
            .play()
            .get(&commitment)
            .cloned()
            .expect("just inserted");
        self.persist()?;
        self.touch();
        Ok(note_dto(&commitment, &stored, true))
    }

    // ===== 签名 =====

    /// 结构化签名预览（确认页第一屏：逐字段展示，不占用 nonce）。
    ///
    /// # Errors
    /// 锁定 / 请求构造非法 / wallet-core 全部拒绝面。
    pub fn preview_sign(&mut self, req: &SignRequestDto) -> ZResult<SigningPreview> {
        let w = self.unlocked_mut()?;
        let now = unix_now();
        let signing_req = build_signing_request(w, req, now)?;
        let mut signer = Signer::new(&w.stores, now, &mut w.nonces);
        let preview = signer.preview(&signing_req)?;
        self.touch();
        Ok(preview)
    }

    /// 结构化签名（确认页第二屏：用户逐字段确认后调用）。
    ///
    /// # Errors
    /// 同 [`Wallet::preview_sign`]；另含 nonce 重放/过期/金额守恒等 wallet-core
    /// 拒绝面（全部 fail-closed）。
    pub fn confirm_sign(&mut self, req: &SignRequestDto) -> ZResult<SignedDto> {
        let w = self.unlocked_mut()?;
        let now = unix_now();
        let signing_req = build_signing_request(w, req, now)?;
        let mut signer = Signer::new(&w.stores, now, &mut w.nonces);
        let signed = signer.sign(&signing_req, &w.owner)?;
        self.persist()?;
        self.touch();
        Ok(SignedDto {
            preview: signed.preview,
            digest_hex: hex::encode(signed.digest),
            operation_borsh_hex: hex::encode(
                borsh::to_vec(&signed.operation).map_err(|e| WalletError::Codec(e.to_string()))?,
            ),
        })
    }

    /// **任意 bytes 签名入口——恒拒绝**（透传 wallet-core `RawBytesRejected`）。
    /// UI 提供"负例按钮"验证该行为（WALLET-ACC-3：无 signBytes 默认能力）。
    ///
    /// # Errors
    /// 恒 [`WalletError::RawBytesRejected`]。
    pub fn sign_raw_bytes(&mut self, label: &str, bytes: &[u8]) -> ZResult<()> {
        let w = self.unlocked_mut()?;
        let mut signer = Signer::new(&w.stores, unix_now(), &mut w.nonces);
        Ok(signer.sign_raw_bytes(label, bytes)?)
    }

    // ===== 备份 =====

    /// 加密备份导出（wallet-core `export_backup`；全链路：keystore + DEK 信封 +
    /// 双库快照 + binding + checkpoint + 声明索引）。
    ///
    /// 返回（信息, 文件字节）——字节由壳层写盘/下载。
    ///
    /// # Errors
    /// 锁定 / KDF 编码失败。
    pub fn backup_export(&mut self, password: &str) -> ZResult<(BackupInfoDto, Vec<u8>)> {
        self.backup_export_with_params(password, params_interactive())
    }

    /// 同 [`Wallet::backup_export`]，可指定 KDF 参数（测试用轻量参数）。
    ///
    /// # Errors
    /// 同 [`Wallet::backup_export`]。
    pub fn backup_export_with_params(
        &mut self,
        password: &str,
        params: Params,
    ) -> ZResult<(BackupInfoDto, Vec<u8>)> {
        // 先读盘上的信封（不可变借用随后即结束），再取解锁态做库快照。
        let keystore_env = self
            .paths
            .read_envelope(&self.paths.keystore())?
            .ok_or(WalletError::Tampered("missing keystore envelope"))?;
        let dek_env = self
            .paths
            .read_envelope(&self.paths.dek())?
            .ok_or(WalletError::Tampered("missing dek envelope"))?;
        let w = self.unlocked_mut()?;
        let payload = BackupPayloadV1 {
            keystore: Some(keystore_env),
            dek_envelope: Some(dek_env),
            real_store: Some(w.stores.real().seal(&w.dek)?),
            play_store: Some(w.stores.play().seal(&w.dek)?),
            bindings: w.registry.clone(),
            checkpoint: w.checkpoint.clone(),
            indexes: collect_indexes(&w.stores),
            created_unix: unix_now(),
        };
        let backup = export_backup(&payload, password.as_bytes(), params)?;
        let info = BackupInfoDto {
            magic: "ZCBK".into(),
            version: backup.version,
            created_unix: payload.created_unix,
            notes_real: w.stores.real().len(),
            notes_play: w.stores.play().len(),
            suggested_filename: format!(
                "zchain-wallet-backup-{}-{}.zcbk",
                CHAIN_ID,
                payload.created_unix
            ),
        };
        let bytes = backup.to_bytes()?;
        self.touch();
        Ok((info, bytes))
    }

    /// 加密备份导入（wallet-core `import_backup`：口令 → DEK 信封 → 双库解密 →
    /// 索引重建与声明索引比对；**任何环节失败 fail-closed，不覆盖现有目录**）。
    ///
    /// 导入成功后钱包回到锁定态（要求重新解锁——恢复流程的显式边界）。
    ///
    /// # Errors
    /// 口令错 / 篡改 / 未来版本 / 索引不一致（全部 wallet-core fail-closed）。
    pub fn backup_import(&mut self, bytes: &[u8], password: &str) -> ZResult<StatusDto> {
        let backup = EncryptedBackup::from_bytes(bytes)?;
        let payload = import_backup(&backup, password.as_bytes())?;
        let keystore_env =
            payload.keystore.clone().ok_or(WalletError::Tampered("no keystore in backup"))?;
        let dek_env = payload
            .dek_envelope
            .clone()
            .ok_or(WalletError::Tampered("no dek envelope in backup"))?;
        // 校验通过后才写盘（fail-closed：坏备份绝不污染现有数据目录）。
        self.paths.write_envelope(&self.paths.keystore(), &keystore_env)?;
        self.paths.write_envelope(&self.paths.dek(), &dek_env)?;
        for class in [AssetClass::Real, AssetClass::Play] {
            let blob = match class {
                AssetClass::Real => payload.real_store.clone(),
                AssetClass::Play => payload.play_store.clone(),
            };
            if let Some(data) = blob {
                self.paths.write_blob(&self.paths.stores(class), &persist::HexBlob { data })?;
            }
        }
        let reg_bytes =
            borsh::to_vec(&payload.bindings).map_err(|e| WalletError::Codec(e.to_string()))?;
        self.paths.write_blob(&self.paths.sessions(), &persist::HexBlob { data: reg_bytes })?;
        if let Some(cp) = &payload.checkpoint {
            let cp_bytes = borsh::to_vec(cp).map_err(|e| WalletError::Codec(e.to_string()))?;
            self.paths.write_blob(&self.paths.checkpoint(), &persist::HexBlob { data: cp_bytes })?;
        }
        // nonces 不随备份迁移（chain 本地防重放水位独立）。
        self.paths.write_blob(&self.paths.nonces(), &NonceTracker::new().used_map())?;
        self.lock();
        Ok(self.status())
    }
}

// ===== 自由函数 =====

/// 组装 wallet-core 结构化请求（壳层边界：devnet 演示钱包只接受 PLAY；
/// withdraw/settle 不在本 MVP 的 UI 暴露面内）。
fn build_signing_request(
    w: &UnlockedWallet,
    req: &SignRequestDto,
    now: u64,
) -> ZResult<SigningRequest> {
    if !req.asset_class.eq_ignore_ascii_case("PLAY") {
        // devnet 演示钱包边界：REAL 操作（含提现）未上线，不提供入口。
        return Err(WalletError::AssetClassMismatch(
            "devnet demo wallet only supports PLAY (REAL operations are not launched)".into(),
        )
        .into());
    }
    let nonce = req.nonce.unwrap_or_else(|| next_nonce(&w.nonces, CHAIN_ID));
    let ctx = RequestContext {
        network: NetworkCtx {
            domain: parse_domain(DOMAIN)?,
            chain_id: CHAIN_ID.into(),
            abi_version: ABI_VERSION,
        },
        nonce,
        expiry: req.expiry.unwrap_or(now + REQUEST_TTL_SECS),
    };
    let inputs = parse_commitments_or_all_spendable(&w.stores.play(), &req.inputs)?;
    match req.kind.as_str() {
        "transfer" => {
            if req.outputs.is_empty() {
                return Err(WalletError::InvalidArgument("outputs").into());
            }
            let outputs = req
                .outputs
                .iter()
                .map(|o| Ok(OutputSpec { owner: parse_key33(&o.owner)?, amount: o.amount }))
                .collect::<WalletResult<Vec<OutputSpec>>>()?;
            Ok(SigningRequest::Transfer {
                ctx,
                asset_class: AssetClass::Play,
                inputs,
                outputs,
            })
        }
        "buy_in" => {
            let table_id = req.table_id.ok_or(WalletError::InvalidArgument("table_id"))?;
            let seat_owner = match &req.seat_owner {
                Some(s) => parse_key33(s)?,
                None => w.owner.public_bytes(),
            };
            Ok(SigningRequest::BuyIn {
                ctx,
                asset_class: AssetClass::Play,
                table_id,
                seat_owner,
                inputs,
            })
        }
        _other => Err(WalletError::InvalidArgument(
            "kind (transfer|buy_in; withdraw/settle are not exposed in this MVP)",
        )
        .into()),
    }
}

/// 环境徽章（每个页面固定显示；§6.12.5 / §6.9 纪律）。
#[must_use]
pub fn environment_badge() -> String {
    "devnet · PLAY · 自托管密钥（keystore 在本机）· 本地演示数据（未连网）".into()
}

/// 下一个空闲 nonce（自动分配：已用集合 max + 1）。
fn next_nonce(nonces: &NonceTracker, chain_id: &str) -> u64 {
    nonces
        .used_map()
        .get(chain_id)
        .and_then(|v| v.iter().max().map(|m| m + 1))
        .unwrap_or(0)
}

/// 解析输入承诺列表；空列表 = 自动选择全部未花费 PLAY note（sweep 语义，
/// UI 明示"输出合计必须等于该总额"）。
fn parse_commitments_or_all_spendable(
    store: &wallet_core::note_store::NoteStore,
    inputs: &[String],
) -> WalletResult<Vec<[u8; 32]>> {
    if inputs.is_empty() {
        return Ok(store
            .records()
            .filter(|(_, r)| r.spendable())
            .map(|(c, _)| *c)
            .collect());
    }
    inputs
        .iter()
        .map(|s| parse_key32(s))
        .collect::<WalletResult<Vec<[u8; 32]>>>()
}

/// hex → 32B（承诺/request id）。
fn parse_key32(s: &str) -> WalletResult<[u8; 32]> {
    let v = hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| WalletError::BadKeyMaterial("hex32"))?;
    v.try_into().map_err(|_| WalletError::BadKeyMaterial("hex32 length"))
}

/// hex → 33B（压缩公钥）。
fn parse_key33(s: &str) -> WalletResult<[u8; 33]> {
    let v = hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| WalletError::BadKeyMaterial("hex33"))?;
    v.try_into().map_err(|_| WalletError::BadKeyMaterial("hex33 length"))
}

/// note 展示 DTO 构造。
fn note_dto(commitment: &[u8; 32], r: &NoteRecord, demo: bool) -> NoteDto {
    NoteDto {
        commitment_hex: hex::encode(commitment),
        amount: r.note.amount,
        table_id: r.note.table_id,
        proof: match r.proof {
            ProofState::Pending => "pending",
            ProofState::Soft => "soft",
            ProofState::Proven { .. } => "proven",
            ProofState::Finalized => "finalized",
        }
        .to_string(),
        spent_by_op: r.spent_by_op,
        nullifier_hex: hex::encode(r.nullifier()),
        origin_op_index: r.origin.op_index,
        demo,
    }
}
