//! 持久化：与 poker-wallet CLI **完全一致**的文件布局（zchain-wallet 数据目录
//! 格式，plan §6.12.5 CLI bin）。密文文件是 `{"data": <borsh 字节的 JSON 数组>}`
//! 的 HexBlob 壳，内部字节与 CLI 相同（keystore/dek 是 borsh `SealedEnvelope`，
//! note 库是 DEK AEAD 快照）——**CLI 与桌面钱包可以互读对方的数据目录**。
//!
//! ```text
//! keystore.json          owner key 信封（口令 Argon2id → AEAD）
//! dek.json               DEK 信封（同一口令；note 库加密根）
//! notes_real.json        REAL 物理分库快照（AAD 钉 REAL）
//! notes_play.json        PLAY 物理分库快照（AAD 钉 PLAY——互不能打开）
//! sessions.json          会话 binding 登记表（borsh）
//! checkpoint.json        同步断点
//! nonces.json            已用签名 nonce
//! settings.json          壳层设置（自动锁屏秒数；非 wallet-core 数据）
//! ```

use std::path::PathBuf;

use borsh::BorshDeserialize as _;
use wallet_core::error::{WalletError, WalletResult};
use wallet_core::keystore::SealedEnvelope;
use serde::{Deserialize, Serialize};

/// borsh 字节的 JSON 容器（与 CLI `HexBlob` 同构）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexBlob {
    /// borsh 编码字节。
    pub data: Vec<u8>,
}

/// 壳层设置（settings.json；不属于 wallet-core 协议数据）。
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Settings {
    /// 应用自动锁屏秒数（空闲后强制回锁）。
    pub auto_lock_secs: u64,
}

/// 数据目录内的固定文件布局。
pub struct WalletPaths {
    /// 钱包数据目录。
    pub dir: PathBuf,
}

impl WalletPaths {
    /// 绑定数据目录。
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// owner key 信封。
    pub fn keystore(&self) -> PathBuf {
        self.dir.join("keystore.json")
    }

    /// DEK 信封。
    pub fn dek(&self) -> PathBuf {
        self.dir.join("dek.json")
    }

    /// REAL/PLAY 物理分库快照（两个文件，互相打不开）。
    pub fn stores(&self, class: poker_appchain::note::AssetClass) -> PathBuf {
        self.dir.join(format!("notes_{}.json", class.name().to_lowercase()))
    }

    /// 会话 binding 登记表。
    pub fn sessions(&self) -> PathBuf {
        self.dir.join("sessions.json")
    }

    /// 同步断点。
    pub fn checkpoint(&self) -> PathBuf {
        self.dir.join("checkpoint.json")
    }

    /// 已用签名 nonce。
    pub fn nonces(&self) -> PathBuf {
        self.dir.join("nonces.json")
    }

    /// 壳层设置。
    pub fn settings(&self) -> PathBuf {
        self.dir.join("settings.json")
    }

    /// 钱包是否已初始化（keystore 信封存在）。
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.keystore().exists()
    }

    /// 读 borsh hex 容器（缺文件 → None）。
    pub fn read_blob<T: serde::de::DeserializeOwned>(&self, p: &PathBuf) -> WalletResult<Option<T>> {
        let bytes = match std::fs::read(p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WalletError::Io(e.to_string())),
        };
        serde_json::from_slice(&bytes).map(Some).map_err(|e| WalletError::Codec(e.to_string()))
    }

    /// 写 borsh hex 容器。
    pub fn write_blob<T: Serialize>(&self, p: &PathBuf, v: &T) -> WalletResult<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| WalletError::Io(e.to_string()))?;
        let bytes = serde_json::to_vec_pretty(v).map_err(|e| WalletError::Codec(e.to_string()))?;
        std::fs::write(p, bytes).map_err(|e| WalletError::Io(e.to_string()))
    }

    /// 读信封文件（borsh `SealedEnvelope`）。
    pub fn read_envelope(&self, p: &PathBuf) -> WalletResult<Option<SealedEnvelope>> {
        match self.read_blob::<HexBlob>(p)? {
            Some(blob) => SealedEnvelope::try_from_slice(&blob.data)
                .map(Some)
                .map_err(|e| WalletError::Codec(e.to_string())),
            None => Ok(None),
        }
    }

    /// 写信封文件。
    pub fn write_envelope(&self, p: &PathBuf, env: &SealedEnvelope) -> WalletResult<()> {
        let data = borsh::to_vec(env).map_err(|e| WalletError::Codec(e.to_string()))?;
        self.write_blob(p, &HexBlob { data })
    }
}
