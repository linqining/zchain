//! DaBackend — 数据可用性后端抽象（多结算层架构 Phase 1.5，见
//! docs/plan-multi-settlement-architecture.md §5）。
//!
//! 定位：L2 帧数据（soft-confirm 帧 / WAL 段）必须**可重建**，证明器与
//! follower 才能独立重放。当前自托管（SelfHostDa：内容寻址落盘）为默认
//! 实现；宿主 calldata / Celestia / Avail 为后续实现目标——**引擎只面向
//! 本 trait**，加 DA = 加实现，不碰 sequencer/pipeline。
//!
//! 完整性纪律：`DaRef` 携带内容摘要（blake2s32，与 checkpoint payload 同
//! 域纪律），`retrieve` 逐字节校验（防存储层腐化/篡改静默通过）。

use crate::error::{AppchainError, AppchainResult};
use crate::keys::blake2s32;

/// 数据可用性引用（发布产物；句柄 + 完整性摘要）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DaRef {
    /// 内容摘要 = blake2s32(payload)（retrieve 时逐字节校验）。
    pub digest: [u8; 32],
    /// 后端定位符（SelfHost = 文件名；calldata = tx hash；Celestia = height+namespace）。
    pub locator: String,
    /// 字节长度（快速对账）。
    pub len: u64,
}

/// 数据可用性后端 trait（加 DA = 实现本 trait）。
pub trait DaBackend: Send {
    /// 发布一段 L2 数据（帧段/批次数据），返回引用。
    ///
    /// # Errors
    /// 后端写入失败 / 超限。
    fn publish(&mut self, payload: &[u8]) -> AppchainResult<DaRef>;

    /// 按引用取回并校验完整性（摘要不符 → [`AppchainError::DaCorrupted`]）。
    ///
    /// # Errors
    /// 不可达 / 摘要不符。
    fn retrieve(&self, reference: &DaRef) -> AppchainResult<Vec<u8>>;
}

/// 自托管 DA（默认实现）：内容寻址落盘（`<dir>/<hex(digest)>.da`）。
///
/// 与现有 WAL/网关归档的关系：WAL 是 sequencer 的写前日志（权威数据面），
/// SelfHostDa 是**面向 follower/证明器的分发面**——把批次数据以内容寻址方式
/// 导出，`DaRef` 经网关/checkpoint 分发。
pub struct SelfHostDa {
    dir: std::path::PathBuf,
}

impl SelfHostDa {
    /// 打开（不存在则创建）目录。
    ///
    /// # Errors
    /// 目录创建失败。
    pub fn open(dir: impl Into<std::path::PathBuf>) -> AppchainResult<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppchainError::DaUnavailable(format!("da dir {}: {e}", dir.display())))?;
        Ok(Self { dir })
    }

    fn path_for(&self, digest: &[u8; 32]) -> std::path::PathBuf {
        self.dir.join(format!("{}.da", hex::encode(digest)))
    }
}

impl DaBackend for SelfHostDa {
    fn publish(&mut self, payload: &[u8]) -> AppchainResult<DaRef> {
        if payload.is_empty() {
            return Err(AppchainError::DaEmpty);
        }
        let digest = blake2s32(&[payload]);
        let path = self.path_for(&digest);
        if !path.exists() {
            // 原子写（tmp + rename）防撕裂。
            let tmp = self.dir.join(format!(".{}.tmp", hex::encode(digest)));
            std::fs::write(&tmp, payload)
                .map_err(|e| AppchainError::DaUnavailable(format!("da write: {e}")))?;
            std::fs::rename(&tmp, &path)
                .map_err(|e| AppchainError::DaUnavailable(format!("da rename: {e}")))?;
        }
        Ok(DaRef {
            digest,
            locator: format!("{}.da", hex::encode(digest)),
            len: payload.len() as u64,
        })
    }

    fn retrieve(&self, reference: &DaRef) -> AppchainResult<Vec<u8>> {
        let path = self.dir.join(&reference.locator);
        let payload = std::fs::read(&path)
            .map_err(|e| AppchainError::DaUnavailable(format!("da read {}: {e}", path.display())))?;
        if payload.len() as u64 != reference.len {
            return Err(AppchainError::DaCorrupted(format!(
                "len mismatch: ref={} actual={}",
                reference.len,
                payload.len()
            )));
        }
        let actual = blake2s32(&[&payload]);
        if actual != reference.digest {
            return Err(AppchainError::DaCorrupted(format!(
                "digest mismatch: ref={} actual={}",
                hex::encode(reference.digest),
                hex::encode(actual)
            )));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_retrieve_roundtrip_content_addressed() {
        let dir = std::env::temp_dir().join(format!("zchain-da-test-{}", std::process::id()));
        let mut da = SelfHostDa::open(&dir).expect("opens");
        let payload = b"zchain frames batch 001".to_vec();

        let reference = da.publish(&payload).expect("publishes");
        assert_eq!(reference.len, payload.len() as u64);
        assert_eq!(reference.digest, blake2s32(&[&payload]));

        let back = da.retrieve(&reference).expect("retrieves");
        assert_eq!(back, payload);

        // 内容寻址：同 payload 再发布 → 同 locator（幂等去重）。
        let again = da.publish(&payload).expect("re-publishes");
        assert_eq!(again.locator, reference.locator);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tampered_storage_detected() {
        let dir = std::env::temp_dir().join(format!("zchain-da-tamper-{}", std::process::id()));
        let mut da = SelfHostDa::open(&dir).expect("opens");
        let reference = da.publish(b"frames-abc").expect("publishes");

        // 模拟存储层腐化：改写文件内容。
        let path = dir.join(&reference.locator);
        std::fs::write(&path, b"frames-XYZ").expect("writes tamper");

        let err = da.retrieve(&reference).expect_err("must detect");
        assert!(matches!(err, AppchainError::DaCorrupted(_)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_handle_and_empty_payload_rejected() {
        let dir = std::env::temp_dir().join(format!("zchain-da-miss-{}", std::process::id()));
        let mut da = SelfHostDa::open(&dir).expect("opens");
        assert!(matches!(
            da.publish(b""),
            Err(AppchainError::DaEmpty)
        ));
        let ghost = DaRef {
            digest: [7u8; 32],
            locator: "deadbeef.da".into(),
            len: 4,
        };
        assert!(da.retrieve(&ghost).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
