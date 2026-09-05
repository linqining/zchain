//! M3：写前日志（WAL）——软确认链的持久化。
//!
//! 格式：`u32 LE 长度 || borsh(SignedFrame)` 逐条追加。重启时全量重放：
//! 重放即恢复（帧链本身是完整历史，无需快照）。写入顺序 = 先 WAL 后内存
//! 应用（write-ahead），崩溃窗口内最多丢"未落盘"的软确认，已落盘的必然
//! 可重放。

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{AppchainError, AppchainResult};
use crate::soft_confirm::SignedFrame;

/// WAL 写端。
pub struct WalWriter {
    path: PathBuf,
    writer: BufWriter<File>,
    appended: u64,
}

impl WalWriter {
    /// 打开（不存在则创建；已存在则**截断风险由调用方管理**——正常路径
    /// 用 [`WalWriter::open_append`]）。
    ///
    /// # Errors
    /// IO 错误 → [`AppchainError::WalCorrupted`]。
    pub fn create(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("create failed"))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
            appended: 0,
        })
    }

    /// 追加打开（崩溃恢复路径）。
    ///
    /// # Errors
    /// IO 错误 → [`AppchainError::WalCorrupted`]。
    pub fn open_append(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("open failed"))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: BufWriter::new(file),
            appended: 0,
        })
    }

    /// 追加一帧（write-ahead：调用方在应用内存状态**之前**调用）。
    ///
    /// # Errors
    /// 序列化/IO 失败 → [`AppchainError::WalCorrupted`] / Codec。
    pub fn append(&mut self, frame: &SignedFrame) -> AppchainResult<()> {
        let bytes =
            borsh::to_vec(frame).map_err(|e| AppchainError::Codec(e.to_string()))?;
        let len = u32::try_from(bytes.len())
            .map_err(|_| AppchainError::WalCorrupted("frame too large"))?;
        self.writer
            .write_all(&len.to_le_bytes())
            .and_then(|_| self.writer.write_all(&bytes))
            .map_err(|_| AppchainError::WalCorrupted("write failed"))?;
        self.appended += 1;
        Ok(())
    }

    /// 刷盘（软确认承诺点：fsync 后帧才算"已承诺"）。
    ///
    /// # Errors
    /// IO 失败 → [`AppchainError::WalCorrupted`]。
    pub fn flush(&mut self) -> AppchainResult<()> {
        self.writer
            .flush()
            .map_err(|_| AppchainError::WalCorrupted("flush failed"))
    }

    /// 路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 本次会话已追加帧数。
    #[must_use]
    pub fn appended(&self) -> u64 {
        self.appended
    }
}

/// 全量读取并解析 WAL（不做语义验证——链/签名验证由 sequencer 重放执行）。
///
/// # Errors
/// 截断/损坏 → [`AppchainError::WalCorrupted`]。
pub fn read_all(path: &Path) -> AppchainResult<Vec<SignedFrame>> {
    let file = File::open(path)
        .map_err(|_| AppchainError::WalCorrupted("open failed"))?;
    let mut r = BufReader::new(file);
    let mut out = Vec::new();
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return Err(AppchainError::WalCorrupted("read length")),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(AppchainError::WalCorrupted("frame length insane"));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)
            .map_err(|_| AppchainError::WalCorrupted("truncated frame"))?;
        let frame = borsh::from_slice::<SignedFrame>(&buf)
            .map_err(|_| AppchainError::WalCorrupted("bad frame encoding"))?;
        out.push(frame);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee::FeePolicy;
    use crate::keys::SequencerKey;
    use crate::ops::Operation;
    use crate::soft_confirm::{genesis_prev_hash, SoftConfirmFrame};

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("poker-appchain-wal-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn append_read_roundtrip() {
        let p = temp_path("roundtrip.wal");
        let _ = std::fs::remove_file(&p);
        let key = SequencerKey::from_seed(&[6u8; 32]);
        let mut w = WalWriter::create(&p).unwrap();
        let f = SignedFrame::sign(
            SoftConfirmFrame {
                index: 0,
                prev_hash: genesis_prev_hash(),
                op: Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
                state_root: [1; 32],
                ts_ms: 42,
            },
            &key,
        )
        .unwrap();
        w.append(&f).unwrap();
        w.flush().unwrap();
        drop(w);
        let frames = read_all(&p).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], f);
    }

    #[test]
    fn truncated_wal_detected() {
        let p = temp_path("trunc.wal");
        std::fs::write(&p, [10, 0, 0, 0, 1, 2, 3]).unwrap();
        assert!(read_all(&p).is_err());
    }
}
