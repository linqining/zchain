//! M3：写前日志（WAL）——软确认链的持久化。
//!
//! 格式：`u32 LE 长度 || borsh(SignedFrame)` 逐条追加。重启时全量重放：
//! 重放即恢复（帧链本身是完整历史，无需快照）。
//!
//! ## 写入顺序（P0-4：先 WAL 后内存应用）
//!
//! write-ahead 纪律由调用方（`sequencer::submit`）执行：克隆态试算 → 帧签名
//! → [`WalWriter::append`] → [`WalWriter::sync`]（承诺点）→ 成功后才把试算
//! 态换入内存。崩溃窗口内最多丢"未过承诺点"的软确认；已过承诺点的帧必然
//! 可重放，且 WAL 写/fsync 失败时内存态零变更（内存与 WAL 不可能分叉）。
//!
//! ## fsync 开关
//!
//! [`WalWriter::sync`] = BufWriter flush + `File::sync_all`（数据 + 元数据
//! 真落盘），构造默认开启；测试可用 [`WalWriter::with_fsync(false)`] 关闭
//! （只做用户态 flush）提速。

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{AppchainError, AppchainResult};
use crate::keys::SequencerKey;
use crate::soft_confirm::SignedFrame;

/// WAL 落盘 sink 抽象：生产 = [`File`]；测试注入故障 sink（模拟磁盘满）。
pub(crate) trait WalSink: std::io::Write + Send {
    /// 真刷盘（fsync：数据 + 元数据）。
    fn sync(&mut self) -> std::io::Result<()>;
}

impl WalSink for File {
    fn sync(&mut self) -> std::io::Result<()> {
        File::sync_all(self)
    }
}

/// WAL 写端。
pub struct WalWriter {
    path: PathBuf,
    writer: BufWriter<Box<dyn WalSink>>,
    appended: u64,
    /// fsync 开关（默认 true）：false 时 [`WalWriter::sync`] 只做用户态 flush。
    fsync: bool,
}

impl WalWriter {
    /// 打开（不存在则创建；已存在则**截断风险由调用方管理**——正常路径
    /// 用 [`WalWriter::open_append`]）。fsync 默认开启。
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
            writer: BufWriter::new(Box::new(file)),
            appended: 0,
            fsync: true,
        })
    }

    /// 追加打开（崩溃恢复路径）。fsync 默认开启。
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
            writer: BufWriter::new(Box::new(file)),
            appended: 0,
            fsync: true,
        })
    }

    /// 设置 fsync 开关（builder 风格）：`true`（默认）= [`WalWriter::sync`]
    /// 真落盘；`false` = 只做用户态 flush（测试提速用，进程崩溃可能丢帧）。
    #[must_use]
    pub fn with_fsync(mut self, enabled: bool) -> Self {
        self.fsync = enabled;
        self
    }

    /// 追加一帧（write-ahead：调用方在内存状态生效**之前**调用，且必须在
    /// [`WalWriter::sync`] 过承诺点之前）。
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

    /// 软确认承诺点：BufWriter flush +（默认）真 fsync（`File::sync_all`，
    /// 数据 + 元数据落盘）。fsync 关闭时只做用户态 flush。
    ///
    /// # Errors
    /// flush/fsync 失败 → [`AppchainError::WalCorrupted`]。
    pub fn sync(&mut self) -> AppchainResult<()> {
        self.writer
            .flush()
            .map_err(|_| AppchainError::WalCorrupted("flush failed"))?;
        if self.fsync {
            self.writer
                .get_mut()
                .sync()
                .map_err(|_| AppchainError::WalCorrupted("fsync failed"))?;
        }
        Ok(())
    }

    /// 用户态刷盘（不 fsync；承诺点请用 [`WalWriter::sync`]）。
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

    /// 注入自定义 sink（测试故障注入用；生产路径走 create/open_append）。
    /// 使用零容量 BufWriter（无缓冲）：故障点 = 写点，注入语义精确。
    #[cfg(test)]
    pub(crate) fn from_sink(path: PathBuf, sink: Box<dyn WalSink>, fsync: bool) -> Self {
        Self {
            path,
            writer: BufWriter::with_capacity(0, sink),
            appended: 0,
            fsync,
        }
    }
}

/// 故障注入 sink：字节数预算耗尽后所有写返回错误（模拟磁盘满/掉盘）。
/// 底层仍是真实文件，可验证"失败后落盘内容"的重放行为。
#[cfg(test)]
pub(crate) struct BudgetSink {
    file: File,
    budget: usize,
}

#[cfg(test)]
impl BudgetSink {
    /// 构造：允许写 `budget` 字节，之后一律报错。
    pub(crate) fn new(file: File, budget: usize) -> Self {
        Self { file, budget }
    }
}

#[cfg(test)]
impl std::io::Write for BudgetSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.budget {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "injected: wal budget exhausted",
            ));
        }
        self.budget -= buf.len();
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
impl WalSink for BudgetSink {
    fn sync(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

/// 容崩读取：解析 + 逐帧验签（链哈希连续 + 签名），在**第一个坏帧**处
/// 截停，返回有效前缀（崩溃安全——追加写 WAL 的尾帧可能因进程被杀而撕裂；
/// fsync 过的有效前缀必须可恢复）。首帧即坏 → 无可恢复前缀，返回错误。
/// 返回值：(有效帧, 有效前缀字节数, 尾帧废弃原因)。
///
/// # Errors
/// 文件不可读或首帧解析/验签失败 → [`AppchainError`]。
pub fn read_all_strict_prefix(
    path: &Path,
    sequencer_public: &[u8; 32],
) -> AppchainResult<(Vec<SignedFrame>, u64, Option<String>)> {
    let file = File::open(path)
        .map_err(|_| AppchainError::WalCorrupted("open failed"))?;
    let mut r = BufReader::new(file);
    let mut out: Vec<SignedFrame> = Vec::new();
    let mut valid_bytes: u64 = 0;
    let mut prev = crate::soft_confirm::genesis_prev_hash();
    let mut prev_index: Option<u64> = None;
    let mut tail_reason: Option<String> = None;
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => {
                tail_reason = Some("read length".into());
                break;
            }
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            tail_reason = Some("frame length insane".into());
            break;
        }
        let mut buf = vec![0u8; len];
        if let Err(e) = r.read_exact(&mut buf) {
            tail_reason = Some(format!("truncated frame ({e})"));
            break;
        }
        let frame = match borsh::from_slice::<SignedFrame>(&buf) {
            Ok(f) => f,
            Err(_) => {
                tail_reason = Some("bad frame encoding".into());
                break;
            }
        };
        // 逐帧验签（与 soft_confirm::verify_chain 同语义，增量版）。
        let verify_ok = (|| -> bool {
            match prev_index {
                None => {
                    frame.frame.index == 0
                        && frame.frame.prev_hash == crate::soft_confirm::genesis_prev_hash()
                        && frame
                            .hash()
                            .map(|h| SequencerKey::verify(sequencer_public, &h, &frame.sig))
                            .unwrap_or(false)
                }
                Some(pi) => frame.verify_against(&prev, pi, sequencer_public).is_ok(),
            }
        })();
        if !verify_ok {
            tail_reason = Some(format!("frame {} signature/chain invalid", frame.frame.index));
            break;
        }
        valid_bytes += 4 + len as u64;
        prev = frame.hash()?;
        prev_index = Some(frame.frame.index);
        out.push(frame);
    }
    if out.is_empty() {
        return Err(AppchainError::WalCorrupted("no recoverable frame"));
    }
    Ok((out, valid_bytes, tail_reason))
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

    fn sample_frame(key: &SequencerKey, index: u64) -> SignedFrame {
        SignedFrame::sign(
            SoftConfirmFrame {
                index,
                prev_hash: genesis_prev_hash(),
                op: Operation::OpenTable { table_id: 1, policy: FeePolicy::Zero },
                state_root: [1; 32],
                ts_ms: 42,
            },
            key,
        )
        .unwrap()
    }

    #[test]
    fn append_read_roundtrip() {
        let p = temp_path("roundtrip.wal");
        let _ = std::fs::remove_file(&p);
        let key = SequencerKey::from_seed(&[6u8; 32]);
        let mut w = WalWriter::create(&p).unwrap();
        let f = sample_frame(&key, 0);
        w.append(&f).unwrap();
        // 承诺点走 sync（P0-4：含真 fsync 路径）
        w.sync().unwrap();
        drop(w);
        let frames = read_all(&p).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], f);
    }

    #[test]
    fn fsync_disabled_roundtrip() {
        let p = temp_path("nofsync.wal");
        let _ = std::fs::remove_file(&p);
        let key = SequencerKey::from_seed(&[7u8; 32]);
        let mut w = WalWriter::create(&p).unwrap().with_fsync(false);
        let f = sample_frame(&key, 0);
        w.append(&f).unwrap();
        w.sync().unwrap(); // 关 fsync：只做用户态 flush
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
