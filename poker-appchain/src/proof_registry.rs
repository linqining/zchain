//! E2 闭环：proof 归档注册表——证明产物（[`crate::pipeline::ProofBundle`]）
//! 的 JSONL sidecar 归档 + 读取（explorer 网关下载端点的数据源）。
//!
//! ## 冻结契约（每行一个紧凑 JSON 对象 + 换行；字段名/顺序/编码不得变更）
//!
//! ```text
//! {"binding_hex":"<64hex>","op_index":<u64>,"engine":"<str>",
//!  "attestor_public":"<64hex>","payload_b64":"<base64 of archive bytes>"}
//! ```
//!
//! - `engine` 为版本化引擎标识（如 `host-validate-v2`）；写入方拒绝包含
//!   `"` / `\` / 控制字符的 engine（契约形状保证，fail-closed）；
//! - `payload_b64` 为**标准 base64（RFC 4648，含 `=` 填充、规范尾位）**——
//!   workspace 无 base64 crate，[`b64_encode`]/[`b64_decode`] 为本 crate
//!   内唯一实现（RFC 4648 测试向量钉住）。
//!
//! ## 写入纪律（与 proven log 同口径）
//!
//! 每行完整追加（含换行）；默认只 flush 不 fsync（[`ProofRegistryWriter::with_fsync`]
//! 可开真落盘）。sidecar 是**归档/观测优化而非承诺点**——证明水位承诺点
//! 仍是 WAL fsync；撕裂尾行由读取方按"忽略 + 告警"处理。
//!
//! ## 读取容错（fail-closed 取向，与 proven log 一致）
//!
//! - 空文件 → 空列表（合法）；
//! - 最后一行无换行结尾（撕裂写）→ 忽略残行 + 告警（即使恰好可解析）；
//! - 中间行坏 JSON / 坏 hex / 坏 base64 → **Err**（连续前缀承诺已破）；
//! - `binding_hex` 重复追加**允许**（幂等去重由读取方负责——归档端只追加，
//!   不做改写/去重）。

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::path::Path;

use crate::error::{AppchainError, AppchainResult};

/// 一条归档条目（对应一次完成的证明产出）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRegistryEntry {
    /// 结算绑定（hex 编码 32B；重复追加允许，去重由读取方负责）。
    pub binding_hex: String,
    /// 帧链序号。
    pub op_index: u64,
    /// 引擎标识（版本化）。
    pub engine: String,
    /// attestation 签名公钥（32B ed25519）。
    pub attestor_public: [u8; 32],
    /// 证明载荷原始字节（`payload_b64` 解码后）。
    pub payload: Vec<u8>,
}

/// 标准 base64 字母表（RFC 4648 §4，含 `+` `/`；填充为 `=`）。
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 标准 base64 编码（RFC 4648 §4，含 `=` 填充）。
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// 单个 base64 字符 → 6-bit 值。
fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// 标准 base64 严格解码（RFC 4648 §4）：
/// - 长度必须为 4 的倍数；`=` 填充只允许出现在末组且至多 2 个；
/// - 尾位必须规范（填充组被丢弃的 bit 必须为 0——非规范编码拒绝，fail-closed）。
///
/// 非法输入 → `None`。
#[must_use]
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (gi, chunk) in bytes.chunks(4).enumerate() {
        let is_last = gi + 1 == bytes.len() / 4;
        // 填充只允许在末组：`rev().take_while` 保证 `=` 全部贴尾。
        let pad = if is_last {
            chunk.iter().rev().take_while(|&&c| c == b'=').count()
        } else {
            0
        };
        if pad > 2 {
            return None;
        }
        // 非末组出现 `=`（pad==0 但组内含 `=`）→ b64_val 拒绝；末组 pad 位形
        // 如 `AAB=`/`AA==` 合法，`A==A`/`=AAA` 形状已被 take_while 排除。
        let mut vals = [0u32; 4];
        for (j, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if j < 4 - pad {
                    return None; // 填充位之后还有数据位
                }
                vals[j] = 0;
            } else {
                vals[j] = b64_val(c)?;
            }
        }
        // 规范尾位：pad 组丢弃的低位必须为 0
        if pad >= 1 && vals[2] & 0b000011 != 0 {
            return None;
        }
        if pad == 2 && vals[1] & 0b001111 != 0 {
            return None;
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// 契约形状检查：engine 不得含 `"` / `\` / ASCII 控制字符（紧凑 JSON 单行
/// 契约的形状保证；引擎标识来自 `SettlementProver::name()` 受控词表）。
fn engine_contract_ok(engine: &str) -> bool {
    engine
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
}

/// 条目 → 契约格式一行（紧凑 JSON、字段顺序冻结、带换行）。
///
/// # Errors
/// engine 含非法字符（破坏单行 JSON 契约形状）→ [`AppchainError::AdmissionRejected`]。
pub fn encode_line(entry: &ProofRegistryEntry) -> AppchainResult<String> {
    if !engine_contract_ok(&entry.engine) {
        return Err(AppchainError::AdmissionRejected(
            "proof registry engine violates frozen contract",
        ));
    }
    Ok(format!(
        "{{\"binding_hex\":\"{}\",\"op_index\":{},\"engine\":\"{}\",\"attestor_public\":\"{}\",\"payload_b64\":\"{}\"}}\n",
        entry.binding_hex,
        entry.op_index,
        entry.engine,
        hex::encode(entry.attestor_public),
        b64_encode(&entry.payload),
    ))
}

/// 解析一行契约记录（字段缺失/类型错/hex/base64 非法 → Err）。
fn parse_line(line: &str) -> Result<ProofRegistryEntry, &'static str> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|_| "bad json")?;
    let obj = v.as_object().ok_or("not a json object")?;
    let binding_hex = obj
        .get("binding_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid binding_hex")?;
    if hex::decode(binding_hex)
        .map_err(|_| "binding_hex not hex")?
        .len()
        != 32
    {
        return Err("binding_hex not 32 bytes (64 hex)");
    }
    let op_index = obj
        .get("op_index")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid op_index")?;
    let engine = obj
        .get("engine")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid engine")?
        .to_string();
    let attestor_hex = obj
        .get("attestor_public")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid attestor_public")?;
    let attestor_public: [u8; 32] = hex::decode(attestor_hex)
        .map_err(|_| "attestor_public not hex")?
        .try_into()
        .map_err(|_| "attestor_public not 32 bytes (64 hex)")?;
    let payload_b64 = obj
        .get("payload_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid payload_b64")?;
    let payload = b64_decode(payload_b64).ok_or("payload_b64 not valid standard base64")?;
    Ok(ProofRegistryEntry {
        binding_hex: binding_hex.to_string(),
        op_index,
        engine,
        attestor_public,
        payload,
    })
}

/// proof 注册表 sidecar 写端（追加模式；与 proven log 同写入纪律）。
pub struct ProofRegistryWriter {
    file: BufWriter<File>,
    /// true 时追加后 `sync_all`（数据 + 元数据真落盘）。
    fsync: bool,
    /// 一次写失败后置位（fail-closed：此后本实例不再追加——归档是
    /// 旁路优化，写失败只计告警计数，绝不影响证明管道主路径）。
    pub(crate) failed: bool,
}

impl ProofRegistryWriter {
    /// 打开（create + append；调用方负责目录存在）。
    ///
    /// # Errors
    /// 打开失败 → [`AppchainError::WalCorrupted`]。
    pub fn open(path: &Path) -> AppchainResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("proof registry open failed"))?;
        Ok(Self {
            file: BufWriter::new(file),
            fsync: false,
            failed: false,
        })
    }

    /// fsync 开关（builder 风格）：`true` = 每行追加后 `sync_all`。
    pub fn with_fsync(&mut self, enabled: bool) -> &mut Self {
        self.fsync = enabled;
        self
    }

    /// 追加一条契约记录（完整行 + 换行；flush；可选 fsync）。
    ///
    /// # Errors
    /// 写入/fsync 失败 → [`AppchainError::WalCorrupted`]。
    pub fn append(&mut self, entry: &ProofRegistryEntry) -> AppchainResult<()> {
        let line = encode_line(entry)?;
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.flush())
            .map_err(|_| AppchainError::WalCorrupted("proof registry write failed"))?;
        if self.fsync {
            self.file
                .get_ref()
                .sync_all()
                .map_err(|_| AppchainError::WalCorrupted("proof registry fsync failed"))?;
        }
        Ok(())
    }
}

/// 读取并解析 proof 注册表（模块文档的容错语义；撕裂尾行忽略 + eprintln 告警）。
///
/// # Errors
/// 文件不可读 / 非 utf-8 / 中间行违反冻结契约 → [`AppchainError::WalCorrupted`]。
pub fn read_registry(path: &Path) -> AppchainResult<Vec<ProofRegistryEntry>> {
    let bytes = std::fs::read(path)
        .map_err(|_| AppchainError::WalCorrupted("proof registry open failed"))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::WalCorrupted("proof registry not utf-8"))?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop(); // split 对换行结尾产生的空尾串
    } else {
        // 撕裂尾行：无换行结尾的最后一行一律忽略并告警（与 proven log 同口径）。
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                eprintln!(
                    "[poker-appchain::proof_registry] warning: torn final line \
                     ignored ({} bytes, no newline)",
                    tail.len()
                );
            }
            _ => {}
        }
    }
    let mut out: Vec<ProofRegistryEntry> = Vec::with_capacity(lines.len());
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_line(line).map_err(|why| {
            // 中间行违反冻结契约 → fail-closed（连续前缀承诺已破）
            AppchainError::Codec(format!("proof registry line {}: {why}", i + 1))
        })?;
        out.push(entry);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== base64：RFC 4648 §10 测试向量（encode 与 decode 对拍）=====

    #[test]
    fn b64_rfc4648_test_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (raw, expect) in cases {
            assert_eq!(&b64_encode(raw), expect, "encode {raw:?}");
            assert_eq!(b64_decode(expect).as_deref(), Some(*raw), "decode {expect}");
        }
    }

    #[test]
    fn b64_binary_roundtrip() {
        // 全 0..255 字节两轮拼接（覆盖 1/2/3 字节余数与全部字母表值）
        let data: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let enc = b64_encode(&data);
        assert_eq!(b64_decode(&enc).unwrap(), data);
        assert_eq!(
            b64_decode(&b64_encode(&enc.as_bytes())).unwrap(),
            enc.as_bytes()
        );
    }

    #[test]
    fn b64_decode_rejects_malformed() {
        // 长度非 4 倍数
        assert!(b64_decode("Zm9vY").is_none());
        // 非字母表字符
        assert!(b64_decode("Zm9*").is_none());
        assert!(b64_decode("Zm9v\n").is_none());
        // 填充形状非法
        assert!(b64_decode("A===").is_none());
        assert!(
            b64_decode("AAB=").is_none(),
            "non-canonical tail bits rejected"
        );
        assert_eq!(b64_decode("AAE=").as_deref(), Some(&[0u8, 1][..]));
        assert!(b64_decode("=AAA").is_none());
        assert!(b64_decode("AB=C").is_none());
        // 填充后缺数据位
        assert!(
            b64_decode("AQB=").is_none(),
            "non-canonical low bits rejected"
        );
        // URL-safe 字母表不接受（标准字母表之外）
        assert!(b64_decode("Zm9-").is_none());
    }

    // ===== 契约：编码行 / 解析 / 容错 =====

    fn sample_entry(binding: u8) -> ProofRegistryEntry {
        ProofRegistryEntry {
            binding_hex: hex::encode([binding; 32]),
            op_index: 42,
            engine: "host-validate-v2".to_string(),
            attestor_public: [0x77; 32],
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
        }
    }

    #[test]
    fn line_matches_frozen_contract_shape() {
        let line = encode_line(&sample_entry(0xAB)).unwrap();
        assert!(line.ends_with('\n'));
        let line = line.trim_end();
        assert_eq!(
            line,
            format!(
                "{{\"binding_hex\":\"{}\",\"op_index\":42,\"engine\":\"host-validate-v2\",\"attestor_public\":\"{}\",\"payload_b64\":\"{}\"}}",
                hex::encode([0xAB; 32]),
                hex::encode([0x77; 32]),
                "3q2+7wAB",
            ),
            "field order and encodings frozen"
        );
        let back = parse_line(line).unwrap();
        assert_eq!(back, sample_entry(0xAB));
    }

    #[test]
    fn empty_file_is_legal() {
        let dir = std::env::temp_dir().join("poker-appchain-proofreg-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "").unwrap();
        assert!(read_registry(&path).unwrap().is_empty());
    }

    #[test]
    fn writer_roundtrip_and_duplicate_binding_allowed() {
        let dir = std::env::temp_dir().join("poker-appchain-proofreg-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roundtrip.jsonl");
        let _ = std::fs::remove_file(&path);
        {
            let mut w = ProofRegistryWriter::open(&path).unwrap();
            w.with_fsync(false);
            w.append(&sample_entry(1)).unwrap();
            // 重复 binding 允许（幂等去重由读方处理）
            w.append(&sample_entry(1)).unwrap();
            w.append(&sample_entry(2)).unwrap();
        }
        let entries = read_registry(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].binding_hex, entries[1].binding_hex);
        assert_eq!(entries[2], sample_entry(2));
    }

    #[test]
    fn torn_tail_ignored_midfile_corrupt_rejected() {
        let dir = std::env::temp_dir().join("poker-appchain-proofreg-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let good1 = encode_line(&sample_entry(1)).unwrap();
        let good2 = encode_line(&sample_entry(2)).unwrap();

        // 撕裂尾行：截掉换行再补半行 → 读取成功（忽略残行），只剩完整行
        let path = dir.join("torn.jsonl");
        std::fs::write(&path, format!("{good1}{{\"binding_hex\":\"zz")).unwrap();
        let entries = read_registry(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], sample_entry(1));

        // 中间行损坏（完整行 + 坏行 + 换行结尾）→ Err
        let path = dir.join("midcorrupt.jsonl");
        std::fs::write(&path, format!("{good1}not-json\n{good2}")).unwrap();
        assert!(read_registry(&path).is_err());

        // 坏 base64（非法字符）→ Err
        let path = dir.join("badb64.jsonl");
        std::fs::write(
            &path,
            format!(
                "{{\"binding_hex\":\"{}\",\"op_index\":1,\"engine\":\"e\",\"attestor_public\":\"{}\",\"payload_b64\":\"**\"}}\n",
                hex::encode([3u8; 32]),
                hex::encode([4u8; 32]),
            ),
        )
        .unwrap();
        assert!(read_registry(&path).is_err());

        // 坏 hex（binding 短）→ Err
        let path = dir.join("badhex.jsonl");
        std::fs::write(
            &path,
            format!(
                "{{\"binding_hex\":\"aabb\",\"op_index\":1,\"engine\":\"e\",\"attestor_public\":\"{}\",\"payload_b64\":\"\"}}\n",
                hex::encode([4u8; 32]),
            ),
        )
        .unwrap();
        assert!(read_registry(&path).is_err());
    }

    #[test]
    fn engine_with_contract_violation_rejected() {
        let mut e = sample_entry(1);
        e.engine = "bad\"engine".to_string();
        assert!(encode_line(&e).is_err());
        e.engine = "bad\\engine".to_string();
        assert!(encode_line(&e).is_err());
        e.engine = "bad\u{7f}".to_string();
        assert!(encode_line(&e).is_err());
    }
}
