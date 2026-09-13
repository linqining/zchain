//! M8 安全：KeyProvider——sequencer / attestor 密钥的**可插拔注入**接缝。
//!
//! ## 背景（外部评审建议 4，加重项）
//!
//! 此前生产侧没有密钥注入接缝：[`crate::keys::SequencerKey::from_seed`]
//! 是唯一构造原语，"从环境/文件/远程取真实密钥"的装配得各调用方自己拼，
//! 事实上鼓励了"测试种子进生产"。本模块把密钥来源抽象为 [`KeyProvider`]
//! 的三个实现，并在 crate 内提供唯一合规的取钥通道：
//!
//! - [`EnvKeyProvider`]：环境变量注入（替代确定性种子派生的生产主路径）；
//! - [`FileKeyProvider`]：密钥文件注入（含 Unix 权限过宽拒绝）；
//! - [`RemoteKeyProvider`]：KMS 外部端点接缝（最小 HTTP 客户端，无云 SDK）。
//!
//! ## fail-closed 纪律（无默认种子回退）
//!
//! - 三个实现的取钥失败一律 `Err`：变量缺失 / 文件缺失或权限过宽 / 端点
//!   超时或坏响应，**不存在任何"开发默认种子"回退路径**；
//! - 全零 32B 种子一律拒绝（对齐 poker_l1 §7.5"全零私钥拒绝"纪律，
//!   见 docs/37-1-node-deployment.md）；
//! - [`from_config`] 对未配置 / 未知 provider 种类一律 `Err`（不存在
//!   `Default` 实现——`KeyProvider` 刻意不可凭空构造）。
//!
//! 生产装配点写法（不改 [`crate::sequencer::Sequencer`] 签名）：
//!
//! ```ignore
//! use poker_appchain::key_provider::{from_config, SequencerKeyExt};
//! let provider = from_config("ZCHAIN")?;            // fail-closed
//! let seq_key = SequencerKey::from_provider(provider.as_ref())?;
//! let attestor = provider.attestor_signing_key()?;
//! let mut seq = Sequencer::new(seq_key, config, metrics);   // 生产
//! let engine = ValidationEngine::new(attestor);             // 生产
//! ```
//!
//! 测试/重放兼容：单元与集成测试仍可用 `SequencerKey::from_seed`（测试
//! 工具保留，如 `bin/loadtest` 的固定种子）；`Sequencer::replay` 只需
//! 公钥，签名不经过它——其内部的占位 signing key 不构成生产回退路径
//! （见 `sequencer.rs` 中该行的文档注明）。
//!
//! ## 诚实边界（如实标注的降级点）
//!
//! - **TLS**：std `TcpStream` 无 TLS；[`RemoteKeyProvider`] 只讲明文
//!   HTTP，对 `https://` 端点**拒绝启动**（fail-closed：无法校验证书就
//!   不假装安全）。生产接入真 KMS 时在部署侧放一个本机 TLS 终结代理
//!   （sidecar，如 `127.0.0.1:<port>`），provider 指向它；证书策略属
//!   部署工程。AWS KMS / HSM 等云厂商鉴权（SigV4、IAM 等）同理——本
//!   trait 只是接缝，适配层属部署工程。
//! - **内存驻留**：本 crate 依赖图未启用 `zeroize`（零新依赖纪律），
//!   密钥字节 drop 后不清零。缓解：provider 只在构造时短暂经手原始
//!   字节，进程长期驻留的是 `ed25519_dalek::SigningKey` / `SequencerKey`
//!   本体（与 v1 现状一致，非本模块引入的新暴露面）。
//! - **错误映射**：v1 错误枚举不加新变体（改动最小化），一切取钥失败
//!   映射为 [`AppchainError::Codec`]，消息统一带 `key provider: ` 前缀。

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{AppchainError, AppchainResult};
use crate::keys::SequencerKey;

/// 远程端点响应体的读取上限（字节）：密钥响应 <= 数百字节，超限即视为
/// 恶意/错配端点（fail-closed，防无限读）。
const REMOTE_RESPONSE_CAP: usize = 4096;

/// [`from_config`] 未指定超时时的远程取钥默认超时。
const DEFAULT_REMOTE_TIMEOUT_MS: u64 = 3_000;

/// 密钥注入提供者：sequencer 软确认链签名密钥 + attestor 签名密钥的
/// 统一取钥接缝。
///
/// 实现纪律：
/// - 两个方法都应是**取钥即取**（每次调用重新取，支持外部轮换后热换钥
///   的装配方重建实例）；实现内部**禁止**缓存明文种子超过单次取钥所需；
/// - 一切失败返回 `Err`（[`AppchainError::Codec`] + `key provider: ` 前
///   缀），**禁止**回退到任何常量种子（这是本模块存在的全部意义）。
pub trait KeyProvider {
    /// 取 sequencer 软确认链签名密钥（ed25519）。
    ///
    /// # Errors
    /// 取钥/解析/校验失败 → [`AppchainError::Codec`]（fail-closed）。
    fn sequencer_key(&self) -> AppchainResult<SequencerKey>;

    /// 取 attestor 签名密钥（ed25519；经
    /// [`crate::pipeline::ValidationEngine::new`] 注入证明管道）。
    ///
    /// # Errors
    /// 取钥/解析/校验失败 → [`AppchainError::Codec`]（fail-closed）。
    fn attestor_signing_key(&self) -> AppchainResult<ed25519_dalek::SigningKey>;
}

/// 便捷构造：从 provider 取钥构造 [`SequencerKey`]（生产装配点的一行
/// 接线；本 crate 内对 `SequencerKey` 的唯一新增 API，v1 既有
/// `from_seed` 语义不变）。
///
/// # Errors
/// provider 取钥失败 → 原样透传（fail-closed，无回退）。
pub trait SequencerKeyExt {
    /// 从 provider 取 sequencer 密钥。
    ///
    /// # Errors
    /// 见 [`KeyProvider::sequencer_key`]。
    fn from_provider(provider: &dyn KeyProvider) -> AppchainResult<SequencerKey>;
}

impl SequencerKeyExt for SequencerKey {
    fn from_provider(provider: &dyn KeyProvider) -> AppchainResult<SequencerKey> {
        provider.sequencer_key()
    }
}

/// 解析 32B 密钥种子：64 hex 字符（容忍首尾空白），全零拒绝。
///
/// # Errors
/// 非 hex / 长度错 / 全零 → [`AppchainError::Codec`]。
fn parse_seed_hex(s: &str) -> AppchainResult<[u8; 32]> {
    let trimmed = s.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|_| AppchainError::Codec("key provider: key is not valid hex".to_string()))?;
    let decoded_len = bytes.len();
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        AppchainError::Codec(format!(
            "key provider: key must be 32 bytes (64 hex chars), got {decoded_len} bytes"
        ))
    })?;
    reject_zero_seed(&seed)?;
    Ok(seed)
}

/// 全零种子拒绝（poker_l1 §7.5 同款纪律：全零"密钥"不是密钥）。
///
/// # Errors
/// 全零 → [`AppchainError::Codec`]。
fn reject_zero_seed(seed: &[u8; 32]) -> AppchainResult<()> {
    if seed.iter().all(|&b| b == 0) {
        return Err(AppchainError::Codec(
            "key provider: all-zero seed rejected".to_string(),
        ));
    }
    Ok(())
}

/// 从密钥 blob（hex 或 base64 编码的 32B）解析种子：远程端点响应与
/// 文件内容共用（hex 优先，base64 兜底）。
///
/// # Errors
/// 两种编码都解不出 32B 非零种子 → [`AppchainError::Codec`]。
fn decode_key_blob(body: &str) -> AppchainResult<[u8; 32]> {
    let trimmed = body.trim();
    // hex 优先（64 hex 字符）；base64 兜底（44 字符含 padding）。
    if let Ok(seed) = parse_seed_hex(trimmed) {
        return Ok(seed);
    }
    let bytes = base64_decode(trimmed).ok_or_else(|| {
        AppchainError::Codec(
            "key provider: key blob is neither 64-char hex nor base64 of 32 bytes".to_string(),
        )
    })?;
    let decoded_len = bytes.len();
    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        AppchainError::Codec(format!(
            "key provider: decoded key must be 32 bytes, got {decoded_len}"
        ))
    })?;
    reject_zero_seed(&seed)?;
    Ok(seed)
}

/// 最小 base64 解码（标准字母表，容忍 padding 缺省；零新依赖）。
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let compact: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if compact.len() % 4 == 1 || compact.len() < 2 {
        return None;
    }
    let mut out = Vec::with_capacity(compact.len() / 4 * 3 + 3);
    for chunk in compact.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if chunk.len() > 2 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

// ===== 实现 1：环境变量注入 =====

/// 环境变量密钥提供者（生产主路径，替代确定性种子派生）。
///
/// 变量名可配（默认前缀 `ZCHAIN`，对齐 poker_l1 的 `ZCHAIN_VALIDATOR_KEY`
/// 口径）：`{prefix}_SEQUENCER_KEY_HEX` / `{prefix}_ATTESTOR_KEY_HEX`，
/// 内容 = 32B hex（全零拒绝）。
///
/// fail-closed：变量缺失 / 非 hex / 长度错 → `Err`，**不回退到固定种子**。
#[derive(Debug, Clone)]
pub struct EnvKeyProvider {
    sequencer_var: String,
    attestor_var: String,
}

impl EnvKeyProvider {
    /// 用默认变量名构造：`{prefix}_SEQUENCER_KEY_HEX` /
    /// `{prefix}_ATTESTOR_KEY_HEX`。
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self {
            sequencer_var: format!("{prefix}_SEQUENCER_KEY_HEX"),
            attestor_var: format!("{prefix}_ATTESTOR_KEY_HEX"),
        }
    }

    /// 显式指定变量名（测试 / 非标准命名空间部署用）。
    #[must_use]
    pub fn with_vars(sequencer_var: String, attestor_var: String) -> Self {
        Self {
            sequencer_var,
            attestor_var,
        }
    }

    /// 读单个密钥变量（缺失 → Err，fail-closed）。
    ///
    /// # Errors
    /// 变量缺失或非 32B hex → [`AppchainError::Codec`]。
    fn read_var(&self, var: &str) -> AppchainResult<[u8; 32]> {
        let value = std::env::var(var).map_err(|_| {
            AppchainError::Codec(format!(
                "key provider: environment variable {var} is not set \
                 (fail-closed: no default key source exists; export a 32-byte \
                 hex seed or use a file/remote provider)"
            ))
        })?;
        parse_seed_hex(&value).map_err(|e| append_var_context(e, &format!("env var {var}")))
    }
}

fn append_var_context(e: AppchainError, context: &str) -> AppchainError {
    match e {
        AppchainError::Codec(msg) => AppchainError::Codec(format!("{msg} [{context}]")),
        other => other,
    }
}

impl KeyProvider for EnvKeyProvider {
    fn sequencer_key(&self) -> AppchainResult<SequencerKey> {
        let seed = self.read_var(&self.sequencer_var)?;
        Ok(SequencerKey::from_seed(&seed))
    }

    fn attestor_signing_key(&self) -> AppchainResult<ed25519_dalek::SigningKey> {
        let seed = self.read_var(&self.attestor_var)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
}

// ===== 实现 2：密钥文件注入 =====

/// 密钥文件提供者：从两个本地文件读 32B 种子（`zchain keygen` JSON 的
/// `secret_key_hex` 字段或裸 64-char hex——与 `seq_key_rotate` 同款双形态）。
///
/// Unix 权限校验（fail-closed）：文件 mode 的 group/other 位非零（如
/// `0644`）→ 拒绝并提示 `chmod 600`。密钥文件谁都能读 = 等于写在墙上。
#[derive(Debug, Clone)]
pub struct FileKeyProvider {
    sequencer_path: PathBuf,
    attestor_path: PathBuf,
}

impl FileKeyProvider {
    /// 指定 sequencer / attestor 密钥文件路径构造。
    #[must_use]
    pub fn new(sequencer_path: PathBuf, attestor_path: PathBuf) -> Self {
        Self {
            sequencer_path,
            attestor_path,
        }
    }

    /// 读单个密钥文件（读 → 权限校验 → 解析，顺序无关紧要，全部通过才算）。
    ///
    /// # Errors
    /// 文件缺失 / 不可读 / 权限过宽 / 内容非法 → [`AppchainError::Codec`]。
    fn read_file(&self, path: &std::path::Path) -> AppchainResult<[u8; 32]> {
        let meta = std::fs::metadata(path).map_err(|_| {
            AppchainError::Codec(format!(
                "key provider: key file {} unreadable (missing or no permission)",
                path.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(AppchainError::Codec(format!(
                    "key provider: key file {} permissions too wide (mode {:04o}); \
                     group/other must have no access — chmod 600 {}",
                    path.display(),
                    mode & 0o7777,
                    path.display()
                )));
            }
        }
        #[cfg(not(unix))]
        {
            // 非 Unix：无 POSIX mode 可查；权限边界由部署平台自行保证
            // （文档化降级：本实现在此平台不做权限校验）。
            let _ = meta;
        }
        let text = std::fs::read_to_string(path).map_err(|_| {
            AppchainError::Codec(format!(
                "key provider: key file {} unreadable",
                path.display()
            ))
        })?;
        parse_key_file_content(&text)
            .map_err(|e| append_var_context(e, &format!("file {}", path.display())))
    }
}

/// 解析密钥文件内容：`zchain keygen` JSON（`secret_key_hex` 字段）或裸
/// 32B hex（与 `bin/seq_key_rotate.rs` 的读取纪律同款）。
///
/// # Errors
/// 两种形态都不成立 → [`AppchainError::Codec`]。
fn parse_key_file_content(text: &str) -> AppchainResult<[u8; 32]> {
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(Some(sk)) = v.get("secret_key_hex").map(serde_json::Value::as_str)
    {
        return parse_seed_hex(sk);
    }
    parse_seed_hex(trimmed)
}

impl KeyProvider for FileKeyProvider {
    fn sequencer_key(&self) -> AppchainResult<SequencerKey> {
        let seed = self.read_file(&self.sequencer_path)?;
        Ok(SequencerKey::from_seed(&seed))
    }

    fn attestor_signing_key(&self) -> AppchainResult<ed25519_dalek::SigningKey> {
        let seed = self.read_file(&self.attestor_path)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
}

// ===== 实现 3：远程 KMS 端点接缝 =====

/// 远程密钥端点提供者（KMS 接缝，**无云 SDK**）。
///
/// 协议契约（最小可用面）：对可配端点做 `HTTP POST`，请求体为
/// `{"key_id":"<id>"}`；端点返回 `2xx`，响应体 = 32B 种子的 hex（64 字符）
/// 或 base64 编码。超时可配（默认 3s），读超时 / 连接失败 / 非 2xx /
/// 坏响应体一律 `Err`。
///
/// **安全边界（如实标注）**：只支持 `http://` 明文端点——`https://` 在
/// 构造时即拒绝（std 无 TLS，无法校验证书就不假装安全）。生产必须在本
/// 机 sidecar 终结 TLS 后转发（provider 指向 `http://127.0.0.1:<port>`）；
/// 云 KMS（AWS KMS 等）的鉴权适配属部署工程，本类型只是接缝。
#[derive(Debug, Clone)]
pub struct RemoteKeyProvider {
    endpoint: String,
    timeout: Duration,
    sequencer_key_id: String,
    attestor_key_id: String,
}

impl RemoteKeyProvider {
    /// 构造。`endpoint` 仅接受 `http://host[:port]/path`（`https://` 拒绝，
    /// 见类型文档）。
    ///
    /// # Errors
    /// endpoint 非 `http://` → [`AppchainError::Codec`]（fail-closed）。
    pub fn new(
        endpoint: &str,
        timeout: Duration,
        sequencer_key_id: &str,
        attestor_key_id: &str,
    ) -> AppchainResult<Self> {
        if !endpoint.starts_with("http://") {
            return Err(AppchainError::Codec(
                "key provider: remote endpoint must be http:// (std seam has no \
                 TLS; terminate https at a local sidecar and point this provider \
                 at it — certificate policy is deployment engineering)"
                    .to_string(),
            ));
        }
        Ok(Self {
            endpoint: endpoint.to_string(),
            timeout,
            sequencer_key_id: sequencer_key_id.to_string(),
            attestor_key_id: attestor_key_id.to_string(),
        })
    }

    /// POST 取一把密钥并解析成 32B 种子。
    ///
    /// # Errors
    /// 连接失败 / 超时 / 非 2xx / 坏响应体 → [`AppchainError::Codec`]。
    fn fetch_key(&self, key_id: &str) -> AppchainResult<[u8; 32]> {
        let body = self.http_post(key_id)?;
        decode_key_blob(&body)
    }

    /// 最小 HTTP 客户端（std `TcpStream`）：POST `{"key_id":..}`，读一个
    /// 完整响应（Content-Length 满足 / EOF / 超时三者先到为准），返回
    /// 响应体字符串。
    ///
    /// # Errors
    /// URL 非法 / 连接失败 / 读写超时 / 响应超限 / 非 2xx →
    /// [`AppchainError::Codec`]。
    fn http_post(&self, key_id: &str) -> AppchainResult<String> {
        // URL 拆解：http://host[:port]/path
        let rest = self
            .endpoint
            .strip_prefix("http://")
            .ok_or_else(|| AppchainError::Codec("key provider: endpoint must be http://".into()))?;
        let (host_port, path) = match rest.split_once('/') {
            Some((h, p)) => (h, format!("/{p}")),
            None => (rest, "/".to_string()),
        };
        let default_port = if let Some(h) = host_port.strip_prefix('[') {
            // IPv6 字面量 [::1]:8080
            let (h, p) = h
                .split_once(']')
                .ok_or_else(|| AppchainError::Codec("key provider: bad ipv6 endpoint".into()))?;
            let port: u16 = p
                .strip_prefix(':')
                .and_then(|x| x.parse().ok())
                .unwrap_or(80);
            (h.to_string(), port)
        } else {
            match host_port.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse()
                        .map_err(|_| AppchainError::Codec("key provider: bad port".into()))?,
                ),
                None => (host_port.to_string(), 80),
            }
        };
        let addrs: Vec<SocketAddr> = (default_port.0.as_str(), default_port.1)
            .to_socket_addrs()
            .map_err(|e| AppchainError::Codec(format!("key provider: dns resolve failed: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(AppchainError::Codec(
                "key provider: endpoint resolved to no addresses".into(),
            ));
        }
        let body = format!("{{\"key_id\":\"{key_id}\"}}");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut last_err: Option<String> = None;
        for addr in &addrs {
            let mut stream = match TcpStream::connect_timeout(addr, self.timeout) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("connect {} failed: {e}", addr));
                    continue;
                }
            };
            stream
                .set_read_timeout(Some(self.timeout))
                .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
                .map_err(|e| AppchainError::Codec(format!("key provider: set timeout: {e}")))?;
            use std::io::{Read as _, Write as _};
            if let Err(e) = stream.write_all(request.as_bytes()) {
                last_err = Some(format!("write failed: {e}"));
                continue;
            }
            // 读响应：Content-Length 满足 / EOF / 超时三者先到为准。
            let mut raw: Vec<u8> = Vec::with_capacity(1024);
            let mut chunk = [0u8; 1024];
            let mut read_err: Option<String> = None;
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        if raw.len() > REMOTE_RESPONSE_CAP {
                            return Err(AppchainError::Codec(
                                "key provider: remote response exceeds size cap (not a key endpoint?)"
                                    .into(),
                            ));
                        }
                        if complete_http_body(&raw).is_some() {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        if complete_http_body(&raw).is_some() {
                            break; // 超时前已收到完整响应
                        }
                        return Err(AppchainError::Codec(format!(
                            "key provider: remote endpoint timed out after {} ms \
                             (fail-closed)",
                            self.timeout.as_millis()
                        )));
                    }
                    Err(e) => {
                        read_err = Some(format!("read failed: {e}"));
                        break;
                    }
                }
            }
            // 响应不完整且底层读失败 → 报读失败原因（而不是误报"格式坏"）。
            if complete_http_body(&raw).is_none()
                && let Some(msg) = read_err
            {
                return Err(AppchainError::Codec(format!(
                    "key provider: remote endpoint {msg} (fail-closed)"
                )));
            }
            return parse_http_body(&raw);
        }
        Err(AppchainError::Codec(format!(
            "key provider: remote endpoint unreachable ({})",
            last_err.unwrap_or_else(|| "unknown".into())
        )))
    }
}

/// 若 `raw` 已含完整响应体则返回 `(头部长度, 体切片长度)` 形态的边界，
/// 否则 `None`。
fn complete_http_body(raw: &[u8]) -> Option<usize> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let headers = std::str::from_utf8(&raw[..header_end]).ok()?;
    let mut content_length: Option<usize> = None;
    for line in headers.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok();
        }
    }
    let body_len = content_length?;
    if raw.len() >= header_end + body_len {
        Some(header_end + body_len)
    } else {
        None
    }
}

/// 从原始 HTTP 响应字节提取校验过的 2xx 响应体。
///
/// # Errors
/// 非法响应行 / 非 2xx / 响应体缺失 → [`AppchainError::Codec`]。
fn parse_http_body(raw: &[u8]) -> AppchainResult<String> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| AppchainError::Codec("key provider: response is not utf-8".into()))?;
    let mut parts = text.splitn(2, "\r\n\r\n");
    let headers = parts
        .next()
        .ok_or_else(|| AppchainError::Codec("key provider: malformed http response".into()))?;
    let body_all = parts
        .next()
        .ok_or_else(|| AppchainError::Codec("key provider: http response has no body".into()))?;
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| AppchainError::Codec("key provider: empty http response".into()))?;
    let code: u32 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| AppchainError::Codec("key provider: unreadable http status line".into()))?;
    if !(200..300).contains(&code) {
        return Err(AppchainError::Codec(format!(
            "key provider: remote endpoint returned http {code} (fail-closed)"
        )));
    }
    // 按 Content-Length 截断（有的话），避免半途截断的噪声进解析器。
    let body = match complete_http_body(raw) {
        Some(end) => {
            let header_end = text.len() - body_all.len();
            text.get(header_end..end).ok_or_else(|| {
                AppchainError::Codec("key provider: response body boundary invalid".into())
            })?
        }
        None => body_all,
    };
    Ok(body.to_string())
}

impl KeyProvider for RemoteKeyProvider {
    fn sequencer_key(&self) -> AppchainResult<SequencerKey> {
        let seed = self.fetch_key(&self.sequencer_key_id)?;
        Ok(SequencerKey::from_seed(&seed))
    }

    fn attestor_signing_key(&self) -> AppchainResult<ed25519_dalek::SigningKey> {
        let seed = self.fetch_key(&self.attestor_key_id)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }
}

// ===== 工厂 =====

/// 按配置选择 provider（`KeyProvider::from_config` 工厂；v1 错误枚举不
/// 加变体，失败一律 [`AppchainError::Codec`]）。
///
/// 配置（环境变量，`prefix` 默认用 `ZCHAIN`）：
///
/// | 变量 | 语义 |
/// |---|---|
/// | `{prefix}_KEY_PROVIDER` | `env` / `file` / `remote`（必填，缺失或未知值一律 Err——**无默认**） |
/// | `{prefix}_SEQUENCER_KEY_HEX` / `{prefix}_ATTESTOR_KEY_HEX` | `env` 模式的两把 32B hex 种子 |
/// | `{prefix}_SEQUENCER_KEY_FILE` / `{prefix}_ATTESTOR_KEY_FILE` | `file` 模式的两个密钥文件路径（必填） |
/// | `{prefix}_KMS_ENDPOINT` / `{prefix}_KMS_SEQUENCER_KEY_ID` / `{prefix}_KMS_ATTESTOR_KEY_ID` | `remote` 模式端点与 key id（必填） |
/// | `{prefix}_KMS_TIMEOUT_MS` | `remote` 模式超时（可选，默认 3000） |
///
/// # Errors
/// 未配置 / 未知种类 / 所需变量缺失 → [`AppchainError::Codec`]（fail-closed）。
pub fn from_config(prefix: &str) -> AppchainResult<Box<dyn KeyProvider>> {
    let kind_var = format!("{prefix}_KEY_PROVIDER");
    let kind = std::env::var(&kind_var).map_err(|_| {
        AppchainError::Codec(format!(
            "key provider: {kind_var} is not set (expected env | file | remote); \
             refusing to fall back to any default key source"
        ))
    })?;
    match kind.trim() {
        "env" => Ok(Box::new(EnvKeyProvider::new(prefix))),
        "file" => {
            let seq_var = format!("{prefix}_SEQUENCER_KEY_FILE");
            let att_var = format!("{prefix}_ATTESTOR_KEY_FILE");
            let seq_path = env_path(&seq_var)?;
            let att_path = env_path(&att_var)?;
            Ok(Box::new(FileKeyProvider::new(seq_path, att_path)))
        }
        "remote" => {
            let endpoint_var = format!("{prefix}_KMS_ENDPOINT");
            let endpoint = std::env::var(&endpoint_var).map_err(|_| {
                AppchainError::Codec(format!(
                    "key provider: {endpoint_var} is not set (required for remote provider)"
                ))
            })?;
            let seq_id = require_var(&format!("{prefix}_KMS_SEQUENCER_KEY_ID"))?;
            let att_id = require_var(&format!("{prefix}_KMS_ATTESTOR_KEY_ID"))?;
            let timeout = match std::env::var(format!("{prefix}_KMS_TIMEOUT_MS")) {
                Ok(v) => {
                    let ms: u64 = v.trim().parse().map_err(|_| {
                        AppchainError::Codec(format!(
                            "key provider: {prefix}_KMS_TIMEOUT_MS={v:?} is not a u64"
                        ))
                    })?;
                    Duration::from_millis(ms)
                }
                Err(_) => Duration::from_millis(DEFAULT_REMOTE_TIMEOUT_MS),
            };
            Ok(Box::new(RemoteKeyProvider::new(
                endpoint.trim(),
                timeout,
                seq_id.trim(),
                att_id.trim(),
            )?))
        }
        other => Err(AppchainError::Codec(format!(
            "key provider: {kind_var}={other:?} is not one of env | file | remote \
             (no dev/test/default provider exists — fail-closed)"
        ))),
    }
}

/// 读路径型配置变量（缺失 → Err）。
///
/// # Errors
/// 变量缺失 → [`AppchainError::Codec`]。
fn env_path(var: &str) -> AppchainResult<PathBuf> {
    Ok(PathBuf::from(require_var(var)?))
}

/// 读必填字符串配置变量（缺失 → Err）。
///
/// # Errors
/// 变量缺失 → [`AppchainError::Codec`]。
fn require_var(var: &str) -> AppchainResult<String> {
    std::env::var(var).map_err(|_| {
        AppchainError::Codec(format!(
            "key provider: {var} is not set (required by selected provider; fail-closed)"
        ))
    })
}

// 注：env 变量相关的行为测试在 `tests/key_provider.rs`（独立测试 crate）
// ——edition 2024 里 `env::set_var` 是 unsafe，而本 crate 顶部
// `#![deny(unsafe_code)]` 覆盖 lib 内测试模块，集成测试 crate 无此约束。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrip() {
        // "AAAA" = 24 bit 全零 = 3 个 0 字节。
        assert_eq!(base64_decode("AAAA").as_deref(), Some(&[0u8, 0, 0][..]));
        // "AQIDBA==" → 01 02 03 04
        assert_eq!(
            base64_decode("AQIDBA==").as_deref(),
            Some(&[1u8, 2, 3, 4][..])
        );
        // 无 padding 也接受（6 字符 = 4 字节，尾部 4 bit 丢弃）。
        assert_eq!(
            base64_decode("AQIDBA").as_deref(),
            Some(&[1u8, 2, 3, 4][..])
        );
        assert!(base64_decode("!!!!").is_none());
        // 0x5e × 32 的标准编码 ↔ 字节逐位一致（与远程测试用例同源）。
        let b64 = "Xl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl4=";
        assert_eq!(base64_decode(b64).as_deref(), Some(&[0x5eu8; 32][..]));
    }

    #[test]
    fn zero_seed_rejected() {
        assert!(parse_seed_hex(&"0".repeat(64)).is_err());
        assert!(decode_key_blob(&"00".repeat(32)).is_err());
    }

    #[test]
    fn https_endpoint_rejected() {
        let e = RemoteKeyProvider::new("https://kms.example.com", Duration::from_secs(1), "s", "a");
        assert!(e.is_err(), "https must be rejected (no TLS in std seam)");
    }
}
