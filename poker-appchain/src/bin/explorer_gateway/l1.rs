//! explorer gateway — L1 JSON-RPC 只读代理客户端（std 手写，零新增依赖）。
//!
//! 传输路径（5s 连接/读写超时，全程 fail-closed）：
//! 1. **首选 HTTP/1.1 POST**：`TcpStream::connect_timeout` + 手写请求行/头
//!    （`Content-Length` 必带），响应按 `Content-Length` 或 chunked 解析；
//! 2. **回落 newline-delimited JSON-RPC**：zchain 节点（`src/main.rs`
//!    `handle_connection`）实际以"一行请求 / 一行响应"裸 TCP 协议服务，
//!    不说 HTTP。当路径 1 收不到合法 HTTP 响应时，新开连接发送
//!    `body + '\n'`、读单行响应。两种协议都打不通才算失败（→ 502）。
//!
//! 缓存：方法 + 参数为键的内存缓存，TTL 60 s（只读查询，幂等安全）。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 连接/读写超时。
const TIMEOUT: Duration = Duration::from_secs(5);
/// 缓存 TTL。
const CACHE_TTL: Duration = Duration::from_secs(60);
/// 响应体上限（16 MiB，防 OOM）。
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// L1 代理客户端（目标 = zchain 节点 RPC 监听地址）。
pub struct L1Client {
    host: String,
    port: u16,
    path: String,
    cache: Mutex<HashMap<String, (Instant, serde_json::Value)>>,
}

impl L1Client {
    /// 解析 `http://host:port[/path]`（仅 http；https 不支持——fail-closed）。
    ///
    /// # Errors
    /// URL 形状不合法或 scheme 非 http → Err。
    pub fn from_url(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| "l1-rpc url must start with http:// (https not supported)".to_string())?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        if hostport.is_empty() || hostport.contains(['/', '?', '#']) {
            return Err(format!("invalid l1-rpc url: {url}"));
        }
        let (host, port) = hostport
            .rsplit_once(':')
            .filter(|(_, p)| p.parse::<u16>().is_ok())
            .map(|(h, p)| (h.to_string(), p.parse::<u16>().expect("checked above")))
            .ok_or_else(|| format!("invalid l1-rpc host:port: {hostport}"))?;
        Ok(Self {
            host,
            port,
            path,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// 目标 `host:port`（日志用）。
    #[must_use]
    pub fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// 调用（带 60s 缓存）。失败返回描述性 Err（映射为 502）。
    pub fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let cache_key = format!("{method}:{params}");
        if let Some(v) = self.cache_get(&cache_key) {
            return Ok(v);
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();
        let resp_text = self.post_http(&body).or_else(|http_err| {
            self.post_newline(&body)
                .map_err(|nl_err| format!("http: {http_err}; newline-rpc: {nl_err}"))
        })?;
        let result = parse_rpc_response(&resp_text)?;
        self.cache_put(cache_key, result.clone());
        Ok(result)
    }

    fn cache_get(&self, key: &str) -> Option<serde_json::Value> {
        let mut map = self.cache.lock().expect("l1 cache lock");
        if let Some((at, v)) = map.get(key) {
            if at.elapsed() < CACHE_TTL {
                return Some(v.clone());
            }
        }
        map.retain(|_, (at, _)| at.elapsed() < CACHE_TTL);
        None
    }

    fn cache_put(&self, key: String, v: serde_json::Value) {
        let mut map = self.cache.lock().expect("l1 cache lock");
        map.insert(key, (Instant::now(), v));
    }

    /// 连接（解析 DNS，5s connect_timeout）。
    fn connect(&self) -> Result<TcpStream, String> {
        let addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| format!("resolve {}: {e}", self.host))?
            .collect::<Vec<_>>();
        let mut last = "no address".to_string();
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, TIMEOUT) {
                Ok(s) => {
                    let _ = s.set_read_timeout(Some(TIMEOUT));
                    let _ = s.set_write_timeout(Some(TIMEOUT));
                    return Ok(s);
                }
                Err(e) => last = format!("connect {addr}: {e}"),
            }
        }
        Err(last)
    }

    /// 路径 1：HTTP/1.1 POST（手写请求头；响应按 Content-Length / chunked 解析）。
    ///
    /// 快速失败：先读状态行，非 `HTTP/` 前缀（newline 协议节点对 POST 行
    /// 回 JSON）立即 Err 触发回落——不付整个 body 读取的 5s 超时代价。
    fn post_http(&self, body: &str) -> Result<String, String> {
        let mut stream = self.connect()?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.path,
            self.host,
            self.port,
            body.len()
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|e| format!("read: {e}"))?;
        if status_line.is_empty() {
            return Err("connection closed without response".to_string());
        }
        if !status_line.starts_with("HTTP/") {
            return Err(format!(
                "not an http response: {:.40}",
                status_line.trim()
            ));
        }
        let mut raw = status_line.into_bytes();
        reader
            .take(MAX_RESPONSE as u64)
            .read_to_end(&mut raw)
            .map_err(|e| format!("read: {e}"))?;
        parse_http_response(&raw)
    }

    /// 路径 2：newline-delimited JSON-RPC（zchain 节点原生协议）。
    fn post_newline(&self, body: &str) -> Result<String, String> {
        let mut stream = self.connect()?;
        stream
            .write_all(body.as_bytes())
            .and_then(|_| stream.write_all(b"\n"))
            .and_then(|_| stream.flush())
            .map_err(|e| format!("write: {e}"))?;
        let reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .take(MAX_RESPONSE as u64)
            .read_line(&mut line)
            .map_err(|e| format!("read: {e}"))?;
        if line.is_empty() {
            return Err("connection closed without response".to_string());
        }
        Ok(line)
    }
}

/// 解析 HTTP 响应（状态行 + 头 + Content-Length/chunked/EOF 三种体定界）。
fn parse_http_response(raw: &[u8]) -> Result<String, String> {
    let header_end = find_subslice(raw, b"\r\n\r\n").ok_or("no header terminator")?;
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| "non-utf8 head".to_string())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    // 非 HTTP 响应（如 newline 协议节点直接回 JSON 行）→ 触发回落。
    if !status_line.starts_with("HTTP/") {
        return Err(format!("not an http response: {status_line:.40}"));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("bad status line")?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if k == "content-length" {
            content_length = v.parse().ok();
        } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }
    let body_bytes = &raw[header_end + 4..];
    let body = if chunked {
        decode_chunked(body_bytes)?
    } else if let Some(n) = content_length {
        if n > body_bytes.len() {
            return Err(format!("truncated body (want {n}, got {})", body_bytes.len()));
        }
        body_bytes[..n].to_vec()
    } else {
        body_bytes.to_vec() // Connection: close 定界
    };
    if status >= 400 {
        return Err(format!("http status {status}"));
    }
    String::from_utf8(body).map_err(|_| "non-utf8 body".to_string())
}

/// chunked 传输解码。
fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(body, b"\r\n").ok_or("bad chunk header")?;
        let size_str = std::str::from_utf8(&body[..line_end]).map_err(|_| "bad chunk size")?;
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| "bad chunk size hex")?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size {
            return Err("truncated chunk".to_string());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size..];
        if body.starts_with(b"\r\n") {
            body = &body[2..];
        }
    }
}

/// 子串查找。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// 解析 JSON-RPC 响应文本：error → Err；缺 result → Err。
fn parse_rpc_response(text: &str) -> Result<serde_json::Value, String> {
    let v: serde_json::Value = serde_json::from_str(text.trim()).map_err(|e| {
        format!("invalid json-rpc response: {e}")
    })?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc error: {err}"));
    }
    match v.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err("json-rpc response missing result".to_string()),
    }
}
