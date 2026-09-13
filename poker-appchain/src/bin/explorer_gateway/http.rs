//! explorer gateway — 极简 HTTP/1.1 服务端（std 库手写，零新增依赖）。
//!
//! 只读 JSON API 的传输层：
//! - 请求解析带硬上限（请求行 8 KiB / 头块 16 KiB），超限一律 400；
//! - 响应统一带 `X-Zchain-Gateway: replay-v1`；`status`/`frames` 附带
//!   `Cache-Control: max-age=5`；`--public` 时附带 `Access-Control-Allow-Origin: *`；
//! - 连接语义：一请求一响应后关闭（`Connection: close`），不实现 keep-alive
//!   ——浏览器/`fetch`/`curl` 对此透明；
//! - 读超时 5 s（慢速攻击者不会长期占住线程；超时连接直接丢弃）。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// 请求行长度上限（字节）。
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// 整个头块（含请求行）长度上限（字节）。
pub const MAX_HEADER_BLOCK: usize = 16 * 1024;
/// socket 读超时。
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// 解析后的请求（本网关只关心方法 / 路径 / 查询串）。
#[derive(Debug)]
pub struct Request {
    /// 方法（大写规范化，如 `GET`）。
    pub method: String,
    /// 不含查询串的路径（已做最小 percent-decode）。
    pub path: String,
    /// 查询串键值（重复键取首值；解码失败即整体解析失败）。
    pub query: HashMap<String, String>,
}

/// 解析失败的语义（映射 HTTP 状态码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// 请求行/头块超长或格式坏（携带响应状态码）。
    Bad(u16),
    /// 客户端在超时内未发出完整头（连接空转）。
    TimedOut,
    /// 连接被对端关闭（静默丢弃，不回错误）。
    Closed,
}

/// 从连接读取并解析一个请求（头块为止；不读 body——非 GET 一律 405 后关闭）。
pub fn read_request(stream: &TcpStream) -> Result<Request, ParseError> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|_| ParseError::Bad(400))?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|_| ParseError::Bad(400))?);
    let mut block = Vec::with_capacity(512);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    ParseError::TimedOut
                }
                std::io::ErrorKind::UnexpectedEof => ParseError::Closed,
                _ => ParseError::Bad(400),
            })?;
        if n == 0 {
            return Err(ParseError::Closed);
        }
        block.push(line.clone());
        if block.iter().map(String::len).sum::<usize>() > MAX_HEADER_BLOCK {
            return Err(ParseError::Bad(400));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // 头块结束
        }
    }
    parse_head_block(&block)
}

/// 解析头块（首行 = 请求行；其余行仅用于长度约束——本网关不需要任何请求头）。
fn parse_head_block(block: &[String]) -> Result<Request, ParseError> {
    let request_line = block
        .first()
        .map(String::as_str)
        .unwrap_or("")
        .trim_end_matches(['\r', '\n']);
    if request_line.len() > MAX_REQUEST_LINE {
        return Err(ParseError::Bad(400));
    }
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(ParseError::Bad(400))?
        .to_ascii_uppercase();
    let target = parts.next().ok_or(ParseError::Bad(400))?;
    // HTTP 版本不校验（HTTP/1.0 无 Host 亦接受——只读接口，宽容无害）。
    let (raw_path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    let path = percent_decode(raw_path).ok_or(ParseError::Bad(400))?;
    let query = match raw_query {
        None => HashMap::new(),
        Some(q) => parse_query(q).ok_or(ParseError::Bad(400))?,
    };
    Ok(Request { method, path, query })
}

/// 查询串解析：`k=v&k2=v2`；键值做 percent-decode；无 `=` 的键值为空串。
fn parse_query(q: &str) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let k = percent_decode(k)?;
        let v = percent_decode(v)?;
        out.entry(k).or_insert(v);
    }
    Some(out)
}

/// 最小 percent-decode（`%XX` + `+`→空格）；非法编码返回 None（→ 400）。
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 3 > bytes.len() {
                    return None;
                }
                let hex = &bytes[i + 1..i + 3];
                let hi = (hex[0] as char).to_digit(16)?;
                let lo = (hex[1] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// 响应描述。
pub struct Response {
    /// HTTP 状态码。
    pub status: u16,
    /// 响应体（JSON 文本）。
    pub body: String,
    /// 额外头（如 `Cache-Control: max-age=5`、CORS）。
    pub extra_headers: Vec<(String, String)>,
}

impl Response {
    /// JSON 响应（统一 content-type）。
    #[must_use]
    pub fn json(status: u16, body: String) -> Self {
        Self {
            status,
            body,
            extra_headers: Vec::new(),
        }
    }
}

/// 状态码原因短语（只覆盖本网关会用到的）。
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

/// 把响应写回连接并关闭（`Connection: close`）。
pub fn write_response(stream: &mut TcpStream, resp: &Response) {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nX-Zchain-Gateway: replay-v1\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status),
        resp.body.len()
    );
    let mut bytes = Vec::with_capacity(head.len() + resp.body.len() + 16);
    bytes.extend_from_slice(head.as_bytes());
    for (k, v) in &resp.extra_headers {
        bytes.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(resp.body.as_bytes());
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
    // Connection: close：立即关闭（写端 shutdown 由 drop 完成）。
}
