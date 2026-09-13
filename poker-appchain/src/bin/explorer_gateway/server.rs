//! explorer gateway — TCP accept 循环与请求处理。
//!
//! fail-closed 装配点：
//! - 监听地址默认回环；非回环地址必须 `--public` 显式开启（main 负责校验）；
//! - 限流在路由前（每 IP 令牌桶，超限 429）；
//! - 非 GET 一律 405（附 `Allow: GET`）；
//! - 请求解析失败一律 400；未知路径 404；
//! - `status`/`frames` 响应带 `Cache-Control: max-age=5`；`--public` 时全部
//!   响应带 `Access-Control-Allow-Origin: *`；所有响应带
//!   `X-Zchain-Gateway: replay-v1`。

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::api;
use super::http::{self, Response};
use super::l1::L1Client;
use super::rate_limit::RateLimiter;
use super::state::GatewayState;

/// 服务端运行参数。
pub struct ServerOptions {
    /// 是否 `--public`（决定 CORS 头；监听地址校验在 main）。
    pub public: bool,
    /// 每 IP 令牌桶速率（req/s）。
    pub rate_per_sec: u32,
    /// 每 IP 令牌桶容量（突发）。
    pub burst: u32,
    /// L1 代理客户端（None = `/api/v1/l1/*` 返回 404）。
    pub l1: Option<L1Client>,
}

/// 绑定监听（`addr` 支持 `127.0.0.1:0` 供测试取临时端口）。
///
/// # Errors
/// 绑定失败（占用/权限）→ IO 错误。
pub fn bind(addr: &str) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr)
}

/// 起后台 accept 线程（每连接一线程；请求-响应-关闭语义）。
pub fn spawn(
    listener: TcpListener,
    state: Arc<GatewayState>,
    opts: ServerOptions,
) -> JoinHandle<()> {
    let limiter = Arc::new(RateLimiter::new(opts.rate_per_sec, opts.burst));
    let l1 = opts.l1.map(Arc::new);
    let public = opts.public;
    std::thread::Builder::new()
        .name("explorer-gateway-accept".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let limiter = Arc::clone(&limiter);
                let state = Arc::clone(&state);
                let l1 = l1.clone();
                let _ = std::thread::Builder::new()
                    .name("explorer-gateway-conn".to_string())
                    .spawn(move || {
                        handle_connection(stream, &state, &limiter, l1.as_deref(), public);
                    });
            }
        })
        .expect("spawn accept thread")
}

/// 单连接处理：解析 → 限流 → 路由 → 响应 → 关闭。
fn handle_connection(
    mut stream: TcpStream,
    state: &Arc<GatewayState>,
    limiter: &RateLimiter,
    l1: Option<&L1Client>,
    public: bool,
) {
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    limiter.maybe_prune();

    let request = match http::read_request(&stream) {
        Ok(r) => r,
        Err(http::ParseError::Closed | http::ParseError::TimedOut) => return,
        Err(http::ParseError::Bad(status)) => {
            let mut resp = api::error_response(status, "malformed request");
            apply_headers(&mut resp, public, false);
            http::write_response(&mut stream, &resp);
            return;
        }
    };

    // 限流在路由前（超限 429；被限流的请求不消耗后端资源）。
    if !limiter.check(peer_ip) {
        let mut resp = api::error_response(429, "rate limit exceeded");
        apply_headers(&mut resp, public, false);
        http::write_response(&mut stream, &resp);
        return;
    }

    let mut resp = if request.method == "GET" {
        api::route(state, &request, l1)
    } else {
        let mut r = api::error_response(405, "method not allowed (read-only gateway: GET only)");
        r.extra_headers.push(("Allow".to_string(), "GET".to_string()));
        r
    };
    apply_headers(&mut resp, public, cacheable(&request.path));
    http::write_response(&mut stream, &resp);
}

/// 附加统一响应头。
fn apply_headers(resp: &mut Response, public: bool, cacheable: bool) {
    if cacheable {
        resp.extra_headers
            .push(("Cache-Control".to_string(), "max-age=5".to_string()));
    }
    if public {
        resp.extra_headers
            .push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
    }
}

/// 可缓存端点（status / frames）。
fn cacheable(path: &str) -> bool {
    matches!(path, "/api/v1/status" | "/api/v1/frames")
}
