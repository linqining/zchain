//! explorer gateway — TCP accept 循环与请求处理。
//!
//! fail-closed 装配点：
//! - 监听地址默认回环；非回环地址必须 `--public` 显式开启（main 负责校验）；
//! - 并发连接数硬上限（DoS 界：每连接一线程的模型下，无上限 = 连接洪水
//!   无限吃线程；超限写最小 503 后关闭，不起线程、不解析）；
//! - 限流在解析前（accept 后即按对端 IP 令牌桶判定，超限 429——慢速/
//!   垃圾字节不再绕过限流消耗解析资源）；
//! - 非 GET 一律 405（附 `Allow: GET`）；
//! - 请求解析失败一律 400；未知路径 404；
//! - `status`/`frames` 响应带 `Cache-Control: max-age=5`；`--public` 时全部
//!   响应带 `Access-Control-Allow-Origin: *`；所有响应带
//!   `X-Zchain-Gateway: replay-v1`。

use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;

use super::api;
use super::http::{self, Response};
use super::l1::L1Client;
use super::rate_limit::RateLimiter;
use super::state::GatewayState;

/// 并发连接数硬上限（DoS 界：thread-per-connection 模型下必须封顶，
/// 否则连接洪水可无限占用线程/内存；超限 503 后关闭）。
pub const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// 连接计数守卫：`Drop` 时递减活跃计数。线程收尾、panic unwind、以及
/// spawn 失败时闭包被丢弃，三种路径都会触发 Drop——计数不泄漏。
struct ConnGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

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

/// 起后台 accept 线程（每连接一线程；请求-响应-关闭语义；并发连接数
/// 以 [`MAX_CONCURRENT_CONNECTIONS`] 封顶——DoS 界，见常量注释）。
pub fn spawn(
    listener: TcpListener,
    state: Arc<GatewayState>,
    opts: ServerOptions,
) -> JoinHandle<()> {
    let limiter = Arc::new(RateLimiter::new(opts.rate_per_sec, opts.burst));
    let l1 = opts.l1.map(Arc::new);
    let public = opts.public;
    let active = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("explorer-gateway-accept".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // DoS 界：accept 即计数；超上限写最小 503 后关闭（不解析、
                // 不起线程）。日志只在越过上限的边界打一行——按连接打日志
                // 会被洪水反向打爆。注：http.rs 的 reason() 无 503 短语，
                // 状态行回退为 "OK"（原因短语仅装饰，客户端按状态码判定）。
                let prev = active.fetch_add(1, Ordering::SeqCst);
                if prev >= MAX_CONCURRENT_CONNECTIONS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    if prev == MAX_CONCURRENT_CONNECTIONS {
                        eprintln!(
                            "[explorer_gateway] concurrent connection cap {} reached; \
                             rejecting further connections with 503",
                            MAX_CONCURRENT_CONNECTIONS
                        );
                    }
                    let mut resp = api::error_response(503, "gateway at capacity");
                    apply_headers(&mut resp, public, false);
                    http::write_response(&mut stream, &resp);
                    // 尽力而为的非阻塞排空：把接收队列中已在途的请求字节
                    // 读掉，降低 close 时残留数据 → RST 的概率。**不得**在
                    // accept 线程上阻塞等待对端字节（过载洪水会把 accept
                    // 循环拖死）；竞态下对端收到 RST/空响应属可接受的过载
                    // 丢弃语义（curl 报 connection reset，不误读为 200）。
                    use std::io::Read as _;
                    let _ = stream.set_nonblocking(true);
                    let mut sink = [0u8; 2048];
                    while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
                    continue;
                }
                // 守卫移入闭包：线程结束时 Drop 递减；spawn 失败时闭包被
                // 丢弃同样触发 Drop——两种路径计数都恰好归还一次。
                let guard = ConnGuard {
                    active: Arc::clone(&active),
                };
                let limiter = Arc::clone(&limiter);
                let state = Arc::clone(&state);
                let l1 = l1.clone();
                let _ = std::thread::Builder::new()
                    .name("explorer-gateway-conn".to_string())
                    .spawn(move || {
                        let _guard = guard;
                        handle_connection(stream, &state, &limiter, l1.as_deref(), public);
                    });
            }
        })
        .expect("spawn accept thread")
}

/// 单连接处理：限流 → 解析 → 路由 → 响应 → 关闭。
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

    // 限流前置（read_request 之前，键 = 对端 IP 与既有实现相同）：
    // 超限连接直接 429，不为它花费路由资源——慢速/垃圾字节此前可绕过
    // 限流；一连接一请求语义下单次判定等价，只会更严、不弱化既有上限。
    if !limiter.check(peer_ip) {
        let mut resp = api::error_response(429, "rate limit exceeded");
        apply_headers(&mut resp, public, false);
        http::write_response(&mut stream, &resp);
        // 排空对端在途请求头后再关闭：提前回 429 意味着请求字节可能还
        // 躺在接收队列里，带残留数据 close 会被内核以 RST 收尾（客户端
        // 读到 connection reset 而非 429 体）。复用 read_request 的既有
        // 界（行/头块上限 + 5s 读超时），只消费不解析。
        let _ = http::read_request(&stream);
        return;
    }

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
