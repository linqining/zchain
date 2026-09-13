//! explorer gateway — 每 IP 令牌桶限流。
//!
//! 简单实现：`Mutex<HashMap<IpAddr, Bucket>>`，每桶 `tokens ∈ [0, burst]`，
//! 按恒定速率回填。默认 10 req/s、突发 20；超限一律 429（fail-closed：
//! 未显式开启 `--public` 时这是唯一防滥用的软防线，仍应只绑回环）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// 单 IP 令牌桶。
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// 每 IP 限流器。
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    /// 构造（`rate` req/s，容量 `burst`）。
    #[must_use]
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate: f64::from(rate_per_sec.max(1)),
            burst: f64::from(burst.max(1)),
        }
    }

    /// 判定该 IP 本次请求是否放行（放行即扣一个令牌）。
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut map = self.buckets.lock().expect("rate limiter lock");
        let now = Instant::now();
        let bucket = map.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 表过大时回收长时间静默的桶（防映射无界增长；阈值 65_536 条）。
    pub fn maybe_prune(&self) {
        let mut map = self.buckets.lock().expect("rate limiter lock");
        if map.len() < 65_536 {
            return;
        }
        map.retain(|_, b| b.last.elapsed().as_secs() < 60);
    }
}
