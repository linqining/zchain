//! M9：指标注册表 + 文本导出 + 告警规则。
//!
//! 传输层归上层 server（延续 PERFORMANCE_FOLLOWUPS 对 /metrics 的处置），
//! 本模块只提供库内导出器。线程安全（pipeline/sequencer 跨线程写）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// 计数器/gauge/直方图通用注册表。计数器与 gauge 用 Mutex 包表
/// （entry API 需要 &mut；吞吐足够 v1）。
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    counters: Mutex<BTreeMap<String, AtomicU64>>,
    gauges: Mutex<BTreeMap<String, AtomicU64>>,
    histograms: Mutex<BTreeMap<String, Vec<u64>>>,
    histogram_cap: usize,
}

/// 直方图摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistSummary {
    /// 样本数。
    pub count: u64,
    /// 最小值。
    pub min: u64,
    /// p50。
    pub p50: u64,
    /// p95。
    pub p95: u64,
    /// p99。
    pub p99: u64,
    /// 最大值。
    pub max: u64,
}

impl MetricsRegistry {
    /// 注册表（直方图窗口上限默认 16384 样本）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(BTreeMap::new()),
            gauges: Mutex::new(BTreeMap::new()),
            histograms: Mutex::new(BTreeMap::new()),
            histogram_cap: 16_384,
        }
    }

    /// 设置 gauge（水位、队列深度等瞬时值）。
    pub fn set_gauge(&self, name: &str, v: u64) {
        self.gauges
            .lock()
            .expect("gauge lock")
            .entry(name.to_owned())
            .or_insert_with(|| AtomicU64::new(0))
            .store(v, Ordering::Relaxed);
    }

    /// 读 gauge。
    #[must_use]
    pub fn gauge(&self, name: &str) -> u64 {
        self.gauges
            .lock()
            .expect("gauge lock")
            .get(name)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 计数器 +1。
    pub fn inc(&self, name: &str) {
        self.add(name, 1);
    }

    /// 计数器 +n。
    pub fn add(&self, name: &str, n: u64) {
        self.counters
            .lock()
            .expect("counter lock")
            .entry(name.to_owned())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// 读计数器。
    #[must_use]
    pub fn counter(&self, name: &str) -> u64 {
        self.counters
            .lock()
            .expect("counter lock")
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 直方图观测（值域不限；窗口满后整体重置——轻量有界）。
    pub fn observe(&self, name: &str, value: u64) {
        let mut hs = self
            .histograms
            .lock()
            .expect("histogram lock poisoned");
        let v = hs.entry(name.to_owned()).or_default();
        if v.len() >= self.histogram_cap {
            v.clear();
        }
        v.push(value);
    }

    /// 直方图摘要。
    #[must_use]
    pub fn hist_summary(&self, name: &str) -> Option<HistSummary> {
        let hs = self.histograms.lock().expect("histogram lock poisoned");
        let v = hs.get(name)?;
        if v.is_empty() {
            return None;
        }
        let mut sorted = v.clone();
        sorted.sort_unstable();
        let pick = |q: f64| -> u64 {
            let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
            sorted[idx.min(sorted.len() - 1)]
        };
        Some(HistSummary {
            count: sorted.len() as u64,
            min: sorted[0],
            p50: pick(0.50),
            p95: pick(0.95),
            p99: pick(0.99),
            max: sorted[sorted.len() - 1],
        })
    }

    /// Prometheus 风格文本导出。
    #[must_use]
    pub fn export_text(&self) -> String {
        let mut out = String::new();
        for (name, g) in self.gauges.lock().expect("gauge lock").iter() {
            out.push_str(&format!("{name} {}\n", g.load(Ordering::Relaxed)));
        }
        for (name, c) in self.counters.lock().expect("counter lock").iter() {
            out.push_str(&format!("{name} {}\n", c.load(Ordering::Relaxed)));
        }
        let hs = self.histograms.lock().expect("histogram lock poisoned");
        for (name, v) in hs.iter() {
            if let Some(s) = self.summarize(v) {
                out.push_str(&format!(
                    "{name}_summary{{quantile=\"0.5\"}} {}\n{name}_summary{{quantile=\"0.95\"}} {}\n{name}_summary{{quantile=\"0.99\"}} {}\n{name}_count {}\n",
                    s.p50, s.p95, s.p99, s.count
                ));
            }
        }
        out
    }

    fn summarize(&self, v: &[u64]) -> Option<HistSummary> {
        if v.is_empty() {
            return None;
        }
        let mut sorted = v.to_vec();
        sorted.sort_unstable();
        let pick = |q: f64| -> u64 {
            let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
            sorted[idx.min(sorted.len() - 1)]
        };
        Some(HistSummary {
            count: sorted.len() as u64,
            min: sorted[0],
            p50: pick(0.50),
            p95: pick(0.95),
            p99: pick(0.99),
            max: sorted[sorted.len() - 1],
        })
    }
}

/// 告警等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    /// 提示。
    Info,
    /// 警告。
    Warn,
    /// 严重。
    Critical,
}

/// 告警事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// 等级。
    pub level: AlertLevel,
    /// 规则名。
    pub rule: &'static str,
    /// 人读描述。
    pub message: String,
}

/// 告警规则输入（由上层周期性从各组件采集）。
#[derive(Debug, Clone, Copy)]
pub struct HealthInputs {
    /// 证明队列当前深度。
    pub proof_queue_depth: u64,
    /// 证明积压降级标志。
    pub proof_degraded: bool,
    /// 提现队列当前深度。
    pub withdrawal_queue_depth: u64,
    /// 出入金对账差异（0 = 无差异）。
    pub reconciliation_delta: i128,
    /// 软确认链自上一帧以来的毫秒数（活性探针）。
    pub soft_confirm_idle_ms: u64,
}

/// 告警规则评估（M9-ACC-2：每条规则都可注入触发）。
#[must_use]
pub fn evaluate_alerts(h: &HealthInputs) -> Vec<Alert> {
    let mut out = Vec::new();
    if h.proof_degraded {
        out.push(Alert {
            level: AlertLevel::Warn,
            rule: "proof_backlog_degraded",
            message: "证明管道进入积压降级档".to_owned(),
        });
    }
    if h.proof_queue_depth > 10_000 {
        out.push(Alert {
            level: AlertLevel::Critical,
            rule: "proof_queue_overflow",
            message: format!("证明队列深度 {}", h.proof_queue_depth),
        });
    }
    if h.reconciliation_delta != 0 {
        out.push(Alert {
            level: AlertLevel::Critical,
            rule: "reconciliation_delta",
            message: format!("账实差异 {:+}", h.reconciliation_delta),
        });
    }
    if h.withdrawal_queue_depth > 1_000 {
        out.push(Alert {
            level: AlertLevel::Warn,
            rule: "withdrawal_backlog",
            message: format!("提现队列深度 {}", h.withdrawal_queue_depth),
        });
    }
    if h.soft_confirm_idle_ms > 30_000 {
        out.push(Alert {
            level: AlertLevel::Warn,
            rule: "soft_confirm_idle",
            message: format!("软确认链空闲 {}ms", h.soft_confirm_idle_ms),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_and_histogram() {
        let m = MetricsRegistry::new();
        m.inc("ops_total");
        m.add("ops_total", 4);
        assert_eq!(m.counter("ops_total"), 5);
        for i in 0..100u64 {
            m.observe("latency_ms", i);
        }
        let s = m.hist_summary("latency_ms").unwrap();
        assert_eq!(s.count, 100);
        assert_eq!(s.min, 0);
        assert_eq!(s.max, 99);
    }

    #[test]
    fn alerts_fire_on_inputs() {
        let h = HealthInputs {
            proof_queue_depth: 20_000,
            proof_degraded: true,
            withdrawal_queue_depth: 2_000,
            reconciliation_delta: -5,
            soft_confirm_idle_ms: 60_000,
        };
        let alerts = evaluate_alerts(&h);
        let rules: Vec<_> = alerts.iter().map(|a| a.rule).collect();
        assert!(rules.contains(&"proof_queue_overflow"));
        assert!(rules.contains(&"proof_backlog_degraded"));
        assert!(rules.contains(&"withdrawal_backlog"));
        assert!(rules.contains(&"reconciliation_delta"));
        assert!(rules.contains(&"soft_confirm_idle"));
    }

    #[test]
    fn clean_health_no_alerts() {
        let h = HealthInputs {
            proof_queue_depth: 0,
            proof_degraded: false,
            withdrawal_queue_depth: 0,
            reconciliation_delta: 0,
            soft_confirm_idle_ms: 100,
        };
        assert!(evaluate_alerts(&h).is_empty());
    }
}
