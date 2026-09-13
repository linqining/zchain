//! M9：指标注册表 + 文本导出 + 告警规则。
//!
//! 传输层归上层 server（延续 PERFORMANCE_FOLLOWUPS 对 /metrics 的处置），
//! 本模块只提供库内导出器。线程安全（pipeline/sequencer 跨线程写）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// per-table 指标的桌数上限（M9 防泄漏：恶意/异常客户端狂开新桌不得让
/// 指标表无界增长）。达到上限后**新桌被拒绝**并计
/// `table_metrics_overflow_total`；既有桌的写入不受影响。
pub const TABLE_METRIC_CAP: usize = 4_096;

/// per-table 结算窗口（TPH 分母用）：桌的首笔/末笔结算时刻 + 累计笔数。
/// `first_ms` 用 `Option`（ts=0 是合法时刻，不能当哨兵）。
#[derive(Debug, Default, Clone, Copy)]
struct TableSettleWindow {
    count: u64,
    first_ms: Option<u64>,
    last_ms: u64,
}

/// 计数器/gauge/直方图通用注册表。计数器与 gauge 用 Mutex 包表
/// （entry API 需要 &mut；吞吐足够 v1）。
#[derive(Debug)]
pub struct MetricsRegistry {
    counters: Mutex<BTreeMap<String, AtomicU64>>,
    gauges: Mutex<BTreeMap<String, AtomicU64>>,
    histograms: Mutex<BTreeMap<String, Vec<u64>>>,
    histogram_cap: usize,
    /// per-table 指标族（M9）：键 = (table_id, 指标名)，有界
    /// （[`TABLE_METRIC_CAP`] 桌，超限拒绝 + 溢出计数）。
    table_values: Mutex<BTreeMap<(u64, String), AtomicU64>>,
    /// per-table 结算窗口（TPH 摘要用），与 table_values 同界。
    table_settles: Mutex<BTreeMap<u64, TableSettleWindow>>,
    /// per-table 指标溢出计数（新桌超上限被拒次数）。
    table_overflow: AtomicU64,
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
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
            table_values: Mutex::new(BTreeMap::new()),
            table_settles: Mutex::new(BTreeMap::new()),
            table_overflow: AtomicU64::new(0),
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

    // ===== per-table 指标族（M9：`table_ops_total{table_id}` 等）=====

    /// per-table gauge 写入（如 `table_ops_inflight`）。桌数超
    /// [`TABLE_METRIC_CAP`] 且为新桌 → 拒绝并计溢出。
    pub fn set_table_gauge(&self, table_id: u64, name: &str, v: u64) {
        let mut tv = self.table_values.lock().expect("table gauge lock");
        let key = (table_id, name.to_owned());
        if tv.len() >= TABLE_METRIC_CAP && !tv.contains_key(&key) {
            drop(tv);
            self.table_overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        tv.entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .store(v, Ordering::Relaxed);
    }

    /// per-table 计数器 +n（如 `table_ops_total`）。
    pub fn add_table_counter(&self, table_id: u64, name: &str, n: u64) {
        let mut tv = self.table_values.lock().expect("table counter lock");
        let key = (table_id, name.to_owned());
        if tv.len() >= TABLE_METRIC_CAP && !tv.contains_key(&key) {
            drop(tv);
            self.table_overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        tv.entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(n, Ordering::Relaxed);
    }

    /// 读 per-table 计数器/gauge（不存在 → 0）。
    #[must_use]
    pub fn table_value(&self, table_id: u64, name: &str) -> u64 {
        self.table_values
            .lock()
            .expect("table value lock")
            .get(&(table_id, name.to_owned()))
            .map(|v| v.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// per-table 指标溢出计数（新桌超 [`TABLE_METRIC_CAP`] 被拒次数）。
    #[must_use]
    pub fn table_overflow_total(&self) -> u64 {
        self.table_overflow.load(Ordering::Relaxed)
    }

    /// 记录一桌的一次结算（TPH 窗口累计；`now_ms` 由调用方注入——
    /// 注册表自身无时钟，保持可注入/可测试）。
    pub fn record_table_settlement(&self, table_id: u64, now_ms: u64) {
        self.add_table_counter(table_id, "table_settlements_total", 1);
        let mut ws = self.table_settles.lock().expect("table settles lock");
        if ws.len() >= TABLE_METRIC_CAP && !ws.contains_key(&table_id) {
            drop(ws);
            self.table_overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let w = ws.entry(table_id).or_default();
        w.count = w.count.saturating_add(1);
        if w.first_ms.is_none() || now_ms < w.first_ms.unwrap_or(u64::MAX) {
            w.first_ms = Some(now_ms);
        }
        if now_ms > w.last_ms {
            w.last_ms = now_ms;
        }
    }

    /// 每桌 TPH 摘要：**窗口内结算数/分钟**（任务口径；非每小时）。
    ///
    /// 口径：`tph = count · 60000 / span_ms`，`span = max(end − first, 60s)`
    /// ——首笔结算后不足 1 分钟按 1 分钟计（保守下限，不外推瞬时爆发）；
    /// `now_ms == 0`（无外部时钟）时用每桌末笔结算时刻作 end。
    #[must_use]
    pub fn table_tph_report(&self, now_ms: u64) -> serde_json::Value {
        let ws = self.table_settles.lock().expect("table settles lock");
        let tables: Vec<serde_json::Value> = ws
            .iter()
            .map(|(table_id, w)| {
                let first = w.first_ms.unwrap_or(w.last_ms);
                let end = now_ms.max(w.last_ms);
                let span_ms = end.saturating_sub(first).max(60_000);
                let tph = f64::from(u32::try_from(w.count).unwrap_or(u32::MAX)) * 60_000.0
                    / f64::from(u32::try_from(span_ms).unwrap_or(u32::MAX));
                serde_json::json!({
                    "table_id": table_id,
                    "settlements": w.count,
                    "tph": (tph * 100.0).round() / 100.0,
                })
            })
            .collect();
        serde_json::json!({
            "table_count": tables.len(),
            "unit": "settlements_per_min",
            "overflow_total": self.table_overflow_total(),
            "tables": tables,
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
        {
            let tv = self.table_values.lock().expect("table value lock");
            for ((table_id, name), v) in tv.iter() {
                out.push_str(&format!(
                    "{name}{{table_id=\"{table_id}\"}} {}\n",
                    v.load(Ordering::Relaxed)
                ));
            }
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

    /// M9-ACC-4：四延迟报告（soft-confirm / proof-ready 实测分位；bft /
    /// claimable 未上线，恒输出 `null`）。
    ///
    /// - `soft_confirm_ms`：取 `soft_confirm_us` 直方图（sequencer 提交路径
    ///   观测的微秒值）换算为毫秒（保留小数，避免亚毫秒延迟坍缩成 0）；
    /// - `proof_ready_ms`：取 `proof_ready_ms` 直方图（pipeline 完成路径
    ///   观测：结算任务入队 → 证明完成的墙钟毫秒）；
    /// - **没有样本的直方图输出 `null` 而不是 0**——0 会被读成"延迟为零"，
    ///   而 null 明确表达"尚无观测"。
    #[must_use]
    pub fn latency_report(&self) -> serde_json::Value {
        let us_to_ms = |v: u64| -> f64 { f64::from(u32::try_from(v).unwrap_or(u32::MAX)) / 1_000.0 };
        let soft_confirm_ms = self.hist_summary("soft_confirm_us").map(|s| {
            serde_json::json!({
                "p50": us_to_ms(s.p50),
                "p95": us_to_ms(s.p95),
                "p99": us_to_ms(s.p99),
            })
        });
        let proof_ready_ms = self.hist_summary("proof_ready_ms").map(|s| {
            serde_json::json!({ "p50": s.p50, "p95": s.p95 })
        });
        serde_json::json!({
            "soft_confirm_ms": soft_confirm_ms,
            "proof_ready_ms": proof_ready_ms,
            "bft_finality_ms": serde_json::Value::Null,
            "claimable_ms": serde_json::Value::Null,
            "note": "bft/claimable 属 v1.5/Phase 2，未上线输出 null",
        })
    }

    /// M9：延迟报告 + 每桌 TPH 摘要（`latency_report()` 的超集；`now_ms`
    /// 为注入时钟，`0` = 无外部时钟，TPH 用每桌末笔结算时刻收口）。
    #[must_use]
    pub fn latency_report_at(&self, now_ms: u64) -> serde_json::Value {
        let mut v = self.latency_report();
        if let Some(obj) = v.as_object_mut() {
            obj.insert("per_table_tph".to_owned(), self.table_tph_report(now_ms));
        }
        v
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
    /// 限流拒绝窗口计数（`ops_rejected_total` 的近窗读数；超过阈值 = 有
    /// principal 在持续超频，M3-ACC-4 告警面）。
    pub rate_limit_rejected_window: u64,
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
    // M3-ACC-4 告警面：限流拒绝近窗计数超阈值（限流拒绝本身是正确的
    // 防御行为；告警语义 = "有主体持续超频，运维应识别并处置"——与
    // runbook §2.4 告警对照表同步）。
    if h.rate_limit_rejected_window > 100 {
        out.push(Alert {
            level: AlertLevel::Warn,
            rule: "rate_limit_storm",
            message: format!(
                "限流拒绝近窗 {} 次（超频主体持续被拒）",
                h.rate_limit_rejected_window
            ),
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
            rate_limit_rejected_window: 500,
        };
        let alerts = evaluate_alerts(&h);
        let rules: Vec<_> = alerts.iter().map(|a| a.rule).collect();
        assert!(rules.contains(&"proof_queue_overflow"));
        assert!(rules.contains(&"proof_backlog_degraded"));
        assert!(rules.contains(&"withdrawal_backlog"));
        assert!(rules.contains(&"reconciliation_delta"));
        assert!(rules.contains(&"soft_confirm_idle"));
        // M3-ACC-4：限流告警规则注入触发
        assert!(rules.contains(&"rate_limit_storm"));
    }

    #[test]
    fn clean_health_no_alerts() {
        let h = HealthInputs {
            proof_queue_depth: 0,
            proof_degraded: false,
            withdrawal_queue_depth: 0,
            reconciliation_delta: 0,
            soft_confirm_idle_ms: 100,
            rate_limit_rejected_window: 0,
        };
        assert!(evaluate_alerts(&h).is_empty());
    }

    /// M9-ACC-4：空直方图 → 四延迟报告输出 null（不是 0——0 会误导）。
    #[test]
    fn latency_report_nulls_when_no_samples() {
        let m = MetricsRegistry::new();
        let r = m.latency_report();
        assert_eq!(r["soft_confirm_ms"], serde_json::Value::Null);
        assert_eq!(r["proof_ready_ms"], serde_json::Value::Null);
        assert_eq!(r["bft_finality_ms"], serde_json::Value::Null);
        assert_eq!(r["claimable_ms"], serde_json::Value::Null);
        assert!(r["note"].as_str().unwrap().contains("v1.5"));
    }

    /// M9-ACC-4：灌样本后分位正确（分位取自 hist_summary 同一实现，
    /// 期望值按 `round((n-1)·q)` 索引手工展开，防实现静默漂移）。
    #[test]
    fn latency_report_quantiles_match_samples() {
        let m = MetricsRegistry::new();
        // soft_confirm_us：0..=99（100 样本）→ p50=idx50, p95=idx94, p99=idx98
        for i in 0..100u64 {
            m.observe("soft_confirm_us", i);
        }
        // proof_ready_ms：{10,20,30,40} → p50=idx2=30, p95=idx3=40
        for v in [10u64, 20, 30, 40] {
            m.observe("proof_ready_ms", v);
        }
        let r = m.latency_report();
        assert_eq!(r["soft_confirm_ms"]["p50"], serde_json::json!(0.050));
        assert_eq!(r["soft_confirm_ms"]["p95"], serde_json::json!(0.094));
        assert_eq!(r["soft_confirm_ms"]["p99"], serde_json::json!(0.098));
        assert_eq!(r["proof_ready_ms"]["p50"], serde_json::json!(30));
        assert_eq!(r["proof_ready_ms"]["p95"], serde_json::json!(40));
    }

    // ===== per-table 指标族（M9）=====

    /// per-table 计数器/gauge 读写 + 文本导出带 `{table_id}` 标签。
    #[test]
    fn table_metrics_roundtrip_and_export() {
        let m = MetricsRegistry::new();
        m.add_table_counter(7, "table_ops_total", 3);
        m.add_table_counter(7, "table_ops_total", 4);
        m.set_table_gauge(7, "table_ops_inflight", 2);
        m.add_table_counter(9, "table_ops_total", 1);
        assert_eq!(m.table_value(7, "table_ops_total"), 7);
        assert_eq!(m.table_value(7, "table_ops_inflight"), 2);
        assert_eq!(m.table_value(9, "table_ops_total"), 1);
        assert_eq!(m.table_value(8, "table_ops_total"), 0, "未知桌读 0");
        let text = m.export_text();
        assert!(text.contains("table_ops_total{table_id=\"7\"} 7\n"));
        assert!(text.contains("table_ops_inflight{table_id=\"7\"} 2\n"));
        assert!(text.contains("table_ops_total{table_id=\"9\"} 1\n"));
        assert_eq!(m.table_overflow_total(), 0);
    }

    /// 有界防泄漏：桌数超 [`TABLE_METRIC_CAP`] 后新桌拒绝并计溢出；
    /// 既有桌写入不受影响。
    #[test]
    fn table_metrics_bounded_with_overflow_counter() {
        let m = MetricsRegistry::new();
        for t in 0..TABLE_METRIC_CAP as u64 {
            m.add_table_counter(t, "table_ops_total", 1);
        }
        assert_eq!(m.table_overflow_total(), 0);
        // 超限新桌：拒绝 + 溢出计数（不 panic、不影响既有桌）
        m.add_table_counter(TABLE_METRIC_CAP as u64, "table_ops_total", 1);
        m.set_table_gauge(TABLE_METRIC_CAP as u64 + 1, "x", 1);
        assert_eq!(m.table_value(TABLE_METRIC_CAP as u64, "table_ops_total"), 0);
        assert_eq!(
            m.table_overflow_total(),
            2,
            "两个超限新桌各计一次溢出"
        );
        // 既有桌仍可写
        m.add_table_counter(0, "table_ops_total", 5);
        assert_eq!(m.table_value(0, "table_ops_total"), 6);
    }

    /// 每桌 TPH：**结算数/分钟**（任务口径）。span 不足 1 分钟按 1 分钟
    /// 保守计；`now_ms == 0` 时用每桌末笔时刻收口。
    #[test]
    fn table_tph_report_window_math() {
        let m = MetricsRegistry::new();
        // 桌 1：t=0 与 t=30000 两笔 → 不足 1 分钟 → tph = 2/min（保守）
        m.record_table_settlement(1, 0);
        m.record_table_settlement(1, 30_000);
        // 桌 2：t=0..=540000 共 10 笔（每 60s 一笔）→ now=600000 时
        // span = 600000ms = 10min → tph = 10 × 60000/600000 = 1.0/min
        for i in 0..10u64 {
            m.record_table_settlement(2, i * 60_000);
        }
        let r = m.table_tph_report(600_000);
        assert_eq!(r["table_count"], 2);
        assert_eq!(r["unit"], "settlements_per_min");
        let approx = |v: &serde_json::Value, want: f64| {
            assert!((v.as_f64().unwrap() - want).abs() < 1e-9, "{v} vs {want}");
        };
        let t1 = r["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["table_id"] == 1)
            .unwrap();
        assert_eq!(t1["settlements"], 2);
        approx(&t1["tph"], 0.2); // 2 笔 / 10min 窗口
        let t2 = r["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["table_id"] == 2)
            .unwrap();
        assert_eq!(t2["settlements"], 10);
        approx(&t2["tph"], 1.0); // 10 笔 / 10min
        // now_ms == 0：用每桌末笔收口（桌 1 end=30000 → span 钳 60s → 2.0）
        let r0 = m.table_tph_report(0);
        let t1_0 = r0["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["table_id"] == 1)
            .unwrap();
        approx(&t1_0["tph"], 2.0);
    }

    /// latency_report_at = latency_report 超集（附 per_table_tph；
    /// latency_report 本身保持原形状——既有调用方不被破坏）。
    #[test]
    fn latency_report_at_appends_per_table() {
        let m = MetricsRegistry::new();
        m.record_table_settlement(3, 1_000);
        let base = m.latency_report();
        assert!(base.get("per_table_tph").is_none());
        let at = m.latency_report_at(61_000);
        assert_eq!(at["soft_confirm_ms"], base["soft_confirm_ms"]);
        assert_eq!(at["per_table_tph"]["table_count"], 1);
        assert_eq!(at["per_table_tph"]["tables"][0]["table_id"], 3);
        assert_eq!(at["per_table_tph"]["tables"][0]["settlements"], 1);
    }
}
