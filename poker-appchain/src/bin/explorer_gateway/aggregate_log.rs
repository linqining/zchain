//! explorer gateway — aggregate log 读取（格式冻结契约）。
//!
//! 契约（写入方 `sequencer.rs::AggregateLogWriter`，格式冻结）：JSONL，
//! 每行一个对象
//!
//! ```text
//! {"index":<u64>,"through_op":<u64>,"root":"<64hex>","ts_ms":<u64>,"batch_count":<u64>}
//! ```
//!
//! `index` 从 0 起连续递增；`through_op` 严格递增（写入方保证）。
//!
//! 读取容错（fail-closed 取向，与 `proven_log.rs` 一致）：
//! - 空文件 → 空列表；
//! - 最后一行无换行结尾（写入方撕裂写）→ 忽略残行并告警；
//! - 其他任何行解析/校验失败 → **致命错误**（中间行损坏意味着日志连续
//!   前缀承诺已破，网关拒绝在可疑数据上启动）。

use std::path::Path;

/// 一条 M4 outer aggregate 聚合记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateEntry {
    /// 聚合序号（从 0 起连续递增）。
    pub index: u64,
    /// 覆盖到的最大帧序号。
    pub through_op: u64,
    /// 聚合根（Poseidon 折叠，域 `poker-appchain.aggregate_root.v1`）。
    pub root: [u8; 32],
    /// 记录时间（毫秒）。
    pub ts_ms: u64,
    /// 本窗口折叠的批次根数量。
    pub batch_count: u64,
}

/// 读取结果：合法条目 + 告警（撕裂尾行等；调用方负责打到日志）。
pub struct AggregateLog {
    /// 按追加顺序的条目。
    pub entries: Vec<AggregateEntry>,
    /// 非致命告警。
    pub warnings: Vec<String>,
}

/// 读入并解析 aggregate log。致命失败返回 Err（描述性消息，调用方退出非零）。
pub fn read(path: &Path) -> Result<AggregateLog, String> {
    let bytes = std::fs::read(path).map_err(|_| "aggregate log open failed".to_string())?;
    if bytes.is_empty() {
        return Ok(AggregateLog {
            entries: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let text = String::from_utf8(bytes).map_err(|_| "aggregate log not utf-8".to_string())?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    // split('\n') 对换行结尾文件会产生一个空尾串；直接弹掉。
    if ends_with_newline {
        lines.pop();
    }
    // 撕裂尾行：无换行结尾的最后一行一律忽略并告警（即使碰巧可解析——
    // 契约要求写入方逐行完整追加，未终结的行不可信）。
    let mut warnings = Vec::new();
    if !ends_with_newline {
        let tail = lines.pop().unwrap_or("");
        warnings.push(format!(
            "aggregate log: ignoring torn final line ({} bytes, no newline)",
            tail.len()
        ));
    }

    let mut entries: Vec<AggregateEntry> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_line(line).map_err(|e| format!("aggregate log line {}: {e}", i + 1))?;
        // index 连续（首行 = 0）与 through_op 严格递增为冻结纪律。
        if entry.index != u64::try_from(entries.len()).unwrap_or(u64::MAX) {
            return Err(format!(
                "aggregate log line {}: index {} breaks consecutive sequence",
                i + 1,
                entry.index
            ));
        }
        if let Some(prev) = entries.last() {
            if entry.through_op <= prev.through_op {
                return Err(format!(
                    "aggregate log line {}: through_op {} does not advance past {}",
                    i + 1,
                    entry.through_op,
                    prev.through_op
                ));
            }
        }
        entries.push(entry);
    }
    Ok(AggregateLog { entries, warnings })
}

/// 解析单行（字段缺失/类型错/root 非 64hex → Err）。
fn parse_line(line: &str) -> Result<AggregateEntry, String> {
    let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("bad json: {e}"))?;
    let obj = v.as_object().ok_or("not a json object")?;
    let index = obj
        .get("index")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid index")?;
    let through_op = obj
        .get("through_op")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid through_op")?;
    let root_hex = obj
        .get("root")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid root")?;
    let ts_ms = obj
        .get("ts_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid ts_ms")?;
    let batch_count = obj
        .get("batch_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid batch_count")?;
    let root: [u8; 32] = hex::decode(root_hex)
        .map_err(|_| "root not hex".to_string())?
        .try_into()
        .map_err(|_| "root not 32 bytes (64 hex)".to_string())?;
    Ok(AggregateEntry {
        index,
        through_op,
        root,
        ts_ms,
        batch_count,
    })
}

/// 把条目序列化回契约格式的一行（`--gen-fixture` 写入方使用；带换行）。
#[must_use]
pub fn encode_line(entry: &AggregateEntry) -> String {
    format!(
        "{{\"index\":{},\"through_op\":{},\"root\":\"{}\",\"ts_ms\":{},\"batch_count\":{}}}\n",
        entry.index,
        entry.through_op,
        hex::encode(entry.root),
        entry.ts_ms,
        entry.batch_count
    )
}
