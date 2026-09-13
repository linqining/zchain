//! explorer gateway — proven log 读取（格式冻结契约）。
//!
//! 契约（写入方下一波实现，格式冻结）：JSONL，每行一个对象
//! `{"op_index": <u64>, "batch_root": "<64hex>", "ts_ms": <u64>}`，
//! 按水位推进顺序追加；watermark = 最后一条的 `op_index`（写入方保证
//! 连续前缀）；`batch_roots[op_index] = root`。
//!
//! 读取容错（fail-closed 取向）：
//! - 空文件 → 空列表；
//! - 最后一行无换行结尾（写入方撕裂写）→ 忽略残行并告警；
//! - 其他任何行解析/校验失败 → **致命错误**（中间行损坏意味着日志
//!   连续前缀承诺已破，网关拒绝在可疑水位上启动）。

use std::path::Path;

/// 一条水位推进记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenEntry {
    /// 覆盖到的 op index（含）。
    pub op_index: u64,
    /// 批次根（Poseidon 折叠）。
    pub batch_root: [u8; 32],
    /// 记录时间（毫秒，单调性由写入方保证）。
    pub ts_ms: u64,
}

/// 读取结果：合法条目 + 告警（撕裂尾行等；调用方负责打到日志）。
pub struct ProvenLog {
    /// 按追加顺序的条目。
    pub entries: Vec<ProvenEntry>,
    /// 非致命告警。
    pub warnings: Vec<String>,
}

/// 读入并解析 proven log。致命失败返回 Err（描述性消息，调用方退出非零）。
pub fn read(path: &Path) -> Result<ProvenLog, String> {
    let bytes =
        std::fs::read(path).map_err(|_| "proven log open failed".to_string())?;
    let warnings = Vec::new();
    if bytes.is_empty() {
        return Ok(ProvenLog {
            entries: Vec::new(),
            warnings,
        });
    }
    let text = String::from_utf8(bytes).map_err(|_| "proven log not utf-8".to_string())?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    // split('\n') 对换行结尾文件会产生一个空尾串；直接弹掉。
    if ends_with_newline {
        lines.pop();
    }
    // 撕裂尾行：无换行结尾的最后一行一律忽略并告警（即使碰巧可解析——
    // 契约要求写入方逐行完整追加，未终结的行不可信）。
    let mut warnings = warnings;
    if !ends_with_newline {
        let tail = lines.pop().unwrap_or("");
        warnings.push(format!(
            "proven log: ignoring torn final line ({} bytes, no newline)",
            tail.len()
        ));
    }

    let mut entries: Vec<ProvenEntry> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = parse_line(line)
            .map_err(|e| format!("proven log line {}: {e}", i + 1))?;
        if let Some(prev) = entries.last() {
            if entry.op_index <= prev.op_index {
                return Err(format!(
                    "proven log line {}: op_index {} does not advance past {}",
                    i + 1,
                    entry.op_index,
                    prev.op_index
                ));
            }
        }
        entries.push(entry);
    }
    Ok(ProvenLog {
        entries,
        warnings,
    })
}

/// 解析单行（字段缺失/类型错/root 非 64hex → Err）。
fn parse_line(line: &str) -> Result<ProvenEntry, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("bad json: {e}"))?;
    let obj = v.as_object().ok_or("not a json object")?;
    let op_index = obj
        .get("op_index")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid op_index")?;
    let root_hex = obj
        .get("batch_root")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing/invalid batch_root")?;
    let ts_ms = obj
        .get("ts_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing/invalid ts_ms")?;
    let root_bytes = hex::decode(root_hex).map_err(|_| "batch_root not hex".to_string())?;
    let batch_root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| "batch_root not 32 bytes (64 hex)".to_string())?;
    Ok(ProvenEntry {
        op_index,
        batch_root,
        ts_ms,
    })
}

/// 把条目序列化回契约格式的一行（`--gen-fixture` 写入方使用；带换行）。
#[must_use]
pub fn encode_line(entry: &ProvenEntry) -> String {
    format!(
        "{{\"op_index\":{},\"batch_root\":\"{}\",\"ts_ms\":{}}}\n",
        entry.op_index,
        hex::encode(entry.batch_root),
        entry.ts_ms
    )
}
