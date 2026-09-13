//! explorer gateway — 静态快照导出（`--snapshot-out`）。
//!
//! 写 `<dir>/explorer.json`：status + 最近 20 帧 + 最近 20 settlements +
//! batch_roots，供静态站点构建消费。`--snapshot-interval-secs 0`（默认）
//! 启动时写一次；`N > 0` 时由后台线程周期性重写。

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::api;
use super::state::GatewayState;

/// 快照里的列表长度上限。
const SNAPSHOT_TAIL: usize = 20;

/// 生成快照 JSON 文本。
#[must_use]
pub fn render(state: &Arc<GatewayState>) -> String {
    // 双数据面统一视图：帧/结算摘要由 api 层抽取（replay = 内存链，
    // index = 持久化索引），快照形状两模式一致。
    let frames: Vec<serde_json::Value> = api::frame_summaries(state)
        .iter()
        .rev()
        .take(SNAPSHOT_TAIL)
        .rev()
        .map(|f| {
            serde_json::json!({
                "index": f.index,
                "ts_ms": f.ts_ms,
                "state_root": f.state_root_hex,
                "op": f.op,
            })
        })
        .collect();
    let mut all: Vec<serde_json::Value> = api::settlement_summaries(state);
    all.reverse();
    all.truncate(SNAPSHOT_TAIL);
    all.reverse();
    let settlements = all;

    let body = serde_json::json!({
        "generated_unix_ms": unix_ms(),
        "mode": state.data_source,
        "status": api::status_json(state),
        "frames": frames,
        "settlements": settlements,
        "batch_roots": state.proven.iter().map(|e| serde_json::json!({
            "op_index": e.op_index,
            "batch_root": hex::encode(e.batch_root),
            "ts_ms": e.ts_ms,
        })).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".to_string())
}

/// 写快照文件（目录不存在则创建）。
///
/// # Errors
/// 目录创建/文件写入失败 → IO 错误消息。
pub fn write_to(dir: &Path, state: &Arc<GatewayState>) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("snapshot dir: {e}"))?;
    let path = dir.join("explorer.json");
    std::fs::write(&path, render(state)).map_err(|e| format!("snapshot write: {e}"))?;
    Ok(())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
