//! explorer gateway — 只读 JSON API（路由 + 载荷构造）。
//!
//! 全部端点为 GET、全部只读、白名单路由：
//! - `/api/v1/status`                     链头/水位/计数/最新聚合摘要 +
//!   `assets` 资产摘要（TE-M5：REAL 域三 token 的 issued/burned/
//!   outstanding + GAME 域供给对账；index 模式恒 null——token 聚合账
//!   是 replay 重建态，不入索引）
//! - `/api/v1/frames`                     软确认帧摘要分页（limit 上限 200）
//! - `/api/v1/settlements`                结算摘要分页 + `table_id` 过滤
//! - `/api/v1/settlement/{hand_binding}`  单笔结算全量明细（含 payout_root、
//!   proof 链接与 TE-M5 资产维度 `asset_id`——inputs/payouts/rake 输出
//!   逐项带 domain/token 名称解析）
//! - `/api/v1/batch_roots`                批次根列表（proven log）
//! - `/api/v1/proofs`                     proof 归档元数据分页（≤200）
//! - `/api/v1/proof/{binding_hex}`        proof 归档下载（payload_b64 +
//!                                        `X-Zchain-Engine` 响应头）
//! - `/api/v1/aggregates`                 M4 outer aggregate 聚合记录列表
//! - `/api/v1/metrics`                    注册表文本导出（启动态静态快照）
//! - `/api/v1/l1/*`                       L1 JSON-RPC 只读代理（未配置 → 404）
//!
//! ## 数据面（replay / index 双模式）
//!
//! 端点语义在两种数据面下**逐字段一致**：
//! - replay 模式（默认）：查询走 WAL 全量重放后的 sequencer 内存链；
//! - index 模式（`--index-file`）：frames/settlements/status 由持久化索引
//!   直接服务（免 replay）；`settlement/{binding}` 明细按索引记录的 WAL
//!   字节偏移定向读单帧，先做完整性校验（sequencer 验签 + 帧哈希/序号/
//!   时刻/状态根与索引行交叉核对，任一不符 → 500 fail-closed，不出数据）。
//!   响应 `status.data_source` / `metrics.mode` 回显 `replay`/`index`。
//!
//! 纪律：未知路径 404；非 GET 405；查询参数解析失败一律 400；
//! hex 参数格式坏 400、格式合法但不存在 404。

use std::path::Path;
use std::sync::Arc;

use poker_appchain::asset_id::{AssetId, REAL_DOMAIN_TOKENS};
use poker_appchain::keys::SequencerKey;
use poker_appchain::ops::Operation;
use poker_appchain::sequencer::{LedgerState, Sequencer};
use poker_appchain::settlement::{payout_root_bytes, SettlementRecord};
use poker_appchain::soft_confirm::SignedFrame;

use super::http::{Request, Response};
use super::l1::L1Client;
use super::state::GatewayState;

/// 帧列表单页上限（纪律：不内联完整 op，页上限 200）。
pub const PAGE_LIMIT_CAP: usize = 200;

/// 路由入口（server 层完成限流后调用）。
pub fn route(state: &Arc<GatewayState>, req: &Request, l1: Option<&L1Client>) -> Response {
    match req.path.as_str() {
        "/api/v1/status" => status(state),
        "/api/v1/frames" => frames(state, &req.query),
        "/api/v1/settlements" => settlements(state, &req.query),
        "/api/v1/batch_roots" => batch_roots(state),
        "/api/v1/proofs" => proofs(state, &req.query),
        "/api/v1/aggregates" => aggregates(state),
        "/api/v1/metrics" => metrics(state),
        "/api/v1/l1/metrics" => l1_route(l1, "get_metrics", serde_json::Value::Null),
        "/api/v1/l1/block" => match query_u64(&req.query, "height") {
            Ok(height) => l1_route(l1, "get_block", serde_json::json!({ "height": height })),
            Err(resp) => resp,
        },
        "/api/v1/l1/tx" => match query_hash32(&req.query, "hash") {
            Ok(hash) => l1_route(l1, "get_tx", serde_json::json!({ "tx_hash": hash })),
            Err(resp) => resp,
        },
        p if p.starts_with("/api/v1/settlement/") => {
            let binding_hex = &p["/api/v1/settlement/".len()..];
            settlement_detail(state, binding_hex)
        }
        p if p.starts_with("/api/v1/proof/") => {
            let binding_hex = &p["/api/v1/proof/".len()..];
            proof_download(state, binding_hex)
        }
        _ => error_response(404, "not found"),
    }
}

/// 统一错误载荷。
#[must_use]
pub fn error_response(status: u16, message: &str) -> Response {
    Response::json(status, serde_json::json!({ "error": message }).to_string())
}

// ===== 通用查询参数解析 =====

/// `offset`（默认 0）。
fn query_offset(query: &std::collections::HashMap<String, String>) -> Result<u64, Response> {
    match query.get("offset") {
        None => Ok(0),
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| error_response(400, "invalid query param: offset")),
    }
}

/// `limit`（默认 `default`；超 `PAGE_LIMIT_CAP` 截断到上限并在响应中回显生效值）。
fn query_limit(query: &std::collections::HashMap<String, String>) -> Result<usize, Response> {
    match query.get("limit") {
        None => Ok(20),
        Some(v) => {
            let raw = v
                .parse::<usize>()
                .map_err(|_| error_response(400, "invalid query param: limit"))?;
            Ok(raw.min(PAGE_LIMIT_CAP))
        }
    }
}

/// 无符号整数参数（如 `table_id`、`height`）。
fn query_u64(
    query: &std::collections::HashMap<String, String>,
    key: &str,
) -> Result<u64, Response> {
    match query.get(key) {
        None => Err(error_response(400, &format!("missing query param: {key}"))),
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| error_response(400, &format!("invalid query param: {key}"))),
    }
}

/// 32 字节 hex 参数（如 `hash`）。
fn query_hash32(
    query: &std::collections::HashMap<String, String>,
    key: &str,
) -> Result<[u8; 32], Response> {
    let hex_str = query
        .get(key)
        .ok_or_else(|| error_response(400, &format!("missing query param: {key}")))?;
    decode_hex32(hex_str)
        .ok_or_else(|| error_response(400, &format!("invalid query param: {key} (need 64 hex chars)")))
}

/// 严格 64-hex → 32B。
#[must_use]
pub fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// owner 缩写：前 8 + "…" + 后 8 个 hex 字符（列表摘要用，不给全量）。
#[must_use]
pub fn short_hex(bytes: &[u8]) -> String {
    let h = hex::encode(bytes);
    if h.len() <= 20 {
        return h;
    }
    format!("{}…{}", &h[..8], &h[h.len() - 8..])
}

/// 结算层级：`frame_index ≤ watermark` → proven，否则 soft_accepted。
fn level_for(state: &GatewayState, frame_index: u64) -> &'static str {
    match state.watermark {
        Some(w) if frame_index <= w => "proven",
        _ => "soft_accepted",
    }
}

/// op 类型名（不内联完整 op 细节——摘要端点纪律）。
#[must_use]
pub fn op_type_name(op: &Operation) -> &'static str {
    match op {
        Operation::OpenTable { .. } => "OpenTable",
        Operation::CloseTable { .. } => "CloseTable",
        Operation::Deposit { .. } => "Deposit",
        Operation::WithdrawRequest { .. } => "WithdrawRequest",
        Operation::Transfer { .. } => "Transfer",
        Operation::BuyIn { .. } => "BuyIn",
        Operation::Settle(_) => "Settle",
        // ABI v2 追加变体（判别值 7/8；additive 纪律见 ops.rs 模块文档）
        Operation::MigrateNote(_) => "MigrateNote",
        Operation::SettleV2(_) => "SettleV2",
        // TE-M2 追加变体（判别值 9/10；本 match 对 Operation 穷尽，新变体
        // 只能在此追加命名——冻结文件旁的最小机械追加，与 archive_index
        // 的 kind_of 同一拼写）
        Operation::DepositV2(_) => "DepositV2",
        Operation::WithdrawRequestV2(_) => "WithdrawRequestV2",
        // TE-M3 追加变体（判别值 11/12/13；GTS 游戏币——与 archive_index
        // 的 kind_of 同一拼写，见 docs/ABI_TE_M3.md）
        Operation::RegisterGameToken(_) => "RegisterGameToken",
        Operation::IssueGameToken(_) => "IssueGameToken",
        Operation::BurnGameToken(_) => "BurnGameToken",
        // TE-M6 追加变体（判别值 14/15/16；Free 模式与 gas 额度——与
        // archive_index 的 kind_of 同一拼写，机械追加）
        Operation::FaucetMint(_) => "FaucetMint",
        Operation::BuyGasCredits(_) => "BuyGasCredits",
        Operation::BindGasPolicy(_) => "BindGasPolicy",
    }
}

/// 链上的 (帧, 结算记录) 序列（replay 模式一次遍历提取）。
#[must_use]
pub fn settlement_frames(seq: &Sequencer) -> Vec<(&SignedFrame, &SettlementRecord)> {
    seq.chain()
        .iter()
        .filter_map(|f| match &f.frame.op {
            Operation::Settle(record) => Some((f, record.as_ref())),
            _ => None,
        })
        .collect()
}

// ===== TE-M5：资产维度展示（显示层不做第二种换算）=====

/// 资产 token 展示名（与 [`AssetId::to_string`] 的 token 段同一拼写；
/// GAME 域未注册 token 如实给编号，不造名称）。
#[must_use]
pub fn asset_token_name(a: &AssetId) -> String {
    match *a {
        AssetId::REAL_NATIVE => "native".to_owned(),
        AssetId::REAL_USDT => "usdt".to_owned(),
        AssetId::REAL_USDC => "usdc".to_owned(),
        AssetId::GAME_PLAY => "play(legacy)".to_owned(),
        _ => a.token_id.to_string(),
    }
}

/// AssetId 展示对象：domain 判别值/名称 + token 编号/展示名 + 规范字符串。
/// 冻结映射（v1 `AssetClass::Real` → REAL/NATIVE、`Play` → GAME/PLAY）经
/// [`AssetId::of_v1`] 升维后同样适用——v1 结算明细的资产维度即由此表达。
#[must_use]
pub fn asset_id_json(a: &AssetId) -> serde_json::Value {
    serde_json::json!({
        "domain": a.domain.as_u8(),
        "domain_name": a.domain.name(),
        "token_id": a.token_id,
        "token": asset_token_name(a),
        "asset": a.to_string(),
    })
}

/// 资产摘要（`/api/v1/status.assets`；TE-M5 对账页数据面）。
///
/// 口径（如实标注——**来源限于链上可见面**）：
/// - REAL 域（封闭枚举 NATIVE/USDT/USDC）逐 token：`issued` = 存续 v2
///   note 面额 + 已销毁毛额（[`LedgerState::issued_v2_real_by_token`]，
///   托管对账 issued 口径）；`burned` = 提现销毁毛额合计（账本 `burned_v2`）；
///   `outstanding = issued − burned`（= 存续面额）。托管侧储备
///   （CustodyLedgerV2 的 reserved/浮存/提现队列）网关不可达——不出数据、
///   不伪装，`source` 字段如实标注。
/// - GAME 域逐 token：[`LedgerState::game_reconciliation`]（Σminted /
///   Σburned / outstanding / live_note_sum / consistent，供给恒等式
///   `outstanding = Σminted − Σburned`）+ 注册表规格（mode / anchor /
///   rate / max_supply，注册后冻结；遗留 PLAY(0) 无 GTS 规格 →
///   `mode`/`anchor`/`rate`/`max_supply` 为 null，`registered` 如实标注）。
/// - u128/u64 大数一律十进制字符串（与 `game_reconciliation_json` 同纪律，
///   避免 JSON 数值精度歧义）；token 集合确定序（REAL 封闭枚举序 /
///   GAME token_id 升序）。
#[must_use]
pub fn assets_summary(state: &LedgerState) -> serde_json::Value {
    // REAL 域：issued 按精确 AssetId（域隔离——GAME 域 note 不入 REAL 口径）
    let issued_by_token = state.issued_v2_real_by_token();
    let mut burned_by_token: std::collections::BTreeMap<u32, u128> = std::collections::BTreeMap::new();
    for (_, asset, gross) in &state.burned_v2 {
        *burned_by_token.entry(asset.token_id).or_insert(0) += u128::from(*gross);
    }
    let real_tokens: Vec<serde_json::Value> = REAL_DOMAIN_TOKENS
        .iter()
        .map(|&t| {
            let id = AssetId::real(t).expect("REAL domain closed enum");
            let issued = issued_by_token.get(&id).copied().unwrap_or(0);
            let burned = burned_by_token.get(&t).copied().unwrap_or(0);
            let outstanding = issued.saturating_sub(burned);
            serde_json::json!({
                "domain": "REAL",
                "token_id": t,
                "token": asset_token_name(&id),
                "asset": id.to_string(),
                "issued": issued.to_string(),
                "burned": burned.to_string(),
                "outstanding": outstanding.to_string(),
            })
        })
        .collect();

    // GAME 域：供给对账（恒等式三边核对）+ 注册表规格展示
    let rec = state.game_reconciliation();
    let game_tokens: Vec<serde_json::Value> = rec
        .tokens
        .iter()
        .map(|t| {
            let id = AssetId::game(t.token_id);
            let spec = state.game_registry.get(t.token_id);
            serde_json::json!({
                "domain": "GAME",
                "token_id": t.token_id,
                "token": asset_token_name(&id),
                "asset": id.to_string(),
                "registered": spec.is_some() || t.token_id == poker_appchain::asset_id::GAME_TOKEN_PLAY,
                "mode": spec.map(|s| if s.is_paid() { "paid" } else { "free" }),
                "anchor": spec.and_then(|s| s.anchor()).map(|a| a.to_string()),
                "rate": spec.and_then(|s| s.rate()).map(|r| r.to_string()),
                "max_supply": spec.map(|s| s.max_supply.to_string()),
                "minted_total": t.minted_total.to_string(),
                "burned_total": t.burned_total.to_string(),
                "outstanding": t.outstanding.to_string(),
                "live_note_sum": t.live_note_sum.to_string(),
                "consistent": t.consistent,
            })
        })
        .collect();

    serde_json::json!({
        "source": "appchain_ledger (chain-visible face; custody reserves / withdrawal queues are not exposed by the read-only gateway)",
        "real": { "tokens": real_tokens },
        "game": { "tokens": game_tokens, "all_consistent": rec.all_consistent },
    })
}

// ===== 双数据面统一视图 =====

/// 帧摘要（双数据面统一；`frames` 端点与快照共用）。
#[derive(Debug, Clone)]
pub struct FrameSummary {
    /// 帧序号。
    pub index: u64,
    /// 帧时刻（毫秒）。
    pub ts_ms: u64,
    /// 帧后状态根 hex。
    pub state_root_hex: String,
    /// op 类型名。
    pub op: String,
}

/// 全部帧摘要（replay：内存链；index：持久化索引）。
#[must_use]
pub fn frame_summaries(state: &GatewayState) -> Vec<FrameSummary> {
    if let Some(seq) = &state.seq {
        let seq = seq.lock().expect("gateway seq lock");
        seq.chain()
            .iter()
            .map(|f| FrameSummary {
                index: f.frame.index,
                ts_ms: f.frame.ts_ms,
                state_root_hex: hex::encode(f.frame.state_root),
                op: op_type_name(&f.frame.op).to_owned(),
            })
            .collect()
    } else if let Some(index) = &state.index {
        index
            .frames()
            .iter()
            .map(|e| FrameSummary {
                index: e.index,
                ts_ms: e.ts_ms,
                state_root_hex: hex::encode(e.state_root),
                op: e.kind.clone(),
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// 全部结算摘要（replay：内存链投影；index：索引 Settle 行投影——
/// 两数据面逐字段一致，`level` 同一水位语义）。
#[must_use]
pub fn settlement_summaries(state: &GatewayState) -> Vec<serde_json::Value> {
    if let Some(seq) = &state.seq {
        let seq = seq.lock().expect("gateway seq lock");
        settlement_frames(&seq)
            .iter()
            .map(|(f, r)| settlement_summary_json(f, r, state))
            .collect()
    } else if let Some(index) = &state.index {
        index
            .frames()
            .iter()
            .filter_map(|e| {
                let s = e.settle.as_ref()?;
                Some(serde_json::json!({
                    "frame_index": e.index,
                    "ts_ms": e.ts_ms,
                    "table_id": s.table_id,
                    "hand_binding": hex::encode(s.binding),
                    "pot": s.pot,
                    "rake_base": s.rake_base,
                    "rake_total": s.rake_total,
                    "payouts": s.payouts.iter().map(|(owner_short, amount)| serde_json::json!({
                        "owner_short": owner_short,
                        "amount": amount,
                    })).collect::<Vec<_>>(),
                    "level": level_for(state, e.index),
                }))
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// 单笔结算记录查找（双数据面统一）：返回 `(frame_index, ts_ms, record)`。
///
/// index 模式：按索引记录的 WAL 字节偏移**定向读单帧**，先做完整性校验
/// （sequencer 验签 + 帧哈希/序号/时刻/状态根与索引行交叉核对）。
///
/// # Errors
/// index 模式下 WAL 不可读 / 帧损坏 / 完整性校验失败 → Err（调用方必须
/// fail-closed：不出数据，500）。
pub fn find_settlement_record(
    state: &GatewayState,
    binding: &[u8; 32],
) -> Result<Option<(u64, u64, SettlementRecord)>, String> {
    if let Some(seq) = &state.seq {
        let seq = seq.lock().expect("gateway seq lock");
        Ok(settlement_frames(&seq)
            .into_iter()
            .find(|(_, r)| r.hand_binding == *binding)
            .map(|(f, r)| (f.frame.index, f.frame.ts_ms, r.clone())))
    } else if let Some(index) = &state.index {
        let Some(entry) = index.settlement_by_binding(binding) else {
            return Ok(None);
        };
        let wal = state.wal_path.as_deref().ok_or_else(|| {
            "index mode requires --appchain-wal for targeted reads".to_owned()
        })?;
        let frame = read_frame_at(wal, entry.offset)?;
        // 完整性校验（fail-closed）：索引行 ↔ 帧内容 ↔ sequencer 签名。
        let hash = frame.hash().map_err(|e| format!("frame hash: {e}"))?;
        if hash != entry.hash
            || frame.frame.index != entry.index
            || frame.frame.ts_ms != entry.ts_ms
            || frame.frame.state_root != entry.state_root
        {
            return Err(format!(
                "index/wal integrity mismatch at frame {} (offset {})",
                entry.index, entry.offset
            ));
        }
        if !SequencerKey::verify(&state.sequencer_public, &hash, &frame.sig) {
            return Err(format!(
                "frame signature invalid at frame {} (offset {})",
                entry.index, entry.offset
            ));
        }
        match frame.frame.op {
            Operation::Settle(record) => Ok(Some((frame.frame.index, frame.frame.ts_ms, *record))),
            _ => Err(format!(
                "indexed frame {} is not a Settle (index corruption)",
                entry.index
            )),
        }
    } else {
        Ok(None)
    }
}

/// 定向读单帧（index 模式明细查询用；WAL 记录格式 = `u32 LE 长度 || borsh`）。
fn read_frame_at(wal: &Path, offset: u64) -> Result<SignedFrame, String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(wal).map_err(|e| format!("wal open: {e}"))?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| format!("wal seek: {e}"))?;
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf).map_err(|_| "wal record truncated".to_owned())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err("wal frame length insane".to_owned());
    }
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf).map_err(|_| "wal frame truncated".to_owned())?;
    borsh::from_slice::<SignedFrame>(&buf).map_err(|_| "wal frame decode failed".to_owned())
}

// ===== 端点实现 =====

/// `GET /api/v1/status`。
fn status(state: &Arc<GatewayState>) -> Response {
    Response::json(200, status_json(state).to_string())
}

/// status 载荷（`/api/v1/status` 与快照导出共用）。
#[must_use]
pub fn status_json(state: &GatewayState) -> serde_json::Value {
    // 双数据面：链头/计数在 replay 模式取内存链，index 模式取索引头部行
    // （冻结契约：chain_head/frame_count/settlement_count）。TE-M5 资产
    // 摘要只在 replay 模式可得（token 聚合账是 WAL 重放重建态，不入索引
    // ——index 模式恒 null，如实呈现，不从 v1 计数伪造）。
    let (chain_head, frame_count, settlement_count, batch_covered, latest_batch_root, assets) =
        if let Some(seq) = &state.seq {
            let seq = seq.lock().expect("gateway seq lock");
            let frames = seq.chain();
            let head = frames.last();
            let head_json = serde_json::json!({
                "index": head.map(|f| f.frame.index),
                "hash": head.map(|f| f.hash().ok()).flatten().map(hex::encode),
                "state_root": head.map(|f| hex::encode(f.frame.state_root)),
            });
            let covered = seq.batch_covered_through();
            let root = covered.and_then(|op| seq.batch_root_at(op)).map(hex::encode);
            let assets = assets_summary(seq.state());
            (
                head_json,
                frames.len() as u64,
                settlement_frames(&seq).len() as u64,
                serde_json::json!(covered),
                serde_json::json!(root),
                serde_json::json!(assets),
            )
        } else if let Some(index) = &state.index {
            let h = index.header();
            (
                serde_json::json!({
                    "index": h.chain_head_index,
                    "hash": hex::encode(h.chain_head_hash),
                    "state_root": hex::encode(h.chain_head_state_root),
                }),
                h.frame_count,
                h.settlement_count,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
            )
        } else {
            (
                serde_json::json!({"index": null, "hash": null, "state_root": null}),
                0,
                0,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
            )
        };
    serde_json::json!({
        "env": "devnet",
        "data_source": state.data_source,
        "chain_head": chain_head,
        "sequencer_public": hex::encode(state.sequencer_public),
        "watermark": state.watermark,
        "watermark_source": state.watermark_source,
        "batch_covered_through": batch_covered,
        "latest_batch_root": latest_batch_root,
        "latest_aggregate_root": state.aggregates.last().map(|a| hex::encode(a.root)),
        "latest_aggregate_through_op": state.aggregates.last().map(|a| a.through_op),
        "frame_count": frame_count,
        "settlement_count": settlement_count,
        "assets": assets,
    })
}

/// `GET /api/v1/frames?offset=&limit=` — 帧摘要分页。
fn frames(state: &Arc<GatewayState>, query: &std::collections::HashMap<String, String>) -> Response {
    let offset = match query_offset(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let limit = match query_limit(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let all = frame_summaries(state);
    let total = all.len() as u64;
    let skip = (offset as usize).min(all.len());
    let page: Vec<serde_json::Value> = all
        .iter()
        .skip(skip)
        .take(limit)
        .map(|f| {
            serde_json::json!({
                "index": f.index,
                "ts_ms": f.ts_ms,
                "state_root": f.state_root_hex,
                "op": f.op,
            })
        })
        .collect();
    let body = serde_json::json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "frames": page,
    });
    Response::json(200, body.to_string())
}

/// `GET /api/v1/settlements?offset=&limit=&table_id=` — 结算摘要分页。
fn settlements(
    state: &Arc<GatewayState>,
    query: &std::collections::HashMap<String, String>,
) -> Response {
    let offset = match query_offset(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let limit = match query_limit(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let table_id = match query.get("table_id") {
        None => None,
        Some(v) => match v.parse::<u64>() {
            Ok(t) => Some(t),
            Err(_) => return error_response(400, "invalid query param: table_id"),
        },
    };

    let matched: Vec<serde_json::Value> = settlement_summaries(state)
        .into_iter()
        .filter(|s| match table_id {
            None => true,
            Some(t) => s.get("table_id").and_then(|v| v.as_u64()) == Some(t),
        })
        .collect();
    let total = matched.len() as u64;
    let skip = (offset as usize).min(matched.len());
    let page: Vec<serde_json::Value> = matched
        .into_iter()
        .skip(skip)
        .take(limit)
        .collect();
    let body = serde_json::json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "settlements": page,
    });
    Response::json(200, body.to_string())
}

/// 结算摘要（列表/快照用：payout 只给 owner 缩写 + amount）。
#[must_use]
pub fn settlement_summary_json(
    f: &SignedFrame,
    r: &SettlementRecord,
    state: &GatewayState,
) -> serde_json::Value {
    serde_json::json!({
        "frame_index": f.frame.index,
        "ts_ms": f.frame.ts_ms,
        "table_id": r.table_id,
        "hand_binding": hex::encode(r.hand_binding),
        "pot": r.pot,
        "rake_base": r.plan.rake_base(),
        "rake_total": r.rake.total,
        "payouts": r.payouts.iter().map(|p| serde_json::json!({
            "owner_short": short_hex(&p.owner),
            "amount": p.amount,
        })).collect::<Vec<_>>(),
        "level": level_for(state, f.frame.index),
    })
}

/// `GET /api/v1/settlement/{hand_binding_hex}` — 单笔结算全量明细。
fn settlement_detail(state: &Arc<GatewayState>, binding_hex: &str) -> Response {
    let binding = match decode_hex32(binding_hex) {
        Some(b) => b,
        None => {
            return error_response(400, "invalid hand_binding (need 64 hex chars)");
        }
    };
    let (frame_index, ts_ms, record) = match find_settlement_record(state, &binding) {
        Ok(Some(hit)) => hit,
        Ok(None) => return error_response(404, "settlement not found"),
        Err(e) => {
            // fail-closed：index/WAL 完整性问题不出数据
            eprintln!("[explorer_gateway] settlement detail integrity error: {e}");
            return error_response(500, "index/wal integrity check failed");
        }
    };
    let r = &record;
    let plan = &r.plan;
    let binding_hex = hex::encode(r.hand_binding);
    // proof 链接：注册表命中时补 engine（未命中 → engine = null，链接仍给
    // 出——诚实表达"该结算暂无已归档证明产物"）。
    let registry_hit = state
        .proofs
        .iter()
        .find(|e| e.binding_hex == binding_hex);
    let body = serde_json::json!({
        "frame_index": frame_index,
        "ts_ms": ts_ms,
        "table_id": r.table_id,
        "hand_binding": binding_hex,
        "pot": r.pot,
        "policy_commitment": hex::encode(r.policy_commitment),
        "payout_root": hex::encode(payout_root_bytes(r)),
        "level": level_for(state, frame_index),
        "proof": {
            "href": format!("/api/v1/proof/{binding_hex}"),
            "engine": registry_hit.map(|e| e.engine.as_str()),
        },
        "inputs": r.inputs.iter().map(|i| {
            // TE-M5：资产维度展示（v1 note 经冻结映射 of_v1 升维——
            // Real → real:native / Play → game:play(legacy)，唯一换算）
            let asset = asset_id_json(&AssetId::of_v1(i.note.asset_class));
            serde_json::json!({
                "commitment": hex::encode(i.spend.commitment),
                "nullifier": hex::encode(i.spend.nullifier),
                "owner": hex::encode(i.note.owner),
                "amount": i.note.amount,
                "asset_class": i.note.asset_class.name(),
                "asset_id": asset,
                "table_id": i.note.table_id,
            })
        }).collect::<Vec<_>>(),
        "payouts": r.payouts.iter().map(|p| {
            let asset = asset_id_json(&AssetId::of_v1(p.asset_class));
            serde_json::json!({
                "owner": hex::encode(p.owner),
                "amount": p.amount,
                "asset_class": p.asset_class.name(),
                "asset_id": asset,
                "table_id": p.table_id,
                "pot_index": p.pot_index,
                "runout_index": p.runout_index,
            })
        }).collect::<Vec<_>>(),
        "rake": {
            "total": r.rake.total,
            "treasury_out": r.rake.treasury_out.as_ref().map(|o| serde_json::json!({
                "owner": hex::encode(o.owner),
                "amount": o.amount,
                "asset_class": o.asset_class.name(),
                "asset_id": asset_id_json(&AssetId::of_v1(o.asset_class)),
            })),
            "operator_out": r.rake.operator_out.as_ref().map(|o| serde_json::json!({
                "owner": hex::encode(o.owner),
                "amount": o.amount,
                "asset_class": o.asset_class.name(),
                "asset_id": asset_id_json(&AssetId::of_v1(o.asset_class)),
            })),
        },
        "plan": {
            "version": plan.version,
            "schedule": schedule_name(&plan.schedule),
            "gross_pot": plan.gross_pot,
            "rake": plan.rake,
            "total_awards": plan.total_awards,
            "winner_mask": plan.winner_mask,
            "pot_count": plan.pots.len(),
            "pots": plan.pots.iter().map(|p| serde_json::json!({
                "pot_index": p.pot_index,
                "gross_amount": p.gross_amount,
                "rake": p.rake,
                "net_amount": p.net_amount,
                "eligible_mask": p.eligible_mask,
                "contested": p.is_contested(),
                "active_runouts": active_runouts(plan, p.pot_index),
            })).collect::<Vec<_>>(),
        },
        "hand_proof": r.hand_proof.as_ref().map(|hp| serde_json::json!({
            "archive_bytes_len": hp.archive_bytes.len(),
            "post_state_commitment": hex::encode(hp.post_state_commitment),
            "pre_state_root": hex::encode(hp.pre_state_root),
            "post_state_root": hex::encode(hp.post_state_root),
        })),
    });
    Response::json(200, body.to_string())
}

/// runout 调度名。
fn schedule_name(s: &poker_settlement_core::SettlementRunoutSchedule) -> String {
    match s {
        poker_settlement_core::SettlementRunoutSchedule::Single => "Single".to_string(),
        poker_settlement_core::SettlementRunoutSchedule::Twice { .. } => "Twice".to_string(),
    }
}

/// 该层的 active runout 槽位数（contested 层 = 调度数；否则 1）。
fn active_runouts(
    plan: &poker_settlement_core::SettlementPlan,
    pot_index: u8,
) -> usize {
    let Some(pot) = plan.pots.iter().find(|p| p.pot_index == pot_index) else {
        return 0;
    };
    if pot.is_contested() {
        usize::from(plan.schedule.count())
    } else {
        1
    }
}

/// `GET /api/v1/batch_roots` — proven log 的批次根列表。
fn batch_roots(state: &Arc<GatewayState>) -> Response {
    let body = serde_json::json!({
        "batch_roots": state.proven.iter().map(|e| serde_json::json!({
            "op_index": e.op_index,
            "batch_root": hex::encode(e.batch_root),
            "ts_ms": e.ts_ms,
        })).collect::<Vec<_>>(),
    });
    Response::json(200, body.to_string())
}

/// proof 注册表命中查询（binding hex → 条目引用）。
fn proof_hit<'a>(
    state: &'a GatewayState,
    binding_hex: &str,
) -> Option<&'a poker_appchain::proof_registry::ProofRegistryEntry> {
    state.proofs.iter().find(|e| e.binding_hex == binding_hex)
}

/// `GET /api/v1/proofs?offset=&limit=` — proof 归档元数据分页（只给元数据，
/// 不内联 payload——下载走 `/api/v1/proof/{binding_hex}`）。
fn proofs(state: &Arc<GatewayState>, query: &std::collections::HashMap<String, String>) -> Response {
    let offset = match query_offset(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let limit = match query_limit(query) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let total = state.proofs.len() as u64;
    let skip = (offset as usize).min(state.proofs.len());
    let page: Vec<serde_json::Value> = state
        .proofs
        .iter()
        .skip(skip)
        .take(limit)
        .map(|e| {
            serde_json::json!({
                "binding_hex": e.binding_hex,
                "op_index": e.op_index,
                "engine": e.engine,
                "payload_bytes": e.payload.len(),
            })
        })
        .collect();
    let body = serde_json::json!({
        "total": total,
        "offset": offset,
        "limit": limit,
        "proofs": page,
    });
    Response::json(200, body.to_string())
}

/// `GET /api/v1/proof/{binding_hex}` — proof 归档下载（payload_b64 全量）。
///
/// 响应头：`Content-Type: application/json`（传输层统一附加）+
/// `X-Zchain-Engine`（命中时 = 归档引擎标识）；坏 hex → 400；格式合法但
/// 未命中 → 404（JSON）。
fn proof_download(state: &Arc<GatewayState>, binding_hex: &str) -> Response {
    if decode_hex32(binding_hex).is_none() {
        return error_response(400, "invalid binding (need 64 hex chars)");
    }
    let Some(e) = proof_hit(state, binding_hex) else {
        return error_response(404, "proof not found");
    };
    let mut resp = Response::json(
        200,
        serde_json::json!({
            "binding_hex": e.binding_hex,
            "op_index": e.op_index,
            "engine": e.engine,
            "attestor_public": hex::encode(e.attestor_public),
            "payload_b64": poker_appchain::proof_registry::b64_encode(&e.payload),
            "payload_len": e.payload.len(),
        })
        .to_string(),
    );
    resp.extra_headers
        .push(("X-Zchain-Engine".to_string(), e.engine.clone()));
    resp
}

/// `GET /api/v1/aggregates` — M4 outer aggregate 聚合记录列表。
fn aggregates(state: &Arc<GatewayState>) -> Response {
    let body = serde_json::json!({
        "aggregates": state.aggregates.iter().map(|a| serde_json::json!({
            "index": a.index,
            "through_op": a.through_op,
            "root": hex::encode(a.root),
            "ts_ms": a.ts_ms,
            "batch_count": a.batch_count,
        })).collect::<Vec<_>>(),
    });
    Response::json(200, body.to_string())
}

/// `GET /api/v1/metrics` — 注册表文本导出（启动态静态快照）。
fn metrics(state: &Arc<GatewayState>) -> Response {
    let body = serde_json::json!({
        "mode": state.data_source,
        "note": "static snapshot captured at startup; the gateway does not process live ops",
        "metrics": state.metrics.export_text(),
    });
    Response::json(200, body.to_string())
}

/// `GET /api/v1/l1/*` — L1 只读代理（未配置 `--l1-rpc` → 404）。
fn l1_route(l1: Option<&L1Client>, method: &str, params: serde_json::Value) -> Response {
    let Some(client) = l1 else {
        return error_response(404, "l1 proxy not configured (start with --l1-rpc)");
    };
    match client.call(method, params) {
        Ok(result) => Response::json(
            200,
            serde_json::json!({ "ok": true, "method": method, "result": result }).to_string(),
        ),
        Err(e) => Response::json(
            502,
            serde_json::json!({ "ok": false, "error": format!("l1 rpc failed: {e}") }).to_string(),
        ),
    }
}
