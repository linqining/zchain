//! `rake_audit verify`——rake 审计的**独立代码路径**复验。
//!
//! ## 独立性边界（v1，如实标注）
//!
//! - 本文件**不 import** `poker_appchain` 的任何模块：不调用
//!   `settlement::validate_settlement`、不调用 `fee::FeePolicy`，公式按
//!   导出的 rate/cap/treasury_bps 数值在本地用 u128 独立重实现
//!   （`floor(base·rate/10⁴)`、cap==0 = 无封顶、`floor(rake·treasury_bps/10⁴)`
//!   、零头归 operator）——与链内校验器**无共享代码**，只共享被审计的数值；
//! - 依赖仅 `serde_json` + `hex` + std；
//! - **完整第三方独立性**（独立仓库、独立构建、第三方维护）仍是 M5-ACC-3
//!   的最终形态；当前"同仓独立代码路径"是通往该形态的 v1 步骤，不能宣称
//!   已达成第三方审计独立性。
//!
//! ## 复验清单（与导出文件对照，任何一条不符即差异）
//!
//! 1. 逐条重算：`rake_base = Σ contested 层 gross`（contested 标志按
//!    `eligible_seats ≥ 2` 独立重导出，不信任导出标志）；期望 rake =
//!    `min(floor(rake_base×rate_bps/10⁴), cap)`；`treasury =
//!    floor(rake×treasury_bps/10⁴)`、`operator = rake − treasury`，与导出
//!    值逐一比对；
//! 2. uncontested 层 rake 必须为 0（B9 contested-only 计费语义）；
//! 3. 守恒：`Σinputs == Σpayouts + Σrake_outputs`（全部用导出数值）；
//! 4. 汇总 `header.rake_total` 与明细和一致；`hand_binding` 全非零。

use std::path::Path;

/// 复验一条审计文件。
///
/// # Errors
/// 文件不可读 / JSON 不合法 / 结构缺字段（输入错误，对应退出码 2）。
/// 结构合法但数值不符 → 返回差异清单（非空 = 退出码 1）。
pub fn run(path: &Path) -> Result<Vec<String>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("读取 {} 失败: {e}", path.display()))?;
    let doc: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("JSON 解析失败: {e}"))?;

    let format = str_field(&doc, "format")?;
    if format != crate::FORMAT_TAG {
        return Err(format!("format 不支持：{format:?}（期望 {:?}）", crate::FORMAT_TAG));
    }
    let header = doc
        .get("header")
        .ok_or("缺 header 对象")?
        .as_object()
        .ok_or("header 不是对象")?;
    if !header.contains_key("wal_head_hash") {
        return Err("header 缺 wal_head_hash".into());
    }
    let header_rake_total = header
        .get("rake_total")
        .ok_or("header 缺 rake_total")?
        .as_u64()
        .ok_or("header.rake_total 不是非负整数")?;
    let records = doc
        .get("records")
        .ok_or("缺 records 数组")?
        .as_array()
        .ok_or("records 不是数组")?;

    let mut diffs: Vec<String> = Vec::new();
    let mut detail_rake_sum: u64 = 0;
    for (i, rec) in records.iter().enumerate() {
        verify_record(i, rec, &mut diffs);

        let rake_total = rec.get("rake_total").and_then(|v| v.as_u64()).unwrap_or(0);
        detail_rake_sum = detail_rake_sum.saturating_add(rake_total);
    }

    // 4. 汇总一致性：删改明细必然造成明细和 ≠ 头部汇总。
    if detail_rake_sum != header_rake_total {
        diffs.push(format!(
            "汇总不一致：header.rake_total={header_rake_total} 但明细和={detail_rake_sum}（记录数 {}）",
            records.len()
        ));
    }
    Ok(diffs)
}

/// 逐条复验（清单 1–4 的记录级部分）。
fn verify_record(i: usize, rec: &serde_json::Value, diffs: &mut Vec<String>) {
    let tag = |what: &str| format!("records[{i}](frame={}) {what}", rec.get("frame_index").and_then(|v| v.as_u64()).unwrap_or(u64::MAX));
    let num = |name: &str| rec.get(name).and_then(|v| v.as_u64());

    // hand_binding 非零 + 形状（32 字节 hex）。
    match rec.get("hand_binding").and_then(|v| v.as_str()) {
        None => diffs.push(tag("缺 hand_binding hex（按结构错误计入差异）")),
        Some(h) => match hex_decode_32(h) {
            None => diffs.push(tag("hand_binding 不是 64 位 hex")),
            Some(b) if b == [0u8; 32] => diffs.push(tag("hand_binding 为全零")),
            Some(_) => {}
        },
    }

    // 逐层：contested 标志独立重导出（eligible_seats ≥ 2）+ B9 uncontested rake==0。
    let Some(pots) = rec.get("pots").and_then(|v| v.as_array()) else {
        diffs.push(tag("缺 pots 数组"));
        return;
    };
    if pots.is_empty() {
        diffs.push(tag("pots 为空（结算至少一层）"));
    }
    let mut recomputed_base: u128 = 0;
    for (li, pot) in pots.iter().enumerate() {
        let gross = pot.get("gross_amount").and_then(|v| v.as_u64());
        let rake = pot.get("rake").and_then(|v| v.as_u64());
        let seats = pot.get("eligible_seats").and_then(|v| v.as_u64());
        let contested = pot.get("contested").and_then(|v| v.as_bool());
        let (Some(gross), Some(rake), Some(seats), Some(contested)) = (gross, rake, seats, contested) else {
            diffs.push(format!("records[{i}] pots[{li}] 缺 gross_amount/rake/eligible_seats/contested"));
            continue;
        };
        let recomputed_contested = seats >= 2;
        if contested != recomputed_contested {
            diffs.push(format!(
                "records[{i}] pots[{li}] contested 标志={} 与 eligible_seats={seats} 矛盾（应为 {recomputed_contested}）",
                contested
            ));
        }
        if !recomputed_contested && rake != 0 {
            diffs.push(format!(
                "records[{i}] pots[{li}] uncontested 层 rake={rake} ≠ 0（B9：uncalled/sole-survivor 层不计费）"
            ));
        }
        if recomputed_contested {
            recomputed_base += u128::from(gross);
        }
    }

    // 1. rake_base / 期望 rake / 分账独立重算。
    let Some(rake_base) = num("rake_base") else {
        diffs.push(tag("缺 rake_base"));
        return;
    };
    if u128::from(rake_base) != recomputed_base {
        diffs.push(format!(
            "records[{i}] rake_base={rake_base} 与 contested 层 gross 之和={recomputed_base} 不符"
        ));
    }
    let Some(policy) = rec.get("policy") else {
        diffs.push(tag("缺 policy 对象"));
        return;
    };
    let mode = policy.get("mode").and_then(|v| v.as_u64());
    let rate_bps = policy.get("rate_bps").and_then(|v| v.as_u64());
    let cap = policy.get("cap").and_then(|v| v.as_u64());
    let treasury_bps = policy.get("treasury_bps").and_then(|v| v.as_u64());
    let (Some(mode), Some(rate_bps), Some(cap), Some(treasury_bps)) = (mode, rate_bps, cap, treasury_bps) else {
        diffs.push(tag("policy 缺 mode/rate_bps/cap/treasury_bps"));
        return;
    };
    let expected_total: u128 = match mode {
        0 => 0, // ZERO 桌：任意基数抽取恒 0
        1 => {
            if rate_bps > 10_000 {
                diffs.push(format!("records[{i}] rate_bps={rate_bps} 越界（>10000）"));
            }
            let raw = u128::from(rake_base) * u128::from(rate_bps) / 10_000;
            if cap == 0 { raw } else { raw.min(u128::from(cap)) }
        }
        other => {
            diffs.push(format!("records[{i}] 未知策略 mode={other}"));
            return;
        }
    };
    let Some(rake_total) = num("rake_total") else {
        diffs.push(tag("缺 rake_total"));
        return;
    };
    if u128::from(rake_total) != expected_total {
        diffs.push(format!(
            "records[{i}] rake_total={rake_total} 与独立重算值={expected_total} 不符（base={rake_base} rate_bps={rate_bps} cap={cap}）"
        ));
    }
    let expected_treasury = expected_total * u128::from(treasury_bps) / 10_000;
    let expected_operator = expected_total - expected_treasury;
    check_split(i, "treasury_out", expected_treasury, rec, diffs);
    check_split(i, "operator_out", expected_operator, rec, diffs);

    // 3. 守恒（全部用导出数值）。
    let cons = rec.get("conservation");
    let get_sum = |name: &str| cons.and_then(|c| c.get(name)).and_then(|v| v.as_u64());
    let (Some(inputs), Some(payouts), Some(rake_outs)) =
        (get_sum("inputs_sum"), get_sum("payouts_sum"), get_sum("rake_outputs_sum"))
    else {
        diffs.push(tag("conservation 缺 inputs_sum/payouts_sum/rake_outputs_sum"));
        return;
    };
    if u128::from(inputs) != u128::from(payouts) + u128::from(rake_outs) {
        diffs.push(format!(
            "records[{i}] 守恒不符：Σinputs={inputs} ≠ Σpayouts={payouts} + Σrake_outputs={rake_outs}"
        ));
    }
}

/// 分账输出核对：期望数额 > 0 时必须存在且数额一致；期望为 0 时必须为 null。
fn check_split(
    i: usize,
    name: &str,
    expected: u128,
    rec: &serde_json::Value,
    diffs: &mut Vec<String>,
) {
    let field = rec.get(name);
    match (expected, field) {
        (0, None) | (0, Some(serde_json::Value::Null)) => {}
        (0, Some(_)) => {
            diffs.push(format!("records[{i}] {name} 应为 null（期望分账为 0）"));
        }
        (_, None) | (_, Some(serde_json::Value::Null)) => {
            diffs.push(format!("records[{i}] 缺 {name}（期望分账 {expected}）"));
        }
        (_, Some(o)) => {
            let amount = o.get("amount").and_then(|v| v.as_u64());
            let owner = o.get("owner").and_then(|v| v.as_str());
            match (amount, owner) {
                (Some(a), Some(h)) => {
                    if u128::from(a) != expected {
                        diffs.push(format!(
                            "records[{i}] {name}.amount={a} 与独立重算值={expected} 不符"
                        ));
                    }
                    if hex::decode(h).map(|b| b.len()).unwrap_or(0) != 33 {
                        diffs.push(format!("records[{i}] {name}.owner 不是 66 位 hex（33 字节压缩公钥）"));
                    }
                }
                _ => diffs.push(format!("records[{i}] {name} 缺 amount/owner")),
            }
        }
    }
}

/// 64 位 hex → 32 字节（verify 本地实现，不用共享工具）。
fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    bytes.try_into().ok()
}

/// str 字段读取（verify 本地实现）。
fn str_field<'a>(doc: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    doc.get(name)
        .ok_or_else(|| format!("缺 {name}"))?
        .as_str()
        .ok_or_else(|| format!("{name} 不是字符串"))
}
