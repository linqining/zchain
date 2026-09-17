//! wallet-core 的 WASM 绑定（plan-appchain §6.12.4 Extension 0.1）。
//!
//! # 纪律
//!
//! 本文件是 wallet-core 公开 API 之上的**纯 JSON 前端**：不含任何密码学实现。
//! 摘要（blake2s/poseidon）、签名（secp256k1）、加密（Argon2id + ChaCha20-Poly1305）
//! 全部由 `wallet_core`（以及它复用的 `poker_appchain` 校验面）完成。浏览器扩展
//! 的 JS 侧（`extension/background/`）不得自行实现任何原语，一律经本模块。
//!
//! # 构建（feature `wasm` 门控；默认构建/测试/CLI 完全不受影响）
//!
//! ```text
//! CC_wasm32_unknown_unknown=<支持 wasm32 的 clang> \
//! cargo build -p poker-wallet --target wasm32-unknown-unknown \
//!             --features wasm --release --bin wallet_core_wasm
//! wasm-bindgen --target web --out-dir <repo>/extension/vendor/wallet-core \
//!     target/wasm32-unknown-unknown/release/wallet_core_wasm.wasm
//! ```
//!
//! `required-features = ["wasm"]`（Cargo.toml）+ 本文件的
//! `#[cfg(target_arch = "wasm32")]` 双重门控：native 下该 bin 不会被构建
//! （`required-features`），带 `--features wasm` 的 native 构建也只会得到
//! 空桩（见文件底部）。
//!
//! # ABI 约定（所有入口均为 `String -> String`，JSON）
//!
//! - 金额一律**十进制字符串**（JS Number 只有 2^53 安全整数，u64 金额必须绕开）；
//! - 公钥（33B）/承诺/nullifier/摘要（32B）一律小写 hex；
//! - `SealedEnvelope`/`SettlementRecord`/`FeePolicy` 用 borsh（稳定字节 ABI）+
//!   hex 传输，与账本层逐字节一致（WALLET-ACC-2 的逻辑前提）；
//! - 错误统一 `{"error": "<STABLE_CODE>", "detail": "..."}`；detail 来自
//!   wallet-core 的 `WalletError` Display，不含任何密钥材料。
//!
//! # 会话模型
//!
//! 单会话槽（`SESSION`）：解锁后 owner key / DEK / 双 note 库 / nonce 账本
//! 只存在于 wasm 线性内存中，`wallet_lock()` 即整体 drop；持久化形态只有
//! 密文（口令信封 + DEK 信封 + 加密 note 库快照），由 JS 侧落 chrome.storage。
//! 私钥/DEK/spend secret **永不**跨越 wasm 边界输出。

#[cfg(not(target_arch = "wasm32"))]
fn main() {}

#[cfg(target_arch = "wasm32")]
fn main() {}

// ===========================================================================
// Extension 0.2 共享逻辑（非门控：native 测试可直接覆盖，wasm 入口薄转发）
//
// 设计约束：本模块零密码学、零 IO、无 wasm 依赖——只有对 poker-appchain /
// poker-settlement-core 公开校验面的**纯 JSON 前端**，因此可以在 native 下
// 用 `cargo test -p poker-wallet --features wasm --bin wallet_core_wasm`
// 完整测试（与 wasm32 下的行为同一份实现）。会话/口令相关入口仍在下方
// `mod imp`（wasm32 门控）。
// ===========================================================================

/// Extension 0.2：proof portal 的结算关系复验（网关 settlement 明细 JSON →
/// 本地验证结论）。
///
/// # 诚实边界（不虚标）
///
/// 网关 `/api/v1/settlement/{binding}` 明细**不含** record borsh 与 P 层
/// SpendAuth 签名，因此本验证面验证的是**结算关系的可复算投影**：
///
/// 1. `hand_binding` 非零且为 64 hex；
/// 2. 守恒：`Σinputs == plan.gross_pot == pot`，`Σpayouts + rake.total == pot`；
/// 3. 费率关系：`rake.total == plan.rake`；plan 分层自洽
///    （`Σ pots.gross == gross_pot`，`Σ pots.net + Σ pots.rake == Σ gross`）；
/// 4. **payout_root 复算比对**：由 payouts（owner/amount/asset/table/pot/
///    runout）经 `poker_appchain::settlement::payout_root_bytes`（与链同一
///    实现，`poker_settlement_core::payout_root`）重算，与网关声明的
///    `payout_root` 逐字节比对——赔付结构任何篡改必然失配；
/// 5. payout 的 table_id 与记录 table_id 一致（None 或 Some(同值)）。
///
/// **不在本面内**：P 层签名验证、手牌证明绑定、STARK 证明本身（浏览器内
/// 完整 STARK 验证属 stwo-wasm，0.2 未交付——portal 如实展示归档引擎与
/// 字节数，不宣称"证明已验证"）。签名完备记录的全量校验仍走
/// `wallet_preview(kind=settle)` / `wallet_sign(kind=settle)`（M6-ACC-1 面）。
///
/// 层级（proven / soft_accepted）是网关水位声明，本验证面**不推进**层级
/// （层级推进需要批次根/BFT 证据，见 verifier::verify_batch_root / 软确认链）。
mod portal_check {
    use serde_json::{json, Value};

    use poker_appchain::note::{AssetClass, NoteSpec};
    use poker_appchain::settlement::{payout_root_bytes, RakeSplitRecord, SettlementRecord};

    use wallet_core::error::{WalletError, WalletResult};

    /// 结算明细复验：输入 = 网关 settlement detail 的投影（只读取本面需要的
    /// 字段，未知字段忽略——网关演进不破坏旧客户端）。
    pub fn verify_detail(detail: &Value) -> WalletResult<Value> {
        let binding_hex = str_field(detail, "hand_binding")?;
        let binding = decode_hex32(binding_hex).ok_or(WalletError::InvalidArgument("hand_binding"))?;
        if binding == [0u8; 32] {
            return Err(WalletError::InvalidArgument("hand_binding zero"));
        }
        let table_id = u64_field(detail, "table_id")?;
        let pot = u64_field(detail, "pot")?;
        let declared_payout_root = decode_hex32(str_field(detail, "payout_root")?)
            .ok_or(WalletError::InvalidArgument("payout_root"))?;

        // ---- plan 投影（只读数值字段）----
        let plan = detail
            .get("plan")
            .and_then(Value::as_object)
            .ok_or(WalletError::InvalidArgument("plan"))?;
        let gross_pot = json_u64(plan.get("gross_pot"), "plan.gross_pot")?;
        let plan_rake = json_u64(plan.get("rake"), "plan.rake")?;
        let total_awards = json_u64(plan.get("total_awards"), "plan.total_awards")?;
        let pots = plan
            .get("pots")
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("plan.pots"))?;

        // ---- rake 投影 ----
        let rake_total = json_u64(detail.get("rake").and_then(|r| r.get("total")), "rake.total")?;

        // ---- inputs / payouts 投影 ----
        let inputs = detail
            .get("inputs")
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("inputs"))?;
        let payouts = detail
            .get("payouts")
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("payouts"))?;
        if payouts.is_empty() {
            return Err(WalletError::InvalidArgument("payouts empty"));
        }

        let mut checks = Vec::new();
        let mut fail = |name: &'static str, ok: bool, detail: String| {
            checks.push(json!({ "check": name, "ok": ok, "detail": detail }));
            ok
        };

        // (2) 守恒：Σinputs == pot == gross_pot
        let mut sum_inputs = 0u128;
        for i in inputs {
            sum_inputs = sum_inputs
                .checked_add(json_u64(i.get("amount"), "inputs[].amount")? as u128)
                .ok_or(WalletError::AmountOverflow("inputs"))?;
        }
        fail(
            "inputs_sum_equals_pot",
            sum_inputs == pot as u128 && pot as u128 == gross_pot as u128,
            format!("Σinputs {sum_inputs} vs pot {pot} vs plan.gross_pot {gross_pot}"),
        );

        // (2) 守恒：Σpayouts + rake.total == pot
        let mut sum_payouts = 0u128;
        for p in payouts {
            sum_payouts = sum_payouts
                .checked_add(json_u64(p.get("amount"), "payouts[].amount")? as u128)
                .ok_or(WalletError::AmountOverflow("payouts"))?;
        }
        fail(
            "payouts_plus_rake_equals_pot",
            sum_payouts.saturating_add(rake_total as u128) == pot as u128,
            format!("Σpayouts {sum_payouts} + rake {rake_total} vs pot {pot}"),
        );

        // (3) 费率：rake.total == plan.rake == gross_pot - total_awards
        fail(
            "rake_matches_plan",
            rake_total == plan_rake,
            format!("rake.total {rake_total} vs plan.rake {plan_rake}"),
        );
        let awards_delta = (gross_pot as u128)
            .checked_sub(total_awards as u128)
            .ok_or(WalletError::AmountOverflow("plan.awards"))?;
        fail(
            "plan_awards_consistent",
            awards_delta == rake_total as u128,
            format!("gross_pot {gross_pot} - total_awards {total_awards} != rake {rake_total}"),
        );

        // (3) plan 分层自洽：Σ pots.gross == gross_pot；Σ (net + rake) == Σ gross
        let mut sum_gross = 0u128;
        let mut sum_net = 0u128;
        let mut sum_pot_rake = 0u128;
        for p in pots {
            sum_gross = sum_gross
                .checked_add(json_u64(p.get("gross_amount"), "pot.gross_amount")? as u128)
                .ok_or(WalletError::AmountOverflow("plan.pots.gross"))?;
            sum_net = sum_net
                .checked_add(json_u64(p.get("net_amount"), "pot.net_amount")? as u128)
                .ok_or(WalletError::AmountOverflow("plan.pots.net"))?;
            sum_pot_rake = sum_pot_rake
                .checked_add(json_u64(p.get("rake"), "pot.rake")? as u128)
                .ok_or(WalletError::AmountOverflow("plan.pots.rake"))?;
        }
        fail(
            "plan_pots_sum",
            sum_gross == pot as u128 && sum_net + sum_pot_rake == sum_gross,
            format!("Σpots.gross {sum_gross} vs pot {pot}; Σ(net+rake) {} vs Σgross {sum_gross}", sum_net + sum_pot_rake),
        );

        // (4) payout_root 复算（与链同一实现）。
        let specs: Vec<NoteSpec> = payouts
            .iter()
            .map(|p| parse_note_spec(p, table_id))
            .collect::<WalletResult<Vec<_>>>()?;
        // payout_root 只依赖 payouts + table_id：dummy plan 不参与计算
        // （flat_settlement_plan 是 poker-appchain 的公开构造器；awards 数长
        // = SETTLEMENT_SEATS，若上层变更该常量本文件编译期即失败——可见、
        // 无静默漂移）。
        let dummy_record = SettlementRecord {
            table_id,
            hand_binding: binding,
            policy_commitment: [0u8; 32],
            pot,
            inputs: Vec::new(),
            payouts: specs,
            rake: RakeSplitRecord { total: rake_total, treasury_out: None, operator_out: None },
            plan: poker_appchain::settlement::flat_settlement_plan(0, 0, [0u64; 9]),
            hand_proof: None,
        };
        let computed = payout_root_bytes(&dummy_record);
        let root_ok = computed == declared_payout_root;
        fail(
            "payout_root_recomputed",
            root_ok,
            format!(
                "computed {} vs declared {}",
                hex::encode(computed),
                hex::encode(declared_payout_root)
            ),
        );

        // (5) payout table_id 与记录一致（None 或 Some(同值)）。
        let table_ok = payouts.iter().all(|p| match p.get("table_id") {
            None | Some(Value::Null) => true,
            Some(v) => v.as_u64() == Some(table_id),
        });
        fail("payout_table_id_consistent", table_ok, format!("record table_id {table_id}"));

        let all_ok = checks.iter().all(|c| c.get("ok").and_then(Value::as_bool).unwrap_or(false));
        let verifier = wallet_core::verifier::meta();
        Ok(json!({
            "verdict": if all_ok { "verified" } else { "rejected" },
            "binding": hex::encode(binding),
            "table_id": table_id,
            "pot": pot.to_string(),
            "payout_root_declared": hex::encode(declared_payout_root),
            "payout_root_computed": hex::encode(computed),
            "checks": checks,
            "verifier": {
                "name": verifier.name,
                "version": verifier.version,
                "abi_version": verifier.abi_version,
            },
        })
        )
    }

    // ---- 小工具（portal_check 内部）----

    fn str_field<'a>(v: &'a Value, key: &'static str) -> WalletResult<&'a str> {
        v.get(key).and_then(Value::as_str).ok_or(WalletError::InvalidArgument(key))
    }

    fn u64_field(v: &Value, key: &'static str) -> WalletResult<u64> {
        json_u64(v.get(key), key)
    }

    fn json_u64(v: Option<&Value>, key: &'static str) -> WalletResult<u64> {
        let v = v.ok_or(WalletError::InvalidArgument(key))?;
        if let Some(n) = v.as_u64() {
            return Ok(n);
        }
        // 金额/索引也可能是十进制字符串（JS Number 精度纪律）。
        let s = v.as_str().ok_or(WalletError::InvalidArgument(key))?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WalletError::InvalidArgument(key));
        }
        s.parse().map_err(|_| WalletError::AmountOverflow(key))
    }

    /// 严格 64-hex（portal 侧绑定/根字段）。
    fn decode_hex32(s: &str) -> Option<[u8; 32]> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(out)
    }

    /// 网关 payout JSON → NoteSpec（同 ABI 字段；payout.table_id 为 None 时
    /// 落记录 table_id，与 payout_leaves 的 leaf 语义一致）。
    fn parse_note_spec(p: &Value, record_table_id: u64) -> WalletResult<NoteSpec> {
        // 网关明细端点为展示隐私把 owner 截成 short_hex；全量 66-hex 走
        // owner_full（wasm 复算 payout_root 必须全量）。兼容两者：优先
        // owner_full，缺失时回落 owner（直连 WAL/旧网关载荷）。
        let owner_hex = match p.get("owner_full").and_then(Value::as_str) {
            Some(h) if h.len() == 66 && h.bytes().all(|b| b.is_ascii_hexdigit()) => h,
            _ => str_field(p, "owner")?,
        };
        if owner_hex.len() != 66 || !owner_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(WalletError::InvalidArgument("payouts[].owner"));
        }
        let mut owner = [0u8; 33];
        hex::decode_to_slice(owner_hex, &mut owner).map_err(|_| WalletError::InvalidArgument("payouts[].owner"))?;
        let amount = json_u64(p.get("amount"), "payouts[].amount")?;
        if amount == 0 {
            return Err(WalletError::InvalidArgument("payouts[].amount zero"));
        }
        let class = match str_field(p, "asset_class")? {
            "REAL" => AssetClass::Real,
            "PLAY" => AssetClass::Play,
            _ => return Err(WalletError::InvalidArgument("payouts[].asset_class")),
        };
        let pot_index = json_u64(p.get("pot_index"), "payouts[].pot_index")?;
        let runout_index = json_u64(p.get("runout_index"), "payouts[].runout_index")?;
        if pot_index > u8::MAX as u64 || runout_index > u8::MAX as u64 {
            return Err(WalletError::InvalidArgument("payouts[].index"));
        }
        Ok(NoteSpec {
            asset_class: class,
            amount,
            owner,
            // leaf 语义：PayoutLeaf.table_id 恒取记录 table_id（见
            // poker_appchain::settlement::payout_leaves）；payout 自身的
            // table_id 一致性由第 (5) 项检查单独断言。
            table_id: Some(record_table_id),
            pot_index: pot_index as u8,
            runout_index: runout_index as u8,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::verify_detail;
        use serde_json::{json, Value};

        use poker_appchain::note::{AssetClass, NoteSpec};
        use poker_appchain::settlement::{
            flat_settlement_plan, payout_root_bytes, RakeSplitRecord, SettlementRecord,
        };

        const TABLE: u64 = 1001;
        const HAND_BINDING: [u8; 32] = [7; 32];

        fn spec(owner_seed: u8, amount: u64, pot_index: u8, runout_index: u8) -> NoteSpec {
            NoteSpec {
                asset_class: AssetClass::Play,
                amount,
                owner: [owner_seed; 33],
                table_id: Some(TABLE),
                pot_index,
                runout_index,
            }
        }

        /// 构造一份与 explorer gateway `/api/v1/settlement/{binding}` 明细同
        /// 形状的投影 JSON（正例；输入侧只提供 amount——校验面只读金额）。
        fn detail_from(record: &SettlementRecord, inputs_amounts: &[u64]) -> Value {
            let pots: Vec<Value> = record
                .plan
                .pots
                .iter()
                .map(|p| {
                    json!({
                        "pot_index": p.pot_index,
                        "gross_amount": p.gross_amount,
                        "rake": p.rake,
                        "net_amount": p.net_amount,
                    })
                })
                .collect();
            json!({
                "hand_binding": hex::encode(record.hand_binding),
                "table_id": record.table_id,
                "pot": record.pot,
                "payout_root": hex::encode(payout_root_bytes(record)),
                "rake": { "total": record.rake.total },
                "plan": {
                    "gross_pot": record.plan.gross_pot,
                    "rake": record.plan.rake,
                    "total_awards": record.plan.total_awards,
                    "pots": pots,
                },
                "inputs": inputs_amounts.iter().map(|a| json!({
                    "amount": a, "asset_class": "PLAY", "commitment": "ab".repeat(32),
                })).collect::<Vec<_>>(),
                "payouts": record.payouts.iter().map(|p| json!({
                    "owner": hex::encode(p.owner),
                    "amount": p.amount,
                    "asset_class": p.asset_class.name(),
                    "table_id": p.table_id,
                    "pot_index": p.pot_index,
                    "runout_index": p.runout_index,
                })).collect::<Vec<_>>(),
            })
        }

        /// 两层 pot（主池 + 边池）正例记录：payout 投影与 plan 一致。
        fn two_pot_record() -> SettlementRecord {
            // awards[0]=700（座 0），awards[1]=2170（座 1）；gross 3020 = 700+2170+rake 150
            let mut awards = [0u64; 9];
            awards[0] = 700;
            awards[1] = 2170;
            let gross = 3020u64;
            let plan = flat_settlement_plan(gross, 0b11, awards);
            SettlementRecord {
                table_id: TABLE,
                hand_binding: HAND_BINDING,
                policy_commitment: [3; 32],
                pot: gross,
                inputs: Vec::new(), // 校验面只读明细 JSON 的 inputs[].amount
                payouts: vec![
                    spec(1, 700, 0, 0),
                    spec(2, 1070, 1, 0),
                    spec(2, 1100, 1, 1),
                ],
                rake: RakeSplitRecord { total: plan.rake, treasury_out: None, operator_out: None },
                plan,
                hand_proof: None,
            }
        }

        fn checks_of(v: &Value) -> Vec<(String, bool)> {
            v["checks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| (c["check"].as_str().unwrap().to_string(), c["ok"].as_bool().unwrap()))
                .collect()
        }

        #[test]
        fn positive_detail_verifies_and_recomputes_payout_root() {
            let record = two_pot_record();
            let detail = detail_from(&record, &[1510, 1510]);
            let verdict = verify_detail(&detail).unwrap();
            assert_eq!(verdict["verdict"], "verified", "{verdict}");
            assert_eq!(verdict["payout_root_computed"], verdict["payout_root_declared"]);
            assert_eq!(verdict["binding"], hex::encode(HAND_BINDING));
            // verifier 元信息（UI 显示"验证器版本"）来自 wallet-core 单实现。
            assert_eq!(verdict["verifier"]["name"], wallet_core::verifier::VERIFIER_NAME);
            assert!(checks_of(&verdict).iter().all(|(_, ok)| *ok));
            // pot / 金额为十进制字符串（JS 安全整数纪律）
            assert_eq!(verdict["pot"], "3020");
        }

        #[test]
        fn tampered_payout_breaks_payout_root_binding() {
            let record = two_pot_record();
            let mut detail = detail_from(&record, &[1510, 1510]);
            // 赔付金额被篡改（1070 → 1071），声明的 payout_root 未变 → 复算必失配
            detail["payouts"][1]["amount"] = json!(1071);
            let verdict = verify_detail(&detail).unwrap();
            assert_eq!(verdict["verdict"], "rejected");
            let checks = checks_of(&verdict);
            assert!(!checks.iter().all(|(_, ok)| *ok));
            assert!(checks.iter().any(|(n, ok)| n == "payout_root_recomputed" && !ok));
            // 守恒同样被破坏（Σpayouts + rake != pot）
            assert!(checks.iter().any(|(n, ok)| n == "payouts_plus_rake_equals_pot" && !ok));
        }

        #[test]
        fn declared_payout_root_mismatch_rejected() {
            let record = two_pot_record();
            let mut detail = detail_from(&record, &[1510, 1510]);
            detail["payout_root"] = json!(hex::encode([9u8; 32]));
            let verdict = verify_detail(&detail).unwrap();
            assert_eq!(verdict["verdict"], "rejected");
            assert!(checks_of(&verdict).iter().any(|(n, ok)| n == "payout_root_recomputed" && !ok));
        }

        #[test]
        fn conservation_and_rake_relation_fail_closed() {
            let record = two_pot_record();
            // (a) Σinputs != pot
            let d = detail_from(&record, &[3020, 2999]);
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "rejected");
            // (b) rake.total 与 plan.rake 不一致
            let mut d = detail_from(&record, &[1510, 1510]);
            d["rake"]["total"] = json!(100);
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "rejected");
            // (c) plan.awards 与 rake 不自洽（total_awards 抬高）
            let mut d = detail_from(&record, &[1510, 1510]);
            d["plan"]["total_awards"] = json!(2971);
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "rejected");
            // (d) plan 分层 gross 与 pot 不符
            let mut d = detail_from(&record, &[1510, 1510]);
            d["plan"]["pots"][0]["gross_amount"] = json!(9999);
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "rejected");
        }

        #[test]
        fn structural_inputs_fail_closed() {
            let record = two_pot_record();
            // 零 hand_binding
            let mut d = detail_from(&record, &[1510, 1510]);
            d["hand_binding"] = json!("00".repeat(32));
            assert!(verify_detail(&d).is_err());
            // 坏长度 binding
            let mut d = detail_from(&record, &[1510, 1510]);
            d["hand_binding"] = json!("ab".repeat(31));
            assert!(verify_detail(&d).is_err());
            // 非 hex payout owner
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"][0]["owner"] = json!("zz".repeat(33));
            assert!(verify_detail(&d).is_err());
            // 零金额 payout
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"][0]["amount"] = json!(0);
            assert!(verify_detail(&d).is_err());
            // 未知资产类
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"][0]["asset_class"] = json!("POINTS");
            assert!(verify_detail(&d).is_err());
            // payout.table_id 与记录不符
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"][0]["table_id"] = json!(2002);
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "rejected");
            // payouts 缺失
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"] = json!([]);
            assert!(verify_detail(&d).is_err());
            // 十进制字符串金额接受（JS 侧安全整数纪律）
            let mut d = detail_from(&record, &[1510, 1510]);
            d["payouts"][0]["amount"] = json!("700");
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "verified");
        }

        #[test]
        fn mixed_asset_payouts_recompute_consistently() {
            // REAL/PLAY 混合赔付（asset 字节进入 payout leaf）——复算仍须一致。
            let mut record = two_pot_record();
            record.payouts[1].asset_class = AssetClass::Real;
            let d = detail_from(&record, &[1510, 1510]);
            // 注意：detail 的 asset_class 字符串来自记录本身，REAL leaf 参与
            // payout_root，复算一致 → verified。
            assert_eq!(verify_detail(&d).unwrap()["verdict"], "verified");
        }
    }
}

/// Extension 0.3/0.4：会话密钥 binding 的状态查询、限额 enforcement 与
/// SNIP-12 `AuthorizeZChainKey` 摘要（全部为 wallet-core 公开纯函数之上的
/// **纯 JSON 前端**：`account_binding` / `key_manager` 的状态机与 admission
/// 单实现；本模块零密码学实现、零 IO、无 wasm 依赖，native 下可直接测试，
/// 与 wasm32 下行为同一份实现）。
///
/// # 输入形状（extension 侧 binding 记录的 JSON 镜像；camelCase）
///
/// ```text
/// {
///   "bindingId": <64 hex>,            // 主键
///   "chainId": "zchain-devnet-1",     // 换网失效（防跨链重放）
///   "accountAddress": <felt hex>,     // 授权方 Starknet 账户（≤64 hex）
///   "delegatedPublicKey": <66 hex>,   // delegated key（33B 压缩 secp256k1）
///   "allowedScopes": ["play", …],     // key_manager::Scope 名
///   "perTxLimit": <十进制|null>,      // null → 不限（SNIP-12 编码 0）
///   "perDayLimit": <十进制|null>,
///   "tableAllowlist": [u64]|null,     // null = 全桌
///   "nonce": u64, "validAfter": u64, "validUntil": u64,
///   "revoked": bool,                  // 撤销粘滞位
///   "dailyUsedDay": u64, "dailyUsedAmount": <十进制>  // 日限聚合
/// }
/// ```
///
/// 准入判定顺序与 `key_manager::session_admission` 完全一致（撤销 → 换网 →
/// 时间窗 → scope → 桌白名单 → 单笔限额 → 日限额，fail-closed）；拒绝不是
/// error 而是**结构化 verdict**（`{admitted:false, rejected_reason}`）——
/// admission 本身成功产出了结论，拒绝的是这笔请求。扩展 JS 层有同序镜像
/// 实现（`extension/common/sessions.js`），两层独立校验（wasm/JS 双层）。
mod session_check {
    use serde_json::{json, Value};

    use wallet_core::account_binding::{
        authorize_encode_type, authorize_message_hash, binding_admission, constraints_from_message,
        AuthorizeZChainKeyMessage, BindingStatus, SessionBinding, Snip12Domain,
    };
    use wallet_core::error::{SessionRejectReason, WalletError, WalletResult};
    use wallet_core::key_manager::{Scope, SessionAdmission};

    /// binding/请求 JSON 的公共小工具（与 portal_check 各自独立，保持模块
    /// 零交叉依赖）。
    fn json_u64(v: Option<&Value>, key: &'static str) -> WalletResult<u64> {
        let v = v.ok_or(WalletError::InvalidArgument(key))?;
        if let Some(n) = v.as_u64() {
            return Ok(n);
        }
        let s = v.as_str().ok_or(WalletError::InvalidArgument(key))?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WalletError::InvalidArgument(key));
        }
        s.parse().map_err(|_| WalletError::AmountOverflow(key))
    }

    /// 限额字段：缺失/null/"0" → None（不限，SNIP-12 amount 编码 0）。
    fn amount_opt(v: Option<&Value>, key: &'static str) -> WalletResult<Option<u64>> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(v) => match json_u64(Some(v), key)? {
                0 => Ok(None),
                n => Ok(Some(n)),
            },
        }
    }

    fn is_hex(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// felt hex（≤64 hex；'0x' 前缀可选）→ 32B 大端左填充。
    fn felt_bytes(s: &str, field: &'static str) -> WalletResult<[u8; 32]> {
        let t = s.strip_prefix("0x").unwrap_or(s);
        if !is_hex(t) || t.len() > 64 {
            return Err(WalletError::InvalidArgument(field));
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(format!("{t:0>64}"), &mut out)
            .map_err(|_| WalletError::InvalidArgument(field))?;
        Ok(out)
    }

    /// 定长 hex（'0x' 前缀可选）→ n 字节。
    fn fixed_bytes(s: &str, n: usize, field: &'static str) -> WalletResult<Vec<u8>> {
        let t = s.strip_prefix("0x").unwrap_or(s);
        if t.len() != n * 2 || !is_hex(t) {
            return Err(WalletError::InvalidArgument(field));
        }
        hex::decode(t).map_err(|_| WalletError::InvalidArgument(field))
    }

    /// JSON → `AuthorizeZChainKeyMessage`（SNIP-12 message 的扩展侧镜像）。
    pub fn parse_message(v: &Value) -> WalletResult<AuthorizeZChainKeyMessage> {
        let zchain_chain_id = v
            .get("chainId")
            .and_then(Value::as_str)
            .ok_or(WalletError::InvalidArgument("chainId"))?
            .to_string();
        if zchain_chain_id.is_empty() {
            return Err(WalletError::InvalidArgument("chainId"));
        }
        let account_address = felt_bytes(
            v.get("accountAddress")
                .and_then(Value::as_str)
                .ok_or(WalletError::InvalidArgument("accountAddress"))?,
            "accountAddress",
        )?;
        let delegated_public_key = {
            let b = fixed_bytes(
                v.get("delegatedPublicKey")
                    .and_then(Value::as_str)
                    .ok_or(WalletError::InvalidArgument("delegatedPublicKey"))?,
                33,
                "delegatedPublicKey",
            )?;
            let mut out = [0u8; 33];
            out.copy_from_slice(&b);
            out
        };
        let signature_scheme = v
            .get("signatureScheme")
            .and_then(Value::as_str)
            .unwrap_or("secp256k1")
            .to_string();
        let allowed_scopes = v
            .get("allowedScopes")
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("allowedScopes"))?
            .iter()
            .map(|s| Scope::from_name(s.as_str().ok_or(WalletError::InvalidArgument("allowedScopes[]"))?))
            .collect::<WalletResult<Vec<_>>>()?;
        if allowed_scopes.is_empty() {
            return Err(WalletError::InvalidArgument("allowedScopes empty"));
        }
        let per_tx_limit = amount_opt(v.get("perTxLimit"), "perTxLimit")?;
        let per_day_limit = amount_opt(v.get("perDayLimit"), "perDayLimit")?;
        let table_allowlist = match v.get("tableAllowlist") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => Some(
                a.iter()
                    .map(|t| json_u64(Some(t), "tableAllowlist[]"))
                    .collect::<WalletResult<Vec<_>>>()?,
            ),
            Some(_) => return Err(WalletError::InvalidArgument("tableAllowlist")),
        };
        let binding_id = {
            let b = fixed_bytes(
                v.get("bindingId")
                    .and_then(Value::as_str)
                    .ok_or(WalletError::InvalidArgument("bindingId"))?,
                32,
                "bindingId",
            )?;
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            out
        };
        Ok(AuthorizeZChainKeyMessage {
            zchain_chain_id,
            account_address,
            delegated_public_key,
            signature_scheme,
            allowed_scopes,
            per_tx_limit,
            per_day_limit,
            table_allowlist,
            binding_id,
            nonce: json_u64(v.get("nonce"), "nonce")?,
            valid_after: json_u64(v.get("validAfter"), "validAfter")?,
            valid_until: json_u64(v.get("validUntil"), "validUntil")?,
        })
    }

    /// binding 记录 JSON → [`SessionBinding`]（constraints + 撤销粘滞位 +
    /// 日限聚合；constraints 由 message 经 `constraints_from_message` 派生，
    /// 与 SNIP-12 字段一一对应）。
    pub fn parse_binding(v: &Value) -> WalletResult<SessionBinding> {
        let msg = parse_message(v)?;
        let mut binding = SessionBinding::new(constraints_from_message(&msg));
        binding.revoked = v.get("revoked").and_then(Value::as_bool).unwrap_or(false);
        binding.daily_used_day = json_u64(v.get("dailyUsedDay"), "dailyUsedDay").unwrap_or(0);
        binding.daily_used_amount =
            json_u64(v.get("dailyUsedAmount"), "dailyUsedAmount").unwrap_or(0);
        Ok(binding)
    }

    fn status_name(s: BindingStatus) -> &'static str {
        match s {
            BindingStatus::Active => "active",
            BindingStatus::Expired => "expired",
            BindingStatus::Revoked => "revoked",
            BindingStatus::Exhausted => "exhausted",
        }
    }

    fn reason_name(r: &SessionRejectReason) -> &'static str {
        match r {
            SessionRejectReason::Revoked => "Revoked",
            SessionRejectReason::NotYetValid => "NotYetValid",
            SessionRejectReason::Expired => "Expired",
            SessionRejectReason::ScopeNotAllowed => "ScopeNotAllowed",
            SessionRejectReason::TableNotAllowed => "TableNotAllowed",
            SessionRejectReason::OverPerTxLimit => "OverPerTxLimit",
            SessionRejectReason::DailyLimitExhausted => "DailyLimitExhausted",
            SessionRejectReason::ChainMismatch => "ChainMismatch",
            SessionRejectReason::UnknownBinding => "UnknownBinding",
            SessionRejectReason::OwnerRequired => "OwnerRequired",
        }
    }

    /// binding 状态查询（撤销粘滞 / 时间窗 / 日限耗尽；wallet-core 状态机
    /// 单实现输出——撤销状态查询入口，Extension 0.4 registry UI 消费）。
    pub fn status(v: &Value, now: u64) -> WalletResult<Value> {
        let binding = parse_binding(v)?;
        let st = binding.status(now);
        let daily_remaining = binding.constraints.daily_limit.map(|limit| {
            let used = if binding.daily_used_day == now / 86_400 { binding.daily_used_amount } else { 0 };
            limit.saturating_sub(used)
        });
        Ok(json!({
            "status": status_name(st),
            "binding_id": hex::encode(binding.constraints.binding_id),
            "chain_id": binding.constraints.chain_id,
            "allowed_scopes": binding.constraints.allowed_scopes.iter().map(|s| s.name()).collect::<Vec<_>>(),
            "per_tx_limit": binding.constraints.per_tx_limit.map(|l| l.to_string()),
            "daily_limit": binding.constraints.daily_limit.map(|l| l.to_string()),
            "daily_used_amount": binding.daily_used_amount.to_string(),
            "daily_used_day": binding.daily_used_day,
            "daily_remaining": daily_remaining.map(|r| r.to_string()),
            "valid_after": binding.constraints.valid_after.to_string(),
            "valid_until": binding.constraints.valid_until.to_string(),
        })
        )
    }

    /// 限额/约束 enforcement（Extension 0.4 签名路径第二层；请求形状
    /// `{scope, table_id|null, amount, chain_id}`）。拒绝是结构化 verdict
    /// （非 error）：`{admitted:false, rejected_reason:<SessionRejectReason 名>}`。
    pub fn admit(binding_v: &Value, req: &Value, now: u64) -> WalletResult<Value> {
        let binding = parse_binding(binding_v)?;
        let scope = Scope::from_name(
            req.get("scope")
                .and_then(Value::as_str)
                .ok_or(WalletError::InvalidArgument("scope"))?,
        )?;
        let table_id = match req.get("table_id") {
            None | Some(Value::Null) => None,
            Some(v) => Some(json_u64(Some(v), "table_id")?),
        };
        let admission = SessionAdmission {
            scope,
            table_id,
            amount: json_u64(req.get("amount"), "amount")?,
            chain_id: req
                .get("chain_id")
                .and_then(Value::as_str)
                .ok_or(WalletError::InvalidArgument("chain_id"))?
                .to_string(),
        };
        let st = status_name(binding.status(now));
        match binding_admission(&binding, &admission, now) {
            Ok(()) => Ok(json!({ "admitted": true, "rejected_reason": null, "status": st })),
            Err(WalletError::SessionRejected(r)) => {
                Ok(json!({ "admitted": false, "rejected_reason": reason_name(&r), "status": st }))
            }
            Err(e) => Err(e),
        }
    }

    /// SNIP-12 `AuthorizeZChainKey` 完整摘要（revision 1；poseidon，wallet-core
    /// 单实现）。Extension 0.3 的授权确认页展示该摘要——用户确认的即此摘要。
    pub fn authorize_digest(v: &Value) -> WalletResult<Value> {
        let msg = parse_message(v)?;
        let domain = Snip12Domain::zchain(&msg.zchain_chain_id);
        let hash = authorize_message_hash(&domain, &msg)?;
        Ok(json!({
            "digest": format!("0x{}", hex::encode(hash.to_bytes_be())),
            "encode_type": authorize_encode_type(),
            "domain": {
                "name": domain.name,
                "version": domain.version,
                "chainId": domain.chain_id,
                "revision": wallet_core::account_binding::SNIP12_REVISION,
            },
        })
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

        use wallet_core::account_binding::{authorize_message_hash, Snip12Domain};

        fn binding_json() -> Value {
            json!({
                "bindingId": format!("{}ab", "00".repeat(31)),
                "chainId": "zchain-devnet-1",
                "accountAddress": "0x1234",
                "delegatedPublicKey": "cd".repeat(33),
                "signatureScheme": "secp256k1",
                "allowedScopes": ["play", "buyin", "settle"],
                "perTxLimit": "1000",
                "perDayLimit": "5000",
                "tableAllowlist": [1, 2],
                "nonce": 7,
                "validAfter": 1_000_000,
                "validUntil": 2_000_000,
                "revoked": false,
                "dailyUsedDay": 0,
                "dailyUsedAmount": "0",
            })
        }

        const NOW: u64 = 1_500_000;

        #[test]
        fn status_query_reflects_state_machine() {
            let b = binding_json();
            assert_eq!(status(&b, NOW).unwrap()["status"], "active");
            // 未生效 / 过期（时间窗 [valid_after, valid_until)）
            assert_eq!(status(&b, 999_999).unwrap()["status"], "expired");
            assert_eq!(status(&b, 2_000_000).unwrap()["status"], "expired");
            // 撤销粘滞：有效期内也是 revoked
            let mut r = b.clone();
            r["revoked"] = json!(true);
            let st = status(&r, NOW).unwrap();
            assert_eq!(st["status"], "revoked");
            assert_eq!(st["binding_id"], format!("{}ab", "00".repeat(31)));
            // 日限耗尽（同一天窗口内用满）
            let mut e = b.clone();
            e["dailyUsedDay"] = json!(NOW / 86_400);
            e["dailyUsedAmount"] = json!("5000");
            assert_eq!(status(&e, NOW).unwrap()["status"], "exhausted");
            // 跨天窗重置（used 记在前一天）
            let mut e2 = b.clone();
            e2["dailyUsedDay"] = json!(NOW / 86_400 - 1);
            e2["dailyUsedAmount"] = json!("5000");
            assert_eq!(status(&e2, NOW).unwrap()["status"], "active");
            // daily_remaining 投影
            let mut h = b.clone();
            h["dailyUsedDay"] = json!(NOW / 86_400);
            h["dailyUsedAmount"] = json!("1200");
            assert_eq!(status(&h, NOW).unwrap()["daily_remaining"], "3800");
        }

        #[test]
        fn admit_positive_and_limit_enforcement() {
            let b = binding_json();
            let req = json!({ "scope": "buyin", "table_id": 1, "amount": "1000", "chain_id": "zchain-devnet-1" });
            let v = admit(&b, &req, NOW).unwrap();
            assert_eq!(v["admitted"], true, "{v}");
            // 单笔超限
            let over = json!({ "scope": "buyin", "table_id": 1, "amount": "1001", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &over, NOW).unwrap()["rejected_reason"], "OverPerTxLimit");
            // 桌白名单外
            let table = json!({ "scope": "buyin", "table_id": 3, "amount": "10", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &table, NOW).unwrap()["rejected_reason"], "TableNotAllowed");
            // 白名单模式下缺桌 id（fail-closed）
            let no_table = json!({ "scope": "settle", "amount": "10", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &no_table, NOW).unwrap()["rejected_reason"], "TableNotAllowed");
            // scope 不在授权集
            let scope = json!({ "scope": "transfer", "amount": "10", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &scope, NOW).unwrap()["rejected_reason"], "ScopeNotAllowed");
            // 换网
            let chain = json!({ "scope": "buyin", "table_id": 1, "amount": "10", "chain_id": "zchain-testnet-1" });
            assert_eq!(admit(&b, &chain, NOW).unwrap()["rejected_reason"], "ChainMismatch");
            // 时间窗（admission 区分未生效/过期；状态机查询统一归并 expired）
            let early = json!({ "scope": "buyin", "table_id": 1, "amount": "10", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &early, 999_999).unwrap()["rejected_reason"], "NotYetValid");
            let late = json!({ "scope": "buyin", "table_id": 1, "amount": "10", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &late, 2_000_000).unwrap()["rejected_reason"], "Expired");
            // 撤销最优先（时间窗/限额讨论都无效）
            let mut r = b.clone();
            r["revoked"] = json!(true);
            assert_eq!(admit(&r, &req, NOW).unwrap()["rejected_reason"], "Revoked");
        }

        #[test]
        fn admit_daily_limit_aggregates_across_day_window() {
            let mut b = binding_json();
            b["dailyUsedDay"] = json!(NOW / 86_400);
            b["dailyUsedAmount"] = json!("4200");
            // 当日剩余 800：800 可过、801 拒
            let ok = json!({ "scope": "buyin", "table_id": 1, "amount": "800", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &ok, NOW).unwrap()["admitted"], true);
            let over = json!({ "scope": "buyin", "table_id": 1, "amount": "801", "chain_id": "zchain-devnet-1" });
            assert_eq!(admit(&b, &over, NOW).unwrap()["rejected_reason"], "DailyLimitExhausted");
            // 前一天的用量不计入今日窗口
            b["dailyUsedDay"] = json!(NOW / 86_400 - 1);
            assert_eq!(admit(&b, &over, NOW).unwrap()["admitted"], true);
        }

        #[test]
        fn digest_matches_wallet_core_and_is_field_sensitive() {
            let v = binding_json();
            let out = authorize_digest(&v).unwrap();
            // 与 Rust 单实现直接构造的摘要逐字节一致（JSON 前端不引入漂移）。
            let msg = parse_message(&v).unwrap();
            let direct = authorize_message_hash(&Snip12Domain::zchain("zchain-devnet-1"), &msg).unwrap();
            assert_eq!(out["digest"], format!("0x{}", hex::encode(direct.to_bytes_be())));
            assert_eq!(out["encode_type"], wallet_core::account_binding::authorize_encode_type());
            // scope 变化 → 摘要变化
            let mut m = v.clone();
            m["allowedScopes"] = json!(["play"]);
            assert_ne!(out["digest"], authorize_digest(&m).unwrap()["digest"]);
            // 换网 → 摘要变化
            let mut c = v.clone();
            c["chainId"] = json!("zchain-testnet-1");
            assert_ne!(out["digest"], authorize_digest(&c).unwrap()["digest"]);
            // 确定性（同输入两次一致）
            assert_eq!(out["digest"], authorize_digest(&v).unwrap()["digest"]);
        }

        #[test]
        fn parse_fail_closed() {
            // 坏 delegated key 长度
            let mut v = binding_json();
            v["delegatedPublicKey"] = json!("cd".repeat(32));
            assert!(parse_message(&v).is_err());
            // 未知 scope 名
            let mut v = binding_json();
            v["allowedScopes"] = json!(["withdraw"]); // 形状合法；准入由 Scope 集合判定
            assert!(parse_message(&v).is_ok()); // 解析面不拒绝（withdraw 是合法 Scope）
            let mut v = binding_json();
            v["allowedScopes"] = json!(["wizard"]);
            assert!(parse_message(&v).is_err());
            // 空 scopes
            let mut v = binding_json();
            v["allowedScopes"] = json!([]);
            assert!(parse_message(&v).is_err());
            // 坏 bindingId 长度 / 非 hex accountAddress / 非十进制金额
            let mut v = binding_json();
            v["bindingId"] = json!("ab".repeat(31));
            assert!(parse_message(&v).is_err());
            let mut v = binding_json();
            v["accountAddress"] = json!("zz");
            assert!(parse_message(&v).is_err());
            let mut v = binding_json();
            v["perTxLimit"] = json!("-5");
            assert!(parse_message(&v).is_err());
            // null 限额 = 不限
            let mut v = binding_json();
            v["perTxLimit"] = Value::Null;
            let msg = parse_message(&v).unwrap();
            assert_eq!(msg.per_tx_limit, None);
            // felt accountAddress 左填充（'0x1234' → 高位零）
            let v = binding_json();
            let msg = parse_message(&v).unwrap();
            assert_eq!(msg.account_address[31], 0x34);
            assert_eq!(msg.account_address[30], 0x12);
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::sync::Mutex;

    use borsh::BorshDeserialize;
    use serde_json::{json, Value};
    use wasm_bindgen::prelude::wasm_bindgen;

    use poker_appchain::fee::FeePolicy;
    use poker_appchain::note::{AssetClass, Note};
    use poker_appchain::settlement::SettlementRecord;
    use poker_appchain::soft_confirm::genesis_prev_hash;

    use wallet_core::error::{WalletError, WalletResult};
    use wallet_core::key_manager::OwnerKeyPair;
    use wallet_core::keystore::{self, SealedEnvelope};
    use wallet_core::note_store::{NoteRecord, OriginFrame, ProofState, WalletStores};
    use wallet_core::operation_signer::{
        parse_domain, NetworkCtx, NonceTracker, OutputSpec, RequestContext, Signer, SigningRequest,
        DOMAIN_OPERATION_DIGEST, SUPPORTED_ABI_VERSION,
    };

    /// Extension 0.1 唯一网络（devnet；换网是 0.2 交付）。
    pub const DEFAULT_CHAIN_ID: &str = "zchain-devnet-1";

    /// console.error（避免依赖 wasm-bindgen 的 console 特性开关）。
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console)]
        fn log_error(s: &str);
    }

    /// 解锁会话：内存态，锁定即 drop。明文密钥材料不出本结构。
    struct Session {
        key: OwnerKeyPair,
        dek: wallet_core::key_manager::SecretBytes,
        stores: WalletStores,
        nonces: NonceTracker,
        /// 持久化所需的密文形态（owner/DEK 信封 borsh hex；解锁时原样保留）。
        owner_envelope_hex: String,
        dek_envelope_hex: String,
        chain_id: String,
        /// Extension 0.3：本会话内生成的 delegated/session key（私钥只活在
        /// wasm 线性内存，锁定即 drop；持久化形态只有约束记录，由扩展侧
        /// 保存——会话密钥自身的链上签名路径未开放，0.3/0.4 交付的是授权
        /// 与约束执行面）。
        session_keys: Vec<wallet_core::key_manager::SessionKey>,
    }

    static SESSION: Mutex<Option<Session>> = Mutex::new(None);

    fn set_panic_hook() {
        use std::sync::Once;
        static HOOK: Once = Once::new();
        HOOK.call_once(|| {
            std::panic::set_hook(Box::new(|info| {
                log_error(&format!("wallet_core_wasm panic: {info}"));
            }));
        });
    }

    fn lock_session() -> std::sync::MutexGuard<'static, Option<Session>> {
        SESSION.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// WalletError → 稳定错误码（extension 校验层与 UI 依赖这些码，不解析文本）。
    fn error_code(e: &WalletError) -> &'static str {
        match e {
            WalletError::BadPassword => "BadPassword",
            WalletError::Tampered(_) => "Tampered",
            WalletError::UnsupportedVersion { .. } => "UnsupportedVersion",
            WalletError::UnknownDomainTag(_) => "UnknownDomainTag",
            WalletError::UnknownAbiVersion(_) => "UnknownAbiVersion",
            WalletError::AmountOverflow(_) => "AmountOverflow",
            WalletError::RawBytesRejected => "RawBytesRejected",
            WalletError::SessionRejected(_) => "SessionRejected",
            WalletError::Expired { .. } => "Expired",
            WalletError::NonceReplay { .. } => "NonceReplay",
            WalletError::NoteNotFound(_) => "NoteNotFound",
            WalletError::AssetClassMismatch(_) => "AssetClassMismatch",
            WalletError::VerifierRejected(_) => "VerifierRejected",
            WalletError::Codec(_) => "Codec",
            WalletError::InvalidArgument(_) => "InvalidArgument",
            WalletError::BadKeyMaterial(_) => "BadKeyMaterial",
            WalletError::ReorgDetected { .. } => "ReorgDetected",
            WalletError::VaultRejected(_) => "VaultRejected",
            WalletError::Io(_) => "Io",
        }
    }

    fn err_json(e: &WalletError) -> String {
        json!({ "error": error_code(e), "detail": e.to_string() }).to_string()
    }

    fn parse_json(s: &str) -> Result<Value, WalletError> {
        serde_json::from_str(s).map_err(|e| WalletError::Codec(format!("bad json: {e}")))
    }

    /// 金额解析（fail-closed）：只接受十进制整数（字符串优先），拒绝负数/
    /// 小数/非安全数值/u64 溢出/0。
    fn amount_u64(v: &Value, field: &'static str) -> Result<u64, WalletError> {
        let s = match v.as_str() {
            Some(s) => s.to_string(),
            None => match v.as_u64() {
                Some(n) => n.to_string(),
                None => {
                    return Err(WalletError::InvalidArgument(field));
                }
            },
        };
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(WalletError::InvalidArgument(field));
        }
        let n: u64 = s.parse().map_err(|_| WalletError::AmountOverflow(field))?;
        if n == 0 {
            return Err(WalletError::AmountOverflow(field));
        }
        Ok(n)
    }

    fn u64_field(v: &Value, field: &'static str) -> Result<u64, WalletError> {
        let n = amount_u64(v, field)?;
        Ok(n)
    }

    fn hex_field(v: &Value, field: &'static str, len: usize) -> Result<Vec<u8>, WalletError> {
        let bytes = hex_var(v, field)?;
        if bytes.len() != len {
            return Err(WalletError::InvalidArgument(field));
        }
        Ok(bytes)
    }

    /// 变长 hex（borsh 载荷；长度 sanity 上限 4 KiB，防异常输入）。
    fn hex_var(v: &Value, field: &'static str) -> Result<Vec<u8>, WalletError> {
        let s = v.as_str().ok_or(WalletError::InvalidArgument(field))?;
        if s.len() > 8192 {
            return Err(WalletError::InvalidArgument(field));
        }
        let bytes = hex::decode(s).map_err(|_| WalletError::InvalidArgument(field))?;
        if bytes.is_empty() {
            return Err(WalletError::InvalidArgument(field));
        }
        Ok(bytes)
    }

    fn hex32(v: &Value, field: &'static str) -> Result<[u8; 32], WalletError> {
        let b = hex_field(v, field, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        Ok(out)
    }

    fn hex33(v: &Value, field: &'static str) -> Result<[u8; 33], WalletError> {
        let b = hex_field(v, field, 33)?;
        let mut out = [0u8; 33];
        out.copy_from_slice(&b);
        Ok(out)
    }

    fn asset_class(v: &Value) -> Result<AssetClass, WalletError> {
        match v.as_str() {
            Some("REAL") => Ok(AssetClass::Real),
            Some("PLAY") => Ok(AssetClass::Play),
            _ => Err(WalletError::InvalidArgument("asset_class")),
        }
    }

    /// 请求上下文（network + nonce + expiry）。
    fn parse_ctx(req: &Value) -> Result<RequestContext, WalletError> {
        let chain_id = req
            .get("chain_id")
            .and_then(Value::as_str)
            .ok_or(WalletError::InvalidArgument("chain_id"))?
            .to_string();
        if chain_id.is_empty() {
            return Err(WalletError::InvalidArgument("chain_id"));
        }
        let domain = parse_domain(
            req.get("domain")
                .and_then(Value::as_str)
                .ok_or(WalletError::InvalidArgument("domain"))?,
        )?;
        let abi_version = req.get("abi_version").and_then(Value::as_u64).ok_or(
            WalletError::InvalidArgument("abi_version"),
        )? as u32;
        let nonce = u64_field(req.get("nonce").ok_or(WalletError::InvalidArgument("nonce"))?, "nonce")?;
        let expiry =
            u64_field(req.get("expiry").ok_or(WalletError::InvalidArgument("expiry"))?, "expiry")?;
        Ok(RequestContext {
            network: NetworkCtx { domain, chain_id, abi_version },
            nonce,
            expiry,
        })
    }

    /// JSON 请求 → 结构化 SigningRequest（封闭映射；未知 kind 拒绝）。
    fn parse_request(req: &Value) -> Result<SigningRequest, WalletError> {
        let ctx = parse_ctx(req)?;
        let class = asset_class(req.get("asset_class").ok_or(WalletError::InvalidArgument("asset_class"))?)?;
        let kind = req
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(WalletError::InvalidArgument("kind"))?;
        match kind {
            "transfer" => {
                let inputs = parse_commitment_list(req.get("inputs"))?;
                let outputs = req
                    .get("outputs")
                    .and_then(Value::as_array)
                    .ok_or(WalletError::InvalidArgument("outputs"))?
                    .iter()
                    .map(|o| {
                        Ok(OutputSpec {
                            owner: hex33(o.get("owner").ok_or(WalletError::InvalidArgument("outputs[].owner"))?, "outputs[].owner")?,
                            amount: amount_u64(o.get("amount").ok_or(WalletError::InvalidArgument("outputs[].amount"))?, "outputs[].amount")?,
                        })
                    })
                    .collect::<Result<Vec<OutputSpec>, WalletError>>()?;
                Ok(SigningRequest::Transfer { ctx, asset_class: class, inputs, outputs })
            }
            "buy_in" => {
                let table_id =
                    u64_field(req.get("table_id").ok_or(WalletError::InvalidArgument("table_id"))?, "table_id")?;
                let seat_owner =
                    hex33(req.get("seat_owner").ok_or(WalletError::InvalidArgument("seat_owner"))?, "seat_owner")?;
                let inputs = parse_commitment_list(req.get("inputs"))?;
                Ok(SigningRequest::BuyIn { ctx, asset_class: class, table_id, seat_owner, inputs })
            }
            "settle" => {
                let policy_bytes = hex_var(
                    req.get("policy_borsh").ok_or(WalletError::InvalidArgument("policy_borsh"))?,
                    "policy_borsh",
                )?;
                let policy =
                    FeePolicy::try_from_slice(&policy_bytes).map_err(|e| WalletError::Codec(format!("policy: {e}")))?;
                let record_bytes = hex_var(
                    req.get("record_borsh").ok_or(WalletError::InvalidArgument("record_borsh"))?,
                    "record_borsh",
                )?;
                let record =
                    SettlementRecord::try_from_slice(&record_bytes).map_err(|e| WalletError::Codec(format!("record: {e}")))?;
                Ok(SigningRequest::Settle { ctx, policy, record })
            }
            // 0.1 不开放 withdraw/key_rotation（提现预览与密钥轮换是 0.2/0.3 交付；
            // provider 层同时拒，这里再拒一次：纵深防御）。
            "withdraw" | "key_rotation" => Err(WalletError::InvalidArgument("kind disabled in extension 0.1")),
            _ => Err(WalletError::InvalidArgument("kind")),
        }
    }

    fn parse_commitment_list(v: Option<&Value>) -> Result<Vec<[u8; 32]>, WalletError> {
        let arr = v
            .and_then(Value::as_array)
            .ok_or(WalletError::InvalidArgument("inputs"))?;
        if arr.is_empty() {
            return Err(WalletError::InvalidArgument("inputs"));
        }
        arr.iter().map(|c| hex32(c, "inputs[]")).collect()
    }

    /// SigningPreview → JSON（金额转十进制字符串，避免 JS 精度损失）。
    fn preview_json(p: &wallet_core::operation_signer::SigningPreview) -> Value {
        json!({
            "kind": p.kind,
            "domain": p.domain,
            "chain_id": p.chain_id,
            "abi_version": p.abi_version,
            "asset_class": p.asset_class,
            "amount_in": p.amount_in.to_string(),
            "amount_out": p.amount_out.to_string(),
            "rake": p.rake.to_string(),
            "table_id": p.table_id.map(|t| t.to_string()),
            "outputs": p.outputs.iter().map(|o| json!({
                "owner": o.owner, "amount": o.amount.to_string(),
            })).collect::<Vec<_>>(),
            "request_id": p.request_id,
            "hand_binding": p.hand_binding,
            "proof_states": p.proof_states,
            "expiry": p.expiry.to_string(),
            "nonce": p.nonce.to_string(),
            "digest": p.digest,
        })
    }

    fn keystore_json(session: &Session, play_store_hex: String, real_store_hex: Option<String>) -> Value {
        json!({
            "version": 1,
            "chain_id": session.chain_id,
            "owner_envelope": session.owner_envelope_hex,
            "dek_envelope": session.dek_envelope_hex,
            "play_store": play_store_hex,
            "real_store": real_store_hex,
        })
    }

    fn now_u64(now: &str) -> Result<u64, WalletError> {
        let n: u64 = now.parse().map_err(|_| WalletError::InvalidArgument("now"))?;
        Ok(n)
    }

    // -----------------------------------------------------------------------
    // 入口 0：元信息
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_core_meta() -> String {
        set_panic_hook();
        json!({
            "crate_version": env!("CARGO_PKG_VERSION"),
            "abi_version": SUPPORTED_ABI_VERSION,
            "domain": "zchain",
            "preview_domain": hex::encode(DOMAIN_OPERATION_DIGEST),
            "default_chain_id": DEFAULT_CHAIN_ID,
        })
        .to_string()
    }

    // -----------------------------------------------------------------------
    // 入口 1：创建（真实 Argon2id + ChaCha20-Poly1305 + secp256k1，全在 wallet-core）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_create(password: String, profile: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let (m, t, p) = match profile.as_str() {
                "interactive" => keystore::params_interactive(),
                // 仅测试/冒烟；生产路径必须 interactive。
                "test" => keystore::params_test(),
                _ => return Err(WalletError::InvalidArgument("profile")),
            };
            if password.is_empty() {
                return Err(WalletError::InvalidArgument("password"));
            }
            let key = OwnerKeyPair::generate();
            let dek = keystore::generate_dek();
            let owner_env = keystore::seal_owner_key(&key, password.as_bytes(), (m, t, p))?;
            let dek_env = keystore::seal_dek(&dek, password.as_bytes(), (m, t, p))?;
            let stores = WalletStores::new();
            let play_store_hex = hex::encode(stores.play().seal(&dek)?);
            let session = Session {
                key,
                dek,
                stores,
                nonces: NonceTracker::new(),
                owner_envelope_hex: hex::encode(borsh::to_vec(&owner_env).map_err(|e| WalletError::Codec(format!("owner env: {e}")))?),
                dek_envelope_hex: hex::encode(borsh::to_vec(&dek_env).map_err(|e| WalletError::Codec(format!("dek env: {e}")))?),
                chain_id: DEFAULT_CHAIN_ID.to_string(),
                session_keys: Vec::new(),
            };
            let public_key = hex::encode(session.key.public_bytes());
            let real_store_hex = hex::encode(session.stores.real().seal(&session.dek)?);
            let ks = keystore_json(&session, play_store_hex, Some(real_store_hex));
            *lock_session() = Some(session);
            Ok(json!({ "public_key": public_key, "keystore": ks }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 2：解锁（口令错 → BadPassword fail-closed）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_unlock(keystore: String, password: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let ks = parse_json(&keystore)?;
            let owner_env: SealedEnvelope = SealedEnvelope::try_from_slice(&hex_var(
                ks.get("owner_envelope").ok_or(WalletError::InvalidArgument("owner_envelope"))?,
                "owner_envelope",
            )?)
            .map_err(|e| WalletError::Codec(format!("owner_envelope: {e}")))?;
            let dek_env: SealedEnvelope = SealedEnvelope::try_from_slice(&hex_var(
                ks.get("dek_envelope").ok_or(WalletError::InvalidArgument("dek_envelope"))?,
                "dek_envelope",
            )?)
            .map_err(|e| WalletError::Codec(format!("dek_envelope: {e}")))?;
            let play_blob = hex_var(
                ks.get("play_store").ok_or(WalletError::InvalidArgument("play_store"))?,
                "play_store",
            )?;
            let chain_id = ks
                .get("chain_id")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_CHAIN_ID)
                .to_string();

            let key = keystore::open_owner_key(&owner_env, password.as_bytes())?;
            let dek = keystore::open_dek(&dek_env, password.as_bytes())?;
            let play = wallet_core::note_store::NoteStore::open(&dek, AssetClass::Play, &play_blob)?;
            let mut stores = WalletStores::new();
            stores.set_play(play);
            // REAL 库（Extension 0.2 起：备份恢复/分库视图携带；0.1 账户无此
            // 字段时保持空 REAL 库——分库语义不变）。
            if let Some(real_hex) = ks.get("real_store") {
                let real_blob = hex_var(real_hex, "real_store")?;
                let real = wallet_core::note_store::NoteStore::open(&dek, AssetClass::Real, &real_blob)?;
                stores.set_real(real);
            }
            stores.verify_indexes()?;
            let balances = stores.balances();
            let public_key = hex::encode(key.public_bytes());
            let notes = stores.play().len() + stores.real().len();
            let session = Session {
                key,
                dek,
                stores,
                nonces: NonceTracker::new(),
                owner_envelope_hex: hex::encode(borsh::to_vec(&owner_env).map_err(|e| WalletError::Codec(format!("owner env: {e}")))?),
                dek_envelope_hex: hex::encode(borsh::to_vec(&dek_env).map_err(|e| WalletError::Codec(format!("dek env: {e}")))?),
                chain_id: chain_id.clone(),
                session_keys: Vec::new(),
            };
            *lock_session() = Some(session);
            Ok(json!({
                "public_key": public_key,
                "chain_id": chain_id,
                "play_free": balances.play_free.to_string(),
                "play_locked": balances.play_locked.to_string(),
                "real_free": balances.real_free.to_string(),
                "real_locked": balances.real_locked.to_string(),
                "notes": notes,
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 3：锁定 + 持久化快照
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_lock() -> String {
        set_panic_hook();
        *lock_session() = None;
        json!({ "locked": true }).to_string()
    }

    /// 当前状态 → 持久化密文快照（note 库变化后调用；全部为密文）。
    #[wasm_bindgen]
    pub fn wallet_persist() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let play_store_hex = hex::encode(s.stores.play().seal(&s.dek)?);
            let real_store_hex = hex::encode(s.stores.real().seal(&s.dek)?);
            Ok(keystore_json(s, play_store_hex, Some(real_store_hex)).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 4：devnet PLAY 本地水龙头（Extension 0.1 专用 stub，如实标注）
    // -----------------------------------------------------------------------

    /// 本地铸造一张 PLAY 余额 note（devnet 水龙头 stub：无网络、无链上 mint，
    /// 仅用于 0.1 桌面/买入/结算签名链路演示；真实同步在 0.2 接 `sync` trait）。
    #[wasm_bindgen]
    pub fn wallet_faucet_play(amount: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let n: u64 = amount.parse().map_err(|_| WalletError::InvalidArgument("amount"))?;
            let mut nonce = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let note = Note::new(AssetClass::Play, n, s.key.public_bytes(), nonce, None)
                .map_err(|e| WalletError::Codec(format!("note: {e}")))?;
            let rec = NoteRecord::new(
                note,
                OriginFrame { op_index: 0, frame_hash: genesis_prev_hash() },
                ProofState::Soft,
            );
            let commitment = s.stores.store(AssetClass::Play).insert(rec)?;
            let balances = s.stores.balances();
            Ok(json!({
                "commitment": hex::encode(commitment),
                "play_free": balances.play_free.to_string(),
                "faucet": "local-devnet-stub",
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 5：note 列表（脱敏：无 spend secret、无 nullifier）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_get_notes() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let notes: Vec<Value> = s
                .stores
                .play()
                .records()
                .map(|(commitment, r)| {
                    json!({
                        "commitment": hex::encode(commitment),
                        "amount": r.note.amount.to_string(),
                        "table_id": r.note.table_id.map(|t| t.to_string()),
                        "proof": match r.proof {
                            ProofState::Pending => "pending",
                            ProofState::Soft => "soft",
                            ProofState::Proven { .. } => "proven",
                            ProofState::Finalized => "finalized",
                        },
                        "spendable": r.spendable(),
                    })
                })
                .collect();
            Ok(json!({ "notes": notes }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 6：预览（不占用 nonce；签名前 UI 用）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_preview(req: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&req)?;
            let request = parse_request(&parsed)?;
            let now = now_u64(&now)?;
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            // 预览用一次性 nonce 账本：preview 不占用会话 nonce。
            let mut scratch = NonceTracker::new();
            let mut signer = Signer::new(&s.stores, now, &mut scratch);
            let preview = signer.preview(&request)?;
            Ok(json!({ "preview": preview_json(&preview) }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 7：签名（owner 路径；占用 nonce；全拒绝面生效）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_sign(req: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&req)?;
            let request = parse_request(&parsed)?;
            let now = now_u64(&now)?;
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            let mut signer = Signer::new(&s.stores, now, &mut s.nonces);
            let signed = signer.sign(&request, &s.key)?;
            let op_borsh = borsh::to_vec(&signed.operation)
                .map_err(|e| WalletError::Codec(format!("operation: {e}")))?;
            Ok(json!({
                "operation_borsh": hex::encode(op_borsh),
                "digest": hex::encode(signed.digest),
                "preview": preview_json(&signed.preview),
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // 入口 8：结算单输入补签（多人桌路径；operator 收集 SpendAuth）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_sign_settle_input(record_borsh: String, input_index: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let bytes = hex::decode(&record_borsh).map_err(|_| WalletError::InvalidArgument("record_borsh"))?;
            let record =
                SettlementRecord::try_from_slice(&bytes).map_err(|e| WalletError::Codec(format!("record: {e}")))?;
            let idx: usize = input_index.parse().map_err(|_| WalletError::InvalidArgument("input_index"))?;
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let mut scratch = NonceTracker::new();
            let signer = Signer::new(&s.stores, 0, &mut scratch);
            let auth = signer.sign_settle_input(&record, idx, &s.key)?;
            Ok(json!({
                "commitment": hex::encode(auth.commitment),
                "nullifier": hex::encode(auth.nullifier),
                "sig": hex::encode(auth.sig.bytes),
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // Extension 0.2 入口：REAL/PLAY 全库 note 视图（物理分库 + 余额分栏）
    // -----------------------------------------------------------------------

    /// REAL/PLAY 分库 note 列表 + 按资产类余额（脱敏：无 spend secret/nullifier）。
    /// REAL 侧同样只出承诺/金额/proof 状态——REAL 操作面（提现/claim）0.2 不开放。
    #[wasm_bindgen]
    pub fn wallet_get_all_notes() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            // 物理分库只读访问（real()/play()；store() 需要 &mut，这里仅展示）。
            let view = |recs: &wallet_core::note_store::NoteStore| -> Vec<Value> {
                recs.records()
                    .map(|(commitment, r)| {
                        json!({
                            "commitment": hex::encode(commitment),
                            "amount": r.note.amount.to_string(),
                            "table_id": r.note.table_id.map(|t| t.to_string()),
                            "proof": match r.proof {
                                ProofState::Pending => "pending",
                                ProofState::Soft => "soft",
                                ProofState::Proven { .. } => "proven",
                                ProofState::Finalized => "finalized",
                            },
                            "spendable": r.spendable(),
                        })
                    })
                    .collect()
            };
            let play = view(s.stores.play());
            let real = view(s.stores.real());
            let b = s.stores.balances();
            Ok(json!({
                "play": play,
                "real": real,
                "balances": {
                    "real_free": b.real_free.to_string(),
                    "real_locked": b.real_locked.to_string(),
                    "play_free": b.play_free.to_string(),
                    "play_locked": b.play_locked.to_string(),
                },
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // Extension 0.2 入口：REAL/PLAY 展示门（WALLET-ACC-6，display.rs 单实现）
    // -----------------------------------------------------------------------

    /// UI 展示门视图（claim 门 + 托管风险提示）。Extension 0.2 的就绪态恒为
    /// offline（Vault/verifier/BFT finality 均未接入）→ REAL 页无 claim 操作、
    /// 常显托管风险提示；PLAY 页无任何 REAL 字段。UI 壳层只消费本输出，
    /// 不得自行决定（display.rs 是唯一事实源）。
    #[wasm_bindgen]
    pub fn wallet_display_views() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let b = s.stores.balances();
            let flags = wallet_core::display::ReadinessFlags::offline();
            let real = wallet_core::display::real_page_view(&flags, b.real_free);
            let play = wallet_core::display::play_page_view(b.play_free, true);
            Ok(json!({
                "real": serde_json::to_value(&real).map_err(|e| WalletError::Codec(e.to_string()))?,
                "play": serde_json::to_value(&play).map_err(|e| WalletError::Codec(e.to_string()))?,
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // Extension 0.2 入口：proof portal 的结算关系复验（无会话、无 nonce、
    // 纯验证；诚实边界见上方 portal_check 模块文档）
    // -----------------------------------------------------------------------

    #[wasm_bindgen]
    pub fn wallet_verify_settlement_detail(detail: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&detail)?;
            let verdict = super::portal_check::verify_detail(&parsed)?;
            Ok(verdict.to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // Extension 0.2 入口：全库加密备份导出/导入（WALLET-ACC-5；复用
    // wallet-core backup 单实现：ZCBK v1 + Argon2id + ChaCha20-Poly1305 +
    // 恢复索引自检，全部 fail-closed）
    // -----------------------------------------------------------------------

    /// 备份导出（需解锁会话）：REAL/PLAY 双库快照 + keystore/DEK 信封 +
    /// 声明索引 → 口令加密的 EncryptedBackup（borsh hex 传输；JS 侧转二进制
    /// 文件下载）。profile 同 wallet_create："interactive"（生产 Argon2id
    /// 参数）或 "test"（仅测试/冒烟）。
    #[wasm_bindgen]
    pub fn wallet_backup_export(password: String, profile: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            if password.is_empty() {
                return Err(WalletError::InvalidArgument("password"));
            }
            let params = match profile.as_str() {
                "interactive" => keystore::params_interactive(),
                "test" => keystore::params_test(),
                _ => return Err(WalletError::InvalidArgument("profile")),
            };
            let created_unix = now_u64(&now)?;
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            // 备份是自包含的：owner/DEK 信封以**备份口令**重新封装（与钱包
            // 口令独立）——恢复时只需备份口令即可通过 import_backup 的全链路
            // 自检（口令 → DEK 信封 → 双库解密 → 索引重建比对）。
            let owner_env = keystore::seal_owner_key(&s.key, password.as_bytes(), params)?;
            let dek_env = keystore::seal_dek(&s.dek, password.as_bytes(), params)?;
            let payload = wallet_core::backup::BackupPayloadV1 {
                keystore: Some(owner_env),
                dek_envelope: Some(dek_env),
                real_store: Some(s.stores.real().seal(&s.dek)?),
                play_store: Some(s.stores.play().seal(&s.dek)?),
                bindings: wallet_core::account_binding::BindingRegistry::new(),
                checkpoint: None,
                indexes: wallet_core::backup::collect_indexes(&s.stores),
                created_unix,
            };
            let backup = wallet_core::backup::export_backup(&payload, password.as_bytes(), params)?;
            let counts = (s.stores.real().len(), s.stores.play().len());
            Ok(json!({
                "backup_hex": hex::encode(backup.to_bytes()?),
                "created_unix": created_unix.to_string(),
                "notes": { "real": counts.0, "play": counts.1 },
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// 备份导入（**无会话**：恢复路径在锁定态可用）。拒绝面：结构/魔数篡改
    /// （Tampered）、未来版本（UnsupportedVersion，解密前拒绝）、错误口令
    /// （AEAD 认证失败 → BadPassword）、声明索引与重建索引不一致
    /// （Tampered）。成功时 keystore 信封再用同一口令开启校验一次
    ///（fail-closed 快路径）并回 public_key；恢复数据以密文+信封 hex 返回，
    /// 由 JS 侧落为新账户，**不**自动替换当前会话。
    #[wasm_bindgen]
    pub fn wallet_backup_import(backup_hex: String, password: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            if password.is_empty() {
                return Err(WalletError::InvalidArgument("password"));
            }
            let bytes = hex::decode(backup_hex.trim())
                .map_err(|_| WalletError::InvalidArgument("backup_hex"))?;
            let backup = wallet_core::backup::EncryptedBackup::from_bytes(&bytes)?;
            let payload = wallet_core::backup::import_backup(&backup, password.as_bytes())?;
            let owner_env = payload
                .keystore
                .as_ref()
                .ok_or(WalletError::Tampered("backup missing keystore envelope"))?;
            let key = keystore::open_owner_key(owner_env, password.as_bytes())?;
            let dek_hex = match payload.dek_envelope.as_ref() {
                Some(d) => hex::encode(
                    borsh::to_vec(d).map_err(|e| WalletError::Codec(format!("dek env: {e}")))?,
                ),
                None => return Err(WalletError::Tampered("backup missing dek envelope")),
            };
            let keystore_obj = json!({
                "version": 1,
                "chain_id": DEFAULT_CHAIN_ID,
                "owner_envelope": hex::encode(borsh::to_vec(owner_env).map_err(|e| WalletError::Codec(format!("owner env: {e}")))?),
                "dek_envelope": dek_hex,
                "real_store": payload.real_store.as_ref().map(hex::encode),
                "play_store": payload.play_store.as_ref().map(hex::encode),
            });
            Ok(json!({
                "public_key": hex::encode(key.public_bytes()),
                "created_unix": payload.created_unix.to_string(),
                "keystore": keystore_obj,
                "indexes": {
                    "commitments": payload.indexes.commitments.len(),
                    "nullifiers": payload.indexes.nullifiers.len(),
                    "spent": payload.indexes.spent.len(),
                },
            })
            .to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    // -----------------------------------------------------------------------
    // Extension 0.3/0.4 入口：会话密钥（delegated key）生成 / 列表、binding
    // 状态查询、限额 enforcement、SNIP-12 授权摘要。
    //
    // - delegated key 生成是唯一会话依赖入口（私钥只活在 wasm 线性内存，
    //   锁定即 drop，永不出边界）；其余入口均为上方 `session_check` 纯模块
    //   的薄转发（无会话、无副作用）。
    // - 授权登记/撤销状态的持久化在扩展侧（chrome.storage），链侧 admission
    //   登记入口形态未接（0.3 如实标注）。
    // -----------------------------------------------------------------------

    /// 生成满足约束的 delegated key（OS 随机源；wallet-core 单实现）。
    /// 输入 = session_check 模块文档中的 binding 形状，其中
    /// `delegatedPublicKey` **不可提供**（由本入口生成后返回）；
    /// `bindingId` 可缺省（缺省时用 OS 随机源生成 32B）。
    /// 返回 binding 摘要（公钥级信息）；私钥不入返回值。
    #[wasm_bindgen]
    pub fn wallet_session_key_create(req: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&req)?;
            if parsed.get("delegatedPublicKey").map_or(false, |v| !v.is_null()) {
                return Err(WalletError::InvalidArgument("delegatedPublicKey is generated here"));
            }
            // 与 session_check::parse_message 相同的解析面：delegated 公钥
            // 与（缺省时的）bindingId 以占位符注入，稍后回填真实值。
            let mut draft = parsed.clone();
            if draft.get("delegatedPublicKey").is_none() {
                draft["delegatedPublicKey"] = json!("00".repeat(33));
            }
            if draft.get("bindingId").is_none() {
                draft["bindingId"] = json!("00".repeat(32));
            }
            let mut constraints = wallet_core::account_binding::constraints_from_message(
                &super::session_check::parse_message(&draft)?,
            );
            if parsed.get("bindingId").is_none() {
                use rand::RngCore;
                let mut id = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut id);
                // 规范 felt（< 2^251）：清掉最高字节的高 6 位，保证 SNIP-12
                // 摘要构造（account_binding::felt_from_32）对任意生成值恒可行
                // （与 sn_keccak 同一掩码方向；binding_id 既是 registry 主键，
                // 也作为 felt252 参与 AuthorizeZChainKey 摘要）。
                id[0] &= 0b0000_0011;
                constraints.binding_id = id;
            }
            // 生成：随机 secret → wallet-core 派生公钥 → 回填约束 → SessionKey
            // （secret 两份拷贝都在 zeroizing 容器内；本地中间字节用后即清）。
            use rand::RngCore;
            let mut sk = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut sk);
            let probe = OwnerKeyPair::from_secret_bytes(&sk)?;
            constraints.delegated_public = probe.public_bytes();
            let secret = secp256k1::SecretKey::from_slice(&sk)
                .map_err(|_| WalletError::BadKeyMaterial("session key"))?;
            sk.fill(0);
            let key = wallet_core::key_manager::SessionKey::from_secret(constraints, secret);
            let summary = session_key_json(&key);
            let mut guard = lock_session();
            let s = guard.as_mut().ok_or(WalletError::InvalidArgument("locked"))?;
            // 同 bindingId 幂等 upsert（重授权替换旧条目）。
            let id = key.constraints.binding_id;
            s.session_keys.retain(|k| k.constraints.binding_id != id);
            s.session_keys.push(key);
            Ok(json!({ "binding": summary }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// 本会话内生成的 delegated key 列表（仅公钥级字段；锁定/切换账户即清空，
    /// 如实反映"私钥不持久化"边界）。
    #[wasm_bindgen]
    pub fn wallet_session_key_list() -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let guard = lock_session();
            let s = guard.as_ref().ok_or(WalletError::InvalidArgument("locked"))?;
            let keys: Vec<Value> = s.session_keys.iter().map(session_key_json).collect();
            Ok(json!({ "keys": keys }).to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// binding 状态查询（撤销粘滞/时间窗/日限；无会话依赖）。
    #[wasm_bindgen]
    pub fn wallet_binding_status(binding: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&binding)?;
            let now = now_u64(&now)?;
            Ok(super::session_check::status(&parsed, now)?.to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// 限额/约束 enforcement（Extension 0.4 签名路径第二层；无会话依赖）。
    /// 输出 `{admitted, rejected_reason, status}`（拒绝是 verdict，非 error）。
    #[wasm_bindgen]
    pub fn wallet_session_admit(binding: String, req: String, now: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let binding_v = parse_json(&binding)?;
            let req_v = parse_json(&req)?;
            let now = now_u64(&now)?;
            Ok(super::session_check::admit(&binding_v, &req_v, now)?.to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// SNIP-12 `AuthorizeZChainKey` 摘要（revision 1；授权确认页展示面）。
    #[wasm_bindgen]
    pub fn wallet_snip12_authorize_digest(msg: String) -> String {
        set_panic_hook();
        let run = || -> WalletResult<String> {
            let parsed = parse_json(&msg)?;
            Ok(super::session_check::authorize_digest(&parsed)?.to_string())
        };
        match run() {
            Ok(s) => s,
            Err(e) => err_json(&e),
        }
    }

    /// SessionKey → 公钥级 JSON 摘要（私钥永不输出）。
    fn session_key_json(key: &wallet_core::key_manager::SessionKey) -> Value {
        json!({
            "binding_id": hex::encode(key.constraints.binding_id),
            "delegated_public_key": hex::encode(key.public_bytes()),
            "chain_id": key.constraints.chain_id,
            "account_address": hex::encode(key.constraints.account_address),
            "allowed_scopes": key.constraints.allowed_scopes.iter().map(|s| s.name()).collect::<Vec<_>>(),
            "per_tx_limit": key.constraints.per_tx_limit.map(|l| l.to_string()),
            "per_day_limit": key.constraints.daily_limit.map(|l| l.to_string()),
            "table_allowlist": key.constraints.table_allowlist.clone(),
            "nonce": key.constraints.nonce.to_string(),
            "valid_after": key.constraints.valid_after.to_string(),
            "valid_until": key.constraints.valid_until.to_string(),
        })
    }
}
