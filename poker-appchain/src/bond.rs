//! M8：bond（保证金）内部记账框架——v1 **只记录、不执行真实罚没**。
//!
//! [`BondLedger`] 是 append-only 事件账：Deposit / Withdraw 入余额，
//! [`BondEventKind::SlashRecord`] 是**记录语义**（名字里不带 Slash 的执行
//! 含义）：v1 只把"应罚没事实"记入账本供对账/runbook 处置，**不扣减
//! `balance`、不触发任何真实资产移动**——执行路径（含 L1 侧联动）是
//! v1.5+ 的工作。`amount` 为 `u128`，负额在类型层面不可表示；运行期
//! 拒绝 0 额（fail-closed）。
//!
//! 持久化：JSONL 逐行完整追加（每行含换行），纪律与 proven-log 一致——
//! 空文件合法；撕裂尾行（最后一行无换行）忽略 + 告警；中间行损坏拒绝
//! （fail-closed）。行格式（本模块自有，非冻结契约）：
//!
//! ```text
//! {"validator_pubkey":"<64hex>","kind":"Deposit","amount":"<十进制>","ts_ms":<u64>,"reason":"<json 字符串>"}
//! ```
//!
//! `amount` 以十进制字符串编码：u128 超出 JSON number 安全语义时不失真。

use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{AppchainError, AppchainResult};

/// 事件类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondEventKind {
    /// 保证金存入（计入余额）。
    Deposit,
    /// 罚没**记录**（v1 只记录不执行：不改余额，见模块文档）。
    SlashRecord,
    /// 保证金提取（计入余额扣减）。
    Withdraw,
}

impl BondEventKind {
    /// JSONL 编码标签。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "Deposit",
            Self::SlashRecord => "SlashRecord",
            Self::Withdraw => "Withdraw",
        }
    }

    /// JSONL 解码（严格标签）。
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Deposit" => Some(Self::Deposit),
            "SlashRecord" => Some(Self::SlashRecord),
            "Withdraw" => Some(Self::Withdraw),
            _ => None,
        }
    }
}

/// 一条 bond 账目事件（append-only，不可变）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondEvent {
    /// validator 公钥（32B，与 sequencer/attestor 同编解码域）。
    pub validator_pubkey: [u8; 32],
    /// 事件类别。
    pub kind: BondEventKind,
    /// 数额（u128；负额类型层面不可表示，0 在运行期拒绝）。
    pub amount: u128,
    /// 记账时间（墙钟毫秒）。
    pub ts_ms: u64,
    /// 事件原因（自由文本；runbook/审计线索）。
    pub reason: String,
}

impl BondEvent {
    /// 序列化为一行 JSONL（含换行；`amount` 十进制字符串防精度歧义）。
    fn encode_line(&self) -> String {
        let reason = serde_json::to_string(&self.reason)
            .expect("String serde_json encoding is infallible");
        format!(
            "{{\"validator_pubkey\":\"{}\",\"kind\":\"{}\",\"amount\":\"{}\",\"ts_ms\":{},\"reason\":{}}}\n",
            hex::encode(self.validator_pubkey),
            self.kind.as_str(),
            self.amount,
            self.ts_ms,
            reason
        )
    }

    /// 从一行 JSONL 解析（字段缺失/类型错 → None）。
    fn decode_line(line: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        let obj = v.as_object()?;
        let pk_hex = obj.get("validator_pubkey")?.as_str()?;
        let pubkey: [u8; 32] = hex::decode(pk_hex).ok()?.try_into().ok()?;
        let kind = BondEventKind::parse(obj.get("kind")?.as_str()?)?;
        let amount: u128 = obj.get("amount")?.as_str()?.parse().ok()?;
        let ts_ms = obj.get("ts_ms")?.as_u64()?;
        let reason = obj.get("reason")?.as_str()?.to_string();
        Some(Self {
            validator_pubkey: pubkey,
            kind,
            amount,
            ts_ms,
            reason,
        })
    }
}

/// 分类合计（`slash_recorded` 是**记录额**，未从任何余额执行——v1 语义）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BondTotals {
    /// 存入合计。
    pub deposit: u128,
    /// 罚没记录合计（只记录）。
    pub slash_recorded: u128,
    /// 提取合计。
    pub withdraw: u128,
}

/// append-only bond 账本。`writer` 为 `None` 时纯内存（测试/演练）。
#[derive(Debug)]
pub struct BondLedger {
    events: Vec<BondEvent>,
    writer: Option<(PathBuf, BufWriter<std::fs::File>)>,
}

impl BondLedger {
    /// 空内存账本（不持久化）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            writer: None,
        }
    }

    /// 打开（追加模式）：先加载既有事件，再挂追加写端。文件不存在则
    /// 从空账开始。
    ///
    /// # Errors
    /// 读取失败 / 中间行损坏 / 行字段非法 → [`AppchainError::WalCorrupted`]。
    pub fn open(path: &Path) -> AppchainResult<Self> {
        let events = if path.exists() {
            load_events(path)?
        } else {
            Vec::new()
        };
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|_| AppchainError::WalCorrupted("bond ledger open failed"))?;
        Ok(Self {
            events,
            writer: Some((path.to_path_buf(), BufWriter::new(file))),
        })
    }

    /// 记账（先落盘后入内存——写失败则内存零变更，fail-closed）。
    ///
    /// # Errors
    /// `amount == 0` → [`AppchainError::AdmissionRejected`]；
    /// JSONL 写失败 → [`AppchainError::WalCorrupted`]。
    pub fn record(&mut self, event: BondEvent) -> AppchainResult<()> {
        if event.amount == 0 {
            // u128 下负额类型层面不可表示；0 额事件无记账语义，拒绝。
            return Err(AppchainError::AdmissionRejected(
                "bond amount must be positive",
            ));
        }
        if let Some((_, w)) = self.writer.as_mut() {
            w.write_all(event.encode_line().as_bytes())
                .and_then(|()| w.flush())
                .map_err(|_| AppchainError::WalCorrupted("bond ledger write failed"))?;
        }
        self.events.push(event);
        Ok(())
    }

    /// 某 validator 的余额 = ΣDeposit − ΣWithdraw。
    ///
    /// [`BondEventKind::SlashRecord`] **不参与**余额（只记录语义，见模块
    /// 文档）；罚没执行是 v1.5+ 路径。
    #[must_use]
    pub fn balance(&self, validator_pubkey: &[u8; 32]) -> u128 {
        let mut bal = 0u128;
        for e in &self.events {
            if e.validator_pubkey != *validator_pubkey {
                continue;
            }
            match e.kind {
                BondEventKind::Deposit => bal = bal.saturating_add(e.amount),
                BondEventKind::Withdraw => bal = bal.saturating_sub(e.amount),
                BondEventKind::SlashRecord => {}
            }
        }
        bal
    }

    /// 全账本分类合计。
    #[must_use]
    pub fn total_by_kind(&self) -> BondTotals {
        let mut t = BondTotals::default();
        for e in &self.events {
            match e.kind {
                BondEventKind::Deposit => t.deposit = t.deposit.saturating_add(e.amount),
                BondEventKind::SlashRecord => {
                    t.slash_recorded = t.slash_recorded.saturating_add(e.amount);
                }
                BondEventKind::Withdraw => t.withdraw = t.withdraw.saturating_add(e.amount),
            }
        }
        t
    }

    /// 全部事件（追加序）。
    #[must_use]
    pub fn events(&self) -> &[BondEvent] {
        &self.events
    }

    /// 持久化路径（内存账本 → None）。
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.writer.as_ref().map(|(p, _)| p.as_path())
    }
}


// ===== 对账恒等（排期表 §2 bond/slash 行出口判据第三项；appchain 侧） =====
//
// 余额恒等：`balance(v) == ΣDeposit(v) − ΣWithdraw(v)`（SlashRecord 不进
// 余额，v1"只记录不执行"语义）。跨进程对账锚：poker_l1 执行侧
// `SlashLedger::reconciliation_digest()`（链式事件折叠根）经
// `BondEventKind::SlashRecord` 的 `reason` 字段以
// `slash_ledger_digest:<hex>` 约定留痕——两侧摘要相等即"执行侧扣减流 ==
// 记录侧留痕流"（runbook 约定，两仓无依赖边）。

/// 单 validator 余额对账行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondReconciliationRow {
    /// validator 公钥。
    pub validator_pubkey: [u8; 32],
    /// ΣDeposit。
    pub deposits: u128,
    /// ΣWithdraw。
    pub withdraws: u128,
    /// ΣSlashRecord（**不进余额**，记录面观察值）。
    pub slash_recorded: u128,
    /// 恒等式期望余额（deposits − withdraws，saturating）。
    pub expected_balance: u128,
    /// `balance()` 实时值（恒等于 expected——破坏即账本实现 bug）。
    pub actual_balance: u128,
    /// 恒等式核对。
    pub consistent: bool,
}

/// 余额对账报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondReconciliationReport {
    /// 逐 validator 行（pubkey 字典序）。
    pub rows: Vec<BondReconciliationRow>,
    /// 全部行一致。
    pub all_consistent: bool,
    /// 留痕的 slash ledger 摘要集合（`slash_ledger_digest:<hex>` 约定；
    /// 与 poker_l1 执行侧对账的凭据面）。
    pub slash_ledger_digests: Vec<String>,
}

impl BondLedger {
    /// 余额恒等对账（排期表 §2 出口判据"对账恒等"的 appchain 侧）。
    #[must_use]
    pub fn reconcile(&self) -> BondReconciliationReport {
        use std::collections::BTreeMap;
        let mut pks: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        let mut deposits: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut withdraws: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut slash_recorded: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut digests: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for e in &self.events {
            pks.insert(e.validator_pubkey);
            match e.kind {
                BondEventKind::Deposit => {
                    *deposits.entry(e.validator_pubkey).or_insert(0) += e.amount;
                }
                BondEventKind::Withdraw => {
                    *withdraws.entry(e.validator_pubkey).or_insert(0) += e.amount;
                }
                BondEventKind::SlashRecord => {
                    *slash_recorded.entry(e.validator_pubkey).or_insert(0) += e.amount;
                    const PREFIX: &str = "slash_ledger_digest:";
                    if let Some(d) = e.reason.strip_prefix(PREFIX) {
                        digests.insert(d.to_string());
                    }
                }
            }
        }
        let mut rows = Vec::with_capacity(pks.len());
        let mut all_consistent = true;
        for pk in pks {
            let d = deposits.get(&pk).copied().unwrap_or(0);
            let w = withdraws.get(&pk).copied().unwrap_or(0);
            let expected = d.saturating_sub(w);
            let actual = self.balance(&pk);
            let consistent = expected == actual;
            all_consistent &= consistent;
            rows.push(BondReconciliationRow {
                validator_pubkey: pk,
                deposits: d,
                withdraws: w,
                slash_recorded: slash_recorded.get(&pk).copied().unwrap_or(0),
                expected_balance: expected,
                actual_balance: actual,
                consistent,
            });
        }
        BondReconciliationReport {
            rows,
            all_consistent,
            slash_ledger_digests: digests.into_iter().collect(),
        }
    }
}

impl Default for BondLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// 读取既有事件（撕裂尾行忽略 + 告警；中间行损坏拒绝）。
fn load_events(path: &Path) -> AppchainResult<Vec<BondEvent>> {
    let bytes = std::fs::read(path)
        .map_err(|_| AppchainError::WalCorrupted("bond ledger read failed"))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| AppchainError::WalCorrupted("bond ledger not utf-8"))?;
    let ends_with_newline = text.ends_with('\n');
    let mut lines: Vec<&str> = text.split('\n').collect();
    if ends_with_newline {
        lines.pop();
    } else {
        match lines.pop() {
            Some(tail) if !tail.trim().is_empty() => {
                eprintln!(
                    "[poker-appchain::bond] warning: torn final line ignored \
                     ({} bytes, no newline)",
                    tail.len()
                );
            }
            _ => {}
        }
    }
    let mut out = Vec::with_capacity(lines.len());
    for raw in &lines {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let e = BondEvent::decode_line(line).ok_or(
            AppchainError::WalCorrupted("bond ledger line corrupt"),
        )?;
        out.push(e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("poker-appchain-bond-tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(tag)
    }

    fn event(kind: BondEventKind, amount: u128, pk: [u8; 32]) -> BondEvent {
        BondEvent {
            validator_pubkey: pk,
            kind,
            amount,
            ts_ms: 1_700_000_000_000,
            reason: match kind {
                BondEventKind::Deposit => "genesis bond".into(),
                BondEventKind::SlashRecord => "M8-ACC: equivocation evidence".into(),
                BondEventKind::Withdraw => "planned exit".into(),
            },
        }
    }

    #[test]
    fn deposit_withdraw_balance_and_totals() {
        let mut l = BondLedger::new();
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        l.record(event(BondEventKind::Deposit, 1_000, v1)).unwrap();
        l.record(event(BondEventKind::Deposit, 500, v2)).unwrap();
        l.record(event(BondEventKind::Withdraw, 200, v1)).unwrap();
        // SlashRecord：记录进账本，但不改余额（v1 只记录不执行）
        l.record(event(BondEventKind::SlashRecord, 300, v1)).unwrap();
        assert_eq!(l.balance(&v1), 800);
        assert_eq!(l.balance(&v2), 500);
        assert_eq!(l.balance(&[9; 32]), 0);
        let t = l.total_by_kind();
        assert_eq!(t.deposit, 1_500);
        assert_eq!(t.withdraw, 200);
        assert_eq!(t.slash_recorded, 300);
        // 提取不能透支余额（saturating 语义下余额不为负——u128 保证）
        l.record(event(BondEventKind::Withdraw, 5_000, v2)).unwrap();
        assert_eq!(l.balance(&v2), 0, "saturating: no negative balance possible");
    }

    /// 负额拒绝：u128 类型层面不可表示 + 0 额运行期拒绝（文档化语义）。
    #[test]
    fn zero_and_negative_amounts_rejected() {
        let mut l = BondLedger::new();
        let err = l
            .record(event(BondEventKind::Deposit, 0, [3; 32]))
            .unwrap_err();
        assert!(matches!(
            err,
            AppchainError::AdmissionRejected("bond amount must be positive")
        ));
        assert!(l.events().is_empty(), "rejected event must not be recorded");
        // 负数在 u128 事件模型下无法构造（编译期排除）；u128::MAX 大额可承载
        l.record(event(BondEventKind::Deposit, u128::MAX, [3; 32]))
            .unwrap();
        assert_eq!(l.balance(&[3; 32]), u128::MAX);
    }

    #[test]
    fn persistence_roundtrip() {
        let p = temp_path("roundtrip.jsonl");
        let _ = std::fs::remove_file(&p);
        let v = [7u8; 32];
        {
            let mut l = BondLedger::open(&p).unwrap();
            l.record(event(BondEventKind::Deposit, 1_234, v)).unwrap();
            l.record(event(BondEventKind::SlashRecord, 34, v)).unwrap();
            l.record(event(BondEventKind::Withdraw, 1_200, v)).unwrap();
        }
        let l2 = BondLedger::open(&p).unwrap();
        assert_eq!(l2.events().len(), 3);
        assert_eq!(l2.balance(&v), 34);
        let t = l2.total_by_kind();
        assert_eq!(t.deposit, 1_234);
        assert_eq!(t.slash_recorded, 34);
        assert_eq!(t.withdraw, 1_200);
        // 追加写不破坏旧行
        let mut l3 = BondLedger::open(&p).unwrap();
        l3.record(event(BondEventKind::Deposit, 1, v)).unwrap();
        drop(l3);
        let l4 = BondLedger::open(&p).unwrap();
        assert_eq!(l4.events().len(), 4);
        assert_eq!(l4.balance(&v), 35);
    }

    /// 撕裂尾行忽略；中间行损坏拒绝（与 proven-log 同纪律）。
    #[test]
    fn torn_tail_ignored_midfile_corrupt_rejected() {
        let p = temp_path("torn.jsonl");
        let _ = std::fs::remove_file(&p);
        let mut l = BondLedger::open(&p).unwrap();
        l.record(event(BondEventKind::Deposit, 10, [4; 32])).unwrap();
        let good = std::fs::read_to_string(&p).unwrap();
        drop(l);
        // 撕裂尾行
        std::fs::write(&p, format!("{}{{\"validator_pubkey\":", good)).unwrap();
        let l2 = BondLedger::open(&p).unwrap();
        assert_eq!(l2.events().len(), 1);
        // 中间行损坏（换行终结的坏行）
        std::fs::write(&p, format!("{good}not-json\n")).unwrap();
        assert!(BondLedger::open(&p).is_err());
    }

    #[test]
    fn bond_reconciliation_identity_and_digest_anchor() {
        let mut ledger = BondLedger::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        ledger.record(BondEvent {
            validator_pubkey: a,
            kind: BondEventKind::Deposit,
            amount: 1_000,
            ts_ms: 1,
            reason: "genesis bond".into(),
        })
        .unwrap();
        ledger.record(BondEvent {
            validator_pubkey: a,
            kind: BondEventKind::Withdraw,
            amount: 300,
            ts_ms: 2,
            reason: "partial unbond".into(),
        })
        .unwrap();
        // SlashRecord 不进余额（v1 只记录语义），但进记录合计与摘要留痕
        ledger.record(BondEvent {
            validator_pubkey: a,
            kind: BondEventKind::SlashRecord,
            amount: 700,
            ts_ms: 3,
            reason: "slash_ledger_digest:deadbeef".into(),
        })
        .unwrap();
        ledger.record(BondEvent {
            validator_pubkey: b,
            kind: BondEventKind::Deposit,
            amount: 500,
            ts_ms: 4,
            reason: "genesis bond".into(),
        })
        .unwrap();
        let report = ledger.reconcile();
        assert!(report.all_consistent, "余额恒等必须成立: {report:?}");
        assert_eq!(report.rows.len(), 2);
        let ra = report.rows.iter().find(|r| r.validator_pubkey == a).unwrap();
        assert_eq!((ra.deposits, ra.withdraws, ra.slash_recorded), (1_000, 300, 700));
        assert_eq!((ra.expected_balance, ra.actual_balance), (700, 700));
        assert_eq!(report.slash_ledger_digests, vec!["deadbeef".to_string()]);
        assert_eq!(ledger.balance(&a), 700, "SlashRecord 不改余额");
        assert_eq!(ledger.total_by_kind().slash_recorded, 700);
    }
}
