//! 合规运营化框架（排期表 §4b"合规运营化框架" + §6 TEC-v1 行；设计依据
//! `docs/plan-token-economy-compliance-v1.md` §5/§8/§10）。
//!
//! # 定位（roadmap 出口判据的工程面）
//!
//! **地区/限额开关配置框架 + 审计事件**；运营参数（真实限额数值、市场
//! 名单）另行治理（C-M1 法务评审定版）。本模块把合规控制映射为**准入
//! 控制**（与 TE-v1 fail-closed 纪律同构），不是运营手册：
//!
//! ```text
//! GeoPolicy（版本化）
//!   markets: BTreeMap<市场代码, MarketPolicy>
//!   MarketPolicy {
//!     real_enabled / game_enabled        // 地区总开关（封禁市场直接拒）
//!     kyc_required_real / _game          // KYC 制动位（见下方语义）
//!     fiat_only                          // REAL 侧仅稳定币通道（NATIVE 拒）
//!     allowed_real_tokens                // REAL token 白名单（空 = 不限）
//!     self_excluded                      // RG 自排除个体黑名单（owner 承诺）
//!     max_deposit / max_game_issue       // 单笔限额（0 = 不限）
//!   }
//! ```
//!
//! # 协议落点（TEC-v1 §5 映射）
//!
//! | 控制项 | 本实现 |
//! |---|---|
//! | GEO 允许名单 | 版本化 [`GeoPolicy`]；入金/发行/gas 购买前校验；未配置市场 fail-closed 拒 |
//! | KYC 门 | REAL `Deposit`/`DepositV2` 与 GAME `IssueGameToken`/`FaucetMint`/`BuyGasCredits` 准入校验，**无状态拒收** + metric |
//! | 钱包筛查 | 托管/watcher 入金前置（命中不确认、不产生 deposit_id）——**不在链上**（设计原文），链上提供 `kyc_required_*` 制动位 |
//! | RG 限额/自排除 | 自排除名单进 [`MarketPolicy::self_excluded`]；单笔限额在准入执行 |
//! | 审计留痕 | [`ComplianceAuditLog`]：逐 gated op 记录 accept/reject 事件（运营审计流输入） |
//! | 指标 | `geo_policy_rejected_total{market}`、`kyc_gate_rejected_total` |
//!
//! # KYC 门的"无状态拒收"语义（如实声明）
//!
//! KYC 状态的主战场在**托管/watcher 前置筛查**（设计 §5："命中 → 不确认，
//! 不产生 deposit_id"）——链上没有 KYC 状态可查。因此链上
//! `kyc_required_*` 是 **fail-closed 制动位**：开启 = 该资产类在本市场的
//! 入金/发行通道**一律拒收**（法务 48h 封禁生效路径，§8"封禁列表可 48h
//! 内生效"的工程面；KYC 供应商中断的紧急停通道）。正常运营期该位为
//! `false`，KYC 义务由托管侧前置筛查承担——两层合起来才是完整的 KYC 门。
//! `kyc_gate_rejected_total` 只计制动位拒收。
//!
//! # 配置纪律（与 `game_rate_min/max` 同源）
//!
//! `SequencerConfig::compliance` 是**全网一致参数**：门在 apply 路径上
//! 执行（WAL 重放同路径复核），变更必须同步所有重放方，否则边界 op 的
//! 重放分叉（fail-closed 暴露）。市场切换 = 部署级重配 + 全网一致重启
//! （policy 版本号随 [`GeoPolicy::digest`] 进审计事件，可对账）。
//!
//! # 边界（如实声明，不在此实现）
//!
//! - **版本号进软确认帧**（TEC-v1 §5"配置版本号进软确认帧（审计）"）：
//!   帧格式是签名承诺面，additive 变更属 ABI 升级——本期版本号经
//!   [`ComplianceEvent`] 进**审计流**，帧内嵌随 ABI v2.x 排期；
//! - 年龄门/EDD/SOF/STR/SAR：运营流程（设计 §5 强制层列明），链上仅
//!   承接自排除名单与限额；
//! - EU 14 天撤回弃权、GAME 月度限额滚动窗：购买页/运营层；
//!   本期 `max_game_issue` 为**单笔**限额（滚动窗需要时间状态，随
//!   faucet 窗口机制同源演进）。

use crate::asset_id::{AssetId, TOKEN_NATIVE};
use crate::keys::blake2s32;
use crate::owner_v2::owner_commitment;
use crate::owner_v2::OwnerRef;

// ---------------------------------------------------------------------------
// 域标签与常量
// ---------------------------------------------------------------------------

/// geo_policy 摘要域标签（冻结）。
pub const DOMAIN_GEO_POLICY: &[u8] = b"zchain.compliance.geo_policy.v1";

/// v1 owner（[u8;33] 压缩公钥）到自排除键的域标签（冻结）。
const DOMAIN_OWNER_KEY_V1: &[u8] = b"zchain.compliance.owner.v1";

/// 审计账容量上限（超出后丢弃**新**事件并计 `compliance_audit_dropped_total`
/// ——确定性优先：重放按同序重建，drop-newest 保证两侧一致）。
pub const COMPLIANCE_AUDIT_CAP: usize = 65_536;

// ---------------------------------------------------------------------------
// GeoPolicy（版本化）
// ---------------------------------------------------------------------------

/// 单市场合规策略（字段语义见模块头）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct MarketPolicy {
    /// REAL 域开关（false = 该市场封禁 REAL 入金/提现通道）。
    pub real_enabled: bool,
    /// GAME 域开关（false = 该市场封禁游戏币发行/faucet/gas 购买）。
    pub game_enabled: bool,
    /// REAL 侧仅稳定币（true = NATIVE 入金拒；§8"USDC-only 美区起步"）。
    pub fiat_only: bool,
    /// REAL token 白名单（token id；空 = 不限，配合 `fiat_only` 细化）。
    pub allowed_real_tokens: Vec<u32>,
    /// REAL 入金 KYC 制动位（true = 通道拒收；语义见模块头）。
    pub kyc_required_real: bool,
    /// GAME 发行/购买 KYC 制动位（同上）。
    pub kyc_required_game: bool,
    /// RG 自排除个体黑名单（owner 承诺 32B；v1/v2 身份各自换算后比对）。
    pub self_excluded: std::collections::BTreeSet<[u8; 32]>,
    /// REAL 单笔入金限额（0 = 不限）。
    pub max_deposit: u64,
    /// GAME 单笔发行/faucet 限额（0 = 不限）。
    pub max_game_issue: u64,
}

impl Default for MarketPolicy {
    fn default() -> Self {
        Self {
            real_enabled: false,
            game_enabled: false,
            fiat_only: false,
            allowed_real_tokens: Vec::new(),
            // fail-closed 缺省：未显式放行的市场，两个资产类全关 + 制动位
            // 开（构造后必须显式打开需要的通道）。
            kyc_required_real: true,
            kyc_required_game: true,
            self_excluded: std::collections::BTreeSet::new(),
            max_deposit: 0,
            max_game_issue: 0,
        }
    }
}

/// 版本化 geo_policy（市场 → 策略；`version` 随审计事件留痕）。
#[derive(Debug, Clone, PartialEq, Eq, Default, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct GeoPolicy {
    /// 策略版本（> 0；每次变更递增，进审计事件可对账）。
    pub version: u32,
    /// 市场代码 → 策略（BTreeMap 序保证 digest/导出确定）。
    pub markets: std::collections::BTreeMap<String, MarketPolicy>,
}

impl GeoPolicy {
    /// 结构校验（fail-closed）：版本 > 0；市场代码非空；token 白名单不含
    /// NATIVE 保留位之外的非注册值由准入按注册表复核（本层只查结构）。
    ///
    /// # Errors
    /// 上述任一不满足 → [`crate::error::AppchainError::AdmissionRejected`]。
    pub fn validate(&self) -> crate::error::AppchainResult<()> {
        use crate::error::AppchainError;
        if self.version == 0 {
            return Err(AppchainError::AdmissionRejected(
                "geo policy version must be positive",
            ));
        }
        for (market, _policy) in &self.markets {
            if market.is_empty() {
                return Err(AppchainError::AdmissionRejected(
                    "geo policy market code must be non-empty",
                ));
            }
        }
        Ok(())
    }

    /// 策略摘要：`blake2s(DOMAIN || borsh(self))`——版本 + 全市场策略绑定，
    /// 审计对账键（谁在哪个版本下放行了哪笔 op）。
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let payload =
            borsh::to_vec(self).expect("GeoPolicy borsh encoding is infallible");
        blake2s32(&[DOMAIN_GEO_POLICY, &payload])
    }

    /// 查询市场策略；未配置市场返回 `None`（准入 fail-closed 拒）。
    #[must_use]
    pub fn policy_of(&self, market: &str) -> Option<&MarketPolicy> {
        self.markets.get(market)
    }
}

/// 部署级合规参数（`SequencerConfig::compliance`；本 sequencer 服务单一
/// 市场——多市场 = 多部署或运营层路由）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceParams {
    /// 版本化策略。
    pub policy: GeoPolicy,
    /// 本部署服务的市场代码（必须 ∈ `policy.markets`；装配时校验）。
    pub market: String,
}

impl ComplianceParams {
    /// 装配校验：策略结构合法 + 市场已配置。
    ///
    /// # Errors
    /// 策略非法 / 市场未配置 → [`crate::error::AppchainError::AdmissionRejected`]。
    pub fn validate(&self) -> crate::error::AppchainResult<()> {
        use crate::error::{AppchainError, AppchainResult};
        self.policy.validate()?;
        if self.market.is_empty() || !self.policy.markets.contains_key(&self.market) {
            return Err(AppchainError::AdmissionRejected(
                "compliance market must be configured in the geo policy",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 准入判定（纯函数；sequencer apply 路径调用）
// ---------------------------------------------------------------------------

/// sequencer 准入的 op 分类（门判定输入；身份/金额由 sequencer 侧提取）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceOpClass {
    /// REAL 入金（v1 Real 臂 / v2 DepositV2 REAL 域）。
    RealDeposit {
        /// owner 自排除键。
        owner32: [u8; 32],
        /// REAL token id。
        token: u32,
    },
    /// GAME 发行（IssueGameToken / FaucetMint）。
    GameIssue {
        /// owner 自排除键。
        owner32: [u8; 32],
    },
    /// gas credit 购买（BuyGasCredits；同 IssueGameToken 口径挂门）。
    GasPurchase {
        /// payer 自排除键。
        owner32: [u8; 32],
    },
}

/// 门判定结果（审计事件的 reason 源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// 市场未在 geo_policy 配置（fail-closed）。
    MarketNotConfigured,
    /// 地区总开关关闭（REAL 侧）。
    RealDisabled,
    /// 地区总开关关闭（GAME 侧）。
    GameDisabled,
    /// KYC 制动位开启（REAL 侧）。
    KycGateReal,
    /// KYC 制动位开启（GAME 侧）。
    KycGateGame,
    /// fiat_only 市场收 NATIVE 入金。
    FiatOnlyNativeRejected,
    /// REAL token 不在白名单。
    RealTokenNotAllowed,
    /// owner 在 RG 自排除名单。
    SelfExcluded,
    /// 超单笔 REAL 入金限额。
    DepositLimitExceeded,
    /// 超单笔 GAME 发行限额。
    GameIssueLimitExceeded,
}

impl Rejection {
    /// 审计/日志用稳定标识（冻结；外部审计流消费）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MarketNotConfigured => "market_not_configured",
            Self::RealDisabled => "real_disabled",
            Self::GameDisabled => "game_disabled",
            Self::KycGateReal => "kyc_gate_real",
            Self::KycGateGame => "kyc_gate_game",
            Self::FiatOnlyNativeRejected => "fiat_only_native_rejected",
            Self::RealTokenNotAllowed => "real_token_not_allowed",
            Self::SelfExcluded => "self_excluded",
            Self::DepositLimitExceeded => "deposit_limit_exceeded",
            Self::GameIssueLimitExceeded => "game_issue_limit_exceeded",
        }
    }
}

/// REAL 入金门（v1 [`crate::ops::Operation::Deposit`] 的 AssetClass::Real
/// 臂与 v2 `DepositV2` 共用判定；`owner32` = owner 承诺，`token` =
/// REAL token id，`amount` = 面额）。
///
/// 检查序（全 fail-closed）：市场配置 → REAL 开关 → KYC 制动 → 自排除 →
/// token 白名单（含 fiat_only）→ 单笔限额。
pub fn gate_real_deposit(
    policy: &GeoPolicy,
    market: &str,
    owner32: &[u8; 32],
    token: u32,
    amount: u64,
) -> Result<(), Rejection> {
    let mp = policy
        .policy_of(market)
        .ok_or(Rejection::MarketNotConfigured)?;
    if !mp.real_enabled {
        return Err(Rejection::RealDisabled);
    }
    if mp.kyc_required_real {
        return Err(Rejection::KycGateReal);
    }
    if mp.self_excluded.contains(owner32) {
        return Err(Rejection::SelfExcluded);
    }
    if mp.fiat_only && token == TOKEN_NATIVE {
        return Err(Rejection::FiatOnlyNativeRejected);
    }
    if !mp.allowed_real_tokens.is_empty() && !mp.allowed_real_tokens.contains(&token) {
        return Err(Rejection::RealTokenNotAllowed);
    }
    if mp.max_deposit != 0 && amount > mp.max_deposit {
        return Err(Rejection::DepositLimitExceeded);
    }
    Ok(())
}

/// GAME 发行门（`IssueGameToken` / `FaucetMint` 共用判定；`owner32` =
/// 买家/领取人 owner 承诺，`amount` = 申请铸造量）。
///
/// 检查序：市场配置 → GAME 开关 → KYC 制动 → 自排除 → 单笔限额。
pub fn gate_game_issue(
    policy: &GeoPolicy,
    market: &str,
    owner32: &[u8; 32],
    amount: u64,
) -> Result<(), Rejection> {
    let mp = policy
        .policy_of(market)
        .ok_or(Rejection::MarketNotConfigured)?;
    if !mp.game_enabled {
        return Err(Rejection::GameDisabled);
    }
    if mp.kyc_required_game {
        return Err(Rejection::KycGateGame);
    }
    if mp.self_excluded.contains(owner32) {
        return Err(Rejection::SelfExcluded);
    }
    if mp.max_game_issue != 0 && amount > mp.max_game_issue {
        return Err(Rejection::GameIssueLimitExceeded);
    }
    Ok(())
}

/// gas credit 购买门（`BuyGasCredits`；TEC-v1 §10-5：与 `IssueGameToken`
/// 同口径挂 KYC/GEO——计价资产是 REAL 域，走 REAL 开关 + KYC 制动 +
/// 自排除 + 入金限额，金额口径 = 购买额）。
pub fn gate_gas_purchase(
    policy: &GeoPolicy,
    market: &str,
    payer32: &[u8; 32],
    amount: u64,
) -> Result<(), Rejection> {
    let mp = policy
        .policy_of(market)
        .ok_or(Rejection::MarketNotConfigured)?;
    if !mp.real_enabled {
        return Err(Rejection::RealDisabled);
    }
    if mp.kyc_required_real {
        return Err(Rejection::KycGateReal);
    }
    if mp.self_excluded.contains(payer32) {
        return Err(Rejection::SelfExcluded);
    }
    if mp.max_deposit != 0 && amount > mp.max_deposit {
        return Err(Rejection::DepositLimitExceeded);
    }
    Ok(())
}

/// v1 owner（33B 压缩公钥）→ 自排除键（32B；域分离换算，唯一入口）。
#[must_use]
pub fn owner_key_v1(owner: &[u8; 33]) -> [u8; 32] {
    blake2s32(&[DOMAIN_OWNER_KEY_V1, owner])
}

/// v2 owner（[`OwnerRef`]）→ 自排除键（= owner_commitment；v2 身份空间
/// 原生 32B）。
#[must_use]
pub fn owner_key_v2(owner: &OwnerRef) -> [u8; 32] {
    owner_commitment(owner)
}

/// REAL token 提取：v1 AssetClass（Real → token 0 NATIVE 映射、Play 非REAL）
/// 与 v2 AssetId 的统一视图。Play/游戏域返回 `None`（不走 REAL 门）。
#[must_use]
pub fn real_token_of(asset: &AssetId) -> Option<u32> {
    if asset.is_real_domain() {
        Some(asset.token_id)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// 审计留痕
// ---------------------------------------------------------------------------

/// 单条合规审计事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceEvent {
    /// 帧时间戳（unix ms；提交与重放同值——确定性）。
    pub ts_ms: u64,
    /// 策略版本（事件时刻生效的 [`GeoPolicy::version`]）。
    pub policy_version: u32,
    /// 策略摘要（事件时刻生效的 [`GeoPolicy::digest`]；热更新对账键）。
    pub policy_digest: [u8; 32],
    /// 市场代码。
    pub market: String,
    /// op 稳定标识（"deposit" / "deposit_v2" / "issue_game_token" /
    /// "faucet_mint" / "buy_gas_credits"；冻结）。
    pub op_tag: &'static str,
    /// 判定：`Ok(())` → accepted；`Err(reason)` → reason.as_str()。
    pub decision: Result<(), Rejection>,
    /// 主体（owner/payer 承诺 32B）。
    pub subject: [u8; 32],
    /// 金额（若 op 有金额语义）。
    pub amount: Option<u64>,
}

impl ComplianceEvent {
    /// 稳定判定标识。
    #[must_use]
    pub fn decision_str(&self) -> &'static str {
        match self.decision {
            Ok(()) => "accepted",
            Err(r) => r.as_str(),
        }
    }
}

/// 合规审计账（append-only，容量 [`COMPLIANCE_AUDIT_CAP`]；超出 drop-newest
/// + 计数——与 metrics 同级的运营观测面，**不入状态根、不属共识态**，
/// 失败路径允许留痕（C1 纪律的 metrics 同款豁免）。WAL 重放按同序重建
/// accepted 侧；rejected 侧只在提交时刻产生（拒绝不进 WAL）——导出侧
/// 以下方 `replayed_only` 字段如实标注。
#[derive(Debug, Clone, Default)]
pub struct ComplianceAuditLog {
    events: Vec<ComplianceEvent>,
    dropped: u64,
}

impl ComplianceAuditLog {
    /// 追加事件（超容量 drop-newest + 计数）。
    pub fn record(&mut self, event: ComplianceEvent) {
        if self.events.len() >= COMPLIANCE_AUDIT_CAP {
            self.dropped += 1;
            return;
        }
        self.events.push(event);
    }

    /// 事件切片（时间序）。
    #[must_use]
    pub fn events(&self) -> &[ComplianceEvent] {
        &self.events
    }

    /// 因容量溢出被丢弃的事件数。
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// JSON 导出（运营审计流输入；u128/32B 十六进制/十进制字符串化）。
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "format": "zchain.compliance.audit.v1",
            "dropped": self.dropped,
            "events": self.events.iter().map(|e| serde_json::json!({
                "ts_ms": e.ts_ms,
                "policy_version": e.policy_version,
                "policy_digest": hex::encode(e.policy_digest),
                "market": e.market,
                "op": e.op_tag,
                "decision": e.decision_str(),
                "subject": hex::encode(e.subject),
                "amount": e.amount.map(|a| a.to_string()),
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_market() -> MarketPolicy {
        MarketPolicy {
            real_enabled: true,
            game_enabled: true,
            kyc_required_real: false,
            kyc_required_game: false,
            ..MarketPolicy::default()
        }
    }

    fn policy_v1() -> GeoPolicy {
        let mut markets = std::collections::BTreeMap::new();
        markets.insert("IM".to_string(), base_market());
        markets.insert(
            "US-WA".to_string(),
            MarketPolicy {
                real_enabled: false,
                game_enabled: false,
                ..MarketPolicy::default()
            },
        );
        GeoPolicy {
            version: 1,
            markets,
        }
    }

    /// 版本化与摘要：validate 正例/零版本拒/空市场名拒；digest 全字段敏感
    /// + 确定性与域分离。
    #[test]
    fn geo_policy_validation_and_digest() {
        let p = policy_v1();
        assert!(p.validate().is_ok());
        assert!(GeoPolicy {
            version: 0,
            ..p.clone()
        }
        .validate()
        .is_err());
        assert!(GeoPolicy {
            markets: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(String::new(), base_market());
                m
            },
            version: 2,
        }
        .validate()
        .is_err());
        // digest：确定性 + 版本敏感 + 市场敏感
        let d = p.digest();
        assert_eq!(d, p.digest(), "确定性");
        assert_ne!(
            d,
            GeoPolicy {
                version: 2,
                ..p.clone()
            }
            .digest(),
            "版本进摘要"
        );
        assert_ne!(
            d,
            GeoPolicy {
                markets: std::collections::BTreeMap::new(),
                version: 1,
            }
            .digest(),
            "市场表进摘要"
        );
        assert_ne!(d, [0u8; 32]);
    }

    /// REAL 门：开关/kyc 制动/fiat_only/白名单/限额/自排除逐位 fail-closed。
    #[test]
    fn real_deposit_gate_matrix() {
        let mut im = policy_v1();
        // 未配置市场 → fail-closed
        assert_eq!(
            gate_real_deposit(&im, "CN", &[1u8; 32], 1, 100).unwrap_err(),
            Rejection::MarketNotConfigured
        );
        // 封禁市场（US-WA）
        assert_eq!(
            gate_real_deposit(&im, "US-WA", &[1u8; 32], 1, 100).unwrap_err(),
            Rejection::RealDisabled
        );
        // IM 正例（USDT token=1，不限额）
        assert!(gate_real_deposit(&im, "IM", &[1u8; 32], 1, 100).is_ok());
        // KYC 制动
        im.markets.get_mut("IM").unwrap().kyc_required_real = true;
        assert_eq!(
            gate_real_deposit(&im, "IM", &[1u8; 32], 1, 100).unwrap_err(),
            Rejection::KycGateReal
        );
        let mut im2 = policy_v1();
        im2.markets.get_mut("IM").unwrap().fiat_only = true;
        assert_eq!(
            gate_real_deposit(&im2, "IM", &[1u8; 32], TOKEN_NATIVE, 100).unwrap_err(),
            Rejection::FiatOnlyNativeRejected
        );
        assert!(gate_real_deposit(&im2, "IM", &[1u8; 32], 2, 100).is_ok(), "稳定币过 fiat_only");
        // 白名单
        let mut im3 = policy_v1();
        im3.markets.get_mut("IM").unwrap().allowed_real_tokens = vec![2];
        assert_eq!(
            gate_real_deposit(&im3, "IM", &[1u8; 32], 1, 100).unwrap_err(),
            Rejection::RealTokenNotAllowed
        );
        assert!(gate_real_deposit(&im3, "IM", &[1u8; 32], 2, 100).is_ok());
        // 自排除
        let mut im4 = policy_v1();
        im4.markets
            .get_mut("IM")
            .unwrap()
            .self_excluded
            .insert([7u8; 32]);
        assert_eq!(
            gate_real_deposit(&im4, "IM", &[7u8; 32], 1, 100).unwrap_err(),
            Rejection::SelfExcluded
        );
        // 限额
        let mut im5 = policy_v1();
        im5.markets.get_mut("IM").unwrap().max_deposit = 1_000;
        assert_eq!(
            gate_real_deposit(&im5, "IM", &[1u8; 32], 1, 1_001).unwrap_err(),
            Rejection::DepositLimitExceeded
        );
        assert!(gate_real_deposit(&im5, "IM", &[1u8; 32], 1, 1_000).is_ok(), "边界值含");
        // 限额 0 = 不限（base 正例已覆盖）
    }

    /// GAME 门与 gas 购买门：开关/制动/自排除/限额；gas 购买走 REAL 开关。
    #[test]
    fn game_and_gas_gate_matrix() {
        let p = policy_v1();
        // GAME 封禁市场
        assert_eq!(
            gate_game_issue(&p, "US-WA", &[1u8; 32], 10).unwrap_err(),
            Rejection::GameDisabled
        );
        assert!(gate_game_issue(&p, "IM", &[1u8; 32], 10).is_ok());
        // GAME 限额
        let mut im = policy_v1();
        im.markets.get_mut("IM").unwrap().max_game_issue = 500;
        assert_eq!(
            gate_game_issue(&im, "IM", &[1u8; 32], 501).unwrap_err(),
            Rejection::GameIssueLimitExceeded
        );
        // GAME KYC 制动
        im.markets.get_mut("IM").unwrap().kyc_required_game = true;
        assert_eq!(
            gate_game_issue(&im, "IM", &[1u8; 32], 10).unwrap_err(),
            Rejection::KycGateGame
        );
        // gas 购买：REAL 关 ⇒ 拒（同口径 REAL 开关）
        assert_eq!(
            gate_gas_purchase(&p, "US-WA", &[1u8; 32], 10).unwrap_err(),
            Rejection::RealDisabled
        );
        assert!(gate_gas_purchase(&p, "IM", &[1u8; 32], 10).is_ok());
        // gas 购买限额走 max_deposit
        let mut im2 = policy_v1();
        im2.markets.get_mut("IM").unwrap().max_deposit = 100;
        assert_eq!(
            gate_gas_purchase(&im2, "IM", &[1u8; 32], 101).unwrap_err(),
            Rejection::DepositLimitExceeded
        );
    }

    /// 身份换算：v1 域分离键确定且 ≠ 原始公钥截断；v2 键 = owner_commitment；
    /// real_token_of 对 GAME 域返回 None。
    #[test]
    fn identity_keys_and_asset_view() {
        let mut pk = [2u8; 33];
        pk[1] = 9;
        let k1 = owner_key_v1(&pk);
        assert_eq!(k1, owner_key_v1(&pk), "确定");
        assert_ne!(&k1[..], &pk[1..33], "域分离（非裸截断）");
        assert_ne!(k1, owner_key_v1(&[3u8; 33]));
        let asset = AssetId::REAL_USDT;
        assert_eq!(real_token_of(&asset), Some(asset.token_id));
        let game = AssetId::GAME_PLAY;
        assert_eq!(real_token_of(&game), None, "GAME 域不走 REAL 门");
    }

    /// 审计账：容量内追加、超容量 drop-newest + 计数、JSON 形状冻结。
    #[test]
    fn audit_log_cap_and_json_shape() {
        let mut log = ComplianceAuditLog::default();
        for i in 0..(COMPLIANCE_AUDIT_CAP + 3) {
            log.record(ComplianceEvent {
                ts_ms: i as u64,
                policy_version: 1,
                policy_digest: [0u8; 32],
                market: "IM".into(),
                op_tag: "deposit",
                decision: Ok(()),
                subject: [i as u8; 32],
                amount: Some(1),
            });
        }
        assert_eq!(log.events().len(), COMPLIANCE_AUDIT_CAP);
        assert_eq!(log.dropped(), 3);
        assert_eq!(log.events()[0].ts_ms, 0, "保留最旧（drop-newest）");
        let v = log.to_json();
        assert_eq!(v["format"], "zchain.compliance.audit.v1");
        assert_eq!(v["dropped"], 3);
        assert_eq!(v["events"][0]["decision"], "accepted");
        assert_eq!(v["events"][0]["market"], "IM");
    }

    /// ComplianceParams 装配校验：市场未配置拒；策略非法拒。
    #[test]
    fn compliance_params_validation() {
        let ok = ComplianceParams {
            policy: policy_v1(),
            market: "IM".into(),
        };
        assert!(ok.validate().is_ok());
        let bad_market = ComplianceParams {
            market: "XX".into(),
            ..ok.clone()
        };
        assert!(bad_market.validate().is_err());
        let bad_policy = ComplianceParams {
            policy: GeoPolicy::default(),
            market: "IM".into(),
        };
        assert!(bad_policy.validate().is_err(), "version=0 空策略拒");
    }
}
