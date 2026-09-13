//! TE-M3：GTS 游戏币标准（Game Token Standard；排期表 §6 TE-M3 行，
//! 设计依据 `docs/plan-token-economy-v1.md` §3/§4.3/§5/§6）。
//!
//! 每个游戏币是一个**独立 token**，由发行记录（genesis）定义；注册后
//! **全部字段冻结**（重定价 = 发新 token，旧 token 自然消亡，TE-D2）：
//!
//! ```text
//! GameTokenSpec { token_id, issuer, mode, max_supply, genesis_digest }
//! IssuanceMode := Paid { anchor, rate }   // 付费铸造（价带强制，§3.2）
//!              |  Free  { faucet }        // 免费限量铸造（TE-M6 完整机制）
//! ```
//!
//! ## 单向与不可桥（INV-TE-3，结构性质）
//!
//! 入口仅 `IssueGameToken`（外部支付 anchor → watcher 幂等确认 → 铸 GAME
//! note，复用 Deposit 的 deposit_id 幂等模式）；出口仅 `BurnGameToken`
//! 销毁。封闭操作集里不存在"GAME → anchor"的变体，外部资产通道
//! （REAL Deposit/Withdraw）对 GAME 域全部拒绝（TE-M2 已在 DepositV2/
//! WithdrawRequestV2 拒 GAME；本任务的 Issue/Burn 对 REAL 域对称拒绝）
//! ——**"不能和原生代币或稳定币兑换/不能跨链"是结构性质**，不是运营策略。
//!
//! ## 价带（INV-TE-4）
//!
//! `rate ∉ [R_min, R_max]` → 注册拒绝（[`validate_rate`]，validation 层
//! 强制点）。R_max 默认按成本覆盖推导 `1/(k·c), k≥5` 取 `1e7`；R_min 默认
//! `1e5`（u64 余量核算见设计文档 §3.2）。双层强制的第二层：rate 进
//! [`GameTokenSpec::genesis_digest`]（全部字段绑定）——带外发行的 witness
//! 不可证明。价带参数是治理参数（版本化），经
//! `SequencerConfig::game_rate_min/max` 注入；**变更必须全网一致**，否则
//! WAL 重放对边界注册分叉（fail-closed 暴露，与 network_id 同纪律）。
//!
//! ## 供给恒等（INV-TE-7）
//!
//! ```text
//! outstanding(token) = Σminted − Σburned == Σ 存续 GAME note 面额
//! ```
//!
//! 聚合账在 sequencer [`crate::sequencer::LedgerState`]（TE-M3 追加字段，
//! 不入状态根——WAL 重放经 apply 路径重建，与 `deposit_records_v2` 同
//! 纪律）；日终对账导出见 [`GameReconciliation`] / [`reconciliation_json`]。
//!
//! ## 哈希原语（诚实声明）
//!
//! genesis 摘要用 crate 规范 32B 哈希 [`crate::keys::blake2s32`]
//! （blake2 家族 blake2s-256；零新依赖）。域标签
//! `zchain.game_token.genesis.v1` 冻结；设计文档 §3.1 的 poseidon 口径
//! 由 AIR 层落地时对齐（本层承诺与 AIR 公共输入经同一 32B 摘要衔接）。
//!
//! ## 边界（如实声明，不在此实现）
//!
//! - **Free 模式的完整机制属 TE-M6**：时间窗限流（每玩家单位时间上限）、
//!   `GasPolicy`/gas credit、`FaucetMint` 独立 op。本任务 Free 模式只有
//!   注册 + 限量铸造骨架（单次上限 + 玩家终身上限，见 [`FaucetPolicy`]），
//!   gas 服务费不实现；
//! - GAME 桌（`FixedRakeBurn`、GAME 域开桌入口）属 TE-M4；
//! - 链上支付通道（anchor 收款地址、KYC 界面）属部署/运营面（B-TE-3）；
//! - v1 发行方 = 平台自营（TE-D3）；`issuer` 字段为第三方白名单预留。
//!
//! ## TE-M6：Free 模式 gas 服务费（排期表 §6；设计 §3.8）
//!
//! Free 桌按对局收**固定费额** gas 服务费（[`GasPolicy`]：REAL 域
//! NATIVE/USDT/USDC 计价，刻意不与底池挂钩——底池比例费形似对 wager
//! 抽水，损害"服务费"定性）。gas credit 是**预付服务额度**
//! （[`GasCreditLedger`] 计量账）：
//!
//! - **不铸 note、不进 `CustodyLedger` 对账恒等式**——服务费收入是已售
//!   服务额度（无赎回、无储备义务），与 REAL 托管恒等式
//!   `delta[code] = reserved − issued == 0` **物理隔离**（收入不进
//!   reserved/issued 的任何一边）。这保护"服务费"合规定性：它不是玩家
//!   余额、不是负债，资金不需要 1:1 储备；
//! - INV-TE-8：逐玩家逐币种 `credit = Σpurchased − Σconsumed ≥ 0`——
//!   消耗前置校验，不足整笔拒绝（扣减从不穿透零点）；
//! - INV-TE-9：Free 模式 token 的结算出现在未绑定 GasPolicy 的桌 →
//!   受理拒绝（fail-closed 排序不变量；强制点在结算准入，见 sequencer
//!   `apply_settle_v2` 的 TE-M6 门——v2 seat 生命周期 BuyInV2 未引入，
//!   Free token 进入桌生命周期的首个受理点即 SettleV2）；
//! - 成本覆盖（Free 模式的"价带等价物"，设计 §3.8.4）：绑定时刻校验
//!   `fee_per_hand ≥ min_coverage_k · c_hand`（`min_coverage_k ≥ 3`）。
//!   `c_hand`（每手摊薄运营成本 = (结算 gas + 证明成本 + 基础设施) /
//!   预期手数）由 `SequencerConfig::gas_c_hand_estimate` 注入——**运营
//!   参数**，真实计量属部署面（B-TE-2 同源），非协议常量；
//! - TE-D7：Paid 模式 token 的桌绑定 GasPolicy 一律拒（双重收费 v1
//!   禁止）；遗留 PLAY(0) 永不绑 gas（永久免费层，合规防御）。
//!
//! 判别值：`FaucetMint` = 14、`BuyGasCredits` = 15、`BindGasPolicy` = 16
//! （TE-M3 预留位落地，冻结；见 `docs/ABI_TE_M6.md`）。

use crate::asset_id::{AssetId, GAME_TOKEN_PLAY};
use crate::error::{AppchainError, AppchainResult};
use crate::keys::blake2s32;

// ---------------------------------------------------------------------------
// 域标签与常量（冻结）
// ---------------------------------------------------------------------------

/// 域标签：GTS genesis 摘要（`zchain.game_token.genesis.v1`，冻结；独立
/// 命名空间，不与 `zchain.note.v2.*` / `zchain.asset.v2.id` 拼装）。
pub const DOMAIN_GAME_TOKEN_GENESIS: &[u8] = b"zchain.game_token.genesis.v1";

/// 换算分母：anchor 资产以 1e18 wei 计价参与换算（设计 §3.1 冻结）。
pub const RATE_DENOM: u128 = 1_000_000_000_000_000_000;

/// 默认价带下界 `R_min = 1e5`（设计 §3.2 参考值；治理可版本化覆盖）。
pub const RATE_MIN_DEFAULT: u64 = 100_000;
/// 默认价带上界 `R_max = 1e7`（成本覆盖 `1/(k·c), k≥5` 推导的示例默认；
/// 真实成本数据复核后由治理定版，B-TE-2）。
pub const RATE_MAX_DEFAULT: u64 = 10_000_000;

/// 供给对账导出格式标签（冻结）。
pub const RECONCILIATION_FORMAT: &str = "zchain.game_token.reconciliation.v1";

// ---------------------------------------------------------------------------
// 发行模式
// ---------------------------------------------------------------------------

/// 发行模式（设计 §3.1/§3.8；borsh 判别值 = 声明序：Paid = 0、Free = 1，
/// **冻结**；TE-M6 的新模式只能尾部追加）。
///
/// Paid 模式 `rate` 语义（冻结）：`R = 每 1e18 wei anchor 可铸游戏币数`
/// （`R = 1_000_000` 即 1U = 100 万游戏币）；铸造公式
/// `mint = floor(pay_amount_e18 * R / 1e18)`，向下取整，尘埃留在未铸侧
/// （无分数币，fail-closed：整笔支付不足 1 币则该次发行拒绝）。
///
/// Free 模式无 anchor 无 rate（faucet 参数进 genesis 同样冻结）；其成本
/// 覆盖点从价带换成 gas 服务费定价（`fee_per_hand ≥ k·c_hand`，TE-M6）。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub enum IssuanceMode {
    /// 付费铸造：锚定资产 + 比率（价带校验见 [`validate_rate`]）。
    Paid {
        /// 锚定资产（REAL 域已注册 token；TE-D4：仅稳定币起步——本层
        /// 只强制 REAL 域封闭枚举，anchor 币种白名单是治理面）。
        anchor: AssetId,
        /// 每 1e18 wei anchor 可铸游戏币数（冻结；进 genesis 摘要）。
        rate: u64,
    },
    /// 免费铸造：faucet 限量（TE-M3 只有骨架，完整机制 TE-M6）。
    Free {
        /// faucet 限量参数（进 genesis 摘要，冻结）。
        faucet: FaucetPolicy,
    },
}

/// faucet 限量参数（Free 模式；TE-M3 骨架口径，TE-M6 沿用）。
///
/// - `single_max`：单次发行上限（骨架强制点）；
/// - `player_lifetime_max`：每玩家**终身**累计上限（骨架强制点；
///   按 owner_commitment 记账，重放可重建）。
///
/// 边界（TE-M6 落地后仍如实声明）：设计 §3.8.3 的"每玩家**单位时间**
/// 上限"需要时间窗状态，**v1 仍未实现**（TE-M6 只补 `FaucetMint` 独立
/// op + `claim_id` 幂等；`IssueGameToken` 的 TE-M3 Free 分支保留兼容）
/// ——限量口径弱于最终口径，faucet 生产启用前的时间窗限流属后续任务。
/// faucet 参数冻结后**不得人为稀缺化**（设计 §3.8.1 合规要件：收紧到
/// "付费才能继续玩"即退化为 Paid 监管画像）。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct FaucetPolicy {
    /// 单次发行上限（> 0）。
    pub single_max: u64,
    /// 每玩家终身累计上限（≥ single_max）。
    pub player_lifetime_max: u64,
}

// ---------------------------------------------------------------------------
// GameTokenSpec（genesis 冻结）
// ---------------------------------------------------------------------------

/// 游戏币 genesis 规格（注册后全部字段**冻结**，TE-D2）。
///
/// `genesis_digest` = `blake2s32(DOMAIN_GAME_TOKEN_GENESIS, borsh(
/// (token_id, issuer, mode, max_supply)))`——**全部字段绑定**：任何字段
/// 篡改必得不同摘要（注册 op 的声明摘要必须与链侧重算全等，否则拒绝）。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct GameTokenSpec {
    /// 注册表分配的 token id（GAME 域 `AssetId.token_id`；0 = 遗留 PLAY
    /// 保留位，GTS 从 1 起）。
    pub token_id: u32,
    /// 发行方公钥（v1 = 平台运营方；33B 压缩公钥，非零）。
    pub issuer: [u8; 33],
    /// 发行模式（Paid / Free）。
    pub mode: IssuanceMode,
    /// 供给上限（0 = 不限；`Σminted ≤ max_supply` 由 sequencer 强制）。
    pub max_supply: u64,
    /// genesis 摘要（全部字段绑定；注册时链侧重算核对）。
    pub genesis_digest: [u8; 32],
}

impl GameTokenSpec {
    /// genesis 摘要计算（全部字段绑定；[`GameTokenSpec::new`] 与 sequencer
    /// 注册准入共用同一函数——不存在第二种换算）。
    #[must_use]
    pub fn genesis_digest_of(
        token_id: u32,
        issuer: &[u8; 33],
        mode: &IssuanceMode,
        max_supply: u64,
    ) -> [u8; 32] {
        let payload = borsh::to_vec(&(token_id, *issuer, mode, max_supply))
            .expect("genesis payload borsh encoding is infallible");
        blake2s32(&[DOMAIN_GAME_TOKEN_GENESIS, &payload])
    }

    /// 构造并做结构校验（fail-closed）：
    /// 1. `token_id != 0`（0 = 遗留 PLAY 保留位，不可注册/重定义）；
    /// 2. `issuer` 非零；
    /// 3. Paid：anchor 必须是 REAL 域**已注册** token（GAME 域 anchor/
    ///    伪造 REAL token 拒——对称纪律的注册面）；
    /// 4. Paid：`rate > 0`；
    /// 5. Free：faucet 参数合法（`single_max > 0` 且
    ///    `single_max ≤ player_lifetime_max`）。
    ///
    /// 价带校验**不在此处**（[`validate_rate`] 独立函数）：价带是治理
    /// 参数（可版本化），规格字段是协议冻结面；注册准入先 `new` 后
    /// `validate_rate`。
    ///
    /// # Errors
    /// 上述任一不满足 → [`AppchainError::GameRegistryRejected`] /
    /// [`AppchainError::OutOfRange`]。
    pub fn new(
        token_id: u32,
        issuer: &[u8; 33],
        mode: IssuanceMode,
        max_supply: u64,
    ) -> AppchainResult<Self> {
        if token_id == GAME_TOKEN_PLAY {
            return Err(AppchainError::GameRegistryRejected(
                "token_id 0 is the reserved legacy PLAY slot",
            ));
        }
        if *issuer == [0u8; 33] {
            return Err(AppchainError::GameRegistryRejected("zero issuer"));
        }
        match &mode {
            IssuanceMode::Paid { anchor, rate } => {
                // 对称纪律（注册面）：anchor 必须是 REAL 域已注册 token
                // ——GAME 域资产/伪造 REAL token 作 anchor 一律拒
                //（"不认识 ≠ 接受"）。REAL 域封闭枚举是 v1 口径。
                if !anchor.is_real_domain() || !anchor.domain.is_registered_token(anchor.token_id)
                {
                    return Err(AppchainError::GameRegistryRejected(
                        "paid anchor must be a REAL domain registered token",
                    ));
                }
                if *rate == 0 {
                    return Err(AppchainError::OutOfRange("game token rate"));
                }
            }
            IssuanceMode::Free { faucet } => {
                if faucet.single_max == 0 {
                    return Err(AppchainError::OutOfRange("faucet single_max"));
                }
                if faucet.single_max > faucet.player_lifetime_max {
                    return Err(AppchainError::OutOfRange(
                        "faucet single_max exceeds player_lifetime_max",
                    ));
                }
            }
        }
        let genesis_digest = Self::genesis_digest_of(token_id, issuer, &mode, max_supply);
        Ok(Self {
            token_id,
            issuer: *issuer,
            mode,
            max_supply,
            genesis_digest,
        })
    }

    /// 是否 Paid 模式。
    #[must_use]
    pub fn is_paid(&self) -> bool {
        matches!(self.mode, IssuanceMode::Paid { .. })
    }

    /// Paid 模式的锚定资产（Free 模式 `None`）。
    #[must_use]
    pub fn anchor(&self) -> Option<AssetId> {
        match self.mode {
            IssuanceMode::Paid { anchor, .. } => Some(anchor),
            IssuanceMode::Free { .. } => None,
        }
    }

    /// Paid 模式的比率 R（Free 模式 `None`）。
    #[must_use]
    pub fn rate(&self) -> Option<u64> {
        match self.mode {
            IssuanceMode::Paid { rate, .. } => Some(rate),
            IssuanceMode::Free { .. } => None,
        }
    }

    /// 铸造量：`floor(pay_amount_e18 * R / 1e18)`（设计 §3.1 冻结公式，
    /// u128 中间量防溢出；Free 模式不经此函数——faucet 按申请量直铸）。
    #[must_use]
    pub fn mint_for(&self, pay_amount_e18: u64) -> u128 {
        match self.mode {
            IssuanceMode::Paid { rate, .. } => paid_mint_amount(rate, pay_amount_e18),
            IssuanceMode::Free { .. } => 0,
        }
    }
}

/// Paid 模式铸造公式（冻结）：`floor(pay_amount_e18 * R / 1e18)`。
///
/// u128 中间量：`pay_amount ≤ u64::MAX ≈ 1.8e19`、`R ≤ u64::MAX`，乘积
/// ≤ ~3.4e38 < u128::MAX，无溢出。结果为 0 表示支付不足 1 币（尘埃
/// 全额留在未铸侧——调用方必须拒绝该次发行，无零面额 note）。
#[must_use]
pub fn paid_mint_amount(rate: u64, pay_amount_e18: u64) -> u128 {
    (u128::from(pay_amount_e18) * u128::from(rate)) / RATE_DENOM
}

// ---------------------------------------------------------------------------
// 价带（INV-TE-4）
// ---------------------------------------------------------------------------

/// 发行价带（治理参数；[`RateBand::default`] 为设计 §3.2 参考默认）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateBand {
    /// 最低比率（单币名义锚定价值 ≤ 1/R_min：play-money 属性 + u64 余量）。
    pub min: u64,
    /// 最高比率（单币发行价 ≥ 1/R_max：成本覆盖 `R ≤ 1/(k·c), k≥5`）。
    pub max: u64,
}

impl Default for RateBand {
    fn default() -> Self {
        Self {
            min: RATE_MIN_DEFAULT,
            max: RATE_MAX_DEFAULT,
        }
    }
}

/// 价带校验（validation 层强制点，INV-TE-4 第 1 层；越界拒绝并计
/// `issuance_rate_rejected_total`——由调用方计数）。AIR 层强制是同一
/// rate 进 genesis 摘要（第 2 层）。
///
/// # Errors
/// `rate < band.min` 或 `rate > band.max` →
/// [`AppchainError::RateOutOfBand`]。
pub fn validate_rate(rate: u64, band: &RateBand) -> AppchainResult<()> {
    if band.min > band.max {
        return Err(AppchainError::OutOfRange("rate band min > max"));
    }
    if rate < band.min || rate > band.max {
        return Err(AppchainError::RateOutOfBand {
            rate,
            min: band.min,
            max: band.max,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 注册表（冻结语义：append-only，重注册拒）
// ---------------------------------------------------------------------------

/// GAME token 注册表（token_id → spec；注册后冻结，重注册一律拒）。
///
/// 账本态：由 `RegisterGameToken` op 驱动、WAL 重放重建（不入状态根，
/// 与 `deposit_records_v2` 同纪律）；BTreeMap 序保证导出确定。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GameTokenRegistry {
    tokens: std::collections::BTreeMap<u32, GameTokenSpec>,
}

impl GameTokenRegistry {
    /// 注册（冻结语义）：同 token_id 重注册拒（含载荷不同/相同的重放
    /// ——载荷相同由上层幂等键另防，本层语义是"注册位一次性"）。
    ///
    /// # Errors
    /// token_id 已注册 → [`AppchainError::GameRegistryRejected`]。
    pub fn register(&mut self, spec: GameTokenSpec) -> AppchainResult<()> {
        if self.tokens.contains_key(&spec.token_id) {
            return Err(AppchainError::GameRegistryRejected(
                "token_id already registered (genesis is frozen; repricing = new token)",
            ));
        }
        self.tokens.insert(spec.token_id, spec);
        Ok(())
    }

    /// 查询规格。
    #[must_use]
    pub fn get(&self, token_id: u32) -> Option<&GameTokenSpec> {
        self.tokens.get(&token_id)
    }

    /// 是否已注册。
    #[must_use]
    pub fn contains(&self, token_id: u32) -> bool {
        self.tokens.contains_key(&token_id)
    }

    /// 已注册 token 数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// 空表判定。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// 全部已注册 token id（升序）。
    pub fn token_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.tokens.keys().copied()
    }

    /// 全部规格（token_id 升序；对账/导出用）。
    pub fn specs(&self) -> impl Iterator<Item = &GameTokenSpec> {
        self.tokens.values()
    }
}

// ---------------------------------------------------------------------------
// TE-M6：桌级 GasPolicy（Free 桌固定费额 gas 服务费）
// ---------------------------------------------------------------------------

/// 成本覆盖边际倍数下限（设计 §3.8.4 冻结：`k ≥ 3`——费用对每手摊薄
/// 成本取 ≥ 3 倍边际，吸收成本波动；低于 3 的 `min_coverage_k` 绑定拒）。
pub const GAS_MIN_COVERAGE_K: u64 = 3;

/// gas credit 计量账对账导出格式标签（冻结；日终审计流输入）。
pub const GAS_CREDIT_LEDGER_FORMAT: &str = "zchain.game_token.gas_credit.v1";

/// 桌级 gas 服务费策略（Free 桌；**绑定即冻结**，重绑拒——同 FeePolicy
/// 开桌冻结纪律）。
///
/// **固定费额，刻意不与底池挂钩**（设计 §3.8.2）：底池比例费形似对
/// wager 抽水，损害"服务费"定性；固定费 = 与胜负无关的服务定价。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct GasPolicy {
    /// 每手固定服务费（计价资产最小单位；> 0。与 credit 同量纲）。
    pub fee_per_hand: u64,
    /// 计价资产（REAL 域**已注册** token：NATIVE/USDT/USDC 封闭枚举；
    /// GAME 域拒——服务费必须以真实价值资产计价，设计 §3.8.2）。
    pub pricing_asset_id: AssetId,
    /// 成本覆盖边际倍数（`≥ [`GAS_MIN_COVERAGE_K`]`；覆盖条件
    /// `fee_per_hand ≥ k·c_hand`，`c_hand` 由 sequencer 配置注入）。
    pub min_coverage_k: u64,
}

impl GasPolicy {
    /// 构造并做结构校验（fail-closed；绑定准入的强制点）：
    /// 1. `fee_per_hand > 0`（零费 = 未定价，拒）；
    /// 2. `min_coverage_k ≥ GAS_MIN_COVERAGE_K`（k ≥ 3 冻结下限）；
    /// 3. 计价资产必须是 REAL 域已注册 token（封闭枚举；"不认识 ≠ 接受"）。
    ///
    /// 成本覆盖校验**不在此处**（[`GasPolicy::covers_cost`] 独立函数）：
    /// `c_hand` 是 sequencer 配置注入的运营参数，不进本结构（策略字段
    /// 是协议冻结面；TE-D7 的 Paid 拒与冻结语义在 sequencer 绑定准入）。
    ///
    /// # Errors
    /// 上述任一不满足 → [`AppchainError::GasPolicyRejected`]。
    pub fn new(
        fee_per_hand: u64,
        pricing_asset_id: AssetId,
        min_coverage_k: u64,
    ) -> AppchainResult<Self> {
        if fee_per_hand == 0 {
            return Err(AppchainError::GasPolicyRejected("fee_per_hand must be positive"));
        }
        if min_coverage_k < GAS_MIN_COVERAGE_K {
            return Err(AppchainError::GasPolicyRejected(
                "min_coverage_k below frozen floor (k >= 3)",
            ));
        }
        if !pricing_asset_id.is_real_domain()
            || !pricing_asset_id.domain.is_registered_token(pricing_asset_id.token_id)
        {
            return Err(AppchainError::GasPolicyRejected(
                "pricing asset must be a REAL domain registered token",
            ));
        }
        Ok(Self {
            fee_per_hand,
            pricing_asset_id,
            min_coverage_k,
        })
    }

    /// 成本覆盖判定（Free 模式的"价带等价物"，设计 §3.8.4）：
    /// `fee_per_hand ≥ min_coverage_k × c_hand`。u128 中间量防溢出。
    ///
    /// `c_hand` = 每手摊薄运营成本（结算 gas + 证明成本 + 基础设施）/
    /// 预期手数，以计价资产计——**运营参数**（sequencer 配置注入；真实
    /// 计量属部署面，如实标注）。`c_hand = 0` 恒过（部署面未配置成本
    /// 数据时的诚实缺省：覆盖强制未激活，但 k ≥ 3 与费额 > 0 仍强制）。
    #[must_use]
    pub fn covers_cost(&self, c_hand: u64) -> bool {
        let required = u128::from(self.min_coverage_k) * u128::from(c_hand);
        u128::from(self.fee_per_hand) >= required
    }
}

// ---------------------------------------------------------------------------
// TE-M6：gas credit 计量账（预付服务额度；收入非储备）
// ---------------------------------------------------------------------------

/// gas credit 计量账（sequencer 侧权威；设计 §3.8.3）。
///
/// **账面额度，不是链上资产**——物理隔离声明（合规定性的实现面）：
///
/// - 不铸 note（无承诺、无 nullifier、不进任何 Merkle 树/状态根）；
/// - **不进 `CustodyLedger` 对账恒等式**：服务费收入不进 `reserved` /
///   `issued` 的任何一边，`delta[code] = reserved − issued == 0` 不因本
///   账任何活动而变化——credit 无赎回（封闭操作集无退回变体）、无储备
///   义务，是已售服务额度不是负债；
/// - 记账恒等（INV-TE-8）：逐 (owner, 计价 asset) `credit =
///   Σpurchased − Σconsumed ≥ 0`——`spend` 前置校验拒绝不足扣减，
///   u64 + checked 算术使负余额**结构上不可表达**；
/// - 账本态：由 `BuyGasCredits` / 结算准入消耗驱动、WAL 重放重建
///   （不入状态根，与 `game_registry` 同纪律）；BTreeMap 序保证导出确定。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GasCreditLedger {
    /// 余额：(owner_commitment, 计价 asset) → credit。
    balances: std::collections::BTreeMap<([u8; 32], AssetId), u64>,
    /// `BuyGasCredits.pay_digest` 已用集（op 族幂等）。
    pay_digests: std::collections::BTreeSet<[u8; 32]>,
    /// Σpurchased per 计价 asset（恒等导出侧）。
    purchased_total: std::collections::BTreeMap<AssetId, u128>,
    /// Σconsumed per 计价 asset（恒等导出侧）。
    consumed_total: std::collections::BTreeMap<AssetId, u128>,
}

impl GasCreditLedger {
    /// 入账（`BuyGasCredits` 应用段）：`pay_digest` 幂等（重复支付身份
    /// 一律拒）、面额 > 0，1:1 记入 (owner, asset) 余额。
    ///
    /// # Errors
    /// `pay_digest` 已用 → [`AppchainError::WithdrawalConflict`]；
    /// `amount == 0` → [`AppchainError::InvalidAmount`]。
    pub fn credit(
        &mut self,
        owner: &[u8; 32],
        asset: AssetId,
        pay_digest: &[u8; 32],
        amount: u64,
    ) -> AppchainResult<()> {
        if amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        if !self.pay_digests.insert(*pay_digest) {
            return Err(AppchainError::WithdrawalConflict(
                "duplicate gas credit pay digest".into(),
            ));
        }
        let balance = self.balances.entry((*owner, asset)).or_insert(0);
        *balance = balance
            .checked_add(amount)
            .ok_or(AppchainError::OutOfRange("gas credit balance overflow"))?;
        *self.purchased_total.entry(asset).or_insert(0) += u128::from(amount);
        Ok(())
    }

    /// INV-TE-8 前置校验（结算准入检查段调用；只读）：余额 ≥ fee。
    ///
    /// # Errors
    /// 不足 → [`AppchainError::GasCreditInsufficient`]（零状态变更）。
    pub fn ensure_spendable(&self, owner: &[u8; 32], asset: AssetId, fee: u64) -> AppchainResult<()> {
        let balance = self.balance_of(owner, asset);
        if balance < fee {
            return Err(AppchainError::GasCreditInsufficient {
                asset,
                balance,
                required: fee,
            });
        }
        Ok(())
    }

    /// 消耗（结算受理变更段调用）：前置校验 + 扣减。检查段已
    /// `ensure_spendable` 且检查到变更之间零状态变更时本函数不可失败
    /// （仍返回 Result 以保持强制点单一——[`Self::ensure_spendable`]）。
    ///
    /// # Errors
    /// 余额不足 → [`AppchainError::GasCreditInsufficient`]。
    pub fn spend(&mut self, owner: &[u8; 32], asset: AssetId, fee: u64) -> AppchainResult<()> {
        self.ensure_spendable(owner, asset, fee)?;
        let balance = self.balances.get_mut(&(*owner, asset)).expect("checked above");
        *balance -= fee;
        if *balance == 0 {
            // 零余额键移除（索引语义 == 空集；与 owner_index 同纪律）
            self.balances.remove(&(*owner, asset));
        }
        *self.consumed_total.entry(asset).or_insert(0) += u128::from(fee);
        Ok(())
    }

    /// 某 (owner, asset) 的 credit 余额（无记录 = 0）。
    #[must_use]
    pub fn balance_of(&self, owner: &[u8; 32], asset: AssetId) -> u64 {
        self.balances.get(&(*owner, asset)).copied().unwrap_or(0)
    }

    /// `pay_digest` 是否已用（幂等查重读侧）。
    #[must_use]
    pub fn contains_pay_digest(&self, pay_digest: &[u8; 32]) -> bool {
        self.pay_digests.contains(pay_digest)
    }

    /// Σpurchased per asset（恒等导出侧）。
    #[must_use]
    pub fn purchased_total_of(&self, asset: AssetId) -> u128 {
        self.purchased_total.get(&asset).copied().unwrap_or(0)
    }

    /// Σconsumed per asset（恒等导出侧）。
    #[must_use]
    pub fn consumed_total_of(&self, asset: AssetId) -> u128 {
        self.consumed_total.get(&asset).copied().unwrap_or(0)
    }

    /// 某计价 asset 的全部持有者余额合计（gauge 输入）。
    #[must_use]
    pub fn total_balance_of(&self, asset: AssetId) -> u128 {
        self.balances
            .iter()
            .filter(|((_, a), _)| *a == asset)
            .map(|(_, v)| u128::from(*v))
            .sum()
    }

    /// 已见过的全部计价 asset（升序确定；导出用）。
    pub fn assets(&self) -> impl Iterator<Item = AssetId> + '_ {
        let mut set: std::collections::BTreeSet<AssetId> =
            self.balances.keys().map(|(_, a)| *a).collect();
        set.extend(self.purchased_total.keys().copied());
        set.extend(self.consumed_total.keys().copied());
        set.into_iter()
    }

    /// INV-TE-8 恒等核对：逐 asset `Σ余额 == Σpurchased − Σconsumed`。
    /// 任何 false 即计量账 bug 信号（日终告警面；非负性由 u64 + checked
    /// 算术结构保证，本核对钉聚合守恒）。
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        self.assets().all(|a| {
            self.total_balance_of(a) == self.purchased_total_of(a) - self.consumed_total_of(a)
        })
    }

    /// JSON 导出（日终审计流输入；u128 十进制字符串，owner hex）。
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "format": GAS_CREDIT_LEDGER_FORMAT,
            "reserve_note": "gas service fee revenue is NOT reserve; outside CustodyLedger identity",
            "invariant_holds": self.invariant_holds(),
            "assets": self.assets().map(|a| serde_json::json!({
                "asset": a.to_string(),
                "purchased_total": self.purchased_total_of(a).to_string(),
                "consumed_total": self.consumed_total_of(a).to_string(),
                "balance_total": self.total_balance_of(a).to_string(),
            })).collect::<Vec<_>>(),
            "balances": self.balances.iter().map(|((o, a), v)| serde_json::json!({
                "owner": hex::encode(o),
                "asset": a.to_string(),
                "balance": v.to_string(),
            })).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// 供给恒等对账（INV-TE-7，日终导出）
// ---------------------------------------------------------------------------

/// 单 token 供给报告（设计 §4.3 GAME 域恒等式）。
///
/// `consistent == (outstanding == live_note_sum)`——恒等式破坏即账本
/// bug 信号（日终对账任何一项 false 必须告警）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameSupplyReport {
    /// token id。
    pub token_id: u32,
    /// Σminted（账本聚合，TE-M3 起）。
    pub minted_total: u128,
    /// Σburned（`BurnGameToken` 销毁面额合计）。
    pub burned_total: u128,
    /// `Σminted − Σburned`。
    pub outstanding: u128,
    /// 存续 GAME v2 note 面额合计（对 `notes_v2` 全量扫描）。
    pub live_note_sum: u128,
    /// 恒等式核对结果。
    pub consistent: bool,
}

/// 日终对账（全部 token；`tokens` 按 token_id 升序确定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameReconciliation {
    /// 逐 token 报告。
    pub tokens: Vec<GameSupplyReport>,
    /// 全部 token 恒等式成立。
    pub all_consistent: bool,
}

impl GameReconciliation {
    /// JSON 导出（日终对账/explorer 供给视图的输入；u128 以十进制字符串
    /// 表达，避免 JSON 数值精度歧义；键序为 `serde_json::json!` 字母序，
    /// 读取方按名读取）。
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "format": RECONCILIATION_FORMAT,
            "all_consistent": self.all_consistent,
            "tokens": self.tokens.iter().map(|t| serde_json::json!({
                "token_id": t.token_id,
                "minted_total": t.minted_total.to_string(),
                "burned_total": t.burned_total.to_string(),
                "outstanding": t.outstanding.to_string(),
                "live_note_sum": t.live_note_sum.to_string(),
                "consistent": t.consistent,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset_id::AssetDomain;
    use borsh::BorshDeserialize as _;

    fn issuer(seed: u8) -> [u8; 33] {
        let mut k = [0u8; 33];
        k[0] = 2; // 压缩公钥前缀形态（非零即可，本层不验签）
        k[1] = seed;
        k
    }

    fn paid(rate: u64) -> IssuanceMode {
        IssuanceMode::Paid {
            anchor: AssetId::REAL_USDT,
            rate,
        }
    }

    /// genesis 摘要：全字段敏感 + 确定性与域分离。
    #[test]
    fn genesis_digest_binds_all_fields() {
        let base = GameTokenSpec::genesis_digest_of(1, &issuer(1), &paid(1_000_000), 0);
        // 确定性
        assert_eq!(base, GameTokenSpec::genesis_digest_of(1, &issuer(1), &paid(1_000_000), 0));
        // 逐字段敏感
        assert_ne!(base, GameTokenSpec::genesis_digest_of(2, &issuer(1), &paid(1_000_000), 0), "token_id 进摘要");
        assert_ne!(base, GameTokenSpec::genesis_digest_of(1, &issuer(2), &paid(1_000_000), 0), "issuer 进摘要");
        assert_ne!(base, GameTokenSpec::genesis_digest_of(1, &issuer(1), &paid(1_000_001), 0), "rate 进摘要");
        assert_ne!(base, GameTokenSpec::genesis_digest_of(1, &issuer(1), &paid(1_000_000), 9), "max_supply 进摘要");
        assert_ne!(
            base,
            GameTokenSpec::genesis_digest_of(
                1,
                &issuer(1),
                &IssuanceMode::Free {
                    faucet: FaucetPolicy { single_max: 1, player_lifetime_max: 1 },
                },
                0
            ),
            "mode 进摘要"
        );
        // 换 anchor 币种（同 REAL 域不同 token）同样敏感
        let other_anchor = GameTokenSpec::genesis_digest_of(
            1,
            &issuer(1),
            &IssuanceMode::Paid { anchor: AssetId::REAL_USDC, rate: 1_000_000 },
            0,
        );
        assert_ne!(base, other_anchor, "anchor 进摘要");
        // 域分离：与资产承诺命名空间不同（摘要非零且稳定）
        assert_ne!(base, [0u8; 32]);
    }

    /// 规格构造校验：PLAY 保留位 / 零 issuer / GAME 域 anchor / 伪造
    /// REAL token / 零 rate / faucet 参数非法 全部拒。
    #[test]
    fn spec_new_validates_structure_fail_closed() {
        // 正例
        assert!(GameTokenSpec::new(1, &issuer(1), paid(1_000_000), 0).is_ok());
        assert!(GameTokenSpec::new(
            3,
            &issuer(1),
            IssuanceMode::Free { faucet: FaucetPolicy { single_max: 100, player_lifetime_max: 1_000 } },
            5_000,
        )
        .is_ok());
        // token 0 = 遗留 PLAY 保留位
        let err = GameTokenSpec::new(0, &issuer(1), paid(1_000_000), 0).unwrap_err();
        assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
        // 零 issuer
        assert!(GameTokenSpec::new(1, &[0u8; 33], paid(1_000_000), 0).is_err());
        // GAME 域 anchor 拒（对称纪律：anchor 只能 REAL 域）
        let game_anchor = IssuanceMode::Paid { anchor: AssetId::GAME_PLAY, rate: 1_000_000 };
        assert!(GameTokenSpec::new(1, &issuer(1), game_anchor, 0).is_err());
        // 伪造 REAL token（borsh 绕过构造器的载荷）拒
        let forged = AssetId { domain: AssetDomain::Real, token_id: 999 };
        let forged_anchor = IssuanceMode::Paid { anchor: forged, rate: 1_000_000 };
        assert!(GameTokenSpec::new(1, &issuer(1), forged_anchor, 0).is_err());
        // 零 rate
        assert!(GameTokenSpec::new(1, &issuer(1), paid(0), 0).is_err());
        // faucet：single_max = 0 / single > lifetime 拒
        assert!(GameTokenSpec::new(
            1,
            &issuer(1),
            IssuanceMode::Free { faucet: FaucetPolicy { single_max: 0, player_lifetime_max: 10 } },
            0,
        )
        .is_err());
        assert!(GameTokenSpec::new(
            1,
            &issuer(1),
            IssuanceMode::Free { faucet: FaucetPolicy { single_max: 100, player_lifetime_max: 10 } },
            0,
        )
        .is_err());
    }

    /// 价带校验：默认带 [1e5, 1e7]，上下界越界拒、边界值过；min>max 配置拒。
    #[test]
    fn validate_rate_band_bounds() {
        let band = RateBand::default();
        assert_eq!(band.min, RATE_MIN_DEFAULT);
        assert_eq!(band.max, RATE_MAX_DEFAULT);
        // 典型发行 1U = 100 万居带内
        validate_rate(1_000_000, &band).unwrap();
        // 边界值含（闭区间）
        validate_rate(band.min, &band).unwrap();
        validate_rate(band.max, &band).unwrap();
        // 越界
        let err = validate_rate(band.min - 1, &band).unwrap_err();
        assert!(matches!(err, AppchainError::RateOutOfBand { rate: 99_999, min: 100_000, max: 10_000_000 }));
        let err = validate_rate(band.max + 1, &band).unwrap_err();
        assert!(matches!(err, AppchainError::RateOutOfBand { rate: 10_000_001, .. }));
        // 极端：0 与 u64::MAX
        assert!(validate_rate(0, &band).is_err());
        assert!(validate_rate(u64::MAX, &band).is_err());
        // 坏配置（min > max）fail-closed
        assert!(validate_rate(5, &RateBand { min: 10, max: 1 }).is_err());
        // 自定义带（治理版本化）
        let narrow = RateBand { min: 500_000, max: 2_000_000 };
        assert!(validate_rate(1_000_000, &narrow).is_ok());
        assert!(validate_rate(100_000, &narrow).is_err());
    }

    /// floor 公式精确断言（含 1U = 100 万币示例与尘埃边界）。
    #[test]
    fn paid_mint_floor_formula_exact() {
        // 示例：R = 1_000_000（1U = 100 万币）
        assert_eq!(paid_mint_amount(1_000_000, 1_000_000_000_000_000_000), 1_000_000, "1U → 100 万币");
        assert_eq!(paid_mint_amount(1_000_000, 2_500_000_000_000_000_000), 2_500_000, "2.5U → 250 万币");
        // 向下取整：0.5 wei 级尘埃截断
        assert_eq!(paid_mint_amount(1_000_000, 1_500_000_000_000_000_001), 1_500_000, "1 wei 尘埃截断");
        assert_eq!(paid_mint_amount(3, 1_500_000_000_000_000_000), 4, "1.5U × 3 = 4.5 → 4（floor）");
        assert_eq!(paid_mint_amount(3, 999_999_999_999_999_999), 2, "0.999...U × 3 = 2.99... → 2");
        // 不足 1 币 → 0（调用方必须拒绝）
        assert_eq!(paid_mint_amount(1_000_000, 999_999), 0, "尘埃支付 → 0 币");
        assert_eq!(paid_mint_amount(100_000, 9_999_999_999), 0);
        // R 边界值
        assert_eq!(paid_mint_amount(RATE_MIN_DEFAULT, 1_000_000_000_000_000_000), 100_000);
        assert_eq!(paid_mint_amount(RATE_MAX_DEFAULT, 1_000_000_000_000_000_000), 10_000_000);
        // 经 spec 入口一致
        let spec = GameTokenSpec::new(1, &issuer(1), paid(1_000_000), 0).unwrap();
        assert_eq!(spec.mint_for(1_000_000_000_000_000_000), 1_000_000);
        // Free 模式不经换算（mint_for 恒 0；faucet 按申请量直铸）
        let free = GameTokenSpec::new(
            2,
            &issuer(1),
            IssuanceMode::Free { faucet: FaucetPolicy { single_max: 10, player_lifetime_max: 100 } },
            0,
        )
        .unwrap();
        assert_eq!(free.mint_for(1_000_000_000_000_000_000), 0);
        assert!(free.anchor().is_none() && free.rate().is_none());
        assert!(spec.anchor() == Some(AssetId::REAL_USDT) && spec.rate() == Some(1_000_000));
    }

    /// 注册表冻结语义：注册成功 → 查询一致；重注册（同 id）一律拒；
    /// 不同 token 独立共存（重定价 = 发新 token）。
    #[test]
    fn registry_register_is_frozen_and_append_only() {
        let mut reg = GameTokenRegistry::default();
        assert!(reg.is_empty());
        let s1 = GameTokenSpec::new(1, &issuer(1), paid(1_000_000), 0).unwrap();
        reg.register(s1.clone()).unwrap();
        // 同 id 重注册（同载荷）→ 拒
        let err = reg.register(GameTokenSpec::new(1, &issuer(1), paid(1_000_000), 0).unwrap()).unwrap_err();
        assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
        // 同 id 重注册（异载荷——试图"重定价"）→ 同样拒
        let err = reg.register(GameTokenSpec::new(1, &issuer(1), paid(2_000_000), 0).unwrap()).unwrap_err();
        assert!(matches!(err, AppchainError::GameRegistryRejected(_)));
        // 新 token 独立注册（重定价 = 发新 token 的正例）
        reg.register(GameTokenSpec::new(2, &issuer(1), paid(2_000_000), 777).unwrap()).unwrap();
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.get(1).unwrap().rate(), Some(1_000_000), "旧 token 字段冻结不变");
        assert_eq!(reg.get(2).unwrap().max_supply, 777);
        assert_eq!(reg.token_ids().collect::<Vec<_>>(), vec![1, 2]);
        assert!(reg.contains(2) && !reg.contains(3));
        // borsh roundtrip（ IssuanceMode 判别值：Paid = 0 / Free = 1 ）
        let bytes = borsh::to_vec(&paid(5)).unwrap();
        assert_eq!(bytes[0], 0, "Paid 判别值冻结");
        let free_mode = IssuanceMode::Free {
            faucet: FaucetPolicy { single_max: 1, player_lifetime_max: 2 },
        };
        assert_eq!(borsh::to_vec(&free_mode).unwrap()[0], 1, "Free 判别值冻结");
        let back = IssuanceMode::try_from_slice(&bytes).unwrap();
        assert_eq!(back, paid(5));
    }

    /// 对账 JSON 导出：结构冻结、u128 以字符串表达、逐字段一致。
    #[test]
    fn reconciliation_json_shape() {
        let rec = GameReconciliation {
            tokens: vec![GameSupplyReport {
                token_id: 1,
                minted_total: 2_500_000,
                burned_total: 500_000,
                outstanding: 2_000_000,
                live_note_sum: 2_000_000,
                consistent: true,
            }],
            all_consistent: true,
        };
        let v = rec.to_json();
        assert_eq!(v["format"], RECONCILIATION_FORMAT);
        assert_eq!(v["all_consistent"], true);
        assert_eq!(v["tokens"][0]["token_id"], 1);
        assert_eq!(v["tokens"][0]["minted_total"], "2500000", "u128 十进制字符串");
        assert_eq!(v["tokens"][0]["outstanding"], "2000000");
        assert_eq!(v["tokens"][0]["consistent"], true);
        let text = v.to_string();
        assert!(text.contains(RECONCILIATION_FORMAT));
    }

    // ===== TE-M6：GasPolicy / gas credit 计量账 =====

    /// GasPolicy 构造校验（fail-closed）：零费 / k < 3 / 计价资产非 REAL
    /// 域注册 token 全部拒；正例字段保真 + borsh roundtrip。
    #[test]
    fn gas_policy_new_validates_structure_fail_closed() {
        // 正例（USDT 计价）
        let p = GasPolicy::new(1_000, AssetId::REAL_USDT, 3).unwrap();
        assert_eq!(p.fee_per_hand, 1_000);
        assert_eq!(p.pricing_asset_id, AssetId::REAL_USDT);
        assert_eq!(p.min_coverage_k, 3);
        // 三币种（封闭枚举内）全过
        assert!(GasPolicy::new(1, AssetId::REAL_NATIVE, 5).is_ok());
        assert!(GasPolicy::new(1, AssetId::REAL_USDC, GAS_MIN_COVERAGE_K).is_ok());
        // 零费拒
        let err = GasPolicy::new(0, AssetId::REAL_USDT, 3).unwrap_err();
        assert!(matches!(err, AppchainError::GasPolicyRejected(s) if s.contains("fee_per_hand")));
        // k < 3（冻结下限）拒
        assert!(GasPolicy::new(1_000, AssetId::REAL_USDT, 2).is_err());
        // GAME 域计价拒（服务费必须真实价值资产）
        assert!(GasPolicy::new(1_000, AssetId::GAME_PLAY, 3).is_err());
        assert!(GasPolicy::new(1_000, AssetId::game(1), 3).is_err());
        // 伪造 REAL token（封闭枚举外）拒
        let forged = AssetId { domain: crate::asset_id::AssetDomain::Real, token_id: 999 };
        assert!(GasPolicy::new(1_000, forged, 3).is_err());
        // borsh roundtrip（BindGasPolicy 载荷字段）
        let bytes = borsh::to_vec(&p).unwrap();
        let back: GasPolicy = borsh::BorshDeserialize::try_from_slice(&bytes).unwrap();
        assert_eq!(back, p);
    }

    /// 成本覆盖判定（设计 §3.8.4）：`fee_per_hand ≥ k·c_hand`（u128 中间量，
    /// k·c 溢出安全）；c_hand = 0 恒过（诚实缺省：覆盖强制未激活）。
    #[test]
    fn gas_policy_cost_coverage_k_times_c_hand() {
        let p = GasPolicy::new(3_000, AssetId::REAL_USDT, 3).unwrap();
        // 边界含：3000 == 3 × 1000 过
        assert!(p.covers_cost(1_000));
        // 超出：3 × 1001 = 3003 > 3000 拒
        assert!(!p.covers_cost(1_001));
        // c_hand = 0 恒过
        assert!(p.covers_cost(0));
        // 大数溢出安全：k·c 在 u128 内不溢出（u128::from(u64::MAX)^2 <
        // u128::MAX），fee < k·c 时正确拒
        let big = GasPolicy::new(u64::MAX, AssetId::REAL_USDT, u64::MAX).unwrap();
        assert!(!big.covers_cost(1_000), "u64::MAX < u64::MAX·1000，必须拒");
        assert!(big.covers_cost(1), "u64::MAX ≥ u64::MAX·1，边界含");
        // 恰好相等的大数边界
        assert!(GasPolicy::new(6_000, AssetId::REAL_USDT, 3)
            .unwrap()
            .covers_cost(2_000));
        // k = 5 的自定义边际
        let p5 = GasPolicy::new(10_000, AssetId::REAL_USDC, 5).unwrap();
        assert!(p5.covers_cost(2_000));
        assert!(!p5.covers_cost(2_001));
    }

    /// gas credit 计量账：入账 1:1、pay_digest 幂等拒、零面额拒、余额
    /// 按 (owner, asset) 隔离。
    #[test]
    fn gas_credit_ledger_credit_is_idempotent_and_per_asset() {
        let mut ledger = GasCreditLedger::default();
        let owner = [7u8; 32];
        // 1:1 入账
        ledger.credit(&owner, AssetId::REAL_USDT, &[1u8; 32], 5_000).unwrap();
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDT), 5_000);
        // 同 digest 重复入账拒（幂等，零状态变更）
        let err = ledger.credit(&owner, AssetId::REAL_USDT, &[1u8; 32], 5_000).unwrap_err();
        assert!(matches!(err, AppchainError::WithdrawalConflict(s) if s.contains("gas credit")));
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDT), 5_000, "重复入账零状态变更");
        assert!(ledger.contains_pay_digest(&[1u8; 32]));
        assert!(!ledger.contains_pay_digest(&[2u8; 32]));
        // 零面额拒
        assert!(matches!(
            ledger.credit(&owner, AssetId::REAL_USDT, &[3u8; 32], 0),
            Err(AppchainError::InvalidAmount(0))
        ));
        // 同 owner 不同计价 asset 隔离记账
        ledger.credit(&owner, AssetId::REAL_USDC, &[4u8; 32], 900).unwrap();
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDC), 900);
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDT), 5_000);
        // 不同 owner 同 asset 隔离记账
        let other = [8u8; 32];
        ledger.credit(&other, AssetId::REAL_USDT, &[5u8; 32], 111).unwrap();
        assert_eq!(ledger.balance_of(&other, AssetId::REAL_USDT), 111);
    }

    /// INV-TE-8：消耗前置校验（不足拒、零状态变更）+ 恰好扣尽 + 聚合
    /// 恒等 `Σ余额 == Σpurchased − Σconsumed` + JSON 导出契约。
    #[test]
    fn gas_credit_ledger_spend_enforces_non_negative_invariant() {
        let mut ledger = GasCreditLedger::default();
        let owner = [9u8; 32];
        ledger.credit(&owner, AssetId::REAL_USDT, &[1u8; 32], 1_000).unwrap();
        // 不足拒（INV-TE-8 前置校验；余额不变）
        let err = ledger.ensure_spendable(&owner, AssetId::REAL_USDT, 1_001).unwrap_err();
        assert!(matches!(
            err,
            AppchainError::GasCreditInsufficient { asset, balance: 1_000, required: 1_001 }
            if asset == AssetId::REAL_USDT
        ));
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDT), 1_000);
        // 恰好扣尽 → 余额 0（键移除）、consumed 记账
        ledger.spend(&owner, AssetId::REAL_USDT, 1_000).unwrap();
        assert_eq!(ledger.balance_of(&owner, AssetId::REAL_USDT), 0);
        // 再次消耗：余额 0 < 任意正 fee → 拒（负余额结构上不可表达）
        assert!(matches!(
            ledger.spend(&owner, AssetId::REAL_USDT, 1),
            Err(AppchainError::GasCreditInsufficient { balance: 0, .. })
        ));
        // 聚合恒等：Σ余额(0) == purchased(1000) − consumed(1000)
        assert!(ledger.invariant_holds());
        assert_eq!(ledger.purchased_total_of(AssetId::REAL_USDT), 1_000);
        assert_eq!(ledger.consumed_total_of(AssetId::REAL_USDT), 1_000);
        assert_eq!(ledger.total_balance_of(AssetId::REAL_USDT), 0);
        // 部分消耗的恒等（多 owner 多 asset）
        let a = [10u8; 32];
        let b = [11u8; 32];
        ledger.credit(&a, AssetId::REAL_USDC, &[2u8; 32], 5_000).unwrap();
        ledger.credit(&b, AssetId::REAL_USDC, &[3u8; 32], 700).unwrap();
        ledger.spend(&a, AssetId::REAL_USDC, 1_200).unwrap();
        assert_eq!(ledger.total_balance_of(AssetId::REAL_USDC), 4_500);
        assert_eq!(
            ledger.purchased_total_of(AssetId::REAL_USDC) - ledger.consumed_total_of(AssetId::REAL_USDC),
            4_500
        );
        assert!(ledger.invariant_holds());
        // JSON 导出：格式标签 + 非储备声明 + u128 十进制字符串
        let v = ledger.to_json();
        assert_eq!(v["format"], GAS_CREDIT_LEDGER_FORMAT);
        assert_eq!(v["invariant_holds"], true);
        let text = v.to_string();
        assert!(text.contains("NOT reserve"), "非储备声明必须在导出中");
        assert!(text.contains(GAS_CREDIT_LEDGER_FORMAT));
        assert_eq!(v["assets"][0]["purchased_total"], "1000");
    }
}
