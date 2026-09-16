//! M3：封闭操作集（closed operation set）。
//!
//! 链只处理这组操作——防滥用由封闭性给出，不依赖定价（plan §0）。
//! 任何新操作 = 协议版本升级，走 ABI 版本号，不允许运行时扩展。
//!
//! ## additive 变体纪律（ABI v2）
//!
//! 新变体只能**追加在 enum 末尾**（borsh 判别值 = 声明序，旧字节流解码
//! 兼容）：`MigrateNote` = 7、`SettleV2` = 8（v1 判别值 0..=6 冻结不动，
//! 见 docs/ABI_V2.md §Operation 判别值表）；TE-M2 追加 `DepositV2` = **9**、
//! `WithdrawRequestV2` = **10**（判别值冻结，后续变体只能 ≥ 11 追加；见
//! docs/ABI_TE_M2.md）。TE-M3 追加 GTS 游戏币三变体：`RegisterGameToken`
//! = **11**、`IssueGameToken` = **12**、`BurnGameToken` = **13**（判别值
//! 冻结，TE-M6 的 FaucetMint/BuyGasCredits/BindGasPolicy 从 **14** 起后续
//! 排；见 docs/ABI_TE_M3.md）。TE-M6 落地该三变体：`FaucetMint` = **14**、
//! `BuyGasCredits` = **15**、`BindGasPolicy` = **16**（判别值冻结，
//! 后续变体只能 ≥ 17 追加；见 docs/ABI_TE_M6.md）。

use crate::asset_id::AssetId;
use crate::fee::FeePolicy;
// TE-M3：GTS 发行模式（RegisterGameToken 载荷字段）
// TE-M6：桌级 GasPolicy（BindGasPolicy 载荷字段）
use crate::game_token::{GasPolicy, IssuanceMode};
use crate::note::{AssetClass, NoteSpec};
use crate::note_v2::{NoteV2, SettlementRecordV2};
use crate::owner_v2::{MigrateNoteRecord, OwnerRef, SignatureEnvelope, VerifierMaterial};
use crate::settlement::{SettlementRecord, SpendAuth};

/// ABI v2 迁移操作载荷：旧 owner 授权消费旧 v1 note → 同额同资产类铸
/// v2 note（[`NoteV2`]）。
///
/// borsh 载荷**刻意不含** [`crate::owner_v2::VerifierMaterial`]（呈递
/// 材料）：材料是准入时证据，经 `Sequencer::submit_migrate` 呈递并全量
/// 验签（[`crate::owner_v2::validate_migrate_note`] 8 步）；帧/重放侧
/// 复核材料无关的全部关系（结构/摘要/新鲜度/账本存在性/nonce 查重），
/// 边界见 docs/ABI_V2.md §边界。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct MigrateNoteOp {
    /// 迁移记录（验签走 owner_v2：migrate_digest + SignatureEnvelope）。
    pub record: MigrateNoteRecord,
    /// 铸出的 v2 note（amount/asset_id/new_owner_ref 必须与 record
    /// 一致——准入校验；table/pot/runout 必须为自由余额形态 0/None）。
    pub minted: NoteV2,
}

/// TE-M2 多币种存款载荷（判别值 **9**，追加变体；docs/ABI_TE_M2.md）：
/// 外部支付 → watcher 按币种幂等确认 → 铸 REAL 域 `asset_id` 指定 token
/// 的 v2 note（复用 v1 [`Operation::Deposit`] 的 deposit_id 幂等模式）。
///
/// REAL 域任意已注册 token（NATIVE/USDT/USDC，封闭枚举强制点在
/// [`AssetId::real`] + sequencer 准入复核 `is_registered_token`）；
/// **GAME 域拒入本 op**（fail-closed）——GAME 域发行是 TE-M3 的
/// `IssueGameToken`（另行追加变体），本 op 不做 GAME 入口。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct DepositV2Op {
    /// 外部充值幂等键（跨版本全局：与 v1 [`Operation::Deposit`] 共享
    /// 幂等查重，同一外部支付不得经两条路径重复铸造）。
    pub deposit_id: [u8; 32],
    /// 收款人（v2 owner 引用，承诺含 scheme/key_version）。
    pub owner: OwnerRef,
    /// 资产身份（REAL 域 token；GAME 域准入拒绝）。
    pub asset_id: AssetId,
    /// 面额 > 0。
    pub amount: u64,
}

/// TE-M2 多币种提现申请载荷（判别值 **10**，追加变体；docs/ABI_TE_M2.md）：
/// owner 授权销毁一张 v2 note → vault 按 token 入提现队列 → 托管打款侧
/// 按币种独立通道执行（plan §2.3）。
///
/// 授权走 v2 [`SignatureEnvelope`]（owner_v2 验签，非 v1
/// [`SpendAuth`]）——`typed_data_digest` 必须等于链侧重算的
/// `v2_spend_digest(owner, note 承诺, nullifier, scope, effect)`，其中
/// scope = `spend_scope(network_id, abi_version, [`scope::WITHDRAW_V2`])`、
/// effect = 本 op 效果摘要（绑定 request_id/asset_id/gross_amount/
/// external_recipient/created_at_ms/note 承诺）。与 MigrateNote 不同，
/// 验签材料随载荷携带（`crate::note_v2::SettleInputV2::V2` 同款纪律）
/// ——WAL 重放可**全量复核**签名，无需独立呈递通道。
///
/// 提现费从 `gross_amount` 内扣（打款净额 = gross − fee，销毁面额不变）；
/// 打款净额才进 withdrawal root 叶（M7 语义不变）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct WithdrawRequestV2Op {
    /// 提现幂等键（跨版本全局查重，同 [`DepositV2Op::deposit_id`]）。
    pub request_id: [u8; 32],
    /// owner 授权信封（v2；signer 必须等于被销毁 note 的 owner）。
    pub owner_sig: SignatureEnvelope,
    /// 提现资产（REAL 域 token；GAME 域拒入本 op——GAME 赎回属 TE-M3+）。
    pub asset_id: AssetId,
    /// 提现总额（销毁面额；费从内扣）。
    pub gross_amount: u64,
    /// 外部收款地址（抽象 32B；vault 打款通道按 token 分用）。
    pub external_recipient: [u8; 32],
    /// 受理声明时刻（unix 毫秒；签名覆盖，SLA 计时起点——随 op 进帧，
    /// 重放确定性所需）。
    pub created_at_ms: u64,
    /// 被销毁 v2 note 全量内容（账本核对：存在、内容一致、面额 ==
    /// `gross_amount`、资产 == `asset_id`、owner == 信封 signer；与 v1
    /// [`Operation::WithdrawRequest`] 携带 `note` 同纪律）。
    pub note: NoteV2,
    /// 声明的消费 nullifier（客户端按 [`NoteV2::nullifier`] 派生；非零，
    /// 进共享 nullifier 集防双花——与 [`crate::note_v2::SettleInputV2::V2`]
    /// 同纪律）。
    pub nullifier: [u8; 32],
    /// 验签材料（按 [`SignatureEnvelope::scheme`] 呈递；变体不匹配
    /// fail-closed 拒绝）。
    pub material: VerifierMaterial,
}

/// TE-M3 GTS genesis 注册载荷（判别值 **11**，追加变体；docs/ABI_TE_M3.md）：
/// 发行方/平台登记游戏币 genesis——注册即冻结，同 token_id 重注册拒
/// （重定价 = 发新 token，TE-D2）。载荷绑定 genesis 全部字段 +
/// `genesis_digest`（客户端按 [`crate::game_token::GameTokenSpec::
/// genesis_digest_of`] 预计算；链侧重算必须全等，任何字段篡改必失配）。
///
/// 价带校验（INV-TE-4 validation 层）在 sequencer 准入执行：Paid 模式
/// `rate ∉ [R_min, R_max]` → 拒绝（治理参数经 `SequencerConfig` 注入）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RegisterGameTokenOp {
    /// 注册表分配的 token id（GAME 域 `AssetId.token_id`；0 = 遗留 PLAY
    /// 保留位，GTS 从 1 起）。
    pub token_id: u32,
    /// 发行方公钥（v1 = 平台运营方，33B 压缩公钥）。
    pub issuer: [u8; 33],
    /// 发行模式（Paid / Free；TE-M3 Free 只有注册 + 限量铸造骨架，
    /// gas 服务费/时间窗限流属 TE-M6）。
    pub mode: IssuanceMode,
    /// 供给上限（0 = 不限；`Σminted ≤ max_supply` 由 sequencer 强制）。
    pub max_supply: u64,
    /// genesis 摘要（`zchain.game_token.genesis.v1` 域分离，全部字段绑定；
    /// 链侧重算核对，防注册载荷被中间篡改）。
    pub genesis_digest: [u8; 32],
}

/// TE-M3 GTS 发行载荷（判别值 **12**，追加变体；docs/ABI_TE_M3.md）：
/// 外部支付 anchor → watcher 按 `issue_id` 幂等确认 → 铸 GAME 域 v2 note
/// （**唯一入口**，完全复用 v1 [`Operation::Deposit`] 的 deposit_id 幂等
/// 模式；发行支付全额进协议金库，不退回、不分给发行方）。
///
/// - Paid：`pay_amount` = anchor 1e18 wei 支付额，铸
///   `floor(pay_amount * R / 1e18)`（向下取整；不足 1 币的尘埃支付拒绝
///   ——无零面额 note，fail-closed）；
/// - Free：`pay_amount` = 申请铸造量（faucet 限量骨架：单次上限 + 玩家
///   终身上限；完整机制 TE-M6）。
///
/// 幂等**跨路径**：`issue_id` 与 v1/v2 `deposit_id` 双向查重——同一外部
/// 支付不得既走 REAL Deposit 又走 GAME 发行。本 op 只铸 GAME 域资产；
/// anchor 的 REAL 域合法性在注册面冻结（对称纪律：REAL 域拒入本 op 的
/// 铸出侧由类型结构保证——铸出资产恒为 `AssetId::game(token_id)`）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct IssueGameTokenOp {
    /// 外部支付幂等键（复用 deposit_id 幂等模式；跨路径查重见结构文档）。
    pub issue_id: [u8; 32],
    /// 目标游戏币（必须已注册；未注册 token / 遗留 PLAY(0) 拒绝）。
    pub token_id: u32,
    /// 买家（v2 owner 引用；铸出 note 的 owner）。
    pub buyer: OwnerRef,
    /// Paid：anchor 支付额（1e18 wei 计价）；Free：申请铸造量。
    pub pay_amount: u64,
}

/// TE-M3 GTS 销毁载荷（判别值 **13**，追加变体；docs/ABI_TE_M3.md）：
/// owner 授权销毁一张 GAME 域 v2 note（**唯一出口**——rake 回收与玩家
/// 主动销毁共用；GAME 币无任何赎回/桥接通道，单向性结构面）。
///
/// 授权走 v2 [`SignatureEnvelope`]（镜像 [`WithdrawRequestV2Op`] 纪律，
/// scope 换用 [`scope::BURN_GAME`]）；验签材料随载荷携带（WAL 重放可
/// 全量复核）。**REAL 域拒入本 op**（对称纪律，fail-closed + 计数）——
/// REAL 资产出口是 Withdraw/WithdrawV2，两通道互斥。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct BurnGameTokenOp {
    /// 销毁幂等键（本 op 族内查重；防同一授权重复提交）。
    pub burn_id: [u8; 32],
    /// 被销毁 note 的 GAME token id（必须 == `note.asset_id.token_id` 且
    /// 已注册；遗留 PLAY(0) 无 GTS 规格，拒入本 op）。
    pub token_id: u32,
    /// 被销毁 v2 note 全量内容（账本核对：存在、内容一致、GAME 域）。
    pub note: NoteV2,
    /// 声明的消费 nullifier（非零，进共享 nullifier 集防双花）。
    pub nullifier: [u8; 32],
    /// owner 授权信封（signer 必须 == note owner；摘要 =
    /// `v2_spend_digest(owner, note 承诺, nullifier, BURN_GAME scope,
    /// effect)`）。
    pub owner_sig: SignatureEnvelope,
    /// 验签材料（按 scheme 呈递；变体不匹配 fail-closed 拒绝）。
    pub material: VerifierMaterial,
}

/// TE-M6 Free 模式 faucet 领取载荷（判别值 **14**，追加变体；
/// docs/ABI_TE_M6.md）：Free token 按 genesis 冻结的 [`crate::game_token::
/// FaucetPolicy`] 限量铸造——单次上限 + 玩家终身上限（按
/// `owner_commitment` 记账，WAL 重放可重建）。**无外部支付**（不销售，
/// 合规定性见设计 §3.8.1：币刻意不稀缺），watcher/operator 外驱动的
/// operator 帧。
///
/// 边界（如实声明）：设计 §3.8.3 的"每玩家单位时间上限"（时间窗限流）
/// v1 不做——限量口径为 single_max + player_lifetime_max 双上限，
/// 弱于最终口径；`claim_id` 是本 op 族幂等键（防同一领取授权重复提交），
/// 不与 deposit/issue 幂等集交叉（faucet 无外部支付身份）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct FaucetMintOp {
    /// 领取幂等键（op 族内查重）。
    pub claim_id: [u8; 32],
    /// 目标游戏币（必须已注册且 Free 模式；Paid token 的铸造通道是
    /// `IssueGameToken`，遗留 PLAY(0) 拒）。
    pub token_id: u32,
    /// 领取人（v2 owner 引用；铸出 GAME 域自由余额 note 的 owner）。
    pub owner: OwnerRef,
    /// 申请铸造量（> 0；`≤ single_max` 且终身累计 `≤ player_lifetime_max`）。
    pub amount: u64,
}

/// TE-M6 gas credit 预付额度购买载荷（判别值 **15**，追加变体；
/// docs/ABI_TE_M6.md）：REAL 域注册 token 计价的外部支付 → 额度入账。
///
/// **credit 是账面额度，不是链上资产**：本 op 不铸任何 note、不进
/// `CustodyLedger` 对账恒等式（gas 服务费收入是**已售服务额度**，无储备
/// 义务——设计 §3.8.3；与 REAL 托管恒等式物理隔离，保护"服务费"合规
/// 定性）。计量账见 [`crate::game_token::GasCreditLedger`]；额度按计价
/// `asset_id` 1:1 入账（`pay_amount` 原生最小单位 == credit 单位，与
/// `GasPolicy::fee_per_hand` 同量纲；1e18 展示刻度属部署/呈现面）。
///
/// 幂等：`pay_digest` 是外部支付身份——本 op 族 + **跨路径前向查重**
/// （v1 `deposit_ids` / v2 `deposit_records_v2` / GAME `game_issue_ids`
/// 任一命中即拒：同一外部支付不得既走托管存款/发行又走服务费收入）。
/// 反向防线（deposit/issue 侧不反查 gas 摘要集）由 watcher 支付确认幂等
/// 承担，如实声明。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct BuyGasCreditsOp {
    /// 外部支付幂等键（op 族 + 跨路径前向查重，见结构文档）。
    pub pay_digest: [u8; 32],
    /// 付款人（v2 owner 引用；credit 余额记账身份 =
    /// `owner_commitment(payer)`）。
    pub payer: OwnerRef,
    /// 计价资产（REAL 域已注册 token——NATIVE/USDT/USDC 封闭枚举；
    /// GAME 域拒入本 op：服务费必须以真实价值资产计价）。
    pub pricing_asset_id: AssetId,
    /// 支付额（计价资产最小单位；> 0，1:1 转为 credit 额度）。
    pub pay_amount: u64,
}

/// TE-M6 Free 桌 gas 策略绑定载荷（判别值 **16**，追加变体；
/// docs/ABI_TE_M6.md）：GAME 桌绑定桌级 [`crate::game_token::GasPolicy`]
/// ——**绑定即冻结**（重绑拒；同 FeePolicy 开桌冻结纪律）。设计 §3.8.2
/// 排序：只能 `OpenTable` 之后、首次买入/结算受理之前执行。
///
/// TE-D7：Paid 模式 token 的桌绑定一律拒（双重收费 v1 禁止，放开 =
/// 治理项）；遗留 PLAY(0) 无 GTS 规格，同样拒（永久免费层，永不商业化）。
///
/// 固定费额，刻意**不与底池挂钩**（底池比例费形似对 wager 抽水，损害
/// "服务费"定性；固定费 = 与胜负无关的服务定价，设计 §3.8.2）。成本
/// 覆盖（`fee_per_hand ≥ min_coverage_k · c_hand`，k ≥ 3）在绑定时刻
/// 校验：`c_hand` 由 `SequencerConfig::gas_c_hand_estimate` 注入——
/// **运营参数**（真实每手成本计量属部署面，非协议常量，如实标注）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct BindGasPolicyOp {
    /// 目标桌 ID（必须已 `OpenTable` 且开放）。
    pub table_id: u64,
    /// 该桌 GAME token（必须已注册且 Free 模式；INV-TE-9 的判定键——
    /// Free token 的结算出现在未绑定桌即拒）。
    pub token_id: u32,
    /// 桌级 gas 策略（`fee_per_hand` / `pricing_asset_id` /
    /// `min_coverage_k`；绑定后冻结）。
    pub policy: GasPolicy,
}

/// 操作集（v1 判别值 0..=6 冻结；v2 追加变体见模块文档）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum Operation {
    /// 开桌并冻结费率策略（operator，帧签名即授权）。
    OpenTable {
        /// 桌 ID。
        table_id: u64,
        /// 费率策略（注册表冻结）。
        policy: FeePolicy,
    },
    /// 关桌（operator）。
    CloseTable {
        /// 桌 ID。
        table_id: u64,
    },
    /// 入金铸币（operator 托管路径；deposit_id 幂等）。
    Deposit {
        /// 外部充值幂等键。
        deposit_id: [u8; 32],
        /// 收款人。
        owner: [u8; 33],
        /// 资产类。
        asset_class: AssetClass,
        /// 面额。
        amount: u64,
    },
    /// 出金销毁（owner 签名授权；vault 侧打款）。
    ///
    /// 审计 P1 修复：载荷新增 `payout_recipient` 并纳入效果摘要（见
    /// [`Operation::effect_digest`]）——打款收款人从此被 owner 签名绑定，
    /// 操作方无法在持签请求上偷换收款地址（vault 受理侧另有
    /// `WithdrawalRequest::ensure_matches_op` fail-closed 核对）。
    WithdrawRequest {
        /// 花费授权（销毁 balance note）。
        spend: SpendAuth,
        /// 被销毁 note 的完整内容（账本核对）。
        note: crate::note::Note,
        /// 提现幂等键。
        request_id: [u8; 32],
        /// 外部收款地址（抽象 32B；与 v2 `WithdrawRequestV2Op::
        /// external_recipient` 同纪律——进效果摘要，被 spend 签名覆盖）。
        payout_recipient: [u8; 32],
    },
    /// 玩家间转账（守恒，同类）。
    Transfer {
        /// 消费授权（≥1）。
        spends: Vec<SpendAuth>,
        /// 被消费 note 内容（≥1，与 spends 对齐）。
        notes: Vec<crate::note::Note>,
        /// 输出（≥1）。
        outputs: Vec<NoteSpec>,
    },
    /// 买入：消费 balance note → 铸一张 seat note（桌准入约束）。
    BuyIn {
        /// 桌 ID。
        table_id: u64,
        /// 消费授权。
        spends: Vec<SpendAuth>,
        /// 被消费 note 内容。
        notes: Vec<crate::note::Note>,
        /// seat 归属。
        seat_owner: [u8; 33],
    },
    /// 一手牌结算（M2 关系）。
    Settle(Box<SettlementRecord>),
    /// ABI v2 迁移（判别值 7，追加变体）：旧 v1 note 消费 → NoteV2 铸造。
    ///
    /// 授权是 `record.old_owner_sig`（SignatureEnvelope），不是
    /// [`SpendAuth`]——[`Operation::spends`] 对本变体返回空；准入经
    /// `Sequencer::submit_migrate`（呈递验签材料）。`Box` 仅 Rust 侧
    /// 布局优化（帧内 Operation 按值嵌入），borsh 编码与裸结构完全一致。
    MigrateNote(Box<MigrateNoteOp>),
    /// ABI v2 混合结算（判别值 8，追加变体）：v1/v2 输入并行验证。
    SettleV2(Box<SettlementRecordV2>),
    /// TE-M2 多币种存款（判别值 **9**，追加变体；borsh 判别值冻结）：
    /// REAL 域任意 token 铸 v2 note，GAME 域准入拒绝（见 [`DepositV2Op`]）。
    /// `Box` 布局优化与 [`Operation::MigrateNote`] 同纪律。
    DepositV2(Box<DepositV2Op>),
    /// TE-M2 多币种提现申请（判别值 **10**，追加变体；borsh 判别值冻结）：
    /// owner 信封授权销毁 v2 note → vault 按 token 入队（见
    /// [`WithdrawRequestV2Op`]）。授权走 SignatureEnvelope——
    /// [`Operation::spends`] 对本变体返回空（与 [`Operation::MigrateNote`]
    /// 同纪律）。
    WithdrawRequestV2(Box<WithdrawRequestV2Op>),
    /// TE-M3 GTS genesis 注册（判别值 **11**，追加变体；borsh 判别值冻结）：
    /// issuer/平台登记游戏币 genesis，注册即冻结（见
    /// [`RegisterGameTokenOp`]）。operator 帧——[`Operation::spends`] 返回
    /// 空、效果摘要为零（同 v1 Deposit 纪律）。`Box` 布局优化与
    /// [`Operation::MigrateNote`] 同纪律。
    RegisterGameToken(Box<RegisterGameTokenOp>),
    /// TE-M3 GTS 发行（判别值 **12**，追加变体；borsh 判别值冻结）：GAME
    /// 域唯一入口，deposit_id 幂等模式（见 [`IssueGameTokenOp`]）。watcher
    /// 确认后的 operator 帧——spends() 空、效果摘要为零（同
    /// [`Operation::DepositV2`] 纪律）。
    IssueGameToken(Box<IssueGameTokenOp>),
    /// TE-M3 GTS 销毁（判别值 **13**，追加变体；borsh 判别值冻结）：GAME
    /// 域唯一出口，REAL 域拒入（见 [`BurnGameTokenOp`]）。授权走
    /// SignatureEnvelope + BURN_GAME scope——spends() 返回空；效果摘要绑定
    /// 全部语义载荷（被 owner 信封签名消费，同
    /// [`Operation::WithdrawRequestV2`] 纪律）。
    BurnGameToken(Box<BurnGameTokenOp>),
    /// TE-M6 Free 模式 faucet 领取（判别值 **14**，追加变体；borsh 判别值
    /// **冻结**，后续变体只能 ≥ 17 追加）：Free token 限量铸造
    /// （single_max + player_lifetime_max；见 [`FaucetMintOp`]）。operator
    /// 帧（无外部支付、无 SpendAuth）——spends() 返回空、效果摘要为零
    /// （同 [`Operation::DepositV2`] 纪律）。`Box` 布局优化同上。
    FaucetMint(Box<FaucetMintOp>),
    /// TE-M6 gas credit 预付额度购买（判别值 **15**，追加变体；borsh 判别
    /// 值**冻结**）：REAL 域计价支付 → 额度入账，**不铸 note、不进
    /// CustodyLedger**（收入非储备，见 [`BuyGasCreditsOp`]）。operator 帧
    /// （watcher 确认外驱动）——spends() 返回空、效果摘要为零。
    BuyGasCredits(Box<BuyGasCreditsOp>),
    /// TE-M6 Free 桌 gas 策略绑定（判别值 **16**，追加变体；borsh 判别值
    /// **冻结**）：桌级 GasPolicy 绑定即冻结，Paid 桌拒（TE-D7，见
    /// [`BindGasPolicyOp`]）。operator 帧（同 [`Operation::OpenTable`]）——
    /// spends() 返回空、效果摘要为零。
    BindGasPolicy(Box<BindGasPolicyOp>),
}

impl Operation {
    /// 本操作消耗的全部花费授权（签名验证入口）。
    #[must_use]
    pub fn spends(&self) -> Vec<&SpendAuth> {
        match self {
            Operation::OpenTable { .. } | Operation::CloseTable { .. }
            | Operation::Deposit { .. } => Vec::new(),
            Operation::WithdrawRequest { spend, .. } => vec![spend],
            Operation::Transfer { spends, .. } | Operation::BuyIn { spends, .. } => {
                spends.iter().collect()
            }
            Operation::Settle(record) => {
                record.inputs.iter().map(|i| &i.spend).collect()
            }
            // v2 变体：MigrateNote 授权走 SignatureEnvelope（非 SpendAuth）；
            // SettleV2 只收集 v1 输入臂的 SpendAuth（v2 输入是 SignatureEnvelope，
            // 验证在 note_v2::settle_spend_verifier_v2）。
            // TE-M2：DepositV2 是 operator 托管路径（同 v1 Deposit，无
            // SpendAuth）；WithdrawRequestV2 授权走 SignatureEnvelope
            // （owner_v2 验签在 sequencer apply 内全量执行）——两者
            // spends() 均为空。
            Operation::MigrateNote(_) => Vec::new(),
            Operation::SettleV2(record) => record
                .inputs
                .iter()
                .filter_map(|i| match i {
                    crate::note_v2::SettleInputV2::V1 { spend, .. } => Some(spend),
                    crate::note_v2::SettleInputV2::V2 { .. } => None,
                })
                .collect(),
            Operation::DepositV2(_) => Vec::new(),
            Operation::WithdrawRequestV2(_) => Vec::new(),
            // TE-M3：三变体均无 SpendAuth——RegisterGameToken / IssueGameToken
            // 是 operator 帧（同 Deposit 纪律）；BurnGameToken 授权走
            // SignatureEnvelope（owner_v2 验签在 sequencer apply 内全量执行，
            // 同 WithdrawRequestV2 纪律）。
            Operation::RegisterGameToken(_) => Vec::new(),
            Operation::IssueGameToken(_) => Vec::new(),
            Operation::BurnGameToken(_) => Vec::new(),
            // TE-M6：三变体均无 SpendAuth——FaucetMint（无外部支付）、
            // BuyGasCredits（watcher 确认 operator 帧）、BindGasPolicy
            // （operator 桌配置帧，同 OpenTable 纪律）。
            Operation::FaucetMint(_) => Vec::new(),
            Operation::BuyGasCredits(_) => Vec::new(),
            Operation::BindGasPolicy(_) => Vec::new(),
        }
    }

    /// 效果摘要：绑定本操作**除签名外的全部语义载荷**（收款人、金额、桌、
    /// 幂等键、结算分配），纳入每个花费授权的签名摘要（审计 S1 修复）。
    ///
    /// 无花费授权的操作（operator 帧）返回零摘要（不参与签名）。
    #[must_use]
    pub fn effect_digest(&self) -> [u8; 32] {
        match self {
            Operation::OpenTable { .. } | Operation::CloseTable { .. }
            | Operation::Deposit { .. } => [0u8; 32],
            // 审计 P1 修复：效果摘要绑定 payout_recipient（与 v2 绑定
            // external_recipient 同纪律）——同一签名授权不能被挪到另一个
            // 收款地址（换地址必摘要失配 → BadSignature）。
            Operation::WithdrawRequest { request_id, payout_recipient, .. } => {
                crate::keys::blake2s32(&[
                    b"effect.withdraw.v1",
                    request_id,
                    payout_recipient,
                ])
            }
            Operation::Transfer { outputs, .. } => {
                let bytes =
                    borsh::to_vec(outputs).expect("NoteSpec borsh encoding is infallible");
                crate::keys::blake2s32(&[b"effect.transfer.v1", &bytes])
            }
            Operation::BuyIn {
                table_id, seat_owner, ..
            } => crate::keys::blake2s32(&[
                b"effect.buyin.v1",
                &table_id.to_be_bytes(),
                seat_owner,
            ]),
            Operation::Settle(record) => {
                // 结算效果 = 结算绑定（覆盖 pot、分配、全部输出）
                let binding = crate::settlement::settlement_binding(record);
                crate::keys::blake2s32(&[
                    b"effect.settle.v1",
                    &crate::felt::felt_to_bytes32(&binding),
                ])
            }
            // v2 变体：效果摘要绑定全部语义载荷（与 v1 审计 S1 同纪律）。
            // MigrateNote 无 SpendAuth，摘要不被签名消费，但保持确定性可审计。
            Operation::MigrateNote(op) => {
                let record_bytes =
                    borsh::to_vec(&op.record).expect("MigrateNoteRecord borsh is infallible");
                let minted_bytes =
                    borsh::to_vec(&op.minted).expect("NoteV2 borsh is infallible");
                crate::keys::blake2s32(&[b"effect.migrate_note.v2", &record_bytes, &minted_bytes])
            }
            Operation::SettleV2(record) => crate::keys::blake2s32(&[
                b"effect.settle_v2.v1",
                &crate::note_v2::settle_effect_v2(record),
            ]),
            // TE-M2 变体：DepositV2 是 operator 帧（同 v1 Deposit——无花费
            // 授权，返回零摘要，不参与签名）。
            Operation::DepositV2(_) => [0u8; 32],
            // TE-M2：WithdrawRequestV2 效果摘要绑定除验签证据（信封摘要/
            // 签名字节/呈递材料）外的全部语义载荷——request_id、asset_id、
            // gross_amount、external_recipient、created_at_ms、被销毁 note
            // 承诺（承诺本身覆盖 note 全字段）。该摘要是 owner 信封签名
            // 消费的 effect 输入（经 v2_spend_digest），任何载荷篡改必然
            // 摘要失配（与 v1 审计 S1 同纪律）。
            Operation::WithdrawRequestV2(op) => crate::keys::blake2s32(&[
                b"effect.withdraw_v2.v2",
                &op.request_id,
                &borsh::to_vec(&op.asset_id).expect("AssetId borsh encoding is infallible"),
                &op.gross_amount.to_be_bytes(),
                &op.external_recipient,
                &op.created_at_ms.to_be_bytes(),
                &op.note.commitment_bytes(),
            ]),
            // TE-M3 变体：RegisterGameToken / IssueGameToken 是 operator 帧
            // （同 v1 Deposit / DepositV2——无花费授权，返回零摘要，不参与
            // 签名；幂等键与载荷核对在 sequencer 准入执行）。
            Operation::RegisterGameToken(_) => [0u8; 32],
            Operation::IssueGameToken(_) => [0u8; 32],
            // TE-M3：BurnGameToken 效果摘要绑定除验签证据外的全部语义载荷
            // ——burn_id、token_id、被销毁 note 承诺、nullifier（镜像
            // WithdrawRequestV2 纪律）。该摘要是 owner 信封签名消费的 effect
            // 输入（经 v2_spend_digest + BURN_GAME scope），任何载荷篡改必然
            // 摘要失配。
            Operation::BurnGameToken(op) => crate::keys::blake2s32(&[
                b"effect.burn_game.v2",
                &op.burn_id,
                &op.token_id.to_be_bytes(),
                &op.note.commitment_bytes(),
                &op.nullifier,
            ]),
            // TE-M6 变体：FaucetMint / BuyGasCredits / BindGasPolicy 均为
            // operator 帧（同 v1 Deposit / DepositV2 / RegisterGameToken
            // ——无花费授权，返回零摘要，不参与签名；幂等键 claim_id/
            // pay_digest 与载荷核对在 sequencer 准入执行）。
            Operation::FaucetMint(_) => [0u8; 32],
            Operation::BuyGasCredits(_) => [0u8; 32],
            Operation::BindGasPolicy(_) => [0u8; 32],
        }
    }
}

/// 花费 scope 标签（防跨操作重放：同一 note 在不同操作类型下摘要不同）。
pub mod scope {
    /// 出金销毁 scope。
    pub const WITHDRAW: &[u8] = b"withdraw.v1";
    /// 转账 scope。
    pub const TRANSFER: &[u8] = b"transfer.v1";
    /// 买入 scope。
    pub const BUYIN: &[u8] = b"buyin.v1";
    /// TE-M2：v2 多币种提现 scope 标签（判别值冻结）——不直接使用，
    /// 必须经 [`crate::note_v2::spend_scope`] 绑定 network_id + abi_version
    /// 后作为 v2 花费 scope（防跨网/跨版重放，ABI_V2.md 冻结纪律）。
    pub const WITHDRAW_V2: &[u8] = b"withdraw.v2";
    /// TE-M3：GAME 币销毁 scope 标签（判别值冻结）——不直接使用，必须经
    /// [`crate::note_v2::spend_scope`] 绑定 network_id + abi_version 后作为
    /// v2 花费 scope（与 WITHDRAW_V2 域分离：同一 note 的提现授权不能被
    /// 重放进销毁，反之亦然）。
    pub const BURN_GAME: &[u8] = b"burn_game.v2";
}
