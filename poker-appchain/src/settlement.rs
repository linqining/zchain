//! M2：结算关系 `SettleNotes`。
//!
//! 一手牌的结算 = 消费 N 个 seat note → 产出赔付 note + rake 分账 note。
//! 本模块定义 witness/record 的 ABI 形状与 **纯函数校验**（守恒 + 费率 +
//! 分账 + P 层签名覆盖 + 非零标识 + **已验证状态派生的结算计划**），是
//! 后续 AIR 关系（stwo 约束）的语义规范与 host 侧 admission 层。
//!
//! ## ABI v1.2（plan-appchain §5.2-1/2/7，P0-1/P0-2/P0-7）
//!
//! - `SettlementRecord` 追加 `plan: SettlementPlan`（borsh 尾缀字段，
//!   `poker-settlement-core` 类型——**结算语义唯一事实源**，VM/appchain/
//!   verifier 共用）。pot 不再是独立可信输入：它必须与已验证计划
//!   `plan.gross_pot` 一致，手牌证明绑定存在时还必须与**已证明终态
//!   状态镜像中的 pot 字段**逐字节一致；
//! - `NoteSpec` 追加 `pot_index`/`runout_index`（非结算输出恒 0）；
//! - `settlement_binding` 前影追加 `plan_digest`、`payout_root`、
//!   `side_pot_root`（32B hi/lo 无损拆分）；
//! - `settle_effect`（纳入每个花费授权签名）追加 `payout_root`——玩家
//!   签名覆盖**精确赔付结构**（asset/amount/owner/table/pot/runout 全绑定，
//!   不再"只签 owner 和金额"）；
//! - `TexasArchiveScope` 迁移到 canonical 归档布局（镜像
//!   `poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof`
//!   的公开字段序，borsh 逐字段一致）；
//! - `HandProofBinding` 追加 `pre_state_root`/`post_state_root` 声明字段。
//!
//! ## fail-closed 校验面（拒绝路径全清单，顺序即实现）
//!
//! 1. `hand_binding` 非零；inputs 非空
//! 2. `plan.validate(inputs.len())` 通过（版本/边界/守恒/runout 投影）
//! 3. `plan.gross_pot == record.pot`
//! 4. 每个 input：table_id 一致、同类、承诺匹配、nullifier 非零；
//!    `Σinputs == plan.gross_pot`（seat note 即本手下注贡献）
//! 5. 输出同类、非零；每个 payout 的 `table_id` 为 None 或
//!    `Some(record.table_id)`
//! 6. payouts 与 `plan` 投影**一一对应**：声明顺序给出 owner↔seat 映射
//!    （k-th payout ↔ 第 k 个 (pot_index, runout_index, seat) 规范序三元组），
//!    `(pot_index, runout_index, amount)` 必须与三元组一致（索引越界即
//!    投影不符）、owner↔seat 一一对应，且按 owner 聚合 == `plan.awards`
//! 7. P 层签名：owner 对（scope + 结算效果摘要）签名；效果摘要含
//!    `payout_root` → 篡改赔付结构必然签名失败
//! 8. `record.rake.total == plan.rake == policy.rake_of(plan.rake_base())`
//!    （v1.2.2/B9：rake 计费基数 = **contested 层 gross 之和**——eligible ≥ 2
//!    座的层；uncalled 返还层不计费，`plan.validate` 已强制其 rake == 0。
//!    与 poker_l1 canonical 的 contested-only 计费同口径）；
//!    `policy_commitment == policy.commitment_bytes()`
//! 9. 守恒：`Σinputs == Σoutputs`
//! 10. 分账：treasury/operator 数额与收款人 == `policy.split_of(rake.total)`
//! 11. 手牌证明绑定（可选，scope 级 fail-closed）：归档 scope（canonical
//!     布局）满足 table_id 一致、终态承诺/前后状态根与声明一致、非空批；
//!     **gross_pot 逐字节绑定**——解析 `post_state_image_bytes` 中
//!     `pot`（偏移 74，8B LE）断言其值 == `record.pot`；归档含 rake
//!     opening 时断言 `record.rake.total` == `min(floor(pot·bps/10⁴), cap, pot)`
//!     （与 poker_texas_air `canonical_settlement_rake` 同式；mode 0 → 0）。
//!     **完整 STARK 验证**由 `poker-appchain-texasair` 适配器执行。
//! 12. REAL 出证策略门（P0-3，本 crate 外的引擎/管道层强制，判定输入为本
//!     模块的 [`settlement_input_class`]）：REAL 类结算不得由 host 签名
//!     引擎出证（`RealRequiresStarkProof`）；生产模式（StarkRequired）下
//!     证明必须来自 texas-air-* STARK 引擎且 attestor 钉扎到固定 verifier
//!     key（`VerifierKeyMismatch`）。清单见 `real_policy` 模块文档。
//!
//! ## ABI v1.3：hand_binding 升域 + 洗牌/发牌 deck 链消费（设计文档
//! `docs/shuffle-deal-proof-design.md` §5-C2/C3，路线 A/B 消费半边）
//!
//! - **11a. hand_binding 升域判定**（每次手牌证明绑定校验内强制）：
//!   `record.hand_binding` 对归档 scope 分类为
//!   [`HandBindingFormat::HandBindingV2`]（= [`hand_binding_v2`] 重导值，
//!   Poseidon 折叠 `zchain.settlement.binding.v2` 域，覆盖
//!   `batch_digest + deck_chain_digest + reveal_commitment`）/
//!   [`HandBindingFormat::LegacyBatchDigest`]（= `scope.batch_digest`，
//!   v1 e2e 形态）/ [`HandBindingFormat::Unbound`]（与归档无关系）。
//!   v2 → 追加 11b 全链强制；Legacy/Unbound → **迁移期接受并计数**
//!   （`legacy_binding_accept_count`/`unbound_binding_accept_count`，
//!   ABI v2 双轨迁移纪律先例）；`full_chain_enforcement()` 置 true
//!   （迁移窗关闭）后 Legacy/Unbound 一律拒绝。
//! - **11b. v2 全链 fail-closed 强制**（仅 v2 格式记录）：首转移 kind ∈
//!   [`FULL_CHAIN_FIRST_KINDS`]、末 kind ∈ [`SETTLEMENT_TERMINAL_KINDS`]、
//!   `blind_opening` 存在且形状合法、pre/post 镜像 `deck_commitment`
//!   非零（S1 锚）、终态 `reveal_commitment` 非零（发牌覆盖）。
//! - **11b-f. REAL × 协议行 fail-closed（阶段 0 负面发现的链侧执行）**：
//!   上游 stage0 实测——canonical AIR **无法察觉非末段 shuffle 行 deck
//!   承诺篡改**（AIR 只冻结锚、不重算密文哈希；篡改批照样出证，见
//!   SHUFFLE_STAGE0.md §3.4 负例 2）。因此凡归档含协议行
//!   （[`archive_has_protocol_rows`]）的 **REAL 类**结算，必须持有一
//!   已通过的路线 A 原生校验（引擎侧 BG/DLEq 逐行验证 + 承诺链重导）；
//!   该验证结果在结算层**不可自证**（纯函数无密码学面），故本层直接
//!   fail-closed 拒绝该批——引擎侧 receipt 归责（路线 B，attestation
//!   v2.2）接线后此处升级为"要求回执集验证"。PLAY 类不受此条约束
//!   （娱乐筹码不构成 REAL 出证对象）。
//! - **11c. 路线 B receipt 门**（默认关）：`crypto_receipt_enforcement()`
//!   开启时，v2 记录**显式拒绝**（"引擎侧 BG/DLEq receipt 集成未接线"）
//!   ——本 crate 提供 [`CryptoVerifierReceipt`] / [`verify_receipt_set`] /
//!   [`expected_crypto_statements`] 占位校验结构（**覆盖记账**，不做任何
//!   密码学方程验证），引擎接线前开启开关即 fail-closed，**不许假验证**。
//!   上游 stage0（2026-09-12）已冻结 receipt ABI
//!   （`ShuffleChainReceipt.engine_receipt_digest`，见结构文档）——剩余
//!   待接线的是**本仓引擎侧**（poker-appchain-texasair C1）。
//!
//! ## TE-M4：FixedRakeBurn 桌（GAME 桌销毁计费）的 v1/v2 边界
//!
//! `FeePolicy::FixedRakeBurn`（判别值 2，TE-E0 冻结）桌的 rake 处置是
//! **销毁**（不是 treasury/operator 分账）：rake 份额从赢家应付中扣除后
//! 直接销毁，`game_burned` 计数、`game_outstanding` 收缩。两侧落点：
//!
//! - **v1 路径拒绝**（fail-closed，见 [`validate_settlement`] 第 0 条）：
//!   GAME 币是 v2 账本资产，v1 rake 输出表示无法表达 GAME 注册 token，
//!   且 v1 分账路径会把销毁误当分账入账；
//! - **v2 路径放行**（`note_v2::validate_settlement_v2` + sequencer
//!   `apply_settle_v2`）：rake 不产生输出 note，守恒式为
//!   `Σinputs == Σpayouts + rake.total`（rake.total 是已销毁的输出侧），
//!   应用时 `game_burned[token] += rake.total`；
//! - 计价数量关系与 `FixedRake` 完全同式（`rake_of` / plan 同式，TE-E0
//!   已冻结），本文件对 mode 2 无任何计价特判——只有处置特判。

use starknet_crypto::{poseidon_hash_many, FieldElement};

use poker_settlement_core::{side_pot_root, PayoutLeaf, SettlementPlan};

// 结算计划类型再导出：`SettlementRecord.plan` 的公开字段类型必须可命名。
pub use poker_settlement_core::SettlementPlan as Plan;

use crate::error::{AppchainError, AppchainResult};
use crate::fee::FeePolicy;
use crate::felt::{
    bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32,
    DOMAIN_SETTLEMENT_BINDING,
};
use crate::keys::{spend_digest, verify_ecsdsa, EcdsaSig};
use crate::note::{AssetClass, Note, NoteSpec};

/// 花费授权：owner 对 (commitment, nullifier, scope) 的 P 层签名。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SpendAuth {
    /// 被消费 note 的承诺（32B 规范编码）。
    pub commitment: [u8; 32],
    /// owner 派生的 nullifier（32B 规范编码）。
    pub nullifier: [u8; 32],
    /// owner ECDSA 签名。
    pub sig: EcdsaSig,
}

/// 结算输入：被消费的 seat note（完整 note，账本层有据可查）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SettleInput {
    /// seat note（table_id 必须等于记录的 table_id）。
    pub note: Note,
    /// 花费授权（owner 签名）。
    pub spend: SpendAuth,
}

/// rake 分账记录。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RakeSplitRecord {
    /// 抽取总额。
    pub total: u64,
    /// treasury 输出（数额由校验器重导出，非信任字段）。
    pub treasury_out: Option<NoteSpec>,
    /// operator 输出。
    pub operator_out: Option<NoteSpec>,
}

/// 结算记录（SettleNotes witness，AIR 形状就绪）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct SettlementRecord {
    /// 桌 ID。
    pub table_id: u64,
    /// 手绑定（防重放；沿用 DAPV §6 语义，非零）。
    pub hand_binding: [u8; 32],
    /// 策略承诺（桌绑定策略的承诺字节）。
    pub policy_commitment: [u8; 32],
    /// 本手底池（rake 计费基数；v1.2 起必须与 `plan.gross_pot` 一致）。
    pub pot: u64,
    /// 输入 seat notes（≥1；v1.2 起其总额必须等于 `plan.gross_pot`）。
    pub inputs: Vec<SettleInput>,
    /// 赔付输出（v1.2：与 `plan` 投影一一对应，含 pot/runout 索引）。
    pub payouts: Vec<NoteSpec>,
    /// rake 分账。
    pub rake: RakeSplitRecord,
    /// 已验证的结算计划（v1.2 追加字段——`poker-settlement-core`
    /// [`SettlementPlan`]，pot 从已验证计划状态派生，plan-appchain §5.2-2）。
    pub plan: SettlementPlan,
    /// 手牌批次证明绑定（B1/B2 接入缝，可选；borsh 追加字段——
    /// v1.1 引入，v1.2 扩展 HandProofBinding 自身字段）。
    pub hand_proof: Option<HandProofBinding>,
}

/// plan 摘要（32B，域 `zchain.texas_poker.settlement_plan.v2`）。校验后的
/// plan 摘要实际不可失败（borsh 定形 + 定长 blake2b）；`expect` 仅钉住该
/// 不变量。公开导出供 texas-air 适配器的 attestation v2.1（覆盖已验证结算
/// 计划摘要）与 REAL 出证策略层使用。
///
/// # Panics
/// 仅当 plan 编码/摘要内部失败（内存内构形 plan 不会发生）。
#[must_use]
pub fn plan_digest_bytes(plan: &SettlementPlan) -> [u8; 32] {
    plan.digest()
        .expect("settlement plan digest is infallible for in-memory plans")
}

/// 结算资产类（单类语义：首个输入的资产类即全类；空输入返回 None——
/// 该记录由 [`validate_settlement`] 的非空检查独立拒绝）。供 REAL 出证
/// 策略门（`real_policy`/引擎/管道层）判定使用。
#[must_use]
pub fn settlement_input_class(record: &SettlementRecord) -> Option<AssetClass> {
    record.inputs.first().map(|i| i.note.asset_class)
}

/// 结算赔付 → payout_root 叶子集合（plan-appchain §5.2-7：完整绑定）。
fn payout_leaves(record: &SettlementRecord) -> Vec<PayoutLeaf> {
    record
        .payouts
        .iter()
        .map(|o| PayoutLeaf {
            asset_class: o.asset_class.as_u8(),
            amount: o.amount,
            owner: o.owner,
            table_id: record.table_id,
            pot_index: o.pot_index,
            runout_index: o.runout_index,
        })
        .collect()
}

/// 赔付根：`poker_settlement_core::payout_root`（blake2b + RFC 6962 域分离，
/// 域 `zchain.settlement.payout_root.v1`；算法见 crate 文档）。
#[must_use]
pub fn payout_root_bytes(record: &SettlementRecord) -> [u8; 32] {
    poker_settlement_core::payout_root(&payout_leaves(record))
}

/// 结算绑定摘要：`poseidon(DOMAIN, table, hand_binding, policy, pot,
/// Σinputs commitments, Σoutputs (owner,amount), rake,
/// plan_digest, payout_root, side_pot_root)`。
///
/// AIR transcript 绑定的 host 侧对应物；任何字段篡改都改变摘要，
/// 从而改变签名判据。32B 字段一律 hi/lo 无损拆分。
#[must_use]
pub fn settlement_binding(record: &SettlementRecord) -> FieldElement {
    let push32 = |parts: &mut Vec<FieldElement>, b: &[u8; 32]| {
        let (hi, lo) = bytes32_to_felts(b);
        parts.push(hi);
        parts.push(lo);
    };
    let mut parts = vec![domain_felt(DOMAIN_SETTLEMENT_BINDING)];
    parts.push(felt_from_u64(record.table_id));
    push32(&mut parts, &record.hand_binding);
    push32(&mut parts, &record.policy_commitment);
    parts.push(felt_from_u64(record.pot));
    for i in &record.inputs {
        push32(&mut parts, &i.spend.commitment);
        push32(&mut parts, &i.spend.nullifier);
    }
    for o in &record.payouts {
        let (x, y) = crate::keys::public_xy_bytes_from_compressed(&o.owner);
        let (x_hi, x_lo) = bytes32_to_felts(&x);
        let (y_hi, y_lo) = bytes32_to_felts(&y);
        parts.push(x_hi);
        parts.push(x_lo);
        parts.push(y_hi);
        parts.push(y_lo);
        parts.push(felt_from_u64(o.amount));
    }
    parts.push(felt_from_u64(record.rake.total));
    // v1.2：三个结算结构根（计划摘要 / 赔付根 / 分层根），hi/lo 拆分。
    for root in [
        plan_digest_bytes(&record.plan),
        payout_root_bytes(record),
        side_pot_root(&record.plan),
    ] {
        let (hi, lo) = bytes32_to_felts(&root);
        parts.push(hi);
        parts.push(lo);
    }
    poseidon_hash_many(&parts)
}

/// 构造单个输入 note 的花费签名摘要（scope = 结算域 + hand_binding）。
#[must_use]
pub fn settle_spend_scope(hand_binding: &[u8; 32]) -> Vec<u8> {
    let mut scope = Vec::with_capacity(DOMAIN_SETTLEMENT_BINDING.len() + 32);
    scope.extend_from_slice(DOMAIN_SETTLEMENT_BINDING);
    scope.extend_from_slice(hand_binding);
    scope
}

/// 结算效果摘要（S1 + P0-7）：覆盖 hand_binding、pot、全部输入承诺、全部
/// 输出（owner, amount）、rake.total 与 **payout_root**（精确赔付结构：
/// asset/owner/amount/table/pot/runout 全绑定）。纳入每个 settle 花费授权
/// 签名——玩家签名不再"只签 owner 和金额"。**不含** policy_commitment
/// （策略由注册表冻结检查强制）与 plan 细节（plan 由校验器对 pot/payouts
/// 投影一致性强制的，且 plan_digest 已入 `settlement_binding`）。
#[must_use]
pub fn settle_effect(record: &SettlementRecord) -> [u8; 32] {
    let mut h_input = Vec::with_capacity(record.inputs.len() * 64);
    let mut h_output = Vec::with_capacity(record.payouts.len() * 64);
    for i in &record.inputs {
        h_input.extend_from_slice(&i.spend.commitment);
    }
    for o in &record.payouts {
        h_output.extend_from_slice(&o.owner);
        h_output.extend_from_slice(&o.amount.to_be_bytes());
    }
    crate::keys::blake2s32(&[
        b"poker-appchain.settle.effect.v1",
        &record.hand_binding,
        &record.pot.to_be_bytes(),
        &h_input,
        &h_output,
        &record.rake.total.to_be_bytes(),
        &payout_root_bytes(record),
    ])
}

/// canonical 状态镜像每座位字节数与座位容量（poker_texas_air
/// `MAX_CANONICAL_SEATS = 9`，`CanonicalStateImage` v5 定宽 borsh ABI）。
pub const MAX_CANONICAL_SEATS: usize = 9;

/// canonical 状态镜像 borsh 编码总长（v5 ABI，1,680 字节）。
pub const CANONICAL_STATE_IMAGE_BORSH_BYTES: usize = 1_680;
/// 状态镜像中 `chip_pool: u64`（LE）的字节偏移（poker_texas_air
/// `STATE_IMAGE_CHIP_POOL_OFFSET`）。
pub const STATE_IMAGE_CHIP_POOL_OFFSET: usize = 66;
/// 状态镜像中 `pot: u64`（LE）的字节偏移（poker_texas_air
/// `STATE_IMAGE_POT_OFFSET`）。
pub const STATE_IMAGE_POT_OFFSET: usize = 74;

/// 从状态镜像字节读取定宽 u64（LE）。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
fn state_image_u64(image: &[u8], offset: usize) -> AppchainResult<u64> {
    if image.len() < offset + 8 {
        return Err(AppchainError::AdmissionRejected("state image truncated"));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&image[offset..offset + 8]);
    Ok(u64::from_le_bytes(bytes))
}

// ===== 洗牌/发牌证明链消费侧（ABI v1.3）=====
//
// 以下偏移/判别值镜像 `poker_texas_air`（path 依赖，本 crate 刻意不依赖
// 它——lockfile 隔离）的冻结 ABI：
// - 状态镜像偏移按 `CanonicalStateImage`（v5 定宽 borsh）字段序推导，与
//   既有锚点 `chip_pool`@66 / `pot`@74 互证（board_cards_commitment 之前
//   的全部字段均为定宽标量，偏移不受 enum 编码影响）；
// - 转移选择子判别值 = `CanonicalTransitionKind`（`#[repr(u8)]`，
//   `borsh(use_discriminant)`，29 选择子）。
// 真实归档逐字段钉扎属适配器测试职责（poker-appchain-texasair，
// 排队清单见 poker-appchain/docs/SHUFFLE_CONSUME.md）。

/// 状态镜像 `board_cards_commitment: [u8; 32]` 偏移（CanonicalStateImage v5）。
pub const STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET: usize = 90;
/// 状态镜像 `deck_commitment: [u8; 32]` 偏移——**牌序（加密形态）进入
/// 状态镜像的唯一入口**（S1 锚，canonical AIR 冻结字段）。
pub const STATE_IMAGE_DECK_COMMITMENT_OFFSET: usize = 122;
/// 状态镜像 `reveal_commitment: [u8; 32]` 偏移（SubmitReveal 行
/// `proof_commitment == post.reveal_commitment` 的镜像侧锚）。
pub const STATE_IMAGE_REVEAL_COMMITMENT_OFFSET: usize = 154;
/// 状态镜像 `reconstruction_commitment: [u8; 32]` 偏移（暂只消费存在性，
/// 无强制——重构为可选协议路径）。
pub const STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET: usize = 186;

/// canonical 转移选择子：`JoinTable`（入座）。
pub const KIND_JOIN_TABLE: u8 = 1;
/// canonical 转移选择子：`StartHand`（发牌入场，hand-start 镜像）。
pub const KIND_START_HAND: u8 = 3;
/// canonical 转移选择子：`SubmitShuffle`（BG 洗牌证明行）。
pub const KIND_SUBMIT_SHUFFLE: u8 = 7;
/// canonical 转移选择子：`SubmitReveal`（reveal token DLEq 行）。
pub const KIND_SUBMIT_REVEAL: u8 = 8;
/// canonical 转移选择子：`SubmitReconstruct`（重构 V3 行）。
pub const KIND_SUBMIT_RECONSTRUCT: u8 = 9;
/// canonical 转移选择子：`Raise`（加注——负例矩阵用的非链入口 kind）。
pub const KIND_RAISE: u8 = 13;
/// canonical 转移选择子：`AdvanceRound`（本街注码收池微步）。
pub const KIND_ADVANCE_ROUND: u8 = 19;
/// canonical 转移选择子：`AutoFold`（超时弃牌——非收池，非结算语义）。
pub const KIND_AUTO_FOLD: u8 = 20;
/// canonical 转移选择子：`EndWithoutShowdown`（最后存活者零 rake 终局）。
pub const KIND_END_WITHOUT_SHOWDOWN: u8 = 21;
/// canonical 转移选择子：`RevealTimeoutAward`（超时独存者零 rake 终局）。
pub const KIND_REVEAL_TIMEOUT_AWARD: u8 = 27;
/// canonical 转移选择子：`RevealTimeoutRakedAward`（超时独存者带 rake 终局）。
pub const KIND_REVEAL_TIMEOUT_RAKED_AWARD: u8 = 28;

/// v2 全链批**准入首 kind 集**（设计文档 §5-C2 字面集：
/// {JoinTable, StartHand, SubmitShuffle}；阶段 0 单批/两段实测结论出来前
/// 冻结为此集，不预设放宽——见 SHUFFLE_CONSUME.md 排队清单）。
pub const FULL_CHAIN_FIRST_KINDS: [u8; 3] =
    [KIND_JOIN_TABLE, KIND_START_HAND, KIND_SUBMIT_SHUFFLE];

/// **结算语义末 kind 集**：批末行必须把注码收进 pot 或直接终局分派。
/// canonical AIR 无独立 showdown 结算行（v1 证明段以 `AdvanceRound`
/// 收池收尾）；超时终局走 21/27/28。`ResetOnly`(22)/`AutoFold`(20) 等
/// 零注码/非收池行不在集内（结算记录要求 pot = Σinputs > 0）。
pub const SETTLEMENT_TERMINAL_KINDS: [u8; 4] = [
    KIND_ADVANCE_ROUND,
    KIND_END_WITHOUT_SHOWDOWN,
    KIND_REVEAL_TIMEOUT_AWARD,
    KIND_REVEAL_TIMEOUT_RAKED_AWARD,
];

/// 从状态镜像字节读取定宽 32B 承诺。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
fn state_image_commitment32(
    image: &[u8],
    offset: usize,
) -> AppchainResult<[u8; 32]> {
    if image.len() < offset + 32 {
        return Err(AppchainError::AdmissionRejected("state image truncated"));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&image[offset..offset + 32]);
    Ok(bytes)
}

/// 归档 scope 的 deck/reveal 链锚（路线 A 消费半边的输入面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeckChainAnchors {
    /// 起始帧 `deck_commitment`（批首状态镜像，S1 锚）。
    pub pre_deck_commitment: [u8; 32],
    /// 终态帧 `deck_commitment`（结算 hand 必须续自该锚）。
    pub post_deck_commitment: [u8; 32],
    /// 终态帧 `reveal_commitment`（发牌揭示账本锚）。
    pub post_reveal_commitment: [u8; 32],
    /// 终态帧 `reconstruction_commitment`（存在性消费，暂无强制）。
    pub post_reconstruction_commitment: [u8; 32],
}

impl DeckChainAnchors {
    /// 消费侧 deck 承诺链：去重 consecutive 的 `[pre, post]`——相等
    /// （betting 段批，批内无洗牌）→ 单元素链；不等（批内含洗牌段）→
    /// 双元素链。长度恒 ≤ 2，[`poker_settlement_core::deck_chain_digest`]
    /// 的 `None` 分支在此不可达（`expect` 仅钉住该不变量）。
    #[must_use]
    pub fn chain(&self) -> Vec<[u8; 32]> {
        if self.pre_deck_commitment == self.post_deck_commitment {
            vec![self.post_deck_commitment]
        } else {
            vec![self.pre_deck_commitment, self.post_deck_commitment]
        }
    }
}

/// 归档 scope → deck/reveal 链锚（pre/post 状态镜像定宽偏移读取）。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
pub fn deck_chain_anchors(scope: &TexasArchiveScope) -> AppchainResult<DeckChainAnchors> {
    Ok(DeckChainAnchors {
        pre_deck_commitment: state_image_commitment32(
            &scope.pre_state_image_bytes,
            STATE_IMAGE_DECK_COMMITMENT_OFFSET,
        )?,
        post_deck_commitment: state_image_commitment32(
            &scope.post_state_image_bytes,
            STATE_IMAGE_DECK_COMMITMENT_OFFSET,
        )?,
        post_reveal_commitment: state_image_commitment32(
            &scope.post_state_image_bytes,
            STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
        )?,
        post_reconstruction_commitment: state_image_commitment32(
            &scope.post_state_image_bytes,
            STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET,
        )?,
    })
}

/// hand_binding v2 域标签（ABI v1.3 升域，设计文档 §5-C3 冻结：
/// `zchain.settlement.binding.v2`；与 v1 的
/// `poker-appchain.settlement.binding.v1`（花费 scope 域）不同层、不同名）。
pub const DOMAIN_HAND_BINDING_V2: &[u8] = b"zchain.settlement.binding.v2";

/// hand_binding v2 值（从归档 scope 重导）：**域分离 Poseidon 折叠**
///
/// ```text
/// hand_binding_v2 = felt32(poseidon_hash_many(
///     domain_felt(zchain.settlement.binding.v2),
///     hi/lo(scope.batch_digest),
///     hi/lo(deck_chain_digest([pre.deck, post.deck] 去重 consecutive)),
///     hi/lo(post.reveal_commitment),
/// ))
/// ```
///
/// 与上游 `hand_binding.rs` 的 Poseidon 布局**子集对齐**（zchain 消费侧
/// 折影子集：不含 players/settlement_digest——上游全量对齐属 §6-Q3 决策
/// 点，见 SHUFFLE_CONSUME.md）。三个数据输入全部重导自归档 scope：
/// 记录声明 v2 绑定即**绑定到该归档的 deck 承诺链**——跨手拼装/换锚
/// 必然失配（`HandBindingFormat::Unbound`，迁移窗关闭后拒绝）。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
pub fn hand_binding_v2(scope: &TexasArchiveScope) -> AppchainResult<[u8; 32]> {
    let anchors = deck_chain_anchors(scope)?;
    let deck_chain_digest = poker_settlement_core::deck_chain_digest(&anchors.chain())
        .expect("consecutive-dedup [pre, post] chain length is 1 or 2, within DECK_CHAIN_MAX");
    let mut parts = Vec::with_capacity(7);
    parts.push(domain_felt(DOMAIN_HAND_BINDING_V2));
    for bytes in [&scope.batch_digest, &deck_chain_digest, &anchors.post_reveal_commitment] {
        let (hi, lo) = bytes32_to_felts(bytes);
        parts.push(hi);
        parts.push(lo);
    }
    Ok(felt_to_bytes32(&poseidon_hash_many(&parts)))
}

/// `record.hand_binding` 对归档 scope 的格式分类（11a 判定输入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandBindingFormat {
    /// v2 deck 链绑定（= [`hand_binding_v2`] 重导值）——追加全链强制。
    HandBindingV2,
    /// v1 e2e 形态（= `scope.batch_digest`）——迁移期接受并计数。
    LegacyBatchDigest,
    /// 与归档无关系——迁移期接受并计数；迁移窗关闭后拒绝。
    Unbound,
}

/// 分类 `record.hand_binding`（v2 优先；先 batch_digest 后 Unbound）。
///
/// # Errors
/// 镜像截断（v2 重导需要读镜像偏移）→ [`AppchainError::AdmissionRejected`]。
pub fn classify_hand_binding(
    record: &SettlementRecord,
    scope: &TexasArchiveScope,
) -> AppchainResult<HandBindingFormat> {
    if record.hand_binding == hand_binding_v2(scope)? {
        Ok(HandBindingFormat::HandBindingV2)
    } else if record.hand_binding == scope.batch_digest {
        Ok(HandBindingFormat::LegacyBatchDigest)
    } else {
        Ok(HandBindingFormat::Unbound)
    }
}

// ===== 迁移窗 / receipt 门（进程级 fail-closed 开关，默认全关）=====
//
// validate_settlement 是纯函数，开关为进程级原子量（单进程 appchain/
// 验证引擎各持语义）。默认值保证既有 v1 流量零回退（双轨迁移期）。

static FULL_CHAIN_ENFORCEMENT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static CRYPTO_RECEIPT_ENFORCEMENT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static LEGACY_BINDING_ACCEPTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static UNBOUND_BINDING_ACCEPTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// 关闭 hand_binding 迁移窗：置 true 后，手牌证明绑定存在但
/// `hand_binding` 既非 v2 deck 链绑定也非归档 batch_digest 的记录
/// 一律拒绝（ABI v1.3 单轨化）。
pub fn set_full_chain_enforcement(enabled: bool) {
    FULL_CHAIN_ENFORCEMENT.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// 迁移窗是否已关闭。
#[must_use]
pub fn full_chain_enforcement() -> bool {
    FULL_CHAIN_ENFORCEMENT.load(std::sync::atomic::Ordering::Relaxed)
}

/// 迁移期接受的 Legacy（batch_digest 形态）记录计数（告警口径①）。
#[must_use]
pub fn legacy_binding_accept_count() -> u64 {
    LEGACY_BINDING_ACCEPTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// 迁移期接受的 Unbound（绑定与归档无关系）记录计数（告警口径②）。
#[must_use]
pub fn unbound_binding_accept_count() -> u64 {
    UNBOUND_BINDING_ACCEPTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// 开启路线 B receipt 强制门（默认关）。**语义**：开启后 v2 记录在引擎
/// 侧 BG/DLEq receipt 集成落地（上游 stage0 对齐）前**显式拒绝**——
/// 该门是"忘记接 receipt 就静默放行"的防遗忘互锁，不是验证实现。
pub fn set_crypto_receipt_enforcement(enabled: bool) {
    CRYPTO_RECEIPT_ENFORCEMENT.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// receipt 强制门是否开启。
#[must_use]
pub fn crypto_receipt_enforcement() -> bool {
    CRYPTO_RECEIPT_ENFORCEMENT.load(std::sync::atomic::Ordering::Relaxed)
}

// ===== 路线 B：verifier receipt digest 归责（覆盖记账 + 已冻结上游 ABI）=====
//
// **诚实边界**：BG V2 / reveal token DLEq 的密码学方程验证发生在引擎侧
// （poker-appchain-texasair C1 编排，上游 Plan D 分工）；本模块只冻结
// **语句面 ABI**（什么语句被验证）与**覆盖记账**（每个语句恰有一张
// 回执），不做任何密码学验证。上游 stage0（2026-09-12）已冻结 receipt
// 的**规范构造**（`canonical_shuffle_chain::ShuffleChainReceipt`）：
//
// ```text
// statement_digest = poseidon_bytes_digest(DOMAIN ‖ kind ‖ seat ‖ pre ‖ post)
//                    // kind ∈ {b"shuffle", b"reveal", b"reconstruct"}，逐协议行
// engine_receipt_digest = poseidon_bytes_digest(DOMAIN ‖ b"receipt"
//                    ‖ batch_digest ‖ deck/reveal/reconstruct 三链摘要
//                    ‖ 逐行 statement_digest)      // DOMAIN 同 deck 链域
// ```
//
// `receipt_digest` 字段即承载该 `engine_receipt_digest`（32B，非零）；
// 逐行 statement 级对账需归档携带协议行明细（sidecar vs 扩归档 =
// 设计文档 §6-Q2，仍未决），在此之前 [`verify_receipt_set`] 只能证明
// "覆盖完整"，不能证明"验证为真"。

/// 密码学语句域标签（消费侧语句面，冻结）。
pub const CRYPTO_STATEMENT_DOMAIN: &[u8] = b"zchain.settlement.crypto_statement.v1";
/// 语句类别：Bayer–Groth 洗牌（pre.deck → post.deck 锚续链）。
pub const STATEMENT_KIND_SHUFFLE: &[u8] = b"bg.shuffle.v2";
/// 语句类别：reveal token DLEq（post.deck → reveal 承诺开启）。
pub const STATEMENT_KIND_REVEAL: &[u8] = b"dleq.reveal.v1";

/// 域绑定密码学语句摘要：`blake2b-256(DOMAIN ‖ kind ‖ inputs…)`。
/// 语句面（kind 标签 + 输入锚集）由本模块冻结；上游方法 AIR 的
/// `REQUEST_DIGEST` 口径对齐属 stage0 排队项。
#[must_use]
pub fn crypto_statement_digest(kind_tag: &[u8], inputs: &[[u8; 32]]) -> [u8; 32] {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = Blake2bVar::new(32).expect("32 <= Blake2b maximum output");
    hasher.update(CRYPTO_STATEMENT_DOMAIN);
    hasher.update(kind_tag);
    for input in inputs {
        hasher.update(input);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("32 <= Blake2b maximum output");
    out
}

/// 归档 scope 的**期望语句集**（引擎侧应验证并出回执的语句面）。
///
/// - 批内含洗牌段（pre.deck ≠ post.deck）→ 一条 BG 洗牌语句
///   （pre.deck → post.deck 锚续链）；
/// - 批内含发牌（post.reveal_commitment 非零）→ 一条 reveal DLEq 语句。
///
/// 注：本集合是 scope 级**粗粒度**语句面（每批每类一条）；逐张/逐玩家的
/// 细粒度语句（52 张 reveal token、n 玩家洗牌链）需归档携带协议行明细，
/// 待上游 stage0（SHUFFLE_CONSUME.md 排队清单）。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
pub fn expected_crypto_statements(
    scope: &TexasArchiveScope,
) -> AppchainResult<Vec<[u8; 32]>> {
    let anchors = deck_chain_anchors(scope)?;
    let mut statements = Vec::new();
    if anchors.pre_deck_commitment != anchors.post_deck_commitment {
        statements.push(crypto_statement_digest(
            STATEMENT_KIND_SHUFFLE,
            &[anchors.pre_deck_commitment, anchors.post_deck_commitment],
        ));
    }
    if anchors.post_reveal_commitment != [0u8; 32] {
        statements.push(crypto_statement_digest(
            STATEMENT_KIND_REVEAL,
            &[anchors.post_deck_commitment, anchors.post_reveal_commitment],
        ));
    }
    Ok(statements)
}

/// 引擎签发的验证回执：语句摘要 + 引擎 receipt 摘要。
///
/// `receipt_digest` 规范构造**已由上游 stage0 冻结**（2026-09-12）：
/// = `poker_texas_air::canonical_shuffle_chain::ShuffleChainReceipt::
/// engine_receipt_digest`——poseidon_bytes_digest(DOMAIN ‖ b"receipt"
/// ‖ batch_digest ‖ deck/reveal/reconstruct 三链摘要 ‖ 逐行 statement
/// digest)，域 `zchain.texas.canonical-shuffle-chain.v1`（与本 crate
/// [`poker_settlement_core::DECK_CHAIN_DIGEST_DOMAIN`] 同域同源）。
/// 逐行 statement digest 的消费侧对账仍受 §6-Q2（协议行明细传输形态）
/// 制约，见模块文档。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct CryptoVerifierReceipt {
    /// 被验证语句的摘要（= [`crypto_statement_digest`] 输出；上游逐行
    /// statement_digest 的对齐待 §6-Q2）。
    pub statement_digest: [u8; 32],
    /// 引擎签发的 receipt 摘要（= 上游 `engine_receipt_digest`，域绑定
    /// 可由任何持归档+sidecar 者重放；零值拒绝）。
    pub receipt_digest: [u8; 32],
}

/// receipt 集覆盖记账：每个期望语句**恰有一张**回执，无未知语句、无
/// 重复、`receipt_digest` 非零。检查顺序（诊断精度递减）：回执自身
/// 有效性（零 digest / 未知语句）→ 重复语句 → 数额 → 覆盖完整性。
///
/// **这不是密码学验证**——BG/DLEq 方程验证在引擎侧（C1）；本函数只
/// 保证"该验的都领了回执、没有多余回执"的覆盖关系，供引擎/客户端在
/// stage0 冻结 receipt ABI 后接入完整归责。
///
/// # Errors
/// 零 receipt / 未知语句 / 重复 / 数额不符 / 覆盖缺失 →
/// [`AppchainError::AdmissionRejected`]。
pub fn verify_receipt_set(
    expected: &[[u8; 32]],
    receipts: &[CryptoVerifierReceipt],
) -> AppchainResult<()> {
    // 1. 回执自身有效性：零 digest / 未知语句
    for receipt in receipts {
        if receipt.receipt_digest == [0u8; 32] {
            return Err(AppchainError::AdmissionRejected(
                "crypto receipt digest is zero",
            ));
        }
        if !expected.contains(&receipt.statement_digest) {
            return Err(AppchainError::AdmissionRejected(
                "crypto receipt set contains an unknown statement",
            ));
        }
    }
    // 2. 重复语句（同语句双回执 → 归责歧义）
    let mut seen = std::collections::HashSet::new();
    for receipt in receipts {
        if !seen.insert(receipt.statement_digest) {
            return Err(AppchainError::AdmissionRejected(
                "crypto receipt set contains duplicate statements",
            ));
        }
    }
    // 3. 数额：在 1/2 通过后，数额不符 ⇒ 必有缺失
    if receipts.len() != expected.len() {
        return Err(AppchainError::AdmissionRejected(
            "crypto receipt count does not match expected statement count",
        ));
    }
    // 4. 覆盖完整性（防御性：1–3 通过时恒成立）
    for statement in expected {
        if !seen.contains(statement) {
            return Err(AppchainError::AdmissionRejected(
                "crypto receipt set is missing a required statement",
            ));
        }
    }
    Ok(())
}

/// v2 全链 fail-closed 强制（11b）：仅对 `HandBindingFormat::HandBindingV2`
/// 记录执行——声明 deck 链绑定即接受全链语义。
///
/// # Errors
/// 见函数内逐条拒绝路径（消息即清单）。
fn enforce_full_chain_scope(scope: &TexasArchiveScope) -> AppchainResult<()> {
    // a. 首 kind ∈ 准入集（协议链入口）
    if !FULL_CHAIN_FIRST_KINDS.contains(&scope.first_transition_kind) {
        return Err(AppchainError::AdmissionRejected(
            "full-chain archive first transition kind is not a chain-entry kind",
        ));
    }
    // b. 末 kind ∈ 结算语义集
    if !SETTLEMENT_TERMINAL_KINDS.contains(&scope.last_transition_kind) {
        return Err(AppchainError::AdmissionRejected(
            "full-chain archive last transition kind is not settlement-terminal",
        ));
    }
    // c. blind_opening 存在性 + 形状（发牌→下注桥的批级公开投影）
    let blind = scope.blind_opening.ok_or(AppchainError::AdmissionRejected(
        "full-chain archive is missing the blind opening",
    ))?;
    if blind.ante_mode > 2 {
        return Err(AppchainError::AdmissionRejected(
            "blind opening has unsupported ante mode",
        ));
    }
    if blind.small_blind == 0 && blind.big_blind == 0 && blind.ante_amount == 0 {
        return Err(AppchainError::AdmissionRejected(
            "blind opening is vacuous (all-zero blinds and ante)",
        ));
    }
    // d. deck 锚（S1）：pre/post 镜像 deck_commitment 非零
    let anchors = deck_chain_anchors(scope)?;
    if anchors.pre_deck_commitment == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected(
            "archive pre-state deck commitment is zero (S1 anchor missing)",
        ));
    }
    if anchors.post_deck_commitment == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected(
            "archive post-state deck commitment is zero",
        ));
    }
    // e. 发牌覆盖：终态 reveal_commitment 非零（SubmitReveal 行锚）
    if anchors.post_reveal_commitment == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected(
            "archive terminal reveal commitment is zero (deal not covered)",
        ));
    }
    // f. 盲注面额与 blind_opening 的镜像解耦校验（座位 bet 布局消费）：
    //    座位区偏移已推导但 blind_opening 不携带座位指派，跨镜像强校验
    //    待上游 stage0 冻结座位指派口径（SHUFFLE_CONSUME.md 排队清单）。
    Ok(())
}

/// 归档是否携带**协议行**（SubmitShuffle/SubmitReveal/SubmitReconstruct
/// 及其完成行、reveal-timeout 级联——凡洗牌/发牌/重构机制参与过的批）。
///
/// 判定全部来自 scope 公开端点（fail-closed 的过近似，宁滥勿缺）：
/// - 首/末转移 kind ∈ {7, 8, 9}（协议提交行打头/收尾的批段）；
/// - deck 承诺链在批内轮转（pre.deck ≠ post.deck ⇒ 批内有洗牌/重构完成行）；
/// - reveal 承诺在批内轮转（pre ≠ post ⇒ 批内有 SubmitReveal 行或
///   reveal-timeout 级联——两者都是协议机制）；
/// - reconstruction 承诺在批内轮转（pre ≠ post ⇒ 批内有 SubmitReconstruct 行）。
///
/// 依据（上游 stage0 实测）：canonical AIR 对**非末段** shuffle 行的 deck
/// 承诺篡改不可见（只冻结锚、不重算密文哈希）——含协议行的 REAL 结算
/// 因此必须经路线 A 原生校验（11b-f），本判定是其触发器。
///
/// # Errors
/// 镜像截断 → [`AppchainError::AdmissionRejected`]。
#[must_use]
pub fn archive_has_protocol_rows(scope: &TexasArchiveScope) -> AppchainResult<bool> {
    const PROTOCOL_KINDS: [u8; 3] =
        [KIND_SUBMIT_SHUFFLE, KIND_SUBMIT_REVEAL, KIND_SUBMIT_RECONSTRUCT];
    let anchors = deck_chain_anchors(scope)?;
    let pre_reveal = state_image_commitment32(
        &scope.pre_state_image_bytes,
        STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
    )?;
    let pre_reconstruction = state_image_commitment32(
        &scope.pre_state_image_bytes,
        STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET,
    )?;
    Ok(
        PROTOCOL_KINDS.contains(&scope.first_transition_kind)
            || PROTOCOL_KINDS.contains(&scope.last_transition_kind)
            || anchors.pre_deck_commitment != anchors.post_deck_commitment
            || pre_reveal != anchors.post_reveal_commitment
            || pre_reconstruction != anchors.post_reconstruction_commitment,
    )
}

/// poker_texas_air `CanonicalRakeOpening` 的镜像（borsh 逐字节一致）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct RakeOpeningScope {
    /// `RAKE_MODE_NONE` (0) 或 `RAKE_MODE_PERCENTAGE` (1)。
    pub rake_mode: u8,
    /// Basis points，至多 10_000。
    pub rake_bps: u16,
    /// 单手 rake 硬封顶。
    pub rake_cap: u64,
}

/// poker_texas_air `CanonicalBlindOpening` 的镜像（borsh 逐字节一致）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct BlindOpeningScope {
    /// 小盲。
    pub small_blind: u64,
    /// 大盲。
    pub big_blind: u64,
    /// ante 模式（0/1/2）。
    pub ante_mode: u8,
    /// ante 数额。
    pub ante_amount: u64,
}

/// poker_texas_air 手牌批次证明的**公开范围镜像**（scope v2）。
///
/// 字段序与 `poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof`
/// 的**公开字段序完全一致**（borsh 逐字段兼容）。尾部字段
/// （`rules_hash` / `state_object_key` / `state_opening_epoch` /
/// `stark_proof_bytes`）刻意不镜像：borsh 结构解码不消费尾缀字节，
/// scope 只需要公开绑定所需前缀。镜像一致性由
/// `poker-appchain-texasair` 适配器测试（真实归档 → `parse_archive_scope`
/// 逐字段比对）钉住。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct TexasArchiveScope {
    /// trace log2 尺寸。
    pub log_size: u32,
    /// 列数。
    pub num_columns: u32,
    /// 公开桌范围。
    pub table_id: u64,
    /// 批内首个手 ID。
    pub first_hand_id: u32,
    /// 批内末个手 ID。
    pub last_hand_id: u32,
    /// 批内首个转移序号。
    pub first_call_seq: u32,
    /// 批内末个转移序号。
    pub last_call_seq: u32,
    /// 转移数。
    pub transition_count: u16,
    /// 首行转移选择子（canonical AIR 公开绑定）。
    pub first_transition_kind: u8,
    /// 末行转移选择子。
    pub last_transition_kind: u8,
    /// reveal-timeout 级联踢出行数。
    pub reveal_timeout_cascade_count: u8,
    /// 级联座位序（未用槽位 `u8::MAX` 填充）。
    pub reveal_timeout_cascade_schedule: [u8; MAX_CANONICAL_SEATS],
    /// 批摘要。
    pub batch_digest: [u8; 32],
    /// 首状态承诺。
    pub pre_state_commitment: [u8; 32],
    /// 终态承诺。
    pub post_state_commitment: [u8; 32],
    /// 首**状态根**（SMT，v2 新增公开域）。
    pub pre_state_root: [u8; 32],
    /// 终**状态根**（SMT，v2 新增公开域）。
    pub post_state_root: [u8; 32],
    /// 首 lifecycle 根。
    pub pre_lifecycle_root: [u8; 32],
    /// 终 lifecycle 根。
    pub post_lifecycle_root: [u8; 32],
    /// 首 overlay 根。
    pub pre_overlay_root: [u8; 32],
    /// 终 overlay 根。
    pub post_overlay_root: [u8; 32],
    /// 首 settlement 承诺。
    pub pre_settlement_commitment: [u8; 32],
    /// 终 settlement 承诺。
    pub post_settlement_commitment: [u8; 32],
    /// 首 custody 承诺。
    pub pre_custody_commitment: [u8; 32],
    /// 终 custody 承诺。
    pub post_custody_commitment: [u8; 32],
    /// 首 canonical 状态镜像完整 borsh 字节（被 Fiat--Shamir 范围绑定）。
    pub pre_state_image_bytes: Vec<u8>,
    /// 终 canonical 状态镜像完整 borsh 字节（被 Fiat--Shamir 范围绑定）。
    pub post_state_image_bytes: Vec<u8>,
    /// range LogUp 关系公开 claimed sum。
    pub range_claimed_sum: [u32; 4],
    /// 已认证 rake 配置（恰在批含 `RevealTimeoutRakedAward` 行时出现）。
    pub rake_opening: Option<RakeOpeningScope>,
    /// 已认证盲注/ante 投影（恰在批含末个 `SubmitReveal` 时出现）。
    pub blind_opening: Option<BlindOpeningScope>,
}

/// 归档字节 → 公开范围（borsh，字段序与 poker_texas_air canonical 归档一致）。
///
/// 刻意用 `deserialize_reader`（前缀消费）而非 `try_from_slice`：scope 只
/// 镜像 canonical 归档的公开绑定前缀，尾部字段（`rules_hash`/
/// `state_object_key`/`state_opening_epoch`/`stark_proof_bytes`）不消费。
/// 镜像一致性由适配器测试逐字段钉住。
///
/// # Errors
/// 编码不合法 → [`AppchainError::Codec`]。
pub fn parse_archive_scope(archive_bytes: &[u8]) -> AppchainResult<TexasArchiveScope> {
    use borsh::BorshDeserialize as _;
    let mut cursor = std::io::Cursor::new(archive_bytes);
    TexasArchiveScope::deserialize_reader(&mut cursor)
        .map_err(|e| AppchainError::Codec(format!("archive scope: {e}")))
}

/// 手牌证明绑定（B1/B2 接入缝）：结算声明其对应的手牌批次证明。
///
/// v1.2 起同时声明前后**状态根**；`post_state_commitment`/
/// `post_state_root`/`pre_state_root` 都是**声明值**，由
/// `validate_settlement` 与归档 scope 逐字节比对，`texas-air` feature 下
/// 适配器额外执行完整 STARK 验证。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct HandProofBinding {
    /// poker_texas_air 归档字节（borsh）。
    pub archive_bytes: Vec<u8>,
    /// 声明的终态承诺（= 归档 post_state_commitment）。
    pub post_state_commitment: [u8; 32],
    /// 声明的首状态根（v1.2 = 归档 pre_state_root）。
    pub pre_state_root: [u8; 32],
    /// 声明的终状态根（v1.2 = 归档 post_state_root）。
    pub post_state_root: [u8; 32],
}

/// 校验 payouts 与 `plan` 投影一一对应（fail-closed 清单第 8 条）。
///
/// - 期望三元组序列 `(pot_index, runout_index, seat, amount)` 按
///   `(pot_index, runout_index, seat)` 规范序从 `plan` 展开
///   （只含 active runout 槽位与非零 award）；
/// - 声明顺序给出 owner↔seat 映射：第 k 个 payout ↔ 第 k 个三元组；
/// - `(pot_index, runout_index, amount)` 必须逐项相等；
/// - owner↔seat 必须一一对应（同一 owner 跨座位 / 同一座位跨 owner 拒绝）；
/// - 按 owner 聚合 == `plan.awards`。
fn validate_payout_projection(record: &SettlementRecord) -> AppchainResult<()> {
    let plan = &record.plan;
    let mut expected: Vec<(u8, u8, usize, u64)> = Vec::new();
    for pot in &plan.pots {
        let active_runouts = if pot.is_contested() {
            usize::from(plan.schedule.count())
        } else {
            1
        };
        for (runout_index, runout) in pot.runouts.iter().enumerate().take(active_runouts) {
            for (seat, amount) in runout.awards.iter().enumerate() {
                if *amount > 0 {
                    expected.push((pot.pot_index, u8::try_from(runout_index).unwrap_or(u8::MAX), seat, *amount));
                }
            }
        }
    }

    if record.payouts.len() != expected.len() {
        return Err(AppchainError::AdmissionRejected(
            "payout count does not match plan projection",
        ));
    }
    let mut owner_of_seat: [Option<[u8; 33]>; poker_settlement_core::SETTLEMENT_SEATS] =
        [None; poker_settlement_core::SETTLEMENT_SEATS];
    for (payout, exp) in record.payouts.iter().zip(&expected) {
        if payout.pot_index != exp.0 || payout.runout_index != exp.1 || payout.amount != exp.3 {
            return Err(AppchainError::AdmissionRejected(
                "payout does not match plan projection (table/pot/runout/amount)",
            ));
        }
        let seat = exp.2;
        match owner_of_seat[seat] {
            None => {
                // 同一 owner 不得映射到多个座位
                if owner_of_seat
                    .iter()
                    .enumerate()
                    .any(|(other_seat, owner)| other_seat != seat && *owner == Some(payout.owner))
                {
                    return Err(AppchainError::AdmissionRejected(
                        "payout owner spans multiple seats",
                    ));
                }
                owner_of_seat[seat] = Some(payout.owner);
            }
            Some(owner) => {
                if owner != payout.owner {
                    return Err(AppchainError::AdmissionRejected(
                        "payout order violates the declared owner-seat mapping",
                    ));
                }
            }
        }
    }
    // Σ(payouts 按 owner 聚合) == plan.awards（数额逐项相等时为 plan.validate
    // 聚合的重复投影，仍独立断言 fail-closed）。
    let mut aggregated = [0u64; poker_settlement_core::SETTLEMENT_SEATS];
    for (payout, exp) in record.payouts.iter().zip(&expected) {
        aggregated[exp.2] = aggregated[exp.2]
            .checked_add(payout.amount)
            .ok_or(AppchainError::InvalidAmount(u64::MAX))?;
    }
    if aggregated != plan.awards {
        return Err(AppchainError::AdmissionRejected(
            "aggregated payouts do not equal plan awards",
        ));
    }
    Ok(())
}

/// 对 `SettlementRecord` 做纯函数校验（不触碰账本状态）。
///
/// 这是 M2 的语义核心：**全部拒绝路径都从这里出**（清单见模块文档），
/// sequencer 层不重复实现语义（避免双实现漂移）。
///
/// # Errors
/// 见模块文档 fail-closed 清单（1..=11）。
pub fn validate_settlement(
    record: &SettlementRecord,
    policy: &FeePolicy,
) -> AppchainResult<()> {
    // 0. TE-M4 v1/v2 边界（fail-closed）：v1 结算遇 `FixedRakeBurn` 桌一律拒。
    //    理由（二选一决策记录）：(a) GAME 币本就是 v2 账本资产（v1 NoteSpec
    //    的二元 AssetClass 无法表达 GAME 注册 token），burn 桌的合法结算
    //    只能走 v2 路径；(b) v1 的 rake 输出表示（treasury/operator note
    //    铸入 v1 账本）会把销毁误当分账入账——与合约侧"处置 = burn"直接
    //    冲突。v1 路径保持零变更：本分支只影响此前不可结算的 burn 桌。
    if matches!(policy, FeePolicy::FixedRakeBurn { .. }) {
        return Err(AppchainError::AdmissionRejected(
            "v1 settlement cannot settle a FixedRakeBurn table (burn disposal requires the v2 GAME ledger)",
        ));
    }
    // 1a. 非零标识（对齐 canonical AIR 的 non-zero identifier 关系）
    if record.hand_binding == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected("zero hand binding"));
    }
    if record.inputs.is_empty() {
        return Err(AppchainError::AdmissionRejected("empty settlement inputs"));
    }

    // 2. 结算计划自身守恒/形状（单一事实源校验：版本/边界/runout 投影）
    record
        .plan
        .validate(record.inputs.len())
        .map_err(|e| AppchainError::Codec(format!("settlement plan: {e}")))?;

    // 3. pot 从已验证计划派生（plan-appchain §5.2-2：不再独立可信）
    if record.plan.gross_pot != record.pot {
        return Err(AppchainError::AdmissionRejected(
            "plan gross pot does not match record pot",
        ));
    }

    // 4. table_id 一致 + 资产类一致 + 输入 note 与授权的承诺一致 + 贡献守恒
    let class = record.inputs[0].note.asset_class;
    let mut input_sum: u128 = 0;
    let mut commitments: Vec<FieldElement> = Vec::with_capacity(record.inputs.len());
    for input in &record.inputs {
        if input.note.table_id != Some(record.table_id) {
            return Err(AppchainError::AdmissionRejected("seat note table mismatch"));
        }
        if input.note.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                input.note.asset_class.name(),
            ));
        }
        let c = input.note.commitment();
        if felt_to_bytes32(&c) != input.spend.commitment {
            return Err(AppchainError::AdmissionRejected("spend commitment mismatch"));
        }
        // nullifier 非零：零 nullifier 会让任意两张 note 冲突（griefing 向量），
        // 且无法区分不同花费。真实 (commitment, secret) 派生绑定由 owner
        // 签名覆盖 —— 签名摘要包含 nullifier 字节。
        if input.spend.nullifier == [0u8; 32] {
            return Err(AppchainError::AdmissionRejected("zero nullifier"));
        }
        commitments.push(c);
        input_sum += u128::from(input.note.amount);
    }
    // 4b. seat notes 即本手下注贡献：Σinputs == plan.gross_pot
    if input_sum != u128::from(record.plan.gross_pot) {
        return Err(AppchainError::AdmissionRejected(
            "seat inputs do not equal plan gross pot",
        ));
    }

    // 5. 输出资产类一致 + 非零 + payout 桌绑定
    let mut output_sum: u128 = 0;
    for o in record.payouts.iter().chain(
        record
            .rake
            .treasury_out
            .iter()
            .chain(record.rake.operator_out.iter()),
    ) {
        if o.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                o.asset_class.name(),
            ));
        }
        if o.amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        if matches!(o.table_id, Some(id) if id != record.table_id) {
            return Err(AppchainError::AdmissionRejected(
                "payout table binding mismatch",
            ));
        }
        output_sum += u128::from(o.amount);
    }
    // 8. payouts 与 plan 投影一一对应（含 pot/runout 索引越界 → 投影不符）
    validate_payout_projection(record)?;

    // 6. P 层签名覆盖：每个输入 note 的 owner 对（绑定摘要 + 结算效果）签名；
    //    settle_effect 含 payout_root → 赔付结构篡改必然签名失败（P0-7）
    let scope = settle_spend_scope(&record.hand_binding);
    let effect = settle_effect(record);
    for input in &record.inputs {
        let d = spend_digest(&input.spend.commitment, &input.spend.nullifier, &scope, &effect);
        verify_ecsdsa(&input.note.owner, &d, &input.spend.sig)?;
    }

    // 7. 费率 + 策略承诺绑定：rake.total == plan.rake == policy.rake_of(rake_base)
    //    （v1.2.2/B9：计费基数 = plan.rake_base()——contested 层 gross 之和，
    //    uncalled 返还层不计费；plan.validate 已强制 uncontested 层 rake == 0，
    //    因此 plan.rake 只能来自 contested 层，与 poker_l1 canonical 的
    //    contested-only 计费唯一对齐。gross_pot 层面守恒不受影响：第 2/3/4/
    //    9 条仍强制 gross_pot == pot == Σinputs == Σoutputs + rake。）
    let rake_total = u128::from(record.rake.total);
    if u128::from(record.plan.rake) != rake_total {
        return Err(AppchainError::AdmissionRejected(
            "plan rake does not match record rake",
        ));
    }
    let rake_base = record.plan.rake_base();
    let expected = policy.rake_of(rake_base);
    if u128::from(expected) != rake_total {
        return Err(AppchainError::FeeMismatch {
            expected: u128::from(expected),
            got: rake_total,
        });
    }
    if policy.commitment_bytes() != record.policy_commitment {
        return Err(AppchainError::FeeMismatch {
            expected: rake_total,
            got: rake_total,
        });
    }

    // 9. 守恒：inputs = payouts + rake 输出 note（rake note 已含在
    //    output_sum 里；rake.total 与其一致性由第 10 步分账检查保证）
    if input_sum != output_sum {
        return Err(AppchainError::ConservationViolated {
            inputs: input_sum,
            outputs: output_sum,
            rake: rake_total,
        });
    }

    // 10. 分账
    let (t_exp, o_exp) = policy.split_of(record.rake.total);
    match (t_exp, o_exp) {
        (0, 0) => {
            if record.rake.treasury_out.is_some() || record.rake.operator_out.is_some() {
                return Err(AppchainError::FeeMismatch { expected: 0, got: rake_total });
            }
        }
        _ => {
            let t = record.rake.treasury_out.as_ref().ok_or(AppchainError::FeeMismatch {
                expected: u128::from(t_exp),
                got: 0,
            })?;
            let o = record
                .rake
                .operator_out
                .as_ref()
                .ok_or(AppchainError::FeeMismatch {
                    expected: u128::from(o_exp),
                    got: 0,
                })?;
            if t.amount != t_exp || o.amount != o_exp {
                return Err(AppchainError::FeeMismatch {
                    expected: u128::from(t_exp + o_exp),
                    got: u128::from(t.amount + o.amount),
                }
                .into());
            }
            // 收款人必须与策略绑定一致（防"金额对、打给自己"）
            if let FeePolicy::FixedRake { split, .. } = policy {
                if t.owner != split.treasury || o.owner != split.operator {
                    return Err(AppchainError::FeeMismatch {
                        expected: u128::from(t_exp + o_exp),
                        got: u128::from(t.amount + o.amount),
                    });
                }
            }
        }
    }

    // 11. 手牌证明绑定（B2 接入缝，scope 级 fail-closed；canonical scope v2）
    if let Some(hp) = &record.hand_proof {
        let scope = parse_archive_scope(&hp.archive_bytes)?;
        if scope.table_id != record.table_id {
            return Err(AppchainError::AdmissionRejected("archive table mismatch"));
        }
        if scope.post_state_commitment != hp.post_state_commitment {
            return Err(AppchainError::AdmissionRejected("archive state commitment mismatch"));
        }
        // v1.2：前后状态根必须与声明一致（SMT 根域，STARK 公开绑定）
        if scope.pre_state_root != hp.pre_state_root
            || scope.post_state_root != hp.post_state_root
        {
            return Err(AppchainError::AdmissionRejected("archive state root mismatch"));
        }
        if scope.transition_count == 0 {
            return Err(AppchainError::AdmissionRejected("empty archive batch"));
        }
        // gross_pot 逐字节绑定（plan-appchain §5.2-2）：已证明终态状态镜像
        // 中偏移 74 的 8 字节 LE `pot` 必须等于 record.pot（== plan.gross_pot）。
        let image_pot = state_image_u64(&scope.post_state_image_bytes, STATE_IMAGE_POT_OFFSET)?;
        if image_pot != record.pot {
            return Err(AppchainError::AdmissionRejected(
                "archive terminal state pot does not match record pot",
            ));
        }
        // 归档含 rake opening（raked terminal 批）时：费率配置必须精确重导出
        // record.rake.total（与 poker_texas_air canonical_settlement_rake 同式：
        // mode 0 → 0；mode 1 → min(floor(pot·bps/10⁴), cap, pot)）。
        // 该批级 opening 的计费基数是终态全池 pot；与 contested-only 的
        // plan.rake（v1.2.2/B9 基数 = rake_base）在终局**无 uncalled 层**时
        // 数值恒等（pot == rake_base），含 uncalled 返还层的 raked 终局仍
        // fail-closed 拒绝（不放宽；记录于 ABI.md §4）。
        if let Some(rake) = &scope.rake_opening {
            match rake.rake_mode {
                0 => {
                    if record.rake.total != 0 {
                        return Err(AppchainError::AdmissionRejected(
                            "archive rake opening (none-mode) conflicts with claimed rake",
                        ));
                    }
                }
                1 => {
                    let expected = poker_settlement_core::rake_for(
                        record.pot,
                        u64::from(rake.rake_bps),
                        10_000,
                    )
                    .min(rake.rake_cap)
                    .min(record.pot);
                    if record.rake.total != expected {
                        return Err(AppchainError::AdmissionRejected(
                            "archive rake opening does not reproduce claimed rake",
                        ));
                    }
                }
                _ => {
                    return Err(AppchainError::AdmissionRejected(
                        "archive rake opening has unsupported mode",
                    ));
                }
            }
        }

        // ===== 11a. hand_binding 升域判定（ABI v1.3 双轨，设计文档 §5-C3）=====
        // v2 → 11b 全链强制（+ 11c receipt 门）；Legacy/Unbound → 迁移期
        // 接受并计数告警（迁移窗关闭后拒绝）。分类需要读镜像偏移重导 v2
        // 绑定，截断镜像在此 fail-closed（`?`）。
        match classify_hand_binding(record, &scope)? {
            HandBindingFormat::HandBindingV2 => {
                enforce_full_chain_scope(&scope)?;
                // 11b-f（阶段 0 负面发现的链侧执行，fail-closed，**无开关**）：
                // 含协议行的 REAL 结算必须经路线 A 原生校验；该验证结果在
                // 结算纯函数层不可自证（引擎侧 BG/DLEq 承诺链重导发生在
                // poker-appchain-texasair C1），故此处直接拒绝该批——宁可
                // 停、不可假。引擎 receipt 归责（路线 B，attestation v2.2）
                // 接线后，本分支升级为"要求回执集验证通过"。依据与负例：
                // SHUFFLE_STAGE0.md §3.4-2（AIR 照常出证、原生 sidecar 拒）。
                if archive_has_protocol_rows(&scope)?
                    && settlement_input_class(record) == Some(AssetClass::Real)
                {
                    return Err(AppchainError::AdmissionRejected(
                        "REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)",
                    ));
                }
                if crypto_receipt_enforcement() {
                    // 路线 B 门（默认关）：开启即要求引擎 receipt 归责已接线；
                    // 未接线前 fail-closed 拒绝，绝不静默放行（不许假验证）。
                    return Err(AppchainError::AdmissionRejected(
                        "crypto receipt enforcement is enabled but engine receipt integration is pending upstream stage0",
                    ));
                }
            }
            HandBindingFormat::LegacyBatchDigest => {
                if full_chain_enforcement() {
                    return Err(AppchainError::AdmissionRejected(
                        "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)",
                    ));
                }
                LEGACY_BINDING_ACCEPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            HandBindingFormat::Unbound => {
                if full_chain_enforcement() {
                    return Err(AppchainError::AdmissionRejected(
                        "hand binding matches neither the v2 deck-chain binding nor the archive batch digest (migration window closed)",
                    ));
                }
                UNBOUND_BINDING_ACCEPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    let _ = commitments; // 保留供未来 trace 导出
    Ok(())
}

/// 结算后按策略生成 rake 输出规格的辅助（游戏服务器侧构造用）。
///
/// rake 输出的投影恒为 `(pot_index=0, runout_index=0)`（rake 不参与
/// plan 投影一致性检查，其数额/收款人由费率关系与策略绑定强制）。
///
/// TE-M4：`FixedRakeBurn` 桌**不产生** rake 输出规格（rake 份额处置 =
/// burn，不铸 treasury/operator note）——v1 [`validate_settlement`] 已对
/// burn 桌整体拒绝，故本函数的 burn 分支在 v1 路径不可达；v2 结算的
/// burn 处置在 `note_v2::validate_settlement_v2`（无 rake 输出 + 守恒
/// 计入销毁额）与 sequencer `apply_settle_v2`（game_burned 记账）落点。
#[must_use]
pub fn rake_outputs(
    record: &SettlementRecord,
    policy: &FeePolicy,
) -> (Option<NoteSpec>, Option<NoteSpec>) {
    let class = record.inputs[0].note.asset_class;
    let (t, o) = policy.split_of(record.rake.total);
    let mk = |amount: u64, owner: [u8; 33]| NoteSpec {
        asset_class: class,
        amount,
        owner,
        table_id: None,
        pot_index: 0,
        runout_index: 0,
    };
    if record.rake.total == 0 {
        (None, None)
    } else if let FeePolicy::FixedRake { split, .. } = policy {
        (Some(mk(t, split.treasury)), Some(mk(o, split.operator)))
    } else {
        (None, None)
    }
}

/// 构造**单层**结算计划的辅助（游戏服务器/测试侧构造用）。
///
/// 单层 pot：`eligible_mask == seats_mask`（`seats_mask.count_ones() >= 2`
/// 时为 contested 层，runout 槽位数随 `Single` 调度取 1）；净额 =
/// `gross_pot - Σawards` 全部记为该层 rake（调用方保证非负且与费率策略
/// 一致——`validate_settlement` 第 8 条会独立强制；contested 单层的
/// `rake_base() == gross_pot`，费率关系退化为 `rake_of(gross_pot)`）。
#[must_use]
pub fn flat_settlement_plan(
    gross_pot: u64,
    seats_mask: u16,
    awards: [u64; poker_settlement_core::SETTLEMENT_SEATS],
) -> SettlementPlan {
    use poker_settlement_core::{
        RunoutPotPlan, SettlementPotPlan, SettlementRunoutSchedule, SETTLEMENT_PLAN_VERSION,
    };
    let total_awards: u64 = awards.iter().sum();
    let rake = gross_pot - total_awards;
    let mut runout = RunoutPotPlan::inactive();
    runout.amount = total_awards;
    runout.winner_mask = seats_mask;
    runout.awards = awards;
    SettlementPlan {
        version: SETTLEMENT_PLAN_VERSION,
        schedule: SettlementRunoutSchedule::Single,
        gross_pot,
        rake,
        total_awards,
        winner_mask: seats_mask,
        awards,
        pots: vec![SettlementPotPlan {
            pot_index: 0,
            gross_amount: gross_pot,
            rake,
            net_amount: total_awards,
            eligible_mask: seats_mask,
            runouts: [runout, RunoutPotPlan::inactive()],
        }],
    }
}

/// 资产类一致性快速断言（输出构造侧用）。
///
/// # Errors
/// 混类 → [`AppchainError::AssetClassMismatch`]。
pub fn assert_single_class(class: AssetClass, specs: &[NoteSpec]) -> AppchainResult<()> {
    for s in specs {
        if s.asset_class != class {
            return Err(AppchainError::AssetClassMismatch(
                class.name(),
                s.asset_class.name(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod shuffle_consume_tests {
    use super::*;
    use crate::felt::DOMAIN_SETTLEMENT_BINDING;

    /// golden：hand_binding v2 域标签经 [`domain_felt`] 与 v1 花费 scope 域
    /// （`DOMAIN_SETTLEMENT_BINDING`）必然分离（升域的域前提）。
    #[test]
    fn v2_domain_is_distinct_from_v1_spend_scope_domain() {
        assert_ne!(DOMAIN_HAND_BINDING_V2, DOMAIN_SETTLEMENT_BINDING);
        assert_ne!(domain_felt(DOMAIN_HAND_BINDING_V2), domain_felt(DOMAIN_SETTLEMENT_BINDING));
    }

    /// golden：密码学语句摘要（blake2b-256，独立预计算）。
    #[test]
    fn crypto_statement_digest_golden() {
        assert_eq!(
            hex_of(&crypto_statement_digest(
                STATEMENT_KIND_SHUFFLE,
                &[[0x11; 32], [0x22; 32]],
            )),
            "aa53908e32d91d454ac9bb6c535e02c71ed6d502f04f75ace96e40038f9b3e70",
        );
        assert_eq!(
            hex_of(&crypto_statement_digest(
                STATEMENT_KIND_REVEAL,
                &[[0x33; 32], [0x44; 32]],
            )),
            "e0875a468badf8825d91d562e66a75c1c2dc7c343b647b2cd0d24874ef6fbc7d",
        );
    }

    /// 链去重语义：pre == post → 单元素链（betting 段批）；不等 → 双元素。
    #[test]
    fn deck_chain_anchors_dedup_consecutive() {
        let image = |deck: [u8; 32]| {
            let mut img = vec![0u8; CANONICAL_STATE_IMAGE_BORSH_BYTES];
            img[STATE_IMAGE_DECK_COMMITMENT_OFFSET..][..32].copy_from_slice(&deck);
            img[STATE_IMAGE_REVEAL_COMMITMENT_OFFSET..][..32].copy_from_slice(&[9u8; 32]);
            img
        };
        let scope = minimal_scope_with_images(image([7u8; 32]), image([7u8; 32]));
        let anchors = deck_chain_anchors(&scope).unwrap();
        assert_eq!(anchors.chain(), vec![[7u8; 32]]);

        let scope = minimal_scope_with_images(image([5u8; 32]), image([7u8; 32]));
        let anchors = deck_chain_anchors(&scope).unwrap();
        assert_eq!(anchors.chain(), vec![[5u8; 32], [7u8; 32]]);
    }

    fn minimal_scope_with_images(
        pre: Vec<u8>,
        post: Vec<u8>,
    ) -> TexasArchiveScope {
        TexasArchiveScope {
            log_size: 8,
            num_columns: 1,
            table_id: 1,
            first_hand_id: 1,
            last_hand_id: 1,
            first_call_seq: 0,
            last_call_seq: 1,
            transition_count: 2,
            first_transition_kind: KIND_START_HAND,
            last_transition_kind: KIND_ADVANCE_ROUND,
            reveal_timeout_cascade_count: 0,
            reveal_timeout_cascade_schedule: [u8::MAX; MAX_CANONICAL_SEATS],
            batch_digest: [1; 32],
            pre_state_commitment: [2; 32],
            post_state_commitment: [3; 32],
            pre_state_root: [4; 32],
            post_state_root: [5; 32],
            pre_lifecycle_root: [0; 32],
            post_lifecycle_root: [0; 32],
            pre_overlay_root: [0; 32],
            post_overlay_root: [0; 32],
            pre_settlement_commitment: [0; 32],
            post_settlement_commitment: [0; 32],
            pre_custody_commitment: [0; 32],
            post_custody_commitment: [0; 32],
            pre_state_image_bytes: pre,
            post_state_image_bytes: post,
            range_claimed_sum: [0; 4],
            rake_opening: None,
            blind_opening: None,
        }
    }

    fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
