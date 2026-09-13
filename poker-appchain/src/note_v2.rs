//! ABI v2 正式版：NoteV2 账本核心（v2 Note / 输出规格 / 混合结算校验）。
//!
//! v1 Note ABI（[`crate::note`]）**冻结不动**；v2 全部走本模块的新类型。
//! 与 v1 的关键差异：
//!
//! - owner 从裸 33B 压缩公钥升级为 [`crate::owner_v2::OwnerRef`]（带
//!   scheme + key_version + binding_id），承诺与 nullifier 全部经
//!   [`crate::owner_v2::owner_commitment`] 绑定——同一公钥在不同
//!   scheme/version 下互为不同身份；
//! - `nonce` 从 32B 字节收窄为 `u64`（铸币方单调序号；唯一性由账本
//!   "承诺查重" 强制，承诺中含全部字段）；
//! - 补齐 `pot_index`/`runout_index`（与 v1 [`crate::note::NoteSpec`]
//!   的 §5.2-7 完整绑定对齐）；
//! - 域标签在本模块内**定义并冻结**（`zchain.note.v2.*` 命名空间）——
//!   与 [`crate::felt`] v1 常量表的关系由 `docs/ABI_V2.md` 统一收录
//!   （felt.rs 冻结，v2 常量不进该表）。
//!
//! ## nullifier 语义（防跨网/跨版重放）
//!
//! [`NoteV2::nullifier`] = `poseidon(域, commitment, owner_commitment,
//! secret, blake2s32(spend_scope))`：owner_commitment 使 scheme 参与
//! 派生；`spend_scope` 必须含 `network_id || abi_version || 操作标签`
//! （[`spend_scope`] 构造器），同一张 note 在不同网络/ABI 版本下的
//! nullifier 不同——跨网重放在 nullifier 层天然失效。
//!
//! ## 混合结算（双 verifier 并行）
//!
//! [`SettlementRecordV2`] 的输入可以是 v1 note（走既有
//! `spend_digest` + `verify_ecsdsa` 路径）或 v2 note（走
//! [`settle_spend_verifier_v2`]：SignatureEnvelope + v2 域 scope）。
//! 两条验证路径并行、逐输入分派（[`SettleInputV2`] 判别式即分派点），
//! 交叉伪造（v2 输入配 v1 验签）在类型层不可表达、在验证层 fail-closed
//! 拒绝。守恒/费率/单资产隔离（TE-M1：AssetId 粒度，v1 纪律的等价推广）
//! 对两种输入统一强制。
//!
//! ## 边界（如实声明）
//!
//! - v2 输入的证明覆盖是 **host 侧校验关系**：canonical AIR 约束未
//!   扩展到 v2 owner（见 `docs/ABI_V2.md` §边界），批次证明当前不覆盖
//!   v2 验签关系本身；
//! - v2 结算不携带 `SettlementPlan`（poker-settlement-core 计划绑定是
//!   v1 `SettlementRecord` 专属）：v2 侧以 `pot == Σinputs` 的单层
//!   contested 口径计费（与 `flat_settlement_plan` 语义一致），plan 级
//!   投影绑定（payout↔seat 投影）待 v2 BuyIn/seat 生命周期引入后扩展。
//!
//! ## TE-M1：`asset_class` → `asset_id`（排期表 §6 TE-M1，方案 A）
//!
//! v2 alpha 未冻结窗口内的**一次性改型**（避免 v1→v2→v3 两轮迁移债）：
//! `NoteV2/NoteSpec2` 的 `asset_class: AssetClass` 升级为
//! `asset_id: AssetId`（[`crate::asset_id`]，domain + token_id）。
//!
//! - v2 域标签**不变**（`zchain.note.v2.*` 冻结值不动）；资产身份以
//!   [`crate::asset_id::asset_commitment`]（域 `zchain.asset.v2.id`）
//!   单 felt 进入承诺 preimage——`token_id` 不进承诺 = 同域不同币种
//!   可互换，INV-TE-1 因此在承诺层强制；
//! - 同类守恒从"同 AssetClass"升级为"同 AssetId"（domain 与 token_id
//!   任一不同 → [`AppchainError::AssetMismatch`]；跨 `AssetId` 混合
//!   fail-closed 拒绝）；
//! - v1 输入（[`SettleInputV2::V1`]）经冻结映射
//!   [`AssetId::of_v1`] 升维后参与同一校验（Real→REAL/0，
//!   Play→GAME/0）；v1 note 本身与 v1 结算路径零变更；
//! - [`SettlementRecordV2`] 效果摘要的赔付段追加
//!   `asset_commitment(asset_id)`——资产维度进签名覆盖，赔付资产
//!   篡改必然摘要失配；
//! - borsh 字段类型变更记录见 `docs/ABI_ASSET_ID.md` §TE-M1 变更记录
//!   （NoteV2 尚未上链，无冻结包袱；[`MigrateNoteRecord`] 保持 v1
//!   `asset_class` 字段与其摘要不变，升维发生在 sequencer 准入比对）。

use starknet_crypto::{poseidon_hash_many, FieldElement};

use crate::asset_id::{asset_commitment, AssetId};
use crate::error::{AppchainError, AppchainResult};
use crate::fee::FeePolicy;
use crate::felt::{bytes32_to_felts, domain_felt, felt_from_u64, felt_to_bytes32};
use crate::keys::{blake2s32, spend_digest, verify_ecsdsa};
use crate::owner_v2::{
    check_envelope_freshness, owner_commitment, validate_envelope, validate_owner_ref,
    v2_spend_digest, verify_owner_signature, MigrateNoteRecord, OwnerRef, SignatureEnvelope,
    VerifierMaterial,
};
use crate::settlement::{settle_spend_scope, RakeSplitRecord};

// ---------------------------------------------------------------------------
// 域标签（冻结；`zchain.note.v2` 命名空间，常量表归 docs/ABI_V2.md 收录）
// ---------------------------------------------------------------------------

/// 域标签：v2 note 承诺（`zchain.note.v2`，ABI_V2.md 冻结）。
pub const DOMAIN_NOTE_V2_COMMITMENT: &[u8] = b"zchain.note.v2";
/// 域标签：v2 note nullifier（owner secret 参与派生）。
pub const DOMAIN_NOTE_V2_NULLIFIER: &[u8] = b"zchain.note.v2.nullifier.v1";
/// 域标签：迁移消费 nullifier（链侧派生，不依赖旧 owner spend secret）。
pub const DOMAIN_NOTE_V2_MIGRATION_NULLIFIER: &[u8] = b"zchain.note.v2.migrate_nullifier.v1";
/// 域标签：v2 结算花费 scope 前缀（scope 含 network_id + abi_version）。
pub const DOMAIN_NOTE_V2_SETTLE_SCOPE: &[u8] = b"zchain.owner_v2.settle.v1";
/// v2 结算效果摘要域前缀。
pub const DOMAIN_NOTE_V2_SETTLE_EFFECT: &[u8] = b"zchain.owner_v2.settle.effect.v1";

/// 默认 ZChain network id（`blake2s32("zchain-poker-devnet")`；与
/// `tests/owner_v2.rs` 迁移夹具同源）。生产网络经
/// [`crate::sequencer::SequencerConfig::network_id`] 覆盖。
#[must_use]
pub fn default_network_id() -> [u8; 32] {
    blake2s32(&[b"zchain-poker-devnet"])
}

/// v2 花费 scope 构造器：`network_id || abi_version(BE) || tag`。
///
/// **纪律**：所有 v2 花费授权（nullifier 派生与 SignatureEnvelope 摘要）
/// 的 scope 必须经本构造器产出，保证 network_id 与 ABI 版本参与全部
/// 授权摘要（防跨网/跨版重放；ABI_V2.md 冻结）。
#[must_use]
pub fn spend_scope(network_id: &[u8; 32], abi_version: u32, tag: &[u8]) -> Vec<u8> {
    let mut scope = Vec::with_capacity(32 + 4 + tag.len());
    scope.extend_from_slice(network_id);
    scope.extend_from_slice(&abi_version.to_be_bytes());
    scope.extend_from_slice(tag);
    scope
}

// ---------------------------------------------------------------------------
// NoteV2 / NoteSpec2
// ---------------------------------------------------------------------------

/// 一张 owned note（ABI v2）。
///
/// 面额单位与 v1 一致（STRK wei）；`table_id` 为 Some 时是桌内 seat
/// note，None 是自由余额 note。`pot_index`/`runout_index` 对齐 v1
/// `NoteSpec` 的结算投影绑定（非结算输出恒 0）。
///
/// TE-M1：资产字段为 [`AssetId`]（domain + token_id）——REAL 多币种
/// （TE-M2）与 GAME 币（TE-M3）的账本地基；v1 二元资产类经
/// [`AssetId::of_v1`] 冻结映射升维（Real→REAL/0，Play→GAME/0）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct NoteV2 {
    /// 资产身份（TE-M1；隔离语义 = v1 单类隔离的 AssetId 粒度推广）。
    pub asset_id: AssetId,
    /// 面额 > 0。
    pub amount: u64,
    /// owner 引用（scheme + key_version 参与全部承诺/摘要）。
    pub owner: OwnerRef,
    /// 铸币方单调序号。
    pub nonce: u64,
    /// 桌绑定（seat note 时 Some）。
    pub table_id: Option<u64>,
    /// 结算投影：pot 分层索引（非结算输出恒 0）。
    pub pot_index: u8,
    /// 结算投影：runout 索引（非结算输出恒 0）。
    pub runout_index: u8,
}

impl NoteV2 {
    /// 构造校验：面额 > 0 且 owner 引用结构合法（fail-closed）。
    ///
    /// # Errors
    /// amount == 0 → [`AppchainError::InvalidAmount`]；owner 非法 →
    /// [`AppchainError::AdmissionRejected`]（`owner_v2` 稳定类别映射）。
    pub fn new(
        asset_id: AssetId,
        amount: u64,
        owner: OwnerRef,
        nonce: u64,
        table_id: Option<u64>,
        pot_index: u8,
        runout_index: u8,
    ) -> AppchainResult<Self> {
        if amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        validate_owner_ref(&owner)?;
        Ok(Self {
            asset_id,
            amount,
            owner,
            nonce,
            table_id,
            pot_index,
            runout_index,
        })
    }

    /// 承诺：`poseidon(DOMAIN_NOTE_V2_COMMITMENT,
    /// asset_commitment(asset_id), amount, owner_commitment hi/lo,
    /// nonce, table, pot_index, runout_index)`。
    ///
    /// `owner_commitment` 已含 scheme/key_version/binding_id——同一底层
    /// 公钥在不同 scheme 下必得不同承诺。table 编码与 v1 一致：None → 0，
    /// Some(id) → id + 1。TE-M1：第二位从 class 判别值 felt 升级为
    /// [`asset_commitment`]（域 `zchain.asset.v2.id` 域分离哈希）——
    /// 域标签 `DOMAIN_NOTE_V2_COMMITMENT` 冻结不变，资产身份（domain
    /// 与 token_id）整体进 preimage。
    #[must_use]
    pub fn commitment(&self) -> FieldElement {
        let (o_hi, o_lo) = bytes32_to_felts(&owner_commitment(&self.owner));
        let table = match self.table_id {
            None => FieldElement::ZERO,
            Some(id) => felt_from_u64(id.wrapping_add(1)),
        };
        poseidon_hash_many(&[
            domain_felt(DOMAIN_NOTE_V2_COMMITMENT),
            asset_commitment(&self.asset_id),
            felt_from_u64(self.amount),
            o_hi,
            o_lo,
            felt_from_u64(self.nonce),
            table,
            felt_from_u64(u64::from(self.pot_index)),
            felt_from_u64(u64::from(self.runout_index)),
        ])
    }

    /// 承诺的 32 字节编码。
    #[must_use]
    pub fn commitment_bytes(&self) -> [u8; 32] {
        felt_to_bytes32(&self.commitment())
    }

    /// nullifier：`poseidon(DOMAIN_NOTE_V2_NULLIFIER, commitment hi/lo,
    /// owner_commitment hi/lo, secret hi/lo, blake2s32(spend_scope) hi/lo)`。
    ///
    /// scheme 经 owner_commitment 参与派生；`spend_scope` 由客户端经
    /// [`spend_scope`] 构造（必须含 network_id + abi_version）。
    #[must_use]
    pub fn nullifier(&self, secret: &[u8; 32], spend_scope: &[u8]) -> [u8; 32] {
        let (c_hi, c_lo) = bytes32_to_felts(&self.commitment_bytes());
        let (o_hi, o_lo) = bytes32_to_felts(&owner_commitment(&self.owner));
        let (s_hi, s_lo) = bytes32_to_felts(secret);
        let (sc_hi, sc_lo) = bytes32_to_felts(&blake2s32(&[spend_scope]));
        felt_to_bytes32(&poseidon_hash_many(&[
            domain_felt(DOMAIN_NOTE_V2_NULLIFIER),
            c_hi,
            c_lo,
            o_hi,
            o_lo,
            s_hi,
            s_lo,
            sc_hi,
            sc_lo,
        ]))
    }

    /// 同资产断言（TE-M1：从"同 AssetClass"升级为"同 AssetId"——
    /// domain 与 token_id 任一不同即拒）。
    ///
    /// # Errors
    /// 跨 `AssetId` → [`AppchainError::AssetMismatch`]。
    pub fn assert_same_asset(&self, other: &NoteV2) -> AppchainResult<()> {
        self.asset_id.ensure_same(other.asset_id)
    }
}

/// 输出 note 规格（ABI v2 铸造侧）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct NoteSpec2 {
    /// 资产身份（TE-M1）。
    pub asset_id: AssetId,
    /// 面额 > 0。
    pub amount: u64,
    /// 收款人 owner 引用。
    pub owner: OwnerRef,
    /// 桌绑定。
    pub table_id: Option<u64>,
    /// 结算投影：pot 分层索引（非结算输出恒 0）。
    pub pot_index: u8,
    /// 结算投影：runout 索引（非结算输出恒 0）。
    pub runout_index: u8,
}

impl NoteSpec2 {
    /// 铸造成实际 note（nonce 由铸币方补齐）。
    ///
    /// # Errors
    /// amount == 0 / owner 非法 → 对应 [`AppchainError`]。
    pub fn mint(self, nonce: u64) -> AppchainResult<NoteV2> {
        NoteV2::new(
            self.asset_id,
            self.amount,
            self.owner,
            nonce,
            self.table_id,
            self.pot_index,
            self.runout_index,
        )
    }
}

// ---------------------------------------------------------------------------
// 迁移消费 nullifier（链侧派生）
// ---------------------------------------------------------------------------

/// 迁移消费 nullifier：`poseidon(DOMAIN_NOTE_V2_MIGRATION_NULLIFIER,
/// old_commitment hi/lo, migration_nonce hi/lo)`。
///
/// 链侧确定性派生——迁移不要求旧 owner 交出 v1 spend secret：
/// `migration_nonce` 被 [`crate::owner_v2::migrate_digest`] 签名覆盖，
/// 因此该 nullifier 是旧 owner 授权的确定性函数，且全局查重
/// （migration_nonces 集）保证每个 nonce 只消费一张 note。
#[must_use]
pub fn migration_nullifier(record: &MigrateNoteRecord) -> [u8; 32] {
    let (c_hi, c_lo) = bytes32_to_felts(&record.old_commitment);
    let (n_hi, n_lo) = bytes32_to_felts(&record.migration_nonce);
    felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_NOTE_V2_MIGRATION_NULLIFIER),
        c_hi,
        c_lo,
        n_hi,
        n_lo,
    ]))
}

// ---------------------------------------------------------------------------
// 混合结算（双 verifier 并行）
// ---------------------------------------------------------------------------

/// v2 结算的混合输入（判别式即 verifier 分派点）。
///
/// - `V1`：v1 seat note + 既有 [`crate::settlement::SpendAuth`]（v1
///   `spend_digest` + secp256k1 验签路径）；
/// - `V2`：v2 note + [`SignatureEnvelope`]（v2 域 scope +
///   [`verify_owner_signature`] 多 scheme 路径；验签材料随输入呈递，
///   WAL 重放可全量复核）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum SettleInputV2 {
    /// v1 输入（既有 SpendAuth 路径）。
    V1 {
        /// seat note（table_id 必须 == 记录 table_id）。
        note: crate::note::Note,
        /// 花费授权。
        spend: crate::settlement::SpendAuth,
    },
    /// v2 输入（SignatureEnvelope 路径）。
    V2 {
        /// note 全量内容（账本核对 + 承诺/conservation）。
        note: NoteV2,
        /// v2 nullifier（客户端按 [`NoteV2::nullifier`] 派生；scope 含
        /// network_id + abi_version）。
        nullifier: [u8; 32],
        /// 授权信封（typed_data_digest 必须等于 v2 花费摘要）。
        envelope: SignatureEnvelope,
        /// 按 scheme 呈递的验签材料。
        material: VerifierMaterial,
    },
}

impl SettleInputV2 {
    /// 输入资产身份（TE-M1）。
    ///
    /// v1 臂经冻结映射 [`AssetId::of_v1`] 升维（v1 note 本身与 v1 路径
    /// 零变更——`AssetClass` 只在此一处换算成 `AssetId`），v2 臂直取
    /// note 的 `asset_id`。守恒校验以本返回值分组。
    #[must_use]
    pub fn asset_id(&self) -> AssetId {
        match self {
            Self::V1 { note, .. } => AssetId::of_v1(note.asset_class),
            Self::V2 { note, .. } => note.asset_id,
        }
    }

    /// 输入面额。
    #[must_use]
    pub fn amount(&self) -> u64 {
        match self {
            Self::V1 { note, .. } => note.amount,
            Self::V2 { note, .. } => note.amount,
        }
    }

    /// 声明的消费 nullifier。
    ///
    /// # Errors
    /// v2 输入的 nullifier 为零 → [`AppchainError::AdmissionRejected`]
    ///（零 nullifier 会让不同 note 的消费在共享 nullifier 集里碰撞，
    /// 与 v1 同款 fail-closed 纪律）。
    pub fn declared_nullifier(&self) -> AppchainResult<[u8; 32]> {
        match self {
            Self::V1 { spend, .. } => {
                if spend.nullifier == [0u8; 32] {
                    return Err(AppchainError::AdmissionRejected("zero nullifier"));
                }
                Ok(spend.nullifier)
            }
            Self::V2 { nullifier, .. } => {
                if *nullifier == [0u8; 32] {
                    return Err(AppchainError::AdmissionRejected("zero nullifier"));
                }
                Ok(*nullifier)
            }
        }
    }
}

/// v2 结算记录（混合输入；`Operation::SettleV2` 载荷）。
///
/// 语义对齐 v1 [`crate::settlement::SettlementRecord`] 的纪律子集
/// （守恒/费率/单类/重放绑定/逐输入签名），差异如实声明：
/// - **无 `SettlementPlan`**：v2 以单层 contested 口径计费
///   （`rake.total == policy.rake_of(pot)`，`pot == Σinputs`）；
/// - v1 输入保持 seat 绑定（`table_id == Some(table_id)`）；v2 输入
///   允许自由余额 note（`table_id == None`）参与结算——v2 seat 生命
///   周期（BuyInV2）本版未引入，桌绑定对 v2 侧暂不强制（ABI_V2.md
///   §混合结算如实记录）；
/// - 赔付输出为 [`NoteSpec2`]（收款人 = OwnerRef，铸入 v2 账本）；
///   rake 输出沿用 v1 [`RakeSplitRecord`]（treasury/operator 是 legacy
///   33B 身份，铸入 v1 账本）。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SettlementRecordV2 {
    /// 桌 ID。
    pub table_id: u64,
    /// 手绑定（防重放；与 v1 共享 settled_bindings 集——跨版本重放
    /// 一并阻断，非零）。
    pub hand_binding: [u8; 32],
    /// 策略承诺（桌绑定策略的承诺字节）。
    pub policy_commitment: [u8; 32],
    /// 本手底池（必须 == Σinputs）。
    pub pot: u64,
    /// 混合输入（≥1）。
    pub inputs: Vec<SettleInputV2>,
    /// 赔付输出（v2 账本铸造；非零、同 AssetId、桌绑定一致）。
    pub payouts: Vec<NoteSpec2>,
    /// rake 分账（v1 账本铸造）。
    pub rake: RakeSplitRecord,
}

/// v2 结算效果摘要：覆盖 hand_binding、pot、全部输入承诺、全部输出
/// （owner_commitment, asset_commitment(asset_id), amount）、rake.total。
///
/// 与 v1 [`crate::settlement::settle_effect`] 同纪律（签名覆盖精确
/// 分配结构），输出侧以 owner_commitment（32B）替代裸公钥 (x,y)。
/// TE-M1：赔付段追加 [`asset_commitment`]（TE-M1 变更——资产维度进
/// 签名覆盖，赔付 `asset_id` 被篡改必然摘要失配；输入承诺本身已含
/// 资产身份，无需重复）。v1 / v2 两条输入路径签名消费**同一**效果
/// 摘要——分配结构篡改对两种输入都必然签名失败。
#[must_use]
pub fn settle_effect_v2(record: &SettlementRecordV2) -> [u8; 32] {
    let mut h_input = Vec::with_capacity(record.inputs.len() * 64);
    let mut h_output = Vec::with_capacity(record.payouts.len() * 72);
    for i in &record.inputs {
        let c = match i {
            SettleInputV2::V1 { spend, .. } => spend.commitment,
            SettleInputV2::V2 { note, .. } => note.commitment_bytes(),
        };
        h_input.extend_from_slice(&c);
    }
    for o in &record.payouts {
        h_output.extend_from_slice(&owner_commitment(&o.owner));
        h_output.extend_from_slice(&felt_to_bytes32(&asset_commitment(&o.asset_id)));
        h_output.extend_from_slice(&o.amount.to_be_bytes());
    }
    blake2s32(&[
        DOMAIN_NOTE_V2_SETTLE_EFFECT,
        &record.hand_binding,
        &record.pot.to_be_bytes(),
        &h_input,
        &h_output,
        &record.rake.total.to_be_bytes(),
    ])
}

/// v2 输入的结算花费 scope：`DOMAIN_NOTE_V2_SETTLE_SCOPE ||
/// network_id || abi_version(BE) || hand_binding`。
///
/// 网络与 ABI 版本参与 scope（防跨网重放）；hand_binding 防跨手重放。
#[must_use]
pub fn settle_scope_v2(network_id: &[u8; 32], abi_version: u32, hand_binding: &[u8; 32]) -> Vec<u8> {
    let mut scope = Vec::with_capacity(DOMAIN_NOTE_V2_SETTLE_SCOPE.len() + 36 + 32);
    scope.extend_from_slice(DOMAIN_NOTE_V2_SETTLE_SCOPE);
    scope.extend_from_slice(network_id);
    scope.extend_from_slice(&abi_version.to_be_bytes());
    scope.extend_from_slice(hand_binding);
    scope
}

/// **v2 输入花费验证器**（双 verifier 之 v2 路；sequencer 准入分派点）。
///
/// `input` 必须是 [`SettleInputV2::V2`] 臂（v1 臂进入本函数即
/// fail-closed 拒绝——"v2 输入配 v1 载荷/验签"在分派层被显式阻断）。
/// 顺序即实现，全 fail-closed：
/// 1. nullifier 非零；
/// 2. 信封结构一致（scheme 匹配 + signer 引用合法）；
/// 3. 信封签名者 == note owner（防"他人代签"）；
/// 4. `typed_data_digest == v2_spend_digest(owner, commitment, nullifier,
///    scope, effect)`（scope 必须是 v2 域 + network/abi 绑定——v1 域
///    签名在此必然摘要不一致 → 拒，即"交叉伪造"防线）；
/// 5. 新鲜度（expiry + per-signer nonce 单调）；
/// 6. 按 scheme 分派验签（材料变体不匹配 → MaterialMismatch 拒）。
///
/// # Errors
/// 见 [`crate::owner_v2::OwnerV2Error`] 的稳定类别映射 + 上述第 3 条。
pub fn settle_spend_verifier_v2(
    input: &SettleInputV2,
    scope: &[u8],
    effect: &[u8; 32],
    now: u64,
    last_nonce: Option<u64>,
) -> AppchainResult<()> {
    let (note, nullifier, envelope, material) = match input {
        SettleInputV2::V2 {
            note,
            nullifier,
            envelope,
            material,
        } => (note, nullifier, envelope, material),
        SettleInputV2::V1 { .. } => {
            return Err(AppchainError::AdmissionRejected(
                "v1 input cannot enter the v2 spend verifier",
            ));
        }
    };
    if *nullifier == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected("zero nullifier"));
    }
    validate_envelope(envelope)?;
    if envelope.signer_ref != note.owner {
        return Err(AppchainError::AdmissionRejected(
            "settle v2 envelope signer is not the note owner",
        ));
    }
    let digest = v2_spend_digest(
        &note.owner,
        &note.commitment_bytes(),
        nullifier,
        scope,
        effect,
    );
    if envelope.typed_data_digest != digest {
        return Err(crate::owner_v2::OwnerV2Error::DigestMismatch.into());
    }
    check_envelope_freshness(envelope, now, last_nonce)?;
    verify_owner_signature(
        &envelope.signer_ref,
        &envelope.typed_data_digest,
        &envelope.signature,
        material,
    )?;
    Ok(())
}

/// per-signer 已见最大 nonce 查询（v2 信封新鲜度用）。
pub type NonceLookup<'a> = &'a dyn Fn(&OwnerRef) -> Option<u64>;

/// [`SettlementRecordV2`] 纯函数校验（不触碰账本状态；账本存在性核对
/// 在 sequencer 准入层）。
///
/// fail-closed 清单（顺序即实现）：
/// 1. `hand_binding` 非零；inputs 非空；
/// 2. 单资产隔离（TE-M1）：全部输入、赔付、rake 输出与首输入的
///    `AssetId` 全等（domain 与 token_id 任一不同 →
///    [`AppchainError::AssetMismatch`]）；
/// 3. 输入 nullifier 非零；v1 输入承诺与授权一致、seat 绑定 ==
///    `Some(table_id)`（v1 纪律不变）；v2 输入桌绑定 ∈ {None,
///    Some(table_id)}；
/// 4. `pot == Σinputs`；
/// 5. `rake.total == policy.rake_of(pot)` 且 `policy_commitment` 与冻结
///    策略一致；
/// 6. 赔付非零、桌绑定一致、收款人 OwnerRef 合法；
/// 7. 守恒：`Σinputs == Σpayouts + rake 输出`（TE-M4：FixedRakeBurn 桌为
///    `Σinputs == Σpayouts + rake.total`——rake.total 是已销毁的输出侧，
///    且记录不得携带 treasury/operator 输出）；
/// 8. 分账：treasury/operator 数额与收款人 == `policy.split_of(rake.total)`
///    （TE-M4：FixedRakeBurn 桌跳过分账——处置 = burn，路径隔离）；
/// 9. 逐输入签名：v1 走 `spend_digest`（scope = v1 结算域 +
///    hand_binding）+ `verify_ecsdsa`；v2 走 [`settle_spend_verifier_v2`]。
///    两条路径消费同一 [`settle_effect_v2`]。
///
/// `now` / `nonce_of`：v2 信封新鲜度（expiry / per-signer nonce）。
///
/// # Errors
/// 见 [`AppchainError`] 各变体（每拒绝路径唯一）。
pub fn validate_settlement_v2(
    record: &SettlementRecordV2,
    policy: &FeePolicy,
    network_id: &[u8; 32],
    abi_version: u32,
    now: u64,
    nonce_of: NonceLookup<'_>,
) -> AppchainResult<()> {
    // 1. 非零标识 + 非空
    if record.hand_binding == [0u8; 32] {
        return Err(AppchainError::AdmissionRejected("zero hand binding"));
    }
    if record.inputs.is_empty() {
        return Err(AppchainError::AdmissionRejected("empty settlement inputs"));
    }

    // 2. 单资产隔离（TE-M1：从"同 AssetClass"升级为"同 AssetId"——
    //    全部输入、赔付、rake 输出与首输入的 asset_id 全等；跨域或
    //    同域跨 token 混合一律 AssetMismatch）
    let asset = record.inputs[0].asset_id();
    let mut input_sum: u128 = 0;
    for i in &record.inputs {
        if !i.asset_id().same_asset(asset) {
            return Err(AppchainError::AssetMismatch {
                expected: asset,
                got: i.asset_id(),
            });
        }
        input_sum += u128::from(i.amount());
    }

    // 3. 输入承诺/nullifier/桌绑定
    for i in &record.inputs {
        i.declared_nullifier()?;
        match i {
            SettleInputV2::V1 { note, spend } => {
                if note.table_id != Some(record.table_id) {
                    return Err(AppchainError::AdmissionRejected("seat note table mismatch"));
                }
                if felt_to_bytes32(&note.commitment()) != spend.commitment {
                    return Err(AppchainError::AdmissionRejected("spend commitment mismatch"));
                }
            }
            SettleInputV2::V2 { note, .. } => {
                // v2 输入桌绑定：seat note 必须绑本桌；自由余额（None）
                // 允许参与（v2 seat 生命周期未引入，ABI_V2.md 如实记录）
                if matches!(note.table_id, Some(id) if id != record.table_id) {
                    return Err(AppchainError::AdmissionRejected("v2 input table mismatch"));
                }
                validate_owner_ref(&note.owner)?;
            }
        }
    }

    // 4. pot == Σinputs（v2 单层 contested 口径）
    if u128::from(record.pot) != input_sum {
        return Err(AppchainError::AdmissionRejected(
            "pot does not equal sum of inputs",
        ));
    }

    // 5. 费率 + 策略承诺绑定
    let rake_total = u128::from(record.rake.total);
    let expected_rake = u128::from(policy.rake_of(record.pot));
    if expected_rake != rake_total {
        return Err(AppchainError::FeeMismatch {
            expected: expected_rake,
            got: rake_total,
        });
    }
    if policy.commitment_bytes() != record.policy_commitment {
        return Err(AppchainError::FeeMismatch {
            expected: rake_total,
            got: rake_total,
        });
    }

    // 6. 赔付：非零、同资产、桌绑定、owner 合法（v2 赔付与 v1 rake 输出
    //    类型不同——NoteSpec2 / NoteSpec——分开校验，规则一致）。
    //    TE-M1：赔付按 asset_id 全等；rake 输出是 v1 `NoteSpec`
    //    （`asset_class`，v1 账本铸造），经冻结映射 `of_v1` 升维后与
    //    记录资产比对——非遗留资产（REAL 非 NATIVE / GAME 非遗留）在
    //    v1 账本无表示，比对必不等 → fail-closed 拒。TE-M4：FixedRakeBurn
    //    桌的 rake 处置 = burn，记录**不携带** rake 输出（携带即拒，见下），
    //    其守恒处理在 7/8 两步。
    let burn_disposal = matches!(policy, FeePolicy::FixedRakeBurn { .. });
    // TE-M4（最小 match 臂，先例注明）：burn 桌携带 treasury/operator 输出
    // 即"既入账又销毁"的双计形态——在资产/守恒检查前拒绝（诊断精确），
    // 处置落点在 sequencer `apply_settle_v2`（game_burned 记账）与合约侧
    // `rake_disposal`。
    if burn_disposal
        && (record.rake.treasury_out.is_some() || record.rake.operator_out.is_some())
    {
        return Err(AppchainError::AdmissionRejected(
            "fixed rake burn settlement must not carry treasury/operator outputs",
        ));
    }
    let mut output_sum: u128 = 0;
    for o in &record.payouts {
        if !o.asset_id.same_asset(asset) {
            return Err(AppchainError::AssetMismatch {
                expected: asset,
                got: o.asset_id,
            });
        }
        if o.amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        if matches!(o.table_id, Some(id) if id != record.table_id) {
            return Err(AppchainError::AdmissionRejected("payout table binding mismatch"));
        }
        validate_owner_ref(&o.owner)?;
        output_sum += u128::from(o.amount);
    }
    for o in record.rake.treasury_out.iter().chain(record.rake.operator_out.iter()) {
        let rake_asset = AssetId::of_v1(o.asset_class);
        if !rake_asset.same_asset(asset) {
            return Err(AppchainError::AssetMismatch {
                expected: asset,
                got: rake_asset,
            });
        }
        if o.amount == 0 {
            return Err(AppchainError::InvalidAmount(0));
        }
        if matches!(o.table_id, Some(id) if id != record.table_id) {
            return Err(AppchainError::AdmissionRejected("payout table binding mismatch"));
        }
        output_sum += u128::from(o.amount);
    }

    // 7. 守恒（TE-M4：burn 桌的 rake.total 是**已销毁的输出侧**——
    //    `Σinputs == Σpayouts + 销毁额`；非 burn 桌销毁额恒 0，等式与
    //    既有 `Σinputs == Σoutputs` 逐点一致，零回退）。
    let burned_rake = if burn_disposal { rake_total } else { 0 };
    if input_sum != output_sum + burned_rake {
        return Err(AppchainError::ConservationViolated {
            inputs: input_sum,
            outputs: output_sum + burned_rake,
            rake: rake_total,
        });
    }

    // 8. 分账（数额 + 收款人）。TE-M4：burn 桌与 percentage 分账路径隔离
    //    （携带输出已在第 6 条拒），burn 记录直接跳过分账检查。
    if !burn_disposal {
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
                let o = record.rake.operator_out.as_ref().ok_or(AppchainError::FeeMismatch {
                    expected: u128::from(o_exp),
                    got: 0,
                })?;
                if t.amount != t_exp || o.amount != o_exp {
                    return Err(AppchainError::FeeMismatch {
                        expected: u128::from(t_exp + o_exp),
                        got: u128::from(t.amount + o.amount),
                    });
                }
                if let FeePolicy::FixedRake { split, .. } = policy
                    && (t.owner != split.treasury || o.owner != split.operator)
                {
                    return Err(AppchainError::FeeMismatch {
                        expected: u128::from(t_exp + o_exp),
                        got: u128::from(t.amount + o.amount),
                    });
                }
            }
        }
    }

    // 9. 逐输入签名（双 verifier 分派）
    let effect = settle_effect_v2(record);
    let scope_v1 = settle_spend_scope(&record.hand_binding);
    let scope_v2 = settle_scope_v2(network_id, abi_version, &record.hand_binding);
    for i in &record.inputs {
        match i {
            SettleInputV2::V1 { note, spend } => {
                let d = spend_digest(&spend.commitment, &spend.nullifier, &scope_v1, &effect);
                verify_ecsdsa(&note.owner, &d, &spend.sig)?;
            }
            SettleInputV2::V2 { note, .. } => {
                settle_spend_verifier_v2(i, &scope_v2, &effect, now, nonce_of(&note.owner))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::OwnerKey;
    // MigrateNoteRecord（v1 层身份字段，冻结）仍用 v1 AssetClass
    use crate::note::AssetClass;
    use crate::owner_v2::{legacy_account_id, SignatureScheme};
    use crate::settlement::SpendAuth;

    /// secp 测试密钥。
    fn secp_key(seed: u8) -> OwnerKey {
        OwnerKey::from_seed(&[seed; 32]).unwrap()
    }

    /// Legacy OwnerRef。
    fn legacy_ref(key: &OwnerKey, key_version: u32) -> OwnerRef {
        OwnerRef {
            scheme: SignatureScheme::LegacySecp256k1,
            account_id: legacy_account_id(&key.public_bytes()),
            key_version,
            binding_id: None,
        }
    }

    /// StarkCurve OwnerRef。
    fn stark_ref(seed: u64, key_version: u32) -> OwnerRef {
        OwnerRef {
            scheme: SignatureScheme::StarkCurve,
            account_id: starknet_crypto::get_public_key(&starknet_crypto::FieldElement::from(seed))
                .to_bytes_be(),
            key_version,
            binding_id: None,
        }
    }

    fn note_v2(owner: OwnerRef, amount: u64, nonce: u64, asset: AssetId) -> NoteV2 {
        NoteV2::new(asset, amount, owner, nonce, None, 0, 0).unwrap()
    }

    #[test]
    fn commitment_is_deterministic_and_sensitive() {
        let o = legacy_ref(&secp_key(1), 0);
        let a = note_v2(o.clone(), 100, 1, AssetId::REAL_NATIVE);
        let b = note_v2(o.clone(), 100, 1, AssetId::REAL_NATIVE);
        assert_eq!(a.commitment(), b.commitment());
        // 面额敏感
        assert_ne!(a.commitment(), note_v2(o.clone(), 101, 1, AssetId::REAL_NATIVE).commitment());
        // nonce 敏感
        assert_ne!(a.commitment(), note_v2(o.clone(), 100, 2, AssetId::REAL_NATIVE).commitment());
        // 资产身份隔离（TE-M1：domain 与 token_id 任一不同承诺必不同）
        assert_ne!(a.commitment(), note_v2(o.clone(), 100, 1, AssetId::GAME_PLAY).commitment());
        assert_ne!(a.commitment(), note_v2(o.clone(), 100, 1, AssetId::REAL_USDT).commitment());
        // pot/runout 投影参与承诺
        let mut proj = a.clone();
        proj.pot_index = 1;
        assert_ne!(a.commitment(), proj.commitment());
        // 桌绑定参与承诺
        let seated = NoteV2::new(AssetId::REAL_NATIVE, 100, o.clone(), 1, Some(7), 0, 0).unwrap();
        assert_ne!(a.commitment(), seated.commitment());
    }

    /// TE-M1：同资产断言从 AssetClass 升级为 AssetId 全等（同域跨 token
    /// 也拒——v1 二元模型表达不了的负例）。
    #[test]
    fn same_asset_assertion_is_asset_id_exact() {
        let o = stark_ref(0x51, 0);
        let native = note_v2(o.clone(), 10, 1, AssetId::REAL_NATIVE);
        let usdt = note_v2(o.clone(), 10, 2, AssetId::REAL_USDT);
        let play = note_v2(o, 10, 3, AssetId::GAME_PLAY);
        assert!(native.assert_same_asset(&native).is_ok());
        assert!(matches!(
            native.assert_same_asset(&play),
            Err(AppchainError::AssetMismatch { expected: AssetId::REAL_NATIVE, got: AssetId::GAME_PLAY })
        ));
        assert!(matches!(
            native.assert_same_asset(&usdt),
            Err(AppchainError::AssetMismatch { expected: AssetId::REAL_NATIVE, got: AssetId::REAL_USDT })
        ));
    }

    #[test]
    fn commitment_separates_schemes_and_key_versions() {
        let key = secp_key(2);
        let v0 = note_v2(legacy_ref(&key, 0), 50, 1, AssetId::GAME_PLAY);
        let v1 = note_v2(legacy_ref(&key, 1), 50, 1, AssetId::GAME_PLAY);
        assert_ne!(v0.commitment(), v1.commitment(), "key_version must separate commitments");
        // 同一 felt account_id 跨 scheme 必不同
        let account = stark_ref(0xBEE, 0).account_id;
        let stark = note_v2(
            OwnerRef { scheme: SignatureScheme::StarkCurve, account_id: account, key_version: 0, binding_id: None },
            50, 1, AssetId::GAME_PLAY,
        );
        let legacy = note_v2(
            OwnerRef { scheme: SignatureScheme::LegacySecp256k1, account_id: account, key_version: 0, binding_id: None },
            50, 1, AssetId::GAME_PLAY,
        );
        assert_ne!(stark.commitment(), legacy.commitment());
    }

    #[test]
    fn nullifier_binds_secret_scheme_and_scope() {
        let o = stark_ref(0xACE, 0);
        let n = note_v2(o.clone(), 80, 3, AssetId::REAL_NATIVE);
        let net = default_network_id();
        let scope = spend_scope(&net, 2, b"transfer.v2");
        assert_ne!(n.nullifier(&[1u8; 32], &scope), n.nullifier(&[2u8; 32], &scope));
        // scope 敏感
        assert_ne!(
            n.nullifier(&[1u8; 32], &scope),
            n.nullifier(&[1u8; 32], &spend_scope(&net, 2, b"settle.v2"))
        );
        // network_id 参与（防跨网重放）
        assert_ne!(
            n.nullifier(&[1u8; 32], &scope),
            n.nullifier(&[1u8; 32], &spend_scope(&[9u8; 32], 2, b"transfer.v2"))
        );
        // abi_version 参与
        assert_ne!(
            n.nullifier(&[1u8; 32], &scope),
            n.nullifier(&[1u8; 32], &spend_scope(&net, 3, b"transfer.v2"))
        );
        // scheme 经 owner_commitment 参与派生
        let same_key_other_scheme = note_v2(legacy_ref(&secp_key(1), 0), 80, 3, AssetId::REAL_NATIVE);
        assert_ne!(n.nullifier(&[1u8; 32], &scope), same_key_other_scheme.nullifier(&[1u8; 32], &scope));
    }

    #[test]
    fn zero_amount_and_bad_owner_rejected() {
        let o = legacy_ref(&secp_key(1), 0);
        assert!(NoteV2::new(AssetId::REAL_NATIVE, 0, o.clone(), 1, None, 0, 0).is_err());
        let bad = OwnerRef {
            scheme: SignatureScheme::StarkCurve,
            account_id: [0u8; 32],
            key_version: 0,
            binding_id: None,
        };
        assert!(NoteV2::new(AssetId::REAL_NATIVE, 1, bad, 1, None, 0, 0).is_err());
    }

    /// 结构合法的迁移记录夹具（migration_nullifier 只依赖字段，不需签名）。
    fn fixture_migrate_record() -> MigrateNoteRecord {
        use crate::owner_v2::OWNER_V2_ABI_VERSION;
        MigrateNoteRecord {
            old_commitment: blake2s32(&[b"fixture old commitment"]),
            old_owner_sig: SignatureEnvelope {
                scheme: SignatureScheme::LegacySecp256k1,
                signer_ref: OwnerRef {
                    scheme: SignatureScheme::LegacySecp256k1,
                    account_id: blake2s32(&[b"fixture account"]),
                    key_version: 0,
                    binding_id: None,
                },
                typed_data_digest: [1u8; 32],
                signature: [0u8; 64],
                nonce: 1,
                expiry: u64::MAX,
            },
            new_owner_ref: stark_ref(77, 0),
            amount: 100,
            asset_class: AssetClass::Play,
            migration_nonce: blake2s32(&[b"fixture migration nonce"]),
            network_id: default_network_id(),
            abi_version: OWNER_V2_ABI_VERSION,
        }
    }

    #[test]
    fn migration_nullifier_is_deterministic_and_record_bound() {
        let r = fixture_migrate_record();
        let n1 = migration_nullifier(&r);
        assert_eq!(n1, migration_nullifier(&r));
        let mut r2 = r.clone();
        r2.migration_nonce[0] ^= 0x01;
        assert_ne!(n1, migration_nullifier(&r2));
        let mut r3 = r.clone();
        r3.old_commitment[31] ^= 0x01;
        assert_ne!(n1, migration_nullifier(&r3));
        // 与 v2 note nullifier 域分离
        let o = legacy_ref(&secp_key(3), 0);
        let n = note_v2(o, 1, 1, AssetId::GAME_PLAY);
        assert_ne!(n1, n.nullifier(&[1u8; 32], &spend_scope(&default_network_id(), 2, b"x")));
    }

    #[test]
    fn borsh_roundtrip_note_v2_and_spec2() {
        let o = stark_ref(0xF00, 2);
        let n = NoteV2::new(AssetId::REAL_NATIVE, 500, o.clone(), 9, Some(3), 1, 0).unwrap();
        let bytes = borsh::to_vec(&n).unwrap();
        let back: NoteV2 = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back, n);
        let spec = NoteSpec2 {
            asset_id: AssetId::GAME_PLAY,
            amount: 5,
            owner: o,
            table_id: None,
            pot_index: 0,
            runout_index: 0,
        };
        let minted = spec.clone().mint(42).unwrap();
        assert_eq!(minted.amount, 5);
        assert_eq!(minted.nonce, 42);
        assert_eq!(minted.asset_id, AssetId::GAME_PLAY);
        let _ = spec;
    }

    /// SpendAuth 夹具构造（v1 输入路径单元辅助）。
    #[allow(dead_code)]
    fn dummy_spend(commitment: [u8; 32]) -> SpendAuth {
        SpendAuth {
            commitment,
            nullifier: blake2s32(&[b"fixture nullifier"]),
            sig: crate::keys::EcdsaSig { bytes: [0u8; 64] },
        }
    }
}
