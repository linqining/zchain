//! ABI v2（plan-appchain §6.12.1b）：带 scheme 的 OwnerRef、版本化
//! SignatureEnvelope、MigrateNote 迁移记录。
//!
//! 双轨方案的"完整路径"落地面：承诺/摘要/校验关系全部显式携带
//! OwnerRef 的 scheme + key_version，防止同一公钥在不同验证器下产生
//! 同一承诺（v2 Note commitment / nullifier scope / Operation digest /
//! payout leaf 必须含 scheme/version——本模块提供承诺与摘要原语）。
//!
//! ## 边界（v2 正式版接入后更新；原 alpha 边界已按排期落地）
//!
//! v2 正式版（排期 §1"ABI v2 正式版"）已接入链准入：[`MigrateNoteRecord`]
//! 经 `Operation::MigrateNote`（borsh 判别值见 docs/ABI_V2.md）进入
//! sequencer 准入与应用（消费旧 v1 note → 铸 [`crate::note_v2::NoteV2`]），
//! v2 结算输入走 [`verify_owner_signature`]（见 `crate::note_v2` 的
//! 混合结算校验）。**仍属边界（如实声明）**：
//!
//! - `StarknetAccountBinding` 的 alpha 限制**继承**：验签落地为"SNIP-12
//!   授权摘要格式 + 会话密钥 ECDSA"，SNIP-12 typed-data 的 keccak 重算、
//!   授权内 delegated key 与 account 的绑定复核、链上 account contract
//!   verifier 仍属后续版本；`binding_id` 的锚定关系由 registry 侧保证；
//! - **canonical AIR 未扩展到 v2 owner**：v2 输入验签/nullifier 规则是
//!   host 侧校验关系，AIR 约束与批次证明当前仍只覆盖 v1 关系——v2 结算
//!   的 STARK 证明边界见 docs/ABI_V2.md §边界；
//! - 迁移/混合结算的 `VerifierMaterial` 呈递是准入时证据（MigrateNote
//!   op 的 borsh 载荷只含 record + minted；材料经
//!   `Sequencer::submit_migrate` 呈递，重放侧复核材料无关的全部关系，
//!   见 [`validate_migrate_note_structure`]）。
//!
//! ## 摘要层选型
//!
//! 与 AIR 绑定层一致（docs/ABI.md §4.1 哈希选型记录）：全部摘要用
//! **Poseidon252 + 域分隔标签**（[`crate::felt::domain_felt`]，32B 值按
//! hi/lo 无损拆分），输出恒为 canonical felt——StarkCurve 验签直接以摘要
//! 为消息 felt，无需二次编码；Legacy secp256k1 与会话密钥（也是 secp）
//! 路径按 32B 字节消费同一摘要。
//!
//! ## 三种 scheme 的验签形态
//!
//! - `LegacySecp256k1`：`account_id = blake2s32(压缩公钥 33B)`（32B key-id，
//!   见 [`legacy_account_id`]）；验签要求呈递完整压缩公钥，呈递键哈希必须
//!   等于 `account_id` 后走 ECDSA compact 验证（复用 [`crate::keys`] 原语）。
//! - `StarkCurve`：`account_id` 即规范化 felt252 公钥（32B 大端，非零、
//!   < 域模数）；`starknet_crypto::verify` 直接验证 (r, s)。
//! - `StarknetAccountBinding`：`account_id` 是 Starknet 账户地址，
//!   `binding_id` 指向已锚定的 `AuthorizeZChainKey` 授权记录。验签落地为
//!   验 binding 授权摘要格式（canonical 非零 felt）加会话密钥（SNIP-12
//!   delegated key，secp256k1）对 binding 摘要的签名；SNIP-12 typed-data
//!   的 keccak 重算（授权内 delegated key 与 account 的绑定复核）与链上
//!   account contract verifier 属后续版本（边界见上）。
//!   互操作性由冻结向量钉住（见 `tests/owner_v2.rs`，来源
//!   poker-wallet `account_binding` 的 SNIP-12 rev1 实现）。

use starknet_crypto::{FieldElement, poseidon_hash_many};

use crate::error::AppchainError;
use crate::felt::{
    bytes32_to_felts, domain_felt, felt_from_bytes32_exact, felt_from_u64, felt_to_bytes32,
};
use crate::keys::blake2s32;
use crate::note::AssetClass;

// ---------------------------------------------------------------------------
// 域标签（冻结；变更必须升 `.v2` 并同步 docs/ABI.md 附录）
// ---------------------------------------------------------------------------

/// 域标签：v2 owner 引用承诺。
pub const DOMAIN_OWNER_REF_V2: &[u8] = b"zchain.owner_v2.owner_ref.v1";
/// 域标签：v2 花费摘要（对应 v1 的 `poker-appchain.spend.digest.v1`）。
pub const DOMAIN_OWNER_V2_SPEND: &[u8] = b"zchain.owner_v2.spend.v1";
/// 域标签：v2 迁移记录摘要。
pub const DOMAIN_OWNER_V2_MIGRATE: &[u8] = b"zchain.owner_v2.migrate.v1";
/// 域标签：Starknet 账户绑定（授权摘要 + 会话密钥）派生摘要。
pub const DOMAIN_OWNER_V2_BINDING: &[u8] = b"zchain.owner_v2.binding.v1";

/// v2-alpha 目标 ABI 版本（`MigrateNoteRecord.abi_version` 的合法值）。
pub const OWNER_V2_ABI_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// 错误类型（模块自包含；不与 v1 error.rs 抢字段，稳定类别经 From 映射）
// ---------------------------------------------------------------------------

/// owner_v2 统一错误（fail-closed：任何未覆盖语义一律拒绝）。
#[derive(Debug, thiserror::Error)]
pub enum OwnerV2Error {
    /// 签名验证失败或签名/摘要字节非法（不区分格式错误与验证错误）。
    #[error("owner_v2 signature invalid or missing")]
    BadSignature,
    /// 信封已过期（`now >= expiry`）。
    #[error("owner_v2 envelope expired: now={now} >= expiry={expiry}")]
    Expired {
        /// 当前 unix 秒。
        now: u64,
        /// 信封过期 unix 秒。
        expiry: u64,
    },
    /// nonce 重放（不严格大于已见 nonce）。
    #[error("owner_v2 nonce replay: got={got}, last={last}")]
    NonceReplay {
        /// 信封携带的 nonce。
        got: u64,
        /// 已见的最大 nonce。
        last: u64,
    },
    /// 信封 `typed_data_digest` 与记录重算摘要不一致。
    #[error("owner_v2 typed-data digest mismatch against recomputed record digest")]
    DigestMismatch,
    /// scheme 相关字段不一致（信封 scheme ≠ signer_ref scheme 等）。
    #[error("owner_v2 scheme mismatch: {0}")]
    SchemeMismatch(&'static str),
    /// OwnerRef 结构非法（account_id 非规范 felt / binding_id 缺失或多余）。
    #[error("owner_v2 owner ref invalid: {0}")]
    OwnerRefInvalid(&'static str),
    /// 必须非零的字段为零（旧承诺 / migration_nonce / account_id 等）。
    #[error("owner_v2 required field is zero: {0}")]
    ZeroField(&'static str),
    /// 金额非法（0 面额）。
    #[error("owner_v2 invalid note amount: {0}")]
    InvalidAmount(u64),
    /// 验签材料与 scheme 不匹配（变体给错 / 材料字段非法）。
    #[error("owner_v2 verifier material does not match scheme: {0}")]
    MaterialMismatch(&'static str),
}

/// 带 stable category 的 Result 别名。
pub type OwnerV2Result<T> = Result<T, OwnerV2Error>;

/// 映射到 v1 统一错误稳定类别（供未来 v2 准入接入复用；本 alpha 不接链）。
///
/// - `BadSignature` → [`AppchainError::BadSignature`]；
/// - `Expired` → [`AppchainError::OutOfRange`]；`NonceReplay` →
///   [`AppchainError::SettlementReplay`]（同为重放防线）；
/// - `InvalidAmount` → [`AppchainError::InvalidAmount`]；
/// - 其余结构非法 → [`AppchainError::AdmissionRejected`]（静态短语，
///   保留 fail-closed 单变体语义）。
impl From<OwnerV2Error> for AppchainError {
    fn from(e: OwnerV2Error) -> Self {
        match e {
            OwnerV2Error::BadSignature => AppchainError::BadSignature,
            OwnerV2Error::Expired { .. } => AppchainError::OutOfRange("owner_v2 envelope expired"),
            OwnerV2Error::NonceReplay { .. } => AppchainError::SettlementReplay,
            OwnerV2Error::InvalidAmount(a) => AppchainError::InvalidAmount(a),
            OwnerV2Error::DigestMismatch => {
                AppchainError::AdmissionRejected("owner_v2 digest mismatch")
            }
            OwnerV2Error::SchemeMismatch(_) => {
                AppchainError::AdmissionRejected("owner_v2 scheme mismatch")
            }
            OwnerV2Error::OwnerRefInvalid(_) => {
                AppchainError::AdmissionRejected("owner_v2 owner ref invalid")
            }
            OwnerV2Error::ZeroField(_) => AppchainError::AdmissionRejected("owner_v2 zero field"),
            OwnerV2Error::MaterialMismatch(_) => {
                AppchainError::AdmissionRejected("owner_v2 material mismatch")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 类型（borsh 稳定 ABI；判别值冻结）
// ---------------------------------------------------------------------------

/// 签名方案（v2 ABI 判别值**冻结**：LegacySecp256k1=0 / StarkCurve=1 /
/// StarknetAccountBinding=2；新增方案只能追加新判别值，不得复用）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SignatureScheme {
    /// v1 既有 secp256k1 ECDSA（迁移期并存；治理关闭 legacy 前长期存在）。
    LegacySecp256k1 = 0,
    /// Stark 曲线（felt252 公钥）裸签名。
    StarkCurve = 1,
    /// Starknet 合约账户 + SNIP-12 `AuthorizeZChainKey` 授权的会话密钥。
    StarknetAccountBinding = 2,
}

impl SignatureScheme {
    /// ABI 数值（冻结判别值）。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 从 ABI 数值解析。
    ///
    /// # Errors
    /// 未定义数值拒绝（fail-closed）。
    pub fn from_u8(v: u8) -> OwnerV2Result<Self> {
        match v {
            0 => Ok(Self::LegacySecp256k1),
            1 => Ok(Self::StarkCurve),
            2 => Ok(Self::StarknetAccountBinding),
            _ => Err(OwnerV2Error::SchemeMismatch("undefined discriminant")),
        }
    }
}

/// 带 scheme 的 owner 引用（ABI v2；替代 v1 `Note.owner: [u8; 33]` 的
/// 裸公钥形态）。
///
/// `account_id` 语义按 scheme：
/// - `LegacySecp256k1`：[`legacy_account_id`]（压缩公钥的 blake2s32 key-id）；
/// - `StarkCurve`：规范化 felt252 公钥（32B 大端，非零、< 域模数）；
/// - `StarknetAccountBinding`：Starknet 账户地址（canonical felt）。
///
/// `key_version` 参与全部摘要（同公钥换版本即换身份，支持密钥轮换）；
/// `binding_id` 仅 `StarknetAccountBinding` 允许 Some（指向已锚定的
/// `AuthorizeZChainKey` 授权记录）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct OwnerRef {
    /// 签名方案（判别值冻结）。
    pub scheme: SignatureScheme,
    /// 32B 规范标识（语义按 scheme，见结构体文档）。
    pub account_id: [u8; 32],
    /// 密钥版本（参与摘要；同公钥换版本即换身份）。
    pub key_version: u32,
    /// 账户绑定授权记录 id（仅 StarknetAccountBinding）。
    pub binding_id: Option<[u8; 32]>,
}

/// 版本化签名信封：一次授权的完整载体（scheme 自描述，验签材料按 scheme
/// 外部呈递，见 [`VerifierMaterial`]）。
///
/// `signature` 载荷按 scheme：
/// - `LegacySecp256k1`：64B r‖s compact ECDSA over `typed_data_digest`；
/// - `StarkCurve`：64B r‖s，各为 canonical felt；
/// - `StarknetAccountBinding`：会话密钥（secp256k1 delegated key）对
///   binding 摘要（[`binding_authorization_digest`]）的 64B compact ECDSA。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SignatureEnvelope {
    /// 签名方案（必须与 `signer_ref.scheme` 一致，fail-closed）。
    pub scheme: SignatureScheme,
    /// 签名者 owner 引用。
    pub signer_ref: OwnerRef,
    /// 被签 typed-data 摘要（32B；迁移路径下必须等于 [`migrate_digest`]）。
    pub typed_data_digest: [u8; 32],
    /// 64B 签名载荷（编码按 scheme，见结构体文档）。
    pub signature: [u8; 64],
    /// 防重放 nonce（单调递增：必须严格大于该 signer 已见的最大 nonce）。
    pub nonce: u64,
    /// 过期 unix 秒（`now >= expiry` 即过期，fail-closed）。
    pub expiry: u64,
}

/// MigrateNote 迁移记录（plan §6.12.1b 规则 2）：旧 owner 授权消费旧
/// note → 同额同资产类铸 v2 note。
///
/// 本 alpha 只定义记录与校验关系（[`validate_migrate_note`]，AIR witness
/// 形状就绪）；迁移进 proof/checkpoint 与 v1 链准入的接入属 v2 正式版。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct MigrateNoteRecord {
    /// 被消费的 v1 note 承诺（非零）。
    pub old_commitment: [u8; 32],
    /// 旧 owner 授权信封（`typed_data_digest` 必须等于本记录重算摘要）。
    pub old_owner_sig: SignatureEnvelope,
    /// 铸出的 v2 note owner 引用（同额同资产类）。
    pub new_owner_ref: OwnerRef,
    /// 面额（> 0；必须与旧 note 同额）。
    pub amount: u64,
    /// 资产类（必须与旧 note 同类；REAL/PLAY 隔离语义不变）。
    pub asset_class: AssetClass,
    /// 迁移防重放 nonce（非零；链侧记录后不得复用）。
    pub migration_nonce: [u8; 32],
    /// 目标 ZChain network id（32B 规范字节；防跨网重放）。
    pub network_id: [u8; 32],
    /// 目标 ABI 版本（本 alpha 恒 [`OWNER_V2_ABI_VERSION`]）。
    pub abi_version: u32,
}

// ---------------------------------------------------------------------------
// 校验辅助
// ---------------------------------------------------------------------------

/// Legacy scheme 的 `account_id` 派生：`blake2s32(压缩公钥 33B)`。
///
/// 32B key-id 与 v2 摘要层同宽；验签时呈递完整压缩公钥并复核哈希一致
/// （fail-closed），密钥本体不入 OwnerRef。
#[must_use]
pub fn legacy_account_id(compressed_public: &[u8; 33]) -> [u8; 32] {
    blake2s32(&[compressed_public])
}

/// OwnerRef 结构合法性（纯函数；所有路径 fail-closed）：
/// - `account_id` 非零；
/// - `StarkCurve` / `StarknetAccountBinding`：`account_id` 必须是 canonical
///   felt（< 域模数）；
/// - `StarknetAccountBinding`：`binding_id` 必须 Some 且非零；
/// - 其余 scheme：`binding_id` 必须 None（无意义的绑定 id 拒绝）。
///
/// # Errors
/// 见 [`OwnerV2Error::OwnerRefInvalid`] / [`OwnerV2Error::ZeroField`]。
pub fn validate_owner_ref(owner: &OwnerRef) -> OwnerV2Result<()> {
    if owner.account_id == [0u8; 32] {
        return Err(OwnerV2Error::ZeroField("account_id"));
    }
    match owner.scheme {
        SignatureScheme::LegacySecp256k1 => {
            if owner.binding_id.is_some() {
                return Err(OwnerV2Error::OwnerRefInvalid(
                    "binding_id must be None for LegacySecp256k1",
                ));
            }
            Ok(())
        }
        SignatureScheme::StarkCurve => {
            felt_from_bytes32_exact(&owner.account_id).map_err(|_| {
                OwnerV2Error::OwnerRefInvalid("StarkCurve account_id not canonical felt")
            })?;
            if owner.binding_id.is_some() {
                return Err(OwnerV2Error::OwnerRefInvalid(
                    "binding_id must be None for StarkCurve",
                ));
            }
            Ok(())
        }
        SignatureScheme::StarknetAccountBinding => {
            let addr = felt_from_bytes32_exact(&owner.account_id).map_err(|_| {
                OwnerV2Error::OwnerRefInvalid("binding account_id not canonical felt")
            })?;
            if addr == FieldElement::ZERO {
                return Err(OwnerV2Error::ZeroField("binding account_id"));
            }
            match owner.binding_id {
                Some(id) if id != [0u8; 32] => Ok(()),
                _ => Err(OwnerV2Error::OwnerRefInvalid(
                    "StarknetAccountBinding requires a nonzero binding_id",
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 摘要/承诺函数（域分离；全部 Poseidon + hi/lo 无损拆分，输出恒 canonical felt）
// ---------------------------------------------------------------------------

/// OwnerRef 承诺：scheme + key_version + account_id + binding_id 全参与。
///
/// 同 `account_id` 不同 scheme（或不同 `key_version`）必得不同承诺——
/// 防同一公钥跨验证器同承诺。输出为 canonical felt 的 32B 编码。
#[must_use]
pub fn owner_commitment(owner: &OwnerRef) -> [u8; 32] {
    let (a_hi, a_lo) = bytes32_to_felts(&owner.account_id);
    let (flag, b_hi, b_lo) = match &owner.binding_id {
        None => (FieldElement::ZERO, FieldElement::ZERO, FieldElement::ZERO),
        Some(id) => {
            let (hi, lo) = bytes32_to_felts(id);
            (FieldElement::from(1u64), hi, lo)
        }
    };
    felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_OWNER_REF_V2),
        felt_from_u64(u64::from(owner.scheme.as_u8())),
        felt_from_u64(u64::from(owner.key_version)),
        a_hi,
        a_lo,
        flag,
        b_hi,
        b_lo,
    ]))
}

/// v2 花费摘要：域 `zchain.owner_v2.spend.v1`，绑定 owner 承诺（含
/// scheme/version）+（note 承诺, nullifier, 操作 scope, 效果摘要）四要素。
///
/// 对应 v1 [`crate::keys::spend_digest`] 的 v2 形态：owner 侧不再是裸
/// 32B 公钥而是 [`owner_commitment`]，使同一公钥在不同 scheme/version
/// 下的授权互不通用。scope 为变长字节，取 `blake2s32(scope)` 后无损拆分
/// （scope 标签是短常量串，域分离足够）。
#[must_use]
pub fn v2_spend_digest(
    owner: &OwnerRef,
    commitment: &[u8; 32],
    nullifier: &[u8; 32],
    scope: &[u8],
    effect: &[u8; 32],
) -> [u8; 32] {
    let (c_hi, c_lo) = bytes32_to_felts(commitment);
    let (n_hi, n_lo) = bytes32_to_felts(nullifier);
    let (s_hi, s_lo) = bytes32_to_felts(&blake2s32(&[scope]));
    let (e_hi, e_lo) = bytes32_to_felts(effect);
    let (o_hi, o_lo) = bytes32_to_felts(&owner_commitment(owner));
    felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_OWNER_V2_SPEND),
        o_hi,
        o_lo,
        c_hi,
        c_lo,
        n_hi,
        n_lo,
        s_hi,
        s_lo,
        e_hi,
        e_lo,
    ]))
}

/// MigrateNote 摘要：域 `zchain.owner_v2.migrate.v1`，绑定记录全部语义
/// 字段（旧承诺、旧信封 scheme/signer/nonce/expiry、新 owner、金额、
/// 资产类、migration_nonce、network_id、abi_version）。
///
/// **sighash 规则**：`old_owner_sig.typed_data_digest` 与签名字节本身
/// 不参与（前者必须**等于**本摘要，后者是见证工件）——否则自指循环。
#[must_use]
pub fn migrate_digest(record: &MigrateNoteRecord) -> [u8; 32] {
    let (oc_hi, oc_lo) = bytes32_to_felts(&record.old_commitment);
    let (s_hi, s_lo) = bytes32_to_felts(&owner_commitment(&record.old_owner_sig.signer_ref));
    let (mn_hi, mn_lo) = bytes32_to_felts(&record.migration_nonce);
    let (net_hi, net_lo) = bytes32_to_felts(&record.network_id);
    let (n_hi, n_lo) = bytes32_to_felts(&owner_commitment(&record.new_owner_ref));
    felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_OWNER_V2_MIGRATE),
        oc_hi,
        oc_lo,
        felt_from_u64(u64::from(record.old_owner_sig.scheme.as_u8())),
        s_hi,
        s_lo,
        felt_from_u64(record.old_owner_sig.nonce),
        felt_from_u64(record.old_owner_sig.expiry),
        n_hi,
        n_lo,
        felt_from_u64(record.amount),
        felt_from_u64(u64::from(record.asset_class.as_u8())),
        mn_hi,
        mn_lo,
        net_hi,
        net_lo,
        felt_from_u64(u64::from(record.abi_version)),
    ]))
}

/// Starknet 账户绑定的 appchain 侧派生摘要：绑定（账户地址, binding_id,
/// SNIP-12 授权摘要, 会话密钥, 授权终点）。
///
/// 会话密钥对本摘要签名（[`verify_account_binding`]）；SNIP-12 授权摘要
/// 由钱包侧 SNIP-12 rev1 编码器产出（互操作向量见 `tests/owner_v2.rs`）。
///
/// # Errors
/// 任一 felt 输入非 canonical / 会话密钥派生失败 →
/// [`OwnerV2Error::OwnerRefInvalid`]。
pub fn binding_authorization_digest(
    account_address: &[u8; 32],
    binding_id: &[u8; 32],
    snip12_authorize_digest: &[u8; 32],
    session_public: &[u8; 33],
    binding_valid_until: u64,
) -> OwnerV2Result<[u8; 32]> {
    let addr = canonical_felt(account_address, "account_address")?;
    let binding = canonical_felt(binding_id, "binding_id")?;
    let snip12 = canonical_felt(snip12_authorize_digest, "snip12_authorize_digest")?;
    if *session_public == [0u8; 33] {
        return Err(OwnerV2Error::ZeroField("session_public"));
    }
    let (sp_hi, sp_lo) = bytes32_to_felts(&blake2s32(&[session_public]));
    Ok(felt_to_bytes32(&poseidon_hash_many(&[
        domain_felt(DOMAIN_OWNER_V2_BINDING),
        addr,
        binding,
        snip12,
        sp_hi,
        sp_lo,
        felt_from_u64(binding_valid_until),
    ])))
}

// ---------------------------------------------------------------------------
// nonce 单调 + expiry 校验
// ---------------------------------------------------------------------------

/// 信封新鲜度：`now < expiry` 且 nonce 严格大于该 signer 已见最大 nonce
/// （首个信封 `last_nonce = None` 时任意 nonce 接受）。过期 / 重放 → Err。
///
/// # Errors
/// 过期 → [`OwnerV2Error::Expired`]；nonce 重放 →
/// [`OwnerV2Error::NonceReplay`]。
pub fn check_envelope_freshness(
    envelope: &SignatureEnvelope,
    now: u64,
    last_nonce: Option<u64>,
) -> OwnerV2Result<()> {
    if now >= envelope.expiry {
        return Err(OwnerV2Error::Expired {
            now,
            expiry: envelope.expiry,
        });
    }
    if let Some(last) = last_nonce
        && envelope.nonce <= last
    {
        return Err(OwnerV2Error::NonceReplay {
            got: envelope.nonce,
            last,
        });
    }
    Ok(())
}

/// 信封结构一致性：scheme 与 `signer_ref.scheme` 一致 + signer_ref 合法。
///
/// # Errors
/// scheme 不一致 → [`OwnerV2Error::SchemeMismatch`]；signer 非法 →
/// [`OwnerV2Error::OwnerRefInvalid`] / [`OwnerV2Error::ZeroField`]。
pub fn validate_envelope(envelope: &SignatureEnvelope) -> OwnerV2Result<()> {
    if envelope.scheme != envelope.signer_ref.scheme {
        return Err(OwnerV2Error::SchemeMismatch(
            "envelope.scheme != signer_ref.scheme",
        ));
    }
    validate_owner_ref(&envelope.signer_ref)
}

// ---------------------------------------------------------------------------
// 三 scheme 验签
// ---------------------------------------------------------------------------

/// 验签材料（按 scheme 外部呈递；变体与 scheme 不匹配 → fail-closed）。
///
/// v2 正式版起实现 borsh 稳定 ABI：`SettleInputV2::V2` 携带材料进帧
/// （WAL 重放全量复核）；MigrateNote 的材料仍走 `submit_migrate` 准入
/// 呈递（op 载荷形状按 v2 排期冻结，不入帧）。
#[derive(
    Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub enum VerifierMaterial {
    /// `LegacySecp256k1`：呈递完整压缩公钥（33B；哈希必须等于 account_id）。
    LegacySecp256k1 {
        /// 呈递的压缩公钥。
        presented_public: [u8; 33],
    },
    /// `StarkCurve`：无附加材料（account_id 即公钥 felt）。
    StarkCurve,
    /// `StarknetAccountBinding`：SNIP-12 授权摘要 + 会话密钥 + 授权终点。
    AccountBinding {
        /// 钱包侧 SNIP-12 rev1 `AuthorizeZChainKey` message hash（canonical felt）。
        snip12_authorize_digest: [u8; 32],
        /// 会话密钥压缩公钥（SNIP-12 delegated key，secp256k1）。
        session_public: [u8; 33],
        /// 授权有效期终点（unix 秒；与 binding 登记一致）。
        binding_valid_until: u64,
    },
}

/// Legacy secp256k1 验签：呈递公钥哈希 == `account_id` 后 ECDSA compact
/// 验证（复用 [`crate::keys::verify_ecsdsa`] 原语）。
///
/// # Errors
/// 见 [`OwnerV2Error`]（一律 fail-closed）。
pub fn verify_legacy_secp256k1(
    account_id: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
    presented_public: &[u8; 33],
) -> OwnerV2Result<()> {
    if *account_id == [0u8; 32] {
        return Err(OwnerV2Error::ZeroField("account_id"));
    }
    if legacy_account_id(presented_public) != *account_id {
        return Err(OwnerV2Error::MaterialMismatch(
            "presented public key does not hash to account_id",
        ));
    }
    crate::keys::verify_ecsdsa(
        presented_public,
        digest,
        &crate::keys::EcdsaSig { bytes: *signature },
    )
    .map_err(|_| OwnerV2Error::BadSignature)
}

/// Stark 曲线验签：`account_id` 即公钥 felt，`starknet_crypto::verify`
/// 直接验证 (r, s)（各 32B canonical felt）。
///
/// # Errors
/// 见 [`OwnerV2Error`]（一律 fail-closed）。
pub fn verify_stark_curve(
    account_id: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> OwnerV2Result<()> {
    let pubkey = canonical_felt(account_id, "StarkCurve account_id")?;
    if pubkey == FieldElement::ZERO {
        return Err(OwnerV2Error::ZeroField("StarkCurve public key"));
    }
    let msg = canonical_felt(digest, "typed_data_digest")?;
    if msg == FieldElement::ZERO {
        return Err(OwnerV2Error::ZeroField("typed_data_digest"));
    }
    let r = canonical_felt(&signature[0..32].try_into().expect("32B slice"), "sig.r")?;
    let s = canonical_felt(&signature[32..64].try_into().expect("32B slice"), "sig.s")?;
    if r == FieldElement::ZERO || s == FieldElement::ZERO {
        return Err(OwnerV2Error::BadSignature);
    }
    match starknet_crypto::verify(&pubkey, &msg, &r, &s) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(OwnerV2Error::BadSignature),
    }
}

/// Starknet 账户绑定验签（alpha 形态）：验 SNIP-12 授权摘要格式
/// （canonical 非零 felt）+ 重算 binding 摘要 + 会话密钥 ECDSA 验证。
///
/// 完整账户 verifier（SNIP-12 keccak 重算复核授权内 delegated key、
/// 链上 account contract 多签/Passkey 语义）属 v2 正式版；alpha 阶段
/// 授权真实性与 `binding_id` 的锚定关系由 registry 侧保证。
///
/// # Errors
/// 见 [`OwnerV2Error`]（一律 fail-closed）。
pub fn verify_account_binding(
    owner: &OwnerRef,
    material: &VerifierMaterial,
    signature: &[u8; 64],
) -> OwnerV2Result<()> {
    let binding_id = owner.binding_id.ok_or(OwnerV2Error::OwnerRefInvalid(
        "StarknetAccountBinding requires binding_id",
    ))?;
    let VerifierMaterial::AccountBinding {
        snip12_authorize_digest,
        session_public,
        binding_valid_until,
    } = material
    else {
        return Err(OwnerV2Error::MaterialMismatch(
            "expected AccountBinding material",
        ));
    };
    // SNIP-12 授权摘要格式：canonical 非零 felt。
    let snip12 = canonical_felt(snip12_authorize_digest, "snip12_authorize_digest")?;
    if snip12 == FieldElement::ZERO {
        return Err(OwnerV2Error::ZeroField("snip12_authorize_digest"));
    }
    let digest = binding_authorization_digest(
        &owner.account_id,
        &binding_id,
        snip12_authorize_digest,
        session_public,
        *binding_valid_until,
    )?;
    crate::keys::verify_ecsdsa(
        session_public,
        &digest,
        &crate::keys::EcdsaSig { bytes: *signature },
    )
    .map_err(|_| OwnerV2Error::BadSignature)
}

/// 按 scheme 分派验签（材料变体不匹配 → fail-closed）。
///
/// # Errors
/// scheme 与材料不匹配 → [`OwnerV2Error::MaterialMismatch`]；各 scheme
/// 验签失败 → [`OwnerV2Error::BadSignature`] 等（一律 Err）。
pub fn verify_owner_signature(
    signer: &OwnerRef,
    digest: &[u8; 32],
    signature: &[u8; 64],
    material: &VerifierMaterial,
) -> OwnerV2Result<()> {
    match (signer.scheme, material) {
        (
            SignatureScheme::LegacySecp256k1,
            VerifierMaterial::LegacySecp256k1 { presented_public },
        ) => verify_legacy_secp256k1(&signer.account_id, digest, signature, presented_public),
        (SignatureScheme::StarkCurve, VerifierMaterial::StarkCurve) => {
            verify_stark_curve(&signer.account_id, digest, signature)
        }
        (SignatureScheme::StarknetAccountBinding, VerifierMaterial::AccountBinding { .. }) => {
            verify_account_binding(signer, material, signature)
        }
        _ => Err(OwnerV2Error::MaterialMismatch(
            "verifier material variant does not match owner scheme",
        )),
    }
}

// ---------------------------------------------------------------------------
// MigrateNote 校验关系（纯函数；AIR witness 形状就绪）
// ---------------------------------------------------------------------------

/// MigrateNote 全量校验（顺序即实现，全部 fail-closed）：
///
/// 1. `old_commitment` 非零；
/// 2. `migration_nonce` 非零；
/// 3. `amount > 0`；
/// 4. `new_owner_ref` 结构合法（account_id 非零 / StarkCurve 规范化 /
///    binding_id 关系）；
/// 5. 信封结构一致（scheme 匹配 + signer 合法）；
/// 6. 摘要一致：`old_owner_sig.typed_data_digest == migrate_digest(record)`；
/// 7. 新鲜度：`now < expiry` 且 nonce 严格单调；
/// 8. 旧签名验签通过（按 scheme 分派）。
///
/// # Errors
/// 任一条不满足即 Err（对应唯一变体，见 [`OwnerV2Error`]）。
pub fn validate_migrate_note(
    record: &MigrateNoteRecord,
    now: u64,
    last_nonce: Option<u64>,
    material: &VerifierMaterial,
) -> OwnerV2Result<()> {
    validate_migrate_note_structure(record, now, last_nonce)?;
    verify_owner_signature(
        &record.old_owner_sig.signer_ref,
        &record.old_owner_sig.typed_data_digest,
        &record.old_owner_sig.signature,
        material,
    )
}

/// [`validate_migrate_note`] 的第 1–7 步（材料无关关系；**不含**第 8 步
/// 加密验签）。
///
/// v2 正式版接入 sequencer 后的双重用途：
/// - `Sequencer::submit_migrate`：先经本函数 + [`verify_owner_signature`]
///   （全 8 步）；
/// - WAL 重放侧（op 载荷不含呈递材料，见模块文档边界）：重放材料无关
///   的全部关系（结构/摘要/新鲜度），加密验签以准入时的提交路径为准。
///
/// # Errors
/// 第 1–7 步任一不满足即 Err。
pub fn validate_migrate_note_structure(
    record: &MigrateNoteRecord,
    now: u64,
    last_nonce: Option<u64>,
) -> OwnerV2Result<()> {
    if record.old_commitment == [0u8; 32] {
        return Err(OwnerV2Error::ZeroField("old_commitment"));
    }
    if record.migration_nonce == [0u8; 32] {
        return Err(OwnerV2Error::ZeroField("migration_nonce"));
    }
    if record.amount == 0 {
        return Err(OwnerV2Error::InvalidAmount(0));
    }
    validate_owner_ref(&record.new_owner_ref)?;
    validate_envelope(&record.old_owner_sig)?;
    let digest = migrate_digest(record);
    if record.old_owner_sig.typed_data_digest != digest {
        return Err(OwnerV2Error::DigestMismatch);
    }
    check_envelope_freshness(&record.old_owner_sig, now, last_nonce)
}

// ---------------------------------------------------------------------------
// 内部辅助
// ---------------------------------------------------------------------------

/// 32B → canonical felt（非 canonical 拒绝；fail-closed）。
fn canonical_felt(bytes: &[u8; 32], what: &'static str) -> OwnerV2Result<FieldElement> {
    felt_from_bytes32_exact(bytes).map_err(|_| OwnerV2Error::OwnerRefInvalid(what))
}
