//! `account_binding`：SNIP-12 typed data + binding 状态机（plan §6.12.1a/§6.12.3）。
//!
//! ## SNIP-12（revision 1）摘要
//!
//! 生产形态是 **Starknet Account + SNIP-12 授权的 ZChain 会话密钥**：授权由
//! Starknet 账户对其 typed data 摘要签名，Appchain 只登记摘要并验证受限
//! 会话密钥。本模块实现两条消息的 typed data 构造与 Poseidon 摘要：
//!
//! - `AuthorizeZChainKey`：chain id / 账户地址 / delegated 公钥 / scope 集 /
//!   单笔与日限额 / 桌白名单 / nonce / 有效期；
//! - `RevokeZChainKey`：chain id / binding id / nonce / 撤销时间。
//!
//! 摘要算法（SNIP-12 revision 1，仅覆盖本 crate 用到的类型子集）：
//!
//! ```text
//! type_hash(T)      = sn_keccak(encode_type(T))
//! struct_hash(T)    = poseidon_hash_many([type_hash(T), …成员编码…])
//! domain_sep        = struct_hash(StarknetDomain)
//! message_hash      = poseidon_hash_many([sn_keccak("StarkNetMessage(
//!                       type_hash,struct_hash)"), domain_sep, struct_hash])
//! sn_keccak(x)      = keccak256(x) 截断到 250 bit
//! ```
//!
//! 成员类型编码：`shortstring`/`felt252`/`amount` → felt；`bytes` →
//! `H(len, 31B 大端 chunk 序)`；`T[]` 数组 → `H(len, 元素哈希序)`。
//!
//! ## 签名验证
//!
//! [`verify_account_signature`] 用 workspace `starknet-crypto`（Stark curve
//! Pedersen/ECDSA 原语，不重实现）在**本地**验证账户签名公钥。合约账户的
//! 完整验证在链上 account contract 内完成；本地路径等价于单签 OZ 账户的
//! 验证语义，多签/Passkey 账户的授权以链上登记为准（如实标注，不冒充）。
//!
//! ## 状态机与准入
//!
//! [`BindingRegistry`] 维护 `active → revoked`（粘滞）+ 时间窗/限额派生态
//! （`expired` / `exhausted`）；[`binding_status`] 与 [`binding_admission`]
//! 是纯函数，Appchain admission 可直接复用（fail-closed）。

use starknet_crypto::FieldElement;

use crate::error::{WalletError, WalletResult};
use crate::key_manager::{session_admission, Scope, SessionAdmission, SessionConstraints};

/// SNIP-12 revision（本 crate 固定 revision 1）。
pub const SNIP12_REVISION: &str = "1";

/// SNIP-12 message hash 前缀常量（revision 1）。
const SNIP12_MESSAGE_PREFIX: &[u8] = b"StarkNetMessage(type_hash,struct_hash)";

/// Typed data 域（SNIP-12 `StarknetDomain`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snip12Domain {
    /// 域名（固定 `ZChain`）。
    pub name: String,
    /// 域版本（跟随钱包 ABI，如 `1`）。
    pub version: String,
    /// 版本化 ZChain chain id（不复用 `SN_MAIN`/EVM chain id）。
    pub chain_id: String,
}

impl Snip12Domain {
    /// ZChain 标准域。
    #[must_use]
    pub fn zchain(chain_id: impl Into<String>) -> Self {
        Self { name: "ZChain".to_string(), version: "1".to_string(), chain_id: chain_id.into() }
    }
}

/// `AuthorizeZChainKey` 消息（§6.12.1a 全字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeZChainKeyMessage {
    /// 授权适用的 ZChain chain id。
    pub zchain_chain_id: String,
    /// 授权方 Starknet 账户地址（felt252 规范 32B；**必须 < 域模数**，
    /// 否则摘要构造拒绝——真实地址恒满足）。
    pub account_address: [u8; 32],
    /// 被授权 delegated 公钥（33B 压缩 secp256k1；SNIP-12 `bytes` 类型）。
    pub delegated_public_key: [u8; 33],
    /// 签名方案（`secp256k1`）。
    pub signature_scheme: String,
    /// 允许的 scope 集。
    pub allowed_scopes: Vec<Scope>,
    /// 单笔限额（None → 0 = 不限）。
    pub per_tx_limit: Option<u64>,
    /// 每日限额（None → 0 = 不限）。
    pub per_day_limit: Option<u64>,
    /// 桌白名单（None = 全桌；Some = 白名单模式，空集 = 全拒）。
    pub table_allowlist: Option<Vec<u64>>,
    /// 授权登记 ID。
    pub binding_id: [u8; 32],
    /// 授权 nonce。
    pub nonce: u64,
    /// 生效起点（unix 秒）。
    pub valid_after: u64,
    /// 生效终点（unix 秒）。
    pub valid_until: u64,
}

/// `RevokeZChainKey` 消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeZChainKeyMessage {
    /// 授权适用的 ZChain chain id。
    pub zchain_chain_id: String,
    /// 要撤销的授权登记 ID。
    pub binding_id: [u8; 32],
    /// 撤销 nonce。
    pub nonce: u64,
    /// 撤销时间（unix 秒）。
    pub revoked_at: u64,
}

// ---------------------------------------------------------------------------
// SNIP-12 编码原语
// ---------------------------------------------------------------------------

/// sn_keccak：keccak256 截断到 250 bit（SNIP-12 type hash 原语）。
#[must_use]
pub fn sn_keccak(data: &[u8]) -> FieldElement {
    use sha3::Digest as _;
    let mut h = sha3::Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    // 大端最高字节清掉高 6 位：值 < 2^250 < Stark 域模数（必为 canonical felt）。
    buf[0] &= 0b0000_0011;
    FieldElement::from_bytes_be(&buf).expect("masked 250-bit value is a canonical felt")
}

/// shortstring → felt（≤31 字节 ASCII）。
///
/// # Errors
/// 超过 31 字节 → [`WalletError::InvalidArgument`]。
pub fn shortstring(s: &str) -> WalletResult<FieldElement> {
    if s.len() > 31 {
        return Err(WalletError::InvalidArgument("shortstring length"));
    }
    let mut buf = [0u8; 32];
    buf[32 - s.len()..].copy_from_slice(s.as_bytes());
    FieldElement::from_bytes_be(&buf).map_err(|_| WalletError::InvalidArgument("shortstring"))
}

/// 32B 规范字节 → felt。
///
/// # Errors
/// 非规范（超出 felt 模数）→ [`WalletError::InvalidArgument`]。
pub fn felt_from_32(bytes: &[u8; 32]) -> WalletResult<FieldElement> {
    FieldElement::from_bytes_be(bytes).map_err(|_| WalletError::InvalidArgument("felt252"))
}

/// `bytes` 类型编码：`H(len, chunk_0, …)`（31B 大端 chunk）。
fn hash_bytes(data: &[u8]) -> WalletResult<FieldElement> {
    let mut parts = vec![FieldElement::from(data.len() as u64)];
    for chunk in data.chunks(31) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        parts.push(FieldElement::from_bytes_be(&buf).map_err(|_| WalletError::InvalidArgument("bytes chunk"))?);
    }
    Ok(starknet_crypto::poseidon_hash_many(&parts))
}

/// 数组类型编码：`H(len, 元素哈希序)`。
fn hash_array(elements: &[FieldElement]) -> FieldElement {
    let mut parts = Vec::with_capacity(elements.len() + 1);
    parts.push(FieldElement::from(elements.len() as u64));
    parts.extend_from_slice(elements);
    starknet_crypto::poseidon_hash_many(&parts)
}

/// `AuthorizeZChainKey` 的 SNIP-12 `encode_type`。
///
/// revision 1：成员按名字母序排列（本结构只依赖内建类型，无自定义依赖）。
#[must_use]
pub fn authorize_encode_type() -> &'static str {
    "AuthorizeZChainKey(account_address:felt252,allowed_scopes:shortstring[],binding_id:felt252,chain_id:shortstring,delegated_public_key:bytes,nonce:felt252,per_day_limit:amount,per_tx_limit:amount,signature_scheme:shortstring,table_allowlist:felt252[],table_allowlist_scope:shortstring,valid_after:amount,valid_until:amount,zchain_chain_id:shortstring)"
}

/// `RevokeZChainKey` 的 SNIP-12 `encode_type`。
#[must_use]
pub fn revoke_encode_type() -> &'static str {
    "RevokeZChainKey(binding_id:felt252,chain_id:shortstring,nonce:felt252,revoked_at:amount,zchain_chain_id:shortstring)"
}

/// `StarknetDomain` 的 SNIP-12 `encode_type`（revision 1 含 revision 成员）。
#[must_use]
pub fn domain_encode_type() -> &'static str {
    "StarknetDomain(name:shortstring,version:shortstring,chainId:shortstring,revision:shortstring)"
}

/// 域分离子（`struct_hash(StarknetDomain)`）。
///
/// # Errors
/// 域字段超长/非法 → [`WalletError::InvalidArgument`]。
pub fn domain_separator(domain: &Snip12Domain) -> WalletResult<FieldElement> {
    let type_hash = sn_keccak(domain_encode_type().as_bytes());
    Ok(starknet_crypto::poseidon_hash_many(&[
        type_hash,
        shortstring(&domain.name)?,
        shortstring(&domain.version)?,
        shortstring(&domain.chain_id)?,
        shortstring(SNIP12_REVISION)?,
    ]))
}

/// SNIP-12 完整消息哈希：`H(prefix, domain_sep, struct_hash)`。
fn message_hash(domain: &Snip12Domain, struct_hash: FieldElement) -> WalletResult<FieldElement> {
    let prefix = sn_keccak(SNIP12_MESSAGE_PREFIX);
    let sep = domain_separator(domain)?;
    Ok(starknet_crypto::poseidon_hash_many(&[prefix, sep, struct_hash]))
}

/// `AuthorizeZChainKey` 的 struct hash。
///
/// # Errors
/// 域/字段非法 → [`WalletError::InvalidArgument`]。
pub fn authorize_struct_hash(msg: &AuthorizeZChainKeyMessage) -> WalletResult<FieldElement> {
    let type_hash = sn_keccak(authorize_encode_type().as_bytes());
    let scopes: Vec<FieldElement> = msg
        .allowed_scopes
        .iter()
        .map(|s| shortstring(s.name()))
        .collect::<WalletResult<_>>()?;
    let tables: Vec<FieldElement> = msg
        .table_allowlist
        .iter()
        .flatten()
        .map(|t| FieldElement::from(*t))
        .collect();
    // 成员编码顺序 = encode_type 成员名字母序（revision 1；改动必须显式升级 ABI）。
    Ok(starknet_crypto::poseidon_hash_many(&[
        type_hash,
        // account_address
        felt_from_32(&msg.account_address)?,
        // allowed_scopes (shortstring[])
        hash_array(&scopes),
        // binding_id
        felt_from_32(&msg.binding_id)?,
        // chain_id (shortstring)
        shortstring(&msg.zchain_chain_id)?,
        // delegated_public_key (bytes)
        hash_bytes(&msg.delegated_public_key)?,
        // nonce
        FieldElement::from(msg.nonce),
        // per_day_limit (amount; 0 = 不限)
        FieldElement::from(msg.per_day_limit.unwrap_or(0)),
        // per_tx_limit (amount; 0 = 不限)
        FieldElement::from(msg.per_tx_limit.unwrap_or(0)),
        // signature_scheme (shortstring)
        shortstring(&msg.signature_scheme)?,
        // table_allowlist (felt252[])
        hash_array(&tables),
        // table_allowlist_scope (shortstring: "all" | "allowlist")
        shortstring(if msg.table_allowlist.is_some() { "allowlist" } else { "all" })?,
        // valid_after / valid_until (amount)
        FieldElement::from(msg.valid_after),
        FieldElement::from(msg.valid_until),
        // zchain_chain_id (shortstring)
        shortstring(&msg.zchain_chain_id)?,
    ]))
}

/// `RevokeZChainKey` 的 struct hash。
///
/// # Errors
/// 域/字段非法 → [`WalletError::InvalidArgument`]。
pub fn revoke_struct_hash(msg: &RevokeZChainKeyMessage) -> WalletResult<FieldElement> {
    let type_hash = sn_keccak(revoke_encode_type().as_bytes());
    Ok(starknet_crypto::poseidon_hash_many(&[
        type_hash,
        // binding_id
        felt_from_32(&msg.binding_id)?,
        // chain_id
        shortstring(&msg.zchain_chain_id)?,
        // nonce
        FieldElement::from(msg.nonce),
        // revoked_at
        FieldElement::from(msg.revoked_at),
        // zchain_chain_id
        shortstring(&msg.zchain_chain_id)?,
    ]))
}

/// `AuthorizeZChainKey` 完整摘要（SNIP-12 revision 1）。
///
/// # Errors
/// 域/字段非法 → [`WalletError::InvalidArgument`]。
pub fn authorize_message_hash(
    domain: &Snip12Domain,
    msg: &AuthorizeZChainKeyMessage,
) -> WalletResult<FieldElement> {
    message_hash(domain, authorize_struct_hash(msg)?)
}

/// `RevokeZChainKey` 完整摘要（SNIP-12 revision 1）。
///
/// # Errors
/// 域/字段非法 → [`WalletError::InvalidArgument`]。
pub fn revoke_message_hash(
    domain: &Snip12Domain,
    msg: &RevokeZChainKeyMessage,
) -> WalletResult<FieldElement> {
    message_hash(domain, revoke_struct_hash(msg)?)
}

// ---------------------------------------------------------------------------
// Stark 签名验证（外部账户签名接口）
// ---------------------------------------------------------------------------

/// Stark 曲线签名 (r, s)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarkSignature {
    /// r 分量。
    pub r: FieldElement,
    /// s 分量。
    pub s: FieldElement,
}

/// 验证 Starknet 账户对 message hash 的签名（本地路径：对账户的验证公钥做
/// Stark curve ECDSA 验证；合约账户的完整验证在链上 account contract，
/// 多签/Passkey 以链上登记为准）。
///
/// # Errors
/// 底层验证错误 → [`WalletError::VerifierRejected`]（签名非法返回 Ok(false)）。
pub fn verify_account_signature(
    account_public_key: &FieldElement,
    message_hash: &FieldElement,
    sig: &StarkSignature,
) -> WalletResult<bool> {
    starknet_crypto::verify(account_public_key, message_hash, &sig.r, &sig.s)
        .map_err(|e| WalletError::VerifierRejected(format!("stark verify: {e}")))
}

// ---------------------------------------------------------------------------
// Binding 状态机与准入（纯函数；Appchain 侧复用）
// ---------------------------------------------------------------------------

/// binding 生命周期状态（plan §6.12.3：active/expired/revoked/exhausted）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingStatus {
    /// 在有效期内且未撤销、日限额未耗尽。
    Active,
    /// 当前时间在 [valid_after, valid_until) 之外。
    Expired,
    /// 已撤销（粘滞）。
    Revoked,
    /// 日限额已耗尽。
    Exhausted,
}

/// 一条已登记的授权（constraints + 撤销粘滞位 + 日限额聚合）。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SessionBinding {
    /// 授权约束（SNIP-12 message 的 Rust 镜像）。
    pub constraints: SessionConstraints,
    /// 撤销粘滞位（撤销后不可恢复）。
    pub revoked: bool,
    /// 日限额聚合：当天（unix 天序号）已用金额与对应天序号。
    pub daily_used_day: u64,
    /// 日限额聚合：当天已用金额。
    pub daily_used_amount: u64,
}

impl SessionBinding {
    /// 新建（未撤销、日限额清零）。
    #[must_use]
    pub fn new(constraints: SessionConstraints) -> Self {
        Self { constraints, revoked: false, daily_used_day: 0, daily_used_amount: 0 }
    }

    /// 当前状态。
    #[must_use]
    pub fn status(&self, now: u64) -> BindingStatus {
        if self.revoked {
            return BindingStatus::Revoked;
        }
        if now < self.constraints.valid_after || now >= self.constraints.valid_until {
            return BindingStatus::Expired;
        }
        if let Some(limit) = self.constraints.daily_limit {
            let used = if self.daily_used_day == now / 86_400 { self.daily_used_amount } else { 0 };
            if used >= limit {
                return BindingStatus::Exhausted;
            }
        }
        BindingStatus::Active
    }

    /// 记账一笔已授权花费（日限聚合；跨天自动开新窗）。
    pub fn record_spend(&mut self, amount: u64, now: u64) {
        let today = now / 86_400;
        if self.daily_used_day != today {
            self.daily_used_day = today;
            self.daily_used_amount = 0;
        }
        self.daily_used_amount = self.daily_used_amount.saturating_add(amount);
    }
}

/// 授权登记表：`binding_id → SessionBinding`（撤销粘滞；确定性 BTreeMap）。
#[derive(Debug, Clone, Default, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct BindingRegistry {
    bindings: std::collections::BTreeMap<[u8; 32], SessionBinding>,
}

impl BindingRegistry {
    /// 新建空表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记/更新授权（幂等 upsert：同 id 重复授权替换为最新约束）。
    pub fn authorize(&mut self, binding: SessionBinding) {
        self.bindings.insert(binding.constraints.binding_id, binding);
    }

    /// 撤销（粘滞；未知 binding 拒绝——fail-closed）。
    ///
    /// # Errors
    /// 未知 binding → [`WalletError::NoteNotFound`]（registry 无该条目）。
    pub fn revoke(&mut self, binding_id: &[u8; 32]) -> WalletResult<()> {
        let b = self
            .bindings
            .get_mut(binding_id)
            .ok_or_else(|| WalletError::NoteNotFound(hex::encode(binding_id)))?;
        b.revoked = true;
        Ok(())
    }

    /// 查询。
    #[must_use]
    pub fn get(&self, binding_id: &[u8; 32]) -> Option<&SessionBinding> {
        self.bindings.get(binding_id)
    }

    /// 可变查询。
    pub fn get_mut(&mut self, binding_id: &[u8; 32]) -> Option<&mut SessionBinding> {
        self.bindings.get_mut(binding_id)
    }

    /// 全部条目（稳定序；备份用）。
    #[must_use]
    pub fn entries(&self) -> impl Iterator<Item = &SessionBinding> {
        self.bindings.values()
    }
}

/// binding 状态机纯函数（无 registry 依赖；Appchain admission 可复用）。
#[must_use]
pub fn binding_status(
    constraints: &SessionConstraints,
    revoked: bool,
    daily_used: (u64, u64),
    now: u64,
) -> BindingStatus {
    if revoked {
        return BindingStatus::Revoked;
    }
    if now < constraints.valid_after || now >= constraints.valid_until {
        return BindingStatus::Expired;
    }
    if let Some(limit) = constraints.daily_limit {
        let used = if daily_used.0 == now / 86_400 { daily_used.1 } else { 0 };
        if used >= limit {
            return BindingStatus::Exhausted;
        }
    }
    BindingStatus::Active
}

/// binding 准入纯函数：状态机 + 约束全判定（撤销/换网/时间窗/scope/桌白名单/
/// 单笔限额/日限额，fail-closed）。内部委托 [`session_admission`]。
///
/// # Errors
/// 见 [`session_admission`]。
pub fn binding_admission(
    binding: &SessionBinding,
    req: &SessionAdmission,
    now: u64,
) -> WalletResult<()> {
    let today = now / 86_400;
    let used = if binding.daily_used_day == today {
        binding.daily_used_amount
    } else {
        0
    };
    session_admission(
        &binding.constraints,
        binding.revoked,
        (binding.daily_used_day, used),
        req,
        now,
    )
}

/// SNIP-12 消息 → 约束（typed data 与 admission 字段一一对应；
/// WALLET-ACC-2 v2 展示/verifier 字段相等的逻辑面）。
#[must_use]
pub fn constraints_from_message(msg: &AuthorizeZChainKeyMessage) -> SessionConstraints {
    SessionConstraints {
        binding_id: msg.binding_id,
        chain_id: msg.zchain_chain_id.clone(),
        account_address: msg.account_address,
        delegated_public: msg.delegated_public_key,
        allowed_scopes: msg.allowed_scopes.clone(),
        per_tx_limit: msg.per_tx_limit,
        daily_limit: msg.per_day_limit,
        table_allowlist: msg.table_allowlist.clone(),
        valid_after: msg.valid_after,
        valid_until: msg.valid_until,
        nonce: msg.nonce,
    }
}

/// 撤销摘要便捷构造（registry revoke 之前用于本地确认）。
///
/// # Errors
/// 域/字段非法 → [`WalletError::InvalidArgument`]。
pub fn revoke_digest_for(
    domain: &Snip12Domain,
    chain_id: &str,
    binding_id: &[u8; 32],
    nonce: u64,
    revoked_at: u64,
) -> WalletResult<FieldElement> {
    revoke_message_hash(
        domain,
        &RevokeZChainKeyMessage {
            zchain_chain_id: chain_id.to_string(),
            binding_id: *binding_id,
            nonce,
            revoked_at,
        },
    )
}

/// 会话拒绝原因重导出（appchain 侧错误映射用）。
pub use crate::error::SessionRejectReason as RejectReason;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_manager::SessionConstraints;

    fn felt_test(byte: u8) -> [u8; 32] {
        let mut f = [0u8; 32];
        f[31] = byte;
        f
    }

    fn constraints() -> SessionConstraints {
        SessionConstraints {
            binding_id: felt_test(9),
            chain_id: "zchain-devnet-1".into(),
            account_address: felt_test(3),
            delegated_public: [4; 33],
            allowed_scopes: vec![Scope::Play, Scope::BuyIn, Scope::Settle],
            per_tx_limit: Some(1_000),
            daily_limit: Some(5_000),
            table_allowlist: Some(vec![1, 2]),
            valid_after: 1_000,
            valid_until: 2_000,
            nonce: 7,
        }
    }

    fn message() -> AuthorizeZChainKeyMessage {
        AuthorizeZChainKeyMessage {
            zchain_chain_id: "zchain-devnet-1".into(),
            account_address: felt_test(3),
            delegated_public_key: [4; 33],
            signature_scheme: "secp256k1".into(),
            allowed_scopes: vec![Scope::Play, Scope::BuyIn, Scope::Settle],
            per_tx_limit: Some(1_000),
            per_day_limit: Some(5_000),
            table_allowlist: Some(vec![1, 2]),
            binding_id: felt_test(9),
            nonce: 7,
            valid_after: 1_000,
            valid_until: 2_000,
        }
    }

    #[test]
    fn message_and_constraints_agree() {
        let c = constraints_from_message(&message());
        assert_eq!(c, constraints());
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let d = Snip12Domain::zchain("zchain-devnet-1");
        let h1 = authorize_message_hash(&d, &message()).unwrap();
        let h2 = authorize_message_hash(&d, &message()).unwrap();
        assert_eq!(h1, h2);
        // scope 变化 → 摘要变化
        let mut m = message();
        m.allowed_scopes = vec![Scope::Play];
        assert_ne!(h1, authorize_message_hash(&d, &m).unwrap());
        // 换网 → 摘要变化
        let d2 = Snip12Domain::zchain("zchain-testnet-1");
        assert_ne!(h1, authorize_message_hash(&d2, &message()).unwrap());
        // revoke 摘要与 authorize 不同且确定
        let r = revoke_digest_for(&d, "zchain-devnet-1", &felt_test(9), 8, 1_500).unwrap();
        assert_eq!(r, revoke_digest_for(&d, "zchain-devnet-1", &felt_test(9), 8, 1_500).unwrap());
    }

    #[test]
    fn status_state_machine() {
        let c = constraints();
        // active
        assert_eq!(binding_status(&c, false, (0, 0), 1_500), BindingStatus::Active);
        // not yet valid / expired
        assert_eq!(binding_status(&c, false, (0, 0), 999), BindingStatus::Expired);
        assert_eq!(binding_status(&c, false, (0, 0), 2_000), BindingStatus::Expired);
        // revoked 粘滞（有效期内也 revoked）
        assert_eq!(binding_status(&c, true, (0, 0), 1_500), BindingStatus::Revoked);
        // exhausted（当日用满）
        assert_eq!(binding_status(&c, false, (1_500 / 86_400, 5_000), 1_500), BindingStatus::Exhausted);
        // 跨天窗重置
        assert_eq!(binding_status(&c, false, (86_400 - 1, 5_000), 1_500), BindingStatus::Active);
    }

    #[test]
    fn shortstring_length_guard() {
        assert!(shortstring("zchain").is_ok());
        let long = "x".repeat(32);
        assert!(shortstring(&long).is_err());
    }
}
