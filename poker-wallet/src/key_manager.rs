//! `key_manager`：密钥生成/导入与约束执行（plan §6.12.3）。
//!
//! - **owner key**：secp256k1（workspace secp256k1 0.29，复用 appchain 的
//!   ECDSA/digest 原语，不重实现）。生成走 OS 随机源；导入只接受 32B 规范
//!   私钥字节；secret 常驻 [`SecretBytes`]（zeroize on drop），`Debug` 永远
//!   输出 `[REDACTED]`。
//! - **delegated/session key**：本地生成 secp256k1 子密钥，其权限由
//!   [`SessionConstraints`] 描述并由 SNIP-12 `AuthorizeZChainKey`
//!   （见 [`crate::account_binding`]）锚定。约束执行是纯函数
//!   [`session_admission`]，Appchain 侧 admission 可直接复用；撤销/到期/
//!   超额/越权全部 fail-closed。
//!
//! 本模块不做 Starknet 账户私钥管理：Vault 账户只有 address + 授权证明
//! （见 [`crate::vault_adapter`]）。

use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};
use zeroize::Zeroizing;

use crate::error::{SessionRejectReason, WalletError, WalletResult};

/// 32 字节敏感材料：zeroize on drop；`Debug` 输出脱敏占位（WALLET-ACC-4：
/// 私钥/spend secret 不进日志）。
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<[u8; 32]>);

impl borsh::BorshSerialize for SecretBytes {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(self.expose(), writer)
    }
}

impl borsh::BorshDeserialize for SecretBytes {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 32];
        std::io::Read::read_exact(reader, &mut buf)?;
        Ok(Self::new(buf))
    }
}

impl SecretBytes {
    /// 从 32 字节构造。
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// 暴露引用（仅限签名/哈希等就地使用，不得拷贝落盘）。
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED])")
    }
}

/// 会话密钥 scope 标签（plan §6.12.1a：PLAY/buy-in/bet/settle/transfer/withdraw）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, borsh::BorshSerialize, borsh::BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum Scope {
    /// 休闲牌局登录/通用 PLAY 操作。
    Play = 1,
    /// 买入。
    BuyIn = 2,
    /// 牌内下注（高频路径）。
    Bet = 3,
    /// 一手牌结算。
    Settle = 4,
    /// 玩家间转账。
    Transfer = 5,
    /// 提现（高风险；会话密钥默认不得持有，见 [`SessionConstraints`]）。
    Withdraw = 6,
}

impl Scope {
    /// ABI 数值。
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// 静态名（SNIP-12 shortstring 与错误信息用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Play => "play",
            Self::BuyIn => "buyin",
            Self::Bet => "bet",
            Self::Settle => "settle",
            Self::Transfer => "transfer",
            Self::Withdraw => "withdraw",
        }
    }

    /// 从 ABI 数值解析（fail-closed：未定义数值拒绝）。
    ///
    /// # Errors
    /// 未定义数值 → [`WalletError::InvalidArgument`]。
    pub fn from_u8(v: u8) -> WalletResult<Self> {
        match v {
            1 => Ok(Self::Play),
            2 => Ok(Self::BuyIn),
            3 => Ok(Self::Bet),
            4 => Ok(Self::Settle),
            5 => Ok(Self::Transfer),
            6 => Ok(Self::Withdraw),
            _ => Err(WalletError::InvalidArgument("scope")),
        }
    }

    /// 从 shortstring 名称解析（SNIP-12 反序列化侧，fail-closed）。
    ///
    /// # Errors
    /// 未知名称 → [`WalletError::InvalidArgument`]。
    pub fn from_name(name: &str) -> WalletResult<Self> {
        match name {
            "play" => Ok(Self::Play),
            "buyin" => Ok(Self::BuyIn),
            "bet" => Ok(Self::Bet),
            "settle" => Ok(Self::Settle),
            "transfer" => Ok(Self::Transfer),
            "withdraw" => Ok(Self::Withdraw),
            _ => Err(WalletError::InvalidArgument("scope name")),
        }
    }
}

/// 会话密钥约束（SNIP-12 `AuthorizeZChainKey` message 的 Rust 镜像）。
///
/// 撤销不在结构内（撤销是 registry 的粘滞状态，见
/// [`crate::account_binding::BindingRegistry`]），这里只携带授权本身。
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SessionConstraints {
    /// 授权登记 ID（Appchain `AccountBindingRegistry` 锚点）。
    pub binding_id: [u8; 32],
    /// 授权适用的版本化 ZChain chain id（换网失效，防跨链重放）。
    pub chain_id: String,
    /// 授权方 Starknet 账户地址（felt252 规范 32B）。
    pub account_address: [u8; 32],
    /// 被授权的 delegated 公钥（33B 压缩 secp256k1）。
    pub delegated_public: [u8; 33],
    /// 允许的 scope 集合。
    pub allowed_scopes: Vec<Scope>,
    /// 单笔限额（None = 不限；提额属高风险，不得由会话密钥自改）。
    pub per_tx_limit: Option<u64>,
    /// 每日限额（None = 不限；按 unix 天窗聚合）。
    pub daily_limit: Option<u64>,
    /// 桌白名单（None = 全桌允许；Some 空集 = 全桌拒绝——fail-closed 方向）。
    pub table_allowlist: Option<Vec<u64>>,
    /// 生效起点（unix 秒，含）。
    pub valid_after: u64,
    /// 生效终点（unix 秒，不含）。
    pub valid_until: u64,
    /// 授权 nonce（防授权重放）。
    pub nonce: u64,
}

/// 会话密钥（delegated key）材质：约束 + 本地私钥。
#[derive(Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SessionKey {
    /// 授权约束。
    pub constraints: SessionConstraints,
    secret: SecretBytes,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("constraints", &self.constraints)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl SessionKey {
    /// 生成满足约束的 delegated 密钥（OS 随机源）。
    #[must_use]
    pub fn generate(constraints: SessionConstraints) -> Self {
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, secret_bytes.as_mut());
        // 极小概率非法（≥ 曲线阶）——重试到合法为止（可忽略开销）。
        let secret = loop {
            match SecretKey::from_slice(secret_bytes.as_ref()) {
                Ok(sk) => break sk,
                Err(_) => {
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, secret_bytes.as_mut());
                }
            }
        };
        Self::from_secret(constraints, secret)
    }

    /// 从已有 secret 构造（导入/测试向量路径）。
    #[must_use]
    pub fn from_secret(constraints: SessionConstraints, secret: SecretKey) -> Self {
        let raw = Zeroizing::new(secret.secret_bytes());
        Self {
            constraints,
            secret: SecretBytes::new(*raw),
        }
    }

    /// 33B 压缩公钥。
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 33] {
        self.constraints.delegated_public
    }

    /// 对 32B 摘要的 ECDSA 签名（64B compact，确定性 RFC6979）。
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let secret = SecretKey::from_slice(self.secret.expose())
            .expect("SessionKey secret is validated at construction");
        let msg = Message::from_digest(*digest);
        SECP256K1.sign_ecdsa(&msg, &secret).serialize_compact()
    }
}

/// secp256k1 owner 密钥对。
///
/// 与 poker-appchain `keys::OwnerKey` 语义一致（同曲线同编码），但 secret
/// 生命周期由 [`SecretBytes`] 管理；`Debug` 不泄露明文。
#[derive(Clone)]
pub struct OwnerKeyPair {
    secret: SecretBytes,
    public: [u8; 33],
}

impl std::fmt::Debug for OwnerKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKeyPair")
            .field("public", &hex::encode(self.public))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl OwnerKeyPair {
    /// 生成新 owner key（OS 随机源）。
    #[must_use]
    pub fn generate() -> Self {
        let secret = SecretKey::new(&mut rand::rngs::OsRng);
        Self::from_secret_key(secret)
    }

    /// 从 secp256k1 SecretKey 构造。
    #[must_use]
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let public = PublicKey::from_secret_key(SECP256K1, &secret)
            .serialize()
            .to_owned();
        let raw = Zeroizing::new(secret.secret_bytes());
        Self {
            secret: SecretBytes::new(*raw),
            public,
        }
    }

    /// 从 32B 私钥字节导入。
    ///
    /// # Errors
    /// 字节非法（0 或 ≥ 曲线阶）→ [`WalletError::BadKeyMaterial`]。
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> WalletResult<Self> {
        let secret =
            SecretKey::from_slice(bytes).map_err(|_| WalletError::BadKeyMaterial("secp256k1 secret"))?;
        Ok(Self::from_secret_key(secret))
    }

    /// 从 seed 构造（测试向量路径；生产走 [`OwnerKeyPair::generate`]）。
    ///
    /// # Errors
    /// 同 [`OwnerKeyPair::from_secret_bytes`]。
    pub fn from_seed(seed: &[u8; 32]) -> WalletResult<Self> {
        Self::from_secret_bytes(seed)
    }

    /// 33B 压缩公钥。
    #[must_use]
    pub fn public_bytes(&self) -> [u8; 33] {
        self.public
    }

    /// 私钥 32B（zeroizing 容器；调用方不得落盘/打印）。
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.secret.expose())
    }

    /// 对 32B 摘要的 ECDSA 签名（64B compact，确定性 RFC6979；与账本 ABI 一致）。
    #[must_use]
    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        let secret = SecretKey::from_slice(self.secret.expose())
            .expect("OwnerKeyPair secret is validated at construction");
        let msg = Message::from_digest(*digest);
        SECP256K1.sign_ecdsa(&msg, &secret).serialize_compact()
    }
}

/// 校验 owner/delegated 签名（复用 poker-appchain 的 fail-closed 验证）。
///
/// # Errors
/// 格式或验证失败一律 [`WalletError::BadKeyMaterial`]（不区分原因）。
pub fn verify_owner_signature(
    public: &[u8; 33],
    digest: &[u8; 32],
    sig: &[u8; 64],
) -> WalletResult<()> {
    let ok = poker_appchain::keys::verify_ecsdsa(
        public,
        digest,
        &poker_appchain::keys::EcdsaSig { bytes: *sig },
    );
    ok.map_err(|_| WalletError::BadKeyMaterial("ecdsa"))
}

/// 会话准入请求视图（纯数据；由 signer/sequencer 从具体操作投影）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAdmission {
    /// 请求 scope。
    pub scope: Scope,
    /// 请求涉及的桌（无桌操作传 None）。
    pub table_id: Option<u64>,
    /// 请求金额（单笔；日限聚合用）。
    pub amount: u64,
    /// 请求 chain_id（与授权不一致即拒绝，防换网重放）。
    pub chain_id: String,
}

/// 会话准入纯函数（**Appchain 侧可复用**：只依赖输入，不依赖钱包状态）。
///
/// fail-closed 判定顺序（每类拒绝独立可测，WALLET-ACC-3/3a）：
/// 撤销 → 换网 → 未生效/过期 → scope → 桌白名单 → 单笔限额 → 日限额。
///
/// # Errors
/// 任何一条不满足 → 对应 [`SessionRejectReason`] 包装的
/// [`WalletError::SessionRejected`]。
pub fn session_admission(
    constraints: &SessionConstraints,
    revoked: bool,
    daily_used: (u64, u64), // (day_index, used_amount)
    req: &SessionAdmission,
    now: u64,
) -> WalletResult<()> {
    // 1. 撤销粘滞（最先判：撤销后任何窗口/限额讨论都无效）
    if revoked {
        return Err(WalletError::SessionRejected(SessionRejectReason::Revoked));
    }
    // 2. 换网（chain_id 必须逐字节一致）
    if constraints.chain_id != req.chain_id {
        return Err(WalletError::SessionRejected(SessionRejectReason::ChainMismatch));
    }
    // 3. 时间窗 [valid_after, valid_until)
    if now < constraints.valid_after {
        return Err(WalletError::SessionRejected(SessionRejectReason::NotYetValid));
    }
    if now >= constraints.valid_until {
        return Err(WalletError::SessionRejected(SessionRejectReason::Expired));
    }
    // 4. scope 白名单
    if !constraints.allowed_scopes.contains(&req.scope) {
        return Err(WalletError::SessionRejected(SessionRejectReason::ScopeNotAllowed));
    }
    // 5. 桌白名单（None = 全桌；Some 列表精确匹配）。白名单只约束**桌内
    // 操作**（play/buyin/bet/settle）：桌 ID 缺失即拒绝（fail-closed）；
    // 非桌操作（transfer/withdraw）不受白名单约束。
    if let Some(allowlist) = &constraints.table_allowlist {
        match (req.table_id, scope_is_table_bound(req.scope)) {
            (Some(table), _) if allowlist.contains(&table) => {}
            (Some(_), _) => return Err(WalletError::SessionRejected(SessionRejectReason::TableNotAllowed)),
            (None, true) => return Err(WalletError::SessionRejected(SessionRejectReason::TableNotAllowed)),
            (None, false) => {}
        }
    }
    // 6. 单笔限额
    if let Some(limit) = constraints.per_tx_limit {
        if req.amount > limit {
            return Err(WalletError::SessionRejected(SessionRejectReason::OverPerTxLimit));
        }
    }
    // 7. 日限额（按 unix 天窗聚合；跨天窗清零由调用方携带的 daily_used 决定）
    if let Some(limit) = constraints.daily_limit {
        let today = now / 86_400;
        let used = if daily_used.0 == today { daily_used.1 } else { 0 };
        let new_total = used
            .checked_add(req.amount)
            .ok_or(WalletError::SessionRejected(SessionRejectReason::DailyLimitExhausted))?;
        if new_total > limit {
            return Err(WalletError::SessionRejected(SessionRejectReason::DailyLimitExhausted));
        }
    }
    Ok(())
}

/// 桌内操作判定（桌白名单的约束范围）。
#[must_use]
pub fn scope_is_table_bound(scope: Scope) -> bool {
    matches!(scope, Scope::Play | Scope::BuyIn | Scope::Bet | Scope::Settle)
}
