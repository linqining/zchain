//! `operation_signer`：只接受结构化请求的签名器（plan §6.12.3）。
//!
//! ## 拒绝面（M6-ACC-7 / WALLET-ACC-3，全部 fail-closed）
//!
//! - 任意 bytes 签名：[`Signer::sign_raw_bytes`] 永远拒绝（不存在
//!   `signBytes` 默认能力）；
//! - 未知域标签：域必须是 [`parse_domain`] 认识的 `zchain`；
//! - 未知 ABI 版本：只支持 [`SUPPORTED_ABI_VERSION`]；
//! - 金额溢出/守恒破坏：u128 checked 聚合 + u64 上限 + 输入输出守恒预检；
//! - 请求过期：`expiry < now` 拒绝；
//! - nonce 重放：签名器持有 (chain, nonce) 已用集合；
//! - 结算：签名输出前对**签名完备后**的记录跑账本全量校验
//!   [`validate_settlement`]，失败即不出签名（M6-ACC-3 联动）；
//! - session 路径：scope/限额/桌白名单/过期/撤销/换网由
//!   [`crate::key_manager::session_admission`] 执行；高风险操作
//!   （KeyRotation）要求主 owner（WALLET-ACC-3a）。
//!
//! ## 摘要
//!
//! 钱包级确认摘要 [`preview_digest`] 绑定 chain_id/domain/ABI 版本/操作语义
//! （WALLET-ACC-2 逻辑面：跨网络/ABI/域摘要必不同）；每笔花费授权的账本级
//! 摘要复用 poker-appchain `spend_digest`（scope + 效果摘要），与 sequencer
//! 验证路径完全一致。

use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::{blake2s32, spend_digest};
use poker_appchain::note::{AssetClass, Note, NoteSpec};
use poker_appchain::ops::{scope as op_scope, Operation};
use poker_appchain::settlement::{
    settle_effect, settle_spend_scope, validate_settlement, SettlementRecord, SpendAuth,
};

use crate::error::{SessionRejectReason, WalletError, WalletResult};
use crate::key_manager::{OwnerKeyPair, Scope, SessionKey};
use crate::note_store::{NoteRecord, WalletStores};

/// 钱包支持的 Operation ABI 版本（唯一；更高版本走协议升级流程）。
pub const SUPPORTED_ABI_VERSION: u32 = 1;

/// 钱包确认摘要域标签。
pub const DOMAIN_OPERATION_DIGEST: &[u8] = b"zchain.wallet.op.v1";

/// 已知域标签（M6-ACC-7：之外的标签一律拒绝）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainTag {
    /// ZChain 主域。
    ZChain,
}

impl DomainTag {
    /// 规范名（进入摘要与预览）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZChain => "zchain",
        }
    }
}

/// 解析域标签（fail-closed：`SN_MAIN`、`eip155`、任意未知标签全拒）。
///
/// # Errors
/// 未知标签 → [`WalletError::UnknownDomainTag`]。
pub fn parse_domain(tag: &str) -> WalletResult<DomainTag> {
    match tag {
        "zchain" => Ok(DomainTag::ZChain),
        other => Err(WalletError::UnknownDomainTag(other.to_string())),
    }
}

/// 网络/域上下文（进入每笔签名摘要，防跨网络/跨域重放）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCtx {
    /// 域标签（结构化；构造入口只接受 [`parse_domain`] 的结果）。
    pub domain: DomainTag,
    /// 版本化 chain id（如 `zchain-devnet-1`；不同网络摘要不同）。
    pub chain_id: String,
    /// Operation ABI 版本。
    pub abi_version: u32,
}

/// 请求级上下文：网络 + nonce + 过期。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    /// 网络上下文。
    pub network: NetworkCtx,
    /// 防重放 nonce（签名器内 (chain, nonce) 唯一）。
    pub nonce: u64,
    /// 过期时间（unix 秒；`expiry < now` 拒绝）。
    pub expiry: u64,
}

/// 输出 note 规格（铸造侧；桌绑定恒 None/0，由账本层补齐语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct OutputSpec {
    /// 收款 owner（33B 压缩公钥）。
    pub owner: [u8; 33],
    /// 面额 > 0。
    pub amount: u64,
}

/// 结构化签名请求（封闭枚举；**没有**任意 bytes 变体）。
#[derive(Debug, Clone)]
pub enum SigningRequest {
    /// 玩家间转账（守恒，同类）。
    Transfer {
        /// 请求上下文。
        ctx: RequestContext,
        /// 资产类。
        asset_class: AssetClass,
        /// 输入 note 承诺（≥1；从本地 note store 解析）。
        inputs: Vec<[u8; 32]>,
        /// 输出（≥1；Σoutputs == Σinputs）。
        outputs: Vec<OutputSpec>,
    },
    /// 买入：消费 balance note → 铸 seat note。
    BuyIn {
        /// 请求上下文。
        ctx: RequestContext,
        /// 资产类。
        asset_class: AssetClass,
        /// 桌 ID。
        table_id: u64,
        /// seat 归属（33B 压缩公钥）。
        seat_owner: [u8; 33],
        /// 输入 note 承诺（≥1）。
        inputs: Vec<[u8; 32]>,
    },
    /// 提现：销毁单张 balance note（vault 侧打款）。
    Withdraw {
        /// 请求上下文。
        ctx: RequestContext,
        /// 资产类。
        asset_class: AssetClass,
        /// 被销毁 note 的承诺。
        input: [u8; 32],
        /// 提现幂等键。
        request_id: [u8; 32],
        /// 外部收款地址（32B；**进 op 载荷与效果摘要**——P1 修复：收款人被
        /// owner 签名绑定，链与托管侧均不可偷换）。
        payout_recipient: [u8; 32],
        /// 展示用 vault 收款目标（地址串；仅入预览，不入账本摘要）。
        vault_target: String,
    },
    /// 一手牌结算：请求携带 operator 下发的结算记录骨架（payouts/pot/plan/
    /// rake/hand_binding + 全部输入 note；对手方的 spend 签名如已收集则一并
    /// 带入）。本钱包只补签 **owner == 签名人公钥** 的输入；签名完备后跑
    /// [`validate_settlement`]，不过不出签名。
    Settle {
        /// 请求上下文。
        ctx: RequestContext,
        /// 桌绑定的费率策略（开桌帧冻结；用于本地全量校验）。
        policy: FeePolicy,
        /// 结算记录骨架。
        record: SettlementRecord,
    },
    /// 密钥轮换（plan §6.12.6）：旧 owner 消费自己的 note，等额铸给新 owner。
    /// 高风险：session 密钥不得签署（[`SessionRejectReason::OwnerRequired`]）。
    KeyRotation {
        /// 请求上下文。
        ctx: RequestContext,
        /// 资产类。
        asset_class: AssetClass,
        /// 输入 note 承诺（≥1）。
        inputs: Vec<[u8; 32]>,
        /// 新 owner（33B 压缩公钥）。
        new_owner: [u8; 33],
    },
}

impl SigningRequest {
    /// 请求上下文借用。
    #[must_use]
    pub const fn ctx(&self) -> &RequestContext {
        match self {
            Self::Transfer { ctx, .. }
            | Self::BuyIn { ctx, .. }
            | Self::Withdraw { ctx, .. }
            | Self::Settle { ctx, .. }
            | Self::KeyRotation { ctx, .. } => ctx,
        }
    }

    /// 请求对应的 session scope。
    #[must_use]
    pub const fn scope(&self) -> Scope {
        match self {
            Self::Transfer { .. } | Self::KeyRotation { .. } => Scope::Transfer,
            Self::BuyIn { .. } => Scope::BuyIn,
            Self::Withdraw { .. } => Scope::Withdraw,
            Self::Settle { .. } => Scope::Settle,
        }
    }
}

/// 输出预览条目。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, borsh::BorshSerialize)]
pub struct PreviewOutput {
    /// 收款 owner（hex）。
    pub owner: String,
    /// 面额。
    pub amount: u64,
}

/// 人类可读签名预览（M6-ACC-7：网络、资产类、金额、桌、输出 owner、rake、
/// request_id、hand_binding、proof 状态、过期）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SigningPreview {
    /// 操作种类（transfer/buy_in/withdraw/settle/key_rotation）。
    pub kind: &'static str,
    /// 域标签。
    pub domain: String,
    /// 链 ID。
    pub chain_id: String,
    /// ABI 版本。
    pub abi_version: u32,
    /// 资产类（REAL/PLAY）。
    pub asset_class: &'static str,
    /// 输入总额。
    pub amount_in: u128,
    /// 输出总额。
    pub amount_out: u128,
    /// rake（结算时为记录 rake；其余 0）。
    pub rake: u64,
    /// 桌 ID（无桌 None）。
    pub table_id: Option<u64>,
    /// 输出条目。
    pub outputs: Vec<PreviewOutput>,
    /// request_id（hex；转账/买入为空串）。
    pub request_id: String,
    /// hand_binding（hex；非结算为空串）。
    pub hand_binding: String,
    /// 各输入 note 的 proof 状态名。
    pub proof_states: Vec<String>,
    /// 过期时间（unix 秒）。
    pub expiry: u64,
    /// nonce。
    pub nonce: u64,
    /// 钱包确认摘要（hex；含 chain_id/domain/ABI）。
    pub digest: String,
}

impl std::fmt::Display for SigningPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "== ZChain signing request ==")?;
        writeln!(f, "  kind:        {}", self.kind)?;
        writeln!(f, "  network:     {} (domain {})", self.chain_id, self.domain)?;
        writeln!(f, "  abi_version: {}", self.abi_version)?;
        writeln!(f, "  asset_class: {}", self.asset_class)?;
        writeln!(f, "  amount_in:   {}", self.amount_in)?;
        writeln!(f, "  amount_out:  {}", self.amount_out)?;
        writeln!(f, "  rake:        {}", self.rake)?;
        if let Some(t) = self.table_id {
            writeln!(f, "  table_id:    {t}")?;
        }
        for o in &self.outputs {
            writeln!(f, "  output:      {} -> {}", o.amount, o.owner)?;
        }
        if !self.request_id.is_empty() {
            writeln!(f, "  request_id:  {}", self.request_id)?;
        }
        if !self.hand_binding.is_empty() {
            writeln!(f, "  hand_bind:   {}", self.hand_binding)?;
        }
        for (i, p) in self.proof_states.iter().enumerate() {
            writeln!(f, "  proof[{i}]:    {p}")?;
        }
        writeln!(f, "  expiry:      {}", self.expiry)?;
        writeln!(f, "  nonce:       {}", self.nonce)?;
        writeln!(f, "  digest:      {}", self.digest)?;
        Ok(())
    }
}

/// 已签名操作（含签名前生成的预览与确认摘要）。
#[derive(Debug, Clone)]
pub struct SignedOperation {
    /// 完整账本操作（spend 签名已内嵌，borsh ABI 与 poker-appchain 一致）。
    pub operation: Operation,
    /// 钱包确认摘要（含 chain_id/domain/ABI）。
    pub digest: [u8; 32],
    /// 人类可读预览（签名人看到什么，摘要就绑定什么）。
    pub preview: SigningPreview,
}

/// nonce 防重放账本：(chain_id, nonce) 已用集合。
#[derive(Debug, Default, Clone)]
pub struct NonceTracker {
    used: std::collections::BTreeMap<String, std::collections::BTreeSet<u64>>,
}

impl NonceTracker {
    /// 新建空账本。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 检查（不占用）。
    #[must_use]
    pub fn is_free(&self, chain_id: &str, nonce: u64) -> bool {
        self.used.get(chain_id).is_none_or(|s| !s.contains(&nonce))
    }

    /// 占用（重复 → [`WalletError::NonceReplay`]）。
    ///
    /// # Errors
    /// 重放 → [`WalletError::NonceReplay`]。
    pub fn consume(&mut self, chain_id: &str, nonce: u64) -> WalletResult<()> {
        let set = self.used.entry(chain_id.to_string()).or_default();
        if !set.insert(nonce) {
            return Err(WalletError::NonceReplay {
                chain: chain_id.to_string(),
                nonce,
            });
        }
        Ok(())
    }

    /// 已用集合快照（持久化用；稳定序）。
    #[must_use]
    pub fn used_map(&self) -> std::collections::BTreeMap<String, Vec<u64>> {
        self.used
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
            .collect()
    }

    /// 从持久化快照恢复。
    #[must_use]
    pub fn from_used(used: std::collections::BTreeMap<String, Vec<u64>>) -> Self {
        Self {
            used: used
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().collect()))
                .collect(),
        }
    }
}

/// 签名器：持有 note store 视图与当前时间，执行全部前置检查。
pub struct Signer<'a> {
    stores: &'a WalletStores,
    now: u64,
    nonces: &'a mut NonceTracker,
}

impl<'a> Signer<'a> {
    /// 新建签名器（`now` 为 unix 秒；nonce 账本由调用方持久化）。
    #[must_use]
    pub fn new(stores: &'a WalletStores, now: u64, nonces: &'a mut NonceTracker) -> Self {
        Self { stores, now, nonces }
    }

    /// 上下文合法性检查（ABI 版本/过期/nonce 重放），通过后占用 nonce。
    fn check_ctx(&mut self, ctx: &RequestContext) -> WalletResult<()> {
        if ctx.network.chain_id.is_empty() {
            return Err(WalletError::InvalidArgument("chain_id"));
        }
        if ctx.network.abi_version != SUPPORTED_ABI_VERSION {
            return Err(WalletError::UnknownAbiVersion(ctx.network.abi_version));
        }
        if ctx.expiry < self.now {
            return Err(WalletError::Expired { expiry: ctx.expiry, now: self.now });
        }
        if !self.nonces.is_free(&ctx.network.chain_id, ctx.nonce) {
            return Err(WalletError::NonceReplay {
                chain: ctx.network.chain_id.clone(),
                nonce: ctx.nonce,
            });
        }
        self.nonces.consume(&ctx.network.chain_id, ctx.nonce)
    }

    /// 按承诺解析本钱包持有的 note（要求未花费；seat note 不可经此路径花费）。
    fn resolve_inputs(
        &self,
        asset_class: AssetClass,
        inputs: &[[u8; 32]],
    ) -> WalletResult<Vec<NoteRecord>> {
        let store = self.store_ref(asset_class);
        inputs
            .iter()
            .map(|c| {
                let rec = store
                    .get(c)
                    .ok_or_else(|| WalletError::NoteNotFound(hex::encode(c)))?;
                if rec.note.asset_class != asset_class {
                    return Err(WalletError::AssetClassMismatch(format!(
                        "expected {}, got {}",
                        asset_class.name(),
                        rec.note.asset_class.name()
                    )));
                }
                if !rec.spendable() {
                    return Err(WalletError::InvalidArgument("note already spent or seated"));
                }
                Ok(rec.clone())
            })
            .collect()
    }

    /// 按承诺解析 note（不要求未花费——结算消费 seat note 时使用）。
    fn resolve_any(&self, asset_class: AssetClass, commitment: &[u8; 32]) -> WalletResult<NoteRecord> {
        let store = self.store_ref(asset_class);
        let rec = store
            .get(commitment)
            .ok_or_else(|| WalletError::NoteNotFound(hex::encode(commitment)))?;
        if rec.note.asset_class != asset_class {
            return Err(WalletError::AssetClassMismatch(format!(
                "expected {}, got {}",
                asset_class.name(),
                rec.note.asset_class.name()
            )));
        }
        Ok(rec.clone())
    }

    fn store_ref(&self, class: AssetClass) -> &crate::note_store::NoteStore {
        match class {
            AssetClass::Real => self.stores.real(),
            AssetClass::Play => self.stores.play(),
        }
    }

    /// 安静解析（找不到返回 None；预览展示用，不走 fail-closed 错误路径）。
    fn stores_resolve_quiet(&self, class: AssetClass, commitment: &[u8; 32]) -> Option<NoteRecord> {
        self.store_ref(class).get(commitment).cloned()
    }

    /// 守恒/溢出预检（u128 checked 聚合；u64 上限；`exact_balance` 时要求
    /// Σinputs == Σoutputs——转账/轮换的守恒语义）。
    fn precheck_amounts(
        inputs: &[NoteRecord],
        outputs: &[OutputSpec],
        exact_balance: bool,
    ) -> WalletResult<(u128, u128)> {
        let mut sum_in: u128 = 0;
        for r in inputs {
            sum_in = sum_in
                .checked_add(u128::from(r.note.amount))
                .ok_or(WalletError::AmountOverflow("input sum"))?;
        }
        let mut sum_out: u128 = 0;
        for o in outputs {
            if o.amount == 0 {
                return Err(WalletError::AmountOverflow("zero output"));
            }
            sum_out = sum_out
                .checked_add(u128::from(o.amount))
                .ok_or(WalletError::AmountOverflow("output sum"))?;
        }
        if sum_in > u64::MAX as u128 || sum_out > u64::MAX as u128 {
            return Err(WalletError::AmountOverflow("exceeds u64 ledger amounts"));
        }
        if exact_balance && sum_in != sum_out {
            return Err(WalletError::AmountOverflow("inputs != outputs"));
        }
        Ok((sum_in, sum_out))
    }

    /// 结算骨架的预览期守恒检查（完整校验在签名完备后跑）。
    fn precheck_settle(record: &SettlementRecord) -> WalletResult<(u128, u128)> {
        if record.inputs.is_empty() {
            return Err(WalletError::InvalidArgument("empty settlement inputs"));
        }
        let mut sum_in: u128 = 0;
        for i in &record.inputs {
            sum_in = sum_in
                .checked_add(u128::from(i.note.amount))
                .ok_or(WalletError::AmountOverflow("settle input sum"))?;
        }
        let mut sum_out: u128 = record.rake.total as u128;
        for p in &record.payouts {
            sum_out = sum_out
                .checked_add(u128::from(p.amount))
                .ok_or(WalletError::AmountOverflow("settle payout sum"))?;
        }
        if sum_in != sum_out {
            return Err(WalletError::AmountOverflow("settle conservation"));
        }
        if u128::from(record.pot) != sum_in {
            return Err(WalletError::AmountOverflow("pot != seat contributions"));
        }
        Ok((sum_in, sum_out - u128::from(record.rake.total)))
    }

    /// 构造人类可读预览 + 确认摘要（只读检查，不占用 nonce）。
    ///
    /// # Errors
    /// 全部拒绝面（见模块文档）。
    pub fn preview(&mut self, req: &SigningRequest) -> WalletResult<SigningPreview> {
        let ctx = req.ctx();
        if ctx.network.abi_version != SUPPORTED_ABI_VERSION {
            return Err(WalletError::UnknownAbiVersion(ctx.network.abi_version));
        }
        if ctx.expiry < self.now {
            return Err(WalletError::Expired { expiry: ctx.expiry, now: self.now });
        }
        let (kind, asset_class, amount_in, amount_out, rake, table_id, outputs, request_id, hand_binding, proof_states) =
            match req {
                SigningRequest::Transfer { asset_class, inputs, outputs, .. } => {
                    let recs = self.resolve_inputs(*asset_class, inputs)?;
                    let (i, o) = Self::precheck_amounts(&recs, outputs, true)?;
                    let prev_outs = outputs
                        .iter()
                        .map(|s| PreviewOutput { owner: hex::encode(s.owner), amount: s.amount })
                        .collect();
                    ("transfer", *asset_class, i, o, 0u64, None, prev_outs, String::new(), String::new(), proof_names(&recs))
                }
                SigningRequest::KeyRotation { asset_class, inputs, new_owner, .. } => {
                    let recs = self.resolve_inputs(*asset_class, inputs)?;
                    let outs: Vec<OutputSpec> = recs
                        .iter()
                        .map(|r| OutputSpec { owner: *new_owner, amount: r.note.amount })
                        .collect();
                    let (i, o) = Self::precheck_amounts(&recs, &outs, true)?;
                    let prev_outs = outs
                        .iter()
                        .map(|s| PreviewOutput { owner: hex::encode(s.owner), amount: s.amount })
                        .collect();
                    ("key_rotation", *asset_class, i, o, 0u64, None, prev_outs, String::new(), String::new(), proof_names(&recs))
                }
                SigningRequest::BuyIn { asset_class, table_id, inputs, .. } => {
                    let recs = self.resolve_inputs(*asset_class, inputs)?;
                    let (i, _) = Self::precheck_amounts(&recs, &[], false)?;
                    ("buy_in", *asset_class, i, i, 0u64, Some(*table_id), Vec::new(), String::new(), String::new(), proof_names(&recs))
                }
                SigningRequest::Withdraw { asset_class, input, request_id, vault_target, .. } => {
                    let rec = self.resolve_any(*asset_class, input)?;
                    if !rec.spendable() {
                        return Err(WalletError::InvalidArgument("note already spent or seated"));
                    }
                    let amount = u128::from(rec.note.amount);
                    let prev_outs = vec![PreviewOutput { owner: vault_target.clone(), amount: rec.note.amount }];
                    ("withdraw", *asset_class, amount, 0, 0u64, None, prev_outs, hex::encode(request_id), String::new(), proof_names(std::slice::from_ref(&rec)))
                }
                SigningRequest::Settle { record, .. } => {
                    let (i, o) = Self::precheck_settle(record)?;
                    // 预览只标注 proof 状态：本钱包不持有的输入（对手方的
                    // seat note）标记为 external，不视为错误——完整校验在
                    // 签名完备后由 validate_settlement 执行（fail-closed）。
                    let mut recs = Vec::new();
                    for input in &record.inputs {
                        match self.stores_resolve_quiet(input.note.asset_class, &input.note.commitment_bytes()) {
                            Some(rec) => recs.push(rec),
                            None => recs.push(NoteRecord::external_proof_stub()),
                        }
                    }
                    let prev_outs = record
                        .payouts
                        .iter()
                        .map(|p| PreviewOutput { owner: hex::encode(p.owner), amount: p.amount })
                        .collect();
                    (
                        "settle", record.inputs[0].note.asset_class, i, o,
                        record.rake.total, Some(record.table_id), prev_outs,
                        String::new(), hex::encode(record.hand_binding), proof_names(&recs),
                    )
                }
            };
        let digest = preview_digest(req, &outputs, rake, table_id, &request_id);
        Ok(SigningPreview {
            kind,
            domain: ctx.network.domain.as_str().to_string(),
            chain_id: ctx.network.chain_id.clone(),
            abi_version: ctx.network.abi_version,
            asset_class: asset_class.name(),
            amount_in,
            amount_out,
            rake,
            table_id,
            outputs,
            request_id,
            hand_binding,
            proof_states,
            expiry: ctx.expiry,
            nonce: ctx.nonce,
            digest: hex::encode(digest),
        })
    }

    /// 结构化签名（owner key 路径）。
    ///
    /// # Errors
    /// 全部拒绝面（见模块文档）。
    pub fn sign(&mut self, req: &SigningRequest, key: &OwnerKeyPair) -> WalletResult<SignedOperation> {
        let preview = self.preview(req)?;
        self.check_ctx(req.ctx())?;
        let op = self.build_operation(req, &SignerKey::Owner(key))?;
        // 结算：签名完备后的记录必须通过账本全量校验，否则不出签名。
        if let Operation::Settle(record) = &op {
            if let SigningRequest::Settle { policy, .. } = req {
                validate_settlement(record, policy)
                    .map_err(|e| WalletError::VerifierRejected(e.to_string()))?;
            }
        }
        let digest = hex::decode(&preview.digest)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or(WalletError::Codec("digest decode".into()))?;
        Ok(SignedOperation { operation: op, digest, preview })
    }

    /// 结构化签名（session key 路径；WALLET-ACC-3/3a）。
    ///
    /// 约束：scope/限额/桌白名单/时间窗/撤销/换网。KeyRotation 属高风险，
    /// 会话密钥一律拒绝（必须主 owner 二次授权）。
    ///
    /// # Errors
    /// 见 [`crate::key_manager::session_admission`] 与模块文档拒绝面。
    pub fn sign_with_session(
        &mut self,
        req: &SigningRequest,
        session: &SessionKey,
        revoked: bool,
        daily_used: (u64, u64),
    ) -> WalletResult<SignedOperation> {
        if matches!(req, SigningRequest::KeyRotation { .. }) {
            return Err(WalletError::SessionRejected(SessionRejectReason::OwnerRequired));
        }
        let ctx = req.ctx();
        let preview = self.preview(req)?;
        let amount = preview.amount_out.min(u64::MAX as u128) as u64;
        crate::key_manager::session_admission(
            &session.constraints,
            revoked,
            daily_used,
            &crate::key_manager::SessionAdmission {
                scope: req.scope(),
                table_id: preview.table_id,
                amount,
                chain_id: ctx.network.chain_id.clone(),
            },
            self.now,
        )?;
        self.check_ctx(ctx)?;
        let op = self.build_operation(req, &SignerKey::Session(session))?;
        let digest = hex::decode(&preview.digest)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or(WalletError::Codec("digest decode".into()))?;
        Ok(SignedOperation { operation: op, digest, preview })
    }

    /// **任意 bytes 签名入口——不存在。** 本函数永远拒绝（WALLET-ACC-3：
    /// 恶意 dapp 无法借钱包盲签任意字节）。
    ///
    /// # Errors
    /// 恒 [`WalletError::RawBytesRejected`]。
    pub fn sign_raw_bytes(&mut self, _label: &str, _bytes: &[u8]) -> WalletResult<()> {
        Err(WalletError::RawBytesRejected)
    }

    /// 结算**单输入**花费授权（多人桌协议路径：每个玩家只签自己的 seat note，
    /// operator 收集全部 SpendAuth 后组装完整记录；本地钱包随后用
    /// [`crate::verifier::verify_settlement`] 对完整记录做验证即确认）。
    ///
    /// 摘要与 [`SigningRequest::Settle`] 路径完全一致（scope = 结算域 +
    /// hand_binding，effect = 完整结算效果摘要——二者都不含 spend 本身，
    /// 因此可以先于记录完备签名）。
    ///
    /// # Errors
    /// 输入越界 / 输入 owner 不是签名人 / 本地无该 note 或内容不符 →
    /// 对应错误（fail-closed）。
    pub fn sign_settle_input(
        &self,
        record: &SettlementRecord,
        input_index: usize,
        key: &OwnerKeyPair,
    ) -> WalletResult<SpendAuth> {
        let input = record
            .inputs
            .get(input_index)
            .ok_or(WalletError::InvalidArgument("settle input index"))?;
        if input.note.owner != key.public_bytes() {
            return Err(WalletError::InvalidArgument("settle input not owned by signer"));
        }
        let rec = self.resolve_any(input.note.asset_class, &input.note.commitment_bytes())?;
        if rec.note != input.note {
            return Err(WalletError::InvalidArgument("settle input mismatch"));
        }
        let scope = settle_spend_scope(&record.hand_binding);
        let effect = settle_effect(record);
        let commitment = input.note.commitment_bytes();
        let nullifier =
            poker_appchain::felt::felt_to_bytes32(&input.note.nullifier(rec.spend_secret.expose()));
        let digest = spend_digest(&commitment, &nullifier, &scope, &effect);
        Ok(SpendAuth {
            commitment,
            nullifier,
            sig: poker_appchain::keys::EcdsaSig { bytes: key.sign_digest(&digest) },
        })
    }

    fn build_operation(
        &mut self,
        req: &SigningRequest,
        key: &SignerKey<'_>,
    ) -> WalletResult<Operation> {
        let signer_public = key.public_bytes();
        /// 用签名人私钥对单张 note 的花费授权签名（nullifier 由该 note 的
        /// spend secret 派生）。
        fn make_spend(
            key: &SignerKey<'_>,
            note_secret: &[u8; 32],
            note: &Note,
            scope_tag: &[u8],
            effect: &[u8; 32],
        ) -> SpendAuth {
            let commitment = note.commitment_bytes();
            let nullifier = poker_appchain::felt::felt_to_bytes32(&note.nullifier(note_secret));
            let digest = spend_digest(&commitment, &nullifier, scope_tag, effect);
            SpendAuth {
                commitment,
                nullifier,
                sig: poker_appchain::keys::EcdsaSig { bytes: key.sign_digest(&digest) },
            }
        }
        match req {
            SigningRequest::Transfer { asset_class, inputs, outputs, .. } => {
                let recs = self.resolve_inputs(*asset_class, inputs)?;
                let specs: Vec<NoteSpec> = outputs
                    .iter()
                    .map(|o| NoteSpec {
                        asset_class: *asset_class,
                        amount: o.amount,
                        owner: o.owner,
                        table_id: None,
                        pot_index: 0,
                        runout_index: 0,
                    })
                    .collect();
                let effect =
                    Operation::Transfer { spends: vec![], notes: vec![], outputs: specs.clone() }
                        .effect_digest();
                let spends: Vec<SpendAuth> = recs
                    .iter()
                    .map(|r| make_spend(key, r.spend_secret.expose(), &r.note, op_scope::TRANSFER, &effect))
                    .collect();
                let notes: Vec<Note> = recs.iter().map(|r| r.note.clone()).collect();
                Ok(Operation::Transfer { spends, notes, outputs: specs })
            }
            SigningRequest::KeyRotation { asset_class, inputs, new_owner, .. } => {
                let recs = self.resolve_inputs(*asset_class, inputs)?;
                let specs: Vec<NoteSpec> = recs
                    .iter()
                    .map(|r| NoteSpec {
                        asset_class: *asset_class,
                        amount: r.note.amount,
                        owner: *new_owner,
                        table_id: None,
                        pot_index: 0,
                        runout_index: 0,
                    })
                    .collect();
                let effect =
                    Operation::Transfer { spends: vec![], notes: vec![], outputs: specs.clone() }
                        .effect_digest();
                let spends: Vec<SpendAuth> = recs
                    .iter()
                    .map(|r| make_spend(key, r.spend_secret.expose(), &r.note, op_scope::TRANSFER, &effect))
                    .collect();
                let notes: Vec<Note> = recs.iter().map(|r| r.note.clone()).collect();
                Ok(Operation::Transfer { spends, notes, outputs: specs })
            }
            SigningRequest::BuyIn { asset_class, table_id, seat_owner, inputs, .. } => {
                let recs = self.resolve_inputs(*asset_class, inputs)?;
                let effect = Operation::BuyIn {
                    table_id: *table_id,
                    spends: vec![],
                    notes: vec![],
                    seat_owner: *seat_owner,
                }
                .effect_digest();
                let spends: Vec<SpendAuth> = recs
                    .iter()
                    .map(|r| make_spend(key, r.spend_secret.expose(), &r.note, op_scope::BUYIN, &effect))
                    .collect();
                let notes: Vec<Note> = recs.iter().map(|r| r.note.clone()).collect();
                Ok(Operation::BuyIn { table_id: *table_id, spends, notes, seat_owner: *seat_owner })
            }
            SigningRequest::Withdraw { asset_class, input, request_id, payout_recipient, .. } => {
                let rec = self.resolve_any(*asset_class, input)?;
                if !rec.spendable() {
                    return Err(WalletError::InvalidArgument("note already spent or seated"));
                }
                let note = rec.note.clone();
                // P1：收款人进效果摘要 → 进 spend 签名（链侧换地址必 BadSignature）
                let effect = Operation::WithdrawRequest {
                    spend: SpendAuth {
                        commitment: [0; 32],
                        nullifier: [0; 32],
                        sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                    },
                    note: note.clone(),
                    request_id: *request_id,
                    payout_recipient: *payout_recipient,
                }
                .effect_digest();
                let spend = make_spend(key, rec.spend_secret.expose(), &note, op_scope::WITHDRAW, &effect);
                Ok(Operation::WithdrawRequest {
                    spend,
                    note,
                    request_id: *request_id,
                    payout_recipient: *payout_recipient,
                })
            }
            SigningRequest::Settle { record, .. } => {
                let scope = settle_spend_scope(&record.hand_binding);
                let effect = settle_effect(record);
                let mut signed = record.clone();
                for input in &mut signed.inputs {
                    if input.note.owner == signer_public {
                        // 本钱包的 seat note：从 note store 解析 secret 并补签。
                        let rec = self.resolve_any(input.note.asset_class, &input.note.commitment_bytes())?;
                        if rec.note != input.note {
                            return Err(WalletError::InvalidArgument("settle input mismatch"));
                        }
                        input.spend = make_spend(key, rec.spend_secret.expose(), &input.note, &scope, &effect);
                    }
                    // 非本钱包输入：保留 operator 收集到的既有签名。
                }
                Ok(Operation::Settle(Box::new(signed)))
            }
        }
    }
}

/// 内部签名身份（owner 或 session）。
enum SignerKey<'k> {
    /// 主 owner key。
    Owner(&'k OwnerKeyPair),
    /// 受限会话 key。
    Session(&'k SessionKey),
}

impl SignerKey<'_> {
    fn public_bytes(&self) -> [u8; 33] {
        match self {
            Self::Owner(k) => k.public_bytes(),
            Self::Session(k) => k.public_bytes(),
        }
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        match self {
            Self::Owner(k) => k.sign_digest(digest),
            Self::Session(k) => k.sign_digest(digest),
        }
    }
}

/// proof 状态名（预览展示；本钱包不持有的输入显示 external）。
fn proof_names(recs: &[NoteRecord]) -> Vec<String> {
    recs.iter()
        .map(|r| {
            if r.is_external_stub {
                return "external".to_string();
            }
            match r.proof {
                crate::note_store::ProofState::Pending => "pending",
                crate::note_store::ProofState::Soft => "soft",
                crate::note_store::ProofState::Proven { .. } => "proven",
                crate::note_store::ProofState::Finalized => "finalized",
            }
            .to_string()
        })
        .collect()
}

/// 钱包确认摘要：`blake2s(DOMAIN, chain_id, domain, abi_be, kind, nonce,
/// expiry_be, semantic_payload_borsh, preview_bytes)`。
///
/// 语义载荷按种类取"签名即授权"的最小绑定集（输出集/桌/幂等键/结算记录）；
/// 跨网络/跨 ABI/跨域摘要必不同（WALLET-ACC-2 逻辑面）。
#[must_use]
pub fn preview_digest(
    req: &SigningRequest,
    outputs: &[PreviewOutput],
    rake: u64,
    table_id: Option<u64>,
    request_id: &str,
) -> [u8; 32] {
    let ctx = req.ctx();
    let payload: Vec<u8> = match req {
        SigningRequest::Transfer { outputs: outs, asset_class, inputs, .. } => {
            borsh::to_vec(&(inputs, outs, asset_class.as_u8())).unwrap_or_default()
        }
        SigningRequest::KeyRotation { inputs, new_owner, asset_class, .. } => {
            borsh::to_vec(&(inputs, new_owner, asset_class.as_u8())).unwrap_or_default()
        }
        SigningRequest::BuyIn { inputs, seat_owner, asset_class, .. } => {
            borsh::to_vec(&(inputs, seat_owner, asset_class.as_u8())).unwrap_or_default()
        }
        SigningRequest::Withdraw { input, request_id, asset_class, payout_recipient, vault_target, .. } => {
            borsh::to_vec(&(input, request_id, asset_class.as_u8(), payout_recipient, vault_target))
                .unwrap_or_default()
        }
        SigningRequest::Settle { record, policy, .. } => {
            borsh::to_vec(&(record, policy)).unwrap_or_default()
        }
    };
    // 预览输出（含十六进制 owner 串）一并入摘要：展示与签名内容一致。
    let preview_bytes =
        borsh::to_vec(&(outputs, rake, table_id, request_id)).unwrap_or_default();
    blake2s32(&[
        DOMAIN_OPERATION_DIGEST,
        ctx.network.chain_id.as_bytes(),
        ctx.network.domain.as_str().as_bytes(),
        &ctx.network.abi_version.to_be_bytes(),
        kind_bytes(req),
        &ctx.nonce.to_be_bytes(),
        &ctx.expiry.to_be_bytes(),
        &payload,
        &preview_bytes,
    ])
}

/// 操作种类字节（摘要用）。
fn kind_bytes(req: &SigningRequest) -> &'static [u8] {
    match req {
        SigningRequest::Transfer { .. } => b"transfer",
        SigningRequest::BuyIn { .. } => b"buy_in",
        SigningRequest::Withdraw { .. } => b"withdraw",
        SigningRequest::Settle { .. } => b"settle",
        SigningRequest::KeyRotation { .. } => b"key_rotation",
    }
}
