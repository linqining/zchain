//! 跨链桥模块（Task 34）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 893-907 行：
//! - **SubTask 34.1**：定义 `BridgeHook` trait + `bridge_verify` syscall 接口
//! - **SubTask 34.2**：`bridge_verify` 必须由协议层在 deposit 流程中调用，
//!   不允许任意合约直接调用（返回 `BridgeVerifyNotAuthorized`）
//! - **SubTask 34.3**：签名绑定 `(nonce, source_chain_id, dest_chain_id, asset, amount,
//!   recipient, source_tx_hash)` 防重放（SEC-H3 修复 — 补全 `recipient` 与 `source_tx_hash`）；
//!   防重放由 `nonce` + `dest_chain_id` 保证；在 poker_l1 上铸造对应 wrapped 对象给 `recipient`；
//!   **SEC2-M1 修复**：bridge_verify tx 须由 recipient 本人签名提交（防抢跑）；
//!   recipient 可指定 `preferred_relayer` 获额外奖励
//! - **SubTask 34.4**：反向操作需 burn wrapped 对象 + burn proof（burn-on-source）
//! - **SubTask 34.5**：桥验证器插槽注册机制
//!
//! # 安全约束
//!
//! - **SEC-H3**：签名绑定补全 `recipient` + `source_tx_hash`
//! - **SEC2-M1**：bridge_verify 须 recipient 签名 + preferred_relayer 机制
//! - **SubTask 34.2**：协议层调用强制

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;
use crate::{Address, ChainId, Hash};

// ===== 常量 =====

/// 桥签名域分隔前缀。
const BRIDGE_SIG_DOMAIN: u8 = 0x42; // 'B' for Bridge

/// Burn proof 域分隔前缀。
const BURN_PROOF_DOMAIN: u8 = 0x62; // 'b' for burn

// ===== BridgeDeposit（跨链存款凭证） =====

/// 跨链存款凭证（SubTask 34.3）。
///
/// SEC-H3 修复：签名绑定字段补全 `recipient` 与 `source_tx_hash`。
///
/// # 字段说明
///
/// - `nonce`：源链上的唯一 nonce（防重放）
/// - `source_chain_id`：源链 chain_id
/// - `dest_chain_id`：目标链 chain_id（poker_l1）
/// - `asset`：资产标识（源链上的合约地址 / token id）
/// - `amount`：存款金额
/// - `recipient`：poker_l1 上的接收地址（tagged pubkey 派生地址，SEC-H3）
/// - `source_tx_hash`：源链上的交易哈希（跨链追踪，SEC-H3）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDeposit {
    /// 源链上的唯一 nonce（防重放）。
    pub nonce: u64,
    /// 源链 chain_id。
    pub source_chain_id: ChainId,
    /// 目标链 chain_id（poker_l1）。
    pub dest_chain_id: ChainId,
    /// 资产标识（源链上的合约地址 / token id，32 字节）。
    pub asset: Hash,
    /// 存款金额。
    pub amount: u64,
    /// poker_l1 上的接收地址（SEC-H3：tagged pubkey 派生地址）。
    pub recipient: Address,
    /// 源链上的交易哈希（SEC-H3：跨链追踪）。
    pub source_tx_hash: Hash,
}

impl BridgeDeposit {
    /// 计算桥签名的消息哈希。
    ///
    /// 签名对象 = `blake2b_256(BRIDGE_SIG_DOMAIN || nonce || source_chain_id ||
    /// dest_chain_id || asset || amount || recipient || source_tx_hash)`
    ///
    /// SEC-H3：所有字段均参与哈希，防签名被重用到不同 recipient / amount。
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[BRIDGE_SIG_DOMAIN]);
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.source_chain_id.to_le_bytes());
        h.update(&self.dest_chain_id.to_le_bytes());
        h.update(&self.asset);
        h.update(&self.amount.to_le_bytes());
        h.update(&self.recipient);
        h.update(&self.source_tx_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

// ===== BridgeVerifyTx（bridge_verify 交易） =====

/// bridge_verify 交易（SubTask 34.3 + SEC2-M1）。
///
/// SEC2-M1 修复：
/// - `recipient_sig`：须由 recipient 本人签名提交（防第三方抢跑）
/// - `preferred_relayer`：recipient 可指定优先 relayer 获额外奖励
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeVerifyTx {
    /// 存款凭证。
    pub deposit: BridgeDeposit,
    /// 桥验证器的签名集合（多签背书）。
    pub validator_signatures: Vec<BridgeValidatorSig>,
    /// recipient 本人签名（SEC2-M1：防抢跑）。
    ///
    /// 签名对象 = `blake2b_256(BRIDGE_SIG_DOMAIN || deposit.message_hash())`
    pub recipient_sig: Vec<u8>,
    /// recipient 的 tagged pubkey（用于验证 recipient_sig）。
    pub recipient_pubkey: TaggedPubkey,
    /// 优先 relayer（SEC2-M1：获额外奖励；None 表示无优先）。
    pub preferred_relayer: Option<TaggedPubkey>,
}

/// 桥验证器签名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeValidatorSig {
    /// 验证器 tagged pubkey。
    pub validator: TaggedPubkey,
    /// 签名字节。
    pub signature: Vec<u8>,
}

// ===== BurnProof（burn-on-source） =====

/// Burn 证明（SubTask 34.4）。
///
/// 反向操作：在 poker_l1 上 burn wrapped 对象，生成 burn proof，
/// 提交到源链以解锁原始资产。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnProof {
    /// burn nonce（poker_l1 上的唯一 nonce，防重放）。
    pub burn_nonce: u64,
    /// 源链 chain_id（资产原始链）。
    pub source_chain_id: ChainId,
    /// 目标链 chain_id（poker_l1，burn 发生链）。
    pub dest_chain_id: ChainId,
    /// 资产标识。
    pub asset: Hash,
    /// burn 金额。
    pub amount: u64,
    /// 接收地址（源链上的接收者）。
    pub recipient: Address,
    /// poker_l1 上的 burn tx 哈希。
    pub burn_tx_hash: Hash,
}

impl BurnProof {
    /// 计算 burn proof 的消息哈希。
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[BURN_PROOF_DOMAIN]);
        h.update(&self.burn_nonce.to_le_bytes());
        h.update(&self.source_chain_id.to_le_bytes());
        h.update(&self.dest_chain_id.to_le_bytes());
        h.update(&self.asset);
        h.update(&self.amount.to_le_bytes());
        h.update(&self.recipient);
        h.update(&self.burn_tx_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

// ===== BridgeValidatorSlot（桥验证器插槽） =====

/// 桥验证器插槽（SubTask 34.5）。
///
/// 每条外部链可注册独立的桥验证器集，负责签名背书存款凭证。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeValidatorSlot {
    /// 源链 chain_id。
    pub source_chain_id: ChainId,
    /// 注册的桥验证器 pubkey 集合。
    pub validators: BTreeSet<TaggedPubkey>,
    /// 所需 quorum 数（2/3 of validators）。
    pub quorum: usize,
}

impl BridgeValidatorSlot {
    /// 创建新插槽。
    #[must_use]
    pub fn new(source_chain_id: ChainId, validators: BTreeSet<TaggedPubkey>) -> Self {
        let quorum = required_bridge_quorum(validators.len());
        Self {
            source_chain_id,
            validators,
            quorum,
        }
    }

    /// 校验签名数是否达到 quorum。
    #[must_use]
    pub const fn has_quorum(&self, sig_count: usize) -> bool {
        sig_count >= self.quorum
    }

    /// 校验签名者是否全部在插槽中，且无重复签名（H1 修复）。
    pub fn validate_signers(&self, sigs: &[BridgeValidatorSig]) -> PokerL1Result<()> {
        let mut seen = BTreeSet::new();
        for sig in sigs {
            if !self.validators.contains(&sig.validator) {
                return Err(PokerL1Error::BridgeValidatorSlotNotRegistered(
                    sig.validator.clone(),
                ));
            }
            if !seen.insert(sig.validator.clone()) {
                return Err(PokerL1Error::DuplicateBridgeValidator(
                    sig.validator.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// 计算桥验证器 quorum（2/3，向上取整）。
#[must_use]
pub const fn required_bridge_quorum(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    (validator_count * 2).div_ceil(3) // ceil(n * 2 / 3)
}

// ===== BridgeHook trait（SubTask 34.1） =====

/// 跨链桥 hook trait（SubTask 34.1）。
///
/// 实现者通过此 trait 注册新桥，定义特定于源链的验证逻辑。
///
/// # 安全约束
///
/// - `bridge_verify` 必须由协议层在 deposit 流程中调用（SubTask 34.2）
/// - 不允许任意合约直接调用（返回 `BridgeVerifyNotAuthorized`）
pub trait BridgeHook: Send + Sync {
    /// 返回源链 chain_id。
    fn source_chain_id(&self) -> ChainId;

    /// 验证桥存款凭证的签名背书。
    ///
    /// # 参数
    /// - `deposit`：存款凭证
    /// - `sigs`：桥验证器签名集合
    ///
    /// # 返回
    /// - `Ok(())`：验证通过
    /// - `Err(_)`：签名不足 / 验证器未注册 / 签名无效
    fn verify_deposit(
        &self,
        deposit: &BridgeDeposit,
        sigs: &[BridgeValidatorSig],
    ) -> PokerL1Result<()>;

    /// 验证 burn proof（SubTask 34.4）。
    ///
    /// 反向操作：验证 poker_l1 上的 burn 是否合法。
    fn verify_burn(&self, burn: &BurnProof) -> PokerL1Result<()>;
}

// ===== BridgeRegistry（桥注册表） =====

/// 桥注册表（管理所有已注册的 BridgeHook）。
#[derive(Debug, Default)]
pub struct BridgeRegistry {
    /// 按 source_chain_id 索引的桥验证器插槽。
    slots: BTreeMap<ChainId, BridgeValidatorSlot>,
    /// 已消费的 nonce（防重放：`(source_chain_id, nonce)` → true）。
    consumed_nonces: BTreeSet<(ChainId, u64)>,
    /// 已消费的 burn nonce（防重放）。
    consumed_burn_nonces: BTreeSet<(ChainId, u64)>,
}

impl BridgeRegistry {
    /// 创建空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册桥验证器插槽（SubTask 34.5）。
    pub fn register_slot(&mut self, slot: BridgeValidatorSlot) {
        self.slots.insert(slot.source_chain_id, slot);
    }

    /// 获取指定源链的插槽。
    #[must_use]
    pub fn slot(&self, source_chain_id: ChainId) -> Option<&BridgeValidatorSlot> {
        self.slots.get(&source_chain_id)
    }

    /// 检查 nonce 是否已消费（防重放）。
    #[must_use]
    pub fn is_nonce_consumed(&self, source_chain_id: ChainId, nonce: u64) -> bool {
        self.consumed_nonces.contains(&(source_chain_id, nonce))
    }

    /// 标记 nonce 已消费。
    pub fn consume_nonce(&mut self, source_chain_id: ChainId, nonce: u64) {
        self.consumed_nonces.insert((source_chain_id, nonce));
    }

    /// 检查 burn nonce 是否已消费。
    #[must_use]
    pub fn is_burn_nonce_consumed(&self, dest_chain_id: ChainId, burn_nonce: u64) -> bool {
        self.consumed_burn_nonces
            .contains(&(dest_chain_id, burn_nonce))
    }

    /// 标记 burn nonce 已消费。
    pub fn consume_burn_nonce(&mut self, dest_chain_id: ChainId, burn_nonce: u64) {
        self.consumed_burn_nonces
            .insert((dest_chain_id, burn_nonce));
    }
}

// ===== bridge_verify（协议层调用，SubTask 34.2） =====

/// bridge_verify 协议层入口（SubTask 34.2 + 34.3 + SEC2-M1）。
///
/// **安全约束**：此函数必须由协议层在 deposit 流程中调用，
/// 不允许任意合约直接调用。合约直接调用应返回 `BridgeVerifyNotAuthorized`。
///
/// # 验证流程
///
/// 1. 校验 `tx.deposit.dest_chain_id == network_chain_id`（防跨链重放）
/// 2. 校验 nonce 未被消费（防重放）
/// 3. 校验 recipient 签名（SEC2-M1：须 recipient 本人签名）
/// 4. 校验桥验证器签名 quorum + 签名有效性
/// 5. 标记 nonce 已消费
/// 6. 返回验证结果，由协议层执行铸造
///
/// # 参数
///
/// - `registry`：桥注册表
/// - `tx`：bridge_verify 交易
/// - `network_chain_id`：当前网络 chain_id
/// - `is_protocol_caller`：调用方是否为协议层（false → 返回 `BridgeVerifyNotAuthorized`）
pub fn bridge_verify(
    registry: &mut BridgeRegistry,
    tx: &BridgeVerifyTx,
    network_chain_id: ChainId,
    is_protocol_caller: bool,
) -> PokerL1Result<BridgeVerifyOutcome> {
    // SubTask 34.2：必须由协议层调用
    if !is_protocol_caller {
        return Err(PokerL1Error::BridgeVerifyNotAuthorized);
    }

    // 1. 校验目标链匹配
    if tx.deposit.dest_chain_id != network_chain_id {
        return Err(PokerL1Error::BridgeSignatureInvalid(format!(
            "dest_chain_id mismatch: deposit={}, network={}",
            tx.deposit.dest_chain_id, network_chain_id
        )));
    }

    // 2. 校验 nonce 未被消费（防重放）
    if registry.is_nonce_consumed(tx.deposit.source_chain_id, tx.deposit.nonce) {
        return Err(PokerL1Error::BridgeNonceConsumed(tx.deposit.nonce));
    }

    // 3. 校验 recipient 签名（SEC2-M1）
    let deposit_msg_hash = tx.deposit.message_hash();
    verify_signature(&tx.recipient_pubkey, &tx.recipient_sig, &deposit_msg_hash).map_err(|e| {
        PokerL1Error::BridgeSignatureInvalid(format!("recipient signature invalid: {e}"))
    })?;

    // 校验 recipient_pubkey 派生地址 == deposit.recipient
    let derived_addr = derive_address(&tx.recipient_pubkey);
    if derived_addr != tx.deposit.recipient {
        return Err(PokerL1Error::BridgeSignatureInvalid(
            "recipient_pubkey does not derive to deposit.recipient".to_string(),
        ));
    }

    // 4. 校验桥验证器签名
    let slot = registry.slot(tx.deposit.source_chain_id).ok_or_else(|| {
        PokerL1Error::BridgeValidatorSlotNotRegistered(tx.recipient_pubkey.clone())
    })?;

    // 校验签名者全部在插槽中
    slot.validate_signers(&tx.validator_signatures)?;

    // 校验 quorum
    if !slot.has_quorum(tx.validator_signatures.len()) {
        return Err(PokerL1Error::BridgeSignatureInvalid(format!(
            "insufficient validator signatures: got={}, required={}",
            tx.validator_signatures.len(),
            slot.quorum
        )));
    }

    // 校验每个签名（验证桥验证器对 deposit 的签名）
    for sig in &tx.validator_signatures {
        verify_signature(&sig.validator, &sig.signature, &deposit_msg_hash).map_err(|e| {
            PokerL1Error::BridgeSignatureInvalid(format!(
                "validator {:?} signature invalid: {e}",
                sig.validator
            ))
        })?;
    }

    // 5. 标记 nonce 已消费
    registry.consume_nonce(tx.deposit.source_chain_id, tx.deposit.nonce);

    // 6. 返回验证结果
    Ok(BridgeVerifyOutcome {
        deposit: tx.deposit.clone(),
        recipient: tx.deposit.recipient,
        preferred_relayer: tx.preferred_relayer.clone(),
    })
}

/// bridge_verify 验证结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeVerifyOutcome {
    /// 已验证的存款凭证。
    pub deposit: BridgeDeposit,
    /// 接收地址。
    pub recipient: Address,
    /// 优先 relayer（如有）。
    pub preferred_relayer: Option<TaggedPubkey>,
}

// ===== burn_on_source（SubTask 34.4） =====

/// 执行 burn-on-source（SubTask 34.4）。
///
/// 反向操作：在 poker_l1 上 burn wrapped 对象，生成 burn proof。
///
/// # 验证流程
///
/// 1. 校验 burn_nonce 未被消费
/// 2. 标记 burn_nonce 已消费
/// 3. 返回 burn proof（提交到源链以解锁原始资产）
///
/// # 参数
///
/// - `registry`：桥注册表
/// - `burn`：burn proof
/// - `network_chain_id`：当前网络 chain_id（= burn.dest_chain_id）
pub fn burn_on_source(
    registry: &mut BridgeRegistry,
    burn: &BurnProof,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    // 校验 burn 发生在当前链
    if burn.dest_chain_id != network_chain_id {
        return Err(PokerL1Error::BurnProofInvalid(format!(
            "dest_chain_id mismatch: burn={}, network={}",
            burn.dest_chain_id, network_chain_id
        )));
    }

    // 校验 burn_nonce 未被消费
    if registry.is_burn_nonce_consumed(burn.dest_chain_id, burn.burn_nonce) {
        return Err(PokerL1Error::BurnProofInvalid(format!(
            "burn_nonce already consumed: {}",
            burn.burn_nonce
        )));
    }

    // 标记 burn_nonce 已消费
    registry.consume_burn_nonce(burn.dest_chain_id, burn.burn_nonce);

    Ok(())
}

// ===== 辅助函数 =====

/// 从 tagged pubkey 派生地址（blake2b_256(tagged_pubkey)[0..20]）。
///
/// 与 `account` 模块的地址派生逻辑一致。
fn derive_address(pubkey: &TaggedPubkey) -> Address {
    let bytes = pubkey.to_bytes();
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[0..20]);
    addr
}

// ===== 合约直接调用防护（SubTask 34.2） =====

/// 合约直接调用 bridge_verify 的拒绝路径（SubTask 34.2）。
///
/// 合约层不可直接调用 `bridge_verify`，必须通过协议层。
/// 此函数供 syscall 注册时使用，始终返回 `BridgeVerifyNotAuthorized`。
pub const fn bridge_verify_contract_call_denied() -> PokerL1Error {
    PokerL1Error::BridgeVerifyNotAuthorized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw).unwrap()
    }

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_deposit(nonce: u64, amount: u64, recipient: Address) -> BridgeDeposit {
        BridgeDeposit {
            nonce,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount,
            recipient,
            source_tx_hash: [0xCD; 32],
        }
    }

    fn make_real_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey) {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        // secp256k1_scheme::verify 期望 raw = compressed pubkey (33 字节)
        let compressed = public_key.serialize();
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            compressed.to_vec(),
        )
        .unwrap();
        (secret_key, public_key, tagged)
    }

    fn sign_with_key(
        secp: &Secp256k1<secp256k1::All>,
        secret: &secp256k1::SecretKey,
        msg_hash: &Hash,
    ) -> Vec<u8> {
        let msg = Message::from_digest_slice(msg_hash).unwrap();
        // secp256k1_scheme::verify 期望 r(32) || s(32) || v(1) = 65 字节
        let sig = secp.sign_ecdsa_recoverable(&msg, secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(recovery_id.to_i32() as u8);
        sig_bytes
    }

    // ===== BridgeDeposit 测试 =====

    #[test]
    fn test_deposit_message_hash_deterministic() {
        let deposit1 = make_deposit(1, 100, make_addr(0x01));
        let deposit2 = make_deposit(1, 100, make_addr(0x01));
        assert_eq!(deposit1.message_hash(), deposit2.message_hash());
    }

    #[test]
    fn test_deposit_message_hash_differs_by_field() {
        let base = make_deposit(1, 100, make_addr(0x01));

        // nonce 不同
        let mut d = base.clone();
        d.nonce = 2;
        assert_ne!(base.message_hash(), d.message_hash());

        // amount 不同
        let mut d = base.clone();
        d.amount = 200;
        assert_ne!(base.message_hash(), d.message_hash());

        // recipient 不同（SEC-H3）
        let mut d = base.clone();
        d.recipient = make_addr(0x02);
        assert_ne!(base.message_hash(), d.message_hash());

        // source_tx_hash 不同（SEC-H3）
        let mut d = base.clone();
        d.source_tx_hash = [0xEF; 32];
        assert_ne!(base.message_hash(), d.message_hash());
    }

    // ===== BridgeValidatorSlot 测试 =====

    #[test]
    fn test_required_bridge_quorum() {
        assert_eq!(required_bridge_quorum(0), 0);
        assert_eq!(required_bridge_quorum(1), 1);
        assert_eq!(required_bridge_quorum(3), 2); // ceil(3*2/3) = 2
        assert_eq!(required_bridge_quorum(5), 4); // ceil(5*2/3) = 4
        assert_eq!(required_bridge_quorum(10), 7); // ceil(10*2/3) = 7
    }

    #[test]
    fn test_validator_slot_new() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        assert_eq!(slot.source_chain_id, 0xAAAA);
        assert_eq!(slot.validators.len(), 5);
        assert_eq!(slot.quorum, 4); // ceil(5*2/3) = 4
    }

    #[test]
    fn test_validator_slot_has_quorum() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        assert!(!slot.has_quorum(3));
        assert!(slot.has_quorum(4));
        assert!(slot.has_quorum(5));
    }

    #[test]
    fn test_validator_slot_validate_signers_ok() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators.clone());

        let sigs: Vec<BridgeValidatorSig> = validators
            .iter()
            .take(4)
            .map(|v| BridgeValidatorSig {
                validator: v.clone(),
                signature: vec![0u8; 65],
            })
            .collect();

        assert!(slot.validate_signers(&sigs).is_ok());
    }

    #[test]
    fn test_validator_slot_validate_signers_reject_unknown() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);

        // 未注册的 validator
        let sigs = vec![BridgeValidatorSig {
            validator: make_tagged_pubkey(0xFF),
            signature: vec![0u8; 65],
        }];

        assert!(matches!(
            slot.validate_signers(&sigs),
            Err(PokerL1Error::BridgeValidatorSlotNotRegistered(_))
        ));
    }

    // ===== BridgeRegistry 测试 =====

    #[test]
    fn test_registry_nonce_consumption() {
        let mut registry = BridgeRegistry::new();
        assert!(!registry.is_nonce_consumed(0xAAAA, 1));
        registry.consume_nonce(0xAAAA, 1);
        assert!(registry.is_nonce_consumed(0xAAAA, 1));
        // 不同 source_chain_id 的 nonce 不冲突
        assert!(!registry.is_nonce_consumed(0xBBBB, 1));
    }

    #[test]
    fn test_registry_burn_nonce_consumption() {
        let mut registry = BridgeRegistry::new();
        assert!(!registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 1));
        registry.consume_burn_nonce(crate::DEFAULT_CHAIN_ID, 1);
        assert!(registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 1));
    }

    #[test]
    fn test_registry_register_slot() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);
        assert!(registry.slot(0xAAAA).is_some());
        assert!(registry.slot(0xBBBB).is_none());
    }

    // ===== bridge_verify 测试 =====

    #[test]
    fn test_bridge_verify_rejects_contract_caller() {
        let mut registry = BridgeRegistry::new();
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        // is_protocol_caller = false → 拒绝
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, false);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeVerifyNotAuthorized)
        ));
    }

    #[test]
    fn test_bridge_verify_dest_chain_mismatch() {
        let mut registry = BridgeRegistry::new();
        let tx = BridgeVerifyTx {
            deposit: BridgeDeposit {
                nonce: 1,
                source_chain_id: 0xAAAA,
                dest_chain_id: 0x9999, // 错误
                asset: [0xAB; 32],
                amount: 100,
                recipient: make_addr(0x01),
                source_tx_hash: [0xCD; 32],
            },
            validator_signatures: vec![],
            recipient_sig: vec![],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    #[test]
    fn test_bridge_verify_slot_not_registered() {
        let mut registry = BridgeRegistry::new();
        // 不注册 slot
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        // 应失败（slot 未注册 或 recipient 签名无效）
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_verify_nonce_consumed() {
        let mut registry = BridgeRegistry::new();
        // 预先注册 slot
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 预先消费 nonce
        registry.consume_nonce(0xAAAA, 1);

        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))));
    }

    #[test]
    fn test_bridge_verify_insufficient_quorum() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 仅 3 个签名（< quorum=4）
        let sigs: Vec<BridgeValidatorSig> = (0..3)
            .map(|i| BridgeValidatorSig {
                validator: make_tagged_pubkey(0x10 + i as u8),
                signature: vec![0u8; 65],
            })
            .collect();

        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: sigs,
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        // recipient 签名会先失败（占位签名），所以错误是 BridgeSignatureInvalid
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_verify_full_flow_with_real_signatures() {
        let mut registry = BridgeRegistry::new();
        let secp = Secp256k1::new();

        // 生成 recipient 密钥对
        let (recipient_secret, _recipient_public, recipient_tagged) = make_real_keypair();

        // 生成 5 个桥验证器密钥对
        let validator_keys: Vec<(secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey)> = (0
            ..5)
            .map(|_| {
                let (s, p) = secp.generate_keypair(&mut OsRng);
                let compressed = p.serialize();
                let tagged = TaggedPubkey::new(
                    SignatureScheme::Secp256k1,
                    CURRENT_VERSION,
                    compressed.to_vec(),
                )
                .unwrap();
                (s, p, tagged)
            })
            .collect();

        // 注册 slot
        let validator_set: BTreeSet<TaggedPubkey> =
            validator_keys.iter().map(|(_, _, t)| t.clone()).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validator_set);
        registry.register_slot(slot);

        // 构造 deposit（recipient 地址从 tagged pubkey 派生）
        let recipient_addr = derive_address(&recipient_tagged);
        let deposit = make_deposit(1, 1000, recipient_addr);
        let msg_hash = deposit.message_hash();

        // recipient 签名
        let recipient_sig = sign_with_key(&secp, &recipient_secret, &msg_hash);

        // 桥验证器签名（4 个 = quorum）
        let validator_sigs: Vec<BridgeValidatorSig> = validator_keys
            .iter()
            .take(4)
            .map(|(s, _, t)| {
                let sig = sign_with_key(&secp, s, &msg_hash);
                BridgeValidatorSig {
                    validator: t.clone(),
                    signature: sig,
                }
            })
            .collect();

        let tx = BridgeVerifyTx {
            deposit,
            validator_signatures: validator_sigs,
            recipient_sig,
            recipient_pubkey: recipient_tagged,
            preferred_relayer: Some(make_tagged_pubkey(0x99)),
        };

        // 执行 bridge_verify
        let outcome = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true).unwrap();
        assert_eq!(outcome.deposit.amount, 1000);
        assert_eq!(outcome.recipient, recipient_addr);
        assert!(outcome.preferred_relayer.is_some());

        // nonce 已消费 → 重复提交失败
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))));
    }

    #[test]
    fn test_bridge_verify_recipient_signature_invalid() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 占位 recipient 签名（无效）
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    // ===== burn_on_source 测试 =====

    #[test]
    fn test_burn_on_source_success() {
        let mut registry = BridgeRegistry::new();
        let burn = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        burn_on_source(&mut registry, &burn, crate::DEFAULT_CHAIN_ID).unwrap();
        // 重复 burn → 失败
        let result = burn_on_source(&mut registry, &burn, crate::DEFAULT_CHAIN_ID);
        assert!(matches!(result, Err(PokerL1Error::BurnProofInvalid(_))));
    }

    #[test]
    fn test_burn_on_source_chain_mismatch() {
        let mut registry = BridgeRegistry::new();
        let burn = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: 0x9999, // 错误
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        let result = burn_on_source(&mut registry, &burn, crate::DEFAULT_CHAIN_ID);
        assert!(matches!(result, Err(PokerL1Error::BurnProofInvalid(_))));
    }

    // ===== BurnProof 测试 =====

    #[test]
    fn test_burn_proof_message_hash() {
        let burn1 = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        let burn2 = burn1.clone();
        assert_eq!(burn1.message_hash(), burn2.message_hash());

        // 不同 burn_nonce → 不同哈希
        let mut burn3 = burn1.clone();
        burn3.burn_nonce = 2;
        assert_ne!(burn1.message_hash(), burn3.message_hash());
    }

    // ===== bridge_verify_contract_call_denied 测试 =====

    #[test]
    fn test_bridge_verify_contract_call_denied() {
        let err = bridge_verify_contract_call_denied();
        assert!(matches!(err, PokerL1Error::BridgeVerifyNotAuthorized));
    }

    // ===== derive_address 测试 =====

    #[test]
    fn test_derive_address_deterministic() {
        let pk = make_tagged_pubkey(0x01);
        let addr1 = derive_address(&pk);
        let addr2 = derive_address(&pk);
        assert_eq!(addr1, addr2);
        // 不同 pubkey → 不同地址
        let pk2 = make_tagged_pubkey(0x02);
        let addr3 = derive_address(&pk2);
        assert_ne!(addr1, addr3);
    }
}
