//! 账户抽象与交易安全（Task 6 — S7/M9/M10 修复）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）账户抽象与交易安全章节：
//! - **S7 修复**：tagged pubkey → address 派生（`blake2b_256(tagged_pubkey)[0..20]`）
//! - **M9 修复**：`Account = { address, tagged_pubkey, nonce: u64, balance: u64 }`，一账户绑定一 pubkey
//! - **M10 修复**：tx 含 `chain_id` + `nonce`，validator 校验后 `account.nonce += 1`
//! - **NEW-M9 修复**：GameTurn 通道 tx 使用 `gameturn_nonce`（per-game per-player）替代 account nonce；
//!   account nonce 仅由 Public / ForceSync tx 推进，不阻塞 GameTurn 出牌
//! - **SEC-L3 修复**：`gameturn_nonce` 存储于 `Game.player_nonce: BTreeMap<PlayerAddress, u64>`，
//!   玩家首次 join 初始化为 0，冷启动按 0 处理（Phase 2 Game 对象实现后接入）
//! - **SEC-H7 修复**：`is_fallback: bool` 字段；正常 GameTurn tx 不得设置 `is_fallback = true`
//!   （validator 拒绝，返回 `InvalidFallbackFlag`）；fallback tx 走 `gameturn_nonce` 验证路径
//! - **SEC-L4 修复**：所有 tx 签名域统一加 `chain_id` 首字段（在 `transaction` 模块实现）
//!
//! Phase 1 实现：
//! - `Account` 结构与地址派生
//! - `AccountStore`（内存版，Phase 4 接入 rocksdb）
//! - 重放保护校验函数（chain_id / nonce / gameturn_nonce / is_fallback）
//! - 余额管理（debit / credit）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::transaction::Transaction;
use crate::{Address, ChainId};

/// 账户 nonce 类型（M10：Public / ForceSync 通道重放保护）。
pub type Nonce = u64;

/// 账户余额类型（用于 Public 通道 gas 支付）。
pub type Balance = u64;

/// 账户（spec M9 修复）。
///
/// 一个账户绑定一个 tagged pubkey（MVP 不支持多 key 账户）。
/// `balance` 用于支付 Public 通道 tx 的 gas；GameTurn 通道 tx 免 gas。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Account {
    /// 账户地址 = `blake2b_256(tagged_pubkey)[0..20]`（S7 修复）。
    pub address: Address,
    /// 绑定的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// Account nonce（M10：仅由 Public / ForceSync tx 推进）。
    pub nonce: Nonce,
    /// 账户余额（用于 Public 通道 gas 支付）。
    pub balance: Balance,
}

impl Account {
    /// 创建新账户。地址由 tagged pubkey 派生（S7 修复）。
    pub fn new(tagged_pubkey: TaggedPubkey, initial_balance: Balance) -> Self {
        let address = derive_address(&tagged_pubkey);
        Self {
            address,
            tagged_pubkey,
            nonce: 0,
            balance: initial_balance,
        }
    }

    /// 从 tagged pubkey 派生地址（S7 修复：`blake2b_256(tagged_pubkey)[0..20]`）。
    /// 不同曲线的 tagged pubkey 不会产生地址碰撞（tag 字节不同）。
    pub fn derive_address_from_pubkey(tagged_pubkey: &TaggedPubkey) -> Address {
        derive_address(tagged_pubkey)
    }

    /// 递增 account nonce（Public / ForceSync tx 执行成功后调用）。
    pub const fn increment_nonce(&mut self) {
        self.nonce = self.nonce.saturating_add(1);
    }

    /// 扣除 gas 费用（Public 通道 tx 执行后调用）。
    /// 余额不足返回 `InsufficientBalance`。
    pub const fn debit(&mut self, amount: Balance) -> PokerL1Result<()> {
        if amount > self.balance {
            return Err(PokerL1Error::InsufficientBalance {
                needed: amount,
                has: self.balance,
            });
        }
        self.balance -= amount;
        Ok(())
    }

    /// 充值余额（faucet / 收款）。
    ///
    /// SEC-FIX-3：使用 `checked_add` 替代 `saturating_add`，溢出时返回
    /// `BalanceOverflow` 错误而非静默封顶。调用方应处理错误并决定是否回滚。
    pub const fn credit(&mut self, amount: Balance) -> PokerL1Result<()> {
        match self.balance.checked_add(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                Ok(())
            }
            None => Err(PokerL1Error::BalanceOverflow {
                current: self.balance,
                credit: amount,
            }),
        }
    }
}

/// 从 tagged pubkey 派生地址（S7 修复）。
///
/// `address = blake2b_256(tag || raw_pubkey)[0..20]`
///
/// 不同曲线的 tagged pubkey tag 字节不同（secp256k1=0x01, ed25519=0x11），
/// 因此即使 raw pubkey 相同也不会产生地址碰撞。
pub fn derive_address(tagged_pubkey: &TaggedPubkey) -> Address {
    let bytes = tagged_pubkey.to_bytes();
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[..20]);
    addr
}

// ===== 重放保护校验（M10 + NEW-M9 + SEC-H7 + SEC-L4） =====

/// 校验 tx 的 chain_id 与网络 chain_id 一致（SEC-L4 修复）。
///
/// 不匹配返回 `WrongChainId`（防跨链重放）。
pub const fn validate_chain_id(
    tx_chain_id: ChainId,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    if tx_chain_id != network_chain_id {
        return Err(PokerL1Error::WrongChainId {
            tx: tx_chain_id,
            network: network_chain_id,
        });
    }
    Ok(())
}

/// 校验 Public / ForceSync 通道 tx 的重放保护（M10 修复）。
///
/// 校验规则：
/// 1. `tx.chain_id == network_chain_id`（SEC-L4）
/// 2. `tx.nonce == account.nonce`（严格匹配，不允许跳号）
///    - `tx.nonce < account.nonce` → `NonceTooLow`（重放）
///    - `tx.nonce > account.nonce` → `NonceTooHigh`（跳号，防 tx 排序攻击）
///
/// 注意：GameTurn 通道 tx 不走此函数，走 `validate_gameturn_tx`。
pub fn validate_public_tx(
    account: &Account,
    tx: &Transaction,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    validate_chain_id(tx.chain_id, network_chain_id)?;
    if tx.nonce < account.nonce {
        return Err(PokerL1Error::NonceTooLow {
            tx: tx.nonce,
            account: account.nonce,
        });
    }
    if tx.nonce > account.nonce {
        return Err(PokerL1Error::NonceTooHigh {
            tx: tx.nonce,
            account: account.nonce,
        });
    }
    Ok(())
}

/// 校验 GameTurn 通道 tx 的重放保护（NEW-M9 + SEC-H7 修复）。
///
/// 校验规则：
/// 1. `tx.chain_id == network_chain_id`（SEC-L4）
/// 2. `tx.is_fallback == false` 的正常 GameTurn tx 不得设置 `is_fallback = true`（SEC-H7）
///    — 注意：此函数不区分"正常"与"fallback"，由调用方决定是否允许 is_fallback；
///    此处仅校验 `gameturn_nonce` 严格匹配
/// 3. `tx.gameturn_nonce == Some(expected)`（per-game per-player 计数器）
///    - `None` → `GameTurnNonceMismatch`（GameTurn tx 必须携带 gameturn_nonce）
///    - 不匹配 → `GameTurnNonceMismatch`
///
/// `expected` = `Game.player_nonce[player]`，冷启动（玩家未 join）按 0 处理（SEC-L3）。
///
/// 注意：此函数不推进 nonce，由调用方在 tx 执行成功后调用 `apply_gameturn_tx`。
pub fn validate_gameturn_tx(
    expected_gameturn_nonce: u64,
    tx: &Transaction,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    validate_chain_id(tx.chain_id, network_chain_id)?;
    match tx.gameturn_nonce {
        Some(n) if n == expected_gameturn_nonce => Ok(()),
        Some(n) => Err(PokerL1Error::GameTurnNonceMismatch {
            tx: n,
            game: expected_gameturn_nonce,
        }),
        None => Err(PokerL1Error::GameTurnNonceMismatch {
            tx: 0,
            game: expected_gameturn_nonce,
        }),
    }
}

/// 校验正常 GameTurn tx 不得设置 `is_fallback = true`（SEC-H7 修复）。
///
/// validator 据此防止 assigned_validator 误将正常 tx 路由到 fallback 路径
/// 绕过轮转排序独占权。
///
/// - `is_fallback = true` 的正常 GameTurn tx → `InvalidFallbackFlag`
/// - fallback tx（NEW-H2）由调用方显式标记 `is_fallback = true` 并走此函数校验通过
pub const fn validate_normal_gameturn_not_fallback(tx: &Transaction) -> PokerL1Result<()> {
    if tx.is_fallback {
        Err(PokerL1Error::InvalidFallbackFlag)
    } else {
        Ok(())
    }
}

/// 应用 Public / ForceSync tx 到账户（执行成功后调用）。
///
/// 1. 校验 `gas_used <= tx.gas.budget`（实际消耗不超过声明预算）
/// 2. 扣除 gas 费用（`gas_used` 由 VM 执行后返回；Phase 1 简化为调用方传入）
/// 3. 递增 account nonce
///
/// 注意：此函数假设 `validate_public_tx` 已通过。GameTurn 通道 tx 免 gas，不走此函数。
pub fn apply_public_tx(
    account: &mut Account,
    tx: &Transaction,
    gas_used: Balance,
) -> PokerL1Result<()> {
    if gas_used > tx.gas.budget {
        return Err(PokerL1Error::GasExceedsBudget {
            used: gas_used,
            budget: tx.gas.budget,
        });
    }
    account.debit(gas_used)?;
    account.increment_nonce();
    Ok(())
}

/// 应用 GameTurn tx 到 per-game per-player nonce（执行成功后调用）。
///
/// GameTurn 通道 tx 免 gas，仅递增 `gameturn_nonce`。
///
/// 注意：此函数假设 `validate_gameturn_tx` 已通过。
pub const fn apply_gameturn_tx(game_player_nonce: &mut u64) {
    *game_player_nonce = game_player_nonce.saturating_add(1);
}

// ===== AccountStore（内存版） =====

/// 内存版 AccountStore（Phase 4 接入 rocksdb 持久化）。
///
/// 按 `address` 索引账户。提供创建 / 查询 / 余额管理接口。
#[derive(Debug, Default)]
pub struct AccountStore {
    accounts: HashMap<Address, Account>,
}

impl AccountStore {
    /// 创建空 store。
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// 注册新账户。若地址已存在返回 `ObjectIDCollision`（语义：地址碰撞）。
    ///
    /// 注意：地址碰撞理论上不可能（blake2b_256 抗碰撞），此校验为防御性编程。
    pub fn create(&mut self, account: Account) -> PokerL1Result<()> {
        if self.accounts.contains_key(&account.address) {
            return Err(PokerL1Error::Other(format!(
                "account address collision: {:?}",
                account.address
            )));
        }
        self.accounts.insert(account.address, account);
        Ok(())
    }

    /// 查询账户。
    pub fn get(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// 可变查询账户。
    pub fn get_mut(&mut self, address: &Address) -> Option<&mut Account> {
        self.accounts.get_mut(address)
    }

    /// 从 tagged pubkey 查询账户（先派生地址再查）。
    pub fn get_by_pubkey(&self, tagged_pubkey: &TaggedPubkey) -> Option<&Account> {
        let addr = derive_address(tagged_pubkey);
        self.accounts.get(&addr)
    }

    /// 充值（faucet / 收款）。
    ///
    /// SEC-FIX-3：传播 `Account::credit` 的溢出错误。
    pub fn credit(&mut self, address: &Address, amount: Balance) -> PokerL1Result<()> {
        let account = self
            .accounts
            .get_mut(address)
            .ok_or_else(|| PokerL1Error::Other(format!("account not found: {:?}", address)))?;
        account.credit(amount)
    }

    /// 当前账户数量。
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// 迭代所有账户。
    pub fn iter(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxLane};

    /// 构造测试用 tagged pubkey（不验证签名，仅用于地址派生）。
    fn make_tagged_pubkey(byte: u8, scheme: SignatureScheme) -> TaggedPubkey {
        let raw_len = scheme.raw_pubkey_len();
        TaggedPubkey {
            tag: encode_tag(scheme, 1),
            raw: vec![byte; raw_len],
        }
    }

    /// 构造测试用 Transaction（最小化字段，仅用于重放保护校验）。
    /// Public 通道用非零 gas budget（apply_public_tx 校验 gas_used <= budget）；
    /// GameTurn 通道用 Gas::zero()（免 gas）。
    fn make_tx(
        chain_id: ChainId,
        nonce: u64,
        gameturn_nonce: Option<u64>,
        is_fallback: bool,
        lane: TxLane,
    ) -> Transaction {
        let gas = match lane {
            TxLane::GameTurn | TxLane::CheckpointAnchor => Gas::zero(),
            TxLane::Public | TxLane::ForceSync => Gas::new(1_000_000, 1),
        };
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x02, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas,
            lane_hint: lane,
            route_hint: RouteHint::AnyValidator,
            chain_id,
            nonce,
            gameturn_nonce,
            is_fallback,
        }
    }

    const NETWORK: ChainId = crate::DEFAULT_CHAIN_ID;

    // ===== 地址派生测试（S7 修复） =====

    #[test]
    fn derive_address_deterministic() {
        let tp = make_tagged_pubkey(0xAB, SignatureScheme::Secp256k1);
        let a1 = derive_address(&tp);
        let a2 = derive_address(&tp);
        assert_eq!(a1, a2, "地址派生必须确定性");
        assert_eq!(a1.len(), 20);
    }

    #[test]
    fn derive_address_different_pubkeys_dont_collide() {
        let tp1 = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let tp2 = make_tagged_pubkey(0x02, SignatureScheme::Secp256k1);
        assert_ne!(derive_address(&tp1), derive_address(&tp2));
    }

    #[test]
    fn derive_address_different_curves_dont_collide() {
        // 即使 raw pubkey 字节相同，tag 不同（secp256k1=0x01, ed25519=0x11）也不碰撞
        let tp_sec = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x42; 32], // secp256k1 期望 33B，这里故意 32B 测试 tag 区分
        };
        let tp_ed = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: vec![0x42; 32],
        };
        assert_ne!(derive_address(&tp_sec), derive_address(&tp_ed));
    }

    #[test]
    fn account_new_derives_address() {
        let tp = make_tagged_pubkey(0xCD, SignatureScheme::Ed25519);
        let account = Account::new(tp.clone(), 1_000_000);
        assert_eq!(account.address, derive_address(&tp));
        assert_eq!(account.nonce, 0);
        assert_eq!(account.balance, 1_000_000);
    }

    // ===== 序列化测试 =====

    #[test]
    fn account_bcs_roundtrip() {
        let tp = make_tagged_pubkey(0x99, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 500_000);
        let bytes = borsh::to_vec(&account).unwrap();
        let recovered: Account = borsh::from_slice(&bytes).unwrap();
        assert_eq!(account, recovered);
    }

    #[test]
    fn account_json_roundtrip() {
        let tp = make_tagged_pubkey(0x77, SignatureScheme::Ed25519);
        let account = Account::new(tp, 250_000);
        let json = serde_json::to_string(&account).unwrap();
        let recovered: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(account, recovered);
    }

    // ===== 余额管理测试（SubTask 6.4） =====

    #[test]
    fn debit_succeeds_when_sufficient_balance() {
        let tp = make_tagged_pubkey(0x11, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 1_000);
        account.debit(300).unwrap();
        assert_eq!(account.balance, 700);
    }

    #[test]
    fn debit_fails_when_insufficient_balance() {
        let tp = make_tagged_pubkey(0x22, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 100);
        let err = account.debit(500).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::InsufficientBalance {
                needed: 500,
                has: 100
            }
        ));
    }

    #[test]
    fn credit_increases_balance() {
        let tp = make_tagged_pubkey(0x33, SignatureScheme::Ed25519);
        let mut account = Account::new(tp, 200);
        account.credit(800).expect("正常充值应成功");
        assert_eq!(account.balance, 1000);
    }

    /// SEC-FIX-3：验证 credit 溢出返回错误而非静默封顶。
    #[test]
    fn credit_overflow_returns_error() {
        let tp = make_tagged_pubkey(0x55, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, u64::MAX - 100);
        // 再充 200 应溢出（MAX-100 + 200 > u64::MAX）
        let result = account.credit(200);
        assert!(
            matches!(result, Err(PokerL1Error::BalanceOverflow { current, credit })
                if current == u64::MAX - 100 && credit == 200),
            "溢出应返回 BalanceOverflow 错误"
        );
        // 余额不应改变
        assert_eq!(account.balance, u64::MAX - 100);
    }

    #[test]
    fn increment_nonce_monotonic() {
        let tp = make_tagged_pubkey(0x44, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 0);
        assert_eq!(account.nonce, 0);
        account.increment_nonce();
        account.increment_nonce();
        assert_eq!(account.nonce, 2);
    }

    // ===== 重放保护测试（M10 + SEC-L4） =====

    #[test]
    fn validate_chain_id_passes_when_match() {
        validate_chain_id(NETWORK, NETWORK).unwrap();
    }

    #[test]
    fn validate_chain_id_fails_when_mismatch() {
        let err = validate_chain_id(NETWORK, NETWORK + 1).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::WrongChainId {
                tx: NETWORK,
                network: _
            }
        ));
    }

    #[test]
    fn validate_public_tx_passes_when_nonce_matches() {
        let tp = make_tagged_pubkey(0x55, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 1_000_000);
        let tx = make_tx(NETWORK, 0, None, false, TxLane::Public);
        validate_public_tx(&account, &tx, NETWORK).unwrap();
    }

    #[test]
    fn validate_public_tx_rejects_nonce_too_low() {
        let tp = make_tagged_pubkey(0x66, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 1_000_000);
        account.increment_nonce(); // account.nonce = 1
        let tx = make_tx(NETWORK, 0, None, false, TxLane::Public); // tx.nonce = 0 < 1
        let err = validate_public_tx(&account, &tx, NETWORK).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::NonceTooLow { tx: 0, account: 1 }
        ));
    }

    #[test]
    fn validate_public_tx_rejects_nonce_too_high() {
        let tp = make_tagged_pubkey(0x77, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 1_000_000); // nonce = 0
        let tx = make_tx(NETWORK, 5, None, false, TxLane::Public); // tx.nonce = 5 > 0
        let err = validate_public_tx(&account, &tx, NETWORK).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::NonceTooHigh { tx: 5, account: 0 }
        ));
    }

    #[test]
    fn validate_public_tx_rejects_wrong_chain_id() {
        let tp = make_tagged_pubkey(0x88, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 1_000_000);
        let tx = make_tx(NETWORK + 99, 0, None, false, TxLane::Public);
        let err = validate_public_tx(&account, &tx, NETWORK).unwrap_err();
        assert!(matches!(err, PokerL1Error::WrongChainId { .. }));
    }

    #[test]
    fn apply_public_tx_debits_gas_and_increments_nonce() {
        let tp = make_tagged_pubkey(0x99, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 1_000_000);
        let tx = make_tx(NETWORK, 0, None, false, TxLane::Public);
        apply_public_tx(&mut account, &tx, 500).unwrap();
        assert_eq!(account.balance, 1_000_000 - 500);
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn apply_public_tx_fails_when_insufficient_balance() {
        let tp = make_tagged_pubkey(0xAA, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 100);
        let tx = make_tx(NETWORK, 0, None, false, TxLane::Public);
        let err = apply_public_tx(&mut account, &tx, 500).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientBalance { .. }));
        // 失败时 nonce 不推进
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn apply_public_tx_fails_when_gas_exceeds_budget() {
        // make_tx 对 Public lane 设置 budget=1_000_000；gas_used=2_000_000 > budget → GasExceedsBudget
        let tp = make_tagged_pubkey(0xAC, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 10_000_000);
        let tx = make_tx(NETWORK, 0, None, false, TxLane::Public); // budget = 1_000_000
        let err = apply_public_tx(&mut account, &tx, 2_000_000).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::GasExceedsBudget {
                used: 2_000_000,
                budget: 1_000_000
            }
        ));
        assert_eq!(account.nonce, 0, "失败时 nonce 不推进");
        assert_eq!(account.balance, 10_000_000, "失败时不扣费");
    }

    // ===== GameTurn 重放保护测试（NEW-M9 + SEC-H7） =====

    #[test]
    fn validate_gameturn_tx_passes_when_nonce_matches() {
        let tx = make_tx(NETWORK, 0, Some(7), false, TxLane::GameTurn);
        validate_gameturn_tx(7, &tx, NETWORK).unwrap();
    }

    #[test]
    fn validate_gameturn_tx_rejects_mismatch() {
        let tx = make_tx(NETWORK, 0, Some(3), false, TxLane::GameTurn);
        let err = validate_gameturn_tx(7, &tx, NETWORK).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::GameTurnNonceMismatch { tx: 3, game: 7 }
        ));
    }

    #[test]
    fn validate_gameturn_tx_rejects_missing_nonce() {
        let tx = make_tx(NETWORK, 0, None, false, TxLane::GameTurn);
        let err = validate_gameturn_tx(0, &tx, NETWORK).unwrap_err();
        assert!(matches!(err, PokerL1Error::GameTurnNonceMismatch { .. }));
    }

    #[test]
    fn validate_gameturn_tx_rejects_wrong_chain_id() {
        let tx = make_tx(NETWORK + 1, 0, Some(0), false, TxLane::GameTurn);
        let err = validate_gameturn_tx(0, &tx, NETWORK).unwrap_err();
        assert!(matches!(err, PokerL1Error::WrongChainId { .. }));
    }

    #[test]
    fn validate_gameturn_tx_accepts_cold_start_zero() {
        // SEC-L3：冷启动（玩家未 join）按 0 处理
        let tx = make_tx(NETWORK, 0, Some(0), false, TxLane::GameTurn);
        validate_gameturn_tx(0, &tx, NETWORK).unwrap();
    }

    #[test]
    fn validate_normal_gameturn_rejects_fallback_flag() {
        // SEC-H7：正常 GameTurn tx 不得设置 is_fallback=true
        let tx = make_tx(NETWORK, 0, Some(0), true, TxLane::GameTurn);
        let err = validate_normal_gameturn_not_fallback(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidFallbackFlag));
    }

    #[test]
    fn validate_normal_gameturn_passes_without_fallback_flag() {
        let tx = make_tx(NETWORK, 0, Some(0), false, TxLane::GameTurn);
        validate_normal_gameturn_not_fallback(&tx).unwrap();
    }

    #[test]
    fn apply_gameturn_tx_increments_nonce() {
        let mut n: u64 = 5;
        apply_gameturn_tx(&mut n);
        assert_eq!(n, 6);
    }

    #[test]
    fn gameturn_tx_does_not_block_account_nonce() {
        // NEW-M9 核心语义：GameTurn tx 仅推进 gameturn_nonce，不影响 account nonce
        let tp = make_tagged_pubkey(0xBB, SignatureScheme::Secp256k1);
        let mut account = Account::new(tp, 1_000_000);
        let mut game_player_nonce: u64 = 0;

        // 玩家出牌 3 次（GameTurn tx）
        for _ in 0..3 {
            let tx = make_tx(NETWORK, 0, Some(game_player_nonce), false, TxLane::GameTurn);
            validate_gameturn_tx(game_player_nonce, &tx, NETWORK).unwrap();
            apply_gameturn_tx(&mut game_player_nonce);
        }
        assert_eq!(game_player_nonce, 3);
        // account nonce 不变（GameTurn tx 不推进 account nonce）
        assert_eq!(account.nonce, 0);
        // balance 不变（GameTurn tx 免 gas）
        assert_eq!(account.balance, 1_000_000);

        // 之后玩家提交 Public tx，account nonce 从 0 开始
        let public_tx = make_tx(NETWORK, 0, None, false, TxLane::Public);
        validate_public_tx(&account, &public_tx, NETWORK).unwrap();
        apply_public_tx(&mut account, &public_tx, 100).unwrap();
        assert_eq!(account.nonce, 1);
        assert_eq!(account.balance, 1_000_000 - 100);
    }

    #[test]
    fn fallback_tx_uses_gameturn_nonce_path() {
        // SEC-H7：fallback tx 走 gameturn_nonce 验证路径（不走 account nonce）
        let mut game_player_nonce: u64 = 2;
        let tx = make_tx(NETWORK, 0, Some(2), true, TxLane::GameTurn);
        // fallback tx 不走 validate_normal_gameturn_not_fallback 校验
        validate_gameturn_tx(game_player_nonce, &tx, NETWORK).unwrap();
        apply_gameturn_tx(&mut game_player_nonce);
        assert_eq!(game_player_nonce, 3);
    }

    // ===== AccountStore 测试 =====

    #[test]
    fn account_store_create_and_get() {
        let mut store = AccountStore::new();
        let tp = make_tagged_pubkey(0xCC, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 1_000);
        let addr = account.address;
        store.create(account).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&addr).unwrap().balance, 1_000);
    }

    #[test]
    fn account_store_get_by_pubkey() {
        let mut store = AccountStore::new();
        let tp = make_tagged_pubkey(0xDD, SignatureScheme::Ed25519);
        let account = Account::new(tp.clone(), 500);
        store.create(account).unwrap();
        assert!(store.get_by_pubkey(&tp).is_some());
    }

    #[test]
    fn account_store_create_collision_fails() {
        let mut store = AccountStore::new();
        let tp = make_tagged_pubkey(0xEE, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 1_000);
        store.create(account).unwrap();
        // 同地址再次创建
        let tp2 = make_tagged_pubkey(0xEE, SignatureScheme::Secp256k1);
        let account2 = Account::new(tp2, 2_000);
        let err = store.create(account2).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn account_store_credit() {
        let mut store = AccountStore::new();
        let tp = make_tagged_pubkey(0xFF, SignatureScheme::Secp256k1);
        let account = Account::new(tp, 100);
        let addr = account.address;
        store.create(account).unwrap();
        store.credit(&addr, 900).unwrap();
        assert_eq!(store.get(&addr).unwrap().balance, 1000);
    }

    #[test]
    fn account_store_is_empty() {
        let store = AccountStore::new();
        assert!(store.is_empty());
    }
}
