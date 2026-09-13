//! PokerVault 绑定：筹码账本读写 + owner 接线（部署器复用）。
//!
//! 语义（poker_texas_air `poker_vault.cairo` v3）：只可花未锁定余额；
//! 结算负 delta 优先消耗锁定额度；`unlock_after_deadline` 任何人可调
//! （TTL 自助解锁，后端失联保护）。

use starknet::core::types::Call;

use crate::client::ChainClient;
use crate::codec::{felt_to_u128, u256_from_felts, Felt, Uint256};
use crate::error::{ContractsError, ContractsResult};
use crate::instance::amount_felts;

/// PokerVault 句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vault {
    /// 合约地址。
    pub address: Felt,
}

impl Vault {
    /// 绑定地址（对标 `Contract.at`）。
    #[must_use]
    pub fn at(address: Felt) -> Self {
        Self { address }
    }

    // ===== 视图读 =====

    /// `chip_balance(player)`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn chip_balance(&self, client: &ChainClient, player: Felt) -> ContractsResult<Uint256> {
        u256_from_felts(&client.call(self.address, "chip_balance", vec![player]).await?)
    }

    /// `token()`（绑定的代币地址）。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn token(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "token", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("token: empty".into()))
    }

    /// `unshield_helper()`。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn unshield_helper(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "unshield_helper", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("unshield_helper: empty".into()))
    }

    /// `locked_balance(player)`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn locked_balance(&self, client: &ChainClient, player: Felt) -> ContractsResult<Uint256> {
        u256_from_felts(&client.call(self.address, "locked_balance", vec![player]).await?)
    }

    /// `lock_ttl()`（秒）。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn lock_ttl(&self, client: &ChainClient) -> ContractsResult<u64> {
        let res = client.call(self.address, "lock_ttl", vec![]).await?;
        felt_scalar(&res, "lock_ttl")
    }

    /// `paused()`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn paused(&self, client: &ChainClient) -> ContractsResult<bool> {
        let res = client.call(self.address, "paused", vec![]).await?;
        felt_scalar(&res, "paused").map(|v| v == 1)
    }

    /// `total_chips()`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn total_chips(&self, client: &ChainClient) -> ContractsResult<Uint256> {
        u256_from_felts(&client.call(self.address, "total_chips", vec![]).await?)
    }

    // ===== 玩家 / operator 写 =====

    /// `deposit(amount)`（先 `approve`）。
    #[must_use]
    pub fn deposit_call(&self, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "deposit", amount_felts(amount))
    }

    /// `deposit_for(player, amount)`（operator 代充）。
    #[must_use]
    pub fn deposit_for_call(&self, player: Felt, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "deposit_for", [vec![player], amount_felts(amount)].concat())
    }

    /// `withdraw(amount)`。
    #[must_use]
    pub fn withdraw_call(&self, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "withdraw", amount_felts(amount))
    }

    /// `withdraw_to(to, amount)`。
    #[must_use]
    pub fn withdraw_to_call(&self, to: Felt, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "withdraw_to", [vec![to], amount_felts(amount)].concat())
    }

    /// `lock(player, amount)`（operator：入座锁额度）。
    #[must_use]
    pub fn lock_call(&self, player: Felt, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "lock", [vec![player], amount_felts(amount)].concat())
    }

    /// `refresh_session(player)`（结算/续局续时钟）。
    #[must_use]
    pub fn refresh_session_call(&self, player: Felt) -> Call {
        ChainClient::make_call(self.address, "refresh_session", vec![player])
    }

    /// `unlock_after_deadline(player)`（无许可 TTL 解锁）。
    #[must_use]
    pub fn unlock_after_deadline_call(&self, player: Felt) -> Call {
        ChainClient::make_call(self.address, "unlock_after_deadline", vec![player])
    }

    // ===== owner 接线（部署器复用） =====

    /// `set_settlement_contract(settlement)`。
    #[must_use]
    pub fn set_settlement_contract_call(&self, settlement: Felt) -> Call {
        ChainClient::make_call(self.address, "set_settlement_contract", vec![settlement])
    }

    /// `set_unshield_helper(helper)`。
    #[must_use]
    pub fn set_unshield_helper_call(&self, helper: Felt) -> Call {
        ChainClient::make_call(self.address, "set_unshield_helper", vec![helper])
    }
}

/// 单标量返回 → u64（felt 非负，越界报错）。
pub(crate) fn felt_scalar(res: &[Felt], what: &str) -> ContractsResult<u64> {
    let f = res
        .first()
        .copied()
        .ok_or_else(|| ContractsError::Chain(format!("{what}: empty response")))?;
    let v = felt_to_u128(f)?;
    u64::try_from(v).map_err(|_| ContractsError::Codec(format!("{what}: exceeds u64: {v}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_shapes_target_self_address() {
        let vault = Vault::at(Felt::from(0xAA_u64));
        let player = Felt::from(0xBB_u64);
        let c = vault.deposit_call(Uint256::from_u128(7));
        assert_eq!(c.to, vault.address);
        assert_eq!(c.calldata, vec![Felt::from(7_u64), Felt::ZERO]);
        assert_eq!(vault.withdraw_to_call(player, Uint256::from_u128(1)).calldata.len(), 3);
        assert_eq!(vault.set_settlement_contract_call(player).calldata, vec![player]);
        assert_eq!(vault.unlock_after_deadline_call(player).selector, crate::codec::selector("unlock_after_deadline"));
    }
}
