//! 规范 STRK（ERC20）绑定：筹码出入金审批 / 余额读。
//!
//! canonical 地址 mainnet/sepolia/devnet 同址（[`crate::config::CANONICAL_STRK`]）。

use starknet::core::types::Call;

use crate::client::ChainClient;
use crate::codec::{u256_from_felts, Uint256};
use crate::error::ContractsResult;
use crate::instance::amount_felts;

/// STRK 代币句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrkToken {
    /// 代币合约地址。
    pub address: crate::codec::Felt,
}

impl StrkToken {
    /// 绑定地址（对标 `Contract.at`）。
    #[must_use]
    pub fn at(address: crate::codec::Felt) -> Self {
        Self { address }
    }

    /// 规范 STRK 的便捷构造。
    #[must_use]
    pub fn canonical() -> Self {
        Self::at(crate::codec::parse_felt(crate::config::CANONICAL_STRK).expect("const felt"))
    }

    /// `balance_of(owner)` → `[low, high]`。
    ///
    /// # Errors
    /// RPC / 解码失败 → 上游错误。
    pub async fn balance_of(
        &self,
        client: &ChainClient,
        owner: crate::codec::Felt,
    ) -> ContractsResult<Uint256> {
        let res = client.call(self.address, "balance_of", vec![owner]).await?;
        u256_from_felts(&res)
    }

    /// `transfer(to, amount)` 调用。
    #[must_use]
    pub fn transfer_call(&self, to: crate::codec::Felt, amount: Uint256) -> Call {
        ChainClient::make_call(
            self.address,
            "transfer",
            [vec![to], amount_felts(amount)].concat(),
        )
    }

    /// `approve(spender, amount)` 调用（deposit 前置）。
    #[must_use]
    pub fn approve_call(&self, spender: crate::codec::Felt, amount: Uint256) -> Call {
        ChainClient::make_call(self.address, "approve", vec![spender].into_iter().chain(amount_felts(amount)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Felt;

    #[test]
    fn approve_calldata_shape() {
        let token = StrkToken::canonical();
        let spender = Felt::from(0xB_u64);
        let call = token.approve_call(spender, Uint256::from_u128(1_000));
        assert_eq!(call.to, token.address);
        assert_eq!(call.calldata.len(), 3); // spender, low, high
        assert_eq!(call.calldata[0], spender);
        assert_eq!(call.calldata[1], Felt::from(1_000_u64));
        assert_eq!(call.calldata[2], Felt::ZERO);
    }
}
