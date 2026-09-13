//! PokerSettlement（legacy 线性结算）绑定：只读核验 + prover 管理视图。
//!
//! legacy 结算提交（`register_aggregate`/`settle_hand` 的 aggregate proof
//! 载荷）由 poker_texas_air 侧的结算编排产出，本模块不构造——只提供核验
//! 与状态读取（zchain 侧的接入面以核验为主，见模块文档）。

use crate::client::ChainClient;
use crate::codec::Felt;
use crate::error::{ContractsError, ContractsResult};

use super::vault::felt_scalar;

/// 结算承诺根（与合约 `settle_hand` 内 `poseidon_hash_span` 同公式）：
/// `poseidon([hand_id, (player, sign, |delta|)*, action_log_digest])`，
/// sign：1=正 / 0=负。`register_aggregate` 的 `settlement_roots` 逐手提交
/// 此值，`settle_hand` 链上重算比对——本函数为部署/运维侧的离线同式计算。
#[must_use]
pub fn settlement_root(
    hand_id: u64,
    participants: &[(Felt, i128)],
    action_log_digest: Felt,
) -> Felt {
    let mut elements = vec![Felt::from(hand_id)];
    for (player, delta) in participants {
        elements.push(*player);
        if *delta >= 0 {
            elements.push(Felt::ONE);
        } else {
            elements.push(Felt::ZERO);
        }
        elements.push(Felt::from(delta.unsigned_abs()));
    }
    elements.push(action_log_digest);
    starknet_crypto::poseidon_hash_many(&elements)
}

/// PokerSettlement 句柄。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// 合约地址。
    pub address: Felt,
}

impl Settlement {
    /// 绑定地址（对标 `Contract.at`）。
    #[must_use]
    pub fn at(address: Felt) -> Self {
        Self { address }
    }

    /// `vault()`（绑定的 vault 地址）。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn vault(&self, client: &ChainClient) -> ContractsResult<Felt> {
        let res = client.call(self.address, "vault", vec![]).await?;
        res.into_iter().next().ok_or_else(|| ContractsError::Chain("vault: empty".into()))
    }

    /// `hand_settled(hand_id)`。
    ///
    /// # Errors
    /// RPC 失败 → 上游错误。
    pub async fn hand_settled(&self, client: &ChainClient, hand_id: u64) -> ContractsResult<bool> {
        let res = client
            .call(self.address, "hand_settled", vec![Felt::from(hand_id)])
            .await?;
        felt_scalar(&res, "hand_settled").map(|v| v == 1)
    }

    /// `settlement_digest(hand_id)`。
    ///
    /// # Errors
    /// RPC 失败 → [`ContractsError::Chain`]。
    pub async fn settlement_digest(&self, client: &ChainClient, hand_id: u64) -> ContractsResult<Felt> {
        let res = client
            .call(self.address, "settlement_digest", vec![Felt::from(hand_id)])
            .await?;
        res.into_iter()
            .next()
            .ok_or_else(|| ContractsError::Chain("settlement_digest: empty".into()))
    }

    /// `is_prover(addr)`。
    ///
    /// # Errors
    /// RPC 失败 → 上游错误。
    pub async fn is_prover(&self, client: &ChainClient, addr: Felt) -> ContractsResult<bool> {
        let res = client.call(self.address, "is_prover", vec![addr]).await?;
        felt_scalar(&res, "is_prover").map(|v| v == 1)
    }
}
